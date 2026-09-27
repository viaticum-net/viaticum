// Filesystem watcher: watches directories and converts notify events to DirtyEvents.
//
// Uses notify::RecommendedWatcher with a std channel bridge to tokio mpsc.
// Debounces rapid successive events on the same path (debounce_ms window).
// Filters (the same for the scan and live events, see `exclude`): only regular
// files; nothing with a hidden component below the watch root; nothing inside a
// Viaticum data directory; `.viaticumignore` rules. Symlinks to directories are
// not followed (neither by the scan nor by notify).
//
// Design: the notify callback posts to a std::sync::mpsc::Sender<(PathBuf, DirtyKind)>.
// A dedicated tokio task drains that channel, runs debounce, and forwards
// DirtyEvent to the backup coordinator channel.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc as std_mpsc;
use std::time::Instant;

use arc_swap::ArcSwap; // crate: arc-swap
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use notify::event::{EventKind, ModifyKind, RemoveKind};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tokio_util::sync::CancellationToken;

use crate::daemon::backup::{DirtyEvent, DirtyKind};
use crate::daemon::watch_admin::{WatchEntryState, WatcherStatusSignal};
use std::sync::RwLock;
use viaticum_core::types::DeviceId;

/// Built-in ignore patterns applied to every watch directory.
///
/// These are common build-artifact / cache directories that should never be
/// part of a backup. Users can override with `!pattern` in `.viaticumignore`.
const DEFAULT_IGNORE_PATTERNS: &[&str] = &[
    ".git/",
    "node_modules/",
    "target/",
    "__pycache__/",
    ".cache/",
];

/// Filename recognized at the root of each watch directory, holding
/// gitignore-syntax patterns for files that should not be backed up.
pub const VIATICUMIGNORE_FILENAME: &str = ".viaticumignore";

mod exclude;
pub(crate) use exclude::{
    FolderRefusal, data_dir_between, has_hidden_component_below, is_viaticum_data_dir,
    refuse_folder, symlink_into_data_dir,
};

#[cfg(test)]
mod tests;
#[cfg(all(test, unix))]
mod tests_exclude;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors from the watcher module.
#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
    #[error("notify watcher error: {0}")]
    Notify(#[from] notify::Error),

    #[error("no watch directories configured")]
    NoWatchDirs,

    #[error("failed to build ignore matcher: {0}")]
    IgnoreBuild(String),
}

// ─── WatcherCommand ───────────────────────────────────────────────────────────

/// Commands sent from WatchAdmin to the watcher task.
pub enum WatcherCommand {
    /// Start watching a new directory with given importance.
    /// The watcher registers the path, rebuilds IgnoreSet, and runs a full scan.
    Add { path: PathBuf, importance: f64 },
    /// Stop watching a directory.
    Remove { path: PathBuf },
    /// Trigger a full scan of a specific directory (already watched).
    Scan { path: PathBuf },
}

// ─── IgnoreSet ────────────────────────────────────────────────────────────────

/// Gitignore-style path matcher for a set of watch directories.
///
/// Each watch directory gets its own `Gitignore`, seeded with
/// [`DEFAULT_IGNORE_PATTERNS`] and optionally extended from a `.viaticumignore`
/// file at the root of that directory. A path is checked against the matcher
/// whose root is an ancestor of the path.
///
/// The matcher answers "is this path (or directory) ignored?" — see
/// [`IgnoreSet::is_ignored`].
pub struct IgnoreSet {
    /// (root, matcher). A root whose canonical form differs appears twice: under
    /// its configured spelling and canonicalized (macOS FSEvents reports canonical
    /// paths; inotify reports the configured spelling).
    matchers: Vec<(PathBuf, Gitignore)>,
}

impl IgnoreSet {
    /// Build a matcher covering every watch directory.
    ///
    /// For each directory:
    /// 1. Seed a `GitignoreBuilder` with `DEFAULT_IGNORE_PATTERNS`.
    /// 2. If a `.viaticumignore` exists at the directory root, append its
    ///    rules. A malformed file is logged and ignored (non-fatal).
    /// 3. Build the final `Gitignore`.
    pub fn build(watch_dirs: &[PathBuf]) -> Result<Self, WatcherError> {
        let mut matchers = Vec::with_capacity(watch_dirs.len());
        for dir in watch_dirs {
            matchers.push((dir.clone(), Self::matcher_for(dir, dir)?));
            if let Ok(canon) = std::fs::canonicalize(dir)
                && canon != *dir
            {
                matchers.push((canon.clone(), Self::matcher_for(dir, &canon)?));
            }
        }
        Ok(Self { matchers })
    }

    /// The matcher of watch folder `dir`, rooted at `root` (`dir` or its canonical form).
    fn matcher_for(dir: &Path, root: &Path) -> Result<Gitignore, WatcherError> {
        let mut builder = GitignoreBuilder::new(root);
        for pat in DEFAULT_IGNORE_PATTERNS {
            // `add_line` only fails on truly malformed patterns — the
            // constants above are hand-written, so this is effectively
            // infallible. Surface any breakage loudly in tests.
            builder
                .add_line(None, pat)
                .map_err(|e| WatcherError::IgnoreBuild(format!("default pattern {pat}: {e}")))?;
        }
        let ignore_file = dir.join(VIATICUMIGNORE_FILENAME);
        if ignore_file.is_file() {
            if let Some(err) = builder.add(&ignore_file) {
                tracing::warn!(
                    path = %ignore_file.display(),
                    error = %err,
                    "watcher: failed to parse .viaticumignore, skipping"
                );
            } else {
                tracing::info!(path = %ignore_file.display(), "loaded .viaticumignore");
            }
        }
        builder
            .build()
            .map_err(|e| WatcherError::IgnoreBuild(e.to_string()))
    }

    /// Empty matcher: no watch roots, so nothing is ignored and no path lies
    /// under a root (`should_watch_path` drops everything).
    pub fn empty() -> Self {
        Self {
            matchers: Vec::new(),
        }
    }

    /// Returns true if `path` should be skipped (not watched, not scanned).
    ///
    /// Finds the watch-dir matcher that is an ancestor of `path` and queries
    /// it. `is_dir` matters because gitignore patterns distinguish `build/`
    /// from `build` — a trailing slash matches only directories.
    ///
    /// Uses `matched_path_or_any_parents` so that a directory pattern like
    /// `target/` correctly prunes every file under `target/`. Pure `matched`
    /// only checks the leaf and would miss such subtree rules.
    ///
    /// Paths outside every watch dir fall through as "not ignored" — filtering
    /// of such stray paths is the caller's responsibility.
    pub fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        match self.matcher_of(path) {
            Some((_, gi)) => matches!(
                gi.matched_path_or_any_parents(path, is_dir),
                ignore::Match::Ignore(_)
            ),
            None => false,
        }
    }

    /// The watch root that `path` lies under (longest match), if any.
    pub fn root_of(&self, path: &Path) -> Option<&Path> {
        self.matcher_of(path).map(|(root, _)| root.as_path())
    }

    fn matcher_of(&self, path: &Path) -> Option<&(PathBuf, Gitignore)> {
        self.matchers
            .iter()
            .filter(|(root, _)| path.starts_with(root))
            .max_by_key(|(root, _)| root.components().count())
    }
}

// ─── Config ───────────────────────────────────────────────────────────────────

/// Configuration for the filesystem watcher.
pub struct WatcherConfig {
    /// Directories to watch recursively.
    pub watch_dirs: Vec<PathBuf>,
    /// Device ID stamped on each emitted DirtyEvent.
    pub device_id: DeviceId,
    /// Debounce window in milliseconds. Events arriving within this window
    /// for the same path are coalesced: only the last-seen kind is forwarded.
    pub debounce_ms: u64,
    /// Data directory for storing last_scan timestamp file.
    pub data_dir: PathBuf,
    /// Rescan interval in seconds. 0 = no periodic rescan.
    /// Default: 604800 (1 week).
    pub rescan_interval_secs: u64,
    /// Optional shared watch_states map (owned by WatchAdmin). When provided,
    /// the watcher writes status transitions into it: Scanning during scans,
    /// Idle when complete, Error on failure. None in tests that don't use
    /// WatchAdmin.
    pub watch_states: Option<Arc<RwLock<HashMap<PathBuf, WatchEntryState>>>>,
}

/// Compute the watcher debounce window (ms) for a given `time_scale`.
///
/// Production (`time_scale == 1`) uses [`viaticum_core::constants::DEBOUNCE_SECS`]
/// (30 min): a cold-backup workload coalesces rapid edits instead of re-encoding
/// on every save. Higher `time_scale` values (experiments, tests) shrink the
/// window proportionally, the same way every other time constant in the daemon is
/// scaled. Floored at 1 ms so an extreme scale never yields a zero-length window.
pub fn debounce_ms_for_time_scale(time_scale: u64) -> u64 {
    (viaticum_core::constants::DEBOUNCE_SECS * 1000 / time_scale.max(1)).max(1)
}

/// A watch folder as the watcher keys it: absolute, not canonicalized (notify
/// reports paths under the spelling it was given; symlinks in the path stay).
/// Relative paths are resolved against the current directory.
pub(crate) fn absolute_watch_dir(dir: &Path) -> PathBuf {
    std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf())
}

// ─── start_watcher ────────────────────────────────────────────────────────────

/// Start the filesystem watcher.
///
/// Spawns a tokio task that:
/// 1. Creates a `notify::RecommendedWatcher` posting to a std channel.
/// 2. Drains the std channel on a poll interval.
/// 3. Debounces events by path within `debounce_ms`.
/// 4. Sends `DirtyEvent` to `dirty_tx`.
/// 5. Exits cleanly when `cancel` is triggered.
/// 6. Processes `WatcherCommand` messages from `control_rx` to add/remove/scan dirs.
///
/// Starts cleanly with an empty watch directory list (receives `Add` commands later).
pub async fn start_watcher(
    config: WatcherConfig,
    dirty_tx: mpsc::Sender<DirtyEvent>,
    mut control_rx: mpsc::Receiver<WatcherCommand>,
    cancel: CancellationToken,
) -> Result<(), WatcherError> {
    // Mutable local list of watched directories (starts from config, grows/shrinks via commands).
    // A folder that is a Viaticum data dir or lies in its storage is refused
    // (backup-i13): Error with the reason, never watched, never scanned, and not a
    // root of the IgnoreSet — so no event under it can pass the filter (W2).
    let mut watch_dirs: Vec<PathBuf> = Vec::with_capacity(config.watch_dirs.len());
    for dir in &config.watch_dirs {
        if let Some(refusal) = refuse_folder(dir) {
            refuse(&config.watch_states, dir, &refusal);
        } else if !watch_dirs.contains(dir) {
            watch_dirs.push(dir.clone());
        }
    }

    // Build the ignore matcher; share via ArcSwap so notify callback always sees the latest.
    let ignore_arc: Arc<ArcSwap<IgnoreSet>> =
        Arc::new(ArcSwap::new(Arc::new(IgnoreSet::build(&watch_dirs)?)));

    // Bridge: notify → std channel → tokio task.
    let (std_tx, std_rx) = std_mpsc::channel::<(PathBuf, DirtyKind)>();

    // Build the notify watcher. The closure runs in a thread managed by notify.
    let std_tx_clone = std_tx.clone();
    let ignore_for_notify = Arc::clone(&ignore_arc);
    // Symlinks to directories are not followed (W4): a link to an ancestor would
    // loop, a link elsewhere would pull a foreign part of the disk into the backup.
    let notify_config = notify::Config::default().with_follow_symlinks(false);
    let mut watcher_inner = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| match res {
            Ok(event) => {
                if let Some(kind) = classify_event(&event.kind) {
                    for path in &event.paths {
                        let ig = ignore_for_notify.load();
                        if should_watch_path(path, &ig) {
                            let _ = std_tx_clone.send((path.clone(), kind));
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("watcher notify error: {e}");
            }
        },
        notify_config,
    )?;

    // Register all directories (empty list = no-op). A folder that cannot be
    // watched (missing — a USB disk or NAS share not mounted yet —, unreadable
    // subfolder, inotify limit) must not stop the others (daemon-i3): it is marked
    // Error with the reason and the rest carry on. It stays a root of the
    // IgnoreSet and is scanned (backup-i17): whatever is readable is backed up,
    // and live events from the part of the tree notify did put under watch pass.
    // Scans leave its Error in place. A missing folder yields nothing; its files
    // are NOT treated as deleted (dr-i10: absence is not deletion).
    let mut watch_failed: HashSet<PathBuf> = HashSet::new();
    for dir in &watch_dirs {
        match watcher_inner.watch(dir, RecursiveMode::Recursive) {
            Ok(()) => tracing::info!(dir = %dir.display(), "watching directory"),
            Err(e) => {
                let reason = describe_watch_error(&e);
                tracing::warn!(
                    path = %dir.display(), error = %reason,
                    "watch folder unavailable; other folders keep being backed up"
                );
                set_status(
                    &config.watch_states,
                    dir,
                    WatcherStatusSignal::Error,
                    Some(reason),
                );
                watch_failed.insert(dir.clone());
            }
        }
    }

    // ── Initial / periodic scan ────────────────────────────────────────────
    let scan_marker = config.data_dir.join("last_scan");
    let needs_scan = should_run_scan(&scan_marker, config.rescan_interval_secs);
    if needs_scan && !watch_dirs.is_empty() {
        for dir in &watch_dirs {
            set_scan_status(
                &config.watch_states,
                &watch_failed,
                dir,
                WatcherStatusSignal::Scanning,
            );
        }
        let ig = ignore_arc.load();
        let count = run_full_scan(&watch_dirs, config.device_id, &dirty_tx, &ig).await;
        // Write current timestamp as marker.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = std::fs::write(&scan_marker, now.to_string());
        for dir in &watch_dirs {
            set_scan_status(
                &config.watch_states,
                &watch_failed,
                dir,
                WatcherStatusSignal::Idle,
            );
        }
        tracing::info!(files = count, "initial/periodic scan complete");
    } else if watch_dirs.is_empty() {
        tracing::info!("watcher started with empty watch list; awaiting Add commands");
    } else {
        tracing::info!("scan skipped (last scan recent enough)");
    }

    // Debounce state: path → (kind, deadline).
    let mut pending: HashMap<PathBuf, (DirtyKind, Instant)> = HashMap::new();
    let debounce_dur = std::time::Duration::from_millis(config.debounce_ms.max(1));

    // Poll the std channel at quarter-debounce resolution (min 10 ms).
    let poll_ms = (config.debounce_ms / 4).max(10);
    let mut poll_timer = interval(Duration::from_millis(poll_ms));

    // Periodic rescan timer; `rescan_interval_secs == 0` disables it. A huge
    // period is not a substitute: tokio computes `deadline + period` for the
    // next tick and panics on `Instant` overflow.
    let mut rescan_timer = if config.rescan_interval_secs > 0 {
        let mut t = interval(Duration::from_secs(config.rescan_interval_secs));
        t.tick().await; // skip immediate first tick
        Some(t)
    } else {
        None
    };

    // Keep watcher alive for the duration of this async function.
    // Must be mut so we can call watch()/unwatch() on Add/Remove commands.
    let mut notify_watcher = watcher_inner;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("watcher: cancel requested, exiting");
                break;
            }
            _ = async {
                match rescan_timer.as_mut() {
                    Some(t) => { t.tick().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                if !watch_dirs.is_empty() {
                    for dir in &watch_dirs {
                        set_scan_status(&config.watch_states, &watch_failed, dir,
                            WatcherStatusSignal::Scanning);
                    }
                    let ig = ignore_arc.load();
                    let count = run_full_scan(
                        &watch_dirs,
                        config.device_id,
                        &dirty_tx,
                        &ig,
                    ).await;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let _ = std::fs::write(&scan_marker, now.to_string());
                    for dir in &watch_dirs {
                        set_scan_status(&config.watch_states, &watch_failed, dir,
                            WatcherStatusSignal::Idle);
                    }
                    tracing::info!(files = count, "periodic rescan complete");
                }
            }
            Some(cmd) = control_rx.recv() => {
                match cmd {
                    WatcherCommand::Add { path, importance: _ } => {
                        if let Some(refusal) = refuse_folder(&path) {
                            refuse(&config.watch_states, &path, &refusal);
                        } else {
                            // A failed watch still makes the folder a root and
                            // gets it scanned (backup-i17); its status stays Error.
                            watch_failed.remove(&path);
                            if let Err(e) = notify_watcher.watch(&path, RecursiveMode::Recursive) {
                                let reason = describe_watch_error(&e);
                                tracing::warn!(
                                    path = %path.display(), error = %reason,
                                    "watcher: failed to watch new directory"
                                );
                                set_status(&config.watch_states, &path,
                                    WatcherStatusSignal::Error, Some(reason));
                                watch_failed.insert(path.clone());
                            }
                            if !watch_dirs.contains(&path) {
                                watch_dirs.push(path.clone());
                            }
                            // Rebuild IgnoreSet for all current dirs.
                            match IgnoreSet::build(&watch_dirs) {
                                Ok(new_set) => {
                                    ignore_arc.store(Arc::new(new_set));
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "watcher: IgnoreSet rebuild failed");
                                }
                            }
                            // Trigger initial scan of the new dir only.
                            set_scan_status(&config.watch_states, &watch_failed, &path,
                                WatcherStatusSignal::Scanning);
                            let ig = ignore_arc.load();
                            let count = run_full_scan_one(
                                &path, config.device_id, &dirty_tx, &ig
                            ).await;
                            tracing::info!(
                                dir = %path.display(), files = count,
                                "watcher: initial scan of newly added dir"
                            );
                            set_scan_status(&config.watch_states, &watch_failed, &path,
                                WatcherStatusSignal::Idle);
                        }
                    }
                    WatcherCommand::Remove { path } => {
                        let _ = notify_watcher.unwatch(&path);
                        watch_dirs.retain(|d| d != &path);
                        watch_failed.remove(&path);
                        match IgnoreSet::build(&watch_dirs) {
                            Ok(new_set) => { ignore_arc.store(Arc::new(new_set)); }
                            Err(e) => { tracing::warn!(error = %e, "watcher: IgnoreSet rebuild"); }
                        }
                    }
                    WatcherCommand::Scan { path } => {
                        // The root of every scan goes through refuse_folder (W2): a
                        // refused folder keeps its error, Scan does not turn it Idle.
                        if let Some(refusal) = refuse_folder(&path) {
                            tracing::info!(path = %path.display(), reason = %refusal,
                                "manual scan skipped: folder refused");
                            set_status(&config.watch_states, &path,
                                WatcherStatusSignal::Error, Some(refusal.to_string()));
                        } else {
                            set_scan_status(&config.watch_states, &watch_failed, &path,
                                WatcherStatusSignal::Scanning);
                            let ig = ignore_arc.load();
                            let count = run_full_scan_one(
                                &path, config.device_id, &dirty_tx, &ig
                            ).await;
                            tracing::info!(
                                dir = %path.display(), files = count,
                                "watcher: manual rescan complete"
                            );
                            set_scan_status(&config.watch_states, &watch_failed, &path,
                                WatcherStatusSignal::Idle);
                        }
                    }
                }
            }
            _ = poll_timer.tick() => {
                // Drain all pending std-channel messages.
                loop {
                    match std_rx.try_recv() {
                        Ok((path, kind)) => {
                            pending.insert(path, (kind, Instant::now() + debounce_dur));
                        }
                        Err(std_mpsc::TryRecvError::Empty) => break,
                        Err(std_mpsc::TryRecvError::Disconnected) => {
                            tracing::error!("watcher: std channel disconnected unexpectedly");
                            return Ok(());
                        }
                    }
                }

                // Flush all events whose debounce window has expired.
                let ig = ignore_arc.load();
                let mut data_dirs: HashMap<PathBuf, bool> = HashMap::new();
                let now = Instant::now();
                let mut to_flush: Vec<(PathBuf, DirtyKind)> = Vec::new();
                pending.retain(|path, (kind, deadline)| {
                    if now >= *deadline {
                        to_flush.push((path.clone(), *kind));
                        false
                    } else {
                        true
                    }
                });

                for (path, kind) in to_flush {
                    // A path under no root: its folder was removed meanwhile (N3).
                    let Some(root) = ig.root_of(&path) else {
                        tracing::debug!(path = %path.display(),
                            "watcher: event outside every watch folder dropped");
                        continue;
                    };
                    // Inside a Viaticum data dir below the root: the daemon's own
                    // writes (db.redb, holdings, staging) never enter the backup.
                    if data_dir_between(root, &path, &mut data_dirs) {
                        tracing::debug!(path = %path.display(),
                            "watcher: event inside a Viaticum data directory dropped");
                        continue;
                    }
                    if path.symlink_metadata().is_ok_and(|m| m.file_type().is_symlink())
                        && symlink_into_data_dir(&path, &mut data_dirs)
                    {
                        tracing::debug!(path = %path.display(),
                            "watcher: event of a symlink into a Viaticum data directory dropped");
                        continue;
                    }
                    let path_str = path.to_string_lossy().into_owned();
                    let event = DirtyEvent {
                        path: path_str,
                        kind,
                        device_id: config.device_id,
                    };
                    if dirty_tx.send(event).await.is_err() {
                        tracing::debug!("watcher: dirty_tx receiver dropped, exiting");
                        return Ok(());
                    }
                }
            }
        }
    }

    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Map a notify EventKind to a DirtyKind. Returns None for events we ignore.
fn classify_event(kind: &EventKind) -> Option<DirtyKind> {
    match kind {
        EventKind::Create(_) => Some(DirtyKind::Added),
        EventKind::Modify(
            ModifyKind::Data(_) | ModifyKind::Any | ModifyKind::Other | ModifyKind::Name(_),
        ) => Some(DirtyKind::Modified),
        EventKind::Remove(RemoveKind::File | RemoveKind::Any | RemoveKind::Other) => {
            Some(DirtyKind::Deleted)
        }
        EventKind::Modify(ModifyKind::Metadata(_)) => None, // metadata-only: ignore
        EventKind::Access(_) => None,                       // reads: ignore
        EventKind::Remove(RemoveKind::Folder) => None,      // directory removal: ignore
        _ => None,
    }
}

/// Human-readable reason a folder could not be put under watch (shown in
/// `/api/watches` and the log). Names the kernel knob for the inotify limit.
pub(crate) fn describe_watch_error(e: &notify::Error) -> String {
    match &e.kind {
        notify::ErrorKind::PathNotFound => "folder does not exist".to_string(),
        notify::ErrorKind::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
            "folder does not exist".to_string()
        }
        notify::ErrorKind::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => {
            "permission denied".to_string()
        }
        notify::ErrorKind::MaxFilesWatch => "inotify watch limit reached \
             (raise fs.inotify.max_user_watches)"
            .to_string(),
        _ => e.to_string(),
    }
}

/// Check whether a full scan is needed based on last_scan marker file.
fn should_run_scan(marker: &std::path::Path, interval_secs: u64) -> bool {
    let contents = match std::fs::read_to_string(marker) {
        Ok(c) => c,
        Err(_) => return true, // no marker = never scanned
    };
    let last_ts: u64 = match contents.trim().parse() {
        Ok(v) => v,
        Err(_) => return true,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(last_ts) >= interval_secs
}

/// Update the shared watch_states map for a single path, preserving last_event_at.
/// No-op when watch_states is None (tests without WatchAdmin).
fn set_status(
    states: &Option<Arc<RwLock<HashMap<PathBuf, WatchEntryState>>>>,
    path: &Path,
    signal: WatcherStatusSignal,
    error: Option<String>,
) {
    let Some(states) = states else { return };
    let Ok(mut map) = states.write() else { return };
    let prev_event_at = map.get(path).and_then(|s| s.last_event_at);
    map.insert(
        path.to_path_buf(),
        WatchEntryState {
            status: signal,
            error,
            last_changed: Instant::now(),
            last_event_at: prev_event_at,
        },
    );
}

/// Scanning/Idle around a scan, except for a folder whose `watch()` failed: it
/// keeps its Error (backup-i17), a scan does not mean it is being watched.
fn set_scan_status(
    states: &Option<Arc<RwLock<HashMap<PathBuf, WatchEntryState>>>>,
    watch_failed: &HashSet<PathBuf>,
    path: &Path,
    signal: WatcherStatusSignal,
) {
    if !watch_failed.contains(path) {
        set_status(states, path, signal, None);
    }
}

/// A watch folder that is refused (backup-i13): Error with the reason, WARN.
fn refuse(
    states: &Option<Arc<RwLock<HashMap<PathBuf, WatchEntryState>>>>,
    dir: &Path,
    refusal: &FolderRefusal,
) {
    tracing::warn!(path = %dir.display(), reason = %refusal, "watch folder refused");
    set_status(
        states,
        dir,
        WatcherStatusSignal::Error,
        Some(refusal.to_string()),
    );
}

/// Walk a single directory and emit DirtyEvent::Added for every non-ignored file.
///
/// Never descends into: a hidden directory; one pruned by `.viaticumignore` /
/// defaults; a Viaticum data directory (INFO `data directory excluded from backup`);
/// a symlink to a directory (not followed, W4; a symlink to a file inside a data
/// dir is skipped, backup-i16); a directory already visited (same
/// `(st_dev, st_ino)` — a bind mount of an ancestor). A root that is itself refused
/// (a data dir, or inside daemon storage) yields nothing.
pub(crate) async fn run_full_scan_one(
    dir: &Path,
    device_id: DeviceId,
    dirty_tx: &mpsc::Sender<DirtyEvent>,
    ignore_set: &IgnoreSet,
) -> u64 {
    if let Some(refusal) = refuse_folder(dir) {
        tracing::warn!(dir = %dir.display(), reason = %refusal, "scan skipped: folder refused");
        return 0;
    }
    let mut count: u64 = 0;
    let mut visited: HashSet<exclude::DirKey> = HashSet::new();
    let mut data_dirs: HashMap<PathBuf, bool> = HashMap::new();
    if let Some(key) = exclude::dir_key(dir) {
        visited.insert(key);
    }
    // Use a stack-based walk to avoid recursion depth issues.
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(dir = %current.display(), error = %e, "scan: cannot read directory");
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // file_type() does not follow symlinks.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                match path.metadata() {
                    Ok(meta) if meta.is_dir() => {
                        tracing::debug!(path = %path.display(),
                            "scan: symlink to a directory not followed");
                        continue;
                    }
                    // Dangling or looping link: nothing to read.
                    Err(_) => continue,
                    Ok(_) if symlink_into_data_dir(&path, &mut data_dirs) => {
                        tracing::info!(path = %path.display(),
                            "scan: symlink into a Viaticum data directory skipped");
                        continue;
                    }
                    Ok(_) => {}
                }
            }
            if file_type.is_dir() {
                // Skip hidden directories.
                if path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with('.'))
                {
                    continue;
                }
                // Prune subtrees matched by .viaticumignore / defaults.
                if ignore_set.is_ignored(&path, true) {
                    continue;
                }
                if is_viaticum_data_dir(&path) {
                    tracing::info!(dir = %path.display(), "data directory excluded from backup");
                    continue;
                }
                if let Some(key) = exclude::dir_key(&path)
                    && !visited.insert(key)
                {
                    tracing::debug!(dir = %path.display(), "scan: directory already visited");
                    continue;
                }
                stack.push(path);
            } else if should_watch_path(&path, ignore_set) {
                let event = DirtyEvent {
                    path: path.to_string_lossy().into_owned(),
                    kind: DirtyKind::Added,
                    device_id,
                };
                if dirty_tx.send(event).await.is_err() {
                    return count;
                }
                count += 1;
            }
        }
    }
    count
}

/// Walk all watch directories and emit DirtyEvent::Added for every file found.
///
/// Directories matching `ignore_set` are pruned at descent time (no files
/// under an ignored directory are emitted). Individual files are checked via
/// [`should_watch_path`] using the same matcher.
async fn run_full_scan(
    dirs: &[PathBuf],
    device_id: DeviceId,
    dirty_tx: &mpsc::Sender<DirtyEvent>,
    ignore_set: &IgnoreSet,
) -> u64 {
    let mut count: u64 = 0;
    for dir in dirs {
        count += run_full_scan_one(dir, device_id, dirty_tx, ignore_set).await;
    }
    count
}

/// Returns true if the path should trigger a DirtyEvent.
///
/// Filters out:
/// - Paths with no filename component
/// - Paths under no watch root (a folder removed meanwhile, or never watched)
/// - Anything with a hidden component below its watch root (backup-i14): the
///   same rule the scan applies when it skips hidden directories
/// - Paths matched by the ignore set (`.viaticumignore` + defaults)
/// - Directories (if stat is available)
///
/// Viaticum data directories below the root are dropped at flush time
/// ([`data_dir_between`]): that check stats every ancestor, too costly here.
pub(crate) fn should_watch_path(path: &std::path::Path, ignore_set: &IgnoreSet) -> bool {
    // Require a filename component.
    if path.file_name().is_none() {
        return false;
    }

    let Some(root) = ignore_set.root_of(path) else {
        return false;
    };

    // Skip hidden files and everything under a hidden directory below the root.
    if has_hidden_component_below(root, path) {
        return false;
    }

    // Ignore-set match (files).
    if ignore_set.is_ignored(path, false) {
        return false;
    }

    // Only regular files. If stat fails (deleted file), allow through.
    match path.metadata() {
        Ok(meta) => meta.is_file(),
        Err(_) => true,
    }
}
