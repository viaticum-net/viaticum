// The watcher's state between notify and the backup channel (L0, К3): debounce, the
// resolution of a move by the disk, the watch root rule, overflow rescans, rechecks,
// WatchAdmin commands. `start_watcher` owns the notify callback and the select loop and
// hands everything else to `WatchLoop`, which unit tests drive with synthetic events.
//
// Rules (spec c_l0_l1_watcher_rollback.md §2.2 К3; delete-i12, backup-i22, dr-i64):
// - a move (`Modify(Name(_))`, and `Remove(Folder)`) is resolved at the end of its
//   debounce by what is on disk: path gone → deletion; a file → `Added`; a directory →
//   a scan of its subtree;
// - a deletion is sent only while the watch root is on disk and is the recorded
//   directory (`RootId`); otherwise the root rule fires once: `RootLost` (or
//   `RootChanged` for another directory) to the backup (no deletion, recent deletions
//   undone, confirmations dropped), unwatch, the folder in error, and events under it
//   dropped until it heals (manual Scan, periodic scan: the root exists and is not empty
//   → new identity, error cleared, scan);
// - the same check runs at start and before every scan: a recorded root missing or
//   replaced gets the root rule (a loss whose event died with a shutdown inside the
//   debounce, or happened while the daemon was down); a new root is recorded only when
//   it is not empty (an unmounted mount point is never an identity);
// - an inotify overflow (`Rescan` flag) → WARN and a full scan after a quiet window;
// - a recheck (a rebuild did not find a path) → `GoneOnRecheck` when the root is intact,
//   not in error, the path is gone and its parent exists and is not empty.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use viaticum_core::types::DeviceId;

use super::roots::{RootId, RootStore, non_empty_dir};
use super::{
    IgnoreSet, WatcherCommand, data_dir_between, describe_watch_error, is_viaticum_data_dir,
    refuse, refuse_folder, run_full_scan_one, set_scan_status, set_status, symlink_into_data_dir,
};
use crate::daemon::backup::{DirtyEvent, DirtyKind, path_gone};
use crate::daemon::watch_admin::{WatchEntryState, WatcherStatusSignal};

/// Error shown for a watch folder under the root rule (dr-i64).
pub(crate) const ROOT_LOST_ERROR: &str = "folder was moved, renamed or removed; its files stay \
     in the backup; press Scan or restart when it is back";

/// What a debounced path will be resolved as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingKind {
    /// A plain event: sent as this kind (a deletion still passes the root check).
    Dirty(DirtyKind),
    /// A rename or a directory removal: resolved by the disk at the end of the debounce.
    Moved,
}

/// One item from the notify callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Raw {
    Path(PathBuf, PendingKind),
    /// The kernel queue overflowed: events were lost.
    Rescan,
}

/// A path waiting out its debounce.
struct Pending {
    kind: PendingKind,
    deadline: Instant,
    /// Its first event in this window was a creation: if it is gone at the end, it
    /// was created and gone within the debounce (an atomic-save tmp, a `.part`) and
    /// there is nothing to delete.
    born: bool,
}

/// The dirty channel is closed: the daemon is shutting down.
#[derive(Debug)]
pub(crate) struct Closed;

/// A watch root on disk against its recorded identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootCheck {
    /// The recorded directory.
    Same,
    /// Nothing recorded (a new root, or one that was empty or missing so far).
    NoRecord,
    /// Recorded, and gone from disk.
    Lost,
    /// Recorded, and another directory stands at the path.
    Changed,
}

/// Fixed parameters of the loop.
pub(crate) struct LoopParams {
    pub(crate) device_id: DeviceId,
    pub(crate) debounce: Duration,
    pub(crate) data_dir: PathBuf,
    pub(crate) watch_states: Option<Arc<RwLock<HashMap<PathBuf, WatchEntryState>>>>,
    /// A recheck of the same path more often than this is ignored.
    pub(crate) recheck_every: Duration,
}

pub(crate) struct WatchLoop {
    params: LoopParams,
    dirty_tx: mpsc::Sender<DirtyEvent>,
    notify: RecommendedWatcher,
    pub(crate) ignore: Arc<ArcSwap<IgnoreSet>>,
    pub(crate) watch_dirs: Vec<PathBuf>,
    pub(crate) watch_failed: HashSet<PathBuf>,
    roots: RootStore,
    /// Roots under the root rule (error until they heal).
    pub(crate) lost: HashSet<PathBuf>,
    pending: HashMap<PathBuf, Pending>,
    rescan_due: Option<Instant>,
    recheck_seen: HashMap<PathBuf, Instant>,
}

impl WatchLoop {
    pub(crate) fn new(
        params: LoopParams,
        dirty_tx: mpsc::Sender<DirtyEvent>,
        notify: RecommendedWatcher,
        ignore: Arc<ArcSwap<IgnoreSet>>,
        watch_dirs: Vec<PathBuf>,
    ) -> Self {
        let roots = RootStore::load(&params.data_dir);
        WatchLoop {
            params,
            dirty_tx,
            notify,
            ignore,
            watch_dirs,
            watch_failed: HashSet::new(),
            roots,
            lost: HashSet::new(),
            pending: HashMap::new(),
            rescan_due: None,
            recheck_seen: HashMap::new(),
        }
    }

    // ── Start ──────────────────────────────────────────────────────────────────

    /// Put every folder under watch. One that cannot be watched (missing — a USB disk
    /// or NAS share not mounted yet —, unreadable subfolder, inotify limit) does not
    /// stop the others (daemon-i3): Error with the reason; it stays a root of the
    /// IgnoreSet and is scanned (backup-i17). A missing folder yields nothing; its files
    /// are NOT treated as deleted (dr-i64).
    pub(crate) fn register_all(&mut self) {
        for dir in self.watch_dirs.clone() {
            match self.notify.watch(&dir, RecursiveMode::Recursive) {
                Ok(()) => tracing::info!(dir = %dir.display(), "watching directory"),
                Err(e) => {
                    let reason = describe_watch_error(&e);
                    tracing::warn!(
                        path = %dir.display(), error = %reason,
                        "watch folder unavailable; other folders keep being backed up"
                    );
                    set_status(
                        &self.params.watch_states,
                        &dir,
                        WatcherStatusSignal::Error,
                        Some(reason),
                    );
                    self.watch_failed.insert(dir);
                }
            }
        }
    }

    /// Compare every root with `watch_roots.json` (BLOCK-2 of the L0 review): a recorded
    /// root that is missing, or another directory, gets the root rule — it may have gone
    /// while the daemon was down, or within the debounce before a shutdown, after its
    /// first files were already marked deleted. A root seen for the first time is
    /// recorded, unless it is empty (an unmounted mount point is never taken as a root).
    pub(crate) async fn check_roots_at_start(&mut self) -> Result<(), Closed> {
        self.roots.retain(&self.watch_dirs);
        for dir in self.watch_dirs.clone() {
            self.verify_root(&dir).await?;
        }
        Ok(())
    }

    // ── Events ─────────────────────────────────────────────────────────────────

    /// Take one item from the callback. A path waits out the debounce (the last kind
    /// seen wins); an overflow schedules a full scan after a quiet window.
    pub(crate) fn ingest(&mut self, raw: Raw, now: Instant) {
        match raw {
            Raw::Path(path, kind) => {
                let deadline = now + self.params.debounce;
                let born = match self.pending.get(&path) {
                    Some(p) => p.born,
                    None => kind == PendingKind::Dirty(DirtyKind::Added),
                };
                self.pending.insert(
                    path,
                    Pending {
                        kind,
                        deadline,
                        born,
                    },
                );
            }
            Raw::Rescan => {
                if self.rescan_due.is_none() {
                    tracing::warn!(
                        "inotify event queue overflowed; watched folders will be rescanned"
                    );
                }
                self.rescan_due = Some(now + self.params.debounce);
            }
        }
    }

    /// Resolve every path whose debounce ended by `now`, then run a due overflow scan.
    pub(crate) async fn flush_due(&mut self, now: Instant) -> Result<(), Closed> {
        let mut due: Vec<(PathBuf, PendingKind, bool)> = Vec::new();
        self.pending.retain(|path, p| {
            if now >= p.deadline {
                due.push((path.clone(), p.kind, p.born));
                false
            } else {
                true
            }
        });
        let mut data_dirs: HashMap<PathBuf, bool> = HashMap::new();
        for (path, kind, born) in due {
            self.resolve(path, kind, born, &mut data_dirs).await?;
        }
        if self.rescan_due.is_some_and(|t| now >= t) {
            self.rescan_due = None;
            let count = self.scan_roots(&self.active_roots()).await?;
            tracing::info!(files = count, "watcher: overflow rescan complete");
        }
        Ok(())
    }

    async fn resolve(
        &mut self,
        path: PathBuf,
        kind: PendingKind,
        born: bool,
        data_dirs: &mut HashMap<PathBuf, bool>,
    ) -> Result<(), Closed> {
        let ig = self.ignore.load_full();
        // A path under no root: its folder was removed meanwhile (N3).
        let Some(root) = ig.root_of(&path).map(Path::to_path_buf) else {
            tracing::debug!(path = %path.display(), "watcher: event outside every watch folder dropped");
            return Ok(());
        };
        if self.lost.contains(&root) {
            tracing::debug!(path = %path.display(), "watcher: event under a folder in error dropped");
            return Ok(());
        }
        // Inside a Viaticum data dir below the root: the daemon's own writes (db.redb,
        // holdings, staging) never enter the backup.
        if data_dir_between(&root, &path, data_dirs) {
            tracing::debug!(path = %path.display(),
                "watcher: event inside a Viaticum data directory dropped");
            return Ok(());
        }
        if path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
            && symlink_into_data_dir(&path, data_dirs)
        {
            tracing::debug!(path = %path.display(),
                "watcher: event of a symlink into a Viaticum data directory dropped");
            return Ok(());
        }
        self.record_if_new(&root);
        match kind {
            // A removal is resolved by the disk too: a path that is back (a file) is
            // `Added`, not deleted.
            PendingKind::Dirty(DirtyKind::Deleted) | PendingKind::Moved => {
                self.resolve_moved(&root, &path, born, &ig).await
            }
            PendingKind::Dirty(kind) => self.emit(&path, kind).await,
        }
    }

    /// A move by what is on disk now (Р-1): gone → deletion; a file → `Added`; a
    /// directory → a scan of its subtree (Р-3); the root itself → the identity decides.
    async fn resolve_moved(
        &mut self,
        root: &Path,
        path: &Path,
        born: bool,
        ig: &IgnoreSet,
    ) -> Result<(), Closed> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return self.deletion(root, path, born).await;
            }
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "watcher: moved path unreadable; dropped");
                return Ok(());
            }
        };
        if path == root {
            return match self.check_root(root) {
                RootCheck::Same => Ok(()),
                RootCheck::Changed => self.root_rule(root, DirtyKind::RootChanged).await,
                RootCheck::Lost | RootCheck::NoRecord => {
                    self.root_rule(root, DirtyKind::RootLost).await
                }
            };
        }
        if meta.is_dir() {
            if ig.is_ignored(path, true) || is_viaticum_data_dir(path) {
                tracing::debug!(path = %path.display(), "watcher: moved-in directory excluded");
                return Ok(());
            }
            let count = run_full_scan_one(path, self.params.device_id, &self.dirty_tx, ig).await;
            if self.dirty_tx.is_closed() {
                return Err(Closed);
            }
            tracing::info!(dir = %path.display(), files = count, "watcher: moved-in directory scanned");
            return Ok(());
        }
        let is_file = if meta.file_type().is_symlink() {
            // A symlink to a file is backed up; one to a directory is not followed (W4).
            path.metadata().is_ok_and(|m| m.is_file())
        } else {
            meta.is_file()
        };
        if is_file {
            self.emit(path, DirtyKind::Added).await
        } else {
            Ok(())
        }
    }

    /// `path` is gone: a deletion while its root is the recorded directory, else the
    /// root rule. A path created and gone within the debounce has nothing to delete.
    async fn deletion(&mut self, root: &Path, path: &Path, born: bool) -> Result<(), Closed> {
        match self.check_root(root) {
            RootCheck::Same => {}
            RootCheck::Changed => return self.root_rule(root, DirtyKind::RootChanged).await,
            // No record: no deletion without a known root (the safe side) — except for a
            // path created and gone within the debounce, which has nothing to delete.
            RootCheck::NoRecord if born => {}
            RootCheck::Lost | RootCheck::NoRecord => {
                return self.root_rule(root, DirtyKind::RootLost).await;
            }
        }
        if born {
            tracing::debug!(path = %path.display(),
                "watcher: created and gone within the debounce; nothing to delete");
            return Ok(());
        }
        self.emit(path, DirtyKind::Deleted).await
    }

    fn check_root(&self, root: &Path) -> RootCheck {
        match (RootId::of(root), self.roots.get(root)) {
            (_, None) => RootCheck::NoRecord,
            (None, Some(_)) => RootCheck::Lost,
            (Some(now), Some(recorded)) if now.same_dir(recorded) => RootCheck::Same,
            (Some(_), Some(_)) => RootCheck::Changed,
        }
    }

    /// The root is on disk and is the recorded directory.
    fn root_intact(&self, root: &Path) -> bool {
        self.check_root(root) == RootCheck::Same
    }

    /// Record a root seen for the first time — only when it is a non-empty directory
    /// (W1 b: an empty one may be an unmounted mount point).
    fn record_if_new(&mut self, root: &Path) {
        if self.roots.get(root).is_none()
            && !self.lost.contains(root)
            && non_empty_dir(root)
            && let Some(id) = RootId::of(root)
        {
            self.roots.set(root, id);
        }
    }

    /// On start and before a scan: a recorded root that is missing or another directory
    /// gets the root rule (BLOCK-2); a new non-empty one is recorded.
    async fn verify_root(&mut self, root: &Path) -> Result<(), Closed> {
        match self.check_root(root) {
            RootCheck::Same => Ok(()),
            RootCheck::NoRecord => {
                self.record_if_new(root);
                Ok(())
            }
            RootCheck::Lost => self.root_rule(root, DirtyKind::RootLost).await,
            RootCheck::Changed => self.root_rule(root, DirtyKind::RootChanged).await,
        }
    }

    /// The root rule (Р-4, dr-i64), once per loss: `kind` (`RootLost` or `RootChanged`)
    /// to the backup (no deletion, recent deletions undone, confirmations dropped),
    /// unwatch, the same visible folder error for both (W1 c), events under it dropped
    /// until it heals on a Scan or a periodic scan.
    async fn root_rule(&mut self, root: &Path, kind: DirtyKind) -> Result<(), Closed> {
        if !self.lost.insert(root.to_path_buf()) {
            return Ok(());
        }
        let _ = self.notify.unwatch(root);
        self.pending.retain(|p, _| !p.starts_with(root));
        set_status(
            &self.params.watch_states,
            root,
            WatcherStatusSignal::Error,
            Some(ROOT_LOST_ERROR.to_string()),
        );
        if kind == DirtyKind::RootChanged {
            tracing::warn!(folder = %root.display(),
                "watch folder is another directory than the recorded one: no file under it \
                 is deleted; folder in error until a scan accepts it");
        } else {
            tracing::warn!(folder = %root.display(),
                "watch folder moved, renamed or removed: no file under it is deleted; \
                 folder in error until it is back");
        }
        self.emit(root, kind).await
    }

    async fn emit(&self, path: &Path, kind: DirtyKind) -> Result<(), Closed> {
        let event = DirtyEvent {
            path: path.to_string_lossy().into_owned(),
            kind,
            device_id: self.params.device_id,
        };
        self.dirty_tx.send(event).await.map_err(|_| Closed)
    }

    // ── Recheck ────────────────────────────────────────────────────────────────

    /// A rebuild did not find `path` (delete-i12 (в)). `GoneOnRecheck` when the root is
    /// intact and not in error, the path is gone, and its parent exists and is not empty
    /// (an unmounted or emptied folder is not a deletion). A path rechecked within
    /// `recheck_every` is ignored.
    pub(crate) async fn on_recheck(&mut self, path: PathBuf, now: Instant) -> Result<(), Closed> {
        let every = self.params.recheck_every;
        if self
            .recheck_seen
            .get(&path)
            .is_some_and(|t| now.saturating_duration_since(*t) < every)
        {
            return Ok(());
        }
        if self.recheck_seen.len() > 10_000 {
            self.recheck_seen
                .retain(|_, t| now.saturating_duration_since(*t) < every);
        }
        self.recheck_seen.insert(path.clone(), now);

        let ig = self.ignore.load_full();
        let Some(root) = ig.root_of(&path).map(Path::to_path_buf) else {
            tracing::debug!(path = %path.display(), "recheck: path under no watch folder");
            return Ok(());
        };
        if self.lost.contains(&root) || !self.root_intact(&root) {
            tracing::debug!(path = %path.display(), "recheck: watch folder in error or changed; kept");
            return Ok(());
        }
        if !path_gone(&path) {
            return Ok(());
        }
        let parent_has_entries = path
            .parent()
            .and_then(|p| std::fs::read_dir(p).ok())
            .is_some_and(|mut entries| entries.next().is_some());
        if !parent_has_entries {
            tracing::debug!(path = %path.display(), "recheck: parent missing or empty; kept");
            return Ok(());
        }
        tracing::info!(path = %path.display(), "watcher: recheck: path gone, treated as deletion");
        self.emit(&path, DirtyKind::GoneOnRecheck).await
    }

    // ── Scans and commands ─────────────────────────────────────────────────────

    /// Roots not under the root rule.
    pub(crate) fn active_roots(&self) -> Vec<PathBuf> {
        self.watch_dirs
            .iter()
            .filter(|d| !self.lost.contains(*d))
            .cloned()
            .collect()
    }

    /// Scan `roots` with Scanning/Idle around (a folder whose watch failed keeps Error).
    pub(crate) async fn scan_roots(&self, roots: &[PathBuf]) -> Result<u64, Closed> {
        let states = &self.params.watch_states;
        for dir in roots {
            set_scan_status(
                states,
                &self.watch_failed,
                dir,
                WatcherStatusSignal::Scanning,
            );
        }
        let ig = self.ignore.load_full();
        let mut count = 0;
        for dir in roots {
            count += run_full_scan_one(dir, self.params.device_id, &self.dirty_tx, &ig).await;
        }
        if self.dirty_tx.is_closed() {
            return Err(Closed);
        }
        for dir in roots {
            set_scan_status(states, &self.watch_failed, dir, WatcherStatusSignal::Idle);
        }
        Ok(count)
    }

    /// The periodic scan: folders already in error try to heal (and are scanned by the
    /// heal); every other root is checked against its record (BLOCK-2: a missing or
    /// replaced root gets the root rule and waits for the next scan to heal), then scanned.
    pub(crate) async fn periodic_scan(&mut self) -> Result<u64, Closed> {
        let mut healed = Vec::new();
        for root in self.lost.clone() {
            if self.try_heal(&root, false).await? {
                healed.push(root);
            }
        }
        for root in self.active_roots() {
            if !healed.contains(&root) {
                self.verify_root(&root).await?;
            }
        }
        let roots: Vec<PathBuf> = self
            .active_roots()
            .into_iter()
            .filter(|r| !healed.contains(r))
            .collect();
        self.scan_roots(&roots).await
    }

    /// Self-heal of a folder under the root rule (Р-13): it exists, is a directory and is
    /// not empty → watch it again, record its identity, clear the error, scan it (the scan
    /// confirms what is there). Otherwise the error stays.
    async fn try_heal(&mut self, root: &Path, manual: bool) -> Result<bool, Closed> {
        let back = RootId::of(root).is_some() && non_empty_dir(root);
        if !back {
            if manual {
                tracing::info!(folder = %root.display(), "manual scan skipped: folder unavailable");
            }
            return Ok(false);
        }
        if let Err(e) = self.notify.watch(root, RecursiveMode::Recursive) {
            tracing::warn!(folder = %root.display(), error = %describe_watch_error(&e),
                "watcher: folder is back but cannot be watched; error stays");
            return Ok(false);
        }
        if let Some(id) = RootId::of(root) {
            self.roots.set(root, id);
        }
        self.lost.remove(root);
        self.watch_failed.remove(root);
        tracing::info!(folder = %root.display(), "watch folder is back; identity renewed");
        let count = self.scan_roots(&[root.to_path_buf()]).await?;
        tracing::info!(dir = %root.display(), files = count, "watcher: scan of the returned folder complete");
        Ok(true)
    }

    /// A WatchAdmin command.
    pub(crate) async fn on_command(&mut self, cmd: WatcherCommand) -> Result<(), Closed> {
        match cmd {
            WatcherCommand::Add {
                path,
                importance: _,
            } => {
                if let Some(refusal) = refuse_folder(&path) {
                    refuse(&self.params.watch_states, &path, &refusal);
                    return Ok(());
                }
                // A failed watch still makes the folder a root and gets it scanned
                // (backup-i17); its status stays Error.
                self.watch_failed.remove(&path);
                self.lost.remove(&path);
                if let Err(e) = self.notify.watch(&path, RecursiveMode::Recursive) {
                    let reason = describe_watch_error(&e);
                    tracing::warn!(path = %path.display(), error = %reason,
                        "watcher: failed to watch new directory");
                    set_status(
                        &self.params.watch_states,
                        &path,
                        WatcherStatusSignal::Error,
                        Some(reason),
                    );
                    self.watch_failed.insert(path.clone());
                }
                // An explicit Add accepts the directory there now (if it is not empty).
                self.roots.remove(&path);
                self.record_if_new(&path);
                if !self.watch_dirs.contains(&path) {
                    self.watch_dirs.push(path.clone());
                }
                self.rebuild_ignore();
                // Initial scan of the new dir only.
                let count = self.scan_roots(std::slice::from_ref(&path)).await?;
                tracing::info!(dir = %path.display(), files = count,
                    "watcher: initial scan of newly added dir");
            }
            WatcherCommand::Remove { path } => {
                let _ = self.notify.unwatch(&path);
                self.watch_dirs.retain(|d| d != &path);
                self.watch_failed.remove(&path);
                self.lost.remove(&path);
                self.roots.remove(&path);
                self.pending.retain(|p, _| !p.starts_with(&path));
                self.rebuild_ignore();
            }
            WatcherCommand::Scan { path } => {
                // The root of every scan goes through refuse_folder (W2): a refused
                // folder keeps its error, Scan does not turn it Idle.
                if let Some(refusal) = refuse_folder(&path) {
                    tracing::info!(path = %path.display(), reason = %refusal,
                        "manual scan skipped: folder refused");
                    set_status(
                        &self.params.watch_states,
                        &path,
                        WatcherStatusSignal::Error,
                        Some(refusal.to_string()),
                    );
                } else if self.lost.contains(&path) {
                    self.try_heal(&path, true).await?;
                } else {
                    // A root missing or replaced gets the root rule first; an explicit
                    // Scan then accepts the directory there if it is not empty (Р-13).
                    self.verify_root(&path).await?;
                    if self.lost.contains(&path) {
                        self.try_heal(&path, true).await?;
                        return Ok(());
                    }
                    let count = self.scan_roots(std::slice::from_ref(&path)).await?;
                    tracing::info!(dir = %path.display(), files = count,
                        "watcher: manual rescan complete");
                }
            }
        }
        Ok(())
    }

    fn rebuild_ignore(&self) {
        match IgnoreSet::build(&self.watch_dirs) {
            Ok(set) => self.ignore.store(Arc::new(set)),
            Err(e) => tracing::warn!(error = %e, "watcher: IgnoreSet rebuild failed"),
        }
    }
}
