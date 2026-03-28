// Filesystem watcher: watches directories and converts notify events to DirtyEvents.
//
// Uses notify::RecommendedWatcher with a std channel bridge to tokio mpsc.
// Debounces rapid successive events on the same path (debounce_ms window).
// Filters: only regular files, no hidden files (basename starts with '.').
//
// Design: the notify callback posts to a std::sync::mpsc::Sender<(PathBuf, DirtyKind)>.
// A dedicated tokio task drains that channel, runs debounce, and forwards
// DirtyEvent to the backup coordinator channel.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::time::Instant;

use notify::event::{EventKind, ModifyKind, RemoveKind};
use notify::{recommended_watcher, Event, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tokio_util::sync::CancellationToken;

use crate::daemon::backup::{DirtyEvent, DirtyKind};
use syncback_core::types::DeviceId;

#[cfg(test)]
mod tests;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors from the watcher module.
#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
    #[error("notify watcher error: {0}")]
    Notify(#[from] notify::Error),

    #[error("no watch directories configured")]
    NoWatchDirs,
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
///
/// Returns `WatcherError` immediately if any watch directory fails to register.
pub async fn start_watcher(
    config: WatcherConfig,
    dirty_tx: mpsc::Sender<DirtyEvent>,
    cancel: CancellationToken,
) -> Result<(), WatcherError> {
    if config.watch_dirs.is_empty() {
        return Err(WatcherError::NoWatchDirs);
    }

    // Bridge: notify → std channel → tokio task.
    let (std_tx, std_rx) = std_mpsc::channel::<(PathBuf, DirtyKind)>();

    // Build the notify watcher. The closure runs in a thread managed by notify.
    let std_tx_clone = std_tx.clone();
    let mut watcher = recommended_watcher(move |res: Result<Event, notify::Error>| {
        match res {
            Ok(event) => {
                if let Some(kind) = classify_event(&event.kind) {
                    for path in &event.paths {
                        if should_watch_path(path) {
                            let _ = std_tx_clone.send((path.clone(), kind));
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("watcher notify error: {e}");
            }
        }
    })?;

    // Register all directories.
    for dir in &config.watch_dirs {
        watcher.watch(dir, RecursiveMode::Recursive)?;
        tracing::info!(dir = %dir.display(), "watching directory");
    }

    // ── Initial / periodic scan ────────────────────────────────────────────
    let scan_marker = config.data_dir.join("last_scan");
    let needs_scan = should_run_scan(&scan_marker, config.rescan_interval_secs);
    if needs_scan {
        let count = run_full_scan(
            &config.watch_dirs,
            config.device_id,
            &dirty_tx,
        )
        .await;
        // Write current timestamp as marker.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = std::fs::write(&scan_marker, now.to_string());
        tracing::info!(files = count, "initial/periodic scan complete");
    } else {
        tracing::info!("scan skipped (last scan recent enough)");
    }

    // Debounce state: path → (kind, deadline).
    let mut pending: HashMap<PathBuf, (DirtyKind, Instant)> = HashMap::new();
    let debounce_dur = std::time::Duration::from_millis(config.debounce_ms.max(1));

    // Poll the std channel at quarter-debounce resolution (min 10 ms).
    let poll_ms = (config.debounce_ms / 4).max(10);
    let mut poll_timer = interval(Duration::from_millis(poll_ms));

    // Periodic rescan timer.
    let rescan_secs = if config.rescan_interval_secs > 0 {
        config.rescan_interval_secs
    } else {
        u64::MAX / 2 // effectively never
    };
    let mut rescan_timer = interval(Duration::from_secs(rescan_secs));
    rescan_timer.tick().await; // skip immediate first tick

    // Keep watcher alive for the duration of this async function.
    let _watcher = watcher;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("watcher: cancel requested, exiting");
                break;
            }
            _ = rescan_timer.tick() => {
                let count = run_full_scan(
                    &config.watch_dirs,
                    config.device_id,
                    &dirty_tx,
                ).await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let _ = std::fs::write(&scan_marker, now.to_string());
                tracing::info!(files = count, "periodic rescan complete");
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
        EventKind::Access(_) => None,                        // reads: ignore
        EventKind::Remove(RemoveKind::Folder) => None,       // directory removal: ignore
        _ => None,
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

/// Walk all watch directories and emit DirtyEvent::Added for every file found.
async fn run_full_scan(
    dirs: &[PathBuf],
    device_id: DeviceId,
    dirty_tx: &mpsc::Sender<DirtyEvent>,
) -> u64 {
    let mut count: u64 = 0;
    for dir in dirs {
        let walker = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "scan: cannot read directory");
                continue;
            }
        };
        // Use a stack-based walk to avoid recursion depth issues.
        let mut stack: Vec<PathBuf> = vec![dir.clone()];
        while let Some(current) = stack.pop() {
            let entries = match std::fs::read_dir(&current) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Skip hidden directories.
                    if let Some(name) = path.file_name() {
                        if !name.to_string_lossy().starts_with('.') {
                            stack.push(path);
                        }
                    }
                } else if should_watch_path(&path) {
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
        drop(walker);
    }
    count
}

/// Returns true if the path should trigger a DirtyEvent.
///
/// Filters out:
/// - Paths with no filename component
/// - Hidden files (basename starts with '.')
/// - Directories (if stat is available)
pub(crate) fn should_watch_path(path: &std::path::Path) -> bool {
    // Require a filename component.
    let Some(name) = path.file_name() else {
        return false;
    };

    // Skip hidden files.
    if name.to_string_lossy().starts_with('.') {
        return false;
    }

    // Only regular files. If stat fails (deleted file), allow through.
    match path.metadata() {
        Ok(meta) => meta.is_file(),
        Err(_) => true,
    }
}
