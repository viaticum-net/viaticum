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

    // Debounce state: path → (kind, deadline).
    let mut pending: HashMap<PathBuf, (DirtyKind, Instant)> = HashMap::new();
    let debounce_dur = std::time::Duration::from_millis(config.debounce_ms.max(1));

    // Poll the std channel at quarter-debounce resolution (min 10 ms).
    let poll_ms = (config.debounce_ms / 4).max(10);
    let mut poll_timer = interval(Duration::from_millis(poll_ms));

    // Keep watcher alive for the duration of this async function.
    let _watcher = watcher;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("watcher: cancel requested, exiting");
                break;
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
