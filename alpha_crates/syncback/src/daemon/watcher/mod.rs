use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::RecursiveMode;
use notify_debouncer_mini::new_debouncer;
use syncback_core::types::Timestamp;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::daemon::{BackupConfig, DirtyEvent, DirtyKind};

#[cfg(test)]
mod tests;

// ============================================================
// Error type
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
    #[error("invalid glob pattern '{pattern}': {source}")]
    InvalidGlob {
        pattern: String,
        #[source]
        source: glob::PatternError,
    },

    #[error("notify error: {0}")]
    Notify(#[from] notify::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ============================================================
// Internal types
// ============================================================

struct CompiledInclude {
    root: PathBuf,
    importance: f64,
    pattern: Option<glob::Pattern>,
}

struct CompiledExclude {
    pattern: glob::Pattern,
}

pub(crate) struct WatcherState {
    includes: Vec<CompiledInclude>,
    excludes: Vec<CompiledExclude>,
}

// ============================================================
// WatcherState impl
// ============================================================

impl WatcherState {
    pub(crate) fn from_config(config: &BackupConfig) -> Result<Self, WatcherError> {
        let mut includes = Vec::new();
        for entry in &config.include {
            let expanded = expand_tilde(&entry.path);
            let s = expanded.to_string_lossy();
            // Detect glob suffix: presence of *, ?, or [ in any path component.
            let has_glob = s.contains('*') || s.contains('?') || s.contains('[');
            let (root, pattern) = if has_glob {
                // Split at first component containing a glob character.
                let components: Vec<&str> = s.split('/').collect();
                let split_idx = components
                    .iter()
                    .position(|c| c.contains('*') || c.contains('?') || c.contains('['))
                    .unwrap_or(components.len());
                let root_str = components[..split_idx].join("/");
                let root = if root_str.is_empty() {
                    PathBuf::from("/")
                } else {
                    PathBuf::from(&root_str)
                };
                let glob_str = components[split_idx..].join("/");
                let pat = glob::Pattern::new(&glob_str).map_err(|e| WatcherError::InvalidGlob {
                    pattern: glob_str.clone(),
                    source: e,
                })?;
                (root, Some(pat))
            } else {
                (expanded, None)
            };
            includes.push(CompiledInclude {
                root,
                importance: entry.importance,
                pattern,
            });
        }

        let mut excludes = Vec::new();
        for pat_str in &config.exclude {
            let pat = glob::Pattern::new(pat_str).map_err(|e| WatcherError::InvalidGlob {
                pattern: pat_str.clone(),
                source: e,
            })?;
            excludes.push(CompiledExclude { pattern: pat });
        }

        Ok(WatcherState { includes, excludes })
    }

    /// Returns true if the path should be watched (matches an include and no exclude).
    pub(crate) fn is_included(&self, path: &Path) -> bool {
        if self.is_excluded(path) {
            return false;
        }
        self.best_include(path).is_some()
    }

    /// Returns the importance for a path. 0.0 if not included.
    pub(crate) fn importance_for(&self, path: &Path) -> f64 {
        if self.is_excluded(path) {
            return 0.0;
        }
        self.best_include(path)
            .map(|inc| inc.importance)
            .unwrap_or(0.0)
    }

    /// Returns all unique root directories to watch.
    pub(crate) fn watch_roots(&self) -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = Vec::new();
        for inc in &self.includes {
            if !roots.contains(&inc.root) {
                roots.push(inc.root.clone());
            }
        }
        roots
    }

    // ---- private helpers ----

    fn is_excluded(&self, path: &Path) -> bool {
        for exc in &self.excludes {
            // 1. Check if any path component matches the exclude pattern exactly.
            for component in path.components() {
                let comp_str = component.as_os_str().to_string_lossy();
                if exc.pattern.matches(&comp_str) {
                    return true;
                }
            }
            // 2. Check if the file name matches (already covered by component loop, but explicit).
            // 3. Check if the full path matches.
            if let Some(path_str) = path.to_str() {
                if exc.pattern.matches(path_str) {
                    return true;
                }
            }
        }
        false
    }

    /// Return the best (longest root) matching include entry, or None.
    fn best_include<'a>(&'a self, path: &Path) -> Option<&'a CompiledInclude> {
        let mut best: Option<&'a CompiledInclude> = None;
        for inc in &self.includes {
            if !path.starts_with(&inc.root) {
                continue;
            }
            // If include has a glob pattern, check it against the relative file portion.
            if let Some(ref pat) = inc.pattern {
                let rel = match path.strip_prefix(&inc.root) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if !pat.matches_path(rel) {
                    continue;
                }
            }
            // Longest root wins.
            let is_longer = best
                .map(|b| inc.root.as_os_str().len() > b.root.as_os_str().len())
                .unwrap_or(true);
            if is_longer {
                best = Some(inc);
            }
        }
        best
    }
}

// ============================================================
// Tilde expansion
// ============================================================

fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with("~/") || s == "~" {
        let home = std::env::var("HOME").expect("HOME not set");
        PathBuf::from(home).join(s.trim_start_matches("~/"))
    } else {
        path.to_path_buf()
    }
}

// ============================================================
// Hash helper
// ============================================================

fn hash_file(path: &Path) -> Option<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize().into())
}

// ============================================================
// Initial scan
// ============================================================

pub(crate) fn run_initial_scan(
    state: &WatcherState,
    db: &syncback_core::db::Db,
    dirty_tx: &mpsc::Sender<DirtyEvent>,
) -> usize {
    let mut dirty_count = 0usize;
    let now = Timestamp::now();

    for inc in &state.includes {
        let walker = walkdir::WalkDir::new(&inc.root)
            .follow_links(false)
            .into_iter();
        for entry in walker.filter_map(|e| e.ok()) {
            let path = entry.path();

            // Only regular files.
            if !entry.file_type().is_file() {
                continue;
            }

            if !state.is_included(path) {
                continue;
            }

            let path_str = path.to_string_lossy();

            let record = match db.get_file(&path_str) {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(path = %path_str, error = %e, "watcher: db get_file error, skipping");
                    continue;
                }
            };

            match record {
                Some(r) if r.dirty => {
                    // Already dirty — Processor knows about it.
                    continue;
                }
                Some(r) => {
                    // Compare hash.
                    let hash = match hash_file(path) {
                        Some(h) => h,
                        None => {
                            tracing::debug!(path = %path_str, "watcher: cannot hash file, skipping");
                            continue;
                        }
                    };
                    if hash == r.content_hash {
                        // Unchanged — skip.
                        continue;
                    }
                    // Hash differs — file was modified while daemon was offline.
                    let event = DirtyEvent {
                        path: path.to_path_buf(),
                        kind: DirtyKind::Modified,
                        detected_at: now.0,
                    };
                    tracing::debug!(path = %path_str, "watcher: initial scan — modified");
                    if dirty_tx.blocking_send(event).is_err() {
                        tracing::debug!("watcher: dirty channel closed during initial scan");
                        return dirty_count;
                    }
                    dirty_count += 1;
                }
                None => {
                    // No record — new file.
                    let event = DirtyEvent {
                        path: path.to_path_buf(),
                        kind: DirtyKind::Created,
                        detected_at: now.0,
                    };
                    tracing::debug!(path = %path_str, "watcher: initial scan — created");
                    if dirty_tx.blocking_send(event).is_err() {
                        tracing::debug!("watcher: dirty channel closed during initial scan");
                        return dirty_count;
                    }
                    dirty_count += 1;
                }
            }
        }
    }

    dirty_count
}

// ============================================================
// Debounced event handler
// ============================================================

async fn handle_debounced_event(
    ev: &notify_debouncer_mini::DebouncedEvent,
    state: &WatcherState,
    dirty_tx: &mpsc::Sender<DirtyEvent>,
) {
    let path = &ev.path;

    if path.is_dir() {
        return;
    }

    if !state.is_included(path) {
        return;
    }

    let kind = if path.exists() {
        DirtyKind::Modified
    } else {
        DirtyKind::Deleted
    };

    tracing::debug!(path = ?path, ?kind, "watcher: dirty event");

    let event = DirtyEvent {
        path: path.clone(),
        kind,
        detected_at: Timestamp::now().0,
    };

    if dirty_tx.try_send(event).is_err() {
        tracing::debug!(path = ?path, "watcher: event channel full, dropping event");
    }
}

// ============================================================
// Public run function
// ============================================================

pub async fn run(
    cancel: CancellationToken,
    dirty_tx: mpsc::Sender<DirtyEvent>,
    db: syncback_core::db::Db,
    config: crate::daemon::Config,
) {
    let state = match WatcherState::from_config(&config.backup) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!(error = %e, "watcher: invalid config, watcher disabled");
            cancel.cancelled().await;
            return;
        }
    };

    let roots = state.watch_roots();
    let n_roots = roots.len();

    // Bridge std::sync::mpsc (notify) → tokio::sync::mpsc.
    let (std_tx, std_rx) = std::sync::mpsc::channel();
    let mut debouncer = match new_debouncer(Duration::from_secs(30), std_tx) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "watcher: failed to create debouncer, watcher disabled");
            cancel.cancelled().await;
            return;
        }
    };

    // Register watches BEFORE initial scan so no events are lost.
    for root in &roots {
        debouncer
            .watcher()
            .watch(root, RecursiveMode::Recursive)
            .unwrap_or_else(|e| {
                tracing::info!(
                    path = ?root,
                    error = %e,
                    "watcher: cannot watch directory, skipping"
                );
            });
    }

    tracing::info!(n_dirs = n_roots, "watcher: started, watching N directories");

    // Spawn blocking thread to forward std channel → tokio channel.
    let (debounce_tx, mut debounce_rx) = tokio::sync::mpsc::channel(512);
    std::thread::spawn(move || {
        while let Ok(events) = std_rx.recv() {
            if debounce_tx.blocking_send(events).is_err() {
                break;
            }
        }
    });

    // Run initial scan in blocking thread pool.
    {
        let dirty_tx_clone = dirty_tx.clone();
        let db_clone = db.clone();
        let state_clone = state.clone();
        let n = tokio::task::spawn_blocking(move || {
            run_initial_scan(&state_clone, &db_clone, &dirty_tx_clone)
        })
        .await
        .expect("initial scan panicked");

        tracing::info!(n_dirty = n, "watcher: initial scan complete, N dirty files found");
    }

    // Main event loop.
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("watcher: cancelled");
                break;
            }
            batch = debounce_rx.recv() => {
                match batch {
                    Some(Ok(events)) => {
                        for ev in &events {
                            handle_debounced_event(ev, &state, &dirty_tx).await;
                        }
                    }
                    Some(Err(error)) => {
                        tracing::debug!(error = %error, "watcher: notify error");
                    }
                    None => {
                        tracing::debug!("watcher: debounce channel closed");
                        break;
                    }
                }
            }
        }
    }

    tracing::debug!("watcher: stopped");
}
