// WatchAdmin: manages dynamic folder (watch directory) add/remove/status/rollup.
//
// Owns the live_configs Arc<RwLock<Vec<WatchConfig>>> shared with BackupCoordinator
// and web_api handlers. Uses toml_edit to write config.toml without disturbing
// comments or other sections.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use syncback_core::config::{expand_watch_path, WatchConfig, DEFAULT_IMPORTANCE};
use syncback_core::db::Db;
use syncback_core::types::{FileId, LocalState, PlacementStatus, Timestamp};
use tokio::sync::mpsc;

use crate::daemon::watcher::WatcherCommand;

#[cfg(test)]
mod tests;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum WatchAdminError {
    #[error("path does not exist or is not a directory: {0}")]
    NotADirectory(String),

    #[error("path is not absolute after tilde expansion: {0}")]
    NotAbsolute(String),

    #[error("path nesting conflict: {new} is inside existing watch {existing}")]
    Nested { new: String, existing: String },

    #[error("watch not found: {0}")]
    NotFound(String),

    #[error("config save failed: {0}")]
    ConfigSave(String),

    #[error("db error: {0}")]
    Db(String),

    #[error("watcher channel closed")]
    WatcherGone,
}

// ─── Status types ─────────────────────────────────────────────────────────────

/// Per-folder status (Syncthing-inspired state machine).
///
/// Working is DERIVED from the rollup (encoding > 0 or queued > 0), not stored.
/// Watchers signal Idle / Scanning / Error into `watch_states`. The final
/// `WatchStatus` returned in WatchEntry is computed by `derive_status()`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WatchStatus {
    /// Watcher registered, no activity.
    Idle,
    /// Full scan in progress.
    Scanning,
    /// Backup pipeline is processing files in this folder (derived: encoding + queued > 0).
    Working,
    /// An unrecoverable error (e.g. path disappeared after add).
    Error,
}

/// Status signalled by the watcher task into `watch_states`.
/// Does NOT include Working — that is derived at read time from the rollup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatcherStatusSignal {
    Idle,
    Scanning,
    Error,
}

/// Live per-folder state tracked in memory by the watcher task.
#[derive(Debug, Clone)]
pub struct WatchEntryState {
    pub status: WatcherStatusSignal,
    /// Human-readable error message when status == Error.
    pub error: Option<String>,
    /// Timestamp of last status change (for display only).
    pub last_changed: std::time::Instant,
    /// Timestamp of last filesystem event observed under this path.
    pub last_event_at: Option<std::time::Instant>,
}

impl WatchEntryState {
    pub fn idle() -> Self {
        Self {
            status: WatcherStatusSignal::Idle,
            error: None,
            last_changed: std::time::Instant::now(),
            last_event_at: None,
        }
    }

    pub fn scanning() -> Self {
        Self {
            status: WatcherStatusSignal::Scanning,
            error: None,
            last_changed: std::time::Instant::now(),
            last_event_at: None,
        }
    }
}

// ─── API types ────────────────────────────────────────────────────────────────

/// API response for one watch entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WatchEntry {
    /// Absolute expanded path (tilde resolved).
    pub path: String,
    /// Importance [0.0, 1.0].
    pub importance: f64,
    /// "idle" | "scanning" | "working" | "error" — derived from WatcherStatusSignal + rollup.
    pub status: WatchStatus,
    /// Set when status == "error".
    pub error: Option<String>,
    /// Seconds since the last filesystem event under this path. None if never seen.
    pub last_event_age_secs: Option<u64>,
    // ── Rollup counters ──
    pub total_files: u64,
    pub total_bytes: u64,
    /// Files whose latest version has backed_up_at.is_some().
    pub backed_up: u64,
    /// Files with ≥1 placement in Uncertain or PresumedLost status.
    pub at_risk: u64,
    /// Files with all placements in Lost status.
    pub lost: u64,
    /// Files with placements currently in Offered or Accepted status.
    pub encoding: u64,
    /// Files queued in BackupCoordinator for upload. MVP: always 0 (not wired yet).
    pub queued: u64,
    /// Seconds since the last rollup recompute. None if never computed yet.
    pub rollup_age_secs: Option<u64>,
    // ── Derived ──
    /// "green" | "yellow" | "orange" | "red"
    pub traffic_light: String,
}

/// Request body for POST /api/watches.
#[derive(Debug, serde::Deserialize)]
pub struct AddWatchRequest {
    pub path: String,
    #[serde(default = "default_importance_fn")]
    pub importance: f64,
}

fn default_importance_fn() -> f64 {
    DEFAULT_IMPORTANCE
}

/// Request body for PATCH /api/watches/{path_b64}.
#[derive(Debug, serde::Deserialize)]
pub struct PatchWatchRequest {
    pub importance: f64,
}

/// Query parameters for DELETE /api/watches/{path_b64}.
#[derive(Debug, serde::Deserialize)]
pub struct DeleteWatchQuery {
    #[serde(default)]
    pub purge: bool,
}

/// Defaults returned by GET /api/watches/defaults.
#[derive(Debug, serde::Serialize)]
pub struct WatchDefaults {
    pub importance: f64,
}

// ─── Internal types ───────────────────────────────────────────────────────────

/// Cached rollup counters for one watch directory.
#[derive(Debug, Default, Clone)]
pub struct FolderRollup {
    pub total_files: u64,
    pub total_bytes: u64,
    pub backed_up: u64,
    pub at_risk: u64,
    pub lost: u64,
    pub encoding: u64,
    pub queued: u64, // MVP: always 0
}

/// One rollup snapshot + when it was taken.
#[derive(Debug, Clone)]
pub struct CachedRollup {
    pub rollup: FolderRollup,
    pub computed_at: std::time::Instant,
}

// ─── WatchAdmin ───────────────────────────────────────────────────────────────

pub struct WatchAdmin {
    /// Absolute path to config.toml (for save_watches).
    pub config_path: PathBuf,
    /// Live watch configs. Shared with web_api handlers and BackupCoordinator.
    pub live_configs: Arc<RwLock<Vec<WatchConfig>>>,
    /// Per-folder live state (status signal + last_event_at).
    /// Written by the watcher task, read by WatchAdmin.list_watches.
    pub watch_states: Arc<RwLock<HashMap<PathBuf, WatchEntryState>>>,
    /// Cached rollups keyed by expanded watch path.
    pub cached_rollups: Arc<RwLock<HashMap<PathBuf, CachedRollup>>>,
    /// Channel to send commands to the watcher task.
    pub control_tx: mpsc::Sender<WatcherCommand>,
    /// DB handle for rollup queries and purge.
    pub db: Db,
}

impl WatchAdmin {
    /// Create a WatchAdmin. Populates watch_states from live_configs (all start Idle)
    /// and performs an initial `recompute_all_rollups()` so `GET /api/watches` has data.
    pub fn new(
        config_path: PathBuf,
        live_configs: Arc<RwLock<Vec<WatchConfig>>>,
        control_tx: mpsc::Sender<WatcherCommand>,
        db: Db,
    ) -> Self {
        let watch_states = {
            let cfgs = live_configs.read().expect("live_configs lock poisoned");
            let mut map = HashMap::new();
            for wc in cfgs.iter() {
                let path = expand_watch_path(&wc.path);
                map.insert(path, WatchEntryState::idle());
            }
            Arc::new(RwLock::new(map))
        };

        let admin = Self {
            config_path,
            live_configs,
            watch_states,
            cached_rollups: Arc::new(RwLock::new(HashMap::new())),
            control_tx,
            db,
        };

        // Prime the rollup cache.
        if let Err(e) = admin.recompute_all_rollups() {
            tracing::warn!(error = %e, "WatchAdmin::new: initial rollup recompute failed");
        }

        admin
    }

    /// Full scan of DB, update cached_rollups for every watch path.
    /// Called by the 5-min background task and by POST /api/watches/refresh.
    pub fn recompute_all_rollups(&self) -> Result<(), WatchAdminError> {
        let configs = self.live_configs.read().expect("live_configs lock poisoned");
        let all_files = self
            .db
            .list_all_files()
            .map_err(|e| WatchAdminError::Db(e.to_string()))?;
        let all_placements = self
            .db
            .list_all_placements()
            .map_err(|e| WatchAdminError::Db(e.to_string()))?;

        // Group placements by file_id.
        let mut placements_by_file: HashMap<FileId, Vec<PlacementStatus>> = HashMap::new();
        for p in &all_placements {
            placements_by_file
                .entry(p.file_id)
                .or_default()
                .push(p.status);
        }

        let now = std::time::Instant::now();

        let mut new_rollups: HashMap<PathBuf, CachedRollup> = HashMap::new();

        for wc in configs.iter() {
            let watch_path = expand_watch_path(&wc.path);
            let prefix = watch_path.to_string_lossy().to_string();
            let prefix_with_sep = if prefix.ends_with('/') {
                prefix.clone()
            } else {
                format!("{}/", prefix)
            };

            let mut rollup = FolderRollup::default();

            for file_record in &all_files {
                let file_path = &file_record.path;
                if !file_path.starts_with(&prefix_with_sep) && file_path != &prefix {
                    continue;
                }

                rollup.total_files += 1;

                // total_bytes: use k*t from the latest version as a proxy.
                // TODO: add FileVersion.source_size to store original uncompressed file size.
                if let Some(latest_version) = file_record.versions.last() {
                    rollup.total_bytes +=
                        latest_version.k as u64 * latest_version.t as u64;

                    if latest_version.backed_up_at.is_some() {
                        rollup.backed_up += 1;
                    }
                }

                // Placement stats.
                let statuses = placements_by_file
                    .get(&file_record.file_id)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);

                if !statuses.is_empty() {
                    let has_encoding = statuses.iter().any(|s| {
                        matches!(s, PlacementStatus::Offered | PlacementStatus::Accepted)
                    });
                    let has_uncertain = statuses.iter().any(|s| {
                        matches!(
                            s,
                            PlacementStatus::Uncertain | PlacementStatus::PresumedLost
                        )
                    });
                    let all_lost = statuses
                        .iter()
                        .all(|s| matches!(s, PlacementStatus::Lost));

                    if has_encoding {
                        rollup.encoding += 1;
                    }
                    if has_uncertain && !all_lost {
                        rollup.at_risk += 1;
                    }
                    if all_lost {
                        rollup.lost += 1;
                    }
                }
            }

            new_rollups.insert(
                watch_path,
                CachedRollup {
                    rollup,
                    computed_at: now,
                },
            );
        }

        let mut cache = self.cached_rollups.write().expect("cached_rollups lock poisoned");
        *cache = new_rollups;
        Ok(())
    }

    /// Validate and add a new watch directory.
    pub async fn add_watch(
        &self,
        req: AddWatchRequest,
    ) -> Result<WatchEntry, WatchAdminError> {
        let expanded = expand_watch_path(&req.path);

        if !expanded.is_absolute() {
            return Err(WatchAdminError::NotAbsolute(
                expanded.to_string_lossy().into_owned(),
            ));
        }
        if !expanded.is_dir() {
            return Err(WatchAdminError::NotADirectory(
                expanded.to_string_lossy().into_owned(),
            ));
        }

        // Check nesting against current live_configs (both directions).
        {
            let cfgs = self.live_configs.read().expect("live_configs lock poisoned");
            for wc in cfgs.iter() {
                let existing = expand_watch_path(&wc.path);
                // new is child of existing
                if expanded.starts_with(&existing) && expanded != existing {
                    return Err(WatchAdminError::Nested {
                        new: expanded.to_string_lossy().into_owned(),
                        existing: existing.to_string_lossy().into_owned(),
                    });
                }
                // existing is child of new
                if existing.starts_with(&expanded) && existing != expanded {
                    return Err(WatchAdminError::Nested {
                        new: expanded.to_string_lossy().into_owned(),
                        existing: existing.to_string_lossy().into_owned(),
                    });
                }
            }
        }

        // Build the new config entry.
        let new_wc = WatchConfig {
            path: expanded.to_string_lossy().into_owned(),
            importance: req.importance,
        };

        // Step 4: save_watches atomically (write config first).
        {
            let cfgs = self.live_configs.read().expect("live_configs lock poisoned");
            let mut new_list = cfgs.clone();
            new_list.push(new_wc.clone());
            save_watches(&self.config_path, &new_list)?;
        }

        // Step 5+: mutate live_configs.
        {
            let mut cfgs = self.live_configs.write().expect("live_configs lock poisoned");
            cfgs.push(new_wc.clone());
        }

        // Step 7: set scanning state.
        {
            let mut states = self.watch_states.write().expect("watch_states lock poisoned");
            states.insert(expanded.clone(), WatchEntryState::scanning());
        }

        // Step 8: send Add command to watcher.
        self.control_tx
            .send(WatcherCommand::Add {
                path: expanded.clone(),
                importance: req.importance,
            })
            .await
            .map_err(|_| WatchAdminError::WatcherGone)?;

        // Build and return WatchEntry (rollup starts at 0).
        let entry = self.build_watch_entry(&expanded, req.importance);
        Ok(entry)
    }

    /// Update importance of an existing watch.
    pub async fn patch_watch(
        &self,
        path_b64: &str,
        req: PatchWatchRequest,
    ) -> Result<WatchEntry, WatchAdminError> {
        let path = decode_path_b64(path_b64)?;

        // Check exists.
        {
            let cfgs = self.live_configs.read().expect("live_configs lock poisoned");
            if !cfgs
                .iter()
                .any(|wc| expand_watch_path(&wc.path) == path)
            {
                return Err(WatchAdminError::NotFound(path.to_string_lossy().into_owned()));
            }
        }

        // Build new list with updated importance.
        let new_list = {
            let cfgs = self.live_configs.read().expect("live_configs lock poisoned");
            cfgs.iter()
                .map(|wc| {
                    if expand_watch_path(&wc.path) == path {
                        WatchConfig {
                            path: wc.path.clone(),
                            importance: req.importance,
                        }
                    } else {
                        wc.clone()
                    }
                })
                .collect::<Vec<_>>()
        };

        // Save first (atomic-commit: config write before memory mutation).
        save_watches(&self.config_path, &new_list)?;

        // Update live_configs.
        {
            let mut cfgs = self.live_configs.write().expect("live_configs lock poisoned");
            *cfgs = new_list;
        }

        let entry = self.build_watch_entry(&path, req.importance);
        Ok(entry)
    }

    /// Remove a watch directory.
    pub async fn remove_watch(
        &self,
        path_b64: &str,
        purge: bool,
    ) -> Result<(), WatchAdminError> {
        let path = decode_path_b64(path_b64)?;

        // Find in live_configs.
        {
            let cfgs = self.live_configs.read().expect("live_configs lock poisoned");
            if !cfgs
                .iter()
                .any(|wc| expand_watch_path(&wc.path) == path)
            {
                return Err(WatchAdminError::NotFound(path.to_string_lossy().into_owned()));
            }
        }

        // Build new list without this entry.
        let new_list = {
            let cfgs = self.live_configs.read().expect("live_configs lock poisoned");
            cfgs.iter()
                .filter(|wc| expand_watch_path(&wc.path) != path)
                .cloned()
                .collect::<Vec<_>>()
        };

        // Save first.
        save_watches(&self.config_path, &new_list)?;

        // Remove from live_configs.
        {
            let mut cfgs = self.live_configs.write().expect("live_configs lock poisoned");
            *cfgs = new_list;
        }

        // Remove from watch_states.
        {
            let mut states = self.watch_states.write().expect("watch_states lock poisoned");
            states.remove(&path);
        }

        // Send Remove command to watcher.
        self.control_tx
            .send(WatcherCommand::Remove { path: path.clone() })
            .await
            .map_err(|_| WatchAdminError::WatcherGone)?;

        // Purge if requested.
        if purge {
            self.purge_folder_files(&path.to_string_lossy())?;
        }

        Ok(())
    }

    /// Trigger a full rescan of a specific watch folder.
    pub async fn scan_watch(&self, path_b64: &str) -> Result<(), WatchAdminError> {
        let path = decode_path_b64(path_b64)?;

        // Verify it's currently watched.
        {
            let cfgs = self.live_configs.read().expect("live_configs lock poisoned");
            if !cfgs
                .iter()
                .any(|wc| expand_watch_path(&wc.path) == path)
            {
                return Err(WatchAdminError::NotFound(path.to_string_lossy().into_owned()));
            }
        }

        self.control_tx
            .send(WatcherCommand::Scan { path })
            .await
            .map_err(|_| WatchAdminError::WatcherGone)?;

        Ok(())
    }

    /// Return WatchEntry list with rollup counters.
    pub fn list_watches(&self) -> Vec<WatchEntry> {
        let cfgs = self.live_configs.read().expect("live_configs lock poisoned");
        cfgs.iter()
            .map(|wc| {
                let path = expand_watch_path(&wc.path);
                self.build_watch_entry(&path, wc.importance)
            })
            .collect()
    }

    /// Return a WatchEntry for a single path (or NotFound).
    pub fn get_watch(&self, path_b64: &str) -> Result<WatchEntry, WatchAdminError> {
        let path = decode_path_b64(path_b64)?;
        let cfgs = self.live_configs.read().expect("live_configs lock poisoned");
        for wc in cfgs.iter() {
            if expand_watch_path(&wc.path) == path {
                return Ok(self.build_watch_entry(&path, wc.importance));
            }
        }
        Err(WatchAdminError::NotFound(path.to_string_lossy().into_owned()))
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Build a WatchEntry for the given path using cached rollup and watch_states.
    fn build_watch_entry(&self, path: &Path, importance: f64) -> WatchEntry {
        let (signal, error, last_event_age_secs) = {
            let states = self.watch_states.read().expect("watch_states lock poisoned");
            if let Some(state) = states.get(path) {
                let age = state.last_event_at.map(|t| t.elapsed().as_secs());
                (state.status.clone(), state.error.clone(), age)
            } else {
                (WatcherStatusSignal::Idle, None, None)
            }
        };

        let (rollup, rollup_age_secs) = {
            let cache = self.cached_rollups.read().expect("cached_rollups lock poisoned");
            if let Some(cr) = cache.get(path) {
                let age = cr.computed_at.elapsed().as_secs();
                (cr.rollup.clone(), Some(age))
            } else {
                (FolderRollup::default(), None)
            }
        };

        let status = derive_status(&signal, &rollup);
        let traffic_light = traffic_light(&status, &rollup);

        WatchEntry {
            path: path.to_string_lossy().into_owned(),
            importance,
            error,
            last_event_age_secs,
            total_files: rollup.total_files,
            total_bytes: rollup.total_bytes,
            backed_up: rollup.backed_up,
            at_risk: rollup.at_risk,
            lost: rollup.lost,
            encoding: rollup.encoding,
            queued: rollup.queued,
            rollup_age_secs,
            traffic_light,
            status,
        }
    }

    /// Mark all FileRecords under `dir_prefix` as Deleted on all devices.
    fn purge_folder_files(&self, dir_prefix: &str) -> Result<u64, WatchAdminError> {
        let prefix_with_sep = if dir_prefix.ends_with('/') {
            dir_prefix.to_string()
        } else {
            format!("{dir_prefix}/")
        };
        let now = Timestamp::now();
        let files = self
            .db
            .list_all_files()
            .map_err(|e| WatchAdminError::Db(e.to_string()))?;
        let mut count = 0u64;
        for mut record in files {
            if !record.path.starts_with(&prefix_with_sep) && record.path != dir_prefix {
                continue;
            }
            // Mark every device entry as Deleted(now).
            for (_, state) in &mut record.devices {
                *state = LocalState::Deleted(now);
            }
            self.db
                .upsert_file(&record)
                .map_err(|e| WatchAdminError::Db(e.to_string()))?;
            count += 1;
        }
        Ok(count)
    }
}

// ─── Status derivation ────────────────────────────────────────────────────────

pub fn derive_status(signal: &WatcherStatusSignal, rollup: &FolderRollup) -> WatchStatus {
    match signal {
        WatcherStatusSignal::Error => WatchStatus::Error,
        WatcherStatusSignal::Scanning => WatchStatus::Scanning,
        WatcherStatusSignal::Idle => {
            if rollup.encoding > 0 || rollup.queued > 0 {
                WatchStatus::Working
            } else {
                WatchStatus::Idle
            }
        }
    }
}

/// Derive traffic light color from status and rollup.
pub fn traffic_light(status: &WatchStatus, rollup: &FolderRollup) -> String {
    if *status == WatchStatus::Error {
        "orange".to_string()
    } else if rollup.lost > 0 {
        "red".to_string()
    } else if *status == WatchStatus::Working
        || *status == WatchStatus::Scanning
        || rollup.at_risk > 0
    {
        "yellow".to_string()
    } else {
        "green".to_string()
    }
}

// ─── Path encoding / decoding ─────────────────────────────────────────────────

pub fn encode_path_b64(path: &Path) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(path.to_string_lossy().as_bytes())
}

pub fn decode_path_b64(s: &str) -> Result<PathBuf, WatchAdminError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| WatchAdminError::NotFound(format!("invalid path encoding: {e}")))?;
    let s = String::from_utf8(bytes)
        .map_err(|e| WatchAdminError::NotFound(format!("non-utf8 path: {e}")))?;
    Ok(PathBuf::from(s))
}

// ─── Config persistence ───────────────────────────────────────────────────────

/// Rewrite the [[watch]] sections in config.toml using toml_edit.
///
/// Preserves all other sections and comments.
/// Replaces the entire [[watch]] array with the provided configs.
/// Creates the file if it does not exist.
pub fn save_watches(
    config_path: &Path,
    configs: &[WatchConfig],
) -> Result<(), WatchAdminError> {
    let mut doc: toml_edit::DocumentMut = if config_path.exists() {
        let content = std::fs::read_to_string(config_path)
            .map_err(|e| WatchAdminError::ConfigSave(format!("read error: {e}")))?;
        content
            .parse::<toml_edit::DocumentMut>()
            .map_err(|e| WatchAdminError::ConfigSave(format!("toml parse error: {e}")))?
    } else {
        toml_edit::DocumentMut::new()
    };

    // Remove existing [[watch]] array.
    doc.remove("watch");

    // Re-insert if we have entries.
    if !configs.is_empty() {
        let mut aot = toml_edit::ArrayOfTables::new();
        for wc in configs {
            let mut t = toml_edit::Table::new();
            t.insert("path", toml_edit::value(wc.path.as_str()));
            t.insert("importance", toml_edit::value(wc.importance));
            aot.push(t);
        }
        doc.insert("watch", toml_edit::Item::ArrayOfTables(aot));
    }

    std::fs::write(config_path, doc.to_string())
        .map_err(|e| WatchAdminError::ConfigSave(format!("write error: {e}")))?;

    Ok(())
}
