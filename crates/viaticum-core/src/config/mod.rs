use std::path::{Path, PathBuf};

use crate::constants::{
    DEFAULT_CLUSTER_SYNC_BATCH_SIZE, DEFAULT_COMPLETION_BONUS_COEFFICIENT,
    DEFAULT_DISK_RESERVE_BYTES, DEFAULT_MAX_VERSION_AGE_SECS, DEFAULT_MAX_VERSIONS,
    DEFAULT_SOURCE_BLOCK_SIZE, MAX_COMPLETION_BONUS_COEFFICIENT,
};

#[cfg(test)]
mod tests;

// ============================================================
// Error
// ============================================================

/// Errors from config loading and validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io error reading config file: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse error: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("validation error: {field}: {reason}")]
    Validation { field: String, reason: String },
}

// ============================================================
// Section structs
// ============================================================

/// [backup] — erasure coding and versioning parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct BackupCfg {
    /// Source block size in megabytes. Must be a power of two, >= 1.
    /// Default: 128 (128 MB). Use 32 on Raspberry Pi (~65 MB peak RAM).
    pub source_block_size_mb: u64,

    /// Maximum number of versions kept per file path.
    /// Default: 5.
    pub max_versions: u32,

    /// Maximum age of old file versions in days.
    /// Default: 90.
    pub max_version_age_days: u64,
}

impl Default for BackupCfg {
    fn default() -> Self {
        Self {
            source_block_size_mb: DEFAULT_SOURCE_BLOCK_SIZE / 1_048_576,
            max_versions: DEFAULT_MAX_VERSIONS,
            max_version_age_days: DEFAULT_MAX_VERSION_AGE_SECS / 86400,
        }
    }
}

/// [storage] — disk quota and data directory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct StorageCfg {
    /// Soft quota in gigabytes. 0 = unlimited (no ceiling).
    /// effective_quota = min(soft_quota, disk_free - disk_reserve).
    /// Default: 0.
    pub soft_quota_gb: f64,

    /// Hard quota floor in gigabytes. 0 = no floor (evict freely).
    /// The holder will never evict below this floor even under pressure.
    /// Default: 0.
    pub hard_quota_gb: f64,

    /// Minimum free disk space to keep, in gigabytes. The daemon will start
    /// evicting symbols before disk_free drops below this value.
    /// Default: 20.
    pub disk_reserve_gb: f64,

    /// Root data directory: database, symbols, relay board.
    /// `~` is expanded to the user home directory.
    /// Default: "~/.viaticum".
    pub data_dir: String,
}

impl Default for StorageCfg {
    fn default() -> Self {
        Self {
            soft_quota_gb: 0.0,
            hard_quota_gb: 0.0,
            disk_reserve_gb: DEFAULT_DISK_RESERVE_BYTES as f64 / 1_073_741_824.0,
            data_dir: "~/.viaticum".to_string(),
        }
    }
}

/// [network] — libp2p transport / NAT-traversal settings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct NetworkCfg {
    /// Enable libp2p circuit relay for NAT traversal. When true, the swarm
    /// uses relay servers to connect nodes behind NAT.
    /// When false, only direct connections (LAN or port-forwarded setups).
    /// Default: true.
    pub enable_relay: bool,

    /// Act as a circuit relay server for other peers (relay traffic on their
    /// behalf). When true, this node accepts relay reservations and forwards
    /// circuits — costs CPU/bandwidth even when idle. Off by default: home
    /// NAS / laptop users should opt in. VPS / always-on nodes with good
    /// uplink should enable.
    /// Default: false.
    pub enable_relay_server: bool,

    /// Custom relay server URL. When set with enable_relay = true, connects
    /// to this relay server instead of bootstrap peers acting as relays.
    /// Format: "http://hostname:port" (dev mode) or "https://hostname" (production).
    /// Default: None (use bootstrap peers / Kademlia-discovered relays).
    #[serde(default)]
    pub relay_url: Option<String>,

    /// Bootstrap peer addresses to connect on startup.
    /// Format: "NodeId_hex@ip:port" or "NodeId_hex@relay_url,ip:port".
    /// Default: [] (empty — no bootstrap peers).
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,

    /// Additional libp2p/Kademlia bootstrap nodes (Multiaddr strings).
    /// These supplement the built-in IPFS bootstrap nodes.
    /// Format: standard libp2p Multiaddr, e.g.
    ///   "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"
    /// Default: [] (use only IPFS built-in bootstrap nodes).
    #[serde(default)]
    pub kademlia_bootstrap_peers: Vec<String>,

    /// Disable IPFS built-in bootstrap nodes and use only kademlia_bootstrap_peers.
    /// Default: true (IPFS public DHT is a separate network, not useful for Viaticum).
    /// Set to false only if you have custom bootstrap infrastructure on the IPFS DHT.
    #[serde(default)]
    pub kademlia_disable_ipfs_bootstrap: bool,

    /// libp2p TCP listen port. 0 = ephemeral (default). Set to a fixed value
    /// when running behind a firewall that only opens specific ports.
    #[serde(default)]
    pub listen_port: u16,
}

// ============================================================
// Watch config
// ============================================================

/// Fallback importance returned when no watch config matches a file path.
/// Preserved from pre-Wave-6 lookup_importance semantics.
pub const DEFAULT_IMPORTANCE: f64 = 0.5;

/// Default importance multiplier for a watch folder when none is configured.
/// Range [0.0, 2.0]; 1.0 = no change to the derived base importance.
pub const DEFAULT_IMPORTANCE_MULTIPLIER: f64 = 1.0;

/// Maximum number of file paths sampled when classifying a watched folder.
pub const CLASSIFY_SCAN_CAP: usize = 200;

/// Per-directory watch configuration.
///
/// Listed under [[watch]] in config.toml. The daemon watches each configured
/// path (and its subdirectories) for file changes.
///
/// # Migration note (Wave 6)
///
/// The field `importance` has been renamed to `importance_multiplier`.
/// The old name is accepted via TOML alias for backward compatibility.
/// Semantics: a multiplier in [0.0, 2.0] applied to each file's derived
/// base importance. Default 1.0 = no change.
///
/// If your old config had `importance = 0.5`, this is now interpreted as
/// "halve the computed importance of all files in this folder".
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct WatchConfig {
    /// Absolute or tilde-prefixed path to watch recursively.
    pub path: String,

    /// Multiplier applied to derived file importance. Range [0.0, 2.0], default 1.0.
    /// Serialized as `importance_multiplier` in config.toml.
    /// Legacy TOML `importance = X` is accepted and interpreted as this field.
    pub importance_multiplier: f64,

    /// True if this WatchConfig was loaded from a legacy `importance` TOML field.
    /// Set by the custom Deserialize impl. Never serialized. Used to emit a
    /// one-time deprecation warning at startup.
    #[serde(skip)]
    pub was_legacy_importance: bool,

    /// Folder media classification, computed by populate_classification() at watch-start.
    /// None until populate_classification() is called. Not serialized.
    #[serde(skip)]
    pub classification: Option<crate::importance::FolderClassification>,

    /// Burst groups detected at watch-start by populate_bursts().
    ///
    /// Each element is a set of paths that form a time-clustered media burst
    /// (>= 8 files within a 60-second mtime window). None = not yet populated.
    /// Empty vec = populated but no bursts detected.
    ///
    /// Not serialized -- regenerated at each daemon start by scanning the
    /// filesystem. Files added after daemon start do not appear in burst sets
    /// until the next restart.
    #[serde(skip)]
    pub bursts: Option<Vec<std::collections::HashSet<std::path::PathBuf>>>,
}

/// Private intermediate struct for custom WatchConfig deserialization.
#[derive(serde::Deserialize)]
struct WatchConfigRaw {
    pub path: String,
    /// Canonical field name (Wave 6+).
    #[serde(default)]
    pub importance_multiplier: Option<f64>,
    /// Legacy field name. If present and importance_multiplier absent → legacy mode.
    #[serde(default)]
    pub importance: Option<f64>,
}

impl<'de> serde::Deserialize<'de> for WatchConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = WatchConfigRaw::deserialize(d)?;
        let (multiplier, was_legacy) = match (raw.importance_multiplier, raw.importance) {
            (Some(m), _) => (m, false),   // canonical field present → not legacy
            (None, Some(v)) => (v, true), // only legacy field → legacy
            (None, None) => (DEFAULT_IMPORTANCE_MULTIPLIER, false), // neither → default
        };
        Ok(WatchConfig {
            path: raw.path,
            importance_multiplier: multiplier,
            was_legacy_importance: was_legacy,
            classification: None,
            bursts: None,
        })
    }
}

impl WatchConfig {
    /// Scan the directory at `self.path` and compute its FolderClassification.
    ///
    /// Walks up to CLASSIFY_SCAN_CAP (200) file paths using a stack-based DFS.
    /// Skips hidden directories (names starting with '.').
    /// Skips symlinks (both file and directory) to avoid loops.
    /// Stores the result in `self.classification`.
    ///
    /// If the directory does not exist or is not accessible, stores
    /// `FolderClassification::default()` (is_media_folder = false, multiplier = 1.0)
    /// and logs a warning.
    ///
    /// The `importance_multiplier` of the returned FolderClassification is always 1.0
    /// (classify_folder never has access to config). The user-configured multiplier
    /// lives in `self.importance_multiplier`, NOT in `self.classification.importance_multiplier`.
    pub fn populate_classification(&mut self) {
        self.populate_classification_with_cap(CLASSIFY_SCAN_CAP);
    }

    /// Like populate_classification but with a configurable cap (used in tests).
    pub(crate) fn populate_classification_with_cap(&mut self, cap: usize) {
        use std::path::PathBuf;
        let expanded = expand_watch_path(&self.path);
        let mut paths_seen: Vec<PathBuf> = Vec::new();
        let mut stack: Vec<PathBuf> = vec![expanded.clone()];

        'outer: while let Some(current) = stack.pop() {
            let entries = match std::fs::read_dir(&current) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        dir = %current.display(),
                        error = %e,
                        "populate_classification: cannot read directory; using default classification"
                    );
                    self.classification = Some(crate::importance::FolderClassification::default());
                    return;
                }
            };
            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else { continue };
                // Skip symlinks to avoid loops.
                if ft.is_symlink() {
                    continue;
                }
                let path = entry.path();
                if ft.is_dir() {
                    // Skip hidden directories (starting with '.').
                    if let Some(name) = path.file_name()
                        && name.to_string_lossy().starts_with('.')
                    {
                        continue;
                    }
                    stack.push(path);
                } else if ft.is_file() {
                    paths_seen.push(path);
                    if paths_seen.len() >= cap {
                        break 'outer;
                    }
                }
            }
        }

        self.classification = Some(crate::importance::classify_folder(&paths_seen));
    }

    /// Scan the watch directory and detect time-clustered media file bursts.
    ///
    /// Walks ALL files in the directory (no path count cap -- unlike
    /// populate_classification which caps at 200). For each media-extension file,
    /// reads its mtime via metadata(). Files with unreadable metadata are silently
    /// skipped (logged at debug level).
    ///
    /// Calls detect_bursts(collected_pairs, BURST_WINDOW, BURST_MIN_COUNT).
    /// Stores the result in self.bursts.
    ///
    /// On partial read errors (a subdirectory becomes inaccessible mid-walk):
    /// continues with the paths collected so far. Files in the unreadable
    /// subdirectory are not included in burst detection and will not be downweighted.
    ///
    /// If the directory does not exist or is not accessible, stores Some(vec![])
    /// (no bursts) and logs a warning.
    ///
    /// # Lifecycle
    ///
    /// Called once per watch at daemon startup and at dynamic watch-add time,
    /// immediately after populate_classification(). Never called again during the
    /// daemon lifetime.
    pub fn populate_bursts(&mut self) {
        use crate::importance::{BURST_MIN_COUNT, BURST_WINDOW};
        use std::path::PathBuf;
        use std::time::SystemTime;

        let expanded = expand_watch_path(&self.path);
        let mut media_pairs: Vec<(PathBuf, SystemTime)> = Vec::new();
        let mut stack: Vec<PathBuf> = vec![expanded.clone()];

        while let Some(current) = stack.pop() {
            let entries = match std::fs::read_dir(&current) {
                Ok(r) => r,
                Err(e) => {
                    if current == expanded {
                        // Root directory inaccessible: store empty bursts.
                        tracing::warn!(
                            dir = %current.display(),
                            error = %e,
                            "populate_bursts: cannot read root watch directory; no burst detection"
                        );
                        self.bursts = Some(vec![]);
                        return;
                    } else {
                        // Subdirectory inaccessible: partial scan, continue.
                        tracing::debug!(
                            dir = %current.display(),
                            error = %e,
                            "populate_bursts: cannot read subdirectory; skipping"
                        );
                        continue;
                    }
                }
            };

            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else { continue };
                // Skip symlinks to avoid loops.
                if ft.is_symlink() {
                    continue;
                }
                let path = entry.path();
                if ft.is_dir() {
                    // Skip hidden directories (names starting with '.').
                    if let Some(name) = path.file_name()
                        && name.to_string_lossy().starts_with('.')
                    {
                        continue;
                    }
                    stack.push(path);
                } else if ft.is_file() {
                    // Only include media-extension files in burst detection.
                    let is_media = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| crate::importance::burst::is_media_ext(&e.to_ascii_lowercase()))
                        .unwrap_or(false);
                    if !is_media {
                        continue;
                    }
                    // Read mtime; skip file if unavailable.
                    match entry.metadata().and_then(|m| m.modified()) {
                        Ok(mtime) => media_pairs.push((path, mtime)),
                        Err(e) => {
                            tracing::debug!(
                                path = %entry.path().display(),
                                error = %e,
                                "populate_bursts: cannot read mtime; skipping file"
                            );
                        }
                    }
                }
            }
        }

        self.bursts = Some(crate::importance::detect_bursts(
            &media_pairs,
            BURST_WINDOW,
            BURST_MIN_COUNT,
        ));
    }
}

impl Default for NetworkCfg {
    fn default() -> Self {
        Self {
            enable_relay: true,
            enable_relay_server: false,
            relay_url: None,
            bootstrap_peers: vec![],
            kademlia_bootstrap_peers: vec![],
            kademlia_disable_ipfs_bootstrap: true,
            listen_port: 0,
        }
    }
}

/// [cluster] — multi-device cluster parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ClusterCfg {
    /// Maximum events per cluster sync batch.
    /// Default: 100.
    pub sync_batch_size: usize,
}

impl Default for ClusterCfg {
    fn default() -> Self {
        Self {
            sync_batch_size: DEFAULT_CLUSTER_SYNC_BATCH_SIZE,
        }
    }
}

// ============================================================
// Metrics config
// ============================================================

/// Configuration for periodic metrics push to a Prometheus-compatible endpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct MetricsCfg {
    /// Enable metrics push.
    pub enabled: bool,
    /// URL to POST Prometheus text metrics to (e.g. VictoriaMetrics import endpoint).
    pub push_url: String,
    /// Push interval in seconds.
    pub push_interval_secs: u64,
}

impl Default for MetricsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            push_url: String::new(),
            push_interval_secs: 60,
        }
    }
}

// ============================================================
// Web API config
// ============================================================

/// Configuration for the built-in web UI / JSON API server.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct WebApiCfg {
    /// Enable the web API server.
    pub enabled: bool,
    /// Bind address. Format: "<host>:<port>".
    /// Default: "127.0.0.1:0" (loopback, OS-chosen port — read from api-port file).
    /// For LAN/NAS access: "0.0.0.0:8080".
    pub bind: String,
    /// Directory containing the built SPA (index.html + assets).
    /// Relative to data_dir if not absolute. Empty = embedded assets (rust-embed).
    pub static_dir: String,
}

impl Default for WebApiCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:0".to_string(),
            static_dir: String::new(),
        }
    }
}

// ============================================================
// Restore config
// ============================================================

/// [restore] — restore staging configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct RestoreCfg {
    /// Warn in log when total size of data_dir/restore/ exceeds this threshold.
    /// Unit: gigabytes. Default: 50.
    pub staging_warn_gb: f64,
    // `fetch_timeout_secs` is gone (restore-i12): a restore has no deadline per
    // block. A legacy `fetch_timeout_secs = …` line still loads (ignored).
}

impl Default for RestoreCfg {
    fn default() -> Self {
        Self {
            staging_warn_gb: 50.0,
        }
    }
}

// ============================================================
// Reliability config
// ============================================================

/// [reliability] — scheduling and placement reliability parameters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ReliabilityConfig {
    /// Completion bonus coefficient for the priority formula.
    ///
    /// Formula: `priority = importance × (1 + k × current_alive / n_target)`
    ///
    /// * `0.0` — pure importance ordering; completion progress ignored.
    /// * `1.5` (default) — near-done blocks at same importance beat new blocks.
    /// * `5.0` (max) — strong preference for finishing blocks over starting new ones.
    ///
    /// Range: [0.0, 5.0]. Values outside range are clamped with a WARN log.
    pub completion_bonus_coefficient: f64,
}

impl Default for ReliabilityConfig {
    fn default() -> Self {
        Self {
            completion_bonus_coefficient: DEFAULT_COMPLETION_BONUS_COEFFICIENT,
        }
    }
}

// ============================================================
// Top-level config
// ============================================================

/// Unified daemon configuration. Loaded from `~/.viaticum/config.toml` or an explicit path.
/// Every field has a sensible default; `AppConfig::default()` requires no file.
///
/// Unknown sections are ignored (no `deny_unknown_fields`): a legacy `[escrow]` section from
/// before v1 removed the holder-side restore gate (restore-i6) still loads.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub backup: BackupCfg,
    pub storage: StorageCfg,
    pub network: NetworkCfg,
    pub cluster: ClusterCfg,
    pub metrics: MetricsCfg,
    pub web_api: WebApiCfg,
    pub restore: RestoreCfg,
    pub reliability: ReliabilityConfig,
    /// Per-directory watch configuration.
    /// Listed as [[watch]] array in config.toml.
    /// When empty, watch_dirs from CLI are used with DEFAULT_IMPORTANCE_MULTIPLIER.
    pub watch: Vec<WatchConfig>,
}

impl AppConfig {
    /// Load config from a TOML file at `path`.
    ///
    /// Missing fields in the file are filled with `Default::default()`.
    /// After deserialization, `normalize()` clamps out-of-range values, then
    /// `validate()` is called — returns Err if any hard constraint is violated.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let mut cfg: AppConfig = toml::from_str(&contents)?;
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Clamp any out-of-range config values, emitting WARN logs for each clamp.
    ///
    /// Called by `load()` after deserialization and before `validate()`.
    /// Absent fields are handled by `serde(default)` — no log for missing fields.
    fn normalize(&mut self) {
        let r = &mut self.reliability;
        let original = r.completion_bonus_coefficient;
        r.completion_bonus_coefficient = r
            .completion_bonus_coefficient
            .clamp(0.0, MAX_COMPLETION_BONUS_COEFFICIENT);
        if (r.completion_bonus_coefficient - original).abs() > f64::EPSILON {
            tracing::warn!(
                original,
                clamped = r.completion_bonus_coefficient,
                "reliability.completion_bonus_coefficient out of range; clamped"
            );
        }
    }

    /// Return a fully-populated config with all defaults.
    /// Equivalent to `AppConfig::default()` but named for clarity at call sites.
    pub fn defaults() -> Self {
        Self::default()
    }

    /// Validate all cross-field constraints.
    ///
    /// Called by `load()`. May also be called by callers that build
    /// `AppConfig` programmatically.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let b = &self.backup;
        let s = &self.storage;
        let n = &self.network;
        let c = &self.cluster;

        if b.source_block_size_mb < 1 {
            return Err(ConfigError::Validation {
                field: "backup.source_block_size_mb".to_string(),
                reason: "must be >= 1".to_string(),
            });
        }
        if !is_power_of_two(b.source_block_size_mb) {
            return Err(ConfigError::Validation {
                field: "backup.source_block_size_mb".to_string(),
                reason: "must be a power of two".to_string(),
            });
        }
        if b.max_versions < 1 {
            return Err(ConfigError::Validation {
                field: "backup.max_versions".to_string(),
                reason: "must be >= 1".to_string(),
            });
        }
        if b.max_version_age_days < 1 {
            return Err(ConfigError::Validation {
                field: "backup.max_version_age_days".to_string(),
                reason: "must be >= 1".to_string(),
            });
        }
        if s.soft_quota_gb < 0.0 {
            return Err(ConfigError::Validation {
                field: "storage.soft_quota_gb".to_string(),
                reason: "must be >= 0.0".to_string(),
            });
        }
        if s.hard_quota_gb < 0.0 {
            return Err(ConfigError::Validation {
                field: "storage.hard_quota_gb".to_string(),
                reason: "must be >= 0.0".to_string(),
            });
        }
        if s.disk_reserve_gb < 0.0 {
            return Err(ConfigError::Validation {
                field: "storage.disk_reserve_gb".to_string(),
                reason: "must be >= 0.0".to_string(),
            });
        }
        if s.hard_quota_gb != 0.0 && s.soft_quota_gb != 0.0 && s.hard_quota_gb > s.soft_quota_gb {
            return Err(ConfigError::Validation {
                field: "storage.hard_quota_gb".to_string(),
                reason: "hard floor cannot exceed soft ceiling".to_string(),
            });
        }
        if c.sync_batch_size < 1 {
            return Err(ConfigError::Validation {
                field: "cluster.sync_batch_size".to_string(),
                reason: "must be >= 1".to_string(),
            });
        }

        // Validate kademlia_bootstrap_peers: each entry must start with '/'
        // (basic Multiaddr syntax check; full parse happens in the daemon layer).
        for (i, addr) in n.kademlia_bootstrap_peers.iter().enumerate() {
            if addr.is_empty() || !addr.starts_with('/') {
                return Err(ConfigError::Validation {
                    field: format!("network.kademlia_bootstrap_peers[{i}]"),
                    reason: format!("invalid multiaddr '{addr}': must start with '/'"),
                });
            }
        }

        if self.web_api.enabled {
            if self.web_api.bind.is_empty() {
                return Err(ConfigError::Validation {
                    field: "web_api.bind".to_string(),
                    reason: "bind must be non-empty when web_api is enabled".to_string(),
                });
            }
            self.web_api
                .bind
                .parse::<std::net::SocketAddr>()
                .map_err(|e| ConfigError::Validation {
                    field: "web_api.bind".to_string(),
                    reason: format!("invalid socket address: {e}"),
                })?;
        }

        if self.metrics.enabled && self.metrics.push_url.is_empty() {
            return Err(ConfigError::Validation {
                field: "metrics.push_url".to_string(),
                reason: "push_url must be set when metrics are enabled".to_string(),
            });
        }

        if self.restore.staging_warn_gb <= 0.0 {
            return Err(ConfigError::Validation {
                field: "restore.staging_warn_gb".to_string(),
                reason: "must be > 0.0".to_string(),
            });
        }

        Ok(())
    }
}

// ============================================================
// Conversion helpers
// ============================================================

/// Convert AppConfig fields → source_block_size in bytes.
///
/// Returns backup.source_block_size_mb * 1_048_576.
pub fn source_block_size_bytes(cfg: &AppConfig) -> u64 {
    cfg.backup.source_block_size_mb * 1_048_576
}

/// Convert storage.soft_quota_gb → bytes. 0.0 maps to 0 (unlimited sentinel).
pub fn soft_quota_bytes(cfg: &AppConfig) -> u64 {
    if cfg.storage.soft_quota_gb == 0.0 {
        return 0;
    }
    (cfg.storage.soft_quota_gb * 1_073_741_824.0) as u64
}

/// Convert storage.hard_quota_gb → bytes. 0.0 maps to 0 (no floor sentinel).
pub fn hard_quota_bytes(cfg: &AppConfig) -> u64 {
    if cfg.storage.hard_quota_gb == 0.0 {
        return 0;
    }
    (cfg.storage.hard_quota_gb * 1_073_741_824.0) as u64
}

/// Convert storage.disk_reserve_gb → bytes.
pub fn disk_reserve_bytes(cfg: &AppConfig) -> u64 {
    if cfg.storage.disk_reserve_gb == 0.0 {
        return 0;
    }
    (cfg.storage.disk_reserve_gb * 1_073_741_824.0) as u64
}

/// Expand `~` in storage.data_dir to the user's home directory.
///
/// Uses `std::env::var("HOME")` on Unix, `USERPROFILE` on Windows.
/// If the env var is missing, returns the path as-is (no `~` expansion).
pub fn expand_data_dir(cfg: &AppConfig) -> PathBuf {
    let s = &cfg.storage.data_dir;
    if s == "~" {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        return PathBuf::from(home);
    }
    if let Some(rest) = s.strip_prefix("~/") {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(s)
    }
}

/// Expand `~` in a watch path to the user's home directory and return as PathBuf.
pub fn expand_watch_path(s: &str) -> PathBuf {
    if s == "~" {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        return PathBuf::from(home);
    }
    if let Some(rest) = s.strip_prefix("~/") {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        PathBuf::from(home).join(rest)
    } else {
        PathBuf::from(s)
    }
}

/// Derive the effective importance for a file path from the watch configs.
///
/// Finds the first WatchConfig whose expanded path is a prefix of `file_path`,
/// then computes importance in order:
///
/// 1. class = classify_file(path, wc.classification.unwrap_or_default())
/// 2. base = effective_importance(class, wc.importance_multiplier)
/// 3. Burst check: if is_in_any_burst(path, wc.bursts.as_deref().unwrap_or(&[]))
///    AND burst_downweight_selects(path): return apply_burst_downweight(base)
/// 4. Otherwise: return base
///
/// If no WatchConfig matches, returns DEFAULT_IMPORTANCE (0.5).
///
/// # Note on FolderClassification.importance_multiplier
///
/// The FolderClassification stored on WatchConfig (produced by classify_folder)
/// always has importance_multiplier = 1.0. The user-configured multiplier is
/// wc.importance_multiplier, which is what this function passes to effective_importance.
/// Do NOT pass classification.importance_multiplier.
///
/// # Ordering
///
/// The user-configured folder multiplier (step 2) is applied BEFORE burst downweight
/// (step 3). Burst downweight is a per-file correction; it does not interact
/// multiplicatively with the folder-level knob.
///
/// # Prefix matching
///
/// Same semantics as the replaced lookup_importance: a trailing '/' is appended
/// to the watch path before comparison, so '/docs' does not match '/documents/file'.
/// Tilde expansion is NOT applied to file_path (it is already absolute by the time
/// it reaches this function from the watcher).
pub fn derive_file_importance(file_path: &str, watch_cfgs: &[WatchConfig]) -> f64 {
    if let Some(wc) = find_watch_config(file_path, watch_cfgs) {
        let folder = wc.classification.clone().unwrap_or_default();
        let path = std::path::Path::new(file_path);
        let class = crate::importance::classify_file(path, &folder);
        let base = crate::importance::effective_importance(class, wc.importance_multiplier);
        let bursts = wc.bursts.as_deref().unwrap_or(&[]);
        if crate::importance::is_in_any_burst(path, bursts)
            && crate::importance::burst_downweight_selects(path)
        {
            crate::importance::apply_burst_downweight(base)
        } else {
            base
        }
    } else {
        DEFAULT_IMPORTANCE
    }
}

/// Find the first WatchConfig whose expanded path is a prefix of file_path.
/// Returns None if no match.
fn find_watch_config<'a>(
    file_path: &str,
    watch_cfgs: &'a [WatchConfig],
) -> Option<&'a WatchConfig> {
    for wc in watch_cfgs {
        let expanded = expand_watch_path(&wc.path);
        let base = expanded.to_string_lossy();
        let prefix = if base.ends_with('/') {
            base.to_string()
        } else {
            format!("{}/", base)
        };
        if file_path.starts_with(prefix.as_str()) || file_path == base.as_ref() {
            return Some(wc);
        }
    }
    None
}

// ============================================================
// Helpers
// ============================================================

fn is_power_of_two(n: u64) -> bool {
    n > 0 && (n & (n - 1)) == 0
}
