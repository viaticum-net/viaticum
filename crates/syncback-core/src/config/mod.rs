use std::path::{Path, PathBuf};

use crate::constants::{
    DEFAULT_CLUSTER_SYNC_BATCH_SIZE, DEFAULT_DISK_RESERVE_BYTES, DEFAULT_ESCROW_K_FACTOR,
    DEFAULT_MAX_VERSIONS, DEFAULT_MAX_VERSION_AGE_SECS, DEFAULT_SOURCE_BLOCK_SIZE,
    MAX_BOARD_ENTRIES, MAX_BOARD_SIZE_BYTES, RELAY_TTL_SECS,
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
    /// Default: "~/.syncback".
    pub data_dir: String,
}

impl Default for StorageCfg {
    fn default() -> Self {
        Self {
            soft_quota_gb: 0.0,
            hard_quota_gb: 0.0,
            disk_reserve_gb: DEFAULT_DISK_RESERVE_BYTES as f64 / 1_073_741_824.0,
            data_dir: "~/.syncback".to_string(),
        }
    }
}

/// [escrow] — contribution-based restore budget.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct EscrowCfg {
    /// Days of storage contribution required to earn 1 GB of restore credit.
    /// Formula: restore_budget_gb = stored_gb_days / k_factor.
    /// Default: 7.0 (store 1 GB for 7 days → earn 1 GB restore budget).
    pub k_factor: f64,
}

impl Default for EscrowCfg {
    fn default() -> Self {
        Self {
            k_factor: DEFAULT_ESCROW_K_FACTOR,
        }
    }
}

/// [network] — epidemic relay board limits.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct NetworkCfg {
    /// Maximum number of entries on the local relay board.
    /// Default: 2000 (from protocol.md §1.5).
    pub relay_max_entries: usize,

    /// Maximum total relay board size in megabytes.
    /// Default: 8.
    pub relay_max_size_mb: usize,

    /// Relay entry time-to-live in days.
    /// Default: 7.
    pub relay_ttl_days: u64,

    /// Enable libp2p circuit relay for NAT traversal. When true, the swarm
    /// uses relay servers to connect nodes behind NAT.
    /// When false, only direct connections (LAN or port-forwarded setups).
    /// Default: true.
    pub enable_relay: bool,

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
    /// Default: true (IPFS public DHT is a separate network, not useful for SyncBack).
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

/// Default importance value used when no watch config matches a path.
pub const DEFAULT_IMPORTANCE: f64 = 0.5;

fn default_importance() -> f64 {
    DEFAULT_IMPORTANCE
}

/// Per-directory watch configuration with importance override.
///
/// Listed under [[watch]] in config.toml. The daemon watches each configured
/// path (and its subdirectories) for file changes. The importance value controls
/// how many erasure symbols are allocated for files under this directory —
/// higher importance means more redundancy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct WatchConfig {
    /// Absolute or tilde-prefixed path to watch recursively.
    pub path: String,

    /// Importance override for files under this directory. Range: [0.0, 1.0].
    /// 0.0 = minimum redundancy, 1.0 = maximum redundancy.
    /// Default: 0.5.
    #[serde(default = "default_importance")]
    pub importance: f64,
}

impl Default for NetworkCfg {
    fn default() -> Self {
        Self {
            relay_max_entries: MAX_BOARD_ENTRIES,
            relay_max_size_mb: MAX_BOARD_SIZE_BYTES / 1_048_576,
            relay_ttl_days: RELAY_TTL_SECS / 86400,
            enable_relay: true,
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

    /// Timeout in seconds for fetching symbols from a holder over the network.
    /// Applied to the entire fetch_from_holders() call (across all holders for one block).
    /// Default: 60.
    pub fetch_timeout_secs: u64,
}

impl Default for RestoreCfg {
    fn default() -> Self {
        Self {
            staging_warn_gb: 50.0,
            fetch_timeout_secs: 60,
        }
    }
}

// ============================================================
// Top-level config
// ============================================================

/// Unified daemon configuration. Loaded from `~/.syncback/config.toml` or an explicit path.
/// Every field has a sensible default; `AppConfig::default()` requires no file.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub backup: BackupCfg,
    pub storage: StorageCfg,
    pub escrow: EscrowCfg,
    pub network: NetworkCfg,
    pub cluster: ClusterCfg,
    pub metrics: MetricsCfg,
    pub web_api: WebApiCfg,
    pub restore: RestoreCfg,
    /// Per-directory watch configuration.
    /// Listed as [[watch]] array in config.toml.
    /// When empty, watch_dirs from CLI are used with DEFAULT_IMPORTANCE.
    pub watch: Vec<WatchConfig>,
}

impl AppConfig {
    /// Load config from a TOML file at `path`.
    ///
    /// Missing fields in the file are filled with `Default::default()`.
    /// After deserialization, `validate()` is called — returns Err if any
    /// constraint is violated.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        let cfg: AppConfig = toml::from_str(&contents)?;
        cfg.validate()?;
        Ok(cfg)
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
        let e = &self.escrow;
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
        if e.k_factor <= 0.0 {
            return Err(ConfigError::Validation {
                field: "escrow.k_factor".to_string(),
                reason: "must be > 0.0".to_string(),
            });
        }
        if n.relay_max_entries < 1 {
            return Err(ConfigError::Validation {
                field: "network.relay_max_entries".to_string(),
                reason: "must be >= 1".to_string(),
            });
        }
        if n.relay_max_size_mb < 1 {
            return Err(ConfigError::Validation {
                field: "network.relay_max_size_mb".to_string(),
                reason: "must be >= 1".to_string(),
            });
        }
        if n.relay_ttl_days < 1 {
            return Err(ConfigError::Validation {
                field: "network.relay_ttl_days".to_string(),
                reason: "must be >= 1".to_string(),
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

/// Look up the importance for a file path by matching against watch configs.
///
/// Iterates `watch_cfgs` in order. Returns the importance of the first entry
/// whose `path` is a prefix of `file_path`. If no entry matches, returns
/// `DEFAULT_IMPORTANCE` (0.5).
///
/// Matching is prefix-based on the string representation of the path.
/// A trailing separator is added to the watch path before comparison so that
/// `/home/user/docs` does not accidentally match `/home/user/documents/file.txt`.
pub fn lookup_importance(file_path: &str, watch_cfgs: &[WatchConfig]) -> f64 {
    for wc in watch_cfgs {
        // Normalise: the watch path might or might not end with '/'.
        // We compare against "watch_path/" so `/docs` doesn't match `/documents`.
        let prefix = if wc.path.ends_with('/') {
            wc.path.clone()
        } else {
            format!("{}/", wc.path)
        };
        if file_path.starts_with(prefix.as_str()) || file_path == wc.path.as_str() {
            return wc.importance;
        }
    }
    DEFAULT_IMPORTANCE
}

// ============================================================
// Helpers
// ============================================================

fn is_power_of_two(n: u64) -> bool {
    n > 0 && (n & (n - 1)) == 0
}
