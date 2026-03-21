/// Request sent from CLI process to daemon over Unix socket.
/// Wire types for CLI ↔ daemon communication.
/// Encoded as CBOR with u32 BE length prefix over a Unix socket.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CliRequest {
    Status,
    Restore {
        path: String,
        /// Version index (1-based). None = latest.
        version: Option<u32>,
        /// ISO-8601 date string, e.g. "2026-01-15". None = latest.
        date: Option<String>,
        /// Destination path override. None = restore in place.
        dest: Option<String>,
    },
    DeviceList,
    DeviceAdd {
        /// Human-readable label for the new device.
        label: String,
    },
    DeviceRevoke {
        /// Hex-encoded DeviceId (16 bytes = 32 hex chars).
        device_id_hex: String,
    },
    Files {
        /// Optional path prefix filter. None = list all.
        path_prefix: Option<String>,
    },
    Versions {
        path: String,
    },
    /// Connect to a peer by iroh address string.
    Connect {
        /// Iroh node address of the peer.
        addr: String,
    },
}

/// Response from daemon to CLI process.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CliResponse {
    Status(StatusData),
    Restore(RestoreData),
    DeviceList(Vec<DeviceEntry>),
    DeviceAdded(DeviceEntry),
    DeviceRevoked { device_id_hex: String },
    Files(Vec<FileEntry>),
    Versions(Vec<VersionEntry>),
    /// Response to Connect: contains the peer's identity pubkey as hex.
    Connected {
        /// Hex-encoded IdentityPub of the connected peer.
        peer_id: String,
    },
    Error(String),
}

/// Data for the `status` subcommand.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StatusData {
    /// This node's identity pubkey (hex).
    pub node_identity: String,
    /// This node's iroh endpoint address (for `syncback connect`).
    pub node_addr: String,
    /// Number of known peers.
    pub peer_count: u32,
    /// Average trust score across all peers (combined score).
    pub avg_trust: f64,
    /// Total bytes we are storing for others.
    pub holding_bytes: u64,
    /// Total backed-up files (all versions counted once per path).
    pub backed_up_files: u32,
    /// Total raw bytes of all files backed up (latest version only).
    pub backed_up_bytes: u64,
    /// Number of source blocks with needs_repair == true.
    pub blocks_needing_repair: u32,
    /// Peer summaries (up to 20 entries, sorted by trust descending).
    pub peers: Vec<PeerSummary>,
    /// Effective quota in bytes. 0 = unlimited.
    pub effective_quota_bytes: u64,
    /// Bytes currently used for held symbols.
    pub used_bytes: u64,
}

/// Peer summary shown in `syncback status`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PeerSummary {
    /// First 8 bytes of identity pubkey, hex (16 chars).
    pub identity_hex: String,
    /// Combined trust score.
    pub trust: f64,
    /// Bytes we store for this peer.
    pub bytes_we_store: u64,
    /// Bytes this peer stores for us.
    pub bytes_peer_stores: u64,
    /// ISO-8601 date of last_seen.
    pub last_seen: String,
}

/// Data returned by `syncback restore`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RestoreData {
    pub path: String,
    pub version_used: u32,
    pub content_hash_hex: String,
    /// "started" | "queued" | "error"
    pub status: String,
}

/// Device entry for `syncback device list`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeviceEntry {
    /// Hex-encoded DeviceId (16 bytes = 32 hex chars).
    pub device_id_hex: String,
    /// Human-readable label.
    pub label: String,
    /// True if this is the current device.
    pub is_current: bool,
    /// ISO-8601 date the device was added.
    pub added_at: String,
    /// True if revoked.
    pub revoked: bool,
}

/// File entry for `syncback files`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FileEntry {
    pub path: String,
    /// Number of versions.
    pub versions: u32,
    /// Latest version's backed_up_at as ISO-8601 date, or "pending" if None.
    pub last_backed_up: String,
    /// Size in bytes of the latest version.
    pub size_bytes: u64,
    /// Whether the file is locally present on any device.
    pub local_state: String,
}

/// Version entry for `syncback versions <path>`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct VersionEntry {
    /// 1-based version index (1 = oldest, N = newest).
    pub version: u32,
    /// ISO-8601 datetime.
    pub created_at: String,
    /// ISO-8601 datetime, or "pending" if backed_up_at is None.
    pub backed_up_at: String,
    /// BLAKE3 hex of content.
    pub content_hash_hex: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Block ID hex.
    pub source_block_id_hex: String,
}

/// Errors from CLI operations.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("daemon not running (socket not found at {path})")]
    DaemonNotRunning { path: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encode error: {0}")]
    Encode(String),

    #[error("decode error: {0}")]
    Decode(String),

    #[error("daemon returned error: {0}")]
    DaemonError(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}
