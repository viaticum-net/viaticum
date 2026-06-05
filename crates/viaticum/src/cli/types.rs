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
    /// Connect to a peer by node address string.
    Connect {
        /// Node address of the peer (format: <device_id_hex>@<ip>:<port>).
        addr: String,
    },
}

/// Response from daemon to CLI process.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CliResponse {
    Status(StatusData),
    Restore(RestoreData),
    /// Restore was rejected before any data movement; reason carried in `RestoreBlocker`.
    /// Maps to HTTP 409 in `web_api`.
    RestoreBlocked(RestoreBlocker),
    DeviceList(Vec<DeviceEntry>),
    DeviceAdded(DeviceEntry),
    DeviceRevoked {
        device_id_hex: String,
    },
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
    /// This node's DeviceId, first 8 bytes hex (16 chars). Matches PeerSummary.identity_hex.
    #[serde(default)]
    pub device_id: String,
    /// This node's libp2p address (for `viaticum connect`).
    pub node_addr: String,
    /// Number of known peers (PeerRecord rows in DB — includes peers that
    /// were once seen via libp2p `identify` but never completed the viaticum
    /// cert exchange). For the count of peers we can actually exchange heavy
    /// messages with, use `peer_count_authenticated`.
    pub peer_count: u32,
    /// Number of peers libp2p currently has a live transport-level connection
    /// to (post-Noise + identify). Subset of `peer_count`. 0 if swarm is down.
    #[serde(default)]
    pub peer_count_connected: u32,
    /// Number of peers that have completed the viaticum cert exchange and
    /// are authorised for placement / restore / PoS traffic. Strict subset of
    /// `peer_count_connected`. Restored from in-memory swarm state, so this
    /// resets on daemon restart until cert exchange runs again.
    #[serde(default)]
    pub peer_count_authenticated: u32,
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
    /// Total PoS challenges issued (all peers, all weeks).
    #[serde(default)]
    pub pos_total_challenges: u32,
    /// Total PoS challenges passed (all peers, all weeks).
    #[serde(default)]
    pub pos_total_passes: u32,
    /// Total placement records.
    #[serde(default)]
    pub placement_count: u32,
    /// Placements with Alive status.
    #[serde(default)]
    pub placement_alive: u32,
    /// Placements with Lost/PresumedLost status.
    #[serde(default)]
    pub placement_lost: u32,
    /// Source blocks with alive placements >= k (healthy).
    #[serde(default)]
    pub blocks_ok: u32,
    /// Source blocks with alive placements < k (at risk).
    #[serde(default)]
    pub blocks_at_risk: u32,
    /// DB table row counts (shown only in --json mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_stats: Option<viaticum_core::db::TableStats>,
    /// Per-importance-bucket reliability aggregate.
    /// Always present with 5 entries (critical, high, medium, low, trivial).
    /// Empty buckets have block_count=0, mean_p_recoverable=0.0, status="empty".
    #[serde(default)]
    pub by_importance: Vec<viaticum_core::types::ImportanceBucketStats>,
}

/// Peer summary shown in `viaticum status`.
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
    /// Proportional trust component.
    #[serde(default)]
    pub trust_p: f64,
    /// Integral trust component.
    #[serde(default)]
    pub trust_i: f64,
    /// Storage balance factor.
    #[serde(default)]
    pub trust_s: f64,
    /// PoS challenges in last 4 weeks.
    #[serde(default)]
    pub pos_challenges_recent: u32,
    /// PoS passes in last 4 weeks.
    #[serde(default)]
    pub pos_passes_recent: u32,
    /// "auth" / "conn" / "known": "auth" — cert exchange complete (any device
    /// of this master is in swarm.authenticated); "conn" — at least one device
    /// has a live libp2p connection (post-Noise+identify) but cert exchange
    /// hasn't finished; "known" — only PeerRecord row in DB, no live link.
    #[serde(default = "default_link")]
    pub link: String,
}

fn default_link() -> String {
    "known".to_string()
}

/// Data returned by `viaticum restore`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RestoreData {
    pub path: String,
    pub version_used: u32,
    pub content_hash_hex: String,
    /// "started" | "queued" | "error"
    pub status: String,
    /// Absolute path to the per-job staging directory on the server.
    /// Example: "/home/alice/.viaticum/restore/550e8400-.../home/alice/docs/report.docx"
    #[serde(default)]
    pub staging_path: String,
}

/// Device entry for `viaticum device list`.
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

/// Lifecycle state for a file's latest version, computed from placement counts
/// + escrow estimate. Drives the badge in the UI. See `compute_effective_status`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EffectiveStatus {
    /// In encoder queue, no source block yet.
    Queued,
    /// Source block created, holders haven't accepted enough.
    /// `live` = placements in Alive; `target` = `k_eff` for the block.
    Replicating { live: u32, target: u32 },
    /// `live >= target` (k_eff alive), restore would also succeed today
    /// (escrow budget is sufficient). Greenlight.
    Restorable { live: u32, target: u32 },
    /// `live >= target` but restore would be denied — escrow budget is below
    /// what this block needs. Common right after first replication when
    /// contribution hasn't accrued yet.
    ReplicatedCold {
        live: u32,
        target: u32,
        est_seconds_to_restorable: Option<u64>,
    },
    /// We had `target` Alive at some point; now `live < target` after losses.
    /// Repair pipeline is responsible for bringing it back.
    Degraded { live: u32, lost: u32, target: u32 },
}

/// Reason a restore cannot succeed right now. Returned in 409 Conflict from
/// POST /api/restore; UI surfaces it verbatim with a human-readable message.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RestoreBlocker {
    /// `live < k_eff` — not enough Alive placements (some holders offline /
    /// repair pending). Auto-resolves when more come back.
    InsufficientPlacements {
        have: u32,
        need: u32,
        holders_offline: u32,
    },
    /// All holders refused via escrow because we haven't earned enough
    /// contribution yet. `est_seconds` is a rough wait-time estimate or None
    /// if we can't predict (e.g. nothing accruing).
    EscrowLocked {
        budget_gb: f64,
        needed_gb: f64,
        est_seconds: Option<u64>,
    },
    /// All `Alive` holders are unreachable (last_seen too old).
    AllHoldersOffline { last_seen_secs_ago: u64 },
}

/// File entry for `viaticum files`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FileEntry {
    pub path: String,
    /// Number of versions.
    pub versions: u32,
    /// Latest version's backed_up_at as ISO-8601 date, or "pending" if None.
    pub last_backed_up: String,
    /// Size in bytes of the latest version (encoded block size today; see
    /// `FileVersion.source_size` tech-debt).
    pub size_bytes: u64,
    /// Whether the file is locally present on any device.
    pub local_state: String,
    /// Lifecycle state for the latest version. None for files with no version.
    pub effective_status: Option<EffectiveStatus>,
    /// True when the latest version is backed up and its source block has reached
    /// its reliability target — i.e. the network can reconstruct it without the
    /// local source, so deleting the local copy is safe. Conservative: false when
    /// not backed up, no block found, or below target.
    pub is_safe_to_delete: bool,
}

/// Version entry for `viaticum versions <path>`.
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
    /// Size in bytes (encoded block size; see source_size tech-debt).
    pub size_bytes: u64,
    /// Block ID hex.
    pub source_block_id_hex: String,
    /// Lifecycle state for THIS version's source block.
    pub effective_status: EffectiveStatus,
    /// None if restore would succeed, Some(reason) otherwise. Estimate based
    /// on owner-side data — actual restore may still differ.
    pub restore_blocker: Option<RestoreBlocker>,
}

/// Errors from CLI operations.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("daemon not reachable: {reason}")]
    DaemonNotReachable { reason: String },

    #[error("daemon refused auth — token mismatch")]
    Unauthorized,

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
