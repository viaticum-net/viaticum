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
    /// One restore job by id (restore-i4, i14).
    RestoreJobStatus {
        job_id: String,
    },
    /// Recent restore jobs, newest first.
    RestoreJobList,
    /// Connect to a peer by node address string.
    Connect {
        /// Node address of the peer (format: <device_id_hex>@<ip>:<port>).
        addr: String,
    },
}

/// Response from daemon to CLI process.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CliResponse {
    /// Boxed: `StatusData` is several times larger than every other variant.
    Status(Box<StatusData>),
    /// A restore job: the accepted job (POST /api/restore → 202) or its current state.
    RestoreJob(RestoreJob),
    /// Recent restore jobs, newest first.
    RestoreJobs(Vec<RestoreJob>),
    /// A restore request refused before any job was created (or an unknown job id).
    RestoreRejected(RestoreRejection),
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
    /// Effective quota in bytes when `quota_state` is `bytes`; 0 then means no room at all
    /// (free disk at or below the reserve, holder-i1) — never "unlimited".
    pub effective_quota_bytes: u64,
    /// `bytes` — the quota is known; `unknown` — the free disk could not be read and no
    /// soft quota is set: offers are refused, nothing is evicted (holder-i2).
    #[serde(default)]
    pub quota_state: String,
    /// "could not read free space on <path>; …" when the free disk could not be read, else "".
    #[serde(default)]
    pub quota_note: String,
    /// holder-i4: the free disk is below the reserve — `Some(bytes the pressure tick gives
    /// back)` (friends' data, down to the hard floor), at any quota; `None` otherwise.
    #[serde(default)]
    pub below_reserve_giving_back_bytes: Option<u64>,
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
    /// Job dirs under `<data_dir>/restore` (restore-i8: the daemon never deletes them).
    #[serde(default)]
    pub restore_staging_jobs: u32,
    /// Bytes under `<data_dir>/restore`; `None` while the daemon is still counting
    /// (right after start).
    #[serde(default)]
    pub restore_staging_bytes: Option<u64>,
    /// Absolute path of the staging root (`<data_dir>/restore`) on the daemon host.
    #[serde(default)]
    pub restore_staging_path: String,
    /// How restored files are published in staging (`hard_link`, `rename_noreplace`,
    /// `checked_rename`), `unavailable` if none works there (restore-i19).
    #[serde(default)]
    pub restore_publish: String,
    /// The holder is under disk pressure while staging holds restored files: staging
    /// takes space from friends' data (restore-i18).
    #[serde(default)]
    pub restore_staging_squeezes_holdings: bool,
    /// dr-i9: unix secs of this node's last recovery-pointer publication accepted by
    /// ≥ 1 postman; 0 = never (DR from the phrase would not find this catalog yet).
    #[serde(default)]
    pub dr_pointer_published_at: u64,
    /// Live files in the catalog that publication restores.
    #[serde(default)]
    pub dr_pointer_files: u32,
    /// Postmen that accepted that publication.
    #[serde(default)]
    pub dr_pointer_acks: u32,
    /// Hex of this DB's catalog history id; "" before the node minted one.
    #[serde(default)]
    pub catalog_lineage: String,
    /// dr-i11: live catalog files whose path does not exist on this machine (not
    /// re-protected until they are back).
    #[serde(default)]
    pub files_without_source: u32,
    /// dr-i39 / dr-i41: the accepted pointer has `dr_pointer_ack_threshold` acks and
    /// every catalog block it names is recoverable (owner's estimate, holders seen
    /// within 7 days).
    #[serde(default)]
    pub dr_ready: bool,
    /// Distinct friends that must hold the pointer (3; half of a circle below 6).
    #[serde(default)]
    pub dr_pointer_ack_threshold: u32,
    /// Catalog (SystemState) blocks of the accepted pointer that are recoverable.
    #[serde(default)]
    pub dr_ss_blocks_placed: u32,
    /// Catalog blocks the accepted pointer names (base + diffs).
    #[serde(default)]
    pub dr_ss_blocks_total: u32,
    /// mailbox-i49: why friends refused the newest pointer, in words ("" = no refusal).
    #[serde(default)]
    pub dr_pointer_refusal: String,
    /// mailbox-i54: unix secs since the newest catalog changes wait to enter the
    /// network; 0 = they are in.
    #[serde(default)]
    pub dr_waiting_since: u64,
    /// Why they wait, in words ("" = not waiting).
    #[serde(default)]
    pub dr_waiting: String,
    /// dr-i53: unix secs — the date of the catalog state DR from the phrase would
    /// restore (the newest restorable pointer place); 0 = DR not ready.
    #[serde(default)]
    pub dr_restores_state_of: u64,
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

// ─── Restore jobs (restore-i3, i4, i14, i15) ─────────────────────────────────

/// A restore job as the daemon reports it. The CLI polls it until `Finished`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RestoreJob {
    pub job_id: String,
    /// The path the user asked to restore (a file or a directory prefix).
    pub path: String,
    pub state: RestoreJobState,
    /// Catalog files the path matched.
    pub files_total: u32,
    /// Files visible under their own names in staging.
    pub files_restored: u32,
    /// Catalog paths of the restored files (scripts compare staging with this list).
    #[serde(default)]
    pub restored_paths: Vec<String>,
    /// Files that were not restored, each with a machine-readable reason.
    #[serde(default)]
    pub failures: Vec<RestoreFailure>,
    /// `None` until the job is finished.
    #[serde(default)]
    pub outcome: Option<RestoreOutcome>,
    /// The job's staging directory. A restored file lands at `staging_path` + its
    /// catalog path with the leading '/' stripped.
    pub staging_path: String,
    /// ISO-8601 UTC.
    pub submitted_at: String,
    /// ISO-8601 UTC; `None` while the job runs, and for a job found interrupted at
    /// startup (the daemon did not see it end).
    #[serde(default)]
    pub finished_at: Option<String>,
    /// ISO-8601 UTC. Set while the running job waits for holders that did not
    /// answer (redialed, retried at this time, restore-i26); absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_for_holders_until: Option<String>,
}

/// Lifecycle of a restore job. `Queued` exists only in the daemon's memory; the
/// job record on disk is `Running` or `Finished`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreJobState {
    Queued,
    Running,
    Finished,
}

/// How a restore job ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreOutcome {
    /// Every matched file restored, nothing failed.
    Complete,
    /// Some files restored, some failed.
    Partial,
    /// Nothing restored.
    NothingRestored,
    /// The daemon stopped (shutdown, crash, kill) before the job finished.
    Interrupted,
}

impl RestoreOutcome {
    /// `Complete ⇔ failures == 0 ∧ restored == total ∧ total > 0`; `Interrupted` if
    /// the job was stopped; `NothingRestored ⇔ restored == 0`; otherwise `Partial`.
    pub fn from_counts(
        files_total: u32,
        files_restored: u32,
        failures: usize,
        interrupted: bool,
    ) -> Self {
        if interrupted {
            RestoreOutcome::Interrupted
        } else if failures == 0 && files_restored == files_total && files_total > 0 {
            RestoreOutcome::Complete
        } else if files_restored == 0 {
            RestoreOutcome::NothingRestored
        } else {
            RestoreOutcome::Partial
        }
    }

    /// CLI exit code: complete 0, partial 2, nothing restored 1, interrupted 1.
    pub fn exit_code(self) -> i32 {
        match self {
            RestoreOutcome::Complete => 0,
            RestoreOutcome::Partial => 2,
            RestoreOutcome::NothingRestored | RestoreOutcome::Interrupted => 1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RestoreOutcome::Complete => "complete",
            RestoreOutcome::Partial => "partial",
            RestoreOutcome::NothingRestored => "nothing_restored",
            RestoreOutcome::Interrupted => "interrupted",
        }
    }
}

/// One file that was not restored, and why.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RestoreFailure {
    /// Catalog path of the file (or the requested path for a job-level failure).
    pub path: String,
    /// Records written before B1.3 have no kind: read as `internal`.
    #[serde(default)]
    pub kind: RestoreFailureKind,
    /// Human-readable detail.
    pub detail: String,
}

/// Why a file was not restored (machine-readable; the CLI and web UI explain it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreFailureKind {
    /// Not enough symbols came back from the holders; a retry later may succeed.
    HoldersUnavailable,
    /// No backed-up version matches (never backed up, or the selector matches none).
    NotBackedUp,
    /// The catalog has no usable block record for the file.
    BlockMissing,
    /// The data did not decode, decrypt, decompress or unpack.
    Corrupt,
    /// The catalog path is unsafe to write.
    PathUnsafe,
    /// Writing into staging failed (disk full, name taken, filesystem).
    WriteFailed,
    /// The daemon stopped before this file was restored.
    Interrupted,
    #[default]
    Internal,
}

impl RestoreFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RestoreFailureKind::HoldersUnavailable => "holders_unavailable",
            RestoreFailureKind::NotBackedUp => "not_backed_up",
            RestoreFailureKind::BlockMissing => "block_missing",
            RestoreFailureKind::Corrupt => "corrupt",
            RestoreFailureKind::PathUnsafe => "path_unsafe",
            RestoreFailureKind::WriteFailed => "write_failed",
            RestoreFailureKind::Interrupted => "interrupted",
            RestoreFailureKind::Internal => "internal",
        }
    }
}

/// A restore request refused before any job exists, or a lookup of an unknown job.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum RestoreRejection {
    /// No catalog record at the path and none under it as a directory.
    NotInCatalog {
        path: String,
    },
    /// The path matches catalog records, but none has a selectable backed-up version.
    NotBackedUp {
        path: String,
    },
    /// `--version N` names no backed-up version under the path; `available` lists
    /// the (1-based) version numbers that are backed up there, ascending.
    VersionNotFound {
        path: String,
        version: u32,
        available: Vec<u32>,
    },
    /// `--dest` is not supported.
    DestNotSupported,
    InvalidDate {
        date: String,
    },
    /// The restore queue is full.
    Busy {
        active: u32,
    },
    /// The restore coordinator is not running (daemon shutting down).
    Unavailable,
    UnknownJob {
        job_id: String,
    },
}

impl RestoreRejection {
    /// HTTP status the web API answers with.
    pub fn http_status(&self) -> u16 {
        match self {
            RestoreRejection::NotInCatalog { .. }
            | RestoreRejection::VersionNotFound { .. }
            | RestoreRejection::UnknownJob { .. } => 404,
            RestoreRejection::NotBackedUp { .. } => 422,
            RestoreRejection::DestNotSupported | RestoreRejection::InvalidDate { .. } => 400,
            RestoreRejection::Busy { .. } | RestoreRejection::Unavailable => 503,
        }
    }
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

/// Lifecycle state for a file's latest version, computed from placement counts.
/// Drives the badge in the UI. See `compute_effective_status`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EffectiveStatus {
    /// In encoder queue, no source block yet.
    Queued,
    /// Source block created, holders haven't accepted enough.
    /// `live` = placements in Alive; `target` = `k_eff` for the block.
    Replicating { live: u32, target: u32 },
    /// `live >= target` (k_eff alive): the network can rebuild it. Greenlight.
    /// No holder-side gate can refuse the owner (restore-i6).
    Restorable { live: u32, target: u32 },
    /// We had `target` Alive at some point; now `live < target` after losses.
    /// Repair pipeline is responsible for bringing it back.
    Degraded { live: u32, lost: u32, target: u32 },
}

/// Owner-side estimate of why restoring a version would not succeed right now
/// (`VersionEntry.restore_blocker`, from placement counts).
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
