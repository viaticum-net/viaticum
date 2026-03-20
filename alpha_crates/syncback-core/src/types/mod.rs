use crate::constants::{
    ERASURE_K, SECS_PER_WEEK, TIER_HIGH_N, TIER_HIGH_THRESHOLD, TIER_LOW_N, TIER_LOW_THRESHOLD,
    TIER_MID_N, TIER_MID_THRESHOLD,
};

// ============================================================
// Newtype ID wrappers
// ============================================================

/// BLAKE3 hash of shard blob content. 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ShardId(pub [u8; 32]);

/// Identifier of a unit (pack or chunk). Derived from owner+index+hash.
/// 32 bytes, opaque — exact derivation is in shard_manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct UnitId(pub [u8; 32]);

/// Ed25519 public key of a peer identity. 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct IdentityPub(pub [u8; 32]);

/// Monotonically-increasing file identifier. u64, assigned on first index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FileId(pub u64);

/// iroh NodeId — the transport-layer peer identity. 32 bytes (Ed25519 pubkey).
/// Distinct from IdentityPub: IdentityPub = "who you are", NodeId = "how to reach you".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NodeId(pub [u8; 32]);

// --- Display ---

impl std::fmt::Display for ShardId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode_upper_lower(&self.0[..8]))
    }
}

impl std::fmt::Display for UnitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode_upper_lower(&self.0[..8]))
    }
}

impl std::fmt::Display for IdentityPub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode_upper_lower(&self.0[..8]))
    }
}

impl std::fmt::Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode_upper_lower(&self.0[..8]))
    }
}

// Inline helper — lowercase hex of a byte slice.
mod hex {
    pub fn encode_upper_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// --- AsRef<[u8]> ---

impl AsRef<[u8]> for ShardId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for UnitId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for IdentityPub {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for NodeId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ============================================================
// Timestamp
// ============================================================

/// Unix timestamp in seconds. u64 — no negatives, good until year 2554.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Current wall-clock time (seconds since Unix epoch).
    /// Uses std::time::SystemTime — no tokio dependency.
    pub fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs();
        Timestamp(secs)
    }

    /// Add a number of seconds.
    pub fn add_secs(self, secs: u64) -> Self {
        Timestamp(self.0 + secs)
    }

    /// Add a number of weeks (1 week = 604800 seconds).
    pub fn add_weeks(self, weeks: u64) -> Self {
        Timestamp(self.0 + weeks * SECS_PER_WEEK)
    }

    /// How many whole weeks have elapsed since `self` as of `now`.
    /// Returns 0 if `now` < `self`.
    pub fn weeks_elapsed(self, now: Timestamp) -> u64 {
        if now.0 <= self.0 {
            return 0;
        }
        (now.0 - self.0) / SECS_PER_WEEK
    }

    /// How many whole seconds have elapsed since `self` as of `now`.
    pub fn secs_elapsed(self, now: Timestamp) -> u64 {
        if now.0 <= self.0 {
            return 0;
        }
        now.0 - self.0
    }
}

// ============================================================
// Erasure coding tier
// ============================================================

/// Reed-Solomon tier derived from importance score.
/// Tiers are fixed by the protocol recommendation (overview.md §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ErasureTier {
    /// importance >= 0.8 → 5-of-15 (×3.0 overhead)
    High,
    /// importance >= 0.4 → 5-of-10 (×2.0 overhead)
    Medium,
    /// importance >= 0.1 → 5-of-7 (×1.4 overhead)
    Low,
}

impl ErasureTier {
    /// Minimum shards required for reconstruction (k).
    pub fn k(self) -> usize {
        ERASURE_K as usize
    }

    /// Total shards before adaptive adjustment (n_base).
    pub fn n_base(self) -> usize {
        match self {
            ErasureTier::High => TIER_HIGH_N as usize,
            ErasureTier::Medium => TIER_MID_N as usize,
            ErasureTier::Low => TIER_LOW_N as usize,
        }
    }

    /// Overhead multiplier (n_base / k), as a float.
    pub fn overhead(self) -> f64 {
        self.n_base() as f64 / self.k() as f64
    }

    /// Derive tier from importance score [0.0, 1.0].
    /// importance < 0.1 → None (do not back up).
    pub fn from_importance(importance: f64) -> Option<Self> {
        if importance >= TIER_HIGH_THRESHOLD {
            Some(ErasureTier::High)
        } else if importance >= TIER_MID_THRESHOLD {
            Some(ErasureTier::Medium)
        } else if importance >= TIER_LOW_THRESHOLD {
            Some(ErasureTier::Low)
        } else {
            None
        }
    }
}

// ============================================================
// File type
// ============================================================

/// Whether a shard belongs to user data or the system state backup.
/// Stored in ShardDescriptor, signed by owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    /// Normal user file shard.
    User,
    /// System state backup shard. Holder stores with max priority, TTL 5 years.
    System,
}

// ============================================================
// Shard state (holder side)
// ============================================================

/// Lifecycle state of a shard on the holder's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ShardState {
    /// Stored, PoS challenges expected. High priority.
    Active,
    /// Owner sent `delete`. Cooling down (4 weeks). Then delete.
    MarkedForDelete,
    /// No PoS challenges, no delete message. Owner silent.
    /// Priority determined by owner trust.
    Silent,
}

// ============================================================
// Unit type and status
// ============================================================

/// How the unit was created from the source file(s).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UnitType {
    /// Multiple small files packed into one unit.
    Pack,
    /// One chunk of a large file (≥ U bytes). Index stored in UnitRecord.
    Chunk,
}

/// Lifecycle status of a unit on the owner's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UnitStatus {
    /// Current version, shards distributed in network.
    Active,
    /// One or more member files have changed. Unit exists in network but is outdated.
    Stale,
    /// Delete message sent to all holders. Waiting for cooldown.
    Deleting,
    /// Cooldown elapsed, treated as removed.
    Deleted,
}

// ============================================================
// Shard status (owner side)
// ============================================================

/// Status of a shard from the owner's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ShardStatus {
    /// shard_offer sent, no shard_accept/reject yet.
    Offered,
    /// shard_accept received, blob transfer in progress.
    Accepted,
    /// shard_stored received. Holder confirmed storage.
    Stored,
    /// Holder dropped or lost the shard (shard_dropped, PoS fail, timeout).
    Lost,
    /// delete message sent. Cooldown in progress.
    Deleting,
}

// ============================================================
// Record structs
// ============================================================

/// Stored in the `files` table. Key: file_path (UTF-8 string bytes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileRecord {
    pub file_id: FileId,
    /// Canonical absolute path (UTF-8).
    pub path: String,
    /// BLAKE3 hash of the file's last-seen content.
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    /// Importance score from config, range [0.0, 1.0].
    pub importance: f64,
    /// File has changed since last backup. Watcher sets this.
    pub dirty: bool,
    /// Current unit containing this file's latest version.
    /// None before first backup or after deletion.
    pub current_unit_id: Option<UnitId>,
    /// When this file was last successfully backed up.
    pub last_backed_up: Option<Timestamp>,
    /// Whether this file has ever been fully backed up.
    pub backed_up: bool,
    /// When the file was first indexed.
    pub first_seen: Timestamp,
}

/// Stored in the `units` table. Key: UnitId (32 bytes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnitRecord {
    pub unit_id: UnitId,
    pub unit_type: UnitType,
    pub status: UnitStatus,
    /// File IDs that are members of this pack. For Chunk units: single element.
    pub member_file_ids: Vec<FileId>,
    /// For Chunk units: which chunk (0-indexed) of the parent file.
    pub chunk_index: Option<u32>,
    /// For Chunk units: the parent file.
    pub parent_file_id: Option<FileId>,
    /// Unencrypted size of this unit's content in bytes.
    pub size_bytes: u64,
    /// BLAKE3 hash of the unencrypted plaintext unit content.
    pub plaintext_hash: [u8; 32],
    /// When this unit was created.
    pub created_at: Timestamp,
    /// Average importance of member files. Used for erasure tier selection.
    pub importance_avg: f64,
    /// Reed-Solomon k parameter used when sharding this unit.
    pub rs_k: u8,
    /// Reed-Solomon n parameter (actual, post-adaptive adjustment).
    pub rs_n: u8,
}

/// Stored in the `shards` table. Key: ShardId (32 bytes).
/// Represents a shard the local node has placed in the network (owner view).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardRecord {
    pub shard_id: ShardId,
    pub unit_id: UnitId,
    /// Index of this shard in the RS set (0-indexed).
    pub shard_index: u8,
    /// Peer holding this shard.
    pub holder_id: IdentityPub,
    pub status: ShardStatus,
    /// Timestamp of last successful PoS verification.
    pub last_verified: Option<Timestamp>,
    /// When this shard was offered.
    pub offered_at: Timestamp,
    /// When shard_stored was received.
    pub stored_at: Option<Timestamp>,
    /// BLAKE3 Merkle root over 64 KB blocks of the shard blob.
    /// Used by the owner to verify PoS responses from the holder.
    #[serde(default)]
    pub merkle_root: [u8; 32],
}

/// Stored in the `peers` table. Key: IdentityPub (32 bytes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerRecord {
    pub identity: IdentityPub,
    /// Last known iroh NodeId for transport connection.
    pub node_id: Option<NodeId>,
    /// P component: rolling 4-week PoS success rate.
    /// Range [0.0, 1.0].
    pub trust_p: f64,
    /// I component: cumulative mean PoS success rate.
    /// Range [0.0, 1.0].
    pub trust_i: f64,
    /// S component: pairwise storage ratio (their_stored_for_us / our_stored_for_them).
    /// Range [0.0, ∞), clamped to [0.1, 1.0] in trust formula.
    pub trust_s: f64,
    /// Total bytes we have sent to this peer (for S calculation).
    pub bytes_sent_to_peer: u64,
    /// Total bytes we have received from this peer (for S calculation).
    pub bytes_received_from_peer: u64,
    /// When this peer was first seen.
    pub first_seen: Timestamp,
    /// When we last received any message from this peer.
    pub last_seen: Timestamp,
    /// How many weeks this peer has been in the network (cumulative, never decrements).
    pub weeks_in_network: u32,
    /// IPv4 /24 subnet prefix (first 3 octets), or None if unknown/IPv6.
    /// Used for Sybil resistance: max 1 shard per /24.
    pub subnet_prefix: Option<[u8; 3]>,
    /// Whether this peer is manually trusted (trusted identity / allowlist).
    /// Shards from allowlisted peers are never evicted and bypass escrow.
    pub allowlisted: bool,
}

/// Stored in the `holding` table. Key: ShardId (32 bytes).
/// Represents a shard we are holding for someone else (holder view).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HoldingRecord {
    pub shard_id: ShardId,
    pub owner_pub: IdentityPub,
    /// Importance claimed by owner in ShardDescriptor. Verified via signature.
    pub importance: f64,
    /// Shard blob size on disk in bytes.
    pub size_bytes: u64,
    /// Lifecycle state on our side.
    pub state: ShardState,
    /// When we received and stored this shard.
    pub received_at: Timestamp,
    /// When we received a `delete` message from owner. None if no delete request.
    pub delete_requested_at: Option<Timestamp>,
    /// When we sent shard_drop_notice to owner (Phase 2 disk pressure).
    /// Shard deletable after sent_at + DROP_NOTICE_WINDOW_SECS (7 days).
    pub drop_notice_sent_at: Option<Timestamp>,
    /// file_type from ShardDescriptor: User or System.
    pub file_type: FileType,
    /// Merkle root from ShardDescriptor (for PoS verification).
    pub merkle_root: [u8; 32],
    /// RS k parameter from ShardDescriptor.
    pub rs_k: u8,
    /// RS n parameter from ShardDescriptor.
    pub rs_n: u8,
    /// Shard index in RS set (0-indexed).
    pub shard_index: u8,
}

/// Stored in the `escrow_restore_log` table. Key = IdentityPub (32 bytes).
/// Tracks cumulative bytes served by this holder to each owner via restore.
/// Holder-local heuristic for escrow tier determination.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EscrowRestoreLog {
    pub owner_pub: IdentityPub,
    /// Total bytes served to this owner via restore operations.
    pub bytes_restored: u64,
    /// Timestamp of the first restore we served to this owner.
    pub first_restore_at: Option<Timestamp>,
    /// Timestamp of the most recent restore we served to this owner.
    pub last_restore_at: Option<Timestamp>,
}

/// Stored in SYSTEM_STATE_BLOBS. Keyed by owner IdentityPub.
/// The holder stores one entry per owner whose system state it holds.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemStateBlobRecord {
    /// Encrypted system state blob (only readable by the owner's identity key).
    pub blob: Vec<u8>,
    /// When the owner created this backup (from the message).
    pub created_at: Timestamp,
    /// When this node received and stored it.
    pub received_at: Timestamp,
}

/// Stored in the `budget` table. Singleton, key = "budget".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BudgetRecord {
    /// Estimated network storage budget available for our backups, in GB.
    pub estimated_gb: f64,
    /// When the last budget estimation ran.
    pub last_calculated: Timestamp,
    /// Fraction of recent shard_offer attempts that got shard_stored.
    /// Range [0.0, 1.0].
    pub placement_success_rate: f64,
    /// Rolling window of (offered, accepted) counts per week.
    /// Length <= WEEKLY_STATS_WINDOW (4). Oldest entry at index 0.
    /// Added in budget module; default = empty vec for backward-compatible deserialization.
    #[serde(default)]
    pub weekly_stats: Vec<(u32, u32)>,
}

/// Stored in the `schedule` table. Key = task name (UTF-8).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScheduleRecord {
    pub task_name: String,
    pub last_run: Option<Timestamp>,
    pub next_run: Timestamp,
}

/// Signed descriptor attached to a shard. Sent in shard_offer messages.
/// Holder verifies this before accepting blob.
/// See overview.md §1.2 and §1.7.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardDescriptor {
    /// BLAKE3 hash of the raw shard blob content.
    pub shard_id: ShardId,
    /// Unit this shard belongs to (encryption scope).
    pub unit_id: UnitId,
    /// Zero-indexed position in the RS set.
    pub shard_index: u8,
    /// Minimum shards required for reconstruction.
    pub rs_k: u8,
    /// Total shards in the RS set.
    pub rs_n: u8,
    /// Root of the BLAKE3 Merkle tree over 64 KB blocks (for PoS).
    pub merkle_root: [u8; 32],
    /// Owner's Ed25519 public key.
    pub owner_pub: IdentityPub,
    /// Importance score [0.0, 1.0].
    pub importance: f64,
    /// User data or system state backup.
    pub file_type: FileType,
    /// When this descriptor was created.
    pub created_at: Timestamp,
    /// Ed25519 signature over all fields above, by owner's identity key.
    /// Covers CBOR encoding of all preceding fields in field order.
    #[serde(with = "sig64")]
    pub sig_owner: [u8; 64],
}

/// Serde helper for `[u8; 64]` — serde only auto-impls arrays up to 32 bytes.
mod sig64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        bytes.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes for sig_owner"))
    }
}

// ============================================================
// CBOR serialization helpers
// ============================================================

/// Serialize a value to CBOR bytes.
/// Panics if serialization fails (only possible with non-serializable types —
/// all types in this module serialize cleanly).
pub fn to_cbor_bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).expect("cbor serialization failed");
    buf
}

/// Deserialize a value from CBOR bytes.
pub fn from_cbor_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CborError> {
    ciborium::de::from_reader(bytes).map_err(|e| CborError::Decode(e.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum CborError {
    #[error("cbor decode: {0}")]
    Decode(String),
}


#[cfg(test)]
mod tests;
