use crate::constants::{
    DECODE_OVERHEAD, OVERHEAD_BASE, OVERHEAD_SCALE, SECS_PER_WEEK, SYMBOL_SIZE,
};

// ============================================================
// Newtype ID wrappers
// ============================================================

/// BLAKE3 hash of encrypted source block content. 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SourceBlockId(pub [u8; 32]);

/// Ed25519 public key of a peer identity (master key). 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct IdentityPub(pub [u8; 32]);

/// Random device identifier, stored in ~/.syncback/device_id. 16 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DeviceId(pub [u8; 16]);

/// Monotonically-increasing file identifier. u64, assigned on first index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FileId(pub u64);

/// iroh NodeId — transport-layer peer identity. 32 bytes (Ed25519 pubkey).
/// Distinct from IdentityPub: IdentityPub = "who you are", NodeId = "how to reach you".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NodeId(pub [u8; 32]);

// --- Display ---

impl std::fmt::Display for SourceBlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex_lower(&self.0[..8]))
    }
}

impl std::fmt::Display for IdentityPub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex_lower(&self.0[..8]))
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex_lower(&self.0[..8]))
    }
}

impl std::fmt::Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex_lower(&self.0[..8]))
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- AsRef<[u8]> ---

impl AsRef<[u8]> for SourceBlockId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for IdentityPub {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for DeviceId {
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

/// Unix timestamp in seconds.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs();
        Timestamp(secs)
    }

    pub fn add_secs(self, secs: u64) -> Self {
        Timestamp(self.0 + secs)
    }

    pub fn add_weeks(self, weeks: u64) -> Self {
        Timestamp(self.0 + weeks * SECS_PER_WEEK)
    }

    pub fn weeks_elapsed(self, now: Timestamp) -> u64 {
        now.0.saturating_sub(self.0) / SECS_PER_WEEK
    }

    pub fn secs_elapsed(self, now: Timestamp) -> u64 {
        now.0.saturating_sub(self.0)
    }
}

// ============================================================
// Erasure parameters
// ============================================================

/// Computed erasure coding parameters for a source block.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ErasureParams {
    /// Source symbols count (source_block_size / T).
    pub k: u32,
    /// Effective K for decode (K + DECODE_OVERHEAD).
    pub k_eff: u32,
    /// Symbol size in bytes.
    pub t: u16,
    /// Overhead multiplier (1.5 + importance * 1.5).
    pub overhead: f64,
    /// Total symbols to distribute (k_eff * overhead, rounded up).
    pub n: u32,
}

impl ErasureParams {
    /// Compute erasure parameters for a given source block size and importance.
    pub fn compute(source_block_size: u64, importance: f64) -> Self {
        let t = SYMBOL_SIZE;
        let k = (source_block_size as f64 / t as f64).ceil() as u32;
        let k_eff = k + DECODE_OVERHEAD;
        let overhead = OVERHEAD_BASE + importance.clamp(0.0, 1.0) * OVERHEAD_SCALE;
        let n = (k_eff as f64 * overhead).ceil() as u32;
        ErasureParams {
            k,
            k_eff,
            t,
            overhead,
            n,
        }
    }

    /// Max symbols any single holder should store.
    /// min(K_eff - 1, concentration_cap * N).
    pub fn max_per_holder(&self) -> u32 {
        let cap_fraction = (1.0 - 1.0 / self.overhead) * crate::constants::CONCENTRATION_CAP_FACTOR;
        let cap = (cap_fraction * self.n as f64).floor() as u32;
        cap.min(self.k_eff - 1)
    }
}

// ============================================================
// File types
// ============================================================

/// Category for packing queue assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FileCategory {
    Photo,
    Document,
    Video,
    Other,
}

/// Local state of a file on a specific device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LocalState {
    Present,
    Deleted(Timestamp),
}

// ============================================================
// Source block
// ============================================================

/// How the source block was created.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SourceBlockType {
    /// Batch of small files packed together. Index describes contents.
    Pack { entries: Vec<PackEntry> },
    /// One file (or one chunk of a large file).
    Single,
}

/// Entry in a pack index: which file, at what offset and size within the pack.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PackEntry {
    pub file_id: FileId,
    pub offset: u64,
    pub size: u64,
}

/// Lifecycle status of a source block on the owner's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SourceBlockStatus {
    /// Symbols distributed, active.
    Active,
    /// >50% members invalid, vacuum candidate.
    Stale,
    /// Delete in progress (cooldown).
    Deleting,
    /// Fully cleaned up.
    Deleted,
}

// ============================================================
// Records (stored in DB)
// ============================================================

/// File catalog entry. Key: file path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileRecord {
    pub file_id: FileId,
    pub path: String,
    pub importance: f64,
    pub devices: Vec<(DeviceId, LocalState)>,
    pub versions: Vec<FileVersion>,
    pub first_seen: Timestamp,
}

/// One version of a file (immutable once created).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileVersion {
    pub content_hash: [u8; 32],
    pub source_block_id: SourceBlockId,
    pub k: u32,
    pub t: u16,
    pub created_at: Timestamp,
    pub backed_up_at: Option<Timestamp>,
}

/// Source block metadata. Key: SourceBlockId.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SourceBlockRecord {
    pub block_id: SourceBlockId,
    pub k: u32,
    pub t: u16,
    pub block_type: SourceBlockType,
    pub status: SourceBlockStatus,
    pub created_at: Timestamp,
}

/// Symbol placement from owner's perspective. Key: (SourceBlockId, holder IdentityPub).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SymbolPlacement {
    pub source_block_id: SourceBlockId,
    pub holder_id: IdentityPub,
    /// File that owns this source block (for O(1) index updates).
    pub file_id: FileId,
    /// Ranges of ESIs assigned to this holder: (start_esi, count).
    pub esi_ranges: Vec<(u32, u32)>,
    /// Seed for per-holder binding: HKDF(source_block_id, holder_id).
    pub binding_seed: [u8; 32],
    pub status: PlacementStatus,
    pub last_verified: Option<Timestamp>,
    pub placed_at: Timestamp,
}

impl SymbolPlacement {
    /// Total number of symbols at this holder.
    pub fn symbol_count(&self) -> u32 {
        self.esi_ranges.iter().map(|(_, count)| count).sum()
    }
}

/// Status of symbols from the owner's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PlacementStatus {
    /// symbol_offer sent, waiting for response.
    Offered,
    /// Holder accepted, transfer in progress.
    Accepted,
    /// Symbols stored and confirmed.
    Alive,
    /// Holder dropped symbols or failed PoS.
    Lost,
    /// Delete in progress.
    Deleting,
}

/// Peer info. Key: IdentityPub.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerRecord {
    pub identity: IdentityPub,
    pub node_id: Option<NodeId>,
    /// P component: rolling 4-week PoS success rate [0.0, 1.0].
    pub trust_p: f64,
    /// I component: cumulative mean PoS success rate [0.0, 1.0].
    pub trust_i: f64,
    /// S component: pairwise storage ratio (raw, not clamped).
    pub trust_s: f64,
    /// Total bytes we store for this peer.
    pub bytes_we_store_for_peer: u64,
    /// Total bytes this peer stores for us.
    pub bytes_peer_stores_for_us: u64,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    /// Calendar weeks since first_seen.
    pub weeks_in_network: u32,
    /// Which device manages this peer relationship (peer-to-device affinity).
    pub device_id: Option<DeviceId>,
}

/// Symbols we hold for another owner. Key: (SourceBlockId, owner IdentityPub).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HoldingRecord {
    pub source_block_id: SourceBlockId,
    pub owner_id: IdentityPub,
    pub esi_ranges: Vec<(u32, u32)>,
    pub importance: f64,
    pub total_bytes: u64,
    pub status: HoldingStatus,
    pub received_at: Timestamp,
    pub delete_requested_at: Option<Timestamp>,
    pub drop_notice_sent_at: Option<Timestamp>,
}

impl HoldingRecord {
    pub fn symbol_count(&self) -> u32 {
        self.esi_ranges.iter().map(|(_, count)| count).sum()
    }
}

/// Lifecycle state of held symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HoldingStatus {
    /// Stored, PoS challenges expected.
    Active,
    /// Owner sent delete. Cooling down.
    MarkedForDelete,
    /// No PoS challenges, owner silent. Priority by owner trust.
    Silent,
}

/// Budget estimation record. Singleton.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BudgetRecord {
    pub estimated_gb: f64,
    pub last_calculated: Timestamp,
    pub placement_success_rate: f64,
    pub weekly_stats: Vec<(u32, u32)>,
}

// ============================================================
// RAM hot aggregates
// ============================================================

/// Per-source-block aggregate (RAM layer).
#[derive(Debug, Clone, Copy)]
pub struct BlockAgg {
    pub k: u32,
    pub total_alive_symbols: u32,
}

/// Per-(source_block, holder) aggregate (RAM layer).
#[derive(Debug, Clone, Copy)]
pub struct PlacementAgg {
    pub symbol_count: u32,
    pub status: PlacementStatus,
    pub last_pos: Option<Timestamp>,
}

// ============================================================
// Event log
// ============================================================

/// Events for cluster sync (append-only, commutative).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Event {
    SymbolsPlaced {
        source_block_id: SourceBlockId,
        holder_id: IdentityPub,
        esi_range: (u32, u32),
    },
    SymbolsLost {
        source_block_id: SourceBlockId,
        holder_id: IdentityPub,
    },
    SymbolsVerified {
        source_block_id: SourceBlockId,
        holder_id: IdentityPub,
    },
    FileAdded {
        file_id: FileId,
        path: String,
    },
    FileModified {
        file_id: FileId,
        content_hash: [u8; 32],
    },
    FileDeleted {
        file_id: FileId,
        device_id: DeviceId,
    },
    DeviceAdded {
        device_id: DeviceId,
    },
    DeviceRevoked {
        device_id: DeviceId,
    },
    EpochRotated {
        epoch: u32,
    },
}

/// One entry in the append-only event log.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EventEntry {
    pub timestamp: Timestamp,
    pub device_id: DeviceId,
    pub event: Event,
}

// ============================================================
// CBOR serialization helpers
// ============================================================

pub fn to_cbor_bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).expect("cbor serialization failed");
    buf
}

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
