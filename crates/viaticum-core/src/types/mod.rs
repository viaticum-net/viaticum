use crate::constants::{
    DECODE_OVERHEAD, OVERHEAD_BASE, OVERHEAD_SCALE, RAPTORQ_MAX_SOURCE_SYMBOLS, SECS_PER_DAY,
    SECS_PER_WEEK, SYMBOL_SIZE,
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

/// Device identity = Ed25519 public key of the device signing key. 32 bytes.
/// DeviceId.0 IS the public key — no separate device_pub_key field needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DeviceId(pub [u8; 32]);

/// Monotonically-increasing file identifier. u64, assigned on first index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FileId(pub u64);

// --- Display ---

impl std::fmt::Display for SourceBlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex_encode(&self.0[..8]))
    }
}

impl std::fmt::Display for IdentityPub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex_encode(&self.0[..8]))
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex_encode(&self.0[..8]))
    }
}

impl std::fmt::Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Encode bytes as lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
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
            .unwrap_or_default()
            .as_secs();
        Timestamp(secs)
    }

    pub fn add_secs(self, secs: u64) -> Self {
        // CS-DEL-8: saturating add (defense-in-depth). Operands are wall-clock plus
        // bounded cooldowns/TTLs, so overflow is not realistic and not attacker-
        // controlled, but a saturating add cannot silently wrap past u64::MAX.
        Timestamp(self.0.saturating_add(secs))
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

/// Errors returned by [`ErasureParams::compute`].
#[derive(Debug, thiserror::Error)]
pub enum ErasureParamsError {
    #[error("source block is empty")]
    EmptySourceBlock,
    #[error("source block too large: {0} bytes (k would exceed the RaptorQ single-block limit)")]
    TooLarge(u64),
}

impl ErasureParams {
    /// Compute erasure parameters for a given source block size and importance.
    ///
    /// Returns `Err(EmptySourceBlock)` if `source_block_size == 0` — an empty
    /// block cannot be erasure-coded (k=0 is invalid for RaptorQ).
    ///
    /// Returns `Err(TooLarge)` if the resulting k would exceed
    /// `RAPTORQ_MAX_SOURCE_SYMBOLS` — the raptorq crate panics above it.
    pub fn compute(source_block_size: u64, importance: f64) -> Result<Self, ErasureParamsError> {
        if source_block_size == 0 {
            return Err(ErasureParamsError::EmptySourceBlock);
        }
        let t = SYMBOL_SIZE;
        let k_raw = (source_block_size as f64 / t as f64).ceil() as u64;
        // The raptorq crate panics on K above RAPTORQ_MAX_SOURCE_SYMBOLS (one source
        // block); refuse it here as an error (backup-i5). This also keeps k_eff and n
        // far from u32 overflow.
        let k_limit = RAPTORQ_MAX_SOURCE_SYMBOLS as u64;
        if k_raw > k_limit {
            return Err(ErasureParamsError::TooLarge(source_block_size));
        }
        let k = k_raw as u32;
        let k_eff = k + DECODE_OVERHEAD;
        let overhead = OVERHEAD_BASE + importance.clamp(0.0, 1.0) * OVERHEAD_SCALE;
        let n = (k_eff as f64 * overhead).ceil() as u32;
        Ok(ErasureParams {
            k,
            k_eff,
            t,
            overhead,
            n,
        })
    }

    /// Max symbols any single holder should store.
    /// min(K_eff - 1, concentration_cap * N).
    pub fn max_per_holder(&self) -> u32 {
        let cap_fraction = (1.0 - 1.0 / self.overhead) * crate::constants::CONCENTRATION_CAP_FACTOR;
        let cap = (cap_fraction * self.n as f64).floor() as u32;
        cap.min(self.k_eff.saturating_sub(1))
    }
}

// ============================================================
// File types
// ============================================================

/// Category for packing queue assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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
    /// This device saw the file at this path (an event or a scan found it on disk).
    /// Cleared by DR (`prepare_restored_state`) and by a watch root change. A record
    /// without the field decodes as unconfirmed: the safe side, since only a confirmed
    /// record may be marked deleted by a recheck (dr-i64).
    #[serde(default)]
    pub on_disk_confirmed: bool,
}

/// One version of a file. A backed-up version is never rewritten. The pending one
/// (`backed_up_at == None`, sentinel block; at most one per record, and it is the last)
/// is completed in place when its batch is packed — with the hash of the bytes actually
/// packed — or dropped when a newer event for the path supersedes it (backup-i9, i23).
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
    /// Exact byte length of the stored blob ([nonce][ciphertext]).
    /// Required for restore: decoded erasure block is padded to k*t; trim to encrypted_size.
    /// None for records created before this field was added (legacy).
    #[serde(default)]
    pub encrypted_size: Option<u64>,
    /// Total repair symbols distributed (N = ceil(k_eff * overhead)).
    /// None for records created before this field was added (legacy).
    #[serde(default)]
    pub n: Option<u32>,
    /// Overhead multiplier used at encode time (1.5 + importance * 1.5).
    /// None for records created before this field was added (legacy).
    #[serde(default)]
    pub overhead: Option<f64>,
    /// DEAD since H3 (2026-06-10): was a per-block dedup gate that wrongly skipped
    /// holders 2..n of a multi-holder block. Deletion dedup is now per-(block,holder)
    /// via the engine's `status != Deleting` filter; this field is no longer written
    /// or read. Kept for serde compatibility (drop at the next wire-format break).
    #[serde(default)]
    pub drop_notice_sent_at: Option<Timestamp>,

    // --- Wave 8: cached reliability fields ---
    /// File importance in [0.0, 1.0]. Derived from overhead at migration; set directly at
    /// block creation (Wave 9+). Legacy records get this from the inverse overhead formula or
    /// DEFAULT_IMPORTANCE if overhead is absent.
    /// Default: 0.0 (pre-migration sentinel; replaced by migration before workers start).
    #[serde(default)]
    pub importance: f64,

    /// Count of SymbolPlacement rows with status Alive or Uncertain for this block.
    /// Updated by migration at startup; updated by Wave 11 on state transitions.
    /// Default: 0.
    #[serde(default)]
    pub current_alive: u32,

    /// P(block recoverable) in [0.0, 1.0]. Cached from reliability::block_reliability.
    /// Updated by migration at startup; updated by Wave 11 on state transitions.
    /// Default: 0.0.
    #[serde(default)]
    pub current_reliability: f64,

    /// P target from reliability::target_reliability(importance). Fixed at creation/migration.
    /// Default: 0.0 (pre-migration sentinel).
    #[serde(default)]
    pub target_reliability: f64,

    /// N1 (backup-i8, delete-i9): generation of this block's seal (not the SS ledger's
    /// `generation`). 0 for every block sealed before L1b and whenever the id at generation
    /// 0 is free or in service; content backed up again while the block of the same
    /// plaintext is being released takes the next generation, so its id differs from the
    /// one an old Delete addresses. Enters the nonce derivation
    /// (`backup::pipeline::seal_compressed`); rides SystemState with the record. Not
    /// serialized when 0, so records and SS plaintexts of generation 0 stay byte-identical
    /// (INV-G0).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub seal_generation: u32,
    /// repair-i8: monotonic ESI cursor of this block — the end of the highest range ever
    /// offered for it. Never decreases (`Db::upsert_source_block` keeps the larger value);
    /// written in the transaction that writes the `Offered` rows; rides SystemState with the
    /// record. 0 for records written before this field (and not serialized when 0, so such
    /// records stay byte-identical, as INV-G0 for `seal_generation`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub esi_high_water: u32,
    // B-4: worker cooldown (last_attempted_at / last_pool_signature) moved to the
    // RAM-only HotCache::block_cooldown — never persisted, resets on restart.
    // Old records may still carry these CBOR map keys; serde ignores them.
}

/// `skip_serializing_if` for [`SourceBlockRecord::seal_generation`] (INV-G0) and
/// [`SourceBlockRecord::esi_high_water`].
fn is_zero(v: &u32) -> bool {
    *v == 0
}

impl SourceBlockRecord {
    /// Return the ErasureParams for this block.
    ///
    /// If both `n` and `overhead` are stored, uses them directly.
    /// Otherwise falls back to `ErasureParams::compute(k * t, 0.0)` for legacy records
    /// (importance=0.0 gives the most conservative overhead=1.5).
    pub fn erasure_params(&self) -> ErasureParams {
        match (self.n, self.overhead) {
            (Some(n), Some(overhead)) => {
                let k_eff = self.k + DECODE_OVERHEAD;
                ErasureParams {
                    k: self.k,
                    k_eff,
                    t: self.t,
                    overhead,
                    n,
                }
            }
            // Legacy record: k and t were validated when the block was created, so
            // k*t > 0 is guaranteed (k=0 was the bug we're fixing going forward).
            _ => ErasureParams::compute(self.k as u64 * self.t as u64, 0.0)
                .expect("legacy SourceBlockRecord has valid k>0 and t>0"),
        }
    }
}

/// Aggregate reliability metrics for one named importance bucket.
/// Used in StatusData.by_importance (5 entries, one per bucket, critical → trivial).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ImportanceBucketStats {
    /// Bucket name: "critical" | "high" | "medium" | "low" | "trivial".
    pub bucket: String,

    /// Number of Active SourceBlockRecords with importance in this bucket's range.
    pub block_count: u32,

    /// Arithmetic mean of current_reliability across blocks in this bucket.
    /// 0.0 if block_count == 0.
    pub mean_p_recoverable: f64,

    /// Representative target reliability: target_reliability(bucket_midpoint).
    /// Constant per bucket; computed at call time, not hardcoded.
    pub target_p: f64,

    /// "healthy" if `reliability::meets_target(mean_p_recoverable, target_p)`, "degraded" if below,
    /// "empty" if block_count == 0.
    pub status: String,
}

/// Symbol placement from owner's perspective. Key: (SourceBlockId, holder DeviceId).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SymbolPlacement {
    pub source_block_id: SourceBlockId,
    /// Device that holds these symbols.
    pub holder_id: DeviceId,
    /// File that owns this source block (for O(1) index updates).
    pub file_id: FileId,
    /// Ranges of ESIs assigned to this holder: (start_esi, count).
    pub esi_ranges: Vec<(u32, u32)>,
    /// Seed for per-holder binding: HKDF(source_block_id, holder_id).
    pub binding_seed: [u8; 32],
    pub status: PlacementStatus,
    pub last_verified: Option<Timestamp>,
    pub placed_at: Timestamp,
    /// Consecutive PoS timeout misses. Reset to 0 on Pass. Not incremented on Fail/NotHeld
    /// (those are immediate: status → Lost without graduation).
    #[serde(default)]
    pub consecutive_misses: u32,
}

impl SymbolPlacement {
    /// Total number of symbols at this holder.
    pub fn symbol_count(&self) -> u32 {
        self.esi_ranges.iter().map(|(_, count)| count).sum()
    }

    /// Whether this placement counts as CONFIRMED service at `now` for the 4R pair ledger
    /// (У-3, decisions Д-F/Д-G): status `Alive` AND a PoS pass no older than
    /// `window_scaled_secs` on the SCALED clock — the same clock
    /// [`PairLedger::elapsed_days`] uses (`age_real × time_scale`, `0` treated as `1`).
    ///
    /// `last_verified` is written only on `Pass` (`daemon/scheduler`), so a placement that
    /// became `Alive` on `SymbolStored` and was never proven does not count. This is the one
    /// definition of "confirmed" in the tree: the ledger sweep
    /// ([`crate::db::Db::storage_bytes_by_master`]) calls it and nothing re-implements it.
    ///
    /// A pass stamped after `now` (backward wall-clock jump) has age 0 and counts; the
    /// recorder integrates nothing on such a tick anyway (its interval is 0). An absurd
    /// `time_scale` saturates the age instead of wrapping it, so it reads as "too old".
    pub fn confirmed_at(&self, now: Timestamp, time_scale: u64, window_scaled_secs: u64) -> bool {
        if self.status != PlacementStatus::Alive {
            return false;
        }
        let Some(passed_at) = self.last_verified else {
            return false;
        };
        let age_scaled = now
            .0
            .saturating_sub(passed_at.0)
            .saturating_mul(time_scale.max(1));
        age_scaled <= window_scaled_secs
    }
}

/// Status of symbols from the owner's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PlacementStatus {
    /// symbol_offer sent, waiting for response.
    Offered,
    /// Holder accepted, transfer in progress.
    Accepted,
    /// Symbols stored and confirmed. PoS challenges active.
    Alive,
    /// Holder missed 1-2 consecutive PoS challenges (timeout). Not yet confirmed lost.
    Uncertain,
    /// Holder missed 3+ consecutive PoS challenges. Repair will be triggered.
    PresumedLost,
    /// Holder dropped symbols or explicitly failed PoS. Repair triggered.
    Lost,
    /// Delete in progress.
    Deleting,
}

impl PlacementStatus {
    /// The owner believes the holder may still have these symbols, and only a PoS
    /// verdict may change that belief (Pass → Alive, Fail/NotHeld → Lost).
    /// The worker must not offer this block to such a holder again, and must not
    /// overwrite its placement record (repair-i2).
    pub fn may_hold_symbols(self) -> bool {
        matches!(
            self,
            PlacementStatus::Alive | PlacementStatus::Uncertain | PlacementStatus::PresumedLost
        )
    }
}

/// Kind of a pair-ledger drop event (У-4, Д-I). One event = one placement of ours at one
/// device of the pair's master leaving the held set {Alive, Uncertain} for the first time in
/// its episode, on evidence STRICTLY younger than the episode (`evidence_at > placed_at`).
///
/// Two boundaries, not to be confused (review of intent N-4):
///
/// 1. The episode's TIME boundary is always `placed_at`: only a repair re-placement or
///    `Offered → Alive` moves it; a `Pass` out of `PresumedLost` does NOT
///    (`pos::apply_pos_outcome` leaves `placed_at` alone).
/// 2. "Already counted" is the STATUS: after a `Pass` out of `PresumedLost` the placement is
///    `Alive` again, so a later loss on evidence younger than `placed_at` is a new event —
///    while the time check still compares with the same `placed_at`.
///
/// The first kind recognised wins: `PresumedLost → Lost` (by a notice or a `Fail`) is not a
/// second event. Known over/under-counts (v1 costs, named in the spec): a holder clock
/// running ahead + the stale-notice loop over-counts `Announced` (4r-i32); one holder master
/// with two devices holding the block may count `Announced` + `Presumed` for one loss
/// (4r-i35); evidence stamped in the same second as `placed_at` is not counted (under-count,
/// the price of the strict comparison, 4r-i29).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DropKind {
    /// A signed `SymbolDropNotice` moved the placement to `Lost`.
    Announced,
    /// Our own PoS proved the loss — wrong hash (`Fail`) or an explicit `NotHeld` — to
    /// `Lost`. In v1 only `Fail` reaches it: `NotHeld` is not delivered over the mailbox.
    Silent,
    /// Our own PoS inferred the loss from silence — the timeout that reached `PresumedLost`.
    Presumed,
}

/// Drop events recorded for ONE master since the ledger tick last folded them (У-4, Д-K).
///
/// An outbox between the event sites and the recorder: NOT a ledger field, NOT in the
/// SystemState snapshot (lost on DR, 4r-i31). Lenient decode on purpose — every field
/// defaulted: it is never accrued upon, only taken, so a foreign or damaged row costs at most
/// the pending counts, while a strict decode would fail the whole accrual tick (an error
/// every hour, the ledger frozen). The AC-6″ hazard of [`PairLedger`] (a zero row accrued
/// upon) does not apply here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingDrops {
    #[serde(default)]
    pub announced: u32,
    #[serde(default)]
    pub silent: u32,
    #[serde(default)]
    pub presumed: u32,
}

impl PendingDrops {
    /// Saturating `+1` on the counter of `kind`.
    pub fn add(&mut self, kind: DropKind) {
        let counter = match kind {
            DropKind::Announced => &mut self.announced,
            DropKind::Silent => &mut self.silent,
            DropKind::Presumed => &mut self.presumed,
        };
        *counter = counter.saturating_add(1);
    }

    /// No event of any kind is pending.
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// Sum of all three counters (in `u64`, so three saturated counters cannot overflow).
    pub fn total(&self) -> u64 {
        self.announced as u64 + self.silent as u64 + self.presumed as u64
    }
}

/// Which kind of signed letter a row of `seen_signed_letters` remembers (DN-1). Extensible: line
/// B may add `Delete` / `Revocation` without changing the API. Encoded by serde as the variant
/// NAME (a CBOR text string), so adding variants never breaks decoding of existing rows —
/// renaming a variant would, and `types::tests` pins the encoding of the existing ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SignedLetterClass {
    /// A holder's `SymbolDropNoticeMsg` applied by the owner (4r-i47).
    DropNotice,
}

/// A signed letter this node has already applied (DN-1). Key: the letter's 64-byte signature
/// (table `seen_signed_letters`) — looked up only AFTER the letter passed `verify_strict`
/// against its signer. The key is canonical because ed25519-dalek 2.x (without
/// `legacy_compatibility`) rejects a non-canonical S already in `verify`; `verify_strict` adds
/// the rejection of small-order R / public keys.
///
/// The mechanism is a filter of byte-identical repeats of a signed payload: a mailbox
/// re-delivery of the same letter carries the same payload and (ed25519 being deterministic)
/// the same signature, while a NEW letter — e.g. the same holder dropping the same block again,
/// with a new `timestamp` — has a new signature and is applied (4r-i47, 4r-i48). This matches
/// the mailbox model (mailbox-i26): the envelope does not authenticate `msg_id` or times, the
/// payload signature does. Times are deliberately NOT compared for DropNotice: the holder's
/// clock stamps the letter, the owner's clock stamps `placed_at`; a holder clock running behind
/// would make a genuine new drop look old and swallow it.
///
/// Owner-local; deliberately NOT in the SystemState snapshot (4r-i51): after DR the table is
/// empty and a live letter costs at most one extra application before it is remembered again.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SeenSignedLetter {
    pub class: SignedLetterClass,
    /// When this node first applied the letter (its own clock).
    pub first_seen: Timestamp,
    /// The row is forgotten once `now >= forget_after` (expiry index, pruned on insert).
    pub forget_after: Timestamp,
}

/// 4R relay latch of this holder (T5): whether the holder is in the evicting state of the
/// two-gap hysteresis, and since when. Singleton row of the `four_r_state` table.
///
/// В-0: written by the SHADOW pressure tick only (on a change of `evicting`) and read only by
/// the shadow (pressure tick and offer shadow); В-1a makes it authoritative. NOT in the
/// SystemState snapshot — node-local like HOLDINGS: after a holder DR the row is absent
/// (`evicting = false` until the first pressure tick) and the holdings are gone too.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FourRPhaseRecord {
    /// True iff the relay is latched in the evicting state.
    #[serde(default)]
    pub evicting: bool,
    /// Wall clock of the last change of `evicting` (`None` = never changed).
    #[serde(default)]
    pub since: Option<Timestamp>,
}

/// A file the daemon refused to back up because it is larger than this machine's limit
/// (backup-i4). Node-local: keyed by path in `TOO_LARGE_SOURCES`, NOT part of the
/// SystemState snapshot and not carried by DR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TooLargeMark {
    /// Size of the file when last evaluated (`metadata().len()`).
    pub size_bytes: u64,
    /// The limit in force at that evaluation.
    pub limit_bytes: u64,
    /// When the path was first marked (kept across re-evaluations).
    pub first_seen: Timestamp,
    /// When the path was last evaluated as too large.
    pub last_seen: Timestamp,
}

/// 4R pair-ledger accumulators for ONE economic pair: this node and one **master
/// identity**. Key: [`IdentityPub`], in its own redb table — NOT a field of
/// [`PeerRecord`].
///
/// **This is a recorder, not an input.** No decision in the daemon reads these fields:
/// placement, eviction, offer admission and PoS cadence all still run on the legacy
/// `trust` axes. That is *not* enforced structurally — [`crate::db::Db`] is reachable
/// from every module and `get_pair_ledger` is an ordinary `pub` method. The honest
/// guarantee is weaker: **the readers are the recorder itself ([`crate::pair_ledger`],
/// which accrues these values on a scheduler tick), the SystemState snapshot/restore pair
/// that carries them through disaster recovery, and — since В-0 — the 4R SHADOW
/// ([`crate::four_r_holder`], called from the daemon's pressure tick and, off the reply
/// path, after each symbol offer), whose only outputs are log lines and its own latch row
/// ([`FourRPhaseRecord`]) — no decision site.** The ledger exists so that when the 4R
/// decision kernel ([`crate::four_r`]) is wired into the daemon, it starts on *warm
/// history* instead of zeros.
///
/// The reason it cannot wait for that wiring: `G` is a *leaky* integral — a decaying
/// weighted history, not a running total, and nothing recorded today can produce one
/// after the fact. On the owner-side axis the daemon really does keep only a snapshot
/// (`PeerRecord::bytes_peer_stores_for_us` = how much right now). On the holder-side
/// axis it does better than that but still not enough:
/// [`crate::db::Db::stored_for_peer_gb_days`] and
/// [`crate::db::Db::held_contributions_gb_days`] already compute real gb·days per master
/// (`total_bytes / BYTES_PER_GB × age_days`, `time_scale`-aware) — but they sum over the
/// holdings *still active right now*, so a dropped or re-placed holding retroactively
/// erases its own history, and there is no leak term, so nothing is ever forgotten
/// either. `G` and the slow `depth` are neither of those shapes; both have to accrue in
/// calendar time. Spec: `private/beta-planning/tasks/pair_ledger.md`.
///
/// # Field names are ABSOLUTE here, role-relative in the kernel
///
/// The names deliberately do NOT mirror [`crate::four_r::FirstHandObs`] (they did until
/// У-2). The kernel's `g_owner_from_holder` / `g_holder_from_owner` are named relative to
/// the SEAT the caller occupies, so the same name denotes opposite physical flows for an
/// owner-side and a holder-side decision. Two separate passes of this project — sim
/// transaction 3a and slice У-1 — wrote the mapping down inverted, so this struct states
/// the direction in the field name instead and leaves the seat choice to an explicit,
/// visible mapping:
///
/// | this row | physical flow | kernel field, OWNER-side view | kernel field, HOLDER-side view |
/// |---|---|---|---|
/// | `gb_days_they_store_for_us` | their machines keep OUR data | `obs.g_owner_from_holder` | `obs.g_holder_from_owner` (the κ_O input) |
/// | `gb_days_we_store_for_them` | we keep THEIR data | `obs.g_holder_from_owner` | `obs.g_owner_from_holder` |
/// | `depth_of_their_service` | (slow twin of row 1) | — | `OwnerEvictionView::depth` |
/// | `v_dem` | THEIR confirmed service to us (ratchet) | `obs.v_dem` | `obs.v_dem` |
/// | `observed_volume`, `observed_tau` | THEIR confirmed service to us (current run) | `obs.observed_volume` / `obs.observed_tau` | the same |
/// | `drop_ann`, `drop_silent`, `drop_presumed` | THEIR devices dropped OUR data (У-4) | `obs.drop_ann` / `obs.drop_silent` (+ `drop_presumed`, bridge's choice — see the field) | not read (`eviction_order` takes only `g_holder_from_owner` and `observed_tau`) |
///
/// The last two rows do NOT swap with the seat (У-3): in the owner seat `v_dem` reads "how
/// much the holder has proven it keeps of mine", in the holder seat it is `v_dem^{ho}`,
/// "how much O has proven it serves me" (`4r_rebase_quanta.md` §5.1, NOTE-3) — the same
/// physical direction, their service to us. Only the two `g` fields trade places.
///
/// The right-hand column is the one that matters and the one that was got wrong: the
/// eviction key is `kappa_key(obs.g_holder_from_owner, depth, ..)` and the kernel says in
/// as many words that this term is "the eviction seat: the owner `O`'s reciprocal service
/// to ME, the holder" (`four_r/mod.rs:338-340`), plus "this is the direction the old doc
/// comment inverted" (`four_r/mod.rs:697-703`). So a holder-side view is built from
/// `gb_days_they_store_for_us`, and the bridge (У-5) must pick its seat consciously rather
/// than matching names.
///
/// # Why a separate table, not fields on `PeerRecord`
///
/// **ONE structural reason** — stated alone on purpose, because two plausible-sounding
/// companions were checked against the code and did not survive (both recorded below, so
/// the fourth reader does not re-invent them).
///
/// **The input exists only per-master.** [`PeerRecord`] is keyed by [`DeviceId`]; this
/// ledger is keyed by master identity (next section). The holder-side quantity being
/// integrated is computed per-MASTER at the source: [`crate::db::Db::refresh_peer_storage_bytes`]
/// sums HOLDINGS over `owner_id == master_for(device)`, and HOLDINGS themselves are keyed
/// by `owner_id(master) ‖ block_id` (owner first — `db::holding_key`, S-4: one owner's
/// holdings are a contiguous range). So a ledger field on `PeerRecord` would give a master
/// with N devices N rows of one person's economic history, each carrying the full
/// master-wide total — `gb_days_we_store_for_them` inflated ×N.
///
/// Not "physically impossible", to be exact about what was proven: there is **no
/// non-arbitrary per-device decomposition** of that quantity. Summing the N rows gives ×N;
/// dividing by N breaks conservation the moment a device is added or removed
/// (retroactively rescaling months of integral); anointing one device's row as canonical
/// is a made-up rule plus a full PEERS scan on every per-master read.
///
/// **Refuted reason #1 — diff-stream churn.** *"The ledger changes on every accrual tick,
/// so a field on `PeerRecord` would mark every peer dirty every tick and balloon the diff
/// blocks."* The mechanism is real ([`crate::system_state::diff_states`] does compare the
/// CBOR of whole records), but the counterfactual delta is ≈ zero: peer rows are already
/// rewritten hourly WITHOUT any ledger. `MailboxRouter::poll` calls `record_avail_contact`
/// → `upsert_peer` on every successful fetch, the poll interval is 3600 s and the read
/// fanout is 300, so in a circle under 300 peers every reachable peer is written once an
/// hour — six times inside one 6-hour SystemState push window. "One `DiffOp` per peer per
/// push", "non-empty diff every push" and "forced compaction" are today's normal, not
/// something a ledger field would introduce. The residue is only OFFLINE peers, which
/// change once a day from `apply_avail_decay_batch`; a ledger would raise that to ~4×/day
/// on that subset. A minor consideration, not a reason — and the `peers` section is
/// emphatically NOT "state that changes rarely".
///
/// **Refuted reason #2 — sibling overwrite.** *"A sibling's diff would overwrite my
/// first-hand integrals."* It reads well and it is false.
/// [`crate::system_state::apply_diffs`] has exactly one non-test call site — disaster
/// recovery — and it runs against a database file that was just deleted and recreated,
/// with the base and the diffs taken from ONE self-pointer. No live path applies another
/// node's diff on top of a running DB, so excluding the ledger from `DiffOp` closes no
/// channel. What does cross nodes is the *base snapshot*, and the ledger rides it
/// ([`crate::system_state::SystemState::pair_ledgers`]): in a cluster a device can
/// restore from a *sibling's* snapshot and inherit the sibling's ledger, exactly as it
/// already inherits the sibling's `peers` / `files` / `symbol_placements` today. That is
/// a property of the whole SystemState (open in tech-debt), not something this table
/// either causes or fixes.
///
/// # Why keyed by master identity, not `DeviceId`
///
/// The economic pair is a **person**, not a machine.
/// [`crate::db::Db::refresh_peer_storage_bytes`] already computes
/// `bytes_we_store_for_peer` per-MASTER ("escrow is economic between humans, not
/// devices") while `bytes_peer_stores_for_us` is per-device. Keyed by `DeviceId`, each
/// of a master's N device rows would accrue the full master-wide total — inflating
/// `gb_days_we_store_for_them` ×N.
///
/// The placeholder identity `IdentityPub([0; 32])` is NOT a person and never gets a row:
/// it is what the deprecated `TrustEngine::upsert_peer` and pre-certificate peer rows
/// leave behind (`daemon/dr` repairs such rows on re-authentication, CS-DR-12), so
/// accepting it would fold every unidentified device into one shared "zero person" whose
/// ledger is the sum of unrelated strangers.
///
/// PoS outcomes stay per-device (an observation of a machine, not an economic fact) —
/// though NOT on [`PeerRecord`], which carries no such fields, only the derived
/// `trust_p` / `trust_i`. They live in the `pos_weekly` table, keyed by
/// `DeviceId ‖ week`, as `WeeklyPosEntry { challenged, passed }`; a PoS *timeout* is not
/// persisted anywhere at all. Folding those per-device observations into this per-master
/// row is the bridge's job (У-5), and the missing timeout has to be either an honest
/// zero or derived from placement `Alive → Uncertain → PresumedLost` transitions.
///
/// # Units — fixed here, and not renegotiable later
///
/// | field | unit |
/// |---|---|
/// | `gb_days_they_store_for_us`, `gb_days_we_store_for_them`, `depth_of_their_service` | **gb·days** |
/// | `v_dem`, `observed_volume` | **gb** |
/// | `observed_tau` | **days** |
/// | `drop_ann`, `drop_silent`, `drop_presumed` | dimensionless (decaying event counts, `+1` per placement) |
/// | `last_update` | wall-clock [`Timestamp`] (unix **seconds**) |
///
/// "gb" means `bytes as f64 / constants::BYTES_PER_GB` (2^30) — a CONVENTION chosen
/// here, not a fact about the kernel. [`crate::four_r`] never converts bytes at all: it
/// labels quantities "gb" and states its calibrations (`v_free`, `d_ref`, `c_recip`) in
/// the same label. What actually matters is SELF-consistency — `V_conf`, `v_dem`,
/// `v_free` and `D_ref` must all mean the same gigabyte. Picking 10^9 instead of 2^30
/// would rescale every gb-valued quantity by the same ≈7%, harmless as long as nothing
/// mixes the two, and corrupting as soon as something does. The daemon's own storage
/// counters are raw **bytes**; convert at the write boundary and never park bytes in
/// these fields — months of series recorded in the wrong unit cannot be repaired after
/// the fact, which is the whole reason the recorder is landing early.
///
/// `last_update` is the only seconds-valued member, and every kernel entry point takes
/// DAYS (`update_capital(.., dt)`, `update_v_dem(.., dt_days, ..)`,
/// `update_depth(.., dt_days, ..)`, `λ ≈ 1/60 day⁻¹`). Convert with
/// [`PairLedger::elapsed_days`]; handing a seconds delta to the kernel is an 86400×
/// error that looks like a working integrator.
///
/// # Adding a field later — read this first
///
/// Every NEW field added to this struct MUST carry `#[serde(default)]`. The fields
/// present today deliberately do not: with the same 32-byte key type as `PEERS`, a
/// blanket default would let any unrelated CBOR map decode into a plausible all-zero
/// ledger that an integrator would then keep accruing on top of. Decoding is therefore
/// strict, and a new field without a default makes every row written before it
/// unreadable. The blast radius is not "one stale row":
/// [`crate::db::Db::list_pair_ledgers`] returns `Err` on the first old row →
/// `system_state::snapshot_db` fails → the daemon's periodic SystemState push logs an
/// error and skips the tick, so publication stops with nothing but a log line; and every
/// base blob already published stops decoding, so disaster recovery cannot restore at
/// all. `#[serde(default)]` on the new field is the entire fix; both halves are pinned by
/// `types::tests::pair_ledger_with_a_new_defaulted_field_still_reads_rows_written_today`
/// and its `..._required_field_cannot_read_...` twin.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PairLedger {
    /// **[gb·days]** — leaky integral of the data THIS MASTER'S DEVICES KEEP FOR US.
    ///
    /// Charged from the daemon's own owner-side bookkeeping: `symbol_count × t` summed
    /// over the CONFIRMED placements (below) at any device of this master, integrated by
    /// [`crate::four_r::update_capital`] at `λ`.
    ///
    /// The number comes from the SWEEP [`crate::db::Db::storage_bytes_by_master`]
    /// (`MasterStorageBytes::they_store_for_us_confirmed`), which is the only production
    /// path (Д-C: one pass per table for all masters, because the tick runs inside the
    /// scheduler's `select!`). [`crate::db::Db::bytes_master_stores_for_us`] computes the
    /// BELIEVED formula (every `Alive` placement) for ONE master and has no production call
    /// site at all — it is the point-query reference the sweep's believed column is
    /// cross-checked against
    /// (`pair_ledger::tests::the_sweep_and_the_point_queries_report_the_same_volumes`). The
    /// confirmed column deliberately has no point-query twin: its definition lives in
    /// [`SymbolPlacement::confirmed_at`], so there is no second implementation to drift.
    ///
    /// **Charged by CONFIRMED volume only** (У-3, decision Д-F = A): the bytes of `Alive`
    /// placements whose last PoS pass is no older than
    /// [`crate::constants::PAIR_LEDGER_CONFIRMATION_WINDOW_SECS`] on the scaled clock
    /// ([`SymbolPlacement::confirmed_at`]). An `Alive` placement that was never proven —
    /// the hours between `SymbolStored` and the first pass, a holder that accepted and never
    /// answered, SystemState blocks (not challenged at all, Bug-B) — charges nothing.
    ///
    /// What remains of invented service: a holder that dies keeps counting as confirmed
    /// until its last pass ages out of the window — at most 14 d 3 h after that pass, ≈10.6 d
    /// on average for a death uniform inside the weekly PoS cycle (≈18 % of `τ = 60 days`).
    /// It is bounded by the window, not by the PoS state machine: `Alive → Uncertain` needs
    /// the next challenge to be issued and to time out, which is later.
    pub gb_days_they_store_for_us: f64,
    /// **[gb·days]** — leaky integral of the data WE KEEP FOR THIS MASTER.
    ///
    /// Charged from `total_bytes` summed over `Active` holdings owned by this master — the
    /// same number [`crate::db::Db::refresh_peer_storage_bytes`] writes into
    /// `PeerRecord::bytes_we_store_for_peer`, and already per-master at the source.
    ///
    /// Same as the axis above: the live path is the sweep
    /// [`crate::db::Db::storage_bytes_by_master`], while
    /// [`crate::db::Db::bytes_we_store_for_master`] is the per-master reference kept for
    /// point lookups and for the cross-check that keeps the two from drifting.
    pub gb_days_we_store_for_them: f64,
    /// `D` **[gb·days]**: the SLOW-leaky loyalty depth of the pair
    /// ([`crate::four_r::update_depth`], `τ_slow ≈ 6 months`) — the second time-integral
    /// of the SAME flow that charges [`PairLedger::gb_days_they_store_for_us`], on a
    /// time-constant one order slower.
    ///
    /// The invariant, stated without roles so it cannot invert again: **the depth is
    /// charged by exactly the flow whose accrual reads "this counterparty served me", and
    /// the eviction key reads exactly the cell that accrual wrote.** In the sim that is
    /// literally one statement — `capital[holder][owner].g_ho` and `.depth_ho` are
    /// incremented together (`sim_dynamic/engine.rs:1884-1886`) and
    /// `observe_eviction_views` reads that same cell back
    /// (`engine.rs:1972-1979`, `observer.rs:149,183`). In the kernel it is spelled out in
    /// prose: κ_O's capital term is "the owner `O`'s reciprocal service to ME, the holder"
    /// (`four_r/mod.rs:338-340`).
    ///
    /// It is not part of [`crate::four_r::FirstHandObs`] because the kernel takes it as a
    /// separate parameter: [`crate::four_r::OwnerEvictionView`] is `{ obs, depth, symbols }`
    /// and the single holder-side reciprocity key is
    /// `kappa_key(obs.g_holder_from_owner, depth, &DepthParams)` — where that observation
    /// field must be fed from THIS row's `gb_days_they_store_for_us` (see the seat table
    /// above). Without a recorded `D` the eviction axis κ_O would start from zero on the
    /// day 4R is wired in — and since `D` is an integral over months, it is exactly the
    /// quantity that cannot be back-computed. Same reason as the capitals, one
    /// time-constant slower.
    pub depth_of_their_service: f64,
    /// `V_dem` **[gb]**: the demonstrated scale of THEIR service to us — max proven
    /// retained volume, a slow ratchet ([`crate::four_r::update_v_dem`], A.3). Snaps up
    /// instantly to the pair's CONFIRMED volume (the same flow as
    /// [`PairLedger::gb_days_they_store_for_us`] — the model's one `V_conf`), and eases down
    /// only through `λ_dem` ([`crate::constants::PAIR_LEDGER_LAMBDA_DEM`], 1/365 day⁻¹,
    /// PROVISIONAL — swept in В-3½). After any accrual `v_dem ≥` that tick's confirmed
    /// volume. A peer that accepted our data and never passed a challenge stays at 0.
    ///
    /// The volume is the pair's FOOTPRINT (all placements of every device of the master,
    /// Р-8), not one symbol's: the simulator ratchets per challenged symbol
    /// (`sim_dynamic/engine.rs:1874`), so this series is NOT comparable bit-for-bit with a
    /// sim run the way `G`/`D` are — the sim has not been re-based on the footprint yet.
    /// Same direction in both seats (see the seat table above).
    pub v_dem: f64,
    /// `V0` **[gb]**: the SMALLEST confirmed volume of the current unbroken run of
    /// confirmed service by this pair to us (Д-H) — the honest point "they kept at least
    /// `V0` for `τ0`". Reset to 0 with [`PairLedger::observed_tau`] when an observed tick
    /// sees nothing confirmed; the next confirmed tick starts a new run at its own volume.
    ///
    /// This is ONE of three readings of `(V0, τ0)` in the project (the sim uses a constant
    /// PoS window `τ0 = 7 d`; the eviction model reads "holding seniority"). It is the one
    /// that cannot be computed after the fact; the sim and the bridge (У-5) may read
    /// `τ0` differently ([`crate::four_r::estimate_surface`] is its only kernel consumer).
    pub observed_volume: f64,
    /// `τ0` **[days]**: OBSERVED days of the current run of confirmed service (Д-H). Grows
    /// by the observed tail of each accrual whose confirmed volume is > 0; a dark stretch
    /// (our own outage, Д-A) neither adds to it nor ends the run by itself — the run ends on
    /// the first observed tail with nothing confirmed, which is what happens after an outage
    /// longer than the confirmation window. See [`PairLedger::observed_volume`].
    pub observed_tau: f64,
    /// Decaying count of ANNOUNCED drops of our data by this pair (У-4): a signed
    /// `SymbolDropNotice` moved one of our placements at one of their devices out of the held
    /// set {Alive, Uncertain} into `Lost` — the first loss of that placement's episode, on a
    /// notice stamped strictly after `placed_at` ([`DropKind`], Д-I). Re-deliveries,
    /// republications with a new deadline and the final `deadline = now` notice find the
    /// placement already `Lost` and add nothing; a notice for a `Deleting` or missing
    /// placement (our own deletion) is not an event at all.
    ///
    /// Unit: `+1` per placement (block × device), not the volume lost. Moment: when WE apply
    /// the notice, not when the symbols died on their disk. Leaks at `λ_drop`
    /// ([`crate::constants::PAIR_LEDGER_LAMBDA_DROP`], 1/56 day⁻¹ — "the system must
    /// forgive") on every sub-step of every interval, the unobserved part included; the
    /// events of a tick are added AFTER that tick's decay (Д-K).
    ///
    /// Not the sim's counter, only its leak rate: the sim counts a symbol's death at T+1,
    /// exempts cap trims (the notice carries no reason, so the daemon counts them) and steps
    /// weekly (×0.875/week) where the daemon steps hourly (×0.8825/week).
    pub drop_ann: f64,
    /// Decaying count of SILENT drops (У-4): our own PoS PROVED a loss — a wrong-hash `Fail`
    /// (or an explicit `NotHeld`) moved a held placement to `Lost`, first in its episode, on
    /// a challenge issued strictly after `placed_at`. In v1 this is only `Fail` (corrupted
    /// bytes): `NotHeld` is not delivered over the mailbox, so a holder that lost or wiped
    /// our data shows up as silence, i.e. in [`PairLedger::drop_presumed`].
    ///
    /// Same unit, moment and leak as [`PairLedger::drop_ann`]. The sim's "silent" is a
    /// holder's departure, one event per pair and episode — a different definition.
    pub drop_silent: f64,
    /// Decaying count of PRESUMED drops of our data by this pair (У-4, Д-J): one of our
    /// placements at one of their devices reached `PresumedLost` — three consecutive PoS
    /// timeouts, the daemon's only visible trace of a holder that vanished (the sim's
    /// silent-loss-by-departure twin). The first timeout (`→ Uncertain`) and every timeout
    /// after `PresumedLost` add nothing.
    ///
    /// Kept apart from [`PairLedger::drop_silent`] (proven loss) because the two cannot be
    /// separated later, while they can always be summed (both leak by the same factor). The
    /// bridge (У-5) decides the mapping: while `pos_timeout` is an honest 0, map
    /// `obs.drop_silent = drop_silent + drop_presumed`; if it ever derives `pos_timeout` from
    /// placement transitions, do NOT add this field (the kernel's `drop_frac` would count the
    /// same timeouts twice). Leaks at `λ_drop` like the other two.
    ///
    /// Added after rows were already written: `#[serde(default)]` is what keeps those rows
    /// (and published SystemState blobs) readable — W-1, see "Adding a field later" above.
    #[serde(default)]
    pub drop_presumed: f64,
    /// Wall clock of the last accrual (unix seconds). Single clock for the `G`/`D`
    /// integrators and the drop decay: every accrual integrates over `now - last_update`,
    /// so the contribution is set by elapsed time and not by how many times the tick
    /// happened to fire. A second tick at the same `now` accrues nothing (AC-2′).
    ///
    /// "Integrates over the whole interval" is not the same as "charges volume over the
    /// whole interval": the DECAY covers every elapsed day, while the measured volume is
    /// only charged over the last [`crate::pair_ledger::observed_window_days`] of it —
    /// three periods of the accrual timer, which is a different number of seconds at every
    /// `time_scale`. A daemon that slept a week comes back to a row decayed by a week and
    /// credited for the few hours it can actually vouch for (Д-A — see
    /// [`crate::pair_ledger`]).
    ///
    /// `None` = the clock has never started (nothing accrued yet). It is a distinct state
    /// from "accrued to zero": a first tick must SEED this field and integrate nothing,
    /// because there is no interval to integrate over.
    pub last_update: Option<Timestamp>,
}

impl PairLedger {
    /// `Δt` in DAYS since the last accrual — the unit every [`crate::four_r`] integrator
    /// expects (`update_capital`, `update_v_dem`, `update_depth`).
    ///
    /// `days = (now − last_update) · time_scale / 86400`. `time_scale` accelerates
    /// simulated time (`1` = real time; local E2E runs use 1000), and the same `.max(1)`
    /// guard as the neighbours treats `0` as `1` — `--time-scale` is an unvalidated CLI
    /// argument. This matches the gb·day sums and the daemon's timers, but NOT every clock
    /// in the tree: `run_avail_decay_task` deliberately ticks on raw `AVAIL_DECAY_TICK_SECS`
    /// without dividing by the scale, so under acceleration availability ages on the real
    /// calendar while this ledger ages on the simulated one. Keep that in mind when
    /// comparing series from an accelerated run. Without the scale an accelerated run would advance
    /// the daemon's timers, PoS cadence and the existing gb·day sums
    /// ([`crate::db::Db::stored_for_peer_gb_days`]) along the simulated calendar while
    /// this ledger crawled along the real one, accruing `1/time_scale` of the history —
    /// and an accelerated run is precisely where "check that the accounting actually
    /// accumulated" gets checked.
    ///
    /// `None` when the clock has never started ([`PairLedger::last_update`] is `None`):
    /// the caller must seed the clock rather than integrate from the unix epoch. A
    /// backward wall-clock jump yields `0.0`, never a negative `Δt` — a negative would
    /// drive the leaky integrator backwards instead of leaving it untouched.
    ///
    /// # The returned Δt is NOT bounded — the integrator must sub-step
    ///
    /// [`crate::four_r::update_capital`] is a single explicit Euler step, multiplier
    /// `(1 − λΔt)`: monotone only while `λΔt < 1`, oscillating between 1 and 2, divergent
    /// above 2. At `λ = 1/60 day⁻¹` those thresholds are 60 and 120 days, and both are
    /// reachable here — a daemon that was off for three months returns `Δt ≈ 90`, and at
    /// `time_scale = 1000` a two-hour outage returns `≈ 83`. (The recorder's
    /// own CADENCE stays far below both at every scale a script in this tree uses: its
    /// timer is divided by `time_scale` too, so an on-schedule tick returns
    /// `max(1, 3600/scale)·scale/86400` days — 1/24 day up to `scale = 3600`, then growing
    /// with the one-second timer floor to ≈1.16 days at `scale = 100_000`. It would take
    /// `scale > 5.184·10⁶` for one on-schedule tick to cross 60 days on its own. So a large
    /// `Δt` means downtime, not acceleration.)
    /// Feeding such a `Δt`
    /// straight in can invert the accrual: the step lands at `g(1 − λΔt) + v_conf·Δt`, so
    /// it goes NEGATIVE once `v_conf < g(λΔt − 1)/Δt` — that is, for a pair that has
    /// largely stopped storing, which is exactly the pair a long outage produces. Even
    /// when it stays positive it is no longer an integral: past `λΔt > 1` the step is
    /// non-monotone and past 2 it diverges.
    ///
    /// This is deliberately NOT clamped here: clamping would silently discard accrual,
    /// which is the exact failure this layer exists to prevent. The fix belongs to the
    /// integrator (У-2) — split a large `Δt` into sub-steps of at most `λΔt ≈ 0.5` and
    /// iterate, so a long outage is *accrued*, not truncated and not inverted.
    pub fn elapsed_days(&self, now: Timestamp, time_scale: u64) -> Option<f64> {
        let last = self.last_update?;
        let secs = now.0.saturating_sub(last.0);
        let scale = time_scale.max(1) as f64;
        Some(secs as f64 * scale / SECS_PER_DAY as f64)
    }
}

/// Peer info. Key: DeviceId.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerRecord {
    /// Primary key: the device this record describes.
    pub device_id: DeviceId,
    /// Master identity this device belongs to. Populated from DeviceCertExchange.
    pub master_identity: IdentityPub,
    /// P component: rolling 4-week PoS success rate [0.0, 1.0].
    pub trust_p: f64,
    /// I component: cumulative mean PoS success rate [0.0, 1.0].
    pub trust_i: f64,
    /// S component: pairwise storage ratio (raw, not clamped).
    pub trust_s: f64,
    /// Total bytes we store for this peer's master identity.
    pub bytes_we_store_for_peer: u64,
    /// Total bytes this specific device stores for us.
    pub bytes_peer_stores_for_us: u64,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    /// Device public keys we know are revoked for this peer's master identity.
    /// Populated when we receive a valid RevocationBroadcast via relay board.
    #[serde(default)]
    pub revoked_device_pub_keys: Vec<[u8; 32]>,
    /// Known addresses in "NodeId_hex@ip:port" format.
    #[serde(default)]
    pub addrs: Vec<String>,
    /// X25519 public key for directed relay board encryption.
    /// Received via PeerAnnounce; None for peers that have not sent it yet.
    #[serde(default)]
    pub x25519_pub: Option<[u8; 32]>,
    /// Rolling EWMA availability score [0.0, 1.0].
    /// Updated on each authenticated contact: avail = α·1.0 + (1-α)·avail
    /// Decayed daily when no contact: avail = α·0.0 + (1-α)·avail
    /// New peers start at AVAIL_EWMA_INITIAL = 0.1 (pessimistic prior).
    /// Rationale: earn-it axis consistent with trust_i (starts at 0.0);
    ///   slows Sybil write-fanout capture via always-online new nodes.
    #[serde(default = "default_avail_ewma")]
    pub avail_ewma: f64,
    /// Unix secs of last positive availability observation (authenticated contact).
    /// Used as the decay clock: decay applies strictly 1 tick when
    ///   now - last_avail_sample >= AVAIL_DECAY_TICK_SECS (no double-decay).
    /// Also advanced to `now` each time decay is applied (startup catch-up).
    /// Separate from `last_seen` to avoid the proxy problem: long-lived TCP
    ///   connections keep `last_seen` fresh without new observations.
    #[serde(default)]
    pub last_avail_sample: u64,
}

fn default_avail_ewma() -> f64 {
    crate::constants::AVAIL_EWMA_INITIAL
}

impl PeerRecord {
    /// Check if a DeviceId is in the revoked list for this peer's master identity.
    pub fn is_device_revoked(&self, device_id: &DeviceId) -> bool {
        self.revoked_device_pub_keys.contains(&device_id.0)
    }
}

/// Apply one positive observation (authenticated contact).
/// avail = α·1.0 + (1-α)·avail
pub fn ewma_contact_observed(avail: f64, alpha: f64) -> f64 {
    alpha + (1.0 - alpha) * avail
}

/// Apply one negative observation (no-contact decay tick).
/// avail = α·0.0 + (1-α)·avail  =  (1-α)·avail
pub fn ewma_decay_tick(avail: f64, alpha: f64) -> f64 {
    (1.0 - alpha) * avail
}

/// Apply N consecutive no-contact decay ticks (batch for missed days).
/// avail = (1-α)^n · avail
pub fn ewma_decay_n_ticks(avail: f64, alpha: f64, n: u32) -> f64 {
    avail * (1.0 - alpha).powi(n as i32)
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
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Event {
    SymbolsPlaced {
        source_block_id: SourceBlockId,
        holder_id: DeviceId,
        esi_range: (u32, u32),
    },
    SymbolsLost {
        source_block_id: SourceBlockId,
        holder_id: DeviceId,
    },
    SymbolsVerified {
        source_block_id: SourceBlockId,
        holder_id: DeviceId,
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
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EventEntry {
    pub timestamp: Timestamp,
    pub device_id: DeviceId,
    pub event: Event,
}

// ============================================================
// ESI range helpers
// ============================================================

/// Convert a sorted list of ESIs to compact `(start, count)` ranges.
///
/// Consecutive ESIs are merged into a single range. The input MUST be sorted
/// in ascending order — this function does not sort.
///
/// Lives in core (review A3) so `processor`, `restore`, `holder_cleanup` and
/// any future module share the same implementation instead of drifting.
pub fn esi_list_to_ranges(esis: &[u32]) -> Vec<(u32, u32)> {
    if esis.is_empty() {
        return Vec::new();
    }
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    let mut start = esis[0];
    let mut count = 1u32;
    for &esi in &esis[1..] {
        if esi == start + count {
            count += 1;
        } else {
            ranges.push((start, count));
            start = esi;
            count = 1;
        }
    }
    ranges.push((start, count));
    ranges
}

/// Expand `(start, count)` ESI ranges back to a flat sorted list of ESIs.
///
/// Uses checked arithmetic for `start + count` (defense-in-depth, same helper
/// family as the SM-1/SM-7 guards): a corrupt or hostile range whose end would
/// overflow `u32` is clamped to `u32::MAX` rather than wrapping and producing
/// an empty/garbage range.
pub fn ranges_to_esi_list(ranges: &[(u32, u32)]) -> Vec<u32> {
    ranges
        .iter()
        .flat_map(|&(start, count)| start..start.saturating_add(count))
        .collect()
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

/// Serde helper for `[u8; 64]` signature fields. Use with `#[serde(with = "sig_serde")]`.
pub mod sig_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        sig.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64-byte signature"))
    }
}

/// Serde helper for optional `[u8; 64]` signature fields. Use with
/// `#[serde(default, with = "crate::types::opt_sig_serde")]`: `None` encodes as CBOR
/// null, `Some` as the 64-byte sequence (same shape as `sig_serde`).
pub mod opt_sig_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(sig: &Option<[u8; 64]>, s: S) -> Result<S::Ok, S::Error> {
        sig.as_ref().map(|b| b.as_slice()).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 64]>, D::Error> {
        let v: Option<Vec<u8>> = Option::deserialize(d)?;
        v.map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("expected 64-byte signature"))
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests;
