use crate::constants::{
    DECODE_OVERHEAD, OVERHEAD_BASE, OVERHEAD_SCALE, SECS_PER_DAY, SECS_PER_WEEK, SYMBOL_SIZE,
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
    #[error("source block too large: {0} bytes (k would overflow u32)")]
    TooLarge(u64),
}

impl ErasureParams {
    /// Compute erasure parameters for a given source block size and importance.
    ///
    /// Returns `Err(EmptySourceBlock)` if `source_block_size == 0` — an empty
    /// block cannot be erasure-coded (k=0 is invalid for RaptorQ).
    ///
    /// Returns `Err(TooLarge)` if the resulting k would exceed `u32::MAX` — the
    /// silent `as u32` truncation would produce a wrong k value (review L-1).
    pub fn compute(source_block_size: u64, importance: f64) -> Result<Self, ErasureParamsError> {
        if source_block_size == 0 {
            return Err(ErasureParamsError::EmptySourceBlock);
        }
        let t = SYMBOL_SIZE;
        let k_raw = (source_block_size as f64 / t as f64).ceil() as u64;
        // Reserve headroom for DECODE_OVERHEAD and the overhead multiplier so
        // k_eff and n do not silently overflow. Cap at u32::MAX / 4 to keep the
        // margin generous even with importance=1.0 (overhead = 3x).
        let k_limit = (u32::MAX / 4) as u64;
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
    // B-4: worker cooldown (last_attempted_at / last_pool_signature) moved to the
    // RAM-only HotCache::block_cooldown — never persisted, resets on restart.
    // Old records may still carry these CBOR map keys; serde ignores them.
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

    /// "healthy" if mean_p_recoverable >= target_p, "degraded" if below,
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

/// 4R pair-ledger accumulators for ONE economic pair: this node and one **master
/// identity**. Key: [`IdentityPub`], in its own redb table — NOT a field of
/// [`PeerRecord`].
///
/// **This is a recorder, not an input.** No decision in the daemon reads these fields:
/// placement, eviction, offer admission and PoS cadence all still run on the legacy
/// `trust` axes. That is *not* enforced structurally — [`crate::db::Db`] is reachable
/// from every module and `get_pair_ledger` is an ordinary `pub` method. The honest
/// guarantee is weaker: **there is no call site that reads it.** The ledger exists so
/// that when the 4R decision kernel ([`crate::four_r`]) is wired into the daemon, it
/// starts on *warm history* instead of zeros.
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
/// Field names mirror [`crate::four_r::FirstHandObs`] so the bridge (У-5) is a
/// rename-free map; `depth` is the one field the kernel takes *beside* `FirstHandObs`
/// (see below).
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
/// by `block_id ‖ owner_id(master)`. So a ledger field on `PeerRecord` would give a master
/// with N devices N rows of one person's economic history, each carrying the full
/// master-wide total — `g_holder_from_owner` inflated ×N.
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
/// `g_holder_from_owner` ×N.
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
/// | `g_owner_from_holder`, `g_holder_from_owner`, `depth` | **gb·days** |
/// | `v_dem`, `observed_volume` | **gb** |
/// | `observed_tau` | **days** |
/// | `drop_ann`, `drop_silent` | dimensionless (decaying event counts) |
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
    /// `G(O←h)` **[gb·days]**: this master's service TO US — leaky integral of
    /// PoS-confirmed gb·days it stored for us. Accrued from `bytes_peer_stores_for_us`
    /// (summed over the master's devices) via [`crate::four_r::update_capital`].
    pub g_owner_from_holder: f64,
    /// `G(h←O)` **[gb·days]**: OUR service to this master — leaky integral of gb·days we
    /// stored for them. Accrued from the per-master `bytes_we_store_for_peer`.
    pub g_holder_from_owner: f64,
    /// `D` **[gb·days]**: the SLOW-leaky loyalty depth of the pair
    /// ([`crate::four_r::update_depth`], `τ_slow ≈ 6 months`) — the second time-integral
    /// of the same confirmed-service flow that charges `g_holder_from_owner`.
    ///
    /// It is not part of [`crate::four_r::FirstHandObs`] because the kernel takes it as a
    /// separate parameter: [`crate::four_r::OwnerEvictionView`] is `{ obs, depth, symbols }`
    /// and the single holder-side reciprocity key is
    /// `kappa_key(g_holder_from_owner, depth, &DepthParams)`. Without a recorded `D` the
    /// eviction axis κ_O would start from zero on the day 4R is wired in — and since `D`
    /// is an integral over months, it is exactly the quantity that cannot be
    /// back-computed. Same reason as `g`, one time-constant slower.
    pub depth: f64,
    /// `V_dem` **[gb]**: max proven retained volume for this pair. A slow ratchet — snaps
    /// up to freshly confirmed volume, eases down only through `λ_dem`
    /// ([`crate::four_r::update_v_dem`]).
    pub v_dem: f64,
    /// `V0` **[gb]**: the observed volume point for this pair — the one `(V, τ)` slice we
    /// ever sampled it at ([`crate::four_r::estimate_surface`]).
    pub observed_volume: f64,
    /// `τ0` **[days]**: observed retention duration at `V0`.
    pub observed_tau: f64,
    /// Decaying count of ANNOUNCED drops of our data by this pair (a signed
    /// `SymbolDropNotice` arrived). Fades with `λ_drop` — "the system must forgive".
    pub drop_ann: f64,
    /// Decaying count of SILENT drops — we detected the loss ourselves, no notice.
    pub drop_silent: f64,
    /// Wall clock of the last accrual (unix seconds). Single clock for the `G`/`D`
    /// integrators and the drop decay: every accrual integrates over `now - last_update`,
    /// so the contribution is set by elapsed time and not by how many times the tick
    /// happened to fire. A daemon that slept a week accrues a week on its next tick, not
    /// one tick's worth; a second tick at the same `now` accrues nothing (AC-2′).
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
    /// `time_scale = 1000` an hourly tick already returns `≈ 42`. Feeding such a `Δt`
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

#[cfg(test)]
mod tests;
