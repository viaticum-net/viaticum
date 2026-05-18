// All tunable protocol constants in one place.
// β version — RaptorQ, continuous importance, configurable block size.

// === Time ===

/// Seconds in one week (7 * 24 * 60 * 60).
pub const SECS_PER_WEEK: u64 = 604_800;

// === Trust formula ===
// trust = (KP * P + KI * I) * clamp(S, S_CLAMP_MIN, S_CLAMP_MAX)
// P = 4-week rolling pass rate, I = cumulative mean, S = pairwise GB ratio.

/// Weight on P (4-week rolling window).
pub const KP: f64 = 0.4;

/// Weight on I (cumulative mean).
pub const KI: f64 = 1.75;

/// Rolling window length for P score (weeks).
pub const P_WINDOW_WEEKS: u32 = 4;

/// Initial P value for newly connected peers — neutral Bayesian prior.
/// A new peer has no PoS history yet; we treat them as 50/50 rather than
/// "minimally trusted" so they get a real shot at being chosen as a holder
/// during their first few hours, before their P score becomes evidence-based.
/// Without this they sit at the trust floor (~0.04 combined) and lose every
/// holder selection to peers with even one passed challenge — bootstrap fails.
pub const INITIAL_TRUST_P: f64 = 0.5;

/// S floor — even zero-storage peers get 10% trust multiplier.
pub const S_CLAMP_MIN: f64 = 0.1;

/// S ceiling.
pub const S_CLAMP_MAX: f64 = 1.0;

// === Escrow (contribution-based) ===

/// Days of storage contribution required to earn 1 GB of restore credit.
/// Formula: restore_budget_gb = stored_gb_days / k_factor.
/// Default K=7: store 1 GB for 7 days → earn 1 GB restore budget.
pub const DEFAULT_ESCROW_K_FACTOR: f64 = 7.0;

/// Days of storage contribution required to earn 1 GB of OFFER budget (backup credit).
/// Formula: earned_offer_gb = Σ(gb_days × master_trust / MAX_COMBINED_TRUST) / K_OFFER.
/// Smaller than restore-K (7) on purpose — we want self-awareness for fresh
/// owners (a node holding for the network a few days can back up its first
/// files), and offering cost is already inflated ×overhead_factor by the
/// caller. Set to 5 (tunable). Sybil mitigation logged in tech-debt.
pub const OFFER_EARN_K_FACTOR_DAYS: f64 = 5.0;

// === Budget floor (owner-side) ===

/// Owner-side budget floor: minimum GB offered even with zero committed storage.
/// Used by budget planner (not escrow). Ensures new nodes can start backing up.
pub const FREE_TIER_GB: f64 = 1.0;

// === Cooldown (ransomware protection) ===

/// Owner-side cooldown before sending delete message (seconds).
pub const OWNER_DELETE_COOLDOWN_SECS: u64 = 4 * SECS_PER_WEEK;

/// Holder-side cooldown after receiving delete before physical removal (seconds).
pub const HOLDER_DELETE_COOLDOWN_SECS: u64 = 4 * SECS_PER_WEEK;

/// Phase 2 disk pressure: notice window before holder drops symbols (seconds).
pub const DROP_NOTICE_WINDOW_SECS: u64 = 7 * 24 * 3600; // 7 days

// === Erasure coding (RaptorQ) ===

/// Default source block size in bytes (128 MB). Configurable via config.toml.
pub const DEFAULT_SOURCE_BLOCK_SIZE: u64 = 128 * 1024 * 1024;

/// Symbol size T in bytes. Fixed at ~64 KB (max for raptorq crate, u16 limit).
pub const SYMBOL_SIZE: u16 = 65_535;

/// Decode overhead: K_eff = K + DECODE_OVERHEAD.
pub const DECODE_OVERHEAD: u32 = 3;

/// Overhead formula: overhead = OVERHEAD_BASE + importance * OVERHEAD_SCALE.
/// Range: 1.5x (importance=0) to 3.0x (importance=1).
pub const OVERHEAD_BASE: f64 = 1.5;
pub const OVERHEAD_SCALE: f64 = 1.5;

// === Placement ===

/// Maximum holders per source block. Beyond ~30, marginal fault tolerance
/// gain is tiny while PoS/restore overhead grows linearly.
pub const MAX_HOLDERS_PER_BLOCK: u32 = 30;

/// Minimum symbols assigned per holder. Below this threshold the per-holder
/// tracking overhead (PoS, repair) isn't justified. Protects small-block configs.
pub const MIN_SYMBOLS_PER_HOLDER: u32 = 32; // 2 MB at T=64KB

/// Concentration cap factor: max_share = (1 - 1/overhead) * this.
pub const CONCENTRATION_CAP_FACTOR: f64 = 0.85;

// === Eviction priority ===
// priority = importance * trust_of_owner * (1 + age_bonus)

/// Hysteresis: new data must beat existing by this fraction to displace.
pub const EVICTION_HYSTERESIS: f64 = 0.2;

/// Max age bonus (+30% for old data).
pub const AGE_BONUS_CAP: f64 = 0.3;

/// Full age bonus reached after this many weeks.
pub const AGE_BONUS_WEEKS: f64 = 26.0;

/// Trust floor for unknown owners during eviction.
pub const UNKNOWN_OWNER_TRUST_FLOOR: f64 = 0.1;

// === Disk pressure ===

/// Default disk reserve in bytes (20 GB).
pub const DEFAULT_DISK_RESERVE_BYTES: u64 = 20 * 1024 * 1024 * 1024;

// === PoS (Proof of Storage) ===

/// PoS response timeout (7 days, also relay TTL).
pub const POS_TIMEOUT_SECS: u64 = 7 * 24 * 3600;

/// Base PoS challenges per holder per week.
pub const POS_BASE_CHALLENGES_PER_WEEK: u32 = 1;

/// volume_factor = ceil(holder_symbols / POS_VOLUME_DIVISOR).
pub const POS_VOLUME_DIVISOR: u32 = 1000;

// === Wire format ===

/// Max CBOR message frame size (128 MiB). Matches MAX_MSG_SIZE in swarm.rs codec.
pub const MAX_MESSAGE_SIZE: u32 = 128 * 1024 * 1024;

/// Soft budget for the symbol-data payload of a single SymbolTransferMsg.
/// Owners chunk larger deliveries into multiple transfers to stay below
/// MAX_MESSAGE_SIZE. The budget is expressed against *raw* `symbol.data.len()`
/// and is set conservatively (≈60% of MAX_MESSAGE_SIZE) to absorb CBOR
/// per-symbol overhead in the worst case we saw in gamma runs: ≈2240 symbols
/// × 65548 wire bytes ≈ 146 MiB wire from ≈140 MiB raw. Lowering from 100 MiB
/// to 80 MiB fixes those borderline cases; see tech-debt for the proper
/// wire-size accurate variant.
pub const SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES: usize = 80 * 1024 * 1024;

/// Protocol version for wire messages.
pub const PROTOCOL_VERSION: u8 = 1;

/// Handshake timestamp freshness window (+-300 seconds).
pub const HANDSHAKE_FRESHNESS_SECS: u64 = 300;

/// Max relay hop count — drop entries with hop >= this.
pub const MAX_RELAY_HOP: u8 = 2;

/// Relay entry TTL (7 days).
pub const RELAY_TTL_SECS: u64 = 7 * 24 * 3600;

/// HKDF info string for directed message encryption (ECDH -> ChaCha20).
pub const DIRECTED_ENCRYPTION_INFO: &[u8] = b"syncback-directed";

// === Backup triggers ===

/// Debounce: wait this long after last fs event before processing (seconds).
pub const DEBOUNCE_SECS: u64 = 30 * 60; // 30 minutes

/// Flush packing queue if idle for this long (seconds).
pub const FLUSH_IDLE_SECS: u64 = 60 * 60; // 1 hour

/// Flush packing queue unconditionally after this long (seconds).
pub const FLUSH_FALLBACK_SECS: u64 = 24 * 60 * 60; // 24 hours

/// Minimum batch size for flushing packing queue (bytes).
pub const MIN_BATCH_BYTES: u64 = 1024 * 1024; // 1 MB

// === File versioning ===

/// Default max versions kept per file path.
pub const DEFAULT_MAX_VERSIONS: u32 = 5;

/// Default max age for old versions (90 days, seconds).
pub const DEFAULT_MAX_VERSION_AGE_SECS: u64 = 90 * 24 * 3600;

// === Vacuum ===

/// Fraction of invalid files in a batch to trigger repack.
pub const VACUUM_INVALID_THRESHOLD: f64 = 0.5;

// === Budget planner ===

/// Default placement success rate on first run (no history).
pub const DEFAULT_SUCCESS_RATE: f64 = 0.5;

/// Conservative headroom multiplier.
pub const WILLINGNESS_FACTOR: f64 = 1.0;

/// Rolling window for weekly placement stats.
pub const WEEKLY_STATS_WINDOW: u32 = 4;

// === Cluster ===

/// Default max events per cluster sync batch.
pub const DEFAULT_CLUSTER_SYNC_BATCH_SIZE: usize = 100;

// === Relay board limits ===

/// Max entries per relay board (from protocol.md §1.5).
pub const MAX_BOARD_ENTRIES: usize = 2000;

/// Max total board size in bytes (8 MB, from protocol.md §1.5).
pub const MAX_BOARD_SIZE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum relay board entries accepted from a single author per
/// `process_remote_entries` call.
///
/// Prevents a malicious peer from filling the entire board with its own
/// entries and crowding out legitimate messages (pos_challenge, peer_announce).
///
/// Derived from MAX_BOARD_ENTRIES / 10, assuming a cluster of ~10 peers.
/// Each peer gets a fair share of the 2000-entry board.
pub const MAX_BOARD_ENTRIES_PER_AUTHOR: usize = 200;

// === PoS placement status thresholds ===

/// Number of consecutive PoS timeouts before a placement is marked Uncertain.
/// First timeout → Uncertain immediately (1 miss = Uncertain).
pub const POS_CONSECUTIVE_MISS_UNCERTAIN: u32 = 1;

/// Number of consecutive PoS timeouts before a placement is marked PresumedLost.
/// 3+ consecutive misses → PresumedLost → triggers repair.
pub const POS_CONSECUTIVE_MISS_PRESUMED_LOST: u32 = 3;

// === Commitment telemetry ===

/// Weight of PoS pass rate in commitment score.
pub const COMMITMENT_POS_WEIGHT: f64 = 0.5;

/// Weight of disk pressure signal in commitment score.
pub const COMMITMENT_PRESSURE_WEIGHT: f64 = 0.25;

/// Weight of relationship age signal in commitment score.
pub const COMMITMENT_AGE_WEIGHT: f64 = 0.15;

/// Weight of eviction priority of our data at the holder's node.
pub const COMMITMENT_PRIORITY_WEIGHT: f64 = 0.10;

/// Weeks of relationship needed to reach full age signal (1.0).
pub const COMMITMENT_AGE_SATURATION_WEEKS: f64 = 26.0;

/// Minimum PoS challenges required for the pass rate to count.
/// Below this: treat as if pass rate were 0. Prevents "no challenges = pass_rate=1.0".
pub const COMMITMENT_MIN_CHALLENGES: u32 = 1;

/// Eviction priority threshold below which commitment takes a penalty.
/// Set to 0.0 to disable the relative penalty (use only absolute priority).
pub const COMMITMENT_PRIORITY_FLOOR: f64 = 0.0;

// === Reliability forecast ===

/// Default assumed annual churn (30%). Used when no per-holder commitment data
/// is available. Matches the calibration table in docs/beta/raptorq.md.
pub const DEFAULT_ANNUAL_CHURN_RATE: f64 = 0.30;

/// Reliability threshold below which a block is flagged needs_repair.
/// 99.0% = two nines. Blocks below this get flagged in ReliabilityReport.
pub const RELIABILITY_REPAIR_THRESHOLD: f64 = 0.99;

/// Small N threshold: use exact binomial CDF for N < this value, normal
/// approximation for N >= this value.
pub const BINOMIAL_EXACT_THRESHOLD: u32 = 100;

// === Symbol offer handshake ===

/// Timeout for awaiting SymbolAccept on a direct connection (seconds).
/// Direct connection: 30s is generous for the offer→accept handshake.
pub const SYMBOL_OFFER_TIMEOUT_SECS: u64 = 30;

/// Timeout before an Offered placement is swept to Lost (seconds).
/// Must be long enough for full symbol delivery (encode + transfer + disk write).
/// 300s = 5 minutes — same as SYMBOL_OFFER_EXPIRY_SECS.
pub const OFFERED_PLACEMENT_TIMEOUT_SECS: u64 = 300;

/// Long-absence threshold for Offered placements (seconds).
/// Offered → Lost only after this interval if no real signal received.
/// Default: 14 days.
pub const LONG_ABSENCE_SECS: u64 = 14 * 24 * 3600; // 1_209_600

/// Stale accepted offer expiry (seconds). AcceptedOffers older than this are
/// discarded on next access even if no Transfer arrived.
pub const SYMBOL_OFFER_EXPIRY_SECS: u64 = 300;

// === Network reconnection ===

/// Seconds before retrying a failed peer connection.
pub const RECONNECT_BACKOFF_SECS: u64 = 30;

// === Holdings integrity scan ===

/// Default holdings integrity scan interval in seconds (1 day).
pub const DEFAULT_HOLDINGS_INTEGRITY_INTERVAL_SECS: u64 = 86_400;

// === Two-level trust ===

/// Fraction of master_trust inherited by a new device with zero device_trust.
/// effective_trust = base + dt * (1 - base/MAX_COMBINED_TRUST)
/// where base = master_trust.combined * TRUST_INHERITANCE_FACTOR
pub const TRUST_INHERITANCE_FACTOR: f64 = 0.3;

/// Maximum combined trust value (P=1, I=1, S=1 → KP + KI = 2.15).
/// Used in effective_trust formula denominator.
pub const MAX_COMBINED_TRUST: f64 = KP + KI; // = 2.15

// === Units ===

/// Bytes in one gibibyte (2^30).
pub const BYTES_PER_GB: f64 = 1_073_741_824.0;

// === Disaster Recovery ===

/// Maximum size of an encrypted SystemState blob accepted from a peer.
///
/// A legitimate SystemState blob for a cluster of ~20 peers (device certs,
/// trust records, placement metadata) compresses to tens of KB at most.
/// 2 MiB = ~100× headroom. Blobs above this limit are dropped with a warning
/// to prevent disk DoS from authenticated-but-malicious peers.
/// Must be << MAX_MESSAGE_SIZE (128 MiB).
pub const MAX_SYSTEM_STATE_BLOB_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

// === Compile-time sanity checks ===

const _: () = assert!(S_CLAMP_MIN < S_CLAMP_MAX);
const _: () = assert!(OVERHEAD_BASE > 1.0);
const _: () = assert!(DECODE_OVERHEAD > 0);
const _: () = assert!(SYMBOL_OFFER_TIMEOUT_SECS < SYMBOL_OFFER_EXPIRY_SECS);
const _: () = assert!(MAX_SYSTEM_STATE_BLOB_BYTES < MAX_MESSAGE_SIZE as usize);
