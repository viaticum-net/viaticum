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

/// Initial P value for newly connected peers.
pub const INITIAL_TRUST_P: f64 = 0.1;

/// S floor — even zero-storage peers get 10% trust multiplier.
pub const S_CLAMP_MIN: f64 = 0.1;

/// S ceiling.
pub const S_CLAMP_MAX: f64 = 1.0;

// === Escrow tiers (weeks_in_network thresholds) ===

/// Tier 1: basic restore access (1 month).
pub const ESCROW_TIER1_WEEKS: u32 = 4;

/// Tier 2: full restore access (3 months).
pub const ESCROW_TIER2_WEEKS: u32 = 13;

/// Tier 3: unlimited restore (6 months).
pub const ESCROW_TIER3_WEEKS: u32 = 26;

/// Free demo credit — first 1 GiB restorable with zero tenure.
pub const FREE_TIER_BYTES: u64 = 1 << 30; // 1 GiB

/// Tier 1 max cumulative restore (5 GiB).
pub const TIER1_MAX_BYTES: u64 = 5 << 30; // 5 GiB

/// Tier 2 max cumulative restore (50 GiB).
pub const TIER2_MAX_BYTES: u64 = 50 << 30; // 50 GiB

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

/// Target number of holders for symbol distribution.
pub const TARGET_HOLDER_COUNT: u32 = 15;

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

/// Max CBOR message frame size (64 MiB).
pub const MAX_MESSAGE_SIZE: u32 = 64 * 1024 * 1024;

/// ALPN protocol identifier for direct QUIC connections.
pub const ALPN: &[u8] = b"syncback/1";

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
pub const WILLINGNESS_FACTOR: f64 = 0.5;

/// Rolling window for weekly placement stats.
pub const WEEKLY_STATS_WINDOW: u32 = 4;

// === Compile-time sanity checks ===

const _: () = assert!(S_CLAMP_MIN < S_CLAMP_MAX);
const _: () = assert!(ESCROW_TIER1_WEEKS < ESCROW_TIER2_WEEKS);
const _: () = assert!(ESCROW_TIER2_WEEKS < ESCROW_TIER3_WEEKS);
const _: () = assert!(OVERHEAD_BASE > 1.0);
const _: () = assert!(DECODE_OVERHEAD > 0);
