# Task: constants.rs

Single file with ALL tunable constants. One place to review, one place to tweak, `cargo build`.

**File:** `crates/syncback-core/src/constants.rs`
**Dependencies:** none (leaf module, no imports from crate)
**Depended on by:** every other module via `use crate::constants::*`

## Rules

- Every numeric constant that appears in business logic goes here
- Module-internal implementation details (table names, buffer internals) stay in modules
- Comments are mandatory: one line per constant explaining what it is
- Group by domain (trust, escrow, erasure, placement, eviction, disk pressure, wire format, time)

## Constants

```rust
// === Time ===
/// Seconds in one week (7 * 24 * 60 * 60)
pub const SECS_PER_WEEK: u64 = 604_800;

// === Trust formula ===
// trust = (KP * P + KI * I) * clamp(S, S_CLAMP_MIN, S_CLAMP_MAX)
// P = 4-week rolling pass rate, I = cumulative mean, S = pairwise GB ratio

/// Weight on P (4-week rolling window). Range [0.3, 0.5] from simulations.
pub const KP: f64 = 0.4;

/// Weight on I (cumulative mean). Range [1.5, 2.0] from simulations.
pub const KI: f64 = 1.75;

/// Rolling window length for P score (weeks)
pub const P_WINDOW_WEEKS: u32 = 4;

/// S floor — even zero-storage peers get 10% trust multiplier
pub const S_CLAMP_MIN: f64 = 0.1;

/// S ceiling
pub const S_CLAMP_MAX: f64 = 1.0;

// === Escrow tiers (weeks_in_network thresholds) ===

/// Tier 1: basic restore access (1 month)
pub const ESCROW_TIER1_WEEKS: u32 = 4;

/// Tier 2: full restore access (3 months)
pub const ESCROW_TIER2_WEEKS: u32 = 13;

/// Tier 3: unlimited restore (6 months)
pub const ESCROW_TIER3_WEEKS: u32 = 26;

/// Free demo credit — first 1 GiB restorable with zero tenure
pub const FREE_TIER_BYTES: u64 = 1 << 30; // 1 GiB

/// Tier 1 max cumulative restore (5 GiB)
pub const TIER1_MAX_BYTES: u64 = 5 << 30; // 5 GiB

/// Tier 2 max cumulative restore (50 GiB)
pub const TIER2_MAX_BYTES: u64 = 50 << 30; // 50 GiB

// Tier 3: unlimited (no constant needed)

// === Cooldown (ransomware protection) ===
// Owner waits 4wk before sending delete + holder waits 4wk before deleting = 8wk total

/// Owner-side cooldown before sending delete message (seconds)
pub const OWNER_DELETE_COOLDOWN_SECS: u64 = 4 * SECS_PER_WEEK;

/// Holder-side cooldown after receiving delete before physical removal (seconds)
pub const HOLDER_DELETE_COOLDOWN_SECS: u64 = 4 * SECS_PER_WEEK;

/// Phase 2 disk pressure: notice window before holder drops shard (seconds)
pub const DROP_NOTICE_WINDOW_SECS: u64 = 7 * 24 * 3600; // 7 days

// === Erasure coding ===

/// Minimum shards needed to reconstruct a file (Reed-Solomon k)
pub const ERASURE_K: u32 = 5;

/// importance >= this → 5-of-15 (critical data: documents, keys)
pub const TIER_HIGH_THRESHOLD: f64 = 0.8;
/// n_base for high tier
pub const TIER_HIGH_N: u32 = 15;

/// importance >= this → 5-of-10 (valuable: photos)
pub const TIER_MID_THRESHOLD: f64 = 0.4;
/// n_base for mid tier
pub const TIER_MID_N: u32 = 10;

/// importance >= this → 5-of-7 (replaceable: videos)
pub const TIER_LOW_THRESHOLD: f64 = 0.1;
/// n_base for low tier
pub const TIER_LOW_N: u32 = 7;

// === Placement ===

/// Max shards of the same unit on one partner
pub const MAX_SHARDS_PER_PARTNER: u32 = 6;

/// avg_trust below this → add 2 extra shards to n
pub const ADAPTIVE_N_LOW_TRUST: f64 = 0.3;

/// avg_trust below this (but >= LOW) → add 1 extra shard
pub const ADAPTIVE_N_MID_TRUST: f64 = 0.6;

// === Eviction priority ===
// priority = importance * trust_of_owner * (1 + age_bonus)
// age_bonus = min(weeks_stored / AGE_BONUS_WEEKS, AGE_BONUS_CAP)

/// Hysteresis: new shard must beat existing by this fraction to displace
pub const EVICTION_HYSTERESIS: f64 = 0.2;

/// Max age bonus (+30% for old shards)
pub const AGE_BONUS_CAP: f64 = 0.3;

/// Full age bonus reached after this many weeks
pub const AGE_BONUS_WEEKS: f64 = 26.0;

/// Trust floor for unknown owners during eviction (0.1 = don't evict too aggressively)
pub const UNKNOWN_OWNER_TRUST_FLOOR: f64 = 0.1;

// === Disk pressure (fraction of storage_quota) ===

/// Soft threshold: stop accepting new offers when free < 15%
pub const SOFT_PRESSURE_THRESHOLD: f64 = 0.15;

/// Hard threshold: start evicting when free < 5%
pub const HARD_PRESSURE_THRESHOLD: f64 = 0.05;

// === Budget planner ===

/// Default placement success rate on first run (no history)
pub const DEFAULT_SUCCESS_RATE: f64 = 0.5;

/// Conservative headroom multiplier: headroom = committed * success_rate * this
pub const WILLINGNESS_FACTOR: f64 = 0.5;

/// Rolling window for weekly placement stats
pub const WEEKLY_STATS_WINDOW: u32 = 4;

// === Wire format ===

/// Max CBOR message frame size (64 KiB)
pub const MAX_MESSAGE_SIZE: u32 = 65_536;

/// ALPN protocol identifier for direct QUIC connections
pub const ALPN: &[u8] = b"syncback/1";

/// Board entry TTL (7 days) — also PoS response deadline
pub const BOARD_TTL_SECS: u64 = 7 * 24 * 3600;

/// Protocol version for wire messages
pub const PROTOCOL_VERSION: u8 = 1;

/// Handshake timestamp freshness window (±300 seconds)
pub const HANDSHAKE_FRESHNESS_SECS: u64 = 300;

/// Max relay hop count — drop entries with hop >= this
pub const MAX_RELAY_HOP: u8 = 2;

/// HKDF info string for directed message encryption (ECDH → ChaCha20)
pub const DIRECTED_ENCRYPTION_INFO: &[u8] = b"syncback-directed";
```

## Test scenarios

Constants module has no logic, so no unit tests. Constants are tested indirectly through every other module's tests.

One compile-time sanity check (in the module itself):

```rust
// Compile-time assertions
const _: () = assert!(ERASURE_K < TIER_LOW_N);
const _: () = assert!(TIER_LOW_N < TIER_MID_N);
const _: () = assert!(TIER_MID_N < TIER_HIGH_N);
const _: () = assert!(TIER_LOW_THRESHOLD < TIER_MID_THRESHOLD);
const _: () = assert!(TIER_MID_THRESHOLD < TIER_HIGH_THRESHOLD);
const _: () = assert!(HARD_PRESSURE_THRESHOLD < SOFT_PRESSURE_THRESHOLD);
const _: () = assert!(S_CLAMP_MIN < S_CLAMP_MAX);
const _: () = assert!(ESCROW_TIER1_WEEKS < ESCROW_TIER2_WEEKS);
const _: () = assert!(ESCROW_TIER2_WEEKS < ESCROW_TIER3_WEEKS);
```

## Build order

`constants` is the very first module — before `types`. No dependencies.

```
constants → types → db → trust → escrow → placement → budget → messages
```
