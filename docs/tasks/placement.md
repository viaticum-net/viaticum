# Task Spec: placement.rs

Module in `crates/syncback-core/src/placement.rs`.

## Overview

PlacementEngine selects which peers will hold a given unit's shards. It applies
weighted selection (w = trust^2), enforces per-partner shard caps, computes
erasure coding parameters from importance, and applies adaptive n when average
trust is low. This module is pure logic: it reads from DB, returns a placement
plan, performs no I/O and no network calls.

## Dependencies

- `types.rs` — `ShardId`, `UnitId`, `IdentityPub`, `ImportanceScore`, `ErasureParams`
- `db.rs` — `Db`, queries over `peers`, `shards` tables
- `trust.rs` — `TrustEngine`, `TrustScore`
- `constants` — `ERASURE_K`, `TIER_HIGH_THRESHOLD`, `TIER_HIGH_N`, `TIER_MID_THRESHOLD`,
  `TIER_MID_N`, `TIER_LOW_THRESHOLD`, `TIER_LOW_N`, `MAX_SHARDS_PER_PARTNER`,
  `ADAPTIVE_N_LOW_TRUST`, `ADAPTIVE_N_MID_TRUST`
- `rand` — weighted sampling

## Public API

### Structs

```rust
/// Engine for shard placement decisions.
pub struct PlacementEngine {
    db: Db,
    trust: TrustEngine,
}

/// Parameters selected for a unit's erasure coding.
#[derive(Debug, Clone, PartialEq)]
pub struct ErasureParams {
    /// Data shards (k). Must have at least k shards to recover.
    pub k: usize,
    /// Total shards (n). n >= k.
    pub n: usize,
}

/// A concrete holder assignment for one shard.
#[derive(Debug, Clone)]
pub struct ShardAssignment {
    pub shard_index: u8,   // 0..n-1
    pub holder: IdentityPub,
}

/// Output of a placement decision for one unit.
#[derive(Debug, Clone)]
pub struct PlacementPlan {
    pub unit_id: UnitId,
    pub params: ErasureParams,
    /// Length == params.n. shard_index matches position in vec.
    pub assignments: Vec<ShardAssignment>,
}
```

### impl PlacementEngine

```rust
impl PlacementEngine {
    /// Create a new PlacementEngine backed by the given DB and TrustEngine.
    pub fn new(db: Db, trust: TrustEngine) -> Self;

    /// Select holders for a unit and return a PlacementPlan.
    ///
    /// Steps:
    ///   1. Compute ErasureParams from importance (see Business Rules).
    ///   2. Gather candidate peers from DB (all peers with trust > 0).
    ///   3. Compute weight w_i = trust_i^2 for each candidate.
    ///   4. Apply adaptive n if avg trust is low (see Business Rules).
    ///   5. Select n holders via weighted sampling without replacement,
    ///      enforcing the per-partner cap (max 6 shards per partner).
    ///   6. Apply subnet diversity rule (see Business Rules).
    ///   7. Return PlacementPlan.
    ///
    /// Errors:
    ///   - NotEnoughPeers if eligible candidates < n after cap enforcement.
    pub fn select_holders(
        &self,
        unit_id: UnitId,
        importance: ImportanceScore,
    ) -> Result<PlacementPlan, PlacementError>;

    /// Return ErasureParams for a given importance score.
    /// Pure function, no DB access.
    pub fn erasure_params(importance: ImportanceScore) -> ErasureParams;

    /// Return adjusted n after applying adaptive-n rule.
    /// avg_trust is the mean trust score over all candidate peers.
    /// Pure function, no DB access.
    pub fn adaptive_n(base_n: usize, avg_trust: f64) -> usize;

    /// Count how many shards of a given unit each peer currently holds
    /// in the `shards` table (status active or pending). Used for cap enforcement.
    ///
    /// Returns a map peer → shard count for the given unit.
    pub fn current_shard_counts(
        &self,
        unit_id: UnitId,
    ) -> Result<std::collections::HashMap<IdentityPub, usize>, PlacementError>;
}
```

### Error Enum

```rust
#[derive(Debug, thiserror::Error)]
pub enum PlacementError {
    #[error("not enough eligible peers: need {need}, have {have}")]
    NotEnoughPeers { need: usize, have: usize },

    #[error("trust error: {0}")]
    Trust(#[from] TrustError),

    #[error("db error: {0}")]
    Db(#[from] redb::Error),
}
```

## Types Required

These are defined in `types.rs` and used here:

```rust
/// Importance score clamped to [0.0, 1.0].
/// Implements PartialOrd, Copy.
pub struct ImportanceScore(pub f64);

/// Newtype for peer identity.
pub struct IdentityPub(pub [u8; 32]);

/// Newtype for unit identity.
pub struct UnitId(pub [u8; 32]);

/// Trust score (output of TrustEngine::score).
#[derive(Debug, Clone, Copy)]
pub struct TrustScore {
    pub value: f64,   // [0.0, ∞) — unbounded above, clamped when used
    pub p: f64,
    pub i: f64,
    pub s: f64,
}
```

`TrustScore` is defined in `trust.rs`; `PlacementEngine` uses it via the trust
module's public API.

## DB Operations

### Tables read

**`peers`** table: `IdentityPub → PeerRecord`
- Query: iterate all peers to gather candidates and their trust components.
- Used in: `select_holders` candidate gathering step.

**`shards`** table: `ShardId → ShardRecord`
- Query: scan all shards for a given `unit_id` to count existing holder
  assignments per partner.
- Used in: `current_shard_counts`.

Fields needed from `PeerRecord`:
- `trust_p: f64`, `trust_i: f64`, `trust_s: f64` — for weight calculation
- `subnet: Option<[u8; 3]>` — for subnet diversity rule (IPv4 /24)
- `asn: Option<u32>` — for ASN diversity rule (post-MVP, can be `None` for MVP)

Fields needed from `ShardRecord`:
- `unit_id: UnitId`
- `holder_id: IdentityPub`
- `status: ShardStatus` — only count `Active` or `Pending` shards

### Tables written

None. PlacementEngine is read-only. The caller (Processor) writes the resulting
`PlacementPlan` to the `shards` table after the plan is approved.

## Business Rules

### Erasure tiers by importance

```
importance >= 0.8  →  ErasureParams { k: 5, n: 15 }  (×3.0 overhead)
importance >= 0.4  →  ErasureParams { k: 5, n: 10 }  (×2.0 overhead)
importance >= 0.1  →  ErasureParams { k: 5, n: 7  }  (×1.4 overhead)
importance < 0.1   →  do not back up (caller should not call select_holders)
```

The caller (Scheduler/Budget Planner) must filter out importance < 0.1 before
calling `select_holders`. If called with importance < 0.1, return
`PlacementError::NotEnoughPeers { need: n, have: 0 }`.

DECIDED: Yes, separate `PlacementError::ImportanceTooLow(ImportanceScore)` error variant.
Caller should filter before calling, but if they don't — clear error, not confusing NotEnoughPeers.

### Weight formula

```
w_i = trust_i^2
```

where `trust_i` is the full trust score `(kp * P_i + ki * I_i) * clamp(S_i, 0.1, 1.0)`.

Peers with `trust_i == 0.0` are excluded from candidate set entirely (weight 0 →
never selected).

### Per-partner shard cap

Maximum 6 shards of the SAME UNIT per holder. This prevents a single peer from
holding too many shards of the same file (diversity).

Implementation: after weighted sampling picks a holder, check
`current_shard_counts[holder] < 6`. If the cap would be exceeded, exclude this
peer from the pool and re-sample. Continue until n holders are selected or the
eligible pool is exhausted.

Note: the cap is per-unit, not global. A single peer can hold shards from many
different units.

### Adaptive n

When average trust of candidate peers is low, increase n to compensate for
expected holder churn:

```
avg_trust = mean(trust_i for all candidates)

extra = if avg_trust < 0.3 { 2 }
        else if avg_trust < 0.6 { 1 }
        else { 0 }

n_actual = n_base + extra
```

`n_actual` is the n used for weighted sampling after computing `ErasureParams`.
The k value does NOT change — k = 5 always. Only n grows.

DECIDED: Thresholds 0.3 / 0.6 confirmed as `ADAPTIVE_N_LOW_TRUST` / `ADAPTIVE_N_MID_TRUST`
in `crate::constants`. From simulation experiments, reasonable for MVP.

### Subnet diversity rule (anti-Sybil)

After selecting a holder, check:
- At most 1 shard of this unit per /24 subnet (IPv4 first 3 octets)
- At most 2 shards of this unit per ASN

If adding this holder would violate the subnet rule, skip it and try next
candidate. This is a best-effort rule — if the peer pool is small and all peers
share a subnet, the rule is relaxed to allow placement (log at DEBUG level).

For peers where `subnet` is `None` (IPv6 or unknown), skip the subnet check
(allow unconditionally).

For MVP, ASN diversity is not enforced (ASN data not collected). Add TODO.

### Weighted sampling algorithm

Use weighted sampling without replacement:

```
1. Build vec of (peer, weight) for all eligible candidates.
2. Normalize weights to sum to 1.0.
3. For each of n slots:
   a. Sample peer proportional to weight.
   b. Check cap + subnet constraints. If violated, remove peer from pool,
      pick next heaviest candidate (no re-normalization needed for alpha).
   c. If accepted: add to assignments, reduce remaining pool.
4. If pool exhausted with < n assignments: return NotEnoughPeers.
```

Deterministic seeding is NOT required (non-deterministic selection is fine and
desirable for diversity). Use `rand::thread_rng()` if rand is available, or
implement a simple weighted Fisher-Yates shuffle.

DECIDED: Add `rand` to workspace Cargo.toml deps. Implementer adds it when implementing
this module.

## Test Scenarios

All tests use real redb (via `testutil::test_db()`). No mocks.

### 1. `erasure_params_tier_mapping`

```
ImportanceScore(0.9) → ErasureParams { k:5, n:15 }
ImportanceScore(0.8) → ErasureParams { k:5, n:15 }  (boundary)
ImportanceScore(0.79)→ ErasureParams { k:5, n:10 }
ImportanceScore(0.4) → ErasureParams { k:5, n:10 }  (boundary)
ImportanceScore(0.39)→ ErasureParams { k:5, n:7  }
ImportanceScore(0.1) → ErasureParams { k:5, n:7  }  (boundary)
ImportanceScore(0.09)→ NotEnoughPeers (or ImportanceTooLow)
ImportanceScore(0.0) → NotEnoughPeers
```

### 2. `placement_fails_when_fewer_peers_than_n`

Setup: 4 peers in DB, all with trust 0.5. Call `select_holders` with
`importance = 0.8` (n_base = 15).
Expected: `PlacementError::NotEnoughPeers { need: 15, have: 4 }`.

### 3. `placement_succeeds_with_exact_n_peers`

Setup: exactly 15 peers in DB (no adaptive bump since avg_trust is moderate).
importance = 0.8.
Expected: Ok(PlacementPlan) with 15 unique holders, no duplicates.

### 4. `placement_weights_are_proportional_to_trust_squared`

Setup: 3 peers with trust values 0.1, 0.5, 1.0.
Expected weights: 0.01, 0.25, 1.0 (proportional). High-trust peer should be
selected most often in 1000 trials (statistical test, not exact).
NOTE: this test is a probabilistic sanity check. Run 1000 times and verify
high-trust peer is in > 60% of single-slot selections.

### 5. `per_partner_cap_enforced`

Setup: 3 peers (A, B, C) with equal trust. Unit already has 6 shards assigned
to peer A in DB. importance = 0.1 (n=7).
Expected: peer A never appears in assignment for the remaining 1 slot.

### 6. `adaptive_n_increases_n_when_avg_trust_low`

Setup: 20 peers with trust = 0.2 (below 0.3 threshold).
importance = 0.4 (base n=10).
Expected: `plan.params.n == 12` (base 10 + extra 2).
Assignments list has 12 entries.

### 7. `subnet_diversity_limits_per_subnet_shards`

Setup: 15 peers, all with subnet `[192, 168, 1]` (same /24). importance = 0.8
(n_base=15).
Expected: either the rule is relaxed and 15 holders are selected (all same
subnet), OR if strictly enforced with only 1 allowed, PlacementError::NotEnoughPeers.
Decision: the rule is best-effort. Log warning, allow placement.
Expected: Ok(PlacementPlan) with 15 assignments, log message at DEBUG.

### 8. `zero_trust_peers_excluded`

Setup: 10 peers with trust = 0.0, 7 peers with trust > 0.0. importance = 0.1
(n=7).
Expected: only the 7 positive-trust peers are in assignments.

### 9. `placement_returns_correct_shard_indices`

Setup: 8 peers. importance = 0.1 (n=7).
Expected: assignments have shard_index in 0..7, each exactly once, no gaps.

### 10. `current_shard_counts_counts_only_active_and_pending`

Setup: unit_id X has shards in states: 3 Active, 2 Pending, 1 Deleted for peer A.
Expected: `current_shard_counts(X)[A] == 5` (Active + Pending).

## Module Skeleton

```rust
// placement.rs
use crate::{
    db::Db,
    trust::{TrustEngine, TrustError},
    types::{IdentityPub, ImportanceScore, UnitId},
};

pub struct PlacementEngine { ... }
pub struct ErasureParams { ... }
pub struct ShardAssignment { ... }
pub struct PlacementPlan { ... }

#[derive(Debug, thiserror::Error)]
pub enum PlacementError { ... }

impl PlacementEngine {
    pub fn new(db: Db, trust: TrustEngine) -> Self { ... }
    pub fn select_holders(...) -> Result<PlacementPlan, PlacementError> { ... }
    pub fn erasure_params(importance: ImportanceScore) -> ErasureParams { ... }
    pub fn adaptive_n(base_n: usize, avg_trust: f64) -> usize { ... }
    pub fn current_shard_counts(...) -> Result<HashMap<IdentityPub, usize>, PlacementError> { ... }
}

#[cfg(test)]
mod tests { ... }
```
