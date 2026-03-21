# Task: placement — SymbolBudgetManager (β)

Module: `crates/syncback-core/src/placement/`
Files: `mod.rs` + `tests.rs`

---

## Overview

The placement module computes how many symbols to assign to each candidate holder, given
their trust scores and a total symbol budget N. It is pure logic — no DB, no async, no
network. The BackupCoordinator calls this to determine ESI allocation before encoding and
distributing symbols.

**What this module does:**

1. **Weight computation** — compute `weight_i = trust_i / sqrt(1 - trust_i)` for each
   candidate holder (the mean-variance optimal placement weight).

2. **Share computation** — normalize weights to shares, multiply by N, round to integer
   symbol counts.

3. **Concentration cap enforcement** — clamp each holder's allocation to
   `max_per_holder` from `ErasureParams::max_per_holder()`. Redistribute excess from
   capped holders to uncapped holders iteratively until stable.

4. **ESI range assignment** — assign non-overlapping ESI ranges to holders
   (holder 0 gets ESIs 0..count_0, holder 1 gets count_0..count_0+count_1, etc.).

5. **Minimum guarantee** — every holder in the input list gets at least 1 symbol
   (unless total N < len(holders), in which case some holders are dropped from the result).

6. **Validation** — return `Err` if not enough candidates to produce a viable
   distribution (fewer than 2 holders after filtering, or total N < 2).

This module does NOT select which peers to consider — that is done by the caller
(BackupCoordinator reads PeerRecords from DB and passes candidates here). This module
only computes counts and ESI ranges.

---

## Dependencies

- `crate::types::{IdentityPub, ErasureParams}`
- `crate::constants::{TARGET_HOLDER_COUNT}`
- No DB. No async. No network. Pure logic.

---

## Types

```rust
/// Input: one candidate holder with its trust score.
#[derive(Debug, Clone)]
pub struct HolderCandidate {
    pub identity: IdentityPub,
    /// Combined trust score in [0.0, 1.0]. From TrustEngine::combined_score.
    pub trust: f64,
}

/// Output: symbol allocation for one holder.
#[derive(Debug, Clone, PartialEq)]
pub struct HolderAllocation {
    pub identity: IdentityPub,
    /// Number of symbols assigned to this holder.
    pub symbol_count: u32,
    /// ESI range: symbols ESI start_esi .. start_esi + symbol_count.
    pub start_esi: u32,
}

impl HolderAllocation {
    /// ESI range as (start, count) pair (matches SymbolPlacement.esi_ranges format).
    pub fn esi_range(&self) -> (u32, u32) {
        (self.start_esi, self.symbol_count)
    }
}

/// Error from placement computation.
#[derive(Debug, thiserror::Error)]
pub enum PlacementError {
    /// No candidates provided.
    #[error("no candidates provided")]
    NoCandidates,

    /// All candidates have trust = 1.0 exactly (weight = infinity).
    /// This is a degenerate input — use a trust floor in practice.
    #[error("all candidates have trust = 1.0 (degenerate input)")]
    AllTrustMaximum,

    /// Fewer than 2 viable holders after filtering.
    /// A single holder having all symbols defeats the purpose of erasure coding.
    #[error("fewer than 2 viable holders: {count}")]
    TooFewHolders { count: usize },

    /// N is less than number of holders (cannot assign 1 symbol per holder).
    /// Caller should reduce holder count.
    #[error("N={n} is less than holder count={holders}, cannot assign minimum 1 per holder")]
    NTooSmall { n: u32, holders: usize },
}
```

---

## Public API

```rust
/// Compute symbol allocation across candidate holders.
///
/// Algorithm:
///   1. Filter out candidates with trust >= 1.0 (weight = infinity, degenerate).
///      If all candidates are filtered → Err(AllTrustMaximum).
///      If fewer than 2 remain → Err(TooFewHolders).
///   2. Clamp trust to [0.001, 0.999] to avoid weight = 0 or infinity.
///   3. Compute weight_i = trust_i / sqrt(1 - trust_i).
///   4. Normalize: share_i = weight_i / sum(weights).
///   5. raw_i = max(1, round(params.n * share_i)).
///   6. Redistribute: while any holder is over max_per_holder AND any is under:
///      a. excess = sum(raw_i - max_per_holder for capped holders)
///      b. cap all capped holders to max_per_holder
///      c. distribute excess proportionally to uncapped holders (by weight)
///      d. re-clamp to max_per_holder
///      Repeat until stable (max 10 iterations — convergence is guaranteed).
///   7. Adjust total to exactly params.n:
///      - If sum > n: reduce allocations for lowest-weight holders first
///      - If sum < n: increase allocations for highest-weight uncapped holders first
///   8. Assign ESI ranges: sorted by descending symbol count (most symbols first).
///      holder[0]: ESIs 0..count_0
///      holder[1]: ESIs count_0..count_0+count_1
///      etc.
///   9. Return allocations sorted by descending symbol_count.
///
/// Returns Err(NTooSmall) if params.n < candidates.len() after filtering.
///
/// candidates: list of candidate holders. May be longer than TARGET_HOLDER_COUNT;
/// the function uses all provided candidates (caller pre-filters by trust threshold).
pub fn compute_allocation(
    candidates: &[HolderCandidate],
    params: &ErasureParams,
) -> Result<Vec<HolderAllocation>, PlacementError>;

/// Compute just the weight for a single trust score.
/// weight = trust / sqrt(1 - trust)
/// trust is clamped to [0.001, 0.999] before computation.
/// Exposed for testing and for BackupCoordinator priority sorting.
pub fn holder_weight(trust: f64) -> f64;
```

---

## Business Rules

### Weight formula

```
trust_clamped = clamp(trust, 0.001, 0.999)
weight = trust_clamped / sqrt(1.0 - trust_clamped)
```

At trust=0.5: weight = 0.5 / sqrt(0.5) ≈ 0.707
At trust=0.8: weight = 0.8 / sqrt(0.2) ≈ 1.789
At trust=0.95: weight = 0.95 / sqrt(0.05) ≈ 4.249

This is the mean-variance optimal placement weight (higher trust holders get
disproportionately more symbols, reflecting lower loss probability).

### Concentration cap

From `ErasureParams::max_per_holder()`:
```
cap_fraction = (1 - 1/overhead) × CONCENTRATION_CAP_FACTOR  // CONCENTRATION_CAP_FACTOR = 0.85
cap = floor(cap_fraction × N)
max_per_holder = min(K_eff - 1, cap)
```

The K_eff-1 hard limit ensures no single holder can reconstruct the whole block on its own.

### Redistribution algorithm

The redistribution loop is bounded at 10 iterations and always terminates because:
- Each iteration either moves symbols from capped to uncapped holders (reducing capped count)
- Or the system is already stable (no changes)

After redistribution, the total may drift slightly from params.n due to rounding. The
step 7 adjustment corrects this by adding/removing 1 symbol from the highest/lowest
weight holders.

### Minimum 1 symbol per holder

Every candidate in the result receives at least 1 symbol. If params.n < len(candidates),
return `Err(NTooSmall)` so the caller can reduce the holder list.

In practice this case is unlikely: N is at minimum K_eff * 1.5, and TARGET_HOLDER_COUNT
= 15, so N / holders ≈ 200 for default parameters.

### ESI assignment order

Assign ESI ranges sorted by descending symbol count (largest allocation first, ESIs
starting at 0). This is a convention — the BackupCoordinator and RestoreCoordinator must
agree on it. The sort is deterministic because ties are broken by `identity` bytes.

```
allocations.sort_by(|a, b| {
    b.symbol_count.cmp(&a.symbol_count)
        .then(a.identity.0.cmp(&b.identity.0))
});
esi_offset = 0;
for alloc in &mut allocations {
    alloc.start_esi = esi_offset;
    esi_offset += alloc.symbol_count;
}
```

### Numerical example

From raptorq_cheatsheet.md:
```
N=9838, overhead=2.4x, max_per_holder≈4821, 15 holders

Holder   trust   weight   raw_share   capped?  symbols
NAS      0.95    4.36     26.6%       no       2616
Desktop  0.80    1.79     10.9%       no       1071
Peer C   0.70    1.28     7.8%        no       768
...other 12 peers (trust 0.3-0.6)...
Total:                                          9838 ✓
```

---

## DB Operations

None. This module is pure logic. The caller reads PeerRecords from DB, extracts trust
scores, and passes HolderCandidates to this module.

---

## Test Scenarios

Tests in `placement/tests.rs`. Pattern: `what_when_then`.

### 1. `compute_allocation_single_holder_fails`

```
candidates = [HolderCandidate { identity: [1u8;32].into(), trust: 0.8 }]
params = ErasureParams::compute(65535, 0.5)
result = compute_allocation(&candidates, &params)
assert matches!(result, Err(PlacementError::TooFewHolders { count: 1 }))
```

### 2. `compute_allocation_no_candidates_fails`

```
result = compute_allocation(&[], &params)
assert matches!(result, Err(PlacementError::NoCandidates))
```

### 3. `compute_allocation_total_equals_n`

```
// 15 candidates with varying trust scores
candidates = make_candidates(15, trusts=[0.9, 0.85, 0.8, 0.75, 0.7, 0.65, 0.6, 0.55, 0.5, 0.45, 0.4, 0.35, 0.3, 0.25, 0.2])
params = ErasureParams::compute(128 * 1024 * 1024, 0.6)  // N ≈ 4922
allocs = compute_allocation(&candidates, &params).unwrap()
total = allocs.iter().map(|a| a.symbol_count).sum::<u32>()
assert total == params.n
```

### 4. `compute_allocation_all_above_one_symbol`

```
// All allocations must be >= 1
allocs = compute_allocation(&candidates, &params).unwrap()
for alloc in &allocs:
    assert alloc.symbol_count >= 1
```

### 5. `compute_allocation_none_exceed_max_per_holder`

```
allocs = compute_allocation(&candidates, &params).unwrap()
max = params.max_per_holder()
for alloc in &allocs:
    assert alloc.symbol_count <= max
```

### 6. `compute_allocation_esi_ranges_are_contiguous_non_overlapping`

```
allocs = compute_allocation(&candidates, &params).unwrap()
// Sort by start_esi
allocs.sort_by_key(|a| a.start_esi)
next_esi = 0
for alloc in &allocs:
    assert alloc.start_esi == next_esi
    next_esi = alloc.start_esi + alloc.symbol_count
assert next_esi == params.n
```

### 7. `compute_allocation_high_trust_holder_gets_more_symbols`

```
candidates = [
    HolderCandidate { identity: [1u8;32].into(), trust: 0.95 },
    HolderCandidate { identity: [2u8;32].into(), trust: 0.3 },
    HolderCandidate { identity: [3u8;32].into(), trust: 0.5 },
]
params = ErasureParams::compute(128 * 1024 * 1024, 0.6)
allocs = compute_allocation(&candidates, &params).unwrap()
// Find allocations by identity
alloc_95 = allocs.iter().find(|a| a.identity == [1u8;32].into()).unwrap()
alloc_30 = allocs.iter().find(|a| a.identity == [2u8;32].into()).unwrap()
assert alloc_95.symbol_count > alloc_30.symbol_count
```

### 8. `compute_allocation_equal_trust_distributes_evenly`

```
// 3 holders with identical trust
candidates = (0..3).map(|i| HolderCandidate { identity: [i as u8 + 1; 32].into(), trust: 0.7 }).collect()
params = ErasureParams::compute(128 * 1024 * 1024, 0.5)  // some N
allocs = compute_allocation(&candidates, &params).unwrap()
// Each allocation should be within 1 of params.n / 3
expected = params.n / 3
for alloc in &allocs:
    assert (alloc.symbol_count as i64 - expected as i64).abs() <= 1
```

### 9. `compute_allocation_cap_enforced_with_very_high_trust`

```
// One holder at trust=0.99 would get almost everything without cap
candidates = [
    HolderCandidate { identity: [1u8;32].into(), trust: 0.99 },
    HolderCandidate { identity: [2u8;32].into(), trust: 0.01 },
    HolderCandidate { identity: [3u8;32].into(), trust: 0.01 },
]
params = ErasureParams::compute(128 * 1024 * 1024, 0.5)
allocs = compute_allocation(&candidates, &params).unwrap()
max = params.max_per_holder()
alloc_99 = allocs.iter().find(|a| a.identity == [1u8;32].into()).unwrap()
assert alloc_99.symbol_count <= max
// Remainder distributed to the other two
total = allocs.iter().map(|a| a.symbol_count).sum::<u32>()
assert total == params.n
```

### 10. `compute_allocation_two_candidates_minimum_viable`

```
candidates = [
    HolderCandidate { identity: [1u8;32].into(), trust: 0.8 },
    HolderCandidate { identity: [2u8;32].into(), trust: 0.6 },
]
params = ErasureParams::compute(128 * 1024 * 1024, 0.5)
result = compute_allocation(&candidates, &params)
assert result.is_ok()
allocs = result.unwrap()
assert allocs.len() == 2
total = allocs.iter().map(|a| a.symbol_count).sum::<u32>()
assert total == params.n
```

### 11. `holder_weight_increases_with_trust`

```
w1 = holder_weight(0.3)
w2 = holder_weight(0.5)
w3 = holder_weight(0.7)
w4 = holder_weight(0.9)
assert w1 < w2 && w2 < w3 && w3 < w4
```

### 12. `holder_weight_at_half_is_sqrt_half`

```
w = holder_weight(0.5)
// trust/(sqrt(1-trust)) = 0.5/sqrt(0.5) = 0.5/0.7071... ≈ 0.7071
assert (w - 0.7071).abs() < 0.001
```

### 13. `compute_allocation_n_too_small_returns_error`

```
// 5 candidates but N = 3 (impossible to assign 1 each)
candidates = (0..5).map(|i| HolderCandidate { identity: [i;32].into(), trust: 0.5 }).collect()
// Use a very small source block to get tiny N
params = ErasureParams { k: 1, k_eff: 4, t: 65535, overhead: 1.5, n: 3 }  // manually crafted
result = compute_allocation(&candidates, &params)
assert matches!(result, Err(PlacementError::NTooSmall { .. }))
```

### 14. `compute_allocation_fifteen_holders_realistic_params`

```
// Realistic scenario: 15 holders, source block 128 MB, importance 0.6
candidates = make_15_candidates_varying_trust()
params = ErasureParams::compute(128 * 1024 * 1024, 0.6)
allocs = compute_allocation(&candidates, &params).unwrap()
assert allocs.len() == 15
total = allocs.iter().map(|a| a.symbol_count).sum::<u32>()
assert total == params.n  // exactly params.n
for alloc in &allocs {
    assert alloc.symbol_count >= 1
    assert alloc.symbol_count <= params.max_per_holder()
}
// Verify ESI coverage
let mut seen = vec![false; params.n as usize];
for alloc in &allocs {
    for esi in alloc.start_esi..alloc.start_esi + alloc.symbol_count {
        assert !seen[esi as usize], "duplicate ESI {esi}";
        seen[esi as usize] = true;
    }
}
assert seen.iter().all(|&b| b);
```

### 15. `esi_range_helper_returns_start_and_count`

```
alloc = HolderAllocation { identity: ..., symbol_count: 100, start_esi: 500 }
assert alloc.esi_range() == (500, 100)
```

---

## Module Structure

```
placement/
  mod.rs    — all types and functions above
  tests.rs  — all test scenarios above
```

---

## Notes for implementer

- The redistribution loop must be bounded (max 10 iterations) to prevent any possible
  infinite loop due to floating-point rounding. In practice it always converges in 2-3
  iterations.

- For step 7 (adjust total to exactly N): when sum > N, reduce from the lowest-weight
  holders first (they lose the least reliability per symbol removed). When sum < N, add
  to the highest-weight uncapped holders first.

- `trust >= 1.0` holders should be filtered out entirely (weight = infinity = degenerate).
  In practice the TrustEngine never produces trust = 1.0 because the trust formula
  converges but never reaches 1.0. The filter is a safety guard.

- The `candidates` slice may contain up to 50+ peers (all known peers). The function
  should use all of them — no internal limit on candidate count. The caller can
  pre-filter by minimum trust threshold before calling.

- `ErasureParams` is already defined in `crate::types`. Import and use
  `params.max_per_holder()`, `params.n`, `params.k_eff`.

- All tests live in `placement/tests.rs`, never inline.

- The `esi_range()` helper on `HolderAllocation` returns a `(start, count)` tuple that
  directly matches the format of `SymbolPlacement.esi_ranges` in the DB layer. The
  BackupCoordinator will use this to build `SymbolPlacement` records.
