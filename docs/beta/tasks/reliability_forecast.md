# Task: Reliability Forecast (Phase 4.5)

Module: `crates/syncback-core/src/reliability/`
Files: `mod.rs` + `tests.rs`

---

## Overview

The reliability forecast module answers: "What is the probability that a given file
or source block can be recovered at some future time?" It does this by computing the
binomial survival probability formula from `docs/beta/raptorq.md`:

```
P(file alive) = P(Binomial(N, p) >= K_eff)
```

where N is the number of symbols currently alive across all holders, p is the per-symbol
survival probability (derived from holder commitment scores), and K_eff is the minimum
symbols required for decode.

The module is purely computational: no DB, no async, no network. All inputs are
assembled by the caller (daemon scheduler) from existing data structures.

### How it fits in the system

1. **Scheduler tick:** assembles `BlockReliabilityInput` per source block from
   `SymbolPlacement` records and commitment scores, calls `block_reliability`.
2. **`syncback status`:** calls `file_reliability` to show per-file survival probability.
3. **RepairAgent:** calls `per_holder_impact` to find single points of failure and
   prioritise repair targets.

---

## Dependencies

- `crate::types::{SourceBlockId, IdentityPub}` — identifiers only (no DB records here)
- `crate::constants::DECODE_OVERHEAD` — used in sanity checks
- `crate::commitment::CommitmentScore` — holder survival probability input
- No DB. No async. No network. No external probability crate.

---

## New Constants in `constants.rs`

Add the following after the commitment telemetry block:

```rust
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
```

---

## Types

Define these in `reliability/mod.rs`:

```rust
/// Input for per-holder data when computing block reliability.
/// The caller assembles this from SymbolPlacement + CommitmentScore.
#[derive(Debug, Clone)]
pub struct HolderReliabilityInput {
    pub holder_id: IdentityPub,
    /// Number of symbols this holder currently holds (alive, not Lost/Deleting).
    pub alive_symbols: u32,
    /// Estimated survival probability for this holder's symbols.
    /// Derived from CommitmentScore: p = 1.0 - eviction_risk(score).
    /// Caller uses `commitment::eviction_risk` to convert.
    /// Range: [0.0, 1.0].
    pub survival_prob: f64,
}

/// All inputs needed to compute reliability for one source block.
/// Assembled by the caller from DB records + commitment scores.
#[derive(Debug, Clone)]
pub struct BlockReliabilityInput {
    pub block_id: SourceBlockId,
    /// Minimum symbols needed for decode (K + DECODE_OVERHEAD).
    pub k_eff: u32,
    /// Per-holder data. Must include only holders with status Alive or Uncertain.
    /// Lost / Deleting / Offered holders should be excluded by the caller.
    pub holders: Vec<HolderReliabilityInput>,
}

/// Reliability summary for one source block.
#[derive(Debug, Clone)]
pub struct ReliabilityReport {
    pub block_id: SourceBlockId,
    /// P(block recoverable) in [0.0, 1.0].
    pub current_reliability: f64,
    /// Total alive symbols across all holders.
    pub symbols_alive: u32,
    /// Minimum symbols needed for decode.
    pub symbols_needed: u32,
    /// Impact of losing the weakest holder: reliability if they disappear.
    /// None if there are no holders.
    pub weakest_holder_impact: Option<WeakestHolderImpact>,
    /// True if current_reliability < RELIABILITY_REPAIR_THRESHOLD.
    pub needs_repair: bool,
}

/// Describes the most critical single holder for a source block.
#[derive(Debug, Clone)]
pub struct WeakestHolderImpact {
    pub holder_id: IdentityPub,
    /// Symbols held by this holder.
    pub symbols_held: u32,
    /// Reliability if this holder disappears.
    pub reliability_without: f64,
}

/// Error variants for the reliability module.
#[derive(Debug, thiserror::Error)]
pub enum ReliabilityError {
    #[error("k_eff must be > 0, got {0}")]
    InvalidKEff(u32),
    #[error("survival_prob out of range [0.0, 1.0]: {0}")]
    InvalidSurvivalProb(f64),
    #[error("alive_symbols overflow: sum exceeds u32::MAX")]
    SymbolCountOverflow,
}
```

---

## Public API

```rust
/// Compute P(Binomial(n, p) >= k) — the probability that at least k symbols
/// survive out of n distributed symbols, each surviving independently with
/// probability p.
///
/// This is the core reliability formula from docs/beta/raptorq.md.
///
/// Implementation strategy:
///   - n < BINOMIAL_EXACT_THRESHOLD: exact computation via CDF summation
///   - n >= BINOMIAL_EXACT_THRESHOLD: normal approximation with continuity correction
///
/// Edge cases:
///   - k == 0              → 1.0 (trivially satisfied)
///   - k > n               → exact binomial CDF (will be near 0 for low p)
///   - p == 0.0 and k > 0  → 0.0
///   - p == 1.0            → 1.0 (all symbols survive)
///   - n == 0 and k > 0    → 0.0
///
/// Returns Err(InvalidSurvivalProb) if p is outside [0.0, 1.0].
pub fn binomial_survival(n: u32, k: u32, p: f64) -> Result<f64, ReliabilityError>;

/// Compute the survival probability for a source block given its holder set.
///
/// The model treats each symbol independently: each holder contributes
/// `alive_symbols` independent symbols, each surviving with probability
/// `survival_prob`. Total alive = sum of alive_symbols across all holders.
/// Effective survival probability = weighted mean of per-holder survival_prob,
/// weighted by alive_symbols count.
///
/// Then: reliability = binomial_survival(total_alive, k_eff, weighted_mean_p)
///
/// Rationale for weighted mean: symbols held by a high-commitment holder are
/// more likely to survive. Weighting by symbol count correctly accounts for
/// how many symbols benefit from that holder's reliability.
///
/// Returns Err if k_eff == 0 or any holder has an invalid survival_prob.
pub fn block_reliability(input: &BlockReliabilityInput) -> Result<f64, ReliabilityError>;

/// Compute P(file recoverable) for a multi-block file.
///
/// P(file) = product of P(block_i) for each block.
///
/// For a file with one source block: returns that block's reliability.
/// For a file split across B source blocks: all blocks must be recoverable.
///
/// Empty slice → 1.0 (degenerate: no blocks needed = file is trivially present).
///
/// Each tuple is (alive_symbols, k_eff, avg_survival_prob) — the compact form
/// used when the caller has already aggregated per-block stats.
/// For callers with full BlockReliabilityInput, use block_reliability per block
/// and multiply the results.
///
/// Returns Err if any block has k_eff == 0 or invalid avg_survival_prob.
pub fn file_reliability(blocks: &[(u32, u32, f64)]) -> Result<f64, ReliabilityError>;

/// Compute the reliability of a block if a specific holder disappears.
///
/// Used to find single points of failure:
///   "If holder X leaves, what is the new reliability?"
///
/// Algorithm:
///   1. Remove holder's symbols from the total count.
///   2. Recompute weighted mean survival prob without that holder.
///   3. Call binomial_survival with the reduced inputs.
///
/// Returns Err if holder_id is not found in input.holders, or if k_eff == 0,
/// or if any holder has an invalid survival_prob.
pub fn per_holder_impact(
    input: &BlockReliabilityInput,
    holder_id: &IdentityPub,
) -> Result<f64, ReliabilityError>;

/// Build a full ReliabilityReport for a source block.
///
/// Steps:
///   1. Compute current_reliability via block_reliability.
///   2. Sum symbols_alive.
///   3. Find the weakest holder: the holder whose removal causes the largest
///      drop in reliability (highest delta between current and without-holder).
///      Ties broken by descending symbols_held, then by holder_id bytes.
///   4. Set needs_repair = current_reliability < RELIABILITY_REPAIR_THRESHOLD.
///
/// Returns Err on any invalid input (propagates from block_reliability /
/// per_holder_impact).
pub fn build_report(input: &BlockReliabilityInput) -> Result<ReliabilityReport, ReliabilityError>;

/// Convert a CommitmentScore to a per-symbol survival probability.
///
/// Bridges commitment telemetry → reliability forecast.
/// survival_prob = 1.0 - eviction_risk(score)
///               = 1.0 - (1.0 - score.value()^2)
///               = score.value()^2
///
/// Rationale: commitment::eviction_risk uses 1 - score^2. Inverting gives
/// p = score^2, which maps:
///   score=1.0 (fully committed) → p=1.0 (will survive)
///   score=0.5 (medium)         → p=0.25
///   score=0.0 (at-risk)        → p=0.0
///
/// This is intentionally pessimistic for low-commitment holders.
pub fn commitment_to_survival_prob(score: CommitmentScore) -> f64;
```

---

## Math: Binomial CDF Implementation

The binomial survival probability P(X >= k) where X ~ Binomial(n, p) is computed
as 1 - P(X <= k-1).

### Exact computation (n < BINOMIAL_EXACT_THRESHOLD = 100)

Use the direct CDF summation with log-space arithmetic to avoid overflow:

```
P(X <= k-1) = sum_{i=0}^{k-1} C(n, i) * p^i * (1-p)^(n-i)

// Compute using recurrence to avoid recomputing C(n,i) from scratch:
// term_0 = (1-p)^n
// term_{i+1} = term_i * (n-i) / (i+1) * p / (1-p)
```

Implementation outline:

```rust
fn binomial_cdf_exact(n: u32, k_minus_1: u32, p: f64) -> f64 {
    // P(X <= k_minus_1)
    let q = 1.0 - p;
    let mut term = q.powi(n as i32);  // P(X=0)
    let mut cdf = term;
    let ratio = p / q;
    for i in 0..k_minus_1 {
        term *= (n - i) as f64 / (i + 1) as f64 * ratio;
        cdf += term;
    }
    cdf.min(1.0)
}
```

Special cases before calling this:
- `p == 0.0`: return `if k == 0 { 1.0 } else { 0.0 }`
- `p == 1.0`: return `1.0`
- `k == 0`: return `1.0`
- `n == 0`: return `if k == 0 { 1.0 } else { 0.0 }`

### Normal approximation (n >= BINOMIAL_EXACT_THRESHOLD)

Use the normal approximation with continuity correction:

```
mean     = n * p
variance = n * p * (1 - p)
stddev   = sqrt(variance)

// P(X >= k) with continuity correction:
// P(X >= k) ≈ P(Z >= (k - 0.5 - mean) / stddev)
//           = 1 - Phi((k - 0.5 - mean) / stddev)

z = (k as f64 - 0.5 - mean) / stddev
P(X >= k) ≈ 1.0 - standard_normal_cdf(z)
```

Edge case: if variance is zero (p=0 or p=1), fall through to the exact special cases
above rather than dividing by zero.

### Standard normal CDF (rational approximation)

Implement Phi(z) using Abramowitz & Stegun formula 26.2.17 (maximum error 7.5e-8):

```rust
fn standard_normal_cdf(z: f64) -> f64 {
    // Phi(z) = P(Z <= z)
    // Use symmetry: Phi(z) = 1 - Phi(-z) for z < 0
    let x = z.abs();
    let t = 1.0 / (1.0 + 0.2316419 * x);
    let poly = t * (0.319381530
        + t * (-0.356563782
        + t * (1.781477937
        + t * (-1.821255978
        + t * 1.330274429))));
    let pdf = (-x * x / 2.0).exp() / std::f64::consts::TAU.sqrt();
    let upper_tail = pdf * poly;
    if z >= 0.0 {
        1.0 - upper_tail
    } else {
        upper_tail
    }
}
```

This gives sufficient accuracy for cold backup reliability estimates. No external
probability crate is needed or permitted.

---

## Business Rules

### Weighted mean survival probability

When a block has multiple holders with different symbol counts and survival
probabilities, the effective per-symbol survival probability is the count-weighted mean:

```
total_alive = sum(holder.alive_symbols for holder in holders)

if total_alive == 0:
    weighted_mean_p = 0.0
else:
    weighted_mean_p = sum(holder.alive_symbols * holder.survival_prob)
                      / total_alive
```

This models the system correctly: a symbol's survival probability depends on which
holder it is at. A holder with 1000 symbols and p=0.9 contributes more to average
reliability than a holder with 10 symbols and p=0.1.

### Multi-block file reliability

For files split across multiple source blocks, ALL blocks must be recoverable. So:

```
P(file) = P(block_1) * P(block_2) * ... * P(block_B)
```

This is the multiplicative rule for independent events. Chunks of a large file are
independent (different holders, different symbol sets). A 2 GB video split into 16
chunks has P(file) = P(chunk)^16 — which is why high per-block reliability matters
especially for large files.

### Weakest holder identification

The "weakest" holder is the one whose removal causes the largest absolute drop in
reliability:

```
for each holder H in input.holders:
    r_without_H = per_holder_impact(input, H.holder_id)
    delta_H = current_reliability - r_without_H

weakest = argmax(delta_H)
```

Ties (same delta) are broken by:
1. Descending symbols_held (more symbols = more critical in case of tie)
2. Ascending holder_id bytes (deterministic tiebreak)

If a holder has 0 alive_symbols, their impact delta is 0.0 — they cannot be the
weakest holder in a meaningful sense. Still include them in iteration but they will
never win the argmax against a real holder.

### needs_repair flag

```
needs_repair = current_reliability < RELIABILITY_REPAIR_THRESHOLD (0.99)
```

This is the advisory signal to RepairAgent. The threshold corresponds to "less than
two nines reliability" — below this, proactive repair is warranted regardless of
current PlacementStatus.

Note: RepairAgent may also trigger repair for other reasons (PresumedLost status,
commitment AtRisk). This flag is a reliability-based trigger independent of PoS
status.

### Handling PlacementStatus in inputs

The caller is responsible for filtering holders by status before building
`BlockReliabilityInput`. The rule:

| PlacementStatus | Include in reliability input? |
|-----------------|-------------------------------|
| Alive           | Yes, full symbol count        |
| Uncertain       | Yes, full symbol count (still holding, just missed PoS) |
| PresumedLost    | No (treat as lost for reliability purposes) |
| Lost            | No                            |
| Offered         | No (not confirmed held yet)   |
| Accepted        | No (transfer not complete)    |
| Deleting        | No                            |

The module does not enforce this — it operates on whatever `HolderReliabilityInput`
the caller provides. The caller must apply the above filter.

### Default survival probability fallback

When no commitment data is available (new holder, no PoS history), the caller should
use `DEFAULT_ANNUAL_CHURN_RATE = 0.30`, meaning `survival_prob = 0.70`. This is the
calibration point from the reliability table in `docs/beta/raptorq.md`.

The module does not apply this default internally — the caller sets `survival_prob`
explicitly. This keeps the module stateless and testable.

---

## DB Operations

None. This module has no DB dependency. The daemon scheduler assembles inputs from:

| `HolderReliabilityInput` field | Source |
|-------------------------------|--------|
| `holder_id`                   | `SymbolPlacement.holder_id` |
| `alive_symbols`               | `SymbolPlacement.symbol_count()` (filtered by status) |
| `survival_prob`               | `commitment_to_survival_prob(commitment::compute_commitment(profile)?)` |

The daemon integration point (informational, not implemented here):

```rust
// In scheduler tick (pseudocode, syncback/ crate):
for block in active_source_blocks {
    let placements = db.load_placements(block.id);
    let mut holders = Vec::new();
    for p in &placements {
        // Only include Alive and Uncertain holders
        if !matches!(p.status, PlacementStatus::Alive | PlacementStatus::Uncertain) {
            continue;
        }
        let profile = build_holder_profile(&p, &db, &trust_engine, now);
        let score = commitment::compute_commitment(&profile)?;
        holders.push(HolderReliabilityInput {
            holder_id: p.holder_id,
            alive_symbols: p.symbol_count(),
            survival_prob: reliability::commitment_to_survival_prob(score),
        });
    }
    let input = BlockReliabilityInput {
        block_id: block.block_id,
        k_eff: block.k + DECODE_OVERHEAD,
        holders,
    };
    let report = reliability::build_report(&input)?;
    if report.needs_repair {
        repair_agent.schedule(block.block_id);
    }
    // report.current_reliability → display in `syncback status`
}
```

---

## Test Scenarios

All tests go in `crates/syncback-core/src/reliability/tests.rs`.
Naming convention: `what_when_then`.

### Core math: binomial_survival

#### 1. `binomial_survival_k_zero_always_one`
```
binomial_survival(n=10, k=0, p=0.7)
→ Ok(1.0)
// trivially satisfied
```

#### 2. `binomial_survival_p_zero_k_positive_returns_zero`
```
binomial_survival(n=10, k=1, p=0.0)
→ Ok(0.0)
```

#### 3. `binomial_survival_p_one_returns_one`
```
binomial_survival(n=10, k=10, p=1.0)
→ Ok(1.0)
```

#### 4. `binomial_survival_n_zero_k_positive_returns_zero`
```
binomial_survival(n=0, k=1, p=0.7)
→ Ok(0.0)
```

#### 5. `binomial_survival_known_value_k5_n15_p07`

From the reliability table in `docs/beta/raptorq.md`:
K=5, N=15, p=0.7 → P(alive) = 99.93%

```
result = binomial_survival(n=15, k=5, p=0.7)
assert result.is_ok()
assert (result.unwrap() - 0.9993).abs() < 0.001
// Exact: sum_{i=5}^{15} C(15,i) * 0.7^i * 0.3^(15-i) ≈ 0.99927...
```

#### 6. `binomial_survival_known_value_k5_n10_p07`

From the table: K=5, N=10, overhead=2.0x, p=0.7 → 95.3%

```
result = binomial_survival(n=10, k=5, p=0.7)
assert (result.unwrap() - 0.953).abs() < 0.001
```

#### 7. `binomial_survival_known_value_k5_n20_p07`

From the table: K=5, N=20, overhead=4.0x, p=0.7 → 99.9994%

```
result = binomial_survival(n=20, k=5, p=0.7)
assert (result.unwrap() - 0.999994).abs() < 0.0001
```

#### 8. `binomial_survival_invalid_p_returns_error`
```
binomial_survival(n=10, k=5, p=1.5)
→ Err(ReliabilityError::InvalidSurvivalProb(1.5))

binomial_survival(n=10, k=5, p=-0.1)
→ Err(ReliabilityError::InvalidSurvivalProb(-0.1))
```

#### 9. `binomial_survival_k_greater_than_n`
```
// k > n: can only happen if 0 symbols survive but we need more than available
result = binomial_survival(n=3, k=5, p=0.7)
// P(Binomial(3, 0.7) >= 5) = 0.0 (impossible)
assert (result.unwrap() - 0.0).abs() < 1e-10
```

#### 10. `binomial_survival_exact_vs_normal_approx_agrees`

At the boundary (n=100), exact and normal should agree within 0.1%:

```
// Use n=99 (exact) and n=100 (normal approx) with same k/p
r_exact  = binomial_survival(n=99,  k=50, p=0.7).unwrap()
r_approx = binomial_survival(n=100, k=50, p=0.7).unwrap()
assert (r_exact - r_approx).abs() < 0.001
```

#### 11. `binomial_survival_large_n_normal_approx`

Test normal approximation path (n >= 100):

```
// K=200, N=480, overhead=2.4x, p=0.7 → table says ~99.999%
result = binomial_survival(n=480, k=200, p=0.7)
assert result.unwrap() > 0.9999
```

### block_reliability

#### 12. `block_reliability_single_holder_exact`

One holder, 15 alive symbols, k_eff=5, survival_prob=0.7:

```
input = BlockReliabilityInput {
    block_id: ...,
    k_eff: 5,
    holders: [HolderReliabilityInput { alive_symbols: 15, survival_prob: 0.7, ... }],
}
result = block_reliability(&input).unwrap()
assert (result - 0.9993).abs() < 0.001
// Same as binomial_survival(15, 5, 0.7)
```

#### 13. `block_reliability_empty_holders_below_k_eff`

No holders (total_alive = 0), k_eff = 5:

```
input = BlockReliabilityInput { k_eff: 5, holders: [], ... }
result = block_reliability(&input).unwrap()
assert result == 0.0
// P(Binomial(0, 0.0) >= 5) = 0
```

#### 14. `block_reliability_multiple_holders_weighted_mean`

Two holders with different commitment:
- Holder A: 10 symbols, survival_prob=0.9
- Holder B: 5 symbols, survival_prob=0.5
- total_alive = 15, k_eff = 5

Weighted mean p = (10 * 0.9 + 5 * 0.5) / 15 = (9.0 + 2.5) / 15 = 11.5 / 15 ≈ 0.7667

```
result = block_reliability(&input).unwrap()
// Should be binomial_survival(15, 5, 0.7667)
expected = binomial_survival(15, 5, 0.7667).unwrap()
assert (result - expected).abs() < 1e-9
```

#### 15. `block_reliability_invalid_k_eff_zero`

```
input = BlockReliabilityInput { k_eff: 0, holders: [...], ... }
→ Err(ReliabilityError::InvalidKEff(0))
```

#### 16. `block_reliability_invalid_survival_prob`

```
input with a holder having survival_prob = 1.5
→ Err(ReliabilityError::InvalidSurvivalProb(1.5))
```

### file_reliability

#### 17. `file_reliability_empty_blocks_returns_one`

```
file_reliability(&[])
→ Ok(1.0)
```

#### 18. `file_reliability_single_block`

```
file_reliability(&[(15, 5, 0.7)])
→ same as binomial_survival(15, 5, 0.7) ≈ 0.9993
```

#### 19. `file_reliability_two_blocks_multiply`

Two blocks, each with reliability R:
- Block 1: (15, 5, 0.7) → r1 ≈ 0.9993
- Block 2: (10, 5, 0.7) → r2 ≈ 0.953

```
result = file_reliability(&[(15, 5, 0.7), (10, 5, 0.7)]).unwrap()
expected = 0.9993 * 0.953
assert (result - expected).abs() < 0.001
```

#### 20. `file_reliability_large_file_many_blocks`

16-block video (each block 99.93% reliable):
P(file) = 0.9993^16 ≈ 0.9893

```
blocks: [(15, 5, 0.7); 16]
result = file_reliability(&blocks).unwrap()
assert (result - 0.9893).abs() < 0.005
```

#### 21. `file_reliability_one_degraded_block_drags_down`

If one block is at 50% reliability, the whole file is below 50%:

```
blocks: [(5, 5, 0.7), (5, 10, 0.7)]
// block 1: N=5, k_eff=5, p=0.7 → very low reliability (need all 5 to survive)
result = file_reliability(&blocks).unwrap()
// result < 0.5
assert result < 0.5
```

#### 22. `file_reliability_invalid_k_eff_zero_propagates`

```
file_reliability(&[(10, 0, 0.7)])
→ Err(ReliabilityError::InvalidKEff(0))
```

### per_holder_impact

#### 23. `per_holder_impact_only_holder_removes_all`

One holder with 15 symbols, k_eff=5:

```
result = per_holder_impact(&input, &holder_id).unwrap()
assert result == 0.0
// Without the only holder: total_alive = 0 → P(Binomial(0,p) >= 5) = 0
```

#### 24. `per_holder_impact_redundant_holder`

Two holders, A has 15 symbols, B has 3 symbols. k_eff=5.
Removing B leaves 15 symbols — still reliable:

```
r_without_b = per_holder_impact(&input, &holder_b_id).unwrap()
// binomial_survival(15, 5, weighted_mean_without_b)
assert r_without_b > 0.99
```

#### 25. `per_holder_impact_holder_not_found`

```
per_holder_impact(&input, &unknown_id)
// unknown_id not in input.holders
// DECISION NEEDED: return Err or treat as no-op?
// Spec: return Err with a new variant HolderNotFound.
→ Err(ReliabilityError::HolderNotFound(unknown_id))
```

Note: add `HolderNotFound(IdentityPub)` variant to `ReliabilityError`.

### build_report

#### 26. `build_report_healthy_block`

Input: 2 holders, total_alive=30, k_eff=5, survival_prob=0.9.

```
report = build_report(&input).unwrap()
assert report.symbols_alive == 30
assert report.symbols_needed == 5
assert report.current_reliability > 0.999
assert report.needs_repair == false
assert report.weakest_holder_impact.is_some()
```

#### 27. `build_report_degraded_block_needs_repair`

Only 6 alive symbols for k_eff=5, low survival_prob=0.5:
P(Binomial(6, 0.5) >= 5) is low.

```
input = BlockReliabilityInput {
    k_eff: 5,
    holders: [HolderReliabilityInput { alive_symbols: 6, survival_prob: 0.5 }],
}
report = build_report(&input).unwrap()
assert report.needs_repair == true
```

#### 28. `build_report_weakest_holder_is_largest`

Two holders: A has 12 symbols (p=0.8), B has 3 symbols (p=0.8). k_eff=10.
Removing A leaves only 3 — catastrophic. B is less critical.

```
report = build_report(&input).unwrap()
assert report.weakest_holder_impact.unwrap().holder_id == holder_a_id
assert report.weakest_holder_impact.unwrap().symbols_held == 12
```

#### 29. `build_report_no_holders`

```
input = BlockReliabilityInput { k_eff: 5, holders: [], ... }
report = build_report(&input).unwrap()
assert report.symbols_alive == 0
assert report.current_reliability == 0.0
assert report.needs_repair == true
assert report.weakest_holder_impact.is_none()
```

### commitment_to_survival_prob

#### 30. `commitment_to_survival_prob_full_score`

```
score = CommitmentScore::new(1.0)
commitment_to_survival_prob(score) == 1.0
```

#### 31. `commitment_to_survival_prob_zero_score`

```
score = CommitmentScore::new(0.0)
commitment_to_survival_prob(score) == 0.0
```

#### 32. `commitment_to_survival_prob_midpoint`

```
score = CommitmentScore::new(0.5)
result = commitment_to_survival_prob(score)
assert (result - 0.25).abs() < 1e-9
// score^2 = 0.25
```

#### 33. `commitment_to_survival_prob_default_churn`

The default churn scenario (30% annual): a "typical" peer with
commitment score such that p ≈ 0.7:

```
// commitment_to_survival_prob(score) = score^2 = 0.7
// score = sqrt(0.7) ≈ 0.8367
score = CommitmentScore::new(0.7_f64.sqrt())
result = commitment_to_survival_prob(score)
assert (result - 0.7).abs() < 1e-6
```

#### 34. `survival_prob_round_trips_commitment`

Verify the formula is consistent with eviction_risk:

```
// survival_prob should equal 1.0 - eviction_risk(score)
use crate::commitment::eviction_risk;
for score_val in [0.0, 0.3, 0.5, 0.7, 0.9, 1.0] {
    let score = CommitmentScore::new(score_val);
    let sp = commitment_to_survival_prob(score);
    let er = eviction_risk(score);
    assert ((sp + er) - 1.0).abs() < 1e-9;
}
```

---

## Module Structure

```
crates/syncback-core/src/reliability/
    mod.rs      — all types, public functions, private math helpers
    tests.rs    — all 34 test scenarios above
```

Add to `crates/syncback-core/src/lib.rs`:

```rust
pub mod reliability;
```

Add to `crates/syncback-core/src/constants.rs` (after the commitment telemetry block):

```rust
// === Reliability forecast ===

pub const DEFAULT_ANNUAL_CHURN_RATE: f64 = 0.30;
pub const RELIABILITY_REPAIR_THRESHOLD: f64 = 0.99;
pub const BINOMIAL_EXACT_THRESHOLD: u32 = 100;
```

---

## Internal module structure (non-public helpers)

Keep all math helpers private to the module. The public surface is intentionally
minimal. Private functions to implement:

```rust
// Private helpers — do NOT pub
fn binomial_cdf_exact(n: u32, k_minus_1: u32, p: f64) -> f64;
fn binomial_survival_normal_approx(n: u32, k: u32, p: f64) -> f64;
fn standard_normal_cdf(z: f64) -> f64;
fn weighted_mean_survival(holders: &[HolderReliabilityInput]) -> (u32, f64);
// Returns (total_alive, weighted_mean_p)
```

---

## DECISION NEEDED

1. `per_holder_impact` when holder_id is not found in input.holders: the spec above
   returns `Err(ReliabilityError::HolderNotFound(unknown_id))`. This requires adding
   a `HolderNotFound(IdentityPub)` variant to `ReliabilityError`. An alternative is
   to panic (programmer error, not runtime). Current spec: return Err (graceful).
   Add the variant:
   ```rust
   #[error("holder {0} not found in block input")]
   HolderNotFound(IdentityPub),
   ```

2. `IdentityPub` does not implement `Display` in `types/mod.rs` (it implements
   `fmt::Display` showing 8 hex bytes). The `HolderNotFound` error variant uses
   `{0}` formatting. This is already supported by the existing `Display` impl.
   No changes needed.

---

## What NOT to do

- Do not add an external `statrs`, `rand`, or other probability/statistics crate.
  The normal CDF rational approximation is sufficient for 2-3 significant figures.
- Do not store state — all functions are pure and deterministic.
- Do not access the DB inside this module.
- Do not call `commitment::compute_commitment` inside this module — the caller
  converts commitment scores to survival probabilities before building inputs.
  `commitment_to_survival_prob` is a pure conversion helper, not a pipeline stage.
- Do not use `anyhow` — use `thiserror` per-module error type.
- Do not add `tracing` calls — this is `syncback-core`, logging belongs in the daemon.
- Do not add `#[cfg(test)]` inline — all tests go in `tests.rs`.

---

## Files to Create/Modify

1. `/home/ilya/projects/syncback/crates/syncback-core/src/reliability/mod.rs`
   — New file: all types, public API, private math helpers

2. `/home/ilya/projects/syncback/crates/syncback-core/src/reliability/tests.rs`
   — New file: all 34 test scenarios

3. `/home/ilya/projects/syncback/crates/syncback-core/src/lib.rs`
   — Add `pub mod reliability;`

4. `/home/ilya/projects/syncback/crates/syncback-core/src/constants.rs`
   — Add 3 new constants in the reliability forecast block

---

## Definition of Done

- `cargo test -p syncback-core` passes with no failures
- `cargo clippy -p syncback-core -- -D warnings` clean
- All 34 test scenarios present and passing in `reliability/tests.rs`
- The known-value tests (scenarios 5, 6, 7) pass against the table in raptorq.md
- `binomial_survival` uses exact computation for n < 100, normal approximation for n >= 100
- No external probability crate added to `syncback-core/Cargo.toml`
- `ReliabilityReport`, `WeakestHolderImpact`, `BlockReliabilityInput`,
  `HolderReliabilityInput`, `ReliabilityError` exported from `reliability/mod.rs`
- All public functions have doc comments
- No inline `#[cfg(test)]` — tests exclusively in `tests.rs`
