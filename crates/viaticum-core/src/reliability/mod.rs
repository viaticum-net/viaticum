// Reliability forecast: P(file or source block is recoverable in the future).
// Pure computation — no DB, no async, no network.
// All inputs are assembled by the caller (daemon scheduler) from DB records
// and commitment scores.
//
// Core model (holder-correlated, see `correlated_recovery_prob`):
//   P(block alive) = P( Σ_{i : holder i survives} sᵢ  >=  K_eff )
//
// Each holder is alive-or-dead as a unit (all its sᵢ symbols survive together
// with probability pᵢ); the block is recoverable iff the surviving holders hold
// >= K_eff distinct symbols. ESI ranges are disjoint across holders (watermark),
// so surviving holders' symbols sum as distinct. `binomial_survival` is retained
// as the per-symbol special case (all sᵢ = 1) and for the pre-placement N-solver.

use crate::commitment::{CommitmentScore, eviction_risk};
use crate::constants::{
    BINOMIAL_EXACT_THRESHOLD, MAX_OVERHEAD_FACTOR, MIN_REDUNDANCY, RELIABILITY_REPAIR_THRESHOLD,
};
use crate::types::{DeviceId, SourceBlockId};

#[cfg(test)]
mod tests;

// ============================================================
// Input types
// ============================================================

/// Input for per-holder data when computing block reliability.
/// The caller assembles this from SymbolPlacement + CommitmentScore.
#[derive(Debug, Clone)]
pub struct HolderReliabilityInput {
    pub holder_id: DeviceId,
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

// ============================================================
// Output types
// ============================================================

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
    pub holder_id: DeviceId,
    /// Symbols held by this holder.
    pub symbols_held: u32,
    /// Reliability if this holder disappears.
    pub reliability_without: f64,
}

// ============================================================
// Errors
// ============================================================

/// Error variants for the reliability module.
#[derive(Debug, thiserror::Error)]
pub enum ReliabilityError {
    #[error("k_eff must be > 0, got {0}")]
    InvalidKEff(u32),
    #[error("survival_prob out of range [0.0, 1.0]: {0}")]
    InvalidSurvivalProb(f64),
    #[error("alive_symbols overflow: sum exceeds u32::MAX")]
    SymbolCountOverflow,
    #[error("holder {0} not found in block input")]
    HolderNotFound(DeviceId),
    #[error("holders slice is empty; cannot compute weighted mean trust")]
    EmptyHolderSlice,
}

// ============================================================
// Public API
// ============================================================

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
pub fn binomial_survival(n: u32, k: u32, p: f64) -> Result<f64, ReliabilityError> {
    if !(0.0..=1.0).contains(&p) {
        return Err(ReliabilityError::InvalidSurvivalProb(p));
    }

    // Trivial edge cases that bypass the CDF.
    if k == 0 {
        return Ok(1.0);
    }
    if n == 0 {
        return Ok(0.0);
    }
    if p == 0.0 {
        return Ok(0.0);
    }
    if p == 1.0 {
        return Ok(1.0);
    }

    // k > n: impossible to get k successes from n trials with p in (0,1).
    if k > n {
        // Fall through to exact — the loop will sum all terms 0..n which
        // is less than k, so P(X >= k) = 0. But we can short-circuit here.
        return Ok(0.0);
    }

    if n < BINOMIAL_EXACT_THRESHOLD {
        let cdf = binomial_cdf_exact(n, k - 1, p);
        Ok((1.0 - cdf).max(0.0))
    } else {
        Ok(binomial_survival_normal_approx(n, k, p))
    }
}

/// Holder-correlated recovery probability for a block.
///
/// Each holder either survives — all of its `sᵢ` symbols present at once — or
/// dies (all gone), surviving independently with probability `pᵢ`. The block is
/// recoverable iff the surviving holders together hold ≥ `k_eff` *distinct*
/// symbols. ESI ranges are disjoint across holders (guaranteed by the placement
/// watermark), so surviving holders' symbols sum as distinct.
///
/// Computed exactly by a DP convolution over holders, capping the running
/// "surviving symbol count" at `k_eff` (anything ≥ k_eff is already enough):
///
/// ```text
/// dist[0] = 1
/// for (s, p) in holders:
///     new[x]               += dist[x] · (1−p)          // holder dies
///     new[min(x+s, k_eff)] += dist[x] · p              // holder survives
/// R = dist[k_eff]
/// ```
///
/// Cost: O(H · k_eff), H ≤ MAX_HOLDERS_PER_BLOCK → trivial.
///
/// Degenerate cases (sanity-checked in tests):
///   - all sᵢ = 1             → R = P(Binomial-like ≥ k_eff) (per-symbol model)
///   - all sᵢ = k_eff         → R = 1 − Π(1−pᵢ) (replica model; any one holder recovers)
///   - k_eff == 0             → R = 1.0 (trivially recoverable)
///   - empty holders, k_eff>0 → R = 0.0
///
/// Each tuple is `(alive_symbols, survival_prob)`.
/// Returns Err(InvalidSurvivalProb) if any `survival_prob` is outside [0.0, 1.0].
pub fn correlated_recovery_prob(
    holders: &[(u32, f64)],
    k_eff: u32,
) -> Result<f64, ReliabilityError> {
    for &(_, p) in holders {
        if !(0.0..=1.0).contains(&p) {
            return Err(ReliabilityError::InvalidSurvivalProb(p));
        }
    }

    // dist[x] = P(surviving holders so far hold exactly x distinct symbols),
    // with x capped at k_eff (≥ k_eff is lumped into the top bucket — already enough).
    let cap = k_eff as usize;
    let mut dist = vec![0.0f64; cap + 1];
    dist[0] = 1.0;

    for &(s, p) in holders {
        let q = 1.0 - p;
        let s = (s as usize).min(cap);
        let mut next = vec![0.0f64; cap + 1];
        for (x, &mass) in dist.iter().enumerate() {
            if mass == 0.0 {
                continue;
            }
            next[x] += mass * q; // holder dies → 0 symbols added
            next[(x + s).min(cap)] += mass * p; // holder survives → +s (capped)
        }
        dist = next;
    }

    Ok(dist[cap])
}

/// Compute the survival probability for a source block given its holder set.
///
/// Holder-correlated model (see `correlated_recovery_prob`): each holder is
/// alive-or-dead as a unit, and the block is recoverable iff surviving holders
/// together hold ≥ k_eff distinct symbols. A single holder with ≥ k_eff symbols
/// therefore yields exactly its own survival probability `p`.
///
/// Returns Err if k_eff == 0 or any holder has an invalid survival_prob.
pub fn block_reliability(input: &BlockReliabilityInput) -> Result<f64, ReliabilityError> {
    if input.k_eff == 0 {
        return Err(ReliabilityError::InvalidKEff(0));
    }

    let holders: Vec<(u32, f64)> = input
        .holders
        .iter()
        .map(|h| (h.alive_symbols, h.survival_prob))
        .collect();
    correlated_recovery_prob(&holders, input.k_eff)
}

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
pub fn file_reliability(blocks: &[(u32, u32, f64)]) -> Result<f64, ReliabilityError> {
    let mut product = 1.0_f64;
    for &(alive_symbols, k_eff, avg_survival_prob) in blocks {
        if k_eff == 0 {
            return Err(ReliabilityError::InvalidKEff(0));
        }
        let r = binomial_survival(alive_symbols, k_eff, avg_survival_prob)?;
        product *= r;
    }
    Ok(product)
}

/// Compute the reliability of a block if a specific holder disappears.
///
/// Used to find single points of failure:
///   "If holder X leaves, what is the new reliability?"
///
/// Algorithm: drop the named holder, then recompute the holder-correlated
/// recovery probability over the remaining holders.
///
/// Returns Err if holder_id is not found in input.holders, or if k_eff == 0,
/// or if any holder has an invalid survival_prob.
pub fn per_holder_impact(
    input: &BlockReliabilityInput,
    holder_id: &DeviceId,
) -> Result<f64, ReliabilityError> {
    if input.k_eff == 0 {
        return Err(ReliabilityError::InvalidKEff(0));
    }

    if !input.holders.iter().any(|h| &h.holder_id == holder_id) {
        return Err(ReliabilityError::HolderNotFound(*holder_id));
    }

    let reduced: Vec<(u32, f64)> = input
        .holders
        .iter()
        .filter(|h| &h.holder_id != holder_id)
        .map(|h| (h.alive_symbols, h.survival_prob))
        .collect();
    correlated_recovery_prob(&reduced, input.k_eff)
}

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
pub fn build_report(input: &BlockReliabilityInput) -> Result<ReliabilityReport, ReliabilityError> {
    let current_reliability = block_reliability(input)?;

    let symbols_alive = input.holders.iter().try_fold(0u32, |acc, h| {
        acc.checked_add(h.alive_symbols)
            .ok_or(ReliabilityError::SymbolCountOverflow)
    })?;

    let weakest_holder_impact = if input.holders.is_empty() {
        None
    } else {
        let mut best: Option<(f64, u32, DeviceId, f64)> = None;
        // Track (delta, symbols_held, holder_id, reliability_without)
        // Larger delta = weaker (more critical).

        for holder in &input.holders {
            let r_without = per_holder_impact(input, &holder.holder_id)?;
            let delta = current_reliability - r_without;

            let is_better = match &best {
                None => true,
                Some((best_delta, best_symbols, best_id, _)) => {
                    if (delta - best_delta).abs() > f64::EPSILON {
                        delta > *best_delta
                    } else if holder.alive_symbols != *best_symbols {
                        holder.alive_symbols > *best_symbols
                    } else {
                        // Ascending holder_id bytes (lower bytes = wins tiebreak)
                        holder.holder_id.0 < best_id.0
                    }
                }
            };

            if is_better {
                best = Some((delta, holder.alive_symbols, holder.holder_id, r_without));
            }
        }

        best.map(
            |(_, symbols_held, holder_id, reliability_without)| WeakestHolderImpact {
                holder_id,
                symbols_held,
                reliability_without,
            },
        )
    };

    let needs_repair = current_reliability < RELIABILITY_REPAIR_THRESHOLD;

    Ok(ReliabilityReport {
        block_id: input.block_id,
        current_reliability,
        symbols_alive,
        symbols_needed: input.k_eff,
        weakest_holder_impact,
        needs_repair,
    })
}

/// Convert a CommitmentScore to a per-symbol survival probability.
///
/// Bridges commitment telemetry → reliability forecast. Two independent channels
/// must BOTH hold for our data to survive the repair horizon:
///
/// - behavioural: the holder keeps storing honestly — `1 - eviction_risk(score) = score²`;
/// - physical: the node doesn't involuntarily vanish (disk/fire/theft/ISP/departure) —
///   capped by `BASELINE_HOLDER_SURVIVAL`, independent of trust.
///
/// survival_prob = BASELINE_HOLDER_SURVIVAL × score²
///
///   score=1.0 (fully committed) → p = 0.90  (NOT 1.0 — no node is a certainty)
///   score=0.5 (medium)          → p = 0.225
///   score=0.0 (at-risk)         → p = 0.0
///
/// The trust ceiling is what makes the placement solver build real replication for
/// critical/few-holder blocks instead of a thin spread that assumed immortal holders.
/// Intentionally pessimistic (under-estimating p over-places — the safe direction).
pub fn commitment_to_survival_prob(score: CommitmentScore) -> f64 {
    crate::constants::BASELINE_HOLDER_SURVIVAL * (1.0 - eviction_risk(score))
}

// ============================================================
// Pre-placement solver types
// ============================================================

/// Minimal holder descriptor for pre-placement N computation.
///
/// Used by `solve_n_for_target` and `weighted_mean_trust`. Contains only the
/// information needed by the N-solver: the estimated survival probability of
/// each pool candidate.
///
/// Distinct from `HolderReliabilityInput` (post-placement, tracks alive symbols
/// and holder identity). This type is deliberately minimal — no `holder_id`
/// field because the solver does not use identity.
///
/// Callers derive `survival_prob` via `commitment_to_survival_prob(score)`.
#[derive(Debug, Clone)]
pub struct HolderCandidate {
    /// Estimated probability that this holder's symbols survive over the
    /// relevant time horizon. Derived from `CommitmentScore`.
    /// Range: [0.0, 1.0].
    pub survival_prob: f64,
}

// ============================================================
// Public API: target_reliability
// ============================================================

/// Compute the target reliability for a source block given its importance.
///
/// Returns P(block survives) that the system aims to achieve, as a function of
/// how important the data is. Uses the smooth formula from R8:
///
///   target_p = 1 - 10^(-(0.3 + importance × 4.7))
///
/// Anchor table (from unified_work_pipeline.md §R8):
/// | importance | target_p  |
/// |------------|-----------|
/// | 0.00       | ≈ 0.499   |
/// | 0.05       | ≈ 0.71    |
/// | 0.20       | ≈ 0.94    |
/// | 0.65       | ≈ 0.9996  |
/// | 0.95       | ≈ 0.99998 |
/// | 1.00       | = 0.99999 |
///
/// # Clamping
///
/// `importance` is clamped to [0.0, 1.0] before applying the formula.
/// Callers are expected to pass already-clamped values, but defensive
/// clamping is applied for safety.
///
/// # Range
///
/// Always returns a value in [0.499, 0.99999]. Never returns NaN or infinity.
pub fn target_reliability(importance: f64) -> f64 {
    let imp = importance.clamp(0.0, 1.0);
    let log10_failure = -(0.3 + imp * 4.7);
    1.0 - 10f64.powf(log10_failure)
}

/// True if `current` reliability meets `target`, compared in failure-probability
/// space with a relative tolerance: `(1 - current) <= (1 - target) * (1 + TOL)`.
///
/// The single definition of "at target" for the whole system (worker selection,
/// `is_safe_to_delete`, importance-bucket status, placement solver). Raw `>=` on
/// reliabilities is forbidden outside this function: e.g. five full copies at
/// p = 0.9 are exactly at target 1-1e-5 mathematically but compute to
/// 0.9999899999999999 < 0.99999 in f64.
///
/// Why failure space: targets are set in "nines", so the meaningful quantity is the
/// ratio of failure probabilities. For `current ∈ [0.5, 1]` the subtraction
/// `1 - current` is exact (Sterbenz), so the tolerance absorbs the DP's rounding
/// instead of adding its own.
///
/// NaN in either argument → false (treated as "not at target", as before).
/// `target <= 0.0` is NOT special-cased here (callers keep their sentinel checks).
pub fn meets_target(current: f64, target: f64) -> bool {
    let fail_current = 1.0 - current;
    let fail_target = 1.0 - target;
    fail_current <= fail_target * (1.0 + crate::constants::RELIABILITY_TARGET_REL_TOL)
}

// ============================================================
// Public API: solve_n_for_target
// ============================================================

/// Find the smallest N such that `binomial_survival(N, k_eff, mean_p)` meets `target_p`
/// (see [`meets_target`]).
///
/// Uses the pool's equal-weight mean survival probability (`weighted_mean_trust`)
/// as the per-symbol survival proxy. Searches N in the range
/// `[k_eff + MIN_REDUNDANCY, k_eff * MAX_OVERHEAD_FACTOR]`.
///
/// # Returns
///
/// - `Ok(n)` where n is the smallest satisfying N, or `Ok(k_eff * MAX_OVERHEAD_FACTOR)`
///   if the target is unachievable within the overhead cap. Callers can detect
///   the capped case by comparing `n == k_eff * MAX_OVERHEAD_FACTOR`.
/// - `Err(EmptyHolderSlice)` if `holders` is empty.
/// - `Err(InvalidKEff(0))` if `k_eff == 0`.
/// - `Err(InvalidSurvivalProb(...))` if any `holder.survival_prob` is outside [0.0, 1.0].
///
/// # Caller contract
///
/// The returned N is a suggestion for initial block construction. After N is chosen
/// and `compute_allocation` runs, the actual holder assignments may differ from the
/// uniform-trust model used here. The caller is responsible for re-evaluating
/// `block_reliability` once placements are live.
///
/// # Why Ok(max_n) instead of Err for unachievable target?
///
/// An unreachable target is a normal operational condition (small / low-trust pool).
/// Returning `Ok(max_n)` lets the caller use best-effort N and decide independently
/// whether to defer or proceed. An Err would require every call site to handle a
/// non-exceptional condition as an exception.
pub fn solve_n_for_target(
    k_eff: u32,
    holders: &[HolderCandidate],
    target_p: f64,
) -> Result<u32, ReliabilityError> {
    if k_eff == 0 {
        return Err(ReliabilityError::InvalidKEff(0));
    }
    if holders.is_empty() {
        return Err(ReliabilityError::EmptyHolderSlice);
    }

    let mean_p = weighted_mean_trust(holders)?;
    let min_n = k_eff + MIN_REDUNDANCY;
    let max_n = k_eff * MAX_OVERHEAD_FACTOR;

    for n in min_n..=max_n {
        if meets_target(binomial_survival(n, k_eff, mean_p)?, target_p) {
            return Ok(n);
        }
    }

    // Target unachievable within overhead cap — return cap, caller checks.
    Ok(max_n)
}

// ============================================================
// Public API: solve_placement_for_target (holder-correlated)
// ============================================================

/// A holder-correlated placement plan: how many symbols each pool candidate gets.
#[derive(Debug, Clone, PartialEq)]
pub struct PlacementPlan {
    /// Symbols assigned to each input candidate, index-aligned with the `holders`
    /// slice passed to `solve_placement_for_target`. `0` = candidate unused.
    pub per_holder: Vec<u32>,
    /// True if the achieved holder-correlated reliability meets `target_p`
    /// ([`meets_target`]).
    /// False = best-effort placement under the limits (caller flags under-target).
    pub reached_target: bool,
}

/// Greedily choose a holder-correlated placement that reaches `target_p` with as
/// few symbols as possible, within the given limits.
///
/// At each step it adds the single symbol that most raises the correlated recovery
/// probability (`correlated_recovery_prob`) — to a *fresh* holder (diversity) or an
/// existing partial holder (concentration), whichever raises R more. The shape is
/// therefore **emergent**, not configured: few holders → full copies (replicas),
/// many holders → thin spread. On the R=0 plateau (total symbols < k_eff, no
/// surviving combination can decode yet) all single increments tie at ΔR=0; the
/// tiebreak prefers opening a new holder, so spread builds where the pool allows.
///
/// Limits:
///   - per holder ≤ `k_eff` — a full copy already decodes; more is pure waste,
///   - at most `max_holders` distinct holders used,
///   - at most `k_eff × max_overhead` symbols in total.
///
/// Stops when R meets `target_p` per [`meets_target`] (`reached_target = true`) or no legal increment
/// remains; on a small/weak pool it returns a best-effort plan with
/// `reached_target = false` rather than erroring (DR doctrine: defer-not-refuse).
///
/// `target_p` is clamped to [0,1]. Returns `Err(InvalidKEff(0))` if `k_eff == 0`,
/// `Err(InvalidSurvivalProb)` for an out-of-range candidate.
///
/// Cost: greedy single-symbol; each step re-evaluates the O(H·k_eff) DP per
/// candidate. Bounded by `min(max_holders, H)·k_eff` placed symbols. Cheap for the
/// small/moderate `k_eff` where replica-vs-spread matters; callers should gate very
/// large `k_eff` blocks (which are erasure-spread regardless) to the weight-based path.
pub fn solve_placement_for_target(
    k_eff: u32,
    holders: &[HolderCandidate],
    target_p: f64,
    max_holders: usize,
    max_overhead: u32,
) -> Result<PlacementPlan, ReliabilityError> {
    if k_eff == 0 {
        return Err(ReliabilityError::InvalidKEff(0));
    }
    for h in holders {
        if !(0.0..=1.0).contains(&h.survival_prob) {
            return Err(ReliabilityError::InvalidSurvivalProb(h.survival_prob));
        }
    }

    let target_p = target_p.clamp(0.0, 1.0);
    let n_holders = holders.len();
    let max_total = (k_eff as u64).saturating_mul(max_overhead as u64);
    let mut per_holder = vec![0u32; n_holders];

    // R for the current placement (probs already validated → unwrap is safe).
    let recovery = |per: &[u32]| -> f64 {
        let pairs: Vec<(u32, f64)> = per
            .iter()
            .zip(holders.iter())
            .filter(|&(&s, _)| s > 0)
            .map(|(&s, h)| (s, h.survival_prob))
            .collect();
        correlated_recovery_prob(&pairs, k_eff).unwrap_or(0.0)
    };

    let mut current_r = recovery(&per_holder);

    // Phase A — SPREAD: open fresh holders one symbol each, strongest first, until
    // R reaches target or we run out of holders / budget. Spreading 1-each is the
    // symbol-cheapest way to raise correlated recovery while distinct holders remain
    // (each adds an independent survival path), so "many holders → thin spread"
    // falls out naturally. Note: on a highly heterogeneous pool (a few strong + many
    // near-zero holders) spreading onto weak holders can underperform deepening the
    // strong ones — acceptable for the curated, trust-filtered candidate pool;
    // revisit only if measurements show waste (design open question).
    let mut order: Vec<usize> = (0..n_holders).collect();
    order.sort_by(|&a, &b| {
        holders[b]
            .survival_prob
            .partial_cmp(&holders[a].survival_prob)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.cmp(&b))
    });
    // `take(max_holders)` opens at most `max_holders` distinct holders (one per
    // non-broken iteration), so no separate counter is needed.
    for &idx in order.iter().take(max_holders) {
        if meets_target(current_r, target_p) {
            break;
        }
        let total: u64 = per_holder.iter().map(|&s| s as u64).sum();
        if total >= max_total {
            break;
        }
        per_holder[idx] = 1;
        current_r = recovery(&per_holder);
    }

    // Phase B — DEEPEN: with no fresh holders left, thicken the opened holders'
    // erasure shares *uniformly* (up to k_eff each) until R reaches target. This is
    // what makes the shape track k_eff vs holder count: with a large k_eff and few
    // holders it grows balanced erasure shares (~k_eff/m each, far cheaper than full
    // copies); with a small k_eff it fills holders to k_eff, which is replicas.
    //
    // A per-symbol greedy here would be O(total · H² · k_eff) — far too slow for
    // production k_eff (~2000 for a 128 MiB block). Instead: R is monotonic in the
    // total symbol count T under an even split, so binary-search the smallest T whose
    // even split reaches target. O(log(H·k_eff) · H·k_eff). Equivalent to the
    // emptier-first per-symbol deepen (both keep holder counts within 1 of each other).
    if !meets_target(current_r, target_p) {
        let opened: Vec<usize> = order
            .iter()
            .copied()
            .filter(|&i| per_holder[i] > 0)
            .collect();
        let h = opened.len() as u64;
        if h > 0 {
            // Even split of T symbols across the opened holders (strongest take the
            // remainder); capped at k_eff each (guaranteed by T ≤ h·k_eff).
            let apply_even = |per: &mut [u32], t: u64| {
                let base = (t / h) as u32;
                let rem = (t % h) as u32;
                for (rank, &idx) in opened.iter().enumerate() {
                    per[idx] = base + u32::from((rank as u64) < rem as u64);
                }
            };

            let lo_t = h; // current state: 1 symbol each
            let hi_t = (h * k_eff as u64).min(max_total);

            apply_even(&mut per_holder, hi_t);
            if !meets_target(recovery(&per_holder), target_p) {
                // Unreachable even at the cap — keep the best-effort max placement.
                current_r = recovery(&per_holder);
            } else {
                let mut lo = lo_t;
                let mut hi = hi_t;
                while lo < hi {
                    let mid = lo + (hi - lo) / 2;
                    apply_even(&mut per_holder, mid);
                    if meets_target(recovery(&per_holder), target_p) {
                        hi = mid;
                    } else {
                        lo = mid + 1;
                    }
                }
                apply_even(&mut per_holder, lo);
                current_r = recovery(&per_holder);
            }
        }
    }

    Ok(PlacementPlan {
        reached_target: meets_target(current_r, target_p),
        per_holder,
    })
}

// ============================================================
// pub(crate) helper: weighted_mean_trust
// ============================================================

/// Compute the equal-weight arithmetic mean of `survival_prob` across all holders.
///
/// Used by `solve_n_for_target` before symbol allocation, when per-holder symbol
/// counts are not yet known. Equal weighting is the only well-defined choice at
/// this stage.
///
/// Returns `Err(EmptyHolderSlice)` if `holders` is empty.
/// Returns `Err(InvalidSurvivalProb)` if any holder has `survival_prob` outside [0.0, 1.0].
pub(crate) fn weighted_mean_trust(holders: &[HolderCandidate]) -> Result<f64, ReliabilityError> {
    if holders.is_empty() {
        return Err(ReliabilityError::EmptyHolderSlice);
    }
    let mut sum = 0.0f64;
    for h in holders {
        if !(0.0..=1.0).contains(&h.survival_prob) {
            return Err(ReliabilityError::InvalidSurvivalProb(h.survival_prob));
        }
        sum += h.survival_prob;
    }
    Ok(sum / holders.len() as f64)
}

// ============================================================
// Private math helpers
// ============================================================

/// Compute P(X <= k_minus_1) where X ~ Binomial(n, p).
/// Uses recurrence relation to avoid recomputing C(n,i) from scratch.
/// Preconditions: p in (0, 1), n > 0, k_minus_1 < n.
fn binomial_cdf_exact(n: u32, k_minus_1: u32, p: f64) -> f64 {
    let q = 1.0 - p;
    // term_0 = P(X=0) = q^n
    let mut term = q.powi(n as i32);
    let mut cdf = term;
    let ratio = p / q;

    for i in 0..k_minus_1 {
        // term_{i+1} = term_i * (n - i) / (i + 1) * (p / q)
        term *= (n - i) as f64 / (i + 1) as f64 * ratio;
        cdf += term;
    }

    cdf.min(1.0)
}

/// Normal approximation of P(X >= k) with continuity correction.
/// For n >= BINOMIAL_EXACT_THRESHOLD.
/// Preconditions: p in (0, 1), n > 0, k >= 1.
fn binomial_survival_normal_approx(n: u32, k: u32, p: f64) -> f64 {
    let mean = n as f64 * p;
    let variance = n as f64 * p * (1.0 - p);

    if variance == 0.0 {
        // Degenerate: p=0 or p=1 handled by caller.
        return if (k as f64) <= mean { 1.0 } else { 0.0 };
    }

    let stddev = variance.sqrt();
    // P(X >= k) with continuity correction: P(Z >= (k - 0.5 - mean) / stddev)
    let z = (k as f64 - 0.5 - mean) / stddev;
    (1.0 - standard_normal_cdf(z)).max(0.0)
}

/// Standard normal CDF: Phi(z) = P(Z <= z).
/// Abramowitz & Stegun formula 26.2.17, max error 7.5e-8.
fn standard_normal_cdf(z: f64) -> f64 {
    let x = z.abs();
    let t = 1.0 / (1.0 + 0.2316419 * x);
    let poly = t
        * (0.319_381_530
            + t * (-0.356_563_782
                + t * (1.781_477_937 + t * (-1.821_255_978 + t * 1.330_274_429))));
    let pdf = (-x * x / 2.0).exp() / std::f64::consts::TAU.sqrt();
    let upper_tail = pdf * poly;
    if z >= 0.0 {
        1.0 - upper_tail
    } else {
        upper_tail
    }
}
