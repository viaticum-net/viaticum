// Reliability forecast: P(file or source block is recoverable in the future).
// Pure computation — no DB, no async, no network.
// All inputs are assembled by the caller (daemon scheduler) from DB records
// and commitment scores.
//
// Core formula (from docs/beta/raptorq.md):
//   P(block alive) = P(Binomial(N, p) >= K_eff)
//
// where N = total alive symbols across all holders,
//       p = weighted mean per-symbol survival probability,
//   K_eff = minimum symbols required for decode.

use crate::commitment::{eviction_risk, CommitmentScore};
use crate::constants::{BINOMIAL_EXACT_THRESHOLD, RELIABILITY_REPAIR_THRESHOLD};
use crate::types::{IdentityPub, SourceBlockId};

#[cfg(test)]
mod tests;

// ============================================================
// Input types
// ============================================================

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
    pub holder_id: IdentityPub,
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
    HolderNotFound(IdentityPub),
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
pub fn block_reliability(input: &BlockReliabilityInput) -> Result<f64, ReliabilityError> {
    if input.k_eff == 0 {
        return Err(ReliabilityError::InvalidKEff(0));
    }

    let (total_alive, weighted_mean_p) = weighted_mean_survival(&input.holders)?;
    binomial_survival(total_alive, input.k_eff, weighted_mean_p)
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
) -> Result<f64, ReliabilityError> {
    if input.k_eff == 0 {
        return Err(ReliabilityError::InvalidKEff(0));
    }

    if !input.holders.iter().any(|h| &h.holder_id == holder_id) {
        return Err(ReliabilityError::HolderNotFound(*holder_id));
    }

    // Validate all survival probabilities upfront.
    for h in &input.holders {
        if !(0.0..=1.0).contains(&h.survival_prob) {
            return Err(ReliabilityError::InvalidSurvivalProb(h.survival_prob));
        }
    }

    let reduced: Vec<&HolderReliabilityInput> = input
        .holders
        .iter()
        .filter(|h| &h.holder_id != holder_id)
        .collect();

    let (total_alive, weighted_mean_p) = weighted_mean_survival_refs(&reduced)?;
    binomial_survival(total_alive, input.k_eff, weighted_mean_p)
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

    let symbols_alive = input
        .holders
        .iter()
        .try_fold(0u32, |acc, h| {
            acc.checked_add(h.alive_symbols)
                .ok_or(ReliabilityError::SymbolCountOverflow)
        })?;

    let weakest_holder_impact = if input.holders.is_empty() {
        None
    } else {
        let mut best: Option<(f64, u32, IdentityPub, f64)> = None;
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

        best.map(|(_, symbols_held, holder_id, reliability_without)| WeakestHolderImpact {
            holder_id,
            symbols_held,
            reliability_without,
        })
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
pub fn commitment_to_survival_prob(score: CommitmentScore) -> f64 {
    1.0 - eviction_risk(score)
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
    let poly = t * (0.319_381_530
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

/// Compute (total_alive, weighted_mean_p) from a slice of HolderReliabilityInput.
/// Returns Err(InvalidSurvivalProb) for any holder with p outside [0.0, 1.0].
/// Returns Err(SymbolCountOverflow) if total_alive overflows u32.
fn weighted_mean_survival(
    holders: &[HolderReliabilityInput],
) -> Result<(u32, f64), ReliabilityError> {
    let mut total_alive: u32 = 0;
    let mut weighted_sum: f64 = 0.0;

    for h in holders {
        if !(0.0..=1.0).contains(&h.survival_prob) {
            return Err(ReliabilityError::InvalidSurvivalProb(h.survival_prob));
        }
        total_alive = total_alive
            .checked_add(h.alive_symbols)
            .ok_or(ReliabilityError::SymbolCountOverflow)?;
        weighted_sum += h.alive_symbols as f64 * h.survival_prob;
    }

    let weighted_mean_p = if total_alive == 0 {
        0.0
    } else {
        weighted_sum / total_alive as f64
    };

    Ok((total_alive, weighted_mean_p))
}

/// Same as weighted_mean_survival but for a slice of references (used in per_holder_impact).
fn weighted_mean_survival_refs(
    holders: &[&HolderReliabilityInput],
) -> Result<(u32, f64), ReliabilityError> {
    let mut total_alive: u32 = 0;
    let mut weighted_sum: f64 = 0.0;

    for h in holders {
        if !(0.0..=1.0).contains(&h.survival_prob) {
            return Err(ReliabilityError::InvalidSurvivalProb(h.survival_prob));
        }
        total_alive = total_alive
            .checked_add(h.alive_symbols)
            .ok_or(ReliabilityError::SymbolCountOverflow)?;
        weighted_sum += h.alive_symbols as f64 * h.survival_prob;
    }

    let weighted_mean_p = if total_alive == 0 {
        0.0
    } else {
        weighted_sum / total_alive as f64
    };

    Ok((total_alive, weighted_mean_p))
}
