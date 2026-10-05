// Symbol placement: compute how many symbols each holder gets and which ESI ranges.
// Pure logic — no DB, no async, no network.
// Weight formula: trust / sqrt(1 - trust)  (mean-variance optimum)

use crate::constants::{MAX_HOLDERS_PER_BLOCK, MAX_OVERHEAD_FACTOR, MIN_SYMBOLS_PER_HOLDER};
use crate::reliability;
use crate::types::{DeviceId, ErasureParams};

#[cfg(test)]
mod tests;

// ─── Public types ────────────────────────────────────────────────────────────

/// A candidate holder for symbol placement.
#[derive(Debug, Clone)]
pub struct HolderCandidate {
    pub device_id: DeviceId,
    /// Combined trust score [0.0, 1.0).
    pub trust: f64,
}

/// Allocation result for one holder.
#[derive(Debug, Clone, PartialEq)]
pub struct HolderAllocation {
    pub device_id: DeviceId,
    /// Number of symbols assigned to this holder.
    pub symbol_count: u32,
    /// ESI range start (contiguous: ESIs start_esi .. start_esi + symbol_count).
    pub start_esi: u32,
}

impl HolderAllocation {
    /// ESI range as (start, count) pair (matches SymbolPlacement.esi_ranges format).
    pub fn esi_range(&self) -> (u32, u32) {
        (self.start_esi, self.symbol_count)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PlacementError {
    /// No candidates provided.
    #[error("no candidates provided")]
    NoCandidates,

    /// All candidates have trust >= 1.0 (weight = infinity).
    #[error("all candidates have trust >= 1.0 (degenerate input)")]
    AllTrustMaximum,

    /// Fewer than 2 viable holders after filtering.
    #[error("fewer than 2 viable holders: {count}")]
    TooFewHolders { count: usize },

    /// N is less than number of holders (cannot assign 1 symbol per holder).
    #[error("N={n} is less than holder count={holders}, cannot assign minimum 1 per holder")]
    NTooSmall { n: u32, holders: usize },

    /// Total placed symbols are below k_eff — the block would be undecodable.
    #[error("placed {placed} symbols but {needed} (k_eff) are required to decode")]
    InsufficientCapacity { placed: u32, needed: u32 },
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Compute placement weight for a trust score.
///
/// Formula: trust / sqrt(1 - trust)
/// Input must be in (0, 1). Values outside that range are clamped first.
pub fn holder_weight(trust: f64) -> f64 {
    let t = trust.clamp(0.001, 0.999);
    t / (1.0 - t).sqrt()
}

/// Compute a symbol allocation across holders.
///
/// Algorithm:
/// 1. Filter out candidates with trust >= 1.0. Error if all filtered or < 2 remain.
///    Then enforce holder limits (MAX_HOLDERS_PER_BLOCK, N / MIN_SYMBOLS_PER_HOLDER),
///    keeping top candidates by weight.
/// 2. Check N >= candidate count (NTooSmall guard).
/// 3. Clamp trust to [0.001, 0.999].
/// 4. Compute weight_i = trust_i / sqrt(1 - trust_i).
/// 5. Normalize: share_i = weight_i / sum(weights).
/// 6. raw_i = max(1, round(N * share_i)).
/// 7. Redistribution loop (max 10 iterations):
///    - Cap holders exceeding params.max_per_holder().
///    - Redistribute excess proportionally to strictly-uncapped holders.
/// 8. Adjust total to exactly params.n:
///    - sum > n: reduce from lowest-weight holders first (keep >= 1).
///    - sum < n: add to highest-weight uncapped holders first.
/// 9. Assign ESI ranges starting at `esi_offset`, sorted by descending symbol_count
///    (ties broken by identity bytes).
///
/// `esi_offset` is the first ESI to assign. Pass `0` for single-device or test scenarios.
/// In a multi-device cluster, pass `esi_namespace_start(device_index)` so each device
/// allocates non-overlapping ESI ranges.
pub fn compute_allocation(
    candidates: &[HolderCandidate],
    params: &ErasureParams,
    esi_offset: u32,
) -> Result<Vec<HolderAllocation>, PlacementError> {
    if candidates.is_empty() {
        return Err(PlacementError::NoCandidates);
    }

    // Step 1: filter degenerate (trust >= 1.0)
    let mut valid: Vec<&HolderCandidate> = candidates.iter().filter(|c| c.trust < 1.0).collect();

    if valid.is_empty() {
        return Err(PlacementError::AllTrustMaximum);
    }
    if valid.len() < 2 {
        return Err(PlacementError::TooFewHolders { count: valid.len() });
    }

    // Step 1b: enforce holder limits
    let max_by_symbols = params
        .n
        .checked_div(MIN_SYMBOLS_PER_HOLDER)
        .map_or(usize::MAX, |v| v as usize);
    let effective_max = (MAX_HOLDERS_PER_BLOCK as usize).min(max_by_symbols).max(2);

    if valid.len() > effective_max {
        // Sort by weight descending, keep top effective_max
        valid.sort_by(|a, b| {
            holder_weight(b.trust)
                .partial_cmp(&holder_weight(a.trust))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.device_id.0.cmp(&b.device_id.0))
        });
        valid.truncate(effective_max);
    }

    let n = params.n;
    let mut max_per = params.max_per_holder();

    // CL-1: the concentration cap can be tighter than k_eff / holders for small,
    // low-importance blocks placed across few holders. If the cap cannot cover
    // k_eff across the available holders, the block would be silently
    // unrecoverable. Relax the cap to the minimum that still covers k_eff —
    // only in that under-capacity case, so normal blocks are unaffected.
    let holders = valid.len() as u32;
    if (max_per as u64) * (holders as u64) < params.k_eff as u64 {
        max_per = params.k_eff.div_ceil(holders);
    }

    // Step 2: check N >= candidate count
    if (n as usize) < valid.len() {
        return Err(PlacementError::NTooSmall {
            n,
            holders: valid.len(),
        });
    }

    // Step 3 & 4: clamp trust, compute weights
    let weights: Vec<f64> = valid.iter().map(|c| holder_weight(c.trust)).collect();
    let weight_sum: f64 = weights.iter().sum();

    // Step 5 & 6: shares → initial counts (minimum 1 each)
    let mut counts: Vec<u32> = weights
        .iter()
        .map(|&w| {
            let share = w / weight_sum;
            let raw = (n as f64 * share).round() as u32;
            raw.max(1)
        })
        .collect();

    // Step 7: redistribution loop (max 10 iterations)
    for _ in 0..10 {
        let capped_excess: u32 = counts.iter().map(|&c| c.saturating_sub(max_per)).sum();
        if capped_excess == 0 {
            break;
        }

        // Collect uncapped weight sum (strictly under cap)
        let uncapped_weight_sum: f64 = weights
            .iter()
            .zip(counts.iter())
            .filter(|&(_, &c)| c < max_per)
            .map(|(&w, _)| w)
            .sum();

        for i in 0..counts.len() {
            if counts[i] > max_per {
                counts[i] = max_per;
            } else if counts[i] < max_per && uncapped_weight_sum > 0.0 {
                // Only add to holders strictly under the cap
                let extra =
                    (capped_excess as f64 * weights[i] / uncapped_weight_sum).round() as u32;
                counts[i] = (counts[i] + extra).min(max_per);
            }
        }
    }

    // Step 8: adjust total to exactly n
    let total: u32 = counts.iter().sum();

    if total > n {
        // Reduce from lowest-weight holders first
        let mut indexed: Vec<usize> = (0..counts.len()).collect();
        indexed.sort_by(|&a, &b| {
            weights[a]
                .partial_cmp(&weights[b])
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| valid[a].device_id.0.cmp(&valid[b].device_id.0))
        });
        let mut excess = total - n;
        for idx in indexed {
            if excess == 0 {
                break;
            }
            let reducible = counts[idx].saturating_sub(1);
            let reduce = reducible.min(excess);
            counts[idx] -= reduce;
            excess -= reduce;
        }
    } else if total < n {
        // Add to highest-weight uncapped holders first
        let mut indexed: Vec<usize> = (0..counts.len()).collect();
        indexed.sort_by(|&a, &b| {
            weights[b]
                .partial_cmp(&weights[a])
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| valid[a].device_id.0.cmp(&valid[b].device_id.0))
        });
        let mut deficit = n - total;
        for idx in indexed {
            if deficit == 0 {
                break;
            }
            let headroom = max_per.saturating_sub(counts[idx]);
            let add = headroom.min(deficit);
            counts[idx] += add;
            deficit -= add;
        }
    }

    // CL-1 invariant: never emit a placement that cannot be decoded. With the
    // relaxed cap above this is unreachable on valid input (holders >= 2, cap
    // covers k_eff), but a future change to the redistribution logic could
    // reintroduce under-placement — fail loud here rather than silently lose data.
    let placed: u32 = counts.iter().sum();
    if placed < params.k_eff {
        return Err(PlacementError::InsufficientCapacity {
            placed,
            needed: params.k_eff,
        });
    }

    // Step 9: assign ESI ranges sorted by descending symbol_count (ties by device_id bytes)
    let mut order: Vec<usize> = (0..counts.len()).collect();
    order.sort_by(|&a, &b| {
        counts[b]
            .cmp(&counts[a])
            .then_with(|| valid[a].device_id.0.cmp(&valid[b].device_id.0))
    });

    let mut allocations = Vec::with_capacity(valid.len());
    let mut esi_cursor: u32 = esi_offset;

    for idx in order {
        let count = counts[idx];
        if count == 0 {
            continue;
        }
        allocations.push(HolderAllocation {
            device_id: valid[idx].device_id,
            symbol_count: count,
            start_esi: esi_cursor,
        });
        esi_cursor = esi_cursor.saturating_add(count); // CS-ERA-6
    }

    Ok(allocations)
}

/// Compute a holder-correlated symbol allocation driven by block importance.
///
/// This is the unified placement path (placement/reliability redesign). It derives
/// the decode threshold `k_eff` from the block size, the reliability target from
/// `importance` (`reliability::target_reliability`), then calls
/// `reliability::solve_placement_for_target` to choose per-holder symbol counts that
/// reach the target with as few symbols as possible under the holder-correlated
/// model. The placement *shape* is emergent: few holders → full-copy replicas, many
/// holders → thin erasure spread — no mode flag, no concentration cap, no minimum
/// holder/redundancy floor. A single holder is a valid best-effort placement.
///
/// Per-holder counts are capped at `k_eff` (a full copy already decodes), bounded by
/// `MAX_HOLDERS_PER_BLOCK` distinct holders and `k_eff × MAX_OVERHEAD_FACTOR` total
/// symbols. If the target is unreachable within those limits the placement is still
/// returned best-effort (the caller detects under-target via a reliability check and
/// schedules repair — DR doctrine: defer-not-refuse).
///
/// # Parameters
///
/// - `candidates`: trusted holder pool. `trust` is used as the per-holder survival
///   proxy (clamped to [0, 0.999]). Must be non-empty for a non-NoCandidates result.
/// - `source_size`: compressed+encrypted blob size in bytes. Drives `k`/`k_eff`. > 0.
/// - `importance`: block importance in [0.0, 1.0]. Clamped if out of range.
/// - `esi_offset`: first ESI to assign (0 for single-device; namespace offset for cluster).
///
/// # Errors
///
/// Returns `PlacementError::NoCandidates` if `candidates` is empty or `source_size`
/// is 0 (an empty block cannot be erasure-coded).
pub fn compute_allocation_with_importance(
    candidates: &[HolderCandidate],
    source_size: u64,
    importance: f64,
    esi_offset: u32,
) -> Result<Vec<HolderAllocation>, PlacementError> {
    if candidates.is_empty() {
        return Err(PlacementError::NoCandidates);
    }

    // k_eff from the block size (k, t are derived; overhead/n are no longer used —
    // redundancy is target-driven by the solver, not the static overhead formula).
    let base_params = ErasureParams::compute(source_size, importance)
        .map_err(|_| PlacementError::NoCandidates)?;
    let k_eff = base_params.k_eff;

    let target_p = reliability::target_reliability(importance);

    // Per-holder survival probability via `commitment_to_survival_prob`, the same
    // function the post-placement reliability recompute uses — so both apply the
    // physical survival ceiling (BASELINE_HOLDER_SURVIVAL): trust is NOT survival,
    // even a fully trusted node can vanish, so p never approaches 1 and critical
    // few-holder blocks earn full replicas instead of a thin spread.
    // NOTE: the *input* still differs — placement feeds the combined trust score
    // here, while the recompute feeds bare `trust_p`; both are capped+squared, but
    // unifying the input is a tracked follow-up (see private tech-debt SS-DR-2).
    let solver_candidates: Vec<reliability::HolderCandidate> = candidates
        .iter()
        .map(|c| reliability::HolderCandidate {
            survival_prob: reliability::commitment_to_survival_prob(
                crate::commitment::CommitmentScore::new(c.trust),
            ),
        })
        .collect();

    let plan = match reliability::solve_placement_for_target(
        k_eff,
        &solver_candidates,
        target_p,
        MAX_HOLDERS_PER_BLOCK as usize,
        MAX_OVERHEAD_FACTOR,
    ) {
        Ok(plan) => plan,
        Err(_) => {
            // Invalid k_eff (0) — cannot place. Treated as no viable placement.
            return Err(PlacementError::NoCandidates);
        }
    };

    if !plan.reached_target {
        tracing::debug!(
            k_eff,
            importance,
            target_p,
            "compute_allocation_with_importance: best-effort placement (under target)"
        );
    }

    // Assign ESI ranges, largest share first (ties by device_id bytes) — matches the
    // contiguous, non-overlapping ESI convention used elsewhere.
    let mut order: Vec<usize> = (0..candidates.len())
        .filter(|&i| plan.per_holder[i] > 0)
        .collect();
    order.sort_by(|&a, &b| {
        plan.per_holder[b]
            .cmp(&plan.per_holder[a])
            .then_with(|| candidates[a].device_id.0.cmp(&candidates[b].device_id.0))
    });

    let mut allocations = Vec::with_capacity(order.len());
    let mut esi_cursor = esi_offset;
    for idx in order {
        let count = plan.per_holder[idx];
        allocations.push(HolderAllocation {
            device_id: candidates[idx].device_id,
            symbol_count: count,
            start_esi: esi_cursor,
        });
        esi_cursor = esi_cursor.saturating_add(count); // CS-ERA-6
    }

    Ok(allocations)
}
