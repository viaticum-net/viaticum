// Symbol placement: compute how many symbols each holder gets and which ESI ranges.
// Pure logic — no DB, no async, no network.
// Weight formula: trust / sqrt(1 - trust)  (mean-variance optimum)

use crate::constants::{MAX_HOLDERS_PER_BLOCK, MIN_SYMBOLS_PER_HOLDER};
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
    let max_by_symbols = if MIN_SYMBOLS_PER_HOLDER > 0 {
        (params.n / MIN_SYMBOLS_PER_HOLDER) as usize
    } else {
        usize::MAX
    };
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
    let max_per = params.max_per_holder();

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
        let capped_excess: u32 = counts
            .iter()
            .map(|&c| c.saturating_sub(max_per))
            .sum();
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
        esi_cursor += count;
    }

    Ok(allocations)
}
