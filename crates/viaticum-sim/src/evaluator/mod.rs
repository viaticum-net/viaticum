//! Evaluator — the god-view scorer (outside every node decision).
//!
//! The evaluator may read the hidden ground-truth ([`crate::generator`]) because
//! it never feeds anything back into a kernel decision — it only SCORES outcomes.
//! For SIM-2 it (a) counts accept→evict→reaccept chatter cycles from the engine
//! trace, and (b) checks the kernel's eviction rank against the TRUE net-debtor
//! ordering via Spearman rank correlation.

#[cfg(test)]
mod tests;

use crate::engine::RunTrace;
use crate::generator::Population;

/// Spearman rank correlation between two equal-length sequences.
///
/// Returns a value in [-1, 1]; `1.0` means the two rankings agree perfectly.
/// Uses the standard `1 − 6·Σd²/(n(n²−1))` form on dense ranks (the sequences
/// here have no ties because the generator spreads true G with a small jitter).
pub fn spearman(a: &[f64], b: &[f64]) -> f64 {
    let n = a.len();
    if n != b.len() || n < 2 {
        return 0.0;
    }
    let ra = dense_ranks(a);
    let rb = dense_ranks(b);
    let mut d2 = 0.0;
    for i in 0..n {
        let d = ra[i] - rb[i];
        d2 += d * d;
    }
    let nf = n as f64;
    1.0 - (6.0 * d2) / (nf * (nf * nf - 1.0))
}

/// Fractional ranks of the values (1-based), averaging ties.
fn dense_ranks(v: &[f64]) -> Vec<f64> {
    let n = v.len();
    let mut idx: Vec<usize> = (0..n).collect();
    idx.sort_by(|&i, &j| v[i].total_cmp(&v[j]));
    let mut ranks = vec![0.0; n];
    let mut i = 0;
    while i < n {
        let mut j = i + 1;
        while j < n && v[idx[j]] == v[idx[i]] {
            j += 1;
        }
        // Average rank for the tie group [i, j).
        let avg = ((i + 1 + j) as f64) / 2.0;
        for &k in &idx[i..j] {
            ranks[k] = avg;
        }
        i = j;
    }
    ranks
}

/// SIM-2 verdict for one run.
#[derive(Debug, Clone)]
pub struct Sim2Result {
    /// Number of SHORT-PERIOD (tick-frequency) accept→evict→reaccept chatter
    /// cycles of the tracked symbol — the limit cycle the hysteresis must kill.
    pub chatter_cycles: u32,
    /// All drop→reaccept→drop cycles at any period (chatter + the legitimate slow
    /// load-period cycle). Diagnostic: in the damped run `all_cycles > 0` while
    /// `chatter_cycles == 0` — proving both legs are live, not that accept is dead.
    pub all_cycles: u32,
    /// Number of ticks the accept leg (`accept_ok`) fired. Diagnostic: proves the
    /// reaccept leg is genuinely reachable in the damped run (was structurally
    /// dead before the WARN-1 retune).
    pub accept_fire_count: u32,
    /// Spearman correlation between the kernel's eviction rank and the true
    /// net-debtor order (ascending true `G(h←O)`). 1.0 = perfect agreement.
    pub eviction_rank_spearman: f64,
    /// True iff the drop order was strictly ascending in true `G(h←O)`.
    pub strictly_ascending: bool,
    /// True iff every true net-debtor (true `G` below the population median) is
    /// dropped before every true net-creditor — the explicit god-view check that
    /// "net-debtors are evicted first" using the hidden archetype/median.
    pub debtors_before_creditors: bool,
}

/// Score a run against the hidden population.
///
/// * `chatter_cycles` is read straight from the engine trace.
/// * the eviction-rank check maps each evicted holding (by index) to its TRUE
///   `g_holder_from_owner`, then compares the kernel's drop *position* against the
///   true ascending order via Spearman.
pub fn score(pop: &Population, trace: &RunTrace) -> Sim2Result {
    let drop_order = &trace.last_drop_order;

    // For each holding in the order the kernel chose to drop it, the drop POSITION
    // (0 = dropped first) should correlate with its TRUE G ascending. Build two
    // aligned sequences: position-in-drop-order vs true G.
    let mut positions = Vec::with_capacity(drop_order.len());
    let mut true_gs = Vec::with_capacity(drop_order.len());
    for (pos, &holding_idx) in drop_order.iter().enumerate() {
        positions.push(pos as f64);
        true_gs.push(pop.owners[holding_idx].true_g_holder_from_owner);
    }

    let eviction_rank_spearman = spearman(&positions, &true_gs);

    // Strictly ascending: each successive dropped holding has true G ≥ the
    // previous (net-debtors before net-creditors).
    let mut strictly_ascending = true;
    for w in true_gs.windows(2) {
        if w[1] < w[0] {
            strictly_ascending = false;
            break;
        }
    }

    // Explicit god-view net-debtor-first check: classify each dropped holding as
    // a true net-debtor (hidden archetype / below-median true G) and confirm no
    // creditor is dropped before any debtor. Once a creditor appears in the drop
    // order, no later position may be a debtor.
    let median_g = pop.median_true_g();
    let mut debtors_before_creditors = true;
    let mut seen_creditor = false;
    for &holding_idx in drop_order {
        let is_debtor = pop.owners[holding_idx].is_net_debtor(median_g);
        if is_debtor && seen_creditor {
            debtors_before_creditors = false;
            break;
        }
        if !is_debtor {
            seen_creditor = true;
        }
    }

    Sim2Result {
        chatter_cycles: trace.tracked.chatter_cycles,
        all_cycles: trace.tracked.all_cycles,
        accept_fire_count: trace.tracked.accept_fire_count,
        eviction_rank_spearman,
        strictly_ascending,
        debtors_before_creditors,
    }
}
