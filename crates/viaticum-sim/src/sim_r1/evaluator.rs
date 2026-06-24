//! SIM-R1 evaluator — the god-view scorer (outside every kernel decision).
//!
//! The evaluator MAY read the hidden ground-truth (`true_surface`,
//! `true_keep_depth`) because it never feeds anything back into a forecast — it
//! only MEASURES what actually happens. It realises BOTH death routes:
//!
//!   * **Hardware death (Route A):** a Bernoulli draw on `true_surface` decides
//!     whether the holder is alive at the horizon. A dead holder loses ALL of the
//!     owner's symbols regardless of ι.
//!   * **Eviction (Route B):** an ALIVE holder keeps only the top of the owner's
//!     ι-ladder — the symbols whose ι-RANK is at or above the eviction edge
//!     `1 − true_keep_depth`. This is the SAME two-level rule the kernel forecasts
//!     (within this owner, lowest-ι goes first); here it is applied with the HIDDEN
//!     true depth, not the inferred φ_O.
//!
//! A symbol survives iff its holder is hardware-alive AND the symbol is not
//! evicted. The block survives iff at least `k_eff` of the chosen symbols survive.
//! All of this is god-view — `place`/the kernel never saw `true_surface` or
//! `true_keep_depth`.

use crate::generator::Rng;
use crate::sim_r1::generator::SimR1Pop;

/// The ι-RANK ∈ [0,1] of the symbol at `symbol_in_ladder` within a holder's
/// ι-ladder, by the SAME convention as `HolderPlacement::iota_rank`: the fraction
/// of the ladder strictly below this symbol (singleton ladder ⇒ 0). The evaluator
/// recomputes it from the hidden ladder so it is self-contained.
fn iota_rank(ladder: &[f64], symbol_in_ladder: usize) -> f64 {
    let m = ladder.len();
    if m <= 1 {
        return 0.0;
    }
    let my = ladder
        .get(symbol_in_ladder)
        .copied()
        .unwrap_or(f64::NEG_INFINITY);
    let lower = ladder.iter().filter(|&&i| i < my).count();
    lower as f64 / (m - 1) as f64
}

/// Whether a single symbol on holder `h_idx` (rung `symbol_in_ladder`) survives in
/// ONE Monte-Carlo trial: holder hardware-alive (Bernoulli on `true_surface`) AND
/// the symbol's ι-rank at/above the eviction edge `1 − true_keep_depth`.
fn symbol_survives_trial(
    pop: &SimR1Pop,
    h_idx: usize,
    symbol_in_ladder: usize,
    rng: &mut Rng,
) -> bool {
    let h = &pop.holders[h_idx];
    // Route A — hardware death.
    let alive = rng.unit() < h.true_surface;
    if !alive {
        return false;
    }
    // Route B — eviction by the two-level rule, with the HIDDEN true depth.
    let edge = 1.0 - h.true_keep_depth;
    let rank = iota_rank(&h.ladder_iotas, symbol_in_ladder);
    // A symbol at/above the edge is kept; below it is evicted. Use a tiny epsilon so
    // a symbol exactly at the edge is KEPT (matches "retained band is [edge, 1]").
    rank + 1e-12 >= edge
}

/// Monte-Carlo measured ACTUAL survival fraction of ONE symbol (rung
/// `symbol_in_ladder`) on holder `h_idx`, over `trials` independent draws.
pub fn actual_symbol_survival(
    pop: &SimR1Pop,
    h_idx: usize,
    symbol_in_ladder: usize,
    trials: usize,
    seed: u64,
) -> f64 {
    let mut rng = Rng::new(seed);
    let mut survived = 0usize;
    for _ in 0..trials.max(1) {
        if symbol_survives_trial(pop, h_idx, symbol_in_ladder, &mut rng) {
            survived += 1;
        }
    }
    survived as f64 / trials.max(1) as f64
}

/// Monte-Carlo measured ACTUAL block survival fraction: the fraction of trials in
/// which at least `k_eff` of the chosen symbols survive. `chosen` is a list of
/// `(holder_index, symbol_in_ladder)` — the symbols actually placed (one per chosen
/// holder, after the §7 spread). Within each trial, holder hardware-death and the
/// eviction edge are realised once, jointly across all chosen symbols (a holder
/// dying kills every symbol it carries).
pub fn actual_block_survival(
    pop: &SimR1Pop,
    chosen: &[(usize, usize)],
    k_eff: usize,
    trials: usize,
    seed: u64,
) -> f64 {
    if k_eff == 0 {
        return 1.0;
    }
    let mut rng = Rng::new(seed);
    let mut block_survived = 0usize;
    for _ in 0..trials.max(1) {
        // Realise hardware-death once per holder this trial (shared across the
        // holder's symbols — a dead disk takes them all).
        let mut alive: Vec<Option<bool>> = vec![None; pop.holders.len()];
        let mut survivors = 0usize;
        for &(h_idx, sym) in chosen {
            let h = &pop.holders[h_idx];
            let is_alive = match alive[h_idx] {
                Some(a) => a,
                None => {
                    let a = rng.unit() < h.true_surface;
                    alive[h_idx] = Some(a);
                    a
                }
            };
            if !is_alive {
                continue;
            }
            let edge = 1.0 - h.true_keep_depth;
            let rank = iota_rank(&h.ladder_iotas, sym);
            if rank + 1e-12 >= edge {
                survivors += 1;
            }
        }
        if survivors >= k_eff {
            block_survived += 1;
        }
    }
    block_survived as f64 / trials.max(1) as f64
}
