//! God-view metric collection (design `4r_world_v3_detail.md` §3).
//!
//! All metrics are read from the god-view [`World`] in the evaluator role — NEVER fed
//! back into a node decision. The scalar/durability readers here replicate `sim_diag`'s
//! sections (6a) share-A>0, (6f) mean loyalty depth D, (6g) mean suspicion σ, (5) floor
//! durability, plus the eviction/preemption/cap-trim counters — so `honest_v2`'s
//! seed-42 numbers match `sim_diag 42 100 50 1 v2` byte-for-byte (the regression anchor).
//!
//! The extraction-ratio (design §3.2) is the real non-inflation signal (spec §10 п.17):
//! per archetype, `Σ consumed / Σ served_out` over the `served` gb·time integral.

use crate::sim_dynamic::engine::DynParams;
use crate::sim_dynamic::generator::{Archetype, World};

/// One seed's god-view snapshot at the run horizon.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricSet {
    /// Alive symbols over present holders (the share-A>0 denominator).
    pub alive_symbols: usize,
    /// Present node count at the horizon.
    pub present_nodes: usize,
    /// Share of alive symbols whose (owner←holder) reciprocity `g_ho > 0`, in percent
    /// (sim_diag 6a).
    pub share_a_pos: f64,
    /// Total eviction events over the run (`world.eviction_log.len()`).
    pub evicts: usize,
    /// Preemptive-swap count (`world.preempt_count`).
    pub preempts: usize,
    /// Р-7 holder-side volume-cap trims (`world.cap_trim_count`).
    pub cap_trims: usize,
    /// Mean loyalty depth D over alive pairs (sim_diag 6f), gb·days.
    pub mean_depth: f64,
    /// Mean suspicion σ over alive pairs (sim_diag 6g).
    pub mean_sigma: f64,
    /// Per-archetype floor durability = mean alive NON-cream holders per own block
    /// (sim_diag 5). Indexed by [`Archetype::ALL`] position; `NaN` if the archetype has
    /// no present-owner blocks.
    pub durability: [f64; 6],
    /// Per-archetype extraction ratio = `Σ consumed / Σ served_out` over the archetype's
    /// nodes (design §3.2). Indexed by [`Archetype::ALL`] position; `NaN` if the
    /// archetype gave nothing (served_out == 0).
    pub extraction_roi: [f64; 6],
}

/// Collect every 0.1 metric from a run's final god-view world. Pure read — no mutation,
/// no RNG, no feedback into any decision (evaluator discipline). `_params` is threaded so
/// a later tranche's metrics (restore window, k_eff cuts) can read the dials without a
/// signature change; 0.1's readers are dial-free.
pub fn collect_metrics(world: &World, _params: &DynParams) -> MetricSet {
    let n = world.nodes.len();

    // --- share A>0, mean D, mean σ over alive pairs on present holders (6a/6f/6g) ---
    let mut alive_symbols = 0usize;
    let mut a_pos = 0usize;
    let mut depth_sum = 0.0f64;
    let mut sigma_sum = 0.0f64;
    for h in 0..n {
        if !world.nodes[h].present {
            continue;
        }
        for s in world.nodes[h].holdings.iter().filter(|s| s.alive) {
            alive_symbols += 1;
            let cap = &world.capital[s.owner][h];
            if cap.g_ho > 1e-12 {
                a_pos += 1;
            }
            depth_sum += cap.depth_ho;
            sigma_sum += cap.sigma;
        }
    }
    let share_a_pos = if alive_symbols > 0 {
        100.0 * a_pos as f64 / alive_symbols as f64
    } else {
        0.0
    };
    let mean_depth = if alive_symbols > 0 {
        depth_sum / alive_symbols as f64
    } else {
        f64::NAN
    };
    let mean_sigma = if alive_symbols > 0 {
        sigma_sum / alive_symbols as f64
    } else {
        f64::NAN
    };

    let present_nodes = world.nodes.iter().filter(|nd| nd.present).count();

    // --- per-archetype floor durability (sim_diag section 5) ---
    let mut durability = [f64::NAN; 6];
    for (ai, &arch) in Archetype::ALL.iter().enumerate() {
        let mut sum = 0usize;
        let mut blocks = 0usize;
        for o in 0..n {
            if !world.nodes[o].present || world.nodes[o].archetype != arch {
                continue;
            }
            for b in &world.nodes[o].own_blocks {
                let alive = (0..n)
                    .filter(|&h| {
                        world.nodes[h].present
                            && world.nodes[h]
                                .holdings
                                .iter()
                                .any(|s| s.alive && !s.cream && s.owner == o && s.block == b.id)
                    })
                    .count();
                sum += alive;
                blocks += 1;
            }
        }
        if blocks > 0 {
            durability[ai] = sum as f64 / blocks as f64;
        }
    }

    // --- per-archetype extraction ratio Σconsumed/Σserved_out (design §3.2) ---
    // served[holder][owner] = gb·time the OWNER received at that HOLDER (a PoS-confirmed
    // retained integral). consumed(O) = column O sum (what O received for its own data);
    // served_out(O) = row O sum (what O gave others as a holder). Lifetime integral, so
    // departed nodes still count — archetype persists on the node.
    let mut extraction_roi = [f64::NAN; 6];
    for (ai, &arch) in Archetype::ALL.iter().enumerate() {
        let mut consumed = 0.0f64;
        let mut served_out = 0.0f64;
        for o in 0..n {
            if world.nodes[o].archetype != arch {
                continue;
            }
            for h in 0..n {
                consumed += world.served[h][o];
                served_out += world.served[o][h];
            }
        }
        if served_out > 0.0 {
            extraction_roi[ai] = consumed / served_out;
        }
    }

    MetricSet {
        alive_symbols,
        present_nodes,
        share_a_pos,
        evicts: world.eviction_log.len(),
        preempts: world.preempt_count,
        cap_trims: world.cap_trim_count,
        mean_depth,
        mean_sigma,
        durability,
        extraction_roi,
    }
}

/// Bit-exact metric equality (used by the determinism board row). Uses `f64::to_bits`
/// so a deterministically-produced `NaN` (an archetype with no blocks / no served-out)
/// compares EQUAL to itself — the derived `PartialEq` would report `NaN != NaN` and
/// false-FAIL the determinism check.
pub(crate) fn bit_eq(a: &MetricSet, b: &MetricSet) -> bool {
    a.alive_symbols == b.alive_symbols
        && a.present_nodes == b.present_nodes
        && a.share_a_pos.to_bits() == b.share_a_pos.to_bits()
        && a.evicts == b.evicts
        && a.preempts == b.preempts
        && a.cap_trims == b.cap_trims
        && a.mean_depth.to_bits() == b.mean_depth.to_bits()
        && a.mean_sigma.to_bits() == b.mean_sigma.to_bits()
        && a.durability
            .iter()
            .zip(&b.durability)
            .all(|(x, y)| x.to_bits() == y.to_bits())
        && a.extraction_roi
            .iter()
            .zip(&b.extraction_roi)
            .all(|(x, y)| x.to_bits() == y.to_bits())
}

/// Mean and SAMPLE standard deviation (n−1) over the FINITE values (NaN skipped). The
/// mean is `NaN` with no finite value; σ is `NaN` with fewer than two (undefined spread).
/// Shared by the report's metric table and the verdict engine's power test.
pub(crate) fn mean_sigma(xs: &[f64]) -> (f64, f64) {
    let v: Vec<f64> = xs.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return (f64::NAN, f64::NAN);
    }
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    let sigma = if v.len() < 2 {
        f64::NAN
    } else {
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (v.len() as f64 - 1.0);
        var.sqrt()
    };
    (mean, sigma)
}
