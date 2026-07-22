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

/// World-v3 phase-3 (A15) god-view EVALUATOR read (never a decision input): the NEWCOMER
/// floor-durability. Among PRESENT nodes that joined strictly AFTER `join_cutoff` — the genuine
/// newcomers arriving into an already-established network (the inflow pool tail; the bootstrap
/// cohort all joins by `T_join ≤ cutoff`, so `joined_tick > cutoff` cleanly isolates them) — the
/// MEAN over nodes of `(floor-met blocks that CURRENTLY still hold ≥ floor non-cream symbols) /
/// (floor-met blocks)`. A newcomer with no floor-met block yet is SKIPPED (no denominator);
/// `NaN` if no newcomer has a floor-met block. The A15 enclosure headline: did newcomers' data,
/// once it reached durable, STAY durable despite the incumbent cartel? (The per-archetype floor
/// durability of [`collect_metrics`], restricted to the post-cutoff arrivals and expressed as a
/// per-block "still ≥ floor" fraction.)
pub fn newcomer_floor_durability(world: &World, join_cutoff: u64, floor: usize) -> f64 {
    let n = world.nodes.len();
    let mut ratio_sum = 0.0f64;
    let mut counted = 0usize;
    for o in 0..n {
        if !world.nodes[o].present || world.nodes[o].joined_tick <= join_cutoff {
            continue;
        }
        let mut met = 0usize; // blocks that ever met floor
        let mut still = 0usize; // ... whose CURRENT non-cream holder count is still ≥ floor
        for b in &world.nodes[o].own_blocks {
            if !b.floor_ever_met {
                continue;
            }
            met += 1;
            let live = (0..n)
                .filter(|&h| {
                    world.nodes[h].present
                        && world.nodes[h]
                            .holdings
                            .iter()
                            .any(|s| s.alive && !s.cream && s.owner == o && s.block == b.id)
                })
                .count();
            if live >= floor {
                still += 1;
            }
        }
        if met > 0 {
            ratio_sum += still as f64 / met as f64;
            counted += 1;
        }
    }
    if counted > 0 {
        ratio_sum / counted as f64
    } else {
        f64::NAN
    }
}

/// World-v3 phase-3 (A15) CARTEL-PAYS read (spec §4, SECONDARY): the mean outbound-service
/// integral `served_out = Σ_h served[node][h]` (gb·days the node GAVE others) for the CARTEL
/// nodes vs the NON-cartel INCUMBENTS (present nodes that joined by `join_cutoff` and are not in
/// the cartel). Returns `(cartel_mean, non_cartel_incumbent_mean)`. A cartel that refuses to
/// serve newcomers serves LESS, so it should earn NO MORE than an honest incumbent of the same
/// vintage. Each side is `NaN` when it has no members (skipped by the caller). Pure god-view.
pub fn cartel_earnings_split(world: &World, cartel: &[usize], join_cutoff: u64) -> (f64, f64) {
    let n = world.nodes.len();
    let served_out = |node: usize| -> f64 { (0..n).map(|h| world.served[node][h]).sum() };
    let mut cartel_sum = 0.0f64;
    let mut cartel_cnt = 0usize;
    let mut inc_sum = 0.0f64;
    let mut inc_cnt = 0usize;
    for node in 0..n {
        if !world.nodes[node].present {
            continue;
        }
        if cartel.contains(&node) {
            cartel_sum += served_out(node);
            cartel_cnt += 1;
        } else if world.nodes[node].joined_tick <= join_cutoff {
            // A non-cartel INCUMBENT (same "established" vintage as the cartel).
            inc_sum += served_out(node);
            inc_cnt += 1;
        }
    }
    let cartel_mean = if cartel_cnt > 0 {
        cartel_sum / cartel_cnt as f64
    } else {
        f64::NAN
    };
    let inc_mean = if inc_cnt > 0 {
        inc_sum / inc_cnt as f64
    } else {
        f64::NAN
    };
    (cartel_mean, inc_mean)
}

/// World-v3 phase-3 (A7 sybil-farm) god-view EVALUATOR read (never a decision input, `4r_a7_spec.md`
/// §3): the CROSS-BOUNDARY honest storage the farm captured. `Σ_{h∉farm, s∈farm} served[h][s]` —
/// the gb·time integral of the FARM's own data (`s` = sybil owner ∈ farm) that lived on an HONEST
/// holder (`h` ∉ farm), PoS-confirmed. This is the storage the farm actually captured from the honest
/// network. The reader counts only honest↔farm flows (the intra-farm `served[i∈farm][j∈farm]` cells
/// the collusion writes are EXCLUDED: `h ∉ farm`, `s ∈ farm`).
///
/// NOTE (SIM-FIDELITY ARTIFACT, `4r_a7_spec.md` + A7 adversarial review): under collusion this metric
/// inflates ~58× — but NOT because collusion beats the credit-limit. The pairwise κ_O credit key
/// [`farm_honest_reciprocity`] (`capital[sybil][honest].g_ho`) stays ≈ 0, so the credit-limit HOLDS.
/// The inflation rides the sim's OWNER-ORDERING PROXY: `place_own_data`'s `giver_priority_order`
/// (engine `place_own_data`, default on) sorts owners each tick by the GLOBAL row-sum
/// `Σ_h capital[o][h].g_ho`, which collusion inflates for free — so the sybils sort to the FRONT of
/// the placement order and win scarce free-accept holder slots under contention. That global scheduler
/// ranking-all-owners-by-total-service has NO real-protocol analogue (the daemon's priority is
/// holder-side pairwise), and the code itself flags it as a proxy "NOT the spec's ideal". So the 58×
/// is a sim-fidelity artifact; the trust-model defence is [`farm_honest_reciprocity`] ≈ 0
/// (INV-SYBIL-CREDIT-LIMIT-HOLDS). `0.0` for an empty farm.
pub fn farm_honest_storage(world: &World, farm: &[usize]) -> f64 {
    let n = world.nodes.len();
    let is_farm = |x: usize| farm.contains(&x);
    let mut sum = 0.0f64;
    for h in 0..n {
        if is_farm(h) {
            continue; // honest holder only
        }
        for &s in farm {
            sum += world.served[h][s]; // served[holder][owner] = honest h held sybil s's data
        }
    }
    sum
}

/// World-v3 phase-3 (A7) THE HEADLINE DEFENCE reader (`4r_a7_spec.md` §4 + A7 review): the farm's
/// EARNED HONEST RECIPROCITY — the pairwise κ_O credit key that gates the farm's data on honest
/// holders — `Σ_{s∈farm, h∉farm} capital[s][h].g_ho`. This is the cell the eviction/preemption rank
/// (core `eviction_order`) and the admit-guard read to decide how much of sybil `s`'s data holder `h`
/// keeps (`V_ret = v_free + κ_O/c_recip`). Collusion writes ONLY intra-farm cells, so it can NOT
/// inflate this honest key: it stays ≈ 0 under collude-ON (the ε-farm never serves honest, so it earns
/// no honest reciprocity). INV-SYBIL-CREDIT-LIMIT-HOLDS asserts this ≈ 0 — the proof that
/// "reputation = credit-limit" RESISTS sybil multiplication. `0.0` for an empty farm.
pub fn farm_honest_reciprocity(world: &World, farm: &[usize]) -> f64 {
    let n = world.nodes.len();
    let is_farm = |x: usize| farm.contains(&x);
    let mut sum = 0.0f64;
    for &s in farm {
        for h in 0..n {
            if is_farm(h) {
                continue; // honest holder only
            }
            sum += world.capital[s][h].g_ho; // sybil s's earned reciprocity as a SERVER of honest h
        }
    }
    sum
}

/// World-v3 phase-3 (A7) god-view EVALUATOR read (`4r_a7_spec.md` §3): the farm→honest OUTBOUND
/// service `Σ_{s∈farm, h∉farm} served[s][h]` — how much the farm REALLY served the honest network
/// (for the cross-ROI if it is > 0). An ε-serving sybil farm gives ≈ 0 (it earns no honest
/// reciprocity — which is why [`farm_honest_reciprocity`] stays ≈ 0). `0.0` for an empty farm.
pub fn farm_honest_served(world: &World, farm: &[usize]) -> f64 {
    let n = world.nodes.len();
    let is_farm = |x: usize| farm.contains(&x);
    let mut sum = 0.0f64;
    for &s in farm {
        for h in 0..n {
            if is_farm(h) {
                continue; // honest holder only
            }
            sum += world.served[s][h]; // served[holder][owner] = sybil s held honest h's data
        }
    }
    sum
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
