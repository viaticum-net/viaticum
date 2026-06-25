//! `sim_dynamic` evaluator — the god-view scorer (outside every kernel decision).
//!
//! Computes the three Experiment-1 metrics from ground-truth (design §10.D/E/F).
//! The evaluator MAY read hidden state (`archetype`, the god-view served volumes)
//! because it never feeds back into a decision — it only MEASURES.
//!
//! The anti-oracle litmus is enforced by SOURCE separation: the NODE-side estimate
//! (metric (a)'s correlate) reads from the surface estimator (`estimate_surface`)
//! on first-hand obs; the GOD-side truth reads from `true_*` fields here. They do
//! NOT share a source.

use viaticum_core::four_r::{SurfacePrior, estimate_surface};

use crate::sim_dynamic::generator::{Archetype, World};
use crate::sim_dynamic::observer::{self, OBSERVED_TAU0, OBSERVED_V0};

/// Per-node god-view summary used by the metrics.
#[derive(Debug, Clone)]
pub struct NodeSummary {
    pub idx: usize,
    pub archetype: Archetype,
    /// Total EARNED `G(O←h)` this node has rendered as a holder, i.e. the SUM over
    /// all owners of `g_owner_from_holder` (PoS-confirmed leaky-integral capital).
    ///
    /// **Why SUM, not mean (design §4(a)/§10.D).** In 4R the "badness" of a
    /// Hoarder/Freeloader is NOT low per-pair reliability (a Hoarder has high uptime
    /// and passes the few rounds it bothers with) — it is that it *accepts little /
    /// does not reciprocate*, so it serves FEW partners and the network-wide capital
    /// it builds stays small ("много reject, не строится G"). The per-pair MEAN
    /// divides that breadth back out and would REWARD a Hoarder for being selective
    /// (verified empirically: mean misranks, sum ranks correctly). The total earned
    /// G captures both per-pair quality AND breadth of service — exactly the signal
    /// the gap metric must separate honest holders from exploiters on.
    pub total_earned_g: f64,
    /// The number of distinct OWNERS this node served as a holder (pairs with some
    /// interaction history). This is the SERVED-PAIR BREADTH — the dial-sensitive
    /// count that the SUM metric mostly re-measures (a Reliable accepts broadly, a
    /// Hoarder/Freeloader accepts ~`accept_rate` as broadly). Reported honestly so the
    /// breadth-driven nature of the SUM gap is visible (FIX 1).
    pub served_pair_count: usize,
    /// Mean PER-PAIR earned G = `total_earned_g / served_pair_count` (NaN if no
    /// pairs). This is the per-pair surface QUALITY the kernel actually ranks. It
    /// goes the WRONG way (exploiters score HIGHER per pair) — a selection effect:
    /// a node only forms a surface estimate for holders that ACCEPTED its data, so
    /// per-pair quality cannot see accept-breadth. Reported, not hidden (FIX 1).
    pub mean_per_pair_g: f64,
    /// Mean node-side surface estimate OTHERS hold of this node (the secondary ρ
    /// metric's node side, read from `estimate_surface`).
    pub mean_surface_estimate_of_me: f64,
    /// God-view truth `true_accept_and_hold` for this node (the ρ metric's truth
    /// side): true accept-rate × true uptime.
    pub true_accept_and_hold: f64,
}

/// Metric (a): convergence / rank (design §10.D), reported HONESTLY across THREE
/// aggregations of earned G (FIX 1). The headline SUM gap is breadth-driven, not a
/// per-pair ranking power — all three are surfaced so that is not implied away.
#[derive(Debug, Clone)]
pub struct RankMetric {
    // --- (1) SUM of earned G (the headline; legitimate "total foregone service") ---
    /// Mean (over the archetype's nodes) of each node's TOTAL (SUM) earned G.
    pub mean_g_reliable: f64,
    /// Mean (over the archetype's nodes) of each node's TOTAL (SUM) earned G, for
    /// Hoarder+Freeloader.
    pub mean_g_bad: f64,
    /// PRIMARY SUM gap (reliable − bad). Positive ⇒ correct sign. This is a
    /// legitimate operationalisation of §4(a)/§10.D ("много reject, не строится G" =
    /// total foregone service), but it is BREADTH-driven — see the per-pair and
    /// breadth fields below.
    pub gap: f64,

    // --- (2) MEAN per-pair earned G (the per-pair surface QUALITY) ---
    /// Mean PER-PAIR earned G for Reliable nodes.
    pub mean_per_pair_g_reliable: f64,
    /// Mean PER-PAIR earned G for Hoarder+Freeloader.
    pub mean_per_pair_g_bad: f64,
    /// Per-pair gap (reliable − bad). This is NEGATIVE — per pair, exploiters score
    /// HIGHER. Reported, not hidden (FIX 1): a selection effect (a node only forms a
    /// surface for holders that ACCEPTED, so per-pair quality cannot see breadth).
    pub gap_per_pair: f64,

    // --- (3) BREADTH = mean served-pair count ---
    /// Mean served-pair count (distinct served owners) for Reliable nodes.
    pub breadth_reliable: f64,
    /// Mean served-pair count for Hoarder+Freeloader.
    pub breadth_bad: f64,
    /// Breadth ratio (reliable / bad). > 1 (≈ the accept_rate dial ratio): the SUM
    /// gap is predominantly re-measuring the input accept dial via served-pair COUNT.
    pub breadth_ratio: f64,

    // --- (4) Secondary diagnostic ---
    /// SECONDARY diagnostic: Spearman ρ between the node-side surface estimate of a
    /// node and the god-view `true_accept_and_hold(node)`. Negative here, consistent
    /// with the per-pair inversion (surface cannot see accept-breadth).
    pub spearman_rho: f64,
}

/// Compute the per-node god-view summaries needed by the metrics.
pub fn node_summaries(world: &World, prior: &SurfacePrior) -> Vec<NodeSummary> {
    let n = world.nodes.len();
    let mut out = Vec::with_capacity(n);
    for node in 0..n {
        // Mean earned G as a holder: average over owners (j) of capital[j][node].g_oh
        // — how much THIS node served others (others confirmed it via PoS).
        let mut g_sum = 0.0;
        let mut g_cnt = 0usize;
        // Mean surface estimate others hold of me: for each owner j that has a pair
        // with me, estimate_surface(obs_j_of_me) at the canonical (V,τ).
        let mut surf_sum = 0.0;
        let mut surf_cnt = 0usize;
        for j in 0..n {
            if j == node {
                continue;
            }
            let cap = &world.capital[j][node];
            // Only count pairs with some interaction history.
            if cap.pos_window.is_empty() && cap.g_oh == 0.0 {
                continue;
            }
            g_sum += cap.g_oh;
            g_cnt += 1;
            // Node-side estimate: build obs of `node` as owner j sees it, read r_hat.
            let obs = observer::observe_pair(
                cap,
                &world.nodes[node],
                crate::sim_dynamic::generator::DAYS_PER_TICK,
            );
            let est = estimate_surface(&obs, prior, OBSERVED_V0, OBSERVED_TAU0);
            surf_sum += est.r_hat;
            surf_cnt += 1;
        }
        let total_earned_g = g_sum; // SUM over served pairs (see NodeSummary doc)
        let served_pair_count = g_cnt; // BREADTH of service (distinct served owners)
        let mean_per_pair_g = if g_cnt > 0 {
            g_sum / g_cnt as f64 // per-pair surface QUALITY (FIX 1)
        } else {
            f64::NAN
        };
        let mean_surface_estimate_of_me = if surf_cnt > 0 {
            surf_sum / surf_cnt as f64
        } else {
            0.0
        };
        // God-view truth: true accept × true mean uptime.
        let arch = world.nodes[node].archetype;
        let true_accept = arch.accept_rate();
        let true_uptime = mean_uptime(world, node);
        let true_accept_and_hold = true_accept * true_uptime;

        out.push(NodeSummary {
            idx: node,
            archetype: arch,
            total_earned_g,
            served_pair_count,
            mean_per_pair_g,
            mean_surface_estimate_of_me,
            true_accept_and_hold,
        });
    }
    out
}

/// God-view mean uptime of a node over a representative window of ticks (design
/// §10.D's `true uptime to τ`). We average the calendar predicate over the most
/// recent year of ticks (or all ticks if fewer have elapsed).
fn mean_uptime(world: &World, node: usize) -> f64 {
    use crate::sim_dynamic::generator::{TICKS_PER_YEAR, online};
    let arch = world.nodes[node].archetype;
    let id = world.nodes[node].id;
    let end = world.tick;
    let start = end.saturating_sub(TICKS_PER_YEAR);
    let span = (end - start).max(1);
    let mut up = 0usize;
    for t in start..end {
        if online(arch, id, t, world.seed) {
            up += 1;
        }
    }
    up as f64 / span as f64
}

/// Compute metric (a): the earned-G gap (primary) and the surface↔truth Spearman ρ
/// (secondary diagnostic). Anti-oracle: the node-side ρ input is the surface
/// estimate (first-hand path), the god-side is `true_accept_and_hold` — different
/// sources (design §10.D).
pub fn rank_metric(summaries: &[NodeSummary]) -> RankMetric {
    let is_bad = |a: Archetype| matches!(a, Archetype::Hoarder | Archetype::Freeloader);

    // (1) SUM of earned G.
    let g_reliable: Vec<f64> = summaries
        .iter()
        .filter(|s| s.archetype == Archetype::Reliable)
        .map(|s| s.total_earned_g)
        .collect();
    let g_bad: Vec<f64> = summaries
        .iter()
        .filter(|s| is_bad(s.archetype))
        .map(|s| s.total_earned_g)
        .collect();
    let mean_g_reliable = mean(&g_reliable);
    let mean_g_bad = mean(&g_bad);
    let gap = mean_g_reliable - mean_g_bad;

    // (2) MEAN per-pair earned G. Only count nodes that served ≥1 pair (per-pair is
    // undefined otherwise); a node with zero served pairs has no surface-quality
    // value to contribute.
    let pp_reliable: Vec<f64> = summaries
        .iter()
        .filter(|s| s.archetype == Archetype::Reliable && s.mean_per_pair_g.is_finite())
        .map(|s| s.mean_per_pair_g)
        .collect();
    let pp_bad: Vec<f64> = summaries
        .iter()
        .filter(|s| is_bad(s.archetype) && s.mean_per_pair_g.is_finite())
        .map(|s| s.mean_per_pair_g)
        .collect();
    let mean_per_pair_g_reliable = mean(&pp_reliable);
    let mean_per_pair_g_bad = mean(&pp_bad);
    let gap_per_pair = mean_per_pair_g_reliable - mean_per_pair_g_bad;

    // (3) BREADTH = mean served-pair count.
    let br_reliable: Vec<f64> = summaries
        .iter()
        .filter(|s| s.archetype == Archetype::Reliable)
        .map(|s| s.served_pair_count as f64)
        .collect();
    let br_bad: Vec<f64> = summaries
        .iter()
        .filter(|s| is_bad(s.archetype))
        .map(|s| s.served_pair_count as f64)
        .collect();
    let breadth_reliable = mean(&br_reliable);
    let breadth_bad = mean(&br_bad);
    let breadth_ratio = if breadth_bad > 0.0 {
        breadth_reliable / breadth_bad
    } else {
        f64::INFINITY
    };

    // (4) Spearman ρ over all nodes with interaction history.
    let pairs: Vec<(f64, f64)> = summaries
        .iter()
        .map(|s| (s.mean_surface_estimate_of_me, s.true_accept_and_hold))
        .collect();
    let spearman_rho = spearman(&pairs);

    RankMetric {
        mean_g_reliable,
        mean_g_bad,
        gap,
        mean_per_pair_g_reliable,
        mean_per_pair_g_bad,
        gap_per_pair,
        breadth_reliable,
        breadth_bad,
        breadth_ratio,
        spearman_rho,
    }
}

/// Metric (b): reciprocity on the GOD-VIEW served-volume TIME-INTEGRAL (design
/// §10.E). The balance is measured on the Regime-2 WINDOW integral so the fill
/// regime's bulk accumulation does not swamp the steady-state signal.
#[derive(Debug, Clone)]
pub struct ReciprocityMetric {
    /// Balance ratios `served(O→P)/served(P→O)` over honest pairs (both cooperative)
    /// with non-trivial bidirectional service, on the Regime-2 window integral.
    /// Healthy ⇒ distribution near 1.
    pub honest_balance_ratios: Vec<f64>,
    /// Median honest balance ratio (a network-health summary).
    pub median_honest_balance: f64,
    /// Mean INBOUND served volume to Freeloaders (data Freeloaders' OWN backups that
    /// others retained for them), CUMULATIVE integral at end of Regime-2.
    pub freeloader_inbound_served: f64,
    /// Mean inbound served volume to Reliable nodes (cumulative end-of-Regime-2) —
    /// the baseline the freeloader figure is compared against.
    pub reliable_inbound_served: f64,
    /// Mean Freeloader inbound served at the END of REGIME-1 (the decay-trend
    /// anchor — compare against the end-of-Regime-2 figure to see whether the
    /// Freeloader's relative inbound shrinks).
    pub freeloader_inbound_r1_end: f64,
    /// Mean Reliable inbound served at the end of Regime-1 (the trend baseline).
    pub reliable_inbound_r1_end: f64,
    /// Freeloader-relative-to-Reliable inbound RATIO at the end of Regime-1
    /// (`freeloader_inbound_r1_end / reliable_inbound_r1_end`).
    pub freeloader_share_r1_end: f64,
    /// Freeloader-relative-to-Reliable inbound RATIO at the end of Regime-2. If H3
    /// bites, this is SMALLER than `freeloader_share_r1_end` (Freeloader inbound
    /// decays relative to Reliable). If it does NOT shrink, the H3 attractor has not
    /// engaged at this horizon — reported honestly, not tuned away.
    pub freeloader_share_r2_end: f64,
    /// The full inbound-served time-series (`(tick, freeloader_inbound,
    /// reliable_inbound)` samples) so the trend is fully inspectable.
    pub series: Vec<crate::sim_dynamic::generator::ServedSample>,
}

/// The Regime-2 WINDOW served-volume matrix `served2[O][P]` = the time-integral of
/// PoS-confirmed retained bytes of P's data on holder O, accumulated ONLY over
/// Regime-2 (`world.served − snapshot at the Regime-1 boundary`). This is the
/// god-view ground truth (design §10.E), NOT the G-ledger, NOT a standing snapshot.
///
/// If the Regime-1 snapshot is missing (e.g. a run with no Regime-1 boundary), this
/// falls back to the full cumulative `world.served` integral.
pub fn served_window_matrix(world: &World) -> Vec<Vec<f64>> {
    let n = world.nodes.len();
    match &world.served_regime1_snapshot {
        Some(snap) => {
            let mut out = vec![vec![0.0f64; n]; n];
            // Both indices are write targets keyed off the same (o,p) — the range
            // form is the clear one.
            #[allow(clippy::needless_range_loop)]
            for o in 0..n {
                for p in 0..n {
                    // The snapshot may be smaller (taken before the newcomer joined);
                    // treat out-of-range snapshot cells as 0.
                    let base = snap.get(o).and_then(|r| r.get(p)).copied().unwrap_or(0.0);
                    out[o][p] = (world.served[o][p] - base).max(0.0);
                }
            }
            out
        }
        None => world.served.clone(),
    }
}

/// Compute metric (b) from the god-view served-volume time-integral (design §10.E).
///
/// * The balance ratio distribution is taken on the Regime-2 WINDOW integral.
/// * The inbound figures and the Freeloader-share trend (Regime-1 end vs Regime-2
///   end) are taken from the CUMULATIVE integral and the recorded time-series, so
///   the decay (or its absence) is observable.
///
/// `_regime1_end_tick` is retained for documentation/symmetry; the window split is
/// driven by `world.served_regime1_snapshot` (frozen at that boundary).
pub fn reciprocity_metric(world: &World, _regime1_end_tick: u64) -> ReciprocityMetric {
    let n = world.nodes.len();
    let served2 = served_window_matrix(world);

    let is_cooperative = |a: Archetype| {
        matches!(
            a,
            Archetype::Reliable | Archetype::Weekend | Archetype::Seasonal | Archetype::Nomad
        )
    };

    let mut honest_ratios = Vec::new();
    // Symmetric pair access `served2[o][p]` / `served2[p][o]` needs both indices.
    #[allow(clippy::needless_range_loop)]
    for o in 0..n {
        for p in (o + 1)..n {
            let so = served2[o][p];
            let sp = served2[p][o];
            if so <= 0.0 || sp <= 0.0 {
                continue; // need bidirectional service to speak of balance
            }
            if is_cooperative(world.nodes[o].archetype) && is_cooperative(world.nodes[p].archetype)
            {
                // Ratio normalised to ≥1 so a give/take imbalance in either direction
                // shows as a distance above 1 (symmetric).
                let r = (so / sp).max(sp / so);
                honest_ratios.push(r);
            }
        }
    }

    // Cumulative inbound integral (end of Regime-2) for the headline figures.
    let freeloader_inbound_served = world.mean_inbound_served(Archetype::Freeloader);
    let reliable_inbound_served = world.mean_inbound_served(Archetype::Reliable);

    // The decay trend from the time-series: the Regime-1-boundary sample vs the last
    // (Regime-2-boundary) sample. `series` is in tick order; the Regime-1 boundary is
    // the first sample at-or-after `_regime1_end_tick`, the final entry is Regime-2's.
    let (freeloader_inbound_r1_end, reliable_inbound_r1_end) = world
        .served_series
        .iter()
        .find(|s| s.tick >= _regime1_end_tick)
        .map(|s| (s.freeloader_inbound, s.reliable_inbound))
        .unwrap_or((f64::NAN, f64::NAN));

    let safe_ratio = |num: f64, den: f64| -> f64 { if den > 0.0 { num / den } else { f64::NAN } };
    let freeloader_share_r1_end = safe_ratio(freeloader_inbound_r1_end, reliable_inbound_r1_end);
    let freeloader_share_r2_end = safe_ratio(freeloader_inbound_served, reliable_inbound_served);

    let mut sorted = honest_ratios.clone();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let median_honest_balance = if sorted.is_empty() {
        f64::NAN
    } else {
        sorted[sorted.len() / 2]
    };

    ReciprocityMetric {
        honest_balance_ratios: honest_ratios,
        median_honest_balance,
        freeloader_inbound_served,
        reliable_inbound_served,
        freeloader_inbound_r1_end,
        reliable_inbound_r1_end,
        freeloader_share_r1_end,
        freeloader_share_r2_end,
        series: world.served_series.clone(),
    }
}

/// Metric (c): DR sanity (design §10.F).
#[derive(Debug, Clone)]
pub struct DrMetric {
    /// `R_actual(T)` per sampled victim block (god-view block-survival).
    pub victim_survivals: Vec<f64>,
    /// Median over victims (PASS = > 0.9).
    pub median_survival: f64,
    /// Count of systematic zeros (victims with R_actual == 0).
    pub zero_count: usize,
    /// PASS = median > 0.9 AND no systematic zeros.
    pub pass: bool,
}

/// Compute metric (c): for `m` random victim blocks, the god-view block survival
/// `R_actual(T)` via the Monte-Carlo estimator (design §D.1): sample the hidden
/// per-holder hazard and report the empirical `P(≥ k_eff survive)` to a short
/// horizon. This replaces the old deterministic 0/1 alive-count — survival is now a
/// graded probability over the hidden hazard, seeded and reproducible.
pub fn dr_metric(world: &World, k_eff: usize, m: usize, seed: u64) -> DrMetric {
    use crate::generator::Rng;
    let n = world.nodes.len();
    // Pool of all (owner, block) blocks that have any placement.
    let mut blocks: Vec<(usize, usize)> = Vec::new();
    for o in 0..n {
        if !world.nodes[o].present {
            continue;
        }
        for b in &world.nodes[o].own_blocks {
            blocks.push((o, b.id));
        }
    }
    let mut survivals = Vec::new();
    if blocks.is_empty() {
        return DrMetric {
            victim_survivals: survivals,
            median_survival: f64::NAN,
            zero_count: 0,
            pass: false,
        };
    }
    let mut rng = Rng::new(seed);
    let m = m.min(blocks.len());
    // Sample m distinct victims deterministically.
    let mut chosen_idx: Vec<usize> = Vec::new();
    while chosen_idx.len() < m {
        let i = (rng.unit() * blocks.len() as f64) as usize % blocks.len();
        if !chosen_idx.contains(&i) {
            chosen_idx.push(i);
        }
    }

    // Short DR horizon for the sanity probe (the restore is "soon after loss").
    const DR_HORIZON_TICKS: u64 = 4;
    const DR_SAMPLES: usize = 200;
    for &i in &chosen_idx {
        let (owner, block_id) = blocks[i];
        // Monte-Carlo R_actual(T): empirical P(≥ k_eff symbols survive the hidden
        // hazard to the DR horizon), seeded off the DR seed + the victim.
        let r_actual = mc_block_r_actual(
            world,
            owner,
            block_id,
            k_eff,
            DR_HORIZON_TICKS,
            DR_SAMPLES,
            seed,
        );
        survivals.push(r_actual);
    }

    let zero_count = survivals.iter().filter(|&&r| r == 0.0).count();
    let mut sorted = survivals.clone();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let median_survival = if sorted.is_empty() {
        f64::NAN
    } else {
        sorted[sorted.len() / 2]
    };
    let pass = median_survival > 0.9 && zero_count == 0;

    DrMetric {
        victim_survivals: survivals,
        median_survival,
        zero_count,
        pass,
    }
}

// ============================================================
// Pillar 1 — efficiency: Monte-Carlo R_actual + R_actual/own-disk + drop-ranking.
// ============================================================

/// Per-holder god-view survival probability of an owner's CURRENTLY-HELD symbol to
/// horizon `T` ticks (design §D.1). This is the HIDDEN hazard the Monte-Carlo
/// estimator samples — NEVER a kernel input; it is read here only to SCORE.
///
/// The symbol is currently ALIVE on the holder, so it has already survived eviction
/// up to now; the forward survival is the product of three independent FORWARD death
/// routes over the horizon:
///  * **Departure (churn).** Per-tick departure prob `p` by archetype; survives the
///    whole horizon with prob `(1−p)^T` (Hoarder/Freeloader churn 3×, mirroring the
///    engine's `churn`).
///  * **Forward eviction.** A SOFT per-tick keep-probability over the horizon, from
///    how deep the symbol sits vs the holder's effective retained edge `1−keep_depth`
///    (deep = above the edge ⇒ kept; shallow ⇒ at risk). We use a smooth retention
///    `s ∈ [0,1]` (a ramp around the edge, not the engine's hard 0/1) BECAUSE the
///    symbol already survived the current edge — the forward question is the RISK of
///    being dropped over the next T ticks as contention persists, which is graded.
///    Compounded over the horizon: `keep_per_tick^T`.
///  * **Reachable at restore.** The holder must be online at the restore attempt —
///    its baseline uptime.
///
/// All three multiply (independent failure modes). Returns a probability in [0,1].
fn holder_symbol_survival_prob(
    world: &World,
    holder: usize,
    owner: usize,
    block: usize,
    t: u64,
) -> f64 {
    let node = &world.nodes[holder];
    if !node.present {
        return 0.0;
    }
    // Is the symbol currently alive on this holder?
    let sym = node
        .holdings
        .iter()
        .find(|s| s.alive && s.owner == owner && s.block == block);
    let sym = match sym {
        Some(s) => s,
        None => return 0.0,
    };
    // Departure survival over the horizon (per-tick churn by archetype).
    let base_churn: f64 = 0.002; // matches DynParams::default().churn_out_prob
    let p_depart = match node.archetype {
        Archetype::Hoarder | Archetype::Freeloader => base_churn * 3.0,
        _ => base_churn,
    };
    let survive_presence = (1.0 - p_depart).powi(t as i32);
    // Forward eviction route: the probability the holder does NOT drop this
    // (currently-retained) symbol over the horizon as contention persists. The symbol
    // is ALIVE now, so it sits above the current edge; the forward risk is that the
    // holder deepens its eviction past it. Three god-view drivers, mirroring the
    // engine's eviction-by-G + ι-ladder + disk-pressure realisation:
    //  * **Reciprocity (god-view served).** Eviction is ascending the holder's
    //    service to the owner; an owner that SERVED this holder back is squeezed LAST
    //    ⇒ its data is protected. We read the GOD-VIEW reciprocity directly: how much
    //    the OWNER has served THIS holder (`served[owner][holder]` = owner-as-holder
    //    retained this holder's data). A Freeloader serves almost nobody ⇒ ≈0 ⇒ its
    //    data is NOT protected ⇒ evicted first. This is the heart of pillar-1: serving
    //    your holders makes YOUR data survive (foundation §2B / §9.10). Using the
    //    god-view served VOLUME (not the symmetric G-ledger) is the honest signal.
    //  * **ι-rank.** Within an owner, higher-ι symbols are kept (intra-owner ladder).
    //  * **Disk headroom.** A holder with φ well above the eviction trigger `s_hard`
    //    won't deepen eviction at all; one pinned at the wall might.
    let phi = node.phi_free_ratio();
    let headroom = (phi - 0.10).clamp(-0.10, 0.30); // distance above s_hard=0.10
    let (ladder, _) = observer::owner_ladder_on_holder(node, owner, block);
    let iota_rank = iota_rank_of(&ladder, sym.iota);
    // Owner's god-view reciprocal service to THIS holder (the honest protection
    // signal): served[owner][holder] = volume of this holder's data the owner held.
    let recip = world.served[owner][holder].max(0.0);
    let g_protect = recip / (recip + 40.0); // ∈[0,1): served back ⇒ protected
    // Combine: protection from G + ι-depth + disk headroom. A logistic keeps it a
    // probability; the constants weight G as the dominant (reciprocity) driver.
    let evict_safety = 6.0 * g_protect + 2.0 * iota_rank + 8.0 * headroom - 1.5;
    let survive_eviction = logistic(evict_safety).clamp(0.02, 1.0);
    // Reachable at restore: the holder's baseline uptime.
    let reachable = node.archetype.base_uptime();
    (survive_presence * survive_eviction * reachable).clamp(0.0, 1.0)
}

/// Numerically-stable logistic `1/(1+e^{−x})` (local copy; the kernel's is private).
fn logistic(x: f64) -> f64 {
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let e = x.exp();
        e / (1.0 + e)
    }
}

/// ι-rank ∈ [0,1] of `iota` within `ladder` (same convention as the engine/kernel).
fn iota_rank_of(ladder: &[f64], iota: f64) -> f64 {
    let m = ladder.len();
    if m <= 1 {
        return 0.0;
    }
    let lower = ladder.iter().filter(|&&i| i < iota).count();
    lower as f64 / (m - 1) as f64
}

/// Monte-Carlo `R_actual(T)` of one owner's block (design §D.1): the empirical
/// probability that ≥ `k_eff` of its holders' symbols survive to horizon `T` ticks,
/// estimated by sampling the hidden per-holder survival hazard `n_samples` times.
///
/// This REPLACES the old deterministic 0/1 alive-count (`dr_metric`) with a genuine
/// Monte-Carlo over the hidden hazard. Seeded (`mc_seed` + the owner/block) so it is
/// bit-reproducible across runs. More surviving-likely holders ⇒ higher R_actual,
/// monotonically.
pub fn mc_block_r_actual(
    world: &World,
    owner: usize,
    block: usize,
    k_eff: usize,
    t: u64,
    n_samples: usize,
    mc_seed: u64,
) -> f64 {
    use crate::generator::Rng;
    let n = world.nodes.len();
    // Per-holder survival probabilities for this block's current holders.
    let probs: Vec<f64> = (0..n)
        .filter_map(|h| {
            let p = holder_symbol_survival_prob(world, h, owner, block, t);
            if p > 0.0
                || world.nodes[h]
                    .holdings
                    .iter()
                    .any(|s| s.alive && s.owner == owner && s.block == block)
            {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    if probs.is_empty() {
        return 0.0;
    }
    if n_samples == 0 {
        return 0.0;
    }
    let mut rng = Rng::derive(mc_seed, 0x5DAC_70A1, owner as u64, block as u64, t);
    let mut reconstructable = 0usize;
    for _ in 0..n_samples {
        let survivors = probs.iter().filter(|&&p| rng.unit() < p).count();
        if survivors >= k_eff {
            reconstructable += 1;
        }
    }
    reconstructable as f64 / n_samples as f64
}

/// Pillar-1 efficiency: a node's achieved `R_actual(T)` of its OWN data per unit own
/// disk it GAVE to others (design §D.1). The headline efficiency metric: Reliable
/// should achieve a higher `R_actual / own-disk-given` than Freeloader/Hoarder.
#[derive(Debug, Clone)]
pub struct Pillar1Metric {
    /// Per-archetype mean achieved `R_actual(T)` of own data (god-view MC), over the
    /// archetype's present nodes that have ≥1 own block.
    pub mean_r_actual_reliable: f64,
    pub mean_r_actual_hoarder: f64,
    pub mean_r_actual_freeloader: f64,
    /// Per-archetype mean own-disk GIVEN to others (gb of alive foreign holdings this
    /// node stores) — the "price paid in own disk" denominator.
    pub mean_given_reliable: f64,
    pub mean_given_hoarder: f64,
    pub mean_given_freeloader: f64,
    /// EFFICIENCY = mean `R_actual / own-disk-given` per archetype (the headline; a
    /// node optimises reliability per unit of own disk lent, foundation §2B). Higher
    /// is better. A node that gives little disk earns little reciprocal redundancy,
    /// so its own data is less reliable per unit it DID give — Reliable should lead.
    pub efficiency_reliable: f64,
    pub efficiency_hoarder: f64,
    pub efficiency_freeloader: f64,
}

/// Compute the pillar-1 efficiency metric (design §D.1). For each present node with
/// own data, MC-estimate its blocks' `R_actual(T)` and divide by the own disk it
/// gave to others. Aggregate per archetype.
pub fn pillar1_metric(
    world: &World,
    k_eff: usize,
    t: u64,
    n_samples: usize,
    mc_seed: u64,
) -> Pillar1Metric {
    let n = world.nodes.len();
    // Per-node (r_actual_mean, own_given, archetype).
    let mut rows: Vec<(f64, f64, Archetype)> = Vec::new();
    for o in 0..n {
        if !world.nodes[o].present || world.nodes[o].own_blocks.is_empty() {
            continue;
        }
        let mut r_sum = 0.0;
        let mut r_cnt = 0usize;
        let blocks: Vec<usize> = world.nodes[o].own_blocks.iter().map(|b| b.id).collect();
        for b in blocks {
            r_sum += mc_block_r_actual(world, o, b, k_eff, t, n_samples, mc_seed);
            r_cnt += 1;
        }
        let r_actual = if r_cnt > 0 { r_sum / r_cnt as f64 } else { 0.0 };
        // Own disk GIVEN to others = alive foreign-holdings volume this node stores.
        let given = world.nodes[o].used_disk();
        rows.push((r_actual, given, world.nodes[o].archetype));
    }

    // Per-archetype means over the (r_actual, given, archetype) rows.
    let mean_r = |arch: Archetype| -> f64 {
        let v: Vec<f64> = rows.iter().filter(|r| r.2 == arch).map(|r| r.0).collect();
        mean(&v)
    };
    let mean_given = |arch: Archetype| -> f64 {
        let v: Vec<f64> = rows.iter().filter(|r| r.2 == arch).map(|r| r.1).collect();
        mean(&v)
    };
    // Efficiency = R_actual / own-disk-given, per node, averaged (only nodes that
    // gave > 0 disk — otherwise the ratio is undefined / infinite).
    let efficiency = |arch: Archetype| -> f64 {
        let v: Vec<f64> = rows
            .iter()
            .filter(|r| r.2 == arch && r.1 > 0.0)
            .map(|r| r.0 / r.1)
            .collect();
        mean(&v)
    };

    Pillar1Metric {
        mean_r_actual_reliable: mean_r(Archetype::Reliable),
        mean_r_actual_hoarder: mean_r(Archetype::Hoarder),
        mean_r_actual_freeloader: mean_r(Archetype::Freeloader),
        mean_given_reliable: mean_given(Archetype::Reliable),
        mean_given_hoarder: mean_given(Archetype::Hoarder),
        mean_given_freeloader: mean_given(Archetype::Freeloader),
        efficiency_reliable: efficiency(Archetype::Reliable),
        efficiency_hoarder: efficiency(Archetype::Hoarder),
        efficiency_freeloader: efficiency(Archetype::Freeloader),
    }
}

/// Drop-ranking metric (design §D.1): under contention, does eviction systematically
/// drop LOW-`served(h←O)` owners first? Motive-blind — ranked by god-view served
/// VOLUME (NOT the G-ledger, which would be tautological), never by archetype.
#[derive(Debug, Clone)]
pub struct DropRankingMetric {
    /// Number of eviction events scored (events where the holder served ≥2 distinct
    /// owners, so a rank is meaningful).
    pub events_scored: usize,
    /// Mean served-RANK percentile of the evicted owner among the holder's served
    /// owners (0 = the holder's LOWEST-served owner was dropped, 1 = the highest).
    /// Eviction-by-G working ⇒ this is well BELOW 0.5 (low-served dropped first).
    pub mean_evicted_served_rank: f64,
    /// Fraction of scored events where the evicted owner was in the BOTTOM HALF of
    /// the holder's served owners (rank < 0.5). Working ⇒ well above 0.5.
    pub frac_below_median: f64,
}

/// Compute the drop-ranking metric (design §D.1). For each logged eviction event,
/// rank the evicted owner by god-view `served(h←O)` = "owner O served holder h" =
/// `world.served[O][h]` (the reciprocity-key direction) among ALL owners that served
/// this holder, and report whether eviction systematically hits the low-served end.
///
/// Partial anti-tautology: ranks by `world.served` (the RAW cumulative PoS-confirmed
/// retained-bytes integral), a DIFFERENT functional from the `G`-ledger the kernel
/// evicts on (a leaky integral, decay `λ`, of the same pass events). Using the raw
/// integral rather than the exact eviction key catches gross ordering bugs, but the
/// two are NOT orthogonal — both derive from the same PoS-pass stream, so a "the
/// balancer balances" residue remains. The orthogonal proof of free-rider exclusion
/// is the pillar-1 OUTCOME separation (`R_actual/own-disk`: Reliable ≫ Freeloader),
/// not this mechanism-level diagnostic.
pub fn drop_ranking_metric(world: &World) -> DropRankingMetric {
    let n = world.nodes.len();
    let mut ranks: Vec<f64> = Vec::new();
    for ev in &world.eviction_log {
        let holder = ev.holder;
        let owner = ev.owner;
        if holder >= n || owner >= n {
            continue;
        }
        // Rank by the RECIPROCITY-key direction: how much each OWNER served THIS
        // holder (served[owner][holder] = "O served h" = G(h←O)), NOT how much the
        // holder served the owner. Eviction squeezes the owners who served the
        // holder LEAST (ascending g_holder_from_owner), so a working balancer drops
        // low-`served[owner][holder]` owners first. The set is the owners that have
        // any reciprocal service to this holder. served is indexed [holder][owner],
        // so "owner o served this holder" is served[o][holder].
        let served_owners: Vec<(usize, f64)> = (0..n)
            .map(|o| (o, world.served[o][holder]))
            .filter(|&(_, v)| v > 0.0)
            .collect();
        // Need ≥2 distinct served owners for a meaningful rank.
        if served_owners.len() < 2 {
            continue;
        }
        let evicted_served = world.served[owner][holder];
        // Rank percentile: fraction of served owners with STRICTLY LESS served volume
        // than the evicted owner (0 = lowest-served, 1 = highest-served).
        let lower = served_owners
            .iter()
            .filter(|&&(_, v)| v < evicted_served)
            .count();
        let rank = lower as f64 / (served_owners.len() - 1) as f64;
        ranks.push(rank);
    }
    let events_scored = ranks.len();
    let mean_evicted_served_rank = mean(&ranks);
    let frac_below_median = if events_scored > 0 {
        ranks.iter().filter(|&&r| r < 0.5).count() as f64 / events_scored as f64
    } else {
        f64::NAN
    };
    DropRankingMetric {
        events_scored,
        mean_evicted_served_rank,
        frac_below_median,
    }
}

/// Contention-front summary (design §A acceptance / §E observability): did the world
/// REACH contention (utilization→1, full disks, eviction firing)?
#[derive(Debug, Clone)]
pub struct ContentionMetric {
    /// Mean free-ratio `φ` over present nodes at the end of the run (→0 ⇒ contended).
    pub mean_phi_end: f64,
    /// Mean utilization `1−φ` at the end (→1 ⇒ contended; the headline acceptance).
    pub mean_utilization_end: f64,
    /// Fraction of present nodes whose `φ < s_hard` at the end (in the eviction band).
    pub frac_nodes_in_eviction_band: f64,
    /// Total eviction events logged over the whole run.
    pub total_evictions: usize,
    /// Number of ticks on which ≥1 eviction fired.
    pub ticks_with_eviction: u64,
    /// Total ticks elapsed (so the % with eviction is computable).
    pub total_ticks: u64,
}

/// Compute the contention-front summary at the current world state (design §A/§E).
pub fn contention_metric(world: &World, s_hard: f64) -> ContentionMetric {
    let n = world.nodes.len();
    let present: Vec<usize> = (0..n).filter(|&i| world.nodes[i].present).collect();
    let in_band = present
        .iter()
        .filter(|&&i| world.nodes[i].phi_free_ratio() < s_hard)
        .count();
    let frac_nodes_in_eviction_band = if present.is_empty() {
        f64::NAN
    } else {
        in_band as f64 / present.len() as f64
    };
    ContentionMetric {
        mean_phi_end: world.mean_phi(),
        mean_utilization_end: world.mean_utilization(),
        frac_nodes_in_eviction_band,
        total_evictions: world.eviction_log.len(),
        ticks_with_eviction: world.ticks_with_eviction,
        total_ticks: world.tick,
    }
}

/// Newcomer bootstrap metric (design §10.I).
#[derive(Debug, Clone)]
pub struct NewcomerMetric {
    /// Ticks from the newcomer's join until its own high-ι block first reaches
    /// `r_target` placement depth in god-view (None ⇒ never within the probe).
    pub t_boot_placed: Option<u64>,
    /// Ticks until the newcomer was first CHOSEN as a holder by ≥1 established owner.
    pub t_boot_chosen: Option<u64>,
}

// --- small statistics helpers ---

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return f64::NAN;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Spearman rank correlation between paired samples. Returns NaN if < 2 pairs or a
/// degenerate (zero-variance) axis.
pub fn spearman(pairs: &[(f64, f64)]) -> f64 {
    let n = pairs.len();
    if n < 2 {
        return f64::NAN;
    }
    let rank = |vals: Vec<f64>| -> Vec<f64> {
        let mut idx: Vec<usize> = (0..vals.len()).collect();
        idx.sort_by(|&a, &b| vals[a].total_cmp(&vals[b]));
        let mut ranks = vec![0.0; vals.len()];
        let mut i = 0;
        while i < idx.len() {
            let mut j = i;
            while j + 1 < idx.len() && vals[idx[j + 1]] == vals[idx[i]] {
                j += 1;
            }
            // Average rank for ties (1-based).
            let avg = ((i + j) as f64) / 2.0 + 1.0;
            for &k in &idx[i..=j] {
                ranks[k] = avg;
            }
            i = j + 1;
        }
        ranks
    };
    let xs: Vec<f64> = pairs.iter().map(|p| p.0).collect();
    let ys: Vec<f64> = pairs.iter().map(|p| p.1).collect();
    let rx = rank(xs);
    let ry = rank(ys);
    pearson(&rx, &ry)
}

/// Pearson correlation. Returns NaN on a zero-variance axis.
fn pearson(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len() as f64;
    let mx = xs.iter().sum::<f64>() / n;
    let my = ys.iter().sum::<f64>() / n;
    let mut sxy = 0.0;
    let mut sxx = 0.0;
    let mut syy = 0.0;
    for i in 0..xs.len() {
        let dx = xs[i] - mx;
        let dy = ys[i] - my;
        sxy += dx * dy;
        sxx += dx * dx;
        syy += dy * dy;
    }
    if sxx <= 0.0 || syy <= 0.0 {
        return f64::NAN;
    }
    sxy / (sxx.sqrt() * syy.sqrt())
}
