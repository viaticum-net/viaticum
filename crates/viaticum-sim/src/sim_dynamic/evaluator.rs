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
/// `R_actual(T)` — the fraction of alive placements ≥ k_eff. Since at evaluation
/// time the placements are already realised (alive/dead), `R_actual` here is a
/// deterministic 0/1 per block; we average the indicator over the sampled victims.
/// Reuses the surviving-placement-count vs k_eff rule (the DR floor-probe).
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

    for &i in &chosen_idx {
        let (owner, block_id) = blocks[i];
        // God-view: count distinct present holders with an alive symbol of this block.
        let alive_holders = (0..n)
            .filter(|&h| {
                world.nodes[h].present
                    && world.nodes[h]
                        .holdings
                        .iter()
                        .any(|s| s.alive && s.owner == owner && s.block == block_id)
            })
            .count();
        // R_actual = 1.0 if ≥ k_eff alive holders (block reconstructable), else a
        // graded fraction toward k_eff (so the median is informative, not just 0/1).
        let r_actual = if alive_holders >= k_eff {
            1.0
        } else {
            alive_holders as f64 / k_eff as f64
        };
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
