//! `sim_dynamic` — the dynamic 4R simulation harness (design `sim_dynamic_design.md`).
//!
//! A time-loop harness on top of the shared `viaticum_core::four_r` decision kernel.
//! It extends the established 4-layer sim pattern (generator / observer / engine /
//! evaluator) from one-shot probes to a DYNAMIC, stateful, multi-tick run with
//! agent nodes (design §6).
//!
//! ## What it is for (design §3)
//!
//! Experiment-1 (`run_experiment_1`): HONEST convergence of the 4R model under
//! dynamics/scale/horizon. The Phase-1 Python sims fed the storage-oracle
//! (`S = STORAGE_RATIOS[archetype]`) straight into the trust formula, so their
//! ranking τ was inflated. Here the archetype lives ONLY in god-view and gates
//! BEHAVIOUR; the kernel sees only first-hand consequences (PoS pass/fail, capital,
//! reject/drop, address). The honest result may be LOWER than the oracle-inflated
//! Phase-1 (τ≈0.97) — that is the real number to report.
//!
//! ## The four layers
//!
//! * [`generator`] — hidden god-view world (archetypes, calendar, capital state).
//! * [`observer`] — the single anti-oracle boundary: god-view → first-hand obs.
//! * [`engine`] — the per-tick loop; calls the kernel each tick (place / eviction /
//!   capital), all through the observer.
//! * [`evaluator`] — god-view scorer for the three metrics; never feeds a decision.
//!
//! ## Anti-oracle (design §1, §10.H)
//!
//! The crate edge runs one way (`viaticum-sim` → `viaticum-core`), so a kernel fn
//! physically cannot name the god-view types. The remaining discipline is what the
//! observer WRITES into legal fields: it SAMPLES the hidden truth (§10.B), it does
//! not copy a probability. The regression test (`tests::anti_oracle_*`) asserts two
//! nodes differing ONLY in hidden archetype produce bit-identical first-hand obs.

#[cfg(test)]
mod tests;

pub mod engine;
pub mod evaluator;
pub mod generator;
pub mod observer;

use viaticum_core::four_r::{EvictPhase, PlacementPolicy, SurfacePrior};

use crate::generator::Rng;
use crate::sim_dynamic::engine::{DynParams, fresh_capital, step};
use crate::sim_dynamic::evaluator::{
    DrMetric, NewcomerMetric, RankMetric, ReciprocityMetric, dr_metric, node_summaries,
    rank_metric, reciprocity_metric,
};
use crate::sim_dynamic::generator::{
    Archetype, Node, OwnBlock, SERVED_SAMPLE_EVERY, World, population_mix,
};

/// Build a fresh dynamic world of `n` nodes with the design §3 archetype mix.
///
/// Each node gets a disk cap, a distinct subnet (one §7 bucket per node — the
/// independence the placement assumes is earned), an own-data set to back up, and
/// a zeroed pair-capital matrix. Bandwidth is abstracted: a node backs up its
/// blocks over successive ticks (one `place` attempt per block per tick).
pub fn build_world(n: usize, params: &DynParams, seed: u64) -> World {
    let mix = population_mix(n);
    let mut rng = Rng::new(seed ^ WORLD_SALT);
    let mut nodes = Vec::with_capacity(n);
    for (i, &arch) in mix.iter().enumerate() {
        // Disk cap: enough to hold a healthy multiple of its own backup load, so
        // Regime-1 fills before contention bites. Hoarders advertise a normal disk
        // but reject — that is behaviour, not capacity.
        let disk_cap = 200.0 + rng.range(0.0, 100.0);
        let own_blocks: Vec<OwnBlock> = (0..params.blocks_per_node)
            .map(|b| OwnBlock {
                id: b,
                volume: params.block_volume,
                // Importance spread across a node's own blocks so the ι-ladder is
                // non-trivial on each holder.
                iota: 0.2 + 0.6 * (b as f64) / (params.blocks_per_node.max(2) - 1) as f64,
                placements: Vec::new(),
            })
            .collect();
        nodes.push(Node {
            id: i as u64,
            archetype: arch,
            disk_cap,
            holdings: Vec::new(),
            own_blocks,
            addr_subnet: i as u32,
            master_byte: i as u8,
            evict_phase: EvictPhase::default(),
            present: true,
            joined_tick: 0,
        });
    }
    World {
        nodes,
        seed,
        tick: 0,
        capital: fresh_capital(n),
        next_block_id: vec![params.blocks_per_node; n],
        served: vec![vec![0.0; n]; n],
        served_series: Vec::new(),
        served_regime1_snapshot: None,
    }
}

/// Stable salt for the world-build RNG (kept out of the PoS/online streams).
const WORLD_SALT: u64 = 0x0B07_57AB_1E5E_EDED;

/// The full Experiment-1 report (design §7).
#[derive(Debug, Clone)]
pub struct Experiment1Report {
    /// Node count and tick budget used.
    pub n_nodes: usize,
    pub regime1_ticks: u64,
    pub regime2_ticks: u64,
    /// Metric (a): rank/convergence (gap + ρ).
    pub rank: RankMetric,
    /// Metric (b): reciprocity.
    pub reciprocity: ReciprocityMetric,
    /// Metric (c): DR sanity.
    pub dr: DrMetric,
    /// Newcomer probe.
    pub newcomer: NewcomerMetric,
}

/// Configuration of an Experiment-1 run.
#[derive(Debug, Clone, Copy)]
pub struct Experiment1Config {
    pub n_nodes: usize,
    /// Regime-1 (fill) ticks — disks fill, no contention.
    pub regime1_ticks: u64,
    /// Regime-2 (steady) ticks — full disks, eviction/ranking play.
    pub regime2_ticks: u64,
    /// DR victims sampled at the end of Regime-2.
    pub dr_victims: usize,
    pub seed: u64,
}

impl Default for Experiment1Config {
    fn default() -> Self {
        // ~200 nodes, ~2-3 years of weekly ticks (≈ 130 ticks total), as design §7.
        Experiment1Config {
            n_nodes: 200,
            regime1_ticks: 40,
            regime2_ticks: 90,
            dr_victims: 30,
            seed: 0x00E1_5EED,
        }
    }
}

/// Run the full honest-convergence experiment (design §7 + §10.I newcomer probe).
///
/// Sequence: Regime-1 fill → Regime-2 steady → inject ONE newcomer into the mature
/// network and watch it bootstrap. Deterministic in `cfg.seed`.
pub fn run_experiment_1(cfg: Experiment1Config) -> Experiment1Report {
    let params = DynParams::default();
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();

    let mut world = build_world(cfg.n_nodes, &params, cfg.seed);

    // --- Regime-1: fill (disks fill, abundance, no contention) ---
    for _ in 0..cfg.regime1_ticks {
        step(&mut world, &params, &prior, &policy);
        // Sample the inbound-served time-series every SERVED_SAMPLE_EVERY ticks so
        // the Freeloader-vs-Reliable decay trend is observable across the run.
        if world.tick.is_multiple_of(SERVED_SAMPLE_EVERY) {
            world.sample_served_series();
        }
    }
    // Boundary sample: end of Regime-1 (the snapshot §10.E asks for explicitly).
    world.sample_served_series();
    let regime1_end_tick = world.tick;
    // Freeze the served-integral at the Regime-1 boundary, so reciprocity can be
    // computed on the Regime-2 WINDOW (`served_now − snapshot`).
    world.served_regime1_snapshot = Some(world.served.clone());

    // --- Regime-2: steady state (full disks, eviction/ranking) ---
    for _ in 0..cfg.regime2_ticks {
        step(&mut world, &params, &prior, &policy);
        if world.tick.is_multiple_of(SERVED_SAMPLE_EVERY) {
            world.sample_served_series();
        }
    }
    // Boundary sample: end of Regime-2.
    world.sample_served_series();

    // --- Metrics at the end of Regime-2 (god-view) ---
    let summaries = node_summaries(&world, &prior);
    let rank = rank_metric(&summaries);
    let reciprocity = reciprocity_metric(&world, regime1_end_tick);
    let dr = dr_metric(&world, params.k_eff, cfg.dr_victims, cfg.seed ^ 0xD11);

    // --- Newcomer probe (§10.I): inject ONE reliable newcomer, measure T_boot ---
    let newcomer = run_newcomer_probe(&mut world, &params, &prior, &policy, 30);

    Experiment1Report {
        n_nodes: cfg.n_nodes,
        regime1_ticks: cfg.regime1_ticks,
        regime2_ticks: cfg.regime2_ticks,
        rank,
        reciprocity,
        dr,
        newcomer,
    }
}

/// Inject ONE new Reliable node into the mature network and run `probe_ticks` more
/// ticks, measuring the two `T_boot` signals (design §10.I):
///   (i) ticks until the newcomer's own high-ι block first reaches `r_target`
///       placement depth (≥ k_eff alive holders),
///   (ii) ticks until the newcomer is first CHOSEN as a holder by ≥1 established
///       owner.
fn run_newcomer_probe(
    world: &mut World,
    params: &DynParams,
    prior: &SurfacePrior,
    policy: &PlacementPolicy,
    probe_ticks: u64,
) -> NewcomerMetric {
    let n = world.nodes.len();
    let newcomer_idx = n;
    let join_tick = world.tick;

    // Grow the capital matrix to (n+1) and add the newcomer node.
    for row in world.capital.iter_mut() {
        row.push(crate::sim_dynamic::generator::PairCapital::default());
    }
    world.capital.push(
        (0..=n)
            .map(|_| crate::sim_dynamic::generator::PairCapital::default())
            .collect(),
    );
    // Grow the served-integral matrix to (n+1) in lock-step (so [holder][owner]
    // indices stay valid for the new node).
    for row in world.served.iter_mut() {
        row.push(0.0);
    }
    world.served.push(vec![0.0; n + 1]);

    // A high-ι own block so the placement-depth probe is meaningful.
    let own_blocks = vec![OwnBlock {
        id: 0,
        volume: params.block_volume,
        iota: 0.9,
        placements: Vec::new(),
    }];
    world.nodes.push(Node {
        id: newcomer_idx as u64,
        archetype: Archetype::Reliable,
        disk_cap: 250.0,
        holdings: Vec::new(),
        own_blocks,
        addr_subnet: newcomer_idx as u32,
        master_byte: (newcomer_idx % 256) as u8,
        evict_phase: EvictPhase::default(),
        present: true,
        joined_tick: join_tick,
    });
    world.next_block_id.push(1);

    let mut t_boot_placed: Option<u64> = None;
    let mut t_boot_chosen: Option<u64> = None;

    for _ in 0..probe_ticks {
        step(world, params, prior, policy);
        let elapsed = world.tick - join_tick;

        // (i) newcomer's own block at r_target depth?
        if t_boot_placed.is_none() {
            let alive_holders = (0..world.nodes.len())
                .filter(|&h| {
                    h != newcomer_idx
                        && world.nodes[h].present
                        && world.nodes[h]
                            .holdings
                            .iter()
                            .any(|s| s.alive && s.owner == newcomer_idx && s.block == 0)
                })
                .count();
            if alive_holders >= params.k_eff {
                t_boot_placed = Some(elapsed);
            }
        }
        // (ii) newcomer chosen as a holder by ≥1 established owner?
        if t_boot_chosen.is_none() {
            let chosen = world.nodes[newcomer_idx]
                .holdings
                .iter()
                .any(|s| s.alive && s.owner != newcomer_idx);
            if chosen {
                t_boot_chosen = Some(elapsed);
            }
        }
        if t_boot_placed.is_some() && t_boot_chosen.is_some() {
            break;
        }
    }

    NewcomerMetric {
        t_boot_placed,
        t_boot_chosen,
    }
}

/// Pretty-print the Experiment-1 report (structured, for the on-demand runner).
pub fn print_experiment_1(report: &Experiment1Report) {
    println!("=== Experiment-1: honest 4R convergence (dynamic, anti-oracle) ===");
    println!();
    println!(
        "scale: {} nodes, regime-1 {} ticks (fill) + regime-2 {} ticks (steady), weekly ticks",
        report.n_nodes, report.regime1_ticks, report.regime2_ticks
    );
    println!();
    println!("-- Metric (a): convergence / rank (design §10.D) — THREE honest aggregations --");
    println!(
        "  (1) SUM earned G        Reliable = {:.4}   bad = {:.4}   gap = {:+.4}",
        report.rank.mean_g_reliable, report.rank.mean_g_bad, report.rank.gap
    );
    println!(
        "  (2) MEAN per-pair G     Reliable = {:.4}   bad = {:.4}   gap = {:+.4}",
        report.rank.mean_per_pair_g_reliable,
        report.rank.mean_per_pair_g_bad,
        report.rank.gap_per_pair
    );
    println!(
        "  (3) BREADTH served pairs Reliable = {:.4}   bad = {:.4}   ratio = {:.4}×",
        report.rank.breadth_reliable, report.rank.breadth_bad, report.rank.breadth_ratio
    );
    println!(
        "  (4) SECONDARY ρ(surface,truth)    = {:.4}",
        report.rank.spearman_rho
    );
    println!();
    println!("  INTERPRETATION (honest, FIX 1):");
    println!("    The SUM gap (1) is large and POSITIVE, but it is BREADTH-DRIVEN: the breadth");
    println!(
        "    ratio (3) = {:.2}× tracks the accept_rate dial (Reliable 1.0 vs Hoarder 0.2 /",
        report.rank.breadth_ratio
    );
    println!("    Freeloader 0.1) almost exactly, so SUM ≈ breadth × per-pair predominantly re-");
    println!("    measures the input accept dial via served-pair COUNT (total foregone service /");
    println!("    reject-breadth). The per-pair surface QUALITY (2) — what the kernel actually");
    println!(
        "    ranks — goes the WRONG way (gap {:+.2} < 0, confirmed by ρ = {:.2} < 0): a",
        report.rank.gap_per_pair, report.rank.spearman_rho
    );
    println!("    SELECTION EFFECT — a node only forms a surface estimate for holders that");
    println!("    ACCEPTED its data, so per-pair surface cannot see accept-breadth and even anti-");
    println!(
        "    correlates. The kernel separates exploiters via total foregone service / reject-"
    );
    println!("    breadth, NOT per-pair surface quality.");
    println!();
    println!(
        "-- Metric (b): reciprocity on god-view served-volume TIME-INTEGRAL (design §10.E) --"
    );
    println!(
        "  honest-pair balance ratios (Regime-2 window integral): {} pairs, median = {:.4}  (1.0 = balanced)",
        report.reciprocity.honest_balance_ratios.len(),
        report.reciprocity.median_honest_balance
    );
    println!(
        "  inbound served (cumulative integral, end of Regime-2): Freeloader = {:.4}   Reliable = {:.4}",
        report.reciprocity.freeloader_inbound_served, report.reciprocity.reliable_inbound_served
    );
    println!("  Freeloader-relative-to-Reliable inbound SHARE (decay test; a SHRINK ⇒ H3 bites):");
    println!(
        "    end of Regime-1 = {:.4}   →   end of Regime-2 = {:.4}",
        report.reciprocity.freeloader_share_r1_end, report.reciprocity.freeloader_share_r2_end
    );
    print_served_trend(&report.reciprocity);
    println!();
    println!("-- Metric (c): DR sanity (design §10.F) --");
    println!(
        "  victims sampled = {}, median R_actual = {:.4}, systematic zeros = {}",
        report.dr.victim_survivals.len(),
        report.dr.median_survival,
        report.dr.zero_count
    );
    println!(
        "  PASS (median > 0.9 AND no systematic zeros) = {}",
        report.dr.pass
    );
    println!();
    println!("-- Newcomer probe into the mature network (design §10.I) --");
    println!(
        "  T_boot (own block reaches r_target depth) = {}",
        fmt_opt(report.newcomer.t_boot_placed)
    );
    println!(
        "  T_boot (first chosen as a holder)          = {}",
        fmt_opt(report.newcomer.t_boot_chosen)
    );
    println!();
    println!("HONEST FRAME (design §7): the gap/ρ may be LOWER than Phase-1's oracle-inflated");
    println!("τ≈0.97 — that is the real, un-poisoned result.");
}

fn fmt_opt(x: Option<u64>) -> String {
    match x {
        Some(v) => format!("{v} ticks"),
        None => "never (within probe)".to_string(),
    }
}

/// Print the inbound-served time-series (Freeloader vs Reliable) and an HONEST read
/// of whether the Freeloader's relative inbound decays at this horizon (design
/// §10.E). If the share does not shrink, that is REPORTED — not tuned away.
fn print_served_trend(recip: &crate::sim_dynamic::evaluator::ReciprocityMetric) {
    println!("  inbound-served time-series (tick: Freeloader / Reliable, cumulative integral):");
    for s in &recip.series {
        let share = if s.reliable_inbound > 0.0 {
            s.freeloader_inbound / s.reliable_inbound
        } else {
            f64::NAN
        };
        println!(
            "    t={:>3}: F={:>10.2}  R={:>10.2}  (F/R share = {:.4})",
            s.tick, s.freeloader_inbound, s.reliable_inbound, share
        );
    }
    // Honest verdict on the H3 decay signal.
    let r1 = recip.freeloader_share_r1_end;
    let r2 = recip.freeloader_share_r2_end;
    if r1.is_finite() && r2.is_finite() {
        // A meaningful decay is a clear DROP in the Freeloader's relative inbound.
        let drop = r1 - r2;
        if drop > 0.05 {
            println!(
                "    H3 read: Freeloader inbound share SHRANK ({r1:.4} → {r2:.4}) — the attractor bites at this horizon."
            );
        } else if drop < -0.05 {
            println!(
                "    H3 read: Freeloader inbound share GREW ({r1:.4} → {r2:.4}) — NO decay at this horizon (honest null)."
            );
        } else {
            println!(
                "    H3 read: Freeloader inbound share ≈ flat ({r1:.4} → {r2:.4}) — signal weak at 200 nodes / ~130 ticks."
            );
            println!(
                "             H3 needs a longer horizon and/or harder disk contention (replication-depth → k_eff) to engage."
            );
        }
    } else {
        println!(
            "    H3 read: insufficient bidirectional inbound to judge (too few honest pairs)."
        );
    }
}
