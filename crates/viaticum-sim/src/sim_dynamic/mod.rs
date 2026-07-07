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
pub mod repair_storm;

use viaticum_core::four_r::{EvictPhase, PlacementPolicy, SurfacePrior};

use crate::generator::Rng;
use crate::sim_dynamic::engine::{DynParams, fresh_capital, step};
use crate::sim_dynamic::evaluator::{
    ContentionMetric, DrMetric, DropRankingMetric, NewcomerMetric, Pillar1Metric, RankMetric,
    ReciprocityMetric, contention_metric, drop_ranking_metric, legacy_dr_metric, node_summaries,
    pillar1_metric, rank_metric, reciprocity_metric,
};
use crate::sim_dynamic::generator::{
    Archetype, DiskProfile, GiverTier, Node, OwnBlock, SERVED_SAMPLE_EVERY, World, giver_tier_mix,
    population_mix,
};

/// Build a fresh dynamic world of `n` nodes with the design §3 archetype mix.
///
/// Each node gets a disk cap, a distinct subnet (one §7 bucket per node — the
/// independence the placement assumes is earned), an own-data set to back up, and
/// a zeroed pair-capital matrix. Bandwidth is abstracted: a node backs up its
/// blocks over successive ticks (one `place` attempt per block per tick).
pub fn build_world(n: usize, params: &DynParams, seed: u64) -> World {
    // Shuffle the archetype→index assignment (BUGFIX: tie-break artifact). The
    // eviction tie-break, when the reciprocity key g_ho ties (the ~98% g_ho=0 mass
    // under sparse reciprocity), falls through observed_tau (constant) to a STABLE
    // sort by owner node-index — so the LOWEST-index owners are dropped first.
    // `population_mix` is block-ordered (Reliable at indices 0..0.4n, Freeloader
    // last), so without this shuffle the artifact systematically over-evicts
    // Reliable and NEVER evicts Freeloader (measured: 91% of evictions hit the
    // low-index half), FABRICATING the "parasite wins" inversion. A seeded shuffle
    // decorrelates archetype from index; the among-tie order is then archetype-
    // neutral. (Deterministic: separate salted stream, leaves the disk draws below
    // bit-identical.)
    let mix = {
        let mut m = population_mix(n);
        let mut shuf = Rng::new(seed ^ 0x5EED_A53C_7112_BB01);
        for i in (1..m.len()).rev() {
            let j = ((shuf.unit() * (i as f64 + 1.0)) as usize).min(i);
            m.swap(i, j);
        }
        m
    };
    let tiers = giver_tier_mix(n, seed);
    let mut rng = Rng::new(seed ^ WORLD_SALT);
    let mut nodes = Vec::with_capacity(n);
    for (i, &arch) in mix.iter().enumerate() {
        let tier = tiers[i];
        // Disk cap: a modest physical disk SHARED between own data and foreign
        // holdings. It is deliberately NOT a huge multiple of the backup load — under
        // own-data growth (§A.2) the disk fills and the world contends (utilization→1),
        // which is the whole point. Hoarders advertise a normal disk but reject — that
        // is behaviour (will), not capacity.
        let disk_cap = params.disk_cap_base + rng.range(0.0, params.disk_cap_spread);
        // God-view disk profile (§A layer-2): own data sized from the tier's own:free
        // band, growing each tick. Own:free = r ⇒ own = cap·r/(1+r) leaves free = cap/(1+r).
        // A seeded ±15% jitter per node so a tier is a BAND, not a single point.
        let ratio_jitter = 1.0 + rng.range(-0.15, 0.15);
        let own_to_free = (tier.own_to_free_centre() * ratio_jitter).max(0.05);
        let own_data = disk_cap * own_to_free / (1.0 + own_to_free);
        // Seeded growth (gb/tick) = fractional rate × initial own data (§A.2 linear).
        let own_growth_per_tick = own_data * tier.own_growth_frac_per_tick();
        let own_blocks: Vec<OwnBlock> = (0..params.blocks_per_node)
            .map(|b| OwnBlock {
                id: b,
                volume: params.block_volume,
                // Importance spread across a node's own blocks so the ι-ladder is
                // non-trivial on each holder.
                iota: 0.2 + 0.6 * (b as f64) / (params.blocks_per_node.max(2) - 1) as f64,
                placements: Vec::new(),
                floor_ever_met: false,
                floor_deficit_since: None,
                to_restore: false,
            })
            .collect();
        // World-v2 §9.1 incremental arrival: in the ONE-SHOT world (`incremental =
        // false`) every node is live at t=0 (the old degenerate = infinite-bandwidth
        // random graph). In the STREAM world a fraction `n0_frac` is live at t=0 and
        // the rest join per a seeded schedule uniformly over `[1, T_join]`
        // (T_join = join_horizon·t_join_frac). Deterministic: one salted draw per node.
        let joined_tick = join_schedule(i, params, seed);
        nodes.push(Node {
            id: i as u64,
            archetype: arch,
            disk_cap,
            disk: DiskProfile {
                tier,
                own_data,
                own_growth_per_tick,
            },
            holdings: Vec::new(),
            own_blocks,
            addr_subnet: i as u32,
            master_byte: i as u8,
            evict_phase: EvictPhase::default(),
            // A not-yet-joined node starts ABSENT and is activated at its `joined_tick`
            // by `engine::step`. Departure (churn) only fires on PRESENT nodes, so a
            // node that is absent at tick T with `joined_tick == T` can only be a
            // not-yet-joined node (never a departed one) — the activation is unambiguous
            // without a separate "has joined" flag.
            present: joined_tick == 0,
            joined_tick,
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
        eviction_log: Vec::new(),
        ticks_with_eviction: 0,
        first_earned_g: vec![None; n],
        first_own_accept: vec![None; n],
        preempt_count: 0,
        cap_trim_count: 0,
        repair_stat: crate::sim_dynamic::generator::RepairStat::default(),
        burn_ann_count: 0,
        burn_silent_count: 0,
        pending_silent_loss: Vec::new(),
        // R̂-calibration log OFF by default (sim_diag/tests pay nothing); the sim_adv runner
        // flips `pred_log_enabled` on to collect the dataset. Metric-only, no decision reads it.
        pred_log: Vec::new(),
        pred_log_enabled: false,
    }
}

/// World-v2 §9.1 incremental-arrival schedule: the tick node `i` JOINS the network.
///
/// One salted uniform draw `r ∈ [0,1)` per node. If `r < n0_frac` the node is live at
/// t=0 (the `~n0` bootstrap set); otherwise it joins uniformly over `[1, T_join]` where
/// `T_join = round(join_horizon_ticks · t_join_frac)`. When `incremental = false`
/// every node joins at t=0 (the one-shot world, for A/B). Deterministic in the seed.
pub fn join_schedule(i: usize, params: &DynParams, seed: u64) -> u64 {
    if !params.incremental {
        return 0;
    }
    let r = Rng::derive(seed ^ JOIN_SALT, i as u64, 0, 0, 0).unit();
    let n0 = params.n0_frac.clamp(0.0, 1.0);
    if r < n0 {
        return 0;
    }
    let t_join_max = (params.join_horizon_ticks as f64 * params.t_join_frac)
        .round()
        .max(1.0);
    let frac = if n0 < 1.0 { (r - n0) / (1.0 - n0) } else { 0.0 };
    1 + (frac * (t_join_max - 1.0)).round() as u64
}

/// Stable salt for the incremental-join RNG stream (kept off the disk/PoS streams).
const JOIN_SALT: u64 = 0x101_7A17_3011_1EDA;

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
    /// Phase-1 §A acceptance: did the world REACH contention (utilization→1)?
    pub contention: ContentionMetric,
    /// Phase-1 §D.1: pillar-1 efficiency (R_actual / own-disk per archetype).
    pub pillar1: Pillar1Metric,
    /// Phase-1 §D.1: drop-ranking (evicted owner correlates with low served).
    pub drop_ranking: DropRankingMetric,
}

impl Experiment1Report {
    /// Phase-1 §A acceptance: did the world REACH contention (utilization→1)? TRUE
    /// iff mean end-of-run utilization > 0.80 AND eviction fired on > 25% of ticks.
    /// This is the make-or-break gate Exp-1 failed (permanent abundance, no eviction).
    pub fn contention_reached(&self) -> bool {
        let c = &self.contention;
        let pct_ticks = if c.total_ticks > 0 {
            c.ticks_with_eviction as f64 / c.total_ticks as f64
        } else {
            0.0
        };
        c.mean_utilization_end > 0.80 && pct_ticks > 0.25
    }
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
    /// Monte-Carlo samples per block for the `R_actual(T)` estimator (design §D.1).
    pub mc_samples: usize,
    /// Monte-Carlo survival horizon `T` in ticks (design §D.1 / W10).
    pub mc_horizon_ticks: u64,
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
            mc_samples: 400,
            mc_horizon_ticks: 26, // ~6 months — cold-backup loyalty horizon (W10)
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
    let dr = legacy_dr_metric(&world, params.k_eff, cfg.dr_victims, cfg.seed ^ 0xD11);

    // --- Phase-1 §A/§D.1: contention reached? pillar-1 efficiency? drop-ranking? ---
    // Computed on the MATURE contended network BEFORE the newcomer probe mutates it.
    let contention = contention_metric(&world, params.hyst.s_hard);
    let pillar1 = pillar1_metric(
        &world,
        params.k_eff,
        cfg.mc_horizon_ticks,
        cfg.mc_samples,
        cfg.seed ^ 0x9C_11,
    );
    let drop_ranking = drop_ranking_metric(&world);

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
        contention,
        pillar1,
        drop_ranking,
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
        floor_ever_met: false,
        floor_deficit_since: None,
        to_restore: false,
    }];
    // A T1-loose newcomer (plenty of free disk to lend) so the bootstrap probe is
    // about TRUST accrual, not the newcomer's own disk being full.
    let nc_cap = 250.0;
    let nc_own_to_free = GiverTier::T1.own_to_free_centre();
    world.nodes.push(Node {
        id: newcomer_idx as u64,
        archetype: Archetype::Reliable,
        disk_cap: nc_cap,
        disk: DiskProfile {
            tier: GiverTier::T1,
            own_data: nc_cap * nc_own_to_free / (1.0 + nc_own_to_free),
            own_growth_per_tick: 0.0,
        },
        holdings: Vec::new(),
        own_blocks,
        addr_subnet: newcomer_idx as u32,
        master_byte: (newcomer_idx % 256) as u8,
        evict_phase: EvictPhase::default(),
        present: true,
        joined_tick: join_tick,
    });
    world.next_block_id.push(1);
    // Grow the world-v2 §9 newcomer-trace vectors in lock-step with the node count.
    world.first_earned_g.push(None);
    world.first_own_accept.push(None);

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
    println!("  INTERPRETATION (Phase-1 contention regime):");
    println!("    Metric (a)'s earned-G SUM/breadth framing is RETIRED (design §G supersede): it");
    println!("    was an ABUNDANCE artifact — the reject-breadth headline re-measured the accept");
    println!("    dial, and the per-pair selection effect made it a tautology. Under contention");
    println!(
        "    the SUM gap even INVERTS (exploiters accumulate more raw G per pair from the few"
    );
    println!(
        "    deep partners they keep), which is exactly why we do NOT headline it. The Phase-1"
    );
    println!(
        "    headline is the PILLAR-1 efficiency (R_actual / own-disk) + drop-ranking below —"
    );
    println!("    the MECHANISM under contention, not the input accept dial. (Numbers shown for");
    println!("    continuity only; do not read a ranking into the metric-(a) sign.)");
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
    print_phase1(report);
}

/// Print the Phase-1 §A/§D.1 results: contention reached, pillar-1 efficiency,
/// drop-ranking. This is the make-or-break section (design §A: utilization→1).
fn print_phase1(report: &Experiment1Report) {
    let c = &report.contention;
    println!("=== PHASE-1 (§A/§D.1): CONTENTION + PILLAR-1 EFFICIENCY ===");
    println!();
    println!("-- §A acceptance: did the world REACH contention (utilization→1)? --");
    println!(
        "  mean φ (free-ratio) at end   = {:.4}   (→0 ⇒ contended)",
        c.mean_phi_end
    );
    println!(
        "  mean utilization (1−φ) at end = {:.4}   (→1 ⇒ contended; THE make-or-break)",
        c.mean_utilization_end
    );
    println!(
        "  nodes in eviction band (φ<s_hard) = {:.1}%",
        c.frac_nodes_in_eviction_band * 100.0
    );
    let pct_ticks = if c.total_ticks > 0 {
        c.ticks_with_eviction as f64 / c.total_ticks as f64 * 100.0
    } else {
        0.0
    };
    println!(
        "  eviction fired on {}/{} ticks ({:.1}%), {} total eviction events",
        c.ticks_with_eviction, c.total_ticks, pct_ticks, c.total_evictions
    );
    let contended = report.contention_reached();
    println!(
        "  VERDICT: {} (utilization > 0.80 AND eviction fired on > 25% of ticks)",
        if contended {
            "CONTENTION REACHED"
        } else {
            "NOT CONTENDED (still abundance — make-or-break FAILED)"
        }
    );
    println!();
    let p = &report.pillar1;
    println!("-- §D.1 pillar-1 efficiency: R_actual(T) of own data / own-disk given --");
    println!(
        "  Reliable   : R_actual = {:.4}   own-disk-given = {:.2}   efficiency = {:.6}",
        p.mean_r_actual_reliable, p.mean_given_reliable, p.efficiency_reliable
    );
    println!(
        "  Hoarder    : R_actual = {:.4}   own-disk-given = {:.2}   efficiency = {:.6}",
        p.mean_r_actual_hoarder, p.mean_given_hoarder, p.efficiency_hoarder
    );
    println!(
        "  Freeloader : R_actual = {:.4}   own-disk-given = {:.2}   efficiency = {:.6}",
        p.mean_r_actual_freeloader, p.mean_given_freeloader, p.efficiency_freeloader
    );
    println!("  EXPECTED: Reliable achieves HIGHER R_actual/own-disk than Freeloader/Hoarder");
    println!();
    let d = &report.drop_ranking;
    println!("-- §D.1 drop-ranking: does eviction drop LOW-served owners first? --");
    println!(
        "  eviction events scored = {}   mean evicted served-rank = {:.4}   (<0.5 ⇒ working)",
        d.events_scored, d.mean_evicted_served_rank
    );
    println!(
        "  fraction of drops hitting bottom-half served owners = {:.1}%   (>50% ⇒ working)",
        d.frac_below_median * 100.0
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
