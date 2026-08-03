//! `sim_dynamic::repair_storm` — the correlated-holder-death ("repair-storm") god-view
//! diagnostic (aggregate-economy review §5.2; sim_diag section 7).
//!
//! ## What it tests
//!
//! The aggregate review raised a HYPOTHETICAL aggregate mode: individual optimisation
//! herds symbols onto the best surfaces (the T1-NAS holders), so the death of ONE
//! popular holder drops MANY owners' blocks below floor at the same instant → a
//! synchronised repair spike → a possible bandwidth cascade. The pair-local ζ-analysis
//! cannot see this cross-node mode; only a god-view sim can.
//!
//! Ilya's counter-hypothesis (what we are TESTING, not assuming): "at our speeds this is
//! nothing" — the PoS detection cadence is weeks (`DAYS_PER_TICK = 7`), so owners notice
//! their losses at STAGGERED ticks, the synchronous shock is smeared across the detection
//! window, redundancy carries the blocks through, and no cascade materialises.
//!
//! ## The instrument (all god-view — never a kernel input)
//!
//! 1. **Shock injection** ([`select_top_holders`] + [`inject_shock`]): at tick `T_shock`
//!    kill the top-`K%` holders by POPULARITY (count of alive foreign symbols they hold —
//!    god-view truth, not an owner-visible signal). Killing = `present=false` + all their
//!    held symbols die, synchronously and targeted (a churn shock, not random attrition).
//! 2. **Post-shock trajectory** ([`run_repair_storm`]): per tick to the horizon, record
//!    the under-replicated block count (`< k_eff` alive floor holders), the outstanding
//!    repair demand (symbols owed to fill the spread cap), the engine's DETECTION-GATED
//!    repair concurrency (owners repairing this tick), the detected repair front (blocks)
//!    and its SYMBOL demand, and the aggregate upload bandwidth ceiling (present nodes ×
//!    per-node budget).
//! 3. **Detection mode** (the crux): `detection_delay_max = 0` ⇒ INSTANT (owner refills
//!    next tick); `> 0` ⇒ LATENT — each owner discovers a below-floor block at a seeded
//!    uniform offset in `[0, delay_max]` ticks (the PoS cadence), staggering the repairs.
//!
//! ## Units, after SIM-UNIFICATION (read this before touching the demand columns)
//!
//! The R̂ loop discovers a block's symbol need by placing, so "detected demand" splits into
//! two quantities that must not be confused: [`StormTick::detected_blocks_below_target`]
//! (BLOCKS — the width of the repair front) and [`StormTick::detected_demand_symbols_lb`]
//! (SYMBOLS — a documented LOWER BOUND). Only the latter may be compared against
//! [`StormTick::bandwidth_symbols`].
//!
//! The headline numbers: peak concurrent repairers (instant vs latent), whether any tick's
//! repair demand exceeds the aggregate bandwidth, and — the make-or-break — how many blocks
//! are actually LOST (`< k_eff` and not recovered by the horizon).

use viaticum_core::four_r::{PlacementPolicy, SurfacePrior};

use crate::sim_dynamic::build_world;
use crate::sim_dynamic::engine::{DynParams, per_node_upload_budget, step};
use crate::sim_dynamic::generator::World;

/// Configuration of one repair-storm run.
#[derive(Debug, Clone)]
pub struct RepairStormConfig {
    /// The world regime (block volume, bandwidth `U`, cream, preemption, …). The run
    /// overrides only `repair_detection_delay_max` from `detection_delay_max` below.
    pub base_params: DynParams,
    /// Node count.
    pub n_nodes: usize,
    /// Run seed (every draw keys off it → the whole run is bit-reproducible).
    pub seed: u64,
    /// Warm-up ticks before the shock — the tick the shock fires at (`T_shock`).
    pub warmup_ticks: u64,
    /// Ticks after the shock to observe recovery.
    pub post_ticks: u64,
    /// Fraction of present holders to kill, as a PERCENT (`1.0` = top 1%). `0.0` = a
    /// no-shock control (measures the background churn baseline for the same seed/mode).
    pub k_percent: f64,
    /// Detection latency window (ticks). `0` = instant; `> 0` = latent PoS cadence.
    pub detection_delay_max: u64,
}

/// One post-shock tick of the trajectory (god-view).
#[derive(Debug, Clone, Copy)]
pub struct StormTick {
    /// Absolute world tick.
    pub tick: u64,
    /// Ticks since the shock fired (`tick − T_shock`).
    pub since_shock: u64,
    /// Present nodes this tick.
    pub present: usize,
    /// Established present-owner blocks with `< k_eff` alive floor holders (at risk).
    pub under_k_blocks: usize,
    /// Symbols owed to fill every established present-owner block back to the `n_symbols`
    /// SPREAD CAP (a god-view capacity PROXY for the outstanding repair demand — detected
    /// or not). SIM-UNIFICATION: the cap is no longer the owner's placement goal (that is
    /// `R̂ ≥ r_target`), so this over-states the demand of a block whose target is met with
    /// fewer holders; it is kept as the pre-existing upper-bound instrument.
    pub outstanding_demand_symbols: usize,
    /// Owners the engine actually repaired this tick (detection-gated concurrency).
    pub owners_repairing: usize,
    /// **BLOCKS** the engine's detection gate exposed as below target this tick — the WIDTH
    /// of the repair front. SIM-UNIFICATION: this was a SYMBOL count (`Σ n_symbols − floor`);
    /// the R̂ loop discovers the symbol demand by placing, so the block count is what the gate
    /// itself knows. NOT comparable to a bandwidth (see the field below). See
    /// [`crate::sim_dynamic::generator::RepairStat::detected_blocks_below_target`].
    pub detected_blocks_below_target: usize,
    /// **SYMBOLS** the same detected below-target blocks owe this tick, as a documented
    /// LOWER BOUND (`Σ min(max(1, min_width − alive), n_symbols − floor)`) — the demand side
    /// of the demand-vs-bandwidth comparison, in the SAME unit as
    /// [`StormTick::bandwidth_symbols`]. See
    /// [`crate::sim_dynamic::generator::RepairStat::detected_demand_symbols_lb`].
    pub detected_demand_symbols_lb: usize,
    /// Aggregate upload bandwidth ceiling this tick (present × per-node budget), symbols.
    pub bandwidth_symbols: usize,
}

/// The full repair-storm report.
#[derive(Debug, Clone)]
pub struct RepairStormReport {
    pub n_nodes: usize,
    pub k_percent: f64,
    pub detection_delay_max: u64,
    pub t_shock: u64,
    pub k_eff: usize,
    pub n_symbols: usize,
    /// Holders killed by the shock.
    pub victims_killed: usize,
    /// Alive foreign symbols destroyed in the shock (the synchronous loss).
    pub victim_symbols_killed: usize,
    /// Established present-owner blocks `< k_eff` at `T_shock` (the pre-shock baseline).
    pub baseline_under_k: usize,
    /// Established present-owner blocks at `T_shock` (the durability denominator).
    pub baseline_established_blocks: usize,
    /// Per post-shock tick trajectory.
    pub trajectory: Vec<StormTick>,
    /// Peak `under_k_blocks` over the trajectory (how deep redundancy dipped).
    pub peak_under_k: usize,
    /// Peak concurrent repairers over the trajectory (the synchronisation headline).
    pub peak_owners_repairing: usize,
    /// Peak detection-gated repair front (BLOCKS below target per tick) over the
    /// trajectory. SIM-UNIFICATION: blocks, not symbols (see [`StormTick`]).
    pub peak_detected_blocks_below_target: usize,
    /// Peak detection-gated repair DEMAND in SYMBOLS (the lower bound of
    /// [`StormTick::detected_demand_symbols_lb`]) over the trajectory — the quantity the
    /// aggregate bandwidth ceiling is compared against.
    pub peak_detected_demand_symbols_lb: usize,
    /// Peak outstanding (god-view total) repair demand (symbols/tick).
    pub peak_outstanding_demand_symbols: usize,
    /// Representative aggregate bandwidth (symbols/tick) just after the shock.
    pub bandwidth_symbols: usize,
    /// Ticks where the detection-gated repair demand EXCEEDED the aggregate bandwidth —
    /// SYMBOLS vs SYMBOLS. SIM-UNIFICATION: the demand side is the LOWER BOUND
    /// [`StormTick::detected_demand_symbols_lb`], so this is CONSERVATIVE: every counted
    /// tick certainly over-subscribed the bandwidth, and a zero here does not prove no tick
    /// ever did (a block starving for symbols the bound does not see would be missed).
    pub demand_exceeds_bandwidth_ticks: usize,
    /// Max ratio of detection-gated symbol demand (lower bound) to aggregate bandwidth
    /// (symbols) over the trajectory — one unit on both sides, and a LOWER BOUND on the true
    /// demand/bandwidth ratio.
    pub max_demand_bandwidth_ratio: f64,
    /// Established present-owner blocks still `< k_eff` at the horizon (not recovered —
    /// recoverable in principle, the owner is present and re-encodes from source).
    pub blocks_under_k_end: usize,
    /// Established present-owner blocks with ZERO alive floor holders at the horizon.
    pub blocks_zero_end: usize,
    /// Established blocks of DEPARTED non-victim owners left `< k_eff` (cascade-
    /// unrecoverable: no source to re-encode → truly lost data).
    pub blocks_orphaned_lost: usize,
    /// Established blocks of the SHOCK-VICTIM owners left `< k_eff` (the victims' own
    /// data — a direct consequence of killing them, reported separately from the cascade).
    pub blocks_victim_owned_lost: usize,
    /// Ticks after the shock until `under_k_blocks` returned to (≤) the baseline. `None`
    /// if it never recovered within the horizon.
    pub ticks_to_recover: Option<u64>,
}

/// How many alive FOREIGN symbols `holder` currently stores = its "popularity" (god-view
/// truth: the load-bearing holder-death mass). A holder never stores its own data, so
/// every alive holding is foreign; the explicit `owner != holder` filter is defensive.
pub fn holder_popularity(world: &World, holder: usize) -> usize {
    world.nodes[holder]
        .holdings
        .iter()
        .filter(|s| s.alive && s.owner != holder)
        .count()
}

/// Select the top-`k_percent`% present holders by [`holder_popularity`], breaking ties by
/// ascending node index (deterministic). `count = ⌈k_percent/100 · present⌉`, floored at 1
/// when `k_percent > 0`. `k_percent ≤ 0` selects nothing (the no-shock control).
pub fn select_top_holders(world: &World, k_percent: f64) -> Vec<usize> {
    if k_percent <= 0.0 {
        return Vec::new();
    }
    let mut present: Vec<usize> = (0..world.nodes.len())
        .filter(|&i| world.nodes[i].present)
        .collect();
    if present.is_empty() {
        return Vec::new();
    }
    // Rank by popularity DESC, then node index ASC (stable, deterministic tie-break).
    present.sort_by(|&a, &b| {
        holder_popularity(world, b)
            .cmp(&holder_popularity(world, a))
            .then(a.cmp(&b))
    });
    let count = ((k_percent / 100.0) * present.len() as f64).ceil() as usize;
    let count = count.max(1).min(present.len());
    present.truncate(count);
    present
}

/// Inject the shock: kill each victim holder (as a synchronous, targeted churn) —
/// `present = false` and every symbol it holds dies. Returns the count of alive foreign
/// symbols destroyed. The victims' OWN data (symbols they placed elsewhere) is untouched
/// here — it lives on other holders but can no longer be re-encoded (owner departed).
pub fn inject_shock(world: &mut World, victims: &[usize]) -> usize {
    let mut symbols_killed = 0usize;
    for &v in victims {
        if !world.nodes[v].present {
            continue;
        }
        world.nodes[v].present = false;
        for hs in world.nodes[v].holdings.iter_mut() {
            if hs.alive {
                hs.alive = false;
                symbols_killed += 1;
            }
        }
    }
    symbols_killed
}

/// Alive, present-holder, FLOOR (non-cream) holders of `owner`'s block `block_id` — the
/// durability count (mirrors the §5 truthful-durability metric: cream is not a guarantee).
fn alive_floor_holders(world: &World, owner: usize, block_id: usize) -> usize {
    (0..world.nodes.len())
        .filter(|&h| {
            world.nodes[h].present
                && world.nodes[h]
                    .holdings
                    .iter()
                    .any(|s| s.alive && !s.cream && s.owner == owner && s.block == block_id)
        })
        .count()
}

/// Established present-owner blocks with `< k_eff` alive floor holders (durability at risk).
fn present_under_k(world: &World, k_eff: usize) -> usize {
    let mut c = 0usize;
    for o in 0..world.nodes.len() {
        if !world.nodes[o].present {
            continue;
        }
        for b in &world.nodes[o].own_blocks {
            if b.target_ever_met && alive_floor_holders(world, o, b.id) < k_eff {
                c += 1;
            }
        }
    }
    c
}

/// Symbols owed to restore every established present-owner block to its `n_symbols` floor
/// (total outstanding repair demand, god-view — regardless of detection).
fn present_outstanding_demand(world: &World, params: &DynParams) -> usize {
    let mut d = 0usize;
    for o in 0..world.nodes.len() {
        if !world.nodes[o].present {
            continue;
        }
        for b in &world.nodes[o].own_blocks {
            if b.target_ever_met {
                let floor = alive_floor_holders(world, o, b.id);
                d += params.n_symbols.saturating_sub(floor);
            }
        }
    }
    d
}

/// Established present-owner blocks at/above the given denominator (the baseline count).
fn present_established_blocks(world: &World) -> usize {
    let mut c = 0usize;
    for o in 0..world.nodes.len() {
        if !world.nodes[o].present {
            continue;
        }
        for b in &world.nodes[o].own_blocks {
            if b.target_ever_met {
                c += 1;
            }
        }
    }
    c
}

/// Final loss scan: split established blocks by the fate of their durability at horizon.
struct LossScan {
    under_k_present: usize,
    zero_present: usize,
    orphaned_lost: usize,
    victim_owned_lost: usize,
}

fn final_loss_scan(world: &World, k_eff: usize, victims: &[usize]) -> LossScan {
    let mut s = LossScan {
        under_k_present: 0,
        zero_present: 0,
        orphaned_lost: 0,
        victim_owned_lost: 0,
    };
    for o in 0..world.nodes.len() {
        let is_victim = victims.contains(&o);
        for b in &world.nodes[o].own_blocks {
            if !b.target_ever_met {
                continue;
            }
            let floor = alive_floor_holders(world, o, b.id);
            if world.nodes[o].present {
                if floor < k_eff {
                    s.under_k_present += 1;
                }
                if floor == 0 {
                    s.zero_present += 1;
                }
            } else if floor < k_eff {
                // Departed owner: no source to re-encode → unrecoverable if under floor.
                if is_victim {
                    s.victim_owned_lost += 1;
                } else {
                    s.orphaned_lost += 1;
                }
            }
        }
    }
    s
}

/// Run one repair-storm: warm up to `T_shock`, snapshot the baseline, inject the shock,
/// then observe the recovery trajectory. Deterministic in `cfg.seed`.
pub fn run_repair_storm(cfg: &RepairStormConfig) -> RepairStormReport {
    let params = DynParams {
        repair_detection_delay_max: cfg.detection_delay_max,
        ..cfg.base_params
    };
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(cfg.n_nodes, &params, cfg.seed);

    // --- Warm-up to the shock tick (the world fills and reaches contention) ---
    for _ in 0..cfg.warmup_ticks {
        step(&mut world, &params, &prior, &policy);
    }
    let t_shock = world.tick;
    let baseline_under_k = present_under_k(&world, params.k_eff);
    let baseline_established_blocks = present_established_blocks(&world);

    // --- Shock: kill the top-K% popular holders synchronously ---
    let victims = select_top_holders(&world, cfg.k_percent);
    let victim_symbols_killed = inject_shock(&mut world, &victims);
    let victims_killed = victims.len();

    // --- Post-shock trajectory ---
    let mut trajectory: Vec<StormTick> = Vec::with_capacity(cfg.post_ticks as usize);
    let mut ticks_to_recover: Option<u64> = None;
    let mut demand_exceeds_bandwidth_ticks = 0usize;
    let mut max_demand_bandwidth_ratio = 0.0f64;
    let per_node = per_node_upload_budget(&params);
    let mut bandwidth_at_shock = 0usize;

    for _ in 0..cfg.post_ticks {
        step(&mut world, &params, &prior, &policy);
        let since_shock = world.tick - t_shock;
        let present = world.nodes.iter().filter(|n| n.present).count();
        let bandwidth = present.saturating_mul(per_node);
        if bandwidth_at_shock == 0 {
            bandwidth_at_shock = bandwidth;
        }
        let under_k = present_under_k(&world, params.k_eff);
        let outstanding = present_outstanding_demand(&world, &params);
        let stat = world.repair_stat;

        // SYMBOLS vs SYMBOLS (the demand side is the documented lower bound — see
        // `RepairStat::detected_demand_symbols_lb`). The pre-fix code compared the
        // below-target BLOCK count against a symbol bandwidth: a unit error.
        if stat.detected_demand_symbols_lb > bandwidth {
            demand_exceeds_bandwidth_ticks += 1;
        }
        if bandwidth > 0 {
            let ratio = stat.detected_demand_symbols_lb as f64 / bandwidth as f64;
            if ratio > max_demand_bandwidth_ratio {
                max_demand_bandwidth_ratio = ratio;
            }
        }
        if ticks_to_recover.is_none() && under_k <= baseline_under_k {
            ticks_to_recover = Some(since_shock);
        }

        trajectory.push(StormTick {
            tick: world.tick,
            since_shock,
            present,
            under_k_blocks: under_k,
            outstanding_demand_symbols: outstanding,
            owners_repairing: stat.owners_repairing,
            detected_blocks_below_target: stat.detected_blocks_below_target,
            detected_demand_symbols_lb: stat.detected_demand_symbols_lb,
            bandwidth_symbols: bandwidth,
        });
    }

    let peak_under_k = trajectory
        .iter()
        .map(|t| t.under_k_blocks)
        .max()
        .unwrap_or(0);
    let peak_owners_repairing = trajectory
        .iter()
        .map(|t| t.owners_repairing)
        .max()
        .unwrap_or(0);
    let peak_detected_blocks_below_target = trajectory
        .iter()
        .map(|t| t.detected_blocks_below_target)
        .max()
        .unwrap_or(0);
    let peak_detected_demand_symbols_lb = trajectory
        .iter()
        .map(|t| t.detected_demand_symbols_lb)
        .max()
        .unwrap_or(0);
    let peak_outstanding_demand_symbols = trajectory
        .iter()
        .map(|t| t.outstanding_demand_symbols)
        .max()
        .unwrap_or(0);

    let loss = final_loss_scan(&world, params.k_eff, &victims);

    RepairStormReport {
        n_nodes: cfg.n_nodes,
        k_percent: cfg.k_percent,
        detection_delay_max: cfg.detection_delay_max,
        t_shock,
        k_eff: params.k_eff,
        n_symbols: params.n_symbols,
        victims_killed,
        victim_symbols_killed,
        baseline_under_k,
        baseline_established_blocks,
        trajectory,
        peak_under_k,
        peak_owners_repairing,
        peak_detected_blocks_below_target,
        peak_detected_demand_symbols_lb,
        peak_outstanding_demand_symbols,
        bandwidth_symbols: bandwidth_at_shock,
        demand_exceeds_bandwidth_ticks,
        max_demand_bandwidth_ratio,
        blocks_under_k_end: loss.under_k_present,
        blocks_zero_end: loss.zero_present,
        blocks_orphaned_lost: loss.orphaned_lost,
        blocks_victim_owned_lost: loss.victim_owned_lost,
        ticks_to_recover,
    }
}
