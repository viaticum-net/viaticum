//! The scenario runner: multi-seed rayon fan-out + the event executor.
//!
//! Determinism (spec §10 п.12): seeds fan out over rayon but the results are collected
//! into a seed-INDEXED `Vec` (rayon's `map(...).collect::<Vec<_>>()` preserves input
//! order regardless of thread-completion order), so the aggregated report is byte-for-
//! byte identical on repeat. Each seed's world is fully seeded (the engine's LCG), so a
//! single seed is itself reproducible.
//!
//! Event execution (sub-tranche 0.2): the due events are applied at the top of each tick.
//! [`Event::Disaster`] is a REAL executor now — it resolves its [`NodeSel`], strikes each
//! victim ([`disaster_strike`]), starts the restore-truth measurement, and schedules the
//! victim's return (same identity) one tick later. The other event kinds are still
//! recorded-only (their executors are 0.3/0.4). With no Disaster in the scenario the loop
//! is bit-identical to a raw `step` loop, so `honest_v2` is unchanged (the 0.2 gate).

use std::collections::BTreeMap;

use rayon::prelude::*;

use viaticum_core::four_r::{PlacementPolicy, SurfacePrior};

use crate::generator::Rng;
use crate::sim_adv::brier::Calibration;
use crate::sim_adv::cli::{SimAdvError, apply_dial};
use crate::sim_adv::hetero::{DemandClass, HeteroReport, HeteroTracker, apply_demand_classes};
use crate::sim_adv::inflow::{PopSeries, apply_inflow, bootstrap_n0, present_count};
use crate::sim_adv::metrics::{
    MetricSet, cartel_earnings_split, collect_metrics, newcomer_floor_durability,
};
use crate::sim_adv::predators::{
    AdvMetrics, RunMode, collect_adv_metrics, fold_cap_ratio, inject_adversaries,
    inject_incumbent_cartel, install_adv_uptime, observe_adv_aggregates, observe_cap_ratio,
    twin_dial_override,
};
use crate::sim_adv::restore::{RestoreTracker, RestoreTruth};
use crate::sim_adv::scenario::AdvId;
use crate::sim_adv::scenario::{Event, EventKind, NodeSel, Scenario, ScenarioId};
use crate::sim_adv::tier::{TierMix, TierReport, apply_tier_mix, tier_report};
use crate::sim_dynamic::build_world;
use crate::sim_dynamic::engine::{DynParams, depart_node, disaster_strike, step};
use crate::sim_dynamic::generator::World;

/// A recorded dispatch (0.1 executor is a no-op — this is the whole observable effect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiredEvent {
    /// The tick the event fired at.
    pub tick: u64,
    /// The event kind (payload-free label).
    pub kind: EventKind,
}

/// The full multi-seed result of one scenario run.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// The scenario id.
    pub scenario: ScenarioId,
    /// The seeds used, in order (aligned with `per_seed` / `fired`).
    pub seeds: Vec<u64>,
    /// Per-seed god-view metrics, seed-indexed (deterministic order).
    pub per_seed: Vec<MetricSet>,
    /// Per-seed event record, seed-indexed (empty when a scenario has no events, e.g.
    /// `honest_v2`).
    pub fired: Vec<Vec<FiredEvent>>,
    /// Per-seed restore-truth (metric №1), seed-indexed. `None` for a seed with no
    /// Disaster event (e.g. `honest_v2`); `Some` for a DR scenario like `dr_baseline`.
    pub per_seed_restore: Vec<Option<RestoreTruth>>,
    /// Per-seed R̂-calibration dataset (transche 0.3), seed-indexed. Every sim_adv seed
    /// collects it (the runner enables the prediction log); possibly EMPTY for a run whose
    /// predictions never reach their `H`-tick horizon (short horizon). The Brier judge reads
    /// this — a GOD-VIEW metric channel, never a decision input.
    pub per_seed_calibration: Vec<Calibration>,
    /// Per-seed Attack-ROI read (phase 1), seed-indexed. `None` for a seed of a scenario with
    /// no adversaries (e.g. `honest_v2`); `Some(pair)` pairs the predator run with its matched
    /// honest twin (both at the SAME seed), the comparison the ROI verdicts read.
    pub per_seed_adv: Vec<Option<AdvPair>>,
    /// Per-seed hetero report (hetero-v2, D1), seed-indexed. `None` for a UNIFORM-demand
    /// scenario (e.g. `honest_v2` / `dr_baseline`); `Some` for a `Classes` mix (`honest_hetero_v2`
    /// / `dr_hetero`) — the per-class placement metrics + the L-footprint curve.
    pub per_seed_hetero: Vec<Option<HeteroReport>>,
    /// Per-seed per-tier report (phase-2a P7), seed-indexed. `None` for a non-tiered scenario;
    /// `Some` for a `UptimeMix::Tiered` scenario (`tiered_v1` / `tiered_hetero`) — the per-tier
    /// floor-completeness / durability / share-A / give↔get served / parked table.
    pub per_seed_tier: Vec<Option<TierReport>>,
    /// Per-seed present-count series (`4r_inflow_spec.md`), seed-indexed. `None` for a
    /// non-inflow scenario; `Some` for an [`crate::sim_adv::InflowPolicy::Steady`] scenario
    /// (`tiered_v1_inflow`) — the population curve the INV-POP-STATIONARY board row reads.
    pub per_seed_pop: Vec<Option<PopSeries>>,
    /// Per-seed NEWCOMER floor-durability (`4r_a15_spec.md` §3), seed-indexed. `NaN` for a
    /// non-enclosure scenario; a finite fraction for the A15 `a15_enclosure` scenario — the
    /// god-view durability of post-cutoff newcomers' floor-met blocks, which INV-ENCLOSURE-FLOOR
    /// reads and the cartel-fraction sweep tracks.
    pub per_seed_newcomer: Vec<f64>,
    /// Per-seed CARTEL-PAYS ratio (`4r_a15_spec.md` §4, SECONDARY), seed-indexed: the cartel's
    /// mean outbound service / the non-cartel incumbents' mean. `NaN` for a non-enclosure scenario
    /// (or a seed with no baseline). `≤ 1` ⇒ the cartel earns no more than an honest incumbent.
    pub per_seed_cartel_earn: Vec<f64>,
}

/// All per-seed outputs of one seed run (kept as a struct so the growing set of optional
/// metric channels — restore-truth, R̂-calibration, Attack-ROI, hetero — does not become an
/// unreadable wide tuple). A `None` optional channel means "this scenario does not carry it".
pub(crate) struct SeedRun {
    /// The god-view metrics at the horizon.
    pub metrics: MetricSet,
    /// The scripted-event dispatch record.
    pub fired: Vec<FiredEvent>,
    /// Restore-truth (metric №1) for a DR scenario, else `None`.
    pub restore: Option<RestoreTruth>,
    /// The R̂-calibration dataset (always collected; possibly empty for a short horizon).
    pub calib: Calibration,
    /// The Attack-ROI read for an adversary scenario, else `None`.
    pub adv: Option<AdvMetrics>,
    /// The per-class hetero report for a `Classes`-mix scenario, else `None`.
    pub hetero: Option<HeteroReport>,
    /// The per-tier report for a TIERED scenario (phase-2a), else `None`.
    pub tier: Option<TierReport>,
    /// The present-count time-series for an INFLOW scenario (`4r_inflow_spec.md`), else `None`
    /// (a closed-cohort / non-inflow scenario records no curve, so its output is unchanged).
    pub pop: Option<PopSeries>,
    /// The NEWCOMER floor-durability at the horizon for an A15 enclosure scenario (`4r_a15_spec.md`
    /// §3), else `NaN` (a non-enclosure scenario carries no cartel / newcomer cut).
    pub newcomer_durability: f64,
    /// The CARTEL-PAYS ratio (cartel mean served-out / non-cartel incumbent mean) for an A15
    /// enclosure scenario (`4r_a15_spec.md` §4), else `NaN`.
    pub cartel_earn_ratio: f64,
}

/// A predator run paired with its matched honest twin (same seed, same construction, hooks
/// OFF on the twin) — the Attack-ROI comparison (spec §4 п.3 / detail §3.3).
#[derive(Debug, Clone, Copy)]
pub struct AdvPair {
    /// The predator (hooks active).
    pub pred: AdvMetrics,
    /// The matched honest twin (hooks off).
    pub twin: AdvMetrics,
}

/// Tick-indexed scripted-event queue.
struct EventQueue {
    by_tick: BTreeMap<u64, Vec<Event>>,
}

impl EventQueue {
    fn from_scenario(events: &[(u64, Event)]) -> Self {
        let mut by_tick: BTreeMap<u64, Vec<Event>> = BTreeMap::new();
        for &(tick, ev) in events {
            by_tick.entry(tick).or_default().push(ev);
        }
        EventQueue { by_tick }
    }

    fn due(&self, tick: u64) -> &[Event] {
        self.by_tick.get(&tick).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

/// Resolve a [`NodeSel`] against the built world → concrete PRESENT victim indices.
/// Deterministic; `Random` draws off a dedicated salted stream so it never perturbs the
/// engine's placement/PoS/churn draws. `classes` is the per-node demand-class assignment
/// (read only by `FirstDemandArchetype`).
fn resolve_nodesel(world: &World, sel: NodeSel, classes: &[DemandClass]) -> Vec<usize> {
    let n = world.nodes.len();
    let present = |i: usize| i < n && world.nodes[i].present;
    match sel {
        NodeSel::Index(i) => {
            if present(i) {
                vec![i]
            } else {
                Vec::new()
            }
        }
        NodeSel::Archetype(a) => (0..n)
            .filter(|&i| present(i) && world.nodes[i].archetype == a)
            .collect(),
        NodeSel::TopHolders(frac) => {
            let mut ranked: Vec<usize> = (0..n).filter(|&i| present(i)).collect();
            ranked.sort_by(|&a, &b| {
                let ca = world.nodes[a].holdings.iter().filter(|s| s.alive).count();
                let cb = world.nodes[b].holdings.iter().filter(|s| s.alive).count();
                cb.cmp(&ca).then(a.cmp(&b))
            });
            let take = (frac.clamp(0.0, 1.0) * ranked.len() as f64).round() as usize;
            ranked.into_iter().take(take).collect()
        }
        NodeSel::Random(count) => {
            let mut pool: Vec<usize> = (0..n).filter(|&i| present(i)).collect();
            let mut rng = Rng::derive(world.seed, NODESEL_SALT, count as u64, 0, 0);
            // Fisher-Yates prefix of length `count`.
            for i in (1..pool.len()).rev() {
                let j = (rng.unit() * (i as f64 + 1.0)) as usize;
                pool.swap(i, j.min(i));
            }
            pool.into_iter().take(count.min(n)).collect()
        }
        NodeSel::FirstTierArchetype(tier, arch) => {
            // The DR-primary backbone: among present nodes matching (tier, archetype),
            // the EARLIEST-established one (smallest `joined_tick`, tie by index). Picking
            // the earliest — not merely the lowest index — models "Ilya's NAS running for
            // years" and avoids striking a late-joiner whose blocks never reached floor
            // (a degenerate victim with no established backups to restore).
            (0..n)
                .filter(|&i| {
                    present(i)
                        && world.nodes[i].disk.tier == tier
                        && world.nodes[i].archetype == arch
                })
                .min_by(|&a, &b| {
                    world.nodes[a]
                        .joined_tick
                        .cmp(&world.nodes[b].joined_tick)
                        .then(a.cmp(&b))
                })
                .map(|i| vec![i])
                .unwrap_or_default()
        }
        NodeSel::FirstDemandArchetype(class, arch) => {
            // The hetero DR backbone: among present nodes matching (demand class, archetype),
            // the EARLIEST-established one (smallest `joined_tick`, tie by index) — mirrors
            // `FirstTierArchetype` so the L-class victim is a mature big-footprint owner.
            (0..n)
                .filter(|&i| {
                    present(i) && classes.get(i) == Some(&class) && world.nodes[i].archetype == arch
                })
                .min_by(|&a, &b| {
                    world.nodes[a]
                        .joined_tick
                        .cmp(&world.nodes[b].joined_tick)
                        .then(a.cmp(&b))
                })
                .map(|i| vec![i])
                .unwrap_or_default()
        }
    }
}

/// Salt for the `NodeSel::Random` draw (kept off the engine's streams).
const NODESEL_SALT: u64 = 0x0005_E1EC_7D15_A57E;

/// Salt for the correlated-disaster co-loss holder pick (`Event::CorrelatedDisaster`). A
/// DEDICATED stream, distinct from [`NODESEL_SALT`] and every engine draw, so choosing WHICH
/// holders are co-lost never perturbs the engine's placement / PoS / churn RNG (determinism).
const CORR_LOSS_SALT: u64 = 0x00C0_1055_ADDE_D000; // "co-loss added"

/// The victim's CURRENT holders: the union, over the victim's alive placed symbols, of the
/// PRESENT nodes `h != victim` holding an alive symbol of `owner == victim`. Sorted ascending
/// (deterministic). A departed holder has all its holdings dead ⇒ excluded by the `alive`
/// filter, and the explicit `present` filter also keeps a paused (A5) holder out of the pick.
fn victim_holders(world: &World, victim: usize) -> Vec<usize> {
    let n = world.nodes.len();
    let mut holders: Vec<usize> = (0..n)
        .filter(|&h| {
            h != victim
                && world.nodes[h].present
                && world.nodes[h]
                    .holdings
                    .iter()
                    .any(|s| s.alive && s.owner == victim)
        })
        .collect();
    holders.sort_unstable();
    holders
}

/// Seeded-pick `k` of the victim's (already sorted) `holders` to co-lose, off the dedicated
/// [`CORR_LOSS_SALT`] stream so the pick never perturbs the engine. The Fisher-Yates draw does
/// NOT depend on `k`, so the picked set is NESTED as `k` grows (`pick(k) ⊆ pick(k+1)` at the
/// same seed) — the HONEST-REFLECT monotonicity of the co-loss sweep rests on this. Returns the
/// picked indices sorted ascending (so the departure order — and thus the silent-loss queue
/// order — is deterministic regardless of the shuffle). `k == 0` ⇒ empty, drawing no RNG (so
/// `CorrelatedDisaster{co_loss:0}` is byte-identical to a plain `Disaster`).
fn coloss_pick(seed: u64, victim: usize, tick: u64, holders: &[usize], k: usize) -> Vec<usize> {
    if k == 0 || holders.is_empty() {
        return Vec::new();
    }
    let mut pool = holders.to_vec();
    let mut rng = Rng::derive(seed, CORR_LOSS_SALT, victim as u64, tick, 0);
    // Fisher-Yates prefix (k-independent order ⇒ nested picks across k).
    for i in (1..pool.len()).rev() {
        let j = (rng.unit() * (i as f64 + 1.0)) as usize;
        pool.swap(i, j.min(i));
    }
    pool.truncate(k.min(pool.len()));
    pool.sort_unstable();
    pool
}

/// Apply the events due at `tick`: record each, and for a [`Event::Disaster`] run the
/// real executor (strike each victim, start its restore measurement, schedule its return
/// at `tick + 1`). Other kinds are recorded-only in 0.2.
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_events(
    world: &mut World,
    due: &[Event],
    tick: u64,
    log: &mut Vec<FiredEvent>,
    tracker: &mut RestoreTracker,
    revive_at: &mut BTreeMap<u64, Vec<usize>>,
    classes: &[DemandClass],
) {
    for ev in due {
        log.push(FiredEvent {
            tick,
            kind: ev.kind(),
        });
        match ev {
            Event::Disaster(sel) => {
                for victim in resolve_nodesel(world, *sel, classes) {
                    strike_victim(world, victim, tick, tracker, revive_at, classes);
                }
            }
            // A16: a Disaster on the victim PLUS a correlated loss of `co_loss_holders` of its
            // CURRENT holders in the SAME tick. The victim is struck exactly as a plain
            // Disaster; then a seeded pick of its holders departs with `churn` physics (NOT
            // restore-tracked, NOT revived). `co_loss_holders == 0` ⇒ the pick is empty and no
            // RNG is drawn ⇒ byte-identical to a plain `Disaster` (the anchor).
            Event::CorrelatedDisaster {
                sel,
                co_loss_holders,
            } => {
                for victim in resolve_nodesel(world, *sel, classes) {
                    strike_victim(world, victim, tick, tracker, revive_at, classes);
                    let holders = victim_holders(world, victim);
                    let pick = coloss_pick(world.seed, victim, tick, &holders, *co_loss_holders);
                    for h in pick {
                        depart_node(world, h);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Strike one disaster `victim`: the engine's [`disaster_strike`], start its restore-truth
/// measurement, and schedule its same-identity return at `tick + 1`. Shared by the plain and
/// correlated disaster arms so the victim physics is identical between them (the co-loss is a
/// pure addendum layered on top).
fn strike_victim(
    world: &mut World,
    victim: usize,
    tick: u64,
    tracker: &mut RestoreTracker,
    revive_at: &mut BTreeMap<u64, Vec<usize>>,
    classes: &[DemandClass],
) {
    let class = classes.get(victim).copied().unwrap_or(DemandClass::M);
    disaster_strike(world, victim);
    tracker.on_disaster(world, victim, tick, class);
    revive_at.entry(tick + 1).or_default().push(victim);
}

/// Build a scenario's t=0 world: `build_world` + the opt-in tier / demand / uptime / inflow
/// layers (each a no-op on its default, so a bare scenario stays byte-identical). Does NOT inject
/// adversaries — that is the runner's job (only `run_one_seed_mode` repurposes slots as predators);
/// [`population_curve`] wants the honest world. Shared by both so the world construction (including
/// the inflow re-schedule) is defined in ONE place.
fn build_world_for(scenario: &Scenario, params: &DynParams, seed: u64) -> World {
    let mut world = build_world(scenario.world.n_nodes, params, seed);
    // Phase-2a P7 (axis 2): re-mix the tier shares + re-shape each node's disk. Default `Backbone`
    // leaves `build_world`'s tiers (byte-identical). Done FIRST so demand + uptime see the final tier.
    if let TierMix::Custom(shares) = &scenario.world.tier_mix {
        apply_tier_mix(&mut world, shares, seed);
    }
    // Hetero-v2 (D1): per-owner demand classes; `Uniform` ⇒ NOT applied (byte-identical).
    let classes = scenario.world.demand.assign(scenario.world.n_nodes, seed);
    if scenario.world.demand.is_hetero() {
        apply_demand_classes(
            &mut world,
            &classes,
            params,
            scenario.world.demand.disk_policy(),
        );
    }
    // Phase-2a uptime profiles (axis 3): default `Legacy` ⇒ all-`None` (byte-identical archetype iid).
    if scenario.world.uptime.is_tiered() {
        world.uptime = scenario.world.uptime.assign(&world);
    }
    // Inflow (`4r_inflow_spec.md`): re-schedule the pool as a steady arrival stream. Default `None`
    // ⇒ NO-OP, no RNG (byte-identical closed cohort). Only rewrites `joined_tick` / `present`.
    apply_inflow(&mut world, scenario.world.inflow, scenario.horizon);
    world
}

/// Run a scenario's HONEST world (no adversary injection) and return the present-count per tick
/// (index = tick, post-step). The population-curve measurement (`4r_inflow_spec.md` §3): used to
/// compare the WITHOUT-inflow closed cohort (`tiered_v1`) against the WITH-inflow stationary world
/// (`tiered_v1_inflow`). Deterministic in `seed`. A bare `step` loop, so it matches
/// [`run_one_seed_mode`]'s own recorded series for any scenario with no events / adversaries (the
/// tiered scenarios) — the runner's extra passes (event dispatch, calibration log, trackers) never
/// mutate `present`. NOT for a scenario carrying `events`/`adversaries` (its world would diverge).
pub fn population_curve(scenario: &Scenario, seed: u64) -> Vec<usize> {
    let params = scenario.world.base;
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world_for(scenario, &params, seed);
    let mut curve = Vec::with_capacity(scenario.horizon as usize);
    for _ in 0..scenario.horizon {
        step(&mut world, &params, &prior, &policy);
        curve.push(present_count(&world));
    }
    curve
}

/// Run one seed as the PREDATOR (hooks active for any adversaries) to the horizon and
/// collect its god-view metrics + event record + (for a DR scenario) the restore-truth
/// metric + (for an adversary scenario) the Attack-ROI read. Kept for the determinism
/// re-run and the unit tests.
///
/// The per-tick order is: (a) revive any victim returning this tick (same identity, empty
/// disk); (b) apply due events (Disaster mutates, others record-only); (c) observe the
/// restore window "as tick `t` begins"; (d) `step`. With no Disaster the loop is a bare
/// `step` loop, so `honest_v2` seed-42 still matches `sim_diag 42 100 50 1 v2`.
pub(crate) fn run_one_seed(scenario: &Scenario, seed: u64) -> SeedRun {
    run_one_seed_mode(scenario, seed, RunMode::Predator)
}

/// Run one seed in the given [`RunMode`] (predator hooks on / off). A `Twin` run injects the
/// adversaries' CONSTRUCTION but no hooks — the matched honest control.
pub(crate) fn run_one_seed_mode(scenario: &Scenario, seed: u64, mode: RunMode) -> SeedRun {
    // The MATCHED-TWIN dial override (spec: some predators' control differs by ONE dial, not a
    // hook). A5's twin is the SAME deep node in a `depth_w_d = 0` world (D-floor OFF). Applied ONLY
    // to the TWIN arm; the predator arm and every honest scenario keep `scenario.world.base` verbatim
    // (byte-identical). `depth_w_d` is not read at build time, so the two arms share the same t=0
    // world and diverge only in eviction dynamics — the clean A/B.
    let mut params_owned = scenario.world.base; // DynParams is Copy — a value copy, not an alias
    if mode == RunMode::Twin
        && let Some((dial, value)) = twin_dial_override(&scenario.adversaries)
    {
        let _ = apply_dial(&mut params_owned, dial, value);
    }
    let params = &params_owned;
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();

    let mut world = build_world_for(scenario, params, seed);
    // The per-owner demand class assignment (idempotent, pure) is needed below by the event
    // resolver + hetero tracker; `build_world_for` already applied it to the world for a hetero mix.
    let classes = scenario.world.demand.assign(scenario.world.n_nodes, seed);
    // Inflow (`4r_inflow_spec.md`): record the present-count curve when a steady stream is installed
    // (`None` ⇒ no recording, output unchanged). Setpoint = the bootstrap cohort `n0` (= n − pool).
    let record_pop = scenario.world.inflow.is_steady();
    let pop_setpoint = bootstrap_n0(
        scenario.world.n_nodes,
        scenario.world.inflow,
        scenario.horizon,
    );
    let mut pop_series: Option<Vec<usize>> = if record_pop {
        Some(Vec::with_capacity(scenario.horizon as usize))
    } else {
        None
    };
    // Phase 1/3: inject the scenario's adversaries (empty ⇒ no-op; honest scenarios stay
    // byte-identical). `Predator` installs the hooks; `Twin` injects the same nodes with hooks off
    // (the matched control). Deterministic, no RNG. A15 (incumbent-enclosure) needs a DIFFERENT
    // injection: its cartel is the EARLIEST-joined INCUMBENTS (not the last slots, which under
    // inflow are the newcomer pool), so it branches to `inject_incumbent_cartel`.
    let is_enclosure = scenario
        .adversaries
        .iter()
        .any(|a| a.id == AdvId::A15IncumbentEnclosure);
    let adv_nodes = if is_enclosure {
        match scenario
            .adversaries
            .iter()
            .find(|a| a.id == AdvId::A15IncumbentEnclosure)
        {
            Some(spec) => inject_incumbent_cartel(&mut world, spec, mode),
            None => Vec::new(),
        }
    } else {
        inject_adversaries(&mut world, &scenario.adversaries, params, mode)
    };
    // A15 newcomer cut (`4r_a15_spec.md` §3): a NEWCOMER is a node that joined strictly AFTER the
    // initial bootstrap cohort finished joining — `joined_tick > newcomer_cutoff` (the max
    // `joined_tick` over the first n0 bootstrap nodes; see `inflow::newcomer_cutoff`). Derived from
    // the world (self-documenting), NOT a tuned bar: for the fully-established a15 world
    // (`n0_frac = 1.0`) the cohort all joins at tick 0 ⇒ cutoff 0, so every inflow-pool arrival is a
    // newcomer (and the cartel incumbents, `joined_tick == 0`, are excluded from the metric).
    let join_cutoff = crate::sim_adv::inflow::newcomer_cutoff(&world, pop_setpoint);
    // The Attack-ROI (parked / cap-ratio / consumed-vs-served) channel is meaningful only for a
    // twin-compared predator scenario. A15 enclosure is a world-cut (newcomer-durability), NOT a
    // twin comparison, so it does NOT populate the Attack-ROI read — leaving `sr.adv = None` (and
    // `per_seed_adv = None` in `run`), which keeps the determinism board's adv-channel check
    // consistent (both the run and its re-run carry `None`).
    let track_adv_roi = !adv_nodes.is_empty() && !is_enclosure;
    // Phase-2a-2 (A3 флаппер): install the mode-differentiated flapper uptime profile on the A3
    // slots — bursty Seasonal (predator) vs mean-matched iid Ragged (twin). No-op for every other
    // predator id (they keep their archetype uptime); leaves the non-A3 slots untouched.
    install_adv_uptime(&mut world, &adv_nodes, mode);
    // Transche 0.3: enable the god-view R̂-calibration prediction log for sim_adv runs (the
    // engine now appends a forecast at each placement). This is a METRIC channel — it drives
    // NO decision and consumes NO RNG, so the world evolution is bit-identical to the log-off
    // (sim_diag / default) path; only `world.pred_log` is populated.
    world.pred_log_enabled = true;
    let horizon_h = params.pred_horizon_ticks;
    let k_eff = params.k_eff;

    let queue = EventQueue::from_scenario(&scenario.events);
    let mut fired: Vec<FiredEvent> = Vec::new();
    let mut tracker = RestoreTracker::new(&scenario.world);
    // Victims to revive, keyed by their return tick (disaster_tick + 1).
    let mut revive_at: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    // R̂-calibration resolution: predictions are appended to `world.pred_log` in tick order,
    // so their resolve ticks (`pred.tick + H`) are non-decreasing; a single cursor drains
    // each as the world reaches its horizon and reads the realised outcome.
    let mut calib = Calibration::new();
    let mut resolve_cursor = 0usize;
    // Phase-1 Attack-ROI: the Р-7 cap engages TRANSIENTLY (the eviction latch is momentary),
    // so fold the per-tick max cap ratio over the run (NaN ⇒ no evicting holder held adversary
    // data this tick). Empty for a non-adversary scenario.
    let mut run_cap_ratio = f64::NAN;
    // A2 seat-sync fix (2026-07-19): the enforced-retention arms diverge chaotically, so the
    // horizon snapshot is noisy. Integrate the adversary aggregates (g_oh ledger + parked own
    // volume) over the run for a stable paired signal. Zero for a non-adversary scenario.
    let mut retention_g_integral = 0.0f64;
    let mut parked_integral = 0.0f64;
    // Hetero-v2 (D1): the per-class placement tracker — samples the L-footprint fill curve and
    // records each owner's first full-footprint tick. `None` for a uniform-demand scenario.
    let mut hetero_tracker = if scenario.world.demand.is_hetero() {
        Some(HeteroTracker::new(&classes, params))
    } else {
        None
    };
    // Phase-2a-2 A3 (флаппер) diagnostics: surfaced-in-window (the PoS PASS proxy) + online (the
    // REAL storage-time proxy) counts over the run, summed over the PROFILED adversary nodes (only
    // an A3 flapper carries an uptime profile). Both accessors are pure functions of (id, seed,
    // profile, tick) — the SAME draws the engine's PoS reads — so sampling them here perturbs no
    // decision (determinism preserved). NaN fractions for a scenario with no profiled adversary.
    let mut a3_surfaced = 0u64;
    let mut a3_online = 0u64;
    let mut a3_samples = 0u64;
    // Phase-2a-2 A5 (молчащий глубокий): the deep nodes + their shared pause window `[pstart, pend)`.
    // The survival snapshots SUM the alive parked own-symbol count over ALL deep nodes at the pause
    // boundaries (peak at the start, survivors at the end) — pooling several deep nodes smooths the
    // per-seed fraction. `None` for a non-A5 scenario (survival ⇒ NaN).
    let a5: Option<(Vec<usize>, u64, u64)> = {
        let deep: Vec<usize> = adv_nodes
            .iter()
            .copied()
            .filter(|&node| {
                world.adv[node]
                    .as_ref()
                    .is_some_and(|r| r.id == AdvId::A5DeepSilent && r.dials.pause_len > 0)
            })
            .collect();
        deep.first().and_then(|&first| {
            world.adv[first].as_ref().map(|r| {
                (
                    deep.clone(),
                    r.dials.pause_start,
                    r.dials.pause_start.saturating_add(r.dials.pause_len),
                )
            })
        })
    };
    let mut a5_peak: Option<usize> = None;
    let mut a5_survivors: Option<usize> = None;

    for t in 0..scenario.horizon {
        // A5 pause-boundary snapshots (BEFORE the tick advances — so `pend` reads the state after
        // the last paused tick, before the returning nodes repair in `step`).
        if let Some((deep, pstart, pend)) = &a5 {
            if t == *pstart {
                a5_peak = Some(deep.iter().map(|&d| parked_own_symbols(&world, d)).sum());
            }
            if t == *pend {
                a5_survivors = Some(deep.iter().map(|&d| parked_own_symbols(&world, d)).sum());
            }
        }
        // (a) return any victim whose window starts this tick (present=true, empty disk).
        if let Some(victims) = revive_at.remove(&t) {
            for v in victims {
                world.nodes[v].present = true;
            }
        }
        // (b) apply due events (Disaster strikes; others recorded-only in 0.2).
        apply_events(
            &mut world,
            queue.due(t),
            t,
            &mut fired,
            &mut tracker,
            &mut revive_at,
            &classes,
        );
        // (c) observe the restore window before the tick advances the world.
        tracker.observe(&world, t);
        // (d) advance one tick (placements this tick append forecasts with `tick == t`).
        step(&mut world, params, &prior, &policy);

        // (d') inflow population curve: record the present-count AFTER this tick (post-activation,
        //      post-churn). No-op unless the scenario installs an inflow stream.
        if let Some(pp) = pop_series.as_mut() {
            pp.push(present_count(&world));
        }

        // (e) resolve any forecast whose horizon `H` is reached at the NEW `world.tick`
        //     (= t+1): the realised outcome is "the block still has ≥ k_eff live symbols".
        let now = world.tick;
        while resolve_cursor < world.pred_log.len() {
            let e = world.pred_log[resolve_cursor];
            if e.tick + horizon_h > now {
                break; // tick-ordered ⇒ nothing further is due yet
            }
            let outcome = block_live_symbols(&world, e.owner, e.block) >= k_eff;
            calib.push(e.r_hat, outcome, e.floor_complete);
            resolve_cursor += 1;
        }

        // (f) fold this tick's Р-7 cap ratio + the A2 adversary aggregates (only meaningful for a
        //     twin-compared Attack-ROI scenario; A15 enclosure uses the newcomer-durability channel,
        //     NOT the Attack-ROI read, so it skips this).
        if track_adv_roi {
            run_cap_ratio =
                fold_cap_ratio(run_cap_ratio, observe_cap_ratio(&world, params, &adv_nodes));
            let (g, park) = observe_adv_aggregates(&world, &adv_nodes);
            retention_g_integral += g;
            parked_integral += park;
        }

        // (g) hetero placement observation (after the tick advances: read the post-step state).
        if let Some(ht) = &mut hetero_tracker {
            ht.observe(&world);
        }

        // (h) A3 flapper diagnostics: sample the surfaced-in-window / online status of each PROFILED
        //     adversary at the tick that just ran (`t` — the tick the PoS pass used).
        for &node in &adv_nodes {
            if world.uptime.get(node).and_then(|o| *o).is_some() {
                a3_samples += 1;
                if world.node_surfaced_in_window(node, t) {
                    a3_surfaced += 1;
                }
                if world.node_online(node, t) {
                    a3_online += 1;
                }
            }
        }
    }

    let restore = if tracker.is_active() {
        Some(tracker.finalize())
    } else {
        None
    };
    let adv = if !track_adv_roi {
        None
    } else {
        let surfaced_frac = frac_or_nan(a3_surfaced, a3_samples);
        let online_frac = frac_or_nan(a3_online, a3_samples);
        let park_survival = match (a5_peak, a5_survivors) {
            (Some(peak), Some(surv)) if peak > 0 => surv as f64 / peak as f64,
            _ => f64::NAN,
        };
        Some(collect_adv_metrics(
            &world,
            &adv_nodes,
            run_cap_ratio,
            retention_g_integral,
            parked_integral,
            surfaced_frac,
            online_frac,
            park_survival,
        ))
    };
    let hetero = hetero_tracker.map(|ht| ht.finalize(&world));
    // Phase-2a: the per-tier report — only for a tiered scenario (keeps every other scenario's
    // report byte-identical, `None`). A pure end-of-run god-view read (no per-tick tracker).
    let tier = if scenario.world.uptime.is_tiered() {
        Some(tier_report(&world))
    } else {
        None
    };
    let pop = pop_series.map(|present_per_tick| PopSeries {
        present_per_tick,
        setpoint: pop_setpoint,
    });
    // A15 (`4r_a15_spec.md` §3/§4): the newcomer floor-durability world-cut + the CARTEL-PAYS
    // ratio. Evaluator-only god-view reads (never fed into a decision). `NaN` for a non-enclosure
    // scenario (the channel is unused there).
    let (newcomer_durability, cartel_earn_ratio) = if is_enclosure {
        let dur = newcomer_floor_durability(&world, join_cutoff, params.n_symbols);
        let (cartel_e, inc_e) = cartel_earnings_split(&world, &adv_nodes, join_cutoff);
        let ratio = if inc_e > 0.0 {
            cartel_e / inc_e
        } else {
            f64::NAN
        };
        (dur, ratio)
    } else {
        (f64::NAN, f64::NAN)
    };
    SeedRun {
        metrics: collect_metrics(&world, params),
        fired,
        restore,
        calib,
        adv,
        hetero,
        tier,
        pop,
        newcomer_durability,
        cartel_earn_ratio,
    }
}

/// `num / den` as a fraction, `NaN` for an empty denominator (the A3 no-profiled-adversary case).
fn frac_or_nan(num: u64, den: u64) -> f64 {
    if den == 0 {
        f64::NAN
    } else {
        num as f64 / den as f64
    }
}

/// God-view count of `owner`'s ALIVE parked own-symbols across PRESENT holders (excluding the owner
/// itself) — the A5 pause-survival snapshot quantity. A holder keeps ≤ 1 symbol per (owner, block)
/// by the §7 spread, so this counts the distinct surviving placements of the deep node's data.
fn parked_own_symbols(world: &World, owner: usize) -> usize {
    let n = world.nodes.len();
    (0..n)
        .filter(|&h| h != owner && world.nodes[h].present)
        .map(|h| {
            world.nodes[h]
                .holdings
                .iter()
                .filter(|s| s.alive && s.owner == owner)
                .count()
        })
        .sum()
}

/// God-view count of a block's live symbols (across PRESENT holders) — the R̂-calibration
/// outcome reader (≥ `k_eff` ⇒ "the block survived to the horizon"). Evaluator-only: never
/// fed back into a decision. The §7 spread keeps ≤ 1 symbol per holder per block, so this is
/// the number of distinct live holders.
fn block_live_symbols(world: &World, owner: usize, block: usize) -> usize {
    world
        .nodes
        .iter()
        .filter(|nd| nd.present)
        .map(|nd| {
            nd.holdings
                .iter()
                .filter(|s| s.alive && s.owner == owner && s.block == block)
                .count()
        })
        .sum()
}

/// Run a scenario across `seeds`, fanning out over rayon. The collect preserves seed
/// order, so the aggregated report is deterministic (spec §10 п.12). For an adversary
/// scenario each seed ALSO runs the matched honest twin (same seed, hooks off) so the
/// Attack-ROI comparison is seed-paired (variance-reducing); honest scenarios skip the twin
/// (no extra work, `per_seed_adv` all `None`).
pub fn run(scenario: &Scenario, seeds: &[u64]) -> RunResult {
    // A15 (incumbent-enclosure) is a cartel-fraction SWEEP measured by a world-cut, NOT a
    // predator-vs-twin comparison (its control is a separate cartel_frac=0 run), so it needs NO
    // twin — skipping it halves the enclosure scenario's cost and leaves `per_seed_adv` all
    // `None` (the enclosure has no Attack-ROI comparative row).
    let is_enclosure = scenario
        .adversaries
        .iter()
        .any(|a| a.id == AdvId::A15IncumbentEnclosure);
    let needs_twin = !scenario.adversaries.is_empty() && !is_enclosure;
    // Per seed: the predator run + (for a twin-compared adversary scenario) its matched twin's
    // Attack-ROI.
    let outcomes: Vec<(SeedRun, Option<AdvMetrics>)> = seeds
        .par_iter()
        .map(|&seed| {
            let pred = run_one_seed_mode(scenario, seed, RunMode::Predator);
            let twin_adv = if needs_twin {
                run_one_seed_mode(scenario, seed, RunMode::Twin).adv
            } else {
                None
            };
            (pred, twin_adv)
        })
        .collect();

    let mut per_seed = Vec::with_capacity(outcomes.len());
    let mut fired = Vec::with_capacity(outcomes.len());
    let mut per_seed_restore = Vec::with_capacity(outcomes.len());
    let mut per_seed_calibration = Vec::with_capacity(outcomes.len());
    let mut per_seed_adv = Vec::with_capacity(outcomes.len());
    let mut per_seed_hetero = Vec::with_capacity(outcomes.len());
    let mut per_seed_tier = Vec::with_capacity(outcomes.len());
    let mut per_seed_pop = Vec::with_capacity(outcomes.len());
    let mut per_seed_newcomer = Vec::with_capacity(outcomes.len());
    let mut per_seed_cartel_earn = Vec::with_capacity(outcomes.len());
    for (sr, twin_adv) in outcomes {
        per_seed.push(sr.metrics);
        fired.push(sr.fired);
        per_seed_restore.push(sr.restore);
        per_seed_calibration.push(sr.calib);
        per_seed_hetero.push(sr.hetero);
        per_seed_tier.push(sr.tier);
        per_seed_pop.push(sr.pop);
        per_seed_newcomer.push(sr.newcomer_durability);
        per_seed_cartel_earn.push(sr.cartel_earn_ratio);
        per_seed_adv.push(match (sr.adv, twin_adv) {
            (Some(pred), Some(twin)) => Some(AdvPair { pred, twin }),
            _ => None,
        });
    }

    RunResult {
        scenario: scenario.id,
        seeds: seeds.to_vec(),
        per_seed,
        fired,
        per_seed_restore,
        per_seed_calibration,
        per_seed_adv,
        per_seed_hetero,
        per_seed_tier,
        per_seed_pop,
        per_seed_newcomer,
        per_seed_cartel_earn,
    }
}

/// One row of a dial sweep: the dial value and the run it produced.
pub struct SweepRow {
    /// The dial value applied to `world.base`.
    pub value: f64,
    /// The run at that value.
    pub result: RunResult,
}

/// Run a `--sweep dial=v1,v2,...` sweep: clone the scenario, override `world.base.<dial>`
/// with each value, and run. Errors (unknown dial) surface as [`SimAdvError`] — never a
/// panic. A/B toggles (`c_recip_days=0` vs 30, `depth_w_d=0` vs 0.5) are the two-value
/// special case.
pub fn run_sweep(
    scenario: &Scenario,
    dial: &str,
    values: &[f64],
    seeds: &[u64],
) -> Result<Vec<SweepRow>, SimAdvError> {
    let mut rows = Vec::with_capacity(values.len());
    for &value in values {
        let mut sc = scenario.clone();
        apply_dial(&mut sc.world.base, dial, value)?;
        rows.push(SweepRow {
            value,
            result: run(&sc, seeds),
        });
    }
    Ok(rows)
}
