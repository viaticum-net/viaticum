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
use crate::sim_adv::cli::{SimAdvError, apply_dial};
use crate::sim_adv::metrics::{MetricSet, collect_metrics};
use crate::sim_adv::restore::{RestoreTracker, RestoreTruth};
use crate::sim_adv::scenario::{Event, EventKind, NodeSel, Scenario, ScenarioId};
use crate::sim_dynamic::build_world;
use crate::sim_dynamic::engine::{disaster_strike, step};
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
/// engine's placement/PoS/churn draws.
fn resolve_nodesel(world: &World, sel: NodeSel) -> Vec<usize> {
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
    }
}

/// Salt for the `NodeSel::Random` draw (kept off the engine's streams).
const NODESEL_SALT: u64 = 0x0005_E1EC_7D15_A57E;

/// Apply the events due at `tick`: record each, and for a [`Event::Disaster`] run the
/// real executor (strike each victim, start its restore measurement, schedule its return
/// at `tick + 1`). Other kinds are recorded-only in 0.2.
fn apply_events(
    world: &mut World,
    due: &[Event],
    tick: u64,
    log: &mut Vec<FiredEvent>,
    tracker: &mut RestoreTracker,
    revive_at: &mut BTreeMap<u64, Vec<usize>>,
) {
    for ev in due {
        log.push(FiredEvent {
            tick,
            kind: ev.kind(),
        });
        if let Event::Disaster(sel) = ev {
            for victim in resolve_nodesel(world, *sel) {
                disaster_strike(world, victim);
                tracker.on_disaster(world, victim, tick);
                revive_at.entry(tick + 1).or_default().push(victim);
            }
        }
    }
}

/// Run one seed to the horizon and collect its god-view metrics + event record + (for a
/// DR scenario) the restore-truth metric.
///
/// The per-tick order is: (a) revive any victim returning this tick (same identity, empty
/// disk); (b) apply due events (Disaster mutates, others record-only); (c) observe the
/// restore window "as tick `t` begins"; (d) `step`. With no Disaster the loop is a bare
/// `step` loop, so `honest_v2` seed-42 still matches `sim_diag 42 100 50 1 v2`.
pub(crate) fn run_one_seed(
    scenario: &Scenario,
    seed: u64,
) -> (MetricSet, Vec<FiredEvent>, Option<RestoreTruth>) {
    let params = &scenario.world.base;
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();

    let mut world = build_world(scenario.world.n_nodes, params, seed);
    let queue = EventQueue::from_scenario(&scenario.events);
    let mut fired: Vec<FiredEvent> = Vec::new();
    let mut tracker = RestoreTracker::new(&scenario.world);
    // Victims to revive, keyed by their return tick (disaster_tick + 1).
    let mut revive_at: BTreeMap<u64, Vec<usize>> = BTreeMap::new();

    for t in 0..scenario.horizon {
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
        );
        // (c) observe the restore window before the tick advances the world.
        tracker.observe(&world, t);
        // (d) advance one tick.
        step(&mut world, params, &prior, &policy);
    }

    let restore = if tracker.is_active() {
        Some(tracker.finalize())
    } else {
        None
    };
    (collect_metrics(&world, params), fired, restore)
}

/// Run a scenario across `seeds`, fanning out over rayon. The collect preserves seed
/// order, so the aggregated report is deterministic (spec §10 п.12).
pub fn run(scenario: &Scenario, seeds: &[u64]) -> RunResult {
    let outcomes: Vec<(MetricSet, Vec<FiredEvent>, Option<RestoreTruth>)> = seeds
        .par_iter()
        .map(|&seed| run_one_seed(scenario, seed))
        .collect();

    let mut per_seed = Vec::with_capacity(outcomes.len());
    let mut fired = Vec::with_capacity(outcomes.len());
    let mut per_seed_restore = Vec::with_capacity(outcomes.len());
    for (m, f, r) in outcomes {
        per_seed.push(m);
        fired.push(f);
        per_seed_restore.push(r);
    }

    RunResult {
        scenario: scenario.id,
        seeds: seeds.to_vec(),
        per_seed,
        fired,
        per_seed_restore,
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
