//! The scenario runner: multi-seed rayon fan-out + the event-dispatch skeleton.
//!
//! Determinism (spec §10 п.12): seeds fan out over rayon but the results are collected
//! into a seed-INDEXED `Vec` (rayon's `map(...).collect::<Vec<_>>()` preserves input
//! order regardless of thread-completion order), so the aggregated report is byte-for-
//! byte identical on repeat. Each seed's world is fully seeded (the engine's LCG), so a
//! single seed is itself reproducible.
//!
//! Event dispatch is a SKELETON in 0.1: at the start of every tick the queue's due
//! events are handed to a NO-OP executor that only RECORDS `(tick, kind)` (so the
//! dispatch is testable) and never touches `&mut World`. Real execution (Disaster, ...)
//! is phase 0.2 — this keeps the honest baseline bit-identical to a raw `step` loop.

use std::collections::BTreeMap;

use rayon::prelude::*;

use viaticum_core::four_r::{PlacementPolicy, SurfacePrior};

use crate::sim_adv::cli::{SimAdvError, apply_dial};
use crate::sim_adv::metrics::{MetricSet, collect_metrics};
use crate::sim_adv::scenario::{Event, EventKind, Scenario, ScenarioId};
use crate::sim_dynamic::build_world;
use crate::sim_dynamic::engine::step;

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
    /// Per-seed dispatch record (no-op executor in 0.1; empty when a scenario has no
    /// events, e.g. `honest_v2`).
    pub fired: Vec<Vec<FiredEvent>>,
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

/// The 0.1 no-op executor: RECORD the dispatch, touch nothing else. Kept as a free
/// function so the dispatch test can drive it directly. Phase 0.2 replaces the body with
/// real mutation (`&mut World`) behind this same call site.
fn dispatch_noop(due: &[Event], tick: u64, log: &mut Vec<FiredEvent>) {
    for ev in due {
        log.push(FiredEvent {
            tick,
            kind: ev.kind(),
        });
    }
}

/// Run one seed to the horizon and collect its god-view metrics + dispatch record.
///
/// The loop is `dispatch(t) → step` for `t in 0..horizon`, exactly the `sim_diag` shape
/// (which is a bare `step` loop) once the 0.1 dispatcher is a no-op — this is what makes
/// `honest_v2` seed-42 match `sim_diag 42 100 50 1 v2`.
pub(crate) fn run_one_seed(scenario: &Scenario, seed: u64) -> (MetricSet, Vec<FiredEvent>) {
    let params = &scenario.world.base;
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();

    let mut world = build_world(scenario.world.n_nodes, params, seed);
    let queue = EventQueue::from_scenario(&scenario.events);
    let mut fired: Vec<FiredEvent> = Vec::new();

    for t in 0..scenario.horizon {
        dispatch_noop(queue.due(t), t, &mut fired);
        step(&mut world, params, &prior, &policy);
    }

    (collect_metrics(&world, params), fired)
}

/// Run a scenario across `seeds`, fanning out over rayon. The collect preserves seed
/// order, so the aggregated report is deterministic (spec §10 п.12).
pub fn run(scenario: &Scenario, seeds: &[u64]) -> RunResult {
    let outcomes: Vec<(MetricSet, Vec<FiredEvent>)> = seeds
        .par_iter()
        .map(|&seed| run_one_seed(scenario, seed))
        .collect();

    let mut per_seed = Vec::with_capacity(outcomes.len());
    let mut fired = Vec::with_capacity(outcomes.len());
    for (m, f) in outcomes {
        per_seed.push(m);
        fired.push(f);
    }

    RunResult {
        scenario: scenario.id,
        seeds: seeds.to_vec(),
        per_seed,
        fired,
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
