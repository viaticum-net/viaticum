//! `sim_adv` — the World-v3 adversarial-polygon harness (phase 0, sub-tranche 0.1).
//!
//! This is the SKELETON of the "measuring instrument" polygon (design
//! `4r_world_v3_spec.md` §5 / `4r_world_v3_detail.md` §4). It reuses the
//! [`crate::sim_dynamic`] engine unchanged — it is NOT a fork — driving it through the
//! engine's existing `pub` surface (`build_world` / `step` / `World` god-view fields).
//!
//! ## What sub-tranche 0.1 delivers (behaviour-neutral)
//!
//! * A scenario REGISTRY — scenarios are Rust structs ([`Scenario`]), not a DSL
//!   (convention "no magic"). [`registry::all_scenarios`] / [`registry::find_scenario`].
//! * Multi-seed fan-out via rayon ([`runner::run`]), aggregated into a seed-INDEXED
//!   `Vec` (never in thread-completion order) so the report is byte-identical on repeat.
//! * A PASS / FAIL / INCONCLUSIVE verdict engine ([`verdict`]) that reports effect/σ and
//!   returns INCONCLUSIVE whenever statistical power `< 2` (spec §10 п.16).
//! * An invariant board v0: determinism, anti-oracle (structural), and per-node
//!   extraction-ROI by archetype (spec §10 п.17, replacing the tautological INV-AGG-1).
//! * The first scenario `honest_v2` — a faithful replay of the current v2 acceptance
//!   run, whose seed-42 numbers MATCH `sim_diag 42 100 50 1 v2` (regression anchor).
//!
//! ## Deliberately NOT in 0.1 (later tranches)
//!
//! Event EXECUTION (Disaster wiping a node, subnet kills, ...) is phase 0.2+: here the
//! [`Event`] vocabulary and the tick-indexed dispatch queue exist, but the executor is a
//! NO-OP that only RECORDS which event fired at which tick (so the dispatch is testable)
//! and never touches `&mut World`. Predator behaviour is phase 1: only the anti-oracle
//! hook SIGNATURES exist ([`BehaviorHook`], which by construction cannot borrow `&World`
//! — spec §10 п.14 / WARN-5). Restore-truth (0.2), sim-unification (0.3) and
//! heterogeneous volumes (0.4) are separate tranches.

#[cfg(test)]
mod tests;

pub mod cli;
pub mod metrics;
pub mod registry;
pub mod report;
pub mod runner;
pub mod scenario;
pub mod verdict;

pub use cli::{Cli, SimAdvError, Sweep, parse_cli};
pub use metrics::MetricSet;
pub use registry::{all_scenarios, find_scenario};
pub use report::{format_report, format_sweep, run_result_csv, sweep_csv};
pub use runner::{FiredEvent, RunResult, run, run_sweep};
pub use scenario::{
    AdvAction, AdvContext, AdvDials, AdvId, AdvSpec, BehaviorHook, Event, EventKind, InfoModel,
    MetricId, NodeSel, Scenario, ScenarioId, WorldParams,
};
pub use verdict::{Direction, Invariant, InvariantSpec, Verdict, VerdictKind, evaluate_board};
