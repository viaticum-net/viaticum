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
//! ## Added in 0.2 (restore-truth + Disaster)
//!
//! * The [`Event::Disaster`] executor: it strikes a victim (loses source + holdings, P1),
//!   returns it one tick later with the same identity, and never lets the source-less
//!   owner "repair" (the `to_restore` gate in `place_own_data`).
//! * Restore-truth (metric №1, [`restore`]): the god-view fraction of a victim's blocks
//!   that can be COLD-RESTORED (≥ `k_eff` live symbols re-collected in a `W`-day window),
//!   under Model U (union-over-window) and Model S (bandwidth-aware) — plus the floor-only
//!   `durability_floor`. Scenario `dr_baseline` + the `INV-RESTORE-SANITY` board row.
//!
//! ## Still deliberately NOT here (later tranches)
//!
//! The other event executors (subnet kills, join waves, ...) are still recorded-only.
//! Predator behaviour is phase 1: only the anti-oracle hook SIGNATURES exist
//! ([`BehaviorHook`], which by construction cannot borrow `&World` — spec §10 п.14 /
//! WARN-5). Sim-unification (0.3) and heterogeneous volumes (0.4) are separate tranches.

#[cfg(test)]
mod tests;

pub mod bootstrap;
pub mod brier;
pub mod cli;
pub mod hetero;
pub mod metrics;
pub mod predators;
pub mod registry;
pub mod report;
pub mod restore;
pub mod runner;
pub mod scenario;
pub mod tier;
pub mod uptime;
pub mod verdict;

pub use bootstrap::{BootstrapStats, collect_bootstrap, mean_over_seeds, run_bootstrap};
pub use brier::{BrierBucket, BrierReport, Calibration, DEFAULT_BRIER_BUCKETS, IncompleteSummary};
pub use cli::{Cli, SimAdvError, Sweep, parse_cli};
pub use hetero::{
    ClassMetrics, DemandClass, DemandMix, HeteroReport, HeteroSample, apply_demand_classes,
};
pub use metrics::MetricSet;
pub use predators::{AdvMetrics, RunMode, collect_adv_metrics, hook_for, inject_adversaries};
pub use registry::{all_scenarios, find_scenario};
pub use report::{format_report, format_sweep, restore_csv, run_result_csv, sweep_csv};
pub use restore::{BlockOutcome, RestoreTracker, RestoreTruth};
pub use runner::{AdvPair, FiredEvent, RunResult, run, run_sweep};
pub use scenario::{
    AdvAction, AdvContext, AdvDials, AdvId, AdvRole, AdvSpec, BehaviorHook, Event, EventKind,
    InfoModel, MetricId, NodeSel, Scenario, ScenarioId, WorldParams,
};
pub use tier::{TierMetrics, TierMix, TierReport, apply_tier_mix, tier_report};
pub use uptime::{UptimeMix, UptimeProfile, tier_profile};
pub use verdict::{Direction, Invariant, InvariantSpec, Verdict, VerdictKind, evaluate_board};
