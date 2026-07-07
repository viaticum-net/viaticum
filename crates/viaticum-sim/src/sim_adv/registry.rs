//! The scenario registry (design §5: scenarios are Rust structs, not a DSL).
//!
//! 0.1 registers a single scenario, `honest_v2` — a faithful replay of the current v2
//! acceptance run (n=100, block_volume=50, reciprocal, world-v2 defaults, 5 seeds 42..46)
//! whose seed-42 god-view numbers match `sim_diag 42 100 50 1 v2` (the regression anchor
//! that proves the harness does not distort the engine).

use crate::sim_adv::cli::SimAdvError;
use crate::sim_adv::metrics::MetricSet;
use crate::sim_adv::restore::RestoreTruth;
use crate::sim_adv::scenario::{Event, MetricId, NodeSel, Scenario, ScenarioId, WorldParams};
use crate::sim_adv::verdict::{Direction, Invariant, InvariantSpec};
use crate::sim_dynamic::engine::DynParams;
use crate::sim_dynamic::generator::{Archetype, GiverTier};

/// Restore window `W` in days (spec §10 п.9): 14 days = 2 weekly ticks.
const RESTORE_WINDOW_DAYS: f64 = 14.0;
/// Model-S restore download budget in GB/day (OPEN calibration guess; see [`WorldParams`]).
const RESTORE_BW_GB_DAY: f64 = 50.0;

/// Every registered scenario (hard-coded like `Archetype::ALL`).
pub fn all_scenarios() -> Vec<Scenario> {
    vec![honest_v2(), dr_baseline()]
}

/// Look a scenario up by name, or a graceful [`SimAdvError::UnknownScenario`] listing the
/// known names (NOT a panic — an unknown scenario is user error, not corruption).
pub fn find_scenario(name: &str) -> Result<Scenario, SimAdvError> {
    all_scenarios()
        .into_iter()
        .find(|s| s.id.as_str() == name)
        .ok_or_else(|| {
            let known = all_scenarios()
                .iter()
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            SimAdvError::UnknownScenario(name.to_string(), known)
        })
}

/// The honest baseline: the v2 acceptance run through the harness.
///
/// The world is `build_world`'s CANONICAL mix (`population`/`tiers` below document that
/// mix for the report; injecting a CUSTOM mix into `build_world` is a later tranche), so
/// its seed-42 numbers reproduce `sim_diag 42 100 50 1 v2` exactly.
pub fn honest_v2() -> Scenario {
    Scenario {
        id: ScenarioId("honest_v2"),
        about: "v2 acceptance replay (n=100, bv=50, reciprocal, world-v2 defaults) — the honest baseline & regression anchor vs sim_diag",
        world: WorldParams {
            n_nodes: 100,
            // DynParams::default() IS the v2 world (block_volume=50, reciprocal placement,
            // incremental+bandwidth+cream on, Р-2 recalibrated prior) — the exact dials
            // `sim_diag 42 100 50 1 v2` runs.
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
        },
        // The engine's canonical §3 mixes (documented for the report header).
        population: vec![
            (Archetype::Reliable, 0.40),
            (Archetype::Weekend, 0.20),
            (Archetype::Seasonal, 0.15),
            (Archetype::Nomad, 0.10),
            (Archetype::Hoarder, 0.10),
            (Archetype::Freeloader, 0.05),
        ],
        tiers: vec![
            (GiverTier::T1, 0.35),
            (GiverTier::T2, 0.30),
            (GiverTier::T3, 0.25),
            (GiverTier::T4, 0.10),
        ],
        adversaries: Vec::new(),
        events: Vec::new(),
        // 130 ticks = the sim_diag horizon (its section-6 diagnostics run after 130 steps).
        horizon: 130,
        // Five seeds 42..46 inclusive (the acceptance seed band).
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![MetricId::Extraction, MetricId::InvariantBoard],
        verdicts: honest_v2_invariants(),
        fast: true,
    }
}

/// The DR baseline: `honest_v2` + a Disaster on one T1/Reliable node at tick 60 (design
/// §4 п.1, detail §3.1). Measures restore-truth (metric №1) over the mature honest world.
///
/// NOTE-8: this is a SANITY FLOOR (restore-truth should sit HIGH under the current
/// near-always-on uptime — a T1/Reliable node's holders are almost all reachable), NOT a
/// regression detector. Metric №1 only starts to DISCRIMINATE once the phase-2 uptime
/// profiles (nomad / vacation) make "online at least once in the window" a real gate.
pub fn dr_baseline() -> Scenario {
    Scenario {
        id: ScenarioId("dr_baseline"),
        about: "honest_v2 + Disaster of one T1/Reliable node @ tick 60 — restore-truth (metric №1) sanity floor (NOTE-8)",
        world: WorldParams {
            n_nodes: 100,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: Vec::new(),
        // Strike the reliable backbone (the DR-primary "Ilya's NAS") at tick 60 — a mature
        // world (well past the incremental-join fill), leaving room for the W-window well
        // inside the 130-tick horizon.
        events: vec![(
            60,
            Event::Disaster(NodeSel::FirstTierArchetype(
                GiverTier::T1,
                Archetype::Reliable,
            )),
        )],
        horizon: 130,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![MetricId::RestoreTruth, MetricId::InvariantBoard],
        verdicts: dr_baseline_invariants(),
        fast: true,
    }
}

/// Reliable's extraction ROI (Reliable is index 0 in `Archetype::ALL`).
fn reliable_roi(m: &MetricSet) -> f64 {
    m.extraction_roi[0]
}

/// The flagship restore-truth scalar (Model U, any symbol) for a seed.
fn restore_u(r: &RestoreTruth) -> f64 {
    r.restore_truth_u()
}

/// The invariant board v0 (design §3.8 / spec §10 п.17).
fn honest_v2_invariants() -> Vec<Invariant> {
    vec![
        Invariant {
            id: "INV-DETERMINISM",
            spec: InvariantSpec::Determinism,
            threshold: 1.0,
        },
        Invariant {
            id: "INV-ANTI-ORACLE",
            spec: InvariantSpec::AntiOracle,
            threshold: 1.0,
        },
        // The real non-inflation test (replaces the tautological INV-AGG-1, spec §10
        // п.17), FACT-CORRECTED. The spec's literal "per-archetype ROI < 1" is
        // impossible: the served matrix conserves (Σ consumed ≡ Σ served_out over all
        // cells), so the served-weighted mean ROI is EXACTLY 1 — some archetype must be
        // ≥ 1. Measured on the honest world, the dominant honest giver Reliable sits at
        // BALANCED reciprocity (ROI ≈ 1.04, seeds 42..46 ∈ [1.01, 1.07]), NOT below 1.
        // So the honest invariant is BOUNDED extraction, not net-provider: the honest
        // giver does not run away with free storage — its ROI stays under a 1.25 slack
        // ceiling (a round SEMANTIC bound with a wide margin, frozen on the honest run —
        // anti-Goodhart; it FAILS only if a regression lets an honest node extract far
        // above balance). The per-archetype ROI table in the report is the evidence.
        Invariant {
            id: "INV-ROI-RELIABLE",
            spec: InvariantSpec::Statistical {
                measure: reliable_roi,
                dir: Direction::LessThan,
            },
            threshold: 1.25,
        },
    ]
}

/// The `dr_baseline` board: the two structural rows + the restore-truth sanity floor.
fn dr_baseline_invariants() -> Vec<Invariant> {
    vec![
        Invariant {
            id: "INV-DETERMINISM",
            spec: InvariantSpec::Determinism,
            threshold: 1.0,
        },
        Invariant {
            id: "INV-ANTI-ORACLE",
            spec: InvariantSpec::AntiOracle,
            threshold: 1.0,
        },
        // INV-RESTORE-SANITY (design §4 п.1 / spec §10 п.19, NOTE-8): the flagship
        // restore-truth U must clear a floor on the honest DR baseline. FROZEN from the
        // actual honest run (seeds 42..46: restore-truth U = 1.0000 on EVERY seed, σ = 0 —
        // an established T1/Reliable node's floor symbols are reciprocity-protected and its
        // holders are near-always-online, so all three blocks re-collect inside the 2-tick
        // window), with wide margin — the same anti-Goodhart discipline as INV-ROI-RELIABLE.
        // A round 0.60 floor means "FAIL if > 40% of the victim's blocks become
        // unrestorable" — a real DR-collapse gate that clears the honest 1.0 decisively
        // yet tolerates the coarse 3-block granularity's seed-to-seed noise (a single-block
        // hiccup on one seed → mean ≈ 0.933, power ≈ 2.2 vs 0.60 ⇒ still PASS). (GreaterThan
        // ⇒ PASS when mean > 0.60 with power ≥ 2; power<2 ⇒ INCONCLUSIVE, spec §10 п.16; here
        // σ = 0 ⇒ power = ∞ ⇒ decisive PASS.)
        Invariant {
            id: "INV-RESTORE-SANITY",
            spec: InvariantSpec::RestoreStatistical {
                measure: restore_u,
                dir: Direction::GreaterThan,
            },
            threshold: 0.60,
        },
    ]
}
