//! The scenario registry (design §5: scenarios are Rust structs, not a DSL).
//!
//! 0.1 registers a single scenario, `honest_v2` — a faithful replay of the current v2
//! acceptance run (n=100, block_volume=50, reciprocal, world-v2 defaults, 5 seeds 42..46)
//! whose seed-42 god-view numbers match `sim_diag 42 100 50 1 v2` (the regression anchor
//! that proves the harness does not distort the engine).

use crate::sim_adv::cli::SimAdvError;
use crate::sim_adv::hetero::{DemandClass, DemandMix, DiskPolicy, HeteroReport};
use crate::sim_adv::metrics::MetricSet;
use crate::sim_adv::predators::AdvMetrics;
use crate::sim_adv::restore::RestoreTruth;
use crate::sim_adv::scenario::{
    AdvDials, AdvId, AdvSpec, Event, InfoModel, MetricId, NodeSel, Scenario, ScenarioId,
    WorldParams,
};
use crate::sim_adv::verdict::{Direction, Invariant, InvariantSpec};
use crate::sim_dynamic::engine::DynParams;
use crate::sim_dynamic::generator::{Archetype, GiverTier};

/// Restore window `W` in days (spec §10 п.9): 14 days = 2 weekly ticks.
const RESTORE_WINDOW_DAYS: f64 = 14.0;
/// Model-S restore download budget in GB/day (OPEN calibration guess; see [`WorldParams`]).
const RESTORE_BW_GB_DAY: f64 = 50.0;

/// Every registered scenario (hard-coded like `Archetype::ALL`).
pub fn all_scenarios() -> Vec<Scenario> {
    vec![
        honest_v2(),
        dr_baseline(),
        a1_whale(),
        a4_whitewasher(),
        a2_dropper(),
        honest_hetero_v2(),
        honest_hetero_hard(),
        dr_hetero(),
    ]
}

/// The hetero-v2 demand mix (D1): S 60% / M 30% / L 10% — a long tail of small owners with a
/// few big-footprint archives (the DR-primary T1 NAS shape). Shared by the hetero scenarios; the
/// [`DiskPolicy`] selects the LIGHT (`Grow`) vs HARD (`Fixed`) device regime (WARN-2).
fn hetero_mix(disk: DiskPolicy) -> DemandMix {
    DemandMix::Classes(
        vec![
            (DemandClass::S, 0.60),
            (DemandClass::M, 0.30),
            (DemandClass::L, 0.10),
        ],
        disk,
    )
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
            demand: DemandMix::Uniform,
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
        // RhatCalibration (transche 0.3): the sim-unification judge — Brier + reliability/
        // resolution of the kernel's own placement forecast (spec §10 п.7).
        metrics: vec![
            MetricId::Extraction,
            MetricId::RhatCalibration,
            MetricId::InvariantBoard,
        ],
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
            demand: DemandMix::Uniform,
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

/// The A1 ε-give whale scenario (phase 1, `4r_p1_spec.md` §3 / detail §2-A1): the honest
/// world plus four ε-give whales — each an honest-uptime node with ×12 the backup demand that
/// serves only 5% (so it earns almost no reciprocity κ_O). It probes the Р-7 V_ret cap (P1b):
/// where the cap engages, the whale's parked volume is trimmed to ≈ V_free, and its
/// protected-storage integral falls below its matched honest twin (same ×12 demand, serving
/// fully — the honest heavy backer).
///
/// The world is the default v2 world; the whales' heavy demand + own-data growth over a long
/// horizon drive the holders deep into the eviction band, where the cap binds hard enough that
/// the honest twin's earned V_ret clearly outstrips the whale's V_free floor. `n = 60`,
/// horizon 170, 5 seeds.
pub fn a1_whale() -> Scenario {
    Scenario {
        id: ScenarioId("a1_whale"),
        about: "honest world + 4 ε-give whales (×12 demand, serve 5%) — Р-7 V_ret cap (P1b) + protected-storage ≤ honest twin",
        world: WorldParams {
            n_nodes: 60,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: DemandMix::Uniform,
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: vec![AdvSpec {
            id: AdvId::A1EpsilonWhale,
            count: 4,
            info_model: InfoModel::Own,
            dials: AdvDials {
                whale_block_mult: 12.0,
                whale_accept: 0.05,
                ..AdvDials::default()
            },
        }],
        events: Vec::new(),
        horizon: 170,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![
            MetricId::AttackRoi,
            MetricId::Extraction,
            MetricId::InvariantBoard,
        ],
        verdicts: a1_whale_invariants(),
        fast: true,
    }
}

/// The A4 whitewasher scenario (phase 1, `4r_p1_spec.md` §4 / detail §2-A4): the honest world
/// plus six whitewashers — honest-uptime nodes that burn their identity every 20 ticks
/// (serve → drop → self-churn → re-enter fresh). It probes the pair-local entry price: a
/// re-entered identity gets NO credit for its prior life (κ_O reset ⇒ V_ret = V_free), and the
/// total delivered park over the cycles falls below the continuous honest twin.
///
/// `period_ticks = 20`: long enough to (re-)establish a floor each cycle (bandwidth ≈ 1
/// chunk/tick, 15 floor symbols) — a real attempt — yet each reset orphans the accumulated
/// backups and re-pays the θ_p/λ entry. Six whitewashers keep the per-seed aggregate tight.
/// `n = 70`, horizon 140, 5 seeds.
pub fn a4_whitewasher() -> Scenario {
    Scenario {
        id: ScenarioId("a4_whitewasher"),
        about: "honest world + 6 whitewashers (burn identity every 20 ticks) — re-entry price (P2): fresh identity ≤ V_free + delivered park ≤ honest twin",
        world: WorldParams {
            n_nodes: 70,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: DemandMix::Uniform,
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: vec![AdvSpec {
            id: AdvId::A4Whitewasher,
            count: 6,
            info_model: InfoModel::Own,
            dials: AdvDials {
                period_ticks: 20,
                ..AdvDials::default()
            },
        }],
        events: Vec::new(),
        horizon: 140,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![
            MetricId::AttackRoi,
            MetricId::Extraction,
            MetricId::InvariantBoard,
        ],
        verdicts: a4_whitewasher_invariants(),
        fast: true,
    }
}

/// The A2 DropNotice-refuser scenario (phase 4-in-sim, `4r_a2_spec.md`): the honest world plus
/// eight voluntary droppers, each shedding `drop_rate = 4%` of its foreign holdings every tick.
///
/// **The matched control is NOT the honest node** (unlike A1/A4) — it is the POLITE dropper
/// (`twin_hook_for(A2)` = `a2_polite_dropper_hook`): the predator (SILENT) and its twin (POLITE)
/// drop the SAME victims at the SAME rate by the SAME deterministic selection — EQUAL harm — and
/// differ ONLY in whether each drop is announced. So the comparison isolates the PRICE OF
/// SILENCE: the silent drop burns the owner's reliability capital `g_oh` at `b_max` (a total-loss
/// burn ⇒ ≈ 0) and jumps σ; the announced drop rides the F2 notice (dies at T+1) and burns only
/// `b_ann`. `n = 80`, 8 droppers (10% — enough to tighten the per-seed g_oh aggregate to a
/// power-5+ verdict), horizon 160 (≥ 3 PoS/σ windows so burn + detection settle), 5 seeds.
///
/// **δ is frozen BEFORE the run at 0.15 (anti-Goodhart, spec §3): INV-A2-SILENT-PUNISHED asserts
/// `g_oh(silent) / g_oh(polite) < 1 − δ = 0.85`.** Calibrating the SCENARIO (drop_rate, n,
/// horizon) is allowed; the threshold is not.
pub fn a2_dropper() -> Scenario {
    Scenario {
        id: ScenarioId("a2_dropper"),
        about: "honest world + 8 voluntary droppers (silent predator vs polite twin, EQUAL 4%/tick drop) — the price of silence (g_oh ledger + inflow)",
        world: WorldParams {
            n_nodes: 80,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: DemandMix::Uniform,
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: vec![AdvSpec {
            id: AdvId::A2DropRefuser,
            count: 8,
            info_model: InfoModel::Own,
            // drop_rate = the shared equal-harm dial (both arms). announce is set by the
            // injection MODE (predator = silent hook, twin = polite hook), NOT this field.
            dials: AdvDials {
                drop_rate: 0.04,
                ..AdvDials::default()
            },
        }],
        events: Vec::new(),
        horizon: 160,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![
            MetricId::AttackRoi,
            MetricId::Extraction,
            MetricId::InvariantBoard,
        ],
        verdicts: a2_dropper_invariants(),
        fast: true,
    }
}

/// The honest hetero-v2 world (D1): the v2 world with a per-owner DEMAND-CLASS mix (S 60% /
/// M 30% / L 10%) instead of the uniform blocks_per_node footprint. Measures whether a big
/// footprint (L-class, 10 blocks) reaches floor under the credit / reciprocity constraint —
/// the D1 question. The M owners are byte-identical to `honest_v2`; only S/L rebuild.
///
/// `n = 200` (⇒ ~120 S / 60 M / 20 L), horizon 130 (past L's 10th block maturing at tick 54 and
/// its ~tick-63 full-placement, well onto the placement plateau; matches `honest_v2`'s horizon
/// so the network is not over-depopulated by churn-without-rejoin). `n = 200` (not 100) so the
/// smallest class L carries ~20 owners — enough that the per-seed no-starvation RATIO is not
/// dominated by a handful of L owners' noise (at n=100 the real effect sits below the power-2
/// gate purely from small-sample variance; more owners is the power-discipline fix, not a
/// threshold change). 5 seeds.
pub fn honest_hetero_v2() -> Scenario {
    Scenario {
        id: ScenarioId("honest_hetero_v2"),
        about: "honest world + per-owner demand classes (S 60% / M 30% / L 10%) — does the big L-footprint reach floor under credit/reciprocity? (D1)",
        world: WorldParams {
            n_nodes: 200,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: hetero_mix(DiskPolicy::Grow),
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: Vec::new(),
        events: Vec::new(),
        horizon: 130,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![
            MetricId::Extraction,
            MetricId::RhatCalibration,
            MetricId::InvariantBoard,
        ],
        verdicts: honest_hetero_v2_invariants(),
        fast: false,
    }
}

/// The HARD hetero regime (WARN-2 — the SHARP D1 test): identical to `honest_hetero_v2` (same
/// classes, n, horizon, seeds) EXCEPT the device cap is FIXED at `build_world` size for every
/// class ([`DiskPolicy::Fixed`]). The L owner's source scales ×10/3 on an UNCHANGED disk, so its
/// own-data eats its own device (truncated at the cap when it overflows — the "full device" P7 T4
/// physics), leaving little lendable free ⇒ little κ_O ⇒ V_ret near V_free. This is a big footprint
/// on an ORDINARY device: does the credit / reciprocity mechanic LOCK it? Any outcome is
/// informative — a FAIL here is the real credit-lock finding (report, do NOT tune).
pub fn honest_hetero_hard() -> Scenario {
    Scenario {
        id: ScenarioId("honest_hetero_hard"),
        about: "hetero classes on a FIXED ordinary device (L source eats its disk ⇒ little lendable ⇒ little credit) — the SHARP D1 credit-lock test (WARN-2)",
        world: WorldParams {
            n_nodes: 200,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: hetero_mix(DiskPolicy::Fixed),
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: Vec::new(),
        events: Vec::new(),
        horizon: 130,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![
            MetricId::Extraction,
            MetricId::RhatCalibration,
            MetricId::InvariantBoard,
        ],
        verdicts: honest_hetero_hard_invariants(),
        fast: false,
    }
}

/// The hetero DR (D1 + axis 8): the hetero world + a Disaster on ONE reliable owner of EACH
/// footprint class (S/M/L) at tick 60, measuring restore-truth PER CLASS. The L-class victim
/// (a big-footprint NAS) is the DR-primary headline — does its large restored footprint
/// re-collect as well as a small one?
///
/// Disaster at tick 60 (the mature-but-healthy world, matching `dr_baseline`'s timing — the
/// long horizon depopulates the network via churn-without-rejoin, which would confound the
/// restore signal, so the strike lands while the holders are still present), horizon 130.
pub fn dr_hetero() -> Scenario {
    Scenario {
        id: ScenarioId("dr_hetero"),
        about: "hetero world + Disaster of one reliable S/M/L owner @ tick 60 — restore-truth PER CLASS (the L victim is DR-primary)",
        world: WorldParams {
            n_nodes: 100,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: hetero_mix(DiskPolicy::Grow),
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: Vec::new(),
        // One reliable victim of each footprint class, same tick — restore-truth splits by class.
        events: vec![
            (
                60,
                Event::Disaster(NodeSel::FirstDemandArchetype(
                    DemandClass::S,
                    Archetype::Reliable,
                )),
            ),
            (
                60,
                Event::Disaster(NodeSel::FirstDemandArchetype(
                    DemandClass::M,
                    Archetype::Reliable,
                )),
            ),
            (
                60,
                Event::Disaster(NodeSel::FirstDemandArchetype(
                    DemandClass::L,
                    Archetype::Reliable,
                )),
            ),
        ],
        horizon: 130,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![MetricId::RestoreTruth, MetricId::InvariantBoard],
        verdicts: dr_hetero_invariants(),
        fast: false,
    }
}

/// Reliable's extraction ROI (Reliable is index 0 in `Archetype::ALL`).
fn reliable_roi(m: &MetricSet) -> f64 {
    m.extraction_roi[0]
}

/// The L-class NO-STARVATION ratio: the big footprint's floor-completeness relative to the
/// smaller-footprint owners' baseline `mean(S, M)`. ≥ 1 ⇒ the big footprint places AT LEAST as
/// well as the small owners (the D1 "no lock"). This is COMPARATIVE, not absolute, on purpose:
/// the substrate's "n_symbols (=5) SIMULTANEOUS floor holders" bar caps ABSOLUTE
/// floor-completeness for EVERY class (even the honest M baseline sits ≈ 0.35 — blocks settle
/// near k_eff under the eviction economy), so an absolute floor would measure that substrate
/// difficulty, not hetero starvation. The starvation question is inherently RELATIVE. `NaN` if
/// there is no small-owner baseline.
fn hetero_l_no_starvation(h: &HeteroReport) -> f64 {
    let l = h.l_floor_completeness();
    let s = h.class[DemandClass::S.index()].floor_completeness;
    let m = h.class[DemandClass::M.index()].floor_completeness;
    let peer = (s + m) / 2.0;
    if peer > 0.0 { l / peer } else { f64::NAN }
}

/// The L-class restore-truth U (any symbol) — the hetero DR per-class headline scalar.
fn restore_u_l(r: &RestoreTruth) -> f64 {
    r.restore_u_in_class(DemandClass::L)
}

/// The predator's Р-7 cap ratio (max parked / (V_ret + one chunk) where the cap engages).
fn adv_cap_ratio(a: &AdvMetrics) -> f64 {
    a.max_cap_ratio
}

/// The predator's protected-own-storage integral (`consumed` gb·days = §3.3 utility).
fn adv_consumed(a: &AdvMetrics) -> f64 {
    a.consumed
}

/// The predator's raw extraction ROI `consumed / served_out`.
fn adv_roi(a: &AdvMetrics) -> f64 {
    a.roi
}

/// A2: the price-of-silence ledger — `Σ_O g_oh` (owners' reliability record of the adversary).
fn adv_retention_g(a: &AdvMetrics) -> f64 {
    a.retention_g
}

/// A2: the placement-inflow proxy — total foreign symbols the adversary was ever offered-and-
/// accepted (`Σ_adv holdings.len()`).
fn adv_inflow(a: &AdvMetrics) -> f64 {
    a.inflow_total
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

/// The `a1_whale` board (`4r_p1_spec.md` §3): the two structural rows + the Р-7 cap (P1b) +
/// the Attack-ROI comparative (protected-storage ≤ honest twin).
fn a1_whale_invariants() -> Vec<Invariant> {
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
        // INV-P1B-CAP (P1b / detail §2-A1): where the Р-7 cap engages (evicting holders), the
        // ε-whale's SETTLED parked volume is bounded by `V_ret + one chunk`. The metric is
        // `max parked / (V_ret + v_per_symbol)`, so the round threshold 1.0 IS the cap
        // formula itself (NOT a calibrated number — anti-Goodhart): PASS ⇒ the whale parks
        // within its earned V_ret everywhere the cap binds, FAIL ⇒ it hoards beyond the cap.
        // (LessThan, power-gated; NaN — no evicting holder held whale data — ⇒ INCONCLUSIVE.)
        Invariant {
            id: "INV-P1B-CAP",
            spec: InvariantSpec::AdvCap {
                measure: adv_cap_ratio,
                dir: Direction::LessThan,
            },
            threshold: 1.0,
        },
        // INV-ROI-PRED≤TWIN (spec §4 п.3 / detail §3.3): the whale's protected-own-storage
        // integral (consumed gb·days) ≤ its matched honest twin's, at equal ×12 demand — the
        // attack buys no more durable protection than serving honestly. The comparative ratio
        // `consumed(pred)/consumed(twin) < 1.0` (threshold IS the "no better than honest"
        // line, not calibrated); power<2 ⇒ INCONCLUSIVE (no clear effect). This is the
        // STRUCTURALLY robust row (stays defined even for a future predator whose served → 0).
        Invariant {
            id: "INV-ROI-PRED≤TWIN",
            spec: InvariantSpec::AdvComparative {
                measure: adv_consumed,
                dir: Direction::LessThan,
            },
            threshold: 1.0,
        },
        // INV-ROI-RAW≤TWIN (WARN-2): the RAW extraction ratio `consumed/served_out` also passes
        // pred < twin, asserted here as an ADDITIONAL row WHILE it is defined (both sides serve
        // comparably in this scenario, so it is — not undefined). `roi(pred)/roi(twin) < 1.0`.
        Invariant {
            id: "INV-ROI-RAW≤TWIN",
            spec: InvariantSpec::AdvComparative {
                measure: adv_roi,
                dir: Direction::LessThan,
            },
            threshold: 1.0,
        },
    ]
}

/// The `a4_whitewasher` board (`4r_p1_spec.md` §4): the two structural rows + the re-entry
/// price (P2) + the Attack-ROI comparative (delivered park ≤ honest twin).
fn a4_whitewasher_invariants() -> Vec<Invariant> {
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
        // INV-P2-REENTRY (P2 / detail §2-A4): a re-entered identity is bounded by the V_ret it
        // has EARNED IN ITS CURRENT life (κ_O wiped on each burn), never its lifetime — the
        // same Р-7 cap machinery as INV-P1B-CAP, read where the cap engages. Because each
        // cycle resets κ_O the whitewasher's V_ret collapses toward V_free, so it gets no
        // Sybil discount from its prior identities. Metric `max parked / (V_ret + chunk) < 1`.
        Invariant {
            id: "INV-P2-REENTRY",
            spec: InvariantSpec::AdvCap {
                measure: adv_cap_ratio,
                dir: Direction::LessThan,
            },
            threshold: 1.0,
        },
        // INV-ROI-PRED≤TWIN (spec §4 п.3 / detail §3.3): total delivered park over N cycles
        // (consumed gb·days) ≤ the CONTINUOUS honest twin's — each identity burn orphans the
        // accumulated backups and re-pays the entry latency, so the whitewash cycle protects
        // strictly less than serving straight through. Ratio `consumed(pred)/consumed(twin) < 1`.
        // The STRUCTURALLY robust row (defined even if a future predator's served → 0).
        Invariant {
            id: "INV-ROI-PRED≤TWIN",
            spec: InvariantSpec::AdvComparative {
                measure: adv_consumed,
                dir: Direction::LessThan,
            },
            threshold: 1.0,
        },
        // INV-ROI-RAW≤TWIN (WARN-2): the RAW extraction ratio `consumed/served_out` also passes
        // pred < twin (the whitewasher serves ~as much as the twin but protects far less), an
        // ADDITIONAL row WHILE the ratio is defined. `roi(pred)/roi(twin) < 1.0`.
        Invariant {
            id: "INV-ROI-RAW≤TWIN",
            spec: InvariantSpec::AdvComparative {
                measure: adv_roi,
                dir: Direction::LessThan,
            },
            threshold: 1.0,
        },
    ]
}

/// The `a2_dropper` board (`4r_a2_spec.md` §3): the two structural rows + the price-of-silence
/// comparative (g_oh ledger) + the placement-inflow comparative. Both are pred(silent)/twin(polite)
/// ratios (the A2 twin is the POLITE dropper, not the honest node).
fn a2_dropper_invariants() -> Vec<Invariant> {
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
        // INV-A2-SILENT-PUNISHED (spec §3): the silent dropper's reliability capital owners hold
        // in it (`Σ_O g_oh`) is punished BELOW the polite twin's by more than δ — the price of
        // silence. Ratio `retention_g(silent)/retention_g(polite) < 1 − δ = 0.85`, δ = 0.15 FROZEN
        // before the run (anti-Goodhart: calibrate the scenario, never this threshold). LessThan,
        // power-gated (spec §10 п.16): the silent drop burns `g_oh` at b_max (total loss ⇒ ≈ 0),
        // the announced drop at b_ann (barely), so this discriminates hard. A twin g_oh of 0 ⇒ NaN
        // (skipped). This is the LEDGER price — see the report on whether it is yet ENFORCED.
        Invariant {
            id: "INV-A2-SILENT-PUNISHED",
            spec: InvariantSpec::AdvComparative {
                measure: adv_retention_g,
                dir: Direction::LessThan,
            },
            threshold: 0.85,
        },
        // INV-A2-INFLOW (spec §3): owners turn away from the silent dropper ⇒ its placement
        // inflow (foreign symbols offered-and-accepted) sits BELOW the polite twin's. Ratio
        // `inflow(silent)/inflow(polite) < 1.0` (the natural no-effect boundary, frozen). LessThan,
        // power-gated. HONEST NOTE (report): the DECISIVE placement path (post-0.3 sim-unification)
        // reads only the surface PoS-window, NOT g_oh / drop-counters / σ, so this row is EXPECTED
        // to land INCONCLUSIVE — the enforcement consumer of the reliability ledger is not yet
        // wired (spec §3 zoo-gate: σ/drop consumers are phase-4/diagnostic). The row MEASURES that
        // gap; it is NOT tuned to pass.
        Invariant {
            id: "INV-A2-INFLOW",
            spec: InvariantSpec::AdvComparative {
                measure: adv_inflow,
                dir: Direction::LessThan,
            },
            threshold: 1.0,
        },
    ]
}

/// The `honest_hetero_v2` board: the two structural rows + the no-starvation floor on the
/// L-class footprint.
fn honest_hetero_v2_invariants() -> Vec<Invariant> {
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
        // INV-HETERO-NO-STARVATION (D1): does the mechanic LOCK the large footprint? The measure
        // is the COMPARATIVE ratio L-floor-completeness / mean(S, M) — the big footprint's
        // placement success RELATIVE to the small owners. The threshold 0.75 is a SEMANTIC
        // no-starvation line ("the big footprint places within 25 % of the small owners"), frozen
        // anti-Goodhart — NOT fitted (the measured ratio sits ≈ 1.2, so L actually places AT LEAST
        // as well as its small peers). Comparative, not absolute, because the substrate's
        // 5-simultaneous-floor bar caps ABSOLUTE floor-completeness for EVERY class (honest M ≈
        // 0.35), so an absolute floor would test substrate difficulty, not starvation. GreaterThan,
        // power-gated (spec §10 п.16): a genuine LOCK (L far below its peers) FAILS, and that FAIL
        // is a real FINDING — the threshold is NOT to be lowered to hide it. The per-class table +
        // the L-curve in the report carry the absolute numbers (nothing hidden).
        Invariant {
            id: "INV-HETERO-NO-STARVATION",
            spec: InvariantSpec::HeteroStatistical {
                measure: hetero_l_no_starvation,
                dir: Direction::GreaterThan,
            },
            threshold: 0.75,
        },
    ]
}

/// The `honest_hetero_hard` board: the two structural rows + INV-HETERO-HARD — the SAME comparative
/// no-starvation measure and the SAME frozen 0.75 threshold as the light regime (WARN-2 asks for
/// the identical bar), read on the FIXED-device world. A FAIL here (L placement collapses below its
/// small peers once its own source eats its disk) is the real credit-lock finding — NOT to be tuned.
fn honest_hetero_hard_invariants() -> Vec<Invariant> {
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
        Invariant {
            id: "INV-HETERO-HARD",
            spec: InvariantSpec::HeteroStatistical {
                measure: hetero_l_no_starvation,
                dir: Direction::GreaterThan,
            },
            threshold: 0.75,
        },
    ]
}

/// The `dr_hetero` board: the two structural rows + the L-class restore-truth floor.
fn dr_hetero_invariants() -> Vec<Invariant> {
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
        // INV-RESTORE-HETERO-L (D1 + axis 8): the big-footprint L victim's restore-truth U must
        // clear the same 0.60 semantic floor as INV-RESTORE-SANITY — "FAIL if > 40% of the big
        // restored footprint is unrestorable". Frozen anti-Goodhart (the honest DR sits high
        // under the near-always-on uptime); a genuine collapse FAILS and is a real finding. The
        // per-class restore table (S vs M vs L) in the report is the comparative evidence.
        Invariant {
            id: "INV-RESTORE-HETERO-L",
            spec: InvariantSpec::RestoreStatistical {
                measure: restore_u_l,
                dir: Direction::GreaterThan,
            },
            threshold: 0.60,
        },
    ]
}
