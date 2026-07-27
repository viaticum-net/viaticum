//! The scenario registry (design §5: scenarios are Rust structs, not a DSL).
//!
//! 0.1 registers a single scenario, `honest_v2` — a faithful replay of the current v2
//! acceptance run (n=100, block_volume=50, reciprocal, world-v2 defaults, 5 seeds 42..46)
//! whose seed-42 god-view numbers match `sim_diag 42 100 50 1 v2` (the regression anchor
//! that proves the harness does not distort the engine).

use crate::sim_adv::cli::SimAdvError;
use crate::sim_adv::hetero::{DemandClass, DemandMix, DiskPolicy, HeteroReport};
use crate::sim_adv::inflow::{InflowPolicy, POP_BAND, PopSeries, expected_outflow, pool_size};
use crate::sim_adv::metrics::MetricSet;
use crate::sim_adv::predators::AdvMetrics;
use crate::sim_adv::restore::RestoreTruth;
use crate::sim_adv::scenario::{
    AdvDials, AdvId, AdvSpec, Event, InfoModel, MetricId, NodeSel, Scenario, ScenarioId,
    WorldParams,
};
use crate::sim_adv::tier::{TierMix, TierReport};
use crate::sim_adv::uptime::UptimeMix;
use crate::sim_adv::verdict::{Direction, Invariant, InvariantSpec};
use crate::sim_dynamic::engine::DynParams;
use crate::sim_dynamic::generator::{Archetype, GiverTier};

/// Restore window `W` in days (spec §10 п.9): 14 days = 2 weekly ticks.
const RESTORE_WINDOW_DAYS: f64 = 14.0;
/// Model-S restore download budget in GB/day (OPEN calibration guess; see [`WorldParams`]).
const RESTORE_BW_GB_DAY: f64 = 50.0;

/// The `dr_battle` co-loss size K_floor (`4r_dr_battle_spec.md` §3), FROZEN in code BEFORE the
/// run (anti-Goodhart; calibrating the SCENARIO K is sanctioned, the threshold X is not).
/// Calibrated from the runtime holder count of the T1/Reliable victim at the disaster tick
/// (measured, seeds 42..46 — see `dr_battle_calibration_*`): the victim's MATURE blocks carry
/// 5-7 distinct holders (typical 6; union across its 3 blocks = 11-16). Applying the spec's
/// "holders − k_eff − margin, leave k_eff + 1" to the typical 6-holder block gives
/// K_FLOOR = 6 − 2 − 1 = 3. The co-loss draws its 3 holders from the 11-16-holder UNION, so the
/// deterministic seeded pick keeps EVERY floor-met block ≥ k_eff (measured restore-U = 1.0000,
/// σ = 0 at K = 3). HONEST NOTE (finding): one seed's victim has a MARGINAL 3-holder floor-met
/// block (a block that met floor earlier, then decayed) — so the strict worst-case "all K picks
/// hit the smallest block" bound would force K ≤ 1; the frozen K = 3 rests on the deterministic
/// union pick, not that worst case (the monotone sweep + collapse tests carry the honest
/// degradation past this floor).
const DR_BATTLE_K_FLOOR: usize = 3;

/// The `dr_battle` SURVIVAL-FLOOR threshold X (`4r_dr_battle_spec.md` §3 INV-DR-BATTLE-FLOOR),
/// FROZEN in code BEFORE the run (anti-Goodhart). At K_FLOOR the victim's blocks keep ≥ k_eff
/// survivors, so restore-truth U must clear a real DR-collapse floor: the same round 0.60
/// semantic bar as INV-RESTORE-SANITY / INV-RESTORE-HETERO-L ("FAIL if > 40 % of the victim's
/// blocks become unrestorable"), which the calibrated case clears decisively (measured mean =
/// 1.0000, σ = 0 ⇒ power = ∞). Calibrate the SCENARIO (K_FLOOR), never this bar.
const DR_BATTLE_FLOOR_X: f64 = 0.60;

// ============================================================
// A15 incumbent-enclosure (`4r_a15_spec.md`) — constants FROZEN in code BEFORE the run
// (anti-Goodhart). The calibration test `a15_enclosure_calibration_*` prints the runtime numbers
// (n0, present-at-t0, pool, newcomers past cutoff, typical newcomer vs incumbent g_ho) that
// justify each; see the frozen-constants section of the A15 report.
// ============================================================

/// The bootstrap INCUMBENT setpoint n0 for `a15_enclosure`. The world is a fully-established
/// incumbent network at t=0 (`n0_frac = 1.0`, so all n0 join at tick 0) into which the inflow pool
/// streams as newcomers — the regime the enclosure question lives in. 50 keeps the run modest
/// (n0 + pool ≈ 71 nodes over 160 ticks) while leaving room for a cartel-fraction sweep up to the
/// TOTAL incumbent cartel (frac = 1.0 = all n0 present-at-t0 incumbents enclose).
const A15_N0: usize = 50;

/// The enclosure horizon (weekly ticks). 160 ≈ 3 years — long enough that inflow newcomers (every
/// pool arrival is a newcomer, since `join_cutoff = 0`: the whole n0 incumbent cohort joins at t=0)
/// have many ticks to mature their blocks and, where possible, serve the cartel across several PoS
/// windows, yet short enough to run locally.
const A15_HORIZON: u64 = 160;

/// The reciprocity gate g_ho threshold: a cartel HOLDER rejects an owner whose service to it
/// `capital[owner][holder].g_ho < A15_ENCLOSE_THRESH`. FROZEN from the measured g_ho scale (seeds
/// 42..46): only ~6-14 % of owner→cartel pairs carry ANY g_ho (most owners never placed on a given
/// cartel member), and among those the served incumbents sit at mean g_ho ≈ 60-110. Set to 40 —
/// well above a fresh newcomer's ≈ 0 g_ho — so the door is genuinely shut (~95 % of offers rejected)
/// and the enclosure gets its strongest lockout shot: a newcomer must SERVE the cartel to clear it
/// (soft enclosure). Calibrate the SCENARIO, never this bar.
const A15_ENCLOSE_THRESH: f64 = 40.0;

/// The FLOOR-board cartel size (group_size = C_floor). 10 of the n0 = 50 incumbents (frac 0.2): the
/// non-cartel present capacity (≈ 40 incumbents + ~17 newcomers, all ≫ n_symbols = 5) still lets a
/// newcomer the cartel refuses place and hold its floor on the honest remainder — the
/// INV-ENCLOSURE-FLOOR sanity. FROZEN from the runtime present-count; see the report.
const A15_C_FLOOR: usize = 10;

/// The INV-ENCLOSURE-FLOOR newcomer-durability floor X. FROZEN as a round COLLAPSE bar (0.20) BELOW
/// the measured baseline (mean newcomer durability ≈ 0.53-0.55 at C_floor, seeds 42..46) — "FAIL if
/// the newcomer durability collapses below 0.20", NOT tuned. The metric carries large seed-
/// REALIZATION variance (σ ≈ 0.40 ⇒ power ≈ 0.8 < 2), so the row lands INCONCLUSIVE — the same
/// honest outcome as A5's INV-A5-DEEP-FLOOR (WARN-7: seed variance dominates, growing the world does
/// not fix it), reported with the flat sweep, not tuned away.
const A15_FLOOR_X: f64 = 0.20;

// ============================================================
// A7 sybil-farm (`4r_a7_spec.md`) — constants FROZEN in code BEFORE the run (anti-Goodhart). The
// calibration test `a7_sybil_calibration_*` prints the runtime table (collude ON/OFF × V_free {0, 2})
// of BOTH the earned-honest-reciprocity credit key (≈ 0 ⇒ credit-limit holds) and the
// giver_priority_order honest-storage proxy artifact; see the A7 report + review.
// ============================================================

/// The sybil-farm size N (group_size). 8 fake identities in an n = 120 world (~7 %): a big enough
/// farm to build MASSIVE collusive intra-farm reputation (every ordered pair fakes a PoS pass every
/// tick) yet a realistic minority — the test is whether that collusive reputation converts to honest
/// storage (it must not).
const A7_FARM_N: usize = 8;

/// The farm's shared subnet id (its farm identifier — `adv_collude_farm` colludes only within a
/// matching `group_subnet`). Arbitrary; used only to group the sybils.
const A7_GROUP_SUBNET: u32 = 7;

/// The farm node count's world size + horizon (matching the a6 hetero-free honest world scale).
const A7_N_NODES: usize = 120;
const A7_HORIZON: u64 = 130;

/// The farm's demand multiplier (`whale_block_mult`): ×12 own-data (like the a1 whale) so the farm
/// has plenty of data to PUSH onto honest holders — the surface the collusion is tested against.
const A7_BLOCK_MULT: f64 = 12.0;

/// INV-SYBIL-CREDIT-LIMIT-HOLDS threshold ε (gb·days): the farm's EARNED HONEST RECIPROCITY — the
/// pairwise κ_O credit key `Σ_{s∈farm, h∉farm} capital[s][h].g_ho` that gates the farm's data on
/// honest holders — must stay below this under collude-ON. FROZEN at 1.0 (effectively 0): the
/// ε-serving farm never holds honest data, so it never accrues an honest credit key (measured
/// exactly 0.0000 across seeds 42..46); 1.0 is ≪ a single real symbol-window of honest service
/// (`v_per_symbol·Δt ≈ 175`). This row PASSES decisively (power = ∞ at mean 0, σ 0) — the proof that
/// pairwise "reputation = credit-limit" RESISTS collusion (the farm's ~10k of collusive intra-farm
/// g_ho buys ZERO honest credit). The ~58× honest-STORAGE inflation is a separate
/// `giver_priority_order` owner-ordering PROXY artifact (sim-fidelity, no real-protocol analogue),
/// measured in the calibration table but NOT a board row.
const A7_CREDIT_LIMIT_EPS: f64 = 1.0;

// ============================================================
// A10 provider-exit (`4r_a10_spec.md`) — constants FROZEN in code BEFORE the run (anti-Goodhart).
// The calibration test `a10_provider_exit_calibration_*` prints the runtime numbers (present holders
// at the exit tick, top-holder alive-holding load, survivor capacity vs the n_symbols = 5 floor, the
// post-exit repair-storm peak, and the durability(provider_frac) sweep) that justify each; see the
// frozen-constants section of the A10 report.
// ============================================================

/// The provider-exit tick T (fixed mature trigger, as `dr_battle` @ 60): the top holders are well
/// loaded by tick 60 (past the incremental-join fill), and the 130-tick horizon leaves a long
/// (70-tick) post-exit recovery window. Documented (not `after_share`): the top-load set is already
/// established by T60, so a fixed tick is simpler and equivalent.
const A10_EXIT_TICK: u64 = 60;

/// The recovery horizon (weekly ticks). 130 = the `honest_v2` horizon: 70 post-exit ticks — far more
/// than the repair-detection delay (default 3) needs — so the survivors have ample time to re-take
/// the orphaned floor. With the event cleared this is exactly `honest_v2` (the anchor).
const A10_HORIZON: u64 = 130;

/// The board provider fraction: the top `A10_PROVIDER_FRAC` most-loaded holders mass-exit. FROZEN at
/// 0.15 — MEASURED (seed 42): ~14 of the ~90 present holders leave, so the ~76 survivors ≫ the
/// n_symbols = 5 floor and can re-take every orphaned symbol; post-exit floor-fill then stays at the
/// steady-state baseline. HONEST SCOPE NOTE (review W3): honest_v2's per-holder load is NEAR-FLAT —
/// the top holders sit tied at the ~5-symbol cap (tie broken by index), only ~2× the mean — so this
/// selects "the largest correlated holder set", NOT a dramatically over-concentrated provider; the
/// exit is still a genuine shock (~35 % of alive symbols orphaned, silent losses queued). Calibrate
/// the SCENARIO (frac), never the threshold X. (Runtime justification — survivor count vs floor,
/// top-holder load — is printed by the calibration dump; see the report.)
const A10_PROVIDER_FRAC: f64 = 0.15;

/// The INV-PROVIDER-EXIT-FLOOR collapse bar X. FROZEN at 0.20 — a NO-COLLAPSE bar, deliberately BELOW
/// the whole measured sweep (review W1: it proves "a provider exit never collapses floor-fill below
/// 0.20", NOT "the exit was absorbed" — the absorb-vs-degrade discrimination lives in the `tests.rs`
/// sweep, the A15 `INV-ENCLOSURE-FLOOR` idiom). NOTE the SCALE (measured): under the eviction economy
/// floor-met blocks settle near k_eff (≈ 1.7 non-cream holders of the 5-symbol floor), so the
/// steady-state floor-fill baseline is ≈ 0.34 — NOT ≈ 1 (this is FILL of the placed floor, not
/// decodability — see `metrics::overall_floor_durability`'s proxy note). X = 0.20 is ~40 % below that
/// baseline. At `A10_PROVIDER_FRAC` post-exit floor-fill ≈ 0.338 (unmoved from the 0.341 control),
/// clearing X with power ≈ 2.9 (PASS). The degradation at LARGER fractions (down to ≈ 0.24 at frac
/// 0.70 — depressed but not a collapse) is the sweep's finding, NOT this board row. Calibrate the
/// SCENARIO, never this bar; a FAIL at the frozen fraction would be the fragility / repair-latency
/// FINDING.
const A10_FLOOR_X: f64 = 0.20;

/// Every registered scenario (hard-coded like `Archetype::ALL`).
pub fn all_scenarios() -> Vec<Scenario> {
    vec![
        honest_v2(),
        dr_baseline(),
        dr_battle(),
        a1_whale(),
        a4_whitewasher(),
        a2_dropper(),
        honest_hetero_v2(),
        honest_hetero_hard(),
        dr_hetero(),
        tiered_v1(),
        tiered_v1_inflow(),
        tiered_hetero(),
        tiered_hetero_hard(),
        a3_flapper(),
        a5_deep_silent(),
        a6_discriminator(),
        a15_enclosure(),
        a7_sybil(),
        a10_provider_exit(),
    ]
}

/// The phase-2a P7 tier-share population guess (`4r_p2a_spec.md` §1): T1 15% / T2 25% / T3 40% /
/// T4 20% — laptops the plurality, NAS the minority (a realistic population of would-be givers,
/// distinct from `build_world`'s NAS-heavy 35/30/25/10 backbone). Shared by the tiered scenarios.
fn tiered_mix() -> TierMix {
    TierMix::Custom(vec![
        (GiverTier::T1, 0.15),
        (GiverTier::T2, 0.25),
        (GiverTier::T3, 0.40),
        (GiverTier::T4, 0.20),
    ])
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
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
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
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
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

/// The DR-in-battle scenario (2b-step-2, `4r_dr_battle_spec.md`): `dr_baseline` but the
/// Disaster on the T1/Reliable backbone is CORRELATED — [`DR_BATTLE_K_FLOOR`] of the victim's
/// current holders fall in the SAME tick (a region / provider outage that took the NAS *and*
/// its offsite cluster of copies, A16). K_FLOOR is FROZEN so the victim's blocks keep ≥ k_eff
/// survivors across the frozen seeds 42-46 (MEASURED + monotonicity-backed from the co_loss=4
/// margin — NOT structural for an arbitrary seed; see [`DR_BATTLE_K_FLOOR`]), so restore-truth U
/// must still clear the [`DR_BATTLE_FLOOR_X`] floor (INV-DR-BATTLE-FLOOR). The HONEST-REFLECT
/// monotonicity (U falls as more holders are co-lost, → 0 below k_eff) is a `tests.rs` sweep, not
/// a board row.
pub fn dr_battle() -> Scenario {
    Scenario {
        id: ScenarioId("dr_battle"),
        about: "dr_baseline but the T1/Reliable Disaster is CORRELATED — K_floor holders co-lost in the same tick — restore-truth over the survival floor (A16)",
        world: WorldParams {
            n_nodes: 100,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: DemandMix::Uniform,
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: Vec::new(),
        // Same strike as dr_baseline (T1/Reliable backbone @ tick 60), but K_FLOOR of the
        // victim's holders are co-lost in the same tick.
        events: vec![(
            60,
            Event::CorrelatedDisaster {
                sel: NodeSel::FirstTierArchetype(GiverTier::T1, Archetype::Reliable),
                co_loss_holders: DR_BATTLE_K_FLOOR,
            },
        )],
        horizon: 130,
        // FROZEN band: the ≥k_eff survival margin at K_FLOOR is MEASURED for exactly these seeds
        // (see DR_BATTLE_K_FLOOR's marginal-block note). Do NOT widen without re-checking FLOOR
        // per-seed — `dr_battle_floor_holds_per_seed_across_the_frozen_band` fails a bad seed.
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![MetricId::RestoreTruth, MetricId::InvariantBoard],
        verdicts: dr_battle_invariants(),
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
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
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
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
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
/// ten voluntary droppers, each shedding `drop_rate = 4%` of its foreign holdings every tick.
///
/// **The matched control is NOT the honest node** (unlike A1/A4) — it is the POLITE dropper
/// (`twin_hook_for(A2)` = `a2_polite_dropper_hook`): the predator (SILENT) and its twin (POLITE)
/// drop the SAME victims at the SAME rate by the SAME deterministic selection — EQUAL harm — and
/// differ ONLY in whether each drop is announced. So the comparison isolates the PRICE OF
/// SILENCE: the silent drop burns the reliability quantity `G(dropper→victim)` at `b_max` (a
/// total-loss burn ⇒ ≈ 0) and jumps σ; the announced drop rides the F2 notice (dies at T+1) and
/// burns only `b_ann`.
///
/// **Seat-sync fix (2026-07-19).** The burn now hits BOTH mirror copies of `G(dropper→victim)` —
/// the owner's forecast `g_oh` AND the transpose `g_ho` that `kappa_key` reads for the V_ret cap /
/// eviction / preemption (an accrual keeps the two in sync, the burn used not to). So silence now
/// bites the ENFORCEMENT standing, not just an inert forecast: the silent dropper's κ_O is halved,
/// its V_ret shrinks, its parked data is squeezed harder than the polite twin's. The fix makes the
/// two arms diverge CHAOTICALLY, so the board reads TIME-INTEGRAL ratios (a horizon snapshot is
/// noisy). `n = 100`, 10 droppers (10%), horizon 160, **10 seeds** (the "full" band — the diverged
/// arms need it to clear the power gate).
///
/// **δ frozen BEFORE the run at 0.15 (anti-Goodhart, spec §3):** INV-A2-SILENT-PUNISHED and
/// INV-A2-RETENTION assert `silent/polite < 1 − δ = 0.85`; INV-A2-INFLOW at 1.0. Calibrating the
/// SCENARIO (drop_rate, n, seeds) is allowed; the thresholds are not.
pub fn a2_dropper() -> Scenario {
    Scenario {
        id: ScenarioId("a2_dropper"),
        about: "honest world + 10 voluntary droppers (silent predator vs polite twin, EQUAL 4%/tick drop) — the price of silence (enforced g_oh≡g_ho + park)",
        world: WorldParams {
            n_nodes: 100,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: DemandMix::Uniform,
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: vec![AdvSpec {
            id: AdvId::A2DropRefuser,
            count: 10,
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
        // 10 seeds (the "full" band, spec §5): the seat-sync fix makes the enforced-retention
        // arms diverge chaotically, so the paired ratios need 10 seeds to clear the power gate.
        seeds: vec![42, 43, 44, 45, 46, 47, 48, 49, 50, 51],
        metrics: vec![
            MetricId::AttackRoi,
            MetricId::Extraction,
            MetricId::InvariantBoard,
        ],
        verdicts: a2_dropper_invariants(),
        fast: false,
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
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
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
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
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
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
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

/// The phase-2a HONEST TIERED world (`4r_p2a_spec.md` §3): the v2 world with the P7 tier population
/// (15/25/40/20) + a STRUCTURAL uptime profile per tier (T1 24/7, T2/T3 diurnal, T4 ragged) over a
/// LONG 520-tick (10-year) horizon. Measures the per-tier report — "who gets what in the network of
/// givers" (floor-completeness / durability / share A>0 / give↔get served / parked). No adversaries,
/// no disasters (DR is 2b, blocked). n = 180: enough per-tier owners (T1 ≈ 27 … T3 ≈ 72) for the
/// give↔get rank to clear the multi-seed power gate.
///
/// EXPECTED honest finding (report, do not tune): the network DEPOPULATES over 520 ticks (churn has
/// no rejoin — cooperative survival (1−0.002)^520 ≈ 0.35), so the steady-state columns thin toward
/// the horizon; floor-completeness is measured over the tier's LIFETIME owners (monotone), which
/// stays robust. If floor-completeness SATURATES across tiers the P7 gradient lives in
/// durability/parked — a finding, not a threshold to move.
pub fn tiered_v1() -> Scenario {
    Scenario {
        id: ScenarioId("tiered_v1"),
        about: "P7 tiered honest world (15/25/40/20 tiers × 24-7/diurnal/ragged uptime) over 520 ticks — per-tier 'who gets what' (no DR, no predators)",
        world: WorldParams {
            n_nodes: 180,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: DemandMix::Uniform,
            uptime: UptimeMix::Tiered,
            tier_mix: tiered_mix(),
            inflow: InflowPolicy::None,
        },
        population: honest_v2().population,
        tiers: vec![
            (GiverTier::T1, 0.15),
            (GiverTier::T2, 0.25),
            (GiverTier::T3, 0.40),
            (GiverTier::T4, 0.20),
        ],
        adversaries: Vec::new(),
        events: Vec::new(),
        // 520 weekly ticks ≈ 10 years (spec §3: the long horizon the profiles need to bite).
        horizon: 520,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![
            MetricId::TierReport,
            MetricId::Extraction,
            MetricId::InvariantBoard,
        ],
        verdicts: tiered_invariants(),
        // Long horizon ⇒ NOT a fast-mode member (nightly / on-demand only).
        fast: false,
    }
}

/// The inflow bootstrap setpoint `n0` for [`tiered_v1_inflow`] (`4r_inflow_spec.md` §3): 180 — the
/// SAME cohort size as [`tiered_v1`], so the without-vs-with-inflow comparison holds n0 fixed and
/// isolates the arrival stream. The world's total node count is `n0 + pool` (the pool sized by λ_in).
const INFLOW_N0: usize = 180;

/// `tiered_v1` + a STEADY inflow stream (`4r_inflow_spec.md`): the P7 tiered honest world, but with a
/// pre-allocated pool of newcomers arriving at λ_in ≈ the expected churn outflow at n0, so the 520-tick
/// (10-year) horizon reaches a STATIONARY population instead of the closed cohort's die-off (180 → ~59).
///
/// The comparison is against [`tiered_v1`] (same n0 = 180, no inflow): its present-count COLLAPSES to
/// ~31 % over the horizon; here it should hold within ±25 % of the setpoint over the last half
/// (INV-POP-STATIONARY, threshold FROZEN before the run). λ_in is the expected per-tick outflow at n0
/// under the §3 mix ([`expected_outflow`]) — an OPEN calibration guess, NOT tuned; a residual drift is
/// an HONEST finding to report (spec §4). Total nodes = n0 + [`pool_size`]; the un-arrived pool tail is
/// inert buffer, excluded from every metric. The per-tier P7 table is now read on this STABLE world
/// (compare to the closed-cohort `tiered_v1` "2a" table). `n0 = 180`, 520 ticks, 5 seeds.
pub fn tiered_v1_inflow() -> Scenario {
    let horizon = 520;
    let lambda = expected_outflow(INFLOW_N0, DynParams::default().churn_out_prob);
    let n_nodes = INFLOW_N0 + pool_size(lambda, horizon);
    Scenario {
        id: ScenarioId("tiered_v1_inflow"),
        about: "tiered_v1 + steady newcomer inflow (λ_in ≈ churn outflow at n0=180) over 520 ticks — the population reaches STATIONARY instead of the closed-cohort die-off",
        world: WorldParams {
            n_nodes,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: DemandMix::Uniform,
            uptime: UptimeMix::Tiered,
            tier_mix: tiered_mix(),
            inflow: InflowPolicy::Steady {
                joins_per_tick: lambda,
            },
        },
        population: honest_v2().population,
        tiers: vec![
            (GiverTier::T1, 0.15),
            (GiverTier::T2, 0.25),
            (GiverTier::T3, 0.40),
            (GiverTier::T4, 0.20),
        ],
        adversaries: Vec::new(),
        events: Vec::new(),
        horizon,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![
            MetricId::TierReport,
            MetricId::Extraction,
            MetricId::InvariantBoard,
        ],
        verdicts: tiered_inflow_invariants(),
        // Long horizon + ~427 nodes (n0 180 + pool 247) ⇒ NOT a fast-mode member (nightly / on-demand only).
        fast: false,
    }
}

/// The phase-2a TIERED × HETERO world — LIGHT regime (`4r_p2a_spec.md` §3): `tiered_v1` PLUS the
/// hetero-v2 demand classes (S 60% / M 30% / L 10%), so the big footprint is a POPULATION member,
/// not a single measured lock. Same 180 nodes, 520 ticks, tier population + uptime profiles.
///
/// **[`DiskPolicy::Grow`] (LIGHT).** WARN-1 (review): under `Grow` a big archive keeps the tier's
/// own:free ratio, so its device cap GROWS with the source — and a T4 owner already keeps
/// `own_to_free_centre = 0.50` (≈ 67 % free). So the "full phone with a big footprint" (T4 × L)
/// does NOT actually sit FULL here — it has ample lendable disk. This is the light co-report; the
/// SHARP "full device" test is [`tiered_hetero_hard`] ([`DiskPolicy::Fixed`]), where the L source
/// on an unchanged device genuinely eats the disk.
pub fn tiered_hetero() -> Scenario {
    Scenario {
        id: ScenarioId("tiered_hetero"),
        about: "P7 tiered world × hetero demand classes (S/M/L footprints) over 520 ticks — the T4×L 'full phone with a big footprint' now in the population",
        world: WorldParams {
            n_nodes: 180,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: hetero_mix(DiskPolicy::Grow),
            uptime: UptimeMix::Tiered,
            tier_mix: tiered_mix(),
            inflow: InflowPolicy::None,
        },
        population: honest_v2().population,
        tiers: vec![
            (GiverTier::T1, 0.15),
            (GiverTier::T2, 0.25),
            (GiverTier::T3, 0.40),
            (GiverTier::T4, 0.20),
        ],
        adversaries: Vec::new(),
        events: Vec::new(),
        horizon: 520,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![
            MetricId::TierReport,
            MetricId::Extraction,
            MetricId::InvariantBoard,
        ],
        verdicts: tiered_invariants(),
        fast: false,
    }
}

/// The phase-2a TIERED × HETERO world — HARD regime (WARN-1 fix, the SHARP "full phone" test):
/// identical to [`tiered_hetero`] (same 15/25/40/20 tiers, S/M/L classes, uptime profiles, 180
/// nodes, 520 ticks, seeds, and the SAME frozen [`tiered_invariants`] board) EXCEPT the demand disk
/// policy is [`DiskPolicy::Fixed`] — the device cap stays at `build_world` size for every class. A
/// T4 × L owner (a phone with a big archive) then has its L source (× 10/3) eat its UNCHANGED disk,
/// truncated at the cap when it overflows: little lendable free ⇒ little κ_O ⇒ V_ret near V_free.
/// This is where the "забитый телефон" of `4r_p2a_spec.md` §1/§3 actually sits FULL in the
/// population. Any outcome is informative — a hard T4/L floor-completeness collapse is the real
/// credit-lock finding (report, do NOT tune).
pub fn tiered_hetero_hard() -> Scenario {
    Scenario {
        id: ScenarioId("tiered_hetero_hard"),
        about: "P7 tiered world × hetero classes on a FIXED ordinary device (T4×L 'full phone with a big footprint' actually FULL) over 520 ticks — the SHARP credit-lock test (WARN-1)",
        world: WorldParams {
            n_nodes: 180,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: hetero_mix(DiskPolicy::Fixed),
            uptime: UptimeMix::Tiered,
            tier_mix: tiered_mix(),
            inflow: InflowPolicy::None,
        },
        population: honest_v2().population,
        tiers: vec![
            (GiverTier::T1, 0.15),
            (GiverTier::T2, 0.25),
            (GiverTier::T3, 0.40),
            (GiverTier::T4, 0.20),
        ],
        adversaries: Vec::new(),
        events: Vec::new(),
        horizon: 520,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![
            MetricId::TierReport,
            MetricId::Extraction,
            MetricId::InvariantBoard,
        ],
        verdicts: tiered_invariants(),
        fast: false,
    }
}

/// A3 — флаппер (phase-2a-2, `4r_p2a2_spec.md` §A3): the honest world + 4 flappers, each a
/// BURSTY-uptime holder (a Seasonal 4-on/4-off cycle at ~0.95 on-week uptime ⇒ mean daily ≈ 0.475).
/// Its MATCHED TWIN (same node, `RunMode::Twin`) is a mean-matched HONEST diurnal — an iid Ragged at
/// the flapper's exact period mean — so the ONLY difference is the AUTOCORRELATION of absence.
///
/// **DIAGNOSTIC ONLY (spec §A3 / world-v3 §3 WARN-1): NO INV-A3-* board row.** The σ-consumer of the
/// PoS cadence (r_0(1+σ)) is phase-4 work — σ is INERT here (no decision reads it) — so the finding is
/// a REPORT of the σ-profile / surfaced-frac (PoS pass) / online-frac (real storage) gap between the
/// clustered flapper and the mean-matched spread twin, informing what the phase-4 σ-cadence must
/// catch. The board carries only the two STRUCTURAL rows. `n = 80`, horizon 130, 5 seeds.
pub fn a3_flapper() -> Scenario {
    Scenario {
        id: ScenarioId("a3_flapper"),
        about: "honest world + 4 bursty flappers (Seasonal 4-on/4-off) vs mean-matched iid twin — σ/pass-rate DIAGNOSTIC for the phase-4 σ-cadence (NO board row)",
        world: WorldParams {
            n_nodes: 80,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: DemandMix::Uniform,
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: vec![AdvSpec {
            id: AdvId::A3Flapper,
            count: 4,
            info_model: InfoModel::Own,
            // period_ticks = the flap period (weeks), duty = the ON-fraction. 8-week period × 0.5
            // duty ⇒ a 4-on/4-off cycle: long enough off-runs to MISS whole PoS windows (σ
            // accumulation), the discriminating structure vs the spread twin.
            dials: AdvDials {
                period_ticks: 8,
                duty: 0.5,
                ..AdvDials::default()
            },
        }],
        events: Vec::new(),
        horizon: 130,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![
            MetricId::AttackRoi,
            MetricId::Extraction,
            MetricId::InvariantBoard,
        ],
        verdicts: a3_flapper_invariants(),
        fast: false,
    }
}

/// A5 — молчащий глубокий (phase-2a-2, `4r_p2a2_spec.md` §A5): the honest world + 6 DEEP nodes
/// (Reliable, present from t0 — years of service accruing the A.4 loyalty depth) that go SILENT (a
/// PRESENCE pause, not a death) for `pause_len` ticks from tick 65, then return. The MATCHED TWIN is
/// the SAME deep nodes in a world with the depth floor OFF (`depth_w_d = 0`, via `twin_dial_override`)
/// — the first DIRECT dynamic test of Р-1/W10 ("the tail melts with D but survives").
///
/// Board INV-A5-DEEP-FLOOR (`AdvDifference`, threshold FROZEN before the run): the deep nodes' parked
/// data SURVIVES the pause BETTER with the depth floor than without — `survival(w_d=0.5) −
/// survival(w_d=0) > 0.10` (a difference, not a ratio: at v_free=0 the no-floor survival can hit 0 —
/// the strongest case — which a ratio cannot express).
///
/// **The board runs the M=2-month pause (`pause_len = 8` weeks) — WITHIN the depth memory** (A.4
/// `τ_slow ≈ 6 months`), where the W10/Р-1 floor demonstrably operates. Choosing the pause length is
/// SCENARIO calibration (allowed); the 0.10 bar stays frozen. The report-dump M-ladder {2, 4, 6}
/// months shows the floor's protection FADING as the pause approaches `τ_slow` (the depth itself
/// decays away over ~6 months) — the honest "хвост тает с D" physics, NOT a threshold to move.
///
/// **The frozen board lands INCONCLUSIVE (power 0.98 < 2), HONESTLY (WARN-7).** The mean survival lift
/// is robustly POSITIVE (+0.21 at M=2mo; the clean monotone M-ladder), but the per-seed lift is
/// SEED-REALIZATION-dependent (σ ≈ the effect) — the `a5_board_power_scan` diagnostic shows this
/// variance does NOT shrink with more deep nodes / seeds, and growing the world only WEAKENS the
/// effect (less eviction pressure). So no scenario scale clears power 2 without faking; the ladder +
/// sign are the real evidence, the board reports INCONCLUSIVE (NOT a tuned PASS). `n = 90`, horizon
/// 130 (warmup 65 + pause + recovery), 6 deep nodes (pooled survival), 5 seeds.
pub fn a5_deep_silent() -> Scenario {
    Scenario {
        id: ScenarioId("a5_deep_silent"),
        about: "honest world + 6 deep nodes pausing M=2mo from tick 65 — depth-floor survival A/B (w_d=0.5 vs 0): does the deep tail survive the silence? (Р-1/W10)",
        world: WorldParams {
            n_nodes: 90,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: DemandMix::Uniform,
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: vec![AdvSpec {
            id: AdvId::A5DeepSilent,
            count: 6,
            info_model: InfoModel::Own,
            // pause_start = 65 (past the join horizon, world at steady-state pressure and the deep
            // nodes' data concentrated on their reciprocal holders); pause_len = 8 weeks ≈ 2 months
            // (well within the A.4 τ_slow ≈ 6-month depth memory — the regime the floor protects).
            dials: AdvDials {
                pause_start: 65,
                pause_len: 8,
                ..AdvDials::default()
            },
        }],
        events: Vec::new(),
        horizon: 130,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![MetricId::AttackRoi, MetricId::InvariantBoard],
        verdicts: a5_deep_silent_invariants(),
        fast: false,
    }
}

/// A6 — дискриминатор (phase-2a-2, `4r_p2a2_spec.md` §A6): the HETERO world (S/M/L footprints) + 4
/// discriminator holders that SILENTLY drop the symbols of SMALL owners (footprint ≤ 1 block = the
/// S class) every tick while serving the large fully. Its MATCHED TWIN is the HONEST holder (same
/// Reliable construction, hooks off — retains everyone). At v_free=0 (Р-9) a small owner survives
/// ONLY on earned reciprocity, so the sharp question is: does the discriminator PAY for shedding the
/// small (consumed ≤ honest twin) or is discrimination UNPUNISHED (a number to report, not tune)?
///
/// Board INV-A6-DISCR-ROI (`AdvComparative` on protected-storage, threshold FROZEN 1.0): consumed
/// (discr) / consumed(twin) < 1 ⇒ the discriminator protects no more own data than an honest holder
/// of the same capacity (discrimination does not pay). A FAIL / INCONCLUSIVE here IS the finding
/// ("discrimination is legal in this economy"), reported with the small-owner retention gap — NOT
/// tuned away. `n = 120` (~72 S / 36 M / 12 L), horizon 130, 5 seeds.
pub fn a6_discriminator() -> Scenario {
    Scenario {
        id: ScenarioId("a6_discriminator"),
        about: "hetero world + 4 discriminators (silently drop SMALL owners, serve large) vs honest twin — cost-or-impunity of discrimination at v_free=0",
        world: WorldParams {
            n_nodes: 120,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: hetero_mix(DiskPolicy::Grow),
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: vec![AdvSpec {
            id: AdvId::A6Discriminator,
            count: 4,
            info_model: InfoModel::Own,
            // discr_max_blocks = 1: an owner with ≤ 1 own block (the S class) is "small" and dropped.
            dials: AdvDials {
                discr_max_blocks: 1,
                ..AdvDials::default()
            },
        }],
        events: Vec::new(),
        horizon: 130,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![
            MetricId::AttackRoi,
            MetricId::Extraction,
            MetricId::InvariantBoard,
        ],
        verdicts: a6_discriminator_invariants(),
        fast: false,
    }
}

/// A15 — incumbent-enclosure (phase 3, `4r_a15_spec.md`): a fully-established incumbent network
/// (`n0_frac = 1.0`, n0 = 50 present at t=0) plus a STEADY inflow stream of newcomers, with a
/// CARTEL of `C_floor` EARLIEST-joined incumbents that reciprocity-refuses newcomers (as a holder
/// it hard-rejects any owner whose `g_ho < enclose_thresh`). The question: can the cartel LOCK OUT
/// the newcomer stream?
///
/// The mechanism is SOFT enclosure — the cartel places its OWN data honestly (no placement lever).
/// The headline is the newcomer floor-durability (the fraction of newcomers' floor-met blocks that
/// stay ≥ floor). Board: INV-ENCLOSURE-FLOOR (at C_floor, where the non-cartel capacity still covers
/// n_symbols = 5, the newcomer durability clears the frozen X) + the two structural rows. The
/// cartel-FRACTION SWEEP (durability vs cartel_frac) is a `tests.rs` sweep, NOT a board row (A15 is
/// a world-cut, not a twin). MEASURED FINDING (`newcomer_durability_monotone…`): in the ample-
/// capacity regime (cartel ≤ 0.8·n0) the abundant non-cartel remainder keeps durability flat; at the
/// TOTAL incumbent cartel (frac = 1.0) durability degrades (~0.55 → ~0.315) — enclosure bites — but
/// never achieves LOCKOUT (> the collapse floor), because the inflow cohort forms its own reciprocal
/// sub-community. `n0 = 50`, 160 ticks (weekly), 5 seeds.
pub fn a15_enclosure() -> Scenario {
    let horizon = A15_HORIZON;
    // A fully-established incumbent network at t=0: `n0_frac = 1.0` makes all n0 bootstrap nodes
    // present at tick 0 (so the cartel can be picked from the whole n0 incumbent set), and the
    // inflow pool is still forced `present = false` and streamed in over `[1, horizon)`.
    let base = DynParams {
        n0_frac: 1.0,
        ..DynParams::default()
    };
    let lambda = expected_outflow(A15_N0, base.churn_out_prob);
    let n_nodes = A15_N0 + pool_size(lambda, horizon);
    Scenario {
        id: ScenarioId("a15_enclosure"),
        about: "established incumbent network (n0=50) + steady newcomer inflow + a cartel of C_floor earliest-joined incumbents reciprocity-refusing newcomers — can the cartel lock newcomers out? (soft enclosure; bites at total cartel but no lockout — inflow sub-community)",
        world: WorldParams {
            n_nodes,
            base,
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: DemandMix::Uniform,
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::Steady {
                joins_per_tick: lambda,
            },
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: vec![AdvSpec {
            id: AdvId::A15IncumbentEnclosure,
            // `count` mirrors the cartel size for the report; the injection sizes the cartel by
            // `dials.group_size` (spec §2). The sweep keeps the two in sync.
            count: A15_C_FLOOR,
            info_model: InfoModel::Own,
            dials: AdvDials {
                group_size: A15_C_FLOOR,
                enclose_thresh: A15_ENCLOSE_THRESH,
                ..AdvDials::default()
            },
        }],
        events: Vec::new(),
        horizon,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![MetricId::InvariantBoard],
        verdicts: a15_enclosure_invariants(),
        fast: false,
    }
}

/// The `a15_enclosure` board (`4r_a15_spec.md` §4): the two structural rows + INV-ENCLOSURE-FLOOR.
fn a15_enclosure_invariants() -> Vec<Invariant> {
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
        // INV-ENCLOSURE-FLOOR: at the calibrated cartel fraction C_floor — where the NON-cartel
        // present capacity still far exceeds n_symbols = 5 — a newcomer the cartel refuses can
        // still reach and hold floor on the honest remainder, so the newcomer floor-durability
        // clears a frozen floor X. GreaterThan, power-gated (spec §10 п.16): power < 2 ⇒
        // INCONCLUSIVE, itself a finding ("enclosure's newcomer effect is below the seed noise").
        // A FAIL (durability < X even at a modest cartel) is the enclosure-bites finding — reported
        // with the sweep curve, NOT tuned away.
        Invariant {
            id: "INV-ENCLOSURE-FLOOR",
            spec: InvariantSpec::EnclosureFloor {
                dir: Direction::GreaterThan,
            },
            threshold: A15_FLOOR_X,
        },
    ]
}

/// A7 — sybil-farm (phase 3, `4r_a7_spec.md`): the honest world plus a FARM of `A7_FARM_N` fake
/// identities (same `group_subnet`) that COLLUSIVELY inflate mutual reputation (fake PoS every tick,
/// no real holdings) while ε-serving the honest network (they store ~nothing real). The question:
/// does that collusive intra-farm reputation convert into REAL storage credit for the farm's data on
/// the HONEST network — does sybil multiplication beat "reputation = credit-limit"?
///
/// FINDING (A7 adversarial review): the pairwise κ_O credit-limit RESISTS collusion, exactly as the
/// spec predicted. The farm's data on an honest holder is gated by `capital[sybil][honest].g_ho` (the
/// eviction/preemption + admit-guard key), which the ε-serving farm never earns and the collusion
/// never touches — it stays ≈ 0.0000 under collude-ON. The board row INV-SYBIL-CREDIT-LIMIT-HOLDS
/// asserts this and PASSES decisively: sybil multiplication does NOT convert collusive reputation into
/// honest storage CREDIT.
///
/// A separate observation: the raw honest-STORAGE measurement inflates ~58× under collusion (~360k vs
/// ~6k gb·time), but this is a SIM-FIDELITY ARTIFACT, not a credit-limit break. `place_own_data`'s
/// `giver_priority_order` (default on) sorts owners each tick by the GLOBAL row-sum
/// `Σ_h capital[o][h].g_ho`; collusion inflates that free-of-charge, so sybils sort to the FRONT of
/// the per-tick placement order and win scarce free-accept holder slots under contention. That
/// global scheduler ranking-all-owners-by-total-service has NO real-protocol analogue (the daemon's
/// priority is holder-side pairwise) and the code flags it as a proxy "NOT the spec's ideal". Ilya's
/// call: DOCUMENT the proxy (keep `giver_priority_order`), do not treat the artifact as a
/// vulnerability. It is measured in the calibration table + the two proxy tests, but is NOT gated.
/// `n = 120`, farm N = 8 (×12 demand), horizon 130, 5 seeds, V_free = 0 (Р-9).
pub fn a7_sybil() -> Scenario {
    Scenario {
        id: ScenarioId("a7_sybil"),
        about: "honest world + a farm of 8 colluding sybils (fake mutual PoS, no real storage, ε-serve) — the pairwise κ_O credit-limit RESISTS: earned honest reciprocity stays ≈ 0 (INV-SYBIL-CREDIT-LIMIT-HOLDS passes). The ~58× honest-storage inflation is a giver_priority_order sim-proxy artifact, documented not gated",
        world: WorldParams {
            n_nodes: A7_N_NODES,
            // V_free = 0 (Р-9 default): the board tests the credit-limit at the canonical floor.
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: DemandMix::Uniform,
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: vec![AdvSpec {
            id: AdvId::A7SybilFarm,
            count: A7_FARM_N,
            info_model: InfoModel::Own,
            dials: AdvDials {
                group_size: A7_FARM_N,
                group_subnet: A7_GROUP_SUBNET,
                whale_block_mult: A7_BLOCK_MULT,
                // whale_accept = 0.0 (the AdvDials default): the farm ε-serves ⇒ stores nothing real
                // ⇒ earns no honest reciprocity ⇒ its only honest surface is V_free (the isolation
                // the finding rests on). `collude = true`: the farm colludes (the ON arm; the tests'
                // OFF control clones this with collude = false, same ε-serving construction).
                collude: true,
                ..AdvDials::default()
            },
        }],
        events: Vec::new(),
        horizon: A7_HORIZON,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![MetricId::Extraction, MetricId::InvariantBoard],
        verdicts: a7_sybil_invariants(),
        fast: false,
    }
}

/// The `a7_sybil` board (`4r_a7_spec.md` §4): the two structural rows + INV-SYBIL-CREDIT-LIMIT-HOLDS.
fn a7_sybil_invariants() -> Vec<Invariant> {
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
        // INV-SYBIL-CREDIT-LIMIT-HOLDS: the REAL defence — under collude-ON at V_free = 0 the farm's
        // EARNED HONEST RECIPROCITY (the pairwise κ_O credit key `Σ capital[sybil][honest].g_ho` the
        // eviction/preemption rank + admit-guard read) stays below a tiny ε (LessThan). It PASSES
        // decisively (the key is ≈ 0.0000 — collusion writes only intra-farm cells, so ~10k of
        // collusive g_ho buys ZERO honest credit): pairwise "reputation = credit-limit" resists sybil
        // multiplication. (The ~58× honest-STORAGE inflation is a separate `giver_priority_order`
        // owner-ordering PROXY artifact — sim-fidelity, no real-protocol analogue — measured in the
        // calibration table, NOT gated. See the a7_sybil doc.)
        Invariant {
            id: "INV-SYBIL-CREDIT-LIMIT-HOLDS",
            spec: InvariantSpec::SybilCreditLimit {
                dir: Direction::LessThan,
            },
            threshold: A7_CREDIT_LIMIT_EPS,
        },
    ]
}

/// A10 — provider-exit (phase 3, `4r_a10_spec.md`): the honest world, then a large "PROVIDER" — the
/// top `A10_PROVIDER_FRAC` most-loaded holders (honest_v2's loads are near-flat, so this is the
/// largest correlated holder set, not a dramatic concentration — see the `A10_PROVIDER_FRAC` scope
/// note) — mass-EXITS in ONE tick at `A10_EXIT_TICK`. Each provider node departs with the SAME churn
/// / A16 per-node physics (`depart_node`): a silent loss to every present owner it carried + its held
/// symbols killed. It is a PERMANENT exit (NOT restore-tracked, NOT revived — the owners repair the
/// orphaned floor themselves onto the survivors). The question: does the survivors' re-placement
/// keep the placed floor filled, or does the exit leave floor-fill depressed?
///
/// Headline: the post-exit floor-FILL at the horizon (`metrics::overall_floor_durability` — the mean
/// over present owners of their floor-met blocks' non-cream fill fraction; a conservative PROXY, NOT
/// decodability — see its doc; a restore-truth cross-check is deferred with the sim-unification
/// decision). Board: INV-PROVIDER-EXIT-FLOOR (a NO-COLLAPSE bar at `A10_PROVIDER_FRAC` — X sits
/// below the whole sweep by design, review W1) + the two structural rows. The provider-FRACTION sweep
/// (floor-fill vs provider_frac: HONEST-REFLECT monotone-degrade + the large-frac depressed point) is
/// a `tests.rs` sweep, NOT a board row (A10 is a world-cut, no twin).
///
/// MEASURED FINDING (seeds 42..46): the floor-fill(provider_frac) curve is monotone non-increasing —
/// 0.341 (control) → 0.338 (frac 0.15) → 0.287 (0.30) → 0.287 (0.50) → 0.240 (0.70). At a MODEST exit
/// (frac 0.15) the ~76 survivors re-take the orphaned floor, so fill is UNMOVED from the control; at
/// a LARGE exit (frac 0.70) the shrunken survivor set leaves fill depressed ~30 % below baseline —
/// but never a collapse (≈ 0.24 > X), the same "bites but no total collapse" shape as A15. Whether
/// the thinned floor costs actual RESTORABILITY is NOT measured here (the B1 proxy caveat). `n = 100`,
/// exit @ tick 60, horizon 130, 5 seeds.
pub fn a10_provider_exit() -> Scenario {
    Scenario {
        id: ScenarioId("a10_provider_exit"),
        about: "honest world + a PROVIDER (top-load holder set) mass-exits @ tick 60 — do survivors keep the placed floor filled? floor-fill PROXY (restorability not measured); no-collapse board bar (A10 provider-exit)",
        world: WorldParams {
            n_nodes: 100,
            base: DynParams::default(),
            restore_window_days: RESTORE_WINDOW_DAYS,
            restore_bw_gb_day: RESTORE_BW_GB_DAY,
            demand: DemandMix::Uniform,
            uptime: UptimeMix::Legacy,
            tier_mix: TierMix::Backbone,
            inflow: InflowPolicy::None,
        },
        population: honest_v2().population,
        tiers: honest_v2().tiers,
        adversaries: Vec::new(),
        // The top A10_PROVIDER_FRAC most-loaded holders exit as a correlated set at the mature tick.
        events: vec![(
            A10_EXIT_TICK,
            Event::ProviderExit {
                sel: NodeSel::TopHolders(A10_PROVIDER_FRAC),
            },
        )],
        horizon: A10_HORIZON,
        seeds: vec![42, 43, 44, 45, 46],
        metrics: vec![MetricId::InvariantBoard],
        verdicts: a10_provider_exit_invariants(),
        fast: false,
    }
}

/// The `a10_provider_exit` board (`4r_a10_spec.md` §3): the two structural rows + the
/// INV-PROVIDER-EXIT-FLOOR no-collapse bar.
fn a10_provider_exit_invariants() -> Vec<Invariant> {
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
        // INV-PROVIDER-EXIT-FLOOR: a NO-COLLAPSE bar (review W1 — X sits below the whole measured
        // sweep, so this row proves "the exit never collapses floor-fill below X", NOT "absorbed";
        // the absorb-vs-degrade discrimination is the tests.rs sweep, per the A15 FLOOR idiom). At
        // the frozen A10_PROVIDER_FRAC the surviving capacity ≫ n_symbols = 5 and post-exit
        // floor-fill clears X. GreaterThan, power-gated (spec §10 п.16): power < 2 ⇒ INCONCLUSIVE,
        // itself a finding. A FAIL (floor-fill collapses even at this modest fraction) is the
        // fragility / repair-latency finding — reported with the sweep curve, NOT tuned away.
        Invariant {
            id: "INV-PROVIDER-EXIT-FLOOR",
            spec: InvariantSpec::ProviderExitFloor {
                dir: Direction::GreaterThan,
            },
            threshold: A10_FLOOR_X,
        },
    ]
}

/// Reliable's extraction ROI (Reliable is index 0 in `Archetype::ALL`).
fn reliable_roi(m: &MetricSet) -> f64 {
    m.extraction_roi[0]
}

/// INV-TIER-GIVERS scalar: the smallest adjacent floor-completeness step over the tier rank.
fn tier_giver_gap(t: &TierReport) -> f64 {
    t.min_adjacent_giver_gap()
}

/// INV-TIER-T1-ALIVE scalar: the T1-NAS floor-completeness (the "backbone does not starve" sanity).
fn tier_t1_floor(t: &TierReport) -> f64 {
    t.t1_floor_completeness()
}

/// INV-POP-STATIONARY scalar (`4r_inflow_spec.md` §3): the last-half present-count max deviation from
/// the setpoint. `< POP_BAND` ⇒ the population held stationary; a drift/collapse pushes it above.
fn pop_max_dev(p: &PopSeries) -> f64 {
    p.stationary_max_dev()
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

/// A5: the deep node's parked-symbol SURVIVAL across the pause (the W10/Р-1 depth-floor scalar).
fn adv_park_survival(a: &AdvMetrics) -> f64 {
    a.park_survival
}

/// A2: the price-of-silence ledger, TIME-INTEGRATED (`Σ_t Σ_O g_oh`). Post the seat-sync fix
/// (2026-07-19) `g_oh ≡ g_ho^T`, so this IS the enforcement key κ_O (= the V_ret / eviction /
/// preemption input) — the integral smooths the now-chaotic per-arm divergence.
fn adv_retention_g_integral(a: &AdvMetrics) -> f64 {
    a.retention_g_integral
}

/// A2: the adversary's PARKED own-volume, TIME-INTEGRATED (`Σ_t parked_live`) — the realized
/// downstream retention squeeze the burned enforcement key produces.
fn adv_parked_integral(a: &AdvMetrics) -> f64 {
    a.parked_integral
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

/// The `dr_battle` board (`4r_dr_battle_spec.md` §3): the two structural rows + the
/// SURVIVAL-FLOOR row (restore-truth U ≥ X at the frozen K_floor). The HONEST-REFLECT
/// monotonicity + below-k_eff collapse are `tests.rs` sweeps (not board rows — they need
/// multiple co_loss values, which the board's single scenario cannot carry).
fn dr_battle_invariants() -> Vec<Invariant> {
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
        // INV-DR-BATTLE-FLOOR (spec §3, SURVIVAL-FLOOR): at the frozen K_floor the victim's
        // blocks keep ≥ k_eff survivors across the frozen seeds 42-46 (MEASURED, not structural
        // for an arbitrary seed — see DR_BATTLE_K_FLOOR; `dr_battle_floor_holds_per_seed_*` guards
        // it per-seed so widening the band can't silently pass on a mean), so restore-truth U must
        // clear the frozen DR_BATTLE_FLOOR_X floor — the correlated loss did NOT push a mature
        // backbone block below reconstructible. GreaterThan, power-gated (spec §10 п.16): a genuine
        // collapse FAILS and is the finding, NOT a bar to lower. The restore-U(co_loss) sweep
        // (tests.rs) is the HONEST-REFLECT co-evidence.
        Invariant {
            id: "INV-DR-BATTLE-FLOOR",
            spec: InvariantSpec::RestoreStatistical {
                measure: restore_u,
                dir: Direction::GreaterThan,
            },
            threshold: DR_BATTLE_FLOOR_X,
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
        // INV-A2-SILENT-PUNISHED (spec §3): the silent dropper's reliability quantity `G(dropper→
        // victim)` is punished BELOW the polite twin's by more than δ — the price of silence.
        // Ratio `retention_g_integral(silent)/retention_g_integral(polite) < 1 − δ = 0.85`,
        // δ = 0.15 FROZEN before the run (anti-Goodhart). LessThan, power-gated. After the seat-sync
        // fix (2026-07-19) BOTH mirror copies are burned, so this quantity IS the ENFORCEMENT KEY
        // κ_O (`g_ho`, read by `kappa_key` for the V_ret cap / eviction / preemption) — so the row
        // no longer measures an inert forecast: silence now cuts the dropper's V_ret standing.
        // Time-INTEGRATED because the fix makes the two arms diverge chaotically (a horizon snapshot
        // is noisy). The property test `g_oh ≡ g_ho^T` backs the "one key" claim.
        Invariant {
            id: "INV-A2-SILENT-PUNISHED",
            spec: InvariantSpec::AdvComparative {
                measure: adv_retention_g_integral,
                dir: Direction::LessThan,
            },
            threshold: 0.85,
        },
        // INV-A2-RETENTION (seat-sync fix, 2026-07-19): the REALIZED downstream squeeze — the silent
        // dropper's integrated PARKED volume sits below the polite twin's, because its lower κ_O
        // (= the burned `g_ho`) lowers its V_ret cap and makes it the eviction/preemption victim at
        // its reciprocal holders. Ratio `parked_integral(silent)/parked_integral(polite) < 0.85`
        // (same δ = 0.15, frozen). LessThan, power-gated. This realized volume is a DILUTED,
        // NOISIER signal than the direct key (INV-A2-SILENT-PUNISHED): non-victim park is unaffected
        // and the A.4 depth floor is deliberately NOT burned, so it may land INCONCLUSIVE while the
        // per-seed park curves clearly diverge — the DIRECT enforcement proof is the κ_O row + the
        // g_oh≡g_ho property test, this row is its (noisy) realization.
        Invariant {
            id: "INV-A2-RETENTION",
            spec: InvariantSpec::AdvComparative {
                measure: adv_parked_integral,
                dir: Direction::LessThan,
            },
            threshold: 0.85,
        },
        // INV-A2-INFLOW (spec §3): owners turn away from the silent dropper ⇒ its placement inflow
        // sits BELOW the polite twin's. Ratio `inflow(silent)/inflow(polite) < 1.0`. LessThan,
        // power-gated. HONEST NOTE (report): the DECISIVE placement path (post-0.3) reads the surface
        // PoS-window ONLY, NOT g_oh / drop-counters / σ (grep-verified), so placement does NOT
        // enforce — any aggregate inflow shift is an EMERGENT world-divergence side-effect, not
        // owners reading the ledger. EXPECTED INCONCLUSIVE at the modest adversary load; the direct
        // placement consumer is honest phase-4 work (out of A2 scope). The row MEASURES that gap.
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

/// The phase-2a tiered board (shared by `tiered_v1` / `tiered_hetero`): the two structural rows +
/// INV-TIER-GIVERS (the P7 give↔get rank) + INV-TIER-T1-ALIVE (the backbone sanity floor). Both
/// thresholds are FROZEN here BEFORE any tiered run (anti-Goodhart, `4r_p2a_spec.md` §3).
fn tiered_invariants() -> Vec<Invariant> {
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
        // INV-TIER-GIVERS (P7 §4 п.7): the RANK of what each tier RECEIVES (floor-completeness)
        // tracks the rank of what it can GIVE — T1 ≥ T2 ≥ T3 ≥ T4. The scalar is the smallest
        // adjacent floor-completeness STEP (`min_adjacent_giver_gap`); the row PASSES iff no
        // adjacent tier inverts by more than `TIER_RANK_MARGIN = 0.05` ⇒ threshold −0.05,
        // GreaterThan (mean gap > −0.05). Comparative on purpose: if floor-completeness saturates
        // (all ≈ 1, `floor_ever_met` monotone) the gap ≈ 0 with σ ≈ 0 ⇒ decisive PASS, and the
        // real gradient is read off durability/parked in the table (a FINDING, not a tuned bar). A
        // genuine inversion (a lower tier out-placing a higher one by > 5 pp) FAILS — that is a real
        // finding to report, not to hide. (power<2 ⇒ INCONCLUSIVE, spec §10 п.16.)
        Invariant {
            id: "INV-TIER-GIVERS",
            spec: InvariantSpec::TierStatistical {
                measure: tier_giver_gap,
                dir: Direction::GreaterThan,
            },
            threshold: -0.05,
        },
        // INV-TIER-T1-ALIVE (P7 sanity, §3 "T1-NAS не голодает"): the always-on NAS backbone must
        // reach floor on essentially all of its data. FROZEN at 0.90 (a round "FAIL if > 10% of the
        // backbone's data never places" gate) before the run — the T1 24/7 tier is the DR-primary
        // core, and if IT starves the whole giver network is broken. GreaterThan, power-gated.
        Invariant {
            id: "INV-TIER-T1-ALIVE",
            spec: InvariantSpec::TierStatistical {
                measure: tier_t1_floor,
                dir: Direction::GreaterThan,
            },
            threshold: 0.90,
        },
    ]
}

/// The `tiered_v1_inflow` board (`4r_inflow_spec.md` §3): the two structural rows + INV-POP-STATIONARY.
/// The tier P7 rank is NOT re-boarded here (the per-tier TABLE is shown for the closed-cohort
/// comparison via [`MetricId::TierReport`], but the spec makes only the population-stationarity claim a
/// board row); the lifetime floor-completeness growth is a secondary confirmation in the table.
fn tiered_inflow_invariants() -> Vec<Invariant> {
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
        // INV-POP-STATIONARY (spec §3): with the steady inflow the present-count holds within ±25 %
        // (POP_BAND) of the setpoint n0 over the LAST HALF of the horizon — a STATIONARY population,
        // not the closed cohort's monotone die-off. The scalar is the last-half MAX relative deviation
        // (`stationary_max_dev`); PASS iff mean < POP_BAND (LessThan, power-gated). The threshold is
        // FROZEN at POP_BAND = 0.25 BEFORE the run (anti-Goodhart): calibrate the SCENARIO (n0, λ_in),
        // never this bar. A residual drift beyond it is an HONEST finding about the λ_in calibration
        // (report with the curve, do NOT blind-tune λ_in — spec §4).
        Invariant {
            id: "INV-POP-STATIONARY",
            spec: InvariantSpec::PopStationary {
                measure: pop_max_dev,
                dir: Direction::LessThan,
            },
            threshold: POP_BAND,
        },
    ]
}

/// The `a3_flapper` board (phase-2a-2 §A3): DIAGNOSTIC-ONLY ⇒ the two STRUCTURAL rows ONLY. NO
/// INV-A3-* statistical row is registered — the σ-consumer is phase-4 work and σ is inert here, so
/// the flapper finding is a REPORT section (σ-profile / surfaced-frac / online-frac pred-vs-twin), NOT
/// a pass/fail bar (spec §A3 / world-v3 §3 WARN-1: "diagnostics until phase-4 σ-consumer").
fn a3_flapper_invariants() -> Vec<Invariant> {
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
    ]
}

/// The `a5_deep_silent` board (phase-2a-2 §A5): the two structural rows + INV-A5-DEEP-FLOOR.
fn a5_deep_silent_invariants() -> Vec<Invariant> {
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
        // INV-A5-DEEP-FLOOR (Р-1/W10, first direct dynamic test): the deep node's parked data
        // survives the M-month silence BETTER WITH the depth floor than WITHOUT it —
        // `survival(w_d=0.5) − survival(w_d=0) > 0.10` (the DIFFERENCE, not a ratio: at v_free=0 the
        // no-floor survival can be 0, the strongest case, which x/0 cannot express). Threshold 0.10 =
        // "the floor keeps ≥ 10 percentage points more of the deep tail alive" — a SEMANTIC margin
        // FROZEN before any run (anti-Goodhart): calibrate the SCENARIO (warmup, pause, deep-node
        // count), never this bar. GreaterThan, power-gated (spec §10 п.16): power < 2 ⇒ INCONCLUSIVE,
        // which is itself a finding ("the depth floor's dynamic protection is below the seed noise").
        Invariant {
            id: "INV-A5-DEEP-FLOOR",
            spec: InvariantSpec::AdvDifference {
                measure: adv_park_survival,
                dir: Direction::GreaterThan,
            },
            threshold: 0.10,
        },
    ]
}

/// The `a6_discriminator` board (phase-2a-2 §A6): the two structural rows + INV-A6-DISCR-ROI.
fn a6_discriminator_invariants() -> Vec<Invariant> {
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
        // INV-A6-DISCR-ROI (does discrimination PAY?): the discriminator's protected-own-storage
        // integral relative to its matched HONEST twin — `consumed(discr)/consumed(twin) < 1.0` ⇒
        // shedding the small owners buys it NO more durable protection than serving everyone (same
        // form as A1/A4's INV-ROI-PRED≤TWIN). Threshold 1.0 is the SEMANTIC "no better than honest"
        // line, FROZEN (anti-Goodhart). LessThan, power-gated. A FAIL (discr > twin ⇒ discrimination
        // REWARDED) or INCONCLUSIVE (discr ≈ twin ⇒ discrimination FREE) is the number-finding the
        // spec asks for — reported with the small-owner retention gap, NOT tuned away.
        Invariant {
            id: "INV-A6-DISCR-ROI",
            spec: InvariantSpec::AdvComparative {
                measure: adv_consumed,
                dir: Direction::LessThan,
            },
            threshold: 1.0,
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
