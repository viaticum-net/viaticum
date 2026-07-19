//! Unit tests for `sim_adv` (sub-tranches 0.1 + 0.2 restore-truth). `what_when_then`.

use crate::sim_adv::bootstrap::{
    BootstrapStats, collect_bootstrap, mean_over_seeds, run_bootstrap,
};
use crate::sim_adv::brier::{Calibration, DEFAULT_BRIER_BUCKETS};
use crate::sim_adv::cli::{apply_dial, parse_cli, resolve_seeds};
use crate::sim_adv::hetero::{
    DemandClass, DemandMix, DiskPolicy, apply_demand_classes, bit_eq as hetero_bit_eq,
};
use crate::sim_adv::metrics::{bit_eq as metrics_bit_eq, collect_metrics, mean_sigma};
use crate::sim_adv::predators::{
    RunMode, a1_epsilon_whale_hook, a4_whitewasher_hook, bit_eq as adv_bit_eq, fold_cap_ratio,
    inject_adversaries,
};
use crate::sim_adv::registry::{
    a1_whale, a4_whitewasher, all_scenarios, dr_baseline, dr_hetero, find_scenario,
    honest_hetero_hard, honest_hetero_v2, honest_v2,
};
use crate::sim_adv::report::{format_report, format_sweep, restore_csv, run_result_csv, sweep_csv};
use crate::sim_adv::restore::{
    BlockOutcome, IOTA_BUCKETS, RestoreTracker, RestoreTruth, bit_eq as restore_bit_eq, iota_bucket,
};
use crate::sim_adv::runner::{run, run_one_seed, run_sweep};
use crate::sim_adv::scenario::{
    AdvAction, AdvContext, AdvDials, AdvId, AdvSpec, BehaviorHook, Event, EventKind, InfoModel,
    MetricId, NodeSel, Scenario, WorldParams,
};
use crate::sim_adv::verdict::{Direction, VerdictKind, decide, evaluate_board};
use crate::sim_dynamic::build_world;
use crate::sim_dynamic::engine::{DynParams, whitewash_rejoin_for_test};
use crate::sim_dynamic::generator::{Archetype, GiverTier, HeldSymbol, OwnBlock, World, online};

// ------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------

/// A tiny scenario (fast to run) carrying one scripted event, for the dispatch test.
fn tiny_scenario_with_events(events: Vec<(u64, Event)>) -> Scenario {
    Scenario {
        id: crate::sim_adv::scenario::ScenarioId("tiny"),
        about: "tiny dispatch-skeleton scenario",
        world: WorldParams {
            n_nodes: 8,
            base: DynParams::default(),
            restore_window_days: 14.0,
            restore_bw_gb_day: 50.0,
            demand: DemandMix::Uniform,
        },
        population: Vec::new(),
        tiers: Vec::new(),
        adversaries: Vec::new(),
        events,
        horizon: 4,
        seeds: vec![1],
        metrics: vec![MetricId::InvariantBoard],
        verdicts: Vec::new(),
        fast: true,
    }
}

/// A cheap `honest_v2` clone (small world, short horizon) for sweep tests — mirrors the
/// shrink `report_text_is_byte_identical_on_repeat_under_rayon` already uses so sweep
/// tests stay fast without touching the full honest_v2 run.
fn tiny_sweep_scenario() -> Scenario {
    let mut sc = honest_v2();
    sc.world.n_nodes = 20;
    sc.horizon = 20;
    sc.seeds = vec![1, 2];
    sc
}

// ------------------------------------------------------------------
// registry
// ------------------------------------------------------------------

#[test]
fn registry_finds_honest_v2_by_name() {
    let s = find_scenario("honest_v2").expect("honest_v2 is registered");
    assert_eq!(s.id.as_str(), "honest_v2");
    assert_eq!(s.world.n_nodes, 100);
    assert_eq!(s.seeds, vec![42, 43, 44, 45, 46]);
}

#[test]
fn registry_returns_error_not_panic_for_unknown_scenario() {
    let err = find_scenario("does_not_exist");
    assert!(err.is_err(), "unknown scenario must be a graceful Err");
    // The message lists the known names (helpful, not a panic).
    let msg = format!("{}", err.unwrap_err());
    assert!(msg.contains("honest_v2"), "error lists known names: {msg}");
}

#[test]
fn registry_all_scenarios_is_non_empty() {
    assert!(!all_scenarios().is_empty());
}

// ------------------------------------------------------------------
// event dispatch skeleton
// ------------------------------------------------------------------

#[test]
fn event_dispatch_records_executor_on_the_scripted_tick() {
    let sc = tiny_scenario_with_events(vec![(2, Event::Disaster(NodeSel::Index(0)))]);
    let fired = run_one_seed(&sc, 1).fired;
    assert_eq!(fired.len(), 1, "exactly one event fired");
    assert_eq!(fired[0].tick, 2, "fired on the scripted tick");
    assert_eq!(fired[0].kind, EventKind::Disaster);
}

#[test]
fn event_dispatch_skips_events_scheduled_beyond_horizon() {
    // horizon is 4 (ticks 0..4); an event at tick 9 must never fire.
    let sc = tiny_scenario_with_events(vec![(9, Event::KillSubnet(3))]);
    let fired = run_one_seed(&sc, 1).fired;
    assert!(fired.is_empty(), "event past the horizon does not fire");
}

#[test]
fn event_dispatch_fires_multiple_events_at_their_ticks() {
    let sc = tiny_scenario_with_events(vec![
        (0, Event::JoinWave { count: 3 }),
        (
            1,
            Event::ContentChurn(NodeSel::Archetype(
                crate::sim_dynamic::generator::Archetype::Reliable,
            )),
        ),
        (3, Event::AdvActivate(AdvId::A1EpsilonWhale)),
    ]);
    let fired = run_one_seed(&sc, 1).fired;
    let ticks: Vec<u64> = fired.iter().map(|f| f.tick).collect();
    assert_eq!(ticks, vec![0, 1, 3]);
    assert_eq!(fired[0].kind, EventKind::JoinWave);
    assert_eq!(fired[1].kind, EventKind::ContentChurn);
    assert_eq!(fired[2].kind, EventKind::AdvActivate);
}

// ------------------------------------------------------------------
// verdict engine (power<2 ⇒ INCONCLUSIVE)
// ------------------------------------------------------------------

#[test]
fn verdict_is_inconclusive_when_power_below_two() {
    // mean 0.95, threshold 1.0, σ 0.10 ⇒ power = 0.5 < 2 ⇒ INCONCLUSIVE.
    let (kind, power) = decide(0.95, 0.10, 1.0, Direction::LessThan);
    assert_eq!(kind, VerdictKind::Inconclusive);
    assert!((power - 0.5).abs() < 1e-9, "power = {power}");
}

#[test]
fn verdict_passes_when_effect_clears_threshold_with_power() {
    // mean 0.30, threshold 1.0, σ 0.02 ⇒ power = 35 ≫ 2, mean < threshold ⇒ PASS.
    let (kind, power) = decide(0.30, 0.02, 1.0, Direction::LessThan);
    assert_eq!(kind, VerdictKind::Pass);
    assert!(power > 2.0);
}

#[test]
fn verdict_fails_when_effect_violates_threshold_with_power() {
    // mean 1.50, threshold 1.0, σ 0.02 ⇒ power = 25 ≫ 2, mean > threshold (LessThan) ⇒ FAIL.
    let (kind, _power) = decide(1.50, 0.02, 1.0, Direction::LessThan);
    assert_eq!(kind, VerdictKind::Fail);
}

#[test]
fn verdict_is_inconclusive_when_sigma_is_not_estimable() {
    // A single finite seed ⇒ σ NaN ⇒ INCONCLUSIVE (no spread estimate).
    let (kind, _p) = decide(0.3, f64::NAN, 1.0, Direction::LessThan);
    assert_eq!(kind, VerdictKind::Inconclusive);
}

// ------------------------------------------------------------------
// determinism of the report under the rayon fan-out
// ------------------------------------------------------------------

#[test]
fn report_text_is_byte_identical_on_repeat_under_rayon() {
    // A small-but-real world keeps the test quick while still exercising the whole
    // pipeline: the multi-seed rayon fan-out (order-preserving collect), the board's
    // seed[0] re-run, and the fixed-precision report formatting.
    let mut sc = honest_v2();
    sc.world.n_nodes = 20;
    sc.horizon = 25;
    sc.seeds = vec![7, 8, 9, 10];
    let seeds = sc.seeds.clone();

    let r1 = run(&sc, &seeds);
    let v1 = evaluate_board(&sc, &r1);
    let text1 = format_report(&sc, &r1, &v1);

    let r2 = run(&sc, &seeds);
    let v2 = evaluate_board(&sc, &r2);
    let text2 = format_report(&sc, &r2, &v2);

    assert_eq!(text1, text2, "report must be byte-identical on repeat");
}

// ------------------------------------------------------------------
// regression anchor: honest_v2 seed 42 == sim_diag 42 100 50 1 v2
// ------------------------------------------------------------------

#[test]
fn honest_v2_seed42_matches_sim_diag_anchor() {
    // Anchor = `sim_diag 42 100 50 1 v2` — RE-FROZEN 2026-07-19 for the Р-9 V_free-sweep
    // tranche (model default `v_free_symbols` flipped 2.0 → 0.0). Both sim_diag and honest_v2
    // run the SAME engine (build_world + step with DynParams::default), so they STILL agree
    // field-for-field — the point of this anchor is that the harness does not distort the
    // engine, not the exact values. The "≡ sim_diag" property is PRESERVED (both consume the
    // new default). Cross-verified vs `sim_diag 42 100 50 1 v2` at re-freeze time.
    //   The Р-9 shift (v_free 2 → 0, this seed): alive 224 UNCHANGED (occupancy is bandwidth/
    //   contention-bound, not V_free-bound); cap_trims 1 → 190 (the tariff now bites all parked
    //   volume above the earned κ_O/c_recip); evicts 506 → 643 (the cap-trims are logged too);
    //   preempts 377 → 386; share A>0 76.79 → 80.36 (low-reciprocity parked volume is trimmed,
    //   raising the g_ho>0 fraction); D 7306 → 7102; σ ~unchanged; durability Reliable 0.83 →
    //   0.97 (freed disk lets the high-κ_O giver hold more floor holders) but Nomad 0.71 → 0.29.
    //   ⚠ 0.29 is seed-42's LOWER TAIL, not a signal: the 5-seed sweep gives Nomad 0.76 ± 0.31
    //   at v_free=0 (review N1) — do not read a causal "v_free=0 punishes Nomad" story into
    //   this single-seed anchor value.
    let m = run_one_seed(&honest_v2(), 42).metrics;

    // Exact integer counters (sim_diag §6a/§3-sum/§6d).
    assert_eq!(m.alive_symbols, 224, "alive symbols (6a)");
    assert_eq!(m.evicts, 643, "eviction_log.len (sum of §3)");
    assert_eq!(m.preempts, 386, "preempt_count (6d)");
    assert_eq!(
        m.cap_trims, 190,
        "cap_trim_count (6d) — Р-9 tariff bites at V_free=0"
    );

    // Floats to the sim_diag print precision.
    assert!(
        (m.share_a_pos - 80.36).abs() < 0.1,
        "share A>0 = {}",
        m.share_a_pos
    );
    assert!(
        (m.mean_depth - 7102.365).abs() < 0.01,
        "mean D = {}",
        m.mean_depth
    );
    assert!(
        (m.mean_sigma - 0.0054).abs() < 1e-4,
        "mean σ = {}",
        m.mean_sigma
    );
    // Per-archetype floor durability (sim_diag §5): Reliable 0.97, Nomad 0.29, Hoarder 1.29.
    assert!(
        (m.durability[0] - 0.97).abs() < 0.01,
        "Reliable durability = {}",
        m.durability[0]
    );
    assert!(
        (m.durability[3] - 0.29).abs() < 0.01,
        "Nomad durability = {}",
        m.durability[3]
    );
    assert!(
        (m.durability[4] - 1.29).abs() < 0.01,
        "Hoarder durability = {}",
        m.durability[4]
    );
}

// ------------------------------------------------------------------
// ROI invariant on honest_v2 (asserted on the FACT, not a wish)
// ------------------------------------------------------------------

#[test]
fn honest_v2_reliable_extraction_roi_is_near_balance_and_bounded() {
    // FACT (measured, not a wish): under served-matrix conservation the honest giver
    // Reliable operates at BALANCED reciprocity — seed 42 ROI ≈ 1.006 (Р-9 V_free=0 tranche;
    // was 0.989 at v_free=2), NOT above the ceiling. (Universal "< 1 for all archetypes" is
    // impossible: Σconsumed ≡ Σserved_out.) The invariant is BOUNDED extraction, so we lock
    // the measured value and the 1.25 ceiling.
    let m = run_one_seed(&honest_v2(), 42).metrics;
    let roi = m.extraction_roi[0];
    assert!(
        (roi - 1.006).abs() < 0.01,
        "Reliable ROI (seed 42 fact) = {roi}"
    );
    assert!(
        roi < 1.25,
        "honest giver's extraction is bounded (< 1.25 ceiling): {roi}"
    );
}

#[test]
fn honest_v2_board_has_the_three_v0_invariants() {
    let sc = {
        let mut s = honest_v2();
        s.seeds = vec![42, 43];
        s
    };
    let seeds = sc.seeds.clone();
    let result = run(&sc, &seeds);
    let verdicts = evaluate_board(&sc, &result);
    let ids: Vec<&str> = verdicts.iter().map(|v| v.id).collect();
    assert_eq!(
        ids,
        vec!["INV-DETERMINISM", "INV-ANTI-ORACLE", "INV-ROI-RELIABLE"]
    );
    // Structural rows PASS; the ROI row is decided from the two-seed spread.
    assert_eq!(verdicts[0].kind, VerdictKind::Pass, "determinism");
    assert_eq!(verdicts[1].kind, VerdictKind::Pass, "anti-oracle");
}

// ------------------------------------------------------------------
// CLI parsing
// ------------------------------------------------------------------

#[test]
fn cli_parses_scenario_and_defaults() {
    let cli = parse_cli(&["honest_v2".to_string()]).unwrap();
    assert_eq!(cli.scenario, "honest_v2");
    assert_eq!(cli.seeds, None);
    assert!(cli.sweep.is_none());
    assert!(cli.csv.is_none());
    assert!(!cli.fast);
}

#[test]
fn cli_parses_seeds_sweep_csv_fast() {
    let cli = parse_cli(&[
        "honest_v2".to_string(),
        "--seeds".to_string(),
        "3".to_string(),
        "--sweep".to_string(),
        "block_volume=20,50".to_string(),
        "--csv".to_string(),
        "/tmp/x.csv".to_string(),
        "--fast".to_string(),
    ])
    .unwrap();
    assert_eq!(cli.seeds, Some(3));
    let sw = cli.sweep.unwrap();
    assert_eq!(sw.dial, "block_volume");
    assert_eq!(sw.values, vec![20.0, 50.0]);
    assert_eq!(cli.csv.as_deref(), Some("/tmp/x.csv"));
    assert!(cli.fast);
}

#[test]
fn cli_missing_scenario_is_error() {
    assert!(parse_cli(&[]).is_err());
}

#[test]
fn cli_unknown_flag_is_error() {
    assert!(parse_cli(&["honest_v2".to_string(), "--nope".to_string()]).is_err());
}

#[test]
fn cli_unknown_sweep_dial_is_error() {
    let err = parse_cli(&[
        "honest_v2".to_string(),
        "--sweep".to_string(),
        "bogus_dial=1,2".to_string(),
    ]);
    assert!(err.is_err(), "unknown dial is a graceful error");
    assert!(format!("{}", err.unwrap_err()).contains("bogus_dial"));
}

#[test]
fn cli_seeds_zero_is_error() {
    assert!(
        parse_cli(&[
            "honest_v2".to_string(),
            "--seeds".to_string(),
            "0".to_string()
        ])
        .is_err()
    );
}

#[test]
fn resolve_seeds_overrides_count_from_base() {
    assert_eq!(resolve_seeds(&[42, 43, 44, 45, 46], Some(1)), vec![42]);
    assert_eq!(
        resolve_seeds(&[42, 43, 44, 45, 46], Some(3)),
        vec![42, 43, 44]
    );
    assert_eq!(
        resolve_seeds(&[42, 43, 44, 45, 46], None),
        vec![42, 43, 44, 45, 46]
    );
}

#[test]
fn apply_dial_sets_known_and_rejects_unknown() {
    let mut p = DynParams::default();
    apply_dial(&mut p, "block_volume", 20.0).unwrap();
    assert_eq!(p.block_volume, 20.0);
    apply_dial(&mut p, "depth_w_d", 0.0).unwrap();
    assert_eq!(p.depth_w_d, 0.0);
    assert!(apply_dial(&mut p, "not_a_dial", 1.0).is_err());
}

// ------------------------------------------------------------------
// stats helper + CSV
// ------------------------------------------------------------------

#[test]
fn mean_sigma_skips_nan_and_needs_two_for_sigma() {
    let (m, s) = mean_sigma(&[2.0, 4.0, f64::NAN]);
    assert!((m - 3.0).abs() < 1e-9);
    assert!((s - std::f64::consts::SQRT_2).abs() < 1e-9); // sample sd of {2,4} = √2
    let (m1, s1) = mean_sigma(&[5.0]);
    assert_eq!(m1, 5.0);
    assert!(s1.is_nan(), "σ undefined for one value");
}

#[test]
fn csv_has_header_and_one_row_per_seed() {
    let mut sc = honest_v2();
    sc.seeds = vec![42, 43];
    let result = run(&sc, &sc.seeds.clone());
    let csv = run_result_csv(&result);
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 3, "header + 2 seed rows");
    assert!(lines[0].starts_with("scenario,seed,alive_symbols"));
    assert!(lines[1].starts_with("honest_v2,42,"));
    assert!(lines[2].starts_with("honest_v2,43,"));
}

// ------------------------------------------------------------------
// sweep CSV (BLOCK review fix: one header + dial/value columns, distinguishable points)
// ------------------------------------------------------------------

#[test]
fn run_sweep_gives_distinguishable_results_across_dial_values() {
    let sc = tiny_sweep_scenario();
    let seeds = sc.seeds.clone();
    let rows = run_sweep(&sc, "block_volume", &[10.0, 90.0], &seeds).unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].value, 10.0);
    assert_eq!(rows[1].value, 90.0);
    // Larger blocks ⇒ fewer alive symbols per seed: the two sweep points are not just
    // different `value`s but genuinely different runs (this was invisible in the old
    // per-run-concatenated CSV, which had no column to tell the points apart at all).
    for (i, &seed) in seeds.iter().enumerate() {
        assert_ne!(
            rows[0].result.per_seed[i], rows[1].result.per_seed[i],
            "seed {seed} metrics must differ between block_volume=10 and =90",
        );
        assert!(
            rows[0].result.per_seed[i].alive_symbols > rows[1].result.per_seed[i].alive_symbols,
            "smaller block_volume keeps more alive symbols (seed {seed})",
        );
    }
}

#[test]
fn sweep_csv_has_one_header_dial_value_columns_and_distinguishable_rows() {
    let sc = tiny_sweep_scenario();
    let seeds = sc.seeds.clone();
    let rows = run_sweep(&sc, "block_volume", &[10.0, 90.0], &seeds).unwrap();
    let csv = sweep_csv("block_volume", &rows);
    let lines: Vec<&str> = csv.lines().collect();

    // Exactly one header, 2 sweep points × 2 seeds = 4 data rows.
    assert_eq!(lines.len(), 5, "one header + 4 data rows: {csv}");
    let header_count = lines
        .iter()
        .filter(|l| l.starts_with("scenario,seed,alive_symbols"))
        .count();
    assert_eq!(header_count, 1, "header must appear exactly once: {csv}");
    assert!(
        lines[0].ends_with(",dial,value"),
        "header carries the dial/value columns: {}",
        lines[0]
    );

    // Every data row is tagged with the handle name and its own value.
    let data_rows = &lines[1..];
    assert!(data_rows.iter().any(|l| l.ends_with(",block_volume,10")));
    assert!(data_rows.iter().any(|l| l.ends_with(",block_volume,90")));

    // The two sweep points are distinguishable by more than the trailing dial/value
    // columns: alive_symbols (column index 2) differs between them.
    let alive_at = |suffix: &str| -> Vec<usize> {
        data_rows
            .iter()
            .filter(|l| l.ends_with(suffix))
            .map(|l| l.split(',').nth(2).unwrap().parse::<usize>().unwrap())
            .collect()
    };
    let at10 = alive_at(",block_volume,10");
    let at90 = alive_at(",block_volume,90");
    assert_eq!(at10.len(), 2);
    assert_eq!(at90.len(), 2);
    for (a, b) in at10.iter().zip(&at90) {
        assert_ne!(a, b, "alive_symbols must differ between sweep points");
    }
}

#[test]
fn format_sweep_shows_both_dial_points() {
    let sc = tiny_sweep_scenario();
    let seeds = sc.seeds.clone();
    let rows = run_sweep(&sc, "block_volume", &[10.0, 90.0], &seeds).unwrap();
    let text = format_sweep(&sc, "block_volume", &rows);

    let data_lines: Vec<&str> = text.lines().skip(2).collect();
    assert_eq!(data_lines.len(), 2, "one line per sweep point: {text}");
    assert!(data_lines[0].trim_start().starts_with("10.0000"));
    assert!(data_lines[1].trim_start().starts_with("90.0000"));
}

// ------------------------------------------------------------------
// anti-oracle behaviour-hook signature (spec §10 п.14)
// ------------------------------------------------------------------

fn noop_hook(_ctx: &AdvContext) -> AdvAction {
    AdvAction::NOOP
}

#[test]
fn behavior_hook_has_no_world_and_returns_action() {
    // The hook is a `fn(&AdvContext) -> AdvAction` — no `&World` by construction.
    let hook: BehaviorHook = noop_hook;
    let ctx = AdvContext {
        adv_node: 7,
        tick: 3,
        info_model: InfoModel::DrCard { target: 0 },
        dials: AdvDials::default(),
        joined_tick: 0,
    };
    assert_eq!(hook(&ctx), AdvAction::NOOP);
}

// ------------------------------------------------------------------
// vocabulary skeleton coverage (the id enums exist and label cleanly)
// ------------------------------------------------------------------

#[test]
fn vocabulary_enums_are_complete_and_labelled() {
    assert_eq!(AdvId::ALL.len(), 14);
    assert!(AdvId::ALL.iter().all(|a| !a.label().is_empty()));
    assert_eq!(EventKind::ALL.len(), 8);
    assert!(EventKind::ALL.iter().all(|k| !k.label().is_empty()));
    assert_eq!(MetricId::ALL.len(), 8);
    assert!(MetricId::ALL.iter().all(|m| !m.label().is_empty()));

    // Touch the remaining vocabulary so it is genuine caркас, not future dead types.
    let _sel = [
        NodeSel::Index(0),
        NodeSel::Archetype(crate::sim_dynamic::generator::Archetype::Hoarder),
        NodeSel::TopHolders(0.1),
        NodeSel::Random(3),
    ];
    let _spec = AdvSpec {
        id: AdvId::A7SybilFarm,
        count: 5,
        info_model: InfoModel::Own,
        dials: AdvDials {
            group_size: 5,
            ..AdvDials::default()
        },
    };
}

// ------------------------------------------------------------------
// restore-truth (metric №1, sub-tranche 0.2) — god-view collectability
// ------------------------------------------------------------------

/// A restore `WorldParams` with the given window / bandwidth (default-engine dials).
fn restore_wp(n_nodes: usize, window_days: f64, bw_gb_day: f64) -> WorldParams {
    WorldParams {
        n_nodes,
        base: DynParams::default(),
        restore_window_days: window_days,
        restore_bw_gb_day: bw_gb_day,
        demand: DemandMix::Uniform,
    }
}

/// A floor-met, source-present own block (so `on_disaster` counts it in the denominator).
fn floor_met_block(id: usize, iota: f64) -> OwnBlock {
    OwnBlock {
        id,
        volume: 50.0,
        iota,
        placements: Vec::new(),
        floor_ever_met: true,
        floor_deficit_since: None,
        to_restore: false,
    }
}

/// A controlled world: all nodes present + Reliable with empty holdings (so we place the
/// victim's symbols by hand and `online()` is stable-high — we still SELECT holders that
/// `online()` returns true for, so collection is deterministic).
fn controlled_world(n_nodes: usize, seed: u64) -> World {
    let params = DynParams::default();
    let mut world = build_world(n_nodes, &params, seed);
    for nd in &mut world.nodes {
        nd.present = true;
        nd.archetype = Archetype::Reliable;
        nd.holdings.clear();
    }
    world
}

/// `count` holders (≠ `victim`) that are present AND online at `tick` — so a symbol placed
/// on them is deterministically collectable in a window covering `tick`.
fn online_holders(world: &World, victim: usize, tick: u64, count: usize) -> Vec<usize> {
    let h: Vec<usize> = (0..world.nodes.len())
        .filter(|&i| {
            i != victim
                && world.nodes[i].present
                && online(
                    world.nodes[i].archetype,
                    world.nodes[i].id,
                    tick,
                    world.seed,
                )
        })
        .take(count)
        .collect();
    assert_eq!(h.len(), count, "need {count} online holders for the setup");
    h
}

/// Place one alive symbol of `owner`'s `block` on `holder` (10 GB, floor or cream).
fn push_held(world: &mut World, holder: usize, owner: usize, block: usize, iota: f64, cream: bool) {
    world.nodes[holder].holdings.push(HeldSymbol {
        owner,
        block,
        iota,
        volume: 10.0,
        alive: true,
        cream,
    });
}

#[test]
fn restore_truth_counts_cream_when_floor_below_k_but_floor_plus_cream_reaches_k() {
    // BLOCK-1 (spec §10 п.1): RaptorQ decodes from ANY k_eff symbols, so 1 floor + 2 cream
    // (k_eff = 2) is RESTORABLE (any-symbol) even though the floor alone (1) is below k_eff.
    // The durability-floor column, counting floor only, is NOT restorable — the flagship
    // metric and the "what is guaranteed" column legitimately disagree.
    let wp = restore_wp(16, 14.0, 50.0);
    let mut world = controlled_world(wp.n_nodes, 7);
    let victim = 0usize;
    world.nodes[victim].own_blocks = vec![floor_met_block(0, 0.5)];
    let disaster_tick = 5u64;
    let return_tick = disaster_tick + 1;
    let holders = online_holders(&world, victim, return_tick, 3);
    push_held(&mut world, holders[0], victim, 0, 0.5, false); // floor
    push_held(&mut world, holders[1], victim, 0, 0.5, true); // cream
    push_held(&mut world, holders[2], victim, 0, 0.5, true); // cream

    let mut tracker = RestoreTracker::new(&wp);
    tracker.on_disaster(&world, victim, disaster_tick, DemandClass::M);
    tracker.observe(&world, return_tick);
    tracker.observe(&world, return_tick + 1);
    let rt = tracker.finalize();

    assert_eq!(rt.blocks.len(), 1, "one surviving floor-met block");
    let b = rt.blocks[0];
    assert_eq!(b.n_collectable_any, 3, "1 floor + 2 cream all collectable");
    assert_eq!(
        b.n_collectable_floor, 1,
        "only the floor symbol is a floor symbol"
    );
    assert!(
        b.restorable_u,
        "any ≥ k_eff (3 ≥ 2) ⇒ restorable — cream counts (BLOCK-1)"
    );
    assert!(
        !b.restorable_floor,
        "floor alone (1) < k_eff (2) ⇒ NOT durability-floor"
    );
    assert_eq!(rt.restore_truth_u(), 1.0);
    assert_eq!(rt.durability_floor(), 0.0);
}

#[test]
fn restore_truth_model_s_is_at_most_model_u_and_bites_under_a_tiny_budget() {
    // Model S = Model U collectability under a download cap (spec §10 п.9). Two floor-met
    // blocks, each with k_eff online floor holders (each restorable under U). A budget that
    // fits ONE block's k_eff symbols but not two ⇒ S restores 1 of 2 while U restores 2 of
    // 2: S < U, and never S > U. The higher-ι block is the one restored (greedy by ι).
    let k = DynParams::default().k_eff; // 2
    let window_days = 14.0;
    // Cost per block = k × 10 GB = 20 GB. Budget ≈ 21 GB ⇒ fits one block, not two.
    let bw = 21.0 / window_days;
    let wp = restore_wp(16, window_days, bw);
    let mut world = controlled_world(wp.n_nodes, 11);
    let victim = 0usize;
    world.nodes[victim].own_blocks = vec![floor_met_block(0, 0.8), floor_met_block(1, 0.4)];
    let disaster_tick = 5u64;
    let return_tick = disaster_tick + 1;
    let holders = online_holders(&world, victim, return_tick, 2 * k);
    for &h in holders.iter().take(k) {
        push_held(&mut world, h, victim, 0, 0.8, false);
    }
    for &h in holders.iter().skip(k).take(k) {
        push_held(&mut world, h, victim, 1, 0.4, false);
    }

    let mut tracker = RestoreTracker::new(&wp);
    tracker.on_disaster(&world, victim, disaster_tick, DemandClass::M);
    tracker.observe(&world, return_tick);
    tracker.observe(&world, return_tick + 1);
    let rt = tracker.finalize();

    for b in &rt.blocks {
        assert!(
            !b.restorable_s || b.restorable_u,
            "Model S ⇒ Model U (S ≤ U) per block"
        );
    }
    assert_eq!(rt.restore_truth_u(), 1.0, "both blocks restorable under U");
    assert!(
        rt.restore_truth_s() < rt.restore_truth_u(),
        "the tiny budget makes S bite below U"
    );
    assert_eq!(
        rt.restore_truth_s(),
        0.5,
        "budget fits exactly one of two blocks"
    );
    let hi = rt.blocks.iter().find(|b| b.block_id == 0).unwrap();
    let lo = rt.blocks.iter().find(|b| b.block_id == 1).unwrap();
    assert!(
        hi.restorable_s && !lo.restorable_s,
        "Model S restores the higher-ι block first (importance-priority greedy)"
    );
}

#[test]
fn restore_truth_respects_the_window_departed_and_out_of_window_holders_are_not_collected() {
    // The window is honoured two ways: (1) a holder that has LEFT (present=false) before
    // the window is not collectable even though its stale symbol slot is still alive; and
    // (2) observing at a tick PAST the window collects nothing.
    let wp = restore_wp(16, 14.0, 50.0); // W = 2 ticks
    let mut world = controlled_world(wp.n_nodes, 3);
    let victim = 0usize;
    world.nodes[victim].own_blocks = vec![floor_met_block(0, 0.6)];
    let disaster_tick = 5u64;
    let return_tick = disaster_tick + 1;
    let holders = online_holders(&world, victim, return_tick, 3);
    for &h in &holders {
        push_held(&mut world, h, victim, 0, 0.6, false);
    }
    // One holder has DEPARTED before the window opens (gone, not collectable).
    world.nodes[holders[2]].present = false;

    let mut tracker = RestoreTracker::new(&wp);
    tracker.on_disaster(&world, victim, disaster_tick, DemandClass::M);
    tracker.observe(&world, return_tick);
    tracker.observe(&world, return_tick + 1);
    let rt = tracker.finalize();
    assert_eq!(
        rt.blocks[0].n_collectable_any, 2,
        "the departed holder is not collectable; the two present-online ones are"
    );
    assert!(rt.blocks[0].restorable_u, "2 present holders ≥ k_eff = 2");

    // Observing only at a tick PAST the window (return + 2 = window end, exclusive) collects
    // nothing — the window [return, return+2) is respected.
    let mut tracker2 = RestoreTracker::new(&wp);
    tracker2.on_disaster(&world, victim, disaster_tick, DemandClass::M);
    tracker2.observe(&world, return_tick + 2);
    let rt2 = tracker2.finalize();
    assert_eq!(
        rt2.blocks[0].n_collectable_any, 0,
        "observing past the window collects nothing"
    );
}

#[test]
fn restore_truth_victim_does_not_resurrect_with_data_when_no_holder_is_collectable() {
    // The victim returns with an EMPTY disk — restore-truth reflects actual collection, not
    // magic recovery. With every holder of a block departed, that block is NOT restorable
    // (0 collectable symbols), even though it once met floor.
    let wp = restore_wp(16, 14.0, 50.0);
    let mut world = controlled_world(wp.n_nodes, 21);
    let victim = 0usize;
    world.nodes[victim].own_blocks = vec![floor_met_block(0, 0.7)];
    let disaster_tick = 5u64;
    let return_tick = disaster_tick + 1;
    let holders = online_holders(&world, victim, return_tick, 3);
    for &h in &holders {
        push_held(&mut world, h, victim, 0, 0.7, false);
        world.nodes[h].present = false; // every holder of this block is gone
    }

    let mut tracker = RestoreTracker::new(&wp);
    tracker.on_disaster(&world, victim, disaster_tick, DemandClass::M);
    tracker.observe(&world, return_tick);
    tracker.observe(&world, return_tick + 1);
    let rt = tracker.finalize();
    assert_eq!(
        rt.blocks[0].n_collectable_any, 0,
        "no holder alive to collect from"
    );
    assert!(
        !rt.blocks[0].restorable_u,
        "not restorable without collection"
    );
    assert_eq!(rt.restore_truth_u(), 0.0);
}

#[test]
fn restore_truth_model_o_equals_u_at_full_uptime() {
    // F4 (D7): Model O (one-shot) counts holders reachable at the FIRST window tick only.
    // When the k_eff holders are all reachable at the first tick (full uptime), O = U — the
    // pessimistic no-retry floor equals the aspirational union ceiling.
    let wp = restore_wp(16, 14.0, 50.0);
    let mut world = controlled_world(wp.n_nodes, 31);
    let victim = 0usize;
    world.nodes[victim].own_blocks = vec![floor_met_block(0, 0.6)];
    let disaster_tick = 5u64;
    let return_tick = disaster_tick + 1;
    let k = wp.base.k_eff; // 2
    let holders = online_holders(&world, victim, return_tick, k);
    for &h in &holders {
        push_held(&mut world, h, victim, 0, 0.6, false);
    }

    let mut tracker = RestoreTracker::new(&wp);
    tracker.on_disaster(&world, victim, disaster_tick, DemandClass::M);
    tracker.observe(&world, return_tick);
    tracker.observe(&world, return_tick + 1);
    let rt = tracker.finalize();

    let b = rt.blocks[0];
    assert!(
        b.n_collectable_oneshot <= b.n_collectable_any,
        "O ≤ U per block"
    );
    assert_eq!(
        b.n_collectable_oneshot, b.n_collectable_any,
        "all holders reachable at the first tick ⇒ O = U count"
    );
    assert!(
        b.restorable_o && b.restorable_u,
        "both restorable at full uptime"
    );
    assert_eq!(rt.restore_truth_o(), 1.0);
    assert_eq!(rt.restore_truth_u(), 1.0);
    assert_eq!(
        rt.restore_truth_o(),
        rt.restore_truth_u(),
        "O = U at full uptime"
    );
}

#[test]
fn restore_truth_model_o_is_below_u_when_a_holder_surfaces_only_after_the_first_tick() {
    // F4 (D7): a holder NOT reachable at the FIRST window tick but reachable later is counted
    // by Model U (union-over-window) yet NOT by Model O (one-shot). With exactly k_eff holders,
    // one of them unreachable at the first tick, the block is U-restorable but NOT O-restorable
    // ⇒ O < U (strictly). This is the discrimination phase-2 uptime profiles will surface;
    // dr_baseline itself has O = U because its holders are ~always reachable (NOTE-8).
    let wp = restore_wp(16, 14.0, 50.0);
    let mut world = controlled_world(wp.n_nodes, 41);
    let victim = 0usize;
    world.nodes[victim].own_blocks = vec![floor_met_block(0, 0.6)];
    let disaster_tick = 5u64;
    let return_tick = disaster_tick + 1;
    let k = wp.base.k_eff; // 2
    let holders = online_holders(&world, victim, return_tick, k);
    for &h in &holders {
        push_held(&mut world, h, victim, 0, 0.6, false);
    }
    // The SECOND holder is NOT reachable at the first tick (models an offline-at-first holder).
    let late = holders[1];
    world.nodes[late].present = false;

    let mut tracker = RestoreTracker::new(&wp);
    tracker.on_disaster(&world, victim, disaster_tick, DemandClass::M);
    tracker.observe(&world, return_tick); // late holder unreachable ⇒ not in O nor U yet
    world.nodes[late].present = true; // it surfaces on the second window tick
    tracker.observe(&world, return_tick + 1); // U grabs it (union); O does NOT (past first tick)
    let rt = tracker.finalize();

    let b = rt.blocks[0];
    assert_eq!(
        b.n_collectable_oneshot, 1,
        "only the first-tick holder is in O"
    );
    assert_eq!(
        b.n_collectable_any, 2,
        "both holders are in U (union over window)"
    );
    assert!(!b.restorable_o, "O below k_eff ⇒ NOT one-shot restorable");
    assert!(b.restorable_u, "U reaches k_eff ⇒ restorable");
    assert!(
        rt.restore_truth_o() < rt.restore_truth_u(),
        "O < U when a holder surfaces only after the first tick: O={} U={}",
        rt.restore_truth_o(),
        rt.restore_truth_u()
    );
}

#[test]
fn restore_truth_is_bit_identical_on_repeat() {
    // Determinism (spec §10 п.13): the whole Disaster → restore-truth path is seeded, so
    // two runs of a DR scenario produce bit-identical restore-truth per seed.
    let mut sc = dr_baseline();
    sc.world.n_nodes = 60;
    sc.horizon = 60;
    sc.events = vec![(
        30,
        Event::Disaster(NodeSel::FirstTierArchetype(
            GiverTier::T1,
            Archetype::Reliable,
        )),
    )];
    sc.seeds = vec![1, 2];
    let seeds = sc.seeds.clone();

    let r1 = run(&sc, &seeds);
    let r2 = run(&sc, &seeds);
    assert!(
        r1.per_seed_restore.iter().any(|r| r.is_some()),
        "the DR scenario must actually produce restore-truth"
    );
    for (a, b) in r1.per_seed_restore.iter().zip(&r2.per_seed_restore) {
        match (a, b) {
            (Some(x), Some(y)) => {
                assert!(
                    restore_bit_eq(x, y),
                    "restore-truth must be bit-identical on repeat"
                )
            }
            (None, None) => {}
            _ => panic!("restore presence differs between the two runs"),
        }
    }
}

#[test]
fn dr_baseline_board_passes_the_restore_sanity_floor() {
    // The frozen INV-RESTORE-SANITY row: on the honest DR baseline, restore-truth U clears
    // the 0.60 floor decisively (σ = 0 ⇒ power = ∞). Uses two seeds to keep the test quick.
    let sc = {
        let mut s = dr_baseline();
        s.seeds = vec![42, 43];
        s
    };
    let result = run(&sc, &sc.seeds.clone());
    let verdicts = evaluate_board(&sc, &result);
    let sanity = verdicts
        .iter()
        .find(|v| v.id == "INV-RESTORE-SANITY")
        .expect("dr_baseline board carries INV-RESTORE-SANITY");
    assert_eq!(sanity.kind, VerdictKind::Pass, "restore sanity floor holds");
    assert!(
        sanity.effect > 0.60,
        "restore-truth U clears the floor: {}",
        sanity.effect
    );
}

#[test]
fn restore_csv_carries_both_models_and_the_info_model_column() {
    // Spec §10 п.18 / NOTE-5: the restore CSV has both Model U and Model S columns plus an
    // info_model column ("none" while there are no predators).
    let sc = {
        let mut s = dr_baseline();
        s.seeds = vec![42];
        s
    };
    let result = run(&sc, &sc.seeds.clone());
    let csv = restore_csv(&result);
    let lines: Vec<&str> = csv.lines().collect();
    assert!(
        lines[0].contains("restore_truth_u") && lines[0].contains("restore_truth_s"),
        "header carries both models: {}",
        lines[0]
    );
    assert!(
        lines[0].ends_with(",info_model"),
        "header ends with info_model"
    );
    assert_eq!(lines.len(), 2, "header + one seed row");
    assert!(lines[1].starts_with("dr_baseline,42,"));
    assert!(
        lines[1].ends_with(",none"),
        "info_model = none (no predators): {}",
        lines[1]
    );
}

// ------------------------------------------------------------------
// 0.2-fix (NOTE): direct tests for `iota_bucket` / `restore_u_in_bucket`
// ------------------------------------------------------------------

/// A minimal `BlockOutcome` row: only `iota` and `restorable_u` matter for these tests.
fn bucket_row(iota: f64, restorable_u: bool) -> BlockOutcome {
    BlockOutcome {
        owner: 0,
        block_id: 0,
        iota,
        tier: GiverTier::T1,
        class: DemandClass::M,
        n_collectable_any: 0,
        n_collectable_floor: 0,
        n_collectable_oneshot: 0,
        restorable_u,
        restorable_s: false,
        restorable_o: false,
        restorable_floor: false,
    }
}

fn restore_truth_with_blocks(blocks: Vec<BlockOutcome>) -> RestoreTruth {
    RestoreTruth {
        disaster_tick: 0,
        window_days: 14.0,
        window_ticks: 14,
        restore_bw_gb_day: 0.0,
        n_victims: 1,
        k_eff: 2,
        blocks,
        info_model: "none",
    }
}

#[test]
fn iota_bucket_returns_the_second_bucket_when_iota_sits_on_its_lower_edge() {
    // IOTA_BUCKETS[1] = (0.4, 0.6): the lower edge is INCLUSIVE (half-open on the low side).
    assert_eq!(iota_bucket(0.4), 1);
}

#[test]
fn iota_bucket_returns_the_last_bucket_when_iota_is_one() {
    // The top bucket (0.8, 1.0) is CLOSED at 1.0 — unlike the other three, whose upper edge
    // is exclusive.
    assert_eq!(iota_bucket(1.0), IOTA_BUCKETS.len() - 1);
}

#[test]
fn iota_bucket_clamps_into_the_first_bucket_when_iota_is_below_the_covered_range() {
    // No scenario places ι below 0.2 in practice, but the function must not panic or
    // return an out-of-range index — it clamps into bucket 0 (the same as an in-range
    // low value would).
    assert_eq!(iota_bucket(0.1), 0);
    assert_eq!(iota_bucket(-5.0), 0);
}

#[test]
fn restore_u_in_bucket_computes_the_fraction_restorable_within_that_bucket_only() {
    // A small synthetic set spanning two buckets (0.3 and 0.35 both fall in bucket 0 per
    // `iota_bucket`, 0.5 falls in bucket 1): bucket 0 gets 1-of-2 restorable, bucket 1 gets
    // 1-of-1, and bucket 2 is left empty (covered by the NaN test below).
    let rt = restore_truth_with_blocks(vec![
        bucket_row(0.3, true),   // bucket 0
        bucket_row(0.35, false), // bucket 0
        bucket_row(0.5, true),   // bucket 1
    ]);

    assert!(
        (rt.restore_u_in_bucket(0) - 0.5).abs() < 1e-9,
        "1 of 2 rows in bucket 0 restorable"
    );
    assert_eq!(
        rt.restore_u_in_bucket(1),
        1.0,
        "the only row in bucket 1 is restorable"
    );
}

#[test]
fn restore_u_in_bucket_is_nan_when_the_bucket_has_no_rows() {
    let rt = restore_truth_with_blocks(vec![bucket_row(0.3, true)]);
    assert!(
        rt.restore_u_in_bucket(2).is_nan(),
        "bucket 2 (0.6,0.8) has no rows in this synthetic set"
    );
}

// ------------------------------------------------------------------
// R̂-calibration Brier math (transche 0.3 judge) — synthetic invariants.
// ------------------------------------------------------------------

#[test]
fn brier_is_zero_for_a_perfect_forecast() {
    // A forecast that always calls the outcome exactly (0 when it dies, 1 when it lives)
    // scores Brier 0, reliability 0, and resolution == uncertainty (perfect separation).
    let mut c = Calibration::new();
    for _ in 0..40 {
        c.push(1.0, true, true);
    }
    for _ in 0..60 {
        c.push(0.0, false, true);
    }
    let r = c.complete_report(DEFAULT_BRIER_BUCKETS).expect("non-empty");
    assert!(
        r.brier.abs() < 1e-12,
        "perfect forecast ⇒ Brier 0, got {}",
        r.brier
    );
    assert!(
        r.reliability.abs() < 1e-12,
        "perfect forecast ⇒ reliability 0, got {}",
        r.reliability
    );
    // base rate 0.4 ⇒ uncertainty 0.24; a perfect forecast's resolution equals it.
    assert!((r.base_rate - 0.4).abs() < 1e-12);
    assert!((r.uncertainty - 0.24).abs() < 1e-12);
    assert!(
        (r.resolution - r.uncertainty).abs() < 1e-12,
        "perfect forecast ⇒ resolution == uncertainty"
    );
    // Murphy identity holds exactly here (forecasts constant within their buckets).
    assert!((r.brier - (r.reliability - r.resolution + r.uncertainty)).abs() < 1e-12);
}

#[test]
fn brier_is_one_quarter_for_a_constant_half_forecast_on_a_coin() {
    // A constant 0.5 forecast on a 50/50 world scores exactly 0.25, with zero reliability
    // (0.5 IS the observed frequency) and zero resolution (one bucket, no discrimination).
    let mut c = Calibration::new();
    for i in 0..100 {
        c.push(0.5, i % 2 == 0, true);
    }
    let r = c.complete_report(DEFAULT_BRIER_BUCKETS).expect("non-empty");
    assert!(
        (r.brier - 0.25).abs() < 1e-12,
        "const 0.5 on a coin ⇒ 0.25, got {}",
        r.brier
    );
    assert!(
        r.reliability.abs() < 1e-12,
        "0.5 == observed freq ⇒ reliability 0"
    );
    assert!(r.resolution.abs() < 1e-12, "single bucket ⇒ no resolution");
    assert!((r.uncertainty - 0.25).abs() < 1e-12);
    assert!((r.brier - (r.reliability - r.resolution + r.uncertainty)).abs() < 1e-12);
}

#[test]
fn brier_report_is_none_for_an_empty_dataset() {
    assert!(
        Calibration::new()
            .complete_report(DEFAULT_BRIER_BUCKETS)
            .is_none()
    );
}

#[test]
fn brier_judge_excludes_incomplete_structural_zero_rows() {
    // WARN-1: the judge (complete_report) scores ONLY floor_complete rows. Incomplete rows
    // (structural-zero r_hat=0 vs a HIGH observed survival) are diagnosed separately and must
    // NOT pollute the Brier. Here: 100 perfect complete rows (Brier 0) + 50 incomplete rows
    // whose r̂=0 but survived (would wreck a naïve Brier) ⇒ the JUDGE still reads 0.
    let mut c = Calibration::new();
    for _ in 0..100 {
        c.push(1.0, true, true); // complete, perfectly forecast
    }
    for _ in 0..50 {
        c.push(0.0, true, false); // incomplete: structural zero, but the block survived
    }
    let judge = c
        .complete_report(DEFAULT_BRIER_BUCKETS)
        .expect("complete rows");
    assert_eq!(judge.n, 100, "the judge scores only the complete rows");
    assert!(
        judge.brier.abs() < 1e-12,
        "incomplete structural-zero rows must NOT enter the judge, got {}",
        judge.brier
    );
    // The pooled (overall) Brier WOULD be badly polluted — proves the exclusion matters.
    let overall = c.overall_report(DEFAULT_BRIER_BUCKETS).expect("rows");
    assert!(
        overall.brier > 0.3,
        "the overall Brier is wrecked by the structural-zero rows ({}) — why WARN-1 gates them",
        overall.brier
    );
    // The incomplete diagnostic captures them: n=50, share 1/3, f̄≈0, ō=1.
    let inc = c.incomplete_summary().expect("incomplete rows");
    assert_eq!(inc.n, 50);
    assert!((inc.share_of_total - 50.0 / 150.0).abs() < 1e-12);
    assert!(inc.mean_forecast.abs() < 1e-12, "structural-zero forecast");
    assert!((inc.observed_freq - 1.0).abs() < 1e-12, "but they survived");
}

#[test]
fn brier_buckets_partition_forecasts_at_the_right_edges() {
    // 1.0 lands in the closed top bucket; the diagram sums back to the full N.
    let mut c = Calibration::new();
    c.push(0.0, false, true);
    c.push(0.55, true, true);
    c.push(1.0, true, true);
    let r = c.complete_report(10).expect("non-empty");
    let n: usize = r.buckets.iter().map(|b| b.n).sum();
    assert_eq!(n, 3, "every prediction lands in exactly one bucket");
    assert_eq!(
        r.buckets[9].n, 1,
        "forecast 1.0 ⇒ the closed top bucket [0.9,1.0]"
    );
    assert_eq!(r.buckets[0].n, 1, "forecast 0.0 ⇒ bucket [0.0,0.1)");
    assert_eq!(r.buckets[5].n, 1, "forecast 0.55 ⇒ bucket [0.5,0.6)");
}

// ------------------------------------------------------------------
// Anti-oracle: the R̂-calibration prediction log is WRITTEN but never READ by any
// decision (enabling it leaves the world evolution bit-identical).
// ------------------------------------------------------------------

#[test]
fn pred_log_is_written_when_enabled_and_never_alters_a_decision() {
    use viaticum_core::four_r::{PlacementPolicy, SurfacePrior};

    use crate::sim_dynamic::engine::step;

    let params = DynParams::default();
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();

    // Two identical worlds (same seed); log ON in one, OFF in the other.
    let mut on = build_world(40, &params, 7);
    let mut off = build_world(40, &params, 7);
    on.pred_log_enabled = true;
    off.pred_log_enabled = false;

    for _ in 0..40 {
        step(&mut on, &params, &prior, &policy);
        step(&mut off, &params, &prior, &policy);
    }

    // The prediction log records forecasts when enabled, none when disabled.
    assert!(
        !on.pred_log.is_empty(),
        "the prediction log must be populated when enabled"
    );
    assert!(
        off.pred_log.is_empty(),
        "no prediction is logged when the channel is disabled"
    );
    // Every logged forecast is a probability.
    assert!(
        on.pred_log.iter().all(|e| (0.0..=1.0).contains(&e.r_hat)),
        "logged R̂ must be a probability in [0,1]"
    );

    // The decision fingerprint (god-view metrics: alive symbols, share A>0, evicts,
    // preempts, cap_trims, depth, σ, per-archetype durability + ROI) must be BIT-IDENTICAL:
    // the metric channel feeds back into NO decision and consumes NO RNG.
    let m_on = collect_metrics(&on, &params);
    let m_off = collect_metrics(&off, &params);
    assert!(
        metrics_bit_eq(&m_on, &m_off),
        "enabling the prediction log must not change ANY decision (bit-identical metrics)"
    );
    // And the ledger of drops/preempts matches exactly (a stronger structural check).
    assert_eq!(on.eviction_log.len(), off.eviction_log.len());
    assert_eq!(on.preempt_count, off.preempt_count);
    assert_eq!(on.cap_trim_count, off.cap_trim_count);
}

// ------------------------------------------------------------------
// phase 1: adversary machinery — injection + hooks + whitewash reset
// ------------------------------------------------------------------

/// A whale AdvSpec (×8 demand, serve 5%).
fn whale_spec(count: usize) -> AdvSpec {
    AdvSpec {
        id: AdvId::A1EpsilonWhale,
        count,
        info_model: InfoModel::Own,
        dials: AdvDials {
            whale_block_mult: 8.0,
            whale_accept: 0.05,
            ..AdvDials::default()
        },
    }
}

#[test]
fn build_world_leaves_the_adv_layer_empty_and_honest_scenarios_inject_nothing() {
    // A fresh world is all-honest (the byte-identical honest path); an honest scenario's
    // (empty) adversary list injects nothing.
    let params = DynParams::default();
    let w = build_world(30, &params, 1);
    assert!(w.adv.iter().all(|a| a.is_none()), "adv layer empty");
    assert!(w.adv_rejoin_count.iter().all(|&c| c == 0));

    let mut w2 = build_world(30, &params, 1);
    let injected = inject_adversaries(
        &mut w2,
        &honest_v2().adversaries,
        &params,
        RunMode::Predator,
    );
    assert!(injected.is_empty(), "honest_v2 has no adversaries");
    assert!(w2.adv.iter().all(|a| a.is_none()));
}

#[test]
fn inject_adversaries_is_deterministic_and_repurposes_the_last_slots() {
    let params = DynParams::default();
    let spec = whale_spec(2);
    let mut w1 = build_world(20, &params, 7);
    let mut w2 = build_world(20, &params, 7);
    let n1 = inject_adversaries(
        &mut w1,
        std::slice::from_ref(&spec),
        &params,
        RunMode::Predator,
    );
    let n2 = inject_adversaries(&mut w2, &[spec], &params, RunMode::Predator);
    assert_eq!(n1, n2, "injection is deterministic");
    assert_eq!(
        n1,
        vec![18, 19],
        "the last `count` slots become adversaries"
    );
    for &i in &n1 {
        // ×8 demand = 8·blocks_per_node(3) = 24 own blocks, present from t=0, hook installed.
        assert_eq!(w1.nodes[i].own_blocks.len(), 24, "×8 backup demand");
        assert!(w1.nodes[i].present && w1.nodes[i].joined_tick == 0);
        assert!(w1.adv[i].is_some(), "predator role installed");
    }
}

#[test]
fn twin_injection_matches_construction_and_carries_a_noop_role() {
    // WARN-1: the matched twin gets the SAME heavy nodes AND an `adv` role — but a NOOP hook
    // (no accept override, no rejoin). The role is what makes the engine treat the node as
    // hook-driven and BYPASS the random churn Bernoulli, so BOTH predator and twin are immortal
    // (no mortality confound); the only difference is the hook's BEHAVIOUR.
    let params = DynParams::default();
    let spec = whale_spec(2);
    let mut pred = build_world(20, &params, 7);
    let mut twin = build_world(20, &params, 7);
    let np = inject_adversaries(
        &mut pred,
        std::slice::from_ref(&spec),
        &params,
        RunMode::Predator,
    );
    let nt = inject_adversaries(&mut twin, &[spec], &params, RunMode::Twin);
    assert_eq!(np, nt);
    let ctx = |node: usize| AdvContext {
        adv_node: node,
        tick: 5,
        info_model: InfoModel::Own,
        dials: AdvDials {
            whale_accept: 0.05,
            ..AdvDials::default()
        },
        joined_tick: 0,
    };
    for &i in &np {
        assert_eq!(
            pred.nodes[i].own_blocks.len(),
            twin.nodes[i].own_blocks.len(),
            "matched demand"
        );
        // Both carry a role (so both bypass churn), but the twin's hook is a no-op: it serves
        // at the archetype rate (accept_rate None) and never rejoins, while the predator's
        // whale hook forces the ε serve rate.
        let pred_role = pred.adv[i].expect("predator role");
        let twin_role = twin.adv[i].expect("twin role");
        assert_eq!(
            (pred_role.hook)(&ctx(i)).accept_rate,
            Some(0.05),
            "predator serves ε"
        );
        assert_eq!(
            (twin_role.hook)(&ctx(i)).accept_rate,
            None,
            "twin serves at the archetype rate"
        );
        assert!(!(twin_role.hook)(&ctx(i)).rejoin, "twin never rejoins");
    }
}

#[test]
fn mean_over_seeds_skips_nan_and_is_nan_when_every_seed_is_empty() {
    // W1 review gate: NaN seeds (empty cohort) drop out of the mean; all-NaN → NaN.
    let stat = |v: f64| BootstrapStats {
        n_newcomers: if v.is_nan() { 0 } else { 1 },
        first_block_floor_ever: v,
        mean_time_to_first_g: v,
        mean_time_to_first_accept: v,
        frac_ever_placed: v,
        mean_first_block_parked_holders: v,
        frac_first_block_lost: v,
    };
    let mixed = [stat(1.0), stat(f64::NAN), stat(3.0)];
    assert_eq!(mean_over_seeds(&mixed, |s| s.frac_first_block_lost), 2.0);
    let all_empty = [stat(f64::NAN), stat(f64::NAN)];
    assert!(mean_over_seeds(&all_empty, |s| s.frac_first_block_lost).is_nan());
    assert!(mean_over_seeds(&[], |s: &BootstrapStats| s.frac_first_block_lost).is_nan());
}

#[test]
fn fold_cap_ratio_covers_all_nan_branches() {
    // NaN = "no sample this tick"; the fold keeps the running max otherwise.
    assert!(fold_cap_ratio(f64::NAN, f64::NAN).is_nan(), "no sample yet");
    assert_eq!(
        fold_cap_ratio(f64::NAN, 0.7),
        0.7,
        "first real sample seeds it"
    );
    assert_eq!(fold_cap_ratio(0.7, f64::NAN), 0.7, "a NaN tick is ignored");
    assert_eq!(fold_cap_ratio(0.7, 0.9), 0.9, "keeps the larger");
    assert_eq!(
        fold_cap_ratio(0.9, 0.7),
        0.9,
        "keeps the larger (other order)"
    );
}

#[test]
fn a1_hook_serves_epsilon_and_never_rejoins() {
    let ctx = AdvContext {
        adv_node: 5,
        tick: 9,
        info_model: InfoModel::Own,
        dials: AdvDials {
            whale_accept: 0.05,
            ..AdvDials::default()
        },
        joined_tick: 0,
    };
    let a = a1_epsilon_whale_hook(&ctx);
    assert_eq!(a.accept_rate, Some(0.05), "ε-give serve rate");
    assert!(!a.rejoin, "a whale never burns its identity");
}

#[test]
fn a4_hook_rejoins_once_per_period_measured_from_the_current_join() {
    let dials = AdvDials {
        period_ticks: 20,
        ..AdvDials::default()
    };
    let mk = |tick: u64, joined: u64| AdvContext {
        adv_node: 5,
        tick,
        info_model: InfoModel::Own,
        dials,
        joined_tick: joined,
    };
    assert!(
        !a4_whitewasher_hook(&mk(0, 0)).rejoin,
        "not on the join tick"
    );
    assert!(!a4_whitewasher_hook(&mk(19, 0)).rejoin);
    assert!(a4_whitewasher_hook(&mk(20, 0)).rejoin, "one period elapsed");
    assert!(!a4_whitewasher_hook(&mk(21, 0)).rejoin);
    // After a burn the join tick moves forward, so the cadence resets from there.
    assert!(!a4_whitewasher_hook(&mk(40, 21)).rejoin);
    assert!(
        a4_whitewasher_hook(&mk(41, 21)).rejoin,
        "one period after re-join"
    );
    // The whitewasher serves at its archetype rate between burns (no accept override).
    assert_eq!(a4_whitewasher_hook(&mk(41, 21)).accept_rate, None);
}

#[test]
fn whitewash_rejoin_wipes_capital_own_data_and_reschedules_the_join() {
    let params = DynParams::default();
    let mut w = build_world(10, &params, 3);
    let node = 4usize;
    // Give the node capital both ways, a foreign holding it stores, and one of its own
    // symbols placed on a holder.
    w.capital[node][2].g_ho = 5.0;
    w.capital[node][2].depth_ho = 3.0;
    w.capital[7][node].g_oh = 9.0; // holder 7's record of node-as-holder
    w.nodes[node].holdings.push(HeldSymbol {
        owner: 1,
        block: 0,
        iota: 0.5,
        volume: 10.0,
        alive: true,
        cream: false,
    });
    w.nodes[6].holdings.push(HeldSymbol {
        owner: node,
        block: 0,
        iota: 0.5,
        volume: 10.0,
        alive: true,
        cream: false,
    });
    let old_first_block = w.nodes[node].own_blocks[0].id;

    whitewash_rejoin_for_test(&mut w, node, 30, &params);

    // Mutual amnesia: the node's capital ROW and COLUMN are wiped.
    assert_eq!(w.capital[node][2].g_ho, 0.0);
    assert_eq!(w.capital[node][2].depth_ho, 0.0);
    assert_eq!(w.capital[7][node].g_oh, 0.0, "counterparties forget it");
    // It abandoned others' data, and its own backed-up data is orphaned.
    assert!(w.nodes[node].holdings.iter().all(|s| !s.alive));
    assert!(
        w.nodes[6].holdings.iter().all(|s| !s.alive),
        "own data on a holder is orphaned"
    );
    // Fresh own blocks (new ids, un-placed) — a brand-new backup demand.
    assert_ne!(w.nodes[node].own_blocks[0].id, old_first_block);
    assert!(
        w.nodes[node]
            .own_blocks
            .iter()
            .all(|b| !b.floor_ever_met && b.placements.is_empty() && !b.to_restore)
    );
    // Re-joins next tick with the fresh identity.
    assert!(!w.nodes[node].present);
    assert_eq!(w.nodes[node].joined_tick, 31);
    assert_eq!(w.adv_rejoin_count[node], 1);
}

// ------------------------------------------------------------------
// phase 1: A1 ε-whale + A4 whitewasher — the invariants (spec §3/§4)
// ------------------------------------------------------------------

/// Mean of a per-seed adversary quantity over the adversary pairs (predator side or twin).
fn adv_mean(
    result: &crate::sim_adv::RunResult,
    twin: bool,
    f: impl Fn(&crate::sim_adv::AdvMetrics) -> f64,
) -> f64 {
    let vals: Vec<f64> = result
        .per_seed_adv
        .iter()
        .flatten()
        .map(|p| if twin { f(&p.twin) } else { f(&p.pred) })
        .collect();
    vals.iter().sum::<f64>() / vals.len() as f64
}

#[test]
fn a1_whale_parked_volume_is_capped_and_protects_less_than_the_honest_twin() {
    // Р-7 (P1b): where the cap engages, the ε-whale's SETTLED parked volume is bounded by
    // V_ret + one chunk (ratio ≤ 1) on EVERY seed; and its protected-storage integral sits
    // below its matched honest twin (same ×8 demand, serving fully). Three seeds keep it
    // quick while still exercising the full pred+twin comparison.
    let mut sc = a1_whale();
    sc.seeds = vec![42, 43, 44];
    let result = run(&sc, &sc.seeds.clone());

    let mut cap_engaged = false;
    for p in result.per_seed_adv.iter().flatten() {
        if !p.pred.max_cap_ratio.is_nan() {
            cap_engaged = true;
            assert!(
                p.pred.max_cap_ratio <= 1.0,
                "the Р-7 cap must bind the whale where it engages: ratio {}",
                p.pred.max_cap_ratio
            );
        }
    }
    assert!(cap_engaged, "the Р-7 cap must engage on ≥1 seed");
    let pred = adv_mean(&result, false, |a| a.consumed);
    let twin = adv_mean(&result, true, |a| a.consumed);
    assert!(
        pred < twin,
        "ε-whale protects less than its honest twin: {pred} < {twin}"
    );
}

#[test]
fn a4_whitewasher_reenters_capped_at_v_free_and_delivers_less_than_the_twin() {
    // A4: the whitewasher actually re-enters (rejoins > 0); its re-entered identity is bounded
    // by the freshly-earned V_ret (cap ratio ≤ 1, κ_O reset each cycle — the Sybil price); and
    // its total delivered park sits below the continuous honest twin.
    let mut sc = a4_whitewasher();
    sc.seeds = vec![42, 43, 44];
    let result = run(&sc, &sc.seeds.clone());

    for p in result.per_seed_adv.iter().flatten() {
        assert!(p.pred.rejoins > 0, "the whitewasher must actually re-enter");
        if !p.pred.max_cap_ratio.is_nan() {
            assert!(
                p.pred.max_cap_ratio <= 1.0,
                "re-entered identity bounded by V_ret: ratio {}",
                p.pred.max_cap_ratio
            );
        }
    }
    let pred = adv_mean(&result, false, |a| a.consumed);
    let twin = adv_mean(&result, true, |a| a.consumed);
    assert!(
        pred < twin,
        "whitewash delivers less park than the honest twin: {pred} < {twin}"
    );
}

#[test]
fn a1_whale_board_passes_every_row() {
    // The acceptance board (spec §3): the two structural rows + INV-P1B-CAP + INV-ROI-PRED≤TWIN
    // all PASS on the frozen 5-seed run (deterministic — power gate is exact, not flaky).
    let sc = a1_whale();
    let result = run(&sc, &sc.seeds.clone());
    let verdicts = evaluate_board(&sc, &result);
    let ids: Vec<&str> = verdicts.iter().map(|v| v.id).collect();
    assert_eq!(
        ids,
        vec![
            "INV-DETERMINISM",
            "INV-ANTI-ORACLE",
            "INV-P1B-CAP",
            "INV-ROI-PRED≤TWIN",
            "INV-ROI-RAW≤TWIN"
        ]
    );
    for v in &verdicts {
        assert_eq!(
            v.kind,
            VerdictKind::Pass,
            "{} must PASS (effect {}, power {})",
            v.id,
            v.effect,
            v.power
        );
    }
}

#[test]
fn a4_whitewasher_board_passes_every_row() {
    let sc = a4_whitewasher();
    let result = run(&sc, &sc.seeds.clone());
    let verdicts = evaluate_board(&sc, &result);
    let ids: Vec<&str> = verdicts.iter().map(|v| v.id).collect();
    assert_eq!(
        ids,
        vec![
            "INV-DETERMINISM",
            "INV-ANTI-ORACLE",
            "INV-P2-REENTRY",
            "INV-ROI-PRED≤TWIN",
            "INV-ROI-RAW≤TWIN"
        ]
    );
    for v in &verdicts {
        assert_eq!(
            v.kind,
            VerdictKind::Pass,
            "{} must PASS (effect {}, power {})",
            v.id,
            v.effect,
            v.power
        );
    }
}

#[test]
fn adv_run_is_bit_identical_on_repeat() {
    // Determinism (spec §10 п.13): the whole predator + twin + Attack-ROI path is seeded, so a
    // DR-free adversary scenario re-runs bit-identical per seed.
    let mut sc = a1_whale();
    sc.seeds = vec![42, 43];
    let seeds = sc.seeds.clone();
    let r1 = run(&sc, &seeds);
    let r2 = run(&sc, &seeds);
    assert!(r1.per_seed_adv.iter().all(|p| p.is_some()));
    for (a, b) in r1.per_seed_adv.iter().zip(&r2.per_seed_adv) {
        match (a, b) {
            (Some(x), Some(y)) => assert!(
                adv_bit_eq(&x.pred, &y.pred) && adv_bit_eq(&x.twin, &y.twin),
                "Attack-ROI must be bit-identical on repeat"
            ),
            (None, None) => {}
            _ => panic!("adv presence differs between runs"),
        }
    }
    for (a, b) in r1.per_seed.iter().zip(&r2.per_seed) {
        assert!(
            metrics_bit_eq(a, b),
            "god-view metrics bit-identical on repeat"
        );
    }
}

// ------------------------------------------------------------------
// hetero-v2 (D1): per-owner demand classes = the NUMBER of equal blocks
// ------------------------------------------------------------------

/// A shrunk `honest_hetero_v2` (small world, short horizon) for the fast unit tests.
fn tiny_hetero() -> Scenario {
    let mut sc = honest_hetero_v2();
    sc.world.n_nodes = 40;
    sc.horizon = 90;
    sc.seeds = vec![1, 2];
    sc
}

#[test]
fn demand_class_n_blocks_maps_the_three_footprints() {
    // S=1, L=10 are absolute; M ties to blocks_per_node so an M owner is byte-identical to
    // build_world for any default (the spec's S=1/M=3/L=10 holds at the default bpn=3).
    assert_eq!(DemandClass::S.n_blocks(3), 1);
    assert_eq!(DemandClass::M.n_blocks(3), 3);
    assert_eq!(DemandClass::L.n_blocks(3), 10);
    assert_eq!(DemandClass::M.n_blocks(5), 5, "M tracks blocks_per_node");
}

#[test]
fn demand_mix_assignment_is_deterministic_and_hits_the_shares() {
    let mix = DemandMix::Classes(
        vec![
            (DemandClass::S, 0.60),
            (DemandClass::M, 0.30),
            (DemandClass::L, 0.10),
        ],
        DiskPolicy::Grow,
    );
    let a = mix.assign(100, 42);
    let b = mix.assign(100, 42);
    assert_eq!(a, b, "assignment is deterministic in the seed");
    let count = |c: DemandClass| a.iter().filter(|&&x| x == c).count();
    assert_eq!(count(DemandClass::S), 60);
    assert_eq!(count(DemandClass::M), 30);
    assert_eq!(count(DemandClass::L), 10);
    // A different seed PERMUTES which node is which class (independent of index/archetype).
    let c = mix.assign(100, 43);
    assert_ne!(a, c, "a different seed permutes the assignment");
}

#[test]
fn uniform_demand_apply_leaves_the_world_bit_identical_to_build_world() {
    // The byte-identity guarantee (the honest-anchor freeze): applying an all-M assignment
    // reproduces build_world EXACTLY — own_blocks id/volume/ι, next_block_id, and the disk
    // fields (source_scale = 1.0). This is what keeps honest_v2 seed-42 frozen.
    let params = DynParams::default();
    let base = build_world(30, &params, 7);
    let mut applied = build_world(30, &params, 7);
    apply_demand_classes(
        &mut applied,
        &[DemandClass::M; 30],
        &params,
        DiskPolicy::Grow,
    );
    for i in 0..base.nodes.len() {
        assert_eq!(
            base.nodes[i].own_blocks.len(),
            applied.nodes[i].own_blocks.len()
        );
        for (a, b) in base.nodes[i]
            .own_blocks
            .iter()
            .zip(&applied.nodes[i].own_blocks)
        {
            assert_eq!(a.id, b.id);
            assert_eq!(a.volume.to_bits(), b.volume.to_bits());
            assert_eq!(a.iota.to_bits(), b.iota.to_bits());
        }
        assert_eq!(
            base.nodes[i].disk_cap.to_bits(),
            applied.nodes[i].disk_cap.to_bits(),
            "M disk_cap unchanged (×1.0)"
        );
        assert_eq!(
            base.nodes[i].disk.own_data.to_bits(),
            applied.nodes[i].disk.own_data.to_bits()
        );
        assert_eq!(base.next_block_id[i], applied.next_block_id[i]);
    }
}

#[test]
fn apply_demand_classes_sets_footprint_and_grows_only_the_l_disk() {
    let params = DynParams::default();
    let mut world = build_world(6, &params, 3);
    let base_cap: Vec<f64> = world.nodes.iter().map(|n| n.disk_cap).collect();
    let base_own: Vec<f64> = world.nodes.iter().map(|n| n.disk.own_data).collect();
    let classes = vec![
        DemandClass::S,
        DemandClass::M,
        DemandClass::L,
        DemandClass::S,
        DemandClass::M,
        DemandClass::L,
    ];
    apply_demand_classes(&mut world, &classes, &params, DiskPolicy::Grow);
    for (i, &c) in classes.iter().enumerate() {
        let want = c.n_blocks(params.blocks_per_node);
        assert_eq!(
            world.nodes[i].own_blocks.len(),
            want,
            "footprint = n_blocks"
        );
        assert_eq!(world.next_block_id[i], want);
    }
    // The disk CAP only GROWS: L up, S and M unchanged (never shrink the majority's device).
    assert!(
        world.nodes[2].disk_cap > base_cap[2],
        "L disk cap scaled up"
    );
    assert_eq!(
        world.nodes[0].disk_cap.to_bits(),
        base_cap[0].to_bits(),
        "S disk cap unchanged (a small source is not a small device)"
    );
    assert_eq!(
        world.nodes[1].disk_cap.to_bits(),
        base_cap[1].to_bits(),
        "M disk cap unchanged"
    );
    // own-data (the source on disk) tracks the footprint: L bigger, S smaller, M unchanged.
    assert!(world.nodes[2].disk.own_data > base_own[2], "L source grows");
    assert!(
        world.nodes[0].disk.own_data < base_own[0],
        "S source shrinks"
    );
    assert_eq!(
        world.nodes[1].disk.own_data.to_bits(),
        base_own[1].to_bits(),
        "M source unchanged"
    );
}

#[test]
fn apply_demand_classes_fixed_keeps_the_device_and_truncates_an_overflowing_source() {
    // WARN-2 HARD regime: DiskPolicy::Fixed keeps the device cap at build_world size for every
    // class, and own-data still scales with the source — TRUNCATED at the cap when it overflows
    // (the "full device" physics: free disk floors at 0). L's ×10/3 source on a fixed disk either
    // fills more of the disk or is clamped to it; the cap itself never moves.
    let params = DynParams::default();
    let mut world = build_world(30, &params, 9);
    let base_cap: Vec<f64> = world.nodes.iter().map(|n| n.disk_cap).collect();
    let mix = DemandMix::Classes(
        vec![(DemandClass::S, 0.4), (DemandClass::L, 0.6)],
        DiskPolicy::Fixed,
    );
    let classes = mix.assign(30, 9);
    apply_demand_classes(&mut world, &classes, &params, DiskPolicy::Fixed);
    for (i, node) in world.nodes.iter().enumerate() {
        // Device cap is UNCHANGED for every class in the hard regime.
        assert_eq!(
            node.disk_cap.to_bits(),
            base_cap[i].to_bits(),
            "hard regime never moves the device cap"
        );
        // own-data never exceeds the device (source truncated at the cap — no negative free disk).
        assert!(
            node.disk.own_data <= node.disk_cap,
            "source is truncated at the device cap"
        );
        assert!(node.free_disk() >= 0.0, "free disk floors at 0");
    }
    // At least one L owner's source overflowed a tight-tier device (truncation actually engaged),
    // OR every L simply grew within a loose device — either way the cap is fixed and free ≥ 0.
    let some_l_full = classes
        .iter()
        .enumerate()
        .any(|(i, &c)| c == DemandClass::L && world.nodes[i].free_disk() < 1.0);
    // Not asserted as mandatory (depends on the tier draw), but exercises the truncation path.
    let _ = some_l_full;
}

#[test]
fn demand_class_labels_are_the_three_letters() {
    // NOTE-4: the class labels used across the report / CSV.
    assert_eq!(DemandClass::S.label(), "S");
    assert_eq!(DemandClass::M.label(), "M");
    assert_eq!(DemandClass::L.label(), "L");
    assert_eq!(DemandClass::ALL.len(), 3);
}

#[test]
fn restore_per_class_accessors_slice_blocks_by_demand_class() {
    // NOTE-4: restore_{u,s,o}_in_class + n_blocks_in_class slice a RestoreTruth by demand class.
    let mk = |class: DemandClass, u: bool, s: bool, o: bool| BlockOutcome {
        owner: 0,
        block_id: 0,
        iota: 0.5,
        tier: GiverTier::T1,
        class,
        n_collectable_any: 0,
        n_collectable_floor: 0,
        n_collectable_oneshot: 0,
        restorable_u: u,
        restorable_s: s,
        restorable_o: o,
        restorable_floor: false,
    };
    // L: 2 blocks (1 restorable U, 0 S, 2 O); M: 1 block (restorable all); S: none.
    let rt = restore_truth_with_blocks(vec![
        mk(DemandClass::L, true, false, true),
        mk(DemandClass::L, false, false, true),
        mk(DemandClass::M, true, true, true),
    ]);
    assert_eq!(rt.n_blocks_in_class(DemandClass::L), 2);
    assert_eq!(rt.n_blocks_in_class(DemandClass::M), 1);
    assert_eq!(rt.n_blocks_in_class(DemandClass::S), 0);
    assert!(
        (rt.restore_u_in_class(DemandClass::L) - 0.5).abs() < 1e-9,
        "1 of 2 L restorable U"
    );
    assert_eq!(
        rt.restore_s_in_class(DemandClass::L),
        0.0,
        "no L restorable S"
    );
    assert_eq!(
        rt.restore_o_in_class(DemandClass::L),
        1.0,
        "both L restorable O"
    );
    assert_eq!(rt.restore_u_in_class(DemandClass::M), 1.0);
    assert!(
        rt.restore_u_in_class(DemandClass::S).is_nan(),
        "an empty class is NaN, not 0"
    );
}

#[test]
fn honest_hetero_hard_is_registered_and_carries_the_hard_board_row() {
    // WARN-2: the hard regime is a registered scenario with INV-HETERO-HARD (same measure +
    // frozen threshold as the light row). Structural rows PASS; the hard row's PASS/FAIL is the
    // credit-lock finding (validated on the full run).
    let s = find_scenario("honest_hetero_hard").expect("registered");
    assert_eq!(s.id.as_str(), "honest_hetero_hard");
    assert_eq!(s.world.demand.disk_policy(), DiskPolicy::Fixed);
    let mut sc = s;
    sc.world.n_nodes = 40;
    sc.horizon = 90;
    sc.seeds = vec![1, 2];
    let result = run(&sc, &sc.seeds.clone());
    assert!(result.per_seed_hetero.iter().all(|h| h.is_some()));
    let verdicts = evaluate_board(&sc, &result);
    let ids: Vec<&str> = verdicts.iter().map(|v| v.id).collect();
    assert_eq!(
        ids,
        vec!["INV-DETERMINISM", "INV-ANTI-ORACLE", "INV-HETERO-HARD"]
    );
    assert_eq!(verdicts[0].kind, VerdictKind::Pass, "determinism");
    assert_eq!(verdicts[1].kind, VerdictKind::Pass, "anti-oracle");
}

#[test]
fn honest_hetero_v2_is_registered_and_produces_a_per_class_report() {
    let s = find_scenario("honest_hetero_v2").expect("registered");
    assert_eq!(s.id.as_str(), "honest_hetero_v2");
    let sc = tiny_hetero();
    let result = run(&sc, &sc.seeds.clone());
    assert!(
        result.per_seed_hetero.iter().all(|h| h.is_some()),
        "every seed carries a hetero report"
    );
    let h = result.per_seed_hetero[0].as_ref().unwrap();
    assert_eq!(h.n_blocks, [1, 3, 10], "S/M/L footprint sizes");
    assert!(
        h.class[DemandClass::L.index()].n_owners_present > 0,
        "there are L-class owners"
    );
    // The big footprint is NOT locked at zero placement (the archive-0% artifact must not
    // recur): SOME of the L footprint reaches floor.
    assert!(
        h.class[DemandClass::L.index()].floor_completeness > 0.0,
        "L footprint places (not the archive-0% artifact): {}",
        h.class[DemandClass::L.index()].floor_completeness
    );
}

#[test]
fn hetero_report_is_bit_identical_on_repeat() {
    // Determinism (spec §10 п.13): the seeded class assignment + god-view placement metrics
    // re-run bit-identical.
    let sc = tiny_hetero();
    let seeds = sc.seeds.clone();
    let r1 = run(&sc, &seeds);
    let r2 = run(&sc, &seeds);
    for (a, b) in r1.per_seed_hetero.iter().zip(&r2.per_seed_hetero) {
        match (a, b) {
            (Some(x), Some(y)) => {
                assert!(hetero_bit_eq(x, y), "hetero report bit-identical on repeat")
            }
            (None, None) => {}
            _ => panic!("hetero presence differs between runs"),
        }
    }
}

#[test]
fn honest_hetero_v2_board_carries_the_no_starvation_row() {
    // The board carries the two structural rows + INV-HETERO-NO-STARVATION; the structural
    // rows PASS (the no-starvation row's PASS/FAIL is the finding, validated on the full run).
    let sc = tiny_hetero();
    let result = run(&sc, &sc.seeds.clone());
    let verdicts = evaluate_board(&sc, &result);
    let ids: Vec<&str> = verdicts.iter().map(|v| v.id).collect();
    assert_eq!(
        ids,
        vec![
            "INV-DETERMINISM",
            "INV-ANTI-ORACLE",
            "INV-HETERO-NO-STARVATION"
        ]
    );
    assert_eq!(verdicts[0].kind, VerdictKind::Pass, "determinism");
    assert_eq!(verdicts[1].kind, VerdictKind::Pass, "anti-oracle");
}

#[test]
fn hetero_report_text_is_byte_identical_on_repeat() {
    let sc = tiny_hetero();
    let seeds = sc.seeds.clone();
    let r1 = run(&sc, &seeds);
    let t1 = format_report(&sc, &r1, &evaluate_board(&sc, &r1));
    let r2 = run(&sc, &seeds);
    let t2 = format_report(&sc, &r2, &evaluate_board(&sc, &r2));
    assert_eq!(t1, t2, "hetero report must be byte-identical on repeat");
    assert!(
        t1.contains("hetero-v2 (D1)"),
        "the report renders the hetero section"
    );
}

#[test]
fn dr_hetero_splits_restore_truth_by_demand_class() {
    // dr_hetero strikes one reliable S/M/L victim at the same tick, so restore-truth carries
    // blocks from more than one demand class — the per-class DR cut.
    let mut sc = dr_hetero();
    sc.world.n_nodes = 60;
    sc.horizon = 150;
    sc.seeds = vec![42, 43];
    let result = run(&sc, &sc.seeds.clone());
    let rt = result
        .per_seed_restore
        .iter()
        .flatten()
        .next()
        .expect("dr_hetero produces restore-truth");
    let classes: std::collections::BTreeSet<DemandClass> =
        rt.blocks.iter().map(|b| b.class).collect();
    assert!(
        classes.len() > 1,
        "the S/M/L victims give a per-class split, got {classes:?}"
    );
}

// ------------------------------------------------------------------
// Р-9 V_free sweep — bootstrap-focus: a NEWCOMER's onboarding under contention
// (the key missing measurement the V_free dial is meant to serve)
// ------------------------------------------------------------------

/// A minimal own block with a chosen `floor_ever_met` (the newcomer's first-backup flag).
fn own_first(id: usize, floor_ever_met: bool) -> OwnBlock {
    OwnBlock {
        id,
        volume: 50.0,
        iota: 0.5,
        placements: Vec::new(),
        floor_ever_met,
        floor_deficit_since: None,
        to_restore: false,
    }
}

/// A hand-built world exercising the bootstrap cohort selector: three LATE cooperative
/// newcomers (Reliable / Weekend / Nomad), one LATE Hoarder (parasite — excluded), and two
/// early holders (joined at 0 — not newcomers). Their first blocks / entry gaps / held
/// holders are set by hand so the evaluator's arithmetic is checkable.
fn bootstrap_controlled_world() -> World {
    let params = DynParams::default();
    let mut w = build_world(6, &params, 7);
    for nd in &mut w.nodes {
        nd.present = true;
        nd.holdings.clear();
    }
    // node 0: early Reliable holder (joined 0 ⇒ NOT a newcomer).
    w.nodes[0].joined_tick = 0;
    w.nodes[0].archetype = Archetype::Reliable;
    // node 1: LATE Reliable newcomer whose first block met floor + is held once.
    w.nodes[1].joined_tick = 20;
    w.nodes[1].archetype = Archetype::Reliable;
    w.nodes[1].own_blocks = vec![own_first(0, true)];
    w.first_earned_g[1] = Some(25); // gap 5
    w.first_own_accept[1] = Some(28); // gap 8
    // node 2: LATE Weekend newcomer that NEVER placed (first block never met floor, 0 holders).
    w.nodes[2].joined_tick = 15;
    w.nodes[2].archetype = Archetype::Weekend;
    w.nodes[2].own_blocks = vec![own_first(0, false)];
    w.first_earned_g[2] = None;
    w.first_own_accept[2] = None;
    // node 3: LATE Hoarder ⇒ EXCLUDED from the cohort (a parasite, not the newcomer V_free serves).
    w.nodes[3].joined_tick = 30;
    w.nodes[3].archetype = Archetype::Hoarder;
    // node 4: LATE Nomad newcomer, first block floor-met + held by TWO holders.
    w.nodes[4].joined_tick = 12;
    w.nodes[4].archetype = Archetype::Nomad;
    w.nodes[4].own_blocks = vec![own_first(0, true)];
    w.first_earned_g[4] = Some(20); // gap 8
    w.first_own_accept[4] = Some(18); // gap 6
    // node 5: another early holder (joined 0 ⇒ not a newcomer).
    w.nodes[5].joined_tick = 0;
    w.nodes[5].archetype = Archetype::Reliable;
    // Holdings: node1.block0 on holder 5; node4.block0 on holders 5 AND 0 (two distinct holders).
    push_held(&mut w, 5, 1, 0, 0.5, false);
    push_held(&mut w, 5, 4, 0, 0.5, false);
    push_held(&mut w, 0, 4, 0, 0.5, false);
    w
}

#[test]
fn bootstrap_evaluator_reads_the_late_cohort_first_block_and_entry_gaps() {
    // The god-view evaluator selects only LATE cooperative newcomers and reads their first
    // block's floor-ever + parked holders + entry gaps from the engine's own trace.
    let w = bootstrap_controlled_world();
    let b = collect_bootstrap(&w, 10);
    assert_eq!(
        b.n_newcomers, 3,
        "3 late cooperative newcomers (Hoarder excluded)"
    );
    assert!(
        (b.first_block_floor_ever - 2.0 / 3.0).abs() < 1e-9,
        "2 of 3 first blocks ever met floor: {}",
        b.first_block_floor_ever
    );
    assert!(
        (b.mean_time_to_first_g - 6.5).abs() < 1e-9,
        "mean earn gap = (5+8)/2: {}",
        b.mean_time_to_first_g
    );
    assert!(
        (b.mean_time_to_first_accept - 7.0).abs() < 1e-9,
        "mean accept gap = (8+6)/2: {}",
        b.mean_time_to_first_accept
    );
    assert!(
        (b.frac_ever_placed - 2.0 / 3.0).abs() < 1e-9,
        "2 of 3 ever placed: {}",
        b.frac_ever_placed
    );
    assert!(
        (b.mean_first_block_parked_holders - 1.0).abs() < 1e-9,
        "parked holders (1 + 0 + 2)/3 = 1.0: {}",
        b.mean_first_block_parked_holders
    );
    assert!(
        (b.frac_first_block_lost - 1.0 / 3.0).abs() < 1e-9,
        "1 of 3 first blocks has 0 holders: {}",
        b.frac_first_block_lost
    );
}

#[test]
fn bootstrap_evaluator_is_empty_when_no_late_newcomer_is_present() {
    // No node joined at/after the threshold ⇒ empty cohort (rates NaN, not 0).
    let mut w = bootstrap_controlled_world();
    for nd in &mut w.nodes {
        nd.joined_tick = 0;
    }
    let b = collect_bootstrap(&w, 10);
    assert_eq!(b.n_newcomers, 0);
    assert!(b.first_block_floor_ever.is_nan());
    assert!(b.frac_first_block_lost.is_nan());
}

#[test]
fn bootstrap_run_is_deterministic_and_finds_late_newcomers() {
    // A small honest run: the late cohort exists and the read is bit-identical on repeat
    // (the whole path is seeded). Kept small so it belongs in the gate.
    let params = DynParams::default();
    let a = run_bootstrap(&params, 50, 80, 7, 30);
    let b = run_bootstrap(&params, 50, 80, 7, 30);
    assert_eq!(a, b, "bootstrap read is deterministic on repeat");
    assert!(
        a.n_newcomers > 0,
        "the incremental world produces late newcomers"
    );
    assert!(
        a.frac_first_block_lost.is_finite() && a.first_block_floor_ever.is_finite(),
        "the cohort is non-empty ⇒ finite rates"
    );
}

/// The bootstrap 2×2: newcomer onboarding in a FREE (abundant-disk) vs TIGHT (default,
/// contended) world × V_free ∈ {0, 2}, over 5 seeds. IGNORED (heavy: 4 configs × 5 seeds ×
/// full honest world). Run explicitly for the tranche report:
///   `cargo test -p viaticum-sim sim_adv bootstrap_newcomer_onboarding_free_vs_tight_table \
///    -- --ignored --nocapture --test-threads=1`
#[test]
#[ignore]
fn bootstrap_newcomer_onboarding_free_vs_tight_table() {
    let seeds = [42u64, 43, 44, 45, 46];
    let n = 100usize;
    let horizon = 130u64;
    let threshold = 40u64; // "late": joined into the already-established (join done ~tick 65) world.

    let base = DynParams::default();
    // FREE = abundant disk (no contention: holders never fill ⇒ V_free is moot).
    let free = |v_free: f64| DynParams {
        v_free_symbols: v_free,
        disk_cap_base: 600.0,
        disk_cap_spread: 0.0,
        ..base
    };
    // TIGHT = the default contended honest world.
    let tight = |v_free: f64| DynParams {
        v_free_symbols: v_free,
        ..base
    };

    let agg = |p: &DynParams| -> Vec<BootstrapStats> {
        seeds
            .iter()
            .map(|&s| run_bootstrap(p, n, horizon, s, threshold))
            .collect()
    };

    println!(
        "\n=== BOOTSTRAP 2×2: newcomer onboarding (mean over 5 seeds; late cohort joined_tick>=40) ==="
    );
    println!(
        "  {:<14} {:>8} {:>12} {:>12} {:>12} {:>12} {:>12}",
        "world/v_free", "n_new", "floor_ever", "lost@hzn", "parked_hld", "t_first_g", "t_accept",
    );
    for (label, mk) in [
        ("FREE", &free as &dyn Fn(f64) -> DynParams),
        ("TIGHT", &tight as &dyn Fn(f64) -> DynParams),
    ] {
        for v_free in [0.0f64, 2.0] {
            let stats = agg(&mk(v_free));
            println!(
                "  {:<14} {:>8.1} {:>12.4} {:>12.4} {:>12.4} {:>12.3} {:>12.3}",
                format!("{label}/{v_free:.0}"),
                mean_over_seeds(&stats, |b| b.n_newcomers as f64),
                mean_over_seeds(&stats, |b| b.first_block_floor_ever),
                mean_over_seeds(&stats, |b| b.frac_first_block_lost),
                mean_over_seeds(&stats, |b| b.mean_first_block_parked_holders),
                mean_over_seeds(&stats, |b| b.mean_time_to_first_g),
                mean_over_seeds(&stats, |b| b.mean_time_to_first_accept),
            );
        }
    }
    println!(
        "  (floor_ever = frac first blocks that EVER met floor; lost@hzn = frac with 0 live floor holders at horizon)"
    );
}

/// The full scenario × V_free ∈ {0,1,2} sweep, printing each point's whole `format_report`
/// (god-view + Attack-ROI + restore-truth + hetero per-class + board). IGNORED (heavy — the
/// report data source). Run explicitly for the tranche report:
///   `cargo test -p viaticum-sim sim_adv v_free_sweep_full_report_tables \
///    -- --ignored --nocapture --test-threads=1`
#[test]
#[ignore]
fn v_free_sweep_full_report_tables() {
    let values = [0.0f64, 1.0, 2.0];
    let scenarios = [
        honest_v2(),
        dr_baseline(),
        a1_whale(),
        a4_whitewasher(),
        honest_hetero_v2(),
        honest_hetero_hard(),
    ];
    for sc in scenarios {
        let seeds = sc.seeds.clone();
        let rows = run_sweep(&sc, "v_free_symbols", &values, &seeds).expect("known dial");
        for row in &rows {
            println!(
                "\n########## scenario '{}'  v_free_symbols = {} ##########",
                sc.id, row.value
            );
            // The board's determinism re-run rebuilds from the scenario's OWN params, so it
            // must carry the SAME dial value `row.result` was computed at (else the re-run
            // diverges and INV-DETERMINISM false-FAILs). Apply the dial to a clone first.
            let mut scv = sc.clone();
            apply_dial(&mut scv.world.base, "v_free_symbols", row.value).expect("known dial");
            let verdicts = evaluate_board(&scv, &row.result);
            print!("{}", format_report(&scv, &row.result, &verdicts));
        }
    }
}

/// Mean cap-trims over `seeds` for `honest_v2` at a chosen V_free.
fn honest_v2_cap_trims_at(v_free: f64, seeds: &[u64]) -> f64 {
    let mut sc = honest_v2();
    sc.seeds = seeds.to_vec();
    sc.world.base.v_free_symbols = v_free;
    let r = run(&sc, seeds);
    r.per_seed.iter().map(|m| m.cap_trims as f64).sum::<f64>() / seeds.len() as f64
}

#[test]
fn cap_trims_dwarf_the_v_free_two_baseline_when_v_free_is_zero() {
    // Р-9 god-view sign (the clean monotone one): at V_free=0 the retention tariff
    // V_ret = κ_O/c_recip bites ALL parked volume above earned reciprocity, so holder cap-trims
    // explode; at V_free=2 the 2-symbol free floor absorbs almost all of it (barely any trims).
    // 5-seed measured means: 147 (V_free=0) vs 2.6 (V_free=2). Here on 3 seeds with a wide margin.
    let seeds = [42u64, 43, 44];
    let trims_0 = honest_v2_cap_trims_at(0.0, &seeds);
    let trims_2 = honest_v2_cap_trims_at(2.0, &seeds);
    assert!(
        trims_0 > 5.0 * trims_2.max(1.0),
        "V_free=0 cap-trims ({trims_0}) must dwarf the V_free=2 baseline ({trims_2})"
    );
}

#[test]
fn both_predators_still_lose_to_their_twin_when_v_free_is_zero() {
    // Р-9 core claim: V_free is NOT load-bearing for DEFENCE. At V_free=0 both the ε-give whale
    // (A1) and the whitewasher (A4) STILL protect strictly less own storage than their MATCHED
    // honest twin (pred consumed < twin consumed) — removing the free floor never lets a predator
    // win. (Nuance for the report, NOT asserted: the whitewasher loses HARDER at 0 while the
    // ε-whale is v_free-insensitive — but "predator < twin" holds robustly at every V_free.)
    let seeds = [42u64, 43, 44];
    for mut sc in [a1_whale(), a4_whitewasher()] {
        let id = sc.id;
        sc.seeds = seeds.to_vec();
        sc.world.base.v_free_symbols = 0.0;
        let r = run(&sc, &seeds);
        let pred: f64 = r
            .per_seed_adv
            .iter()
            .flatten()
            .map(|p| p.pred.consumed)
            .sum();
        let twin: f64 = r
            .per_seed_adv
            .iter()
            .flatten()
            .map(|p| p.twin.consumed)
            .sum();
        assert!(
            pred < twin,
            "{id}: predator must protect less than its twin even at V_free=0: {pred} < {twin}"
        );
    }
}
