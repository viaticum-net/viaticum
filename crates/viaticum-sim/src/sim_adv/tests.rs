//! Unit tests for the `sim_adv` skeleton (sub-tranche 0.1). `what_when_then` naming.

use crate::sim_adv::cli::{apply_dial, parse_cli, resolve_seeds};
use crate::sim_adv::metrics::mean_sigma;
use crate::sim_adv::registry::{all_scenarios, find_scenario, honest_v2};
use crate::sim_adv::report::{format_report, format_sweep, run_result_csv, sweep_csv};
use crate::sim_adv::runner::{run, run_one_seed, run_sweep};
use crate::sim_adv::scenario::{
    AdvAction, AdvContext, AdvDials, AdvId, AdvSpec, BehaviorHook, Event, EventKind, InfoModel,
    MetricId, NodeSel, Scenario, WorldParams,
};
use crate::sim_adv::verdict::{Direction, VerdictKind, decide, evaluate_board};
use crate::sim_dynamic::engine::DynParams;

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
    let (_metrics, fired) = run_one_seed(&sc, 1);
    assert_eq!(fired.len(), 1, "exactly one event fired");
    assert_eq!(fired[0].tick, 2, "fired on the scripted tick");
    assert_eq!(fired[0].kind, EventKind::Disaster);
}

#[test]
fn event_dispatch_skips_events_scheduled_beyond_horizon() {
    // horizon is 4 (ticks 0..4); an event at tick 9 must never fire.
    let sc = tiny_scenario_with_events(vec![(9, Event::KillSubnet(3))]);
    let (_metrics, fired) = run_one_seed(&sc, 1);
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
    let (_m, fired) = run_one_seed(&sc, 1);
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
    // Anchor = `sim_diag 42 100 50 1 v2` (captured 2026-07-07). The harness must NOT
    // distort the engine: same build_world + 130 steps ⇒ same god-view numbers.
    let (m, _fired) = run_one_seed(&honest_v2(), 42);

    // Exact integer counters (sim_diag §6a/§3-sum/§6d).
    assert_eq!(m.alive_symbols, 564, "alive symbols (6a)");
    assert_eq!(m.evicts, 1413, "eviction_log.len (sum of §3)");
    assert_eq!(m.preempts, 1189, "preempt_count (6d)");
    assert_eq!(m.cap_trims, 10, "cap_trim_count (6d)");

    // Floats to the sim_diag print precision.
    assert!(
        (m.share_a_pos - 95.9).abs() < 0.1,
        "share A>0 = {}",
        m.share_a_pos
    );
    assert!(
        (m.mean_depth - 3371.852).abs() < 0.01,
        "mean D = {}",
        m.mean_depth
    );
    assert!(
        (m.mean_sigma - 0.0570).abs() < 1e-4,
        "mean σ = {}",
        m.mean_sigma
    );
    // Per-archetype floor durability (sim_diag §5): Reliable 2.30, Nomad 0.42, Hoarder 2.42.
    assert!(
        (m.durability[0] - 2.30).abs() < 0.01,
        "Reliable durability = {}",
        m.durability[0]
    );
    assert!(
        (m.durability[3] - 0.42).abs() < 0.01,
        "Nomad durability = {}",
        m.durability[3]
    );
    assert!(
        (m.durability[4] - 2.42).abs() < 0.01,
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
    // Reliable operates at BALANCED reciprocity — seed 42 ROI ≈ 1.0123, NOT below 1.
    // (Universal "< 1 for all archetypes" is impossible: Σconsumed ≡ Σserved_out.) The
    // invariant is BOUNDED extraction, so we lock the measured value and the 1.25 ceiling.
    let (m, _fired) = run_one_seed(&honest_v2(), 42);
    let roi = m.extraction_roi[0];
    assert!(
        (roi - 1.0123).abs() < 0.01,
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
    AdvAction::NoOp
}

#[test]
fn behavior_hook_has_no_world_and_returns_action() {
    // The hook is a `fn(&AdvContext) -> AdvAction` — no `&World` by construction.
    let hook: BehaviorHook = noop_hook;
    let ctx = AdvContext {
        adv_node: 7,
        tick: 3,
        info_model: InfoModel::DrCard { target: 0 },
    };
    assert_eq!(hook(&ctx), AdvAction::NoOp);
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
