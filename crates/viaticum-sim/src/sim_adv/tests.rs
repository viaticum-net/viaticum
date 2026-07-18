//! Unit tests for `sim_adv` (sub-tranches 0.1 + 0.2 restore-truth). `what_when_then`.

use crate::sim_adv::brier::{Calibration, DEFAULT_BRIER_BUCKETS};
use crate::sim_adv::cli::{apply_dial, parse_cli, resolve_seeds};
use crate::sim_adv::metrics::{bit_eq as metrics_bit_eq, collect_metrics, mean_sigma};
use crate::sim_adv::registry::{all_scenarios, dr_baseline, find_scenario, honest_v2};
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
use crate::sim_dynamic::engine::DynParams;
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
    let (_metrics, fired, _r, _c) = run_one_seed(&sc, 1);
    assert_eq!(fired.len(), 1, "exactly one event fired");
    assert_eq!(fired[0].tick, 2, "fired on the scripted tick");
    assert_eq!(fired[0].kind, EventKind::Disaster);
}

#[test]
fn event_dispatch_skips_events_scheduled_beyond_horizon() {
    // horizon is 4 (ticks 0..4); an event at tick 9 must never fire.
    let sc = tiny_scenario_with_events(vec![(9, Event::KillSubnet(3))]);
    let (_metrics, fired, _r, _c) = run_one_seed(&sc, 1);
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
    let (_m, fired, _r, _c) = run_one_seed(&sc, 1);
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
    // Anchor = `sim_diag 42 100 50 1 v2` — RE-FROZEN 2026-07-18 for the F1-F6 sim-substrate
    // tranche. Both sim_diag and honest_v2 run the SAME engine (build_world + step with
    // DynParams::default), so they STILL agree field-for-field — the point of this anchor is
    // that the harness does not distort the engine, not the exact values. The F1-F6 shift
    // (transche-0.3 → F1-F6) is documented in the tranche report; cross-verified vs
    // `sim_diag 42 100 50 1 v2` at re-freeze time (share 76.8% / 224 alive / 506 evicts /
    // 377 preempts / 1 cap_trim / D 7306.05 / dur R 0.83, N 0.71, H 1.25).
    //   Drivers of the shift: F1 (window-PoS) collapses σ (0.054→0.005) and lifts D
    //   (3428→7306, intermittent holders now confirmed); F5 (chunk = source/k_eff = 25 gb,
    //   2.5× bigger) conserves placed GB but ~2.5× fewer symbols (565→224) and fewer eviction
    //   events (1514→506); share A>0 96.6→76.8 (harder contention, fewer mutual pairs).
    let (m, _fired, _r, _c) = run_one_seed(&honest_v2(), 42);

    // Exact integer counters (sim_diag §6a/§3-sum/§6d).
    assert_eq!(m.alive_symbols, 224, "alive symbols (6a)");
    assert_eq!(m.evicts, 506, "eviction_log.len (sum of §3)");
    assert_eq!(m.preempts, 377, "preempt_count (6d)");
    assert_eq!(m.cap_trims, 1, "cap_trim_count (6d)");

    // Floats to the sim_diag print precision.
    assert!(
        (m.share_a_pos - 76.79).abs() < 0.1,
        "share A>0 = {}",
        m.share_a_pos
    );
    assert!(
        (m.mean_depth - 7306.051).abs() < 0.01,
        "mean D = {}",
        m.mean_depth
    );
    assert!(
        (m.mean_sigma - 0.0054).abs() < 1e-4,
        "mean σ = {}",
        m.mean_sigma
    );
    // Per-archetype floor durability (sim_diag §5): Reliable 0.83, Nomad 0.71, Hoarder 1.25.
    assert!(
        (m.durability[0] - 0.83).abs() < 0.01,
        "Reliable durability = {}",
        m.durability[0]
    );
    assert!(
        (m.durability[3] - 0.71).abs() < 0.01,
        "Nomad durability = {}",
        m.durability[3]
    );
    assert!(
        (m.durability[4] - 1.25).abs() < 0.01,
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
    // Reliable operates at BALANCED reciprocity — seed 42 ROI ≈ 0.989 (F1-F6 tranche; was
    // 1.015 pre-F1-F6), NOT above the ceiling. (Universal "< 1 for all archetypes" is
    // impossible: Σconsumed ≡ Σserved_out.) The invariant is BOUNDED extraction, so we lock
    // the measured value and the 1.25 ceiling.
    let (m, _fired, _r, _c) = run_one_seed(&honest_v2(), 42);
    let roi = m.extraction_roi[0];
    assert!(
        (roi - 0.989).abs() < 0.01,
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
    tracker.on_disaster(&world, victim, disaster_tick);
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
    tracker.on_disaster(&world, victim, disaster_tick);
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
    tracker.on_disaster(&world, victim, disaster_tick);
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
    tracker2.on_disaster(&world, victim, disaster_tick);
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
    tracker.on_disaster(&world, victim, disaster_tick);
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
    tracker.on_disaster(&world, victim, disaster_tick);
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
    tracker.on_disaster(&world, victim, disaster_tick);
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
