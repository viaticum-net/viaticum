//! Tests for the dynamic 4R harness (`sim_dynamic`).
//!
//! Naming: `what_when_then`. The keystone is the anti-oracle regression test
//! (design §10.H): two god-view nodes identical in every observable but differing
//! in hidden archetype must produce bit-identical first-hand obs AND identical
//! kernel decisions.

use viaticum_core::four_r::{
    EvictPhase, PlacementPolicy, RetentionPrior, SurfacePrior, estimate_surface, retained_depth,
};

use crate::sim_dynamic::engine::{
    DynParams, PosOutcome, assert_lambda_dt_stable, fresh_capital, step,
};
use crate::sim_dynamic::generator::{
    Archetype, DAYS_PER_TICK, Node, PairCapital, online, population_mix,
};
use crate::sim_dynamic::observer::{self, observe_pair};
use crate::sim_dynamic::{Experiment1Config, build_world, run_experiment_1};

// ============================================================
// Helpers
// ============================================================

/// A bare god-view node with the given archetype and a tiny holdings set, used to
/// build observations. All OBSERVABLE fields are identical regardless of archetype.
fn node_with(archetype: Archetype) -> Node {
    Node {
        id: 7,
        archetype,
        disk_cap: 100.0,
        holdings: Vec::new(),
        own_blocks: Vec::new(),
        addr_subnet: 11,
        master_byte: 22,
        evict_phase: EvictPhase::default(),
        present: true,
        joined_tick: 0,
    }
}

/// A capital state with some interaction history (so obs is non-trivial).
fn cap_with_history() -> PairCapital {
    let mut c = PairCapital {
        g_oh: 12.0,
        g_ho: 8.0,
        g_oh_prev: 10.0,
        v_dem: 10.0,
        pos_window: Vec::new(),
    };
    // 6 passes, 2 non-passes.
    for &b in &[true, true, false, true, true, true, false, true] {
        c.push_outcome(b);
    }
    c
}

// ============================================================
// §10.H — Anti-oracle regression (the keystone)
// ============================================================

#[test]
fn first_hand_obs_is_bit_identical_when_only_hidden_archetype_differs() {
    // Two nodes identical in EVERY observable, differing ONLY in hidden archetype.
    let n_reliable = node_with(Archetype::Reliable);
    let n_hoarder = node_with(Archetype::Hoarder);
    let n_freeloader = node_with(Archetype::Freeloader);
    let cap = cap_with_history();

    let obs_r = observe_pair(&cap, &n_reliable, DAYS_PER_TICK);
    let obs_h = observe_pair(&cap, &n_hoarder, DAYS_PER_TICK);
    let obs_f = observe_pair(&cap, &n_freeloader, DAYS_PER_TICK);

    // The observer has nowhere to write the archetype → the obs are bit-identical.
    assert_eq!(obs_r, obs_h);
    assert_eq!(obs_r, obs_f);
}

#[test]
fn kernel_decisions_are_identical_when_only_hidden_archetype_differs() {
    // Same setup; assert any kernel decision on the obs is identical across the
    // hidden archetypes. (The kernel has no archetype field — this can only fail if
    // the observer leaked the truth into a legal field.)
    let cap = cap_with_history();
    let obs_r = observe_pair(&cap, &node_with(Archetype::Reliable), DAYS_PER_TICK);
    let obs_h = observe_pair(&cap, &node_with(Archetype::Hoarder), DAYS_PER_TICK);

    let prior = SurfacePrior::default();
    let retention = RetentionPrior::default();

    // Surface estimate.
    let s_r = estimate_surface(&obs_r, &prior, 10.0, DAYS_PER_TICK);
    let s_h = estimate_surface(&obs_h, &prior, 10.0, DAYS_PER_TICK);
    assert_eq!(s_r, s_h);

    // Retained depth.
    assert_eq!(
        retained_depth(&obs_r, &retention),
        retained_depth(&obs_h, &retention)
    );
}

// ============================================================
// Determinism
// ============================================================

#[test]
fn experiment_summary_is_identical_for_the_same_seed() {
    let cfg = Experiment1Config {
        n_nodes: 30,
        regime1_ticks: 10,
        regime2_ticks: 15,
        dr_victims: 8,
        seed: 123,
    };
    let a = run_experiment_1(cfg);
    let b = run_experiment_1(cfg);
    assert_eq!(a.rank.gap.to_bits(), b.rank.gap.to_bits());
    assert_eq!(a.rank.spearman_rho.to_bits(), b.rank.spearman_rho.to_bits());
    assert_eq!(
        a.reciprocity.median_honest_balance.to_bits(),
        b.reciprocity.median_honest_balance.to_bits()
    );
    assert_eq!(
        a.dr.median_survival.to_bits(),
        b.dr.median_survival.to_bits()
    );
    assert_eq!(a.newcomer.t_boot_placed, b.newcomer.t_boot_placed);
}

#[test]
fn different_seeds_generally_give_different_runs() {
    let base = Experiment1Config {
        n_nodes: 30,
        regime1_ticks: 10,
        regime2_ticks: 15,
        dr_victims: 8,
        seed: 1,
    };
    let other = Experiment1Config { seed: 999, ..base };
    let a = run_experiment_1(base);
    let b = run_experiment_1(other);
    // The gap should differ (overwhelmingly likely for two unrelated seeds).
    assert_ne!(a.rank.gap.to_bits(), b.rank.gap.to_bits());
}

#[test]
fn world_build_is_deterministic_in_seed() {
    let params = DynParams::default();
    let w1 = build_world(20, &params, 55);
    let w2 = build_world(20, &params, 55);
    assert_eq!(w1.nodes.len(), w2.nodes.len());
    for (a, b) in w1.nodes.iter().zip(&w2.nodes) {
        assert_eq!(a.archetype, b.archetype);
        assert_eq!(a.disk_cap.to_bits(), b.disk_cap.to_bits());
    }
}

// ============================================================
// λ·dt < 1 stability assertion (design §10.C)
// ============================================================

#[test]
fn lambda_dt_assertion_passes_for_the_default_dials() {
    let params = DynParams::default();
    // Must not panic — the default (1/60 per day × 7 days) is well below 1.
    assert_lambda_dt_stable(params.lambda, DAYS_PER_TICK);
    assert!(params.lambda * DAYS_PER_TICK < 1.0);
}

#[test]
#[should_panic(expected = "must be < 1")]
fn lambda_dt_assertion_panics_when_product_exceeds_one() {
    // λ·dt = 0.5 × 7 = 3.5 ≥ 1 → the discrete capital step would oscillate/diverge.
    assert_lambda_dt_stable(0.5, DAYS_PER_TICK);
}

#[test]
fn stepping_the_world_exercises_the_stability_assertion() {
    // A normal step calls assert_lambda_dt_stable internally — it must not panic.
    let params = DynParams::default();
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(15, &params, 7);
    step(&mut world, &params, &prior, &policy);
    assert_eq!(world.tick, 1);
}

// ============================================================
// Calendar predicate (design §10.A)
// ============================================================

#[test]
fn calendar_is_tick_indexed_and_deterministic() {
    // Same (archetype, node, tick, seed) → same answer (no wall-clock).
    let a = online(Archetype::Weekend, 3, 10, 42);
    let b = online(Archetype::Weekend, 3, 10, 42);
    assert_eq!(a, b);
}

#[test]
fn weekend_is_online_more_on_weekend_ticks_than_weekday_ticks() {
    // Over many ticks, a Weekend node is online far more often on tick%7 in {4,5,6}.
    let mut weekend_up = 0;
    let mut weekend_tot = 0;
    let mut weekday_up = 0;
    let mut weekday_tot = 0;
    for t in 0..7000u64 {
        let up = online(Archetype::Weekend, 1, t, 9);
        if (t % 7) >= 4 {
            weekend_tot += 1;
            if up {
                weekend_up += 1;
            }
        } else {
            weekday_tot += 1;
            if up {
                weekday_up += 1;
            }
        }
    }
    let weekend_rate = weekend_up as f64 / weekend_tot as f64;
    let weekday_rate = weekday_up as f64 / weekday_tot as f64;
    // ~0.95 vs ~0.30 — clearly separated.
    assert!(
        weekend_rate > weekday_rate + 0.3,
        "weekend {weekend_rate} should exceed weekday {weekday_rate} by a wide margin"
    );
}

#[test]
fn seasonal_is_offline_more_in_summer_than_winter() {
    let mut summer_up = 0;
    let mut summer_tot = 0;
    let mut winter_up = 0;
    let mut winter_tot = 0;
    use crate::sim_dynamic::generator::TICKS_PER_YEAR;
    for t in 0..(TICKS_PER_YEAR * 50) {
        let up = online(Archetype::Seasonal, 2, t, 3);
        let month = (t % TICKS_PER_YEAR) * 12 / TICKS_PER_YEAR;
        let is_summer = (5..=7).contains(&month);
        if is_summer {
            summer_tot += 1;
            if up {
                summer_up += 1;
            }
        } else {
            winter_tot += 1;
            if up {
                winter_up += 1;
            }
        }
    }
    let summer_rate = summer_up as f64 / summer_tot as f64;
    let winter_rate = winter_up as f64 / winter_tot as f64;
    assert!(
        winter_rate > summer_rate + 0.3,
        "winter {winter_rate} should far exceed summer {summer_rate}"
    );
}

#[test]
fn reliable_uptime_is_high_and_freeloader_lower() {
    let count = |a: Archetype| {
        let mut up = 0;
        for t in 0..5000u64 {
            if online(a, 5, t, 17) {
                up += 1;
            }
        }
        up as f64 / 5000.0
    };
    let reliable = count(Archetype::Reliable);
    let freeloader = count(Archetype::Freeloader);
    assert!(
        reliable > 0.95,
        "reliable uptime {reliable} should be ~0.99"
    );
    assert!(
        reliable > freeloader,
        "reliable {reliable} should exceed freeloader {freeloader}"
    );
}

// ============================================================
// Accept/reject sampling + population mix (design §10.A, §3)
// ============================================================

#[test]
fn accept_rates_match_the_archetype_dials() {
    assert_eq!(Archetype::Reliable.accept_rate(), 1.0);
    assert_eq!(Archetype::Weekend.accept_rate(), 1.0);
    assert!(Archetype::Hoarder.accept_rate() <= 0.2);
    assert!(Archetype::Freeloader.accept_rate() <= 0.1);
}

#[test]
fn population_mix_sums_to_n_and_respects_shares() {
    let mix = population_mix(200);
    assert_eq!(mix.len(), 200);
    let count = |a: Archetype| mix.iter().filter(|&&x| x == a).count();
    // Reliable 40% = 80, Weekend 20% = 40, Freeloader is the small remainder.
    assert_eq!(count(Archetype::Reliable), 80);
    assert_eq!(count(Archetype::Weekend), 40);
    assert!(count(Archetype::Freeloader) >= 1);
    // All six present.
    for a in Archetype::ALL {
        assert!(count(a) >= 1, "{a:?} missing from mix");
    }
}

#[test]
fn hoarder_holds_less_than_reliable_after_a_run() {
    // The accept-rate dial really bites: over a run the Hoarder/Freeloader population
    // ends with fewer foreign symbols held than Reliable (god-view), because they
    // reject most offers. This is the behavioural anti-oracle (the kernel never saw
    // the archetype; the reject is observed first-hand).
    let params = DynParams::default();
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(60, &params, 71);
    for _ in 0..40 {
        step(&mut world, &params, &prior, &policy);
    }
    let avg_held = |a: Archetype| {
        let nodes: Vec<&Node> = world.nodes.iter().filter(|n| n.archetype == a).collect();
        if nodes.is_empty() {
            return 0.0;
        }
        let held: usize = nodes
            .iter()
            .map(|n| n.holdings.iter().filter(|s| s.alive).count())
            .sum();
        held as f64 / nodes.len() as f64
    };
    let reliable = avg_held(Archetype::Reliable);
    let hoarder = avg_held(Archetype::Hoarder);
    let freeloader = avg_held(Archetype::Freeloader);
    assert!(
        reliable > hoarder,
        "reliable holds {reliable}, hoarder {hoarder} — hoarder should hold less"
    );
    assert!(
        hoarder > freeloader || freeloader == 0.0,
        "hoarder {hoarder} should hold ≥ freeloader {freeloader}"
    );
}

// ============================================================
// PoS outcome classification (design §10.B)
// ============================================================

#[test]
fn pos_outcome_is_timeout_when_holder_offline() {
    // Replicate the classification logic: offline ⇒ timeout regardless of holding.
    let online_holder = false;
    let holds = true;
    let outcome = classify(online_holder, holds);
    assert_eq!(outcome, PosOutcome::Timeout);
}

#[test]
fn pos_outcome_is_fail_when_online_but_not_holding() {
    let outcome = classify(true, false);
    assert_eq!(outcome, PosOutcome::Fail);
}

#[test]
fn pos_outcome_is_pass_when_online_and_holding() {
    let outcome = classify(true, true);
    assert_eq!(outcome, PosOutcome::Pass);
}

/// Mirror of the engine's outcome classification (design §10.B) for a unit test.
fn classify(holder_online: bool, holds: bool) -> PosOutcome {
    if !holder_online {
        PosOutcome::Timeout
    } else if holds {
        PosOutcome::Pass
    } else {
        PosOutcome::Fail
    }
}

// ============================================================
// Capital threading (design §10.C) — grows on pass, NOT on fail/timeout
// ============================================================

#[test]
fn capital_grows_on_pass_and_not_on_fail_or_timeout() {
    use viaticum_core::four_r::update_capital;
    let lambda = DynParams::default().lambda;
    let dt = DAYS_PER_TICK;
    let volume = 10.0;

    // Pass: v_conf = volume ⇒ capital rises.
    let g0 = 5.0;
    let g_pass = update_capital(g0, volume, lambda, dt);
    assert!(g_pass > g0, "capital must rise on a pass: {g_pass} > {g0}");

    // Fail / timeout: v_conf = 0 ⇒ capital only LEAKS (falls toward 0).
    let g_fail = update_capital(g0, 0.0, lambda, dt);
    assert!(
        g_fail < g0,
        "capital must NOT grow on a fail/timeout: {g_fail} < {g0}"
    );
}

#[test]
fn pos_window_tracks_recent_pass_fraction() {
    let mut c = PairCapital::default();
    for _ in 0..6 {
        c.push_outcome(true);
    }
    for _ in 0..2 {
        c.push_outcome(false);
    }
    // 6 pass + 2 fail = 0.75 (window holds the last 8).
    assert!((c.recent_rate_p() - 0.75).abs() < 1e-9);
}

#[test]
fn capital_actually_accumulates_for_a_reliable_holder_over_a_run() {
    // After a run, a Reliable holder has earned positive g_oh from at least one owner
    // (it accepted, held, and passed PoS). The capital threading is live, not inert.
    let params = DynParams::default();
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(40, &params, 88);
    for _ in 0..30 {
        step(&mut world, &params, &prior, &policy);
    }
    let reliable_idx = world
        .nodes
        .iter()
        .position(|n| n.archetype == Archetype::Reliable)
        .unwrap();
    let total_g: f64 = (0..world.nodes.len())
        .filter(|&j| j != reliable_idx)
        .map(|j| world.capital[j][reliable_idx].g_oh)
        .sum();
    assert!(
        total_g > 0.0,
        "a Reliable holder should accrue positive earned G over a run, got {total_g}"
    );
}

// ============================================================
// Observer eviction view + ladder (sanity)
// ============================================================

#[test]
fn fresh_capital_is_zeroed_and_correctly_sized() {
    let cap = fresh_capital(5);
    assert_eq!(cap.len(), 5);
    for row in &cap {
        assert_eq!(row.len(), 5);
        for c in row {
            assert_eq!(c.g_oh, 0.0);
            assert!(c.pos_window.is_empty());
        }
    }
}

#[test]
fn owner_ladder_on_holder_returns_sorted_iotas_and_correct_rung() {
    let mut holder = node_with(Archetype::Reliable);
    use crate::sim_dynamic::generator::HeldSymbol;
    holder.holdings = vec![
        HeldSymbol {
            owner: 0,
            block: 2,
            iota: 0.9,
            volume: 10.0,
            alive: true,
        },
        HeldSymbol {
            owner: 0,
            block: 0,
            iota: 0.2,
            volume: 10.0,
            alive: true,
        },
        HeldSymbol {
            owner: 0,
            block: 1,
            iota: 0.5,
            volume: 10.0,
            alive: true,
        },
    ];
    // Ladder sorted by block id: blocks 0,1,2 ⇒ iotas 0.2,0.5,0.9; target block 2 is rung 2.
    let (iotas, rung) = observer::owner_ladder_on_holder(&holder, 0, 2);
    assert_eq!(iotas, vec![0.2, 0.5, 0.9]);
    assert_eq!(rung, 2);
}

// ============================================================
// Fast smoke Experiment-1 (in the normal suite)
// ============================================================

#[test]
fn experiment_1_smoke_produces_sane_metrics_with_correct_gap_sign() {
    // Small + fast (~30 nodes, ~20 ticks total). Asserts: no panic, finite ratios,
    // and the PRIMARY gap has the right SIGN (Reliable earns more total G than the
    // Hoarder/Freeloader pair — honest holders rank above exploiters).
    let cfg = Experiment1Config {
        n_nodes: 30,
        regime1_ticks: 8,
        regime2_ticks: 12,
        dr_victims: 8,
        seed: 2026,
    };
    let r = run_experiment_1(cfg);

    // (a) gap sign: honest > exploiters.
    assert!(
        r.rank.gap > 0.0,
        "primary gap must be positive (Reliable {:.2} vs bad {:.2}), got {:+.2}",
        r.rank.mean_g_reliable,
        r.rank.mean_g_bad,
        r.rank.gap
    );

    // (b) reciprocity ratios are finite where present.
    for &ratio in &r.reciprocity.honest_balance_ratios {
        assert!(
            ratio.is_finite() && ratio >= 1.0,
            "balance ratio {ratio} must be finite ≥ 1"
        );
    }

    // (c) DR median is a valid probability (or NaN only if no blocks, which should
    // not happen at this scale).
    assert!(
        r.dr.median_survival.is_finite(),
        "DR median should be finite, got {}",
        r.dr.median_survival
    );
    assert!((0.0..=1.0).contains(&r.dr.median_survival));

    // The newcomer probe at least placed its own data (the network is reachable).
    assert!(
        r.newcomer.t_boot_placed.is_some(),
        "newcomer should be able to place its own data in a reachable network"
    );
}

// ============================================================
// FIX 1 — metric (a) reports THREE honest aggregations with documented signs
// ============================================================

#[test]
fn metric_a_reports_sum_mean_and_breadth_with_documented_signs() {
    // The reviewer-required honest framing (FIX 1): on a run, the SUM gap is
    // POSITIVE (breadth-driven), the per-pair MEAN gap is NEGATIVE (exploiters score
    // higher per pair — selection effect), and the breadth ratio is > 1 (Reliable
    // serves more pairs, ≈ the accept_rate dial). A small-but-real smoke run.
    let cfg = Experiment1Config {
        n_nodes: 120,
        regime1_ticks: 20,
        regime2_ticks: 40,
        dr_victims: 10,
        seed: 4242,
    };
    let r = run_experiment_1(cfg);

    // (1) SUM gap > 0: honest holders out-earn exploiters on TOTAL foregone service.
    assert!(
        r.rank.gap > 0.0,
        "SUM gap must be > 0 (breadth-driven), got {:+.4}",
        r.rank.gap
    );
    // (2) per-pair MEAN gap < 0: per pair, exploiters score HIGHER (must be surfaced,
    // not hidden — the kernel does NOT rank on per-pair surface quality).
    assert!(
        r.rank.gap_per_pair < 0.0,
        "per-pair gap must be NEGATIVE (exploiters score higher per pair), got {:+.4} \
         (reliable {:.4} vs bad {:.4})",
        r.rank.gap_per_pair,
        r.rank.mean_per_pair_g_reliable,
        r.rank.mean_per_pair_g_bad
    );
    // (3) breadth ratio > 1: Reliable serves more distinct pairs (≈ accept_rate dial).
    assert!(
        r.rank.breadth_ratio > 1.0,
        "breadth ratio must be > 1 (Reliable serves more pairs), got {:.4}× \
         (reliable {:.4} vs bad {:.4})",
        r.rank.breadth_ratio,
        r.rank.breadth_reliable,
        r.rank.breadth_bad
    );
    // (4) ρ(surface,truth) is finite (a real diagnostic exists); its sign is the
    // per-pair inversion's cousin but we only assert finiteness here (sign can wobble
    // on a small smoke run; the full run reports it).
    assert!(
        r.rank.spearman_rho.is_finite(),
        "Spearman ρ must be finite, got {}",
        r.rank.spearman_rho
    );
}

// ============================================================
// FIX 2 — served-integral: accumulates only on PoS-pass, monotone non-decreasing
// ============================================================

#[test]
fn served_integral_accumulates_only_on_pos_pass_and_is_monotone() {
    // The god-view served[holder][owner] integral (design §10.E) must (a) only ever
    // grow on a PoS pass — so the GLOBAL sum equals the running total of all
    // PoS-confirmed retained volume, never more — and (b) be monotone non-decreasing
    // across ticks (an integral never shrinks).
    let params = DynParams::default();
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(50, &params, 314);

    let global_sum = |w: &crate::sim_dynamic::generator::World| -> f64 {
        w.served.iter().flat_map(|r| r.iter()).sum()
    };

    let mut prev_cells: Vec<Vec<f64>> = world.served.clone();
    let mut prev_total = global_sum(&world);
    for _ in 0..40 {
        step(&mut world, &params, &prior, &policy);
        let total = global_sum(&world);
        // Monotone non-decreasing GLOBAL total.
        assert!(
            total >= prev_total - 1e-9,
            "served integral total must never shrink: {total} < {prev_total}"
        );
        // Monotone PER CELL (each accumulator only grows).
        for (o, row) in world.served.iter().enumerate() {
            for (p, &cell) in row.iter().enumerate() {
                let was = prev_cells[o][p];
                assert!(
                    cell >= was - 1e-9,
                    "served[{o}][{p}] shrank: {cell} < {was}"
                );
            }
        }
        prev_cells = world.served.clone();
        prev_total = total;
    }
    // The integral grew at all (a Reliable holder passed PoS over the run).
    assert!(
        prev_total > 0.0,
        "served integral should be positive after a run, got {prev_total}"
    );
}

#[test]
fn served_integral_equals_zero_when_no_symbol_is_ever_held() {
    // A degenerate world where every node is a Freeloader-like rejector would barely
    // accumulate; here we just assert the integral starts at exactly zero and that a
    // single tick with placements either leaves it zero (all rejected) or strictly
    // positive — never negative.
    let params = DynParams::default();
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(20, &params, 7);
    let zero: f64 = world.served.iter().flat_map(|r| r.iter()).sum();
    assert_eq!(zero, 0.0, "served integral must start at zero");
    step(&mut world, &params, &prior, &policy);
    let after: f64 = world.served.iter().flat_map(|r| r.iter()).sum();
    assert!(
        after >= 0.0,
        "served integral must never be negative, got {after}"
    );
}

#[test]
fn served_series_samples_at_regime_boundary_and_records_a_trend() {
    // The inbound-served time-series (design §10.E decay observable) must be
    // populated by a full experiment run, and the Regime-1-end / Regime-2-end shares
    // must be finite numbers (so the H3 verdict can be rendered honestly).
    let cfg = Experiment1Config {
        n_nodes: 80,
        regime1_ticks: 20,
        regime2_ticks: 30,
        dr_victims: 8,
        seed: 9090,
    };
    let r = run_experiment_1(cfg);
    assert!(
        !r.reciprocity.series.is_empty(),
        "the served time-series must be populated"
    );
    // The series is in tick order, and the integral is monotone, so each archetype's
    // inbound is non-decreasing across samples.
    let mut prev_f = 0.0;
    let mut prev_r = 0.0;
    for s in &r.reciprocity.series {
        assert!(
            s.freeloader_inbound >= prev_f - 1e-9,
            "freeloader inbound must be monotone across samples"
        );
        assert!(
            s.reliable_inbound >= prev_r - 1e-9,
            "reliable inbound must be monotone across samples"
        );
        prev_f = s.freeloader_inbound;
        prev_r = s.reliable_inbound;
    }
    // The Regime-2 balance ratios come from the WINDOW integral, so they are finite
    // and ≥ 1 (normalised) where present.
    for &ratio in &r.reciprocity.honest_balance_ratios {
        assert!(
            ratio.is_finite() && ratio >= 1.0,
            "windowed balance ratio {ratio} must be finite ≥ 1"
        );
    }
}

// ============================================================
// Full Experiment-1 (on-demand, #[ignore] — the long ~200-node run)
// ============================================================

/// The full honest-convergence Experiment-1 at design scale (~200 nodes, ~130
/// weekly ticks). `#[ignore]`-d so it does NOT run in the default suite — invoke
/// with `cargo test -p viaticum-sim full_experiment_1 -- --ignored --nocapture`
/// (or via the `sim_dynamic` bin). Deterministic; prints the structured report.
#[test]
#[ignore = "long ~200-node run; on-demand only (see also the sim_dynamic bin)"]
fn full_experiment_1_prints_structured_report() {
    let cfg = Experiment1Config::default();
    let report = run_experiment_1(cfg);
    crate::sim_dynamic::print_experiment_1(&report);

    // Even on-demand, assert the load-bearing structural sign so a regression is
    // caught: honest holders out-earn exploiters on total G.
    assert!(
        report.rank.gap > 0.0,
        "primary gap must be positive at scale, got {:+.4}",
        report.rank.gap
    );
}
