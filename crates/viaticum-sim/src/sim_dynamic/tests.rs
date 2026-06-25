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
use crate::sim_dynamic::evaluator::{
    contention_metric, drop_ranking_metric, mc_block_r_actual, pillar1_metric,
};
use crate::sim_dynamic::generator::{
    Archetype, DAYS_PER_TICK, DiskProfile, GiverTier, HeldSymbol, Node, OWN_DATA_DISK_FRACTION,
    PairCapital, World, giver_tier_mix, online, population_mix,
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
        disk: DiskProfile {
            tier: GiverTier::T1,
            own_data: 20.0,
            own_growth_per_tick: 0.0,
        },
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
        mc_samples: 64,
        mc_horizon_ticks: 8,
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
        mc_samples: 64,
        mc_horizon_ticks: 8,
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
fn hoarder_and_freeloader_hold_less_than_reliable_in_abundance() {
    // The accept-rate dial really bites: in the ABUNDANCE phase (early ticks, ample
    // free disk) the Hoarder/Freeloader population holds fewer foreign symbols than
    // Reliable (god-view), because they REJECT most offers — the behavioural anti-
    // oracle (the kernel never saw the archetype; the reject is observed first-hand).
    //
    // Measured in abundance ON PURPOSE: once the §A.3 room-gate bites under contention,
    // holdings are capped by physical disk for EVERYONE, washing out the accept-rate
    // signal (a full Reliable can hold no more than a full Freeloader). The clean
    // behavioural reject signal lives BEFORE disks fill — that is what this asserts.
    let params = DynParams::default();
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(120, &params, 71);
    for _ in 0..6 {
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
    // The load-bearing behavioural anti-oracle invariant: BOTH exploiters hold less
    // than Reliable (they reject most offers — the kernel never saw the archetype, the
    // reject is observed first-hand). The Hoarder-vs-Freeloader ORDERING is NOT
    // asserted: both are low rejectors and under the §A.3 room-gate + accept-gate their
    // relative holdings depend on which contended holders they happened to land on —
    // a weak secondary that is not a model property.
    assert!(
        reliable > hoarder,
        "reliable holds {reliable}, hoarder {hoarder} — hoarder should hold less"
    );
    assert!(
        reliable > freeloader,
        "reliable holds {reliable}, freeloader {freeloader} — freeloader should hold less"
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
fn experiment_1_smoke_produces_sane_phase1_metrics() {
    // Small + fast (~30 nodes, ~20 ticks total). Asserts the Phase-1 SANE invariants:
    // no panic, finite ratios, DR a valid probability, and the pillar-1 efficiency is
    // well-formed. (The retired metric-(a) earned-G gap SIGN is no longer asserted —
    // it was an abundance artifact, design §G supersede; the pillar-1 efficiency +
    // drop-ranking are the headline now. The smoke run is too short to firmly contend,
    // so the contention gate is asserted only by the full-scale on-demand test.)
    let cfg = Experiment1Config {
        n_nodes: 30,
        regime1_ticks: 8,
        regime2_ticks: 12,
        dr_victims: 8,
        mc_samples: 64,
        mc_horizon_ticks: 8,
        seed: 2026,
    };
    let r = run_experiment_1(cfg);

    // (a) reciprocity ratios are finite where present.
    for &ratio in &r.reciprocity.honest_balance_ratios {
        assert!(
            ratio.is_finite() && ratio >= 1.0,
            "balance ratio {ratio} must be finite ≥ 1"
        );
    }

    // (b) DR median is a valid probability.
    assert!(
        r.dr.median_survival.is_finite(),
        "DR median should be finite, got {}",
        r.dr.median_survival
    );
    assert!((0.0..=1.0).contains(&r.dr.median_survival));

    // (c) pillar-1 efficiency figures are well-formed probabilities / non-negative.
    assert!(
        (0.0..=1.0).contains(&r.pillar1.mean_r_actual_reliable),
        "Reliable R_actual must be a probability, got {}",
        r.pillar1.mean_r_actual_reliable
    );
    assert!(
        r.pillar1.efficiency_reliable >= 0.0 || r.pillar1.efficiency_reliable.is_nan(),
        "efficiency must be non-negative (or NaN if no disk given)"
    );

    // (d) the contention instrumentation is populated (utilization is a valid ratio).
    assert!(
        (0.0..=1.0).contains(&r.contention.mean_utilization_end),
        "utilization must be a valid ratio, got {}",
        r.contention.mean_utilization_end
    );
}

// ============================================================
// Metric (a) — RETIRED earned-G framing is still well-formed (design §G supersede)
// ============================================================

#[test]
fn metric_a_earned_g_aggregations_are_well_formed() {
    // The old metric-(a) earned-G SUM/per-pair/breadth framing is RETIRED as a HEADLINE
    // (design §G: the reject-breadth headline was an abundance artifact / tautology of
    // the input accept dial). Under the Phase-1 CONTENTION regime the SUM gap can even
    // INVERT (exploiters accumulate more raw per-pair G from the few deep partners they
    // keep). We therefore NO LONGER assert the old POSITIVE-SUM / NEGATIVE-per-pair /
    // breadth>1 signs — that would be faking a property the contention regime does not
    // have. We assert only that the (continuity-only) aggregations are FINITE and the
    // breadth figures non-negative, so a NaN/garbage regression is still caught. The
    // real Phase-1 headline is the pillar-1 efficiency + drop-ranking (asserted above).
    let cfg = Experiment1Config {
        n_nodes: 120,
        regime1_ticks: 20,
        regime2_ticks: 40,
        dr_victims: 10,
        mc_samples: 64,
        mc_horizon_ticks: 8,
        seed: 4242,
    };
    let r = run_experiment_1(cfg);

    assert!(
        r.rank.gap.is_finite(),
        "SUM gap must be finite, got {}",
        r.rank.gap
    );
    assert!(
        r.rank.mean_g_reliable.is_finite() && r.rank.mean_g_bad.is_finite(),
        "earned-G means must be finite"
    );
    assert!(
        r.rank.breadth_reliable >= 0.0 && r.rank.breadth_bad >= 0.0,
        "breadth counts must be non-negative"
    );
    // ρ(surface,truth) is finite (a real diagnostic exists).
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
        mc_samples: 64,
        mc_horizon_ticks: 8,
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

    // NOTE: the retired metric-(a) earned-G SUM gap is NOT asserted positive here —
    // under the Phase-1 contention regime it inverts (an abundance artifact, design §G
    // supersede). The load-bearing Phase-1 assertions are contention + pillar-1 below.

    // Phase-1 make-or-break: the world REACHED contention (utilization→1, eviction
    // firing) — the thing Exp-1 failed (permanent abundance). This is THE result.
    assert!(
        report.contention_reached(),
        "Phase-1 make-or-break: the world must REACH contention (util {:.3}, eviction on \
         {}/{} ticks)",
        report.contention.mean_utilization_end,
        report.contention.ticks_with_eviction,
        report.contention.total_ticks,
    );
    // Pillar-1 efficiency: Reliable achieves higher R_actual/own-disk than the
    // exploiters (the heart of §D.1).
    assert!(
        report.pillar1.efficiency_reliable > report.pillar1.efficiency_freeloader
            && report.pillar1.efficiency_reliable > report.pillar1.efficiency_hoarder,
        "Reliable efficiency {:.6} must exceed Freeloader {:.6} and Hoarder {:.6}",
        report.pillar1.efficiency_reliable,
        report.pillar1.efficiency_freeloader,
        report.pillar1.efficiency_hoarder,
    );
}

// ============================================================
// PHASE-1 §A — realism-v2 world reaches contention (the make-or-break)
// ============================================================

/// Build a small disk-profiled world and run it; helper for the Phase-1 tests.
fn run_small(seed: u64, ticks: u64) -> World {
    let params = DynParams::default();
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(120, &params, seed);
    for _ in 0..ticks {
        step(&mut world, &params, &prior, &policy);
    }
    world
}

#[test]
fn full_disk_rejects_a_new_offer_even_when_willing() {
    // §A.3 SymbolReject-on-quota fidelity: a holder with NO free disk must reject a
    // new offer EVEN IF it is willing (accept_rate 1.0). The old engine accepted on a
    // pure Bernoulli with no disk check — this asserts the room gate now bites.
    let params = DynParams::default();
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    // A 2-node world: owner 0 wants to back up; holder 1 is a willing Reliable but
    // its disk is physically FULL (own_data == cap, no free room).
    let mut world = build_world(2, &params, 5);
    // Force holder 1 full: own data fills the disk entirely.
    world.nodes[1].archetype = Archetype::Reliable; // willing
    world.nodes[1].disk.own_data = world.nodes[1].disk_cap; // no room
    world.nodes[1].disk.own_growth_per_tick = 0.0;
    let held_before = world.nodes[1].holdings.iter().filter(|s| s.alive).count();
    // Stop own-data growth on the full holder so the cap-clamp doesn't shrink it.
    step(&mut world, &params, &prior, &policy);
    let held_after = world.nodes[1].holdings.iter().filter(|s| s.alive).count();
    assert_eq!(
        held_before, 0,
        "precondition: holder starts with no holdings"
    );
    assert_eq!(
        held_after, 0,
        "a FULL holder must reject all offers (SymbolReject-on-quota, §A.3) — got {held_after} \
         accepted despite zero free disk"
    );
    assert!(
        world.nodes[1].free_disk() < params.block_volume / params.n_symbols as f64,
        "the holder really had no room for a symbol"
    );
}

#[test]
fn greed_fills_the_disk_above_the_r_target_floor() {
    // §A.1 holder-greed: an owner places MORE than the k_eff floor needs — the cream
    // margin (ι-prioritized) fills free holder capacity. A high-ι block ends with
    // strictly more than k_eff alive holders (greed past the floor), as long as the
    // network has room early on.
    let params = DynParams::default();
    let world = run_small(77, 6); // a few ticks: Regime-1, plenty of room
    // Find a high-ι block (the last block of some present Reliable owner) and count
    // its alive holders — greed should push it ABOVE k_eff.
    let n = world.nodes.len();
    let mut max_holders = 0usize;
    for o in 0..n {
        if !world.nodes[o].present {
            continue;
        }
        for b in &world.nodes[o].own_blocks {
            let ah = (0..n)
                .filter(|&h| {
                    world.nodes[h].present
                        && world.nodes[h]
                            .holdings
                            .iter()
                            .any(|s| s.alive && s.owner == o && s.block == b.id)
                })
                .count();
            max_holders = max_holders.max(ah);
        }
    }
    assert!(
        max_holders > params.k_eff,
        "greed must place ABOVE the k_eff={} floor (cream margin, §A.1); best block had {} holders",
        params.k_eff,
        max_holders
    );
}

#[test]
fn own_data_grows_monotonically_over_the_run() {
    // §A.2 own-data growth: every present node's own data is monotone non-decreasing
    // across ticks (the contention driver), and at least the fast-growing tiers
    // actually grew.
    let params = DynParams::default();
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(60, &params, 42);
    let mut prev: Vec<f64> = world.nodes.iter().map(|n| n.disk.own_data).collect();
    let start: Vec<f64> = prev.clone();
    for _ in 0..30 {
        step(&mut world, &params, &prior, &policy);
        for (i, node) in world.nodes.iter().enumerate() {
            if node.present {
                assert!(
                    node.disk.own_data >= prev[i] - 1e-9,
                    "own_data must be monotone non-decreasing: node {i} {} < {}",
                    node.disk.own_data,
                    prev[i]
                );
            }
            prev[i] = node.disk.own_data;
        }
    }
    // At least one node's own data grew over the run (the drift driver is live).
    let grew = world
        .nodes
        .iter()
        .enumerate()
        .any(|(i, n)| n.disk.own_data > start[i] + 1e-6);
    assert!(
        grew,
        "own-data growth must actually move (the contention driver)"
    );
}

#[test]
fn own_data_growth_respects_the_disk_fraction_ceiling() {
    // §A.2: own data never exceeds OWN_DATA_DISK_FRACTION of the disk (so a lendable
    // floor always remains — contention is on the holdings budget, not own-data flood).
    let world = run_small(9, 60);
    for node in &world.nodes {
        assert!(
            node.disk.own_data <= node.disk_cap * OWN_DATA_DISK_FRACTION + 1e-6,
            "own_data {} exceeded the ceiling {} (cap {} × {})",
            node.disk.own_data,
            node.disk_cap * OWN_DATA_DISK_FRACTION,
            node.disk_cap,
            OWN_DATA_DISK_FRACTION
        );
    }
}

#[test]
fn world_reaches_contention_with_eviction_firing() {
    // §A make-or-break (scaled-down smoke): a disk-profiled world reaches high
    // utilization AND eviction actually fires (unlike Exp-1's permanent abundance).
    let params = DynParams::default();
    let world = run_small(2026, 100);
    let c = contention_metric(&world, params.hyst.s_hard);
    assert!(
        c.mean_utilization_end > 0.75,
        "utilization must climb toward 1 (got {:.3}) — the world must not stay in abundance",
        c.mean_utilization_end
    );
    assert!(
        c.total_evictions > 0,
        "eviction must actually FIRE under contention (got {} events) — the Exp-1 failure was \
         that it never did",
        c.total_evictions
    );
    assert!(
        c.ticks_with_eviction > 0,
        "at least some ticks must see eviction"
    );
}

// ============================================================
// PHASE-1 §D.1 — Monte-Carlo R_actual + pillar-1 efficiency + drop-ranking
// ============================================================

#[test]
fn mc_r_actual_rises_with_more_surviving_holders() {
    // §D.1 MC estimator monotonicity: more (likely-surviving) holders ⇒ higher
    // R_actual. Build a tiny world, place a block on few vs many strong holders, and
    // assert the MC survival rises. Uses the real god-view survival hazard.
    let params = DynParams::default();
    let mut world = build_world(10, &params, 3);
    // Make every node a present Reliable with comfortable disk (high survival probs)
    // and give owner 0 a single block held by a controllable number of holders.
    for node in &mut world.nodes {
        node.archetype = Archetype::Reliable;
        node.present = true;
        node.disk.own_data = node.disk_cap * 0.2; // lots of headroom → high survival
        node.holdings.clear();
    }
    let owner = 0usize;
    let block = world.nodes[owner].own_blocks[0].id;
    let iota = world.nodes[owner].own_blocks[0].iota;
    // Helper: place the block on the first `k` holders (indices 1..=k) and give the
    // owner reciprocal served credit so the symbols are protected.
    let place_on = |world: &mut World, k: usize| {
        for h in 1..world.nodes.len() {
            world.nodes[h].holdings.retain(|s| s.owner != owner);
        }
        world.nodes[owner].own_blocks[0].placements.clear();
        for h in 1..=k {
            world.nodes[h].holdings.push(HeldSymbol {
                owner,
                block,
                iota,
                volume: 10.0,
                alive: true,
            });
            world.served[owner][h] = 100.0; // owner served the holder → protected
        }
    };
    place_on(&mut world, 2);
    let r_few = mc_block_r_actual(&world, owner, block, params.k_eff, 8, 400, 11);
    place_on(&mut world, 8);
    let r_many = mc_block_r_actual(&world, owner, block, params.k_eff, 8, 400, 11);
    assert!(
        r_many > r_few,
        "more surviving holders must raise R_actual: many={r_many:.4} ≤ few={r_few:.4}"
    );
    assert!(
        (0.0..=1.0).contains(&r_few) && (0.0..=1.0).contains(&r_many),
        "R_actual must be a probability"
    );
}

#[test]
fn mc_r_actual_is_deterministic_for_the_same_seed() {
    // §F determinism: the MC estimator is bit-reproducible for a fixed seed.
    let params = DynParams::default();
    let world = run_small(123, 40);
    let owner = (0..world.nodes.len())
        .find(|&o| world.nodes[o].present && !world.nodes[o].own_blocks.is_empty())
        .unwrap();
    let block = world.nodes[owner].own_blocks[0].id;
    let a = mc_block_r_actual(&world, owner, block, params.k_eff, 8, 300, 77);
    let b = mc_block_r_actual(&world, owner, block, params.k_eff, 8, 300, 77);
    assert_eq!(
        a.to_bits(),
        b.to_bits(),
        "MC must be deterministic: {a} vs {b}"
    );
}

#[test]
fn pillar1_efficiency_ranks_reliable_above_exploiters() {
    // §D.1 pillar-1: under contention, Reliable achieves higher R_actual/own-disk than
    // BOTH exploiters. A real (small) contended run; the structural SIGN is asserted.
    let params = DynParams::default();
    let world = run_small(4242, 110);
    let p = pillar1_metric(&world, params.k_eff, 26, 200, 99);
    // Reliable's achieved own-data reliability beats both exploiters.
    assert!(
        p.mean_r_actual_reliable > p.mean_r_actual_hoarder,
        "Reliable R_actual {:.4} must beat Hoarder {:.4}",
        p.mean_r_actual_reliable,
        p.mean_r_actual_hoarder
    );
    assert!(
        p.mean_r_actual_reliable > p.mean_r_actual_freeloader,
        "Reliable R_actual {:.4} must beat Freeloader {:.4}",
        p.mean_r_actual_reliable,
        p.mean_r_actual_freeloader
    );
    // And the efficiency (R_actual per own-disk-given) leads too.
    assert!(
        p.efficiency_reliable > p.efficiency_freeloader
            && p.efficiency_reliable > p.efficiency_hoarder,
        "Reliable efficiency {:.6} must lead (Freeloader {:.6}, Hoarder {:.6})",
        p.efficiency_reliable,
        p.efficiency_freeloader,
        p.efficiency_hoarder
    );
}

#[test]
fn drop_ranking_picks_low_served_owners_first() {
    // §D.1 drop-ranking: under contention, eviction systematically drops LOW-served
    // owners first. Scored against god-view served VOLUME (not the G-ledger — that
    // would be tautological). Working ⇒ mean evicted served-rank well below 0.5.
    let world = run_small(2026, 110);
    let d = drop_ranking_metric(&world);
    assert!(
        d.events_scored > 0,
        "there must be scored eviction events under contention"
    );
    assert!(
        d.mean_evicted_served_rank < 0.45,
        "eviction must drop LOW-served owners first: mean served-rank {:.3} (want < 0.45)",
        d.mean_evicted_served_rank
    );
    assert!(
        d.frac_below_median > 0.6,
        "most drops must hit bottom-half served owners: {:.1}% (want > 60%)",
        d.frac_below_median * 100.0
    );
}

// ============================================================
// PHASE-1 §A — disk-profile layer-2 is GOD-VIEW only (anti-oracle extension)
// ============================================================

#[test]
fn first_hand_obs_is_bit_identical_when_only_disk_profile_differs() {
    // Anti-oracle extension (§A / §B): the layer-2 disk PROFILE (giver tier, own-data,
    // growth rate) is god-view ONLY. Two nodes identical in every observable but
    // differing in disk profile (tier/own-data/growth) must produce BIT-IDENTICAL
    // first-hand obs — there is nowhere on FirstHandObs to write a tier, so it cannot
    // leak (just like the archetype). The kernel sees only the legal `φ` scalar, which
    // is a NodeLocal field, not part of a peer observation.
    let cap = cap_with_history();
    let mut n_t1 = node_with(Archetype::Reliable);
    n_t1.disk = DiskProfile {
        tier: GiverTier::T1,
        own_data: 10.0,
        own_growth_per_tick: 0.001,
    };
    let mut n_t4 = node_with(Archetype::Reliable);
    n_t4.disk = DiskProfile {
        tier: GiverTier::T4,
        own_data: 90.0,
        own_growth_per_tick: 0.05,
    };
    let obs_t1 = observe_pair(&cap, &n_t1, DAYS_PER_TICK);
    let obs_t4 = observe_pair(&cap, &n_t4, DAYS_PER_TICK);
    // Bit-identical: the disk profile has nowhere to leak into the obs.
    assert_eq!(
        obs_t1, obs_t4,
        "disk profile (god-view layer-2) must NOT leak into first-hand obs"
    );
}

#[test]
fn giver_tier_mix_sums_to_n_and_spans_all_tiers() {
    // §A layer-2: the tier mix sums to n, is deterministic in the seed, and (at
    // reasonable n) spans all four tiers.
    let mix_a = giver_tier_mix(200, 7);
    let mix_b = giver_tier_mix(200, 7);
    assert_eq!(mix_a.len(), 200);
    assert_eq!(mix_a, mix_b, "tier mix must be deterministic in the seed");
    for t in GiverTier::ALL {
        assert!(
            mix_a.iter().filter(|&&x| x == t).count() >= 1,
            "{t:?} must be present in the mix"
        );
    }
    // A different seed reshuffles (assignment differs) but counts are the same multiset.
    let mut a_sorted = mix_a.clone();
    let mut c_sorted = giver_tier_mix(200, 999);
    a_sorted.sort_by_key(|t| *t as u8);
    c_sorted.sort_by_key(|t| *t as u8);
    assert_eq!(
        a_sorted, c_sorted,
        "tier COUNTS are seed-independent (only the assignment shuffles)"
    );
}
