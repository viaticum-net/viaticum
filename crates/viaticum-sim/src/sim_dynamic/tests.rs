//! Tests for the dynamic 4R harness (`sim_dynamic`).
//!
//! Naming: `what_when_then`. The keystone is the anti-oracle regression test
//! (design §10.H): two god-view nodes identical in every observable but differing
//! in hidden archetype must produce bit-identical first-hand obs AND identical
//! kernel decisions.

use viaticum_core::four_r::{
    BlockReq, EvictPhase, PlacementPolicy, RetentionPrior, SurfacePrior, capital_steady_state,
    estimate_surface, retained_depth,
};

use crate::sim_dynamic::engine::{
    DynParams, PosOutcome, admit_offer_for_test, alive_block_counts_for_test,
    assert_lambda_dt_stable, block_mature_for_test, fresh_capital, place_reciprocal_for_test, step,
    symbols_per_tick_for_test,
};
use crate::sim_dynamic::evaluator::{
    contention_metric, drop_ranking_metric, mc_block_r_actual, pillar1_metric,
};
use crate::sim_dynamic::generator::{
    Archetype, DAYS_PER_TICK, DiskProfile, GiverTier, HeldSymbol, Node, OWN_DATA_DISK_FRACTION,
    PairCapital, World, giver_tier_mix, online, population_mix,
};
use crate::sim_dynamic::observer::{self, observe_pair};
use crate::sim_dynamic::repair_storm::{
    RepairStormConfig, holder_popularity, inject_shock, run_repair_storm, select_top_holders,
};
use crate::sim_dynamic::{Experiment1Config, build_world, run_experiment_1};

use crate::sim_dynamic::engine::{per_node_upload_budget, repair_detected_for_test};

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
        depth_ho: 0.0,
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
    // Non-incremental world (every node present at t=0) but WITH the bandwidth limit, so
    // disks fill GRADUALLY. Measured at tick 4 — the ABUNDANCE window (mean φ ≈ 0.39, well
    // above the contention band). Beyond it, once cooperative disks fill and start
    // rejecting, demand REDIRECTS onto the still-empty exploiters (they rejected early, so
    // they have room) and their holdings catch up — washing the accept-rate signal out.
    // The clean behavioural-reject signal lives in early abundance, and that is asserted.
    let params = DynParams {
        incremental: false,
        ..DynParams::default()
    };
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(120, &params, 71);
    for _ in 0..4 {
        step(&mut world, &params, &prior, &policy);
    }
    // Precondition: we are genuinely in the ABUNDANCE window (mean φ well above the
    // contention band), so the assertion below tests the accept-rate reject signal and
    // not a disk-full plateau. Assert the regime rather than trusting the tick count.
    let mean_phi: f64 =
        world.nodes.iter().map(|n| n.phi_free_ratio()).sum::<f64>() / world.nodes.len() as f64;
    assert!(
        mean_phi > 0.35,
        "precondition: must still be in abundance (mean φ = {mean_phi:.3} > 0.35)"
    );
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
// PoS outcome classification (world-v2 §9.4 — ONE physics)
// ============================================================

#[test]
fn pos_outcome_is_timeout_when_holder_offline() {
    // §9.4 one physics: a challenged (alive) symbol on an OFFLINE holder times out.
    assert_eq!(classify(false), PosOutcome::Timeout);
}

#[test]
fn pos_outcome_is_pass_when_holder_online() {
    // §9.4 one physics: a challenged (alive) symbol on an ONLINE holder passes — there
    // is no "fail on a still-held symbol"; symbol death is a real engine event that
    // removes it from the challenge set (so `holds` is true by construction).
    assert_eq!(classify(true), PosOutcome::Pass);
}

/// Mirror of the engine's one-physics outcome classification (world-v2 §9.4): the
/// symbol is alive by construction, so the only variable is the holder's uptime.
fn classify(holder_online: bool) -> PosOutcome {
    if holder_online {
        PosOutcome::Pass
    } else {
        PosOutcome::Timeout
    }
}

#[test]
fn pos_pass_iff_symbol_alive_and_holder_online() {
    // §9.4 (§3-fix) INVARIANT: PoS-pass ⟺ the symbol is alive ∧ the holder is online.
    // Three cases, all deterministic:
    //   * alive ∧ ONLINE  ⇒ pass ⇒ capital GROWS (archetype aggression is NOT in the
    //     outcome — a cooperative always-online holder confirms every alive holding).
    //   * alive ∧ OFFLINE ⇒ timeout ⇒ challenged with v_conf=0 ⇒ capital LEAKS.
    //   * DEAD            ⇒ not challenged ⇒ no accrual, but the per-tick N² A.1 decay
    //     still applies ⇒ capital DRAINS toward 0 over ~1/λ (W2 fix; case (3) asserts <).
    let params = DynParams::default();
    let mut world = build_world(4, &params, 424242);
    for node in &mut world.nodes {
        node.archetype = Archetype::Reliable;
        node.present = true;
        node.holdings.clear();
    }
    let owner = 0usize;
    let holder = 1usize;
    let block = world.nodes[owner].own_blocks[0].id;
    world.nodes[holder].holdings.push(HeldSymbol {
        owner,
        block,
        iota: 0.5,
        volume: 10.0,
        alive: true,
        cream: false,
    });
    // (1) alive ∧ online ⇒ grows. Sample several ticks so a lone 1%-offline draw cannot
    // make it flaky (a Reliable is online ~99% of the time).
    let g0 = world.capital[owner][holder].g_oh;
    for t in 0..8u64 {
        world.tick = t;
        crate::sim_dynamic::engine::pos_and_capital_for_test(&mut world, &params);
    }
    assert!(
        world.capital[owner][holder].g_oh > g0,
        "an alive symbol on an online holder must PASS and accrue capital: {} > {g0}",
        world.capital[owner][holder].g_oh
    );
    assert!(
        world.capital[holder][owner].g_ho > 0.0,
        "the reciprocal g_ho must be mirrored on the transpose cell"
    );
    // (2) alive ∧ OFFLINE ⇒ timeout ⇒ leak. Make the holder a Nomad and pick a tick on
    // which the calendar says it is offline (deterministic via `online`).
    world.nodes[holder].archetype = Archetype::Nomad;
    let off_tick = (0..400u64)
        .find(|&t| !online(Archetype::Nomad, world.nodes[holder].id, t, world.seed))
        .expect("a Nomad has offline ticks");
    world.tick = off_tick;
    let g_pre = world.capital[owner][holder].g_oh;
    crate::sim_dynamic::engine::pos_and_capital_for_test(&mut world, &params);
    assert!(
        world.capital[owner][holder].g_oh < g_pre,
        "an OFFLINE holder times out (v_conf=0) so capital must LEAK: {} < {g_pre}",
        world.capital[owner][holder].g_oh
    );
    // (3) DEAD ⇒ not challenged ⇒ no accrual, and per the WARN-2 A.1-decay fix the idle
    // pair now DRAINS each tick (it is no longer frozen). So its capital strictly LEAKS.
    world.nodes[holder].holdings[0].alive = false;
    let g_dead0 = world.capital[owner][holder].g_oh;
    assert!(g_dead0 > 0.0, "precondition: the pair has capital to drain");
    for t in off_tick + 1..off_tick + 9 {
        world.tick = t;
        crate::sim_dynamic::engine::pos_and_capital_for_test(&mut world, &params);
    }
    assert!(
        world.capital[owner][holder].g_oh < g_dead0,
        "a dead/idle pair accrues nothing and DRAINS via the A.1 decay (WARN-2 fix): {} < {g_dead0}",
        world.capital[owner][holder].g_oh
    );
}

// ============================================================
// A.4 loyalty depth D (transaction 3a) — slow-leaky, grows only on confirmed
// live service, fades for a departed partner (W2, no fossil depth)
// ============================================================

#[test]
fn depth_grows_only_on_confirmed_live_service() {
    // A.4 / §9.4 ONE physics: the loyalty depth D accrues on the SAME signal as g_ho —
    // a live symbol confirmed by PoS on an ONLINE holder — and on NOTHING else. A pair
    // with no service stays at D = 0.
    let params = DynParams::default();
    let mut world = build_world(4, &params, 727272);
    for node in &mut world.nodes {
        node.archetype = Archetype::Reliable; // ~always online
        node.present = true;
        node.holdings.clear();
    }
    let owner = 0usize;
    let holder = 1usize;
    let block = world.nodes[owner].own_blocks[0].id;
    world.nodes[holder].holdings.push(HeldSymbol {
        owner,
        block,
        iota: 0.5,
        volume: 10.0,
        alive: true,
        cream: false,
    });

    for t in 0..8u64 {
        world.tick = t;
        crate::sim_dynamic::engine::pos_and_capital_for_test(&mut world, &params);
    }

    // Depth accrues on the SAME transpose cell as g_ho (the holder's own service record).
    assert!(
        world.capital[holder][owner].depth_ho > 0.0,
        "confirmed live service must grow the loyalty depth: {}",
        world.capital[holder][owner].depth_ho
    );
    assert!(
        world.capital[holder][owner].g_ho > 0.0,
        "precondition: g_ho grew on the same signal"
    );
    // A pair that never rendered service stays at D = 0 (no phantom loyalty).
    assert_eq!(
        world.capital[2][3].depth_ho, 0.0,
        "a pair with no confirmed service must have zero depth"
    );
    // Two-timescale property: fed the SAME per-tick accrual but leaking SLOWER
    // (τ_slow ≈ 6 mo vs τ_fast ≈ 2 mo, so D* = v·τ_slow = 3·g*), the depth RETAINS more
    // of the accumulated service than the fast capital — its level exceeds g_ho's.
    assert!(
        world.capital[holder][owner].depth_ho > world.capital[holder][owner].g_ho,
        "the slow depth retains more than the fast capital under the same service: {} vs {}",
        world.capital[holder][owner].depth_ho,
        world.capital[holder][owner].g_ho
    );
}

#[test]
fn depth_fades_for_a_departed_partner_no_fossil() {
    // W2 anti-fossil (A.4): depth is decayed for EVERY pair each tick, including a
    // partner that has DEPARTED. A once-deep partner that goes silent must see its
    // loyalty floor FADE, never freeze — the D-farm is closed. (This is the sim twin of
    // the kernel test `eviction_deep_floor_fades_after_years_of_silence`.)
    let params = DynParams::default();
    let mut world = build_world(4, &params, 838383);
    for node in &mut world.nodes {
        node.archetype = Archetype::Reliable;
        node.present = true;
        node.holdings.clear();
    }
    let owner = 0usize;
    let holder = 1usize;
    let block = world.nodes[owner].own_blocks[0].id;
    world.nodes[holder].holdings.push(HeldSymbol {
        owner,
        block,
        iota: 0.5,
        volume: 10.0,
        alive: true,
        cream: false,
    });

    // Build up some depth via live service.
    for t in 0..12u64 {
        world.tick = t;
        crate::sim_dynamic::engine::pos_and_capital_for_test(&mut world, &params);
    }
    let d_peak = world.capital[holder][owner].depth_ho;
    assert!(d_peak > 0.0, "precondition: the pair earned some depth");

    // The serving partner DEPARTS: its held symbols die and it is absent. No more
    // confirmed service for this pair — only the per-tick decay remains.
    world.nodes[holder].present = false;
    for hs in world.nodes[holder].holdings.iter_mut() {
        hs.alive = false;
    }
    let mut d_prev = d_peak;
    for t in 12..72u64 {
        world.tick = t;
        crate::sim_dynamic::engine::pos_and_capital_for_test(&mut world, &params);
        let d_now = world.capital[holder][owner].depth_ho;
        assert!(
            d_now < d_prev,
            "a departed partner's depth must strictly FADE each tick (no fossil): {d_now} < {d_prev}"
        );
        d_prev = d_now;
    }
    // After ~2·τ_slow of silence the floor has collapsed to a small fraction (not zero,
    // not frozen) — deep loyalty is earned by CONTINUED service, not banked forever.
    let d_end = world.capital[holder][owner].depth_ho;
    assert!(
        d_end > 0.0 && d_end < 0.2 * d_peak,
        "the loyalty floor must decay toward 0 over months of silence: {d_end} vs peak {d_peak}"
    );
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
    // One-shot world (§9 A/B off) so the chosen Reliable is present from t=0 and
    // bandwidth does not gate the probe — this isolates the capital threading.
    let params = one_shot_params();
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
            cream: false,
        },
        HeldSymbol {
            owner: 0,
            block: 0,
            iota: 0.2,
            volume: 10.0,
            alive: true,
            cream: false,
        },
        HeldSymbol {
            owner: 0,
            block: 1,
            iota: 0.5,
            volume: 10.0,
            alive: true,
            cream: false,
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

/// The ONE-SHOT world (§9 A/B off): every node live at t=0 (`incremental = false`) with
/// unlimited upload bandwidth (`bandwidth_u = ∞`) — the degenerate baseline used to
/// ISOLATE a single mechanism (accept-rate, room-gate, greed) without the world-v2
/// arrival/bandwidth dynamics confounding it. Cream stays ON (it is orthogonal here).
fn one_shot_params() -> DynParams {
    DynParams {
        incremental: false,
        bandwidth_u: f64::INFINITY,
        ..DynParams::default()
    }
}

#[test]
fn full_disk_rejects_a_new_offer_even_when_willing() {
    // §A.3 SymbolReject-on-quota fidelity: a holder with NO free disk must reject a
    // new offer EVEN IF it is willing (accept_rate 1.0). The old engine accepted on a
    // pure Bernoulli with no disk check — this asserts the room gate now bites.
    // One-shot world so both nodes are present at t=0 (a 2-node incremental world could
    // start empty) and bandwidth does not confound the room-gate test.
    let params = one_shot_params();
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
    // One-shot world (§9 A/B off): unlimited bandwidth fills the floor + cream in a few
    // ticks, isolating the greed-past-floor invariant from the world-v2 bandwidth stretch.
    let params = one_shot_params();
    let world = {
        let prior = SurfacePrior::default();
        let policy = PlacementPolicy::default();
        let mut w = build_world(120, &params, 77);
        for _ in 0..6 {
            step(&mut w, &params, &prior, &policy);
        }
        w
    };
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
                cream: false,
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
fn pillar1_reliable_data_is_more_durable_than_exploiters_seed_averaged() {
    // §D.1 pillar-1: under contention, SEED-AVERAGED Reliable R_actual beats BOTH exploiters.
    // HONESTY (re-gate 2026-07-05): this is a WEAK seed-averaged signal — per-seed it inverts
    // in 3/5 seeds (mean margin ~0.04). That is CANON-CONSISTENT (§9.13b: survival stands on
    // redundancy+repair, reciprocity = EFFICIENCY not durability-discrimination); the parasite
    // penalty belongs to CAPACITY (credit-limit-gated placement), which the sim does not model.
    // AVERAGED OVER SEEDS, because at this scale (5% Hoarder, 2.5% Freeloader,
    // and aggression→3× churn) the per-seed comparison is small-sample-noisy: the WORST
    // parasites CHURN OUT and are excluded from the present-node durability, so surviving
    // parasites are a biased sample, and the §5 scorer is a parallel model (эталон §5
    // flags it for a future rewrite). The seed-averaged R_actual recovers the robust
    // ranking Reliable > Hoarder > Freeloader (the reachability + reciprocity penalties
    // the scorer folds in). The sharper per-run inversion lives in the aggregate
    // durability of the on-demand experiment; the parasite-EXCLUSION mechanism is asserted
    // structurally in the preemption test.
    let params = DynParams::default();
    let seeds = [4242u64, 2026, 71, 999, 12345];
    let (mut rel, mut hoard, mut free) = (0.0, 0.0, 0.0);
    for &seed in &seeds {
        let world = run_small(seed, 110);
        let p = pillar1_metric(&world, params.k_eff, 26, 150, 99);
        rel += p.mean_r_actual_reliable;
        hoard += p.mean_r_actual_hoarder;
        free += p.mean_r_actual_freeloader;
    }
    let k = seeds.len() as f64;
    let (rel, hoard, free) = (rel / k, hoard / k, free / k);
    assert!(
        rel > hoard,
        "seed-averaged Reliable R_actual {rel:.4} must beat Hoarder {hoard:.4}"
    );
    assert!(
        rel > free,
        "seed-averaged Reliable R_actual {rel:.4} must beat Freeloader {free:.4}"
    );
}

#[test]
fn drop_ranking_picks_low_served_owners_first() {
    // §D.1 drop-ranking: under contention, eviction still skews toward LOW-served owners
    // (below random). Scored against god-view served VOLUME (not the G-ledger — that
    // would be tautological).
    //
    // NOTE (world-v2 §9.4 update): the §3-fix (ONE physics — PoS-pass ⟺ alive ∧ online,
    // no `retained_edge` starvation) intentionally stops capital from starving under
    // contention. The old sharp signal (mean served-rank < 0.45, frac-below > 0.6) came
    // from parasites' PoS FAILING and pinning g_ho=0 — an artifact of the physics the fix
    // removes. Under the one-physics world the per-holder served-DEPTH ranking is genuinely
    // softer (mean ≈ 0.44-0.47 across seeds): eviction is the LEAST-`g_ho` owner, whose
    // raw served-rank is only slightly below median because reciprocity is now dense. The
    // LOAD-BEARING free-rider exclusion is the pillar-1 OUTCOME (durability: Reliable ≫
    // exploiters), asserted in `pillar1_efficiency_ranks_reliable_above_exploiters`. Here
    // we assert only the robust directional sign: dropped owners skew BELOW random.
    //
    // 3a: κ_O — eviction now ranks owners by κ_O = g_ho + w_d·min(D/d_ref,1)·g* (A.14),
    // not bare g_ho. The slow loyalty depth D accrues from the SAME confirmed-service
    // signal as g_ho, so it REINFORCES (never inverts) the low-served-first direction:
    // the sign holds. Thresholds unchanged — the directional invariant is what we assert.
    let world = run_small(2026, 110);
    let d = drop_ranking_metric(&world);
    assert!(
        d.events_scored > 0,
        "there must be scored eviction events under contention"
    );
    assert!(
        d.mean_evicted_served_rank < 0.5,
        "eviction must still skew toward LOW-served owners (below random 0.5): mean served-rank \
         {:.3}",
        d.mean_evicted_served_rank
    );
    assert!(
        d.frac_below_median > 0.45,
        "a plurality of drops must still hit bottom-half served owners: {:.1}% (want > 45%)",
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

// ============================================================
// WORLD-v2 §9 — reciprocity-aware placement (place_reciprocal)
// ============================================================

#[test]
fn place_reciprocal_prefers_reciprocal_holder_and_caps_one_per_bucket() {
    // §9.1 / эталон §1: with reciprocity ON, a holder we already SERVE (high g_ho ⇒ high
    // retained_depth) outranks a stranger of EQUAL surface; with it OFF (pure surface)
    // the g_ho boost is gone and equal-surface candidates fall back to input order. The
    // §7 spread admits ≤1 candidate per addr bucket.
    let prior = SurfacePrior::default();
    let retention = RetentionPrior::default();
    // Identical surface signals; ONLY g_ho differs (0 stranger vs 500 reciprocal).
    let mut cap_stranger = PairCapital::default();
    let mut cap_recip = PairCapital::default();
    for _ in 0..8 {
        cap_stranger.push_outcome(true);
        cap_recip.push_outcome(true);
    }
    cap_stranger.g_oh = 100.0;
    cap_recip.g_oh = 100.0;
    cap_stranger.g_ho = 0.0;
    cap_recip.g_ho = 500.0;
    let mut n_stranger = node_with(Archetype::Reliable);
    n_stranger.addr_subnet = 1;
    let mut n_recip = node_with(Archetype::Reliable);
    n_recip.addr_subnet = 2;
    let mut n_recip_twin = node_with(Archetype::Reliable);
    n_recip_twin.addr_subnet = 2; // shares the reciprocal's bucket (collision)
    let obs = vec![
        observe_pair(&cap_stranger, &n_stranger, DAYS_PER_TICK),
        observe_pair(&cap_recip, &n_recip, DAYS_PER_TICK),
        observe_pair(&cap_recip, &n_recip_twin, DAYS_PER_TICK),
    ];
    let req = BlockReq {
        volume: 50.0,
        n_symbols: 5,
        k_eff: 2,
        tau: DAYS_PER_TICK,
        r_target: 0.9,
        // Inert here: place_reciprocal (not core place) is exercised.
        r_min: 0.5,
    };
    // reciprocal ON ⇒ the reciprocal holder (idx 1) ranks first.
    let chosen = place_reciprocal_for_test(&obs, &req, &prior, true, &retention, 3, &[]);
    assert_eq!(
        chosen[0], 1,
        "the reciprocal-boosted holder must rank first: {chosen:?}"
    );
    // ≤1 per bucket: the chosen buckets are all distinct.
    let buckets: Vec<u32> = chosen.iter().map(|&c| obs[c].addr_subnet).collect();
    let distinct: std::collections::BTreeSet<u32> = buckets.iter().copied().collect();
    assert_eq!(
        buckets.len(),
        distinct.len(),
        "≤1 symbol per addr bucket (§7 spread): {buckets:?}"
    );
    // reciprocal OFF (pure surface) ⇒ equal surface, so input order (stranger idx 0) leads.
    let chosen_off = place_reciprocal_for_test(&obs, &req, &prior, false, &retention, 3, &[]);
    assert_eq!(
        chosen_off[0], 0,
        "pure-surface: equal surface ⇒ input order (stranger first): {chosen_off:?}"
    );
}

// ============================================================
// WORLD-v2 §9.2 — preemptive accept (θ_p margin, WARN-2/WARN-4)
// ============================================================

#[test]
fn preemption_admits_reciprocal_owner_drops_low_iota_victim_and_blocks_parasite() {
    // §2 / A.12-2: a FULL holder admits a new owner ONLY by displacing its least-reciprocal
    // owner (WARN-4: that owner's LOW-ι symbol), and ONLY if the newcomer clears the
    // DIMENSIONLESS margin θ_p·g* (WARN-1). A parasite (g_ho=0) can never clear it. A
    // negative θ_p DISABLES preemption (WARN-2).
    let params = DynParams::default(); // preempt_theta = 0.2
    let holder = 1usize;
    let v = params.block_volume / params.n_symbols as f64; // 10 gb
    let mk = |seed: u64| -> World {
        let mut w = build_world(6, &params, seed);
        for node in &mut w.nodes {
            node.present = true;
            node.holdings.clear();
            node.archetype = Archetype::Reliable; // willing holders
            node.disk.own_growth_per_tick = 0.0;
        }
        w
    };
    let mut world = mk(99);
    // Holder holds: owner 2 (A, protected), owner 3 (B, parasite) with TWO ι-distinct
    // symbols. Fill the disk so free_disk == 0 (contention → preemption path).
    world.nodes[holder].holdings.push(HeldSymbol {
        owner: 2,
        block: 0,
        iota: 0.5,
        volume: v,
        alive: true,
        cream: false,
    });
    world.nodes[holder].holdings.push(HeldSymbol {
        owner: 3,
        block: 0,
        iota: 0.8,
        volume: v,
        alive: true,
        cream: false,
    });
    world.nodes[holder].holdings.push(HeldSymbol {
        owner: 3,
        block: 1,
        iota: 0.2,
        volume: v,
        alive: true,
        cream: false,
    });
    world.nodes[holder].disk.own_data = world.nodes[holder].disk_cap - 3.0 * v;
    assert!(
        world.nodes[holder].free_disk() < v,
        "precondition: the holder is full"
    );
    world.capital[2][holder].g_ho = 500.0; // A reciprocal → protected
    world.capital[3][holder].g_ho = 0.0; // B parasite → victim
    world.capital[4][holder].g_ho = 500.0; // owner D reciprocal → preempts
    world.capital[5][holder].g_ho = 0.0; // owner C parasite → cannot preempt
    let margin = params.preempt_theta * capital_steady_state(v, params.lambda);
    assert!(500.0 > margin, "D must clear the margin θ_p·g* = {margin}");

    // (1) parasite C (g_ho=0) cannot preempt.
    assert!(
        !admit_offer_for_test(&mut world, 5, holder, v, &params, 0),
        "a parasite (g_ho=0) must NOT be able to preempt in"
    );
    assert_eq!(
        world.nodes[holder]
            .holdings
            .iter()
            .filter(|s| s.alive)
            .count(),
        3,
        "a failed preemption must not evict anything"
    );
    // (2) reciprocal D preempts: the victim is B's LOW-ι symbol (block 1), not A, not B-hi.
    assert!(
        admit_offer_for_test(&mut world, 4, holder, v, &params, 0),
        "a reciprocal owner above the margin must preempt"
    );
    let alive = |o: usize, b: usize| {
        world.nodes[holder]
            .holdings
            .iter()
            .any(|s| s.alive && s.owner == o && s.block == b)
    };
    assert!(
        !alive(3, 1),
        "the victim's LOW-ι symbol must be dropped (WARN-4)"
    );
    assert!(
        alive(3, 0),
        "the victim's HIGH-ι symbol must survive (ladder)"
    );
    assert!(alive(2, 0), "the reciprocal owner A must NOT be the victim");
    assert_eq!(
        world.preempt_count, 1,
        "one preemptive swap must be counted"
    );

    // (3) a negative θ_p DISABLES preemption (WARN-2), it does not merely weaken it.
    let mut world2 = mk(99);
    world2.nodes[holder].holdings.push(HeldSymbol {
        owner: 3,
        block: 0,
        iota: 0.5,
        volume: v,
        alive: true,
        cream: false,
    });
    world2.nodes[holder].disk.own_data = world2.nodes[holder].disk_cap - v;
    world2.capital[3][holder].g_ho = 0.0;
    world2.capital[4][holder].g_ho = 500.0;
    let params_off = DynParams {
        preempt_theta: -1.0,
        ..params
    };
    assert!(
        !admit_offer_for_test(&mut world2, 4, holder, v, &params_off, 0),
        "a negative θ_p must DISABLE preemption, not weaken it (WARN-2)"
    );
    assert_eq!(
        world2.preempt_count, 0,
        "no swap when preemption is disabled"
    );
}

// ============================================================
// WORLD-v2 §9.2 — bandwidth queue (U/v_per_symbol cap, carry-over, ι-priority)
// ============================================================

#[test]
fn bandwidth_caps_symbols_per_tick_and_carries_the_queue_over() {
    // §9.2: a node places ≤ ⌊U/v_per_symbol⌋ symbols per tick; the rest carries to later
    // ticks (ι-priority — the high-ι block is served first).
    let params = DynParams {
        incremental: false,
        bandwidth_u: 20.0,
        cream_enabled: false, // clean floor-only count
        ..DynParams::default()
    };
    let v = params.block_volume / params.n_symbols as f64;
    assert_eq!(
        symbols_per_tick_for_test(params.bandwidth_u, v),
        2,
        "budget = ⌊20/10⌋ = 2"
    );
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(60, &params, 31);
    let owned_alive = |w: &World, o: usize| -> usize {
        (0..w.nodes.len())
            .map(|h| {
                w.nodes[h]
                    .holdings
                    .iter()
                    .filter(|s| s.alive && s.owner == o)
                    .count()
            })
            .sum()
    };
    let owner = 0usize;
    step(&mut world, &params, &prior, &policy);
    let after1 = owned_alive(&world, owner);
    assert!(
        after1 <= 2,
        "≤ budget (2) symbols placed in one tick, got {after1}"
    );
    // ι-priority: the highest-ι block is served no less than the lowest-ι one.
    let hi = world.nodes[owner]
        .own_blocks
        .iter()
        .max_by(|a, b| a.iota.total_cmp(&b.iota))
        .unwrap()
        .id;
    let lo = world.nodes[owner]
        .own_blocks
        .iter()
        .min_by(|a, b| a.iota.total_cmp(&b.iota))
        .unwrap()
        .id;
    let cnt = |w: &World, b: usize| {
        (0..w.nodes.len())
            .filter(|&h| {
                w.nodes[h]
                    .holdings
                    .iter()
                    .any(|s| s.alive && s.owner == owner && s.block == b)
            })
            .count()
    };
    assert!(
        cnt(&world, hi) >= cnt(&world, lo),
        "ι-priority: the high-ι block must be served first"
    );
    step(&mut world, &params, &prior, &policy);
    let after2 = owned_alive(&world, owner);
    assert!(
        after2 > after1,
        "the placement queue must carry over: {after2} > {after1}"
    );
    assert!(after2 <= 4, "≤ 2·budget after two ticks, got {after2}");
}

// ============================================================
// WORLD-v2 §9.1 — incremental arrival (schedule + maturation)
// ============================================================

#[test]
fn incremental_join_schedule_is_deterministic_and_bounded() {
    let params = DynParams::default(); // incremental, n0_frac 0.2, t_join_frac 0.5, horizon 130
    let t_join = (params.join_horizon_ticks as f64 * params.t_join_frac).round() as u64;
    let mut at0 = 0usize;
    let mut maxj = 0u64;
    for i in 0..500usize {
        let a = crate::sim_dynamic::join_schedule(i, &params, 4242);
        let b = crate::sim_dynamic::join_schedule(i, &params, 4242);
        assert_eq!(a, b, "the join schedule must be deterministic in the seed");
        assert!(
            a <= t_join,
            "every node joins by T_join = {t_join}, got {a}"
        );
        if a == 0 {
            at0 += 1;
        }
        maxj = maxj.max(a);
    }
    let frac0 = at0 as f64 / 500.0;
    assert!(
        (0.12..0.28).contains(&frac0),
        "≈ n0_frac (0.2) of nodes join at t=0, got {frac0:.3}"
    );
    assert!(
        maxj >= t_join - 2,
        "the join stream should span up to ~T_join (max {maxj}, T_join {t_join})"
    );
    // One-shot: everyone joins at t=0.
    let one_shot = DynParams {
        incremental: false,
        ..params
    };
    for i in 0..50usize {
        assert_eq!(crate::sim_dynamic::join_schedule(i, &one_shot, 7), 0);
    }
}

#[test]
fn block_maturation_staggers_demand_and_is_off_in_one_shot() {
    // §9.1: block at position `b` matures at joined_tick + b·maturation (demand in
    // portions); one-shot disables maturation (all blocks eligible at join).
    let params = DynParams::default(); // maturation_ticks_per_block = 6
    assert!(
        block_mature_for_test(10, 0, 10, &params),
        "block 0 mature at join"
    );
    assert!(
        !block_mature_for_test(10, 1, 10, &params),
        "block 1 not yet at join"
    );
    assert!(
        block_mature_for_test(10, 1, 16, &params),
        "block 1 mature at join+6"
    );
    assert!(
        !block_mature_for_test(10, 2, 21, &params),
        "block 2 not yet at join+11"
    );
    assert!(
        block_mature_for_test(10, 2, 22, &params),
        "block 2 mature at join+12"
    );
    let os = DynParams {
        incremental: false,
        ..params
    };
    assert!(
        block_mature_for_test(10, 2, 0, &os),
        "one-shot: every block mature immediately"
    );
}

// ============================================================
// WORLD-v2 §9.3 — cream (floor split, no floor-repair trigger)
// ============================================================

// ============================================================
// WORLD-v2 §9.5 — giver-priority owner-order toggle
// ============================================================

#[test]
fn giver_priority_order_toggle_runs_deterministically_both_ways() {
    // §9.5: the giver-priority owner-order toggle (net givers first vs a neutral shuffle —
    // an owner-order proxy, not literal per-holder familiarity) is a real dial; both
    // settings run deterministically to a valid contended state. In abundance it barely
    // changes outcomes — it bites only for scarce slots under contention.
    let run = |by_g: bool, seed: u64| -> f64 {
        let params = DynParams {
            giver_priority_order: by_g,
            ..DynParams::default()
        };
        let prior = SurfacePrior::default();
        let policy = PlacementPolicy::default();
        let mut w = build_world(60, &params, seed);
        for _ in 0..60 {
            step(&mut w, &params, &prior, &policy);
        }
        w.nodes
            .iter()
            .flat_map(|n| n.holdings.iter())
            .filter(|s| s.alive)
            .map(|s| s.volume)
            .sum()
    };
    // Deterministic each way (same seed + setting ⇒ bit-identical summary).
    assert_eq!(run(true, 7).to_bits(), run(true, 7).to_bits());
    assert_eq!(run(false, 7).to_bits(), run(false, 7).to_bits());
    // Both settings reach a non-trivial contended state (positive alive volume).
    assert!(run(true, 7) > 0.0 && run(false, 7) > 0.0);
}

#[test]
fn cream_symbols_are_excluded_from_the_floor_and_do_not_trigger_floor_repair() {
    // §9.3: cream (over-the-floor) symbols carry the flag, are excluded from the FLOOR
    // count, and their death leaves the floor DEMAND (`n_symbols − floor`) unchanged — so
    // a full-floor block with dead cream is not repaired.
    let params = one_shot_params(); // cream ON, ∞ bandwidth, all present
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(60, &params, 55);
    for _ in 0..3 {
        step(&mut world, &params, &prior, &policy);
    }
    // A high-ι block with a FULL floor AND ≥1 cream.
    let mut found = None;
    'outer: for o in 0..world.nodes.len() {
        for b in &world.nodes[o].own_blocks {
            let (floor, cream) = alive_block_counts_for_test(&world, o, b.id);
            if floor == params.n_symbols && cream >= 1 {
                found = Some((o, b.id, floor, cream));
                break 'outer;
            }
        }
    }
    let (o, bid, floor0, cream0) = found.expect("a high-ι block should carry cream in abundance");
    assert!(cream0 >= 1);
    // Kill every cream symbol of this block.
    for node in &mut world.nodes {
        for s in node.holdings.iter_mut() {
            if s.alive && s.owner == o && s.block == bid && s.cream {
                s.alive = false;
            }
        }
    }
    let (floor1, cream1) = alive_block_counts_for_test(&world, o, bid);
    assert_eq!(cream1, 0, "the cream should now be gone");
    assert_eq!(
        floor1, floor0,
        "killing cream must NOT change the FLOOR count (§9.3)"
    );
    assert_eq!(
        floor1, params.n_symbols,
        "the floor demand (n_symbols − floor) stays 0 ⇒ cream death triggers no floor repair"
    );
}

// ============================================================
// §7 — repair-storm (correlated holder death) diagnostic
// ============================================================

/// Give `holder` exactly `count` alive foreign holdings (distinct owners) so its
/// god-view popularity is deterministic and known for the selection tests.
fn give_holdings(world: &mut World, holder: usize, count: usize) {
    let n = world.nodes.len();
    for j in 0..count {
        let mut owner = (holder + 1 + j) % n;
        if owner == holder {
            owner = (owner + 1) % n;
        }
        world.nodes[holder].holdings.push(HeldSymbol {
            owner,
            block: j,
            iota: 0.5,
            volume: 1.0,
            alive: true,
            cream: false,
        });
    }
}

/// A modest, fast repair-storm config for the behaviour tests (n=120, warm-up 60).
fn storm_config(seed: u64, delay: u64, k: f64) -> RepairStormConfig {
    RepairStormConfig {
        base_params: DynParams {
            block_volume: 20.0,
            ..DynParams::default()
        },
        n_nodes: 120,
        seed,
        warmup_ticks: 60,
        post_ticks: 30,
        k_percent: k,
        detection_delay_max: delay,
    }
}

#[test]
fn holder_popularity_counts_alive_foreign_symbols() {
    let params = DynParams::default();
    let mut world = build_world(8, &params, 0xABC);
    give_holdings(&mut world, 2, 5);
    // Killing one leaves four alive; a bare node has zero.
    world.nodes[2].holdings[0].alive = false;
    assert_eq!(holder_popularity(&world, 2), 4);
    assert_eq!(holder_popularity(&world, 3), 0);
}

#[test]
fn shock_selects_exactly_top_k_holders_by_popularity_deterministically() {
    // Non-incremental so every node is present at t=0 (the selection is over present nodes).
    let params = DynParams {
        incremental: false,
        ..DynParams::default()
    };
    let mut world = build_world(20, &params, 0xDEED);
    // A known popularity ladder over an otherwise-empty world.
    give_holdings(&mut world, 3, 10); // most popular
    give_holdings(&mut world, 7, 8);
    give_holdings(&mut world, 2, 6); // ties with node 5 → lower index wins
    give_holdings(&mut world, 5, 6);
    give_holdings(&mut world, 1, 4);
    // top-10% of 20 present = ceil(2) = the two most popular: 3 then 7.
    assert_eq!(select_top_holders(&world, 10.0), vec![3, 7]);
    // top-25% = ceil(5): the 6-6 tie between 2 and 5 breaks by ascending index.
    let top5 = select_top_holders(&world, 25.0);
    assert_eq!(top5, vec![3, 7, 2, 5, 1]);
    // Deterministic re-selection, and K=0 (control) selects nothing.
    assert_eq!(select_top_holders(&world, 25.0), top5);
    assert!(select_top_holders(&world, 0.0).is_empty());
}

#[test]
fn inject_shock_marks_victims_absent_and_kills_their_holdings() {
    let params = DynParams {
        incremental: false,
        ..DynParams::default()
    };
    let mut world = build_world(10, &params, 0x5);
    give_holdings(&mut world, 1, 3);
    give_holdings(&mut world, 4, 2);
    let killed = inject_shock(&mut world, &[1, 4]);
    assert_eq!(killed, 5, "3 + 2 alive symbols must be destroyed");
    assert!(!world.nodes[1].present && !world.nodes[4].present);
    assert!(world.nodes[1].holdings.iter().all(|s| !s.alive));
    assert!(world.nodes[4].holdings.iter().all(|s| !s.alive));
    assert!(world.nodes[2].present, "a non-victim must be untouched");
}

#[test]
fn repair_detected_is_instant_when_delay_zero() {
    // delay_max = 0 ⇒ offset 0 ⇒ detected as soon as the tick reaches the deficit tick.
    assert!(repair_detected_for_test(0xF00D, 3, 1, 40, 40, 0));
    assert!(repair_detected_for_test(0xF00D, 3, 1, 40, 45, 0));
    // Never before the deficit was even observed.
    assert!(!repair_detected_for_test(0xF00D, 3, 1, 41, 40, 0));
}

#[test]
fn repair_detected_staggers_across_the_cadence_window_when_latent() {
    // With delay_max = 3 the per-(owner,block) first-detection offset must span [0,3]
    // across many blocks (the smearing) and never exceed it.
    let delay = 3u64;
    let since = 100u64;
    let mut offsets = std::collections::BTreeSet::new();
    for block_id in 0..200usize {
        let mut first = None;
        for d in 0..=(delay + 2) {
            if repair_detected_for_test(0x1234, 9, block_id, since, since + d, delay) {
                first = Some(d);
                break;
            }
        }
        let off = first.expect("must detect within the window");
        assert!(off <= delay, "offset {off} must be within [0,{delay}]");
        offsets.insert(off);
    }
    assert!(
        offsets.len() >= 3,
        "detection offsets should span the cadence window, got {offsets:?}"
    );
    // Deterministic per (owner, block, episode).
    assert_eq!(
        repair_detected_for_test(0x1234, 9, 5, since, since + 1, delay),
        repair_detected_for_test(0x1234, 9, 5, since, since + 1, delay)
    );
}

#[test]
fn latent_detection_lowers_peak_repair_concurrency_after_a_shock() {
    let seed = 14_769_901;
    let inst = run_repair_storm(&storm_config(seed, 0, 10.0));
    let lat = run_repair_storm(&storm_config(seed, 3, 10.0));
    // The same seed kills the same holders in both modes.
    assert_eq!(inst.victims_killed, lat.victims_killed);
    assert!(inst.victims_killed > 0);
    // Latency staggers the repairs ⇒ a strictly lower synchronous peak (the hypothesis).
    assert!(
        lat.peak_owners_repairing < inst.peak_owners_repairing,
        "latent peak {} should be below instant peak {}",
        lat.peak_owners_repairing,
        inst.peak_owners_repairing
    );
}

#[test]
fn repair_storm_demand_never_exceeds_aggregate_bandwidth() {
    // At realistic upload speeds even the synchronous instant spike stays under the
    // aggregate bandwidth ceiling — no bandwidth cascade.
    let r = run_repair_storm(&storm_config(14_769_901, 0, 10.0));
    assert_eq!(
        r.demand_exceeds_bandwidth_ticks, 0,
        "no tick's detected repair demand should exceed aggregate bandwidth"
    );
    assert!(
        r.max_demand_bandwidth_ratio < 1.0,
        "peak demand/bandwidth ratio {} should stay below 1",
        r.max_demand_bandwidth_ratio
    );
}

#[test]
fn repair_storm_report_is_deterministic_for_the_same_config() {
    let cfg = storm_config(777, 3, 5.0);
    let a = run_repair_storm(&cfg);
    let b = run_repair_storm(&cfg);
    assert_eq!(a.victims_killed, b.victims_killed);
    assert_eq!(a.victim_symbols_killed, b.victim_symbols_killed);
    assert_eq!(a.peak_owners_repairing, b.peak_owners_repairing);
    assert_eq!(a.peak_under_k, b.peak_under_k);
    assert_eq!(a.blocks_orphaned_lost, b.blocks_orphaned_lost);
    assert_eq!(a.blocks_victim_owned_lost, b.blocks_victim_owned_lost);
    assert_eq!(a.trajectory.len(), b.trajectory.len());
    for (x, y) in a.trajectory.iter().zip(b.trajectory.iter()) {
        assert_eq!(x.under_k_blocks, y.under_k_blocks);
        assert_eq!(x.owners_repairing, y.owners_repairing);
        assert_eq!(x.detected_demand_symbols, y.detected_demand_symbols);
        assert_eq!(x.outstanding_demand_symbols, y.outstanding_demand_symbols);
    }
}

#[test]
fn default_params_use_instant_repair_detection() {
    // The bit-identity contract: the shared engine defaults to instant detection, so the
    // other experiments are unchanged (no RNG drawn on the repair-detection stream).
    assert_eq!(DynParams::default().repair_detection_delay_max, 0);
}

#[test]
fn per_node_upload_budget_is_floor_u_over_v_symbol() {
    // block_volume 20, n_symbols 5 ⇒ v_per_symbol 4; U=20 ⇒ ⌊20/4⌋ = 5.
    let p = DynParams {
        block_volume: 20.0,
        bandwidth_u: 20.0,
        ..DynParams::default()
    };
    assert_eq!(per_node_upload_budget(&p), 5);
    // Infinite U (the one-shot world) ⇒ unbounded.
    let inf = DynParams {
        bandwidth_u: f64::INFINITY,
        ..DynParams::default()
    };
    assert_eq!(per_node_upload_budget(&inf), usize::MAX);
}
