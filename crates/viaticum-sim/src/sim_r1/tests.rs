//! SIM-R1 tests — the three structural claims plus anti-oracle litmus.

use super::*;
use crate::sim_r1::generator::{Archetype, Dial, SimR1Holder, SimR1Pop};
use viaticum_core::four_r::{
    BlockReq, HolderPlacement, PlacementPolicy, RetentionPrior, SurfacePrior,
    estimate_block_survival_per_symbol,
};

#[test]
fn sim_r1_forecast_is_conservative_across_dials() {
    // Claim 1: the per-symbol forecast block-R̂ never exceeds the actual god-view
    // survival fraction (the safe side), for EVERY swept dial.
    let report = run(42);
    assert!(
        report.claim_conservative,
        "forecast must be ≤ actual survival for every dial: {:#?}",
        report.rows
    );
}

#[test]
fn sim_r1_high_iota_symbols_actually_survive_more() {
    // Claim 2: in god-view, a block of high-ι symbols survives more than the same
    // block of low-ι symbols (eviction drops lowest-ι first), for EVERY dial.
    let report = run(42);
    assert!(
        report.claim_ordering,
        "high-ι symbols must actually survive more than low-ι: {:#?}",
        report.rows
    );
}

#[test]
fn sim_r1_per_symbol_beats_aggregate_across_dials() {
    // Claim 3: the per-symbol forecast is closer to actual than the
    // per-holder-average aggregate (which goes optimistic on the bottom rung),
    // while staying conservative, for EVERY dial.
    let report = run(42);
    assert!(
        report.claim_per_symbol_beats_aggregate,
        "per-symbol must beat the aggregate-per-holder-average forecast: {:#?}",
        report.rows
    );
}

#[test]
fn sim_r1_passes_under_multiple_seeds() {
    // Dial-robustness: the structural sign must not depend on the RNG seed either.
    for seed in [1u64, 7, 42, 100, 2024] {
        let report = run(seed);
        assert!(
            report.pass,
            "SIM-R1 must PASS for seed {seed}: conservative={} ordering={} beats_agg={}",
            report.claim_conservative,
            report.claim_ordering,
            report.claim_per_symbol_beats_aggregate
        );
    }
}

#[test]
fn sim_r1_forecast_is_bit_identical_for_holders_differing_only_in_hidden_archetype() {
    // ANTI-ORACLE: build two populations identical in every OBSERVABLE field but
    // differing ONLY in the hidden `archetype`. The per-symbol forecast must be
    // bit-for-bit identical — the kernel has no field for the archetype, so the
    // hidden axis is structurally unreachable.
    let prior = SurfacePrior::default();
    let retention = RetentionPrior::default();
    let policy = PlacementPolicy::default();

    let make_pop = |arch: Archetype| -> SimR1Pop {
        let holders = (0..6)
            .map(|i| SimR1Holder {
                master: i as u8,
                subnet: i as u32,
                true_g_holder_from_owner: 4.0,
                // The hidden ground-truth fields below would change the EVALUATOR's
                // measured survival, but they are NEVER observed by the kernel.
                true_surface: 0.9,
                true_keep_depth: 0.5,
                observed_drop_frac: 0.1, // identical observable signal in both pops
                ladder_iotas: vec![0.2, 0.5, 0.8],
                archetype: arch, // the ONLY difference
            })
            .collect();
        SimR1Pop { holders }
    };

    let pop_a = make_pop(Archetype::Generous);
    let pop_b = make_pop(Archetype::Flaky);

    let req = BlockReq {
        volume: 60.0,
        n_symbols: 6,
        k_eff: 3,
        tau: 30.0,
        r_target: 0.99,
    };

    let plc_a: Vec<HolderPlacement> = observer::observe_all(&pop_a, 1);
    let plc_b: Vec<HolderPlacement> = observer::observe_all(&pop_b, 1);

    let r_a = estimate_block_survival_per_symbol(&plc_a, &prior, &retention, &req, &policy);
    let r_b = estimate_block_survival_per_symbol(&plc_b, &prior, &retention, &req, &policy);

    assert_eq!(
        r_a.to_bits(),
        r_b.to_bits(),
        "forecast must be bit-identical when only the hidden archetype differs: a={r_a} b={r_b}"
    );
}

#[test]
fn sim_r1_observer_writes_only_observable_fields() {
    // Sanity: a Flaky archetype with high drops and a Generous one with none, but
    // OTHERWISE identical observables, must shadow into DIFFERENT obs ONLY because
    // their observable drop-fraction differs — never because of the archetype.
    let flaky = SimR1Holder {
        master: 0,
        subnet: 0,
        true_g_holder_from_owner: 4.0,
        true_surface: 0.9,
        true_keep_depth: 0.5,
        observed_drop_frac: 0.3,
        ladder_iotas: vec![0.2, 0.8],
        archetype: Archetype::Flaky,
    };
    let obs = observer::observe(&flaky);
    // The observed drop fraction must appear in the PoS record (30% of 100 rounds).
    assert_eq!(obs.pos_fail, 30);
    assert_eq!(obs.pos_pass, 70);
    // Standing is shadowed verbatim (first-hand, bilaterally observable).
    assert_eq!(obs.g_holder_from_owner, 4.0);
}

#[test]
fn sim_r1_evaluator_drops_bottom_rung_under_contention() {
    // god-view sanity: a fully-alive holder (true_surface=1) that keeps only the
    // TOP half of the ladder (true_keep_depth=0.5) must KEEP the top rung and DROP
    // the bottom rung — the two-level eviction rule realised by the evaluator.
    let pop = SimR1Pop {
        holders: vec![SimR1Holder {
            master: 0,
            subnet: 0,
            true_g_holder_from_owner: 8.0,
            true_surface: 1.0,    // never hardware-dies
            true_keep_depth: 0.5, // keeps the top half of the ladder
            observed_drop_frac: 0.0,
            ladder_iotas: vec![0.1, 0.9], // edge at rank 0.5: bottom (0.0) dropped, top (1.0) kept
            archetype: Archetype::Generous,
        }],
    };
    let bottom = evaluator::actual_symbol_survival(&pop, 0, 0, 1000, 1);
    let top = evaluator::actual_symbol_survival(&pop, 0, 1, 1000, 1);
    assert!(bottom < 0.01, "bottom rung must be evicted: {bottom}");
    assert!(top > 0.99, "top rung must be kept: {top}");
}

#[test]
fn sim_r1_build_is_deterministic_for_a_seed() {
    let dial = Dial {
        n_holders: 8,
        ladder_len: 4,
        mean_surface: 0.9,
        mean_keep_depth: 0.5,
    };
    let a = SimR1Pop::build(dial, 123);
    let b = SimR1Pop::build(dial, 123);
    assert_eq!(a.holders.len(), b.holders.len());
    for (x, y) in a.holders.iter().zip(b.holders.iter()) {
        assert_eq!(x.true_g_holder_from_owner, y.true_g_holder_from_owner);
        assert_eq!(x.true_surface, y.true_surface);
        assert_eq!(x.true_keep_depth, y.true_keep_depth);
    }
}
