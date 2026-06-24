use super::*;
use crate::sim6::evaluator::{block_survives_farm_drop, farm_positions_taken};
use crate::sim6::generator::Sim6Pop;
use crate::sim6::observer;

// ============================================================
// Generator — hidden ground-truth shape.
// ============================================================

#[test]
fn generator_places_honest_on_distinct_subnets_and_farm_on_few() {
    let dial = Dial {
        n_symbols: 6,
        k_eff: 3,
        honest_holders: 10,
        farm_masters: 40,
    };
    let pop = Sim6Pop::build(dial, 2, 42);
    let honest: Vec<_> = pop.holders.iter().filter(|h| !h.is_farm).collect();
    let farm: Vec<_> = pop.holders.iter().filter(|h| h.is_farm).collect();
    assert_eq!(honest.len(), 10);
    assert_eq!(farm.len(), 40);
    // Honest subnets are all distinct.
    let mut honest_subnets: Vec<u32> = honest.iter().map(|h| h.subnet).collect();
    honest_subnets.sort_unstable();
    honest_subnets.dedup();
    assert_eq!(
        honest_subnets.len(),
        10,
        "honest holders must be on distinct subnets"
    );
    // Farm spans exactly `farm_subnets` distinct subnets.
    let mut farm_subnets: Vec<u32> = farm.iter().map(|h| h.subnet).collect();
    farm_subnets.sort_unstable();
    farm_subnets.dedup();
    assert_eq!(
        farm_subnets.len(),
        2,
        "farm must be confined to the requested subnet count"
    );
    // Farm master-ids are all distinct (cheap key-minting).
    let mut farm_masters: Vec<u32> = farm.iter().map(|h| h.master).collect();
    farm_masters.sort_unstable();
    farm_masters.dedup();
    assert_eq!(farm_masters.len(), 40, "farm mints distinct master-ids");
}

#[test]
fn generator_keeps_honest_and_farm_subnet_spaces_disjoint() {
    let dial = Dial {
        n_symbols: 8,
        k_eff: 4,
        honest_holders: 20,
        farm_masters: 50,
    };
    let pop = Sim6Pop::build(dial, 3, 7);
    for h in &pop.holders {
        if h.is_farm {
            assert!(
                h.subnet >= 1_000_000,
                "farm subnet must be in the farm id-space"
            );
        } else {
            assert!(
                h.subnet < 1_000_000,
                "honest subnet must be in the honest id-space"
            );
        }
    }
}

// ============================================================
// Observer — the anti-oracle boundary.
// ============================================================

#[test]
fn observer_exposes_subnet_and_master_but_no_farm_signal() {
    // The observed FirstHandObs carries the subnet (observable) and clean PoS, and
    // there is structurally NO field for `is_farm` — the type itself enforces the
    // anti-oracle. We assert the observable surface is IDENTICAL for a farm holder
    // and an honest holder with the same subnet, so the ONLY distinguishing
    // observable is the subnet correlate (which the cap uses), never farm-identity.
    let honest = crate::sim6::generator::Sim6Holder {
        master: 5,
        subnet: 5,
        is_farm: false,
    };
    let farm = crate::sim6::generator::Sim6Holder {
        master: 5,
        subnet: 5,
        is_farm: true,
    };
    let o_honest = observer::observe(&honest);
    let o_farm = observer::observe(&farm);
    // Same subnet + same PoS surface ⇒ the observations are identical: farm-ness
    // left no trace. (If `is_farm` had leaked into any field they would differ.)
    assert_eq!(
        o_honest, o_farm,
        "farm-identity must not leak into the observation"
    );
}

// ============================================================
// Evaluator — god-view scoring of the synchronous drop.
// ============================================================

#[test]
fn evaluator_block_survives_when_enough_honest_holders_chosen() {
    let dial = Dial {
        n_symbols: 6,
        k_eff: 3,
        honest_holders: 10,
        farm_masters: 10,
    };
    let pop = Sim6Pop::build(dial, 1, 99);
    // Pick the first 3 honest holders + 2 farm holders.
    let honest_idx: Vec<usize> = pop
        .holders
        .iter()
        .enumerate()
        .filter(|(_, h)| !h.is_farm)
        .map(|(i, _)| i)
        .take(3)
        .collect();
    let farm_idx: Vec<usize> = pop
        .holders
        .iter()
        .enumerate()
        .filter(|(_, h)| h.is_farm)
        .map(|(i, _)| i)
        .take(2)
        .collect();
    let mut chosen = honest_idx.clone();
    chosen.extend(farm_idx.iter());
    assert!(
        block_survives_farm_drop(&pop, &chosen, 3),
        "3 honest holdings ≥ k_eff=3 ⇒ block survives the farm drop"
    );
    assert_eq!(farm_positions_taken(&pop, &chosen), 2);
}

#[test]
fn evaluator_block_falls_when_too_few_honest_survive() {
    let dial = Dial {
        n_symbols: 6,
        k_eff: 3,
        honest_holders: 10,
        farm_masters: 10,
    };
    let pop = Sim6Pop::build(dial, 1, 99);
    let honest_idx: Vec<usize> = pop
        .holders
        .iter()
        .enumerate()
        .filter(|(_, h)| !h.is_farm)
        .map(|(i, _)| i)
        .take(2) // only 2 honest < k_eff=3
        .collect();
    let farm_idx: Vec<usize> = pop
        .holders
        .iter()
        .enumerate()
        .filter(|(_, h)| h.is_farm)
        .map(|(i, _)| i)
        .take(4)
        .collect();
    let mut chosen = honest_idx;
    chosen.extend(farm_idx);
    assert!(
        !block_survives_farm_drop(&pop, &chosen, 3),
        "only 2 honest holdings < k_eff=3 ⇒ block falls on the farm drop"
    );
}

// ============================================================
// Scenario-level — the STRUCTURAL sign (sim_plan.md §5.1).
// ============================================================

#[test]
fn sim6_addr_cap_raises_attacker_address_floor_for_every_dial() {
    // The load-bearing structural claim: under policy B (spread by addr_subnet) the
    // farm needs strictly MORE distinct subnets to deny than under policy A
    // (spread by master-id only) — for EVERY swept dial, not one tuned point.
    let report = run(42);
    assert!(
        report.structural_sign_holds,
        "B must raise the attacker address-floor for every dial: rows={:?}",
        report.rows
    );
    // Each row individually: B's floor strictly above A's.
    for r in &report.rows {
        assert!(
            r.min_subnets_deny_b > r.min_subnets_deny_a,
            "dial {:?}: minB={} must exceed minA={}",
            r.dial,
            r.min_subnets_deny_b,
            r.min_subnets_deny_a,
        );
    }
}

#[test]
fn sim6_one_subnet_farm_survives_under_b_but_falls_under_a() {
    // The concrete survive/fall witness: with the farm confined to ONE subnet, the
    // block SURVIVES under B (subnet-spread holds — one position) yet FALLS under A
    // (master-spread bypassed by N master-ids). The single sharpest illustration.
    let report = run(42);
    assert!(
        report.witness_b_survives_a_falls,
        "one-subnet farm must survive under B and fall under A"
    );
}

#[test]
fn sim6_structural_sign_is_seed_robust() {
    // The sign is a structural property, not a lucky seed: it must hold across
    // several seeds (a different shuffle / population each time).
    for seed in [1u64, 7, 13, 99, 12345] {
        let report = run(seed);
        assert!(
            report.structural_sign_holds && report.witness_b_survives_a_falls,
            "seed {seed}: structural sign must hold (B raises floor + witness)"
        );
    }
}

#[test]
fn sim6_full_run_passes() {
    let report = run(42);
    assert!(report.pass, "SIM-6 must PASS: {report:?}");
}
