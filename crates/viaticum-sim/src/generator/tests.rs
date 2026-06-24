use super::*;

// ---- Rng determinism ----

#[test]
fn rng_same_seed_produces_same_sequence() {
    let mut a = Rng::new(12345);
    let mut b = Rng::new(12345);
    for _ in 0..1000 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
}

#[test]
fn rng_different_seeds_diverge() {
    let mut a = Rng::new(1);
    let mut b = Rng::new(2);
    // Extremely unlikely to agree on the first draw for an LCG with these seeds.
    assert_ne!(a.next_u64(), b.next_u64());
}

#[test]
fn rng_unit_is_in_unit_interval() {
    let mut r = Rng::new(7);
    for _ in 0..10_000 {
        let u = r.unit();
        assert!((0.0..1.0).contains(&u), "unit() out of [0,1): {u}");
    }
}

#[test]
fn rng_range_stays_within_bounds() {
    let mut r = Rng::new(99);
    for _ in 0..10_000 {
        let x = r.range(2.5, 7.5);
        assert!((2.5..7.5).contains(&x), "range() out of bounds: {x}");
    }
}

// ---- Population::median_true_g empty-input guard ----

#[test]
fn median_true_g_is_zero_for_empty_population() {
    let pop = Population { owners: vec![] };
    assert_eq!(
        pop.median_true_g(),
        0.0,
        "empty population must return the 0.0 median sentinel, not panic"
    );
}

#[test]
fn median_true_g_picks_the_upper_middle_element() {
    // The implementation takes v[len/2] after sorting (upper median for even len).
    let owners = vec![
        OwnerGt {
            archetype: Archetype::Freeloader,
            true_g_holder_from_owner: 1.0,
            true_tau: 0.0,
            declared_iota: 0.0,
        },
        OwnerGt {
            archetype: Archetype::Modest,
            true_g_holder_from_owner: 5.0,
            true_tau: 0.0,
            declared_iota: 0.0,
        },
        OwnerGt {
            archetype: Archetype::Reciprocator,
            true_g_holder_from_owner: 9.0,
            true_tau: 0.0,
            declared_iota: 0.0,
        },
    ];
    let pop = Population { owners };
    assert_eq!(pop.median_true_g(), 5.0);
}

// ---- is_net_debtor ----

#[test]
fn is_net_debtor_is_true_below_median_only() {
    let debtor = OwnerGt {
        archetype: Archetype::Freeloader,
        true_g_holder_from_owner: 0.2,
        true_tau: 0.0,
        declared_iota: 0.0,
    };
    let creditor = OwnerGt {
        archetype: Archetype::Reciprocator,
        true_g_holder_from_owner: 8.0,
        true_tau: 0.0,
        declared_iota: 0.0,
    };
    let median = 4.0;
    assert!(debtor.is_net_debtor(median));
    assert!(!creditor.is_net_debtor(median));
    // Exactly at the median is NOT a debtor (strict less-than).
    let at_median = OwnerGt {
        archetype: Archetype::Modest,
        true_g_holder_from_owner: median,
        true_tau: 0.0,
        declared_iota: 0.0,
    };
    assert!(!at_median.is_net_debtor(median));
}

// ---- Population::sim2 shape ----

#[test]
fn sim2_population_is_deterministic_and_distinct_in_g() {
    let a = Population::sim2(30, 42);
    let b = Population::sim2(30, 42);
    assert_eq!(a.owners.len(), 30);
    for (x, y) in a.owners.iter().zip(b.owners.iter()) {
        assert_eq!(x.true_g_holder_from_owner, y.true_g_holder_from_owner);
        assert_eq!(x.archetype, y.archetype);
    }
    // No two owners tie in true G (the Spearman rank check relies on this).
    let mut gs: Vec<f64> = a
        .owners
        .iter()
        .map(|o| o.true_g_holder_from_owner)
        .collect();
    gs.sort_by(|p, q| p.total_cmp(q));
    for w in gs.windows(2) {
        assert!(w[0] != w[1], "true G values must be distinct (no ties)");
    }
}
