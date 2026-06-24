use super::*;
use crate::generator::Archetype;

fn owner(archetype: Archetype, g: f64, tau: f64) -> OwnerGt {
    OwnerGt {
        archetype,
        true_g_holder_from_owner: g,
        true_tau: tau,
        // Owner-declared ι is metadata, not ground-truth — a fixed value here so it
        // never varies by archetype (the anti-oracle guard asserts that).
        declared_iota: 0.5,
    }
}

/// THE anti-oracle regression guard. Two owners with IDENTICAL first-hand service
/// (`true_g_holder_from_owner`, `true_tau`) but DIFFERENT hidden archetype must
/// produce IDENTICAL `FirstHandObs` at the same index. If a future bug ever lets
/// the hidden archetype/hazard leak into the observation, these two observations
/// would diverge and this test fails. This pins the structural anti-oracle
/// (no archetype field on FirstHandObs) as a behavioural test, not just a
/// compile-time property.
#[test]
fn observe_is_blind_to_hidden_archetype() {
    // Same first-hand service, different hidden archetype.
    let a = owner(Archetype::Freeloader, 4.0, 50.0);
    let b = owner(Archetype::Reciprocator, 4.0, 50.0);
    let obs_a = observe(&a, 7);
    let obs_b = observe(&b, 7);
    assert_eq!(
        obs_a, obs_b,
        "observation must be identical when first-hand service is identical, \
         regardless of hidden archetype (anti-oracle)"
    );

    // The SAME guard must also hold for the two-level eviction view: with
    // identical first-hand service AND identical declared ι, two owners differing
    // only in hidden archetype must produce bit-identical OwnerEvictionViews. The
    // new ι path carries no oracle — it is owner-declared metadata, not archetype.
    let views_a = observe_eviction_views(&[a]);
    let views_b = observe_eviction_views(&[b]);
    assert_eq!(
        views_a, views_b,
        "eviction view must be identical when first-hand service + declared ι are \
         identical, regardless of hidden archetype (anti-oracle, new input shape)"
    );
}

#[test]
fn observe_eviction_view_carries_g_and_declared_iota_as_first_hand() {
    // Two owners with different G and different declared ι. The view must shadow G
    // into obs.g_holder_from_owner (inter-owner key) and ι into the single symbol's
    // importance (intra-owner key) — both first-hand, no archetype anywhere.
    let mut hi = owner(Archetype::Reciprocator, 9.0, 90.0);
    hi.declared_iota = 0.9;
    let mut lo = owner(Archetype::Freeloader, 0.2, 3.0);
    lo.declared_iota = 0.1;
    let views = observe_eviction_views(&[hi, lo]);
    assert_eq!(views.len(), 2);
    // Inter-owner key.
    assert_eq!(views[0].obs.g_holder_from_owner, 9.0);
    assert_eq!(views[1].obs.g_holder_from_owner, 0.2);
    // One symbol per owner, importance = declared ι, id = owner index.
    assert_eq!(views[0].symbols.len(), 1);
    assert_eq!(views[0].symbols[0].importance, 0.9);
    assert_eq!(views[0].symbols[0].id.0, 0);
    assert_eq!(views[1].symbols[0].importance, 0.1);
    assert_eq!(views[1].symbols[0].id.0, 1);
}

/// Make the absence of any archetype-derived field explicit: assert there is no
/// field that ever differs by archetype alone. We do this by sweeping all three
/// archetypes with the same first-hand service and checking every produced
/// observation is bit-identical to the first.
#[test]
fn observe_produces_no_archetype_dependent_field() {
    let svc = (4.0, 50.0);
    let base = observe(&owner(Archetype::Modest, svc.0, svc.1), 3);
    for arch in [
        Archetype::Reciprocator,
        Archetype::Modest,
        Archetype::Freeloader,
    ] {
        let got = observe(&owner(arch, svc.0, svc.1), 3);
        assert_eq!(
            got, base,
            "archetype {arch:?} changed an observation field — oracle leak"
        );
    }
}

#[test]
fn observe_shadows_first_hand_service_and_tau() {
    let o = owner(Archetype::Modest, 3.5, 42.0);
    let obs = observe(&o, 0);
    // The legitimately-first-hand quantities ARE shadowed through.
    assert_eq!(obs.g_holder_from_owner, 3.5);
    assert_eq!(obs.v_dem, 3.5);
    assert_eq!(obs.observed_volume, 3.5);
    assert_eq!(obs.observed_tau, 42.0);
}

#[test]
fn observe_gives_distinct_crypto_ids_per_index() {
    let o = owner(Archetype::Modest, 1.0, 1.0);
    let a = observe(&o, 1);
    let b = observe(&o, 2);
    assert_ne!(
        a.master_id, b.master_id,
        "distinct master-id per owner index"
    );
    assert_ne!(
        a.device_id, b.device_id,
        "distinct device-id per owner index"
    );
    // addr_subnet is the index correlate.
    assert_eq!(a.addr_subnet, 1);
    assert_eq!(b.addr_subnet, 2);
}

#[test]
fn observe_all_preserves_index_order() {
    let owners = vec![
        owner(Archetype::Reciprocator, 8.0, 90.0),
        owner(Archetype::Freeloader, 0.2, 3.0),
    ];
    let obs = observe_all(&owners);
    assert_eq!(obs.len(), 2);
    assert_eq!(obs[0].g_holder_from_owner, 8.0);
    assert_eq!(obs[1].g_holder_from_owner, 0.2);
    assert_eq!(obs[0].addr_subnet, 0);
    assert_eq!(obs[1].addr_subnet, 1);
}

#[test]
fn observe_failure_point_records_one_observed_slice_and_pos_history() {
    // The production-node surface view: ONE observed (V0, τ0) point plus a PoS
    // pass/fail history there. v_dem == observed volume (we proved exactly that).
    let obs = observe_failure_point(12.0, 40.0, 30, 10);
    assert_eq!(obs.observed_volume, 12.0);
    assert_eq!(obs.observed_tau, 40.0);
    assert_eq!(obs.v_dem, 12.0);
    assert_eq!(obs.pos_pass, 30);
    assert_eq!(obs.pos_fail, 10);
    // recent_rate_p is the empirical pass-fraction (first-hand).
    assert!((obs.recent_rate_p - 0.75).abs() < 1e-12);
}

#[test]
fn observe_failure_point_handles_zero_pos_samples() {
    // With no PoS samples the pass-fraction is the 0.0 sentinel, not a NaN.
    let obs = observe_failure_point(5.0, 10.0, 0, 0);
    assert_eq!(obs.recent_rate_p, 0.0);
    assert_eq!(obs.pos_pass, 0);
    assert_eq!(obs.pos_fail, 0);
}
