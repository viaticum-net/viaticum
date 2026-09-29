// H-5a..H-8: the plan (cap, pressure, floor), the κ = 0 classes, the order divergence.

use super::*;
use crate::budget::evaluate_pressure;
use crate::four_r::{EvictPhase, eviction_order_by_key};

/// Run view → kernel → plan for a holdings set under `p`.
fn plan_for(
    h: &[HoldingRecord],
    ledgers: &[(IdentityPub, PairLedger)],
    q: QuotaInputs,
    p: &FourRParams,
) -> EvictionPlan {
    let v = build_holder_view(h, ledgers, &master(0xEE), p);
    let s = quota_state(&q);
    let d = eviction_order_by_key(
        &v.views,
        &v.kappa,
        s.phi_forecast,
        p.hyst,
        EvictPhase::default(),
        &p.retention_cap(),
    );
    plan_eviction(&v, &d, &s, &q, p.hyst.s_target)
}

fn whys(plan: &EvictionPlan) -> Vec<(SourceBlockId, PlannedWhy)> {
    plan.drops
        .iter()
        .map(|d| (d.key.source_block_id, d.why))
        .collect()
}

/// H-5a: the cap takes ALL of a zero-service owner's excess even after φ is back above
/// `s_target` (tariff, not pressure relief).
#[test]
fn the_cap_trims_without_a_phi_stop() {
    let w = master(0x0F);
    let f = master(0x02);
    let h = vec![
        holding(w, block(0x0F, 0), 200, 0.1),
        holding(w, block(0x0F, 1), 200, 0.2),
        holding(w, block(0x0F, 2), 200, 0.3),
        holding(f, block(0x02, 0), 360, 0.5),
    ];
    let ledgers = vec![(f, ledger(1.0, 0.0, 0.0, 0.0, 0.0))];
    // Q = 1000, H = 960 ⇒ φ = 0.04 < s_hard. After the first W drop φ = 0.24 ≥ s_target.
    let plan = plan_for(&h, &ledgers, soft_quota(&h, 1000, 0), &s1_params());
    assert_eq!(
        whys(&plan),
        vec![
            (block(0x0F, 0), PlannedWhy::Cap),
            (block(0x0F, 1), PlannedWhy::Cap),
            (block(0x0F, 2), PlannedWhy::Cap),
        ]
    );
    assert_eq!(
        (plan.cap_bytes, plan.pressure_bytes, plan.mfd_bytes),
        (600, 0, 0)
    );
    assert!((plan.phi_forecast_after - 0.64).abs() < 1e-12);
}

/// H-5b: pressure relieves only down to `s_target`, MarkedForDelete first.
#[test]
fn pressure_stops_at_s_target_and_takes_marked_for_delete_first() {
    let a = master(0x0A);
    let b = master(0x0B);
    let c = master(0x0C);
    let d = master(0x0D);
    let h = vec![
        holding(a, block(0x0A, 0), 100, 0.3),
        holding(a, block(0x0A, 1), 100, 0.1),
        holding(a, block(0x0A, 2), 100, 0.2),
        holding(b, block(0x0B, 0), 100, 0.5),
        holding(b, block(0x0B, 1), 100, 0.5),
        marked(holding(c, block(0x0C, 0), 50, 0.9)),
        holding(d, block(0x0D, 0), 450, 0.5),
    ];
    let ledgers = vec![
        (b, ledger(1.0, 0.0, 0.0, 0.0, 0.0)),
        (d, ledger(5.0, 0.0, 0.0, 0.0, 0.0)),
    ];
    let p = FourRParams {
        c_recip_days: 0.0, // cap off: pressure only
        ..s1_params()
    };
    // Q = 1000 = H ⇒ φ = 0. MFD 50 ⇒ φ 0.05; A's lowest ι (100) ⇒ 0.15 ≥ s_target: stop.
    let plan = plan_for(&h, &ledgers, soft_quota(&h, 1000, 0), &p);
    assert_eq!(
        whys(&plan),
        vec![
            (block(0x0C, 0), PlannedWhy::MarkedForDelete),
            (block(0x0A, 1), PlannedWhy::Pressure),
        ]
    );
    assert_eq!(
        (plan.mfd_bytes, plan.pressure_bytes, plan.cap_bytes),
        (50, 100, 0)
    );
    assert!((plan.phi_forecast_after - 0.15).abs() < 1e-12);
}

/// H-5c: the `hard_quota` floor bounds the cap and the pressure list alike.
#[test]
fn the_hard_quota_floor_bounds_both_lists() {
    let w = master(0x0F);
    let f = master(0x02);
    let h = vec![
        holding(w, block(0x0F, 0), 100, 0.1),
        holding(w, block(0x0F, 1), 100, 0.2),
        holding(w, block(0x0F, 2), 100, 0.3),
        holding(f, block(0x02, 0), 700, 0.5),
    ];
    let ledgers = vec![(f, ledger(1.0, 0.0, 0.0, 0.0, 0.0))];
    // H = Q = 1000, floor 900: the first cap drop leaves exactly 900 (allowed), the rest
    // would go below; F's 700 in the pressure list too.
    let plan = plan_for(&h, &ledgers, soft_quota(&h, 1000, 900), &s1_params());
    assert_eq!(whys(&plan), vec![(block(0x0F, 0), PlannedWhy::Cap)]);
    assert_eq!(plan.cap_bytes, 100);
    assert_eq!(plan.floor_skipped_bytes, 200 + 700);
    assert_eq!(plan.pressure_bytes, 0);
}

/// H-5d: no latch ⇒ no plan, whatever the cap would say.
#[test]
fn no_plan_when_not_evicting() {
    let w = master(0x0F);
    let h = vec![holding(w, block(0x0F, 0), 100, 0.1)];
    let plan = plan_for(&h, &[], soft_quota(&h, 1000, 0), &s1_params());
    assert!(plan.drops.is_empty());
    assert_eq!(
        (
            plan.cap_bytes,
            plan.pressure_bytes,
            plan.floor_skipped_bytes
        ),
        (0, 0, 0)
    );
    assert!((plan.phi_forecast_after - 0.9).abs() < 1e-12);
}

/// H-6: the κ = 0 classes follow OUR placements at that master's devices.
#[test]
fn presence_classes_follow_our_placements_by_master() {
    let m1 = master(1);
    let m2 = master(2);
    let m3 = master(3);
    let m4 = master(4);
    let m5 = master(5);
    let peers = vec![
        peer(21, m2),
        peer(22, m2),
        peer(31, m3),
        peer(41, m4),
        peer(51, m5),
        peer(99, IdentityPub([0u8; 32])), // placeholder master: skipped
    ];
    let b = block(0xEE, 0);
    let pls = vec![
        placement(b, 21, PlacementStatus::Offered),
        placement(b, 22, PlacementStatus::Lost),
        placement(b, 31, PlacementStatus::PresumedLost),
        placement(block(0xEE, 1), 31, PlacementStatus::Deleting),
        placement(b, 41, PlacementStatus::Alive),
        placement(b, 51, PlacementStatus::Uncertain),
        placement(b, 77, PlacementStatus::Alive), // no PeerRecord: skipped
        placement(b, 99, PlacementStatus::Alive), // placeholder: skipped
    ];
    let pres = placement_presence_by_master(&pls, &peers);
    assert_eq!(pres.len(), 4);
    assert_eq!(zero_kappa_class(pres.get(&m1)), ZeroKappaClass::NeverAsked);
    assert_eq!(zero_kappa_class(pres.get(&m2)), ZeroKappaClass::Asked);
    assert_eq!(zero_kappa_class(pres.get(&m3)), ZeroKappaClass::Asked);
    assert_eq!(
        zero_kappa_class(pres.get(&m4)),
        ZeroKappaClass::ServingUnconfirmed
    );
    assert_eq!(
        zero_kappa_class(pres.get(&m5)),
        ZeroKappaClass::ServingUnconfirmed
    );
    assert!(!pres.contains_key(&IdentityPub([0u8; 32])));
}

/// H-7: overlap and Kendall τ of two owner orders.
#[test]
fn compare_owner_orders_reports_overlap_and_kendall() {
    let m: Vec<IdentityPub> = (0..14u8).map(master).collect();
    let rev: Vec<IdentityPub> = m[..4].iter().rev().copied().collect();
    let d = compare_owner_orders(&m[..4], &rev);
    assert_eq!((d.common, d.top10_overlap), (4, 4));
    assert_eq!(d.kendall_tau, Some(-1.0));
    assert_eq!((d.first_old, d.first_new), (Some(m[0]), Some(m[3])));

    let d = compare_owner_orders(&m[..4], &m[..4]);
    assert_eq!(d.kendall_tau, Some(1.0));

    // One swap among 4 common owners: 5 concordant, 1 discordant ⇒ τ = 4/6.
    let one_swap = vec![m[1], m[0], m[2], m[3]];
    let d = compare_owner_orders(&m[..4], &one_swap);
    assert!((d.kendall_tau.unwrap() - 4.0 / 6.0).abs() < 1e-12);

    // Owners present in only one order are ignored by τ; < 2 common ⇒ None.
    let d = compare_owner_orders(&[m[0], m[5]], &[m[0], m[6]]);
    assert_eq!((d.common, d.kendall_tau), (1, None));

    // Top-10 of 14: old ascending, new = old rotated by 4 ⇒ overlap 6.
    let rot: Vec<IdentityPub> = m[4..].iter().chain(m[..4].iter()).copied().collect();
    let d = compare_owner_orders(&m, &rot);
    assert_eq!((d.common, d.top10_overlap), (14, 6));
}

/// H-8: the shadow's "old order" is exactly `evaluate_pressure`'s candidate order — the first
/// immediate eviction is the first old owner, and owners appear in the same order.
#[test]
fn old_owner_order_matches_evaluate_pressure_candidate_order() {
    let now = 10 * crate::constants::SECS_PER_WEEK;
    let a = master(0x0A);
    let b = master(0x0B);
    let c = master(0x0C);
    let d = master(0x0D);
    let mut h = vec![
        holding(a, block(0x0A, 0), 100, 0.9),
        holding(b, block(0x0B, 0), 100, 0.2),
        holding(c, block(0x0C, 0), 100, 0.5),
        holding(d, block(0x0D, 0), 300, 0.5),
        marked(holding(a, block(0x0A, 1), 100, 0.9)), // MFD ⇒ priority min(0, p): first
        holding(b, block(0x0B, 1), 290, 0.2),
    ];
    h[2].received_at = Timestamp(now - 5 * crate::constants::SECS_PER_WEEK); // age bonus
    let trust = |m: &IdentityPub| -> f64 {
        match m.0[0] {
            0x0A => 0.9,
            0x0B => 0.8,
            0x0C => 0.3,
            _ => 0.6,
        }
    };
    // used = 990 of 1000 ⇒ Hard, hard floor 0.
    let used: u64 = h.iter().map(|r| r.total_bytes).sum();
    let res = evaluate_pressure(crate::budget::Quota::Bytes(1000), 0, used, &h, trust, now);
    assert_eq!(res.pressure, crate::budget::DiskPressure::Hard);
    let old = old_owner_order(&h, trust, now);
    assert_eq!(res.immediate_evictions[0].owner_id, old[0]);
    assert_eq!(old[0], a); // the MarkedForDelete holding goes first
    let mut seen: Vec<IdentityPub> = Vec::new();
    for o in res
        .immediate_evictions
        .iter()
        .map(|e| e.owner_id)
        .chain(res.drop_notices.iter().map(|n| n.owner_id))
    {
        if !seen.contains(&o) {
            seen.push(o);
        }
    }
    assert!(
        seen.len() >= 2,
        "fixture must reach at least two owners: {seen:?}"
    );
    assert_eq!(&old[..seen.len()], seen.as_slice());
}
