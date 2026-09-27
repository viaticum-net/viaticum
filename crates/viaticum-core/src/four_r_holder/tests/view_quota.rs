// H-1..H-4e: κ seat, quota/φ, the view.

use super::*;
use crate::constants::PAIR_LEDGER_LAMBDA;
use crate::four_r::owner_order_by_key;

/// H-1: κ reads `gb_days_they_store_for_us` (the owner's service to us), never
/// `gb_days_we_store_for_them`; no row is an explicit 0.
#[test]
fn holder_kappa_reads_the_holder_seat_and_is_zero_without_a_row() {
    let p = FourRParams::default();
    assert_eq!(holder_kappa(None, &p), 0.0);
    // they > 0, we = 0 ⇒ κ > 0.
    let they = ledger(2.0, 0.0, 0.0, 0.01, 0.0);
    assert!((holder_kappa(Some(&they), &p) - 2.0).abs() < 1e-12);
    // they = 0, we > 0 ⇒ κ = 0 (the inverted seat, audit О-1, would give 5).
    let we = ledger(0.0, 5.0, 0.0, 0.0, 0.0);
    assert_eq!(holder_kappa(Some(&we), &p), 0.0);
    // v_dem = 0 ⇒ d_ref = 0 and g* = 0 ⇒ κ = g, whatever the depth.
    let no_dem = ledger(1.5, 0.0, 100.0, 0.0, 0.0);
    assert_eq!(holder_kappa(Some(&no_dem), &p), 1.5);
    // D ≥ d_ref = τ_ref·v_dem ⇒ κ = g + w_d · v_dem / λ.
    let v_dem = 0.01;
    let deep = ledger(0.3, 9.0, 365.0 * v_dem * 2.0, v_dem, 0.0);
    let want = 0.3 + p.w_d * v_dem / PAIR_LEDGER_LAMBDA;
    assert!((holder_kappa(Some(&deep), &p) - want).abs() < 1e-12);
    // Half depth ⇒ half floor.
    let half = ledger(0.0, 0.0, 365.0 * v_dem * 0.5, v_dem, 0.0);
    let want_half = p.w_d * 0.5 * v_dem / PAIR_LEDGER_LAMBDA;
    assert!((holder_kappa(Some(&half), &p) - want_half).abs() < 1e-12);
}

/// H-2 (NOTE-6): with the default dials a silent-but-deep pair keeps exactly its demonstrated
/// scale: V_ret = 0 + (w_d · v_dem/λ)/c_recip = 0.5 · 60 · v_dem / 30 = v_dem.
#[test]
fn default_params_give_vret_equal_to_vdem_for_a_silent_deep_pair() {
    let p = FourRParams::default();
    for v_dem in [0.001, 0.5, 2.0, 40.0] {
        let row = ledger(0.0, 0.0, 365.0 * v_dem * 3.0, v_dem, 10.0);
        let k = holder_kappa(Some(&row), &p);
        let v_ret = p.retention_cap().v_ret(k);
        assert!(
            (v_ret - v_dem).abs() < 1e-9 * v_dem.max(1.0),
            "{v_dem}: {v_ret}"
        );
    }
}

/// H-3a (Р-12): holdings are counted once. Disk 100 free, H 30, soft 0, reserve 10 ⇒
/// Q = 30 + 100 − 10 = 120, φ = 90/120 = 0.75; the old formula subtracts H twice (90).
#[test]
fn quota_counts_holdings_once() {
    let h = vec![holding(master(1), block(1, 0), 30, 0.5)];
    let q = QuotaInputs::from_holdings(&h, 100, 0, 10, 0);
    let s = quota_state(&q);
    assert_eq!(s.q_bytes, 120);
    assert_eq!(s.phi_actual, 0.75);
    assert_eq!(s.phi_forecast, 0.75);
    assert_eq!(s.free_now_bytes, 90);
    assert!(!s.q_nonpositive && s.measure_valid && !s.disk_free_zero);
    assert_eq!(crate::budget::compute_effective_quota(0, 100, 10), 90);
    // A soft cap below the disk bound wins.
    let s = quota_state(&QuotaInputs::from_holdings(&h, 100, 60, 10, 0));
    assert_eq!(s.q_bytes, 60);
    assert_eq!(s.phi_actual, 0.5);
}

/// H-3b (`4r-i52`): Q ≤ 0 ⇒ φ = −1, no room; a zero free disk invalidates the measure.
#[test]
fn quota_state_flags_nonpositive_and_zero_disk_and_invalidates_the_measure() {
    let h = vec![holding(master(1), block(1, 0), 30, 0.5)];
    // disk 0, reserve 50 ⇒ Q = 30 + 0 − 50 = −20.
    let s = quota_state(&QuotaInputs::from_holdings(&h, 0, 0, 50, 0));
    assert_eq!(s.q_bytes, -20);
    assert!(s.q_nonpositive);
    assert_eq!(
        (s.phi_actual, s.phi_forecast, s.free_now_bytes),
        (-1.0, -1.0, 0)
    );
    assert!(s.disk_free_zero && !s.measure_valid);
    // disk 0 with a soft cap: Q = min(100, 30) = 30 > 0, but the measure is still invalid.
    let s = quota_state(&QuotaInputs::from_holdings(&h, 0, 100, 0, 0));
    assert_eq!(s.q_bytes, 30);
    assert!(!s.q_nonpositive);
    assert_eq!(s.phi_actual, 0.0);
    assert!(s.disk_free_zero && !s.measure_valid);
    // A real free disk: valid.
    let s = quota_state(&QuotaInputs::from_holdings(&h, 1000, 0, 0, 0));
    assert!(!s.disk_free_zero && s.measure_valid && !s.q_nonpositive);
}

/// H-3c (Р-14): notified bytes are still on disk — they lift the forecast φ, not the actual.
#[test]
fn notified_bytes_raise_the_forecast_not_the_actual_phi() {
    let h = vec![
        holding(master(1), block(1, 0), 60, 0.5),
        notified(holding(master(1), block(1, 1), 40, 0.5)),
    ];
    let q = QuotaInputs::from_holdings(&h, 900, 200, 0, 0);
    assert_eq!((q.h_all_bytes, q.h_notified_bytes), (100, 40));
    let s = quota_state(&q);
    assert_eq!(s.q_bytes, 200);
    assert_eq!(s.phi_actual, 0.5);
    assert_eq!(s.phi_forecast, 0.7);
    assert_eq!(s.free_now_bytes, 100);
}

/// H-4a: own master → notified → MarkedForDelete → view, in that precedence.
#[test]
fn the_view_excludes_own_master_notified_and_marked_for_delete_in_that_precedence() {
    let own = master(0xEE);
    let a = master(0x0A);
    let b = master(0x0B);
    let h = vec![
        holding(own, block(0xEE, 0), 7, 0.5),
        notified(holding(own, block(0xEE, 1), 5, 0.5)), // own beats notified
        notified(marked(holding(a, block(0x0A, 0), 11, 0.5))), // notified beats MFD
        holding(a, block(0x0A, 1), 13, 0.5),
        marked(holding(b, block(0x0B, 0), 17, 0.5)), // B only MFD ⇒ not in view
    ];
    let q = QuotaInputs::from_holdings(&h, 1000, 0, 0, 0);
    assert_eq!(
        (q.h_all_bytes, q.h_notified_bytes, q.h_mfd_bytes),
        (53, 16, 17)
    );
    let v = build_holder_view(&h, &[], &own, &FourRParams::default());
    assert_eq!(v.masters, vec![a]);
    assert_eq!(v.holdings[0].len(), 1);
    assert_eq!(v.holdings[0][0].key.source_block_id, block(0x0A, 1));
    assert_eq!(v.notified.len(), 1);
    assert_eq!(v.notified[0].key.source_block_id, block(0x0A, 0));
    assert_eq!(v.marked_for_delete.len(), 1);
    assert_eq!(v.marked_for_delete[0].key.owner_id, b);
    assert_eq!(v.own_master_bytes, 12);
    assert_eq!(v.kappa, vec![0.0]);
}

/// H-4b (Q4): owners by master bytes, symbols by block id; with κ = 0 and τ = 0 for all, the
/// kernel's stable order IS the master-bytes order.
#[test]
fn view_owners_are_ordered_by_master_bytes_and_symbols_by_block_id() {
    let own = master(0xEE);
    let h = vec![
        holding(master(0x30), block(0x30, 2), 1, 0.5),
        holding(master(0x10), block(0x10, 9), 1, 0.5),
        holding(master(0x10), block(0x10, 3), 1, 0.5),
        holding(master(0x20), block(0x20, 0), 1, 0.5),
    ];
    let v = build_holder_view(&h, &[], &own, &FourRParams::default());
    assert_eq!(v.masters, vec![master(0x10), master(0x20), master(0x30)]);
    let blocks: Vec<_> = v.holdings[0]
        .iter()
        .map(|x| x.key.source_block_id)
        .collect();
    assert_eq!(blocks, vec![block(0x10, 3), block(0x10, 9)]);
    assert_eq!(owner_order_by_key(&v.views, &v.kappa), vec![0, 1, 2]);
    // An observed_tau tie-break moves an owner within the κ = 0 class only by τ.
    let ledgers = vec![(master(0x10), ledger(0.0, 0.0, 0.0, 0.0, 5.0))];
    let v = build_holder_view(&h, &ledgers, &own, &FourRParams::default());
    assert_eq!(owner_order_by_key(&v.views, &v.kappa), vec![1, 2, 0]);
}

/// H-4c (З-6): every view slot maps back to exactly its holding, and the view covers every
/// in-view holding once.
#[test]
fn every_view_slot_maps_back_to_its_holding() {
    let own = master(0xEE);
    let h = vec![
        holding(master(1), block(1, 5), 100, 0.9),
        holding(master(1), block(1, 2), 200, 0.1),
        holding(master(2), block(2, 7), 300, 0.4),
        notified(holding(master(2), block(2, 1), 400, 0.4)),
    ];
    let v = build_holder_view(&h, &[], &own, &FourRParams::default());
    let mut seen = std::collections::HashSet::new();
    for (oi, view) in v.views.iter().enumerate() {
        assert_eq!(view.symbols.len(), v.holdings[oi].len());
        for (si, sym) in view.symbols.iter().enumerate() {
            let back = v.holdings[oi][si];
            assert_eq!(sym.id, crate::four_r::SymbolId(si as u64));
            assert_eq!(back.key.owner_id, v.masters[oi]);
            assert_eq!(sym.volume, bytes_to_gb(back.bytes));
            assert_eq!(sym.importance, back.importance);
            let rec = h
                .iter()
                .find(|r| {
                    r.source_block_id == back.key.source_block_id && r.owner_id == back.key.owner_id
                })
                .unwrap();
            assert_eq!(rec.total_bytes, back.bytes);
            assert!(seen.insert(back.key));
        }
    }
    assert_eq!(seen.len(), 3);
}

/// H-4d (`4r-i24`): one master is one owner — one view entry, one κ — whatever device of
/// that master stored it; our placements at two of its devices fold into one presence.
#[test]
fn one_master_is_one_owner_in_the_view() {
    let own = master(0xEE);
    let w = master(0x0F);
    let h = vec![
        holding(w, block(0x0F, 0), 10, 0.5),
        holding(w, block(0x0F, 1), 20, 0.5),
    ];
    let ledgers = vec![(w, ledger(0.4, 0.0, 0.0, 0.0, 0.0))];
    let v = build_holder_view(&h, &ledgers, &own, &FourRParams::default());
    assert_eq!(v.masters, vec![w]);
    assert_eq!(v.kappa.len(), 1);
    assert_eq!(v.views[0].symbols.len(), 2);
    let peers = vec![peer(1, w), peer(2, w)];
    let pls = vec![
        placement(block(0xEE, 0), 1, PlacementStatus::Offered),
        placement(block(0xEE, 1), 2, PlacementStatus::Alive),
    ];
    let pres = placement_presence_by_master(&pls, &peers);
    assert_eq!(pres.len(), 1);
    assert_eq!(
        pres[&w],
        Presence {
            any: true,
            held: true
        }
    );
}

/// H-4e (Р-20, NOTE-2): `Silent` holdings are ordinary view members.
#[test]
fn silent_holdings_are_ordinary_view_members() {
    let own = master(0xEE);
    let mut s = holding(master(3), block(3, 0), 10, 0.5);
    s.status = HoldingStatus::Silent;
    let v = build_holder_view(&[s], &[], &own, &FourRParams::default());
    assert_eq!(v.masters, vec![master(3)]);
    assert_eq!(v.parked_bytes(0), 10);
}
