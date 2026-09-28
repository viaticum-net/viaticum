// H-9, H-10: the whole shadow tick in miniature and its replay record.

use super::*;
use crate::budget::DiskPressure;
use crate::four_r::EvictPhase;

const MIB: u64 = 1 << 20;

/// The S1 laptop in miniature: L holds for a friend F (who serves L), for P (serves L too)
/// and for a whale W (never stored anything for L, was asked: our offers to W sit `Offered`).
struct Mini {
    own: IdentityPub,
    f: IdentityPub,
    p: IdentityPub,
    w: IdentityPub,
    holdings: Vec<HoldingRecord>,
    ledgers: Vec<(IdentityPub, PairLedger)>,
    placements: Vec<SymbolPlacement>,
    peers: Vec<PeerRecord>,
}

fn mini() -> Mini {
    let own = master(0x4C);
    let f = master(0x46);
    let p = master(0x50);
    let w = master(0x57);
    let mut holdings = vec![
        holding(f, block(0x46, 0), 2 * MIB, 0.6),
        holding(f, block(0x46, 1), 2 * MIB, 0.6),
        holding(p, block(0x50, 0), 2 * MIB, 0.5),
    ];
    for i in 0..10 {
        holdings.push(holding(w, block(0x57, i), 5 * MIB, 0.3 + 0.01 * i as f64));
    }
    let ledgers = vec![
        (f, ledger(0.08, 0.02, 0.05, 0.004, 1.2)),
        (p, ledger(0.05, 0.02, 0.03, 0.004, 1.1)),
        // W: a row exists (we store for W) but W stores nothing for us.
        (w, ledger(0.0, 0.3, 0.0, 0.0, 0.0)),
    ];
    let peers = vec![peer(0x46, f), peer(0x50, p), peer(0x57, w)];
    let placements = vec![
        placement(block(0x4C, 0), 0x46, PlacementStatus::Alive),
        placement(block(0x4C, 0), 0x50, PlacementStatus::Alive),
        placement(block(0x4C, 0), 0x57, PlacementStatus::Offered),
    ];
    Mini {
        own,
        f,
        p,
        w,
        holdings,
        ledgers,
        placements,
        peers,
    }
}

fn input(m: &Mini, soft: u64, old_order: Vec<IdentityPub>) -> ShadowPressureInput<'_> {
    ShadowPressureInput {
        holdings: &m.holdings,
        ledgers: &m.ledgers,
        placements: &m.placements,
        peers: &m.peers,
        own_master: m.own,
        quota: soft_quota(&m.holdings, soft, 0),
        phase_prev: EvictPhase::default(),
        old_owner_order: old_order,
        old_plan: OldPlan {
            pressure: DiskPressure::Hard,
            immediate: vec![],
            notices: vec![],
        },
    }
}

/// H-9: the whale (κ = 0, asked) is squeezed first and cap-trimmed WHOLE; the serving friend
/// keeps its share; the old order (trust × importance) can disagree and the tick says so.
#[test]
fn the_whale_goes_first_and_is_capped_whole_while_the_serving_friend_keeps_its_share() {
    let m = mini();
    let h: u64 = m.holdings.iter().map(|r| r.total_bytes).sum(); // 56 MiB
    let soft = h + h / 50; // φ ≈ 0.0196 < s_hard
    // The old path's order ranks F first (its trust × importance is lowest).
    let t = shadow_pressure_tick(&input(&m, soft, vec![m.f, m.w, m.p]), &s1_params());
    assert!(t.decision.phase.evicting);
    assert_eq!(t.owner_order[0], m.w);
    let row = |x: &IdentityPub| t.owners.iter().find(|o| o.master == *x).unwrap().clone();
    let (rw, rf, rp) = (row(&m.w), row(&m.f), row(&m.p));
    assert_eq!(rw.kappa, 0.0);
    assert_eq!(rw.parked_bytes, 50 * MIB);
    assert_eq!(
        rw.cap_bytes, rw.parked_bytes,
        "V_ret(W) = 0 ⇒ the whole whale goes"
    );
    assert_eq!(rw.v_ret_gb, Some(0.0));
    assert_eq!(rw.zk_class, Some(ZeroKappaClass::Asked));
    assert_eq!(rf.cap_bytes, 0);
    assert_eq!(rp.cap_bytes, 0);
    assert!(rf.kappa > ZERO_KAPPA_EPS && rf.zk_class.is_none());
    assert!(rf.rank_new > rw.rank_new);
    assert_eq!((rw.rank_old, rf.rank_old), (Some(1), Some(0)));
    assert_eq!(t.zero_kappa.asked, 50 * MIB);
    assert_eq!(t.zero_kappa.total, 50 * MIB);
    assert_eq!(
        t.zero_kappa.never_asked + t.zero_kappa.serving_unconfirmed,
        0
    );
    // Cap first: after the whale φ ≫ s_target, so pressure takes nothing from F or P.
    assert_eq!(t.plan.cap_bytes, 50 * MIB);
    assert_eq!(t.plan.pressure_bytes, 0);
    assert_eq!(t.divergence.first_old, Some(m.f));
    assert_eq!(t.divergence.first_new, Some(m.w));
    assert_eq!(t.divergence.kendall_tau, Some(-1.0 / 3.0));
    assert!(t.quota.measure_valid);

    // In abundance the same owners produce no plan and no latch.
    let t = shadow_pressure_tick(&input(&m, 4 * h, vec![]), &s1_params());
    assert!(!t.decision.phase.evicting && t.decision.accept_ok);
    assert!(t.plan.drops.is_empty());
    assert_eq!(
        t.owner_order[0], m.w,
        "the order exists even without contention"
    );
}

/// H-10: the record copies the ledger row under absolute names straight from the row, keeps
/// the own master's holdings (outside the view) and every flag the replay needs.
#[test]
fn the_raw_record_copies_ledger_fields_by_absolute_name_from_the_row() {
    let mut m = mini();
    m.ledgers[0].1 = ledger(1.25, 7.5, 3.0, 0.02, 4.0);
    m.holdings
        .push(holding(m.own, block(0x4C, 9), 3 * MIB, 0.5));
    m.holdings
        .push(notified(holding(m.f, block(0x46, 7), MIB, 0.6)));
    let h: u64 = m.holdings.iter().map(|r| r.total_bytes).sum();
    let mut inp = input(&m, h + h / 50, vec![m.w, m.f]);
    inp.old_plan.immediate = vec![HoldingKey {
        source_block_id: block(0x57, 0),
        owner_id: m.w,
    }];
    let p = s1_params();
    let t = shadow_pressure_tick(&inp, &p);
    let rec = raw_pressure_record(&inp, &p, &t, 1234);
    assert_eq!(rec.v, RAW_RECORD_VERSION);
    assert_eq!(rec.kind, "pressure");
    assert_eq!(rec.now, 1234);
    let hex = |x: &IdentityPub| crate::types::hex_encode(&x.0);
    let f = rec.owners.iter().find(|o| o.master == hex(&m.f)).unwrap();
    assert_eq!(
        f.row,
        Some(RawRow {
            g_they: 1.25,
            g_we: 7.5,
            depth: 3.0,
            v_dem: 0.02,
            observed_tau: 4.0,
        })
    );
    assert_eq!(f.notified_bytes, MIB);
    assert_eq!(f.parked_bytes, 4 * MIB);
    assert_eq!(f.holdings.len(), 3);
    assert!(
        f.holdings
            .iter()
            .any(|x| x.notified && x.status == "Active")
    );
    // κ in the output comes from g_they (1.25 + floor), not from g_we (7.5).
    let kf = rec
        .out
        .kappa
        .iter()
        .find(|(x, _)| *x == hex(&m.f))
        .unwrap()
        .1;
    assert_eq!(kf, holder_kappa(Some(&m.ledgers[0].1), &p));
    assert!(kf < 7.5);
    // The own master is in the owners list (all holdings), not in the view.
    let own = rec.owners.iter().find(|o| o.master == hex(&m.own)).unwrap();
    assert_eq!(
        (own.parked_bytes, own.holdings.len(), own.row.is_none()),
        (0, 1, true)
    );
    assert!(rec.out.kappa.iter().all(|(x, _)| *x != hex(&m.own)));
    assert_eq!(rec.own_master, hex(&m.own));
    assert_eq!(rec.quota.h_notified_bytes, MIB);
    let old = rec.old_plan.as_ref().unwrap();
    assert_eq!(old.pressure, "Hard");
    assert_eq!(
        old.immediate,
        vec![(crate::types::hex_encode(&block(0x57, 0).0), hex(&m.w))]
    );
    assert_eq!(rec.out.first_owner_old, Some(hex(&m.w)));
    assert_eq!(rec.out.first_owner_new, Some(hex(&m.w)));
    assert_eq!(rec.params.lambda, crate::constants::PAIR_LEDGER_LAMBDA);
    assert_eq!(rec.params.c_recip_days, 3.0);
    assert_eq!(rec.presence.len(), 3);
    assert_eq!(rec.out.zk_class, vec![(hex(&m.w), "Asked".to_string())]);
    assert_eq!(rec.out.cap.len(), 10);
}

/// H-3c (`4r-i66`): a tick whose measure is invalid (`disk_free = 0`: φ is blind) does not
/// move the latch — OFF stays OFF under a blind φ ≤ 0, ON stays ON under a blind φ ≥ s_target
/// — and the next VALID tick in the deadband therefore stays OFF (nothing inherited).
#[test]
fn an_invalid_tick_does_not_move_the_latch_either_way() {
    let mut m = mini();
    let p = s1_params();
    let blind = |m: &Mini, prev: bool| {
        let mut inp = input(m, 0, vec![]);
        // disk_free = 0 ⇒ Q = min(soft, H) = H ⇒ φ_actual = 0, φ_forecast = H_notified / H.
        inp.quota = QuotaInputs::from_holdings(&m.holdings, 0, 1 << 40, 0, 0);
        inp.phase_prev = EvictPhase { evicting: prev };
        shadow_pressure_tick(&inp, &p)
    };

    // OFF latch, blind φ = 0 < s_hard: the rule would latch ON; the frozen tick stays OFF.
    let t = blind(&m, false);
    assert!(!t.quota.measure_valid && t.quota.disk_free_zero);
    assert!(t.quota.phi_forecast < p.hyst.s_hard);
    assert!(!t.decision.phase.evicting, "a blind tick must not latch ON");
    assert!(t.plan.drops.is_empty(), "not evicting ⇒ no plan");
    assert_eq!(t.phase_prev, EvictPhase { evicting: false });
    // Control: the same holdings with the disk READ and φ < s_hard do latch ON.
    let h: u64 = m.holdings.iter().map(|r| r.total_bytes).sum();
    let valid = shadow_pressure_tick(&input(&m, h + h / 50, vec![]), &p);
    assert!(valid.quota.measure_valid && valid.decision.phase.evicting);

    // The next valid tick in the deadband (φ = 0.10) after the frozen OFF: stays OFF.
    let deadband = h * 10 / 9 + 1; // φ = 1 − H/Q ≈ 0.10
    let mut next = input(&m, deadband, vec![]);
    next.phase_prev = t.decision.phase;
    let t2 = shadow_pressure_tick(&next, &p);
    assert!(t2.quota.measure_valid);
    assert!(t2.quota.phi_forecast > p.hyst.s_hard && t2.quota.phi_forecast < p.hyst.s_target);
    assert!(!t2.decision.phase.evicting);

    // ON latch, blind φ_forecast ≥ s_target (notified bytes lift it): the rule would release;
    // the frozen tick stays ON.
    m.holdings
        .push(notified(holding(m.f, block(0x46, 9), 20 * MIB, 0.6)));
    let t = blind(&m, true);
    assert!(!t.quota.measure_valid);
    assert!(t.quota.phi_forecast >= p.hyst.s_target);
    assert!(t.decision.phase.evicting, "a blind tick must not release");
    assert_eq!(
        tick_phase(&t.quota, p.hyst, EvictPhase { evicting: true }),
        EvictPhase { evicting: true }
    );
}

/// H-10b (`4r-i67`): the pressure record carries the RAW inputs of the presence join — our
/// placements by (device, status) and the stored master of each such device, the placeholder
/// master included and a device without a `PeerRecord` absent — next to the shadow's own
/// presence (which skips both).
#[test]
fn the_pressure_record_carries_the_raw_inputs_of_the_presence_join() {
    let mut m = mini();
    m.placements
        .push(placement(block(0x4C, 1), 0x46, PlacementStatus::Alive));
    m.placements
        .push(placement(block(0x4C, 1), 0x57, PlacementStatus::Lost));
    m.placements
        .push(placement(block(0x4C, 1), 0x98, PlacementStatus::Alive));
    m.placements
        .push(placement(block(0x4C, 1), 0x99, PlacementStatus::Alive));
    m.peers.push(peer(0x98, IdentityPub([0u8; 32])));
    m.peers.push(peer(0x77, master(0x77))); // no placement at 0x77: not in the record
    let p = s1_params();
    let inp = input(&m, 1 << 40, vec![]);
    let t = shadow_pressure_tick(&inp, &p);
    let rec = raw_pressure_record(&inp, &p, &t, 1);
    let hex = |b: u8| crate::types::hex_encode(&[b; 32]);
    let got: Vec<(String, String, u64)> = rec
        .placements
        .iter()
        .map(|x| (x.device.clone(), x.status.clone(), x.count))
        .collect();
    assert_eq!(
        got,
        vec![
            (hex(0x46), "Alive".to_string(), 2),
            (hex(0x50), "Alive".to_string(), 1),
            (hex(0x57), "Lost".to_string(), 1),
            (hex(0x57), "Offered".to_string(), 1),
            (hex(0x98), "Alive".to_string(), 1),
            (hex(0x99), "Alive".to_string(), 1),
        ]
    );
    let pm: Vec<(String, String)> = rec
        .peer_masters
        .iter()
        .map(|x| (x.device.clone(), x.master.clone()))
        .collect();
    assert_eq!(
        pm,
        vec![
            (hex(0x46), hex(0x46)),
            (hex(0x50), hex(0x50)),
            (hex(0x57), hex(0x57)),
            (hex(0x98), hex(0x00)),
        ]
    );
    // The shadow's own join skips the placeholder and the unknown device.
    let pres: Vec<(String, bool, bool)> = rec
        .presence
        .iter()
        .map(|x| (x.master.clone(), x.any, x.held))
        .collect();
    assert_eq!(
        pres,
        vec![
            (hex(0x46), true, true),
            (hex(0x50), true, true),
            (hex(0x57), true, false),
        ]
    );
}
