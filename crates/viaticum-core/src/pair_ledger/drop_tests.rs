// Tests for the drop events of the 4R pair ledger (У-4).
//
// Spec: private/beta-planning/tasks/pair_ledger.md, "Спека У-4" (Д-I..Д-M, У4-11);
// intent: private/intent/4r.md 4r-i25..i30.
//
//   AC-4c/4d  what IS one event: the first loss of a held placement, on evidence strictly
//             younger than the episode (DC-1).
//   AC-4e     the counters leak at λ_drop with the sim's own expression, dark part included
//             (DC-2, DC-3; DC-7 lives in tests.rs next to the other sub-step checks).
//   AC-4f     the tick folds the queue AFTER the interval's decay, only on accruing rows,
//             exactly once, and nothing else changes (DC-4..DC-6, DC-8, DC-11; DC-10 in
//             tests.rs next to R-1).
//   AC-4h     the event's master is the PeerRecord master (DC-9).
//
// Expectations are computed in the test from the constant and the literal expression, not
// copied from a run.

use super::{
    LossCause, NotCounted, PairLedgerRecorder, Volumes, accrue, accrue_interval, drop_event_for,
    ledger_master_for_device, observed_window_days, sub_steps,
};
use crate::constants::{PAIR_LEDGER_LAMBDA_DROP, PAIR_LEDGER_TICK_SECS};
use crate::db::Db;
use crate::db::testutil::test_db;
use crate::types::{
    DeviceId, DropKind, IdentityPub, PairLedger, PeerRecord, PendingDrops, PlacementStatus,
    Timestamp,
};

// ── Fixtures ────────────────────────────────────────────────────────────────

const DAY: u64 = 86_400;
const TICK: u64 = PAIR_LEDGER_TICK_SECS;

fn master(seed: u8) -> IdentityPub {
    IdentityPub([seed; 32])
}

fn device(seed: u8) -> DeviceId {
    DeviceId([seed; 32])
}

fn my_master() -> IdentityPub {
    master(0x01)
}

fn peer_of(dev: DeviceId, m: IdentityPub) -> PeerRecord {
    PeerRecord {
        device_id: dev,
        master_identity: m,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: crate::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    }
}

fn no_volume() -> Volumes {
    Volumes {
        they_store_for_us: 0.0,
        they_store_for_us_confirmed: 0.0,
        we_store_for_them: 0.0,
    }
}

/// The literal sim sweep expression (`sim_dynamic/engine.rs:1753-1755`), written out here
/// so the recorder is compared against the model's formula, not against itself.
fn sim_leak(count: f64, dt: f64) -> f64 {
    let drop_decay = (1.0 - PAIR_LEDGER_LAMBDA_DROP * dt).max(0.0);
    count * drop_decay
}

fn queue(db: &Db, m: &IdentityPub, kind: DropKind, times: u32) {
    let mut txn = db.write_txn().unwrap();
    for _ in 0..times {
        txn.record_drop_event(m, kind).unwrap();
    }
    txn.commit().unwrap();
}

fn pending_of(db: &Db, m: &IdentityPub) -> Option<PendingDrops> {
    db.list_pending_drops()
        .unwrap()
        .into_iter()
        .find(|(k, _)| k == m)
        .map(|(_, p)| p)
}

fn row_with_drops(ann: f64, silent: f64, presumed: f64, last_update: u64) -> PairLedger {
    PairLedger {
        drop_ann: ann,
        drop_silent: silent,
        drop_presumed: presumed,
        last_update: Some(Timestamp(last_update)),
        ..PairLedger::default()
    }
}

// ── DC-1: what one event is (Д-I) ───────────────────────────────────────────

#[test]
fn only_the_first_loss_of_a_held_placement_on_fresh_evidence_is_a_drop_event() {
    // The spec's table, written out: which (cause, new status) pair is a loss of which kind.
    // Every other combination must be refused, and the refusal must name the right reason.
    fn kind_of(cause: LossCause, new: PlacementStatus) -> Option<DropKind> {
        match (cause, new) {
            (LossCause::DropNotice, PlacementStatus::Lost) => Some(DropKind::Announced),
            (LossCause::PosFail, PlacementStatus::Lost) => Some(DropKind::Silent),
            (LossCause::PosNotHeld, PlacementStatus::Lost) => Some(DropKind::Silent),
            (LossCause::PosTimeout, PlacementStatus::PresumedLost) => Some(DropKind::Presumed),
            _ => None,
        }
    }
    let priors = [
        PlacementStatus::Offered,
        PlacementStatus::Accepted,
        PlacementStatus::Alive,
        PlacementStatus::Uncertain,
        PlacementStatus::PresumedLost,
        PlacementStatus::Lost,
        PlacementStatus::Deleting,
    ];
    let causes = [
        LossCause::DropNotice,
        LossCause::PosFail,
        LossCause::PosNotHeld,
        LossCause::PosTimeout,
    ];
    let news = [
        PlacementStatus::Lost,
        PlacementStatus::PresumedLost,
        PlacementStatus::Uncertain,
    ];
    let placed_at = Timestamp(1_000);
    // Before the episode, in the SAME second (review of intent BLOCK-1: not an event), after.
    let evidence = [
        ("older", Timestamp(999), false),
        ("same second", Timestamp(1_000), false),
        ("younger", Timestamp(1_001), true),
    ];

    let mut events = 0;
    for prior in priors {
        for cause in causes {
            for new in news {
                for (label, at, fresh) in evidence {
                    let got = drop_event_for(prior, new, cause, at, placed_at);
                    let held = matches!(prior, PlacementStatus::Alive | PlacementStatus::Uncertain);
                    let want = match kind_of(cause, new) {
                        None => Err(NotCounted::NoLossTransition),
                        Some(_) if !held => Err(NotCounted::PriorNotHeld),
                        Some(_) if !fresh => Err(NotCounted::EvidenceBeforeEpisode),
                        Some(kind) => Ok(kind),
                    };
                    assert_eq!(
                        got, want,
                        "{prior:?} -> {new:?} by {cause:?}, evidence {label} than placed_at"
                    );
                    if got.is_ok() {
                        events += 1;
                    }
                }
            }
        }
    }
    // 2 held priors × 4 matching (cause, status) pairs × 1 fresh evidence.
    assert_eq!(
        events, 8,
        "exactly the held × matching × fresh cells are events"
    );
}

// ── DC-2 / DC-3: the leak (Д-L) ─────────────────────────────────────────────

#[test]
fn drop_counters_leak_bit_for_bit_like_the_sim_sweep_at_the_same_dt() {
    // DC-2. One sub-step each (27.9 < 28 days), so the recorder applies the expression once
    // and must equal the sim's to the last bit.
    for dt in [1.0 / 24.0, 1.0, 7.0, 27.9] {
        assert_eq!(sub_steps(dt).count, 1, "premise: dt={dt} is one sub-step");
        let mut ledger = row_with_drops(5.0, 5.0, 5.0, 0);
        accrue(&mut ledger, &no_volume(), dt);
        assert_eq!(ledger.drop_ann, sim_leak(5.0, dt), "drop_ann at dt={dt}");
        assert_eq!(
            ledger.drop_silent,
            sim_leak(5.0, dt),
            "drop_silent at dt={dt}"
        );
        assert_eq!(
            ledger.drop_presumed,
            sim_leak(5.0, dt),
            "drop_presumed at dt={dt}"
        );
    }
}

#[test]
fn an_unobserved_gap_leaks_the_drop_counters_too() {
    // DC-3. The decay is unconditional — like the sim, unlike the charge: the dark 9.875 days
    // leak first, then the observed 0.125.
    let window = observed_window_days(1);
    assert_eq!(window, 0.125, "premise: the observed window at scale 1");
    let mut ledger = row_with_drops(4.0, 2.0, 1.0, 0);

    let outcome = accrue_interval(&mut ledger, &no_volume(), 10.0, window);

    assert_eq!(outcome.unobserved_days, 9.875);
    assert_eq!(ledger.drop_ann, sim_leak(sim_leak(4.0, 9.875), 0.125));
    assert_eq!(ledger.drop_silent, sim_leak(sim_leak(2.0, 9.875), 0.125));
    assert_eq!(ledger.drop_presumed, sim_leak(sim_leak(1.0, 9.875), 0.125));
}

#[test]
fn drop_counters_leak_exactly_like_the_sim_across_a_sub_step_boundary() {
    // N-5 (review). Intervals longer than the 28-day ceiling are leaked in equal sub-steps,
    // each by the sim's own expression: 56 days = 2 × 28 (factor 1 − 28/56 = 0.5 each, so
    // a quarter survives), 90 days = 4 × 22.5.
    for (dt, count, step) in [(56.0, 2u32, 28.0), (90.0, 4u32, 22.5)] {
        let plan = sub_steps(dt);
        assert_eq!(
            (plan.count, plan.step_days),
            (count, step),
            "premise: dt={dt} is {count} × {step} days"
        );
        let mut ledger = row_with_drops(8.0, 4.0, 2.0, 0);
        accrue(&mut ledger, &no_volume(), dt);
        let sim = |c: f64| (0..count).fold(c, |c, _| sim_leak(c, step));
        assert_eq!(ledger.drop_ann, sim(8.0), "drop_ann at dt={dt}");
        assert_eq!(ledger.drop_silent, sim(4.0), "drop_silent at dt={dt}");
        assert_eq!(ledger.drop_presumed, sim(2.0), "drop_presumed at dt={dt}");
    }
    let mut ledger = row_with_drops(8.0, 0.0, 0.0, 0);
    accrue(&mut ledger, &no_volume(), 56.0);
    assert!(
        (ledger.drop_ann - 0.25 * 8.0).abs() <= 1e-12 * 8.0,
        "56 days leave a quarter: {}",
        ledger.drop_ann
    );
}

// ── DC-4..DC-6, DC-8: the fold (Д-K) ────────────────────────────────────────

#[test]
fn a_tick_folds_pending_drops_after_decaying_the_interval_and_empties_the_queue() {
    // DC-4. "Decay over the interval, then +N": the events queued since the last tick are
    // added at full weight on top of the decayed row, and the queue is emptied.
    let db = test_db();
    let them = master(0x20);
    db.upsert_peer(&peer_of(device(0x21), them)).unwrap();
    let t0 = 10 * DAY;
    let prior = row_with_drops(2.0, 0.0, 1.0, t0);
    db.upsert_pair_ledger(&them, &prior).unwrap();
    queue(&db, &them, DropKind::Announced, 3);
    queue(&db, &them, DropKind::Presumed, 2);

    let report = PairLedgerRecorder::new(db.clone())
        .tick_report(&my_master(), Timestamp(t0 + TICK), 1)
        .unwrap();

    let dt = prior.elapsed_days(Timestamp(t0 + TICK), 1).unwrap();
    let stored = db.get_pair_ledger(&them).unwrap().unwrap();
    assert_eq!(stored.drop_ann, sim_leak(2.0, dt) + 3.0);
    assert_eq!(stored.drop_silent, 0.0);
    assert_eq!(stored.drop_presumed, sim_leak(1.0, dt) + 2.0);
    assert!(
        db.list_pending_drops().unwrap().is_empty(),
        "the queue is taken, not copied"
    );
    let row = &report.rows[0];
    assert_eq!(
        (row.ann_events, row.silent_events, row.presumed_events),
        (3, 0, 2)
    );
    assert_eq!(row.drop_ann, stored.drop_ann);
    assert_eq!(row.drop_presumed, stored.drop_presumed);
    assert_eq!(report.stats.drop_events_folded, 5);
}

#[test]
fn folding_before_the_decay_would_have_given_a_different_answer() {
    // The order is observable: `+N` then decay would shrink the fresh events too. Pins that
    // DC-4 checks the order and not only the sum (mutation "+N first" of the spec).
    let dt = 1.0 / 24.0;
    let decay_then_add = sim_leak(2.0, dt) + 3.0;
    let add_then_decay = sim_leak(2.0 + 3.0, dt);
    assert!(decay_then_add > add_then_decay);
}

#[test]
fn a_seeding_or_idle_tick_leaves_pending_drops_queued() {
    // DC-5. A seeded row is not reported (nothing was integrated), so an event folded there
    // would never reach the log; an idle tick (same second / clock went back) writes
    // nothing. Both leave the queue for the next ACCRUING tick.
    let db = test_db();
    let them = master(0x30);
    db.upsert_peer(&peer_of(device(0x31), them)).unwrap();
    queue(&db, &them, DropKind::Announced, 1);
    let recorder = PairLedgerRecorder::new(db.clone());
    let t0 = 5 * DAY;

    let seed = recorder
        .tick_report(&my_master(), Timestamp(t0), 1)
        .unwrap();
    assert_eq!(seed.stats.seeded, 1);
    assert_eq!(seed.stats.drop_events_folded, 0);
    assert_eq!(
        pending_of(&db, &them),
        Some(PendingDrops {
            announced: 1,
            ..PendingDrops::default()
        })
    );
    assert_eq!(db.get_pair_ledger(&them).unwrap().unwrap().drop_ann, 0.0);

    let idle = recorder
        .tick_report(&my_master(), Timestamp(t0), 1)
        .unwrap();
    assert_eq!(idle.stats.idle, 1);
    assert_eq!(pending_of(&db, &them).map(|p| p.announced), Some(1));

    let back = recorder
        .tick_report(&my_master(), Timestamp(t0 - DAY), 1)
        .unwrap();
    assert_eq!(back.stats.idle, 1, "a backward clock jump is idle too");
    assert_eq!(pending_of(&db, &them).map(|p| p.announced), Some(1));

    let accrued = recorder
        .tick_report(&my_master(), Timestamp(t0 + TICK), 1)
        .unwrap();
    assert_eq!(accrued.rows[0].ann_events, 1);
    assert_eq!(db.get_pair_ledger(&them).unwrap().unwrap().drop_ann, 1.0);
    assert_eq!(pending_of(&db, &them), None);
}

#[test]
fn pending_drops_are_folded_exactly_once_across_ticks() {
    // DC-6. The second accruing tick finds an empty queue: no event, only the leak.
    let db = test_db();
    let them = master(0x40);
    db.upsert_peer(&peer_of(device(0x41), them)).unwrap();
    let t0 = 20 * DAY;
    db.upsert_pair_ledger(&them, &row_with_drops(0.0, 0.0, 0.0, t0))
        .unwrap();
    queue(&db, &them, DropKind::Silent, 1);
    let recorder = PairLedgerRecorder::new(db.clone());

    let first = recorder
        .tick_report(&my_master(), Timestamp(t0 + TICK), 1)
        .unwrap();
    let after_first = db.get_pair_ledger(&them).unwrap().unwrap();
    let second = recorder
        .tick_report(&my_master(), Timestamp(t0 + 2 * TICK), 1)
        .unwrap();
    let after_second = db.get_pair_ledger(&them).unwrap().unwrap();

    assert_eq!(first.rows[0].silent_events, 1);
    assert_eq!(after_first.drop_silent, 1.0);
    assert_eq!(
        (
            second.rows[0].ann_events,
            second.rows[0].silent_events,
            second.rows[0].presumed_events
        ),
        (0, 0, 0)
    );
    assert_eq!(second.stats.drop_events_folded, 0);
    let dt = after_first
        .elapsed_days(Timestamp(t0 + 2 * TICK), 1)
        .unwrap();
    assert_eq!(after_second.drop_silent, sim_leak(1.0, dt), "only the leak");
}

#[test]
fn pending_drops_for_a_master_outside_the_sweep_stay_queued() {
    // DC-8. The fold is a point `take` per row of the sweep (Д-C), not a scan of the queue:
    // a master without a PeerRecord has no row this tick, so its events wait (N-5).
    let db = test_db();
    let known = master(0x50);
    let stranger = master(0x51);
    db.upsert_peer(&peer_of(device(0x52), known)).unwrap();
    db.upsert_pair_ledger(&known, &row_with_drops(0.0, 0.0, 0.0, DAY))
        .unwrap();
    queue(&db, &stranger, DropKind::Announced, 2);

    let report = PairLedgerRecorder::new(db.clone())
        .tick_report(&my_master(), Timestamp(DAY + TICK), 1)
        .unwrap();

    assert_eq!(report.stats.accrued, 1, "premise: the known master accrued");
    assert_eq!(pending_of(&db, &stranger).map(|p| p.announced), Some(2));
    assert!(db.get_pair_ledger(&stranger).unwrap().is_none());
}

// ── DC-9: the event's master (Д-M) ──────────────────────────────────────────

#[test]
fn the_drop_master_is_the_peer_record_master_not_device_to_master() {
    // DC-9. device_to_master is not in the SystemState snapshot, PeerRecord is (Р3 п.4): the
    // event must be keyed by the same master the sweep groups by, or it never folds.
    let db = test_db();
    let dev = device(0x60);
    let m = master(0x61);
    db.upsert_peer(&peer_of(dev, m)).unwrap();
    db.set_master_for_device(&dev, &master(0x62)).unwrap(); // a DIFFERENT mapping
    assert_eq!(ledger_master_for_device(&db, &dev).unwrap(), Some(m));

    let placeholder_dev = device(0x63);
    db.upsert_peer(&peer_of(placeholder_dev, IdentityPub([0; 32])))
        .unwrap();
    assert_eq!(
        ledger_master_for_device(&db, &placeholder_dev).unwrap(),
        None,
        "the placeholder is not a person"
    );

    assert_eq!(
        ledger_master_for_device(&db, &device(0x64)).unwrap(),
        None,
        "no PeerRecord, no master"
    );
}

// ── DC-11: the fold touches nothing else (AC-7) ─────────────────────────────

#[test]
fn folding_drops_changes_no_other_axis() {
    // DC-11. Two identical databases, one with queued events: after one tick every field
    // except the three drop counters is equal to the bit.
    let make = |with_events: bool| {
        let db = test_db();
        let them = master(0x70);
        db.upsert_peer(&peer_of(device(0x71), them)).unwrap();
        db.upsert_holding(&crate::types::HoldingRecord {
            source_block_id: crate::types::SourceBlockId([0x72; 32]),
            owner_id: them,
            esi_ranges: vec![(0, 10)],
            importance: 0.5,
            total_bytes: 3 * (crate::constants::BYTES_PER_GB as u64),
            status: crate::types::HoldingStatus::Active,
            received_at: Timestamp(0),
            delete_requested_at: None,
            drop_notice_sent_at: None,
        })
        .unwrap();
        db.upsert_pair_ledger(
            &them,
            &PairLedger {
                gb_days_they_store_for_us: 7.0,
                gb_days_we_store_for_them: 11.0,
                depth_of_their_service: 13.0,
                v_dem: 2.0,
                observed_volume: 1.0,
                observed_tau: 3.0,
                drop_ann: 0.5,
                drop_silent: 0.25,
                drop_presumed: 0.125,
                last_update: Some(Timestamp(30 * DAY)),
            },
        )
        .unwrap();
        if with_events {
            queue(&db, &them, DropKind::Announced, 1);
            queue(&db, &them, DropKind::Silent, 2);
            queue(&db, &them, DropKind::Presumed, 3);
        }
        PairLedgerRecorder::new(db.clone())
            .tick(&my_master(), Timestamp(30 * DAY + TICK), 1)
            .unwrap();
        db.get_pair_ledger(&them).unwrap().unwrap()
    };
    let without = make(false);
    let with = make(true);

    assert_eq!(
        PairLedger {
            drop_ann: 0.0,
            drop_silent: 0.0,
            drop_presumed: 0.0,
            ..with.clone()
        },
        PairLedger {
            drop_ann: 0.0,
            drop_silent: 0.0,
            drop_presumed: 0.0,
            ..without.clone()
        },
        "G, D, v_dem, the run and the clock ignore drop events"
    );
    assert_eq!(with.drop_ann, without.drop_ann + 1.0);
    assert_eq!(with.drop_silent, without.drop_silent + 2.0);
    assert_eq!(with.drop_presumed, without.drop_presumed + 3.0);
}
