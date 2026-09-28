// D-1a, D-1b, D-2: the 4R shadow on the pressure tick decides nothing, cannot stop the old
// path, and keeps its latch across restarts.

use std::collections::BTreeSet;

use tempfile::TempDir;
use viaticum_core::budget::{DiskPressure, PressureResult, evaluate_pressure};
use viaticum_core::db::Db;
use viaticum_core::four_r::Hysteresis;
use viaticum_core::four_r_holder::FourRParams;
use viaticum_core::messages::SymbolDropNoticeBatchMsg;
use viaticum_core::types::{HoldingRecord, HoldingStatus, PairLedger, Timestamp, from_cbor_bytes};

use super::{block_id, holder_master_pub, make_router_and_sender, owner_id, test_key};
use crate::daemon::four_r_log::tests::capture;

/// Hard pressure (quota 1000, used 990) over four owners. The old path evicts the lowest
/// importance × trust first; the ledger rows make 4R rank the owners DIFFERENTLY (owner 0x01,
/// the old path's first victim, serves us a lot), so a shadow that leaked into the decision
/// would change what is dropped.
fn hard_fixture(db: &Db) -> Vec<HoldingRecord> {
    let now = Timestamp::now().0;
    let mk = |o: u8, b: u8, bytes: u64, imp: f64, received: u64| HoldingRecord {
        source_block_id: block_id(b),
        owner_id: owner_id(o),
        esi_ranges: vec![(0, 1)],
        importance: imp,
        total_bytes: bytes,
        status: HoldingStatus::Active,
        received_at: Timestamp(received),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    let hs = vec![
        mk(0x01, 0xA1, 300, 0.1, 0),
        mk(0x02, 0xB1, 250, 0.9, now),
        mk(0x03, 0xC1, 240, 0.5, now),
        mk(0x04, 0xD1, 200, 0.7, now),
    ];
    for h in &hs {
        db.upsert_holding(h).unwrap();
    }
    let row = |g: f64| PairLedger {
        gb_days_they_store_for_us: g,
        last_update: Some(Timestamp(1)),
        ..Default::default()
    };
    db.upsert_pair_ledger(&owner_id(0x01), &row(5.0)).unwrap();
    db.upsert_pair_ledger(&owner_id(0x03), &row(0.5)).unwrap();
    hs
}

/// Everything the old path left behind: surviving holdings with their notice flag, and the
/// published DropNotices as (target, block, deadline ≤ now).
async fn run_old_path_with(
    p: &FourRParams,
) -> (BTreeSet<(u8, bool)>, BTreeSet<(u8, u8, bool)>, bool) {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let (router, sender) = make_router_and_sender(&db);
    hard_fixture(&db);
    super::super::check_pressure(
        &db,
        dir.path(),
        &router,
        holder_master_pub(),
        1000,
        0,
        dir.path(),
        0,
        1,
        &test_key(),
        p,
    )
    .await
    .unwrap();
    let left: BTreeSet<(u8, bool)> = db
        .list_all_holdings()
        .unwrap()
        .iter()
        .map(|h| (h.source_block_id.0[0], h.drop_notice_sent_at.is_some()))
        .collect();
    let now = Timestamp::now().0;
    let mut published = BTreeSet::new();
    for req in sender.drain().await {
        let batch: SymbolDropNoticeBatchMsg = from_cbor_bytes(&req.entry.payload).unwrap();
        for n in batch.notices {
            published.insert((
                req.entry.target.0[0],
                n.source_block_id.0[0],
                n.deadline.0 <= now,
            ));
        }
    }
    let latched = db.get_four_r_phase().unwrap().evicting;
    (left, published, latched)
}

/// D-1a (4r-i44, W-1): with the shadow at two very different dial sets the old path deletes
/// the same holdings, publishes the same notices and stamps the same `drop_notice_sent_at` —
/// exactly `evaluate_pressure`'s plan — while the shadow did run (its latch row is set).
#[tokio::test]
async fn check_pressure_with_the_shadow_evicts_and_notifies_exactly_as_before() {
    let aggressive = FourRParams {
        v_free_gb: 0.0,
        c_recip_days: 1e-12, // V_ret ≈ ∞·κ: only κ = 0 owners are capped — but whole
        theta_p: 0.0,
        hyst: Hysteresis {
            s_hard: 0.5,
            s_target: 0.8,
            s_soft: 0.9,
        },
        ..FourRParams::default()
    };
    let (left_a, pub_a, latched_a) = run_old_path_with(&FourRParams::default()).await;
    let (left_b, pub_b, latched_b) = run_old_path_with(&aggressive).await;
    assert!(
        latched_a && latched_b,
        "the shadow must have run (latch row written)"
    );
    assert_eq!(left_a, left_b);
    assert_eq!(pub_a, pub_b);

    // …and it is exactly the old plan.
    let db = Db::open_in_memory().unwrap();
    let hs = hard_fixture(&db);
    let res = evaluate_pressure(
        1000,
        0,
        990,
        &hs,
        |_: &viaticum_core::types::IdentityPub| 0.5,
        Timestamp::now().0,
    );
    assert_eq!(res.pressure, DiskPressure::Hard);
    let immediate: BTreeSet<u8> = res
        .immediate_evictions
        .iter()
        .map(|e| e.source_block_id.0[0])
        .collect();
    let noticed: BTreeSet<u8> = res
        .drop_notices
        .iter()
        .map(|n| n.source_block_id.0[0])
        .collect();
    assert!(
        !immediate.is_empty() && !noticed.is_empty(),
        "fixture must exercise both phases"
    );
    let want_left: BTreeSet<(u8, bool)> = hs
        .iter()
        .map(|h| h.source_block_id.0[0])
        .filter(|b| !immediate.contains(b))
        .map(|b| (b, noticed.contains(&b)))
        .collect();
    assert_eq!(left_a, want_left);
    let published_blocks: BTreeSet<u8> = pub_a.iter().map(|x| x.1).collect();
    let want_blocks: BTreeSet<u8> = immediate.union(&noticed).copied().collect();
    assert_eq!(
        published_blocks, want_blocks,
        "no DropNotice outside the old plan"
    );
    for (_, b, deadline_now) in &pub_a {
        assert_eq!(
            *deadline_now,
            immediate.contains(b),
            "block {b:#x}: immediate vs advance"
        );
    }
}

/// D-1b: a shadow that cannot read its inputs (corrupt ledger row) logs a warning and the old
/// path still evicts.
#[tokio::test]
async fn a_failing_shadow_does_not_stop_the_old_eviction() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let (router, sender) = make_router_and_sender(&db);
    let hs = hard_fixture(&db);
    db.corrupt_pair_ledger_row_for_test(&owner_id(0x02))
        .unwrap();
    let (sink, guard) = capture("viaticum::four_r=warn");
    super::super::check_pressure(
        &db,
        dir.path(),
        &router,
        holder_master_pub(),
        1000,
        0,
        dir.path(),
        0,
        1,
        &test_key(),
        &FourRParams::default(),
    )
    .await
    .expect("the old path must not fail on a shadow error");
    drop(guard);
    let left = db.list_all_holdings().unwrap().len();
    assert!(
        left < hs.len(),
        "the old path must still have evicted (left {left})"
    );
    assert!(
        !sender.drain().await.is_empty(),
        "…and published its DropNotices"
    );
    assert!(
        sink.text().contains("four_r: shadow tick failed"),
        "{}",
        sink.text()
    );
    assert!(
        !db.get_four_r_phase().unwrap().evicting,
        "a failed tick writes no latch"
    );
}

fn empty_result() -> PressureResult {
    PressureResult {
        pressure: DiskPressure::Normal,
        immediate_evictions: vec![],
        drop_notices: vec![],
        freed_bytes: 0,
    }
}

fn one_holding(bytes: u64) -> Vec<HoldingRecord> {
    vec![HoldingRecord {
        source_block_id: block_id(0x51),
        owner_id: owner_id(0x05),
        esi_ranges: vec![(0, 1)],
        importance: 0.5,
        total_bytes: bytes,
        status: HoldingStatus::Active,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    }]
}

fn tick(db: &Db, bytes: u64) {
    tick_with_disk(db, bytes, 1 << 40);
}

fn tick_with_disk(db: &Db, bytes: u64, disk_free: u64) {
    super::super::shadow::shadow_pressure(
        db,
        &one_holding(bytes),
        super::super::shadow::ShadowQuota {
            disk_free,
            soft: 1000,
            reserve: 0,
            hard: 0,
        },
        holder_master_pub(),
        &|_: &viaticum_core::types::IdentityPub| 0.5,
        Timestamp::now(),
        &empty_result(),
        &FourRParams::default(),
    )
    .unwrap();
}

/// D-2: the latch goes on below `s_hard`, HOLDS in the deadband across a reopened database
/// (a RAM latch would forget it), and is released at `s_target`.
#[test]
fn the_shadow_tick_latches_and_releases_the_persisted_phase() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("db.redb");
    {
        let db = Db::open(&path).unwrap();
        tick(&db, 990); // φ = 0.01 < s_hard
        let ph = db.get_four_r_phase().unwrap();
        assert!(ph.evicting && ph.since.is_some());
    }
    {
        let db = Db::open(&path).unwrap();
        tick(&db, 900); // φ = 0.10, deadband: hold the persisted latch
        assert!(db.get_four_r_phase().unwrap().evicting);
        tick(&db, 850); // φ = 0.15 ≥ s_target: release
        assert!(!db.get_four_r_phase().unwrap().evicting);
    }
    let db = Db::open(&path).unwrap();
    tick(&db, 900); // deadband after a release: stays released
    assert!(!db.get_four_r_phase().unwrap().evicting);
}

/// D-2b (`4r-i66`): a tick on which the node did not read its disk (`disk_free = 0`, blind
/// φ = 0 < s_hard) leaves the persisted latch untouched — OFF, never written — and the next
/// valid tick in the deadband therefore stays OFF instead of inheriting a blind ON.
#[test]
fn an_invalid_tick_does_not_write_the_latch_and_the_next_deadband_tick_stays_off() {
    let dir = TempDir::new().unwrap();
    let db = Db::open(&dir.path().join("db.redb")).unwrap();
    let (sink, g) = capture("viaticum::four_r=info");
    tick_with_disk(&db, 900, 0); // Q = min(1000, 900 + 0) = 900 ⇒ φ = 0, measure invalid
    drop(g);
    let ph = db.get_four_r_phase().unwrap();
    assert!(!ph.evicting, "a blind tick must not latch ON");
    assert!(ph.since.is_none(), "the latch row must not be written");
    let line = sink
        .text()
        .lines()
        .find(|l| l.contains("four_r: pressure tick"))
        .map(str::to_string)
        .expect("the frozen tick is still logged");
    for key in ["measure_valid=false", "phase_prev=false", "phase=false"] {
        assert!(line.contains(key), "missing {key}: {line}");
    }
    tick(&db, 900); // disk read, φ = 0.10: deadband ⇒ hold OFF
    assert!(!db.get_four_r_phase().unwrap().evicting);
    // Control: the same φ = 0 with the disk READ does latch ON.
    tick(&db, 1000);
    assert!(db.get_four_r_phase().unwrap().evicting);
}
