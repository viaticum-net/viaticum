// Р-3 (C-SP K1c, cluster-i2): a DropNotice changes only the placement whose ESIs it names.
// The rows of one block never share an ESI (repair-i8), so a notice that intersects none of
// this master's placements is about something we do not have — a range the device was since
// re-placed with fresh numbers, or another owner device's row read from the same master
// mailbox. Such a notice is ignored: no `Lost`, no seen row, no repair wake. A notice naming
// no ESI (holder cleanup) applies only when exactly one placement of the master can change.
// Child of `processor/tests.rs` (reuses `drop_fixture` and the two-device helpers of
// `drop_notice_dedup.rs`). Also dr-i8-b: the holder device found through PEERS after DR.

use tokio::sync::mpsc;
use viaticum_core::cluster::master_identity;
use viaticum_core::messages::build_signed_symbol_drop_notice;
use viaticum_core::types::{PlacementStatus, Timestamp};

use super::{
    DropFixture, drop_fixture, make_block_id, make_device_id, make_peer_record, make_signing_key,
    make_source_block, make_symbol_placement,
};
use crate::daemon::mailbox::poll::DropNoticeHandler;
use crate::daemon::repair::RepairTrigger;

impl DropFixture {
    /// A notice naming no ESI (what `holder_cleanup` sends).
    fn empty_notice(&self, after: u64) -> viaticum_core::messages::SymbolDropNoticeMsg {
        let ts = Timestamp(self.placed_at.0 + after);
        build_signed_symbol_drop_notice(self.block, vec![], ts, ts, &self.key)
    }
}

/// Mutation M13 (rule 2 back: no intersection → the first placement the notice can change)
/// → d2 goes `Lost`, the notice is remembered and repair wakes; this test reddens.
#[tokio::test]
async fn drop_notice_without_intersection_changes_nothing() {
    // d1 (0..10) and d2 (10..20), both Alive; an immediate notice for 500..510.
    let f = drop_fixture(0x85, PlacementStatus::Alive, None);
    let d2 = f.add_second_device(PlacementStatus::Alive);
    let notice = f.notice_for((500, 10), 10, 10);
    let (tx, mut rx) = mpsc::channel::<RepairTrigger>(16);
    let handler = super::super::ProcessorDropHandler::new(f.db.clone(), tx);

    handler.handle_drop_notice(f.signer, notice.clone());

    assert!(!f.apply(notice), "not applied");
    assert_eq!(f.status(), PlacementStatus::Alive);
    assert_eq!(f.status_of(d2), PlacementStatus::Alive);
    assert_eq!(f.seen_rows(), 0, "not remembered");
    assert_eq!(f.announced_for(f.ledger_master), 0, "no pair-ledger event");
    assert!(rx.try_recv().is_err(), "no repair wake");
}

/// cluster-i2, owner side. Owner devices O1 and O2 read one master mailbox. Here we are O2:
/// our placement of the block on the holder's device is 0..10; the holder's letter is about
/// O1's placement, 10..20 — not ours. Mutation M13 → our placement goes `Lost`; reddens.
///
/// Holds only the case of DISJOINT ranges of the owner siblings. The overlapping case (both
/// siblings in ESI namespace 0, the same `block_id` from the same file) is not closed: a
/// letter about O1's placement also names ESIs of ours, and ours goes `Lost`. That is the
/// residual door of cluster-i2-a, accepted by the conductor, not fixed by Р-3.
#[tokio::test]
async fn drop_notice_for_owner_sibling_range_changes_nothing() {
    let f = drop_fixture(0x87, PlacementStatus::Alive, None);

    assert!(!f.apply(f.notice_for((10, 10), 10, 10)));

    assert_eq!(f.status(), PlacementStatus::Alive);
    assert_eq!(f.seen_rows(), 0);
    assert_eq!(f.announced_for(f.ledger_master), 0);
}

/// cluster-i2 (repair-i8 at work). d1 (0..10) announces an advance drop and goes `Lost`;
/// repair puts the block on its sibling d2 with fresh numbers (10..20); a week later d1's
/// FINAL notice for 0..10 arrives. It finds d1 (already `Lost`) and leaves d2 `Alive`. The
/// fresh numbers are what keep the two apart (with d1's numbers reused, both rows would
/// intersect the final notice — `offer_plan` tests, `repair_after_advance_drop_notice_…`).
#[tokio::test]
async fn final_drop_notice_after_repair_onto_sibling_keeps_sibling_alive() {
    let f = drop_fixture(0x89, PlacementStatus::Alive, None);
    let week = 7 * 86_400;
    assert!(f.apply(f.notice_for((0, 10), 10, 10 + week)), "advance");
    assert_eq!(f.status(), PlacementStatus::Lost);
    let d2 = f.add_second_device(PlacementStatus::Alive);

    assert!(
        f.apply(f.notice_for((0, 10), 10 + week, 10 + week)),
        "final"
    );

    assert_eq!(f.status(), PlacementStatus::Lost);
    assert_eq!(
        f.status_of(d2),
        PlacementStatus::Alive,
        "the sibling is untouched"
    );
    assert_eq!(f.announced_for(f.ledger_master), 1, "one loss, one event");
}

/// Р-3: a notice naming no ESI cannot tell two devices apart — ignored. Mutation: the empty
/// notice falls back to "the first placement it can change" → d1 goes `Lost`; reddens.
#[tokio::test]
async fn empty_range_notice_with_two_candidates_is_ignored() {
    let f = drop_fixture(0x8B, PlacementStatus::Alive, None);
    let d2 = f.add_second_device(PlacementStatus::Alive);

    assert!(!f.apply(f.empty_notice(10)));

    assert_eq!(f.status(), PlacementStatus::Alive);
    assert_eq!(f.status_of(d2), PlacementStatus::Alive);
    assert_eq!(f.seen_rows(), 0);
}

/// Р-3: with exactly one placement the notice can change (d2 already `Lost`), an empty notice
/// is about d1 and applies.
#[tokio::test]
async fn empty_range_notice_with_one_candidate_applies() {
    let f = drop_fixture(0x8D, PlacementStatus::Alive, None);
    let d2 = f.add_second_device(PlacementStatus::Lost);

    assert!(f.apply(f.empty_notice(10)));

    assert_eq!(f.status(), PlacementStatus::Lost);
    assert_eq!(f.status_of(d2), PlacementStatus::Lost);
    assert_eq!(f.seen_rows(), 1);
}

/// dr-i8-b. After the owner's DR `device_to_master` is empty (it is not in the SS); the
/// holder's PeerRecord (from the SS) carries its master. The holder's letter applies to its
/// placement at once, without waiting for re-authentication. Mutation: the bare
/// `get_devices_for_master` back → "unknown master", nothing applied; this test reddens.
#[tokio::test]
async fn drop_notice_after_owner_dr_finds_holder_device_through_peers() {
    let db = viaticum_core::db::Db::open_in_memory().unwrap();
    let key = make_signing_key(0x8F);
    let signer = master_identity(&key);
    let device = make_device_id(0x8F);
    let block = make_block_id(0x90);
    let placed_at = Timestamp(Timestamp::now().0 - 3600);
    let mut peer = make_peer_record(device);
    peer.master_identity = signer;
    db.upsert_peer(&peer).unwrap();
    db.upsert_source_block(&make_source_block(block)).unwrap();
    let mut p = make_symbol_placement(block, device, vec![(0, 10)], PlacementStatus::Alive);
    p.placed_at = placed_at;
    db.upsert_placement(&p).unwrap();
    assert!(
        db.get_devices_for_master(&signer).unwrap().is_empty(),
        "premise: device_to_master is empty, as after DR"
    );
    let f = DropFixture {
        db,
        key,
        signer,
        ledger_master: signer,
        device,
        block,
        placed_at,
    };

    assert!(
        f.apply(f.fresh_notice(10)),
        "applied without re-authentication"
    );

    assert_eq!(f.status(), PlacementStatus::Lost);
    assert_eq!(f.seen_rows(), 1);
    assert_eq!(f.announced_for(signer), 1);
}
