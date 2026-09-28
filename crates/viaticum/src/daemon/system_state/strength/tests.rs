// Strength of SS blocks, place choice, keep-set (CROWN-1 V.16.5, V.17; mailbox-i56,
// dr-i48, dr-i49). Real redb, real records.

use viaticum_core::db::Db;
use viaticum_core::db::testutil::test_db;
use viaticum_core::mailbox::seal::PointerPlace;
use viaticum_core::system_state::CatalogLineageId;
use viaticum_core::system_state::catalog::{
    PlacePublication, PointerPublications, ReachedEnvelope, RetiredPointer,
};
use viaticum_core::types::{
    DeviceId, FileId, IdentityPub, PeerRecord, PlacementStatus, SourceBlockId, SourceBlockRecord,
    SourceBlockStatus, SourceBlockType, SymbolPlacement, Timestamp,
};

use super::*;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 24 * 3600;

/// k = 1 → k_eff = 1 + DECODE_OVERHEAD = 4: a holder with 4 symbols is one copy.
fn ss_record(db: &Db, id: u8) -> SourceBlockId {
    let block_id = SourceBlockId([id; 32]);
    db.upsert_source_block(&SourceBlockRecord {
        block_id,
        k: 1,
        t: 64,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(1),
        encrypted_size: Some(64),
        n: Some(12),
        overhead: Some(3.0),
        drop_notice_sent_at: None,
        importance: 1.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.99,
    })
    .unwrap();
    block_id
}

/// A holder (device `[holder; 32]`) last seen at `seen`, holding `symbols` of `block`.
fn hold(db: &Db, block: SourceBlockId, holder: u8, symbols: u32, seen: u64) {
    let device = DeviceId([holder; 32]);
    db.upsert_peer(&PeerRecord {
        device_id: device,
        master_identity: IdentityPub([holder; 32]),
        trust_p: 0.5,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1),
        last_seen: Timestamp(seen),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.5,
        last_avail_sample: 0,
    })
    .unwrap();
    db.upsert_placement(&SymbolPlacement {
        source_block_id: block,
        holder_id: device,
        file_id: FileId(0),
        esi_ranges: vec![(u32::from(holder) * 100, symbols)],
        binding_seed: [0; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(1),
        consecutive_misses: 0,
    })
    .unwrap();
}

/// A block with `copies` holders seen now (strength = copies).
fn block_of_strength(db: &Db, id: u8, copies: u8) -> SourceBlockId {
    let b = ss_record(db, id);
    for h in 0..copies {
        hold(db, b, id.wrapping_mul(16).wrapping_add(h + 1), 4, NOW);
    }
    b
}

fn record(
    place: PointerPlace,
    base: SourceBlockId,
    diffs: Vec<SourceBlockId>,
    at: u64,
    acks: usize,
) -> PlacePublication {
    PlacePublication {
        place,
        base,
        diffs,
        generation: 1,
        created_at: Timestamp(at),
        files: 1,
        acks: (0..acks).map(|i| DeviceId([0xE0 + i as u8; 32])).collect(),
        entry_cbor: vec![],
        target_sig: [0; 64],
        last_refusal: None,
        to_retire: vec![],
        reached: None,
    }
}

fn meta(current: Option<PlacePublication>, other: Option<PlacePublication>) -> PointerPublications {
    PointerPublications {
        current,
        other,
        ..PointerPublications::new(CatalogLineageId([1; 16]))
    }
}

// ─── strength (V.17.1, dr-i49) ─────────────────────────────────────────────────

#[test]
fn strength_ignores_holders_not_seen_for_w() {
    let db = test_db();
    let b = ss_record(&db, 1);
    hold(&db, b, 10, 4, NOW);
    hold(&db, b, 11, 4, NOW - 8 * DAY);
    hold(&db, b, 12, 4, NOW - 30 * DAY);
    assert_eq!(
        block_strength(&db, &b, NOW, 1).unwrap(),
        1.0,
        "only the seen holder counts"
    );
}

#[test]
fn night_offline_does_not_lower_strength() {
    let db = test_db();
    let b = ss_record(&db, 2);
    hold(&db, b, 20, 4, NOW);
    hold(&db, b, 21, 4, NOW - 10 * 3600);
    assert_eq!(block_strength(&db, &b, NOW, 1).unwrap(), 2.0);
}

#[test]
fn strength_window_scales_with_time_scale() {
    let db = test_db();
    let b = ss_record(&db, 3);
    // Seen 700 s ago: inside W at ts=1 (7 days), outside at ts=1000 (≈ 605 s).
    hold(&db, b, 30, 4, NOW - 700);
    assert_eq!(holder_seen_window_secs(1000), 7 * DAY / 1000);
    assert_eq!(block_strength(&db, &b, NOW, 1).unwrap(), 1.0);
    assert_eq!(block_strength(&db, &b, NOW, 1000).unwrap(), 0.0);
}

#[test]
fn strength_counts_uncertain_but_not_lost_placements() {
    let db = test_db();
    let b = ss_record(&db, 4);
    hold(&db, b, 40, 4, NOW);
    hold(&db, b, 41, 4, NOW);
    let mut p = db.list_placements_for_block(&b).unwrap();
    p.sort_by_key(|x| x.holder_id.0);
    let mut uncertain = p[0].clone();
    uncertain.status = PlacementStatus::Uncertain;
    db.upsert_placement(&uncertain).unwrap();
    let mut lost = p[1].clone();
    lost.status = PlacementStatus::Lost;
    db.upsert_placement(&lost).unwrap();
    assert_eq!(block_strength(&db, &b, NOW, 1).unwrap(), 1.0);
}

/// dr-i41 / dr-i49: ready = the accepted pointer has the dr-i39 acks AND every block
/// (base and diffs) is recoverable by the estimate; a holder not seen for W does not
/// count; an unacked newer record does not make the node ready.
#[test]
fn readiness_needs_acks_and_every_block_recoverable() {
    let db = test_db();
    for i in 0..6u8 {
        db.upsert_peer(&PeerRecord {
            device_id: DeviceId([0xA0 + i; 32]),
            ..peer_template()
        })
        .unwrap();
    }
    assert_eq!(pointer_readiness(&db, 6, NOW, 1).unwrap().accepted, None);
    let base = block_of_strength(&db, 5, 3);
    let d1 = block_of_strength(&db, 6, 1);
    let d2 = ss_record(&db, 7);
    hold(&db, d2, 0x70, 4, NOW - 8 * DAY); // gone for more than W
    let mut m = meta(
        Some(record(PointerPlace::A, base, vec![d1, d2], 100, 3)),
        None,
    );
    db.put_pointer_publications(&m).unwrap();
    let r = pointer_readiness(&db, 6, NOW, 1).unwrap();
    assert_eq!((r.blocks_placed, r.blocks_total, r.ready), (2, 3, false));
    assert_eq!(r.accepted, Some((100, 1, 3)));
    hold(&db, d2, 0x71, 4, NOW);
    assert!(pointer_readiness(&db, 6, NOW, 1).unwrap().ready);
    // Two acks < 3.
    m.current.as_mut().unwrap().acks.truncate(2);
    db.put_pointer_publications(&m).unwrap();
    assert!(!pointer_readiness(&db, 6, NOW, 1).unwrap().ready);
    // A newer, unacked record: the older accepted one is what is reported.
    let newer = block_of_strength(&db, 8, 3);
    let m2 = meta(
        Some(record(PointerPlace::B, newer, vec![], 200, 0)),
        Some(record(PointerPlace::A, base, vec![d1, d2], 100, 3)),
    );
    db.put_pointer_publications(&m2).unwrap();
    let r = pointer_readiness(&db, 6, NOW, 1).unwrap();
    assert_eq!(r.accepted, Some((100, 1, 3)));
    assert!(r.ready);
}

/// dr-i52: a place whose new envelope is short of the threshold stands on the kept
/// earlier one (its diffs, its acks) while that one is unexpired; once it expires the
/// place stands on its own envelope again.
#[test]
fn readiness_stands_on_the_kept_envelope_until_it_expires() {
    let db = test_db();
    let base = block_of_strength(&db, 5, 3);
    let d1 = block_of_strength(&db, 6, 1);
    let mut cur = record(PointerPlace::A, base, vec![d1], 200, 1);
    cur.reached = Some(ReachedEnvelope {
        diffs: vec![],
        generation: 1,
        created_at: Timestamp(100),
        files: 7,
        acks: 3,
        expires_at: NOW + 1,
    });
    db.put_pointer_publications(&meta(Some(cur), None)).unwrap();
    let r = pointer_readiness(&db, 6, NOW, 1).unwrap();
    assert_eq!(r.accepted, Some((100, 7, 3)));
    assert_eq!((r.blocks_total, r.ready), (1, true));
    let r = pointer_readiness(&db, 6, NOW + 1, 1).unwrap();
    assert_eq!(r.accepted, Some((200, 1, 1)), "the kept envelope expired");
    assert!(!r.ready);
}

/// dr-i53: DR is ready while one place is restorable. A new base in the other place
/// with 1-2 acks does not make it "not ready"; the state DR restores is the ready
/// place's. Once the new base reaches the threshold it is the newest restorable state.
/// When no place is restorable, the newest acked place is reported, not ready.
#[test]
fn readiness_holds_on_the_other_place_while_a_new_base_collects_acks() {
    let db = test_db();
    let old = block_of_strength(&db, 5, 3);
    let new = block_of_strength(&db, 9, 3);
    for acks in [1, 2] {
        db.put_pointer_publications(&meta(
            Some(record(PointerPlace::B, new, vec![], 200, acks)),
            Some(record(PointerPlace::A, old, vec![], 100, 3)),
        ))
        .unwrap();
        let r = pointer_readiness(&db, 6, NOW, 1).unwrap();
        assert!(
            r.ready,
            "{acks} ack(s) on the new base: place A is restorable"
        );
        assert_eq!(
            r.restores_state_of,
            Some(100),
            "DR restores place A's state"
        );
        assert_eq!(r.accepted, Some((100, 1, 3)));
        assert_eq!((r.blocks_placed, r.blocks_total), (1, 1));
    }
    db.put_pointer_publications(&meta(
        Some(record(PointerPlace::B, new, vec![], 200, 3)),
        Some(record(PointerPlace::A, old, vec![], 100, 3)),
    ))
    .unwrap();
    let r = pointer_readiness(&db, 6, NOW, 1).unwrap();
    assert_eq!(
        (r.ready, r.restores_state_of),
        (true, Some(200)),
        "both restorable: the newest"
    );
    // Place A's holders gone for more than W: nothing restorable → not ready, and the
    // newest acked place (B, 2 acks) is what status reports.
    let gone = ss_record(&db, 0x55);
    hold(&db, gone, 0x5A, 4, NOW - 8 * DAY);
    db.put_pointer_publications(&meta(
        Some(record(PointerPlace::B, new, vec![], 200, 2)),
        Some(record(PointerPlace::A, gone, vec![], 100, 3)),
    ))
    .unwrap();
    let r = pointer_readiness(&db, 6, NOW, 1).unwrap();
    assert_eq!((r.ready, r.restores_state_of), (false, None));
    assert_eq!(r.accepted, Some((200, 1, 2)));
}

fn peer_template() -> PeerRecord {
    PeerRecord {
        device_id: DeviceId([0; 32]),
        master_identity: IdentityPub([0; 32]),
        trust_p: 0.5,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1),
        last_seen: Timestamp(NOW),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.5,
        last_avail_sample: 0,
    }
}

#[test]
fn readiness_threshold_is_three_or_half_of_a_small_circle() {
    assert_eq!(readiness_ack_threshold(25), 3);
    assert_eq!(readiness_ack_threshold(6), 3);
    assert_eq!(readiness_ack_threshold(5), 3);
    assert_eq!(readiness_ack_threshold(4), 2);
    assert_eq!(readiness_ack_threshold(1), 1);
    assert_eq!(readiness_ack_threshold(0), 1);
}

// ─── place choice (mailbox-i56) ────────────────────────────────────────────────

#[test]
fn new_base_goes_to_the_empty_place_first() {
    let db = test_db();
    let strong = block_of_strength(&db, 1, 5);
    let m = meta(Some(record(PointerPlace::A, strong, vec![], 100, 3)), None);
    assert_eq!(
        place_for_new_base(&db, &m, NOW, 1).unwrap(),
        PointerPlace::B
    );
    let m = meta(Some(record(PointerPlace::B, strong, vec![], 100, 3)), None);
    assert_eq!(
        place_for_new_base(&db, &m, NOW, 1).unwrap(),
        PointerPlace::A
    );
    assert_eq!(
        place_for_new_base(&db, &meta(None, None), NOW, 1).unwrap(),
        PointerPlace::A
    );
}

#[test]
fn new_base_replaces_the_weaker_place() {
    let db = test_db();
    let strong = block_of_strength(&db, 1, 5);
    let weak = block_of_strength(&db, 2, 1);
    let m = meta(
        Some(record(PointerPlace::A, strong, vec![], 200, 3)),
        Some(record(PointerPlace::B, weak, vec![], 100, 3)),
    );
    assert_eq!(
        place_for_new_base(&db, &m, NOW, 1).unwrap(),
        PointerPlace::B
    );
    // The current one is the weaker: it is displaced, the strong older one stays.
    let m = meta(
        Some(record(PointerPlace::A, weak, vec![], 200, 3)),
        Some(record(PointerPlace::B, strong, vec![], 100, 3)),
    );
    assert_eq!(
        place_for_new_base(&db, &m, NOW, 1).unwrap(),
        PointerPlace::A
    );
}

/// `r` with a real sealed envelope that expires at `expires_at`.
fn with_envelope(mut r: PlacePublication, expires_at: u64) -> PlacePublication {
    use viaticum_core::mailbox::seal::{RendezvousKeys, seal_self_pointer};
    let rv = RendezvousKeys::derive(&[7; 64]);
    let sealed = seal_self_pointer(
        &rv,
        &[1; 16],
        r.place,
        b"pointer",
        expires_at,
        expires_at - 10,
    )
    .unwrap();
    r.entry_cbor = viaticum_core::types::to_cbor_bytes(sealed.entry());
    r
}

/// mailbox-i58: the postmen dropped an expired envelope, so its place is empty in the
/// network — a new base takes it even over a weaker live place.
#[test]
fn place_with_expired_envelope_counts_as_empty() {
    let db = test_db();
    let strong = block_of_strength(&db, 1, 5);
    let weak = block_of_strength(&db, 2, 1);
    let live_strong = meta(
        Some(with_envelope(
            record(PointerPlace::B, weak, vec![], 200, 3),
            NOW + DAY,
        )),
        Some(with_envelope(
            record(PointerPlace::A, strong, vec![], 100, 3),
            NOW + DAY,
        )),
    );
    assert_eq!(
        place_for_new_base(&db, &live_strong, NOW, 1).unwrap(),
        PointerPlace::B,
        "control: the weaker live place is displaced"
    );
    let expired_strong = meta(
        Some(with_envelope(
            record(PointerPlace::B, weak, vec![], 200, 3),
            NOW + DAY,
        )),
        Some(with_envelope(
            record(PointerPlace::A, strong, vec![], 100, 3),
            NOW,
        )),
    );
    assert_eq!(
        place_for_new_base(&db, &expired_strong, NOW, 1).unwrap(),
        PointerPlace::A,
        "the strong base's envelope expired: its place is empty"
    );
}

#[test]
fn equal_strength_displaces_the_older_record() {
    let db = test_db();
    let x = block_of_strength(&db, 1, 2);
    let y = block_of_strength(&db, 2, 2);
    let m = meta(
        Some(record(PointerPlace::B, x, vec![], 300, 3)),
        Some(record(PointerPlace::A, y, vec![], 100, 3)),
    );
    assert_eq!(
        place_for_new_base(&db, &m, NOW, 1).unwrap(),
        PointerPlace::A
    );
}

#[test]
fn unaccepted_record_is_the_weaker_place() {
    let db = test_db();
    let strong = block_of_strength(&db, 1, 5);
    let weak = block_of_strength(&db, 2, 1);
    // The unconfirmed record has the STRONGER base, yet it goes first (V.17.4).
    let m = meta(
        Some(record(PointerPlace::A, strong, vec![], 300, 0)),
        Some(record(PointerPlace::B, weak, vec![], 100, 3)),
    );
    assert_eq!(
        place_for_new_base(&db, &m, NOW, 1).unwrap(),
        PointerPlace::A
    );
}

#[test]
fn place_choice_uses_base_strength_not_weakest_diff() {
    let db = test_db();
    let base_a = block_of_strength(&db, 1, 5);
    let weak_diff = block_of_strength(&db, 2, 0);
    let base_b = block_of_strength(&db, 3, 2);
    let m = meta(
        Some(record(PointerPlace::A, base_a, vec![weak_diff], 300, 3)),
        Some(record(PointerPlace::B, base_b, vec![], 100, 3)),
    );
    assert_eq!(
        place_for_new_base(&db, &m, NOW, 1).unwrap(),
        PointerPlace::B,
        "B's base (2) is weaker than A's base (5); A's weak diff does not count"
    );
}

#[test]
fn place_choice_ignores_holders_not_seen_for_w() {
    let db = test_db();
    // A: five holders, all gone for 10 days; B: one holder seen now.
    let gone = ss_record(&db, 1);
    for h in 0..5 {
        hold(&db, gone, 50 + h, 4, NOW - 10 * DAY);
    }
    let alive = block_of_strength(&db, 2, 1);
    let m = meta(
        Some(record(PointerPlace::B, alive, vec![], 300, 3)),
        Some(record(PointerPlace::A, gone, vec![], 100, 3)),
    );
    assert_eq!(
        place_for_new_base(&db, &m, NOW, 1).unwrap(),
        PointerPlace::A
    );
}

// ─── keep-set and sweep (V.16.4 п.5-6, V.17.2) ─────────────────────────────────

#[test]
fn keep_set_holds_both_places_their_retire_lists_and_the_candidate() {
    let b = |x: u8| SourceBlockId([x; 32]);
    let mut cur = record(PointerPlace::A, b(1), vec![b(2)], 10, 1);
    cur.to_retire = vec![RetiredPointer {
        base: b(3),
        diffs: vec![b(4)],
    }];
    // dr-i52: the diffs of the earlier envelope readiness stands on are kept too.
    cur.reached = Some(ReachedEnvelope {
        diffs: vec![b(9)],
        generation: 1,
        created_at: Timestamp(9),
        files: 1,
        acks: 3,
        expires_at: NOW,
    });
    let m = meta(
        Some(cur),
        Some(record(PointerPlace::B, b(5), vec![b(6)], 5, 1)),
    );
    let keep = ss_blocks_to_keep(Some(&m), Some((&b(7), &[b(8)])));
    let want: HashSet<SourceBlockId> = (1..=9).map(b).collect();
    assert_eq!(keep, want);
    assert!(ss_blocks_to_keep(None, None).is_empty());
}

#[test]
fn retire_skips_blocks_no_longer_in_ss_ledger() {
    let db = test_db();
    let dir = tempfile::tempdir().unwrap();
    let kept = ss_record(&db, 1);
    let gone = ss_record(&db, 2);
    db.mark_ss_block(&kept, 1).unwrap();
    db.mark_ss_block(&gone, 1).unwrap();
    // A user block that happens to be missing from the keep-set is never touched: the
    // sweep walks the SS ledger only.
    let user = ss_record(&db, 3);
    let m = meta(Some(record(PointerPlace::A, kept, vec![], 1, 1)), None);
    assert_eq!(sweep_ss_ledger(&db, dir.path(), Some(&m), None).unwrap(), 1);
    assert!(db.is_ss_block(&kept).unwrap());
    assert!(!db.is_ss_block(&gone).unwrap());
    assert!(db.get_source_block(&gone).unwrap().is_none());
    assert!(db.get_source_block(&user).unwrap().is_some());
    // A second sweep finds nothing more to retire.
    assert_eq!(sweep_ss_ledger(&db, dir.path(), Some(&m), None).unwrap(), 0);
}
