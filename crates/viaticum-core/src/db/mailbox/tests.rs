// db/mailbox: byte counters, the SelfPointer slot rule (CROWN-1 C3a, AC-29,
// mailbox-i50) and the directed-mail addressing lookups (AC-21, F14). Real redb.

use crate::db::testutil::test_db;
use crate::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use crate::types::{DeviceId, IdentityPub, PeerRecord, Timestamp};

fn addr(b: u8) -> MailboxAddress {
    MailboxAddress([b; 32])
}

fn entry(
    target: MailboxAddress,
    id: u8,
    class: MailboxClass,
    len: usize,
    stored_at: u64,
) -> MailboxEntry {
    MailboxEntry {
        target,
        msg_id: [id; 16],
        class,
        payload_version: 1,
        payload: vec![0xAB; len],
        expires_at: stored_at + 1_000_000,
        stored_at,
        sender: None,
    }
}

fn peer(device: u8, master: IdentityPub, x25519: Option<[u8; 32]>, last_seen: u64) -> PeerRecord {
    PeerRecord {
        device_id: DeviceId([device; 32]),
        master_identity: master,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1000),
        last_seen: Timestamp(last_seen),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: x25519,
        avail_ewma: crate::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    }
}

// ─── Counters ────────────────────────────────────────────────────────────────

#[test]
fn self_pointer_counter_tracks_only_self_pointers() {
    let db = test_db();
    let t = addr(1);
    let sp = entry(t, 1, MailboxClass::SelfPointer, 500, 10);
    let dn = entry(t, 2, MailboxClass::DropNotice, 700, 10);
    db.mailbox_insert(&sp, 10).unwrap();
    db.mailbox_insert(&dn, 10).unwrap();

    let sp_size = sp.serialized_size() as u64;
    let dn_size = dn.serialized_size() as u64;
    assert_eq!(
        db.mailbox_self_pointer_bytes_for_target(&t).unwrap(),
        sp_size
    );
    assert_eq!(db.mailbox_bytes_for_target(&t).unwrap(), sp_size + dn_size);

    db.mailbox_delete(&t, sp.msg_id, sp.class).unwrap();
    assert_eq!(db.mailbox_self_pointer_bytes_for_target(&t).unwrap(), 0);
    assert_eq!(db.mailbox_bytes_for_target(&t).unwrap(), dn_size);
}

#[test]
fn sweep_expired_updates_self_pointer_counter() {
    let db = test_db();
    let t = addr(2);
    let mut sp = entry(t, 1, MailboxClass::SelfPointer, 100, 10);
    sp.expires_at = 20;
    db.mailbox_insert(&sp, 10).unwrap();
    assert!(db.mailbox_self_pointer_bytes_for_target(&t).unwrap() > 0);

    assert_eq!(db.mailbox_sweep_expired(21).unwrap(), 1);
    assert_eq!(db.mailbox_self_pointer_bytes_for_target(&t).unwrap(), 0);
    assert_eq!(db.mailbox_bytes_for_target(&t).unwrap(), 0);
    assert!(db.mailbox_list_all_targets().unwrap().is_empty());
}

#[test]
fn mailbox_contains_sees_expired_entries_too() {
    let db = test_db();
    let t = addr(3);
    let mut e = entry(t, 1, MailboxClass::PosChallenge, 10, 10);
    e.expires_at = 11;
    db.mailbox_insert(&e, 10).unwrap();
    assert!(db.mailbox_contains(&t, e.msg_id, e.class).unwrap());
    assert!(
        !db.mailbox_contains(&t, e.msg_id, MailboxClass::PosResponse)
            .unwrap()
    );
    assert!(!db.mailbox_contains(&addr(4), e.msg_id, e.class).unwrap());
}

#[test]
fn x25519_for_master_resolves_from_peers() {
    let db = test_db();
    let m = IdentityPub([0x11; 32]);
    db.upsert_peer(&peer(1, m, Some([0x77; 32]), 100)).unwrap();
    db.upsert_peer(&peer(2, IdentityPub([0x22; 32]), Some([0x88; 32]), 500))
        .unwrap();
    assert_eq!(db.x25519_for_master(&m).unwrap(), Some([0x77; 32]));
    assert_eq!(
        db.x25519_for_master(&IdentityPub([0x33; 32])).unwrap(),
        None
    );
}

#[test]
fn x25519_for_master_zero_master_is_none() {
    let db = test_db();
    let zero = IdentityPub([0u8; 32]);
    db.upsert_peer(&peer(1, zero, Some([0x77; 32]), 100))
        .unwrap();
    assert_eq!(db.x25519_for_master(&zero).unwrap(), None);
}

#[test]
fn x25519_for_master_prefers_some_over_newer_none() {
    let db = test_db();
    let m = IdentityPub([0x11; 32]);
    // Old record with the key; newer DR-minimal record of another device without it.
    db.upsert_peer(&peer(1, m, Some([0x77; 32]), 100)).unwrap();
    db.upsert_peer(&peer(2, m, None, 9_999)).unwrap();
    assert_eq!(db.x25519_for_master(&m).unwrap(), Some([0x77; 32]));
}

#[test]
fn x25519_for_master_latest_some_wins_when_keys_disagree() {
    let db = test_db();
    let m = IdentityPub([0x11; 32]);
    db.upsert_peer(&peer(1, m, Some([0x01; 32]), 100)).unwrap();
    db.upsert_peer(&peer(2, m, Some([0x02; 32]), 300)).unwrap();
    db.upsert_peer(&peer(3, m, None, 900)).unwrap();
    assert_eq!(db.x25519_for_master(&m).unwrap(), Some([0x02; 32]));
}

#[test]
fn master_for_peer_device_resolves_from_peers() {
    let db = test_db();
    let m = IdentityPub([0x11; 32]);
    db.upsert_peer(&peer(1, m, None, 100)).unwrap();
    db.upsert_peer(&peer(2, IdentityPub([0u8; 32]), None, 100))
        .unwrap();
    assert_eq!(
        db.master_for_peer_device(&DeviceId([1; 32])).unwrap(),
        Some(m)
    );
    // Zero placeholder and unknown device: no master (never the device-id box).
    assert_eq!(db.master_for_peer_device(&DeviceId([2; 32])).unwrap(), None);
    assert_eq!(db.master_for_peer_device(&DeviceId([3; 32])).unwrap(), None);
}

#[test]
fn master_for_holder_falls_back_to_peers_after_dr() {
    // After DR device_to_master is empty; the PeerRecord (from the SS) carries the master.
    let db = test_db();
    let m = IdentityPub([0x11; 32]);
    db.upsert_peer(&peer(1, m, None, 100)).unwrap();
    assert_eq!(db.get_master_for_device(&DeviceId([1; 32])).unwrap(), None);
    assert_eq!(db.master_for_holder(&DeviceId([1; 32])).unwrap(), Some(m));
    // Unknown anywhere: None, never the device id.
    assert_eq!(db.master_for_holder(&DeviceId([9; 32])).unwrap(), None);
}

#[test]
fn master_for_holder_prefers_peers_over_device_to_master() {
    let db = test_db();
    let from_peer = IdentityPub([0x11; 32]);
    let from_map = IdentityPub([0x22; 32]);
    db.upsert_peer(&peer(1, from_peer, None, 100)).unwrap();
    db.set_master_for_device(&DeviceId([1; 32]), &from_map)
        .unwrap();
    assert_eq!(
        db.master_for_holder(&DeviceId([1; 32])).unwrap(),
        Some(from_peer)
    );
    // No PeerRecord: device_to_master is the fallback.
    db.set_master_for_device(&DeviceId([2; 32]), &from_map)
        .unwrap();
    assert_eq!(
        db.master_for_holder(&DeviceId([2; 32])).unwrap(),
        Some(from_map)
    );
}

#[test]
fn master_for_holder_ignores_zero_placeholder_master() {
    let db = test_db();
    let zero = IdentityPub([0u8; 32]);
    db.upsert_peer(&peer(1, zero, None, 100)).unwrap();
    db.set_master_for_device(&DeviceId([2; 32]), &zero).unwrap();
    assert_eq!(db.master_for_holder(&DeviceId([1; 32])).unwrap(), None);
    assert_eq!(db.master_for_holder(&DeviceId([2; 32])).unwrap(), None);
    // Zero in PEERS must not hide a real master in device_to_master.
    let m = IdentityPub([0x33; 32]);
    db.set_master_for_device(&DeviceId([1; 32]), &m).unwrap();
    assert_eq!(db.master_for_holder(&DeviceId([1; 32])).unwrap(), Some(m));
}

#[test]
fn holder_devices_of_master_finds_peers_devices_when_device_to_master_is_empty() {
    // dr-i8-b: after DR only PEERS (from the SS) knows the holder's devices.
    let db = test_db();
    let m = IdentityPub([0x11; 32]);
    db.upsert_peer(&peer(2, m, None, 100)).unwrap();
    db.upsert_peer(&peer(1, m, None, 100)).unwrap();
    db.upsert_peer(&peer(3, IdentityPub([0x22; 32]), None, 100))
        .unwrap();
    assert!(db.get_devices_for_master(&m).unwrap().is_empty());
    assert_eq!(
        db.holder_devices_of_master(&m).unwrap(),
        vec![DeviceId([1; 32]), DeviceId([2; 32])]
    );
}

#[test]
fn holder_devices_of_master_unites_both_tables_once_each() {
    let db = test_db();
    let m = IdentityPub([0x11; 32]);
    db.upsert_peer(&peer(1, m, None, 100)).unwrap();
    db.set_master_for_device(&DeviceId([1; 32]), &m).unwrap();
    db.set_master_for_device(&DeviceId([4; 32]), &m).unwrap();
    db.set_master_for_device(&DeviceId([5; 32]), &IdentityPub([0x22; 32]))
        .unwrap();
    assert_eq!(
        db.holder_devices_of_master(&m).unwrap(),
        vec![DeviceId([1; 32]), DeviceId([4; 32])]
    );
}

#[test]
fn holder_devices_of_master_is_empty_for_zero_placeholder() {
    let db = test_db();
    let zero = IdentityPub([0u8; 32]);
    db.upsert_peer(&peer(1, zero, None, 100)).unwrap();
    db.set_master_for_device(&DeviceId([2; 32]), &zero).unwrap();
    assert!(db.holder_devices_of_master(&zero).unwrap().is_empty());
}

// ─── Pointer slots (CROWN-1 C3a, AC-29, mailbox-i40/i50) ─────────────────────

use crate::db::{SelfPointerStore, read_only_mailbox_raw_entries};

/// A SelfPointer in slot `slot` of `target`, with a payload that differs per
/// `(slot, stored_at)` unless the caller overrides it.
fn slot_pointer(target: MailboxAddress, slot: u8, stored_at: u64, len: usize) -> MailboxEntry {
    let mut e = entry(target, slot, MailboxClass::SelfPointer, len, stored_at);
    e.payload[..8].copy_from_slice(&stored_at.to_be_bytes());
    e
}

fn held(db: &crate::db::Db, t: &MailboxAddress) -> Vec<MailboxEntry> {
    db.mailbox_list_for_target(t, 0).unwrap()
}

#[test]
fn put_self_pointer_into_empty_slot_is_stored() {
    let db = test_db();
    let t = addr(19);
    let p = slot_pointer(t, 1, 100, 64);
    assert_eq!(
        db.mailbox_put_self_pointer(&p, 128).unwrap(),
        SelfPointerStore::Stored
    );
    assert_eq!(held(&db, &t), vec![p]);
}

#[test]
fn put_self_pointer_newer_in_same_slot_replaces_and_keeps_one_entry() {
    let db = test_db();
    let t = addr(20);
    db.mailbox_put_self_pointer(&slot_pointer(t, 1, 100, 64), 128)
        .unwrap();
    let newer = slot_pointer(t, 1, 200, 64);
    assert_eq!(
        db.mailbox_put_self_pointer(&newer, 128).unwrap(),
        SelfPointerStore::Replaced {
            previous_stored_at: 100
        }
    );
    assert_eq!(
        held(&db, &t),
        vec![newer],
        "one entry per slot, the newer one"
    );
    assert_eq!(db.mailbox_self_pointer_slot_count(&t).unwrap(), 1);
}

/// Mutation guard (V.7, mailbox-i40): "replace without comparing stored_at" makes
/// this red — a replayed older envelope of the same slot must change nothing.
#[test]
fn put_self_pointer_older_in_same_slot_is_superseded_and_changes_nothing() {
    let db = test_db();
    let t = addr(21);
    let newer = slot_pointer(t, 1, 300, 64);
    db.mailbox_put_self_pointer(&newer, 128).unwrap();
    let bytes_before = db.mailbox_bytes_for_target(&t).unwrap();
    for older_at in [299, 1] {
        let older = slot_pointer(t, 1, older_at, 64);
        assert_eq!(
            db.mailbox_put_self_pointer(&older, 128).unwrap(),
            SelfPointerStore::Superseded {
                held_stored_at: 300
            }
        );
    }
    assert_eq!(held(&db, &t), vec![newer]);
    assert_eq!(db.mailbox_bytes_for_target(&t).unwrap(), bytes_before);
}

#[test]
fn put_self_pointer_same_time_same_payload_is_duplicate() {
    let db = test_db();
    let t = addr(22);
    let p = slot_pointer(t, 1, 100, 64);
    db.mailbox_put_self_pointer(&p, 128).unwrap();
    // The postman clamps expires_at: a re-offer of the same envelope may differ there
    // and still be the same pointer.
    let mut again = p.clone();
    again.expires_at -= 7;
    assert_eq!(
        db.mailbox_put_self_pointer(&again, 128).unwrap(),
        SelfPointerStore::Duplicate
    );
    assert_eq!(held(&db, &t), vec![p]);
}

#[test]
fn put_self_pointer_same_time_other_payload_is_superseded() {
    let db = test_db();
    let t = addr(23);
    let p = slot_pointer(t, 1, 100, 64);
    db.mailbox_put_self_pointer(&p, 128).unwrap();
    let mut other = p.clone();
    other.payload[20] ^= 0xFF;
    assert_eq!(
        db.mailbox_put_self_pointer(&other, 128).unwrap(),
        SelfPointerStore::Superseded {
            held_stored_at: 100
        }
    );
    assert_eq!(held(&db, &t), vec![p]);
}

#[test]
fn put_self_pointer_replacement_adjusts_both_counters_by_delta() {
    let db = test_db();
    let t = addr(24);
    let junk = entry(t, 9, MailboxClass::DropNotice, 300, 10);
    db.mailbox_insert(&junk, 10).unwrap();
    let small = slot_pointer(t, 1, 100, 100);
    db.mailbox_put_self_pointer(&small, 128).unwrap();
    let big = slot_pointer(t, 1, 200, 5_000);
    db.mailbox_put_self_pointer(&big, 128).unwrap();
    let big_size = big.serialized_size() as u64;
    assert_eq!(
        db.mailbox_self_pointer_bytes_for_target(&t).unwrap(),
        big_size
    );
    assert_eq!(
        db.mailbox_bytes_for_target(&t).unwrap(),
        big_size + junk.serialized_size() as u64
    );
    // And back down: a smaller newer pointer shrinks both counters.
    let smaller = slot_pointer(t, 1, 300, 50);
    db.mailbox_put_self_pointer(&smaller, 128).unwrap();
    let smaller_size = smaller.serialized_size() as u64;
    assert_eq!(
        db.mailbox_self_pointer_bytes_for_target(&t).unwrap(),
        smaller_size
    );
    assert_eq!(
        db.mailbox_bytes_for_target(&t).unwrap(),
        smaller_size + junk.serialized_size() as u64
    );
}

/// Cap 128 (V.16.1 п.6): a new slot beyond the cap is refused, no older slot is
/// evicted to make room — even one with the oldest stored_at — and the slots already
/// held keep being replaceable.
#[test]
fn put_self_pointer_new_slot_beyond_cap_is_refused_and_evicts_nothing() {
    let cap = crate::mailbox::class_config::MAX_POINTER_SLOTS_PER_ADDRESS;
    assert_eq!(cap, 128);
    let db = test_db();
    let t = addr(25);
    for slot in 0..cap {
        let mut p = slot_pointer(t, 0, 1_000 + slot as u64, 32);
        p.msg_id[..8].copy_from_slice(&(slot as u64).to_be_bytes());
        assert_eq!(
            db.mailbox_put_self_pointer(&p, cap).unwrap(),
            SelfPointerStore::Stored
        );
    }
    let before = held(&db, &t);
    let bytes_before = db.mailbox_self_pointer_bytes_for_target(&t).unwrap();
    let mut extra = slot_pointer(t, 0xEE, 1_000_000, 32);
    extra.msg_id = [0xEE; 16];
    assert_eq!(
        db.mailbox_put_self_pointer(&extra, cap).unwrap(),
        SelfPointerStore::SlotsFull
    );
    assert_eq!(held(&db, &t), before, "nothing evicted, nothing inserted");
    assert_eq!(
        db.mailbox_self_pointer_bytes_for_target(&t).unwrap(),
        bytes_before
    );
    // A held slot (the oldest) still takes its own newer pointer at the cap.
    let mut refresh = slot_pointer(t, 0, 2_000_000, 32);
    refresh.msg_id = before.iter().min_by_key(|e| e.stored_at).unwrap().msg_id;
    assert!(matches!(
        db.mailbox_put_self_pointer(&refresh, cap).unwrap(),
        SelfPointerStore::Replaced { .. }
    ));
    assert_eq!(db.mailbox_self_pointer_slot_count(&t).unwrap(), cap);
}

/// Directed junk planted in the pointer box neither occupies pointer slots nor
/// blocks a pointer; slots of other addresses do not count.
#[test]
fn slot_count_ignores_directed_entries_in_same_address() {
    let db = test_db();
    let t = addr(26);
    for i in 0..5u8 {
        db.mailbox_insert(&entry(t, 100 + i, MailboxClass::DropNotice, 10, 10), 10)
            .unwrap();
    }
    db.mailbox_put_self_pointer(&slot_pointer(addr(27), 1, 10, 10), 2)
        .unwrap();
    assert_eq!(db.mailbox_self_pointer_slot_count(&t).unwrap(), 0);
    db.mailbox_put_self_pointer(&slot_pointer(t, 1, 10, 10), 2)
        .unwrap();
    assert_eq!(
        db.mailbox_put_self_pointer(&slot_pointer(t, 2, 10, 10), 2)
            .unwrap(),
        SelfPointerStore::Stored,
        "5 directed entries + 1 slot: the second slot still fits a cap of 2"
    );
    assert_eq!(db.mailbox_self_pointer_slot_count(&t).unwrap(), 2);
    assert_eq!(
        db.mailbox_put_self_pointer(&slot_pointer(t, 3, 10, 10), 2)
            .unwrap(),
        SelfPointerStore::SlotsFull
    );
}

/// N3 boundary (mailbox-i49 note): an expired but not yet swept pointer still holds
/// its slot until the sweep; after the sweep the slot is free.
#[test]
fn slot_count_includes_expired_unswept_pointers_until_sweep() {
    let db = test_db();
    let t = addr(28);
    let mut p = slot_pointer(t, 1, 10, 10);
    p.expires_at = 20;
    db.mailbox_put_self_pointer(&p, 1).unwrap();
    assert_eq!(
        db.mailbox_put_self_pointer(&slot_pointer(t, 2, 30, 10), 1)
            .unwrap(),
        SelfPointerStore::SlotsFull
    );
    db.mailbox_sweep_expired(21).unwrap();
    assert_eq!(
        db.mailbox_put_self_pointer(&slot_pointer(t, 2, 30, 10), 1)
            .unwrap(),
        SelfPointerStore::Stored
    );
}

/// mailbox-probe audit path: a stopped node's redb is read without writing to it
/// (no pre-open `.bak` copy, file bytes unchanged).
#[test]
fn read_only_mailbox_raw_entries_reads_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.redb");
    let e1 = entry(addr(30), 1, MailboxClass::SelfPointer, 10, 100);
    let e2 = entry(addr(30), 2, MailboxClass::DropNotice, 10, 100);
    let e3 = entry(addr(31), 3, MailboxClass::PosChallenge, 10, 100);
    {
        let db = crate::db::Db::open(&path).unwrap();
        for e in [&e1, &e2, &e3] {
            db.mailbox_insert(e, 0).unwrap();
        }
    }
    let _ = std::fs::remove_file(path.with_extension("redb.bak"));
    let before = std::fs::read(&path).unwrap();

    let dump = read_only_mailbox_raw_entries(&path).unwrap();
    assert!(
        !dump.from_repaired_copy,
        "a cleanly closed file is read in place"
    );
    let got = dump.boxes;

    assert_eq!(got.len(), 2);
    assert_eq!(got[0].0, addr(30));
    assert_eq!(got[0].1.len(), 2);
    assert_eq!(got[1].0, addr(31));
    let back: MailboxEntry = crate::types::from_cbor_bytes(&got[1].1[0]).unwrap();
    assert_eq!(back, e3);
    assert_eq!(std::fs::read(&path).unwrap(), before, "db.redb unchanged");
    assert!(
        !path.with_extension("redb.bak").exists(),
        "no backup copy written"
    );
}

/// A postman frozen with SIGKILL leaves `db.redb` needing crash recovery, which a
/// read-only handle refuses. The audit then repairs and reads a private copy; the
/// original stays byte-identical. (Simulated by copying the file while the database
/// is still open: the copy carries the "not cleanly closed" state.)
#[test]
fn read_only_mailbox_raw_entries_reads_a_killed_nodes_file_via_repaired_copy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db.redb");
    let dirty = dir.path().join("killed.redb");
    let e1 = entry(addr(40), 1, MailboxClass::PosChallenge, 10, 100);
    let db = crate::db::Db::open(&path).unwrap();
    db.mailbox_insert(&e1, 0).unwrap();
    std::fs::copy(&path, &dirty).unwrap();
    drop(db);
    let before = std::fs::read(&dirty).unwrap();

    let dump = read_only_mailbox_raw_entries(&dirty).unwrap();

    assert!(
        dump.from_repaired_copy,
        "the dirty file needed the repaired-copy path"
    );
    assert_eq!(dump.boxes.len(), 1);
    let back: MailboxEntry = crate::types::from_cbor_bytes(&dump.boxes[0].1[0]).unwrap();
    assert_eq!(back, e1);
    assert_eq!(std::fs::read(&dirty).unwrap(), before, "original untouched");
}
