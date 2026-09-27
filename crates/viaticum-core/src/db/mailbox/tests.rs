// db/mailbox: pointer-budget counters, monotone pointer eviction (N5) and the
// directed-mail addressing lookups (AC-21, F14). Real redb.

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

// ─── Monotone pointer eviction (N5) ──────────────────────────────────────────

#[test]
fn evict_oldest_self_pointers_removes_oldest_first_down_to_keep_bytes() {
    let db = test_db();
    let t = addr(6);
    let sizes: Vec<u64> = (0..4)
        .map(|i| {
            let e = entry(t, i, MailboxClass::SelfPointer, 1000, 100 + i as u64);
            db.mailbox_insert(&e, 0).unwrap();
            e.serialized_size() as u64
        })
        .collect();
    let total: u64 = sizes.iter().sum();
    // Keep room for two pointers: the two oldest go.
    let removed = db
        .mailbox_evict_oldest_self_pointers(&t, total - sizes[0] - sizes[1], 1_000)
        .unwrap();
    assert_eq!(removed, 2);
    let mut left: Vec<u64> = db
        .mailbox_list_for_target(&t, 0)
        .unwrap()
        .into_iter()
        .map(|e| e.stored_at)
        .collect();
    left.sort();
    assert_eq!(left, vec![102, 103]);
    assert_eq!(
        db.mailbox_self_pointer_bytes_for_target(&t).unwrap(),
        sizes[2] + sizes[3]
    );
}

#[test]
fn evict_oldest_self_pointers_never_touches_entries_at_or_after_older_than() {
    let db = test_db();
    let t = addr(7);
    for i in 0..3u8 {
        db.mailbox_insert(
            &entry(t, i, MailboxClass::SelfPointer, 1000, 200 + i as u64),
            0,
        )
        .unwrap();
    }
    // Incoming stored_at = 200: nothing is strictly older, so nothing may go even
    // though keep_bytes = 0 asks for everything.
    assert_eq!(
        db.mailbox_evict_oldest_self_pointers(&t, 0, 200).unwrap(),
        0
    );
    assert_eq!(db.mailbox_list_for_target(&t, 0).unwrap().len(), 3);
}

#[test]
fn evict_oldest_self_pointers_is_all_or_nothing() {
    let db = test_db();
    let t = addr(8);
    for i in 0..3u8 {
        db.mailbox_insert(
            &entry(t, i, MailboxClass::SelfPointer, 1000, 300 + i as u64),
            0,
        )
        .unwrap();
    }
    // Only the oldest (300) is older than 301, but keep_bytes = 0 would need all
    // three gone: evicting the one would not make room, so none is evicted.
    assert_eq!(
        db.mailbox_evict_oldest_self_pointers(&t, 0, 301).unwrap(),
        0
    );
    assert_eq!(db.mailbox_list_for_target(&t, 0).unwrap().len(), 3);
}

#[test]
fn evict_oldest_self_pointers_never_touches_directed_entries_or_other_targets() {
    let db = test_db();
    let t = addr(9);
    let other = addr(10);
    db.mailbox_insert(&entry(t, 1, MailboxClass::SelfPointer, 1000, 1), 0)
        .unwrap();
    db.mailbox_insert(&entry(t, 2, MailboxClass::DropNotice, 1000, 0), 0)
        .unwrap();
    db.mailbox_insert(&entry(other, 3, MailboxClass::SelfPointer, 1000, 0), 0)
        .unwrap();

    assert_eq!(
        db.mailbox_evict_oldest_self_pointers(&t, 0, 1_000).unwrap(),
        1
    );
    let left: Vec<MailboxClass> = db
        .mailbox_list_for_target(&t, 0)
        .unwrap()
        .into_iter()
        .map(|e| e.class)
        .collect();
    assert_eq!(left, vec![MailboxClass::DropNotice]);
    assert_eq!(db.mailbox_list_for_target(&other, 0).unwrap().len(), 1);
    assert!(db.mailbox_self_pointer_bytes_for_target(&other).unwrap() > 0);
}

// ─── Addressing (AC-21, F14) ─────────────────────────────────────────────────

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

// ─── Atomic pointer store (review WARN-1, mailbox-i31) ───────────────────────

use crate::db::{SelfPointerStore, read_only_mailbox_raw_entries};

#[test]
fn insert_self_pointer_within_budget_evicts_older_in_one_step() {
    let db = test_db();
    let t = addr(20);
    let old = entry(t, 1, MailboxClass::SelfPointer, 1000, 100);
    let budget = old.serialized_size() as u64;
    assert_eq!(
        db.mailbox_insert_self_pointer_within_budget(&old, budget)
            .unwrap(),
        SelfPointerStore::Stored { evicted: 0 }
    );
    let new = entry(t, 2, MailboxClass::SelfPointer, 1000, 200);
    assert_eq!(
        db.mailbox_insert_self_pointer_within_budget(&new, budget)
            .unwrap(),
        SelfPointerStore::Stored { evicted: 1 }
    );
    let left: Vec<u64> = db
        .mailbox_list_for_target(&t, 0)
        .unwrap()
        .iter()
        .map(|e| e.stored_at)
        .collect();
    assert_eq!(left, vec![200]);
    assert_eq!(
        db.mailbox_self_pointer_bytes_for_target(&t).unwrap(),
        budget
    );
    assert_eq!(db.mailbox_bytes_for_target(&t).unwrap(), budget);
}

#[test]
fn insert_self_pointer_within_budget_refuses_older_and_changes_nothing() {
    let db = test_db();
    let t = addr(21);
    let newer = entry(t, 1, MailboxClass::SelfPointer, 1000, 300);
    let budget = newer.serialized_size() as u64;
    db.mailbox_insert_self_pointer_within_budget(&newer, budget)
        .unwrap();
    let replay = entry(t, 2, MailboxClass::SelfPointer, 1000, 299);
    assert_eq!(
        db.mailbox_insert_self_pointer_within_budget(&replay, budget)
            .unwrap(),
        SelfPointerStore::OverBudget
    );
    let left: Vec<u64> = db
        .mailbox_list_for_target(&t, 0)
        .unwrap()
        .iter()
        .map(|e| e.stored_at)
        .collect();
    assert_eq!(left, vec![300]);
}

#[test]
fn insert_self_pointer_within_budget_reports_duplicate_without_eviction() {
    let db = test_db();
    let t = addr(22);
    let a = entry(t, 1, MailboxClass::SelfPointer, 1000, 100);
    let budget = a.serialized_size() as u64;
    db.mailbox_insert_self_pointer_within_budget(&a, budget)
        .unwrap();
    // Same key, later stored_at: must be a duplicate, not "newer, evict the old".
    let mut again = a.clone();
    again.stored_at = 500;
    assert_eq!(
        db.mailbox_insert_self_pointer_within_budget(&again, budget)
            .unwrap(),
        SelfPointerStore::Duplicate
    );
    assert_eq!(db.mailbox_list_for_target(&t, 0).unwrap(), vec![a]);
}

#[test]
fn insert_self_pointer_larger_than_budget_is_refused() {
    let db = test_db();
    let t = addr(23);
    let big = entry(t, 1, MailboxClass::SelfPointer, 1000, 100);
    assert_eq!(
        db.mailbox_insert_self_pointer_within_budget(&big, 10)
            .unwrap(),
        SelfPointerStore::OverBudget
    );
    assert!(db.mailbox_list_for_target(&t, 0).unwrap().is_empty());
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
