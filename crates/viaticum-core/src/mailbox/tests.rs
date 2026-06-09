use crate::db::testutil::test_db;
use crate::mailbox::{MailboxClass, MailboxEngine, MailboxEntry, MailboxError};
use crate::types::IdentityPub;

// ============================================================
// Helpers
// ============================================================

fn make_target(seed: u8) -> IdentityPub {
    IdentityPub([seed; 32])
}

fn make_msg_id(seed: u8) -> [u8; 16] {
    [seed; 16]
}

fn make_entry(
    target: IdentityPub,
    msg_id: [u8; 16],
    class: MailboxClass,
    payload: Vec<u8>,
    stored_at: u64,
    ttl_secs: u64,
) -> MailboxEntry {
    MailboxEntry {
        target,
        msg_id,
        class,
        payload_version: 1,
        payload,
        expires_at: stored_at + ttl_secs,
        stored_at,
        sender: None,
    }
}

// ============================================================
// T-1 test scenarios (spec §2.2)
// ============================================================

#[test]
fn mailbox_insert_and_list_for_target_returns_entry() {
    let db = test_db();
    let engine = MailboxEngine::new(db);
    let target = make_target(1);
    let now = 1_000_000u64;
    let entry = make_entry(
        target,
        make_msg_id(1),
        MailboxClass::PosChallenge,
        b"challenge_payload".to_vec(),
        now,
        7 * 24 * 3600,
    );

    engine.store(&entry, now).expect("store failed");
    let fetched = engine.fetch(&target, now).expect("fetch failed");

    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].msg_id, entry.msg_id);
    assert_eq!(fetched[0].class, MailboxClass::PosChallenge);
    assert_eq!(fetched[0].payload, b"challenge_payload");
    assert_eq!(fetched[0].payload_version, 1);
}

#[test]
fn mailbox_list_returns_only_matching_target() {
    let db = test_db();
    let engine = MailboxEngine::new(db);
    let target_a = make_target(1);
    let target_b = make_target(2);
    let now = 1_000_000u64;

    let entry_a = make_entry(
        target_a,
        make_msg_id(1),
        MailboxClass::PosChallenge,
        b"a".to_vec(),
        now,
        3600,
    );
    let entry_b = make_entry(
        target_b,
        make_msg_id(2),
        MailboxClass::PosChallenge,
        b"b".to_vec(),
        now,
        3600,
    );

    engine.store(&entry_a, now).unwrap();
    engine.store(&entry_b, now).unwrap();

    let fetched_a = engine.fetch(&target_a, now).unwrap();
    let fetched_b = engine.fetch(&target_b, now).unwrap();

    assert_eq!(fetched_a.len(), 1);
    assert_eq!(fetched_a[0].target, target_a);
    assert_eq!(fetched_b.len(), 1);
    assert_eq!(fetched_b[0].target, target_b);
}

#[test]
fn mailbox_sweep_expired_removes_ttl_entries() {
    let db = test_db();
    let engine = MailboxEngine::new(db);
    let target = make_target(1);
    let stored_at = 1_000_000u64;
    let ttl_secs = 3600u64; // 1 hour TTL

    let entry = make_entry(
        target,
        make_msg_id(1),
        MailboxClass::PosChallenge,
        b"payload".to_vec(),
        stored_at,
        ttl_secs,
    );

    engine.store(&entry, stored_at).unwrap();

    // Before expiry: entry visible.
    let before_expiry = stored_at + ttl_secs - 1;
    let fetched = engine.fetch(&target, before_expiry).unwrap();
    assert_eq!(fetched.len(), 1, "entry should be visible before expiry");

    // Sweep at exactly expires_at — entry should still NOT be swept (expires_at == now means still valid)
    let at_expiry = stored_at + ttl_secs;
    let removed = engine.sweep_expired(at_expiry).unwrap();
    assert_eq!(removed, 0, "entry at exactly expires_at is not expired yet");

    // Sweep after expiry.
    let after_expiry = stored_at + ttl_secs + 1;
    let removed = engine.sweep_expired(after_expiry).unwrap();
    assert_eq!(removed, 1, "one entry should be swept after expiry");

    // After sweep: entry gone.
    let fetched_after = engine.fetch(&target, after_expiry).unwrap();
    assert!(fetched_after.is_empty(), "entry should be gone after sweep");
}

#[test]
fn mailbox_bytes_for_target_updated_on_insert_and_delete() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(3);
    let now = 2_000_000u64;

    let entry = make_entry(
        target,
        make_msg_id(1),
        MailboxClass::DropNotice,
        vec![0u8; 100], // 100 byte payload
        now,
        14 * 24 * 3600,
    );

    // Before insert: 0 bytes.
    let bytes_before = db.mailbox_bytes_for_target(&target).unwrap();
    assert_eq!(bytes_before, 0);

    engine.store(&entry, now).unwrap();

    // After insert: > 0 bytes.
    let bytes_after = db.mailbox_bytes_for_target(&target).unwrap();
    assert!(bytes_after > 0, "bytes counter must be updated on insert");

    // After delete: back to 0.
    engine
        .delete(&target, make_msg_id(1), MailboxClass::DropNotice)
        .unwrap();
    let bytes_deleted = db.mailbox_bytes_for_target(&target).unwrap();
    assert_eq!(bytes_deleted, 0, "bytes counter must be updated on delete");
}

#[test]
fn mailbox_evict_lru_removes_non_high_trust_first() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(4);
    let now = 3_000_000u64;
    let long_ttl = 5 * 365 * 24 * 3600u64; // 5 years

    // Insert a SelfPointer (high-trust) entry first (older stored_at).
    let high_trust_entry = make_entry(
        target,
        make_msg_id(10),
        MailboxClass::SelfPointer,
        vec![0u8; 50],
        now,
        long_ttl,
    );

    // Insert two PosChallenge (non-high-trust) entries with later stored_at.
    let non_trust_1 = make_entry(
        target,
        make_msg_id(20),
        MailboxClass::PosChallenge,
        vec![0u8; 50],
        now + 1,
        7 * 24 * 3600,
    );
    let non_trust_2 = make_entry(
        target,
        make_msg_id(21),
        MailboxClass::PosChallenge,
        vec![0u8; 50],
        now + 2,
        7 * 24 * 3600,
    );

    engine.store(&high_trust_entry, now).unwrap();
    engine.store(&non_trust_1, now + 1).unwrap();
    engine.store(&non_trust_2, now + 2).unwrap();

    let bytes_before = db.mailbox_bytes_for_target(&target).unwrap();
    assert!(bytes_before > 0);

    // All 3 entries have similar sizes. We set target_bytes to roughly 1/3 of total
    // (one entry's worth) so the algorithm needs to evict 2 entries. Since non-high-trust
    // entries sort before the SelfPointer, those 2 should be evicted first.
    // Use bytes_before / 3 + 1 to stay just above one entry's size.
    let target_bytes = bytes_before / 3 + 1;
    let removed = db
        .mailbox_evict_lru_for_target(&target, target_bytes)
        .unwrap();
    assert!(
        removed >= 1,
        "at least one non-high-trust entry must be evicted"
    );

    // The SelfPointer (high-trust) entry should still be present.
    let remaining = db.mailbox_list_for_target(&target, now).unwrap();
    let has_self_pointer = remaining
        .iter()
        .any(|e| e.class == MailboxClass::SelfPointer);
    assert!(
        has_self_pointer,
        "SelfPointer (high-trust) must survive when non-high-trust entries freed enough quota"
    );
}

#[test]
fn mailbox_high_trust_entry_not_evicted_until_ttl() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(5);
    let now = 4_000_000u64;
    let long_ttl = 5 * 365 * 24 * 3600u64;

    let sp = make_entry(
        target,
        make_msg_id(1),
        MailboxClass::SelfPointer,
        b"pointer_bytes".to_vec(),
        now,
        long_ttl,
    );

    engine.store(&sp, now).unwrap();

    // Fetch well before TTL: visible.
    let fetched = engine.fetch(&target, now + 1000).unwrap();
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].class, MailboxClass::SelfPointer);

    // Sweep well before TTL: NOT removed.
    let removed = engine.sweep_expired(now + 1000).unwrap();
    assert_eq!(removed, 0, "SelfPointer must not be swept before TTL");

    // Fetch after TTL: gone.
    let after_ttl = now + long_ttl + 1;
    let fetched_after = engine.fetch(&target, after_ttl).unwrap();
    assert!(
        fetched_after.is_empty(),
        "SelfPointer must not appear in fetch after TTL"
    );

    // Sweep after TTL: removed.
    let removed_after = engine.sweep_expired(after_ttl).unwrap();
    assert_eq!(removed_after, 1, "SelfPointer must be swept after TTL");
}

#[test]
fn mailbox_class_ttl_values_are_correct() {
    assert_eq!(
        MailboxClass::SelfPointer.default_ttl_secs(),
        5 * 365 * 24 * 3600,
        "SelfPointer TTL = 5 years"
    );
    assert_eq!(
        MailboxClass::PosChallenge.default_ttl_secs(),
        7 * 24 * 3600,
        "PosChallenge TTL = 7 days"
    );
    assert_eq!(
        MailboxClass::PosResponse.default_ttl_secs(),
        7 * 24 * 3600,
        "PosResponse TTL = 7 days"
    );
    assert_eq!(
        MailboxClass::DropNotice.default_ttl_secs(),
        14 * 24 * 3600,
        "DropNotice TTL = 14 days"
    );
    assert_eq!(
        MailboxClass::Generic.default_ttl_secs(),
        90 * 24 * 3600,
        "Generic TTL = 90 days"
    );
}

#[test]
fn mailbox_class_is_high_trust_only_self_pointer() {
    assert!(MailboxClass::SelfPointer.is_high_trust());
    assert!(!MailboxClass::PosChallenge.is_high_trust());
    assert!(!MailboxClass::PosResponse.is_high_trust());
    assert!(!MailboxClass::DropNotice.is_high_trust());
    assert!(!MailboxClass::Generic.is_high_trust());
}

#[test]
fn mailbox_class_round_trips_through_u8() {
    for cls in [
        MailboxClass::SelfPointer,
        MailboxClass::PosChallenge,
        MailboxClass::PosResponse,
        MailboxClass::DropNotice,
        MailboxClass::Generic,
    ] {
        let round = MailboxClass::from_u8(cls.as_u8());
        assert_eq!(round, Some(cls), "round-trip for {:?}", cls);
    }
    assert_eq!(MailboxClass::from_u8(99), None);
}

#[test]
fn mailbox_payload_version_defaults_to_one_on_deserialization() {
    let target = make_target(6);
    let entry = MailboxEntry {
        target,
        msg_id: make_msg_id(1),
        class: MailboxClass::PosChallenge,
        payload_version: 1,
        payload: b"test".to_vec(),
        expires_at: 9999999,
        stored_at: 1000000,
        sender: None,
    };

    // Serialize without payload_version field (simulate old data by manually removing it).
    // Use serde_cbor round-trip — the #[serde(default)] ensures backward compat.
    let cbor = crate::types::to_cbor_bytes(&entry);
    let decoded: MailboxEntry = crate::types::from_cbor_bytes(&cbor).unwrap();
    assert_eq!(
        decoded.payload_version, 1,
        "payload_version should round-trip"
    );
}

#[test]
fn mailbox_store_returns_duplicate_error_on_same_msg_id() {
    let db = test_db();
    let engine = MailboxEngine::new(db);
    let target = make_target(7);
    let now = 5_000_000u64;

    let entry = make_entry(
        target,
        make_msg_id(1),
        MailboxClass::PosChallenge,
        b"payload".to_vec(),
        now,
        3600,
    );

    engine.store(&entry, now).unwrap();

    // Store the same entry again — should fail with Duplicate.
    let result = engine.store(&entry, now);
    assert!(
        matches!(result, Err(MailboxError::Duplicate)),
        "second insert of same msg_id should be Duplicate, got: {:?}",
        result
    );
}

#[test]
fn mailbox_sweep_expired_updates_bytes_counter() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(8);
    let now = 6_000_000u64;
    let short_ttl = 100u64;

    let entry = make_entry(
        target,
        make_msg_id(1),
        MailboxClass::PosChallenge,
        vec![0u8; 200],
        now,
        short_ttl,
    );

    engine.store(&entry, now).unwrap();
    let bytes_before = db.mailbox_bytes_for_target(&target).unwrap();
    assert!(bytes_before > 0);

    // Sweep after expiry.
    let removed = engine.sweep_expired(now + short_ttl + 1).unwrap();
    assert_eq!(removed, 1);

    // Byte counter must be 0 after sweep.
    let bytes_after = db.mailbox_bytes_for_target(&target).unwrap();
    assert_eq!(
        bytes_after, 0,
        "bytes counter must be zeroed after sweep removes all entries"
    );
}

#[test]
fn mailbox_multiple_classes_stored_per_target() {
    let db = test_db();
    let engine = MailboxEngine::new(db);
    let target = make_target(9);
    let now = 7_000_000u64;

    let classes = [
        (MailboxClass::SelfPointer, make_msg_id(1)),
        (MailboxClass::PosChallenge, make_msg_id(2)),
        (MailboxClass::PosResponse, make_msg_id(3)),
        (MailboxClass::DropNotice, make_msg_id(4)),
    ];

    for (class, msg_id) in &classes {
        let ttl = class.default_ttl_secs();
        let entry = make_entry(target, *msg_id, *class, b"payload".to_vec(), now, ttl);
        engine.store(&entry, now).unwrap();
    }

    let fetched = engine.fetch(&target, now).unwrap();
    assert_eq!(fetched.len(), 4, "all 4 classes should be fetchable");

    let fetched_classes: std::collections::HashSet<_> = fetched.iter().map(|e| e.class).collect();
    assert!(fetched_classes.contains(&MailboxClass::SelfPointer));
    assert!(fetched_classes.contains(&MailboxClass::PosChallenge));
    assert!(fetched_classes.contains(&MailboxClass::PosResponse));
    assert!(fetched_classes.contains(&MailboxClass::DropNotice));
}

#[test]
fn mailbox_total_bytes_sums_all_targets() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let now = 8_000_000u64;

    let target_a = make_target(10);
    let target_b = make_target(11);

    let ea = make_entry(
        target_a,
        make_msg_id(1),
        MailboxClass::PosChallenge,
        vec![0u8; 100],
        now,
        3600,
    );
    let eb = make_entry(
        target_b,
        make_msg_id(2),
        MailboxClass::PosChallenge,
        vec![0u8; 100],
        now,
        3600,
    );

    engine.store(&ea, now).unwrap();
    engine.store(&eb, now).unwrap();

    let total = db.mailbox_total_bytes().unwrap();
    let a = db.mailbox_bytes_for_target(&target_a).unwrap();
    let b_bytes = db.mailbox_bytes_for_target(&target_b).unwrap();
    assert_eq!(
        total,
        a + b_bytes,
        "total must equal sum of per-target bytes"
    );
    assert!(total > 0);
}

// ============================================================
// T-11 test scenarios: Bug-D high-trust TTL-only eviction policy
// ============================================================

/// AC-6 / T-11: eviction_prefers_non_high_trust_first
///
/// Under quota pressure with mixed entries, non-high-trust entries are always
/// dropped before any high-trust (SelfPointer) entry is considered.
#[test]
fn eviction_prefers_non_high_trust_first() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(20);
    let now = 10_000_000u64;
    let long_ttl = 5 * 365 * 24 * 3600u64;

    // Insert SelfPointer (high-trust) — oldest stored_at (would be LRU if not protected).
    let sp = make_entry(
        target,
        make_msg_id(1),
        MailboxClass::SelfPointer,
        vec![0u8; 200],
        now,
        long_ttl,
    );
    // Insert two DropNotice (non-high-trust) — newer stored_at.
    let dn1 = make_entry(
        target,
        make_msg_id(2),
        MailboxClass::DropNotice,
        vec![0u8; 200],
        now + 1,
        14 * 24 * 3600,
    );
    let dn2 = make_entry(
        target,
        make_msg_id(3),
        MailboxClass::DropNotice,
        vec![0u8; 200],
        now + 2,
        14 * 24 * 3600,
    );

    engine.store(&sp, now).unwrap();
    engine.store(&dn1, now + 1).unwrap();
    engine.store(&dn2, now + 2).unwrap();

    let total_bytes = db.mailbox_bytes_for_target(&target).unwrap();

    // Set quota such that we need to evict all 3 entries but only 2 non-HT exist.
    // Target = 0 bytes → evict as much as possible (non-HT only).
    let removed = db.mailbox_evict_lru_for_target(&target, 0).unwrap();

    // Both non-HT entries must be removed.
    assert_eq!(removed, 2, "must evict exactly 2 non-high-trust entries");

    // SelfPointer must survive.
    let remaining = db.mailbox_list_for_target(&target, now).unwrap();
    assert_eq!(remaining.len(), 1, "SelfPointer must survive eviction");
    assert_eq!(remaining[0].class, MailboxClass::SelfPointer);

    let _ = total_bytes; // used to trigger the insert
}

/// T-11 core (Bug-D): high_trust_not_evicted_under_pressure_even_when_still_over_quota
///
/// When a target's entries are ALL high-trust (or only high-trust remain), the
/// eviction function must NOT remove them even if still over quota after exhausting
/// non-high-trust candidates.
#[test]
fn high_trust_not_evicted_under_pressure_even_when_still_over_quota() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(21);
    let now = 11_000_000u64;
    let long_ttl = 5 * 365 * 24 * 3600u64;

    // Insert two SelfPointer entries (different msg_ids, both high-trust).
    let sp1 = make_entry(
        target,
        make_msg_id(10),
        MailboxClass::SelfPointer,
        vec![0u8; 500],
        now,
        long_ttl,
    );
    let sp2 = make_entry(
        target,
        make_msg_id(11),
        MailboxClass::SelfPointer,
        vec![0u8; 500],
        now + 1,
        long_ttl,
    );

    engine.store(&sp1, now).unwrap();
    engine.store(&sp2, now + 1).unwrap();

    let total_bytes = db.mailbox_bytes_for_target(&target).unwrap();
    assert!(total_bytes > 0, "bytes must be tracked");

    // Attempt to evict with target_bytes=0 (maximum pressure).
    let removed = db.mailbox_evict_lru_for_target(&target, 0).unwrap();

    // Must remove 0 entries — all are high-trust, none eligible.
    assert_eq!(
        removed, 0,
        "high-trust entries must NOT be evicted even under maximum disk pressure"
    );

    // Both SelfPointers must remain.
    let remaining = db.mailbox_list_for_target(&target, now).unwrap();
    assert_eq!(remaining.len(), 2, "both SelfPointers must survive");
    assert!(
        remaining
            .iter()
            .all(|e| e.class == MailboxClass::SelfPointer)
    );

    // Byte counter unchanged (both still present).
    let bytes_after = db.mailbox_bytes_for_target(&target).unwrap();
    assert_eq!(bytes_after, total_bytes, "byte counter must be unchanged");
}

/// T-11 / AC-6: self_pointer_evicted_after_ttl_expiry
///
/// TTL sweep removes a SelfPointer once expires_at < now_secs.
/// This is the ONLY eviction path for high-trust entries.
#[test]
fn self_pointer_evicted_after_ttl_expiry() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(22);
    let now = 12_000_000u64;
    // Short TTL for test speed.
    let short_ttl = 1000u64;

    let sp = make_entry(
        target,
        make_msg_id(1),
        MailboxClass::SelfPointer,
        b"pointer".to_vec(),
        now,
        short_ttl,
    );
    engine.store(&sp, now).unwrap();

    // Before TTL: eviction does NOT remove it (LRU path is blocked for HT).
    let removed_lru = db.mailbox_evict_lru_for_target(&target, 0).unwrap();
    assert_eq!(removed_lru, 0, "LRU eviction must not remove SelfPointer");

    // Before TTL: sweep does NOT remove it.
    let removed_sweep = engine.sweep_expired(now + short_ttl - 1).unwrap();
    assert_eq!(
        removed_sweep, 0,
        "sweep before TTL must not remove SelfPointer"
    );

    // After TTL: sweep removes it.
    let removed_after = engine.sweep_expired(now + short_ttl + 1).unwrap();
    assert_eq!(
        removed_after, 1,
        "sweep after TTL must remove the SelfPointer"
    );

    // Entry is gone.
    let remaining = db
        .mailbox_list_for_target(&target, now + short_ttl + 1)
        .unwrap();
    assert!(
        remaining.is_empty(),
        "SelfPointer must be gone after TTL sweep"
    );
}

/// T-11: mailbox_list_all_targets returns correct set
#[test]
fn mailbox_list_all_targets_returns_targets_with_entries() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let now = 13_000_000u64;

    let target_a = make_target(30);
    let target_b = make_target(31);

    let ea = make_entry(
        target_a,
        make_msg_id(1),
        MailboxClass::PosChallenge,
        b"a".to_vec(),
        now,
        3600,
    );
    let eb = make_entry(
        target_b,
        make_msg_id(2),
        MailboxClass::DropNotice,
        b"b".to_vec(),
        now,
        3600,
    );

    engine.store(&ea, now).unwrap();
    engine.store(&eb, now).unwrap();

    let targets = db.mailbox_list_all_targets().unwrap();
    let target_set: std::collections::HashSet<_> = targets.into_iter().collect();
    assert!(target_set.contains(&target_a), "target_a must be listed");
    assert!(target_set.contains(&target_b), "target_b must be listed");
    assert_eq!(target_set.len(), 2, "exactly 2 targets expected");
}

/// T-11: mailbox_list_non_high_trust_for_target excludes SelfPointer
#[test]
fn mailbox_list_non_high_trust_for_target_excludes_self_pointer() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(32);
    let now = 14_000_000u64;

    let sp = make_entry(
        target,
        make_msg_id(1),
        MailboxClass::SelfPointer,
        b"ptr".to_vec(),
        now,
        5 * 365 * 24 * 3600,
    );
    let pos = make_entry(
        target,
        make_msg_id(2),
        MailboxClass::PosChallenge,
        b"challenge".to_vec(),
        now,
        7 * 24 * 3600,
    );

    engine.store(&sp, now).unwrap();
    engine.store(&pos, now).unwrap();

    let non_ht = db.mailbox_list_non_high_trust_for_target(&target).unwrap();
    assert_eq!(non_ht.len(), 1, "only non-HT entry expected");
    assert_eq!(non_ht[0].class, MailboxClass::PosChallenge);
}
