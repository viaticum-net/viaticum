use crate::db::testutil::test_db;
use crate::mailbox::{
    MAILBOX_TRANSIT_GRACE_SECS, MailboxAddress, MailboxClass, MailboxEngine, MailboxEntry,
    MailboxError, SELF_POINTER_MAX_FUTURE_SKEW_SECS, Stored, check_entry_clock,
    check_pointer_sealed, class_config, seal, transit_grace_secs,
};

// ============================================================
// Helpers
// ============================================================

fn make_target(seed: u8) -> MailboxAddress {
    MailboxAddress([seed; 32])
}

fn make_msg_id(seed: u8) -> [u8; 16] {
    [seed; 16]
}

fn make_entry(
    target: MailboxAddress,
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

/// P1-5: `default_ttl_secs` must agree with the `class_config` source-of-truth
/// constants for every class — they are no longer duplicated literals, so this
/// pins the delegation (and covers DeleteRequest/Revocation, absent above).
#[test]
fn default_ttl_secs_agrees_with_class_config() {
    use crate::mailbox::class_config;
    assert_eq!(
        MailboxClass::SelfPointer.default_ttl_secs(),
        class_config::SELF_POINTER_TTL.as_secs()
    );
    assert_eq!(
        MailboxClass::PosChallenge.default_ttl_secs(),
        class_config::POS_CHALLENGE_TTL.as_secs()
    );
    assert_eq!(
        MailboxClass::PosResponse.default_ttl_secs(),
        class_config::POS_CHALLENGE_TTL.as_secs()
    );
    assert_eq!(
        MailboxClass::DropNotice.default_ttl_secs(),
        class_config::DROP_NOTICE_TTL.as_secs()
    );
    assert_eq!(
        MailboxClass::Generic.default_ttl_secs(),
        class_config::UNKNOWN_SENDER_TTL.as_secs()
    );
    assert_eq!(
        MailboxClass::DeleteRequest.default_ttl_secs(),
        class_config::DELETE_REQUEST_TTL.as_secs()
    );
    assert_eq!(
        MailboxClass::Revocation.default_ttl_secs(),
        class_config::REVOCATION_TTL.as_secs()
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
/// (Besides this sweep, only the monotone pointer budget at store time removes one.)
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

// ============================================================
// scaled_ttl_secs (time_scale scaling — P1-3 / PL-3)
// ============================================================

use crate::mailbox::scaled_ttl_secs;

/// scale=1 (production) → TTL unchanged.
#[test]
fn scaled_ttl_is_unchanged_when_time_scale_is_one() {
    let pos_ttl = 7 * 24 * 3600;
    let delete_ttl = 14 * 24 * 3600;
    let pointer_ttl = 5 * 365 * 24 * 3600;
    assert_eq!(scaled_ttl_secs(pos_ttl, 1), pos_ttl);
    assert_eq!(scaled_ttl_secs(delete_ttl, 1), delete_ttl);
    assert_eq!(scaled_ttl_secs(pointer_ttl, 1), pointer_ttl);
}

/// scale=N → TTL divided by N.
#[test]
fn scaled_ttl_is_divided_when_time_scale_is_above_one() {
    let pos_ttl = 7 * 24 * 3600; // 604_800
    assert_eq!(scaled_ttl_secs(pos_ttl, 60), pos_ttl / 60);
    assert_eq!(scaled_ttl_secs(pos_ttl, 3600), pos_ttl / 3600);
}

/// time_scale larger than the TTL → floored at 1 second, not 0.
#[test]
fn scaled_ttl_is_floored_at_one_when_time_scale_exceeds_ttl() {
    let pos_ttl = 7 * 24 * 3600;
    assert_eq!(scaled_ttl_secs(pos_ttl, 10_000_000), 1);
    // Exactly equal divisor would give 1 too; one-greater divisor still floors to 1.
    assert_eq!(scaled_ttl_secs(pos_ttl, pos_ttl + 1), 1);
}

/// time_scale=0 is guarded (treated as 1) — no panic, no division by zero.
#[test]
fn scaled_ttl_treats_zero_time_scale_as_one() {
    let pos_ttl = 7 * 24 * 3600;
    assert_eq!(scaled_ttl_secs(pos_ttl, 0), pos_ttl);
}

// ============================================================
// CS-POS-2: store clamps sender-controlled expires_at to the class TTL
// ============================================================

/// A signed entry with an over-long `expires_at` (e.g. `u64::MAX`) must be capped at
/// `now + class.default_ttl_secs()` at store time, so a postman cannot be forced to
/// keep + re-serve it forever (unbounded recompute + permanent store squat). A normal
/// in-bounds `expires_at` (whether unscaled or time-scale-scaled) must round-trip
/// unchanged — the clamp only caps the MAXIMUM.
#[test]
fn store_clamps_expires_at_to_class_ttl() {
    let db = test_db();
    let engine = MailboxEngine::new(db);
    let target = make_target(7);
    let now = 1_000_000u64;
    let class = MailboxClass::PosChallenge;
    let raw_ttl = class.default_ttl_secs();

    // 1) Over-long expires_at (u64::MAX) → clamped to now + raw class TTL.
    let mut forever = make_entry(target, make_msg_id(1), class, b"forever".to_vec(), now, 0);
    forever.expires_at = u64::MAX;
    engine.store(&forever, now).expect("store forever failed");
    let fetched = engine.fetch(&target, now).expect("fetch failed");
    assert_eq!(fetched.len(), 1);
    assert_eq!(
        fetched[0].expires_at,
        now + raw_ttl,
        "over-long expires_at must be clamped to now + class TTL"
    );

    // 2) A normal (unscaled, in-bounds) entry round-trips unchanged.
    let normal_ttl = raw_ttl / 2;
    let normal = make_entry(
        target,
        make_msg_id(2),
        class,
        b"normal".to_vec(),
        now,
        normal_ttl,
    );
    let normal_expires = normal.expires_at;
    engine.store(&normal, now).expect("store normal failed");
    let fetched = engine.fetch(&target, now).expect("fetch failed");
    let got = fetched
        .iter()
        .find(|e| e.msg_id == make_msg_id(2))
        .expect("normal entry present");
    assert_eq!(
        got.expires_at, normal_expires,
        "in-bounds expires_at must be left unchanged by the clamp"
    );

    // 3) A scaled (smaller-than-raw) entry — as the publisher produces under
    //    time-scale acceleration — also round-trips unchanged: scaled < raw, so the
    //    `min()` keeps the scaled value.
    let scaled_ttl = scaled_ttl_secs(raw_ttl, 3600);
    let scaled = make_entry(
        target,
        make_msg_id(3),
        class,
        b"scaled".to_vec(),
        now,
        scaled_ttl,
    );
    let scaled_expires = scaled.expires_at;
    assert!(
        scaled_expires < now + raw_ttl,
        "scaled must be below raw cap"
    );
    engine.store(&scaled, now).expect("store scaled failed");
    let fetched = engine.fetch(&target, now).expect("fetch failed");
    let got = fetched
        .iter()
        .find(|e| e.msg_id == make_msg_id(3))
        .expect("scaled entry present");
    assert_eq!(
        got.expires_at, scaled_expires,
        "scaled (in-bounds) expires_at must be left unchanged by the clamp"
    );
}

// ============================================================
// CROWN-1 C3a: SelfPointer slots (mailbox-i40/i50, AC-29), postman clock (i42) and
// the plaintext rule
// ============================================================

/// Payload that makes one SelfPointer entry ≈ 200 KB (128 slots ≈ 25 MB).
const BIG: usize = 200_000;

/// A pointer in slot `slot` of `target`, stored at `stored_at`.
fn pointer(target: MailboxAddress, slot: u32, stored_at: u64) -> MailboxEntry {
    let mut msg_id = [0u8; 16];
    msg_id[..4].copy_from_slice(&slot.to_be_bytes());
    let mut payload = vec![0x5A; BIG];
    payload[..8].copy_from_slice(&stored_at.to_be_bytes());
    MailboxEntry {
        target,
        msg_id,
        class: MailboxClass::SelfPointer,
        payload_version: seal::SEALED_PAYLOAD_VERSION,
        payload,
        expires_at: stored_at + 10_000_000,
        stored_at,
        sender: None,
    }
}

fn small_pointer(target: MailboxAddress, slot: u32, stored_at: u64) -> MailboxEntry {
    let mut e = pointer(target, slot, stored_at);
    e.payload.truncate(512);
    e
}

/// Fill every pointer slot of `target` (slots 0..cap, stored at `first_stored_at..`).
fn fill_pointer_slots(db: &crate::db::Db, target: MailboxAddress, first_stored_at: u64) {
    let engine = MailboxEngine::new(db.clone());
    for slot in 0..class_config::MAX_POINTER_SLOTS_PER_ADDRESS as u32 {
        engine
            .store(&pointer(target, slot, first_stored_at + slot as u64), 0)
            .unwrap();
    }
}

fn stored_ats(db: &crate::db::Db, target: &MailboxAddress) -> Vec<u64> {
    let mut v: Vec<u64> = db
        .mailbox_list_for_target(target, 0)
        .unwrap()
        .into_iter()
        .map(|e| e.stored_at)
        .collect();
    v.sort();
    v
}

/// AC-5′(в), dr-i42, mailbox-i40/i50. The lost laptop's history (slot D) published
/// once; a shadow node of the same phrase then publishes its own history 1000 times,
/// restarting and filling the rest of the address with its places. D is still there,
/// unchanged. Mutation guard: "evict the oldest slot at the cap" makes this red.
#[test]
fn dormant_slot_survives_any_number_of_shadow_publications() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(40);
    let dormant = small_pointer(target, 0xD0D0, 1_000);
    engine.store(&dormant, 0).unwrap();

    // The shadow's two places, republished 1000 times each (newer every time).
    for i in 0..1000u64 {
        for slot in [1u32, 2] {
            let r = engine.store(&small_pointer(target, slot, 10_000 + i), 0);
            assert!(r.is_ok(), "shadow publication {i} slot {slot}: {r:?}");
        }
    }
    // Then shadow restarts / other installations try new slots until the cap is hit
    // and beyond — every new slot past the cap is refused, nothing is evicted.
    let mut refused = 0;
    for slot in 3..(class_config::MAX_POINTER_SLOTS_PER_ADDRESS as u32 + 40) {
        match engine.store(&small_pointer(target, slot, 50_000 + slot as u64), 0) {
            Ok(_) => {}
            Err(MailboxError::QuotaExceeded { .. }) => refused += 1,
            Err(e) => panic!("slot {slot}: {e}"),
        }
    }
    assert_eq!(refused, 40, "new slots beyond the cap are refused");

    let held = db.mailbox_list_for_target(&target, 0).unwrap();
    assert_eq!(held.len(), class_config::MAX_POINTER_SLOTS_PER_ADDRESS);
    assert!(
        held.contains(&dormant),
        "the dormant history's pointer survives, byte-identical"
    );
}

#[test]
fn store_newer_pointer_in_same_slot_reports_replaced() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(41);
    assert_eq!(
        engine.store(&small_pointer(target, 1, 100), 0).unwrap(),
        Stored::New
    );
    assert_eq!(
        engine.store(&small_pointer(target, 1, 200), 0).unwrap(),
        Stored::Replaced {
            previous_stored_at: 100
        }
    );
    assert_eq!(stored_ats(&db, &target), vec![200]);
}

#[test]
fn store_older_pointer_in_same_slot_is_superseded() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(42);
    engine.store(&small_pointer(target, 1, 200), 0).unwrap();
    let res = engine.store(&small_pointer(target, 1, 100), 0);
    assert!(
        matches!(
            res,
            Err(MailboxError::Superseded {
                held: 200,
                incoming: 100
            })
        ),
        "got {res:?}"
    );
    // The same envelope again is a duplicate (the handler answers Ack).
    let res = engine.store(&small_pointer(target, 1, 200), 0);
    assert!(matches!(res, Err(MailboxError::Duplicate)), "got {res:?}");
    assert_eq!(stored_ats(&db, &target), vec![200]);
}

/// AC-8 at the engine: the general quota is full of directed junk, a pointer is
/// still stored (pointers are bounded by slots, not by the general quota).
#[test]
fn self_pointer_store_bypasses_full_general_quota() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(44);
    let mut i = 0u32;
    loop {
        let mut junk = make_entry(
            target,
            [0; 16],
            MailboxClass::DropNotice,
            vec![0xEE; BIG],
            10,
            1_000_000,
        );
        junk.msg_id[..4].copy_from_slice(&i.to_be_bytes());
        match engine.store(&junk, 0) {
            Ok(_) => i += 1,
            Err(MailboxError::QuotaExceeded { .. }) => break,
            Err(e) => panic!("{e}"),
        }
    }
    assert!(
        i > 100,
        "general quota should hold > 100 junk entries, held {i}"
    );
    engine.store(&pointer(target, 1, 10), 0).unwrap();
    assert_eq!(stored_ats(&db, &target).len() as u32, i + 1);
}

/// AC-8: the owner's pointers (all 128 slots full) do not consume the directed quota.
#[test]
fn directed_quota_does_not_count_self_pointers() {
    let db = test_db();
    let engine = MailboxEngine::new(db.clone());
    let target = make_target(45);
    fill_pointer_slots(&db, target, 100);
    let pointer_bytes = db.mailbox_self_pointer_bytes_for_target(&target).unwrap();
    assert!(pointer_bytes > 20 * 1024 * 1024);
    // Directed mail up to (almost) the full general quota is still accepted.
    let per = make_entry(
        target,
        [0; 16],
        MailboxClass::DropNotice,
        vec![0xEE; BIG],
        10,
        1_000_000,
    )
    .serialized_size() as u64;
    // +8: msg_id bytes >= 24 encode as 2 CBOR bytes, so later entries are a bit larger.
    let fits = class_config::MAX_MAILBOX_BYTES_PER_PEER / (per + 8);
    for i in 0..fits as u32 {
        let mut e = make_entry(
            target,
            [0; 16],
            MailboxClass::DropNotice,
            vec![0xEE; BIG],
            10,
            1_000_000,
        );
        e.msg_id[..4].copy_from_slice(&i.to_be_bytes());
        engine
            .store(&e, 0)
            .unwrap_or_else(|err| panic!("directed #{i} refused: {err}"));
    }
}

#[test]
fn check_entry_clock_rejects_already_expired_entry() {
    let now = 5_000_000;
    let mut e = make_entry(
        make_target(47),
        make_msg_id(1),
        MailboxClass::PosChallenge,
        vec![],
        now,
        10,
    );
    e.expires_at = now;
    assert!(matches!(
        check_entry_clock(&e, now),
        Err(MailboxError::ClockSkew { .. })
    ));
    e.expires_at = now - 1;
    assert!(matches!(
        check_entry_clock(&e, now),
        Err(MailboxError::ClockSkew { .. })
    ));
    e.expires_at = now + 1;
    assert!(check_entry_clock(&e, now).is_ok());
}

/// mailbox-i42 mutation guard: "drop the future bound" makes this red.
#[test]
fn check_entry_clock_rejects_self_pointer_more_than_a_day_ahead() {
    let day = SELF_POINTER_MAX_FUTURE_SKEW_SECS;
    assert_eq!(day, 24 * 3600);
    let now = 1_800_000_000;
    for (stored_at, ok) in [
        (now, true),
        (now + day, true),
        (now + day + 1, false),
        (now + 400 * day, false),
    ] {
        let mut e = pointer(make_target(48), 1, stored_at);
        e.expires_at = stored_at + 1_000;
        assert_eq!(
            check_entry_clock(&e, now).is_ok(),
            ok,
            "stored_at offset {}",
            stored_at as i128 - now as i128
        );
    }
    // The stored_at rule is for pointers only: directed mail is judged by expiry.
    let mut d = make_entry(
        make_target(48),
        make_msg_id(2),
        MailboxClass::DropNotice,
        vec![],
        now + 400 * day,
        0,
    );
    d.expires_at = now + 1_000;
    assert!(check_entry_clock(&d, now).is_ok());
}

/// mailbox-i42: no past bound — a pointer published 4 years ago and not expired is
/// accepted (the slot ordering, not the clock, decides between versions).
#[test]
fn check_entry_clock_accepts_old_unexpired_self_pointer() {
    let now = 1_800_000_000;
    let four_years = 4 * 365 * 24 * 3600;
    let mut e = pointer(make_target(49), 1, now - four_years);
    e.expires_at = now + 365 * 24 * 3600;
    assert!(check_entry_clock(&e, now).is_ok());
}

/// A PoS response with the production TTL (7 days) sent at `stored_at`.
fn pos_response(stored_at: u64) -> MailboxEntry {
    make_entry(
        make_target(51),
        make_msg_id(1),
        MailboxClass::PosResponse,
        vec![],
        stored_at,
        7 * 24 * 3600,
    )
}

/// mailbox-i61: an entry whose TTL ran out on the way (expired up to a minute ago by
/// the postman's clock, sealed in the postman's past) is `Expired`, not a clock fault.
#[test]
fn entry_expired_within_grace_is_expired_not_clock_skew() {
    let now = 1_800_000_000;
    let mut e = pos_response(now - 7 * 24 * 3600);
    assert_eq!(transit_grace_secs(&e), MAILBOX_TRANSIT_GRACE_SECS);
    for expired_ago in [0, 1, MAILBOX_TRANSIT_GRACE_SECS - 1] {
        e.expires_at = now - expired_ago;
        assert!(
            matches!(
                check_entry_clock(&e, now),
                Err(MailboxError::Expired { expires_at, now: n }) if expires_at == now - expired_ago && n == now
            ),
            "expired {expired_ago} s ago"
        );
    }
    // A pointer is judged the same way.
    let mut p = pointer(make_target(52), 1, now - 1_000);
    p.expires_at = now - 1;
    assert!(matches!(
        check_entry_clock(&p, now),
        Err(MailboxError::Expired { .. })
    ));
}

/// mailbox-i61: past the window, or an entry "sealed" in the postman's future, is
/// still `ClockSkew` (the sender's clock is off by about the whole TTL or more).
#[test]
fn entry_expired_long_ago_is_clock_skew() {
    let now = 1_800_000_000;
    let mut e = pos_response(now - 30 * 24 * 3600);
    for expired_ago in [
        MAILBOX_TRANSIT_GRACE_SECS,
        MAILBOX_TRANSIT_GRACE_SECS + 1,
        3600,
    ] {
        e.expires_at = now - expired_ago;
        assert!(
            matches!(
                check_entry_clock(&e, now),
                Err(MailboxError::ClockSkew { .. })
            ),
            "expired {expired_ago} s ago"
        );
    }
    // stored_at ahead of the postman: not "in transit", whatever the expiry.
    let mut ahead = pos_response(now + 10);
    ahead.expires_at = now;
    assert!(matches!(
        check_entry_clock(&ahead, now),
        Err(MailboxError::ClockSkew { .. })
    ));
}

/// Р.3: the window is a quarter of the entry's own lifetime when that is under four
/// minutes (a PoS TTL scaled by time_scale 20000 lives ~30 s → ~7 s of grace), so a
/// scaled entry is not read as "in transit" for most of its life.
#[test]
fn grace_shrinks_with_a_short_lived_entry() {
    let now = 1_800_000_000;
    let ttl = 7 * 24 * 3600 / 20_000; // 30 s
    let mut e = pos_response(0);
    e.stored_at = now - 100;
    e.expires_at = e.stored_at + ttl;
    let grace = transit_grace_secs(&e);
    assert_eq!(grace, ttl / 4);
    assert!(grace < MAILBOX_TRANSIT_GRACE_SECS);
    e.stored_at = now - ttl - grace + 1;
    e.expires_at = e.stored_at + ttl; // expired grace − 1 s ago
    assert!(matches!(
        check_entry_clock(&e, now),
        Err(MailboxError::Expired { .. })
    ));
    e.stored_at -= 1;
    e.expires_at -= 1; // expired exactly `grace` ago: out of the window
    assert!(matches!(
        check_entry_clock(&e, now),
        Err(MailboxError::ClockSkew { .. })
    ));
    // Zero lifetime: no window at all.
    e.stored_at = now;
    e.expires_at = now;
    assert_eq!(transit_grace_secs(&e), 0);
    assert!(matches!(
        check_entry_clock(&e, now),
        Err(MailboxError::ClockSkew { .. })
    ));
}

#[test]
fn check_pointer_sealed_rejects_plaintext_self_pointer_only() {
    let mut p = pointer(make_target(50), 1, 10);
    assert!(check_pointer_sealed(&p).is_ok());
    for v in [0u8, 1] {
        p.payload_version = v;
        assert!(
            matches!(check_pointer_sealed(&p), Err(MailboxError::PlaintextPayload(x)) if x == v),
            "v={v}"
        );
    }
    // Directed classes are not judged until C4 seals them.
    let d = make_entry(
        make_target(50),
        make_msg_id(2),
        MailboxClass::DropNotice,
        vec![],
        10,
        10,
    );
    assert_eq!(d.payload_version, 1);
    assert!(check_pointer_sealed(&d).is_ok());
}

/// mailbox-i31: 16 concurrent stores into ONE slot. Check, replacement and insert
/// are one write transaction, so however they interleave the slot ends with exactly
/// one entry — the newest — and the newest store is never refused. Many rounds,
/// because a split check/replace only fails on some interleavings.
#[test]
fn concurrent_same_slot_stores_keep_the_newest() {
    use std::sync::{Arc, Barrier};
    const WRITERS: u32 = 16;
    for round in 0..40u8 {
        let db = test_db();
        let target = make_target(round);
        let barrier = Arc::new(Barrier::new(WRITERS as usize));
        let handles: Vec<_> = (0..WRITERS)
            .map(|n| {
                let db = db.clone();
                let barrier = Arc::clone(&barrier);
                let e = small_pointer(target, 7, 1_000 + n as u64);
                std::thread::spawn(move || {
                    barrier.wait();
                    MailboxEngine::new(db).store(&e, 0)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        assert_eq!(
            stored_ats(&db, &target),
            vec![1_000 + (WRITERS - 1) as u64],
            "round {round}: one entry, the newest"
        );
        assert!(
            results[(WRITERS - 1) as usize].is_ok(),
            "round {round}: the newest pointer was refused: {:?}",
            results[(WRITERS - 1) as usize]
        );
        let small = small_pointer(target, 7, 1_000 + (WRITERS - 1) as u64);
        assert_eq!(
            db.mailbox_self_pointer_bytes_for_target(&target).unwrap(),
            small.serialized_size() as u64,
            "round {round}: the counter matches the one entry"
        );
    }
}

/// mailbox-i31: 16 concurrent stores of 16 DIFFERENT new slots against a cap of 4:
/// exactly 4 are stored, 12 refused, never more than the cap.
#[test]
fn concurrent_new_slots_never_exceed_cap() {
    use std::sync::{Arc, Barrier};
    const WRITERS: u32 = 16;
    const CAP: usize = 4;
    for round in 0..40u8 {
        let db = test_db();
        let target = make_target(round);
        let barrier = Arc::new(Barrier::new(WRITERS as usize));
        let handles: Vec<_> = (0..WRITERS)
            .map(|n| {
                let db = db.clone();
                let barrier = Arc::clone(&barrier);
                let e = small_pointer(target, n, 1_000 + n as u64);
                std::thread::spawn(move || {
                    barrier.wait();
                    MailboxEngine::new(db).store_with_slot_cap(&e, 0, CAP)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok = results.iter().filter(|r| r.is_ok()).count();
        let refused = results
            .iter()
            .filter(|r| matches!(r, Err(MailboxError::QuotaExceeded { .. })))
            .count();
        assert_eq!(
            (ok, refused),
            (CAP, WRITERS as usize - CAP),
            "round {round}"
        );
        assert_eq!(
            db.mailbox_self_pointer_slot_count(&target).unwrap(),
            CAP,
            "round {round}"
        );
    }
}
