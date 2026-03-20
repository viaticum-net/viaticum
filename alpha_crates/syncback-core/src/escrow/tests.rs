use super::*;
use crate::constants::{
    DROP_NOTICE_WINDOW_SECS, FREE_TIER_BYTES, HOLDER_DELETE_COOLDOWN_SECS, TIER1_MAX_BYTES,
    TIER2_MAX_BYTES,
};
use crate::testutil::{test_db, test_peer, test_shard_id, week};
use crate::types::{FileType, ShardState};

fn make_holding(shard_id: ShardId, owner_pub: IdentityPub, size_bytes: u64) -> HoldingRecord {
    HoldingRecord {
        shard_id,
        owner_pub,
        importance: 0.5,
        size_bytes,
        state: ShardState::Active,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
        file_type: FileType::User,
        merkle_root: [0u8; 32],
        rs_k: 5,
        rs_n: 10,
        shard_index: 0,
    }
}

fn make_peer(
    db: &Db,
    identity: IdentityPub,
    weeks_in_network: u32,
) -> crate::types::PeerRecord {
    use crate::types::{NodeId, PeerRecord};
    let record = PeerRecord {
        identity,
        node_id: Some(NodeId([0u8; 32])),
        trust_p: 0.8,
        trust_i: 0.7,
        trust_s: 1.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        weeks_in_network,
        subnet_prefix: None,
        allowlisted: false,
    };
    db.upsert_peer(&record).unwrap();
    record
}

#[test]
fn free_tier_always_allowed() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();

    // No restore log → bytes_restored = 0 → FreeTier → Allowed
    let decision = checker.check_restore(&shard, &peer, Timestamp(0)).unwrap();
    assert!(matches!(decision, RestoreDecision::Allowed));
}

#[test]
fn tier1_denied_below_4_weeks() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, FREE_TIER_BYTES + 1))
        .unwrap();
    checker
        .record_restore(&shard, &peer, FREE_TIER_BYTES + 1, Timestamp(0))
        .unwrap();
    make_peer(&db, peer, 3);

    let decision = checker.check_restore(&shard, &peer, Timestamp(0)).unwrap();
    match decision {
        RestoreDecision::Denied(denial) => {
            assert_eq!(denial.tier, EscrowTier::Tier1);
            assert_eq!(denial.required_weeks, 4);
            assert_eq!(denial.current_weeks, 3);
        }
        RestoreDecision::Allowed => panic!("expected Denied"),
    }
}

#[test]
fn tier1_allowed_at_4_weeks() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, FREE_TIER_BYTES + 1))
        .unwrap();
    checker
        .record_restore(&shard, &peer, FREE_TIER_BYTES + 1, Timestamp(0))
        .unwrap();
    make_peer(&db, peer, 4);

    let decision = checker.check_restore(&shard, &peer, Timestamp(0)).unwrap();
    assert!(matches!(decision, RestoreDecision::Allowed));
}

#[test]
fn tier2_denied_below_13_weeks() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, TIER1_MAX_BYTES + 1))
        .unwrap();
    checker
        .record_restore(&shard, &peer, TIER1_MAX_BYTES + 1, Timestamp(0))
        .unwrap();
    make_peer(&db, peer, 12);

    let decision = checker.check_restore(&shard, &peer, Timestamp(0)).unwrap();
    match decision {
        RestoreDecision::Denied(denial) => {
            assert_eq!(denial.tier, EscrowTier::Tier2);
            assert_eq!(denial.required_weeks, 13);
            assert_eq!(denial.current_weeks, 12);
        }
        RestoreDecision::Allowed => panic!("expected Denied"),
    }
}

#[test]
fn tier2_allowed_at_13_weeks() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, TIER1_MAX_BYTES + 1))
        .unwrap();
    checker
        .record_restore(&shard, &peer, TIER1_MAX_BYTES + 1, Timestamp(0))
        .unwrap();
    make_peer(&db, peer, 13);

    let decision = checker.check_restore(&shard, &peer, Timestamp(0)).unwrap();
    assert!(matches!(decision, RestoreDecision::Allowed));
}

#[test]
fn tier3_denied_below_26_weeks() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, TIER2_MAX_BYTES + 1))
        .unwrap();
    checker
        .record_restore(&shard, &peer, TIER2_MAX_BYTES + 1, Timestamp(0))
        .unwrap();
    make_peer(&db, peer, 25);

    let decision = checker.check_restore(&shard, &peer, Timestamp(0)).unwrap();
    match decision {
        RestoreDecision::Denied(denial) => {
            assert_eq!(denial.tier, EscrowTier::Tier3);
            assert_eq!(denial.required_weeks, 26);
            assert_eq!(denial.current_weeks, 25);
        }
        RestoreDecision::Allowed => panic!("expected Denied"),
    }
}

#[test]
fn tier3_allowed_at_26_weeks() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, TIER2_MAX_BYTES + 1))
        .unwrap();
    checker
        .record_restore(&shard, &peer, TIER2_MAX_BYTES + 1, Timestamp(0))
        .unwrap();
    make_peer(&db, peer, 26);

    let decision = checker.check_restore(&shard, &peer, Timestamp(0)).unwrap();
    assert!(matches!(decision, RestoreDecision::Allowed));
}

#[test]
fn unknown_owner_gets_zero_weeks() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, FREE_TIER_BYTES + 1))
        .unwrap();
    checker
        .record_restore(&shard, &peer, FREE_TIER_BYTES + 1, Timestamp(0))
        .unwrap();
    // peer NOT in peers table

    let decision = checker.check_restore(&shard, &peer, Timestamp(0)).unwrap();
    match decision {
        RestoreDecision::Denied(denial) => {
            assert_eq!(denial.required_weeks, 4);
            assert_eq!(denial.current_weeks, 0);
        }
        RestoreDecision::Allowed => panic!("expected Denied"),
    }
}

#[test]
fn veteran_always_passes_tier3() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, TIER2_MAX_BYTES + 1))
        .unwrap();
    checker
        .record_restore(&shard, &peer, TIER2_MAX_BYTES + 1, Timestamp(0))
        .unwrap();
    make_peer(&db, peer, 200);

    let decision = checker.check_restore(&shard, &peer, Timestamp(0)).unwrap();
    assert!(matches!(decision, RestoreDecision::Allowed));
}

#[test]
fn record_restore_accumulates() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard_a = test_shard_id(1);
    let shard_b = test_shard_id(2);
    let t1 = Timestamp(1_000_000);
    let t2 = Timestamp(2_000_000);

    checker
        .record_restore(&shard_a, &peer, 500_000_000, t1)
        .unwrap();
    checker
        .record_restore(&shard_b, &peer, 600_000_000, t2)
        .unwrap();

    let log = db.get_restore_log(&peer).unwrap().unwrap();
    assert_eq!(log.bytes_restored, 1_100_000_000);
    assert_eq!(log.first_restore_at, Some(t1));
    assert_eq!(log.last_restore_at, Some(t2));
}

#[test]
fn mark_for_delete_sets_state() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();
    checker
        .mark_for_delete(&shard, &peer, Timestamp(0))
        .unwrap();

    let record = checker.get_holding(&shard).unwrap().unwrap();
    assert_eq!(record.state, ShardState::MarkedForDelete);
    assert_eq!(record.delete_requested_at, Some(Timestamp(0)));
}

#[test]
fn mark_for_delete_is_idempotent() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();
    checker
        .mark_for_delete(&shard, &peer, Timestamp(100))
        .unwrap();
    checker
        .mark_for_delete(&shard, &peer, Timestamp(200))
        .unwrap();

    let record = checker.get_holding(&shard).unwrap().unwrap();
    assert_eq!(record.delete_requested_at, Some(Timestamp(100)));
}

#[test]
fn holder_cooldown_not_expired_keeps_shard() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();
    checker
        .mark_for_delete(&shard, &peer, Timestamp(0))
        .unwrap();

    let decision = checker
        .should_delete_now(&shard, Timestamp(HOLDER_DELETE_COOLDOWN_SECS - 1))
        .unwrap();
    assert!(matches!(decision, DeleteDecision::Keep));
}

#[test]
fn holder_cooldown_expired_deletes_shard() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();
    checker
        .mark_for_delete(&shard, &peer, Timestamp(0))
        .unwrap();

    let decision = checker
        .should_delete_now(&shard, Timestamp(HOLDER_DELETE_COOLDOWN_SECS))
        .unwrap();
    assert!(matches!(decision, DeleteDecision::Delete));
}

#[test]
fn cancel_delete_restores_active_state() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();
    checker
        .mark_for_delete(&shard, &peer, Timestamp(0))
        .unwrap();
    checker.cancel_delete(&shard, &peer).unwrap();

    let record = checker.get_holding(&shard).unwrap().unwrap();
    assert_eq!(record.state, ShardState::Active);
    assert_eq!(record.delete_requested_at, None);
}

#[test]
fn cancel_delete_after_cooldown_expired_still_keeps() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();
    checker
        .mark_for_delete(&shard, &peer, Timestamp(0))
        .unwrap();
    checker.cancel_delete(&shard, &peer).unwrap();

    let very_late = Timestamp(HOLDER_DELETE_COOLDOWN_SECS * 10);
    let decision = checker.should_delete_now(&shard, very_late).unwrap();
    assert!(matches!(decision, DeleteDecision::Keep));
}

#[test]
fn drop_notice_window_not_expired() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();
    checker.record_drop_notice(&shard, Timestamp(0)).unwrap();

    let decision = checker
        .check_drop_notice(&shard, Timestamp(DROP_NOTICE_WINDOW_SECS - 1))
        .unwrap();
    assert!(matches!(decision, DropNoticeDecision::StillWaiting));
}

#[test]
fn drop_notice_window_expired() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();
    checker.record_drop_notice(&shard, Timestamp(0)).unwrap();

    let decision = checker
        .check_drop_notice(&shard, Timestamp(DROP_NOTICE_WINDOW_SECS))
        .unwrap();
    assert!(matches!(decision, DropNoticeDecision::DeleteNow));
}

#[test]
fn no_drop_notice_sent_is_still_waiting() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();

    let decision = checker
        .check_drop_notice(&shard, Timestamp(999_999_999))
        .unwrap();
    assert!(matches!(decision, DropNoticeDecision::StillWaiting));
}

#[test]
fn expired_deletes_returns_correct_shards() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard_a = test_shard_id(1);
    let shard_b = test_shard_id(2);
    let shard_c = test_shard_id(3);

    checker
        .insert_holding(make_holding(shard_a, peer, 1024))
        .unwrap();
    checker
        .insert_holding(make_holding(shard_b, peer, 1024))
        .unwrap();
    checker
        .insert_holding(make_holding(shard_c, peer, 1024))
        .unwrap();

    checker
        .mark_for_delete(&shard_a, &peer, Timestamp(0))
        .unwrap();
    checker
        .mark_for_delete(&shard_b, &peer, Timestamp(0))
        .unwrap();
    checker
        .mark_for_delete(&shard_c, &peer, Timestamp(HOLDER_DELETE_COOLDOWN_SECS))
        .unwrap();

    let expired = checker
        .expired_deletes(Timestamp(HOLDER_DELETE_COOLDOWN_SECS))
        .unwrap();

    assert!(expired.contains(&shard_a));
    assert!(expired.contains(&shard_b));
    assert!(!expired.contains(&shard_c));
    assert_eq!(expired.len(), 2);
}

#[test]
fn owner_mismatch_is_error() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer_a = test_peer(1);
    let peer_b = test_peer(2);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer_a, 1024))
        .unwrap();

    let err = checker
        .mark_for_delete(&shard, &peer_b, Timestamp(0))
        .unwrap_err();
    assert!(matches!(err, EscrowError::OwnerMismatch { .. }));
}

#[test]
fn check_restore_shard_not_held() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    let err = checker
        .check_restore(&shard, &peer, Timestamp(0))
        .unwrap_err();
    assert!(matches!(err, EscrowError::ShardNotHeld(_)));
}

#[test]
fn free_tier_boundary_exact() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();

    // FREE_TIER_BYTES - 1 → FreeTier → Allowed
    checker
        .record_restore(&shard, &peer, FREE_TIER_BYTES - 1, Timestamp(0))
        .unwrap();
    let decision = checker.check_restore(&shard, &peer, Timestamp(0)).unwrap();
    assert!(matches!(decision, RestoreDecision::Allowed));

    // Add 1 more byte → exactly FREE_TIER_BYTES → Tier1
    checker
        .record_restore(&shard, &peer, 1, Timestamp(1))
        .unwrap();
    let decision = checker.check_restore(&shard, &peer, Timestamp(0)).unwrap();
    assert!(matches!(decision, RestoreDecision::Denied(_)));

    // Add 1 more → FREE_TIER_BYTES + 1 → still Tier1
    checker
        .record_restore(&shard, &peer, 1, Timestamp(2))
        .unwrap();
    let decision = checker.check_restore(&shard, &peer, Timestamp(0)).unwrap();
    assert!(matches!(decision, RestoreDecision::Denied(_)));
}

#[test]
fn mark_silent_and_back_to_active() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();

    checker.mark_silent(&shard).unwrap();
    let record = checker.get_holding(&shard).unwrap().unwrap();
    assert_eq!(record.state, ShardState::Silent);

    checker.mark_active(&shard).unwrap();
    let record = checker.get_holding(&shard).unwrap().unwrap();
    assert_eq!(record.state, ShardState::Active);
}

#[test]
fn all_holdings_returns_all() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard_a = test_shard_id(1);
    let shard_b = test_shard_id(2);
    let shard_c = test_shard_id(3);

    checker
        .insert_holding(make_holding(shard_a, peer, 1024))
        .unwrap();
    checker
        .insert_holding(make_holding(shard_b, peer, 2048))
        .unwrap();
    checker
        .insert_holding(make_holding(shard_c, peer, 4096))
        .unwrap();

    let holdings = checker.all_holdings().unwrap();
    assert_eq!(holdings.len(), 3);
}

#[test]
fn mark_for_delete_is_denied_after_cooldown_via_check_restore() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();
    checker
        .mark_for_delete(&shard, &peer, Timestamp(0))
        .unwrap();

    // After cooldown: check_restore returns Denied
    let decision = checker
        .check_restore(&shard, &peer, Timestamp(HOLDER_DELETE_COOLDOWN_SECS))
        .unwrap();
    assert!(matches!(decision, RestoreDecision::Denied(_)));
}

#[test]
fn check_restore_during_cooldown_applies_normal_escrow() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();
    checker
        .mark_for_delete(&shard, &peer, Timestamp(0))
        .unwrap();

    // During cooldown (before expiry): escrow check applies → free tier → Allowed
    let decision = checker
        .check_restore(&shard, &peer, Timestamp(HOLDER_DELETE_COOLDOWN_SECS - 1))
        .unwrap();
    assert!(matches!(decision, RestoreDecision::Allowed));
}

#[test]
fn silent_shards_returns_only_silent() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard_a = test_shard_id(1);
    let shard_b = test_shard_id(2);
    let shard_c = test_shard_id(3);

    checker
        .insert_holding(make_holding(shard_a, peer, 1024))
        .unwrap();
    checker
        .insert_holding(make_holding(shard_b, peer, 1024))
        .unwrap();
    checker
        .insert_holding(make_holding(shard_c, peer, 1024))
        .unwrap();

    checker.mark_silent(&shard_a).unwrap();
    checker.mark_silent(&shard_c).unwrap();

    let silent = checker.silent_shards().unwrap();
    assert_eq!(silent.len(), 2);
    assert!(silent.contains(&shard_a));
    assert!(silent.contains(&shard_c));
    assert!(!silent.contains(&shard_b));
}

#[test]
fn expired_drop_notices_returns_correct_shards() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard_a = test_shard_id(1);
    let shard_b = test_shard_id(2);
    let shard_c = test_shard_id(3);

    checker
        .insert_holding(make_holding(shard_a, peer, 1024))
        .unwrap();
    checker
        .insert_holding(make_holding(shard_b, peer, 1024))
        .unwrap();
    checker
        .insert_holding(make_holding(shard_c, peer, 1024))
        .unwrap();

    checker.record_drop_notice(&shard_a, Timestamp(0)).unwrap();
    checker.record_drop_notice(&shard_b, Timestamp(0)).unwrap();
    // shard_c: no drop notice

    let expired = checker
        .expired_drop_notices(Timestamp(DROP_NOTICE_WINDOW_SECS))
        .unwrap();
    assert!(expired.contains(&shard_a));
    assert!(expired.contains(&shard_b));
    assert!(!expired.contains(&shard_c));
    assert_eq!(expired.len(), 2);
}

#[test]
fn mark_silent_does_not_affect_marked_for_delete() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();
    checker
        .mark_for_delete(&shard, &peer, Timestamp(0))
        .unwrap();
    checker.mark_silent(&shard).unwrap();

    let record = checker.get_holding(&shard).unwrap().unwrap();
    assert_eq!(record.state, ShardState::MarkedForDelete);
}

#[test]
fn remove_holding_deletes_record() {
    let (db, _tmp) = test_db();
    let checker = EscrowChecker::new(db.clone());
    let peer = test_peer(1);
    let shard = test_shard_id(1);

    checker
        .insert_holding(make_holding(shard, peer, 1024))
        .unwrap();
    checker.remove_holding(&shard).unwrap();

    let record = checker.get_holding(&shard).unwrap();
    assert!(record.is_none());
}

#[test]
fn week_helper_produces_correct_timestamps() {
    assert_eq!(week(0), Timestamp(0));
    assert_eq!(week(4), Timestamp(4 * 604_800));
    assert_eq!(week(13), Timestamp(13 * 604_800));
    assert_eq!(week(26), Timestamp(26 * 604_800));
}
