// Tests for the Scheduler module.
//
// Strategy: test issue_due_challenges() and check_timeouts() directly
// (not the run() loop) to avoid real timers and network connections.
// The PendingChallenges map is used as the primary observable output.

use std::collections::HashMap;
use std::sync::Arc;

use syncback_core::db::Db;
use syncback_core::types::{
    DeviceId, FileId, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp,
};
use tokio::sync::{mpsc, Mutex};

use syncback_core::erasure::RaptorQEncoder;

use crate::daemon::relay::RelayPost;
use crate::daemon::repair::RepairTrigger;
use crate::daemon::scheduler::{PendingChallenges, PendingHashChallenge, Scheduler, SchedulerConfig};

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn make_block_id(seed: u8) -> SourceBlockId {
    SourceBlockId([seed; 32])
}

fn make_identity(seed: u8) -> DeviceId {
    DeviceId([seed; 32])
}

fn make_placement(block_id: SourceBlockId, holder_id: DeviceId) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: FileId(1),
        // Single ESI range: [0, 64] — 64 symbols.
        esi_ranges: vec![(0, 64)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None, // None → always due immediately.
        placed_at: Timestamp(0),
        consecutive_misses: 0,
    }
}

fn make_pending_challenges() -> PendingChallenges {
    Arc::new(Mutex::new(HashMap::new()))
}

fn make_test_encoder() -> std::sync::Arc<dyn syncback_core::erasure::ErasureEncoder> {
    std::sync::Arc::new(RaptorQEncoder::new())
}

const TEST_EPOCH_KEY: [u8; 32] = [0u8; 32];

// ─── Tests ────────────────────────────────────────────────────────────────────

/// After check_timeouts() processes a stale entry, the entry is removed from
/// pending and a RepairNow trigger is sent when the transition requires repair.
#[tokio::test]
async fn check_timeouts_removes_stale_entry_and_triggers_repair() {
    let db = Db::open_in_memory().expect("db open");
    let block_id = make_block_id(1);
    let holder_id = make_identity(2);

    // Insert a placement with 3 consecutive misses so the next Timeout → PresumedLost
    // and trigger_repair=true.
    let mut placement = make_placement(block_id, holder_id);
    placement.consecutive_misses = 2; // one more timeout will → PresumedLost (3 misses)
    db.upsert_placement(&placement).expect("upsert placement");

    let pending = make_pending_challenges();
    let (repair_tx, mut repair_rx) = mpsc::channel::<RepairTrigger>(8);

    // Insert a stale pending challenge: issued far in the past (0 unix seconds).
    {
        let mut guard = pending.lock().await;
        guard.insert(
            (block_id, holder_id),
            PendingHashChallenge {
                source_block_id: block_id,
                holder_id,
                esi_ranges: vec![(0, 64)],
                expected_chain_hash: [0u8; 32],
                issued_at: Timestamp(0), // ancient — definitely timed out
                challenge_id: [0u8; 16],
            },
        );
    }

    // Build a Scheduler with no real network needed (check_timeouts doesn't use it).
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1, // real-time scale, threshold = POS_TIMEOUT_SECS
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };

    // We need a NetworkHandle for the constructor. Build a no-op one via a stub.
    // Since check_timeouts doesn't use network, we pass a real (but unused) handle.
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let scheduler = Scheduler::new(db.clone(), config, repair_tx, pending.clone(), relay_post_tx, signing_key, std::path::PathBuf::from("/tmp/test_source_blocks"), crate::daemon::processor::make_empty_accepted_offers(), make_test_encoder(), TEST_EPOCH_KEY);

    scheduler.check_timeouts().await.expect("check_timeouts");

    // Pending map should be empty now.
    assert!(
        pending.lock().await.is_empty(),
        "pending map should be cleared after timeout processing"
    );

    // RepairNow should have been sent (3 misses → PresumedLost → trigger_repair=true).
    let trigger = repair_rx.try_recv().expect("repair trigger should be sent");
    match trigger {
        RepairTrigger::RepairNow { block_id: bid, holder_id: hid } => {
            assert_eq!(bid, block_id);
            assert_eq!(hid, holder_id);
        }
        other => panic!("expected RepairNow, got {other:?}"),
    }

    // Verify placement was updated to PresumedLost in DB.
    let updated = db
        .get_placement(&block_id, &holder_id)
        .expect("db read")
        .expect("placement exists");
    assert_eq!(updated.status, PlacementStatus::PresumedLost);
    assert_eq!(updated.consecutive_misses, 3);
}

/// A fresh pending challenge (issued_at = now) is NOT timed out.
#[tokio::test]
async fn check_timeouts_ignores_fresh_challenges() {
    let db = Db::open_in_memory().expect("db open");
    let block_id = make_block_id(3);
    let holder_id = make_identity(4);

    let placement = make_placement(block_id, holder_id);
    db.upsert_placement(&placement).expect("upsert");

    let pending = make_pending_challenges();
    let (repair_tx, mut repair_rx) = mpsc::channel::<RepairTrigger>(8);

    // Challenge issued right now.
    let now = Timestamp::now();
    {
        let mut guard = pending.lock().await;
        guard.insert(
            (block_id, holder_id),
            PendingHashChallenge {
                source_block_id: block_id,
                holder_id,
                esi_ranges: vec![(5, 1)],
                expected_chain_hash: [0u8; 32],
                issued_at: now,
                challenge_id: [1u8; 16],
            },
        );
    }

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1, // POS_TIMEOUT_SECS = 604_800 s — fresh challenge won't expire
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let scheduler = Scheduler::new(db, config, repair_tx, pending.clone(), relay_post_tx, signing_key, std::path::PathBuf::from("/tmp/test_source_blocks"), crate::daemon::processor::make_empty_accepted_offers(), make_test_encoder(), TEST_EPOCH_KEY);

    scheduler.check_timeouts().await.expect("check_timeouts");

    // Pending map still has the entry (not timed out).
    assert_eq!(
        pending.lock().await.len(),
        1,
        "fresh challenge should remain in pending"
    );

    // No repair triggered.
    assert!(
        repair_rx.try_recv().is_err(),
        "no repair should be triggered for fresh challenge"
    );
}

/// PendingChallenges can be cloned and accessed concurrently from two tasks.
#[tokio::test]
async fn pending_challenges_shared_between_tasks() {
    let pending: PendingChallenges = Arc::new(Mutex::new(HashMap::new()));
    let block_id = make_block_id(10);
    let holder_id = make_identity(11);

    let pending_writer = pending.clone();
    let pending_reader = pending.clone();

    // Writer task inserts an entry.
    let write_handle = tokio::spawn(async move {
        let mut guard = pending_writer.lock().await;
        guard.insert(
            (block_id, holder_id),
            PendingHashChallenge {
                source_block_id: block_id,
                holder_id,
                esi_ranges: vec![(42, 1)],
                expected_chain_hash: [0u8; 32],
                issued_at: Timestamp::now(),
                challenge_id: [7u8; 16],
            },
        );
    });

    write_handle.await.expect("writer task");

    // Reader task sees the entry.
    let read_handle = tokio::spawn(async move {
        let guard = pending_reader.lock().await;
        assert_eq!(guard.len(), 1, "reader should see written entry");
        let entry = guard.get(&(block_id, holder_id)).expect("entry present");
        assert_eq!(entry.esi_ranges, vec![(42, 1)]);
    });

    read_handle.await.expect("reader task");
}

/// With time_scale > 1, timeouts are detected proportionally sooner.
#[tokio::test]
async fn check_timeouts_respects_time_scale() {
    let db = Db::open_in_memory().expect("db open");
    let block_id = make_block_id(20);
    let holder_id = make_identity(21);

    let mut placement = make_placement(block_id, holder_id);
    placement.consecutive_misses = 0;
    db.upsert_placement(&placement).expect("upsert");

    let pending = make_pending_challenges();
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);

    // time_scale = POS_TIMEOUT_SECS so threshold = 1 second.
    // issued_at = 10 seconds ago → clearly timed out at threshold=1.
    let now = Timestamp::now();
    let issued_at = Timestamp(now.0.saturating_sub(10));

    {
        let mut guard = pending.lock().await;
        guard.insert(
            (block_id, holder_id),
            PendingHashChallenge {
                source_block_id: block_id,
                holder_id,
                esi_ranges: vec![(0, 64)],
                expected_chain_hash: [0u8; 32],
                issued_at,
                challenge_id: [0u8; 16],
            },
        );
    }

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: syncback_core::constants::POS_TIMEOUT_SECS, // threshold = 1 second
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let scheduler = Scheduler::new(db.clone(), config, repair_tx, pending.clone(), relay_post_tx, signing_key, std::path::PathBuf::from("/tmp/test_source_blocks"), crate::daemon::processor::make_empty_accepted_offers(), make_test_encoder(), TEST_EPOCH_KEY);

    scheduler.check_timeouts().await.expect("check_timeouts");

    // Entry should have been processed (removed from pending).
    assert!(
        pending.lock().await.is_empty(),
        "timed-out entry should be removed with scaled threshold"
    );

    // Placement should now be Uncertain (first timeout, consecutive_misses=1).
    let updated = db
        .get_placement(&block_id, &holder_id)
        .expect("db read")
        .expect("placement exists");
    assert_eq!(updated.status, PlacementStatus::Uncertain);
    assert_eq!(updated.consecutive_misses, 1);
}

/// issue_due_challenges() skips a placement that already has a pending challenge.
#[tokio::test]
async fn issue_due_challenges_skips_already_pending() {
    let db = Db::open_in_memory().expect("db open");
    let block_id = make_block_id(30);
    let holder_id = make_identity(31);

    // Placement with last_verified=None → would normally be due.
    let placement = make_placement(block_id, holder_id);
    db.upsert_placement(&placement).expect("upsert");

    let pending = make_pending_challenges();
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);

    // Pre-populate pending — simulates a challenge already in flight.
    {
        let mut guard = pending.lock().await;
        guard.insert(
            (block_id, holder_id),
            PendingHashChallenge {
                source_block_id: block_id,
                holder_id,
                esi_ranges: vec![(5, 1)],
                expected_chain_hash: [0u8; 32],
                issued_at: Timestamp::now(),
                challenge_id: [2u8; 16],
            },
        );
    }

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let scheduler = Scheduler::new(db, config, repair_tx, pending.clone(), relay_post_tx, signing_key, std::path::PathBuf::from("/tmp/test_source_blocks"), crate::daemon::processor::make_empty_accepted_offers(), make_test_encoder(), TEST_EPOCH_KEY);

    // issue_due_challenges should skip this holder because it's already pending.
    // The existing pending entry's esi_ranges should not be overwritten.
    scheduler
        .issue_due_challenges()
        .await
        .expect("issue_due_challenges");

    let guard = pending.lock().await;
    assert_eq!(guard.len(), 1, "only the pre-existing entry should remain");
    let entry = guard.get(&(block_id, holder_id)).expect("entry present");
    assert_eq!(entry.esi_ranges, vec![(5, 1)], "existing pending entry esi_ranges unchanged");
}

// ─── SCHED-07: scheduler_skips_deleting_placements ───────────────────────────

/// Placements with status Deleting must not be challenged.
/// issue_due_challenges() filters to Alive|Uncertain|PresumedLost only.
/// A Deleting placement with last_verified=None (normally always due) should
/// never appear in the pending map.
#[tokio::test]
async fn scheduler_skips_deleting_placements() {
    let db = Db::open_in_memory().expect("db open");
    let block_id = make_block_id(50);
    let holder_id = make_identity(51);

    // Insert a Deleting placement — would be due for a challenge if not filtered.
    let mut placement = make_placement(block_id, holder_id);
    placement.status = PlacementStatus::Deleting;
    placement.last_verified = None; // would normally trigger immediate challenge
    db.upsert_placement(&placement).expect("upsert");

    let pending = make_pending_challenges();
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let scheduler = Scheduler::new(db, config, repair_tx, pending.clone(), relay_post_tx, signing_key, std::path::PathBuf::from("/tmp/test_source_blocks"), crate::daemon::processor::make_empty_accepted_offers(), make_test_encoder(), TEST_EPOCH_KEY);

    scheduler.issue_due_challenges().await.expect("issue_due_challenges");

    // Pending map must remain empty: Deleting placement was filtered out.
    assert!(
        pending.lock().await.is_empty(),
        "Deleting placement must not generate a pending challenge"
    );
}

// ─── SCHED-08: time_scale_divides_intervals ───────────────────────────────────

/// With time_scale=N, the timeout threshold is divided by N.
/// A challenge issued `POS_TIMEOUT_SECS / N + 1` seconds ago must be treated
/// as timed out when time_scale=N, but the same challenge would NOT be timed
/// out with time_scale=1 (which needs 7 days).
#[tokio::test]
async fn time_scale_divides_intervals() {
    use syncback_core::constants::POS_TIMEOUT_SECS;

    let db = Db::open_in_memory().expect("db open");
    let block_id = make_block_id(60);
    let holder_id = make_identity(61);

    let mut placement = make_placement(block_id, holder_id);
    placement.consecutive_misses = 0;
    db.upsert_placement(&placement).expect("upsert");

    let pending = make_pending_challenges();
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);

    // time_scale = POS_TIMEOUT_SECS means threshold = 1 second.
    // Issue challenge 5 seconds in the past.
    let scale = POS_TIMEOUT_SECS;
    let now = Timestamp::now();
    let issued_at = Timestamp(now.0.saturating_sub(5));

    {
        let mut guard = pending.lock().await;
        guard.insert(
            (block_id, holder_id),
            PendingHashChallenge {
                source_block_id: block_id,
                holder_id,
                esi_ranges: vec![(0, 1)],
                expected_chain_hash: [0u8; 32],
                issued_at,
                challenge_id: [0u8; 16],
            },
        );
    }

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: scale,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let scheduler = Scheduler::new(db.clone(), config, repair_tx, pending.clone(), relay_post_tx, signing_key, std::path::PathBuf::from("/tmp/test_source_blocks"), crate::daemon::processor::make_empty_accepted_offers(), make_test_encoder(), TEST_EPOCH_KEY);

    scheduler.check_timeouts().await.expect("check_timeouts");

    // With time_scale=POS_TIMEOUT_SECS, threshold = 1 second.
    // Challenge issued 5 seconds ago must have been processed (removed from pending).
    assert!(
        pending.lock().await.is_empty(),
        "with time_scale={scale}, a 5s-old challenge should be timed out (threshold=1s)"
    );

    // Placement status updated: consecutive_misses=1 → Uncertain.
    let updated = db
        .get_placement(&block_id, &holder_id)
        .expect("db read")
        .expect("placement exists");
    assert_eq!(updated.status, PlacementStatus::Uncertain);
}

// ─── process_deletion_tick tests ──────────────────────────────────────────────

/// When a file has all devices deleted and owner cooldown has elapsed,
/// process_deletion_tick sends DeleteMsg via board and marks placement Deleting.
#[tokio::test]
async fn deletion_tick_sends_drop_notice_and_marks_placement_deleting() {
    use syncback_core::types::{
        DeviceId, FileRecord, FileVersion, LocalState, SourceBlockRecord, SourceBlockStatus,
        SourceBlockType,
    };

    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xD1);
    let holder_id = make_identity(0xD2);
    let device_id = DeviceId([0x01; 32]);

    // File: all devices deleted, deleted_at = 0 (very old).
    let file = FileRecord {
        file_id: FileId(1),
        path: "test.txt".to_string(),
        importance: 0.5,
        devices: vec![(device_id, LocalState::Deleted(Timestamp(0)))],
        versions: vec![FileVersion {
            content_hash: [0; 32],
            source_block_id: block_id,
            k: 100,
            t: 65535,
            created_at: Timestamp(0),
            backed_up_at: Some(Timestamp(0)),
        }],
        first_seen: Timestamp(0),
    };
    db.upsert_file(&file).unwrap();

    // Source block: Active.
    let sb = SourceBlockRecord {
        block_id,
        k: 100,
        t: 65535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(0),
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
        last_attempted_at: None,
        last_pool_signature: 0,
    };
    db.upsert_source_block(&sb).unwrap();

    // Placement: Alive.
    let placement = make_placement(block_id, holder_id);
    db.upsert_placement(&placement).unwrap();

    // Peer record (needed for trust lookup in due_challenges, also for deletion signing).
    let peer = syncback_core::types::PeerRecord {
        device_id: holder_id,
        master_identity: syncback_core::types::IdentityPub(holder_id.0),
        trust_p: 0.5,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    };
    db.upsert_peer(&peer).unwrap();

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let (relay_post_tx, mut relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let pending = make_pending_challenges();
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(db.clone(), config, repair_tx, pending, relay_post_tx, signing_key, std::path::PathBuf::from("/tmp/test_source_blocks"), crate::daemon::processor::make_empty_accepted_offers(), make_test_encoder(), TEST_EPOCH_KEY);

    // Now = after owner cooldown. Deleted_at=0, cooldown=4 weeks.
    // process_deletion_tick uses Timestamp::now() internally. Since deleted_at=0,
    // any now > OWNER_DELETE_COOLDOWN_SECS will trigger.
    scheduler.process_deletion_tick().await.unwrap();

    // Should have posted a "delete" message via relay.
    let post = relay_post_rx.try_recv().expect("expected a delete RelayPost");
    assert_eq!(post.msg_type, "delete");
    // process_deletion_tick falls back to IdentityPub(holder_id.0) when no master mapping.
    assert_eq!(post.target, Some(syncback_core::types::IdentityPub(holder_id.0)));

    // Placement should be Deleting.
    let updated = db.get_placement(&block_id, &holder_id).unwrap().unwrap();
    assert_eq!(updated.status, PlacementStatus::Deleting);

    // Source block should be Deleting.
    let updated_sb = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(updated_sb.status, SourceBlockStatus::Deleting);
}

/// When no files are eligible, process_deletion_tick is a no-op.
#[tokio::test]
async fn deletion_tick_noop_when_no_eligible_files() {
    let db = Db::open_in_memory().unwrap();

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let (relay_post_tx, mut relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let pending = make_pending_challenges();
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(db, config, repair_tx, pending, relay_post_tx, signing_key, std::path::PathBuf::from("/tmp/test_source_blocks"), crate::daemon::processor::make_empty_accepted_offers(), make_test_encoder(), TEST_EPOCH_KEY);

    scheduler.process_deletion_tick().await.unwrap();

    // No messages should be posted.
    assert!(relay_post_rx.try_recv().is_err());
}

// ─── B3: sweep_offered_placements tests ──────────────────────────────────────

/// An Offered placement past the 14-day long-absence threshold is marked Lost and triggers repair.
#[tokio::test]
async fn scheduler_transitions_offered_to_lost_after_long_absence() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(20);
    let holder_id = make_identity(21);

    // Place far in the past (Unix epoch 0) — age >> 14 days.
    let ancient = Timestamp(0);
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: FileId(1),
        esi_ranges: vec![(0, 64)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Offered,
        last_verified: None,
        placed_at: ancient,
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    let (repair_tx, mut repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let pending = make_pending_challenges();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

    // Threshold = LONG_ABSENCE_SECS = 14 days.
    // placed_at = 0 means age = now >> 14 days → must become Lost.
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending,
        relay_post_tx,
        signing_key,
        std::path::PathBuf::from("/tmp/test_source_blocks"),
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
    );

    scheduler.sweep_offered_placements().await.unwrap();

    // Placement should be Lost now.
    let updated = db
        .get_placement(&block_id, &holder_id)
        .unwrap()
        .expect("placement exists");
    assert_eq!(
        updated.status,
        PlacementStatus::Lost,
        "Offered placement absent > 14 days should become Lost"
    );

    // repair_tx should have received RepairNow.
    let trigger = repair_rx.try_recv().expect("repair trigger must be sent");
    match trigger {
        RepairTrigger::RepairNow {
            block_id: bid,
            holder_id: hid,
        } => {
            assert_eq!(bid, block_id);
            assert_eq!(hid, holder_id);
        }
        other => panic!("expected RepairNow, got {other:?}"),
    }
}

/// An Offered placement less than 14 days old is NOT swept.
#[tokio::test]
async fn scheduler_does_not_transition_offered_to_lost_before_long_absence() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(22);
    let holder_id = make_identity(23);

    // 1 day ago — well below the 14-day LONG_ABSENCE_SECS threshold.
    let one_day_ago = Timestamp(Timestamp::now().0.saturating_sub(86_400));
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: FileId(1),
        esi_ranges: vec![(0, 64)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Offered,
        last_verified: None,
        placed_at: one_day_ago,
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    let (repair_tx, mut repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let pending = make_pending_challenges();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending,
        relay_post_tx,
        signing_key,
        std::path::PathBuf::from("/tmp/test_source_blocks"),
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
    );

    scheduler.sweep_offered_placements().await.unwrap();

    // Placement should remain Offered — only 1 day old, threshold is 14 days.
    let updated = db
        .get_placement(&block_id, &holder_id)
        .unwrap()
        .expect("placement exists");
    assert_eq!(
        updated.status,
        PlacementStatus::Offered,
        "Offered placement younger than 14 days must not be swept"
    );

    // No repair triggered.
    assert!(
        repair_rx.try_recv().is_err(),
        "no repair should be triggered for placement below long-absence threshold"
    );
}

// ─── D3: drop_notice dedup tests ──────────────────────────────────────────────

/// Drop notice is sent only once even when process_deletion_tick is called twice.
/// On the second tick, drop_notice_sent_at is Some → skip sending.
#[tokio::test]
async fn drop_notice_sent_only_once_when_tick_called_twice() {
    use syncback_core::types::{
        DeviceId, FileRecord, FileVersion, LocalState, SourceBlockRecord, SourceBlockStatus,
        SourceBlockType,
    };

    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xE1);
    let holder_id = make_identity(0xE2);
    let device_id = DeviceId([0x01; 32]);

    // File: all devices deleted, deleted_at = 0 (well past owner cooldown).
    let file = FileRecord {
        file_id: FileId(99),
        path: "dedup_test.txt".to_string(),
        importance: 0.5,
        devices: vec![(device_id, LocalState::Deleted(Timestamp(0)))],
        versions: vec![FileVersion {
            content_hash: [0; 32],
            source_block_id: block_id,
            k: 10,
            t: 65535,
            created_at: Timestamp(0),
            backed_up_at: Some(Timestamp(0)),
        }],
        first_seen: Timestamp(0),
    };
    db.upsert_file(&file).unwrap();

    // Source block: Active, drop_notice_sent_at = None.
    let sb = SourceBlockRecord {
        block_id,
        k: 10,
        t: 65535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(0),
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
        last_attempted_at: None,
        last_pool_signature: 0,
    };
    db.upsert_source_block(&sb).unwrap();

    // Placement: Alive.
    let placement = make_placement(block_id, holder_id);
    db.upsert_placement(&placement).unwrap();

    // Peer record.
    let peer = syncback_core::types::PeerRecord {
        device_id: holder_id,
        master_identity: syncback_core::types::IdentityPub(holder_id.0),
        trust_p: 0.5,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    };
    db.upsert_peer(&peer).unwrap();

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let (relay_post_tx, mut relay_post_rx) = mpsc::channel::<RelayPost>(64);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let pending = make_pending_challenges();
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending,
        relay_post_tx,
        signing_key,
        std::path::PathBuf::from("/tmp/test_source_blocks"),
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
    );

    // First tick: should send the drop notice.
    scheduler.process_deletion_tick().await.unwrap();
    let first_post = relay_post_rx.try_recv().expect("first tick must send a delete msg");
    assert_eq!(first_post.msg_type, "delete");

    // drop_notice_sent_at must now be set.
    let updated_sb = db.get_source_block(&block_id).unwrap().unwrap();
    assert!(
        updated_sb.drop_notice_sent_at.is_some(),
        "drop_notice_sent_at must be set after first tick"
    );

    // Second tick: must NOT send another message.
    scheduler.process_deletion_tick().await.unwrap();
    assert!(
        relay_post_rx.try_recv().is_err(),
        "second tick must not send another drop notice (dedup)"
    );
}

// ─── D4: cleanup_block_removes_files_from_disk ───────────────────────────────

/// CleanupBlock must call remove_dir_all on the owner-side source block directory.
///
/// Setup:
///   - File: single device, deleted_at = 0 (well past owner + holder cooldowns).
///   - Source block: Deleting.
///   - Placement: Deleting.
///   - source_blocks_dir contains {block_hex}/block.bin.
///
/// After process_deletion_tick the directory must be gone.
#[tokio::test]
async fn cleanup_block_removes_files_from_disk() {
    use syncback_core::types::DeviceId;
    use tempfile::TempDir;

    let db = Db::open_in_memory().unwrap();
    let source_blocks_tmp = TempDir::new().expect("tempdir");

    let block_id = make_block_id(0xC1);
    let holder_id = make_identity(0xC2);
    let device_id = DeviceId([0xC3u8; 32]);

    // File: single device, fully deleted at time 0.
    let file = syncback_core::types::FileRecord {
        file_id: FileId(200),
        path: "cleanup_test.bin".to_string(),
        importance: 0.5,
        devices: vec![(device_id, syncback_core::types::LocalState::Deleted(Timestamp(0)))],
        versions: vec![syncback_core::types::FileVersion {
            content_hash: [0; 32],
            source_block_id: block_id,
            k: 10,
            t: 65535,
            created_at: Timestamp(0),
            backed_up_at: Some(Timestamp(0)),
        }],
        first_seen: Timestamp(0),
    };
    db.upsert_file(&file).unwrap();

    // Source block: already in Deleting state.
    let sb = syncback_core::types::SourceBlockRecord {
        block_id,
        k: 10,
        t: 65535,
        block_type: syncback_core::types::SourceBlockType::Single,
        status: syncback_core::types::SourceBlockStatus::Deleting,
        created_at: Timestamp(0),
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: Some(Timestamp(0)), // already sent, skip SendDropNotice
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
        last_attempted_at: None,
        last_pool_signature: 0,
    };
    db.upsert_source_block(&sb).unwrap();

    // Placement: already Deleting (holder has acknowledged).
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: FileId(200),
        esi_ranges: vec![(0, 64)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Deleting,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    // Create the owner-side directory with a fake block.bin.
    let block_hex = syncback_core::types::hex_encode(&block_id.0);
    let block_dir = source_blocks_tmp.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();
    std::fs::write(block_dir.join("block.bin"), b"fake content").unwrap();
    assert!(block_dir.exists(), "block dir must exist before the tick");

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let pending = make_pending_challenges();
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending,
        relay_post_tx,
        signing_key,
        source_blocks_tmp.path().to_path_buf(),
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
    );

    scheduler.process_deletion_tick().await.unwrap();

    // The block directory must have been removed.
    assert!(
        !block_dir.exists(),
        "CleanupBlock must remove the source block directory from disk"
    );

    // Source block record must also be gone from DB.
    let sb_after = db.get_source_block(&block_id).unwrap();
    assert!(
        sb_after.is_none(),
        "CleanupBlock must delete the source block record from DB"
    );
}

// ─── W11a: Scheduler timeout cached-fields hook tests ─────────────────────────

/// Build a minimal SourceBlockRecord for W11a hook tests in scheduler context.
fn make_block_for_hook(
    block_id: SourceBlockId,
    current_alive: u32,
    current_reliability: f64,
) -> syncback_core::types::SourceBlockRecord {
    syncback_core::types::SourceBlockRecord {
        block_id,
        k: 5,
        t: 1,
        block_type: syncback_core::types::SourceBlockType::Single,
        status: syncback_core::types::SourceBlockStatus::Active,
        created_at: Timestamp(0),
        encrypted_size: Some(5),
        n: Some(20),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 0.5,
        current_alive,
        current_reliability,
        target_reliability: 0.99,
        last_attempted_at: None,
        last_pool_signature: 0,
    }
}

fn make_scheduler_for_hook(
    db: Db,
    repair_tx: mpsc::Sender<RepairTrigger>,
    pending: PendingChallenges,
) -> Scheduler {
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
    };
    Scheduler::new(
        db,
        config,
        repair_tx,
        pending,
        relay_post_tx,
        signing_key,
        std::path::PathBuf::from("/tmp/sched_hook_test"),
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
    )
}

/// Scheduler timeout: Alive→Uncertain preserves current_alive (Uncertain still counts).
///
/// Tests call site 6: check_timeouts inline path after upsert_placement.
#[tokio::test]
async fn scheduler_pos_timeout_alive_to_uncertain_preserves_current_alive() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xA0);
    let holder_a = make_identity(0xA1);
    let holder_b = make_identity(0xA2);

    // Insert block with 2 alive holders.
    db.upsert_source_block(&make_block_for_hook(block_id, 2, 0.9)).unwrap();

    // Two Alive placements with consecutive_misses=0 (Timeout → Uncertain at miss=1).
    let mut p_a = make_placement(block_id, holder_a);
    p_a.consecutive_misses = 0;
    db.upsert_placement(&p_a).unwrap();

    let p_b = make_placement(block_id, holder_b);
    db.upsert_placement(&p_b).unwrap();

    let pending = make_pending_challenges();
    {
        let mut guard = pending.lock().await;
        // Only holder_a times out.
        guard.insert(
            (block_id, holder_a),
            PendingHashChallenge {
                source_block_id: block_id,
                holder_id: holder_a,
                esi_ranges: vec![(0, 4)],
                expected_chain_hash: [0u8; 32],
                issued_at: Timestamp(0), // ancient → timed out
                challenge_id: [0xA0u8; 16],
            },
        );
    }

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let scheduler = make_scheduler_for_hook(db.clone(), repair_tx, pending);

    scheduler.check_timeouts().await.unwrap();

    // holder_a: Alive → Uncertain (1 miss); current_alive should remain 2 (Uncertain counts).
    let placement_a = db.get_placement(&block_id, &holder_a).unwrap().unwrap();
    assert_eq!(placement_a.status, PlacementStatus::Uncertain, "holder_a must become Uncertain");

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive,
        2,
        "current_alive must remain 2 after Alive→Uncertain (Uncertain still counts)"
    );
}

/// Scheduler timeout: Uncertain→PresumedLost decrements current_alive.
///
/// PresumedLost does NOT count as alive, so count should drop.
#[tokio::test]
async fn scheduler_pos_timeout_uncertain_to_presumed_lost_decrements_current_alive() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xB0);
    let holder_a = make_identity(0xB1);
    let holder_b = make_identity(0xB2);

    // Insert block with 2 alive holders.
    db.upsert_source_block(&make_block_for_hook(block_id, 2, 0.9)).unwrap();

    // holder_a at consecutive_misses = POS_CONSECUTIVE_MISS_PRESUMED_LOST - 1
    // so one more Timeout → PresumedLost.
    let presumed_threshold = syncback_core::constants::POS_CONSECUTIVE_MISS_PRESUMED_LOST;
    let mut p_a = make_placement(block_id, holder_a);
    p_a.status = PlacementStatus::Uncertain;
    p_a.consecutive_misses = presumed_threshold.saturating_sub(1);
    db.upsert_placement(&p_a).unwrap();

    let p_b = make_placement(block_id, holder_b); // stays Alive
    db.upsert_placement(&p_b).unwrap();

    let pending = make_pending_challenges();
    {
        let mut guard = pending.lock().await;
        guard.insert(
            (block_id, holder_a),
            PendingHashChallenge {
                source_block_id: block_id,
                holder_id: holder_a,
                esi_ranges: vec![(0, 4)],
                expected_chain_hash: [0u8; 32],
                issued_at: Timestamp(0), // ancient → timed out
                challenge_id: [0xB0u8; 16],
            },
        );
    }

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let scheduler = make_scheduler_for_hook(db.clone(), repair_tx, pending);

    // Establish baseline by computing reliability from the actual 2-holder state
    // (1 Alive + 1 Uncertain both count toward current_alive).
    crate::daemon::processor::recompute_and_persist_block_cached_fields(&db, &block_id);
    let reliability_before = db
        .get_source_block(&block_id)
        .unwrap()
        .unwrap()
        .current_reliability;

    scheduler.check_timeouts().await.unwrap();

    // holder_a: Uncertain → PresumedLost; current_alive must drop from 2 → 1.
    let placement_a = db.get_placement(&block_id, &holder_a).unwrap().unwrap();
    assert_eq!(
        placement_a.status,
        PlacementStatus::PresumedLost,
        "holder_a must become PresumedLost after threshold misses"
    );

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive,
        1,
        "current_alive must be 1 after Uncertain→PresumedLost (PresumedLost not counted)"
    );

    // Directional: dropping a holder must not increase reliability.
    // Strict-less when both holders contribute non-trivial survival mass; equality only
    // possible in degenerate case where the dropped holder added zero independent mass.
    assert!(
        updated_block.current_reliability <= reliability_before,
        "reliability must not increase after holder loss (before={reliability_before}, after={after})",
        after = updated_block.current_reliability,
    );
    assert!(
        (0.0..=1.0).contains(&updated_block.current_reliability),
        "current_reliability must be in [0.0, 1.0], got {}",
        updated_block.current_reliability
    );
}

// ─── Stub network helper ──────────────────────────────────────────────────────
