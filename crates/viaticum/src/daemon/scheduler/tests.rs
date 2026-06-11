// Tests for the Scheduler module.
//
// Strategy: test issue_due_challenges() and check_timeouts() directly
// (not the run() loop) to avoid real timers and network connections.
// The PendingChallenges map is used as the primary observable output.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};
use viaticum_core::db::Db;
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
};
use viaticum_core::types::{
    DeviceId, FileId, IdentityPub, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp,
};

use viaticum_core::erasure::RaptorQEncoder;

use crate::daemon::mailbox::routing::{MailboxNetworkSender, MailboxRouter};
use crate::daemon::repair::RepairTrigger;
use crate::daemon::scheduler::{
    PendingChallenges, PendingHashChallenge, Scheduler, SchedulerConfig,
};

// ─── Test helpers ─────────────────────────────────────────────────────────────

/// No-op mailbox sender for scheduler tests that do not exercise mailbox delivery.
struct NoOpMailboxSender;

#[async_trait::async_trait]
impl MailboxNetworkSender for NoOpMailboxSender {
    async fn send_store(
        &self,
        _device: DeviceId,
        _req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        // Simulate 0 acks: always returns an error so scheduler treats as undelivered.
        anyhow::bail!("no-op sender: no network in tests")
    }
    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        anyhow::bail!("no-op sender: no network in tests")
    }
}

fn make_test_router(db: &Db) -> Arc<MailboxRouter> {
    Arc::new(MailboxRouter::with_sender(
        Arc::new(NoOpMailboxSender),
        db.clone(),
    ))
}

fn dummy_master_pub() -> IdentityPub {
    IdentityPub([0u8; 32])
}

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

fn make_test_encoder() -> std::sync::Arc<dyn viaticum_core::erasure::ErasureEncoder> {
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
        time_scale: 1, // real-time scale, threshold = POS_CHALLENGE_PENDING_TIMEOUT_SECS
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };

    // We need a NetworkHandle for the constructor. Build a no-op one via a stub.
    // Since check_timeouts doesn't use network, we pass a real (but unused) handle.
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending.clone(),
        make_test_router(&db),
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    scheduler.check_timeouts().await.expect("check_timeouts");

    // Pending map should be empty now.
    assert!(
        pending.lock().await.is_empty(),
        "pending map should be cleared after timeout processing"
    );

    // A repair wake should have been sent (3 misses → PresumedLost → trigger_repair=true).
    let trigger = repair_rx.try_recv().expect("repair trigger should be sent");
    assert!(
        matches!(trigger, RepairTrigger::Wake),
        "expected RepairTrigger::Wake, got {trigger:?}"
    );

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
        time_scale: 1, // POS_CHALLENGE_PENDING_TIMEOUT_SECS ≈ 1_213_200 s — fresh challenge won't expire
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let test_router = make_test_router(&db);
    let scheduler = Scheduler::new(
        db,
        config,
        repair_tx,
        pending.clone(),
        test_router,
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

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

    // time_scale = POS_CHALLENGE_PENDING_TIMEOUT_SECS so threshold = 1 second.
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
        time_scale: viaticum_core::constants::POS_CHALLENGE_PENDING_TIMEOUT_SECS, // threshold = 1 second
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending.clone(),
        make_test_router(&db),
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

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
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let test_router = make_test_router(&db);
    let scheduler = Scheduler::new(
        db,
        config,
        repair_tx,
        pending.clone(),
        test_router,
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    // issue_due_challenges should skip this holder because it's already pending.
    // The existing pending entry's esi_ranges should not be overwritten.
    scheduler
        .issue_due_challenges()
        .await
        .expect("issue_due_challenges");

    let guard = pending.lock().await;
    assert_eq!(guard.len(), 1, "only the pre-existing entry should remain");
    let entry = guard.get(&(block_id, holder_id)).expect("entry present");
    assert_eq!(
        entry.esi_ranges,
        vec![(5, 1)],
        "existing pending entry esi_ranges unchanged"
    );
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
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let test_router = make_test_router(&db);
    let scheduler = Scheduler::new(
        db,
        config,
        repair_tx,
        pending.clone(),
        test_router,
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    scheduler
        .issue_due_challenges()
        .await
        .expect("issue_due_challenges");

    // Pending map must remain empty: Deleting placement was filtered out.
    assert!(
        pending.lock().await.is_empty(),
        "Deleting placement must not generate a pending challenge"
    );
}

// ─── SCHED-08: time_scale_divides_intervals ───────────────────────────────────

/// With time_scale=N, the timeout threshold is divided by N.
/// A challenge issued `POS_CHALLENGE_PENDING_TIMEOUT_SECS / N + 1` seconds ago
/// must be treated as timed out when time_scale=N, but the same challenge would
/// NOT be timed out with time_scale=1 (which needs ~14 days + 2h).
#[tokio::test]
async fn time_scale_divides_intervals() {
    use viaticum_core::constants::POS_CHALLENGE_PENDING_TIMEOUT_SECS;

    let db = Db::open_in_memory().expect("db open");
    let block_id = make_block_id(60);
    let holder_id = make_identity(61);

    let mut placement = make_placement(block_id, holder_id);
    placement.consecutive_misses = 0;
    db.upsert_placement(&placement).expect("upsert");

    let pending = make_pending_challenges();
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);

    // time_scale = POS_CHALLENGE_PENDING_TIMEOUT_SECS means threshold = 1 second.
    // Issue challenge 5 seconds in the past — clearly timed out at threshold=1s.
    let scale = POS_CHALLENGE_PENDING_TIMEOUT_SECS;
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
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending.clone(),
        make_test_router(&db),
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    scheduler.check_timeouts().await.expect("check_timeouts");

    // With time_scale=POS_CHALLENGE_PENDING_TIMEOUT_SECS, threshold = 1 second.
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
/// process_deletion_tick publishes DeleteMsg via mailbox (T-13b-1) — NOT relay —
/// and marks placement Deleting.
///
/// Acceptance: delete_published_via_mailbox_not_relay
#[tokio::test]
async fn deletion_tick_sends_drop_notice_and_marks_placement_deleting() {
    use viaticum_core::mailbox::{DeleteRequestPayload, MailboxClass};
    use viaticum_core::types::{
        DeviceId, FileRecord, FileVersion, LocalState, SourceBlockRecord, SourceBlockStatus,
        SourceBlockType,
    };

    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xD1);
    // Use a real Ed25519 key so device_id_to_peer_id succeeds and mailbox publish
    // actually tries candidates (same pattern as scheduler_issues_challenge_via_mailbox_not_relay).
    let holder_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xA2u8; 32]);
    let holder_id = DeviceId(holder_signing_key.verifying_key().to_bytes());
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
    };
    db.upsert_source_block(&sb).unwrap();

    // Placement: Alive.
    let placement = make_placement(block_id, holder_id);
    db.upsert_placement(&placement).unwrap();

    // Peer record (needed for trust lookup in due_challenges, also for deletion signing).
    let peer = make_peer_record(holder_id);
    db.upsert_peer(&peer).unwrap();

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    // T-13b-1: use RecordingMailboxSender to capture mailbox publishes.
    let recording_sender = Arc::new(RecordingMailboxSender::new());
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::clone(&recording_sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let pending = make_pending_challenges();
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending,
        router,
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    // Now = after owner cooldown. Deleted_at=0, cooldown=4 weeks.
    // process_deletion_tick uses Timestamp::now() internally. Since deleted_at=0,
    // any now > OWNER_DELETE_COOLDOWN_SECS will trigger.
    scheduler.process_deletion_tick().await.unwrap();

    // T-13b-1 acceptance: Must have published via mailbox with class = DeleteRequest.
    let captured = recording_sender.captured_requests();
    assert!(
        !captured.is_empty(),
        "delete_published_via_mailbox_not_relay: expected ≥1 MailboxStoreRequest to be captured"
    );
    let delete_req = captured
        .iter()
        .find(|r| r.entry.class == MailboxClass::DeleteRequest)
        .expect("expected a DeleteRequest-class mailbox entry");

    // Target = holder master (falls back to IdentityPub(holder_id.0) when no master mapping).
    assert_eq!(
        delete_req.entry.target,
        viaticum_core::types::IdentityPub(holder_id.0),
        "delete_published_via_mailbox_not_relay: entry target must be holder master"
    );

    // Sender = owner master (my_master_pub passed to scheduler).
    assert_eq!(
        delete_req.entry.sender,
        Some(dummy_master_pub()),
        "delete_published_via_mailbox_not_relay: entry sender must be owner master"
    );

    // Payload must decode as DeleteRequestPayload::Delete.
    let payload: DeleteRequestPayload =
        viaticum_core::types::from_cbor_bytes(&delete_req.entry.payload)
            .expect("payload must be valid DeleteRequestPayload CBOR");
    assert!(
        matches!(payload, DeleteRequestPayload::Delete(_)),
        "delete_published_via_mailbox_not_relay: payload kind must be Delete, got {payload:?}"
    );

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
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let pending = make_pending_challenges();
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let test_router = make_test_router(&db);
    let scheduler = Scheduler::new(
        db,
        config,
        repair_tx,
        pending,
        test_router,
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    scheduler.process_deletion_tick().await.unwrap();

    // No messages should be posted.
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
    let pending = make_pending_challenges();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    // Threshold = LONG_ABSENCE_SECS = 14 days.
    // placed_at = 0 means age = now >> 14 days → must become Lost.
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending,
        make_test_router(&db),
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
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

    // repair_tx should have received a repair wake.
    let trigger = repair_rx.try_recv().expect("repair trigger must be sent");
    assert!(
        matches!(trigger, RepairTrigger::Wake),
        "expected RepairTrigger::Wake, got {trigger:?}"
    );
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
    let pending = make_pending_challenges();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending,
        make_test_router(&db),
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
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

// ─── D3: per-(block,holder) delete dedup tests ───────────────────────────────

/// H3 rework of the former per-BLOCK dedup test. The dedup is now per-(block,
/// holder): once a holder's placement is Deleting (it acked on the first tick),
/// the engine no longer emits SendDropNotice for it, so the scheduler does NOT
/// re-publish to that holder on later ticks. (The old test asserted a per-block
/// `drop_notice_sent_at` gate; that gate was the H3 bug and has been removed.)
#[tokio::test]
async fn already_deleting_holder_is_not_republished() {
    use viaticum_core::types::{
        DeviceId, FileRecord, FileVersion, LocalState, SourceBlockRecord, SourceBlockStatus,
        SourceBlockType,
    };

    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xE1);
    // Real Ed25519 key so device_id_to_peer_id succeeds and the Ack-returning sender
    // is actually reached (delivery gated on ≥1 ack).
    let holder_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xE2u8; 32]);
    let holder_id = DeviceId(holder_signing_key.verifying_key().to_bytes());
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

    // Source block: Active.
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
    };
    db.upsert_source_block(&sb).unwrap();

    // Placement: Alive.
    let placement = make_placement(block_id, holder_id);
    db.upsert_placement(&placement).unwrap();

    // Peer record.
    db.upsert_peer(&make_peer_record(holder_id)).unwrap();

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let pending = make_pending_challenges();
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    // Ack-returning recording sender: first tick delivers (≥1 ack) → state advances.
    let recording_sender = Arc::new(RecordingMailboxSender::new());
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::clone(&recording_sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending,
        router,
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    // First tick: should publish a DeleteRequest via mailbox (Ack → placement → Deleting).
    scheduler.process_deletion_tick().await.unwrap();

    // The holder's placement must now be Deleting and the block promoted to Deleting.
    let updated_p = db.get_placement(&block_id, &holder_id).unwrap().unwrap();
    assert_eq!(
        updated_p.status,
        PlacementStatus::Deleting,
        "holder placement must transition to Deleting after a successful publish"
    );
    let updated_sb = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_sb.status,
        SourceBlockStatus::Deleting,
        "source block must be promoted to Deleting after the first holder acks"
    );
    let publishes_after_first = recording_sender
        .captured_requests()
        .iter()
        .filter(|r| r.entry.class == viaticum_core::mailbox::MailboxClass::DeleteRequest)
        .count();
    assert_eq!(
        publishes_after_first, 1,
        "exactly one DeleteRequest publish on the first tick"
    );

    // Second tick: the (single) holder is already Deleting, so the engine emits no
    // SendDropNotice for it → no additional publish (per-(block,holder) dedup).
    scheduler.process_deletion_tick().await.unwrap();
    let publishes_after_second = recording_sender
        .captured_requests()
        .iter()
        .filter(|r| r.entry.class == viaticum_core::mailbox::MailboxClass::DeleteRequest)
        .count();
    assert_eq!(
        publishes_after_second, 1,
        "an already-Deleting placement must not be re-published"
    );
}

// ─── H3: multi-holder deletion reaches every holder ──────────────────────────

/// Recording sender that returns Ack for every target EXCEPT those in `fail_targets`
/// (for which it records the request but returns an Err → 0 acks). Used to assert
/// per-holder retry: the unacked holder stays Active and is re-attempted next tick.
struct SelectiveMailboxSender {
    captured: std::sync::Mutex<Vec<viaticum_core::messages::MailboxStoreRequest>>,
    fail_targets: std::sync::Mutex<std::collections::HashSet<IdentityPub>>,
}

impl SelectiveMailboxSender {
    fn new() -> Self {
        SelectiveMailboxSender {
            captured: std::sync::Mutex::new(Vec::new()),
            fail_targets: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    fn fail_for(&self, target: IdentityPub) {
        self.fail_targets.lock().unwrap().insert(target);
    }

    fn captured_requests(&self) -> Vec<viaticum_core::messages::MailboxStoreRequest> {
        self.captured.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl MailboxNetworkSender for SelectiveMailboxSender {
    async fn send_store(
        &self,
        _device: DeviceId,
        req: viaticum_core::messages::MailboxStoreRequest,
    ) -> anyhow::Result<viaticum_core::messages::MailboxStoreResponse> {
        let target = req.entry.target;
        let msg_id = req.entry.msg_id;
        self.captured.lock().unwrap().push(req);
        if self.fail_targets.lock().unwrap().contains(&target) {
            anyhow::bail!("selective sender: simulated 0-ack for target {target}")
        }
        Ok(viaticum_core::messages::MailboxStoreResponse::Ack { msg_id })
    }
    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        anyhow::bail!("selective sender: fetch not used")
    }
}

/// Make a holder identity backed by a REAL Ed25519 key (so device_id_to_peer_id
/// succeeds and the holder is a usable mailbox candidate) plus its peer record.
fn make_real_holder(seed: u8) -> (DeviceId, IdentityPub) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let device_id = DeviceId(sk.verifying_key().to_bytes());
    let master = IdentityPub(device_id.0);
    (device_id, master)
}

fn make_multi_holder_file(
    fid: FileId,
    block_id: SourceBlockId,
) -> viaticum_core::types::FileRecord {
    use viaticum_core::types::{FileRecord, FileVersion, LocalState};
    let owner_device = DeviceId([0x01; 32]);
    FileRecord {
        file_id: fid,
        path: "multi_holder_delete.txt".to_string(),
        importance: 0.5,
        devices: vec![(owner_device, LocalState::Deleted(Timestamp(0)))],
        versions: vec![FileVersion {
            content_hash: [0; 32],
            source_block_id: block_id,
            k: 10,
            t: 65535,
            created_at: Timestamp(0),
            backed_up_at: Some(Timestamp(0)),
        }],
        first_seen: Timestamp(0),
    }
}

fn make_active_block(block_id: SourceBlockId) -> viaticum_core::types::SourceBlockRecord {
    use viaticum_core::types::{SourceBlockRecord, SourceBlockStatus, SourceBlockType};
    SourceBlockRecord {
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
    }
}

fn make_deletion_scheduler(
    db: &Db,
    router: Arc<MailboxRouter>,
) -> (Scheduler, mpsc::Receiver<RepairTrigger>) {
    let (repair_tx, repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let pending = make_pending_challenges();
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending,
        router,
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );
    (scheduler, repair_rx)
}

/// H3 core: a multi-holder block's Delete must reach EVERY holder's master, and
/// all placements must transition to Deleting. (Fails on the old per-block
/// `drop_notice_sent_at` gate, which delivered to only the first holder.)
#[tokio::test]
async fn delete_sent_to_every_holder_of_multi_holder_block() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xA0);
    let fid = FileId(701);

    db.upsert_file(&make_multi_holder_file(fid, block_id))
        .unwrap();
    db.upsert_source_block(&make_active_block(block_id))
        .unwrap();

    // Three holders, each a real Ed25519 identity → distinct master targets.
    let holders = [
        make_real_holder(0xB1),
        make_real_holder(0xB2),
        make_real_holder(0xB3),
    ];
    for (device_id, _master) in &holders {
        let mut p = make_placement(block_id, *device_id);
        p.file_id = fid;
        db.upsert_placement(&p).unwrap();
        db.upsert_peer(&make_peer_record(*device_id)).unwrap();
    }

    let recording_sender = Arc::new(RecordingMailboxSender::new());
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::clone(&recording_sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));
    let (scheduler, _repair_rx) = make_deletion_scheduler(&db, router);

    scheduler.process_deletion_tick().await.unwrap();

    // Every holder master must have received a DeleteRequest.
    let delete_targets: std::collections::HashSet<IdentityPub> = recording_sender
        .captured_requests()
        .iter()
        .filter(|r| r.entry.class == viaticum_core::mailbox::MailboxClass::DeleteRequest)
        .map(|r| r.entry.target)
        .collect();
    for (_device_id, master) in &holders {
        assert!(
            delete_targets.contains(master),
            "DeleteRequest must be published to holder master {master}"
        );
    }
    assert_eq!(
        delete_targets.len(),
        holders.len(),
        "DeleteRequest must reach exactly the {} holder masters, got {:?}",
        holders.len(),
        delete_targets
    );

    // All placements must now be Deleting.
    for (device_id, _master) in &holders {
        let p = db.get_placement(&block_id, device_id).unwrap().unwrap();
        assert_eq!(
            p.status,
            PlacementStatus::Deleting,
            "every holder placement must transition to Deleting"
        );
    }
}

/// H3 per-holder retry: if one holder's publish gets 0 acks, only that holder stays
/// Active and is re-attempted on the next tick; the acked holders go Deleting and
/// are NOT re-published.
#[tokio::test]
async fn multi_holder_delete_retries_only_unacked_holder() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xA5);
    let fid = FileId(702);

    db.upsert_file(&make_multi_holder_file(fid, block_id))
        .unwrap();
    db.upsert_source_block(&make_active_block(block_id))
        .unwrap();

    let holders = [
        make_real_holder(0xC1),
        make_real_holder(0xC2),
        make_real_holder(0xC3),
    ];
    for (device_id, _master) in &holders {
        let mut p = make_placement(block_id, *device_id);
        p.file_id = fid;
        db.upsert_placement(&p).unwrap();
        db.upsert_peer(&make_peer_record(*device_id)).unwrap();
    }

    // Holder n (last) will 0-ack.
    let (failing_device, failing_master) = holders[holders.len() - 1];
    let sender = Arc::new(SelectiveMailboxSender::new());
    sender.fail_for(failing_master);
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));
    let (scheduler, _repair_rx) = make_deletion_scheduler(&db, router);

    // First tick: holders 1..n-1 ack → Deleting; holder n 0-acks → stays Alive.
    scheduler.process_deletion_tick().await.unwrap();

    for (device_id, _master) in &holders[..holders.len() - 1] {
        let p = db.get_placement(&block_id, device_id).unwrap().unwrap();
        assert_eq!(
            p.status,
            PlacementStatus::Deleting,
            "acked holder must be Deleting after first tick"
        );
    }
    let failing_p = db
        .get_placement(&block_id, &failing_device)
        .unwrap()
        .unwrap();
    assert_eq!(
        failing_p.status,
        PlacementStatus::Alive,
        "unacked holder must stay Alive after first tick"
    );

    // Capture the per-target publish counts after the first tick.
    let publishes_to = |s: &SelectiveMailboxSender, target: IdentityPub| -> usize {
        s.captured_requests()
            .iter()
            .filter(|r| {
                r.entry.class == viaticum_core::mailbox::MailboxClass::DeleteRequest
                    && r.entry.target == target
            })
            .count()
    };
    let failing_publishes_first = publishes_to(&sender, failing_master);
    let acked_publishes_first: Vec<usize> = holders[..holders.len() - 1]
        .iter()
        .map(|(_d, m)| publishes_to(&sender, *m))
        .collect();
    assert!(
        failing_publishes_first >= 1,
        "failing holder must have been published to on the first tick"
    );

    // Second tick: only the unacked holder is re-attempted (engine no longer emits
    // for the Deleting holders).
    scheduler.process_deletion_tick().await.unwrap();

    assert!(
        publishes_to(&sender, failing_master) > failing_publishes_first,
        "the unacked holder must be re-published on the second tick"
    );
    for ((_device_id, master), first_count) in holders[..holders.len() - 1]
        .iter()
        .zip(acked_publishes_first.iter())
    {
        assert_eq!(
            publishes_to(&sender, *master),
            *first_count,
            "an already-Deleting holder must NOT be re-published"
        );
    }
}

/// H3 completion: once all placements are Deleting, after the holder cooldown the
/// engine emits CleanupPlacement for each and then CleanupBlock — proving the block
/// is no longer stuck. This asserts the engine ACTIONS (CleanupPlacement ×n then
/// CleanupBlock); actual row removal by the scheduler arm is covered by
/// `cleanup_block_removes_db_record`.
#[tokio::test]
async fn multi_holder_block_reaches_cleanup_when_all_holders_deleting() {
    use viaticum_core::constants::{HOLDER_DELETE_COOLDOWN_SECS, OWNER_DELETE_COOLDOWN_SECS};
    use viaticum_core::deletion::{DeletionAction, DeletionEngine};
    use viaticum_core::types::{SourceBlockStatus, SourceBlockType};

    // Drive the engine directly with all placements already Deleting and the block
    // Deleting; advance now past owner + holder cooldown.
    let engine = DeletionEngine::new();
    let block_id = make_block_id(0xA9);
    let fid = FileId(703);

    let mut block = make_active_block(block_id);
    block.block_type = SourceBlockType::Single;
    block.status = SourceBlockStatus::Deleting;

    let holders = [
        make_real_holder(0xD1),
        make_real_holder(0xD2),
        make_real_holder(0xD3),
    ];
    let placements: Vec<SymbolPlacement> = holders
        .iter()
        .map(|(device_id, _master)| {
            let mut p = make_placement(block_id, *device_id);
            p.file_id = fid;
            p.status = PlacementStatus::Deleting;
            p
        })
        .collect();

    let file = make_multi_holder_file(fid, block_id);
    let now = Timestamp(OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS);

    let actions = engine.process_cooldowns(&[file], &[block], &placements, now, 1);

    // CleanupPlacement for every holder.
    for (device_id, _master) in &holders {
        assert!(
            actions.contains(&DeletionAction::CleanupPlacement {
                source_block_id: block_id,
                holder_id: *device_id,
            }),
            "CleanupPlacement must be emitted for every holder"
        );
    }
    // CleanupBlock fires (block not stuck).
    assert!(
        actions.contains(&DeletionAction::CleanupBlock {
            source_block_id: block_id,
            file_id: fid,
        }),
        "CleanupBlock must fire once all holders are Deleting and cooldown elapsed"
    );
}

/// H3 retry-dedup: two publishes of the same (block, holder) Delete must use the
/// same stable msg_id so candidate postmen dedup re-stores as Duplicate.
#[tokio::test]
async fn delete_republish_uses_stable_msg_id_for_dedup() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xAB);
    let fid = FileId(704);

    db.upsert_file(&make_multi_holder_file(fid, block_id))
        .unwrap();
    db.upsert_source_block(&make_active_block(block_id))
        .unwrap();

    // Single holder that always 0-acks → block stays eligible, scheduler re-publishes.
    let (device_id, master) = make_real_holder(0xE5);
    let mut p = make_placement(block_id, device_id);
    p.file_id = fid;
    db.upsert_placement(&p).unwrap();
    db.upsert_peer(&make_peer_record(device_id)).unwrap();

    let sender = Arc::new(SelectiveMailboxSender::new());
    sender.fail_for(master); // force re-publish across ticks
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));
    let (scheduler, _repair_rx) = make_deletion_scheduler(&db, router);

    scheduler.process_deletion_tick().await.unwrap();
    scheduler.process_deletion_tick().await.unwrap();

    let msg_ids: std::collections::HashSet<[u8; 16]> = sender
        .captured_requests()
        .iter()
        .filter(|r| {
            r.entry.class == viaticum_core::mailbox::MailboxClass::DeleteRequest
                && r.entry.target == master
        })
        .map(|r| r.entry.msg_id)
        .collect();
    assert!(
        !msg_ids.is_empty(),
        "expected ≥1 DeleteRequest publish to the holder"
    );
    assert_eq!(
        msg_ids.len(),
        1,
        "all re-publishes of the same (block, holder) Delete must share one stable msg_id, got {msg_ids:?}"
    );
}

/// Counting mailbox sender that records every send_store attempt and always fails
/// (0 acks). Used to assert the ack-gate retry path: the scheduler must re-attempt
/// the publish on a subsequent tick when delivery failed.
struct CountingFailMailboxSender {
    store_attempts: std::sync::atomic::AtomicUsize,
}

impl CountingFailMailboxSender {
    fn new() -> Self {
        CountingFailMailboxSender {
            store_attempts: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn attempts(&self) -> usize {
        self.store_attempts
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl MailboxNetworkSender for CountingFailMailboxSender {
    async fn send_store(
        &self,
        _device: DeviceId,
        _req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        self.store_attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        anyhow::bail!("counting-fail sender: simulated undelivered store (0 acks)")
    }
    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        anyhow::bail!("counting-fail sender: fetch not used")
    }
}

/// T-13 H1(a) regression: when the DeleteMsg publish yields 0 acks, the scheduler
/// must NOT mark the block as "drop notice sent" and must NOT transition
/// placement/source_block to Deleting — otherwise the dedup gate skips the block
/// forever and the owner's erasure request is silently lost. The block must remain
/// eligible so a subsequent tick re-attempts delivery (natural retry).
#[tokio::test]
async fn delete_not_marked_sent_when_publish_zero_acks() {
    use viaticum_core::types::{
        DeviceId, FileRecord, FileVersion, LocalState, SourceBlockRecord, SourceBlockStatus,
        SourceBlockType,
    };

    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xF3);
    // Real Ed25519 key so device_id_to_peer_id yields a candidate and publish
    // actually attempts a send_store (which the counting sender fails → 0 acks).
    let holder_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xF4u8; 32]);
    let holder_id = DeviceId(holder_signing_key.verifying_key().to_bytes());
    let device_id = DeviceId([0x01; 32]);

    let file = FileRecord {
        file_id: FileId(303),
        path: "zero_acks.txt".to_string(),
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
    };
    db.upsert_source_block(&sb).unwrap();

    let placement = make_placement(block_id, holder_id);
    db.upsert_placement(&placement).unwrap();

    let peer = make_peer_record(holder_id);
    db.upsert_peer(&peer).unwrap();

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let counting_sender = Arc::new(CountingFailMailboxSender::new());
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::clone(&counting_sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let pending = make_pending_challenges();
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending,
        router,
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    // First tick: publish fails (0 acks).
    scheduler.process_deletion_tick().await.unwrap();
    assert!(
        counting_sender.attempts() >= 1,
        "first tick must attempt to publish the DeleteMsg"
    );

    // State must NOT have advanced — block stays eligible for retry.
    let sb_after = db.get_source_block(&block_id).unwrap().unwrap();
    assert!(
        sb_after.drop_notice_sent_at.is_none(),
        "drop_notice_sent_at must stay None when publish got 0 acks"
    );
    assert_eq!(
        sb_after.status,
        SourceBlockStatus::Active,
        "source block must stay Active (not transitioned to Deleting) on 0 acks"
    );
    let placement_after = db.get_placement(&block_id, &holder_id).unwrap().unwrap();
    assert_eq!(
        placement_after.status,
        PlacementStatus::Alive,
        "placement must stay Alive (not Deleting) on 0 acks"
    );

    // Second tick: the block is still eligible, so the scheduler must re-attempt.
    let attempts_before_second = counting_sender.attempts();
    scheduler.process_deletion_tick().await.unwrap();
    assert!(
        counting_sender.attempts() > attempts_before_second,
        "second tick must re-attempt publish (block not skipped by dedup gate after 0-ack failure)"
    );
    // Still not advanced (still 0 acks).
    let sb_after2 = db.get_source_block(&block_id).unwrap().unwrap();
    assert!(
        sb_after2.drop_notice_sent_at.is_none(),
        "drop_notice_sent_at must remain None across repeated 0-ack ticks"
    );
}

// ─── D4: cleanup_block_removes_db_record ─────────────────────────────────────

/// PL-6: CleanupBlock removes the source block + file version from the DB.
///
/// Post-Wave-11b there are no owner-side symbol files on disk to remove — the
/// pipeline persists nothing, so `{source_blocks_dir}/{block_hex}` is never created
/// and the old disk-cleanup was a dead no-op. The remaining observable effect of
/// CleanupBlock is the DB row removal.
///
/// Setup:
///   - File: single device, deleted_at = 0 (well past owner + holder cooldowns).
///   - Source block: Deleting.
///   - Placement: Deleting.
///
/// After process_deletion_tick the source block record must be gone from the DB.
#[tokio::test]
async fn cleanup_block_removes_db_record() {
    use viaticum_core::types::DeviceId;

    let db = Db::open_in_memory().unwrap();
    let data_dir = tempfile::TempDir::new().expect("tempdir");

    let block_id = make_block_id(0xC1);
    let holder_id = make_identity(0xC2);
    let device_id = DeviceId([0xC3u8; 32]);

    // File: single device, fully deleted at time 0.
    let file = viaticum_core::types::FileRecord {
        file_id: FileId(200),
        path: "cleanup_test.bin".to_string(),
        importance: 0.5,
        devices: vec![(
            device_id,
            viaticum_core::types::LocalState::Deleted(Timestamp(0)),
        )],
        versions: vec![viaticum_core::types::FileVersion {
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
    let sb = viaticum_core::types::SourceBlockRecord {
        block_id,
        k: 10,
        t: 65535,
        block_type: viaticum_core::types::SourceBlockType::Single,
        status: viaticum_core::types::SourceBlockStatus::Deleting,
        created_at: Timestamp(0),
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: Some(Timestamp(0)), // already sent, skip SendDropNotice
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
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

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let pending = make_pending_challenges();
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending,
        make_test_router(&db),
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        data_dir.path().to_path_buf(),
    );

    scheduler.process_deletion_tick().await.unwrap();

    // Source block record must be gone from DB.
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
) -> viaticum_core::types::SourceBlockRecord {
    viaticum_core::types::SourceBlockRecord {
        block_id,
        k: 5,
        t: 1,
        block_type: viaticum_core::types::SourceBlockType::Single,
        status: viaticum_core::types::SourceBlockStatus::Active,
        created_at: Timestamp(0),
        encrypted_size: Some(5),
        n: Some(20),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 0.5,
        current_alive,
        current_reliability,
        target_reliability: 0.99,
    }
}

fn make_scheduler_for_hook(
    db: Db,
    repair_tx: mpsc::Sender<RepairTrigger>,
    pending: PendingChallenges,
) -> Scheduler {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let router = make_test_router(&db);
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    Scheduler::new(
        db,
        config,
        repair_tx,
        pending,
        router,
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
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
    db.upsert_source_block(&make_block_for_hook(block_id, 2, 0.9))
        .unwrap();

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
    assert_eq!(
        placement_a.status,
        PlacementStatus::Uncertain,
        "holder_a must become Uncertain"
    );

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 2,
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
    db.upsert_source_block(&make_block_for_hook(block_id, 2, 0.9))
        .unwrap();

    // holder_a at consecutive_misses = POS_CONSECUTIVE_MISS_PRESUMED_LOST - 1
    // so one more Timeout → PresumedLost.
    let presumed_threshold = viaticum_core::constants::POS_CONSECUTIVE_MISS_PRESUMED_LOST;
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
        updated_block.current_alive, 1,
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

// ─── T-6 spec-required scenarios ─────────────────────────────────────────────

/// Recording mailbox sender: records every MailboxStoreRequest it receives
/// and returns Ack for each. Used to verify scheduler publishes to mailbox.
struct RecordingMailboxSender {
    captured: std::sync::Mutex<Vec<viaticum_core::messages::MailboxStoreRequest>>,
}

impl RecordingMailboxSender {
    fn new() -> Self {
        RecordingMailboxSender {
            captured: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn captured_requests(&self) -> Vec<viaticum_core::messages::MailboxStoreRequest> {
        self.captured.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl MailboxNetworkSender for RecordingMailboxSender {
    async fn send_store(
        &self,
        _device: DeviceId,
        req: viaticum_core::messages::MailboxStoreRequest,
    ) -> anyhow::Result<viaticum_core::messages::MailboxStoreResponse> {
        let msg_id = req.entry.msg_id;
        self.captured.lock().unwrap().push(req);
        Ok(viaticum_core::messages::MailboxStoreResponse::Ack { msg_id })
    }
    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        anyhow::bail!("recording sender: fetch not used in store tests")
    }
}

/// Ack mailbox sender: always returns Ack. Used to verify W-3 gate when acks ARE received.
struct AckMailboxSender;

#[async_trait::async_trait]
impl MailboxNetworkSender for AckMailboxSender {
    async fn send_store(
        &self,
        _device: DeviceId,
        req: viaticum_core::messages::MailboxStoreRequest,
    ) -> anyhow::Result<viaticum_core::messages::MailboxStoreResponse> {
        Ok(viaticum_core::messages::MailboxStoreResponse::Ack {
            msg_id: req.entry.msg_id,
        })
    }
    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        anyhow::bail!("ack sender: fetch not used")
    }
}

// ─── Minimal source block setup for PoS hash tests ───────────────────────────
//
// To exercise issue_due_challenges() end-to-end we need:
//   1. A SourceBlockRecord with valid erasure params (k, t, n, overhead).
//   2. The block's source bytes available to `load_source_block_data`.
//   3. A SymbolPlacement for a holder with known ESI ranges.
//   4. A PeerRecord for the holder (so trust lookup doesn't panic).
//
// Minimal params: k=10, t=64 → block size = 640 bytes; k_eff=13, n=20, overhead=1.5.
//
// PL-6: the on-disk `block.bin` tier of `load_source_block_data` was removed. These
// tests now serve the block's bytes via the SystemState retained-blob tier
// (`<data_dir>/system_state/<hex>.bin`, verified blake3(blob) == block_id), which is a
// live tier. Because that tier is content-addressed, the block_id is DERIVED from the
// bytes (see `seed_retained_pos_block`) rather than an arbitrary `make_block_id`.

const TEST_K: u32 = 10;
const TEST_T: u16 = 64;

fn make_source_block_record(block_id: SourceBlockId) -> viaticum_core::types::SourceBlockRecord {
    use viaticum_core::types::{SourceBlockRecord, SourceBlockStatus, SourceBlockType};
    let k_eff = TEST_K + viaticum_core::constants::DECODE_OVERHEAD;
    let n = (k_eff as f64 * 1.5).ceil() as u32;
    SourceBlockRecord {
        block_id,
        k: TEST_K,
        t: TEST_T,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(0),
        encrypted_size: Some((TEST_K as u64) * (TEST_T as u64)),
        n: Some(n),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 0.5,
        current_alive: 1,
        current_reliability: 0.9,
        target_reliability: 0.99,
    }
}

/// Deterministic k*t-byte block body for PoS tests, seeded so different blocks differ.
fn pos_block_bytes(seed: u8) -> Vec<u8> {
    (0..(TEST_K as usize * TEST_T as usize))
        .map(|i| ((i.wrapping_add(seed as usize)) & 0xFF) as u8)
        .collect()
}

/// Seed a content-addressed source block for PoS tests: write the block bytes as a
/// retained blob under `data_dir` (the live tier `load_source_block_data` reads first)
/// and upsert a matching `SourceBlockRecord`. Returns the derived block_id.
///
/// Replaces the old `write_block_bin` (which exploited the now-removed on-disk
/// `block.bin` tier, hence could use arbitrary block_ids). The retained-blob tier
/// verifies blake3(blob) == block_id, so the id is derived from the bytes here.
fn seed_retained_pos_block(data_dir: &std::path::Path, db: &Db, seed: u8) -> SourceBlockId {
    let blob = pos_block_bytes(seed);
    let block_id = SourceBlockId(*blake3::hash(&blob).as_bytes());
    crate::daemon::system_state::block::store_retained_block(data_dir, &block_id, &blob)
        .expect("store retained block");
    db.upsert_source_block(&make_source_block_record(block_id))
        .expect("upsert source block");
    block_id
}

fn make_peer_record(holder_id: DeviceId) -> viaticum_core::types::PeerRecord {
    viaticum_core::types::PeerRecord {
        device_id: holder_id,
        master_identity: viaticum_core::types::IdentityPub(holder_id.0),
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
        avail_ewma: viaticum_core::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    }
}

// ─── T-6 test: challenge goes via mailbox, not relay ─────────────────────────

/// A due PoS challenge is published via MailboxRouter (the mailbox bus).
///
/// Asserts:
/// - At least one MailboxStoreRequest was captured by the recording sender.
/// - The captured entry has class == PosChallenge, sender == Some(owner master_pub).
/// - The payload decodes as a valid PosHashChallengeMsg.
#[tokio::test]
async fn scheduler_issues_challenge_via_mailbox_not_relay() {
    use viaticum_core::mailbox::MailboxClass;
    use viaticum_core::messages::PosHashChallengeMsg;
    use viaticum_core::types::from_cbor_bytes;

    let db = Db::open_in_memory().expect("db open");
    let data_dir = tempfile::TempDir::new().unwrap();
    let holder_id = make_identity(0xA2);

    // Insert source block record + retained blob + placement + peer.
    let block_id = seed_retained_pos_block(data_dir.path(), &db, 0xA1);

    let placement = make_placement(block_id, holder_id);
    db.upsert_placement(&placement).unwrap();
    db.upsert_peer(&make_peer_record(holder_id)).unwrap();

    let recording_sender = Arc::new(RecordingMailboxSender::new());
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::clone(&recording_sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let pending = make_pending_challenges();
    let my_master = dummy_master_pub();

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending.clone(),
        router,
        my_master,
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        data_dir.path().to_path_buf(),
    );

    scheduler
        .issue_due_challenges()
        .await
        .expect("issue_due_challenges");

    // At least one store request must have been sent via the mailbox sender.
    let requests = recording_sender.captured_requests();
    assert!(
        !requests.is_empty(),
        "expected at least one MailboxStoreRequest to be sent for the due challenge"
    );

    // Find the PosChallenge entry.
    let pos_req = requests
        .iter()
        .find(|r| r.entry.class == MailboxClass::PosChallenge)
        .expect("expected a PosChallenge entry in captured requests");

    // Entry target = holder's master (which is IdentityPub(holder_id.0) since no device cert in DB).
    assert_eq!(
        pos_req.entry.target,
        viaticum_core::types::IdentityPub(holder_id.0),
        "PosChallenge entry target must be holder's master pub"
    );

    // sender = Some(owner master_pub) so holder knows where to publish the response.
    assert_eq!(
        pos_req.entry.sender,
        Some(my_master),
        "PosChallenge entry sender must be Some(owner master_pub)"
    );

    // Payload decodes as a valid PosHashChallengeMsg.
    let decoded = from_cbor_bytes::<PosHashChallengeMsg>(&pos_req.entry.payload)
        .expect("entry payload must decode as PosHashChallengeMsg");
    assert_eq!(
        decoded.source_block_id, block_id,
        "decoded challenge source_block_id must match"
    );
}

// ─── T-6 test: PosChallenge entry has correct TTL ────────────────────────────

/// The published MailboxEntry.expires_at - stored_at equals POS_CHALLENGE_TTL (7 days).
#[tokio::test]
async fn pos_challenge_stored_in_mailbox_with_correct_ttl() {
    use viaticum_core::mailbox::{MailboxClass, class_config::POS_CHALLENGE_TTL};

    let db = Db::open_in_memory().expect("db open");
    let data_dir = tempfile::TempDir::new().unwrap();
    let holder_id = make_identity(0xB2);

    let block_id = seed_retained_pos_block(data_dir.path(), &db, 0xB1);

    let placement = make_placement(block_id, holder_id);
    db.upsert_placement(&placement).unwrap();
    db.upsert_peer(&make_peer_record(holder_id)).unwrap();

    let recording_sender = Arc::new(RecordingMailboxSender::new());
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::clone(&recording_sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let pending = make_pending_challenges();

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending.clone(),
        router,
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        data_dir.path().to_path_buf(),
    );

    scheduler
        .issue_due_challenges()
        .await
        .expect("issue_due_challenges");

    let requests = recording_sender.captured_requests();
    let pos_req = requests
        .iter()
        .find(|r| r.entry.class == MailboxClass::PosChallenge)
        .expect("expected a PosChallenge entry");

    let entry = &pos_req.entry;
    let actual_ttl_secs = entry.expires_at.saturating_sub(entry.stored_at);
    let expected_ttl_secs = POS_CHALLENGE_TTL.as_secs();

    assert_eq!(
        actual_ttl_secs, expected_ttl_secs,
        "PosChallenge entry TTL must equal POS_CHALLENGE_TTL ({expected_ttl_secs} s); \
         got {actual_ttl_secs} s"
    );
}

// ─── T-6 test: PosResponse via mailbox resolves pending challenge ─────────────

/// Owner side: handle_pos_response_from_mailbox resolves a pending challenge.
///
/// Pass case: matching chain hash → placement transitions to last_verified set, status updated.
/// Fail case: wrong chain hash → Fail path, repair trigger sent.
#[tokio::test]
async fn pos_response_via_mailbox_resolves_pending_challenge() {
    use viaticum_core::pos::compute_chain_hash;

    let db = Db::open_in_memory().expect("db open");
    let block_id = make_block_id(0xC1);
    let holder_id = make_identity(0xC2);
    let challenge_id = [0x42u8; 16];

    // Insert placement and peer record.
    let mut placement = make_placement(block_id, holder_id);
    placement.status = viaticum_core::types::PlacementStatus::Alive;
    db.upsert_placement(&placement).unwrap();
    db.upsert_peer(&make_peer_record(holder_id)).unwrap();

    // CS-ID-1: the owner now verifies the response signature against the master of
    // pending.holder_id. Register a holder master keypair and the device→master mapping so
    // the owner resolves a real verifying key, and sign the response with that key.
    let holder_master_key = ed25519_dalek::SigningKey::from_bytes(&[0xC3u8; 32]);
    let holder_master = IdentityPub(holder_master_key.verifying_key().to_bytes());
    db.set_master_for_device(&holder_id, &holder_master)
        .unwrap();

    // Compute a known expected_chain_hash using an arbitrary symbol.
    // We don't need real erasure data here — just a hash that the response can match.
    let dummy_esi: u32 = 0;
    let dummy_symbol = b"dummy_symbol_data_for_pos_hash_test".as_slice();
    let expected_chain_hash =
        compute_chain_hash(&challenge_id, &[(dummy_esi, dummy_symbol)]).unwrap();

    let pending = make_pending_challenges();
    {
        let mut guard = pending.lock().await;
        guard.insert(
            (block_id, holder_id),
            PendingHashChallenge {
                source_block_id: block_id,
                holder_id,
                esi_ranges: vec![(dummy_esi, 1)],
                expected_chain_hash,
                issued_at: Timestamp::now(),
                challenge_id,
            },
        );
    }

    let (repair_tx, mut repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending.clone(),
        make_test_router(&db),
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    // ── Pass case: correct chain_hash ────────────────────────────────────────
    let pass_response = viaticum_core::messages::build_pos_hash_response(
        challenge_id,
        block_id,
        expected_chain_hash, // correct hash = Pass
        Timestamp::now(),
        Some(holder_id),
        &holder_master_key,
    );

    scheduler
        .handle_pos_response_from_mailbox(pass_response)
        .await
        .expect("handle_pos_response_from_mailbox failed");

    // Pending map must be empty after resolution.
    assert!(
        pending.lock().await.is_empty(),
        "pending map must be empty after Pass response is consumed"
    );

    // Placement must have last_verified set (Pass outcome).
    let updated = db
        .get_placement(&block_id, &holder_id)
        .unwrap()
        .expect("placement exists after Pass");
    assert!(
        updated.last_verified.is_some(),
        "Pass outcome must set last_verified on the placement"
    );
    // Status must not have degraded (was Alive, Pass → stays Alive).
    assert_eq!(
        updated.status,
        PlacementStatus::Alive,
        "Alive placement after Pass must remain Alive"
    );
    // No repair triggered for Pass.
    assert!(
        repair_rx.try_recv().is_err(),
        "Pass outcome must NOT trigger repair"
    );

    // ── Fail case: wrong chain_hash ──────────────────────────────────────────
    // Set up a fresh DB/pending state for the Fail variant.
    let db2 = Db::open_in_memory().expect("db2 open");
    let block_id2 = make_block_id(0xD1);
    let holder_id2 = make_identity(0xD2);
    let challenge_id2 = [0x99u8; 16];

    let mut placement2 = make_placement(block_id2, holder_id2);
    placement2.consecutive_misses = 2; // any Fail → Lost directly (misses reset to 0, repair=true)
    placement2.status = PlacementStatus::Uncertain;
    db2.upsert_placement(&placement2).unwrap();
    db2.upsert_peer(&make_peer_record(holder_id2)).unwrap();

    // CS-ID-1: register holder2's master mapping + key for response signing/verify.
    let holder2_master_key = ed25519_dalek::SigningKey::from_bytes(&[0xD3u8; 32]);
    let holder2_master = IdentityPub(holder2_master_key.verifying_key().to_bytes());
    db2.set_master_for_device(&holder_id2, &holder2_master)
        .unwrap();

    let expected_hash2 =
        compute_chain_hash(&challenge_id2, &[(0u32, b"correct".as_slice())]).unwrap();
    let pending2 = make_pending_challenges();
    {
        let mut guard = pending2.lock().await;
        guard.insert(
            (block_id2, holder_id2),
            PendingHashChallenge {
                source_block_id: block_id2,
                holder_id: holder_id2,
                esi_ranges: vec![(0, 1)],
                expected_chain_hash: expected_hash2,
                issued_at: Timestamp::now(),
                challenge_id: challenge_id2,
            },
        );
    }

    let (repair_tx2, mut repair_rx2) = mpsc::channel::<RepairTrigger>(8);
    let signing_key2 = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let config2 = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler2 = Scheduler::new(
        db2.clone(),
        config2,
        repair_tx2,
        pending2.clone(),
        make_test_router(&db2),
        dummy_master_pub(),
        signing_key2,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    // Send a response with the WRONG chain_hash → Fail outcome. The response is correctly
    // SIGNED by the honest holder (a holder can produce a valid sig over a wrong hash, e.g.
    // if its symbols are corrupted) — the Fail must still be applied.
    let wrong_hash = [0xFFu8; 32]; // definitely not expected_hash2
    let fail_response = viaticum_core::messages::build_pos_hash_response(
        challenge_id2,
        block_id2,
        wrong_hash,
        Timestamp::now(),
        Some(holder_id2),
        &holder2_master_key,
    );

    scheduler2
        .handle_pos_response_from_mailbox(fail_response)
        .await
        .expect("handle_pos_response_from_mailbox (fail) failed");

    // Pending must be consumed.
    assert!(
        pending2.lock().await.is_empty(),
        "pending map must be empty after Fail response is consumed"
    );

    // Placement must have degraded: Fail (wrong hash) → Lost directly (any Fail → Lost, misses=0).
    // From apply_pos_outcome docstring: "Any + Fail → Lost, misses=0, repair=true".
    let updated2 = db2
        .get_placement(&block_id2, &holder_id2)
        .unwrap()
        .expect("placement2 exists after Fail");
    assert_eq!(
        updated2.status,
        PlacementStatus::Lost,
        "Fail (wrong chain hash) must → Lost regardless of consecutive_misses"
    );

    // Repair trigger must have been sent.
    let trigger = repair_rx2
        .try_recv()
        .expect("Fail outcome must trigger repair (trigger_repair=true)");
    assert!(
        matches!(trigger, RepairTrigger::Wake),
        "expected RepairTrigger::Wake after Fail, got {trigger:?}"
    );
}

// ─── A3 (P1-4 / M1): owner-side idempotency for a re-delivered PosResponse ──────

/// A3: under the reliable-delivery design the holder re-publishes the SAME PosResponse
/// while the challenge entry lives in its mailbox (deterministic msg_id derived from
/// challenge_id ‖ chain_hash — stable across re-dispatch, unpredictable to a postman).
/// A duplicate of an already-resolved response can therefore reach the owner after its
/// pending entry was consumed by the first valid response. That duplicate must be a
/// no-op: unknown challenge_id → silent drop, no panic, no double-apply of the outcome.
#[tokio::test]
async fn pos_response_duplicate_after_consume_is_dropped() {
    use viaticum_core::pos::compute_chain_hash;

    let db = Db::open_in_memory().expect("db open");
    let block_id = make_block_id(0xA1);
    let holder_id = make_identity(0xA2);
    let challenge_id = [0x77u8; 16];

    let mut placement = make_placement(block_id, holder_id);
    placement.status = PlacementStatus::Alive;
    db.upsert_placement(&placement).unwrap();
    db.upsert_peer(&make_peer_record(holder_id)).unwrap();

    let holder_master_key = ed25519_dalek::SigningKey::from_bytes(&[0xA3u8; 32]);
    let holder_master = IdentityPub(holder_master_key.verifying_key().to_bytes());
    db.set_master_for_device(&holder_id, &holder_master)
        .unwrap();

    let dummy_symbol = b"dummy_symbol_data_for_dup_test".as_slice();
    let expected_chain_hash = compute_chain_hash(&challenge_id, &[(0u32, dummy_symbol)]).unwrap();

    let pending = make_pending_challenges();
    {
        let mut guard = pending.lock().await;
        guard.insert(
            (block_id, holder_id),
            PendingHashChallenge {
                source_block_id: block_id,
                holder_id,
                esi_ranges: vec![(0, 1)],
                expected_chain_hash,
                issued_at: Timestamp::now(),
                challenge_id,
            },
        );
    }

    let (repair_tx, mut repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending.clone(),
        make_test_router(&db),
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    // The same signed Pass response is delivered twice (the holder re-published it).
    let response = viaticum_core::messages::build_pos_hash_response(
        challenge_id,
        block_id,
        expected_chain_hash, // correct hash = Pass
        Timestamp::now(),
        Some(holder_id),
        &holder_master_key,
    );

    // First delivery: resolves and consumes the pending challenge.
    scheduler
        .handle_pos_response_from_mailbox(response.clone())
        .await
        .expect("first PosResponse must resolve cleanly");
    assert!(
        pending.lock().await.is_empty(),
        "pending must be empty after the first valid response is consumed"
    );

    let after_first = db
        .get_placement(&block_id, &holder_id)
        .unwrap()
        .expect("placement exists after first response");
    assert!(
        after_first.last_verified.is_some(),
        "first Pass must set last_verified"
    );
    let first_verified = after_first.last_verified;

    // Second delivery of the SAME response: pending is gone → unknown challenge_id →
    // must be a silent no-op (Ok, no panic), no double-apply, no repair.
    scheduler
        .handle_pos_response_from_mailbox(response)
        .await
        .expect("duplicate PosResponse after consume must NOT error or panic");

    assert!(
        pending.lock().await.is_empty(),
        "pending must remain empty after the duplicate"
    );
    let after_dup = db
        .get_placement(&block_id, &holder_id)
        .unwrap()
        .expect("placement exists after duplicate");
    assert_eq!(
        after_dup.status,
        PlacementStatus::Alive,
        "duplicate response must not change placement status"
    );
    assert_eq!(
        after_dup.last_verified, first_verified,
        "duplicate must not re-apply the outcome (last_verified unchanged)"
    );
    assert!(
        repair_rx.try_recv().is_err(),
        "duplicate response must not trigger repair"
    );
}

// ─── CS-ID-1 / P1-1 / P1-7: forged PosResponse is ignored, pending left intact ──

/// A forged response from a positioned postman — valid `challenge_id` but signed by an
/// identity that is NOT the challenged holder's master (or unsigned) — must be IGNORED:
/// the pending challenge is LEFT INTACT (so the honest holder's real response can still
/// resolve it) and NO Fail outcome is applied to the honest holder's placement.
#[tokio::test]
async fn pos_response_from_wrong_identity_is_ignored() {
    use viaticum_core::pos::compute_chain_hash;

    let db = Db::open_in_memory().expect("db open");
    let block_id = make_block_id(0xF1);
    let holder_id = make_identity(0xF2);
    let challenge_id = [0x55u8; 16];

    let mut placement = make_placement(block_id, holder_id);
    placement.consecutive_misses = 2; // any Fail would → Lost (so a wrong outcome is observable)
    placement.status = PlacementStatus::Alive;
    db.upsert_placement(&placement).unwrap();
    db.upsert_peer(&make_peer_record(holder_id)).unwrap();

    // Register the honest holder's master mapping.
    let holder_master_key = ed25519_dalek::SigningKey::from_bytes(&[0xF3u8; 32]);
    let holder_master = IdentityPub(holder_master_key.verifying_key().to_bytes());
    db.set_master_for_device(&holder_id, &holder_master)
        .unwrap();

    let expected_chain_hash =
        compute_chain_hash(&challenge_id, &[(0u32, b"honest".as_slice())]).unwrap();

    let pending = make_pending_challenges();
    {
        let mut guard = pending.lock().await;
        guard.insert(
            (block_id, holder_id),
            PendingHashChallenge {
                source_block_id: block_id,
                holder_id,
                esi_ranges: vec![(0, 1)],
                expected_chain_hash,
                issued_at: Timestamp::now(),
                challenge_id,
            },
        );
    }

    let (repair_tx, mut repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending.clone(),
        make_test_router(&db),
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    // Forge: correct challenge_id + garbage chain_hash, signed by an ATTACKER master key
    // (not the holder's). This is the postman's framing attack.
    let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0xAAu8; 32]);
    let forged = viaticum_core::messages::build_pos_hash_response(
        challenge_id,
        block_id,
        [0xFFu8; 32], // wrong hash — would be Fail → Lost if applied
        Timestamp::now(),
        Some(holder_id),
        &attacker_key,
    );

    scheduler
        .handle_pos_response_from_mailbox(forged)
        .await
        .expect("handler must not error on a forged response");

    // Pending MUST remain — the forge must not consume it (P1-7).
    assert!(
        !pending.lock().await.is_empty(),
        "forged response must NOT consume the pending challenge (pending left intact)"
    );

    // Placement MUST NOT have degraded — no Fail applied to the honest holder.
    let updated = db
        .get_placement(&block_id, &holder_id)
        .unwrap()
        .expect("placement still exists");
    assert_eq!(
        updated.status,
        PlacementStatus::Alive,
        "forged response must NOT apply a Fail to the honest holder's placement"
    );

    // No repair triggered.
    assert!(
        repair_rx.try_recv().is_err(),
        "forged response must NOT trigger repair against the honest holder"
    );

    // And the honest holder's correctly-signed response STILL resolves the pending challenge.
    let honest = viaticum_core::messages::build_pos_hash_response(
        challenge_id,
        block_id,
        expected_chain_hash, // correct hash = Pass
        Timestamp::now(),
        Some(holder_id),
        &holder_master_key,
    );
    scheduler
        .handle_pos_response_from_mailbox(honest)
        .await
        .expect("handler must not error on the honest response");
    assert!(
        pending.lock().await.is_empty(),
        "honest signed response must resolve (consume) the pending challenge"
    );
    let resolved = db
        .get_placement(&block_id, &holder_id)
        .unwrap()
        .expect("placement still exists after honest Pass");
    assert!(
        resolved.last_verified.is_some(),
        "honest Pass must set last_verified"
    );
}

// ─── T-6 test: pending timeout boundary is 14d2h not 7d1h ───────────────────

/// Pins the POS_CHALLENGE_PENDING_TIMEOUT_SECS (14d2h) boundary.
///
/// A challenge issued `POS_CHALLENGE_PENDING_TIMEOUT_SECS - small` ago is NOT expired.
/// A challenge issued `POS_CHALLENGE_PENDING_TIMEOUT_SECS + small` ago IS expired.
///
/// Uses time_scale = POS_CHALLENGE_PENDING_TIMEOUT_SECS so threshold = 1 second,
/// then issues challenges at 0s ago (fresh) vs 5s ago (stale).
#[tokio::test]
async fn pos_pending_timeout_is_14d_2h_not_7d_1h() {
    use viaticum_core::constants::POS_CHALLENGE_PENDING_TIMEOUT_SECS;

    let db = Db::open_in_memory().expect("db open");
    let block_id_fresh = make_block_id(0xE1);
    let block_id_stale = make_block_id(0xE2);
    let holder_fresh = make_identity(0xE3);
    let holder_stale = make_identity(0xE4);

    let placement_fresh = make_placement(block_id_fresh, holder_fresh);
    let mut placement_stale = make_placement(block_id_stale, holder_stale);
    placement_stale.consecutive_misses = 0;
    db.upsert_placement(&placement_fresh).unwrap();
    db.upsert_placement(&placement_stale).unwrap();

    let pending = make_pending_challenges();
    let now = Timestamp::now();

    {
        let mut guard = pending.lock().await;
        // Fresh: issued right now (0s ago) — at threshold=1s, this is NOT timed out.
        guard.insert(
            (block_id_fresh, holder_fresh),
            PendingHashChallenge {
                source_block_id: block_id_fresh,
                holder_id: holder_fresh,
                esi_ranges: vec![(0, 1)],
                expected_chain_hash: [0u8; 32],
                issued_at: now,
                challenge_id: [0xE1u8; 16],
            },
        );
        // Stale: issued 5 seconds ago — at threshold=1s, this IS timed out.
        guard.insert(
            (block_id_stale, holder_stale),
            PendingHashChallenge {
                source_block_id: block_id_stale,
                holder_id: holder_stale,
                esi_ranges: vec![(0, 1)],
                expected_chain_hash: [0u8; 32],
                issued_at: Timestamp(now.0.saturating_sub(5)),
                challenge_id: [0xE2u8; 16],
            },
        );
    }

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

    // time_scale = POS_CHALLENGE_PENDING_TIMEOUT_SECS → threshold = 1 second.
    // This directly pins the 14d2h constant: if code ever reverts to POS_TIMEOUT_SECS (7d),
    // POS_TIMEOUT_SECS / POS_CHALLENGE_PENDING_TIMEOUT_SECS < 1 → threshold rounds to 1s still,
    // but the constant used in the impl would differ. We verify POS_CHALLENGE_PENDING_TIMEOUT_SECS
    // equals the expected 14d2h value (= 7d + 7d + 2h) explicitly below.
    let expected_14d2h: u64 = 7 * 24 * 3600 + 7 * 24 * 3600 + 2 * 3600;
    assert_eq!(
        POS_CHALLENGE_PENDING_TIMEOUT_SECS, expected_14d2h,
        "POS_CHALLENGE_PENDING_TIMEOUT_SECS must equal 14d2h ({expected_14d2h}s); \
         if this fails, someone changed the constant — verify the design decision"
    );

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: POS_CHALLENGE_PENDING_TIMEOUT_SECS,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending.clone(),
        make_test_router(&db),
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        std::env::temp_dir(),
    );

    scheduler.check_timeouts().await.expect("check_timeouts");

    let guard = pending.lock().await;

    // Fresh challenge (0s old) must NOT have been timed out.
    assert!(
        guard.contains_key(&(block_id_fresh, holder_fresh)),
        "fresh challenge (0s old) must NOT be expired at threshold=1s \
         (boundary: POS_CHALLENGE_PENDING_TIMEOUT_SECS=14d2h)"
    );

    // Stale challenge (5s old) MUST have been timed out.
    assert!(
        !guard.contains_key(&(block_id_stale, holder_stale)),
        "stale challenge (5s old) MUST be expired at threshold=1s \
         (boundary: POS_CHALLENGE_PENDING_TIMEOUT_SECS=14d2h)"
    );
}

// ─── T-6 test: SS blocks excluded from due challenges ────────────────────────

/// SS blocks (registered in ss_block_id_set) must not receive PoS challenges.
/// Normal blocks placed alongside them must still be challenged.
#[tokio::test]
async fn ss_blocks_excluded_from_due_challenges_via_existing_ss_block_id_set() {
    let db = Db::open_in_memory().expect("db open");
    let data_dir = tempfile::TempDir::new().unwrap();

    let normal_holder = make_identity(0xF3);
    let ss_holder = make_identity(0xF4);

    // Two content-addressed blocks (retained blobs + records): one normal, one SS.
    let normal_block_id = seed_retained_pos_block(data_dir.path(), &db, 0xF1);
    let ss_block_id = seed_retained_pos_block(data_dir.path(), &db, 0xF2);

    // Insert placements for both holders.
    db.upsert_placement(&make_placement(normal_block_id, normal_holder))
        .unwrap();
    db.upsert_placement(&make_placement(ss_block_id, ss_holder))
        .unwrap();
    db.upsert_peer(&make_peer_record(normal_holder)).unwrap();
    db.upsert_peer(&make_peer_record(ss_holder)).unwrap();

    // Register ss_block_id in the SS ledger (generation=1).
    db.mark_ss_block(&ss_block_id, 1).unwrap();

    let recording_sender = Arc::new(RecordingMailboxSender::new());
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::clone(&recording_sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));

    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let pending = make_pending_challenges();

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
        event_log_retain_rows: 100_000,
        pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
    };
    let scheduler = Scheduler::new(
        db.clone(),
        config,
        repair_tx,
        pending.clone(),
        router,
        dummy_master_pub(),
        signing_key,
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        data_dir.path().to_path_buf(),
    );

    scheduler
        .issue_due_challenges()
        .await
        .expect("issue_due_challenges");

    let requests = recording_sender.captured_requests();

    // The normal block's holder must have received a challenge.
    let normal_challenged = requests
        .iter()
        .any(|r| r.target == viaticum_core::types::IdentityPub(normal_holder.0));
    assert!(
        normal_challenged,
        "normal block holder must be challenged via mailbox"
    );

    // The SS block's holder must NOT have received a challenge.
    let ss_challenged = requests
        .iter()
        .any(|r| r.target == viaticum_core::types::IdentityPub(ss_holder.0));
    assert!(
        !ss_challenged,
        "SS block holder must NOT be challenged (SS blocks excluded via ss_block_id_set)"
    );

    // Pending: normal block holder must be in pending, SS block holder must not be.
    let guard = pending.lock().await;
    let normal_pending = guard.contains_key(&(normal_block_id, normal_holder));
    let ss_pending = guard.contains_key(&(ss_block_id, ss_holder));
    assert!(
        normal_pending,
        "normal block placement must be in pending after challenge"
    );
    assert!(!ss_pending, "SS block placement must NOT be in pending");
}

// ─── T-6 test: W-3 — pending not created before mailbox store ack ─────────────

/// W-3 invariant: pending entry is created ONLY after ≥1 MailboxStoreAck.
///
/// With NoOpMailboxSender (returns errors = 0 acks): no pending entry is created.
/// With AckMailboxSender (returns Ack): pending entry IS created.
#[tokio::test]
async fn pending_challenge_not_created_before_mailbox_store_ack() {
    let holder_id = make_identity(0x78);

    // ── Case 1: NoOpMailboxSender → 0 acks → no pending entry ────────────────
    {
        let db = Db::open_in_memory().expect("db open");
        let data_dir = tempfile::TempDir::new().unwrap();
        let block_id = seed_retained_pos_block(data_dir.path(), &db, 0x77);
        db.upsert_placement(&make_placement(block_id, holder_id))
            .unwrap();
        db.upsert_peer(&make_peer_record(holder_id)).unwrap();

        let router = Arc::new(MailboxRouter::with_sender(
            Arc::new(NoOpMailboxSender) as Arc<dyn MailboxNetworkSender>,
            db.clone(),
        ));

        let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pending = make_pending_challenges();

        let config = SchedulerConfig {
            pos_interval_secs: 3600,
            timeout_check_secs: 3600,
            time_scale: 1,
            event_log_retain_rows: 100_000,
            pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
        };
        let scheduler = Scheduler::new(
            db.clone(),
            config,
            repair_tx,
            pending.clone(),
            router,
            dummy_master_pub(),
            ed25519_dalek::SigningKey::from_bytes(&signing_key.to_bytes()),
            crate::daemon::processor::make_empty_accepted_offers(),
            make_test_encoder(),
            TEST_EPOCH_KEY,
            data_dir.path().to_path_buf(),
        );

        scheduler
            .issue_due_challenges()
            .await
            .expect("issue_due_challenges (0 acks)");

        assert!(
            pending.lock().await.is_empty(),
            "W-3: with 0 acks, pending map must remain empty — challenge is not confirmed delivered"
        );
    }

    // ── Case 2: AckMailboxSender → ≥1 ack → pending entry IS created ─────────
    {
        let db = Db::open_in_memory().expect("db open (ack case)");
        let data_dir = tempfile::TempDir::new().unwrap();
        let block_id = seed_retained_pos_block(data_dir.path(), &db, 0x77);
        db.upsert_placement(&make_placement(block_id, holder_id))
            .unwrap();
        db.upsert_peer(&make_peer_record(holder_id)).unwrap();

        let router = Arc::new(MailboxRouter::with_sender(
            Arc::new(AckMailboxSender) as Arc<dyn MailboxNetworkSender>,
            db.clone(),
        ));

        let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pending = make_pending_challenges();

        let config = SchedulerConfig {
            pos_interval_secs: 3600,
            timeout_check_secs: 3600,
            time_scale: 1,
            event_log_retain_rows: 100_000,
            pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
        };
        let scheduler = Scheduler::new(
            db.clone(),
            config,
            repair_tx,
            pending.clone(),
            router,
            dummy_master_pub(),
            signing_key,
            crate::daemon::processor::make_empty_accepted_offers(),
            make_test_encoder(),
            TEST_EPOCH_KEY,
            data_dir.path().to_path_buf(),
        );

        scheduler
            .issue_due_challenges()
            .await
            .expect("issue_due_challenges (ack)");

        assert!(
            !pending.lock().await.is_empty(),
            "W-3: with ≥1 ack, pending map must contain the challenge entry"
        );

        // Verify the pending entry has the right block/holder.
        let guard = pending.lock().await;
        assert!(
            guard.contains_key(&(block_id, holder_id)),
            "pending entry must be keyed by (block_id, holder_id)"
        );
    }
}

// ─── Stub network helper ──────────────────────────────────────────────────────
