// Tests for the Scheduler module.
//
// Strategy: test issue_due_challenges() and check_timeouts() directly
// (not the run() loop) to avoid real timers and network connections.
// The PendingChallenges map is used as the primary observable output.

use std::collections::HashMap;
use std::sync::Arc;

use syncback_core::db::Db;
use syncback_core::types::{
    FileId, IdentityPub, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp,
};
use tokio::sync::{mpsc, Mutex};

use crate::daemon::repair::RepairTrigger;
use crate::daemon::scheduler::{PendingChallenges, Scheduler, SchedulerConfig};

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn make_block_id(seed: u8) -> SourceBlockId {
    SourceBlockId([seed; 32])
}

fn make_identity(seed: u8) -> IdentityPub {
    IdentityPub([seed; 32])
}

fn make_placement(block_id: SourceBlockId, holder_id: IdentityPub) -> SymbolPlacement {
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
            crate::daemon::scheduler::PendingChallenge {
                source_block_id: block_id,
                holder_id,
                esi: 0,
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
    };

    // We need a NetworkHandle for the constructor. Build a no-op one via a stub.
    // Since check_timeouts doesn't use network, we pass a real (but unused) handle.
    let network = make_stub_network().await;

    let scheduler = Scheduler::new(db.clone(), config, network, repair_tx, pending.clone());

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
            crate::daemon::scheduler::PendingChallenge {
                source_block_id: block_id,
                holder_id,
                esi: 5,
                issued_at: now,
                challenge_id: [1u8; 16],
            },
        );
    }

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1, // POS_TIMEOUT_SECS = 604_800 s — fresh challenge won't expire
    };
    let network = make_stub_network().await;
    let scheduler = Scheduler::new(db, config, network, repair_tx, pending.clone());

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
            crate::daemon::scheduler::PendingChallenge {
                source_block_id: block_id,
                holder_id,
                esi: 42,
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
        assert_eq!(entry.esi, 42);
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
            crate::daemon::scheduler::PendingChallenge {
                source_block_id: block_id,
                holder_id,
                esi: 0,
                issued_at,
                challenge_id: [0u8; 16],
            },
        );
    }

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: syncback_core::constants::POS_TIMEOUT_SECS, // threshold = 1 second
    };
    let network = make_stub_network().await;
    let scheduler = Scheduler::new(db.clone(), config, network, repair_tx, pending.clone());

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
            crate::daemon::scheduler::PendingChallenge {
                source_block_id: block_id,
                holder_id,
                esi: 5,
                issued_at: Timestamp::now(),
                challenge_id: [2u8; 16],
            },
        );
    }

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: 1,
    };
    let network = make_stub_network().await;
    let scheduler = Scheduler::new(db, config, network, repair_tx, pending.clone());

    // issue_due_challenges should skip this holder because it's already pending.
    // The existing pending entry's esi (5) should not be overwritten.
    scheduler
        .issue_due_challenges()
        .await
        .expect("issue_due_challenges");

    let guard = pending.lock().await;
    assert_eq!(guard.len(), 1, "only the pre-existing entry should remain");
    let entry = guard.get(&(block_id, holder_id)).expect("entry present");
    assert_eq!(entry.esi, 5, "existing pending entry esi unchanged");
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
    };
    let network = make_stub_network().await;
    let scheduler = Scheduler::new(db, config, network, repair_tx, pending.clone());

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
            crate::daemon::scheduler::PendingChallenge {
                source_block_id: block_id,
                holder_id,
                esi: 0,
                issued_at,
                challenge_id: [0u8; 16],
            },
        );
    }

    let config = SchedulerConfig {
        pos_interval_secs: 3600,
        timeout_check_secs: 3600,
        time_scale: scale,
    };
    let network = make_stub_network().await;
    let scheduler = Scheduler::new(db.clone(), config, network, repair_tx, pending.clone());

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

// ─── Stub network helper ──────────────────────────────────────────────────────

/// Build a real NetworkHandle bound to localhost with a dummy identity.
/// Used where the Scheduler constructor needs one but the test doesn't exercise
/// the network path.
async fn make_stub_network() -> Arc<crate::daemon::network::NetworkHandle> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let mi = syncback_core::types::IdentityPub(signing_key.verifying_key().to_bytes());
    let (incoming_tx, _incoming_rx) = tokio::sync::mpsc::channel(1);

    let config = crate::daemon::network::NetworkConfig {
        signing_key,
        master_identity: mi,
        known_peers: std::collections::HashMap::new(),
        device_cert: None,
        iroh_secret_key: None,
        relay_mode: iroh::RelayMode::Disabled,
    };

    Arc::new(
        crate::daemon::network::NetworkHandle::start(config, incoming_tx)
            .await
            .expect("stub network"),
    )
}
