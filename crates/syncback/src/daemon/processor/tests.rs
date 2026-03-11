use std::path::PathBuf;
use std::time::Duration;

use syncback_core::db::Db;
use syncback_core::types::{
    FileType, HoldingRecord, IdentityPub, PeerRecord, ShardId, ShardRecord, ShardState,
    ShardStatus, Timestamp, UnitId,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::daemon::{
    BackupConfig, CliCmd, Config, DirtyEvent, DirtyKind, IncludeEntry, NetCommand, NetEvent,
    NetworkConfig, ProcessorMsg, ScheduleConfig, ScheduledCmd, StorageConfig, SyncFrequency,
    VacuumFrequency,
};

use super::run;

// ============================================================
// Test helpers
// ============================================================

fn test_db() -> (Db, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("test.redb");
    let db = Db::open(&path).expect("open db");
    (db, dir)
}

fn test_config(syncback_dir: PathBuf) -> Config {
    Config {
        syncback_dir: syncback_dir.clone(),
        backup: BackupConfig {
            include: vec![IncludeEntry {
                path: PathBuf::from("/home/user/docs"),
                importance: 0.9,
            }],
            exclude: Vec::new(),
        },
        storage: StorageConfig { quota_gb: 100 },
        network: NetworkConfig {
            seed_nodes: Vec::new(),
            bandwidth_limit_mbps: 0,
        },
        schedule: ScheduleConfig {
            sync: SyncFrequency::Weekly,
            vacuum: VacuumFrequency::Monthly,
        },
    }
}

fn test_identity() -> (ed25519_dalek::SigningKey, IdentityPub) {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
    let pub_bytes: [u8; 32] = key.verifying_key().to_bytes();
    (key, IdentityPub(pub_bytes))
}

/// Spawn the processor task and return handles to all channels.
fn spawn_processor(
    db: Db,
    config: Config,
) -> (
    CancellationToken,
    mpsc::Sender<ProcessorMsg>,
    mpsc::Sender<DirtyEvent>,
    mpsc::Sender<NetEvent>,
    mpsc::Receiver<NetCommand>,
    tokio::task::JoinHandle<()>,
) {
    let cancel = CancellationToken::new();
    let (processor_tx, processor_rx) = mpsc::channel::<ProcessorMsg>(64);
    let (dirty_tx, dirty_rx) = mpsc::channel::<DirtyEvent>(64);
    let (net_event_tx, net_event_rx) = mpsc::channel::<NetEvent>(64);
    let (net_cmd_tx, net_cmd_rx) = mpsc::channel::<NetCommand>(64);

    let (identity_key, identity_pub) = test_identity();

    let handle = tokio::spawn(run(
        db,
        cancel.clone(),
        processor_rx,
        dirty_rx,
        net_event_rx,
        net_cmd_tx,
        config,
        identity_key,
        identity_pub,
    ));

    (cancel, processor_tx, dirty_tx, net_event_tx, net_cmd_rx, handle)
}

fn make_peer_record(identity: IdentityPub, now: Timestamp) -> PeerRecord {
    PeerRecord {
        identity,
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: now,
        last_seen: now,
        weeks_in_network: 10,
        subnet_prefix: None,
        allowlisted: false,
    }
}

// ============================================================
// Tests
// ============================================================

#[tokio::test]
async fn processor_handles_shutdown_command() {
    let (db, _dir) = test_db();
    let config = test_config(_dir.path().to_path_buf());

    let (cancel, processor_tx, _dirty_tx, _net_event_tx, _net_cmd_rx, handle) =
        spawn_processor(db, config);

    processor_tx
        .send(ProcessorMsg::Cli(CliCmd::Shutdown))
        .await
        .expect("send shutdown");

    let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(result.is_ok(), "processor did not shut down within 2 seconds");
    drop(cancel);
}

#[tokio::test]
async fn processor_cancellation_token_stops_loop() {
    let (db, _dir) = test_db();
    let config = test_config(_dir.path().to_path_buf());

    let (cancel, _processor_tx, _dirty_tx, _net_event_tx, _net_cmd_rx, handle) =
        spawn_processor(db, config);

    cancel.cancel();

    let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(result.is_ok(), "processor did not stop on cancellation within 2 seconds");
}

#[tokio::test]
async fn processor_cli_status_returns_correct_counts() {
    let (db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());
    let now = Timestamp::now();

    // Insert 3 peers.
    for i in 0u8..3 {
        let mut bytes = [0u8; 32];
        bytes[0] = i + 1;
        let identity = IdentityPub(bytes);
        let record = make_peer_record(identity, now);
        db.upsert_peer(&record).expect("upsert peer");
    }

    // Insert 5 holding records.
    for i in 0u8..5 {
        let mut shard_bytes = [0u8; 32];
        shard_bytes[0] = i + 10;
        let shard_id = ShardId(shard_bytes);
        let mut owner_bytes = [0u8; 32];
        owner_bytes[0] = 1;
        let record = HoldingRecord {
            shard_id,
            owner_pub: IdentityPub(owner_bytes),
            importance: 0.5,
            size_bytes: 1024,
            state: ShardState::Active,
            received_at: now,
            delete_requested_at: None,
            drop_notice_sent_at: None,
            file_type: FileType::User,
            merkle_root: [0u8; 32],
            rs_k: 5,
            rs_n: 10,
            shard_index: i,
        };
        db.upsert_holding(&record).expect("upsert holding");
    }

    // Insert 2 stored shard records (owner view).
    let unit_id = UnitId([42u8; 32]);
    for i in 0u8..2 {
        let mut shard_bytes = [0u8; 32];
        shard_bytes[0] = i + 100;
        let shard_id = ShardId(shard_bytes);
        let mut holder_bytes = [0u8; 32];
        holder_bytes[0] = 2;
        let record = ShardRecord {
            shard_id,
            unit_id,
            shard_index: i,
            holder_id: IdentityPub(holder_bytes),
            status: ShardStatus::Stored,
            last_verified: None,
            offered_at: now,
            stored_at: Some(now),
            merkle_root: [0u8; 32],
        };
        db.upsert_shard(&record).expect("upsert shard");
    }

    let (cancel, processor_tx, _dirty_tx, _net_event_tx, _net_cmd_rx, handle) =
        spawn_processor(db, config);

    // Give processor a moment to start.
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    processor_tx
        .send(ProcessorMsg::Cli(CliCmd::Status { reply: reply_tx }))
        .await
        .expect("send status");

    let reply = tokio::time::timeout(Duration::from_secs(2), reply_rx)
        .await
        .expect("status reply timeout")
        .expect("status reply channel");

    assert_eq!(reply.peer_count, 3, "peer_count mismatch");
    assert_eq!(reply.shards_held, 5, "shards_held mismatch");
    assert_eq!(reply.shards_placed, 2, "shards_placed mismatch");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn processor_handles_dirty_event_creates_file_record() {
    let (db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());
    let db2 = db.clone();

    let (cancel, _processor_tx, dirty_tx, _net_event_tx, _net_cmd_rx, handle) =
        spawn_processor(db, config);

    // Give processor a moment to start.
    tokio::time::sleep(Duration::from_millis(10)).await;

    let now = Timestamp::now();
    dirty_tx
        .send(DirtyEvent {
            path: PathBuf::from("/home/user/docs/notes.txt"),
            kind: DirtyKind::Created,
            detected_at: now.0,
        })
        .await
        .expect("send dirty event");

    // Give processor time to handle.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let record = db2
        .get_file("/home/user/docs/notes.txt")
        .expect("get_file");
    assert!(record.is_some(), "file record should have been created");
    let record = record.unwrap();
    assert!(
        (record.importance - 0.9).abs() < 1e-9,
        "importance should be 0.9"
    );
    assert!(record.dirty, "record should be dirty");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn processor_handles_dirty_event_ignores_low_importance() {
    let (db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());
    let db2 = db.clone();

    let (cancel, _processor_tx, dirty_tx, _net_event_tx, _net_cmd_rx, handle) =
        spawn_processor(db, config);

    tokio::time::sleep(Duration::from_millis(10)).await;

    let now = Timestamp::now();
    // Send a path that doesn't match any include pattern.
    dirty_tx
        .send(DirtyEvent {
            path: PathBuf::from("/tmp/some-random-file.txt"),
            kind: DirtyKind::Created,
            detected_at: now.0,
        })
        .await
        .expect("send dirty event");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let record = db2.get_file("/tmp/some-random-file.txt").expect("get_file");
    assert!(record.is_none(), "low-importance file should not be recorded");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn processor_handles_peer_connected_registers_peer() {
    let (db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());
    let db2 = db.clone();

    let (cancel, _processor_tx, _dirty_tx, net_event_tx, _net_cmd_rx, handle) =
        spawn_processor(db, config);

    tokio::time::sleep(Duration::from_millis(10)).await;

    let peer = IdentityPub([7u8; 32]);
    let node_id = syncback_core::types::NodeId([8u8; 32]);
    net_event_tx
        .send(NetEvent::PeerConnected {
            peer_identity: peer,
            peer_node_id: node_id,
        })
        .await
        .expect("send peer connected");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let record = db2.get_peer(&peer).expect("get_peer");
    assert!(record.is_some(), "peer should have been registered");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn processor_handles_weekly_sync_scheduled() {
    let (db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());
    let db2 = db.clone();

    let (cancel, processor_tx, _dirty_tx, _net_event_tx, _net_cmd_rx, handle) =
        spawn_processor(db, config);

    tokio::time::sleep(Duration::from_millis(10)).await;

    processor_tx
        .send(ProcessorMsg::Scheduled(ScheduledCmd::WeeklySync))
        .await
        .expect("send weekly sync");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // After weekly sync, schedule record should be set.
    let schedule = db2
        .get_schedule("weekly_sync")
        .expect("get_schedule");
    assert!(schedule.is_some(), "weekly_sync schedule should be set");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

#[tokio::test]
async fn processor_handles_fatal_error_cancels_token() {
    let (db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());

    let (cancel, _processor_tx, _dirty_tx, net_event_tx, _net_cmd_rx, handle) =
        spawn_processor(db, config);

    tokio::time::sleep(Duration::from_millis(10)).await;

    net_event_tx
        .send(NetEvent::FatalError("test fatal error".to_string()))
        .await
        .expect("send fatal error");

    // Processor should cancel the token and then exit.
    let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(result.is_ok(), "processor should have exited after fatal error");
    assert!(cancel.is_cancelled(), "cancel token should be set");
}
