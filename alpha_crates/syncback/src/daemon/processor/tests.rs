use std::path::PathBuf;
use std::time::Duration;

use syncback_core::db::Db;
use syncback_core::types::{
    FileType, HoldingRecord, IdentityPub, NodeId, PeerRecord, ShardId, ShardRecord, ShardState,
    ShardStatus, SystemStateBlobRecord, Timestamp, UnitId,
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
        time_scale: 1,
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
        "test-node-id".to_string(),
    ));

    (cancel, processor_tx, dirty_tx, net_event_tx, net_cmd_rx, handle)
}

/// Spawn processor with a specific identity key (for DR tests).
fn spawn_processor_with_identity(
    db: Db,
    config: Config,
    identity_key: ed25519_dalek::SigningKey,
    identity_pub: IdentityPub,
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
        "test-node-id".to_string(),
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

// ============================================================
// System state and DR boot tests
// ============================================================

/// Helper: generate a BIP39 mnemonic from 32 bytes of entropy.
fn make_mnemonic(entropy: [u8; 32]) -> (Vec<String>, [u8; 32], IdentityPub) {
    use bip39::Mnemonic;
    let mnemonic = Mnemonic::from_entropy(&entropy).expect("valid entropy");
    let words: Vec<String> = mnemonic.words().map(|s| s.to_string()).collect();
    let seed = mnemonic.to_seed("");
    let (signing_key, _) = crate::cli::init::derive_keys(&seed);
    let pub_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    let identity_key_bytes: [u8; 32] = signing_key.to_bytes();
    (words, identity_key_bytes, IdentityPub(pub_bytes))
}

/// Build a PeerRecord with a known NodeId (so it can be selected for backup).
/// Uses a valid ed25519 public key derived from the given seed byte for the NodeId.
fn make_peer_with_node_id(identity: IdentityPub, seed_byte: u8, now: Timestamp) -> PeerRecord {
    // Derive a valid ed25519 key from a known seed byte for the NodeId.
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    seed[31] = 0x01; // ensure non-zero
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let node_id_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    PeerRecord {
        identity,
        node_id: Some(NodeId(node_id_bytes)),
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

/// Drain all NetCommands from rx without blocking.
fn drain_net_cmds(rx: &mut mpsc::Receiver<NetCommand>) -> Vec<NetCommand> {
    let mut cmds = Vec::new();
    while let Ok(cmd) = rx.try_recv() {
        cmds.push(cmd);
    }
    cmds
}

/// system_state_backup_sends_to_peers_when_enough_known
///
/// Owner has 3+ peers with node_ids. Triggering SystemStateBackup should
/// emit SendMessage commands for each of them.
#[tokio::test]
async fn system_state_backup_sends_to_peers_when_enough_known() {
    let (db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());
    let db2 = db.clone();
    let now = Timestamp::now();

    // Create 3 peers with known NodeIds so the backup can select them.
    for i in 1u8..=3 {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        bytes[31] = 0x01; // ensure distinct, non-zero identity
        let identity = IdentityPub(bytes);
        let record = make_peer_with_node_id(identity, i, now);
        db2.upsert_peer(&record).expect("upsert peer");
    }

    let (cancel, processor_tx, _dirty_tx, _net_event_tx, mut net_cmd_rx, handle) =
        spawn_processor(db, config);

    tokio::time::sleep(Duration::from_millis(10)).await;

    processor_tx
        .send(ProcessorMsg::Scheduled(ScheduledCmd::SystemStateBackup))
        .await
        .expect("send cmd");

    // Give time to process and emit commands.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let cmds = drain_net_cmds(&mut net_cmd_rx);

    let send_message_count = cmds
        .iter()
        .filter(|c| matches!(c, NetCommand::SendMessage { .. }))
        .count();

    assert!(
        send_message_count >= 3,
        "expected at least 3 SendMessage commands, got {send_message_count}. cmds: {cmds:?}"
    );

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

/// system_state_backup_too_few_peers_skips_sending
///
/// When fewer than 3 peers have known node_ids, backup should not send anything.
#[tokio::test]
async fn system_state_backup_too_few_peers_skips_sending() {
    let (db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());
    let db2 = db.clone();
    let now = Timestamp::now();

    // Only 2 peers — below minimum of 3.
    for i in 1u8..=2 {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        bytes[31] = 0x01;
        let identity = IdentityPub(bytes);
        let record = make_peer_with_node_id(identity, i, now);
        db2.upsert_peer(&record).expect("upsert peer");
    }

    let (cancel, processor_tx, _dirty_tx, _net_event_tx, mut net_cmd_rx, handle) =
        spawn_processor(db, config);

    tokio::time::sleep(Duration::from_millis(10)).await;

    processor_tx
        .send(ProcessorMsg::Scheduled(ScheduledCmd::SystemStateBackup))
        .await
        .expect("send cmd");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let cmds = drain_net_cmds(&mut net_cmd_rx);
    let send_message_count = cmds
        .iter()
        .filter(|c| matches!(c, NetCommand::SendMessage { .. }))
        .count();

    assert_eq!(
        send_message_count, 0,
        "expected no SendMessage with fewer than 3 peers, got {send_message_count}"
    );

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

/// system_state_backup_received_stores_blob_from_known_peer
///
/// Holder processor receives SystemStateBackup from a known peer.
/// Blob should be stored in DB, ack sent via SendDirect.
#[tokio::test]
async fn system_state_backup_received_stores_blob_from_known_peer() {
    use syncback_core::messages::{DirectBody, DirectMessage, SystemStateBackupMsg};

    let (holder_db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());
    let holder_db2 = holder_db.clone();
    let now = Timestamp::now();

    // Register the owner peer in holder's DB.
    let mut owner_bytes = [0u8; 32];
    owner_bytes[0] = 77;
    let owner_identity = IdentityPub(owner_bytes);
    let owner_record = make_peer_record(owner_identity, now);
    holder_db2.upsert_peer(&owner_record).expect("upsert owner peer");

    let (cancel, _processor_tx, _dirty_tx, net_event_tx, mut net_cmd_rx, handle) =
        spawn_processor(holder_db.clone(), config);

    tokio::time::sleep(Duration::from_millis(10)).await;

    // Simulate owner sending SystemStateBackup to holder.
    let blob = vec![0u8; 100]; // Fake blob (small but non-empty).
    let msg = DirectMessage {
        v: syncback_core::constants::PROTOCOL_VERSION,
        body: DirectBody::SystemStateBackup(SystemStateBackupMsg {
            blob: blob.clone(),
            created_at: now.0,
        }),
    };
    net_event_tx
        .send(NetEvent::MessageReceived {
            from: owner_identity,
            message: msg,
        })
        .await
        .expect("send net event");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify blob stored in holder's DB.
    let stored = holder_db
        .get_system_state_blob(&owner_identity)
        .expect("get blob");
    assert!(stored.is_some(), "expected blob to be stored");
    assert_eq!(stored.unwrap().blob, blob);

    // Verify ack sent via SendDirect.
    let cmds = drain_net_cmds(&mut net_cmd_rx);
    let has_ack = cmds
        .iter()
        .any(|c| matches!(c, NetCommand::SendDirect { peer, .. } if *peer == owner_identity));
    assert!(has_ack, "expected SendDirect ack to owner");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

/// system_state_backup_received_rejects_from_unknown_peer
///
/// Holder receives SystemStateBackup from an unknown peer.
/// Should send ack(stored=false) and NOT store the blob.
#[tokio::test]
async fn system_state_backup_received_rejects_from_unknown_peer() {
    use syncback_core::messages::{DirectBody, DirectMessage, SystemStateBackupMsg};

    let (holder_db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());
    let holder_db2 = holder_db.clone();
    let now = Timestamp::now();

    // Unknown peer — NOT in DB.
    let mut unknown_bytes = [0u8; 32];
    unknown_bytes[0] = 99;
    let unknown_identity = IdentityPub(unknown_bytes);

    let (cancel, _processor_tx, _dirty_tx, net_event_tx, _net_cmd_rx, handle) =
        spawn_processor(holder_db.clone(), config);

    tokio::time::sleep(Duration::from_millis(10)).await;

    let msg = DirectMessage {
        v: syncback_core::constants::PROTOCOL_VERSION,
        body: DirectBody::SystemStateBackup(SystemStateBackupMsg {
            blob: vec![42u8; 50],
            created_at: now.0,
        }),
    };
    net_event_tx
        .send(NetEvent::MessageReceived {
            from: unknown_identity,
            message: msg,
        })
        .await
        .expect("send net event");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Blob should NOT be stored.
    let stored = holder_db2
        .get_system_state_blob(&unknown_identity)
        .expect("get blob");
    assert!(stored.is_none(), "expected blob NOT to be stored for unknown peer");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

/// system_state_request_found_returns_blob
///
/// Holder has a blob for owner. SystemStateRequest should return it via SendDirect.
#[tokio::test]
async fn system_state_request_found_returns_blob() {
    use syncback_core::messages::{DirectBody, DirectMessage, SystemStateRequestMsg};

    let (holder_db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());
    let holder_db2 = holder_db.clone();
    let now = Timestamp::now();

    let mut owner_bytes = [0u8; 32];
    owner_bytes[0] = 55;
    let owner_identity = IdentityPub(owner_bytes);

    // Pre-store a blob for owner.
    let blob = vec![1u8, 2, 3, 4, 5];
    holder_db2
        .store_system_state_blob(
            &owner_identity,
            &SystemStateBlobRecord {
                blob: blob.clone(),
                created_at: now,
                received_at: now,
            },
        )
        .expect("store blob");

    let (cancel, _processor_tx, _dirty_tx, net_event_tx, mut net_cmd_rx, handle) =
        spawn_processor(holder_db, config);

    tokio::time::sleep(Duration::from_millis(10)).await;

    // Owner sends SystemStateRequest.
    let msg = DirectMessage {
        v: syncback_core::constants::PROTOCOL_VERSION,
        body: DirectBody::SystemStateRequest(SystemStateRequestMsg {
            requester: owner_identity,
        }),
    };
    net_event_tx
        .send(NetEvent::MessageReceived {
            from: owner_identity,
            message: msg,
        })
        .await
        .expect("send");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let cmds = drain_net_cmds(&mut net_cmd_rx);
    let has_response = cmds
        .iter()
        .any(|c| matches!(c, NetCommand::SendDirect { peer, .. } if *peer == owner_identity));
    assert!(has_response, "expected SendDirect response to owner");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

/// system_state_request_not_found_returns_empty
///
/// Holder has NO blob for owner. SystemStateRequest should return empty blob via SendDirect.
#[tokio::test]
async fn system_state_request_not_found_returns_empty() {
    use syncback_core::messages::{DirectBody, DirectMessage, SystemStateRequestMsg};

    let (holder_db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());

    let mut owner_bytes = [0u8; 32];
    owner_bytes[0] = 44;
    let owner_identity = IdentityPub(owner_bytes);

    // No blob stored for owner.

    let (cancel, _processor_tx, _dirty_tx, net_event_tx, mut net_cmd_rx, handle) =
        spawn_processor(holder_db, config);

    tokio::time::sleep(Duration::from_millis(10)).await;

    let msg = DirectMessage {
        v: syncback_core::constants::PROTOCOL_VERSION,
        body: DirectBody::SystemStateRequest(SystemStateRequestMsg {
            requester: owner_identity,
        }),
    };
    net_event_tx
        .send(NetEvent::MessageReceived {
            from: owner_identity,
            message: msg,
        })
        .await
        .expect("send");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let cmds = drain_net_cmds(&mut net_cmd_rx);
    // A SendDirect command should be sent (the "not found" response).
    let has_response = cmds
        .iter()
        .any(|c| matches!(c, NetCommand::SendDirect { peer, .. } if *peer == owner_identity));
    assert!(has_response, "expected SendDirect response (empty) to owner");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

/// system_state_request_requester_mismatch_is_ignored
///
/// Peer C sends SystemStateRequest with requester=A (forged).
/// Holder should NOT send any response (requester != from).
#[tokio::test]
async fn system_state_request_requester_mismatch_is_ignored() {
    use syncback_core::messages::{DirectBody, DirectMessage, SystemStateRequestMsg};

    let (holder_db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());

    let mut a_bytes = [0u8; 32];
    a_bytes[0] = 0xAA;
    let a_identity = IdentityPub(a_bytes);

    let mut c_bytes = [0u8; 32];
    c_bytes[0] = 0xCC;
    let c_identity = IdentityPub(c_bytes);

    let (cancel, _processor_tx, _dirty_tx, net_event_tx, mut net_cmd_rx, handle) =
        spawn_processor(holder_db, config);

    tokio::time::sleep(Duration::from_millis(10)).await;

    // C sends a request claiming to be A.
    let msg = DirectMessage {
        v: syncback_core::constants::PROTOCOL_VERSION,
        body: DirectBody::SystemStateRequest(SystemStateRequestMsg {
            requester: a_identity, // forged — should be c_identity
        }),
    };
    net_event_tx
        .send(NetEvent::MessageReceived {
            from: c_identity,
            message: msg,
        })
        .await
        .expect("send");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // No response should have been sent to C or A.
    let cmds = drain_net_cmds(&mut net_cmd_rx);
    let response_count = cmds.iter().filter(|c| matches!(c, NetCommand::SendDirect { .. })).count();
    assert_eq!(
        response_count, 0,
        "expected no response to forged requester mismatch, got: {cmds:?}"
    );

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

/// dr_restore_rejects_wrong_seed_phrase
///
/// Processor has identity from entropy A. DrRestore with seed from entropy B
/// should fail with an error.
#[tokio::test]
async fn dr_restore_rejects_wrong_seed_phrase() {
    let (db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());

    // Entropy A → identity A.
    let entropy_a = [0u8; 32];
    let (_words_a, key_bytes_a, identity_a) = make_mnemonic(entropy_a);

    // Entropy B → identity B (different).
    let entropy_b = [1u8; 32];
    let (words_b, _key_bytes_b, _identity_b) = make_mnemonic(entropy_b);

    // Spawn processor with identity A.
    let signing_key_a = ed25519_dalek::SigningKey::from_bytes(&key_bytes_a);
    let (cancel, processor_tx, _dirty_tx, _net_event_tx, _net_cmd_rx, handle) =
        spawn_processor_with_identity(db, config, signing_key_a, identity_a);

    tokio::time::sleep(Duration::from_millis(10)).await;

    // Try DR restore with seed B (wrong seed for this daemon).
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    processor_tx
        .send(ProcessorMsg::Cli(CliCmd::DrRestore {
            seed_phrase: words_b,
            peer_addr: "{}".to_string(), // invalid addr (won't get there)
            reply: reply_tx,
        }))
        .await
        .expect("send");

    let result = tokio::time::timeout(Duration::from_secs(2), reply_rx)
        .await
        .expect("timeout")
        .expect("channel");

    assert!(
        result.is_err(),
        "expected error for wrong seed phrase, got: {result:?}"
    );
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("seed phrase does not match") || err_msg.contains("identity"),
        "unexpected error message: {err_msg}"
    );

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

/// system_state_backup_overwrites_old_blob
///
/// Holder receives two SystemStateBackup messages from the same owner.
/// Only the latest blob should be stored (overwrite semantics).
#[tokio::test]
async fn system_state_backup_overwrites_old_blob() {
    use syncback_core::messages::{DirectBody, DirectMessage, SystemStateBackupMsg};

    let (holder_db, dir) = test_db();
    let config = test_config(dir.path().to_path_buf());
    let holder_db2 = holder_db.clone();
    let now = Timestamp::now();

    let mut owner_bytes = [0u8; 32];
    owner_bytes[0] = 33;
    let owner_identity = IdentityPub(owner_bytes);

    // Register owner as a known peer.
    let owner_record = make_peer_record(owner_identity, now);
    holder_db2.upsert_peer(&owner_record).expect("upsert owner");

    let (cancel, _processor_tx, _dirty_tx, net_event_tx, _net_cmd_rx, handle) =
        spawn_processor(holder_db.clone(), config);

    tokio::time::sleep(Duration::from_millis(10)).await;

    // First backup.
    let blob_v1 = vec![1u8; 50];
    let msg_v1 = DirectMessage {
        v: syncback_core::constants::PROTOCOL_VERSION,
        body: DirectBody::SystemStateBackup(SystemStateBackupMsg {
            blob: blob_v1.clone(),
            created_at: 1000,
        }),
    };
    net_event_tx
        .send(NetEvent::MessageReceived {
            from: owner_identity,
            message: msg_v1,
        })
        .await
        .expect("send v1");

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second backup (newer).
    let blob_v2 = vec![2u8; 60];
    let msg_v2 = DirectMessage {
        v: syncback_core::constants::PROTOCOL_VERSION,
        body: DirectBody::SystemStateBackup(SystemStateBackupMsg {
            blob: blob_v2.clone(),
            created_at: 2000,
        }),
    };
    net_event_tx
        .send(NetEvent::MessageReceived {
            from: owner_identity,
            message: msg_v2,
        })
        .await
        .expect("send v2");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Only latest blob should be stored.
    let stored = holder_db
        .get_system_state_blob(&owner_identity)
        .expect("get blob")
        .expect("blob should be stored");

    assert_eq!(stored.blob, blob_v2, "expected latest blob (v2) to be stored");
    assert_eq!(stored.created_at.0, 2000, "expected latest created_at=2000");

    // Only one entry should exist.
    let all_owners = holder_db
        .list_system_state_blob_owners()
        .expect("list owners");
    let owner_count = all_owners.iter().filter(|(id, _)| *id == owner_identity).count();
    assert_eq!(owner_count, 1, "expected exactly 1 entry per owner");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
}

// ============================================================
// VirtualClock unit tests
// ============================================================

#[test]
fn virtual_clock_scale_1_approximates_real_time() {
    let clock = super::VirtualClock::new(1);
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let virtual_now = clock.now().0;
    assert!(
        virtual_now.abs_diff(real_now) <= 2,
        "virtual={virtual_now}, real={real_now}"
    );
}

#[test]
fn virtual_clock_advances_proportionally() {
    let scale = 100_u64;
    let clock = super::VirtualClock::new(scale);
    let t0 = clock.now().0;
    std::thread::sleep(std::time::Duration::from_millis(10));
    let t1 = clock.now().0;
    let delta = t1 - t0;
    assert!(delta <= 10, "unexpected large delta: {delta}s in 10ms real time");
}

#[test]
fn virtual_clock_scale_zero_treated_as_one() {
    let c0 = super::VirtualClock::new(0);
    let c1 = super::VirtualClock::new(1);
    let diff = c0.now().0.abs_diff(c1.now().0);
    assert!(diff <= 1, "scale=0 and scale=1 should produce same virtual time, diff={diff}");
}
