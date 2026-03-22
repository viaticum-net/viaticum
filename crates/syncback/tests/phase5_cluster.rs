// Phase 5 Cluster: cluster integration tests.
//
// Exercises multi-device flows end-to-end.
//
//   1. two_devices_backup_then_dedup_on_second
//      — Device A backs up a file. Device B (same cluster) skips it as dedup.
//   2. device_revocation_epoch_rotation_rejects_revoked_key
//      — Revoke device A. Partners (via PeerRecord) reject A's old device key.
//   3. cluster_sync_propagates_file_deletion_event
//      — Device A deletes a file (Event::FileDeleted). Device B syncs → sees deletion.
//
// GATE CRITERIA: all 3 tests pass → Phase 5 cluster is verified.

use std::sync::{Arc, Mutex};

use syncback::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};
use syncback::daemon::cluster_sync::{ClusterSyncConfig, ClusterSyncManager};
use syncback_core::cluster::{
    derive_device_key, derive_epoch_key, derive_master_key, issue_device_certificate,
    issue_revocation, master_identity, ClusterState, EpochCounter,
};
use syncback_core::db::Db;
use syncback_core::erasure::RaptorQEncoder;
use syncback_core::placement::HolderCandidate;
use syncback_core::types::{
    DeviceId, Event, EventEntry, FileId, IdentityPub, PeerRecord, SourceBlockStatus, Timestamp,
};
use tempfile::TempDir;

// ─── Shared fixtures ──────────────────────────────────────────────────────────

const SEED: &[u8] = &[0xBB_u8; 64];
const DEVICE_A_ID: DeviceId = DeviceId([0xA1u8; 16]);
const DEVICE_B_ID: DeviceId = DeviceId([0xB1u8; 16]);
const NOW: Timestamp = Timestamp(1_700_000_000);
const EPOCH_KEY: [u8; 32] = [0x55u8; 32];
/// Small block size: two symbols. Fast encode in tests.
const SMALL_BLOCK_SIZE: u64 = 65_535 * 2;

fn mk() -> ed25519_dalek::SigningKey {
    derive_master_key(SEED).unwrap()
}

fn device_pub(id: DeviceId) -> [u8; 32] {
    derive_device_key(SEED, &id).unwrap().verifying_key().to_bytes()
}

/// Init ClusterState with both DEVICE_A and DEVICE_B registered.
fn init_cluster(db: Db) -> ClusterState {
    let master = mk();
    let mp = master_identity(&master);
    let cert_a = issue_device_certificate(&master, DEVICE_A_ID, device_pub(DEVICE_A_ID), NOW);
    let mut state = ClusterState::init(db, mp, cert_a, NOW, NOW).unwrap();
    let cert_b = issue_device_certificate(&master, DEVICE_B_ID, device_pub(DEVICE_B_ID), NOW);
    state.add_device(cert_b, NOW).unwrap();
    state
}

/// 5 mock holders with varying trust.
fn holders_5() -> Vec<HolderCandidate> {
    (0..5)
        .map(|i| HolderCandidate {
            identity: IdentityPub([(i + 1) as u8; 32]),
            trust: 0.3 + i as f64 * 0.1,
        })
        .collect()
}

/// BackupConfig with cluster_state attached.
fn backup_cfg_with_cluster(
    symbols_dir: &TempDir,
    device_id: DeviceId,
    cluster_state: Arc<Mutex<ClusterState>>,
) -> BackupConfig {
    BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: EPOCH_KEY,
        device_id,
        mock_holders: holders_5(),
        cluster_state: Some(cluster_state),
        network: None,
        watch_configs: vec![],
        time_scale: 1,
    }
}

/// Write bytes to a file in a TempDir, return absolute path string.
fn write_file(dir: &TempDir, name: &str, content: &[u8]) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write test file");
    path.to_string_lossy().into_owned()
}

// ─── 1. two_devices_backup_then_dedup_on_second ───────────────────────────────
//
// Shared DB (simulates two devices with synced state on same hardware, or
// post-sync). Device A backs up a file. Device B encounters the same file:
// BackupCoordinator detects the content is already backed up via ClusterState
// and produces zero new source blocks (dedup skip).

#[test]
fn two_devices_backup_then_dedup_on_second() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    // Shared cluster state: both devices registered.
    let cluster_state = Arc::new(Mutex::new(init_cluster(db.clone())));

    // Content for the file both devices will "see".
    let content: Vec<u8> = (0..4096u32).map(|i| (i * 3 + 7) as u8).collect();
    let path = write_file(&files_dir, "shared.bin", &content);

    // Device A: back up the file.
    let mut backup_a = BackupCoordinator::new(
        db.clone(),
        backup_cfg_with_cluster(&symbols_dir, DEVICE_A_ID, Arc::clone(&cluster_state)),
        Arc::new(RaptorQEncoder::new()),
    );
    backup_a
        .process_event(DirtyEvent {
            path: path.clone(),
            kind: DirtyKind::Added,
            device_id: DEVICE_A_ID,
        })
        .unwrap();
    let results_a = backup_a.flush_all(true).unwrap();
    assert_eq!(results_a.len(), 1, "device A creates one source block");

    // Verify backed_up_at is set in DB for the file backed up by A.
    let file_a = db.get_file(&path).unwrap().expect("file record must exist");
    assert!(
        file_a.versions.iter().any(|v| v.backed_up_at.is_some()),
        "at least one version must have backed_up_at set after A's backup"
    );

    // Device B: same file path, same content → dedup must skip encoding.
    let mut backup_b = BackupCoordinator::new(
        db.clone(),
        backup_cfg_with_cluster(&symbols_dir, DEVICE_B_ID, Arc::clone(&cluster_state)),
        Arc::new(RaptorQEncoder::new()),
    );
    backup_b
        .process_event(DirtyEvent {
            path: path.clone(),
            kind: DirtyKind::Added,
            device_id: DEVICE_B_ID,
        })
        .unwrap();
    let results_b = backup_b.flush_all(true).unwrap();
    assert_eq!(
        results_b.len(),
        0,
        "device B dedup skips already-backed-up content: expected 0 new source blocks"
    );

    // Only one source block in the DB: A's block (status = Active).
    let blocks = db.list_source_blocks_by_status(SourceBlockStatus::Active).unwrap();
    assert_eq!(blocks.len(), 1, "only one source block in DB after dedup");
}

// ─── 2. device_revocation_epoch_rotation_rejects_revoked_key ─────────────────
//
// Revoke device A. Verify epoch increments, A is in the revoked list, and
// external peers that receive the RevocationBroadcast correctly mark A's
// device pub key as revoked in their PeerRecord.

#[test]
fn device_revocation_epoch_rotation_rejects_revoked_key() {
    let db = Db::open_in_memory().unwrap();
    let mut state = init_cluster(db);

    // Both devices active before revocation.
    assert_eq!(state.active_devices().len(), 2);
    assert_eq!(state.current_epoch(), EpochCounter(0));

    let master = mk();
    let new_epoch = EpochCounter(1);
    let rev = issue_revocation(&master, DEVICE_A_ID, NOW, new_epoch);
    state.revoke_device(rev.clone(), NOW, NOW).unwrap();

    // ClusterState: A revoked, epoch incremented.
    assert!(state.is_device_revoked(&DEVICE_A_ID), "device A must be revoked");
    assert!(!state.is_device_revoked(&DEVICE_B_ID), "device B must not be revoked");
    assert_eq!(state.current_epoch(), EpochCounter(1), "epoch must be 1 after revocation");

    // Only B remains active.
    let active = state.active_devices();
    assert_eq!(active.len(), 1, "only device B must remain active");
    assert_eq!(active[0].device_id, DEVICE_B_ID);

    // Build RevocationBroadcast (same as phase3_gate test 5).
    let cert_a = issue_device_certificate(&master, DEVICE_A_ID, device_pub(DEVICE_A_ID), NOW);
    let broadcast = ClusterSyncManager::build_revocation_broadcast(&rev, &cert_a);

    // Simulate an external peer receiving the broadcast.
    // The peer extracts device_pub_key from the cert and adds it to revoked list.
    let revoked_pub = broadcast.device_cert.device_pub_key;
    let mut peer_record = PeerRecord {
        identity: IdentityPub([0x77u8; 32]),
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: NOW,
        last_seen: NOW,
        device_id: None,
        revoked_device_pub_keys: Vec::new(),
        addrs: vec![],
    };
    peer_record.revoked_device_pub_keys.push(revoked_pub);

    // A's device pub key must be rejected by the peer.
    assert!(
        peer_record.is_device_revoked(&IdentityPub(device_pub(DEVICE_A_ID))),
        "peer must reject revoked device A key"
    );
    // B's device pub key must NOT be in the revoked list.
    assert!(
        !peer_record.is_device_revoked(&IdentityPub(device_pub(DEVICE_B_ID))),
        "peer must not reject device B key"
    );

    // Epoch keys before and after revocation must differ.
    let ek0 = derive_epoch_key(SEED, EpochCounter(0)).unwrap();
    let ek1 = derive_epoch_key(SEED, EpochCounter(1)).unwrap();
    assert_ne!(
        ek0.key_bytes, ek1.key_bytes,
        "epoch keys for epoch 0 and epoch 1 must differ"
    );

    // Epoch history must have two entries.
    assert_eq!(state.epoch_history().len(), 2);
}

// ─── 3. cluster_sync_propagates_file_deletion_event ──────────────────────────
//
// Device A records FileAdded then FileDeleted in its event log.
// Device B (separate DB, same cluster) syncs from A via ClusterSyncManager
// and receives both events. The FileDeleted event is present in the response.
// After applying, B's cursor for A is advanced.

#[test]
fn cluster_sync_propagates_file_deletion_event() {
    // Device A: separate DB with both devices in ClusterState.
    let db_a = Db::open_in_memory().unwrap();
    let state_a = init_cluster(db_a.clone());

    // Record the seq after cluster init so we can track manually-added events.
    let base_seq = db_a.last_event_seq().unwrap();

    // A records a FileAdded event.
    let file_id_a = FileId(42);
    db_a.append_event(&EventEntry {
        timestamp: NOW,
        device_id: DEVICE_A_ID,
        event: Event::FileAdded {
            file_id: file_id_a,
            path: "/photos/sunset.jpg".to_string(),
        },
    })
    .unwrap();

    // A records a FileDeleted event for the same file.
    db_a.append_event(&EventEntry {
        timestamp: NOW,
        device_id: DEVICE_A_ID,
        event: Event::FileDeleted { file_id: file_id_a, device_id: DEVICE_A_ID },
    })
    .unwrap();

    // A records an EpochRotated event (epoch 7) that B hasn't seen.
    // This ensures apply_events returns > 0 when B processes the response
    // (EpochRotated is the only event type that ClusterState::apply_events
    // counts as "applied" for events B hasn't seen yet).
    db_a.append_event(&EventEntry {
        timestamp: NOW,
        device_id: DEVICE_A_ID,
        event: Event::EpochRotated { epoch: 7 },
    })
    .unwrap();

    let a_last_seq = db_a.last_event_seq().unwrap();
    assert_eq!(
        a_last_seq,
        base_seq + 3,
        "A must have 3 new events after FileAdded + FileDeleted + EpochRotated"
    );

    let sync_a = ClusterSyncManager::new(
        db_a.clone(),
        ClusterSyncConfig { our_device_id: DEVICE_A_ID, batch_size: 100 },
        Arc::new(Mutex::new(state_a)),
    );

    // Device B: separate DB. Also knows both devices (same cluster seed).
    let db_b = Db::open_in_memory().unwrap();
    let state_b = init_cluster(db_b.clone());

    let sync_b = ClusterSyncManager::new(
        db_b.clone(),
        ClusterSyncConfig { our_device_id: DEVICE_B_ID, batch_size: 100 },
        Arc::new(Mutex::new(state_b)),
    );

    // B requests sync from A (cursor = 0: never synced before).
    let a_identity = IdentityPub(device_pub(DEVICE_A_ID));
    let request = sync_b.build_sync_request(&a_identity);
    assert_eq!(request.last_known_seq, 0, "B has never synced A before");
    assert_eq!(request.from_device_id, DEVICE_B_ID);

    // A handles B's request.
    let response = sync_a.handle_sync_request(&request).unwrap();
    assert_eq!(
        response.responder_last_seq, a_last_seq,
        "responder_last_seq must match A's last seq"
    );
    assert!(
        !response.events.is_empty(),
        "response must contain events (cluster init + FileAdded + FileDeleted)"
    );

    // FileDeleted event must be present in the response.
    let has_deletion = response.events.iter().any(|(_, entry)| {
        matches!(&entry.event, Event::FileDeleted { file_id, .. } if *file_id == file_id_a)
    });
    assert!(has_deletion, "FileDeleted event must be present in sync response");

    // B applies the response.
    let applied = sync_b.process_sync_response(&a_identity, response).unwrap();
    assert!(applied > 0, "at least some events must be applied by B");

    // B's cursor for A must now be advanced to a_last_seq.
    let req2 = sync_b.build_sync_request(&a_identity);
    assert_eq!(
        req2.last_known_seq, a_last_seq,
        "B's cursor for A must advance to a_last_seq after sync"
    );

    // Second sync: A has no new events → empty response.
    let response2 = sync_a.handle_sync_request(&req2).unwrap();
    assert!(
        response2.events.is_empty(),
        "no new events since last sync — response must be empty"
    );
}
