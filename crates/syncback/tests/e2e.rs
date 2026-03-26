// E2E: full lifecycle test — backup → version → selective restore →
//      cluster → dedup → revocation → deletion.
//
// One test function covers the complete SyncBack β user story.
// No network, no filesystem watcher — direct API calls only.
//
// Run with: cargo test -p syncback --test e2e -- --nocapture

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use syncback::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};
use syncback::daemon::network::{NetworkConfig, NetworkHandle};
use syncback::daemon::restore::{RestoreConfig, RestoreCoordinator, RestoreRequest, VersionSelector};
use syncback_core::cluster::{
    derive_device_key, derive_epoch_key, derive_master_key, issue_device_certificate,
    issue_revocation, master_identity, ClusterState, EpochCounter,
};
use syncback_core::constants::OWNER_DELETE_COOLDOWN_SECS;
use syncback_core::db::Db;
use syncback_core::deletion::{DeletionAction, DeletionEngine, MarkDeletedResult};
use syncback_core::erasure::RaptorQEncoder;
use syncback_core::placement::HolderCandidate;
use syncback_core::types::{DeviceId, IdentityPub, LocalState, PeerRecord, Timestamp};
use tempfile::TempDir;

// ─── Shared fixtures ──────────────────────────────────────────────────────────

const SEED: &[u8] = &[0xCC_u8; 64];
const DEVICE_A: DeviceId = DeviceId([0xA0u8; 16]);
const DEVICE_B: DeviceId = DeviceId([0xB0u8; 16]);
const EPOCH_KEY: [u8; 32] = [0x42u8; 32];
/// Small source block size so all small test files fit within one block.
const SMALL_BLOCK_SIZE: u64 = 65_535 * 2;
const NOW: Timestamp = Timestamp(1_700_000_000);

fn test_holders() -> Vec<HolderCandidate> {
    (0..5)
        .map(|i| HolderCandidate {
            identity: IdentityPub([(i + 1) as u8; 32]),
            trust: 0.3 + (i as f64) * 0.1,
        })
        .collect()
}

fn backup_config(symbols_dir: &TempDir) -> BackupConfig {
    BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: EPOCH_KEY,
        device_id: DEVICE_A,
        mock_holders: test_holders(),
        cluster_state: None,
        network: None,
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: None,
    }
}

fn restore_config(symbols_dir: &TempDir) -> RestoreConfig {
    RestoreConfig {
        epoch_key: EPOCH_KEY,
        parallel_holders: 5,
        identity: IdentityPub([0x99u8; 32]),
        device_id: DEVICE_B,
        symbols_dir: symbols_dir.path().to_path_buf(),
    }
}

fn write_file(dir: &TempDir, name: &str, content: &[u8]) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write test file");
    path.to_string_lossy().into_owned()
}

async fn make_network_handle() -> NetworkHandle {
    let sk = SigningKey::generate(&mut OsRng);
    let mi = IdentityPub(sk.verifying_key().to_bytes());
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    NetworkHandle::start(
        NetworkConfig {
            signing_key: sk,
            master_identity: mi,
            known_peers: HashMap::new(),
            device_cert: None,
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
            x25519_pub: None,
        },
        tx,
    )
    .await
    .expect("NetworkHandle::start")
}

fn device_pub_bytes(device_id: DeviceId) -> [u8; 32] {
    derive_device_key(SEED, &device_id)
        .unwrap()
        .verifying_key()
        .to_bytes()
}

fn init_cluster(db: Db) -> ClusterState {
    let master = derive_master_key(SEED).unwrap();
    let mp = master_identity(&master);
    let cert_a = issue_device_certificate(&master, DEVICE_A, device_pub_bytes(DEVICE_A), NOW);
    let mut state = ClusterState::init(db, mp, cert_a, NOW, NOW).unwrap();
    let cert_b = issue_device_certificate(&master, DEVICE_B, device_pub_bytes(DEVICE_B), NOW);
    state.add_device(cert_b, NOW).unwrap();
    state
}

// ─── Full lifecycle E2E test ──────────────────────────────────────────────────

#[tokio::test]
async fn full_lifecycle_e2e() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    // ── Step 1: Backup 3 files ────────────────────────────────────────────────
    //
    // photo.jpg    — 8 KB (Photo category, importance=0.8)
    // document.txt — 2 KB (Document category, importance=0.5)
    // archive.tar  — 16 KB (Other category, importance=0.3)

    let original_photo: Vec<u8> = (0..8192u32).map(|i| (i * 7 + 3) as u8).collect();
    let photo_path = write_file(&files_dir, "photo.jpg", &original_photo);

    let doc_content: Vec<u8> = b"This is the document content. "
        .iter()
        .cycle()
        .take(2048)
        .copied()
        .collect();
    let doc_path = write_file(&files_dir, "document.txt", &doc_content);

    let archive_content: Vec<u8> = (0..16384u32).map(|i| (i * 11 + 7) as u8).collect();
    let archive_path = write_file(&files_dir, "archive.tar", &archive_content);

    let mut backup = BackupCoordinator::new(
        db.clone(),
        backup_config(&symbols_dir),
        Arc::new(RaptorQEncoder::new()),
    );

    backup
        .process_event(DirtyEvent {
            path: photo_path.clone(),
            kind: DirtyKind::Added,
            device_id: DEVICE_A,
        })
        .unwrap();
    backup
        .process_event(DirtyEvent {
            path: doc_path.clone(),
            kind: DirtyKind::Added,
            device_id: DEVICE_A,
        })
        .unwrap();
    backup
        .process_event(DirtyEvent {
            path: archive_path.clone(),
            kind: DirtyKind::Added,
            device_id: DEVICE_A,
        })
        .unwrap();

    let results = backup.flush_all(true).unwrap();
    assert!(!results.is_empty(), "at least one source block created");

    let all_files = db.list_all_files().unwrap();
    assert_eq!(all_files.len(), 3, "all 3 files must be in DB");
    for f in &all_files {
        assert!(
            f.versions.first().and_then(|v| v.backed_up_at).is_some(),
            "file must be backed up: {}",
            f.path
        );
    }

    let blocks_after_step1 = db.list_all_source_blocks().unwrap().len();
    eprintln!("[E2E] Step 1: 3 files backed up ({} source blocks)", blocks_after_step1);

    // ── Step 2: Modify photo.jpg → creates second version ────────────────────

    let new_photo_content: Vec<u8> =
        (0..8192u32).map(|i| ((i * 13 + 5) % 256) as u8).collect();
    std::fs::write(&photo_path, &new_photo_content).unwrap();

    backup
        .process_event(DirtyEvent {
            path: photo_path.clone(),
            kind: DirtyKind::Modified,
            device_id: DEVICE_A,
        })
        .unwrap();
    backup.flush_all(true).unwrap();

    let photo_record = db
        .get_file(&photo_path)
        .unwrap()
        .expect("photo must exist in DB");
    assert_eq!(
        photo_record.versions.len(),
        2,
        "photo must have 2 versions after modification"
    );
    let v0_hash = photo_record.versions[0].content_hash;
    let v1_hash = photo_record.versions[1].content_hash;
    assert_ne!(v0_hash, v1_hash, "versions must have different content hashes");

    eprintln!("[E2E] Step 2: photo.jpg has 2 versions, content hashes differ");

    // ── Step 3: Selective restore ─────────────────────────────────────────────

    let network = Arc::new(make_network_handle().await);
    let restore = RestoreCoordinator::new(
        db.clone(),
        restore_config(&symbols_dir),
        Arc::new(RaptorQEncoder::new()),
        network,
    );

    // 3a — restore photo.jpg at Latest version → must be v1 (new_photo_content)
    let out_latest = TempDir::new().unwrap();
    let result_latest = restore
        .restore(RestoreRequest {
            path: photo_path.clone(),
            version_selector: VersionSelector::Latest,
            output_dir: out_latest.path().to_path_buf(),
            device_id: DEVICE_B,
        })
        .await
        .unwrap();
    assert_eq!(
        result_latest.files_restored,
        1,
        "Latest restore failures: {:?}",
        result_latest.failures
    );
    assert!(result_latest.failures.is_empty());
    let rel = photo_path.trim_start_matches('/');
    let restored_latest = std::fs::read(out_latest.path().join(rel)).unwrap();
    assert_eq!(
        restored_latest, new_photo_content,
        "Latest restore must return v1 (modified) content"
    );

    eprintln!("[E2E] Step 3a: Latest restore — byte-for-byte match (v1)");

    // 3b — restore photo.jpg at Index(0) → must be v0 (original_photo)
    let out_v0 = TempDir::new().unwrap();
    let result_v0 = restore
        .restore(RestoreRequest {
            path: photo_path.clone(),
            version_selector: VersionSelector::Index(0),
            output_dir: out_v0.path().to_path_buf(),
            device_id: DEVICE_B,
        })
        .await
        .unwrap();
    assert_eq!(
        result_v0.files_restored,
        1,
        "Index(0) restore failures: {:?}",
        result_v0.failures
    );
    assert!(result_v0.failures.is_empty());
    let restored_v0 = std::fs::read(out_v0.path().join(rel)).unwrap();
    assert_eq!(
        restored_v0, original_photo,
        "Index(0) restore must return v0 (original) content"
    );

    eprintln!("[E2E] Step 3b: Version(0) restore — byte-for-byte match (v0)");

    // 3c — restore by directory prefix → all 3 files
    let out_all = TempDir::new().unwrap();
    let prefix = files_dir.path().to_string_lossy().to_string() + "/";
    let result_all = restore
        .restore(RestoreRequest {
            path: prefix,
            version_selector: VersionSelector::Latest,
            output_dir: out_all.path().to_path_buf(),
            device_id: DEVICE_B,
        })
        .await
        .unwrap();
    assert_eq!(
        result_all.files_restored,
        3,
        "directory restore failures: {:?}",
        result_all.failures
    );
    assert!(result_all.failures.is_empty());

    eprintln!("[E2E] Step 3c: directory restore — 3 files restored");

    // ── Step 4: Add second device → verify dedup ──────────────────────────────
    //
    // Device B tries to back up a file with the same content as the already-backed-up
    // new_photo_content (v1 backed up by Device A in Step 2).
    // The BackupCoordinator with cluster_state must skip it (dedup = 0 new blocks).

    let cluster_state = Arc::new(Mutex::new(init_cluster(db.clone())));

    let files_dir_b = TempDir::new().unwrap();
    let b_photo_path = write_file(&files_dir_b, "photo.jpg", &new_photo_content);

    let mut backup_b = BackupCoordinator::new(
        db.clone(),
        BackupConfig {
            source_block_size: SMALL_BLOCK_SIZE,
            symbols_dir: symbols_dir.path().to_path_buf(),
            epoch_key: EPOCH_KEY,
            device_id: DEVICE_B,
            mock_holders: test_holders(),
            cluster_state: Some(Arc::clone(&cluster_state)),
            network: None,
            watch_configs: vec![],
            time_scale: 1,
            mock_offer_budget_gb: None,
        },
        Arc::new(RaptorQEncoder::new()),
    );

    let blocks_before_b = db.list_all_source_blocks().unwrap().len();

    backup_b
        .process_event(DirtyEvent {
            path: b_photo_path.clone(),
            kind: DirtyKind::Added,
            device_id: DEVICE_B,
        })
        .unwrap();
    let results_b = backup_b.flush_all(true).unwrap();

    assert_eq!(
        results_b.len(),
        0,
        "device B dedup: no new source blocks for already-backed-up content"
    );
    let blocks_after_b = db.list_all_source_blocks().unwrap().len();
    assert_eq!(
        blocks_after_b, blocks_before_b,
        "total block count must not change after dedup"
    );

    eprintln!("[E2E] Step 4: dedup — 0 new source blocks for device B");

    // ── Step 5: Revoke device B → verify key rejection ────────────────────────

    let master = derive_master_key(SEED).unwrap();
    let new_epoch = EpochCounter(1);
    let rev = issue_revocation(&master, DEVICE_B, NOW, new_epoch);

    {
        let mut state = cluster_state.lock().unwrap();
        state.revoke_device(rev, NOW, NOW).unwrap();

        assert!(state.is_device_revoked(&DEVICE_B), "B must be revoked");
        assert!(!state.is_device_revoked(&DEVICE_A), "A must not be revoked");
        assert_eq!(state.current_epoch(), EpochCounter(1), "epoch must be 1");
    }

    // Epoch keys must differ before and after rotation
    let ek0 = derive_epoch_key(SEED, EpochCounter(0)).unwrap();
    let ek1 = derive_epoch_key(SEED, EpochCounter(1)).unwrap();
    assert_ne!(
        ek0.key_bytes, ek1.key_bytes,
        "epoch keys must differ after revocation"
    );

    // An external peer that learns about the revocation can store B's device
    // pub key in its revoked list and reject further connections from B.
    let b_device_pub = device_pub_bytes(DEVICE_B);
    let a_device_pub = device_pub_bytes(DEVICE_A);
    let mut peer = PeerRecord {
        identity: IdentityPub([0xFFu8; 32]),
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: NOW,
        last_seen: NOW,
        device_id: None,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    };
    peer.revoked_device_pub_keys.push(b_device_pub);

    assert!(
        peer.is_device_revoked(&IdentityPub(b_device_pub)),
        "peer must reject B's device pub key"
    );
    assert!(
        !peer.is_device_revoked(&IdentityPub(a_device_pub)),
        "peer must not reject A's device pub key"
    );

    eprintln!("[E2E] Step 5: device B revoked, epoch=1, peer rejects B's key");

    // ── Step 6: Delete document.txt → verify cooldown → SendDropNotice ───────

    let engine = DeletionEngine::new();

    // Re-read document.txt: Step 3c (directory restore) added DEVICE_B as Present.
    // Both devices must be in Deleted state before mark_deleted returns CooldownStarted.
    let doc_record = db
        .get_file(&doc_path)
        .unwrap()
        .expect("document.txt must be in DB");

    // Mark DEVICE_B deleted first so the record no longer blocks DEVICE_A.
    // (In production, watcher would emit Deleted events on each device.)
    let mut doc_b_deleted = doc_record.clone();
    for (id, state) in &mut doc_b_deleted.devices {
        if *id == DEVICE_B {
            *state = LocalState::Deleted(NOW);
        }
    }
    db.upsert_file(&doc_b_deleted).unwrap();

    // Now re-read and mark DEVICE_A deleted: all devices are Deleted → CooldownStarted
    let doc_record_fresh = db
        .get_file(&doc_path)
        .unwrap()
        .expect("document.txt must be in DB");
    let del_result = engine.mark_deleted(&doc_record_fresh, DEVICE_A, NOW).unwrap();
    assert!(
        matches!(del_result, MarkDeletedResult::CooldownStarted { .. }),
        "all-devices-deleted must start cooldown: got {:?}",
        del_result
    );
    if let MarkDeletedResult::CooldownStarted { notify_after, .. } = del_result {
        assert_eq!(
            notify_after.0,
            NOW.0 + OWNER_DELETE_COOLDOWN_SECS,
            "notify_after must equal NOW + OWNER_DELETE_COOLDOWN_SECS"
        );
    }

    // Persist DEVICE_A as Deleted(NOW) too
    let mut updated_doc = doc_record_fresh.clone();
    for (id, state) in &mut updated_doc.devices {
        if *id == DEVICE_A {
            *state = LocalState::Deleted(NOW);
        }
    }
    db.upsert_file(&updated_doc).unwrap();

    // Before cooldown expires: no drop/cleanup actions for this file.
    // (VacuumBlock actions may appear for unrelated blocks — those are expected
    // because other Pack blocks in the DB may have all files deleted after the
    // multi-device scenario above. We only assert that no SendDropNotice is generated.)
    let all_blocks = db.list_all_source_blocks().unwrap();
    let all_placements: Vec<_> = all_blocks
        .iter()
        .flat_map(|b| db.list_placements_for_block(&b.block_id).unwrap())
        .collect();
    let pre_actions =
        engine.process_cooldowns(&[updated_doc.clone()], &all_blocks, &all_placements, NOW, 1);
    let pre_drop_notices: Vec<_> = pre_actions
        .iter()
        .filter(|a| matches!(a, DeletionAction::SendDropNotice { .. }))
        .collect();
    assert!(
        pre_drop_notices.is_empty(),
        "no SendDropNotice before cooldown expires: got {:?}",
        pre_drop_notices
    );

    // After owner cooldown expires: SendDropNotice for each holder of doc's blocks
    let after_owner = Timestamp(NOW.0 + OWNER_DELETE_COOLDOWN_SECS + 1);
    let post_actions =
        engine.process_cooldowns(&[updated_doc], &all_blocks, &all_placements, after_owner, 1);
    let drop_notices: Vec<_> = post_actions
        .iter()
        .filter(|a| matches!(a, DeletionAction::SendDropNotice { .. }))
        .collect();
    assert!(
        !drop_notices.is_empty(),
        "SendDropNotice actions must be generated after owner cooldown expires"
    );

    eprintln!(
        "[E2E] Step 6: delete cooldown — {} drop notices generated after 4 weeks",
        drop_notices.len()
    );
    eprintln!("[E2E] ALL STEPS PASSED");
}
