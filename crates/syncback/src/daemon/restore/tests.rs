// Tests for RestoreCoordinator.
// Pattern: what_when_then.
//
// All tests use real Db::open_in_memory(), real RaptorQEncoder, tempfile::TempDir.
// Source block size is small (65_535 * 2 = ~128 KB) to keep encode/decode fast.
// Async tests use #[tokio::test].

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use syncback_core::db::Db;
use syncback_core::erasure::RaptorQEncoder;
use syncback_core::types::{
    DeviceId, FileId, FileRecord, FileVersion, IdentityPub, LocalState, PackEntry, SourceBlockId,
    Timestamp,
};
use syncback_core::types::to_cbor_bytes;
use tempfile::TempDir;

use crate::daemon::backup::{
    BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind,
};
use crate::daemon::network::{NetworkConfig, NetworkHandle};

use super::{RestoreConfig, RestoreCoordinator, VersionSelector};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Small source block size for fast tests (2 * SYMBOL_SIZE = ~128 KB).
const SMALL_BLOCK_SIZE: u64 = 65_535 * 2;
const TEST_EPOCH_KEY: [u8; 32] = [42u8; 32];

/// Build mock holders for backup tests.
fn test_holders() -> Vec<syncback_core::placement::HolderCandidate> {
    (0..5)
        .map(|i| syncback_core::placement::HolderCandidate {
            identity: IdentityPub([(i + 1) as u8; 32]),
            trust: 0.3 + (i as f64) * 0.1,
        })
        .collect()
}

/// Build a BackupCoordinator pointing at symbols_dir and a given db.
fn test_backup_coord(db: Db, symbols_dir: &TempDir) -> BackupCoordinator {
    let config = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: TEST_EPOCH_KEY,
        device_id: DeviceId([1u8; 16]),
        mock_holders: test_holders(),
        cluster_state: None,
        network: None,
    };
    BackupCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()))
}

/// Build a RestoreCoordinator for Phase 2 (local) tests.
/// Creates a throwaway NetworkHandle; not used in local restore.
async fn test_restore_coord(
    db: Db,
    symbols_dir: &TempDir,
) -> (RestoreCoordinator, NetworkHandle) {
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let config_net = NetworkConfig {
        signing_key: signing_key.clone(),
        known_peers: Default::default(),
        device_cert: None,
        iroh_secret_key: None,
        relay_mode: iroh::RelayMode::Disabled,
    };
    let network = NetworkHandle::start(config_net, tx)
        .await
        .expect("NetworkHandle::start in test");

    let restore_config = RestoreConfig {
        epoch_key: TEST_EPOCH_KEY,
        parallel_holders: 5,
        identity: IdentityPub([9u8; 32]),
        device_id: DeviceId([2u8; 16]),
        symbols_dir: symbols_dir.path().to_path_buf(),
    };

    let coord = RestoreCoordinator::new(
        db,
        restore_config,
        Arc::new(RaptorQEncoder::new()),
        Arc::new(network),
    );
    // We can't return network because it was moved into Arc; just return coord
    // with a second one for shutdown if needed. For tests, leaking is fine.
    let signing_key2 = SigningKey::from_bytes(&[10u8; 32]);
    let (tx2, _rx2) = tokio::sync::mpsc::channel(1);
    let net2 = NetworkHandle::start(
        NetworkConfig {
            signing_key: signing_key2,
            known_peers: Default::default(),
            device_cert: None,
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
        },
        tx2,
    )
    .await
    .expect("NetworkHandle::start in test 2");

    (coord, net2)
}

/// Write a file to a TempDir and return its absolute path string.
fn write_file(dir: &TempDir, name: &str, content: &[u8]) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write test file");
    path.to_string_lossy().into_owned()
}

/// Create an Added DirtyEvent.
fn added_event(path: &str) -> DirtyEvent {
    DirtyEvent {
        path: path.to_string(),
        kind: DirtyKind::Added,
        device_id: DeviceId([1u8; 16]),
    }
}

// ─── Version selector tests (pure, no IO) ─────────────────────────────────────

/// Build a minimal FileRecord with given versions for selector tests.
fn make_record_with_versions(versions: Vec<FileVersion>) -> FileRecord {
    FileRecord {
        file_id: FileId(1),
        path: "/test/file.txt".to_string(),
        importance: 0.5,
        devices: vec![],
        versions,
        first_seen: Timestamp(0),
    }
}

fn make_version(backed_up_at: Option<u64>) -> FileVersion {
    FileVersion {
        content_hash: [0u8; 32],
        source_block_id: SourceBlockId([0u8; 32]),
        k: 2,
        t: 65_535,
        created_at: Timestamp(100),
        backed_up_at: backed_up_at.map(Timestamp),
    }
}

#[test]
fn select_version_latest_returns_last_backed_up() {
    let record = make_record_with_versions(vec![
        make_version(Some(100)),
        make_version(Some(200)),
        make_version(None), // queued but not yet backed up
    ]);
    let result = RestoreCoordinator::select_version(&record, &VersionSelector::Latest);
    assert!(result.is_some());
    assert_eq!(result.unwrap().backed_up_at, Some(Timestamp(200)));
}

#[test]
fn select_version_latest_returns_none_when_none_backed_up() {
    let record = make_record_with_versions(vec![make_version(None)]);
    let result = RestoreCoordinator::select_version(&record, &VersionSelector::Latest);
    assert!(result.is_none());
}

#[test]
fn select_version_index_returns_nth() {
    let versions = vec![
        make_version(Some(100)),
        make_version(Some(500)),
        make_version(Some(900)),
    ];
    let record = make_record_with_versions(versions);
    let result = RestoreCoordinator::select_version(&record, &VersionSelector::Index(1));
    assert!(result.is_some());
    assert_eq!(result.unwrap().backed_up_at, Some(Timestamp(500)));
}

#[test]
fn select_version_index_out_of_range_returns_none() {
    let record = make_record_with_versions(vec![make_version(Some(100))]);
    let result = RestoreCoordinator::select_version(&record, &VersionSelector::Index(5));
    assert!(result.is_none());
}

#[test]
fn select_version_before_date_returns_correct_version() {
    let record = make_record_with_versions(vec![
        make_version(Some(100)),
        make_version(Some(300)),
        make_version(Some(500)),
    ]);
    let result = RestoreCoordinator::select_version(
        &record,
        &VersionSelector::BeforeDate(Timestamp(400)),
    );
    assert!(result.is_some());
    assert_eq!(result.unwrap().backed_up_at, Some(Timestamp(300)));
}

#[test]
fn select_version_before_date_exact_match() {
    let record = make_record_with_versions(vec![
        make_version(Some(100)),
        make_version(Some(400)),
        make_version(Some(700)),
    ]);
    // Timestamp(400) should match exactly.
    let result = RestoreCoordinator::select_version(
        &record,
        &VersionSelector::BeforeDate(Timestamp(400)),
    );
    assert!(result.is_some());
    assert_eq!(result.unwrap().backed_up_at, Some(Timestamp(400)));
}

#[test]
fn select_version_before_date_returns_none_when_all_after() {
    let record = make_record_with_versions(vec![make_version(Some(500)), make_version(Some(600))]);
    let result = RestoreCoordinator::select_version(
        &record,
        &VersionSelector::BeforeDate(Timestamp(100)),
    );
    assert!(result.is_none());
}

// ─── extract_from_pack tests ──────────────────────────────────────────────────

#[test]
fn extract_from_pack_finds_file_by_id() {
    let entries: Vec<PackEntry> = vec![
        PackEntry {
            file_id: FileId(1),
            offset: 0,
            size: 5,
        },
        PackEntry {
            file_id: FileId(2),
            offset: 5,
            size: 8,
        },
    ];
    let cbor_bytes = to_cbor_bytes(&entries);
    let file1 = b"hello";
    let file2 = b"world!!!";

    let mut plaintext = cbor_bytes;
    plaintext.extend_from_slice(file1);
    plaintext.extend_from_slice(file2);

    let result1 = super::pipeline::extract_from_pack(&plaintext, FileId(1)).unwrap();
    assert_eq!(result1, Some(b"hello".to_vec()));

    let result2 = super::pipeline::extract_from_pack(&plaintext, FileId(2)).unwrap();
    assert_eq!(result2, Some(b"world!!!".to_vec()));
}

#[test]
fn extract_from_pack_unknown_file_id_returns_none() {
    let entries: Vec<PackEntry> = vec![PackEntry {
        file_id: FileId(1),
        offset: 0,
        size: 4,
    }];
    let cbor_bytes = to_cbor_bytes(&entries);
    let mut plaintext = cbor_bytes;
    plaintext.extend_from_slice(b"data");

    let result = super::pipeline::extract_from_pack(&plaintext, FileId(99)).unwrap();
    assert!(result.is_none());
}

// ─── Roundtrip tests (backup → restore) ──────────────────────────────────────

#[tokio::test]
async fn restore_single_file_by_exact_path() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();

    // Backup one file
    let content = b"single file content for restore test";
    let path = write_file(&files_dir, "single.txt", content);
    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path)).unwrap();
    let results = backup.flush_all(true).unwrap();
    assert!(!results.is_empty(), "should have produced at least one block");

    // Restore
    let (restore, _net) = test_restore_coord(db.clone(), &symbols_dir).await;
    let request = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        output_dir: out_dir.path().to_path_buf(),
        device_id: DeviceId([2u8; 16]),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(result.files_restored, 1, "failures: {:?}", result.failures);
    assert!(result.failures.is_empty());

    // Verify content
    let rel = path.trim_start_matches('/');
    let out_file = out_dir.path().join(rel);
    let restored = std::fs::read(&out_file).unwrap();
    assert_eq!(restored, content);
}

#[tokio::test]
async fn restore_pack_multiple_files_roundtrip() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();

    // Backup 3 files into one pack
    let contents: Vec<(&str, &[u8])> = vec![
        ("file0.txt", b"file content 0"),
        ("file1.txt", b"file content 1"),
        ("file2.txt", b"file content 2"),
    ];

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    let mut paths = Vec::new();
    for (name, content) in &contents {
        let path = write_file(&files_dir, name, content);
        backup.process_event(added_event(&path)).unwrap();
        paths.push(path);
    }
    let results = backup.flush_all(true).unwrap();
    assert!(!results.is_empty(), "should have produced blocks");

    // Restore all 3 using prefix (the files_dir path as prefix)
    let (restore, _net) = test_restore_coord(db.clone(), &symbols_dir).await;
    let prefix = files_dir.path().to_string_lossy().to_string() + "/";
    let request = super::RestoreRequest {
        path: prefix,
        version_selector: VersionSelector::Latest,
        output_dir: out_dir.path().to_path_buf(),
        device_id: DeviceId([2u8; 16]),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(
        result.files_restored, 3,
        "failures: {:?}", result.failures
    );
    assert!(result.failures.is_empty());

    // Verify contents
    for (name, content) in &contents {
        let full_path = files_dir.path().join(name);
        let rel = full_path.to_string_lossy();
        let rel = rel.trim_start_matches('/');
        let out_file = out_dir.path().join(rel);
        let restored = std::fs::read(&out_file).unwrap();
        assert_eq!(&restored, content, "content mismatch for {}", name);
    }
}

#[tokio::test]
async fn restore_specific_version_by_index() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let out_dir1 = TempDir::new().unwrap();
    let out_dir2 = TempDir::new().unwrap();

    // Create file, backup v1
    let path_name = "versioned.txt";
    let path = write_file(&files_dir, path_name, b"version one content");
    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path)).unwrap();
    backup.flush_all(true).unwrap();

    // Modify file, backup v2
    std::fs::write(&path, b"version two content").unwrap();
    backup
        .process_event(DirtyEvent {
            path: path.clone(),
            kind: DirtyKind::Modified,
            device_id: DeviceId([1u8; 16]),
        })
        .unwrap();
    backup.flush_all(true).unwrap();

    // Verify 2 versions exist in DB
    let record = db.get_file(&path).unwrap().unwrap();
    let backed_up_count = record
        .versions
        .iter()
        .filter(|v| v.backed_up_at.is_some())
        .count();
    assert_eq!(backed_up_count, 2, "should have 2 backed-up versions");

    // Restore version index 0 (the first)
    let (restore, _net) = test_restore_coord(db.clone(), &symbols_dir).await;
    let request_v0 = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Index(0),
        output_dir: out_dir1.path().to_path_buf(),
        device_id: DeviceId([2u8; 16]),
    };
    let result = restore.restore(request_v0).await.unwrap();
    assert_eq!(result.files_restored, 1, "failures: {:?}", result.failures);

    let rel = path.trim_start_matches('/');
    let out_v0 = std::fs::read(out_dir1.path().join(rel)).unwrap();
    assert_eq!(out_v0, b"version one content");

    // Restore latest (should be v2)
    let request_latest = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        output_dir: out_dir2.path().to_path_buf(),
        device_id: DeviceId([2u8; 16]),
    };
    let result2 = restore.restore(request_latest).await.unwrap();
    assert_eq!(result2.files_restored, 1, "failures: {:?}", result2.failures);

    let out_latest = std::fs::read(out_dir2.path().join(rel)).unwrap();
    assert_eq!(out_latest, b"version two content");
}

#[tokio::test]
async fn restore_prefix_matches_multiple_files() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();

    // Create a photos subdirectory and a docs subdirectory
    let photos_dir = files_dir.path().join("photos");
    let docs_dir = files_dir.path().join("docs");
    std::fs::create_dir_all(&photos_dir).unwrap();
    std::fs::create_dir_all(&docs_dir).unwrap();

    let photo_a = photos_dir.join("a.jpg");
    let photo_b = photos_dir.join("b.jpg");
    let doc_c = docs_dir.join("c.txt");
    std::fs::write(&photo_a, b"photo a").unwrap();
    std::fs::write(&photo_b, b"photo b").unwrap();
    std::fs::write(&doc_c, b"doc c").unwrap();

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    for p in [&photo_a, &photo_b, &doc_c] {
        backup
            .process_event(added_event(&p.to_string_lossy()))
            .unwrap();
    }
    backup.flush_all(true).unwrap();

    // Restore only photos prefix
    let (restore, _net) = test_restore_coord(db.clone(), &symbols_dir).await;
    let photos_prefix = photos_dir.to_string_lossy().to_string() + "/";
    let request = super::RestoreRequest {
        path: photos_prefix,
        version_selector: VersionSelector::Latest,
        output_dir: out_dir.path().to_path_buf(),
        device_id: DeviceId([2u8; 16]),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(result.files_restored, 2, "failures: {:?}", result.failures);
    assert!(result.failures.is_empty());

    // doc_c should NOT be in output
    let doc_c_rel = doc_c.to_string_lossy();
    let doc_c_rel = doc_c_rel.trim_start_matches('/');
    assert!(
        !out_dir.path().join(doc_c_rel).exists(),
        "docs/c.txt should not be in output"
    );
}

#[tokio::test]
async fn restore_missing_path_returns_empty_result() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();

    let (restore, _net) = test_restore_coord(db.clone(), &symbols_dir).await;
    let request = super::RestoreRequest {
        path: "/nonexistent/file.txt".to_string(),
        version_selector: VersionSelector::Latest,
        output_dir: out_dir.path().to_path_buf(),
        device_id: DeviceId([2u8; 16]),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(result.files_restored, 0);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].0, "/nonexistent/file.txt");
}

#[tokio::test]
async fn restore_updates_local_state_to_present() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();

    let content = b"state update test";
    let path = write_file(&files_dir, "state.txt", content);

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path)).unwrap();
    backup.flush_all(true).unwrap();

    let restore_device = DeviceId([2u8; 16]);
    let (restore, _net) = test_restore_coord(db.clone(), &symbols_dir).await;
    let request = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        output_dir: out_dir.path().to_path_buf(),
        device_id: restore_device,
    };
    let result = restore.restore(request).await.unwrap();
    assert_eq!(result.files_restored, 1);

    // Check LocalState updated
    let record = db.get_file(&path).unwrap().unwrap();
    let state = record
        .devices
        .iter()
        .find(|(d, _)| *d == restore_device)
        .map(|(_, s)| s);
    assert!(
        matches!(state, Some(LocalState::Present)),
        "expected Present, got {:?}",
        state
    );
}

#[tokio::test]
async fn restore_deduplicates_source_blocks() {
    // Two files backed up in same pack block should cause only 1 decode call.
    // We verify this indirectly: blocks_fetched == 1 even though files_restored == 2.
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let out_dir = TempDir::new().unwrap();

    let path_a = write_file(&files_dir, "a.txt", b"file a content");
    let path_b = write_file(&files_dir, "b.txt", b"file b content");

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path_a)).unwrap();
    backup.process_event(added_event(&path_b)).unwrap();
    let results = backup.flush_all(true).unwrap();

    // Both files should land in the same block (total size << SMALL_BLOCK_SIZE)
    assert_eq!(results.len(), 1, "should produce exactly 1 block");

    let (restore, _net) = test_restore_coord(db.clone(), &symbols_dir).await;
    let prefix = files_dir.path().to_string_lossy().to_string() + "/";
    let request = super::RestoreRequest {
        path: prefix,
        version_selector: VersionSelector::Latest,
        output_dir: out_dir.path().to_path_buf(),
        device_id: DeviceId([2u8; 16]),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(result.files_restored, 2, "failures: {:?}", result.failures);
    assert_eq!(result.blocks_fetched, 1, "should decode exactly 1 block");
    assert!(result.failures.is_empty());
}
