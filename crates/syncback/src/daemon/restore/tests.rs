// Tests for RestoreCoordinator.
// Pattern: what_when_then.
//
// All tests use real Db::open_in_memory(), real RaptorQEncoder, tempfile::TempDir.
// Source block size is small (65_535 * 2 = ~128 KB) to keep encode/decode fast.
// Async tests use #[tokio::test].
//
// Network-fetch tests (Phase 7.7):
//   - collect_esis_from_ranges_* — unit tests for the ESI helper.
//   - fetch_from_holders_returns_insufficient_when_no_peers_reachable — all
//     holders unreachable → InsufficientSymbols.
//   - fetch_skips_denied_holder_and_tries_next — holder A returns
//     RestoreDenied; holder B returns symbols; decode succeeds.
//   - decode_block_fetches_from_network_when_local_files_missing — owner
//     symbols_dir empty; two holder nodes serve symbols over iroh; decode
//     roundtrip produces original plaintext.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use syncback_core::cluster::{
    derive_device_key, derive_master_key, issue_device_certificate, master_identity,
};
use syncback_core::db::Db;
use syncback_core::erasure::{ErasureEncoder, RaptorQEncoder};
use syncback_core::messages::{Message, RestoreDeniedMsg, RestoreResponseMsg};
use syncback_core::types::{
    DeviceId, ErasureParams, FileId, FileRecord, FileVersion, IdentityPub, LocalState, PackEntry,
    PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType,
    SymbolPlacement, Timestamp,
};
use syncback_core::types::to_cbor_bytes;
use tempfile::TempDir;

use crate::daemon::backup::{
    BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind,
};
use crate::daemon::backup::pipeline::compress_and_encrypt;
use crate::daemon::network::{NetworkConfig, NetworkHandle};
use crate::daemon::restore::pipeline::hex_encode;

use super::{collect_esis_from_ranges, RestoreConfig, RestoreCoordinator, VersionSelector};

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
        watch_configs: vec![],
        time_scale: 1,
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
        master_identity: IdentityPub(signing_key.verifying_key().to_bytes()),
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
            signing_key: signing_key2.clone(),
            master_identity: IdentityPub(signing_key2.verifying_key().to_bytes()),
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

// ─── REST-09: prefix_restore_finds_multiple_files ────────────────────────────

/// resolve_path with trailing '/' uses list_files_with_prefix.
/// Insert 3 FileRecords: 2 under "/data/photos/", 1 under "/data/docs/".
/// Resolving prefix "/data/photos/" must return exactly 2 records.
///
/// We test the DB layer directly — the resolve_path method is private but
/// list_files_with_prefix is the exact call it delegates to, so this is
/// equivalent coverage without depending on internal RestoreCoordinator state.
#[test]
fn prefix_restore_finds_multiple_files() {
    let db = Db::open_in_memory().unwrap();

    let make_record = |path: &str, id: u64| -> FileRecord {
        FileRecord {
            file_id: FileId(id),
            path: path.to_string(),
            importance: 0.5,
            devices: vec![],
            versions: vec![FileVersion {
                content_hash: [id as u8; 32],
                source_block_id: SourceBlockId([id as u8; 32]),
                k: 2,
                t: 65_535,
                created_at: Timestamp(id * 1000),
                backed_up_at: Some(Timestamp(id * 2000)),
            }],
            first_seen: Timestamp(0),
        }
    };

    db.upsert_file(&make_record("/data/photos/a.jpg", 1)).unwrap();
    db.upsert_file(&make_record("/data/photos/b.jpg", 2)).unwrap();
    db.upsert_file(&make_record("/data/docs/c.txt", 3)).unwrap();

    let photos = db.list_files_with_prefix("/data/photos/").unwrap();
    assert_eq!(photos.len(), 2, "prefix /data/photos/ should match 2 files");
    let paths: Vec<&str> = photos.iter().map(|r| r.path.as_str()).collect();
    assert!(
        paths.contains(&"/data/photos/a.jpg"),
        "a.jpg missing from results"
    );
    assert!(
        paths.contains(&"/data/photos/b.jpg"),
        "b.jpg missing from results"
    );

    let docs = db.list_files_with_prefix("/data/docs/").unwrap();
    assert_eq!(docs.len(), 1, "prefix /data/docs/ should match 1 file");
    assert_eq!(docs[0].path, "/data/docs/c.txt");
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

// ─── collect_esis_from_ranges unit tests ──────────────────────────────────────

#[test]
fn collect_esis_from_ranges_empty_returns_empty() {
    assert_eq!(collect_esis_from_ranges(&[]), Vec::<u32>::new());
}

#[test]
fn collect_esis_from_ranges_single_range() {
    assert_eq!(collect_esis_from_ranges(&[(0, 3)]), vec![0, 1, 2]);
}

#[test]
fn collect_esis_from_ranges_two_disjoint_ranges() {
    assert_eq!(
        collect_esis_from_ranges(&[(0, 2), (5, 2)]),
        vec![0, 1, 5, 6]
    );
}

#[test]
fn collect_esis_from_ranges_count_one() {
    assert_eq!(collect_esis_from_ranges(&[(7, 1)]), vec![7]);
}

// ─── fetch_from_holders: unreachable peers → InsufficientSymbols ──────────────

#[tokio::test]
async fn fetch_from_holders_returns_insufficient_when_no_peers_reachable() {
    // 3 placements, all Alive, but the owner NetworkHandle has no known_peers.
    // Every get_connection call returns PeerNotFound; all holders are skipped.
    // Expected: InsufficientSymbols(got=0).
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let block_id = SourceBlockId([0xBBu8; 32]);

    let placements: Vec<SymbolPlacement> = (0u8..3)
        .map(|i| SymbolPlacement {
            source_block_id: block_id,
            holder_id: IdentityPub([(i + 1) * 0x11u8; 32]),
            file_id: FileId(1),
            esi_ranges: vec![(u32::from(i) * 3, 3)],
            binding_seed: [0u8; 32],
            status: PlacementStatus::Alive,
            last_verified: None,
            placed_at: Timestamp(0),
            consecutive_misses: 0,
        })
        .collect();

    let (coord, _net) = test_restore_coord(db, &symbols_dir).await;
    let params = ErasureParams::compute(65_535_u64, 0.5);

    let result = coord
        .fetch_from_holders(&block_id, &placements, &params)
        .await;

    assert!(
        matches!(
            result,
            Err(super::RestoreError::InsufficientSymbols { got: 0, .. })
        ),
        "expected InsufficientSymbols(got=0), got: {result:?}"
    );
}

// ─── fetch_skips_denied_holder_and_tries_next ─────────────────────────────────

/// Holder A returns RestoreDenied; Holder B has all k_eff symbols.
/// fetch_from_holders skips A and collects from B successfully.
#[tokio::test]
async fn fetch_skips_denied_holder_and_tries_next() {
    let content = b"hello from the network restore test";
    let epoch_key = [0x77u8; 32];

    let stored = compress_and_encrypt(content, &epoch_key).expect("compress_and_encrypt");
    let encrypted_size = stored.len() as u64;

    let encoder = Arc::new(RaptorQEncoder::new());
    // k=1 (one symbol source block). k_eff = 1 + 3 = 4.
    let params = ErasureParams::compute(65_535_u64, 0.5);
    let k_eff = params.k_eff as usize;

    let total_size = (params.k as usize) * (params.t as usize);
    let mut padded = stored.clone();
    padded.resize(total_size, 0u8);

    let block_id = SourceBlockId([0xCCu8; 32]);

    // Holder B: seed [0x0Bu8; 32]
    let seed_b = [0x0Bu8; 32];
    let master_key_b = derive_master_key(&seed_b).unwrap();
    let master_b = master_identity(&master_key_b);
    let did_b = DeviceId([0x0Bu8; 16]);
    let device_key_b = derive_device_key(&seed_b, &did_b).unwrap();
    let cert_b = issue_device_certificate(
        &master_key_b,
        did_b,
        device_key_b.verifying_key().to_bytes(),
        Timestamp::now(),
    );

    let symbols_b = encoder
        .encode(&padded, &params, 0, k_eff as u32, &block_id, &master_b)
        .expect("encode for holder_b");

    let holdings_dir_b = TempDir::new().unwrap();
    let block_dir_b = holdings_dir_b.path().join(hex_encode(&block_id.0));
    std::fs::create_dir_all(&block_dir_b).unwrap();
    for sym in &symbols_b {
        std::fs::write(block_dir_b.join(format!("{}.bin", sym.esi)), &sym.data).unwrap();
    }

    // Holder A: seed [0x0Au8; 32]
    let seed_a = [0x0Au8; 32];
    let master_key_a = derive_master_key(&seed_a).unwrap();
    let master_a = master_identity(&master_key_a);
    let did_a = DeviceId([0x0Au8; 16]);
    let device_key_a = derive_device_key(&seed_a, &did_a).unwrap();
    let cert_a = issue_device_certificate(
        &master_key_a,
        did_a,
        device_key_a.verifying_key().to_bytes(),
        Timestamp::now(),
    );

    let (tx_a, mut rx_a) =
        tokio::sync::mpsc::channel::<crate::daemon::network::connection::Connection>(4);
    let (tx_b, mut rx_b) =
        tokio::sync::mpsc::channel::<crate::daemon::network::connection::Connection>(4);

    let handle_a = NetworkHandle::start(
        NetworkConfig {
            signing_key: device_key_a,
            master_identity: master_a,
            known_peers: Default::default(),
            device_cert: Some(cert_a),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
        },
        tx_a,
    )
    .await
    .unwrap();

    let handle_b = NetworkHandle::start(
        NetworkConfig {
            signing_key: device_key_b,
            master_identity: master_b,
            known_peers: Default::default(),
            device_cert: Some(cert_b),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
        },
        tx_b,
    )
    .await
    .unwrap();

    let addr_a = handle_a.local_addr().unwrap();
    let addr_b = handle_b.local_addr().unwrap();

    // Holder A: always returns RestoreDenied.
    tokio::spawn(async move {
        while let Some(mut conn) = rx_a.recv().await {
            tokio::spawn(async move {
                loop {
                    match conn.recv_message().await {
                        Ok(Message::RestoreRequest(req)) => {
                            let denied = Message::RestoreDenied(RestoreDeniedMsg {
                                v: 1,
                                source_block_id: req.source_block_id,
                                reason: "test always denied".to_string(),
                                current_trust: 0.0,
                                needed_trust: 0.5,
                                restore_budget_gb: 0.0,
                                timestamp: Timestamp::now(),
                            });
                            let _ = conn.send_message(&denied).await;
                        }
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
            });
        }
    });

    // Holder B: serves symbols from disk.
    let dir_b = block_dir_b.clone();
    tokio::spawn(async move {
        while let Some(mut conn) = rx_b.recv().await {
            let dir = dir_b.clone();
            tokio::spawn(async move {
                loop {
                    match conn.recv_message().await {
                        Ok(Message::RestoreRequest(req)) => {
                            let mut symbols = Vec::new();
                            for esi in &req.esi_list {
                                let path = dir.join(format!("{esi}.bin"));
                                if let Ok(data) = std::fs::read(&path) {
                                    symbols.push(syncback_core::erasure::Symbol {
                                        esi: *esi,
                                        data,
                                    });
                                }
                            }
                            let resp = Message::RestoreResponse(RestoreResponseMsg {
                                v: 1,
                                source_block_id: req.source_block_id,
                                symbols,
                                timestamp: Timestamp::now(),
                            });
                            let _ = conn.send_message(&resp).await;
                        }
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
            });
        }
    });

    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    // Placement for Holder A: claims 1 symbol (it will deny).
    let placement_a = SymbolPlacement {
        source_block_id: block_id,
        holder_id: master_a,
        file_id: FileId(1),
        esi_ranges: vec![(0, 1)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement_a).unwrap();

    // Placement for Holder B: all k_eff symbols.
    let placement_b = SymbolPlacement {
        source_block_id: block_id,
        holder_id: master_b,
        file_id: FileId(1),
        esi_ranges: vec![(0, k_eff as u32)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement_b).unwrap();

    // Owner: seed [0x99u8; 32]
    let seed_owner = [0x99u8; 32];
    let owner_master_key = derive_master_key(&seed_owner).unwrap();
    let owner_master = master_identity(&owner_master_key);
    let owner_did = DeviceId([0xAAu8; 16]);
    let owner_device_key = derive_device_key(&seed_owner, &owner_did).unwrap();
    let owner_cert = issue_device_certificate(
        &owner_master_key,
        owner_did,
        owner_device_key.verifying_key().to_bytes(),
        Timestamp::now(),
    );
    let (tx_owner, _rx_owner) = tokio::sync::mpsc::channel(4);
    let owner_net = NetworkHandle::start(
        NetworkConfig {
            signing_key: owner_device_key,
            master_identity: owner_master,
            known_peers: Default::default(),
            device_cert: Some(owner_cert),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
        },
        tx_owner,
    )
    .await
    .unwrap();
    owner_net.add_peer(master_a, addr_a).await;
    owner_net.add_peer(master_b, addr_b).await;

    let restore_config = RestoreConfig {
        epoch_key,
        parallel_holders: 5,
        identity: owner_master,
        device_id: owner_did,
        symbols_dir: symbols_dir.path().to_path_buf(),
    };
    let coord = RestoreCoordinator::new(
        db,
        restore_config,
        encoder.clone(),
        Arc::new(owner_net),
    );

    let placements = vec![placement_a, placement_b];
    let result = coord
        .fetch_from_holders(&block_id, &placements, &params)
        .await;

    assert!(
        result.is_ok(),
        "fetch_from_holders should succeed (skipping denied holder): {result:?}"
    );
    let unbound = result.unwrap();
    assert!(
        unbound.len() >= k_eff,
        "should have >= k_eff unbound symbols, got {}",
        unbound.len()
    );

    // Verify the symbols actually decode to the original content.
    let decoded_padded = encoder.decode(&unbound, &params).expect("decode");
    let decoded_stored = &decoded_padded[..encrypted_size as usize];
    let plaintext =
        crate::daemon::backup::pipeline::decrypt_and_decompress(decoded_stored, &epoch_key)
            .expect("decrypt_and_decompress");
    assert_eq!(plaintext, content);

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}

// ─── decode_block_fetches_from_network_when_local_files_missing ──────────────

/// Owner symbols_dir is empty. Two holder network nodes each serve their
/// portion of symbols. decode_block_local falls back to network and returns
/// the original plaintext.
#[tokio::test]
async fn decode_block_fetches_from_network_when_local_files_missing() {
    let content = b"network restore integration test content for phase 7.7";
    let epoch_key = [0x42u8; 32];

    let stored = compress_and_encrypt(content, &epoch_key).expect("compress_and_encrypt");
    let encrypted_size = stored.len() as u64;

    let encoder = Arc::new(RaptorQEncoder::new());
    // k=1 source block. k_eff = 4.
    let params = ErasureParams::compute(65_535_u64, 0.5);
    let k_eff = params.k_eff as usize;

    let total_size = (params.k as usize) * (params.t as usize);
    let mut padded = stored.clone();
    padded.resize(total_size, 0u8);

    let block_id = SourceBlockId([0xDDu8; 32]);

    // Holder H1: seed [0x11u8; 32]
    let seed_h1 = [0x11u8; 32];
    let master_key_h1 = derive_master_key(&seed_h1).unwrap();
    let master_h1 = master_identity(&master_key_h1);
    let did_h1 = DeviceId([0x11u8; 16]);
    let device_key_h1 = derive_device_key(&seed_h1, &did_h1).unwrap();
    let cert_h1 = issue_device_certificate(
        &master_key_h1,
        did_h1,
        device_key_h1.verifying_key().to_bytes(),
        Timestamp::now(),
    );

    // Holder H2: seed [0x22u8; 32]
    let seed_h2 = [0x22u8; 32];
    let master_key_h2 = derive_master_key(&seed_h2).unwrap();
    let master_h2 = master_identity(&master_key_h2);
    let did_h2 = DeviceId([0x22u8; 16]);
    let device_key_h2 = derive_device_key(&seed_h2, &did_h2).unwrap();
    let cert_h2 = issue_device_certificate(
        &master_key_h2,
        did_h2,
        device_key_h2.verifying_key().to_bytes(),
        Timestamp::now(),
    );

    // Split k_eff symbols between two holders.
    let h1_count = (k_eff / 2) as u32;
    let h2_count = k_eff as u32 - h1_count;

    let symbols_h1 = encoder
        .encode(&padded, &params, 0, h1_count, &block_id, &master_h1)
        .expect("encode h1");
    let symbols_h2 = encoder
        .encode(&padded, &params, h1_count, h2_count, &block_id, &master_h2)
        .expect("encode h2");

    let block_hex = hex_encode(&block_id.0);

    let holdings_dir_h1 = TempDir::new().unwrap();
    let block_dir_h1 = holdings_dir_h1.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir_h1).unwrap();
    for sym in &symbols_h1 {
        std::fs::write(block_dir_h1.join(format!("{}.bin", sym.esi)), &sym.data).unwrap();
    }

    let holdings_dir_h2 = TempDir::new().unwrap();
    let block_dir_h2 = holdings_dir_h2.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir_h2).unwrap();
    for sym in &symbols_h2 {
        std::fs::write(block_dir_h2.join(format!("{}.bin", sym.esi)), &sym.data).unwrap();
    }

    let (tx_h1, rx_h1) =
        tokio::sync::mpsc::channel::<crate::daemon::network::connection::Connection>(4);
    let (tx_h2, rx_h2) =
        tokio::sync::mpsc::channel::<crate::daemon::network::connection::Connection>(4);

    let handle_h1 = NetworkHandle::start(
        NetworkConfig {
            signing_key: device_key_h1,
            master_identity: master_h1,
            known_peers: Default::default(),
            device_cert: Some(cert_h1),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
        },
        tx_h1,
    )
    .await
    .unwrap();

    let handle_h2 = NetworkHandle::start(
        NetworkConfig {
            signing_key: device_key_h2,
            master_identity: master_h2,
            known_peers: Default::default(),
            device_cert: Some(cert_h2),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
        },
        tx_h2,
    )
    .await
    .unwrap();

    let addr_h1 = handle_h1.local_addr().unwrap();
    let addr_h2 = handle_h2.local_addr().unwrap();

    fn spawn_mock_holder(
        mut rx: tokio::sync::mpsc::Receiver<crate::daemon::network::connection::Connection>,
        block_dir: std::path::PathBuf,
    ) {
        tokio::spawn(async move {
            while let Some(mut conn) = rx.recv().await {
                let dir = block_dir.clone();
                tokio::spawn(async move {
                    loop {
                        match conn.recv_message().await {
                            Ok(Message::RestoreRequest(req)) => {
                                let mut symbols = Vec::new();
                                for esi in &req.esi_list {
                                    let path = dir.join(format!("{esi}.bin"));
                                    if let Ok(data) = std::fs::read(&path) {
                                        symbols.push(syncback_core::erasure::Symbol {
                                            esi: *esi,
                                            data,
                                        });
                                    }
                                }
                                let resp = Message::RestoreResponse(RestoreResponseMsg {
                                    v: 1,
                                    source_block_id: req.source_block_id,
                                    symbols,
                                    timestamp: Timestamp::now(),
                                });
                                let _ = conn.send_message(&resp).await;
                            }
                            Ok(_) => continue,
                            Err(_) => break,
                        }
                    }
                });
            }
        });
    }

    spawn_mock_holder(rx_h1, block_dir_h1.clone());
    spawn_mock_holder(rx_h2, block_dir_h2.clone());

    let db = Db::open_in_memory().unwrap();

    let block_record = SourceBlockRecord {
        block_id,
        k: params.k,
        t: params.t,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp::now(),
        encrypted_size: Some(encrypted_size),
        n: None,
        overhead: None,
    };
    db.upsert_source_block(&block_record).unwrap();

    let placement_h1 = SymbolPlacement {
        source_block_id: block_id,
        holder_id: master_h1,
        file_id: FileId(1),
        esi_ranges: vec![(0, h1_count)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement_h1).unwrap();

    let placement_h2 = SymbolPlacement {
        source_block_id: block_id,
        holder_id: master_h2,
        file_id: FileId(1),
        esi_ranges: vec![(h1_count, h2_count)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement_h2).unwrap();

    // Owner: seed [0x55u8; 32]
    let seed_owner = [0x55u8; 32];
    let owner_master_key = derive_master_key(&seed_owner).unwrap();
    let owner_master = master_identity(&owner_master_key);
    let owner_did = DeviceId([0x66u8; 16]);
    let owner_device_key = derive_device_key(&seed_owner, &owner_did).unwrap();
    let owner_cert = issue_device_certificate(
        &owner_master_key,
        owner_did,
        owner_device_key.verifying_key().to_bytes(),
        Timestamp::now(),
    );
    let (tx_owner, _rx_owner) = tokio::sync::mpsc::channel(4);
    let owner_net = NetworkHandle::start(
        NetworkConfig {
            signing_key: owner_device_key,
            master_identity: owner_master,
            known_peers: Default::default(),
            device_cert: Some(owner_cert),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
        },
        tx_owner,
    )
    .await
    .unwrap();
    owner_net.add_peer(master_h1, addr_h1).await;
    owner_net.add_peer(master_h2, addr_h2).await;

    // Owner symbols_dir is EMPTY.
    let symbols_dir = TempDir::new().unwrap();

    let restore_config = RestoreConfig {
        epoch_key,
        parallel_holders: 5,
        identity: owner_master,
        device_id: owner_did,
        symbols_dir: symbols_dir.path().to_path_buf(),
    };
    let coord = RestoreCoordinator::new(db, restore_config, encoder, Arc::new(owner_net));

    // decode_block_local: empty local symbols_dir → falls back to network.
    let plaintext = coord
        .decode_block_local(&block_id, &params, encrypted_size)
        .await
        .expect("decode_block_local should succeed via network fetch");

    assert_eq!(
        plaintext, content,
        "decoded plaintext must match original content"
    );

    handle_h1.shutdown().await;
    handle_h2.shutdown().await;
}
