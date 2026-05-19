// Tests for RestoreCoordinator.
// Pattern: what_when_then.
//
// All tests use real Db::open_in_memory(), real RaptorQEncoder, tempfile::TempDir.
// Source block size is small (65_535 * 2 = ~128 KB) to keep encode/decode fast.
// Async tests use #[tokio::test(flavor = "multi_thread", worker_threads = 2)].
//
// Network-fetch tests (Phase 7.7 iroh era) removed in ε.5:
//   - fetch_skips_denied_holder_and_tries_next — used iroh NetworkHandle
//   - decode_block_fetches_from_network_when_local_files_missing — used iroh NetworkHandle
// Network restore via libp2p SwarmHandle is tested in swarm_tests.rs and E2E.

use std::sync::Arc;

use tempfile::TempDir;
use viaticum_core::db::Db;
use viaticum_core::erasure::RaptorQEncoder;
use viaticum_core::types::to_cbor_bytes;
use viaticum_core::types::{
    DeviceId, ErasureParams, FileId, FileRecord, FileVersion, IdentityPub, LocalState, PackEntry,
    PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType,
    SymbolPlacement, Timestamp,
};

use crate::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};

use super::{RestoreConfig, RestoreCoordinator, VersionSelector, collect_esis_from_ranges};
use crate::daemon::restore::staging::JobId;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Small source block size for fast tests (2 * SYMBOL_SIZE = ~128 KB).
const SMALL_BLOCK_SIZE: u64 = 65_535 * 2;
const TEST_EPOCH_KEY: [u8; 32] = [42u8; 32];

/// Build mock holders for backup tests.
fn test_holders() -> Vec<viaticum_core::placement::HolderCandidate> {
    (0..5)
        .map(|i| viaticum_core::placement::HolderCandidate {
            device_id: viaticum_core::types::DeviceId([(i + 1) as u8; 32]),
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
        device_id: DeviceId([1u8; 32]),
        mock_holders: test_holders(),
        cluster_state: None,
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: None,
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
    };
    BackupCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()))
}

/// Build a RestoreCoordinator for Phase 2 (local) tests (no network needed).
/// `staging_dir`: the TempDir that will serve as both staging_root and data_dir
/// (they're the same in tests — staging_root = staging_dir/restore, data_dir = staging_dir).
fn test_restore_coord(db: Db, symbols_dir: &TempDir, staging_dir: &TempDir) -> RestoreCoordinator {
    // Create the restore staging subdirectory under staging_dir.
    let staging_root = staging_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).expect("create staging_root");

    let restore_config = RestoreConfig {
        epoch_key: TEST_EPOCH_KEY,
        parallel_holders: 5,
        identity: IdentityPub([9u8; 32]),
        device_id: DeviceId([2u8; 32]),
        symbols_dir: symbols_dir.path().to_path_buf(),
        swarm: None,
        staging_root,
        data_dir: staging_dir.path().to_path_buf(),
        fetch_timeout: std::time::Duration::from_secs(60),
    };

    RestoreCoordinator::new(db, restore_config, Arc::new(RaptorQEncoder::new()))
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
        device_id: DeviceId([1u8; 32]),
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
    let result =
        RestoreCoordinator::select_version(&record, &VersionSelector::BeforeDate(Timestamp(400)));
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
    let result =
        RestoreCoordinator::select_version(&record, &VersionSelector::BeforeDate(Timestamp(400)));
    assert!(result.is_some());
    assert_eq!(result.unwrap().backed_up_at, Some(Timestamp(400)));
}

#[test]
fn select_version_before_date_returns_none_when_all_after() {
    let record = make_record_with_versions(vec![make_version(Some(500)), make_version(Some(600))]);
    let result =
        RestoreCoordinator::select_version(&record, &VersionSelector::BeforeDate(Timestamp(100)));
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

    db.upsert_file(&make_record("/data/photos/a.jpg", 1))
        .unwrap();
    db.upsert_file(&make_record("/data/photos/b.jpg", 2))
        .unwrap();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_single_file_by_exact_path() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    // Backup one file
    let content = b"single file content for restore test";
    let path = write_file(&files_dir, "single.txt", content);
    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path)).unwrap();
    let results = backup.flush_all(true, &Default::default()).unwrap();
    assert!(
        !results.is_empty(),
        "should have produced at least one block"
    );

    // Restore
    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let request = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        device_id: DeviceId([2u8; 32]),
        job_id: JobId::new(),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(result.files_restored, 1, "failures: {:?}", result.failures);
    assert!(result.failures.is_empty());

    // Verify content: file is in staging_path/<rel_path>
    let rel = path.trim_start_matches('/');
    let out_file = result.staging_path.join(rel);
    let restored = std::fs::read(&out_file).unwrap();
    assert_eq!(restored, content);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_pack_multiple_files_roundtrip() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

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
    let results = backup.flush_all(true, &Default::default()).unwrap();
    assert!(!results.is_empty(), "should have produced blocks");

    // Restore all 3 using prefix (the files_dir path as prefix)
    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let prefix = files_dir.path().to_string_lossy().to_string() + "/";
    let request = super::RestoreRequest {
        path: prefix,
        version_selector: VersionSelector::Latest,
        device_id: DeviceId([2u8; 32]),
        job_id: JobId::new(),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(result.files_restored, 3, "failures: {:?}", result.failures);
    assert!(result.failures.is_empty());

    // Verify contents — files are in staging_path/<rel_path>
    for (name, content) in &contents {
        let full_path = files_dir.path().join(name);
        let rel = full_path.to_string_lossy();
        let rel = rel.trim_start_matches('/');
        let out_file = result.staging_path.join(rel);
        let restored = std::fs::read(&out_file).unwrap();
        assert_eq!(&restored, content, "content mismatch for {}", name);
    }
}

/// Wave 11b: restore_specific_version_by_index
///
/// After Wave 11b, restoring historical versions requires the source file to still exist
/// (rebuild_source_blob path) or symbols in holders (network path).
/// This test now verifies version selection logic using files that still exist on disk:
/// v1 content is restored first, then v2 is backed up, and we restore v2 (still on disk).
/// For v1 restore, we write raw symbol files manually to simulate what a holder would store,
/// allowing the local raw symbol path to work as a test scaffold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_specific_version_by_index() {
    use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder};
    use viaticum_core::types::{ErasureParams, hex_encode};

    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    // Create file, backup v1
    let path_name = "versioned.txt";
    let path = write_file(&files_dir, path_name, b"version one content");
    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path)).unwrap();
    let v1_results = backup.flush_all(true, &Default::default()).unwrap();
    assert_eq!(v1_results.len(), 1, "v1 should produce 1 block");
    let v1_block_id = v1_results[0].source_block_id;

    // Write v1 raw symbols to disk manually (test scaffold for the local raw path).
    // This simulates what the old pipeline wrote; after Wave 11b the pipeline doesn't
    // write these, but we need them here to test version-specific restore without a swarm.
    {
        let encoder = RaptorQEncoder::new();
        let v1_blob = crate::daemon::backup::pipeline::rebuild_source_blob(
            &db,
            &db.get_source_block(&v1_block_id).unwrap().unwrap(),
            &TEST_EPOCH_KEY, // same epoch_key as test_backup_coord
        )
        .await
        .unwrap();
        let stored_size = v1_blob.len() as u64;
        let params = ErasureParams::compute(stored_size, 0.5).unwrap();
        let raws = encoder
            .encode_raw(&v1_blob, &params, 0, params.k_eff)
            .unwrap();
        let raw_dir = symbols_dir
            .path()
            .join(hex_encode(&v1_block_id.0))
            .join("raw");
        std::fs::create_dir_all(&raw_dir).unwrap();
        for sym in &raws {
            std::fs::write(raw_dir.join(format!("{}.bin", sym.esi)), &sym.data).unwrap();
        }
    }

    // Modify file, backup v2 (source file now has different content)
    std::fs::write(&path, b"version two content").unwrap();
    backup
        .process_event(DirtyEvent {
            path: path.clone(),
            kind: DirtyKind::Modified,
            device_id: DeviceId([1u8; 32]),
        })
        .unwrap();
    backup.flush_all(true, &Default::default()).unwrap();

    // Verify 2 versions exist in DB
    let record = db.get_file(&path).unwrap().unwrap();
    let backed_up_count = record
        .versions
        .iter()
        .filter(|v| v.backed_up_at.is_some())
        .count();
    assert_eq!(backed_up_count, 2, "should have 2 backed-up versions");

    // Restore version index 0 (the first — v1 with "version one content")
    // Uses the raw/ files we wrote above.
    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let request_v0 = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Index(0),
        device_id: DeviceId([2u8; 32]),
        job_id: JobId::new(),
    };
    let result = restore.restore(request_v0).await.unwrap();
    assert_eq!(result.files_restored, 1, "failures: {:?}", result.failures);

    let rel = path.trim_start_matches('/');
    let out_v0 = std::fs::read(result.staging_path.join(rel)).unwrap();
    assert_eq!(out_v0, b"version one content");

    // Restore latest (v2, "version two content" — still on disk, rebuild works)
    let request_latest = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        device_id: DeviceId([2u8; 32]),
        job_id: JobId::new(),
    };
    let result2 = restore.restore(request_latest).await.unwrap();
    assert_eq!(
        result2.files_restored, 1,
        "failures: {:?}",
        result2.failures
    );

    let out_latest = std::fs::read(result2.staging_path.join(rel)).unwrap();
    assert_eq!(out_latest, b"version two content");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_prefix_matches_multiple_files() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

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
    backup.flush_all(true, &Default::default()).unwrap();

    // Restore only photos prefix
    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let photos_prefix = photos_dir.to_string_lossy().to_string() + "/";
    let request = super::RestoreRequest {
        path: photos_prefix,
        version_selector: VersionSelector::Latest,
        device_id: DeviceId([2u8; 32]),
        job_id: JobId::new(),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(result.files_restored, 2, "failures: {:?}", result.failures);
    assert!(result.failures.is_empty());

    // doc_c should NOT be in staging output
    let doc_c_rel = doc_c.to_string_lossy();
    let doc_c_rel = doc_c_rel.trim_start_matches('/');
    assert!(
        !result.staging_path.join(doc_c_rel).exists(),
        "docs/c.txt should not be in output"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_missing_path_returns_empty_result() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let request = super::RestoreRequest {
        path: "/nonexistent/file.txt".to_string(),
        version_selector: VersionSelector::Latest,
        device_id: DeviceId([2u8; 32]),
        job_id: JobId::new(),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(result.files_restored, 0);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].0, "/nonexistent/file.txt");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_updates_local_state_to_present() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    let content = b"state update test";
    let path = write_file(&files_dir, "state.txt", content);

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path)).unwrap();
    backup.flush_all(true, &Default::default()).unwrap();

    let restore_device = DeviceId([2u8; 32]);
    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let request = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        device_id: restore_device,
        job_id: JobId::new(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_deduplicates_source_blocks() {
    // Two files backed up in same pack block should cause only 1 decode call.
    // We verify this indirectly: blocks_fetched == 1 even though files_restored == 2.
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    let path_a = write_file(&files_dir, "a.txt", b"file a content");
    let path_b = write_file(&files_dir, "b.txt", b"file b content");

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path_a)).unwrap();
    backup.process_event(added_event(&path_b)).unwrap();
    let results = backup.flush_all(true, &Default::default()).unwrap();

    // Both files should land in the same block (total size << SMALL_BLOCK_SIZE)
    assert_eq!(results.len(), 1, "should produce exactly 1 block");

    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let prefix = files_dir.path().to_string_lossy().to_string() + "/";
    let request = super::RestoreRequest {
        path: prefix,
        version_selector: VersionSelector::Latest,
        device_id: DeviceId([2u8; 32]),
        job_id: JobId::new(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_from_holders_returns_insufficient_when_no_peers_reachable() {
    // 3 placements, all Alive, but swarm is None (no peers reachable).
    // Expected: InsufficientSymbols(got=0).
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let block_id = SourceBlockId([0xBBu8; 32]);

    let placements: Vec<SymbolPlacement> = (0u8..3)
        .map(|i| SymbolPlacement {
            source_block_id: block_id,
            holder_id: viaticum_core::types::DeviceId([(i + 1) * 0x11u8; 32]),
            file_id: FileId(1),
            esi_ranges: vec![(u32::from(i) * 3, 3)],
            binding_seed: [0u8; 32],
            status: PlacementStatus::Alive,
            last_verified: None,
            placed_at: Timestamp(0),
            consecutive_misses: 0,
        })
        .collect();

    let staging_dir = TempDir::new().unwrap();
    let coord = test_restore_coord(db, &symbols_dir, &staging_dir);
    let params = ErasureParams::compute(65_535_u64, 0.5).unwrap();

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetch_from_holders_attempts_presumed_lost_and_uncertain_placements() {
    // Regression: PresumedLost/Uncertain placements must be included in network
    // fetch attempts. Before the fix, only Alive placements were tried — a holder
    // that temporarily went offline and came back would be unreachable because
    // its placement was PresumedLost (missed 3 PoS rounds) until the next PoS pass.
    //
    // With swarm=None all fetch attempts fail the same way (InsufficientSymbols),
    // so we can't distinguish success vs skip here. This test verifies that
    // passing PresumedLost/Uncertain placements does NOT cause a panic or a
    // different error class — the caller code path reaches fetch_unbound_symbols.
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let block_id = SourceBlockId([0xCCu8; 32]);

    let placements: Vec<SymbolPlacement> = [
        PlacementStatus::PresumedLost,
        PlacementStatus::Uncertain,
        PlacementStatus::Alive,
    ]
    .into_iter()
    .enumerate()
    .map(|(i, status)| SymbolPlacement {
        source_block_id: block_id,
        holder_id: viaticum_core::types::DeviceId([(i as u8 + 1) * 0x11; 32]),
        file_id: FileId(1),
        esi_ranges: vec![(i as u32 * 3, 3)],
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses: i as u32,
    })
    .collect();

    let staging_dir2 = TempDir::new().unwrap();
    let coord = test_restore_coord(db, &symbols_dir, &staging_dir2);
    let params = ErasureParams::compute(65_535_u64, 0.5).unwrap();

    let result = coord
        .fetch_from_holders(&block_id, &placements, &params)
        .await;

    assert!(
        matches!(
            result,
            Err(super::RestoreError::InsufficientSymbols { got: 0, .. })
        ),
        "expected InsufficientSymbols(got=0) for all-no-swarm case, got: {result:?}"
    );
}

// fetch_skips_denied_holder_and_tries_next and
// decode_block_fetches_from_network_when_local_files_missing removed in ε.5.
// Both used iroh NetworkHandle + connection::Connection for direct QUIC exchange.
// Network restore via libp2p SwarmHandle is tested in swarm_tests.rs and E2E.

/// Holder A returns RestoreDenied; Holder B has all k_eff symbols.
/// fetch_from_holders skips A and collects from B successfully.
// Disabled in ε.5: used iroh NetworkHandle. Network restore tested in swarm_tests.rs + E2E.
#[cfg(any())]
async fn fetch_skips_denied_holder_and_tries_next() {
    let content = b"hello from the network restore test";
    let epoch_key = [0x77u8; 32];

    let stored = compress_and_encrypt(content, &epoch_key).expect("compress_and_encrypt");
    let encrypted_size = stored.len() as u64;

    let encoder = Arc::new(RaptorQEncoder::new());
    // k=1 (one symbol source block). k_eff = 1 + 3 = 4.
    let params = ErasureParams::compute(65_535_u64, 0.5).unwrap();
    let k_eff = params.k_eff as usize;

    let total_size = (params.k as usize) * (params.t as usize);
    let mut padded = stored.clone();
    padded.resize(total_size, 0u8);

    let block_id = SourceBlockId([0xCCu8; 32]);

    // Holder B: seed [0x0Bu8; 32]
    let seed_b = [0x0Bu8; 32];
    let master_key_b = derive_master_key(&seed_b).unwrap();
    let master_b = master_identity(&master_key_b);
    let did_b = DeviceId([0x0Bu8; 32]);
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
    let did_a = DeviceId([0x0Au8; 32]);
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
            signing_key: device_key_a.clone(),
            master_signing_key: device_key_a,
            master_identity: master_a,
            known_peers: Default::default(),
            device_cert: Some(cert_a),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
            x25519_pub: None,
        },
        tx_a,
    )
    .await
    .unwrap();

    let handle_b = NetworkHandle::start(
        NetworkConfig {
            signing_key: device_key_b.clone(),
            master_signing_key: device_key_b,
            master_identity: master_b,
            known_peers: Default::default(),
            device_cert: Some(cert_b),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
            x25519_pub: None,
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
                                    symbols
                                        .push(viaticum_core::erasure::Symbol { esi: *esi, data });
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
    let owner_did = DeviceId([0xAAu8; 32]);
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
            signing_key: owner_device_key.clone(),
            master_signing_key: owner_device_key,
            master_identity: owner_master,
            known_peers: Default::default(),
            device_cert: Some(owner_cert),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
            x25519_pub: None,
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
        swarm: None,
    };
    let coord = RestoreCoordinator::new(db, restore_config, encoder.clone(), Arc::new(owner_net));

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
// Disabled in ε.5: used iroh NetworkHandle. Network restore tested in swarm_tests.rs + E2E.
#[cfg(any())]
async fn decode_block_fetches_from_network_when_local_files_missing() {
    let content = b"network restore integration test content for phase 7.7";
    let epoch_key = [0x42u8; 32];

    let stored = compress_and_encrypt(content, &epoch_key).expect("compress_and_encrypt");
    let encrypted_size = stored.len() as u64;

    let encoder = Arc::new(RaptorQEncoder::new());
    // k=1 source block. k_eff = 4.
    let params = ErasureParams::compute(65_535_u64, 0.5).unwrap();
    let k_eff = params.k_eff as usize;

    let total_size = (params.k as usize) * (params.t as usize);
    let mut padded = stored.clone();
    padded.resize(total_size, 0u8);

    let block_id = SourceBlockId([0xDDu8; 32]);

    // Holder H1: seed [0x11u8; 32]
    let seed_h1 = [0x11u8; 32];
    let master_key_h1 = derive_master_key(&seed_h1).unwrap();
    let master_h1 = master_identity(&master_key_h1);
    let did_h1 = DeviceId([0x11u8; 32]);
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
    let did_h2 = DeviceId([0x22u8; 32]);
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
            signing_key: device_key_h1.clone(),
            master_signing_key: device_key_h1,
            master_identity: master_h1,
            known_peers: Default::default(),
            device_cert: Some(cert_h1),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
            x25519_pub: None,
        },
        tx_h1,
    )
    .await
    .unwrap();

    let handle_h2 = NetworkHandle::start(
        NetworkConfig {
            signing_key: device_key_h2.clone(),
            master_signing_key: device_key_h2,
            master_identity: master_h2,
            known_peers: Default::default(),
            device_cert: Some(cert_h2),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
            x25519_pub: None,
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
                                        symbols.push(viaticum_core::erasure::Symbol {
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
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
        last_attempted_at: None,
        last_pool_signature: 0,
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
    let owner_did = DeviceId([0x66u8; 32]);
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
            signing_key: owner_device_key.clone(),
            master_signing_key: owner_device_key,
            master_identity: owner_master,
            known_peers: Default::default(),
            device_cert: Some(owner_cert),
            iroh_secret_key: None,
            relay_mode: iroh::RelayMode::Disabled,
            x25519_pub: None,
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
        swarm: None,
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

// ─── Restore-safety tests (alpha_restore_safety spec) ─────────────────────────

/// C2: Default restore (no dest) writes files to staging, not the original location.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_restore_writes_to_staging_not_origin() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    let content = b"original content that must not be modified";
    let original_path = write_file(&files_dir, "important.txt", content);

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&original_path)).unwrap();
    backup.flush_all(true, &Default::default()).unwrap();

    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let request = super::RestoreRequest {
        path: original_path.clone(),
        version_selector: VersionSelector::Latest,
        device_id: DeviceId([2u8; 32]),
        job_id: JobId::new(),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(result.files_restored, 1, "failures: {:?}", result.failures);

    // staging_path must be inside staging_dir (not in files_dir).
    assert!(
        result.staging_path.starts_with(staging_dir.path()),
        "staging_path {:?} must be inside staging_dir {:?}",
        result.staging_path,
        staging_dir.path()
    );

    // Original file must be unchanged.
    let still_original = std::fs::read(&original_path).unwrap();
    assert_eq!(
        still_original, content,
        "original file must not be modified"
    );

    // Restored file must exist in staging.
    let rel = original_path.trim_start_matches('/');
    let staged_file = result.staging_path.join(rel);
    assert!(
        staged_file.exists(),
        "restored file must exist in staging at {staged_file:?}"
    );
    let restored = std::fs::read(&staged_file).unwrap();
    assert_eq!(restored, content, "restored content must match original");
}

/// E1: Path traversal from DB record is rejected.
/// Simulates a malicious DR blob where record.path = "../../../etc/cron.d/evil".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_traversal_from_db_record_is_rejected() {
    use viaticum_core::path_safety::PathSafetyError;

    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    // Insert a file record with a malicious path.
    let malicious_path = "../../../etc/cron.d/evil";
    let block_id = SourceBlockId([0xEEu8; 32]);

    let record = viaticum_core::types::FileRecord {
        file_id: FileId(99),
        path: malicious_path.to_string(),
        importance: 0.5,
        devices: vec![],
        versions: vec![FileVersion {
            content_hash: [0u8; 32],
            source_block_id: block_id,
            k: 2,
            t: 65_535,
            created_at: Timestamp(100),
            backed_up_at: Some(Timestamp(200)),
        }],
        first_seen: Timestamp(0),
    };
    db.upsert_file(&record).unwrap();

    // Insert a source block record.
    let source_block = SourceBlockRecord {
        block_id,
        k: 2,
        t: 65_535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(100),
        encrypted_size: Some(10),
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
    db.upsert_source_block(&source_block).unwrap();

    let _restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);

    // The restore will try to decode a block — it will fail because there are no symbols.
    // But before that, if extract_and_write_file is called, path validation must reject it.
    // Since there are no symbols, the restore returns InsufficientSymbols before writing.
    // Test the validation directly via validate_record_path to confirm the E1 invariant.
    let validation_result = viaticum_core::path_safety::validate_record_path(malicious_path);
    assert_eq!(
        validation_result,
        Err(PathSafetyError::DotDot),
        "malicious path must be rejected by PathValidator"
    );

    // Also verify the RestoreError::PathUnsafe variant exists and maps correctly.
    let err = super::RestoreError::PathUnsafe {
        path: malicious_path.to_string(),
        source: PathSafetyError::DotDot,
    };
    assert!(
        format!("{err}").contains(".."),
        "PathUnsafe error must describe the DotDot issue"
    );
}

/// E1 (integration): extract_and_write_file rejects malicious record.path values.
///
/// This test calls extract_and_write_file directly with pre-built plaintext bytes.
/// If someone removes the validate_record_path call from extract_and_write_file,
/// this test will write the file instead of returning PathUnsafe — and the
/// assert will fail, making the regression immediately visible.
#[test]
fn extract_and_write_file_rejects_path_traversal() {
    use crate::daemon::restore::staging::{JobId, StagingWriter};
    use viaticum_core::types::{FileId, FileVersion, SourceBlockType, Timestamp};

    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    let coord = test_restore_coord(db, &symbols_dir, &staging_dir);

    let staging_root = staging_dir.path().join("restore");
    let writer = StagingWriter::open(&staging_root, staging_dir.path(), JobId::new()).unwrap();

    // Malicious paths that must be rejected.
    // Note: "/etc/shadow" is intentionally omitted — the leading '/' is stripped
    // by validate_record_path (POSIX backup paths normalised), so the file would
    // land at staging/etc/shadow which is safe. Only true traversal is tested here.
    let bad_paths = [
        "../../../etc/passwd",
        "foo/../../../etc/cron.d/evil",
        "C:\\Windows\\System32\\evil.exe",
        "..\\..\\windows\\evil.bat",
    ];

    for bad_path in &bad_paths {
        let record = viaticum_core::types::FileRecord {
            file_id: FileId(1),
            path: bad_path.to_string(),
            importance: 0.5,
            devices: vec![],
            versions: vec![FileVersion {
                content_hash: [0u8; 32],
                source_block_id: viaticum_core::types::SourceBlockId([0u8; 32]),
                k: 2,
                t: 65_535,
                created_at: Timestamp(100),
                backed_up_at: Some(Timestamp(200)),
            }],
            first_seen: Timestamp(0),
        };
        let version = record.versions[0].clone();
        let plaintext = b"malicious payload";

        let result = coord.extract_and_write_file(
            &record,
            &version,
            &SourceBlockType::Single,
            plaintext,
            &writer,
        );

        assert!(
            matches!(result, Err(super::RestoreError::PathUnsafe { .. })),
            "extract_and_write_file must return PathUnsafe for {:?}, got: {:?}",
            bad_path,
            result,
        );
    }
}

/// Smoke test: result.staging_path is non-empty after successful restore.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_result_contains_staging_path() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    let content = b"staging path smoke test content";
    let path = write_file(&files_dir, "smoke.txt", content);

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path)).unwrap();
    backup.flush_all(true, &Default::default()).unwrap();

    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let request = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        device_id: DeviceId([2u8; 32]),
        job_id: JobId::new(),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(result.files_restored, 1);
    assert!(
        !result.staging_path.as_os_str().is_empty(),
        "staging_path must be non-empty"
    );
    assert!(
        result.staging_path.is_dir(),
        "staging_path {:?} must be an existing directory",
        result.staging_path
    );
}

// ─── StagingWriter tests ───────────────────────────────────────────────────────

mod staging_tests {
    use crate::daemon::restore::staging::{JobId, StagingError, StagingWriter};
    use std::path::Path;
    use tempfile::TempDir;
    use viaticum_core::path_safety::validate_record_path;

    /// G1: staging writer creates file at the correct relative path.
    #[test]
    fn staging_writer_creates_file_at_correct_path() {
        let data_dir = TempDir::new().unwrap();
        let staging_root = data_dir.path().join("restore");
        std::fs::create_dir_all(&staging_root).unwrap();

        let job_id = JobId::new();
        let writer = StagingWriter::open(&staging_root, data_dir.path(), job_id).unwrap();

        let validated = validate_record_path("home/alice/docs/report.docx").unwrap();
        let out = writer.write_file(&validated, b"report content").unwrap();

        // File must exist at the returned path.
        assert!(out.exists(), "file must exist at {out:?}");
        let content = std::fs::read(&out).unwrap();
        assert_eq!(content, b"report content");

        // Path must be rooted in staging_path.
        assert!(
            out.starts_with(writer.staging_path()),
            "file must be inside staging dir"
        );
    }

    /// Basic open test: job dir is created.
    #[test]
    fn staging_writer_open_creates_job_dir() {
        let data_dir = TempDir::new().unwrap();
        let staging_root = data_dir.path().join("restore");
        std::fs::create_dir_all(&staging_root).unwrap();

        let job_id = JobId::new();
        let writer = StagingWriter::open(&staging_root, data_dir.path(), job_id).unwrap();

        assert!(
            writer.staging_path().is_dir(),
            "job staging dir must exist: {:?}",
            writer.staging_path()
        );
        // Job dir name must be the UUID string.
        let dir_name = writer.staging_path().file_name().unwrap().to_string_lossy();
        assert_eq!(
            dir_name,
            job_id.to_string(),
            "job dir name must be the UUID"
        );
    }

    /// Mode 0o600 on written files (Unix only).
    #[cfg(unix)]
    #[test]
    fn staging_writer_mode_is_600_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let data_dir = TempDir::new().unwrap();
        let staging_root = data_dir.path().join("restore");
        std::fs::create_dir_all(&staging_root).unwrap();

        let writer = StagingWriter::open(&staging_root, data_dir.path(), JobId::new()).unwrap();
        let validated = validate_record_path("secret.txt").unwrap();
        let out = writer.write_file(&validated, b"secret").unwrap();

        let meta = std::fs::metadata(&out).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file mode must be 0o600, got {:o}", mode);
    }

    /// Mode 0o700 on job staging directory (Unix only).
    #[cfg(unix)]
    #[test]
    fn staging_writer_job_dir_mode_is_700_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let data_dir = TempDir::new().unwrap();
        let staging_root = data_dir.path().join("restore");
        std::fs::create_dir_all(&staging_root).unwrap();

        let writer = StagingWriter::open(&staging_root, data_dir.path(), JobId::new()).unwrap();

        let meta = std::fs::metadata(writer.staging_path()).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "job dir mode must be 0o700, got {:o}", mode);
    }

    /// C1: Writing the same path twice in the same job fails on the second attempt.
    #[test]
    fn write_twice_same_path_fails_second() {
        let data_dir = TempDir::new().unwrap();
        let staging_root = data_dir.path().join("restore");
        std::fs::create_dir_all(&staging_root).unwrap();

        let writer = StagingWriter::open(&staging_root, data_dir.path(), JobId::new()).unwrap();
        let validated = validate_record_path("docs/file.txt").unwrap();

        // First write succeeds.
        writer.write_file(&validated, b"first content").unwrap();

        // Second write fails with AlreadyExists.
        let result = writer.write_file(&validated, b"second content");
        assert!(
            matches!(result, Err(StagingError::AlreadyExists(_))),
            "second write must fail with AlreadyExists, got: {result:?}"
        );

        // First file must be intact.
        let out_path = writer.staging_path().join(validated.to_relative_path());
        let content = std::fs::read(&out_path).unwrap();
        assert_eq!(content, b"first content", "first file must remain intact");
    }

    /// B2: staging_root that is a symlink pointing outside data_dir is rejected.
    #[cfg(unix)]
    #[test]
    fn staging_root_symlink_outside_data_dir_is_rejected() {
        let data_dir = TempDir::new().unwrap();
        // Create a separate "outside" directory.
        let outside_dir = TempDir::new().unwrap();

        // Create staging_root as a symlink to outside_dir.
        let staging_root = data_dir.path().join("restore");
        std::os::unix::fs::symlink(outside_dir.path(), &staging_root).unwrap();

        let job_id = JobId::new();
        let result = StagingWriter::open(&staging_root, data_dir.path(), job_id);

        assert!(
            matches!(result, Err(StagingError::OutsideDataDir { .. })),
            "symlinked staging_root outside data_dir must be rejected, got: {result:?}"
        );
    }

    /// B1: Write through a symlink in the staging tree — cap_std prevents symlink following.
    /// The write should either succeed (capping to staging dir) or fail with an error,
    /// but must NOT end up writing to the symlink target.
    #[cfg(unix)]
    #[test]
    fn staging_write_does_not_follow_symlink_in_tree() {
        let data_dir = TempDir::new().unwrap();
        let staging_root = data_dir.path().join("restore");
        std::fs::create_dir_all(&staging_root).unwrap();

        let job_id = JobId::new();
        let writer = StagingWriter::open(&staging_root, data_dir.path(), job_id).unwrap();

        // Create a symlink inside the job dir that points to /tmp.
        let job_dir = writer.staging_path();
        let link_path = job_dir.join("link");
        std::os::unix::fs::symlink("/tmp", &link_path).unwrap();

        // Attempt to write "link/attack_file" — cap_std should not follow the symlink.
        let validated = validate_record_path("link/attack_file").unwrap();
        let result = writer.write_file(&validated, b"malicious content");

        // The write must either fail (cap_std rejects symlink in tree) or succeed
        // but land inside the staging dir (not in /tmp).
        match result {
            Err(_) => {
                // Rejected by cap_std — the ideal outcome.
                assert!(
                    !Path::new("/tmp/attack_file").exists(),
                    "/tmp/attack_file must not be created"
                );
            }
            Ok(out_path) => {
                // Allowed — but must not be at /tmp/attack_file.
                assert!(
                    out_path.starts_with(job_dir),
                    "written file must be inside staging dir, not symlink target: {out_path:?}"
                );
                assert!(
                    !Path::new("/tmp/attack_file").exists(),
                    "/tmp/attack_file must not exist"
                );
            }
        }
    }

    /// G2: Two restore jobs get different job_ids.
    #[test]
    fn two_restore_jobs_get_different_job_ids() {
        let id1 = JobId::new();
        let id2 = JobId::new();
        assert_ne!(
            id1, id2,
            "two JobId::new() calls must produce different IDs"
        );
    }
}

// ─── Cleanup tests ────────────────────────────────────────────────────────────
// Moved here from cleanup.rs per convention (tests in separate files).

mod cleanup_tests {
    use crate::daemon::restore::cleanup::{check_staging_warn, should_warn, staging_total_bytes};
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn staging_total_bytes_returns_zero_for_missing_dir() {
        let total = staging_total_bytes(Path::new("/nonexistent/path/that/does/not/exist"));
        assert_eq!(total, 0);
    }

    #[test]
    fn staging_total_bytes_returns_correct_sum() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.bin"), b"hello").unwrap(); // 5 bytes
        std::fs::write(dir.path().join("b.bin"), b"world!!").unwrap(); // 7 bytes

        let total = staging_total_bytes(dir.path());
        assert_eq!(total, 12, "expected 5+7=12 bytes");
    }

    #[test]
    fn staging_total_bytes_recurses_into_subdirectories() {
        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(dir.path().join("root.bin"), [0u8; 100]).unwrap();
        std::fs::write(sub.join("nested.bin"), [0u8; 200]).unwrap();

        let total = staging_total_bytes(dir.path());
        assert_eq!(total, 300, "expected 100+200=300 bytes");
    }

    /// W2: should_warn returns false when used <= threshold.
    #[test]
    fn should_warn_returns_false_when_under_threshold() {
        assert!(
            !should_warn(4, 1_073_741_824),
            "4 bytes must not exceed 1 GB threshold"
        );
    }

    /// W2: should_warn returns true when used > threshold.
    #[test]
    fn should_warn_returns_true_when_over_threshold() {
        assert!(should_warn(10, 5), "10 bytes must exceed 5-byte threshold");
    }

    /// W2: should_warn returns false when equal to threshold.
    #[test]
    fn should_warn_returns_false_when_equal_to_threshold() {
        assert!(!should_warn(5, 5), "equal to threshold must not warn");
    }

    #[test]
    fn staging_cleanup_warn_not_emitted_when_under_threshold() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("small.bin"), b"tiny").unwrap();

        // Threshold = 1 GB; actual = 4 bytes → should not warn (no panic/error).
        check_staging_warn(dir.path(), 1_073_741_824);
        // No assertion — just verifying it doesn't panic or error.
    }

    #[test]
    fn staging_cleanup_warn_emitted_when_over_threshold() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("big.bin"), b"0123456789").unwrap();

        // 10 bytes > 5-byte threshold → should_warn must be true for this size.
        assert!(should_warn(10, 5), "total must exceed threshold");
        // check_staging_warn runs without panic.
        check_staging_warn(dir.path(), 5);
    }
}

// ─── Issue K: fetch timeout tests ────────────────────────────────────────────

// T-K3: RestoreConfig default fetch_timeout is 60 seconds.
#[test]
fn restore_fetch_timeout_default_is_60_seconds() {
    let cfg = RestoreConfig::default();
    assert_eq!(
        cfg.fetch_timeout,
        std::time::Duration::from_secs(60),
        "default fetch_timeout must be 60 seconds"
    );
}

// T-K4: fetch_timeout_secs is configurable via AppConfig and converts correctly.
#[test]
fn restore_fetch_timeout_configurable_via_app_config() {
    let mut app_config = viaticum_core::config::AppConfig::default();
    app_config.restore.fetch_timeout_secs = 120;
    // This mirrors the conversion used in handle/mod.rs wiring.
    let duration = std::time::Duration::from_secs(app_config.restore.fetch_timeout_secs);
    assert_eq!(
        duration,
        std::time::Duration::from_secs(120),
        "120s config must produce 120s Duration"
    );
}

// T-K2 marker: timeout behavior when fetch_from_holders hangs.
//
// The timeout path (RestoreError::Timeout) cannot be exercised in unit tests
// without injecting a slow mock for fetch_from_holders. Adding a trait for
// fetch_from_holders conflicts with project conventions (no traits for the future).
//
// Coverage: manual E2E via experiments/local_fault_test.sh — kill a holder
// mid-restore and observe 504 response and "fetch from holders timed out" body.
//
// This test verifies the compile-time presence of RestoreError::Timeout.
#[test]
fn restore_timeout_error_variant_exists() {
    let block = SourceBlockId([0u8; 32]);
    let err = super::RestoreError::Timeout { block, secs: 1 };
    let msg = err.to_string();
    assert!(
        msg.contains("timed out after 1s"),
        "Timeout error message must mention timeout duration, got: {msg}"
    );
}

// ─── B2: Wave 11b — restore_reconstructs_from_source_when_raw_missing ─────────

/// Wave 11b invariant (I5): after W11b, `raw/{esi}.bin` files are never written.
/// Restore must succeed by using the `rebuild_source_blob` path in
/// `decode_block_local` (lines ~461-499 in restore/mod.rs):
///   source still on disk → rebuild_source_blob → encode_raw(k_eff) → decode → bytes.
///
/// This test verifies the full roundtrip:
///   1. Backup via BackupCoordinator (W11b: no raw/ files written).
///   2. Source file still on disk.
///   3. No raw/{esi}.bin files anywhere in symbols_dir.
///   4. Restore succeeds and returned bytes == original.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_reconstructs_from_source_when_raw_missing() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    // 1. Write a source file with known content.
    let original_content =
        b"Wave 11b restore test: raw files must NOT exist, restore must work from source";
    let path = write_file(&files_dir, "w11b_restore.txt", original_content);

    // 2. Backup via BackupCoordinator — W11b guarantees no raw/ files are written.
    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path)).unwrap();
    let results = backup.flush_all(true, &Default::default()).unwrap();
    assert!(
        !results.is_empty(),
        "backup must produce at least one block"
    );

    // 3. Assert: NO raw/{esi}.bin files exist in symbols_dir (W11b invariant I5).
    fn find_files_recursive(
        root: &std::path::Path,
        pred: &dyn Fn(&std::path::Path) -> bool,
    ) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        fn walk(
            dir: &std::path::Path,
            pred: &dyn Fn(&std::path::Path) -> bool,
            found: &mut Vec<std::path::PathBuf>,
        ) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    walk(&p, pred, found);
                } else if pred(&p) {
                    found.push(p);
                }
            }
        }
        walk(root, pred, &mut found);
        found
    }

    let raw_bins = find_files_recursive(symbols_dir.path(), &|p| {
        p.extension().map(|e| e == "bin").unwrap_or(false)
    });
    assert!(
        raw_bins.is_empty(),
        "Wave 11b invariant violated: no .bin files must exist in symbols_dir after flush, found: {:?}",
        raw_bins
    );

    // 4. Source file is still on disk (the key assertion: restore path must use it).
    assert!(
        std::path::Path::new(&path).exists(),
        "source file must still exist on disk for rebuild_source_blob path"
    );

    // 5. Restore without any raw symbol files.
    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let request = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        device_id: DeviceId([2u8; 32]),
        job_id: JobId::new(),
    };
    let result = restore.restore(request).await;

    // 6. Assert: restore succeeded and returned bytes == original.
    let result = result.expect("restore must succeed when source file is still on disk");
    assert_eq!(
        result.files_restored, 1,
        "restore must succeed (files_restored=1); failures: {:?}",
        result.failures
    );
    assert!(result.failures.is_empty(), "no restore failures expected");

    // Verify content matches original.
    let rel = path.trim_start_matches('/');
    let restored_path = result.staging_path.join(rel);
    let restored_bytes =
        std::fs::read(&restored_path).expect("restored file must exist in staging area");
    assert_eq!(
        restored_bytes.as_slice(),
        original_content,
        "restored bytes must exactly match original content"
    );
}
