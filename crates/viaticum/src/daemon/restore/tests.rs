// Tests for RestoreCoordinator.
// Pattern: what_when_then.
//
// All tests use real Db::open_in_memory(), real RaptorQEncoder, tempfile::TempDir.
// Source block size is small (65_535 * 2 = ~128 KB) to keep encode/decode fast.
// Async tests use #[tokio::test(flavor = "multi_thread", worker_threads = 2)].
//
// Network restore goes through `SymbolSource`: the job tests below script a fake
// holder set (restore-i12 chunk rounds, T10 cancel); the libp2p round trip is
// covered by the E2E scenarios.

use std::sync::Arc;

use tempfile::TempDir;
use viaticum_core::db::Db;
use viaticum_core::erasure::RaptorQEncoder;
use viaticum_core::types::to_cbor_bytes;
use viaticum_core::types::{
    DeviceId, ErasureParams, FileId, FileRecord, FileVersion, LocalState, PackEntry,
    PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType,
    SymbolPlacement, Timestamp,
};

use crate::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};

use super::{RestoreConfig, RestoreCoordinator, VersionSelector, collect_esis_from_ranges};
use crate::cli::types::{RestoreFailureKind, RestoreJobState, RestoreOutcome};
use crate::daemon::restore::no_answer::NoAnswerPauses;
use crate::daemon::restore::staging::JobId;
use crate::daemon::restore::staging::record::{RecordStatus, read_job_record, scan_staging};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Small source block size for fast tests (2 * SYMBOL_SIZE = ~128 KB).
const SMALL_BLOCK_SIZE: u64 = 65_535 * 2;
pub(super) const TEST_EPOCH_KEY: [u8; 32] = [42u8; 32];

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
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: None,
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
        resubmit_tx: None,
        max_file_size_bytes: viaticum_core::constants::MAX_FILE_SIZE_CEILING_BYTES,
    };
    BackupCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()))
}

/// Build a RestoreCoordinator for Phase 2 (local) tests (no network needed).
/// `staging_dir`: the TempDir that will serve as both staging_root and data_dir
/// (they're the same in tests — staging_root = staging_dir/restore, data_dir = staging_dir).
// `_symbols_dir` is retained in the signature (callers share one TempDir with the
// backup coord) but is unused: Wave 11b removed the on-disk symbol tier, so the
// restore coord no longer reads from symbols_dir (PL-2).
fn test_restore_coord(db: Db, _symbols_dir: &TempDir, staging_dir: &TempDir) -> RestoreCoordinator {
    // Create the restore staging subdirectory under staging_dir.
    let staging_root = staging_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).expect("create staging_root");

    let restore_config = RestoreConfig::new(
        TEST_EPOCH_KEY,
        staging_root,
        staging_dir.path().to_path_buf(),
    );

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
        on_disk_confirmed: true,
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
fn select_version_index_skips_never_backed_up_version() {
    // CS-DR-14: Index must apply the same backed_up_at filter as Latest/BeforeDate.
    // Version 1 is queued-only (backed_up_at = None) → no symbols placed → selecting
    // it would only yield a loud BlockNotFound. select_version must return None.
    let record = make_record_with_versions(vec![
        make_version(Some(100)),
        make_version(None), // queued but never backed up
    ]);
    let result = RestoreCoordinator::select_version(&record, &VersionSelector::Index(1));
    assert!(
        result.is_none(),
        "Index(1) points at a never-backed-up version and must be filtered out"
    );

    // A backed-up version at the same index path still selects normally.
    let result0 = RestoreCoordinator::select_version(&record, &VersionSelector::Index(0));
    assert_eq!(result0.unwrap().backed_up_at, Some(Timestamp(100)));
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
            on_disk_confirmed: true,
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

// ─── restore-i38: a member by file_id, else by content hash (К4) ─────────────

/// Pack plaintext of members `(file_id, bytes)` in order.
fn pack_of(members: &[(u64, &[u8])]) -> Vec<u8> {
    let mut offset = 0u64;
    let entries: Vec<PackEntry> = members
        .iter()
        .map(|(id, bytes)| {
            let e = PackEntry {
                file_id: FileId(*id),
                offset,
                size: bytes.len() as u64,
            };
            offset += bytes.len() as u64;
            e
        })
        .collect();
    let mut plaintext = to_cbor_bytes(&entries);
    for (_, bytes) in members {
        plaintext.extend_from_slice(bytes);
    }
    plaintext
}

/// A copy or a renamed path has a fresh `file_id` that is not in the pack: its bytes
/// are found by the version's content hash.
#[test]
fn extract_by_file_id_absent_falls_back_to_content_hash() {
    let plaintext = pack_of(&[(1, b"first member"), (2, b"second member")]);
    let h = *blake3::hash(b"second member").as_bytes();

    let got = super::pipeline::extract_member(&plaintext, FileId(77), &h).unwrap();

    assert_eq!(got.as_deref(), Some(&b"second member"[..]));
}

/// After a swap inside one pack, the record's own member holds the other file's
/// content: the member whose bytes have the version's hash is returned.
#[test]
fn extract_by_file_id_with_wrong_bytes_falls_back_to_content_hash() {
    let plaintext = pack_of(&[(1, b"content of d1"), (2, b"content of d2")]);
    let h_d2 = *blake3::hash(b"content of d2").as_bytes();

    let got = super::pipeline::extract_member(&plaintext, FileId(1), &h_d2).unwrap();

    assert_eq!(got.as_deref(), Some(&b"content of d2"[..]));
}

/// No member has the content and none has the record's `file_id`: `None` (restore
/// reports it as `PackIndexParseFailed`).
#[test]
fn extract_fails_when_no_entry_matches_hash() {
    let plaintext = pack_of(&[(1, b"aaa"), (2, b"bbb")]);
    let h = *blake3::hash(b"ccc").as_bytes();

    let got = super::pipeline::extract_member(&plaintext, FileId(7), &h).unwrap();

    assert!(got.is_none());
}

/// A catalog from before L1: the version's hash is of other bytes than those packed.
/// No member has it, so the member packed under the record's `file_id` is returned.
#[test]
fn extract_falls_back_to_file_id_member_when_no_member_has_the_hash() {
    let plaintext = pack_of(&[(1, b"bytes packed at flush"), (2, b"bbb")]);
    let h_at_enqueue = *blake3::hash(b"bytes seen at enqueue").as_bytes();

    let got = super::pipeline::extract_member(&plaintext, FileId(1), &h_at_enqueue).unwrap();

    assert_eq!(got.as_deref(), Some(&b"bytes packed at flush"[..]));
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

/// Wave 11b / PL-2: end-to-end restore of the LATEST version via rebuild-from-source.
///
/// After Wave 11b there is no on-disk symbol cache, so an end-to-end restore is only
/// possible for a version whose source content still exists on disk (rebuild path) or
/// whose symbols live in holders (network path). This test backs up two versions and
/// restores the latest (still on disk) via `rebuild_source_blob`. Restoring a historical
/// version whose source content was overwritten now requires holders — covered by the
/// network-restore tests. Pure version-selection logic (Index/BeforeDate/Latest) is
/// covered by the `select_version_*` unit tests above.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_latest_version_via_source_rebuild() {
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

    // Restore latest (v2, "version two content" — still on disk, rebuild works)
    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let request_latest = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        job_id: JobId::new(),
    };
    let result2 = restore.restore(request_latest).await.unwrap();
    assert_eq!(
        result2.files_restored, 1,
        "failures: {:?}",
        result2.failures
    );

    let rel = path.trim_start_matches('/');
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
        job_id: JobId::new(),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(result.files_restored, 0);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].path, "/nonexistent/file.txt");
    assert_eq!(result.failures[0].kind, RestoreFailureKind::NotBackedUp);
}

/// CS-DR-10 + restore-i8: a path that matches nothing creates no job dir (staging
/// is never cleaned up by the daemon, so a typo must leave nothing behind).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_of_unmatched_path_creates_no_staging_dir() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();
    db.upsert_file(&catalog_record("/a/bc/file.txt", 1))
        .unwrap();

    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    for path in ["/nope.bin", "/a/b"] {
        let result = restore
            .restore(super::RestoreRequest {
                path: path.to_string(),
                version_selector: VersionSelector::Latest,
                job_id: JobId::new(),
            })
            .await
            .unwrap();
        assert_eq!(result.files_restored, 0, "{path}");
        assert!(result.staging_path.as_os_str().is_empty(), "{path}");
    }
    let job_dirs = std::fs::read_dir(staging_dir.path().join("restore"))
        .unwrap()
        .count();
    assert_eq!(
        job_dirs, 0,
        "no job dir may be created for an unmatched path"
    );
}

/// restore-i14: a successful job leaves a finished record naming the restored file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_writes_finished_job_record_with_restored_paths() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();
    let path = write_file(&files_dir, "rec.txt", b"job record content");

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path)).unwrap();
    backup.flush_all(true, &Default::default()).unwrap();

    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let job_id = JobId::new();
    let result = restore
        .restore(super::RestoreRequest {
            path: path.clone(),
            version_selector: VersionSelector::Latest,
            job_id,
        })
        .await
        .unwrap();

    let record = read_job_record(&result.staging_path).unwrap().unwrap();
    assert_eq!(record.job_id, job_id);
    assert_eq!(record.path, path);
    assert_eq!(record.state, RestoreJobState::Finished);
    assert_eq!(record.outcome, Some(RestoreOutcome::Complete));
    assert_eq!((record.files_total, record.files_restored), (1, 1));
    assert_eq!(record.restored_paths, vec![path.clone()]);
    assert!(record.failures.is_empty());
    assert!(record.finished_at.is_some());

    // The scan after a "restart" reports the same outcome, and the staged file is
    // not confused with the service entries.
    let jobs = scan_staging(&staging_dir.path().join("restore"));
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].outcome, RestoreOutcome::Complete);
    assert_eq!(
        jobs[0].partial_files, 0,
        "no temp may remain after a clean job"
    );
}

/// N1 / restore-i14: the job dir carries a `running` record before the first file
/// is written, so a crash at any later point reads as `interrupted`, not unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn begin_job_writes_running_record_before_any_file() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();
    let restore = test_restore_coord(db, &symbols_dir, &staging_dir);
    let request = super::RestoreRequest {
        path: "/home/kolya/photos/".to_string(),
        version_selector: VersionSelector::Latest,
        job_id: JobId::new(),
    };

    restore
        .config
        .jobs
        .mark_running(request.job_id, &request.path, 7);
    let writer = restore.begin_job(&request).unwrap();

    let on_disk = read_job_record(writer.staging_path()).unwrap().unwrap();
    assert_eq!(
        Some(&on_disk),
        restore.config.jobs.record(request.job_id).as_ref()
    );
    assert_eq!(on_disk.state, RestoreJobState::Running);
    assert_eq!(on_disk.job_id, request.job_id);
    assert_eq!(on_disk.files_total, 7);
    // "Crash" now: the scan reports the job as interrupted, with 0 files.
    let jobs = scan_staging(&staging_dir.path().join("restore"));
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].record, RecordStatus::NotFinished);
    assert_eq!(jobs[0].outcome, RestoreOutcome::Interrupted);
    assert_eq!(jobs[0].files_restored, 0);
}

/// W2 / restore-i14: a file whose target is taken (a directory already sits there)
/// fails with AlreadyExists after its block was decoded; it is not counted, it is
/// in failures, and the files on disk are exactly the record's restored_paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_with_taken_target_counts_only_published_files() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();
    let a = write_file(&files_dir, "a.txt", b"file a content");
    let b = write_file(&files_dir, "b.txt", b"file b content");

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&a)).unwrap();
    backup.process_event(added_event(&b)).unwrap();
    backup.flush_all(true, &Default::default()).unwrap();

    let job_id = JobId::new();
    let job_dir = staging_dir.path().join("restore").join(job_id.to_string());
    std::fs::create_dir_all(job_dir.join(b.trim_start_matches('/'))).unwrap();

    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let prefix = files_dir.path().to_string_lossy().to_string() + "/";
    let result = restore
        .restore(super::RestoreRequest {
            path: prefix,
            version_selector: VersionSelector::Latest,
            job_id,
        })
        .await
        .unwrap();

    assert_eq!(result.files_restored, 1, "failures: {:?}", result.failures);
    assert!(
        result.failures.iter().any(|f| f.path == b
            && f.detail.contains("already exists")
            && f.kind == RestoreFailureKind::WriteFailed),
        "b must fail with AlreadyExists: {:?}",
        result.failures
    );
    let record = read_job_record(&job_dir).unwrap().unwrap();
    assert_eq!(record.outcome, Some(RestoreOutcome::Partial));
    assert_eq!(record.files_restored, 1);
    assert_eq!(record.restored_paths, vec![a.clone()]);
    assert_eq!(record.failures.len(), 1);
    assert_eq!(record.failures[0].path, b);

    // The disk agrees with the record: regular files outside `.viaticum-*`.
    let mut on_disk = Vec::new();
    collect_user_files(&job_dir, &job_dir, &mut on_disk);
    assert_eq!(on_disk, record.restored_paths);
}

/// Regular files under `job_dir` (top-level `.viaticum-*` skipped) as catalog paths.
fn collect_user_files(job_dir: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if dir == job_dir && e.file_name().to_string_lossy().starts_with(".viaticum-") {
            continue;
        }
        let m = std::fs::symlink_metadata(&p).unwrap();
        if m.is_dir() {
            collect_user_files(job_dir, &p, out);
        } else if m.is_file() {
            out.push(format!("/{}", p.strip_prefix(job_dir).unwrap().display()));
        }
    }
    out.sort();
}

// ─── CS-DR-10: resolve_path ───────────────────────────────────────────────────

fn catalog_record(path: &str, id: u64) -> FileRecord {
    FileRecord {
        file_id: FileId(id),
        path: path.to_string(),
        importance: 0.5,
        devices: vec![],
        versions: vec![make_version(Some(200))],
        first_seen: Timestamp(0),
        on_disk_confirmed: true,
    }
}

fn resolved_paths(db: &Db, path: &str) -> Vec<String> {
    let mut v: Vec<String> = super::resolve_path(db, path)
        .unwrap()
        .into_iter()
        .map(|r| r.path)
        .collect();
    v.sort();
    v
}

/// CS-DR-10: "/a/b" is a directory prefix only on a separator boundary; it must not
/// capture the sibling "/a/bc".
#[test]
fn resolve_path_prefix_without_separator_does_not_match_sibling() {
    let db = Db::open_in_memory().unwrap();
    db.upsert_file(&catalog_record("/a/b/x.txt", 1)).unwrap();
    db.upsert_file(&catalog_record("/a/b/sub/y.txt", 2))
        .unwrap();
    db.upsert_file(&catalog_record("/a/bc/z.txt", 3)).unwrap();
    db.upsert_file(&catalog_record("/a/b-old/w.txt", 4))
        .unwrap();

    assert_eq!(
        resolved_paths(&db, "/a/b"),
        vec!["/a/b/sub/y.txt".to_string(), "/a/b/x.txt".to_string()]
    );
    assert!(
        resolved_paths(&db, "/a/bc/z").is_empty(),
        "no partial-name match"
    );
    assert!(
        resolved_paths(&db, "/a/b/x").is_empty(),
        "no file-name prefix match"
    );
}

/// An exact record wins over a directory of the same name.
#[test]
fn resolve_path_prefers_exact_record_over_prefix() {
    let db = Db::open_in_memory().unwrap();
    db.upsert_file(&catalog_record("/a/report", 1)).unwrap();
    db.upsert_file(&catalog_record("/a/report/inner.txt", 2))
        .unwrap();
    assert_eq!(
        resolved_paths(&db, "/a/report"),
        vec!["/a/report".to_string()]
    );
}

/// A trailing separator is a plain prefix query (the directory's contents only).
#[test]
fn resolve_path_trailing_separator_is_prefix_query() {
    let db = Db::open_in_memory().unwrap();
    db.upsert_file(&catalog_record("/a/b/x.txt", 1)).unwrap();
    db.upsert_file(&catalog_record("/a/bc/z.txt", 2)).unwrap();
    assert_eq!(resolved_paths(&db, "/a/b/"), vec!["/a/b/x.txt".to_string()]);
}

/// CS-DR-6 / restore-i11: restore writes the file into staging and leaves the
/// catalog's per-device state alone (no `Present` for the restoring device, no new
/// device entry).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_does_not_change_local_state() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    let content = b"state update test";
    let path = write_file(&files_dir, "state.txt", content);

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path)).unwrap();
    backup.flush_all(true, &Default::default()).unwrap();
    let devices_before = db.get_file(&path).unwrap().unwrap().devices;

    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let request = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        job_id: JobId::new(),
    };
    let result = restore.restore(request).await.unwrap();
    assert_eq!(result.files_restored, 1, "failures: {:?}", result.failures);

    let devices_after = db.get_file(&path).unwrap().unwrap().devices;
    assert_eq!(devices_after, devices_before);
}

/// CS-DR-6 + delete-i3: restoring a file whose record is deleted keeps the record
/// deleted, so its block is not live-referenced and the owner delete window keeps
/// running from the original deletion time. (The source stays on disk only so the
/// unit test can rebuild the block without a network; the catalog state is what is
/// checked.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_of_deleted_file_keeps_delete_cooldown_running() {
    use viaticum_core::deletion::{latest_deletion_per_block, live_referenced_blocks};

    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    let content = b"deleted then restored";
    let path = write_file(&files_dir, "gone.txt", content);

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&path)).unwrap();
    backup.flush_all(true, &Default::default()).unwrap();

    // The user deletes the file; the watcher marks the record deleted on the device.
    let deleted_at = Timestamp(1_000);
    let mut record = db.get_file(&path).unwrap().unwrap();
    assert!(!record.devices.is_empty());
    for (_, state) in record.devices.iter_mut() {
        *state = LocalState::Deleted(deleted_at);
    }
    db.upsert_file(&record).unwrap();
    let block = record.versions.last().unwrap().source_block_id;

    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let request = super::RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        job_id: JobId::new(),
    };
    let result = restore.restore(request).await.unwrap();
    assert_eq!(result.files_restored, 1, "failures: {:?}", result.failures);

    let after = db.get_file(&path).unwrap().unwrap();
    assert!(
        after
            .devices
            .iter()
            .all(|(_, s)| *s == LocalState::Deleted(deleted_at)),
        "restore changed LocalState: {:?}",
        after.devices
    );
    let files = db.list_all_files().unwrap();
    assert!(!live_referenced_blocks(&files).contains(&block));
    assert_eq!(
        latest_deletion_per_block(&files).get(&block),
        Some(&deleted_at)
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
        job_id: JobId::new(),
    };
    let result = restore.restore(request).await.unwrap();

    assert_eq!(result.files_restored, 2, "failures: {:?}", result.failures);
    assert_eq!(result.blocks_fetched, 1, "should decode exactly 1 block");
    assert!(result.failures.is_empty());
}

/// CS-DR-3: one unrecoverable block must not abort the whole restore job. The bad
/// block is recorded in `failures`; the recoverable block is still restored, and
/// the job returns Ok with the staging path. The bad block is given higher
/// importance so it is attempted FIRST — proving the loop does not bail on the
/// first failure but continues to the lower-importance, recoverable block.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_unrecoverable_block_does_not_abort_remaining_blocks() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let staging_dir = TempDir::new().unwrap();

    // 1. Back up a real file in its own subdir → its own recoverable single block.
    let good_dir = files_dir.path().join("data");
    std::fs::create_dir_all(&good_dir).unwrap();
    let good_content = b"recoverable block content";
    let good_path = good_dir.join("good.txt");
    std::fs::write(&good_path, good_content).unwrap();
    let good_path_str = good_path.to_string_lossy().to_string();

    let mut backup = test_backup_coord(db.clone(), &symbols_dir);
    backup.process_event(added_event(&good_path_str)).unwrap();
    let results = backup.flush_all(true, &Default::default()).unwrap();
    assert_eq!(results.len(), 1, "good file must produce one block");

    // 2. Inject a second file referencing a DISTINCT, unrecoverable block: the
    //    SourceBlockRecord has encrypted_size = None (legacy), which fails the
    //    per-block decode path. Give it HIGH importance so it is tried first.
    let bad_block = SourceBlockId([0xBAu8; 32]);
    let bad_path = good_dir.join("bad.txt");
    let bad_path_str = bad_path.to_string_lossy().to_string();
    db.upsert_file(&FileRecord {
        file_id: FileId(777),
        path: bad_path_str.clone(),
        importance: 0.99, // higher than the good file → sorts first
        devices: vec![],
        versions: vec![FileVersion {
            content_hash: [0u8; 32],
            source_block_id: bad_block,
            k: 2,
            t: 65_535,
            created_at: Timestamp(100),
            backed_up_at: Some(Timestamp(200)),
        }],
        first_seen: Timestamp(0),
        on_disk_confirmed: true,
    })
    .unwrap();
    db.upsert_source_block(&SourceBlockRecord {
        seal_generation: 0,
        block_id: bad_block,
        k: 2,
        t: 65_535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(100),
        encrypted_size: None, // legacy record → unrecoverable
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.99,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    })
    .unwrap();

    // 3. Restore the shared prefix covering BOTH files.
    let restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);
    let prefix = good_dir.to_string_lossy().to_string() + "/";
    let request = super::RestoreRequest {
        path: prefix,
        version_selector: VersionSelector::Latest,
        job_id: JobId::new(),
    };

    // The job must COMPLETE (Ok), not abort on the bad block.
    let result = restore
        .restore(request)
        .await
        .expect("restore must not abort on one unrecoverable block");

    // The recoverable block was restored.
    assert_eq!(
        result.files_restored, 1,
        "the recoverable file must still be restored; failures: {:?}",
        result.failures
    );
    let good_rel = good_path_str.trim_start_matches('/');
    let restored = std::fs::read(result.staging_path.join(good_rel))
        .expect("recoverable file must exist in staging");
    assert_eq!(restored.as_slice(), good_content);

    // The bad block is recorded in failures (error still detected/recorded — the
    // underlying decode error is NOT swallowed, just contained per-block).
    assert!(
        result.failures.iter().any(|f| f.path == bad_path_str),
        "the unrecoverable block's file must appear in failures, got: {:?}",
        result.failures
    );

    // restore-i14: the job record carries the same per-file outcome.
    let record = read_job_record(&result.staging_path).unwrap().unwrap();
    assert_eq!(record.state, RestoreJobState::Finished);
    assert_eq!(record.outcome, Some(RestoreOutcome::Partial));
    assert_eq!(record.files_total, 2);
    assert_eq!(record.files_restored, 1);
    assert_eq!(record.restored_paths, vec![good_path_str.clone()]);
    assert_eq!(record.failures.len(), 1);
    assert_eq!(record.failures[0].path, bad_path_str);
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
        .fetch_from_holders(
            &block_id,
            &placements,
            &params,
            &mut NoAnswerPauses::new(JobId::new(), 1),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(super::RestoreError::InsufficientSymbols { got: 0, .. })
        ),
        "expected InsufficientSymbols(got=0), got: {result:?}"
    );
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
        on_disk_confirmed: true,
    };
    db.upsert_file(&record).unwrap();

    // Insert a source block record.
    let source_block = SourceBlockRecord {
        seal_generation: 0,
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
    };
    db.upsert_source_block(&source_block).unwrap();

    let _restore = test_restore_coord(db.clone(), &symbols_dir, &staging_dir);

    // The restore would try to decode this block and fail (no symbols); post
    // CS-DR-3 that failure is recorded in `failures` and the job continues rather
    // than aborting. Either way the path is never written: if decode ever did
    // succeed, extract_and_write_file must still reject the malicious record.path.
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
            on_disk_confirmed: true,
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

// ─── B1.3: restore as a job (restore-i3, i4, i12, i14, T10) ──────────────────
//
// `FakeHolders` plays the holder set behind `SymbolSource`: it serves the real
// bound symbols of a backed-up block (encode_raw + apply_binding, as holders store
// them), or hangs, and can run a hook on every request.

use std::collections::HashMap;
use std::sync::Mutex;

use viaticum_core::erasure::{ErasureEncoder, Symbol};
use viaticum_core::messages::RestoreRequestMsg;

use crate::daemon::restore::jobs::RestoreJobs;
use crate::daemon::restore::{RestoreError, RestoreRequest, failure_kind};
use crate::daemon::symbol_fetch::{FetchError, RestoreSource, SymbolSource};

pub(super) type RequestHook = Box<dyn Fn() + Send + Sync>;

#[derive(Default)]
pub(super) struct FakeHolders {
    /// Bound symbols by (holder, block, ESI).
    pub(super) symbols: Mutex<HashMap<(DeviceId, SourceBlockId, u32), Symbol>>,
    pub(super) hang: bool,
    /// Every answered request takes this long (a slow link).
    pub(super) delay: std::time::Duration,
    /// Holders whose first request runs into the 30 s request timeout.
    pub(super) silent_first: Mutex<std::collections::HashSet<DeviceId>>,
    pub(super) requests: Mutex<Vec<(DeviceId, usize)>>,
    pub(super) on_request: Mutex<Option<RequestHook>>,
    /// The owner has no connection to any holder: every request fails at once,
    /// as `send_to_device` does without a live connection (restore-i26).
    pub(super) offline: std::sync::atomic::AtomicBool,
    /// Holders that never answer: every request to them fails at once.
    pub(super) dead: Mutex<std::collections::HashSet<DeviceId>>,
    /// `reconnect` call number at which `offline` clears (the redial worked).
    pub(super) online_after_reconnects: Mutex<Option<usize>>,
    /// Every `reconnect` call: when (tokio clock) and with which holders.
    pub(super) reconnects: Mutex<Vec<(tokio::time::Instant, Vec<DeviceId>)>>,
}

#[async_trait::async_trait]
impl SymbolSource for FakeHolders {
    async fn request(
        &self,
        holder: DeviceId,
        req: RestoreRequestMsg,
    ) -> Result<Vec<Symbol>, FetchError> {
        self.requests
            .lock()
            .unwrap()
            .push((holder, req.esi_list.len()));
        if let Some(hook) = self.on_request.lock().unwrap().as_ref() {
            hook();
        }
        if self.offline.load(std::sync::atomic::Ordering::SeqCst)
            || self.dead.lock().unwrap().contains(&holder)
        {
            return Err(FetchError::Swarm("peer not authenticated".into()));
        }
        if self.hang {
            std::future::pending::<()>().await;
        }
        let silent = self.silent_first.lock().unwrap().remove(&holder);
        if silent {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            return Err(FetchError::Swarm("request timed out".into()));
        }
        tokio::time::sleep(self.delay).await;
        let map = self.symbols.lock().unwrap();
        Ok(req
            .esi_list
            .iter()
            .filter_map(|e| map.get(&(holder, req.source_block_id, *e)).cloned())
            .collect())
    }
}

#[async_trait::async_trait]
impl RestoreSource for FakeHolders {
    async fn reconnect(&self, holders: &[DeviceId]) {
        let mut calls = self.reconnects.lock().unwrap();
        calls.push((tokio::time::Instant::now(), holders.to_vec()));
        if *self.online_after_reconnects.lock().unwrap() == Some(calls.len()) {
            self.offline
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Spread every symbol of `path`'s block over three holders: placements in the
/// catalog, bound symbols in `holders`. Call while the source file still exists.
pub(super) async fn place_on_fake_holders(db: &Db, path: &str, holders: &FakeHolders) {
    place_on_fake_holders_with_status(db, path, holders, PlacementStatus::Alive).await;
}

/// `place_on_fake_holders` with every placement recorded under `status`.
async fn place_on_fake_holders_with_status(
    db: &Db,
    path: &str,
    holders: &FakeHolders,
    status: PlacementStatus,
) {
    let record = db.get_file(path).unwrap().unwrap();
    let version = record.versions.last().unwrap();
    let block = db
        .get_source_block(&version.source_block_id)
        .unwrap()
        .unwrap();
    let blob = crate::daemon::backup::pipeline::rebuild_source_blob(
        db,
        &block,
        &TEST_EPOCH_KEY,
        &Default::default(),
    )
    .await
    .unwrap();
    let params = block.erasure_params();
    let enc = RaptorQEncoder::new();
    let raws = enc.encode_raw(&blob, &params, 0, params.n).unwrap();
    let per = params.n.div_ceil(3);
    for h in 0..3u32 {
        let holder = DeviceId([0x40 + h as u8; 32]);
        let start = h * per;
        let count = per.min(params.n.saturating_sub(start));
        if count == 0 {
            continue;
        }
        db.upsert_placement(&SymbolPlacement {
            source_block_id: block.block_id,
            holder_id: holder,
            file_id: record.file_id,
            esi_ranges: vec![(start, count)],
            binding_seed: viaticum_core::erasure::binding_seed(&block.block_id, &holder),
            status,
            last_verified: None,
            placed_at: Timestamp(0),
            consecutive_misses: 0,
        })
        .unwrap();
        let mut map = holders.symbols.lock().unwrap();
        for raw in raws
            .iter()
            .filter(|s| s.esi >= start && s.esi < start + count)
        {
            map.insert(
                (holder, block.block_id, raw.esi),
                enc.apply_binding(raw.clone(), &block.block_id, &holder),
            );
        }
    }
}

/// Back up `name` with `content` as its own block (one flush per file).
pub(super) fn backup_one(
    db: &Db,
    symbols_dir: &TempDir,
    dir: &std::path::Path,
    name: &str,
    content: &[u8],
) -> String {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    let path = path.to_string_lossy().into_owned();
    let mut backup = test_backup_coord(db.clone(), symbols_dir);
    backup.process_event(added_event(&path)).unwrap();
    backup.flush_all(true, &Default::default()).unwrap();
    path
}

pub(super) fn coord_with_source(
    db: Db,
    staging_dir: &TempDir,
    source: Option<Arc<FakeHolders>>,
) -> RestoreCoordinator {
    let staging_root = staging_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).unwrap();
    let mut config = RestoreConfig::new(
        TEST_EPOCH_KEY,
        staging_root,
        staging_dir.path().to_path_buf(),
    );
    config.symbols = source.map(|s| s as Arc<dyn RestoreSource>);
    RestoreCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()))
}

pub(super) fn request(path: &str) -> RestoreRequest {
    RestoreRequest {
        path: path.to_string(),
        version_selector: VersionSelector::Latest,
        job_id: JobId::new(),
    }
}

/// The fake holder set is a faithful stand-in: with the source gone, the file
/// comes back from "the network" byte for byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_without_source_decodes_symbols_from_holders() {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, staging_dir) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let content = b"network restore content".repeat(50);
    let path = backup_one(&db, &symbols_dir, files_dir.path(), "net.bin", &content);
    let holders = Arc::new(FakeHolders::default());
    place_on_fake_holders(&db, &path, &holders).await;
    std::fs::remove_file(&path).unwrap();

    let coord = coord_with_source(db, &staging_dir, Some(holders.clone()));
    let result = coord.restore(request(&path)).await.unwrap();

    assert_eq!(result.files_restored, 1, "{:?}", result.failures);
    assert!(
        !holders.requests.lock().unwrap().is_empty(),
        "network not used"
    );
    let staged = result.staging_path.join(path.trim_start_matches('/'));
    assert_eq!(std::fs::read(staged).unwrap(), content);
}

/// restore-i2: the source is gone and every placement of the block is `status`
/// (the holders missed PoS rounds, but they are back and still hold the symbols).
/// Restore must ask them and bring the file back byte for byte.
async fn restore_from_holders_all_marked(status: PlacementStatus) {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, staging_dir) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let content = b"holder came back after missed PoS rounds".repeat(40);
    let path = backup_one(&db, &symbols_dir, files_dir.path(), "back.bin", &content);
    let holders = Arc::new(FakeHolders::default());
    place_on_fake_holders_with_status(&db, &path, &holders, status).await;
    std::fs::remove_file(&path).unwrap();

    let coord = coord_with_source(db, &staging_dir, Some(holders.clone()));
    let result = coord.restore(request(&path)).await.unwrap();

    assert_eq!(
        result.files_restored, 1,
        "{status:?} holders not asked: {:?}",
        result.failures
    );
    assert!(
        !holders.requests.lock().unwrap().is_empty(),
        "network not used"
    );
    let staged = result.staging_path.join(path.trim_start_matches('/'));
    assert_eq!(std::fs::read(staged).unwrap(), content);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_without_source_when_all_placements_uncertain_fetches_from_them() {
    restore_from_holders_all_marked(PlacementStatus::Uncertain).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_without_source_when_all_placements_presumed_lost_fetches_from_them() {
    restore_from_holders_all_marked(PlacementStatus::PresumedLost).await;
}

/// restore-i3: source gone and no placements → the file is a failure with the
/// machine reason `holders_unavailable`; nothing restored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_reports_holders_unavailable_when_no_source_and_no_placements() {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, staging_dir) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let path = backup_one(&db, &symbols_dir, files_dir.path(), "gone.bin", b"gone");
    std::fs::remove_file(&path).unwrap();

    let coord = coord_with_source(db, &staging_dir, Some(Arc::new(FakeHolders::default())));
    let req = request(&path);
    let job_id = req.job_id;
    let result = coord.restore(req).await.unwrap();

    assert_eq!(result.files_restored, 0);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].path, path);
    assert_eq!(
        result.failures[0].kind,
        RestoreFailureKind::HoldersUnavailable
    );
    let record = read_job_record(&result.staging_path).unwrap().unwrap();
    assert_eq!(record.outcome, Some(RestoreOutcome::NothingRestored));
    assert_eq!(coord.config.jobs.record(job_id), Some(record));
}

/// A catalog record whose only version was never backed up.
fn not_backed_up_record(path: &str, id: u64) -> FileRecord {
    FileRecord {
        file_id: FileId(id),
        path: path.to_string(),
        importance: 0.5,
        devices: vec![],
        versions: vec![FileVersion {
            content_hash: [7u8; 32],
            source_block_id: SourceBlockId([7u8; 32]),
            k: 1,
            t: 64,
            created_at: Timestamp(10),
            backed_up_at: None,
        }],
        first_seen: Timestamp(0),
        on_disk_confirmed: true,
    }
}

/// restore-i3: a file under the path with no backed-up version is reported
/// `not_backed_up`; the backed-up sibling is restored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_reports_not_backed_up_for_version_without_backup() {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, staging_dir) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let ok = backup_one(&db, &symbols_dir, files_dir.path(), "ok.txt", b"ok content");
    let pending = files_dir
        .path()
        .join("pending.txt")
        .to_string_lossy()
        .into_owned();
    db.upsert_file(&not_backed_up_record(&pending, 900))
        .unwrap();

    let coord = coord_with_source(db, &staging_dir, None);
    let prefix = files_dir.path().to_string_lossy().into_owned() + "/";
    let result = coord.restore(request(&prefix)).await.unwrap();

    assert_eq!(result.files_restored, 1, "{:?}", result.failures);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].path, pending);
    assert_eq!(result.failures[0].kind, RestoreFailureKind::NotBackedUp);
    let record = read_job_record(&result.staging_path).unwrap().unwrap();
    assert_eq!(record.restored_paths, vec![ok]);
    assert_eq!(record.outcome, Some(RestoreOutcome::Partial));
}

/// restore-i3 (per-file accounting): every matched file ends either restored or
/// with a failure — restored + failed == files_total — in the registry, in the job
/// record on disk, and on disk itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_counts_restored_plus_failed_equal_files_total() {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, staging_dir) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let restorable = backup_one(&db, &symbols_dir, files_dir.path(), "a.txt", b"aaaa");
    let lost = backup_one(&db, &symbols_dir, files_dir.path(), "b.txt", b"bbbb");
    std::fs::remove_file(&lost).unwrap();
    let pending = files_dir
        .path()
        .join("c.txt")
        .to_string_lossy()
        .into_owned();
    db.upsert_file(&not_backed_up_record(&pending, 901))
        .unwrap();

    let coord = coord_with_source(db, &staging_dir, None);
    let prefix = files_dir.path().to_string_lossy().into_owned() + "/";
    let req = request(&prefix);
    let job_id = req.job_id;
    let result = coord.restore(req).await.unwrap();

    let record = coord.config.jobs.record(job_id).unwrap();
    assert_eq!(record.files_total, 3);
    assert_eq!(
        record.files_restored as usize + record.failures.len(),
        record.files_total as usize,
        "{record:?}"
    );
    assert_eq!(record.restored_paths, vec![restorable]);
    let mut failed: Vec<(String, RestoreFailureKind)> = record
        .failures
        .iter()
        .map(|f| (f.path.clone(), f.kind))
        .collect();
    failed.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        failed,
        vec![
            (lost, RestoreFailureKind::HoldersUnavailable),
            (pending, RestoreFailureKind::NotBackedUp),
        ]
    );
    assert_eq!(
        read_job_record(&result.staging_path).unwrap().unwrap(),
        record
    );
    let mut on_disk = Vec::new();
    collect_user_files(&result.staging_path, &result.staging_path, &mut on_disk);
    assert_eq!(on_disk, record.restored_paths);
}

/// restore-i4: while the job runs, the registry shows it `running` with the files
/// already restored; at the end it is `finished` with the restored paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_records_progress_and_restored_paths_into_registered_job() {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, staging_dir) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let first = backup_one(&db, &symbols_dir, files_dir.path(), "first.txt", b"first");
    let second = backup_one(
        &db,
        &symbols_dir,
        files_dir.path(),
        "second.bin",
        &[9u8; 3000],
    );
    // `first` is restored from its source first (higher importance); `second`
    // then goes to the network.
    let first_block = db.get_file(&first).unwrap().unwrap().versions[0].source_block_id;
    let mut rec = db.get_source_block(&first_block).unwrap().unwrap();
    rec.importance = 0.99;
    db.upsert_source_block(&rec).unwrap();
    let holders = Arc::new(FakeHolders::default());
    place_on_fake_holders(&db, &second, &holders).await;
    std::fs::remove_file(&second).unwrap();

    let coord = coord_with_source(db, &staging_dir, Some(holders.clone()));
    let jobs = coord.config.jobs.clone();
    let prefix = files_dir.path().to_string_lossy().into_owned() + "/";
    let job = jobs.submit(JobId::new(), &prefix, 2);
    let job_id = JobId::parse(&job.job_id).unwrap();
    assert_eq!(job.state, RestoreJobState::Queued);

    let seen: Arc<Mutex<Vec<crate::cli::types::RestoreJob>>> = Arc::default();
    {
        let (jobs, seen) = (jobs.clone(), seen.clone());
        *holders.on_request.lock().unwrap() = Some(Box::new(move || {
            seen.lock().unwrap().push(jobs.get(job_id).unwrap());
        }));
    }
    coord
        .restore(RestoreRequest {
            path: prefix,
            version_selector: VersionSelector::Latest,
            job_id,
        })
        .await
        .unwrap();

    let during = seen.lock().unwrap()[0].clone();
    assert_eq!(during.state, RestoreJobState::Running);
    assert_eq!(during.files_restored, 1);
    assert_eq!(during.restored_paths, vec![first.clone()]);
    let done = jobs.get(job_id).unwrap();
    assert_eq!(done.state, RestoreJobState::Finished);
    assert_eq!(done.outcome, Some(RestoreOutcome::Complete));
    assert_eq!(done.restored_paths, vec![first, second]);
}

/// T10: on the daemon's cancel token a job waiting on a silent holder stops at
/// once; every file not done is `interrupted`, the outcome is `interrupted`, and the
/// final record is on disk (the drain is 10 s; this takes well under 1 s).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_cancelled_marks_remaining_files_interrupted_and_outcome_interrupted() {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, staging_dir) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let a = backup_one(&db, &symbols_dir, files_dir.path(), "a.bin", &[1u8; 2000]);
    let b = backup_one(&db, &symbols_dir, files_dir.path(), "b.bin", &[2u8; 2000]);
    let holders = Arc::new(FakeHolders {
        hang: true,
        ..Default::default()
    });
    place_on_fake_holders(&db, &a, &holders).await;
    place_on_fake_holders(&db, &b, &holders).await;
    std::fs::remove_file(&a).unwrap();
    std::fs::remove_file(&b).unwrap();

    let coord = coord_with_source(db, &staging_dir, Some(holders.clone()));
    let cancel = coord.config.cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        cancel.cancel();
    });
    let prefix = files_dir.path().to_string_lossy().into_owned() + "/";
    let req = request(&prefix);
    let job_id = req.job_id;
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), coord.restore(req))
        .await
        .expect("a cancelled restore must not hang")
        .unwrap();

    assert!(result.interrupted);
    assert_eq!(
        holders.requests.lock().unwrap().len(),
        1,
        "one request, abandoned"
    );
    let record = read_job_record(&result.staging_path).unwrap().unwrap();
    assert_eq!(record.state, RestoreJobState::Finished);
    assert_eq!(record.outcome, Some(RestoreOutcome::Interrupted));
    assert_eq!(record.files_restored, 0);
    let mut paths: Vec<&str> = record.failures.iter().map(|f| f.path.as_str()).collect();
    paths.sort();
    assert_eq!(paths, vec![a.as_str(), b.as_str()]);
    assert!(
        record
            .failures
            .iter()
            .all(|f| f.kind == RestoreFailureKind::Interrupted)
    );
    assert_eq!(coord.config.jobs.record(job_id), Some(record));
}

/// A job whose staging dir cannot be opened fails before it starts; `run` still
/// finishes it in the registry with the reason — never left `queued`/`running`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_finishes_job_even_when_restore_returns_job_level_error() {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, data_dir, elsewhere) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let path = backup_one(&db, &symbols_dir, files_dir.path(), "x.txt", b"x");
    // Staging root outside data_dir: StagingWriter::open refuses (OutsideDataDir).
    let staging_root = elsewhere.path().join("restore");
    std::fs::create_dir_all(&staging_root).unwrap();
    let config = RestoreConfig::new(TEST_EPOCH_KEY, staging_root, data_dir.path().to_path_buf());
    let jobs = config.jobs.clone();
    let coord = RestoreCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()));
    let job_id = JobId::new();
    jobs.submit(job_id, &path, 1);

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        job_id,
    })
    .await
    .unwrap();
    drop(tx);
    coord.run(rx).await.unwrap();

    let job = jobs.get(job_id).unwrap();
    assert_eq!(job.state, RestoreJobState::Finished);
    assert_eq!(job.outcome, Some(RestoreOutcome::NothingRestored));
    assert_eq!(job.failures.len(), 1);
    assert_eq!(job.failures[0].path, path);
    assert_eq!(job.failures[0].kind, RestoreFailureKind::WriteFailed);
}

/// `run` takes a job from the queue and leaves its job record `finished` on disk,
/// equal to the registry's view.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_rewrites_job_marker_as_finished() {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, staging_dir) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let path = backup_one(&db, &symbols_dir, files_dir.path(), "m.txt", b"marker");
    let coord = coord_with_source(db, &staging_dir, None);
    let jobs = coord.config.jobs.clone();
    let job_id = JobId::new();
    jobs.submit(job_id, &path, 1);

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(RestoreRequest {
        path: path.clone(),
        version_selector: VersionSelector::Latest,
        job_id,
    })
    .await
    .unwrap();
    drop(tx);
    coord.run(rx).await.unwrap();

    let job_dir = staging_dir.path().join("restore").join(job_id.to_string());
    let record = read_job_record(&job_dir).unwrap().unwrap();
    assert_eq!(record.state, RestoreJobState::Finished);
    assert_eq!(record.outcome, Some(RestoreOutcome::Complete));
    assert_eq!(record.restored_paths, vec![path]);
    assert_eq!(jobs.record(job_id), Some(record));
}

/// T10: the coordinator task ends on the daemon's cancel token even while the
/// request channel is open (DaemonState keeps a sender) — it does not hold the
/// shutdown until the drain deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_returns_on_cancel_while_the_queue_is_open() {
    let db = Db::open_in_memory().unwrap();
    let staging_dir = TempDir::new().unwrap();
    let coord = coord_with_source(db, &staging_dir, None);
    let cancel = coord.config.cancel.clone();
    let (_tx, rx) = tokio::sync::mpsc::channel::<RestoreRequest>(4);
    let task = tokio::spawn(coord.run(rx));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    cancel.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .expect("run must return on cancel")
        .unwrap()
        .unwrap();
}

/// N3 / restore-i8: after each job the coordinator (not the HTTP path) refreshes
/// the cached staging status, so `status` counts the new job dir at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_refreshes_cached_staging_summary_after_job() {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, staging_dir) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let path = backup_one(&db, &symbols_dir, files_dir.path(), "s.txt", b"0123456789");
    let coord = coord_with_source(db, &staging_dir, None);
    let status = coord.config.staging_status.clone();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(request(&path)).await.unwrap();
    drop(tx);
    coord.run(rx).await.unwrap();

    let cached = *status.lock().unwrap();
    assert_eq!(cached.job_dirs, 1);
    let bytes = cached.bytes.expect("bytes counted after the job");
    assert!(bytes >= 10, "the restored file is counted: {bytes}");
}

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn held(total_bytes: u64) -> viaticum_core::types::HoldingRecord {
    viaticum_core::types::HoldingRecord {
        source_block_id: SourceBlockId([9u8; 32]),
        owner_id: viaticum_core::types::IdentityPub([8u8; 32]),
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes,
        status: viaticum_core::types::HoldingStatus::Active,
        received_at: Timestamp(100),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    }
}

/// restore-i20: at the end of a restore job — not on the hourly tick — the node
/// WARNs when the fresh staging squeezes friends' data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_warns_at_once_when_staging_squeezes_holdings() {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, staging_dir) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    // 2 MiB restored into staging (>= the 1 MiB warning floor).
    let path = backup_one(
        &db,
        &symbols_dir,
        files_dir.path(),
        "big.bin",
        &vec![5u8; 2 * 1024 * 1024],
    );
    // Quota 1000 bytes, 950 held: the holder no longer takes friends' data.
    db.upsert_holding(&held(950)).unwrap();
    let staging_root = staging_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).unwrap();
    let mut config = RestoreConfig::new(
        TEST_EPOCH_KEY,
        staging_root,
        staging_dir.path().to_path_buf(),
    );
    config.pressure = Some(crate::daemon::restore::cleanup::HoldingsPressure {
        db: db.clone(),
        data_dir: staging_dir.path().to_path_buf(),
        soft_quota_bytes: 1000,
        disk_reserve_bytes: 0,
    });
    let coord = RestoreCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()));
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(request(&path)).await.unwrap();
    drop(tx);

    let buf = LogBuf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    tracing::instrument::WithSubscriber::with_subscriber(
        coord.run(rx),
        tracing::Dispatch::new(subscriber),
    )
    .await
    .unwrap();
    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("is taking space from your friends' data"),
        "{logs}"
    );
}

/// restore-i3: every RestoreError has a machine reason, and the mapping follows
/// the spec (§2.4.3).
#[test]
fn failure_kind_maps_every_restore_error_variant() {
    use viaticum_core::path_safety::PathSafetyError;
    let b = SourceBlockId([1u8; 32]);
    let cases: Vec<(RestoreError, RestoreFailureKind)> = vec![
        (
            RestoreError::FileNotFound { path: "p".into() },
            RestoreFailureKind::NotBackedUp,
        ),
        (
            RestoreError::VersionNotFound {
                path: "p".into(),
                selector: "s".into(),
            },
            RestoreFailureKind::NotBackedUp,
        ),
        (
            RestoreError::BlockNotFound(b),
            RestoreFailureKind::BlockMissing,
        ),
        (
            RestoreError::LegacyRecord(b),
            RestoreFailureKind::BlockMissing,
        ),
        (
            RestoreError::InsufficientSymbols {
                block: b,
                got: 1,
                need: 3,
            },
            RestoreFailureKind::HoldersUnavailable,
        ),
        (
            RestoreError::DecodeFailed(b, "x".into()),
            RestoreFailureKind::Corrupt,
        ),
        (
            RestoreError::DecryptionFailed(b),
            RestoreFailureKind::Corrupt,
        ),
        (
            RestoreError::DecompressionFailed(b, "x".into()),
            RestoreFailureKind::Corrupt,
        ),
        (
            RestoreError::PackIndexParseFailed(b, "x".into()),
            RestoreFailureKind::Corrupt,
        ),
        (
            RestoreError::Swarm("x".into()),
            RestoreFailureKind::HoldersUnavailable,
        ),
        (
            RestoreError::PathUnsafe {
                path: "p".into(),
                source: PathSafetyError::DotDot,
            },
            RestoreFailureKind::PathUnsafe,
        ),
        (
            RestoreError::Staging(
                crate::daemon::restore::staging::StagingError::AlreadyExists("p".into()),
            ),
            RestoreFailureKind::WriteFailed,
        ),
        (
            RestoreError::Db(viaticum_core::db::DbError::Database(
                redb::DatabaseError::DatabaseAlreadyOpen,
            )),
            RestoreFailureKind::Internal,
        ),
        (
            RestoreError::Io(std::io::Error::other("x")),
            RestoreFailureKind::WriteFailed,
        ),
        (RestoreError::Cancelled, RestoreFailureKind::Interrupted),
    ];
    for (err, want) in cases {
        assert_eq!(failure_kind(&err), want, "{err}");
    }
}

/// `RestoreConfig::new` gives the coordinator one registry for its staging root;
/// a clone (what the daemon hands to dispatch) is the same registry.
#[test]
fn restore_config_new_shares_one_registry_for_its_staging_root() {
    let cfg = RestoreConfig::new([0u8; 32], "/d/restore".into(), "/d".into());
    assert_eq!(cfg.jobs.staging_root(), std::path::Path::new("/d/restore"));
    let shared: RestoreJobs = cfg.jobs.clone();
    shared.submit(JobId::new(), "/a", 1);
    assert_eq!(cfg.jobs.list().len(), 1);
}

/// restore-i12 (spec claim 13 in miniature): no deadline on a block. Two holders
/// hit the 30 s request timeout, the third answers slowly; the block is decoded
/// after well over 60 s (the old per-block deadline) instead of failing. Paused
/// clock: the minutes are virtual.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn block_fetch_has_no_deadline_slow_holders_past_60s_still_decode() {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, staging_dir) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let content = b"slow home link".repeat(200);
    let path = backup_one(&db, &symbols_dir, files_dir.path(), "slow.bin", &content);
    let holders = Arc::new(FakeHolders {
        delay: std::time::Duration::from_secs(25),
        ..Default::default()
    });
    place_on_fake_holders(&db, &path, &holders).await;
    holders
        .silent_first
        .lock()
        .unwrap()
        .extend([DeviceId([0x40; 32]), DeviceId([0x41; 32])]);
    std::fs::remove_file(&path).unwrap();
    let block = db.get_file(&path).unwrap().unwrap().versions[0].source_block_id;
    let rec = db.get_source_block(&block).unwrap().unwrap();

    let coord = coord_with_source(db, &staging_dir, Some(holders.clone()));
    let t0 = tokio::time::Instant::now();
    let plaintext = coord
        .decode_block_local(
            &block,
            &rec.erasure_params(),
            rec.encrypted_size.unwrap(),
            &mut NoAnswerPauses::new(JobId::new(), 1),
        )
        .await
        .expect("a slow holder set is not 'holders unavailable'");

    // A small file is packed: the block is the pack index followed by the bytes.
    assert!(
        plaintext.ends_with(&content),
        "decoded {} bytes without the file content",
        plaintext.len()
    );
    assert!(
        t0.elapsed() >= std::time::Duration::from_secs(85),
        "30 s + 30 s + 25 s at least: {:?}",
        t0.elapsed()
    );
}

/// backup-i5 (J1): the local tier reads no source file above this machine's size limit. The
/// source is there and within reach, but over the limit: the block comes from the network,
/// and no request is made in the control run, where the limit admits the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_tier_does_not_read_source_over_the_size_limit_and_goes_to_the_network() {
    let db = Db::open_in_memory().unwrap();
    let (symbols_dir, files_dir, staging_dir) = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let content = b"the file that outgrew the limit".repeat(100);
    let path = backup_one(&db, &symbols_dir, files_dir.path(), "big.bin", &content);
    let holders = Arc::new(FakeHolders::default());
    place_on_fake_holders(&db, &path, &holders).await;
    let block = db.get_file(&path).unwrap().unwrap().versions[0].source_block_id;
    let rec = db.get_source_block(&block).unwrap().unwrap();
    let size = std::fs::metadata(&path).unwrap().len();
    let decode = |limit: u64| {
        let mut coord = coord_with_source(db.clone(), &staging_dir, Some(holders.clone()));
        coord.config.max_source_bytes = limit;
        let rec = rec.clone();
        async move {
            coord
                .decode_block_local(
                    &block,
                    &rec.erasure_params(),
                    rec.encrypted_size.unwrap(),
                    &mut NoAnswerPauses::new(JobId::new(), 1),
                )
                .await
        }
    };

    // Control: the limit admits the file, the local tier serves it, the network is not asked.
    let plaintext = decode(size).await.unwrap();
    assert!(plaintext.ends_with(&content));
    assert!(
        holders.requests.lock().unwrap().is_empty(),
        "within the limit the source serves the block"
    );

    // One byte under the file's size: not read, the holders are asked, the bytes are right.
    let plaintext = decode(size - 1).await.unwrap();
    assert!(plaintext.ends_with(&content));
    assert!(
        !holders.requests.lock().unwrap().is_empty(),
        "over the limit the block comes from the network"
    );
}
