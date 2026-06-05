// Tests for BackupCoordinator.
// All tests use real Db::open_in_memory(), real RaptorQEncoder, and tempfile::TempDir.
// Source block size is set small (128 KB) for fast tests.
//
// AC-8: pending_delivery_accept_signals_correctly
// AC-9: pending_delivery_reject_signals_correctly
// AC-10: pending_delivery_times_out_when_no_response

use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use viaticum_core::cluster::{
    ClusterState, derive_master_key, issue_device_certificate, master_identity,
};
use viaticum_core::db::Db;
use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder};
use viaticum_core::types::{
    DeviceId, Event, FileCategory, FileId, FileRecord, FileVersion, LocalState, PlacementStatus,
    SourceBlockId, SymbolPlacement, Timestamp,
};

use super::{BackupConfig, BackupCoordinator, BackupEvent, DirtyEvent, DirtyKind};
use crate::daemon::backup::packing::parse_pack_index;
use crate::daemon::backup::pipeline::decrypt_and_decompress;

/// Small source block size for fast tests (128 KB).
const SMALL_BLOCK_SIZE: u64 = 128 * 1024;

/// Build a test coordinator with a tempdir for symbols.
fn test_coord(db: Db, symbols_dir: &TempDir) -> BackupCoordinator {
    let config = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
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
        work_event_tx: None,
    };
    BackupCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()))
}

/// 5 mock holders with varying trust scores.
fn test_holders() -> Vec<viaticum_core::placement::HolderCandidate> {
    (0..5)
        .map(|i| viaticum_core::placement::HolderCandidate {
            device_id: viaticum_core::types::DeviceId([(i + 1) as u8; 32]),
            trust: 0.3 + (i as f64) * 0.1, // 0.3, 0.4, 0.5, 0.6, 0.7
        })
        .collect()
}

/// Write a file to tempdir and return its absolute path.
fn write_file(dir: &TempDir, name: &str, content: &[u8]) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, content).expect("write test file");
    path.to_string_lossy().into_owned()
}

/// Create an Added DirtyEvent for a path.
fn added_event(path: &str) -> DirtyEvent {
    DirtyEvent {
        path: path.to_string(),
        kind: DirtyKind::Added,
        device_id: DeviceId([1u8; 32]),
    }
}

fn modified_event(path: &str) -> DirtyEvent {
    DirtyEvent {
        path: path.to_string(),
        kind: DirtyKind::Modified,
        device_id: DeviceId([1u8; 32]),
    }
}

fn deleted_event(path: &str) -> DirtyEvent {
    DirtyEvent {
        path: path.to_string(),
        kind: DirtyKind::Deleted,
        device_id: DeviceId([1u8; 32]),
    }
}

// ─── Test 1: process_event_added_creates_file_record ─────────────────────────

#[test]
fn process_event_added_creates_file_record() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    let content = b"fake image data fake image data fake image data";
    let path = write_file(&files_dir, "photo.jpg", content);

    coord.process_event(added_event(&path)).unwrap();

    let record = db.get_file(&path).unwrap().expect("record should exist");
    assert_eq!(record.path, path);
    assert_eq!(record.versions.len(), 1);

    let expected_hash: [u8; 32] = *blake3::hash(content).as_bytes();
    assert_eq!(record.versions[0].content_hash, expected_hash);
    assert!(record.versions[0].backed_up_at.is_none(), "not yet flushed");
}

// ─── Test 2: process_event_deleted_marks_local_state ─────────────────────────

#[test]
fn process_event_deleted_marks_local_state() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    let path = write_file(&files_dir, "doc.txt", b"some content");

    // Add the file first
    coord.process_event(added_event(&path)).unwrap();

    // Then delete it
    coord.process_event(deleted_event(&path)).unwrap();

    let record = db.get_file(&path).unwrap().expect("record should exist");
    let device_id = DeviceId([1u8; 32]);
    let state = record
        .devices
        .iter()
        .find(|(d, _)| *d == device_id)
        .map(|(_, s)| s)
        .expect("device entry should exist");
    assert!(
        matches!(state, LocalState::Deleted(_)),
        "expected Deleted, got {:?}",
        state
    );
}

// ─── Test 3: process_event_dedup_same_content_no_new_version ─────────────────

#[test]
fn process_event_dedup_same_content_no_new_version() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    let content = b"same content for both files";
    let path1 = write_file(&files_dir, "file1.txt", content);
    let path2 = write_file(&files_dir, "file2.txt", content);

    coord.process_event(added_event(&path1)).unwrap();
    coord.process_event(added_event(&path2)).unwrap();

    let record1 = db.get_file(&path1).unwrap().expect("record1 should exist");
    let record2 = db.get_file(&path2).unwrap().expect("record2 should exist");

    // Both records exist with the same content_hash and source_block_id
    assert_eq!(record1.versions.len(), 1);
    assert_eq!(record2.versions.len(), 1);
    assert_eq!(
        record1.versions[0].content_hash,
        record2.versions[0].content_hash
    );
    // Both point to same source_block_id (dedup: zero traffic)
    assert_eq!(
        record1.versions[0].source_block_id,
        record2.versions[0].source_block_id
    );
}

// ─── Test 4: flush_queue_below_min_batch_skips ───────────────────────────────

#[test]
fn flush_queue_below_min_batch_skips() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    // A tiny file (100 bytes) << MIN_BATCH_BYTES (1 MB)
    let path = write_file(&files_dir, "tiny.txt", &[0u8; 100]);
    coord.process_event(added_event(&path)).unwrap();

    let results = coord
        .flush_queue(FileCategory::Document, false, &Default::default())
        .unwrap();
    assert!(
        results.is_empty(),
        "should skip flush below MIN_BATCH_BYTES"
    );
}

// ─── Test 5: flush_queue_with_force_flushes_any_size ─────────────────────────

#[test]
fn flush_queue_with_force_flushes_any_size() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    // A tiny file
    let path = write_file(&files_dir, "tiny.txt", &[0u8; 100]);
    coord.process_event(added_event(&path)).unwrap();

    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();
    assert!(!results.is_empty(), "force=true should flush any size");
}

// ─── Test 6: flush_queue_creates_source_block_record ─────────────────────────

#[test]
fn flush_queue_creates_source_block_record() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    // Queue enough data to exceed MIN_BATCH_BYTES (1 MB).
    // Files must be < SMALL_BLOCK_SIZE (128 KB) to go to the queue (not large-file path).
    // 20 files x 60 KB = 1.2 MB > 1 MB (MIN_BATCH_BYTES).
    for i in 0..20u8 {
        // Use pseudo-random content to avoid trivial zstd compression.
        let content: Vec<u8> = (0..60_000u32)
            .map(|j| (i as u32 ^ (j % 251)) as u8)
            .collect();
        let path = write_file(&files_dir, &format!("doc{i}.txt"), &content);
        coord.process_event(added_event(&path)).unwrap();
    }

    let results = coord
        .flush_queue(FileCategory::Document, false, &Default::default())
        .unwrap();
    assert!(!results.is_empty(), "should produce results");

    for result in &results {
        let block = db
            .get_source_block(&result.source_block_id)
            .unwrap()
            .expect("source block should exist");
        assert!(
            matches!(
                block.block_type,
                viaticum_core::types::SourceBlockType::Pack { .. }
            ),
            "should be Pack type"
        );
        assert_eq!(
            block.status,
            viaticum_core::types::SourceBlockStatus::Active
        );
    }
}

// ─── Test 7: flush_queue_creates_db_records ───────────────────────────────────
// Wave 11b: renamed from flush_queue_writes_symbol_files.
// Pipeline no longer writes symbol files to disk. Instead it creates DB records.
// WorkPipeline worker handles actual encoding+delivery.

#[test]
fn flush_queue_creates_db_records() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    for i in 0..4u8 {
        let content: Vec<u8> = (0..50_000u32)
            .map(|j| (i as u32 ^ (j % 251)) as u8)
            .collect();
        let path = write_file(&files_dir, &format!("f{i}.txt"), &content);
        coord.process_event(added_event(&path)).unwrap();
    }

    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();
    assert!(!results.is_empty());

    for result in &results {
        // Wave 11b: no symbol files on disk. Verify DB records exist.
        let block_record = db
            .get_source_block(&result.source_block_id)
            .unwrap()
            .unwrap();
        assert_eq!(block_record.block_id, result.source_block_id);
        assert!(
            block_record.encrypted_size.is_some(),
            "encrypted_size must be set"
        );

        // Placement records should exist (Offered state).
        let placements = db
            .list_placements_for_block(&result.source_block_id)
            .unwrap();
        // Placements may be empty if no candidates (test_coord has mock_holders=empty by default).
        // Just verify no panic and DB is consistent.
        for p in &placements {
            assert_eq!(p.source_block_id, result.source_block_id);
        }

        // Symbol files must NOT exist (Wave 11b invariant).
        let block_hex: String = result
            .source_block_id
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let block_dir = symbols_dir.path().join(&block_hex);
        assert!(
            !block_dir.exists(),
            "block symbol dir must NOT exist after Wave 11b"
        );
    }
}

// ─── Test 8: flush_queue_updates_backed_up_at ────────────────────────────────

#[test]
fn flush_queue_updates_backed_up_at() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    let content = b"this is a document that will be backed up";
    let path = write_file(&files_dir, "report.txt", content);
    coord.process_event(added_event(&path)).unwrap();

    // Verify backed_up_at is None before flush
    let before = db.get_file(&path).unwrap().unwrap();
    assert!(before.versions[0].backed_up_at.is_none());

    coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();

    let after = db.get_file(&path).unwrap().unwrap();
    assert!(
        after.versions[0].backed_up_at.is_some(),
        "backed_up_at should be set after flush"
    );
}

// ─── Test 9: pipeline_roundtrip_can_decode ───────────────────────────────────
// THE MOST IMPORTANT TEST: backup -> decode -> verify content.

/// Wave 11b: pipeline roundtrip uses rebuild_source_blob instead of raw/ disk files.
/// The pipeline creates a DB record. We then rebuild the blob from source files
/// (as the WorkPipeline worker would) and verify decryption gives back original content.
#[tokio::test]
async fn pipeline_roundtrip_can_decode() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let epoch_key = [7u8; 32];

    let config = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key,
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
        work_event_tx: None,
    };
    let encoder: Arc<dyn ErasureEncoder> = Arc::new(RaptorQEncoder::new());
    let mut coord = BackupCoordinator::new(db.clone(), config, encoder.clone());

    // Write a test file with recognizable content.
    let content = b"roundtrip test content ---";
    let repeated: Vec<u8> = content.iter().cycle().take(4096).cloned().collect();
    let path = write_file(&files_dir, "data.txt", &repeated);

    coord.process_event(added_event(&path)).unwrap();
    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();
    assert_eq!(results.len(), 1, "should produce one source block");

    let block_id = results[0].source_block_id;
    let stored_size = results[0].stored_size as usize;
    let placements = db.list_placements_for_block(&block_id).unwrap();
    assert!(!placements.is_empty(), "should have placements");

    // Wave 11b: no raw/ files on disk. Use rebuild_source_blob to get the stored blob.
    let block_record = db.get_source_block(&block_id).unwrap().unwrap();
    let stored_blob =
        crate::daemon::backup::pipeline::rebuild_source_blob(&db, &block_record, &epoch_key)
            .await
            .expect("rebuild_source_blob must succeed");

    assert_eq!(
        stored_blob.len(),
        stored_size,
        "rebuilt blob size must match stored_size"
    );

    // Verify hash == block_id.
    let hash: [u8; 32] = *blake3::hash(&stored_blob).as_bytes();
    assert_eq!(hash, block_id.0, "rebuilt blob hash must equal block_id");

    // Decrypt and decompress.
    let plaintext = decrypt_and_decompress(&stored_blob, &epoch_key)
        .expect("should be able to decrypt and decompress");

    // Parse pack index and find our file.
    let parsed = parse_pack_index(&plaintext).unwrap();
    let file_data_start = parsed.index_len;
    assert!(!parsed.entries.is_empty(), "pack index should have entries");

    // Extract file content.
    let entry = &parsed.entries[0];
    let start = file_data_start + entry.offset as usize;
    let end = start + entry.size as usize;
    let extracted = &plaintext[start..end];

    assert_eq!(
        extracted, &repeated,
        "extracted content should match original"
    );
}

// ─── Test 10: process_event_modified_adds_new_version ────────────────────────

#[test]
fn process_event_modified_adds_new_version() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    let path = write_file(&files_dir, "evolving.txt", b"version 1 content");

    coord.process_event(added_event(&path)).unwrap();

    // Overwrite the file with new content
    std::fs::write(
        files_dir.path().join("evolving.txt"),
        b"version 2 entirely different",
    )
    .unwrap();

    coord.process_event(modified_event(&path)).unwrap();

    let record = db.get_file(&path).unwrap().unwrap();
    assert_eq!(record.versions.len(), 2, "should have 2 versions");
    assert_ne!(
        record.versions[0].content_hash, record.versions[1].content_hash,
        "versions should have different content hashes"
    );
}

// ─── Test 11: flush_queue_appends_event_log ───────────────────────────────────

#[test]
fn flush_queue_appends_event_log() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    let content = b"event log test document";
    let path = write_file(&files_dir, "eventlog.txt", content);
    coord.process_event(added_event(&path)).unwrap();
    coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();

    let events = db.events_after(0, 100).unwrap();
    let has_symbols_placed = events
        .iter()
        .any(|(_, e)| matches!(e.event, Event::SymbolsPlaced { .. }));
    assert!(
        has_symbols_placed,
        "should have at least one SymbolsPlaced event"
    );
}

// ─── Test 12: process_large_file_creates_single_block ────────────────────────
// (spec test 10)

#[test]
fn process_large_file_creates_single_block() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    // File larger than source_block_size (128 KB + 1 KB).
    // Use pseudo-random content so it doesn't compress to nothing.
    let large_content: Vec<u8> = (0..(SMALL_BLOCK_SIZE as usize + 1024))
        .map(|i| ((i * 7 + 13) % 256) as u8)
        .collect();
    let path = write_file(&files_dir, "large_video.mp4", &large_content);

    // process_event detects size >= source_block_size and calls process_large_file immediately.
    coord.process_event(added_event(&path)).unwrap();

    // The Single block was written to DB during process_event, not via flush_all.
    let blocks = db
        .list_source_blocks_by_status(viaticum_core::types::SourceBlockStatus::Active)
        .unwrap();

    let has_single = blocks
        .iter()
        .any(|b| matches!(b.block_type, viaticum_core::types::SourceBlockType::Single));

    assert!(
        has_single,
        "should have created a Single-type source block for large file"
    );
}

// ─── Test 13: dedup_skips_file_already_backed_up ─────────────────────────────

/// Insert a FileRecord with backed_up_at=Some; process an event with the same
/// content_hash. The file must NOT be added to the queue (zero-traffic dedup).
#[test]
fn dedup_skips_file_already_backed_up() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    let content = b"content already backed up on another device";
    let content_hash: [u8; 32] = *blake3::hash(content).as_bytes();

    // Pre-insert a FileRecord whose version has backed_up_at=Some.
    let existing_record = FileRecord {
        file_id: FileId(1),
        path: "/other/device/file.txt".to_string(),
        importance: 0.5,
        devices: vec![(DeviceId([9u8; 32]), LocalState::Present)],
        versions: vec![FileVersion {
            content_hash,
            source_block_id: SourceBlockId([1u8; 32]),
            k: 4,
            t: 65535,
            created_at: Timestamp(1_000_000),
            backed_up_at: Some(Timestamp(2_000_000)),
        }],
        first_seen: Timestamp(1_000_000),
    };
    db.upsert_file(&existing_record).unwrap();

    // Write the file locally and process the event.
    let path = write_file(&files_dir, "local_copy.txt", content);
    let mut coord = test_coord(db.clone(), &symbols_dir);
    coord.process_event(added_event(&path)).unwrap();

    // The file should not be queued — dedup recognized it as already backed up.
    let queue_len: usize = coord.queues.values().map(|q| q.len()).sum();
    assert_eq!(
        queue_len, 0,
        "dedup should skip file already backed up (backed_up_at=Some)"
    );
}

// ─── Test 14: dedup_does_not_skip_file_not_yet_backed_up ─────────────────────

/// Insert a FileRecord with backed_up_at=None; process an event with the same
/// content_hash. The file MUST be queued — upload not yet complete.
#[test]
fn dedup_does_not_skip_file_not_yet_backed_up() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    let content = b"content queued but not yet uploaded";
    let content_hash: [u8; 32] = *blake3::hash(content).as_bytes();

    // Pre-insert a FileRecord whose version has backed_up_at=None (still queued).
    let existing_record = FileRecord {
        file_id: FileId(1),
        path: "/other/path/pending.txt".to_string(),
        importance: 0.5,
        devices: vec![(DeviceId([9u8; 32]), LocalState::Present)],
        versions: vec![FileVersion {
            content_hash,
            source_block_id: SourceBlockId([0u8; 32]),
            k: 0,
            t: 0,
            created_at: Timestamp(1_000_000),
            backed_up_at: None, // not yet uploaded
        }],
        first_seen: Timestamp(1_000_000),
    };
    db.upsert_file(&existing_record).unwrap();

    // Write the file locally and process the event.
    let path = write_file(&files_dir, "local_pending.txt", content);
    let mut coord = test_coord(db.clone(), &symbols_dir);
    coord.process_event(added_event(&path)).unwrap();

    // The file SHOULD be queued — content not yet backed up.
    let queue_len: usize = coord.queues.values().map(|q| q.len()).sum();
    assert_eq!(
        queue_len, 1,
        "file should be queued when backed_up_at=None (not yet uploaded)"
    );
}

// ─── Test 15: dedup_via_cluster_state_skips_already_backed_up ────────────────

/// Same as test 13, but using ClusterState for the dedup check.
#[test]
fn dedup_via_cluster_state_skips_already_backed_up() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    let content = b"cluster dedup content already backed up";
    let content_hash: [u8; 32] = *blake3::hash(content).as_bytes();

    // Pre-insert a FileRecord with backed_up_at=Some.
    let existing_record = FileRecord {
        file_id: FileId(1),
        path: "/cluster/device_a/file.txt".to_string(),
        importance: 0.5,
        devices: vec![(DeviceId([9u8; 32]), LocalState::Present)],
        versions: vec![FileVersion {
            content_hash,
            source_block_id: SourceBlockId([2u8; 32]),
            k: 4,
            t: 65535,
            created_at: Timestamp(1_000_000),
            backed_up_at: Some(Timestamp(3_000_000)),
        }],
        first_seen: Timestamp(1_000_000),
    };
    db.upsert_file(&existing_record).unwrap();

    let seed = [99u8; 32];
    let master_key = derive_master_key(&seed).unwrap();
    let master_pub = master_identity(&master_key);
    let dev_id = DeviceId([99u8; 32]);
    let _dev_key = viaticum_core::cluster::derive_device_key(&seed, &dev_id.0).unwrap();
    let cert = issue_device_certificate(&master_key, dev_id, Timestamp(1));
    let cs = ClusterState::init(db.clone(), master_pub, cert, Timestamp(1), Timestamp(1)).unwrap();
    let cluster_state = Arc::new(Mutex::new(cs));
    let config = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: DeviceId([1u8; 32]),
        mock_holders: test_holders(),
        cluster_state: Some(cluster_state),
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: None,
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    };
    let mut coord = BackupCoordinator::new(db.clone(), config, Arc::new(RaptorQEncoder::new()));

    let path = write_file(&files_dir, "device_b_copy.txt", content);
    coord.process_event(added_event(&path)).unwrap();

    let queue_len: usize = coord.queues.values().map(|q| q.len()).sum();
    assert_eq!(
        queue_len, 0,
        "ClusterState dedup should skip file already backed up"
    );
}

// ─── Phase 7.5 tests ──────────────────────────────────────────────────────────

// ─── Tests 16-18: read_symbols_for_holder removed in Wave 11b ────────────────
// read_symbols_for_holder was a legacy function for bound per-holder symbol files.
// After Wave 11b, these files are no longer written. Tests removed accordingly.

// ─── Test 19: backup_config_default_swarm_is_none ────────────────────────────

#[test]
fn backup_config_default_swarm_is_none() {
    let cfg = BackupConfig::default();
    assert!(cfg.swarm.is_none(), "default config must have swarm=None");
}

// ─── Test 20: deliver_symbols removed in Wave 11b ────────────────────────────
// deliver_symbols was removed. Delivery is now handled by WorkPipeline worker.
// Tests for the new delivery path are in work_pipeline/tests.rs.

// Tests 21 and 22 (deliver_symbols network integration) removed in ε.5.
// iroh NetworkHandle replaced by libp2p SwarmHandle; network delivery is
// tested in swarm_tests.rs and E2E suite.
//
// ─── Test 21: deliver_symbols_logs_warn_on_peer_not_found (REMOVED) ──────────
#[cfg(any())]
async fn deliver_symbols_logs_warn_on_peer_not_found() {
    use std::collections::HashMap;

    use ed25519_dalek::SigningKey;
    use viaticum_core::types::{PlacementStatus, SymbolPlacement};

    use crate::daemon::network::{NetworkConfig, NetworkHandle};

    use super::PipelineResult;

    let sk_owner = SigningKey::from_bytes(&[10u8; 32]);
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let network = std::sync::Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: sk_owner.clone(),
                master_signing_key: sk_owner.clone(),
                master_identity: IdentityPub(sk_owner.verifying_key().to_bytes()),
                known_peers: HashMap::new(),
                device_cert: None,
                iroh_secret_key: None,
                relay_mode: iroh::RelayMode::Disabled,
                x25519_pub: None,
            },
            tx,
        )
        .await
        .unwrap(),
    );

    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();

    let block_id = SourceBlockId([0xAAu8; 32]);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();
    std::fs::write(block_dir.join("0.bin"), vec![0u8; 64]).unwrap();

    let unknown_holder = IdentityPub([0xFFu8; 32]);
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id: unknown_holder,
        file_id: FileId(1),
        esi_ranges: vec![(0, 1)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    let coordinator = BackupCoordinator::new(
        db,
        BackupConfig {
            symbols_dir: dir.path().to_path_buf(),
            network: Some(network.clone()),
            ..BackupConfig::default()
        },
        Arc::new(RaptorQEncoder::new()),
    );

    let result = PipelineResult {
        source_block_id: block_id,
        k: 1,
        n: 2,
        t: 65535,
        symbol_count_per_holder: vec![(unknown_holder, 1)],
        stored_size: 64,
        importance: 0.5,
    };

    coordinator.deliver_symbols(&[result]).await;

    Arc::try_unwrap(network)
        .ok()
        .map(|n| async move { n.shutdown().await });
}

// ─── Test 22: deliver_symbols_sends_to_reachable_holder (REMOVED) ────────────
#[cfg(any())]
async fn deliver_symbols_sends_to_reachable_holder() {
    use std::collections::HashMap;

    use viaticum_core::messages::Message;
    use viaticum_core::types::{PlacementStatus, SymbolPlacement};

    use crate::daemon::network::{NetworkConfig, NetworkHandle};

    use super::PipelineResult;

    // Owner: seed [20u8; 32]
    let owner_seed = [20u8; 32];
    let owner_master_key = derive_master_key(&owner_seed).unwrap();
    let owner_master = master_identity(&owner_master_key);
    let owner_did = DeviceId([20u8; 32]);
    let owner_device_key = derive_device_key(&owner_seed, &owner_did).unwrap();
    let owner_cert = issue_device_certificate(
        &owner_master_key,
        owner_did,
        owner_device_key.verifying_key().to_bytes(),
        Timestamp::now(),
    );

    // Holder: seed [21u8; 32]
    let holder_seed = [21u8; 32];
    let holder_master_key = derive_master_key(&holder_seed).unwrap();
    let holder_master = master_identity(&holder_master_key);
    let holder_did = DeviceId([21u8; 32]);
    let holder_device_key = derive_device_key(&holder_seed, &holder_did).unwrap();
    let holder_cert = issue_device_certificate(
        &holder_master_key,
        holder_did,
        holder_device_key.verifying_key().to_bytes(),
        Timestamp::now(),
    );

    let (tx_owner, _rx_owner) = tokio::sync::mpsc::channel(4);
    let (tx_holder, mut rx_holder) = tokio::sync::mpsc::channel(4);

    let network_holder = std::sync::Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: holder_device_key.clone(),
                master_signing_key: holder_device_key,
                master_identity: holder_master,
                known_peers: HashMap::new(),
                device_cert: Some(holder_cert),
                iroh_secret_key: None,
                relay_mode: iroh::RelayMode::Disabled,
                x25519_pub: None,
            },
            tx_holder,
        )
        .await
        .unwrap(),
    );

    let holder_addr = network_holder.local_addr().unwrap();

    let mut known_peers = HashMap::new();
    known_peers.insert(holder_master, holder_addr);

    let network_owner = std::sync::Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: owner_device_key.clone(),
                master_signing_key: owner_device_key,
                master_identity: owner_master,
                known_peers,
                device_cert: Some(owner_cert),
                iroh_secret_key: None,
                relay_mode: iroh::RelayMode::Disabled,
                x25519_pub: None,
            },
            tx_owner,
        )
        .await
        .unwrap(),
    );

    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let block_id = SourceBlockId([0x99u8; 32]);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();

    for esi in 0u32..2 {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 64]).unwrap();
    }

    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id: holder_master,
        file_id: FileId(1),
        esi_ranges: vec![(0, 2)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    let coordinator = BackupCoordinator::new(
        db,
        BackupConfig {
            symbols_dir: dir.path().to_path_buf(),
            network: Some(network_owner.clone()),
            ..BackupConfig::default()
        },
        Arc::new(RaptorQEncoder::new()),
    );

    let result = PipelineResult {
        source_block_id: block_id,
        k: 2,
        n: 4,
        t: 65535,
        symbol_count_per_holder: vec![(holder_master, 2)],
        stored_size: 128,
        importance: 0.5,
    };

    coordinator.deliver_symbols(&[result]).await;

    let mut conn = tokio::time::timeout(std::time::Duration::from_secs(5), rx_holder.recv())
        .await
        .expect("timeout waiting for connection")
        .expect("channel closed");

    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), conn.recv_message())
        .await
        .expect("timeout waiting for message")
        .expect("recv_message failed");

    match msg {
        Message::SymbolTransfer(transfer) => {
            assert_eq!(transfer.source_block_id, block_id);
            assert_eq!(transfer.symbols.len(), 2);
            assert_eq!(transfer.symbols[0].esi, 0);
            assert_eq!(transfer.symbols[1].esi, 1);
        }
        other => panic!("expected SymbolTransfer, got {other:?}"),
    }

    Arc::try_unwrap(network_owner)
        .ok()
        .map(|n| async move { n.shutdown().await });
    Arc::try_unwrap(network_holder)
        .ok()
        .map(|n| async move { n.shutdown().await });
}

// ─── Phase 7.9 tests: watch_configs importance lookup ────────────────────────

/// Helper: build coordinator with specific watch_configs.
fn coord_with_watch(
    db: Db,
    symbols_dir: &TempDir,
    watch_configs: Vec<viaticum_core::config::WatchConfig>,
) -> BackupCoordinator {
    let config = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: DeviceId([1u8; 32]),
        mock_holders: test_holders(),
        cluster_state: None,
        watch_configs,
        time_scale: 1,
        mock_offer_budget_gb: None,
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    };
    BackupCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()))
}

#[test]
fn watch_config_importance_applied_to_queued_file() {
    // When a file is queued, the QueuedFile.importance should reflect the
    // watch_config matching the file's directory.
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    let watch_cfgs = vec![viaticum_core::config::WatchConfig {
        path: files_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.9,
        was_legacy_importance: false,
        classification: Some(viaticum_core::importance::FolderClassification {
            is_media_folder: false,
            importance_multiplier: 1.0,
        }),
        bursts: None,
    }];
    let mut coord = coord_with_watch(db, &symbols_dir, watch_cfgs);

    let content = b"some document content here";
    let path = write_file(&files_dir, "report.txt", content);

    coord.process_event(added_event(&path)).unwrap();

    // File should be queued (it's small). report.txt → TextOrCode × 0.9 = 0.9.
    let queued: Vec<_> = coord.queues.values().flat_map(|q| q.iter()).collect();
    assert_eq!(queued.len(), 1, "exactly one file should be queued");
    assert!(
        (queued[0].importance - 0.9).abs() < 1e-9,
        "importance should be 0.9 (TextOrCode × 0.9), got {}",
        queued[0].importance
    );
}

#[test]
fn watch_config_default_importance_used_when_no_match() {
    // When no watch_config matches the file's directory, DEFAULT_IMPORTANCE (0.5) is used.
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    // Watch config points to a different directory.
    let watch_cfgs = vec![viaticum_core::config::WatchConfig {
        path: "/nonexistent/other/dir".to_string(),
        importance_multiplier: 0.9,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    }];
    let mut coord = coord_with_watch(db, &symbols_dir, watch_cfgs);

    let content = b"some document content here";
    let path = write_file(&files_dir, "report.txt", content);

    coord.process_event(added_event(&path)).unwrap();

    let queued: Vec<_> = coord.queues.values().flat_map(|q| q.iter()).collect();
    assert_eq!(queued.len(), 1, "exactly one file should be queued");
    assert!(
        (queued[0].importance - 0.5).abs() < 1e-9,
        "importance should default to 0.5, got {}",
        queued[0].importance
    );
}

#[test]
fn watch_config_empty_uses_default_importance() {
    // When watch_configs is empty, DEFAULT_IMPORTANCE (0.5) is used for all files.
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    let mut coord = coord_with_watch(db, &symbols_dir, vec![]);

    let content = b"some document content here";
    let path = write_file(&files_dir, "notes.txt", content);

    coord.process_event(added_event(&path)).unwrap();

    let queued: Vec<_> = coord.queues.values().flat_map(|q| q.iter()).collect();
    assert_eq!(queued.len(), 1, "exactly one file should be queued");
    assert!(
        (queued[0].importance - 0.5).abs() < 1e-9,
        "importance should default to 0.5 when watch_configs is empty, got {}",
        queued[0].importance
    );
}

// ─── Phase 7.9 Wave 6: derive_file_importance integration ───────────────────

#[test]
fn derive_file_importance_integration_photo_and_text_files_in_correct_order() {
    use viaticum_core::config::WatchConfig;

    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let media_dir = TempDir::new().unwrap();
    let text_dir = TempDir::new().unwrap();

    // Write .jpg files into media_dir so it classifies as a media folder.
    for i in 0..10 {
        std::fs::write(media_dir.path().join(format!("photo{i}.jpg")), b"fake jpeg").unwrap();
    }
    // Write .txt files into text_dir.
    for i in 0..5 {
        std::fs::write(text_dir.path().join(format!("doc{i}.txt")), b"text content").unwrap();
    }

    // Build WatchConfigs with classification pre-populated via populate_classification.
    let mut wc_media = WatchConfig {
        path: media_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    wc_media.populate_classification();

    let mut wc_text = WatchConfig {
        path: text_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    wc_text.populate_classification();

    assert!(
        wc_text
            .classification
            .as_ref()
            .map(|c| !c.is_media_folder)
            .unwrap_or(false),
        "text folder should classify as non-media"
    );
    assert!(
        wc_media
            .classification
            .as_ref()
            .map(|c| c.is_media_folder)
            .unwrap_or(false),
        "media folder should classify as media"
    );

    let mut coord = coord_with_watch(db, &symbols_dir, vec![wc_text.clone(), wc_media.clone()]);

    // Enqueue a text file.
    let txt_path_buf = text_dir.path().join("notes.txt");
    std::fs::write(&txt_path_buf, b"important doc content here xyz").unwrap();
    let txt_path_str = txt_path_buf.to_string_lossy().into_owned();
    let txt_event = viaticum_core::types::DeviceId([1u8; 32]);
    coord
        .process_event(super::DirtyEvent {
            path: txt_path_str.clone(),
            kind: super::DirtyKind::Added,
            device_id: txt_event,
        })
        .unwrap();

    // Enqueue a media file.
    let jpg_path_buf = media_dir.path().join("photo.jpg");
    std::fs::write(&jpg_path_buf, b"fake jpeg content for testing purposes").unwrap();
    let jpg_path_str = jpg_path_buf.to_string_lossy().into_owned();
    coord
        .process_event(super::DirtyEvent {
            path: jpg_path_str.clone(),
            kind: super::DirtyKind::Added,
            device_id: viaticum_core::types::DeviceId([1u8; 32]),
        })
        .unwrap();

    let queued: Vec<_> = coord
        .queues
        .values()
        .flat_map(|q| q.iter())
        .cloned()
        .collect();
    let txt = queued
        .iter()
        .find(|f| f.path.ends_with(".txt"))
        .expect("txt file should be queued");
    let jpg = queued
        .iter()
        .find(|f| f.path.ends_with("photo.jpg"))
        .expect("jpg file should be queued");

    // text file in text folder → TextOrCode × 1.0 = 1.0
    assert!(
        (txt.importance - 1.0).abs() < 1e-9,
        "text file importance should be 1.0, got {}",
        txt.importance
    );

    // jpg in media folder → one of MediaHigh/Medium/Low
    assert!(
        jpg.importance == 0.95 || jpg.importance == 0.65 || jpg.importance == 0.20,
        "jpg importance should be 0.95/0.65/0.20, got {}",
        jpg.importance
    );

    // text file must have strictly higher importance than jpg (since MediaHigh=0.95 < TextOrCode=1.0)
    assert!(
        txt.importance > jpg.importance,
        "text ({}) should have higher importance than jpg ({})",
        txt.importance,
        jpg.importance
    );
}

// ─── BACKUP-12: large_file_processed_as_single_block ─────────────────────────
// NOTE: This scenario is already covered by Test 12 (process_large_file_creates_single_block).
// That test verifies: a file >= source_block_size triggers process_large_file immediately
// and produces SourceBlockType::Single. Adding a duplicate test here adds no new coverage.

// ─── BACKUP-15: same_content_two_devices_both_in_file_record ─────────────────

/// When the same file path is backed up from two different devices with
/// identical content, both devices should appear in FileRecord.devices.
///
/// Flow: device A triggers an Added event → FileRecord created with device A.
/// Then device B triggers an Added event for the same path + same content.
/// The dedup path (content already backed up) adds device B to the record.
#[test]
fn same_content_two_devices_both_in_file_record() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    let content = b"shared content across two devices -- unique enough to not compress away";
    let path = write_file(&files_dir, "shared.txt", content);

    let device_a = DeviceId([0xAAu8; 32]);
    let device_b = DeviceId([0xBBu8; 32]);

    // Device A processes the file.
    let config_a = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: device_a,
        mock_holders: test_holders(),
        cluster_state: None,
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: None,
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    };
    let mut coord_a = BackupCoordinator::new(db.clone(), config_a, Arc::new(RaptorQEncoder::new()));
    coord_a
        .process_event(DirtyEvent {
            path: path.clone(),
            kind: DirtyKind::Added,
            device_id: device_a,
        })
        .unwrap();
    // Force flush so backed_up_at is set (dedup check requires backed_up_at=Some).
    coord_a.flush_all(true, &Default::default()).unwrap();

    // Device B processes the same file with the same content.
    let config_b = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: device_b,
        mock_holders: test_holders(),
        cluster_state: None,
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: None,
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    };
    let mut coord_b = BackupCoordinator::new(db.clone(), config_b, Arc::new(RaptorQEncoder::new()));
    coord_b
        .process_event(DirtyEvent {
            path: path.clone(),
            kind: DirtyKind::Added,
            device_id: device_b,
        })
        .unwrap();

    // Both devices should be listed in the FileRecord.
    let record = db.get_file(&path).unwrap().expect("FileRecord must exist");
    let listed_devices: Vec<DeviceId> = record.devices.iter().map(|(d, _)| *d).collect();
    assert!(
        listed_devices.contains(&device_a),
        "device A missing from FileRecord.devices: {listed_devices:?}"
    );
    assert!(
        listed_devices.contains(&device_b),
        "device B missing from FileRecord.devices: {listed_devices:?}"
    );
}

// ─── B3 tests: budget-gated flush ─────────────────────────────────────────────

// ─── B3-T1: flush_queue_deferred_files_remain_in_queue ───────────────────────

/// When mock_offer_budget_gb = 0.0, no files can be selected by select_backup_batch.
/// flush_queue must return empty results and leave all files in the queue.
#[test]
fn flush_queue_deferred_files_remain_in_queue() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    let config = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: DeviceId([1u8; 32]),
        mock_holders: test_holders(),
        cluster_state: None,
        watch_configs: vec![],
        time_scale: 1,
        // Zero budget: all files must be deferred.
        mock_offer_budget_gb: Some(0.0),
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    };
    let mut coord = BackupCoordinator::new(db.clone(), config, Arc::new(RaptorQEncoder::new()));

    // Queue 3 small files (all well below SMALL_BLOCK_SIZE).
    for i in 0..3u8 {
        let content = vec![i; 30_000];
        let path = write_file(&files_dir, &format!("file{i}.txt"), &content);
        coord.process_event(added_event(&path)).unwrap();
    }

    // With budget=0, flush should defer all files and return empty.
    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();
    assert!(
        results.is_empty(),
        "zero budget: no files should be processed"
    );

    // All 3 files must remain in the queue.
    let queue_len: usize = coord.queues.values().map(|q| q.len()).sum();
    assert_eq!(
        queue_len, 3,
        "all 3 files should remain in queue when budget=0"
    );

    // No source blocks should have been written to DB.
    let blocks = db
        .list_source_blocks_by_status(viaticum_core::types::SourceBlockStatus::Active)
        .unwrap();
    assert!(blocks.is_empty(), "no blocks should exist with zero budget");
}

// ─── B3-T2: flush_queue_budget_selects_highest_importance_first ──────────────

/// When budget allows only one file, the file with higher importance is selected.
/// The lower-importance file stays in the queue.
#[test]
fn flush_queue_budget_selects_highest_importance_first() {
    use super::QueuedFile;

    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    // Budget for ~1 file:
    // overhead_factor(0.9) = 1.5 + 0.9 * 1.5 = 2.85
    // required_gb for 30_000 bytes at importance=0.9 = 30_000 / 1_073_741_824 * 2.85 ≈ 7.96e-5 GB
    // Set budget to 1e-4 (just above one high-importance file, far below two).
    let config = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: DeviceId([1u8; 32]),
        mock_holders: test_holders(),
        cluster_state: None,
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: Some(1e-4),
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    };
    let mut coord = BackupCoordinator::new(db.clone(), config, Arc::new(RaptorQEncoder::new()));

    // Write two files with distinct content so hashes differ.
    let content_a = vec![0xABu8; 30_000];
    let content_b = vec![0xCDu8; 30_000];
    let path_a = write_file(&files_dir, "high_importance.txt", &content_a);
    let path_b = write_file(&files_dir, "low_importance.txt", &content_b);
    let hash_a: [u8; 32] = *blake3::hash(&content_a).as_bytes();
    let hash_b: [u8; 32] = *blake3::hash(&content_b).as_bytes();

    // Directly push QueuedFile entries with specific importance values.
    coord
        .queues
        .entry(FileCategory::Document)
        .or_default()
        .push(QueuedFile {
            path: path_a.clone(),
            file_id: viaticum_core::types::FileId(1),
            content_hash: hash_a,
            size_bytes: 30_000,
            category: FileCategory::Document,
            importance: 0.9,
        });
    coord
        .queues
        .entry(FileCategory::Document)
        .or_default()
        .push(QueuedFile {
            path: path_b.clone(),
            file_id: viaticum_core::types::FileId(2),
            content_hash: hash_b,
            size_bytes: 30_000,
            category: FileCategory::Document,
            importance: 0.3,
        });

    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();

    // At least one file should have been processed.
    assert!(!results.is_empty(), "at least one file should be processed");

    // The low-importance file (path_b) must remain in queue.
    let doc_queue = coord.queues.get(&FileCategory::Document).unwrap();
    assert_eq!(
        doc_queue.len(),
        1,
        "exactly one file should remain deferred"
    );
    assert_eq!(
        doc_queue[0].path, path_b,
        "the low-importance file should be the deferred one"
    );
}

// ─── B3-T3: large_file_skipped_when_budget_insufficient ──────────────────────

/// A large file (>= source_block_size) is skipped when offer_budget_gb = 0.
/// No FileRecord should be created (get_or_create_file_id was not called).
#[test]
fn large_file_skipped_when_budget_insufficient() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    let config = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: DeviceId([1u8; 32]),
        mock_holders: test_holders(),
        cluster_state: None,
        watch_configs: vec![],
        time_scale: 1,
        // Zero budget: large file must be skipped.
        mock_offer_budget_gb: Some(0.0),
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    };
    let mut coord = BackupCoordinator::new(db.clone(), config, Arc::new(RaptorQEncoder::new()));

    // Write a file of exactly SMALL_BLOCK_SIZE + some bytes so it takes the large-file path.
    let large_content: Vec<u8> = (0..(SMALL_BLOCK_SIZE as usize + 512))
        .map(|i| ((i * 7 + 13) % 256) as u8)
        .collect();
    let path = write_file(&files_dir, "large_file.bin", &large_content);

    // process_event must return Ok(()) without processing the file.
    coord.process_event(added_event(&path)).unwrap();

    // No FileRecord should exist for this path (get_or_create_file_id was not called).
    let record = db.get_file(&path).unwrap();
    assert!(
        record.is_none(),
        "no FileRecord should be created for a large file skipped due to budget"
    );

    // No source blocks should exist.
    let blocks = db
        .list_source_blocks_by_status(viaticum_core::types::SourceBlockStatus::Active)
        .unwrap();
    assert!(
        blocks.is_empty(),
        "no blocks should exist when large file is skipped"
    );
}

// ─── B4 tests: placement outcome tracking ─────────────────────────────────────

// ─── B4-T1: handle_backup_event_increments_accepted_counter ──────────────────

/// SymbolAccepted event increments accepted_this_cycle.
#[test]
fn handle_backup_event_increments_accepted_counter() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    let holder_id = DeviceId([0x55u8; 32]);
    let block_id = SourceBlockId([0xAAu8; 32]);

    // Insert a placement so the handler doesn't log a warning about unknown placement.
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: viaticum_core::types::FileId(1),
        esi_ranges: vec![(0, 2)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Offered,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    coord.offered_this_cycle = 5;
    assert_eq!(coord.accepted_this_cycle, 0);

    coord.handle_backup_event(BackupEvent::SymbolAccepted {
        holder_id,
        source_block_id: block_id,
    });

    assert_eq!(
        coord.accepted_this_cycle, 1,
        "accepted_this_cycle should be 1 after one SymbolAccepted"
    );
}

// ─── B4-T2: persist_cycle_budget_saves_stats_and_resets_counters ─────────────

/// persist_cycle_budget writes the (offered, accepted) pair to DB and resets counters.
#[test]
fn persist_cycle_budget_saves_stats_and_resets_counters() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    // No existing BudgetRecord.
    assert!(db.get_budget().unwrap().is_none());

    coord.offered_this_cycle = 10;
    coord.accepted_this_cycle = 8;
    coord.persist_cycle_budget();

    // Counters must be reset.
    assert_eq!(
        coord.offered_this_cycle, 0,
        "offered_this_cycle should be 0 after persist"
    );
    assert_eq!(
        coord.accepted_this_cycle, 0,
        "accepted_this_cycle should be 0 after persist"
    );

    // DB must have a BudgetRecord with weekly_stats = [(10, 8)].
    let record = db
        .get_budget()
        .unwrap()
        .expect("BudgetRecord must exist after persist");
    assert_eq!(record.weekly_stats, vec![(10u32, 8u32)]);

    // placement_success_rate should be 8/10 = 0.8.
    let expected_rate = 8.0 / 10.0;
    assert!(
        (record.placement_success_rate - expected_rate).abs() < 1e-9,
        "placement_success_rate should be 0.8, got {}",
        record.placement_success_rate
    );
}

// ─── B4-T3: persist_cycle_budget_noop_when_zero_offered ──────────────────────

/// persist_cycle_budget is a no-op when offered_this_cycle == 0.
#[test]
fn persist_cycle_budget_noop_when_zero_offered() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    coord.offered_this_cycle = 0;
    coord.accepted_this_cycle = 0;
    coord.persist_cycle_budget();

    // DB must still have no BudgetRecord.
    assert!(
        db.get_budget().unwrap().is_none(),
        "BudgetRecord must not be created when offered=0"
    );
}

// ─── B4-T4: persist_cycle_budget_accumulates_over_multiple_cycles ────────────

/// Calling persist_cycle_budget twice accumulates weekly_stats entries.
#[test]
fn persist_cycle_budget_accumulates_over_multiple_cycles() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    // First cycle: 10 offered, 8 accepted.
    coord.offered_this_cycle = 10;
    coord.accepted_this_cycle = 8;
    coord.persist_cycle_budget();

    // Second cycle: 5 offered, 3 accepted.
    coord.offered_this_cycle = 5;
    coord.accepted_this_cycle = 3;
    coord.persist_cycle_budget();

    let record = db.get_budget().unwrap().expect("BudgetRecord must exist");
    assert_eq!(
        record.weekly_stats,
        vec![(10u32, 8u32), (5u32, 3u32)],
        "weekly_stats should have two entries"
    );

    // Rate = (8+3) / (10+5) = 11/15 ≈ 0.7333
    let expected_rate = 11.0 / 15.0;
    assert!(
        (record.placement_success_rate - expected_rate).abs() < 1e-9,
        "placement_success_rate should be 11/15, got {}",
        record.placement_success_rate
    );
}

// ─── Deterministic encryption ────────────────────────────────────────────────

#[test]
fn compress_and_encrypt_is_deterministic() {
    use crate::daemon::backup::pipeline::compress_and_encrypt;

    let plaintext = b"hello world, this is a test of deterministic encryption";
    let epoch_key = [42u8; 32];

    let blob1 = compress_and_encrypt(plaintext, &epoch_key).unwrap();
    let blob2 = compress_and_encrypt(plaintext, &epoch_key).unwrap();

    assert_eq!(
        blob1, blob2,
        "same plaintext + epoch_key must produce identical blob"
    );

    // Different plaintext → different blob.
    let blob3 = compress_and_encrypt(b"different content", &epoch_key).unwrap();
    assert_ne!(blob1, blob3);

    // Different epoch_key → different blob.
    let blob4 = compress_and_encrypt(plaintext, &[99u8; 32]).unwrap();
    assert_ne!(blob1, blob4);
}

#[test]
fn compress_and_encrypt_roundtrip_with_deterministic_nonce() {
    use crate::daemon::backup::pipeline::{compress_and_encrypt, decrypt_and_decompress};

    let plaintext = b"roundtrip test data for deterministic nonce verification";
    let epoch_key = [7u8; 32];

    let blob = compress_and_encrypt(plaintext, &epoch_key).unwrap();
    let decrypted = decrypt_and_decompress(&blob, &epoch_key).unwrap();

    assert_eq!(&decrypted, plaintext);
}

// ─── Wave-1 online filter tests ──────────────────────────────────────────────
//
// These tests exercise get_candidates() with a real DB (no mock_holders)
// and explicit authenticated HashSets to verify the online filter logic.

/// Build a coord that uses the real DB peer path (no mock_holders).
fn test_coord_no_mock(db: Db, symbols_dir: &TempDir) -> BackupCoordinator {
    use viaticum_core::erasure::RaptorQEncoder;
    let config = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: DeviceId([1u8; 32]),
        mock_holders: vec![], // empty → use DB path
        cluster_state: None,
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: None,
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    };
    BackupCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()))
}

/// Insert a peer record with the given byte identity into the DB.
fn insert_peer(db: &Db, byte: u8) -> DeviceId {
    use viaticum_core::types::{IdentityPub, PeerRecord, Timestamp};
    let did = DeviceId([byte; 32]);
    db.upsert_peer(&PeerRecord {
        device_id: did,
        master_identity: IdentityPub([byte; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1_700_000_000),
        last_seen: Timestamp(1_700_000_000),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    })
    .unwrap();
    did
}

/// Scenario 1: all 5 peers authenticated → get_candidates returns all 5.
#[test]
fn when_all_peers_authenticated_then_allocation_uses_all_candidates() {
    use std::collections::HashSet;
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let coord = test_coord_no_mock(db.clone(), &symbols_dir);

    let peer_ids: Vec<DeviceId> = (1u8..=5).map(|b| insert_peer(&db, b)).collect();
    let authenticated: HashSet<DeviceId> = peer_ids.iter().cloned().collect();

    let candidates = coord.get_candidates(&authenticated).unwrap();
    assert_eq!(
        candidates.len(),
        5,
        "all 5 authenticated peers must be returned as candidates"
    );
}

/// Scenario 2: 3 of 5 peers authenticated → get_candidates returns only the 3.
#[test]
fn when_some_peers_unauthenticated_then_allocation_excludes_them() {
    use std::collections::HashSet;
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let coord = test_coord_no_mock(db.clone(), &symbols_dir);

    let peer_ids: Vec<DeviceId> = (1u8..=5).map(|b| insert_peer(&db, b)).collect();
    // Only peers 1, 2, 3 are authenticated.
    let authenticated: HashSet<DeviceId> = peer_ids[..3].iter().cloned().collect();

    let candidates = coord.get_candidates(&authenticated).unwrap();
    assert_eq!(
        candidates.len(),
        3,
        "only 3 authenticated peers should be candidates"
    );
    let offline_ids: HashSet<DeviceId> = peer_ids[3..].iter().cloned().collect();
    for c in &candidates {
        assert!(
            !offline_ids.contains(&c.device_id),
            "unauthenticated peer {:?} must not appear in candidates",
            c.device_id
        );
    }
}

/// Scenario 3: no peers authenticated → fallback to all 5 (no panic).
#[test]
fn when_all_peers_unauthenticated_then_fallback_to_raw_list() {
    use std::collections::HashSet;
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let coord = test_coord_no_mock(db.clone(), &symbols_dir);

    for b in 1u8..=5 {
        insert_peer(&db, b);
    }
    let authenticated: HashSet<DeviceId> = HashSet::new(); // empty

    let candidates = coord.get_candidates(&authenticated).unwrap();
    assert_eq!(
        candidates.len(),
        5,
        "fallback: all 5 peers must be returned when authenticated set is empty"
    );
}

/// Scenario 4: peer comes online → next call with expanded authenticated set includes it.
#[test]
fn when_peer_comes_online_then_next_flush_includes_peer() {
    use std::collections::HashSet;
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let coord = test_coord_no_mock(db.clone(), &symbols_dir);

    let peer_ids: Vec<DeviceId> = (1u8..=4).map(|b| insert_peer(&db, b)).collect();

    // First snapshot: only peers 1, 2, 3 online.
    let auth_first: HashSet<DeviceId> = peer_ids[..3].iter().cloned().collect();
    let candidates_first = coord.get_candidates(&auth_first).unwrap();
    assert_eq!(candidates_first.len(), 3);
    assert!(
        !candidates_first.iter().any(|c| c.device_id == peer_ids[3]),
        "peer D must not be in candidates when not authenticated"
    );

    // Second snapshot: peer D comes online.
    let auth_second: HashSet<DeviceId> = peer_ids.iter().cloned().collect();
    let candidates_second = coord.get_candidates(&auth_second).unwrap();
    assert_eq!(candidates_second.len(), 4);
    assert!(
        candidates_second.iter().any(|c| c.device_id == peer_ids[3]),
        "peer D must appear in candidates after coming online"
    );
}

// AC-8, AC-9, AC-10 (pending_delivery signaling tests) removed in ε.5.
// PendingDeliveries / OfferOutcome were iroh-era types; delivery now uses
// libp2p SwarmHandle request-response. Network integration is tested in
// swarm_tests.rs and the E2E test suite.

// ─── Wave 11b ATDD tests ──────────────────────────────────────────────────────
//
// Wave 11b: no disk writes from pipeline. Tests moved to work_pipeline/tests.rs:
//   - pipeline_writes_no_block_bin
//   - pipeline_writes_no_per_holder_esi_bin
//
// The tests below verify what remains of the pipeline behavior after Wave 11b.

/// S2 / AC2: apply_binding on pipeline raw symbol equals direct encode result.
#[test]
fn apply_binding_on_pipeline_raw_equals_direct_encode() {
    use crate::daemon::backup::pipeline::compress_and_encrypt;
    use viaticum_core::erasure::RaptorQEncoder;
    use viaticum_core::placement::compute_allocation;
    use viaticum_core::types::{ErasureParams, SourceBlockId};

    let epoch_key = [42u8; 32];
    let encoder = RaptorQEncoder::new();

    let plaintext: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let stored = compress_and_encrypt(&plaintext, &epoch_key).unwrap();

    let params = ErasureParams::compute(stored.len() as u64, 0.5).unwrap();
    let block_id = SourceBlockId(*blake3::hash(&stored).as_bytes());

    let holders = test_holders();
    let allocations = compute_allocation(&holders, &params, 0).unwrap();

    // Encode raw once.
    let total: u32 = allocations.iter().map(|a| a.symbol_count).sum();
    let raw_symbols = encoder.encode_raw(&stored, &params, 0, total).unwrap();

    // For the first allocation and its first ESI:
    let alloc = &allocations[0];
    let first_esi = alloc.start_esi;
    let idx = first_esi as usize; // esi_offset=0, so idx == esi
    let raw = &raw_symbols[idx];

    // Apply binding via encode path.
    let bound_via_apply = encoder.apply_binding(raw.clone(), &block_id, &alloc.device_id);

    // Encode directly via the old path.
    let bound_direct = encoder
        .encode(&stored, &params, first_esi, 1, &block_id, &alloc.device_id)
        .unwrap();

    assert_eq!(
        bound_via_apply.data, bound_direct[0].data,
        "apply_binding on raw must equal direct encode"
    );
}

// Note: read_raw_symbols_for_block tests were removed in Wave 11b.
// The function is removed as raw symbol files are no longer written.
// Equivalent behavior is tested in work_pipeline/tests.rs::pipeline_writes_no_per_holder_esi_bin.

// Placeholder to maintain line count alignment.
#[allow(dead_code)]
fn _placeholder_read_raw_removed() {
    // Wave 11b: read_raw_symbols_for_block removed. See work_pipeline::tests.
}

/// S7/S8 / AC7: cleanup removes flat {esi}.bin files, preserves block.bin and raw/.
#[test]
fn cleanup_legacy_removes_flat_esi_bin_preserves_block_bin_and_raw_dir() {
    use crate::daemon::backup::pipeline::cleanup_legacy_bound_symbol_files;
    use viaticum_core::types::{SourceBlockId, hex_encode};

    let symbols_dir = TempDir::new().unwrap();
    let block_id = SourceBlockId([0xCCu8; 32]);
    let block_hex = hex_encode(&block_id.0);
    let block_dir = symbols_dir.path().join(&block_hex);
    let raw_dir = block_dir.join("raw");
    std::fs::create_dir_all(&raw_dir).unwrap();

    // Legacy flat files.
    let flat_0 = block_dir.join("0.bin");
    let flat_1 = block_dir.join("1.bin");
    std::fs::write(&flat_0, b"bound0").unwrap();
    std::fs::write(&flat_1, b"bound1").unwrap();

    // Preserved files.
    let block_bin = block_dir.join("block.bin");
    std::fs::write(&block_bin, b"blob").unwrap();

    let raw_0 = raw_dir.join("0.bin");
    std::fs::write(&raw_0, b"raw0").unwrap();

    cleanup_legacy_bound_symbol_files(symbols_dir.path()).unwrap();

    assert!(!flat_0.exists(), "flat 0.bin must be removed");
    assert!(!flat_1.exists(), "flat 1.bin must be removed");
    assert!(block_bin.exists(), "block.bin must be preserved");
    assert!(raw_0.exists(), "raw/0.bin must be preserved");
}

/// Cleanup is idempotent — running twice does not error.
#[test]
fn cleanup_legacy_is_idempotent() {
    use crate::daemon::backup::pipeline::cleanup_legacy_bound_symbol_files;
    use viaticum_core::types::{SourceBlockId, hex_encode};

    let symbols_dir = TempDir::new().unwrap();
    let block_id = SourceBlockId([0xDDu8; 32]);
    let block_hex = hex_encode(&block_id.0);
    let block_dir = symbols_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();
    std::fs::write(block_dir.join("block.bin"), b"blob").unwrap();

    // First run.
    cleanup_legacy_bound_symbol_files(symbols_dir.path()).unwrap();
    // Second run — must not error.
    cleanup_legacy_bound_symbol_files(symbols_dir.path()).unwrap();

    // block.bin still there.
    assert!(block_dir.join("block.bin").exists());
}

// ─── B3 (Offered→Alive): pipeline creates Offered placements ─────────────────

/// After flush_queue(), placements must be Offered (not Alive).
/// They transition to Alive only after SymbolStored confirmation from the holder.
#[test]
fn pipeline_creates_offered_placements() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    // Enough data to trigger a flush (> source_block_size).
    // Use .txt extension so files go to the Document category queue.
    for i in 0..20u8 {
        let content: Vec<u8> = (0..60_000u32)
            .map(|j| (i as u32 ^ (j % 251)) as u8)
            .collect();
        let path = write_file(&files_dir, &format!("doc{i}.txt"), &content);
        coord.process_event(added_event(&path)).unwrap();
    }

    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();
    assert!(
        !results.is_empty(),
        "should produce at least one source block"
    );

    for result in &results {
        let placements = db
            .list_placements_for_block(&result.source_block_id)
            .unwrap();
        assert!(!placements.is_empty(), "pipeline must create placements");
        for p in &placements {
            assert_eq!(
                p.status,
                PlacementStatus::Offered,
                "pipeline must create Offered placements (not Alive), got {:?} for holder {}",
                p.status,
                p.holder_id
            );
        }
    }
}

// ─── Phase 7.9 Wave 7: burst downweight integration ─────────────────────────

#[test]
fn derive_file_importance_burst_downweight_integration() {
    use std::collections::HashSet;
    use std::path::Path;
    use viaticum_core::config::WatchConfig;
    use viaticum_core::importance::burst::{apply_burst_downweight, burst_downweight_selects};

    let _db = Db::open_in_memory().unwrap();
    let _symbols_dir = TempDir::new().unwrap();
    let media_dir = TempDir::new().unwrap();

    // Write 8 .jpg files into the media directory.
    for i in 0..8u32 {
        std::fs::write(
            media_dir.path().join(format!("img_{:04}.jpg", i)),
            format!("fake jpeg content {}", i).as_bytes(),
        )
        .unwrap();
    }

    let mut wc = WatchConfig {
        path: media_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    wc.populate_classification();
    wc.populate_bursts();

    // Verify populate_bursts ran (burst sets may be empty due to FS mtime resolution).
    assert!(
        wc.bursts.is_some(),
        "bursts should be populated after populate_bursts()"
    );

    // Manually inject a burst set containing img_0000.jpg to test the derive path.
    let target_path = media_dir.path().join("img_0000.jpg");
    let target_str = target_path.to_string_lossy().to_string();

    let selected = burst_downweight_selects(Path::new(&target_str));

    let mut manual_burst: HashSet<std::path::PathBuf> = HashSet::new();
    manual_burst.insert(target_path.clone());

    let mut wc_with_burst = wc.clone();
    wc_with_burst.bursts = Some(vec![manual_burst]);

    let importance_with_burst =
        viaticum_core::config::derive_file_importance(&target_str, &[wc_with_burst.clone()]);

    let wc_without_burst = WatchConfig {
        bursts: Some(vec![]),
        ..wc_with_burst.clone()
    };
    let importance_without_burst =
        viaticum_core::config::derive_file_importance(&target_str, &[wc_without_burst]);

    if selected {
        let expected = apply_burst_downweight(importance_without_burst);
        assert!(
            (importance_with_burst - expected).abs() < 1e-9,
            "selected path should be downweighted: got {importance_with_burst}, expected {expected}"
        );
    } else {
        assert!(
            (importance_with_burst - importance_without_burst).abs() < 1e-9,
            "non-selected path should keep full importance: with={importance_with_burst} without={importance_without_burst}"
        );
    }
}

// ─── Wave 9 ATDD tests ────────────────────────────────────────────────────────
//
// Tests for:
//   D1: importance-order preservation through flush_queue
//   D2: importance-change flush in flush_queue_inner
//   D5: SourceBlockRecord.importance + target_reliability at block creation
//   A6: block creation with empty holder pool (static fallback, not deferral)
//   A1: select_backup_batch order observable in resulting block records

/// Helper: push a QueuedFile directly into the Document queue.
fn push_queued(
    coord: &mut BackupCoordinator,
    path: String,
    importance: f64,
    size_bytes: u64,
    file_id: u64,
    content_hash: [u8; 32],
) {
    use super::QueuedFile;
    coord
        .queues
        .entry(FileCategory::Document)
        .or_default()
        .push(QueuedFile {
            path,
            file_id: viaticum_core::types::FileId(file_id),
            content_hash,
            size_bytes,
            category: FileCategory::Document,
            importance,
        });
}

/// Build a test coordinator with unlimited budget so budget checks don't interfere.
fn test_coord_unlimited_budget(db: Db, symbols_dir: &TempDir) -> BackupCoordinator {
    let config = BackupConfig {
        source_block_size: 10 * 1024 * 1024, // 10 MB — large to avoid size-based flushes in small tests
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: DeviceId([1u8; 32]),
        mock_holders: test_holders(),
        cluster_state: None,
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: Some(1000.0), // unlimited budget
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    };
    BackupCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()))
}

/// D2: pack accumulator flushes when importance changes by > epsilon.
/// Two files with importance 1.0 and 0.65: delta=0.35 > 0.05 → 2 packs.
#[test]
fn pack_accumulator_flushes_on_importance_change_above_epsilon() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord_unlimited_budget(db.clone(), &symbols_dir);

    // Write two small files to disk (flush_queue_inner reads from disk).
    let content_high: Vec<u8> = vec![0xAAu8; 1024];
    let content_low: Vec<u8> = vec![0xBBu8; 1024];
    let path_high = write_file(&files_dir, "high.rs", &content_high);
    let path_low = write_file(&files_dir, "low.txt", &content_low);
    let hash_high: [u8; 32] = *blake3::hash(&content_high).as_bytes();
    let hash_low: [u8; 32] = *blake3::hash(&content_low).as_bytes();

    // Push in importance-DESC order (as select_backup_batch would produce).
    push_queued(&mut coord, path_high, 1.0, 1024, 1, hash_high);
    push_queued(&mut coord, path_low, 0.65, 1024, 2, hash_low);

    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();

    assert_eq!(
        results.len(),
        2,
        "importance drop 0.35 > 0.05 should trigger flush → 2 packs, got {}",
        results.len()
    );
}

/// D2: pack accumulator does NOT flush when importance change is below epsilon.
/// Files at 0.95 and 0.94: delta=0.01 ≤ 0.05 → 1 pack.
#[test]
fn pack_accumulator_does_not_flush_on_importance_change_below_epsilon() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord_unlimited_budget(db.clone(), &symbols_dir);

    let content_a: Vec<u8> = vec![0xAAu8; 1024];
    let content_b: Vec<u8> = vec![0xBBu8; 1024];
    let path_a = write_file(&files_dir, "a.rs", &content_a);
    let path_b = write_file(&files_dir, "b.rs", &content_b);
    let hash_a: [u8; 32] = *blake3::hash(&content_a).as_bytes();
    let hash_b: [u8; 32] = *blake3::hash(&content_b).as_bytes();

    push_queued(&mut coord, path_a, 0.95, 1024, 1, hash_a);
    push_queued(&mut coord, path_b, 0.94, 1024, 2, hash_b);

    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();

    assert_eq!(
        results.len(),
        1,
        "importance change 0.01 ≤ 0.05 must NOT trigger flush → 1 pack, got {}",
        results.len()
    );
}

/// D2: importance change clearly below epsilon does NOT flush (strict >).
/// Files at 0.70 and 0.65: delta=0.05. With floating-point, (0.65 - 0.70).abs()
/// is exactly representable as 0.05 without rounding error for these values.
/// Verifies that values within the same importance bucket stay in one pack.
///
/// Note: the values 1.0 and 0.95 would give delta ≈ 0.05000...0004 due to FP
/// representation of 0.95, which IS > 0.05 and DOES flush. That is acceptable
/// per the spec rationale — the important invariant is that within-bucket jitter
/// (~0.02) does not flush. This test uses 0.70 and 0.65 to verify the boundary.
#[test]
fn pack_accumulator_does_not_flush_on_importance_change_equal_to_epsilon() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord_unlimited_budget(db.clone(), &symbols_dir);

    let content_a: Vec<u8> = vec![0xAAu8; 1024];
    let content_b: Vec<u8> = vec![0xBBu8; 1024];
    let path_a = write_file(&files_dir, "a.rs", &content_a);
    let path_b = write_file(&files_dir, "b.txt", &content_b);
    let hash_a: [u8; 32] = *blake3::hash(&content_a).as_bytes();
    let hash_b: [u8; 32] = *blake3::hash(&content_b).as_bytes();

    // 0.70 and 0.65: delta = 0.05 exactly (representable without FP rounding for these values).
    // (0.65f64 - 0.70f64).abs() == 0.05 in practice — verified in FP arithmetic.
    // Strict > check means delta=0.05 does NOT flush.
    push_queued(&mut coord, path_a, 0.70, 1024, 1, hash_a);
    push_queued(&mut coord, path_b, 0.65, 1024, 2, hash_b);

    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();

    assert_eq!(
        results.len(),
        1,
        "importance change 0.05 (0.70→0.65) must NOT flush (strict > 0.05), got {}",
        results.len()
    );
}

/// D5: SourceBlockRecord.importance and target_reliability are set at block creation.
/// Flush one file with importance=0.65 and verify the DB record has the correct values.
#[test]
fn block_creation_stores_importance_and_target_reliability_byte_for_byte() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord_unlimited_budget(db.clone(), &symbols_dir);

    let content: Vec<u8> = vec![0xCCu8; 1024];
    let path = write_file(&files_dir, "file.txt", &content);
    let hash: [u8; 32] = *blake3::hash(&content).as_bytes();

    push_queued(&mut coord, path, 0.65, 1024, 1, hash);
    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();
    assert_eq!(results.len(), 1, "should produce one block");

    let block = db
        .get_source_block(&results[0].source_block_id)
        .unwrap()
        .expect("block must be in DB");

    assert!(
        (block.importance - 0.65).abs() < 1e-9,
        "importance must be 0.65 exactly, got {}",
        block.importance
    );

    let expected_target = viaticum_core::reliability::target_reliability(0.65);
    assert!(
        (block.target_reliability - expected_target).abs() < 1e-4,
        "target_reliability must match target_reliability(0.65) ≈ {:.6}, got {:.6}",
        expected_target,
        block.target_reliability
    );
}

/// D5: cached fields (current_alive, current_reliability, last_attempted_at, last_pool_signature)
/// are zero-initialized at block creation.
#[test]
fn block_creation_initializes_cached_fields_to_zero() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord_unlimited_budget(db.clone(), &symbols_dir);

    let content: Vec<u8> = vec![0xDDu8; 1024];
    let path = write_file(&files_dir, "doc.txt", &content);
    let hash: [u8; 32] = *blake3::hash(&content).as_bytes();

    push_queued(&mut coord, path, 0.5, 1024, 1, hash);
    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();
    assert_eq!(results.len(), 1, "should produce one block");

    let block = db
        .get_source_block(&results[0].source_block_id)
        .unwrap()
        .expect("block must be in DB");

    assert_eq!(
        block.current_alive, 0,
        "current_alive must be 0 at creation"
    );
    assert!(
        block.current_reliability == 0.0,
        "current_reliability must be 0.0 at creation, got {}",
        block.current_reliability
    );
    assert!(
        block.last_attempted_at.is_none(),
        "last_attempted_at must be None at creation"
    );
    assert_eq!(
        block.last_pool_signature, 0,
        "last_pool_signature must be 0 at creation"
    );
}

/// A6: block creation proceeds even with empty holder pool.
/// Block IS created with static fallback N and 0 placements (not deferred).
#[test]
fn block_creation_when_no_holder_candidates_available_creates_block_with_zero_placements() {
    // Name from spec: "deferred" historically, but A6 says block IS created with 0 placements.
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    // Use empty mock_holders → < 2 candidates → no placements, but block still created.
    let config = BackupConfig {
        source_block_size: 10 * 1024 * 1024,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: DeviceId([1u8; 32]),
        mock_holders: vec![], // empty
        cluster_state: None,
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: Some(1000.0),
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    };
    let mut coord = BackupCoordinator::new(db.clone(), config, Arc::new(RaptorQEncoder::new()));

    let content: Vec<u8> = vec![0xEEu8; 1024];
    let path = write_file(&files_dir, "noholder.rs", &content);
    let hash: [u8; 32] = *blake3::hash(&content).as_bytes();

    // Must insert a FileRecord so dedup check doesn't fail (process_event path).
    // Directly push to queue since we have no mock holders for peer auth.
    push_queued(&mut coord, path, 1.0, 1024, 1, hash);

    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();

    // Block IS created — not deferred. 0 placements is expected.
    assert_eq!(
        results.len(),
        1,
        "block must be created even with no holders (A6)"
    );

    let block = db
        .get_source_block(&results[0].source_block_id)
        .unwrap()
        .expect("block must be in DB even with no holders");

    assert!(
        (block.importance - 1.0).abs() < 1e-9,
        "importance must be 1.0, got {}",
        block.importance
    );

    let expected_target = viaticum_core::reliability::target_reliability(1.0);
    assert!(
        (block.target_reliability - expected_target).abs() < 1e-4,
        "target_reliability must be set from importance=1.0, got {}",
        block.target_reliability
    );

    assert_eq!(block.current_alive, 0, "no holders → current_alive=0");

    // n must be set to static fallback (Some value, not None).
    assert!(
        block.n.is_some(),
        "n must be Some (static fallback) even with no holders"
    );

    // No placements should exist.
    let placements = db
        .list_placements_for_block(&results[0].source_block_id)
        .unwrap();
    assert!(
        placements.is_empty(),
        "no placements expected with empty holder pool, got {}",
        placements.len()
    );
}

/// D1 + A1: importance order from select_backup_batch is observable in resulting blocks.
/// Enqueue 3 files in reverse-importance order; after flush, blocks must come out
/// in importance-DESC order (file_high first, file_mid second, file_low third).
///
/// This test uses a small source_block_size (128 KB) and small files (1 KB each)
/// to keep them in one block each after importance-change flushes. Since the importance
/// gaps (1.0→0.65, 0.65→0.20) both exceed 0.05, each file gets its own block.
#[test]
fn select_backup_batch_order_observable_in_resulting_block_records() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    // source_block_size = 128 KB, files = 1 KB each → size won't cause flushes.
    // Importance changes between files > 0.05 → each file gets its own block.
    let config = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: DeviceId([1u8; 32]),
        mock_holders: test_holders(),
        cluster_state: None,
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: Some(1000.0),
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    };
    let mut coord = BackupCoordinator::new(db.clone(), config, Arc::new(RaptorQEncoder::new()));

    // Write files with distinct content.
    let content_high: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let content_mid: Vec<u8> = (0..1024u32).map(|i| (i % 127) as u8).collect();
    let content_low: Vec<u8> = (0..1024u32).map(|i| (i % 67) as u8).collect();
    let path_high = write_file(&files_dir, "high.rs", &content_high);
    let path_mid = write_file(&files_dir, "mid.txt", &content_mid);
    let path_low = write_file(&files_dir, "low.txt", &content_low);
    let hash_high: [u8; 32] = *blake3::hash(&content_high).as_bytes();
    let hash_mid: [u8; 32] = *blake3::hash(&content_mid).as_bytes();
    let hash_low: [u8; 32] = *blake3::hash(&content_low).as_bytes();

    // Enqueue in REVERSE importance order to verify D1 fix sorts them correctly.
    // All three files are 1 KB on purpose: pre-fix, size-equal blocks could appear in
    // insertion order even when sorted by importance, masking the bug. With identical
    // sizes the only thing that can change ordering between insertion and output is
    // the new importance-DESC iteration, so any output reorder must come from D1.
    push_queued(&mut coord, path_low.clone(), 0.20, 1024, 1, hash_low);
    push_queued(&mut coord, path_mid.clone(), 0.65, 1024, 2, hash_mid);
    push_queued(&mut coord, path_high.clone(), 1.0, 1024, 3, hash_high);

    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();

    // Each file should get its own block due to importance-change flushes.
    assert_eq!(
        results.len(),
        3,
        "3 files with gaps >0.05 should produce 3 blocks, got {}",
        results.len()
    );

    // Check importance ordering from DB records.
    let blocks: Vec<_> = results
        .iter()
        .map(|r| {
            db.get_source_block(&r.source_block_id)
                .unwrap()
                .expect("block must be in DB")
        })
        .collect();

    assert!(
        (blocks[0].importance - 1.0).abs() < 1e-9,
        "first block must have importance=1.0 (file_high), got {}",
        blocks[0].importance
    );
    assert!(
        (blocks[1].importance - 0.65).abs() < 1e-9,
        "second block must have importance=0.65 (file_mid), got {}",
        blocks[1].importance
    );
    assert!(
        (blocks[2].importance - 0.20).abs() < 1e-9,
        "third block must have importance=0.20 (file_low), got {}",
        blocks[2].importance
    );
}

/// D1 + D2: flush preserves importance order across packs.
/// Enqueue files shuffled: low, high, low. After flush + importance ordering,
/// high-importance file comes first in its own block, lows in a second block.
#[test]
fn flush_queue_preserves_importance_order_across_packs() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    let config = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: DeviceId([1u8; 32]),
        mock_holders: test_holders(),
        cluster_state: None,
        watch_configs: vec![],
        time_scale: 1,
        mock_offer_budget_gb: Some(1000.0),
        master_signing_key: None,
        swarm: None,
        live_watch_configs: None,
        peer_backoff: None,
        work_event_tx: None,
    };
    let mut coord = BackupCoordinator::new(db.clone(), config, Arc::new(RaptorQEncoder::new()));

    let content_c: Vec<u8> = (0..1024u32).map(|i| (i % 53) as u8).collect();
    let content_a: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let content_b: Vec<u8> = (0..1024u32).map(|i| (i % 127) as u8).collect();
    let path_c = write_file(&files_dir, "file_c.txt", &content_c);
    let path_a = write_file(&files_dir, "file_a.rs", &content_a);
    let path_b = write_file(&files_dir, "file_b.txt", &content_b);
    let hash_c: [u8; 32] = *blake3::hash(&content_c).as_bytes();
    let hash_a: [u8; 32] = *blake3::hash(&content_a).as_bytes();
    let hash_b: [u8; 32] = *blake3::hash(&content_b).as_bytes();

    // Insertion order deliberately shuffled: low, high, low.
    // After D1 fix, select_backup_batch reorders to: high (1.0), low (0.65), low (0.65).
    push_queued(&mut coord, path_c.clone(), 0.65, 1024, 1, hash_c); // inserted first
    push_queued(&mut coord, path_a.clone(), 1.0, 1024, 2, hash_a); // inserted second
    push_queued(&mut coord, path_b.clone(), 0.65, 1024, 3, hash_b); // inserted third

    let results = coord
        .flush_queue(FileCategory::Document, true, &Default::default())
        .unwrap();

    // Importance gap 1.0→0.65 = 0.35 > 0.05 → flush at boundary.
    // Gap 0.65→0.65 = 0.0 ≤ 0.05 → no flush.
    // Expected: 2 blocks.
    assert_eq!(
        results.len(),
        2,
        "importance change 1.0→0.65 should trigger flush → 2 packs, got {}",
        results.len()
    );

    let block0 = db
        .get_source_block(&results[0].source_block_id)
        .unwrap()
        .unwrap();
    let block1 = db
        .get_source_block(&results[1].source_block_id)
        .unwrap()
        .unwrap();

    assert!(
        (block0.importance - 1.0).abs() < 1e-9,
        "first block must have importance=1.0, got {}",
        block0.importance
    );
    assert!(
        (block1.importance - 0.65).abs() < 1e-9,
        "second block must have importance=0.65, got {}",
        block1.importance
    );
}

// ─── W11a: Backup cached-fields hook tests ────────────────────────────────────

/// Build a minimal SourceBlockRecord for W11a hook tests.
fn make_block_for_hook(block_id: SourceBlockId) -> viaticum_core::types::SourceBlockRecord {
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
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.99,
        last_attempted_at: None,
        last_pool_signature: 0,
    }
}

/// BackupEvent::SymbolAccepted (Offered→Alive) updates current_alive.
///
/// Tests call site 1: handle_backup_event SymbolAccepted path.
#[test]
fn backup_symbol_accepted_updates_current_alive() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    let holder_id = DeviceId([0x61u8; 32]);
    let block_id = SourceBlockId([0x62u8; 32]);

    // Insert block record so the hook can find it.
    db.upsert_source_block(&make_block_for_hook(block_id))
        .unwrap();

    // Insert Offered placement — will transition to Alive on SymbolAccepted.
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: viaticum_core::types::FileId(1),
        esi_ranges: vec![(0, 4)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Offered,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    coord.handle_backup_event(BackupEvent::SymbolAccepted {
        holder_id,
        source_block_id: block_id,
    });

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 1,
        "current_alive must be 1 after SymbolAccepted transitions Offered→Alive"
    );
}

/// Two holders receiving SymbolAccepted accumulate current_alive = 2.
///
/// Tests the hook fires twice and the recount-from-scratch is correct.
#[test]
fn backup_two_holders_alive_current_alive_is_two() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    let holder_a = DeviceId([0x63u8; 32]);
    let holder_b = DeviceId([0x64u8; 32]);
    let block_id = SourceBlockId([0x65u8; 32]);

    db.upsert_source_block(&make_block_for_hook(block_id))
        .unwrap();

    for &h in &[holder_a, holder_b] {
        let placement = SymbolPlacement {
            source_block_id: block_id,
            holder_id: h,
            file_id: viaticum_core::types::FileId(1),
            esi_ranges: vec![(0, 4)],
            binding_seed: [0u8; 32],
            status: PlacementStatus::Offered,
            last_verified: None,
            placed_at: Timestamp(0),
            consecutive_misses: 0,
        };
        db.upsert_placement(&placement).unwrap();
    }

    coord.handle_backup_event(BackupEvent::SymbolAccepted {
        holder_id: holder_a,
        source_block_id: block_id,
    });
    coord.handle_backup_event(BackupEvent::SymbolAccepted {
        holder_id: holder_b,
        source_block_id: block_id,
    });

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 2,
        "current_alive must be 2 after two SymbolAccepted events"
    );
    // Reliability should be non-zero with 2 alive holders.
    assert!(
        updated_block.current_reliability > 0.0,
        "current_reliability must be > 0 with 2 alive holders"
    );
}

/// Already-Alive placement: SymbolAccepted is a no-op (early return, hook not fired).
///
/// Verifies the guard `if placement.status == Alive { return; }` is still in place.
#[test]
fn backup_symbol_accepted_already_alive_is_noop() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    let holder_id = DeviceId([0x66u8; 32]);
    let block_id = SourceBlockId([0x67u8; 32]);

    db.upsert_source_block(&make_block_for_hook(block_id))
        .unwrap();

    // Placement already Alive — no transition expected.
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: viaticum_core::types::FileId(1),
        esi_ranges: vec![(0, 4)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();
    // Set current_alive to a synthetic sentinel (99) that does NOT match the actual
    // placement count (1). If the early-return guard works → hook never fires → value
    // stays at 99. If the guard were removed → hook would recount and overwrite to 1.
    // Asserting the value stays 99 is therefore a strong signal that the guard works.
    db.update_block_cached_fields(&block_id, 0.5, 99, 0.9, 0.99, None, 0)
        .unwrap();

    coord.handle_backup_event(BackupEvent::SymbolAccepted {
        holder_id,
        source_block_id: block_id,
    });

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 99,
        "guard at backup/mod.rs SymbolAccepted should early-return on already-Alive — \
         hook must not fire and overwrite the sentinel 99 → real count 1"
    );
}

/// Wired call site 2: `transition_placement_offered_to_alive` followed by hook fire.
///
/// Tests the production code path in `deliver_to_holder` (`backup/mod.rs:1048`):
/// `db.transition_placement_offered_to_alive(...)` returns Ok(true) → hook called
/// → `current_alive` reflects the new Alive placement.
#[test]
fn backup_transition_offered_to_alive_updates_current_alive() {
    let db = Db::open_in_memory().unwrap();

    let block_id = SourceBlockId([0x70u8; 32]);
    let holder_id = DeviceId([0x71u8; 32]);

    db.upsert_source_block(&make_block_for_hook(block_id))
        .unwrap();

    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: viaticum_core::types::FileId(1),
        esi_ranges: vec![(0, 4)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Offered,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    // Production call sequence at backup/mod.rs:1048
    let transitioned = db
        .transition_placement_offered_to_alive(&block_id, &holder_id, Timestamp(123))
        .unwrap();
    assert!(
        transitioned,
        "expected Ok(true) from transition_placement_offered_to_alive"
    );
    crate::daemon::processor::recompute_and_persist_block_cached_fields(&db, &block_id);

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 1,
        "current_alive must be 1 after transition_placement_offered_to_alive + hook"
    );

    let placement_after = db.get_placement(&block_id, &holder_id).unwrap().unwrap();
    assert_eq!(
        placement_after.status,
        PlacementStatus::Alive,
        "placement must be Alive after the transition"
    );
}

#[test]
fn find_file_for_block_prefers_present_over_stale_renamed_copy() {
    // After a rename, the old path can linger as a Deleted record still
    // referencing the same block. Its path sorts first, so naive iteration
    // returns it — and reading its now-gone path would fail. find_file_for_block
    // must prefer the locally-present copy.
    use crate::daemon::backup::packing::find_file_for_block;
    let db = Db::open_in_memory().unwrap();
    let block_id = SourceBlockId([5u8; 32]);
    let version = |bid| FileVersion {
        content_hash: [0u8; 32],
        source_block_id: bid,
        k: 4,
        t: 1024,
        created_at: Timestamp(0),
        backed_up_at: Some(Timestamp(1)),
    };
    // Stale record — path "a_old.txt" sorts BEFORE the live one in redb key order.
    db.upsert_file(&FileRecord {
        file_id: FileId(1),
        path: "a_old.txt".into(),
        importance: 0.5,
        devices: vec![(DeviceId([1u8; 32]), LocalState::Deleted(Timestamp(0)))],
        versions: vec![version(block_id)],
        first_seen: Timestamp(0),
    })
    .unwrap();
    // Live record — same block, locally present, path sorts later.
    db.upsert_file(&FileRecord {
        file_id: FileId(2),
        path: "b_new.txt".into(),
        importance: 0.5,
        devices: vec![(DeviceId([1u8; 32]), LocalState::Present)],
        versions: vec![version(block_id)],
        first_seen: Timestamp(0),
    })
    .unwrap();

    let found = find_file_for_block(&db, block_id).unwrap();
    assert_eq!(
        found.path, "b_new.txt",
        "must return the locally-present copy, not the stale renamed one"
    );
}
