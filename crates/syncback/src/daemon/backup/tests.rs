// Tests for BackupCoordinator.
// All tests use real Db::open_in_memory(), real RaptorQEncoder, and tempfile::TempDir.
// Source block size is set small (128 KB) for fast tests.
//
// AC-8: pending_delivery_accept_signals_correctly
// AC-9: pending_delivery_reject_signals_correctly
// AC-10: pending_delivery_times_out_when_no_response

use std::sync::{Arc, Mutex};

use syncback_core::cluster::{
    derive_master_key, issue_device_certificate, master_identity, ClusterState,
};
use syncback_core::db::Db;
use syncback_core::erasure::{ErasureEncoder, RaptorQEncoder};
use syncback_core::types::{
    DeviceId, ErasureParams, Event, FileCategory, FileId, FileRecord, FileVersion,
    LocalState, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp,
};
use tempfile::TempDir;

use super::{BackupConfig, BackupCoordinator, BackupEvent, DirtyEvent, DirtyKind};
use crate::daemon::backup::pipeline::decrypt_and_decompress;
use crate::daemon::backup::packing::parse_pack_index;

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
    };
    BackupCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()))
}

/// 5 mock holders with varying trust scores.
fn test_holders() -> Vec<syncback_core::placement::HolderCandidate> {
    (0..5)
        .map(|i| syncback_core::placement::HolderCandidate {
            device_id: syncback_core::types::DeviceId([(i + 1) as u8; 32]),
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

    let results = coord.flush_queue(FileCategory::Document, false, &Default::default()).unwrap();
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

    let results = coord.flush_queue(FileCategory::Document, true, &Default::default()).unwrap();
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

    let results = coord.flush_queue(FileCategory::Document, false, &Default::default()).unwrap();
    assert!(!results.is_empty(), "should produce results");

    for result in &results {
        let block = db
            .get_source_block(&result.source_block_id)
            .unwrap()
            .expect("source block should exist");
        assert!(
            matches!(
                block.block_type,
                syncback_core::types::SourceBlockType::Pack { .. }
            ),
            "should be Pack type"
        );
        assert_eq!(block.status, syncback_core::types::SourceBlockStatus::Active);
    }
}

// ─── Test 7: flush_queue_writes_symbol_files ─────────────────────────────────

#[test]
fn flush_queue_writes_symbol_files() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    // Files < SMALL_BLOCK_SIZE so they go to queue (not large-file path).
    for i in 0..4u8 {
        let content: Vec<u8> = (0..50_000u32)
            .map(|j| (i as u32 ^ (j % 251)) as u8)
            .collect();
        let path = write_file(&files_dir, &format!("f{i}.txt"), &content);
        coord.process_event(added_event(&path)).unwrap();
    }

    let results = coord.flush_queue(FileCategory::Document, true, &Default::default()).unwrap();
    assert!(!results.is_empty());

    for result in &results {
        let block_hex: String = result
            .source_block_id
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let block_dir = symbols_dir.path().join(&block_hex);
        assert!(block_dir.exists(), "block symbol dir should exist");

        for (_, count) in &result.symbol_count_per_holder {
            assert!(*count > 0, "each holder should have >0 symbols");
        }

        // Verify symbol files exist in the directory
        let entries: Vec<_> = std::fs::read_dir(&block_dir).unwrap().collect();
        assert!(!entries.is_empty(), "symbol files should exist in dir");
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

    coord.flush_queue(FileCategory::Document, true, &Default::default()).unwrap();

    let after = db.get_file(&path).unwrap().unwrap();
    assert!(
        after.versions[0].backed_up_at.is_some(),
        "backed_up_at should be set after flush"
    );
}

// ─── Test 9: pipeline_roundtrip_can_decode ───────────────────────────────────
// THE MOST IMPORTANT TEST: backup -> decode -> verify content.

#[test]
fn pipeline_roundtrip_can_decode() {
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
    };
    let encoder: Arc<dyn ErasureEncoder> = Arc::new(RaptorQEncoder::new());
    let mut coord = BackupCoordinator::new(db.clone(), config, encoder.clone());

    // Write a test file with recognizable content.
    let content = b"roundtrip test content ---";
    let repeated: Vec<u8> = content.iter().cycle().take(4096).cloned().collect();
    let path = write_file(&files_dir, "data.txt", &repeated);

    coord.process_event(added_event(&path)).unwrap();
    let results = coord.flush_queue(FileCategory::Document, true, &Default::default()).unwrap();
    assert_eq!(results.len(), 1, "should produce one source block");

    let block_id = results[0].source_block_id;
    // stored_size is returned by PipelineResult -- use it to trim decoded block.
    let stored_size = results[0].stored_size as usize;
    let placements = db.list_placements_for_block(&block_id).unwrap();
    assert!(!placements.is_empty(), "should have placements");

    // Reconstruct ErasureParams using the actual stored_size.
    let params = ErasureParams::compute(stored_size as u64, 0.5).unwrap();

    // Wave 2: raw symbols are at {block_dir}/raw/{esi}.bin — no unbind needed.
    let mut raw_symbols: Vec<syncback_core::erasure::Symbol> = Vec::new();
    let needed = params.k_eff as usize;

    'outer: for placement in &placements {
        let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
        let raw_dir = symbols_dir.path().join(&block_hex).join("raw");

        for (start_esi, count) in &placement.esi_ranges {
            for i in 0..*count {
                let esi = start_esi + i;
                let sym_path = raw_dir.join(format!("{esi}.bin"));
                if !sym_path.exists() {
                    continue;
                }
                let data = std::fs::read(&sym_path).unwrap();
                // Raw symbol: no unbind needed.
                raw_symbols.push(syncback_core::erasure::Symbol { esi, data });

                if raw_symbols.len() >= needed {
                    break 'outer;
                }
            }
        }
    }

    assert!(
        raw_symbols.len() >= needed,
        "not enough symbols: have {}, need {}",
        raw_symbols.len(),
        needed
    );

    // Decode: returns k*t zero-padded bytes.
    let decoded_padded = encoder.decode(&raw_symbols, &params).unwrap();

    // Trim to exact stored_size (the decoder pads with zeros to k*t).
    assert!(
        decoded_padded.len() >= stored_size,
        "decoded block too small: {} < {}",
        decoded_padded.len(),
        stored_size
    );
    let stored_blob = &decoded_padded[..stored_size];

    // Decrypt and decompress.
    let plaintext = decrypt_and_decompress(stored_blob, &epoch_key)
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
        record.versions[0].content_hash,
        record.versions[1].content_hash,
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
    coord.flush_queue(FileCategory::Document, true, &Default::default()).unwrap();

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
        .list_source_blocks_by_status(syncback_core::types::SourceBlockStatus::Active)
        .unwrap();

    let has_single = blocks
        .iter()
        .any(|b| matches!(b.block_type, syncback_core::types::SourceBlockType::Single));

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
    let _dev_key = syncback_core::cluster::derive_device_key(&seed, &dev_id.0).unwrap();
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

// ─── Test 16: read_symbols_for_holder_reads_correct_files ────────────────────

#[test]
fn read_symbols_for_holder_reads_correct_files() {
    use crate::daemon::backup::pipeline::read_symbols_for_holder;

    let dir = TempDir::new().unwrap();
    let block_id = SourceBlockId([0x01u8; 32]);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();

    for esi in [0u32, 1, 2] {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 64]).unwrap();
    }

    let symbols = read_symbols_for_holder(dir.path(), &block_id, &[(0, 3)]).unwrap();

    assert_eq!(symbols.len(), 3);
    assert_eq!(symbols[0].esi, 0);
    assert_eq!(symbols[1].esi, 1);
    assert_eq!(symbols[2].esi, 2);
    assert_eq!(symbols[0].data, vec![0u8; 64]);
}

// ─── Test 17: read_symbols_for_holder_missing_file_returns_error ─────────────

#[test]
fn read_symbols_for_holder_missing_file_returns_error() {
    use crate::daemon::backup::pipeline::read_symbols_for_holder;

    let dir = TempDir::new().unwrap();
    let block_id = SourceBlockId([0x02u8; 32]);

    let result = read_symbols_for_holder(dir.path(), &block_id, &[(0, 1)]);
    assert!(result.is_err(), "must return error when symbol file is missing");
}

// ─── Test 18: read_symbols_for_holder_multiple_ranges ────────────────────────

#[test]
fn read_symbols_for_holder_multiple_ranges() {
    use crate::daemon::backup::pipeline::read_symbols_for_holder;

    let dir = TempDir::new().unwrap();
    let block_id = SourceBlockId([0x03u8; 32]);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();

    for esi in [0u32, 1, 5, 6, 7] {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 8]).unwrap();
    }

    let symbols =
        read_symbols_for_holder(dir.path(), &block_id, &[(0, 2), (5, 3)]).unwrap();

    assert_eq!(symbols.len(), 5);
    let esis: Vec<u32> = symbols.iter().map(|s| s.esi).collect();
    assert_eq!(esis, vec![0, 1, 5, 6, 7]);
}

// ─── Test 19: backup_config_default_swarm_is_none ────────────────────────────

#[test]
fn backup_config_default_swarm_is_none() {
    let cfg = BackupConfig::default();
    assert!(cfg.swarm.is_none(), "default config must have swarm=None");
}

// ─── Test 20: deliver_symbols_no_op_when_network_none ────────────────────────

#[tokio::test]
async fn deliver_symbols_no_op_when_network_none() {
    use super::PipelineResult;

    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let coordinator = BackupCoordinator::new(
        db,
        BackupConfig {
            symbols_dir: symbols_dir.path().to_path_buf(),
            ..BackupConfig::default()
        },
        Arc::new(RaptorQEncoder::new()),
    );

    coordinator.deliver_symbols(&[]).await;

    let fake_result = PipelineResult {
        source_block_id: SourceBlockId([0u8; 32]),
        k: 1,
        n: 2,
        t: 65535,
        symbol_count_per_holder: vec![(DeviceId([0u8; 32]), 1)],
        stored_size: 0,
        importance: 0.5,
        raw_symbols: vec![],
        esi_offset: 0,
    };
    coordinator.deliver_symbols(&[fake_result]).await;
}

// Tests 21 and 22 (deliver_symbols network integration) removed in ε.5.
// iroh NetworkHandle replaced by libp2p SwarmHandle; network delivery is
// tested in swarm_tests.rs and E2E suite.
//
// ─── Test 21: deliver_symbols_logs_warn_on_peer_not_found (REMOVED) ──────────
#[cfg(any())]
async fn deliver_symbols_logs_warn_on_peer_not_found() {
    use std::collections::HashMap;

    use ed25519_dalek::SigningKey;
    use syncback_core::types::{PlacementStatus, SymbolPlacement};

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

    Arc::try_unwrap(network).ok().map(|n| async move { n.shutdown().await });
}

// ─── Test 22: deliver_symbols_sends_to_reachable_holder (REMOVED) ────────────
#[cfg(any())]
async fn deliver_symbols_sends_to_reachable_holder() {
    use std::collections::HashMap;

    use syncback_core::messages::Message;
    use syncback_core::types::{PlacementStatus, SymbolPlacement};

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

    let mut conn = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx_holder.recv(),
    )
    .await
    .expect("timeout waiting for connection")
    .expect("channel closed");

    let msg = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        conn.recv_message(),
    )
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

    Arc::try_unwrap(network_owner).ok().map(|n| async move { n.shutdown().await });
    Arc::try_unwrap(network_holder).ok().map(|n| async move { n.shutdown().await });
}

// ─── Phase 7.9 tests: watch_configs importance lookup ────────────────────────

/// Helper: build coordinator with specific watch_configs.
fn coord_with_watch(
    db: Db,
    symbols_dir: &TempDir,
    watch_configs: Vec<syncback_core::config::WatchConfig>,
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

    let watch_cfgs = vec![syncback_core::config::WatchConfig {
        path: files_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.9,
        was_legacy_importance: false,
        classification: Some(syncback_core::importance::FolderClassification {
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
    let watch_cfgs = vec![syncback_core::config::WatchConfig {
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
    use syncback_core::config::WatchConfig;

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
        wc_text.classification.as_ref().map(|c| !c.is_media_folder).unwrap_or(false),
        "text folder should classify as non-media"
    );
    assert!(
        wc_media.classification.as_ref().map(|c| c.is_media_folder).unwrap_or(false),
        "media folder should classify as media"
    );

    let mut coord = coord_with_watch(
        db,
        &symbols_dir,
        vec![wc_text.clone(), wc_media.clone()],
    );

    // Enqueue a text file.
    let txt_path_buf = text_dir.path().join("notes.txt");
    std::fs::write(&txt_path_buf, b"important doc content here xyz").unwrap();
    let txt_path_str = txt_path_buf.to_string_lossy().into_owned();
    let txt_event = syncback_core::types::DeviceId([1u8; 32]);
    coord.process_event(super::DirtyEvent {
        path: txt_path_str.clone(),
        kind: super::DirtyKind::Added,
        device_id: txt_event,
    }).unwrap();

    // Enqueue a media file.
    let jpg_path_buf = media_dir.path().join("photo.jpg");
    std::fs::write(&jpg_path_buf, b"fake jpeg content for testing purposes").unwrap();
    let jpg_path_str = jpg_path_buf.to_string_lossy().into_owned();
    coord.process_event(super::DirtyEvent {
        path: jpg_path_str.clone(),
        kind: super::DirtyKind::Added,
        device_id: syncback_core::types::DeviceId([1u8; 32]),
    }).unwrap();

    let queued: Vec<_> = coord.queues.values().flat_map(|q| q.iter()).cloned().collect();
    let txt = queued.iter().find(|f| f.path.ends_with(".txt")).expect("txt file should be queued");
    let jpg = queued.iter().find(|f| f.path.ends_with("photo.jpg")).expect("jpg file should be queued");

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
    };
    let mut coord_a =
        BackupCoordinator::new(db.clone(), config_a, Arc::new(RaptorQEncoder::new()));
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
    };
    let mut coord_b =
        BackupCoordinator::new(db.clone(), config_b, Arc::new(RaptorQEncoder::new()));
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
    };
    let mut coord = BackupCoordinator::new(db.clone(), config, Arc::new(RaptorQEncoder::new()));

    // Queue 3 small files (all well below SMALL_BLOCK_SIZE).
    for i in 0..3u8 {
        let content = vec![i; 30_000];
        let path = write_file(&files_dir, &format!("file{i}.txt"), &content);
        coord.process_event(added_event(&path)).unwrap();
    }

    // With budget=0, flush should defer all files and return empty.
    let results = coord.flush_queue(FileCategory::Document, true, &Default::default()).unwrap();
    assert!(results.is_empty(), "zero budget: no files should be processed");

    // All 3 files must remain in the queue.
    let queue_len: usize = coord.queues.values().map(|q| q.len()).sum();
    assert_eq!(queue_len, 3, "all 3 files should remain in queue when budget=0");

    // No source blocks should have been written to DB.
    let blocks = db
        .list_source_blocks_by_status(syncback_core::types::SourceBlockStatus::Active)
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
    coord.queues.entry(FileCategory::Document).or_default().push(QueuedFile {
        path: path_a.clone(),
        file_id: syncback_core::types::FileId(1),
        content_hash: hash_a,
        size_bytes: 30_000,
        category: FileCategory::Document,
        importance: 0.9,
    });
    coord.queues.entry(FileCategory::Document).or_default().push(QueuedFile {
        path: path_b.clone(),
        file_id: syncback_core::types::FileId(2),
        content_hash: hash_b,
        size_bytes: 30_000,
        category: FileCategory::Document,
        importance: 0.3,
    });

    let results = coord.flush_queue(FileCategory::Document, true, &Default::default()).unwrap();

    // At least one file should have been processed.
    assert!(!results.is_empty(), "at least one file should be processed");

    // The low-importance file (path_b) must remain in queue.
    let doc_queue = coord.queues.get(&FileCategory::Document).unwrap();
    assert_eq!(doc_queue.len(), 1, "exactly one file should remain deferred");
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
        .list_source_blocks_by_status(syncback_core::types::SourceBlockStatus::Active)
        .unwrap();
    assert!(blocks.is_empty(), "no blocks should exist when large file is skipped");
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
        file_id: syncback_core::types::FileId(1),
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

    assert_eq!(coord.accepted_this_cycle, 1, "accepted_this_cycle should be 1 after one SymbolAccepted");
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
    assert_eq!(coord.offered_this_cycle, 0, "offered_this_cycle should be 0 after persist");
    assert_eq!(coord.accepted_this_cycle, 0, "accepted_this_cycle should be 0 after persist");

    // DB must have a BudgetRecord with weekly_stats = [(10, 8)].
    let record = db.get_budget().unwrap().expect("BudgetRecord must exist after persist");
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

    assert_eq!(blob1, blob2, "same plaintext + epoch_key must produce identical blob");

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
    use syncback_core::erasure::RaptorQEncoder;
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
    };
    BackupCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()))
}

/// Insert a peer record with the given byte identity into the DB.
fn insert_peer(db: &Db, byte: u8) -> DeviceId {
    use syncback_core::types::{IdentityPub, PeerRecord, Timestamp};
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
    assert_eq!(candidates.len(), 3, "only 3 authenticated peers should be candidates");
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
    assert!(!candidates_first.iter().any(|c| c.device_id == peer_ids[3]),
        "peer D must not be in candidates when not authenticated");

    // Second snapshot: peer D comes online.
    let auth_second: HashSet<DeviceId> = peer_ids.iter().cloned().collect();
    let candidates_second = coord.get_candidates(&auth_second).unwrap();
    assert_eq!(candidates_second.len(), 4);
    assert!(candidates_second.iter().any(|c| c.device_id == peer_ids[3]),
        "peer D must appear in candidates after coming online");
}

// AC-8, AC-9, AC-10 (pending_delivery signaling tests) removed in ε.5.
// PendingDeliveries / OfferOutcome were iroh-era types; delivery now uses
// libp2p SwarmHandle request-response. Network integration is tested in
// swarm_tests.rs and the E2E test suite.

// ─── Wave 2 ATDD tests ────────────────────────────────────────────────────────
//
// AC1: raw symbols written to symbols/{hex}/raw/{esi}.bin — no flat {esi}.bin
// AC2: PipelineResult carries raw_symbols + esi_offset for inline binding at send time
// AC3: block.bin still written
// AC7: legacy cleanup removes flat {esi}.bin, preserves block.bin and raw/

/// S1 / AC1: when backup runs, only raw/ files are written — no flat {esi}.bin.
#[test]
fn encode_raw_writes_to_raw_subdir_not_flat() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    // Use .txt so it classifies as Document
    let content: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let path = write_file(&files_dir, "data.txt", &content);
    coord.process_event(added_event(&path)).unwrap();
    let results = coord.flush_all(true, &Default::default()).unwrap();
    assert_eq!(results.len(), 1, "should produce one source block");

    let block_hex: String = results[0].source_block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = symbols_dir.path().join(&block_hex);
    let raw_dir = block_dir.join("raw");

    // raw/ subdir must exist.
    assert!(raw_dir.exists(), "raw/ subdir must exist after backup");

    // No flat {esi}.bin files in block_dir (only block.bin and raw/).
    let flat_bin_files: Vec<_> = std::fs::read_dir(&block_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy().to_string();
            name.ends_with(".bin") && name != "block.bin"
        })
        .collect();
    assert!(
        flat_bin_files.is_empty(),
        "no flat {{esi}}.bin files should exist in block_dir after Wave 2, found: {:?}",
        flat_bin_files.iter().map(|e| e.path()).collect::<Vec<_>>()
    );

    // At least one raw symbol file must exist.
    let raw_files: Vec<_> = std::fs::read_dir(&raw_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(!raw_files.is_empty(), "raw/ must contain at least one symbol file");
}

/// S1 / AC5: block.bin is still written after Wave 2.
#[test]
fn block_bin_still_written_after_wave2() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    let content: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let path = write_file(&files_dir, "data2.txt", &content);
    coord.process_event(added_event(&path)).unwrap();
    let results = coord.flush_all(true, &Default::default()).unwrap();
    assert_eq!(results.len(), 1);

    let block_hex: String = results[0].source_block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_bin = symbols_dir.path().join(&block_hex).join("block.bin");
    assert!(block_bin.exists(), "block.bin must still be written after Wave 2");
    assert!(block_bin.metadata().unwrap().len() > 0, "block.bin must be non-empty");
}

/// AC2: PipelineResult contains raw_symbols with correct count and size.
#[test]
fn pipeline_result_contains_raw_symbols() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();
    let mut coord = test_coord(db.clone(), &symbols_dir);

    let content: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let path = write_file(&files_dir, "data3.txt", &content);
    coord.process_event(added_event(&path)).unwrap();
    let results = coord.flush_all(true, &Default::default()).unwrap();
    assert_eq!(results.len(), 1);

    let result = &results[0];
    // With mock_holders (5 holders), there should be raw symbols.
    assert!(
        !result.raw_symbols.is_empty(),
        "PipelineResult must contain raw_symbols when holders are present"
    );
    // All raw symbols must have size == params.t
    for sym in &result.raw_symbols {
        assert_eq!(
            sym.data.len(),
            result.t as usize,
            "raw symbol size must equal params.t"
        );
    }
}

/// S2 / AC2: apply_binding on pipeline raw symbol equals direct encode result.
#[test]
fn apply_binding_on_pipeline_raw_equals_direct_encode() {
    use crate::daemon::backup::pipeline::compress_and_encrypt;
    use syncback_core::erasure::RaptorQEncoder;
    use syncback_core::placement::{compute_allocation, HolderCandidate};
    use syncback_core::types::{ErasureParams, SourceBlockId};

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
    let bound_via_apply =
        encoder.apply_binding(raw.clone(), &block_id, &alloc.device_id);

    // Encode directly via the old path.
    let bound_direct = encoder
        .encode(&stored, &params, first_esi, 1, &block_id, &alloc.device_id)
        .unwrap();

    assert_eq!(
        bound_via_apply.data, bound_direct[0].data,
        "apply_binding on raw must equal direct encode"
    );
}

/// read_raw_symbols_for_block: reads correct ESI range.
#[test]
fn read_raw_symbols_for_block_reads_correct_esi_range() {
    use crate::daemon::backup::pipeline::read_raw_symbols_for_block;
    use syncback_core::types::{hex_encode, SourceBlockId};
    use syncback_core::erasure::Symbol;

    let symbols_dir = TempDir::new().unwrap();
    let block_id = SourceBlockId([0xAAu8; 32]);
    let block_hex = hex_encode(&block_id.0);
    let raw_dir = symbols_dir.path().join(&block_hex).join("raw");
    std::fs::create_dir_all(&raw_dir).unwrap();

    // Write 5 raw symbol files: ESI 0..4.
    for esi in 0u32..5 {
        std::fs::write(raw_dir.join(format!("{esi}.bin")), vec![esi as u8; 100]).unwrap();
    }

    let result = read_raw_symbols_for_block(
        symbols_dir.path(),
        &block_id,
        &[(0, 5)],
    ).unwrap();

    assert_eq!(result.len(), 5, "must return 5 symbols");
    for (i, sym) in result.iter().enumerate() {
        assert_eq!(sym.esi, i as u32, "ESI must match");
        assert_eq!(sym.data.len(), 100);
        assert_eq!(sym.data[0], i as u8);
    }
}

/// read_raw_symbols_for_block: missing file returns error.
#[test]
fn read_raw_symbols_for_block_missing_file_returns_error() {
    use crate::daemon::backup::pipeline::read_raw_symbols_for_block;
    use syncback_core::types::{hex_encode, SourceBlockId};

    let symbols_dir = TempDir::new().unwrap();
    let block_id = SourceBlockId([0xBBu8; 32]);
    let block_hex = hex_encode(&block_id.0);
    let raw_dir = symbols_dir.path().join(&block_hex).join("raw");
    std::fs::create_dir_all(&raw_dir).unwrap();

    // Write ESI 0,1,2,4 — ESI 3 missing.
    for esi in [0u32, 1, 2, 4] {
        std::fs::write(raw_dir.join(format!("{esi}.bin")), vec![esi as u8; 100]).unwrap();
    }

    // Reading 0..4 should fail on ESI=3.
    let result = read_raw_symbols_for_block(
        symbols_dir.path(),
        &block_id,
        &[(0, 5)],
    );
    assert!(result.is_err(), "must return Err when ESI file is missing");
}

/// S7/S8 / AC7: cleanup removes flat {esi}.bin files, preserves block.bin and raw/.
#[test]
fn cleanup_legacy_removes_flat_esi_bin_preserves_block_bin_and_raw_dir() {
    use crate::daemon::backup::pipeline::cleanup_legacy_bound_symbol_files;
    use syncback_core::types::{hex_encode, SourceBlockId};

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
    use syncback_core::types::{hex_encode, SourceBlockId};

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

    let results = coord.flush_queue(FileCategory::Document, true, &Default::default()).unwrap();
    assert!(!results.is_empty(), "should produce at least one source block");

    for result in &results {
        let placements = db.list_placements_for_block(&result.source_block_id).unwrap();
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
    use syncback_core::config::WatchConfig;
    use syncback_core::importance::burst::{apply_burst_downweight, burst_downweight_selects};

    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
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
    assert!(wc.bursts.is_some(), "bursts should be populated after populate_bursts()");

    // Manually inject a burst set containing img_0000.jpg to test the derive path.
    let target_path = media_dir.path().join("img_0000.jpg");
    let target_str = target_path.to_string_lossy().to_string();

    let selected = burst_downweight_selects(Path::new(&target_str));

    let mut manual_burst: HashSet<std::path::PathBuf> = HashSet::new();
    manual_burst.insert(target_path.clone());

    let mut wc_with_burst = wc.clone();
    wc_with_burst.bursts = Some(vec![manual_burst]);

    let importance_with_burst = syncback_core::config::derive_file_importance(
        &target_str,
        &[wc_with_burst.clone()],
    );

    let wc_without_burst = WatchConfig {
        bursts: Some(vec![]),
        ..wc_with_burst.clone()
    };
    let importance_without_burst =
        syncback_core::config::derive_file_importance(&target_str, &[wc_without_burst]);

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
