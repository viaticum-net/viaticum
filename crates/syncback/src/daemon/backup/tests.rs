// Tests for BackupCoordinator.
// All tests use real Db::open_in_memory(), real RaptorQEncoder, and tempfile::TempDir.
// Source block size is set small (128 KB) for fast tests.

use std::sync::{Arc, Mutex};

use syncback_core::cluster::{
    derive_master_key, issue_device_certificate, master_identity, ClusterState,
};
use syncback_core::db::Db;
use syncback_core::erasure::{ErasureEncoder, RaptorQEncoder};
use syncback_core::types::{
    DeviceId, ErasureParams, Event, FileCategory, FileId, FileRecord, FileVersion, LocalState,
    SourceBlockId, Timestamp,
};
use tempfile::TempDir;

use super::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};
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
        device_id: DeviceId([1u8; 16]),
        mock_holders: test_holders(),
        cluster_state: None,
        network: None,
        watch_configs: vec![],
        time_scale: 1,
    };
    BackupCoordinator::new(db, config, Arc::new(RaptorQEncoder::new()))
}

/// 5 mock holders with varying trust scores.
fn test_holders() -> Vec<syncback_core::placement::HolderCandidate> {
    (0..5)
        .map(|i| syncback_core::placement::HolderCandidate {
            identity: syncback_core::types::IdentityPub([(i + 1) as u8; 32]),
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
        device_id: DeviceId([1u8; 16]),
    }
}

fn modified_event(path: &str) -> DirtyEvent {
    DirtyEvent {
        path: path.to_string(),
        kind: DirtyKind::Modified,
        device_id: DeviceId([1u8; 16]),
    }
}

fn deleted_event(path: &str) -> DirtyEvent {
    DirtyEvent {
        path: path.to_string(),
        kind: DirtyKind::Deleted,
        device_id: DeviceId([1u8; 16]),
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
    let device_id = DeviceId([1u8; 16]);
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

    let results = coord.flush_queue(FileCategory::Document, false).unwrap();
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

    let results = coord.flush_queue(FileCategory::Document, true).unwrap();
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

    let results = coord.flush_queue(FileCategory::Document, false).unwrap();
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

    let results = coord.flush_queue(FileCategory::Document, true).unwrap();
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

    coord.flush_queue(FileCategory::Document, true).unwrap();

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
        device_id: DeviceId([1u8; 16]),
        mock_holders: test_holders(),
        cluster_state: None,
        network: None,
        watch_configs: vec![],
        time_scale: 1,
    };
    let encoder: Arc<dyn ErasureEncoder> = Arc::new(RaptorQEncoder::new());
    let mut coord = BackupCoordinator::new(db.clone(), config, encoder.clone());

    // Write a test file with recognizable content.
    let content = b"roundtrip test content ---";
    let repeated: Vec<u8> = content.iter().cycle().take(4096).cloned().collect();
    let path = write_file(&files_dir, "data.txt", &repeated);

    coord.process_event(added_event(&path)).unwrap();
    let results = coord.flush_queue(FileCategory::Document, true).unwrap();
    assert_eq!(results.len(), 1, "should produce one source block");

    let block_id = results[0].source_block_id;
    // stored_size is returned by PipelineResult -- use it to trim decoded block.
    let stored_size = results[0].stored_size as usize;
    let placements = db.list_placements_for_block(&block_id).unwrap();
    assert!(!placements.is_empty(), "should have placements");

    // Reconstruct ErasureParams using the actual stored_size.
    let params = ErasureParams::compute(stored_size as u64, 0.5);

    // Collect unbound symbols from all placements until we have k_eff.
    let mut unbound_symbols: Vec<syncback_core::erasure::Symbol> = Vec::new();
    let needed = params.k_eff as usize;

    'outer: for placement in &placements {
        let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
        let block_dir = symbols_dir.path().join(&block_hex);

        for (start_esi, count) in &placement.esi_ranges {
            for i in 0..*count {
                let esi = start_esi + i;
                let sym_path = block_dir.join(format!("{esi}.bin"));
                if !sym_path.exists() {
                    continue;
                }
                let data = std::fs::read(&sym_path).unwrap();
                let bound = syncback_core::erasure::Symbol { esi, data };
                let unbound = encoder.unbind(bound, &block_id, &placement.holder_id);
                unbound_symbols.push(unbound);

                if unbound_symbols.len() >= needed {
                    break 'outer;
                }
            }
        }
    }

    assert!(
        unbound_symbols.len() >= needed,
        "not enough symbols: have {}, need {}",
        unbound_symbols.len(),
        needed
    );

    // Decode: returns k*t zero-padded bytes.
    let decoded_padded = encoder.decode(&unbound_symbols, &params).unwrap();

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
    coord.flush_queue(FileCategory::Document, true).unwrap();

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
        devices: vec![(DeviceId([9u8; 16]), LocalState::Present)],
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
        devices: vec![(DeviceId([9u8; 16]), LocalState::Present)],
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
        devices: vec![(DeviceId([9u8; 16]), LocalState::Present)],
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
    let dev_id = DeviceId([99u8; 16]);
    let dev_key = syncback_core::cluster::derive_device_key(&seed, &dev_id).unwrap();
    let dev_pub = dev_key.verifying_key().to_bytes();
    let cert = issue_device_certificate(&master_key, dev_id, dev_pub, Timestamp(1));
    let cs = ClusterState::init(db.clone(), master_pub, cert, Timestamp(1), Timestamp(1)).unwrap();
    let cluster_state = Arc::new(Mutex::new(cs));
    let config = BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: [42u8; 32],
        device_id: DeviceId([1u8; 16]),
        mock_holders: test_holders(),
        cluster_state: Some(cluster_state),
        network: None,
        watch_configs: vec![],
        time_scale: 1,
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

// ─── Test 19: backup_config_default_network_is_none ──────────────────────────

#[test]
fn backup_config_default_network_is_none() {
    let cfg = BackupConfig::default();
    assert!(cfg.network.is_none(), "default config must have network=None");
}

// ─── Test 20: deliver_symbols_no_op_when_network_none ────────────────────────

#[tokio::test]
async fn deliver_symbols_no_op_when_network_none() {
    use super::PipelineResult;
    use syncback_core::types::IdentityPub;

    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let coordinator = BackupCoordinator::new(
        db,
        BackupConfig {
            symbols_dir: symbols_dir.path().to_path_buf(),
            network: None,
            ..BackupConfig::default()
        },
        Arc::new(RaptorQEncoder::new()),
    );

    coordinator.deliver_symbols(&[]).await;

    let fake_result = PipelineResult {
        source_block_id: SourceBlockId([0u8; 32]),
        k: 1,
        n: 2,
        symbol_count_per_holder: vec![(IdentityPub([0u8; 32]), 1)],
        stored_size: 0,
    };
    coordinator.deliver_symbols(&[fake_result]).await;
}

// ─── Test 21: deliver_symbols_logs_warn_on_peer_not_found ────────────────────

#[tokio::test]
async fn deliver_symbols_logs_warn_on_peer_not_found() {
    use std::collections::HashMap;

    use ed25519_dalek::SigningKey;
    use syncback_core::types::{IdentityPub, PlacementStatus, SymbolPlacement};

    use crate::daemon::network::{NetworkConfig, NetworkHandle};

    use super::PipelineResult;

    let sk_owner = SigningKey::from_bytes(&[10u8; 32]);
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let network = std::sync::Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: sk_owner.clone(),
                known_peers: HashMap::new(),
                device_cert: None,
                iroh_secret_key: None,
                relay_mode: iroh::RelayMode::Disabled,
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
        symbol_count_per_holder: vec![(unknown_holder, 1)],
        stored_size: 64,
    };

    coordinator.deliver_symbols(&[result]).await;

    Arc::try_unwrap(network).ok().map(|n| async move { n.shutdown().await });
}

// ─── Test 22: deliver_symbols_sends_to_reachable_holder ──────────────────────

#[tokio::test]
async fn deliver_symbols_sends_to_reachable_holder() {
    use std::collections::HashMap;

    use ed25519_dalek::SigningKey;
    use syncback_core::messages::Message;
    use syncback_core::types::{IdentityPub, PlacementStatus, SymbolPlacement};

    use crate::daemon::network::{NetworkConfig, NetworkHandle};

    use super::PipelineResult;

    let sk_owner = SigningKey::from_bytes(&[20u8; 32]);
    let sk_holder = SigningKey::from_bytes(&[21u8; 32]);
    let holder_identity = IdentityPub(sk_holder.verifying_key().to_bytes());

    let (tx_owner, _rx_owner) = tokio::sync::mpsc::channel(4);
    let (tx_holder, mut rx_holder) = tokio::sync::mpsc::channel(4);

    let network_holder = std::sync::Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: sk_holder,
                known_peers: HashMap::new(),
                device_cert: None,
                iroh_secret_key: None,
                relay_mode: iroh::RelayMode::Disabled,
            },
            tx_holder,
        )
        .await
        .unwrap(),
    );

    let holder_addr = network_holder.local_addr().unwrap();

    let mut known_peers = HashMap::new();
    known_peers.insert(holder_identity, holder_addr);

    let network_owner = std::sync::Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: sk_owner.clone(),
                known_peers,
                device_cert: None,
                iroh_secret_key: None,
                relay_mode: iroh::RelayMode::Disabled,
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
        holder_id: holder_identity,
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
        symbol_count_per_holder: vec![(holder_identity, 2)],
        stored_size: 128,
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
        device_id: DeviceId([1u8; 16]),
        mock_holders: test_holders(),
        cluster_state: None,
        network: None,
        watch_configs,
        time_scale: 1,
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
        importance: 0.9,
    }];
    let mut coord = coord_with_watch(db, &symbols_dir, watch_cfgs);

    let content = b"some document content here";
    let path = write_file(&files_dir, "report.txt", content);

    coord.process_event(added_event(&path)).unwrap();

    // File should be queued (it's small) with importance 0.9.
    let queued: Vec<_> = coord.queues.values().flat_map(|q| q.iter()).collect();
    assert_eq!(queued.len(), 1, "exactly one file should be queued");
    assert!(
        (queued[0].importance - 0.9).abs() < 1e-9,
        "importance should be 0.9 from watch config, got {}",
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
        importance: 0.9,
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
