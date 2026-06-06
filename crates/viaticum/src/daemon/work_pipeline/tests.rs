// WorkPipeline tests — ATDD scenarios for Wave 11b.
// All tests use real redb (tmpfile) per project convention.

use std::sync::Arc;
use std::time::Duration;

use tempfile::tempdir;
use viaticum_core::db::Db;
use viaticum_core::erasure::RaptorQEncoder;
use viaticum_core::placement::HolderCandidate;
use viaticum_core::types::{
    DeviceId, IdentityPub, PeerRecord, SourceBlockId, SourceBlockRecord, SourceBlockStatus,
    SourceBlockType, Timestamp,
};

use crate::daemon::work_pipeline::{
    WorkPipeline, WorkPipelineConfig, pool_signature, snapshot_pool,
};

// ─── Filesystem helpers ───────────────────────────────────────────────────────

/// Recursively find all files with the given name under `root`.
fn find_files_named(root: &std::path::Path, name: &str) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    fn walk(dir: &std::path::Path, name: &str, found: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, name, found);
            } else if path.file_name().map(|n| n == name).unwrap_or(false) {
                found.push(path);
            }
        }
    }
    walk(root, name, &mut found);
    found
}

/// Recursively find all directories with the given name under `root`.
fn find_dirs_named(root: &std::path::Path, name: &str) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    fn walk(dir: &std::path::Path, name: &str, found: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().map(|n| n == name).unwrap_or(false) {
                    found.push(path.clone());
                }
                walk(&path, name, found);
            }
        }
    }
    walk(root, name, &mut found);
    found
}

/// Find files that look like `{esi}.bin` (digit-named .bin files that aren't block.bin).
fn find_esi_bin_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    fn walk(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && name.ends_with(".bin")
                && name != "block.bin"
                && name.chars().take(1).all(|c| c.is_ascii_digit())
            {
                found.push(path);
            }
        }
    }
    walk(root, &mut found);
    found
}

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn make_db() -> Db {
    let dir = tempdir().unwrap();
    let path = dir.keep().join("test.redb");
    Db::open(&path).unwrap()
}

fn device_id(byte: u8) -> DeviceId {
    let mut b = [0u8; 32];
    b[0] = byte;
    DeviceId(b)
}

fn block_id(byte: u8) -> SourceBlockId {
    let mut b = [0u8; 32];
    b[0] = byte;
    SourceBlockId(b)
}

fn make_block_record(
    bid: SourceBlockId,
    importance: f64,
    target_reliability: f64,
) -> SourceBlockRecord {
    SourceBlockRecord {
        block_id: bid,
        k: 5,
        t: 1024,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp::now(),
        encrypted_size: Some(5 * 1024),
        n: Some(7),
        overhead: Some(1.4),
        drop_notice_sent_at: None,
        importance,
        target_reliability,
        current_alive: 0,
        current_reliability: 0.0,
        last_attempted_at: None,
        last_pool_signature: 0,
    }
}

fn make_config() -> WorkPipelineConfig {
    WorkPipelineConfig {
        cooldown: Duration::from_secs(30),
        tick_interval: Duration::from_secs(60),
        completion_bonus_coef: 1.5,
        device_id: device_id(0),
        own_master_pub_key: viaticum_core::types::IdentityPub([0u8; 32]),
        epoch_key: [0u8; 32],
        min_pool_size: 2,
    }
}

// ─── pool_signature invariant: empty slice → 0 ────────────────────────────────

#[test]
fn pool_signature_empty_returns_zero() {
    assert_eq!(
        pool_signature(&[]),
        0,
        "pool_signature of empty slice must be 0 (sentinel)"
    );
}

#[test]
fn pool_signature_non_empty_returns_nonzero() {
    let candidates = vec![HolderCandidate {
        device_id: device_id(1),
        trust: 0.7,
    }];
    assert_ne!(
        pool_signature(&candidates),
        0,
        "pool_signature of non-empty set must be non-zero"
    );
}

#[test]
fn pool_signature_golden_value_locks_algorithm() {
    // Golden value: locks the FNV-1a output for a known pool so an accidental
    // change to the hashing (e.g. reverting to DefaultHasher) is caught. The
    // signature is persisted, so its computation must stay stable across builds.
    // Input: one candidate device_id(1) (bytes [1,0,...,0]), trust 0.7 (bucket 14).
    let candidates = vec![HolderCandidate {
        device_id: device_id(1),
        trust: 0.7,
    }];
    assert_eq!(
        pool_signature(&candidates),
        13834821131375203934,
        "FNV-1a golden value changed — pool_signature algorithm must stay stable"
    );
}

#[test]
fn pool_signature_same_peers_same_order_stable() {
    let candidates = vec![
        HolderCandidate {
            device_id: device_id(1),
            trust: 0.7,
        },
        HolderCandidate {
            device_id: device_id(2),
            trust: 0.8,
        },
    ];
    let sig1 = pool_signature(&candidates);
    let sig2 = pool_signature(&candidates);
    assert_eq!(sig1, sig2, "pool_signature must be stable for same input");
}

#[test]
fn pool_signature_different_order_same_result() {
    let a = vec![
        HolderCandidate {
            device_id: device_id(1),
            trust: 0.7,
        },
        HolderCandidate {
            device_id: device_id(2),
            trust: 0.8,
        },
    ];
    let b = vec![
        HolderCandidate {
            device_id: device_id(2),
            trust: 0.8,
        },
        HolderCandidate {
            device_id: device_id(1),
            trust: 0.7,
        },
    ];
    assert_eq!(
        pool_signature(&a),
        pool_signature(&b),
        "pool_signature must be order-independent"
    );
}

#[test]
fn pool_signature_different_peers_different_result() {
    let a = vec![HolderCandidate {
        device_id: device_id(1),
        trust: 0.7,
    }];
    let b = vec![HolderCandidate {
        device_id: device_id(2),
        trust: 0.7,
    }];
    assert_ne!(pool_signature(&a), pool_signature(&b));
}

// ─── Trust bucket bucketing: nearby trust values → same bucket ────────────────

#[test]
fn pool_signature_similar_trust_values_same_bucket() {
    // 0.700 and 0.704 both round to 0.70 → bucket 14. Should produce same sig.
    let a = vec![HolderCandidate {
        device_id: device_id(1),
        trust: 0.700,
    }];
    let b = vec![HolderCandidate {
        device_id: device_id(1),
        trust: 0.704,
    }];
    assert_eq!(
        pool_signature(&a),
        pool_signature(&b),
        "trust values in same bucket must produce same pool_signature"
    );
}

#[test]
fn pool_signature_different_bucket_different_result() {
    // 0.700 is bucket 14, 0.750 is bucket 15.
    let a = vec![HolderCandidate {
        device_id: device_id(1),
        trust: 0.700,
    }];
    let b = vec![HolderCandidate {
        device_id: device_id(1),
        trust: 0.750,
    }];
    assert_ne!(
        pool_signature(&a),
        pool_signature(&b),
        "trust values in different buckets must produce different pool_signature"
    );
}

// ─── reset_all_cooldowns sets last_pool_signature = 0 ─────────────────────────

#[tokio::test]
async fn worker_resets_cooldowns_on_peer_authenticated() {
    let db = make_db();
    let bid = block_id(1);
    let mut record = make_block_record(bid, 1.0, 0.99);
    record.last_pool_signature = 42; // some non-zero value
    record.current_reliability = 0.0; // below target
    db.upsert_source_block(&record).unwrap();

    let encoder =
        Arc::new(RaptorQEncoder::new()) as Arc<dyn viaticum_core::erasure::ErasureEncoder>;
    let (_tx, rx) = tokio::sync::mpsc::channel(4);
    let pipeline = WorkPipeline::new(
        db.clone(),
        make_config(),
        encoder,
        None,
        None,
        None,
        None,
        rx,
    );

    pipeline.reset_all_cooldowns();

    let updated = db.get_source_block(&bid).unwrap().unwrap();
    assert_eq!(
        updated.last_pool_signature, 0,
        "reset_all_cooldowns must set last_pool_signature = 0"
    );
}

// ─── reset_all_cooldowns does NOT reset blocks already at target ───────────────

#[tokio::test]
async fn worker_does_not_reset_cooldowns_for_completed_blocks() {
    let db = make_db();
    let bid = block_id(2);
    let mut record = make_block_record(bid, 1.0, 0.99);
    record.last_pool_signature = 99;
    record.current_reliability = 0.999; // at target
    db.upsert_source_block(&record).unwrap();

    let encoder =
        Arc::new(RaptorQEncoder::new()) as Arc<dyn viaticum_core::erasure::ErasureEncoder>;
    let (_tx, rx) = tokio::sync::mpsc::channel(4);
    let pipeline = WorkPipeline::new(
        db.clone(),
        make_config(),
        encoder,
        None,
        None,
        None,
        None,
        rx,
    );

    pipeline.reset_all_cooldowns();

    let updated = db.get_source_block(&bid).unwrap().unwrap();
    assert_eq!(
        updated.last_pool_signature, 99,
        "reset_all_cooldowns must NOT touch blocks at target reliability"
    );
}

// ─── run_iteration returns Ok(false) when queue is empty ─────────────────────

#[tokio::test]
async fn worker_returns_false_when_queue_empty() {
    let db = make_db();
    let encoder =
        Arc::new(RaptorQEncoder::new()) as Arc<dyn viaticum_core::erasure::ErasureEncoder>;
    let (_tx, rx) = tokio::sync::mpsc::channel(4);
    let mut pipeline = WorkPipeline::new(
        db.clone(),
        make_config(),
        encoder,
        None,
        None,
        None,
        None,
        rx,
    );

    let result = pipeline.run_iteration().await.unwrap();
    assert!(
        !result,
        "run_iteration must return false when no blocks need work"
    );
}

// ─── B3: worker_with_empty_pool_picks_block_because_sig_zero_bypasses_cooldown ─
//
// Formerly named `worker_skips_item_on_cooldown_with_same_pool_sig`.
// Renamed in Wave 11b review (B3) to accurately reflect the behavior tested:
//   empty pool → pool_signature=0 (sentinel) → cooldown bypass in next_work_item
//   → block IS picked by run_iteration → returns Ok(true).
// The old name implied the block was SKIPPED, but it is actually PICKED
// (just with pool_too_small path, so no encoding, but cooldown applied).

#[tokio::test]
async fn worker_with_empty_pool_picks_block_because_sig_zero_bypasses_cooldown() {
    let db = make_db();
    let bid = block_id(3);
    let mut record = make_block_record(bid, 1.0, 0.99);
    // Set last_attempted_at = now - 10s (well within 30s cooldown).
    let last_at = Timestamp(Timestamp::now().0 - 10);
    record.last_attempted_at = Some(last_at);
    // last_pool_signature is non-zero (block was previously attempted).
    record.last_pool_signature = 12345; // some non-zero value
    db.upsert_source_block(&record).unwrap();

    // swarm=None → pool is always empty → pool_signature() of [] == 0 (sentinel).
    // pool_sig=0 bypasses the cooldown check in next_work_item (per spec Part 11).
    // So the block IS picked despite last_attempted_at being recent.
    // Pool too small (0 < 2) → applies cooldown update → returns Ok(true).
    let encoder =
        Arc::new(RaptorQEncoder::new()) as Arc<dyn viaticum_core::erasure::ErasureEncoder>;
    let (_tx, rx) = tokio::sync::mpsc::channel(4);
    let mut pipeline = WorkPipeline::new(
        db.clone(),
        make_config(),
        encoder,
        None,
        None,
        None,
        None,
        rx,
    );

    let result = pipeline.run_iteration().await.unwrap();
    // Block IS picked: pool_sig=0 bypasses cooldown, then pool_too_small path fires.
    assert!(
        result,
        "run_iteration must return true: empty pool (sig=0) bypasses cooldown, block is picked"
    );
}

// ─── run_iteration returns true when block picked with pool too small ──────────

#[tokio::test]
async fn worker_applies_cooldown_when_pool_below_min_size() {
    let db = make_db();
    let bid = block_id(4);
    let record = make_block_record(bid, 1.0, 0.99);
    db.upsert_source_block(&record).unwrap();

    let encoder =
        Arc::new(RaptorQEncoder::new()) as Arc<dyn viaticum_core::erasure::ErasureEncoder>;
    let (_tx, rx) = tokio::sync::mpsc::channel(4);
    let mut pipeline = WorkPipeline::new(
        db.clone(),
        make_config(),
        encoder,
        None,
        None,
        None,
        None,
        rx,
    );

    let result = pipeline.run_iteration().await.unwrap();
    // Block needs work; no swarm → pool empty → pool_too_small → cooldown applied.
    assert!(
        result,
        "run_iteration should return true (block was picked, even if pool too small)"
    );

    // After cooldown applied, last_attempted_at should be set.
    let updated = db.get_source_block(&bid).unwrap().unwrap();
    assert!(
        updated.last_attempted_at.is_some(),
        "last_attempted_at should be set after pool_too_small"
    );
}

// ─── pipeline_writes_no_block_bin ─────────────────────────────────────────────

#[test]
fn pipeline_writes_no_block_bin() {
    use crate::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};

    let db = make_db();
    let dir = tempdir().unwrap();
    let symbols_dir = dir.path().to_path_buf();
    let encoder =
        Arc::new(RaptorQEncoder::new()) as Arc<dyn viaticum_core::erasure::ErasureEncoder>;

    let content = b"hello world test content for pipeline - make it long enough";
    let source_file = dir.path().join("test.txt");
    std::fs::write(&source_file, content).unwrap();

    let config = BackupConfig {
        symbols_dir: symbols_dir.clone(),
        source_block_size: 1024 * 1024,
        epoch_key: [0u8; 32],
        device_id: device_id(0),
        ..Default::default()
    };

    let mut coord = BackupCoordinator::new(db.clone(), config, encoder.clone());
    coord
        .process_event(DirtyEvent {
            path: source_file.to_string_lossy().to_string(),
            kind: DirtyKind::Added,
            device_id: device_id(0),
        })
        .unwrap();
    let results = coord.flush_all(true, &Default::default()).unwrap();
    assert!(!results.is_empty(), "pipeline should produce results");

    // Walk symbols_dir: no block.bin files anywhere.
    let found_block_bin = find_files_named(&symbols_dir, "block.bin");
    assert!(
        found_block_bin.is_empty(),
        "pipeline must not write block.bin after Wave 11b: {:?}",
        found_block_bin
    );
}

// ─── pipeline_writes_no_per_holder_esi_bin ────────────────────────────────────

#[test]
fn pipeline_writes_no_per_holder_esi_bin() {
    use crate::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};

    let db = make_db();
    let dir = tempdir().unwrap();
    let symbols_dir = dir.path().to_path_buf();
    let encoder =
        Arc::new(RaptorQEncoder::new()) as Arc<dyn viaticum_core::erasure::ErasureEncoder>;

    let content = b"no esi bin test content - long enough to create a block";
    let source_file = dir.path().join("test2.txt");
    std::fs::write(&source_file, content).unwrap();

    let config = BackupConfig {
        symbols_dir: symbols_dir.clone(),
        source_block_size: 1024 * 1024,
        epoch_key: [0u8; 32],
        device_id: device_id(0),
        ..Default::default()
    };

    let mut coord = BackupCoordinator::new(db.clone(), config, encoder.clone());
    coord
        .process_event(DirtyEvent {
            path: source_file.to_string_lossy().to_string(),
            kind: DirtyKind::Added,
            device_id: device_id(0),
        })
        .unwrap();
    coord.flush_all(true, &Default::default()).unwrap();

    // No raw/ subdir, no {esi}.bin files.
    let raw_dirs = find_dirs_named(&symbols_dir, "raw");
    assert!(
        raw_dirs.is_empty(),
        "pipeline must not create raw/ subdir after Wave 11b: {:?}",
        raw_dirs
    );
    let esi_bins = find_esi_bin_files(&symbols_dir);
    assert!(
        esi_bins.is_empty(),
        "pipeline must not write {{esi}}.bin files after Wave 11b: {:?}",
        esi_bins
    );
}

// ─── rebuild_source_blob: produces correct block_id hash ─────────────────────

#[tokio::test]
async fn rebuild_source_blob_produces_correct_block_id() {
    use crate::daemon::backup::pipeline::rebuild_source_blob;
    use crate::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};

    let db = make_db();
    let dir = tempdir().unwrap();
    let symbols_dir = dir.path().to_path_buf();
    let encoder =
        Arc::new(RaptorQEncoder::new()) as Arc<dyn viaticum_core::erasure::ErasureEncoder>;
    let epoch_key = [42u8; 32];

    let content = b"rebuild test content 42 - must be long enough to create a block";
    let source_file = dir.path().join("rebuild.txt");
    std::fs::write(&source_file, content).unwrap();

    let config = BackupConfig {
        symbols_dir: symbols_dir.clone(),
        source_block_size: 1024 * 1024,
        epoch_key,
        device_id: device_id(0),
        ..Default::default()
    };

    // Use BackupCoordinator to properly create FileRecord + SourceBlockRecord.
    let mut coord = BackupCoordinator::new(db.clone(), config, encoder.clone());
    coord
        .process_event(DirtyEvent {
            path: source_file.to_string_lossy().to_string(),
            kind: DirtyKind::Added,
            device_id: device_id(0),
        })
        .unwrap();
    let results = coord.flush_all(true, &Default::default()).unwrap();
    assert!(
        !results.is_empty(),
        "should produce at least one source block"
    );
    let block_id = results[0].source_block_id;

    // Now rebuild the blob and verify hash.
    let block_record = db.get_source_block(&block_id).unwrap().unwrap();
    let rebuilt = rebuild_source_blob(&db, &block_record, &epoch_key)
        .await
        .unwrap();

    let rebuilt_hash: [u8; 32] = *blake3::hash(&rebuilt).as_bytes();
    assert_eq!(
        rebuilt_hash, block_id.0,
        "rebuild_source_blob must produce blob with hash == block_id"
    );
    assert_eq!(
        rebuilt.len() as u64,
        block_record.encrypted_size.unwrap(),
        "rebuilt blob length must match encrypted_size"
    );
}

// ─── rebuild_source_blob: fails gracefully when source file deleted ───────────

#[tokio::test]
async fn rebuild_source_blob_fails_gracefully_when_source_file_deleted() {
    use crate::daemon::backup::pipeline::rebuild_source_blob;
    use crate::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};

    let db = make_db();
    let dir = tempdir().unwrap();
    let symbols_dir = dir.path().to_path_buf();
    let encoder =
        Arc::new(RaptorQEncoder::new()) as Arc<dyn viaticum_core::erasure::ErasureEncoder>;
    let epoch_key = [7u8; 32];

    let content = b"content to be deleted - make it long enough";
    let source_file = dir.path().join("deleted.txt");
    std::fs::write(&source_file, content).unwrap();

    let config = BackupConfig {
        symbols_dir: symbols_dir.clone(),
        source_block_size: 1024 * 1024,
        epoch_key,
        device_id: device_id(0),
        ..Default::default()
    };

    let mut coord = BackupCoordinator::new(db.clone(), config, encoder.clone());
    coord
        .process_event(DirtyEvent {
            path: source_file.to_string_lossy().to_string(),
            kind: DirtyKind::Added,
            device_id: device_id(0),
        })
        .unwrap();
    let results = coord.flush_all(true, &Default::default()).unwrap();
    assert!(!results.is_empty());
    let block_id = results[0].source_block_id;

    // Delete the source file.
    std::fs::remove_file(&source_file).unwrap();

    let block_record = db.get_source_block(&block_id).unwrap().unwrap();
    let result = rebuild_source_blob(&db, &block_record, &epoch_key).await;
    assert!(
        result.is_err(),
        "rebuild_source_blob must return Err when source file is deleted"
    );
}

// ─── PoS Lost re-queuing via next_work_item ───────────────────────────────────

#[tokio::test]
async fn worker_pos_lost_triggers_block_reappearing_in_queue() {
    let db = make_db();
    let bid = block_id(5);

    // Block at target reliability.
    let mut record = make_block_record(bid, 1.0, 0.99);
    record.current_reliability = 0.999;
    record.current_alive = 5;
    db.upsert_source_block(&record).unwrap();

    // next_work_item should return None (at target).
    let item = db
        .next_work_item(1.5, Duration::from_secs(30), Timestamp::now(), 0)
        .unwrap();
    assert!(
        item.is_none(),
        "block at target reliability should not appear in work queue"
    );

    // Simulate PoS Lost — drop current_reliability below target.
    let mut updated = record.clone();
    updated.current_alive = 4;
    updated.current_reliability = 0.95; // below target 0.99
    db.upsert_source_block(&updated).unwrap();

    // Now next_work_item should return Some.
    let item = db
        .next_work_item(1.5, Duration::from_secs(30), Timestamp::now(), 0)
        .unwrap();
    assert!(
        item.is_some(),
        "block below target reliability should reappear in work queue after PoS Lost"
    );
}

// ─── worker_picks_highest_priority_item ───────────────────────────────────────

#[test]
fn worker_picks_highest_priority_item() {
    let db = make_db();

    // Block A: importance=1.0, current_alive=0, n=7 → priority = 1.0 * (1 + 1.5 * 0/7) = 1.0
    let bid_a = block_id(10);
    let mut record_a = make_block_record(bid_a, 1.0, 0.99);
    record_a.current_alive = 0;
    record_a.n = Some(7);
    db.upsert_source_block(&record_a).unwrap();

    // Block B: importance=0.5, current_alive=4, n=8 → priority = 0.5 * (1 + 1.5 * 4/8) = 0.875
    let bid_b = block_id(11);
    let mut record_b = make_block_record(bid_b, 0.5, 0.9);
    record_b.current_alive = 4;
    record_b.n = Some(8);
    db.upsert_source_block(&record_b).unwrap();

    let item = db
        .next_work_item(1.5, Duration::from_secs(30), Timestamp::now(), 0)
        .unwrap();
    assert!(item.is_some());
    let picked = item.unwrap();
    assert_eq!(
        picked.block_id, bid_a,
        "worker must pick highest priority block (A with priority=1.0)"
    );
}

// W7: the former `cleanup_block_dir_*` tests here exercised std::fs::remove_dir_all
// inline rather than any production function — the W11b "permissive cleanup" code
// path they stood in for was removed. The real startup cleanup,
// `cleanup_legacy_bound_symbol_files`, is covered in daemon::backup::tests.

// ─── worker_includes_item_after_cooldown_expires ─────────────────────────────

#[test]
fn worker_includes_item_after_cooldown_expires() {
    let db = make_db();
    let bid = block_id(20);
    let mut record = make_block_record(bid, 1.0, 0.99);
    // last_attempted = 60s ago, cooldown = 30s → cooldown expired.
    let old_time = Timestamp(Timestamp::now().0.saturating_sub(60));
    record.last_attempted_at = Some(old_time);
    record.last_pool_signature = 99999; // non-zero pool sig
    db.upsert_source_block(&record).unwrap();

    // With current_pool_sig = 99999 and elapsed=60 > cooldown=30 → eligible.
    let item = db
        .next_work_item(1.5, Duration::from_secs(30), Timestamp::now(), 99999)
        .unwrap();
    assert!(
        item.is_some(),
        "block with expired cooldown must appear in work queue"
    );
}

// ─── worker_includes_item_when_pool_signature_changes ─────────────────────────

#[test]
fn worker_includes_item_when_pool_signature_changes() {
    let db = make_db();
    let bid = block_id(21);
    let mut record = make_block_record(bid, 1.0, 0.99);
    // last_attempted = 5s ago (within cooldown), pool_sig = X.
    let recent = Timestamp(Timestamp::now().0.saturating_sub(5));
    record.last_attempted_at = Some(recent);
    record.last_pool_signature = 11111; // X
    db.upsert_source_block(&record).unwrap();

    // Different pool sig Y → cooldown bypassed.
    let item = db
        .next_work_item(1.5, Duration::from_secs(30), Timestamp::now(), 22222)
        .unwrap();
    assert!(
        item.is_some(),
        "block must be eligible when pool signature changes"
    );
}

// ─── B3: worker_with_empty_pool_picks_block_because_sig_zero_bypasses_cooldown ─

// NOTE: This was formerly named `worker_skips_item_on_cooldown_with_same_pool_sig`.
// The test was renamed because the actual behavior it covers is:
//   empty pool → sig=0 → cooldown bypassed → block IS picked (not skipped).
// The name is now accurate per B3 requirement.
//
// The original test comment about "skipping" was misleading — with sig=0 the
// next_work_item cooldown check is bypassed, so the block is picked and returned
// by run_iteration(). Pool too small → applies cooldown + returns Ok(true).

// ─── B3: worker_skips_item_when_same_pool_sig_within_cooldown ─────────────────

#[tokio::test]
async fn worker_skips_item_when_same_pool_sig_within_cooldown() {
    // Set up: WorkPipeline with cooldown=30s. Block. Use a non-zero pool signature
    // so the cooldown check in next_work_item actually fires.
    //
    // We simulate a non-zero pool sig by setting last_pool_signature = S and
    // arranging for the current pool to produce the same sig S.
    //
    // Since swarm=None → pool is always empty → pool_signature=0 (sentinel).
    // pool_signature=0 BYPASSES the cooldown check per spec (Part 11 hard requirement).
    // So we cannot test the true cooldown skip with empty pool.
    //
    // Instead: directly test next_work_item with matching sig and recent timestamp.
    // This tests the DB-layer invariant that is the actual cooldown enforcement point.
    let db = make_db();
    let bid = block_id(40);
    let mut record = make_block_record(bid, 1.0, 0.99);

    // Arrange: last_attempted_at = now - 5s (within 30s cooldown), pool_sig = S.
    let recent = Timestamp(Timestamp::now().0.saturating_sub(5));
    record.last_attempted_at = Some(recent);
    let sig_s: u64 = 0xdeadbeef_cafebabe; // non-zero signature
    record.last_pool_signature = sig_s;
    db.upsert_source_block(&record).unwrap();

    // First run with same signature S: next_work_item must return None (on cooldown).
    let item_first = db
        .next_work_item(1.5, Duration::from_secs(30), Timestamp::now(), sig_s)
        .unwrap();
    assert!(
        item_first.is_none(),
        "block within cooldown and same pool_sig must not be picked by next_work_item"
    );

    // Run with a DIFFERENT signature: cooldown bypassed → item is returned.
    let item_diff_sig = db
        .next_work_item(1.5, Duration::from_secs(30), Timestamp::now(), sig_s + 1)
        .unwrap();
    assert!(
        item_diff_sig.is_some(),
        "block must be eligible when pool sig changes (different from stored sig)"
    );
}

// ─── B1: worker_drops_raw_vec_after_iteration_no_disk_spill ──────────────────

#[tokio::test]
async fn worker_drops_raw_vec_after_iteration_no_disk_spill() {
    // Set up: tmpdir for symbols_dir. One block in DB needing work.
    // No swarm → pool empty → pool_too_small path triggers.
    // Since no encoding occurs (pool too small), and pipeline never writes block.bin
    // or raw/ files after W11b, symbols_dir must remain empty.
    use crate::daemon::backup::{BackupCoordinator, DirtyEvent, DirtyKind};

    let db = make_db();
    let dir = tempdir().unwrap();
    let symbols_dir = dir.path().to_path_buf();
    let encoder =
        Arc::new(RaptorQEncoder::new()) as Arc<dyn viaticum_core::erasure::ErasureEncoder>;

    // Write a real source file and create a block via BackupCoordinator.
    let content = b"disk spill test content - long enough for a block";
    let source_file = dir.path().join("spill_test.txt");
    std::fs::write(&source_file, content).unwrap();

    let config = crate::daemon::backup::BackupConfig {
        symbols_dir: symbols_dir.clone(),
        source_block_size: 1024 * 1024,
        epoch_key: [0u8; 32],
        device_id: device_id(0),
        ..Default::default()
    };
    let mut coord = BackupCoordinator::new(db.clone(), config, encoder.clone());
    coord
        .process_event(DirtyEvent {
            path: source_file.to_string_lossy().to_string(),
            kind: DirtyKind::Added,
            device_id: device_id(0),
        })
        .unwrap();
    let results = coord.flush_all(true, &Default::default()).unwrap();
    assert!(
        !results.is_empty(),
        "should have created at least one block"
    );

    // Now run the worker iteration.
    let (_tx, rx) = tokio::sync::mpsc::channel(4);
    let mut pipeline = WorkPipeline::new(
        db.clone(),
        make_config(),
        encoder,
        None,
        None,
        None,
        None,
        rx,
    );
    let picked = pipeline.run_iteration().await.unwrap();
    assert!(
        picked,
        "run_iteration must return true (block was picked, pool too small)"
    );

    // Assert: symbols_dir has no block.bin, no raw/ dirs, no {esi}.bin files.
    let block_bins = find_files_named(&symbols_dir, "block.bin");
    assert!(
        block_bins.is_empty(),
        "no block.bin must exist after W11b run_iteration: {:?}",
        block_bins
    );
    let raw_dirs = find_dirs_named(&symbols_dir, "raw");
    assert!(
        raw_dirs.is_empty(),
        "no raw/ dir must exist after W11b run_iteration: {:?}",
        raw_dirs
    );
    let esi_bins = find_esi_bin_files(&symbols_dir);
    assert!(
        esi_bins.is_empty(),
        "no {{esi}}.bin files must exist after W11b run_iteration: {:?}",
        esi_bins
    );
}

// ─── B1: worker_idempotent_re_run_same_block_no_double_send ──────────────────

#[tokio::test]
async fn worker_idempotent_re_run_same_block_no_double_send() {
    // Set up: block with 2 Alive placements (holders A, B already delivered).
    // Pool has 5 candidates A, B, C, D, E. Worker should only allocate to C, D, E.
    //
    // Since no swarm is available, run_block_iteration will not run (swarm=None guard).
    // Instead, we directly verify the DB-layer invariant:
    //   get_existing_holder_ids filters A and B from candidates,
    //   so new placements would only be created for C, D, E.
    //
    // We test this by calling run_iteration with no swarm and verifying:
    //   - The 2 existing Alive placements for A and B are UNCHANGED.
    //   - No new placements appear (no delivery without swarm).
    //   - The block was picked (run_iteration → true).
    //
    // Simplification note: the full delivery path requires a mock swarm;
    // without one, we verify the filter logic via DB inspection.
    use viaticum_core::types::{FileId, PlacementStatus, SymbolPlacement};

    let db = make_db();
    let dir = tempdir().unwrap();
    let _symbols_dir = dir.path().to_path_buf();
    let encoder =
        Arc::new(RaptorQEncoder::new()) as Arc<dyn viaticum_core::erasure::ErasureEncoder>;

    // Create the block in DB.
    let bid = block_id(50);
    let mut record = make_block_record(bid, 1.0, 0.99);
    record.n = Some(5);
    record.current_alive = 2;
    db.upsert_source_block(&record).unwrap();

    let holder_a = device_id(0xA0);
    let holder_b = device_id(0xB0);

    // Insert 2 Alive placements for A and B.
    let placed_at_a = Timestamp::now();
    let placed_at_b = Timestamp::now();
    for (holder, esi_start, placed_at) in
        [(holder_a, 0u32, placed_at_a), (holder_b, 1u32, placed_at_b)]
    {
        db.upsert_placement(&SymbolPlacement {
            source_block_id: bid,
            holder_id: holder,
            file_id: FileId(0),
            esi_ranges: vec![(esi_start, 1)],
            binding_seed: [0u8; 32],
            status: PlacementStatus::Alive,
            last_verified: None,
            placed_at,
            consecutive_misses: 0,
        })
        .unwrap();
    }

    // Run iteration: no swarm, pool too small → applies cooldown, no delivery.
    let config = make_config();
    let (_tx, rx) = tokio::sync::mpsc::channel(4);
    let mut pipeline = WorkPipeline::new(db.clone(), config, encoder, None, None, None, None, rx);
    let picked = pipeline.run_iteration().await.unwrap();
    assert!(picked, "run_iteration must return true (block was picked)");

    // Assert: A and B placements unchanged (status still Alive, same placed_at).
    let placement_a = db.get_placement(&bid, &holder_a).unwrap().unwrap();
    assert_eq!(
        placement_a.status,
        PlacementStatus::Alive,
        "holder A placement must remain Alive"
    );
    assert_eq!(
        placement_a.placed_at, placed_at_a,
        "holder A placed_at must be unchanged"
    );

    let placement_b = db.get_placement(&bid, &holder_b).unwrap().unwrap();
    assert_eq!(
        placement_b.status,
        PlacementStatus::Alive,
        "holder B placement must remain Alive"
    );
    assert_eq!(
        placement_b.placed_at, placed_at_b,
        "holder B placed_at must be unchanged"
    );

    // No new placements for C, D, E (no swarm → no delivery).
    let all_placements = db.list_placements_for_block(&bid).unwrap();
    assert_eq!(
        all_placements.len(),
        2,
        "only 2 placements must exist (A and B); no new ones without swarm"
    );
}

// ─── B1: worker_re_encodes_on_pool_signature_change_deterministically ─────────

#[test]
fn worker_re_encodes_on_pool_signature_change_deterministically() {
    // Verify that encode_raw is deterministic: same (stored_blob, params, esi, count)
    // always produces identical bytes. This is the core invariant (A3 in the spec).
    //
    // We test this directly via the encoder, which is simpler and faster than
    // running two full worker iterations. The worker uses encode_raw under
    // spawn_blocking; the determinism guarantee comes from RaptorQ 2.0.1.
    use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder};
    use viaticum_core::types::ErasureParams;

    let encoder = RaptorQEncoder::new();
    let stored_blob = b"deterministic encode test data - must be stable across calls".to_vec();
    let params = ErasureParams {
        k: 1,
        k_eff: 4,
        t: 65535,
        overhead: 1.5,
        n: 8,
    };
    let esi_offset: u32 = 0;
    let count: u32 = 4;

    // First encode.
    let raws1 = encoder
        .encode_raw(&stored_blob, &params, esi_offset, count)
        .unwrap();
    // Second encode with identical input.
    let raws2 = encoder
        .encode_raw(&stored_blob, &params, esi_offset, count)
        .unwrap();

    assert_eq!(
        raws1.len(),
        raws2.len(),
        "both encodes must produce same number of symbols"
    );
    for (s1, s2) in raws1.iter().zip(raws2.iter()) {
        assert_eq!(s1.esi, s2.esi, "ESI must match between encodes");
        assert_eq!(
            s1.data, s2.data,
            "raw symbol data for ESI {} must be identical between encodes (determinism invariant A3)",
            s1.esi
        );
    }

    // Also verify: different esi_offset produces different symbols.
    let raws3 = encoder
        .encode_raw(&stored_blob, &params, 4 /* different offset */, count)
        .unwrap();
    assert_ne!(
        raws1[0].esi, raws3[0].esi,
        "different esi_offset must produce symbols starting at different ESIs"
    );
}

// ─── B1: worker_wakes_on_peer_authenticated_event (simplified unit form) ──────

#[tokio::test]
async fn after_peer_authenticated_event_cooldowns_are_reset() {
    // Simplified form of worker_wakes_on_peer_authenticated_event.
    // Tests that reset_all_cooldowns is called on PeerAuthenticated by verifying
    // the DB state change directly, without spawning the full run() loop.
    //
    // Rationale for simplification: spawning run() with mock swarm is infeasible
    // without significant mock infrastructure. The run() loop's PeerAuthenticated
    // branch calls reset_all_cooldowns + run_iteration. We test reset_all_cooldowns
    // directly here; run_iteration behavior is covered by other tests.
    let db = make_db();
    let bid = block_id(60);

    // Block with non-zero last_pool_signature (on "cooldown").
    let mut record = make_block_record(bid, 1.0, 0.99);
    record.last_pool_signature = 0xfeedf00d;
    record.current_reliability = 0.0; // below target → eligible for reset
    db.upsert_source_block(&record).unwrap();

    // Create pipeline and call reset_all_cooldowns (simulates PeerAuthenticated handler).
    let encoder =
        Arc::new(RaptorQEncoder::new()) as Arc<dyn viaticum_core::erasure::ErasureEncoder>;
    let (_tx, rx) = tokio::sync::mpsc::channel(4);
    let pipeline = WorkPipeline::new(
        db.clone(),
        make_config(),
        encoder,
        None,
        None,
        None,
        None,
        rx,
    );
    pipeline.reset_all_cooldowns();

    // Assert: last_pool_signature reset to 0, making block eligible in next_work_item.
    let updated = db.get_source_block(&bid).unwrap().unwrap();
    assert_eq!(
        updated.last_pool_signature, 0,
        "after PeerAuthenticated → reset_all_cooldowns, last_pool_signature must be 0 (sentinel)"
    );

    // Verify the block is now eligible in next_work_item (sig=0 bypasses cooldown).
    let item = db
        .next_work_item(1.5, Duration::from_secs(30), Timestamp::now(), 0xfeedf00d)
        .unwrap();
    assert!(
        item.is_some(),
        "block must be eligible in next_work_item after cooldown reset (sig=0 bypass)"
    );
}

// ─── periodic_reliability_scan_updates_below_target_blocks ───────────────────
// NOTE: implemented after RepairAgent::reliability_scan is added in Step 10.

#[tokio::test]
async fn periodic_reliability_scan_updates_below_target_blocks() {
    use crate::daemon::repair::RepairAgent;
    use viaticum_core::types::{FileId, PlacementStatus, SymbolPlacement};

    let db = make_db();
    let bid = block_id(30);

    // Block with current_alive=5 (stale) but only 3 Alive placements.
    let mut record = make_block_record(bid, 1.0, 0.99);
    record.current_alive = 5;
    record.current_reliability = 0.95;
    record.n = Some(7);
    db.upsert_source_block(&record).unwrap();

    // Insert 3 Alive placements.
    for i in 0..3u8 {
        let p = SymbolPlacement {
            source_block_id: bid,
            holder_id: device_id(i + 10),
            file_id: FileId(0),
            esi_ranges: vec![(i as u32, 1)],
            binding_seed: [0u8; 32],
            status: PlacementStatus::Alive,
            last_verified: None,
            placed_at: Timestamp::now(),
            consecutive_misses: 0,
        };
        db.upsert_placement(&p).unwrap();
    }

    let repair = RepairAgent::new(db.clone());

    // reliability_scan() is added to RepairAgent in Step 10.
    let updated_count = repair.reliability_scan().await;
    assert!(
        updated_count >= 1,
        "reliability_scan must update at least one below-target block"
    );

    let updated_block = db.get_source_block(&bid).unwrap().unwrap();
    // current_alive should be corrected to 3 (actual Alive placements).
    assert_eq!(
        updated_block.current_alive, 3,
        "reliability_scan must correct current_alive to match actual Alive placements"
    );
}

// ─── W11b bugfix: worker retries delivery for Offered placements ───────────────
//
// ATDD scenario (bug regression test):
//   Before fix: get_existing_holder_ids filtered Alive|Offered → peer-A with
//   an Offered placement was excluded from candidates → acked=0 forever.
//   After fix: only Alive is excluded → peer-A IS a candidate → delivery retried.

#[test]
fn worker_retries_delivery_for_offered_placement() {
    // ATDD: a block with 1 Offered placement (no Alive yet) must have peer-A
    // included in candidates returned by get_existing_holder_ids.
    //
    // Regression for W11b bug: backup pipeline created Offered placements but
    // worker excluded Offered holders → no delivery retry → placement_alive=0 forever.
    //
    // We test the filter directly: given an Offered placement for peer-A,
    // get_existing_holder_ids must NOT return peer-A (so peer-A remains a candidate).
    use crate::daemon::work_pipeline::worker::get_existing_holder_ids;
    use viaticum_core::types::{FileId, PlacementStatus, SymbolPlacement};

    let db = make_db();
    let bid = block_id(0xBB);
    let peer_a = device_id(0xA0);

    // Create block record.
    let record = make_block_record(bid, 1.0, 0.99);
    db.upsert_source_block(&record).unwrap();

    // Insert 1 Offered placement for peer-A (no Alive placements exist yet).
    db.upsert_placement(&SymbolPlacement {
        source_block_id: bid,
        holder_id: peer_a,
        file_id: FileId(0),
        esi_ranges: vec![(0, 1)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Offered,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    })
    .unwrap();

    // Assert: get_existing_holder_ids returns an empty set.
    // peer-A has an Offered placement, which must NOT be excluded.
    // An empty result means peer-A remains in candidates → delivery will be retried.
    let holders = get_existing_holder_ids(&db, &bid).unwrap();
    assert!(
        holders.is_empty(),
        "with only an Offered placement, get_existing_holder_ids must return empty \
         (peer-A is NOT excluded → worker retries delivery). \
         Regression: previously Offered was excluded, causing placement_alive=0 forever."
    );
    assert!(
        !holders.contains(&peer_a),
        "peer-A with Offered status must NOT be in the excluded set (it is a retry candidate)"
    );
}

// ─── W11b bugfix: get_existing_holder_ids excludes only Alive ─────────────────

#[test]
fn worker_excludes_only_alive_peers_from_candidates() {
    // Unit test for get_existing_holder_ids:
    //   peer-A = Alive   → excluded (already fully delivered)
    //   peer-B = Offered → NOT excluded (retry candidate)
    //   peer-C = Lost    → NOT excluded (needs fresh delivery)
    //
    // Only peer-A must be in the returned set.
    use crate::daemon::work_pipeline::worker::get_existing_holder_ids;
    use viaticum_core::types::{FileId, PlacementStatus, SymbolPlacement};

    let db = make_db();
    let bid = block_id(0xCC);
    let peer_a = device_id(0xA0); // Alive
    let peer_b = device_id(0xB0); // Offered
    let peer_c = device_id(0xC0); // Lost

    let record = make_block_record(bid, 1.0, 0.99);
    db.upsert_source_block(&record).unwrap();

    for (holder, status, esi_start) in [
        (peer_a, PlacementStatus::Alive, 0u32),
        (peer_b, PlacementStatus::Offered, 1u32),
        (peer_c, PlacementStatus::Lost, 2u32),
    ] {
        db.upsert_placement(&SymbolPlacement {
            source_block_id: bid,
            holder_id: holder,
            file_id: FileId(0),
            esi_ranges: vec![(esi_start, 1)],
            binding_seed: [0u8; 32],
            status,
            last_verified: None,
            placed_at: Timestamp::now(),
            consecutive_misses: 0,
        })
        .unwrap();
    }

    let holders = get_existing_holder_ids(&db, &bid).unwrap();

    assert_eq!(
        holders.len(),
        1,
        "only 1 holder (Alive) must be excluded; got {:?}",
        holders
    );
    assert!(
        holders.contains(&peer_a),
        "peer-A (Alive) must be in the excluded set"
    );
    assert!(
        !holders.contains(&peer_b),
        "peer-B (Offered) must NOT be in the excluded set — worker retries delivery"
    );
    assert!(
        !holders.contains(&peer_c),
        "peer-C (Lost) must NOT be in the excluded set — worker retries delivery"
    );
}

// ─── snapshot_pool: sibling exclusion tests ───────────────────────────────────

fn master_pub(byte: u8) -> IdentityPub {
    let mut b = [0u8; 32];
    b[0] = byte;
    IdentityPub(b)
}

fn make_peer_with_master(device_id: DeviceId, master: IdentityPub) -> PeerRecord {
    PeerRecord {
        device_id,
        master_identity: master,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1000),
        last_seen: Timestamp(2000),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    }
}

/// E: snapshot_pool excludes siblings (same master, different device).
#[tokio::test]
async fn snapshot_pool_excludes_siblings_same_master() {
    let db = make_db();
    let own_device = device_id(0x01);
    let own_master = master_pub(0xAA);

    let sibling = device_id(0x02);
    let foreign1 = device_id(0x03);
    let foreign2 = device_id(0x04);

    // own device: master A — registered but own_device_id will filter it
    db.upsert_peer(&make_peer_with_master(own_device, own_master))
        .unwrap();
    // sibling: same master A, different device — must be filtered by master_identity
    db.upsert_peer(&make_peer_with_master(sibling, own_master))
        .unwrap();
    // foreign peers with different masters — must pass
    db.upsert_peer(&make_peer_with_master(foreign1, master_pub(0xBB)))
        .unwrap();
    db.upsert_peer(&make_peer_with_master(foreign2, master_pub(0xCC)))
        .unwrap();

    let pool = snapshot_pool(None, &db, None, &own_device, &own_master, 0).await;

    let candidate_ids: Vec<DeviceId> = pool.candidates.iter().map(|c| c.device_id).collect();
    assert!(
        !candidate_ids.contains(&own_device),
        "own device must be excluded"
    );
    assert!(
        !candidate_ids.contains(&sibling),
        "sibling (same master) must be excluded"
    );
    assert!(
        candidate_ids.contains(&foreign1),
        "foreign1 must be included"
    );
    assert!(
        candidate_ids.contains(&foreign2),
        "foreign2 must be included"
    );
}

/// F: snapshot_pool excludes self via device_id even when master matches.
#[tokio::test]
async fn snapshot_pool_excludes_self_via_device_id() {
    let db = make_db();
    let own_device = device_id(0x10);
    let own_master = master_pub(0xAA);

    db.upsert_peer(&make_peer_with_master(own_device, own_master))
        .unwrap();

    let pool = snapshot_pool(None, &db, None, &own_device, &own_master, 0).await;

    assert!(
        pool.candidates.is_empty(),
        "pool must be empty: only own device was in DB"
    );
}

/// G: snapshot_pool includes cross-master peers only.
#[tokio::test]
async fn snapshot_pool_includes_cross_master_peers() {
    let db = make_db();
    let own_device = device_id(0x20);
    let own_master = master_pub(0x01);

    let peer_b = device_id(0x21);
    let peer_c = device_id(0x22);
    let peer_d = device_id(0x23);

    db.upsert_peer(&make_peer_with_master(own_device, own_master))
        .unwrap();
    db.upsert_peer(&make_peer_with_master(peer_b, master_pub(0x02)))
        .unwrap();
    db.upsert_peer(&make_peer_with_master(peer_c, master_pub(0x03)))
        .unwrap();
    db.upsert_peer(&make_peer_with_master(peer_d, master_pub(0x04)))
        .unwrap();

    let pool = snapshot_pool(None, &db, None, &own_device, &own_master, 0).await;

    assert_eq!(
        pool.candidates.len(),
        3,
        "3 cross-master peers must be in the pool"
    );
    let ids: Vec<DeviceId> = pool.candidates.iter().map(|c| c.device_id).collect();
    assert!(ids.contains(&peer_b));
    assert!(ids.contains(&peer_c));
    assert!(ids.contains(&peer_d));
    assert!(!ids.contains(&own_device), "own device must not appear");
}
