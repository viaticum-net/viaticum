// Pipeline: flush_queue, process_large_file.
// Compress → encrypt → encode → write symbols → update DB.

use std::sync::Arc;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use viaticum_core::cluster::esi_namespace_start;
use viaticum_core::constants::MIN_BATCH_BYTES;
use viaticum_core::db::Db;
use viaticum_core::erasure::{ErasureEncoder, binding_seed};
use viaticum_core::placement::{
    HolderCandidate, PlacementError, compute_allocation_with_importance,
};
use viaticum_core::reliability;

/// Importance change threshold above which the pack accumulator flushes.
/// Strict comparison: delta > IMPORTANCE_FLUSH_EPSILON triggers flush.
/// Value 0.05 separates real bucket transitions (minimum gap 0.30) from
/// within-bucket jitter (maximum ~0.02 from burst downweighting).
const IMPORTANCE_FLUSH_EPSILON: f64 = 0.05;
use viaticum_core::types::{
    DeviceId, ErasureParams, Event, EventEntry, FileId, PlacementStatus, SourceBlockId,
    SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement, Timestamp,
};

use super::packing::build_plaintext;
use super::{BackupConfig, PipelineResult, QueuedFile};

/// Derive the ChaCha20-Poly1305 key from an epoch key.
///
/// Key = HKDF-SHA256(None, epoch_key, "viaticum-block-key")[..32]
pub fn derive_block_key(epoch_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, epoch_key);
    let mut key = [0u8; 32];
    hk.expand(b"viaticum-block-key", &mut key)
        .expect("32 is a valid HKDF-SHA256 output length");
    key
}

/// Derive a deterministic 12-byte nonce from epoch_key and compressed data.
///
/// Uses HKDF-SHA256 with `blake3(compressed)` as salt and epoch_key as IKM.
/// This is a SIV-like construction: nonce depends on message content,
/// so the same plaintext always produces the same blob.
fn derive_nonce(epoch_key: &[u8; 32], compressed: &[u8]) -> [u8; 12] {
    let hash = blake3::hash(compressed);
    let hk = Hkdf::<Sha256>::new(Some(hash.as_bytes()), epoch_key);
    let mut nonce = [0u8; 12];
    hk.expand(b"viaticum-block-nonce", &mut nonce)
        .expect("12 is a valid HKDF-SHA256 output length");
    nonce
}

/// Encrypt plaintext: compress → encrypt → prepend nonce.
///
/// Returns `[12-byte nonce][ciphertext]`.
/// Deterministic: same (plaintext, epoch_key) always produces same output.
pub fn compress_and_encrypt(plaintext: &[u8], epoch_key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    // zstd compress (level 3)
    let compressed = zstd::encode_all(std::io::Cursor::new(plaintext), 3)
        .map_err(|e| anyhow::anyhow!("zstd compress: {e}"))?;

    // Derive encryption key
    let key = derive_block_key(epoch_key);
    let cipher = ChaCha20Poly1305::new(&key.into());

    // Deterministic nonce derived from epoch_key + blake3(compressed)
    let nonce_bytes = derive_nonce(epoch_key, &compressed);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, compressed.as_ref())
        .map_err(|e| anyhow::anyhow!("chacha20poly1305 encrypt: {e}"))?;

    // Stored format: [nonce (12 bytes)][ciphertext]
    let mut stored = Vec::with_capacity(12 + ciphertext.len());
    stored.extend_from_slice(&nonce_bytes);
    stored.extend_from_slice(&ciphertext);
    Ok(stored)
}

/// Decrypt and decompress a stored block (output of `compress_and_encrypt`).
///
/// Input format: `[12-byte nonce][ciphertext]`.
/// Returns decompressed plaintext.
pub fn decrypt_and_decompress(stored: &[u8], epoch_key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    if stored.len() < 12 {
        anyhow::bail!("stored block too short: {} bytes", stored.len());
    }
    let (nonce_bytes, ciphertext) = stored.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = derive_block_key(epoch_key);
    let cipher = ChaCha20Poly1305::new(&key.into());

    let compressed = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("chacha20poly1305 decrypt: {e}"))?;

    let plaintext = zstd::decode_all(std::io::Cursor::new(&compressed))
        .map_err(|e| anyhow::anyhow!("zstd decompress: {e}"))?;
    Ok(plaintext)
}

/// Write one source block through the full pipeline:
/// encode → write symbol files → write DB records.
///
/// `files` contains (QueuedFile, raw_bytes) pairs.
/// `file_id_for_single` is used when this is a Single-type block; for Pack blocks it is
/// computed from the first file in `files`.
/// `block_type` should be `Pack` or `Single`.
/// `pack_importance`: explicit importance for this pack (first file's importance for Pack
/// blocks; file's importance for Single blocks). Used to set `SourceBlockRecord.importance`
/// and `target_reliability` at creation, and to drive `compute_allocation_with_importance`
/// for dynamic N.
/// Returns `PipelineResult` describing the outcome.
#[allow(clippy::too_many_arguments)]
pub fn run_pipeline(
    db: &Db,
    config: &BackupConfig,
    _encoder: &Arc<dyn ErasureEncoder>,
    files: &[(QueuedFile, Vec<u8>)],
    block_type_tag: BlockTypeTag,
    candidates: &[HolderCandidate],
    _file_ids_for_block: &[FileId], // which file_ids reference this block (for back-linking)
    pack_importance: f64,
) -> anyhow::Result<PipelineResult> {
    assert!(!files.is_empty(), "run_pipeline called with empty files");

    // 1. Build plaintext
    let plaintext = match block_type_tag {
        BlockTypeTag::Pack => build_plaintext(files),
        BlockTypeTag::Single => {
            // Large file: use raw bytes directly (no pack index)
            files[0].1.clone()
        }
    };

    // 2. Compress + encrypt → stored blob = [nonce][ciphertext]
    let stored = compress_and_encrypt(&plaintext, &config.epoch_key)?;

    // 3. source_block_id = blake3(stored)
    let block_id_raw: [u8; 32] = *blake3::hash(&stored).as_bytes();
    let block_id = SourceBlockId(block_id_raw);

    // 4. Compute ErasureParams (for k, k_eff, t, overhead; n comes from dynamic solver)
    // Guard: compress_and_encrypt always produces at least 12 bytes (nonce) + auth
    // tag, so stored.len() > 0 in practice. The check is explicit for correctness.
    if stored.is_empty() {
        anyhow::bail!("compressed+encrypted block is empty — cannot compute erasure params");
    }
    let params = ErasureParams::compute(stored.len() as u64, pack_importance)
        .map_err(|e| anyhow::anyhow!("ErasureParams::compute failed: {e}"))?;

    // 5. Placement allocation with dynamic N from pool trust + importance.
    // Compute ESI offset from cluster state so each device gets a non-overlapping
    // ESI namespace. Falls back to 0 for single-device or when cluster unavailable.
    let esi_offset: u32 = config
        .cluster_state
        .as_ref()
        .and_then(|cs| {
            cs.lock()
                .ok()
                .and_then(|guard| guard.get_device(&config.device_id).map(|e| e.device_index))
        })
        .map(esi_namespace_start)
        .unwrap_or(0);

    let allocations_result = if candidates.len() >= 2 {
        match compute_allocation_with_importance(
            candidates,
            stored.len() as u64,
            pack_importance,
            esi_offset,
        ) {
            Ok(allocs) => allocs,
            Err(PlacementError::NTooSmall { .. }) => {
                tracing::warn!(
                    "N too small for {} candidates, encoding without placement",
                    candidates.len()
                );
                vec![]
            }
            Err(e) => {
                tracing::warn!("placement error: {e}, encoding without placement");
                vec![]
            }
        }
    } else {
        tracing::debug!(
            "fewer than 2 candidates ({}), encoding without placement",
            candidates.len()
        );
        vec![]
    };

    // 6. (Wave 11b) No disk writes — raw symbols are not persisted.
    // The WorkPipeline worker re-encodes from source on its next iteration.
    // block.bin and raw/{esi}.bin are never written after Wave 11b.

    let mut symbol_count_per_holder: Vec<(DeviceId, u32)> = Vec::new();

    // Record per-holder counts (binding applied at delivery time, not here).
    for alloc in &allocations_result {
        symbol_count_per_holder.push((alloc.device_id, alloc.symbol_count));
    }

    // 7. DB: upsert SourceBlockRecord
    let block_type = match block_type_tag {
        BlockTypeTag::Pack => {
            let entries = files
                .iter()
                .scan(0u64, |offset, (qf, bytes)| {
                    let entry = viaticum_core::types::PackEntry {
                        file_id: qf.file_id,
                        offset: *offset,
                        size: bytes.len() as u64,
                    };
                    *offset += bytes.len() as u64;
                    Some(entry)
                })
                .collect();
            SourceBlockType::Pack { entries }
        }
        BlockTypeTag::Single => SourceBlockType::Single,
    };

    // Effective N = sum of allocated symbol counts. If empty (< 2 candidates), fall back
    // to the static params.n so the block record stores a meaningful N for future repair.
    let effective_n: u32 = {
        let sum: u32 = allocations_result.iter().map(|a| a.symbol_count).sum();
        if sum == 0 { params.n } else { sum }
    };

    // Wave 9: set importance and target_reliability at creation from pack_importance.
    let target_rel = reliability::target_reliability(pack_importance);

    let block_record = SourceBlockRecord {
        block_id,
        k: params.k,
        t: params.t,
        block_type,
        status: SourceBlockStatus::Active,
        created_at: Timestamp::now(),
        encrypted_size: Some(stored.len() as u64),
        n: Some(effective_n),
        overhead: Some(params.overhead),
        drop_notice_sent_at: None,
        // Wave 9: set at creation from pack importance.
        importance: pack_importance,
        target_reliability: target_rel,
        current_alive: 0,
        current_reliability: 0.0,
    };
    // 8 & 9. DB: atomically write source block + all placements + all events.
    // Using a single write transaction ensures that on crash before commit,
    // neither the source block nor any placement is visible — no orphaned state.
    let primary_file_id = files[0].0.file_id;
    let now = Timestamp::now();

    let mut txn = db.write_txn()?;
    txn.upsert_source_block(&block_record)?;

    for alloc in &allocations_result {
        let seed = binding_seed(&block_id, &alloc.device_id);
        let placement = SymbolPlacement {
            source_block_id: block_id,
            holder_id: alloc.device_id,
            file_id: primary_file_id,
            esi_ranges: vec![alloc.esi_range()],
            binding_seed: seed,
            status: PlacementStatus::Offered, // Offered; transitions to Alive after SymbolStored confirmation
            last_verified: None,
            placed_at: now,
            consecutive_misses: 0,
        };
        txn.upsert_placement(&placement)?;
    }

    for alloc in &allocations_result {
        let entry = EventEntry {
            timestamp: now,
            device_id: config.device_id,
            event: Event::SymbolsPlaced {
                source_block_id: block_id,
                holder_id: alloc.device_id,
                esi_range: alloc.esi_range(),
            },
        };
        txn.append_event(&entry)?;
    }

    txn.commit()?;

    tracing::info!(
        block_id = %block_id,
        k = params.k,
        n = effective_n,
        holders = allocations_result.len(),
        importance = pack_importance,
        target_reliability = target_rel,
        "backup: pipeline complete"
    );

    Ok(PipelineResult {
        source_block_id: block_id,
        k: params.k,
        n: effective_n,
        t: params.t,
        symbol_count_per_holder,
        stored_size: stored.len() as u64,
        importance: pack_importance,
    })
}

/// Whether this pipeline run produces a Pack or Single block.
#[derive(Debug, Clone, Copy)]
pub enum BlockTypeTag {
    Pack,
    Single,
}

/// Flush a queue of files, grouping into batches up to source_block_size.
///
/// Files must be in importance-DESC order (as produced by select_backup_batch).
/// Flushes on EITHER size threshold OR importance change > IMPORTANCE_FLUSH_EPSILON
/// between consecutive files.
///
/// Returns pipeline results for each emitted source block.
/// If `force=false` and total bytes < MIN_BATCH_BYTES, returns empty vec.
pub fn flush_queue_inner(
    db: &Db,
    config: &BackupConfig,
    encoder: &Arc<dyn ErasureEncoder>,
    queued: &mut Vec<QueuedFile>,
    total_bytes_all_categories: u64,
    force: bool,
    candidates: &[HolderCandidate],
) -> anyhow::Result<Vec<PipelineResult>> {
    if queued.is_empty() {
        return Ok(vec![]);
    }

    // MIN_BATCH_BYTES check (across all categories)
    if !force && total_bytes_all_categories < MIN_BATCH_BYTES {
        tracing::debug!(
            "skip flush: {} bytes < MIN_BATCH_BYTES ({})",
            total_bytes_all_categories,
            MIN_BATCH_BYTES
        );
        return Ok(vec![]);
    }

    let mut results = Vec::new();
    let mut batch: Vec<(QueuedFile, Vec<u8>)> = Vec::new();
    let mut batch_bytes: u64 = 0;
    // Track importance of the last file added to the current batch (A9: track last-added).
    let mut prev_importance: Option<f64> = None;
    let drained: Vec<QueuedFile> = std::mem::take(queued);

    for qf in drained {
        // Read file bytes from disk
        let file_bytes =
            std::fs::read(&qf.path).map_err(|e| anyhow::anyhow!("read file {}: {e}", qf.path))?;

        let file_size = file_bytes.len() as u64;

        // Importance-change flush (BEFORE size-overflow check, per D2).
        // Fires when importance changes by more than IMPORTANCE_FLUSH_EPSILON (strict).
        if let Some(prev) = prev_importance
            && (qf.importance - prev).abs() > IMPORTANCE_FLUSH_EPSILON
            && !batch.is_empty()
        {
            let pack_importance = batch[0].0.importance;
            let result = run_pipeline(
                db,
                config,
                encoder,
                &batch,
                BlockTypeTag::Pack,
                candidates,
                &[],
                pack_importance,
            )?;
            update_backed_up_at(db, &batch, result.source_block_id, result.k, result.t)?;
            results.push(result);
            batch.clear();
            batch_bytes = 0;
        }

        // Size-overflow flush: adding this file would push batch over the limit.
        if !batch.is_empty() && batch_bytes + file_size > config.source_block_size {
            let pack_importance = batch[0].0.importance;
            let result = run_pipeline(
                db,
                config,
                encoder,
                &batch,
                BlockTypeTag::Pack,
                candidates,
                &[],
                pack_importance,
            )?;
            update_backed_up_at(db, &batch, result.source_block_id, result.k, result.t)?;
            results.push(result);
            batch.clear();
            batch_bytes = 0;
        }

        prev_importance = Some(qf.importance);
        batch.push((qf, file_bytes));
        batch_bytes += file_size;

        // Immediate size flush: batch is at or over limit after adding the file.
        if batch_bytes >= config.source_block_size {
            let pack_importance = batch[0].0.importance;
            let result = run_pipeline(
                db,
                config,
                encoder,
                &batch,
                BlockTypeTag::Pack,
                candidates,
                &[],
                pack_importance,
            )?;
            update_backed_up_at(db, &batch, result.source_block_id, result.k, result.t)?;
            results.push(result);
            batch.clear();
            batch_bytes = 0;
            prev_importance = None;
        }
    }

    // Flush remaining batch
    if !batch.is_empty() {
        let pack_importance = batch[0].0.importance;
        let result = run_pipeline(
            db,
            config,
            encoder,
            &batch,
            BlockTypeTag::Pack,
            candidates,
            &[],
            pack_importance,
        )?;
        update_backed_up_at(db, &batch, result.source_block_id, result.k, result.t)?;
        results.push(result);
    }

    Ok(results)
}

/// Update `FileVersion.backed_up_at` for all files in a batch after successful pipeline.
pub fn update_backed_up_at(
    db: &Db,
    batch: &[(QueuedFile, Vec<u8>)],
    block_id: SourceBlockId,
    k: u32,
    t: u16,
) -> anyhow::Result<()> {
    let now = Timestamp::now();
    for (qf, _) in batch {
        // Fetch current FileRecord from DB
        if let Some(mut record) = db.get_file(&qf.path)? {
            // Find the version with matching content_hash and update it
            let mut updated = false;
            for version in &mut record.versions {
                if version.content_hash == qf.content_hash {
                    version.backed_up_at = Some(now);
                    version.source_block_id = block_id;
                    version.k = k;
                    version.t = t;
                    updated = true;
                    break;
                }
            }
            if updated {
                db.upsert_file(&record)?;
            } else {
                tracing::warn!(
                    path = %qf.path,
                    "backed_up_at update skipped: content_hash not found in versions (file modified between enqueue and flush?)"
                );
            }
        }
    }
    Ok(())
}

// Note: read_raw_symbols_for_block and read_symbols_for_holder were removed in
// Wave 11b. Raw symbol files are no longer written after Wave 11b; the pipeline
// produces only DB records. The WorkPipeline worker re-encodes from source on delivery.

/// Rebuild the encrypted blob for a SourceBlockRecord by reading source files,
/// compressing, and re-encrypting with the epoch key. Verifies blake3(blob) == block_id.
///
/// This is the primary path for the unified worker (Wave 11b) to obtain the source
/// blob without any on-disk block.bin cache. It is also used by the restore path
/// as a fallback when fetching symbols from holders fails.
///
/// CPU-bound portion (`compress_and_encrypt`) runs inside `spawn_blocking`.
pub async fn rebuild_source_blob(
    db: &viaticum_core::db::Db,
    block_record: &viaticum_core::types::SourceBlockRecord,
    epoch_key: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    let plaintext = crate::daemon::backup::packing::rebuild_plaintext_from_db(db, block_record)
        .map_err(|e| anyhow::anyhow!("rebuild plaintext: {e}"))?;

    let epoch_key_owned = *epoch_key;
    let stored =
        tokio::task::spawn_blocking(move || compress_and_encrypt(&plaintext, &epoch_key_owned))
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking join: {e}"))?
            .map_err(|e| anyhow::anyhow!("compress_and_encrypt: {e}"))?;

    let hash: [u8; 32] = *blake3::hash(&stored).as_bytes();
    if hash != block_record.block_id.0 {
        anyhow::bail!(
            "rebuilt blob hash {} != expected {}",
            viaticum_core::types::hex_encode(&hash),
            block_record.block_id
        );
    }
    Ok(stored)
}

/// Scan `symbols_dir` and remove any legacy flat `{esi}.bin` files
/// (pre-Wave 2 bound symbol files) from block subdirectories.
///
/// Preserves: `block.bin` (source blob) and `raw/` subdirectory.
/// Deletes: `*.bin` files directly under `{symbols_dir}/{block_hex}/`
///          whose name is not `block.bin`.
///
/// This is idempotent and safe to run on every startup.
pub fn cleanup_legacy_bound_symbol_files(symbols_dir: &std::path::Path) -> anyhow::Result<()> {
    let entries = match std::fs::read_dir(symbols_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "read symbols_dir {}: {e}",
                symbols_dir.display()
            ));
        }
    };

    for entry in entries {
        let block_dir = entry?.path();
        if !block_dir.is_dir() {
            continue;
        }

        let block_entries = match std::fs::read_dir(&block_dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(path = %block_dir.display(), "cleanup_legacy: cannot read block dir: {e}");
                continue;
            }
        };

        for file_entry in block_entries {
            let file_path = match file_entry {
                Ok(e) => e.path(),
                Err(e) => {
                    tracing::warn!("cleanup_legacy: dir entry error: {e}");
                    continue;
                }
            };

            if !file_path.is_file() {
                // Skip subdirectories (including raw/).
                continue;
            }

            let name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if name.ends_with(".bin") && name != "block.bin" {
                // Legacy bound symbol file — remove.
                match std::fs::remove_file(&file_path) {
                    Ok(()) => {
                        tracing::debug!(
                            path = %file_path.display(),
                            "cleanup_legacy: removed legacy bound symbol file"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %file_path.display(),
                            "cleanup_legacy: remove failed: {e}"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
