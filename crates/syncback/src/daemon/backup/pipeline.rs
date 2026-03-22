// Pipeline: flush_queue, process_large_file.
// Compress → encrypt → encode → write symbols → update DB.

use std::sync::Arc;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use syncback_core::constants::MIN_BATCH_BYTES;
use syncback_core::db::Db;
use syncback_core::erasure::{binding_seed, ErasureEncoder};
use syncback_core::placement::{compute_allocation, HolderCandidate, PlacementError};
use syncback_core::types::{
    hex_encode, ErasureParams, Event, EventEntry, FileId, IdentityPub, PlacementStatus,
    SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement,
    Timestamp,
};

use super::packing::build_plaintext;
use super::{BackupConfig, PipelineResult, QueuedFile};

/// Derive the ChaCha20-Poly1305 key from an epoch key.
///
/// Key = HKDF-SHA256(None, epoch_key, "syncback-block-key")[..32]
pub fn derive_block_key(epoch_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, epoch_key);
    let mut key = [0u8; 32];
    hk.expand(b"syncback-block-key", &mut key)
        .expect("32 is a valid HKDF-SHA256 output length");
    key
}

/// Encrypt plaintext: compress → encrypt → prepend nonce.
///
/// Returns `[12-byte nonce][ciphertext]`.
pub fn compress_and_encrypt(plaintext: &[u8], epoch_key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    // zstd compress (level 3)
    let compressed = zstd::encode_all(std::io::Cursor::new(plaintext), 3)
        .map_err(|e| anyhow::anyhow!("zstd compress: {e}"))?;

    // Derive encryption key
    let key = derive_block_key(epoch_key);
    let cipher = ChaCha20Poly1305::new(&key.into());

    // Random 12-byte nonce
    let nonce_bytes: [u8; 12] = rand::random();
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
/// Returns `PipelineResult` describing the outcome.
pub fn run_pipeline(
    db: &Db,
    config: &BackupConfig,
    encoder: &Arc<dyn ErasureEncoder>,
    files: &[(QueuedFile, Vec<u8>)],
    block_type_tag: BlockTypeTag,
    candidates: &[HolderCandidate],
    _file_ids_for_block: &[FileId], // which file_ids reference this block (for back-linking)
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

    // 4. Compute ErasureParams
    let avg_importance: f64 = {
        let sum: f64 = files.iter().map(|(qf, _)| qf.importance).sum();
        sum / files.len() as f64
    };
    let params = ErasureParams::compute(stored.len() as u64, avg_importance);

    // 5. Placement allocation
    let allocations_result = if candidates.len() >= 2 {
        match compute_allocation(candidates, &params) {
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

    // 6. Encode symbols for each holder and write to disk
    let symbols_block_dir = config.symbols_dir.join(hex_encode(&block_id.0));
    std::fs::create_dir_all(&symbols_block_dir)
        .map_err(|e| anyhow::anyhow!("create symbols dir: {e}"))?;

    // Also save the stored blob alongside symbols for RepairAgent use.
    // Path: {symbols_dir}/{block_id_hex}/block.bin
    let block_blob_path = symbols_block_dir.join("block.bin");
    std::fs::write(&block_blob_path, &stored)
        .map_err(|e| anyhow::anyhow!("write block.bin: {e}"))?;

    let mut symbol_count_per_holder: Vec<(IdentityPub, u32)> = Vec::new();

    for alloc in &allocations_result {
        let symbols = encoder.encode(
            &stored,
            &params,
            alloc.start_esi,
            alloc.symbol_count,
            &block_id,
            &alloc.identity,
        )?;

        for symbol in &symbols {
            let symbol_path = symbols_block_dir.join(format!("{}.bin", symbol.esi));
            std::fs::write(&symbol_path, &symbol.data)
                .map_err(|e| anyhow::anyhow!("write symbol {}: {e}", symbol.esi))?;
        }

        symbol_count_per_holder.push((alloc.identity, alloc.symbol_count));
    }

    // 7. DB: upsert SourceBlockRecord
    let block_type = match block_type_tag {
        BlockTypeTag::Pack => {
            let entries = files
                .iter()
                .scan(0u64, |offset, (qf, bytes)| {
                    let entry = syncback_core::types::PackEntry {
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

    let block_record = SourceBlockRecord {
        block_id,
        k: params.k,
        t: params.t,
        block_type,
        status: SourceBlockStatus::Active,
        created_at: Timestamp::now(),
        encrypted_size: Some(stored.len() as u64),
    };
    db.upsert_source_block(&block_record)?;

    // 8. DB: upsert SymbolPlacement per holder
    let primary_file_id = files[0].0.file_id;
    let now = Timestamp::now();

    for alloc in &allocations_result {
        let seed = binding_seed(&block_id, &alloc.identity);
        let placement = SymbolPlacement {
            source_block_id: block_id,
            holder_id: alloc.identity,
            file_id: primary_file_id,
            esi_ranges: vec![alloc.esi_range()],
            binding_seed: seed,
            status: PlacementStatus::Alive, // Phase 2: set directly to Alive
            last_verified: None,
            placed_at: now,
            consecutive_misses: 0,
        };
        db.upsert_placement(&placement)?;
    }

    // 9. Append EventLog for each placement
    for alloc in &allocations_result {
        let entry = EventEntry {
            timestamp: now,
            device_id: config.device_id,
            event: Event::SymbolsPlaced {
                source_block_id: block_id,
                holder_id: alloc.identity,
                esi_range: alloc.esi_range(),
            },
        };
        db.append_event(&entry)?;
    }

    let n = params.n;
    tracing::info!(
        block_id = %block_id,
        k = params.k,
        n,
        holders = allocations_result.len(),
        "backup: pipeline complete"
    );

    Ok(PipelineResult {
        source_block_id: block_id,
        k: params.k,
        n,
        t: params.t,
        symbol_count_per_holder,
        stored_size: stored.len() as u64,
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
    let drained: Vec<QueuedFile> = std::mem::take(queued);

    for qf in drained {
        // Read file bytes from disk
        let file_bytes = std::fs::read(&qf.path)
            .map_err(|e| anyhow::anyhow!("read file {}: {e}", qf.path))?;

        let file_size = file_bytes.len() as u64;

        // Check if adding this file would overflow the batch
        if !batch.is_empty() && batch_bytes + file_size > config.source_block_size {
            // Flush current batch
            let result = run_pipeline(db, config, encoder, &batch, BlockTypeTag::Pack, candidates, &[])?;
            update_backed_up_at(db, &batch, result.source_block_id, result.k, result.t)?;
            results.push(result);
            batch.clear();
            batch_bytes = 0;
        }

        batch.push((qf, file_bytes));
        batch_bytes += file_size;

        // If batch is now at or over limit, flush immediately
        if batch_bytes >= config.source_block_size {
            let result = run_pipeline(db, config, encoder, &batch, BlockTypeTag::Pack, candidates, &[])?;
            update_backed_up_at(db, &batch, result.source_block_id, result.k, result.t)?;
            results.push(result);
            batch.clear();
            batch_bytes = 0;
        }
    }

    // Flush remaining batch
    if !batch.is_empty() {
        let result = run_pipeline(db, config, encoder, &batch, BlockTypeTag::Pack, candidates, &[])?;
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

/// Read symbol files for a given holder from the symbols directory.
///
/// Reads files named `{esi}.bin` for each ESI in `esi_ranges`.
/// Returns `Vec<Symbol>` in ESI order.
/// Returns error if any file cannot be read.
pub(crate) fn read_symbols_for_holder(
    symbols_dir: &std::path::Path,
    block_id: &syncback_core::types::SourceBlockId,
    esi_ranges: &[(u32, u32)],
) -> anyhow::Result<Vec<syncback_core::erasure::Symbol>> {
    use syncback_core::erasure::Symbol;

    let block_dir = symbols_dir.join(hex_encode(&block_id.0));
    let mut symbols = Vec::new();

    for &(start_esi, count) in esi_ranges {
        for esi in start_esi..start_esi + count {
            let path = block_dir.join(format!("{esi}.bin"));
            let data = std::fs::read(&path)
                .map_err(|e| anyhow::anyhow!("read symbol {}: {e}", path.display()))?;
            symbols.push(Symbol { esi, data });
        }
    }

    Ok(symbols)
}
