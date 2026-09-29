// Pipeline: flush_queue, process_large_file.
// Compress → encrypt → encode → write symbols → update DB.

use std::sync::Arc;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use viaticum_core::constants::MIN_BATCH_BYTES;
use viaticum_core::db::Db;
use viaticum_core::erasure::ErasureEncoder;
use viaticum_core::placement::HolderCandidate;
use viaticum_core::reliability;

/// Importance change threshold above which the pack accumulator flushes.
/// Strict comparison: delta > IMPORTANCE_FLUSH_EPSILON triggers flush.
/// Value 0.05 separates real bucket transitions (minimum gap 0.30) from
/// within-bucket jitter (maximum ~0.02 from burst downweighting).
const IMPORTANCE_FLUSH_EPSILON: f64 = 0.05;
use viaticum_core::types::{
    ErasureParams, FileId, SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType,
    Timestamp,
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
/// and `target_reliability` at creation, and to drive the target-based N solver.
///
/// A4: backup creates ONLY the `SourceBlockRecord` — no placements, no delivery. The
/// `candidates` pool is used solely to solve a principled target-based N for the record;
/// the WorkPipeline worker is the sole creator of placements and the sole deliverer.
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

    // 5. (Wave 11b / A4) Backup does NOT place or deliver. It only records the
    // SourceBlockRecord. The WorkPipeline worker is the sole creator of placements
    // and the sole deliverer — it re-encodes from source on its next iteration and
    // owns the ESI namespace. Backup therefore needs neither an ESI offset nor a
    // placement allocation here. The `candidates` slice is used only to derive a
    // principled target-based N (below) so the stored record carries a meaningful
    // redundancy target for the worker and for future repair.

    // 6. (Wave 11b) No disk writes — raw symbols are not persisted.
    // The WorkPipeline worker re-encodes from source on its next iteration.
    // block.bin and raw/{esi}.bin are never written after Wave 11b.

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

    // Wave 9: set importance and target_reliability at creation from pack_importance.
    let target_rel = reliability::target_reliability(pack_importance);

    // Effective N: principled, target-based redundancy target from the current pool.
    // Backup no longer derives N from a phantom allocation it never delivers (A4).
    // Instead it solves for the smallest N reaching `target_rel` using a binomial
    // mean-survival-probability model (`solve_n_for_target`). NOTE: this is an
    // *approximation*, not a prediction of what the worker delivers — the worker
    // places via the holder-correlated `solve_placement_for_target` (live-or-die per
    // holder, capped at full replicas), which diverges from the independent-binomial
    // assumption in small / heterogeneous pools. The survival-prob bridge and `k_eff`
    // below DO match the worker exactly; only the solver model differs. `record.n`
    // is a redundancy target / priority heuristic (not a correctness input — repair
    // eligibility is reliability-gated, not n-gated), so the approximation is benign.
    // With no candidates we fall back to the static params.n.
    let k_eff = params.k + viaticum_core::constants::DECODE_OVERHEAD; // mirror worker.rs
    let effective_n: u32 = if candidates.is_empty() {
        params.n
    } else {
        // Convert placement candidates → reliability candidates via the same
        // commitment_to_survival_prob bridge compute_allocation_with_importance uses,
        // so the per-holder survival probability feeding the solver matches the
        // worker's placement model (the solver *aggregation* still differs — see above).
        let solver_candidates: Vec<reliability::HolderCandidate> = candidates
            .iter()
            .map(|c| reliability::HolderCandidate {
                survival_prob: reliability::commitment_to_survival_prob(
                    viaticum_core::commitment::CommitmentScore::new(c.trust),
                ),
            })
            .collect();
        match reliability::solve_n_for_target(k_eff, &solver_candidates, target_rel) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("solve_n_for_target failed ({e}); falling back to params.n");
                params.n
            }
        }
    };

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
    // 8. DB: write the source block record only (A4). Backup creates no placements
    // and emits no SymbolsPlaced events — those belong to the WorkPipeline worker,
    // the sole creator of placements. A single write transaction keeps block-record
    // creation atomic.
    let mut txn = db.write_txn()?;
    txn.upsert_source_block(&block_record)?;
    txn.commit()?;

    tracing::info!(
        block_id = %block_id,
        k = params.k,
        n = effective_n,
        importance = pack_importance,
        target_reliability = target_rel,
        "backup: pipeline complete (block record only; worker places)"
    );

    Ok(PipelineResult {
        source_block_id: block_id,
        k: params.k,
        n: effective_n,
        t: params.t,
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

/// Pack one batch into a Pack block and mark its files backed up.
///
/// An error is returned only from before the block record is committed; the caller
/// then requeues the batch. Once the block is committed its files are marked one by one
/// and a file whose record cannot be updated stays pending (backup-i23): requeueing
/// after the commit would build and commit the block again on every flush.
fn pack_batch(
    db: &Db,
    config: &BackupConfig,
    encoder: &Arc<dyn ErasureEncoder>,
    batch: &[(QueuedFile, Vec<u8>)],
    candidates: &[HolderCandidate],
) -> anyhow::Result<PipelineResult> {
    let pack_importance = batch[0].0.importance;
    let result = run_pipeline(
        db,
        config,
        encoder,
        batch,
        BlockTypeTag::Pack,
        candidates,
        &[],
        pack_importance,
    )?;
    update_backed_up_at(db, batch, result.source_block_id, result.k, result.t);
    Ok(result)
}

/// What the bytes read at flush time are, against what was queued (backup-i23).
pub(crate) enum ReadAtFlush {
    /// Pack these bytes; `content_hash` is theirs (it may differ from the queued one).
    Pack {
        bytes: Vec<u8>,
        content_hash: [u8; 32],
    },
    /// Nothing to pack: the file is gone, unreadable, or now holds content that is
    /// already in the network (its event will point the path there without traffic).
    Skip,
}

/// Re-read a queued (or large) file right before packing it (backup-i23).
///
/// Vanished or unreadable → skipped (INFO / WARN), the rest of the batch goes on.
/// Changed since enqueue → if the new content is already in the network
/// (`in_network`), skipped; otherwise the bytes read are packed with their own hash,
/// so a version is marked backed up only with the hash of the bytes in its block.
pub(crate) fn read_at_flush(
    path: &str,
    queued_hash: &[u8; 32],
    in_network: &dyn Fn(&[u8; 32]) -> bool,
) -> ReadAtFlush {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(path = %path, "flush: file vanished since enqueue; skipped");
            return ReadAtFlush::Skip;
        }
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "flush: cannot read file; skipped");
            return ReadAtFlush::Skip;
        }
    };
    let content_hash: [u8; 32] = *blake3::hash(&bytes).as_bytes();
    if &content_hash != queued_hash {
        if in_network(&content_hash) {
            tracing::debug!(
                path = %path,
                "flush: file changed to content already in the network; skipped"
            );
            return ReadAtFlush::Skip;
        }
        tracing::debug!(path = %path, "flush: file changed since enqueue; packing what was read");
    }
    ReadAtFlush::Pack {
        bytes,
        content_hash,
    }
}

/// Flush a queue of files, grouping into batches up to source_block_size.
///
/// Files must be in importance-DESC order (as produced by select_backup_batch).
/// Flushes on EITHER size threshold OR importance change > IMPORTANCE_FLUSH_EPSILON
/// between consecutive files.
///
/// backup-i23: a file that vanished or changed since enqueue does not stop the others
/// (see [`read_at_flush`]; `in_network` answers "is this content already backed up").
/// An error before a block record is committed puts the batch being built and every
/// file not yet processed back into `queued`, in order, and returns the error. After the
/// commit nothing is requeued (see [`pack_batch`]).
///
/// Returns pipeline results for each emitted source block.
/// If `force=false` and total bytes < MIN_BATCH_BYTES, returns empty vec.
#[allow(clippy::too_many_arguments)]
pub fn flush_queue_inner(
    db: &Db,
    config: &BackupConfig,
    encoder: &Arc<dyn ErasureEncoder>,
    queued: &mut Vec<QueuedFile>,
    total_bytes_all_categories: u64,
    force: bool,
    candidates: &[HolderCandidate],
    in_network: &dyn Fn(&[u8; 32]) -> bool,
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
    let mut rest = std::mem::take(queued).into_iter();

    // On an error before the block commit: the batch, the file in hand (if not in the
    // batch yet) and everything not yet processed go back to the queue, in their order.
    let requeue = |queued: &mut Vec<QueuedFile>,
                   batch: &mut Vec<(QueuedFile, Vec<u8>)>,
                   in_hand: Option<QueuedFile>,
                   rest: std::vec::IntoIter<QueuedFile>| {
        queued.extend(batch.drain(..).map(|(qf, _)| qf));
        queued.extend(in_hand);
        queued.extend(rest);
    };

    while let Some(mut qf) = rest.next() {
        let file_bytes = match read_at_flush(&qf.path, &qf.content_hash, in_network) {
            ReadAtFlush::Pack {
                bytes,
                content_hash,
            } => {
                qf.content_hash = content_hash;
                qf.size_bytes = bytes.len() as u64;
                bytes
            }
            ReadAtFlush::Skip => continue,
        };

        let file_size = file_bytes.len() as u64;

        // Importance-change flush (BEFORE size-overflow check, per D2).
        // Fires when importance changes by more than IMPORTANCE_FLUSH_EPSILON (strict).
        // Size-overflow flush: adding this file would push batch over the limit.
        let importance_changed = prev_importance
            .is_some_and(|prev| (qf.importance - prev).abs() > IMPORTANCE_FLUSH_EPSILON);
        let overflows = batch_bytes + file_size > config.source_block_size;
        if !batch.is_empty() && (importance_changed || overflows) {
            match pack_batch(db, config, encoder, &batch, candidates) {
                Ok(result) => results.push(result),
                Err(e) => {
                    requeue(queued, &mut batch, Some(qf), rest);
                    return Err(e);
                }
            }
            batch.clear();
            batch_bytes = 0;
        }

        prev_importance = Some(qf.importance);
        batch.push((qf, file_bytes));
        batch_bytes += file_size;

        // Immediate size flush: batch is at or over limit after adding the file.
        if batch_bytes >= config.source_block_size {
            match pack_batch(db, config, encoder, &batch, candidates) {
                Ok(result) => results.push(result),
                Err(e) => {
                    requeue(queued, &mut batch, None, rest);
                    return Err(e);
                }
            }
            batch.clear();
            batch_bytes = 0;
            prev_importance = None;
        }
    }

    // Flush remaining batch
    if !batch.is_empty() {
        match pack_batch(db, config, encoder, &batch, candidates) {
            Ok(result) => results.push(result),
            Err(e) => {
                requeue(queued, &mut batch, None, rest);
                return Err(e);
            }
        }
    }

    Ok(results)
}

/// Mark the files of a packed, committed batch backed up (backup-i9, backup-i23).
///
/// For each file: the LAST version of its record, if it is pending, becomes the
/// packed version — its `content_hash` is set to the hash of the bytes actually packed
/// (`qf.content_hash`, set by the flush), `backed_up_at` = now, block, k, t. An older
/// version with the same hash is never touched (a rollback to earlier content keeps
/// that earlier version on its own block). No pending last version, or a record of
/// another `file_id` at the path → WARN, nothing written.
///
/// Never fails: the block is already committed, so a file whose record cannot be read
/// or written gets a WARN and stays pending until its next event or rescan; the other
/// files are still marked.
pub fn update_backed_up_at(
    db: &Db,
    batch: &[(QueuedFile, Vec<u8>)],
    block_id: SourceBlockId,
    k: u32,
    t: u16,
) {
    let now = Timestamp::now();
    for (qf, _) in batch {
        if let Err(e) = mark_backed_up(db, qf, block_id, k, t, now) {
            tracing::warn!(
                path = %qf.path,
                block_id = %block_id,
                error = %e,
                "backed_up_at update failed; the file stays pending until its next event or rescan"
            );
        }
    }
}

/// One file of [`update_backed_up_at`].
fn mark_backed_up(
    db: &Db,
    qf: &QueuedFile,
    block_id: SourceBlockId,
    k: u32,
    t: u16,
    now: Timestamp,
) -> Result<(), viaticum_core::db::DbError> {
    let Some(mut record) = db.get_file(&qf.path)? else {
        tracing::warn!(path = %qf.path, "backed_up_at update skipped: no catalog record");
        return Ok(());
    };
    if record.file_id != qf.file_id {
        tracing::warn!(
            path = %qf.path,
            "backed_up_at update skipped: the record at this path has another file_id"
        );
        return Ok(());
    }
    match record.versions.last_mut() {
        Some(version) if version.backed_up_at.is_none() => {
            version.content_hash = qf.content_hash;
            version.backed_up_at = Some(now);
            version.source_block_id = block_id;
            version.k = k;
            version.t = t;
            db.upsert_file(&record)?;
        }
        _ => tracing::warn!(
            path = %qf.path,
            "backed_up_at update skipped: the last version is not pending"
        ),
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
/// The plaintext is rebuilt by content (`rebuild::rebuild_plaintext_from_db`, INV-RB);
/// its error keeps its type under the "rebuild plaintext" context, so a caller can tell
/// `RebuildError::SourceMissing` apart. Gone paths go to `scope.recheck`.
///
/// CPU-bound portion (`compress_and_encrypt`) runs inside `spawn_blocking`.
pub async fn rebuild_source_blob(
    db: &viaticum_core::db::Db,
    block_record: &viaticum_core::types::SourceBlockRecord,
    epoch_key: &[u8; 32],
    scope: &super::rebuild::RebuildScope,
) -> anyhow::Result<Vec<u8>> {
    use anyhow::Context;
    let plaintext = super::rebuild::rebuild_plaintext_from_db(db, block_record, scope)
        .context("rebuild plaintext")?;

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
