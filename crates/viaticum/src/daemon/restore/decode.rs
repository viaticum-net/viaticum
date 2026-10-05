// Block-level restore work: decode one block (rebuild from the owner's source, else
// fetch from holders), and write one file of it into staging.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info};
use viaticum_core::erasure::{ErasureEncoder, Symbol};
use viaticum_core::types::{
    ErasureParams, FileRecord, FileVersion, PlacementStatus, SourceBlockId, SourceBlockType,
    SymbolPlacement,
};

use super::no_answer::NoAnswerPauses;
use super::staging::JobId;
use super::{RestoreCoordinator, RestoreError, pipeline};
use crate::daemon::backup::rebuild::{RebuildScope, SourceCheck, precheck_sources};
use crate::daemon::mem_budget::{self, MemPermit, PriorityKind};
use crate::daemon::restore::staging::StagingWriter;

/// A wait for memory shows as the phase `waiting_for_memory` (and one INFO line per job) only
/// when it outlasts this (restore-i39, restore-i4).
const MEMORY_WAIT_SHOWN_AFTER: Duration = Duration::from_secs(1);

/// The room, above the sum of the source sizes, that the local tier allows the plaintext: the
/// pack index in front of the members. A pack whose index is larger takes the exact count.
const LOCAL_PLAINTEXT_SLACK: u64 = 1 << 20;

/// What the first stage of the network tier leaves: the decrypted compressed block and the
/// length of its plaintext (counted, not guessed).
#[derive(Debug)]
pub struct DecryptedBlock {
    pub compressed: Vec<u8>,
    pub plaintext_len: u64,
}

/// The first half of stage one: decode the symbols, let them go, decrypt, let the padded block
/// go. What is left is the decrypted compressed block. Blocking. The order is the one the permits of
/// the stages rely on (v3.9 NOTE (б)): the symbols are dropped before the decryption (M59).
fn decode_decrypt_compressed(
    permit: &MemPermit,
    encoder: &dyn ErasureEncoder,
    symbols: Vec<Symbol>,
    params: &ErasureParams,
    encrypted_size: u64,
    key: &[u8; 32],
    block: &SourceBlockId,
) -> Result<Vec<u8>, RestoreError> {
    let padded = mem_budget::decode_block(permit, encoder, &symbols, params)
        .map_err(|e| RestoreError::DecodeFailed(*block, e.to_string()))?;
    drop(symbols);
    if padded.len() < encrypted_size as usize {
        return Err(RestoreError::DecodeFailed(
            *block,
            format!(
                "decoded block ({} bytes) smaller than encrypted_size ({encrypted_size})",
                padded.len()
            ),
        ));
    }
    let compressed =
        crate::daemon::backup::pipeline::decrypt(&padded[..encrypted_size as usize], key).map_err(
            |e| {
                error!(block = %block, "decrypt failed: {e}");
                RestoreError::DecryptionFailed(*block)
            },
        )?;
    drop(padded);
    Ok(compressed)
}

/// The network tier, stage one — runs under the decode permit (`estimate_restore_network`, the
/// window of zstd included): decode the symbols, decrypt, count the plaintext. Blocking. The padded
/// block is gone before the count.
pub fn decode_decrypt_stage(
    permit: &MemPermit,
    encoder: &dyn ErasureEncoder,
    symbols: Vec<Symbol>,
    params: &ErasureParams,
    encrypted_size: u64,
    key: &[u8; 32],
    block: &SourceBlockId,
) -> Result<DecryptedBlock, RestoreError> {
    let compressed =
        decode_decrypt_compressed(permit, encoder, symbols, params, encrypted_size, key, block)?;
    let plaintext_len = crate::daemon::backup::pipeline::plaintext_len(&compressed)
        .map_err(|e| RestoreError::DecompressionFailed(*block, e.to_string()))?;
    Ok(DecryptedBlock {
        compressed,
        plaintext_len,
    })
}

/// The SS block of a DR, parsed under the decode permit and nothing else (spec v3.9b (6)): the
/// decode and the decryption of stage one, then the CBOR is read straight from the decompression
/// stream — there is no plaintext buffer and no second permit. Under the permit: the compressed
/// block (≤ E) and the window of zstd, both inside `estimate_restore_network`; the parsed value is
/// outside the budget. Blocking.
pub fn decode_parse_stage<T: serde::de::DeserializeOwned>(
    permit: &MemPermit,
    encoder: &dyn ErasureEncoder,
    symbols: Vec<Symbol>,
    params: &ErasureParams,
    encrypted_size: u64,
    key: &[u8; 32],
    block: &SourceBlockId,
) -> Result<T, RestoreError> {
    let compressed =
        decode_decrypt_compressed(permit, encoder, symbols, params, encrypted_size, key, block)?;
    crate::daemon::backup::pipeline::parse_cbor_compressed(&compressed)
        .map_err(|e| RestoreError::DecompressionFailed(*block, e.to_string()))
}

/// The network tier, stage two — runs under the permit of `estimate_restore_plaintext`:
/// decompress into one allocation of the counted length (no doubling of `decode_all`, M60; the
/// one-shot call holds no window, only its context). Blocking.
pub fn plaintext_stage(
    _permit: &MemPermit,
    block: &SourceBlockId,
    decrypted: DecryptedBlock,
) -> Result<Vec<u8>, RestoreError> {
    crate::daemon::backup::pipeline::decompress_exact(
        &decrypted.compressed,
        decrypted.plaintext_len,
    )
    .map_err(|e| RestoreError::DecompressionFailed(*block, e.to_string()))
}

/// The local tier's CPU part: decrypt the rebuilt blob and decompress it, with the plaintext
/// sized by the files' `metadata` (`size_hint`); a pack whose index outgrows the slack falls back
/// to the exact count. Blocking; no erasure coding (T4).
pub fn local_plaintext(
    blob: Vec<u8>,
    key: &[u8; 32],
    size_hint: u64,
    block: &SourceBlockId,
) -> Result<Vec<u8>, RestoreError> {
    let compressed = crate::daemon::backup::pipeline::decrypt(&blob, key).map_err(|e| {
        error!(block = %block, "decrypt of the rebuilt blob failed: {e}");
        RestoreError::DecryptionFailed(*block)
    })?;
    drop(blob);
    let decompress_err =
        |e: anyhow::Error| RestoreError::DecompressionFailed(*block, e.to_string());
    match crate::daemon::backup::pipeline::decompress_exact(
        &compressed,
        size_hint.saturating_add(LOCAL_PLAINTEXT_SLACK),
    ) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => {
            let len = crate::daemon::backup::pipeline::plaintext_len(&compressed)
                .map_err(decompress_err)?;
            crate::daemon::backup::pipeline::decompress_exact(&compressed, len)
                .map_err(decompress_err)
        }
    }
}

/// The bytes of the file `record`'s `version` holds, as a slice of the block's plaintext: the whole
/// block for a single-file block, the member of a pack (restore-i38). No copy (restore-i39, M65):
/// outside the budget, while the file is written, there is the one plaintext of the block, not two.
pub fn member_bytes<'a>(
    block_type: &SourceBlockType,
    plaintext: &'a [u8],
    record: &FileRecord,
    version: &FileVersion,
) -> Result<&'a [u8], RestoreError> {
    match block_type {
        SourceBlockType::Pack { .. } => {
            pipeline::extract_member(plaintext, record.file_id, &version.content_hash)
                .map_err(|e| {
                    RestoreError::PackIndexParseFailed(version.source_block_id, e.to_string())
                })?
                .ok_or_else(|| {
                    RestoreError::PackIndexParseFailed(
                        version.source_block_id,
                        format!(
                            "no pack entry with file_id {} or content hash {}",
                            record.file_id,
                            pipeline::hex_encode(&version.content_hash)
                        ),
                    )
                })
        }
        SourceBlockType::Single => Ok(plaintext),
    }
}

impl RestoreCoordinator {
    /// The permit of a restore, behind everybody queued, as a priority waiter the worker and the
    /// batch of PoS checks yield to (restore-i39, Q-V8). Waits only here, in the job's task: no
    /// transaction of the catalog is open, no lock held. A wait that outlasts
    /// `MEMORY_WAIT_SHOWN_AFTER` shows as the job's phase and as one INFO line per job. Stops on
    /// the daemon's cancel token (T10).
    async fn acquire_memory(
        &self,
        job: JobId,
        block: &SourceBlockId,
        tier: &'static str,
        need: u64,
    ) -> Result<MemPermit, RestoreError> {
        let budget = &self.config.mem_budget;
        let jobs = &self.config.jobs;
        let acquire = budget.acquire_priority(
            PriorityKind::Restore,
            block,
            need,
            MEMORY_WAIT_SHOWN_AFTER,
            || {
                if jobs.set_waiting_for_memory(job, true) {
                    info!(
                        job = %job,
                        block = %block,
                        tier = %tier,
                        need_mib = need.min(budget.total_bytes()).div_ceil(1 << 20),
                        queued_ahead = budget.queued_waiters().saturating_sub(1),
                        "restore: waiting for memory budget"
                    );
                }
            },
        );
        let permit = tokio::select! {
            p = acquire => p,
            _ = self.config.cancel.cancelled() => {
                jobs.set_waiting_for_memory(job, false);
                return Err(RestoreError::Cancelled);
            }
        };
        jobs.set_waiting_for_memory(job, false);
        Ok(permit)
    }

    /// The local tier (T4): the owner's own source files, judged by `metadata` first, with no
    /// permit; then one permit for `2·E + S`, the rebuild with the block-id check, the decryption
    /// without any encoding. `Ok(None)`: the block is not served from here (no files, files over
    /// the limit, the content changed since the backup) — the network tier takes it, with no
    /// permit held (J12).
    async fn decode_from_source(
        &self,
        job: JobId,
        block_id: &SourceBlockId,
        params: &ErasureParams,
    ) -> Result<Option<Vec<u8>>, RestoreError> {
        // A4 / Wave 11b: an empty placement set is not an error — a freshly backed-up block has
        // no placements yet and is still restorable from its source.
        let Some(block_record) = self.db.get_source_block(block_id)? else {
            return Ok(None);
        };
        // Local tier: no recheck, any Present record (hash-checked reads), no source file above
        // this machine's size limit read.
        let scope = RebuildScope::default().with_max_source_bytes(self.config.max_source_bytes);
        let (db, record, check_scope) = (self.db.clone(), block_record.clone(), scope.clone());
        let check =
            tokio::task::spawn_blocking(move || precheck_sources(&db, &record, &check_scope))
                .await
                .map_err(|e| {
                    RestoreError::DecodeFailed(*block_id, format!("precheck failed: {e}"))
                })?;
        let plaintext_bytes = match check {
            Ok(SourceCheck::Ready { plaintext_bytes }) => plaintext_bytes,
            _ => {
                debug!(block = %block_id, "restore: source files missing or over the limit; going to the network");
                return Ok(None);
            }
        };

        let need = mem_budget::estimate_restore_local(params.k, params.t, plaintext_bytes);
        let permit = self.acquire_memory(job, block_id, "local", need).await?;
        let stored_blob = match crate::daemon::backup::pipeline::rebuild_source_blob(
            &self.db,
            &block_record,
            &self.config.epoch_key,
            &scope,
        )
        .await
        {
            Ok(blob) => blob,
            Err(e) => {
                // The content changed since the backup, or a file went: release, then network.
                drop(permit);
                debug!(block = %block_id, "restore: rebuild from source files failed ({e}), falling back to network");
                return Ok(None);
            }
        };
        let (key, block) = (self.config.epoch_key, *block_id);
        let plaintext = tokio::task::spawn_blocking(move || {
            let r = local_plaintext(stored_blob, &key, plaintext_bytes, &block);
            // The permit dies here, before the plaintext reaches the writer (J14).
            drop(permit);
            r
        })
        .await
        .map_err(|e| RestoreError::DecodeFailed(block, format!("decode task failed: {e}")))??;
        debug!(block = %block_id, "restore: rebuilt the block from source files (no re-encode)");
        Ok(Some(plaintext))
    }

    /// Decode one source block.
    ///
    /// Strategy (2-tier, post-Wave-11b, under the memory budget since К-b3, restore-i39):
    ///   1. The owner's own source files, if they are there (`decode_from_source`): a permit of
    ///      `2·E + S`, rebuild, decrypt — no erasure coding.
    ///   2. Else fetch symbols from holders over the network — no deadline on the block
    ///      (restore-i12), rounds nobody answered retried from the job's pause budget `pauses`
    ///      (restore-i26), abandoned only on the daemon's cancel token. The fetch holds no
    ///      permit; one permit covers the decode and the decryption, then it is cut to (or
    ///      re-taken for) the exact plaintext size.
    ///
    /// Decrypts and decompresses the decoded data before returning. The permit is gone when it
    /// returns: the writer gets the plaintext outside the budget (J14).
    pub(crate) async fn decode_block_local(
        &self,
        block_id: &SourceBlockId,
        params: &ErasureParams,
        encrypted_size: u64,
        pauses: &mut NoAnswerPauses,
    ) -> Result<Vec<u8>, RestoreError> {
        let k_eff = params.k_eff as usize;
        let job = pauses.job_id();

        // 1. Rebuild from the owner's source files.
        if let Some(plaintext) = self.decode_from_source(job, block_id, params).await? {
            return Ok(plaintext);
        }

        // 2. Network. Holders return bound symbols; the fetch unbinds them, checks
        // their form, restricts ESIs to those requested and dedups (CS-DR-2/5).
        // Candidates: Alive, Uncertain and PresumedLost placements — a presumed-lost
        // holder may be back and still hold its symbols (restore-i2).
        debug!(
            block = %block_id,
            need = k_eff,
            "decode: source rebuild unavailable, fetching symbols from holders"
        );
        let candidates: Vec<SymbolPlacement> = self
            .db
            .list_placements_for_block(block_id)?
            .into_iter()
            .filter(|p| {
                matches!(
                    p.status,
                    PlacementStatus::Alive
                        | PlacementStatus::Uncertain
                        | PlacementStatus::PresumedLost
                )
            })
            .collect();
        let raw_symbols = self
            .fetch_from_holders(block_id, &candidates, params, pauses)
            .await?;
        if raw_symbols.len() < k_eff {
            return Err(RestoreError::InsufficientSymbols {
                block: *block_id,
                got: raw_symbols.len(),
                need: k_eff,
            });
        }
        self.decode_and_decrypt(job, raw_symbols, params, encrypted_size, block_id)
            .await
    }

    /// The network tier under the budget: one permit for the decode and the decryption, then
    /// the exact plaintext — the permit cut to it, or released and taken again when it needs
    /// more (at most two waits per block). CPU work runs on the blocking pool (review A1).
    async fn decode_and_decrypt(
        &self,
        job: JobId,
        raw_symbols: Vec<Symbol>,
        params: &ErasureParams,
        encrypted_size: u64,
        block_id: &SourceBlockId,
    ) -> Result<Vec<u8>, RestoreError> {
        let budget = &self.config.mem_budget;
        let permit = self
            .acquire_memory(
                job,
                block_id,
                "network",
                mem_budget::estimate_restore_network(params.k, params.t),
            )
            .await?;
        let encoder = Arc::clone(&self.encoder);
        let (params, key, block) = (*params, self.config.epoch_key, *block_id);
        let join_err = |e: tokio::task::JoinError| {
            RestoreError::DecodeFailed(block, format!("decode task failed: {e}"))
        };
        let (decrypted, permit) = tokio::task::spawn_blocking(move || {
            decode_decrypt_stage(
                &permit,
                encoder.as_ref(),
                raw_symbols,
                &params,
                encrypted_size,
                &key,
                &block,
            )
            .map(|d| (d, permit))
        })
        .await
        .map_err(join_err)??;

        let need = mem_budget::estimate_restore_plaintext(
            decrypted.compressed.len() as u64,
            decrypted.plaintext_len,
        )
        .min(budget.total_bytes());
        let mut permit = permit;
        if need <= permit.bytes() {
            permit.shrink_to(need);
        } else {
            // The plaintext needs more than the decode held: let go first, then wait again
            // (J12: no second permit in the hand). The compressed block stays outside the budget
            // meanwhile (≤ E, the class of the symbols of a waiting block, A19).
            debug!(
                block = %block_id,
                plaintext_mib = decrypted.plaintext_len >> 20,
                "restore: regrant for plaintext"
            );
            drop(permit);
            permit = self
                .acquire_memory(job, block_id, "plaintext", need)
                .await?;
        }
        tokio::task::spawn_blocking(move || {
            let r = plaintext_stage(&permit, &block, decrypted);
            // The permit dies here, before the plaintext reaches the writer (J14).
            drop(permit);
            r
        })
        .await
        .map_err(join_err)?
    }

    /// Extract one file from decoded plaintext and write to staging directory.
    ///
    /// Validates the record path before writing (prevents path traversal from any
    /// source — normal restore, DR blobs, or malicious peers).
    pub(crate) fn extract_and_write_file(
        &self,
        record: &FileRecord,
        version: &FileVersion,
        block_type: &SourceBlockType,
        plaintext: &[u8],
        writer: &StagingWriter,
    ) -> Result<(), RestoreError> {
        #[cfg(test)]
        self.before_write();
        let file_bytes = member_bytes(block_type, plaintext, record, version)?;

        // Validate the record path from DB — must pass even for DR-sourced records.
        let validated =
            viaticum_core::path_safety::validate_record_path(&record.path).map_err(|e| {
                RestoreError::PathUnsafe {
                    path: record.path.clone(),
                    source: e,
                }
            })?;

        let published = writer.write_file_published(&validated, file_bytes)?;

        debug!(
            src = %record.path,
            dst = ?published.path,
            method = published.method.as_str(),
            "wrote restored file to staging"
        );
        Ok(())
    }
}
