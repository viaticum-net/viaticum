// Block-level restore work: decode one block (rebuild from the owner's source, else
// fetch from holders), and write one file of it into staging.

use std::sync::Arc;

use tracing::{debug, error};
use viaticum_core::erasure::Symbol;
use viaticum_core::types::{
    ErasureParams, FileRecord, FileVersion, PlacementStatus, SourceBlockId, SourceBlockType,
    SymbolPlacement,
};

use super::no_answer::NoAnswerPauses;
use super::{RestoreCoordinator, RestoreError, pipeline};
use crate::daemon::backup::rebuild::RebuildScope;
use crate::daemon::restore::staging::StagingWriter;

impl RestoreCoordinator {
    /// Decode one source block.
    ///
    /// Strategy (2-tier, post-Wave-11b):
    ///   1. Rebuild the stored blob from the owner's own source files and re-encode
    ///      the symbols we need locally. No symbols are persisted on disk anymore.
    ///   2. If the rebuild path is unavailable (e.g. a source file is gone), fall back
    ///      to fetching symbols from holders over the network — no deadline on the
    ///      block (restore-i12), rounds nobody answered retried from the job's pause
    ///      budget `pauses` (restore-i26), abandoned only on the daemon's cancel token.
    ///
    /// Decrypts and decompresses the decoded data before returning.
    // К-b3 / К-b5: the local tier takes a permit and skips the re-encode (T4); until then its
    // `encode_raw` is outside the budget (clippy `disallowed-methods`).
    #[allow(clippy::disallowed_methods)]
    pub(crate) async fn decode_block_local(
        &self,
        block_id: &SourceBlockId,
        params: &ErasureParams,
        encrypted_size: u64,
        pauses: &mut NoAnswerPauses,
    ) -> Result<Vec<u8>, RestoreError> {
        let k_eff = params.k_eff as usize;

        // 1. Rebuild from the owner's source files. A4 / Wave 11b: an empty
        // placement set is not an error — a freshly backed-up block has no
        // placements yet and is still restorable from its source.
        if let Some(block_record) = self.db.get_source_block(block_id)?
            && let Ok(stored_blob) = crate::daemon::backup::pipeline::rebuild_source_blob(
                &self.db,
                &block_record,
                &self.config.epoch_key,
                // Local tier: no recheck, any Present record (hash-checked reads), no
                // source file above this machine's size limit read.
                &RebuildScope::default().with_max_source_bytes(self.config.max_source_bytes),
            )
            .await
        {
            let params_for_encode = block_record.erasure_params();
            let encoder = Arc::clone(&self.encoder);
            let needed = k_eff as u32;
            match tokio::task::spawn_blocking(move || {
                encoder.encode_raw(&stored_blob, &params_for_encode, 0, needed)
            })
            .await
            {
                Ok(Ok(raws)) => {
                    debug!(
                        block = %block_id,
                        symbols = raws.len(),
                        "restore: rebuilt symbols from source files (Wave 11b path)"
                    );
                    return self
                        .decode_and_decrypt(raws, params, encrypted_size, block_id)
                        .await;
                }
                _ => {
                    debug!(block = %block_id, "restore: encode from rebuilt blob failed, falling back to network");
                }
            }
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
        self.decode_and_decrypt(raw_symbols, params, encrypted_size, block_id)
            .await
    }

    /// Erasure decode + decrypt + decompress: CPU-heavy, run on the blocking pool
    /// so the runtime keeps serving (review A1).
    // К-b3: the network tier takes a permit around the decode; until then it is outside the budget
    // (clippy `disallowed-methods`).
    #[allow(clippy::disallowed_methods)]
    async fn decode_and_decrypt(
        &self,
        raw_symbols: Vec<Symbol>,
        params: &ErasureParams,
        encrypted_size: u64,
        block_id: &SourceBlockId,
    ) -> Result<Vec<u8>, RestoreError> {
        let encoder = Arc::clone(&self.encoder);
        let params = *params;
        let key = self.config.epoch_key;
        let block = *block_id;
        tokio::task::spawn_blocking(move || {
            let padded = encoder
                .decode(&raw_symbols, &params)
                .map_err(|e| RestoreError::DecodeFailed(block, e.to_string()))?;
            if padded.len() < encrypted_size as usize {
                return Err(RestoreError::DecodeFailed(
                    block,
                    format!(
                        "decoded block ({} bytes) smaller than encrypted_size ({encrypted_size})",
                        padded.len()
                    ),
                ));
            }
            pipeline::decrypt_and_decompress(&padded[..encrypted_size as usize], &key).map_err(
                |e| {
                    error!(block = %block, "decrypt_and_decompress failed: {e}");
                    RestoreError::DecryptionFailed(block)
                },
            )
        })
        .await
        .map_err(|e| RestoreError::DecodeFailed(block, format!("decode task failed: {e}")))?
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
        let file_bytes = match block_type {
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
                    })?
            }
            SourceBlockType::Single => plaintext.to_vec(),
        };

        // Validate the record path from DB — must pass even for DR-sourced records.
        let validated =
            viaticum_core::path_safety::validate_record_path(&record.path).map_err(|e| {
                RestoreError::PathUnsafe {
                    path: record.path.clone(),
                    source: e,
                }
            })?;

        let published = writer.write_file_published(&validated, &file_bytes)?;

        debug!(
            src = %record.path,
            dst = ?published.path,
            method = published.method.as_str(),
            "wrote restored file to staging"
        );
        Ok(())
    }
}
