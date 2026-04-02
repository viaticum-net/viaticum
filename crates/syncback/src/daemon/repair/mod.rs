// RepairAgent: scans for Lost/PresumedLost placements and regenerates symbols locally.
//
// Phase 2.5 scope: symbol generation only (no network delivery). Symbols are
// written to symbols_dir and placement status is updated to Alive in DB.
// Network delivery of repaired symbols is out of scope until Phase 3.

use std::sync::Arc;

use syncback_core::constants::DECODE_OVERHEAD;
use syncback_core::db::{Db, DbError};
use syncback_core::erasure::ErasureEncoder;
use syncback_core::types::{
    hex_encode, DeviceId, ErasureParams, FileId, IdentityPub, PlacementStatus, SourceBlockId,
    SourceBlockType, Timestamp,
};

#[cfg(test)]
mod tests;

// ============================================================
// Public types
// ============================================================

/// Configuration for the RepairAgent.
#[derive(Debug, Clone)]
pub struct RepairConfig {
    /// Directory where local source block blobs are stored.
    /// Each file is named by its SourceBlockId hex: `{source_blocks_dir}/{hex(block_id)}`
    /// In Phase 2.5, this is `{symbols_dir}/{hex(block_id)}/block.bin` (BackupCoordinator output).
    pub source_blocks_dir: std::path::PathBuf,
    /// Directory where generated repair symbols are written.
    /// Format: `{symbols_dir}/{hex(block_id)}/{hex(holder_id)}/{esi}.sym`
    pub symbols_dir: std::path::PathBuf,
    /// Epoch key for deriving binding key (same as BackupCoordinator uses).
    pub epoch_key: [u8; 32],
    /// This node's identity (unused in Phase 2.5, reserved for Phase 3).
    pub own_identity: IdentityPub,
}

/// One repair job: regenerate symbols for a Lost/PresumedLost placement.
#[derive(Debug, Clone)]
pub struct RepairJob {
    pub source_block_id: SourceBlockId,
    pub holder_id: DeviceId,
    pub file_id: FileId,
}

/// Outcome of executing one repair job.
#[derive(Debug)]
pub struct RepairOutcome {
    pub job: RepairJob,
    pub symbols_written: u32,
    pub new_status: PlacementStatus,
}

/// Error type for repair operations.
#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("source block file not found: {0}")]
    SourceBlockMissing(SourceBlockId),

    #[error("source file deleted from disk, skipping repair: {0}")]
    SourceFileDeleted(String),

    #[error("rebuild stored blob failed: {0}")]
    RebuildFailed(String),

    #[error("source block record missing from DB: {0}")]
    RecordMissing(SourceBlockId),

    #[error("placement record missing from DB: block={0} holder={1}")]
    PlacementMissing(SourceBlockId, DeviceId),

    #[error("erasure encode failed: {0}")]
    EncodeFailed(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("db error: {0}")]
    Db(#[from] DbError),
}

/// Trigger message sent to the RepairAgent via channel.
#[derive(Debug)]
pub enum RepairTrigger {
    /// Immediate repair of a specific placement.
    RepairNow {
        block_id: SourceBlockId,
        holder_id: DeviceId,
    },
    /// Full scan (same as periodic).
    ScanAll,
}

// ============================================================
// RepairAgent
// ============================================================

/// RepairAgent: scans for Lost/PresumedLost placements and regenerates symbols locally.
pub struct RepairAgent {
    db: Db,
    config: RepairConfig,
    encoder: Arc<dyn ErasureEncoder>,
}

impl RepairAgent {
    /// Create a new RepairAgent.
    pub fn new(db: Db, config: RepairConfig, encoder: Arc<dyn ErasureEncoder>) -> Self {
        RepairAgent { db, config, encoder }
    }

    /// Scan DB for placements needing repair and execute all repair jobs.
    ///
    /// Returns the number of placements successfully repaired.
    /// Individual placement failures are logged at ERROR but do not abort the scan.
    pub async fn scan_and_repair(&self) -> usize {
        let needing_repair = match self.db.list_placements_needing_repair() {
            Ok(list) => list,
            Err(e) => {
                tracing::error!("scan_and_repair: list_placements_needing_repair failed: {e}");
                return 0;
            }
        };

        if needing_repair.is_empty() {
            tracing::debug!("scan_and_repair: no placements needing repair");
            return 0;
        }

        tracing::info!(count = needing_repair.len(), "scan_and_repair: starting repair batch");

        let mut repaired = 0usize;
        for placement in &needing_repair {
            match self
                .repair_placement(&placement.source_block_id, &placement.holder_id)
                .await
            {
                Ok(outcome) => {
                    tracing::info!(
                        block_id = %outcome.job.source_block_id,
                        holder_id = %outcome.job.holder_id,
                        symbols_written = outcome.symbols_written,
                        "repair_placement: success"
                    );
                    repaired += 1;
                }
                Err(RepairError::SourceBlockMissing(bid)) => {
                    tracing::error!(
                        block_id = %bid,
                        "repair_placement: source block file missing, cannot repair locally"
                    );
                }
                Err(RepairError::SourceFileDeleted(ref path)) => {
                    tracing::info!(
                        path = %path,
                        "repair_placement: source file deleted, skipping (deletion pipeline will clean up)"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        block_id = %placement.source_block_id,
                        holder_id = %placement.holder_id,
                        "repair_placement: failed: {e}"
                    );
                }
            }
        }

        repaired
    }

    /// Repair a single placement: regenerate its symbols from local source data.
    ///
    /// Steps:
    /// 1. Read SourceBlockRecord from DB → get K, T.
    /// 2. Read SymbolPlacement from DB → get esi_ranges, binding_seed, holder_id.
    /// 3. Read source block file from source_blocks_dir.
    /// 4. Re-encode all ESIs in esi_ranges and write .sym files.
    /// 5. Update placement status to Alive in DB.
    pub async fn repair_placement(
        &self,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Result<RepairOutcome, RepairError> {
        // 1. Get SourceBlockRecord for K and T
        let block_record = self
            .db
            .get_source_block(block_id)?
            .ok_or(RepairError::RecordMissing(*block_id))?;

        // 2. Get SymbolPlacement for esi_ranges
        let mut placement = self
            .db
            .get_placement(block_id, holder_id)?
            .ok_or(RepairError::PlacementMissing(*block_id, *holder_id))?;

        // 3. Get stored blob: try block.bin first, then rebuild from source files.
        let block_file_path = self
            .config
            .source_blocks_dir
            .join(hex_encode(&block_id.0))
            .join("block.bin");

        let source_data = match tokio::fs::read(&block_file_path).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // block.bin cleaned up after delivery — rebuild from source files.
                self.rebuild_stored_blob(block_id, &block_record.block_type)
                    .await?
            }
            Err(e) => return Err(RepairError::Io(e)),
        };

        // 4. Build ErasureParams for encoding
        let k = block_record.k;
        let t = block_record.t;
        let params = ErasureParams {
            k,
            k_eff: k + DECODE_OVERHEAD,
            t,
            overhead: 1.5, // not used by encode, only affects n
            n: k * 4,      // safe over-estimate, not used by encode
        };

        // 5. For each ESI in placement.esi_ranges, encode and write symbol file
        let holder_hex = hex_encode(&holder_id.0);
        let sym_dir = self
            .config
            .symbols_dir
            .join(hex_encode(&block_id.0))
            .join(&holder_hex);

        tokio::fs::create_dir_all(&sym_dir).await.map_err(RepairError::Io)?;

        let mut symbols_written = 0u32;

        for &(start_esi, count) in &placement.esi_ranges {
            for i in 0..count {
                let esi = start_esi + i;

                // CPU-bound: wrap in spawn_blocking for large K
                let source_data_clone = source_data.clone();
                let params_clone = params;
                let block_id_clone = *block_id;
                let holder_id_clone = *holder_id;
                let encoder = Arc::clone(&self.encoder);

                let symbols = tokio::task::spawn_blocking(move || {
                    encoder.encode(
                        &source_data_clone,
                        &params_clone,
                        esi,
                        1,
                        &block_id_clone,
                        &holder_id_clone,
                    )
                })
                .await
                .map_err(|e| RepairError::EncodeFailed(e.to_string()))?
                .map_err(|e| RepairError::EncodeFailed(e.to_string()))?;

                let sym_path = sym_dir.join(format!("{esi}.sym"));
                tokio::fs::write(&sym_path, &symbols[0].data)
                    .await
                    .map_err(RepairError::Io)?;

                symbols_written += 1;
            }
        }

        // 6. Update placement in DB
        placement.status = PlacementStatus::Alive;
        placement.consecutive_misses = 0;
        placement.last_verified = None; // reset: no PoS yet for new symbols
        self.db.upsert_placement(&placement)?;

        Ok(RepairOutcome {
            job: RepairJob {
                source_block_id: *block_id,
                holder_id: *holder_id,
                file_id: placement.file_id,
            },
            symbols_written,
            new_status: PlacementStatus::Alive,
        })
    }

    /// Process an incoming SymbolDropped message — mark placement Lost.
    ///
    /// Idempotent: if placement is already Lost or Deleting, no-op.
    pub async fn handle_symbol_dropped(
        &self,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
        now: Timestamp,
    ) -> Result<(), RepairError> {
        self.mark_placement_lost(block_id, holder_id, now).await
    }

    /// Process an incoming PosNack message — mark placement Lost.
    ///
    /// Equivalent to handle_symbol_dropped from the owner's perspective.
    /// Idempotent: if placement is already Lost or Deleting, no-op.
    pub async fn handle_pos_nack(
        &self,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
        now: Timestamp,
    ) -> Result<(), RepairError> {
        self.mark_placement_lost(block_id, holder_id, now).await
    }

    /// Run as a periodic background task.
    ///
    /// Every scan_interval_secs, calls scan_and_repair().
    /// Also accepts repair triggers via the rx channel for immediate repairs.
    /// Exits cleanly when rx is dropped (channel closed).
    pub async fn run(
        self,
        scan_interval_secs: u64,
        mut rx: tokio::sync::mpsc::Receiver<RepairTrigger>,
    ) -> anyhow::Result<()> {
        use tokio::time::{interval, Duration, MissedTickBehavior};

        let mut timer = interval(Duration::from_secs(scan_interval_secs));
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    tracing::info!("RepairAgent: periodic scan triggered");
                    self.scan_and_repair().await;
                }
                maybe_trigger = rx.recv() => {
                    match maybe_trigger {
                        None => {
                            tracing::info!("RepairAgent: trigger channel closed, exiting");
                            break;
                        }
                        Some(RepairTrigger::ScanAll) => {
                            tracing::debug!("RepairAgent: ScanAll trigger received");
                            self.scan_and_repair().await;
                        }
                        Some(RepairTrigger::RepairNow { block_id, holder_id }) => {
                            tracing::debug!(
                                block_id = %block_id,
                                holder_id = %holder_id,
                                "RepairAgent: RepairNow trigger received"
                            );
                            if let Err(e) = self.repair_placement(&block_id, &holder_id).await {
                                tracing::error!("RepairNow failed: {e}");
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Rebuild the stored blob from source files (delegates to the free function).
    async fn rebuild_stored_blob(
        &self,
        block_id: &SourceBlockId,
        block_type: &SourceBlockType,
    ) -> Result<Vec<u8>, RepairError> {
        rebuild_stored_blob_for_block(&self.db, block_id, block_type, &self.config.epoch_key)
    }

    /// Mark a placement as Lost. Idempotent: no-op if already Lost or Deleting.
    async fn mark_placement_lost(
        &self,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
        _now: Timestamp,
    ) -> Result<(), RepairError> {
        let placement = self
            .db
            .get_placement(block_id, holder_id)?
            .ok_or(RepairError::PlacementMissing(*block_id, *holder_id))?;

        // Idempotent: already lost or deleting → no-op
        if placement.status == PlacementStatus::Lost
            || placement.status == PlacementStatus::Deleting
        {
            return Ok(());
        }

        let mut updated = placement;
        updated.status = PlacementStatus::Lost;
        updated.consecutive_misses = 0;
        self.db.upsert_placement(&updated)?;

        tracing::info!(
            block_id = %block_id,
            holder_id = %holder_id,
            "placement marked Lost (explicit drop/nack)"
        );

        Ok(())
    }
}

// ============================================================
// Helpers
// ============================================================

/// Rebuild the stored blob (encrypted+compressed) from original source files on disk.
///
/// Used by RepairAgent (to re-encode symbols) and Processor (for PoS verification)
/// when `block.bin` has been cleaned up after delivery.
///
/// For Pack blocks: reads all files from PackEntry.file_id, builds plaintext, compress+encrypt.
/// For Single blocks: finds the file via DB scan, reads raw bytes, compress+encrypt.
/// Verifies blake3 hash matches block_id.
pub fn rebuild_stored_blob_for_block(
    db: &Db,
    block_id: &SourceBlockId,
    block_type: &SourceBlockType,
    epoch_key: &[u8; 32],
) -> Result<Vec<u8>, RepairError> {
    use crate::daemon::backup::packing::build_plaintext;
    use crate::daemon::backup::pipeline::compress_and_encrypt;
    use crate::daemon::backup::QueuedFile;

    let plaintext = match block_type {
        SourceBlockType::Pack { entries } => {
            let mut files: Vec<(QueuedFile, Vec<u8>)> = Vec::with_capacity(entries.len());
            for entry in entries {
                let file_record = db.get_file_by_id(entry.file_id)
                    .map_err(|e| RepairError::RebuildFailed(format!("db lookup file {}: {e}", entry.file_id.0)))?
                    .ok_or_else(|| RepairError::RebuildFailed(format!("file {} not in DB", entry.file_id.0)))?;

                let data = match std::fs::read(&file_record.path) {
                    Ok(d) => d,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Err(RepairError::SourceFileDeleted(file_record.path.clone()));
                    }
                    Err(e) => return Err(RepairError::Io(e)),
                };

                let qf = QueuedFile {
                    path: file_record.path.clone(),
                    file_id: entry.file_id,
                    content_hash: [0u8; 32],
                    size_bytes: data.len() as u64,
                    category: syncback_core::types::FileCategory::Other,
                    importance: file_record.importance,
                };
                files.push((qf, data));
            }
            build_plaintext(&files)
        }
        SourceBlockType::Single => {
            let all_files = db.list_all_files()
                .map_err(|e| RepairError::RebuildFailed(format!("list_all_files: {e}")))?;
            let file_record = all_files.iter()
                .find(|f| f.versions.iter().any(|v| v.source_block_id == *block_id))
                .ok_or_else(|| RepairError::RebuildFailed(
                    format!("no file references block {block_id}")
                ))?;

            match std::fs::read(&file_record.path) {
                Ok(d) => d,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(RepairError::SourceFileDeleted(file_record.path.clone()));
                }
                Err(e) => return Err(RepairError::Io(e)),
            }
        }
    };

    let stored = compress_and_encrypt(&plaintext, epoch_key)
        .map_err(|e| RepairError::RebuildFailed(format!("compress_and_encrypt: {e}")))?;

    let hash: [u8; 32] = *blake3::hash(&stored).as_bytes();
    if hash != block_id.0 {
        return Err(RepairError::RebuildFailed(format!(
            "rebuilt blob hash {} != expected block_id {}",
            hex_encode(&hash),
            block_id
        )));
    }

    tracing::info!(
        block_id = %block_id,
        blob_bytes = stored.len(),
        "rebuilt stored blob from source files"
    );

    Ok(stored)
}

