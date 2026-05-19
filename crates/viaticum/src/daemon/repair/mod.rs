// RepairAgent: handles placement state transitions and periodic reliability scanning.
//
// Wave 11b: RepairAgent is retained as a thin wrapper around:
//   - Periodic reliability scanning (`reliability_scan`): corrects stale cached fields.
//   - Placement event handlers: `handle_symbol_dropped`, `handle_pos_nack`.
//   - Blob rebuild helpers: `load_or_rebuild_blob`, `rebuild_blob_from_source`,
//     `fetch_and_rebuild_blob` (used by DR/restore path).
//
// Removed in Wave 11b:
//   - `run()`: the active repair loop (replaced by WorkPipeline worker).
//   - `repair_placement()`: encode+deliver to new holder (worker's job now).
//   - `deliver_repaired_symbols` / `deliver_repaired_symbols_direct`: delivery helpers.
//   - `scan_and_repair()`: scanning is now the worker's job via `next_work_item`.
//
// The `RepairTrigger` channel is kept for backward compat with the Scheduler's
// PoS-failure notification path. `RepairAgent` no longer processes triggers directly;
// the trigger channel is forwarded by a relay task in `handle/mod.rs` to the
// WorkPipeline worker as a wake event.

use std::sync::Arc;

use viaticum_core::db::{Db, DbError};
use viaticum_core::erasure::ErasureEncoder;
use viaticum_core::types::{
    DeviceId, IdentityPub, PlacementStatus, SourceBlockId, SourceBlockStatus, Timestamp, hex_encode,
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
    /// (Legacy: used by `load_or_rebuild_blob` block.bin fast path — blocks no longer written
    ///  after Wave 11b, but kept for compatibility with any existing block.bin files.)
    pub source_blocks_dir: std::path::PathBuf,

    /// Directory for raw symbol files.
    /// (Legacy: raw/{esi}.bin files no longer written after Wave 11b.)
    pub symbols_dir: std::path::PathBuf,

    /// Epoch key for re-deriving binding keys.
    pub epoch_key: [u8; 32],

    /// This node's master identity (for signing SymbolOffer).
    pub own_identity: IdentityPub,

    /// Master signing key (Ed25519). When Some: use SymbolOffer/Accept/Transfer flow.
    /// When None: encode symbols but skip network delivery.
    pub master_signing_key: Option<ed25519_dalek::SigningKey>,

    /// libp2p swarm handle. When Some: deliver repaired symbols over network.
    pub swarm: Option<Arc<crate::daemon::network::swarm::SwarmHandle>>,

    /// Per-peer rejection backoff.
    pub peer_backoff: Option<Arc<crate::daemon::peer_backoff::PeerBackoff>>,
}

/// Trigger message for the Scheduler → WorkPipeline relay.
///
/// The Scheduler sends these when PoS fails (placement Lost). In Wave 11b, these
/// are forwarded by a relay task in `handle/mod.rs` to the WorkPipeline worker
/// as a `WorkEvent::DirtyFileEnqueued` wake signal.
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

/// Error type for repair operations.
#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("source block file not found: {0}")]
    SourceBlockMissing(SourceBlockId),

    #[error("source block record missing from DB: {0}")]
    RecordMissing(SourceBlockId),

    #[error("placement record missing from DB: block={0} holder={1}")]
    PlacementMissing(SourceBlockId, DeviceId),

    #[error("erasure encode failed: {0}")]
    EncodeFailed(String),

    /// No viable holder found.
    #[error("no suitable holder for block {0}: {1}")]
    NoSuitableHolder(SourceBlockId, viaticum_core::placement::PlacementError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("delivery failed for block {0} to holder {1}: {2}")]
    DeliveryFailed(SourceBlockId, DeviceId, String),
}

// ============================================================
// RepairAgent
// ============================================================

/// RepairAgent: thin wrapper around periodic reliability scanning and event handlers.
///
/// In Wave 11b, active repair (encode + deliver to new holder) is handled by
/// the WorkPipeline worker. RepairAgent retains:
///   - `reliability_scan()`: corrects stale `current_alive` / `current_reliability` cached fields.
///   - `handle_symbol_dropped`, `handle_pos_nack`: mark placement Lost + W11a hook.
///   - `load_or_rebuild_blob`: used by DR/restore path.
pub struct RepairAgent {
    db: Db,
    config: RepairConfig,
    encoder: Arc<dyn ErasureEncoder>,
}

impl RepairAgent {
    /// Create a new RepairAgent.
    pub fn new(db: Db, config: RepairConfig, encoder: Arc<dyn ErasureEncoder>) -> Self {
        RepairAgent {
            db,
            config,
            encoder,
        }
    }

    /// Periodic reliability scan: corrects stale cached fields for all active blocks.
    ///
    /// For each Active block, counts actual Alive placements and recomputes
    /// `current_alive` and `current_reliability`. If below target, updates DB so
    /// the WorkPipeline worker will pick it up on the next tick.
    ///
    /// Returns the number of blocks whose cached fields were updated.
    ///
    /// This is a safety net: W11a hooks cover runtime transitions, but the periodic
    /// scan catches any drift from out-of-order events or legacy records.
    pub async fn reliability_scan(&self) -> usize {
        let blocks = match self.db.list_all_source_blocks() {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("reliability_scan: list_all_source_blocks failed: {e}");
                return 0;
            }
        };
        let mut updated = 0usize;
        for block in &blocks {
            if block.status != SourceBlockStatus::Active {
                continue;
            }
            // Delegate to the proper per-holder trust path (W11a).
            // `recompute_and_persist_block_cached_fields` reads actual Alive placements,
            // computes per-holder trust from DB, and updates the cached fields atomically.
            // This is the correct path — it avoids the hardcoded 0.9 neutral estimate.
            let old_alive = block.current_alive;
            crate::daemon::processor::recompute_and_persist_block_cached_fields(
                &self.db,
                &block.block_id,
            );
            // Re-read to detect drift.
            match self.db.get_source_block(&block.block_id) {
                Ok(Some(refreshed)) => {
                    if refreshed.current_alive != old_alive
                        || (refreshed.current_reliability - block.current_reliability).abs() > 0.001
                    {
                        tracing::debug!(
                            block_id = %block.block_id,
                            old_alive,
                            new_alive = refreshed.current_alive,
                            "reliability_scan: corrected cached fields"
                        );
                        updated += 1;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(
                        block_id = %block.block_id,
                        err = %e,
                        "reliability_scan: re-read after recompute failed"
                    );
                }
            }
        }
        if updated > 0 {
            tracing::info!(updated, "reliability_scan: corrected {} blocks", updated);
        }
        updated
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

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Load block.bin from disk, or rebuild it from source files, or fetch it
    /// from holders over the network — in that order.
    ///
    /// Used by the DR/restore path. After Wave 11b, block.bin is never written,
    /// so this falls through to source-file rebuild or network fetch immediately.
    pub async fn load_or_rebuild_blob(
        &self,
        block_id: &SourceBlockId,
    ) -> Result<Vec<u8>, RepairError> {
        let block_file_path = self
            .config
            .source_blocks_dir
            .join(hex_encode(&block_id.0))
            .join("block.bin");

        // (1) block.bin fast path (legacy — never written after Wave 11b).
        match tokio::fs::read(&block_file_path).await {
            Ok(data) => return Ok(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(block_id = %block_id, "block.bin not found (expected after Wave 11b), rebuilding from source");
            }
            Err(e) => return Err(RepairError::Io(e)),
        }

        let block_record = self
            .db
            .get_source_block(block_id)?
            .ok_or(RepairError::RecordMissing(*block_id))?;

        // (2) Rebuild from source files.
        match self.rebuild_blob_from_source(block_id, &block_record).await {
            Ok(stored) => {
                tracing::info!(block_id = %block_id, "repair: rebuilt blob from source files");
                return Ok(stored);
            }
            Err(e) => {
                tracing::warn!(
                    block_id = %block_id,
                    "repair: local rebuild failed ({e}); falling back to fetch from holders"
                );
            }
        }

        // (3) Network fallback: fetch from holders and decode.
        self.fetch_and_rebuild_blob(block_id, &block_record).await
    }

    /// Re-run the backup pipeline (read source files → compress → encrypt)
    /// and verify the resulting blob's hash equals `block_id`.
    pub async fn rebuild_blob_from_source(
        &self,
        block_id: &SourceBlockId,
        block_record: &viaticum_core::types::SourceBlockRecord,
    ) -> Result<Vec<u8>, RepairError> {
        let plaintext =
            crate::daemon::backup::packing::rebuild_plaintext_from_db(&self.db, block_record)
                .map_err(|e| RepairError::EncodeFailed(format!("rebuild plaintext: {e}")))?;

        let epoch_key = self.config.epoch_key;
        let expected_id = *block_id;

        let stored = tokio::task::spawn_blocking(move || {
            crate::daemon::backup::pipeline::compress_and_encrypt(&plaintext, &epoch_key)
        })
        .await
        .map_err(|e| RepairError::EncodeFailed(e.to_string()))?
        .map_err(|e| RepairError::EncodeFailed(e.to_string()))?;

        let rebuilt_id: [u8; 32] = *blake3::hash(&stored).as_bytes();
        if rebuilt_id != expected_id.0 {
            return Err(RepairError::EncodeFailed(format!(
                "rebuilt blob hash {} != expected block_id {}",
                hex_encode(&rebuilt_id),
                hex_encode(&expected_id.0),
            )));
        }
        Ok(stored)
    }

    /// Fetch k_eff unbound symbols from Alive holders, decode, truncate to
    /// `encrypted_size` — yielding the same ciphertext that was originally stored.
    async fn fetch_and_rebuild_blob(
        &self,
        block_id: &SourceBlockId,
        block_record: &viaticum_core::types::SourceBlockRecord,
    ) -> Result<Vec<u8>, RepairError> {
        let swarm = match self.config.swarm.as_ref() {
            Some(s) => s,
            None => {
                return Err(RepairError::EncodeFailed(
                    "no swarm configured; cannot fetch from holders".to_string(),
                ));
            }
        };

        let encrypted_size = block_record.encrypted_size.ok_or_else(|| {
            RepairError::EncodeFailed(format!(
                "block {block_id} has no encrypted_size (legacy record); cannot fetch and rebuild"
            ))
        })?;
        let params = block_record.erasure_params();
        let k_eff = params.k_eff as usize;

        let placements = self.db.list_placements_for_block(block_id)?;
        let reachable: Vec<_> = placements
            .into_iter()
            .filter(|p| {
                matches!(
                    p.status,
                    viaticum_core::types::PlacementStatus::Alive
                        | viaticum_core::types::PlacementStatus::Uncertain
                        | viaticum_core::types::PlacementStatus::PresumedLost
                )
            })
            .collect();

        if reachable.is_empty() {
            return Err(RepairError::EncodeFailed(format!(
                "no reachable placements for block {block_id}; cannot fetch"
            )));
        }

        tracing::info!(
            block_id = %block_id,
            reachable = reachable.len(),
            k_eff,
            "repair: fetching symbols from holders to rebuild lost blob"
        );

        let unbound = crate::daemon::symbol_fetch::fetch_unbound_symbols(
            swarm,
            &self.encoder,
            block_id,
            &reachable,
            k_eff,
        )
        .await
        .map_err(|e| RepairError::EncodeFailed(format!("fetch_unbound_symbols: {e}")))?;

        let encoder = Arc::clone(&self.encoder);
        let expected_id = *block_id;
        let stored = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, RepairError> {
            let padded = encoder
                .decode(&unbound, &params)
                .map_err(|e| RepairError::EncodeFailed(format!("decode: {e}")))?;

            if padded.len() < encrypted_size as usize {
                return Err(RepairError::EncodeFailed(format!(
                    "decoded block ({} bytes) smaller than encrypted_size ({})",
                    padded.len(),
                    encrypted_size
                )));
            }
            let stored = padded[..encrypted_size as usize].to_vec();

            let rebuilt_id: [u8; 32] = *blake3::hash(&stored).as_bytes();
            if rebuilt_id != expected_id.0 {
                return Err(RepairError::EncodeFailed(format!(
                    "fetched blob hash {} != expected block_id {}",
                    hex_encode(&rebuilt_id),
                    hex_encode(&expected_id.0),
                )));
            }
            Ok(stored)
        })
        .await
        .map_err(|e| RepairError::EncodeFailed(e.to_string()))??;

        tracing::info!(
            block_id = %block_id,
            "repair: rebuilt blob from holder symbols (network fallback)"
        );
        Ok(stored)
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

        if placement.status == PlacementStatus::Lost
            || placement.status == PlacementStatus::Deleting
        {
            return Ok(());
        }

        let mut updated = placement;
        updated.status = PlacementStatus::Lost;
        updated.consecutive_misses = 0;
        self.db.upsert_placement(&updated)?;

        // Recompute cached fields after successful upsert (best-effort).
        crate::daemon::processor::recompute_and_persist_block_cached_fields(&self.db, block_id);

        tracing::info!(
            block_id = %block_id,
            holder_id = %holder_id,
            "placement marked Lost (explicit drop/nack)"
        );

        Ok(())
    }
}
