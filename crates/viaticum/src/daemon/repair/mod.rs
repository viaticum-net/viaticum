// RepairAgent: handles placement state transitions and periodic reliability scanning.
//
// Wave 11b: RepairAgent is retained as a thin wrapper around:
//   - Periodic reliability scanning (`reliability_scan`): corrects stale cached fields.
//   - Placement event handlers: `handle_symbol_dropped`, `handle_pos_nack`.
//
// Removed in Wave 11b:
//   - `run()`: the active repair loop (replaced by WorkPipeline worker).
//   - `repair_placement()`: encode+deliver to new holder (worker's job now).
//   - `deliver_repaired_symbols` / `deliver_repaired_symbols_direct`: delivery helpers.
//   - `scan_and_repair()`: scanning is now the worker's job via `next_work_item`.
//   - Blob rebuild helpers (`load_or_rebuild_blob`, `rebuild_blob_from_source`,
//     `fetch_and_rebuild_blob`): worker re-encodes from source files;
//     restore path calls `symbol_fetch::fetch_unbound_symbols` directly.
//
// The `RepairTrigger` channel is kept for backward compat with the Scheduler's
// PoS-failure notification path. `RepairAgent` no longer processes triggers directly;
// the trigger channel is forwarded by a relay task in `handle/mod.rs` to the
// WorkPipeline worker as a wake event.

use viaticum_core::db::{Db, DbError};
use viaticum_core::types::{
    DeviceId, PlacementStatus, SourceBlockId, SourceBlockStatus, Timestamp,
};

#[cfg(test)]
mod tests;

// ============================================================
// Public types
// ============================================================

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
    #[error("placement record missing from DB: block={0} holder={1}")]
    PlacementMissing(SourceBlockId, DeviceId),

    #[error("db error: {0}")]
    Db(#[from] DbError),
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
pub struct RepairAgent {
    db: Db,
}

impl RepairAgent {
    /// Create a new RepairAgent.
    pub fn new(db: Db) -> Self {
        RepairAgent { db }
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
