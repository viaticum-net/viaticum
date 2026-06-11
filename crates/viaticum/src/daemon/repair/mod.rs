// RepairAgent: periodic reliability scanning.
//
// Wave 11b: RepairAgent is a thin wrapper around periodic reliability scanning
// (`reliability_scan`): it corrects stale `current_alive` / `current_reliability`
// cached fields so the WorkPipeline worker sees blocks that drifted below target.
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
// Removed in bucket C (PL-8a): `handle_symbol_dropped`, `handle_pos_nack`,
// `mark_placement_lost`. They duplicated the live `processor::mark_placement_lost`
// path (a drift risk) and had only test callers — every production mark-Lost goes
// through the processor.
//
// The `RepairTrigger` channel is kept as a wake signal. `RepairAgent` does not
// process triggers; the channel is drained by a relay task in `handle/mod.rs` that
// forwards every `RepairTrigger::Wake` to the WorkPipeline worker as a
// `WorkEvent::DirtyFileEnqueued`.

use viaticum_core::db::Db;
use viaticum_core::types::SourceBlockStatus;

#[cfg(test)]
mod tests;

// ============================================================
// Public types
// ============================================================

/// Wake signal for the Scheduler/processor → WorkPipeline relay.
///
/// Producers send this when a placement transitions to Lost (PoS fail/timeout,
/// long-absence sweep, immediate DropNotice). The relay task in `handle/mod.rs`
/// forwards every `Wake` to the WorkPipeline worker as a single
/// `WorkEvent::DirtyFileEnqueued` — the worker then rescans the DB and re-encodes
/// whatever is below target.
///
/// PL-8c: this is a unit variant on purpose. The earlier `RepairNow { block_id,
/// holder_id }` addressing was a dead contract — the consumer discarded the fields
/// and always sent a generic wake — and `ScanAll` (PL-8b) had no producer. The
/// trigger carries no payload because the worker is the sole repair authority and
/// derives all work from the DB, not from the wake.
#[derive(Debug)]
pub enum RepairTrigger {
    /// A placement became Lost somewhere — wake the worker to rescan + re-encode.
    Wake,
}

// ============================================================
// RepairAgent
// ============================================================

/// RepairAgent: thin wrapper around periodic reliability scanning.
///
/// In Wave 11b, active repair (encode + deliver to new holder) is handled by
/// the WorkPipeline worker. RepairAgent retains only `reliability_scan()`, which
/// corrects stale `current_alive` / `current_reliability` cached fields.
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
}
