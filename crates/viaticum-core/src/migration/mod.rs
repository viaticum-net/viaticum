// Migration: Wave-8 cached reliability fields backfill.
//
// Runs unconditionally at daemon startup (after DB open, before workers start).
// Idempotent: running twice produces identical stored state because the computation
// is deterministic given the same Placement and PeerRecord data.

use crate::commitment::{HolderProfile, compute_commitment, eviction_risk};
use crate::config::DEFAULT_IMPORTANCE;
use crate::constants::{
    DECODE_OVERHEAD, OVERHEAD_BASE, OVERHEAD_SCALE, P_WINDOW_WEEKS, SECS_PER_WEEK,
};
use crate::db::{Db, DbError};
use crate::reliability::{
    BlockReliabilityInput, HolderReliabilityInput, block_reliability, target_reliability,
};
use crate::types::{PlacementStatus, Timestamp};

#[cfg(test)]
mod tests;

/// Error type for migration operations.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// DB-level failure — returned only if `list_all_source_blocks` fails.
    /// Per-block read/write errors are handled internally (skipped, logged).
    #[error("db error: {0}")]
    Db(#[from] DbError),
}

/// Migrate all `SourceBlockRecord` rows to populate the Wave-8 cached fields:
/// `importance`, `current_alive`, `current_reliability`, `target_reliability`,
/// `last_attempted_at`, `last_pool_signature`.
///
/// Runs unconditionally at daemon startup (after DB open, before workers start).
/// Idempotent: running twice produces identical stored state.
///
/// # Returns
///
/// The count of block records processed (not just those updated).
///
/// # Errors
///
/// Returns `MigrationError::Db` only if `list_all_source_blocks` fails (fatal).
/// Per-block errors (bad placement data, missing peer record, reliability error)
/// are logged as WARN and skipped — the block retains stale/default cached fields.
pub fn migrate_block_records(db: &Db) -> Result<usize, MigrationError> {
    let started = std::time::Instant::now();
    let blocks = db.list_all_source_blocks()?;
    let total = blocks.len();

    if total == 0 {
        tracing::info!(
            blocks = 0,
            elapsed_ms = 0,
            "migrated SourceBlockRecord cached fields (schema v2)"
        );
        return Ok(0);
    }

    // Compute current protocol week number from wall clock.
    let now = Timestamp::now();
    let current_week = (now.0 / SECS_PER_WEEK) as u32;
    let window_start = current_week.saturating_sub(P_WINDOW_WEEKS.saturating_sub(1));

    let mut processed = 0usize;

    for block in &blocks {
        let block_id = &block.block_id;

        // Derive importance from stored overhead (inverse of encode formula).
        // overhead = OVERHEAD_BASE + importance * OVERHEAD_SCALE
        // => importance = (overhead - OVERHEAD_BASE) / OVERHEAD_SCALE
        let importance = block
            .overhead
            .map(|ov| ((ov - OVERHEAD_BASE) / OVERHEAD_SCALE).clamp(0.0, 1.0))
            .unwrap_or(DEFAULT_IMPORTANCE);

        let computed_target = target_reliability(importance);

        // Load placements for this block to compute current_alive and holder inputs.
        let placements = match db.list_placements_for_block(block_id) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(block = %block_id, err = %e,
                    "migration: list_placements_for_block failed, skipping block");
                processed += 1;
                continue;
            }
        };

        // BR2: count Alive + Uncertain placements.
        let current_alive = placements
            .iter()
            .filter(|p| {
                matches!(
                    p.status,
                    PlacementStatus::Alive | PlacementStatus::Uncertain
                )
            })
            .count() as u32;

        // Assemble per-holder inputs for block_reliability.
        let k_eff = block.k + DECODE_OVERHEAD;
        let mut holder_inputs: Vec<HolderReliabilityInput> = Vec::new();

        for placement in &placements {
            if !matches!(
                placement.status,
                PlacementStatus::Alive | PlacementStatus::Uncertain
            ) {
                continue;
            }

            let alive_symbols = placement.symbol_count();

            // Get survival probability from holder's commitment score.
            let survival_prob = compute_holder_survival_prob(
                db,
                &placement.holder_id,
                placement.consecutive_misses,
                window_start,
                current_week,
                now,
            );

            holder_inputs.push(HolderReliabilityInput {
                holder_id: placement.holder_id,
                alive_symbols,
                survival_prob,
            });
        }

        // Compute block reliability.
        let input = BlockReliabilityInput {
            block_id: *block_id,
            k_eff,
            holders: holder_inputs,
        };
        let current_reliability = match block_reliability(&input) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(block = %block_id, err = %e,
                    "migration: block_reliability failed, using 0.0");
                0.0
            }
        };

        // Write back the cached reliability fields. Worker cooldown is RAM-only
        // (B-4) and starts cleared, so there is nothing to migrate for it.
        if let Err(e) = db.update_block_cached_fields(
            block_id,
            importance,
            current_alive,
            current_reliability,
            computed_target,
        ) {
            tracing::warn!(block = %block_id, err = %e,
                "migration: update_block_cached_fields failed, skipping");
        }

        processed += 1;

        // BR7: log progress every 10 000 blocks. Use INFO so operators watching
        // startup at default log level see migration progress on large DBs.
        if processed.is_multiple_of(10_000) {
            tracing::info!(processed, total, "block record migration in progress");
        }
    }

    let elapsed_ms = started.elapsed().as_millis();
    tracing::info!(
        blocks = total,
        elapsed_ms,
        "migrated SourceBlockRecord cached fields (schema v2)"
    );

    Ok(processed)
}

/// Compute the survival probability for one holder.
///
/// Assembles a `HolderProfile` from the `PeerRecord` and PoS weekly history,
/// then computes `1.0 - eviction_risk(commitment_score)`.
///
/// Falls back to `0.5` (neutral prior) if the `PeerRecord` is missing.
fn compute_holder_survival_prob(
    db: &Db,
    holder_id: &crate::types::DeviceId,
    consecutive_misses: u32,
    window_start: u32,
    current_week: u32,
    now: Timestamp,
) -> f64 {
    let peer = match db.get_peer(holder_id) {
        Ok(Some(p)) => p,
        Ok(None) => {
            tracing::warn!(holder = %holder_id,
                "migration: PeerRecord missing, using survival_prob = 0.5");
            return 0.5;
        }
        Err(e) => {
            tracing::warn!(holder = %holder_id, err = %e,
                "migration: get_peer failed, using survival_prob = 0.5");
            return 0.5;
        }
    };

    // Aggregate PoS stats from the weekly table for the last P_WINDOW_WEEKS weeks.
    let (recent_challenges, recent_passes) = match db.list_pos_weekly_for_peer(holder_id) {
        Ok(entries) => {
            let mut challenged = 0u32;
            let mut passed = 0u32;
            for (week, entry) in &entries {
                if *week >= window_start && *week <= current_week {
                    challenged = challenged.saturating_add(entry.challenged);
                    passed = passed.saturating_add(entry.passed);
                }
            }
            (challenged, passed)
        }
        Err(e) => {
            tracing::warn!(holder = %holder_id, err = %e,
                    "migration: list_pos_weekly_for_peer failed, using neutral PoS stats");
            (0, 0)
        }
    };

    let profile = HolderProfile {
        holder_id: *holder_id,
        recent_challenges,
        recent_passes,
        consecutive_misses,
        // Disk pressure: cannot derive from PeerRecord without live data. Use neutral.
        offers_rejected_recently: false,
        drop_notice_sent_recently: false,
        // Eviction priority: use neutral (0.5 / 1.0 → priority_component returns 0.5).
        our_eviction_priority: 0.5,
        max_known_eviction_priority: 1.0,
        first_seen: peer.first_seen,
        now,
    };

    match compute_commitment(&profile) {
        Ok(score) => {
            let risk = eviction_risk(score);
            (1.0 - risk).clamp(0.0, 1.0)
        }
        Err(e) => {
            tracing::warn!(holder = %holder_id, err = %e,
                "migration: compute_commitment failed, using survival_prob = 0.5");
            0.5
        }
    }
}
