// BudgetPlanner: estimates network storage budget and selects files for backup.
// Also decides which held shards to evict under disk pressure (holder role).
// Pure logic module: reads from DB, returns decisions. No network, no I/O.
// See docs/protocol/overview.md §2.8 and docs/tasks/budget.md for full spec.

use crate::constants::{
    AGE_BONUS_CAP, AGE_BONUS_WEEKS, DEFAULT_SUCCESS_RATE, DROP_NOTICE_WINDOW_SECS,
    HARD_PRESSURE_THRESHOLD, SECS_PER_WEEK, SOFT_PRESSURE_THRESHOLD, UNKNOWN_OWNER_TRUST_FLOOR,
    WEEKLY_STATS_WINDOW, WILLINGNESS_FACTOR,
};
use crate::db::{Db, DbError};
use crate::trust::{TrustEngine, TrustError};
use crate::types::{
    BudgetRecord, ErasureTier, FileType, IdentityPub, ShardId, ShardStatus, Timestamp,
};

#[cfg(test)]
mod tests;

// ============================================================
// Public structs
// ============================================================

/// Snapshot of the estimated network budget (owner role).
#[derive(Debug, Clone)]
pub struct BudgetEstimate {
    /// Total GB currently stored for us in confirmed network shards.
    pub committed_gb: f64,
    /// Additional GB we can reasonably expect to place (conservative estimate).
    pub headroom_gb: f64,
    /// committed_gb + headroom_gb.
    pub total_gb: f64,
    /// When this estimate was computed (Unix seconds).
    pub calculated_at: u64,
    /// Recent shard_offer accept rate [0.0, 1.0].
    pub placement_success_rate: f64,
}

/// A file selected for backup in this sync cycle (owner role).
#[derive(Debug, Clone)]
pub struct BackupCandidate {
    pub path: String,
    pub importance: f64,
    /// Projected GB this file will consume in the network after erasure coding.
    pub required_gb: f64,
}

/// Output of budget-aware file selection (owner role).
#[derive(Debug, Clone)]
pub struct BackupBatch {
    /// Files to back up this cycle, sorted by importance descending.
    pub candidates: Vec<BackupCandidate>,
    /// Total GB the batch will consume.
    pub total_required_gb: f64,
    /// Files that are dirty, have importance >= 0.1, but did not fit in the budget.
    pub deferred_count: usize,
}

/// Current disk pressure level for holder-side eviction decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskPressure {
    /// free_ratio >= 0.15. Normal operation.
    Normal,
    /// 0.05 <= free_ratio < 0.15. Stop accepting new shards.
    Soft,
    /// free_ratio < 0.05. Evict immediately.
    Hard,
}

/// A shard to evict immediately (Phase 1: hard threshold crossed).
#[derive(Debug, Clone)]
pub struct EvictionTarget {
    pub shard_id: ShardId,
    pub owner: IdentityPub,
    /// Eviction priority at time of selection. Lower = evict first.
    pub priority: f64,
}

/// A shard to send shard_drop_notice for (Phase 2: 7-day buffer).
#[derive(Debug, Clone)]
pub struct DropNoticeTarget {
    pub shard_id: ShardId,
    pub owner: IdentityPub,
    /// Unix timestamp: now + 7 days.
    pub deadline: u64,
}

/// Result of evaluating disk pressure and computing eviction lists.
#[derive(Debug, Clone)]
pub struct PressureResult {
    pub pressure: DiskPressure,
    /// Shards to evict immediately (Phase 1). Empty unless pressure == Hard.
    pub immediate_evictions: Vec<EvictionTarget>,
    /// Shards to send shard_drop_notice (Phase 2). Empty unless pressure == Hard.
    pub drop_notices: Vec<DropNoticeTarget>,
    /// GB that would be freed by immediate_evictions (Phase 1 only).
    pub freed_gb: f64,
}

// ============================================================
// Error
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("trust error: {0}")]
    Trust(#[from] TrustError),

    #[error("shard not found: {0:?}")]
    ShardNotFound(ShardId),
}

// ============================================================
// BudgetPlanner
// ============================================================

pub struct BudgetPlanner {
    db: Db,
    trust: TrustEngine,
}

impl BudgetPlanner {
    pub fn new(db: Db, trust: TrustEngine) -> Self {
        BudgetPlanner { db, trust }
    }

    // ----------------------------------------------------------
    // Owner role: budget estimation
    // ----------------------------------------------------------

    /// Estimate the current network budget.
    ///
    /// committed_gb = sum of size_bytes for all shards with status == Stored.
    /// headroom_gb  = committed_gb * placement_success_rate * WILLINGNESS_FACTOR.
    /// total_gb     = committed_gb + headroom_gb.
    ///
    /// Persists updated BudgetRecord to the budget table.
    pub fn estimate_budget(&self) -> Result<BudgetEstimate, BudgetError> {
        // Sum size_bytes of all stored shards (owner's confirmed placements).
        let all_shards = self.db.list_all_shards()?;
        let committed_bytes: u64 = all_shards
            .iter()
            .filter(|s| s.status == ShardStatus::Stored)
            .map(|s| {
                // ShardRecord does not carry size_bytes directly.
                // We count shards by shard_id but we need size from HoldingRecord (holder view).
                // For the owner's estimate, we infer size from unit context.
                // However, ShardRecord has no size_bytes field. See the DB schema:
                // ShardRecord fields: shard_id, unit_id, shard_index, holder_id, status,
                //   last_verified, offered_at, stored_at.
                // Size is only on HoldingRecord (holder view).
                //
                // Resolution: committed_gb is a best-effort estimate based on what
                // we know. Since we don't store size on ShardRecord, we estimate
                // using the unit's size_bytes / rs_n (size per shard) when available.
                // For now, if no size info is available, count 0 (estimate is conservative).
                //
                // Practical path: look up UnitRecord for size_bytes.
                let _ = s; // used below via unit lookup
                0u64 // placeholder, real logic below
            })
            .sum();
        // The above approach won't work cleanly in a single map. Use a proper loop.
        let _ = committed_bytes; // discard placeholder

        let mut committed_bytes_total: u64 = 0;
        for shard in &all_shards {
            if shard.status != ShardStatus::Stored {
                continue;
            }
            // Look up the unit to get size information.
            // unit.size_bytes / unit.rs_n ≈ bytes per shard.
            if let Some(unit) = self.db.get_unit(&shard.unit_id)? {
                if unit.rs_n > 0 {
                    // Each shard is approximately size_bytes / rs_n bytes.
                    committed_bytes_total += unit.size_bytes / u64::from(unit.rs_n);
                }
            }
        }

        let committed_gb = committed_bytes_total as f64 / 1_073_741_824.0;

        // Get the cached placement success rate.
        let budget_record = self.db.get_budget()?;
        let placement_success_rate = match &budget_record {
            Some(r) if !r.weekly_stats.is_empty() => {
                let total_offered: u32 = r.weekly_stats.iter().map(|(o, _)| o).sum();
                let total_accepted: u32 = r.weekly_stats.iter().map(|(_, a)| a).sum();
                if total_offered == 0 {
                    DEFAULT_SUCCESS_RATE
                } else {
                    total_accepted as f64 / total_offered as f64
                }
            }
            _ => DEFAULT_SUCCESS_RATE,
        };

        let headroom_gb = committed_gb * placement_success_rate * WILLINGNESS_FACTOR;
        let total_gb = committed_gb + headroom_gb;
        let now = Timestamp::now();

        // Persist updated record.
        let updated = BudgetRecord {
            estimated_gb: total_gb,
            last_calculated: now,
            placement_success_rate,
            weekly_stats: budget_record
                .as_ref()
                .map(|r| r.weekly_stats.clone())
                .unwrap_or_default(),
        };
        self.db.set_budget(&updated)?;

        Ok(BudgetEstimate {
            committed_gb,
            headroom_gb,
            total_gb,
            calculated_at: now.0,
            placement_success_rate,
        })
    }

    // ----------------------------------------------------------
    // Owner role: backup batch selection
    // ----------------------------------------------------------

    /// Select dirty files to back up in this sync cycle.
    ///
    /// Steps:
    ///   1. Query all dirty files.
    ///   2. Compute required_gb = file_size_bytes / 1_073_741_824 * overhead_factor(importance).
    ///   3. Sort by importance descending (ties: smaller file first to fit more).
    ///   4. Include files until Σ required_gb <= budget_gb.
    ///   5. Files below importance 0.1 are silently skipped (not counted as deferred).
    pub fn select_backup_batch(&self, budget_gb: f64) -> Result<BackupBatch, BudgetError> {
        let dirty_paths = self.db.list_dirty_files()?;
        let mut eligible: Vec<(String, f64, f64)> = Vec::new(); // (path, importance, required_gb)

        for path in dirty_paths {
            let record = match self.db.get_file(&path)? {
                Some(r) => r,
                None => continue,
            };
            // Files with importance < 0.1 are never backed up; skip silently.
            if ErasureTier::from_importance(record.importance).is_none() {
                continue;
            }
            let overhead = Self::overhead_factor(record.importance);
            let required_gb = record.size_bytes as f64 / 1_073_741_824.0 * overhead;
            eligible.push((record.path, record.importance, required_gb));
        }

        // Sort: importance descending; tie-break by required_gb ascending (smaller file first).
        eligible.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    a.2.partial_cmp(&b.2)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });

        let mut candidates: Vec<BackupCandidate> = Vec::new();
        let mut total_required_gb = 0.0f64;
        let mut deferred_count = 0usize;

        for (path, importance, required_gb) in eligible {
            if total_required_gb + required_gb <= budget_gb {
                total_required_gb += required_gb;
                candidates.push(BackupCandidate {
                    path,
                    importance,
                    required_gb,
                });
            } else {
                deferred_count += 1;
            }
        }

        Ok(BackupBatch {
            candidates,
            total_required_gb,
            deferred_count,
        })
    }

    // ----------------------------------------------------------
    // Owner role: overhead factor (pure function)
    // ----------------------------------------------------------

    /// Return the erasure coding overhead factor (n/k) for a given importance.
    ///
    /// importance >= 0.8  →  15/5 = 3.0  (High tier)
    /// importance >= 0.4  →  10/5 = 2.0  (Medium tier)
    /// importance >= 0.1  →   7/5 = 1.4  (Low tier)
    /// importance < 0.1   →  0.0  (not backed up)
    pub fn overhead_factor(importance: f64) -> f64 {
        match ErasureTier::from_importance(importance) {
            Some(tier) => tier.overhead(),
            None => 0.0,
        }
    }

    // ----------------------------------------------------------
    // Holder role: disk pressure evaluation
    // ----------------------------------------------------------

    /// Evaluate disk pressure and compute eviction targets.
    ///
    /// quota_gb: storage quota from config (not total disk size).
    /// used_gb:  GB currently used by all held shards.
    /// now_secs: current Unix timestamp (seconds).
    ///
    /// Returns PressureResult with lists of shards to evict / drop-notice.
    pub fn evaluate_pressure(
        &self,
        quota_gb: f64,
        used_gb: f64,
        now_secs: u64,
    ) -> Result<PressureResult, BudgetError> {
        let free_gb = quota_gb - used_gb;
        let free_ratio = if quota_gb <= 0.0 {
            1.0
        } else {
            free_gb / quota_gb
        };

        if free_ratio >= SOFT_PRESSURE_THRESHOLD {
            return Ok(PressureResult {
                pressure: DiskPressure::Normal,
                immediate_evictions: Vec::new(),
                drop_notices: Vec::new(),
                freed_gb: 0.0,
            });
        }

        if free_ratio >= HARD_PRESSURE_THRESHOLD {
            return Ok(PressureResult {
                pressure: DiskPressure::Soft,
                immediate_evictions: Vec::new(),
                drop_notices: Vec::new(),
                freed_gb: 0.0,
            });
        }

        // Hard pressure: evict to bring free_ratio back to SOFT_PRESSURE_THRESHOLD.
        // deficit_gb = how much total free space we want to have (not how much to free).
        // Stopping condition: (current_free + freed_so_far) >= deficit_gb.
        // deficit_gb = SOFT_PRESSURE_THRESHOLD * quota_gb - (quota_gb - used_gb)
        //            = target_free_gb_to_reach - current_free_gb
        // But we compare (current_free + freed) >= deficit_gb, per spec example.
        let target_free_gb = SOFT_PRESSURE_THRESHOLD * quota_gb;
        let deficit_gb = target_free_gb - free_gb;

        // Phase 2 buffer target: 5% of quota beyond the soft threshold.
        let buffer_gb = 0.05 * quota_gb;

        // Load all held shards and compute eviction priorities.
        let held = self.db.list_all_holding()?;

        // Build (shard_id, owner, priority, size_gb, is_system) tuples.
        struct ShardCandidate {
            shard_id: ShardId,
            owner: IdentityPub,
            priority: f64,
            size_gb: f64,
        }

        let mut candidates: Vec<ShardCandidate> = Vec::new();
        for record in &held {
            // System shards are never evicted.
            if record.file_type == FileType::System {
                continue;
            }
            let priority = self.priority_for_held_shard(
                record.shard_id,
                record.importance,
                &record.owner_pub,
                record.received_at,
                now_secs,
            )?;
            let size_gb = record.size_bytes as f64 / 1_073_741_824.0;
            candidates.push(ShardCandidate {
                shard_id: record.shard_id,
                owner: record.owner_pub,
                priority,
                size_gb,
            });
        }

        // Sort ascending by priority: lowest priority first (evict first).
        candidates.sort_by(|a, b| {
            a.priority
                .partial_cmp(&b.priority)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut immediate_evictions: Vec<EvictionTarget> = Vec::new();
        let mut drop_notices: Vec<DropNoticeTarget> = Vec::new();
        let mut freed_gb = 0.0f64;
        let mut phase2_freed = 0.0f64;
        let mut phase1_done = false;

        for candidate in candidates {
            if !phase1_done {
                // Stopping condition per spec: stop when (initial_free + freed) >= deficit_gb.
                // That is, stop when total_free_after_eviction >= deficit_gb.
                if (free_gb + freed_gb) < deficit_gb {
                    freed_gb += candidate.size_gb;
                    immediate_evictions.push(EvictionTarget {
                        shard_id: candidate.shard_id,
                        owner: candidate.owner,
                        priority: candidate.priority,
                    });
                    // After adding this shard, check if we've met the target.
                    if (free_gb + freed_gb) >= deficit_gb {
                        phase1_done = true;
                    }
                } else {
                    phase1_done = true;
                    // This candidate goes to Phase 2.
                    if phase2_freed < buffer_gb {
                        phase2_freed += candidate.size_gb;
                        drop_notices.push(DropNoticeTarget {
                            shard_id: candidate.shard_id,
                            owner: candidate.owner,
                            deadline: now_secs + DROP_NOTICE_WINDOW_SECS,
                        });
                    } else {
                        break;
                    }
                }
            } else if phase2_freed < buffer_gb {
                phase2_freed += candidate.size_gb;
                drop_notices.push(DropNoticeTarget {
                    shard_id: candidate.shard_id,
                    owner: candidate.owner,
                    deadline: now_secs + DROP_NOTICE_WINDOW_SECS,
                });
            } else {
                break;
            }
        }

        Ok(PressureResult {
            pressure: DiskPressure::Hard,
            immediate_evictions,
            drop_notices,
            freed_gb,
        })
    }

    // ----------------------------------------------------------
    // Holder role: eviction priority
    // ----------------------------------------------------------

    /// Compute eviction priority for a held shard (by shard_id lookup).
    ///
    /// priority = importance × trust_of_owner × (1 + age_bonus)
    /// age_bonus = min(weeks_stored / AGE_BONUS_WEEKS, AGE_BONUS_CAP)
    ///
    /// Higher priority = keep longer; lower priority = evict first.
    /// System shards always return f64::MAX.
    pub fn eviction_priority(
        &self,
        shard_id: ShardId,
        now_secs: u64,
    ) -> Result<f64, BudgetError> {
        let record = self
            .db
            .get_holding(&shard_id)?
            .ok_or(BudgetError::ShardNotFound(shard_id))?;

        if record.file_type == FileType::System {
            return Ok(f64::MAX);
        }

        self.priority_for_held_shard(
            shard_id,
            record.importance,
            &record.owner_pub,
            record.received_at,
            now_secs,
        )
    }

    // ----------------------------------------------------------
    // Owner role: record placement outcome
    // ----------------------------------------------------------

    /// Record placement outcome to update the rolling weekly stats.
    ///
    /// Appends (offered, accepted) to weekly_stats; drops oldest when len > WEEKLY_STATS_WINDOW.
    /// Also recomputes placement_success_rate from the window.
    pub fn record_placement_outcome(
        &self,
        offered: u32,
        accepted: u32,
    ) -> Result<(), BudgetError> {
        let mut budget_record = self.db.get_budget()?.unwrap_or(BudgetRecord {
            estimated_gb: 0.0,
            last_calculated: Timestamp::now(),
            placement_success_rate: DEFAULT_SUCCESS_RATE,
            weekly_stats: Vec::new(),
        });

        budget_record.weekly_stats.push((offered, accepted));
        while budget_record.weekly_stats.len() > WEEKLY_STATS_WINDOW as usize {
            budget_record.weekly_stats.remove(0);
        }

        // Recompute placement_success_rate from the window.
        let total_offered: u32 = budget_record.weekly_stats.iter().map(|(o, _)| o).sum();
        let total_accepted: u32 = budget_record.weekly_stats.iter().map(|(_, a)| a).sum();
        budget_record.placement_success_rate = if total_offered == 0 {
            DEFAULT_SUCCESS_RATE
        } else {
            total_accepted as f64 / total_offered as f64
        };

        self.db.set_budget(&budget_record)?;
        Ok(())
    }

    // ----------------------------------------------------------
    // Holder role: should reject offers
    // ----------------------------------------------------------

    /// Returns true when disk usage is at or above the soft threshold (85% used).
    /// Caller should refuse shard_offer messages when this returns true.
    pub fn should_reject_offers(&self, quota_gb: f64, used_gb: f64) -> bool {
        if quota_gb <= 0.0 {
            return true;
        }
        let free_ratio = (quota_gb - used_gb) / quota_gb;
        free_ratio < SOFT_PRESSURE_THRESHOLD
    }

    // ----------------------------------------------------------
    // Internal helpers
    // ----------------------------------------------------------

    /// Compute eviction priority given shard parameters (no DB lookup).
    /// Used by both evaluate_pressure (inline) and eviction_priority (by shard_id).
    fn priority_for_held_shard(
        &self,
        _shard_id: ShardId,
        importance: f64,
        owner_pub: &IdentityPub,
        received_at: Timestamp,
        now_secs: u64,
    ) -> Result<f64, BudgetError> {
        let trust_of_owner = match self.trust.score(owner_pub) {
            Ok(score) => score.combined.clamp(0.0, 1.0),
            Err(TrustError::UnknownPeer(_)) => UNKNOWN_OWNER_TRUST_FLOOR,
            Err(e) => return Err(BudgetError::Trust(e)),
        };

        let weeks_stored = if now_secs > received_at.0 {
            (now_secs - received_at.0) as f64 / SECS_PER_WEEK as f64
        } else {
            0.0
        };
        let age_bonus = (weeks_stored / AGE_BONUS_WEEKS).min(AGE_BONUS_CAP);
        let priority = importance * trust_of_owner * (1.0 + age_bonus);
        Ok(priority)
    }
}
