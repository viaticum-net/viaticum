// Budget planner: owner-side budget estimation and backup batch selection,
// holder-side disk pressure evaluation and eviction priority.
// All pure functions — no state, no DB, no async.

use crate::constants::{
    AGE_BONUS_CAP, AGE_BONUS_WEEKS, DEFAULT_SUCCESS_RATE, DROP_NOTICE_WINDOW_SECS, FREE_TIER_GB,
    OVERHEAD_BASE, OVERHEAD_SCALE, SECS_PER_WEEK, WEEKLY_STATS_WINDOW, WILLINGNESS_FACTOR,
};
use crate::types::{
    BudgetRecord, HoldingRecord, HoldingStatus, IdentityPub, SourceBlockId, Timestamp,
};

#[cfg(test)]
mod tests;

const SOFT_PRESSURE_THRESHOLD: f64 = 0.15;
const HARD_PRESSURE_THRESHOLD: f64 = 0.05;

// ============================================================
// Public types
// ============================================================

/// Owner-side budget snapshot.
#[derive(Debug, Clone)]
pub struct BudgetEstimate {
    /// GB confirmed stored (Active source blocks).
    pub committed_gb: f64,
    /// Conservative additional capacity estimate.
    pub headroom_gb: f64,
    /// GB of offer credit earned by acting as a holder, trust-weighted.
    pub earned_gb: f64,
    /// committed_gb + headroom_gb + earned_gb, floored at FREE_TIER_GB.
    pub total_gb: f64,
    /// Placement success rate used for this estimate.
    pub placement_success_rate: f64,
    /// How many GB of symbols to offer to the network this cycle.
    /// Always >= total_gb. Accounts for expected rejections.
    /// Formula: total_gb / placement_success_rate.max(0.2)
    pub offer_budget_gb: f64,
}

/// A file the owner wants to back up this cycle.
#[derive(Debug, Clone)]
pub struct BackupCandidate {
    pub path: String,
    pub importance: f64,
    /// GB this file will consume after erasure coding.
    pub required_gb: f64,
}

/// Result of select_backup_batch().
#[derive(Debug, Clone)]
pub struct BackupBatch {
    /// Selected files, sorted by importance descending.
    pub candidates: Vec<BackupCandidate>,
    pub total_required_gb: f64,
    /// Files that didn't fit in the budget (importance > 0 but excluded).
    pub deferred_count: usize,
}

/// Effective quota for held symbols (holder-i1, holder-i2).
///
/// `Unknown` is NEVER `Bytes(0)`: a node that could not read its free disk must not evict
/// everything down to the floor (holder-i2), while `Bytes(0)` — the disk is at or below the
/// reserve — must (holder-i1). "0" never means "no limit".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quota {
    /// The quota in bytes. `Bytes(0)` = no room at all (Critical).
    Bytes(u64),
    /// Free disk could not be read and no soft quota is set: refuse offers, evict nothing.
    Unknown,
    /// No limit at all. Never produced by [`compute_effective_quota`] — explicit, for tests.
    Unlimited,
}

/// Disk pressure level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskPressure {
    /// free_ratio >= 0.15. Normal.
    Normal,
    /// 0.05 <= free_ratio < 0.15, or the quota is `Unknown`. Stop accepting new symbols.
    Soft,
    /// free_ratio < 0.05, or the quota is `Bytes(0)` (Critical: evict down to the hard
    /// floor). Evict immediately.
    Hard,
}

/// Immediate eviction target (Phase 1: hard threshold crossed).
#[derive(Debug, Clone)]
pub struct EvictionTarget {
    pub source_block_id: SourceBlockId,
    pub owner_id: IdentityPub,
    pub priority: f64,
    /// Bytes freed by removing this entry.
    pub bytes: u64,
}

/// 7-day drop notice target (Phase 2: buffer).
#[derive(Debug, Clone)]
pub struct DropNoticeTarget {
    pub source_block_id: SourceBlockId,
    pub owner_id: IdentityPub,
    /// Unix timestamp: now_secs + DROP_NOTICE_WINDOW_SECS.
    pub deadline_secs: u64,
}

/// Full pressure evaluation result.
#[derive(Debug, Clone)]
pub struct PressureResult {
    pub pressure: DiskPressure,
    /// Phase 1: evict immediately (empty unless Hard).
    pub immediate_evictions: Vec<EvictionTarget>,
    /// Phase 2: send drop notice (empty unless Hard).
    pub drop_notices: Vec<DropNoticeTarget>,
    /// Total bytes freed by immediate_evictions.
    pub freed_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("source block not found: {0}")]
    BlockNotFound(SourceBlockId),
}

// ============================================================
// Public API
// ============================================================

/// Estimate current network budget from placement stats.
///
/// committed_bytes: result of Db::committed_bytes() — sum of encrypted_size
///                  for all Active source blocks (owner view, loaded by caller).
/// budget_record: last persisted BudgetRecord (caller loads from DB), None on first run.
/// earned_gb: trust-weighted offer credit earned by holding for others (caller computes
///            via held_contributions_gb_days + master_trust lookup). Zero for new nodes.
pub fn estimate_budget(
    committed_bytes: u64,
    budget_record: Option<&BudgetRecord>,
    earned_gb: f64,
) -> BudgetEstimate {
    let committed_gb = committed_bytes as f64 / 1_073_741_824.0;

    let placement_success_rate = match budget_record {
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
    let earned_gb = earned_gb.max(0.0);
    let total_gb = (committed_gb + headroom_gb + earned_gb).max(FREE_TIER_GB);
    let offer_budget_gb = total_gb / placement_success_rate.max(0.2);

    BudgetEstimate {
        committed_gb,
        headroom_gb,
        earned_gb,
        total_gb,
        placement_success_rate,
        offer_budget_gb,
    }
}

/// Compute trust-weighted earned offer credit from per-owner held contributions.
///
/// contributions: list of (owner_master_identity, gb_days) from
///                `Db::held_contributions_gb_days`.
/// master_trust: callback returning the MasterTrustRecord.combined score for the
///               given master (0.0 if unknown). Trust-weighting caps Sybil abuse
///               where many low-trust peers cross-hold among each other.
/// k_offer_days: conversion factor (days needed to earn 1 GB of offer credit).
pub fn compute_earned_offer_gb<F>(
    contributions: &[(crate::types::IdentityPub, f64)],
    master_trust: F,
    k_offer_days: f64,
) -> f64
where
    F: Fn(&crate::types::IdentityPub) -> f64,
{
    if k_offer_days <= 0.0 {
        return 0.0;
    }
    let max_trust = crate::constants::MAX_COMBINED_TRUST;
    let mut sum = 0.0_f64;
    for (master, gb_days) in contributions {
        let t = master_trust(master).max(0.0);
        let weight = (t / max_trust).min(1.0);
        sum += gb_days * weight;
    }
    sum / k_offer_days
}

/// Overhead factor for erasure coding: N/K for a given importance.
/// overhead = OVERHEAD_BASE + importance.clamp(0.0, 1.0) * OVERHEAD_SCALE
/// Range: 1.5 (importance=0) to 3.0 (importance=1).
pub fn overhead_factor(importance: f64) -> f64 {
    OVERHEAD_BASE + importance.clamp(0.0, 1.0) * OVERHEAD_SCALE
}

/// Select dirty files to back up this cycle.
///
/// candidates: (path, importance, size_bytes) for all dirty files.
/// budget_gb: total_gb from estimate_budget().
///
/// Algorithm:
///   1. Compute required_gb = size_bytes / 1_073_741_824 * overhead(importance)
///   2. Sort by importance DESC, then required_gb ASC (tie-break: smaller first)
///   3. Greedily include until Σ required_gb <= budget_gb
///   4. Files with importance == 0.0 are excluded silently (not deferred)
pub fn select_backup_batch(candidates: &[(String, f64, u64)], budget_gb: f64) -> BackupBatch {
    let mut eligible: Vec<(String, f64, f64)> = candidates
        .iter()
        .filter(|(_, importance, _)| *importance > 0.0)
        .map(|(path, importance, size_bytes)| {
            let required_gb = *size_bytes as f64 / 1_073_741_824.0 * overhead_factor(*importance);
            (path.clone(), *importance, required_gb)
        })
        .collect();

    eligible.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
    });

    let mut selected: Vec<BackupCandidate> = Vec::new();
    let mut total_required_gb = 0.0f64;
    let mut deferred_count = 0usize;

    for (path, importance, required_gb) in eligible {
        if total_required_gb + required_gb <= budget_gb {
            total_required_gb += required_gb;
            selected.push(BackupCandidate {
                path,
                importance,
                required_gb,
            });
        } else {
            deferred_count += 1;
        }
    }

    BackupBatch {
        candidates: selected,
        total_required_gb,
        deferred_count,
    }
}

/// Update rolling weekly stats with a new placement outcome.
///
/// record: existing BudgetRecord (loaded from DB), None if first run.
/// offered: how many symbol_offers were sent this week.
/// accepted: how many were accepted.
///
/// Returns updated BudgetRecord for caller to persist.
pub fn record_placement_outcome(
    record: Option<BudgetRecord>,
    offered: u32,
    accepted: u32,
) -> BudgetRecord {
    let mut r = record.unwrap_or(BudgetRecord {
        estimated_gb: 0.0,
        last_calculated: Timestamp(0),
        placement_success_rate: DEFAULT_SUCCESS_RATE,
        weekly_stats: Vec::new(),
    });

    r.weekly_stats.push((offered, accepted));
    while r.weekly_stats.len() > WEEKLY_STATS_WINDOW as usize {
        r.weekly_stats.remove(0);
    }

    let total_offered: u32 = r.weekly_stats.iter().map(|(o, _)| o).sum();
    let total_accepted: u32 = r.weekly_stats.iter().map(|(_, a)| a).sum();
    r.placement_success_rate = if total_offered == 0 {
        DEFAULT_SUCCESS_RATE
    } else {
        total_accepted as f64 / total_offered as f64
    };

    r
}

/// Compute the effective storage quota for held symbols (holder-i1..i3).
///
/// soft_quota:    user-configured cap in bytes. 0 = no soft cap (the disk bounds the quota).
/// disk_free:     free bytes on the data-dir filesystem (passed in by the caller — this
///                function does NOT query the OS); `None` = the disk could not be read.
/// used_holdings: bytes of held symbols, the SAME number (one snapshot per tick) the caller
///                then passes to [`evaluate_pressure`] / [`should_reject_offers`] as `used`.
/// disk_reserve:  free bytes to keep on the filesystem. Typically
///                DEFAULT_DISK_RESERVE_BYTES (20 GB).
///
/// Formula (holder-i3): `disk_free` already excludes our holdings, so they are added back —
/// counted once, the equilibrium is `disk_free₀ − reserve`, not half of it:
///   Some(free): avail = (free + used_holdings) − reserve (saturating at 0)
///               soft == 0 → Bytes(avail), else Bytes(soft.min(avail))
///   None:       soft > 0  → Bytes(soft) (holder-i2: work by the soft quota)
///               soft == 0 → Unknown
pub fn compute_effective_quota(
    soft_quota: u64,
    disk_free: Option<u64>,
    used_holdings: u64,
    disk_reserve: u64,
) -> Quota {
    match disk_free {
        Some(free) => {
            let avail = free
                .saturating_add(used_holdings)
                .saturating_sub(disk_reserve);
            if soft_quota == 0 {
                Quota::Bytes(avail)
            } else {
                Quota::Bytes(soft_quota.min(avail))
            }
        }
        None if soft_quota > 0 => Quota::Bytes(soft_quota),
        None => Quota::Unknown,
    }
}

/// Evaluate disk pressure and compute eviction targets.
///
/// quota:            effective quota (call compute_effective_quota first).
///                   `Bytes(0)` = no room at all (Critical, holder-i1): Hard, every holding
///                   above the `hard_quota_bytes` floor is evicted.
///                   `Unknown` = Soft (holder-i2): offers refused, nothing evicted.
///                   `Unlimited` = Normal (tests only).
/// hard_quota_bytes: eviction floor. Never evict if remaining usage would
///                   drop below this. 0 = disabled (no floor).
/// used_bytes:       current bytes used by all held symbols — the same snapshot as the
///                   quota's `used_holdings` (holder-i3).
/// holdings:         all HoldingRecord entries (caller loads from DB).
/// owner_trust:      closure providing combined trust score for an owner.
/// now_secs:         current Unix timestamp.
pub fn evaluate_pressure(
    quota: Quota,
    hard_quota_bytes: u64,
    used_bytes: u64,
    holdings: &[HoldingRecord],
    owner_trust: impl Fn(&IdentityPub) -> f64,
    now_secs: u64,
) -> PressureResult {
    let (deficit_bytes, buffer_bytes) = match quota {
        Quota::Unlimited => return no_eviction(DiskPressure::Normal),
        Quota::Unknown => return no_eviction(DiskPressure::Soft),
        // Critical (holder-i1): no room at all — evict down to the hard floor.
        Quota::Bytes(0) => (used_bytes, 0),
        Quota::Bytes(quota_bytes) => {
            let free_bytes = quota_bytes.saturating_sub(used_bytes);
            let free_ratio = free_bytes as f64 / quota_bytes as f64;
            if free_ratio >= SOFT_PRESSURE_THRESHOLD {
                return no_eviction(DiskPressure::Normal);
            }
            if free_ratio >= HARD_PRESSURE_THRESHOLD {
                return no_eviction(DiskPressure::Soft);
            }
            // Hard pressure: evict to bring free space back up to SOFT_PRESSURE_THRESHOLD.
            let target_free_bytes = (SOFT_PRESSURE_THRESHOLD * quota_bytes as f64) as u64;
            (
                target_free_bytes.saturating_sub(free_bytes),
                (0.05 * quota_bytes as f64) as u64,
            )
        }
    };

    struct Candidate<'a> {
        record: &'a HoldingRecord,
        priority: f64,
    }

    let mut candidates: Vec<Candidate<'_>> = holdings
        .iter()
        .map(|record| {
            let trust = owner_trust(&record.owner_id);
            let priority =
                eviction_priority(record.importance, trust, record.received_at, now_secs);
            // MarkedForDelete entries get priority 0.0 so they are evicted first.
            let priority = if record.status == HoldingStatus::MarkedForDelete {
                0.0f64.min(priority)
            } else {
                priority
            };
            Candidate { record, priority }
        })
        .collect();

    candidates.sort_by(|a, b| {
        a.priority
            .partial_cmp(&b.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut immediate_evictions: Vec<EvictionTarget> = Vec::new();
    let mut drop_notices: Vec<DropNoticeTarget> = Vec::new();
    let mut freed_bytes = 0u64;
    let mut phase2_freed = 0u64;
    let mut phase1_done = false;

    for candidate in &candidates {
        if !phase1_done {
            if freed_bytes < deficit_bytes {
                let projected_used = used_bytes
                    .saturating_sub(freed_bytes)
                    .saturating_sub(candidate.record.total_bytes);
                if hard_quota_bytes > 0 && projected_used < hard_quota_bytes {
                    continue;
                }
                freed_bytes += candidate.record.total_bytes;
                immediate_evictions.push(EvictionTarget {
                    source_block_id: candidate.record.source_block_id,
                    owner_id: candidate.record.owner_id,
                    priority: candidate.priority,
                    bytes: candidate.record.total_bytes,
                });
                if freed_bytes >= deficit_bytes {
                    phase1_done = true;
                }
            } else {
                phase1_done = true;
                if phase2_freed < buffer_bytes {
                    phase2_freed += candidate.record.total_bytes;
                    drop_notices.push(DropNoticeTarget {
                        source_block_id: candidate.record.source_block_id,
                        owner_id: candidate.record.owner_id,
                        deadline_secs: now_secs + DROP_NOTICE_WINDOW_SECS,
                    });
                }
            }
        } else if phase2_freed < buffer_bytes {
            phase2_freed += candidate.record.total_bytes;
            drop_notices.push(DropNoticeTarget {
                source_block_id: candidate.record.source_block_id,
                owner_id: candidate.record.owner_id,
                deadline_secs: now_secs + DROP_NOTICE_WINDOW_SECS,
            });
        } else {
            break;
        }
    }

    PressureResult {
        pressure: DiskPressure::Hard,
        immediate_evictions,
        drop_notices,
        freed_bytes,
    }
}

/// A pressure result that evicts nothing and sends no notice.
fn no_eviction(pressure: DiskPressure) -> PressureResult {
    PressureResult {
        pressure,
        immediate_evictions: Vec::new(),
        drop_notices: Vec::new(),
        freed_bytes: 0,
    }
}

/// Compute eviction priority for a single holding entry (pure).
///
/// priority = importance × trust_of_owner × (1 + age_bonus)
/// age_bonus = min(weeks_stored / AGE_BONUS_WEEKS, AGE_BONUS_CAP)
///
/// Higher priority = keep longer. Lower priority = evict first.
pub fn eviction_priority(
    importance: f64,
    trust_of_owner: f64,
    received_at: Timestamp,
    now_secs: u64,
) -> f64 {
    let weeks_stored = if now_secs > received_at.0 {
        (now_secs - received_at.0) as f64 / SECS_PER_WEEK as f64
    } else {
        0.0
    };
    let age_bonus = (weeks_stored / AGE_BONUS_WEEKS).min(AGE_BONUS_CAP);
    importance * trust_of_owner * (1.0 + age_bonus)
}

/// Returns true when the holder must refuse new symbol_offer messages: disk usage at or
/// above the soft threshold, no room at all (`Bytes(0)`, holder-i1) or an unknown quota
/// (holder-i2). `used_bytes` is the same snapshot as the quota's `used_holdings`.
pub fn should_reject_offers(quota: Quota, used_bytes: u64) -> bool {
    let quota_bytes = match quota {
        Quota::Unlimited => return false,
        Quota::Unknown | Quota::Bytes(0) => return true,
        Quota::Bytes(n) => n,
    };
    let free_bytes = quota_bytes.saturating_sub(used_bytes);
    let free_ratio = free_bytes as f64 / quota_bytes as f64;
    free_ratio < SOFT_PRESSURE_THRESHOLD
}
