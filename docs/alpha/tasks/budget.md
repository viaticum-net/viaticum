# Task Spec: budget.rs

Module in `crates/syncback-core/src/budget.rs`.

## Overview

BudgetPlanner answers two questions:

1. **How much network storage is available to the owner?** (budget_gb estimation)
2. **Which files should be backed up within that budget?** (importance-sorted cutoff)

As a holder, BudgetPlanner also decides which shards to evict under disk
pressure, using the eviction priority formula with hysteresis (Strategy E from
Exp 27).

BudgetPlanner is a pure logic module: reads from DB, returns decisions. No
network calls, no I/O. The daemon (Processor) acts on the decisions.

## Dependencies

- `types.rs` — `ShardId`, `UnitId`, `FileId`, `IdentityPub`, `ImportanceScore`
- `db.rs` — `Db`, queries over `files`, `shards`, `holding`, `peers`, `budget` tables
- `trust.rs` — `TrustEngine` (for `trust_of_owner` during eviction)
- `placement.rs` — `ErasureParams`, `PlacementEngine::erasure_params` (for overhead calculation)

## Public API

### Structs

```rust
/// The main budget planning engine.
pub struct BudgetPlanner {
    db: Db,
    trust: TrustEngine,
}

/// Snapshot of the estimated network budget.
#[derive(Debug, Clone)]
pub struct BudgetEstimate {
    /// Total GB the network is estimated to hold for us right now.
    pub committed_gb: f64,
    /// Additional GB we can reasonably expect to place.
    pub headroom_gb: f64,
    /// Combined budget (committed + headroom).
    pub total_gb: f64,
    /// When this estimate was computed (Unix seconds).
    pub calculated_at: u64,
    /// Recent accept rate 0.0–1.0 (accepted / offered in last 4 weeks).
    pub placement_success_rate: f64,
}

/// A file selected for backup in this sync cycle.
#[derive(Debug, Clone)]
pub struct BackupCandidate {
    pub file_id: FileId,
    pub importance: ImportanceScore,
    /// Projected GB this file will consume in the network after erasure coding.
    pub required_gb: f64,
}

/// Output of budget-aware file selection.
#[derive(Debug, Clone)]
pub struct BackupBatch {
    /// Files to back up this cycle, sorted by importance descending.
    pub candidates: Vec<BackupCandidate>,
    /// Total GB the batch will consume.
    pub total_required_gb: f64,
    /// Files that are dirty but did not fit in the budget.
    pub deferred_count: usize,
}

/// Current disk pressure level for holder-side eviction decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskPressure {
    /// >= 15% of quota free. Normal operation.
    Normal,
    /// < 15% but >= 5% free. Stop accepting new shards, warn user.
    Soft,
    /// < 5% free. Evict immediately, then issue drop notices.
    Hard,
}

/// A shard to evict immediately (Phase 1: hard threshold).
#[derive(Debug, Clone)]
pub struct EvictionTarget {
    pub shard_id: ShardId,
    pub owner: IdentityPub,
    /// Eviction priority at time of selection (lower = evict first).
    pub priority: f64,
}

/// A shard to send drop notice for (Phase 2: 7-day buffer).
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
    /// Shards to send shard_drop_notice for (Phase 2). Empty unless pressure == Hard.
    pub drop_notices: Vec<DropNoticeTarget>,
    /// GB that would be freed by immediate_evictions.
    pub freed_gb: f64,
}
```

### impl BudgetPlanner

```rust
impl BudgetPlanner {
    /// Create a new BudgetPlanner.
    pub fn new(db: Db, trust: TrustEngine) -> Self;

    /// Estimate the current network budget (owner role).
    ///
    /// Reads shards table (committed GB) and budget table (cached success rate).
    /// Returns an updated BudgetEstimate and persists it to the budget table.
    pub fn estimate_budget(&self) -> Result<BudgetEstimate, BudgetError>;

    /// Select dirty files to back up in this sync cycle (owner role).
    ///
    /// Steps:
    ///   1. Query all dirty files from files table.
    ///   2. For each file, compute required_gb = file_size_gb * overhead_factor(importance).
    ///   3. Sort by importance descending.
    ///   4. Include files until Σ required_gb <= budget_gb.
    ///   5. Files that do not fit → deferred.
    ///
    /// budget_gb: total GB available (from BudgetEstimate.total_gb).
    pub fn select_backup_batch(
        &self,
        budget_gb: f64,
    ) -> Result<BackupBatch, BudgetError>;

    /// Compute the overhead factor for a given importance (owner role).
    /// Returns n/k for the erasure tier.
    /// Pure function, no DB access.
    pub fn overhead_factor(importance: ImportanceScore) -> f64;

    /// Evaluate disk pressure and compute eviction targets (holder role).
    ///
    /// quota_gb: the storage quota from config (NOT total disk size).
    /// used_gb: GB currently used by held shards.
    ///
    /// Returns PressureResult indicating what action to take.
    ///
    /// Logic:
    ///   free_ratio = (quota_gb - used_gb) / quota_gb
    ///   if free_ratio >= 0.15 → Normal, no evictions
    ///   if free_ratio >= 0.05 → Soft, no evictions but stop accepting
    ///   if free_ratio < 0.05  → Hard:
    ///     Phase 1: compute immediate_evictions (lowest priority first)
    ///              evict until free_ratio >= 0.15 (soft threshold)
    ///     Phase 2: compute drop_notices for additional buffer
    ///              enough to bring free_ratio to ~20% after Phase 2 drains
    pub fn evaluate_pressure(
        &self,
        quota_gb: f64,
        used_gb: f64,
        now_secs: u64,
    ) -> Result<PressureResult, BudgetError>;

    /// Compute eviction priority for a held shard (holder role).
    ///
    /// eviction_priority = importance × trust_of_owner × (1 + age_bonus)
    /// age_bonus = min(weeks_stored / 26, 0.3)
    ///
    /// weeks_stored = (now_secs - received_at_secs) / SECS_PER_WEEK
    ///
    /// Returns priority in [0.0, ∞). Higher = keep longer, lower = evict first.
    pub fn eviction_priority(
        &self,
        shard_id: ShardId,
        now_secs: u64,
    ) -> Result<f64, BudgetError>;

    /// Record placement outcome to update success rate (owner role).
    ///
    /// accepted: number of shard_accept received this cycle.
    /// offered:  number of shard_offer sent this cycle.
    /// Persists to budget table.
    pub fn record_placement_outcome(
        &self,
        offered: u32,
        accepted: u32,
    ) -> Result<(), BudgetError>;

    /// Check whether disk pressure requires refusing new shard offers (holder role).
    /// Returns true if pressure is Soft or Hard (quota usage >= 85%).
    pub fn should_reject_offers(
        &self,
        quota_gb: f64,
        used_gb: f64,
    ) -> bool;
}
```

### Error Enum

```rust
#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("db error: {0}")]
    Db(#[from] redb::Error),

    #[error("trust error: {0}")]
    Trust(#[from] TrustError),

    #[error("shard not found: {0:?}")]
    ShardNotFound(ShardId),
}
```

## Types Required

From `types.rs`:

```rust
pub struct FileId(pub u64);
pub struct ShardId(pub [u8; 32]);
pub struct UnitId(pub [u8; 32]);
pub struct IdentityPub(pub [u8; 32]);

/// Importance score, clamped to [0.0, 1.0].
pub struct ImportanceScore(pub f64);

/// Held shard record (the `holding` table).
pub struct HoldingRecord {
    pub shard_id: ShardId,
    pub owner_pub: IdentityPub,
    pub importance: ImportanceScore,
    pub size_bytes: u64,
    pub state: HoldingState,
    pub received_at: u64,       // Unix seconds
    pub delete_requested_at: Option<u64>,
    pub drop_notice_deadline: Option<u64>,
}

pub enum HoldingState {
    Active,
    MarkedForDelete,
    DropNoticeSent,
}

/// File record (the `files` table).
pub struct FileRecord {
    pub file_id: FileId,
    pub path: String,            // UTF-8 path
    pub size_bytes: u64,
    pub importance: ImportanceScore,
    pub dirty: bool,
    pub current_unit_id: Option<UnitId>,
    pub last_backed_up: Option<u64>,
    pub backed_up: bool,
}

/// Budget singleton (the `budget` table, key = "budget").
pub struct BudgetRecord {
    pub estimated_gb: f64,
    pub last_calculated: u64,
    pub placement_success_rate: f64,
    /// Rolling window: (offered, accepted) per week for last 4 weeks.
    pub weekly_stats: Vec<(u32, u32)>,  // len <= 4
}
```

## DB Operations

### Tables read

**`holding`** table: `ShardId → HoldingRecord`
- `evaluate_pressure`: iterate all records to compute total used_gb and eviction priorities.
- `eviction_priority`: single lookup by `shard_id`.

**`files`** table: `FileId → FileRecord`
- `select_backup_batch`: iterate/query dirty files (dirty == true).

**`shards`** table: `ShardId → ShardRecord`
- `estimate_budget`: iterate shards with `status == Active` to compute committed_gb.
- ShardRecord fields needed: `holder_id`, `size_bytes`, `status`.

**`peers`** table: `IdentityPub → PeerRecord`
- `eviction_priority`: trust_of_owner lookup (via TrustEngine, not direct peer read).

**`budget`** table: `"budget" → BudgetRecord`
- `estimate_budget`, `record_placement_outcome`: read + write singleton.

### Tables written

**`budget`** table: `"budget" → BudgetRecord`
- Written by `estimate_budget` (update `estimated_gb`, `last_calculated`).
- Written by `record_placement_outcome` (update `placement_success_rate`, `weekly_stats`).

**`holding`** table: `ShardId → HoldingRecord`
- Written by `evaluate_pressure` via the caller (Processor), NOT by BudgetPlanner.
  BudgetPlanner returns `PressureResult` with lists; Processor updates holding records.

Note: BudgetPlanner is read-mostly. The only direct writes are to the `budget`
singleton table. All shard state changes go through Processor.

### Index tables read

**`dirty_files`** secondary index: `file_path → timestamp`
- `select_backup_batch`: use this index to efficiently enumerate dirty files
  instead of full scan of `files` table.

## Business Rules

### Owner-side: overhead factor

```
importance >= 0.8  →  n/k = 15/5 = 3.0
importance >= 0.4  →  n/k = 10/5 = 2.0
importance >= 0.1  →  n/k =  7/5 = 1.4
importance < 0.1   →  file is not backed up (overhead_factor returns 0.0)
```

`required_gb = file_size_bytes / 1_073_741_824.0 * overhead_factor(importance)`

### Owner-side: budget estimation

```
committed_gb = Σ size_bytes(shard) / 1e9
               for all shards in `shards` table with status == Active
               (these are shards we own, placed on partners)

headroom_gb = committed_gb * placement_success_rate * willingness_factor

willingness_factor = 0.5  (conservative: expect 50% of committed as new headroom)

total_gb = committed_gb + headroom_gb
```

`placement_success_rate` is a rolling average from `BudgetRecord.weekly_stats`:

```
success_rate = Σ accepted[i] / Σ offered[i]   over last 4 weeks
```

If `weekly_stats` is empty (first run), use `placement_success_rate = 0.5`
(pessimistic default: 50% acceptance expected).

### Owner-side: backup batch selection

Sort dirty files by importance descending (ties broken by file size descending
as tiebreaker — prefer smaller files to fit more items in budget).

Accumulate required_gb until budget_gb is exceeded. Files that don't fit are
returned as `deferred_count`.

Files with `importance < 0.1` are never included regardless of budget (they are
not backed up). They stay dirty but are silently skipped (not counted in
`deferred_count`).

### Holder-side: disk pressure thresholds

```
free_ratio = (quota_gb - used_gb) / quota_gb

free_ratio >= 0.15  →  DiskPressure::Normal
0.05 <= free_ratio < 0.15  →  DiskPressure::Soft
free_ratio < 0.05  →  DiskPressure::Hard
```

`used_gb` = sum of `size_bytes` of all shards in `holding` table with state !=
Deleted (Active, MarkedForDelete, DropNoticeSent all count as used space until
physically removed).

### Holder-side: eviction priority formula

```
eviction_priority = importance × trust_of_owner × (1 + age_bonus)
age_bonus = min(weeks_stored / 26.0, 0.3)
weeks_stored = (now_secs - received_at) / 604_800   (604800 = seconds per week)
```

`trust_of_owner` = `TrustEngine::score(owner_pub).value` clamped to [0.0, 1.0].
If owner is unknown (new peer with no trust history), use `trust_of_owner = 0.1`
(do not use 0 — that would cause their shards to always be evicted first, which
is unfair for new legitimate partners).

DECIDED: Unknown-owner trust floor = 0.1 (`UNKNOWN_OWNER_TRUST_FLOOR` in constants.rs).
For a normally operating new peer, 0.1 is more fair than 0.0.

### Holder-side: hysteresis (Strategy E from Exp 27)

Hysteresis prevents thrashing — a slightly-lower-priority shard should not
immediately replace a resident shard. Two components:

1. **Threshold H = 0.2**: when comparing a new shard_offer to the current
   lowest-priority held shard, accept only if:
   `new_priority > min_held_priority * (1 + H)` i.e. `new_priority > min_held_priority * 1.2`

2. **Age bonus**: already baked into eviction_priority via `age_bonus`. Resident
   shards accumulate age bonus over time, making them harder to evict.

Hysteresis is applied in `storage.rs` (Phase 2 module), NOT in BudgetPlanner.
BudgetPlanner provides the `eviction_priority` function that storage.rs uses
when evaluating whether to accept a new shard_offer in exchange for evicting.

For Phase 1 (budget.rs), only implement eviction_priority. Document the H=0.2
constant as `pub const EVICTION_HYSTERESIS: f64 = 0.2;` in this module.

### Holder-side: special cases (evaluated before the formula)

These are evaluated by Processor/Storage (Phase 2), but BudgetPlanner should
document them as the authoritative reference:

1. `MarkedForDelete` + cooldown expired (received_at + 4 weeks + delete_requested_at + 4 weeks ≤ now)
   → priority = 0.0 (evict immediately, owner asked for it).
   The 4-week owner cooldown + 4-week holder cooldown = 8 weeks total from owner's
   local delete to physical removal.

2. `HoldingState::Active` + owner I-score < 4 weeks in network + no PoS for > 7 days
   → "silent + low I-score" case → priority = 0.0.
   NOTE: This requires `weeks_in_network` from escrow module. For MVP, treat
   owners not seen in peers table as unknown; use trust_of_owner = 0.1 (not 0.0).

3. `file_type == FileType::System` (system state shards)
   → priority = f64::MAX (never evict, TTL 5 years).
   System shards are identified by `HoldingRecord.file_type == FileType::System`.

### Holder-side: Phase 1 and Phase 2 eviction

```
Phase 1 (immediate evictions):
  Target: free_ratio < 0.05. Evict until free_ratio reaches 0.15.
  deficit_gb = 0.15 * quota_gb - (quota_gb - used_gb)
  Sort held shards by eviction_priority ascending.
  Accumulate deficit_gb worth of shards → immediate_evictions.
  Do NOT evict MarkedForDelete shards still in cooldown (they'll be
  evicted naturally when cooldown expires).
  Do NOT evict system state shards (priority = MAX).

Phase 2 (drop notices):
  Target: build a 5% buffer beyond the soft threshold.
  buffer_gb = 0.05 * quota_gb
  Continue sorting from where Phase 1 left off.
  Accumulate buffer_gb worth of additional shards → drop_notices.
  Set deadline = now_secs + 7 * 24 * 3600 (7 days).
```

Total GB freed by Phase 1 = `PressureResult.freed_gb`.
Phase 2 shards are NOT freed immediately — they are only freed after 7 days.

### Weekly stats rolling window

`BudgetRecord.weekly_stats` is a `Vec<(offered, accepted)>` of length <= 4.
Each call to `record_placement_outcome` appends a new week's stats.
When len > 4, drop the oldest entry (front of vec).

DECIDED: `record_placement_outcome` is called once per weekly sync cycle
(aggregated totals for the week), not per shard.

## Test Scenarios

All tests use real redb via `testutil::test_db()`.

### 1. `overhead_factor_returns_correct_multiplier`

```
ImportanceScore(1.0) → 3.0
ImportanceScore(0.8) → 3.0  (boundary)
ImportanceScore(0.5) → 2.0
ImportanceScore(0.4) → 2.0  (boundary)
ImportanceScore(0.2) → 1.4
ImportanceScore(0.1) → 1.4  (boundary)
ImportanceScore(0.09)→ 0.0  (not backed up)
```

### 2. `select_backup_batch_sorts_by_importance_descending`

Setup: 5 dirty files with importances [0.3, 0.9, 0.1, 0.7, 0.5].
budget_gb = 100.0 (large, all fit).
Expected: candidates ordered [0.9, 0.7, 0.5, 0.3, 0.1].

### 3. `select_backup_batch_cutoff_at_budget`

Setup: 3 dirty files:
  file_A: size=10GB, importance=0.8, required_gb=30
  file_B: size=5GB,  importance=0.5, required_gb=10
  file_C: size=20GB, importance=0.1, required_gb=28
budget_gb = 40.0.
Expected: candidates = [file_A (30GB), file_B (10GB)] = 40GB total, deferred_count=1 (file_C).
NOTE: file ordering: A(0.8) > B(0.5) > C(0.1). A fits (30<=40), B fits (30+10=40<=40), C does not (40+28>40).

### 4. `select_backup_batch_skips_low_importance_silently`

Setup: 2 dirty files, importance=0.09 and importance=0.05. budget_gb=100.
Expected: BackupBatch { candidates: [], deferred_count: 0 }.
(Files below 0.1 are never included and not counted as deferred.)

### 5. `estimate_budget_uses_committed_plus_headroom`

Setup: DB has 3 active shards of size 10GB each (committed = 30GB).
budget record: placement_success_rate=0.8, weekly_stats non-empty.
headroom_factor = 0.8 * 0.5 = 0.4.
headroom = 30 * 0.4 = 12.
total_gb = 30 + 12 = 42.
Expected: BudgetEstimate { committed_gb: 30.0, headroom_gb: 12.0, total_gb: 42.0 }.

### 6. `estimate_budget_default_rate_on_first_run`

Setup: empty weekly_stats.
Expected: placement_success_rate = 0.5 (default), total_gb computed accordingly.

### 7. `disk_pressure_normal_when_15_percent_free`

quota_gb=100, used_gb=85.0. free_ratio=0.15. → DiskPressure::Normal.
Expected: PressureResult { pressure: Normal, immediate_evictions: [], drop_notices: [] }.

### 8. `disk_pressure_soft_when_between_5_and_15_percent_free`

quota_gb=100, used_gb=90.0. free_ratio=0.10. → DiskPressure::Soft.
Expected: PressureResult { pressure: Soft, immediate_evictions: [], drop_notices: [] }.

### 9. `disk_pressure_hard_triggers_phase1_evictions`

Setup: quota_gb=100, used_gb=96.0. free_ratio=0.04 < 0.05.
Holding table has 5 shards, sizes 2GB each, priorities [0.1, 0.2, 0.3, 0.4, 0.9].
Phase 1: need to free (0.15*100 - 4) = 11GB. Evict lowest-priority shards first.
  - Shard at priority 0.1: +2GB → free=6GB (still < 11)
  - Shard at priority 0.2: +2GB → free=8GB (still < 11)
  - Shard at priority 0.3: +2GB → free=10GB (still < 11)
  - Shard at priority 0.4: +2GB → free=12GB (>= 11, stop)
Expected: immediate_evictions has 4 shards (priorities 0.1, 0.2, 0.3, 0.4), freed_gb=8.0.

Wait: used_gb=96 → free=4GB. deficit = 0.15*100 - 4 = 11GB.
  After evicting: 4 × 2GB = 8GB freed. free_gb = 4+8 = 12 >= 15. Correct.

### 10. `disk_pressure_hard_phase2_drop_notices`

Continuing test 9 setup. After Phase 1 frees 8GB, there is 1 shard left
at priority 0.9 (size 2GB). Phase 2 buffer target: 5% of quota = 5GB.
Expected: drop_notices has 1 shard (priority 0.9), deadline = now + 7 days.
freed_gb in PressureResult = 8.0 (Phase 1 only, not Phase 2).

### 11. `eviction_priority_increases_with_age`

Shard received_at = now - 26 weeks.
importance = 0.5, trust_of_owner = 0.6.
age_bonus = min(26/26, 0.3) = 0.3.
priority = 0.5 * 0.6 * (1 + 0.3) = 0.5 * 0.6 * 1.3 = 0.39.
Expected: eviction_priority ≈ 0.39.

### 12. `eviction_priority_age_bonus_capped_at_0_3`

Shard received_at = now - 100 weeks (way past 26 weeks).
importance = 1.0, trust_of_owner = 1.0.
age_bonus = min(100/26, 0.3) = 0.3.
priority = 1.0 * 1.0 * 1.3 = 1.3.
Expected: eviction_priority ≈ 1.3 (NOT 1 + 100/26).

### 13. `system_state_shards_never_evicted`

Setup: quota_gb=100, used_gb=99 (very high pressure). Holding table has
2 shards: one system (file_type=System, size=5GB), one user (priority=0.1, size=5GB).
Expected: immediate_evictions contains only the user shard, not the system shard.

### 14. `record_placement_outcome_rolling_window`

Call record_placement_outcome 5 times (5 weeks). Each time offered=10, accepted=8.
Expected: weekly_stats has 4 entries (oldest dropped), success_rate = 8/10 = 0.8.

### 15. `should_reject_offers_true_when_soft_or_hard`

quota_gb=100, used_gb=86. free_ratio=0.14 < 0.15. → true.
quota_gb=100, used_gb=80. free_ratio=0.20 >= 0.15. → false.

## Constants

All constants are imported from `crate::constants` (see `docs/tasks/constants.md`).
This module uses: `EVICTION_HYSTERESIS`, `SOFT_PRESSURE_THRESHOLD`, `HARD_PRESSURE_THRESHOLD`,
`DROP_NOTICE_WINDOW_SECS`, `AGE_BONUS_CAP`, `AGE_BONUS_WEEKS`, `UNKNOWN_OWNER_TRUST_FLOOR`,
`DEFAULT_SUCCESS_RATE`, `WILLINGNESS_FACTOR`, `WEEKLY_STATS_WINDOW`, `SECS_PER_WEEK`.

## Module Skeleton

```rust
// budget.rs
use crate::{
    db::Db,
    placement::PlacementEngine,
    trust::{TrustEngine, TrustError},
    types::{FileId, HoldingRecord, ImportanceScore, ShardId, IdentityPub},
};

use crate::constants::*;

pub struct BudgetPlanner { db: Db, trust: TrustEngine }
pub struct BudgetEstimate { ... }
pub struct BackupCandidate { ... }
pub struct BackupBatch { ... }
pub enum DiskPressure { Normal, Soft, Hard }
pub struct EvictionTarget { ... }
pub struct DropNoticeTarget { ... }
pub struct PressureResult { ... }

#[derive(Debug, thiserror::Error)]
pub enum BudgetError { ... }

impl BudgetPlanner {
    pub fn new(db: Db, trust: TrustEngine) -> Self { ... }
    pub fn estimate_budget(&self) -> Result<BudgetEstimate, BudgetError> { ... }
    pub fn select_backup_batch(&self, budget_gb: f64) -> Result<BackupBatch, BudgetError> { ... }
    pub fn overhead_factor(importance: ImportanceScore) -> f64 { ... }
    pub fn evaluate_pressure(&self, quota_gb: f64, used_gb: f64, now_secs: u64) -> Result<PressureResult, BudgetError> { ... }
    pub fn eviction_priority(&self, shard_id: ShardId, now_secs: u64) -> Result<f64, BudgetError> { ... }
    pub fn record_placement_outcome(&self, offered: u32, accepted: u32) -> Result<(), BudgetError> { ... }
    pub fn should_reject_offers(&self, quota_gb: f64, used_gb: f64) -> bool { ... }
}

#[cfg(test)]
mod tests { ... }
```
