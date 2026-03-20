# Task: budget — BudgetPlanner (β)

Module: `crates/syncback-core/src/budget/`
Files: `mod.rs` + `tests.rs`

---

## Overview

Двойная роль:
1. **Owner:** оценить сколько GB сеть готова хранить для нас → выбрать файлы для резервного копирования.
2. **Holder:** при нехватке места — выбрать что вытеснить (приоритет эвикции).

В β это **чистые функции** без DB и без TrustEngine зависимости. Caller передаёт данные явно. Никакого состояния.

---

## Dependencies

- `crate::types::{IdentityPub, SourceBlockId, Timestamp, ErasureParams, HoldingRecord, HoldingStatus, BudgetRecord}`
- `crate::constants::{AGE_BONUS_CAP, AGE_BONUS_WEEKS, DEFAULT_SUCCESS_RATE, DROP_NOTICE_WINDOW_SECS, SECS_PER_WEEK, UNKNOWN_OWNER_TRUST_FLOOR, WEEKLY_STATS_WINDOW, WILLINGNESS_FACTOR, OVERHEAD_BASE, OVERHEAD_SCALE}`
- No DB. No TrustEngine. No async.

---

## Types

```rust
/// Owner-side budget snapshot.
#[derive(Debug, Clone)]
pub struct BudgetEstimate {
    /// GB confirmed stored (Alive placements).
    pub committed_gb: f64,
    /// Conservative additional capacity estimate.
    pub headroom_gb: f64,
    /// committed_gb + headroom_gb.
    pub total_gb: f64,
    /// Placement success rate used for this estimate.
    pub placement_success_rate: f64,
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
    /// Files that didn't fit in the budget (importance >= 0 but excluded).
    pub deferred_count: usize,
}

/// Disk pressure level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskPressure {
    /// free_ratio >= 0.15. Normal.
    Normal,
    /// 0.05 <= free_ratio < 0.15. Stop accepting new symbols.
    Soft,
    /// free_ratio < 0.05. Evict immediately.
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
```

---

## Public API

All free functions or methods on a zero-field unit struct. No stored state.

```rust
/// Estimate current network budget from placement stats.
///
/// Parameters:
///   committed_bytes: sum of total_bytes of all HoldingRecord-equivalent entries
///                    where PlacementStatus == Alive (owner view, loaded by caller)
///   budget_record: last persisted BudgetRecord (caller loads from DB), None on first run
///
/// Returns estimate. Caller persists updated BudgetRecord if desired.
pub fn estimate_budget(
    committed_bytes: u64,
    budget_record: Option<&BudgetRecord>,
) -> BudgetEstimate;

/// Select dirty files to back up this cycle.
///
/// Parameters:
///   candidates: (path, importance, size_bytes) for all dirty files with importance > 0
///   budget_gb: total_gb from estimate_budget()
///
/// Algorithm:
///   1. Compute required_gb = size_bytes / 1_073_741_824 * overhead(importance)
///   2. Sort by importance DESC, then required_gb ASC (tie-break: smaller first)
///   3. Greedily include until Σ required_gb <= budget_gb
///   4. Files with importance == 0.0 are excluded silently (not deferred)
pub fn select_backup_batch(
    candidates: &[(String, f64, u64)], // (path, importance, size_bytes)
    budget_gb: f64,
) -> BackupBatch;

/// Overhead factor for erasure coding: N/K for a given importance.
/// overhead = OVERHEAD_BASE + importance.clamp(0.0, 1.0) * OVERHEAD_SCALE
/// Range: 1.5 (importance=0) to 3.0 (importance=1).
/// Files with importance == 0.0 are still assigned an overhead; caller decides cutoff.
pub fn overhead_factor(importance: f64) -> f64;

/// Update rolling weekly stats with a new placement outcome.
///
/// Parameters:
///   record: existing BudgetRecord (loaded from DB), None if first run
///   offered: how many symbol_offers were sent this week
///   accepted: how many were accepted
///
/// Returns updated BudgetRecord for caller to persist.
pub fn record_placement_outcome(
    record: Option<BudgetRecord>,
    offered: u32,
    accepted: u32,
) -> BudgetRecord;

/// Evaluate disk pressure and compute eviction targets.
///
/// Parameters:
///   quota_bytes: storage quota (from config).
///                0 = unlimited (returns Normal always).
///   used_bytes: current bytes used by all held symbols.
///   holdings: all HoldingRecord entries (caller loads from DB).
///   owner_trust: closure providing combined trust score for an owner.
///                (peer_identity → f64); returns UNKNOWN_OWNER_TRUST_FLOOR for unknown.
///   now_secs: current Unix timestamp.
pub fn evaluate_pressure(
    quota_bytes: u64,
    used_bytes: u64,
    holdings: &[HoldingRecord],
    owner_trust: impl Fn(&IdentityPub) -> f64,
    now_secs: u64,
) -> PressureResult;

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
) -> f64;

/// Returns true when disk usage is at or above the soft threshold.
/// Caller should refuse new symbol_offer messages when this returns true.
pub fn should_reject_offers(quota_bytes: u64, used_bytes: u64) -> bool;
```

---

## Business Rules

### Budget estimation

```
placement_success_rate:
  if budget_record.weekly_stats is empty: DEFAULT_SUCCESS_RATE = 0.5
  else: sum(accepted) / sum(offered) over all stats entries

headroom_gb = committed_gb * placement_success_rate * WILLINGNESS_FACTOR
  WILLINGNESS_FACTOR = 0.5  (conservative; 50% of what we'd hope)

total_gb = committed_gb + headroom_gb

Bootstrap case (committed_bytes == 0):
  total_gb must allow backing up something.
  Caller should pass budget_gb = 0, and the result is 0.0.
  The daemon's bootstrap logic (not this module) handles first-run.
  This module does NOT have special-case bootstrap logic.
  (α had bootstrap heuristic; β simplifies: caller handles it.)
```

### Overhead factor

```
overhead(importance) = OVERHEAD_BASE + clamp(importance, 0.0, 1.0) * OVERHEAD_SCALE
                     = 1.5 + importance * 1.5
importance=0.0 → 1.5x
importance=0.5 → 2.25x
importance=1.0 → 3.0x
```

### Weekly stats rolling window

- Max `WEEKLY_STATS_WINDOW = 4` entries in `BudgetRecord.weekly_stats`.
- On new entry: append, then drop oldest if `len > WEEKLY_STATS_WINDOW`.
- `placement_success_rate` = total_accepted / total_offered across window; if offered=0 → `DEFAULT_SUCCESS_RATE`.

### Disk pressure thresholds

```
free_ratio = (quota_bytes - used_bytes) as f64 / quota_bytes as f64
If quota_bytes == 0: always Normal (unlimited).

free_ratio >= 0.15  → Normal
0.05 <= free_ratio < 0.15 → Soft (stop accepting offers)
free_ratio < 0.05   → Hard (evict)
```

These thresholds are NOT in `constants.rs` as named constants in the current β codebase. Define them as module-level constants in `budget/mod.rs`:

```rust
const SOFT_PRESSURE_THRESHOLD: f64 = 0.15;
const HARD_PRESSURE_THRESHOLD: f64 = 0.05;
```

### Eviction priority formula

```
priority = importance × trust_of_owner × (1 + age_bonus)

age_bonus = min(weeks_stored / AGE_BONUS_WEEKS, AGE_BONUS_CAP)
  AGE_BONUS_WEEKS = 26.0
  AGE_BONUS_CAP = 0.3

weeks_stored = (now_secs - received_at.0) / SECS_PER_WEEK  (floating point)

If owner is unknown: trust_of_owner = UNKNOWN_OWNER_TRUST_FLOOR = 0.1
```

Higher priority = keep longer. Evict lowest first.

### Eviction target selection (Hard pressure)

```
deficit_bytes = SOFT_PRESSURE_THRESHOLD * quota_bytes - (quota_bytes - used_bytes)
  = target_free_bytes - current_free_bytes

Phase 1 (immediate): evict lowest-priority first until freed_bytes >= deficit_bytes
Phase 2 (drop notice): next 5% of quota worth of holdings get drop notices
  buffer_bytes = 0.05 * quota_bytes
  Continue evict queue from Phase 1 stopping point until buffer filled.

HoldingStatus::MarkedForDelete entries participate in priority but will be evicted first
  (owner already wants them gone).
```

---

## Test Scenarios

Tests in `budget/tests.rs`.

### 1. `overhead_factor_at_zero_importance`

```
overhead_factor(0.0) == 1.5
```

### 2. `overhead_factor_at_full_importance`

```
overhead_factor(1.0) == 3.0
```

### 3. `overhead_factor_midpoint`

```
overhead_factor(0.5) ≈ 2.25 (within 1e-9)
```

### 4. `estimate_budget_no_history`

```
committed_bytes = 10 * 1024^3  (10 GiB)
budget_record = None
placement_success_rate = DEFAULT_SUCCESS_RATE = 0.5
headroom = 10 * 0.5 * 0.5 = 2.5 GiB
total = 12.5 GiB
```

### 5. `estimate_budget_with_stats`

```
committed_bytes = 10 * 1024^3
budget_record with weekly_stats = [(10, 8), (10, 6)]  → rate = 14/20 = 0.7
headroom = 10 * 0.7 * 0.5 = 3.5 GiB
total = 13.5 GiB
```

### 6. `select_backup_batch_fits_all`

```
budget_gb = 100.0
candidates = [("a.jpg", 0.6, 50 MiB), ("b.doc", 0.9, 10 MiB)]
All fit. Sorted: b.doc (0.9) first, a.jpg (0.6) second.
deferred_count = 0
```

### 7. `select_backup_batch_defers_overflow`

```
budget_gb = 0.04  (40 MiB)
candidates = [("big.jpg", 0.6, 50 MiB), ("small.doc", 0.9, 1 MiB)]
required_gb(big.jpg) = 50 MiB / 1024^3 * 2.4 ≈ 0.117 GiB → exceeds budget
required_gb(small.doc) = 1 MiB / 1024^3 * 2.85 ≈ 0.0027 GiB → fits

Sort: small.doc (0.9) first. Add small.doc (fits). Try big.jpg (doesn't fit) → deferred.
candidates = [small.doc], deferred_count = 1
```

### 8. `select_backup_batch_importance_zero_excluded`

```
candidates = [("zero.jpg", 0.0, 100 MiB)]
budget_gb = 1000.0
BackupBatch { candidates: [], deferred_count: 0 }
(importance=0.0 files excluded silently, NOT deferred)
```

### 9. `record_placement_outcome_rolling_window`

```
Call 5 times. After 5th: weekly_stats.len() == WEEKLY_STATS_WINDOW (4).
Oldest entry dropped.
```

### 10. `eviction_priority_new_data`

```
importance = 0.8, trust_of_owner = 0.9
received_at = now (0 weeks stored)
age_bonus = 0.0
priority = 0.8 * 0.9 * 1.0 = 0.72
```

### 11. `eviction_priority_old_data_max_bonus`

```
importance = 0.8, trust_of_owner = 0.9
received_at 26 weeks ago
age_bonus = min(26/26, 0.3) = 0.3
priority = 0.8 * 0.9 * 1.3 = 0.936
```

### 12. `eviction_priority_old_data_capped_bonus`

```
received_at 52 weeks ago
age_bonus = min(52/26, 0.3) = min(2.0, 0.3) = 0.3
Same as 26 weeks.
```

### 13. `eviction_priority_unknown_owner_uses_floor`

```
owner_trust closure returns UNKNOWN_OWNER_TRUST_FLOOR = 0.1 for unknown peer
importance = 0.8, 0 weeks stored
priority = 0.8 * 0.1 * 1.0 = 0.08
```

### 14. `evaluate_pressure_normal`

```
quota_bytes = 100 GiB, used_bytes = 80 GiB → free_ratio = 0.20 → Normal
PressureResult { pressure: Normal, immediate_evictions: [], drop_notices: [] }
```

### 15. `evaluate_pressure_soft`

```
quota_bytes = 100 GiB, used_bytes = 88 GiB → free_ratio = 0.12 → Soft
No evictions.
```

### 16. `evaluate_pressure_hard_evicts_lowest_priority`

```
quota_bytes = 100 GiB, used_bytes = 97 GiB → free_ratio = 0.03 → Hard
deficit = 0.15 * 100 - 3 = 12 GiB

3 holdings:
  A: importance=0.1, trust=0.5, 5 GiB → priority=0.05, low
  B: importance=0.9, trust=0.9, 5 GiB → priority=0.81, high
  C: importance=0.5, trust=0.5, 5 GiB → priority=0.25, medium

Evict order: A first, then C (if needed), B last.
Need to free 12 GiB: evict A (5 GiB) + C (5 GiB) = 10 GiB < 12; also evict B?
Actually: 5+5+5=15 GiB available. deficit=12. Evict A(5) → freed=5 < 12. Evict C(5) → freed=10 < 12. Evict B(5) → freed=15 >= 12. All three in immediate_evictions.
(This tests that we stop at the right point.)
```

### 17. `should_reject_offers_above_soft`

```
quota_bytes = 100 GiB, used_bytes = 86 GiB → free_ratio = 0.14 < 0.15 → true
```

### 18. `should_reject_offers_unlimited_quota`

```
quota_bytes = 0 → false (unlimited)
```

---

## Reference: α code

See `alpha_crates/syncback-core/src/budget/mod.rs`:
- `eviction_priority` logic (importance × trust × age_bonus) — same formula.
- `overhead_factor` — α used discrete tiers (5-of-15 = 3.0x); β uses continuous formula.
- `select_backup_batch` sort logic — same (importance DESC, required_gb ASC tie-break).
- `evaluate_pressure` phase1/phase2 structure — same.

Key differences in β:
- No `BudgetPlanner { db, trust }` struct. All inputs are explicit function parameters.
- `overhead_factor` is continuous (`1.5 + importance * 1.5`), not tier-based.
- No `FileType::System` guard (no system state in β placement; handled by caller).
- `quota_bytes = 0` → unlimited (no division-by-zero trap).
