# Task: escrow-v2 — trust-based escrow (Phase 2.6)

Module: `crates/syncback-core/src/escrow/`
Files: `mod.rs` + `tests.rs`
Also touches: `crates/syncback-core/src/constants.rs`, `crates/syncback/src/daemon/restore/mod.rs`

---

## Overview

Переписать модуль `escrow` с time-based (дискретные тиры на основе `weeks_in_network`) на trust-based (непрерывная формула на основе trust score). Параллельно убрать связанные константы и устаревшее поле `RestoreConfig::weeks_in_network`.

Остаток модуля (`should_delete_now`, `should_drop_after_notice`, `DeleteDecision`, `DropNoticeDecision`) — без изменений. Cooldown-функции не затрагивают escrow и остаются как есть.

---

## Dependencies

- `crate::types::Timestamp` — только для cooldown-функций
- `crate::constants::{FREE_TIER_GB, DEFAULT_ESCROW_TRUST_FACTOR, HOLDER_DELETE_COOLDOWN_SECS, DROP_NOTICE_WINDOW_SECS}`
- No DB. No async. No HashMap. Pure functions only.

---

## Types

### Удалить

```rust
// REMOVE entirely:
pub enum EscrowTier { FreeTier, Tier1, Tier2, Tier3 }
impl EscrowTier { ... }
```

### Оставить без изменений

```rust
/// Decision for holder cooldown (delete flow).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteDecision {
    Keep,
    Delete,
}

/// Decision for drop notice flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropNoticeDecision {
    DeleteNow,
    StillWaiting,
}
```

### Изменить

```rust
/// Decision from check_restore().
#[derive(Debug, Clone, PartialEq)]
pub enum RestoreDecision {
    Allowed,
    Denied(RestoreDenial),
}

/// Reason for denial — sent back to owner as restore_denied message payload.
///
/// Fields map directly to the wire message fields from protocol.md §1.10:
///   restore_denied { shard_id, reason, current_trust, needed_trust, restore_budget_gb }
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RestoreDenial {
    /// Holder's trust score for this owner at the time of denial.
    pub current_trust: f64,
    /// Minimum trust score that would allow this restore.
    /// needed_trust = (restore_gb - FREE_TIER_GB) / escrow_trust_factor
    /// Clamped to 0.0 if restore_gb <= FREE_TIER_GB.
    pub needed_trust: f64,
    /// Max GB restorable at current trust level.
    pub restore_budget_gb: f64,
}
```

---

## Constants (`crates/syncback-core/src/constants.rs`)

### Удалить

```rust
// DELETE these constants:
pub const ESCROW_TIER1_WEEKS: u32 = 4;
pub const ESCROW_TIER2_WEEKS: u32 = 13;
pub const ESCROW_TIER3_WEEKS: u32 = 26;
pub const FREE_TIER_BYTES: u64 = 1 << 30;
pub const TIER1_MAX_BYTES: u64 = 5 << 30;
pub const TIER2_MAX_BYTES: u64 = 50 << 30;

// DELETE compile-time assertions that reference them:
const _: () = assert!(ESCROW_TIER1_WEEKS < ESCROW_TIER2_WEEKS);
const _: () = assert!(ESCROW_TIER2_WEEKS < ESCROW_TIER3_WEEKS);
```

### Добавить

```rust
// === Escrow (trust-based) ===

/// Demo credit — first 1 GB restorable at trust=0.
pub const FREE_TIER_GB: f64 = 1.0;

/// GB per unit of trust. To be calibrated via simulation.
/// Default: trust=2.0 → budget = 1 + 2.0 × 20.0 = 41 GB.
pub const DEFAULT_ESCROW_TRUST_FACTOR: f64 = 20.0;
```

---

## Public API (`crates/syncback-core/src/escrow/mod.rs`)

All functions are free functions — no struct with state.

### Новые функции

```rust
/// Compute max GB restorable at the given trust score.
///
/// Formula: max_restorable_gb = FREE_TIER_GB + trust * escrow_trust_factor
///
/// Parameters:
///   trust               — holder's pairwise trust score for the owner (f64, typically 0..5)
///   escrow_trust_factor — configurable multiplier (pass DEFAULT_ESCROW_TRUST_FACTOR unless overridden)
///
/// Trust is allowed to be negative (new peers in edge cases); clamp result to FREE_TIER_GB minimum.
pub fn restore_budget(trust: f64, escrow_trust_factor: f64) -> f64 {
    (FREE_TIER_GB + trust * escrow_trust_factor).max(FREE_TIER_GB)
}

/// Primary escrow check. Called by holder when owner requests restore.
///
/// Parameters:
///   trust               — holder's pairwise trust score for the owner
///   restore_gb          — size of the requested restore in GB
///   escrow_trust_factor — configurable multiplier (pass DEFAULT_ESCROW_TRUST_FACTOR unless overridden)
///
/// Returns: Allowed if restore_gb <= restore_budget(trust), else Denied.
pub fn check_restore(trust: f64, restore_gb: f64, escrow_trust_factor: f64) -> RestoreDecision {
    let budget = restore_budget(trust, escrow_trust_factor);
    if restore_gb <= budget {
        RestoreDecision::Allowed
    } else {
        // needed_trust: solve budget = FREE_TIER_GB + needed_trust * factor for needed_trust
        let needed_trust = ((restore_gb - FREE_TIER_GB) / escrow_trust_factor).max(0.0);
        RestoreDecision::Denied(RestoreDenial {
            current_trust: trust,
            needed_trust,
            restore_budget_gb: budget,
        })
    }
}
```

### Без изменений

```rust
/// Holder-side: should we physically delete symbols now?
/// Called periodically while status == MarkedForDelete.
pub fn should_delete_now(delete_requested_at: Timestamp, now: Timestamp) -> DeleteDecision;

/// Holder-side: has the drop-notice window expired?
/// Called after sending symbol_drop_notice to owner.
pub fn should_drop_after_notice(drop_notice_sent_at: Timestamp, now: Timestamp) -> DropNoticeDecision;
```

### Удалить

```rust
// DELETE these functions (replaced by check_restore + restore_budget above):
pub fn tier_for_bytes(bytes_restored: u64) -> EscrowTier;
pub fn remaining_bytes_in_tier(bytes_restored: u64) -> u64;
```

---

## Changes to `RestoreConfig` (`crates/syncback/src/daemon/restore/mod.rs`)

### Удалить поле

```rust
// REMOVE from RestoreConfig:
/// weeks_in_network for escrow check on self-restore.
pub weeks_in_network: u32,
```

### Убрать из Default impl

```rust
// REMOVE from RestoreConfig::default():
weeks_in_network: 0,
```

### Обновить `RestoreError::EscrowDenied`

```rust
// REPLACE:
#[error("restore denied by holder {holder}: requires {required_weeks} weeks, have {current_weeks}")]
EscrowDenied {
    holder: IdentityPub,
    required_weeks: u32,
    current_weeks: u32,
},

// WITH:
#[error("restore denied by holder {holder}: trust {current_trust:.2}, budget {restore_budget_gb:.1} GB, requested {restore_gb:.1} GB")]
EscrowDenied {
    holder: IdentityPub,
    current_trust: f64,
    needed_trust: f64,
    restore_budget_gb: f64,
    restore_gb: f64,
},
```

Note: `restore_gb` added to the error so the user message can show both sides of the comparison. This field is not in `RestoreDenial` (denial doesn't know the full context), so it is filled in by the caller at the point of constructing the error.

---

## Business Rules

### Основная формула

```
max_restorable_gb = FREE_TIER_GB + trust × escrow_trust_factor
                  = 1.0 + trust × 20.0    (with defaults)
```

Примеры:
- `trust = 0.0` → budget = 1.0 GB (demo credit, hit-and-run node получает только это)
- `trust = 0.5` → budget = 11.0 GB
- `trust = 2.0` → budget = 41.0 GB (4 weeks with good S-score)
- `trust = 5.0` → budget = 101.0 GB

### Отрицательный trust

Trust теоретически не может быть отрицательным при нормальной работе формулы `(kp*P + ki*I) * clamp(S, 0.1, 1.0)`, но реализация должна быть устойчивой: `restore_budget` использует `.max(FREE_TIER_GB)`, так что минимальный бюджет всегда `FREE_TIER_GB = 1.0`.

### needed_trust в Denial

```
needed_trust = max(0.0, (restore_gb - FREE_TIER_GB) / escrow_trust_factor)
```

Это минимальный trust, при котором данный запрос был бы одобрен. Показывается пользователю для информации.

### Холодный старт (disaster recovery)

Протокол явно учитывает этот случай (protocol.md §1.10): I-score кумулятивный и не обнуляется при потере устройства. Пользователь с годами в сети имеет высокий I → высокий trust → большой budget. Новый пользователь — только 1 GB demo credit.

### Caller responsibility

- `check_restore` принимает `trust: f64` — caller (RestoreCoordinator или Processor) обязан сам получить trust из TrustEngine, передать его сюда.
- `escrow_trust_factor` передаётся как параметр, а не жёстко зашит — caller берёт его из конфига (`DEFAULT_ESCROW_TRUST_FACTOR` по умолчанию).
- Модуль `escrow` не знает ни о DB, ни о TrustEngine, ни о конфиге демона.

---

## Test Scenarios (`escrow/tests.rs`)

Все старые тесты удалить. Написать следующие.

### 1. `restore_budget_at_zero_trust`

```
trust = 0.0, factor = 20.0
→ restore_budget = 1.0
```

### 2. `restore_budget_at_typical_trust`

```
trust = 2.0, factor = 20.0
→ restore_budget = 41.0
```

### 3. `restore_budget_negative_trust_clamped_to_free_tier`

```
trust = -1.0, factor = 20.0
→ restore_budget = 1.0   (clamped, not -19.0)
```

### 4. `restore_budget_custom_factor`

```
trust = 1.0, factor = 10.0
→ restore_budget = 11.0
```

### 5. `check_restore_allowed_within_budget`

```
trust = 2.0, restore_gb = 40.0, factor = 20.0
budget = 41.0 ≥ 40.0
→ RestoreDecision::Allowed
```

### 6. `check_restore_allowed_exactly_at_budget`

```
trust = 2.0, restore_gb = 41.0, factor = 20.0
budget = 41.0 ≥ 41.0
→ Allowed
```

### 7. `check_restore_denied_exceeds_budget`

```
trust = 2.0, restore_gb = 42.0, factor = 20.0
budget = 41.0 < 42.0
→ Denied {
    current_trust: 2.0,
    needed_trust: (42.0 - 1.0) / 20.0 = 2.05,
    restore_budget_gb: 41.0,
  }
```

### 8. `check_restore_denied_zero_trust_above_free_tier`

Сценарий: hit-and-run нода пытается восстановить больше demo credit.

```
trust = 0.0, restore_gb = 1.5, factor = 20.0
budget = 1.0 < 1.5
→ Denied {
    current_trust: 0.0,
    needed_trust: (1.5 - 1.0) / 20.0 = 0.025,
    restore_budget_gb: 1.0,
  }
```

### 9. `check_restore_allowed_zero_trust_within_free_tier`

```
trust = 0.0, restore_gb = 0.5, factor = 20.0
budget = 1.0 ≥ 0.5
→ Allowed
```

### 10. `check_restore_allowed_zero_trust_exactly_free_tier`

```
trust = 0.0, restore_gb = 1.0, factor = 20.0
budget = 1.0 ≥ 1.0
→ Allowed
```

### 11. `needed_trust_clamped_to_zero_when_restore_within_free_tier`

Запрос меньше FREE_TIER_GB, но trust отрицательный — проверяем needed_trust не отрицательный.

```
trust = -0.5, restore_gb = 0.8, factor = 20.0
budget = max(1.0, 1.0 + (-0.5)*20.0) = max(1.0, -9.0) = 1.0
restore_gb (0.8) <= budget (1.0)
→ Allowed
```

### 12. `should_delete_now_before_cooldown`

```
delete_requested_at = Timestamp(1_000_000)
now = Timestamp(1_000_000 + HOLDER_DELETE_COOLDOWN_SECS - 1)
→ DeleteDecision::Keep
```

### 13. `should_delete_now_at_cooldown_boundary`

```
delete_requested_at = Timestamp(1_000_000)
now = Timestamp(1_000_000 + HOLDER_DELETE_COOLDOWN_SECS)
→ DeleteDecision::Delete
```

### 14. `should_drop_after_notice_before_window`

```
drop_notice_sent_at = Timestamp(2_000_000)
now = Timestamp(2_000_000 + DROP_NOTICE_WINDOW_SECS - 1)
→ DropNoticeDecision::StillWaiting
```

### 15. `should_drop_after_notice_at_window_boundary`

```
drop_notice_sent_at = Timestamp(2_000_000)
now = Timestamp(2_000_000 + DROP_NOTICE_WINDOW_SECS)
→ DropNoticeDecision::DeleteNow
```

---

## Gate Criteria (from roadmap.md Phase 2.6)

```
GATE: hit-and-run (trust=0) blocked for >1 GB, honest user (trust≥2) gets full access
```

Тест 8 проверяет первое условие. Тест 5 проверяет второе.

---

## Reference: old code

- `crates/syncback-core/src/escrow/mod.rs` — текущая реализация (time-based)
- `crates/syncback-core/src/escrow/tests.rs` — старые тесты (все удалить)
- `crates/syncback-core/src/constants.rs` — константы для удаления/добавления
- `crates/syncback/src/daemon/restore/mod.rs` — `RestoreConfig` и `RestoreError`

Ключевое отличие от старой реализации:
- Нет `EscrowTier` и tier-based проверок
- `check_restore(trust, restore_gb, factor)` вместо `check_restore(weeks_in_network, bytes_already_restored)`
- `RestoreDenial` содержит trust-поля вместо tier/weeks-полей
- `restore_budget(trust, factor) -> f64` — новая вспомогательная функция
- `tier_for_bytes` и `remaining_bytes_in_tier` удалены
