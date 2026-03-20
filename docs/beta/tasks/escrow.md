# Task: escrow — EscrowChecker (β)

Module: `crates/syncback-core/src/escrow/`
Files: `mod.rs` + `tests.rs`

---

## Overview

Контроль доступа к восстановлению данных. Пир не может восстановить файлы бесплатно — нужно накопить репутацию (время в сети). Второй барьер от ransomware (первый — cooldown удаления).

В β это **чистые функции без состояния**: `EscrowChecker` не хранит данные, принимает всё что нужно как аргументы. Caller (DB layer, Processor) отвечает за персистентность.

Функции `check_restore()` и `tier_for_bytes()` — самодостаточные.

---

## Dependencies

- `crate::types::{IdentityPub, Timestamp}` (только для SourceBlockId в denial)
- `crate::constants::{ESCROW_TIER1_WEEKS, ESCROW_TIER2_WEEKS, ESCROW_TIER3_WEEKS, FREE_TIER_BYTES, TIER1_MAX_BYTES, TIER2_MAX_BYTES, HOLDER_DELETE_COOLDOWN_SECS, DROP_NOTICE_WINDOW_SECS}`
- No DB. No async. No HashMap. Pure functions.

---

## Types

```rust
/// The escrow tier a restore request falls into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EscrowTier {
    /// First FREE_TIER_BYTES (1 GiB) restored: no weeks required.
    FreeTier,
    /// bytes_restored in [1 GiB, 5 GiB): requires >= ESCROW_TIER1_WEEKS (4 wk).
    Tier1,
    /// bytes_restored in [5 GiB, 50 GiB): requires >= ESCROW_TIER2_WEEKS (13 wk).
    Tier2,
    /// bytes_restored >= 50 GiB: requires >= ESCROW_TIER3_WEEKS (26 wk).
    Tier3,
}

impl EscrowTier {
    /// Minimum weeks_in_network required for this tier.
    pub fn required_weeks(self) -> u32;
    /// Determine tier from cumulative bytes already restored to this owner.
    pub fn from_bytes_restored(bytes_restored: u64) -> Self;
}

/// Decision from check_restore().
#[derive(Debug, Clone, PartialEq)]
pub enum RestoreDecision {
    Allowed,
    Denied(RestoreDenial),
}

/// Reason for denial, sent back to owner as restore_denied message payload.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RestoreDenial {
    pub tier: EscrowTier,
    pub required_weeks: u32,
    pub current_weeks: u32,
    /// How many more bytes they can restore before moving to next tier.
    pub remaining_bytes_in_tier: u64,
}

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

/// No stateful errors in this module — all checks are pure.
/// No EscrowError type needed. Invalid inputs → panic (programming error).
```

---

## Public API

All functions are free functions or `impl EscrowTier` — no struct with state.

```rust
/// Primary escrow check. Called by holder when owner requests restore.
///
/// Parameters:
///   weeks_in_network: caller looks this up from PeerRecord.weeks_in_network
///   bytes_already_restored: cumulative bytes holder has served to this owner
///
/// Returns: Allowed or Denied(RestoreDenial)
pub fn check_restore(
    weeks_in_network: u32,
    bytes_already_restored: u64,
) -> RestoreDecision;

/// Determine which tier applies to the given cumulative bytes restored.
/// Pure alias for EscrowTier::from_bytes_restored.
pub fn tier_for_bytes(bytes_restored: u64) -> EscrowTier;

/// How many bytes remain before moving to the next tier.
/// Returns u64::MAX for FreeTier (effectively unlimited within FreeTier).
pub fn remaining_bytes_in_tier(bytes_restored: u64) -> u64;

/// Holder-side: should we physically delete symbols now?
/// Called periodically while status == MarkedForDelete.
///
/// delete_requested_at: when owner sent delete message
/// now: current time
pub fn should_delete_now(delete_requested_at: Timestamp, now: Timestamp) -> DeleteDecision;

/// Holder-side: has the drop-notice window expired?
/// Called after sending symbol_drop_notice to owner.
///
/// drop_notice_sent_at: when we sent the notice
/// now: current time
pub fn should_drop_after_notice(drop_notice_sent_at: Timestamp, now: Timestamp) -> DropNoticeDecision;
```

---

## Business Rules

### Tier Boundaries

```
bytes_restored < FREE_TIER_BYTES (1 GiB)  → FreeTier  (required_weeks = 0)
bytes_restored < TIER1_MAX_BYTES (5 GiB)  → Tier1     (required_weeks = 4)
bytes_restored < TIER2_MAX_BYTES (50 GiB) → Tier2     (required_weeks = 13)
bytes_restored >= TIER2_MAX_BYTES          → Tier3     (required_weeks = 26)
```

Constants from `constants.rs`:
- `FREE_TIER_BYTES = 1 << 30` (1 GiB)
- `TIER1_MAX_BYTES = 5 << 30` (5 GiB)
- `TIER2_MAX_BYTES = 50 << 30` (50 GiB)
- `ESCROW_TIER1_WEEKS = 4`
- `ESCROW_TIER2_WEEKS = 13`
- `ESCROW_TIER3_WEEKS = 26`

### check_restore logic

```
tier = EscrowTier::from_bytes_restored(bytes_already_restored)
if tier == FreeTier: return Allowed
if weeks_in_network >= tier.required_weeks(): return Allowed
else: return Denied { tier, required_weeks: tier.required_weeks(), current_weeks: weeks_in_network, ... }
```

### remaining_bytes_in_tier

```
FreeTier: FREE_TIER_BYTES - bytes_restored  (how many bytes left before Tier1)
Tier1:    TIER1_MAX_BYTES - bytes_restored
Tier2:    TIER2_MAX_BYTES - bytes_restored
Tier3:    u64::MAX  (no upper bound; caller can interpret as "unlimited")
```

### Holder delete cooldown

- After owner sends delete: `delete_requested_at` timestamp recorded.
- `should_delete_now`: returns `Delete` if `now.0 - delete_requested_at.0 >= HOLDER_DELETE_COOLDOWN_SECS`.
- `HOLDER_DELETE_COOLDOWN_SECS = 4 * SECS_PER_WEEK`.

### Drop notice window (disk pressure)

- After holder sends `symbol_drop_notice`: `drop_notice_sent_at` timestamp recorded.
- `should_drop_after_notice`: returns `DeleteNow` if `now.0 - drop_notice_sent_at.0 >= DROP_NOTICE_WINDOW_SECS`.
- `DROP_NOTICE_WINDOW_SECS = 7 * 24 * 3600` (7 days).

---

## Test Scenarios

Tests in `escrow/tests.rs`.

### 1. `free_tier_always_allowed`

```
bytes_already_restored = 0
weeks_in_network = 0
→ RestoreDecision::Allowed
```

### 2. `free_tier_boundary_allowed`

```
bytes_already_restored = FREE_TIER_BYTES - 1  (just under 1 GiB)
weeks_in_network = 0
→ Allowed
```

### 3. `tier1_denied_not_enough_weeks`

```
bytes_already_restored = FREE_TIER_BYTES  (exactly 1 GiB, crossed into Tier1)
weeks_in_network = 3                      (< 4)
→ Denied { tier: Tier1, required_weeks: 4, current_weeks: 3 }
```

### 4. `tier1_allowed_sufficient_weeks`

```
bytes_already_restored = FREE_TIER_BYTES
weeks_in_network = 4
→ Allowed
```

### 5. `tier2_denied_not_enough_weeks`

```
bytes_already_restored = TIER1_MAX_BYTES  (5 GiB)
weeks_in_network = 12
→ Denied { tier: Tier2, required_weeks: 13, current_weeks: 12 }
```

### 6. `tier3_denied_not_enough_weeks`

```
bytes_already_restored = TIER2_MAX_BYTES  (50 GiB)
weeks_in_network = 25
→ Denied { tier: Tier3, required_weeks: 26, current_weeks: 25 }
```

### 7. `tier3_allowed_at_26_weeks`

```
bytes_already_restored = TIER2_MAX_BYTES
weeks_in_network = 26
→ Allowed
```

### 8. `remaining_bytes_free_tier`

```
bytes_restored = 0
→ FREE_TIER_BYTES (= 1 GiB)
```

### 9. `remaining_bytes_tier1`

```
bytes_restored = FREE_TIER_BYTES + 1_000_000
→ TIER1_MAX_BYTES - bytes_restored
```

### 10. `should_delete_now_before_cooldown`

```
delete_requested_at = Timestamp(1_000_000)
now = Timestamp(1_000_000 + HOLDER_DELETE_COOLDOWN_SECS - 1)
→ Keep
```

### 11. `should_delete_now_at_cooldown_boundary`

```
delete_requested_at = Timestamp(1_000_000)
now = Timestamp(1_000_000 + HOLDER_DELETE_COOLDOWN_SECS)
→ Delete
```

### 12. `should_drop_after_notice_before_window`

```
drop_notice_sent_at = Timestamp(2_000_000)
now = Timestamp(2_000_000 + DROP_NOTICE_WINDOW_SECS - 1)
→ StillWaiting
```

### 13. `should_drop_after_notice_at_window_boundary`

```
drop_notice_sent_at = Timestamp(2_000_000)
now = Timestamp(2_000_000 + DROP_NOTICE_WINDOW_SECS)
→ DeleteNow
```

---

## Reference: α code

See `alpha_crates/syncback-core/src/escrow/mod.rs`:
- `EscrowTier::from_bytes_restored()` — same logic, copy directly.
- `EscrowTier::required_weeks()` — same.
- Tier boundary constants — same (now in `constants.rs`).

Key difference in β:
- No `EscrowChecker` struct with DB dependency.
- No `mark_for_delete`, `cancel_delete`, `mark_silent` — those are DB operations, not escrow logic.
- All functions are stateless; DB state management is the caller's responsibility.
