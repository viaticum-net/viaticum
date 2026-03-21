# Task: Disk Pressure Upgrade (Phase 4.2)

Module: `crates/syncback-core/src/budget/`
Files: `mod.rs` (modify) + `tests.rs` (add tests)

---

## Overview

Upgrade the existing `budget` module's disk pressure logic from a single flat
`quota_bytes` parameter to a two-tier quota model:

- **soft_quota** — user-configured cap (0 = unlimited)
- **disk_reserve** — keep this much filesystem space free (default 20 GB)
- **effective_quota** — the actual ceiling: `min(soft_quota, disk_free - disk_reserve)`
- **hard_quota** — floor: never evict below this (protects user's own data)

The current `evaluate_pressure` and `should_reject_offers` take a single
`quota_bytes`. After this task they still take a single `quota_bytes`, but
callers are expected to compute `effective_quota` first using the new pure
helper `compute_effective_quota`. The daemon scheduler is the only caller of
both functions; it will call `compute_effective_quota` and pass the result in.

This keeps the change backward-compatible: no signature breakage of
`evaluate_pressure` or `should_reject_offers`. New behaviour lives in the new
helper plus the new `hard_quota` guard in `evaluate_pressure`.

---

## Dependencies

- Same as current `budget/mod.rs` — no new dependencies.
- `crate::constants::DEFAULT_DISK_RESERVE_BYTES` — already defined as
  `20 * 1024 * 1024 * 1024`.
- No DB. No async. No network.

---

## New constant in `constants.rs`

No new constant needed; `DEFAULT_DISK_RESERVE_BYTES` already exists at line 98:

```rust
/// Default disk reserve in bytes (20 GB).
pub const DEFAULT_DISK_RESERVE_BYTES: u64 = 20 * 1024 * 1024 * 1024;
```

---

## Changes to `budget/mod.rs`

### 1. Add `compute_effective_quota` (new public function)

```rust
/// Compute the effective storage quota for held symbols.
///
/// Parameters:
///   soft_quota:   user-configured cap in bytes. 0 = unlimited (no cap).
///   disk_free:    current free bytes on the filesystem partition (passed in
///                 by caller — this function does NOT query the OS).
///   disk_reserve: minimum free bytes to keep on the filesystem. Typically
///                 DEFAULT_DISK_RESERVE_BYTES (20 GB). Must be > 0 in
///                 practice; callers should never pass 0.
///
/// Returns:
///   The number of bytes available for held symbols.
///
/// Formula:
///   available_from_disk = disk_free.saturating_sub(disk_reserve)
///   if soft_quota == 0 { available_from_disk }
///   else               { soft_quota.min(available_from_disk) }
///
/// Edge cases:
///   - disk_free <= disk_reserve → returns 0 (disk critically full, no room)
///   - soft_quota == 0 && disk_free <= disk_reserve → returns 0
///   - soft_quota > 0 && disk_free >> disk_reserve → returns soft_quota
pub fn compute_effective_quota(soft_quota: u64, disk_free: u64, disk_reserve: u64) -> u64 {
    let available_from_disk = disk_free.saturating_sub(disk_reserve);
    if soft_quota == 0 {
        available_from_disk
    } else {
        soft_quota.min(available_from_disk)
    }
}
```

### 2. Add `hard_quota` guard to `evaluate_pressure`

**Signature stays the same.** Add a new parameter `hard_quota_bytes: u64` as
the second argument (after `quota_bytes`):

```rust
pub fn evaluate_pressure(
    quota_bytes: u64,
    hard_quota_bytes: u64,
    used_bytes: u64,
    holdings: &[HoldingRecord],
    owner_trust: impl Fn(&IdentityPub) -> f64,
    now_secs: u64,
) -> PressureResult;
```

**Behaviour change:**

The existing eviction loop already computes `deficit_bytes` — how many bytes
to free to get back to the soft threshold. With the hard_quota guard, the
loop must stop early if evicting would bring `used_bytes` below
`hard_quota_bytes`. That is:

```
do_not_evict_if:
    used_bytes - evicted_so_far - candidate.bytes < hard_quota_bytes
```

In other words: after an eviction, the remaining used bytes must not fall
below `hard_quota_bytes`. If the candidate would push below the floor, skip
it and continue to the next candidate.

If `hard_quota_bytes == 0`, the guard is disabled (current behaviour).

The guard applies **only to immediate_evictions** (Phase 1). Drop notices
(Phase 2) are not protected by the floor — they are just advance warnings
and the actual eviction happens later when the holder confirms.

### 3. Update `should_reject_offers`

**Signature stays the same.** No changes needed — callers will pass
`compute_effective_quota(...)` as the `quota_bytes` argument.

---

## Full updated signatures

```rust
/// Compute the effective storage quota from configuration values and
/// current filesystem free space. Pure function — does not query OS.
///
/// soft_quota:   0 = no cap (limited only by disk_free - disk_reserve).
/// disk_free:    bytes currently free on the filesystem partition.
/// disk_reserve: bytes to keep free. Use DEFAULT_DISK_RESERVE_BYTES if
///               no override.
pub fn compute_effective_quota(
    soft_quota: u64,
    disk_free: u64,
    disk_reserve: u64,
) -> u64;

/// Evaluate disk pressure and compute eviction targets.
///
/// quota_bytes:      effective quota (call compute_effective_quota first).
///                   0 = unlimited (returns Normal always).
/// hard_quota_bytes: eviction floor. Never evict if remaining usage would
///                   drop below this. 0 = disabled (no floor).
/// used_bytes:       current bytes used by all held symbols.
/// holdings:         all HoldingRecord entries (caller loads from DB).
/// owner_trust:      closure (IdentityPub → f64); UNKNOWN_OWNER_TRUST_FLOOR
///                   for unknown peers.
/// now_secs:         current Unix timestamp.
pub fn evaluate_pressure(
    quota_bytes: u64,
    hard_quota_bytes: u64,
    used_bytes: u64,
    holdings: &[HoldingRecord],
    owner_trust: impl Fn(&IdentityPub) -> f64,
    now_secs: u64,
) -> PressureResult;

// should_reject_offers — signature unchanged, no new parameter:
pub fn should_reject_offers(quota_bytes: u64, used_bytes: u64) -> bool;
```

---

## Business Rules

### `compute_effective_quota` formula

```
available_from_disk = disk_free.saturating_sub(disk_reserve)

if soft_quota == 0:
    effective_quota = available_from_disk
else:
    effective_quota = min(soft_quota, available_from_disk)
```

Rationale: `soft_quota` is "at most this much", `disk_reserve` is
"filesystem must always have at least this much free". Both constraints are
active simultaneously. `soft_quota = 0` means the user has not configured a
cap and the only limit is what the disk can spare.

### `hard_quota_bytes` guard in eviction

```
projected_used = used_bytes - freed_bytes_so_far

Before adding candidate to immediate_evictions:
    if hard_quota_bytes > 0 and
       projected_used - candidate.bytes < hard_quota_bytes:
        skip candidate (do NOT evict), continue loop

This means: if evicting this candidate would leave projected_used <
hard_quota_bytes, skip it. Try the next lower-priority candidate.

After the loop, freed_bytes may be less than deficit_bytes if the floor
prevented sufficient eviction. The PressureResult still records Hard
pressure in that case — the caller should log a warning.
```

Rationale: `hard_quota_bytes` protects the user's own data stored locally.
For example, if the user has 10 GB of their own files and configures
`hard_quota = 10 GB`, SyncBack will not evict down to zero to free space for
held symbols.

### Unchanged rules

All existing pressure threshold logic is unchanged:
- `SOFT_PRESSURE_THRESHOLD = 0.15`
- `HARD_PRESSURE_THRESHOLD = 0.05`
- Phase 1 (immediate eviction) / Phase 2 (drop notice) structure
- Eviction priority formula
- `MarkedForDelete` priority override
- `quota_bytes == 0` → Normal always

---

## Daemon integration point (informational, not implemented here)

The daemon scheduler (in `syncback/` crate, not `syncback-core`) will call
the budget module roughly like this:

```rust
// In scheduler tick (pseudocode):
let disk_free: u64 = get_filesystem_free_bytes(&config.storage_path)?;
let effective = compute_effective_quota(
    config.soft_quota_bytes,   // 0 if not set
    disk_free,
    config.disk_reserve_bytes, // defaults to DEFAULT_DISK_RESERVE_BYTES
);
let result = evaluate_pressure(
    effective,
    config.hard_quota_bytes,   // 0 if not set
    db.used_bytes(),
    &holdings,
    |id| trust_engine.score(id),
    now_secs(),
);
// Act on result.pressure, result.immediate_evictions, result.drop_notices
```

This task does NOT implement the scheduler. It only implements the pure logic.

---

## Test Scenarios

All tests go in `crates/syncback-core/src/budget/tests.rs`.
Add new tests below the existing ones. Do not modify existing tests.
The existing `evaluate_pressure_*` tests call the old 5-argument signature;
update those call sites to pass `0u64` as `hard_quota_bytes` (second argument)
to preserve current behaviour.

### Test 1: `compute_effective_quota_no_soft_cap`

```
soft_quota = 0 (unlimited)
disk_free = 100 GiB
disk_reserve = 20 GiB
→ effective = 100 GiB - 20 GiB = 80 GiB
```

### Test 2: `compute_effective_quota_soft_cap_is_tighter`

```
soft_quota = 50 GiB
disk_free = 200 GiB
disk_reserve = 20 GiB
available_from_disk = 200 - 20 = 180 GiB
→ effective = min(50, 180) = 50 GiB
```

### Test 3: `compute_effective_quota_disk_free_is_tighter`

```
soft_quota = 100 GiB
disk_free = 30 GiB
disk_reserve = 20 GiB
available_from_disk = 30 - 20 = 10 GiB
→ effective = min(100, 10) = 10 GiB
```

### Test 4: `compute_effective_quota_disk_critically_full`

```
soft_quota = 0 (unlimited)
disk_free = 10 GiB
disk_reserve = 20 GiB
available_from_disk = 10 GiB - 20 GiB → saturating_sub → 0
→ effective = 0
```

This means the scheduler will get `quota_bytes = 0` and treat it as
"unlimited" for the existing `evaluate_pressure` logic. However, the
scheduler should handle this case separately: if `effective == 0` and
`disk_free < disk_reserve`, it should log an ERROR and trigger emergency
eviction regardless of quota. That behaviour is in the daemon, not this
module. The pure function just returns 0.

DECISION NEEDED: Should `compute_effective_quota` distinguish "explicitly
unlimited" (soft_quota=0) from "disk full, nothing available" (returns 0)?
Current design has them both return 0. The caller would need to check
`disk_free < disk_reserve` separately. If this ambiguity causes issues,
consider returning an enum instead of u64. Leave as u64 for now.

### Test 5: `compute_effective_quota_soft_cap_zero_and_disk_large`

```
soft_quota = 0
disk_free = 1000 GiB
disk_reserve = 20 GiB
→ effective = 980 GiB
```

Confirms the "unlimited" case uses all available disk minus reserve.

### Test 6: `compute_effective_quota_exact_reserve_boundary`

```
soft_quota = 0
disk_free = 20 GiB  (exactly the reserve)
disk_reserve = 20 GiB
→ effective = 0  (saturating_sub: 20 - 20 = 0)
```

### Test 7: `evaluate_pressure_hard_quota_prevents_eviction`

Hard pressure scenario but hard_quota_bytes prevents any eviction.

```
quota_bytes = 100 GiB
hard_quota_bytes = 100 GiB  (floor = entire quota → nothing can be evicted)
used_bytes = 97 GiB   → free_ratio = 0.03 → Hard
holdings = [
    A: importance=0.1, trust=0.5, 5 GiB, Active
]
→ pressure = Hard
→ immediate_evictions = []  (evicting A would bring used to 92 GiB < 100 GiB floor)
→ freed_bytes = 0
```

### Test 8: `evaluate_pressure_hard_quota_partial_eviction`

Floor allows some but not all evictions.

```
quota_bytes = 100 GiB
hard_quota_bytes = 90 GiB  (can only free down to 90 GiB usage)
used_bytes = 97 GiB → Hard
deficit = 0.15 * 100 - 3 = 12 GiB
holdings = [
    A: importance=0.1, trust=0.5, 5 GiB → priority 0.05  (evict first)
    B: importance=0.9, trust=0.9, 5 GiB → priority 0.81  (evict last)
]
After evicting A: projected_used = 97 - 5 = 92 GiB
  92 GiB >= 90 GiB floor → allowed. freed_bytes = 5 GiB.
After evicting B: projected_used = 92 - 5 = 87 GiB
  87 GiB < 90 GiB floor → SKIP.
→ immediate_evictions = [A]
→ freed_bytes = 5 GiB  (< deficit of 12 GiB, but floor blocks more)
→ pressure = Hard  (still reported as Hard even if eviction was partial)
```

### Test 9: `evaluate_pressure_hard_quota_zero_disables_floor`

Confirms that `hard_quota_bytes = 0` preserves existing behaviour.

```
quota_bytes = 100 GiB
hard_quota_bytes = 0  (no floor)
used_bytes = 97 GiB → Hard
holdings = [
    A: importance=0.1, trust=0.5, 5 GiB
    B: importance=0.9, trust=0.9, 5 GiB
    C: importance=0.5, trust=0.5, 5 GiB
]
→ Same result as existing evaluate_pressure_hard_evicts_lowest_priority test.
→ All three evicted (freed=15 GiB >= deficit=12 GiB).
```

### Test 10: `should_reject_offers_with_effective_quota`

Demonstrates that callers use `compute_effective_quota` before calling
`should_reject_offers`. This is an integration-style test of the two
functions together.

```
soft_quota = 80 GiB
disk_free = 50 GiB
disk_reserve = 20 GiB
effective = min(80, 50-20) = min(80, 30) = 30 GiB

used_bytes = 26 GiB
free_ratio = (30 - 26) / 30 = 4/30 ≈ 0.133 < 0.15
→ should_reject_offers(effective, used_bytes) = true
```

---

## Migration: existing call sites

The signature of `evaluate_pressure` gains one new parameter
(`hard_quota_bytes: u64`) as the second argument. All existing tests that
call `evaluate_pressure` must add `0u64` as the second argument to preserve
current behaviour.

Existing call sites in `budget/tests.rs` (lines 232, 241, 293):
- `evaluate_pressure(gib(100), gib(80), ...)` → `evaluate_pressure(gib(100), 0, gib(80), ...)`
- `evaluate_pressure(gib(100), gib(88), ...)` → `evaluate_pressure(gib(100), 0, gib(88), ...)`
- `evaluate_pressure(gib(100), gib(97), ...)` → `evaluate_pressure(gib(100), 0, gib(97), ...)`

The implementer must update these three call sites. No other changes to
existing tests.

---

## What NOT to do

- Do not query the filesystem from within `syncback-core`. This crate is
  pure logic. Filesystem calls happen in the daemon (`syncback/` crate).
- Do not introduce an `AppConfig` dependency in `syncback-core`. Config
  values are passed as plain `u64` parameters.
- Do not change `should_reject_offers` signature. The caller computes
  effective_quota and passes it in.
- Do not create a new module. All changes go in `budget/mod.rs` and
  `budget/tests.rs`.
- Do not add logging (`tracing`) to `syncback-core`. It is a pure logic
  library.

---

## Files to modify

1. `/home/ilya/projects/syncback/crates/syncback-core/src/budget/mod.rs`
   - Add `compute_effective_quota` function
   - Add `hard_quota_bytes: u64` parameter to `evaluate_pressure` (second argument)
   - Add hard_quota guard in the eviction loop

2. `/home/ilya/projects/syncback/crates/syncback-core/src/budget/tests.rs`
   - Update three existing `evaluate_pressure` call sites (add `0u64`)
   - Add 10 new tests (scenarios 1–10 above)

No other files require changes for this task.

---

## Definition of done

- `cargo test -p syncback-core` passes with no failures
- `cargo clippy -p syncback-core -- -D warnings` clean
- All 10 new test functions present and passing
- Existing 3 `evaluate_pressure` call sites updated with `0u64`
- `compute_effective_quota` is `pub` and tested
- `hard_quota_bytes` guard logic present in `evaluate_pressure`
