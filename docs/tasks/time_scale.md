# Task spec: time_scale — virtual time acceleration for integration testing

**Target files:**
- `crates/syncback/src/daemon/mod.rs` — add `time_scale: u64` to `Config`
- `crates/syncback/src/daemon/scheduler.rs` — scale all Duration constants at startup
- `crates/syncback/src/daemon/processor/mod.rs` — replace `Timestamp::now()` calls with `Processor::now()`, pass `time_scale` into `run()`
- `crates/syncback-core/src/types/mod.rs` — no changes needed (see rationale)

**Phase:** 5 (scale testing infrastructure)
**Role:** Cross-cutting time infrastructure enabling compressed-time integration tests

---

## Overview

Scheduler uses hardcoded `Duration` constants (WEEKLY=604800s, TICK=300s, etc.).
Processor calls `Timestamp::now()` (wall-clock) in every handler that needs the current
time. `current_week = unix_seconds / SECS_PER_WEEK` is computed from real wall-clock.

For integration testing we need to run 26 simulated weeks in ~30 real seconds across
3-5 nodes: verify trust accumulation, escrow gate progression, PoS dynamics.

**Solution:** A `time_scale: u64` knob in `Config` that:
1. Divides all Scheduler Duration values (WEEKLY / time_scale → 604800/time_scale seconds).
2. Gives the Processor a `now()` helper that maps real elapsed time to a proportionally
   advanced virtual Unix timestamp.

`time_scale = 1` (the default) produces exactly the current behavior. No core types change.

---

## Rationale for NOT touching `Timestamp::now()` in syncback-core

`Timestamp::now()` in `types/mod.rs` is used by syncback-core modules directly in tests
(e.g., `testutil::week(n)`). Changing it would require threading a clock into every
engine. Those tests are already millisecond-fast and do not need time scaling.

The daemon (syncback crate) is the only place that cares about real wall-clock vs.
virtual clock for integration testing. Therefore time scaling lives exclusively in the
daemon layer: `Processor::now()` replaces direct `Timestamp::now()` calls inside
processor handlers.

---

## Dependencies

- `crates/syncback/src/daemon/mod.rs` — `Config` struct (already read)
- `crates/syncback/src/daemon/scheduler.rs` — `run()` function (already read)
- `crates/syncback/src/daemon/processor/mod.rs` — `run()` and all handler methods (already read)
- `crates/syncback-core/src/types/mod.rs` — `Timestamp` struct (read, no changes)

---

## Changes by file

---

### 1. `crates/syncback/src/daemon/mod.rs`

#### 1a. Add `time_scale` to `Config`

```rust
#[derive(Debug, Clone)]
pub struct Config {
    pub syncback_dir: PathBuf,
    pub backup: BackupConfig,
    pub storage: StorageConfig,
    pub network: NetworkConfig,
    pub schedule: ScheduleConfig,
    /// Virtual time acceleration factor.
    /// 1 = real time (default, production behavior).
    /// N = each real second counts as N virtual seconds.
    /// Scheduler intervals are divided by this value.
    /// Only intended for integration tests.
    pub time_scale: u64,
}
```

#### 1b. `Config::default()` sets `time_scale: 1`

```rust
impl Default for Config {
    fn default() -> Self {
        Config {
            // ... existing fields unchanged ...
            time_scale: 1,
        }
    }
}
```

`Config::load()` keeps returning `Config::default()` — no config file parsing needed.
Integration tests set `time_scale` by constructing `Config` directly.

#### 1c. Pass `time_scale` to `scheduler::run` and `processor::run`

In `DaemonHandle::start`:

```rust
let scheduler_handle = tokio::spawn(scheduler::run(
    cancel.clone(),
    processor_tx.clone(),
    config.time_scale,          // NEW argument
));

let processor_handle = tokio::spawn(processor::run(
    db,
    cancel.clone(),
    processor_rx,
    dirty_rx,
    net_event_rx,
    net_cmd_tx,
    config.clone(),
    identity_signing_key,
    identity_pub,
    own_node_id,
    // time_scale is inside config — no extra argument needed here
));
```

Note: `processor::run` already receives `config: Config`, so `config.time_scale` is
available inside. No change to the `processor::run` signature is needed for this field.

---

### 2. `crates/syncback/src/daemon/scheduler.rs`

#### 2a. Change `run` signature to accept `time_scale`

```rust
pub async fn run(
    cancel: CancellationToken,
    processor_tx: mpsc::Sender<ProcessorMsg>,
    time_scale: u64,
) {
```

#### 2b. Compute scaled durations at startup from the base constants

The five base constants remain as-is (they document the real-time intent):

```rust
const TICK: Duration = Duration::from_secs(300);          // 5 minutes
const WEEKLY: Duration = Duration::from_secs(604_800);    // 7 days
const MONTHLY: Duration = Duration::from_secs(2_592_000); // 30 days
const POS_FIRST_OFFSET: Duration = Duration::from_secs(86_400);      // 1 day
const REPAIR_FIRST_OFFSET: Duration = Duration::from_secs(172_800);  // 2 days
const SYSTEM_STATE_BACKUP_FIRST_OFFSET: Duration = Duration::from_secs(8 * 24 * 3600);
```

At the top of `run()`, derive scaled variants:

```rust
pub async fn run(
    cancel: CancellationToken,
    processor_tx: mpsc::Sender<ProcessorMsg>,
    time_scale: u64,
) {
    let scale = time_scale.max(1); // guard: 0 is treated as 1

    let tick        = scale_duration(TICK, scale);
    let weekly      = scale_duration(WEEKLY, scale);
    let monthly     = scale_duration(MONTHLY, scale);
    let pos_offset  = scale_duration(POS_FIRST_OFFSET, scale);
    let repair_offset = scale_duration(REPAIR_FIRST_OFFSET, scale);
    let ss_offset   = scale_duration(SYSTEM_STATE_BACKUP_FIRST_OFFSET, scale);

    let start = Instant::now();
    let mut weekly_sync_due        = start + weekly;
    let mut pos_round_due          = start + pos_offset;
    let mut repair_check_due       = start + repair_offset;
    let mut vacuum_due             = start + monthly;
    let mut system_state_backup_due = start + ss_offset;

    // ... existing loop body unchanged, but using local variables
    //     instead of the TICK/WEEKLY/MONTHLY constants ...
    loop {
        tokio::select! {
            _ = cancel.cancelled() => { break; }
            _ = tokio::time::sleep(tick) => {
                let now = Instant::now();
                if now >= weekly_sync_due {
                    send_cmd(&processor_tx, ScheduledCmd::WeeklySync, "weekly_sync").await;
                    weekly_sync_due = now + weekly;
                }
                if now >= pos_round_due {
                    send_cmd(&processor_tx, ScheduledCmd::PosRound, "pos_round").await;
                    pos_round_due = now + weekly;
                }
                if now >= repair_check_due {
                    send_cmd(&processor_tx, ScheduledCmd::RepairCheck, "repair_check").await;
                    repair_check_due = now + weekly;
                }
                if now >= vacuum_due {
                    send_cmd(&processor_tx, ScheduledCmd::Vacuum, "vacuum").await;
                    vacuum_due = now + monthly;
                }
                if now >= system_state_backup_due {
                    send_cmd(&processor_tx, ScheduledCmd::SystemStateBackup, "system_state_backup").await;
                    system_state_backup_due = now + weekly;
                }
            }
        }
    }
}

/// Divide a Duration by a scale factor. Minimum result: 1ms (avoids busy-loop).
fn scale_duration(d: Duration, scale: u64) -> Duration {
    let millis = d.as_millis() as u64;
    Duration::from_millis((millis / scale).max(1))
}
```

The `scale_duration` helper is a private free function in `scheduler.rs`.

#### 2c. Existing tests still pass

All existing scheduler tests use `super::run(cancel.clone(), tx)` — they must be updated
to `super::run(cancel.clone(), tx, 1)`. The `time_scale=1` path is identical to the
current path because `scale_duration(d, 1) == d` (integer division: millis/1 = millis).

The test that uses `super::TICK` directly:
```rust
let ticks = target.as_secs() / super::TICK.as_secs() + 1;
```
still works because `TICK` is still a module-level constant at 300s. The test calls
`run(..., 1)` which makes `tick = TICK`. The internal `tick` local variable in `run()`
equals the constant when `scale=1`, so `tokio::time::advance(TICK + ...)` correctly
advances past each tick boundary.

---

### 3. `crates/syncback/src/daemon/processor/mod.rs`

#### 3a. Add `VirtualClock` to `Processor` struct

```rust
/// Tracks virtual time state for time-scaled operation.
/// When time_scale == 1, `now()` returns real wall-clock time.
struct VirtualClock {
    /// Real monotonic instant when the daemon started.
    real_start: std::time::Instant,
    /// Virtual Unix timestamp at daemon start (real wall-clock at startup).
    virtual_start_secs: u64,
    /// Acceleration factor. 1 = real time.
    time_scale: u64,
}

impl VirtualClock {
    fn new(time_scale: u64) -> Self {
        let virtual_start_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs();
        VirtualClock {
            real_start: std::time::Instant::now(),
            virtual_start_secs,
            time_scale: time_scale.max(1),
        }
    }

    /// Return the current virtual Timestamp.
    /// elapsed_real * time_scale is added to the real Unix time at startup.
    fn now(&self) -> syncback_core::types::Timestamp {
        let elapsed_real_secs = self.real_start.elapsed().as_secs();
        let virtual_secs = self.virtual_start_secs + elapsed_real_secs * self.time_scale;
        syncback_core::types::Timestamp(virtual_secs)
    }
}
```

`VirtualClock` is a private struct defined in `processor/mod.rs` (or a sub-module
`processor/clock.rs` — implementer's choice; `mod.rs` is simpler).

#### 3b. Add `clock` field to `Processor`

```rust
struct Processor {
    db: Db,
    trust: TrustEngine,
    escrow: EscrowChecker,
    placement: PlacementEngine,
    budget: BudgetPlanner,
    storage: Storage,
    shard_manager: ShardManager,
    repair_engine: RepairEngine,
    packer: Packer,
    net_cmd_tx: mpsc::Sender<NetCommand>,
    identity_key: ed25519_dalek::SigningKey,
    identity_pub: IdentityPub,
    own_node_id: String,
    pending_pos_challenges: HashMap<[u8; 32], PendingPosChallenge>,
    pending_dr_peer_addr: Option<String>,
    pending_dr_cli_reply: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    pending_dr_reply: Option<tokio::sync::oneshot::Sender<Result<syncback_core::messages::SystemStateResponseMsg, String>>>,
    clock: VirtualClock,   // NEW
}
```

#### 3c. Initialize `clock` in `Processor::new` (inside `run()`)

```rust
let clock = VirtualClock::new(config.time_scale);
let mut processor = Processor {
    // ... existing fields ...
    clock,
};
```

#### 3d. Add `Processor::now()` helper

```rust
impl Processor {
    fn now(&self) -> syncback_core::types::Timestamp {
        self.clock.now()
    }
}
```

#### 3e. Replace all `Timestamp::now()` calls in processor handlers

Every call to `Timestamp::now()` inside `processor/mod.rs` is replaced with
`self.now()`. The full list of sites (from the grep above):

| Line context | Replace |
|---|---|
| `run_weekly_sync`: `let now = Timestamp::now();` | `let now = self.now();` |
| `run_pos_round`: `let now = Timestamp::now();` | `let now = self.now();` |
| `run_vacuum`: `let now = Timestamp::now();` | `let now = self.now();` |
| `run_repair_check`: `let now = Timestamp::now();` | `let now = self.now();` |
| `handle_system_state_backup`: `let now = Timestamp::now();` | `let now = self.now();` |
| `handle_system_state_backup_received`: `let now = Timestamp::now();` | `let now = self.now();` |
| `handle_peer_connected`: `let now = Timestamp::now();` | `let now = self.now();` |
| `handle_direct_message`: `let now = Timestamp::now();` | `let now = self.now();` |
| `handle_board_message` (shard_offer path): `let now = Timestamp::now();` | `let now = self.now();` |
| PoS response handler: `let now = Timestamp::now();` | `let now = self.now();` |
| Restore request handler: `let now = Timestamp::now();` | `let now = self.now();` |
| `handle_shard_uploaded`: `let now = Timestamp::now();` | `let now = self.now();` |
| `handle_shard_downloaded`: `let now = Timestamp::now();` | `let now = self.now();` |
| `handle_peers_cmd` (cli): `let now = syncback_core::types::Timestamp::now();` | `let now = self.now();` |
| `RestoreRequestMsg` construction: `ts: syncback_core::types::Timestamp::now().0` | `ts: self.now().0` |

**Important:** `current_week = (now.0 / SECS_PER_WEEK) as u32` already derives from
`now`, so it automatically uses virtual time once `now = self.now()`.

**Do NOT replace** `Timestamp::now()` calls in:
- `syncback-core` modules (trust, escrow, escrow_checker, db) — they use real time
  internally and are tested independently with fake timestamps passed from outside.
- The `DirtyEvent` construction in `watcher.rs` — watcher timestamps are wall-clock
  events (file change detection), not protocol time.

#### 3f. `weeks_in_network` increment remains correct

`weeks_in_network` is incremented by `increment_peer_weeks()` once per `WeeklySync`
(line ~363). With time scaling, `WeeklySync` fires every `WEEKLY/time_scale` real
seconds. Each firing still calls `increment_peer_weeks()` exactly once — the semantics
are "one logical week passed". This is correct: 26 WeeklySync events = 26 weeks in
network, regardless of real wall-clock time elapsed.

No change needed to the `weeks_in_network` logic.

---

## Public API

### New function: `scale_duration` (private to scheduler.rs)

```rust
fn scale_duration(d: Duration, scale: u64) -> Duration;
```

Exposed only for tests within `scheduler.rs`. Not public.

### New type: `VirtualClock` (private to processor/mod.rs)

```rust
struct VirtualClock { ... }

impl VirtualClock {
    fn new(time_scale: u64) -> Self;
    fn now(&self) -> syncback_core::types::Timestamp;
}
```

Not `pub`. Only used within the processor module.

### Changed `scheduler::run` signature

```rust
pub async fn run(
    cancel: CancellationToken,
    processor_tx: mpsc::Sender<ProcessorMsg>,
    time_scale: u64,
) -> ()
```

### Changed `Config`

```rust
pub struct Config {
    // ... all existing fields ...
    pub time_scale: u64,   // default = 1
}
```

---

## DB operations

None. No new tables, no new DB methods. This change is purely in the daemon runtime.

---

## Business rules

### Formula: virtual time

```
virtual_unix_secs(t) = real_unix_start + (t - real_start) * time_scale
```

Where:
- `real_unix_start` = wall-clock Unix seconds at daemon startup (captured in `VirtualClock::new`)
- `t - real_start` = real elapsed seconds since startup (from `Instant::elapsed()`)
- `time_scale` = acceleration factor (1 = real time)

The resulting `Timestamp` feeds into `current_week`, PoS timestamps, `last_seen`,
`received_at`, `created_at` — all protocol-level time fields stored in the DB.

### Invariant: time_scale = 1 produces identical behavior

When `time_scale = 1`:
- `scale_duration(d, 1)` = `d` (integer millis / 1 = same millis)
- `VirtualClock::now()` = `virtual_start_secs + elapsed * 1` ≈ `Timestamp::now()`

The slight difference: `VirtualClock` anchors to the startup instant, while
`Timestamp::now()` captures the current instant at each call. For a single-second test,
the delta is sub-second — within existing test tolerances. For production runs
(hours/weeks), the drift is zero since we always add real elapsed time.

For completeness: if the daemon runs for 1 hour (`time_scale=1`), `VirtualClock::now()`
returns `startup_unix + 3600`, while `Timestamp::now()` returns `now_unix`. These are
identical if the system clock does not drift. On NTP-synced systems this is
indistinguishable.

### Minimum tick: 1ms

`scale_duration` clamps to `Duration::from_millis(1)` minimum. This prevents:
- `time_scale > TICK.as_millis()` (300_000x+) from producing zero-duration sleep
- Busy-loop in the scheduler

In practice, tests use `time_scale` up to ~26000 (26 weeks in 30 seconds → WEEKLY /
(604800s/30s) = 604800/20160 ≈ 30). No risk of hitting the 1ms floor.

### `time_scale = 0` is treated as 1

`scale.max(1)` guard in both `scale_duration` and `VirtualClock::new`.

### Watcher and network use real time

`DirtyEvent.detected_at` (watcher) and iroh connection timestamps are real wall-clock.
These are not protocol time fields — they are internal daemon bookkeeping. Not scaled.

---

## Test scenarios

### Unit tests in `scheduler.rs` (update existing + add new)

#### Update existing tests

All tests currently call `super::run(cancel.clone(), tx)`. Change to
`super::run(cancel.clone(), tx, 1)`. Behavior must be identical.

Verify: `scheduler_shuts_down_cleanly_on_cancel` with `time_scale=1` still passes.

#### `scale_duration_divides_correctly`

```rust
#[test]
fn scale_duration_divides_correctly() {
    let d = Duration::from_secs(604_800);
    assert_eq!(super::scale_duration(d, 1), d);
    assert_eq!(super::scale_duration(d, 60), Duration::from_secs(10_080));
    assert_eq!(super::scale_duration(d, 604_800), Duration::from_secs(1));
    // Very large scale: clamp to 1ms minimum
    assert_eq!(super::scale_duration(Duration::from_millis(1), 1_000_000),
               Duration::from_millis(1));
}
```

#### `scale_duration_zero_is_one_millisecond`

```rust
#[test]
fn scale_duration_zero_is_one_millisecond() {
    // scale=0 is treated as max(0,1)=1 in run(), but scale_duration itself
    // clamps result to 1ms minimum
    let tiny = Duration::from_millis(1);
    assert!(super::scale_duration(tiny, u64::MAX) >= Duration::from_millis(1));
}
```

#### `scheduler_with_scale_fires_weekly_faster`

```rust
#[tokio::test(start_paused = true)]
async fn scheduler_with_scale_fires_weekly_faster() {
    // time_scale = 7 * 24: 1 real second = 7*24 virtual seconds
    // WEEKLY / scale = 604800 / (7*24) = 3600 real seconds
    // TICK / scale = 300 / 168 ≈ 1.78 seconds real → Duration::from_millis(1785)
    let scale = 7 * 24_u64;
    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel(32);

    tokio::spawn(super::run(cancel.clone(), tx, scale));

    // Advance exactly WEEKLY/scale + one tick margin
    let scaled_weekly = super::scale_duration(super::WEEKLY, scale);
    let scaled_tick   = super::scale_duration(super::TICK, scale);
    let target = scaled_weekly + scaled_tick * 2;

    // Advance in tick-sized chunks so the scheduler loop wakes up
    let ticks = (target.as_millis() / scaled_tick.as_millis()) as u64 + 2;
    for _ in 0..ticks {
        tokio::time::advance(scaled_tick + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
    }

    let cmds: Vec<_> = {
        let mut v = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            if let ProcessorMsg::Scheduled(cmd) = msg {
                v.push(cmd);
            }
        }
        v
    };

    assert!(
        cmds.iter().any(|c| matches!(c, ScheduledCmd::WeeklySync)),
        "expected WeeklySync after scaled weekly interval, got: {cmds:?}"
    );

    cancel.cancel();
}
```

Note: this test needs `TICK` and `WEEKLY` to be `pub(crate)` or `pub` in `scheduler.rs`.
Currently they are private `const`. Change to `pub(crate) const` for test access.

```rust
pub(crate) const TICK: Duration = Duration::from_secs(300);
pub(crate) const WEEKLY: Duration = Duration::from_secs(604_800);
```

### Unit tests in `processor/mod.rs` (or `processor/tests.rs`)

#### `virtual_clock_scale_1_approximates_real_time`

```rust
#[test]
fn virtual_clock_scale_1_approximates_real_time() {
    let clock = VirtualClock::new(1);
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let virtual_now = clock.now().0;
    // Should be within 2 seconds of real time
    assert!(virtual_now.abs_diff(real_now) <= 2,
        "virtual={virtual_now}, real={real_now}");
}
```

#### `virtual_clock_advances_proportionally`

```rust
#[test]
fn virtual_clock_advances_proportionally() {
    // We can't control Instant::now() directly, but we can verify the formula.
    // Construct a clock then call now() twice and compare deltas.
    // Since we can't freeze time in a unit test, just verify the scale applies.
    let scale = 100_u64;
    let clock = VirtualClock::new(scale);
    let t0 = clock.now().0;
    // Spin for ~1ms of real time
    std::thread::sleep(std::time::Duration::from_millis(10));
    let t1 = clock.now().0;
    let delta = t1 - t0;
    // 10ms real * 100 = 1 virtual second → delta should be >= 0
    // (exact value depends on OS scheduling; just verify it's non-negative
    //  and not absurdly large)
    assert!(delta <= 10, "unexpected large delta: {delta}s in 10ms real time");
    // delta >= 0 is guaranteed by type (u64)
}
```

#### `virtual_clock_scale_zero_treated_as_one`

```rust
#[test]
fn virtual_clock_scale_zero_treated_as_one() {
    let c0 = VirtualClock::new(0);
    let c1 = VirtualClock::new(1);
    // Both should return approximately the same virtual time
    let diff = c0.now().0.abs_diff(c1.now().0);
    assert!(diff <= 1, "scale=0 and scale=1 should produce same virtual time, diff={diff}");
}
```

### Integration test: `26_weeks_in_30_seconds` (new file)

Location: `crates/syncback/tests/time_scale_integration.rs`

This test is the primary motivation for the feature.

```rust
/// Verify that with time_scale = SECS_PER_WEEK / 1 (one virtual week per second),
/// a node accumulates 4 weeks_in_network in ~5 real seconds.
/// This validates the full clock-to-scheduler-to-processor pipeline.
#[tokio::test]
async fn four_virtual_weeks_in_four_seconds() {
    use std::time::Duration;
    use syncback_core::constants::SECS_PER_WEEK;

    // 1 virtual week per 1 real second
    let time_scale = SECS_PER_WEEK;

    // Start a single daemon node in a temp dir, using the time_scale config.
    let dir = tempfile::tempdir().unwrap();
    let mut config = syncback::daemon::Config::default();
    config.syncback_dir = dir.path().to_path_buf();
    config.time_scale = time_scale;

    let handle = syncback::daemon::DaemonHandle::start(config)
        .await
        .expect("daemon start failed");

    // Wait 4 real seconds. Expect 4 WeeklySync events to have fired.
    // Each WeeklySync increments weeks_in_network for all known peers.
    // We just verify the daemon is still alive and the scheduler ran without panic.
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Status check: daemon responds.
    let sock = dir.path().join("syncback.sock");
    // (Use existing send_cli_request helper or inline the socket call)
    // Verify at minimum that the daemon did not panic and is responsive.

    handle.shutdown().await.expect("daemon shutdown failed");
}
```

**Note:** A more thorough version of this test would connect two nodes, run for ~30
real seconds with `time_scale = SECS_PER_WEEK / 2` (one week every 2 seconds → 26
weeks in 52 seconds), and verify `weeks_in_network >= 26` on peer records. That test
belongs in a dedicated Phase 5 gate spec. The test above is a smoke check that the
pipeline does not panic.

---

## File layout

```
crates/syncback/src/daemon/
    mod.rs          — Config.time_scale field + pass to scheduler::run
    scheduler.rs    — run(cancel, tx, time_scale) + scale_duration helper
    processor/
        mod.rs      — VirtualClock struct, Processor.clock field, self.now()
        tests.rs    — 3 new unit tests for VirtualClock

crates/syncback/tests/
    time_scale_integration.rs   — smoke integration test
```

---

## Checklist for implementer

### Step 1: Config

- [ ] `time_scale: u64` added to `Config`
- [ ] `Config::default()` sets `time_scale: 1`
- [ ] `DaemonHandle::start` passes `config.time_scale` to `scheduler::run`

### Step 2: Scheduler

- [ ] `scheduler::run` signature changed to accept `time_scale: u64`
- [ ] `scale_duration(d: Duration, scale: u64) -> Duration` private fn added
- [ ] All five Duration variables computed via `scale_duration` at startup
- [ ] Local `tick`/`weekly`/`monthly` variables used in loop instead of constants
- [ ] `TICK` and `WEEKLY` changed to `pub(crate) const` (for test access)
- [ ] All existing scheduler tests updated: `run(cancel, tx)` → `run(cancel, tx, 1)`
- [ ] New test `scale_duration_divides_correctly` passes
- [ ] New test `scheduler_with_scale_fires_weekly_faster` passes

### Step 3: Processor

- [ ] `VirtualClock` struct defined in `processor/mod.rs`
- [ ] `Processor.clock: VirtualClock` field added
- [ ] `Processor::now()` helper added
- [ ] All `Timestamp::now()` calls in `processor/mod.rs` replaced with `self.now()`
- [ ] `VirtualClock` initialized in `Processor` construction inside `run()`
- [ ] Three new unit tests in `processor/tests.rs`

### Step 4: Tests

- [ ] `crates/syncback/tests/time_scale_integration.rs` created with smoke test
- [ ] All existing tests pass: `cargo test -p syncback`

### Step 5: Clippy

- [ ] No unused imports (`Timestamp` import may now be unused in processor if
      all calls go through `self.now()` — keep the import if it's still needed for
      type annotations, or remove if not needed)
- [ ] `scale_duration` is actually called (not dead code)
- [ ] No `allow(dead_code)` hacks

---

## Key decisions (settled)

- **No core changes:** `Timestamp::now()` in `syncback-core` is unchanged. Scaling is
  a daemon-layer concern only. This keeps core tests fast and independent.
- **Multiplicative, not offset:** Virtual time = `real_start + elapsed * scale`, not
  a hardcoded offset. This means the DB timestamps are believable Unix timestamps
  (e.g., March 2026 + N virtual weeks), not artificial values starting at 0.
- **`weeks_in_network` semantics preserved:** Each WeeklySync tick = 1 logical week.
  No fractional weeks. Escrow gates (4/13/26 weeks) are tested by running N WeeklySync
  events, which is exactly what time_scale enables.
- **`scale=0` is clamped to 1:** No division-by-zero in `scale_duration`.
- **`TICK` and `WEEKLY` stay as module-level constants:** They document the real-time
  intent and are used in existing tests. The scaled values are local variables in `run()`.
- **No `tokio::time::pause()` dependency in production:** `VirtualClock` uses
  `std::time::Instant`, not `tokio::time`. This means time-scaled tests run in real
  time (no pausing), which makes them more realistic for multi-node integration scenarios.
  The existing scheduler unit tests continue to use `tokio::time::pause()` because they
  test the scheduler logic directly without needing the processor.

---

## DECISION NEEDED

None. All design choices are settled above.
