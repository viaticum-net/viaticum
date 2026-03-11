# Task spec: scheduler module (Phase 2)

**Target file:** `crates/syncback/src/daemon/scheduler.rs`
**Phase:** 2 (replaces the stub created in daemon_skeleton)
**Role:** Timer loop — fires periodic commands into the Processor via channel

---

## Overview

The Scheduler is one of the five tokio tasks in the daemon. Its only job is to wake up
at regular intervals, check whether a periodic task is due, and if so send a
`ProcessorMsg::Scheduled(cmd)` to the Processor. It carries no state beyond what the DB
holds (schedule table). It does not access the DB directly during the timer loop — it
reads schedule records only at startup to compute initial sleep durations.

ADR-003 describes the pattern:

```
loop {
    if now - last_weekly_sync >= 1 week  → send(WeeklySync)
    if now - last_pos_round  >= 1 day    → send(PosRound)
    if now - last_vacuum     >= 1 month  → send(Vacuum)
    sleep(5 min)
}
```

The timestamps of last runs are stored in the `schedule` table (key = task name,
value = CBOR(ScheduleRecord)). They survive daemon restarts. Processor is responsible for
writing back the "last_run" timestamp after each task completes; the Scheduler only reads
the schedule at startup.

**The Scheduler does NOT write to the DB.** Writes happen in Processor after the command
is processed and the task is done.

---

## Dependencies

**Crates:**
- `syncback-core::db::Db` — read-only, only at startup (not during loop)
- `syncback-core::types::Timestamp` — for current time
- `syncback-core::types::ScheduleRecord` — read from `schedule` table
- `tokio::time::{interval, sleep, Duration, Instant}`
- `tokio::sync::mpsc::Sender<ProcessorMsg>`
- `tokio_util::sync::CancellationToken`
- `crate::daemon::{ProcessorMsg, ScheduledCmd}`

**Other modules:** none — scheduler is the simplest Phase 2 module.

---

## Public API

```rust
/// Run the scheduler task. Loops until `cancel` is signalled.
/// Checks at every tick whether each scheduled task is due; if so, sends the command.
/// The `db` handle is used at startup to read last_run timestamps; not accessed during loop.
pub async fn run(
    db: syncback_core::db::Db,
    cancel: tokio_util::sync::CancellationToken,
    processor_tx: tokio::sync::mpsc::Sender<crate::daemon::ProcessorMsg>,
);
```

This is a free async function (no struct needed — the scheduler has no methods to call
from outside). The daemon spawns it with `tokio::spawn(scheduler::run(db, cancel, tx))`.

---

## Scheduled tasks

| Task name (`schedule` key) | Command | Default interval | Offset |
|---|---|---|---|
| `"weekly_sync"` | `WeeklySync` | 7 days (604800 s) | 0 |
| `"pos_round"` | `PosRound` | 7 days (604800 s) | 1 day offset from sync |
| `"repair_check"` | `RepairCheck` | 7 days (604800 s) | 2 days offset from sync |
| `"vacuum"` | `Vacuum` | 30 days (2592000 s) | 0 |

"Offset" means: on first run (no prior DB record), the task is scheduled at
`startup_time + offset`. This avoids all four tasks firing simultaneously on first launch.

Concrete first-run delays (if no schedule record exists in DB):
- `weekly_sync`: fires after 7 days (no offset — next Sunday, roughly)
- `pos_round`: fires after 1 day on first run, then every 7 days
- `repair_check`: fires after 2 days on first run, then every 7 days
- `vacuum`: fires after 30 days on first run

---

## Task logic

### Startup sequence

```
1. For each task name in ["weekly_sync", "pos_round", "repair_check", "vacuum"]:
     read ScheduleRecord from db.get_schedule(task_name)
     if record exists: next_due = record.next_run
     else: next_due = Timestamp::now() + first_run_offset (see table above)

2. Store next_due for each task in local variables (not re-read from DB during loop)

3. Enter tick loop
```

The Scheduler does not update the `schedule` table. Only Processor writes to it after
completing the task (via `db.set_schedule()`). The Scheduler simply fires based on elapsed
time since it read next_due at startup. If the daemon restarts before Processor writes
back the record, the task may fire again on restart — this is acceptable for weekly tasks.

### Tick loop

```rust
const TICK_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

loop {
    select! {
        _ = cancel.cancelled() => break,
        _ = tokio::time::sleep(TICK_INTERVAL) => {
            let now = Timestamp::now();
            if now.0 >= weekly_sync_due.0 {
                send_cmd(&processor_tx, ScheduledCmd::WeeklySync, "weekly_sync").await;
                weekly_sync_due = Timestamp(now.0 + 7 * 24 * 3600);
            }
            if now.0 >= pos_round_due.0 {
                send_cmd(&processor_tx, ScheduledCmd::PosRound, "pos_round").await;
                pos_round_due = Timestamp(now.0 + 7 * 24 * 3600);
            }
            if now.0 >= repair_check_due.0 {
                send_cmd(&processor_tx, ScheduledCmd::RepairCheck, "repair_check").await;
                repair_check_due = Timestamp(now.0 + 7 * 24 * 3600);
            }
            if now.0 >= vacuum_due.0 {
                send_cmd(&processor_tx, ScheduledCmd::Vacuum, "vacuum").await;
                vacuum_due = Timestamp(now.0 + 30 * 24 * 3600);
            }
        }
    }
}
```

### `send_cmd` helper

```rust
async fn send_cmd(
    tx: &tokio::sync::mpsc::Sender<ProcessorMsg>,
    cmd: ScheduledCmd,
    name: &str,
) {
    tracing::info!(task = name, "scheduler: firing task");
    tx.send(ProcessorMsg::Scheduled(cmd))
        .await
        .unwrap_or_else(|_| panic!("scheduler: processor channel closed for task {name}"));
}
```

Channel closed means Processor panicked — appropriate to panic here (systemd restarts).

---

## Business rules

1. **No concurrent firing:** if the Processor is slow and the channel is full, `send().await`
   will block (backpressure). The Scheduler does not fire the next tick until the send
   completes. This is correct: we don't want to queue duplicate WeeklySync commands.

2. **Channel capacity is 256:** at most 4 scheduled commands can queue up without blocking.
   In practice the Processor is fast and this never fills.

3. **Idempotent on restart:** if the daemon restarts and DB has a `next_run` in the past,
   the task fires immediately on the first tick (within 5 minutes). This is intentional:
   if weekly sync didn't run last week (power outage), it runs on next start.

4. **No drift correction:** after firing, the Scheduler advances `next_due` by the fixed
   interval from "now", not from the previous due time. This means tasks can drift if the
   daemon is offline. For cold backup with a 1-week cycle, this is acceptable.

5. **PosRound offset:** `pos_round` fires 1 day after `weekly_sync` on first run so that
   placement (from WeeklySync) can complete before PoS challenges go out. In subsequent
   weeks both fire on their 7-day cycles independently.

6. **RepairCheck after PosRound:** repair check fires 2 days after weekly_sync on first
   run so PoS responses (7-day TTL) have time to arrive. In steady state, repairCheck
   fires on its own weekly cycle.

---

## DB operations

Reads at startup only:

| Operation | Method | Purpose |
|---|---|---|
| Read `schedule` record | `db.get_schedule("weekly_sync")` | Get last_run / next_run |
| Read `schedule` record | `db.get_schedule("pos_round")` | Same |
| Read `schedule` record | `db.get_schedule("repair_check")` | Same |
| Read `schedule` record | `db.get_schedule("vacuum")` | Same |

No writes. Processor writes `schedule` records after task completion via
`db.set_schedule(&ScheduleRecord { task_name, last_run: Some(now), next_run })`.

---

## File layout

Per project convention, tests go in a separate file:

```
crates/syncback/src/daemon/scheduler.rs    — run(), send_cmd(), constants
```

No `scheduler/tests.rs` needed (these tests are simple enough to live in the same file
under `#[cfg(test)] mod tests;`). But if tests grow, split to `scheduler/mod.rs` +
`scheduler/tests.rs`.

---

## Error handling

| Situation | Action |
|---|---|
| DB read at startup fails | `panic!("scheduler: cannot read schedule: {e}")` — DB open already succeeded, this is a bug |
| `send().await` returns Err | `panic!("scheduler: processor closed")` — Processor died |
| `cancel.cancelled()` fires | Break loop, return. No cleanup needed. |

---

## Logging

```
INFO  scheduler: firing task {task}           — on each send
DEBUG scheduler: started                      — at loop entry
DEBUG scheduler: next {task} in {secs}s       — at startup, for each task
DEBUG scheduler: cancelled                    — on shutdown
TRACE scheduler: tick (no tasks due)          — every 5-min tick when nothing fires
```

---

## Test scenarios

Tests use `#[tokio::test]`. No real DB access in the loop tests (only startup reads DB).

### `scheduler_fires_weekly_sync_when_due`

```
Setup:
  tmpdir with test DB (testutil::test_db() equivalent for syncback)
  Insert ScheduleRecord for "weekly_sync" with next_run = Timestamp::now() - 1
  Create channel (capacity 4)
  Create CancellationToken

Action:
  tokio::spawn(scheduler::run(db, cancel.clone(), tx))
  tokio::time::sleep(Duration::from_secs(6 * 60))  // just over one tick

Expected:
  rx.try_recv() == Ok(ProcessorMsg::Scheduled(ScheduledCmd::WeeklySync))

Cleanup:
  cancel.cancel()
```

DECISION NEEDED: To avoid waiting 5 real minutes per test, the implementer should expose
`TICK_INTERVAL` as an overridable constant or add a test-only parameter for tick duration.
Recommended approach: define `const TICK_INTERVAL_SECS: u64 = 300;` in the module and
use it in `tokio::time::sleep`. In tests, use `tokio::time::pause()` and
`tokio::time::advance(Duration::from_secs(310))` to fast-forward time without sleeping.
See tokio docs on `tokio::time::pause` for deterministic time control in tests.

### `scheduler_does_not_fire_before_due`

```
Setup:
  Insert ScheduleRecord for "weekly_sync" with next_run = Timestamp::now() + 86400 (1 day)
  Spawn scheduler

Action:
  Fast-forward 6 minutes (1 tick)

Expected:
  rx.try_recv() == Err(Empty)  // no command sent
```

### `scheduler_fires_all_tasks_on_first_run`

```
Setup:
  Empty DB (no schedule records)
  Set task offsets to 0, 1s, 2s, 3s (inject via test parameter or small offset constants)
  Spawn scheduler

Action:
  Fast-forward enough ticks for all tasks

Expected:
  At least one of each: WeeklySync, PosRound, RepairCheck (Vacuum is 30-day, skip in this test)
```

### `scheduler_shuts_down_cleanly_on_cancel`

```
Setup:
  Spawn scheduler with empty DB

Action:
  cancel.cancel() immediately

Expected:
  Task join completes within 1 second
```

### `scheduler_send_blocks_on_full_channel`

```
Note: This is a property test, not easily verified. The behavior is correct by design
(send().await provides backpressure). Skip explicit test; document in code comments.
```

---

## Notes for implementer

1. **`tokio::time::pause()` for tests:** use the tokio `test-util` feature or
   `tokio::time::advance()` to control time in tests. Add to dev-dependencies:
   ```toml
   tokio = { workspace = true, features = ["test-util"] }
   ```
   Then in tests: `tokio::time::pause(); tokio::time::advance(dur).await;`

2. **No `Db` struct in the loop:** the `Db` handle is passed in but only used at startup.
   After the initial reads, store the next_due timestamps as plain `u64` (Unix seconds).
   No need to hold the `Db` throughout the loop.

3. **Constants:** define interval constants at the top of the file:
   ```rust
   const TICK_SECS: u64 = 300;           // 5 minutes
   const WEEKLY_INTERVAL_SECS: u64 = 604_800;
   const MONTHLY_INTERVAL_SECS: u64 = 2_592_000;
   const POS_FIRST_OFFSET_SECS: u64 = 86_400;     // 1 day
   const REPAIR_FIRST_OFFSET_SECS: u64 = 172_800;  // 2 days
   ```

4. **`ScheduledCmd` is `Clone`:** confirmed from `daemon/mod.rs`. No issue sending it.

5. **The stub in `daemon/mod.rs`** currently does a 5-minute sleep. Replace the entire
   body of `scheduler::run` — do not keep the stub logic.
