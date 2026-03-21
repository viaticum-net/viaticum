# Task spec: Phase 7.2 — Spawn Processor + wire channels

**Target file:** `crates/syncback/src/daemon/handle/mod.rs`
**Also touches:** `crates/syncback/src/daemon/handle/tests.rs`
**Phase:** 7.2 (P2P wiring — main blocker removal)
**Role:** Wire the already-implemented Processor into DaemonHandle so incoming network connections are routed instead of dropped.

---

## Overview

The `Processor` module (`crates/syncback/src/daemon/processor/mod.rs`) is fully implemented and tested. It is never spawned. The blocking symptom is two channels created with underscore-prefixed receivers in `DaemonHandle::start()`:

```
let (incoming_tx, _incoming_rx) = mpsc::channel::<Connection>(64);
let (inbound_tx, _inbound_rx) = mpsc::channel::<InboundMessage>(128);
```

The fix requires:
1. Dropping the underscore prefix on both receivers so they are live.
2. Constructing a `ClusterSyncManager` instance.
3. Constructing a `Processor` instance with all required dependencies.
4. Spawning `processor.run(incoming_rx, cancel.clone())` as a tracked task.
5. Handling the `inbound_rx` channel correctly (see section below).
6. Removing the TODO comment on line 287.
7. Updating `handle/tests.rs` with a new test that verifies the Processor task is alive after start.

This is a wiring task — no new logic is written. All components already exist and are tested individually.

---

## Understanding the two channels

### `incoming_rx: mpsc::Receiver<Connection>`

- Produced by: `NetworkHandle::start(net_config, incoming_tx)` — the network accept loop sends each new accepted `Connection` through `incoming_tx`.
- Consumed by: `Processor::run(incoming_rx, cancel)` — the Processor spawns a per-connection read loop.
- Fix: rename `_incoming_rx` to `incoming_rx`, pass to `processor.run(...)`.

### `inbound_rx: mpsc::Receiver<InboundMessage>`

- Produced by: `RelayManager::run(relay_sync_rx, inbound_tx)` — the relay calls `scan_for_self(&inbound_tx, now)` after each board sync and periodic prune, delivering decrypted relay messages directed at us.
- Current state: `_inbound_rx` is dropped immediately, which means the relay's `scan_for_self` calls succeed (`try_send` is used — they silently drop when the channel has no receiver, but the channel is actually closed, so `try_send` returns `TrySendError::Closed` and logs an error). This is a bug: the relay logs errors on every board sync.
- Consumed by: **nothing yet in Phase 7.2.** The Processor's `run()` signature only takes `incoming_rx: Receiver<Connection>`. It does not currently have a parameter for relay inbound messages.

**Phase 7.2 resolution for `inbound_rx`:** Keep `inbound_tx` wired to relay (it is already passed), but add a **drain task** that reads from `inbound_rx` and logs the messages at DEBUG level without acting on them. This stops the relay error-logging loop and unblocks full relay inbound processing for a later sub-phase (7.6). The drain task is a minimal `tokio::spawn(async move { while let Some(msg) = inbound_rx.recv().await { tracing::debug!(...) } })` that is NOT added to the tracked `tasks` vec (it exits naturally when the channel closes on daemon shutdown).

DECISION NEEDED: If a later sub-phase wires relay inbound to Processor, the drain task must be removed and replaced. This is intentional tech debt, explicitly noted in a code comment.

---

## Dependencies

The `ClusterSyncManager` requires:
- `db: Db` — already available.
- `config: ClusterSyncConfig { our_device_id, batch_size }` — `device_id` is already derived on line 114; use default `batch_size: 1000`.
- `cluster_state: Arc<Mutex<ClusterState>>` — already constructed and held in `cluster_state` (type `Option<Arc<Mutex<ClusterState>>>`).

`cluster_state` is `Option<...>`. The `ClusterSyncManager` requires a non-optional `Arc<Mutex<ClusterState>>`. The `Processor` itself holds `Arc<ClusterSyncManager>`. If `cluster_state` is `None` (which only happens on DB errors during first-start, logged at ERROR level), the daemon currently continues without a cluster state — the same degraded behavior must be preserved.

**Resolution:** Construct `ClusterSyncManager` only when `cluster_state.is_some()`. When `None`, skip spawning the Processor task and log a `tracing::warn!` saying the Processor was not started because cluster state is unavailable. This matches the existing degraded-mode pattern in the codebase (other subsystems continue even if cluster_state is None).

The `Processor` requires:
- `db: Db` — available.
- `own_identity: IdentityPub` — available as `identity_pub`.
- `repair_tx: mpsc::Sender<RepairTrigger>` — available; a clone is already made for the scheduler (`repair_tx_for_scheduler`). Create another clone for the Processor before the cancel task consumes the original.
- `cluster_sync: Arc<ClusterSyncManager>` — constructed above.
- `encoder: Arc<dyn ErasureEncoder>` — available as `encoder`.
- `holdings_dir: PathBuf` — this is where the Processor stores symbols it holds for others. Use `cfg.data_dir.join("holdings")`. Create the directory with `std::fs::create_dir_all` alongside the existing `symbols_dir` creation.
- `source_blocks_dir: PathBuf` — where the owner's own source block files live for PoS verification. Use `symbols_dir.clone()` (the existing `symbols_dir = cfg.data_dir.join("symbols")`) because that is already where BackupCoordinator writes source blocks. Read the BackupCoordinator's `BackupConfig.symbols_dir` field — it receives the same `symbols_dir`. The Processor's field name `source_blocks_dir` was always intended to point to the same directory.

DECISION NEEDED: `holdings_dir` vs `source_blocks_dir` path convention. The Processor uses:
- `holdings_dir/{block_id_hex}/{esi}.bin` — symbols held for others.
- `source_blocks_dir/{block_id_hex}/block.bin` — owner's source blocks for PoS verification.

These are logically distinct. Using `symbols_dir` for both conflates them. The recommended split:
- `holdings_dir = cfg.data_dir.join("holdings")` — new directory.
- `source_blocks_dir = cfg.data_dir.join("symbols")` — existing, used by BackupCoordinator.

This is a clean split and the implementer should create `holdings_dir` on startup.

---

## Exact change set

### Section 6 channel declarations (lines 156-160)

Remove underscore prefixes:

```rust
let (incoming_tx, incoming_rx) =
    mpsc::channel::<crate::daemon::network::connection::Connection>(64);
// relay inbound messages — drained by a background task until Phase 7.6
let (inbound_tx, inbound_rx) =
    mpsc::channel::<crate::daemon::relay::InboundMessage>(128);
```

### New import

Add to the use block at the top of `handle/mod.rs`:

```rust
use crate::daemon::cluster_sync::{ClusterSyncConfig, ClusterSyncManager};
use crate::daemon::processor::Processor;
```

### Holdings directory creation (after symbols_dir creation, step 9)

```rust
// ── 9. Ensure symbols and holdings directories exist ──────────────────────
let symbols_dir = cfg.data_dir.join("symbols");
std::fs::create_dir_all(&symbols_dir)?;
let holdings_dir = cfg.data_dir.join("holdings");
std::fs::create_dir_all(&holdings_dir)?;
```

### repair_tx clone for Processor (before cancel task, after scheduler repair clone)

The cancel task (lines 359-367) drops `repair_tx`. The scheduler already takes a separate channel. The Processor needs its own clone. Add before the cancel task:

```rust
let repair_tx_for_processor = repair_tx.clone();
```

### Processor construction and spawn (replace TODO comment at line 287)

Replace:
```rust
// TODO Phase 6.3: spawn Processor (routes incoming_rx, relay_sync_tx, repair_tx)
```

With:

```rust
// ── Phase 7.2: spawn Processor ────────────────────────────────────────────
if let Some(cs) = cluster_state.as_ref() {
    let cluster_sync = Arc::new(ClusterSyncManager::new(
        db.clone(),
        ClusterSyncConfig {
            our_device_id: device_id,
            batch_size: 1000,
        },
        cs.clone(),
    ));
    let processor = Processor::new(
        db.clone(),
        identity_pub,
        repair_tx_for_processor,
        cluster_sync,
        encoder.clone(),
        holdings_dir.clone(),
        symbols_dir.clone(), // source_blocks_dir: owner's blocks for PoS verification
    );
    let cancel_processor = cancel.clone();
    tasks.push(tokio::spawn(async move {
        processor.run(incoming_rx, cancel_processor).await
    }));
} else {
    tracing::warn!("cluster state unavailable — Processor not started, incoming connections will be dropped");
    // Drop incoming_rx so the network accept loop's incoming_tx send() will
    // eventually get channel-full backpressure rather than silent discard.
    drop(incoming_rx);
}

// Drain relay inbound messages at DEBUG level until Phase 7.6 wires them to Processor.
// NOTE: remove this drain task in Phase 7.6 when Processor gains an inbound_rx parameter.
tokio::spawn(async move {
    while let Some(msg) = inbound_rx.recv().await {
        tracing::debug!(
            from = %msg.from,
            msg_type = %msg.msg_type,
            "handle: relay inbound message (drained, not yet processed)"
        );
    }
});
```

### repair_tx_for_processor must be declared before the cancel task

The cancel task currently drops `repair_tx`. The clone must be taken before that. The scheduler clone (`repair_tx_for_scheduler`) is already taken at line 331. Add the Processor clone immediately after it:

```rust
let repair_tx_for_scheduler = repair_tx.clone();
let repair_tx_for_processor = repair_tx.clone();  // ADD THIS LINE
```

---

## Public API (no changes)

This task introduces no new public types. The only public surface change is that `DaemonHandle::start()` now conditionally spawns one more task. The `DaemonHandle` struct and its `stop()`/`wait()` methods are unchanged.

`ClusterSyncManager` and `Processor` are already public. Their constructors are used directly:

```rust
// ClusterSyncManager::new signature (from cluster_sync/mod.rs):
pub fn new(
    db: Db,
    config: ClusterSyncConfig,
    cluster_state: Arc<Mutex<ClusterState>>,
) -> Self

// Processor::new signature (from processor/mod.rs):
pub fn new(
    db: Db,
    own_identity: IdentityPub,
    repair_tx: mpsc::Sender<RepairTrigger>,
    cluster_sync: Arc<ClusterSyncManager>,
    encoder: Arc<dyn ErasureEncoder>,
    holdings_dir: PathBuf,
    source_blocks_dir: PathBuf,
) -> Self

// Processor::run signature (from processor/mod.rs):
pub async fn run(
    self,
    mut incoming_rx: mpsc::Receiver<Connection>,
    cancel: CancellationToken,
) -> anyhow::Result<()>
```

---

## Types

No new types. Existing types used:

| Type | Source | Role |
|------|--------|------|
| `ClusterSyncManager` | `crate::daemon::cluster_sync` | Handles cluster event log exchange in Processor |
| `ClusterSyncConfig` | `crate::daemon::cluster_sync` | Config for ClusterSyncManager |
| `Processor` | `crates/syncback/src/daemon/processor` | Routes incoming connections |
| `Connection` | `crate::daemon::network::connection` | Iroh QUIC connection handle |
| `InboundMessage` | `crate::daemon::relay` | Decrypted relay board message |
| `RepairTrigger` | `crate::daemon::repair` | Sent to RepairAgent when placement is lost |

---

## DB operations

This task introduces no new DB operations. The `ClusterSyncManager` and `Processor` already use the shared `Db` handle — their operations are covered by their own existing tests.

---

## Business rules

1. **Processor runs only with ClusterState.** ClusterSyncManager needs a live ClusterState to validate sync requests. If ClusterState initialization failed (DB corruption or first-init error), the Processor is skipped. The daemon still starts — backup, restore, repair, relay, scheduler continue.

2. **All tasks in `tasks` vec must terminate cleanly on `cancel`.** The Processor's `run()` listens for `cancel.cancelled()` in its select loop. It will exit when the CancellationToken fires.

3. **`inbound_rx` must not be dropped silently.** The relay calls `try_send` on `inbound_tx`. If the receiver is dropped, `try_send` returns `TrySendError::Closed` and the relay logs an ERROR on every board sync. The drain task prevents this.

4. **`holdings_dir` and `symbols_dir` are distinct paths.** The Processor stores symbols it holds for others in `holdings_dir`. The Processor reads source blocks for PoS verification from `symbols_dir` (same directory BackupCoordinator writes to). These paths must not be swapped.

5. **`repair_tx_for_processor` clone must be taken before the cancel task.** The cancel task drops `repair_tx`. Any clone must be taken before that `tokio::spawn`.

---

## Test scenarios

Tests live in `crates/syncback/src/daemon/handle/tests.rs`.

### Test 1: `processor_task_is_spawned_and_stops_cleanly`

**Input:** Fresh data dir, `init_identity`, `DaemonHandle::start` called normally.
**Verification:** After `handle.stop(); handle.wait().await`, no error is returned.
**Notes:** This is the existing `daemon_starts_and_stops_cleanly` test, which is already `#[ignore = "heavy"]`. The Phase 7.2 change should not break it. Verify the test still passes when run with `-- --ignored`.

The existing test is sufficient for basic lifecycle. No additional test is strictly required because:
- The Processor itself is tested in `processor/tests.rs`.
- ClusterSyncManager is tested in `cluster_sync/tests.rs`.
- The wiring change is so minimal (a handful of lines) that the existing integration test covers the critical path.

However, add one new **non-ignored unit test** that verifies the drain task behavior is correct at the channel level:

### Test 2: `inbound_drain_task_does_not_block_relay`

```rust
#[tokio::test]
async fn inbound_drain_task_does_not_block_relay() {
    // Verify that sending on inbound_tx does not block or error when
    // the drain task is consuming.
    use crate::daemon::relay::InboundMessage;
    use syncback_core::types::{IdentityPub, Timestamp};
    use tokio::sync::mpsc;

    let (inbound_tx, inbound_rx) = mpsc::channel::<InboundMessage>(4);

    // Spawn the drain task (mirrors handle/mod.rs logic).
    tokio::spawn(async move {
        let mut rx = inbound_rx;
        while let Some(_msg) = rx.recv().await {}
    });

    // Send several messages; none should block or return an error.
    for i in 0u8..4 {
        let msg = InboundMessage {
            from: IdentityPub([i; 32]),
            payload: vec![i],
            msg_type: "test".to_string(),
            msg_id: [i; 16],
            created_at: Timestamp::now(),
        };
        inbound_tx.send(msg).await.expect("send should succeed");
    }
    // Drop the sender; the drain task should exit naturally.
    drop(inbound_tx);
}
```

This test lives in `handle/tests.rs` and runs without `#[ignore]` (no iroh endpoint needed).

---

## Implementation order

1. Add imports (`ClusterSyncManager`, `ClusterSyncConfig`, `Processor`) to `handle/mod.rs`.
2. Rename `_incoming_rx` to `incoming_rx` and `_inbound_rx` to `inbound_rx` in step 6.
3. Extend step 9 to create `holdings_dir`.
4. Add `repair_tx_for_processor = repair_tx.clone()` after the scheduler clone.
5. Replace the TODO comment with the Processor construction block and drain task.
6. Run `cargo build -p syncback` to confirm zero errors.
7. Run `cargo test -p syncback` to confirm existing tests still pass.
8. Add the new test `inbound_drain_task_does_not_block_relay` to `handle/tests.rs`.
9. Run `cargo test -p syncback` again to confirm the new test passes.
10. Run `cargo clippy -p syncback -- -D warnings` to confirm no warnings.

---

## Potential pitfalls

- **Variable ordering.** `repair_tx_for_processor` must be cloned before the `cancel` task that drops `repair_tx`. If placed after, the compiler will complain about use-after-move. The natural insertion point is immediately after the existing `repair_tx_for_scheduler` clone.

- **`incoming_rx` moved into closure.** The `incoming_rx` is moved into `processor.run(...)`. It cannot be used again after that. The `else` branch drops it explicitly to keep the compiler happy.

- **`holdings_dir` borrow.** Both the Processor constructor and the `cancel` task drain need `holdings_dir`. The Processor constructor takes a `PathBuf` (moves it). If the cancel task were to drop `holdings_dir`, that would be a problem — but it does not. The drain task does not use `holdings_dir`. No conflict.

- **`cluster_state` is `Option<Arc<...>>`.** The code uses `cluster_state.as_ref()` to avoid consuming it — the same `Arc` is still needed by the `DaemonState` that was already constructed above.

- **Unused variable warning.** If `repair_tx_for_processor` is declared but the `else` branch drops `incoming_rx` without consuming the repair clone, the compiler may warn. In the `else` branch, also `drop(repair_tx_for_processor)` to suppress the warning.

---

## Checklist for reviewer

- [ ] `_incoming_rx` renamed to `incoming_rx`, no underscore.
- [ ] `_inbound_rx` renamed to `inbound_rx`, no underscore.
- [ ] `holdings_dir` created with `std::fs::create_dir_all`.
- [ ] `ClusterSyncManager` constructed with correct `device_id` and `batch_size: 1000`.
- [ ] `Processor::new` called with `holdings_dir` (not `symbols_dir`) as the holdings path.
- [ ] `Processor::new` called with `symbols_dir` (not `holdings_dir`) as the `source_blocks_dir`.
- [ ] `repair_tx_for_processor` clone taken before the cancel task.
- [ ] Processor task added to the `tasks` vec (so `wait()` joins it).
- [ ] Drain task is NOT added to the `tasks` vec (it is fire-and-forget).
- [ ] Comment on drain task explains it is temporary, to be removed in Phase 7.6.
- [ ] TODO comment removed.
- [ ] `cargo build -p syncback` passes.
- [ ] `cargo test -p syncback` passes (all non-ignored tests).
- [ ] `cargo clippy -p syncback -- -D warnings` passes.
- [ ] New test `inbound_drain_task_does_not_block_relay` in `handle/tests.rs`.
