# Task spec: processor module (Phase 2)

**Target file:** `crates/syncback/src/daemon/processor.rs`
**Phase:** 2 (replaces the stub created in daemon_skeleton)
**Role:** Central orchestrator — sole DB writer, owns all logic modules, drives all flows

---

## Overview

The Processor is the heart of the daemon. It is one of the five tokio tasks and owns:

- `TrustEngine` — P/I/S trust calculation
- `EscrowChecker` — restore gate and delete cooldowns
- `PlacementEngine` — holder selection for uploads
- `BudgetPlanner` — budget estimation and disk pressure evaluation
- `ShardManager` — encrypt→erasure→place→upload pipeline and PoS
- `Storage` — holder-side blob storage, PoS response, restore serving

The Processor is the **sole writer to the DB** (all engines share the `Db` Arc, but
only Processor coordinates writes that span multiple tables or modules). It processes
three event streams in a single `tokio::select!` loop:

1. `ProcessorMsg` — from Scheduler (`ScheduledCmd`) and CLI Server (`CliCmd`)
2. `DirtyEvent` — from Watcher (file changes on disk)
3. `NetEvent` — from Network task (peer connections, board messages, blob transfers)

The Processor sends outbound network commands via `net_cmd_tx: mpsc::Sender<NetCommand>`.

---

## Dependencies

**syncback-core:**
- `db::Db` — all DB operations flow through this
- `trust::{TrustEngine, TrustScore, PosOutcome, TransferEvent}`
- `escrow::{EscrowChecker, RestoreDecision, EscrowDenial}`
- `placement::PlacementEngine`
- `budget::BudgetPlanner`
- `messages::*` — all message types for dispatch
- `types::*` — all record and ID types

**syncback crate (same crate):**
- `daemon::{ProcessorMsg, ScheduledCmd, CliCmd, DirtyEvent, NetEvent, NetCommand, StatusReply}`
- `daemon::storage::{Storage, StorageError, OfferDecision}`
- `daemon::shard_manager::{ShardManager, PosResult}`

**External:**
- `tokio::sync::mpsc`, `tokio::sync::oneshot`
- `tokio_util::sync::CancellationToken`
- `tracing`

---

## Public API

The public API is a single free async function (consistent with other tasks):

```rust
/// Run the processor task until `cancel` is signalled or a fatal error occurs.
/// Owns all logic modules. Sole DB writer.
pub async fn run(
    db: syncback_core::db::Db,
    cancel: tokio_util::sync::CancellationToken,
    processor_rx: tokio::sync::mpsc::Receiver<crate::daemon::ProcessorMsg>,
    dirty_rx: tokio::sync::mpsc::Receiver<crate::daemon::DirtyEvent>,
    net_event_rx: tokio::sync::mpsc::Receiver<crate::daemon::NetEvent>,
    net_cmd_tx: tokio::sync::mpsc::Sender<crate::daemon::NetCommand>,
    config: crate::daemon::Config,
    identity_key: ed25519_dalek::SigningKey,
    identity_pub: syncback_core::types::IdentityPub,
);
```

**Note:** The current stub in `daemon/mod.rs` does not pass `config`, `identity_key`, or
`identity_pub` to `processor::run`. The daemon skeleton must be updated to pass these.
Check `DaemonHandle::start()` in `daemon/mod.rs` — it currently passes only
`(db, cancel, processor_rx, dirty_rx, net_event_rx, net_cmd_tx)`. The implementer must
add `config` and identity key parameters to both `DaemonHandle::start()` and
`processor::run()`.

DECISION NEEDED: Where does the identity key come from at startup? `DaemonHandle::start()`
currently receives a `Config` but not identity keys. For Phase 2, use a hard-coded
random key in `DaemonHandle::start()` for testing. Full key derivation from seed phrase
(BIP39 → HKDF) is a Phase 3 CLI task (`init`). Add to `DaemonHandle::start()`:
```rust
// Phase 2 stub: random identity key
let identity_signing_key = ed25519_dalek::SigningKey::from_bytes(
    &rand::thread_rng().gen::<[u8; 32]>()
);
let identity_pub = IdentityPub(identity_signing_key.verifying_key().to_bytes());
```

---

## Internal state

```rust
struct Processor {
    db: Db,
    config: Config,
    cancel: CancellationToken,

    // Input channels
    processor_rx: mpsc::Receiver<ProcessorMsg>,
    dirty_rx: mpsc::Receiver<DirtyEvent>,
    net_event_rx: mpsc::Receiver<NetEvent>,

    // Output channel
    net_cmd_tx: mpsc::Sender<NetCommand>,

    // Logic modules
    trust: TrustEngine,
    escrow: EscrowChecker,
    placement: PlacementEngine,
    budget: BudgetPlanner,
    shard_manager: ShardManager,
    storage: Storage,

    // Daemon start time (for uptime calculation in status reply)
    started_at: std::time::Instant,
}
```

The `Processor` struct is an implementation detail — not public. `run()` constructs it
and calls `self.run_loop().await`.

---

## Initialization (inside `run()`)

```rust
pub async fn run(db, cancel, processor_rx, dirty_rx, net_event_rx, net_cmd_tx, config, identity_key, identity_pub) {
    let trust = TrustEngine::new(db.clone());
    let escrow = EscrowChecker::new(db.clone());
    let placement = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let budget = BudgetPlanner::new(db.clone(), TrustEngine::new(db.clone()));

    let shards_dir = config.syncback_dir.join("shards");
    let storage = Storage::new(
        db.clone(),
        shards_dir,
        config.storage.quota_gb as f64,
        TrustEngine::new(db.clone()),
    ).expect("storage init failed");

    let shard_manager = ShardManager::new(
        db.clone(),
        PlacementEngine::new(db.clone(), TrustEngine::new(db.clone())),
        BudgetPlanner::new(db.clone(), TrustEngine::new(db.clone())),
        identity_key,
        identity_pub,
        net_cmd_tx.clone(),
    );

    let mut proc = Processor {
        db, config, cancel,
        processor_rx, dirty_rx, net_event_rx, net_cmd_tx,
        trust, escrow, placement, budget, shard_manager, storage,
        started_at: std::time::Instant::now(),
    };

    tracing::info!("processor: started");
    proc.run_loop().await;
    tracing::info!("processor: stopped");
}
```

Note: multiple `TrustEngine::new(db.clone())` instances are fine — they all share the
same underlying `Arc<redb::Database>`. The duplication is acceptable in alpha
(TrustEngine is a thin wrapper, not a cache).

---

## Main event loop

```rust
async fn run_loop(&mut self) {
    loop {
        tokio::select! {
            _ = self.cancel.cancelled() => {
                tracing::debug!("processor: cancelled");
                break;
            }

            msg = self.processor_rx.recv() => {
                match msg {
                    Some(ProcessorMsg::Scheduled(cmd)) => self.handle_scheduled(cmd).await,
                    Some(ProcessorMsg::Cli(cmd)) => self.handle_cli(cmd).await,
                    None => {
                        tracing::debug!("processor: processor_rx closed");
                        break;
                    }
                }
            }

            event = self.dirty_rx.recv() => {
                match event {
                    Some(ev) => self.handle_dirty(ev).await,
                    None => {
                        tracing::debug!("processor: dirty_rx closed");
                        break;
                    }
                }
            }

            event = self.net_event_rx.recv() => {
                match event {
                    Some(ev) => self.handle_net_event(ev).await,
                    None => {
                        tracing::debug!("processor: net_event_rx closed");
                        break;
                    }
                }
            }
        }
    }
}
```

All handlers are async methods on `Processor`. They do not return `Result` — errors
are handled internally (log and continue for expected errors, panic for unexpected).

---

## Scheduled command handlers

### `handle_scheduled(cmd: ScheduledCmd)`

Dispatches to sub-handlers:

```rust
async fn handle_scheduled(&mut self, cmd: ScheduledCmd) {
    match cmd {
        ScheduledCmd::WeeklySync => self.run_weekly_sync().await,
        ScheduledCmd::PosRound => self.run_pos_round().await,
        ScheduledCmd::Vacuum => self.run_vacuum().await,
        ScheduledCmd::RepairCheck => self.run_repair_check().await,
    }
}
```

### `run_weekly_sync()`

Full weekly backup and maintenance cycle.

```
1. Estimate budget
     let estimate = self.budget.estimate_budget()
         .expect("budget estimation: db error is fatal");
     let budget_gb = estimate.total_gb;

2. Select dirty files to back up
     let batch = self.budget.select_backup_batch(budget_gb)
         .expect("backup batch selection: db error is fatal");
     tracing::info!(files = batch.candidates.len(), deferred = batch.deferred_count,
                    total_gb = batch.total_required_gb, "weekly sync: starting");

3. For each candidate in batch.candidates (Phase 2: stub out file reading)
     // Phase 2: skip actual file packing (Packer is Phase 3)
     // Log what would be backed up, but don't actually encrypt+upload
     tracing::debug!(path = candidate.path, "weekly sync: would back up (packer not impl)");
     // TODO: Phase 3 — call packer.pack_unit(&candidate), then shard_manager.upload_unit()

4. Trust update: recalculate trust for all peers
     let now = Timestamp::now();
     let current_week = (now.0 / SECS_PER_WEEK) as u32;
     let count = self.trust.recalculate_all(now, current_week)
         .expect("trust recalculation: db error is fatal");
     tracing::info!(peers = count, "weekly sync: trust recalculated");

5. Update weeks_in_network for all known peers
     let peers = self.db.list_all_peers()
         .expect("list_all_peers: db error is fatal");
     for peer in &peers {
         self.db.increment_peer_weeks(&peer.identity)
             .expect("increment_peer_weeks: db error is fatal");
     }

6. Process expired cooldowns (holder side)
     let deleted = self.storage.process_expired_cooldowns(now)
         .expect("process_expired_cooldowns: db error is fatal");
     if !deleted.is_empty() {
         tracing::info!(count = deleted.len(), "weekly sync: expired cooldowns processed");
     }

7. Process expired drop notices (holder side)
     let dropped = self.storage.process_expired_drop_notices(now)
         .expect("process_expired_drop_notices: db error is fatal");
     for shard_id in &dropped {
         // Processor sends shard_dropped notification — but we already gave 7-day notice
         // shard_dropped is optional ("good manners") — skip for Phase 2
         tracing::debug!(shard = %shard_id, "drop notice expired, shard deleted");
     }

8. Check disk pressure
     self.check_disk_pressure(now).await;

9. System state backup (Phase 3 — skip for Phase 2)
     // TODO: serialize state snapshot, upload as system shard

10. Update schedule record
     self.db.set_schedule(&ScheduleRecord {
         task_name: "weekly_sync".to_string(),
         last_run: Some(now),
         next_run: Timestamp(now.0 + 7 * 604_800),
     }).expect("set_schedule failed");

     tracing::info!("weekly sync: complete");
```

### `run_pos_round()`

Send PoS challenges to holders of our shards.

```
1. let now = Timestamp::now();
2. let challenges = self.shard_manager.sample_pos_challenges(now)
       .expect("sample_pos_challenges: db error is fatal");
   tracing::info!(count = challenges.len(), "pos round: sending challenges");

3. For each challenge in challenges:
     self.net_cmd_tx.send(NetCommand::SendPosChallenge {
         holder: challenge.holder,
         shard_id: challenge.shard_id,
         block_index: challenge.block_index,
         nonce: challenge.nonce,
     }).await.expect("net channel closed");

4. Update schedule:
     self.db.set_schedule(&ScheduleRecord {
         task_name: "pos_round".to_string(),
         last_run: Some(now),
         next_run: Timestamp(now.0 + 7 * 604_800),
     }).expect("set_schedule failed");

     tracing::info!(sent = challenges.len(), "pos round: complete");
```

### `run_vacuum()`

Monthly maintenance: repack stale units, delete expired units.

```
Phase 2: stub. Log that vacuum ran.
// TODO Phase 3: call packer.vacuum_stale_units()

let now = Timestamp::now();
tracing::info!("vacuum: running (stub - full vacuum in Phase 3)");

// Update stale unit ratios
let stale_units = self.db.list_stale_units()
    .expect("list_stale_units failed");
tracing::info!(stale = stale_units.len(), "vacuum: found stale units");

// Units with Deleting status whose cooldown has expired → mark Deleted
let units = self.db.list_units_by_status(UnitStatus::Deleting)
    .expect("list units failed");
for unit in units {
    // If all shards are Deleting or Lost and cooldown elapsed → mark Deleted
    // Phase 2: just log, no action
    tracing::debug!(unit = %unit.unit_id, "vacuum: deleting unit (stub)");
}

self.db.set_schedule(&ScheduleRecord {
    task_name: "vacuum".to_string(),
    last_run: Some(now),
    next_run: Timestamp(now.0 + 30 * 86_400),
}).expect("set_schedule failed");
```

### `run_repair_check()`

Detect under-replicated units and trigger repair.

```
1. let under_replicated = self.shard_manager.find_under_replicated_units()
       .expect("find_under_replicated_units failed");
   tracing::info!(count = under_replicated.len(), "repair check: under-replicated units");

2. For each unit_id in under_replicated:
     match self.shard_manager.repair_unit(unit_id, None, Timestamp::now()).await {
         Ok(n) => tracing::info!(unit = %unit_id, shards = n, "repaired unit"),
         Err(ShardManagerError::PlaintextNotAvailable) => {
             tracing::info!(unit = %unit_id, "repair: need restore flow (Phase 3)");
             // TODO Phase 3: trigger restore + re-upload
         }
         Err(ShardManagerError::NotEnoughPeers { need, have }) => {
             tracing::info!(unit = %unit_id, need, have, "repair: not enough peers, retry next week");
         }
         Err(e) => panic!("repair_unit unexpected error: {e}"),
     }

3. Update schedule:
     self.db.set_schedule(&ScheduleRecord { ... }).expect("set_schedule failed");
```

---

## CLI command handlers

### `handle_cli(cmd: CliCmd)`

```rust
async fn handle_cli(&mut self, cmd: CliCmd) {
    match cmd {
        CliCmd::Status { reply } => self.handle_cli_status(reply).await,
        CliCmd::BackupNow { reply } => self.handle_cli_backup_now(reply).await,
        CliCmd::RestoreFile { path, dest, reply } => {
            self.handle_cli_restore(path, dest, reply).await
        }
        CliCmd::Shutdown => {
            tracing::info!("processor: shutdown requested via CLI");
            self.cancel.cancel();
        }
    }
}
```

### `handle_cli_status(reply: oneshot::Sender<StatusReply>)`

```rust
async fn handle_cli_status(&self, reply: oneshot::Sender<StatusReply>) {
    let peers = self.db.list_all_peers().expect("list_all_peers failed");
    let shards_held = self.db.list_all_holding().expect("list_all_holding failed").len();
    let shards_placed = self.db.list_all_shards()
        .expect("list_all_shards failed")
        .iter()
        .filter(|s| s.status == ShardStatus::Stored)
        .count();
    let budget_record = self.db.get_budget().expect("get_budget failed");
    let budget_gb = budget_record.map(|b| b.estimated_gb).unwrap_or(0.0);
    let dirty_files = self.db.list_dirty_files().expect("list_dirty_files failed").len();

    let reply_value = StatusReply {
        uptime_secs: self.started_at.elapsed().as_secs(),
        peer_count: peers.len(),
        shards_held,
        shards_placed,
        budget_gb,
        dirty_files,
    };

    let _ = reply.send(reply_value); // Ignore if CLI client disconnected
}
```

### `handle_cli_backup_now(reply: oneshot::Sender<Result<(), String>>)`

```rust
async fn handle_cli_backup_now(&mut self, reply: oneshot::Sender<Result<(), String>>) {
    tracing::info!("backup now: triggered by CLI");
    self.run_weekly_sync().await;
    let _ = reply.send(Ok(()));
}
```

### `handle_cli_restore(path, dest, reply)`

Phase 2 stub — full restore requires downloading shards, which is a Phase 3 user-layer
feature.

```rust
async fn handle_cli_restore(
    &self,
    path: std::path::PathBuf,
    dest: std::path::PathBuf,
    reply: oneshot::Sender<Result<(), String>>,
) {
    tracing::info!(?path, ?dest, "restore: requested (stub - Phase 3)");
    let _ = reply.send(Err("restore not yet implemented (Phase 3)".to_string()));
}
```

---

## DirtyEvent handler

```rust
async fn handle_dirty(&self, event: DirtyEvent) {
    tracing::debug!(path = ?event.path, kind = ?event.kind, "dirty event");
    let path_str = event.path.to_string_lossy().to_string();
    let now = Timestamp(event.detected_at);

    match event.kind {
        DirtyKind::Created | DirtyKind::Modified => {
            // Look up existing file record or create a new one
            match self.db.get_file(&path_str).expect("get_file failed") {
                Some(_) => {
                    self.db.mark_file_dirty(&path_str, now)
                        .expect("mark_file_dirty failed");
                }
                None => {
                    // New file: determine importance from config
                    let importance = self.config_importance_for_path(&event.path);
                    if importance < 0.1 {
                        tracing::debug!(path = ?event.path, "dirty: importance too low, skipping");
                        return;
                    }
                    let file_id = self.next_file_id();
                    let record = FileRecord {
                        file_id,
                        path: path_str.clone(),
                        content_hash: [0u8; 32], // unknown until packer reads it
                        size_bytes: 0,             // unknown until packer reads it
                        importance,
                        dirty: true,
                        current_unit_id: None,
                        last_backed_up: None,
                        backed_up: false,
                        first_seen: now,
                    };
                    self.db.upsert_file(&record).expect("upsert_file failed");
                }
            }
        }
        DirtyKind::Deleted => {
            // Phase 2: mark as dirty=true. Phase 3: Processor schedules delete flow.
            // For now: just log (packer handles deletion properly in Phase 3)
            tracing::debug!(path = ?event.path, "dirty: file deleted (delete flow Phase 3)");
        }
    }
}
```

`config_importance_for_path`: scan `config.backup.include` patterns from most-specific to
least-specific path prefix match, return the importance of the matching entry. If no
match: return 0.0.

`next_file_id`: read next FileId from config table ("next_file_id"), increment and write
back. Start at 1.

---

## NetEvent handlers

### `handle_net_event(event: NetEvent)`

```rust
async fn handle_net_event(&mut self, event: NetEvent) {
    match event {
        NetEvent::PeerConnected { peer, node_addr } => {
            self.handle_peer_connected(peer, node_addr).await
        }
        NetEvent::PeerDisconnected { peer } => {
            self.handle_peer_disconnected(peer).await
        }
        NetEvent::BoardMessage { from, msg_type, payload } => {
            self.handle_board_message(from, msg_type, payload).await
        }
        NetEvent::DirectMessage { from, payload } => {
            self.handle_direct_message(from, payload).await
        }
        NetEvent::PosResponse { from, shard_id, block_index, hash, merkle_proof } => {
            self.handle_pos_response(from, shard_id, block_index, hash, merkle_proof).await
        }
        NetEvent::ShardUploaded { shard_id, holder, bytes } => {
            self.handle_shard_uploaded(shard_id, holder, bytes).await
        }
        NetEvent::ShardDownloaded { shard_id, owner, bytes } => {
            self.handle_shard_downloaded(shard_id, owner, bytes).await
        }
        NetEvent::FatalError(msg) => {
            tracing::error!("network fatal error: {msg}");
            self.cancel.cancel();
        }
    }
}
```

### `handle_peer_connected(peer: IdentityPub, node_addr: String)`

```rust
async fn handle_peer_connected(&self, peer: IdentityPub, node_addr: String) {
    tracing::info!(peer = %peer, "peer connected");
    let now = Timestamp::now();
    // Upsert peer record (updates last_seen and node_id)
    match self.db.get_peer(&peer).expect("get_peer failed") {
        Some(mut record) => {
            record.last_seen = now;
            // Update node_id from addr (parse NodeId from node_addr string)
            // Phase 2: store raw string in node_addr, parse NodeId later
            self.db.upsert_peer(&record).expect("upsert_peer failed");
        }
        None => {
            self.trust.upsert_peer(&peer, now).expect("upsert_peer failed");
        }
    }
}
```

### `handle_peer_disconnected(peer: IdentityPub)`

```rust
async fn handle_peer_disconnected(&self, peer: IdentityPub) {
    tracing::debug!(peer = %peer, "peer disconnected");
    // Update last_seen
    let now = Timestamp::now();
    if let Some(mut record) = self.db.get_peer(&peer).expect("get_peer failed") {
        record.last_seen = now;
        self.db.upsert_peer(&record).expect("upsert_peer failed");
    }
}
```

### `handle_board_message(from: IdentityPub, msg_type: String, payload: Vec<u8>)`

Dispatch on `msg_type` string. Parse payload as CBOR.

```rust
async fn handle_board_message(&mut self, from: IdentityPub, msg_type: String, payload: Vec<u8>) {
    tracing::debug!(peer = %from, msg_type = %msg_type, "board message received");

    // Allowlist check: only process from known peers
    if self.db.get_peer(&from).expect("get_peer failed").is_none() {
        tracing::debug!(peer = %from, "board message from unknown peer, dropping");
        return;
    }

    let now = Timestamp::now();

    match msg_type.as_str() {
        "shard_offer" => {
            let msg: ShardOfferMsg = match from_cbor(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(peer = %from, error = %e, "shard_offer: parse error");
                    return;
                }
            };
            self.handle_shard_offer(from, msg, now).await;
        }
        "shard_accept" => {
            let msg: ShardAcceptMsg = match from_cbor(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(peer = %from, error = %e, "shard_accept: parse error");
                    return;
                }
            };
            self.handle_shard_accept(from, msg, now).await;
        }
        "shard_stored" => {
            let msg: ShardStoredMsg = match from_cbor(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("shard_stored: parse error: {e}");
                    return;
                }
            };
            self.shard_manager.handle_shard_stored(msg.shard_id, now)
                .expect("handle_shard_stored failed");
            tracing::info!(shard = %msg.shard_id, holder = %from, "shard stored confirmed");
        }
        "shard_reject" => {
            let msg: ShardRejectMsg = match from_cbor(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("shard_reject: parse error: {e}");
                    return;
                }
            };
            self.shard_manager.handle_shard_reject(msg.shard_id, now)
                .unwrap_or_else(|e| tracing::debug!(error = %e, "shard_reject: not found (ok)"));
        }
        "shard_dropped" => {
            let msg: ShardDroppedMsg = match from_cbor(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("shard_dropped: parse error: {e}");
                    return;
                }
            };
            self.shard_manager.handle_shard_dropped(msg.shard_id, now)
                .unwrap_or_else(|e| tracing::debug!(error = %e, "shard_dropped: not found (ok)"));
            tracing::info!(shard = %msg.shard_id, holder = %from, "shard dropped by holder");
        }
        "shard_drop_notice" => {
            let msg: ShardDropNoticeMsg = match from_cbor(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("shard_drop_notice: parse error: {e}");
                    return;
                }
            };
            tracing::info!(shard = %msg.shard_id, deadline = msg.deadline, "shard drop notice from holder");
            // TODO Phase 3: trigger repair/re-placement for this shard
            // For now: just log
        }
        "pos_challenge" => {
            let msg: PosChallengeMsg = match from_cbor(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("pos_challenge: parse error: {e}");
                    return;
                }
            };
            self.handle_pos_challenge_incoming(from, msg, now).await;
        }
        "pos_response" => {
            let msg: PosResponseMsg = match from_cbor(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("pos_response: parse error: {e}");
                    return;
                }
            };
            self.handle_pos_response_incoming(from, msg, now).await;
        }
        "delete" => {
            let msg: DeleteMsg = match from_cbor(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("delete: parse error: {e}");
                    return;
                }
            };
            match self.storage.handle_delete_request(msg.shard_id, &from, now) {
                Ok(()) => tracing::debug!(shard = %msg.shard_id, "delete request recorded"),
                Err(StorageError::ShardNotFound(_)) => {
                    tracing::debug!(shard = %msg.shard_id, "delete for unknown shard, ignoring");
                }
                Err(e) => panic!("handle_delete_request unexpected error: {e}"),
            }
        }
        "cancel_delete" => {
            let msg: CancelDeleteMsg = match from_cbor(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("cancel_delete: parse error: {e}");
                    return;
                }
            };
            match self.storage.handle_cancel_delete(msg.shard_id, &from) {
                Ok(()) => tracing::debug!(shard = %msg.shard_id, "cancel_delete processed"),
                Err(StorageError::ShardNotFound(_)) => {
                    tracing::debug!(shard = %msg.shard_id, "cancel_delete for unknown shard, ignoring");
                }
                Err(e) => panic!("handle_cancel_delete unexpected error: {e}"),
            }
        }
        "storage_warning" => {
            let msg: StorageWarningMsg = match from_cbor(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("storage_warning: parse error: {e}");
                    return;
                }
            };
            match self.storage.handle_storage_warning(msg.shard_id) {
                Ok(true) => tracing::debug!(shard = %msg.shard_id, "storage warning: shard intact"),
                Ok(false) => {
                    tracing::error!(shard = %msg.shard_id, "storage warning: shard CORRUPTED");
                    // TODO: notify user, run selfcheck
                }
                Err(StorageError::ShardNotFound(_)) => {
                    tracing::debug!(shard = %msg.shard_id, "storage warning for shard we don't hold");
                }
                Err(e) => panic!("handle_storage_warning unexpected error: {e}"),
            }
        }
        "peer_announce" => {
            let msg: PeerAnnounceMsg = match from_cbor(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("peer_announce: parse error: {e}");
                    return;
                }
            };
            self.handle_peer_announce(from, msg, now).await;
        }
        _ => {
            tracing::debug!(peer = %from, msg_type = %msg_type, "unknown message type, ignoring");
        }
    }
}
```

### `handle_shard_offer(from: IdentityPub, msg: ShardOfferMsg, now: Timestamp)`

We are the holder. Owner is asking if we'll store a shard.

```rust
async fn handle_shard_offer(&mut self, from: IdentityPub, msg: ShardOfferMsg, now: Timestamp) {
    let descriptor = &msg.descriptor;
    tracing::debug!(shard = %descriptor.shard_id, owner = %from, "shard offer received");

    // Verify descriptor signature
    if let Err(e) = descriptor.verify_sig() {
        tracing::debug!(shard = %descriptor.shard_id, error = %e, "shard offer: invalid sig");
        return;
    }

    // Verify owner_pub matches sender
    if descriptor.owner_pub != from {
        tracing::debug!(shard = %descriptor.shard_id, "shard offer: owner_pub mismatch");
        return;
    }

    // Check if we should accept
    match self.storage.should_accept_offer(descriptor).expect("should_accept_offer failed") {
        OfferDecision::Accept => {
            tracing::debug!(shard = %descriptor.shard_id, "shard offer: accepting");
            // Send shard_accept back to owner via board
            let accept_msg = ShardAcceptMsg {
                v: 1,
                shard_id: descriptor.shard_id,
                offer_msg_id: MsgId::derive(&payload, now.0), // we don't have payload here — use shard_id bytes
                ts: now.0,
            };
            // Note: offer_msg_id should be the MsgId of the original offer board entry.
            // For Phase 2: derive from shard_id and timestamp (approximation).
            let accept_payload = to_cbor(&accept_msg).expect("cbor failed");
            self.net_cmd_tx.send(NetCommand::PublishBoard {
                msg_type: "shard_accept".to_string(),
                payload: accept_payload,
                directed_to: Some(from),
            }).await.expect("net channel closed");

            // After accept: owner will push the blob via iroh-blobs.
            // Storage module stores it when NetEvent::ShardDownloaded fires.
        }
        OfferDecision::RejectFull => {
            tracing::debug!(shard = %descriptor.shard_id, "shard offer: rejecting (full)");
            self.send_shard_reject(from, descriptor.shard_id, RejectReason::Full, now).await;
        }
        OfferDecision::RejectUnknown | OfferDecision::RejectNotAllowed => {
            tracing::debug!(shard = %descriptor.shard_id, "shard offer: rejecting (not allowed)");
            self.send_shard_reject(from, descriptor.shard_id, RejectReason::NotAllowed, now).await;
        }
    }
}
```

### `handle_shard_accept(from: IdentityPub, msg: ShardAcceptMsg, now: Timestamp)`

We are the owner. Holder accepted our shard_offer. Send the blob.

```rust
async fn handle_shard_accept(&mut self, from: IdentityPub, msg: ShardAcceptMsg, now: Timestamp) {
    tracing::debug!(shard = %msg.shard_id, holder = %from, "shard accept received");
    match self.shard_manager.handle_shard_accept(msg.shard_id, from, msg.offer_msg_id, now).await {
        Ok(()) => {}
        Err(ShardManagerError::ShardNotFound(_)) => {
            tracing::debug!(shard = %msg.shard_id, "shard accept for unknown shard (TTL expired?)");
        }
        Err(e) => panic!("handle_shard_accept unexpected error: {e}"),
    }
}
```

### `handle_pos_challenge_incoming(from: IdentityPub, msg: PosChallengeMsg, now: Timestamp)`

We are the holder. Owner is challenging us to prove we have a shard.

```rust
async fn handle_pos_challenge_incoming(&self, from: IdentityPub, msg: PosChallengeMsg, now: Timestamp) {
    tracing::debug!(shard = %msg.shard_id, challenger = %from, "pos challenge received");

    match self.storage.answer_pos_challenge(msg.shard_id, msg.block_range.0, &msg.nonce) {
        Ok(answer) => {
            let response = PosResponseMsg {
                v: 1,
                challenge_id: msg.challenge_id,
                block_data_hash: answer.block_data_hash,
                merkle_proof: answer.merkle_proof,
                ts: now.0,
            };
            let payload = to_cbor(&response).expect("cbor failed");
            self.net_cmd_tx.send(NetCommand::PublishBoard {
                msg_type: "pos_response".to_string(),
                payload,
                directed_to: Some(from),
            }).await.expect("net channel closed");
            tracing::debug!(shard = %msg.shard_id, "pos challenge: response sent");
        }
        Err(StorageError::ShardNotFound(_)) => {
            tracing::debug!(shard = %msg.shard_id, "pos challenge: shard not held, no response");
        }
        Err(StorageError::BlobMissing(path)) => {
            tracing::error!(shard = %msg.shard_id, ?path, "pos challenge: blob missing on disk!");
            // We claimed to hold this but the file is gone — data loss situation
        }
        Err(e) => panic!("answer_pos_challenge unexpected error: {e}"),
    }
}
```

### `handle_pos_response_incoming(from: IdentityPub, msg: PosResponseMsg, now: Timestamp)`

We are the challenger. Holder responded to our PoS challenge.

```rust
async fn handle_pos_response_incoming(&mut self, from: IdentityPub, msg: PosResponseMsg, now: Timestamp) {
    tracing::debug!(peer = %from, challenge = ?msg.challenge_id, "pos response received");

    // Find which shard this challenge_id corresponds to
    // (Processor needs to track pending challenges: challenge_id → (shard_id, block_index, nonce))
    // Phase 2: track pending challenges in memory
    let challenge_info = match self.pending_pos_challenges.get(&msg.challenge_id) {
        Some(info) => info.clone(),
        None => {
            tracing::debug!("pos response for unknown challenge_id, ignoring");
            return;
        }
    };

    let current_week = (now.0 / SECS_PER_WEEK) as u32;
    let result = self.shard_manager.handle_pos_response(
        from,
        challenge_info.shard_id,
        challenge_info.block_index,
        msg.block_data_hash,
        msg.merkle_proof,
        challenge_info.nonce,
        now,
        current_week,
    ).expect("handle_pos_response: unexpected error");

    match result {
        PosResult::Pass => {
            tracing::debug!(peer = %from, shard = %challenge_info.shard_id, "pos: pass");
        }
        PosResult::Fail => {
            tracing::info!(peer = %from, shard = %challenge_info.shard_id, "pos: FAIL");
            // Send storage_warning to holder (bit rot notification)
            let warning = StorageWarningMsg {
                v: 1,
                shard_id: challenge_info.shard_id,
                details: "PoS verification failed".to_string(),
                ts: now.0,
            };
            let payload = to_cbor(&warning).expect("cbor failed");
            self.net_cmd_tx.send(NetCommand::PublishBoard {
                msg_type: "storage_warning".to_string(),
                payload,
                directed_to: Some(from),
            }).await.expect("net channel closed");
        }
    }

    // Remove from pending challenges
    self.pending_pos_challenges.remove(&msg.challenge_id);
}
```

**Pending PoS challenge tracking:** Processor needs a map from `challenge_id` to
`(shard_id, block_index, nonce)`. This is in-memory state in the Processor:

```rust
// In Processor struct:
pending_pos_challenges: std::collections::HashMap<[u8; 32], PendingPosChallenge>,

// Helper type:
#[derive(Clone)]
struct PendingPosChallenge {
    shard_id: ShardId,
    block_index: u32,
    nonce: [u8; 32],
}
```

When `run_pos_round` fires, populate this map:
```rust
for challenge in &challenges {
    self.pending_pos_challenges.insert(
        // challenge_id = blake3(shard_id || block_index_be || nonce)
        compute_challenge_id(&challenge),
        PendingPosChallenge {
            shard_id: challenge.shard_id,
            block_index: challenge.block_index,
            nonce: challenge.nonce,
        }
    );
}
```

`challenge_id` must match what we sent in `PosChallengeMsg::challenge_id` (a `[u8; 32]`).
The Network task sends `NetCommand::SendPosChallenge` to the holder; the holder's storage
module includes `challenge_id` in the response. We look it up here.

```rust
fn compute_challenge_id(c: &PosChallenge) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&c.shard_id.0);
    hasher.update(&c.block_index.to_be_bytes());
    hasher.update(&c.nonce);
    *hasher.finalize().as_bytes()
}
```

DECISION NEEDED: The Network task's `SendPosChallenge` command must also include the
`challenge_id` field (so Network can embed it in the wire message). Currently
`NetCommand::SendPosChallenge` does not have a `challenge_id` field. Add it:
```rust
NetCommand::SendPosChallenge {
    holder: IdentityPub,
    shard_id: ShardId,
    block_index: u32,
    nonce: [u8; 32],
    challenge_id: [u8; 32],  // ADD THIS FIELD
}
```
The Network task embeds it in `PosChallengeMsg`. This requires updating `daemon/mod.rs`.

### `handle_peer_announce(from: IdentityPub, msg: PeerAnnounceMsg, now: Timestamp)`

Bootstrap: a peer tells us about another peer.

```rust
async fn handle_peer_announce(&self, from: IdentityPub, msg: PeerAnnounceMsg, now: Timestamp) {
    // Phase 2: record the announced peer as known, connect to it
    tracing::debug!(announced = %msg.identity_pub, from = %from, "peer announce");
    self.trust.upsert_peer(&msg.identity_pub, now).expect("upsert_peer failed");
    // Optionally connect:
    self.net_cmd_tx.send(NetCommand::Connect {
        node_addr: String::from_utf8_lossy(&msg.node_addr).to_string(),
    }).await.expect("net channel closed");
}
```

### `handle_direct_message(from: IdentityPub, payload: Vec<u8>)`

Parse `DirectMessage` from CBOR and dispatch on `DirectBody` variant.

```rust
async fn handle_direct_message(&mut self, from: IdentityPub, payload: Vec<u8>) {
    let msg: DirectMessage = match from_cbor(&payload) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(peer = %from, error = %e, "direct message: parse error");
            return;
        }
    };

    let now = Timestamp::now();
    match msg.body {
        DirectBody::Handshake(_) => {
            // Handshake is handled by Network task before DirectMessage is forwarded.
            // Receiving it here = bug in protocol or network task.
            tracing::debug!(peer = %from, "direct: unexpected handshake in processor");
        }
        DirectBody::RestoreRequest(req) => {
            self.handle_restore_request(from, req, now).await;
        }
        DirectBody::RestoreDenied(denied) => {
            tracing::info!(
                peer = %from,
                shard = %denied.shard_id,
                required_weeks = denied.required_weeks,
                current_weeks = denied.current_weeks,
                "restore denied by holder (escrow)"
            );
        }
        DirectBody::BlobReady(ready) => {
            tracing::debug!(peer = %from, shard = %ready.shard_id, "blob ready from holder");
            // TODO Phase 3: pull shard blob from holder via iroh-blobs
        }
    }
}
```

### `handle_restore_request(from: IdentityPub, req: RestoreRequestMsg, now: Timestamp)`

We are the holder. Owner wants to restore a shard.

```rust
async fn handle_restore_request(&self, from: IdentityPub, req: RestoreRequestMsg, now: Timestamp) {
    tracing::debug!(shard = %req.shard_id, owner = %from, "restore request");

    match self.storage.read_shard_for_restore(req.shard_id, &from, now) {
        Ok(blob) => {
            // Send blob to owner via iroh-blobs upload
            self.net_cmd_tx.send(NetCommand::UploadShard {
                shard_id: req.shard_id,
                holder: from,
                data: blob,
            }).await.expect("net channel closed");
            tracing::info!(shard = %req.shard_id, owner = %from, "restore: blob sent");
        }
        Err(StorageError::EscrowDenied(denial)) => {
            tracing::info!(
                shard = %req.shard_id,
                owner = %from,
                required_weeks = denial.required_weeks,
                current_weeks = denial.current_weeks,
                "restore: denied by escrow"
            );
            let denied_msg = RestoreDeniedMsg {
                v: 1,
                shard_id: req.shard_id,
                reason: DenyReason::EscrowNotMet,
                required_weeks: denial.required_weeks,
                current_weeks: denial.current_weeks,
                ts: now.0,
            };
            let payload = to_cbor(&denied_msg).expect("cbor failed");
            self.net_cmd_tx.send(NetCommand::SendDirect {
                peer: from,
                payload,
            }).await.expect("net channel closed");
        }
        Err(StorageError::ShardNotFound(_)) => {
            tracing::debug!(shard = %req.shard_id, "restore: shard not held");
            let denied_msg = RestoreDeniedMsg {
                v: 1,
                shard_id: req.shard_id,
                reason: DenyReason::NotFound,
                required_weeks: 0,
                current_weeks: 0,
                ts: now.0,
            };
            let payload = to_cbor(&denied_msg).expect("cbor failed");
            self.net_cmd_tx.send(NetCommand::SendDirect {
                peer: from,
                payload,
            }).await.expect("net channel closed");
        }
        Err(e) => panic!("read_shard_for_restore unexpected error: {e}"),
    }
}
```

### `handle_shard_uploaded(shard_id, holder, bytes)`

We successfully uploaded a shard blob to a holder (iroh-blobs transfer complete from our side).
Note: the holder still needs to confirm storage via `shard_stored` message.

```rust
async fn handle_shard_uploaded(&self, shard_id: ShardId, holder: IdentityPub, bytes: u64) {
    tracing::debug!(shard = %shard_id, holder = %holder, bytes, "shard uploaded to holder");
    // Update S score: bytes sent to this peer
    let now = Timestamp::now();
    let event = TransferEvent {
        peer: holder,
        bytes_sent_to_peer: bytes,
        bytes_received_from_peer: 0,
    };
    self.trust.record_transfer(&event, now)
        .unwrap_or_else(|e| tracing::debug!(error = %e, "trust update for unknown peer"));
}
```

### `handle_shard_downloaded(shard_id, owner, bytes)`

A holder successfully downloaded our shard blob (from their perspective, we pushed it to them).
In this architecture: this event fires after `NetCommand::UploadShard` completes.
Use it to update trust S score.

Phase 2: for simplicity, `ShardDownloaded` fires when we serve a blob for restore OR when
a holder pulls during upload. The `owner` field is whoever requested the shard.

```rust
async fn handle_shard_downloaded(&mut self, shard_id: ShardId, owner: IdentityPub, bytes: u64) {
    tracing::debug!(shard = %shard_id, peer = %owner, bytes, "shard downloaded");
    let now = Timestamp::now();
    let event = TransferEvent {
        peer: owner,
        bytes_sent_to_peer: bytes,       // we sent the blob
        bytes_received_from_peer: 0,
    };
    self.trust.record_transfer(&event, now)
        .unwrap_or_else(|e| tracing::debug!(error = %e, "trust update for unknown peer"));

    // If this is restore: the owner has received a shard they need for recovery.
    // Storage.record_restore was already called in handle_restore_request.
    // If this is a shard upload (holder pulled from us): handle_shard_stored will arrive
    // via board when holder confirms.
}
```

---

## `check_disk_pressure(now: Timestamp)` helper

Called at end of weekly sync.

```rust
async fn check_disk_pressure(&mut self, now: Timestamp) {
    let result = self.storage.check_pressure(now)
        .expect("check_pressure failed");

    match result.pressure {
        DiskPressure::Normal => {}
        DiskPressure::Soft => {
            tracing::info!("disk pressure: SOFT — rejecting new shard offers");
            // storage.should_accept_offer() will return RejectFull automatically
        }
        DiskPressure::Hard => {
            tracing::info!(
                evictions = result.immediate_evictions.len(),
                drop_notices = result.drop_notices.len(),
                freed_gb = result.freed_gb,
                "disk pressure: HARD — evicting shards"
            );

            // Phase 1: immediate evictions
            for target in &result.immediate_evictions {
                match self.storage.evict_shard(target.shard_id, now) {
                    Ok(owner_pub) => {
                        // Send shard_dropped to owner (optional but good practice)
                        let msg = ShardDroppedMsg { v: 1, shard_id: target.shard_id, ts: now.0 };
                        let payload = to_cbor(&msg).expect("cbor failed");
                        self.net_cmd_tx.send(NetCommand::PublishBoard {
                            msg_type: "shard_dropped".to_string(),
                            payload,
                            directed_to: Some(owner_pub),
                        }).await.expect("net channel closed");
                    }
                    Err(StorageError::ShardNotFound(_)) => {} // already gone
                    Err(e) => panic!("evict_shard unexpected error: {e}"),
                }
            }

            // Phase 2: drop notices
            for notice in &result.drop_notices {
                self.storage.record_drop_notice(notice.shard_id, now)
                    .unwrap_or_else(|e| tracing::debug!(error = %e, "record_drop_notice: shard not found"));
                // Send shard_drop_notice to owner
                let msg = ShardDropNoticeMsg {
                    v: 1,
                    shard_id: notice.shard_id,
                    deadline: notice.deadline,
                    ts: now.0,
                };
                let payload = to_cbor(&msg).expect("cbor failed");
                // Look up owner for this shard
                if let Ok(Some(record)) = self.db.get_holding(&notice.shard_id) {
                    self.net_cmd_tx.send(NetCommand::PublishBoard {
                        msg_type: "shard_drop_notice".to_string(),
                        payload,
                        directed_to: Some(record.owner_pub),
                    }).await.expect("net channel closed");
                }
            }
        }
    }
}
```

---

## Helper: `send_shard_reject`

```rust
async fn send_shard_reject(&self, to: IdentityPub, shard_id: ShardId, reason: RejectReason, now: Timestamp) {
    let msg = ShardRejectMsg {
        v: 1,
        shard_id,
        offer_msg_id: MsgId::derive(&shard_id.0, now.0), // approximate
        reason,
        ts: now.0,
    };
    let payload = to_cbor(&msg).expect("cbor failed");
    self.net_cmd_tx.send(NetCommand::PublishBoard {
        msg_type: "shard_reject".to_string(),
        payload,
        directed_to: Some(to),
    }).await.expect("net channel closed");
}
```

---

## `next_file_id()` helper

```rust
fn next_file_id(&self) -> FileId {
    let current: u64 = self.db.get_config("next_file_id")
        .expect("get_config failed")
        .unwrap_or(0u64);
    let next = current + 1;
    self.db.set_config("next_file_id", &next)
        .expect("set_config failed");
    FileId(next)
}
```

---

## DB operations summary

Processor is the sole DB writer. All writes go through `Db` methods directly or through
engine methods that call `Db` internally. Key write operations per flow:

| Flow | DB operations |
|---|---|
| DirtyEvent | `get_file`, `upsert_file`, `mark_file_dirty`, `get_config`, `set_config` |
| PeerConnected | `get_peer`, `upsert_peer` |
| WeeklySync | via `BudgetPlanner`, `TrustEngine`, `Db::increment_peer_weeks`, `Db::set_schedule` |
| PoS round | via `ShardManager::sample_pos_challenges`, `Db::set_schedule` |
| ShardOffer (holder) | via `Storage::should_accept_offer` (read-only) |
| ShardAccept (owner) | via `ShardManager::handle_shard_accept` |
| ShardStored (owner) | via `ShardManager::handle_shard_stored` → `Db::update_shard_status` |
| ShardDropped (owner) | via `ShardManager::handle_shard_dropped` → `Db::update_shard_status` |
| Delete (holder) | via `Storage::handle_delete_request` → `Db::mark_holding_for_delete` |
| PoS response (owner) | via `ShardManager::handle_pos_response` → `Db::record_pos_verified`, trust update |
| PoS challenge (holder) | read-only (Storage::answer_pos_challenge) |
| Restore request (holder) | via `Storage::read_shard_for_restore` → `Db::upsert_restore_log` |
| Disk pressure | via `Storage::evict_shard` → `Db::delete_holding`, `Db::set_drop_notice_sent_at` |
| ExpiredCooldowns | via `Storage::process_expired_cooldowns` → `Db::delete_holding` |

---

## Business rules

1. **Sole DB writer:** enforced by structure (only Processor holds `Db` — wait, actually
   all modules hold `Db` via Arc clone). The rule is *coordination*: only Processor
   initiates writes that span multiple tables. Individual modules call their own `Db`
   methods. This is acceptable in alpha since redb's MVCC handles concurrent reads and
   serialized writes.

2. **Alpha panic strategy:** unexpected errors → `panic!`. Expected errors (peer offline,
   not enough peers, shard not found for unknown reason) → log and continue.

3. **Channel send panics:** `net_cmd_tx.send(...).await.expect("net channel closed")` —
   if Network task died, daemon should restart entirely. This is correct.

4. **No duplicate WeeklySync:** Scheduler ensures only one WeeklySync fires per week.
   If the user triggers BackupNow while WeeklySync is running — BackupNow runs
   `run_weekly_sync()` again. This is acceptable in alpha (both calls share the DB, both
   are serialized in the single-threaded Processor).

5. **Allowlist bypass:** if `PeerRecord::allowlisted == true` for an owner in
   `handle_shard_offer`: always accept, do not check quota. Storage handles this.

6. **Importance from config:** `config_importance_for_path` must handle glob patterns.
   Use the `glob` crate or simple prefix matching. For Phase 2, prefix matching is sufficient.

---

## Error handling (alpha rules)

| Error | Category | Action |
|---|---|---|
| DB read/write fails | Unexpected | `panic!("db error: {e}")` |
| Peer offline (send fails) | Expected | log debug, continue |
| Not enough peers | Expected | log info, retry next week |
| Shard not found | Usually expected | log debug, return |
| Invalid message (bad CBOR, wrong sig) | Expected (attacker) | log debug, drop |
| Network channel closed | Fatal | panic (Network task died) |
| iroh endpoint closed | Fatal | `cancel.cancel()` via FatalError event |

---

## File layout

```
crates/syncback/src/daemon/processor.rs   — all processor code
```

If the file exceeds ~600 lines, split into:
```
crates/syncback/src/daemon/processor/
  mod.rs       — Processor struct, run(), run_loop()
  scheduled.rs — handle_scheduled() and sub-handlers
  net_events.rs — handle_net_event() and sub-handlers
  cli.rs       — handle_cli() and sub-handlers
  tests.rs     — test scenarios
```

Per project convention: tests in separate `#[cfg(test)] mod tests;` file.

---

## Test scenarios

Integration tests live in `crates/syncback/tests/`. These use real iroh endpoints.

### Unit tests in processor.rs (fast, no iroh)

#### `processor_handles_dirty_event_creates_file_record`

```
Setup:
  test DB, Config with include=[{path: "/home/user/docs", importance: 0.9}]
  Spawn processor run() with channels

Action:
  Send DirtyEvent { path: "/home/user/docs/notes.txt", kind: Created, detected_at: now }

Expected:
  db.get_file("/home/user/docs/notes.txt") returns Some(record) with importance=0.9, dirty=true
```

#### `processor_handles_dirty_event_ignores_low_importance`

```
Action:
  Send DirtyEvent for a path not matching any include pattern

Expected:
  db.get_file(...) returns None
```

#### `processor_cli_status_returns_correct_counts`

```
Setup:
  Insert 3 peers, 5 holding records, 2 stored shard records
  Spawn processor

Action:
  Send CliCmd::Status { reply: oneshot_tx }
  Receive reply

Expected:
  reply.peer_count == 3
  reply.shards_held == 5
  reply.shards_placed == 2
```

#### `processor_handles_shutdown_command`

```
Setup:
  Spawn processor

Action:
  Send CliCmd::Shutdown
  Wait for task to complete

Expected:
  Task completes within 1 second
```

### Integration tests (real iroh, 2 nodes)

See CLAUDE.md Phase 2 gate scenarios. The processor is involved in all of them.
Key scenarios for processor specifically:

#### `pos_challenge_response`

```
Node A holds a shard for Node B.
Node B runs PosRound → sends NetCommand::SendPosChallenge.
Network delivers PosChallengeMsg to A's board.
A (Processor + Storage) computes answer, publishes PosResponseMsg.
B's processor verifies response → PosResult::Pass.
B's trust for A increases (P updated).
```

#### `escrow_denies_low_trust_restore`

```
Node A holds shard for Node B (owner).
Node B requests restore (direct connection).
Node B has weeks_in_network=2, bytes_restored > 1 GiB → Tier1 requires 4 weeks.
A's processor → handle_restore_request → storage.read_shard_for_restore → EscrowDenied.
A sends RestoreDeniedMsg to B.
B's processor receives RestoreDenied → logs "restore denied by holder (escrow)".
```

#### `disk_pressure_triggers_eviction`

```
Storage quota = 10 MB.
Store 9.8 MB worth of shards (> 95% used → hard pressure).
Processor weekly sync calls check_disk_pressure().
Expected: evict lowest-priority shards until used < 8.5 MB (soft threshold).
Expected: shard_dropped message sent to owner.
```

---

## Notes for implementer

1. **`pending_pos_challenges` map** should be periodically cleaned (old entries). Add
   cleanup in `run_weekly_sync()`:
   ```rust
   let cutoff = now.0 - 7 * 86_400; // older than 7 days (TTL of board entries)
   self.pending_pos_challenges.retain(|_, v| v.sent_at.0 >= cutoff);
   ```
   Add `sent_at: Timestamp` to `PendingPosChallenge`.

2. **Processor struct is not `Send`** if it contains `std::sync::Mutex`. Use
   `tokio::sync::Mutex` for any shared state in ShardManager (pending blobs). Processor
   itself only runs in one task so it doesn't need to be `Send` across threads.

3. **`from_cbor` imports:** use `syncback_core::messages::from_cbor` for board message
   payloads. Use `syncback_core::types::from_cbor_bytes` for DB values (these are
   different functions, same CBOR format).

4. **`to_cbor` for outbound messages:** use `syncback_core::messages::to_cbor` consistently.

5. **`MsgId` for reject/accept:** the `offer_msg_id` in accept/reject responses should
   be the `MsgId` of the original `shard_offer` board entry. In Phase 2, the Processor
   does not track offer MsgIds (that would require storing them when we publish offers).
   Approximation: derive MsgId from `shard_id || ts` at send time. This is sufficient
   for deduplication purposes in alpha.

6. **Parallel shard uploads:** in `upload_unit`, all n shard_offer messages are sent to
   the board (broadcast to multiple holders). The accepts will arrive asynchronously.
   The current `handle_shard_accept` sends blob one at a time. This is correct — no
   parallelism needed in Processor (it's a single task).

7. **`config_importance_for_path` algorithm:**
   - Normalize input path to canonical form (no trailing slash, absolute)
   - For each include entry, check if path starts with entry.path
   - Among all matches, pick the most specific (longest path prefix wins)
   - Return its importance; if no match, return 0.0
   - Exclude patterns: if path matches any exclude glob, return 0.0

8. **`identity_key` sharing:** `ShardManager` is constructed with a clone of the
   `SigningKey`. `ed25519_dalek::SigningKey` does NOT implement `Clone` in some versions.
   Check: if not Clone, use `ed25519_dalek::SigningKey::from_bytes(&key.to_bytes())`.
   Or wrap in `Arc<SigningKey>`. For alpha: clone via `from_bytes`.

9. **Blocking DB in async context:** all `Db` operations use `redb` which does blocking
   I/O. In tokio, blocking I/O should go through `tokio::task::spawn_blocking`. However,
   for alpha with small DBs and infrequent writes, calling `Db` methods directly in the
   async Processor is acceptable. The event loop is not latency-sensitive (1-week cycles).
   If DB calls block the event loop measurably, wrap in `spawn_blocking` later.
