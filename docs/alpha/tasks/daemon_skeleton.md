# Task Spec: daemon skeleton

**Module:** `crates/syncback/src/main.rs` + `crates/syncback/src/daemon/mod.rs`
**Phase:** 2 (syncback daemon, first module)
**Role:** Wiring layer — tokio runtime, graceful shutdown, channel definitions, task stubs

---

## Overview

The daemon skeleton is the structural backbone of the `syncback` binary. It defines:

1. How the process starts (`main.rs`): arg parsing, tracing setup, tokio runtime, call into daemon.
2. The `DaemonHandle` struct (`daemon/mod.rs`): owns all task `JoinHandle`s, channels, and the
   `CancellationToken`. Provides `run()` and `shutdown()`.
3. All channel message types (`Command`, `DirtyEvent`, `NetEvent`, `NetCommand`, `CliRequest`,
   `CliResponse`) — the typed boundaries between tasks.
4. Five stub tasks that compile and respect cancellation but contain no real logic yet.

Subsequent Phase 2 specs (`network.md`, `processor.md`, `scheduler.md`, `storage.md`,
`shard_manager.md`) will flesh out the stubs. The skeleton must not change the channel types once
set — all other modules depend on them.

**This module has no DB reads/writes.** The `Db` is opened here and passed into `DaemonHandle`,
but the skeleton itself issues no queries.

---

## Dependencies

**Crates:**
- `syncback-core` — `Db`, `types::*` (imported but mostly used inside later task impls)
- `tokio` (`full` feature) — runtime, `mpsc`, `JoinHandle`, `signal`
- `tokio-util` — `CancellationToken`
- `tracing` + `tracing-subscriber` — logging
- `thiserror` — `DaemonError`

**Other modules in `syncback`:**
- None yet — this is the first module of Phase 2.

**syncback-core modules used at startup:**
- `syncback_core::db::Db` — opened in `main`, passed to `DaemonHandle::new()`

---

## File layout

```
crates/syncback/src/
  main.rs
  daemon/
    mod.rs          ← DaemonHandle, channel types, task spawn logic
    processor.rs    ← stub (created here, implemented in processor.md)
    network.rs      ← stub
    scheduler.rs    ← stub
    cli_server.rs   ← stub
    watcher.rs      ← stub (Phase 3, but file must exist as empty stub)
```

The implementer creates all five stub files as part of this task. Each stub is a single async
function that loops on `select!(token.cancelled() => break)` and returns `Ok(())`.

---

## Public API

### main.rs

```rust
fn main() -> anyhow::Result<()>
```

Single entry point. Does:
1. Parse args (see "Arg parsing" below).
2. Init tracing to stderr.
3. Build tokio runtime.
4. Dispatch to subcommand.

No `#[tokio::main]` — build the runtime explicitly so we control thread count and can set a name.

### daemon/mod.rs

```rust
pub struct DaemonHandle {
    // private fields
}

impl DaemonHandle {
    /// Open DB, create channels, spawn all tasks, return handle.
    /// Panics if DB cannot be opened (fatal — no DB = no daemon).
    pub async fn start(config: Config) -> Result<Self, DaemonError>;

    /// Wait for all tasks to finish (called after signal or error).
    /// Returns Err if any task panicked.
    pub async fn join(self) -> Result<(), DaemonError>;

    /// Cancel all tasks and wait for them to finish.
    /// Called on Ctrl+C or fatal error.
    pub async fn shutdown(self) -> Result<(), DaemonError>;
}
```

### Config

```rust
/// Parsed configuration for the daemon.
/// Loaded from ~/.syncback/config.toml at startup.
/// Passed into DaemonHandle::start().
#[derive(Debug, Clone)]
pub struct Config {
    pub syncback_dir: std::path::PathBuf,  // ~/.syncback/ or override
    pub backup: BackupConfig,
    pub storage: StorageConfig,
    pub network: NetworkConfig,
    pub schedule: ScheduleConfig,
}

#[derive(Debug, Clone)]
pub struct BackupConfig {
    /// Folders to include, with their importance weights.
    pub include: Vec<IncludeEntry>,
    /// Glob patterns to exclude (applied after include).
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IncludeEntry {
    pub path: std::path::PathBuf,
    pub importance: f64,  // 0.0–1.0
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub quota_gb: u64,
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Bootstrap nodes. Empty = use hardcoded defaults.
    pub seed_nodes: Vec<String>,
    pub bandwidth_limit_mbps: u64,  // 0 = unlimited
}

#[derive(Debug, Clone)]
pub struct ScheduleConfig {
    pub sync: SyncFrequency,
    pub vacuum: VacuumFrequency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncFrequency { Weekly }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VacuumFrequency { Monthly }
```

Config is NOT parsed with serde in this task — the skeleton uses a `Config::default()` that
sets `syncback_dir = ~/.syncback/` and reasonable defaults. Full TOML parsing is part of Phase 3
(`cli.md`). Implementer must write `Config::default()` and `Config::load(path)` where
`Config::load` is a stub that returns `Config::default()` and logs `DEBUG "config load: using
defaults"`.

---

## Channel types

All channel types live in `daemon/mod.rs`. They define the complete message vocabulary between
tasks. **These types must not be changed once implemented.**

### Processor inbox: Command

The Processor receives two kinds of inputs via a single `mpsc::Receiver<ProcessorMsg>`. Both
Scheduler and CLI Server send into the same channel via senders of type
`mpsc::Sender<ProcessorMsg>`.

```rust
/// Top-level message into the Processor task.
pub enum ProcessorMsg {
    Scheduled(ScheduledCmd),
    Cli(CliCmd),
}

/// Periodic commands from the Scheduler.
#[derive(Debug, Clone)]
pub enum ScheduledCmd {
    /// Trigger weekly sync: budget → pack dirty files → upload shards.
    WeeklySync,
    /// Trigger PoS challenge round for all held shards.
    PosRound,
    /// Trigger monthly vacuum: repack stale units, delete expired.
    Vacuum,
    /// Trigger repair check: detect under-replicated units.
    RepairCheck,
}

/// Commands from the CLI Server (user requests).
#[derive(Debug)]
pub enum CliCmd {
    /// Return daemon status (uptime, peer count, shard counts, budget).
    Status {
        /// One-shot reply channel.
        reply: tokio::sync::oneshot::Sender<StatusReply>,
    },
    /// Force an immediate weekly sync (ignores schedule).
    BackupNow {
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    /// Initiate restore of a file by path.
    RestoreFile {
        path: std::path::PathBuf,
        dest: std::path::PathBuf,
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
    /// Graceful daemon shutdown (user ran `syncback stop`).
    Shutdown,
}
```

### Processor inbox: DirtyEvent (from Watcher)

```rust
/// Sent by the Watcher task when a monitored file changes.
#[derive(Debug, Clone)]
pub struct DirtyEvent {
    /// Absolute path of the changed file.
    pub path: std::path::PathBuf,
    /// What happened to the file.
    pub kind: DirtyKind,
    /// When the event was detected (Unix seconds).
    pub detected_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirtyKind {
    Created,
    Modified,
    Deleted,
}
```

Watcher has its own sender: `mpsc::Sender<DirtyEvent>`. The Processor holds a separate receiver
for dirty events. Processor `select!`s on both `ProcessorMsg` and `DirtyEvent`.

### Network ↔ Processor

```rust
/// Events from the Network task to the Processor.
#[derive(Debug)]
pub enum NetEvent {
    /// A peer connected and completed identity exchange.
    PeerConnected {
        peer: syncback_core::types::IdentityPub,
        node_addr: String,  // iroh NodeAddr serialized; Network task handles iroh types
    },
    /// A peer disconnected.
    PeerDisconnected {
        peer: syncback_core::types::IdentityPub,
    },
    /// A board message arrived from a peer (deserialized by Network, passed as raw bytes).
    /// Network verifies the outer BoardEntry signature; Processor dispatches on body type.
    BoardMessage {
        from: syncback_core::types::IdentityPub,
        msg_type: String,   // e.g. "shard_offer", "shard_stored"
        payload: Vec<u8>,   // CBOR bytes of the inner message body
    },
    /// A direct (QUIC) message arrived from a peer.
    DirectMessage {
        from: syncback_core::types::IdentityPub,
        payload: Vec<u8>,   // CBOR bytes of DirectMessage body
    },
    /// PoS challenge response received from a holder.
    PosResponse {
        from: syncback_core::types::IdentityPub,
        shard_id: syncback_core::types::ShardId,
        block_index: u32,
        hash: [u8; 32],
        merkle_proof: Vec<[u8; 32]>,
    },
    /// A shard blob transfer completed (we uploaded our shard to a holder).
    ShardUploaded {
        shard_id: syncback_core::types::ShardId,
        holder: syncback_core::types::IdentityPub,
        bytes: u64,
    },
    /// A shard blob transfer completed (we downloaded a shard we hold for an owner).
    ShardDownloaded {
        shard_id: syncback_core::types::ShardId,
        owner: syncback_core::types::IdentityPub,
        bytes: u64,
    },
    /// Network encountered a fatal error (iroh endpoint closed, etc.).
    FatalError(String),
}

/// Commands from the Processor to the Network task.
#[derive(Debug)]
pub enum NetCommand {
    /// Connect to a peer by node address.
    Connect {
        node_addr: String,
    },
    /// Publish a board message (from us, to our iroh-docs board).
    PublishBoard {
        msg_type: String,
        payload: Vec<u8>,      // CBOR bytes to sign and publish
        directed_to: Option<syncback_core::types::IdentityPub>,
    },
    /// Send a direct QUIC message to a peer.
    SendDirect {
        peer: syncback_core::types::IdentityPub,
        payload: Vec<u8>,
    },
    /// Upload a shard blob to a holder via iroh-blobs.
    UploadShard {
        shard_id: syncback_core::types::ShardId,
        holder: syncback_core::types::IdentityPub,
        data: Vec<u8>,
    },
    /// Send a PoS challenge to a holder.
    SendPosChallenge {
        holder: syncback_core::types::IdentityPub,
        shard_id: syncback_core::types::ShardId,
        block_index: u32,
        nonce: [u8; 32],
    },
    /// Request a held shard for restore (we are the owner).
    RequestShard {
        holder: syncback_core::types::IdentityPub,
        shard_id: syncback_core::types::ShardId,
    },
}
```

### CLI Server ↔ external

The CLI Server receives `StatusReply` from Processor (via oneshot) and serializes it to JSON for
the CLI client. The reply types are defined here so other tasks can construct them.

```rust
/// Response to Status CLI command.
#[derive(Debug, serde::Serialize)]
pub struct StatusReply {
    pub uptime_secs: u64,
    pub peer_count: usize,
    pub shards_held: usize,       // shards we hold for others
    pub shards_placed: usize,     // shards others hold for us
    pub budget_gb: f64,
    pub dirty_files: usize,
}
```

---

## DaemonHandle internals

```rust
struct DaemonHandle {
    cancel: tokio_util::sync::CancellationToken,

    // Task handles — monitored in join()
    processor_handle: tokio::task::JoinHandle<()>,
    network_handle: tokio::task::JoinHandle<()>,
    scheduler_handle: tokio::task::JoinHandle<()>,
    cli_server_handle: tokio::task::JoinHandle<()>,
    // watcher_handle: Phase 3

    // Senders held by DaemonHandle for shutdown signaling (not used by tasks)
    // Tasks receive their senders/receivers at spawn time; handles are dropped on shutdown.
    started_at: std::time::Instant,
}
```

### Channel capacity constants

```rust
const PROCESSOR_CHANNEL_CAPACITY: usize = 256;
const DIRTY_CHANNEL_CAPACITY: usize = 1024;   // file events burst
const NET_EVENT_CHANNEL_CAPACITY: usize = 256;
const NET_CMD_CHANNEL_CAPACITY: usize = 256;
const CLI_CHANNEL_CAPACITY: usize = 16;        // CLI requests are slow
```

These are module-level constants in `daemon/mod.rs`.

### DaemonHandle::start() sequence

```
1. Open DB: syncback_core::db::Db::open(&config.syncback_dir.join("syncback.redb"))
   → panic if fails ("fatal: cannot open DB")

2. Create CancellationToken (one, cloned for all tasks)

3. Create channels:
   - processor_tx / processor_rx  (ProcessorMsg, capacity PROCESSOR_CHANNEL_CAPACITY)
   - dirty_tx / dirty_rx          (DirtyEvent, capacity DIRTY_CHANNEL_CAPACITY)
   - net_event_tx / net_event_rx  (NetEvent, capacity NET_EVENT_CHANNEL_CAPACITY)
   - net_cmd_tx / net_cmd_rx      (NetCommand, capacity NET_CMD_CHANNEL_CAPACITY)
   // CLI channel is internal to cli_server (oneshot per request, no mpsc here)

4. Spawn tasks (tokio::spawn), pass cloned cancel token + relevant channel ends:
   - processor: receives processor_rx, dirty_rx, net_event_rx; sends net_cmd_tx
   - network:   receives net_cmd_rx; sends net_event_tx, processor_tx (for board msgs)
   - scheduler: sends processor_tx (ScheduledCmd wrapped in ProcessorMsg::Scheduled)
   - cli_server: sends processor_tx (CliCmd wrapped in ProcessorMsg::Cli)

5. Log: tracing::info!(socket = ?cli_socket_path, "daemon started")

6. Return DaemonHandle { cancel, handles, started_at }
```

### DaemonHandle::join() logic

```rust
pub async fn join(self) -> Result<(), DaemonError> {
    tokio::select! {
        r = self.processor_handle => {
            r.map_err(|e| DaemonError::TaskPanicked { task: "processor", msg: e.to_string() })?
        }
        r = self.network_handle => {
            r.map_err(|e| DaemonError::TaskPanicked { task: "network", msg: e.to_string() })?
        }
        r = self.scheduler_handle => {
            r.map_err(|e| DaemonError::TaskPanicked { task: "scheduler", msg: e.to_string() })?
        }
        r = self.cli_server_handle => {
            r.map_err(|e| DaemonError::TaskPanicked { task: "cli_server", msg: e.to_string() })?
        }
    }
    Ok(())
}
```

Any task panicking → the select arm returns `Err(JoinError)` → `DaemonError::TaskPanicked` →
propagates to main → process exits non-zero. systemd restarts the process.

### DaemonHandle::shutdown() logic

```rust
pub async fn shutdown(self) -> Result<(), DaemonError> {
    tracing::info!("shutdown: cancelling all tasks");
    self.cancel.cancel();
    // Now wait for all tasks to finish (they observe token.cancelled())
    // Use join_all style but propagate first panic
    let results = tokio::join!(
        self.processor_handle,
        self.network_handle,
        self.scheduler_handle,
        self.cli_server_handle,
    );
    // Check each for panic
    for (name, r) in [("processor", results.0), ("network", results.1),
                      ("scheduler", results.2), ("cli_server", results.3)] {
        r.map_err(|e| DaemonError::TaskPanicked { task: name, msg: e.to_string() })?;
    }
    tracing::info!("shutdown: complete");
    Ok(())
}
```

---

## Error types

```rust
/// Top-level daemon errors. Used in main() via anyhow for final printing.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("task '{task}' panicked: {msg}")]
    TaskPanicked { task: &'static str, msg: String },

    #[error("cannot open database at {path}: {source}")]
    DbOpen {
        path: std::path::PathBuf,
        #[source]
        source: redb::Error,
    },

    #[error("cli socket error: {0}")]
    CliSocket(#[from] std::io::Error),

    #[error("config error: {0}")]
    Config(String),
}
```

`DaemonError` is defined in `daemon/mod.rs`. `main()` uses `anyhow::Result<()>` and converts via
`?` (anyhow's `From<DaemonError>` kicks in).

---

## main.rs: arg parsing

No `clap`. Simple match on `std::env::args()`:

```rust
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(String::as_str);

    init_tracing();

    match subcommand {
        Some("daemon") => run_daemon(&args[2..]),
        Some("init")   => run_init(&args[2..]),
        Some("status") => run_cli_status(&args[2..]),
        Some("stop")   => run_cli_stop(&args[2..]),
        _              => {
            eprintln!("Usage: syncback <daemon|init|status|stop>");
            eprintln!("  daemon  — start the daemon (foreground)");
            eprintln!("  init    — initialize ~/.syncback/");
            eprintln!("  status  — print daemon status");
            eprintln!("  stop    — gracefully stop the running daemon");
            std::process::exit(1);
        }
    }
}
```

All subcommand functions except `run_daemon` are **stubs** in this task:

```rust
fn run_init(_args: &[String]) -> anyhow::Result<()> {
    eprintln!("syncback init: not yet implemented");
    Ok(())
}

fn run_cli_status(_args: &[String]) -> anyhow::Result<()> {
    eprintln!("syncback status: not yet implemented");
    Ok(())
}

fn run_cli_stop(_args: &[String]) -> anyhow::Result<()> {
    eprintln!("syncback stop: not yet implemented");
    Ok(())
}
```

### run_daemon

```rust
fn run_daemon(_args: &[String]) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("syncback-worker")
        .enable_all()
        .build()?;

    rt.block_on(async {
        let config = Config::load(default_syncback_dir())?;
        let handle = DaemonHandle::start(config).await?;

        // Wait for Ctrl+C
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl+C, shutting down");
                handle.shutdown().await?;
            }
            r = handle.join() => {
                // A task exited on its own (panic propagated as Err, normal exit as Ok)
                r?;
            }
        }
        Ok(())
    })
}
```

### init_tracing

```rust
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("RUST_LOG")
                .unwrap_or_else(|_| EnvFilter::new("syncback=debug,iroh=info"))
        )
        .with_writer(std::io::stderr)
        .init();
}
```

### default_syncback_dir

```rust
fn default_syncback_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").expect("HOME env var not set");
    std::path::PathBuf::from(home).join(".syncback")
}
```

---

## Task stubs

Each stub lives in its own file. The implementer creates these files as part of this task. They
are empty async loops that respect cancellation. Later specs replace the body.

### daemon/processor.rs (stub)

```rust
use tokio_util::sync::CancellationToken;
use crate::daemon::{ProcessorMsg, DirtyEvent, NetEvent, NetCommand};
use syncback_core::db::Db;
use tokio::sync::mpsc;

pub async fn run(
    db: Db,
    cancel: CancellationToken,
    processor_rx: mpsc::Receiver<ProcessorMsg>,
    dirty_rx: mpsc::Receiver<DirtyEvent>,
    net_event_rx: mpsc::Receiver<NetEvent>,
    net_cmd_tx: mpsc::Sender<NetCommand>,
) {
    tracing::debug!("processor: started (stub)");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("processor: cancelled");
                break;
            }
            msg = processor_rx.recv() => {
                if msg.is_none() { break; }
                // TODO: implement in processor.md
            }
            event = dirty_rx.recv() => {
                if event.is_none() { break; }
                // TODO: implement in processor.md
            }
            event = net_event_rx.recv() => {
                if event.is_none() { break; }
                // TODO: implement in processor.md
            }
        }
    }
    tracing::debug!("processor: stopped");
}
```

### daemon/network.rs (stub)

```rust
use tokio_util::sync::CancellationToken;
use crate::daemon::{NetCommand, NetEvent, ProcessorMsg};
use tokio::sync::mpsc;

pub async fn run(
    cancel: CancellationToken,
    net_cmd_rx: mpsc::Receiver<NetCommand>,
    net_event_tx: mpsc::Sender<NetEvent>,
    processor_tx: mpsc::Sender<ProcessorMsg>,
) {
    tracing::debug!("network: started (stub)");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("network: cancelled");
                break;
            }
            cmd = net_cmd_rx.recv() => {
                if cmd.is_none() { break; }
                // TODO: implement in network.md
            }
        }
    }
    tracing::debug!("network: stopped");
}
```

### daemon/scheduler.rs (stub)

```rust
use tokio_util::sync::CancellationToken;
use crate::daemon::{ProcessorMsg, ScheduledCmd};
use tokio::sync::mpsc;

pub async fn run(
    cancel: CancellationToken,
    processor_tx: mpsc::Sender<ProcessorMsg>,
) {
    tracing::debug!("scheduler: started (stub)");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("scheduler: cancelled");
                break;
            }
            // TODO: implement in scheduler.md
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(300)) => {
                // Placeholder: do nothing every 5 minutes
                tracing::debug!("scheduler: tick (stub)");
            }
        }
    }
    tracing::debug!("scheduler: stopped");
}
```

### daemon/cli_server.rs (stub)

```rust
use tokio_util::sync::CancellationToken;
use crate::daemon::{ProcessorMsg, CliCmd, StatusReply};
use tokio::sync::mpsc;
use std::path::Path;

pub async fn run(
    cancel: CancellationToken,
    processor_tx: mpsc::Sender<ProcessorMsg>,
    socket_path: std::path::PathBuf,
) {
    tracing::debug!("cli_server: started (stub)");
    // TODO: bind Unix socket, accept connections, dispatch CliCmd
    // For now: just wait for cancellation
    cancel.cancelled().await;
    tracing::debug!("cli_server: stopped");
}
```

### daemon/watcher.rs (stub — Phase 3)

```rust
use tokio_util::sync::CancellationToken;
use crate::daemon::DirtyEvent;
use tokio::sync::mpsc;

pub async fn run(
    cancel: CancellationToken,
    dirty_tx: mpsc::Sender<DirtyEvent>,
) {
    tracing::debug!("watcher: started (stub, Phase 3)");
    cancel.cancelled().await;
    tracing::debug!("watcher: stopped");
}
```

---

## DB operations

This module opens the DB but performs no queries itself. The `Db` handle is passed into
`DaemonHandle::start()` and then cloned into each task that needs it (all clones share the same
`Arc<redb::Database>` internally).

```rust
// In DaemonHandle::start():
let syncback_dir = config.syncback_dir.clone();
let db_path = syncback_dir.join("syncback.redb");
let db = syncback_core::db::Db::open(&db_path)
    .unwrap_or_else(|e| panic!("fatal: cannot open DB at {db_path:?}: {e}"));
```

The schema is already defined in `syncback-core/src/db.rs` (Phase 1). `Db::open()` creates the
tables on first run. No migrations needed in alpha.

---

## Business rules

The skeleton has no protocol business rules. Its only invariants are:

1. **Single DB writer:** `Db` is cloned into Processor only. Other tasks do not hold `Db`.
   (Network and CLI Server get no `Db` handle — they communicate with Processor via channels.)

2. **All DB writes go through Processor:** Watcher sends DirtyEvent → Processor writes to
   `dirty_files` table. Network sends NetEvent → Processor writes to `peers`, `shards`, etc.

3. **Panic propagation:** Any task panic → `join()` returns `Err` → process exits → systemd
   restarts. This is intentional (alpha strategy). Do not catch panics.

4. **Clean shutdown:** `CancellationToken::cancel()` is the only shutdown mechanism. All tasks
   observe `cancel.cancelled()` in their select loops. No `std::process::exit()` in tasks.

5. **Channel send never blocks:** All sends to bounded channels use
   `try_send` or `send` with `.expect("channel closed: {name}")`. A closed channel means the
   receiver task died — panic is appropriate.

   **Exception for CLI:** CLI oneshot senders may be silently dropped if the CLI client
   disconnected. Use `let _ = reply.send(...)` for oneshot sends.

---

## Test scenarios

Tests in `crates/syncback/src/daemon/` module are integration-style (require tokio runtime) but
live in the same file as the skeleton code. Use `#[tokio::test]`.

Tests go in separate files per CLAUDE.md memory feedback:
- `daemon/mod.rs` — main code
- `daemon/tests.rs` — tests, included via `#[cfg(test)] mod tests;`

### daemon_starts_and_cancels_cleanly

```
Setup:
  Config::default() with tmpdir for syncback_dir
  Create syncback_dir (mkdir)
  DaemonHandle::start(config).await  → Ok(handle)
  handle.shutdown().await

Expect:
  No panic
  shutdown() returns Ok(())
```

### daemon_task_panic_propagates_to_join

```
This test cannot easily be written at the skeleton level since we'd need to inject a panic
into a stub task. Mark as SKIP (implement later with real task bodies).
```

### channel_types_are_send

```
// Compile-time test: ensure all message types implement Send (required for mpsc across tasks)
fn assert_send<T: Send>() {}

fn channel_types_are_send() {
    assert_send::<ProcessorMsg>();
    assert_send::<DirtyEvent>();
    assert_send::<NetEvent>();
    assert_send::<NetCommand>();
    assert_send::<StatusReply>();
}
```

### config_default_returns_home_dir

```
Setup:
  Config::load() with nonexistent path (stub returns default)
Expect:
  config.syncback_dir ends with ".syncback"
  config.storage.quota_gb > 0
```

### cancellation_token_propagates_to_all_stubs

```
Setup:
  DaemonHandle::start(config).await
  Immediately call handle.shutdown().await

Expect:
  shutdown() completes within 2 seconds
  (All stub tasks exit on cancelled() without delay)
```

---

## Notes for implementer

1. **`Db` not passed to Network/CLI** — only Processor holds `Db`. This is enforced structurally:
   don't add a `db: Db` parameter to `network::run()` or `cli_server::run()`.

2. **`watcher.rs` is a Phase 3 stub** — it is spawned and immediately waits on cancellation.
   The `dirty_tx` sender is kept alive in `DaemonHandle` so the processor's `dirty_rx` does not
   close prematurely.

3. **CLI socket path** — `~/.syncback/syncback.sock`. Pass as `PathBuf` into `cli_server::run()`.
   Remove the socket file on startup if it already exists (stale file from previous run). Do this
   in `DaemonHandle::start()` before spawning cli_server.

4. **tokio-util version** — `CancellationToken` is in `tokio_util::sync::CancellationToken`.
   The workspace already has `tokio-util = "0.7"`.

5. **`redb` import in syncback crate** — `syncback` does not directly list `redb` as a
   dependency, but `DaemonError::DbOpen` needs `redb::Error`. Add `redb` to
   `crates/syncback/Cargo.toml` as a direct dependency. Alternatively, use `String` for the
   source field. Prefer using `redb::Error` directly for type safety — add the dep.

   ```toml
   # in crates/syncback/Cargo.toml
   redb = { workspace = true }
   ```

6. **`ProcessorMsg` and `ScheduledCmd`** — the Scheduler only sends `ProcessorMsg::Scheduled(cmd)`.
   The CLI Server only sends `ProcessorMsg::Cli(cmd)`. Do not conflate these — the Processor
   must be able to handle them differently in its dispatch logic.

7. **No `anyhow` in `daemon/mod.rs`** — `DaemonError` is a proper `thiserror` enum.
   `anyhow` is used only in `main()` for top-level `?` propagation. `daemon/mod.rs` returns
   `Result<_, DaemonError>` throughout.

8. **Tests in separate file** — per project convention (see CLAUDE.md memory), tests go in
   `daemon/tests.rs`, included from `daemon/mod.rs` with:
   ```rust
   #[cfg(test)]
   mod tests;
   ```

9. **tmpdir for test DB** — in tests, use `tempfile::TempDir` to get a disposable directory:
   ```rust
   let dir = tempfile::TempDir::new().unwrap();
   let config = Config { syncback_dir: dir.path().to_path_buf(), ..Config::default() };
   ```
   `tempfile` is already in `[dev-dependencies]`.

10. **`impl Default for Config`** must be explicit and not derive `Default` (since `PathBuf`
    default is `""` which is wrong). Construct the home-dir path explicitly.

11. **Watcher sender must stay alive** — even though `watcher.rs` is a Phase 3 stub that
    immediately awaits cancellation, the `dirty_tx: mpsc::Sender<DirtyEvent>` must be kept in
    `DaemonHandle` (not dropped). If it drops, Processor's `dirty_rx.recv()` returns `None` and
    the processor exits immediately. Keep the sender alive by storing it in `DaemonHandle`.

    Similarly keep `net_cmd_tx` and the Processor's `processor_tx` clone alive.

---

## Cargo.toml additions

Add to `crates/syncback/Cargo.toml`:

```toml
[dependencies]
# ... existing ...
redb = { workspace = true }
anyhow = "1"
```

`anyhow` is not currently in the workspace — add it:

```toml
# in workspace Cargo.toml [workspace.dependencies]:
anyhow = "1"
```

Then reference it in the syncback crate:

```toml
# crates/syncback/Cargo.toml
anyhow = { workspace = true }
```
