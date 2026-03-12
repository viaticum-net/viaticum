# Task spec: cli module (Phase 3)

**Target files:**
- `crates/syncback/src/daemon/cli_server/mod.rs` — CLI server tokio task (replace the current stub at `cli_server.rs`)
- `crates/syncback/src/daemon/cli_server/tests.rs` — unit tests for CLI server
- `crates/syncback/src/cli/mod.rs` — CLI client subcommand dispatch
- `crates/syncback/src/cli/init.rs` — `syncback init` flow (BIP39, key derivation, directory creation)

**Phase:** 3 (user layer)

**Prerequisites:** All Phase 2 modules complete and GATE passed. Processor's `CliCmd` enum is already defined and wired in `daemon/mod.rs`.

---

## Overview

The CLI module has two distinct, complementary halves:

**CLI Server** is one of the five tokio tasks inside the daemon. It binds a Unix domain socket at `~/.syncback/syncback.sock`, accepts incoming client connections, reads newline-delimited JSON request objects, dispatches to the Processor via the existing `CliCmd` channel mechanism, and writes a JSON response back.

**CLI Client** is the user-facing code in `main.rs` / `cli/mod.rs` / `cli/init.rs`. When the user runs `syncback status` (or any non-`daemon` subcommand), the binary connects to the Unix socket, sends a JSON request, reads the JSON response, and prints it to stdout. When the user runs `syncback init`, no daemon connection is needed — the init flow runs entirely in the calling process.

The current `main.rs` has stub implementations for all subcommands. This task replaces them with working code.

---

## Dependencies

**syncback crate (same crate):**
- `daemon::{ProcessorMsg, CliCmd, StatusReply}` — already defined in `daemon/mod.rs`
- `tokio::sync::{mpsc, oneshot}`
- `tokio_util::sync::CancellationToken`
- `tokio::net::{UnixListener, UnixStream}`
- `tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader}`
- `tracing`
- `serde`, `serde_json`

**External crates to add to `crates/syncback/Cargo.toml`:**
- `serde_json = "1"` — JSON for CLI protocol
- `bip39 = "2"` — BIP39 mnemonic generation and parsing
- `clap = { version = "4", features = ["derive"] }` — argument parsing

**Key derivation (already in Cargo.toml):**
- `hkdf`, `sha2`, `ed25519-dalek`, `rand`

**For init flow:**
- `std::fs`, `std::os::unix::fs::PermissionsExt` — chmod 0600 on identity.key
- `std::io::{stdin, stdout, Write}` — interactive prompts

---

## File layout

```
crates/syncback/src/
  main.rs                    — updated: uses cli::Cli (clap), routes subcommands
  cli/
    mod.rs                   — clap Cli struct, run_subcommand dispatch, connect_to_daemon
    init.rs                  — syncback init flow
  daemon/
    cli_server/
      mod.rs                 — Unix socket server task
      tests.rs               — unit tests
```

The existing `cli_server.rs` flat file becomes the `cli_server/` directory. Update `daemon/mod.rs` to change `mod cli_server;` accordingly — the declaration stays the same, Rust will find `cli_server/mod.rs` automatically.

---

## Part 1: CLI Server (daemon side)

### Location

`crates/syncback/src/daemon/cli_server/mod.rs`

This replaces the current stub `cli_server.rs` which only calls `cancel.cancelled().await`.

### Public API

```rust
/// Run the CLI server task until `cancel` is signalled.
/// Binds `socket_path`, accepts JSON CLI connections, dispatches to Processor.
pub async fn run(
    cancel: tokio_util::sync::CancellationToken,
    processor_tx: tokio::sync::mpsc::Sender<crate::daemon::ProcessorMsg>,
    socket_path: std::path::PathBuf,
);
```

The signature is identical to the current stub — no changes needed in `daemon/mod.rs` where `cli_server::run(...)` is called.

### Internal structure

```rust
// cli_server/mod.rs

use std::path::PathBuf;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use serde_json;

use crate::daemon::{CliCmd, ProcessorMsg};

#[cfg(test)]
mod tests;

pub async fn run(
    cancel: CancellationToken,
    processor_tx: mpsc::Sender<ProcessorMsg>,
    socket_path: PathBuf,
) { ... }

/// Handle one accepted client connection.
async fn handle_connection(
    stream: UnixStream,
    processor_tx: mpsc::Sender<ProcessorMsg>,
    cancel: CancellationToken,
) { ... }

/// Parse a JSON line into a CliRequest and dispatch to Processor.
/// Returns a JSON response string (no trailing newline — caller adds it).
async fn dispatch(
    request: CliRequest,
    processor_tx: &mpsc::Sender<ProcessorMsg>,
) -> CliResponse { ... }
```

### Server event loop

```rust
pub async fn run(cancel, processor_tx, socket_path) {
    let listener = UnixListener::bind(&socket_path)
        .expect("cli_server: failed to bind socket");
    tracing::info!(socket = ?socket_path, "cli_server: listening");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("cli_server: cancelled");
                break;
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, _addr)) => {
                        let tx = processor_tx.clone();
                        let c = cancel.clone();
                        tokio::spawn(handle_connection(stream, tx, c));
                    }
                    Err(e) => {
                        // accept() errors on Linux are transient (EAGAIN etc.)
                        tracing::debug!(err = %e, "cli_server: accept error");
                    }
                }
            }
        }
    }
}
```

Each connection is handled in a separate spawned task so one slow client does not block others.

### Connection handler

Protocol: newline-delimited JSON. One request per connection (alpha simplicity). No persistent connections.

```rust
async fn handle_connection(stream: UnixStream, processor_tx, cancel) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    tokio::select! {
        _ = cancel.cancelled() => return,
        result = reader.read_line(&mut line) => {
            if result.unwrap_or(0) == 0 { return; }
        }
    }

    let response = match serde_json::from_str::<CliRequest>(line.trim()) {
        Ok(req) => dispatch(req, &processor_tx).await,
        Err(e) => CliResponse::Error {
            message: format!("bad request: {e}"),
        },
    };

    let mut json = serde_json::to_string(&response).expect("response serialize");
    json.push('\n');
    let _ = write_half.write_all(json.as_bytes()).await;
}
```

---

## Part 2: JSON wire types

These types are `serde::Serialize + serde::Deserialize`. They live in `cli_server/mod.rs` (server side) and are duplicated / mirrored in `cli/mod.rs` (client side). Both crates are within the same Rust crate (`syncback`), so they can share a module. Put shared types in `cli_server/mod.rs` and re-export from `cli/mod.rs` with `use crate::daemon::cli_server::{CliRequest, CliResponse};`.

### CliRequest

```rust
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum CliRequest {
    /// Query daemon status.
    Status,

    /// Trigger an immediate backup (equivalent to WeeklySync).
    BackupNow,

    /// Request restore of a file by path.
    RestoreFile {
        /// Path of the file to restore (as originally backed up).
        path: String,
        /// Destination path for restored file. Defaults to original path.
        dest: String,
    },

    /// List known peers with trust scores.
    Peers,

    /// Gracefully stop the daemon.
    Shutdown,
}
```

### CliResponse

```rust
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CliResponse {
    /// Generic success with a human-readable message.
    Ok {
        message: String,
    },
    /// Status reply (for Status command).
    StatusOk(StatusPayload),
    /// Peer list reply (for Peers command).
    PeersOk(PeersPayload),
    /// Request accepted, will complete asynchronously.
    Accepted {
        message: String,
    },
    /// Command failed.
    Error {
        message: String,
    },
}
```

### StatusPayload

Mirrors `daemon::StatusReply` but adds human-readable formatting fields:

```rust
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct StatusPayload {
    pub uptime_secs: u64,
    pub peer_count: usize,
    pub shards_held: usize,
    pub shards_placed: usize,
    pub budget_gb: f64,
    pub dirty_files: usize,
}
```

### PeersPayload

```rust
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PeersPayload {
    pub peers: Vec<PeerInfo>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PeerInfo {
    /// First 8 bytes of identity_pub as lowercase hex (display identifier).
    pub identity: String,
    pub trust_p: f64,
    pub trust_i: f64,
    pub trust_s: f64,
    /// Combined trust score: (kp*P + ki*I) * clamp(S, 0.1, 1.0)
    pub trust_score: f64,
    pub weeks_in_network: u32,
    pub shards_held_for_us: usize,
    pub last_seen_secs_ago: u64,
}
```

---

## Part 3: Dispatch table

Map each `CliRequest` variant to a `CliCmd` sent through `processor_tx`:

```rust
async fn dispatch(request: CliRequest, processor_tx: &mpsc::Sender<ProcessorMsg>) -> CliResponse {
    match request {
        CliRequest::Status => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let cmd = ProcessorMsg::Cli(CliCmd::Status { reply: reply_tx });
            if processor_tx.send(cmd).await.is_err() {
                return CliResponse::Error { message: "daemon not responding".into() };
            }
            match reply_rx.await {
                Ok(reply) => CliResponse::StatusOk(StatusPayload {
                    uptime_secs: reply.uptime_secs,
                    peer_count: reply.peer_count,
                    shards_held: reply.shards_held,
                    shards_placed: reply.shards_placed,
                    budget_gb: reply.budget_gb,
                    dirty_files: reply.dirty_files,
                }),
                Err(_) => CliResponse::Error { message: "processor dropped reply".into() },
            }
        }

        CliRequest::BackupNow => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let cmd = ProcessorMsg::Cli(CliCmd::BackupNow { reply: reply_tx });
            if processor_tx.send(cmd).await.is_err() {
                return CliResponse::Error { message: "daemon not responding".into() };
            }
            match reply_rx.await {
                Ok(Ok(())) => CliResponse::Ok { message: "backup triggered".into() },
                Ok(Err(e)) => CliResponse::Error { message: e },
                Err(_) => CliResponse::Error { message: "processor dropped reply".into() },
            }
        }

        CliRequest::RestoreFile { path, dest } => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let cmd = ProcessorMsg::Cli(CliCmd::RestoreFile {
                path: std::path::PathBuf::from(&path),
                dest: std::path::PathBuf::from(&dest),
                reply: reply_tx,
            });
            if processor_tx.send(cmd).await.is_err() {
                return CliResponse::Error { message: "daemon not responding".into() };
            }
            match reply_rx.await {
                Ok(Ok(())) => CliResponse::Ok { message: format!("restore started: {path} -> {dest}") },
                Ok(Err(e)) => CliResponse::Error { message: e },
                Err(_) => CliResponse::Error { message: "processor dropped reply".into() },
            }
        }

        CliRequest::Peers => {
            // DECISION NEEDED: Processor currently has no CliCmd::Peers variant.
            // The implementer must add CliCmd::Peers to daemon/mod.rs and handle
            // it in processor::run. See "Processor extension" section below.
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let cmd = ProcessorMsg::Cli(CliCmd::Peers { reply: reply_tx });
            if processor_tx.send(cmd).await.is_err() {
                return CliResponse::Error { message: "daemon not responding".into() };
            }
            match reply_rx.await {
                Ok(peers) => CliResponse::PeersOk(PeersPayload { peers }),
                Err(_) => CliResponse::Error { message: "processor dropped reply".into() },
            }
        }

        CliRequest::Shutdown => {
            let _ = processor_tx.send(ProcessorMsg::Cli(CliCmd::Shutdown)).await;
            CliResponse::Ok { message: "shutdown requested".into() }
        }
    }
}
```

---

## Part 4: Processor extension — CliCmd::Peers

The current `CliCmd` enum in `daemon/mod.rs` has `Status`, `BackupNow`, `RestoreFile`, `Shutdown`. The `Peers` command is not yet there.

The implementer must add to `daemon/mod.rs`:

```rust
// In CliCmd enum:
Peers {
    reply: tokio::sync::oneshot::Sender<Vec<crate::daemon::cli_server::PeerInfo>>,
},
```

And in `processor/mod.rs`, handle it:

```rust
CliCmd::Peers { reply } => {
    let peers = self.db.list_peers()
        .expect("db read peers")
        .into_iter()
        .map(|rec| {
            let trust_score = self.trust_engine
                .score(&rec.identity)
                .map(|s| s.combined())
                .unwrap_or(0.0);
            let shards_held = self.db.count_stored_shards_for_holder(&rec.identity)
                .unwrap_or(0);
            let now = syncback_core::types::Timestamp::now();
            let last_seen_secs_ago = rec.last_seen.secs_elapsed(now);
            crate::daemon::cli_server::PeerInfo {
                identity: hex::encode(&rec.identity.0[..8]),
                trust_p: rec.trust_p,
                trust_i: rec.trust_i,
                trust_s: rec.trust_s,
                trust_score,
                weeks_in_network: rec.weeks_in_network,
                shards_held_for_us: shards_held,
                last_seen_secs_ago,
            }
        })
        .collect();
    let _ = reply.send(peers);
}
```

Note: `db.list_peers()` and `db.count_stored_shards_for_holder()` may need to be added to `Db` if they do not exist. Check `db/mod.rs` — if `list_peers()` is absent, add it as:

```rust
pub fn list_peers(&self) -> Result<Vec<PeerRecord>, DbError> {
    let rtx = self.db.begin_read()?;
    let table = rtx.open_table(PEERS)?;
    let mut result = Vec::new();
    for entry in table.iter()? {
        let (_k, v) = entry?;
        let rec: PeerRecord = from_cbor_bytes(v.value())?;
        result.push(rec);
    }
    Ok(result)
}
```

`count_stored_shards_for_holder` counts shards in the `shards` table where `holder_id == identity` and `status == ShardStatus::Stored`. If absent, add it.

---

## Part 5: CLI Client

### Location

`crates/syncback/src/cli/mod.rs` and `crates/syncback/src/cli/init.rs`

### Clap CLI struct

```rust
// cli/mod.rs
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "syncback", about = "Decentralized P2P cold backup")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize ~/.syncback/ (generate seed phrase, derive keys)
    Init,
    /// Start the daemon (runs in foreground; use systemd for background)
    Daemon,
    /// Show daemon status
    Status,
    /// Trigger an immediate backup
    Backup,
    /// Request restore of a file
    Restore {
        /// Path of the file to restore (as backed up)
        path: String,
        /// Destination path (default: original path)
        #[arg(short, long)]
        dest: Option<String>,
    },
    /// List known peers with trust scores
    Peers,
    /// Gracefully stop the running daemon
    Stop,
}
```

### main.rs update

Replace the current hand-rolled argument parsing in `main.rs` with clap:

```rust
// main.rs
mod daemon;
mod cli;

use clap::Parser;
use cli::{Cli, Commands};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing();

    match cli.command {
        Commands::Daemon => run_daemon(),
        Commands::Init   => cli::init::run_init(),
        Commands::Status => cli::run_status(),
        Commands::Backup => cli::run_backup(),
        Commands::Restore { path, dest } => cli::run_restore(path, dest),
        Commands::Peers  => cli::run_peers(),
        Commands::Stop   => cli::run_stop(),
    }
}
```

### Socket client helper

All client subcommands share this helper:

```rust
// cli/mod.rs

use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;

fn default_socket_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").expect("HOME env var not set");
    std::path::PathBuf::from(home).join(".syncback").join("syncback.sock")
}

/// Send a CliRequest to the daemon, return the CliResponse.
/// Prints an error and exits with code 1 if the daemon is not running.
pub fn send_request(request: &crate::daemon::cli_server::CliRequest) -> anyhow::Result<crate::daemon::cli_server::CliResponse> {
    let socket_path = default_socket_path();
    let stream = UnixStream::connect(&socket_path)
        .map_err(|e| anyhow::anyhow!("cannot connect to daemon at {:?}: {}", socket_path, e))?;

    let mut writer = std::io::BufWriter::new(&stream);
    let mut reader = std::io::BufReader::new(&stream);

    let json = serde_json::to_string(request)?;
    writeln!(writer, "{json}")?;
    writer.flush()?;

    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response: crate::daemon::cli_server::CliResponse = serde_json::from_str(line.trim())?;
    Ok(response)
}
```

Note: The CLI client uses **synchronous** `std::os::unix::net::UnixStream` (no tokio), because the client does not need an async runtime — it sends one request and exits. This avoids spinning up tokio just for a status check.

### Client subcommand implementations

```rust
// cli/mod.rs

pub mod init;

pub fn run_status() -> anyhow::Result<()> {
    let response = send_request(&CliRequest::Status)?;
    match response {
        CliResponse::StatusOk(s) => {
            println!("uptime:        {}s", s.uptime_secs);
            println!("peers:         {}", s.peer_count);
            println!("shards held:   {}", s.shards_held);
            println!("shards placed: {}", s.shards_placed);
            println!("budget:        {:.1} GB", s.budget_gb);
            println!("dirty files:   {}", s.dirty_files);
        }
        CliResponse::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => {
            eprintln!("unexpected response: {:?}", other);
            std::process::exit(1);
        }
    }
    Ok(())
}

pub fn run_backup() -> anyhow::Result<()> {
    let response = send_request(&CliRequest::BackupNow)?;
    match response {
        CliResponse::Ok { message } => println!("{message}"),
        CliResponse::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => eprintln!("unexpected response: {:?}", other),
    }
    Ok(())
}

pub fn run_restore(path: String, dest: Option<String>) -> anyhow::Result<()> {
    let dest = dest.unwrap_or_else(|| path.clone());
    let response = send_request(&CliRequest::RestoreFile {
        path: path.clone(),
        dest: dest.clone(),
    })?;
    match response {
        CliResponse::Ok { message } => println!("{message}"),
        CliResponse::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => eprintln!("unexpected response: {:?}", other),
    }
    Ok(())
}

pub fn run_peers() -> anyhow::Result<()> {
    let response = send_request(&CliRequest::Peers)?;
    match response {
        CliResponse::PeersOk(payload) => {
            if payload.peers.is_empty() {
                println!("no known peers");
            } else {
                println!("{:<18} {:>6} {:>6} {:>6} {:>7} {:>8} {:>12}",
                    "identity", "P", "I", "S", "trust", "weeks", "shards_held");
                for p in &payload.peers {
                    println!("{:<18} {:>6.3} {:>6.3} {:>6.3} {:>7.3} {:>8} {:>12}",
                        p.identity, p.trust_p, p.trust_i, p.trust_s,
                        p.trust_score, p.weeks_in_network, p.shards_held_for_us);
                }
            }
        }
        CliResponse::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => eprintln!("unexpected response: {:?}", other),
    }
    Ok(())
}

pub fn run_stop() -> anyhow::Result<()> {
    let response = send_request(&CliRequest::Shutdown)?;
    match response {
        CliResponse::Ok { message } => println!("{message}"),
        CliResponse::Error { message } => eprintln!("error: {message}"),
        other => eprintln!("unexpected response: {:?}", other),
    }
    Ok(())
}
```

---

## Part 6: Init flow

### Location

`crates/syncback/src/cli/init.rs`

### Business rules (from ADR-003 §"Инициализация" and CLAUDE.md)

1. Generate BIP39 mnemonic (24 words) from secure random source.
2. Display the mnemonic to the user with a clear warning.
3. Confirm: ask the user to enter 3 specific words by position (chosen randomly). If wrong — abort with clear error.
4. Derive keys via HKDF-SHA256:
   - `HKDF-SHA256(seed_bytes, salt="", info="syncback-identity-ed25519")` → 32 bytes → Ed25519 identity keypair
   - `HKDF-SHA256(seed_bytes, salt="", info="syncback-iroh-ed25519")` → 32 bytes → iroh keypair (stored for reference)
5. Create `~/.syncback/` directory (if not exists, fail if exists and is non-empty — protect against double-init).
6. Write `~/.syncback/identity.key` — CBOR-encoded `IdentityKeyFile` struct, permissions 0600.
7. Write `~/.syncback/config.toml` — default config template.
8. Print instructions: "Start the daemon with: syncback daemon".

### Key file format

```rust
// cli/init.rs

/// Written to ~/.syncback/identity.key.
/// CBOR-encoded. Permissions 0600.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct IdentityKeyFile {
    /// Version tag for future migration.
    pub version: u8,
    /// BIP39 mnemonic (24 words, space-separated). Stored for recovery UX.
    /// NOTE: This IS the secret. File must be 0600. Do not log.
    pub mnemonic_words: Vec<String>,
    /// Derived Ed25519 identity private key bytes (32 bytes seed).
    pub identity_priv: [u8; 32],
    /// Derived Ed25519 identity public key bytes (32 bytes).
    pub identity_pub: [u8; 32],
    /// Derived iroh private key bytes (32 bytes seed). Stored so daemon
    /// can reconstruct without HKDF on each restart.
    pub iroh_priv: [u8; 32],
}
```

### Public API

```rust
// cli/init.rs

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("~/.syncback/ already exists and is non-empty; delete it first to re-initialize")]
    AlreadyInitialized,

    #[error("confirmation failed: word at position {position} should be '{expected}', got '{got}'")]
    ConfirmationFailed {
        position: usize,
        expected: String,
        got: String,
    },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cbor serialization: {0}")]
    Cbor(String),
}

/// Run the interactive init flow.
/// Reads from stdin, writes to stdout/stderr.
/// Returns Ok(()) on success.
pub fn run_init() -> anyhow::Result<()>;

/// Non-interactive init for testing: takes mnemonic words, no prompts.
/// Creates the directory structure and writes key file.
/// Used by integration tests that need a known identity.
pub fn init_with_mnemonic(
    syncback_dir: &std::path::Path,
    mnemonic_words: &[&str],
) -> Result<IdentityKeyFile, InitError>;

/// Derive keys from a 64-byte BIP39 seed.
/// Returns (identity_signing_key, iroh_priv_bytes).
pub fn derive_keys(seed_bytes: &[u8; 64]) -> (ed25519_dalek::SigningKey, [u8; 32]);

/// Read the identity key file from disk.
/// Called by daemon startup to load the actual identity key.
pub fn load_identity(syncback_dir: &std::path::Path) -> Result<IdentityKeyFile, InitError>;
```

### run_init implementation outline

```rust
pub fn run_init() -> anyhow::Result<()> {
    use bip39::Mnemonic;
    use rand::RngCore;

    let syncback_dir = {
        let home = std::env::var("HOME")?;
        std::path::PathBuf::from(home).join(".syncback")
    };

    // Guard: don't clobber existing init
    if syncback_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(&syncback_dir)?.collect();
        if !entries.is_empty() {
            return Err(InitError::AlreadyInitialized.into());
        }
    }

    // Step 1: Generate mnemonic
    let mut entropy = [0u8; 32];  // 256 bits = 24 words
    rand::thread_rng().fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy)?;
    let words: Vec<&str> = mnemonic.word_iter().collect();

    // Step 2: Display
    println!("\n=== SYNCBACK INIT ===\n");
    println!("Write down these 24 words on paper. This is the ONLY way to recover your data.\n");
    for (i, word) in words.iter().enumerate() {
        print!("{:2}. {:12}", i + 1, word);
        if (i + 1) % 4 == 0 { println!(); }
    }
    println!("\n");

    // Step 3: Confirm 3 random words
    let mut rng = rand::thread_rng();
    let mut positions = [0usize; 3];
    // Pick 3 distinct positions
    let mut chosen = std::collections::HashSet::new();
    while chosen.len() < 3 {
        chosen.insert(rng.next_u32() as usize % 24);
    }
    for (i, &pos) in chosen.iter().enumerate() {
        positions[i] = pos;
    }
    positions.sort_unstable();

    println!("Confirm your seed phrase by entering the requested words:\n");
    for &pos in &positions {
        print!("Word #{}: ", pos + 1);
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();
        let expected = words[pos];
        if input != expected {
            return Err(InitError::ConfirmationFailed {
                position: pos + 1,
                expected: expected.to_string(),
                got: input,
            }.into());
        }
    }

    // Steps 4-8: delegate to non-interactive helper
    let words_owned: Vec<&str> = words.clone();
    let key_file = init_with_mnemonic(&syncback_dir, &words_owned)?;

    println!("\nInitialized ~/.syncback/");
    println!("Identity: {}", hex::encode(&key_file.identity_pub[..8]));
    println!("\nRun the daemon with: syncback daemon");
    println!("(Or: systemctl --user start syncback)\n");

    Ok(())
}
```

### init_with_mnemonic implementation

```rust
pub fn init_with_mnemonic(
    syncback_dir: &std::path::Path,
    mnemonic_words: &[&str],
) -> Result<IdentityKeyFile, InitError> {
    use bip39::Mnemonic;
    use std::os::unix::fs::PermissionsExt;

    // Parse mnemonic and derive 64-byte seed
    let phrase = mnemonic_words.join(" ");
    let mnemonic = Mnemonic::parse(&phrase)
        .map_err(|e| InitError::Cbor(e.to_string()))?;
    // BIP39: seed = PBKDF2(mnemonic, "mnemonic" + passphrase, 2048, 64)
    // bip39 crate provides: mnemonic.to_seed(passphrase) -> [u8; 64]
    let seed_bytes = mnemonic.to_seed("");  // empty passphrase

    let (signing_key, iroh_priv) = derive_keys(&seed_bytes);

    let identity_priv: [u8; 32] = signing_key.to_bytes();
    let identity_pub: [u8; 32] = signing_key.verifying_key().to_bytes();

    let key_file = IdentityKeyFile {
        version: 1,
        mnemonic_words: mnemonic_words.iter().map(|s| s.to_string()).collect(),
        identity_priv,
        identity_pub,
        iroh_priv,
    };

    // Create directory
    std::fs::create_dir_all(syncback_dir)?;

    // Write identity.key (0600)
    let key_path = syncback_dir.join("identity.key");
    let cbor = {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&key_file, &mut buf)
            .map_err(|e| InitError::Cbor(e.to_string()))?;
        buf
    };
    std::fs::write(&key_path, &cbor)?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;

    // Write default config.toml
    let config_path = syncback_dir.join("config.toml");
    std::fs::write(&config_path, DEFAULT_CONFIG_TOML)?;

    Ok(key_file)
}
```

### Default config template

```rust
// cli/init.rs

const DEFAULT_CONFIG_TOML: &str = r#"[backup]
include = [
  # { path = "~/Documents", importance = 1.0 },
  # { path = "~/Photos",    importance = 0.5 },
]
exclude = ["*.tmp", "node_modules", ".git"]

[storage]
quota_gb = 100

[network]
seed_nodes = []          # default: hardcoded in binary
bandwidth_limit_mbps = 0 # 0 = unlimited

[schedule]
sync   = "weekly"
vacuum = "monthly"
"#;
```

### derive_keys implementation

```rust
pub fn derive_keys(seed_bytes: &[u8; 64]) -> (ed25519_dalek::SigningKey, [u8; 32]) {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use ed25519_dalek::SigningKey;

    let hkdf = Hkdf::<Sha256>::new(None, seed_bytes);

    let mut identity_bytes = [0u8; 32];
    hkdf.expand(b"syncback-identity-ed25519", &mut identity_bytes)
        .expect("hkdf expand identity");

    let mut iroh_bytes = [0u8; 32];
    hkdf.expand(b"syncback-iroh-ed25519", &mut iroh_bytes)
        .expect("hkdf expand iroh");

    let signing_key = SigningKey::from_bytes(&identity_bytes);
    (signing_key, iroh_bytes)
}
```

### load_identity implementation

```rust
pub fn load_identity(syncback_dir: &std::path::Path) -> Result<IdentityKeyFile, InitError> {
    let key_path = syncback_dir.join("identity.key");
    let bytes = std::fs::read(&key_path)?;
    let key_file: IdentityKeyFile = ciborium::de::from_reader(bytes.as_slice())
        .map_err(|e| InitError::Cbor(e.to_string()))?;
    Ok(key_file)
}
```

---

## Part 7: Daemon startup — load identity from disk

`DaemonHandle::start()` currently generates random ephemeral keys (Phase 2 stub). In Phase 3 this must load from `identity.key`:

```rust
// In daemon/mod.rs DaemonHandle::start():

let key_file = crate::cli::init::load_identity(&syncback_dir)
    .expect("fatal: cannot load identity.key — run 'syncback init' first");

let identity_signing_key = ed25519_dalek::SigningKey::from_bytes(&key_file.identity_priv);
let iroh_secret_key = iroh::SecretKey::from_bytes(&key_file.iroh_priv);
let identity_pub_bytes: [u8; 32] = key_file.identity_pub;
let identity_pub = syncback_core::types::IdentityPub(identity_pub_bytes);
```

The Phase 2 random key generation block must be replaced with the above. The `net_identity_key` copy (for NetworkTask) is derived from `key_file.identity_priv` the same way as before.

---

## Part 8: Config loading

`Config::load()` currently returns `Config::default()` (stub). In Phase 3 this must parse `config.toml`. Add `toml = "0.8"` to `crates/syncback/Cargo.toml`.

### Config file format

Matches ADR-003 `config.toml` example. The `Config::load()` method reads and parses:

```rust
// daemon/mod.rs

impl Config {
    pub fn load(syncback_dir: PathBuf) -> anyhow::Result<Self> {
        let config_path = syncback_dir.join("config.toml");
        let text = std::fs::read_to_string(&config_path)
            .map_err(|e| anyhow::anyhow!("cannot read config.toml: {e}"))?;
        let file: ConfigFile = toml::from_str(&text)?;
        Ok(Config::from_file(file, syncback_dir))
    }
}

/// TOML-deserialized config file structure.
#[derive(serde::Deserialize)]
struct ConfigFile {
    backup: BackupSection,
    storage: StorageSection,
    network: NetworkSection,
    schedule: ScheduleSection,
}
```

The full deserialization details (inner struct mapping) are straightforward — one field per config key. The implementer fills these in.

---

## DB operations

The CLI module adds no new tables. It reads from:

- `peers` table — `list_peers()` for the `Peers` command
- `shards` table — `count_stored_shards_for_holder()` for the `Peers` command (owner's shards stored by a given peer)

If these methods are absent from `db/mod.rs`, add them:

```rust
/// List all known peers.
pub fn list_peers(&self) -> Result<Vec<PeerRecord>, DbError>;

/// Count shards in the `shards` table where holder_id == peer and status == Stored.
/// Used by CLI "peers" command.
pub fn count_stored_shards_for_holder(
    &self,
    peer: &IdentityPub,
) -> Result<usize, DbError>;
```

These are read-only operations — they run in a `ReadTransaction`.

---

## Test scenarios

Tests go in `crates/syncback/src/daemon/cli_server/tests.rs`.

All tests are async (`#[tokio::test]`). No integration tests with real iroh needed here — the CLI server is pure Unix socket I/O.

### Test helpers

```rust
// cli_server/tests.rs

async fn spawn_test_server() -> (
    tokio::task::JoinHandle<()>,
    tokio_util::sync::CancellationToken,
    tokio::sync::mpsc::Receiver<crate::daemon::ProcessorMsg>,
    std::path::PathBuf,
) {
    let dir = tempfile::TempDir::new().unwrap();
    let socket_path = dir.path().join("test.sock");
    let cancel = CancellationToken::new();
    let (processor_tx, processor_rx) = tokio::sync::mpsc::channel(16);
    let handle = tokio::spawn(super::run(
        cancel.clone(),
        processor_tx,
        socket_path.clone(),
    ));
    // Give the task time to bind
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    (handle, cancel, processor_rx, socket_path)
}

fn send_cli_request(socket_path: &std::path::Path, req: &CliRequest) -> CliResponse {
    use std::io::{BufRead, Write};
    let stream = std::os::unix::net::UnixStream::connect(socket_path).unwrap();
    let mut writer = std::io::BufWriter::new(&stream);
    let mut reader = std::io::BufReader::new(&stream);
    writeln!(writer, "{}", serde_json::to_string(req).unwrap()).unwrap();
    writer.flush().unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(line.trim()).unwrap()
}
```

### Test 1: status_returns_status_payload_when_processor_responds

```
Input:  CliRequest::Status
Setup:  spawn test server, have processor_rx mock respond with StatusReply {
          uptime_secs: 42, peer_count: 3, shards_held: 100,
          shards_placed: 500, budget_gb: 12.5, dirty_files: 2
        }
Expected: CliResponse::StatusOk(StatusPayload { uptime_secs: 42, peer_count: 3, ... })
```

```rust
#[tokio::test]
async fn status_returns_status_payload_when_processor_responds() {
    let (handle, cancel, mut rx, socket_path) = spawn_test_server().await;

    // Simulate processor responding to Status command
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let ProcessorMsg::Cli(CliCmd::Status { reply }) = msg {
                let _ = reply.send(StatusReply {
                    uptime_secs: 42,
                    peer_count: 3,
                    shards_held: 100,
                    shards_placed: 500,
                    budget_gb: 12.5,
                    dirty_files: 2,
                });
            }
        }
    });

    let response = tokio::task::spawn_blocking({
        let p = socket_path.clone();
        move || send_cli_request(&p, &CliRequest::Status)
    }).await.unwrap();

    match response {
        CliResponse::StatusOk(s) => {
            assert_eq!(s.uptime_secs, 42);
            assert_eq!(s.peer_count, 3);
            assert_eq!(s.shards_held, 100);
        }
        other => panic!("unexpected: {:?}", other),
    }

    cancel.cancel();
    let _ = handle.await;
}
```

### Test 2: bad_json_returns_error_response

```
Input:  raw string "not valid json\n"
Expected: CliResponse::Error { message contains "bad request" }
```

```rust
#[tokio::test]
async fn bad_json_returns_error_response() {
    let (handle, cancel, _rx, socket_path) = spawn_test_server().await;

    let response = tokio::task::spawn_blocking({
        let p = socket_path.clone();
        move || {
            use std::io::{BufRead, Write};
            let stream = std::os::unix::net::UnixStream::connect(&p).unwrap();
            let mut writer = std::io::BufWriter::new(&stream);
            let mut reader = std::io::BufReader::new(&stream);
            writeln!(writer, "not valid json").unwrap();
            writer.flush().unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            serde_json::from_str::<CliResponse>(line.trim()).unwrap()
        }
    }).await.unwrap();

    match response {
        CliResponse::Error { message } => {
            assert!(message.contains("bad request"), "got: {message}");
        }
        other => panic!("unexpected: {:?}", other),
    }

    cancel.cancel();
    let _ = handle.await;
}
```

### Test 3: shutdown_sends_cli_cmd_shutdown_to_processor

```
Input:  CliRequest::Shutdown
Expected:
  - processor_rx receives ProcessorMsg::Cli(CliCmd::Shutdown)
  - Response is CliResponse::Ok
```

### Test 4: backup_now_relays_backup_cmd_and_returns_ok

```
Input:  CliRequest::BackupNow
Setup:  processor mock replies Ok(())
Expected: CliResponse::Ok { message: "backup triggered" }
```

### Test 5: multiple_concurrent_connections_handled_independently

```
Setup:  spawn test server, send 5 simultaneous Status requests
Expected: all 5 receive CliResponse::StatusOk (or Error if processor dropped)
No deadlock, no panic.
```

### Test 6: server_stops_when_cancelled

```
Setup:  spawn server, cancel immediately
Expected: tokio handle completes without panic within 100ms
```

```rust
#[tokio::test]
async fn server_stops_when_cancelled() {
    let (handle, cancel, _rx, _socket_path) = spawn_test_server().await;
    cancel.cancel();
    tokio::time::timeout(
        std::time::Duration::from_millis(200),
        handle
    ).await
    .expect("server did not stop within timeout")
    .expect("server panicked");
}
```

### Test 7 (init): derive_keys_is_deterministic

```
Input:  same seed_bytes twice
Expected: both calls produce identical identity_priv, identity_pub, iroh_priv
```

```rust
#[test]
fn derive_keys_is_deterministic() {
    let seed = [42u8; 64];
    let (key1, iroh1) = derive_keys(&seed);
    let (key2, iroh2) = derive_keys(&seed);
    assert_eq!(key1.to_bytes(), key2.to_bytes());
    assert_eq!(iroh1, iroh2);
}
```

### Test 8 (init): init_with_mnemonic_creates_files_with_correct_permissions

```
Setup:  temp dir, known 24-word mnemonic
Expected:
  - identity.key exists, permissions == 0600
  - config.toml exists
  - load_identity() returns IdentityKeyFile with matching identity_pub
```

```rust
#[test]
fn init_with_mnemonic_creates_files_with_correct_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::TempDir::new().unwrap();
    let words: Vec<&str> = "witch collapse practice feed shame open despair creek road again ice least"
        .split_whitespace()
        // Extend to 24 words for a valid BIP39 mnemonic (use a known valid one):
        // Actually use a real 24-word mnemonic here.
        .collect();
    // Use a known valid 24-word BIP39 mnemonic:
    let mnemonic_24 = vec![
        "witch","collapse","practice","feed","shame","open",
        "despair","creek","road","again","ice","least",
        "special","clog","spider","october","pony","slab",
        "nominee","supreme","diamond","moment","slim","glow",
    ];
    let key_file = init_with_mnemonic(dir.path(), &mnemonic_24).unwrap();

    let key_path = dir.path().join("identity.key");
    assert!(key_path.exists());
    let perms = std::fs::metadata(&key_path).unwrap().permissions();
    assert_eq!(perms.mode() & 0o777, 0o600);

    let config_path = dir.path().join("config.toml");
    assert!(config_path.exists());

    let loaded = load_identity(dir.path()).unwrap();
    assert_eq!(loaded.identity_pub, key_file.identity_pub);
    assert_eq!(loaded.identity_priv, key_file.identity_priv);
}
```

### Test 9 (init): init_with_mnemonic_fails_if_dir_non_empty

```
Setup:  create dir with an existing file inside
Expected: InitError::AlreadyInitialized
```

### Test 10 (init): load_identity_fails_if_key_file_absent

```
Setup:  empty temp dir
Expected: InitError::Io (file not found)
```

---

## Cargo.toml additions

Add to `crates/syncback/Cargo.toml` `[dependencies]`:

```toml
serde_json = "1"
bip39 = "2"
clap = { version = "4", features = ["derive"] }
toml = "0.8"
hex = "0.4"
```

Add `ciborium` (needed in `cli/init.rs` for CBOR serialization of `IdentityKeyFile`). It is already in the workspace but only in `syncback-core/Cargo.toml`. Add it to `syncback/Cargo.toml`:

```toml
ciborium = { workspace = true }
```

Confirm `ciborium` is in `[workspace.dependencies]` in root `Cargo.toml` — it is (version 0.2).

---

## Error handling rules (from ADR-003)

| Situation | Handling |
|-----------|----------|
| Daemon not running (socket absent) | CLI client: print error to stderr, exit code 1 |
| Processor dropped reply channel | CLI server: return `CliResponse::Error` |
| accept() error on Unix socket | Log debug, continue loop (transient EAGAIN etc.) |
| init with bad mnemonic | Return `InitError`, print to stderr |
| identity.key absent on daemon start | `expect()` with clear message: "run syncback init first" |
| DB read error in Peers handler | `expect()` — panic (alpha rule for unexpected errors) |

---

## Logging

```
INFO:  daemon started, listening on {socket}   — already in daemon/mod.rs
INFO:  cli_server: listening on {socket}
DEBUG: cli_server: request {cmd} from client
DEBUG: cli_server: response sent to client
DEBUG: cli_server: cancelled
DEBUG: init: derived identity {identity_pub_hex}
```

No logging of `identity_priv`, `iroh_priv`, or mnemonic words. Ever.

---

## Integration with existing code — checklist for implementer

1. **Rename `cli_server.rs` → `cli_server/mod.rs`** and create `cli_server/tests.rs`. The `mod cli_server;` declaration in `daemon/mod.rs` is unchanged.

2. **Add `mod cli;` in `main.rs`** and create `cli/mod.rs` + `cli/init.rs`.

3. **Update `main.rs`** to use `clap::Parser` and route to `cli::*` functions.

4. **Add `CliCmd::Peers` to `daemon/mod.rs`** enum and update the `match` in `processor/mod.rs`.

5. **Add `list_peers()` and `count_stored_shards_for_holder()` to `db/mod.rs`** if absent.

6. **Replace key generation stub in `DaemonHandle::start()`** with `load_identity()`.

7. **Implement `Config::load()`** to parse `config.toml` (currently returns defaults).

8. **Add crate dependencies** to `crates/syncback/Cargo.toml`: `serde_json`, `bip39`, `clap`, `toml`, `hex`, `ciborium`.

9. **Add `bip39` to workspace `Cargo.toml`** `[workspace.dependencies]` if not present.

---

## Module file structure summary

```
crates/syncback/src/
  main.rs                            — clap parse, route to cli::* or run_daemon()
  cli/
    mod.rs                           — Cli, Commands, send_request, run_status/backup/restore/peers/stop
    init.rs                          — run_init, init_with_mnemonic, derive_keys, load_identity, IdentityKeyFile
  daemon/
    mod.rs                           — adds CliCmd::Peers, keeps everything else
    cli_server/
      mod.rs                         — run(), handle_connection(), dispatch(), CliRequest, CliResponse, ...
      tests.rs                       — 6+ unit tests (all async #[tokio::test])
    processor/
      mod.rs                         — adds CliCmd::Peers handler
```

---

## Non-goals (out of scope for this task)

- systemd unit file generation (`syncback init --systemd`) — post-MVP
- Shell completion generation — post-MVP
- Daemon auto-start from CLI (if daemon not running, start it) — post-MVP
- TLS or authentication on the Unix socket — not needed (socket permissions guard it)
- JSON streaming / multiple requests per connection — alpha uses one request per connection
- `syncback logs` subcommand — use `journalctl` directly
- Progress bars for backup/restore — alpha prints a single line
