# Task: CLI Module (Phase 4.6)

## Overview

Implement the CLI for the syncback daemon. The CLI lives in `crates/syncback/src/cli/` and
provides five subcommands: `status`, `restore`, `device`, `files`, `versions`. It communicates
with the running daemon over a Unix domain socket.

This task covers:
1. Argument parsing (`cli/mod.rs`) — clap-based subcommand definitions
2. Wire types (`cli/types.rs`) — `CliRequest` / `CliResponse` enums sent over the socket
3. Output formatting (`cli/output.rs`) — human-readable text rendered to stdout
4. Tests (`cli/tests.rs`) — argument parsing and output formatting
5. `main.rs` update — wire clap into the binary entry point
6. `daemon/cli_server/mod.rs` — Unix socket server task (daemon side)
7. `daemon/cli_server/tests.rs` — server tests

The daemon communication is one-shot per invocation: connect, send CBOR-encoded `CliRequest`,
read CBOR-encoded `CliResponse`, disconnect. The daemon assembles responses from its in-memory
state and DB. This task implements the full round-trip; daemon handler methods are stubs that
return mock/empty data (wired to real data in Phase 5).

---

## File Layout

```
crates/syncback/src/
  main.rs                         — updated: parse args via cli::Cli, route or start daemon
  cli/
    mod.rs                        — clap Cli struct + run_subcommand dispatch + connect helpers
    types.rs                      — CliRequest, CliResponse enums (CBOR wire types)
    output.rs                     — format_* functions, render to stdout
    tests.rs                      — all unit tests
  daemon/
    cli_server/
      mod.rs                      — Unix socket server tokio task
      tests.rs                    — server unit tests
    mod.rs                        — add `pub mod cli_server;`
```

---

## Dependencies

### Add to `crates/syncback/Cargo.toml`

```toml
clap = { workspace = true }
```

### Add to workspace `Cargo.toml`

```toml
clap = { version = "4", features = ["derive"] }
```

`ciborium` (CBOR) and `serde` are already in `syncback/Cargo.toml`. No other new deps.

---

## Part 1: Wire Types (`cli/types.rs`)

### `CliRequest`

```rust
/// Request sent from CLI process to daemon over Unix socket.
/// Encoded as CBOR with u32 BE length prefix.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CliRequest {
    Status,
    Restore {
        path: String,
        /// Version index (1-based). None = latest.
        version: Option<u32>,
        /// ISO-8601 date string, e.g. "2026-01-15". None = latest.
        date: Option<String>,
        /// Destination path override. None = restore in place.
        dest: Option<String>,
    },
    DeviceList,
    DeviceAdd {
        /// Human-readable label for the new device.
        label: String,
    },
    DeviceRevoke {
        /// Hex-encoded DeviceId (16 bytes = 32 hex chars).
        device_id_hex: String,
    },
    Files {
        /// Optional path prefix filter. None = list all.
        path_prefix: Option<String>,
    },
    Versions {
        path: String,
    },
}
```

### `CliResponse`

```rust
/// Response from daemon to CLI process.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CliResponse {
    Status(StatusData),
    Restore(RestoreData),
    DeviceList(Vec<DeviceEntry>),
    DeviceAdded(DeviceEntry),
    DeviceRevoked { device_id_hex: String },
    Files(Vec<FileEntry>),
    Versions(Vec<VersionEntry>),
    Error(String),
}

/// Data for the `status` subcommand.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusData {
    /// This node's identity pubkey (hex, 16 chars = 8 bytes).
    pub node_identity: String,
    /// Number of known peers.
    pub peer_count: u32,
    /// Average trust score across all peers (combined score).
    pub avg_trust: f64,
    /// Total bytes we are storing for others.
    pub holding_bytes: u64,
    /// Total backed-up files (all versions counted once per path).
    pub backed_up_files: u32,
    /// Total raw bytes of all files backed up (latest version only).
    pub backed_up_bytes: u64,
    /// Number of source blocks with needs_repair == true.
    pub blocks_needing_repair: u32,
    /// Peer summaries (up to 20 entries, sorted by trust descending).
    pub peers: Vec<PeerSummary>,
    /// Effective quota in bytes. 0 = unlimited.
    pub effective_quota_bytes: u64,
    /// Bytes currently used for held symbols.
    pub used_bytes: u64,
}

/// Peer summary shown in `syncback status`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerSummary {
    /// First 8 bytes of identity pubkey, hex.
    pub identity_hex: String,
    /// Combined trust score.
    pub trust: f64,
    /// Bytes we store for this peer.
    pub bytes_we_store: u64,
    /// Bytes this peer stores for us.
    pub bytes_peer_stores: u64,
    /// ISO-8601 date of last_seen.
    pub last_seen: String,
}

/// Data returned by `syncback restore`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RestoreData {
    pub path: String,
    pub version_used: u32,
    pub content_hash_hex: String,
    /// "started" | "queued" | "error"
    pub status: String,
}

/// Device entry for `syncback device list`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceEntry {
    /// Hex-encoded DeviceId (16 bytes = 32 hex chars).
    pub device_id_hex: String,
    /// Human-readable label.
    pub label: String,
    /// True if this is the current device.
    pub is_current: bool,
    /// ISO-8601 date the device was added.
    pub added_at: String,
    /// True if revoked.
    pub revoked: bool,
}

/// File entry for `syncback files`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileEntry {
    pub path: String,
    /// Number of versions.
    pub versions: u32,
    /// Latest version's backed_up_at as ISO-8601 date, or "pending" if None.
    pub last_backed_up: String,
    /// Size in bytes of the latest version.
    pub size_bytes: u64,
    /// Whether the file is locally present on any device.
    pub local_state: String,
}

/// Version entry for `syncback versions <path>`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VersionEntry {
    /// 1-based version index (1 = oldest, N = newest).
    pub version: u32,
    /// ISO-8601 datetime.
    pub created_at: String,
    /// ISO-8601 datetime, or "pending" if backed_up_at is None.
    pub backed_up_at: String,
    /// BLAKE3 hex of content (first 16 chars shown in output).
    pub content_hash_hex: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Block ID (first 16 chars of hex).
    pub source_block_id_hex: String,
}
```

### Error type

```rust
/// Errors from CLI operations.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("daemon not running (socket not found at {path})")]
    DaemonNotRunning { path: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encode error: {0}")]
    Encode(String),

    #[error("decode error: {0}")]
    Decode(String),

    #[error("daemon returned error: {0}")]
    DaemonError(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}
```

---

## Part 2: Argument Parsing (`cli/mod.rs`)

### Clap structures

```rust
use clap::{Parser, Subcommand};

/// syncback — decentralized P2P cold backup
#[derive(Debug, Parser)]
#[command(name = "syncback", version)]
pub struct Cli {
    /// Path to config file. Default: ~/.syncback/config.toml
    #[arg(long, global = true)]
    pub config: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the syncback daemon
    Daemon,

    /// Show overall system status
    Status,

    /// Restore a file or directory from backup
    Restore {
        /// Path to restore (as stored in the backup catalog)
        path: String,

        /// Version number to restore (1-based, 1 = oldest). Default: latest.
        #[arg(long)]
        version: Option<u32>,

        /// Restore the version closest to this date (YYYY-MM-DD). Default: latest.
        #[arg(long)]
        date: Option<String>,

        /// Restore to this destination path instead of the original location.
        #[arg(long)]
        dest: Option<String>,
    },

    /// Manage cluster devices
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },

    /// List backed-up files
    Files {
        /// Filter by path prefix. Lists all files if omitted.
        path_prefix: Option<String>,
    },

    /// Show all versions of a file
    Versions {
        /// Path as stored in the backup catalog
        path: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum DeviceAction {
    /// List all devices in the cluster
    List,

    /// Add a new device (generates an invitation)
    Add {
        /// Human-readable label for the new device
        label: String,
    },

    /// Revoke a device
    Revoke {
        /// Device ID to revoke (hex string, 32 chars)
        device_id: String,
    },
}
```

### Socket path helper

```rust
/// Default Unix socket path used by daemon and CLI.
pub const DEFAULT_SOCKET_PATH: &str = "~/.syncback/syncback.sock";

/// Expand `~` in socket path to home directory.
/// Returns the raw path unchanged if `HOME` is not set.
pub fn expand_socket_path(path: &str) -> String;
```

### Dispatch function

```rust
/// Parse `CliRequest` from `Command` args, send to daemon, receive `CliResponse`,
/// format and print to stdout. Returns Err on socket/encode/decode failures.
///
/// `socket_path` is the expanded (tilde-resolved) path to the Unix socket.
pub fn run_command(cmd: &Command, socket_path: &str) -> Result<(), CliError>;
```

`run_command` is the single entry point called from `main.rs` for all non-`Daemon` subcommands.
It must:
1. Build a `CliRequest` from `cmd`.
2. Call `send_request(socket_path, &request)` to get a `CliResponse`.
3. Call the appropriate `output::format_*` function and print to stdout.

### Socket I/O helpers (private, but testable via integration)

```rust
/// Connect to daemon socket, send request, receive response.
/// Uses blocking std::os::unix::net::UnixStream (not tokio — CLI runs sync).
fn send_request(socket_path: &str, request: &CliRequest) -> Result<CliResponse, CliError>;
```

Wire format for both sides: `u32 BE length prefix || CBOR payload`.

---

## Part 3: Output Formatting (`cli/output.rs`)

All functions write to stdout via `println!`. No colors or ANSI codes (plain text only — aids
scripting and log capture).

### Function signatures

```rust
/// Format and print StatusData to stdout.
pub fn format_status(data: &StatusData);

/// Format and print RestoreData to stdout.
pub fn format_restore(data: &RestoreData);

/// Format and print a list of DeviceEntry to stdout.
pub fn format_device_list(devices: &[DeviceEntry]);

/// Format and print a newly-added DeviceEntry to stdout.
pub fn format_device_added(device: &DeviceEntry);

/// Format and print a device revocation confirmation to stdout.
pub fn format_device_revoked(device_id_hex: &str);

/// Format and print a list of FileEntry to stdout.
pub fn format_files(files: &[FileEntry]);

/// Format and print a list of VersionEntry for one path.
pub fn format_versions(path: &str, versions: &[VersionEntry]);

/// Format and print a daemon error message to stderr.
pub fn format_error(msg: &str);
```

### Output format specification

**`format_status`** — example output:

```
syncback status
  identity:       a1b2c3d4e5f60708
  peers:          12  (avg trust: 1.43)
  holding:        4.20 GB for 12 peers
  backed up:      847 files, 23.4 GB
  repair needed:  0 blocks
  quota:          unlimited  (used: 4.20 GB)

top peers:
  a1b2c3d4  trust=2.31  stores=1.20GB/0.80GB  last=2026-03-20
  e5f60708  trust=1.87  stores=0.40GB/2.10GB  last=2026-03-19
```

Rules:
- "holding" line uses `holding_bytes`, formatted as `format_bytes(bytes) + " for N peers"`.
- "backed up" uses `backed_up_files` and `format_bytes(backed_up_bytes)`.
- "quota" line: if `effective_quota_bytes == 0`, print "unlimited"; else print the quota.
- "top peers" section: print up to 20 peers from `data.peers` (daemon already sorted descending by trust).
- Each peer line: identity_hex (8 chars), trust (2 decimal places), `stores=X/Y` (we store X GB, peer stores Y GB for us), last_seen date.
- If `peer_count == 0`, skip the "top peers" section and print "  no peers yet".

**`format_restore`** — example output:

```
restore started
  path:     photos/vacation/IMG_001.jpg
  version:  3
  hash:     a1b2c3d4e5f60708...
  status:   started
```

**`format_device_list`** — example output:

```
cluster devices (2):
  [*] 0102030405060708  laptop       added 2026-01-10
      090a0b0c0d0e0f10  phone        added 2026-02-15
```

Rules:
- `[*]` marks the current device (`is_current == true`).
- Revoked devices shown with `[R]` prefix.
- Columns: marker (4 chars), device_id_hex (first 16 chars), label, added date.

**`format_device_added`** — example output:

```
device added
  id:    0102030405060708...
  label: phone
```

**`format_device_revoked`** — example output:

```
device revoked: 0102030405060708...
```

**`format_files`** — example output:

```
backed-up files (3):
  photos/vacation/IMG_001.jpg   3 versions   2026-03-20   1.4 MB   present
  documents/report.pdf          1 version    2026-03-15   245 KB   present
  videos/holiday.mp4            2 versions   2026-02-10   842 MB   deleted
```

Rules:
- Header shows total count.
- If list is empty, print "no files backed up".
- Size column uses `format_bytes`.
- `local_state` field printed as-is (daemon sends "present" or "deleted(YYYY-MM-DD)").
- "1 version" (singular) vs "N versions" (plural).

**`format_versions`** — example output:

```
versions of photos/vacation/IMG_001.jpg (3):
  v1  2026-01-10  backed 2026-01-11  a1b2c3d4...  1.4 MB  [block: ab12cd34]
  v2  2026-02-05  backed 2026-02-05  b2c3d4e5...  1.5 MB  [block: cd34ef56]
  v3  2026-03-20  backed 2026-03-20  c3d4e5f6...  1.4 MB  [block: ef5678ab]
```

Rules:
- Header shows path and total version count.
- If empty, print "no versions found for <path>".
- `backed_up_at` field: if "pending", show as "pending" instead of a date.
- content_hash_hex: show first 8 chars + "...".
- source_block_id_hex: show first 8 chars.

**`format_error`** — prints to stderr:

```
error: <msg>
```

### Private helper

```rust
/// Format bytes as human-readable: < 1 KB → "N B", < 1 MB → "N KB", < 1 GB → "N.N MB",
/// >= 1 GB → "N.NN GB".
fn format_bytes(bytes: u64) -> String;
```

Exact rules:
- `bytes < 1_024` → `"{bytes} B"`
- `bytes < 1_048_576` → `"{} KB"` (rounded, integer KB)
- `bytes < 1_073_741_824` → `"{:.1} MB"` (one decimal)
- else → `"{:.2} GB"` (two decimals)

---

## Part 4: Daemon Side (`daemon/cli_server/mod.rs`)

The CLI server is a tokio task that:
1. Binds a `UnixListener` at the socket path.
2. Accepts connections in a loop.
3. Spawns a short-lived task per connection.
4. Each connection: read `u32 BE length prefix + CBOR CliRequest`, dispatch, write `u32 BE
   length prefix + CBOR CliResponse`.

```rust
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

/// Configuration for the CLI server task.
pub struct CliServerConfig {
    /// Path to the Unix socket to bind.
    pub socket_path: String,
}

/// Handle returned by `start`. Caller awaits it to detect server failure.
pub type CliServerHandle = tokio::task::JoinHandle<()>;

/// Errors from CLI server operations.
#[derive(Debug, thiserror::Error)]
pub enum CliServerError {
    #[error("failed to bind socket at {path}: {source}")]
    Bind { path: String, source: std::io::Error },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encode error: {0}")]
    Encode(String),

    #[error("decode error: {0}")]
    Decode(String),
}

/// Start the CLI server task.
///
/// Binds the Unix socket and enters the accept loop. Returns the JoinHandle
/// immediately; the task runs until `cancel` is triggered.
///
/// If binding fails (e.g., socket already in use), the function returns Err
/// immediately (before spawning).
///
/// The task removes the socket file on shutdown (best-effort).
pub async fn start(
    config: CliServerConfig,
    cancel: CancellationToken,
) -> Result<CliServerHandle, CliServerError>;
```

### Dispatch logic

The CLI server's per-connection handler receives a `CliRequest` and returns a `CliResponse`.
In Phase 4, the handler is a **stub** that returns plausible empty/mock responses:

```rust
/// Dispatch a CliRequest and produce a CliResponse.
/// Phase 4: stub. Phase 5: wire to real daemon state.
async fn dispatch(request: CliRequest) -> CliResponse;
```

Stub responses by variant:
- `Status` → `CliResponse::Status(StatusData { peer_count: 0, avg_trust: 0.0, holding_bytes: 0, backed_up_files: 0, backed_up_bytes: 0, blocks_needing_repair: 0, peers: vec![], effective_quota_bytes: 0, used_bytes: 0, node_identity: "0000000000000000".into() })`
- `Restore { path, .. }` → `CliResponse::Restore(RestoreData { path, version_used: 1, content_hash_hex: "00".repeat(32), status: "queued".into() })`
- `DeviceList` → `CliResponse::DeviceList(vec![])`
- `DeviceAdd { label }` → `CliResponse::DeviceAdded(DeviceEntry { device_id_hex: "00".repeat(16), label, is_current: false, added_at: "2026-01-01".into(), revoked: false })`
- `DeviceRevoke { device_id_hex }` → `CliResponse::DeviceRevoked { device_id_hex }`
- `Files { .. }` → `CliResponse::Files(vec![])`
- `Versions { path }` → `CliResponse::Versions(vec![])`

---

## Part 5: `main.rs` Update

```rust
use clap::Parser;
use cli::{Cli, Command};

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Command::Daemon => {
            // Start daemon (existing stub or actual daemon start).
            println!("syncback β daemon — not yet implemented");
        }
        other => {
            let socket_path = cli
                .config
                .as_deref()
                .map(|_| cli::DEFAULT_SOCKET_PATH)
                .unwrap_or(cli::DEFAULT_SOCKET_PATH);
            let socket_path = cli::expand_socket_path(socket_path);
            if let Err(e) = cli::run_command(other, &socket_path) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
}
```

---

## Business Rules

### Version selection in `Restore`

- `--version N` and `--date DATE` are mutually exclusive. If both are provided, `run_command`
  returns `Err(CliError::InvalidArgument("cannot specify both --version and --date"))`.
- If neither is provided, restore the latest version (highest version index).
- `--version` is 1-based. Version 0 is invalid: `Err(CliError::InvalidArgument("--version must be >= 1"))`.

### Date format in `--date`

The CLI accepts any string for `--date` and passes it to the daemon. The daemon validates the
format. The CLI does no date parsing.

### `DeviceRevoke` hex validation

`device_id_hex` must be exactly 32 hex chars (16 bytes). If not, `run_command` returns
`Err(CliError::InvalidArgument("device ID must be 32 hex characters"))` before contacting
the daemon.

### Socket path expansion

`expand_socket_path` expands a leading `~/` to `$HOME/`. If `HOME` is not set, returns the
path unchanged.

### `format_bytes` thresholds

Exact integer arithmetic. No floating-point rounding beyond what `format!("{:.N}")` provides.

---

## DB Operations

This module has no direct DB access. All data is fetched from the daemon via `CliResponse`.
The daemon stub (Phase 4) returns mock data; real wiring happens in Phase 5.

---

## Test Scenarios

All tests go in `crates/syncback/src/cli/tests.rs` and
`crates/syncback/src/daemon/cli_server/tests.rs`.

### `cli/tests.rs`

#### 1. `command_status_parses_correctly`
```
Input: ["syncback", "status"]
Expected: Command::Status
```

#### 2. `command_restore_parses_path`
```
Input: ["syncback", "restore", "photos/img.jpg"]
Expected: Command::Restore { path: "photos/img.jpg", version: None, date: None, dest: None }
```

#### 3. `command_restore_parses_version_flag`
```
Input: ["syncback", "restore", "photos/img.jpg", "--version", "3"]
Expected: Command::Restore { path: "photos/img.jpg", version: Some(3), date: None, dest: None }
```

#### 4. `command_restore_parses_date_flag`
```
Input: ["syncback", "restore", "photos/img.jpg", "--date", "2026-01-15"]
Expected: Command::Restore { path: "photos/img.jpg", version: None, date: Some("2026-01-15"), dest: None }
```

#### 5. `command_restore_parses_dest_flag`
```
Input: ["syncback", "restore", "photos/img.jpg", "--dest", "/tmp/out"]
Expected: Command::Restore { dest: Some("/tmp/out"), .. }
```

#### 6. `command_files_no_prefix`
```
Input: ["syncback", "files"]
Expected: Command::Files { path_prefix: None }
```

#### 7. `command_files_with_prefix`
```
Input: ["syncback", "files", "photos/"]
Expected: Command::Files { path_prefix: Some("photos/") }
```

#### 8. `command_versions_parses_path`
```
Input: ["syncback", "versions", "documents/report.pdf"]
Expected: Command::Versions { path: "documents/report.pdf" }
```

#### 9. `command_device_list`
```
Input: ["syncback", "device", "list"]
Expected: Command::Device { action: DeviceAction::List }
```

#### 10. `command_device_add`
```
Input: ["syncback", "device", "add", "my-phone"]
Expected: Command::Device { action: DeviceAction::Add { label: "my-phone" } }
```

#### 11. `command_device_revoke`
```
Input: ["syncback", "device", "revoke", "0102030405060708090a0b0c0d0e0f10"]
Expected: Command::Device { action: DeviceAction::Revoke { device_id: "0102030405060708090a0b0c0d0e0f10" } }
```

#### 12. `run_command_restore_rejects_version_zero`
```
Command::Restore { path: "f".into(), version: Some(0), date: None, dest: None }
run_command(&cmd, "ignored_socket") → Err(CliError::InvalidArgument(_))
// Must not attempt socket connection
```

#### 13. `run_command_restore_rejects_version_and_date_both`
```
Command::Restore { path: "f".into(), version: Some(1), date: Some("2026-01-01".into()), dest: None }
→ Err(CliError::InvalidArgument(_))
```

#### 14. `run_command_device_revoke_rejects_short_hex`
```
Command::Device { action: DeviceAction::Revoke { device_id: "tooshort".into() } }
→ Err(CliError::InvalidArgument(_))
// "tooshort" is not 32 hex chars
```

#### 15. `run_command_device_revoke_rejects_non_hex`
```
device_id: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"   // 32 chars but not valid hex
→ Err(CliError::InvalidArgument(_))
```

#### 16. `run_command_fails_when_daemon_not_running`
```
// Use a socket path that does not exist
Command::Status
run_command(&cmd, "/tmp/syncback_test_nonexistent_9999.sock") → Err(CliError::DaemonNotRunning { .. })
```

#### 17. `format_bytes_under_1kb`
```
format_bytes(512) == "512 B"
format_bytes(0)   == "0 B"
format_bytes(1023) == "1023 B"
```

#### 18. `format_bytes_kilobytes`
```
format_bytes(1_024)   == "1 KB"
format_bytes(2_048)   == "2 KB"
format_bytes(10_240)  == "10 KB"
format_bytes(1_048_575) == "1023 KB"
```

#### 19. `format_bytes_megabytes`
```
format_bytes(1_048_576)   == "1.0 MB"
format_bytes(1_572_864)   == "1.5 MB"
format_bytes(10_485_760)  == "10.0 MB"
```

#### 20. `format_bytes_gigabytes`
```
format_bytes(1_073_741_824)    == "1.00 GB"
format_bytes(4_509_715_660)    == "4.20 GB"   // ≈ 4.2 GB
```

#### 21. `format_status_zero_peers_prints_no_peers_yet`
```
data = StatusData { peer_count: 0, peers: vec![], ... }
// capture stdout, assert contains "no peers yet"
// (use a String buffer approach or just check the rendered output)
```

#### 22. `format_status_top_peers_printed`
```
data = StatusData {
    peer_count: 2,
    peers: vec![
        PeerSummary { identity_hex: "a1b2c3d4e5f60708", trust: 2.31, bytes_we_store: 1_288_490_189, bytes_peer_stores: 858_993_459, last_seen: "2026-03-20".into() },
        PeerSummary { identity_hex: "e5f60708090a0b0c", trust: 1.87, bytes_we_store: 429_496_730, bytes_peer_stores: 2_254_857_830, last_seen: "2026-03-19".into() },
    ],
    ...
}
// assert rendered output contains "a1b2c3d4" and "trust=2.31"
// assert output contains "e5f607" and "trust=1.87"
```

#### 23. `format_files_empty_list`
```
format_files(&[])
// output contains "no files backed up"
```

#### 24. `format_files_single_entry_singular_version`
```
files = vec![FileEntry { path: "doc.pdf".into(), versions: 1, last_backed_up: "2026-03-20".into(), size_bytes: 250_000, local_state: "present".into() }]
format_files(&files)
// output contains "1 version" (singular) and "244 KB" (250000 / 1024 ≈ 244 KB)
// output does NOT contain "1 versions"
```

#### 25. `format_versions_empty`
```
format_versions("photos/img.jpg", &[])
// output contains "no versions found for photos/img.jpg"
```

#### 26. `format_versions_pending_backed_up`
```
entry = VersionEntry { version: 1, created_at: "2026-03-20T10:00:00".into(), backed_up_at: "pending".into(), content_hash_hex: "ab".repeat(32), size_bytes: 1_048_576, source_block_id_hex: "cd".repeat(32) }
format_versions("f", &[entry])
// output contains "pending"
// output contains "v1"
// output contains "1.0 MB"
```

#### 27. `format_device_list_marks_current`
```
devices = vec![
    DeviceEntry { device_id_hex: "01".repeat(16), label: "laptop".into(), is_current: true, added_at: "2026-01-10".into(), revoked: false },
    DeviceEntry { device_id_hex: "02".repeat(16), label: "phone".into(), is_current: false, added_at: "2026-02-15".into(), revoked: false },
]
format_device_list(&devices)
// output contains "[*]" for the first entry (current)
// output contains "laptop" and "phone"
```

#### 28. `format_device_list_marks_revoked`
```
devices = vec![DeviceEntry { revoked: true, ... }]
format_device_list(&devices)
// output contains "[R]"
```

#### 29. `cli_request_roundtrips_cbor`
```
// For each CliRequest variant, encode to CBOR and decode back, assert equality.
requests = [
    CliRequest::Status,
    CliRequest::Files { path_prefix: Some("photos/".into()) },
    CliRequest::Versions { path: "doc.pdf".into() },
    CliRequest::Restore { path: "a".into(), version: Some(2), date: None, dest: None },
    CliRequest::DeviceList,
    CliRequest::DeviceAdd { label: "phone".into() },
    CliRequest::DeviceRevoke { device_id_hex: "01".repeat(16) },
]
for req in requests:
    bytes = cbor_encode(&req)
    decoded: CliRequest = cbor_decode(&bytes)
    assert decoded == req
```

#### 30. `cli_response_roundtrips_cbor`
```
// For each CliResponse variant, encode to CBOR and decode back, assert equality.
responses = [
    CliResponse::Status(StatusData { ... }),
    CliResponse::DeviceList(vec![]),
    CliResponse::Error("oops".into()),
    ...
]
```

### `daemon/cli_server/tests.rs`

#### 31. `dispatch_status_returns_status_response`
```
request = CliRequest::Status
response = dispatch(request).await
assert matches!(response, CliResponse::Status(_))
```

#### 32. `dispatch_files_returns_files_response`
```
request = CliRequest::Files { path_prefix: None }
response = dispatch(request).await
assert matches!(response, CliResponse::Files(_))
```

#### 33. `dispatch_restore_returns_restore_response`
```
request = CliRequest::Restore { path: "f".into(), version: None, date: None, dest: None }
response = dispatch(request).await
let CliResponse::Restore(data) = response else { panic!() };
assert data.path == "f"
```

#### 34. `dispatch_device_revoke_echoes_id`
```
id = "aa".repeat(16)
request = CliRequest::DeviceRevoke { device_id_hex: id.clone() }
response = dispatch(request).await
let CliResponse::DeviceRevoked { device_id_hex } = response else { panic!() };
assert device_id_hex == id
```

#### 35. `cli_server_accepts_connection_and_responds`

Integration test: start a CLI server bound to a tempfile socket, send a `CliRequest::Status`
over a raw `UnixStream`, assert the response decodes as `CliResponse::Status`.

```
// 1. Write socket to a tmpfile path (use tempfile crate to get a temp dir, not a file)
// 2. Call start(config, cancel.clone()) — get a JoinHandle
// 3. Give the server a moment to bind (tokio::time::sleep(Duration::from_millis(10)))
// 4. Connect via std::os::unix::net::UnixStream::connect(socket_path)
// 5. Write u32 BE (cbor_len) || cbor(CliRequest::Status)
// 6. Read u32 BE (response_len), read response_len bytes
// 7. Decode as CliResponse — assert it is Status variant
// 8. Cancel the server token, await the handle
```

---

## Module Structure

```
crates/syncback/src/cli/
  mod.rs        — Cli, Command, DeviceAction (clap), run_command, send_request, expand_socket_path
  types.rs      — CliRequest, CliResponse, StatusData, PeerSummary, RestoreData, DeviceEntry,
                  FileEntry, VersionEntry, CliError
  output.rs     — format_status, format_restore, format_device_list, format_device_added,
                  format_device_revoked, format_files, format_versions, format_error, format_bytes
  tests.rs      — all 30 test scenarios for cli/

crates/syncback/src/daemon/cli_server/
  mod.rs        — CliServerConfig, CliServerError, start(), dispatch()
  tests.rs      — scenarios 31-35
```

Add to `crates/syncback/src/lib.rs`:
```rust
pub mod cli;
```

Add to `crates/syncback/src/daemon/mod.rs`:
```rust
pub mod cli_server;
```

---

## Dependencies Between Modules

- `cli/types.rs` — no deps on daemon modules; only `serde`, `ciborium`, `thiserror`
- `cli/output.rs` — depends only on `cli/types.rs`
- `cli/mod.rs` — depends on `cli/types.rs`, `cli/output.rs`
- `daemon/cli_server/mod.rs` — depends on `cli/types.rs` (shared wire format)
- `main.rs` — depends on `cli/mod.rs`

The `cli/types.rs` module is the shared contract between CLI client and daemon server.
Both sides encode/decode using `ciborium` (already in Cargo.toml).

---

## What NOT to Do

- Do not use `anyhow` in `cli/types.rs` or `cli/output.rs` or `daemon/cli_server/mod.rs`.
  Use `thiserror` for `CliError` and `CliServerError`.
- Do not add colored output or ANSI escape sequences. Plain text only.
- Do not use JSON — the wire format is CBOR (consistent with the rest of the system).
- Do not spawn threads in the CLI client. Use blocking `std::os::unix::net::UnixStream`.
- Do not call `std::process::exit` inside `run_command` — return `Result`.
- Do not add inline `#[cfg(test)]` — all tests go in the separate `tests.rs` files.
- Do not implement real daemon logic in `dispatch()` — Phase 4 stubs only.
- Do not add `tracing` calls to `cli/` — logging belongs in the daemon. `cli_server/mod.rs`
  may use `tracing::error!` for unexpected socket errors.

---

## Definition of Done

- `cargo build -p syncback` succeeds.
- `cargo test -p syncback` passes with no failures.
- `cargo clippy -p syncback -- -D warnings` clean.
- All 35 test scenarios present and passing (30 in `cli/tests.rs`, 5 in `daemon/cli_server/tests.rs`).
- `syncback --help` prints usage text.
- `syncback status --help`, `syncback restore --help`, `syncback device --help`,
  `syncback files --help`, `syncback versions --help` all print subcommand help.
- `syncback restore path --version 0` returns a non-zero exit code with an error message.
- `syncback restore path --version 1 --date 2026-01-01` returns a non-zero exit code.
- CBOR roundtrip test passes for all `CliRequest` and `CliResponse` variants.
- `format_bytes` test passes for all threshold boundaries.
- No new `anyhow` usage in `cli/` or `daemon/cli_server/`.
- No inline `#[cfg(test)]` blocks.

---

## Files to Create/Modify

1. `/home/ilya/projects/syncback/crates/syncback/src/cli/mod.rs` — new file
2. `/home/ilya/projects/syncback/crates/syncback/src/cli/types.rs` — new file
3. `/home/ilya/projects/syncback/crates/syncback/src/cli/output.rs` — new file
4. `/home/ilya/projects/syncback/crates/syncback/src/cli/tests.rs` — new file
5. `/home/ilya/projects/syncback/crates/syncback/src/daemon/cli_server/mod.rs` — new file
6. `/home/ilya/projects/syncback/crates/syncback/src/daemon/cli_server/tests.rs` — new file
7. `/home/ilya/projects/syncback/crates/syncback/src/lib.rs` — add `pub mod cli;`
8. `/home/ilya/projects/syncback/crates/syncback/src/daemon/mod.rs` — add `pub mod cli_server;`
9. `/home/ilya/projects/syncback/crates/syncback/src/main.rs` — parse Cli, route subcommands
10. `/home/ilya/projects/syncback/crates/syncback/Cargo.toml` — add `clap`
11. Workspace `Cargo.toml` — add `clap = { version = "4", features = ["derive"] }`
