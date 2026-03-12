# Task spec: watcher module (Phase 3)

**Target files:**
- `crates/syncback/src/daemon/watcher/mod.rs` (implementation)
- `crates/syncback/src/daemon/watcher/tests.rs` (unit tests)

**Phase:** 3 (replaces the stub at `crates/syncback/src/daemon/watcher.rs`)
**Role:** File system monitor — detects changes in configured directories and feeds `DirtyEvent` into the Processor

---

## Overview

The Watcher is one of the five tokio tasks. It has a single responsibility: watch the
directories listed in `BackupConfig.include`, detect file system events (create, modify,
delete, rename), debounce them, filter through include/exclude glob patterns, and send
`DirtyEvent` messages to the Processor via the existing `dirty_tx` channel.

The Watcher also runs an **initial scan** on startup: it walks all configured directories,
computes a content hash for each file, looks up its `FileRecord` in the DB, and emits a
`DirtyEvent` for every file that is either new or has changed since the last backup.

The Watcher does **not** write to the DB. All writes (marking files dirty, inserting
`FileRecord`s) happen in the Processor when it handles a `DirtyEvent`.

The Watcher does **not** trigger backup immediately. It only signals that a file has
changed. The Scheduler drives the actual weekly sync cycle.

Architecture doc quote (architecture.md — Watcher section):

> Мониторит настроенные папки (notify: inotify/FSEvents)
> Детектит изменения: new/modified/deleted
> Отправляет DirtyEvent в Processor через канал; Processor записывает в DB
> **Не запускает backup сразу.** Только сигнализирует об изменениях.

---

## Module file layout

The current stub is a single file at `crates/syncback/src/daemon/watcher.rs`. Phase 3
replaces it with a directory module:

```
crates/syncback/src/daemon/
  watcher/
    mod.rs       ← main implementation (replaces watcher.rs stub)
    tests.rs     ← unit tests
```

The `mod.rs` must also update `crates/syncback/src/daemon/mod.rs` to point at the new
directory module. The current `mod.rs` line is:

```rust
mod watcher;
```

No change needed to the import line — Rust resolves `mod watcher` to either
`watcher.rs` or `watcher/mod.rs` automatically. The implementer must **delete**
`watcher.rs` and create `watcher/mod.rs` instead.

---

## Dependencies

**External crates:**
- `notify` crate (`^6`, `RecommendedWatcher`, `RecursiveMode`, `EventKind`) — file system watching
- `notify-debouncer-mini` crate (`^0.4`, `DebouncedEvent`, `DebouncedEventKind`, `new_debouncer`) — coalesces rapid bursts of events
- `glob` crate (`^0.3`, `Pattern`) — glob pattern matching for include/exclude
- `blake3` — content hash for initial scan
- `tokio::sync::mpsc::Sender<DirtyEvent>` — output channel to Processor
- `tokio_util::sync::CancellationToken` — cooperative shutdown
- `tokio::task::spawn_blocking` — wraps the synchronous initial scan walk
- `walkdir` crate (`^2`) — recursive directory walk for initial scan

**syncback-core:**
- `syncback_core::db::Db` — read-only during initial scan (check `get_file`, compare hashes)
- `syncback_core::types::Timestamp` — `detected_at` field on events

**syncback (same crate):**
- `crate::daemon::{DirtyEvent, DirtyKind, Config, BackupConfig, IncludeEntry}`

**std:**
- `std::path::{Path, PathBuf}`
- `std::time::Duration`

---

## Public API

```rust
/// Run the watcher task. Loops until `cancel` is signalled or `dirty_tx` is closed.
///
/// Steps:
///   1. Build glob matchers from `config.backup.include` and `config.backup.exclude`
///   2. Run initial scan (blocking, spawned on blocking thread pool)
///   3. Start notify watcher on all include root directories
///   4. Process debounced events until cancelled
pub async fn run(
    cancel: CancellationToken,
    dirty_tx: mpsc::Sender<DirtyEvent>,
    db: syncback_core::db::Db,
    config: crate::daemon::Config,
)
```

The `run` function signature must match what `daemon/mod.rs` already passes. Currently
`DaemonHandle::start` calls:

```rust
tokio::spawn(watcher::run(cancel.clone(), dirty_tx.clone()));
```

The stub accepts only `(CancellationToken, mpsc::Sender<DirtyEvent>)`. Phase 3 adds
`db` and `config` parameters. The call site in `daemon/mod.rs` must be updated:

```rust
tokio::spawn(watcher::run(
    cancel.clone(),
    dirty_tx.clone(),
    db.clone(),
    config.clone(),
));
```

No other callers exist.

---

## Internal types

These are private to the watcher module — not exported.

```rust
/// A compiled include entry: path root + importance + compiled glob.
struct CompiledInclude {
    root: PathBuf,           // absolute, expanded (~ resolved)
    importance: f64,
    /// If the config entry has a glob suffix (e.g. "~/Photos/**/*.jpg"),
    /// the compiled pattern for the file portion. None = match all files under root.
    pattern: Option<glob::Pattern>,
}

/// A compiled exclude pattern.
struct CompiledExclude {
    /// The raw pattern string from config (e.g. "*.tmp", "node_modules", ".git")
    pattern: glob::Pattern,
}

/// Internal watcher state — holds compiled patterns and the notify watcher.
struct WatcherState {
    includes: Vec<CompiledInclude>,
    excludes: Vec<CompiledExclude>,
}
```

---

## DirtyEvent recap (defined in `daemon/mod.rs`)

The type already exists. The Watcher must populate all fields:

```rust
pub struct DirtyEvent {
    pub path: PathBuf,       // canonical absolute path of the changed file
    pub kind: DirtyKind,     // Created | Modified | Deleted
    pub detected_at: u64,    // Unix timestamp (seconds), from Timestamp::now().0
}

pub enum DirtyKind {
    Created,
    Modified,
    Deleted,
}
```

---

## Pattern matching rules

### Glob patterns

The `BackupConfig` has:

```rust
pub struct IncludeEntry {
    pub path: PathBuf,       // e.g. "~/Documents", "~/Photos/**"
    pub importance: f64,
}

pub struct BackupConfig {
    pub include: Vec<IncludeEntry>,
    pub exclude: Vec<String>,  // e.g. ["*.tmp", "node_modules", ".git"]
}
```

### Tilde expansion

Paths starting with `~` must be expanded to `$HOME`. Use:

```rust
fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with("~/") || s == "~" {
        let home = std::env::var("HOME").expect("HOME not set");
        PathBuf::from(home).join(s.trim_start_matches("~/"))
    } else {
        path.to_path_buf()
    }
}
```

### Include matching

A file at `abs_path` matches an include entry if:

1. `abs_path` starts with the entry's expanded root directory
2. If the entry has a glob suffix (detected by presence of `*`, `?`, or `[` in the path),
   the file portion matches the compiled `glob::Pattern`

Longest-root match wins when multiple entries match the same file. If no include entry
matches, the file is ignored.

### Exclude matching

An exclude pattern matches if any of the following is true for `abs_path`:

1. Any path component (directory name or file name) equals the exclude pattern exactly
   (e.g. `node_modules` pattern matches `/home/user/projects/node_modules/foo.js`)
2. The file name matches the glob pattern (e.g. `*.tmp` matches `file.tmp`)
3. The full absolute path matches the glob pattern

Exclude takes priority over include: if a file matches both, it is excluded.

### Importance lookup

When the Watcher sends a `DirtyEvent`, it does **not** include the importance — that is
derived by the Processor (which already has `config_importance_for_path`). The Watcher
only needs importance to decide whether to watch/scan a file at all (skip files with
resolved importance < 0.1, which means no include entry matches).

---

## Debounce strategy

Use the `notify-debouncer-mini` crate. Rationale: editors and build tools often write
files in multiple bursts (write, rename, write). Debouncing coalesces these into a
single event.

### Debounce window

`Duration::from_secs(30)` — 30 seconds. Rationale: SyncBack is a cold backup system
(time constant = 1 week). A 30-second debounce window is negligible against a 1-week
backup cadence and eliminates virtually all spurious events from editors, build tools,
and cloud sync clients.

### Debounce implementation

```rust
use notify_debouncer_mini::{new_debouncer, DebouncedEventKind};
use std::sync::mpsc as std_mpsc;  // notify uses std channels

let (std_tx, std_rx) = std_mpsc::channel();
let mut debouncer = new_debouncer(Duration::from_secs(30), std_tx)
    .expect("failed to create debouncer");
```

The `notify-debouncer-mini` crate wraps `notify` and outputs one `DebouncedEvent` per
path after the debounce window expires with no new events on that path. Each
`DebouncedEvent` has a `kind: DebouncedEventKind` (either `Any` for create/modify or
`AnyContinuous` for long-running processes). Both map to `DirtyKind::Modified` unless
we can distinguish create vs. modify from the initial scan.

### Mapping notify events to DirtyKind

From the raw `notify::EventKind`:

| notify EventKind | DirtyKind |
|---|---|
| `Create(_)` | `Created` |
| `Modify(_)` | `Modified` |
| `Remove(_)` | `Deleted` |
| `Rename(RenameMode::From, old_path)` | `Deleted` (for old_path) |
| `Rename(RenameMode::To, new_path)` | `Created` (for new_path) |
| `Rename(RenameMode::Both, _)` | emit `Deleted` for old + `Created` for new |
| `Access(_)`, `Other` | ignore |

`notify-debouncer-mini` coalesces these into a single `DebouncedEvent` per path. The
debouncer loses the fine-grained `EventKind`. Use `DirtyKind::Modified` for all
debounced events where the file exists on disk at event time, and `DirtyKind::Deleted`
if the file does not exist.

**Rename detection:** When a file is renamed within a watched directory, notify emits
a `Rename` event. If the destination is within a watched directory and matches include
patterns, emit `Created` for the destination. If the source was a watched file, emit
`Deleted` for the source. If using the debouncer (which may collapse these), check
existence at event handling time.

---

## Initial scan

On startup, after the notify watcher is registered but before entering the event loop,
the Watcher performs an initial scan of all configured directories.

### Purpose

Find files that changed while the daemon was not running (between sessions). The Watcher
compares each file's current BLAKE3 hash against the stored `FileRecord.content_hash`
in the DB. If the hash differs (or the file is not in the DB at all), a `DirtyEvent` is
emitted.

### Algorithm

```
for each include entry:
    walk all files under entry.root recursively (walkdir)
    for each file:
        if file matches any exclude pattern: skip
        if file does not match include pattern: skip
        compute blake3(file contents)
        look up FileRecord in DB by absolute path
        case no record:
            emit DirtyEvent { path, kind: Created, detected_at: now }
        case record found, content_hash matches:
            skip (already backed up, unchanged)
        case record found, content_hash differs:
            emit DirtyEvent { path, kind: Modified, detected_at: now }
        case record found, dirty=true already:
            skip (Processor already knows it's dirty)
```

### Blocking execution

`walkdir` and `blake3` hashing are synchronous and potentially long-running (500 GB of
files). The initial scan runs in `tokio::task::spawn_blocking`:

```rust
let dirty_tx_clone = dirty_tx.clone();
let db_clone = db.clone();
let state_clone = state.clone();  // Arc<WatcherState>
tokio::task::spawn_blocking(move || {
    run_initial_scan(&state_clone, &db_clone, &dirty_tx_clone);
}).await.expect("initial scan panicked");
```

The blocking task sends events on the `dirty_tx` channel directly (channel is
`tokio::sync::mpsc` which can be sent to from a blocking thread).

### Hash computation

```rust
fn hash_file(path: &Path) -> Option<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf).ok()?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Some(hasher.finalize().into())
}
```

Returns `None` if the file cannot be opened (permissions, deleted between scan and
open). On `None`, skip the file (log at DEBUG level).

### Large directories

For very large directories (hundreds of thousands of files), the initial scan can take
many seconds. This is acceptable for a cold backup system. The scan runs concurrently
with the notify watcher (both are started before the event loop). Events arriving from
notify during the initial scan are queued in the debouncer.

---

## Notify watcher setup

```rust
// Watch all include root directories.
for entry in &state.includes {
    debouncer
        .watcher()
        .watch(&entry.root, RecursiveMode::Recursive)
        .unwrap_or_else(|e| {
            tracing::info!(
                path = ?entry.root,
                error = %e,
                "watcher: cannot watch directory, skipping"
            );
        });
}
```

Note: If a directory does not exist (e.g. external drive not mounted), `watch()` fails.
Log at INFO, continue watching the others. Retry is not implemented in Phase 3.

---

## Event loop

The main task loop uses `tokio::select!` to multiplex between:
1. `cancel.cancelled()` — graceful shutdown
2. Events from the notify debouncer (via an async wrapper or `tokio::task::spawn_blocking`)

### Bridging std channel to tokio

`notify-debouncer-mini` uses `std::sync::mpsc` (not tokio). Bridge with a
`tokio::task::spawn_blocking` or a dedicated blocking thread that forwards events into
a `tokio::sync::mpsc`:

```rust
// Spawn a blocking thread to drain the std channel and forward to tokio channel.
let (debounce_tx, mut debounce_rx) = tokio::sync::mpsc::channel(512);
std::thread::spawn(move || {
    loop {
        match std_rx.recv() {
            Ok(events) => {
                // events: Result<Vec<DebouncedEvent>, Vec<notify::Error>>
                if debounce_tx.blocking_send(events).is_err() {
                    break;  // receiver dropped, stop
                }
            }
            Err(_) => break,  // std channel closed
        }
    }
});
```

Then in the tokio event loop:

```rust
tokio::select! {
    _ = cancel.cancelled() => {
        tracing::debug!("watcher: cancelled");
        break;
    }
    batch = debounce_rx.recv() => {
        match batch {
            Some(Ok(events)) => {
                for ev in events {
                    handle_debounced_event(&ev, &state, &dirty_tx).await;
                }
            }
            Some(Err(errors)) => {
                for e in errors {
                    tracing::debug!(error = %e, "watcher: notify error");
                }
            }
            None => {
                tracing::debug!("watcher: debounce channel closed");
                break;
            }
        }
    }
}
```

### Handling a debounced event

```rust
async fn handle_debounced_event(
    ev: &notify_debouncer_mini::DebouncedEvent,
    state: &WatcherState,
    dirty_tx: &tokio::sync::mpsc::Sender<DirtyEvent>,
) {
    let path = &ev.path;

    // Only emit for files, not directories.
    if path.is_dir() {
        return;
    }

    // Check include/exclude patterns.
    if !state.is_included(path) {
        return;
    }

    let kind = if path.exists() {
        // File exists: created or modified. Processor distinguishes via DB lookup.
        DirtyKind::Modified
    } else {
        DirtyKind::Deleted
    };

    let event = DirtyEvent {
        path: path.clone(),
        kind,
        detected_at: Timestamp::now().0,
    };

    tracing::debug!(path = ?path, kind = ?kind, "watcher: dirty event");

    // Best-effort send. If Processor is overwhelmed, we drop the event.
    // The initial scan on next restart will catch it.
    let _ = dirty_tx.try_send(event);
}
```

`try_send` (non-blocking) is preferred over `send` (async) here because the event loop
must stay responsive. If the channel is full (capacity = 1024 as defined in `daemon/mod.rs`
`DIRTY_CHANNEL_CAPACITY`), the event is dropped. Dropped events are recovered on the next
daemon startup via the initial scan. Log a DEBUG message on drop.

---

## WatcherState helper methods

```rust
impl WatcherState {
    /// Build from config. Expands tildes, compiles glob patterns.
    /// Returns error if a glob pattern is syntactically invalid.
    pub fn from_config(config: &BackupConfig) -> Result<Self, WatcherError>;

    /// Check whether an absolute path should be watched.
    /// Returns true if: at least one include matches AND no exclude matches.
    pub fn is_included(&self, path: &Path) -> bool;

    /// Return the importance for a path (for initial scan filtering).
    /// Returns 0.0 if not included.
    pub fn importance_for(&self, path: &Path) -> f64;

    /// Return all root directories to watch (unique, deduplicated).
    pub fn watch_roots(&self) -> Vec<PathBuf>;
}
```

---

## Error enum

```rust
#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
    #[error("invalid glob pattern '{pattern}': {source}")]
    InvalidGlob {
        pattern: String,
        #[source]
        source: glob::PatternError,
    },

    #[error("notify error: {0}")]
    Notify(#[from] notify::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
```

`WatcherError` is returned by `WatcherState::from_config`. If pattern compilation fails,
`run()` should log at ERROR level and return early (watcher disabled). The daemon
continues running without file watching — existing dirty flags in the DB are still
processed by the Scheduler.

The `run()` function itself has signature `async fn run(...) -> ()` (no Result), matching
the existing pattern used by all other tasks (`scheduler::run`, `cli_server::run`).
Fatal errors inside `run()` are handled by panic (alpha strategy).

---

## DB operations

The Watcher is **read-only** with respect to the DB. It calls:

```rust
// During initial scan only:
db.get_file(path_str: &str) -> Result<Option<FileRecord>, DbError>
```

No writes. The Processor receives `DirtyEvent` and calls `db.upsert_file` or
`db.mark_file_dirty`.

---

## Logging

```
INFO:  "watcher: started, watching N directories"
INFO:  "watcher: initial scan complete, N dirty files found"
DEBUG: "watcher: dirty event" (path, kind)
DEBUG: "watcher: cannot watch directory, skipping" (path, error) — non-fatal
DEBUG: "watcher: event channel full, dropping event" (path) — on try_send failure
DEBUG: "watcher: cancelled"
DEBUG: "watcher: stopped"
```

No WARN level (ADR-003 convention for alpha).

---

## Business rules

1. **Exclude priority:** If a path matches both an include and an exclude pattern, it is
   excluded. Excludes are checked before includes.

2. **Importance threshold:** Files with computed importance < 0.1 (no matching include
   entry, or matching entry has importance < 0.1) are silently ignored. This is consistent
   with the Processor's `handle_dirty` logic which also skips importance < 0.1.

3. **Directories are not files:** Never emit `DirtyEvent` for a directory path. Only
   regular files.

4. **Symlinks:** Treat symlinks as regular files if they resolve to a file. Do not follow
   symlink chains into un-watched directories (use `walkdir` default: `follow_links =
   false` for initial scan). Notify events for symlinks are emitted for the symlink path,
   not the target.

5. **Already-dirty skip:** During initial scan, if `FileRecord.dirty == true`, skip
   hashing. The Processor already knows the file is dirty. Avoids redundant work.

6. **Atomic writes (editor temp-file pattern):** Many editors write to a temp file and
   rename it over the original. Debouncing at 30 seconds absorbs this pattern completely.
   No special handling needed.

7. **Initial scan is best-effort:** If a file cannot be opened (permissions, locked),
   log DEBUG and skip. The file will be caught if it becomes accessible later via notify.

8. **Order of startup:** notify watcher is started BEFORE the initial scan. This ensures
   no events are lost during the scan. The debounce window (30s) means scan events and
   notify events do not double-fire in practice.

9. **Channel back-pressure:** `try_send` is used instead of `send.await`. The channel
   capacity of 1024 (DIRTY_CHANNEL_CAPACITY) is far larger than typical burst rates.
   If it fills, dropped events will be caught on next restart's initial scan. This is
   acceptable for a cold backup system.

---

## Cargo.toml additions

The implementer must add these dependencies to `crates/syncback/Cargo.toml`:

```toml
notify = "6"
notify-debouncer-mini = "0.4"
glob = "0.3"
walkdir = "2"
```

Check existing `Cargo.toml` first — some may already be present.

---

## Test scenarios

Tests live in `crates/syncback/src/daemon/watcher/tests.rs`. Because the watcher
interacts with the real file system and notify, tests use `tempdir` for isolation and
do NOT mock the file system.

### Async test runtime

Use `#[tokio::test]` for all async tests.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    fn test_config(dir: &std::path::Path) -> BackupConfig {
        BackupConfig {
            include: vec![IncludeEntry {
                path: dir.to_path_buf(),
                importance: 0.8,
            }],
            exclude: vec![],
        }
    }
    // ...
}
```

---

### Scenario 1: `pattern_matching_excludes_tmp_files`

**Given:** include = `[{path: "/some/dir", importance: 0.8}]`, exclude = `["*.tmp"]`

**Input:** paths `["/some/dir/notes.txt", "/some/dir/session.tmp", "/some/dir/sub/file.rs"]`

**Expected:**
- `is_included("/some/dir/notes.txt")` → `true`
- `is_included("/some/dir/session.tmp")` → `false` (matches `*.tmp` exclude)
- `is_included("/some/dir/sub/file.rs")` → `true`
- `is_included("/other/dir/notes.txt")` → `false` (not under include root)

```rust
#[test]
fn pattern_matching_excludes_tmp_files() {
    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: PathBuf::from("/some/dir"),
            importance: 0.8,
        }],
        exclude: vec!["*.tmp".to_string()],
    };
    let state = WatcherState::from_config(&config).unwrap();
    assert!(state.is_included(Path::new("/some/dir/notes.txt")));
    assert!(!state.is_included(Path::new("/some/dir/session.tmp")));
    assert!(state.is_included(Path::new("/some/dir/sub/file.rs")));
    assert!(!state.is_included(Path::new("/other/dir/notes.txt")));
}
```

---

### Scenario 2: `pattern_matching_excludes_directory_component`

**Given:** exclude = `["node_modules"]`

**Input:** paths `["/proj/src/index.js", "/proj/node_modules/lodash/index.js"]`

**Expected:**
- `/proj/src/index.js` → included
- `/proj/node_modules/lodash/index.js` → excluded (has `node_modules` component)

```rust
#[test]
fn pattern_matching_excludes_directory_component() {
    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: PathBuf::from("/proj"),
            importance: 0.5,
        }],
        exclude: vec!["node_modules".to_string()],
    };
    let state = WatcherState::from_config(&config).unwrap();
    assert!(state.is_included(Path::new("/proj/src/index.js")));
    assert!(!state.is_included(Path::new("/proj/node_modules/lodash/index.js")));
}
```

---

### Scenario 3: `pattern_matching_longest_include_wins`

**Given:** include = `[{~/Photos, 0.5}, {~/Photos/Favorites, 0.9}]`

**Input:** paths under `~/Photos/Favorites/` and `~/Photos/Other/`

**Expected:**
- `importance_for("~/Photos/Favorites/img.jpg")` → `0.9`
- `importance_for("~/Photos/Other/img.jpg")` → `0.5`

```rust
#[test]
fn pattern_matching_longest_include_wins() {
    let home = std::env::var("HOME").unwrap();
    let photos = PathBuf::from(&home).join("Photos");
    let favs = PathBuf::from(&home).join("Photos/Favorites");
    let config = BackupConfig {
        include: vec![
            IncludeEntry { path: photos.clone(), importance: 0.5 },
            IncludeEntry { path: favs.clone(), importance: 0.9 },
        ],
        exclude: vec![],
    };
    let state = WatcherState::from_config(&config).unwrap();
    assert_eq!(
        state.importance_for(&favs.join("img.jpg")),
        0.9
    );
    assert_eq!(
        state.importance_for(&photos.join("Other/img.jpg")),
        0.5
    );
}
```

---

### Scenario 4: `initial_scan_emits_created_for_new_file`

**Given:** A temp directory with one file. DB has no record for the file.

**Expected:** `DirtyEvent { kind: Created }` is sent.

```rust
#[tokio::test]
async fn initial_scan_emits_created_for_new_file() {
    let tmpdir = TempDir::new().unwrap();
    let file_path = tmpdir.path().join("test.txt");
    std::fs::write(&file_path, b"hello").unwrap();

    let db = syncback_core::db::Db::open(
        &tmpdir.path().join("test.redb")
    ).unwrap();

    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: tmpdir.path().to_path_buf(),
            importance: 0.8,
        }],
        exclude: vec![],
    };

    let (tx, mut rx) = mpsc::channel(64);
    let state = WatcherState::from_config(&config).unwrap();
    // run_initial_scan is an internal function; expose for test or test through run().
    // If not exposed, use the run() function with a short-lived cancel token.
    // Here we test the observable output: DirtyEvent received on channel.
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let daemon_config = make_test_daemon_config(&config, tmpdir.path());
    tokio::spawn(async move {
        run(cancel_clone, tx, db, daemon_config).await;
    });

    // Give time for initial scan + debouncer startup.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    cancel.cancel();

    let event = rx.try_recv().expect("expected at least one DirtyEvent");
    assert_eq!(event.path, file_path);
    assert_eq!(event.kind, DirtyKind::Created);
}
```

DECISION NEEDED: `run_initial_scan` is internal. The test above tests it via `run()`.
If the team prefers a pub(crate) helper for direct unit testing without the notify
machinery, expose `pub(crate) fn run_initial_scan(...)`.

---

### Scenario 5: `initial_scan_skips_unchanged_file`

**Given:** File in DB with `dirty = false` and matching content hash.

**Expected:** No `DirtyEvent` emitted for that file.

```rust
#[tokio::test]
async fn initial_scan_skips_unchanged_file() {
    let tmpdir = TempDir::new().unwrap();
    let file_path = tmpdir.path().join("unchanged.txt");
    let contents = b"same content";
    std::fs::write(&file_path, contents).unwrap();

    let hash: [u8; 32] = blake3::hash(contents).into();

    let db = syncback_core::db::Db::open(&tmpdir.path().join("test.redb")).unwrap();
    db.upsert_file(&syncback_core::types::FileRecord {
        file_id: syncback_core::types::FileId(1),
        path: file_path.to_string_lossy().into_owned(),
        content_hash: hash,
        size_bytes: contents.len() as u64,
        importance: 0.8,
        dirty: false,
        current_unit_id: None,
        last_backed_up: Some(syncback_core::types::Timestamp::now()),
        backed_up: true,
        first_seen: syncback_core::types::Timestamp::now(),
    }).unwrap();

    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: tmpdir.path().to_path_buf(),
            importance: 0.8,
        }],
        exclude: vec![],
    };

    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let daemon_config = make_test_daemon_config(&config, tmpdir.path());

    tokio::spawn(async move {
        run(cancel_clone, tx, db, daemon_config).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    cancel.cancel();

    assert!(rx.try_recv().is_err(), "should not emit event for unchanged file");
}
```

---

### Scenario 6: `initial_scan_emits_modified_for_changed_file`

**Given:** File in DB with different hash than current content, `dirty = false`.

**Expected:** `DirtyEvent { kind: Modified }` emitted.

```rust
#[tokio::test]
async fn initial_scan_emits_modified_for_changed_file() {
    let tmpdir = TempDir::new().unwrap();
    let file_path = tmpdir.path().join("changed.txt");
    std::fs::write(&file_path, b"new content").unwrap();

    let old_hash = [0u8; 32];  // different from blake3("new content")

    let db = syncback_core::db::Db::open(&tmpdir.path().join("test.redb")).unwrap();
    db.upsert_file(&syncback_core::types::FileRecord {
        file_id: syncback_core::types::FileId(1),
        path: file_path.to_string_lossy().into_owned(),
        content_hash: old_hash,
        size_bytes: 7,
        importance: 0.8,
        dirty: false,
        current_unit_id: None,
        last_backed_up: None,
        backed_up: false,
        first_seen: syncback_core::types::Timestamp::now(),
    }).unwrap();

    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: tmpdir.path().to_path_buf(),
            importance: 0.8,
        }],
        exclude: vec![],
    };

    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let daemon_config = make_test_daemon_config(&config, tmpdir.path());

    tokio::spawn(async move {
        run(cancel_clone, tx, db, daemon_config).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    cancel.cancel();

    let event = rx.try_recv().expect("expected DirtyEvent");
    assert_eq!(event.kind, DirtyKind::Modified);
}
```

---

### Scenario 7: `initial_scan_skips_already_dirty_file`

**Given:** File in DB with `dirty = true` (already flagged before restart).

**Expected:** No new `DirtyEvent` emitted (file is already queued for backup).

```rust
#[tokio::test]
async fn initial_scan_skips_already_dirty_file() {
    // Insert FileRecord with dirty=true.
    // Run initial scan.
    // Assert no DirtyEvent emitted.
    // ...
}
```

---

### Scenario 8: `watch_roots_returns_unique_deduplicated_roots`

**Given:** Two include entries with overlapping roots
(`/home/user/docs` and `/home/user/docs/work`).

**Expected:** `watch_roots()` returns only `/home/user/docs` (the other is already
covered). Or at minimum, both are returned without duplicates. The notify crate handles
overlapping watches gracefully (recursive watch of parent covers children).

```rust
#[test]
fn watch_roots_returns_unique_deduplicated_roots() {
    let config = BackupConfig {
        include: vec![
            IncludeEntry { path: PathBuf::from("/home/user/docs"), importance: 0.8 },
            IncludeEntry { path: PathBuf::from("/home/user/docs"), importance: 0.9 },
        ],
        exclude: vec![],
    };
    let state = WatcherState::from_config(&config).unwrap();
    let roots = state.watch_roots();
    assert_eq!(roots.len(), 1);
}
```

---

### Scenario 9: `invalid_glob_pattern_returns_error`

**Given:** An include path with invalid glob syntax (e.g. `[invalid`).

**Expected:** `WatcherState::from_config` returns `Err(WatcherError::InvalidGlob { .. })`.

```rust
#[test]
fn invalid_glob_pattern_returns_error() {
    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: PathBuf::from("/some/[invalid"),
            importance: 0.5,
        }],
        exclude: vec![],
    };
    let result = WatcherState::from_config(&config);
    assert!(matches!(result, Err(WatcherError::InvalidGlob { .. })));
}
```

---

### Scenario 10: `watcher_shuts_down_on_cancel`

**Given:** Watcher task is running (no files, empty config).

**Input:** `cancel.cancel()` is called.

**Expected:** The `run` future completes within a short timeout (100 ms).

```rust
#[tokio::test]
async fn watcher_shuts_down_on_cancel() {
    let tmpdir = TempDir::new().unwrap();
    let db = syncback_core::db::Db::open(&tmpdir.path().join("test.redb")).unwrap();
    let (tx, _rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let config = make_test_daemon_config(&BackupConfig {
        include: vec![],
        exclude: vec![],
    }, tmpdir.path());

    let handle = tokio::spawn(async move {
        run(cancel_clone, tx, db, config).await;
    });

    cancel.cancel();
    tokio::time::timeout(
        std::time::Duration::from_millis(500),
        handle,
    )
    .await
    .expect("watcher did not shut down within timeout")
    .expect("watcher panicked");
}
```

---

### Test helper

```rust
fn make_test_daemon_config(backup: &BackupConfig, syncback_dir: &Path) -> crate::daemon::Config {
    crate::daemon::Config {
        syncback_dir: syncback_dir.to_path_buf(),
        backup: backup.clone(),
        storage: crate::daemon::StorageConfig { quota_gb: 10 },
        network: crate::daemon::NetworkConfig {
            seed_nodes: vec![],
            bandwidth_limit_mbps: 0,
        },
        schedule: crate::daemon::ScheduleConfig {
            sync: crate::daemon::SyncFrequency::Weekly,
            vacuum: crate::daemon::VacuumFrequency::Monthly,
        },
    }
}
```

---

## Dependencies (other modules this one depends on)

| Module | What it uses |
|---|---|
| `daemon/mod.rs` | `DirtyEvent`, `DirtyKind`, `Config`, `BackupConfig`, `IncludeEntry`, `DIRTY_CHANNEL_CAPACITY` |
| `syncback-core::db` | `Db`, `get_file` (read-only, initial scan) |
| `syncback-core::types` | `Timestamp`, `FileRecord` |

No dependency on: `processor`, `network`, `scheduler`, `storage`, `shard_manager`,
`trust`, `escrow`, `placement`, `budget`, `messages`.

---

## Call site changes required

The implementer must update `crates/syncback/src/daemon/mod.rs`:

1. Delete `crates/syncback/src/daemon/watcher.rs` stub.
2. Create `crates/syncback/src/daemon/watcher/mod.rs` and `watcher/tests.rs`.
3. Update the `tokio::spawn(watcher::run(...))` call in `DaemonHandle::start` to pass
   `db.clone()` and `config.clone()`:

```rust
// Before (stub):
tokio::spawn(watcher::run(cancel.clone(), dirty_tx.clone()));

// After (Phase 3):
tokio::spawn(watcher::run(
    cancel.clone(),
    dirty_tx.clone(),
    db.clone(),
    config.clone(),
));
```

No other call sites.

---

## What is NOT in scope for this module

- Writing to the DB (Processor does all writes)
- Computing importance (Processor uses `config_importance_for_path`)
- Triggering backup immediately (Scheduler does this via WeeklySync)
- Watching symlink targets outside configured roots
- Watching removable drives that are not yet mounted (retry is post-MVP)
- Rate-limiting the number of dirty events sent to Processor
- File content hashing at notify-event time (only at initial scan and when Processor
  actually backs up the file via Packer)
- Any network activity
