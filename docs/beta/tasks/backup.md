# Task: backup — BackupCoordinator (β)

Module: `crates/syncback/src/daemon/backup/`
Files: `mod.rs` + `pipeline.rs` + `packing.rs` + `tests.rs`

---

## Overview

The BackupCoordinator orchestrates the full local backup pipeline: it takes dirty file
events from the Watcher, classifies them, packs small files into batches, compresses,
encrypts, erasure-codes, and binds symbols for each candidate holder. In Phase 2 the
pipeline runs locally without network — it produces bound symbols and records in DB, but
does not send anything over the wire. Network distribution is wired up when the Network
module is ready.

**Phase 2 gate requirement:** `roundtrip без сети` — backup files to DB + local symbol
files, then verify the pipeline produces correct records and the symbols can be decoded.

**What this module does:**

1. **Dirty file processing** — consume dirty events (`Added`, `Modified`, `Deleted`),
   compute BLAKE3 content hash, check for dedup, update `FileRecord` in DB.

2. **Packing queues** — maintain three in-memory queues (`Photo`, `Document`, `Other`)
   plus an immediate queue for large files (≥ source_block_size bytes). Debounce events
   per path. Flush on: queue size ≥ source_block_size OR idle for 1 hour OR 24-hour
   fallback. Skip flush if total queued bytes < `MIN_BATCH_BYTES` (1 MB).

3. **Pack construction** — for each batch: serialize `PackIndex` (CBOR `Vec<PackEntry>`)
   + raw file bytes into plaintext. For large files: use file bytes directly (no pack).

4. **Compress → encrypt → ID** — zstd compress the plaintext, then
   ChaCha20-Poly1305 encrypt with a key derived from `epoch_key` via HKDF, then compute
   `source_block_id = blake3(ciphertext)`.

5. **Erasure encode + bind** — for each source block: call `ErasureEncoder::encode()` for
   each holder's ESI range (already bound by the encoder). Write bound symbols to local
   `symbols/` directory as `{source_block_id_hex}/{esi}.bin`.

6. **DB persistence** — write `FileRecord`, `SourceBlockRecord`, `SymbolPlacement`
   records to DB after successful pipeline. Append `Event::SymbolsPlaced` to EventLog.

The coordinator runs as a tokio task. All blocking I/O (file reads, zstd, encoding) runs
in `tokio::task::spawn_blocking`.

---

## Dependencies

- `syncback_core::db::Db`
- `syncback_core::types::{FileRecord, FileVersion, SourceBlockRecord, SourceBlockType,
    SourceBlockStatus, SymbolPlacement, PlacementStatus, PackEntry, FileCategory,
    LocalState, ErasureParams, IdentityPub, SourceBlockId, FileId, DeviceId, Timestamp,
    EventEntry, Event, to_cbor_bytes}`
- `syncback_core::erasure::{ErasureEncoder, RaptorQEncoder, Symbol}`
- `syncback_core::placement::{compute_allocation, HolderCandidate}`
- `syncback_core::constants::{DEFAULT_SOURCE_BLOCK_SIZE, SYMBOL_SIZE, MIN_BATCH_BYTES,
    FLUSH_IDLE_SECS, FLUSH_FALLBACK_SECS, DEBOUNCE_SECS}`
- `blake3`
- `zstd` crate (add to Cargo.toml: `zstd = "0.13"`)
- `chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace, Nonce}`
- `hkdf::Hkdf`, `sha2::Sha256`
- `tokio::{sync::mpsc, task::spawn_blocking, time}`
- `anyhow::{Context, Result}` (in daemon, anyhow allowed)
- `tracing::{info, debug, error, warn}`

New Cargo.toml deps for `syncback`:
```toml
syncback-core = { workspace = true }
tokio = { workspace = true }
anyhow = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
blake3 = { workspace = true }
chacha20poly1305 = { workspace = true }
hkdf = { workspace = true }
sha2 = { workspace = true }
zstd = "0.13"
ciborium = { workspace = true }
serde = { workspace = true }
tempfile = { workspace = true }
```

---

## Types

```rust
/// A dirty file event from the watcher.
#[derive(Debug, Clone)]
pub struct DirtyEvent {
    pub path: String,
    pub kind: DirtyKind,
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirtyKind {
    Added,
    Modified,
    Deleted,
}

/// One item waiting in a packing queue.
#[derive(Debug, Clone)]
pub struct QueuedFile {
    pub path: String,
    pub file_id: FileId,
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    pub category: FileCategory,
}

/// Configuration for BackupCoordinator.
#[derive(Debug, Clone)]
pub struct BackupConfig {
    /// Source block size in bytes. Default: DEFAULT_SOURCE_BLOCK_SIZE.
    pub source_block_size: u64,
    /// Directory where bound symbol files are written.
    pub symbols_dir: std::path::PathBuf,
    /// Epoch key for file encryption. 32 bytes.
    pub epoch_key: [u8; 32],
    /// This device's ID (for LocalState and EventLog).
    pub device_id: DeviceId,
}

impl Default for BackupConfig {
    fn default() -> Self {
        BackupConfig {
            source_block_size: DEFAULT_SOURCE_BLOCK_SIZE,
            symbols_dir: std::path::PathBuf::from("symbols"),
            epoch_key: [0u8; 32],
            device_id: DeviceId([0u8; 16]),
        }
    }
}

/// Result of processing one source block through the pipeline.
#[derive(Debug)]
pub struct PipelineResult {
    pub source_block_id: SourceBlockId,
    pub k: u32,
    pub n: u32,
    pub symbol_count_per_holder: Vec<(IdentityPub, u32)>,
}
```

---

## Public API

```rust
/// BackupCoordinator: orchestrates file → symbol pipeline.
///
/// Holds packing queues, DB handle, encoder, and config.
/// Runs as a tokio task; accepts dirty events via mpsc channel.
pub struct BackupCoordinator {
    db: Db,
    config: BackupConfig,
    encoder: Arc<dyn ErasureEncoder>,
    // Internal packing queues (one per FileCategory)
    // Internal flush timers
}

impl BackupCoordinator {
    /// Create a new coordinator.
    pub fn new(db: Db, config: BackupConfig, encoder: Arc<dyn ErasureEncoder>) -> Self;

    /// Process a single dirty event synchronously (for testing without tokio).
    ///
    /// For Added/Modified:
    ///   1. Read file from path.
    ///   2. content_hash = blake3(file_bytes).
    ///   3. Dedup: check DB for existing FileRecord with same content_hash in any version.
    ///      If found: update FileRecord (add new version pointing to existing source_block_id) → return Ok.
    ///   4. Classify file → FileCategory.
    ///   5. Upsert FileRecord in DB (new or add version with backed_up_at=None).
    ///   6. Queue file for packing (enqueue to category queue).
    ///
    /// For Deleted:
    ///   1. DB lookup by path.
    ///   2. Set devices entry for event.device_id to LocalState::Deleted(now).
    ///   3. Upsert FileRecord.
    ///   4. No network activity.
    ///
    /// Does NOT flush queue. Call flush_queue() explicitly or let timers handle it.
    pub fn process_event(&mut self, event: DirtyEvent) -> anyhow::Result<()>;

    /// Flush the specified category queue if it meets flush criteria.
    ///
    /// Criteria (any of):
    ///   - total queued bytes for category >= source_block_size
    ///   - force=true (caller decided to flush regardless)
    ///
    /// MIN_BATCH_BYTES check: if total bytes across all categories < MIN_BATCH_BYTES
    /// AND force=false → skip flush (return Ok(vec![])).
    ///
    /// For each batch of files (up to source_block_size bytes):
    ///   1. Build plaintext: PackIndex CBOR + concatenated file bytes.
    ///   2. Compress with zstd (level 3).
    ///   3. Encrypt with ChaCha20-Poly1305 (derive key from epoch_key, random nonce).
    ///   4. source_block_id = blake3(ciphertext).
    ///   5. Compute ErasureParams (importance = avg of files in batch).
    ///   6. Encode: for each holder candidate (from DB), call encoder.encode() for that
    ///      holder's ESI range.
    ///   7. Write symbols to symbols_dir/{block_id_hex}/{esi}.bin.
    ///   8. Write SourceBlockRecord + SymbolPlacement records to DB.
    ///   9. Update FileVersion.backed_up_at = now.
    ///  10. Append EventLog entries.
    ///
    /// In Phase 2: holder candidates come from `mock_holders` in config (for testing)
    /// or from DB `list_all_peers()` sorted by trust (for real use).
    ///
    /// Returns list of PipelineResult for each processed source block.
    pub fn flush_queue(
        &mut self,
        category: FileCategory,
        force: bool,
    ) -> anyhow::Result<Vec<PipelineResult>>;

    /// Flush all categories.
    pub fn flush_all(&mut self, force: bool) -> anyhow::Result<Vec<PipelineResult>>;

    /// Process one large file (>= source_block_size) into its own source block.
    ///
    /// Reads file, compresses, encrypts, encodes, writes symbols, updates DB.
    /// Uses SourceBlockType::Single.
    pub fn process_large_file(
        &mut self,
        path: &str,
        file_id: FileId,
        content_hash: [u8; 32],
        importance: f64,
        candidates: &[HolderCandidate],
    ) -> anyhow::Result<PipelineResult>;

    /// Run the coordinator as a tokio task.
    ///
    /// Reads DirtyEvent from rx channel.
    /// Runs flush timers:
    ///   - idle timer (FLUSH_IDLE_SECS): reset on each event, flush when expired
    ///   - fallback timer (FLUSH_FALLBACK_SECS): flush unconditionally
    ///
    /// Exits when rx channel is closed.
    pub async fn run(
        self,
        rx: tokio::sync::mpsc::Receiver<DirtyEvent>,
    ) -> anyhow::Result<()>;
}
```

---

## Business Rules

### Dedup check

```
content_hash = blake3(raw_file_bytes)

For Added:
  existing = db.list_all_files() filtered by any version.content_hash == content_hash
  if found:
    // Zero traffic: same content already backed up
    // Add this device/path as new entry in existing record
    existing_record.devices.push((event.device_id, LocalState::Present))
    db.upsert_file(&existing_record)
    return Ok(())
  else:
    // New content — classify and queue
    classify and enqueue
```

For Modified, same dedup logic applies. A modified file whose new content already exists
in the catalog (e.g., revert to previous version) produces zero traffic.

### File classification

```
fn classify(path: &str) -> FileCategory {
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "heic" | "raw" | "cr2" | "nef" | "webp" => Photo,
        "mp4" | "mov" | "avi" | "mkv" | "m4v" | "wmv" => Video (→ Other for queueing; large files go direct),
        _ => Document,
    }
}
```

Note: Video is NOT a separate queue. Large video files (>= source_block_size) bypass the
queue entirely and go to `process_large_file`. Small videos are queued as `Other`.

### Large file threshold

Files with `size_bytes >= source_block_size` → `process_large_file`, not the queue.
Files with `size_bytes < source_block_size` → queue by category.

### Pack format (plaintext before compress)

```
plaintext = cbor_serialize(Vec<PackEntry>) + [file1_bytes] + [file2_bytes] + ...

PackEntry { file_id, offset, size }
where:
  offset = cumulative position in the concatenated file bytes section
  (not counting the PackIndex itself — offsets are relative to start of file data)
```

The PackIndex CBOR is prepended. Its length is not stored separately — the decoder reads
CBOR first (self-delimiting), then file bytes start at `cbor_len`. The `PackEntry.offset`
is relative to the byte immediately after the PackIndex CBOR.

### Encryption

```
// Key derivation per source block
info = b"syncback-backup" || source_block_id_placeholder  // placeholder = [0u8;32] at derive time
// (We derive key first, then compute block_id after encryption)
// Use a random nonce per source block
nonce = rand::random::<[u8; 12]>()
chacha_key_material = Hkdf::<Sha256>::new(None, &epoch_key)
                      .expand(b"syncback-block-key", &mut key_buf[..32])
// key_buf is the ChaCha20-Poly1305 key
ciphertext = ChaCha20Poly1305::new(&key_buf.into())
             .encrypt(&nonce.into(), plaintext.as_ref())

// Store nonce alongside ciphertext: [12-byte nonce][ciphertext bytes]
// source_block_id = blake3([12-byte nonce][ciphertext])
```

DECISION NEEDED: The nonce must be stored somewhere to allow decryption during restore.
Options: (a) prefix nonce to the stored ciphertext on disk, or (b) derive nonce from
source_block_id (circular dependency). Recommendation: prefix nonce to ciphertext.
The stored format is then `[12-byte nonce][ciphertext]` and source_block_id =
blake3 of the whole `[nonce || ciphertext]` blob.

During restore: read the file → first 12 bytes = nonce, remainder = ciphertext → decrypt.

### Importance for a batch

```
batch_importance = files.iter().map(|f| f.importance).sum() / files.len() as f64
```

Average importance of all files in the batch. Used to compute ErasureParams.overhead.

### Holder candidates in Phase 2

In Phase 2, holder candidates for encoding are obtained from `db.list_all_peers()`.
For testing purposes, `BackupConfig` may include a `mock_holders: Vec<HolderCandidate>`
field that overrides DB lookup. If `mock_holders` is empty and DB has no peers, encoding
still happens but no placements are written (symbols go to disk, no SymbolPlacement
records).

DECISION NEEDED: Spec says use mock_holders for phase 2 testing. Consider whether
`mock_holders` should be part of config or a separate parameter to flush_queue. Recommend
adding to config for simplicity.

### Symbol file naming

```
symbols_dir/{block_id_hex}/{esi}.bin

block_id_hex = hex-encode(source_block_id.0)  // 64 hex chars
```

One file per ESI. The BackupCoordinator writes symbols; RestoreCoordinator reads them.

### DB writes after pipeline

After successful encoding and symbol write for a source block:
1. `db.upsert_source_block(SourceBlockRecord { block_id, k, t, block_type, status: Active, created_at })`
2. For each holder allocation:
   `db.upsert_placement(SymbolPlacement { source_block_id, holder_id, file_id, esi_ranges: [alloc.esi_range()], binding_seed, status: Offered, last_verified: None, placed_at: now })`
   Status is `Offered` initially (no confirmation yet; in Phase 2 it will be set to
   `Alive` immediately since there's no actual network confirmation).
   In Phase 2: set status to `Alive` directly (local roundtrip, no network).
3. Update `FileRecord.versions` latest entry: `backed_up_at = Some(now)`.
4. `db.append_event(EventEntry { timestamp: now, device_id, event: Event::SymbolsPlaced { ... } })`

### binding_seed in SymbolPlacement

The binding seed is derived the same way as in the encoder:
```
binding_seed = HKDF-SHA256(ikm=source_block_id.0 || holder_id.0, info=b"syncback-binding")
               .expand() → [u8; 32]
```
This must match the encoder's internal computation. The seed stored in DB is used by the
RestoreCoordinator to call `encoder.unbind()`.

---

## DB Operations

### Reads
- `db.get_file(path)` — check for existing FileRecord
- `db.list_all_files()` — dedup check by content_hash (O(n), rare)
- `db.list_all_peers()` — get holder candidates (trust scores)
- `db.get_source_block(block_id)` — verify no collision

### Writes
- `db.upsert_file(FileRecord)` — after each dirty event
- `db.upsert_source_block(SourceBlockRecord)` — after encoding
- `db.upsert_placement(SymbolPlacement)` — per holder per source block
- `db.append_event(EventEntry)` — SymbolsPlaced events

---

## Test Scenarios

Tests in `backup/tests.rs`. Pattern: `what_when_then`.

Use a real `Db::open_in_memory()` and a real `RaptorQEncoder`. Use a `tempdir` for
symbols. For encoding tests, use tiny source blocks (a few KB) to keep test runtime fast.
Adjust `BackupConfig::source_block_size` to match test data size.

### 1. `process_event_added_creates_file_record`

```
db = Db::open_in_memory()
coord = BackupCoordinator::new(db.clone(), test_config(), Arc::new(RaptorQEncoder::new()))
path = "/test/photo.jpg"
content = b"fake image data" * 100
write file to tempdir

event = DirtyEvent { path, kind: Added, device_id: DeviceId([1u8;16]) }
coord.process_event(event).unwrap()

record = db.get_file(path).unwrap().unwrap()
assert record.path == path
assert record.versions.len() == 1
assert record.versions[0].content_hash == blake3(content)
assert record.versions[0].backed_up_at.is_none()  // not yet flushed
```

### 2. `process_event_deleted_marks_local_state`

```
// First add the file
coord.process_event(added_event).unwrap()
// Then delete it
coord.process_event(DirtyEvent { path, kind: Deleted, device_id }).unwrap()

record = db.get_file(path).unwrap().unwrap()
let state = record.devices.iter().find(|(d, _)| *d == device_id).map(|(_, s)| s)
assert matches!(state, Some(LocalState::Deleted(_)))
```

### 3. `process_event_dedup_same_content_no_new_version`

```
content = b"same content"
path1 = "/test/file1.txt"
path2 = "/test/file2.txt"

coord.process_event(added_event(path1, content)).unwrap()
// Now add path2 with identical content
coord.process_event(added_event(path2, content)).unwrap()

// path2 should reuse the same source_block_id
record1 = db.get_file(path1).unwrap().unwrap()
record2 = db.get_file(path2).unwrap().unwrap()
// Both should exist in DB, record2 references the same source block as record1
assert record2.versions[0].source_block_id == record1.versions[0].source_block_id
    OR record2.versions.is_empty()  // depends on dedup implementation
```

### 4. `flush_queue_below_min_batch_skips`

```
// Queue a file smaller than MIN_BATCH_BYTES
event = DirtyEvent { path: "/test/tiny.txt", kind: Added, ... }
// file size = 100 bytes
coord.process_event(event).unwrap()
results = coord.flush_queue(FileCategory::Document, false).unwrap()
assert results.is_empty()  // not enough bytes to flush
```

### 5. `flush_queue_with_force_flushes_any_size`

```
// Same tiny file
coord.process_event(event_100_bytes).unwrap()
results = coord.flush_queue(FileCategory::Document, true).unwrap()
assert !results.is_empty()
```

### 6. `flush_queue_creates_source_block_record`

```
// Queue enough data (> MIN_BATCH_BYTES)
for i in 0..20 {
    coord.process_event(added_event_with_1mb_file(i)).unwrap()
}
results = coord.flush_queue(FileCategory::Document, false).unwrap()
assert !results.is_empty()

for result in &results {
    block = db.get_source_block(&result.source_block_id).unwrap().unwrap()
    assert matches!(block.block_type, SourceBlockType::Pack { .. })
    assert block.status == SourceBlockStatus::Active
}
```

### 7. `flush_queue_writes_symbol_files`

```
// After flush, symbol files should exist
for result in &results {
    for (holder_id, count) in &result.symbol_count_per_holder {
        for esi in 0..*count {
            let path = symbols_dir
                .join(hex::encode(result.source_block_id.0))
                .join(format!("{}.bin", esi));
            assert path.exists()
        }
    }
}
```

### 8. `flush_queue_updates_backed_up_at`

```
coord.process_event(added_event).unwrap()
coord.flush_queue(FileCategory::Document, true).unwrap()

record = db.get_file(path).unwrap().unwrap()
assert record.versions[0].backed_up_at.is_some()
```

### 9. `pipeline_roundtrip_can_decode`

```
// Backup a small file, then verify symbols decode back to original content.
content = b"roundtrip test content " * 200  // ~4400 bytes
coord.process_event(added_event(path, content)).unwrap()
results = coord.flush_queue(FileCategory::Document, true).unwrap()
assert results.len() == 1

block_id = results[0].source_block_id
block_record = db.get_source_block(&block_id).unwrap().unwrap()
placements = db.list_placements_for_block(&block_id).unwrap()

// Read all symbols for first holder
placement = &placements[0]
params = ErasureParams::compute(
    block_record.k as u64 * block_record.t as u64, avg_importance)
encoder = RaptorQEncoder::new()

// Read bound symbols from disk, unbind, collect K_eff, decode
symbols = read_symbols_from_disk(&symbols_dir, &block_id, placement)
unbound = symbols.into_iter()
    .map(|s| encoder.unbind(s, &block_id, &placement.holder_id))
    .collect::<Vec<_>>()
// Need K_eff symbols total — gather from multiple placements if needed
decoded = encoder.decode(&unbound_all, &params).unwrap()

// Decrypt and decompress decoded
// Should contain original content
assert decoded_content contains content
```

### 10. `process_large_file_creates_single_block`

```
// A file larger than source_block_size
large_content = vec![0u8; (DEFAULT_SOURCE_BLOCK_SIZE + 1024) as usize]
coord.process_event(added_large_file_event).unwrap()
// process_large_file is called internally for large files
// Verify block type
results = coord.flush_all(true).unwrap()
block = db.get_source_block(&results[0].source_block_id).unwrap().unwrap()
assert matches!(block.block_type, SourceBlockType::Single)
```

### 11. `process_event_modified_adds_new_version`

```
coord.process_event(added_event_v1).unwrap()
coord.process_event(modified_event_v2).unwrap()  // different content

record = db.get_file(path).unwrap().unwrap()
assert record.versions.len() == 2
assert record.versions[0].content_hash != record.versions[1].content_hash
```

### 12. `flush_queue_appends_event_log`

```
coord.process_event(event).unwrap()
coord.flush_queue(FileCategory::Document, true).unwrap()

events = db.list_recent_events(100).unwrap()
// At least one SymbolsPlaced event
assert events.iter().any(|e| matches!(e.event, Event::SymbolsPlaced { .. }))
```

---

## Module Structure

```
backup/
  mod.rs       — BackupCoordinator struct, process_event, run
  pipeline.rs  — flush_queue, process_large_file, pack/compress/encrypt/encode logic
  packing.rs   — pack format: build_plaintext(), parse_pack_index()
  tests.rs     — all test scenarios above
```

---

## Notes for implementer

- `zstd` is not in workspace.dependencies yet. Add `zstd = "0.13"` to the workspace
  Cargo.toml and to `syncback/Cargo.toml`. Use `zstd::encode_all(reader, level)` /
  `zstd::decode_all(reader)`.

- The encryption scheme has a chicken-and-egg problem: we want `source_block_id =
  blake3(ciphertext)` but need a key to encrypt. The key is derived from `epoch_key`
  with a fixed info string (not block_id), so there is no circular dependency. The nonce
  is random per block. Stored format: `[12-byte nonce][ciphertext]`; blake3 covers both.

- The `binding_seed` stored in `SymbolPlacement` is NOT re-computed here — the erasure
  encoder computes it internally. But for the DB record, we need to store it. Either
  (a) add a method to the encoder to expose the binding seed for a (block_id, holder_id)
  pair, or (b) compute it directly using the same HKDF formula. Recommend (b): keep the
  formula in one place in the encoder module and expose a `binding_seed(block_id,
  holder_id) -> [u8;32]` function from `crate::erasure`.

- For Phase 2 tests: set `BackupConfig::source_block_size` to something small (e.g.,
  128 * 1024 = 128 KB) so tests encode quickly. The encoder is O(K) where K =
  source_block_size / T, so small source blocks encode in milliseconds.

- The `run()` method uses tokio interval timers for idle and fallback flushes. Use
  `tokio::time::interval` with `MissedTickBehavior::Skip`. The idle timer should reset
  on each event (use `tokio::time::sleep` with a shared `Instant`, reset on event).

- All blocking I/O (file read, zstd, encode) must run in `spawn_blocking`. The
  coordinator state (queues) is Send + Sync; the closure captures what it needs.

- `db.list_placements_for_block()` may not exist in Phase 1 DB. Add it to the DB module
  (or use `db.list_placements_for_owner()` with the owner being `self`). DECISION NEEDED:
  confirm which DB query is available. The BackupCoordinator needs to list placements
  by source_block_id to write them in test scenarios.

- All tests live in `backup/tests.rs`. Use `#[tokio::test]` for async tests.
  Use `tempfile::TempDir` for the symbols directory.
