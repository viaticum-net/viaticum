# Task: restore — RestoreCoordinator (β)

Module: `crates/syncback/src/daemon/restore/`
Files: `mod.rs` + `pipeline.rs` + `tests.rs`

---

## Overview

The RestoreCoordinator orchestrates the full local + network restore pipeline. It takes a
path or prefix, resolves it to source blocks via DB, fetches bound symbols from holder
peers over the network, decodes, decrypts, decompresses, and writes files back to disk.

**Phase 2 gate requirement:** `backup на A → restore на B` — two nodes on localhost.
Node A backs up files (BackupCoordinator), Node B (acting as holder) has the symbols.
RestoreCoordinator on A connects to B, fetches symbols, and reconstructs the original
files.

**What this module does:**

1. **Path resolution** — take a path prefix (or exact path), query DB for matching
   `FileRecord`s, select the requested version per file (latest, by version index, or by
   date). Deduplicate source blocks (multiple files in the same pack share one block).

2. **Holder selection** — for each unique source block, query DB for `SymbolPlacement`
   records with status `Alive`. Sort holders by trust score (most trusted first). Select
   enough holders to gather at least `K_eff` symbols.

3. **Escrow check** — before fetching, check escrow: call `EscrowChecker::check_restore`
   to verify the requester's tenure. In Phase 2 the coordinator is restoring its own data
   (self-restore), so escrow always passes. Full holder-side escrow enforcement is in the
   holder's incoming-connection handler (not this module).

4. **Symbol fetch** — for each holder in priority order, open a connection via
   `NetworkHandle`, send `RestoreRequestMsg`, receive `RestoreResponseMsg` (or
   `RestoreDeniedMsg`). Collect symbols until we have `K_eff` total for this block.
   Fetch from holders in parallel (up to `RESTORE_PARALLEL_HOLDERS` concurrent).

5. **Decode pipeline** — unbind each received symbol (call `ErasureEncoder::unbind`),
   collect `K_eff` unbound symbols, call `ErasureEncoder::decode`, decrypt the resulting
   ciphertext with ChaCha20-Poly1305, decompress with zstd.

6. **File extraction** — for `SourceBlockType::Pack`: parse `PackIndex` from the
   decoded plaintext, extract each requested file at the correct offset and size, write to
   `output_dir/relative_path`. For `SourceBlockType::Single`: write the whole decoded
   content to a single file.

7. **DB update** — after successful restore, update `FileRecord.devices` for the current
   device to `LocalState::Present`.

The coordinator runs as a tokio task, accepting restore requests via an mpsc channel.

---

## Dependencies

- `syncback_core::db::Db`
- `syncback_core::types::{FileRecord, FileVersion, SourceBlockRecord, SourceBlockType,
    SourceBlockStatus, SymbolPlacement, PlacementStatus, PackEntry, ErasureParams,
    IdentityPub, SourceBlockId, FileId, DeviceId, LocalState, Timestamp, from_cbor_bytes}`
- `syncback_core::erasure::{ErasureEncoder, RaptorQEncoder, Symbol}`
- `syncback_core::escrow::{EscrowChecker, RestoreDecision}`
- `syncback_core::messages::{RestoreRequestMsg, RestoreResponseMsg, RestoreDeniedMsg, Message}`
- `syncback_core::constants::{SYMBOL_SIZE, DECODE_OVERHEAD}`
- `crate::daemon::network::NetworkHandle`
- `blake3`
- `zstd` crate
- `chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace, Nonce}`
- `hkdf::Hkdf`, `sha2::Sha256`
- `tokio::{sync::mpsc, task::spawn_blocking, time}`
- `anyhow::{Context, Result}`
- `tracing::{info, debug, error, warn}`

---

## Types

```rust
/// A restore request from the user or daemon.
#[derive(Debug, Clone)]
pub struct RestoreRequest {
    /// Path or prefix to restore. Trailing '/' treated as prefix.
    pub path: String,
    /// Version selection for all matching files.
    pub version_selector: VersionSelector,
    /// Where to write restored files. Files are written to
    /// `output_dir / relative_path` (stripping leading components as appropriate).
    pub output_dir: std::path::PathBuf,
    /// Device ID performing the restore (for LocalState update).
    pub device_id: DeviceId,
}

/// How to select which version of each file to restore.
#[derive(Debug, Clone, PartialEq)]
pub enum VersionSelector {
    /// Latest backed-up version (default).
    Latest,
    /// Specific version by 0-based index into FileRecord.versions.
    Index(usize),
    /// Nearest version with backed_up_at <= given timestamp.
    BeforeDate(Timestamp),
}

/// Result of a completed restore.
#[derive(Debug)]
pub struct RestoreResult {
    /// Number of files successfully restored.
    pub files_restored: usize,
    /// Number of source blocks fetched from network.
    pub blocks_fetched: usize,
    /// Paths that failed to restore (with reason).
    pub failures: Vec<(String, String)>,
}

/// Configuration for RestoreCoordinator.
#[derive(Debug, Clone)]
pub struct RestoreConfig {
    /// Epoch key for decryption. 32 bytes. Must match the key used during backup.
    pub epoch_key: [u8; 32],
    /// Max parallel holders to fetch symbols from for one block.
    pub parallel_holders: usize,
    /// This device's identity (for trust lookup and LocalState update).
    pub identity: IdentityPub,
    /// This device's ID (for LocalState).
    pub device_id: DeviceId,
    /// weeks_in_network for escrow check (if checking own escrow tier on self-restore).
    pub weeks_in_network: u32,
}

impl Default for RestoreConfig {
    fn default() -> Self {
        RestoreConfig {
            epoch_key: [0u8; 32],
            parallel_holders: 5,
            identity: IdentityPub([0u8; 32]),
            device_id: DeviceId([0u8; 16]),
            weeks_in_network: 0,
        }
    }
}

/// Error type for restore operations.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("file not found in catalog: {path}")]
    FileNotFound { path: String },

    #[error("version not found: {selector:?} for {path}")]
    VersionNotFound { path: String, selector: String },

    #[error("source block not found in DB: {0}")]
    BlockNotFound(SourceBlockId),

    #[error("no alive holders for block {0}")]
    NoHolders(SourceBlockId),

    #[error("insufficient symbols: collected {got}, need {need} for block {block}")]
    InsufficientSymbols { block: SourceBlockId, got: usize, need: usize },

    #[error("decode failed for block {0}: {1}")]
    DecodeFailed(SourceBlockId, String),

    #[error("decryption failed for block {0}")]
    DecryptionFailed(SourceBlockId),

    #[error("decompression failed for block {0}: {1}")]
    DecompressionFailed(SourceBlockId, String),

    #[error("pack index parse failed for block {0}: {1}")]
    PackIndexParseFailed(SourceBlockId, String),

    #[error("restore denied by holder {holder}: requires {required_weeks} weeks, have {current_weeks}")]
    EscrowDenied { holder: IdentityPub, required_weeks: u32, current_weeks: u32 },

    #[error("network error: {0}")]
    Network(#[from] crate::daemon::network::NetworkError),

    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
```

---

## Public API

```rust
/// RestoreCoordinator: orchestrates network symbol fetch → decode → file write.
pub struct RestoreCoordinator {
    db: Db,
    config: RestoreConfig,
    encoder: Arc<dyn ErasureEncoder>,
    network: Arc<NetworkHandle>,
}

impl RestoreCoordinator {
    /// Create a new coordinator.
    pub fn new(
        db: Db,
        config: RestoreConfig,
        encoder: Arc<dyn ErasureEncoder>,
        network: Arc<NetworkHandle>,
    ) -> Self;

    /// Execute a restore request synchronously.
    ///
    /// 1. Resolve path to FileRecords using db.list_files_with_prefix (prefix) or
    ///    db.get_file (exact path).
    /// 2. For each FileRecord, select version via selector.
    /// 3. Collect unique source_block_ids (deduplicate: multiple files → same block).
    /// 4. For each source block: fetch_and_decode_block → returns plaintext bytes.
    /// 5. For each file in block: extract from plaintext → write to output_dir.
    /// 6. Update FileRecord.devices for this device_id to LocalState::Present.
    ///
    /// Returns RestoreResult with counts and failure list.
    /// Individual file failures are collected in RestoreResult.failures; block-level
    /// failures (no symbols available) return Err immediately.
    pub async fn restore(&self, request: RestoreRequest) -> Result<RestoreResult, RestoreError>;

    /// Fetch symbols for one source block from holders and decode to plaintext.
    ///
    /// 1. db.list_placements_for_block(block_id) → filter status == Alive.
    /// 2. Sort holders by trust (db.get_peer → peer.trust_score).
    /// 3. Connect to holders in priority order; stop when K_eff symbols collected.
    ///    Use up to config.parallel_holders concurrent fetches (tokio::spawn per holder).
    /// 4. For each symbol received: call encoder.unbind(symbol, block_id, holder_id).
    /// 5. Once K_eff unbound symbols collected: encoder.decode(symbols, params).
    /// 6. Decrypt: ChaCha20-Poly1305 with epoch_key-derived key. Stored format:
    ///    [12-byte nonce][ciphertext]. Extract nonce from first 12 bytes.
    /// 7. Decompress: zstd::decode_all.
    /// 8. Return plaintext bytes.
    ///
    /// Returns Err(InsufficientSymbols) if fewer than K_eff symbols available across
    /// all alive holders.
    pub async fn fetch_and_decode_block(
        &self,
        block_id: &SourceBlockId,
        params: &ErasureParams,
    ) -> Result<Vec<u8>, RestoreError>;

    /// Request symbols from one holder for a given source block.
    ///
    /// Sends RestoreRequestMsg, waits for RestoreResponseMsg or RestoreDeniedMsg.
    /// Returns Ok(symbols) on success, Err(EscrowDenied) on denial, Err(Network) on
    /// connection failure (caller skips to next holder).
    pub async fn fetch_from_holder(
        &self,
        holder_id: IdentityPub,
        block_id: &SourceBlockId,
        esi_list: Vec<u32>,
    ) -> Result<Vec<Symbol>, RestoreError>;

    /// Select which FileVersion to restore per selector.
    ///
    /// Latest:      versions.last() with backed_up_at.is_some()
    /// Index(n):    versions[n] if present
    /// BeforeDate:  last version with backed_up_at.is_some() && backed_up_at <= ts
    ///
    /// Returns None if no matching version found.
    pub fn select_version<'a>(
        record: &'a FileRecord,
        selector: &VersionSelector,
    ) -> Option<&'a FileVersion>;

    /// Extract one file from a decoded pack plaintext.
    ///
    /// Parses PackIndex from the beginning of plaintext (CBOR Vec<PackEntry>).
    /// Finds the PackEntry for file_id.
    /// Returns the file bytes at [cbor_len + entry.offset .. cbor_len + entry.offset + entry.size].
    pub fn extract_from_pack(
        plaintext: &[u8],
        file_id: FileId,
    ) -> Result<Vec<u8>, RestoreError>;

    /// Run the coordinator as a tokio task.
    /// Accepts RestoreRequest from rx channel, processes sequentially.
    /// Results sent back via oneshot channels embedded in request.
    pub async fn run(
        self,
        rx: tokio::sync::mpsc::Receiver<(RestoreRequest, tokio::sync::oneshot::Sender<Result<RestoreResult, RestoreError>>)>,
    ) -> anyhow::Result<()>;
}
```

---

## Business Rules

### Version selection

```
Latest:
  versions.iter().rev()
         .find(|v| v.backed_up_at.is_some())

Index(n):
  versions.get(n)
  (0-based; versions are in chronological order, oldest first)

BeforeDate(ts):
  versions.iter().rev()
         .find(|v| v.backed_up_at.map(|t| t.0 <= ts.0).unwrap_or(false))
```

If no version matches, return `None` → caller records failure in `RestoreResult.failures`.

### Source block deduplication

Multiple files may share a source block (they were packed together). The coordinator must
decode each source block at most once, then extract all requested files from the decoded
plaintext. Algorithm:

```
// Map source_block_id → Vec<(FileRecord, FileVersion)>
let mut blocks: HashMap<SourceBlockId, Vec<(FileRecord, FileVersion)>> = HashMap::new();
for (record, version) in resolved_files {
    blocks.entry(version.source_block_id).or_default().push((record, version));
}
// Then for each unique block: fetch → decode → extract all files
```

### Symbol fetch parallelism

Use `tokio::select!` or `tokio::task::JoinSet` to fetch from multiple holders
concurrently (up to `config.parallel_holders`). Stop as soon as we have `K_eff` symbols
(first-come, first-served). Do not wait for slow holders once sufficient symbols are
collected.

Holder priority order (highest to lowest):
1. Trust score (from DB PeerRecord, if present; default 0.0 if unknown)
2. Start fetching from high-trust holders first, add low-trust holders only if needed

### ESI list in RestoreRequestMsg

Send `esi_list = []` (empty) to mean "any K_eff symbols from your holdings". The holder
returns all symbols it holds for this block. This simplifies the coordinator — it does not
need to know in advance which ESIs each holder has (DB knows, but the roundtrip to ask
for specific ESIs is not worth it in Phase 2).

If `esi_list` is non-empty, the holder returns exactly those ESIs if available. The
coordinator may use non-empty `esi_list` in Phase 3+ to avoid requesting duplicate ESIs
from multiple holders.

### Unbinding symbols

Each received symbol is bound to the holder that sent it. Before decoding, call:

```rust
let unbound = encoder.unbind(bound_symbol, block_id, holder_id);
```

The `ErasureEncoder::unbind` method is the inverse of the XOR binding applied during
backup. After unbinding, the symbol is raw RaptorQ output and can be passed to `decode`.

### Decryption

```
stored_bytes = [12-byte nonce][ciphertext with 16-byte poly1305 tag]
nonce = stored_bytes[0..12]
ciphertext = stored_bytes[12..]

chacha_key = Hkdf::<Sha256>::new(None, &epoch_key)
             .expand(b"syncback-block-key", &mut key_buf[..32])

plaintext = ChaCha20Poly1305::new(&chacha_key.into())
            .decrypt(&nonce.into(), ciphertext.as_ref())
            .map_err(|_| RestoreError::DecryptionFailed(block_id))?
```

Must use the same `epoch_key` as was used during backup. Key derivation is identical to
`BackupCoordinator`.

### Pack index parsing

The decoded + decrypted + decompressed plaintext starts with a CBOR-encoded
`Vec<PackEntry>`. The CBOR is self-delimiting. After parsing it, the raw file bytes begin
at byte position `cbor_len`:

```
plaintext = [CBOR(Vec<PackEntry>)][file1_bytes][file2_bytes]...

PackEntry { file_id: FileId, offset: u64, size: u64 }
// offset is relative to start of file data section (after CBOR)
```

To find a file:
```
cbor_len = length of CBOR header (parse CBOR, note position)
data_start = cbor_len
file_bytes = plaintext[data_start + entry.offset .. data_start + entry.offset + entry.size]
```

For `SourceBlockType::Single`: no pack index. The entire decoded plaintext is the file.

### DB update after restore

```
record = db.get_file(path)?
// Find or add device entry
match record.devices.iter_mut().find(|(d, _)| d == device_id) {
    Some((_, state)) => *state = LocalState::Present,
    None => record.devices.push((device_id, LocalState::Present)),
}
db.upsert_file(&record)?
```

### Failure handling

- Per-file failures (version not found, file not in pack): collect in `RestoreResult.failures`, continue.
- Per-block failures (no holders, insufficient symbols): return `Err` immediately (no partial restore from that block).
- Individual holder errors (network, escrow denied): skip holder and try next.

---

## DB Operations

### Reads
- `db.get_file(path)` — exact path lookup
- `db.list_files_with_prefix(prefix)` — prefix lookup for folder restore
- `db.get_source_block(block_id)` — get K, T, block_type, status
- `db.list_placements_for_block(block_id)` — all holders for a block
- `db.get_peer(identity)` — get trust score for holder sorting

### Writes
- `db.upsert_file(record)` — update LocalState to Present after restore

---

## Test Scenarios

Tests in `restore/tests.rs`. Pattern: `what_when_then`.

Use a real `Db::open_in_memory()`, real `RaptorQEncoder`, and a small `BackupConfig`
(source_block_size = 128 KB) so encoding is fast in tests. For network tests, use two
in-process `NetworkHandle`s.

### 1. `select_version_latest_returns_last_backed_up`

```
record.versions = [
    FileVersion { backed_up_at: Some(Timestamp(100)), ... },
    FileVersion { backed_up_at: Some(Timestamp(200)), ... },
    FileVersion { backed_up_at: None, ... },   // queued but not yet backed up
]
result = RestoreCoordinator::select_version(&record, &VersionSelector::Latest)
assert result.is_some()
assert result.unwrap().backed_up_at == Some(Timestamp(200))
```

### 2. `select_version_latest_returns_none_when_none_backed_up`

```
record.versions = [FileVersion { backed_up_at: None, ... }]
result = RestoreCoordinator::select_version(&record, &VersionSelector::Latest)
assert result.is_none()
```

### 3. `select_version_index_returns_nth`

```
record.versions = [v0, v1, v2]   // v1.backed_up_at = Some(Timestamp(500))
result = RestoreCoordinator::select_version(&record, &VersionSelector::Index(1))
assert result == Some(&v1)
```

### 4. `select_version_index_out_of_range_returns_none`

```
record.versions = [v0]
result = RestoreCoordinator::select_version(&record, &VersionSelector::Index(5))
assert result.is_none()
```

### 5. `select_version_before_date_returns_correct_version`

```
record.versions = [
    FileVersion { backed_up_at: Some(Timestamp(100)), ... },
    FileVersion { backed_up_at: Some(Timestamp(300)), ... },
    FileVersion { backed_up_at: Some(Timestamp(500)), ... },
]
result = RestoreCoordinator::select_version(&record, &VersionSelector::BeforeDate(Timestamp(400)))
assert result.unwrap().backed_up_at == Some(Timestamp(300))
```

### 6. `extract_from_pack_finds_file_by_id`

```
// Build a pack plaintext manually:
entries = vec![
    PackEntry { file_id: FileId(1), offset: 0, size: 5 },
    PackEntry { file_id: FileId(2), offset: 5, size: 8 },
]
cbor_bytes = to_cbor_bytes(&entries)
file1 = b"hello"
file2 = b"world!!!"
plaintext = [cbor_bytes, file1, file2].concat()

result = RestoreCoordinator::extract_from_pack(&plaintext, FileId(1))
assert result.unwrap() == b"hello"

result2 = RestoreCoordinator::extract_from_pack(&plaintext, FileId(2))
assert result2.unwrap() == b"world!!!"
```

### 7. `extract_from_pack_unknown_file_id_returns_error`

```
result = RestoreCoordinator::extract_from_pack(&plaintext, FileId(99))
assert result.is_err()
```

### 8. `pipeline_roundtrip_small_pack_restores_content`

```
// Use BackupCoordinator to back up 3 files into a pack (force-flush).
coord = BackupCoordinator::new(db.clone(), small_block_config(), Arc::new(RaptorQEncoder::new()))
for i in 0..3 {
    content = format!("file content {i}").into_bytes()
    write_temp_file(&tmpdir, format!("file{i}.txt"), &content)
    coord.process_event(added_event(&tmpdir, format!("file{i}.txt"))).unwrap()
}
results = coord.flush_all(true).unwrap()
assert results.len() == 1  // all in one block

// Now restore using a mock holder that serves the symbols from symbols_dir.
// (In Phase 2: test uses a local mock holder, not real network)
restore_config = RestoreConfig { epoch_key: coord_config.epoch_key, ... }
restore_coord = RestoreCoordinator::new(db.clone(), restore_config, encoder, mock_network)
request = RestoreRequest {
    path: tmpdir_path.to_string(),
    version_selector: VersionSelector::Latest,
    output_dir: out_dir.path().to_path_buf(),
    device_id: DeviceId([1u8; 16]),
}
result = restore_coord.restore(request).await.unwrap()
assert result.files_restored == 3

// Verify file content
for i in 0..3 {
    content = std::fs::read(out_dir.join(format!("file{i}.txt"))).unwrap()
    assert content == format!("file content {i}").into_bytes()
}
```

### 9. `restore_deduplicates_source_blocks`

```
// 2 files in same batch (same source block).
// Restore request for both files.
// Verify fetch_and_decode_block called only once (block decoded once).
// Can be verified by counting decode calls on a spy encoder.
```

### 10. `restore_single_file_by_exact_path`

```
// Add file1.txt (not in a pack, use SourceBlockType::Single for test simplicity).
// Restore file1.txt by exact path.
// Verify output_dir/file1.txt matches original content.
```

### 11. `restore_prefix_returns_all_matching_files`

```
// Add /photos/a.jpg, /photos/b.jpg, /docs/c.txt to DB.
request.path = "/photos/"
result = restore_coord.restore(request).await.unwrap()
assert result.files_restored == 2
// /docs/c.txt should not be in output
```

### 12. `restore_missing_path_returns_file_not_found_in_result`

```
request.path = "/nonexistent/file.txt"
result = restore_coord.restore(request).await.unwrap()
// Not an Err — just an empty/failure result
assert result.files_restored == 0
assert result.failures.len() == 1
assert result.failures[0].0 == "/nonexistent/file.txt"
```

### 13. `restore_no_alive_holders_returns_error`

```
// Add a file to DB but all its SymbolPlacements have status != Alive.
request.path = path
result = restore_coord.restore(request).await
assert matches!(result, Err(RestoreError::NoHolders(_)))
```

### 14. `fetch_from_holder_sends_restore_request_and_receives_symbols`

```
// Two in-process NetworkHandles on localhost.
// Holder B has symbols for block_id stored as HoldingRecord.
// Restore A: fetch_from_holder(B's identity, block_id, esi_list=[]).
// Verify symbols received match what B has.
// (This is the core Phase 2 gate test — full network roundtrip.)
```

### 15. `fetch_from_holder_escrow_denied_returns_error`

```
// B sends RestoreDeniedMsg(required_weeks=13, current_weeks=2).
// fetch_from_holder should return Err(RestoreError::EscrowDenied { ... }).
```

---

## Module Structure

```
restore/
  mod.rs        — RestoreCoordinator struct, restore(), run()
  pipeline.rs   — fetch_and_decode_block(), fetch_from_holder(), extract_from_pack()
  tests.rs      — all test scenarios above
```

---

## Notes for implementer

- `encoder.unbind(symbol, block_id, holder_id)` — the `ErasureEncoder` trait must expose
  `unbind`. Check `crates/syncback-core/src/erasure/mod.rs` — if `unbind` is not yet
  defined as a trait method, add it. The operation is: `symbol.data XOR
  ChaCha20_stream(HKDF(block_id, holder_id))`, identical to what `encode` does during
  binding. See Phase 1 erasure spec for the binding keystream formula.

- The `ErasureParams` needed for `decode` must be reconstructed from `SourceBlockRecord`:
  `ErasureParams::compute(k as u64 * t as u64, importance)`. However, `importance` is not
  stored in `SourceBlockRecord` directly — it is stored in `SymbolPlacement` or must be
  re-computed from file importance. DECISION NEEDED: confirm where to store the
  `importance` value used for encoding so RestoreCoordinator can reconstruct ErasureParams
  exactly. Recommend adding `importance: f64` to `SourceBlockRecord` or storing params.n
  and params.overhead directly.

- The decryption key is derived from `epoch_key` with a fixed info string (same as in
  `BackupCoordinator`). The `epoch_key` in `RestoreConfig` must be the exact same value
  used during backup. In Phase 2 tests, pass the same key to both coordinators explicitly.

- The `PackEntry` type is `syncback_core::types::PackEntry`. Confirm it is defined with
  fields `file_id: FileId, offset: u64, size: u64`. If not defined there, define it in
  `types/mod.rs` (the BackupCoordinator already uses it).

- For Phase 2 gate test (test scenario 14): the "holder" node B must handle incoming
  `RestoreRequest` messages. This requires a minimal holder-side handler in
  `syncback/src/daemon/restore/` or in the Network module's connection dispatcher. In
  Phase 2, implement a simple `HolderServer::handle_restore_request` that reads
  `HoldingRecord` from DB and responds. This can be a helper function in `mod.rs`.

- `spawn_blocking` for all CPU-heavy work: zstd decompress, ChaCha20 decrypt, RaptorQ
  decode. Use `tokio::task::spawn_blocking` and send results back via channels.

- The `run()` method accepts requests via mpsc. Each request also includes a oneshot
  sender for the result, allowing callers to await the restore completion.

- Tests must use `#[tokio::test]`. Use `tempfile::TempDir` for output directory.
  Use a small `source_block_size` (128 KB) to keep encode/decode fast.

- For tests 8-11 (roundtrip tests): the test acts as both BackupCoordinator (producing
  symbols in a local `symbols_dir`) and as a mock holder (serving those symbols in
  response to `RestoreRequest`). There is no real network needed for these tests — use
  an in-memory channel to mock the holder response. Full network roundtrip only in test 14.

- All tests in `restore/tests.rs`. No inline `#[cfg(test)]`.
