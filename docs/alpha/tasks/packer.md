# Task spec: packer module (Phase 3)

**Target file:** `crates/syncback/src/daemon/packer/mod.rs`
**Tests file:** `crates/syncback/src/daemon/packer/tests.rs`
**Phase:** 3
**Role:** Owner — converts dirty files into plaintext units, then encrypts and erasure-codes them into shards ready for `ShardManager` to distribute

---

## Overview

`Packer` is the **owner-role** module that owns the file-to-shard pipeline before the
network. Given a list of dirty files (produced by `BudgetPlanner::select_backup_batch`),
it:

1. Groups small files into pack units, splits large files into chunk units
2. Serializes each pack's content with a file index (offset + length per member)
3. Encrypts the unit plaintext with ChaCha20-Poly1305 (key from HKDF)
4. Erasure-codes the ciphertext with Reed-Solomon into n shards
5. Computes `shard_id = blake3(shard_bytes)` and the BLAKE3 Merkle root per shard
6. Returns a `PackResult` list that `Processor` passes directly to `ShardManager::upload_unit`

Additionally, `Packer` handles the restore path: given k raw shard blobs, it reverses the
pipeline (RS decode → decrypt → unpack files from the index).

`Packer` is **not a tokio task**. It is a sync/async struct called from `Processor` in the
weekly sync loop. File I/O is synchronous (no streaming required — cold backup, batch mode).

**Packer does NOT call ShardManager directly.** It returns `PackResult` and
`Processor` decides whether to call `shard_manager.upload_unit`.

---

## Context: where Packer fits in the weekly sync

```
Scheduler → ScheduledCmd::WeeklySync → Processor::run_weekly_sync()
    │
    ├─ BudgetPlanner::select_backup_batch() → BackupBatch { candidates }
    │
    ├─ Packer::pack_batch(candidates, identity_key) → Vec<PackResult>
    │      │
    │      └─ for each unit:
    │           Read files from disk → serialize pack/chunk →
    │           encrypt → RS encode → compute merkle roots →
    │           return PackedUnit { unit_record, plaintext, shards }
    │
    └─ for each PackResult:
         ShardManager::upload_unit(unit_id, &unit_record, &plaintext, ...)
         DB: upsert_unit, mark files not dirty, update current_unit_id
```

Phase 2 stub in `Processor::run_weekly_sync` (lines ~222-228) does nothing except log.
Phase 3 replaces that stub with a real call to `packer.pack_batch(batch.candidates)`.

---

## Dependencies

**syncback-core (from core library):**
- `db::Db` — read `files` table, write `units` table, update dirty/current_unit_id
- `types::{FileId, FileRecord, UnitId, UnitRecord, UnitType, UnitStatus, ShardId, Timestamp, ErasureTier}`
- `constants::{ERASURE_K, TIER_HIGH_N, TIER_HIGH_THRESHOLD, TIER_MID_N, TIER_MID_THRESHOLD, TIER_LOW_N, TIER_LOW_THRESHOLD}`

**Packer imports from syncback crate:**
- `daemon::merkle::{merkle_root, BLOCK_SIZE}` — must use the same Merkle implementation as storage
- `daemon::shard_manager::{ShardManagerError, encode_unit, decrypt_unit}` — DECISION NEEDED: these are currently private. Either expose them as `pub(crate)` helpers or duplicate them in packer. See "Implementation notes".

**External crates:**
- `chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, NewAead}}`
- `hkdf::Hkdf`
- `sha2::Sha256`
- `blake3`
- `reed_solomon_erasure::galois_8::ReedSolomon`
- `ed25519_dalek::SigningKey` — needed for key derivation (identity_key.to_bytes() as HKDF IKM)
- `rand_core::{OsRng, RngCore}` — random nonce for ChaCha20
- `serde::{Serialize, Deserialize}` — for pack index serialization

**std:**
- `std::path::{Path, PathBuf}`
- `std::fs` — read file contents

---

## Key decisions (from CLAUDE.md / MEMORY)

| Decision | Value |
|---|---|
| File encryption | HKDF-SHA256(identity_priv, salt=unit_id, info="syncback-file-encryption") → 32-byte key → ChaCha20-Poly1305 |
| UnitId derivation | blake3(owner_pub \|\| unit_type_byte \|\| counter_le_u64) for packs; blake3(file_content_hash \|\| chunk_index_le_u32) for chunks |
| ShardId | blake3(shard_bytes) |
| Nonce format | 12 random bytes prepended to ciphertext |
| Erasure tiers | importance ≥ 0.8 → 5-of-15, ≥ 0.4 → 5-of-10, ≥ 0.1 → 5-of-7 |
| Unit size U | Default 256 MiB, configurable |
| Block size for Merkle | 64 KiB = 65_536 bytes |
| Reed-Solomon | `reed-solomon-erasure` crate, galois_8 backend |

---

## Public API

```rust
pub struct Packer {
    db: syncback_core::db::Db,
    identity_key: ed25519_dalek::SigningKey,
    identity_pub: syncback_core::types::IdentityPub,
    unit_size_bytes: u64,     // default: 256 * 1024 * 1024
}

impl Packer {
    pub fn new(
        db: syncback_core::db::Db,
        identity_key: ed25519_dalek::SigningKey,
        identity_pub: syncback_core::types::IdentityPub,
        unit_size_bytes: u64,
    ) -> Self;

    // -------------------------------------------------------------------------
    // Forward path: files → packed units
    // -------------------------------------------------------------------------

    /// Pack a batch of dirty files into units ready for upload.
    ///
    /// Called by Processor on WeeklySync. Files are already selected and
    /// budget-approved by BudgetPlanner::select_backup_batch.
    ///
    /// Steps per file group:
    ///   1. Separate candidates into "small" (size < unit_size_bytes) and
    ///      "large" (size >= unit_size_bytes)
    ///   2. Group small files into packs of ~unit_size_bytes each
    ///   3. Split each large file into chunks of unit_size_bytes
    ///   4. For each unit: call pack_unit() or chunk_unit()
    ///
    /// Returns one PackResult per unit.
    ///
    /// Errors:
    ///   - File not readable (I/O error, permissions) → PackerError::Io
    ///   - File disappeared between indexing and now → PackerError::FileMissing
    ///   - Encryption failure → PackerError::Encryption (panic in alpha: invariant)
    ///
    /// On partial failure: return Ok with the units that succeeded.
    /// Failed files remain dirty in DB — they will be retried next week.
    pub fn pack_batch(
        &self,
        candidates: &[syncback_core::budget::BackupCandidate],
        now: syncback_core::types::Timestamp,
    ) -> Vec<PackResult>;

    /// Pack multiple small files into a single unit.
    ///
    /// Called internally by pack_batch for files smaller than unit_size_bytes.
    /// Also callable directly (used in tests and by vacuum repacking).
    ///
    /// Steps:
    ///   1. Read each file from disk
    ///   2. Build PackIndex (file path, offset, length for each member)
    ///   3. Serialize: [CBOR(PackIndex)][file0_bytes][file1_bytes]...
    ///   4. Derive unit_id = blake3(identity_pub || 0x01 || pack_counter_le_u64)
    ///      where pack_counter increments per unit created this session
    ///   5. Encrypt serialized bytes
    ///   6. RS encode ciphertext into n shards
    ///   7. For each shard: compute shard_id + merkle_root
    ///   8. Return PackResult
    pub fn pack_unit(
        &self,
        files: &[FileRecord],
        importance: f64,
        now: syncback_core::types::Timestamp,
    ) -> Result<PackResult, PackerError>;

    /// Split a single large file into chunk units.
    ///
    /// Steps:
    ///   1. Read file from disk (may be very large — read in chunks)
    ///   2. For each chunk of unit_size_bytes bytes (last chunk may be smaller):
    ///      a. Derive unit_id = blake3(file_content_hash || chunk_index_le_u32)
    ///      b. Encrypt chunk bytes
    ///      c. RS encode into n shards
    ///      d. For each shard: compute shard_id + merkle_root
    ///      e. Build PackResult
    ///
    /// Returns one PackResult per chunk.
    pub fn chunk_file(
        &self,
        file: &FileRecord,
        now: syncback_core::types::Timestamp,
    ) -> Result<Vec<PackResult>, PackerError>;

    // -------------------------------------------------------------------------
    // Reverse path: shards → files (restore)
    // -------------------------------------------------------------------------

    /// Decrypt and unpack files from k shard blobs (restore path).
    ///
    /// Steps:
    ///   1. RS decode k-of-n shards → ciphertext
    ///   2. Decrypt ciphertext → plaintext
    ///   3. Unpack: parse PackIndex from CBOR prefix, extract file bytes
    ///   4. Return Vec<(path, bytes)> one entry per member file
    ///
    /// For chunk units: plaintext is the raw file chunk (no pack index).
    /// Caller (Processor) reassembles chunks in order.
    ///
    /// Arguments:
    ///   - unit_id: needed for HKDF key derivation
    ///   - unit_type: Pack or Chunk (determines unpack logic)
    ///   - shard_blobs: exactly n Option<Vec<u8>> entries (None = shard lost).
    ///     At least k must be Some.
    ///   - k, n: RS parameters from UnitRecord
    ///
    /// Errors:
    ///   - Fewer than k blobs → PackerError::NotEnoughShards { need, have }
    ///   - RS decode failure → PackerError::ReedSolomon
    ///   - Decryption failure → PackerError::Encryption (auth tag mismatch)
    ///   - Pack index parse failure → PackerError::InvalidPackIndex
    pub fn unpack_unit(
        &self,
        unit_id: syncback_core::types::UnitId,
        unit_type: syncback_core::types::UnitType,
        shard_blobs: Vec<Option<Vec<u8>>>,
        k: usize,
        n: usize,
    ) -> Result<UnpackResult, PackerError>;

    // -------------------------------------------------------------------------
    // Vacuum support
    // -------------------------------------------------------------------------

    /// Repack stale units: collect all live files that are still current in stale
    /// packs, form fresh pack units from them.
    ///
    /// Called by Processor on Vacuum (monthly). Stale units have > 50% of
    /// member files outdated.
    ///
    /// Steps:
    ///   1. For each stale unit: collect member file_ids
    ///   2. Identify which member files still have this unit as their current_unit_id
    ///      (these are the "live" members still in this pack)
    ///   3. If live_count / total_count < STALE_RATIO_THRESHOLD (0.5): repack
    ///   4. Repack the live files into new fresh units
    ///   5. Return the new PackResults (Processor uploads them and marks old units Deleting)
    ///
    /// DECISION NEEDED: The vacuum repacker currently has no way to distinguish
    /// "live file still in this stale pack" from "file was updated to a newer pack".
    /// The `FileRecord::current_unit_id` field tracks the CURRENT unit. If
    /// current_unit_id != this_unit_id, the file has moved on and should not be
    /// repacked from this stale unit. Implementation must check this.
    pub fn vacuum_stale_units(
        &self,
        stale_unit_ids: &[syncback_core::types::UnitId],
        now: syncback_core::types::Timestamp,
    ) -> Result<Vec<PackResult>, PackerError>;

    // -------------------------------------------------------------------------
    // Internal helpers (pub(crate) for tests)
    // -------------------------------------------------------------------------

    /// Derive the 32-byte encryption key for a unit.
    /// HKDF-SHA256(identity_priv, salt=unit_id, info="syncback-file-encryption")
    pub(crate) fn derive_unit_key(
        &self,
        unit_id: syncback_core::types::UnitId,
    ) -> [u8; 32];
}
```

---

## Supporting types

```rust
/// Output of packing one unit (pack or single chunk).
/// Passed to ShardManager::upload_unit and DB update.
#[derive(Debug)]
pub struct PackResult {
    /// Unit record ready to upsert into DB (status = Active).
    pub unit_record: syncback_core::types::UnitRecord,
    /// Plaintext bytes of the unit (before encryption).
    /// Needed by ShardManager for encryption + RS encoding.
    /// NOTE: ShardManager re-encrypts. Packer returns plaintext, not ciphertext,
    /// so that ShardManager owns the full pipeline.
    pub plaintext: Vec<u8>,
    /// Pre-computed shard IDs and merkle roots (indexed 0..n).
    /// Packer pre-computes these so Processor can log them before upload.
    /// ShardManager will re-derive them from the plaintext during upload_unit.
    /// This field is optional metadata — ShardManager is authoritative.
    pub shard_preview: Vec<ShardPreview>,
    /// File records for all member files. Processor uses these to call
    /// db.mark_file_clean(path, now, unit_id) after successful upload.
    /// For packs: all member FileRecords.
    /// For chunks: the parent FileRecord (repeated for each chunk — Processor
    /// calls mark_file_clean only after the LAST chunk is uploaded).
    pub file_records: Vec<syncback_core::types::FileRecord>,
    /// Importance score for this unit (used by ShardManager for erasure tier + placement).
    pub importance: f64,
    /// For chunk units: which chunk index this is and how many total.
    /// None for pack units. Processor uses this to determine if all chunks are uploaded.
    pub chunk_info: Option<ChunkInfo>,
}

/// Metadata for chunk units to help Processor track multi-chunk files.
#[derive(Debug, Clone)]
pub struct ChunkInfo {
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub parent_file_id: syncback_core::types::FileId,
}

/// Lightweight preview of one shard (no blob bytes — ShardManager recomputes).
#[derive(Debug, Clone)]
pub struct ShardPreview {
    pub shard_index: u8,
    pub shard_id: syncback_core::types::ShardId,
    pub merkle_root: [u8; 32],
}

/// Output of unpacking a unit (restore path).
#[derive(Debug)]
pub struct UnpackResult {
    /// For Pack units: one entry per member file.
    /// For Chunk units: single entry with (path=None, bytes=chunk_bytes).
    pub files: Vec<UnpackedFile>,
}

#[derive(Debug)]
pub struct UnpackedFile {
    /// Original path as recorded in pack index. None for raw chunk units.
    pub path: Option<String>,
    pub bytes: Vec<u8>,
}

/// Pack file index — CBOR-serialized as the first block of a Pack unit's plaintext.
/// Followed immediately by concatenated file bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackIndex {
    /// Version marker for future changes.
    pub version: u8,
    /// Members in the order they appear in the concatenated payload.
    pub members: Vec<PackMember>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackMember {
    /// Absolute path as UTF-8 string.
    pub path: String,
    /// FileId for cross-referencing with the DB.
    pub file_id: u64,
    /// Byte offset of this file's content in the payload (after the index).
    pub offset: u64,
    /// Length of this file's content in bytes.
    pub length: u64,
    /// BLAKE3 hash of this file's raw content (integrity check on restore).
    pub content_hash: [u8; 32],
    /// Importance at time of packing.
    pub importance: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum PackerError {
    #[error("file not found: {0}")]
    FileMissing(std::path::PathBuf),

    #[error("io error reading {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("reed-solomon error: {0}")]
    ReedSolomon(String),

    #[error("not enough shards to decode: need {need}, have {have}")]
    NotEnoughShards { need: usize, have: usize },

    #[error("invalid pack index: {0}")]
    InvalidPackIndex(String),

    #[error("importance too low to back up (< 0.1): {0}")]
    ImportanceTooLow(f64),

    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),
}
```

---

## Unit ID derivation

The `UnitId` must be stable and unique. Two rules:

**Pack units:** a pack is a new creation each time, so use a session counter:

```rust
// In Packer: keep a session counter (std::sync::atomic::AtomicU64)
// incremented for each unit created in this process lifetime.
let counter: u64 = self.unit_counter.fetch_add(1, Ordering::Relaxed);
let mut hasher = blake3::Hasher::new();
hasher.update(&self.identity_pub.0);
hasher.update(&[0x01u8]); // type discriminant for "pack"
hasher.update(&counter.to_le_bytes());
let unit_id = UnitId(*hasher.finalize().as_bytes());
```

**Chunk units:** derived from file content hash + chunk index, so re-packing produces the
same UnitId if the file content hasn't changed:

```rust
let mut hasher = blake3::Hasher::new();
hasher.update(&file.content_hash);
hasher.update(&(chunk_index as u32).to_le_bytes());
let unit_id = UnitId(*hasher.finalize().as_bytes());
```

This means: if a file is re-chunked without content change (e.g., on repair), the same
`unit_id` is produced → the existing DB records are updated, not duplicated.

---

## Pack plaintext format

A Pack unit's plaintext is structured as:

```
[u32 LE: length of CBOR(PackIndex)][CBOR(PackIndex)][file0_bytes][file1_bytes]...
```

The 4-byte length prefix allows the unpacker to read the index without CBOR streaming.

Alignment: no padding between files. `PackMember.offset` is the byte offset relative to
the start of the concatenated file section (after the index).

**Example: 3 files of sizes 1000, 2000, 3000 bytes:**

```
[u32: N][PackIndex CBOR (N bytes)][1000 bytes file0][2000 bytes file1][3000 bytes file2]
PackIndex.members[0].offset = 0,    .length = 1000
PackIndex.members[1].offset = 1000, .length = 2000
PackIndex.members[2].offset = 3000, .length = 3000
```

Total plaintext size = 4 + N + 6000 bytes.

**Chunk unit plaintext:** raw file bytes only (no index). The file path and metadata are
already in the DB (FileRecord, UnitRecord with chunk_index).

---

## Encryption pipeline

Identical to what ShardManager already does (MUST remain compatible):

```rust
pub(crate) fn derive_unit_key(&self, unit_id: UnitId) -> [u8; 32] {
    let ikm: [u8; 32] = self.identity_key.to_bytes();
    let salt = &unit_id.0;
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut key = [0u8; 32];
    hk.expand(b"syncback-file-encryption", &mut key)
        .expect("HKDF expand: 32 bytes always valid");
    key
}

fn encrypt_plaintext(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, PackerError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| PackerError::Encryption(e.to_string()))?;
    // Output: [12-byte nonce][ciphertext + 16-byte auth tag]
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_ciphertext(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, PackerError> {
    if data.len() < 12 {
        return Err(PackerError::Encryption("ciphertext too short".into()));
    }
    let nonce_bytes: [u8; 12] = data[..12].try_into().expect("slice is 12 bytes");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(Nonce::from_slice(&nonce_bytes), &data[12..])
        .map_err(|e| PackerError::Encryption(e.to_string()))
}
```

Note: `PackResult.plaintext` is the UNENCRYPTED plaintext. `ShardManager::upload_unit`
re-encrypts it with a fresh nonce. Packer does NOT hand ciphertext to ShardManager.
Packer uses encryption only internally (for `shard_preview` computation and `unpack_unit`).

The `shard_preview` field in `PackResult` is computed from a preview encryption that is
discarded after preview computation. The ShardManager's encryption uses a different nonce.
This means `ShardPreview.shard_id` values will NOT match the final shard IDs uploaded.

DECISION: Since shard_preview IDs don't match final IDs, the field is only useful for
logging (size estimates, progress). If this causes confusion, remove `shard_preview` from
`PackResult` entirely and have Processor log file paths/sizes instead.

**Recommended:** keep `shard_preview` as `Vec<ShardPreview>` but mark it clearly as
"approximate — for logging only". Implementation can compute it or leave it empty.

---

## Erasure coding pipeline

Reed-Solomon encoding (same as ShardManager):

```rust
fn rs_encode(ciphertext: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, PackerError> {
    let r = ReedSolomon::new(k, n - k)
        .map_err(|e| PackerError::ReedSolomon(e.to_string()))?;

    let shard_size = ciphertext.len().div_ceil(k);
    let padded_len = shard_size * k;
    let mut padded = ciphertext.to_vec();
    padded.resize(padded_len, 0u8);

    let mut shards: Vec<Vec<u8>> = padded.chunks(shard_size).map(|s| s.to_vec()).collect();
    for _ in 0..(n - k) {
        shards.push(vec![0u8; shard_size]);
    }

    r.encode(&mut shards)
        .map_err(|e| PackerError::ReedSolomon(e.to_string()))?;
    Ok(shards)
}
```

For decoding in `unpack_unit`:

```rust
fn rs_decode(
    shard_blobs: Vec<Option<Vec<u8>>>,
    k: usize,
    n: usize,
) -> Result<Vec<u8>, PackerError> {
    let have = shard_blobs.iter().filter(|s| s.is_some()).count();
    if have < k {
        return Err(PackerError::NotEnoughShards { need: k, have });
    }

    let shard_size = shard_blobs.iter()
        .flatten()
        .map(|s| s.len())
        .next()
        .expect("at least k shards are Some");

    // Build Option<Vec<u8>> shards for reed-solomon
    let mut shards: Vec<Option<Vec<u8>>> = shard_blobs;

    let r = ReedSolomon::new(k, n - k)
        .map_err(|e| PackerError::ReedSolomon(e.to_string()))?;

    r.reconstruct(&mut shards)
        .map_err(|e| PackerError::ReedSolomon(e.to_string()))?;

    // Concatenate the k data shards (indices 0..k)
    let mut ciphertext = Vec::with_capacity(shard_size * k);
    for shard in shards.into_iter().take(k) {
        ciphertext.extend_from_slice(&shard.expect("reconstruct filled all missing shards"));
    }
    Ok(ciphertext)
}
```

Note: `reed_solomon_erasure::galois_8::ReedSolomon::reconstruct` expects
`&mut [Option<Vec<u8>>]` with None for missing shards. It fills them in-place.
Check the crate version in Cargo.toml for exact API — the existing `shard_manager.rs`
uses `r.encode(&mut shards)` (all shards as Vec<Vec<u8>>). For decode, `reconstruct`
is the correct method. Verify against the pinned crate version.

---

## Merkle root computation

For `shard_preview` computation, reuse `daemon::merkle::merkle_root`:

```rust
use crate::daemon::merkle;

let root = merkle::merkle_root(&shard_bytes);
```

This is the same function used by `storage.rs` for PoS. Both sides MUST produce identical
roots from the same bytes — which is guaranteed by using the shared `daemon/merkle.rs` module.

---

## DB operations

Packer reads the `files` table to get `FileRecord` data (path, content_hash, importance).
It does NOT write to the DB — that is Processor's responsibility.

After `pack_batch` returns, Processor calls these DB operations per `PackResult`:

```rust
// 1. Insert the new UnitRecord
db.upsert_unit(&pack_result.unit_record)?;

// 2. Mark files as backed-up (not dirty, update current_unit_id)
//    Use db.mark_file_clean(path, now, unit_id) — exists in db.rs.
//    Takes path: &str (not FileId). Implementer must look up path from FileRecord.
for file_record in &pack_result.file_records {
    db.mark_file_clean(&file_record.path, now, pack_result.unit_record.unit_id)?;
}

// 3. If this unit replaces an old unit for a file: mark old unit Stale
//    (Processor checks FileRecord.current_unit_id before this update)
```

Packer reads from DB in `vacuum_stale_units`:

```rust
// Get unit record
let unit = db.get_unit(&unit_id)?;
// Get file records for each member
for file_id in &unit.member_file_ids {
    let file = db.get_file_by_id(file_id)?;
    // If file.current_unit_id != Some(unit_id): file moved on, skip
}
```

DECISION NEEDED: `db.get_file_by_id(FileId)` — check whether this method exists in the
current `db.rs`. The existing `files` table uses file path as key, not FileId. An index
by FileId may not exist. If it does not exist, the vacuum implementation must either:
  a) Scan all files and filter by file_id (acceptable for alpha, O(n) scan)
  b) Add a secondary index: `file_ids: TableDefinition<&[u8; 8], &str>` mapping FileId → path
  c) Store the file path in UnitRecord.member_file_paths alongside member_file_ids

For alpha, option (a) is simplest. Option (b) adds complexity but fits the ADR-003 secondary
index pattern.

---

## Business rules

### File size decision (pack vs chunk)

```
file.size_bytes < unit_size_bytes  → small file → goes into a pack unit
file.size_bytes >= unit_size_bytes → large file → split into chunk units
```

Default `unit_size_bytes` = 256 MiB = 268_435_456 bytes.

For a large file of size S:
```
chunk_count = ceil(S / unit_size_bytes)
chunks[0..chunk_count-1]: each exactly unit_size_bytes bytes
chunks[chunk_count-1]: remainder bytes (S mod unit_size_bytes, or unit_size_bytes if divisible)
```

### Pack grouping

Group small files into packs not exceeding `unit_size_bytes`:

```
current_pack: []
current_size: 0

for file in sorted_candidates (importance desc, then size asc):
    if current_size + file.size > unit_size_bytes:
        flush current_pack → create unit
        current_pack = [file]
        current_size = file.size
    else:
        current_pack.append(file)
        current_size += file.size

if current_pack non-empty: flush
```

If a single file is smaller than unit_size_bytes but larger than unit_size_bytes * 0.5,
put it in its own pack rather than padding. The 0.5 threshold is approximate — use simple
greedy fill.

### Importance averaging for pack units

```rust
let importance_avg = members.iter().map(|m| m.importance).sum::<f64>() / members.len() as f64;
```

This determines the erasure tier for the pack. Erasure tier is:
```
importance >= 0.8 → High  → k=5, n_base=15
importance >= 0.4 → Mid   → k=5, n_base=10
importance >= 0.1 → Low   → k=5, n_base=7
```

Adaptive n (additional shards for low trust): this is determined by `PlacementEngine`, not
Packer. Packer uses the base n from the tier. ShardManager's call to
`placement.select_holders(unit_id, importance)` applies adaptive n adjustment.

### Content hash verification on restore

When `unpack_unit` extracts a file from a pack, it should verify:

```rust
let actual_hash = *blake3::hash(&file_bytes).as_bytes();
if actual_hash != member.content_hash {
    tracing::error!(path = member.path, "unpack: content hash mismatch — corruption detected");
    // In alpha: continue (return the bytes anyway, log the error)
    // Don't panic — partial restore is better than no restore
}
```

### Stale ratio threshold for vacuum

```
stale_ratio = (total_members - live_members) / total_members
if stale_ratio >= STALE_RATIO_THRESHOLD (0.5): repack
```

Where "live members" = files whose `current_unit_id == this_unit_id`.

---

## UnitRecord construction

For each pack unit:

```rust
UnitRecord {
    unit_id,
    unit_type: UnitType::Pack,
    status: UnitStatus::Active,
    member_file_ids: files.iter().map(|f| f.file_id).collect(),
    chunk_index: None,
    parent_file_id: None,
    size_bytes: plaintext.len() as u64,
    plaintext_hash: *blake3::hash(&plaintext).as_bytes(),
    created_at: now,
    importance_avg,
    rs_k: ERASURE_K as u8,  // 5
    rs_n: n_base as u8,     // 7, 10, or 15 (base, before adaptive)
}
```

For each chunk unit:

```rust
UnitRecord {
    unit_id,
    unit_type: UnitType::Chunk,
    status: UnitStatus::Active,
    member_file_ids: vec![file.file_id],
    chunk_index: Some(chunk_index as u32),
    parent_file_id: Some(file.file_id),
    size_bytes: chunk_bytes.len() as u64,
    plaintext_hash: *blake3::hash(&chunk_bytes).as_bytes(),
    created_at: now,
    importance_avg: file.importance,
    rs_k: ERASURE_K as u8,
    rs_n: n_base as u8,
}
```

Note: `rs_n` in `UnitRecord` is the BASE n (before adaptive adjustment). After
`ShardManager::upload_unit` runs, it updates `UnitRecord.rs_n` to the actual n used
(which may be higher due to adaptive n). See `shard_manager.rs` line ~296-299.

---

## File layout

```
crates/syncback/src/daemon/
  packer/
    mod.rs    ← Packer, PackResult, ShardPreview, UnpackResult, UnpackedFile, PackIndex, PackMember, PackerError
    tests.rs  ← all unit tests
```

Declare in `crates/syncback/src/daemon/mod.rs`:

```rust
pub mod packer;
```

---

## Integration with Processor

Phase 3 replaces the stub in `Processor::run_weekly_sync` (the stub logs "would back up"):

```rust
// Phase 3: replace stub with:
let packer = Packer::new(
    self.db.clone(),
    ed25519_dalek::SigningKey::from_bytes(&self.identity_key.to_bytes()),
    self.identity_pub,
    256 * 1024 * 1024,
);

let pack_results = packer.pack_batch(&batch.candidates, now);

for result in pack_results {
    // Write unit record to DB
    self.db.upsert_unit(&result.unit_record)
        .expect("upsert_unit: db error is fatal");

    // Upload shards
    match self.shard_manager.upload_unit(
        result.unit_record.unit_id,
        &result.unit_record,
        &result.plaintext,
        result.importance,
        FileType::User,
        now,
    ).await {
        Ok(placements) => {
            tracing::info!(
                unit_id = %result.unit_record.unit_id,
                shards = placements.len(),
                "weekly sync: unit uploaded"
            );
            // Mark files as backed-up
            for file_record in &result.file_records {
                self.db.mark_file_clean(&file_record.path, now, result.unit_record.unit_id)
                    .expect("mark_file_clean: db error is fatal");
            }
        }
        Err(ShardManagerError::NotEnoughPeers { need, have }) => {
            tracing::info!(need, have, "upload: not enough peers, retry next week");
            // Files remain dirty — will retry
        }
        Err(e) => panic!("upload_unit unexpected error: {e}"),
    }
}
```

`Packer` is constructed fresh per sync cycle (no shared state other than the atomic
counter). Alternatively, hold it in `Processor` as `packer: Packer`. Either approach works.

---

## Test scenarios

Tests live in `crates/syncback/src/daemon/packer/tests.rs`. All tests use real filesystem
(`tempfile::TempDir`) and real DB where needed.

### `pack_unit_single_small_file`

```
Setup:
  TempDir with one file: "foo.txt" containing "hello world" (11 bytes)
  FileRecord { file_id: FileId(1), path: "/tmp/.../foo.txt", size_bytes: 11, importance: 0.9, ... }
  Packer with test identity key

Action:
  packer.pack_unit(&[file_record], importance=0.9, now)

Expected:
  Ok(PackResult)
  result.unit_record.unit_type == UnitType::Pack
  result.unit_record.member_file_ids == [FileId(1)]
  result.unit_record.importance_avg ≈ 0.9
  result.plaintext.len() > 11  (has index prefix)
  result.file_records.len() == 1
  result.file_records[0].file_id == FileId(1)
  result.importance == 0.9
  result.chunk_info == None
```

### `pack_unit_multiple_files_index_round_trip`

```
Setup:
  3 files in TempDir: sizes 1000, 2000, 3000 bytes, distinct content
  FileRecords for each

Action:
  packer.pack_unit(&[file0, file1, file2], importance=0.5, now)
  // then unpack:
  // produce k shards from plaintext, pass to unpack_unit
  packer.unpack_unit(unit_id, UnitType::Pack, shard_blobs, k, n)

Expected:
  unpack returns UnpackResult with 3 files
  file bytes match original content exactly
  file paths match PackMember.path values
  content hashes match
```

### `chunk_file_splits_large_file`

```
Setup:
  Large file: 300 MiB of deterministic bytes (e.g., repeating 0x42)
  unit_size_bytes = 256 MiB

Action:
  packer.chunk_file(&file_record, now)

Expected:
  Ok(vec) with 2 elements (chunks)
  chunks[0].unit_record.unit_type == UnitType::Chunk
  chunks[0].unit_record.chunk_index == Some(0)
  chunks[1].unit_record.chunk_index == Some(1)
  chunks[0].plaintext.len() == 256 * 1024 * 1024
  chunks[1].plaintext.len() == (300 - 256) * 1024 * 1024
  both have parent_file_id == file_record.file_id
```

### `chunk_file_exact_unit_size_produces_one_chunk`

```
Setup:
  File exactly 256 MiB

Expected:
  Ok(vec) with 1 element
  chunk_index = Some(0)
```

### `derive_unit_key_is_deterministic`

```
Setup:
  Fixed identity key (from_bytes([1u8; 32]))
  Fixed unit_id (UnitId([2u8; 32]))

Action:
  let k1 = packer.derive_unit_key(unit_id);
  let k2 = packer.derive_unit_key(unit_id);

Expected:
  k1 == k2
  k1 != [0u8; 32]  (not trivially zero)
```

### `derive_unit_key_differs_per_unit`

```
Action:
  k1 = packer.derive_unit_key(UnitId([1u8; 32]))
  k2 = packer.derive_unit_key(UnitId([2u8; 32]))

Expected:
  k1 != k2
```

### `pack_unit_id_is_unique_per_call`

```
Setup:
  Two distinct file sets

Action:
  r1 = packer.pack_unit(&files_a, 0.5, now)
  r2 = packer.pack_unit(&files_b, 0.5, now)

Expected:
  r1.unit_record.unit_id != r2.unit_record.unit_id
```

### `chunk_unit_id_stable_for_same_content`

```
Setup:
  File with known content_hash
  chunk_index = 0

Action:
  r1 = packer.chunk_file(&file, now)
  r2 = packer.chunk_file(&file, now)   // same file, same content

Expected:
  r1[0].unit_record.unit_id == r2[0].unit_record.unit_id
  (deterministic from content_hash + chunk_index)
```

### `unpack_unit_recovers_from_k_of_n_shards`

```
Setup:
  3 files packed into one unit → PackResult with k=5, n=7
  Simulate 2 shard losses (indices 0 and 3 → set to None)
  5 shards remain (sufficient)

Action:
  packer.unpack_unit(unit_id, UnitType::Pack, shard_blobs_with_2_nones, k=5, n=7)

Expected:
  Ok(UnpackResult) with 3 files
  File bytes match originals
```

### `unpack_unit_fails_below_k`

```
Setup:
  k=5, n=7, but only 4 Some shards

Action:
  packer.unpack_unit(..., shard_blobs_with_4_nones, k=5, n=7)

Expected:
  Err(PackerError::NotEnoughShards { need: 5, have: 3 })
```

### `pack_batch_groups_small_files`

```
Setup:
  4 files, each ~100 MiB, unit_size_bytes=256 MiB

Expected:
  pack_batch returns 2 PackResults
  first PackResult has 2 member files (~200 MiB)
  second PackResult has 2 member files (~200 MiB)
  (greedy fill: 100+100=200 < 256, so pack together; third file brings 300 > 256 → new pack)
```

### `pack_batch_chunks_large_file`

```
Setup:
  1 file of 700 MiB, unit_size_bytes=256 MiB

Expected:
  pack_batch returns 3 PackResults (3 chunks)
  all have unit_type == Chunk
  sizes: 256, 256, 188 MiB
```

### `pack_batch_mixed_files`

```
Setup:
  2 small files (50 MiB each) + 1 large file (300 MiB), unit_size_bytes=256 MiB

Expected:
  3 PackResults:
    PackResult 0: Pack containing both small files (100 MiB total)
    PackResult 1: Chunk 0 of large file (256 MiB)
    PackResult 2: Chunk 1 of large file (44 MiB)
```

### `pack_index_round_trip_cbor`

```
// Test PackIndex CBOR serialization independently
let index = PackIndex {
    version: 1,
    members: vec![
        PackMember { path: "/foo".into(), file_id: 1, offset: 0, length: 100,
                     content_hash: [0u8; 32], importance: 0.5 },
    ],
};
let bytes = ciborium::ser::to_vec(&index)?;
let decoded: PackIndex = ciborium::de::from_reader(bytes.as_slice())?;
assert_eq!(decoded.members[0].path, "/foo");
```

### `encrypt_decrypt_roundtrip`

```
let key = [0xabu8; 32];
let plaintext = b"test plaintext";
let ciphertext = encrypt_plaintext(&key, plaintext).unwrap();
assert_ne!(ciphertext, plaintext);
let recovered = decrypt_ciphertext(&key, &ciphertext).unwrap();
assert_eq!(recovered, plaintext);
```

### `encrypt_decrypt_different_nonces`

```
// Two encryptions of same plaintext produce different ciphertext (random nonce)
let key = [0u8; 32];
let c1 = encrypt_plaintext(&key, b"test").unwrap();
let c2 = encrypt_plaintext(&key, b"test").unwrap();
assert_ne!(c1, c2);  // different nonces
// Both decrypt to same plaintext
assert_eq!(decrypt_ciphertext(&key, &c1).unwrap(), b"test");
assert_eq!(decrypt_ciphertext(&key, &c2).unwrap(), b"test");
```

### `unpack_unit_detects_wrong_importance`

```
// Not a test for packer itself, but documents the limitation:
// Packer trusts PackIndex.content_hash for integrity.
// It does NOT re-verify importance (that's in ShardDescriptor, verified by storage.rs).
```

---

## Implementation notes

### 1. Crypto code reuse vs duplication

`ShardManager` already has `encrypt_unit`, `decrypt_unit`, `encode_unit` as private `fn`
items. Packer needs the same logic. Options:

  a) **Move to a shared `crates/syncback/src/daemon/crypto.rs` module** — `pub(crate)` functions
     used by both `packer` and `shard_manager`. Cleanest, no duplication.
  b) **Duplicate in packer** — simpler to implement, risk of divergence.
  c) **Expose shard_manager helpers as `pub(crate)`** — avoids a new file but couples modules.

**Recommendation: option (a).** Create `crates/syncback/src/daemon/crypto.rs` with:

```rust
pub(crate) const FILE_ENCRYPTION_INFO: &[u8] = b"syncback-file-encryption";

pub(crate) fn derive_unit_key(identity_key_bytes: &[u8; 32], unit_id: UnitId) -> [u8; 32];
pub(crate) fn encrypt_plaintext(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
pub(crate) fn decrypt_ciphertext(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, CryptoError>;
pub(crate) fn rs_encode(ciphertext: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, CryptoError>;
pub(crate) fn rs_decode(shards: Vec<Option<Vec<u8>>>, k: usize, n: usize) -> Result<Vec<u8>, CryptoError>;
```

Both `shard_manager` and `packer` import from `daemon::crypto`. Shard_manager's existing
private implementations become thin wrappers or are replaced. This is a refactor, but a
small one.

If the implementer prefers to avoid touching shard_manager, option (b) is acceptable for
Phase 3 — just note the duplication with a `// TODO: consolidate with shard_manager` comment.

### 2. Large file reads

For chunk_file, the file may be very large (many GiB). Do NOT read the entire file at once:

```rust
let mut file = std::fs::File::open(&path)?;
let mut chunk_buf = vec![0u8; self.unit_size_bytes as usize];
let mut chunk_index = 0u32;
let mut results = Vec::new();

loop {
    let bytes_read = std::io::Read::read(&mut file, &mut chunk_buf)?;
    if bytes_read == 0 { break; }
    let chunk = &chunk_buf[..bytes_read];
    // process chunk...
    chunk_index += 1;
}
```

### 3. Atomic counter for pack UnitId

```rust
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Packer {
    // ...
    unit_counter: AtomicU64,
}

impl Packer {
    pub fn new(...) -> Self {
        Packer {
            // ...
            unit_counter: AtomicU64::new(0),
        }
    }
}
```

This counter resets on daemon restart. Since pack UnitIds don't need to survive restarts
(new packs get new IDs), this is fine.

### 4. Pack_batch error handling

If reading one file fails during `pack_batch`, log the error and skip that file (it remains
dirty). Do not abort the entire batch. Return Ok with the successful PackResults.

```rust
pub fn pack_batch(&self, candidates: &[BackupCandidate], now: Timestamp) -> Vec<PackResult> {
    let mut results = Vec::new();
    // ... group files ...
    for group in groups {
        match self.pack_unit(&group.files, group.importance, now) {
            Ok(r) => results.push(r),
            Err(PackerError::FileMissing(p)) => {
                tracing::debug!(path = ?p, "pack_batch: file missing, skipping");
            }
            Err(PackerError::Io { path, source }) => {
                tracing::debug!(path = ?path, err = %source, "pack_batch: io error, skipping");
            }
            Err(e) => panic!("pack_batch unexpected error: {e}"),
        }
    }
    results
}
```

### 5. Processor changes for Phase 3

Phase 3 implementer must also modify `Processor::run_weekly_sync` to replace the stub
(lines ~219-228 in processor/mod.rs) with actual packer calls. The Processor holds a
`Packer` instance or constructs one on demand.

Adding `packer: Packer` to `Processor` struct requires the `identity_key` to be
accessible. Currently `identity_key` is passed to `ShardManager`. Processor should clone
it before passing to ShardManager and store a copy for Packer (same key bytes, two
`SigningKey` instances).

### 6. `mark_file_clean` DB method

This method already exists in `db.rs` (line ~224):

```rust
pub fn mark_file_clean(&self, path: &str, ts: Timestamp, unit_id: UnitId) -> Result<(), DbError>
```

It sets `dirty=false`, `last_backed_up=Some(ts)`, `backed_up=true`,
`current_unit_id=Some(unit_id)`, and removes the path from `DIRTY_FILES` index.

The method takes `path: &str` (not `FileId`). This is why `PackResult.file_records`
carries the full `FileRecord` — so Processor can pass `file_record.path` directly.

### 7. PackIndex CBOR size

For 256 MiB packs with potentially thousands of small files, the PackIndex CBOR header may
be several KB. This is negligible compared to the data. No need to compress the index.

---

## Constants

```rust
const FILE_ENCRYPTION_INFO: &[u8] = b"syncback-file-encryption";
const DEFAULT_UNIT_SIZE_BYTES: u64 = 256 * 1024 * 1024;  // 256 MiB
const STALE_RATIO_THRESHOLD: f64 = 0.5;
const PACK_INDEX_VERSION: u8 = 1;
```

Import from `syncback_core::constants`:
- `ERASURE_K` — k for all tiers (= 5)
- `TIER_HIGH_N`, `TIER_MID_N`, `TIER_LOW_N` — n_base per tier
- `TIER_HIGH_THRESHOLD`, `TIER_MID_THRESHOLD`, `TIER_LOW_THRESHOLD` — importance cutoffs

---

## Dependencies checklist

Phase 3 implementer must verify these exist before starting:

| Dependency | Status | Note |
|---|---|---|
| `daemon/merkle.rs` | Exists (Phase 2) | `merkle_root`, `BLOCK_SIZE` |
| `daemon/shard_manager/mod.rs` | Exists (Phase 2) | `ShardManager::upload_unit` |
| `types::UnitRecord`, `UnitType`, `UnitStatus` | Exists | In core/types |
| `types::FileRecord`, `FileId` | Exists | In core/types |
| `db::Db::upsert_unit` | Exists | In core/db |
| `db::Db::list_dirty_files` | Exists | In core/db |
| `db::Db::mark_file_clean` | Exists | Used to clear dirty flag + set current_unit_id |
| `budget::BackupCandidate` | Exists (Phase 1) | Used by Packer |
| `daemon::crypto` | Does not exist | Implementer creates (or duplicates) |
