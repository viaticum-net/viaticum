# Task spec: Phase 4 packer updates

**Target files:**
- `crates/syncback-core/src/constants.rs` — change `MAX_MESSAGE_SIZE` and `DEFAULT_UNIT_SIZE_BYTES` constant comment
- `crates/syncback/src/daemon/packer/mod.rs` — change `DEFAULT_UNIT_SIZE_BYTES`, add zstd compression
- `crates/syncback/src/daemon/packer/tests.rs` — update existing tests, add new tests
- `crates/syncback/Cargo.toml` — add `zstd` dependency

**Phase:** 4 (Full Disaster Recovery)

---

## Overview

Three coordinated changes to reduce RAM usage and enable larger inline transfers:

1. `DEFAULT_UNIT_SIZE_BYTES`: 256 MiB → 32 MiB (peak RAM: ~1.3 GB → ~160 MB for 5-of-15 tier)
2. `MAX_MESSAGE_SIZE`: 4 MiB → 64 MiB (enables 6.4 MB shards + ~13 MB compressed system state)
3. zstd compression inserted between plaintext assembly and encryption

The three changes are implemented together because they have a single coherent motivation: make the packer viable for production-scale backups on modest hardware without changing the wire format or DB schema.

---

## Dependencies

No new module dependencies. The `zstd` crate is added only to `crates/syncback/Cargo.toml`.

| Dependency | Role |
|------------|------|
| `zstd` crate (Rust bindings for libzstd) | compress/decompress |
| `crypto` module (existing) | `encrypt_plaintext`, `decrypt_ciphertext`, `rs_encode`, `rs_decode` |
| `constants.rs` | `MAX_MESSAGE_SIZE`, `DEFAULT_UNIT_SIZE_BYTES` |

---

## Change 1: DEFAULT_UNIT_SIZE_BYTES

**File:** `crates/syncback/src/daemon/packer/mod.rs`, line 31.

**Before:**
```rust
/// Default unit size: 256 MiB. Files smaller than this are packed together;
/// files >= this are split into chunks.
pub const DEFAULT_UNIT_SIZE_BYTES: u64 = 256 * 1024 * 1024;
```

**After:**
```rust
/// Default unit size: 32 MiB. Files smaller than this are packed together;
/// files >= this are split into chunks.
///
/// Reduced from 256 MiB in Phase 4. At 32 MiB units with 5-of-15 erasure,
/// each shard is 32 MB / 5 ≈ 6.4 MB (well under MAX_MESSAGE_SIZE = 64 MB).
/// Peak RAM for one unit: ~160 MB vs ~1.3 GB at 256 MiB.
pub const DEFAULT_UNIT_SIZE_BYTES: u64 = 32 * 1024 * 1024;
```

No other code changes required for this constant — all size logic already uses `self.unit_size_bytes` dynamically.

---

## Change 2: MAX_MESSAGE_SIZE

**File:** `crates/syncback-core/src/constants.rs`, line 132.

**Before:**
```rust
/// Max CBOR message frame size (4 MiB).
/// Increased from 64 KiB to accommodate inline shard blob transfers (ShardData).
pub const MAX_MESSAGE_SIZE: u32 = 4 * 1024 * 1024;
```

**After:**
```rust
/// Max CBOR message frame size (64 MiB).
///
/// Must accommodate:
///   - Inline shard transfer: 32 MB unit / 5 shards = 6.4 MB per shard
///   - System state backup: plain-copy files, largest expected ~13 MB compressed
///
/// DoS protection: legitimate messages never approach this ceiling.
pub const MAX_MESSAGE_SIZE: u32 = 64 * 1024 * 1024;
```

This constant is already validated at the call site (network layer). No other code changes needed for this value.

---

## Change 3: zstd compression in packer pipeline

### 3a. Add dependency

In `crates/syncback/Cargo.toml`, add to `[dependencies]`:

```toml
zstd = "0.13"
```

The `zstd` crate wraps libzstd. Version 0.13 is the current stable release. No features needed beyond defaults.

### 3b. Pipeline positions

The compression step slots between plaintext assembly and encryption on the forward path, and between decryption and plaintext parsing on the reverse path.

**Forward path (pack_unit, chunk_file):**
```
read files
  → build plaintext bytes (PackIndex header + file contents, or raw chunk bytes)
  → zstd::encode_all(plaintext, compression_level=3)   ← NEW STEP
  → stored in PackResult.plaintext                      ← field now holds compressed bytes
```

Note: `PackResult.plaintext` changes meaning — it now stores **compressed** bytes. The field name is kept as `plaintext` for API continuity (it is still the pre-encryption payload), but its content is zstd-compressed. The `UnitRecord.plaintext_hash` is computed over the compressed bytes (consistent with what ShardManager will encrypt).

**Reverse path (unpack_unit):**
```
RS decode → ciphertext
  → decrypt → compressed bytes
  → zstd::decode_all(compressed_bytes)   ← NEW STEP
  → unpack_pack_plaintext or return raw bytes
```

**plaintext_to_shards (test helper):**
This helper bypasses packing but is called in tests with pre-built plaintext. It must also compress its input so that the round-trip through `unpack_unit` works correctly:
```
compress(plaintext) → encrypt → rs_encode → shards
```

### 3c. Compression level

Use `zstd` default compression level 3. This is the library default (`zstd::DEFAULT_COMPRESSION_LEVEL` equals 3). It gives a good ratio/speed tradeoff for cold backup (speed not critical, but extreme compression levels waste CPU with marginal gains).

Add a module-level constant:

```rust
const ZSTD_COMPRESSION_LEVEL: i32 = 3;
```

### 3d. Error handling

`zstd` compression and decompression both return `std::io::Error`. Map these to existing error variants:

- Compression failure → `PackerError::Io { path: PathBuf::new(), source }` with an empty path.

DECISION NEEDED: A dedicated `PackerError::Compression(String)` variant may be cleaner since these failures are not file-I/O errors. The implementer should add this variant:

```rust
#[error("zstd compression error: {0}")]
Compression(String),
```

Use it for both compress and decompress failures. This keeps `PackerError::Io` for filesystem errors only.

### 3e. Incompressible data

`zstd` handles random bytes and other incompressible data gracefully. It detects this case internally and adds roughly 8–16 bytes overhead beyond the input size. The compressed output is always valid input to `zstd::decode_all`. No special handling needed.

---

## Exact code changes

### packer/mod.rs

Add import at the top:
```rust
use std::io::Read as _;   // already present
// Add:
// (no explicit import needed; use zstd::encode_all / zstd::decode_all directly)
```

Add constant after `STALE_RATIO_THRESHOLD`:
```rust
/// zstd compression level for unit plaintext. Level 3 = library default.
const ZSTD_COMPRESSION_LEVEL: i32 = 3;
```

Add error variant to `PackerError`:
```rust
#[error("zstd compression error: {0}")]
Compression(String),
```

#### pack_unit: compress after building plaintext

In `pack_unit`, between step 3 (build `plaintext` vec) and step 4 (derive UnitId), add:

```rust
// 3b. Compress the plaintext.
let plaintext = zstd::encode_all(plaintext.as_slice(), ZSTD_COMPRESSION_LEVEL)
    .map_err(|e| PackerError::Compression(e.to_string()))?;
```

The compressed bytes replace the `plaintext` binding. All subsequent uses (`plaintext.len()`, `blake3::hash(&plaintext)`, shard_preview computation) operate on compressed bytes.

#### chunk_file: compress each chunk

In `chunk_file`, after `let chunk_bytes = buf[..bytes_read].to_vec();`, add:

```rust
let chunk_bytes = zstd::encode_all(chunk_bytes.as_slice(), ZSTD_COMPRESSION_LEVEL)
    .map_err(|e| PackerError::Compression(e.to_string()))?;
```

Similarly for the empty-file edge case (compressing an empty slice produces valid zstd output, about 9 bytes):

```rust
let chunk_bytes = zstd::encode_all([].as_slice(), ZSTD_COMPRESSION_LEVEL)
    .map_err(|e| PackerError::Compression(e.to_string()))?;
```

#### unpack_unit: decompress after decrypt

In `unpack_unit`, between step 2 (decrypt → `plaintext`) and step 3 (unpack by unit type), add:

```rust
// 2b. Decompress.
let plaintext = zstd::decode_all(plaintext.as_slice())
    .map_err(|e| PackerError::Compression(e.to_string()))?;
```

The variable name `plaintext` is rebound to the decompressed bytes. The `unpack_pack_plaintext` call and the Chunk raw return both operate on decompressed bytes.

#### plaintext_to_shards: compress before encrypt

```rust
pub fn plaintext_to_shards(
    &self,
    unit_id: UnitId,
    plaintext: &[u8],
    k: usize,
    n: usize,
) -> Result<Vec<Vec<u8>>, PackerError> {
    let compressed = zstd::encode_all(plaintext, ZSTD_COMPRESSION_LEVEL)
        .map_err(|e| PackerError::Compression(e.to_string()))?;
    let ikm: [u8; 32] = self.identity_key.to_bytes();
    let enc_key = crypto::derive_unit_key(&ikm, unit_id);
    let ciphertext = crypto::encrypt_plaintext(&enc_key, &compressed)?;
    let shards = crypto::rs_encode(&ciphertext, k, n)?;
    Ok(shards)
}
```

---

## Public API (unchanged signatures)

None of the function signatures change. The compression is an internal implementation detail. Callers pass and receive the same types as before.

```rust
pub fn pack_unit(
    &self,
    files: &[FileRecord],
    importance: f64,
    now: Timestamp,
) -> Result<PackResult, PackerError>

pub fn chunk_file(
    &self,
    file: &FileRecord,
    now: Timestamp,
) -> Result<Vec<PackResult>, PackerError>

pub fn unpack_unit(
    &self,
    unit_id: UnitId,
    unit_type: UnitType,
    shard_blobs: Vec<Option<Vec<u8>>>,
    k: usize,
    n: usize,
) -> Result<UnpackResult, PackerError>

pub fn plaintext_to_shards(
    &self,
    unit_id: UnitId,
    plaintext: &[u8],
    k: usize,
    n: usize,
) -> Result<Vec<Vec<u8>>, PackerError>

pub fn pack_batch(
    &self,
    candidates: &[BackupCandidate],
    now: Timestamp,
) -> Vec<PackResult>

pub fn vacuum_stale_units(
    &self,
    stale_unit_ids: &[UnitId],
    now: Timestamp,
) -> Result<Vec<PackResult>, PackerError>
```

New error variant added to `PackerError`:
```rust
#[error("zstd compression error: {0}")]
Compression(String),
```

---

## Semantic changes to `PackResult.plaintext`

`PackResult.plaintext` previously held raw (uncompressed) plaintext bytes. After this change it holds **compressed** bytes. Callers of `pack_unit` and `chunk_file` that pass `plaintext` to `ShardManager::upload_unit` are unaffected because `ShardManager` treats the field opaquely (it only encrypts and RS-encodes it). However, any code that currently reads `PackResult.plaintext` and passes it directly to `unpack_pack_plaintext` must first decompress it. Search for all direct uses of `PackResult.plaintext` outside of `ShardManager`.

Currently no caller outside of tests reads `plaintext` directly for parsing — all parsing goes through `unpack_unit`. If this remains true after this change, there is no compatibility issue.

---

## Test changes

### Existing tests to update

All existing tests in `packer/tests.rs` use `shards_from_pack_result` to simulate the ShardManager path. That helper directly calls `crypto::encrypt_plaintext` on `result.plaintext`. After this change, `result.plaintext` is already compressed, so `shards_from_pack_result` is still correct without modification.

The only test that directly inspects the structure of `result.plaintext` is `pack_unit_single_small_file`:

```rust
// Before: "Plaintext has 4-byte prefix + index bytes + file bytes."
assert!(result.plaintext.len() > content.len());
```

After compression this assertion may fail for very small inputs (compression adds overhead for tiny data). Change the assertion to just check that `plaintext` is non-empty:

```rust
// After compression the size is not predictable for small inputs.
assert!(!result.plaintext.is_empty());
```

Also update `make_packer` which hardcodes `DEFAULT_UNIT_SIZE_BYTES`:
```rust
fn make_packer() -> Packer {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db = syncback_core::db::Db::open(tmp.path()).unwrap();
    Packer::new(db, test_identity_key(), test_identity_pub(), DEFAULT_UNIT_SIZE_BYTES)
}
```
This will now use the new 32 MiB constant. Tests that create files smaller than 32 MiB continue to work. Tests using `make_packer_with_unit_size(unit_size)` with a small explicit size are unaffected.

The `pack_batch_chunks_large_file` test creates a file of `2.5 * 1024` bytes with `unit_size=1024`. This remains well below 32 MiB, so it is unaffected.

The `pack_batch_missing_file_skips_gracefully` test passes `DEFAULT_UNIT_SIZE_BYTES` explicitly. Update it to use the constant (it already does), which now equals 32 MiB. No logic change.

### New tests to add

Add all new tests to `crates/syncback/src/daemon/packer/tests.rs` under a new section `// zstd compression tests`.

#### Test 1: compress_decompress_roundtrip_text

Input: 1000 bytes of ASCII text ("Hello SyncBack! ..." repeated).
Expected: `zstd::decode_all(zstd::encode_all(input, 3)?) == input`.

This tests the zstd API at module level, separate from the packer pipeline.

```
fn zstd_compress_decompress_roundtrip_text() {
    let input: Vec<u8> = b"Hello SyncBack backup system! ".iter().cloned().cycle().take(1000).collect();
    let compressed = zstd::encode_all(input.as_slice(), 3).unwrap();
    let decompressed = zstd::decode_all(compressed.as_slice()).unwrap();
    assert_eq!(decompressed, input);
}
```

#### Test 2: compress_decompress_roundtrip_incompressible

Input: 10_000 random bytes (use a fixed seed for reproducibility — fill with `(0..10_000).map(|i| (i * 17 + 3) as u8)`).
Expected: round-trip succeeds; compressed size may be larger than input (acceptable).

```
fn zstd_compress_decompress_roundtrip_incompressible() {
    let input: Vec<u8> = (0..10_000u32).map(|i| (i.wrapping_mul(17).wrapping_add(3)) as u8).collect();
    let compressed = zstd::encode_all(input.as_slice(), 3).unwrap();
    let decompressed = zstd::decode_all(compressed.as_slice()).unwrap();
    assert_eq!(decompressed, input);
    // Compressed size may exceed input for random data — this is acceptable.
    // Just verify we can round-trip.
}
```

#### Test 3: text_data_compresses_smaller

Input: 50_000 bytes of repeating text ("Lorem ipsum dolor sit amet, consectetur...").
Expected: `compressed.len() < input.len()`.

This verifies that zstd achieves meaningful compression for real text data.

```
fn zstd_text_data_compresses_smaller() {
    let template = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
    let input: Vec<u8> = template.iter().cloned().cycle().take(50_000).collect();
    let compressed = zstd::encode_all(input.as_slice(), 3).unwrap();
    assert!(
        compressed.len() < input.len(),
        "expected compression for text: {} → {} bytes",
        input.len(),
        compressed.len()
    );
}
```

#### Test 4: pack_unit_full_pipeline_with_compression

Full pipeline through `pack_unit` + `unpack_unit`, verifying that the compressed round-trip recovers original file contents.

This is a modified version of the existing `unpack_unit_recovers_pack_from_all_shards` test. The existing test already covers this path implicitly (after this change) — add a companion test with text content to verify compression is actually happening:

```
fn pack_unit_roundtrip_with_text_content() {
    let dir = tempfile::TempDir::new().unwrap();
    let content = b"The quick brown fox jumps over the lazy dog. ".iter()
        .cloned().cycle().take(5_000).collect::<Vec<u8>>();
    let file = make_file_record(&dir, "text.txt", &content, 1, 0.9);

    let packer = make_packer();
    let result = packer.pack_unit(&[file.clone()], 0.9, test_timestamp()).unwrap();

    // Verify compression happened: plaintext field should be smaller than uncompressed pack.
    // Uncompressed pack = 4 bytes + CBOR index + 5000 bytes content ≈ 5100+ bytes.
    // Compressed should be significantly smaller for this repeating text.
    let unit_id = result.unit_record.unit_id;
    let (blobs, k, n) = shards_from_pack_result(&packer, &result);

    let unpacked = packer
        .unpack_unit(unit_id, UnitType::Pack, blobs, k, n)
        .unwrap();
    assert_eq!(unpacked.files.len(), 1);
    assert_eq!(unpacked.files[0].bytes, content.as_slice());
}
```

#### Test 5: chunk_file_roundtrip_with_compression

Full round-trip for chunk units with compressed content.

```
fn chunk_file_roundtrip_with_compression() {
    let unit_size: u64 = 1024;
    let dir = tempfile::TempDir::new().unwrap();
    // Compressible content.
    let content: Vec<u8> = (0..unit_size as usize).map(|i| (i % 26) as u8 + b'a').collect();
    let file = make_file_record(&dir, "chunk_text.bin", &content, 1, 0.9);

    let packer = make_packer_with_unit_size(unit_size);
    let results = packer.chunk_file(&file, test_timestamp()).unwrap();
    assert_eq!(results.len(), 1);

    let result = &results[0];
    let unit_id = result.unit_record.unit_id;
    let (blobs, k, n) = shards_from_pack_result(&packer, result);

    let unpacked = packer
        .unpack_unit(unit_id, UnitType::Chunk, blobs, k, n)
        .unwrap();
    assert_eq!(unpacked.files.len(), 1);
    assert!(unpacked.files[0].path.is_none());
    assert_eq!(unpacked.files[0].bytes, content);
}
```

#### Test 6: max_message_size_accommodates_largest_shard

Verify that the maximum shard size (32 MiB unit / 5 k = 6.4 MiB) fits within `MAX_MESSAGE_SIZE` (64 MiB). This is a compile-time math check expressed as a unit test:

```
fn max_message_size_accommodates_largest_shard() {
    use syncback_core::constants::{MAX_MESSAGE_SIZE, ERASURE_K};
    // Worst-case: 32 MiB unit, before compression (incompressible data), k=5.
    // Shard size = unit_size / k (data shards only). Plus encryption overhead (12 + 16 bytes).
    let max_shard_bytes = DEFAULT_UNIT_SIZE_BYTES / ERASURE_K as u64 + 28;
    assert!(
        max_shard_bytes < MAX_MESSAGE_SIZE as u64,
        "shard size {max_shard_bytes} exceeds MAX_MESSAGE_SIZE {MAX_MESSAGE_SIZE}"
    );
}
```

---

## Business rules

### Compression guarantees

- Compression MUST precede encryption. Encrypted data is indistinguishable from random bytes and does not compress.
- zstd MUST be applied to ALL unit types (Pack and Chunk), not selectively.
- `plaintext_to_shards` MUST also compress, or round-trip tests using `unpack_unit` will fail.
- Incompressible data is acceptable — zstd adds minimal overhead and the round-trip always succeeds.

### Unit size arithmetic

With `DEFAULT_UNIT_SIZE_BYTES = 32 MiB` and `ERASURE_K = 5`:

| Erasure tier | n | Shard size (uncompressed) | + Encryption overhead |
|-------------|---|---------------------------|-----------------------|
| High (5-of-15) | 15 | 32 MB / 5 = 6.4 MB | 6.4 MB + 28 bytes |
| Mid (5-of-10) | 10 | 6.4 MB | 6.4 MB + 28 bytes |
| Low (5-of-7) | 7 | 6.4 MB | 6.4 MB + 28 bytes |

All are well below `MAX_MESSAGE_SIZE = 64 MiB`.

For compressible data, shard sizes will be smaller. For incompressible data (JPEG, video), shard sizes may slightly exceed 6.4 MB due to zstd overhead — still well within 64 MiB.

### PackResult.plaintext field semantics

After this change: `PackResult.plaintext` contains **zstd-compressed** bytes. The `UnitRecord.plaintext_hash` (computed as `blake3::hash(&plaintext)` inside `pack_unit`) is therefore the hash of the compressed bytes. This is consistent — whatever hash is stored, it must match what ShardManager passes through the encryption and RS encoding path.

ShardManager receives the compressed bytes as `plaintext`, encrypts them, and RS-encodes them. On restore, ShardManager or `unpack_unit` decrypts, then `unpack_unit` decompresses. The stored `plaintext_hash` in `UnitRecord` is never compared against the decompressed content — it is only used to detect DB corruption at the storage layer.

### Size in UnitRecord

`UnitRecord.size_bytes` is set to `plaintext.len()` inside `pack_unit` and `chunk_file`. After compression this will reflect the **compressed** size. This is a minor semantic change — the field is used by the budget planner for quota accounting. Using compressed size may cause slight underestimation of storage usage, which is acceptable (conservative in the safe direction: we think we have more quota than we do, which leads to slightly more backups, not fewer).

DECISION NEEDED: If accurate uncompressed size accounting is desired for quota purposes, store the uncompressed size separately before compression. For MVP this is not necessary.

---

## Implementation order

Implement in this order to allow incremental testing:

1. Update `MAX_MESSAGE_SIZE` in `constants.rs` — one-line change, no tests needed (covered by `max_message_size_accommodates_largest_shard` in packer tests)
2. Update `DEFAULT_UNIT_SIZE_BYTES` in `packer/mod.rs` — one-line change
3. Add `zstd = "0.13"` to `Cargo.toml`
4. Add `ZSTD_COMPRESSION_LEVEL` constant
5. Add `PackerError::Compression` variant
6. Add compression to `pack_unit`
7. Add compression to `chunk_file` (both normal loop and empty-file edge case)
8. Add decompression to `unpack_unit`
9. Add compression to `plaintext_to_shards`
10. Fix `pack_unit_single_small_file` assertion
11. Add new tests

Run `cargo test -p syncback` after step 9 to verify all existing tests still pass with compression in the pipeline before adding new tests.

---

## Checklist for reviewer

- [ ] `DEFAULT_UNIT_SIZE_BYTES` = `32 * 1024 * 1024` (not 256)
- [ ] `MAX_MESSAGE_SIZE` = `64 * 1024 * 1024` (not 4)
- [ ] `zstd = "0.13"` in `crates/syncback/Cargo.toml` `[dependencies]`
- [ ] `ZSTD_COMPRESSION_LEVEL: i32 = 3` constant present
- [ ] `PackerError::Compression(String)` variant added
- [ ] `pack_unit`: compression happens BEFORE `blake3::hash(&plaintext)` and shard_preview
- [ ] `chunk_file`: compression happens for every chunk including the empty-file edge case
- [ ] `unpack_unit`: decompression happens AFTER `decrypt_ciphertext`, BEFORE `unpack_pack_plaintext`
- [ ] `plaintext_to_shards`: compresses input before encrypting
- [ ] All existing tests pass
- [ ] 6 new tests present and pass
- [ ] `cargo clippy -p syncback -- -D warnings` clean
