# Task spec: system_state module (Phase 4)

**Target file:** `crates/syncback/src/daemon/system_state/mod.rs`
**Tests file:** `crates/syncback/src/daemon/system_state/tests.rs`
**Phase:** 4 (Full Disaster Recovery)
**Role:** Serialize/compress/encrypt the local DB snapshot for distribution as plain copies, and reverse the pipeline on restore.

---

## Overview

`system_state` is the **owner-role** module responsible for turning the local redb database
into a single encrypted blob that can be handed to peers as an opaque backup copy, and for
reversing that process on disaster recovery.

The module is **not a tokio task**. It is a set of pure functions called synchronously from
`Processor` during the weekly sync (backup path) and from the restore CLI command (restore
path). No network I/O, no async.

### Backup pipeline

```
Processor::run_system_state_backup()
    │
    ├─ system_state::snapshot_db(&db)            → SystemState
    ├─ system_state::pack_system_state(&state, &identity_key_bytes)
    │       1. ciborium::ser → CBOR bytes
    │       2. zstd::encode_all(cbor_bytes, level=3) → compressed
    │       3. HKDF-SHA256(ikm=identity_key_bytes, salt=random_24_bytes, info="syncback-system-state") → key [u8;32]
    │       4. ChaCha20-Poly1305 encrypt(compressed) → ciphertext (nonce prepended)
    │       5. Output: [salt(24)] [nonce(12)] [ciphertext+tag]
    │       → encrypted blob Vec<u8>
    │
    └─ Processor sends blob to ~15 peers as plain copies (existing shard upload path,
       file_type=System, ShardDescriptor.importance=1.0)
```

### Restore pipeline

```
CLI: syncback restore-state --seed "witch collapse ..."
    │
    └─ Processor::run_system_state_restore()
           1. Download blob from any peer with file_type=System for our identity
           2. system_state::unpack_system_state(&blob, &identity_key_bytes) → SystemState
           3. system_state::restore_db(&db, &state)
           4. Continue with normal file restore flow
```

### Design: plain copies, NOT Reed-Solomon

System state is stored as ~15 identical plain encrypted copies, one per peer. Any single
online peer can serve the full restore. This is simpler than RS erasure coding and appropriate
because:
- System state is small enough (~13 MB compressed) to send as individual copies
- Redundancy comes from number of copies, not mathematical reconstruction
- A single copy is sufficient; no k-of-n coordination needed

`Processor` handles the distribution logic (how many copies, which peers). This module only
handles the serialization/encryption/deserialization pipeline.

---

## Context: where system_state fits

```
Scheduler → ScheduledCmd::WeeklySync → Processor::run_weekly_sync()
    │
    ├─ [existing] Packer::pack_batch(dirty_files) → file shards
    │
    └─ [new] system_state::snapshot_db(&db)
             system_state::pack_system_state(&state, &identity_key_bytes)
             → Processor distributes blob to ~15 peers via existing upload mechanism
```

On disaster recovery (no existing DB, fresh node):
```
CLI: syncback restore-state
    → Processor connects to seed nodes
    → Finds peers holding file_type=System shards for our identity_pub
    → Downloads one blob
    → system_state::unpack_system_state(blob, identity_key_bytes)
    → system_state::restore_db(&empty_db, &state)
    → Noda now has full knowledge: files, shards, peers, trust
    → Normal file restore flow continues
```

---

## Dependencies

**From syncback-core:**
- `db::Db` — read all tables (snapshot), write all tables (restore)
- `types::{FileRecord, UnitRecord, ShardRecord, PeerRecord, Timestamp}`
- `types::{to_cbor_bytes, from_cbor_bytes, CborError}`

**From syncback daemon (`crate::daemon::crypto`):**
- `crypto::{encrypt_plaintext, decrypt_ciphertext, FILE_ENCRYPTION_INFO}` — reuse the
  existing ChaCha20-Poly1305 encrypt/decrypt. Note: system state uses a DIFFERENT HKDF info
  string, so key derivation is NOT delegated to `derive_unit_key`.

**New external dependency (add to `crates/syncback/Cargo.toml`):**
- `zstd = "0.13"` — zstandard compression. Use `zstd::encode_all` and `zstd::decode_all`.

**Other external crates (already in Cargo.toml):**
- `hkdf::Hkdf`, `sha2::Sha256` — HKDF-SHA256 key derivation
- `rand_core::{OsRng, RngCore}` — random salt
- `ciborium` — CBOR serialization
- `thiserror` — error enum

**Trust module internals (read-only access):**
- `pos_weekly` table accessed directly via `db.inner` — see DB Operations section.

---

## Public API

```rust
// crates/syncback/src/daemon/system_state/mod.rs

use syncback_core::db::Db;
use syncback_core::types::{
    FileRecord, PeerRecord, ShardRecord, Timestamp, UnitRecord,
};

// ============================================================
// HKDF info string for system state (different from file encryption)
// ============================================================

pub(crate) const SYSTEM_STATE_ENCRYPTION_INFO: &[u8] = b"syncback-system-state";

// ============================================================
// Version
// ============================================================

/// Current format version. Increment when the SystemState struct changes
/// in a backward-incompatible way.
pub const SYSTEM_STATE_VERSION: u8 = 1;

// ============================================================
// SystemState struct
// ============================================================

/// Complete serializable snapshot of the node's DB state.
/// This is what gets compressed + encrypted and distributed to peers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemState {
    /// Format version. Current = SYSTEM_STATE_VERSION = 1.
    /// Restore must reject blobs with version > SYSTEM_STATE_VERSION.
    pub version: u8,

    /// Timestamp when this snapshot was taken.
    pub created_at: Timestamp,

    /// All FileRecord entries from the `files` table.
    pub files: Vec<FileRecord>,

    /// All UnitRecord entries from the `units` table.
    pub units: Vec<UnitRecord>,

    /// All ShardRecord entries from the `shards` table (owner view).
    pub shards: Vec<ShardRecord>,

    /// All PeerRecord entries from the `peers` table.
    pub peers: Vec<PeerRecord>,

    /// All PoS weekly records from the `pos_weekly` table.
    /// Stored as raw key-value pairs because the key encoding
    /// ([IdentityPub(32) || week_number_be(4)]) is not part of the record itself.
    pub pos_weekly: Vec<PosWeeklyEntry>,

    /// All entries from the `config` table, as raw key-value CBOR bytes.
    /// Using raw bytes preserves config values exactly without needing
    /// to know their concrete types at snapshot time.
    pub config: Vec<ConfigEntry>,
}

/// One entry from the `pos_weekly` table.
/// Key is stored alongside value because the week number is in the key, not the record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PosWeeklyEntry {
    /// Raw 36-byte key: [identity_pub(32) || week_number_be(4)]
    pub key: [u8; 36],
    /// Raw CBOR bytes of WeeklyPosRecord (opaque to this module).
    pub value: Vec<u8>,
}

/// One entry from the `config` table.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConfigEntry {
    pub key: String,
    /// Raw CBOR bytes of the config value.
    pub value: Vec<u8>,
}

// ============================================================
// Error
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum SystemStateError {
    /// redb DB access failed.
    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),

    /// CBOR serialization/deserialization failed.
    #[error("cbor error: {0}")]
    Cbor(String),

    /// zstd compression failed.
    #[error("compression error: {0}")]
    Compression(String),

    /// zstd decompression failed.
    #[error("decompression error: {0}")]
    Decompression(String),

    /// ChaCha20-Poly1305 encryption/decryption failed (e.g. wrong key, tampered blob).
    #[error("encryption error: {0}")]
    Encryption(String),

    /// Blob is too short to contain the required header (salt + nonce).
    #[error("blob too short: expected at least {expected} bytes, got {got}")]
    BlobTooShort { expected: usize, got: usize },

    /// version field in the deserialized state is newer than this binary can handle.
    #[error("unsupported system state version: {found}, max supported: {max}")]
    UnsupportedVersion { found: u8, max: u8 },

    /// Attempted to restore into a non-empty DB.
    /// Caller must ensure the DB is empty before calling restore_db.
    #[error("db is not empty: restore requires an empty database")]
    DbNotEmpty,
}

// ============================================================
// Core functions
// ============================================================

/// Dump all critical DB tables into a SystemState struct.
///
/// Reads:
///   - `files` table   → state.files
///   - `units` table   → state.units
///   - `shards` table  → state.shards (owner view)
///   - `peers` table   → state.peers
///   - `pos_weekly`    → state.pos_weekly (raw key+value pairs)
///   - `config`        → state.config (raw key+value pairs)
///
/// Tables NOT included (holder-specific, not needed for DR):
///   - `holding` — shards we hold for others. Owners will re-offer when they reconnect.
///   - `budget` — recomputed on first weekly sync.
///   - `schedule` — recomputed on start.
///   - `dirty_files` — secondary index, rebuilt from `files`.
///   - `stale_units` — secondary index, rebuilt from `units`.
///   - `unverified_shards` — secondary index, rebuilt from `shards`.
///   - `escrow_restore_log` — holder-local state, not our concern after DR.
///
/// Never returns an empty error on an empty DB — an empty DB is valid.
pub fn snapshot_db(db: &Db) -> Result<SystemState, SystemStateError>;

/// Serialize, compress, and encrypt a SystemState.
///
/// Steps:
///   1. CBOR-serialize the SystemState → cbor_bytes
///   2. zstd compress cbor_bytes (level 3) → compressed_bytes
///   3. Generate random 24-byte salt with OsRng
///   4. Derive 32-byte encryption key:
///         HKDF-SHA256(ikm = identity_key_bytes, salt = &random_salt, info = b"syncback-system-state")
///   5. Encrypt compressed_bytes with ChaCha20-Poly1305:
///         nonce = random 12 bytes, ciphertext = encrypt(key, nonce, compressed_bytes)
///   6. Output format: [salt(24)] [nonce(12)] [ciphertext + tag(variable)]
///         Total overhead = 24 + 12 + 16 = 52 bytes above compressed size.
///
/// Arguments:
///   - state: the SystemState to pack
///   - identity_key_bytes: raw 32-byte Ed25519 signing key (used as HKDF IKM)
///
/// The same identity_key_bytes used here MUST be used in unpack_system_state for decryption.
pub fn pack_system_state(
    state: &SystemState,
    identity_key_bytes: &[u8; 32],
) -> Result<Vec<u8>, SystemStateError>;

/// Decrypt, decompress, and deserialize an encrypted system state blob.
///
/// Steps:
///   1. Check blob length >= 52 (24 salt + 12 nonce + 16 min ciphertext)
///      → SystemStateError::BlobTooShort if not
///   2. Extract salt = blob[0..24]
///   3. Re-derive encryption key:
///         HKDF-SHA256(ikm = identity_key_bytes, salt = &blob[0..24], info = b"syncback-system-state")
///   4. Decrypt blob[24..] (nonce = blob[24..36] per encrypt_plaintext convention):
///      NOTE: encrypt_plaintext prepends the 12-byte nonce. So the encrypted payload
///      stored after the 24-byte salt is [nonce(12)][ciphertext+tag], which is exactly
///      what encrypt_plaintext returns. Pass blob[24..] directly to decrypt_ciphertext.
///      → SystemStateError::Encryption on auth failure (wrong key or tampered)
///   5. zstd decompress → cbor_bytes
///      → SystemStateError::Decompression on failure
///   6. CBOR deserialize → SystemState
///      → SystemStateError::Cbor on failure
///   7. Check state.version <= SYSTEM_STATE_VERSION
///      → SystemStateError::UnsupportedVersion if version > max
///   8. Return SystemState
pub fn unpack_system_state(
    blob: &[u8],
    identity_key_bytes: &[u8; 32],
) -> Result<SystemState, SystemStateError>;

/// Populate an empty DB from a SystemState.
///
/// Preconditions (checked at runtime):
///   - db.list_all_files()?.is_empty()  — else SystemStateError::DbNotEmpty
///   - db.list_all_peers()?.is_empty()  — else SystemStateError::DbNotEmpty
///
/// Steps (in order):
///   1. Check DB is empty (files + peers)
///   2. For each FileRecord in state.files: db.upsert_file(&record)
///      - Secondary index (dirty_files) is maintained by upsert_file automatically.
///   3. For each UnitRecord in state.units: db.upsert_unit(&record)
///      - Secondary index (stale_units) is maintained by upsert_unit automatically.
///   4. For each ShardRecord in state.shards: db.upsert_shard(&record)
///      - Secondary index (unverified_shards) is maintained by upsert_shard automatically.
///   5. For each PeerRecord in state.peers: db.upsert_peer(&record)
///   6. For each PosWeeklyEntry in state.pos_weekly: write raw key+value to pos_weekly table
///      - Must use db.inner directly (no high-level CRUD for raw pos_weekly writes)
///   7. For each ConfigEntry in state.config: write raw bytes to config table
///      - Use db.inner directly with CONFIG table definition
///
/// On partial failure in the middle of restore: the DB may be in an inconsistent state.
/// Caller (Processor) should either:
///   a. Start with a fresh DB (recommended), or
///   b. Treat the error as fatal and panic (alpha strategy).
///
/// After restore_db returns Ok, all secondary indexes are populated and consistent.
pub fn restore_db(db: &Db, state: &SystemState) -> Result<(), SystemStateError>;
```

---

## Types needed

All types come from `syncback_core` or are defined in this module.

From `syncback_core::types`:
- `FileRecord`, `UnitRecord`, `ShardRecord`, `PeerRecord`, `Timestamp`

From `syncback_core::db`:
- `Db` — for DB access
- `DbError` — wrapped in `SystemStateError::Db`

Defined in this module:
- `SystemState` — the top-level snapshot struct
- `PosWeeklyEntry` — raw key+value pair from pos_weekly table
- `ConfigEntry` — raw key+value pair from config table
- `SystemStateError` — error enum

---

## DB operations

### snapshot_db reads

| Table | Method | Notes |
|---|---|---|
| `files` | `db.list_all_files()` | Returns `Vec<FileRecord>` |
| `units` | `db.list_units_by_status(Active)` + `list_units_by_status(Stale)` + `list_units_by_status(Deleting)` | Or raw scan; see note |
| `shards` | `db.list_all_shards()` | Returns `Vec<ShardRecord>` |
| `peers` | `db.list_all_peers()` | Returns `Vec<PeerRecord>` |
| `pos_weekly` | raw `db.inner.begin_read()?.open_table(POS_WEEKLY)?` | No high-level API; iterate all entries |
| `config` | raw `db.inner.begin_read()?.open_table(CONFIG)?` | No high-level API; iterate all entries |

**Note on units scan:** `db.list_units_by_status` exists for each status individually. To get
ALL units in one pass, either call it three times (Active, Stale, Deleting) and concat, or do
a single raw table scan. Raw scan is preferred to avoid 3 transactions. Use:

```rust
let tx = db.inner.begin_read()?;
let table = tx.open_table(UNITS)?;
let mut units = Vec::new();
for entry in table.iter()? {
    let (_, v) = entry?;
    units.push(from_cbor_bytes::<UnitRecord>(v.value())?);
}
```

Access to `db.inner` is `pub(crate)` — this module is in the same crate (`syncback`).

### restore_db writes

| Table | Method | Notes |
|---|---|---|
| `files` | `db.upsert_file(&record)` per entry | Also updates dirty_files index |
| `units` | `db.upsert_unit(&record)` per entry | Also updates stale_units index |
| `shards` | `db.upsert_shard(&record)` per entry | Also updates unverified_shards index |
| `peers` | `db.upsert_peer(&record)` per entry | |
| `pos_weekly` | raw write via `db.inner.begin_write()?.open_table(POS_WEEKLY)?` | Write `&entry.key` → `entry.value.as_slice()` |
| `config` | raw write via `db.inner.begin_write()?.open_table(CONFIG)?` | Write `entry.key.as_str()` → `entry.value.as_slice()` |

### Table definitions needed

`pos_weekly` and `config` tables are defined in `syncback-core/src/db/mod.rs` but
`pos_weekly` is `pub(crate)`. Since `system_state` is in the `syncback` crate (not
`syncback-core`), it cannot access `POS_WEEKLY` directly.

**Solution:** define local copies of the table definitions inside `system_state/mod.rs`:

```rust
use redb::TableDefinition;
const POS_WEEKLY_LOCAL: TableDefinition<&[u8; 36], &[u8]> =
    TableDefinition::new("pos_weekly");
const CONFIG_LOCAL: TableDefinition<&str, &[u8]> =
    TableDefinition::new("config");
```

The string name must match exactly (`"pos_weekly"`, `"config"`). redb identifies tables by
name string, so this is safe as long as the string matches.

Alternatively, expose `POS_WEEKLY` as `pub` in `syncback-core/src/db/mod.rs`.

DECISION NEEDED: Which approach to use? Option A (local redefine) is zero-change to core.
Option B (expose pub) is cleaner but touches the core crate. For Phase 4, Option A is
recommended to avoid touching passing core tests.

---

## Business rules

### Encryption key derivation

```
key = HKDF-SHA256(
    ikm  = identity_key_bytes,   // 32-byte Ed25519 signing key
    salt = random_24_bytes,       // randomly generated per pack call
    info = b"syncback-system-state"
)
```

The salt is random (not the unit_id, unlike file encryption). This means each call to
`pack_system_state` produces a different ciphertext even for identical input. The salt is
prepended to the output blob so `unpack_system_state` can re-derive the key.

**Why 24-byte salt?** Matches the convention used in file encryption where `unit_id` (32
bytes) is the salt. 24 bytes provides ample entropy. Any length works for HKDF.

Contrast with file encryption (in `crypto.rs`):
```
// File encryption (derive_unit_key):
HKDF-SHA256(ikm=identity_key_bytes, salt=unit_id.0, info=b"syncback-file-encryption")

// System state encryption (this module):
HKDF-SHA256(ikm=identity_key_bytes, salt=random_24_bytes, info=b"syncback-system-state")
```

The different `info` strings guarantee domain separation even if the same salt happened to
be used by both paths.

### Blob format

```
Offset   Length   Content
0        24       Random HKDF salt
24       12       ChaCha20-Poly1305 nonce (from encrypt_plaintext)
36       var      Ciphertext + 16-byte Poly1305 tag
```

`encrypt_plaintext(key, compressed)` returns `[nonce(12)][ciphertext+tag]`.
So the full blob = `salt(24) || encrypt_plaintext_output`.

In `unpack_system_state`: pass `&blob[24..]` directly to `decrypt_ciphertext`.
No need to manually split nonce — `decrypt_ciphertext` already handles that.

Minimum valid blob length: 24 (salt) + 12 (nonce) + 16 (min tag) = 52 bytes.

### Compression

- Algorithm: zstd, level 3 (balances speed vs ratio; cold backup, not latency-sensitive)
- Estimated ratios for system state CBOR: ~4-5x compression typical
  - 53 MB raw → ~13 MB compressed (for 50K files, 500 GB scenario per the spec)
- `zstd::encode_all(reader, level)` — synchronous, in-memory
- `zstd::decode_all(reader)` — synchronous, in-memory
- Compression failure is an OS resource error, not a logic error → `SystemStateError::Compression`

### Version checking

- `SYSTEM_STATE_VERSION = 1` (current)
- On unpack: if `state.version > SYSTEM_STATE_VERSION` → `SystemStateError::UnsupportedVersion`
- If `state.version < SYSTEM_STATE_VERSION`: accept (forward-compatible read). Currently
  version 1 is the only version, so this case won't occur.
- Version is checked AFTER decryption and deserialization, not before.

### DB emptiness check on restore

`restore_db` checks that both `files` and `peers` tables are empty before proceeding. This
is sufficient to detect an accidental restore into a populated DB. Checking all tables would
be redundant.

If the DB is not empty: return `SystemStateError::DbNotEmpty`. Caller panics in alpha
(unexpected state), or operator uses `syncback reset` to wipe the DB first.

### Tables NOT included in snapshot

The following tables are excluded from `SystemState`:
- `holding` — shards held for other peers. These will be re-offered by their owners once
  they detect the shard is gone (via PoS timeout). Including `holding` would inflate the
  snapshot and the data is not owned by us.
- `budget` — derived from peer trust and past offer stats. Recomputed on first weekly sync.
- `schedule` — task run timestamps. Reset to defaults on daemon start.
- `dirty_files`, `stale_units`, `unverified_shards` — secondary indexes. Fully rebuilt by
  `upsert_file`, `upsert_unit`, `upsert_shard` respectively.
- `escrow_restore_log` — our log of bytes we've served to other owners as holder. Not
  needed for our own restore.

### Processor integration (not implemented here, but documented for context)

`Processor` calls this module as follows:

**Backup trigger:** after weekly sync, if files or peers changed:
```rust
let state = system_state::snapshot_db(&self.db)?;
let blob = system_state::pack_system_state(&state, &self.identity_key_bytes)?;
// Send blob to ~15 highest-trust peers via existing ShardManager upload path
// with file_type=FileType::System, importance=1.0
```

**Restore trigger:** `CliCmd::RestoreState` (new CLI command, specified separately):
```rust
// blob downloaded from a peer
let state = system_state::unpack_system_state(&blob, &self.identity_key_bytes)?;
system_state::restore_db(&self.db, &state)?;
```

`Processor` is responsible for deciding when to trigger backup and how many copies to send.
This module is purely functional — it does not schedule itself.

---

## Cargo.toml changes

Add to `crates/syncback/Cargo.toml` under `[dependencies]`:

```toml
zstd = "0.13"
```

No changes needed to `syncback-core/Cargo.toml` — this module lives in `syncback`.

---

## Test scenarios

Tests live in `crates/syncback/src/daemon/system_state/tests.rs`.
Use `syncback_core::testutil::{test_db, test_peer, test_peers}` for setup helpers.

### Helper: `make_populated_db`

```rust
fn make_populated_db() -> (Db, Vec<FileRecord>, Vec<PeerRecord>, Vec<ShardRecord>, Vec<UnitRecord>)
```

Creates a test DB with:
- 3 FileRecords with distinct paths and file_ids
- 2 PeerRecords with trust values
- 1 UnitRecord (Active, Pack type)
- 2 ShardRecords pointing to unit_id above
Returns the DB and the records (for assertion after restore).

### Test 1: `roundtrip_snapshot_pack_unpack_restore`

Full pipeline: snapshot → pack → unpack → restore → verify.

```
1. Build populated DB (files, peers, units, shards)
2. state = snapshot_db(&db) → Ok
3. blob = pack_system_state(&state, &[0u8; 32]) → Ok
4. state2 = unpack_system_state(&blob, &[0u8; 32]) → Ok
5. restore_db(&empty_db, &state2) → Ok
6. Assert:
   - empty_db.list_all_files() == original files (same file_ids, paths, hashes)
   - empty_db.list_all_peers() == original peers (same identity, trust_p/i/s)
   - empty_db.list_all_shards() == original shards
   - empty_db.list_units_by_status(Active) includes original unit
```

### Test 2: `empty_db_roundtrip`

```
1. db = test_db() (no data inserted)
2. state = snapshot_db(&db) → Ok
   - state.files.is_empty()
   - state.units.is_empty()
   - state.shards.is_empty()
   - state.peers.is_empty()
3. blob = pack_system_state(&state, &[1u8; 32]) → Ok
4. state2 = unpack_system_state(&blob, &[1u8; 32]) → Ok
5. restore_db(&test_db(), &state2) → Ok
6. Restored DB is also empty
```

### Test 3: `large_db_roundtrip`

```
1. Build DB with:
   - 1000 FileRecords
   - 200 UnitRecords
   - 3000 ShardRecords
   - 50 PeerRecords
2. snapshot_db → pack → unpack → restore
3. Assert record counts match exactly in restored DB
4. Assert blob size < 5 MB (smoke check: compression is working)
```

### Test 4: `corrupt_blob_fails_gracefully`

```
1. pack_system_state(state, &key) → blob
2. corrupt_blob = blob[..blob.len()-1].to_vec()  // truncate 1 byte
3. unpack_system_state(&corrupt_blob, &key)
   → Err(SystemStateError::Encryption(_))  // Poly1305 auth tag failure
```

Also test random-byte corruption in the middle of the ciphertext:
```
4. corrupted_mid = blob.clone(); corrupted_mid[50] ^= 0xFF;
5. unpack_system_state(&corrupted_mid, &key) → Err(Encryption(_))
```

### Test 5: `wrong_key_fails`

```
1. pack_system_state(&state, &[0u8; 32]) → blob
2. unpack_system_state(&blob, &[1u8; 32])  // different key
   → Err(SystemStateError::Encryption(_))
```

### Test 6: `version_too_new_fails`

```
1. state = snapshot_db(&db)
2. state.version = 255  // future version
3. blob = pack_system_state(&state, &key) → Ok (packing doesn't check version)
4. unpack_system_state(&blob, &key)
   → Err(SystemStateError::UnsupportedVersion { found: 255, max: 1 })
```

### Test 7: `blob_too_short_fails`

```
1. unpack_system_state(&[0u8; 51], &key)  // 51 < 52 minimum
   → Err(SystemStateError::BlobTooShort { expected: 52, got: 51 })
2. unpack_system_state(&[], &key)
   → Err(SystemStateError::BlobTooShort { expected: 52, got: 0 })
```

### Test 8: `restore_into_nonempty_db_fails`

```
1. db = test_db()
2. db.upsert_file(&some_file_record)
3. state = snapshot_db(&test_db())  // empty state
4. restore_db(&db, &state)
   → Err(SystemStateError::DbNotEmpty)
```

### Test 9: `snapshot_excludes_holding_and_budget`

```
1. Build DB with:
   - 1 HoldingRecord (db.upsert_holding)
   - 1 BudgetRecord  (db.set_budget)
2. state = snapshot_db(&db)
3. Assert: state has no "holding" or "budget" fields (they are not in SystemState struct)
4. restore_db(&empty_db, &state)
5. empty_db.list_all_holding() == [] (holding not restored)
6. empty_db.get_budget() == None (budget not restored)
```

### Test 10: `pos_weekly_roundtrip`

```
1. Use TrustEngine to record some PoS outcomes:
   trust_engine.record_pos_outcome(&peer, PosOutcome { week_number: 5, challenged: 10, passed: 8 })
   trust_engine.record_pos_outcome(&peer, PosOutcome { week_number: 6, challenged: 10, passed: 9 })
2. state = snapshot_db(&db)
3. assert state.pos_weekly.len() == 2
4. blob = pack → unpack
5. restore_db(&empty_db, &state2)
6. Verify: TrustEngine::recalculate(&peer, now, 7) on restored DB returns same score
   as on original DB
```

### Test 11: `config_entries_roundtrip`

```
1. db.set_config("storage_quota_gb", &100u64)
2. db.set_config("node_label", &"my-laptop".to_string())
3. state = snapshot_db(&db)
4. assert state.config.len() == 2
5. blob → roundtrip → restore_db
6. db.get_config::<u64>("storage_quota_gb") == Some(100)
7. db.get_config::<String>("node_label") == Some("my-laptop")
```

### Test 12: `pack_is_deterministic_with_same_salt`

This is a property test, not a functional requirement, but useful for debugging.

```
// NOTE: pack_system_state uses a random salt, so two calls produce different blobs.
// This test verifies that the same (state, key) pair is correctly round-trippable
// on repeated calls — not that the output is byte-identical.
1. Pack twice: blob1 = pack(state, key), blob2 = pack(state, key)
2. blob1 != blob2  // random salt guarantees this
3. unpack(blob1, key) and unpack(blob2, key) both produce equal SystemState structs
```

---

## Implementation notes

### Reusing `encrypt_plaintext` / `decrypt_ciphertext`

These functions are in `crates/syncback/src/daemon/crypto.rs` and are `pub(crate)`.
Since `system_state` is in the same crate, they are accessible directly.

The `derive_unit_key` function in `crypto.rs` uses `info=b"syncback-file-encryption"` and
takes a `UnitId` as salt. Do NOT use it for system state. Instead, implement key derivation
inline in `system_state/mod.rs`:

```rust
fn derive_system_state_key(identity_key_bytes: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), identity_key_bytes);
    let mut key = [0u8; 32];
    hk.expand(SYSTEM_STATE_ENCRYPTION_INFO, &mut key)
        .expect("HKDF expand: 32-byte output always valid");
    key
}
```

### Accessing pos_weekly and config tables directly

Since these tables lack high-level DB CRUD methods for bulk operations, use `db.inner`:

```rust
// In snapshot_db — read pos_weekly
let tx = db.inner.begin_read().map_err(|e| SystemStateError::Db(e.into()))?;
let table = tx.open_table(POS_WEEKLY_LOCAL)
    .map_err(|e| SystemStateError::Db(e.into()))?;
let mut pos_weekly = Vec::new();
for entry in table.iter().map_err(|e| SystemStateError::Db(e.into()))? {
    let (k, v) = entry.map_err(|e| SystemStateError::Db(e.into()))?;
    pos_weekly.push(PosWeeklyEntry {
        key: *k.value(),
        value: v.value().to_vec(),
    });
}
```

### zstd usage

```rust
use std::io::Cursor;

// Compress
let compressed = zstd::encode_all(Cursor::new(&cbor_bytes), 3)
    .map_err(|e| SystemStateError::Compression(e.to_string()))?;

// Decompress
let decompressed = zstd::decode_all(Cursor::new(&ciphertext_decrypted))
    .map_err(|e| SystemStateError::Decompression(e.to_string()))?;
```

### Module registration

Add to `crates/syncback/src/daemon/mod.rs`:

```rust
pub(crate) mod system_state;
```

---

## Logging

Follow ADR-003 tracing conventions (no WARN level in alpha):

```rust
// snapshot_db
tracing::info!(files = state.files.len(), peers = state.peers.len(),
    shards = state.shards.len(), "system state snapshot taken");

// pack_system_state
tracing::info!(raw_bytes = cbor_bytes.len(), compressed_bytes = compressed.len(),
    blob_bytes = blob.len(), "system state packed");

// unpack_system_state
tracing::info!(version = state.version, files = state.files.len(),
    peers = state.peers.len(), "system state unpacked");

// restore_db
tracing::info!(files = state.files.len(), peers = state.peers.len(),
    shards = state.shards.len(), "system state restored to DB");
```

---

## File layout

```
crates/syncback/src/daemon/
  system_state/
    mod.rs     ← all public API + implementation
    tests.rs   ← all tests (included via #[cfg(test)] mod tests; in mod.rs)
```

Per project convention (from CLAUDE.md feedback): always `module/mod.rs` + `module/tests.rs`,
not inline tests.
