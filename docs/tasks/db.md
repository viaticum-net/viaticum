# Task spec: db.rs

**Module:** `crates/syncback-core/src/db.rs`
**Phase:** 1 (second module — implement after types.rs is complete)
**Implements:** `Db` newtype over `Arc<redb::Database>`, all table definitions, all CRUD operations

---

## Overview

`db.rs` is the single point of access to the redb database. Every other module gets a `Db` handle and uses it. There is no other way to read or write persistent state.

The module owns:
- Table constant definitions (redb `TableDefinition`)
- The `Db` newtype wrapper
- All read and write methods for every table

This module contains NO business logic. It does not decide what to write — it only executes what callers ask. Decisions about trust formulas, eviction, etc. live in their own modules.

---

## Dependencies

**Modules in crate:**
- `types.rs` — all record types and ID newtypes

**Crate dependencies:**
- `redb` — embedded key-value database
- `serde` — for CBOR value encoding
- `ciborium` — CBOR encoder/decoder (via `types::to_cbor_bytes` / `types::from_cbor_bytes`)
- `thiserror`
- `tracing`

---

## redb key encoding conventions

| Type | Encoding as redb key |
|------|---------------------|
| `ShardId` | `&[u8; 32]` — raw bytes |
| `UnitId` | `&[u8; 32]` — raw bytes |
| `IdentityPub` | `&[u8; 32]` — raw bytes |
| `FileId` | `u64` big-endian via `redb::Value for u64` |
| `String` / `&str` | `&str` |

redb values: all values are CBOR-encoded using `types::to_cbor_bytes` → stored as `&[u8]`. Decoded with `types::from_cbor_bytes`.

The redb type for values is `&[u8]` (the built-in `redb::Value` impl). Keys use the most compact representation: `[u8; 32]` for fixed-size IDs, `u64` for `FileId`, `&str` for named keys.

---

## Table definitions

These are `redb::TableDefinition` constants, defined at module scope. They encode the key and value types for redb.

```rust
use redb::{TableDefinition, MultimapTableDefinition};

/// Primary file index. Key = file path (UTF-8). Value = CBOR(FileRecord).
const FILES: TableDefinition<&str, &[u8]> = TableDefinition::new("files");

/// Unit records. Key = UnitId bytes. Value = CBOR(UnitRecord).
const UNITS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("units");

/// Shard records (owner view). Key = ShardId bytes. Value = CBOR(ShardRecord).
const SHARDS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("shards");

/// Peer records. Key = IdentityPub bytes. Value = CBOR(PeerRecord).
const PEERS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("peers");

/// Holding records (holder view). Key = ShardId bytes. Value = CBOR(HoldingRecord).
const HOLDING: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("holding");

/// Budget singleton. Key = "budget". Value = CBOR(BudgetRecord).
const BUDGET: TableDefinition<&str, &[u8]> = TableDefinition::new("budget");

/// Scheduler state. Key = task name. Value = CBOR(ScheduleRecord).
const SCHEDULE: TableDefinition<&str, &[u8]> = TableDefinition::new("schedule");

/// Generic config store. Key = config key. Value = CBOR bytes (caller decides type).
const CONFIG: TableDefinition<&str, &[u8]> = TableDefinition::new("config");

// --- Secondary index tables (hot paths) ---

/// Dirty file index. Key = file path. Value = timestamp (u64 BE seconds).
/// Entry present ↔ file is dirty. Removed when file is backed up.
const DIRTY_FILES: TableDefinition<&str, u64> = TableDefinition::new("dirty_files");

/// Stale unit index. Key = UnitId bytes. Value = stale_ratio (f64 as u64 bits).
/// Entry present ↔ unit is Stale.
const STALE_UNITS: TableDefinition<&[u8; 32], u64> = TableDefinition::new("stale_units");

/// Shards due for PoS verification. Key = ShardId bytes. Value = last_verified ts (u64).
/// Entry present ↔ shard is Stored and PoS is needed.
const UNVERIFIED_SHARDS: TableDefinition<&[u8; 32], u64> = TableDefinition::new("unverified_shards");
```

All 11 tables must be created on `Db::open` within a single write transaction.

---

## Public API

### `Db` type

```rust
/// Cheaply cloneable handle to the database.
/// Arc inside: clone() does not copy the database, it increments a refcount.
/// All methods take &self — redb's internal MVCC handles concurrency.
#[derive(Clone)]
pub struct Db {
    inner: Arc<redb::Database>,
}

impl Db {
    /// Open (or create) a database at the given path.
    /// Creates all tables if they do not exist.
    /// Panics if the path is unwritable or the database is corrupt —
    /// these are fatal errors the daemon cannot recover from.
    pub fn open(path: &std::path::Path) -> Result<Self, DbError>;
}
```

### `DbError`

```rust
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("redb error: {0}")]
    Redb(#[from] redb::Error),

    #[error("redb transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),

    #[error("redb table error: {0}")]
    Table(#[from] redb::TableError),

    #[error("redb storage error: {0}")]
    Storage(#[from] redb::StorageError),

    #[error("redb commit error: {0}")]
    Commit(#[from] redb::CommitError),

    #[error("cbor decode: {0}")]
    Cbor(#[from] crate::types::CborError),

    #[error("record not found: {0}")]
    NotFound(String),
}
```

Note: redb has several distinct error types (`TransactionError`, `TableError`, `StorageError`, `CommitError`). All are wrapped individually so callers can match on them if needed. In practice, most callers in alpha use `.expect()` on DB operations.

### Files table

```rust
impl Db {
    /// Insert or replace a file record.
    pub fn upsert_file(&self, record: &FileRecord) -> Result<(), DbError>;

    /// Get a file record by path. Returns None if not found.
    pub fn get_file(&self, path: &str) -> Result<Option<FileRecord>, DbError>;

    /// Get a file record by FileId.
    /// Scans the files table — O(n). Acceptable because FileId lookup is rare
    /// (only needed during unit assembly; normal lookup is by path).
    pub fn get_file_by_id(&self, file_id: FileId) -> Result<Option<FileRecord>, DbError>;

    /// Delete a file record by path. No-op if not found.
    pub fn delete_file(&self, path: &str) -> Result<(), DbError>;

    /// Mark file as dirty (changed, needs backup).
    /// Updates dirty=true in FileRecord AND inserts into dirty_files index.
    pub fn mark_file_dirty(&self, path: &str, ts: Timestamp) -> Result<(), DbError>;

    /// Mark file as clean (successfully backed up).
    /// Updates dirty=false, last_backed_up, backed_up=true in FileRecord.
    /// Removes from dirty_files index.
    pub fn mark_file_clean(&self, path: &str, ts: Timestamp, unit_id: UnitId) -> Result<(), DbError>;

    /// Return all dirty file paths, ordered by their dirty timestamp (oldest first).
    pub fn list_dirty_files(&self) -> Result<Vec<String>, DbError>;

    /// Return all file records. Used by budget planner and weekly sync.
    pub fn list_all_files(&self) -> Result<Vec<FileRecord>, DbError>;
}
```

### Units table

```rust
impl Db {
    pub fn upsert_unit(&self, record: &UnitRecord) -> Result<(), DbError>;
    pub fn get_unit(&self, unit_id: &UnitId) -> Result<Option<UnitRecord>, DbError>;
    pub fn delete_unit(&self, unit_id: &UnitId) -> Result<(), DbError>;

    /// Mark unit as stale. Updates UnitRecord.status=Stale AND upserts stale_units index.
    /// stale_ratio = stale_member_count / total_member_count (caller computes this).
    pub fn mark_unit_stale(&self, unit_id: &UnitId, stale_ratio: f64) -> Result<(), DbError>;

    /// Return all stale unit IDs, ordered by stale_ratio descending (most stale first).
    /// Used by vacuum cycle to find units worth repacking.
    pub fn list_stale_units(&self) -> Result<Vec<(UnitId, f64)>, DbError>;

    /// Return all units with a given status.
    pub fn list_units_by_status(&self, status: UnitStatus) -> Result<Vec<UnitRecord>, DbError>;
}
```

### Shards table (owner view)

```rust
impl Db {
    pub fn upsert_shard(&self, record: &ShardRecord) -> Result<(), DbError>;
    pub fn get_shard(&self, shard_id: &ShardId) -> Result<Option<ShardRecord>, DbError>;
    pub fn delete_shard(&self, shard_id: &ShardId) -> Result<(), DbError>;

    /// Return all ShardRecords for a given unit.
    /// Used by repair check: how many live shards does unit X have?
    pub fn list_shards_for_unit(&self, unit_id: &UnitId) -> Result<Vec<ShardRecord>, DbError>;

    /// Return all ShardRecords for a given holder.
    /// Used when a holder peer is lost: which of our shards do we need to repair?
    pub fn list_shards_for_holder(&self, holder_id: &IdentityPub) -> Result<Vec<ShardRecord>, DbError>;

    /// Return shards due for PoS challenge (last_verified is None or older than given threshold).
    /// Returns up to `limit` shard IDs.
    pub fn list_shards_needing_pos(&self, older_than: Timestamp, limit: usize) -> Result<Vec<ShardId>, DbError>;

    /// Update last_verified timestamp and remove from unverified_shards index.
    pub fn record_pos_verified(&self, shard_id: &ShardId, ts: Timestamp) -> Result<(), DbError>;

    /// Update shard status.
    pub fn update_shard_status(&self, shard_id: &ShardId, status: ShardStatus) -> Result<(), DbError>;
}
```

### Peers table

```rust
impl Db {
    pub fn upsert_peer(&self, record: &PeerRecord) -> Result<(), DbError>;
    pub fn get_peer(&self, identity: &IdentityPub) -> Result<Option<PeerRecord>, DbError>;
    pub fn delete_peer(&self, identity: &IdentityPub) -> Result<(), DbError>;

    /// Return all peer records.
    pub fn list_all_peers(&self) -> Result<Vec<PeerRecord>, DbError>;

    /// Return peers with trust_p >= min_p, ordered by composite trust score descending.
    /// Used by placement to find candidate holders.
    /// Composite = (0.4 * trust_p + 1.75 * trust_i) * clamp(trust_s, 0.1, 1.0)
    /// (weights from trust formula defaults kp=0.4, ki=1.75 — see trust.rs spec)
    /// NOTE: This method does not compute weights itself. It returns all peers sorted
    /// by a simple heuristic. The exact placement weighting is in placement.rs.
    /// This method returns all peers; the caller filters by trust threshold.
    pub fn list_peers_by_trust(&self) -> Result<Vec<PeerRecord>, DbError>;

    /// Update trust components for a peer. Peer must already exist.
    pub fn update_peer_trust(
        &self,
        identity: &IdentityPub,
        trust_p: f64,
        trust_i: f64,
        trust_s: f64,
    ) -> Result<(), DbError>;

    /// Update last_seen timestamp. Creates the record if it does not exist.
    pub fn touch_peer(&self, identity: &IdentityPub, ts: Timestamp) -> Result<(), DbError>;

    /// Increment weeks_in_network by 1 for a peer. Used by weekly trust update.
    pub fn increment_peer_weeks(&self, identity: &IdentityPub) -> Result<(), DbError>;
}
```

### Holding table (holder view)

```rust
impl Db {
    pub fn upsert_holding(&self, record: &HoldingRecord) -> Result<(), DbError>;
    pub fn get_holding(&self, shard_id: &ShardId) -> Result<Option<HoldingRecord>, DbError>;
    pub fn delete_holding(&self, shard_id: &ShardId) -> Result<(), DbError>;

    /// Return all holding records for a given owner.
    pub fn list_holding_for_owner(&self, owner_pub: &IdentityPub) -> Result<Vec<HoldingRecord>, DbError>;

    /// Return all active holding records, ordered by (importance ASC, received_at ASC).
    /// This is the eviction candidate order: lowest importance + oldest first.
    /// Used by disk pressure eviction.
    pub fn list_holding_for_eviction(&self) -> Result<Vec<HoldingRecord>, DbError>;

    /// Return total bytes currently held (sum of size_bytes where state != ShardState::Deleted effectively).
    /// Only counts Active and MarkedForDelete and Silent states.
    pub fn total_holding_bytes(&self) -> Result<u64, DbError>;

    /// Set shard state to MarkedForDelete, record delete_requested_at.
    pub fn mark_holding_for_delete(&self, shard_id: &ShardId, ts: Timestamp) -> Result<(), DbError>;

    /// Set drop_notice_deadline on a holding record.
    pub fn set_drop_notice_deadline(&self, shard_id: &ShardId, deadline: Timestamp) -> Result<(), DbError>;

    /// Return holding records whose delete_requested_at + 4 weeks <= now.
    /// These are ready for actual deletion.
    pub fn list_holding_cooldown_expired(&self, now: Timestamp) -> Result<Vec<HoldingRecord>, DbError>;

    /// Return holding records whose drop_notice_deadline <= now.
    /// Phase 2 eviction: time to actually drop.
    pub fn list_holding_drop_notice_expired(&self, now: Timestamp) -> Result<Vec<HoldingRecord>, DbError>;
}
```

### Budget table

```rust
impl Db {
    /// Get the budget record. Returns None on first run (before any estimation).
    pub fn get_budget(&self) -> Result<Option<BudgetRecord>, DbError>;

    /// Replace the budget record.
    pub fn set_budget(&self, record: &BudgetRecord) -> Result<(), DbError>;
}
```

### Schedule table

```rust
impl Db {
    pub fn get_schedule(&self, task_name: &str) -> Result<Option<ScheduleRecord>, DbError>;
    pub fn set_schedule(&self, record: &ScheduleRecord) -> Result<(), DbError>;
    pub fn list_all_schedules(&self) -> Result<Vec<ScheduleRecord>, DbError>;
}
```

### Config table

```rust
impl Db {
    /// Store an arbitrary CBOR-serializable config value.
    pub fn set_config<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<(), DbError>;

    /// Retrieve a config value by key.
    pub fn get_config<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, DbError>;
}
```

---

## DB operations: exact semantics

### Transaction model

Every `upsert_*`, `delete_*`, `mark_*`, `update_*`, `set_*` method opens a **write transaction**, performs the operation, and commits immediately. Methods that update both a primary table and a secondary index table do so in the same transaction — atomically.

Every `get_*`, `list_*` method opens a **read transaction**.

redb's MVCC means read and write transactions do not block each other. This is safe because `Processor` is the sole caller of write methods.

### upsert semantics

All `upsert_*` methods use insert-or-replace semantics. If a record with the same key already exists, it is overwritten.

### Index table invariants

The following invariants must hold after every write operation:

1. `dirty_files[path]` is present ↔ `files[path].dirty == true`
2. `stale_units[unit_id]` is present ↔ `units[unit_id].status == UnitStatus::Stale`
3. `unverified_shards[shard_id]` is present ↔ `shards[shard_id].status == ShardStatus::Stored AND last_verified is None or stale`

Methods that update primary records must update the corresponding index tables in the same transaction. The caller must not maintain these invariants manually.

Specifically:
- `upsert_file`: if `record.dirty`, insert into `dirty_files`; else remove from `dirty_files`
- `mark_file_dirty`: set `dirty=true` in file record AND insert into `dirty_files`
- `mark_file_clean`: set `dirty=false` in file record AND remove from `dirty_files`
- `upsert_unit`: if `record.status == Stale`, upsert `stale_units`; else remove from `stale_units`
- `mark_unit_stale`: set `status=Stale` in unit AND upsert `stale_units`
- `upsert_shard`: if `record.status == Stored AND last_verified is stale`, insert into `unverified_shards`; else remove
- `record_pos_verified`: update `last_verified` in shard AND remove from `unverified_shards`
- `delete_*`: always remove from all relevant index tables

### `list_shards_needing_pos` implementation

This method scans the `unverified_shards` secondary index table and returns shard IDs whose stored value (last_verified timestamp) is less than `older_than.0`. The `limit` parameter caps the result set.

### `list_holding_for_eviction` ordering

The holding table does not have a btree index on `(importance, received_at)`. Therefore `list_holding_for_eviction` performs a full scan of the `holding` table, collects all `HoldingRecord`s with `state != ShardState::Deleted` (in practice, the deleted holding records should be removed by the caller immediately, but be defensive), then sorts by `(importance ASC, received_at ASC)` in memory.

At the scale of this system (thousands of holding records), in-memory sort is acceptable.

### `list_holding_cooldown_expired` implementation

Scans `holding` table. Returns records where:
- `state == ShardState::MarkedForDelete`
- `delete_requested_at.is_some()`
- `delete_requested_at.unwrap().add_weeks(4).0 <= now.0`

The 4-week cooldown (holder side) is a fixed protocol recommendation. See overview.md §2.8.

### `get_file_by_id` implementation

Scans entire `files` table looking for a record whose `file_id` field matches. This is O(n) and intentionally so — callers use this only in non-hot paths (unit assembly). For hot paths, files are looked up by path.

### stale_ratio encoding in `stale_units`

`stale_units` stores `u64` as value. The `f64` stale_ratio is stored as `f64::to_bits()` and recovered with `f64::from_bits()`. This is a lossless encoding.

---

## Db::open implementation

```rust
pub fn open(path: &std::path::Path) -> Result<Self, DbError> {
    let db = redb::Database::create(path)?;
    let tx = db.begin_write()?;
    {
        tx.open_table(FILES)?;
        tx.open_table(UNITS)?;
        tx.open_table(SHARDS)?;
        tx.open_table(PEERS)?;
        tx.open_table(HOLDING)?;
        tx.open_table(BUDGET)?;
        tx.open_table(SCHEDULE)?;
        tx.open_table(CONFIG)?;
        tx.open_table(DIRTY_FILES)?;
        tx.open_table(STALE_UNITS)?;
        tx.open_table(UNVERIFIED_SHARDS)?;
    }
    tx.commit()?;
    Ok(Db { inner: Arc::new(db) })
}
```

`redb::Database::create` opens an existing database or creates a new one. `open_table` inside a write transaction creates the table if it does not exist. This is the idiomatic redb way to ensure all tables exist on startup.

---

## Test scenarios

All tests live in `#[cfg(test)] mod tests` at the bottom of `db.rs`. They use `testutil::test_db()` which opens a redb on a tmpfile.

### `test_db` helper (in testutil.rs)

```rust
pub fn test_db() -> Db {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    // Keep the file alive for the duration of the test.
    // We must leak the NamedTempFile so the path remains valid.
    // Alternative: use Builder::new().keep(true) and clean up manually.
    let path = tmp.path().to_owned();
    std::mem::forget(tmp);
    Db::open(&path).unwrap()
}
```

DECIDED: Return tuple `(Db, NamedTempFile)` — caller keeps `_tmp` alive for test scope:

```rust
pub fn test_db() -> (Db, tempfile::NamedTempFile) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db = Db::open(tmp.path()).unwrap();
    (db, tmp)  // caller keeps tmp alive
}
```

Tests call `let (db, _tmp) = testutil::test_db();`. The `_tmp` binding keeps the file alive for the test's scope.

### `db_opens_and_creates_all_tables`

```rust
let (db, _tmp) = test_db();
// Simply opening without panic is the assertion.
// Additionally: write a record to each table to confirm tables exist.
```

### `file_upsert_and_get_roundtrip`

Construct a `FileRecord`, upsert, get by path, assert all fields equal.

### `file_not_found_returns_none`

```rust
let result = db.get_file("nonexistent/path");
assert!(matches!(result, Ok(None)));
```

### `mark_file_dirty_updates_index`

1. Upsert a FileRecord with `dirty=false`.
2. `mark_file_dirty(path, ts)`.
3. `get_file(path)` → `dirty == true`.
4. `list_dirty_files()` → contains path.

### `mark_file_clean_removes_from_index`

1. Upsert FileRecord with `dirty=true`, insert into dirty_files.
2. `mark_file_clean(path, ts, unit_id)`.
3. `get_file(path)` → `dirty == false`, `last_backed_up == Some(ts)`, `current_unit_id == Some(unit_id)`.
4. `list_dirty_files()` → does NOT contain path.

### `list_dirty_files_returns_oldest_first`

1. Insert 3 dirty files at t=100, t=50, t=200.
2. `list_dirty_files()` → order is t=50, t=100, t=200 (oldest first).

### `unit_upsert_and_get_roundtrip`

Construct a `UnitRecord` with `status=Active`, upsert, get, assert equality.

### `mark_unit_stale_updates_index`

1. Upsert UnitRecord with `status=Active`.
2. `mark_unit_stale(unit_id, 0.4)`.
3. `get_unit(unit_id)` → `status == Stale`.
4. `list_stale_units()` → contains `(unit_id, 0.4)`.

### `upsert_unit_active_removes_from_stale_index`

1. `mark_unit_stale(unit_id, 0.6)`.
2. Get record, set `status=Active`, `upsert_unit`.
3. `list_stale_units()` → does NOT contain unit_id.

### `shard_upsert_and_get_roundtrip`

Construct `ShardRecord` with `status=Stored`, `last_verified=None`, upsert, get, assert equality.

### `list_shards_for_unit_returns_correct_shards`

Insert 5 ShardRecords for unit_id=A and 3 for unit_id=B. `list_shards_for_unit(A)` returns exactly 5, all with unit_id=A.

### `list_shards_needing_pos_respects_threshold`

1. Insert 3 shards: one with `last_verified=None`, one verified at t=100 (old), one verified at t=9999 (recent).
2. `list_shards_needing_pos(older_than=Timestamp(500), limit=10)` → returns 2 shards (the None and the t=100 one).

### `record_pos_verified_updates_shard_and_index`

1. Insert shard with `last_verified=None`, insert into `unverified_shards`.
2. `record_pos_verified(shard_id, ts)`.
3. `get_shard` → `last_verified == Some(ts)`.
4. `list_shards_needing_pos(older_than=ts+1, limit=10)` → does NOT contain this shard.

### `peer_upsert_and_get_roundtrip`

Construct `PeerRecord`, upsert, get, assert equality. Test both `subnet_prefix: Some(...)` and `None` variants.

### `increment_peer_weeks_adds_one`

1. Upsert peer with `weeks_in_network=5`.
2. `increment_peer_weeks(identity)`.
3. `get_peer(identity)` → `weeks_in_network == 6`.

### `increment_peer_weeks_on_missing_peer_returns_error`

```rust
let result = db.increment_peer_weeks(&test_peer(99));
// Peer does not exist. Expected: Err(DbError::NotFound(...))
assert!(matches!(result, Err(DbError::NotFound(_))));
```

### `holding_upsert_and_get_roundtrip`

Construct `HoldingRecord`, upsert, get, assert equality.

### `list_holding_for_eviction_orders_by_importance_then_age`

1. Insert 3 holding records: (importance=0.8, received_at=100), (importance=0.2, received_at=50), (importance=0.2, received_at=200).
2. `list_holding_for_eviction()` → order: (0.2, t=50), (0.2, t=200), (0.8, t=100).

### `total_holding_bytes_sums_correctly`

Insert 3 holding records with `size_bytes` = 100, 200, 300. `total_holding_bytes()` returns 600.

### `mark_holding_for_delete_sets_state_and_timestamp`

1. Upsert holding with `state=Active`.
2. `mark_holding_for_delete(shard_id, ts)`.
3. `get_holding(shard_id)` → `state == MarkedForDelete`, `delete_requested_at == Some(ts)`.

### `list_holding_cooldown_expired_uses_4_week_threshold`

1. Insert holding record with `state=MarkedForDelete`, `delete_requested_at=Timestamp(0)`.
2. `list_holding_cooldown_expired(now=Timestamp(4 * 604800 - 1))` → empty (not yet expired).
3. `list_holding_cooldown_expired(now=Timestamp(4 * 604800))` → contains the record.

### `budget_set_and_get_roundtrip`

```rust
let record = BudgetRecord { estimated_gb: 45.5, last_calculated: Timestamp(1000), placement_success_rate: 0.87 };
db.set_budget(&record).unwrap();
let got = db.get_budget().unwrap().unwrap();
assert_eq!(got.estimated_gb, 45.5);
```

### `budget_get_returns_none_on_fresh_db`

```rust
let (db, _tmp) = test_db();
assert!(matches!(db.get_budget(), Ok(None)));
```

### `schedule_set_and_get_roundtrip`

Upsert a `ScheduleRecord`, get by task_name, assert equality.

### `config_set_and_get_roundtrip`

```rust
db.set_config("storage_quota_gb", &100u64).unwrap();
let val: u64 = db.get_config("storage_quota_gb").unwrap().unwrap();
assert_eq!(val, 100);
```

### `config_get_returns_none_for_missing_key`

```rust
let result: Result<Option<u64>, _> = db.get_config("nonexistent");
assert!(matches!(result, Ok(None)));
```

### `db_open_is_idempotent`

Open the same file twice in sequence (second call after first Db handle is dropped). Both should succeed without error.

---

## Notes for implementer

1. Do not add any business logic to `db.rs`. For example, the 4-week cooldown literal `4 * 604800` that appears in `list_holding_cooldown_expired` is the DB layer implementing the threshold given to it by the caller. In future, this could become a parameter. For now, the spec says 4 weeks (overview.md §2.8, CLAUDE.md).

2. All scan operations (`list_*`) that do not have a secondary index perform a full table scan. This is acceptable: at 500K files, a scan with `FileRecord` deserialization costs ~100ms in the worst case. This is fine for weekly batch operations. Hot paths (dirty files, stale units) use index tables.

3. `list_peers_by_trust` does a full scan of the peers table and sorts in memory. The sort key is: `(trust_p * 0.4 + trust_i * 1.75) * f64::max(trust_s, 0.1)`. This is the trust formula applied inline for sorting. The actual trust score computation lives in `trust.rs`, but `db.rs` needs a sort key. The implementer may use this formula directly in the sort comparator, or simply return all peers unsorted and leave sorting to `placement.rs`. DECIDED: Renamed to `list_all_peers` — already present in the API above. Removed
`list_peers_by_trust` entirely. `placement.rs` calls `list_all_peers()` and sorts by its own
computed trust scores. Trust formula stays out of db.rs.

4. Error handling: all redb calls use `?` to propagate errors. `DbError::NotFound` is returned explicitly from methods that require the record to exist (e.g., `increment_peer_weeks`, `update_peer_trust`).

5. The `stale_ratio` in `stale_units` is stored as `u64` via `f64::to_bits()` / `f64::from_bits()`. Do not cast to `u64` directly — that truncates. Use `.to_bits()`.

6. `list_dirty_files` returns `Vec<String>` (paths), not `Vec<FileRecord>`. The caller (weekly sync) fetches records by path individually, or via `list_all_files` filtered by dirty flag. The index exists to avoid a full-table scan.

7. `touch_peer` creates a minimal PeerRecord if the peer does not exist. Use defaults: `trust_p=0.0, trust_i=0.0, trust_s=0.0, weeks_in_network=0, allowlisted=false, subnet_prefix=None, node_id=None, first_seen=ts`. This supports the scenario where we receive a handshake from an unknown peer and record them before fully processing.

8. `update_shard_status` must also update the `unverified_shards` index consistently (remove if status is no longer `Stored`).

9. When `delete_shard` is called, remove from `unverified_shards` index in the same transaction.

10. When `delete_file` is called, remove from `dirty_files` index in the same transaction.

11. When `delete_unit` is called, remove from `stale_units` index in the same transaction.

12. When `delete_holding` is called, no index tables need updating for holding (the holding table has no secondary indexes in this design).
