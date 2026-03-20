# Task: db — Database layer (β)

Module: `crates/syncback-core/src/db/`
Files: `mod.rs` + `tests.rs`

---

## Overview

Слой хранения для β. Два уровня:

- **WARM (redb):** персистентное хранение всех record'ов. Ключевые таблицы: `files`, `source_blocks`, `symbol_placements`, `peers`, `holdings`, `event_log`, `budget`, `pos_weekly`.
- **HOT (RAM):** агрегаты для быстрых решений. `BlockAgg` и `PlacementAgg` из `types.rs`. Заполняются при открытии БД, обновляются синхронно с каждой write-операцией.

**Ключевые отличия от α:**
- Нет `units`/`shards` таблиц (замена на `source_blocks`/`symbol_placements`).
- Двойной индекс: `file_holders` и `holder_files`.
- `EventLog` — append-only таблица.
- Hot layer в памяти (в α был только redb).
- Поле `FileRecord.devices: Vec<(DeviceId, LocalState)>` для multi-device.

---

## Dependencies

- `crate::types::{...}` — все Record-типы из `types/mod.rs`
- `redb` (embedded database)
- `crate::types::{to_cbor_bytes, from_cbor_bytes}` — CBOR сериализация
- No async. No tokio. Pure sync.

---

## Table Definitions

```rust
use redb::TableDefinition;

/// File catalog. Key = file path (UTF-8). Value = CBOR(FileRecord).
const FILES: TableDefinition<&str, &[u8]> = TableDefinition::new("files");

/// Source block metadata (owner view). Key = SourceBlockId [u8;32]. Value = CBOR(SourceBlockRecord).
const SOURCE_BLOCKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("source_blocks");

/// Symbol placements (owner view). Key = (SourceBlockId [u8;32], holder IdentityPub [u8;32]) = [u8;64].
/// Value = CBOR(SymbolPlacement).
const SYMBOL_PLACEMENTS: TableDefinition<&[u8; 64], &[u8]> = TableDefinition::new("symbol_placements");

/// Peer records. Key = IdentityPub [u8;32]. Value = CBOR(PeerRecord).
const PEERS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("peers");

/// Held symbols (holder view). Key = (SourceBlockId [u8;32], owner IdentityPub [u8;32]) = [u8;64].
/// Value = CBOR(HoldingRecord).
const HOLDINGS: TableDefinition<&[u8; 64], &[u8]> = TableDefinition::new("holdings");

/// Event log (append-only). Key = u64 sequence number (big-endian). Value = CBOR(EventEntry).
const EVENT_LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("event_log");

/// Budget singleton. Key = "budget". Value = CBOR(BudgetRecord).
const BUDGET: TableDefinition<&str, &[u8]> = TableDefinition::new("budget");

/// PoS weekly results. Key = [IdentityPub(32) || week_number_BE(4)] = [u8;36].
/// Value = CBOR(WeeklyPosEntry { challenged: u32, passed: u32 }).
pub(crate) const POS_WEEKLY: TableDefinition<&[u8; 36], &[u8]> = TableDefinition::new("pos_weekly");

// --- Indices ---

/// file → holders index. Key = (FileId as u64 BE, holder IdentityPub) = [u8;40].
/// Value = symbol_count (u32 BE). Entry present ↔ this holder has symbols for this file.
const FILE_HOLDERS: TableDefinition<&[u8; 40], u32> = TableDefinition::new("file_holders");

/// holder → files index. Key = (holder IdentityPub [u8;32], FileId u64 BE [u8;8]) = [u8;40].
/// Value = symbol_count (u32 BE).
const HOLDER_FILES: TableDefinition<&[u8; 40], u32> = TableDefinition::new("holder_files");
```

Index key helpers:
```rust
fn file_holder_key(file_id: FileId, holder: &IdentityPub) -> [u8; 40];
fn holder_file_key(holder: &IdentityPub, file_id: FileId) -> [u8; 40];
fn placement_key(block_id: &SourceBlockId, holder: &IdentityPub) -> [u8; 64];
fn holding_key(block_id: &SourceBlockId, owner: &IdentityPub) -> [u8; 64];
fn pos_key(peer: &IdentityPub, week_number: u32) -> [u8; 36];
```

---

## Types (defined in db module)

```rust
/// Hot layer: in-memory aggregates loaded at startup.
pub struct HotCache {
    pub blocks: HashMap<SourceBlockId, BlockAgg>,
    pub placements: HashMap<(SourceBlockId, IdentityPub), PlacementAgg>,
}

impl HotCache {
    pub fn empty() -> Self;
    /// Build from full scan of WARM layer. Called at Db::open().
    fn build_from_db(db: &Db) -> Result<Self, DbError>;
}

/// One weekly PoS entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct WeeklyPosEntry {
    pub challenged: u32,
    pub passed: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("redb error: {0}")]
    Redb(Box<redb::Error>),
    #[error("redb database error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("redb transaction error: {0}")]
    Transaction(Box<redb::TransactionError>),
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

impl From<redb::Error> for DbError { ... }
impl From<redb::TransactionError> for DbError { ... }
```

---

## Db Struct

```rust
/// Cheaply cloneable handle. Arc inside: clone() = refcount increment.
/// All methods take &self. redb MVCC handles concurrency.
#[derive(Clone)]
pub struct Db {
    pub inner: Arc<redb::Database>,
    /// Shared hot cache. Protected by RwLock; write-locked on mutations.
    hot: Arc<RwLock<HotCache>>,
}

impl Db {
    /// Open or create database at path. Creates all tables.
    /// Builds hot cache from DB scan.
    /// Panics on unwritable path or corrupt DB (fatal errors).
    pub fn open(path: &std::path::Path) -> Result<Self, DbError>;

    /// Create in-memory database (for tests). Same table setup.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, DbError>;

    /// Access hot cache for read.
    pub fn hot(&self) -> impl Deref<Target = HotCache> + '_;
}
```

---

## Public API

### Files table

```rust
impl Db {
    /// Insert or replace FileRecord.
    pub fn upsert_file(&self, record: &FileRecord) -> Result<(), DbError>;

    /// Get by path. None if not found.
    pub fn get_file(&self, path: &str) -> Result<Option<FileRecord>, DbError>;

    /// Get by FileId. O(n) scan — acceptable, FileId lookup is rare.
    pub fn get_file_by_id(&self, file_id: FileId) -> Result<Option<FileRecord>, DbError>;

    /// Delete by path. No-op if not found.
    pub fn delete_file(&self, path: &str) -> Result<(), DbError>;

    /// List all files. Used by backup coordinator and repair agent.
    pub fn list_all_files(&self) -> Result<Vec<FileRecord>, DbError>;

    /// List files with path starting with prefix. Used for selective restore.
    pub fn list_files_with_prefix(&self, prefix: &str) -> Result<Vec<FileRecord>, DbError>;
}
```

### Source blocks table

```rust
impl Db {
    pub fn upsert_source_block(&self, record: &SourceBlockRecord) -> Result<(), DbError>;
    pub fn get_source_block(&self, block_id: &SourceBlockId) -> Result<Option<SourceBlockRecord>, DbError>;
    pub fn delete_source_block(&self, block_id: &SourceBlockId) -> Result<(), DbError>;

    /// List all source blocks with given status.
    pub fn list_source_blocks_by_status(&self, status: SourceBlockStatus) -> Result<Vec<SourceBlockRecord>, DbError>;
}
```

### Symbol placements table (owner view)

```rust
impl Db {
    /// Insert or replace. Also updates HOT cache and file_holders/holder_files indices.
    pub fn upsert_placement(&self, record: &SymbolPlacement) -> Result<(), DbError>;

    /// Get placement for (block_id, holder_id) pair. None if not found.
    pub fn get_placement(
        &self,
        block_id: &SourceBlockId,
        holder_id: &IdentityPub,
    ) -> Result<Option<SymbolPlacement>, DbError>;

    /// Delete placement. Also cleans up indices and HOT cache.
    pub fn delete_placement(
        &self,
        block_id: &SourceBlockId,
        holder_id: &IdentityPub,
    ) -> Result<(), DbError>;

    /// List all placements for a source block.
    pub fn list_placements_for_block(
        &self,
        block_id: &SourceBlockId,
    ) -> Result<Vec<SymbolPlacement>, DbError>;

    /// List all placements for a holder (scan holder_files index then fetch).
    pub fn list_placements_for_holder(
        &self,
        holder_id: &IdentityPub,
    ) -> Result<Vec<SymbolPlacement>, DbError>;

    /// Convenience: list all holders of a file (via file_holders index).
    pub fn list_holders_for_file(
        &self,
        file_id: FileId,
    ) -> Result<Vec<IdentityPub>, DbError>;

    /// Convenience: list all file_ids a holder has symbols for (via holder_files index).
    pub fn list_files_for_holder(
        &self,
        holder_id: &IdentityPub,
    ) -> Result<Vec<FileId>, DbError>;
}
```

### Peers table

```rust
impl Db {
    pub fn upsert_peer(&self, record: &PeerRecord) -> Result<(), DbError>;
    pub fn get_peer(&self, identity: &IdentityPub) -> Result<Option<PeerRecord>, DbError>;
    pub fn delete_peer(&self, identity: &IdentityPub) -> Result<(), DbError>;
    pub fn list_all_peers(&self) -> Result<Vec<PeerRecord>, DbError>;
}
```

### Holdings table (holder view)

```rust
impl Db {
    pub fn upsert_holding(&self, record: &HoldingRecord) -> Result<(), DbError>;
    pub fn get_holding(
        &self,
        block_id: &SourceBlockId,
        owner_id: &IdentityPub,
    ) -> Result<Option<HoldingRecord>, DbError>;
    pub fn delete_holding(
        &self,
        block_id: &SourceBlockId,
        owner_id: &IdentityPub,
    ) -> Result<(), DbError>;

    /// All holdings for a given owner. Used by escrow module.
    pub fn list_holdings_for_owner(
        &self,
        owner_id: &IdentityPub,
    ) -> Result<Vec<HoldingRecord>, DbError>;

    /// All active holdings sorted by eviction priority (lowest first).
    /// priority = importance ASC, received_at ASC (tie-break).
    /// Used by budget planner as candidate list.
    pub fn list_all_holdings(&self) -> Result<Vec<HoldingRecord>, DbError>;

    /// Total bytes across all holdings (Active + MarkedForDelete + Silent).
    pub fn total_holding_bytes(&self) -> Result<u64, DbError>;

    /// Holdings where delete_requested_at + HOLDER_DELETE_COOLDOWN_SECS <= now.
    pub fn list_holdings_cooldown_expired(
        &self,
        now: Timestamp,
    ) -> Result<Vec<HoldingRecord>, DbError>;

    /// Holdings where drop_notice_sent_at is Some and drop_notice_sent_at + DROP_NOTICE_WINDOW_SECS <= now.
    pub fn list_holdings_drop_notice_expired(
        &self,
        now: Timestamp,
    ) -> Result<Vec<HoldingRecord>, DbError>;
}
```

### Event log table

```rust
impl Db {
    /// Append an event. Assigns next sequence number automatically.
    /// Returns the assigned sequence number.
    pub fn append_event(&self, entry: &EventEntry) -> Result<u64, DbError>;

    /// Return events after (exclusive) a given sequence number, up to limit.
    /// Used for event log sync between devices.
    pub fn events_after(&self, seq: u64, limit: usize) -> Result<Vec<(u64, EventEntry)>, DbError>;

    /// Last sequence number, or 0 if empty.
    pub fn last_event_seq(&self) -> Result<u64, DbError>;
}
```

### Budget table

```rust
impl Db {
    pub fn get_budget(&self) -> Result<Option<BudgetRecord>, DbError>;
    pub fn set_budget(&self, record: &BudgetRecord) -> Result<(), DbError>;
}
```

### PoS weekly table (used by TrustEngine::load/export)

```rust
impl Db {
    /// Upsert weekly PoS entry for a peer.
    pub fn upsert_pos_weekly(
        &self,
        peer: &IdentityPub,
        week_number: u32,
        entry: &WeeklyPosEntry,
    ) -> Result<(), DbError>;

    /// Get entry, or None.
    pub fn get_pos_weekly(
        &self,
        peer: &IdentityPub,
        week_number: u32,
    ) -> Result<Option<WeeklyPosEntry>, DbError>;

    /// All pos weekly entries for a peer (used by TrustEngine::load).
    pub fn list_pos_weekly_for_peer(
        &self,
        peer: &IdentityPub,
    ) -> Result<Vec<(u32, WeeklyPosEntry)>, DbError>;
}
```

---

## HOT Cache Consistency Rules

The hot cache is updated synchronously in the same write operation that modifies WARM:

- `upsert_placement(record)`:
  - Update `hot.blocks[record.source_block_id].total_alive_symbols` — add `record.symbol_count()` if status transitions to Alive, subtract if transitions away from Alive.
  - Update `hot.placements[(record.source_block_id, record.holder_id)]`.
  - Update `file_holders` and `holder_files` indices.

- `delete_placement(block_id, holder_id)`:
  - Remove from hot cache.
  - Remove from indices.
  - If `hot.blocks[block_id].total_alive_symbols` drops to 0, remove block entry.

Hot cache rebuild on `open()`:
```
For each SymbolPlacement in WARM:
  BlockAgg: accumulate total_alive_symbols per block_id
  PlacementAgg: record per (block_id, holder_id)
```

---

## Index Consistency Rules

`file_holders` and `holder_files` are derived from `symbol_placements`:
- Set the file_id from the FileRecord that owns this source_block_id (requires a `source_block_id → file_id` lookup).
- On `upsert_placement`: insert into both indices with current `symbol_count()`.
- On `delete_placement`: remove from both indices.
- On `upsert_source_block`: no index change (indices key on FileId, not block_id).

DECISION NEEDED: The mapping `source_block_id → FileId` requires either:
- A secondary index `source_block_to_file`, OR
- Scanning `files` table (O(n)), OR
- Storing `file_id` on `SymbolPlacement`.

**Recommendation: store `file_id: FileId` on `SymbolPlacement` struct.** This avoids a scan and keeps the index update O(1). This means adding `file_id` to `SymbolPlacement` in `types/mod.rs`.

If adding `file_id` to `SymbolPlacement` is not approved by the architect, use a separate `source_block_to_file: TableDefinition<&[u8;32], u64>` table instead.

---

## testutil.rs

Create `crates/syncback-core/src/testutil.rs` (or re-export from `db/mod.rs` under `#[cfg(test)]`):

```rust
#[cfg(test)]
pub mod testutil {
    use crate::db::Db;
    use crate::types::{IdentityPub, Timestamp};

    pub fn test_db() -> Db {
        Db::open_in_memory().expect("test db")
    }

    pub fn test_peer() -> IdentityPub {
        IdentityPub([1u8; 32])
    }

    pub fn test_peers(n: usize) -> Vec<IdentityPub> {
        (0..n).map(|i| IdentityPub([i as u8 + 1; 32])).collect()
    }

    pub fn week(n: u32) -> Timestamp {
        Timestamp(n as u64 * crate::constants::SECS_PER_WEEK)
    }
}
```

---

## Test Scenarios

Tests in `db/tests.rs`. Use `Db::open_in_memory()`.

### 1. `file_crud`

```
upsert_file(record_A)
get_file(record_A.path) == Some(record_A)
delete_file(record_A.path)
get_file(record_A.path) == None
```

### 2. `file_get_by_id`

```
upsert_file(record with file_id=42)
get_file_by_id(42) == Some(record)
get_file_by_id(99) == None
```

### 3. `file_list_with_prefix`

```
Upsert: "photos/a.jpg", "photos/b.jpg", "docs/c.md"
list_files_with_prefix("photos/") → [a.jpg, b.jpg]
list_files_with_prefix("docs/") → [c.md]
list_files_with_prefix("videos/") → []
```

### 4. `placement_crud`

```
upsert_placement(p1)
get_placement(p1.source_block_id, p1.holder_id) == Some(p1)
delete_placement(...)
get_placement(...) == None
```

### 5. `placement_updates_hot_cache`

```
placement with status=Alive, symbol_count=100
After upsert: hot.blocks[block_id].total_alive_symbols == 100
hot.placements[(block_id, holder_id)].symbol_count == 100
```

### 6. `placement_delete_cleans_hot_cache`

```
Upsert then delete.
hot.placements entry removed.
hot.blocks entry total_alive_symbols decremented to 0 → entry removed.
```

### 7. `double_index_consistency`

```
upsert_placement with file_id=FileId(7), holder_id=H1, symbol_count=50
list_holders_for_file(FileId(7)) contains H1
list_files_for_holder(H1) contains FileId(7)

delete_placement
list_holders_for_file(FileId(7)) is empty
list_files_for_holder(H1) is empty
```

### 8. `holder_files_scan_on_holder_departure`

```
Holder H1 has placements for 3 different files.
list_files_for_holder(H1) returns all 3 FileIds.
This simulates "holder left" — repair agent scans affected files.
```

### 9. `event_log_append_and_query`

```
Append 3 events.
last_event_seq() == 3
events_after(0, 100) == [(1, e1), (2, e2), (3, e3)]
events_after(2, 100) == [(3, e3)]
events_after(3, 100) == []
```

### 10. `event_log_sequence_monotonic`

```
Append 5 events. Sequence numbers are 1, 2, 3, 4, 5 (no gaps).
```

### 11. `holding_crud`

```
upsert_holding(h1)
get_holding(h1.source_block_id, h1.owner_id) == Some(h1)
total_holding_bytes() == h1.total_bytes
delete_holding(...)
total_holding_bytes() == 0
```

### 12. `holding_cooldown_expired`

```
h1 with status=MarkedForDelete, delete_requested_at=T(0)
h2 with status=MarkedForDelete, delete_requested_at=T(0)
now = T(HOLDER_DELETE_COOLDOWN_SECS)

h1: list_holdings_cooldown_expired(now) → includes h1 and h2
h3 with delete_requested_at=T(1) → NOT included (1 second short)
```

### 13. `peer_crud`

```
upsert_peer(p1)
get_peer(p1.identity) == Some(p1)
list_all_peers().len() == 1
delete_peer(p1.identity)
get_peer(p1.identity) == None
```

### 14. `pos_weekly_accumulate`

```
upsert_pos_weekly(peer, week=5, {challenged:3, passed:2})
upsert_pos_weekly(peer, week=5, {challenged:2, passed:2})  // overwrite
get_pos_weekly(peer, week=5) == {challenged:2, passed:2}   // last write wins (upsert)
```

### 15. `hot_cache_rebuilt_after_reopen`

```
Open DB, insert placements with Alive status.
Close DB (drop Db handle).
Reopen DB at same path.
hot.blocks and hot.placements match what was inserted.
```

This validates `HotCache::build_from_db()`.

---

## Reference: α code

See `alpha_crates/syncback-core/src/db/mod.rs`:
- Table definition pattern (redb `TableDefinition`) — same pattern.
- `Db::open()` with table creation — same structure.
- File CRUD pattern — same.
- Peer CRUD — same.
- `POS_WEEKLY` table key format `[u8;36]` — identical.

Key differences in β:
- No `UNITS`, `SHARDS`, `STALE_UNITS`, `UNVERIFIED_SHARDS` tables.
- New: `SOURCE_BLOCKS`, `SYMBOL_PLACEMENTS`, `HOLDINGS` (new key format `[u8;64]`), `EVENT_LOG`.
- New: `FILE_HOLDERS`, `HOLDER_FILES` indices.
- HOT cache (`HotCache` struct) — new in β.
- `ESCROW_RESTORE_LOG`, `SYSTEM_STATE_BLOBS` — not needed in β Phase 1 (restore log handled externally).
