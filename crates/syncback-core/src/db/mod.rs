// Database layer for syncback-core β.
// Two-tier architecture: WARM (redb) + HOT (RAM aggregates).
// See docs/beta/tasks/db.md for full spec.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use redb::{ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::constants::{HOLDER_DELETE_COOLDOWN_SECS, DROP_NOTICE_WINDOW_SECS};
use crate::cluster::StoredClusterState;
use crate::types::{
    from_cbor_bytes, to_cbor_bytes, BlockAgg, BudgetRecord, EventEntry, FileId, FileRecord,
    HoldingRecord, HoldingStatus, IdentityPub, PlacementAgg, PlacementStatus, PeerRecord,
    SourceBlockId, SourceBlockRecord, SourceBlockStatus, SymbolPlacement, Timestamp,
};

// ============================================================
// Table definitions
// ============================================================

/// File catalog. Key = file path (UTF-8). Value = CBOR(FileRecord).
const FILES: TableDefinition<&str, &[u8]> = TableDefinition::new("files");

/// Source block metadata (owner view). Key = SourceBlockId [u8;32]. Value = CBOR(SourceBlockRecord).
const SOURCE_BLOCKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("source_blocks");

/// Symbol placements (owner view). Key = (SourceBlockId[32] || holder IdentityPub[32]) = [u8;64].
/// Value = CBOR(SymbolPlacement).
const SYMBOL_PLACEMENTS: TableDefinition<&[u8; 64], &[u8]> =
    TableDefinition::new("symbol_placements");

/// Peer records. Key = IdentityPub [u8;32]. Value = CBOR(PeerRecord).
const PEERS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("peers");

/// Held symbols (holder view). Key = (SourceBlockId[32] || owner IdentityPub[32]) = [u8;64].
/// Value = CBOR(HoldingRecord).
const HOLDINGS: TableDefinition<&[u8; 64], &[u8]> = TableDefinition::new("holdings");

/// Event log (append-only). Key = u64 sequence number (monotonic, 1-based). Value = CBOR(EventEntry).
const EVENT_LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("event_log");

/// Budget singleton. Key = "budget". Value = CBOR(BudgetRecord).
const BUDGET: TableDefinition<&str, &[u8]> = TableDefinition::new("budget");

/// PoS weekly results. Key = [IdentityPub(32) || week_number_BE(4)] = [u8;36].
/// Value = CBOR(WeeklyPosEntry).
pub(crate) const POS_WEEKLY: TableDefinition<&[u8; 36], &[u8]> =
    TableDefinition::new("pos_weekly");

/// Cluster state singleton. Key = "cluster_state". Value = CBOR(StoredClusterState).
const CLUSTER_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("cluster_state");

/// System state blobs stored for other nodes (holder-side).
/// Key = owner IdentityPub [u8;32]. Value = CBOR(SystemStateBlobRecord).
const SYSTEM_STATE_BLOBS: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("system_state_blobs");

/// TTL for stored system state blobs: 365 days.
pub const SYSTEM_STATE_TTL_SECS: u64 = 365 * 24 * 3600;

// --- Indices ---

/// file → holders index. Key = (FileId u64 BE[8] || holder IdentityPub[32]) = [u8;40].
/// Value = symbol_count (u32). Entry present ↔ holder has symbols for this file.
const FILE_HOLDERS: TableDefinition<&[u8; 40], u32> = TableDefinition::new("file_holders");

/// holder → files index. Key = (holder IdentityPub[32] || FileId u64 BE[8]) = [u8;40].
/// Value = symbol_count (u32).
const HOLDER_FILES: TableDefinition<&[u8; 40], u32> = TableDefinition::new("holder_files");

// ============================================================
// Key helpers
// ============================================================

fn file_holder_key(file_id: FileId, holder: &IdentityPub) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..8].copy_from_slice(&file_id.0.to_be_bytes());
    key[8..40].copy_from_slice(&holder.0);
    key
}

fn holder_file_key(holder: &IdentityPub, file_id: FileId) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(&holder.0);
    key[32..40].copy_from_slice(&file_id.0.to_be_bytes());
    key
}

fn placement_key(block_id: &SourceBlockId, holder: &IdentityPub) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&block_id.0);
    key[32..64].copy_from_slice(&holder.0);
    key
}

fn holding_key(block_id: &SourceBlockId, owner: &IdentityPub) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&block_id.0);
    key[32..64].copy_from_slice(&owner.0);
    key
}

fn pos_key(peer: &IdentityPub, week_number: u32) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..32].copy_from_slice(&peer.0);
    key[32..36].copy_from_slice(&week_number.to_be_bytes());
    key
}

// ============================================================
// Types
// ============================================================

/// One weekly PoS entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WeeklyPosEntry {
    pub challenged: u32,
    pub passed: u32,
}

/// One stored system state blob. Stored by holder on behalf of an owner.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemStateBlobRecord {
    pub owner: IdentityPub,
    pub encrypted_blob: Vec<u8>,
    pub created_at: Timestamp,
    pub stored_at: Timestamp,
}

/// Hot layer: in-memory aggregates loaded at startup.
pub struct HotCache {
    pub blocks: HashMap<SourceBlockId, BlockAgg>,
    pub placements: HashMap<(SourceBlockId, IdentityPub), PlacementAgg>,
}

impl HotCache {
    pub fn empty() -> Self {
        HotCache {
            blocks: HashMap::new(),
            placements: HashMap::new(),
        }
    }

    /// Build from full scan of WARM layer. Called at Db::open().
    fn build_from_db(db: &redb::Database) -> Result<Self, DbError> {
        let mut cache = HotCache::empty();
        let tx = db.begin_read()?;
        let table = tx.open_table(SYMBOL_PLACEMENTS)?;
        for item in table.iter()? {
            let (_, v) = item?;
            let placement: SymbolPlacement = from_cbor_bytes(v.value())?;
            let count = placement.symbol_count();
            // Update per-(block, holder) aggregate
            cache.placements.insert(
                (placement.source_block_id, placement.holder_id),
                PlacementAgg {
                    symbol_count: count,
                    status: placement.status,
                    last_pos: placement.last_verified,
                },
            );
            // Accumulate alive symbols per block
            if placement.status == PlacementStatus::Alive {
                let agg = cache
                    .blocks
                    .entry(placement.source_block_id)
                    .or_insert_with(|| {
                        // k will be filled from SourceBlockRecord but we don't want
                        // a second scan; use 0 as placeholder — callers that need k
                        // should read SourceBlockRecord directly.
                        BlockAgg {
                            k: 0,
                            total_alive_symbols: 0,
                        }
                    });
                agg.total_alive_symbols += count;
            }
        }
        Ok(cache)
    }
}

// ============================================================
// Error type
// ============================================================

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

impl From<redb::Error> for DbError {
    fn from(e: redb::Error) -> Self {
        DbError::Redb(Box::new(e))
    }
}

impl From<redb::TransactionError> for DbError {
    fn from(e: redb::TransactionError) -> Self {
        DbError::Transaction(Box::new(e))
    }
}

// ============================================================
// Db struct
// ============================================================

/// Cheaply cloneable handle. Arc inside: clone() = refcount increment.
/// All methods take &self. redb MVCC handles read concurrency.
/// Hot cache is write-locked during mutations (same transaction as redb write).
#[derive(Clone)]
pub struct Db {
    pub inner: Arc<redb::Database>,
    /// Shared hot cache. Protected by RwLock; write-locked on mutations.
    hot: Arc<RwLock<HotCache>>,
}

impl Db {
    fn create_tables(db: &redb::Database) -> Result<(), DbError> {
        let tx = db.begin_write()?;
        {
            tx.open_table(FILES)?;
            tx.open_table(SOURCE_BLOCKS)?;
            tx.open_table(SYMBOL_PLACEMENTS)?;
            tx.open_table(PEERS)?;
            tx.open_table(HOLDINGS)?;
            tx.open_table(EVENT_LOG)?;
            tx.open_table(BUDGET)?;
            tx.open_table(POS_WEEKLY)?;
            tx.open_table(FILE_HOLDERS)?;
            tx.open_table(HOLDER_FILES)?;
            tx.open_table(CLUSTER_STATE)?;
            tx.open_table(SYSTEM_STATE_BLOBS)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Open or create database at path. Creates all tables.
    /// Builds hot cache from DB scan.
    pub fn open(path: &std::path::Path) -> Result<Self, DbError> {
        if path.exists() {
            let bak = path.with_extension("redb.bak");
            if let Err(e) = std::fs::copy(path, &bak) {
                tracing::warn!(err = %e, "db: failed to create pre-open backup");
            }
        }

        let open_result = redb::Database::builder()
            .set_repair_callback(|session| {
                tracing::warn!(progress = session.progress(), "redb: repair in progress");
            })
            .create(path);

        let mut db = match open_result {
            Ok(db) => db,
            Err(e) => {
                tracing::error!(err = %e, "db: open failed, retrying with repair");
                redb::Database::builder()
                    .set_repair_callback(|session| {
                        tracing::warn!(progress = session.progress(), "redb: repair (retry)");
                    })
                    .create(path)?
            }
        };

        let ok = db.check_integrity()?;
        if !ok {
            tracing::warn!("db: check_integrity returned false, proceeding anyway");
        }

        Self::create_tables(&db)?;
        let hot = HotCache::build_from_db(&db)?;
        Ok(Db {
            inner: Arc::new(db),
            hot: Arc::new(RwLock::new(hot)),
        })
    }

    /// Create in-memory database (for tests). Same table setup.
    #[cfg(any(test, feature = "testutil"))]
    pub fn open_in_memory() -> Result<Self, DbError> {
        let db = redb::Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())?;
        Self::create_tables(&db)?;
        let hot = HotCache::build_from_db(&db)?;
        Ok(Db {
            inner: Arc::new(db),
            hot: Arc::new(RwLock::new(hot)),
        })
    }

    /// Access hot cache for read.
    pub fn hot(&self) -> impl Deref<Target = HotCache> + '_ {
        self.hot.read().expect("hot cache lock poisoned")
    }
}

// ============================================================
// Files table
// ============================================================

impl Db {
    /// Insert or replace FileRecord.
    pub fn upsert_file(&self, record: &FileRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let tx = self.inner.begin_write()?;
        {
            let mut files = tx.open_table(FILES)?;
            files.insert(record.path.as_str(), bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Get by path. None if not found.
    pub fn get_file(&self, path: &str) -> Result<Option<FileRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(FILES)?;
        match table.get(path)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Get by FileId. O(n) scan — FileId lookup is rare.
    pub fn get_file_by_id(&self, file_id: FileId) -> Result<Option<FileRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(FILES)?;
        for item in table.iter()? {
            let (_, v) = item?;
            let record: FileRecord = from_cbor_bytes(v.value())?;
            if record.file_id == file_id {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// Delete by path. No-op if not found.
    pub fn delete_file(&self, path: &str) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut files = tx.open_table(FILES)?;
            files.remove(path)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// List all files.
    pub fn list_all_files(&self) -> Result<Vec<FileRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(FILES)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: FileRecord = from_cbor_bytes(v.value())?;
            records.push(record);
        }
        Ok(records)
    }

    /// List files with path starting with prefix.
    pub fn list_files_with_prefix(&self, prefix: &str) -> Result<Vec<FileRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(FILES)?;
        let mut records = Vec::new();
        // redb stores &str keys in lexicographic order, so a range scan works.
        // We use range from `prefix` to `prefix\xFF` (exclusive upper bound via open end).
        // Simplest correct approach: full scan with prefix check.
        for item in table.iter()? {
            let (k, v) = item?;
            if k.value().starts_with(prefix) {
                let record: FileRecord = from_cbor_bytes(v.value())?;
                records.push(record);
            }
        }
        Ok(records)
    }
}

// ============================================================
// Source blocks table
// ============================================================

impl Db {
    pub fn upsert_source_block(&self, record: &SourceBlockRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(SOURCE_BLOCKS)?;
            table.insert(&record.block_id.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_source_block(
        &self,
        block_id: &SourceBlockId,
    ) -> Result<Option<SourceBlockRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SOURCE_BLOCKS)?;
        match table.get(&block_id.0)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn delete_source_block(&self, block_id: &SourceBlockId) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(SOURCE_BLOCKS)?;
            table.remove(&block_id.0)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// List all source blocks (any status).
    pub fn list_all_source_blocks(&self) -> Result<Vec<SourceBlockRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SOURCE_BLOCKS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: SourceBlockRecord = from_cbor_bytes(v.value())?;
            records.push(record);
        }
        Ok(records)
    }

    /// List all source blocks with given status.
    pub fn list_source_blocks_by_status(
        &self,
        status: SourceBlockStatus,
    ) -> Result<Vec<SourceBlockRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SOURCE_BLOCKS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: SourceBlockRecord = from_cbor_bytes(v.value())?;
            if record.status == status {
                records.push(record);
            }
        }
        Ok(records)
    }
}

// ============================================================
// Symbol placements table (owner view)
// ============================================================

impl Db {
    /// Insert or replace. Also updates HOT cache and file_holders/holder_files indices.
    pub fn upsert_placement(&self, record: &SymbolPlacement) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let key = placement_key(&record.source_block_id, &record.holder_id);
        let fh_key = file_holder_key(record.file_id, &record.holder_id);
        let hf_key = holder_file_key(&record.holder_id, record.file_id);
        let count = record.symbol_count();

        let tx = self.inner.begin_write()?;
        {
            let mut placements = tx.open_table(SYMBOL_PLACEMENTS)?;
            // Read old record to adjust hot cache delta correctly
            let old: Option<SymbolPlacement> = match placements.get(&key)? {
                Some(v) => Some(from_cbor_bytes(v.value())?),
                None => None,
            };
            placements.insert(&key, bytes.as_slice())?;

            // Update indices
            let mut fh = tx.open_table(FILE_HOLDERS)?;
            let mut hf = tx.open_table(HOLDER_FILES)?;
            fh.insert(&fh_key, count)?;
            hf.insert(&hf_key, count)?;

            // Update hot cache under write lock — do this inside transaction scope
            // so that cache and DB stay in sync on failure.
            let mut hot = self.hot.write().expect("hot cache lock poisoned");

            // Adjust block aggregate: remove old alive contribution, add new.
            let old_alive = old
                .as_ref()
                .filter(|o| o.status == PlacementStatus::Alive)
                .map(|o| o.symbol_count())
                .unwrap_or(0);
            let new_alive = if record.status == PlacementStatus::Alive {
                count
            } else {
                0
            };

            let block_agg = hot
                .blocks
                .entry(record.source_block_id)
                .or_insert(BlockAgg {
                    k: 0,
                    total_alive_symbols: 0,
                });
            block_agg.total_alive_symbols =
                block_agg.total_alive_symbols.saturating_sub(old_alive) + new_alive;

            // Update per-(block, holder) aggregate.
            hot.placements.insert(
                (record.source_block_id, record.holder_id),
                PlacementAgg {
                    symbol_count: count,
                    status: record.status,
                    last_pos: record.last_verified,
                },
            );
        }
        tx.commit()?;
        Ok(())
    }

    /// Get placement for (block_id, holder_id) pair. None if not found.
    pub fn get_placement(
        &self,
        block_id: &SourceBlockId,
        holder_id: &IdentityPub,
    ) -> Result<Option<SymbolPlacement>, DbError> {
        let key = placement_key(block_id, holder_id);
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SYMBOL_PLACEMENTS)?;
        match table.get(&key)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Delete placement. Also cleans up indices and HOT cache.
    pub fn delete_placement(
        &self,
        block_id: &SourceBlockId,
        holder_id: &IdentityPub,
    ) -> Result<(), DbError> {
        let key = placement_key(block_id, holder_id);

        let tx = self.inner.begin_write()?;
        {
            let mut placements = tx.open_table(SYMBOL_PLACEMENTS)?;
            // Read before delete so we can update indices and hot cache.
            let old: Option<SymbolPlacement> = match placements.get(&key)? {
                Some(v) => Some(from_cbor_bytes(v.value())?),
                None => None,
            };
            placements.remove(&key)?;

            if let Some(old_record) = old {
                let fh_key = file_holder_key(old_record.file_id, holder_id);
                let hf_key = holder_file_key(holder_id, old_record.file_id);
                let mut fh = tx.open_table(FILE_HOLDERS)?;
                let mut hf = tx.open_table(HOLDER_FILES)?;
                fh.remove(&fh_key)?;
                hf.remove(&hf_key)?;

                // Update hot cache
                let mut hot = self.hot.write().expect("hot cache lock poisoned");
                hot.placements.remove(&(*block_id, *holder_id));

                if old_record.status == PlacementStatus::Alive {
                    let count = old_record.symbol_count();
                    if let Some(agg) = hot.blocks.get_mut(block_id) {
                        agg.total_alive_symbols = agg.total_alive_symbols.saturating_sub(count);
                        if agg.total_alive_symbols == 0 {
                            hot.blocks.remove(block_id);
                        }
                    }
                } else {
                    // If no more placements for this block at all, remove the block entry
                    let still_has_placements = hot
                        .placements
                        .keys()
                        .any(|(bid, _)| bid == block_id);
                    if !still_has_placements {
                        hot.blocks.remove(block_id);
                    }
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// List all placements for a source block. Uses prefix range scan on composite key.
    pub fn list_placements_for_block(
        &self,
        block_id: &SourceBlockId,
    ) -> Result<Vec<SymbolPlacement>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SYMBOL_PLACEMENTS)?;
        let mut records = Vec::new();
        // Keys are [block_id(32) || holder(32)]. Range: [block_id||00..] to [block_id||FF..].
        let mut lo = [0u8; 64];
        let mut hi = [0u8; 64];
        lo[..32].copy_from_slice(&block_id.0);
        hi[..32].copy_from_slice(&block_id.0);
        hi[32..].fill(0xFF);
        for item in table.range::<&[u8; 64]>(&lo..=&hi)? {
            let (_, v) = item?;
            let record: SymbolPlacement = from_cbor_bytes(v.value())?;
            records.push(record);
        }
        Ok(records)
    }

    /// List all placements for a holder (via holder_files index then fetch from placements).
    pub fn list_placements_for_holder(
        &self,
        holder_id: &IdentityPub,
    ) -> Result<Vec<SymbolPlacement>, DbError> {
        // Scan SYMBOL_PLACEMENTS directly: iterate all, filter by holder_id.
        // Alternative would be to use holder_files index then query source_blocks,
        // but we need (block_id, holder_id) pairs, not (file_id, holder_id).
        // Direct scan is simpler and correct; holders typically have O(100s) entries.
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SYMBOL_PLACEMENTS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            // Key = [block_id(32) || holder(32)]; check holder bytes at offset 32.
            let key_bytes = k.value();
            if &key_bytes[32..64] == holder_id.0.as_ref() {
                let record: SymbolPlacement = from_cbor_bytes(v.value())?;
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Convenience: list all holders of a file (via file_holders index).
    pub fn list_holders_for_file(&self, file_id: FileId) -> Result<Vec<IdentityPub>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(FILE_HOLDERS)?;
        let mut result = Vec::new();
        // Keys = [file_id_be(8) || holder(32)]. Range scan by file_id prefix.
        let mut lo = [0u8; 40];
        let mut hi = [0u8; 40];
        lo[..8].copy_from_slice(&file_id.0.to_be_bytes());
        hi[..8].copy_from_slice(&file_id.0.to_be_bytes());
        hi[8..].fill(0xFF);
        for item in table.range::<&[u8; 40]>(&lo..=&hi)? {
            let (k, _) = item?;
            let key_bytes = k.value();
            let mut holder_bytes = [0u8; 32];
            holder_bytes.copy_from_slice(&key_bytes[8..40]);
            result.push(IdentityPub(holder_bytes));
        }
        Ok(result)
    }

    /// Return all placements in the DB (any status).
    /// Used by Scheduler to enumerate candidates for PoS challenges.
    pub fn list_all_placements(&self) -> Result<Vec<SymbolPlacement>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SYMBOL_PLACEMENTS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: SymbolPlacement = from_cbor_bytes(v.value())?;
            records.push(record);
        }
        Ok(records)
    }

    /// Return all placements with status Lost or PresumedLost.
    /// Used by RepairAgent to find work.
    pub fn list_placements_needing_repair(&self) -> Result<Vec<SymbolPlacement>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SYMBOL_PLACEMENTS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: SymbolPlacement = from_cbor_bytes(v.value())?;
            if record.status == PlacementStatus::Lost
                || record.status == PlacementStatus::PresumedLost
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Convenience: list all file_ids a holder has symbols for (via holder_files index).
    pub fn list_files_for_holder(&self, holder_id: &IdentityPub) -> Result<Vec<FileId>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDER_FILES)?;
        let mut result = Vec::new();
        // Keys = [holder(32) || file_id_be(8)]. Range scan by holder prefix.
        let mut lo = [0u8; 40];
        let mut hi = [0u8; 40];
        lo[..32].copy_from_slice(&holder_id.0);
        hi[..32].copy_from_slice(&holder_id.0);
        hi[32..].fill(0xFF);
        for item in table.range::<&[u8; 40]>(&lo..=&hi)? {
            let (k, _) = item?;
            let key_bytes = k.value();
            let file_id_raw = u64::from_be_bytes(key_bytes[32..40].try_into().unwrap());
            result.push(FileId(file_id_raw));
        }
        Ok(result)
    }
}

// ============================================================
// Peers table
// ============================================================

impl Db {
    pub fn upsert_peer(&self, record: &PeerRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let tx = self.inner.begin_write()?;
        {
            let mut peers = tx.open_table(PEERS)?;
            peers.insert(&record.identity.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_peer(&self, identity: &IdentityPub) -> Result<Option<PeerRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(PEERS)?;
        match table.get(&identity.0)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn delete_peer(&self, identity: &IdentityPub) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut peers = tx.open_table(PEERS)?;
            peers.remove(&identity.0)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_all_peers(&self) -> Result<Vec<PeerRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(PEERS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: PeerRecord = from_cbor_bytes(v.value())?;
            records.push(record);
        }
        Ok(records)
    }

    /// Recompute storage-balance fields for a peer and update `trust_s` in the PeerRecord.
    ///
    /// - `bytes_we_store_for_peer`: sum of `total_bytes` over Active holdings whose
    ///   `owner_id == peer`.  (HOLDINGS table — our holder-side view.)
    /// - `bytes_peer_stores_for_us`: sum of `symbol_count * t` over Alive placements
    ///   whose `holder_id == peer`.  (SYMBOL_PLACEMENTS table — our owner-side view.)
    ///
    /// `trust_s = if bytes_we_store == 0 { 1.0 } else { peer_stores / we_store }`
    ///
    /// No-op (returns Ok) if the peer is not yet in the DB.
    pub fn refresh_peer_storage_bytes(&self, peer: &IdentityPub) -> Result<(), DbError> {
        // Compute bytes_we_store_for_peer from HOLDINGS.
        let we_store: u64 = self
            .list_holdings_for_owner(peer)?
            .into_iter()
            .filter(|h| h.status == HoldingStatus::Active)
            .map(|h| h.total_bytes)
            .sum();

        // Compute bytes_peer_stores_for_us from SYMBOL_PLACEMENTS.
        // Each alive placement contributes symbol_count * t bytes.
        let peer_stores: u64 = {
            let mut total = 0u64;
            for placement in self.list_placements_for_holder(peer)? {
                if placement.status != PlacementStatus::Alive {
                    continue;
                }
                let t = self
                    .get_source_block(&placement.source_block_id)?
                    .map(|sb| sb.t as u64)
                    .unwrap_or(0);
                total += placement.symbol_count() as u64 * t;
            }
            total
        };

        let trust_s = if we_store == 0 {
            1.0_f64
        } else {
            peer_stores as f64 / we_store as f64
        };

        // Update PeerRecord. No-op if peer not yet in DB.
        let mut record = match self.get_peer(peer)? {
            Some(r) => r,
            None => return Ok(()),
        };
        record.bytes_we_store_for_peer = we_store;
        record.bytes_peer_stores_for_us = peer_stores;
        record.trust_s = trust_s;
        self.upsert_peer(&record)?;
        Ok(())
    }
}

// ============================================================
// Holdings table (holder view)
// ============================================================

impl Db {
    pub fn upsert_holding(&self, record: &HoldingRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let key = holding_key(&record.source_block_id, &record.owner_id);
        let tx = self.inner.begin_write()?;
        {
            let mut holdings = tx.open_table(HOLDINGS)?;
            holdings.insert(&key, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_holding(
        &self,
        block_id: &SourceBlockId,
        owner_id: &IdentityPub,
    ) -> Result<Option<HoldingRecord>, DbError> {
        let key = holding_key(block_id, owner_id);
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDINGS)?;
        match table.get(&key)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn delete_holding(
        &self,
        block_id: &SourceBlockId,
        owner_id: &IdentityPub,
    ) -> Result<(), DbError> {
        let key = holding_key(block_id, owner_id);
        let tx = self.inner.begin_write()?;
        {
            let mut holdings = tx.open_table(HOLDINGS)?;
            holdings.remove(&key)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// All holdings for a given owner. Used by escrow module.
    pub fn list_holdings_for_owner(
        &self,
        owner_id: &IdentityPub,
    ) -> Result<Vec<HoldingRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDINGS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            if record.owner_id == *owner_id {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// All holdings sorted by eviction priority (lowest first):
    /// importance ASC, received_at ASC (tie-break).
    pub fn list_all_holdings(&self) -> Result<Vec<HoldingRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDINGS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            records.push(record);
        }
        records.sort_by(|a, b| {
            a.importance
                .partial_cmp(&b.importance)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.received_at.cmp(&b.received_at))
        });
        Ok(records)
    }

    /// Total bytes across all holdings (Active + MarkedForDelete + Silent).
    pub fn total_holding_bytes(&self) -> Result<u64, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDINGS)?;
        let mut total = 0u64;
        for item in table.iter()? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            // All statuses count towards held bytes.
            total += record.total_bytes;
        }
        Ok(total)
    }

    /// Holdings where delete_requested_at + HOLDER_DELETE_COOLDOWN_SECS <= now.
    pub fn list_holdings_cooldown_expired(
        &self,
        now: Timestamp,
    ) -> Result<Vec<HoldingRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDINGS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            if record.status == HoldingStatus::MarkedForDelete {
                if let Some(requested_at) = record.delete_requested_at {
                    if requested_at.0 + HOLDER_DELETE_COOLDOWN_SECS <= now.0 {
                        records.push(record);
                    }
                }
            }
        }
        Ok(records)
    }

    /// Holdings where drop_notice_sent_at is Some and
    /// drop_notice_sent_at + DROP_NOTICE_WINDOW_SECS <= now.
    pub fn list_holdings_drop_notice_expired(
        &self,
        now: Timestamp,
    ) -> Result<Vec<HoldingRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDINGS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            if let Some(sent_at) = record.drop_notice_sent_at {
                if sent_at.0 + DROP_NOTICE_WINDOW_SECS <= now.0 {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }
}

// ============================================================
// Event log table
// ============================================================

impl Db {
    /// Append an event. Assigns next sequence number automatically.
    /// Returns the assigned sequence number.
    pub fn append_event(&self, entry: &EventEntry) -> Result<u64, DbError> {
        let bytes = to_cbor_bytes(entry);
        let tx = self.inner.begin_write()?;
        let seq = {
            let table = tx.open_table(EVENT_LOG)?;
            // last() gives the highest key (biggest seq number).
            let last_seq = match table.last()? {
                Some((k, _)) => k.value(),
                None => 0,
            };
            drop(table);
            let next_seq = last_seq + 1;
            let mut table = tx.open_table(EVENT_LOG)?;
            table.insert(next_seq, bytes.as_slice())?;
            next_seq
        };
        tx.commit()?;
        Ok(seq)
    }

    /// Return events after (exclusive) a given sequence number, up to limit.
    pub fn events_after(&self, seq: u64, limit: usize) -> Result<Vec<(u64, EventEntry)>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(EVENT_LOG)?;
        let mut result = Vec::new();
        let start = seq + 1;
        for item in table.range(start..)? {
            if result.len() >= limit {
                break;
            }
            let (k, v) = item?;
            let entry: EventEntry = from_cbor_bytes(v.value())?;
            result.push((k.value(), entry));
        }
        Ok(result)
    }

    /// Last sequence number, or 0 if empty.
    pub fn last_event_seq(&self) -> Result<u64, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(EVENT_LOG)?;
        match table.last()? {
            Some((k, _)) => Ok(k.value()),
            None => Ok(0),
        }
    }
}

// ============================================================
// Budget table
// ============================================================

impl Db {
    pub fn get_budget(&self) -> Result<Option<BudgetRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(BUDGET)?;
        match table.get("budget")? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn set_budget(&self, record: &BudgetRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let tx = self.inner.begin_write()?;
        {
            let mut budget = tx.open_table(BUDGET)?;
            budget.insert("budget", bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }
}

// ============================================================
// PoS weekly table
// ============================================================

impl Db {
    /// Upsert weekly PoS entry for a peer.
    pub fn upsert_pos_weekly(
        &self,
        peer: &IdentityPub,
        week_number: u32,
        entry: &WeeklyPosEntry,
    ) -> Result<(), DbError> {
        let key = pos_key(peer, week_number);
        let bytes = to_cbor_bytes(entry);
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(POS_WEEKLY)?;
            table.insert(&key, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Get entry, or None.
    pub fn get_pos_weekly(
        &self,
        peer: &IdentityPub,
        week_number: u32,
    ) -> Result<Option<WeeklyPosEntry>, DbError> {
        let key = pos_key(peer, week_number);
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(POS_WEEKLY)?;
        match table.get(&key)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// All pos weekly entries for a peer (used by TrustEngine::load).
    pub fn list_pos_weekly_for_peer(
        &self,
        peer: &IdentityPub,
    ) -> Result<Vec<(u32, WeeklyPosEntry)>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(POS_WEEKLY)?;
        let mut result = Vec::new();
        // Range scan: keys = [peer(32) || week_be(4)]. Prefix by peer bytes.
        let mut lo = [0u8; 36];
        let mut hi = [0u8; 36];
        lo[..32].copy_from_slice(&peer.0);
        hi[..32].copy_from_slice(&peer.0);
        hi[32..].fill(0xFF);
        for item in table.range::<&[u8; 36]>(&lo..=&hi)? {
            let (k, v) = item?;
            let key_bytes = k.value();
            let week = u32::from_be_bytes(key_bytes[32..36].try_into().unwrap());
            let entry: WeeklyPosEntry = from_cbor_bytes(v.value())?;
            result.push((week, entry));
        }
        Ok(result)
    }

    /// Sum all challenged and passed counts across all peers and all weeks.
    /// Returns (total_challenged, total_passed).
    pub fn total_pos_stats(&self) -> Result<(u32, u32), DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(POS_WEEKLY)?;
        let mut challenged = 0u32;
        let mut passed = 0u32;
        for item in table.iter()? {
            let (_k, v) = item?;
            let entry: WeeklyPosEntry = from_cbor_bytes(v.value())?;
            challenged = challenged.saturating_add(entry.challenged);
            passed = passed.saturating_add(entry.passed);
        }
        Ok((challenged, passed))
    }
}

// ============================================================
// Cluster state table
// ============================================================

impl Db {
    pub fn get_cluster_state(&self) -> Result<Option<StoredClusterState>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(CLUSTER_STATE)?;
        match table.get("cluster_state")? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn set_cluster_state(&self, state: &StoredClusterState) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(state);
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(CLUSTER_STATE)?;
            table.insert("cluster_state", bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }
}

// ============================================================
// System state blobs table
// ============================================================

impl Db {
    /// Store a system state blob from an owner. Overwrites any previous blob.
    pub fn store_system_state_blob(
        &self,
        owner: &IdentityPub,
        record: &SystemStateBlobRecord,
    ) -> Result<(), DbError> {
        let val = to_cbor_bytes(record);
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(SYSTEM_STATE_BLOBS)?;
            table.insert(&owner.0, val.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Get a stored system state blob for an owner.
    /// Returns None if not found or expired (stored_at older than TTL).
    pub fn get_system_state_blob(
        &self,
        owner: &IdentityPub,
    ) -> Result<Option<SystemStateBlobRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SYSTEM_STATE_BLOBS)?;
        match table.get(&owner.0)? {
            None => Ok(None),
            Some(guard) => {
                let record: SystemStateBlobRecord = from_cbor_bytes(guard.value())?;
                let now = Timestamp::now();
                if now.0.saturating_sub(record.stored_at.0) > SYSTEM_STATE_TTL_SECS {
                    drop(guard);
                    drop(table);
                    drop(tx);
                    let _ = self.delete_system_state_blob(owner);
                    return Ok(None);
                }
                Ok(Some(record))
            }
        }
    }

    /// Delete stored blob for an owner. No-op if not found.
    pub fn delete_system_state_blob(
        &self,
        owner: &IdentityPub,
    ) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(SYSTEM_STATE_BLOBS)?;
            table.remove(&owner.0)?;
        }
        tx.commit()?;
        Ok(())
    }
}

// ============================================================
// Table stats
// ============================================================

/// Row counts per DB table, for observability.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TableStats {
    pub files: u64,
    pub source_blocks: u64,
    pub symbol_placements: u64,
    pub peers: u64,
    pub holdings: u64,
    pub event_log: u64,
    pub pos_weekly: u64,
    pub system_state_blobs: u64,
    pub file_holders: u64,
    pub holder_files: u64,
}

impl Db {
    /// Return row counts for all data tables.
    pub fn table_stats(&self) -> Result<TableStats, DbError> {
        let tx = self.inner.begin_read()?;
        Ok(TableStats {
            files: tx.open_table(FILES)?.len()?,
            source_blocks: tx.open_table(SOURCE_BLOCKS)?.len()?,
            symbol_placements: tx.open_table(SYMBOL_PLACEMENTS)?.len()?,
            peers: tx.open_table(PEERS)?.len()?,
            holdings: tx.open_table(HOLDINGS)?.len()?,
            event_log: tx.open_table(EVENT_LOG)?.len()?,
            pos_weekly: tx.open_table(POS_WEEKLY)?.len()?,
            system_state_blobs: tx.open_table(SYSTEM_STATE_BLOBS)?.len()?,
            file_holders: tx.open_table(FILE_HOLDERS)?.len()?,
            holder_files: tx.open_table(HOLDER_FILES)?.len()?,
        })
    }
}

// ============================================================
// Testutil
// ============================================================

#[cfg(any(test, feature = "testutil"))]
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

#[cfg(test)]
mod tests;
