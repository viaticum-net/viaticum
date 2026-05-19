// Database layer for viaticum-core β.
// Two-tier architecture: WARM (redb) + HOT (RAM aggregates).
// See docs/beta/tasks/db.md for full spec.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::cluster::StoredClusterState;
use crate::constants::{BYTES_PER_GB, DROP_NOTICE_WINDOW_SECS, HOLDER_DELETE_COOLDOWN_SECS};
use crate::trust::{DeviceTrustRecord, MasterTrustRecord};
use crate::types::{
    BlockAgg, BudgetRecord, DeviceId, EventEntry, FileId, FileRecord, HoldingRecord, HoldingStatus,
    IdentityPub, PeerRecord, PlacementAgg, PlacementStatus, SourceBlockId, SourceBlockRecord,
    SourceBlockStatus, SymbolPlacement, Timestamp, from_cbor_bytes, to_cbor_bytes,
};

// ============================================================
// Table definitions
// ============================================================

/// File catalog. Key = file path (UTF-8). Value = CBOR(FileRecord).
const FILES: TableDefinition<&str, &[u8]> = TableDefinition::new("files");

/// Source block metadata (owner view). Key = SourceBlockId [u8;32]. Value = CBOR(SourceBlockRecord).
const SOURCE_BLOCKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("source_blocks");

/// Symbol placements (owner view). Key = (SourceBlockId[32] || holder DeviceId[32]) = [u8;64].
/// Value = CBOR(SymbolPlacement).
const SYMBOL_PLACEMENTS: TableDefinition<&[u8; 64], &[u8]> =
    TableDefinition::new("symbol_placements");

/// Peer records. Key = DeviceId [u8;32]. Value = CBOR(PeerRecord).
const PEERS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("peers");

/// Held symbols (holder view). Key = (SourceBlockId[32] || owner IdentityPub[32]) = [u8;64].
/// Value = CBOR(HoldingRecord).
const HOLDINGS: TableDefinition<&[u8; 64], &[u8]> = TableDefinition::new("holdings");

/// Event log (append-only). Key = u64 sequence number (monotonic, 1-based). Value = CBOR(EventEntry).
const EVENT_LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("event_log");

/// Budget singleton. Key = "budget". Value = CBOR(BudgetRecord).
const BUDGET: TableDefinition<&str, &[u8]> = TableDefinition::new("budget");

/// PoS weekly results. Key = [DeviceId(32) || week_number_BE(4)] = [u8;36].
/// Value = CBOR(WeeklyPosEntry).
pub(crate) const POS_WEEKLY: TableDefinition<&[u8; 36], &[u8]> = TableDefinition::new("pos_weekly");

/// Cluster state singleton. Key = "cluster_state". Value = CBOR(StoredClusterState).
const CLUSTER_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("cluster_state");

/// System state blobs stored for other nodes (holder-side).
/// Key = owner IdentityPub [u8;32]. Value = CBOR(SystemStateBlobRecord).
const SYSTEM_STATE_BLOBS: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("system_state_blobs");

/// Total bytes restored per peer (cumulative, append-only counter).
/// Key = owner IdentityPub [u8;32]. Value = CBOR(u64) — total bytes served.
const RESTORE_SERVED: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("restore_served");

/// Device trust per DeviceId. Key = DeviceId [u8;32]. Value = CBOR(DeviceTrustRecord).
const DEVICE_TRUST: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("device_trust");

/// Master trust per IdentityPub. Key = IdentityPub [u8;32]. Value = CBOR(MasterTrustRecord).
const MASTER_TRUST: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("master_trust");

/// Device-to-master mapping. Key = DeviceId [u8;32]. Value = CBOR(IdentityPub [u8;32]).
/// Populated from DeviceCertExchange (ε.1+); filled manually in tests.
const DEVICE_TO_MASTER: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("device_to_master");

/// meta: key-value singletons (e.g., next_file_id).
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

/// Meta key for persisted next_file_id.
const META_KEY_NEXT_FILE_ID: &str = "next_file_id";

/// TTL for stored system state blobs: 365 days.
pub const SYSTEM_STATE_TTL_SECS: u64 = 365 * 24 * 3600;

// --- Indices ---

/// file → holders index. Key = (FileId u64 BE[8] || holder DeviceId[32]) = [u8;40].
/// Value = symbol_count (u32). Entry present ↔ holder has symbols for this file.
const FILE_HOLDERS: TableDefinition<&[u8; 40], u32> = TableDefinition::new("file_holders");

/// holder → files index. Key = (holder DeviceId[32] || FileId u64 BE[8]) = [u8;40].
/// Value = symbol_count (u32).
const HOLDER_FILES: TableDefinition<&[u8; 40], u32> = TableDefinition::new("holder_files");

// ============================================================
// Key helpers
// ============================================================

fn file_holder_key(file_id: FileId, holder: &DeviceId) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..8].copy_from_slice(&file_id.0.to_be_bytes());
    key[8..40].copy_from_slice(&holder.0);
    key
}

fn holder_file_key(holder: &DeviceId, file_id: FileId) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(&holder.0);
    key[32..40].copy_from_slice(&file_id.0.to_be_bytes());
    key
}

fn placement_key(block_id: &SourceBlockId, holder: &DeviceId) -> [u8; 64] {
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

fn pos_key(device: &DeviceId, week_number: u32) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..32].copy_from_slice(&device.0);
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
    pub placements: HashMap<(SourceBlockId, DeviceId), PlacementAgg>,
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
            // Accumulate alive symbols per block.
            // Uncertain = 1 missed PoS (peer may be on vacation); symbols are
            // likely still held, so count it as alive — matching cli_server behaviour.
            if matches!(
                placement.status,
                PlacementStatus::Alive | PlacementStatus::Uncertain
            ) {
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
    pub(crate) inner: Arc<redb::Database>,
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
            tx.open_table(RESTORE_SERVED)?;
            tx.open_table(DEVICE_TRUST)?;
            tx.open_table(MASTER_TRUST)?;
            tx.open_table(DEVICE_TO_MASTER)?;
            tx.open_table(META)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Load the persisted `next_file_id` singleton. Returns 1 on fresh database.
    /// Used by the backup coordinator at startup to avoid reusing file IDs after
    /// a crash between file-id allocation and file record persistence.
    pub fn load_next_file_id(&self) -> Result<u64, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(META)?;
        match table.get(META_KEY_NEXT_FILE_ID)? {
            Some(v) => Ok(from_cbor_bytes::<u64>(v.value())?),
            None => Ok(1),
        }
    }

    /// Persist the next file id singleton. Called every time a new FileId is allocated
    /// so the counter survives daemon restart.
    pub fn store_next_file_id(&self, value: u64) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(META)?;
            let bytes = to_cbor_bytes(&value);
            table.insert(META_KEY_NEXT_FILE_ID, bytes.as_slice())?;
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
            tracing::error!("db: check_integrity returned false, proceeding anyway");
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
        let db =
            redb::Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?;
        Self::create_tables(&db)?;
        let hot = HotCache::build_from_db(&db)?;
        Ok(Db {
            inner: Arc::new(db),
            hot: Arc::new(RwLock::new(hot)),
        })
    }

    /// Access hot cache for read.
    ///
    /// If the lock is poisoned (another thread panicked while holding write access),
    /// we fall back to the inner data rather than propagating the panic. The hot
    /// cache is only mutated AFTER `tx.commit()` succeeds (see BLOCK-3 fix), so the
    /// poisoned state is at worst a partial delta from an interrupted apply — the
    /// reader gets eventually-consistent data and the next write re-applies.
    pub fn hot(&self) -> impl Deref<Target = HotCache> + '_ {
        self.hot.read().unwrap_or_else(|e| e.into_inner())
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
        for item in table.range::<&str>(prefix..)? {
            let (k, v) = item?;
            if !k.value().starts_with(prefix) {
                break;
            }
            let record: FileRecord = from_cbor_bytes(v.value())?;
            records.push(record);
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

    /// Update the Wave-8 cached fields on a SourceBlockRecord without touching other fields.
    ///
    /// Reads the record, applies the new values, and writes back. Returns `DbError::NotFound`
    /// if no record exists for `block_id`.
    ///
    /// This is a read-modify-write inside a single logical operation but uses two separate
    /// redb transactions (read then write) — the same pattern as
    /// `transition_placement_offered_to_alive`.
    /// Not atomic against concurrent writers, but the daemon is single-process and the migration
    /// runs before any workers start, so no concurrent writes occur during migration.
    #[allow(clippy::too_many_arguments)]
    pub fn update_block_cached_fields(
        &self,
        block_id: &SourceBlockId,
        importance: f64,
        current_alive: u32,
        current_reliability: f64,
        target_reliability: f64,
        last_attempted_at: Option<Timestamp>,
        last_pool_signature: u64,
    ) -> Result<(), DbError> {
        let mut record = self
            .get_source_block(block_id)?
            .ok_or_else(|| DbError::NotFound(format!("SourceBlockRecord {block_id}")))?;
        record.importance = importance;
        record.current_alive = current_alive;
        record.current_reliability = current_reliability;
        record.target_reliability = target_reliability;
        record.last_attempted_at = last_attempted_at;
        record.last_pool_signature = last_pool_signature;
        self.upsert_source_block(&record)
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

    /// Sum of bytes committed to the network (Active source blocks only).
    /// Uses encrypted_size if available, falls back to k * t as a conservative estimate.
    /// k * t is the padded encoded size before trim — a safe upper bound for legacy records.
    pub fn committed_bytes(&self) -> Result<u64, DbError> {
        let blocks = self.list_source_blocks_by_status(SourceBlockStatus::Active)?;
        Ok(blocks
            .iter()
            .map(|b| b.encrypted_size.unwrap_or(b.k as u64 * b.t as u64))
            .sum())
    }

    /// Return the highest-priority source block that needs work, or `None` if nothing to do.
    ///
    /// "Needs work" means: `status == Active`, `target_reliability > 0.0`, and
    /// `current_reliability < target_reliability`.
    ///
    /// Blocks in cooldown are excluded. A block is in cooldown when:
    /// - it was attempted recently (`last_attempted_at` is `Some(t)` with `now - t < cooldown`), AND
    /// - the authenticated peer pool has not changed (`last_pool_signature == current_pool_sig`).
    ///
    /// Cooldown is skipped entirely when `current_pool_sig == 0` (no authenticated peers).
    ///
    /// The returned block is the one with the highest `priority` among eligible blocks.
    /// Priority formula: `importance × (1 + coef × (current_alive / n_target))`.
    /// Ties are broken by `last_attempted_at ASC` (never-attempted wins), then `block_id ASC`.
    ///
    /// # Arguments
    ///
    /// * `coef` — completion bonus coefficient from `ReliabilityConfig`. Typically 1.5.
    /// * `cooldown` — cooldown window. Typically `Duration::from_secs(cfg.reliability.cooldown_base_secs)`.
    /// * `now` — current time. Pass `Timestamp::now()` in production; pass a fixed value in tests.
    /// * `current_pool_sig` — XxHash64 of the sorted authenticated peer DeviceId set at this moment.
    ///   `0` = no authenticated peers (cooldown bypassed).
    ///
    /// # Returns
    ///
    /// `Ok(Some(record))` — the block to work on next.
    /// `Ok(None)` — no block needs work (all at target, or all eligible are in cooldown).
    ///
    /// # Errors
    ///
    /// Returns `DbError` only if the underlying DB read fails.
    ///
    /// # Panics
    ///
    /// Never panics.
    ///
    /// # Read-only guarantee
    ///
    /// This function does NOT mutate any DB record. The caller (Wave 11 worker) is responsible
    /// for writing `last_attempted_at` and `last_pool_signature` after dispatching work.
    pub fn next_work_item(
        &self,
        coef: f64,
        cooldown: Duration,
        now: Timestamp,
        current_pool_sig: u64,
    ) -> Result<Option<SourceBlockRecord>, DbError> {
        let all = self.list_all_source_blocks()?;
        let cooldown_secs = cooldown.as_secs();

        let eligible = all.into_iter().filter(|b| {
            if b.status != SourceBlockStatus::Active {
                return false;
            }
            if b.target_reliability <= 0.0 || b.current_reliability >= b.target_reliability {
                return false;
            }
            if current_pool_sig != 0
                && let Some(last_at) = b.last_attempted_at
            {
                let elapsed = now.0.saturating_sub(last_at.0);
                if elapsed < cooldown_secs && b.last_pool_signature == current_pool_sig {
                    return false;
                }
            }
            true
        });

        let winner = eligible.max_by(|a, b| {
            let pa =
                crate::priority::priority(a.importance, a.current_alive, a.n.unwrap_or(0), coef);
            let pb =
                crate::priority::priority(b.importance, b.current_alive, b.n.unwrap_or(0), coef);
            pa.total_cmp(&pb)
                .then(a.last_attempted_at.cmp(&b.last_attempted_at).reverse())
                .then(a.block_id.0.cmp(&b.block_id.0).reverse())
        });

        Ok(winner)
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

        // Compute delta inside the transaction, but apply to hot cache only after commit.
        let old_alive: u32;
        let new_alive: u32;
        {
            let tx = self.inner.begin_write()?;
            {
                let mut placements = tx.open_table(SYMBOL_PLACEMENTS)?;
                // Read old record to adjust hot cache delta correctly.
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

                // Compute the delta (what needs to change in the hot cache).
                // Alive | Uncertain both count — matches cli_server and protocol intent.
                old_alive = old
                    .as_ref()
                    .filter(|o| {
                        matches!(
                            o.status,
                            PlacementStatus::Alive | PlacementStatus::Uncertain
                        )
                    })
                    .map(|o| o.symbol_count())
                    .unwrap_or(0);
                new_alive = if matches!(
                    record.status,
                    PlacementStatus::Alive | PlacementStatus::Uncertain
                ) {
                    count
                } else {
                    0
                };
            }
            // Commit DB first — hot cache must only be updated after a successful commit.
            tx.commit()?;
        }

        // DB is committed; now apply delta to the hot cache.
        let mut hot = self.hot.write().unwrap_or_else(|e| e.into_inner());
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

        Ok(())
    }

    /// Get placement for (block_id, holder_id) pair. None if not found.
    pub fn get_placement(
        &self,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Result<Option<SymbolPlacement>, DbError> {
        let key = placement_key(block_id, holder_id);
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SYMBOL_PLACEMENTS)?;
        match table.get(&key)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Transition a placement from Offered to Alive.
    ///
    /// - Reads the existing placement from DB.
    /// - If the placement does not exist or its status is not Offered: returns Ok(false).
    /// - Sets status = Alive, placed_at = alive_at.
    /// - Calls upsert_placement to persist the change and update the hot cache.
    /// - Returns Ok(true) if the transition happened, Ok(false) if skipped.
    pub fn transition_placement_offered_to_alive(
        &self,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
        alive_at: Timestamp,
    ) -> Result<bool, DbError> {
        let existing = match self.get_placement(block_id, holder_id)? {
            Some(p) => p,
            None => return Ok(false),
        };
        if existing.status != PlacementStatus::Offered {
            return Ok(false);
        }
        let mut updated = existing;
        updated.status = PlacementStatus::Alive;
        updated.placed_at = alive_at;
        self.upsert_placement(&updated)?;
        Ok(true)
    }

    /// Delete placement. Also cleans up indices and HOT cache.
    /// Returns the deleted placement, or None if it did not exist.
    pub fn delete_placement(
        &self,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Result<Option<SymbolPlacement>, DbError> {
        let key = placement_key(block_id, holder_id);

        // Capture the old record inside the transaction to compute the hot cache delta,
        // but apply to the hot cache only after a successful commit.
        let old_record: Option<SymbolPlacement>;
        {
            let tx = self.inner.begin_write()?;
            {
                let mut placements = tx.open_table(SYMBOL_PLACEMENTS)?;
                // Read before delete so we can update indices and hot cache.
                old_record = match placements.get(&key)? {
                    Some(v) => Some(from_cbor_bytes(v.value())?),
                    None => None,
                };
                placements.remove(&key)?;

                if let Some(ref rec) = old_record {
                    let fh_key = file_holder_key(rec.file_id, holder_id);
                    let hf_key = holder_file_key(holder_id, rec.file_id);
                    let mut fh = tx.open_table(FILE_HOLDERS)?;
                    let mut hf = tx.open_table(HOLDER_FILES)?;
                    fh.remove(&fh_key)?;
                    hf.remove(&hf_key)?;
                }
            }
            // Commit DB first — hot cache must only be updated after a successful commit.
            tx.commit()?;
        }

        // DB is committed; now apply delta to the hot cache.
        if let Some(ref old_rec) = old_record {
            let mut hot = self.hot.write().unwrap_or_else(|e| e.into_inner());
            hot.placements.remove(&(*block_id, *holder_id));

            if matches!(
                old_rec.status,
                PlacementStatus::Alive | PlacementStatus::Uncertain
            ) {
                let count = old_rec.symbol_count();
                if let Some(agg) = hot.blocks.get_mut(block_id) {
                    agg.total_alive_symbols = agg.total_alive_symbols.saturating_sub(count);
                    if agg.total_alive_symbols == 0 {
                        hot.blocks.remove(block_id);
                    }
                }
            } else {
                // If no more placements for this block at all, remove the block entry.
                let still_has_placements = hot.placements.keys().any(|(bid, _)| bid == block_id);
                if !still_has_placements {
                    hot.blocks.remove(block_id);
                }
            }
        }

        Ok(old_record)
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
        holder_id: &DeviceId,
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
    pub fn list_holders_for_file(&self, file_id: FileId) -> Result<Vec<DeviceId>, DbError> {
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
            result.push(DeviceId(holder_bytes));
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

    /// Return the high-water mark ESI for a source block.
    ///
    /// Scans all placements for `block_id` and returns `max(start + count)` across
    /// all `esi_ranges` entries. Returns 0 if there are no placements.
    ///
    /// Used by RepairAgent to allocate new ESI ranges that do not overlap existing
    /// ones when placing a repaired block on a new holder.
    pub fn max_esi_for_block(&self, block_id: &SourceBlockId) -> Result<u32, DbError> {
        let placements = self.list_placements_for_block(block_id)?;
        let max_esi = placements
            .iter()
            .flat_map(|p| p.esi_ranges.iter())
            .map(|(start, count)| start.saturating_add(*count))
            .max()
            .unwrap_or(0);
        Ok(max_esi)
    }

    /// Convenience: list all file_ids a holder has symbols for (via holder_files index).
    pub fn list_files_for_holder(&self, holder_id: &DeviceId) -> Result<Vec<FileId>, DbError> {
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
            peers.insert(&record.device_id.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_peer(&self, device_id: &DeviceId) -> Result<Option<PeerRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(PEERS)?;
        match table.get(&device_id.0)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn delete_peer(&self, device_id: &DeviceId) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut peers = tx.open_table(PEERS)?;
            peers.remove(&device_id.0)?;
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

    /// Recompute storage-balance fields for a device and update `trust_s` in the PeerRecord.
    ///
    /// - `bytes_we_store_for_peer`: sum of `total_bytes` over Active holdings whose
    ///   `owner_id == master_for(device_id)`. Per-master because escrow is economic
    ///   between humans, not devices. (HOLDINGS table — our holder-side view.)
    /// - `bytes_peer_stores_for_us`: sum of `symbol_count * t` over Alive placements
    ///   whose `holder_id == device_id`. Per-device. (SYMBOL_PLACEMENTS table — our owner-side view.)
    ///
    /// `trust_s = if bytes_we_store == 0 { 1.0 } else { peer_stores / we_store }`
    ///
    /// No-op (returns Ok) if the device is not yet in the DB.
    pub fn refresh_peer_storage_bytes(&self, device_id: &DeviceId) -> Result<(), DbError> {
        // Compute bytes_we_store_for_peer from HOLDINGS (per-master).
        let we_store: u64 = match self.get_master_for_device(device_id)? {
            Some(master) => self
                .list_holdings_for_owner(&master)?
                .into_iter()
                .filter(|h| h.status == HoldingStatus::Active)
                .map(|h| h.total_bytes)
                .sum(),
            None => 0,
        };

        // Compute bytes_peer_stores_for_us from SYMBOL_PLACEMENTS (per-device).
        // Each alive placement contributes symbol_count * t bytes.
        let peer_stores: u64 = {
            let mut total = 0u64;
            for placement in self.list_placements_for_holder(device_id)? {
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

        // Update PeerRecord. No-op if device not yet in DB.
        let mut record = match self.get_peer(device_id)? {
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

    /// Holdings where delete_requested_at + HOLDER_DELETE_COOLDOWN_SECS/time_scale <= now.
    pub fn list_holdings_cooldown_expired(
        &self,
        now: Timestamp,
        time_scale: u64,
    ) -> Result<Vec<HoldingRecord>, DbError> {
        let cooldown = HOLDER_DELETE_COOLDOWN_SECS / time_scale.max(1);
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDINGS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            if record.status == HoldingStatus::MarkedForDelete
                && let Some(requested_at) = record.delete_requested_at
                && requested_at.0.saturating_add(cooldown) <= now.0
            {
                records.push(record);
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
            if let Some(sent_at) = record.drop_notice_sent_at
                && sent_at.0.saturating_add(DROP_NOTICE_WINDOW_SECS) <= now.0
            {
                records.push(record);
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

    /// Drop all event_log entries with sequence number < `seq`.
    ///
    /// Review BLOCK-4: event_log grows unbounded without pruning.
    /// Returns number of rows removed.
    pub fn truncate_event_log_before(&self, seq: u64) -> Result<usize, DbError> {
        let tx = self.inner.begin_write()?;
        let mut removed = 0usize;
        {
            let mut table = tx.open_table(EVENT_LOG)?;
            // Collect keys first to avoid iterator invalidation.
            let mut to_delete: Vec<u64> = Vec::new();
            let upper: u64 = seq.saturating_sub(1);
            for item in table.range::<u64>(..=upper)? {
                let (k, _) = item?;
                to_delete.push(k.value());
            }
            for k in to_delete {
                if table.remove(&k)?.is_some() {
                    removed += 1;
                }
            }
        }
        tx.commit()?;
        Ok(removed)
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
    /// Upsert weekly PoS entry for a device.
    pub fn upsert_pos_weekly(
        &self,
        device: &DeviceId,
        week_number: u32,
        entry: &WeeklyPosEntry,
    ) -> Result<(), DbError> {
        let key = pos_key(device, week_number);
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
        device: &DeviceId,
        week_number: u32,
    ) -> Result<Option<WeeklyPosEntry>, DbError> {
        let key = pos_key(device, week_number);
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(POS_WEEKLY)?;
        match table.get(&key)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// All pos weekly entries for a device.
    pub fn list_pos_weekly_for_peer(
        &self,
        device: &DeviceId,
    ) -> Result<Vec<(u32, WeeklyPosEntry)>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(POS_WEEKLY)?;
        let mut result = Vec::new();
        // Range scan: keys = [device(32) || week_be(4)]. Prefix by device bytes.
        let mut lo = [0u8; 36];
        let mut hi = [0u8; 36];
        lo[..32].copy_from_slice(&device.0);
        hi[..32].copy_from_slice(&device.0);
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

    /// Drop all pos_weekly entries whose week number is strictly less than
    /// `keep_after_week`. Returns the number of rows removed.
    ///
    /// Review BLOCK-4: pos_weekly grows unbounded. With P_WINDOW_WEEKS rolling
    /// at ~30 entries per device, anything older is pure history we never use.
    pub fn prune_pos_weekly_before(&self, keep_after_week: u32) -> Result<usize, DbError> {
        let tx = self.inner.begin_write()?;
        let mut removed = 0usize;
        {
            let mut table = tx.open_table(POS_WEEKLY)?;
            let mut to_delete: Vec<[u8; 36]> = Vec::new();
            for item in table.iter()? {
                let (k, _) = item?;
                let key_bytes: [u8; 36] = *k.value();
                let week = u32::from_be_bytes(key_bytes[32..36].try_into().unwrap());
                if week < keep_after_week {
                    to_delete.push(key_bytes);
                }
            }
            for k in &to_delete {
                if table.remove(k)?.is_some() {
                    removed += 1;
                }
            }
        }
        tx.commit()?;
        Ok(removed)
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
    pub fn delete_system_state_blob(&self, owner: &IdentityPub) -> Result<(), DbError> {
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
// Restore served table
// ============================================================

impl Db {
    /// Compute GB·days stored for a given owner across all Active holdings.
    ///
    /// Formula: sum over active holdings of (total_bytes / BYTES_PER_GB * age_days)
    /// where age_days = (now - received_at) * time_scale / SECS_PER_DAY.
    ///
    /// `time_scale` accelerates simulated time (1 = real time, 100_000 = gamma tests).
    /// This matches the same time acceleration used everywhere else in the protocol.
    ///
    /// Returns 0.0 if no active holdings exist for this owner.
    pub fn stored_for_peer_gb_days(
        &self,
        owner_id: &IdentityPub,
        now: Timestamp,
        time_scale: u64,
    ) -> Result<f64, DbError> {
        const SECS_PER_DAY: f64 = 86_400.0;

        let scale = time_scale.max(1) as f64;
        let holdings = self.list_holdings_for_owner(owner_id)?;
        let mut total = 0.0_f64;
        for h in holdings {
            if h.status != HoldingStatus::Active {
                continue;
            }
            let age_secs = now.0.saturating_sub(h.received_at.0) as f64;
            let age_days = age_secs * scale / SECS_PER_DAY;
            let gb = h.total_bytes as f64 / BYTES_PER_GB;
            total += gb * age_days;
        }
        Ok(total)
    }

    /// Per-owner holding contribution in GB-days, summed across all active
    /// HoldingRecords we hold for others. Used by the budget planner to grant
    /// offer-side credit in proportion to our usefulness as a holder.
    ///
    /// Returns one entry per owner_id that has at least one active holding.
    /// Owners with zero age contribute nothing and are omitted.
    pub fn held_contributions_gb_days(
        &self,
        now: Timestamp,
        time_scale: u64,
    ) -> Result<Vec<(IdentityPub, f64)>, DbError> {
        const SECS_PER_DAY: f64 = 86_400.0;

        let scale = time_scale.max(1) as f64;
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDINGS)?;
        let mut by_owner: std::collections::HashMap<IdentityPub, f64> =
            std::collections::HashMap::new();
        for item in table.iter()? {
            let (_k, v) = item?;
            let h: HoldingRecord = from_cbor_bytes(v.value())?;
            if h.status != HoldingStatus::Active {
                continue;
            }
            let age_secs = now.0.saturating_sub(h.received_at.0) as f64;
            if age_secs <= 0.0 {
                continue;
            }
            let age_days = age_secs * scale / SECS_PER_DAY;
            let gb = h.total_bytes as f64 / BYTES_PER_GB;
            *by_owner.entry(h.owner_id).or_insert(0.0) += gb * age_days;
        }
        Ok(by_owner.into_iter().collect())
    }

    /// Total bytes we have served to this owner for restore (cumulative).
    /// Returns 0 if no record exists.
    pub fn restored_total_bytes(&self, owner_id: &IdentityPub) -> Result<u64, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(RESTORE_SERVED)?;
        match table.get(&owner_id.0)? {
            Some(v) => {
                let total: u64 = from_cbor_bytes(v.value())?;
                Ok(total)
            }
            None => Ok(0),
        }
    }

    /// Increment the restore-served counter for this owner by `bytes_served`.
    ///
    /// Reads current value, adds bytes_served, writes back atomically.
    /// Called after successful symbol delivery.
    pub fn record_restore_served(
        &self,
        owner_id: &IdentityPub,
        bytes_served: u64,
    ) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(RESTORE_SERVED)?;
            let current: u64 = match table.get(&owner_id.0)? {
                Some(v) => from_cbor_bytes(v.value())?,
                None => 0,
            };
            let new_total = current.saturating_add(bytes_served);
            let bytes = to_cbor_bytes(&new_total);
            table.insert(&owner_id.0, bytes.as_slice())?;
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
// Device trust table
// ============================================================

impl Db {
    /// Get device trust record. None if device not known.
    pub fn get_device_trust(
        &self,
        device: &DeviceId,
    ) -> Result<Option<DeviceTrustRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(DEVICE_TRUST)?;
        match table.get(&device.0)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Upsert device trust record.
    pub fn set_device_trust(&self, record: &DeviceTrustRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(DEVICE_TRUST)?;
            table.insert(&record.device_id.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Get master trust record. None if master not known.
    pub fn get_master_trust(
        &self,
        master: &IdentityPub,
    ) -> Result<Option<MasterTrustRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(MASTER_TRUST)?;
        match table.get(&master.0)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Upsert master trust record.
    pub fn set_master_trust(&self, record: &MasterTrustRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(MASTER_TRUST)?;
            table.insert(&record.identity.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Get the master IdentityPub for a device. None if mapping unknown.
    pub fn get_master_for_device(&self, device: &DeviceId) -> Result<Option<IdentityPub>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(DEVICE_TO_MASTER)?;
        match table.get(&device.0)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Store device-to-master mapping (learned from DeviceCertificate).
    pub fn set_master_for_device(
        &self,
        device: &DeviceId,
        master: &IdentityPub,
    ) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(master);
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(DEVICE_TO_MASTER)?;
            table.insert(&device.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// List all DeviceIds known to belong to a master identity.
    pub fn get_devices_for_master(&self, master: &IdentityPub) -> Result<Vec<DeviceId>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(DEVICE_TO_MASTER)?;
        let mut result = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            let mapped_master: IdentityPub = from_cbor_bytes(v.value())?;
            if mapped_master == *master {
                result.push(DeviceId(*k.value()));
            }
        }
        Ok(result)
    }
}

// ============================================================
// Multi-table atomic write transaction
// ============================================================

/// Internal: one pending hot-cache update, queued during a DbWriteTxn.
/// Applied in order after a successful commit.
enum HotCacheDelta {
    /// A placement was written. Carries the old alive count (before this txn
    /// write) and the new alive count (after).
    PlacementUpserted {
        block_id: SourceBlockId,
        holder_id: DeviceId,
        old_alive: u32,
        new_alive: u32,
        new_count: u32,
        new_status: PlacementStatus,
        new_last_pos: Option<Timestamp>,
    },
    /// A placement was deleted.
    PlacementDeleted {
        block_id: SourceBlockId,
        holder_id: DeviceId,
        was_alive: bool,
        old_count: u32,
    },
}

/// Handle to an open, uncommitted write transaction.
///
/// Call individual write methods to accumulate operations, then call
/// `commit()` to flush all writes atomically and update the hot cache.
///
/// If dropped without calling `commit()`, the transaction is rolled back.
/// No partial writes reach disk. The hot cache is not updated.
///
/// Note: redb supports only one concurrent write transaction. Calling
/// `db.write_txn()` while another `DbWriteTxn` is open for the same `Db`
/// will block until the first is committed or dropped.
///
/// `DbWriteTxn` is `!Send` because redb's `WriteTransaction` is `!Send`.
pub struct DbWriteTxn<'db> {
    txn: redb::WriteTransaction,
    hot: &'db Arc<RwLock<HotCache>>,
    /// Accumulated hot-cache deltas to apply after commit, in order.
    deltas: Vec<HotCacheDelta>,
}

impl<'db> DbWriteTxn<'db> {
    /// Insert or replace a SourceBlockRecord. No hot cache entry (blocks agg
    /// is derived from placements, not source block records).
    pub fn upsert_source_block(&mut self, record: &SourceBlockRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        {
            let mut table = self.txn.open_table(SOURCE_BLOCKS)?;
            table.insert(&record.block_id.0, bytes.as_slice())?;
        }
        Ok(())
    }

    /// Delete a SourceBlockRecord. No hot cache entry.
    pub fn delete_source_block(&mut self, block_id: &SourceBlockId) -> Result<(), DbError> {
        {
            let mut table = self.txn.open_table(SOURCE_BLOCKS)?;
            table.remove(&block_id.0)?;
        }
        Ok(())
    }

    /// Insert or replace a SymbolPlacement. Queues a hot cache delta.
    pub fn upsert_placement(&mut self, record: &SymbolPlacement) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let key = placement_key(&record.source_block_id, &record.holder_id);
        let fh_key = file_holder_key(record.file_id, &record.holder_id);
        let hf_key = holder_file_key(&record.holder_id, record.file_id);
        let count = record.symbol_count();

        let old_alive: u32;
        let new_alive: u32;

        {
            let mut placements = self.txn.open_table(SYMBOL_PLACEMENTS)?;
            // Read old record (within this transaction) to compute the delta correctly.
            let old: Option<SymbolPlacement> = match placements.get(&key)? {
                Some(v) => Some(from_cbor_bytes(v.value())?),
                None => None,
            };
            placements.insert(&key, bytes.as_slice())?;

            // Compute delta.
            old_alive = old
                .as_ref()
                .filter(|o| {
                    matches!(
                        o.status,
                        PlacementStatus::Alive | PlacementStatus::Uncertain
                    )
                })
                .map(|o| o.symbol_count())
                .unwrap_or(0);
            new_alive = if matches!(
                record.status,
                PlacementStatus::Alive | PlacementStatus::Uncertain
            ) {
                count
            } else {
                0
            };
        }
        {
            let mut fh = self.txn.open_table(FILE_HOLDERS)?;
            fh.insert(&fh_key, count)?;
        }
        {
            let mut hf = self.txn.open_table(HOLDER_FILES)?;
            hf.insert(&hf_key, count)?;
        }

        self.deltas.push(HotCacheDelta::PlacementUpserted {
            block_id: record.source_block_id,
            holder_id: record.holder_id,
            old_alive,
            new_alive,
            new_count: count,
            new_status: record.status,
            new_last_pos: record.last_verified,
        });

        Ok(())
    }

    /// Delete a SymbolPlacement. Queues a hot cache delta.
    /// Returns the deleted placement, or None if it did not exist.
    pub fn delete_placement(
        &mut self,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Result<Option<SymbolPlacement>, DbError> {
        let key = placement_key(block_id, holder_id);

        let old_record: Option<SymbolPlacement>;
        {
            let mut placements = self.txn.open_table(SYMBOL_PLACEMENTS)?;
            old_record = match placements.get(&key)? {
                Some(v) => Some(from_cbor_bytes(v.value())?),
                None => None,
            };
            placements.remove(&key)?;
        }

        if let Some(ref rec) = old_record {
            let fh_key = file_holder_key(rec.file_id, holder_id);
            let hf_key = holder_file_key(holder_id, rec.file_id);
            {
                let mut fh = self.txn.open_table(FILE_HOLDERS)?;
                fh.remove(&fh_key)?;
            }
            {
                let mut hf = self.txn.open_table(HOLDER_FILES)?;
                hf.remove(&hf_key)?;
            }

            let was_alive = matches!(
                rec.status,
                PlacementStatus::Alive | PlacementStatus::Uncertain
            );
            self.deltas.push(HotCacheDelta::PlacementDeleted {
                block_id: *block_id,
                holder_id: *holder_id,
                was_alive,
                old_count: rec.symbol_count(),
            });
        }

        Ok(old_record)
    }

    /// Append an EventEntry. Assigns the next sequence number within the
    /// transaction (visible to subsequent reads within the same transaction).
    /// Returns the assigned sequence number.
    pub fn append_event(&mut self, entry: &EventEntry) -> Result<u64, DbError> {
        let bytes = to_cbor_bytes(entry);
        let seq = {
            // Read last seq from within the same transaction so multiple calls
            // within one DbWriteTxn assign contiguous sequence numbers.
            let table = self.txn.open_table(EVENT_LOG)?;
            let last_seq = match table.last()? {
                Some((k, _)) => k.value(),
                None => 0,
            };
            drop(table);
            let next_seq = last_seq + 1;
            let mut table = self.txn.open_table(EVENT_LOG)?;
            table.insert(next_seq, bytes.as_slice())?;
            next_seq
        };
        Ok(seq)
    }

    /// Insert or replace a FileRecord.
    pub fn upsert_file(&mut self, record: &FileRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        {
            let mut files = self.txn.open_table(FILES)?;
            files.insert(record.path.as_str(), bytes.as_slice())?;
        }
        Ok(())
    }

    /// Delete a FileRecord by path.
    pub fn delete_file(&mut self, path: &str) -> Result<(), DbError> {
        {
            let mut files = self.txn.open_table(FILES)?;
            files.remove(path)?;
        }
        Ok(())
    }

    /// Insert or replace a HoldingRecord.
    pub fn upsert_holding(&mut self, record: &HoldingRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let key = holding_key(&record.source_block_id, &record.owner_id);
        {
            let mut holdings = self.txn.open_table(HOLDINGS)?;
            holdings.insert(&key, bytes.as_slice())?;
        }
        Ok(())
    }

    /// Delete a HoldingRecord.
    pub fn delete_holding(
        &mut self,
        block_id: &SourceBlockId,
        owner_id: &IdentityPub,
    ) -> Result<(), DbError> {
        let key = holding_key(block_id, owner_id);
        {
            let mut holdings = self.txn.open_table(HOLDINGS)?;
            holdings.remove(&key)?;
        }
        Ok(())
    }

    /// Commit all writes atomically. Updates hot cache after successful commit.
    /// Consumes self: the guard is unusable after this call.
    pub fn commit(self) -> Result<(), DbError> {
        // Commit to redb first. On failure, hot cache is NOT updated.
        self.txn.commit()?;

        // redb commit succeeded — now apply accumulated deltas to the hot cache.
        let mut hot = self.hot.write().unwrap_or_else(|e| e.into_inner());
        for delta in self.deltas {
            match delta {
                HotCacheDelta::PlacementUpserted {
                    block_id,
                    holder_id,
                    old_alive,
                    new_alive,
                    new_count,
                    new_status,
                    new_last_pos,
                } => {
                    // Update block aggregate.
                    let block_agg = hot.blocks.entry(block_id).or_insert(BlockAgg {
                        k: 0,
                        total_alive_symbols: 0,
                    });
                    block_agg.total_alive_symbols =
                        block_agg.total_alive_symbols.saturating_sub(old_alive) + new_alive;

                    // Update per-(block, holder) aggregate.
                    hot.placements.insert(
                        (block_id, holder_id),
                        PlacementAgg {
                            symbol_count: new_count,
                            status: new_status,
                            last_pos: new_last_pos,
                        },
                    );
                }
                HotCacheDelta::PlacementDeleted {
                    block_id,
                    holder_id,
                    was_alive,
                    old_count,
                } => {
                    hot.placements.remove(&(block_id, holder_id));

                    if was_alive {
                        if let Some(agg) = hot.blocks.get_mut(&block_id) {
                            agg.total_alive_symbols =
                                agg.total_alive_symbols.saturating_sub(old_count);
                            if agg.total_alive_symbols == 0 {
                                hot.blocks.remove(&block_id);
                            }
                        }
                    } else {
                        // Placement wasn't alive; check if any placements remain.
                        let still_has_placements =
                            hot.placements.keys().any(|(bid, _)| *bid == block_id);
                        if !still_has_placements {
                            hot.blocks.remove(&block_id);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Db {
    /// Open a multi-table write transaction. All writes on the returned guard
    /// are part of a single redb `WriteTransaction`. Call `guard.commit()` to
    /// flush atomically and update the hot cache.
    ///
    /// Note: redb supports only one concurrent write transaction per database.
    /// Calling `write_txn()` while another `DbWriteTxn` is open will block
    /// until the first is committed or dropped.
    pub fn write_txn(&self) -> Result<DbWriteTxn<'_>, DbError> {
        let txn = self.inner.begin_write()?;
        Ok(DbWriteTxn {
            txn,
            hot: &self.hot,
            deltas: Vec::new(),
        })
    }
}

// ============================================================
// Testutil
// ============================================================

#[cfg(any(test, feature = "testutil"))]
pub mod testutil {
    use crate::db::Db;
    use crate::types::{DeviceId, IdentityPub, Timestamp};

    pub fn test_db() -> Db {
        Db::open_in_memory().expect("test db")
    }

    /// Legacy helper: returns a DeviceId for use in tests that previously used IdentityPub.
    pub fn test_peer() -> DeviceId {
        DeviceId([1u8; 32])
    }

    /// Legacy helper: returns Vec<DeviceId> for use in tests.
    pub fn test_peers(n: usize) -> Vec<DeviceId> {
        (0..n).map(|i| DeviceId([i as u8 + 1; 32])).collect()
    }

    /// Returns an IdentityPub for use in tests that need a master identity.
    pub fn test_master() -> IdentityPub {
        IdentityPub([0xAAu8; 32])
    }

    pub fn week(n: u32) -> Timestamp {
        Timestamp(n as u64 * crate::constants::SECS_PER_WEEK)
    }
}

#[cfg(test)]
mod tests;
