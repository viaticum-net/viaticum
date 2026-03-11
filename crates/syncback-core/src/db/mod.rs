use std::sync::Arc;

use redb::{ReadableTable, TableDefinition};

use crate::types::{
    from_cbor_bytes, to_cbor_bytes, BudgetRecord, EscrowRestoreLog, FileId, FileRecord,
    HoldingRecord, IdentityPub, PeerRecord, ScheduleRecord, ShardId, ShardRecord, ShardState,
    ShardStatus, Timestamp, UnitId, UnitRecord, UnitStatus,
};

// === Table definitions ===

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

/// Dirty file index. Key = file path. Value = timestamp (u64 BE seconds).
/// Entry present ↔ file is dirty. Removed when file is backed up.
const DIRTY_FILES: TableDefinition<&str, u64> = TableDefinition::new("dirty_files");

/// Stale unit index. Key = UnitId bytes. Value = stale_ratio (f64 as u64 bits).
/// Entry present ↔ unit is Stale.
const STALE_UNITS: TableDefinition<&[u8; 32], u64> = TableDefinition::new("stale_units");

/// Shards due for PoS verification. Key = ShardId bytes. Value = last_verified ts (u64).
/// Entry present ↔ shard is Stored and PoS is needed.
const UNVERIFIED_SHARDS: TableDefinition<&[u8; 32], u64> =
    TableDefinition::new("unverified_shards");

/// Escrow restore log. Key = IdentityPub bytes. Value = CBOR(EscrowRestoreLog).
/// Tracks cumulative bytes this holder has served to each owner.
const ESCROW_RESTORE_LOG: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("escrow_restore_log");

/// Weekly PoS results. Key = [IdentityPub(32) || week_number_be(4)]. Value = CBOR(WeeklyPosRecord).
/// Used by trust module for P/I calculation.
pub(crate) const POS_WEEKLY: TableDefinition<&[u8; 36], &[u8]> =
    TableDefinition::new("pos_weekly");

// === DbError ===

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

// === Db ===

/// Cheaply cloneable handle to the database.
/// Arc inside: clone() does not copy the database, it increments a refcount.
/// All methods take &self — redb's internal MVCC handles concurrency.
#[derive(Clone)]
pub struct Db {
    pub(crate) inner: Arc<redb::Database>,
}

impl Db {
    /// Open (or create) a database at the given path.
    /// Creates all tables if they do not exist.
    /// Panics if the path is unwritable or the database is corrupt —
    /// these are fatal errors the daemon cannot recover from.
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
            tx.open_table(ESCROW_RESTORE_LOG)?;
            tx.open_table(POS_WEEKLY)?;
        }
        tx.commit()?;
        Ok(Db {
            inner: Arc::new(db),
        })
    }
}

// === Files table ===

impl Db {
    /// Insert or replace a file record.
    pub fn upsert_file(&self, record: &FileRecord) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut files = tx.open_table(FILES)?;
            let mut dirty_idx = tx.open_table(DIRTY_FILES)?;
            let bytes = to_cbor_bytes(record);
            files.insert(record.path.as_str(), bytes.as_slice())?;
            if record.dirty {
                dirty_idx.insert(record.path.as_str(), record.first_seen.0)?;
            } else {
                dirty_idx.remove(record.path.as_str())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Get a file record by path. Returns None if not found.
    pub fn get_file(&self, path: &str) -> Result<Option<FileRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(FILES)?;
        match table.get(path)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Get a file record by FileId.
    /// Scans the files table — O(n). Acceptable because FileId lookup is rare.
    pub fn get_file_by_id(&self, file_id: FileId) -> Result<Option<FileRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(FILES)?;
        for entry in table.iter()? {
            let (_, v) = entry?;
            let record: FileRecord = from_cbor_bytes(v.value())?;
            if record.file_id == file_id {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// Delete a file record by path. No-op if not found.
    pub fn delete_file(&self, path: &str) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut files = tx.open_table(FILES)?;
            let mut dirty_idx = tx.open_table(DIRTY_FILES)?;
            files.remove(path)?;
            dirty_idx.remove(path)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Mark file as dirty (changed, needs backup).
    /// Updates dirty=true in FileRecord AND inserts into dirty_files index.
    pub fn mark_file_dirty(&self, path: &str, ts: Timestamp) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut files = tx.open_table(FILES)?;
            let mut dirty_idx = tx.open_table(DIRTY_FILES)?;
            let record_bytes: Vec<u8> = match files.get(path)? {
                Some(v) => v.value().to_vec(),
                None => return Err(DbError::NotFound(path.to_string())),
            };
            let mut record: FileRecord = from_cbor_bytes(&record_bytes)?;
            record.dirty = true;
            let bytes = to_cbor_bytes(&record);
            files.insert(path, bytes.as_slice())?;
            dirty_idx.insert(path, ts.0)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Mark file as clean (successfully backed up).
    /// Updates dirty=false, last_backed_up, backed_up=true in FileRecord.
    /// Removes from dirty_files index.
    pub fn mark_file_clean(
        &self,
        path: &str,
        ts: Timestamp,
        unit_id: UnitId,
    ) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut files = tx.open_table(FILES)?;
            let mut dirty_idx = tx.open_table(DIRTY_FILES)?;
            let record_bytes: Vec<u8> = match files.get(path)? {
                Some(v) => v.value().to_vec(),
                None => return Err(DbError::NotFound(path.to_string())),
            };
            let mut record: FileRecord = from_cbor_bytes(&record_bytes)?;
            record.dirty = false;
            record.last_backed_up = Some(ts);
            record.backed_up = true;
            record.current_unit_id = Some(unit_id);
            let bytes = to_cbor_bytes(&record);
            files.insert(path, bytes.as_slice())?;
            dirty_idx.remove(path)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Return all dirty file paths, ordered by their dirty timestamp (oldest first).
    pub fn list_dirty_files(&self) -> Result<Vec<String>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(DIRTY_FILES)?;
        let mut entries: Vec<(u64, String)> = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            entries.push((v.value(), k.value().to_string()));
        }
        entries.sort_by_key(|(ts, _)| *ts);
        Ok(entries.into_iter().map(|(_, path)| path).collect())
    }

    /// Return all file records. Used by budget planner and weekly sync.
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
}

// === Units table ===

impl Db {
    pub fn upsert_unit(&self, record: &UnitRecord) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut units = tx.open_table(UNITS)?;
            let mut stale_idx = tx.open_table(STALE_UNITS)?;
            let bytes = to_cbor_bytes(record);
            units.insert(&record.unit_id.0, bytes.as_slice())?;
            if record.status == UnitStatus::Stale {
                // Preserve existing stale_ratio if present; default to 0.0
                let ratio = {
                    let existing = stale_idx.get(&record.unit_id.0)?;
                    existing
                        .map(|v| f64::from_bits(v.value()))
                        .unwrap_or(0.0)
                };
                stale_idx.insert(&record.unit_id.0, ratio.to_bits())?;
            } else {
                stale_idx.remove(&record.unit_id.0)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_unit(&self, unit_id: &UnitId) -> Result<Option<UnitRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(UNITS)?;
        match table.get(&unit_id.0)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn delete_unit(&self, unit_id: &UnitId) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut units = tx.open_table(UNITS)?;
            let mut stale_idx = tx.open_table(STALE_UNITS)?;
            units.remove(&unit_id.0)?;
            stale_idx.remove(&unit_id.0)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Mark unit as stale. Updates UnitRecord.status=Stale AND upserts stale_units index.
    /// stale_ratio = stale_member_count / total_member_count (caller computes this).
    pub fn mark_unit_stale(&self, unit_id: &UnitId, stale_ratio: f64) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut units = tx.open_table(UNITS)?;
            let mut stale_idx = tx.open_table(STALE_UNITS)?;
            let record_bytes: Vec<u8> = match units.get(&unit_id.0)? {
                Some(v) => v.value().to_vec(),
                None => return Err(DbError::NotFound(format!("{unit_id}"))),
            };
            let mut record: UnitRecord = from_cbor_bytes(&record_bytes)?;
            record.status = UnitStatus::Stale;
            let bytes = to_cbor_bytes(&record);
            units.insert(&unit_id.0, bytes.as_slice())?;
            stale_idx.insert(&unit_id.0, stale_ratio.to_bits())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Return all stale unit IDs, ordered by stale_ratio descending (most stale first).
    /// Used by vacuum cycle to find units worth repacking.
    pub fn list_stale_units(&self) -> Result<Vec<(UnitId, f64)>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(STALE_UNITS)?;
        let mut entries: Vec<(UnitId, f64)> = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            let unit_id = UnitId(*k.value());
            let ratio = f64::from_bits(v.value());
            entries.push((unit_id, ratio));
        }
        entries.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        Ok(entries)
    }

    /// Return all units with a given status.
    pub fn list_units_by_status(&self, status: UnitStatus) -> Result<Vec<UnitRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(UNITS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: UnitRecord = from_cbor_bytes(v.value())?;
            if record.status == status {
                records.push(record);
            }
        }
        Ok(records)
    }
}

// === Shards table (owner view) ===

impl Db {
    pub fn upsert_shard(&self, record: &ShardRecord) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut shards = tx.open_table(SHARDS)?;
            let mut unverified_idx = tx.open_table(UNVERIFIED_SHARDS)?;
            let bytes = to_cbor_bytes(record);
            shards.insert(&record.shard_id.0, bytes.as_slice())?;
            if record.status == ShardStatus::Stored {
                let ts = record.last_verified.map(|t| t.0).unwrap_or(0);
                unverified_idx.insert(&record.shard_id.0, ts)?;
            } else {
                unverified_idx.remove(&record.shard_id.0)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_shard(&self, shard_id: &ShardId) -> Result<Option<ShardRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SHARDS)?;
        match table.get(&shard_id.0)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn delete_shard(&self, shard_id: &ShardId) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut shards = tx.open_table(SHARDS)?;
            let mut unverified_idx = tx.open_table(UNVERIFIED_SHARDS)?;
            shards.remove(&shard_id.0)?;
            unverified_idx.remove(&shard_id.0)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Return all ShardRecords in the shards table (owner view, all statuses).
    pub fn list_all_shards(&self) -> Result<Vec<ShardRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SHARDS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: ShardRecord = from_cbor_bytes(v.value())?;
            records.push(record);
        }
        Ok(records)
    }

    /// Return all ShardRecords for a given unit.
    pub fn list_shards_for_unit(&self, unit_id: &UnitId) -> Result<Vec<ShardRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SHARDS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: ShardRecord = from_cbor_bytes(v.value())?;
            if record.unit_id == *unit_id {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Return all ShardRecords for a given holder.
    pub fn list_shards_for_holder(
        &self,
        holder_id: &IdentityPub,
    ) -> Result<Vec<ShardRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SHARDS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: ShardRecord = from_cbor_bytes(v.value())?;
            if record.holder_id == *holder_id {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Return shards due for PoS challenge (last_verified is None or older than given threshold).
    /// Returns up to `limit` shard IDs.
    pub fn list_shards_needing_pos(
        &self,
        older_than: Timestamp,
        limit: usize,
    ) -> Result<Vec<ShardId>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(UNVERIFIED_SHARDS)?;
        let mut result = Vec::new();
        for item in table.iter()? {
            if result.len() >= limit {
                break;
            }
            let (k, v) = item?;
            let last_ts = v.value();
            if last_ts < older_than.0 {
                result.push(ShardId(*k.value()));
            }
        }
        Ok(result)
    }

    /// Update last_verified timestamp and remove from unverified_shards index.
    pub fn record_pos_verified(
        &self,
        shard_id: &ShardId,
        ts: Timestamp,
    ) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut shards = tx.open_table(SHARDS)?;
            let mut unverified_idx = tx.open_table(UNVERIFIED_SHARDS)?;
            let record_bytes: Vec<u8> = match shards.get(&shard_id.0)? {
                Some(v) => v.value().to_vec(),
                None => return Err(DbError::NotFound(format!("{shard_id}"))),
            };
            let mut record: ShardRecord = from_cbor_bytes(&record_bytes)?;
            record.last_verified = Some(ts);
            let bytes = to_cbor_bytes(&record);
            shards.insert(&shard_id.0, bytes.as_slice())?;
            unverified_idx.remove(&shard_id.0)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Update shard status.
    pub fn update_shard_status(
        &self,
        shard_id: &ShardId,
        status: ShardStatus,
    ) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut shards = tx.open_table(SHARDS)?;
            let mut unverified_idx = tx.open_table(UNVERIFIED_SHARDS)?;
            let record_bytes: Vec<u8> = match shards.get(&shard_id.0)? {
                Some(v) => v.value().to_vec(),
                None => return Err(DbError::NotFound(format!("{shard_id}"))),
            };
            let mut record: ShardRecord = from_cbor_bytes(&record_bytes)?;
            record.status = status;
            let last_verified = record.last_verified;
            let bytes = to_cbor_bytes(&record);
            shards.insert(&shard_id.0, bytes.as_slice())?;
            if status == ShardStatus::Stored {
                let ts = last_verified.map(|t| t.0).unwrap_or(0);
                unverified_idx.insert(&shard_id.0, ts)?;
            } else {
                unverified_idx.remove(&shard_id.0)?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

// === Peers table ===

impl Db {
    pub fn upsert_peer(&self, record: &PeerRecord) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut peers = tx.open_table(PEERS)?;
            let bytes = to_cbor_bytes(record);
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

    /// Return all peer records.
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

    /// Return peers sorted by composite trust score descending.
    /// Composite = (0.4 * trust_p + 1.75 * trust_i) * clamp(trust_s, 0.1, 1.0)
    /// This is a convenience sort; actual placement weighting is in placement.rs.
    pub fn list_peers_by_trust(&self) -> Result<Vec<PeerRecord>, DbError> {
        let mut peers = self.list_all_peers()?;
        peers.sort_by(|a, b| {
            let score_a = (0.4 * a.trust_p + 1.75 * a.trust_i)
                * a.trust_s.clamp(0.1, 1.0);
            let score_b = (0.4 * b.trust_p + 1.75 * b.trust_i)
                * b.trust_s.clamp(0.1, 1.0);
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(peers)
    }

    /// Update trust components for a peer. Peer must already exist.
    pub fn update_peer_trust(
        &self,
        identity: &IdentityPub,
        trust_p: f64,
        trust_i: f64,
        trust_s: f64,
    ) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut peers = tx.open_table(PEERS)?;
            let record_bytes: Vec<u8> = match peers.get(&identity.0)? {
                Some(v) => v.value().to_vec(),
                None => return Err(DbError::NotFound(format!("{identity}"))),
            };
            let mut record: PeerRecord = from_cbor_bytes(&record_bytes)?;
            record.trust_p = trust_p;
            record.trust_i = trust_i;
            record.trust_s = trust_s;
            let bytes = to_cbor_bytes(&record);
            peers.insert(&identity.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Update last_seen timestamp. Creates the record if it does not exist.
    pub fn touch_peer(&self, identity: &IdentityPub, ts: Timestamp) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut peers = tx.open_table(PEERS)?;
            let record = match peers.get(&identity.0)? {
                Some(v) => {
                    let bytes = v.value().to_vec();
                    drop(v);
                    let mut r: PeerRecord = from_cbor_bytes(&bytes)?;
                    r.last_seen = ts;
                    r
                }
                None => PeerRecord {
                    identity: *identity,
                    node_id: None,
                    trust_p: 0.0,
                    trust_i: 0.0,
                    trust_s: 0.0,
                    bytes_sent_to_peer: 0,
                    bytes_received_from_peer: 0,
                    first_seen: ts,
                    last_seen: ts,
                    weeks_in_network: 0,
                    subnet_prefix: None,
                    allowlisted: false,
                },
            };
            let bytes = to_cbor_bytes(&record);
            peers.insert(&identity.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Increment weeks_in_network by 1 for a peer. Used by weekly trust update.
    pub fn increment_peer_weeks(&self, identity: &IdentityPub) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut peers = tx.open_table(PEERS)?;
            let record_bytes: Vec<u8> = match peers.get(&identity.0)? {
                Some(v) => v.value().to_vec(),
                None => return Err(DbError::NotFound(format!("{identity}"))),
            };
            let mut record: PeerRecord = from_cbor_bytes(&record_bytes)?;
            record.weeks_in_network += 1;
            let bytes = to_cbor_bytes(&record);
            peers.insert(&identity.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }
}

// === Holding table (holder view) ===

impl Db {
    pub fn upsert_holding(&self, record: &HoldingRecord) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut holding = tx.open_table(HOLDING)?;
            let bytes = to_cbor_bytes(record);
            holding.insert(&record.shard_id.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_holding(&self, shard_id: &ShardId) -> Result<Option<HoldingRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDING)?;
        match table.get(&shard_id.0)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn delete_holding(&self, shard_id: &ShardId) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut holding = tx.open_table(HOLDING)?;
            holding.remove(&shard_id.0)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Return all holding records for a given owner.
    pub fn list_holding_for_owner(
        &self,
        owner_pub: &IdentityPub,
    ) -> Result<Vec<HoldingRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDING)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            if record.owner_pub == *owner_pub {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// Return all active holding records, ordered by (importance ASC, received_at ASC).
    /// This is the eviction candidate order: lowest importance + oldest first.
    /// Used by disk pressure eviction.
    pub fn list_holding_for_eviction(&self) -> Result<Vec<HoldingRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDING)?;
        let mut records: Vec<HoldingRecord> = Vec::new();
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

    /// Return total bytes currently held.
    /// Only counts Active, MarkedForDelete, and Silent states.
    pub fn total_holding_bytes(&self) -> Result<u64, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDING)?;
        let mut total = 0u64;
        for item in table.iter()? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            match record.state {
                ShardState::Active | ShardState::MarkedForDelete | ShardState::Silent => {
                    total += record.size_bytes;
                }
            }
        }
        Ok(total)
    }

    /// Set shard state to MarkedForDelete, record delete_requested_at.
    pub fn mark_holding_for_delete(
        &self,
        shard_id: &ShardId,
        ts: Timestamp,
    ) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut holding = tx.open_table(HOLDING)?;
            let record_bytes: Vec<u8> = match holding.get(&shard_id.0)? {
                Some(v) => v.value().to_vec(),
                None => return Err(DbError::NotFound(format!("{shard_id}"))),
            };
            let mut record: HoldingRecord = from_cbor_bytes(&record_bytes)?;
            record.state = ShardState::MarkedForDelete;
            record.delete_requested_at = Some(ts);
            let bytes = to_cbor_bytes(&record);
            holding.insert(&shard_id.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Set drop_notice_sent_at on a holding record.
    pub fn set_drop_notice_sent_at(
        &self,
        shard_id: &ShardId,
        deadline: Timestamp,
    ) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut holding = tx.open_table(HOLDING)?;
            let record_bytes: Vec<u8> = match holding.get(&shard_id.0)? {
                Some(v) => v.value().to_vec(),
                None => return Err(DbError::NotFound(format!("{shard_id}"))),
            };
            let mut record: HoldingRecord = from_cbor_bytes(&record_bytes)?;
            record.drop_notice_sent_at = Some(deadline);
            let bytes = to_cbor_bytes(&record);
            holding.insert(&shard_id.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Return holding records whose delete_requested_at + 4 weeks <= now.
    /// These are ready for actual deletion.
    pub fn list_holding_cooldown_expired(
        &self,
        now: Timestamp,
    ) -> Result<Vec<HoldingRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDING)?;
        let four_weeks_secs = 4 * 604800u64;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            if record.state == ShardState::MarkedForDelete {
                if let Some(requested_at) = record.delete_requested_at {
                    if requested_at.0 + four_weeks_secs <= now.0 {
                        records.push(record);
                    }
                }
            }
        }
        Ok(records)
    }

    /// Return holding records whose drop_notice_sent_at <= now.
    /// Phase 2 eviction: time to actually drop.
    pub fn list_holding_drop_notice_expired(
        &self,
        now: Timestamp,
    ) -> Result<Vec<HoldingRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDING)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            if let Some(deadline) = record.drop_notice_sent_at {
                if deadline.0 <= now.0 {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    /// Return all holding records in arbitrary order.
    pub fn list_all_holding(&self) -> Result<Vec<HoldingRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDING)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            records.push(record);
        }
        Ok(records)
    }
}

// === Escrow restore log table ===

impl Db {
    /// Return the restore log for an owner, or None if no restores have been served.
    pub fn get_restore_log(
        &self,
        owner_pub: &IdentityPub,
    ) -> Result<Option<EscrowRestoreLog>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(ESCROW_RESTORE_LOG)?;
        match table.get(&owner_pub.0)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Insert or replace the restore log for an owner.
    pub fn upsert_restore_log(&self, log: &EscrowRestoreLog) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(ESCROW_RESTORE_LOG)?;
            let bytes = to_cbor_bytes(log);
            table.insert(&log.owner_pub.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }
}

// === Budget table ===

impl Db {
    /// Get the budget record. Returns None on first run (before any estimation).
    pub fn get_budget(&self) -> Result<Option<BudgetRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(BUDGET)?;
        match table.get("budget")? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Replace the budget record.
    pub fn set_budget(&self, record: &BudgetRecord) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut budget = tx.open_table(BUDGET)?;
            let bytes = to_cbor_bytes(record);
            budget.insert("budget", bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }
}

// === Schedule table ===

impl Db {
    pub fn get_schedule(&self, task_name: &str) -> Result<Option<ScheduleRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SCHEDULE)?;
        match table.get(task_name)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn set_schedule(&self, record: &ScheduleRecord) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut schedule = tx.open_table(SCHEDULE)?;
            let bytes = to_cbor_bytes(record);
            schedule.insert(record.task_name.as_str(), bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_all_schedules(&self) -> Result<Vec<ScheduleRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SCHEDULE)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: ScheduleRecord = from_cbor_bytes(v.value())?;
            records.push(record);
        }
        Ok(records)
    }
}

// === Config table ===

impl Db {
    /// Store an arbitrary CBOR-serializable config value.
    pub fn set_config<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut config = tx.open_table(CONFIG)?;
            let bytes = to_cbor_bytes(value);
            config.insert(key, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Retrieve a config value by key.
    pub fn get_config<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(CONFIG)?;
        match table.get(key)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }
}


#[cfg(test)]
mod tests;
