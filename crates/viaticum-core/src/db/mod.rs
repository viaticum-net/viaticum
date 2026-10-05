// Database layer for viaticum-core β.
// Two-tier architecture: WARM (redb) + HOT (RAM aggregates).
// See docs/beta/tasks/db.md for full spec.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::cluster::StoredClusterState;
use crate::constants::{
    BYTES_PER_GB, DROP_NOTICE_WINDOW_SECS, HOLDER_DELETE_COOLDOWN_SECS,
    PAIR_LEDGER_CONFIRMATION_WINDOW_SECS, SECS_PER_DAY,
};
use crate::mailbox::{MailboxAddress, MailboxClass};
use crate::trust::{DeviceTrustRecord, MasterTrustRecord};
use crate::types::{
    BlockAgg, BudgetRecord, DeviceId, DropKind, EventEntry, FileId, FileRecord, HoldingRecord,
    HoldingStatus, IdentityPub, PairLedger, PeerRecord, PendingDrops, PlacementAgg,
    PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus, SymbolPlacement,
    Timestamp, from_cbor_bytes, to_cbor_bytes,
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

/// Held symbols (holder view). Key = (owner IdentityPub[32] || SourceBlockId[32]) = [u8;64]
/// — owner FIRST, so one owner's holdings form a contiguous range (S-4; see `holding_key`).
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

/// Owner-side ledger of SystemState-as-block ids (the SS-as-block workstream).
/// Key = block_id [u8;32]. Value = CBOR(u32) generation that produced the block.
/// SS blocks live in SOURCE_BLOCKS (so the generic pipeline places/PoS them), but
/// must be EXCLUDED from `snapshot_db` (else a snapshot self-references its own SS
/// blocks → post-DR the recovered node maintains phantom records). This ledger is
/// the SS-identity marker for that exclusion and drives retire/rotation.
const SS_BLOCKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("ss_blocks");

/// Total bytes restored per peer (cumulative, append-only counter).
/// Key = owner IdentityPub [u8;32]. Value = CBOR(u64) — total bytes served.
/// Accounting only (v1): nothing gates restore on it; input for a future escrow-as-debt.
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

/// Meta flag: HOLDINGS keys are owner-first (block‖owner → owner‖block migration done, S-4).
const META_KEY_HOLDINGS_OWNER_KEYED: &str = "holdings_owner_keyed_v1";

/// Meta key: this DB's catalog history id (CBOR `CatalogLineageId`). Minted once per DB,
/// never part of the SystemState snapshot (spec B2).
const META_KEY_CATALOG_LINEAGE: &str = "catalog_lineage_v1";

/// Meta key: the two pointer places of this history (CBOR `PointerPublications`,
/// CROWN-1 V.16.3). Not part of the SystemState snapshot.
const META_KEY_POINTER_PUBLICATIONS: &str = "pointer_publication_v2";

// --- Indices ---

/// file → holders index. Key = (FileId u64 BE[8] || holder DeviceId[32]) = [u8;40].
/// Value = symbol_count (u32). Entry present ↔ holder has symbols for this file.
const FILE_HOLDERS: TableDefinition<&[u8; 40], u32> = TableDefinition::new("file_holders");

/// holder → files index. Key = (holder DeviceId[32] || FileId u64 BE[8]) = [u8;40].
/// Value = symbol_count (u32).
const HOLDER_FILES: TableDefinition<&[u8; 40], u32> = TableDefinition::new("holder_files");

/// content_hash → path index (B-1). Key = content_hash[32] ++ path bytes (variable).
/// Value = empty. A range-scan over the 32-byte content_hash prefix yields every
/// path whose current versions include that hash, turning import dedup from an
/// O(N) full FILES scan per event into a prefix lookup.
const CONTENT_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("content_index");

/// Mailbox entries stored on behalf of other nodes (impl in `db/mailbox`).
/// Key: target address[32] || msg_id[16] || class_u8[1] = 49 bytes.
/// Sorted by target prefix → efficient range-scan for MailboxFetch.
const MAILBOX_ENTRIES: TableDefinition<&[u8; 49], &[u8]> = TableDefinition::new("mailbox_entries");

/// Per-target mailbox byte counter (all classes). Key: target address[32].
/// Value: CBOR(u64). Updated on every insert/delete so quota checks are O(1).
const MAILBOX_BYTES_BY_TARGET: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("mailbox_bytes_by_target");

/// Per-target byte counter of SelfPointer entries only (CROWN-1 pointer budget).
/// Key: target address[32]. Value: CBOR(u64). Maintained with MAILBOX_BYTES_BY_TARGET.
const MAILBOX_SP_BYTES_BY_TARGET: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("mailbox_sp_bytes_by_target");

/// 4R pair-ledger accumulators. Key: master IdentityPub[32]. Value: CBOR([`PairLedger`]).
///
/// Keyed by MASTER, not device: the economic pair is a person (see [`PairLedger`] and
/// `refresh_peer_storage_bytes`, which already sums `bytes_we_store_for_peer` per-master).
///
/// A SEPARATE table rather than fields on [`PeerRecord`] for exactly ONE reason: the
/// holder-side input exists only per-master (HOLDINGS are keyed by owner-master), while
/// `PeerRecord` is keyed by `DeviceId` — so one person's history would exist in N copies,
/// each carrying the master-wide total. Two other reasons were written here at various
/// points and BOTH were refuted against the code ("a sibling's diff would overwrite my
/// integrals"; "ledger churn would balloon the diff stream" — peer rows are already
/// rewritten hourly without any ledger). See [`PairLedger`] for both disproofs; do not
/// re-add them.
///
/// This does NOT make "no decision reads the ledger" structural — `Db` is reachable from
/// every module and `get_pair_ledger` is an ordinary `pub` method. The actual guarantee
/// today is only WHICH call sites read it: the recorder that writes it
/// ([`crate::pair_ledger`], which reads the previous row to continue the integral), the
/// SystemState snapshot/restore pair that carries it through disaster recovery, and the 4R
/// shadow (В-0, [`crate::four_r_holder`]) whose outputs are only log lines and its own latch
/// row. No placement, eviction, offer-admission or PoS-cadence path decides on it.
///
/// `create_tables` opens it on every `Db::open`, so a database written before this table
/// existed simply gains it empty (no migration step).
const PAIR_LEDGER: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("pair_ledger");

/// Outbox of drop events awaiting the next pair-ledger accrual (У-4, Д-K). Key: master
/// identity (the ledger's key). Value: CBOR([`PendingDrops`]), decoded LENIENTLY (a
/// damaged row reads as zeros — see [`PendingDrops`]).
///
/// Written by the placement-loss sites in the SAME write transaction as the placement change
/// ([`DbWriteTxn::record_drop_event`]); taken by the accrual tick in the SAME write
/// transaction as the ledger rows ([`DbWriteTxn::take_pending_drops`]). redb serializes
/// write transactions, so an event lands in exactly one fold: never lost, never doubled.
/// Deliberately NOT part of the SystemState snapshot: pending events are lost on DR
/// (4r-i31), and the `system_state` module is not touched for it.
///
/// Orphans: a row is folded only when its master is a row of the accrual sweep (PEERS). The
/// placeholder master is never written (`record_drop_event` is a no-op for it), but a master
/// that later leaves PEERS keeps its row here un-folded (today unreachable: peers are never
/// deleted — `delete_peer` has no production caller, N-5). Harmless: nothing reads it.
const PAIR_LEDGER_PENDING_DROPS: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("pair_ledger_pending_drops");

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

/// SYMBOL_PLACEMENTS key range of one block: keys are [block_id(32) || holder(32)], so
/// [block_id||00..] to [block_id||FF..].
fn placement_range(block_id: &SourceBlockId) -> ([u8; 64], [u8; 64]) {
    let mut lo = [0u8; 64];
    let mut hi = [0u8; 64];
    lo[..32].copy_from_slice(&block_id.0);
    hi[..32].copy_from_slice(&block_id.0);
    hi[32..].fill(0xFF);
    (lo, hi)
}

/// CONTENT_INDEX key: content_hash (32 bytes) ++ path bytes. The fixed-width hash
/// prefix lets a range scan select all paths for a given content hash.
fn content_index_key(content_hash: &[u8; 32], path: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(32 + path.len());
    key.extend_from_slice(content_hash);
    key.extend_from_slice(path.as_bytes());
    key
}

/// HOLDINGS key: owner IdentityPub (32) ++ block_id (32). Owner-first so all of
/// one owner's holdings form a contiguous range (S-4: `list_holdings_for_owner`
/// is a range scan, not a full-table filter).
fn holding_key(block_id: &SourceBlockId, owner: &IdentityPub) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&owner.0);
    key[32..64].copy_from_slice(&block_id.0);
    key
}

fn pos_key(device: &DeviceId, week_number: u32) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..32].copy_from_slice(&device.0);
    key[32..36].copy_from_slice(&week_number.to_be_bytes());
    key
}

/// MAILBOX_ENTRIES key: target address[32] || msg_id[16] || class_u8[1] = 49 bytes.
/// Sorted by target prefix so a range scan fetches all entries for one target.
fn mailbox_entry_key(target: &MailboxAddress, msg_id: [u8; 16], class: MailboxClass) -> [u8; 49] {
    let mut key = [0u8; 49];
    key[..32].copy_from_slice(&target.0);
    key[32..48].copy_from_slice(&msg_id);
    key[48] = class.as_u8();
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

/// Hot layer: in-memory aggregates loaded at startup.
/// Per-block worker cooldown (B-4). RAM-only: never persisted, so it resets on
/// daemon restart — a restart is a fine moment to re-attempt every block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockCooldown {
    pub last_attempted_at: Option<Timestamp>,
    pub last_pool_signature: u64,
    /// Last attempt found nobody to take symbols (no candidate / empty allocation /
    /// pool too small / no swarm / unreadable source). A parked block is skipped until
    /// the pool signature changes, a placement of this block changes status, cooldowns
    /// are reset, or `parked_cooldown` elapses (repair-i4).
    pub parked: bool,
}

/// Clear the worker park flag of `block_id` if the placement's status changed
/// (None → Some, Some(a) → Some(b≠a), Some → None). Called with the hot write lock
/// held, from every path that updates `hot.placements`, so no status writer
/// (scheduler, processor, deletion, DR) needs to know about parking (repair-i4).
/// The normal cooldown (`last_attempted_at`) is kept: only the long park is lifted.
fn unpark_on_status_change(
    hot: &mut HotCache,
    block_id: &SourceBlockId,
    old: Option<PlacementStatus>,
    new: Option<PlacementStatus>,
) {
    if old == new {
        return;
    }
    if let Some(cd) = hot.block_cooldown.get_mut(block_id) {
        cd.parked = false;
    }
}

pub struct HotCache {
    pub blocks: HashMap<SourceBlockId, BlockAgg>,
    pub placements: HashMap<(SourceBlockId, DeviceId), PlacementAgg>,
    /// Running sum of `total_bytes` over ALL holdings (every status counts).
    /// Maintained on holding upsert/delete so `total_holding_bytes` is O(1)
    /// instead of a full HOLDINGS scan on every incoming SymbolOffer (S-9).
    pub holding_bytes_total: u64,
    /// Worker cooldown per source block (B-4). RAM-only; not rebuilt at open().
    pub block_cooldown: HashMap<SourceBlockId, BlockCooldown>,
}

impl HotCache {
    pub fn empty() -> Self {
        HotCache {
            blocks: HashMap::new(),
            placements: HashMap::new(),
            holding_bytes_total: 0,
            block_cooldown: HashMap::new(),
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

        // Running aggregate of holding bytes (all statuses count) — S-9.
        let holdings = tx.open_table(HOLDINGS)?;
        for item in holdings.iter()? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            cache.holding_bytes_total =
                cache.holding_bytes_total.saturating_add(record.total_bytes);
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

    #[error("duplicate entry")]
    Duplicate,
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
            tx.open_table(CONTENT_INDEX)?;
            tx.open_table(CLUSTER_STATE)?;
            tx.open_table(SS_BLOCKS)?;
            tx.open_table(RESTORE_SERVED)?;
            tx.open_table(DEVICE_TRUST)?;
            tx.open_table(MASTER_TRUST)?;
            tx.open_table(DEVICE_TO_MASTER)?;
            tx.open_table(META)?;
            tx.open_table(MAILBOX_ENTRIES)?;
            tx.open_table(MAILBOX_BYTES_BY_TARGET)?;
            tx.open_table(MAILBOX_SP_BYTES_BY_TARGET)?;
            tx.open_table(PAIR_LEDGER)?;
            tx.open_table(PAIR_LEDGER_PENDING_DROPS)?;
            // backup-i4: too-large source marks (node-local; outside snapshot_db).
            tx.open_table(too_large::TOO_LARGE_SOURCES)?;
            // DN-1: applied signed letters + their expiry index (outside snapshot_db, 4r-i51).
            tx.open_table(seen_signed_letters::SEEN_SIGNED_LETTERS)?;
            tx.open_table(seen_signed_letters::SEEN_SIGNED_LETTERS_BY_EXPIRY)?;
            // В-0: 4R holder latch (shadow only; outside snapshot_db, node-local).
            tx.open_table(four_r_state::FOUR_R_STATE)?;
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

    /// This DB's catalog history id, if one was minted.
    pub fn catalog_lineage(
        &self,
    ) -> Result<Option<crate::system_state::CatalogLineageId>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(META)?;
        match table.get(META_KEY_CATALOG_LINEAGE)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Read this DB's catalog history id, minting a random one if there is none yet.
    /// One write transaction, so two callers racing on a fresh DB get the same id.
    pub fn get_or_create_catalog_lineage(
        &self,
    ) -> Result<crate::system_state::CatalogLineageId, DbError> {
        let tx = self.inner.begin_write()?;
        let id = {
            let mut table = tx.open_table(META)?;
            let existing = match table.get(META_KEY_CATALOG_LINEAGE)? {
                Some(v) => Some(from_cbor_bytes(v.value())?),
                None => None,
            };
            match existing {
                Some(id) => id,
                None => {
                    let id = crate::system_state::CatalogLineageId::random();
                    table.insert(META_KEY_CATALOG_LINEAGE, to_cbor_bytes(&id).as_slice())?;
                    id
                }
            }
        };
        tx.commit()?;
        Ok(id)
    }

    /// The pointer places of this history (CROWN-1 V.16.3), if any was ever written.
    pub fn pointer_publications(
        &self,
    ) -> Result<Option<crate::system_state::catalog::PointerPublications>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(META)?;
        match table.get(META_KEY_POINTER_PUBLICATIONS)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Replace the pointer places record (one write transaction, whole record).
    pub fn put_pointer_publications(
        &self,
        p: &crate::system_state::catalog::PointerPublications,
    ) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(META)?;
            table.insert(META_KEY_POINTER_PUBLICATIONS, to_cbor_bytes(p).as_slice())?;
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
        // A2 (T-13b-3): the relay-board SystemState blob transport is retired.
        // Drop the legacy `system_state_blobs` table if a pre-A2 database still
        // carries it, so the stale blobs are reclaimed. No-op on fresh DBs.
        Self::drop_legacy_system_state_blobs(&db)?;
        let hot = HotCache::build_from_db(&db)?;
        let db = Db {
            inner: Arc::new(db),
            hot: Arc::new(RwLock::new(hot)),
        };
        db.backfill_content_index()?;
        db.migrate_holdings_key_order()?;
        Ok(db)
    }

    /// Create a fresh database in an already opened, empty `file` (DR staging).
    ///
    /// The caller created the file (and, on platforms where a second exclusive lock
    /// on the same descriptor succeeds, already holds `File::try_lock` on it); redb
    /// takes its own lock on the same descriptor for the lifetime of the database.
    /// Unlike [`Db::open`]: no pre-open `.bak` copy and no repair retry, because the
    /// file is new. A lock held through another descriptor →
    /// `DbError::Database(DatabaseAlreadyOpen)`.
    pub fn create_from_file(file: std::fs::File) -> Result<Self, DbError> {
        let db = redb::Database::builder().create_file(file)?;
        Self::create_tables(&db)?;
        Self::drop_legacy_system_state_blobs(&db)?;
        let hot = HotCache::build_from_db(&db)?;
        let db = Db {
            inner: Arc::new(db),
            hot: Arc::new(RwLock::new(hot)),
        };
        // Same one-time markers `open` leaves on a fresh DB, so the daemon's first
        // `open` of the installed file finds nothing to migrate.
        db.backfill_content_index()?;
        db.migrate_holdings_key_order()?;
        Ok(db)
    }

    /// One-time cleanup (A2 / T-13b-3): drop the retired `system_state_blobs`
    /// table. `delete_table` returns `Ok(false)` when the table is absent, so this
    /// is a safe no-op on fresh or already-migrated databases.
    fn drop_legacy_system_state_blobs(db: &redb::Database) -> Result<(), DbError> {
        const LEGACY_SYSTEM_STATE_BLOBS: TableDefinition<&[u8; 32], &[u8]> =
            TableDefinition::new("system_state_blobs");
        let tx = db.begin_write()?;
        let dropped = tx.delete_table(LEGACY_SYSTEM_STATE_BLOBS)?;
        tx.commit()?;
        if dropped {
            tracing::info!("db: dropped retired system_state_blobs table (A2 cut-over)");
        }
        Ok(())
    }

    /// One-time migration (S-4): re-key HOLDINGS from the old block‖owner layout to
    /// owner‖block. The new key is reconstructed from each record's own fields, so a
    /// record keyed in the old order is moved to its owner-first key. Gated by a META
    /// flag so it runs at most once; a no-op on fresh and already-migrated databases.
    fn migrate_holdings_key_order(&self) -> Result<(), DbError> {
        use redb::ReadableTable;
        {
            let rtx = self.inner.begin_read()?;
            let meta = rtx.open_table(META)?;
            if meta.get(META_KEY_HOLDINGS_OWNER_KEYED)?.is_some() {
                return Ok(());
            }
        }

        // Collect (old_key, new_key, value) for every holding.
        let mut moves: Vec<([u8; 64], [u8; 64], Vec<u8>)> = Vec::new();
        {
            let rtx = self.inner.begin_read()?;
            let table = rtx.open_table(HOLDINGS)?;
            for item in table.iter()? {
                let (k, v) = item?;
                let old_key = *k.value();
                let value = v.value().to_vec();
                let record: HoldingRecord = from_cbor_bytes(&value)?;
                let new_key = holding_key(&record.source_block_id, &record.owner_id);
                if old_key != new_key {
                    moves.push((old_key, new_key, value));
                }
            }
        }

        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(HOLDINGS)?;
            for (old_key, new_key, value) in &moves {
                table.remove(old_key)?;
                table.insert(new_key, value.as_slice())?;
            }
            let mut meta = tx.open_table(META)?;
            meta.insert(
                META_KEY_HOLDINGS_OWNER_KEYED,
                to_cbor_bytes(&true).as_slice(),
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Rebuild the content_hash index (B-1) from FILES if it is empty but files
    /// exist — i.e. a database created before the index was introduced. A no-op
    /// once the index is populated (ongoing maintenance keeps it consistent).
    fn backfill_content_index(&self) -> Result<(), DbError> {
        use redb::ReadableTable;
        let keys: Vec<Vec<u8>> = {
            let rtx = self.inner.begin_read()?;
            let idx = rtx.open_table(CONTENT_INDEX)?;
            if idx.len()? > 0 {
                return Ok(());
            }
            let files = rtx.open_table(FILES)?;
            let mut keys = Vec::new();
            for item in files.iter()? {
                let (_, v) = item?;
                let rec: FileRecord = from_cbor_bytes(v.value())?;
                for ver in &rec.versions {
                    keys.push(content_index_key(&ver.content_hash, &rec.path));
                }
            }
            keys
        };
        if keys.is_empty() {
            return Ok(());
        }
        let tx = self.inner.begin_write()?;
        {
            let mut idx = tx.open_table(CONTENT_INDEX)?;
            for k in &keys {
                idx.insert(k.as_slice(), [].as_slice())?;
            }
        }
        tx.commit()?;
        Ok(())
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

    /// Test seam (DN1-16): overwrite the stored row of placement (block, holder) with bytes that
    /// do not decode as a `SymbolPlacement`, so [`Db::get_placement`] answers `Err` — a damaged
    /// row, not a missing one. Bypasses the hot cache on purpose.
    #[cfg(any(test, feature = "testutil"))]
    pub fn corrupt_placement_row_for_test(
        &self,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Result<(), DbError> {
        let key = placement_key(block_id, holder_id);
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(SYMBOL_PLACEMENTS)?;
            table.insert(&key, [0xffu8, 0x00, 0x13].as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Test seam (В-0, D-1b): overwrite the pair-ledger row of `master` with bytes that do not
    /// decode as a `PairLedger`, so [`Db::list_pair_ledgers`] answers `Err`.
    #[cfg(any(test, feature = "testutil"))]
    pub fn corrupt_pair_ledger_row_for_test(&self, master: &IdentityPub) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(PAIR_LEDGER)?;
            table.insert(&master.0, [0xffu8, 0x00, 0x13].as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Test seam (backup-i23): overwrite the PEERS row of `device` with bytes that do not
    /// decode as a `PeerRecord`, so [`Db::list_all_peers`] answers `Err` — a DB error
    /// before any block is built (candidate selection).
    #[cfg(any(test, feature = "testutil"))]
    pub fn corrupt_peer_row_for_test(&self, device: &DeviceId) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(PEERS)?;
            table.insert(&device.0, [0xffu8, 0x00, 0x13].as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Test seam (backup-i23): overwrite the FILES row at `path` with bytes that do not
    /// decode as a `FileRecord`, so [`Db::get_file`] answers `Err` — a DB error inside the
    /// packing pipeline, not a missing record. CONTENT_INDEX is left as it was.
    #[cfg(any(test, feature = "testutil"))]
    pub fn corrupt_file_row_for_test(&self, path: &str) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(FILES)?;
            table.insert(path, [0xffu8, 0x00, 0x13].as_slice())?;
        }
        tx.commit()?;
        Ok(())
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
    /// Insert or replace FileRecord. Maintains the content_hash index (B-1).
    pub fn upsert_file(&self, record: &FileRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let tx = self.inner.begin_write()?;
        {
            let mut files = tx.open_table(FILES)?;
            let old: Option<FileRecord> = match files.get(record.path.as_str())? {
                Some(v) => Some(from_cbor_bytes(v.value())?),
                None => None,
            };
            files.insert(record.path.as_str(), bytes.as_slice())?;

            // CONTENT_INDEX: drop the old record's version-hash keys, add the new ones.
            let mut idx = tx.open_table(CONTENT_INDEX)?;
            if let Some(old) = &old {
                for v in &old.versions {
                    idx.remove(content_index_key(&v.content_hash, &old.path).as_slice())?;
                }
            }
            for v in &record.versions {
                idx.insert(
                    content_index_key(&v.content_hash, &record.path).as_slice(),
                    [].as_slice(),
                )?;
            }
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

    /// Delete by path. No-op if not found. Maintains the content_hash index (B-1).
    pub fn delete_file(&self, path: &str) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut files = tx.open_table(FILES)?;
            let old: Option<FileRecord> = match files.get(path)? {
                Some(v) => Some(from_cbor_bytes(v.value())?),
                None => None,
            };
            files.remove(path)?;

            if let Some(old) = &old {
                let mut idx = tx.open_table(CONTENT_INDEX)?;
                for v in &old.versions {
                    idx.remove(content_index_key(&v.content_hash, &old.path).as_slice())?;
                }
            }
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

    /// Paths whose current versions include `content_hash`, via the CONTENT_INDEX
    /// prefix scan (B-1). Order follows key order; callers treat it as a candidate set.
    fn paths_for_content_hash(&self, content_hash: &[u8; 32]) -> Result<Vec<String>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(CONTENT_INDEX)?;
        let mut paths = Vec::new();
        let lower: &[u8] = content_hash;
        for item in table.range::<&[u8]>(lower..)? {
            let (k, _) = item?;
            let key = k.value();
            if !key.starts_with(content_hash) {
                break;
            }
            let path = std::str::from_utf8(&key[32..])
                .map_err(|e| DbError::NotFound(format!("content_index path utf8: {e}")))?
                .to_string();
            paths.push(path);
        }
        Ok(paths)
    }

    /// Every file record holding a version with `content_hash` (B-1 indexed, via
    /// CONTENT_INDEX), in path order. The caller decides which of them may serve as a
    /// dedup source (backup-i9: only a backed-up version) or as a rebuild candidate.
    pub fn files_with_content_hash(
        &self,
        content_hash: &[u8; 32],
    ) -> Result<Vec<FileRecord>, DbError> {
        let mut records = Vec::new();
        for path in self.paths_for_content_hash(content_hash)? {
            if let Some(rec) = self.get_file(&path)?
                && rec.versions.iter().any(|v| &v.content_hash == content_hash)
            {
                records.push(rec);
            }
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
    pub fn update_block_cached_fields(
        &self,
        block_id: &SourceBlockId,
        importance: f64,
        current_alive: u32,
        current_reliability: f64,
        target_reliability: f64,
    ) -> Result<(), DbError> {
        let mut record = self
            .get_source_block(block_id)?
            .ok_or_else(|| DbError::NotFound(format!("SourceBlockRecord {block_id}")))?;
        record.importance = importance;
        record.current_alive = current_alive;
        record.current_reliability = current_reliability;
        record.target_reliability = target_reliability;
        self.upsert_source_block(&record)
    }

    /// Record a worker attempt on `block_id` (B-4). Cooldown lives only in RAM,
    /// so this performs no disk write — it replaces the per-attempt fsync that
    /// persisting `last_attempted_at`/`last_pool_signature` used to incur.
    ///
    /// `parked = true` records that the attempt found nobody to take symbols; see
    /// [`BlockCooldown::parked`] and [`Db::next_work_item`].
    pub fn set_block_cooldown(
        &self,
        block_id: &SourceBlockId,
        last_attempted_at: Option<Timestamp>,
        last_pool_signature: u64,
        parked: bool,
    ) {
        let mut hot = self.hot.write().unwrap_or_else(|e| e.into_inner());
        hot.block_cooldown.insert(
            *block_id,
            BlockCooldown {
                last_attempted_at,
                last_pool_signature,
                parked,
            },
        );
    }

    /// Read a block's RAM cooldown (B-4). Default (never attempted) if absent.
    pub fn block_cooldown(&self, block_id: &SourceBlockId) -> BlockCooldown {
        self.hot()
            .block_cooldown
            .get(block_id)
            .copied()
            .unwrap_or_default()
    }

    /// Clear all worker cooldowns (B-4). Used on PeerAuthenticated to force every
    /// below-target block to be re-evaluated immediately.
    pub fn clear_all_block_cooldowns(&self) {
        let mut hot = self.hot.write().unwrap_or_else(|e| e.into_inner());
        hot.block_cooldown.clear();
    }

    // ── SystemState-as-block ledger (SS_BLOCKS) ────────────────────────────
    //
    // Records which SOURCE_BLOCKS entries are SystemState blocks so `snapshot_db`
    // can exclude them (avoid self-reference) and the push loop can retire old
    // generations.

    /// Mark `block_id` as a SystemState block produced at `generation`.
    pub fn mark_ss_block(&self, block_id: &SourceBlockId, generation: u32) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(&generation);
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(SS_BLOCKS)?;
            table.insert(&block_id.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Remove `block_id` from the SS ledger (used when retiring a superseded block).
    pub fn unmark_ss_block(&self, block_id: &SourceBlockId) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(SS_BLOCKS)?;
            table.remove(&block_id.0)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Whether `block_id` is a SystemState block (present in the SS ledger).
    pub fn is_ss_block(&self, block_id: &SourceBlockId) -> Result<bool, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SS_BLOCKS)?;
        Ok(table.get(&block_id.0)?.is_some())
    }

    /// List all SS blocks as (block_id, generation). Used to retire old generations.
    pub fn list_ss_blocks(&self) -> Result<Vec<(SourceBlockId, u32)>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SS_BLOCKS)?;
        let mut out = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            let generation: u32 = from_cbor_bytes(v.value())?;
            out.push((SourceBlockId(*k.value()), generation));
        }
        Ok(out)
    }

    /// Set of SS block ids — for bulk exclusion in `snapshot_db`.
    pub fn ss_block_id_set(&self) -> Result<std::collections::HashSet<[u8; 32]>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SS_BLOCKS)?;
        let mut out = std::collections::HashSet::new();
        for item in table.iter()? {
            let (k, _) = item?;
            out.insert(*k.value());
        }
        Ok(out)
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
    /// `!reliability::meets_target(current_reliability, target_reliability)` (repair-i3:
    /// the single tolerance-aware definition of "at target").
    ///
    /// Blocks in cooldown are excluded. A block is in cooldown when:
    /// - it was attempted recently (`last_attempted_at` is `Some(t)` with
    ///   `now - t < cooldown`, or `< parked_cooldown` if the block is parked), AND
    /// - the authenticated peer pool has not changed (`last_pool_signature == current_pool_sig`).
    ///
    /// A parked block (last attempt found nobody to take symbols, repair-i4) is also
    /// released early by a placement-status change of the block (the park flag is
    /// cleared in the hot cache) or by `clear_all_block_cooldowns`.
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
    /// * `parked_cooldown` — the longer window applied to parked blocks (repair-i4).
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
        parked_cooldown: Duration,
        now: Timestamp,
        current_pool_sig: u64,
    ) -> Result<Option<SourceBlockRecord>, DbError> {
        let all = self.list_all_source_blocks()?;
        let cooldown_secs = cooldown.as_secs();
        let parked_cooldown_secs = parked_cooldown.as_secs();
        // Cooldown state is RAM-only (B-4); take one read lock for the whole pass.
        let hot = self.hot();
        let cooldown_of = |id: &SourceBlockId| -> BlockCooldown {
            hot.block_cooldown.get(id).copied().unwrap_or_default()
        };

        let eligible = all.into_iter().filter(|b| {
            if b.status != SourceBlockStatus::Active {
                return false;
            }
            if b.target_reliability <= 0.0
                || crate::reliability::meets_target(b.current_reliability, b.target_reliability)
            {
                return false;
            }
            if current_pool_sig != 0 {
                let cd = cooldown_of(&b.block_id);
                if let Some(last_at) = cd.last_attempted_at {
                    let elapsed = now.0.saturating_sub(last_at.0);
                    let window = if cd.parked {
                        parked_cooldown_secs
                    } else {
                        cooldown_secs
                    };
                    if elapsed < window && cd.last_pool_signature == current_pool_sig {
                        return false;
                    }
                }
            }
            true
        });

        let winner = eligible.max_by(|a, b| {
            let pa =
                crate::priority::priority(a.importance, a.current_alive, a.n.unwrap_or(0), coef);
            let pb =
                crate::priority::priority(b.importance, b.current_alive, b.n.unwrap_or(0), coef);
            let a_last = cooldown_of(&a.block_id).last_attempted_at;
            let b_last = cooldown_of(&b.block_id).last_attempted_at;
            pa.total_cmp(&pb)
                .then(a_last.cmp(&b_last).reverse())
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
        let old_status = hot
            .placements
            .insert(
                (record.source_block_id, record.holder_id),
                PlacementAgg {
                    symbol_count: count,
                    status: record.status,
                    last_pos: record.last_verified,
                },
            )
            .map(|agg| agg.status);
        unpark_on_status_change(
            &mut hot,
            &record.source_block_id,
            old_status,
            Some(record.status),
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
            let old_status = hot
                .placements
                .remove(&(*block_id, *holder_id))
                .map(|agg| agg.status);
            unpark_on_status_change(&mut hot, block_id, old_status, None);

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
        let (lo, hi) = placement_range(block_id);
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

/// Both storage volumes of one economic pair, as of right now — the output row of
/// [`Db::storage_bytes_by_master`]. Raw BYTES; the gb conversion belongs to the writer of
/// the ledger (see [`crate::types::PairLedger`] on units).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MasterStorageBytes {
    /// The economic pair: a person, never a device.
    pub master: IdentityPub,
    /// Bytes on `Alive` placements at this master's devices (× symbol size) — what we
    /// BELIEVE they keep for us. Diagnostics only for the ledger since У-3 (Д-F = A): it is
    /// logged next to the confirmed column, nothing is charged with it.
    pub they_store_for_us: u64,
    /// The subset of those bytes whose placement is
    /// [`SymbolPlacement::confirmed_at`] `now` (a PoS pass inside
    /// [`PAIR_LEDGER_CONFIRMATION_WINDOW_SECS`]) — the `V_conf` of their service to us
    /// (У-3). Always `<= they_store_for_us`: confirmation requires `Alive`.
    pub they_store_for_us_confirmed: u64,
    /// Bytes WE keep for this master (`Active` holdings).
    pub we_store_for_them: u64,
}

/// Symbol size `t` of a source block, memoised across a scan.
///
/// A missing `SourceBlockRecord` contributes 0 — same convention as
/// [`Db::refresh_peer_storage_bytes`], and it is memoised too so a scan does not re-probe
/// the table for every placement of a block that is gone.
fn block_symbol_size(
    blocks: &redb::ReadOnlyTable<&'static [u8; 32], &'static [u8]>,
    block_id: &[u8; 32],
    memo: &mut HashMap<[u8; 32], u64>,
) -> Result<u64, DbError> {
    if let Some(t) = memo.get(block_id) {
        return Ok(*t);
    }
    let t = match blocks.get(block_id)? {
        Some(val) => {
            let block: SourceBlockRecord = from_cbor_bytes(val.value())?;
            block.t as u64
        }
        None => 0,
    };
    memo.insert(*block_id, t);
    Ok(t)
}

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

    /// Read-modify-write of one PeerRecord in ONE write transaction: `f` gets
    /// the stored record (None when there is none) and returns what to store
    /// (None = leave the table as it is: the transaction is aborted, nothing is
    /// written or synced). Returns the record as stored now.
    /// redb serializes write transactions, so two updates of the same peer never
    /// lose each other's change — the lost update of separate `get_peer` +
    /// `upsert_peer` calls (C-DK C4 fix round 1: identify addresses wiped by a
    /// concurrent authentication / announce write).
    pub fn update_peer<F>(&self, device_id: &DeviceId, f: F) -> Result<Option<PeerRecord>, DbError>
    where
        F: FnOnce(Option<PeerRecord>) -> Option<PeerRecord>,
    {
        let tx = self.inner.begin_write()?;
        let (stored, changed) = {
            let mut peers = tx.open_table(PEERS)?;
            let current: Option<PeerRecord> = match peers.get(&device_id.0)? {
                Some(v) => Some(from_cbor_bytes(v.value())?),
                None => None,
            };
            match f(current.clone()) {
                Some(next) => {
                    debug_assert_eq!(next.device_id, *device_id, "update_peer keeps the key");
                    let bytes = to_cbor_bytes(&next);
                    peers.insert(&device_id.0, bytes.as_slice())?;
                    (Some(next), true)
                }
                None => (current, false),
            }
        };
        if changed {
            tx.commit()?;
        } else {
            // Nothing to write: no commit (each redb commit is a durable fsync).
            tx.abort()?;
        }
        Ok(stored)
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

        // Update PeerRecord in one transaction with its read (no lost update of fields
        // written concurrently). No-op if device not yet in DB.
        self.update_peer(device_id, |r| {
            r.map(|mut record| {
                record.bytes_we_store_for_peer = we_store;
                record.bytes_peer_stores_for_us = peer_stores;
                record.trust_s = trust_s;
                record
            })
        })?;
        Ok(())
    }

    // ── 4R pair ledger (recorder; no decision reads it) ─────────────────────

    /// Read the pair ledger for a MASTER identity. `None` if nothing has been accrued.
    ///
    /// Absence is meaningful and must NOT be papered over with a zero-valued ledger by a
    /// caller that then treats it as an observation: a pair with no history is not a pair
    /// whose history integrated to zero. The same distinction inside a stored row is
    /// `PairLedger::last_update == None` (the clock never started).
    pub fn get_pair_ledger(&self, master: &IdentityPub) -> Result<Option<PairLedger>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(PAIR_LEDGER)?;
        match table.get(&master.0)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Insert or replace the pair ledger for a MASTER identity.
    ///
    /// Deliberately does NOT require a `PeerRecord` (or any device of that master) to
    /// exist: the ledger is per-person, and a master can be known from a
    /// `DeviceCertificate` before any peer row is written. Requiring a peer row would
    /// silently drop accrual at exactly that moment.
    ///
    /// This pins INTENT, not a live flow, in the other direction: today no peer row ever
    /// disappears (`delete_peer` has no non-test call site, revocation only appends to
    /// `revoked_device_pub_keys`, and a re-install gets a fresh `DeviceId` leaving the old
    /// row in place). The rule is stated so that if pruning is ever added, a person's
    /// accrued history is not deleted along with a machine.
    ///
    /// The cost is that a caller passing a stray identity creates an orphan row;
    /// `list_pair_ledgers` therefore returns the key, so a future sweep can reconcile
    /// against known masters.
    pub fn upsert_pair_ledger(
        &self,
        master: &IdentityPub,
        ledger: &PairLedger,
    ) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(ledger);
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(PAIR_LEDGER)?;
            table.insert(&master.0, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Insert or replace many pair ledgers in ONE write transaction.
    ///
    /// Restore-shaped counterpart of [`Db::list_pair_ledgers`] (same tuple type, so a
    /// snapshot round-trips through the pair). Used by `system_state::restore_db_inner`,
    /// where the alternative — one transaction per row — would fsync once per known
    /// master while rebuilding a database that is not yet visible to anything.
    ///
    /// Same non-requirement as [`Db::upsert_pair_ledger`]: a row is written whether or
    /// not that master has a `PeerRecord`.
    pub fn upsert_pair_ledgers(&self, rows: &[(IdentityPub, PairLedger)]) -> Result<(), DbError> {
        if rows.is_empty() {
            return Ok(());
        }
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(PAIR_LEDGER)?;
            for (master, ledger) in rows {
                let bytes = to_cbor_bytes(ledger);
                table.insert(&master.0, bytes.as_slice())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// All pair ledgers, paired with the master identity they belong to.
    ///
    /// Iteration order is redb key order (identity bytes ascending) — deterministic, so a
    /// periodic sweep over it cannot depend on insertion history.
    ///
    /// Strict decode: an unreadable row makes the whole call `Err`, which propagates into
    /// `snapshot_db` and stops SystemState publication. That is intended (a silently
    /// zeroed ledger would be worse), and it is why every new [`PairLedger`] field must
    /// carry `#[serde(default)]` — see the type's "Adding a field later" section.
    pub fn list_pair_ledgers(&self) -> Result<Vec<(IdentityPub, PairLedger)>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(PAIR_LEDGER)?;
        let mut out = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            out.push((IdentityPub(*k.value()), from_cbor_bytes(v.value())?));
        }
        Ok(out)
    }

    /// All pending drop events (У-4), in master key order. Tests and diagnostics only —
    /// there is no production reader (AC-7): the accrual tick takes a master's row inside its
    /// own write transaction ([`DbWriteTxn::take_pending_drops`]) and nothing else looks.
    pub fn list_pending_drops(&self) -> Result<Vec<(IdentityPub, PendingDrops)>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(PAIR_LEDGER_PENDING_DROPS)?;
        let mut out = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            let master = IdentityPub(*k.value());
            let pending = decode_pending_drops(&master, v.value());
            out.push((master, pending));
        }
        Ok(out)
    }

    /// Bytes WE currently store for `master` — the recorder's `V_conf` for the
    /// "our service to this person" axis (`PairLedger::gb_days_we_store_for_them`).
    ///
    /// Identical definition to the `bytes_we_store_for_peer` half of
    /// [`Db::refresh_peer_storage_bytes`]: `total_bytes` summed over `Active` holdings whose
    /// `owner_id == master`. Already per-master with nothing to fold — HOLDINGS are keyed by
    /// the owner's MASTER identity, not by device (S-4 key layout).
    ///
    /// A SNAPSHOT (bytes held right now), not a gb·day sum: the recorder multiplies it by
    /// the elapsed interval itself. Compare [`Db::stored_for_peer_gb_days`], which is the
    /// gb·day form but re-derives the age of every holding and therefore forgets a dropped
    /// one retroactively.
    pub fn bytes_we_store_for_master(&self, master: &IdentityPub) -> Result<u64, DbError> {
        let mut total = 0u64;
        for holding in self.list_holdings_for_owner(master)? {
            if holding.status != HoldingStatus::Active {
                continue;
            }
            total = total.saturating_add(holding.total_bytes);
        }
        Ok(total)
    }

    /// Bytes ALL devices of `master` currently store for US — the recorder's `V_conf` for
    /// the "this person's service to us" axis (`PairLedger::gb_days_they_store_for_us`) and
    /// for the loyalty depth `D`.
    ///
    /// A POINT query. The periodic sweep must NOT call it once per master — that is
    /// quadratic (see [`Db::storage_bytes_by_master`], which answers the same question for
    /// everyone in one pass).
    ///
    /// Same per-placement formula as the `bytes_peer_stores_for_us` half of
    /// [`Db::refresh_peer_storage_bytes`] (`symbol_count × t` over `Alive` placements), but
    /// summed across the master's devices instead of one device: SYMBOL_PLACEMENTS is keyed
    /// by holder DEVICE while the ledger is keyed by MASTER, so charging the master row with
    /// a single device's number would under-count the axis by however many machines that
    /// person runs.
    ///
    /// The device set is resolved from PEERS (`PeerRecord::master_identity`), deliberately
    /// NOT from `device_to_master` / [`Db::get_devices_for_master`]. That table is not part
    /// of the SystemState snapshot, so after disaster recovery it is empty until each peer
    /// re-authenticates — the axis would silently read zero for as long as that takes, in
    /// exactly the scenario the ledger is carried through DR for.
    ///
    /// The placeholder identity `IdentityPub([0; 32])` answers 0: it is not a person but
    /// the "master unknown" marker left by pre-certificate peer rows, so summing over the
    /// devices carrying it would report one stranger's storage as another's.
    ///
    /// A block whose `SourceBlockRecord` is gone contributes 0, matching
    /// `refresh_peer_storage_bytes`.
    pub fn bytes_master_stores_for_us(&self, master: &IdentityPub) -> Result<u64, DbError> {
        if master.0 == [0u8; 32] {
            return Ok(0);
        }
        let tx = self.inner.begin_read()?;

        // Devices of this master, from PEERS (see doc comment: NOT device_to_master).
        let mut devices: HashSet<[u8; 32]> = HashSet::new();
        {
            let peers = tx.open_table(PEERS)?;
            for item in peers.iter()? {
                let (_, v) = item?;
                let record: PeerRecord = from_cbor_bytes(v.value())?;
                if record.master_identity == *master {
                    devices.insert(record.device_id.0);
                }
            }
        }
        if devices.is_empty() {
            return Ok(0);
        }

        let placements = tx.open_table(SYMBOL_PLACEMENTS)?;
        let blocks = tx.open_table(SOURCE_BLOCKS)?;
        // One `t` lookup per distinct block instead of per placement: a master with several
        // devices holding symbols of the same block is the normal case.
        let mut symbol_size: HashMap<[u8; 32], u64> = HashMap::new();
        let mut total = 0u64;
        for item in placements.iter()? {
            let (k, v) = item?;
            // Key = [block_id(32) || holder(32)].
            let mut holder = [0u8; 32];
            holder.copy_from_slice(&k.value()[32..64]);
            if !devices.contains(&holder) {
                continue;
            }
            let placement: SymbolPlacement = from_cbor_bytes(v.value())?;
            if placement.status != PlacementStatus::Alive {
                continue;
            }
            let t = block_symbol_size(&blocks, &placement.source_block_id.0, &mut symbol_size)?;
            total = total.saturating_add(placement.symbol_count() as u64 * t);
        }
        Ok(total)
    }

    /// Both storage volumes for EVERY peer master, in one pass over each table.
    ///
    /// This is the sweep form of [`Db::bytes_master_stores_for_us`] +
    /// [`Db::bytes_we_store_for_master`], and it exists because the per-master form is
    /// quadratic when called in a loop: each call re-scans PEERS (CBOR-decoding every
    /// record) and re-walks every SYMBOL_PLACEMENTS key, so a node with M peer masters and
    /// S placements did `M` peer decodes per master and `M·S` key visits — synchronously,
    /// inside the scheduler's `select!`. At 300 masters that is ~90k decodes and ~90M key
    /// visits per tick, and the tick period shrinks with `time_scale`: 3 s at 1000 (integer
    /// `3600/1000`, not 3.6), 1 s at anything above 3600.
    ///
    /// Here PEERS is walked once into `device → master`, SYMBOL_PLACEMENTS once into a
    /// `master → bytes` accumulator sharing ONE `block → t` memo, and HOLDINGS once into
    /// the other accumulator.
    ///
    /// The row set is the peer masters: every distinct non-zero `PeerRecord::master_identity`
    /// (zero = the "master unknown" placeholder, not a person — see
    /// [`Db::bytes_master_stores_for_us`]). Masters known only from HOLDINGS get no row,
    /// matching what a per-master loop over the peer list would have produced. Ordering is
    /// by master identity bytes, so a sweep over the result cannot depend on insertion
    /// history.
    ///
    /// `now` and `time_scale` exist for ONE column, `they_store_for_us_confirmed`: the same
    /// pass over SYMBOL_PLACEMENTS asks each `Alive` placement whether it is
    /// [`SymbolPlacement::confirmed_at`] `now` on the scaled clock (У-3). No extra pass, no
    /// extra table.
    pub fn storage_bytes_by_master(
        &self,
        now: Timestamp,
        time_scale: u64,
    ) -> Result<Vec<MasterStorageBytes>, DbError> {
        let tx = self.inner.begin_read()?;

        // Pass 1: PEERS → device → master (and the master set itself).
        let mut master_of_device: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
        let mut totals: BTreeMap<[u8; 32], MasterStorageBytes> = BTreeMap::new();
        {
            let peers = tx.open_table(PEERS)?;
            for item in peers.iter()? {
                let (_, v) = item?;
                let record: PeerRecord = from_cbor_bytes(v.value())?;
                let master = record.master_identity;
                if master.0 == [0u8; 32] {
                    continue;
                }
                master_of_device.insert(record.device_id.0, master.0);
                totals.entry(master.0).or_insert(MasterStorageBytes {
                    master,
                    they_store_for_us: 0,
                    they_store_for_us_confirmed: 0,
                    we_store_for_them: 0,
                });
            }
        }
        if totals.is_empty() {
            return Ok(Vec::new());
        }

        // Pass 2: SYMBOL_PLACEMENTS → what each master's devices keep for us.
        {
            let placements = tx.open_table(SYMBOL_PLACEMENTS)?;
            let blocks = tx.open_table(SOURCE_BLOCKS)?;
            let mut symbol_size: HashMap<[u8; 32], u64> = HashMap::new();
            for item in placements.iter()? {
                let (k, v) = item?;
                // Key = [block_id(32) || holder(32)].
                let mut holder = [0u8; 32];
                holder.copy_from_slice(&k.value()[32..64]);
                let master = match master_of_device.get(&holder) {
                    Some(m) => *m,
                    None => continue,
                };
                let placement: SymbolPlacement = from_cbor_bytes(v.value())?;
                if placement.status != PlacementStatus::Alive {
                    continue;
                }
                let t = block_symbol_size(&blocks, &placement.source_block_id.0, &mut symbol_size)?;
                if let Some(entry) = totals.get_mut(&master) {
                    let bytes = placement.symbol_count() as u64 * t;
                    entry.they_store_for_us = entry.they_store_for_us.saturating_add(bytes);
                    if placement.confirmed_at(now, time_scale, PAIR_LEDGER_CONFIRMATION_WINDOW_SECS)
                    {
                        entry.they_store_for_us_confirmed =
                            entry.they_store_for_us_confirmed.saturating_add(bytes);
                    }
                }
            }
        }

        // Pass 3: HOLDINGS → what we keep for each master (already keyed by owner-master).
        {
            let holdings = tx.open_table(HOLDINGS)?;
            for item in holdings.iter()? {
                let (k, v) = item?;
                // Key = [owner(32) || block_id(32)] (S-4).
                let mut owner = [0u8; 32];
                owner.copy_from_slice(&k.value()[..32]);
                let entry = match totals.get_mut(&owner) {
                    Some(e) => e,
                    None => continue,
                };
                let holding: HoldingRecord = from_cbor_bytes(v.value())?;
                if holding.status != HoldingStatus::Active {
                    continue;
                }
                entry.we_store_for_them =
                    entry.we_store_for_them.saturating_add(holding.total_bytes);
            }
        }

        Ok(totals.into_values().collect())
    }

    /// Batch decay: for each PeerRecord where (now - last_avail_sample) >= tick_secs,
    /// apply EXACTLY 1 decay tick: avail = (1-alpha) * avail.
    /// Updates avail_ewma + last_avail_sample in one write transaction.
    /// Returns count of updated records.
    pub fn apply_avail_decay_batch(
        &self,
        alpha: f64,
        now_secs: u64,
        tick_secs: u64,
    ) -> Result<u64, DbError> {
        use crate::types::ewma_decay_tick;
        // Guard against a zero tick interval: `elapsed >= 0` is always true, so
        // a zero tick_secs would decay every peer on every call. Never happens
        // with AVAIL_DECAY_TICK_SECS (86400), but keep the invariant explicit.
        if tick_secs == 0 {
            return Ok(0);
        }
        // The records are read inside the write transaction (a snapshot read before it
        // would write back addresses, contacts and revocations committed in between).
        let mut updated = 0u64;
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(PEERS)?;
            let peers = peers_in(&table)?;
            for mut record in peers {
                let elapsed = now_secs.saturating_sub(record.last_avail_sample);
                if elapsed >= tick_secs {
                    record.avail_ewma = ewma_decay_tick(record.avail_ewma, alpha);
                    record.last_avail_sample = now_secs;
                    let bytes = to_cbor_bytes(&record);
                    table.insert(&record.device_id.0, bytes.as_slice())?;
                    updated += 1;
                }
            }
        }
        if updated > 0 {
            tx.commit()?;
        } else {
            tx.abort()?;
        }
        Ok(updated)
    }

    /// Startup catch-up: apply n missed ticks per peer, set last_avail_sample=now.
    /// Called ONCE at daemon start before spawning run_avail_decay_task.
    /// Returns the count of peers whose avail_ewma was actually decayed (n > 0),
    /// consistent with `apply_avail_decay_batch`. Every peer's last_avail_sample
    /// is advanced to `now_secs` regardless, to reset the decay clock.
    pub fn apply_avail_decay_startup_catchup(
        &self,
        alpha: f64,
        now_secs: u64,
        tick_secs: u64,
    ) -> Result<u64, DbError> {
        use crate::types::ewma_decay_n_ticks;
        // Guard against div-by-zero: `elapsed / tick_secs` panics when tick_secs
        // is 0. Never happens with AVAIL_DECAY_TICK_SECS (86400), but explicit.
        if tick_secs == 0 {
            return Ok(0);
        }
        // Read inside the write transaction, as `apply_avail_decay_batch`.
        let mut decayed = 0u64;
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(PEERS)?;
            let peers = peers_in(&table)?;
            for mut record in peers {
                let elapsed = now_secs.saturating_sub(record.last_avail_sample);
                let n = (elapsed / tick_secs) as u32;
                if n > 0 {
                    record.avail_ewma = ewma_decay_n_ticks(record.avail_ewma, alpha, n);
                    decayed += 1;
                }
                record.last_avail_sample = now_secs;
                let bytes = to_cbor_bytes(&record);
                table.insert(&record.device_id.0, bytes.as_slice())?;
            }
        }
        tx.commit()?;
        Ok(decayed)
    }
}

/// Every PeerRecord of `table`, read through the caller's (write) transaction.
fn peers_in(
    table: &redb::Table<'_, &'static [u8; 32], &'static [u8]>,
) -> Result<Vec<PeerRecord>, DbError> {
    let mut out = Vec::new();
    for row in table.iter()? {
        let (_, v) = row?;
        out.push(from_cbor_bytes(v.value())?);
    }
    Ok(out)
}

// ============================================================
// Holdings table (holder view)
// ============================================================

impl Db {
    pub fn upsert_holding(&self, record: &HoldingRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let key = holding_key(&record.source_block_id, &record.owner_id);
        let old_bytes;
        let tx = self.inner.begin_write()?;
        {
            let mut holdings = tx.open_table(HOLDINGS)?;
            // Read the old record (if any) to compute the aggregate delta (S-9).
            old_bytes = match holdings.get(&key)? {
                Some(v) => from_cbor_bytes::<HoldingRecord>(v.value())?.total_bytes,
                None => 0,
            };
            holdings.insert(&key, bytes.as_slice())?;
        }
        tx.commit()?;

        // DB committed — adjust the cached holding-bytes aggregate.
        let mut hot = self.hot.write().unwrap_or_else(|e| e.into_inner());
        hot.holding_bytes_total = hot
            .holding_bytes_total
            .saturating_sub(old_bytes)
            .saturating_add(record.total_bytes);
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
        let old_bytes;
        let tx = self.inner.begin_write()?;
        {
            let mut holdings = tx.open_table(HOLDINGS)?;
            old_bytes = match holdings.get(&key)? {
                Some(v) => from_cbor_bytes::<HoldingRecord>(v.value())?.total_bytes,
                None => 0,
            };
            holdings.remove(&key)?;
        }
        tx.commit()?;

        // DB committed — drop the removed holding's bytes from the cached aggregate.
        let mut hot = self.hot.write().unwrap_or_else(|e| e.into_inner());
        hot.holding_bytes_total = hot.holding_bytes_total.saturating_sub(old_bytes);
        Ok(())
    }

    /// All holdings for a given owner (storage-balance and GB·days accounting).
    pub fn list_holdings_for_owner(
        &self,
        owner_id: &IdentityPub,
    ) -> Result<Vec<HoldingRecord>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(HOLDINGS)?;
        let mut records = Vec::new();
        // Keys are [owner(32) || block_id(32)] (S-4). Range over this owner's prefix.
        let mut lo = [0u8; 64];
        let mut hi = [0u8; 64];
        lo[..32].copy_from_slice(&owner_id.0);
        hi[..32].copy_from_slice(&owner_id.0);
        hi[32..].fill(0xFF);
        for item in table.range::<&[u8; 64]>(&lo..=&hi)? {
            let (_, v) = item?;
            let record: HoldingRecord = from_cbor_bytes(v.value())?;
            records.push(record);
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
    ///
    /// O(1): served from the cached running aggregate (S-9), maintained by
    /// `upsert_holding`/`delete_holding` and rebuilt at `Db::open()`.
    pub fn total_holding_bytes(&self) -> Result<u64, DbError> {
        Ok(self.hot().holding_bytes_total)
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
    /// NOT a leaky integral, and not a substitute for [`crate::types::PairLedger`]: it
    /// re-derives the sum from the holdings that are Active *right now*, so a dropped
    /// holding retroactively erases its own history, and it has no forgetting term. The
    /// 4R capital `G` is neither.
    ///
    /// Returns 0.0 if no active holdings exist for this owner.
    pub fn stored_for_peer_gb_days(
        &self,
        owner_id: &IdentityPub,
        now: Timestamp,
        time_scale: u64,
    ) -> Result<f64, DbError> {
        let secs_per_day = SECS_PER_DAY as f64;
        let scale = time_scale.max(1) as f64;
        let holdings = self.list_holdings_for_owner(owner_id)?;
        let mut total = 0.0_f64;
        for h in holdings {
            if h.status != HoldingStatus::Active {
                continue;
            }
            let age_secs = now.0.saturating_sub(h.received_at.0) as f64;
            let age_days = age_secs * scale / secs_per_day;
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
        let secs_per_day = SECS_PER_DAY as f64;
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
            let age_days = age_secs * scale / secs_per_day;
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
    pub file_holders: u64,
    pub holder_files: u64,
    #[serde(default)]
    pub mailbox_entries: u64,
    /// 4R pair-ledger rows (one per master identity we have accrued history for).
    ///
    /// Exposed because the single instruction left for the 4R return (`4r_handoff.md` §4)
    /// is "check that the accounting actually accumulated" — a row count is the cheapest
    /// way to see that the recorder is alive without reading the ledger itself.
    #[serde(default)]
    pub pair_ledger: u64,
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
            file_holders: tx.open_table(FILE_HOLDERS)?.len()?,
            holder_files: tx.open_table(HOLDER_FILES)?.len()?,
            mailbox_entries: tx.open_table(MAILBOX_ENTRIES)?.len()?,
            pair_ledger: tx.open_table(PAIR_LEDGER)?.len()?,
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
    /// A holding upsert/delete changed the total held bytes (S-9).
    /// Signed delta to apply to `holding_bytes_total` after commit.
    HoldingBytesDelta { delta: i64 },
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

    /// Insert or replace a FileRecord. Maintains the content_hash index (B-1).
    pub fn upsert_file(&mut self, record: &FileRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        {
            let mut files = self.txn.open_table(FILES)?;
            let old: Option<FileRecord> = match files.get(record.path.as_str())? {
                Some(v) => Some(from_cbor_bytes(v.value())?),
                None => None,
            };
            files.insert(record.path.as_str(), bytes.as_slice())?;

            let mut idx = self.txn.open_table(CONTENT_INDEX)?;
            if let Some(old) = &old {
                for v in &old.versions {
                    idx.remove(content_index_key(&v.content_hash, &old.path).as_slice())?;
                }
            }
            for v in &record.versions {
                idx.insert(
                    content_index_key(&v.content_hash, &record.path).as_slice(),
                    [].as_slice(),
                )?;
            }
        }
        Ok(())
    }

    /// Delete a FileRecord by path. Maintains the content_hash index (B-1).
    pub fn delete_file(&mut self, path: &str) -> Result<(), DbError> {
        {
            let mut files = self.txn.open_table(FILES)?;
            let old: Option<FileRecord> = match files.get(path)? {
                Some(v) => Some(from_cbor_bytes(v.value())?),
                None => None,
            };
            files.remove(path)?;

            if let Some(old) = &old {
                let mut idx = self.txn.open_table(CONTENT_INDEX)?;
                for v in &old.versions {
                    idx.remove(content_index_key(&v.content_hash, &old.path).as_slice())?;
                }
            }
        }
        Ok(())
    }

    /// Insert or replace a HoldingRecord.
    pub fn upsert_holding(&mut self, record: &HoldingRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(record);
        let key = holding_key(&record.source_block_id, &record.owner_id);
        let old_bytes;
        {
            let mut holdings = self.txn.open_table(HOLDINGS)?;
            old_bytes = match holdings.get(&key)? {
                Some(v) => from_cbor_bytes::<HoldingRecord>(v.value())?.total_bytes,
                None => 0,
            };
            holdings.insert(&key, bytes.as_slice())?;
        }
        self.deltas.push(HotCacheDelta::HoldingBytesDelta {
            delta: record.total_bytes as i64 - old_bytes as i64,
        });
        Ok(())
    }

    /// Delete a HoldingRecord.
    pub fn delete_holding(
        &mut self,
        block_id: &SourceBlockId,
        owner_id: &IdentityPub,
    ) -> Result<(), DbError> {
        let key = holding_key(block_id, owner_id);
        let old_bytes;
        {
            let mut holdings = self.txn.open_table(HOLDINGS)?;
            old_bytes = match holdings.get(&key)? {
                Some(v) => from_cbor_bytes::<HoldingRecord>(v.value())?.total_bytes,
                None => 0,
            };
            holdings.remove(&key)?;
        }
        self.deltas.push(HotCacheDelta::HoldingBytesDelta {
            delta: -(old_bytes as i64),
        });
        Ok(())
    }

    /// Record one drop event of `kind` for `master` (У-4, Д-K): `+1` on its pending row.
    ///
    /// Called in the SAME transaction as the placement change that IS the event, so the
    /// transition and the event commit or vanish together. The placeholder
    /// `IdentityPub([0; 32])` is a no-op — not a person, the same rule as the accrual sweep.
    pub fn record_drop_event(
        &mut self,
        master: &IdentityPub,
        kind: DropKind,
    ) -> Result<(), DbError> {
        if master.0 == [0u8; 32] {
            return Ok(());
        }
        let mut table = self.txn.open_table(PAIR_LEDGER_PENDING_DROPS)?;
        let mut pending = match table.get(&master.0)? {
            Some(v) => decode_pending_drops(master, v.value()),
            None => PendingDrops::default(),
        };
        pending.add(kind);
        let bytes = to_cbor_bytes(&pending);
        table.insert(&master.0, bytes.as_slice())?;
        Ok(())
    }

    /// Read AND remove the pending drop events of `master` (default when absent) — the
    /// accrual tick's side of the outbox. Atomic with whatever else this transaction writes
    /// (the ledger row the events are folded into): dropped without `commit`, the events stay
    /// queued.
    pub fn take_pending_drops(&mut self, master: &IdentityPub) -> Result<PendingDrops, DbError> {
        let mut table = self.txn.open_table(PAIR_LEDGER_PENDING_DROPS)?;
        let taken = match table.remove(&master.0)? {
            Some(v) => decode_pending_drops(master, v.value()),
            None => PendingDrops::default(),
        };
        Ok(taken)
    }

    /// Transactional twin of [`Db::upsert_pair_ledger`] — the accrual tick writes its rows
    /// in the same transaction that takes the folded events.
    pub fn upsert_pair_ledger(
        &mut self,
        master: &IdentityPub,
        ledger: &PairLedger,
    ) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(ledger);
        let mut table = self.txn.open_table(PAIR_LEDGER)?;
        table.insert(&master.0, bytes.as_slice())?;
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
                    let old_status = hot
                        .placements
                        .insert(
                            (block_id, holder_id),
                            PlacementAgg {
                                symbol_count: new_count,
                                status: new_status,
                                last_pos: new_last_pos,
                            },
                        )
                        .map(|agg| agg.status);
                    unpark_on_status_change(&mut hot, &block_id, old_status, Some(new_status));
                }
                HotCacheDelta::PlacementDeleted {
                    block_id,
                    holder_id,
                    was_alive,
                    old_count,
                } => {
                    let old_status = hot
                        .placements
                        .remove(&(block_id, holder_id))
                        .map(|agg| agg.status);
                    unpark_on_status_change(&mut hot, &block_id, old_status, None);

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
                HotCacheDelta::HoldingBytesDelta { delta } => {
                    hot.holding_bytes_total = if delta >= 0 {
                        hot.holding_bytes_total.saturating_add(delta as u64)
                    } else {
                        hot.holding_bytes_total.saturating_sub((-delta) as u64)
                    };
                }
            }
        }

        Ok(())
    }
}

/// Lenient decode of a [`PendingDrops`] row: anything that does not decode reads as zeros.
/// The row is only ever taken and folded, never accrued upon, so the worst case is losing the
/// pending counts of one master; a strict decode would fail the whole accrual tick instead.
///
/// Not silent: a row that fails to decode is logged at `error!` with its master (graceful +
/// `tracing::error`, the project convention), because the events it held are gone.
fn decode_pending_drops(master: &IdentityPub, bytes: &[u8]) -> PendingDrops {
    match from_cbor_bytes(bytes) {
        Ok(pending) => pending,
        Err(e) => {
            tracing::error!(
                target: "viaticum::ledger",
                master = %master,
                err = %e,
                "pair-ledger: undecodable pending-drops row read as zero events (its queued events are lost)"
            );
            PendingDrops::default()
        }
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

// Mailbox tables (postman storage + directed-mail addressing): db/mailbox.
mod mailbox;
pub use mailbox::{MailboxRawDump, SelfPointerStore, read_only_mailbox_raw_entries};

// ============================================================
// Testutil
// ============================================================

#[cfg(any(test, feature = "testutil"))]
pub mod testutil {
    use redb::StorageBackend;

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

    /// A concurrent PeerRecord writer for lost-update tests: a thread that bumps
    /// `bytes_peer_stores_for_us` of `device` `n` times, each in its own
    /// [`Db::update_peer`] transaction. A writer under test that reads and writes back in
    /// two transactions overwrites some bumps with its stale snapshot; one that goes
    /// through `update_peer` loses none (the field ends at its start value + `n`).
    pub fn bump_peer_in_thread(db: Db, device: DeviceId, n: u64) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            for _ in 0..n {
                db.update_peer(&device, |r| {
                    r.map(|mut rec| {
                        rec.bytes_peer_stores_for_us += 1;
                        rec
                    })
                })
                .expect("bump");
            }
        })
    }

    /// An in-memory storage for probing tests: its writes fail while `fail` is set (a full
    /// disk or a redb I/O error on demand; reads keep working), it counts its syncs (every
    /// durable redb commit syncs; a read or an aborted write transaction does not), and each
    /// sync sleeps `sync_delay_ms` (a slow disk under load).
    #[derive(Debug)]
    struct ProbeBackend {
        inner: redb::backends::InMemoryBackend,
        fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
        syncs: std::sync::Arc<std::sync::atomic::AtomicU64>,
        sync_delay_ms: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl ProbeBackend {
        fn check(&self) -> std::io::Result<()> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                Err(std::io::Error::other("test: storage writes switched off"))
            } else {
                Ok(())
            }
        }
    }

    impl StorageBackend for ProbeBackend {
        fn len(&self) -> std::io::Result<u64> {
            self.inner.len()
        }
        fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
            self.inner.read(offset, out)
        }
        fn set_len(&self, len: u64) -> std::io::Result<()> {
            self.check()?;
            self.inner.set_len(len)
        }
        fn sync_data(&self) -> std::io::Result<()> {
            self.check()?;
            let ms = self.sync_delay_ms.load(std::sync::atomic::Ordering::SeqCst);
            if ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
            self.syncs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.sync_data()
        }
        fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
            self.check()?;
            self.inner.write(offset, data)
        }
    }

    /// The handles of a [`test_db_with_sync_probe`] db.
    #[derive(Debug, Clone)]
    pub struct SyncProbe {
        /// Storage syncs so far (durable commits; compare deltas, a commit may sync more
        /// than once).
        pub syncs: std::sync::Arc<std::sync::atomic::AtomicU64>,
        /// Each sync sleeps this long (ms); 0 = no delay.
        pub sync_delay_ms: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl SyncProbe {
        pub fn syncs(&self) -> u64 {
            self.syncs.load(std::sync::atomic::Ordering::SeqCst)
        }
        pub fn set_sync_delay_ms(&self, ms: u64) {
            self.sync_delay_ms
                .store(ms, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn probe_db() -> (Db, ProbeBackendHandles) {
        let fail = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let syncs = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let sync_delay_ms = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let backend = ProbeBackend {
            inner: redb::backends::InMemoryBackend::new(),
            fail: std::sync::Arc::clone(&fail),
            syncs: std::sync::Arc::clone(&syncs),
            sync_delay_ms: std::sync::Arc::clone(&sync_delay_ms),
        };
        let db = redb::Database::builder()
            .create_with_backend(backend)
            .expect("test db");
        Db::create_tables(&db).expect("test db tables");
        let hot = super::HotCache::build_from_db(&db).expect("test db hot cache");
        (
            Db {
                inner: std::sync::Arc::new(db),
                hot: std::sync::Arc::new(std::sync::RwLock::new(hot)),
            },
            ProbeBackendHandles {
                fail,
                probe: SyncProbe {
                    syncs,
                    sync_delay_ms,
                },
            },
        )
    }

    struct ProbeBackendHandles {
        fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
        probe: SyncProbe,
    }

    /// A test db that counts its durable commits and can make them slow (C-DK C4 fix round
    /// 3: "a batch of authentications is one commit", "the processor does not wait for a
    /// slow disk").
    pub fn test_db_with_sync_probe() -> (Db, SyncProbe) {
        let (db, handles) = probe_db();
        (db, handles.probe)
    }

    /// A test db whose writes fail while the returned switch is `true` (mailbox-i59:
    /// "META not written → nothing sent").
    pub fn test_db_with_write_switch() -> (Db, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        let (db, handles) = probe_db();
        (db, handles.fail)
    }
}

/// DN-1: applied signed letters by signature (`seen_signed_letters` + expiry index).
mod seen_signed_letters;

mod serviceability;
pub use serviceability::{Serviceability, serviceability_of};

/// В-0: 4R holder state (`four_r_state`: the relay latch row).
mod four_r_state;

/// backup-i4: too-large source marks (`too_large_sources`), node-local.
mod too_large;

/// C-DK C4 fix round 3: a batch of peer updates in one write transaction.
mod peer_batch;
pub use peer_batch::PeerBatch;

#[cfg(test)]
mod tests;
