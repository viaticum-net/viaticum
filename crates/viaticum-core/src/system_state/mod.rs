// System state snapshot: serialize the entire DB into an encrypted blob
// for disaster recovery.
//
// Pack flow:  DB → SystemState → CBOR → zstd(3) → ChaCha20-Poly1305 → blob
// Unpack flow: blob → decrypt → decompress → CBOR → SystemState → DB
//
// Wire format: [salt(24)][nonce(12)][ciphertext+tag(N+16)]
// HKDF-SHA256(salt, identity_key) → ChaCha20-Poly1305 key

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit;
use chacha20poly1305::aead::AeadInPlace;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use sha2::Sha256;
use std::io::Cursor;

use crate::cluster::StoredClusterState;

pub mod catalog;
use crate::types::{
    DeviceId, FileId, FileRecord, IdentityPub, PairLedger, PeerRecord, SourceBlockId,
    SourceBlockRecord, SymbolPlacement, Timestamp, to_cbor_bytes,
};
pub use catalog::{CatalogLineageId, CatalogSummary};

// ============================================================
// Local table definition (mirrors db/mod.rs, same name string)
// ============================================================

/// Same key/value types as POS_WEEKLY in db/mod.rs.
/// [IdentityPub(32) || week_number_BE(4)] → CBOR(WeeklyPosEntry)
const POS_WEEKLY_LOCAL: TableDefinition<&[u8; 36], &[u8]> = TableDefinition::new("pos_weekly");

// ============================================================
// Version
// ============================================================

/// Current format version. Increment on backward-incompatible struct changes.
pub const SYSTEM_STATE_VERSION: u8 = 1;

// ============================================================
// HKDF info string
// ============================================================

const SYSTEM_STATE_ENCRYPTION_INFO: &[u8] = b"viaticum-system-state";

// ============================================================
// SystemState struct
// ============================================================

/// Complete serializable snapshot of the node's DB state.
/// Compressed + encrypted → distributed to peers as disaster-recovery blob.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemState {
    /// Format version. Current = SYSTEM_STATE_VERSION.
    /// Restore must reject blobs with version > SYSTEM_STATE_VERSION.
    pub version: u8,

    /// Timestamp when this snapshot was taken.
    pub created_at: Timestamp,

    /// All FileRecord entries.
    pub files: Vec<FileRecord>,

    /// All SourceBlockRecord entries (owner view).
    pub source_blocks: Vec<SourceBlockRecord>,

    /// All SymbolPlacement entries (owner view).
    pub symbol_placements: Vec<SymbolPlacement>,

    /// All PeerRecord entries.
    pub peers: Vec<PeerRecord>,

    /// All PoS weekly records as raw key-value pairs.
    /// Key = identity_pub[32] || week_number_be[4] (36 bytes).
    /// Stored as Vec<u8> because serde only auto-derives fixed arrays up to [u8;32].
    pub pos_weekly: Vec<PosWeeklyEntry>,

    /// Cluster state, if any.
    pub cluster_state: Option<StoredClusterState>,

    /// All 4R pair-ledger rows (`pair_ledger` table), keyed by master identity.
    ///
    /// **Why it is in the snapshot at all.** The ledger is a set of time-integrals
    /// (gb·days accrued over months). Disaster recovery is precisely the event the
    /// project exists for — and if the ledger did not travel in the snapshot, DR would
    /// zero the accounting exactly then, at the moment the history is most expensive to
    /// have lost, since an integral cannot be recomputed from a post-DR snapshot.
    ///
    /// **Why it travels only here and NOT in [`DiffOp`].** There is deliberately no
    /// `PairLedgerUpserted` op — but NOT for either reason previously written here, both
    /// of which were refuted against the code. "A diff would let a cluster sibling
    /// overwrite my first-hand integrals" is false: [`apply_diffs`] has a single non-test
    /// call site (disaster recovery) and it runs on a freshly recreated database, with
    /// base and diffs read from ONE self-pointer, so no live path applies a foreign diff
    /// to a running DB. "Ledger churn would balloon the diff stream" is also false in the
    /// form it was stated: peer rows are already rewritten hourly without any ledger
    /// (`record_avail_contact` on every successful mailbox fetch), so a non-empty diff on
    /// every push is today's baseline. The one reason that survives is key shape — the
    /// ledger is per-master, `PeerRecord` is per-device. See [`crate::types::PairLedger`].
    ///
    /// **What it costs to carry, in bytes (measured, not estimated).** One row encodes to
    /// **223 B** of CBOR (the nine field NAMES are 146 B of that — CBOR maps carry their
    /// keys) plus a 32-byte redb key; wrapped in a [`PairLedgerEntry`] with the master
    /// identity it is **≈304 B**, so a 300-peer circle adds **≈90 KB** to every base blob.
    /// Sub-1% of a base that already carries `files`, `symbol_placements` and `peers`, and
    /// flat in time — the row count is bounded by the number of people, not by history.
    ///
    /// **The cost of base-only, in numbers.** A restored ledger is as of the last *base*
    /// publication. The base is rebuilt on every daemon restart and after
    /// `DIFF_COMPACTION_THRESHOLD = 20` NON-EMPTY diffs, published at most every 6 hours.
    /// So ≈5 days is the **floor**, not the worst case: it is reached only if every single
    /// push carries a change. The quieter the node, the longer 20 diffs take to accumulate
    /// and the staler the ledger in the base — a circle of mostly-offline peers (diffs
    /// roughly daily, from avail decay) lands nearer ≈20 days. Against `τ ≈ 60 days` that
    /// is still bounded, and re-accumulated by simply continuing to accrue.
    ///
    /// **What base-only does NOT protect against.** Because the ledger rides the base, a
    /// cluster device doing DR can restore from a *sibling's* snapshot and inherit the
    /// sibling's ledger — exactly as it already inherits the sibling's `peers`, `files`
    /// and `symbol_placements`. That is a property of the whole SystemState (self-pointer
    /// is signed by the master and lives in the master's mailbox), open in tech-debt next
    /// to CROWN-1, and not something this field either introduces or fixes.
    ///
    /// `#[serde(default)]` is the migration path for blobs packed before this field
    /// existed: they decode with an empty vec instead of erroring.
    #[serde(default)]
    pub pair_ledgers: Vec<PairLedgerEntry>,
}

/// One row of the `pair_ledger` table inside a [`SystemState`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PairLedgerEntry {
    /// Master identity the ledger belongs to (the table key).
    pub master: IdentityPub,
    /// The accumulators themselves.
    pub ledger: PairLedger,
}

/// One entry from the `pos_weekly` table.
/// Key stored alongside value because the week number is encoded only in the key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PosWeeklyEntry {
    /// Raw 36-byte key: [identity_pub(32) || week_number_be(4)].
    /// Using Vec<u8> because serde only auto-impls fixed arrays up to [u8;32].
    pub key: Vec<u8>,
    /// Raw CBOR bytes of WeeklyPosEntry (opaque here).
    pub value: Vec<u8>,
}

// ============================================================
// Error
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum SystemStateError {
    #[error("db error: {0}")]
    Db(#[from] crate::db::DbError),

    #[error("cbor error: {0}")]
    Cbor(String),

    #[error("compression error: {0}")]
    Compression(String),

    #[error("decompression error: {0}")]
    Decompression(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("blob too short: need {expected}, got {got}")]
    BlobTooShort { expected: usize, got: usize },

    #[error("unsupported version {found}, max supported {max}")]
    UnsupportedVersion { found: u8, max: u8 },

    #[error("database not empty: restore requires empty db")]
    DbNotEmpty,

    #[error("invalid self-pointer signature")]
    InvalidSignature,
}

// Convenience conversions from raw redb error types used in raw table access.
impl From<redb::TransactionError> for SystemStateError {
    fn from(e: redb::TransactionError) -> Self {
        SystemStateError::Db(crate::db::DbError::from(e))
    }
}

impl From<redb::TableError> for SystemStateError {
    fn from(e: redb::TableError) -> Self {
        SystemStateError::Db(crate::db::DbError::from(e))
    }
}

impl From<redb::StorageError> for SystemStateError {
    fn from(e: redb::StorageError) -> Self {
        SystemStateError::Db(crate::db::DbError::from(e))
    }
}

impl From<redb::CommitError> for SystemStateError {
    fn from(e: redb::CommitError) -> Self {
        SystemStateError::Db(crate::db::DbError::from(e))
    }
}

// ============================================================
// Key derivation
// ============================================================

fn derive_system_state_key(identity_key: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), identity_key);
    let mut key = [0u8; 32];
    hk.expand(SYSTEM_STATE_ENCRYPTION_INFO, &mut key)
        .expect("HKDF expand: 32-byte output always valid");
    key
}

// ============================================================
// snapshot_db
// ============================================================

/// Dump all critical DB tables into a SystemState struct.
///
/// Reads: files, source_blocks, symbol_placements, peers, pos_weekly, cluster_state,
/// pair_ledger.
/// Does NOT include: holdings (holder-specific), budget, event_log (secondary/ephemeral),
/// device_to_master (rebuilt from live certificate exchange after DR).
/// Also not included: `too_large_sources` (backup-i4). A mark says "this machine refuses this
/// file at this limit"; it depends on the machine's RAM and config, so it must not travel to
/// a node with another limit. A file that was never protected has no catalog record, and a
/// protected one that grew shows its older version with that version's date; the new node
/// re-evaluates every path itself.
///
/// Fails if any table fails to decode — including a `pair_ledger` row (strict decode, see
/// [`crate::types::PairLedger`]). The daemon's periodic push treats a failure here as
/// "log and skip the tick", so a decode error stops SystemState publication entirely.
pub fn snapshot_db(db: &crate::db::Db) -> Result<SystemState, SystemStateError> {
    let files = db.list_all_files()?;
    // SystemState-as-block records live in SOURCE_BLOCKS so the generic pipeline
    // places/PoS them, but they must NOT enter the snapshot: a snapshot that
    // contained its own SS blocks would self-reference, and after DR the recovered
    // node would try to maintain phantom SS records with no retained blob. Exclude
    // SS blocks and their placements via the SS ledger.
    let ss_ids = db.ss_block_id_set()?;
    let source_blocks: Vec<_> = db
        .list_all_source_blocks()?
        .into_iter()
        .filter(|b| !ss_ids.contains(&b.block_id.0))
        .collect();
    let symbol_placements: Vec<_> = db
        .list_all_placements()?
        .into_iter()
        .filter(|p| !ss_ids.contains(&p.source_block_id.0))
        .collect();
    let peers = db.list_all_peers()?;

    let pos_weekly = {
        let tx = db.inner.begin_read()?;
        let table = tx.open_table(POS_WEEKLY_LOCAL)?;
        let mut entries = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            entries.push(PosWeeklyEntry {
                key: k.value().to_vec(),
                value: v.value().to_vec(),
            });
        }
        entries
    };

    let cluster_state = db.get_cluster_state()?;

    let pair_ledgers = db
        .list_pair_ledgers()?
        .into_iter()
        .map(|(master, ledger)| PairLedgerEntry { master, ledger })
        .collect();

    let state = SystemState {
        version: SYSTEM_STATE_VERSION,
        created_at: Timestamp::now(),
        files,
        source_blocks,
        symbol_placements,
        peers,
        pos_weekly,
        cluster_state,
        pair_ledgers,
    };

    tracing::info!(
        files = state.files.len(),
        source_blocks = state.source_blocks.len(),
        placements = state.symbol_placements.len(),
        peers = state.peers.len(),
        pos_weekly = state.pos_weekly.len(),
        pair_ledgers = state.pair_ledgers.len(),
        "system state snapshot taken"
    );

    Ok(state)
}

// ============================================================
// restore_db / restore_db_force
// ============================================================

/// Populate an empty DB from a SystemState.
///
/// Checks that DB is empty (files AND peers both empty) before writing.
/// Returns DbNotEmpty if the check fails.
pub fn restore_db(db: &crate::db::Db, state: &SystemState) -> Result<(), SystemStateError> {
    if !db.list_all_files()?.is_empty() || !db.list_all_peers()?.is_empty() {
        return Err(SystemStateError::DbNotEmpty);
    }
    restore_db_inner(db, state)
}

/// Like restore_db but skips the empty-DB check.
///
/// Used when the node has already registered itself during DR boot.
///
/// **This overwrites, it does not merge.** Every row in `state` replaces the row with the
/// same key, and that now includes the `pair_ledger` accumulators: called against a
/// *running* node it would replace live, freshly-accrued integrals with whatever the blob
/// carried. Today the only non-test caller is the DR boot path, which runs on a database
/// file it just deleted and recreated, so nothing live can be clobbered. Any new caller
/// has to justify that same precondition.
pub fn restore_db_force(db: &crate::db::Db, state: &SystemState) -> Result<(), SystemStateError> {
    restore_db_inner(db, state)
}

/// Merge a peer record learned live (during DR) over the snapshot record of the same
/// device (dr-i18). `restore_db_force` overwrites peers with the snapshot, which may be
/// days old; what DR saw on the wire is fresher evidence of how to reach the peer.
///
/// The snapshot keeps the peer's history (trust p/i/s, byte counters, first_seen,
/// revoked keys, avail_ewma, last_avail_sample). Live wins where it is fresher:
///   addrs           = live addrs, then snapshot addrs not already present (order kept);
///   last_seen       = max(live, snapshot);
///   master_identity = live if non-zero, else snapshot;
///   x25519_pub      = live, else snapshot.
pub fn merge_live_peer(snapshot: &PeerRecord, live: &PeerRecord) -> PeerRecord {
    let mut merged = snapshot.clone();
    let mut addrs = live.addrs.clone();
    for a in &snapshot.addrs {
        if !addrs.contains(a) {
            addrs.push(a.clone());
        }
    }
    merged.addrs = addrs;
    merged.last_seen = snapshot.last_seen.max(live.last_seen);
    if live.master_identity.0 != [0u8; 32] {
        merged.master_identity = live.master_identity;
    }
    merged.x25519_pub = live.x25519_pub.or(snapshot.x25519_pub);
    merged
}

fn restore_db_inner(db: &crate::db::Db, state: &SystemState) -> Result<(), SystemStateError> {
    for record in &state.files {
        db.upsert_file(record)?;
    }

    for record in &state.source_blocks {
        db.upsert_source_block(record)?;
    }

    // upsert_placement rebuilds hot cache and indexes
    for record in &state.symbol_placements {
        db.upsert_placement(record)?;
    }

    for record in &state.peers {
        db.upsert_peer(record)?;
    }

    if !state.pos_weekly.is_empty() {
        let tx = db.inner.begin_write()?;
        {
            let mut table = tx.open_table(POS_WEEKLY_LOCAL)?;
            for entry in &state.pos_weekly {
                // Convert Vec<u8> key back to [u8; 36] required by the table.
                let key_arr: [u8; 36] = entry.key.as_slice().try_into().map_err(|_| {
                    SystemStateError::Cbor(format!(
                        "pos_weekly key must be 36 bytes, got {}",
                        entry.key.len()
                    ))
                })?;
                table.insert(&key_arr, entry.value.as_slice())?;
            }
        }
        tx.commit()?;
    }

    if let Some(cs) = &state.cluster_state {
        db.set_cluster_state(cs)?;
    }

    // The 4R recorder: months of gb·day integrals that cannot be recomputed from a
    // post-DR snapshot. Restored last because nothing else depends on it, and in ONE
    // write transaction (like pos_weekly above) — there is one row per known master, so
    // a transaction each would fsync per peer while rebuilding an invisible database.
    if !state.pair_ledgers.is_empty() {
        let rows: Vec<_> = state
            .pair_ledgers
            .iter()
            .map(|e| (e.master, e.ledger.clone()))
            .collect();
        db.upsert_pair_ledgers(&rows)?;
    }

    tracing::info!(
        files = state.files.len(),
        source_blocks = state.source_blocks.len(),
        placements = state.symbol_placements.len(),
        peers = state.peers.len(),
        pair_ledgers = state.pair_ledgers.len(),
        "system state restored to DB"
    );

    Ok(())
}

// ============================================================
// pack_system_state / unpack_system_state
// ============================================================

/// Serialize, compress, and encrypt a SystemState.
///
/// Steps:
///   1. CBOR-serialize → plaintext bytes
///   2. zstd compress (level 3)
///   3. Generate random 24-byte salt with OsRng
///   4. Derive 32-byte key via HKDF-SHA256(salt, identity_key)
///   5. Generate random 12-byte nonce
///   6. Encrypt with ChaCha20-Poly1305
///   7. Return: [salt(24)][nonce(12)][ciphertext+tag]
pub fn pack_system_state(
    state: &SystemState,
    identity_key: &[u8; 32],
) -> Result<Vec<u8>, SystemStateError> {
    let cbor_bytes = to_cbor_bytes(state);

    let compressed = zstd::encode_all(Cursor::new(&cbor_bytes), 3)
        .map_err(|e| SystemStateError::Compression(e.to_string()))?;

    let mut salt = [0u8; 24];
    OsRng.fill_bytes(&mut salt);

    let key = derive_system_state_key(identity_key, &salt);
    let cipher = ChaCha20Poly1305::new(&key.into());

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::Nonce::from(nonce_bytes);

    let mut buffer = compressed;
    cipher
        .encrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|e| SystemStateError::Encryption(e.to_string()))?;

    let mut blob = Vec::with_capacity(24 + 12 + buffer.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&buffer);

    tracing::info!(
        cbor_bytes = cbor_bytes.len(),
        blob_bytes = blob.len(),
        "system state packed"
    );

    Ok(blob)
}

/// Decrypt, decompress, and deserialize an encrypted system state blob.
///
/// Minimum blob length: 24 (salt) + 12 (nonce) + 16 (poly1305 tag) = 52 bytes.
pub fn unpack_system_state(
    blob: &[u8],
    identity_key: &[u8; 32],
) -> Result<SystemState, SystemStateError> {
    const MIN_BLOB_LEN: usize = 52; // salt(24) + nonce(12) + tag(16)

    if blob.len() < MIN_BLOB_LEN {
        return Err(SystemStateError::BlobTooShort {
            expected: MIN_BLOB_LEN,
            got: blob.len(),
        });
    }

    let salt: [u8; 24] = blob[..24].try_into().expect("slice is exactly 24 bytes");
    let nonce_bytes: [u8; 12] = blob[24..36].try_into().expect("slice is exactly 12 bytes");
    let ciphertext = &blob[36..];

    let key = derive_system_state_key(identity_key, &salt);
    let cipher = ChaCha20Poly1305::new(&key.into());
    let nonce = chacha20poly1305::Nonce::from(nonce_bytes);

    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|e| SystemStateError::Encryption(e.to_string()))?;

    let cbor_bytes = zstd::decode_all(Cursor::new(&buffer))
        .map_err(|e| SystemStateError::Decompression(e.to_string()))?;

    let state: SystemState = ciborium::de::from_reader(cbor_bytes.as_slice())
        .map_err(|e| SystemStateError::Cbor(e.to_string()))?;

    if state.version > SYSTEM_STATE_VERSION {
        return Err(SystemStateError::UnsupportedVersion {
            found: state.version,
            max: SYSTEM_STATE_VERSION,
        });
    }

    tracing::info!(
        version = state.version,
        files = state.files.len(),
        peers = state.peers.len(),
        "system state unpacked"
    );

    Ok(state)
}

// ============================================================
// Incremental diffs (base + diff blocks)
// ============================================================

/// One delta operation against a SystemState snapshot.
///
/// `Upserted` covers both add and modify (keyed insert-or-replace); `Deleted` removes by key.
/// Diffs are applied in order on top of a base snapshot to reconstruct a later state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum DiffOp {
    FileUpserted(FileRecord),
    FileDeleted(FileId),
    SourceBlockUpserted(SourceBlockRecord),
    SourceBlockDeleted(SourceBlockId),
    PlacementUpserted(SymbolPlacement),
    PlacementDeleted {
        source_block_id: SourceBlockId,
        holder_id: DeviceId,
    },
    PeerUpserted(PeerRecord),
    PeerDeleted(DeviceId),
    PosWeeklySet {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    PosWeeklyDeleted {
        key: Vec<u8>,
    },
    /// Cluster state is a singleton; carries the full new value (or None).
    ClusterStateSet(Option<StoredClusterState>),
}

/// Compute the ordered set of diff ops that transforms `old` into `new`.
///
/// Change detection compares CBOR-encoded records (the records do not derive `PartialEq`).
/// Output ops are: every key new-or-changed in `new` → `*Upserted`; every key removed → `*Deleted`.
///
/// **`pair_ledgers` is deliberately NOT diffed** (and has no [`DiffOp`] variant), because
/// the ledger is keyed per-master while diffed peer records are keyed per-device — there
/// is no per-device row for it to ride. It travels in the base snapshot only. Two other
/// justifications were written here at different times and BOTH were refuted against the
/// code ("a sibling's diff would overwrite my integrals"; "ledger churn would balloon this
/// stream") — see [`SystemState::pair_ledgers`] and [`crate::types::PairLedger`] for the
/// disproofs and for the bounded cost of base-only.
pub fn diff_states(old: &SystemState, new: &SystemState) -> Vec<DiffOp> {
    use std::collections::HashMap;
    let mut ops = Vec::new();

    // ── files (key = FileId) ──
    let old_files: HashMap<u64, &FileRecord> = old.files.iter().map(|f| (f.file_id.0, f)).collect();
    let new_files: HashMap<u64, &FileRecord> = new.files.iter().map(|f| (f.file_id.0, f)).collect();
    for f in &new.files {
        match old_files.get(&f.file_id.0) {
            Some(o) if to_cbor_bytes(*o) == to_cbor_bytes(f) => {}
            _ => ops.push(DiffOp::FileUpserted(f.clone())),
        }
    }
    for f in &old.files {
        if !new_files.contains_key(&f.file_id.0) {
            ops.push(DiffOp::FileDeleted(f.file_id));
        }
    }

    // ── source_blocks (key = SourceBlockId) ──
    let old_sb: HashMap<[u8; 32], &SourceBlockRecord> = old
        .source_blocks
        .iter()
        .map(|s| (s.block_id.0, s))
        .collect();
    let new_sb: HashMap<[u8; 32], &SourceBlockRecord> = new
        .source_blocks
        .iter()
        .map(|s| (s.block_id.0, s))
        .collect();
    for s in &new.source_blocks {
        match old_sb.get(&s.block_id.0) {
            Some(o) if to_cbor_bytes(*o) == to_cbor_bytes(s) => {}
            _ => ops.push(DiffOp::SourceBlockUpserted(s.clone())),
        }
    }
    for s in &old.source_blocks {
        if !new_sb.contains_key(&s.block_id.0) {
            ops.push(DiffOp::SourceBlockDeleted(s.block_id));
        }
    }

    // ── placements (key = (SourceBlockId, DeviceId)) ──
    let old_pl: HashMap<([u8; 32], [u8; 32]), &SymbolPlacement> = old
        .symbol_placements
        .iter()
        .map(|p| ((p.source_block_id.0, p.holder_id.0), p))
        .collect();
    let new_pl: HashMap<([u8; 32], [u8; 32]), &SymbolPlacement> = new
        .symbol_placements
        .iter()
        .map(|p| ((p.source_block_id.0, p.holder_id.0), p))
        .collect();
    for p in &new.symbol_placements {
        match old_pl.get(&(p.source_block_id.0, p.holder_id.0)) {
            Some(o) if to_cbor_bytes(*o) == to_cbor_bytes(p) => {}
            _ => ops.push(DiffOp::PlacementUpserted(p.clone())),
        }
    }
    for p in &old.symbol_placements {
        if !new_pl.contains_key(&(p.source_block_id.0, p.holder_id.0)) {
            ops.push(DiffOp::PlacementDeleted {
                source_block_id: p.source_block_id,
                holder_id: p.holder_id,
            });
        }
    }

    // ── peers (key = DeviceId) ──
    let old_peers: HashMap<[u8; 32], &PeerRecord> =
        old.peers.iter().map(|p| (p.device_id.0, p)).collect();
    let new_peers: HashMap<[u8; 32], &PeerRecord> =
        new.peers.iter().map(|p| (p.device_id.0, p)).collect();
    for p in &new.peers {
        match old_peers.get(&p.device_id.0) {
            Some(o) if to_cbor_bytes(*o) == to_cbor_bytes(p) => {}
            _ => ops.push(DiffOp::PeerUpserted(p.clone())),
        }
    }
    for p in &old.peers {
        if !new_peers.contains_key(&p.device_id.0) {
            ops.push(DiffOp::PeerDeleted(p.device_id));
        }
    }

    // ── pos_weekly (key = raw key bytes) ──
    let old_pw: HashMap<&[u8], &[u8]> = old
        .pos_weekly
        .iter()
        .map(|e| (e.key.as_slice(), e.value.as_slice()))
        .collect();
    let new_pw: HashMap<&[u8], &[u8]> = new
        .pos_weekly
        .iter()
        .map(|e| (e.key.as_slice(), e.value.as_slice()))
        .collect();
    for e in &new.pos_weekly {
        match old_pw.get(e.key.as_slice()) {
            Some(v) if *v == e.value.as_slice() => {}
            _ => ops.push(DiffOp::PosWeeklySet {
                key: e.key.clone(),
                value: e.value.clone(),
            }),
        }
    }
    for e in &old.pos_weekly {
        if !new_pw.contains_key(e.key.as_slice()) {
            ops.push(DiffOp::PosWeeklyDeleted { key: e.key.clone() });
        }
    }

    // ── cluster_state (singleton) ──
    if to_cbor_bytes(&old.cluster_state) != to_cbor_bytes(&new.cluster_state) {
        ops.push(DiffOp::ClusterStateSet(new.cluster_state.clone()));
    }

    ops
}

/// Reconstruct a SystemState by applying ordered diff batches on top of `base`.
///
/// Each batch is applied in sequence; within a batch, ops apply in order.
/// `version` and `created_at` are carried from `base`, NOT advanced to the latest diff.
/// So after a base+diffs restore, `state.created_at` is the *base's* creation time, not
/// "current as of" — do not treat it as freshness. The self-pointer carries the true
/// freshness (its own `created_at`, see `SelfPointer`).
pub fn apply_diffs(base: SystemState, diffs: &[Vec<DiffOp>]) -> SystemState {
    use std::collections::HashMap;

    let mut files: HashMap<u64, FileRecord> =
        base.files.into_iter().map(|f| (f.file_id.0, f)).collect();
    let mut blocks: HashMap<[u8; 32], SourceBlockRecord> = base
        .source_blocks
        .into_iter()
        .map(|s| (s.block_id.0, s))
        .collect();
    let mut placements: HashMap<([u8; 32], [u8; 32]), SymbolPlacement> = base
        .symbol_placements
        .into_iter()
        .map(|p| ((p.source_block_id.0, p.holder_id.0), p))
        .collect();
    let mut peers: HashMap<[u8; 32], PeerRecord> =
        base.peers.into_iter().map(|p| (p.device_id.0, p)).collect();
    let mut pos_weekly: HashMap<Vec<u8>, Vec<u8>> = base
        .pos_weekly
        .into_iter()
        .map(|e| (e.key, e.value))
        .collect();
    let mut cluster_state = base.cluster_state;
    // Carried through untouched: no DiffOp can change the ledger by design
    // (see SystemState::pair_ledgers), so the base's rows are the final answer.
    let pair_ledgers = base.pair_ledgers;

    for batch in diffs {
        for op in batch {
            match op {
                DiffOp::FileUpserted(f) => {
                    files.insert(f.file_id.0, f.clone());
                }
                DiffOp::FileDeleted(id) => {
                    files.remove(&id.0);
                }
                DiffOp::SourceBlockUpserted(s) => {
                    blocks.insert(s.block_id.0, s.clone());
                }
                DiffOp::SourceBlockDeleted(id) => {
                    blocks.remove(&id.0);
                }
                DiffOp::PlacementUpserted(p) => {
                    placements.insert((p.source_block_id.0, p.holder_id.0), p.clone());
                }
                DiffOp::PlacementDeleted {
                    source_block_id,
                    holder_id,
                } => {
                    placements.remove(&(source_block_id.0, holder_id.0));
                }
                DiffOp::PeerUpserted(p) => {
                    peers.insert(p.device_id.0, p.clone());
                }
                DiffOp::PeerDeleted(id) => {
                    peers.remove(&id.0);
                }
                DiffOp::PosWeeklySet { key, value } => {
                    pos_weekly.insert(key.clone(), value.clone());
                }
                DiffOp::PosWeeklyDeleted { key } => {
                    pos_weekly.remove(key);
                }
                DiffOp::ClusterStateSet(cs) => {
                    cluster_state = cs.clone();
                }
            }
        }
    }

    SystemState {
        version: base.version,
        created_at: base.created_at,
        files: files.into_values().collect(),
        source_blocks: blocks.into_values().collect(),
        symbol_placements: placements.into_values().collect(),
        peers: peers.into_values().collect(),
        pos_weekly: pos_weekly
            .into_iter()
            .map(|(key, value)| PosWeeklyEntry { key, value })
            .collect(),
        cluster_state,
        pair_ledgers,
    }
}

// ============================================================
// Self-pointer (addressable index of the latest SystemState blocks)
// ============================================================

/// Best-effort dialing hint for a holder of a SystemState block.
///
/// At disaster recovery `symbol_placements` is empty (only loaded after a successful
/// restore), so the self-pointer must carry holder identities directly — otherwise the
/// owner cannot find who stores the base/diff blocks (the DR circular-dependency, Bug-A).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HolderHint {
    pub holder_id: DeviceId,
    /// Last-known dialable multiaddrs (best-effort; may be empty — re-resolved via discovery).
    pub addrs: Vec<String>,
    /// ESI ranges this holder stores for the block, copied from the owner's
    /// `SymbolPlacement` at pointer-build time. DR has no `symbol_placements`
    /// yet (that's what it's recovering), so the ranges must travel inside the
    /// signed pointer to let DR reconstruct a fetch request (closes Bug-A).
    pub esi_ranges: Vec<(u32, u32)>,
}

/// Reference to one SystemState block plus the holders to fetch it from at DR.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BlockRef {
    pub block_id: SourceBlockId,
    pub holders: Vec<HolderHint>,
    /// Encrypted blob length. DR has no SourceBlockRecord (it's inside the state
    /// being recovered), so the size travels in the pointer: DR recomputes the
    /// exact `ErasureParams` via `ErasureParams::compute(encrypted_size, SS_IMPORTANCE)`
    /// and truncates the decoded buffer to this length before decrypt.
    pub encrypted_size: u64,
}

/// Signed, addressable index to the owner's latest SystemState.
///
/// Physically tiny (KB). Stored/transported separately from the (large) base+diff blocks.
/// Verified against the master identity derived from the mnemonic at DR; no master_pub is
/// embedded (the verifier already knows the expected identity, and omitting it binds
/// verification to that identity).
///
/// **Catalog history.** `catalog` (signed) names the history (DB) this pointer belongs
/// to, the device that published it and its live file count. Freshness decides only
/// INSIDE one history; between histories DR does not pick by time
/// (`catalog::select_catalog`).
///
/// **Freshness ordering inside a history:** `created_at` (wall clock at publish) primary,
/// `generation` only as a same-timestamp tiebreak. `generation` is NOT a reliable global
/// freshness key: the publisher holds it in RAM and it **resets to 1 on every owner restart**
/// (see `run_periodic_push`), so a post-restart pointer legitimately has a *lower* generation
/// than a pre-restart one. `created_at` keeps increasing across restarts and is the correct
/// "which is newer" signal. (Its one weakness — a backward wall-clock jump between two
/// publishes — is rare and bounded to one generation; persisting a monotonic generation would
/// remove it, tracked as future hardening.)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SelfPointer {
    pub generation: u32,
    pub base: BlockRef,
    pub diffs: Vec<BlockRef>,
    pub created_at: Timestamp,
    /// Which catalog this pointer restores (history, publisher, live files). Signed.
    pub catalog: CatalogSummary,
    #[serde(with = "crate::types::sig_serde")]
    pub signature: [u8; 64],
}

/// `-v2`: the payload gained `catalog` (spec B2). A `-v1` signature never verifies.
const SELF_POINTER_DOMAIN: &[u8] = b"viaticum-self-pointer-v2";

/// Canonical signing payload:
/// domain tag || CBOR((generation, base, diffs, created_at, catalog)).
fn self_pointer_payload(
    generation: u32,
    base: &BlockRef,
    diffs: &[BlockRef],
    created_at: Timestamp,
    catalog: &CatalogSummary,
) -> Vec<u8> {
    let mut payload = SELF_POINTER_DOMAIN.to_vec();
    payload.extend_from_slice(&to_cbor_bytes(&(
        generation, base, diffs, created_at, catalog,
    )));
    payload
}

/// Build and sign a SelfPointer with the master key.
pub fn sign_self_pointer(
    master_key: &ed25519_dalek::SigningKey,
    generation: u32,
    base: BlockRef,
    diffs: Vec<BlockRef>,
    created_at: Timestamp,
    catalog: CatalogSummary,
) -> SelfPointer {
    use ed25519_dalek::Signer;
    let payload = self_pointer_payload(generation, &base, &diffs, created_at, &catalog);
    let sig = master_key.sign(&payload);
    SelfPointer {
        generation,
        base,
        diffs,
        created_at,
        catalog,
        signature: sig.to_bytes(),
    }
}

/// Verify a SelfPointer against the expected master identity.
pub fn verify_self_pointer(
    pointer: &SelfPointer,
    expected_master: &IdentityPub,
) -> Result<(), SystemStateError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&expected_master.0)
        .map_err(|_| SystemStateError::InvalidSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&pointer.signature);
    let payload = self_pointer_payload(
        pointer.generation,
        &pointer.base,
        &pointer.diffs,
        pointer.created_at,
        &pointer.catalog,
    );
    verifying_key
        .verify_strict(&payload, &sig)
        .map_err(|_| SystemStateError::InvalidSignature)
}

#[cfg(test)]
mod tests;
