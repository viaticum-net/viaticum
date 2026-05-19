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
use crate::types::{
    FileRecord, PeerRecord, SourceBlockRecord, SymbolPlacement, Timestamp, to_cbor_bytes,
};

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
/// Reads: files, source_blocks, symbol_placements, peers, pos_weekly, cluster_state.
/// Does NOT include: holdings (holder-specific), budget, event_log (secondary/ephemeral).
pub fn snapshot_db(db: &crate::db::Db) -> Result<SystemState, SystemStateError> {
    let files = db.list_all_files()?;
    let source_blocks = db.list_all_source_blocks()?;
    let symbol_placements = db.list_all_placements()?;
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

    let state = SystemState {
        version: SYSTEM_STATE_VERSION,
        created_at: Timestamp::now(),
        files,
        source_blocks,
        symbol_placements,
        peers,
        pos_weekly,
        cluster_state,
    };

    tracing::info!(
        files = state.files.len(),
        source_blocks = state.source_blocks.len(),
        placements = state.symbol_placements.len(),
        peers = state.peers.len(),
        pos_weekly = state.pos_weekly.len(),
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
pub fn restore_db_force(db: &crate::db::Db, state: &SystemState) -> Result<(), SystemStateError> {
    restore_db_inner(db, state)
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

    tracing::info!(
        files = state.files.len(),
        source_blocks = state.source_blocks.len(),
        placements = state.symbol_placements.len(),
        peers = state.peers.len(),
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

#[cfg(test)]
mod tests;
