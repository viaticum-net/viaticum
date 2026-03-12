#![allow(dead_code)]

use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use redb::{ReadableTable, TableDefinition};
use sha2::Sha256;
use std::io::Cursor;
use syncback_core::db::{Db, DbError};
use syncback_core::types::{
    from_cbor_bytes, FileRecord, PeerRecord, ShardRecord, Timestamp, UnitRecord,
};

use crate::daemon::crypto::{decrypt_ciphertext, encrypt_plaintext};

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
// Local table definitions (mirrors syncback-core, same name strings)
// ============================================================

const POS_WEEKLY_LOCAL: TableDefinition<&[u8; 36], &[u8]> = TableDefinition::new("pos_weekly");
const CONFIG_LOCAL: TableDefinition<&str, &[u8]> = TableDefinition::new("config");
const UNITS_LOCAL: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("units");

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

/// Serde helper for `[u8; 36]` — serde only auto-impls arrays up to 32 bytes.
mod key36 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 36], s: S) -> Result<S::Ok, S::Error> {
        bytes.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 36], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 36 bytes for pos_weekly key"))
    }
}

/// One entry from the `pos_weekly` table.
/// Key is stored alongside value because the week number is in the key, not the record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PosWeeklyEntry {
    /// Raw 36-byte key: [identity_pub(32) || week_number_be(4)]
    #[serde(with = "key36")]
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
    Db(#[from] DbError),

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

// Convenience conversions from raw redb error types used in snapshot_db / restore_db.
impl From<redb::TransactionError> for SystemStateError {
    fn from(e: redb::TransactionError) -> Self {
        SystemStateError::Db(DbError::from(e))
    }
}

impl From<redb::TableError> for SystemStateError {
    fn from(e: redb::TableError) -> Self {
        SystemStateError::Db(DbError::from(e))
    }
}

impl From<redb::StorageError> for SystemStateError {
    fn from(e: redb::StorageError) -> Self {
        SystemStateError::Db(DbError::from(e))
    }
}

impl From<redb::CommitError> for SystemStateError {
    fn from(e: redb::CommitError) -> Self {
        SystemStateError::Db(DbError::from(e))
    }
}

// ============================================================
// Key derivation
// ============================================================

fn derive_system_state_key(identity_key_bytes: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), identity_key_bytes);
    let mut key = [0u8; 32];
    hk.expand(SYSTEM_STATE_ENCRYPTION_INFO, &mut key)
        .expect("HKDF expand: 32-byte output always valid");
    key
}

// ============================================================
// Core functions
// ============================================================

/// Dump all critical DB tables into a SystemState struct.
///
/// Reads: files, units, shards, peers, pos_weekly, config.
/// Does NOT include: holding, budget, schedule, dirty_files, stale_units,
/// unverified_shards, escrow_restore_log (secondary indexes or holder-specific data).
pub fn snapshot_db(db: &Db) -> Result<SystemState, SystemStateError> {
    let files = db.list_all_files()?;

    let units = {
        let tx = db.inner.begin_read()?;
        let table = tx.open_table(UNITS_LOCAL)?;
        let mut records = Vec::new();
        for entry in table.iter()? {
            let (_, v) = entry?;
            let record: UnitRecord = from_cbor_bytes(v.value())
                .map_err(|e| SystemStateError::Cbor(e.to_string()))?;
            records.push(record);
        }
        records
    };

    let shards = db.list_all_shards()?;
    let peers = db.list_all_peers()?;

    let pos_weekly = {
        let tx = db.inner.begin_read()?;
        let table = tx.open_table(POS_WEEKLY_LOCAL)?;
        let mut entries = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            entries.push(PosWeeklyEntry {
                key: *k.value(),
                value: v.value().to_vec(),
            });
        }
        entries
    };

    let config = {
        let tx = db.inner.begin_read()?;
        let table = tx.open_table(CONFIG_LOCAL)?;
        let mut entries = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            entries.push(ConfigEntry {
                key: k.value().to_string(),
                value: v.value().to_vec(),
            });
        }
        entries
    };

    let state = SystemState {
        version: SYSTEM_STATE_VERSION,
        created_at: Timestamp::now(),
        files,
        units,
        shards,
        peers,
        pos_weekly,
        config,
    };

    tracing::info!(
        files = state.files.len(),
        peers = state.peers.len(),
        shards = state.shards.len(),
        "system state snapshot taken"
    );

    Ok(state)
}

/// Serialize, compress, and encrypt a SystemState.
///
/// Steps:
///   1. CBOR-serialize the SystemState → cbor_bytes
///   2. zstd compress cbor_bytes (level 3) → compressed_bytes
///   3. Generate random 24-byte salt with OsRng
///   4. Derive 32-byte encryption key via HKDF-SHA256
///   5. Encrypt compressed_bytes with ChaCha20-Poly1305
///   6. Output format: [salt(24)] [nonce(12)] [ciphertext + tag]
pub fn pack_system_state(
    state: &SystemState,
    identity_key_bytes: &[u8; 32],
) -> Result<Vec<u8>, SystemStateError> {
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(state, &mut cbor_bytes)
        .map_err(|e| SystemStateError::Cbor(e.to_string()))?;

    let compressed = zstd::encode_all(Cursor::new(&cbor_bytes), 3)
        .map_err(|e| SystemStateError::Compression(e.to_string()))?;

    let mut salt = [0u8; 24];
    OsRng.fill_bytes(&mut salt);

    let key = derive_system_state_key(identity_key_bytes, &salt);

    let encrypted = encrypt_plaintext(&key, &compressed)
        .map_err(|e| SystemStateError::Encryption(e.to_string()))?;

    let mut blob = Vec::with_capacity(24 + encrypted.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&encrypted);

    tracing::info!(
        raw_bytes = cbor_bytes.len(),
        compressed_bytes = compressed.len(),
        blob_bytes = blob.len(),
        "system state packed"
    );

    Ok(blob)
}

/// Decrypt, decompress, and deserialize an encrypted system state blob.
///
/// Minimum blob length: 24 (salt) + 12 (nonce) + 16 (min tag) = 52 bytes.
pub fn unpack_system_state(
    blob: &[u8],
    identity_key_bytes: &[u8; 32],
) -> Result<SystemState, SystemStateError> {
    const MIN_BLOB_LEN: usize = 52;
    if blob.len() < MIN_BLOB_LEN {
        return Err(SystemStateError::BlobTooShort {
            expected: MIN_BLOB_LEN,
            got: blob.len(),
        });
    }

    let salt: [u8; 24] = blob[0..24].try_into().expect("slice is exactly 24 bytes");
    let key = derive_system_state_key(identity_key_bytes, &salt);

    let compressed = decrypt_ciphertext(&key, &blob[24..])
        .map_err(|e| SystemStateError::Encryption(e.to_string()))?;

    let cbor_bytes = zstd::decode_all(Cursor::new(&compressed))
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

/// Populate an empty DB from a SystemState.
///
/// Checks that DB is empty (files + peers) before proceeding.
/// Writes files, units, shards, peers (via high-level methods that maintain indexes),
/// and pos_weekly + config (via raw DB access).
pub fn restore_db(db: &Db, state: &SystemState) -> Result<(), SystemStateError> {
    if !db.list_all_files()?.is_empty() || !db.list_all_peers()?.is_empty() {
        return Err(SystemStateError::DbNotEmpty);
    }

    for record in &state.files {
        db.upsert_file(record)?;
    }

    for record in &state.units {
        db.upsert_unit(record)?;
    }

    for record in &state.shards {
        db.upsert_shard(record)?;
    }

    for record in &state.peers {
        db.upsert_peer(record)?;
    }

    if !state.pos_weekly.is_empty() {
        let tx = db.inner.begin_write()?;
        {
            let mut table = tx.open_table(POS_WEEKLY_LOCAL)?;
            for entry in &state.pos_weekly {
                table.insert(&entry.key, entry.value.as_slice())?;
            }
        }
        tx.commit()?;
    }

    if !state.config.is_empty() {
        let tx = db.inner.begin_write()?;
        {
            let mut table = tx.open_table(CONFIG_LOCAL)?;
            for entry in &state.config {
                table.insert(entry.key.as_str(), entry.value.as_slice())?;
            }
        }
        tx.commit()?;
    }

    tracing::info!(
        files = state.files.len(),
        peers = state.peers.len(),
        shards = state.shards.len(),
        "system state restored to DB"
    );

    Ok(())
}

#[cfg(test)]
mod tests;
