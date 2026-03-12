//! Packer — owner-role file-to-shard pipeline.
//!
//! Converts dirty files into encrypted, erasure-coded units ready for
//! ShardManager to distribute. Also handles the reverse (restore) path.
//!
//! Not a tokio task: synchronous struct called from Processor.

use std::io::Read as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use syncback_core::budget::BackupCandidate;
use syncback_core::constants::ERASURE_K;
use syncback_core::db::Db;
use syncback_core::types::{
    ErasureTier, FileId, FileRecord, Timestamp, UnitId, UnitRecord, UnitStatus, UnitType,
};

use crate::daemon::crypto;
use crate::daemon::merkle;

#[cfg(test)]
mod tests;

// ============================================================
// Constants
// ============================================================

/// Default unit size: 256 MiB. Files smaller than this are packed together;
/// files >= this are split into chunks.
pub const DEFAULT_UNIT_SIZE_BYTES: u64 = 256 * 1024 * 1024;

const STALE_RATIO_THRESHOLD: f64 = 0.5;

// ============================================================
// Public types
// ============================================================

/// Output of packing one unit (pack or single chunk).
/// Passed to ShardManager::upload_unit and DB update.
#[derive(Debug)]
pub struct PackResult {
    /// Unit record ready to upsert into DB (status = Active).
    pub unit_record: UnitRecord,
    /// Plaintext bytes of the unit (before encryption).
    /// ShardManager re-encrypts with a fresh nonce.
    pub plaintext: Vec<u8>,
    /// Pre-computed shard IDs and merkle roots (for logging only — approximate).
    /// ShardManager will recompute authoritative values.
    pub shard_preview: Vec<ShardPreview>,
    /// File records for all member files.
    /// Processor calls db.mark_file_clean per file after successful upload.
    pub file_records: Vec<FileRecord>,
    /// Importance score for this unit (erasure tier + placement).
    pub importance: f64,
    /// Chunk metadata, None for pack units.
    pub chunk_info: Option<ChunkInfo>,
}

/// Metadata for chunk units (multi-chunk files).
#[derive(Debug, Clone)]
pub struct ChunkInfo {
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub parent_file_id: FileId,
}

/// Lightweight preview of one shard (approximate — for logging only).
#[derive(Debug, Clone)]
pub struct ShardPreview {
    pub shard_index: u8,
    pub shard_id: syncback_core::types::ShardId,
    pub merkle_root: [u8; 32],
}

/// Output of unpacking a unit (restore path).
#[derive(Debug)]
pub struct UnpackResult {
    /// For Pack units: one entry per member file.
    /// For Chunk units: single entry with path=None.
    pub files: Vec<UnpackedFile>,
}

#[derive(Debug)]
pub struct UnpackedFile {
    /// Original path from pack index. None for raw chunk units.
    pub path: Option<String>,
    pub bytes: Vec<u8>,
}

/// Pack file index — CBOR-serialized as the header of a Pack unit's plaintext.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackIndex {
    /// Version marker.
    pub version: u8,
    /// Members in concatenation order.
    pub members: Vec<PackMember>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackMember {
    /// Absolute path as UTF-8.
    pub path: String,
    /// FileId for DB cross-reference.
    pub file_id: u64,
    /// Byte offset of this file's content in the payload (after the index header).
    pub offset: u64,
    /// Length in bytes.
    pub length: u64,
    /// BLAKE3 hash of raw file content (integrity check on restore).
    pub content_hash: [u8; 32],
    /// Importance at time of packing.
    pub importance: f64,
}

// ============================================================
// Error
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum PackerError {
    #[error("file not found: {0}")]
    FileMissing(PathBuf),

    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("reed-solomon error: {0}")]
    ReedSolomon(String),

    #[error("not enough shards to decode: need {need}, have {have}")]
    NotEnoughShards { need: usize, have: usize },

    #[error("invalid pack index: {0}")]
    InvalidPackIndex(String),

    #[error("importance too low to back up (< 0.1): {0}")]
    ImportanceTooLow(f64),

    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),
}

impl From<crypto::CryptoError> for PackerError {
    fn from(e: crypto::CryptoError) -> Self {
        match e {
            crypto::CryptoError::Encryption(s) => PackerError::Encryption(s),
            crypto::CryptoError::ReedSolomon(s) => PackerError::ReedSolomon(s),
            crypto::CryptoError::NotEnoughShards { need, have } => {
                PackerError::NotEnoughShards { need, have }
            }
        }
    }
}

// ============================================================
// Packer
// ============================================================

pub struct Packer {
    db: Db,
    identity_key: ed25519_dalek::SigningKey,
    identity_pub: syncback_core::types::IdentityPub,
    /// Maximum size of one unit in bytes. Files >= this are chunked.
    unit_size_bytes: u64,
    /// Session counter for pack UnitId derivation. Resets on restart (that is fine).
    unit_counter: AtomicU64,
}

impl Packer {
    pub fn new(
        db: Db,
        identity_key: ed25519_dalek::SigningKey,
        identity_pub: syncback_core::types::IdentityPub,
        unit_size_bytes: u64,
    ) -> Self {
        Packer {
            db,
            identity_key,
            identity_pub,
            unit_size_bytes,
            unit_counter: AtomicU64::new(0),
        }
    }

    // -------------------------------------------------------------------------
    // Forward path: files → packed units
    // -------------------------------------------------------------------------

    /// Pack a batch of dirty files into units ready for upload.
    ///
    /// Groups small files into packs, splits large files into chunks.
    /// On partial failure (unreadable file): skip that file, continue.
    pub fn pack_batch(
        &self,
        candidates: &[BackupCandidate],
        now: Timestamp,
    ) -> Vec<PackResult> {
        // Separate small files from large files.
        let mut small_candidates: Vec<&BackupCandidate> = Vec::new();
        let mut large_candidates: Vec<&BackupCandidate> = Vec::new();

        for c in candidates {
            // Load file record to get size.
            match self.db.get_file(&c.path) {
                Ok(Some(rec)) => {
                    if rec.size_bytes >= self.unit_size_bytes {
                        large_candidates.push(c);
                    } else {
                        small_candidates.push(c);
                    }
                }
                Ok(None) => {
                    tracing::debug!(path = c.path, "pack_batch: file record missing, skipping");
                }
                Err(e) => {
                    tracing::debug!(path = c.path, err = %e, "pack_batch: db error reading file record, skipping");
                }
            }
        }

        let mut results: Vec<PackResult> = Vec::new();

        // ── Pack small files into groups ──
        let small_groups = self.group_small_files(&small_candidates);
        for group in small_groups {
            let records = self.load_file_records(&group);
            if records.is_empty() {
                continue;
            }
            let importance = group_importance(&records);
            match self.pack_unit(&records, importance, now) {
                Ok(r) => results.push(r),
                Err(PackerError::FileMissing(p)) => {
                    tracing::debug!(path = ?p, "pack_batch: file missing, skipping group");
                }
                Err(PackerError::Io { path, source }) => {
                    tracing::debug!(path = ?path, err = %source, "pack_batch: io error, skipping group");
                }
                Err(e) => panic!("pack_batch unexpected error: {e}"),
            }
        }

        // ── Chunk large files ──
        for c in &large_candidates {
            let rec = match self.db.get_file(&c.path) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    tracing::debug!(path = c.path, "pack_batch: large file record missing, skipping");
                    continue;
                }
                Err(e) => {
                    tracing::debug!(path = c.path, err = %e, "pack_batch: db error, skipping");
                    continue;
                }
            };
            match self.chunk_file(&rec, now) {
                Ok(chunks) => results.extend(chunks),
                Err(PackerError::FileMissing(p)) => {
                    tracing::debug!(path = ?p, "pack_batch: large file missing, skipping");
                }
                Err(PackerError::Io { path, source }) => {
                    tracing::debug!(path = ?path, err = %source, "pack_batch: io error on large file, skipping");
                }
                Err(e) => panic!("pack_batch unexpected error on large file: {e}"),
            }
        }

        results
    }

    /// Pack multiple small files into a single unit.
    pub fn pack_unit(
        &self,
        files: &[FileRecord],
        importance: f64,
        now: Timestamp,
    ) -> Result<PackResult, PackerError> {
        if ErasureTier::from_importance(importance).is_none() {
            return Err(PackerError::ImportanceTooLow(importance));
        }

        // 1. Read all file contents.
        let mut file_contents: Vec<Vec<u8>> = Vec::with_capacity(files.len());
        for f in files {
            let path = PathBuf::from(&f.path);
            if !path.exists() {
                return Err(PackerError::FileMissing(path));
            }
            let bytes = std::fs::read(&path).map_err(|source| PackerError::Io {
                path: path.clone(),
                source,
            })?;
            file_contents.push(bytes);
        }

        // 2. Build PackIndex.
        let mut offset: u64 = 0;
        let mut members: Vec<PackMember> = Vec::with_capacity(files.len());
        for (f, content) in files.iter().zip(file_contents.iter()) {
            let length = content.len() as u64;
            members.push(PackMember {
                path: f.path.clone(),
                file_id: f.file_id.0,
                offset,
                length,
                content_hash: f.content_hash,
                importance: f.importance,
            });
            offset += length;
        }
        let index = PackIndex { version: 1, members };

        // 3. Serialize: [u32 LE: index_len][CBOR(PackIndex)][file0][file1]...
        let mut index_bytes: Vec<u8> = Vec::new();
        ciborium::ser::into_writer(&index, &mut index_bytes)
            .expect("PackIndex CBOR serialization: infallible");
        let index_len = index_bytes.len() as u32;

        let total_file_bytes: usize = file_contents.iter().map(|c| c.len()).sum();
        let mut plaintext =
            Vec::with_capacity(4 + index_bytes.len() + total_file_bytes);
        plaintext.extend_from_slice(&index_len.to_le_bytes());
        plaintext.extend_from_slice(&index_bytes);
        for content in &file_contents {
            plaintext.extend_from_slice(content);
        }

        // 4. Derive UnitId.
        let unit_id = self.next_pack_unit_id();

        // 5. Compute shard_preview (approximate, different nonce than ShardManager will use).
        let tier = ErasureTier::from_importance(importance).expect("importance checked above");
        let k = ERASURE_K as usize;
        let n = tier.n_base();
        let shard_preview = self.compute_shard_preview(unit_id, &plaintext, k, n);

        // 6. Build UnitRecord.
        let plaintext_hash = *blake3::hash(&plaintext).as_bytes();
        let unit_record = UnitRecord {
            unit_id,
            unit_type: UnitType::Pack,
            status: UnitStatus::Active,
            member_file_ids: files.iter().map(|f| f.file_id).collect(),
            chunk_index: None,
            parent_file_id: None,
            size_bytes: plaintext.len() as u64,
            plaintext_hash,
            created_at: now,
            importance_avg: importance,
            rs_k: ERASURE_K as u8,
            rs_n: n as u8,
        };

        tracing::debug!(
            unit_id = %unit_id,
            files = files.len(),
            size = plaintext.len(),
            importance,
            "pack_unit: created"
        );

        Ok(PackResult {
            unit_record,
            plaintext,
            shard_preview,
            file_records: files.to_vec(),
            importance,
            chunk_info: None,
        })
    }

    /// Split a single large file into chunk units.
    ///
    /// Reads in unit_size_bytes chunks to avoid loading entire large file into memory.
    pub fn chunk_file(
        &self,
        file: &FileRecord,
        now: Timestamp,
    ) -> Result<Vec<PackResult>, PackerError> {
        let path = PathBuf::from(&file.path);
        if !path.exists() {
            return Err(PackerError::FileMissing(path.clone()));
        }

        let importance = file.importance;
        let tier = ErasureTier::from_importance(importance)
            .ok_or(PackerError::ImportanceTooLow(importance))?;
        let k = ERASURE_K as usize;
        let n = tier.n_base();

        let mut handle = std::fs::File::open(&path).map_err(|source| PackerError::Io {
            path: path.clone(),
            source,
        })?;

        // Compute total chunk count from file metadata.
        let file_size = handle
            .metadata()
            .map_err(|source| PackerError::Io { path: path.clone(), source })?
            .len();
        let total_chunks =
            (file_size.div_ceil(self.unit_size_bytes)).max(1) as u32;

        let mut buf = vec![0u8; self.unit_size_bytes as usize];
        let mut chunk_index: u32 = 0;
        let mut results: Vec<PackResult> = Vec::new();

        loop {
            let bytes_read = handle.read(&mut buf).map_err(|source| PackerError::Io {
                path: path.clone(),
                source,
            })?;
            if bytes_read == 0 {
                break;
            }
            let chunk_bytes = buf[..bytes_read].to_vec();

            // Derive UnitId from content_hash + chunk_index (stable across identical content).
            let unit_id = derive_chunk_unit_id(&file.content_hash, chunk_index);

            // Compute shard_preview.
            let shard_preview =
                self.compute_shard_preview(unit_id, &chunk_bytes, k, n);

            let plaintext_hash = *blake3::hash(&chunk_bytes).as_bytes();
            let unit_record = UnitRecord {
                unit_id,
                unit_type: UnitType::Chunk,
                status: UnitStatus::Active,
                member_file_ids: vec![file.file_id],
                chunk_index: Some(chunk_index),
                parent_file_id: Some(file.file_id),
                size_bytes: chunk_bytes.len() as u64,
                plaintext_hash,
                created_at: now,
                importance_avg: importance,
                rs_k: ERASURE_K as u8,
                rs_n: n as u8,
            };

            tracing::debug!(
                unit_id = %unit_id,
                chunk_index,
                total_chunks,
                size = chunk_bytes.len(),
                "chunk_file: chunk created"
            );

            results.push(PackResult {
                unit_record,
                plaintext: chunk_bytes,
                shard_preview,
                file_records: vec![file.clone()],
                importance,
                chunk_info: Some(ChunkInfo {
                    chunk_index,
                    total_chunks,
                    parent_file_id: file.file_id,
                }),
            });
            chunk_index += 1;
        }

        // Edge case: empty file → produce one empty chunk.
        if results.is_empty() {
            let chunk_bytes = Vec::new();
            let unit_id = derive_chunk_unit_id(&file.content_hash, 0);
            let shard_preview = self.compute_shard_preview(unit_id, &chunk_bytes, k, n);
            let plaintext_hash = *blake3::hash(&chunk_bytes).as_bytes();
            let unit_record = UnitRecord {
                unit_id,
                unit_type: UnitType::Chunk,
                status: UnitStatus::Active,
                member_file_ids: vec![file.file_id],
                chunk_index: Some(0),
                parent_file_id: Some(file.file_id),
                size_bytes: 0,
                plaintext_hash,
                created_at: now,
                importance_avg: importance,
                rs_k: ERASURE_K as u8,
                rs_n: n as u8,
            };
            results.push(PackResult {
                unit_record,
                plaintext: chunk_bytes,
                shard_preview,
                file_records: vec![file.clone()],
                importance,
                chunk_info: Some(ChunkInfo {
                    chunk_index: 0,
                    total_chunks: 1,
                    parent_file_id: file.file_id,
                }),
            });
        }

        Ok(results)
    }

    // -------------------------------------------------------------------------
    // Reverse path: shards → files (restore)
    // -------------------------------------------------------------------------

    /// Decrypt and unpack files from k shard blobs.
    ///
    /// RS decode → decrypt → parse PackIndex (for Pack units) → return files.
    /// For Chunk units: returns a single entry with path=None.
    pub fn unpack_unit(
        &self,
        unit_id: UnitId,
        unit_type: UnitType,
        shard_blobs: Vec<Option<Vec<u8>>>,
        k: usize,
        n: usize,
    ) -> Result<UnpackResult, PackerError> {
        // 1. RS decode.
        let ciphertext = crypto::rs_decode(shard_blobs, k, n)?;

        // 2. Decrypt.
        let ikm: [u8; 32] = self.identity_key.to_bytes();
        let enc_key = crypto::derive_unit_key(&ikm, unit_id);
        let plaintext = crypto::decrypt_ciphertext(&enc_key, &ciphertext)?;

        // 3. Unpack based on unit type.
        match unit_type {
            UnitType::Pack => {
                let files = unpack_pack_plaintext(&plaintext)?;
                Ok(UnpackResult { files })
            }
            UnitType::Chunk => {
                // Chunk plaintext is raw bytes.
                Ok(UnpackResult {
                    files: vec![UnpackedFile {
                        path: None,
                        bytes: plaintext,
                    }],
                })
            }
        }
    }

    // -------------------------------------------------------------------------
    // Vacuum support
    // -------------------------------------------------------------------------

    /// Repack stale units: re-pack live member files into fresh units.
    ///
    /// "Live" means the file's current_unit_id still points to this stale unit.
    /// Repacks only if stale ratio >= 0.5.
    pub fn vacuum_stale_units(
        &self,
        stale_unit_ids: &[UnitId],
        now: Timestamp,
    ) -> Result<Vec<PackResult>, PackerError> {
        let mut results: Vec<PackResult> = Vec::new();

        for &unit_id in stale_unit_ids {
            let unit = match self.db.get_unit(&unit_id)? {
                Some(u) => u,
                None => {
                    tracing::debug!(unit_id = %unit_id, "vacuum: unit not found, skipping");
                    continue;
                }
            };

            // Collect live members (files whose current_unit_id == this unit).
            let mut live_records: Vec<FileRecord> = Vec::new();
            for &file_id in &unit.member_file_ids {
                let file = match self.db.get_file_by_id(file_id)? {
                    Some(f) => f,
                    None => continue,
                };
                if file.current_unit_id == Some(unit_id) {
                    live_records.push(file);
                }
            }

            let total = unit.member_file_ids.len();
            let live_count = live_records.len();
            if total == 0 {
                continue;
            }
            let stale_ratio = (total - live_count) as f64 / total as f64;
            if stale_ratio < STALE_RATIO_THRESHOLD {
                tracing::debug!(
                    unit_id = %unit_id,
                    stale_ratio,
                    "vacuum: stale ratio below threshold, skipping"
                );
                continue;
            }

            if live_records.is_empty() {
                tracing::debug!(unit_id = %unit_id, "vacuum: no live members, skipping");
                continue;
            }

            let importance = group_importance(&live_records);
            match self.pack_unit(&live_records, importance, now) {
                Ok(r) => {
                    tracing::debug!(
                        old_unit_id = %unit_id,
                        new_unit_id = %r.unit_record.unit_id,
                        live = live_count,
                        "vacuum: repacked stale unit"
                    );
                    results.push(r);
                }
                Err(PackerError::FileMissing(p)) => {
                    tracing::debug!(path = ?p, "vacuum: file missing during repack, skipping");
                }
                Err(PackerError::Io { path, source }) => {
                    tracing::debug!(
                        path = ?path,
                        err = %source,
                        "vacuum: io error during repack, skipping"
                    );
                }
                Err(e) => return Err(e),
            }
        }

        Ok(results)
    }

    // -------------------------------------------------------------------------
    // Internal helpers (pub(crate) for tests)
    // -------------------------------------------------------------------------

    /// Derive the 32-byte encryption key for a unit.
    /// HKDF-SHA256(identity_priv, salt=unit_id, info="syncback-file-encryption")
    pub(crate) fn derive_unit_key(&self, unit_id: UnitId) -> [u8; 32] {
        let ikm: [u8; 32] = self.identity_key.to_bytes();
        crypto::derive_unit_key(&ikm, unit_id)
    }

    /// Allocate the next pack UnitId using the session counter.
    fn next_pack_unit_id(&self) -> UnitId {
        let counter = self.unit_counter.fetch_add(1, Ordering::Relaxed);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.identity_pub.0);
        hasher.update(&[0x01u8]); // type discriminant: pack
        hasher.update(&counter.to_le_bytes());
        UnitId(*hasher.finalize().as_bytes())
    }

    /// Compute shard_preview by doing a preview encryption + RS encode.
    ///
    /// NOTE: these shard IDs are approximate and will differ from final IDs
    /// (ShardManager uses a different random nonce). For logging only.
    fn compute_shard_preview(
        &self,
        unit_id: UnitId,
        plaintext: &[u8],
        k: usize,
        n: usize,
    ) -> Vec<ShardPreview> {
        let ikm: [u8; 32] = self.identity_key.to_bytes();
        let key = crypto::derive_unit_key(&ikm, unit_id);
        let ciphertext = match crypto::encrypt_plaintext(&key, plaintext) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let shards = match crypto::rs_encode(&ciphertext, k, n) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        shards
            .into_iter()
            .enumerate()
            .map(|(i, shard_bytes)| {
                let shard_id =
                    syncback_core::types::ShardId(*blake3::hash(&shard_bytes).as_bytes());
                let root = merkle::merkle_root(&shard_bytes);
                ShardPreview {
                    shard_index: i as u8,
                    shard_id,
                    merkle_root: root,
                }
            })
            .collect()
    }

    /// Group small file candidates into packs of at most unit_size_bytes.
    ///
    /// Candidates already have file size available via the DB record.
    fn group_small_files<'a>(
        &self,
        candidates: &[&'a BackupCandidate],
    ) -> Vec<Vec<&'a BackupCandidate>> {
        let mut groups: Vec<Vec<&BackupCandidate>> = Vec::new();
        let mut current: Vec<&BackupCandidate> = Vec::new();
        let mut current_size: u64 = 0;

        for c in candidates {
            // Look up the actual file size.
            let size = match self.db.get_file(&c.path) {
                Ok(Some(r)) => r.size_bytes,
                _ => 0,
            };
            if !current.is_empty() && current_size + size > self.unit_size_bytes {
                // Flush current group.
                groups.push(std::mem::take(&mut current));
                current_size = 0;
            }
            current.push(c);
            current_size += size;
        }
        if !current.is_empty() {
            groups.push(current);
        }
        groups
    }

    /// Load FileRecord for each candidate in a group.
    fn load_file_records(&self, group: &[&BackupCandidate]) -> Vec<FileRecord> {
        let mut records = Vec::new();
        for c in group {
            match self.db.get_file(&c.path) {
                Ok(Some(r)) => records.push(r),
                Ok(None) => {
                    tracing::debug!(path = c.path, "pack_batch: file record gone, skipping");
                }
                Err(e) => {
                    tracing::debug!(path = c.path, err = %e, "pack_batch: db error, skipping");
                }
            }
        }
        records
    }
}

// ============================================================
// Free helpers
// ============================================================

/// Derive UnitId for a chunk: blake3(content_hash || chunk_index_le_u32).
pub(crate) fn derive_chunk_unit_id(content_hash: &[u8; 32], chunk_index: u32) -> UnitId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(content_hash);
    hasher.update(&chunk_index.to_le_bytes());
    UnitId(*hasher.finalize().as_bytes())
}

/// Average importance of a set of file records.
fn group_importance(records: &[FileRecord]) -> f64 {
    if records.is_empty() {
        return 0.0;
    }
    records.iter().map(|r| r.importance).sum::<f64>() / records.len() as f64
}

/// Parse a Pack unit's plaintext and return UnpackedFile entries.
///
/// Format: [u32 LE: index_len][CBOR(PackIndex)][file0][file1]...
pub(crate) fn unpack_pack_plaintext(plaintext: &[u8]) -> Result<Vec<UnpackedFile>, PackerError> {
    if plaintext.len() < 4 {
        return Err(PackerError::InvalidPackIndex(
            "plaintext too short for index length prefix".into(),
        ));
    }
    let index_len = u32::from_le_bytes(
        plaintext[..4]
            .try_into()
            .expect("slice is exactly 4 bytes"),
    ) as usize;

    if plaintext.len() < 4 + index_len {
        return Err(PackerError::InvalidPackIndex(format!(
            "plaintext too short: expected {} + {} = {} bytes, got {}",
            4,
            index_len,
            4 + index_len,
            plaintext.len()
        )));
    }

    let index_bytes = &plaintext[4..4 + index_len];
    let index: PackIndex = ciborium::de::from_reader(index_bytes)
        .map_err(|e| PackerError::InvalidPackIndex(e.to_string()))?;

    let payload = &plaintext[4 + index_len..];
    let mut files: Vec<UnpackedFile> = Vec::with_capacity(index.members.len());

    for member in &index.members {
        let start = member.offset as usize;
        let end = start + member.length as usize;
        if end > payload.len() {
            return Err(PackerError::InvalidPackIndex(format!(
                "member '{}': end offset {} exceeds payload length {}",
                member.path,
                end,
                payload.len()
            )));
        }
        let file_bytes = payload[start..end].to_vec();

        // Integrity check (log only — partial restore > no restore).
        let actual_hash = *blake3::hash(&file_bytes).as_bytes();
        if actual_hash != member.content_hash {
            tracing::error!(
                path = member.path,
                "unpack: content hash mismatch — possible corruption"
            );
        }

        files.push(UnpackedFile {
            path: Some(member.path.clone()),
            bytes: file_bytes,
        });
    }

    Ok(files)
}

