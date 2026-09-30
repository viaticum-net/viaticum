// SystemState-as-regular-block primitives (mailbox-independent storage layer).
//
// A SystemState snapshot (base) or incremental delta (diff) is turned into an
// ordinary encrypted block (same recipe as a file block: compress → encrypt →
// blake3 = block_id), then placed/PoS-challenged/repaired by the generic pipeline.
//
// Because a snapshot has no backing watch-dir file to re-read, the owner RETAINS
// the block blob on disk under <data_dir>/system_state/<block_hex>.bin. The PoS
// re-encode path (scheduler::load_source_block_data) reads this retained blob;
// integrity is guaranteed by blake3(blob) == block_id (no separate source_hash).
//
// Key choice: SS blocks are encrypted with the DR-STABLE key
// (system_state::identity_key_bytes_from_seed, "viaticum-dr-key-v1"), NOT the
// rotating epoch_key — so disaster recovery (which has only the seed from the
// mnemonic) can always decrypt them regardless of epoch rotation.

use std::path::{Path, PathBuf};

use viaticum_core::types::{
    ErasureParams, SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType, Timestamp,
    hex_encode,
};

#[cfg(test)]
mod tests;

/// Directory holding retained SystemState block blobs.
pub fn retention_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(crate::daemon::identity::SYSTEM_STATE_DIR_NAME)
}

/// On-disk path for one retained SystemState block blob.
pub fn retained_block_path(data_dir: &Path, block_id: &SourceBlockId) -> PathBuf {
    retention_dir(data_dir).join(format!("{}.bin", hex_encode(&block_id.0)))
}

/// Build a SystemState block from plaintext: compress + encrypt, then derive the
/// content-addressed block_id. Deterministic (compress_and_encrypt uses a derived
/// nonce), so the same (plaintext, key) always yields the same block_id — required
/// for the PoS re-encode path to reproduce the exact blob.
pub fn build_state_block(
    plaintext: &[u8],
    key: &[u8; 32],
) -> anyhow::Result<(SourceBlockId, Vec<u8>)> {
    let blob = crate::daemon::backup::pipeline::compress_and_encrypt(plaintext, key)?;
    let block_id = SourceBlockId(*blake3::hash(&blob).as_bytes());
    Ok((block_id, blob))
}

/// Persist a SystemState block blob to the retention store.
///
/// Refuses to write if blake3(blob) != block_id (programming error / corruption guard).
pub fn store_retained_block(
    data_dir: &Path,
    block_id: &SourceBlockId,
    blob: &[u8],
) -> anyhow::Result<()> {
    let computed = blake3::hash(blob);
    if computed.as_bytes() != &block_id.0 {
        anyhow::bail!("refusing to retain SystemState block: blake3(blob) != block_id");
    }
    let dir = retention_dir(data_dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(retained_block_path(data_dir, block_id), blob)?;
    Ok(())
}

/// Read a retained SystemState block blob, verifying integrity (blake3 == block_id).
///
/// Returns an error (not a panic) on corruption so the PoS path can skip the block
/// and log loudly rather than serving a bad blob.
pub fn load_retained_block(data_dir: &Path, block_id: &SourceBlockId) -> anyhow::Result<Vec<u8>> {
    let blob = std::fs::read(retained_block_path(data_dir, block_id))?;
    let computed = blake3::hash(&blob);
    if computed.as_bytes() != &block_id.0 {
        anyhow::bail!("retained SystemState block {block_id} corrupted: blake3 mismatch");
    }
    Ok(blob)
}

/// Try to read a retained SystemState block blob.
///
/// Returns `Ok(None)` when no retained blob exists for `block_id` (so a caller
/// like the PoS re-encode path can fall through to the file-rebuild branch), and
/// `Err` when a blob exists but is corrupt (blake3 mismatch) — corruption must be
/// loud, never silently treated as "absent".
pub fn try_load_retained_block(
    data_dir: &Path,
    block_id: &SourceBlockId,
) -> anyhow::Result<Option<Vec<u8>>> {
    match std::fs::read(retained_block_path(data_dir, block_id)) {
        Ok(blob) => {
            let computed = blake3::hash(&blob);
            if computed.as_bytes() != &block_id.0 {
                anyhow::bail!("retained SystemState block {block_id} corrupted: blake3 mismatch");
            }
            Ok(Some(blob))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Remove a retained SystemState block blob (used after rotation/compaction).
/// Missing file is not an error.
pub fn remove_retained_block(data_dir: &Path, block_id: &SourceBlockId) -> anyhow::Result<()> {
    match std::fs::remove_file(retained_block_path(data_dir, block_id)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Importance assigned to SystemState blocks: maximum, so placement derives the
/// highest redundancy (overhead = 1.5 + 1.0*1.5 = 3.0) — "unusually high replication".
pub const SYSTEM_STATE_IMPORTANCE: f64 = 1.0;

/// Build the generic SourceBlockRecord for a SystemState block so the standard
/// placement / PoS / repair machinery treats it like any block — at MAX importance.
pub fn ss_source_block_record(
    block_id: SourceBlockId,
    blob_len: usize,
) -> anyhow::Result<SourceBlockRecord> {
    let params = ErasureParams::compute(blob_len as u64, SYSTEM_STATE_IMPORTANCE)
        .map_err(|e| anyhow::anyhow!("erasure params for SystemState block: {e}"))?;
    let target_rel = viaticum_core::reliability::target_reliability(SYSTEM_STATE_IMPORTANCE);
    Ok(SourceBlockRecord {
        seal_generation: 0,
        block_id,
        k: params.k,
        t: params.t,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp::now(),
        encrypted_size: Some(blob_len as u64),
        n: Some(params.n),
        overhead: Some(params.overhead),
        drop_notice_sent_at: None,
        importance: SYSTEM_STATE_IMPORTANCE,
        target_reliability: target_rel,
        current_alive: 0,
        current_reliability: 0.0,
    })
}
