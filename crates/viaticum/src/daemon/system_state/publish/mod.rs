// Owner-side production of SystemState-as-regular-blocks (W-E/W-F).
//
// A SystemState snapshot is turned into a *base* block (full state) and
// subsequent changes into *diff* blocks (`Vec<DiffOp>`). Each is an ordinary
// encrypted block — compress → encrypt(DR-stable key) → blake3 = block_id — that
// the generic work pipeline places, the scheduler PoS-challenges (W-D), and the
// repair agent repairs. The owner retains each blob so it can re-serve symbols
// (there is no backing watch-dir file).
//
// On top of the placed blocks the owner publishes a tiny signed SelfPointer
// (W-F) telling disaster recovery which blocks make up the latest state and who
// holds them. The pointer rides the existing SystemStateBackup blob field.

use std::path::Path;

use viaticum_core::db::Db;
use viaticum_core::system_state::{
    BlockRef, DiffOp, HolderHint, SelfPointer, SystemState, sign_self_pointer,
};
use viaticum_core::types::{
    PlacementStatus, SourceBlockId, Timestamp, ranges_to_esi_list, to_cbor_bytes,
};

use super::block;

#[cfg(test)]
mod tests;

/// Build, retain, and register a *base* SystemState block (full snapshot).
///
/// plaintext = CBOR(state); the block is encrypted with the DR-stable key so DR
/// (holding only the seed) can always decrypt. Returns the content-addressed
/// block_id. The upserted record carries MAX importance so the work pipeline
/// gives it the highest redundancy.
pub fn publish_base_block(
    db: &Db,
    data_dir: &Path,
    dr_key: &[u8; 32],
    state: &SystemState,
) -> anyhow::Result<SourceBlockId> {
    let plaintext = to_cbor_bytes(state);
    register_ss_block(db, data_dir, dr_key, &plaintext)
}

/// Build, retain, and register a *diff* SystemState block (`Vec<DiffOp>` delta).
pub fn publish_diff_block(
    db: &Db,
    data_dir: &Path,
    dr_key: &[u8; 32],
    diffs: &[DiffOp],
) -> anyhow::Result<SourceBlockId> {
    let plaintext = to_cbor_bytes(&diffs.to_vec());
    register_ss_block(db, data_dir, dr_key, &plaintext)
}

/// Shared: encrypt plaintext into an SS block, retain the blob, upsert the record.
fn register_ss_block(
    db: &Db,
    data_dir: &Path,
    dr_key: &[u8; 32],
    plaintext: &[u8],
) -> anyhow::Result<SourceBlockId> {
    let (block_id, blob) = block::build_state_block(plaintext, dr_key)?;
    block::store_retained_block(data_dir, &block_id, &blob)?;
    let record = block::ss_source_block_record(block_id, blob.len())?;
    db.upsert_source_block(&record)?;
    Ok(block_id)
}

/// Build a `BlockRef` for one SS block from its currently-Alive placements.
///
/// Holder hints carry `holder_id` + the holder's `esi_ranges` (so DR can build a
/// fetch request without symbol_placements) + best-effort dialable addrs from the
/// holder's PeerRecord. Blocks with no Alive placements yet yield an empty holder
/// list — the pointer is eventually-consistent as placement completes.
pub fn block_ref_from_placements(db: &Db, block_id: &SourceBlockId) -> anyhow::Result<BlockRef> {
    let placements = db.list_placements_for_block(block_id)?;
    let mut holders = Vec::new();
    for p in placements {
        if p.status != PlacementStatus::Alive {
            continue;
        }
        if ranges_to_esi_list(&p.esi_ranges).is_empty() {
            continue;
        }
        let addrs = db
            .get_peer(&p.holder_id)?
            .map(|peer| peer.addrs.clone())
            .unwrap_or_default();
        holders.push(HolderHint {
            holder_id: p.holder_id,
            addrs,
            esi_ranges: p.esi_ranges.clone(),
        });
    }
    Ok(BlockRef {
        block_id: *block_id,
        holders,
    })
}

/// Build and sign the SelfPointer over the current base + diff blocks (W-F).
#[allow(clippy::too_many_arguments)]
pub fn build_pointer(
    db: &Db,
    master_key: &ed25519_dalek::SigningKey,
    generation: u32,
    base_id: &SourceBlockId,
    diff_ids: &[SourceBlockId],
    created_at: Timestamp,
) -> anyhow::Result<SelfPointer> {
    let base = block_ref_from_placements(db, base_id)?;
    let mut diffs = Vec::with_capacity(diff_ids.len());
    for id in diff_ids {
        diffs.push(block_ref_from_placements(db, id)?);
    }
    Ok(sign_self_pointer(
        master_key, generation, base, diffs, created_at,
    ))
}
