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
// holds them. The pointer is carried by the mailbox bus (A2), not by any blob field.

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
    generation: u32,
    state: &SystemState,
) -> anyhow::Result<SourceBlockId> {
    let plaintext = to_cbor_bytes(state);
    register_ss_block(db, data_dir, dr_key, generation, &plaintext)
}

/// Build, retain, and register a *diff* SystemState block (`Vec<DiffOp>` delta).
pub fn publish_diff_block(
    db: &Db,
    data_dir: &Path,
    dr_key: &[u8; 32],
    generation: u32,
    diffs: &[DiffOp],
) -> anyhow::Result<SourceBlockId> {
    let plaintext = to_cbor_bytes(&diffs.to_vec());
    register_ss_block(db, data_dir, dr_key, generation, &plaintext)
}

/// Shared: encrypt plaintext into an SS block, retain the blob, upsert the record,
/// and record it in the SS ledger (so snapshot_db excludes it and retire can find it).
fn register_ss_block(
    db: &Db,
    data_dir: &Path,
    dr_key: &[u8; 32],
    generation: u32,
    plaintext: &[u8],
) -> anyhow::Result<SourceBlockId> {
    let (block_id, blob) = block::build_state_block(plaintext, dr_key)?;
    block::store_retained_block(data_dir, &block_id, &blob)?;
    let record = block::ss_source_block_record(block_id, blob.len())?;
    db.upsert_source_block(&record)?;
    db.mark_ss_block(&block_id, generation)?;
    Ok(block_id)
}

/// Retire a superseded SS block: drop it from the ledger, delete its source-block
/// record + placements, and remove the retained blob. Best-effort — logs but does
/// not fail the publish if individual steps error (the block simply ages out).
///
/// SAFETY GUARD: this deletes a source-block record + its placements, so it must only
/// ever touch SS blocks. It refuses to act on a block_id that is not in the SS ledger —
/// otherwise a caller mistake (or a content-address collision with a user block) could
/// silently destroy user data. A non-SS id here is a bug; log loudly and do nothing.
pub fn retire_ss_block(db: &Db, data_dir: &Path, block_id: &SourceBlockId) {
    match db.is_ss_block(block_id) {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!(block = %block_id,
                "retire SS block: refusing — block_id is NOT in the SS ledger (would delete non-SS data)");
            return;
        }
        Err(e) => {
            tracing::error!(block = %block_id, error = %e,
                "retire SS block: ledger check failed, refusing to delete");
            return;
        }
    }
    if let Err(e) = db.unmark_ss_block(block_id) {
        tracing::warn!(block = %block_id, error = %e, "retire SS block: unmark failed");
    }
    if let Ok(placements) = db.list_placements_for_block(block_id) {
        for p in placements {
            if let Err(e) = db.delete_placement(block_id, &p.holder_id) {
                tracing::warn!(block = %block_id, error = %e, "retire SS block: delete placement failed");
            }
        }
    }
    if let Err(e) = db.delete_source_block(block_id) {
        tracing::warn!(block = %block_id, error = %e, "retire SS block: delete record failed");
    }
    if let Err(e) = block::remove_retained_block(data_dir, block_id) {
        tracing::warn!(block = %block_id, error = %e, "retire SS block: remove retained blob failed");
    }
}

/// Build a `BlockRef` for one SS block from its currently-Alive placements.
///
/// Holder hints carry `holder_id` + the holder's `esi_ranges` (so DR can build a
/// fetch request without symbol_placements) + best-effort dialable addrs from the
/// holder's PeerRecord. Blocks with no Alive placements yet yield an empty holder
/// list — the pointer is eventually-consistent as placement completes.
pub fn block_ref_from_placements(db: &Db, block_id: &SourceBlockId) -> anyhow::Result<BlockRef> {
    let record = db
        .get_source_block(block_id)?
        .ok_or_else(|| anyhow::anyhow!("SS source block record missing: {block_id}"))?;
    let encrypted_size = record
        .encrypted_size
        .ok_or_else(|| anyhow::anyhow!("SS source block {block_id} has no encrypted_size"))?;
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
        encrypted_size,
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

/// Build a pointer that references ONLY the placed prefix of [base, diff_0, diff_1, …].
///
/// SS blocks place asynchronously, so a freshly-created block has no Alive holders
/// yet. A pointer referencing such a block would be unrecoverable at DR (no holder
/// to fetch from). This builds the longest consistent prefix where every referenced
/// block has ≥1 Alive holder:
///   - if the base has no holders yet → `Ok(None)` (nothing useful to advertise — the
///     caller skips publishing this tick; the base places within seconds);
///   - otherwise include diffs in order, stopping at the first one without holders
///     (the omitted tail becomes recoverable on a later tick once it places).
///
/// This keeps DR able to fetch everything the published pointer references.
///
/// # Guard correctness for SS base blocks (Bug-G / AC-7)
///
/// The recoverability threshold is `≥1 alive holder with non-empty ESI ranges`.
/// This is correct because SS base blocks are small (typically ≤ 10 KB), giving a
/// small `k_eff` (≈ 4 for ~1 KB). The placement solver (`solve_placement_for_target`
/// Phase-B DEEPEN) fills each opened holder up to `k_eff` symbols when k_eff is
/// small and holders are few — making every holder an independently decodable full
/// replica. A single alive holder therefore satisfies DR recoverability. See
/// `reliability::solve_placement_for_target` Phase-B comment: "with a small k_eff
/// it fills holders to k_eff, which is replicas".
#[allow(clippy::too_many_arguments)]
pub fn build_pointer_for_placed(
    db: &Db,
    master_key: &ed25519_dalek::SigningKey,
    generation: u32,
    base_id: &SourceBlockId,
    diff_ids: &[SourceBlockId],
    created_at: Timestamp,
) -> anyhow::Result<Option<SelfPointer>> {
    let base = block_ref_from_placements(db, base_id)?;
    if base.holders.is_empty() {
        return Ok(None);
    }
    let mut diffs = Vec::new();
    for id in diff_ids {
        let r = block_ref_from_placements(db, id)?;
        if r.holders.is_empty() {
            break;
        }
        diffs.push(r);
    }
    Ok(Some(sign_self_pointer(
        master_key, generation, base, diffs, created_at,
    )))
}
