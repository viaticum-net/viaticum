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

use viaticum_core::db::{Db, DbError};
use viaticum_core::system_state::{
    BlockRef, CatalogLineageId, CatalogSummary, DiffOp, HolderHint, SelfPointer, SystemState,
    sign_self_pointer,
};
use viaticum_core::trust::compute_combined;
use viaticum_core::types::{
    DeviceId, PlacementStatus, SourceBlockId, Timestamp, ranges_to_esi_list, to_cbor_bytes,
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
///
/// The record and its ledger mark are one transaction (backup-i28-c): an SS record outside
/// the ledger would pass for a user block (the worker's class, backup-i28) and escape the
/// sweep. A blob without a record (a failure after `store_retained_block`) is harmless.
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
    let mut txn = db.write_txn()?;
    txn.upsert_source_block(&record)?;
    txn.mark_ss_block(&block_id, generation)?;
    txn.commit()?;
    Ok(block_id)
}

/// Retire a superseded SS block: drop it from the ledger, delete its source-block
/// record + placements, and remove the retained blob. Best-effort — logs but does
/// not fail the publish.
///
/// The mark, the placements and the record go in one transaction (backup-i28-c): no
/// moment exists where the record is still Active but no longer in the ledger (it would
/// pass for a user block). If that transaction fails, nothing changed: the block stays in
/// the ledger and the next sweep retires it.
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
    if let Err(e) = drop_ss_block_rows(db, block_id) {
        tracing::warn!(block = %block_id, error = %e,
            "retire SS block: the transaction failed, nothing removed (the next sweep retries)");
        return;
    }
    if let Err(e) = block::remove_retained_block(data_dir, block_id) {
        tracing::warn!(block = %block_id, error = %e, "retire SS block: remove retained blob failed");
    }
}

/// The ledger mark, the placements and the record of an SS block, in one transaction
/// (backup-i28-c). The placements are read inside it, so an offer the worker wrote a moment
/// before is dropped too. Rows go with the retired block: its record goes in the same
/// transaction, so no ESI cursor of a live block loses a range (repair-i8).
fn drop_ss_block_rows(db: &Db, block_id: &SourceBlockId) -> Result<(), DbError> {
    let mut txn = db.write_txn()?;
    let placements = txn.placements_for_block(block_id)?;
    txn.unmark_ss_block(block_id)?;
    for p in &placements {
        txn.delete_placement(block_id, &p.holder_id)?;
    }
    txn.delete_source_block(block_id)?;
    txn.commit()
}

/// At most this many holder hints per block in a pointer (CROWN-1 V.3, AC-27′).
pub(crate) const POINTER_MAX_HOLDERS_PER_BLOCK: usize = 5;
/// At most this many addresses per holder hint.
pub(crate) const POINTER_MAX_ADDRS_PER_HINT: usize = 4;
/// Longer address strings are dropped from a hint (N2, V.15.7).
pub(crate) const POINTER_MAX_ADDR_LEN: usize = 256;

/// Build a `BlockRef` for one SS block from its currently-Alive placements.
///
/// Holder hints carry `holder_id` + the holder's `esi_ranges` (so DR can build a
/// fetch request without symbol_placements) + best-effort dialable addrs from the
/// holder's PeerRecord. Blocks with no Alive placements yet yield an empty holder
/// list — the pointer is eventually-consistent as placement completes.
///
/// Size bound by construction (CROWN-1 V.3, V.15.7): at most
/// `POINTER_MAX_HOLDERS_PER_BLOCK` holders (highest `combined_trust × avail_ewma`
/// first, ties by `holder_id`), each with at most `POINTER_MAX_ADDRS_PER_HINT`
/// addresses (public before private before loopback, as DR dials them), none longer
/// than `POINTER_MAX_ADDR_LEN` bytes. With ≤ 20 diffs the sealed pointer stays below
/// `MAX_SEALED_BODY_BYTES`.
pub fn block_ref_from_placements(db: &Db, block_id: &SourceBlockId) -> anyhow::Result<BlockRef> {
    let record = db
        .get_source_block(block_id)?
        .ok_or_else(|| anyhow::anyhow!("SS source block record missing: {block_id}"))?;
    let encrypted_size = record
        .encrypted_size
        .ok_or_else(|| anyhow::anyhow!("SS source block {block_id} has no encrypted_size"))?;
    let placements = db.list_placements_for_block(block_id)?;
    let mut scored: Vec<(f64, HolderHint)> = Vec::new();
    for p in placements {
        if p.status != PlacementStatus::Alive {
            continue;
        }
        if ranges_to_esi_list(&p.esi_ranges).is_empty() {
            continue;
        }
        let peer = db.get_peer(&p.holder_id)?;
        let score = peer
            .as_ref()
            .map(|r| compute_combined(r.trust_p, r.trust_i, r.trust_s) * r.avail_ewma)
            .unwrap_or(0.0);
        let addrs = peer.map(|r| hint_addrs(&r.addrs)).unwrap_or_default();
        scored.push((
            score,
            HolderHint {
                holder_id: p.holder_id,
                addrs,
                esi_ranges: p.esi_ranges.clone(),
            },
        ));
    }
    scored.sort_by(|(sa, a), (sb, b)| {
        sb.partial_cmp(sa)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.holder_id.0.cmp(&b.holder_id.0))
    });
    let holders = scored
        .into_iter()
        .take(POINTER_MAX_HOLDERS_PER_BLOCK)
        .map(|(_, h)| h)
        .collect();
    Ok(BlockRef {
        block_id: *block_id,
        holders,
        encrypted_size,
    })
}

/// The addresses a holder hint carries: strings longer than `POINTER_MAX_ADDR_LEN`
/// dropped, the rest in DR's dial order (unparsable last, input order kept inside a
/// rank), at most `POINTER_MAX_ADDRS_PER_HINT`.
pub(crate) fn hint_addrs(addrs: &[String]) -> Vec<String> {
    let mut ranked: Vec<(u8, &String)> = addrs
        .iter()
        .filter(|a| a.len() <= POINTER_MAX_ADDR_LEN)
        .map(|a| {
            let rank = a
                .parse::<libp2p::Multiaddr>()
                .map(|m| crate::daemon::dr::addr_rank(&m))
                .unwrap_or(u8::MAX);
            (rank, a)
        })
        .collect();
    ranked.sort_by_key(|(rank, _)| *rank);
    ranked
        .into_iter()
        .take(POINTER_MAX_ADDRS_PER_HINT)
        .map(|(_, a)| a.clone())
        .collect()
}

/// What a pointer says about the catalog it restores (spec B2): the history, the
/// publishing device, and the live file count after the base and after each diff.
#[derive(Debug, Clone, Copy)]
pub struct PointerCatalog<'a> {
    pub lineage: CatalogLineageId,
    pub publisher: DeviceId,
    /// `live_file_count` of the state after the base (index 0) and after each diff
    /// (index i+1 = after diff i). Invariant: `len == diff_ids.len() + 1`.
    pub files_after: &'a [u32],
}

impl PointerCatalog<'_> {
    /// The summary of a pointer that lists `diffs_listed` diffs.
    fn summary(&self, diffs_listed: usize) -> anyhow::Result<CatalogSummary> {
        let files = *self.files_after.get(diffs_listed).ok_or_else(|| {
            anyhow::anyhow!(
                "catalog file counts out of sync: {} entries for {} listed diffs",
                self.files_after.len(),
                diffs_listed
            )
        })?;
        Ok(CatalogSummary {
            lineage: self.lineage,
            publisher: self.publisher,
            files,
        })
    }
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
    catalog: PointerCatalog<'_>,
) -> anyhow::Result<SelfPointer> {
    let base = block_ref_from_placements(db, base_id)?;
    let mut diffs = Vec::with_capacity(diff_ids.len());
    for id in diff_ids {
        diffs.push(block_ref_from_placements(db, id)?);
    }
    let summary = catalog.summary(diffs.len())?;
    Ok(sign_self_pointer(
        master_key, generation, base, diffs, created_at, summary,
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
/// This keeps DR able to fetch everything the published pointer references. The
/// pointer's `catalog.files` is the live file count after exactly the listed prefix.
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
    catalog: PointerCatalog<'_>,
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
    let summary = catalog.summary(diffs.len())?;
    Ok(Some(sign_self_pointer(
        master_key, generation, base, diffs, created_at, summary,
    )))
}
