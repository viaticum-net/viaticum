// N1 (backup-i8, delete-i9): which generation a packed plaintext is sealed at.
//
// The id of a block is blake3 of its sealed blob, and the seal is deterministic, so the same
// plaintext (a file returned to its path in a pack of one, a large file) gives the same id as
// the block being released — the id an old Delete, still replayed by postmen, addresses. The
// packing takes the lowest generation whose id is free (no record) or in service (the record
// is kept as it is); an id in the release window (`Stale`) or being released is skipped
// (INV-N1). The choice is read outside the write transaction (encryption holds no write lock)
// and re-checked inside it; a changed answer rolls back and chooses again (Р-4).

use viaticum_core::constants::MAX_BLOCK_GENERATIONS;
use viaticum_core::db::{Db, Serviceability};
use viaticum_core::types::{SourceBlockId, SourceBlockRecord};

use super::pipeline::seal_compressed;

/// A plaintext sealed at the generation the packing may write.
#[derive(Debug)]
pub(crate) struct Sealed {
    pub generation: u32,
    /// `[nonce][ciphertext]` at `generation`.
    pub stored: Vec<u8>,
    pub block_id: SourceBlockId,
    /// Generations passed over: their id exists and is not in service.
    pub skipped: Vec<(SourceBlockId, Serviceability)>,
}

/// The lowest generation below [`MAX_BLOCK_GENERATIONS`] whose id is `Missing` or
/// `Serviceable`; `Window` and `Releasing` ids are skipped. Past the limit → error (the
/// caller keeps the files queued, ERROR in the log).
pub(crate) fn choose_generation(
    db: &Db,
    compressed: &[u8],
    epoch_key: &[u8; 32],
) -> anyhow::Result<Sealed> {
    let mut skipped = Vec::new();
    for generation in 0..MAX_BLOCK_GENERATIONS {
        let stored = seal_compressed(compressed, epoch_key, generation)?;
        let block_id = SourceBlockId(*blake3::hash(&stored).as_bytes());
        match db.block_serviceability(&block_id)? {
            Serviceability::Missing | Serviceability::Serviceable => {
                return Ok(Sealed {
                    generation,
                    stored,
                    block_id,
                    skipped,
                });
            }
            s @ (Serviceability::Window | Serviceability::Releasing) => {
                skipped.push((block_id, s));
            }
        }
    }
    anyhow::bail!(
        "no free block generation below {MAX_BLOCK_GENERATIONS}: every id of this plaintext \
         is being released"
    )
}

/// The test seam's callback.
#[cfg(test)]
pub(crate) type CommitHook = Box<dyn FnMut(&Db, SourceBlockId)>;

#[cfg(test)]
thread_local! {
    /// Test seam between the choice and the write transaction (`run_pipeline`): simulates
    /// the deletion executor writing the chosen id meanwhile.
    pub(crate) static BEFORE_COMMIT: std::cell::RefCell<Option<CommitHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs the test seam, if one is set (no-op outside tests).
pub(crate) fn before_commit(_db: &Db, _block_id: SourceBlockId) {
    #[cfg(test)]
    BEFORE_COMMIT.with(|h| {
        if let Some(f) = h.borrow_mut().as_mut() {
            f(_db, _block_id);
        }
    });
}

/// What the write transaction found at the chosen id.
#[derive(Debug)]
pub(crate) enum Committed {
    /// The id was free: the new record is written.
    Written,
    /// The id is in service: its record is kept untouched (fields, placements, caches).
    Kept(SourceBlockRecord),
    /// The id left the answer the choice relied on (now in the window or being released).
    Changed(Serviceability),
}

/// Inside one write transaction: `record.block_id` still free → write `record`; in service
/// → keep the existing record; otherwise nothing is written (INV-N1).
pub(crate) fn commit_block_record(
    db: &Db,
    record: &SourceBlockRecord,
) -> anyhow::Result<Committed> {
    let mut txn = db.write_txn()?;
    let existing = txn.get_source_block(&record.block_id)?;
    let placements = txn.placements_for_block(&record.block_id)?;
    match viaticum_core::db::serviceability_of(existing.as_ref(), &placements) {
        Serviceability::Missing => {
            txn.upsert_source_block(record)?;
            txn.commit()?;
            Ok(Committed::Written)
        }
        Serviceability::Serviceable => Ok(Committed::Kept(
            existing.expect("a serviceable block has a record"),
        )),
        s @ (Serviceability::Window | Serviceability::Releasing) => Ok(Committed::Changed(s)),
    }
}
