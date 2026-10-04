// Whether the owner keeps a block in service (L1b: backup-i21, P-C3), and the reads a
// write transaction needs to re-check it (INV-N1: the choice of a block generation and the
// worker's offers are re-checked inside the transaction that writes them).

use redb::ReadableTable;

use super::{Db, DbError, DbWriteTxn, SOURCE_BLOCKS, SYMBOL_PLACEMENTS, placement_range};
use crate::types::{
    PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus, SymbolPlacement,
    from_cbor_bytes,
};

#[cfg(test)]
mod tests;

/// Whether the owner keeps a block in service (backup-i21, P-C3). One rule for the dedup
/// gate, the generation choice, the reconcile, `is_safe_to_delete` and `effective_status`,
/// the root rule and the worker (INV-SVC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Serviceability {
    /// Record exists, status Active, no placement Deleting: a new reference is safe.
    Serviceable,
    /// Status Stale (the release window, L2): not a dedup target in L1b; L2 K-5 revives it.
    Window,
    /// Status Deleting / Deleted, or a placement Deleting: a Delete may be out for this id.
    Releasing,
    /// No record for this id.
    Missing,
}

impl Serviceability {
    pub fn is_serviceable(self) -> bool {
        matches!(self, Serviceability::Serviceable)
    }
}

/// The rule. Order: no record → Missing; Deleting/Deleted → Releasing; any placement
/// Deleting → Releasing; Stale → Window; Active → Serviceable.
pub fn serviceability_of(
    block: Option<&SourceBlockRecord>,
    placements: &[SymbolPlacement],
) -> Serviceability {
    let Some(block) = block else {
        return Serviceability::Missing;
    };
    if matches!(
        block.status,
        SourceBlockStatus::Deleting | SourceBlockStatus::Deleted
    ) {
        return Serviceability::Releasing;
    }
    if placements
        .iter()
        .any(|p| p.status == PlacementStatus::Deleting)
    {
        return Serviceability::Releasing;
    }
    match block.status {
        SourceBlockStatus::Stale => Serviceability::Window,
        _ => Serviceability::Serviceable,
    }
}

impl Db {
    /// [`serviceability_of`] over the committed record and placements of `block_id`.
    pub fn block_serviceability(
        &self,
        block_id: &SourceBlockId,
    ) -> Result<Serviceability, DbError> {
        let block = self.get_source_block(block_id)?;
        if block.is_none() {
            return Ok(Serviceability::Missing);
        }
        let placements = self.list_placements_for_block(block_id)?;
        Ok(serviceability_of(block.as_ref(), &placements))
    }
}

impl DbWriteTxn<'_> {
    /// The record of `block_id` inside this write transaction (sees its own uncommitted
    /// writes).
    pub fn get_source_block(
        &self,
        block_id: &SourceBlockId,
    ) -> Result<Option<SourceBlockRecord>, DbError> {
        let table = self.txn.open_table(SOURCE_BLOCKS)?;
        let value = table.get(&block_id.0)?;
        match value {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// The placements of `block_id` inside this write transaction.
    pub fn placements_for_block(
        &self,
        block_id: &SourceBlockId,
    ) -> Result<Vec<SymbolPlacement>, DbError> {
        let table = self.txn.open_table(SYMBOL_PLACEMENTS)?;
        let (lo, hi) = placement_range(block_id);
        let mut records = Vec::new();
        for item in table.range::<&[u8; 64]>(&lo..=&hi)? {
            let (_, v) = item?;
            records.push(from_cbor_bytes(v.value())?);
        }
        Ok(records)
    }

    /// [`serviceability_of`] inside this write transaction.
    pub fn block_serviceability(
        &self,
        block_id: &SourceBlockId,
    ) -> Result<Serviceability, DbError> {
        let block = self.get_source_block(block_id)?;
        if block.is_none() {
            return Ok(Serviceability::Missing);
        }
        let placements = self.placements_for_block(block_id)?;
        Ok(serviceability_of(block.as_ref(), &placements))
    }
}
