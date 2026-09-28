// 4R holder state (В-0, T5): singleton rows of this holder's 4R relay. Today one row — the
// latch `evict_phase` ([`FourRPhaseRecord`]).
//
// Written ONLY by the shadow pressure tick (on a change of `evicting`) and read only by the
// shadow; В-1a makes the same row authoritative. Node-local and deliberately OUTSIDE
// `system_state::snapshot_db` (which lists its tables explicitly): after a holder DR the row
// is absent and the latch starts released — consistent with the holdings, which do not
// travel either. A database written before this table existed gains it empty
// (`create_tables` opens it on every `Db::open`).

use redb::{ReadableDatabase, TableDefinition};

use super::{Db, DbError};
use crate::types::{FourRPhaseRecord, from_cbor_bytes, to_cbor_bytes};

/// 4R holder state (singleton rows). Deliberately outside `snapshot_db`.
pub(super) const FOUR_R_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("four_r_state");

/// Key of the relay latch row.
const KEY_EVICT_PHASE: &str = "evict_phase";

impl Db {
    /// The persisted 4R relay latch. Absent → default (released, `since = None`). A row that
    /// does not decode → `Err`: the caller (the shadow) logs it and skips its tick rather than
    /// silently restarting from "released".
    pub fn get_four_r_phase(&self) -> Result<FourRPhaseRecord, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(FOUR_R_STATE)?;
        match table.get(KEY_EVICT_PHASE)? {
            Some(v) => Ok(from_cbor_bytes(v.value())?),
            None => Ok(FourRPhaseRecord::default()),
        }
    }

    /// Replace the persisted 4R relay latch (one write transaction).
    pub fn set_four_r_phase(&self, rec: &FourRPhaseRecord) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(rec);
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(FOUR_R_STATE)?;
            table.insert(KEY_EVICT_PHASE, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Test hook: write raw bytes into the latch row (a corrupt row for DB-2 / the shadow's
    /// error path).
    #[cfg(any(test, feature = "testutil"))]
    pub fn put_raw_four_r_phase_for_test(&self, bytes: &[u8]) -> Result<(), DbError> {
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(FOUR_R_STATE)?;
            table.insert(KEY_EVICT_PHASE, bytes)?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
