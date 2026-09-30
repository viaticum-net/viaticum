// Too-large source files (backup-i4): paths the daemon refused to back up because the file
// is larger than this machine's limit. One row per path, value = CBOR([`TooLargeMark`]).
//
// Node-local and deliberately OUTSIDE `system_state::snapshot_db` (which lists its tables
// explicitly). Why: after a DR the catalog holds only what was ever protected; a file that
// was never protected has no catalog record, and a protected one that grew is shown by its
// older version with that version's date. A mark says "THIS machine refuses THIS content
// at THIS limit" - it depends on the machine's RAM and config, so it must not travel to a
// machine with another limit (the start pass of the new node re-evaluates every path
// anyway). A database written before this table existed gains it empty
// (`create_tables` opens it on every `Db::open`).

use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use super::{Db, DbError};
use crate::types::{TooLargeMark, from_cbor_bytes, to_cbor_bytes};

/// Too-large marks. Key: source path. Value: CBOR([`TooLargeMark`]).
pub(super) const TOO_LARGE_SOURCES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("too_large_sources");

impl Db {
    /// Insert or replace the mark of `path`.
    pub fn put_too_large(&self, path: &str, mark: &TooLargeMark) -> Result<(), DbError> {
        let bytes = to_cbor_bytes(mark);
        let tx = self.inner.begin_write()?;
        {
            let mut table = tx.open_table(TOO_LARGE_SOURCES)?;
            table.insert(path, bytes.as_slice())?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The mark of `path`, if any.
    pub fn get_too_large(&self, path: &str) -> Result<Option<TooLargeMark>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(TOO_LARGE_SOURCES)?;
        match table.get(path)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Remove the mark of `path`. Returns whether a mark existed.
    pub fn remove_too_large(&self, path: &str) -> Result<bool, DbError> {
        let tx = self.inner.begin_write()?;
        let existed = {
            let mut table = tx.open_table(TOO_LARGE_SOURCES)?;
            table.remove(path)?.is_some()
        };
        tx.commit()?;
        Ok(existed)
    }

    /// All marks in path order.
    pub fn list_too_large(&self) -> Result<Vec<(String, TooLargeMark)>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(TOO_LARGE_SOURCES)?;
        let mut out = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            out.push((k.value().to_string(), from_cbor_bytes(v.value())?));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
