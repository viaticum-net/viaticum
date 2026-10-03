// A batch of peer updates in ONE write transaction (C-DK C4 fix round 3).
//
// The daemon's PeerRecord writer applies every authentication and identify that piled up
// while the previous commit was syncing as one transaction: the PeerRecord and the
// device-to-master mapping of an authentication land in the same commit, and a batch of
// many peers is one durable sync, not one (or two) per peer. Each redb commit is an fsync;
// under load that is 0.5-1 s, and one sync per event made a burst of 39 authentications
// take 73 s.
//
// A write that would store the bytes already stored is skipped, and a batch that wrote
// nothing is aborted, not committed: nothing to sync.

use redb::{ReadableTable, Table};

use super::{DEVICE_TO_MASTER, Db, DbError, PEERS};
use crate::types::{DeviceId, IdentityPub, PeerRecord, from_cbor_bytes, to_cbor_bytes};

#[cfg(test)]
mod tests;

type PeerTable<'t> = Table<'t, &'static [u8; 32], &'static [u8]>;

/// The peer tables (`peers`, `device_to_master`) inside one open write transaction; see
/// [`Db::update_peers`].
pub struct PeerBatch<'t> {
    peers: PeerTable<'t>,
    device_to_master: PeerTable<'t>,
    writes: usize,
}

impl PeerBatch<'_> {
    /// The PeerRecord of `device_id` as this transaction sees it (its own writes included).
    pub fn get(&self, device_id: &DeviceId) -> Result<Option<PeerRecord>, DbError> {
        match self.peers.get(&device_id.0)? {
            Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
            None => Ok(None),
        }
    }

    /// Store `record` under its `device_id`. Returns whether anything was written: a record
    /// whose encoding equals the stored one is not.
    pub fn put(&mut self, record: &PeerRecord) -> Result<bool, DbError> {
        let bytes = to_cbor_bytes(record);
        if put_if_changed(&mut self.peers, &record.device_id.0, &bytes)? {
            self.writes += 1;
            return Ok(true);
        }
        Ok(false)
    }

    /// The device-to-master mapping (as [`Db::set_master_for_device`]), in this transaction.
    /// Returns whether anything was written: the same mapping is not.
    pub fn set_master_for_device(
        &mut self,
        device: &DeviceId,
        master: &IdentityPub,
    ) -> Result<bool, DbError> {
        let bytes = to_cbor_bytes(master);
        if put_if_changed(&mut self.device_to_master, &device.0, &bytes)? {
            self.writes += 1;
            return Ok(true);
        }
        Ok(false)
    }

    /// How many rows this batch has written so far.
    pub fn writes(&self) -> usize {
        self.writes
    }
}

fn put_if_changed(
    table: &mut PeerTable<'_>,
    key: &[u8; 32],
    bytes: &[u8],
) -> Result<bool, DbError> {
    let same = match table.get(key)? {
        Some(v) => v.value() == bytes,
        None => false,
    };
    if same {
        return Ok(false);
    }
    table.insert(key, bytes)?;
    Ok(true)
}

impl Db {
    /// Run `f` over the peer tables in ONE write transaction and commit once: the batch
    /// form of [`Db::update_peer`] (C-DK C4 fix round 3). `f` reads the current rows through
    /// the [`PeerBatch`] (so a concurrent `update_peer`, e.g. a PeerAnnounce, is either fully
    /// before or fully after it: nothing is lost) and writes what changes. When `f` wrote
    /// nothing the transaction is aborted: no commit, no sync. An `Err` from `f` aborts too.
    ///
    /// Returns `f`'s value and whether a commit happened.
    pub fn update_peers<R>(
        &self,
        f: impl FnOnce(&mut PeerBatch<'_>) -> Result<R, DbError>,
    ) -> Result<(R, bool), DbError> {
        let tx = self.inner.begin_write()?;
        let (out, writes) = {
            let mut batch = PeerBatch {
                peers: tx.open_table(PEERS)?,
                device_to_master: tx.open_table(DEVICE_TO_MASTER)?,
                writes: 0,
            };
            let out = f(&mut batch);
            (out, batch.writes)
        };
        match out {
            Ok(value) if writes > 0 => {
                tx.commit()?;
                Ok((value, true))
            }
            Ok(value) => {
                tx.abort()?;
                Ok((value, false))
            }
            Err(e) => {
                tx.abort()?;
                Err(e)
            }
        }
    }
}
