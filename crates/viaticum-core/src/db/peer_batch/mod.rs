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
//
// Revocation (C-DK C4 fix round 4, N1). The daemon admits an authentication (revocation
// check) before it queues it; the record is written a batch later. A revocation committed
// in between must still win, so the batch can ask [`PeerBatch::is_device_revoked`] inside
// its own transaction: both revocation lists are rows (the PeerRecord's
// `revoked_device_pub_keys`, the cluster state's `revoked_devices`), and a revocation is a
// write transaction too, so it is either wholly before the batch (seen) or wholly after it.

use redb::{ReadableTable, Table};

use super::{CLUSTER_STATE, DEVICE_TO_MASTER, Db, DbError, PEERS};
use crate::cluster::StoredClusterState;
use crate::types::{DeviceId, IdentityPub, PeerRecord, from_cbor_bytes, to_cbor_bytes};

#[cfg(test)]
mod tests;

type PeerTable<'t> = Table<'t, &'static [u8; 32], &'static [u8]>;

/// The peer tables (`peers`, `device_to_master`) inside one open write transaction; see
/// [`Db::update_peers`].
pub struct PeerBatch<'t> {
    peers: PeerTable<'t>,
    device_to_master: PeerTable<'t>,
    /// The cluster state's revoked devices as of this transaction (read when it began).
    cluster_revoked: Vec<DeviceId>,
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

    /// Is `device_id` revoked as this transaction sees it? The same two lists the daemon's
    /// admission checks (`Processor::admit_authenticated`): the cluster state's
    /// `revoked_devices` and the device's own PeerRecord `revoked_device_pub_keys` (a
    /// signed revocation of its master).
    pub fn is_device_revoked(&self, device_id: &DeviceId) -> Result<bool, DbError> {
        if self.cluster_revoked.contains(device_id) {
            return Ok(true);
        }
        Ok(self
            .get(device_id)?
            .is_some_and(|r| r.is_device_revoked(device_id)))
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
    /// the [`PeerBatch`] and writes what changes. When `f` wrote nothing the transaction is
    /// aborted: no commit, no sync. An `Err` from `f` aborts too.
    ///
    /// Against [`Db::update_peer`] (e.g. a PeerAnnounce) nothing is lost: that is one write
    /// transaction too, read-modify-write inside it, so it is wholly before or wholly after
    /// the batch. NOT against a writer that reads with [`Db::get_peer`] and writes back with
    /// [`Db::upsert_peer`] in two transactions: if the batch commits between its read and its
    /// write, the write-back restores the record as it was before the batch (addresses,
    /// `last_seen`, the contact count lost). The daemon has no such writer since 2026-10-05
    /// (line B): `record_avail_contact`, `persist_holder_addrs_to_db`, `recalculate_trust`,
    /// [`Db::refresh_peer_storage_bytes`], `RevocationHandler::apply`, the trust_p
    /// migration at start and DR's peer writes all go through [`Db::update_peer`]; the
    /// avail decay passes over every peer read the records inside their write transaction.
    /// [`Db::upsert_peer`] stays for blind writes (a restored snapshot, offline tools).
    ///
    /// Returns `f`'s value and whether a commit happened.
    pub fn update_peers<R>(
        &self,
        f: impl FnOnce(&mut PeerBatch<'_>) -> Result<R, DbError>,
    ) -> Result<(R, bool), DbError> {
        let tx = self.inner.begin_write()?;
        let (out, writes) = {
            let cluster_revoked = {
                let table = tx.open_table(CLUSTER_STATE)?;
                let stored = table.get("cluster_state")?;
                match stored {
                    Some(v) => from_cbor_bytes::<StoredClusterState>(v.value())?.revoked_devices,
                    None => Vec::new(),
                }
            };
            let mut batch = PeerBatch {
                peers: tx.open_table(PEERS)?,
                device_to_master: tx.open_table(DEVICE_TO_MASTER)?,
                cluster_revoked,
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
