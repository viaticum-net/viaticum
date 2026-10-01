// The PeerRecord address book: which peers this node KNOWS and how to dial them
// (network-i14).
//
// "Known" is knowledge, not a connection: a PeerRecord of another master with at
// least one address we can dial. Records are written by the processor on the
// first cert exchange (both sides) and by DR; production never deletes them, so
// the known set only grows. Status reports it (`peer_count_known`,
// `known_devices`), redial dials over the same addresses.
//
// `dialable_addrs` moved here unchanged from handle/redial (C-DK C1): it is the
// one rule for "which stored address is a route to this peer", shared by redial
// and the known count.

#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::str::FromStr;

use libp2p::{Multiaddr, PeerId};
use viaticum_core::db::Db;
use viaticum_core::types::{DeviceId, IdentityPub, PeerRecord};

use crate::daemon::network::swarm::{device_id_to_peer_id, strip_peer_suffix};

/// Why one stored address of a peer is not a route to it.
enum SkippedAddr<'a> {
    /// Not a multiaddr at all.
    Unparseable { addr: &'a str, err: String },
    /// The terminal `/p2p/` names another peer.
    ForeignPeer { addr: &'a str, found: PeerId },
}

/// The routes to `device` among `stored`, without logging: the PeerId (derived
/// from the device key) and the deduplicated transport addresses (terminal
/// `/p2p/` stripped), plus the addresses that were dropped and why.
/// `Err` when the device id is not a valid Ed25519 key.
fn collect_dialable<'a>(
    device: &DeviceId,
    stored: &'a [String],
) -> Result<(PeerId, Vec<Multiaddr>, Vec<SkippedAddr<'a>>), String> {
    let peer_id = device_id_to_peer_id(device).map_err(|e| e.to_string())?;
    let mut seen: HashSet<Multiaddr> = HashSet::new();
    let mut addrs: Vec<Multiaddr> = Vec::new();
    let mut skipped: Vec<SkippedAddr<'a>> = Vec::new();
    for addr_str in stored {
        let addr = match Multiaddr::from_str(addr_str) {
            Ok(a) => a,
            Err(e) => {
                skipped.push(SkippedAddr::Unparseable {
                    addr: addr_str,
                    err: e.to_string(),
                });
                continue;
            }
        };
        match strip_peer_suffix(&addr, peer_id) {
            Ok(transport) => {
                if seen.insert(transport.clone()) {
                    addrs.push(transport);
                }
            }
            Err(found) => skipped.push(SkippedAddr::ForeignPeer {
                addr: addr_str,
                found,
            }),
        }
    }
    Ok((peer_id, addrs, skipped))
}

/// PeerId of `device` and the transport addresses to dial it on (terminal
/// `/p2p/` stripped, deduplicated). `None` when there is nothing to dial.
/// Every dropped stored address is logged and counted in `skipped`.
pub(crate) fn dialable_addrs(
    device: &DeviceId,
    stored: &[String],
    skipped: &mut usize,
) -> Option<(PeerId, Vec<Multiaddr>)> {
    let (peer_id, addrs, dropped) = match collect_dialable(device, stored) {
        Ok(found) => found,
        Err(e) => {
            tracing::warn!(%device, err = %e, "auto-dial: device id is not a valid key, skipping peer");
            return None;
        }
    };
    for skip in &dropped {
        match skip {
            SkippedAddr::Unparseable { addr, err } => {
                tracing::warn!(%device, addr = %addr, err = %err,
                    "auto-dial: unparseable stored address, skipping");
            }
            SkippedAddr::ForeignPeer { addr, found } => {
                tracing::warn!(%device, expected = %peer_id, found = %found, addr = %addr,
                    "auto-dial: stored address names another peer, skipping");
            }
        }
    }
    *skipped += dropped.len();
    if addrs.is_empty() {
        None
    } else {
        Some((peer_id, addrs))
    }
}

/// Read-only view of the PeerRecord table for the swarm (C-DK Р-14,
/// network-i14). C2 reads it once at swarm start to seed the set of known peers
/// that discovery does not dial (Р-5′, network-i43); C4 adds the on-demand dial
/// addresses (network-i42).
///
/// A plain struct over the real DB, not a trait: there is one implementation,
/// and tests use real redb on a tmpfile.
#[derive(Clone)]
pub struct AddressBook {
    db: Db,
    own_master: IdentityPub,
    own_device: DeviceId,
}

impl AddressBook {
    pub fn new(db: Db, own_master: IdentityPub, own_device: DeviceId) -> Self {
        Self {
            db,
            own_master,
            own_device,
        }
    }

    /// PeerIds of every known peer ([`is_known`]). A DB error is logged and
    /// yields none: discovery then dials them once more, nothing worse.
    pub fn known_peer_ids(&self) -> Vec<PeerId> {
        let peers = match self.db.list_all_peers() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(err = %e, "address book: cannot list peers");
                return Vec::new();
            }
        };
        peers
            .iter()
            .filter(|p| is_known(p, &self.own_master, &self.own_device))
            .filter_map(|p| device_id_to_peer_id(&p.device_id).ok())
            .collect()
    }
}

/// network-i14: `record` is a known peer — another master (not our own device,
/// not a sibling of our master) with at least one dialable address. Quiet: a
/// status read must not log every bad stored address again.
pub(crate) fn is_known(
    record: &PeerRecord,
    own_master: &IdentityPub,
    own_device: &DeviceId,
) -> bool {
    if record.device_id == *own_device || record.master_identity == *own_master {
        return false;
    }
    matches!(collect_dialable(&record.device_id, &record.addrs), Ok((_, addrs, _)) if !addrs.is_empty())
}
