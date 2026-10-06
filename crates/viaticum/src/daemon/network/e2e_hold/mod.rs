// Test-only connection hold of `net-probe disconnect --hold-secs N` (C-DK Р-16,
// step 8b of experiments/local_discovery_test.sh). Compiled only with the
// `e2e-tools` feature; a user build has none of it.
//
// Step 8b cools every holder of a block and then restores it: the restore must
// reach a holder by the on-demand dial (network-i42). Without a hold the peers
// come back on their own within seconds — Kademlia's lookups dial them, the
// redial pass dials them, they dial us — and the restore finds them warm. A hold
// makes the cooled state last: until it ends, every new connection with the
// peer is closed at once and never authenticated, EXCEPT our own on-demand dial
// (`send_to_device`, any message kind): the path 8b proves stays open.
//
// The decision is here; the swarm event loop closes the connection
// (`swarm/e2e_hold_loop.rs`).

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use libp2p::PeerId;
use libp2p::swarm::ConnectionId;

/// Held peers and the connections refused while they were held.
#[derive(Default)]
pub(crate) struct E2eHold {
    /// Peer → when its hold ends.
    until: HashMap<PeerId, Instant>,
    /// Connections refused and not closed yet: their cert exchange is ignored.
    refused: HashSet<ConnectionId>,
}

impl E2eHold {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Hold `peer` until `until` (a later call replaces the end; `until` not
    /// after now = no hold).
    pub(crate) fn hold(&mut self, peer: PeerId, until: Instant) {
        self.until.insert(peer, until);
    }

    /// End `peer`'s hold now.
    pub(crate) fn release(&mut self, peer: &PeerId) {
        self.until.remove(peer);
    }

    /// Is `peer` held at `now`? An ended hold is forgotten.
    pub(crate) fn is_held(&mut self, peer: &PeerId, now: Instant) -> bool {
        match self.until.get(peer) {
            Some(end) if now < *end => true,
            Some(_) => {
                self.until.remove(peer);
                false
            }
            None => false,
        }
    }

    /// A new connection `cid` with `peer` is up. `our_on_demand`: it is our
    /// on-demand dial. Refused (true) when the peer is held and it is anything
    /// else — then it is remembered until [`E2eHold::closed`].
    pub(crate) fn refuses(
        &mut self,
        peer: &PeerId,
        cid: ConnectionId,
        our_on_demand: bool,
        now: Instant,
    ) -> bool {
        if our_on_demand || !self.is_held(peer, now) {
            return false;
        }
        self.refused.insert(cid);
        true
    }

    /// Was `cid` refused (and is it still open)?
    pub(crate) fn is_refused(&self, cid: ConnectionId) -> bool {
        self.refused.contains(&cid)
    }

    /// Connection `cid` closed; returns whether it was a refused one.
    pub(crate) fn closed(&mut self, cid: ConnectionId) -> bool {
        self.refused.remove(&cid)
    }
}
