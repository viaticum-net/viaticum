// The event-loop side of the test-only hold (`net-probe disconnect --hold-secs`,
// step 8b; `e2e-tools` only). The decision lives in `network/e2e_hold`; here it
// meets the swarm. Production paths are untouched: a user build compiles the
// two stubs in swarm.rs that refuse nothing.

use std::time::{Duration, Instant};

use libp2p::PeerId;
use libp2p::swarm::ConnectionId;
use tracing::info;

use super::EventLoopState;
use crate::daemon::network::conn_lru::DialOrigin;

impl EventLoopState {
    /// `net-probe disconnect`: hold the peer (when `hold`), then close every
    /// connection to it. Returns whether there was one. A zero `hold` only ends
    /// the peer's hold (no disconnect) and returns whether it is connected.
    pub(super) fn e2e_disconnect(&mut self, peer: PeerId, hold: Option<Duration>) -> bool {
        if hold == Some(Duration::ZERO) {
            self.e2e_hold.release(&peer);
            let connected = self.swarm.is_connected(&peer);
            info!(peer_id = %peer, connected, "e2e: hold released");
            return connected;
        }
        if let Some(d) = hold {
            self.e2e_hold.hold(peer, Instant::now() + d);
        }
        let was_connected = self.swarm.disconnect_peer_id(peer).is_ok();
        info!(
            peer_id = %peer,
            was_connected,
            hold_secs = hold.map_or(0, |d| d.as_secs()),
            "e2e: disconnect peer"
        );
        was_connected
    }

    /// A new connection `cid` with `peer` is up: refuse it when the peer is held
    /// and it is not our on-demand dial — closed at once, no cert sent, its
    /// cert exchange ignored, never in the cache or the on-demand bookkeeping.
    pub(super) fn e2e_hold_refuses(
        &mut self,
        peer: PeerId,
        cid: ConnectionId,
        dialer: bool,
    ) -> bool {
        let origin = self.dial_origin.get(&cid).map(|(_, o, _)| *o);
        let our_on_demand = dialer && origin == Some(DialOrigin::OnDemand);
        if !self
            .e2e_hold
            .refuses(&peer, cid, our_on_demand, Instant::now())
        {
            return false;
        }
        self.dial_origin.remove(&cid);
        let origin = match (dialer, origin) {
            (false, _) => "inbound",
            (true, Some(o)) => o.as_str(),
            (true, None) => DialOrigin::Kad.as_str(),
        };
        info!(peer_id = %peer, origin, "e2e: hold refused a connection");
        self.swarm.close_connection(cid);
        true
    }

    /// Is `cid` a connection the hold refused (still closing)?
    pub(super) fn e2e_is_refused(&self, cid: ConnectionId) -> bool {
        self.e2e_hold.is_refused(cid)
    }

    /// Connection `cid` closed: the hold forgets it if it refused it. (Its
    /// close needs no special case in the on-demand bookkeeping: a connection
    /// closing while our dial is under way never fails it, network-i44.)
    pub(super) fn e2e_forget_closed(&mut self, cid: ConnectionId) {
        self.e2e_hold.closed(cid);
    }
}
