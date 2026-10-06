// Unit tests of the e2e hold's decision (pure; the swarm side is in
// swarm_e2e_tests.rs).

use std::time::{Duration, Instant};

use libp2p::PeerId;
use libp2p::swarm::ConnectionId;

use super::E2eHold;

#[test]
fn held_peer_connection_is_refused_until_closed() {
    let mut h = E2eHold::new();
    let p = PeerId::random();
    let now = Instant::now();
    h.hold(p, now + Duration::from_secs(10));
    let cid = ConnectionId::new_unchecked(1);

    assert!(h.refuses(&p, cid, false, now));
    assert!(h.is_refused(cid));
    assert!(h.closed(cid), "the refused connection is reported once");
    assert!(!h.is_refused(cid));
    assert!(!h.closed(cid));
}

#[test]
fn our_on_demand_dial_passes_a_hold() {
    let mut h = E2eHold::new();
    let p = PeerId::random();
    let now = Instant::now();
    h.hold(p, now + Duration::from_secs(10));
    let cid = ConnectionId::new_unchecked(2);

    assert!(!h.refuses(&p, cid, true, now));
    assert!(!h.is_refused(cid));
    assert!(h.is_held(&p, now), "the hold itself stays");
}

#[test]
fn ended_hold_refuses_nothing() {
    let mut h = E2eHold::new();
    let p = PeerId::random();
    let now = Instant::now();
    h.hold(p, now + Duration::from_secs(1));

    let later = now + Duration::from_secs(1);
    assert!(!h.refuses(&p, ConnectionId::new_unchecked(3), false, later));
    assert!(!h.is_held(&p, now), "an ended hold is forgotten");
}

#[test]
fn unheld_peer_is_never_refused() {
    let mut h = E2eHold::new();
    let held = PeerId::random();
    let other = PeerId::random();
    let now = Instant::now();
    h.hold(held, now + Duration::from_secs(10));

    assert!(!h.refuses(&other, ConnectionId::new_unchecked(4), false, now));
}
