// Unit tests of the on-demand dial bookkeeping (network-i42): pure state, a
// fake clock built from one Instant plus offsets.

use std::time::{Duration, Instant};

use libp2p::PeerId;
use libp2p::swarm::ConnectionId;
use tokio::sync::oneshot;
use viaticum_core::messages::Message;
use viaticum_core::types::DeviceId;

use super::{Next, OnDemand, Outcome, Situation, Waiter};

const WAIT: Duration = Duration::from_secs(10);

fn od(max_dials: usize) -> OnDemand {
    OnDemand::with_limits(
        max_dials,
        WAIT,
        Duration::from_secs(60),
        Duration::from_secs(240),
    )
}

fn waiter(od: &OnDemand, kind: &'static str, now: Instant) -> Waiter {
    let (reply, _rx) = oneshot::channel();
    Waiter {
        kind,
        message: Box::new(Message::Unknown),
        reply,
        deadline: od.deadline(now),
    }
}

fn dev(n: u8) -> DeviceId {
    DeviceId([n; 32])
}

fn cid(n: usize) -> ConnectionId {
    ConnectionId::new_unchecked(n)
}

#[test]
fn on_demand_first_request_dials_and_auth_releases_all_waiters() {
    let t0 = Instant::now();
    let mut o = od(16);
    let p = PeerId::random();
    let w = waiter(&o, "RestoreRequest", t0);
    assert_eq!(
        o.admit(p, dev(1), w, vec![], Situation::default()),
        Next::Dial
    );
    o.dial_started(p, cid(1), t0);
    let w = waiter(&o, "PeerAnnounce", t0);
    assert_eq!(
        o.admit(p, dev(1), w, vec![], Situation::default()),
        Next::Wait
    );
    assert_eq!(o.kinds(&p), "RestoreRequest,PeerAnnounce");
    assert_eq!(o.counts(t0).inflight, 1);
    o.on_established(p, cid(1));
    let (device, waiters) = o.on_authenticated(&p).expect("waiters released");
    assert_eq!((device, waiters.len()), (dev(1), 2));
    let c = o.counts(t0);
    assert_eq!((c.inflight, c.ok_total), (0, 1));
}

#[test]
fn on_demand_dials_are_capped_and_queued() {
    let t0 = Instant::now();
    let mut o = od(2);
    let peers: Vec<PeerId> = (0..4).map(|_| PeerId::random()).collect();
    for (i, p) in peers.iter().enumerate() {
        let w = waiter(&o, "SymbolOffer", t0);
        if o.admit(*p, dev(i as u8), w, vec![], Situation::default()) == Next::Dial {
            o.dial_started(*p, cid(i), t0);
        }
    }
    let c = o.counts(t0);
    assert_eq!((c.inflight, c.queued), (2, 2));
    assert_eq!(o.next_queued(), None, "no slot free");
    // The first dial fails: its slot goes to the first queued peer.
    let (failed, _) = o.on_dial_error(Some(peers[0]), cid(0), "refused", t0);
    assert!(failed.is_some());
    assert_eq!(o.next_queued(), Some(peers[2]));
}

/// M18 (unit): a deadline in the queue (slots taken) is `GaveUp("queued")` and
/// does NOT put the peer in the negative cache; our own dial's deadline does.
#[test]
fn on_demand_queue_timeout_is_not_cached() {
    let t0 = Instant::now();
    let mut o = od(1);
    let (dialed, queued) = (PeerId::random(), PeerId::random());
    let w = waiter(&o, "MailboxFetchRequest", t0);
    assert_eq!(
        o.admit(dialed, dev(1), w, vec![], Situation::default()),
        Next::Dial
    );
    o.dial_started(dialed, cid(1), t0);
    let w = waiter(&o, "MailboxFetchRequest", t0);
    assert_eq!(
        o.admit(queued, dev(2), w, vec![], Situation::default()),
        Next::Wait
    );

    let resolved = o.expire(t0 + WAIT);
    assert_eq!(resolved.len(), 2);
    for r in &resolved {
        if r.peer == dialed {
            assert_eq!(r.outcome, Outcome::Failed("timeout".to_string()));
        } else {
            assert_eq!(r.outcome, Outcome::GaveUp("queued"));
        }
    }
    let now = t0 + WAIT;
    assert!(o.is_cached(&dialed, now), "our dial timed out: cached");
    assert!(!o.is_cached(&queued, now), "never tried: not cached");
}

#[test]
fn on_demand_foreign_dial_timeout_is_not_cached() {
    let t0 = Instant::now();
    let mut o = od(16);
    let p = PeerId::random();
    let sit = Situation {
        connected: true,
        ..Situation::default()
    };
    let w = waiter(&o, "SymbolOffer", t0);
    assert_eq!(o.admit(p, dev(1), w, vec![], sit), Next::Wait);
    let resolved = o.expire(t0 + WAIT);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].outcome, Outcome::GaveUp("foreign_dial"));
    assert!(!o.is_cached(&p, t0 + WAIT));
}

/// W1 a: somebody else's dial failing does not fail our waiter; we dial then.
#[test]
fn on_demand_failure_of_foreign_dial_does_not_fail_waiter() {
    let t0 = Instant::now();
    let mut o = od(16);
    let p = PeerId::random();
    let w = waiter(&o, "SymbolOffer", t0);
    assert_eq!(
        o.admit(p, dev(1), w, vec![], Situation::default()),
        Next::Dial
    );
    o.set_foreign(p); // DialPeerConditionFalse: a dial was already under way
    let (resolved, next) = o.on_dial_error(Some(p), cid(77), "refused", t0);
    assert!(resolved.is_none(), "not our dial: nobody fails");
    assert_eq!(next, Next::Dial, "and now we dial ourselves");
    assert!(!o.is_cached(&p, t0));
}

#[test]
fn on_demand_black_hole_dial_released_at_deadline_and_forgotten_by_its_error() {
    let t0 = Instant::now();
    let mut o = od(16);
    let p = PeerId::random();
    let w = waiter(&o, "RestoreRequest", t0);
    assert_eq!(
        o.admit(p, dev(1), w, vec![], Situation::default()),
        Next::Dial
    );
    o.dial_started(p, cid(5), t0);
    let resolved = o.expire(t0 + WAIT);
    assert_eq!(resolved.len(), 1);
    let c = o.counts(t0 + WAIT);
    assert_eq!((c.inflight, c.abandoned, c.failed_total), (0, 1, 1));
    // The transport timeout ends the dial at 20 s: forgotten, nothing resolved.
    let (resolved, _) = o.on_dial_error(Some(p), cid(5), "timeout", t0 + Duration::from_secs(20));
    assert!(resolved.is_none());
    assert_eq!(o.counts(t0 + Duration::from_secs(20)).abandoned, 0);
}

#[test]
fn on_demand_abandoned_dial_forgotten_after_30s_without_error() {
    let t0 = Instant::now();
    let mut o = od(16);
    let p = PeerId::random();
    let w = waiter(&o, "RestoreRequest", t0);
    let _ = o.admit(p, dev(1), w, vec![], Situation::default());
    o.dial_started(p, cid(5), t0);
    let _ = o.expire(t0 + WAIT);
    let _ = o.expire(t0 + Duration::from_secs(31));
    assert_eq!(o.counts(t0 + Duration::from_secs(31)).abandoned, 0);
}

#[test]
fn negative_cache_doubles_up_to_the_ceiling_and_resets_on_connection() {
    let t0 = Instant::now();
    let mut o = od(16);
    let p = PeerId::random();
    let mut now = t0;
    let mut periods = Vec::new();
    for i in 0..5 {
        let w = waiter(&o, "RestoreRequest", now);
        let _ = o.admit(p, dev(1), w, vec![], Situation::default());
        o.dial_started(p, cid(i), now);
        let (r, _) = o.on_dial_error(Some(p), cid(i), "refused", now);
        assert!(r.is_some());
        let period = o.neg_period(&p).expect("cached");
        periods.push(period.as_secs());
        now += period; // the next failure comes when the entry has expired
    }
    assert_eq!(periods, vec![60, 120, 240, 240, 240]);
    // A failure while still cached does not double again.
    // Any established connection clears the entry (inbound included).
    o.on_established(p, cid(99));
    assert!(!o.is_cached(&p, now));
    assert_eq!(o.neg_period(&p), None);
}

#[test]
fn negative_cache_ceiling_scales_with_time_scale() {
    let o = OnDemand::new(Some(1200));
    let p = PeerId::random();
    assert!(!o.is_cached(&p, Instant::now()));
    // max(1800 / 1200, 60) = 60 s: the ceiling never drops below the TTL.
    assert_eq!(o.neg_max, Duration::from_secs(60));
    assert_eq!(OnDemand::new(None).neg_max, Duration::from_secs(1800));
}

#[test]
fn closing_peer_is_dialed_after_its_connection_closed() {
    let t0 = Instant::now();
    let mut o = od(16);
    let p = PeerId::random();
    let sit = Situation {
        closing: true,
        ..Situation::default()
    };
    let w = waiter(&o, "SymbolOffer", t0);
    assert_eq!(o.admit(p, dev(1), w, vec![], sit), Next::Wait);
    let (r, next) = o.on_closed(p, t0);
    assert!(r.is_none());
    assert_eq!(next, Next::Dial);
}

#[test]
fn our_dial_pending_only_until_our_connection_is_up() {
    let t0 = Instant::now();
    let mut o = od(16);
    let p = PeerId::random();
    assert!(!o.our_dial_pending(&p), "no waiters, no dial");
    let w = waiter(&o, "RestoreRequest", t0);
    assert_eq!(
        o.admit(p, dev(1), w, vec![], Situation::default()),
        Next::Dial
    );
    assert!(!o.our_dial_pending(&p), "admitted, not dialed yet");
    o.dial_started(p, cid(7), t0);
    assert!(o.our_dial_pending(&p));
    // A foreign connection coming up does not end our dial.
    o.on_established(p, cid(8));
    assert!(o.our_dial_pending(&p));
    o.on_established(p, cid(7));
    assert!(!o.our_dial_pending(&p), "our connection is up");
}

/// network-i44: the peer's last connection — an inbound one or somebody else's
/// dial — closes before its cert exchange while our dial is still under way:
/// the waiters stay with our dial, nothing is cached, and our dial brings them
/// out once the peer authenticates.
#[test]
fn foreign_connection_closed_during_our_dial_keeps_waiters() {
    let t0 = Instant::now();
    let mut o = od(16);
    let p = PeerId::random();
    let w = waiter(&o, "RestoreRequest", t0);
    assert_eq!(
        o.admit(p, dev(1), w, vec![], Situation::default()),
        Next::Dial
    );
    o.dial_started(p, cid(11), t0);
    // The peer's own dial to us comes up, then closes before the cert.
    o.on_established(p, cid(90));

    let (r, next) = o.on_closed(p, t0);
    assert!(r.is_none(), "the closed connection was not ours");
    assert_eq!(next, Next::Wait, "our dial is still under way");
    assert!(!o.is_cached(&p, t0));
    assert_eq!(o.counts(t0).failed_total, 0);
    assert_eq!(o.counts(t0).inflight, 1, "our dial keeps its slot");
    o.on_established(p, cid(11));
    let (device, waiters) = o.on_authenticated(&p).expect("waiters kept");
    assert_eq!((device, waiters.len()), (dev(1), 1));
    assert_eq!(o.counts(t0).ok_total, 1);
}

/// Control for network-i44: once our dial's connection is up, its close
/// before the cert is OUR dial failing — Unreachable and the negative cache.
#[test]
fn connection_closed_after_our_dial_connected_fails_and_caches() {
    let t0 = Instant::now();
    let mut o = od(16);
    let p = PeerId::random();
    let w = waiter(&o, "RestoreRequest", t0);
    let _ = o.admit(p, dev(2), w, vec![], Situation::default());
    o.dial_started(p, cid(12), t0);
    o.on_established(p, cid(12));
    assert!(!o.our_dial_pending(&p));

    let (r, next) = o.on_closed(p, t0);
    let r = r.expect("our dial failed");
    assert_eq!(
        r.outcome,
        Outcome::Failed("connection closed before the cert exchange".to_string())
    );
    assert_eq!(r.waiters.len(), 1);
    assert_eq!(next, Next::Wait);
    assert!(o.is_cached(&p, t0));
    assert_eq!(o.counts(t0).failed_total, 1);
    assert_eq!(o.counts(t0).inflight, 0);
}
