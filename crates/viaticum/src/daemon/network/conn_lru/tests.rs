// Unit tests of the connection cache bookkeeping (network-i41): pure, a fake
// clock built from one Instant plus offsets.

use std::time::{Duration, Instant};

use libp2p::PeerId;

use super::{ConnLru, InfraRule, VictimReason};

const GRACE: Duration = Duration::from_secs(10);
const CERT: Duration = Duration::from_secs(35);

fn lru(cap: usize) -> ConnLru {
    ConnLru::new(cap, InfraRule::None, GRACE, 16, CERT)
}

fn at(t0: Instant, secs: u64) -> Instant {
    t0 + Duration::from_secs(secs)
}

/// Connect + authenticate `peer` at `t` and give it one finished request (app
/// traffic touched at `t`). Returns the victims of the passes on the way.
fn app_peer(c: &mut ConnLru, peer: PeerId, t: Instant) -> Vec<PeerId> {
    c.on_connected(peer, t);
    let mut out: Vec<PeerId> = c
        .on_authenticated(&peer, t)
        .into_iter()
        .map(|v| v.peer)
        .collect();
    c.begin(&peer);
    c.touch(&peer, t);
    out.extend(c.end(&peer, t).into_iter().map(|v| v.peer));
    out
}

#[test]
fn lru_evicts_least_recent_activity_first() {
    let t0 = Instant::now();
    let mut c = lru(2);
    let (a, b, d) = (PeerId::random(), PeerId::random(), PeerId::random());
    assert!(app_peer(&mut c, a, at(t0, 1)).is_empty());
    assert!(app_peer(&mut c, b, at(t0, 2)).is_empty());
    let evicted = app_peer(&mut c, d, at(t0, 3));
    assert_eq!(evicted, vec![a], "the peer silent the longest goes");
    assert!(!c.contains(&a));
    assert_eq!(c.evictions_total(), 1);
}

#[test]
fn lru_touch_moves_peer_to_most_recent() {
    let t0 = Instant::now();
    let mut c = lru(2);
    let (a, b, d) = (PeerId::random(), PeerId::random(), PeerId::random());
    let _ = app_peer(&mut c, a, at(t0, 1));
    let _ = app_peer(&mut c, b, at(t0, 2));
    c.touch(&a, at(t0, 3));
    let evicted = app_peer(&mut c, d, at(t0, 4));
    assert_eq!(
        evicted,
        vec![b],
        "a was touched after b, so b is the oldest"
    );
}

/// M11 (unit): a peer with a request in flight is never a victim.
#[test]
fn lru_never_evicts_peer_with_request_in_flight() {
    let t0 = Instant::now();
    let mut c = lru(1);
    let (a, b) = (PeerId::random(), PeerId::random());
    let _ = app_peer(&mut c, a, at(t0, 1));
    c.begin(&a); // a slow request to a
    let evicted = app_peer(&mut c, b, at(t0, 2));
    assert!(
        evicted.is_empty(),
        "a is busy, b is the only free peer: 1 ≤ cap"
    );
    // Even far past the grace and with a third free peer, a stays.
    let d = PeerId::random();
    let evicted = app_peer(&mut c, d, at(t0, 100));
    assert_eq!(evicted, vec![b]);
    assert!(c.contains(&a));
    // The request ends: a is free again and the oldest — it goes in the same turn.
    let evicted: Vec<PeerId> = c.end(&a, at(t0, 101)).into_iter().map(|v| v.peer).collect();
    assert_eq!(evicted, vec![a]);
}

#[test]
fn lru_one_entry_per_peer_across_connections() {
    let t0 = Instant::now();
    let mut c = lru(48);
    let a = PeerId::random();
    c.on_connected(a, at(t0, 1));
    c.on_connected(a, at(t0, 2)); // a duplicate connection of the same peer
    assert_eq!(c.counts(at(t0, 2)).entries, 1);
    c.on_disconnected(&a);
    assert_eq!(c.counts(at(t0, 2)).entries, 0);
}

#[test]
fn lru_overshoot_when_everyone_busy_then_catches_up() {
    let t0 = Instant::now();
    let mut c = lru(1);
    let peers: Vec<PeerId> = (0..3).map(|_| PeerId::random()).collect();
    for (i, p) in peers.iter().enumerate() {
        let _ = app_peer(&mut c, *p, at(t0, i as u64));
        c.begin(p); // each one gets a request that stays in flight
    }
    assert!(
        c.victims(at(t0, 50)).is_empty(),
        "everyone busy: a soft overshoot"
    );
    assert_eq!(c.counts(at(t0, 50)).busy, 3);
    let mut evicted = Vec::new();
    for p in &peers {
        evicted.extend(c.end(p, at(t0, 60)).into_iter().map(|v| v.peer));
    }
    assert_eq!(evicted.len(), 2, "back at the cap as the requests end");
    assert_eq!(c.counts(at(t0, 60)).entries, 1);
}

/// v3.1 B1: the end of the last request of an over-cap peer evicts at once.
#[test]
fn lru_end_evicts_immediately_when_over_cap() {
    let t0 = Instant::now();
    let mut c = lru(1);
    let (a, b) = (PeerId::random(), PeerId::random());
    let _ = app_peer(&mut c, a, at(t0, 1));
    c.on_connected(b, at(t0, 2));
    let _ = c.on_authenticated(&b, at(t0, 2));
    c.begin(&b);
    c.touch(&b, at(t0, 30));
    assert!(c.victims(at(t0, 31)).is_empty(), "b busy, a alone: at cap");
    let evicted = c.end(&b, at(t0, 32));
    assert_eq!(evicted.len(), 1);
    assert_eq!(
        evicted[0].peer, a,
        "a's activity (1 s) is older than b's (30 s)"
    );
}

#[test]
fn handshake_only_peer_protected_for_grace() {
    let t0 = Instant::now();
    let mut c = lru(0);
    let a = PeerId::random();
    c.on_connected(a, at(t0, 0));
    assert!(
        c.on_authenticated(&a, at(t0, 1)).is_empty(),
        "protected inside the grace"
    );
    let counts = c.counts(at(t0, 5));
    assert_eq!((counts.busy, counts.protected), (1, 1));
    let v = c.victims(at(t0, 10));
    assert_eq!(v.len(), 1, "the grace is over at 10 s");
    assert_eq!(v[0].reason, VictimReason::HandshakeExpired);
}

/// M14 (unit): a handshake-only peer goes before any peer with app traffic,
/// even one whose traffic is older.
#[test]
fn handshake_only_peer_evicted_before_app_active() {
    let t0 = Instant::now();
    let mut c = lru(1);
    let (app, hs) = (PeerId::random(), PeerId::random());
    let _ = app_peer(&mut c, app, at(t0, 1));
    c.on_connected(hs, at(t0, 50));
    let _ = c.on_authenticated(&hs, at(t0, 50));
    let v = c.victims(at(t0, 61));
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].peer, hs, "the handshake-only peer goes first");
    assert!(c.contains(&app));
}

#[test]
fn handshake_only_peer_not_evicted_before_cert_done() {
    let t0 = Instant::now();
    let mut c = lru(0);
    let a = PeerId::random();
    c.on_connected(a, at(t0, 0));
    assert!(
        c.victims(at(t0, 30)).is_empty(),
        "cert pending: busy within the cert timeout"
    );
    let counts = c.counts(at(t0, 30));
    assert_eq!(
        (counts.busy, counts.cert_pending, counts.protected),
        (1, 1, 0)
    );
}

/// A connection that never completes the cert exchange (a foreign Kademlia
/// client in the open network) is busy only until the cert timeout, then goes
/// first.
#[test]
fn connection_without_cert_evicted_first_after_cert_timeout() {
    let t0 = Instant::now();
    let mut c = lru(1);
    let (app, stranger) = (PeerId::random(), PeerId::random());
    let _ = app_peer(&mut c, app, at(t0, 0));
    c.on_connected(stranger, at(t0, 1));
    assert!(c.victims(at(t0, 30)).is_empty());
    let v = c.victims(at(t0, 36));
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].peer, stranger, "before the peer with app traffic");
    assert_eq!(v[0].reason, VictimReason::CertMissing);
    assert!(v[0].evictable_for <= Duration::from_secs(6));
}

#[test]
fn handshake_protection_capped_at_16() {
    let t0 = Instant::now();
    let mut c = lru(0);
    for i in 0..20 {
        let p = PeerId::random();
        let t = t0 + Duration::from_millis(i);
        c.on_connected(p, t);
        let _ = c.on_authenticated(&p, t);
    }
    // The 16 youngest stay protected; the rest went on the way.
    let counts = c.counts(t0 + Duration::from_millis(30));
    assert_eq!(counts.protected, 16);
    assert_eq!(counts.entries, 16);
    assert_eq!(c.evictions_total(), 4);
}

#[test]
fn seventeenth_handshake_peer_pushes_oldest_out_in_same_turn() {
    let t0 = Instant::now();
    let mut c = ConnLru::new(0, InfraRule::None, GRACE, 16, CERT);
    let mut first = None;
    for i in 0..16u64 {
        let p = PeerId::random();
        first.get_or_insert(p);
        let t = t0 + Duration::from_millis(i * 10);
        c.on_connected(p, t);
        assert!(c.on_authenticated(&p, t).is_empty());
    }
    let p17 = PeerId::random();
    let t = t0 + Duration::from_millis(500);
    c.on_connected(p17, t);
    let v = c.on_authenticated(&p17, t);
    assert_eq!(
        v.len(),
        1,
        "the 17th protected pushes one out in its own turn"
    );
    assert_eq!(Some(v[0].peer), first, "the oldest of the 16");
    assert_eq!(v[0].reason, VictimReason::HandshakeBeyond16);
}

#[test]
fn victims_removes_entries_and_reports_reason() {
    let t0 = Instant::now();
    let mut c = lru(0);
    let (hs, app) = (PeerId::random(), PeerId::random());
    let _ = app_peer(&mut c, app, at(t0, 0));
    c.on_connected(hs, at(t0, 0));
    let _ = c.on_authenticated(&hs, at(t0, 0));
    // app went on its own (cap 0) during app_peer; check hs at 20 s.
    let v = c.victims(at(t0, 20));
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].peer, hs);
    assert_eq!(v[0].reason, VictimReason::HandshakeExpired);
    assert_eq!(
        c.counts(at(t0, 20)).entries,
        0,
        "a victim's entry is removed by the pass"
    );
    assert!(
        c.victims(at(t0, 21)).is_empty(),
        "nothing is returned twice"
    );
}

/// v3.3 counterexample of v3.2: a peer silent for 5 min that is evicted when a
/// newcomer arrives reports the time since the previous pass, not 300 000 ms.
#[test]
fn evictable_for_counts_from_last_pass_for_long_idle_peer() {
    let t0 = Instant::now();
    let mut c = lru(1);
    let (old, new) = (PeerId::random(), PeerId::random());
    let _ = app_peer(&mut c, old, at(t0, 0));
    assert!(c.victims(at(t0, 295)).is_empty(), "a tick pass at 295 s");
    c.on_connected(new, at(t0, 300));
    let mut v = c.on_authenticated(&new, at(t0, 300));
    c.begin(&new);
    c.touch(&new, at(t0, 300));
    v.extend(c.end(&new, at(t0, 300)));
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].peer, old);
    assert_eq!(v[0].reason, VictimReason::Idle);
    assert!(
        v[0].evictable_for <= Duration::from_secs(5),
        "from the previous pass, not from the end of its request at 0 s: {:?}",
        v[0].evictable_for
    );
    assert!(v[0].idle >= Duration::from_secs(300));
}

#[test]
fn busy_counts_only_connected_peers() {
    let t0 = Instant::now();
    let mut c = lru(48);
    let waiting = PeerId::random();
    c.begin(&waiting); // an on-demand dial to a peer not connected yet
    assert_eq!(
        c.counts(t0).busy,
        0,
        "a waiter without a connection is not counted"
    );
    c.on_connected(waiting, t0);
    let _ = c.on_authenticated(&waiting, at(t0, 30));
    assert_eq!(
        c.counts(at(t0, 30)).busy,
        1,
        "the waiter merged into the entry"
    );
    assert!(c.release_waiter(&waiting, at(t0, 31)).is_empty());
    assert_eq!(c.counts(at(t0, 31)).busy, 0);
}

#[test]
fn conn_stats_counts_protected_and_cert_pending_as_busy() {
    let t0 = Instant::now();
    let mut c = lru(0);
    let (pending, fresh) = (PeerId::random(), PeerId::random());
    c.on_connected(pending, t0);
    c.on_connected(fresh, t0);
    assert!(c.on_authenticated(&fresh, t0).is_empty());
    let counts = c.counts(at(t0, 1));
    assert_eq!(counts.busy, 2);
    assert_eq!(counts.protected, 1);
    assert_eq!(counts.cert_pending, 1);
    // Invariant: entries − busy − infra ≤ cap after a pass.
    assert!(c.victims(at(t0, 1)).is_empty());
    let counts = c.counts(at(t0, 1));
    assert_eq!(counts.entries - counts.busy - counts.infra, 0);
}

/// M17 (unit): infrastructure is outside the cap and never a victim.
#[test]
fn infra_peers_outside_cap() {
    let t0 = Instant::now();
    let seed = PeerId::random();
    let mut c = ConnLru::new(0, InfraRule::Peers(vec![seed]), GRACE, 16, CERT);
    let _ = app_peer(&mut c, seed, at(t0, 0));
    let other = PeerId::random();
    let v = app_peer(&mut c, other, at(t0, 1));
    assert_eq!(
        v,
        vec![other],
        "cap 0: the ordinary peer goes, the seed stays"
    );
    assert!(c.contains(&seed));
    assert_eq!(c.counts(at(t0, 100)).infra, 1);
    assert!(c.victims(at(t0, 100)).is_empty());
}

#[test]
fn seed_infra_rule_counts_up_to_the_limit() {
    let t0 = Instant::now();
    let mut c = ConnLru::new(0, InfraRule::AllUpTo(2), GRACE, 16, CERT);
    let peers: Vec<PeerId> = (0..3).map(|_| PeerId::random()).collect();
    let mut evicted = Vec::new();
    for (i, p) in peers.iter().enumerate() {
        evicted.extend(app_peer(&mut c, *p, at(t0, i as u64)));
    }
    assert_eq!(
        evicted,
        vec![peers[2]],
        "the third is beyond the infra limit"
    );
    assert!(c.is_infra(&peers[0]) && c.is_infra(&peers[1]));
}
