// The connection cache in a real swarm (C-DK Р-11, network-i41): real swarms on
// loopback, a small cap and a short handshake grace.

use std::sync::Arc;
use std::time::Duration;

use libp2p::Multiaddr;
use viaticum_core::messages::Message;
use viaticum_core::types::Timestamp;

use super::conn_lru::InfraRule;
use super::swarm::{SwarmConfig, SwarmHandle};
use super::swarm_test_helpers::{
    app_message, cached_config, get_listen_addr, make_swarm_config, serve_acks, wait_auth,
};

/// A peer that answers every request with an Ack after `delay`.
async fn acking_peer(seed: u8, delay: Duration) -> (Arc<SwarmHandle>, Multiaddr) {
    acking_peer_cfg(make_swarm_config(seed), delay).await
}

async fn acking_peer_cfg(cfg: SwarmConfig, delay: Duration) -> (Arc<SwarmHandle>, Multiaddr) {
    let (h, events) = SwarmHandle::start(cfg).await.expect("peer");
    let h = Arc::new(h);
    let addr = get_listen_addr(&h).await;
    serve_acks(h.clone(), events, delay);
    (h, addr)
}

/// `a` dials `b` and both sides authenticate.
async fn connect(a: &SwarmHandle, b: &SwarmHandle, addr_b: Multiaddr) {
    a.dial(b.peer_id, addr_b).await.expect("dial");
    wait_auth(a, b.device_id, true).await;
}

async fn ack(a: &SwarmHandle, b: &SwarmHandle) {
    let r = a.send_to_device(b.device_id, app_message()).await;
    assert!(
        matches!(r, Ok(Message::Ack(_))),
        "request to {:?}: {r:?}",
        b.peer_id
    );
}

#[tokio::test]
async fn lru_cap_2_evicts_idle_peer_on_third_connection() {
    let (a, ev) = SwarmHandle::start(cached_config(200, 2, 100))
        .await
        .expect("A");
    let a = Arc::new(a);
    serve_acks(a.clone(), ev, Duration::ZERO);
    let mut peers = Vec::new();
    for seed in 201..204u8 {
        let (p, addr) = acking_peer(seed, Duration::ZERO).await;
        connect(&a, &p, addr).await;
        ack(&a, &p).await;
        peers.push(p);
    }
    // The third peer's request ended over the cap: the one silent longest went.
    wait_auth(&a, peers[0].device_id, false).await;
    let (auth, _) = a.peer_sets().await.unwrap();
    assert!(auth.contains(&peers[1].device_id) && auth.contains(&peers[2].device_id));
    let s = a.conn_stats().await.unwrap();
    assert_eq!(s.evictions_total, 1);
    assert!(s.connected - s.busy - s.infra - s.closing <= 2, "{s:?}");
}

/// M11: a peer with a request in flight is not evicted — the pass of
/// ConnStats runs while the slow answer is on its way.
#[tokio::test]
async fn lru_does_not_evict_peer_mid_request() {
    let (a, _ev) = SwarmHandle::start(cached_config(205, 0, 100))
        .await
        .expect("A");
    let a = Arc::new(a);
    let (b, addr_b) = acking_peer(206, Duration::from_millis(1500)).await;
    connect(&a, &b, addr_b).await;
    let (a2, dev_b) = (a.clone(), b.device_id);
    let req = tokio::spawn(async move { a2.send_to_device(dev_b, app_message()).await });
    tokio::time::sleep(Duration::from_millis(400)).await; // the grace is over
    let s = a.conn_stats().await.unwrap(); // runs the eviction pass
    assert_eq!(
        s.evictions_total, 0,
        "busy: not evicted mid-request ({s:?})"
    );
    let r = req.await.expect("join");
    assert!(
        matches!(r, Ok(Message::Ack(_))),
        "the slow answer arrives: {r:?}"
    );
    // Its end frees B, and cap 0 closes it in the same turn.
    wait_auth(&a, b.device_id, false).await;
}

#[tokio::test]
async fn evicted_peer_reached_again_on_demand() {
    let (a, _ev) = SwarmHandle::start(cached_config(207, 1, 100))
        .await
        .expect("A");
    let (b, addr_b) = acking_peer(208, Duration::ZERO).await;
    let (c, addr_c) = acking_peer(209, Duration::ZERO).await;
    connect(&a, &b, addr_b).await;
    ack(&a, &b).await;
    connect(&a, &c, addr_c).await;
    ack(&a, &c).await;
    wait_auth(&a, b.device_id, false).await; // B, silent longer, was evicted
    ack(&a, &b).await; // reached again on demand (the address A dialed it on)
    let s = a.conn_stats().await.unwrap();
    assert!(s.on_demand_ok >= 1, "{s:?}");
    assert!(s.evictions_total >= 2, "C went for B: {s:?}");
}

/// M14: a handshake (cert, PeerAnnounce either way) is not activity — the
/// handshake-only peer goes before the one with app traffic.
#[tokio::test]
async fn handshake_only_peer_evicted_before_app_active() {
    let (a, ev) = SwarmHandle::start(cached_config(210, 1, 1000))
        .await
        .expect("A");
    let a = Arc::new(a);
    serve_acks(a.clone(), ev, Duration::ZERO);
    let (b, addr_b) = acking_peer(211, Duration::ZERO).await;
    connect(&a, &b, addr_b).await;
    ack(&a, &b).await; // B: app traffic
    let (c, _addr_c) = acking_peer(212, Duration::ZERO).await;
    let addr_a = get_listen_addr(&a).await;
    connect(&c, &a, addr_a).await; // inbound for A
    wait_auth(&a, c.device_id, true).await;
    // PeerAnnounce both ways: C → A and A → C.
    let pa_c = Message::PeerAnnounce(c.build_peer_announce(Timestamp::now()));
    assert!(c.send_to_device(a.device_id, pa_c).await.is_ok());
    let pa_a = Message::PeerAnnounce(a.build_peer_announce(Timestamp::now()));
    assert!(a.send_if_connected(c.device_id, pa_a).await.is_ok());
    tokio::time::sleep(Duration::from_millis(1200)).await; // C's grace is over
    let s = a.conn_stats().await.unwrap();
    assert_eq!(s.evictions_total, 1, "{s:?}");
    let (auth, _) = a.peer_sets().await.unwrap();
    assert!(auth.contains(&b.device_id), "the app peer stays");
    assert!(!auth.contains(&c.device_id), "the handshake-only peer went");
}

/// M17: infrastructure is outside the cap — a friend's bootstrap peer stays
/// at cap 0 while an ordinary peer goes.
#[tokio::test]
async fn infra_peers_outside_cap() {
    let (seed, addr_s) = acking_peer(214, Duration::ZERO).await;
    let mut cfg = cached_config(213, 0, 100);
    cfg.conn_policy.infra = InfraRule::Peers(vec![seed.peer_id]);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    let (b, addr_b) = acking_peer(215, Duration::ZERO).await;
    connect(&a, &seed, addr_s).await;
    ack(&a, &seed).await;
    connect(&a, &b, addr_b).await;
    ack(&a, &b).await;
    wait_auth(&a, b.device_id, false).await;
    let s = a.conn_stats().await.unwrap();
    assert_eq!(s.infra, 1, "{s:?}");
    let (auth, _) = a.peer_sets().await.unwrap();
    assert!(auth.contains(&seed.device_id), "the seed stays at cap 0");
    assert_eq!(s.infra_peers, vec![seed.peer_id]);
}

/// WR-1: an evicted peer leaves the cache and `authenticated` at once — before
/// its ConnectionClosed — and is counted as closing.
#[tokio::test]
async fn evicted_peer_leaves_cache_before_connection_closed() {
    let (a, _ev) = SwarmHandle::start(cached_config(216, 48, 10_000))
        .await
        .expect("A");
    let (b, addr_b) = acking_peer(217, Duration::ZERO).await;
    connect(&a, &b, addr_b).await;
    let (evicted, s) = tokio::join!(a.test_evict(b.peer_id), a.conn_stats());
    assert!(evicted);
    let s = s.unwrap();
    assert_eq!((s.closing, s.authenticated), (1, 0), "{s:?}");
    assert_eq!(a.test_lru_entry(b.peer_id).await, None, "no cache entry");
    wait_auth(&a, b.device_id, false).await;
    // Then the close itself.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let s = a.conn_stats().await.unwrap();
            if s.closing == 0 && s.connected == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("closed");
}

/// WR-1: one snapshot — connected counts the closing peer, and the invariant
/// connected − busy − infra − closing ≤ cap holds on it.
#[tokio::test]
async fn conn_stats_is_one_snapshot_and_excludes_closing() {
    let (a, _ev) = SwarmHandle::start(cached_config(218, 1, 10_000))
        .await
        .expect("A");
    let (b, addr_b) = acking_peer(219, Duration::ZERO).await;
    let (c, addr_c) = acking_peer(220, Duration::ZERO).await;
    connect(&a, &b, addr_b).await;
    connect(&a, &c, addr_c).await;
    let (_, s) = tokio::join!(a.test_evict(b.peer_id), a.conn_stats());
    let s = s.unwrap();
    assert_eq!(
        (s.connected, s.closing),
        (2, 1),
        "B still connected, already closing: {s:?}"
    );
    assert!(s.connected - s.busy - s.infra - s.closing <= 1, "{s:?}");
    assert!(s.protected <= 16);
}

/// v3.3 BLOCK-1: the ConnStats handler runs the same pass as the tick before
/// its snapshot — the grace ended between events and no tick came yet.
#[tokio::test]
async fn conn_stats_runs_eviction_pass_before_snapshot() {
    let (a, _ev) = SwarmHandle::start(cached_config(221, 0, 1500))
        .await
        .expect("A");
    let (b, addr_b) = acking_peer(222, Duration::ZERO).await;
    connect(&a, &b, addr_b).await;
    let s = a.conn_stats().await.unwrap();
    assert_eq!(
        (s.busy, s.protected, s.evictions_total),
        (1, 1, 0),
        "protected: {s:?}"
    );
    tokio::time::sleep(Duration::from_millis(1700)).await;
    let s = a.conn_stats().await.unwrap();
    assert_eq!(
        s.evictions_total, 1,
        "the snapshot's own pass evicted B: {s:?}"
    );
    assert!(s.connected - s.busy - s.infra - s.closing == 0, "{s:?}");
}

/// W1 в: a send to a peer being closed by the cache dials after the close.
#[tokio::test]
async fn send_to_evicted_closing_peer_dials_after_close() {
    let (a, _ev) = SwarmHandle::start(cached_config(223, 48, 10_000))
        .await
        .expect("A");
    let (b, addr_b) = acking_peer(224, Duration::ZERO).await;
    connect(&a, &b, addr_b).await;
    let (evicted, r) = tokio::join!(
        a.test_evict(b.peer_id),
        a.send_to_device(b.device_id, app_message())
    );
    assert!(evicted);
    assert!(matches!(r, Ok(Message::Ack(_))), "{r:?}");
    assert_eq!(
        a.conn_stats().await.unwrap().on_demand_ok,
        1,
        "delivered over a NEW on-demand dial, not the closing connection"
    );
}

/// W1 г: the eviction (the ConnStats pass) and the send are separate commands,
/// yet the send never lands on the dying connection.
#[tokio::test]
async fn send_or_dial_is_atomic_under_eviction() {
    let (a, _ev) = SwarmHandle::start(cached_config(225, 0, 100))
        .await
        .expect("A");
    let (b, addr_b) = acking_peer(226, Duration::ZERO).await;
    connect(&a, &b, addr_b).await;
    tokio::time::sleep(Duration::from_millis(200)).await; // B evictable, no tick yet
    let (s, r) = tokio::join!(a.conn_stats(), a.send_to_device(b.device_id, app_message()));
    assert!(s.unwrap().evictions_total >= 1, "the pass evicted B");
    assert!(
        matches!(r, Ok(Message::Ack(_))),
        "the send must not land on the dying connection: {r:?}"
    );
}
