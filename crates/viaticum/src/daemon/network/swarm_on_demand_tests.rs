// On-demand dial (C-DK Р-12, network-i42): real swarms on loopback. A known
// peer without a connection is dialed by `send_to_device`, the request waits
// for its cert and goes out; failures are bounded in time, the negative cache
// spares a black hole, and only OUR dial's failure is cached.

use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::Multiaddr;
use viaticum_core::messages::Message;
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp};

use super::address_book::AddressBook;
use super::swarm::{SwarmConfig, SwarmError, SwarmHandle};
use super::swarm_test_helpers::{
    app_message, black_hole_addr, cached_config, closed_port_addr, device_of, get_listen_addr,
    make_swarm_config, peer_record_with, serve_acks, test_cluster_master_pub, wait_auth,
};

const OTHER_MASTER: IdentityPub = IdentityPub([0xBB; 32]);

/// Give `cfg` an address book holding `records` (device, addrs); the TempDir
/// must outlive the swarm.
fn with_book(
    cfg: &mut SwarmConfig,
    own_seed: u8,
    records: &[(DeviceId, Vec<Multiaddr>)],
) -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let db = viaticum_core::db::Db::open(&dir.path().join("db.redb")).expect("db");
    for (d, addrs) in records {
        db.upsert_peer(&peer_record_with(*d, OTHER_MASTER, addrs))
            .expect("record");
    }
    cfg.conn_policy.address_book = Some(AddressBook::new(
        db,
        test_cluster_master_pub(),
        device_of(own_seed),
    ));
    dir
}

/// A peer that answers every request with an Ack; returns it and its address.
async fn acking_peer(seed: u8) -> (Arc<SwarmHandle>, Multiaddr) {
    let (h, events) = SwarmHandle::start(make_swarm_config(seed))
        .await
        .expect("peer");
    let h = Arc::new(h);
    let addr = get_listen_addr(&h).await;
    serve_acks(h.clone(), events, Duration::ZERO);
    (h, addr)
}

fn is_unreachable(r: &Result<Message, SwarmError>) -> bool {
    matches!(r, Err(SwarmError::Unreachable(..)))
}

/// M12: without the on-demand dial this is `PeerNotAuthenticated`.
#[tokio::test]
async fn on_demand_send_dials_known_peer_and_delivers() {
    let (b, addr_b) = acking_peer(121).await;
    let mut cfg = cached_config(120, 48, 10_000);
    let _dir = with_book(&mut cfg, 120, &[(b.device_id, vec![addr_b])]);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");

    let r = a.send_to_device(b.device_id, app_message()).await;
    assert!(
        matches!(r, Ok(Message::Ack(_))),
        "delivered on demand: {r:?}"
    );
    // Seen on B: A authenticated there.
    wait_auth(&b, a.device_id, true).await;
    let stats = a.conn_stats().await.expect("stats");
    assert_eq!(stats.on_demand_ok, 1);
}

#[tokio::test]
async fn on_demand_send_to_unknown_without_addrs_is_not_authenticated() {
    let (a, _ev) = SwarmHandle::start(cached_config(122, 48, 10_000))
        .await
        .expect("A");
    let t0 = Instant::now();
    let r = a.send_to_device(device_of(123), app_message()).await;
    assert!(
        matches!(r, Err(SwarmError::PeerNotAuthenticated(_))),
        "{r:?}"
    );
    assert!(
        t0.elapsed() < Duration::from_secs(1),
        "nothing to dial: at once"
    );
}

#[tokio::test]
async fn on_demand_send_to_offline_peer_fails_within_timeout() {
    let mut cfg = cached_config(124, 48, 10_000);
    let off = device_of(125);
    let _dir = with_book(&mut cfg, 124, &[(off, vec![closed_port_addr()])]);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    let t0 = Instant::now();
    let r = a.send_to_device(off, app_message()).await;
    assert!(is_unreachable(&r), "{r:?}");
    assert!(
        t0.elapsed() <= Duration::from_secs(11),
        "{:?}",
        t0.elapsed()
    );
    assert_eq!(a.conn_stats().await.unwrap().on_demand_failed, 1);
}

#[tokio::test]
async fn on_demand_dials_are_capped_and_queued() {
    let mut cfg = cached_config(126, 48, 10_000);
    let mut records = Vec::new();
    for seed in 130..150u8 {
        records.push((device_of(seed), vec![black_hole_addr().await]));
    }
    let _dir = with_book(&mut cfg, 126, &records);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    let a = Arc::new(a);
    for (d, _) in &records {
        let (a, d) = (a.clone(), *d);
        tokio::spawn(async move {
            let _ = a.send_to_device(d, app_message()).await;
        });
    }
    let ok = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let s = a.conn_stats().await.unwrap();
            if s.on_demand_inflight + s.on_demand_queued == 20 {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("20 sends admitted");
    assert_eq!((ok.on_demand_inflight, ok.on_demand_queued), (16, 4));
}

/// The DR swap (`ConnPolicy::off`, no on-demand dial): a known peer with an
/// address in the book is still `PeerNotAuthenticated`, as before C4.
#[tokio::test]
async fn policy_off_keeps_old_send_semantics() {
    let (b, addr_b) = acking_peer(151).await;
    let mut cfg = make_swarm_config(150);
    let _dir = with_book(&mut cfg, 150, &[(b.device_id, vec![addr_b])]);
    assert!(!cfg.conn_policy.dial_on_demand);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    let r = a.send_to_device(b.device_id, app_message()).await;
    assert!(
        matches!(r, Err(SwarmError::PeerNotAuthenticated(_))),
        "{r:?}"
    );
    let s = a.conn_stats().await.unwrap();
    assert_eq!((s.connected, s.cap), (0, None), "no dial, no cache");
}

/// M16: without the negative cache the second send waits 10 s again.
#[tokio::test]
async fn on_demand_black_hole_fails_fast_after_first_timeout() {
    let mut cfg = cached_config(152, 48, 10_000);
    let hole = device_of(153);
    let _dir = with_book(&mut cfg, 152, &[(hole, vec![black_hole_addr().await])]);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");

    let t0 = Instant::now();
    let r = a.send_to_device(hole, app_message()).await;
    let first = t0.elapsed();
    assert!(is_unreachable(&r), "{r:?}");
    assert!(
        first >= Duration::from_secs(9) && first <= Duration::from_secs(12),
        "one wait of ~10 s: {first:?}"
    );
    let t1 = Instant::now();
    let r = a.send_to_device(hole, app_message()).await;
    assert!(is_unreachable(&r), "{r:?}");
    assert!(
        t1.elapsed() <= Duration::from_millis(100),
        "cached: at once, not another 10 s ({:?})",
        t1.elapsed()
    );
}

/// WR-2: the slot comes back at the waiter's deadline; the dial itself is
/// abandoned and ends with the 20 s transport timeout.
#[tokio::test]
async fn black_hole_dial_released_at_waiter_deadline_and_cleared_by_transport_timeout() {
    let mut cfg = cached_config(154, 48, 10_000);
    let hole = device_of(155);
    let _dir = with_book(&mut cfg, 154, &[(hole, vec![black_hole_addr().await])]);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    let t0 = Instant::now();
    let r = a.send_to_device(hole, app_message()).await;
    assert!(is_unreachable(&r), "{r:?}");
    let s = a.conn_stats().await.unwrap();
    assert_eq!((s.on_demand_inflight, s.on_demand_abandoned), (0, 1));
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            if a.conn_stats().await.unwrap().on_demand_abandoned == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the transport timeout ends the abandoned dial");
    assert!(
        t0.elapsed() >= Duration::from_secs(18),
        "ended by the 20 s transport timeout, not earlier: {:?}",
        t0.elapsed()
    );
}

/// M18: a deadline spent in the QUEUE does not put the peer in the negative
/// cache; one spent in our own dial does.
#[tokio::test]
async fn on_demand_queue_timeout_is_not_cached() {
    let mut cfg = cached_config(160, 48, 10_000);
    let mut records = Vec::new();
    for seed in 161..177u8 {
        records.push((device_of(seed), vec![black_hole_addr().await]));
    }
    let queued = device_of(177);
    records.push((queued, vec![black_hole_addr().await]));
    let _dir = with_book(&mut cfg, 160, &records);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    let a = Arc::new(a);
    let spawn_send = |d: DeviceId| {
        let a = a.clone();
        tokio::spawn(async move { a.send_to_device(d, app_message()).await })
    };
    // t = 0: 16 dials take every slot.
    for (d, _) in &records[..16] {
        spawn_send(*d);
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    // t = 0.5 s: the 17th waits in the queue (deadline 10.5 s).
    let q = spawn_send(queued);
    tokio::time::sleep(Duration::from_secs(4)).await;
    // t = 4.5 s: a second waiter on each slot holder keeps the slots taken past 10.5 s.
    for (d, _) in &records[..16] {
        spawn_send(*d);
    }
    let r = q.await.expect("join");
    assert!(
        matches!(&r, Err(SwarmError::Unreachable(_, why)) if why.contains("queued")),
        "the queued request gives up as queued: {r:?}"
    );
    // The queued peer is not cached: a new send to it is not answered at once.
    let again = tokio::time::timeout(
        Duration::from_millis(800),
        a.send_to_device(queued, app_message()),
    )
    .await;
    assert!(again.is_err(), "not cached: the new send waits ({again:?})");
    // A slot holder whose own dial timed out IS cached.
    let t = Instant::now();
    let r = a.send_to_device(records[0].0, app_message()).await;
    assert!(
        is_unreachable(&r) && t.elapsed() < Duration::from_millis(200),
        "{r:?}"
    );
}

#[tokio::test]
async fn on_demand_foreign_dial_timeout_is_not_cached() {
    let mut cfg = cached_config(178, 48, 10_000);
    let target = device_of(179);
    let hole = black_hole_addr().await;
    let _dir = with_book(&mut cfg, 178, &[(target, vec![hole.clone()])]);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    let peer = super::swarm::device_id_to_peer_id(&target).unwrap();
    // Somebody else's dial (manual) is under way and hangs.
    a.dial_addrs(peer, vec![hole]).await.expect("dial");
    let r = a.send_to_device(target, app_message()).await;
    assert!(
        matches!(&r, Err(SwarmError::Unreachable(_, why)) if why.contains("queued")),
        "{r:?}"
    );
    assert_eq!(a.conn_stats().await.unwrap().on_demand_neg_cached, 0);
    // The target comes up and connects (a connection that is not ours): the
    // given-up waiter left the cache's count (BLOCK-T в).
    let (t, _evt) = SwarmHandle::start(make_swarm_config(179))
        .await
        .expect("target");
    let addr_a = get_listen_addr(&a).await;
    t.dial(a.peer_id, addr_a).await.expect("dial A");
    wait_auth(&a, target, true).await;
    assert_eq!(a.test_lru_entry(peer).await.map(|e| e.2), Some(0));
}

/// W1 a: a foreign dial that fails does not fail the waiter: we dial then.
#[tokio::test]
async fn on_demand_failure_of_foreign_dial_does_not_fail_waiter() {
    let (b, addr_b) = acking_peer(181).await;
    let mut cfg = cached_config(180, 48, 10_000);
    let _dir = with_book(&mut cfg, 180, &[(b.device_id, vec![addr_b])]);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    // A foreign dial to a dead address of B, then the request.
    a.dial_addrs(b.peer_id, vec![closed_port_addr()])
        .await
        .expect("dial");
    let r = a.send_to_device(b.device_id, app_message()).await;
    assert!(matches!(r, Ok(Message::Ack(_))), "{r:?}");
}

/// N-2: any established connection with the peer clears the negative cache —
/// an inbound one too.
#[tokio::test]
async fn negative_cache_reset_by_inbound_connection() {
    let mut cfg = cached_config(182, 48, 10_000);
    let b_dev = device_of(183);
    let _dir = with_book(&mut cfg, 182, &[(b_dev, vec![closed_port_addr()])]);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    let r = a.send_to_device(b_dev, app_message()).await;
    assert!(is_unreachable(&r));
    assert_eq!(a.conn_stats().await.unwrap().on_demand_neg_cached, 1);

    // B comes back and dials A.
    let (b, _evb) = SwarmHandle::start(make_swarm_config(183)).await.expect("B");
    let addr_a = get_listen_addr(&a).await;
    b.dial(a.peer_id, addr_a).await.expect("dial A");
    wait_auth(&a, b_dev, true).await;
    assert_eq!(a.conn_stats().await.unwrap().on_demand_neg_cached, 0);
    // The failed waiter left the cache's count (BLOCK-T в).
    assert_eq!(a.test_lru_entry(b.peer_id).await.map(|e| e.2), Some(0));
}

/// N-3 / WARN-5: the processor's path never dials.
#[tokio::test]
async fn send_if_connected_does_not_dial() {
    let (b, addr_b) = acking_peer(185).await;
    let mut cfg = cached_config(184, 48, 10_000);
    let _dir = with_book(&mut cfg, 184, &[(b.device_id, vec![addr_b])]);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    let pa = Message::PeerAnnounce(a.build_peer_announce(Timestamp::now()));
    let r = a.send_if_connected(b.device_id, pa).await;
    assert!(
        matches!(r, Err(SwarmError::PeerNotAuthenticated(_))),
        "{r:?}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let s = a.conn_stats().await.unwrap();
    assert_eq!(
        (s.connected, s.on_demand_inflight),
        (0, 0),
        "no dial at all"
    );
}

/// WARN-5: `send_to_device` dials for ANY message — a PeerAnnounce too (the
/// `net-probe reach` path) — but a PeerAnnounce is not activity for the cache.
#[tokio::test]
async fn send_to_device_dials_for_peer_announce_without_touch() {
    let (b, addr_b) = acking_peer(187).await;
    let mut cfg = cached_config(186, 48, 10_000);
    let _dir = with_book(&mut cfg, 186, &[(b.device_id, vec![addr_b])]);
    let (a, _ev) = SwarmHandle::start(cfg).await.expect("A");
    let pa = Message::PeerAnnounce(a.build_peer_announce(Timestamp::now()));
    let r = a.send_to_device(b.device_id, pa).await;
    assert!(
        matches!(r, Ok(Message::Ack(_))),
        "dialed and delivered: {r:?}"
    );
    let entry = a.test_lru_entry(b.peer_id).await;
    assert_eq!(
        entry,
        Some((true, false, 0)),
        "cert done, NO app activity, nothing in flight"
    );
}
