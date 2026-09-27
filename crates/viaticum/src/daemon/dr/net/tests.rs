// Tests for the DR network helpers: Kademlia stabilization (real swarms on loopback),
// the set wait and hint ordering (event channel / pure), live peer records.

use std::collections::HashSet;
use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use tokio::sync::mpsc;
use viaticum_core::db::Db;
use viaticum_core::types::{DeviceId, IdentityPub};

use super::*;
use crate::daemon::network::swarm::ProtocolEvent;
use crate::daemon::network::swarm_test_helpers::{
    make_cert, make_signing_key, test_cluster_master_key,
};

/// A PeerAuthenticated event for the device of `seed` (real key, so the PeerId matches).
fn auth_event(seed: u8, listen_addrs: Vec<Multiaddr>) -> (ProtocolEvent, PeerId, DeviceId) {
    let device_key = make_signing_key(seed);
    let device_id = DeviceId(device_key.verifying_key().to_bytes());
    let peer_id = device_id_to_peer_id(&device_id).unwrap();
    let ev = ProtocolEvent::PeerAuthenticated {
        peer_id,
        device_id,
        identity_pub: IdentityPub([seed; 32]),
        device_cert: make_cert(&test_cluster_master_key(), &device_key),
        x25519_pub: None,
        listen_addrs,
    };
    (ev, peer_id, device_id)
}

// ─── wait_for_kad_bootstrap_stable (real swarms) ──────────────────────────────

/// Three swarms; A dials B and C and the stabilization wait counts both and upserts
/// them into the DB.
#[tokio::test]
async fn wait_for_kad_bootstrap_stable_counts_authenticated_peers_and_upserts_db() {
    use crate::daemon::network::swarm::SwarmHandle;
    use crate::daemon::network::swarm_test_helpers::{get_listen_addr, make_swarm_config};

    let cfg_a = make_swarm_config(0x01);
    let cfg_b = make_swarm_config(0x02);
    let cfg_c = make_swarm_config(0x03);
    let device_id_b = DeviceId(cfg_b.device_signing_key.verifying_key().to_bytes());
    let device_id_c = DeviceId(cfg_c.device_signing_key.verifying_key().to_bytes());

    let (handle_a, mut event_rx_a) = SwarmHandle::start(cfg_a).await.unwrap();
    let (handle_b, _event_rx_b) = SwarmHandle::start(cfg_b).await.unwrap();
    let (handle_c, _event_rx_c) = SwarmHandle::start(cfg_c).await.unwrap();
    let addr_b = get_listen_addr(&handle_b).await;
    let addr_c = get_listen_addr(&handle_c).await;
    handle_a.dial(handle_b.peer_id, addr_b).await.unwrap();
    handle_a.dial(handle_c.peer_id, addr_c).await.unwrap();

    let db = Db::open_in_memory().unwrap();
    let count = wait_for_kad_bootstrap_stable(&mut event_rx_a, &db, 10, 2).await;

    assert_eq!(count, 2, "B and C authenticated");
    let b = db.get_peer(&device_id_b).unwrap().expect("B upserted");
    assert!(db.get_peer(&device_id_c).unwrap().is_some(), "C upserted");
    assert!(
        !b.addrs.is_empty(),
        "the address DR reached B on is kept in its record (dr-i18)"
    );
}

/// An isolated node returns 0 at the timeout and does not hang.
#[tokio::test]
async fn wait_for_kad_bootstrap_stable_returns_zero_on_timeout_no_hang() {
    use crate::daemon::network::swarm::SwarmHandle;
    use crate::daemon::network::swarm_test_helpers::make_swarm_config;

    let (_handle, mut event_rx) = SwarmHandle::start(make_swarm_config(0x10)).await.unwrap();
    let db = Db::open_in_memory().unwrap();
    let start = std::time::Instant::now();
    let count = wait_for_kad_bootstrap_stable(&mut event_rx, &db, 3, 1).await;
    assert_eq!(count, 0);
    assert!(start.elapsed() < Duration::from_secs(5));
}

// ─── wait_for_auth_set ────────────────────────────────────────────────────────

#[tokio::test]
async fn wait_for_auth_set_returns_all_arrived_before_deadline() {
    let db = Db::open_in_memory().unwrap();
    let (tx, mut rx) = mpsc::channel(16);
    let (ev1, p1, d1) = auth_event(0x21, vec![]);
    let (ev2, p2, d2) = auth_event(0x22, vec![]);
    let (stranger, _, d3) = auth_event(0x23, vec![]);
    tx.send(ev1).await.unwrap();
    tx.send(stranger).await.unwrap();
    tx.send(ev2).await.unwrap();

    let start = std::time::Instant::now();
    let arrived = wait_for_auth_set(
        &mut rx,
        &db,
        HashSet::from([p1, p2]),
        Duration::from_secs(10),
    )
    .await;

    assert_eq!(arrived, HashSet::from([p1, p2]));
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "returns as soon as the whole set arrived"
    );
    for d in [d1, d2, d3] {
        assert!(
            db.get_peer(&d).unwrap().is_some(),
            "every authenticated peer is upserted, also the unexpected one"
        );
    }
    drop(tx);
}

#[tokio::test]
async fn wait_for_auth_set_stops_at_deadline() {
    let db = Db::open_in_memory().unwrap();
    let (tx, mut rx) = mpsc::channel(16);
    let (ev1, p1, _) = auth_event(0x31, vec![]);
    let (_, p_missing, _) = auth_event(0x32, vec![]);
    tx.send(ev1).await.unwrap();

    let start = std::time::Instant::now();
    let arrived = wait_for_auth_set(
        &mut rx,
        &db,
        HashSet::from([p1, p_missing]),
        Duration::from_millis(300),
    )
    .await;
    assert_eq!(arrived, HashSet::from([p1]));
    assert!(start.elapsed() < Duration::from_secs(2));
    drop(tx);
}

// ─── live_peer_record ─────────────────────────────────────────────────────────

#[test]
fn live_peer_record_takes_the_authenticated_identity_and_listen_addrs() {
    let db = Db::open_in_memory().unwrap();
    let device = DeviceId([7u8; 32]);
    let addr: Multiaddr = "/ip4/10.0.0.5/tcp/4001".parse().unwrap();
    let r = live_peer_record(
        &db,
        device,
        IdentityPub([0x42; 32]),
        None,
        std::slice::from_ref(&addr),
    );
    assert_eq!(r.master_identity, IdentityPub([0x42; 32]));
    assert_eq!(r.addrs, vec![addr.to_string()]);
}

#[test]
fn live_peer_record_keeps_history_and_addrs_of_an_existing_record_when_none_given() {
    let db = Db::open_in_memory().unwrap();
    let device = DeviceId([8u8; 32]);
    let mut first = live_peer_record(&db, device, IdentityPub([1; 32]), None, &[]);
    first.trust_p = 0.77;
    first.addrs = vec!["/ip4/10.0.0.9/tcp/1".to_string()];
    db.upsert_peer(&first).unwrap();

    let again = live_peer_record(&db, device, IdentityPub([1; 32]), Some([3; 32]), &[]);
    assert_eq!(again.trust_p, 0.77);
    assert_eq!(again.addrs, vec!["/ip4/10.0.0.9/tcp/1".to_string()]);
    assert_eq!(again.x25519_pub, Some([3; 32]));
}

// ─── order_hint_addrs ─────────────────────────────────────────────────────────

fn pid(seed: u8) -> PeerId {
    let device_id = DeviceId(make_signing_key(seed).verifying_key().to_bytes());
    device_id_to_peer_id(&device_id).unwrap()
}

#[test]
fn order_hint_addrs_public_then_private_then_loopback() {
    let p = pid(0x41);
    let hints = vec![
        format!("/ip4/127.0.0.1/tcp/1/p2p/{p}"),
        format!("/ip4/192.168.1.5/tcp/2/p2p/{p}"),
        format!("/ip4/0.0.0.0/tcp/3/p2p/{p}"),
        format!("/ip4/8.8.4.4/tcp/4/p2p/{p}"),
        format!("/ip6/fd00::1/tcp/5/p2p/{p}"),
        format!("/ip4/100.64.0.9/tcp/6/p2p/{p}"),
    ];
    let got: Vec<String> = order_hint_addrs(&hints)
        .into_iter()
        .map(|(peer, a)| {
            assert_eq!(peer, p);
            a.to_string()
        })
        .collect();
    assert_eq!(
        got,
        vec![
            hints[3].clone(),
            hints[1].clone(),
            hints[4].clone(),
            hints[5].clone(),
            hints[0].clone(),
            hints[2].clone(),
        ]
    );
}

#[test]
fn order_hint_addrs_drops_unparsable_and_addrs_without_p2p() {
    let p = pid(0x42);
    let hints = vec![
        "not an address".to_string(),
        "/ip4/10.0.0.1/tcp/4001".to_string(),
        format!("/ip4/10.0.0.2/tcp/4001/p2p/{p}"),
    ];
    let got = order_hint_addrs(&hints);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, p);
    assert_eq!(got[0].1.to_string(), hints[2]);
}
