// Discovery dials only peers we do not know (C-DK Р-5′, network-i43): real
// swarms on loopback. A known peer is reached when there is something to say,
// so a discovery result naming it must not make us dial it — even when we have
// no connection to it.
//
// The discovery pass is driven by `test_discovery_pass`, the same function the
// discovery timer's lookup result goes through: a real lookup would also make
// Kademlia dial what it finds and blur which dial came from where.

use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use viaticum_core::constants::{AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};
use viaticum_core::types::{DeviceId, IdentityPub, PeerRecord, Timestamp};

use super::address_book::AddressBook;
use super::swarm::{ConnPolicy, ProtocolEvent, SwarmConfig, SwarmHandle, device_id_to_peer_id};
use super::swarm_test_helpers::{
    get_listen_addr, make_cert, make_signing_key, make_swarm_config, test_cluster_master_pub,
    wait_for_authenticated,
};

/// A TCP port that accepts and never answers: a dial to it hangs, so the
/// control peer stays "being dialed" and nothing else changes.
async fn black_hole() -> Multiaddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind black hole");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    format!("/ip4/127.0.0.1/tcp/{port}").parse().expect("ma")
}

/// A device of another master (`master_seed`): its cert is self-signed by
/// that master, so our test-cluster swarms authenticate it on the Cross path.
fn stranger_config(seed: u8, master_seed: u8) -> SwarmConfig {
    let mut cfg = make_swarm_config(seed);
    let master = make_signing_key(master_seed);
    let identity = IdentityPub(master.verifying_key().to_bytes());
    cfg.device_cert = make_cert(&master, &cfg.device_signing_key);
    cfg.master_signing_key = master;
    cfg.identity_pub = identity;
    cfg.cluster_master_pub = identity;
    cfg
}

fn device(seed: u8) -> DeviceId {
    DeviceId(make_signing_key(seed).verifying_key().to_bytes())
}

fn peer_record(device_id: DeviceId, master: IdentityPub, addr: &Multiaddr) -> PeerRecord {
    let now = Timestamp::now();
    PeerRecord {
        device_id,
        master_identity: master,
        trust_p: INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![addr.to_string()],
        x25519_pub: None,
        avail_ewma: AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    }
}

/// Wait for the processor-facing ConnectionClosed of `peer` (its last
/// connection gone).
async fn wait_for_closed(rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>, peer: PeerId) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ev = rx.recv().await.expect("event_rx closed");
            if let ProtocolEvent::ConnectionClosed { peer_id, .. } = ev
                && peer_id == peer
            {
                return;
            }
        }
    })
    .await
    .expect("timed out waiting for ConnectionClosed");
}

/// network-i43 (Р-5′): a peer with a PeerRecord in our address book is known
/// from the swarm's start; discovery finding it does not dial it, while a
/// stranger found in the same pass is dialed (the pass is not inert).
/// M: known set seeded empty, or `known.contains` dropped from the skip → RED.
#[tokio::test]
async fn discovery_does_not_dial_peer_from_address_book() {
    let hole = black_hole().await;
    let dir = tempfile::TempDir::new().expect("tempdir");
    let db = viaticum_core::db::Db::open(&dir.path().join("db.redb")).expect("db");
    let other_master = IdentityPub([0xBB; 32]);
    let b = device(51);
    db.upsert_peer(&peer_record(b, other_master, &hole))
        .expect("record of B");
    let b_peer = device_id_to_peer_id(&b).expect("peer id of B");

    let mut cfg = make_swarm_config(50);
    let book = AddressBook::new(db, test_cluster_master_pub(), device(50));
    cfg.conn_policy = ConnPolicy::daemon(book);
    let (a, _events) = SwarmHandle::start(cfg).await.expect("swarm A");

    let stranger = PeerId::random();
    let chosen = a
        .test_discovery_pass(vec![
            (b_peer, vec![hole.clone()]),
            (stranger, vec![hole.clone()]),
        ])
        .await;
    assert_eq!(
        chosen,
        vec![stranger],
        "A must dial only the stranger, not B from its address book"
    );
}

/// network-i43 (Р-5′): a peer of another master met since start (cert
/// exchange on the Cross path) stays known after its connection is gone;
/// discovery finding it does not dial it back. The address book is empty here
/// (`ConnPolicy::off`), so only the meeting itself makes B known.
/// M: `known.insert` on Cross dropped, or `known.contains` dropped from the
/// skip → RED.
#[tokio::test]
async fn discovery_does_not_dial_peer_met_since_start() {
    let hole = black_hole().await;
    let (a, mut events_a) = SwarmHandle::start(make_swarm_config(52))
        .await
        .expect("swarm A");
    let (b, events_b) = SwarmHandle::start(stranger_config(53, 0x77))
        .await
        .expect("swarm B");
    let (b_peer, b_device) = (b.peer_id, b.device_id);
    let addr_b = get_listen_addr(&b).await;
    a.dial(b_peer, addr_b.clone()).await.expect("dial B");
    wait_for_authenticated(&mut events_a, b_device).await;
    // Let the Kademlia bootstrap that B's arrival triggers run its course.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // B goes away: its event loop ends with the last handle, the connection
    // closes, and its port no longer listens.
    drop(b);
    drop(events_b);
    wait_for_closed(&mut events_a, b_peer).await;
    let (connected, authenticated) = a.peer_counts().await.expect("counts");
    assert_eq!((connected, authenticated), (0, 0), "A holds no link to B");

    let stranger = PeerId::random();
    let chosen = a
        .test_discovery_pass(vec![(b_peer, vec![addr_b]), (stranger, vec![hole])])
        .await;
    assert_eq!(
        chosen,
        vec![stranger],
        "A must dial only the stranger, not B it met before"
    );
}
