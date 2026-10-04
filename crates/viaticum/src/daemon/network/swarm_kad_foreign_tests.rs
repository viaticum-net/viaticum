// Our DHT is separate from IPFS by construction (network-i17, C-DK Р-1).
//
// The foreign node F is a raw libp2p swarm built like an IPFS node: identify
// (its stream protocol is `/ipfs/id/1.0.0` for everyone, ours included, so F's
// identify DOES reach our node, announcing F's listen address and its
// Kademlia protocol) and Kademlia under IPFS's name `/ipfs/kad/1.0.0`.
//
// Doors and the mutations that open them:
//   - identify (`foreign_ipfs_kad_peer_is_not_routed`): S dials F, so S holds
//     an address of F and anything that wants F in the table has one to put
//     there. S feeds Kademlia only from peers announcing OUR protocol; without
//     that check (M6) F's identify puts F into S's table. S's own lookup runs
//     (it reaches S's Viaticum peer B) and never returns F;
//   - an incoming connection and Kademlia request
//     (`foreign_kad_query_is_not_answered`): F dials S and asks it over
//     `/ipfs/kad/1.0.0` — no answer, and F is not fed into S's table either
//     (a check that trusts peers we did not dial ourselves is caught here);
//   - the circle's bootstrap list (`foreign_bootstrap_peer_is_dropped_after_identify`):
//     a foreign address in `kademlia_bootstrap_peers` is in S's table from the
//     start; S's identify handler removes it, so S never hands F to friends
//     (M: `remove_peer` dropped → F stays and B, bootstrapping from S, dials F);
//   - the protocol name: with S on `/ipfs/kad/1.0.0` (M5) the first two tests
//     go red — S answers F, Kademlia itself confirms F into S's table, S's
//     lookup returns F.

use std::time::Duration;

use futures::StreamExt;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self, QueryResult};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, StreamProtocol, Swarm};

use super::swarm::SwarmHandle;
use super::swarm_test_helpers::{get_listen_addr, make_swarm_config};

/// IPFS's Kademlia protocol name: not ours (network-i17).
const IPFS_KAD: StreamProtocol = StreamProtocol::new("/ipfs/kad/1.0.0");

#[derive(libp2p::swarm::NetworkBehaviour)]
struct ForeignBehaviour {
    identify: libp2p::identify::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
}

type Foreign = Swarm<ForeignBehaviour>;

/// A node of another Kademlia network: TCP + Noise + Yamux, identify, and
/// Kademlia (server mode) under `/ipfs/kad/1.0.0`.
fn foreign_node() -> Foreign {
    libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .expect("tcp")
        .with_behaviour(|key| {
            let id = key.public().to_peer_id();
            let mut cfg = kad::Config::new(IPFS_KAD);
            cfg.set_query_timeout(Duration::from_secs(5));
            let mut kad = kad::Behaviour::with_config(id, MemoryStore::new(id), cfg);
            kad.set_mode(Some(kad::Mode::Server));
            ForeignBehaviour {
                identify: libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
                    "ipfs/0.1.0".to_string(),
                    key.public(),
                )),
                kad,
            }
        })
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build()
}

/// Drive `f` until `pick` returns something for one of its events (≤ 15 s).
async fn drive_until<T>(
    f: &mut Foreign,
    what: &str,
    mut pick: impl FnMut(SwarmEvent<ForeignBehaviourEvent>) -> Option<T>,
) -> T {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(found) = pick(f.select_next_some().await) {
                return found;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("foreign node: {what} within 15 s"))
}

/// Drive `f` until its query `qid` finishes; the result and the stats.
async fn finish_query(f: &mut Foreign, qid: kad::QueryId) -> (QueryResult, kad::QueryStats) {
    drive_until(f, "its FIND_NODE query finished", |e| match e {
        SwarmEvent::Behaviour(ForeignBehaviourEvent::Kad(
            kad::Event::OutboundQueryProgressed {
                id,
                result,
                stats,
                step,
            },
        )) if id == qid && step.last => Some((result, stats)),
        _ => None,
    })
    .await
}

/// network-i17: an IPFS Kademlia node connected to our node is not routed by
/// it — not in our table, not returned by our lookups.
/// M6 (identify feeds Kademlia without the protocol check) → F in S's table.
/// M5 (our name back to `/ipfs/kad/1.0.0`) → F in S's table and in S's lookup
/// result.
#[tokio::test]
async fn foreign_ipfs_kad_peer_is_not_routed() {
    // B: one of ours, S's Kademlia bootstrap peer — S's lookups have someone
    // to ask, so an empty answer cannot pass for "F not returned".
    let (b, _b_events) = SwarmHandle::start(make_swarm_config(118))
        .await
        .expect("swarm B");
    let b_addr = get_listen_addr(&b).await;
    let mut s_cfg = make_swarm_config(119);
    s_cfg.kademlia_bootstrap_peers = vec![b_addr.with(libp2p::multiaddr::Protocol::P2p(b.peer_id))];
    let (s, _s_events) = SwarmHandle::start(s_cfg).await.expect("swarm S");

    let mut f = foreign_node();
    let f_id = *f.local_peer_id();
    f.listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("ma"))
        .expect("listen");
    let f_addr: Multiaddr = drive_until(&mut f, "a listen address", |e| match e {
        SwarmEvent::NewListenAddr { address, .. } => Some(address),
        _ => None,
    })
    .await;

    // S dials F; both identify each other. F's `Sent` = S has F's identify
    // (listen address + `/ipfs/kad/1.0.0` among the protocols).
    s.dial(f_id, f_addr).await.expect("dial F");
    let s_id = s.peer_id;
    drive_until(&mut f, "its identify sent to S", |e| match e {
        SwarmEvent::Behaviour(ForeignBehaviourEvent::Identify(libp2p::identify::Event::Sent {
            peer_id,
            ..
        })) if peer_id == s_id => Some(()),
        _ => None,
    })
    .await;

    // From here on F only has to stay alive and answer whatever reaches it
    // (with M5, S's lookup asks F).
    let f_task = tokio::spawn(async move {
        loop {
            f.select_next_some().await;
        }
    });

    // F never enters S's table: a fed (identify) or confirmed (Kademlia)
    // entry shows within milliseconds of the identify — watch for 2 s.
    assert_never_in_table(&s, f_id, Duration::from_secs(2)).await;

    // S's lookup runs (B answers) and does not return F.
    let found = s
        .get_closest_peers(f_id.to_bytes())
        .await
        .expect("S's lookup finished");
    let ids: Vec<PeerId> = found.iter().map(|(p, _)| *p).collect();
    assert!(
        ids.contains(&b.peer_id),
        "S's lookup reached its Viaticum peer B: {ids:?}"
    );
    assert!(
        !ids.contains(&f_id),
        "network-i17: our lookup handed out the IPFS node: {ids:?}"
    );

    f_task.abort();
}

/// Watch S's table for `dur`: `peer` must never be in it.
async fn assert_never_in_table(s: &SwarmHandle, peer: PeerId, dur: Duration) {
    let deadline = tokio::time::Instant::now() + dur;
    while tokio::time::Instant::now() < deadline {
        let held = s.test_kad_addrs(peer).await;
        assert!(
            held.is_empty(),
            "network-i17: the IPFS node is in our Kademlia table: {held:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// network-i17: our node does not answer a FIND_NODE asked over IPFS's
/// Kademlia, and a foreign node that dials US is not fed into our table either.
/// The exchange is checked to have happened first: F is connected to S, F got
/// S's identify (our Kademlia, not IPFS's) and S got F's. M5 → answered.
/// M (the protocol check skipped for peers we did not dial) → F in S's table.
#[tokio::test]
async fn foreign_kad_query_is_not_answered() {
    let (s, _events) = SwarmHandle::start(make_swarm_config(120))
        .await
        .expect("swarm S");
    let s_addr = get_listen_addr(&s).await;
    let s_id = s.peer_id;
    let mut f = foreign_node();
    let f_id = *f.local_peer_id();
    // F listens, so its identify carries an address S could put in a table.
    f.listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("ma"))
        .expect("listen");
    f.dial(s_addr.clone()).expect("F dials S");
    let (mut connected, mut got, mut sent) = (false, false, false);
    drive_until(&mut f, "connected to S, identify both ways", |e| {
        match e {
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == s_id => {
                connected = true
            }
            SwarmEvent::Behaviour(ForeignBehaviourEvent::Identify(
                libp2p::identify::Event::Received { peer_id, info, .. },
            )) if peer_id == s_id => {
                assert!(
                    info.protocols
                        .contains(&StreamProtocol::new("/viaticum/kad/1.0.0")),
                    "S announces our Kademlia: {:?}",
                    info.protocols
                );
                assert!(
                    !info.protocols.contains(&IPFS_KAD),
                    "S announces IPFS's Kademlia: {:?}",
                    info.protocols
                );
                got = true
            }
            SwarmEvent::Behaviour(ForeignBehaviourEvent::Identify(
                libp2p::identify::Event::Sent { peer_id, .. },
            )) if peer_id == s_id => sent = true,
            _ => {}
        }
        (connected && got && sent).then_some(())
    })
    .await;

    f.behaviour_mut().kad.add_address(&s_id, s_addr);
    let qid = f.behaviour_mut().kad.get_closest_peers(PeerId::random());
    let (result, stats) = finish_query(&mut f, qid).await;
    assert!(stats.num_requests() >= 1, "F's query reached S");
    assert_eq!(
        stats.num_successes(),
        0,
        "S answered a FIND_NODE on /ipfs/kad/1.0.0"
    );
    match result {
        QueryResult::GetClosestPeers(Ok(ok)) => assert!(
            !ok.peers.iter().any(|p| p.peer_id == s_id),
            "S is among the peers that answered: {:?}",
            ok.peers
        ),
        QueryResult::GetClosestPeers(Err(_)) => {}
        other => panic!("want GetClosestPeers, got {other:?}"),
    }
    let f_task = tokio::spawn(async move {
        loop {
            f.select_next_some().await;
        }
    });
    assert_never_in_table(&s, f_id, Duration::from_secs(1)).await;
    f_task.abort();
}

/// What the foreign node saw, forwarded from its driving task.
#[derive(Debug)]
enum Seen {
    /// A connection some peer opened TO F.
    Inbound(PeerId),
    /// F answered this peer's identify request (the peer has F's identify).
    IdentifySent(PeerId),
}

/// Drive `f` in a task, forwarding inbound connections and identify answers.
fn spawn_foreign(
    mut f: Foreign,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::UnboundedReceiver<Seen>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let seen = match f.select_next_some().await {
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } if endpoint.is_listener() => Seen::Inbound(peer_id),
                SwarmEvent::Behaviour(ForeignBehaviourEvent::Identify(
                    libp2p::identify::Event::Sent { peer_id, .. },
                )) => Seen::IdentifySent(peer_id),
                _ => continue,
            };
            if tx.send(seen).is_err() {
                return;
            }
        }
    });
    (task, rx)
}

/// network-i17, the bootstrap-list boundary: a friend wrote an IPFS node F
/// into S's `kademlia_bootstrap_peers`. F gets S's start-up dial and is in S's
/// table until its identify, then dropped; it is never handed to other peers.
/// B (bootstrap = S) runs a lookup through S: it reaches S, never returns F,
/// and F never sees a connection from B. M (`remove_peer` dropped) → F stays in
/// S's table, S's FIND_NODE answer hands it to B, B dials F.
#[tokio::test]
async fn foreign_bootstrap_peer_is_dropped_after_identify() {
    let mut f = foreign_node();
    let f_id = *f.local_peer_id();
    f.listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("ma"))
        .expect("listen");
    let f_addr: Multiaddr = drive_until(&mut f, "a listen address", |e| match e {
        SwarmEvent::NewListenAddr { address, .. } => Some(address),
        _ => None,
    })
    .await;
    let (f_task, mut seen) = spawn_foreign(f);

    let mut s_cfg = make_swarm_config(121);
    s_cfg.kademlia_bootstrap_peers = vec![f_addr.with(libp2p::multiaddr::Protocol::P2p(f_id))];
    let (s, _s_events) = SwarmHandle::start(s_cfg).await.expect("swarm S");
    let s_id = s.peer_id;
    let s_addr = get_listen_addr(&s).await;

    // S's start-up bootstrap dials F; F's identify reaches S.
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(event) = seen.recv().await {
            if matches!(event, Seen::IdentifySent(p) if p == s_id) {
                return;
            }
        }
    })
    .await
    .expect("S dialed its bootstrap peer F and got F's identify within 15 s");

    // ... and S drops F from its table.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let held = s.test_kad_addrs(f_id).await;
        if held.is_empty() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "network-i17: the IPFS bootstrap peer is still in our table 5 s after its identify: {held:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // A friend bootstrapping from S, then looking up F's id through S.
    let mut b_cfg = make_swarm_config(122);
    b_cfg.kademlia_bootstrap_peers = vec![s_addr.with(libp2p::multiaddr::Protocol::P2p(s_id))];
    let (b, _b_events) = SwarmHandle::start(b_cfg).await.expect("swarm B");
    let found = b
        .get_closest_peers(f_id.to_bytes())
        .await
        .expect("B's lookup finished");
    let ids: Vec<PeerId> = found.iter().map(|(p, _)| *p).collect();
    assert!(ids.contains(&s_id), "B's lookup reached S: {ids:?}");
    assert!(
        !ids.contains(&f_id),
        "network-i17: S handed the IPFS node to B: {ids:?}"
    );
    // Give a dial B might have started a moment to land, then read what F saw.
    tokio::time::sleep(Duration::from_millis(500)).await;
    while let Ok(event) = seen.try_recv() {
        assert!(
            !matches!(event, Seen::Inbound(p) if p == b.peer_id),
            "network-i17: B dialed the IPFS node S knew of"
        );
    }
    f_task.abort();
}
