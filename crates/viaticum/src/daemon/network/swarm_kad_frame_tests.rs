// Guards of the Kademlia answer size (C-DK Р-3, Р-8; network-i18, i20).
//
// Our node S (a real SwarmHandle) is asked by a bare Kademlia client — a raw
// libp2p swarm speaking only our Kademlia protocol, like a stranger in the
// open network. S's table is filled through the identify feed (`feed_kad`)
// with peers announcing 30 addresses each. The answer must decode at the asker
// under the default 16 KiB frame: a regression of the feed cap (M1) or of the
// record filter (FilterBoth) makes it oversized and the asker records a failed
// request instead of a success.
//
// Fake peers' addresses point at a "black hole" listener (accepts TCP, never
// speaks): a refused dial would make libp2p drop the address from the record
// (`address_failed`) and shrink what we are measuring; a hanging one does not.

use std::collections::HashSet;
use std::time::Duration;

use futures::StreamExt;
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self, QueryId, QueryResult, QueryStats};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm};

use super::kad_feed::MAX_KAD_ADDRS_PER_PEER;
use super::swarm::{KAD_PROTOCOL, SwarmHandle};
use super::swarm_test_helpers::{get_listen_addr, make_swarm_config};

type RawKad = Swarm<kad::Behaviour<MemoryStore>>;

/// A TCP listener on every local address that accepts and never answers.
async fn black_hole_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .expect("bind black hole");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    port
}

/// A bare Kademlia node: TCP + Noise + Yamux and our Kademlia protocol only,
/// server mode, short query timeout (queries to the fake peers hang).
fn raw_kad() -> RawKad {
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
            let mut cfg = kad::Config::new(KAD_PROTOCOL);
            cfg.set_query_timeout(Duration::from_secs(5));
            let mut behaviour = kad::Behaviour::with_config(id, MemoryStore::new(id), cfg);
            behaviour.set_mode(Some(kad::Mode::Server));
            behaviour
        })
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build()
}

/// Drive `swarm` until query `qid` finishes; its last result and the stats.
async fn finish(swarm: &mut RawKad, qid: QueryId) -> (QueryResult, QueryStats) {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                id,
                result,
                stats,
                step,
            }) = swarm.select_next_some().await
                && id == qid
                && step.last
            {
                return (result, stats);
            }
        }
    })
    .await
    .expect("kad query finished in 30 s")
}

/// Thirty loopback addresses of the black hole, as a fat identify announces.
fn fat_announce(black_hole: u16) -> Vec<Multiaddr> {
    (2..32)
        .map(|k| {
            format!("/ip4/127.0.0.{k}/tcp/{black_hole}")
                .parse()
                .expect("ma")
        })
        .collect()
}

/// Feed `n` random peers with fat announcements to `s` by the identify path;
/// every record must come out capped (network-i18).
async fn feed_fat_peers(s: &SwarmHandle, n: usize) {
    let bh = black_hole_port().await;
    for _ in 0..n {
        let held = s.test_feed_kad(PeerId::random(), fat_announce(bh)).await;
        assert_eq!(
            held.len(),
            MAX_KAD_ADDRS_PER_PEER,
            "network-i18: the feed caps the record"
        );
    }
}

/// Drive `swarm` for `dur` (lets queued requests reach the wire).
async fn drive_for(swarm: &mut RawKad, dur: Duration) {
    let deadline = tokio::time::Instant::now() + dur;
    while tokio::time::timeout_at(deadline, swarm.select_next_some())
        .await
        .is_ok()
    {}
}

/// A raw client that knows S at `addr`.
fn client_of(s: &SwarmHandle, addr: &Multiaddr) -> RawKad {
    let mut client = raw_kad();
    client.behaviour_mut().add_address(&s.peer_id, addr.clone());
    client
}

/// network-i18, i20: FIND_NODE to a node whose 25 peers announce 30 addresses
/// each is answered with a frame the asker decodes. M1 (feed without the cap)
/// → S's answer ≈ 20 × 30 × 51 B > 16 KiB → no success.
#[tokio::test]
async fn closest_peers_answer_fits_when_peers_have_many_addrs() {
    let (s, _events) = SwarmHandle::start(make_swarm_config(111))
        .await
        .expect("swarm S");
    feed_fat_peers(&s, 25).await;
    let addr = get_listen_addr(&s).await;
    let mut client = client_of(&s, &addr);
    let qid = client.behaviour_mut().get_closest_peers(PeerId::random());
    let (_result, stats) = finish(&mut client, qid).await;
    assert!(
        stats.num_successes() >= 1,
        "S's FIND_NODE answer did not decode: requests={} failures={}",
        stats.num_requests(),
        stats.num_failures()
    );
}

/// network-i20: FIND_NODE to a node whose 25 peers each announce five
/// 255-character DNS names (≈ 300 B each, Global rank, a 4 KiB identify holds
/// them) is answered with a frame the asker decodes: the names are over
/// MAX_KAD_ADDR_BYTES and never reach the table, so the answer stays small
/// however few addresses there are. M (byte limits off) → each record holds the
/// five names first (rank, cap 6) → ≈ 20 × 1.5 KB > 16 KiB → no success.
///
/// The sixth address is the black hole on loopback: S has no DNS transport,
/// and when its Kademlia bootstrap dials a peer whose record is ONLY such names
/// the dial fails at once and libp2p strips all but one of them
/// (`address_failed`), hiding the regression; a dial that hangs on the black
/// hole fails nothing during the test.
#[tokio::test]
async fn closest_peers_answer_fits_when_peers_announce_long_dns_names() {
    let (s, _events) = SwarmHandle::start(make_swarm_config(115))
        .await
        .expect("swarm S");
    let bh = black_hole_port().await;
    for _ in 0..25 {
        let mut announce: Vec<Multiaddr> = (0..5)
            .map(|k| {
                format!("/dns4/{}{k}/tcp/4001", "a".repeat(254))
                    .parse()
                    .expect("ma")
            })
            .collect();
        let hole: Multiaddr = format!("/ip4/127.0.0.2/tcp/{bh}").parse().expect("ma");
        announce.push(hole.clone());
        let peer = PeerId::random();
        let held = s.test_feed_kad(peer, announce).await;
        assert!(
            held.contains(&hole.with(libp2p::multiaddr::Protocol::P2p(peer))),
            "the peer is in S's table: {held:?}"
        );
    }
    let addr = get_listen_addr(&s).await;
    let mut client = client_of(&s, &addr);
    let qid = client.behaviour_mut().get_closest_peers(PeerId::random());
    let (_result, stats) = finish(&mut client, qid).await;
    assert!(
        stats.num_successes() >= 1,
        "S's FIND_NODE answer did not decode: requests={} failures={}",
        stats.num_requests(),
        stats.num_failures()
    );
}

/// network-i20: a stranger publishes a provider record with ~13 KB of
/// addresses (ADD_PROVIDER fits the frame), another asks GET_PROVIDERS. With
/// FilterBoth S stores nothing, so its answer carries only the closer peers and
/// decodes; with the record stored (StoreInserts::Unfiltered) the answer would
/// be ≈ 13 KB + 20 closer peers > 16 KiB.
#[tokio::test]
async fn get_providers_answer_fits_when_peers_have_many_addrs() {
    let (s, _events) = SwarmHandle::start(make_swarm_config(112))
        .await
        .expect("swarm S");
    let addr = get_listen_addr(&s).await;
    let key = kad::RecordKey::new(&[7u8; 32]);

    // The publisher announces 20 external addresses (libp2p's limit) of ~650 B.
    let mut publisher = client_of(&s, &addr);
    for k in 0..20 {
        let fat: Multiaddr = format!("/dns4/{}{k}.example/tcp/1", "a".repeat(640))
            .parse()
            .expect("ma");
        publisher.add_external_address(fat);
    }
    let qid = publisher
        .behaviour_mut()
        .start_providing(key.clone())
        .expect("start_providing");
    let (result, _) = finish(&mut publisher, qid).await;
    assert!(
        matches!(result, QueryResult::StartProviding(Ok(_))),
        "ADD_PROVIDER sent to S: {result:?}"
    );
    // Let the ADD_PROVIDER reach S before anyone asks.
    drive_for(&mut publisher, Duration::from_millis(500)).await;

    // Twenty-five peers with fat records, so the closer-peer part is full.
    feed_fat_peers(&s, 25).await;

    let mut asker = client_of(&s, &addr);
    let qid = asker.behaviour_mut().get_providers(key);
    let (_result, stats) = finish(&mut asker, qid).await;
    assert!(
        stats.num_successes() >= 1,
        "S's GET_PROVIDERS answer did not decode: requests={} failures={}",
        stats.num_requests(),
        stats.num_failures()
    );
}

/// S runs Kademlia in server mode: a foreign client's FIND_NODE gets an answer
/// (replaces the old provider-based `kademlia_mode_is_server`).
#[tokio::test]
async fn server_mode_answers_foreign_find_node() {
    let (s, _events) = SwarmHandle::start(make_swarm_config(113))
        .await
        .expect("swarm S");
    let addr = get_listen_addr(&s).await;
    let mut client = client_of(&s, &addr);
    let qid = client.behaviour_mut().get_closest_peers(PeerId::random());
    let (result, stats) = finish(&mut client, qid).await;
    assert!(stats.num_successes() >= 1, "S did not answer FIND_NODE");
    match result {
        QueryResult::GetClosestPeers(Ok(ok)) => assert!(
            ok.peers.iter().any(|p| p.peer_id == s.peer_id),
            "S is among the peers that answered: {:?}",
            ok.peers
        ),
        other => panic!("want GetClosestPeers(Ok), got {other:?}"),
    }
}

/// Wait until Kademlia has reported `peer` as a new table entry `n` times.
async fn wait_new_peer_events(s: &SwarmHandle, peer: PeerId, n: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while s.test_kad_new_peer_count(peer).await < n {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("RoutingUpdated reached the swarm loop in 5 s");
}

/// network-i18 (W7): a peer restarted on a new port; its next identify
/// replaces the stale addresses in our record instead of piling up next to them
/// — and the peer stays in the table the whole time: no second
/// `RoutingUpdated { is_new_peer: true }`. Removing first (M: remove before
/// add) empties the record: libp2p drops the peer (`remove_address` on its
/// last address) and the add that follows inserts it again. The final address
/// set is the same, and in a bucket with room the peer loses nothing — it lands
/// at the most-recent end. The harm is elsewhere: Kademlia reports a false new
/// peer (`is_new_peer: true`) and may start an automatic bootstrap
/// (`bootstrap_on_low_peers`); and in a full bucket the re-insert is not
/// immediate — the peer becomes the bucket's pending entry, or, when another
/// peer is already pending, gets `Full` and drops out of the table. On a seed
/// (friends dial in, so no dialed address protects the record) that is a
/// friend gone from the routing table until its next identify.
#[tokio::test]
async fn identify_with_new_port_replaces_stale_kad_addrs() {
    let (s, _events) = SwarmHandle::start(make_swarm_config(114))
        .await
        .expect("swarm S");
    let (old_port, new_port) = (black_hole_port().await, black_hole_port().await);
    let peer = PeerId::random();
    // Loopback only: a refused or unroutable address would be dropped by
    // libp2p itself when S dials the peer, not by the feed.
    let on = |port: u16| -> Vec<Multiaddr> {
        ["127.0.0.5", "127.0.0.6", "127.0.0.1"]
            .iter()
            .map(|ip| format!("/ip4/{ip}/tcp/{port}").parse().expect("ma"))
            .collect()
    };
    let before = s.test_feed_kad(peer, on(old_port)).await;
    assert_eq!(before.len(), 3);
    wait_new_peer_events(&s, peer, 1).await;

    let after = s.test_feed_kad(peer, on(new_port)).await;
    // Barrier: Kademlia queues its events in order, so once a peer fed after
    // the second feed is reported, any event of that feed has been seen.
    let barrier = PeerId::random();
    s.test_feed_kad(barrier, on(old_port)).await;
    wait_new_peer_events(&s, barrier, 1).await;

    let want: HashSet<Multiaddr> = on(new_port)
        .into_iter()
        .map(|a| a.with(libp2p::multiaddr::Protocol::P2p(peer)))
        .collect();
    let got: HashSet<Multiaddr> = after.into_iter().collect();
    assert_eq!(got, want, "only the new port's addresses remain");
    assert_eq!(
        s.test_kad_new_peer_count(peer).await,
        1,
        "the peer left the table while its addresses were replaced"
    );
}
