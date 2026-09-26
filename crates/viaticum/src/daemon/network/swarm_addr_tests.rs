// Tests for the addresses the swarm hands out (network-i2, network-i4):
// normalization to one `/p2p/<peer_id>` suffix, and the dialed address being
// part of PeerAuthenticated / GetPeerAddrs.

use std::time::Duration;

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use tokio::time::timeout;
use viaticum_core::types::DeviceId;

use super::swarm_test_helpers::{get_listen_addr, make_swarm_config, wait_for_authenticated};
use crate::daemon::network::swarm::{
    ProtocolEvent, SwarmHandle, device_id_to_peer_id, normalize_peer_addrs, strip_peer_suffix,
};

fn peer_of(seed: u8) -> PeerId {
    let key = make_swarm_config(seed).device_signing_key;
    device_id_to_peer_id(&DeviceId(key.verifying_key().to_bytes())).unwrap()
}

/// Exactly one terminal `/p2p/<expected>` component.
fn has_single_suffix(addr: &Multiaddr, expected: PeerId) -> bool {
    let p2p: Vec<PeerId> = addr
        .iter()
        .filter_map(|p| match p {
            Protocol::P2p(id) => Some(id),
            _ => None,
        })
        .collect();
    p2p == vec![expected] && matches!(addr.iter().last(), Some(Protocol::P2p(id)) if id == expected)
}

// ─── Pure normalization ───────────────────────────────────────────────────────

#[test]
fn normalize_peer_addrs_adds_single_suffix_dedups_and_drops_foreign() {
    let me = peer_of(81);
    let other = peer_of(82);
    let bare: Multiaddr = "/ip4/10.0.0.1/tcp/4001".parse().unwrap();
    let suffixed = bare.clone().with(Protocol::P2p(me));
    let doubled = suffixed.clone().with(Protocol::P2p(me));
    let foreign: Multiaddr = "/ip4/10.0.0.2/tcp/4001"
        .parse::<Multiaddr>()
        .unwrap()
        .with(Protocol::P2p(other));
    let lan: Multiaddr = "/ip4/192.168.0.5/tcp/4001".parse().unwrap();

    let out = normalize_peer_addrs(me, [&bare, &suffixed, &doubled, &foreign, &lan]);

    assert_eq!(
        out,
        vec![suffixed.clone(), lan.clone().with(Protocol::P2p(me))],
        "bare/suffixed/doubled collapse into one entry; foreign is dropped; order kept"
    );
    assert!(out.iter().all(|a| has_single_suffix(a, me)));
}

/// network-i4 (union): the dialed address comes first and survives next to the
/// identify list, even when identify reports only private addresses.
#[test]
fn normalize_peer_addrs_keeps_dialed_addr_alongside_identify_addrs() {
    let me = peer_of(83);
    let dialed: Multiaddr = "/ip4/203.0.113.7/tcp/4001".parse().unwrap();
    let identify: Vec<Multiaddr> = vec![
        "/ip4/192.168.1.10/tcp/4001".parse().unwrap(),
        "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
    ];

    let out = normalize_peer_addrs(me, std::iter::once(&dialed).chain(identify.iter()));

    assert_eq!(out.len(), 3);
    assert_eq!(out[0], dialed.with(Protocol::P2p(me)));
}

/// Only the terminal `/p2p/` identifies the target: a relay-circuit address
/// carries the relay's id in the middle and must stay dialable.
#[test]
fn strip_peer_suffix_keeps_relay_circuit_addr_and_rejects_foreign_target() {
    let me = peer_of(84);
    let relay = peer_of(85);
    let circuit: Multiaddr = "/ip4/198.51.100.1/tcp/4001"
        .parse::<Multiaddr>()
        .unwrap()
        .with(Protocol::P2p(relay))
        .with(Protocol::P2pCircuit);

    assert_eq!(strip_peer_suffix(&circuit, me), Ok(circuit.clone()));
    assert_eq!(
        strip_peer_suffix(&circuit.clone().with(Protocol::P2p(me)), me),
        Ok(circuit.clone())
    );
    assert_eq!(
        strip_peer_suffix(&circuit.clone().with(Protocol::P2p(relay)), me),
        Err(relay),
        "a circuit whose target is another peer is not a route to `me`"
    );
}

// ─── Swarm integration (two swarms on loopback) ───────────────────────────────

/// The dialer's PeerAuthenticated carries the address it dialed, with the
/// listener's `/p2p/` suffix — independent of whether identify arrived first.
#[tokio::test]
async fn peer_authenticated_carries_dialed_addr_with_p2p_suffix() {
    let (handle_a, _events_a) = SwarmHandle::start(make_swarm_config(86))
        .await
        .expect("swarm A");
    let (handle_b, mut events_b) = SwarmHandle::start(make_swarm_config(87))
        .await
        .expect("swarm B");
    let addr_a = get_listen_addr(&handle_a).await;

    handle_b
        .dial(handle_a.peer_id, addr_a.clone())
        .await
        .expect("dial");
    let ev = wait_for_authenticated(&mut events_b, handle_a.device_id).await;

    let ProtocolEvent::PeerAuthenticated { listen_addrs, .. } = ev else {
        panic!("expected PeerAuthenticated");
    };
    let expected = addr_a.with(Protocol::P2p(handle_a.peer_id));
    assert!(
        listen_addrs.contains(&expected),
        "dialed address {expected} missing from {listen_addrs:?}"
    );
    assert!(
        listen_addrs
            .iter()
            .all(|a| has_single_suffix(a, handle_a.peer_id)),
        "every address must end in exactly one /p2p/<A>: {listen_addrs:?}"
    );
}

/// GetPeerAddrs hands out normalized addresses on both sides: the dialer (from
/// the dialed address) and the listener (from identify, which reports bare
/// listen addrs without `/p2p/`).
#[tokio::test]
async fn get_peer_addrs_returns_p2p_suffixed_addrs() {
    let (handle_a, mut events_a) = SwarmHandle::start(make_swarm_config(88))
        .await
        .expect("swarm A");
    let (handle_b, mut events_b) = SwarmHandle::start(make_swarm_config(89))
        .await
        .expect("swarm B");
    let addr_a = get_listen_addr(&handle_a).await;
    handle_b
        .dial(handle_a.peer_id, addr_a.clone())
        .await
        .expect("dial");
    wait_for_authenticated(&mut events_b, handle_a.device_id).await;
    wait_for_authenticated(&mut events_a, handle_b.device_id).await;

    // Dialer side: available right after authentication.
    let from_b = handle_b.get_peer_addrs(handle_a.device_id).await;
    assert!(from_b.contains(&addr_a.with(Protocol::P2p(handle_a.peer_id))));
    assert!(
        from_b
            .iter()
            .all(|a| has_single_suffix(a, handle_a.peer_id)),
        "{from_b:?}"
    );

    // Listener side: only identify knows B's addresses; poll until it arrives.
    let from_a = timeout(Duration::from_secs(5), async {
        loop {
            let addrs = handle_a.get_peer_addrs(handle_b.device_id).await;
            if !addrs.is_empty() {
                return addrs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("identify addrs of B never reached A");
    assert!(
        from_a
            .iter()
            .all(|a| has_single_suffix(a, handle_b.peer_id)),
        "{from_a:?}"
    );
}
