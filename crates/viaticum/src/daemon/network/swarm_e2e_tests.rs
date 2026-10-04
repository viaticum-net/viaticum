// Tests of the test-only swarm instruments (`e2e-tools`, C-DK Р-16): real
// swarms on loopback, like swarm_tests.rs.

use std::time::Duration;

use viaticum_core::messages::Message;
use viaticum_core::types::{DeviceId, Timestamp};

use super::swarm::{SwarmError, SwarmHandle};
use super::swarm_test_helpers::{get_listen_addr, make_swarm_config, wait_for_authenticated};

/// Poll until `handle` no longer lists `device` as authenticated (deadline 5 s).
async fn wait_not_authenticated(handle: &SwarmHandle, device: DeviceId) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let (auth, _) = handle.peer_sets().await.expect("peer_sets");
        if !auth.contains(&device) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "still authenticated after 5 s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// `net-probe disconnect` closes the link: BOTH sides drop the peer from
/// `authenticated`. Then `send_to_device` to it answers `PeerNotAuthenticated`
/// at once — the pre-C4 behaviour step 8a of local_discovery_test is
/// pre-registered RED on (no on-demand dial yet); C4 changes this assertion.
#[tokio::test]
async fn disconnect_device_drops_auth_on_both_sides() {
    let (a, mut events_a) = SwarmHandle::start(make_swarm_config(91))
        .await
        .expect("swarm A");
    let (b, mut events_b) = SwarmHandle::start(make_swarm_config(92))
        .await
        .expect("swarm B");
    a.dial(b.peer_id, get_listen_addr(&b).await)
        .await
        .expect("dial");
    wait_for_authenticated(&mut events_a, b.device_id).await;
    wait_for_authenticated(&mut events_b, a.device_id).await;

    assert!(a.disconnect_device(b.device_id).await.expect("disconnect"));
    wait_not_authenticated(&a, b.device_id).await;
    wait_not_authenticated(&b, a.device_id).await;

    let announce = Message::PeerAnnounce(a.build_peer_announce(Timestamp::now()));
    match a.send_to_device(b.device_id, announce).await {
        Err(SwarmError::PeerNotAuthenticated(d)) => assert_eq!(d, b.device_id),
        other => panic!("want PeerNotAuthenticated, got {other:?}"),
    }
}

/// Disconnecting a peer we have no link to is not an error: it reports `false`.
#[tokio::test]
async fn disconnect_device_without_connection_reports_false() {
    let (a, _events_a) = SwarmHandle::start(make_swarm_config(93))
        .await
        .expect("swarm A");
    let stranger = DeviceId(
        make_swarm_config(94)
            .device_signing_key
            .verifying_key()
            .to_bytes(),
    );
    assert!(!a.disconnect_device(stranger).await.expect("disconnect"));
}

/// The IPv4 listen address of `handle` (the v6 listener has another port).
async fn ipv4_listen_addr(handle: &SwarmHandle) -> libp2p::Multiaddr {
    use libp2p::multiaddr::Protocol;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let addrs = handle.listen_addrs().await.expect("listen_addrs");
        if let Some(a) = addrs
            .into_iter()
            .find(|a| matches!(a.iter().next(), Some(Protocol::Ip4(_))))
        {
            return a;
        }
        assert!(tokio::time::Instant::now() < deadline, "no IPv4 listener");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// C-DK Р-10 on the real path: the aliases a node advertises reach its peer
/// through identify (they are in the address set the peer keeps for it), and
/// they are working addresses — a third node authenticates it over one.
#[tokio::test]
async fn loopback_aliases_reach_the_peer_through_identify_and_work() {
    use super::e2e_amp::TEST_ALIAS_COUNT;
    use libp2p::multiaddr::Protocol;

    TEST_ALIAS_COUNT.with(|c| c.set(Some(3)));
    let (a, _events_a) = SwarmHandle::start(make_swarm_config(95))
        .await
        .expect("swarm A");
    TEST_ALIAS_COUNT.with(|c| c.set(None));
    let (b, mut events_b) = SwarmHandle::start(make_swarm_config(96))
        .await
        .expect("swarm B");
    let a_v4 = ipv4_listen_addr(&a).await;
    let port = a_v4
        .iter()
        .find_map(|p| match p {
            Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .expect("tcp port");
    let alias: libp2p::Multiaddr = format!("/ip4/127.0.0.3/tcp/{port}").parse().unwrap();

    b.dial(a.peer_id, a_v4).await.expect("dial");
    wait_for_authenticated(&mut events_b, a.device_id).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let known = b.get_peer_addrs(a.device_id).await;
        if known
            .iter()
            .any(|m| m.to_string().starts_with(&alias.to_string()))
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "B never learned alias {alias} of A through identify: {known:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (c, mut events_c) = SwarmHandle::start(make_swarm_config(97))
        .await
        .expect("swarm C");
    c.dial(a.peer_id, alias).await.expect("dial alias");
    wait_for_authenticated(&mut events_c, a.device_id).await;
}
