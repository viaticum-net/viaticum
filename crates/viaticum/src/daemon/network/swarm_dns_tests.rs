// network-i28 (R2a): a seed named by DNS is dialed through the DNS transport.
// `localhost` resolves without a DNS server (RFC 6761, the resolver answers it
// itself), so the test touches no network.

use std::time::Duration;

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use viaticum_core::types::DeviceId;

use super::swarm_test_helpers::make_swarm_config;
use crate::daemon::network::swarm::{ProtocolEvent, SwarmHandle};

/// The TCP port of `handle`'s IPv4 listener (wait up to 2 s for it).
async fn ipv4_tcp_port(handle: &SwarmHandle) -> u16 {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let addrs = handle.listen_addrs().await.expect("listen_addrs");
        for addr in &addrs {
            let mut it = addr.iter();
            if let (Some(Protocol::Ip4(_)), Some(Protocol::Tcp(port))) = (it.next(), it.next()) {
                return port;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no IPv4 TCP listen address within 2 s: {addrs:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// Mutation: drop `.with_dns()` from the transport → the /dns4 address is not
// supported, B never reaches A, test red.
#[tokio::test]
async fn dns_bootstrap_resolves_localhost_tcp() {
    let cfg_a = make_swarm_config(41);
    let device_a = DeviceId(cfg_a.device_signing_key.verifying_key().to_bytes());
    let (handle_a, _events_a) = SwarmHandle::start(cfg_a).await.expect("swarm A");
    let port = ipv4_tcp_port(&handle_a).await;

    let seed: Multiaddr = format!("/dns4/localhost/tcp/{port}/p2p/{}", handle_a.peer_id)
        .parse()
        .expect("a DNS multiaddr");
    let mut cfg_b = make_swarm_config(42);
    cfg_b.kademlia_bootstrap_peers = vec![seed];
    cfg_b.kad_discovery_interval_override = Some(Duration::from_millis(200));
    let (_handle_b, mut events_b) = SwarmHandle::start(cfg_b).await.expect("swarm B");

    // B's only way to A is the DNS name: the Kademlia bootstrap dials it.
    let met = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(ev) = events_b.recv().await {
            if let ProtocolEvent::PeerAuthenticated { device_id, .. } = ev
                && device_id == device_a
            {
                return true;
            }
        }
        false
    })
    .await;
    assert!(
        matches!(met, Ok(true)),
        "B did not authenticate A via /dns4/localhost"
    );
}
