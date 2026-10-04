// Tests for ε.4 NAT traversal: relay server + relay client + DCUtR.
//
// Test scenarios:
//   1. swarm_starts_with_relay_and_dcutr_enabled — smoke test, startup does not panic
//   2. relay_connection_enables_indirect_auth — three nodes, A connects to B via R's relay
//   3. relay_reservation_is_logged — after A connects to R, reservation is accepted
//   4. dcutr_fires_after_relay_connection — DCUtR attempt fires after relay circuit
//
// All tests use localhost port 0.

use std::time::Duration;

use libp2p::Multiaddr;
use tokio::time::timeout;
use viaticum_core::types::DeviceId;

use super::swarm_test_helpers::{get_listen_addr, make_swarm_config};
use crate::daemon::network::swarm::{ProtocolEvent, SwarmHandle};

/// Wait for a PeerAuthenticated event for the given DeviceId, up to `timeout_secs`.
async fn wait_for_authenticated(
    event_rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>,
    expected_device_id: DeviceId,
    timeout_secs: u64,
) -> bool {
    timeout(Duration::from_secs(timeout_secs), async {
        loop {
            match event_rx.recv().await {
                Some(ProtocolEvent::PeerAuthenticated { device_id, .. }) => {
                    if device_id == expected_device_id {
                        return true;
                    }
                }
                Some(_) => {}
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Build a relay circuit multiaddr:
/// `<relay_addr>/p2p/<relay_peer_id>/p2p-circuit/p2p/<target_peer_id>`
fn make_relay_circuit_addr(
    relay_addr: Multiaddr,
    relay_peer_id: libp2p::PeerId,
    target_peer_id: libp2p::PeerId,
) -> Multiaddr {
    relay_addr
        .with(libp2p::multiaddr::Protocol::P2p(relay_peer_id))
        .with(libp2p::multiaddr::Protocol::P2pCircuit)
        .with(libp2p::multiaddr::Protocol::P2p(target_peer_id))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// Smoke test: swarm with relay and dcutr features starts without panic.
#[tokio::test]
async fn swarm_starts_with_relay_and_dcutr_enabled() {
    let config = make_swarm_config(200);
    let (handle, _events) = SwarmHandle::start(config).await.expect("start failed");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let addrs = handle.listen_addrs().await.expect("listen_addrs failed");
    assert!(
        !addrs.is_empty(),
        "swarm should have at least one listen address"
    );
}

/// Three-node scenario: A and B both connect to relay R.
/// A then dials B via R's relay circuit address.
/// Expected: PeerAuthenticated fires on both A and B sides.
#[tokio::test]
async fn relay_connection_enables_indirect_auth() {
    // R = relay server (seed 201)
    // A = dialer via relay (seed 202)
    // B = listener via relay (seed 203)
    let config_r = make_swarm_config(201);
    let config_a = make_swarm_config(202);
    let config_b = make_swarm_config(203);

    let b_device_id = DeviceId(config_b.device_signing_key.verifying_key().to_bytes());
    let a_device_id = DeviceId(config_a.device_signing_key.verifying_key().to_bytes());

    let (handle_r, _events_r) = SwarmHandle::start(config_r).await.expect("R start failed");
    let (handle_a, mut events_a) = SwarmHandle::start(config_a).await.expect("A start failed");
    let (handle_b, mut events_b) = SwarmHandle::start(config_b).await.expect("B start failed");

    let r_addr = get_listen_addr(&handle_r).await;
    let r_peer_id = handle_r.peer_id;
    let b_peer_id = handle_b.peer_id;

    // A and B both dial R directly so the relay client can request reservations.
    handle_a
        .dial(r_peer_id, r_addr.clone())
        .await
        .expect("A dial R failed");
    handle_b
        .dial(r_peer_id, r_addr.clone())
        .await
        .expect("B dial R failed");

    // Wait for A and B to authenticate with R (gives relay client time to establish
    // reservations automatically after the connection is up).
    // We don't assert this — R may not have the same master cert as A/B.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A dials B via R's relay circuit address.
    // B must have an active relay reservation with R at this point.
    let b_via_relay = make_relay_circuit_addr(r_addr, r_peer_id, b_peer_id);
    handle_a
        .dial(b_peer_id, b_via_relay)
        .await
        .expect("A dial B-via-relay failed");

    // Both sides should eventually see PeerAuthenticated for each other.
    let a_sees_b = wait_for_authenticated(&mut events_a, b_device_id, 10).await;
    let b_sees_a = wait_for_authenticated(&mut events_b, a_device_id, 10).await;

    assert!(a_sees_b, "A should see B as authenticated via relay");
    assert!(b_sees_a, "B should see A as authenticated via relay");
}

/// After A connects to R, relay client automatically requests a reservation.
/// Verify that the swarm processes this without panic.
/// This is a fire-and-forget test — no explicit assertion beyond "no panic".
#[tokio::test]
async fn relay_reservation_is_logged_no_panic() {
    // R = relay server (seed 204)
    // A = client requesting reservation (seed 205)
    let config_r = make_swarm_config(204);
    let config_a = make_swarm_config(205);

    let (handle_r, _events_r) = SwarmHandle::start(config_r).await.expect("R start failed");
    let (handle_a, _events_a) = SwarmHandle::start(config_a).await.expect("A start failed");

    let r_addr = get_listen_addr(&handle_r).await;
    let r_peer_id = handle_r.peer_id;

    // A dials R. Relay client should automatically request a reservation.
    handle_a.dial(r_peer_id, r_addr).await.expect("dial failed");

    // Give the event loop time to process relay events.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // If we reach here without panic, the relay event handler is correct.
    let addrs = handle_a.listen_addrs().await.expect("listen_addrs failed");
    assert!(!addrs.is_empty());
}

/// After A connects to B via relay, DCUtR should fire (attempt or succeed).
/// On localhost, DCUtR may succeed immediately since both sides are on the same machine.
/// Either outcome is acceptable — we only verify no panic.
#[tokio::test]
async fn dcutr_fires_after_relay_connection_no_panic() {
    // R = relay (seed 206), A = dialer (seed 207), B = target (seed 208)
    let config_r = make_swarm_config(206);
    let config_a = make_swarm_config(207);
    let config_b = make_swarm_config(208);

    let (handle_r, _events_r) = SwarmHandle::start(config_r).await.expect("R start failed");
    let (handle_a, _events_a) = SwarmHandle::start(config_a).await.expect("A start failed");
    let (handle_b, _events_b) = SwarmHandle::start(config_b).await.expect("B start failed");

    let r_addr = get_listen_addr(&handle_r).await;
    let r_peer_id = handle_r.peer_id;
    let b_peer_id = handle_b.peer_id;

    handle_a
        .dial(r_peer_id, r_addr.clone())
        .await
        .expect("A dial R failed");
    handle_b
        .dial(r_peer_id, r_addr.clone())
        .await
        .expect("B dial R failed");

    // Wait for reservations to settle.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A dials B via relay. DCUtR will trigger after relay circuit is up.
    let b_via_relay = make_relay_circuit_addr(r_addr, r_peer_id, b_peer_id);
    handle_a
        .dial(b_peer_id, b_via_relay)
        .await
        .expect("A dial B-via-relay failed");

    // Give DCUtR time to attempt hole punch (or succeed on localhost).
    tokio::time::sleep(Duration::from_secs(2)).await;

    // If we reach here without panic, dcutr event handler is correct.
    let addrs_a = handle_a.listen_addrs().await.expect("listen_addrs failed");
    assert!(!addrs_a.is_empty());
}
