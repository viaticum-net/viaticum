// Connection bookkeeping of the swarm (C-DK Р-4, network-i19): real swarms on
// loopback, like swarm_tests.rs.

use std::time::Duration;

use super::swarm::{ProtocolEvent, SwarmHandle};
use super::swarm_test_helpers::{get_listen_addr, make_swarm_config, wait_for_authenticated};

/// Every event still queued on `rx` (non-blocking).
fn drain(rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>) -> Vec<ProtocolEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

/// network-i19: two connections to the same peer (what simultaneous dials
/// leave behind); one of them closes. The peer stays authenticated on BOTH
/// sides and the processor hears no ConnectionClosed — before N6 the first
/// close dropped the peer from `authenticated` although a channel lived (M3).
#[tokio::test]
async fn connection_closed_keeps_auth_while_another_connection_lives() {
    let (a, mut events_a) = SwarmHandle::start(make_swarm_config(101))
        .await
        .expect("swarm A");
    let (b, mut events_b) = SwarmHandle::start(make_swarm_config(102))
        .await
        .expect("swarm B");
    let addr_b = get_listen_addr(&b).await;
    a.dial(b.peer_id, addr_b.clone()).await.expect("dial");
    wait_for_authenticated(&mut events_a, b.device_id).await;
    wait_for_authenticated(&mut events_b, a.device_id).await;

    // A second connection A → B; A re-sends its cert as the dialer, so both
    // sides authenticate once more over the pair of connections.
    let duplicate = a
        .test_dial_new_connection(addr_b)
        .await
        .expect("second dial");
    wait_for_authenticated(&mut events_b, a.device_id).await;
    wait_for_authenticated(&mut events_a, b.device_id).await;

    assert!(
        a.test_close_connection(duplicate).await,
        "the duplicate connection was open"
    );
    // Both event loops see ConnectionClosed with one connection left.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (auth_a, _) = a.peer_sets().await.expect("peer_sets A");
    let (auth_b, _) = b.peer_sets().await.expect("peer_sets B");
    assert!(auth_a.contains(&b.device_id), "A lost B's auth");
    assert!(auth_b.contains(&a.device_id), "B lost A's auth");
    let (connected_a, authenticated_a) = a.peer_counts().await.expect("counts A");
    assert_eq!((connected_a, authenticated_a), (1, 1));
    for ev in drain(&mut events_a).into_iter().chain(drain(&mut events_b)) {
        assert!(
            !matches!(ev, ProtocolEvent::ConnectionClosed { .. }),
            "the processor must not hear about a closed duplicate: {ev:?}"
        );
    }
}
