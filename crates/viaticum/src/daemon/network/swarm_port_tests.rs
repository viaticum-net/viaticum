// Tests for the authoritative listen-port check (daemon-i1): a fixed listen
// port held by anyone — an unrelated service or a second viaticum — refuses the
// swarm start instead of starting silently.

use std::time::Duration;

use super::swarm_test_helpers::make_swarm_config;
use crate::daemon::network::swarm::{SwarmError, SwarmHandle, wait_for_tcp_port_free};

/// TCP port of the swarm's IPv4 listener. With `listen_port = 0` the IPv4 and
/// IPv6 listeners get different ephemeral ports, so the address family matters:
/// the probe checks `0.0.0.0`.
async fn ipv4_listen_port(handle: &SwarmHandle) -> u16 {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let addrs = handle.listen_addrs().await.expect("listen_addrs");
        for addr in &addrs {
            let mut is_ip4 = false;
            for p in addr.iter() {
                match p {
                    libp2p::multiaddr::Protocol::Ip4(_) => is_ip4 = true,
                    libp2p::multiaddr::Protocol::Tcp(port) if is_ip4 => return port,
                    _ => {}
                }
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no IPv4 listen address within 2 s: {addrs:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// An unrelated process holds the port with a plain listener (no SO_REUSEPORT).
/// The paused clock skips the ~64 s handover wait; the start must end in
/// `PortInUse` naming the port, not in a running swarm.
#[tokio::test(start_paused = true)]
async fn swarm_start_fails_with_port_in_use_when_port_held_without_reuseport() {
    let blocker = std::net::TcpListener::bind("0.0.0.0:0").expect("bind blocker");
    let port = blocker.local_addr().unwrap().port();
    let mut cfg = make_swarm_config(1);
    cfg.listen_port = port;

    let started = tokio::time::Instant::now();
    let result = SwarmHandle::start(cfg).await;

    match result {
        Err(SwarmError::PortInUse { port: p }) => assert_eq!(p, port),
        Err(e) => panic!("expected PortInUse, got {e}"),
        Ok(_) => panic!("swarm started on a port held by another process"),
    }
    // The whole handover window was waited out (virtual time), not skipped.
    assert!(
        started.elapsed() >= Duration::from_secs(60),
        "waited only {:?}",
        started.elapsed()
    );
    drop(blocker);
}

/// A second viaticum on the same fixed port: the first one's libp2p listener
/// has SO_REUSEPORT, which lets another SO_REUSEPORT socket of the same user
/// bind silently. The plain-bind probe still sees the port as taken.
#[tokio::test]
async fn port_probe_reports_busy_when_a_running_swarm_listens_there() {
    let (first, _events) = SwarmHandle::start(make_swarm_config(1))
        .await
        .expect("first swarm");
    let port = ipv4_listen_port(&first).await;

    assert!(
        !wait_for_tcp_port_free("0.0.0.0", port, &[0, 10]).await,
        "port {port} of a running swarm must be reported busy"
    );
}

#[tokio::test]
async fn port_probe_reports_free_when_nobody_listens() {
    let port = {
        let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        l.local_addr().unwrap().port()
    };
    assert!(wait_for_tcp_port_free("0.0.0.0", port, &[0]).await);
}
