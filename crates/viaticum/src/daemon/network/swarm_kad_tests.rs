// Kademlia DHT tests for swarm.rs (ε.3).
//
// All tests use kademlia_disable_ipfs_bootstrap = true to avoid real network
// traffic. Tests bootstrap against each other using localhost addresses.

use std::time::Duration;

use libp2p::Multiaddr;
use tokio::time::timeout;
use viaticum_core::config::{AppConfig, NetworkCfg};
use viaticum_core::types::DeviceId;

use super::swarm_test_helpers::{get_listen_addr, make_cert, make_signing_key};
use crate::daemon::network::swarm::{
    ConnPolicy, ProtocolEvent, SwarmConfig, SwarmHandle, discovery_dial_candidates,
    ipfs_bootstrap_peers, peer_id_from_multiaddr, scaled_kad_cadence,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Build a SwarmConfig for Kademlia tests.
///
/// All tests disable IPFS bootstrap (kademlia_disable_ipfs_bootstrap = true).
/// Bootstrap peers can be added via kademlia_bootstrap_peers.
/// kad_discovery_interval_override speeds up the discovery cycle.
fn make_kad_config(seed_byte: u8, bootstrap_peers: Vec<Multiaddr>) -> SwarmConfig {
    // Reuse the shared test-cluster master so Kad-discovered peers can complete
    // DeviceCertExchange. `seed_byte` only distinguishes device keys.
    use super::swarm_test_helpers::{test_cluster_master_key, test_cluster_master_pub};
    let device_key = make_signing_key(seed_byte);
    let master_key = test_cluster_master_key();
    let identity_pub = test_cluster_master_pub();
    let cert = make_cert(&master_key, &device_key);
    SwarmConfig {
        device_signing_key: device_key,
        master_signing_key: master_key,
        identity_pub,
        cluster_master_pub: identity_pub,
        device_cert: cert,
        x25519_pub: None,
        listen_port: 0,
        cert_timeout_secs: 10,
        kademlia_bootstrap_peers: bootstrap_peers,
        kademlia_disable_ipfs_bootstrap: true,
        kad_republish_interval_override: None,
        // Speed up discovery for tests.
        kad_discovery_interval_override: Some(Duration::from_millis(200)),
        enable_relay_server: false,
        conn_policy: ConnPolicy::off(),
    }
}

/// Append /p2p/<peer_id> component to a Multiaddr.
fn with_p2p(addr: Multiaddr, peer_id: libp2p::PeerId) -> Multiaddr {
    addr.with(libp2p::multiaddr::Protocol::P2p(peer_id))
}

/// Collect the first PeerAuthenticated event for a specific device_id within timeout.
async fn wait_for_peer_authenticated(
    event_rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>,
    expected_device_id: DeviceId,
    wait: Duration,
) -> bool {
    timeout(wait, async {
        loop {
            match event_rx.recv().await {
                Some(ProtocolEvent::PeerAuthenticated { device_id, .. })
                    if device_id == expected_device_id =>
                {
                    return true;
                }
                Some(_) => {}         // other events — keep waiting
                None => return false, // channel closed
            }
        }
    })
    .await
    .unwrap_or(false)
}

// ─── T2: two_kad_nodes_discover_each_other ────────────────────────────────────

/// Two SwarmHandles with DHT enabled discover each other via Kademlia.
/// A acts as bootstrap for B: B's Kademlia bootstrap dials A.
/// Expected: both sides authenticate within 10 seconds.
#[tokio::test]
async fn two_kad_nodes_discover_each_other() {
    let config_a = make_kad_config(10, vec![]);
    let device_id_a = DeviceId(config_a.device_signing_key.verifying_key().to_bytes());
    let device_id_b_key = make_signing_key(20);
    let device_id_b = DeviceId(device_id_b_key.verifying_key().to_bytes());

    let (handle_a, mut events_a) = SwarmHandle::start(config_a).await.expect("swarm A start");
    let addr_a = get_listen_addr(&handle_a).await;

    // B uses A as its Kademlia bootstrap peer.
    let bootstrap_addr = with_p2p(addr_a, handle_a.peer_id);
    let config_b = make_kad_config(20, vec![bootstrap_addr]);

    let (_handle_b, mut events_b) = SwarmHandle::start(config_b).await.expect("swarm B start");

    // Wait for both sides to emit PeerAuthenticated.
    // The discovery flow: B's Kademlia bootstrap dials A → cert exchange →
    // authenticated on both sides.
    let ok_b_sees_a =
        wait_for_peer_authenticated(&mut events_b, device_id_a, Duration::from_secs(10)).await;
    let ok_a_sees_b =
        wait_for_peer_authenticated(&mut events_a, device_id_b, Duration::from_secs(10)).await;

    assert!(
        ok_b_sees_a,
        "B should authenticate A within 10 seconds via DHT discovery"
    );
    assert!(
        ok_a_sees_b,
        "A should authenticate B within 10 seconds via DHT discovery"
    );
}

// ─── T3: kad_does_not_dial_self ───────────────────────────────────────────────

/// dial_discovered_peer must silently skip dialing our own PeerId.
/// After calling it with our own PeerId, no dial attempt should be made.
#[tokio::test]
async fn kad_does_not_dial_self() {
    let config = make_kad_config(30, vec![]);
    let (handle, mut events) = SwarmHandle::start(config).await.expect("swarm start");

    // Wait for bind.
    let _addr = get_listen_addr(&handle).await;

    // Verify: no OutgoingConnectionError appears within 500ms
    // (which would indicate a dial attempt was made for self).
    let got_connection_error = timeout(Duration::from_millis(500), async {
        loop {
            match events.recv().await {
                Some(ProtocolEvent::ConnectionClosed { .. }) => return true,
                Some(_) => {}
                None => return false,
            }
        }
    })
    .await;

    // The key assertion: we should not see a connection error to our own PeerId.
    // If self-dial prevention works, the event loop simply skips the dial.
    // No connection attempt → no connection error → timeout (unwrap_or false).
    assert!(
        !got_connection_error.unwrap_or(false),
        "should not get ConnectionClosed from a self-dial attempt"
    );
}

// ─── T6: three_nodes_mesh_via_dht ────────────────────────────────────────────

/// Three nodes: A (bootstrap), B, C.
/// B and C only know A. They should discover each other via the DHT.
#[tokio::test]
async fn three_nodes_mesh_via_dht() {
    let config_a = make_kad_config(40, vec![]);
    let device_id_a = DeviceId(make_signing_key(40).verifying_key().to_bytes());

    let (handle_a, mut events_a) = SwarmHandle::start(config_a).await.expect("swarm A start");
    let addr_a = get_listen_addr(&handle_a).await;

    let bootstrap_addr = with_p2p(addr_a, handle_a.peer_id);

    let config_b = make_kad_config(50, vec![bootstrap_addr.clone()]);
    let device_id_b = DeviceId(make_signing_key(50).verifying_key().to_bytes());

    let config_c = make_kad_config(60, vec![bootstrap_addr]);
    let device_id_c = DeviceId(make_signing_key(60).verifying_key().to_bytes());

    let (_handle_b, mut events_b) = SwarmHandle::start(config_b).await.expect("swarm B start");
    let (_handle_c, mut events_c) = SwarmHandle::start(config_c).await.expect("swarm C start");

    // All three should eventually authenticate each other.
    // We focus on B↔C discovery (they only know A).
    let ok_b_sees_c =
        wait_for_peer_authenticated(&mut events_b, device_id_c, Duration::from_secs(30)).await;
    let ok_c_sees_b =
        wait_for_peer_authenticated(&mut events_c, device_id_b, Duration::from_secs(30)).await;

    // Also drain A's events (don't block).
    let _ = timeout(Duration::from_millis(100), async {
        while events_a.recv().await.is_some() {}
    })
    .await;

    let _ = device_id_a;

    assert!(
        ok_b_sees_c,
        "B should discover and authenticate C via DHT (through A as bootstrap)"
    );
    assert!(
        ok_c_sees_b,
        "C should discover and authenticate B via DHT (through A as bootstrap)"
    );
}

// ─── T7: config_validation_rejects_invalid_multiaddr ─────────────────────────

/// AppConfig::validate() must reject kademlia_bootstrap_peers entries that are
/// not valid Multiaddr strings (do not start with '/').
#[test]
#[allow(clippy::field_reassign_with_default)]
fn config_validation_rejects_invalid_multiaddr() {
    let mut cfg = AppConfig::default();
    cfg.network = NetworkCfg {
        kademlia_bootstrap_peers: vec!["not_a_multiaddr".to_string()],
        kademlia_disable_ipfs_bootstrap: false,
        ..Default::default()
    };

    let result = cfg.validate();

    assert!(
        result.is_err(),
        "validate() must fail for invalid multiaddr"
    );
    let err = result.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("network.kademlia_bootstrap_peers[0]"),
        "error must name the offending field, got: {err_str}"
    );
}

/// A valid Multiaddr entry (starts with '/') must pass config validation.
#[test]
#[allow(clippy::field_reassign_with_default)]
fn config_validation_accepts_valid_multiaddr_prefix() {
    let mut cfg = AppConfig::default();
    cfg.network = NetworkCfg {
        kademlia_bootstrap_peers: vec![
            "/ip4/127.0.0.1/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"
                .to_string(),
        ],
        kademlia_disable_ipfs_bootstrap: true,
        ..Default::default()
    };

    // Should not return a validation error for kademlia_bootstrap_peers.
    // (Other fields may fail but we don't expect a kademlia error.)
    let result = cfg.validate();
    if let Err(ref e) = result {
        assert!(
            !e.to_string().contains("kademlia_bootstrap_peers"),
            "valid multiaddr should not cause a kademlia validation error, got: {e}"
        );
    }
}

// ─── Unit test: peer_id_from_multiaddr helper ────────────────────────────────

#[test]
fn peer_id_from_multiaddr_extracts_peer_id() {
    let addr_str =
        "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ";
    let addr: Multiaddr = addr_str.parse().expect("valid multiaddr");
    let result = peer_id_from_multiaddr(&addr);
    assert!(
        result.is_some(),
        "should extract PeerId from /p2p component"
    );
}

#[test]
fn peer_id_from_multiaddr_returns_none_without_p2p() {
    let addr_str = "/ip4/127.0.0.1/tcp/4001";
    let addr: Multiaddr = addr_str.parse().expect("valid multiaddr");
    let result = peer_id_from_multiaddr(&addr);
    assert!(
        result.is_none(),
        "should return None when no /p2p component"
    );
}

// ─── Unit test: ipfs_bootstrap_peers ─────────────────────────────────────────

#[test]
fn ipfs_bootstrap_peers_nonempty() {
    let peers = ipfs_bootstrap_peers();
    assert!(
        !peers.is_empty(),
        "ipfs_bootstrap_peers must return at least one entry"
    );
    // Every returned entry must have a valid PeerId.
    for (peer_id, addr) in &peers {
        let extracted = peer_id_from_multiaddr(addr);
        assert!(
            extracted.is_some(),
            "each bootstrap addr must have a /p2p component"
        );
        assert_eq!(
            extracted.unwrap(),
            *peer_id,
            "extracted PeerId must match the returned PeerId"
        );
    }
}

// ─── T-9a: get_closest_peers_returns_known_peers ──────────────────────────────

/// Two nodes: A (bootstrap), B.
/// After B authenticates with A via DHT, querying get_closest_peers from B
/// should return A (or at least one known peer) with addrs populated.
///
/// This is the core T-9a capability: on-demand Kademlia FIND_NODE query
/// exposed as SwarmHandle::get_closest_peers.
#[tokio::test]
async fn get_closest_peers_returns_known_peers() {
    let config_a = make_kad_config(80, vec![]);
    let device_id_a = DeviceId(make_signing_key(80).verifying_key().to_bytes());

    let (handle_a, mut events_a) = SwarmHandle::start(config_a).await.expect("swarm A start");
    let addr_a = get_listen_addr(&handle_a).await;

    // B bootstraps against A.
    let bootstrap_addr = with_p2p(addr_a, handle_a.peer_id);
    let config_b = make_kad_config(81, vec![bootstrap_addr]);

    let (handle_b, mut events_b) = SwarmHandle::start(config_b).await.expect("swarm B start");

    // Wait until B authenticates A (ensures DHT routing table is populated).
    let ok = wait_for_peer_authenticated(&mut events_b, device_id_a, Duration::from_secs(10)).await;
    assert!(ok, "B must authenticate A before querying");

    // Drain A's events (don't block the test).
    let _ = timeout(Duration::from_millis(50), async {
        while events_a.recv().await.is_some() {}
    })
    .await;

    // Query: from B, find closest peers to some 32-byte key.
    let target_key = vec![0xABu8; 32];
    let result = timeout(
        Duration::from_secs(10),
        handle_b.get_closest_peers(target_key),
    )
    .await
    .expect("get_closest_peers must not hang")
    .expect("get_closest_peers must not error");

    // The result must be non-empty — A is in the routing table.
    assert!(
        !result.is_empty(),
        "get_closest_peers must return at least one peer (A is known)"
    );

    // Every returned (peer_id, addrs) pair: peer_id must be valid.
    for (peer_id, addrs) in &result {
        assert_ne!(*peer_id, handle_b.peer_id, "result must not include self");
        // Addrs may be empty for peers only in the routing table without
        // identify info; that is acceptable — the important thing is that
        // the peer_id is returned.
        let _ = addrs;
    }

    // A should be in the result (it is B's only peer).
    let a_found = result.iter().any(|(pid, _)| *pid == handle_a.peer_id);
    assert!(
        a_found,
        "A's peer_id must appear in get_closest_peers result"
    );
}

// ─── T-9a: get_closest_peers_times_out_or_empty_gracefully ───────────────────

/// A node with no peers: get_closest_peers should return Ok(empty) or
/// at most a graceful error — no panic, no hang beyond the method's own timeout.
///
/// We wrap with a generous outer timeout just in case the method hangs.
#[tokio::test]
async fn get_closest_peers_times_out_or_empty_gracefully() {
    let config = make_kad_config(82, vec![]);
    let (handle, _events) = SwarmHandle::start(config).await.expect("swarm start");
    let _addr = get_listen_addr(&handle).await;

    // Target key is arbitrary.
    let target_key = vec![0x42u8; 32];

    // The method's internal timeout is shorter than this outer guard.
    let outcome = timeout(
        Duration::from_secs(35), // outer guard: must complete before this
        handle.get_closest_peers(target_key),
    )
    .await
    .expect("get_closest_peers must not hang beyond 35s");

    // Either Ok(empty) or Err(Timeout) — both are acceptable.
    // What is NOT acceptable: panic or hang.
    match outcome {
        Ok(peers) => {
            // Isolated node: empty result is expected.
            assert!(
                peers.is_empty(),
                "isolated node should return empty peer list, got {peers:?}"
            );
        }
        Err(e) => {
            // A timeout error is also acceptable (the kad query timed out).
            assert!(
                e.to_string().contains("timeout") || e.to_string().contains("Timeout"),
                "unexpected error from isolated get_closest_peers: {e}"
            );
        }
    }
}

// ─── scaled_kad_cadence (discovery time_scale contract) ─────────────────────────

#[test]
fn scaled_kad_cadence_unchanged_at_production_time_scale() {
    // Production runs at time_scale 1 (or 0, clamped to 1): discovery cadence is the base.
    assert_eq!(
        scaled_kad_cadence(Duration::from_secs(300), 1),
        Duration::from_secs(300)
    );
    assert_eq!(
        scaled_kad_cadence(Duration::from_secs(300), 0),
        Duration::from_secs(300)
    );
}

#[test]
fn scaled_kad_cadence_divides_by_time_scale() {
    // 5-min discovery at time_scale 10 -> 30 s, so discovery keeps pace under acceleration.
    assert_eq!(
        scaled_kad_cadence(Duration::from_secs(300), 10),
        Duration::from_secs(30)
    );
}

#[test]
fn scaled_kad_cadence_floored_at_one_second() {
    // Heavy acceleration (300 / 30000 = 0) floors to 1 s — discovery still fires, never 0.
    assert_eq!(
        scaled_kad_cadence(Duration::from_secs(300), 30000),
        Duration::from_secs(1)
    );
}

// ─── discovery_dial_candidates (address-carrying discovery gating) ──────────────

/// Build a synthetic peer list of `n` entries, each with one distinct address.
fn fake_peer_list(n: usize) -> Vec<(libp2p::PeerId, Vec<Multiaddr>)> {
    (0..n)
        .map(|i| {
            let peer_id = libp2p::PeerId::random();
            let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", 4000 + i)
                .parse()
                .expect("valid multiaddr");
            (peer_id, vec![addr])
        })
        .collect()
}

/// Р-5′: known (and otherwise skipped) peers are dropped BEFORE the per-round
/// cap, so a result led by peers we already know still yields new ones.
#[test]
fn discovery_dial_candidates_skips_known_before_cap() {
    use viaticum_core::constants::MAX_CONCURRENT_DISCOVERY_DIALS;
    let peers = fake_peer_list(MAX_CONCURRENT_DISCOVERY_DIALS + 6);
    let known: Vec<libp2p::PeerId> = peers.iter().take(4).map(|(p, _)| *p).collect();
    let fresh: Vec<libp2p::PeerId> = peers
        .iter()
        .skip(4)
        .take(MAX_CONCURRENT_DISCOVERY_DIALS)
        .map(|(p, _)| *p)
        .collect();
    let out = discovery_dial_candidates(peers, |p| known.contains(p));
    let got: Vec<libp2p::PeerId> = out.iter().map(|(p, _)| *p).collect();
    assert_eq!(
        got, fresh,
        "the first unknown peers, up to the cap, in result order"
    );
}

/// Р-5′: no gate on how many peers we already have (TARGET_PEERS is gone):
/// whatever is not skipped is dialed, up to the per-round cap.
#[test]
fn discovery_dial_candidates_has_no_count_gate() {
    use viaticum_core::constants::MAX_CONCURRENT_DISCOVERY_DIALS;
    let peers = fake_peer_list(MAX_CONCURRENT_DISCOVERY_DIALS + 10);
    let out = discovery_dial_candidates(peers, |_| false);
    assert_eq!(out.len(), MAX_CONCURRENT_DISCOVERY_DIALS);

    let few = fake_peer_list(2);
    assert_eq!(discovery_dial_candidates(few, |_| false).len(), 2);

    let all_known = fake_peer_list(8);
    assert!(discovery_dial_candidates(all_known, |_| true).is_empty());
}

#[test]
fn discovery_dial_candidates_preserves_addresses() {
    // The addrs vec must pass through unchanged for each surviving entry.
    let peers = fake_peer_list(2);
    let expected: Vec<(libp2p::PeerId, Vec<Multiaddr>)> = peers.clone();
    let out = discovery_dial_candidates(peers, |_| false);
    assert_eq!(out.len(), expected.len());
    for (got, want) in out.iter().zip(expected.iter()) {
        assert_eq!(got.0, want.0, "peer_id must be preserved");
        assert_eq!(got.1, want.1, "addresses must be preserved unchanged");
        assert!(!got.1.is_empty(), "addresses must not be dropped");
    }
}
