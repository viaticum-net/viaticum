// Shared test helpers for swarm integration tests.
//
// Used by: swarm_tests.rs, swarm_kad_tests.rs, swarm_nat_tests.rs

use std::time::Duration;

use ed25519_dalek::SigningKey;
use libp2p::Multiaddr;
use tokio::time::timeout;
use viaticum_core::cluster::{DeviceCertificate, issue_device_certificate};
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp};

use crate::daemon::network::swarm::{ConnPolicy, ProtocolEvent, SwarmConfig, SwarmHandle};

/// Build a deterministic SigningKey from a seed byte.
pub(crate) fn make_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Build a DeviceCertificate for the given device key, signed by the given master key.
pub(crate) fn make_cert(master_key: &SigningKey, device_key: &SigningKey) -> DeviceCertificate {
    let device_id = DeviceId(device_key.verifying_key().to_bytes());
    issue_device_certificate(master_key, device_id, Timestamp(0))
}

/// Seed byte for the shared test-cluster master key. All peers built by
/// `make_swarm_config` are issued device certificates by this single master
/// so they form one logical cluster (founder = the constant master, every
/// caller-provided `seed_byte` distinguishes a *device* within that cluster).
const TEST_CLUSTER_MASTER_SEED: u8 = 0xFF;

/// Shared master key used by all test peers.
pub(crate) fn test_cluster_master_key() -> SigningKey {
    make_signing_key(TEST_CLUSTER_MASTER_SEED)
}

/// Shared master identity used by all test peers.
pub(crate) fn test_cluster_master_pub() -> IdentityPub {
    IdentityPub(test_cluster_master_key().verifying_key().to_bytes())
}

/// Build a SwarmConfig for testing.
///
/// `seed_byte` selects this peer's device key. The cluster master key is
/// shared across every config built by this helper, so any two peers built
/// from different `seed_byte`s belong to the same logical cluster and will
/// successfully authenticate each other via DeviceCertExchange. To test
/// rejection (peer from different cluster), build SwarmConfig manually with
/// a fresh master and ignore this helper.
pub(crate) fn make_swarm_config(seed_byte: u8) -> SwarmConfig {
    debug_assert!(
        seed_byte != TEST_CLUSTER_MASTER_SEED,
        "seed_byte 0xFF reserved for the shared test cluster master"
    );
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
        kademlia_bootstrap_peers: vec![],
        kad_discovery_interval_override: None,
        enable_relay_server: false,
        conn_policy: ConnPolicy::off(),
    }
}

/// Get the first listen address of a SwarmHandle (wait up to 2s for it to bind).
pub(crate) async fn get_listen_addr(handle: &SwarmHandle) -> Multiaddr {
    let deadline = Duration::from_secs(2);
    timeout(deadline, async {
        loop {
            let addrs = handle.listen_addrs().await.expect("listen_addrs failed");
            if !addrs.is_empty() {
                return addrs.into_iter().next().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("timed out waiting for listen address")
}

/// Collect the first PeerAuthenticated event for a given device_id (wait up to 5s).
pub(crate) async fn wait_for_authenticated(
    event_rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>,
    expected_device_id: DeviceId,
) -> ProtocolEvent {
    let deadline = Duration::from_secs(5);
    timeout(deadline, async {
        loop {
            let event = event_rx.recv().await.expect("event_rx closed");
            if let ProtocolEvent::PeerAuthenticated { device_id, .. } = &event
                && *device_id == expected_device_id
            {
                return event;
            }
        }
    })
    .await
    .expect("timed out waiting for PeerAuthenticated")
}

// ── C-DK C4 helpers: the connection cache and the on-demand dial ─────────────

/// A test config with the connection cache (`cap`), on-demand dial on, and a
/// short handshake grace (`grace_ms`) so the protection ends inside a test.
pub(crate) fn cached_config(seed_byte: u8, cap: usize, grace_ms: u64) -> SwarmConfig {
    let mut cfg = make_swarm_config(seed_byte);
    cfg.conn_policy.cap = Some(cap);
    cfg.conn_policy.dial_on_demand = true;
    cfg.conn_policy.handshake_grace = Duration::from_millis(grace_ms);
    cfg
}

/// A device id of the test cluster for `seed_byte`.
pub(crate) fn device_of(seed_byte: u8) -> DeviceId {
    DeviceId(make_signing_key(seed_byte).verifying_key().to_bytes())
}

/// An application message (activity for the cache).
pub(crate) fn app_message() -> viaticum_core::messages::Message {
    use viaticum_core::messages::{Message, PosHashChallengeMsg};
    Message::PosHashChallenge(PosHashChallengeMsg {
        v: 1,
        challenge_id: [1u8; 16],
        source_block_id: viaticum_core::types::SourceBlockId([2u8; 32]),
        esi_ranges: vec![(42, 1)],
        timestamp: Timestamp(1000),
        device_id: None,
        sig: [0u8; 64],
    })
}

/// Answer every inbound request on `events` with an Ack after `delay`; drop
/// every other event. Owns the event receiver: wait for authentication with
/// [`wait_auth`] instead.
pub(crate) fn serve_acks(
    handle: std::sync::Arc<SwarmHandle>,
    mut events: tokio::sync::mpsc::Receiver<ProtocolEvent>,
    delay: Duration,
) {
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            if let ProtocolEvent::InboundRequest {
                response_channel, ..
            } = ev
            {
                let h = handle.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let ack =
                        viaticum_core::messages::Message::Ack(viaticum_core::messages::AckMsg {
                            v: 1,
                        });
                    let _ = h.respond(response_channel, ack);
                });
            }
        }
    });
}

/// Poll `handle` until `device` is (or is not, `want`) authenticated (≤ 5 s).
pub(crate) async fn wait_auth(handle: &SwarmHandle, device: DeviceId, want: bool) {
    timeout(Duration::from_secs(5), async {
        loop {
            let (auth, _) = handle.peer_sets().await.expect("peer_sets");
            if auth.contains(&device) == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("authenticated({device:?}) never became {want}"));
}

/// A TCP port that accepts and never answers (a "black hole"): a dial to it
/// hangs in the Noise handshake until the transport timeout.
pub(crate) async fn black_hole_addr() -> Multiaddr {
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

/// A TCP port nobody listens on: a dial to it is refused at once.
pub(crate) fn closed_port_addr() -> Multiaddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    drop(l);
    format!("/ip4/127.0.0.1/tcp/{port}").parse().expect("ma")
}

/// A PeerRecord of `device` (another master) with `addrs`.
pub(crate) fn peer_record_with(
    device: DeviceId,
    master: IdentityPub,
    addrs: &[Multiaddr],
) -> viaticum_core::types::PeerRecord {
    use viaticum_core::constants::{AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};
    let now = Timestamp::now();
    viaticum_core::types::PeerRecord {
        device_id: device,
        master_identity: master,
        trust_p: INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: addrs.iter().map(|a| a.to_string()).collect(),
        x25519_pub: None,
        avail_ewma: AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    }
}
