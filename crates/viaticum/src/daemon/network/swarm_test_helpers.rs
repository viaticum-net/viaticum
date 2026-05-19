// Shared test helpers for swarm integration tests.
//
// Used by: swarm_tests.rs, swarm_kad_tests.rs, swarm_nat_tests.rs

use std::time::Duration;

use ed25519_dalek::SigningKey;
use libp2p::Multiaddr;
use tokio::time::timeout;
use viaticum_core::cluster::{DeviceCertificate, issue_device_certificate};
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp};

use crate::daemon::network::swarm::{ProtocolEvent, SwarmConfig, SwarmHandle};

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
///
/// IPFS bootstrap is disabled to avoid real network traffic in tests.
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
        kademlia_disable_ipfs_bootstrap: true,
        kad_republish_interval_override: None,
        kad_discovery_interval_override: None,
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
