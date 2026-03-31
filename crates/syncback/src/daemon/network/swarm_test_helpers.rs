// Shared test helpers for swarm integration tests.
//
// Used by: swarm_tests.rs, swarm_kad_tests.rs, swarm_nat_tests.rs

use std::time::Duration;

use ed25519_dalek::SigningKey;
use libp2p::Multiaddr;
use syncback_core::cluster::{issue_device_certificate, DeviceCertificate};
use syncback_core::types::{DeviceId, IdentityPub, Timestamp};
use tokio::time::timeout;

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

/// Build a SwarmConfig for testing.
///
/// Uses seed_byte to derive device and master keys deterministically.
/// IPFS bootstrap is disabled (kademlia_disable_ipfs_bootstrap = true) to avoid
/// real network traffic in tests.
pub(crate) fn make_swarm_config(seed_byte: u8) -> SwarmConfig {
    let device_key = make_signing_key(seed_byte);
    let master_key = make_signing_key(seed_byte.wrapping_add(128));
    let identity_pub = IdentityPub(master_key.verifying_key().to_bytes());
    let cert = make_cert(&master_key, &device_key);
    SwarmConfig {
        device_signing_key: device_key,
        master_signing_key: master_key,
        identity_pub,
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
            if let ProtocolEvent::PeerAuthenticated { device_id, .. } = &event {
                if *device_id == expected_device_id {
                    return event;
                }
            }
        }
    })
    .await
    .expect("timed out waiting for PeerAuthenticated")
}
