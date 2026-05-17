// Tests for verify_cert_for_peer (HIGH-1: DeviceCertExchange cluster membership).
//
// ATDD mapping:
//   AC-C1 — structural: if cert.master_pub_key were used, AC-C2 would pass (attacker
//            self-signed cert is internally consistent). AC-C2 failing with old code
//            and passing after fix is the definitive proof.
//   AC-C2 — cert_verify_rejects_cert_for_foreign_master
//   AC-C3 — cert_verify_accepts_cert_for_own_master
//   AC-C4 — cert_verify_passes_for_bootstrap_single_device_cluster

use syncback_core::cluster::{derive_master_key, issue_device_certificate, master_identity};
use syncback_core::types::{DeviceId, Timestamp};

use crate::daemon::network::swarm::{device_id_to_peer_id, verify_cert_for_peer};

/// Build a DeviceCertificate for a device, signed by the given master key.
fn make_test_cert_for_device(
    master_key: &ed25519_dalek::SigningKey,
    device_signing_key: &ed25519_dalek::SigningKey,
) -> (syncback_core::cluster::DeviceCertificate, libp2p::PeerId) {
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let cert = issue_device_certificate(master_key, device_id, Timestamp(0));
    let peer_id = device_id_to_peer_id(&device_id).unwrap();
    (cert, peer_id)
}

/// AC-C2: A cert whose master_pub_key differs from own_identity_pub is rejected,
/// even if the cert is internally self-consistent (self-signed by attacker's own key).
#[test]
fn cert_verify_rejects_cert_for_foreign_master() {
    // Our cluster master
    let own_master_key = derive_master_key(&[0x01u8; 64]).unwrap();
    let own_identity_pub = master_identity(&own_master_key);

    // Attacker has their own master key and device key
    let attacker_master = derive_master_key(&[0x02u8; 64]).unwrap();
    let attacker_device_key = ed25519_dalek::SigningKey::from_bytes(&[0xAAu8; 32]);
    let (attacker_cert, attacker_peer_id) =
        make_test_cert_for_device(&attacker_master, &attacker_device_key);

    // Attacker cert is internally valid (self-signed), but wrong cluster master
    let result = verify_cert_for_peer(&attacker_peer_id, &attacker_cert, &own_identity_pub);
    assert!(
        result.is_err(),
        "cert from foreign master must be rejected; got: {result:?}"
    );
}

/// AC-C3: A cert whose master_pub_key equals own_identity_pub and has a valid
/// signature is accepted.
#[test]
fn cert_verify_accepts_cert_for_own_master() {
    let master_key = derive_master_key(&[0x01u8; 64]).unwrap();
    let identity_pub = master_identity(&master_key);
    let device_key = ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32]);
    let (cert, peer_id) = make_test_cert_for_device(&master_key, &device_key);

    let result = verify_cert_for_peer(&peer_id, &cert, &identity_pub);
    assert!(
        result.is_ok(),
        "cert from own master must be accepted; got: {result:?}"
    );
}

/// AC-C4: Bootstrap case — single-device cluster where the master IS the device.
/// own_identity_pub == cert.master_pub_key by construction; check must pass.
#[test]
fn cert_verify_passes_for_bootstrap_single_device_cluster() {
    // In bootstrap, the master signs its own device cert.
    let master_key = derive_master_key(&[0x01u8; 64]).unwrap();
    let identity_pub = master_identity(&master_key);

    // Device key == master key (single-device bootstrap scenario)
    let (cert, peer_id) = make_test_cert_for_device(&master_key, &master_key);

    let result = verify_cert_for_peer(&peer_id, &cert, &identity_pub);
    assert!(
        result.is_ok(),
        "bootstrap self-cert must be accepted; got: {result:?}"
    );
}

/// AC-C1 (structural): Demonstrate that the OLD tautological check would pass
/// for a foreign-master cert, whereas the new check (own_identity_pub) rejects it.
///
/// This test directly proves that using cert.master_pub_key is insecure, while
/// own_identity_pub correctly rejects the same cert.
#[test]
fn cert_verify_uses_own_identity_not_cert_master_pub() {
    let own_master_key = derive_master_key(&[0x01u8; 64]).unwrap();
    let own_identity_pub = master_identity(&own_master_key);

    // Attacker: different master, valid self-signed cert
    let attacker_master = derive_master_key(&[0x02u8; 64]).unwrap();
    let attacker_device_key = ed25519_dalek::SigningKey::from_bytes(&[0xCCu8; 32]);
    let (attacker_cert, attacker_peer_id) =
        make_test_cert_for_device(&attacker_master, &attacker_device_key);

    // Old tautological check: verify against cert.master_pub_key → PASSES (bad)
    let tautological_result = syncback_core::cluster::verify_device_certificate(
        &attacker_cert,
        &attacker_cert.master_pub_key,
    );
    assert!(
        tautological_result.is_ok(),
        "tautological check must pass for any self-signed cert (demonstrates the vuln)"
    );

    // New check: verify against own_identity_pub → REJECTS (correct)
    let fixed_result = verify_cert_for_peer(&attacker_peer_id, &attacker_cert, &own_identity_pub);
    assert!(
        fixed_result.is_err(),
        "fixed check must reject foreign-master cert"
    );
}
