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

// ─── Multi-device cluster cases ───────────────────────────────────────────────
//
// These three tests exercise the case where the founder ≠ verifier. The
// verifier (joiner) stores the FOUNDER's identity as its cluster_master_pub
// in ClusterState; its own seed-derived master is something different and
// MUST NOT be used as the verification anchor.
//
// Wave 1 only tested single-device and inter-cluster boundary; the
// joiner-within-same-cluster case was the actual regression that broke
// the demo cluster in 2026-05-17.

/// AC-M1: A joiner verifying a cert signed by the founder.
///
/// Setup: founder F holds the cluster master key; joiner J has its own
/// seed-derived master (≠ F) and stores F's identity_pub as cluster_master_pub
/// (in real flow this happens during join when J persists state.master_pub).
/// F issues a cert for J. When J verifies its own (founder-signed) cert,
/// or any other founder-signed cert, the check MUST pass.
#[test]
fn cert_verify_multi_device_joiner_accepts_cert_signed_by_founder() {
    // Founder.
    let founder_master = derive_master_key(&[0x10u8; 64]).unwrap();
    let founder_identity = master_identity(&founder_master);

    // Joiner has its own (different) derived master; in real life this is
    // never used as a signing authority — only J's device_key is.
    let joiner_device_key = ed25519_dalek::SigningKey::from_bytes(&[0x21u8; 32]);
    let (joiner_cert, joiner_peer_id) =
        make_test_cert_for_device(&founder_master, &joiner_device_key);

    // J's stored cluster_master_pub == founder_identity (loaded from
    // ClusterState.master_pub() at daemon startup).
    let result = verify_cert_for_peer(&joiner_peer_id, &joiner_cert, &founder_identity);
    assert!(
        result.is_ok(),
        "joiner must accept its own founder-signed cert; got: {result:?}"
    );

    // Also accept ANOTHER joiner's cert that was signed by the same founder.
    let other_device_key = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]);
    let (other_cert, other_peer_id) = make_test_cert_for_device(&founder_master, &other_device_key);
    let result = verify_cert_for_peer(&other_peer_id, &other_cert, &founder_identity);
    assert!(
        result.is_ok(),
        "joiner must accept fellow joiner's founder-signed cert; got: {result:?}"
    );
}

/// AC-M2: A joiner MUST reject a self-signed cert that another joiner
/// fabricated using their OWN master (pretending to be cluster master).
///
/// This is the canonical multi-device attack: rogue device in same cluster
/// tries to impersonate the founder. Wave 1's anchor (own_identity_pub) on
/// the verifying joiner happens to be DIFFERENT from both the founder's and
/// the rogue's master, so detection was incidental. With the correct anchor
/// (cluster_master_pub = founder), this attack is detected directly.
#[test]
fn cert_verify_multi_device_rejects_self_signed_cert_from_joiner() {
    let founder_master = derive_master_key(&[0x10u8; 64]).unwrap();
    let founder_identity = master_identity(&founder_master);

    // Rogue joiner derives its own master and self-signs a cert as if it
    // were the cluster founder.
    let rogue_master = derive_master_key(&[0x11u8; 64]).unwrap();
    let rogue_device_key = ed25519_dalek::SigningKey::from_bytes(&[0x31u8; 32]);
    let (rogue_cert, rogue_peer_id) = make_test_cert_for_device(&rogue_master, &rogue_device_key);

    let result = verify_cert_for_peer(&rogue_peer_id, &rogue_cert, &founder_identity);
    assert!(
        result.is_err(),
        "rogue's self-signed cert must be rejected by a joiner whose anchor is the real founder; got: {result:?}"
    );
}

/// AC-M3: After a joiner is added to the cluster, the founder verifies the
/// joiner's cert using the founder's own cluster_master_pub (== founder's
/// identity). Asymmetric setup: founder's anchor and signing key are the
/// same, joiner's anchor is the founder.
#[test]
fn cert_verify_multi_device_founder_accepts_reissued_joiner_cert() {
    let founder_master = derive_master_key(&[0x10u8; 64]).unwrap();
    let founder_identity = master_identity(&founder_master);

    // Joiner added later — founder issues a cert for them now.
    let joiner_device_key = ed25519_dalek::SigningKey::from_bytes(&[0x41u8; 32]);
    let (joiner_cert, joiner_peer_id) =
        make_test_cert_for_device(&founder_master, &joiner_device_key);

    // Founder verifying joiner's cert: anchor = founder_identity (its own).
    let result = verify_cert_for_peer(&joiner_peer_id, &joiner_cert, &founder_identity);
    assert!(
        result.is_ok(),
        "founder must accept its own reissued cert for joiner; got: {result:?}"
    );
}
