// Tests for verify_cert_for_peer (HIGH-1: DeviceCertExchange cluster membership).
//
// ATDD mapping:
//   AC-C1 — cross-cluster peer accepted as Cross path, not Intra.
//            Demonstrates that foreign-master cert gets Cross (not rejected outright).
//   AC-C2 — cert_verify_accepts_cert_for_foreign_master_as_cross_path
//   AC-C3 — cert_verify_accepts_cert_for_own_master (Intra path)
//   AC-C4 — cert_verify_passes_for_bootstrap_single_device_cluster

use viaticum_core::cluster::{
    CertTrustPath, derive_master_key, issue_device_certificate, master_identity,
};
use viaticum_core::types::{DeviceId, Timestamp};

use crate::daemon::network::swarm::{device_id_to_peer_id, verify_cert_for_peer};

/// Build a DeviceCertificate for a device, signed by the given master key.
fn make_test_cert_for_device(
    master_key: &ed25519_dalek::SigningKey,
    device_signing_key: &ed25519_dalek::SigningKey,
) -> (viaticum_core::cluster::DeviceCertificate, libp2p::PeerId) {
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let cert = issue_device_certificate(master_key, device_id, Timestamp(0));
    let peer_id = device_id_to_peer_id(&device_id).unwrap();
    (cert, peer_id)
}

/// AC-C2: A cert whose master_pub_key differs from own cluster master is now
/// accepted as Cross path (cross-cluster peer authenticated as stranger).
#[test]
fn cert_verify_accepts_cert_for_foreign_master_as_cross_path() {
    let own_master_key = derive_master_key(&[0x01u8; 64]).unwrap();
    let own_identity_pub = master_identity(&own_master_key);

    let attacker_master = derive_master_key(&[0x02u8; 64]).unwrap();
    let attacker_device_key = ed25519_dalek::SigningKey::from_bytes(&[0xAAu8; 32]);
    let (attacker_cert, attacker_peer_id) =
        make_test_cert_for_device(&attacker_master, &attacker_device_key);

    let result = verify_cert_for_peer(&attacker_peer_id, &attacker_cert, &own_identity_pub);
    assert_eq!(
        result.unwrap(),
        CertTrustPath::Cross,
        "cert from foreign master must be accepted as Cross path"
    );
}

/// AC-C3: A cert whose master_pub_key equals own_identity_pub and has a valid
/// signature is accepted as Intra path.
#[test]
fn cert_verify_accepts_cert_for_own_master() {
    let master_key = derive_master_key(&[0x01u8; 64]).unwrap();
    let identity_pub = master_identity(&master_key);
    let device_key = ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32]);
    let (cert, peer_id) = make_test_cert_for_device(&master_key, &device_key);

    let result = verify_cert_for_peer(&peer_id, &cert, &identity_pub);
    assert_eq!(
        result.unwrap(),
        CertTrustPath::Intra,
        "cert from own master must be accepted as Intra path"
    );
}

/// AC-C4: Bootstrap case — single-device cluster where the master IS the device.
#[test]
fn cert_verify_passes_for_bootstrap_single_device_cluster() {
    let master_key = derive_master_key(&[0x01u8; 64]).unwrap();
    let identity_pub = master_identity(&master_key);

    let (cert, peer_id) = make_test_cert_for_device(&master_key, &master_key);

    let result = verify_cert_for_peer(&peer_id, &cert, &identity_pub);
    assert_eq!(
        result.unwrap(),
        CertTrustPath::Intra,
        "bootstrap self-cert must be accepted as Intra path"
    );
}

/// AC-C1 (structural): Cross-cluster peer is accepted as Cross path.
/// A foreign-master cert with valid self-signature → Cross.
/// A foreign-master cert with invalid self-signature → Err.
/// Demonstrates: cross-cluster accepted, not rejected; but a broken cert is still rejected.
#[test]
fn cert_verify_accepts_cross_cluster_not_as_intra() {
    let own_master_key = derive_master_key(&[0x01u8; 64]).unwrap();
    let own_identity_pub = master_identity(&own_master_key);

    let foreign_master = derive_master_key(&[0x02u8; 64]).unwrap();
    let foreign_device_key = ed25519_dalek::SigningKey::from_bytes(&[0xCCu8; 32]);
    let (foreign_cert, foreign_peer_id) =
        make_test_cert_for_device(&foreign_master, &foreign_device_key);

    // Valid cross-cluster cert → Cross path (not rejected, not Intra).
    let result = verify_cert_for_peer(&foreign_peer_id, &foreign_cert, &own_identity_pub);
    assert_eq!(
        result.unwrap(),
        CertTrustPath::Cross,
        "foreign-master cert accepted as Cross, not Intra"
    );

    // Broken cross-cluster cert → Err.
    let mut broken_cert = foreign_cert.clone();
    broken_cert.signature = [0u8; 64];
    let broken_result = verify_cert_for_peer(&foreign_peer_id, &broken_cert, &own_identity_pub);
    assert!(
        broken_result.is_err(),
        "broken cross-cluster cert must be rejected"
    );
}

// ─── Multi-device cluster cases ───────────────────────────────────────────────

/// AC-M1: A joiner verifying a cert signed by the founder (Intra path).
#[test]
fn cert_verify_multi_device_joiner_accepts_cert_signed_by_founder() {
    let founder_master = derive_master_key(&[0x10u8; 64]).unwrap();
    let founder_identity = master_identity(&founder_master);

    let joiner_device_key = ed25519_dalek::SigningKey::from_bytes(&[0x21u8; 32]);
    let (joiner_cert, joiner_peer_id) =
        make_test_cert_for_device(&founder_master, &joiner_device_key);

    let result = verify_cert_for_peer(&joiner_peer_id, &joiner_cert, &founder_identity);
    assert_eq!(
        result.unwrap(),
        CertTrustPath::Intra,
        "joiner must accept its own founder-signed cert as Intra"
    );

    let other_device_key = ed25519_dalek::SigningKey::from_bytes(&[0x22u8; 32]);
    let (other_cert, other_peer_id) = make_test_cert_for_device(&founder_master, &other_device_key);
    let result = verify_cert_for_peer(&other_peer_id, &other_cert, &founder_identity);
    assert_eq!(
        result.unwrap(),
        CertTrustPath::Intra,
        "joiner must accept fellow joiner's founder-signed cert as Intra"
    );
}

/// AC-M2: A rogue joiner self-signing its own cert lands in Cross path (not Intra).
///
/// HIGH-1 impersonation attack is prevented: the rogue cannot enter the Intra
/// path without knowing the founder's master private key. The rogue is accepted
/// as a Cross stranger (trust=0 from trust formula) — this is correct behavior,
/// not an attack success.
#[test]
fn cert_verify_multi_device_rogue_joiner_lands_in_cross_not_intra() {
    let founder_master = derive_master_key(&[0x10u8; 64]).unwrap();
    let founder_identity = master_identity(&founder_master);

    let rogue_master = derive_master_key(&[0x11u8; 64]).unwrap();
    let rogue_device_key = ed25519_dalek::SigningKey::from_bytes(&[0x31u8; 32]);
    let (rogue_cert, rogue_peer_id) = make_test_cert_for_device(&rogue_master, &rogue_device_key);

    // Rogue's master != founder's master → Cross path (not Intra — HIGH-1 protected).
    // Rogue cannot impersonate a cluster member: they are treated as a Cross stranger.
    let result = verify_cert_for_peer(&rogue_peer_id, &rogue_cert, &founder_identity);
    assert_eq!(
        result.unwrap(),
        CertTrustPath::Cross,
        "rogue self-signed cert lands in Cross path, not Intra — impersonation prevented"
    );
}

/// AC-M3: Founder accepts its own reissued cert for a joiner (Intra path).
#[test]
fn cert_verify_multi_device_founder_accepts_reissued_joiner_cert() {
    let founder_master = derive_master_key(&[0x10u8; 64]).unwrap();
    let founder_identity = master_identity(&founder_master);

    let joiner_device_key = ed25519_dalek::SigningKey::from_bytes(&[0x41u8; 32]);
    let (joiner_cert, joiner_peer_id) =
        make_test_cert_for_device(&founder_master, &joiner_device_key);

    let result = verify_cert_for_peer(&joiner_peer_id, &joiner_cert, &founder_identity);
    assert_eq!(
        result.unwrap(),
        CertTrustPath::Intra,
        "founder must accept its own reissued cert for joiner as Intra"
    );
}

// ─── New tests (A-D from spec) ────────────────────────────────────────────────

/// A: Cross-cluster with valid self-signature passes as Cross.
#[test]
fn cert_verify_cross_cluster_passes_with_valid_self_signature() {
    let own_master_key = derive_master_key(&[0xA0u8; 64]).unwrap();
    let own_identity_pub = master_identity(&own_master_key);

    let foreign_master = derive_master_key(&[0xB0u8; 64]).unwrap();
    let foreign_device_key = ed25519_dalek::SigningKey::from_bytes(&[0xD0u8; 32]);
    let (cert, peer_id) = make_test_cert_for_device(&foreign_master, &foreign_device_key);

    let result = verify_cert_for_peer(&peer_id, &cert, &own_identity_pub);
    assert_eq!(result.unwrap(), CertTrustPath::Cross);
}

/// B: Cross-cluster with broken self-signature is rejected.
#[test]
fn cert_verify_cross_cluster_rejects_invalid_self_signature() {
    let own_master_key = derive_master_key(&[0xA0u8; 64]).unwrap();
    let own_identity_pub = master_identity(&own_master_key);

    let foreign_master = derive_master_key(&[0xB0u8; 64]).unwrap();
    let foreign_device_key = ed25519_dalek::SigningKey::from_bytes(&[0xD1u8; 32]);
    let (mut cert, peer_id) = make_test_cert_for_device(&foreign_master, &foreign_device_key);
    cert.signature = [0u8; 64];

    let result = verify_cert_for_peer(&peer_id, &cert, &own_identity_pub);
    assert!(result.is_err());
    let msg = result.unwrap_err();
    assert!(
        msg.contains("cross-cluster cert self-signature"),
        "error message should mention cross-cluster path, got: {msg}"
    );
}

/// C: Intra-cluster with broken signature is rejected with intra error message.
#[test]
fn cert_verify_intra_cluster_rejects_invalid_signature() {
    let own_master_key = derive_master_key(&[0xA0u8; 64]).unwrap();
    let own_identity_pub = master_identity(&own_master_key);

    let device_key = ed25519_dalek::SigningKey::from_bytes(&[0xD2u8; 32]);
    let (mut cert, peer_id) = make_test_cert_for_device(&own_master_key, &device_key);
    cert.signature = [0u8; 64];

    let result = verify_cert_for_peer(&peer_id, &cert, &own_identity_pub);
    assert!(result.is_err());
    let msg = result.unwrap_err();
    assert!(
        msg.contains("intra-cluster cert"),
        "error message should mention intra-cluster path, got: {msg}"
    );
}

/// D: Enum routing — same peer with own-master cert → Intra; foreign-master cert → Cross.
#[test]
fn cert_verify_path_distinguishes_intra_vs_cross() {
    let own_master_key = derive_master_key(&[0xA0u8; 64]).unwrap();
    let own_identity_pub = master_identity(&own_master_key);

    // Intra: device signed by own master.
    let device_key_a = ed25519_dalek::SigningKey::from_bytes(&[0xE0u8; 32]);
    let (cert_intra, peer_intra) = make_test_cert_for_device(&own_master_key, &device_key_a);
    assert_eq!(
        verify_cert_for_peer(&peer_intra, &cert_intra, &own_identity_pub).unwrap(),
        CertTrustPath::Intra
    );

    // Cross: device signed by different master.
    let foreign_master = derive_master_key(&[0xB0u8; 64]).unwrap();
    let device_key_b = ed25519_dalek::SigningKey::from_bytes(&[0xE1u8; 32]);
    let (cert_cross, peer_cross) = make_test_cert_for_device(&foreign_master, &device_key_b);
    assert_eq!(
        verify_cert_for_peer(&peer_cross, &cert_cross, &own_identity_pub).unwrap(),
        CertTrustPath::Cross
    );
}
