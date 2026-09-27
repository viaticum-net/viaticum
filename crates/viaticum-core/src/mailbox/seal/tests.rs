// Unit tests for the CROWN-1 crypto core (slice C1).
//
// Known-answer vectors (`*_matches_known_vector`) were computed independently with
// Python `cryptography` 46 (HKDF-SHA256, X25519, Ed25519, ChaCha20Poly1305) from the
// byte layouts of spec §7.2-§7.3, not by running this code.

use std::collections::HashSet;

use sha2::Digest;
use x25519_dalek::{PublicKey, StaticSecret};

use super::*;
use crate::cluster::{
    EpochCounter, derive_device_key, derive_epoch_key, derive_master_key, derive_x25519_secret,
    master_identity,
};
use crate::db::testutil::test_db;
use crate::mailbox::{
    MailboxEngine, MailboxError, sign_store, verify_fetch_proof, verify_store_sig,
};
use crate::types::hex_encode;

// ============================================================
// Helpers
// ============================================================

/// Deterministic 64-byte "BIP39 seed" 0x00..0x3f (the vector seed).
fn seed() -> [u8; 64] {
    std::array::from_fn(|i| i as u8)
}

fn other_seed() -> [u8; 64] {
    [0xA5; 64]
}

/// A plausible "now" (2026-09) and its epoch.
const NOW: u64 = 1_790_000_000;

fn now_epoch() -> RendezvousEpoch {
    RendezvousEpoch::at(NOW)
}

/// The whole DR window `[e - LOOKBACK, e + FORWARD]` around `NOW`.
fn dr_window() -> Vec<RendezvousEpoch> {
    let e = now_epoch().0;
    (e - crate::constants::RENDEZVOUS_DR_LOOKBACK_EPOCHS
        ..=e + crate::constants::RENDEZVOUS_DR_FORWARD_EPOCHS)
        .map(RendezvousEpoch)
        .collect()
}

fn recipient() -> (StaticSecret, [u8; 32]) {
    let sk = StaticSecret::from([0x42; 32]);
    let pk = PublicKey::from(&sk).to_bytes();
    (sk, pk)
}

fn seal_to(recipient_pub: &[u8; 32], class: MailboxClass, body: &[u8]) -> SealedMailboxEntry {
    seal_directed(
        recipient_pub,
        MailboxAddress([0x11; 32]),
        class,
        [0x01; 16],
        IdentityPub([0x33; 32]),
        body,
        NOW + 3600,
        NOW,
    )
    .expect("seal_directed")
}

fn seal_pointer(keys: &RendezvousKeys, pointer: &[u8]) -> SealedMailboxEntry {
    seal_self_pointer(keys, [0x02; 16], pointer, NOW + 3600, NOW).expect("seal_self_pointer")
}

/// Small-order Curve25519 u-coordinates (0, 1, and the order-8 point).
fn low_order_points() -> Vec<[u8; 32]> {
    let mut one = [0u8; 32];
    one[0] = 1;
    let order8: [u8; 32] = [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ];
    vec![[0u8; 32], one, order8]
}

// ============================================================
// Rendezvous epoch
// ============================================================

#[test]
fn rendezvous_epoch_at_boundaries() {
    assert_eq!(RendezvousEpoch::at(0), RendezvousEpoch(0));
    assert_eq!(
        RendezvousEpoch::at(RENDEZVOUS_EPOCH_SECS - 1),
        RendezvousEpoch(0)
    );
    assert_eq!(
        RendezvousEpoch::at(RENDEZVOUS_EPOCH_SECS),
        RendezvousEpoch(1)
    );
    assert_eq!(
        RendezvousEpoch::at(691 * RENDEZVOUS_EPOCH_SECS + 5),
        RendezvousEpoch(691)
    );
    assert_eq!(RendezvousEpoch(0).prev(), None);
    assert_eq!(RendezvousEpoch(5).prev(), Some(RendezvousEpoch(4)));
    assert_eq!(RendezvousEpoch(5).next(), RendezvousEpoch(6));
    assert_eq!(RendezvousEpoch(u64::MAX).next(), RendezvousEpoch(u64::MAX));
}

// ============================================================
// AC-6: the rendezvous address comes from the seed, not from master_pub
// ============================================================

#[test]
fn rendezvous_address_is_deterministic_for_seed_and_epoch() {
    let a = RendezvousKeys::derive(&seed(), RendezvousEpoch(691));
    let b = RendezvousKeys::derive(&seed(), RendezvousEpoch(691));
    assert_eq!(a.address, b.address);
    assert_eq!(*a.seal_key, *b.seal_key);
    // Known-answer vectors (Python, spec §7.2 layout).
    assert_eq!(
        hex_encode(
            &RendezvousKeys::derive(&seed(), RendezvousEpoch(0))
                .address
                .0
        ),
        "381db64e314da2a02f39d14ab7e08755808a78dfde5af1814970cc783eeef1a7"
    );
    assert_eq!(
        hex_encode(&a.address.0),
        "53186efdc2eaf96d669f59adb931bd3b6cad7c4c11ba5b86404ce55fb1765f22"
    );
    assert_eq!(
        hex_encode(&a.seal_key[..]),
        "c4c8776dfefb420bc005f0264dd5bd2a44212919895f4f0a074ff2ea9dbc2ede"
    );
}

#[test]
fn rendezvous_address_changes_every_epoch() {
    let window = dr_window();
    let expected = crate::constants::RENDEZVOUS_DR_LOOKBACK_EPOCHS
        + crate::constants::RENDEZVOUS_DR_FORWARD_EPOCHS
        + 1;
    assert_eq!(window.len() as u64, expected);
    let keys: Vec<_> = window
        .iter()
        .map(|e| RendezvousKeys::derive(&seed(), *e))
        .collect();
    let addresses: HashSet<[u8; 32]> = keys.iter().map(|k| k.address.0).collect();
    let seal_keys: HashSet<[u8; 32]> = keys.iter().map(|k| *k.seal_key).collect();
    assert_eq!(
        addresses.len(),
        window.len(),
        "one distinct address per epoch"
    );
    assert_eq!(
        seal_keys.len(),
        window.len(),
        "one distinct seal key per epoch"
    );
}

#[test]
fn rendezvous_address_differs_from_master_address_in_every_epoch() {
    let master = master_identity(&derive_master_key(&seed()).unwrap());
    let master_box = MailboxAddress::for_master(&master);
    let master_hash: [u8; 32] = sha2::Sha256::digest(master.0).into();
    for e in dr_window() {
        let keys = RendezvousKeys::derive(&seed(), e);
        assert_ne!(keys.address, master_box, "epoch {}", e.0);
        assert_ne!(keys.address.0, master_hash, "epoch {}", e.0);
    }
}

/// The derivation's secret input is the seed: two masters get different addresses,
/// and the same formula keyed by public data (master_pub, or a hash of master_pub
/// and the epoch) does not reproduce the address.
#[test]
fn rendezvous_derivation_is_keyed_by_seed_not_by_master_pub() {
    let e = now_epoch();
    let keys = RendezvousKeys::derive(&seed(), e);
    let other = RendezvousKeys::derive(&other_seed(), e);
    assert_ne!(keys.address, other.address);

    let master = master_identity(&derive_master_key(&seed()).unwrap());
    let from_pub = RendezvousKeys::derive(&master.0, e);
    assert_ne!(keys.address, from_pub.address);
    let mut h = sha2::Sha256::new();
    h.update(master.0);
    h.update(e.0.to_be_bytes());
    let hashed: [u8; 32] = h.finalize().into();
    assert_ne!(keys.address.0, hashed);
}

// ============================================================
// AC-13: key separation
// ============================================================

#[test]
fn new_keys_are_distinct_from_existing_seed_derivations() {
    let s = seed();
    let mut existing: Vec<[u8; 32]> = Vec::new();
    let master = derive_master_key(&s).unwrap();
    existing.push(master.to_bytes());
    existing.push(master.verifying_key().to_bytes());
    let device = derive_device_key(&s, &[7u8; 32]).unwrap();
    existing.push(device.to_bytes());
    existing.push(device.verifying_key().to_bytes());
    let x = derive_x25519_secret(&s);
    existing.push(x.to_bytes());
    existing.push(PublicKey::from(&x).to_bytes());
    // DR blob key (daemon `identity_key_bytes_from_seed`), recomputed here.
    let dr = {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &s);
        let mut okm = [0u8; 32];
        hk.expand(b"viaticum-dr-key-v1", &mut okm).unwrap();
        okm
    };
    existing.push(dr);

    let mut new: Vec<[u8; 32]> = Vec::new();
    for e in [0u64, 1, 2, 691] {
        existing.push(
            derive_epoch_key(&s, EpochCounter(e as u32))
                .unwrap()
                .key_bytes,
        );
        let k = RendezvousKeys::derive(&s, RendezvousEpoch(e));
        new.push(k.signing_key.to_bytes());
        new.push(k.address.0);
        new.push(*k.seal_key);
    }

    let mut all: HashSet<[u8; 32]> = existing.iter().copied().collect();
    assert_eq!(all.len(), existing.len(), "existing derivations collide");
    for k in &new {
        assert!(all.insert(*k), "new key {} collides", hex_encode(k));
    }
}

#[test]
fn rendezvous_keys_debug_does_not_print_secrets() {
    let keys = RendezvousKeys::derive(&seed(), RendezvousEpoch(691));
    let dbg = format!("{keys:?}");
    assert!(!dbg.contains(&hex_encode(&keys.seal_key[..])));
    assert!(!dbg.contains(&hex_encode(&keys.signing_key.to_bytes())));
    assert!(!dbg.contains("seal_key") && !dbg.contains("signing_key"));
}

// ============================================================
// Known-answer vectors for the raw layers
// ============================================================

#[test]
fn aad_matches_known_vector() {
    assert_eq!(
        hex_encode(&aad(2, MailboxClass::PosChallenge, &[0x11; 32])),
        "766961746963756d2d6d61696c626f782d6161642d7631\
         0201\
         1111111111111111111111111111111111111111111111111111111111111111"
    );
}

#[test]
fn directed_raw_matches_known_vector() {
    let (r_sk, r_pub) = recipient();
    assert_eq!(
        hex_encode(&r_pub),
        "132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472"
    );
    let esk = StaticSecret::from([0x24; 32]);
    let aad = aad(2, MailboxClass::PosChallenge, &[0x11; 32]);
    let pt = b"viaticum directed test vector";
    let payload = seal_directed_raw(&esk, &r_pub, &aad, pt).unwrap();
    assert_eq!(
        hex_encode(&payload),
        "04bcd2e0d00f2cce5fe8f1c6c2fbec5c07fa56e3aa5c88a5689975d88b3fce05\
         1fb173a6a1c1a031465e6b824d86e96e28eb5c9e389485b6bcd4eb0a05b52ba3\
         641ecf79126f93195be750699c"
    );
    assert_eq!(open_directed_raw(&r_sk, &aad, &payload).unwrap(), pt);
}

#[test]
fn self_raw_matches_known_vector() {
    let keys = RendezvousKeys::derive(&seed(), RendezvousEpoch(691));
    let aad = aad(2, MailboxClass::SelfPointer, &keys.address.0);
    let pt = b"viaticum self-seal test vector";
    let payload = seal_self_raw(&keys.seal_key, [7; 12], &aad, pt);
    assert_eq!(
        hex_encode(&payload),
        "070707070707070707070707\
         2478cb5e08eb7320c889222b54163836a2fa21f975974b7c56b0db502067da84\
         db9a11355339ee9a727ec9478f53"
    );
    assert_eq!(open_self_raw(&keys.seal_key, &aad, &payload).unwrap(), pt);
}

/// Pins the whole directed envelope, including the CBOR layout of SealedBody
/// (`{"sender": [32 u8], "body": bstr}`), against an independent encoder.
#[test]
fn directed_envelope_matches_known_vector() {
    let (_, r_pub) = recipient();
    let esk = StaticSecret::from([0x24; 32]);
    let sealed = seal_directed_with_esk(
        &esk,
        &r_pub,
        MailboxAddress([0x11; 32]),
        MailboxClass::DeleteRequest,
        [0x01; 16],
        IdentityPub([0x33; 32]),
        b"hello",
        NOW + 3600,
        NOW,
    )
    .unwrap();
    assert_eq!(
        hex_encode(&sealed.entry().payload),
        "04bcd2e0d00f2cce5fe8f1c6c2fbec5c07fa56e3aa5c88a5689975d88b3fce05\
         cbbe61b7a6c6b02efe1a1ac330d6853854f830c853d3bdf3c18487566f7e9bad\
         58e71b7822f26520e263e4b3dba1ce57cc762d87bbbe88cef66847a508f07456\
         0d55d2d607a24c165b300aa2d004bb905acffcd6d37fc58df8aa5ece218c353d\
         810ab9fea7"
    );
}

// ============================================================
// Self scheme
// ============================================================

#[test]
fn self_seal_roundtrip() {
    let keys = RendezvousKeys::derive(&seed(), now_epoch());
    let sealed = seal_pointer(&keys, b"cbor(self pointer)");
    assert_eq!(sealed.target(), keys.address);
    let entry = sealed.entry();
    assert_eq!(entry.class, MailboxClass::SelfPointer);
    assert_eq!(entry.payload_version, SEALED_PAYLOAD_VERSION);
    assert_eq!(entry.sender, None);
    // A DR machine re-derives the keys from the seed alone and opens it.
    let dr_keys = RendezvousKeys::derive(&seed(), now_epoch());
    assert_eq!(
        open_self_pointer(&dr_keys, entry).unwrap(),
        b"cbor(self pointer)"
    );
}

#[test]
fn self_seal_open_fails_with_other_seed() {
    let keys = RendezvousKeys::derive(&seed(), now_epoch());
    let sealed = seal_pointer(&keys, b"pointer");
    let other = RendezvousKeys::derive(&other_seed(), now_epoch());
    assert!(matches!(
        open_self_pointer(&other, sealed.entry()),
        Err(SealError::Open)
    ));
}

#[test]
fn self_seal_open_fails_when_moved_to_other_epoch_box() {
    let e = now_epoch();
    let sealed = seal_pointer(&RendezvousKeys::derive(&seed(), e), b"pointer");
    let next = RendezvousKeys::derive(&seed(), e.next());
    let mut moved = sealed.entry().clone();
    moved.target = next.address;
    assert!(matches!(
        open_self_pointer(&next, &moved),
        Err(SealError::Open)
    ));
}

/// Same key, different box: only the AAD binding catches this.
#[test]
fn self_seal_open_fails_when_target_is_changed() {
    let keys = RendezvousKeys::derive(&seed(), now_epoch());
    let mut moved = seal_pointer(&keys, b"pointer").entry().clone();
    moved.target = MailboxAddress([0x44; 32]);
    assert!(matches!(
        open_self_pointer(&keys, &moved),
        Err(SealError::Open)
    ));
}

#[test]
fn self_seal_uses_fresh_nonce_per_call() {
    let keys = RendezvousKeys::derive(&seed(), now_epoch());
    let a = seal_pointer(&keys, b"pointer");
    let b = seal_pointer(&keys, b"pointer");
    assert_ne!(a.entry().payload[..12], b.entry().payload[..12]);
}

#[test]
fn open_self_pointer_rejects_directed_class_and_old_version() {
    let keys = RendezvousKeys::derive(&seed(), now_epoch());
    let mut entry = seal_pointer(&keys, b"pointer").entry().clone();
    entry.class = MailboxClass::PosChallenge;
    assert!(matches!(
        open_self_pointer(&keys, &entry),
        Err(SealError::WrongClass(MailboxClass::PosChallenge))
    ));
    let mut entry = seal_pointer(&keys, b"pointer").entry().clone();
    entry.payload_version = 1;
    assert!(matches!(
        open_self_pointer(&keys, &entry),
        Err(SealError::UnsupportedVersion(1))
    ));
}

// ============================================================
// AC-11: directed scheme — only the recipient opens, AAD binds box and class
// ============================================================

#[test]
fn directed_roundtrip_opens_with_recipient_key() {
    let (r_sk, r_pub) = recipient();
    let sealed = seal_to(&r_pub, MailboxClass::PosChallenge, b"challenge body");
    assert_eq!(sealed.target_sig(), None);
    let entry = sealed.entry();
    assert_eq!(entry.sender, None, "sender is not in the header");
    assert_eq!(entry.payload_version, SEALED_PAYLOAD_VERSION);
    let opened = open_directed(&r_sk, entry).unwrap();
    assert_eq!(opened.sender, IdentityPub([0x33; 32]));
    assert_eq!(opened.body, b"challenge body");
    // A sibling device re-derives the same master x25519 from the shared seed.
    let master_x = derive_x25519_secret(&seed());
    let to_master = seal_to(
        &PublicKey::from(&master_x).to_bytes(),
        MailboxClass::DropNotice,
        b"drop",
    );
    let sibling_x = derive_x25519_secret(&seed());
    assert_eq!(
        open_directed(&sibling_x, to_master.entry()).unwrap().body,
        b"drop"
    );
}

#[test]
fn directed_open_fails_with_other_master_key() {
    let (_, r_pub) = recipient();
    let sealed = seal_to(&r_pub, MailboxClass::DeleteRequest, b"delete");
    let other = derive_x25519_secret(&other_seed());
    assert!(matches!(
        open_directed(&other, sealed.entry()),
        Err(SealError::Open)
    ));
}

#[test]
fn directed_open_fails_when_class_is_relabelled() {
    let (r_sk, r_pub) = recipient();
    let mut entry = seal_to(&r_pub, MailboxClass::DeleteRequest, b"delete")
        .entry()
        .clone();
    entry.class = MailboxClass::Revocation;
    assert!(matches!(open_directed(&r_sk, &entry), Err(SealError::Open)));
}

#[test]
fn directed_open_fails_when_target_is_changed() {
    let (r_sk, r_pub) = recipient();
    let mut entry = seal_to(&r_pub, MailboxClass::PosResponse, b"response")
        .entry()
        .clone();
    entry.target = MailboxAddress([0x12; 32]);
    assert!(matches!(open_directed(&r_sk, &entry), Err(SealError::Open)));
}

#[test]
fn directed_open_fails_when_version_is_changed() {
    let (r_sk, r_pub) = recipient();
    let mut entry = seal_to(&r_pub, MailboxClass::PosResponse, b"response")
        .entry()
        .clone();
    entry.payload_version = 3;
    assert!(matches!(
        open_directed(&r_sk, &entry),
        Err(SealError::UnsupportedVersion(3))
    ));
}

#[test]
fn directed_open_fails_when_ciphertext_is_flipped() {
    let (r_sk, r_pub) = recipient();
    let sealed = seal_to(&r_pub, MailboxClass::Revocation, b"revocation");
    // Byte 31 / 0x80 is the epk bit X25519 ignores: the shared secret is unchanged,
    // so only the raw epk bytes in the HKDF salt make this flip fail.
    let last = sealed.entry().payload.len() - 1;
    for (i, mask) in [(0, 0x01), (31, 0x01), (31, 0x80), (32, 0x01), (last, 0x01)] {
        let mut entry = sealed.entry().clone();
        entry.payload[i] ^= mask;
        assert!(
            open_directed(&r_sk, &entry).is_err(),
            "flip {mask:#x} at byte {i}"
        );
    }
}

#[test]
fn directed_open_fails_on_truncated_payload() {
    let (r_sk, r_pub) = recipient();
    let mut entry = seal_to(&r_pub, MailboxClass::DropNotice, b"x")
        .entry()
        .clone();
    entry.payload.truncate(EPK_LEN + TAG_LEN - 1);
    assert!(matches!(
        open_directed(&r_sk, &entry),
        Err(SealError::Truncated)
    ));
    entry.payload.clear();
    assert!(matches!(
        open_directed(&r_sk, &entry),
        Err(SealError::Truncated)
    ));
}

#[test]
fn directed_rejects_low_order_recipient_key() {
    for point in low_order_points() {
        let res = seal_directed(
            &point,
            MailboxAddress([0x11; 32]),
            MailboxClass::PosChallenge,
            [0; 16],
            IdentityPub([0x33; 32]),
            b"x",
            NOW + 1,
            NOW,
        );
        assert!(
            matches!(res, Err(SealError::LowOrderPoint)),
            "point {}",
            hex_encode(&point)
        );
    }
}

#[test]
fn directed_open_rejects_low_order_ephemeral_key() {
    let (r_sk, r_pub) = recipient();
    let honest = seal_to(&r_pub, MailboxClass::PosChallenge, b"x");
    for point in low_order_points() {
        let mut entry = honest.entry().clone();
        entry.payload[..EPK_LEN].copy_from_slice(&point);
        assert!(matches!(
            open_directed(&r_sk, &entry),
            Err(SealError::LowOrderPoint)
        ));
    }
}

#[test]
fn seal_directed_rejects_self_pointer_class() {
    let (r_sk, r_pub) = recipient();
    let res = seal_directed(
        &r_pub,
        MailboxAddress([0x11; 32]),
        MailboxClass::SelfPointer,
        [0; 16],
        IdentityPub([0x33; 32]),
        b"x",
        NOW + 1,
        NOW,
    );
    assert!(matches!(
        res,
        Err(SealError::WrongClass(MailboxClass::SelfPointer))
    ));
    // And a directed envelope relabelled SelfPointer is refused before any crypto.
    let mut entry = seal_to(&r_pub, MailboxClass::Generic, b"x").entry().clone();
    entry.class = MailboxClass::SelfPointer;
    assert!(matches!(
        open_directed(&r_sk, &entry),
        Err(SealError::WrongClass(MailboxClass::SelfPointer))
    ));
}

#[test]
fn directed_uses_fresh_ephemeral_key_per_call() {
    let (_, r_pub) = recipient();
    let a = seal_to(&r_pub, MailboxClass::PosChallenge, b"same");
    let b = seal_to(&r_pub, MailboxClass::PosChallenge, b"same");
    assert_ne!(a.entry().payload[..EPK_LEN], b.entry().payload[..EPK_LEN]);
    assert_ne!(a.entry().payload, b.entry().payload);
}

/// Function-level half of AC-1/AC-2: the envelope carries neither the body nor
/// the sender in the clear. (The postman-disk half is C3/C4, on real handlers.)
#[test]
fn sealed_entry_contains_neither_body_nor_sender_bytes() {
    let (_, r_pub) = recipient();
    let body = b"block 0123456789abcdef holder /ip4/10.0.0.1/tcp/4001";
    let sealed = seal_to(&r_pub, MailboxClass::DeleteRequest, body);
    let entry_cbor = crate::types::to_cbor_bytes(sealed.entry());
    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(&entry_cbor, body));
    assert!(!contains(&entry_cbor, b"/ip4/10.0.0.1"));
    assert!(!contains(&entry_cbor, &[0x33; 32]));
    // The header field `sender` still exists until C4 removes it; seal leaves it empty.
    assert_eq!(sealed.entry().sender, None);
}

// ============================================================
// AC-17: sizes
// ============================================================

/// Worst case of every variable-width field (see `SEAL_OVERHEAD_BYTES`): the entry
/// is EXACTLY the cap, i.e. the constant is the true overhead, not a guess, and the
/// real postman-side size check accepts it.
#[test]
fn max_body_sealed_fits_entry_cap() {
    let (r_sk, r_pub) = recipient();
    let body = vec![0xAB; MAX_SEALED_BODY_BYTES];
    let sealed = seal_directed(
        &r_pub,
        MailboxAddress([0xFF; 32]),
        MailboxClass::DeleteRequest,
        [0xFF; 16],
        IdentityPub([0xFF; 32]),
        &body,
        u64::MAX,
        u64::MAX,
    )
    .unwrap();
    assert_eq!(
        sealed.entry().serialized_size(),
        class_config::MAX_ENTRY_BYTES,
        "SEAL_OVERHEAD_BYTES no longer equals the worst-case overhead; recompute it"
    );
    assert_eq!(open_directed(&r_sk, sealed.entry()).unwrap().body, body);

    let keys = RendezvousKeys::derive(&seed(), now_epoch());
    let pointer = seal_self_pointer(&keys, [0xFF; 16], &body, u64::MAX, u64::MAX).unwrap();
    assert!(pointer.entry().serialized_size() <= class_config::MAX_ENTRY_BYTES);

    let engine = MailboxEngine::new(test_db());
    engine.store(sealed.entry(), NOW).expect("directed fits");
    engine
        .store(pointer.entry(), NOW)
        .expect("self pointer fits");
}

#[test]
fn seal_rejects_body_over_budget() {
    let (_, r_pub) = recipient();
    let body = vec![0u8; MAX_SEALED_BODY_BYTES + 1];
    let res = seal_directed(
        &r_pub,
        MailboxAddress([0x11; 32]),
        MailboxClass::DropNotice,
        [0; 16],
        IdentityPub([0x33; 32]),
        &body,
        NOW + 1,
        NOW,
    );
    assert!(matches!(
        res,
        Err(SealError::BodyTooLarge { size, max })
            if size == MAX_SEALED_BODY_BYTES + 1 && max == MAX_SEALED_BODY_BYTES
    ));
    let keys = RendezvousKeys::derive(&seed(), now_epoch());
    assert!(matches!(
        seal_self_pointer(&keys, [0; 16], &body, NOW + 1, NOW),
        Err(SealError::BodyTooLarge { .. })
    ));
}

// ============================================================
// Store signature and fetch proof (mailbox/mod.rs, used via RendezvousKeys)
// ============================================================

#[test]
fn store_sig_roundtrip() {
    let keys = RendezvousKeys::derive(&seed(), now_epoch());
    let sealed = seal_pointer(&keys, b"pointer");
    let sig = sealed
        .target_sig()
        .expect("self pointer carries target_sig");
    verify_store_sig(sealed.entry(), &sig).unwrap();
    // Master box (C2): the same rule with the master key.
    let master = derive_master_key(&seed()).unwrap();
    let mut entry = sealed.entry().clone();
    entry.target = MailboxAddress::for_master(&master_identity(&master));
    verify_store_sig(&entry, &sign_store(&master, &entry)).unwrap();
}

#[test]
fn store_sig_fails_when_payload_changes() {
    let keys = RendezvousKeys::derive(&seed(), now_epoch());
    let sealed = seal_pointer(&keys, b"pointer");
    let sig = sealed.target_sig().unwrap();
    let mut entry = sealed.entry().clone();
    entry.payload[20] ^= 1;
    assert!(matches!(
        verify_store_sig(&entry, &sig),
        Err(MailboxError::Unauthorized)
    ));
}

type Mutator = fn(&mut MailboxEntry);

#[test]
fn store_sig_fails_when_any_signed_header_field_changes() {
    let keys = RendezvousKeys::derive(&seed(), now_epoch());
    let sealed = seal_pointer(&keys, b"pointer");
    let sig = sealed.target_sig().unwrap();
    let base = sealed.entry().clone();
    let mutations: [(&str, Mutator); 6] = [
        ("target", |e| {
            e.target = RendezvousKeys::derive(&seed(), RendezvousEpoch(1)).address
        }),
        ("class", |e| e.class = MailboxClass::Generic),
        ("msg_id", |e| e.msg_id[0] ^= 1),
        ("payload_version", |e| e.payload_version = 1),
        ("expires_at", |e| e.expires_at += 1),
        ("stored_at", |e| e.stored_at -= 1),
    ];
    for (name, mutate) in mutations {
        let mut entry = base.clone();
        mutate(&mut entry);
        assert!(
            verify_store_sig(&entry, &sig).is_err(),
            "store sig still valid after changing {name}"
        );
    }
}

#[test]
fn store_sig_by_other_epoch_key_is_unauthorized() {
    let e = now_epoch();
    let keys = RendezvousKeys::derive(&seed(), e);
    let sealed = seal_pointer(&keys, b"pointer");
    let prev = RendezvousKeys::derive(&seed(), e.prev().unwrap());
    let forged = prev.sign_store(sealed.entry());
    assert!(matches!(
        verify_store_sig(sealed.entry(), &forged),
        Err(MailboxError::Unauthorized)
    ));
}

/// verify_strict: a small-order address with the trivial signature (R = identity,
/// s = 0) satisfies the cofactorless equation for every message; it must not
/// authorize a write or a read.
#[test]
fn small_order_address_forgery_is_rejected() {
    use ed25519_dalek::Verifier;
    let mut identity_point = [0u8; 32];
    identity_point[0] = 1;
    let mut trivial_sig = [0u8; 64];
    trivial_sig[0] = 1;
    let keys = RendezvousKeys::derive(&seed(), now_epoch());
    let mut entry = seal_pointer(&keys, b"pointer").entry().clone();
    entry.target = MailboxAddress(identity_point);
    let addr = MailboxAddress(identity_point);
    let vk = addr.verifying_key().expect("identity is a valid encoding");
    assert!(
        vk.verify(
            &crate::mailbox::store_sig_input(&entry),
            &ed25519_dalek::Signature::from_bytes(&trivial_sig)
        )
        .is_ok(),
        "precondition: the lax check accepts the trivial forgery"
    );
    assert!(matches!(
        verify_store_sig(&entry, &trivial_sig),
        Err(MailboxError::Unauthorized)
    ));
    assert!(!verify_fetch_proof(&addr, &DeviceId([9; 32]), &trivial_sig));
}

#[test]
fn fetch_proof_bound_to_requester_device() {
    let keys = RendezvousKeys::derive(&seed(), now_epoch());
    let dev_a = DeviceId([0xAA; 32]);
    let dev_b = DeviceId([0xBB; 32]);
    let proof = keys.fetch_proof(&dev_a);
    assert!(verify_fetch_proof(&keys.address, &dev_a, &proof));
    assert!(!verify_fetch_proof(&keys.address, &dev_b, &proof));
    let other_box = RendezvousKeys::derive(&seed(), now_epoch().next()).address;
    assert!(!verify_fetch_proof(&other_box, &dev_a, &proof));
    // A store signature is not a fetch proof (domain separation).
    let sealed = seal_pointer(&keys, b"pointer");
    assert!(!verify_fetch_proof(
        &keys.address,
        &dev_a,
        &sealed.target_sig().unwrap()
    ));
}
