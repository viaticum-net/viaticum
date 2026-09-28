use crate::cluster::{
    EpochCounter, derive_device_key, derive_master_key, issue_device_certificate, issue_revocation,
    master_identity,
};
use crate::constants::HANDSHAKE_FRESHNESS_SECS;
use crate::erasure::Symbol;
use crate::types::{DeviceId, Event, EventEntry, IdentityPub, SourceBlockId, Timestamp};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use super::*;

// ─── helpers ────────────────────────────────────────────────────────────────

fn make_source_block_id(byte: u8) -> SourceBlockId {
    let mut id = [0u8; 32];
    id[0] = byte;
    SourceBlockId(id)
}

fn make_identity_pub(byte: u8) -> IdentityPub {
    let mut id = [0u8; 32];
    id[0] = byte;
    IdentityPub(id)
}

fn minimal_handshake() -> Message {
    Message::Handshake(HandshakeMsg {
        v: 1,
        identity_pub: IdentityPub([1u8; 32]),
        timestamp: Timestamp(1000),
        sig: [0u8; 64],
        device_cert: None,
    })
}

fn minimal_peer_announce() -> Message {
    Message::PeerAnnounce(PeerAnnounceMsg {
        v: 1,
        identity_pub: make_identity_pub(2),
        timestamp: Timestamp(1000),
        sig: [0u8; 64],
        x25519_pub: None,
    })
}

// ─── tests ──────────────────────────────────────────────────────────────────

#[test]
fn frame_message_roundtrip_handshake() {
    let msg = minimal_handshake();
    let framed = frame_message(&msg).unwrap();
    assert!(framed.len() >= 4);
    let (decoded, consumed) = unframe_message(&framed).unwrap();
    assert_eq!(decoded, msg);
    assert_eq!(consumed, framed.len());
}

#[test]
fn frame_message_length_prefix_is_big_endian() {
    let msg = minimal_peer_announce();
    let framed = frame_message(&msg).unwrap();
    let declared_len = u32::from_be_bytes(framed[0..4].try_into().unwrap()) as usize;
    assert_eq!(declared_len, framed.len() - 4);
}

#[test]
fn unframe_message_returns_buffer_too_short_for_3_bytes() {
    let result = unframe_message(&[0x00, 0x00, 0x01]);
    assert!(matches!(result, Err(MessageError::BufferTooShort)));
}

#[test]
fn unframe_message_returns_frame_length_mismatch() {
    // Declare length 100, but only provide 10 bytes of payload.
    let mut buf = vec![0u8, 0u8, 0u8, 100u8];
    buf.extend_from_slice(&[0u8; 10]);
    let result = unframe_message(&buf);
    assert!(matches!(
        result,
        Err(MessageError::FrameLengthMismatch { .. })
    ));
}

#[test]
fn frame_message_too_large_returns_error() {
    // Construct a SymbolTransferMsg with > MAX_MESSAGE_SIZE worth of symbol data.
    // MAX_MESSAGE_SIZE = 128 MiB = 134_217_728 bytes.
    // 2100 × 65535 bytes raw ≈ 137.7 MiB > 128 MiB (CBOR adds per-field overhead).
    let big_symbols: Vec<Symbol> = (0..2100u32)
        .map(|i| Symbol {
            esi: i,
            data: vec![0u8; 65535],
        })
        .collect();
    let msg = Message::SymbolTransfer(SymbolTransferMsg {
        v: 1,
        source_block_id: make_source_block_id(1),
        symbols: big_symbols,
        timestamp: Timestamp(1000),
    });
    let result = frame_message(&msg);
    assert!(matches!(result, Err(MessageError::TooLarge { .. })));
}

#[test]
fn build_and_verify_handshake_passes() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(signing_key.verifying_key().to_bytes());
    let now = Timestamp(1_000_000);
    let msg = build_handshake(identity_pub, now, &signing_key, None);
    let result = verify_handshake(&msg, now);
    assert!(result.is_ok());
}

#[test]
fn verify_handshake_fails_bad_signature() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(signing_key.verifying_key().to_bytes());
    let mut msg = build_handshake(identity_pub, Timestamp(1_000_000), &signing_key, None);
    msg.sig[0] ^= 0xFF;
    let result = verify_handshake(&msg, Timestamp(1_000_000));
    assert!(matches!(result, Err(MessageError::BadSignature)));
}

#[test]
fn verify_handshake_fails_stale_timestamp() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(signing_key.verifying_key().to_bytes());
    let old_ts = Timestamp(1_000_000);
    let now = Timestamp(1_000_000 + HANDSHAKE_FRESHNESS_SECS + 1);
    let msg = build_handshake(identity_pub, old_ts, &signing_key, None);
    let result = verify_handshake(&msg, now);
    assert!(matches!(result, Err(MessageError::HandshakeStale { .. })));
}

#[test]
fn all_message_variants_frame_roundtrip() {
    let sbid = make_source_block_id(1);
    let ts = Timestamp(1000);

    let msgs: Vec<Message> = vec![
        Message::Handshake(HandshakeMsg {
            v: 1,
            identity_pub: IdentityPub([1u8; 32]),
            timestamp: ts,
            sig: [0u8; 64],
            device_cert: None,
        }),
        Message::PeerAnnounce(PeerAnnounceMsg {
            v: 1,
            identity_pub: make_identity_pub(1),
            timestamp: ts,
            sig: [0u8; 64],
            x25519_pub: None,
        }),
        Message::SymbolOffer(SymbolOfferMsg {
            v: 1,
            msg_id: [0u8; 16],
            source_block_id: sbid,
            esi_ranges: vec![(0, 10)],
            importance: 0.5,
            timestamp: ts,
            sig: [0u8; 64],
        }),
        Message::SymbolAccept(SymbolAcceptMsg {
            v: 1,
            source_block_id: sbid,
            offer_msg_id: [0u8; 16],
            timestamp: ts,
        }),
        Message::SymbolReject(SymbolRejectMsg {
            v: 1,
            source_block_id: sbid,
            offer_msg_id: [0u8; 16],
            reason: RejectReason::QuotaFull,
            timestamp: ts,
        }),
        Message::SymbolStored(SymbolStoredMsg {
            v: 1,
            source_block_id: sbid,
            esi_ranges: vec![(0, 5)],
            timestamp: ts,
        }),
        Message::SymbolTransfer(SymbolTransferMsg {
            v: 1,
            source_block_id: sbid,
            symbols: vec![Symbol {
                esi: 0,
                data: vec![0u8; 8],
            }],
            timestamp: ts,
        }),
        Message::Delete(DeleteMsg {
            v: 1,
            source_block_id: sbid,
            timestamp: ts,
            sig: [0u8; 64],
        }),
        Message::CancelDelete(CancelDeleteMsg {
            v: 1,
            source_block_id: sbid,
            timestamp: ts,
            sig: [0u8; 64],
        }),
        Message::StorageWarning(StorageWarningMsg {
            v: 1,
            source_block_id: sbid,
            esi: 0,
            details: "bit rot".to_string(),
            timestamp: ts,
        }),
        Message::SymbolDropped(SymbolDroppedMsg {
            v: 1,
            source_block_id: sbid,
            esi_ranges: vec![(0, 3)],
            timestamp: ts,
            sig: [0u8; 64],
        }),
        Message::SymbolDropNotice(SymbolDropNoticeMsg {
            v: 1,
            source_block_id: sbid,
            esi_ranges: vec![(0, 3)],
            deadline: Timestamp(2000),
            timestamp: ts,
            sig: [0u8; 64],
        }),
        Message::RestoreRequest(RestoreRequestMsg {
            v: 1,
            source_block_id: sbid,
            esi_list: vec![0, 1, 2],
            timestamp: ts,
        }),
        Message::RestoreResponse(RestoreResponseMsg {
            v: 1,
            source_block_id: sbid,
            symbols: vec![Symbol {
                esi: 0,
                data: vec![0u8; 8],
            }],
            timestamp: ts,
        }),
    ];

    for msg in msgs {
        let framed = frame_message(&msg).unwrap();
        let (decoded, _) = unframe_message(&framed).unwrap();
        assert_eq!(decoded, msg);
    }
}

#[test]
fn to_cbor_from_cbor_roundtrip() {
    let offer = SymbolOfferMsg {
        v: 1,
        msg_id: [0u8; 16],
        source_block_id: make_source_block_id(1),
        esi_ranges: vec![(0, 100)],
        importance: 0.7,
        timestamp: Timestamp(1000),
        sig: [0u8; 64],
    };
    let bytes = to_cbor(&offer).unwrap();
    let decoded: SymbolOfferMsg = from_cbor(&bytes).unwrap();
    assert_eq!(decoded, offer);
}

// ─── cluster / handshake extension tests ────────────────────────────────────

fn make_device_cert_for_test() -> (
    ed25519_dalek::SigningKey, // master key
    ed25519_dalek::SigningKey, // device key
    crate::cluster::DeviceCertificate,
    IdentityPub, // master identity
    DeviceId,
) {
    let seed = [0xAAu8; 32];
    let master_key = derive_master_key(&seed).unwrap();
    // device_seed is used to derive device signing key; device_id = pubkey
    let device_seed = [0x01u8; 32];
    let device_key = derive_device_key(&seed, &device_seed).unwrap();
    let device_id = DeviceId(device_key.verifying_key().to_bytes());
    let cert = issue_device_certificate(&master_key, device_id, Timestamp(1_000_000));
    let master_pub = master_identity(&master_key);
    (master_key, device_key, cert, master_pub, device_id)
}

#[test]
fn handshake_with_device_cert_round_trip() {
    let (_, device_key, cert, _, _) = make_device_cert_for_test();
    let device_pub = IdentityPub(device_key.verifying_key().to_bytes());
    let now = Timestamp(1_000_000);
    let msg = build_handshake(device_pub, now, &device_key, Some(cert.clone()));
    let framed = frame_message(&Message::Handshake(msg.clone())).unwrap();
    let (decoded, _) = unframe_message(&framed).unwrap();
    match decoded {
        Message::Handshake(h) => {
            assert_eq!(h.device_cert, Some(cert));
            assert_eq!(h.identity_pub, device_pub);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn handshake_without_device_cert_backward_compat() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(signing_key.verifying_key().to_bytes());
    let now = Timestamp(1_000_000);
    let msg = build_handshake(identity_pub, now, &signing_key, None);
    let framed = frame_message(&Message::Handshake(msg)).unwrap();
    let (decoded, _) = unframe_message(&framed).unwrap();
    match decoded {
        Message::Handshake(h) => assert!(h.device_cert.is_none()),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn extract_cluster_identity_valid_cert() {
    let (_, device_key, cert, master_pub, _) = make_device_cert_for_test();
    let device_pub = IdentityPub(device_key.verifying_key().to_bytes());
    let msg = build_handshake(device_pub, Timestamp(1_000_000), &device_key, Some(cert));
    let result = extract_cluster_identity(&msg).unwrap();
    assert_eq!(result, Some(master_pub));
}

#[test]
fn extract_cluster_identity_none_for_no_cert() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(signing_key.verifying_key().to_bytes());
    let msg = build_handshake(identity_pub, Timestamp(1_000_000), &signing_key, None);
    let result = extract_cluster_identity(&msg).unwrap();
    assert!(result.is_none());
}

#[test]
fn extract_cluster_identity_rejects_mismatched_device_pub() {
    let (_, _device_key, cert, _, _) = make_device_cert_for_test();
    // Use a different identity_pub that doesn't match cert.device_id.0
    let other_key = SigningKey::generate(&mut OsRng);
    let other_pub = IdentityPub(other_key.verifying_key().to_bytes());
    let msg = HandshakeMsg {
        v: 1,
        identity_pub: other_pub,
        timestamp: Timestamp(1_000_000),
        sig: [0u8; 64],
        device_cert: Some(cert),
    };
    let result = extract_cluster_identity(&msg);
    assert!(matches!(result, Err(MessageError::BadSignature)));
}

#[test]
fn extract_cluster_identity_rejects_invalid_cert_signature() {
    let (_, device_key, mut cert, _, _) = make_device_cert_for_test();
    cert.signature[0] ^= 0xFF; // tamper with signature
    let device_pub = IdentityPub(device_key.verifying_key().to_bytes());
    let msg = build_handshake(device_pub, Timestamp(1_000_000), &device_key, Some(cert));
    let result = extract_cluster_identity(&msg);
    assert!(matches!(result, Err(MessageError::BadSignature)));
}

#[test]
fn revocation_broadcast_cbor_round_trip() {
    let seed = [0xBBu8; 32];
    let master_key = derive_master_key(&seed).unwrap();
    let device_seed = [0x02u8; 32];
    let device_key = derive_device_key(&seed, &device_seed).unwrap();
    let device_id = DeviceId(device_key.verifying_key().to_bytes());
    let cert = issue_device_certificate(&master_key, device_id, Timestamp(1_000_000));
    let revocation = issue_revocation(
        &master_key,
        device_id,
        Timestamp(2_000_000),
        EpochCounter(1),
    );
    let broadcast = RevocationBroadcast {
        revocation,
        device_cert: cert,
    };
    let bytes = to_cbor(&broadcast).unwrap();
    let decoded: RevocationBroadcast = from_cbor(&bytes).unwrap();
    assert_eq!(decoded, broadcast);
}

#[test]
fn cluster_sync_request_msg_round_trip() {
    let msg = ClusterSyncRequestMsg {
        v: 1,
        from_device_id: DeviceId([0x03u8; 32]),
        last_known_seq: 42,
        timestamp: Timestamp(1_000_000),
    };
    let bytes = to_cbor(&msg).unwrap();
    let decoded: ClusterSyncRequestMsg = from_cbor(&bytes).unwrap();
    assert_eq!(decoded, msg);
}

#[test]
fn cluster_sync_response_msg_round_trip() {
    let event_entry = EventEntry {
        timestamp: Timestamp(1_000_000),
        device_id: DeviceId([0x04u8; 32]),
        event: Event::DeviceAdded {
            device_id: DeviceId([0x05u8; 32]),
        },
    };
    let msg = ClusterSyncResponseMsg {
        v: 1,
        events: vec![(1u64, event_entry)],
        responder_last_seq: 1,
        timestamp: Timestamp(1_000_000),
    };
    let bytes = to_cbor(&msg).unwrap();
    let decoded: ClusterSyncResponseMsg = from_cbor(&bytes).unwrap();
    assert_eq!(decoded.v, msg.v);
    assert_eq!(decoded.responder_last_seq, msg.responder_last_seq);
    assert_eq!(decoded.events.len(), 1);
    assert_eq!(decoded.events[0].0, 1u64);
}

// ─── PROP-01: CBOR roundtrip sweep — all live Message variants ──────────────

fn all_message_variants() -> Vec<Message> {
    let sbid = make_source_block_id(1);
    let ts = Timestamp(1000);

    vec![
        Message::Handshake(HandshakeMsg {
            v: 1,
            identity_pub: IdentityPub([1u8; 32]),
            timestamp: ts,
            sig: [0u8; 64],
            device_cert: None,
        }),
        Message::PeerAnnounce(PeerAnnounceMsg {
            v: 1,
            identity_pub: make_identity_pub(1),
            timestamp: ts,
            sig: [0u8; 64],
            x25519_pub: None,
        }),
        Message::PosHashChallenge(PosHashChallengeMsg {
            v: 1,
            challenge_id: [0x01u8; 16],
            source_block_id: sbid,
            esi_ranges: vec![(0, 5)],
            timestamp: ts,
            device_id: None,
            sig: [0u8; 64],
        }),
        Message::PosHashResponse(PosHashResponseMsg {
            v: 1,
            challenge_id: [0x02u8; 16],
            source_block_id: sbid,
            chain_hash: [0x03u8; 32],
            timestamp: ts,
            device_id: None,
            sig: [0u8; 64],
        }),
        Message::PosHashNack(PosHashNackMsg {
            v: 1,
            challenge_id: [0x04u8; 16],
            source_block_id: sbid,
            first_missing_esi: 7,
            timestamp: ts,
            device_id: None,
            sig: [0u8; 64],
        }),
        Message::SymbolOffer(SymbolOfferMsg {
            v: 1,
            msg_id: [0u8; 16],
            source_block_id: sbid,
            esi_ranges: vec![(0, 10)],
            importance: 0.5,
            timestamp: ts,
            sig: [0u8; 64],
        }),
        Message::SymbolAccept(SymbolAcceptMsg {
            v: 1,
            source_block_id: sbid,
            offer_msg_id: [0u8; 16],
            timestamp: ts,
        }),
        Message::SymbolReject(SymbolRejectMsg {
            v: 1,
            source_block_id: sbid,
            offer_msg_id: [0u8; 16],
            reason: RejectReason::QuotaFull,
            timestamp: ts,
        }),
        Message::SymbolStored(SymbolStoredMsg {
            v: 1,
            source_block_id: sbid,
            esi_ranges: vec![(0, 5)],
            timestamp: ts,
        }),
        Message::SymbolTransfer(SymbolTransferMsg {
            v: 1,
            source_block_id: sbid,
            symbols: vec![crate::erasure::Symbol {
                esi: 0,
                data: vec![0u8; 8],
            }],
            timestamp: ts,
        }),
        Message::Delete(DeleteMsg {
            v: 1,
            source_block_id: sbid,
            timestamp: ts,
            sig: [0u8; 64],
        }),
        Message::CancelDelete(CancelDeleteMsg {
            v: 1,
            source_block_id: sbid,
            timestamp: ts,
            sig: [0u8; 64],
        }),
        Message::StorageWarning(StorageWarningMsg {
            v: 1,
            source_block_id: sbid,
            esi: 0,
            details: "bit rot".to_string(),
            timestamp: ts,
        }),
        Message::SymbolDropped(SymbolDroppedMsg {
            v: 1,
            source_block_id: sbid,
            esi_ranges: vec![(0, 3)],
            timestamp: ts,
            sig: [0u8; 64],
        }),
        Message::SymbolDropNotice(SymbolDropNoticeMsg {
            v: 1,
            source_block_id: sbid,
            esi_ranges: vec![(0, 3)],
            deadline: Timestamp(2000),
            timestamp: ts,
            sig: [0u8; 64],
        }),
        Message::RestoreRequest(RestoreRequestMsg {
            v: 1,
            source_block_id: sbid,
            esi_list: vec![0, 1, 2],
            timestamp: ts,
        }),
        Message::RestoreResponse(RestoreResponseMsg {
            v: 1,
            source_block_id: sbid,
            symbols: vec![crate::erasure::Symbol {
                esi: 0,
                data: vec![0u8; 8],
            }],
            timestamp: ts,
        }),
        Message::ClusterSyncRequest(ClusterSyncRequestMsg {
            v: 1,
            from_device_id: DeviceId([0x03u8; 32]),
            last_known_seq: 7,
            timestamp: ts,
        }),
        Message::ClusterSyncResponse(ClusterSyncResponseMsg {
            v: 1,
            events: vec![(
                1u64,
                EventEntry {
                    timestamp: ts,
                    device_id: DeviceId([0x04u8; 32]),
                    event: Event::DeviceAdded {
                        device_id: DeviceId([0x05u8; 32]),
                    },
                },
            )],
            responder_last_seq: 1,
            timestamp: ts,
        }),
        Message::Ack(AckMsg { v: 1 }),
        Message::MailboxFetchRequest(MailboxFetchRequest {
            v: 2,
            target: crate::mailbox::MailboxAddress([0x10; 32]),
            since_stored_at: None,
            target_proof: Some([0x42; 64]),
        }),
        Message::MailboxFetchResponse(MailboxFetchResponse {
            v: 2,
            entries: vec![],
            served_msg_ids: vec![],
        }),
        Message::MailboxStoreRequest(MailboxStoreRequest {
            v: 2,
            target_sig: Some([0x43; 64]),
            entry: crate::mailbox::MailboxEntry {
                target: crate::mailbox::MailboxAddress([0x11; 32]),
                msg_id: [0xABu8; 16],
                class: crate::mailbox::MailboxClass::PosChallenge,
                payload_version: 1,
                payload: vec![1, 2, 3],
                expires_at: 9_999_999,
                stored_at: 1_000_000,
                sender: None,
            },
        }),
        Message::MailboxStoreResponse(MailboxStoreResponse::Ack {
            msg_id: [0xCDu8; 16],
        }),
        // Reject is a structurally distinct variant (carries a reason enum) — its
        // CBOR path differs from Ack, so sweep it too (WARN-2).
        Message::MailboxStoreResponse(MailboxStoreResponse::Reject {
            msg_id: [0xEFu8; 16],
            reason: MailboxRejectReason::NotInCandidateSet,
        }),
    ]
}

#[test]
fn all_message_variants_cbor_roundtrip_sweep() {
    let variants = all_message_variants();
    assert_eq!(
        variants.len(),
        25,
        "expected 25 instances: all 24 live Message variants, MailboxStoreResponse twice"
    );
    for msg in &variants {
        let bytes = to_cbor(msg).expect("to_cbor must not fail");
        let decoded: Message = from_cbor(&bytes).expect("from_cbor must not fail");
        assert_eq!(decoded, *msg, "CBOR roundtrip mismatch for {msg:?}");
    }
}

#[test]
fn all_message_variants_frame_unframe_roundtrip_sweep() {
    let variants = all_message_variants();
    assert_eq!(
        variants.len(),
        25,
        "expected 25 instances: all 24 live Message variants, MailboxStoreResponse twice"
    );
    for msg in &variants {
        let framed = frame_message(msg).expect("frame_message must not fail");
        let (decoded, consumed) = unframe_message(&framed).expect("unframe_message must not fail");
        assert_eq!(
            decoded, *msg,
            "frame/unframe roundtrip mismatch for {msg:?}"
        );
        assert_eq!(
            consumed,
            framed.len(),
            "consumed != framed.len() for {msg:?}"
        );
    }
}

// ─── build_peer_announce / verify_peer_announce ───────────────────────────────

#[test]
fn build_peer_announce_produces_valid_signature() {
    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(sk.verifying_key().to_bytes());
    let ts = Timestamp(1_000_000);

    let msg = super::build_peer_announce(identity_pub, ts, &sk, None);

    assert_eq!(msg.v, crate::constants::PROTOCOL_VERSION);
    assert_eq!(msg.identity_pub, identity_pub);
    assert_eq!(msg.timestamp, ts);

    // Signature must verify.
    super::verify_peer_announce(&msg).expect("signature should verify");
}

#[test]
fn verify_peer_announce_rejects_tampered_identity() {
    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(sk.verifying_key().to_bytes());
    let ts = Timestamp(2_000_000);

    let mut msg = super::build_peer_announce(identity_pub, ts, &sk, None);

    // Tamper with the identity_pub — sig should no longer verify.
    msg.identity_pub = make_identity_pub(0xFF);

    let result = super::verify_peer_announce(&msg);
    assert!(
        matches!(result, Err(super::MessageError::BadSignature)),
        "tampered identity_pub should fail verification"
    );
}

#[test]
fn peer_announce_cbor_round_trip() {
    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(sk.verifying_key().to_bytes());
    let ts = Timestamp(4_000_000);

    let msg = super::build_peer_announce(identity_pub, ts, &sk, None);

    // Serialize to CBOR and deserialize.
    let encoded = to_cbor(&msg).expect("cbor encode failed");
    let decoded: PeerAnnounceMsg = from_cbor(&encoded).expect("cbor decode failed");

    assert_eq!(decoded.identity_pub, msg.identity_pub);
    assert_eq!(decoded.timestamp, msg.timestamp);
    assert_eq!(decoded.sig, msg.sig);

    // Signature must still verify after CBOR round-trip.
    super::verify_peer_announce(&decoded).expect("signature should verify after cbor round-trip");
}

// ─── PROP-20: handshake freshness is relative to clock, not peer identity ────

#[test]
fn handshake_freshness_symmetric() {
    // Two distinct peers (A and B) each build a handshake at the same timestamp.
    // Freshness check (verify_handshake) is purely clock-relative: it only checks
    // |msg.timestamp - now|. Therefore, both handshakes must verify successfully
    // when the verifier's clock equals the timestamp they were built with.
    //
    // This also confirms that the identities are independent: verifying A's
    // handshake using A's clock works, and verifying B's using B's clock works —
    // neither party needs to know the other's identity to accept the timestamp.
    let sk_a = SigningKey::generate(&mut OsRng);
    let sk_b = SigningKey::generate(&mut OsRng);

    let identity_a = IdentityPub(sk_a.verifying_key().to_bytes());
    let identity_b = IdentityPub(sk_b.verifying_key().to_bytes());

    // Both built at the same timestamp.
    let shared_ts = Timestamp(1_700_000_000);

    let hs_a = build_handshake(identity_a, shared_ts, &sk_a, None);
    let hs_b = build_handshake(identity_b, shared_ts, &sk_b, None);

    // Both verify successfully when now == shared_ts (delta=0).
    verify_handshake(&hs_a, shared_ts).expect("peer A handshake must verify at its own timestamp");
    verify_handshake(&hs_b, shared_ts).expect("peer B handshake must verify at its own timestamp");

    // Also verify that both still verify within the freshness window.
    let within_window = Timestamp(shared_ts.0 + HANDSHAKE_FRESHNESS_SECS - 1);
    verify_handshake(&hs_a, within_window)
        .expect("peer A handshake must verify within freshness window");
    verify_handshake(&hs_b, within_window)
        .expect("peer B handshake must verify within freshness window");

    // And both reject outside the freshness window.
    let outside_window = Timestamp(shared_ts.0 + HANDSHAKE_FRESHNESS_SECS + 1);
    assert!(
        matches!(
            verify_handshake(&hs_a, outside_window),
            Err(MessageError::HandshakeStale { .. })
        ),
        "peer A handshake must be stale past freshness window"
    );
    assert!(
        matches!(
            verify_handshake(&hs_b, outside_window),
            Err(MessageError::HandshakeStale { .. })
        ),
        "peer B handshake must be stale past freshness window"
    );
}

// ─── MSG-11: unknown_message_variant_decodes_as_unknown_not_error ────────────
//
// Rolling-upgrade compatibility: when a node receives a message whose "type"
// tag is not recognised (e.g. a newer peer sends a variant that does not exist
// yet in this binary), the decode must succeed as Message::Unknown rather than
// returning an Err.  Returning Err would cause read_framed_message in swarm.rs
// to propagate an io::Error, closing the libp2p stream and disconnecting the
// peer — breaking mixed-version clusters during upgrades.

#[test]
fn unknown_message_variant_decodes_as_unknown_not_error() {
    // Build a CBOR map: {"type": "nonexistent_type", "v": 1}.
    // Message uses #[serde(tag = "type", rename_all = "snake_case")] with a
    // #[serde(other)] Unknown unit variant, so an unrecognised "type" value
    // must decode as Message::Unknown without error and without panic.
    let mut buf = Vec::new();
    ciborium::ser::into_writer(
        &ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("type".to_string()),
                ciborium::value::Value::Text("nonexistent_type".to_string()),
            ),
            (
                ciborium::value::Value::Text("v".to_string()),
                ciborium::value::Value::Integer(1.into()),
            ),
        ]),
        &mut buf,
    )
    .expect("CBOR encode of raw map failed");

    let result = from_cbor::<Message>(&buf);
    assert!(
        matches!(result, Ok(Message::Unknown)),
        "deserializing an unknown message type must return Ok(Message::Unknown), got: {result:?}"
    );
}

#[test]
fn unknown_message_variant_from_cbor_does_not_close_stream() {
    // Complementary check: verify that multiple distinct unknown type strings
    // all decode as Message::Unknown (not just one specific unknown type).
    for unknown_type in &["new_feature_v2", "future_msg", "experimental_probe"] {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(
            &ciborium::value::Value::Map(vec![(
                ciborium::value::Value::Text("type".to_string()),
                ciborium::value::Value::Text(unknown_type.to_string()),
            )]),
            &mut buf,
        )
        .expect("CBOR encode failed");

        let result = from_cbor::<Message>(&buf);
        assert!(
            matches!(result, Ok(Message::Unknown)),
            "type={unknown_type}: expected Ok(Message::Unknown), got: {result:?}"
        );
    }
}

// ─── MSG-12: all 24 live message variants have v == 1 (mailbox: v == 2, CROWN-1 C2) ─

#[test]
fn all_messages_have_version_one() {
    let variants = all_message_variants();
    assert_eq!(
        variants.len(),
        25,
        "expected 25 instances: all 24 live Message variants, MailboxStoreResponse twice"
    );

    for msg in &variants {
        let v = match msg {
            Message::Handshake(m) => m.v,
            Message::PeerAnnounce(m) => m.v,
            Message::PosHashChallenge(m) => m.v,
            Message::PosHashResponse(m) => m.v,
            Message::PosHashNack(m) => m.v,
            Message::SymbolOffer(m) => m.v,
            Message::SymbolAccept(m) => m.v,
            Message::SymbolReject(m) => m.v,
            Message::SymbolStored(m) => m.v,
            Message::SymbolTransfer(m) => m.v,
            Message::Delete(m) => m.v,
            Message::CancelDelete(m) => m.v,
            Message::StorageWarning(m) => m.v,
            Message::SymbolDropped(m) => m.v,
            Message::SymbolDropNotice(m) => m.v,
            Message::RestoreRequest(m) => m.v,
            Message::RestoreResponse(m) => m.v,
            Message::ClusterSyncRequest(m) => m.v,
            Message::ClusterSyncResponse(m) => m.v,
            Message::Ack(m) => m.v,
            Message::MailboxFetchRequest(m) => m.v,
            Message::MailboxFetchResponse(m) => m.v,
            Message::MailboxStoreRequest(m) => m.v,
            Message::MailboxStoreResponse(_) => {
                // MailboxStoreResponse is an enum (not a struct), does not have a top-level v field.
                1
            }
            // Unknown is a decode-only sentinel; it is never in all_message_variants().
            Message::Unknown => unreachable!("Unknown must not appear in all_message_variants"),
        };
        // CROWN-1 C2 changed the mailbox request/response fields: those are v = 2.
        let expected = match msg {
            Message::MailboxFetchRequest(_)
            | Message::MailboxFetchResponse(_)
            | Message::MailboxStoreRequest(_) => 2,
            _ => 1,
        };
        assert_eq!(
            v,
            expected,
            "message variant {:?} has v={v}, expected {expected}",
            std::mem::discriminant(msg)
        );
    }
}

// ─── Delete / CancelDelete signature helpers ─────────────────────────────────

#[test]
fn delete_msg_builds_and_verifies() {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let key = SigningKey::generate(&mut OsRng);
    let identity = IdentityPub(key.verifying_key().to_bytes());
    let block_id = SourceBlockId([7u8; 32]);
    let ts = Timestamp(123456);

    let msg = build_delete_msg(block_id, ts, &key);
    assert_eq!(msg.v, 1);
    assert_eq!(msg.source_block_id, block_id);
    assert_eq!(msg.timestamp, ts);
    assert!(verify_delete_msg(&msg, &identity).is_ok());
}

#[test]
fn delete_msg_wrong_owner_fails_verify() {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let key = SigningKey::generate(&mut OsRng);
    let other_key = SigningKey::generate(&mut OsRng);
    let other_identity = IdentityPub(other_key.verifying_key().to_bytes());
    let block_id = SourceBlockId([8u8; 32]);

    let msg = build_delete_msg(block_id, Timestamp(100), &key);
    assert!(verify_delete_msg(&msg, &other_identity).is_err());
}

#[test]
fn cancel_delete_msg_builds_and_verifies() {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let key = SigningKey::generate(&mut OsRng);
    let identity = IdentityPub(key.verifying_key().to_bytes());
    let block_id = SourceBlockId([9u8; 32]);
    let ts = Timestamp(789000);

    let msg = build_cancel_delete_msg(block_id, ts, &key);
    assert_eq!(msg.v, 1);
    assert_eq!(msg.source_block_id, block_id);
    assert!(verify_cancel_delete_msg(&msg, &identity).is_ok());
}

#[test]
fn cancel_delete_msg_wrong_owner_fails() {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let key = SigningKey::generate(&mut OsRng);
    let other_key = SigningKey::generate(&mut OsRng);
    let other_identity = IdentityPub(other_key.verifying_key().to_bytes());

    let msg = build_cancel_delete_msg(SourceBlockId([10u8; 32]), Timestamp(100), &key);
    assert!(verify_cancel_delete_msg(&msg, &other_identity).is_err());
}

#[test]
fn delete_sig_not_valid_as_cancel_delete() {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let key = SigningKey::generate(&mut OsRng);
    let identity = IdentityPub(key.verifying_key().to_bytes());
    let block_id = SourceBlockId([11u8; 32]);
    let ts = Timestamp(500);

    let delete_msg = build_delete_msg(block_id, ts, &key);
    // Reuse the delete sig as a cancel_delete — must fail (different discriminator).
    let fake_cancel = CancelDeleteMsg {
        v: 1,
        source_block_id: block_id,
        timestamp: ts,
        sig: delete_msg.sig,
    };
    assert!(verify_cancel_delete_msg(&fake_cancel, &identity).is_err());
}

// ─── x25519_pub field: roundtrip and backward compat ─────────────────────────

#[test]
fn peer_announce_with_x25519_roundtrips_cbor() {
    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(sk.verifying_key().to_bytes());
    let ts = Timestamp(5_000_000);
    let x25519_bytes = [42u8; 32];

    let msg = super::build_peer_announce(identity_pub, ts, &sk, Some(x25519_bytes));
    assert_eq!(msg.x25519_pub, Some(x25519_bytes));

    // Frame as a full Message and unframe.
    let framed = frame_message(&Message::PeerAnnounce(msg.clone())).expect("frame failed");
    let (decoded_msg, consumed) = unframe_message(&framed).expect("unframe failed");
    assert_eq!(consumed, framed.len());

    let decoded = match decoded_msg {
        Message::PeerAnnounce(m) => m,
        other => panic!("expected PeerAnnounce, got {other:?}"),
    };
    assert_eq!(
        decoded.x25519_pub,
        Some(x25519_bytes),
        "x25519_pub must survive frame/unframe"
    );
    assert_eq!(decoded.identity_pub, msg.identity_pub);
    // Signature still verifies after round-trip.
    super::verify_peer_announce(&decoded).expect("sig must verify after roundtrip");
}

// ─── SymbolDropNoticeBatchMsg roundtrip ──────────────────────────────────────

#[test]
fn symbol_drop_notice_batch_msg_roundtrips_cbor() {
    use super::{SymbolDropNoticeBatchMsg, SymbolDropNoticeMsg};

    let ts = Timestamp(2_000_000);
    let sbid1 = make_source_block_id(1);
    let sbid2 = make_source_block_id(2);

    let batch = SymbolDropNoticeBatchMsg {
        v: 1,
        notices: vec![
            SymbolDropNoticeMsg {
                v: 1,
                source_block_id: sbid1,
                esi_ranges: vec![(0, 3), (5, 8)],
                deadline: Timestamp(ts.0 + 86400 * 14),
                timestamp: ts,
                sig: [0u8; 64],
            },
            SymbolDropNoticeMsg {
                v: 1,
                source_block_id: sbid2,
                esi_ranges: vec![(1, 4)],
                deadline: Timestamp(ts.0 + 86400 * 14),
                timestamp: ts,
                sig: [0u8; 64],
            },
        ],
    };

    let bytes = to_cbor(&batch).expect("to_cbor must not fail");
    let decoded: SymbolDropNoticeBatchMsg = from_cbor(&bytes).expect("from_cbor must not fail");
    assert_eq!(
        decoded, batch,
        "CBOR roundtrip mismatch for SymbolDropNoticeBatchMsg"
    );
    assert_eq!(decoded.notices.len(), 2);
    assert_eq!(decoded.notices[0].source_block_id, sbid1);
    assert_eq!(decoded.notices[0].esi_ranges, vec![(0, 3), (5, 8)]);
    assert_eq!(decoded.notices[1].source_block_id, sbid2);
}

#[test]
fn symbol_drop_notice_batch_msg_empty_notices_roundtrips() {
    use super::SymbolDropNoticeBatchMsg;

    let batch = SymbolDropNoticeBatchMsg {
        v: 1,
        notices: vec![],
    };
    let bytes = to_cbor(&batch).expect("to_cbor");
    let decoded: SymbolDropNoticeBatchMsg = from_cbor(&bytes).expect("from_cbor");
    assert_eq!(decoded, batch);
    assert!(decoded.notices.is_empty());
}

// ─── AckMsg ───────────────────────────────────────────────────────────────────

#[test]
fn ack_msg_roundtrips_cbor() {
    let msg = Message::Ack(AckMsg { v: 1 });

    // CBOR roundtrip.
    let bytes = to_cbor(&msg).expect("to_cbor must not fail");
    let decoded: Message = from_cbor(&bytes).expect("from_cbor must not fail");
    assert_eq!(decoded, msg, "CBOR roundtrip mismatch");

    // Frame/unframe roundtrip.
    let framed = frame_message(&msg).expect("frame_message must not fail");
    let (unframed, consumed) = unframe_message(&framed).expect("unframe_message must not fail");
    assert_eq!(unframed, msg, "frame/unframe roundtrip mismatch");
    assert_eq!(consumed, framed.len(), "consumed != framed.len()");
}

#[test]
fn peer_announce_without_x25519_deserializes_as_none() {
    // Simulate a pre-x25519_pub node by building a CBOR map that lacks the
    // x25519_pub key entirely (not just null). #[serde(default)] must produce
    // x25519_pub == None when the field is missing from the wire payload.
    use ciborium::value::Value;

    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub_bytes = sk.verifying_key().to_bytes();
    let node_id_bytes = [11u8; 32];
    let ts_u64: u64 = 6_000_000;
    // Build a 64-byte zero signature (not actually valid — sufficient for this decode test).
    let sig_bytes = vec![0u8; 64];

    // Manually craft CBOR for PeerAnnounceMsg without x25519_pub field.
    // Fields: v, identity_pub, node_id, timestamp, sig.
    let cbor_map = Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(1.into())),
        (
            Value::Text("identity_pub".into()),
            Value::Bytes(identity_pub_bytes.to_vec()),
        ),
        (
            Value::Text("node_id".into()),
            Value::Bytes(node_id_bytes.to_vec()),
        ),
        (
            Value::Text("timestamp".into()),
            Value::Integer(ts_u64.into()),
        ),
        (Value::Text("sig".into()), Value::Bytes(sig_bytes)),
        // x25519_pub is intentionally absent.
    ]);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cbor_map, &mut buf).expect("CBOR encode failed");

    let decoded: PeerAnnounceMsg =
        from_cbor(&buf).expect("decode must succeed without x25519_pub field");
    assert_eq!(
        decoded.x25519_pub, None,
        "x25519_pub must default to None when field is absent (backward compat)"
    );
}

// ─── SymbolOffer sign / verify ────────────────────────────────────────────────

#[test]
fn symbol_offer_sign_verify_roundtrip() {
    let key = SigningKey::generate(&mut OsRng);
    let owner = IdentityPub(key.verifying_key().to_bytes());
    let block_id = SourceBlockId([0x42u8; 32]);
    let esi_ranges = vec![(0u32, 100u32), (200u32, 50u32)];
    let importance = 0.7_f64;
    let ts = Timestamp(9_999_999);
    let msg_id = [0xABu8; 16];

    let msg = super::build_symbol_offer(msg_id, block_id, esi_ranges.clone(), importance, ts, &key);

    assert_eq!(msg.v, 1);
    assert_eq!(msg.msg_id, msg_id);
    assert_eq!(msg.source_block_id, block_id);
    assert_eq!(msg.esi_ranges, esi_ranges);
    assert_eq!(msg.importance, importance);
    assert_eq!(msg.timestamp, ts);

    super::verify_symbol_offer(&msg, &owner).expect("verify must succeed for correct owner");
}

#[test]
fn symbol_offer_verify_fails_for_wrong_owner() {
    let key = SigningKey::generate(&mut OsRng);
    let other_key = SigningKey::generate(&mut OsRng);
    let wrong_owner = IdentityPub(other_key.verifying_key().to_bytes());

    let block_id = SourceBlockId([0x11u8; 32]);
    let msg = super::build_symbol_offer(
        [0u8; 16],
        block_id,
        vec![(0u32, 10u32)],
        0.5,
        Timestamp(1000),
        &key,
    );

    assert!(
        super::verify_symbol_offer(&msg, &wrong_owner).is_err(),
        "verify must fail for wrong owner"
    );
}

#[test]
fn symbol_offer_verify_fails_for_tampered_sig() {
    let key = SigningKey::generate(&mut OsRng);
    let owner = IdentityPub(key.verifying_key().to_bytes());

    let block_id = SourceBlockId([0x22u8; 32]);
    let mut msg = super::build_symbol_offer(
        [0u8; 16],
        block_id,
        vec![(0u32, 5u32)],
        0.5,
        Timestamp(2000),
        &key,
    );

    // Flip the last byte of the signature.
    msg.sig[63] ^= 0xFF;

    assert!(
        super::verify_symbol_offer(&msg, &owner).is_err(),
        "verify must fail for tampered signature"
    );
}

#[test]
fn pos_hash_challenge_cbor_roundtrip() {
    let msg = PosHashChallengeMsg {
        v: 1,
        challenge_id: [0xAA; 16],
        source_block_id: SourceBlockId([0xBB; 32]),
        esi_ranges: vec![(0, 5), (10, 3)],
        timestamp: Timestamp(1234567890),
        device_id: None,
        sig: [0u8; 64],
    };
    let bytes = to_cbor(&msg).unwrap();
    let decoded: PosHashChallengeMsg = from_cbor(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn pos_hash_response_cbor_roundtrip() {
    let msg = PosHashResponseMsg {
        v: 1,
        challenge_id: [0xCC; 16],
        source_block_id: SourceBlockId([0xEE; 32]),
        chain_hash: [0xDD; 32],
        timestamp: Timestamp(1234567890),
        device_id: None,
        sig: [0u8; 64],
    };
    let bytes = to_cbor(&msg).unwrap();
    let decoded: PosHashResponseMsg = from_cbor(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn pos_hash_nack_cbor_roundtrip() {
    let msg = PosHashNackMsg {
        v: 1,
        challenge_id: [0xEE; 16],
        source_block_id: SourceBlockId([0xFF; 32]),
        first_missing_esi: 42,
        timestamp: Timestamp(1234567890),
        device_id: None,
        sig: [0u8; 64],
    };
    let bytes = to_cbor(&msg).unwrap();
    let decoded: PosHashNackMsg = from_cbor(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn message_enum_pos_hash_challenge_roundtrip() {
    let inner = PosHashChallengeMsg {
        v: 1,
        challenge_id: [0x11; 16],
        source_block_id: SourceBlockId([0x22; 32]),
        esi_ranges: vec![(0, 10)],
        timestamp: Timestamp(999),
        device_id: Some(DeviceId([0x33; 32])),
        sig: [0u8; 64],
    };
    let msg = Message::PosHashChallenge(inner);
    let bytes = to_cbor(&msg).unwrap();
    let decoded: Message = from_cbor(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

// ─── Issue D tests: PeerAnnounce x25519_pub coverage ─────────────────────────

// AC-D1: tampered x25519_pub fails verification
#[test]
fn peer_announce_signature_covers_x25519_pub_tamper_fails() {
    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(sk.verifying_key().to_bytes());
    let ts = Timestamp(1_000_000);
    let x25519_bytes = [0x11u8; 32];

    let mut msg = super::build_peer_announce(identity_pub, ts, &sk, Some(x25519_bytes));
    // Tamper: change x25519_pub to a different value.
    msg.x25519_pub = Some([0x22u8; 32]);

    let result = super::verify_peer_announce(&msg);
    assert!(
        matches!(result, Err(super::MessageError::BadSignature)),
        "tampered x25519_pub must fail verification"
    );
}

// AC-D2: correct x25519_pub verifies
#[test]
fn peer_announce_with_correct_x25519_pub_verifies() {
    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(sk.verifying_key().to_bytes());
    let ts = Timestamp(2_000_000);
    let x25519_bytes = [0xABu8; 32];

    let msg = super::build_peer_announce(identity_pub, ts, &sk, Some(x25519_bytes));
    super::verify_peer_announce(&msg).expect("verify must succeed for correct x25519_pub");
}

// AC-D3: None x25519_pub and Some([0u8;32]) produce the same sig_input (both verify)
#[test]
fn peer_announce_none_x25519_pub_roundtrip() {
    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(sk.verifying_key().to_bytes());
    let ts = Timestamp(3_000_000);

    // Build with None — must verify.
    let msg_none = super::build_peer_announce(identity_pub, ts, &sk, None);
    super::verify_peer_announce(&msg_none).expect("None x25519_pub must verify");

    // Build with Some([0u8;32]) — must also verify.
    let msg_zero = super::build_peer_announce(identity_pub, ts, &sk, Some([0u8; 32]));
    super::verify_peer_announce(&msg_zero).expect("Some([0u8;32]) x25519_pub must verify");

    // Cross-check: sig_input for None == sig_input for Some([0u8;32]).
    let input_none = super::peer_announce_sig_input(&identity_pub, &ts, None);
    let input_zero = super::peer_announce_sig_input(&identity_pub, &ts, Some(&[0u8; 32]));
    assert_eq!(
        input_none, input_zero,
        "None and Some([0u8;32]) must produce identical sig_input"
    );

    // Cross-verify: sig built with None must also verify when x25519_pub is Some([0u8;32]).
    let mut msg_swapped = msg_none.clone();
    msg_swapped.x25519_pub = Some([0u8; 32]);
    super::verify_peer_announce(&msg_swapped)
        .expect("sig built for None must verify when field is Some([0u8;32])");
}

// AC-D4: sig_input byte layout is exactly as specified
#[test]
fn peer_announce_sig_input_includes_x25519_pub_at_known_offset() {
    let identity_pub = IdentityPub([0x01u8; 32]);
    let ts = Timestamp(0x0102030405060708u64);
    let x25519 = [0x55u8; 32];

    let input = super::peer_announce_sig_input(&identity_pub, &ts, Some(&x25519));

    assert_eq!(input.len(), 74, "sig_input must be 74 bytes");
    assert_eq!(&input[0..2], b"pa", "first 2 bytes must be b\"pa\"");
    assert_eq!(
        &input[2..34],
        &identity_pub.0,
        "bytes 2..34 must be identity_pub"
    );
    assert_eq!(
        &input[34..42],
        &ts.0.to_be_bytes(),
        "bytes 34..42 must be timestamp big-endian"
    );
    assert_eq!(&input[42..74], &x25519, "bytes 42..74 must be x25519_pub");
}

// AC-D4 variant: None uses zeroes at x25519 slot
#[test]
fn peer_announce_sig_input_uses_zeroes_for_none_x25519() {
    let identity_pub = IdentityPub([0x02u8; 32]);
    let ts = Timestamp(100);

    let input = super::peer_announce_sig_input(&identity_pub, &ts, None);
    assert_eq!(
        &input[42..74],
        &[0u8; 32],
        "None x25519_pub must encode as [0u8;32]"
    );
}

// AC-D5: old-format sig (covering only identity_pub || timestamp, 40 bytes) fails
#[test]
fn peer_announce_old_sig_format_fails_verification() {
    use ed25519_dalek::Signer;

    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(sk.verifying_key().to_bytes());
    let ts = Timestamp(4_000_000);
    let x25519 = [0xAAu8; 32];

    // Build old-format sig_input: identity_pub (32) || timestamp (8) = 40 bytes (no b"pa", no x25519)
    let mut old_input = Vec::with_capacity(40);
    old_input.extend_from_slice(&identity_pub.0);
    old_input.extend_from_slice(&ts.0.to_be_bytes());
    let old_sig = sk.sign(&old_input).to_bytes();

    // Construct msg with old sig and x25519_pub present.
    let msg = super::PeerAnnounceMsg {
        v: 1,
        identity_pub,
        timestamp: ts,
        sig: old_sig,
        x25519_pub: Some(x25519),
    };

    let result = super::verify_peer_announce(&msg);
    assert!(
        matches!(result, Err(super::MessageError::BadSignature)),
        "old-format sig must fail verification with new verify_peer_announce"
    );
}

// ─── Issue E tests: PosHashNack signature ────────────────────────────────────

// AC-E1: tampered challenge_id fails
#[test]
fn pos_hash_nack_signature_covers_challenge_id() {
    let sk = SigningKey::generate(&mut OsRng);
    let block_id = SourceBlockId([0xBBu8; 32]);
    let ts = Timestamp(1_000_000);

    let mut msg = super::build_pos_hash_nack([0x01u8; 16], block_id, 0, ts, None, &sk);
    // Tamper challenge_id.
    msg.challenge_id = [0x02u8; 16];

    let holder = IdentityPub(sk.verifying_key().to_bytes());
    let result = super::verify_pos_hash_nack(&msg, &holder);
    assert!(
        matches!(result, Err(super::MessageError::BadSignature)),
        "tampered challenge_id must fail verification"
    );
}

// AC-E2: tampered source_block_id fails
#[test]
fn pos_hash_nack_signature_covers_source_block_id() {
    let sk = SigningKey::generate(&mut OsRng);
    let block_id_a = SourceBlockId([0xAAu8; 32]);
    let block_id_b = SourceBlockId([0xCCu8; 32]);
    let ts = Timestamp(2_000_000);

    let mut msg = super::build_pos_hash_nack([0x10u8; 16], block_id_a, 5, ts, None, &sk);
    // Tamper source_block_id.
    msg.source_block_id = block_id_b;

    let holder = IdentityPub(sk.verifying_key().to_bytes());
    let result = super::verify_pos_hash_nack(&msg, &holder);
    assert!(
        matches!(result, Err(super::MessageError::BadSignature)),
        "tampered source_block_id must fail verification"
    );
}

// AC-E3: correctly built message verifies
#[test]
fn pos_hash_nack_with_correct_signature_verifies() {
    let sk = SigningKey::generate(&mut OsRng);
    let block_id = SourceBlockId([0x77u8; 32]);
    let ts = Timestamp(3_000_000);

    let msg = super::build_pos_hash_nack([0x20u8; 16], block_id, 10, ts, None, &sk);
    let holder = IdentityPub(sk.verifying_key().to_bytes());
    super::verify_pos_hash_nack(&msg, &holder).expect("correctly built PosHashNack must verify");
}

// AC-E7: old-format message (no sig field in CBOR) deserializes with sig=[0u8;64]
// and then verify_pos_hash_nack fails (zero sig is not a valid Ed25519 signature)
#[test]
fn pos_hash_nack_missing_sig_field_deserializes_to_zero() {
    use ciborium::value::Value;

    // Build a CBOR map that has all fields EXCEPT sig — simulates old wire format.
    let cbor_map = Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(1.into())),
        (
            Value::Text("challenge_id".into()),
            Value::Bytes(vec![0x11u8; 16]),
        ),
        (
            Value::Text("source_block_id".into()),
            Value::Bytes(vec![0x22u8; 32]),
        ),
        (
            Value::Text("first_missing_esi".into()),
            Value::Integer(42.into()),
        ),
        (
            Value::Text("timestamp".into()),
            Value::Integer(1234567890u64.into()),
        ),
        // sig field intentionally absent — old format
    ]);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cbor_map, &mut buf).expect("CBOR encode failed");

    let decoded: PosHashNackMsg =
        from_cbor(&buf).expect("deserialization must succeed without sig field");
    assert_eq!(
        decoded.sig, [0u8; 64],
        "missing sig field must default to [0u8; 64]"
    );

    // Now verify must fail — zero sig is not a valid Ed25519 signature.
    // Use any key as the expected holder — the zero sig will fail regardless.
    let sk = SigningKey::generate(&mut OsRng);
    let holder = IdentityPub(sk.verifying_key().to_bytes());
    let result = super::verify_pos_hash_nack(&decoded, &holder);
    assert!(
        matches!(result, Err(super::MessageError::BadSignature)),
        "zero sig (old format) must fail verify_pos_hash_nack"
    );
}

// ─── SymbolDropNotice sign / verify ──────────────────────────────────────────

#[test]
fn symbol_drop_notice_build_and_verify_passes() {
    let sk = SigningKey::generate(&mut OsRng);
    let holder = IdentityPub(sk.verifying_key().to_bytes());
    let block_id = SourceBlockId([0x42u8; 32]);
    let esi_ranges = vec![(0u32, 5u32), (10u32, 3u32)];
    let deadline = Timestamp(9_000_000);
    let ts = Timestamp(8_000_000);

    let msg =
        super::build_signed_symbol_drop_notice(block_id, esi_ranges.clone(), deadline, ts, &sk);

    assert_eq!(msg.v, 1);
    assert_eq!(msg.source_block_id, block_id);
    assert_eq!(msg.esi_ranges, esi_ranges);
    assert_eq!(msg.deadline, deadline);
    assert_eq!(msg.timestamp, ts);

    super::verify_symbol_drop_notice(&msg, &holder)
        .expect("correctly built SymbolDropNotice must verify");
}

#[test]
fn symbol_drop_notice_verify_fails_for_wrong_holder() {
    let sk = SigningKey::generate(&mut OsRng);
    let other_sk = SigningKey::generate(&mut OsRng);
    let wrong_holder = IdentityPub(other_sk.verifying_key().to_bytes());

    let msg = super::build_signed_symbol_drop_notice(
        SourceBlockId([0x11u8; 32]),
        vec![(0u32, 10u32)],
        Timestamp(1_000_000),
        Timestamp(900_000),
        &sk,
    );

    assert!(
        super::verify_symbol_drop_notice(&msg, &wrong_holder).is_err(),
        "verify must fail when checked against wrong holder identity"
    );
}

#[test]
fn symbol_drop_notice_tampered_block_id_fails_verify() {
    let sk = SigningKey::generate(&mut OsRng);
    let holder = IdentityPub(sk.verifying_key().to_bytes());

    let mut msg = super::build_signed_symbol_drop_notice(
        SourceBlockId([0xAAu8; 32]),
        vec![(0u32, 5u32)],
        Timestamp(2_000_000),
        Timestamp(1_500_000),
        &sk,
    );
    // Tamper with source_block_id after signing.
    msg.source_block_id = SourceBlockId([0xBBu8; 32]);

    assert!(
        super::verify_symbol_drop_notice(&msg, &holder).is_err(),
        "tampered source_block_id must fail verification"
    );
}

#[test]
fn symbol_drop_notice_zero_sig_fails_verify() {
    let sk = SigningKey::generate(&mut OsRng);
    let holder = IdentityPub(sk.verifying_key().to_bytes());

    let msg = super::SymbolDropNoticeMsg {
        v: 1,
        source_block_id: SourceBlockId([0x33u8; 32]),
        esi_ranges: vec![(0, 5)],
        deadline: Timestamp(3_000_000),
        timestamp: Timestamp(2_900_000),
        sig: [0u8; 64], // legacy/missing sig defaults to zeroes
    };

    assert!(
        super::verify_symbol_drop_notice(&msg, &holder).is_err(),
        "all-zero sig (unsigned legacy notice) must fail verification"
    );
}

#[test]
fn symbol_drop_notice_cbor_roundtrip_preserves_sig() {
    let sk = SigningKey::generate(&mut OsRng);
    let holder = IdentityPub(sk.verifying_key().to_bytes());
    let block_id = SourceBlockId([0x55u8; 32]);

    let msg = super::build_signed_symbol_drop_notice(
        block_id,
        vec![(0u32, 8u32)],
        Timestamp(5_000_000),
        Timestamp(4_800_000),
        &sk,
    );

    let bytes = to_cbor(&msg).expect("CBOR encode");
    let decoded: super::SymbolDropNoticeMsg = from_cbor(&bytes).expect("CBOR decode");

    assert_eq!(decoded.sig, msg.sig, "sig must survive CBOR roundtrip");
    super::verify_symbol_drop_notice(&decoded, &holder)
        .expect("sig must verify after CBOR roundtrip");
}

// ─── PosHashChallenge signature (CS-ID-5 / P1-2) ──────────────────────────────

// A correctly built challenge verifies against the signing (owner) master key.
#[test]
fn pos_hash_challenge_with_correct_signature_verifies() {
    let sk = SigningKey::generate(&mut OsRng);
    let owner = IdentityPub(sk.verifying_key().to_bytes());
    let block_id = SourceBlockId([0x11u8; 32]);

    let msg = super::build_pos_hash_challenge(
        [0x01u8; 16],
        block_id,
        vec![(0, 5), (10, 3)],
        Timestamp(1_000_000),
        None,
        &sk,
    );

    super::verify_pos_hash_challenge(&msg, &owner)
        .expect("correctly built PosHashChallenge must verify");
}

// A challenge signed by owner A does NOT verify against a different identity B —
// a postman that copies a challenge and re-stamps `sender` cannot pass verification.
#[test]
fn pos_hash_challenge_signed_by_wrong_key_is_rejected() {
    let sk = SigningKey::generate(&mut OsRng);
    let other = SigningKey::generate(&mut OsRng);
    let other_pub = IdentityPub(other.verifying_key().to_bytes());
    let block_id = SourceBlockId([0x22u8; 32]);

    let msg = super::build_pos_hash_challenge(
        [0x02u8; 16],
        block_id,
        vec![(0, 4)],
        Timestamp(2_000_000),
        None,
        &sk,
    );

    assert!(
        matches!(
            super::verify_pos_hash_challenge(&msg, &other_pub),
            Err(super::MessageError::BadSignature)
        ),
        "challenge signed by owner A must not verify against identity B"
    );
}

// The signature covers source_block_id — flipping it after signing fails verify.
#[test]
fn pos_hash_challenge_signature_covers_source_block_id() {
    let sk = SigningKey::generate(&mut OsRng);
    let owner = IdentityPub(sk.verifying_key().to_bytes());

    let mut msg = super::build_pos_hash_challenge(
        [0x03u8; 16],
        SourceBlockId([0x30u8; 32]),
        vec![(0, 6)],
        Timestamp(3_000_000),
        None,
        &sk,
    );
    msg.source_block_id = SourceBlockId([0x31u8; 32]);

    assert!(
        matches!(
            super::verify_pos_hash_challenge(&msg, &owner),
            Err(super::MessageError::BadSignature)
        ),
        "tampered source_block_id must fail verification"
    );
}

// The signature covers esi_ranges — widening the work after signing fails verify.
#[test]
fn pos_hash_challenge_signature_covers_esi_ranges() {
    let sk = SigningKey::generate(&mut OsRng);
    let owner = IdentityPub(sk.verifying_key().to_bytes());

    let mut msg = super::build_pos_hash_challenge(
        [0x04u8; 16],
        SourceBlockId([0x40u8; 32]),
        vec![(0, 2)],
        Timestamp(4_000_000),
        None,
        &sk,
    );
    msg.esi_ranges = vec![(0, 1000)];

    assert!(
        matches!(
            super::verify_pos_hash_challenge(&msg, &owner),
            Err(super::MessageError::BadSignature)
        ),
        "tampered esi_ranges must fail verification"
    );
}

// An unsigned (all-zero sig, the serde default for old messages) challenge is rejected.
#[test]
fn pos_hash_challenge_unsigned_is_rejected() {
    let owner = IdentityPub([0x50u8; 32]);
    let msg = PosHashChallengeMsg {
        v: 1,
        challenge_id: [0x05u8; 16],
        source_block_id: SourceBlockId([0x51u8; 32]),
        esi_ranges: vec![(0, 5)],
        timestamp: Timestamp(5_000_000),
        device_id: None,
        sig: [0u8; 64],
    };

    assert!(
        super::verify_pos_hash_challenge(&msg, &owner).is_err(),
        "unsigned (zero-sig) challenge must fail verify"
    );
}

// The sig survives a CBOR roundtrip and still verifies.
#[test]
fn pos_hash_challenge_cbor_roundtrip_preserves_sig() {
    let sk = SigningKey::generate(&mut OsRng);
    let owner = IdentityPub(sk.verifying_key().to_bytes());

    let msg = super::build_pos_hash_challenge(
        [0x06u8; 16],
        SourceBlockId([0x60u8; 32]),
        vec![(0, 7), (20, 2)],
        Timestamp(6_000_000),
        Some(DeviceId([0x61u8; 32])),
        &sk,
    );

    let bytes = to_cbor(&msg).expect("CBOR encode");
    let decoded: PosHashChallengeMsg = from_cbor(&bytes).expect("CBOR decode");
    assert_eq!(decoded.sig, msg.sig, "sig must survive CBOR roundtrip");
    super::verify_pos_hash_challenge(&decoded, &owner)
        .expect("sig must verify after CBOR roundtrip");
}

// ─── PosHashResponse signature (CS-ID-1 / P1-1 / P1-7) ────────────────────────

// A correctly built response verifies against the signing (holder) master key.
#[test]
fn pos_hash_response_with_correct_signature_verifies() {
    let sk = SigningKey::generate(&mut OsRng);
    let holder = IdentityPub(sk.verifying_key().to_bytes());

    let msg = super::build_pos_hash_response(
        [0x07u8; 16],
        SourceBlockId([0x70u8; 32]),
        [0x71u8; 32],
        Timestamp(7_000_000),
        None,
        &sk,
    );

    super::verify_pos_hash_response(&msg, &holder)
        .expect("correctly built PosHashResponse must verify");
}

// A response signed by holder A does NOT verify against a different identity B —
// a positioned postman forging a response cannot pass verification against the
// challenged holder's master key.
#[test]
fn pos_hash_response_signed_by_wrong_key_is_rejected() {
    let sk = SigningKey::generate(&mut OsRng);
    let other = SigningKey::generate(&mut OsRng);
    let other_pub = IdentityPub(other.verifying_key().to_bytes());

    let msg = super::build_pos_hash_response(
        [0x08u8; 16],
        SourceBlockId([0x80u8; 32]),
        [0x81u8; 32],
        Timestamp(8_000_000),
        None,
        &sk,
    );

    assert!(
        matches!(
            super::verify_pos_hash_response(&msg, &other_pub),
            Err(super::MessageError::BadSignature)
        ),
        "response signed by holder A must not verify against identity B"
    );
}

// The signature covers chain_hash — flipping the hash after signing fails verify
// (this is the exact forge a postman would attempt: valid challenge_id, garbage hash).
#[test]
fn pos_hash_response_signature_covers_chain_hash() {
    let sk = SigningKey::generate(&mut OsRng);
    let holder = IdentityPub(sk.verifying_key().to_bytes());

    let mut msg = super::build_pos_hash_response(
        [0x09u8; 16],
        SourceBlockId([0x90u8; 32]),
        [0x91u8; 32],
        Timestamp(9_000_000),
        None,
        &sk,
    );
    msg.chain_hash = [0xFFu8; 32];

    assert!(
        matches!(
            super::verify_pos_hash_response(&msg, &holder),
            Err(super::MessageError::BadSignature)
        ),
        "tampered chain_hash must fail verification"
    );
}

// The signature covers source_block_id — a postman cannot retarget a captured
// response to a different block.
#[test]
fn pos_hash_response_signature_covers_source_block_id() {
    let sk = SigningKey::generate(&mut OsRng);
    let holder = IdentityPub(sk.verifying_key().to_bytes());

    let mut msg = super::build_pos_hash_response(
        [0x0Au8; 16],
        SourceBlockId([0xA0u8; 32]),
        [0xA1u8; 32],
        Timestamp(10_000_000),
        None,
        &sk,
    );
    msg.source_block_id = SourceBlockId([0xA2u8; 32]);

    assert!(
        matches!(
            super::verify_pos_hash_response(&msg, &holder),
            Err(super::MessageError::BadSignature)
        ),
        "tampered source_block_id must fail verification"
    );
}

// An unsigned (all-zero sig, the serde default for old messages) response is rejected.
#[test]
fn pos_hash_response_unsigned_is_rejected() {
    let holder = IdentityPub([0xB0u8; 32]);
    let msg = PosHashResponseMsg {
        v: 1,
        challenge_id: [0x0Bu8; 16],
        source_block_id: SourceBlockId([0xB1u8; 32]),
        chain_hash: [0xB2u8; 32],
        timestamp: Timestamp(11_000_000),
        device_id: None,
        sig: [0u8; 64],
    };

    assert!(
        super::verify_pos_hash_response(&msg, &holder).is_err(),
        "unsigned (zero-sig) response must fail verify"
    );
}

// The sig survives a CBOR roundtrip and still verifies.
#[test]
fn pos_hash_response_cbor_roundtrip_preserves_sig() {
    let sk = SigningKey::generate(&mut OsRng);
    let holder = IdentityPub(sk.verifying_key().to_bytes());

    let msg = super::build_pos_hash_response(
        [0x0Cu8; 16],
        SourceBlockId([0xC0u8; 32]),
        [0xC1u8; 32],
        Timestamp(12_000_000),
        Some(DeviceId([0xC2u8; 32])),
        &sk,
    );

    let bytes = to_cbor(&msg).expect("CBOR encode");
    let decoded: PosHashResponseMsg = from_cbor(&bytes).expect("CBOR decode");
    assert_eq!(decoded.sig, msg.sig, "sig must survive CBOR roundtrip");
    super::verify_pos_hash_response(&decoded, &holder)
        .expect("sig must verify after CBOR roundtrip");
}

// ─── CROWN-1 C2: optional signature fields ───────────────────────────────────

#[test]
fn mailbox_store_request_without_target_sig_roundtrips_as_none() {
    let req = MailboxStoreRequest {
        v: 2,
        target_sig: None,
        entry: crate::mailbox::MailboxEntry {
            target: crate::mailbox::MailboxAddress([0x11; 32]),
            msg_id: [1; 16],
            class: crate::mailbox::MailboxClass::DropNotice,
            payload_version: 1,
            payload: vec![9],
            expires_at: 10,
            stored_at: 5,
            sender: None,
        },
    };
    let msg = Message::MailboxStoreRequest(req.clone());
    let back: Message = from_cbor(&to_cbor(&msg).unwrap()).unwrap();
    assert_eq!(back, msg);
}

#[test]
fn mailbox_fetch_request_rejects_short_target_proof() {
    #[derive(serde::Serialize)]
    struct Forged {
        v: u8,
        target: crate::mailbox::MailboxAddress,
        since_stored_at: Option<u64>,
        target_proof: Option<Vec<u8>>,
    }
    let bytes = crate::types::to_cbor_bytes(&Forged {
        v: 2,
        target: crate::mailbox::MailboxAddress([1; 32]),
        since_stored_at: None,
        target_proof: Some(vec![7; 63]),
    });
    assert!(crate::types::from_cbor_bytes::<MailboxFetchRequest>(&bytes).is_err());
}
