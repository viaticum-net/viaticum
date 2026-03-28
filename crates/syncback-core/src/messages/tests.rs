use crate::cluster::{derive_device_key, derive_master_key, issue_device_certificate, master_identity, issue_revocation, EpochCounter};
use crate::constants::{HANDSHAKE_FRESHNESS_SECS, MAX_RELAY_HOP, RELAY_TTL_SECS};
use crate::erasure::Symbol;
use crate::types::{DeviceId, Event, EventEntry, IdentityPub, NodeId, SourceBlockId, Timestamp};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use super::PosNackMsg;

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

fn make_node_id(byte: u8) -> NodeId {
    let mut id = [0u8; 32];
    id[0] = byte;
    NodeId(id)
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
        node_id: make_node_id(2),
        timestamp: Timestamp(1000),
        sig: [0u8; 64],
        x25519_pub: None,
    })
}

fn minimal_board_entry(signing_key: &SigningKey) -> (BoardEntry, [u8; 16]) {
    let author = IdentityPub(signing_key.verifying_key().to_bytes());
    let msg_id = [0u8; 16];
    let payload = b"test payload".to_vec();
    let entry = build_broadcast_entry("peer_announce", msg_id, payload, author, Timestamp(1000), signing_key);
    (entry, msg_id)
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
    // Construct a SymbolTransferMsg with > MAX_MESSAGE_SIZE worth of symbol data (~72 MB).
    let big_symbols: Vec<Symbol> = (0..1100u32)
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
fn encrypt_decrypt_directed_roundtrip() {
    let their_priv = StaticSecret::random_from_rng(OsRng);
    let their_pub = PublicKey::from(&their_priv);
    let plaintext = b"hello world directed message";
    let envelope = encrypt_directed(plaintext, &their_pub).unwrap();
    let recovered = decrypt_directed(&envelope, &their_priv).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn decrypt_directed_fails_with_wrong_key() {
    let wrong_priv = StaticSecret::random_from_rng(OsRng);
    let their_pub = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
    let envelope = encrypt_directed(b"secret", &their_pub).unwrap();
    let result = decrypt_directed(&envelope, &wrong_priv);
    assert!(result.is_err());
}

#[test]
fn build_broadcast_entry_verify_sig_passes() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let author = IdentityPub(signing_key.verifying_key().to_bytes());
    let msg_id = [0u8; 16];
    let payload = b"test broadcast payload".to_vec();
    let entry = build_broadcast_entry(
        "peer_announce",
        msg_id,
        payload,
        author,
        Timestamp(1000),
        &signing_key,
    );
    assert_eq!(entry.hop, 0);
    assert_eq!(entry.kind, BoardEntryKind::Broadcast);
    let result = verify_board_entry_sig(&entry, "peer_announce", &msg_id);
    assert!(result.is_ok());
}

#[test]
fn build_directed_entry_verify_sig_passes() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let author = IdentityPub(signing_key.verifying_key().to_bytes());
    let target = IdentityPub([2u8; 32]);
    let msg_id = [1u8; 16];
    let encrypted_payload = vec![0u8; 32];
    let entry = build_directed_entry(
        "pos_challenge",
        msg_id,
        target,
        encrypted_payload,
        author,
        Timestamp(1000),
        &signing_key,
    );
    assert_eq!(entry.target_pub, Some(target));
    let result = verify_board_entry_sig(&entry, "pos_challenge", &msg_id);
    assert!(result.is_ok());
}

#[test]
fn verify_board_entry_sig_fails_corrupted_payload() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let (mut entry, msg_id) = minimal_board_entry(&signing_key);
    entry.payload[0] ^= 0xFF;
    let result = verify_board_entry_sig(&entry, "peer_announce", &msg_id);
    assert!(matches!(result, Err(MessageError::BadSignature)));
}

#[test]
fn is_board_entry_expired_false_before_ttl() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let (mut entry, _) = minimal_board_entry(&signing_key);
    entry.created_at = Timestamp(1_000_000);
    let now = Timestamp(1_000_000 + RELAY_TTL_SECS - 1);
    assert!(!is_board_entry_expired(&entry, now));
}

#[test]
fn is_board_entry_expired_true_at_ttl() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let (mut entry, _) = minimal_board_entry(&signing_key);
    entry.created_at = Timestamp(1_000_000);
    let now = Timestamp(1_000_000 + RELAY_TTL_SECS);
    assert!(is_board_entry_expired(&entry, now));
}

#[test]
fn check_relay_hop_allows_hop_zero_and_one() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let (mut entry, _) = minimal_board_entry(&signing_key);
    entry.hop = 0;
    assert!(check_relay_hop(&entry).is_ok());
    entry.hop = 1;
    assert!(check_relay_hop(&entry).is_ok());
}

#[test]
fn check_relay_hop_rejects_hop_two() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let (mut entry, _) = minimal_board_entry(&signing_key);
    entry.hop = MAX_RELAY_HOP;
    let result = check_relay_hop(&entry);
    assert!(matches!(result, Err(MessageError::HopLimitExceeded { hop: 2 })));
}

#[test]
fn relay_copy_increments_hop() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let (mut entry, _) = minimal_board_entry(&signing_key);
    entry.hop = 0;
    let copy = relay_copy(&entry);
    assert_eq!(copy.hop, 1);
    assert_eq!(copy.sig_author, entry.sig_author);
    assert_eq!(copy.author, entry.author);
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
            node_id: make_node_id(1),
            timestamp: ts,
            sig: [0u8; 64],
            x25519_pub: None,
        }),
        Message::PosChallenge(PosChallengeMsg {
            v: 1,
            challenge_id: [0u8; 16],
            source_block_id: sbid,
            esi: 0,
            timestamp: ts,
        }),
        Message::PosResponse(PosResponseMsg {
            v: 1,
            challenge_id: [0u8; 16],
            esi: 0,
            data: vec![0u8; 16],
            timestamp: ts,
        }),
        Message::PosNack(PosNackMsg {
            v: 1,
            challenge_id: [0xABu8; 16],
            source_block_id: sbid,
            esi: 42,
            timestamp: ts,
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
        }),
        Message::SymbolDropNotice(SymbolDropNoticeMsg {
            v: 1,
            source_block_id: sbid,
            esi_ranges: vec![(0, 3)],
            deadline: Timestamp(2000),
            timestamp: ts,
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
        Message::RestoreDenied(RestoreDeniedMsg {
            v: 1,
            source_block_id: sbid,
            reason: "insufficient trust".to_string(),
            current_trust: 0.5,
            needed_trust: 2.0,
            restore_budget_gb: 11.0,
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

#[test]
fn pos_nack_msg_roundtrip() {
    let sbid = SourceBlockId([1u8; 32]);
    let ts = Timestamp(1_000_000);
    let msg = PosNackMsg {
        v: 1,
        challenge_id: [0xABu8; 16],
        source_block_id: sbid,
        esi: 42,
        timestamp: ts,
    };
    let encoded = to_cbor(&Message::PosNack(msg.clone())).unwrap();
    let decoded: Message = from_cbor(&encoded).unwrap();
    assert!(matches!(decoded, Message::PosNack(ref m) if *m == msg));
}

#[test]
fn pos_nack_framing_roundtrip() {
    let msg = Message::PosNack(PosNackMsg {
        v: 1,
        challenge_id: [0xCDu8; 16],
        source_block_id: SourceBlockId([2u8; 32]),
        esi: 99,
        timestamp: Timestamp(2_000_000),
    });
    let framed = frame_message(&msg).unwrap();
    let (decoded, consumed) = unframe_message(&framed).unwrap();
    assert_eq!(decoded, msg);
    assert_eq!(consumed, framed.len());
}

// ─── cluster / handshake extension tests ────────────────────────────────────

fn make_device_cert_for_test() -> (
    ed25519_dalek::SigningKey, // master key
    ed25519_dalek::SigningKey, // device key
    crate::cluster::DeviceCertificate,
    IdentityPub,               // master identity
    DeviceId,
) {
    let seed = [0xAAu8; 32];
    let master_key = derive_master_key(&seed).unwrap();
    let device_id = DeviceId([0x01u8; 16]);
    let device_key = derive_device_key(&seed, &device_id).unwrap();
    let device_pub = device_key.verifying_key().to_bytes();
    let cert = issue_device_certificate(&master_key, device_id, device_pub, Timestamp(1_000_000));
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
    // Use a different identity_pub that doesn't match cert.device_pub_key
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
    let device_id = DeviceId([0x02u8; 16]);
    let device_key = derive_device_key(&seed, &device_id).unwrap();
    let device_pub = device_key.verifying_key().to_bytes();
    let cert = issue_device_certificate(&master_key, device_id, device_pub, Timestamp(1_000_000));
    let revocation = issue_revocation(&master_key, device_id, Timestamp(2_000_000), EpochCounter(1));
    let broadcast = RevocationBroadcast { revocation, device_cert: cert };
    let bytes = to_cbor(&broadcast).unwrap();
    let decoded: RevocationBroadcast = from_cbor(&bytes).unwrap();
    assert_eq!(decoded, broadcast);
}

#[test]
fn cluster_sync_request_msg_round_trip() {
    let msg = ClusterSyncRequestMsg {
        v: 1,
        from_device_id: DeviceId([0x03u8; 16]),
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
        device_id: DeviceId([0x04u8; 16]),
        event: Event::DeviceAdded { device_id: DeviceId([0x05u8; 16]) },
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

// ─── SystemState + PeerDiscovery roundtrips ──────────────────────────────────

#[test]
fn system_state_backup_msg_roundtrip() {
    let msg = Message::SystemStateBackup(SystemStateBackupMsg {
        v: 1,
        encrypted_blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
        timestamp: Timestamp(1_000_000),
    });
    let framed = frame_message(&msg).unwrap();
    let (decoded, consumed) = unframe_message(&framed).unwrap();
    assert_eq!(decoded, msg);
    assert_eq!(consumed, framed.len());
}

#[test]
fn system_state_ack_msg_roundtrip() {
    let msg = Message::SystemStateAck(SystemStateAckMsg {
        v: 1,
        stored: true,
        timestamp: Timestamp(1_000_001),
    });
    let framed = frame_message(&msg).unwrap();
    let (decoded, consumed) = unframe_message(&framed).unwrap();
    assert_eq!(decoded, msg);
    assert_eq!(consumed, framed.len());
}

#[test]
fn system_state_request_msg_roundtrip() {
    let msg = Message::SystemStateRequest(SystemStateRequestMsg {
        v: 1,
        timestamp: Timestamp(1_000_002),
    });
    let framed = frame_message(&msg).unwrap();
    let (decoded, consumed) = unframe_message(&framed).unwrap();
    assert_eq!(decoded, msg);
    assert_eq!(consumed, framed.len());
}

#[test]
fn system_state_response_msg_roundtrip() {
    let msg = Message::SystemStateResponse(SystemStateResponseMsg {
        v: 1,
        encrypted_blob: vec![],
        timestamp: Timestamp(1_000_003),
    });
    let framed = frame_message(&msg).unwrap();
    let (decoded, consumed) = unframe_message(&framed).unwrap();
    assert_eq!(decoded, msg);
    assert_eq!(consumed, framed.len());
}

#[test]
fn peer_discovery_request_msg_roundtrip() {
    let msg = Message::PeerDiscoveryRequest(PeerDiscoveryRequestMsg {
        v: 1,
        timestamp: Timestamp(1_000_004),
    });
    let framed = frame_message(&msg).unwrap();
    let (decoded, consumed) = unframe_message(&framed).unwrap();
    assert_eq!(decoded, msg);
    assert_eq!(consumed, framed.len());
}

#[test]
fn peer_discovery_response_msg_roundtrip() {
    let msg = Message::PeerDiscoveryResponse(PeerDiscoveryResponseMsg {
        v: 1,
        peers: vec![
            DiscoveredPeer {
                identity_pub: make_identity_pub(10),
                node_id: make_node_id(10),
                addrs: vec![],
            },
            DiscoveredPeer {
                identity_pub: make_identity_pub(11),
                node_id: make_node_id(11),
                addrs: vec![],
            },
        ],
        timestamp: Timestamp(1_000_005),
    });
    let framed = frame_message(&msg).unwrap();
    let (decoded, consumed) = unframe_message(&framed).unwrap();
    assert_eq!(decoded, msg);
    assert_eq!(consumed, framed.len());
}

#[test]
fn discovered_peer_with_addrs_roundtrip() {
    let msg = Message::PeerDiscoveryResponse(PeerDiscoveryResponseMsg {
        v: 1,
        peers: vec![DiscoveredPeer {
            identity_pub: make_identity_pub(20),
            node_id: make_node_id(20),
            addrs: vec![
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890@192.168.1.5:12345"
                    .to_string(),
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890@[::1]:9000"
                    .to_string(),
            ],
        }],
        timestamp: Timestamp(1_000_006),
    });
    let framed = frame_message(&msg).unwrap();
    let (decoded, consumed) = unframe_message(&framed).unwrap();
    assert_eq!(decoded, msg);
    assert_eq!(consumed, framed.len());
}

#[test]
fn discovered_peer_addrs_default_for_old_cbor() {
    // Simulate a DiscoveredPeer serialized without the addrs field (protocol v1 peer).
    // With #[serde(default)], decoding must succeed and addrs must be empty.
    use serde::Serialize;

    #[derive(Serialize)]
    struct OldDiscoveredPeer {
        identity_pub: IdentityPub,
        node_id: NodeId,
    }
    #[derive(Serialize)]
    struct OldPeerDiscoveryResponseMsg {
        v: u8,
        peers: Vec<OldDiscoveredPeer>,
        timestamp: Timestamp,
    }

    let old = OldPeerDiscoveryResponseMsg {
        v: 1,
        peers: vec![OldDiscoveredPeer {
            identity_pub: make_identity_pub(30),
            node_id: make_node_id(30),
        }],
        timestamp: Timestamp(1_000_007),
    };
    let cbor = to_cbor(&old).unwrap();
    let decoded: PeerDiscoveryResponseMsg = from_cbor(&cbor).unwrap();
    assert_eq!(decoded.peers.len(), 1);
    assert_eq!(decoded.peers[0].identity_pub, make_identity_pub(30));
    assert_eq!(decoded.peers[0].addrs, Vec::<String>::new());
}

// ─── PROP-01: CBOR roundtrip sweep — all 27 Message variants ────────────────

fn all_27_message_variants() -> Vec<Message> {
    let sbid = make_source_block_id(1);
    let ts = Timestamp(1000);

    let board_entry = BoardEntry {
        kind: BoardEntryKind::Broadcast,
        target_pub: None,
        payload: vec![0xAA, 0xBB],
        sig_author: [0u8; 64],
        author: make_identity_pub(7),
        hop: 0,
        created_at: ts,
    };
    let stored_entry = StoredEntry {
        msg_type: "peer_announce".to_string(),
        msg_id: [0u8; 16],
        entry: board_entry,
    };

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
            node_id: make_node_id(1),
            timestamp: ts,
            sig: [0u8; 64],
            x25519_pub: None,
        }),
        Message::PosChallenge(PosChallengeMsg {
            v: 1,
            challenge_id: [0u8; 16],
            source_block_id: sbid,
            esi: 0,
            timestamp: ts,
        }),
        Message::PosResponse(PosResponseMsg {
            v: 1,
            challenge_id: [0u8; 16],
            esi: 0,
            data: vec![0u8; 16],
            timestamp: ts,
        }),
        Message::PosNack(PosNackMsg {
            v: 1,
            challenge_id: [0xABu8; 16],
            source_block_id: sbid,
            esi: 42,
            timestamp: ts,
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
            symbols: vec![crate::erasure::Symbol { esi: 0, data: vec![0u8; 8] }],
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
        }),
        Message::SymbolDropNotice(SymbolDropNoticeMsg {
            v: 1,
            source_block_id: sbid,
            esi_ranges: vec![(0, 3)],
            deadline: Timestamp(2000),
            timestamp: ts,
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
            symbols: vec![crate::erasure::Symbol { esi: 0, data: vec![0u8; 8] }],
            timestamp: ts,
        }),
        Message::RestoreDenied(RestoreDeniedMsg {
            v: 1,
            source_block_id: sbid,
            reason: "insufficient trust".to_string(),
            current_trust: 0.5,
            needed_trust: 2.0,
            restore_budget_gb: 11.0,
            timestamp: ts,
        }),
        Message::BoardSync(BoardSyncMsg {
            v: 1,
            entries: vec![stored_entry],
            timestamp: ts,
        }),
        Message::ClusterSyncRequest(ClusterSyncRequestMsg {
            v: 1,
            from_device_id: DeviceId([0x03u8; 16]),
            last_known_seq: 7,
            timestamp: ts,
        }),
        Message::ClusterSyncResponse(ClusterSyncResponseMsg {
            v: 1,
            events: vec![(
                1u64,
                EventEntry {
                    timestamp: ts,
                    device_id: DeviceId([0x04u8; 16]),
                    event: Event::DeviceAdded { device_id: DeviceId([0x05u8; 16]) },
                },
            )],
            responder_last_seq: 1,
            timestamp: ts,
        }),
        Message::SystemStateBackup(SystemStateBackupMsg {
            v: 1,
            encrypted_blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
            timestamp: ts,
        }),
        Message::SystemStateAck(SystemStateAckMsg {
            v: 1,
            stored: true,
            timestamp: ts,
        }),
        Message::SystemStateRequest(SystemStateRequestMsg { v: 1, timestamp: ts }),
        Message::SystemStateResponse(SystemStateResponseMsg {
            v: 1,
            encrypted_blob: vec![],
            timestamp: ts,
        }),
        Message::PeerDiscoveryRequest(PeerDiscoveryRequestMsg { v: 1, timestamp: ts }),
        Message::PeerDiscoveryResponse(PeerDiscoveryResponseMsg {
            v: 1,
            peers: vec![DiscoveredPeer {
                identity_pub: make_identity_pub(10),
                node_id: make_node_id(10),
                addrs: vec![],
            }],
            timestamp: ts,
        }),
    ]
}

#[test]
fn all_message_variants_cbor_roundtrip_sweep() {
    let variants = all_27_message_variants();
    assert_eq!(variants.len(), 27, "expected 27 Message variants");
    for msg in &variants {
        let bytes = to_cbor(msg).expect("to_cbor must not fail");
        let decoded: Message = from_cbor(&bytes).expect("from_cbor must not fail");
        assert_eq!(decoded, *msg, "CBOR roundtrip mismatch for {msg:?}");
    }
}

#[test]
fn all_message_variants_frame_unframe_roundtrip_sweep() {
    let variants = all_27_message_variants();
    assert_eq!(variants.len(), 27, "expected 27 Message variants");
    for msg in &variants {
        let framed = frame_message(msg).expect("frame_message must not fail");
        let (decoded, consumed) =
            unframe_message(&framed).expect("unframe_message must not fail");
        assert_eq!(decoded, *msg, "frame/unframe roundtrip mismatch for {msg:?}");
        assert_eq!(consumed, framed.len(), "consumed != framed.len() for {msg:?}");
    }
}

// ─── build_peer_announce / verify_peer_announce ───────────────────────────────

#[test]
fn build_peer_announce_produces_valid_signature() {
    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(sk.verifying_key().to_bytes());
    let node_id = make_node_id(5);
    let ts = Timestamp(1_000_000);

    let msg = super::build_peer_announce(identity_pub, node_id, ts, &sk, None);

    assert_eq!(msg.v, crate::constants::PROTOCOL_VERSION);
    assert_eq!(msg.identity_pub, identity_pub);
    assert_eq!(msg.node_id, node_id);
    assert_eq!(msg.timestamp, ts);

    // Signature must verify.
    super::verify_peer_announce(&msg).expect("signature should verify");
}

#[test]
fn verify_peer_announce_rejects_tampered_identity() {
    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(sk.verifying_key().to_bytes());
    let node_id = make_node_id(6);
    let ts = Timestamp(2_000_000);

    let mut msg = super::build_peer_announce(identity_pub, node_id, ts, &sk, None);

    // Tamper with the identity_pub — sig should no longer verify.
    msg.identity_pub = make_identity_pub(0xFF);

    let result = super::verify_peer_announce(&msg);
    assert!(
        matches!(result, Err(super::MessageError::BadSignature)),
        "tampered identity_pub should fail verification"
    );
}

#[test]
fn verify_peer_announce_rejects_tampered_node_id() {
    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(sk.verifying_key().to_bytes());
    let node_id = make_node_id(7);
    let ts = Timestamp(3_000_000);

    let mut msg = super::build_peer_announce(identity_pub, node_id, ts, &sk, None);

    // Tamper with the node_id.
    msg.node_id = make_node_id(0xFF);

    let result = super::verify_peer_announce(&msg);
    assert!(
        matches!(result, Err(super::MessageError::BadSignature)),
        "tampered node_id should fail verification"
    );
}

#[test]
fn peer_announce_cbor_round_trip() {
    let sk = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(sk.verifying_key().to_bytes());
    let node_id = make_node_id(8);
    let ts = Timestamp(4_000_000);

    let msg = super::build_peer_announce(identity_pub, node_id, ts, &sk, None);

    // Serialize to CBOR and deserialize.
    let encoded = to_cbor(&msg).expect("cbor encode failed");
    let decoded: PeerAnnounceMsg = from_cbor(&encoded).expect("cbor decode failed");

    assert_eq!(decoded.identity_pub, msg.identity_pub);
    assert_eq!(decoded.node_id, msg.node_id);
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
    verify_handshake(&hs_a, shared_ts)
        .expect("peer A handshake must verify at its own timestamp");
    verify_handshake(&hs_b, shared_ts)
        .expect("peer B handshake must verify at its own timestamp");

    // Also verify that both still verify within the freshness window.
    let within_window = Timestamp(shared_ts.0 + HANDSHAKE_FRESHNESS_SECS - 1);
    verify_handshake(&hs_a, within_window)
        .expect("peer A handshake must verify within freshness window");
    verify_handshake(&hs_b, within_window)
        .expect("peer B handshake must verify within freshness window");

    // And both reject outside the freshness window.
    let outside_window = Timestamp(shared_ts.0 + HANDSHAKE_FRESHNESS_SECS + 1);
    assert!(
        matches!(verify_handshake(&hs_a, outside_window), Err(MessageError::HandshakeStale { .. })),
        "peer A handshake must be stale past freshness window"
    );
    assert!(
        matches!(verify_handshake(&hs_b, outside_window), Err(MessageError::HandshakeStale { .. })),
        "peer B handshake must be stale past freshness window"
    );
}

// ─── MSG-11: unknown_message_variant_returns_error_not_panic ─────────────────

#[test]
fn unknown_message_variant_returns_error_not_panic() {
    // Build a CBOR map: {"type": "nonexistent_type", "v": 1}.
    // Message uses #[serde(tag = "type", rename_all = "snake_case")], so an
    // unknown "type" value must produce a deserialization error, not a panic.
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
        result.is_err(),
        "deserializing an unknown message type must return Err, not Ok or panic"
    );
}

// ─── MSG-12: all 27 message variants have v == 1 ─────────────────────────────

#[test]
fn all_messages_have_version_one() {
    let variants = all_27_message_variants();
    assert_eq!(variants.len(), 27, "expected 27 Message variants");

    for msg in &variants {
        let v = match msg {
            Message::Handshake(m) => m.v,
            Message::PeerAnnounce(m) => m.v,
            Message::PosChallenge(m) => m.v,
            Message::PosResponse(m) => m.v,
            Message::PosNack(m) => m.v,
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
            Message::RestoreDenied(m) => m.v,
            Message::BoardSync(m) => m.v,
            Message::ClusterSyncRequest(m) => m.v,
            Message::ClusterSyncResponse(m) => m.v,
            Message::SystemStateBackup(m) => m.v,
            Message::SystemStateAck(m) => m.v,
            Message::SystemStateRequest(m) => m.v,
            Message::SystemStateResponse(m) => m.v,
            Message::PeerDiscoveryRequest(m) => m.v,
            Message::PeerDiscoveryResponse(m) => m.v,
        };
        assert_eq!(
            v, 1,
            "message variant {:?} has v={v}, expected 1",
            std::mem::discriminant(msg)
        );
    }
}

// ─── MSG-13: RestoreDeniedMsg struct fields exist (compile-time check) ────────

#[test]
fn restore_denied_msg_fields_exist() {
    // Compile-time check that RestoreDeniedMsg has the expected fields.
    // The GAP spec mentions 'required_weeks'/'current_weeks' but those do not exist
    // in the current protocol. The actual fields are current_trust and needed_trust.
    // This test documents the actual structure and would fail to compile if the
    // fields were removed.
    let msg = RestoreDeniedMsg {
        v: 1,
        source_block_id: make_source_block_id(1),
        reason: "test".to_string(),
        current_trust: 0.3,
        needed_trust: 0.7,
        restore_budget_gb: 10.0,
        timestamp: Timestamp(1000),
    };
    assert_eq!(msg.v, 1);
    assert!((msg.current_trust - 0.3).abs() < f64::EPSILON);
    assert!((msg.needed_trust - 0.7).abs() < f64::EPSILON);
}

// ─── Delete / CancelDelete signature helpers ─────────────────────────────────

#[test]
fn delete_msg_builds_and_verifies() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

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
    use rand::rngs::OsRng;

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
    use rand::rngs::OsRng;

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
    use rand::rngs::OsRng;

    let key = SigningKey::generate(&mut OsRng);
    let other_key = SigningKey::generate(&mut OsRng);
    let other_identity = IdentityPub(other_key.verifying_key().to_bytes());

    let msg = build_cancel_delete_msg(SourceBlockId([10u8; 32]), Timestamp(100), &key);
    assert!(verify_cancel_delete_msg(&msg, &other_identity).is_err());
}

#[test]
fn delete_sig_not_valid_as_cancel_delete() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

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
    let node_id = make_node_id(10);
    let ts = Timestamp(5_000_000);
    let x25519_bytes = [42u8; 32];

    let msg = super::build_peer_announce(identity_pub, node_id, ts, &sk, Some(x25519_bytes));
    assert_eq!(msg.x25519_pub, Some(x25519_bytes));

    // Frame as a full Message and unframe.
    let framed = frame_message(&Message::PeerAnnounce(msg.clone())).expect("frame failed");
    let (decoded_msg, consumed) = unframe_message(&framed).expect("unframe failed");
    assert_eq!(consumed, framed.len());

    let decoded = match decoded_msg {
        Message::PeerAnnounce(m) => m,
        other => panic!("expected PeerAnnounce, got {other:?}"),
    };
    assert_eq!(decoded.x25519_pub, Some(x25519_bytes), "x25519_pub must survive frame/unframe");
    assert_eq!(decoded.identity_pub, msg.identity_pub);
    assert_eq!(decoded.node_id, msg.node_id);
    // Signature still verifies after round-trip.
    super::verify_peer_announce(&decoded).expect("sig must verify after roundtrip");
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
        (
            Value::Text("sig".into()),
            Value::Bytes(sig_bytes),
        ),
        // x25519_pub is intentionally absent.
    ]);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cbor_map, &mut buf).expect("CBOR encode failed");

    let decoded: PeerAnnounceMsg = from_cbor(&buf).expect("decode must succeed without x25519_pub field");
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
