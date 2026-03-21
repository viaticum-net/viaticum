use crate::constants::{HANDSHAKE_FRESHNESS_SECS, MAX_RELAY_HOP, RELAY_TTL_SECS};
use crate::erasure::Symbol;
use crate::types::{IdentityPub, NodeId, SourceBlockId, Timestamp};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

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
    })
}

fn minimal_peer_announce() -> Message {
    Message::PeerAnnounce(PeerAnnounceMsg {
        v: 1,
        identity_pub: make_identity_pub(2),
        node_id: make_node_id(2),
        timestamp: Timestamp(1000),
        sig: [0u8; 64],
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
    let msg = build_handshake(identity_pub, now, &signing_key);
    let result = verify_handshake(&msg, now);
    assert!(result.is_ok());
}

#[test]
fn verify_handshake_fails_bad_signature() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let identity_pub = IdentityPub(signing_key.verifying_key().to_bytes());
    let mut msg = build_handshake(identity_pub, Timestamp(1_000_000), &signing_key);
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
    let msg = build_handshake(identity_pub, old_ts, &signing_key);
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
        }),
        Message::PeerAnnounce(PeerAnnounceMsg {
            v: 1,
            identity_pub: make_identity_pub(1),
            node_id: make_node_id(1),
            timestamp: ts,
            sig: [0u8; 64],
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
            reason: "not enough tenure".to_string(),
            required_weeks: 4,
            current_weeks: 1,
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
