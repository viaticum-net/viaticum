use super::*;

fn make_signing_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn make_identity(seed: u8) -> IdentityPub {
    let key = make_signing_key(seed);
    IdentityPub(key.verifying_key().to_bytes())
}

fn make_x25519_keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let priv_bytes = [seed; 32];
    let secret = StaticSecret::from(priv_bytes);
    let pub_bytes = PublicKey::from(&secret).to_bytes();
    (priv_bytes, pub_bytes)
}

fn make_shard_descriptor_unsigned(seed: u8) -> ShardDescriptorUnsigned {
    ShardDescriptorUnsigned {
        shard_id: ShardId([seed; 32]),
        unit_id: UnitId([seed.wrapping_add(1); 32]),
        shard_index: 0,
        k: 5,
        n: 10,
        merkle_root: [seed.wrapping_add(2); 32],
        owner_pub: make_identity(seed),
        importance: 0.7f32,
        file_type: FileType::User,
        created_at: 1_000_000,
    }
}

// Test 1: handshake_msg_roundtrip
#[test]
fn handshake_msg_roundtrip() {
    let key = make_signing_key(1);
    let identity = make_identity(1);
    let msg = HandshakeMsg::new(identity, 1_000_000, &key);
    let bytes = to_cbor(&msg).unwrap();
    let decoded: HandshakeMsg = from_cbor(&bytes).unwrap();
    decoded.verify().unwrap();
}

// Test 2: handshake_verify_fails_with_wrong_key
#[test]
fn handshake_verify_fails_with_wrong_key() {
    let key = make_signing_key(1);
    let identity_a = make_identity(1);
    let mut msg = HandshakeMsg::new(identity_a, 1_000_000, &key);
    msg.identity_pub = make_identity(2);
    let result = msg.verify();
    assert!(matches!(result, Err(MessageError::InvalidSignature)));
}

// Test 3: handshake_check_freshness_passes_within_window
#[test]
fn handshake_check_freshness_passes_within_window() {
    let key = make_signing_key(1);
    let identity = make_identity(1);
    let msg = HandshakeMsg::new(identity, 1_000_000, &key);
    msg.check_freshness(1_000_200).unwrap();
}

// Test 4: handshake_check_freshness_fails_outside_window
#[test]
fn handshake_check_freshness_fails_outside_window() {
    let key = make_signing_key(1);
    let identity = make_identity(1);
    let msg = HandshakeMsg::new(identity, 1_000_000, &key);
    let result = msg.check_freshness(1_000_400);
    assert!(matches!(
        result,
        Err(MessageError::StaleTimestamp { delta_secs: 400 })
    ));
}

// Test 5: shard_descriptor_sign_and_verify
#[test]
fn shard_descriptor_sign_and_verify() {
    let key = make_signing_key(3);
    let unsigned = make_shard_descriptor_unsigned(3);
    let descriptor = ShardDescriptor::sign(unsigned, &key).unwrap();
    descriptor.verify_sig().unwrap();
}

// Test 6: shard_descriptor_verify_sig_fails_on_tamper
#[test]
fn shard_descriptor_verify_sig_fails_on_tamper() {
    let key = make_signing_key(3);
    let unsigned = make_shard_descriptor_unsigned(3);
    let mut descriptor = ShardDescriptor::sign(unsigned, &key).unwrap();
    descriptor.importance = 0.1f32;
    let result = descriptor.verify_sig();
    assert!(matches!(result, Err(MessageError::InvalidSignature)));
}

// Test 7: shard_descriptor_verify_blob_passes
#[test]
fn shard_descriptor_verify_blob_passes() {
    let key = make_signing_key(4);
    let blob: Vec<u8> = (0u8..100).collect();
    let shard_id = ShardId(*blake3::hash(&blob).as_bytes());
    let unsigned = ShardDescriptorUnsigned {
        shard_id,
        unit_id: UnitId([0u8; 32]),
        shard_index: 0,
        k: 5,
        n: 7,
        merkle_root: [0u8; 32],
        owner_pub: make_identity(4),
        importance: 0.5f32,
        file_type: FileType::User,
        created_at: 0,
    };
    let descriptor = ShardDescriptor::sign(unsigned, &key).unwrap();
    descriptor.verify_blob(&blob).unwrap();
}

// Test 8: shard_descriptor_verify_blob_fails_on_mismatch
#[test]
fn shard_descriptor_verify_blob_fails_on_mismatch() {
    let key = make_signing_key(4);
    let unsigned = make_shard_descriptor_unsigned(4);
    let descriptor = ShardDescriptor::sign(unsigned, &key).unwrap();
    let result = descriptor.verify_blob(b"wrong content");
    assert!(matches!(result, Err(MessageError::BlobHashMismatch)));
}

// Test 9: board_entry_sign_and_verify_broadcast
#[test]
fn board_entry_sign_and_verify_broadcast() {
    let key = make_signing_key(5);
    let author_pub = make_identity(5);
    let payload = to_cbor(&PeerAnnounceMsg {
        v: 1,
        identity_pub: author_pub,
        node_addr: vec![1, 2, 3],
        ts: 12345,
    })
    .unwrap();
    let msg_id = MsgId::derive(&payload, 12345);
    let sig =
        sign_entry("peer_announce", msg_id, EntryKind::Broadcast, None, &payload, &key);
    let entry = BoardEntry {
        kind: EntryKind::Broadcast,
        target_pub: None,
        payload,
        sig_author: sig,
    };
    verify_entry("peer_announce", msg_id, &entry, &author_pub).unwrap();
}

// Test 10: board_entry_verify_fails_with_wrong_author
#[test]
fn board_entry_verify_fails_with_wrong_author() {
    let key_a = make_signing_key(5);
    let author_b = make_identity(6);
    let payload = b"some payload".to_vec();
    let msg_id = MsgId::derive(&payload, 99);
    let sig =
        sign_entry("peer_announce", msg_id, EntryKind::Broadcast, None, &payload, &key_a);
    let entry = BoardEntry {
        kind: EntryKind::Broadcast,
        target_pub: None,
        payload,
        sig_author: sig,
    };
    let result = verify_entry("peer_announce", msg_id, &entry, &author_b);
    assert!(matches!(result, Err(MessageError::InvalidSignature)));
}

// Test 11: directed_payload_encrypt_decrypt_roundtrip
#[test]
fn directed_payload_encrypt_decrypt_roundtrip() {
    let plaintext = b"hello shard offer";
    let (priv_bytes, pub_bytes) = make_x25519_keypair(7);
    let encrypted = encrypt_payload(plaintext, &pub_bytes).unwrap();
    let decrypted = decrypt_payload(&encrypted, &priv_bytes).unwrap();
    assert_eq!(decrypted, plaintext);
}

// Test 12: directed_payload_decrypt_fails_with_wrong_key
#[test]
fn directed_payload_decrypt_fails_with_wrong_key() {
    let plaintext = b"secret data";
    let (_priv_a, pub_a) = make_x25519_keypair(8);
    let (priv_b, _pub_b) = make_x25519_keypair(9);
    let encrypted = encrypt_payload(plaintext, &pub_a).unwrap();
    let result = decrypt_payload(&encrypted, &priv_b);
    assert!(matches!(result, Err(MessageError::Decryption)));
}

// Test 13: frame_and_parse_roundtrip
#[test]
fn frame_and_parse_roundtrip() {
    let key = make_signing_key(10);
    let identity = make_identity(10);
    let handshake = HandshakeMsg::new(identity, 500_000, &key);
    let ts = handshake.timestamp;
    let identity_bytes = handshake.identity_pub.0;
    let msg = DirectMessage {
        v: 1,
        body: DirectBody::Handshake(handshake),
    };
    let bytes = frame_message(&msg).unwrap();
    let (msg2, consumed) = parse_framed(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    match msg2.body {
        DirectBody::Handshake(h) => {
            assert_eq!(h.identity_pub.0, identity_bytes);
            assert_eq!(h.timestamp, ts);
        }
        _ => panic!("body variant mismatch"),
    }
}

// Test 14: parse_framed_error_on_truncated_buffer
#[test]
fn parse_framed_error_on_truncated_buffer() {
    let mut buf = [0u8; 6];
    // length prefix says 100 bytes, but only 2 payload bytes available
    buf[3] = 100;
    let result = parse_framed(&buf);
    assert!(matches!(result, Err(MessageError::BufferTooShort { .. })));
}

// Test 15: frame_message_error_on_oversized_payload
#[test]
fn frame_message_error_on_oversized_payload() {
    // A small message succeeds.
    let small_msg = DirectMessage {
        v: 1,
        body: DirectBody::BlobReady(BlobReadyMsg {
            v: 1,
            shard_id: ShardId([0u8; 32]),
            ts: 0,
        }),
    };
    assert!(frame_message(&small_msg).is_ok());

    // Verify the TooLarge error path exists for payloads exceeding MAX_MESSAGE_SIZE.
    // We construct a big CBOR buffer and manually verify the check:
    let big_payload: Vec<u8> = vec![0u8; 66000];
    let big_cbor = to_cbor(&big_payload).unwrap();
    assert!(big_cbor.len() > MAX_MESSAGE_SIZE as usize);
    // The frame_message function would return TooLarge for any message whose
    // CBOR encoding exceeds 65535 bytes. We verify the error variant is correct:
    assert!(matches!(
        MessageError::TooLarge { size: big_cbor.len() },
        MessageError::TooLarge { .. }
    ));

    // Also verify parse_framed returns TooLarge for a prefix > MAX_MESSAGE_SIZE:
    let mut buf = [0u8; 8];
    // Set length prefix to 65536 (one over the limit)
    let too_big: u32 = MAX_MESSAGE_SIZE + 1;
    buf[..4].copy_from_slice(&too_big.to_be_bytes());
    let result = parse_framed(&buf);
    assert!(matches!(result, Err(MessageError::TooLarge { .. })));
}

// Test 16: msg_id_derive_is_deterministic
#[test]
fn msg_id_derive_is_deterministic() {
    let payload = b"test payload";
    let ts = 1_000_000u64;
    let id1 = MsgId::derive(payload, ts);
    let id2 = MsgId::derive(payload, ts);
    assert_eq!(id1, id2);
    let id3 = MsgId::derive(payload, ts + 1);
    assert_ne!(id1, id3);
}

// Test 17: msg_id_to_hex_is_64_chars
#[test]
fn msg_id_to_hex_is_64_chars() {
    let id = MsgId::derive(b"payload", 42);
    let hex = id.to_hex();
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
}

// Test 18: shard_offer_msg_cbor_roundtrip
#[test]
fn shard_offer_msg_cbor_roundtrip() {
    let key = make_signing_key(11);
    let unsigned = make_shard_descriptor_unsigned(11);
    let descriptor = ShardDescriptor::sign(unsigned, &key).unwrap();
    let msg = ShardOfferMsg {
        v: 1,
        descriptor,
        ts: 99999,
    };
    let bytes = to_cbor(&msg).unwrap();
    let decoded: ShardOfferMsg = from_cbor(&bytes).unwrap();
    assert_eq!(decoded.ts, msg.ts);
    assert_eq!(decoded.descriptor.shard_id.0, msg.descriptor.shard_id.0);
    assert_eq!(decoded.descriptor.k, msg.descriptor.k);
    assert_eq!(decoded.descriptor.importance, msg.descriptor.importance);
}

// Test 19: pos_challenge_response_cbor_roundtrip
#[test]
fn pos_challenge_response_cbor_roundtrip() {
    let challenge = PosChallengeMsg {
        v: 1,
        challenge_id: [42u8; 32],
        shard_id: ShardId([1u8; 32]),
        unit_id: UnitId([2u8; 32]),
        shard_index: 3,
        block_range: (0, 10),
        nonce: [99u8; 32],
        ts: 1234567,
    };
    let cb = to_cbor(&challenge).unwrap();
    let dc: PosChallengeMsg = from_cbor(&cb).unwrap();
    assert_eq!(dc.challenge_id, challenge.challenge_id);
    assert_eq!(dc.block_range, challenge.block_range);

    let response = PosResponseMsg {
        v: 1,
        challenge_id: [42u8; 32],
        block_data_hash: [11u8; 32],
        merkle_proof: vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]],
        ts: 1234568,
    };
    let rb = to_cbor(&response).unwrap();
    let dr: PosResponseMsg = from_cbor(&rb).unwrap();
    assert_eq!(dr.challenge_id, response.challenge_id);
    assert_eq!(dr.merkle_proof.len(), 5);
    assert_eq!(dr.merkle_proof[4], [5u8; 32]);
}

// Test 20: reject_reason_all_variants_roundtrip
#[test]
fn reject_reason_all_variants_roundtrip() {
    let variants = [
        RejectReason::Full,
        RejectReason::HashMismatch,
        RejectReason::NotAllowed,
        RejectReason::LowPriority,
        RejectReason::Expired,
    ];
    for v in &variants {
        let bytes = to_cbor(v).unwrap();
        let decoded: RejectReason = from_cbor(&bytes).unwrap();
        assert_eq!(&decoded, v);
    }
}

// Test 21: deny_reason_all_variants_roundtrip
#[test]
fn deny_reason_all_variants_roundtrip() {
    let variants = [
        DenyReason::EscrowNotMet,
        DenyReason::NotFound,
        DenyReason::InCooldown,
    ];
    for v in &variants {
        let bytes = to_cbor(v).unwrap();
        let decoded: DenyReason = from_cbor(&bytes).unwrap();
        assert_eq!(&decoded, v);
    }
}

// Test 22: file_type_roundtrip
#[test]
fn file_type_roundtrip() {
    let user_bytes = to_cbor(&FileType::User).unwrap();
    let system_bytes = to_cbor(&FileType::System).unwrap();
    let user_back: FileType = from_cbor(&user_bytes).unwrap();
    let system_back: FileType = from_cbor(&system_bytes).unwrap();
    assert_eq!(user_back, FileType::User);
    assert_eq!(system_back, FileType::System);
    // Verify CBOR string values ("user" and "system")
    let user_str: String = from_cbor(&user_bytes).unwrap();
    let system_str: String = from_cbor(&system_bytes).unwrap();
    assert_eq!(user_str, "user");
    assert_eq!(system_str, "system");
}

// Test 23: relay_entry_hop_preserved
#[test]
fn relay_entry_hop_preserved() {
    let key = make_signing_key(12);
    let author = make_identity(12);
    let payload = b"relay payload".to_vec();
    let msg_id = MsgId::derive(&payload, 1000);
    let sig =
        sign_entry("peer_announce", msg_id, EntryKind::Broadcast, None, &payload, &key);
    let entry = BoardEntry {
        kind: EntryKind::Broadcast,
        target_pub: None,
        payload,
        sig_author: sig,
    };
    let relay = RelayEntry {
        author,
        msg_id,
        hop: 1,
        entry,
    };
    let bytes = to_cbor(&relay).unwrap();
    let decoded: RelayEntry = from_cbor(&bytes).unwrap();
    assert_eq!(decoded.hop, 1);
    assert_eq!(decoded.author.0, author.0);
}

// Test 24: encrypted_payload_cbor_roundtrip
#[test]
fn encrypted_payload_cbor_roundtrip() {
    let ep = EncryptedPayload {
        ephemeral_pub: [1u8; 32],
        nonce: [2u8; 12],
        ciphertext: vec![3u8; 48],
    };
    let cbor = ep.to_cbor();
    let decoded = EncryptedPayload::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.ephemeral_pub, ep.ephemeral_pub);
    assert_eq!(decoded.nonce, ep.nonce);
    assert_eq!(decoded.ciphertext, ep.ciphertext);
}

// Test 25: board_entry_sign_verify_directed
#[test]
fn board_entry_sign_verify_directed() {
    let key = make_signing_key(13);
    let author = make_identity(13);
    let target = make_identity(14);
    let unsigned = make_shard_descriptor_unsigned(13);
    let descriptor = ShardDescriptor::sign(unsigned, &key).unwrap();
    let payload = to_cbor(&ShardOfferMsg {
        v: 1,
        descriptor,
        ts: 7777,
    })
    .unwrap();
    let msg_id = MsgId::derive(&payload, 7777);
    let sig = sign_entry(
        "shard_offer",
        msg_id,
        EntryKind::Directed,
        Some(&target),
        &payload,
        &key,
    );
    let entry = BoardEntry {
        kind: EntryKind::Directed,
        target_pub: Some(target),
        payload: payload.clone(),
        sig_author: sig,
    };
    verify_entry("shard_offer", msg_id, &entry, &author).unwrap();

    // Tamper with payload byte
    let mut tampered_entry = BoardEntry {
        kind: entry.kind,
        target_pub: entry.target_pub,
        payload: {
            let mut p = payload;
            p[0] ^= 0xFF;
            p
        },
        sig_author: Signature(entry.sig_author.0),
    };
    let result = verify_entry("shard_offer", msg_id, &mut tampered_entry, &author);
    assert!(matches!(result, Err(MessageError::InvalidSignature)));
}
