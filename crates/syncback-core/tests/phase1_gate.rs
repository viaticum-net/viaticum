// Phase 1 Gate Integration Tests
//
// Cross-module scenarios that must pass before Phase 2 begins.
// Run with: cargo test -p syncback-core --features testutil
//
// Three scenarios from CLAUDE.md:
//   1. trust + escrow + placement working together end-to-end
//   2. message serialize/deserialize roundtrip for all message types
//   3. budget + placement + importance interaction

use syncback_core::testutil::{test_db, test_peer, test_peers, test_shard_id, test_unit_id, week};
use syncback_core::{
    budget::BudgetPlanner,
    constants::{KI, KP, SECS_PER_WEEK},
    escrow::{EscrowChecker, EscrowTier, RestoreDecision},
    messages::{
        self, BoardEntry, BlobReadyMsg, CancelDeleteMsg, DeleteMsg, DirectBody, DirectMessage,
        EntryKind, FileType, HandshakeMsg, MsgId, PosChallengeMsg, PosResponseMsg, RejectReason,
        RelayEntry, RestoreDeniedMsg, RestoreRequestMsg, ShardAcceptMsg, ShardDescriptor,
        ShardDescriptorUnsigned, ShardDropNoticeMsg, ShardDroppedMsg, ShardOfferMsg,
        ShardRejectMsg, ShardStoredMsg, StorageWarningMsg, DenyReason,
        EncryptedPayload,
    },
    placement::PlacementEngine,
    trust::{PosOutcome, TrustEngine},
    types::{
        FileId, FileRecord, FileType as TypesFileType, HoldingRecord, IdentityPub,
        ShardState, Timestamp,
    },
};

// ============================================================
// Test helpers
// ============================================================

/// Set up a peer with a known combined trust score.
/// Uses the formula: trust = (KP*P + KI*I) * clamp(S, 0.1, 1.0)
/// With S=1.0: combined = (KP + KI) * rate → rate = trust_val / (KP + KI)
fn setup_peer_with_trust(
    engine: &TrustEngine,
    peer: &IdentityPub,
    trust_val: f64,
    started_at_week: u32,
) {
    engine.upsert_peer(peer, week(started_at_week)).unwrap();

    if trust_val > 0.0 {
        let rate = (trust_val / (KP + KI)).min(1.0);
        let passed = (rate * 1000.0).round() as u32;
        engine
            .record_pos_result(
                peer,
                PosOutcome {
                    week_number: started_at_week + 1,
                    challenged: 1000,
                    passed,
                },
            )
            .unwrap();
        engine
            .recalculate(peer, week(started_at_week + 2), started_at_week + 1)
            .unwrap();
    } else {
        engine
            .recalculate(peer, week(started_at_week + 2), started_at_week + 1)
            .unwrap();
    }
}

fn make_file_record(path: &str, id: u64, size_bytes: u64, importance: f64) -> FileRecord {
    FileRecord {
        file_id: FileId(id),
        path: path.to_string(),
        content_hash: [0u8; 32],
        size_bytes,
        importance,
        dirty: true,
        current_unit_id: None,
        last_backed_up: None,
        backed_up: false,
        first_seen: Timestamp(0),
    }
}

fn dummy_signing_key(seed: u8) -> ed25519_dalek::SigningKey {
    // Deterministic signing key from a seed byte. Used for message signing tests.
    let mut key_bytes = [0u8; 32];
    key_bytes[0] = seed;
    ed25519_dalek::SigningKey::from_bytes(&key_bytes)
}

// ============================================================
// Scenario 1: trust + escrow + placement end-to-end
// ============================================================

/// Peers earn trust via PoS, accumulate weeks, then pass escrow and get selected
/// as shard holders by the placement engine.
#[test]
fn trust_escrow_placement_end_to_end() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let escrow = EscrowChecker::new(db.clone());
    let placement = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));

    // Create 15 peers that have been in the network for 5 weeks.
    // This gives them weeks_in_network >= 4 → Tier1 escrow is satisfied.
    // Use trust_val=0.8 (above ADAPTIVE_N_MID_TRUST=0.6) to avoid +1 adaptive bump
    // that would require 16 holders instead of 15 for the High tier.
    let peers = test_peers(15);
    for peer in &peers {
        setup_peer_with_trust(&trust, peer, 0.8, 1);
        // After setup, recalculate sets weeks_in_network based on first_seen vs now.
        // week(1) = start, week(3) = "now" in recalculate call → 2 weeks elapsed.
        // To get >= 4 weeks, simulate by additional recalculation at week 10.
        trust
            .recalculate(peer, week(10), 5)
            .expect("recalculate at week 10");
    }

    // Verify all peers have positive trust.
    for peer in &peers {
        let score = trust.score(peer).unwrap();
        assert!(
            score.combined > 0.0,
            "peer {:?} should have positive trust after PoS, got {}",
            peer,
            score.combined
        );
    }

    // Verify escrow check passes for peers with sufficient weeks.
    // Set up a holding record so check_restore can find the shard.
    let owner = peers[0];
    let shard_id = test_shard_id(42);
    let holding = HoldingRecord {
        shard_id,
        owner_pub: owner,
        importance: 0.8,
        size_bytes: 1024 * 1024,
        state: ShardState::Active,
        received_at: week(1),
        delete_requested_at: None,
        drop_notice_sent_at: None,
        file_type: TypesFileType::User,
        merkle_root: [0u8; 32],
        rs_k: 5,
        rs_n: 15,
        shard_index: 0,
    };
    escrow.insert_holding(holding).unwrap();

    // At week 10, owner has >= 4 weeks_in_network.
    // First restore: bytes_restored == 0 → FreeTier → always allowed.
    let decision = escrow.check_restore(&shard_id, &owner, week(10)).unwrap();
    assert!(
        matches!(decision, RestoreDecision::Allowed),
        "restore should be allowed for peer with sufficient weeks"
    );

    // Now run placement: importance=0.8 → 5-of-15 tier.
    // With 15 trusted peers, placement should succeed.
    let unit_id = test_unit_id(1);
    let plan = placement
        .select_holders(unit_id, 0.8)
        .expect("placement should succeed with 15 trusted peers");

    assert_eq!(plan.assignments.len(), 15, "should select 15 holders for High tier");
    assert_eq!(plan.params.k, 5);
    assert_eq!(plan.params.n, 15, "High-trust peers → no adaptive bump");

    // Every selected holder must have positive trust.
    for assignment in &plan.assignments {
        let score = trust.score(&assignment.holder).unwrap();
        assert!(
            score.combined > 0.0,
            "selected holder {:?} should have positive trust",
            assignment.holder
        );
    }
}

/// Zero-trust peers are excluded from placement; only trusted peers are selected.
#[test]
fn placement_excludes_zero_trust_peers() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let placement = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));

    // 10 zero-trust peers (registered but no PoS)
    let zero_peers = test_peers(10);
    for p in &zero_peers {
        trust.upsert_peer(p, week(1)).unwrap();
        trust.recalculate(p, week(2), 1).unwrap();
    }

    // 7 trusted peers
    let trusted_peers: Vec<IdentityPub> = (10u8..17).map(|i| test_peer(i)).collect();
    for p in &trusted_peers {
        setup_peer_with_trust(&trust, p, 0.8, 1);
    }

    // importance=0.1 → base_n=7; avg_trust of trusted peers is high → no adaptive bump
    let unit_id = test_unit_id(5);
    let plan = placement
        .select_holders(unit_id, 0.1)
        .expect("placement should succeed with 7 trusted peers");

    let zero_set: std::collections::HashSet<_> = zero_peers.iter().cloned().collect();
    for assignment in &plan.assignments {
        assert!(
            !zero_set.contains(&assignment.holder),
            "zero-trust peer should never be selected"
        );
    }
}

/// Escrow denies restore for a peer below the required weeks threshold.
#[test]
fn escrow_denies_restore_when_insufficient_weeks() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let escrow = EscrowChecker::new(db.clone());

    // Peer with only 1 week in network
    let owner = test_peer(1);
    trust.upsert_peer(&owner, week(1)).unwrap();
    trust.recalculate(&owner, week(2), 1).unwrap();

    // Verify weeks_in_network == 1
    let peer_record = db.get_peer(&owner).unwrap().unwrap();
    assert_eq!(peer_record.weeks_in_network, 1);

    // Set up holding record
    let shard_id = test_shard_id(7);
    escrow
        .insert_holding(HoldingRecord {
            shard_id,
            owner_pub: owner,
            importance: 0.5,
            size_bytes: 2 * (1 << 30), // 2 GiB already restored
            state: ShardState::Active,
            received_at: week(1),
            delete_requested_at: None,
            drop_notice_sent_at: None,
            file_type: TypesFileType::User,
            merkle_root: [0u8; 32],
            rs_k: 5,
            rs_n: 10,
            shard_index: 0,
        })
        .unwrap();

    // Simulate 2 GiB previously restored → requires Tier1 (>=4 weeks)
    escrow
        .record_restore(&shard_id, &owner, 2 * (1u64 << 30), week(1))
        .unwrap();

    // With only 1 week, restore must be denied (Tier1 requires 4 weeks)
    let decision = escrow.check_restore(&shard_id, &owner, week(2)).unwrap();
    match decision {
        RestoreDecision::Denied(denial) => {
            assert_eq!(denial.tier, EscrowTier::Tier1);
            assert_eq!(denial.required_weeks, 4);
            assert_eq!(denial.current_weeks, 1);
        }
        RestoreDecision::Allowed => panic!("should be denied with insufficient weeks"),
    }
}

// ============================================================
// Scenario 2: message serialize/deserialize roundtrip
// ============================================================

/// Every board and direct message type survives CBOR encode → decode with full equality.
#[test]
fn message_roundtrip_peer_announce() {
    use syncback_core::messages::PeerAnnounceMsg;
    let msg = PeerAnnounceMsg {
        v: 1,
        identity_pub: test_peer(1),
        node_addr: vec![1, 2, 3, 4, 5],
        ts: 12345678,
    };
    let bytes = messages::to_cbor(&msg).unwrap();
    let decoded: PeerAnnounceMsg = messages::from_cbor(&bytes).unwrap();
    assert_eq!(decoded.v, msg.v);
    assert_eq!(decoded.identity_pub, msg.identity_pub);
    assert_eq!(decoded.node_addr, msg.node_addr);
    assert_eq!(decoded.ts, msg.ts);
}

#[test]
fn message_roundtrip_pos_challenge() {
    let msg = PosChallengeMsg {
        v: 1,
        challenge_id: [42u8; 32],
        shard_id: test_shard_id(3),
        unit_id: test_unit_id(7),
        shard_index: 2,
        block_range: (0, 260),
        nonce: [7u8; 32],
        ts: 999,
    };
    let bytes = messages::to_cbor(&msg).unwrap();
    let decoded: PosChallengeMsg = messages::from_cbor(&bytes).unwrap();
    assert_eq!(decoded.v, msg.v);
    assert_eq!(decoded.challenge_id, msg.challenge_id);
    assert_eq!(decoded.shard_id, msg.shard_id);
    assert_eq!(decoded.unit_id, msg.unit_id);
    assert_eq!(decoded.shard_index, msg.shard_index);
    assert_eq!(decoded.block_range, msg.block_range);
    assert_eq!(decoded.nonce, msg.nonce);
    assert_eq!(decoded.ts, msg.ts);
}

#[test]
fn message_roundtrip_pos_response() {
    let msg = PosResponseMsg {
        v: 1,
        challenge_id: [11u8; 32],
        block_data_hash: [22u8; 32],
        merkle_proof: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        ts: 54321,
    };
    let bytes = messages::to_cbor(&msg).unwrap();
    let decoded: PosResponseMsg = messages::from_cbor(&bytes).unwrap();
    assert_eq!(decoded.v, msg.v);
    assert_eq!(decoded.challenge_id, msg.challenge_id);
    assert_eq!(decoded.block_data_hash, msg.block_data_hash);
    assert_eq!(decoded.merkle_proof, msg.merkle_proof);
    assert_eq!(decoded.ts, msg.ts);
}

#[test]
fn message_roundtrip_shard_offer_accept_reject_stored() {
    let signing_key = dummy_signing_key(1);
    let owner_pub = IdentityPub(signing_key.verifying_key().to_bytes());
    let shard_id = test_shard_id(1);
    let unit_id = test_unit_id(1);

    let unsigned = ShardDescriptorUnsigned {
        shard_id,
        unit_id,
        shard_index: 0,
        k: 5,
        n: 15,
        merkle_root: [0u8; 32],
        owner_pub,
        importance: 0.8f32,
        file_type: FileType::User,
        created_at: 1000u64,
    };
    let descriptor = ShardDescriptor::sign(unsigned, &signing_key).unwrap();

    // shard_offer
    let offer = ShardOfferMsg {
        v: 1,
        descriptor: descriptor.clone(),
        ts: 1000,
    };
    let offer_bytes = messages::to_cbor(&offer).unwrap();
    let offer_decoded: ShardOfferMsg = messages::from_cbor(&offer_bytes).unwrap();
    assert_eq!(offer_decoded.v, offer.v);
    assert_eq!(offer_decoded.ts, offer.ts);
    assert_eq!(offer_decoded.descriptor.shard_id, shard_id);

    // Verify descriptor signature survived roundtrip
    offer_decoded.descriptor.verify_sig().expect("descriptor sig must survive roundtrip");

    // shard_accept
    let offer_msg_id = MsgId([0u8; 32]);
    let accept = ShardAcceptMsg {
        v: 1,
        shard_id,
        offer_msg_id,
        ts: 1001,
    };
    let accept_bytes = messages::to_cbor(&accept).unwrap();
    let accept_decoded: ShardAcceptMsg = messages::from_cbor(&accept_bytes).unwrap();
    assert_eq!(accept_decoded.shard_id, shard_id);
    assert_eq!(accept_decoded.offer_msg_id, offer_msg_id);

    // shard_reject
    let reject = ShardRejectMsg {
        v: 1,
        shard_id,
        offer_msg_id,
        reason: RejectReason::HashMismatch,
        ts: 1002,
    };
    let reject_bytes = messages::to_cbor(&reject).unwrap();
    let reject_decoded: ShardRejectMsg = messages::from_cbor(&reject_bytes).unwrap();
    assert_eq!(reject_decoded.reason, RejectReason::HashMismatch);

    // shard_stored
    let stored = ShardStoredMsg {
        v: 1,
        shard_id,
        ts: 1003,
    };
    let stored_bytes = messages::to_cbor(&stored).unwrap();
    let stored_decoded: ShardStoredMsg = messages::from_cbor(&stored_bytes).unwrap();
    assert_eq!(stored_decoded.shard_id, shard_id);
}

#[test]
fn message_roundtrip_delete_and_cancel() {
    let shard_id = test_shard_id(5);

    let delete = DeleteMsg { v: 1, shard_id, ts: 9000 };
    let bytes = messages::to_cbor(&delete).unwrap();
    let decoded: DeleteMsg = messages::from_cbor(&bytes).unwrap();
    assert_eq!(decoded.shard_id, shard_id);
    assert_eq!(decoded.ts, 9000);

    let cancel = CancelDeleteMsg { v: 1, shard_id, ts: 9001 };
    let bytes = messages::to_cbor(&cancel).unwrap();
    let decoded: CancelDeleteMsg = messages::from_cbor(&bytes).unwrap();
    assert_eq!(decoded.shard_id, shard_id);
}

#[test]
fn message_roundtrip_storage_warning_dropped_notice() {
    let shard_id = test_shard_id(6);

    let warning = StorageWarningMsg {
        v: 1,
        shard_id,
        details: "block hash mismatch at offset 0".to_string(),
        ts: 5000,
    };
    let bytes = messages::to_cbor(&warning).unwrap();
    let decoded: StorageWarningMsg = messages::from_cbor(&bytes).unwrap();
    assert_eq!(decoded.details, warning.details);

    let dropped = ShardDroppedMsg { v: 1, shard_id, ts: 5001 };
    let bytes = messages::to_cbor(&dropped).unwrap();
    let decoded: ShardDroppedMsg = messages::from_cbor(&bytes).unwrap();
    assert_eq!(decoded.shard_id, shard_id);

    let notice = ShardDropNoticeMsg {
        v: 1,
        shard_id,
        deadline: 5001 + 7 * 24 * 3600,
        ts: 5001,
    };
    let bytes = messages::to_cbor(&notice).unwrap();
    let decoded: ShardDropNoticeMsg = messages::from_cbor(&bytes).unwrap();
    assert_eq!(decoded.deadline, notice.deadline);
}

#[test]
fn message_roundtrip_restore_denied() {
    let denied = RestoreDeniedMsg {
        v: 1,
        shard_id: test_shard_id(8),
        reason: DenyReason::EscrowNotMet,
        required_weeks: 13,
        current_weeks: 5,
        ts: 1111,
    };
    let bytes = messages::to_cbor(&denied).unwrap();
    let decoded: RestoreDeniedMsg = messages::from_cbor(&bytes).unwrap();
    assert_eq!(decoded.reason, DenyReason::EscrowNotMet);
    assert_eq!(decoded.required_weeks, 13);
    assert_eq!(decoded.current_weeks, 5);
}

#[test]
fn message_roundtrip_direct_messages() {
    // Handshake (signed)
    let signing_key = dummy_signing_key(2);
    let identity_pub = IdentityPub(signing_key.verifying_key().to_bytes());
    let handshake = HandshakeMsg::new(identity_pub, 99999, &signing_key);
    handshake.verify().expect("handshake sig valid before roundtrip");

    let dm = DirectMessage {
        v: 1,
        body: DirectBody::Handshake(handshake.clone()),
    };
    let framed = messages::frame_message(&dm).unwrap();
    let (decoded_dm, consumed) = messages::parse_framed(&framed).unwrap();
    assert_eq!(consumed, framed.len());
    match &decoded_dm.body {
        DirectBody::Handshake(h) => {
            assert_eq!(h.identity_pub, identity_pub);
            h.verify().expect("handshake sig valid after roundtrip");
        }
        _ => panic!("expected Handshake body"),
    }

    // RestoreRequest
    let rr = DirectMessage {
        v: 1,
        body: DirectBody::RestoreRequest(RestoreRequestMsg {
            v: 1,
            shard_id: test_shard_id(9),
            ts: 200,
        }),
    };
    let framed = messages::frame_message(&rr).unwrap();
    let (decoded, _) = messages::parse_framed(&framed).unwrap();
    match decoded.body {
        DirectBody::RestoreRequest(r) => assert_eq!(r.shard_id, test_shard_id(9)),
        _ => panic!("expected RestoreRequest"),
    }

    // BlobReady
    let br = DirectMessage {
        v: 1,
        body: DirectBody::BlobReady(BlobReadyMsg {
            v: 1,
            shard_id: test_shard_id(10),
            ts: 300,
        }),
    };
    let framed = messages::frame_message(&br).unwrap();
    let (decoded, _) = messages::parse_framed(&framed).unwrap();
    match decoded.body {
        DirectBody::BlobReady(b) => assert_eq!(b.shard_id, test_shard_id(10)),
        _ => panic!("expected BlobReady"),
    }

    // RestoreDenied (as DirectBody)
    let rd = DirectMessage {
        v: 1,
        body: DirectBody::RestoreDenied(RestoreDeniedMsg {
            v: 1,
            shard_id: test_shard_id(11),
            reason: DenyReason::InCooldown,
            required_weeks: 0,
            current_weeks: 0,
            ts: 400,
        }),
    };
    let framed = messages::frame_message(&rd).unwrap();
    let (decoded, _) = messages::parse_framed(&framed).unwrap();
    match decoded.body {
        DirectBody::RestoreDenied(d) => assert_eq!(d.reason, DenyReason::InCooldown),
        _ => panic!("expected RestoreDenied"),
    }
}

#[test]
fn message_roundtrip_board_entry_with_signature() {
    use syncback_core::messages::{sign_entry, verify_entry, PeerAnnounceMsg};

    let signing_key = dummy_signing_key(3);
    let author_pub = IdentityPub(signing_key.verifying_key().to_bytes());

    let announce = PeerAnnounceMsg {
        v: 1,
        identity_pub: author_pub,
        node_addr: vec![127, 0, 0, 1],
        ts: 42,
    };
    let payload = messages::to_cbor(&announce).unwrap();
    let msg_id = MsgId::derive(&payload, 42);

    let sig = sign_entry("peer_announce", msg_id, EntryKind::Broadcast, None, &payload, &signing_key);

    let entry = BoardEntry {
        kind: EntryKind::Broadcast,
        target_pub: None,
        payload: payload.clone(),
        sig_author: sig,
    };

    // Roundtrip the BoardEntry itself
    let entry_bytes = messages::to_cbor(&entry).unwrap();
    let decoded_entry: BoardEntry = messages::from_cbor(&entry_bytes).unwrap();

    // Verify signature survives roundtrip
    verify_entry("peer_announce", msg_id, &decoded_entry, &author_pub)
        .expect("board entry signature must survive CBOR roundtrip");
}

#[test]
fn message_roundtrip_relay_entry() {
    use syncback_core::messages::{sign_entry, PeerAnnounceMsg};

    let signing_key = dummy_signing_key(4);
    let author_pub = IdentityPub(signing_key.verifying_key().to_bytes());

    let announce = PeerAnnounceMsg {
        v: 1,
        identity_pub: author_pub,
        node_addr: vec![10, 0, 0, 1],
        ts: 100,
    };
    let payload = messages::to_cbor(&announce).unwrap();
    let msg_id = MsgId::derive(&payload, 100);
    let sig = sign_entry("peer_announce", msg_id, EntryKind::Broadcast, None, &payload, &signing_key);

    let relay = RelayEntry {
        author: author_pub,
        msg_id,
        hop: 1,
        entry: BoardEntry {
            kind: EntryKind::Broadcast,
            target_pub: None,
            payload,
            sig_author: sig,
        },
    };

    let bytes = messages::to_cbor(&relay).unwrap();
    let decoded: RelayEntry = messages::from_cbor(&bytes).unwrap();
    assert_eq!(decoded.author, author_pub);
    assert_eq!(decoded.hop, 1);
    assert_eq!(decoded.msg_id, msg_id);
}

#[test]
fn message_roundtrip_encrypted_payload() {
    use syncback_core::messages::{decrypt_payload, encrypt_payload};

    // Generate X25519 keypair for recipient
    let recipient_priv = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let recipient_pub = x25519_dalek::PublicKey::from(&recipient_priv);

    let plaintext = b"hello syncback encrypted payload test";
    let encrypted = encrypt_payload(plaintext, recipient_pub.as_bytes()).unwrap();

    // Roundtrip via CBOR
    let cbor_bytes = encrypted.to_cbor();
    let decoded = EncryptedPayload::from_cbor(&cbor_bytes).unwrap();

    let decrypted = decrypt_payload(&decoded, recipient_priv.as_bytes()).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn message_roundtrip_msg_id_hex() {
    let payload = b"test payload";
    let msg_id = MsgId::derive(payload, 12345);
    let hex = msg_id.to_hex();
    assert_eq!(hex.len(), 64, "MsgId hex should be 64 chars");
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "MsgId hex must be valid hex");

    // Derive twice — deterministic
    let msg_id2 = MsgId::derive(payload, 12345);
    assert_eq!(msg_id, msg_id2);

    // Different timestamp → different id
    let msg_id3 = MsgId::derive(payload, 12346);
    assert_ne!(msg_id, msg_id3);
}

#[test]
fn shard_descriptor_verify_blob() {
    let signing_key = dummy_signing_key(5);
    let owner_pub = IdentityPub(signing_key.verifying_key().to_bytes());
    let blob = b"fake shard blob content for testing";
    let shard_id = syncback_core::types::ShardId(*blake3::hash(blob).as_bytes());

    let unsigned = ShardDescriptorUnsigned {
        shard_id,
        unit_id: test_unit_id(1),
        shard_index: 0,
        k: 5,
        n: 10,
        merkle_root: [0u8; 32],
        owner_pub,
        importance: 0.5f32,
        file_type: FileType::User,
        created_at: 500u64,
    };
    let descriptor = ShardDescriptor::sign(unsigned, &signing_key).unwrap();

    // Correct blob verifies OK
    descriptor.verify_blob(blob).expect("blob hash must match shard_id");

    // Wrong blob fails
    let wrong_blob = b"wrong content";
    assert!(
        descriptor.verify_blob(wrong_blob).is_err(),
        "wrong blob should fail verify_blob"
    );
}

// ============================================================
// Scenario 3: budget + placement + importance interaction
// ============================================================

/// Budget selects files by importance, placement computes consistent erasure params,
/// and overhead factors match between the two modules.
#[test]
fn budget_placement_importance_consistency() {
    let (db, _tmp) = test_db();
    let budget = BudgetPlanner::new(db.clone(), TrustEngine::new(db.clone()));

    // Insert dirty files with varying importance
    // importance: 0.9 (High), 0.5 (Medium), 0.2 (Low), 0.05 (excluded)
    let files = vec![
        make_file_record("/data/critical.key", 1, 100 * 1024 * 1024, 0.9),  // 100 MiB
        make_file_record("/photos/album.tar", 2, 200 * 1024 * 1024, 0.5),   // 200 MiB
        make_file_record("/videos/movie.mkv", 3, 500 * 1024 * 1024, 0.2),   // 500 MiB
        make_file_record("/tmp/scratch.log", 4, 50 * 1024 * 1024, 0.05),    // excluded
    ];
    for file in &files {
        db.upsert_file(file).unwrap();
    }

    // Budget = 2.0 GB (enough for critical + photos, but not all)
    let batch = budget.select_backup_batch(2.0).unwrap();

    // File with importance 0.05 is silently excluded, NOT counted as deferred
    assert!(
        batch.candidates.iter().all(|c| c.path != "/tmp/scratch.log"),
        "file below importance threshold must be excluded"
    );

    // Files should be sorted by importance descending
    for window in batch.candidates.windows(2) {
        assert!(
            window[0].importance >= window[1].importance,
            "candidates must be sorted by importance descending"
        );
    }

    // Verify overhead_factor consistency with PlacementEngine::erasure_params
    for candidate in &batch.candidates {
        let overhead = BudgetPlanner::overhead_factor(candidate.importance);
        let params = PlacementEngine::erasure_params(candidate.importance);
        let expected_overhead = params.n as f64 / params.k as f64;

        // overhead_factor = n_base / k (before adaptive adjustment)
        assert!(
            (overhead - expected_overhead).abs() < 1e-9,
            "overhead_factor({}) = {} but erasure_params gives n/k = {}/{}={} (mismatch)",
            candidate.importance,
            overhead,
            params.n,
            params.k,
            expected_overhead
        );

        // required_gb = size_bytes / 1 GiB * overhead
        let file_record = db.get_file(&candidate.path).unwrap().unwrap();
        let expected_required_gb = file_record.size_bytes as f64 / 1_073_741_824.0 * overhead;
        assert!(
            (candidate.required_gb - expected_required_gb).abs() < 1e-9,
            "required_gb mismatch for {} (importance {})",
            candidate.path,
            candidate.importance
        );
    }
}

/// Overhead factor values match the tier definitions exactly.
#[test]
fn overhead_factor_matches_tier_definitions() {
    // High tier: importance >= 0.8 → n=15, k=5 → overhead=3.0
    assert!(
        (BudgetPlanner::overhead_factor(0.9) - 3.0).abs() < 1e-9,
        "High tier overhead should be 3.0"
    );
    assert!(
        (BudgetPlanner::overhead_factor(0.8) - 3.0).abs() < 1e-9,
        "High tier threshold overhead should be 3.0"
    );

    // Medium tier: 0.4 <= importance < 0.8 → n=10, k=5 → overhead=2.0
    assert!(
        (BudgetPlanner::overhead_factor(0.5) - 2.0).abs() < 1e-9,
        "Medium tier overhead should be 2.0"
    );
    assert!(
        (BudgetPlanner::overhead_factor(0.4) - 2.0).abs() < 1e-9,
        "Medium tier threshold overhead should be 2.0"
    );

    // Low tier: 0.1 <= importance < 0.4 → n=7, k=5 → overhead=1.4
    assert!(
        (BudgetPlanner::overhead_factor(0.2) - 1.4).abs() < 1e-9,
        "Low tier overhead should be 1.4"
    );
    assert!(
        (BudgetPlanner::overhead_factor(0.1) - 1.4).abs() < 1e-9,
        "Low tier threshold overhead should be 1.4"
    );

    // Below threshold: not backed up → overhead=0.0
    assert!(
        (BudgetPlanner::overhead_factor(0.09) - 0.0).abs() < 1e-9,
        "Below-threshold importance should have overhead 0.0"
    );
    assert!(
        (BudgetPlanner::overhead_factor(0.0) - 0.0).abs() < 1e-9,
        "Zero importance should have overhead 0.0"
    );
}

/// Budget selection respects the budget limit and defers overflow files.
#[test]
fn budget_respects_limit_and_defers_overflow() {
    let (db, _tmp) = test_db();
    let budget = BudgetPlanner::new(db.clone(), TrustEngine::new(db.clone()));

    // Two 1 GiB files with same importance → both would need 2 GiB overhead (medium, 2x)
    // Budget = 1.5 GiB → first fits (1 * 2.0 = 2.0 GB), neither fits exactly
    // Actually: 1 GiB * 2.0 = 2.0 GB. Budget 1.5 → neither fits → both deferred
    //
    // Let's use a more controlled scenario:
    // File A: 0.5 GiB, importance=0.5 → required = 0.5 * 2.0 = 1.0 GB
    // File B: 0.5 GiB, importance=0.2 → required = 0.5 * 1.4 = 0.7 GB
    // Budget = 1.2 GB → A fits (1.0 GB used), B does NOT fit (1.0 + 0.7 = 1.7 > 1.2)
    let file_a = make_file_record("/docs/report.pdf", 10, 500 * 1024 * 1024, 0.5);
    let file_b = make_file_record("/media/podcast.mp3", 11, 500 * 1024 * 1024, 0.2);
    db.upsert_file(&file_a).unwrap();
    db.upsert_file(&file_b).unwrap();

    let batch = budget.select_backup_batch(1.2).unwrap();

    // Only file_a should fit
    assert_eq!(batch.candidates.len(), 1, "only file_a should fit in 1.2 GB budget");
    assert_eq!(batch.candidates[0].path, "/docs/report.pdf");
    assert_eq!(batch.deferred_count, 1, "file_b should be deferred");

    let total = batch.total_required_gb;
    assert!(
        total <= 1.2,
        "total_required_gb {} must not exceed budget 1.2",
        total
    );
}

/// High-trust peers are selected more frequently than low-trust peers due to trust^2 weighting.
///
/// Setup: 15 high-trust peers (combined ≈ 0.9) and 5 low-trust peers (combined ≈ 0.1).
/// importance=0.1 → base n=7. With avg_trust heavily dominated by 15 high-trust peers,
/// avg_trust >> 0.6 → no adaptive bump → n=7.
/// 20 peers total, selecting 7 per trial: trust^2 weights make high-trust peers dominant.
/// Expected high-trust fraction per slot: 15*0.81 / (15*0.81 + 5*0.01) ≈ 99.6%.
/// Actual fraction across all slots in 100 trials should be well above 80%.
#[test]
fn trust_drives_placement_weight() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());

    // 15 high-trust peers and 5 low-trust peers (20 total)
    let high_peers: Vec<IdentityPub> = (0u8..15).map(|i| test_peer(i)).collect();
    let low_peers: Vec<IdentityPub> = (15u8..20).map(|i| test_peer(i)).collect();

    for p in &high_peers {
        setup_peer_with_trust(&trust, p, 0.9, 1);
    }
    for p in &low_peers {
        setup_peer_with_trust(&trust, p, 0.1, 1);
    }

    // importance=0.1 → base n=7. avg_trust ≈ (15*~0.9 + 5*~0.1)/20 ≈ 0.7 > 0.6
    // → no adaptive bump → n=7.
    let high_set: std::collections::HashSet<_> = high_peers.iter().cloned().collect();
    let mut high_selections = 0usize;
    let mut total_selections = 0usize;
    let trials = 100;

    for trial in 0..trials {
        let unit_id = test_unit_id(trial as u8);
        let engine = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
        let plan = engine
            .select_holders(unit_id, 0.1)
            .expect("placement should succeed with 20 peers");
        for assignment in &plan.assignments {
            total_selections += 1;
            if high_set.contains(&assignment.holder) {
                high_selections += 1;
            }
        }
    }

    let high_ratio = high_selections as f64 / total_selections as f64;

    // Per slot: weight_high = 15 * 0.81 = 12.15, weight_low = 5 * 0.01 = 0.05
    // Expected high fraction ≈ 12.15 / 12.20 ≈ 99.6%
    // Conservative lower bound: > 80% (well above 75% uniform baseline for 15/20 peers).
    assert!(
        high_ratio > 0.80,
        "high-trust peers should dominate selections (got {:.1}%, expected > 80%)",
        high_ratio * 100.0
    );
}

/// Eviction respects priority: lower (importance × trust × age_bonus) evicted first.
#[test]
fn eviction_respects_priority_order() {
    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let budget = BudgetPlanner::new(db.clone(), TrustEngine::new(db.clone()));

    // owner_a has high trust, owner_b has low trust
    let owner_a = test_peer(1);
    let owner_b = test_peer(2);
    setup_peer_with_trust(&trust, &owner_a, 0.8, 1);
    setup_peer_with_trust(&trust, &owner_b, 0.15, 1);

    let now_secs = week(10).0;

    // Shard 1: owner_a (high trust), high importance, recently received → HIGH priority
    let h1 = HoldingRecord {
        shard_id: test_shard_id(1),
        owner_pub: owner_a,
        importance: 0.9,
        size_bytes: 100 * 1024 * 1024, // 100 MiB
        state: ShardState::Active,
        received_at: Timestamp(now_secs - 1 * SECS_PER_WEEK), // 1 week old
        delete_requested_at: None,
        drop_notice_sent_at: None,
        file_type: TypesFileType::User,
        merkle_root: [0u8; 32],
        rs_k: 5,
        rs_n: 15,
        shard_index: 0,
    };

    // Shard 2: owner_b (low trust), low importance, recently received → LOW priority (evict first)
    let h2 = HoldingRecord {
        shard_id: test_shard_id(2),
        owner_pub: owner_b,
        importance: 0.1,
        size_bytes: 200 * 1024 * 1024, // 200 MiB
        state: ShardState::Active,
        received_at: Timestamp(now_secs - 1 * SECS_PER_WEEK),
        delete_requested_at: None,
        drop_notice_sent_at: None,
        file_type: TypesFileType::User,
        merkle_root: [0u8; 32],
        rs_k: 5,
        rs_n: 7,
        shard_index: 0,
    };

    db.upsert_holding(&h1).unwrap();
    db.upsert_holding(&h2).unwrap();

    let prio1 = budget.eviction_priority(test_shard_id(1), now_secs).unwrap();
    let prio2 = budget.eviction_priority(test_shard_id(2), now_secs).unwrap();

    assert!(
        prio1 > prio2,
        "shard 1 (high trust+importance) should have higher priority than shard 2 (low trust+importance). prio1={:.4} prio2={:.4}",
        prio1,
        prio2
    );

    // Simulate hard disk pressure: quota=1 GB, used=0.97 GB (3% free < 5% hard threshold)
    let quota_gb = 1.0f64;
    let used_gb = 0.97f64; // 3% free = hard pressure

    let result = budget.evaluate_pressure(quota_gb, used_gb, now_secs).unwrap();

    use syncback_core::budget::DiskPressure;
    assert_eq!(
        result.pressure,
        DiskPressure::Hard,
        "should be Hard pressure at 3% free"
    );

    // The lowest-priority shard (shard 2) should be evicted first
    assert!(
        !result.immediate_evictions.is_empty(),
        "should have immediate evictions under hard pressure"
    );
    let first_evicted = &result.immediate_evictions[0];
    assert_eq!(
        first_evicted.shard_id,
        test_shard_id(2),
        "lowest-priority shard should be evicted first"
    );
}

/// Budget batch selects files by importance order; low-importance files deferred before high.
#[test]
fn budget_selects_high_importance_files_first() {
    let (db, _tmp) = test_db();
    let budget = BudgetPlanner::new(db.clone(), TrustEngine::new(db.clone()));

    // Four files of equal size: 100 MiB each
    // importance: 0.9, 0.5, 0.2, 0.05 (last excluded, not deferred)
    let files = vec![
        make_file_record("/a/high.bin", 20, 100 * 1024 * 1024, 0.9),
        make_file_record("/b/medium.bin", 21, 100 * 1024 * 1024, 0.5),
        make_file_record("/c/low.bin", 22, 100 * 1024 * 1024, 0.2),
        make_file_record("/d/tiny.bin", 23, 100 * 1024 * 1024, 0.05), // excluded
    ];
    for f in &files {
        db.upsert_file(f).unwrap();
    }

    // overhead: high=3.0 → 0.293 GB, medium=2.0 → 0.195 GB, low=1.4 → 0.137 GB
    // Budget 0.4 GB: high (0.293) fits, medium (0.293+0.195=0.488 > 0.4) does not fit
    let batch = budget.select_backup_batch(0.4).unwrap();

    assert!(
        batch.candidates.iter().any(|c| c.path == "/a/high.bin"),
        "high importance file must be selected"
    );
    assert!(
        !batch.candidates.iter().any(|c| c.path == "/b/medium.bin"),
        "medium importance file should not fit in budget"
    );
    assert!(
        !batch.candidates.iter().any(|c| c.path == "/d/tiny.bin"),
        "below-threshold file must be excluded"
    );

    // Only files with importance >= 0.1 that didn't fit count as deferred
    assert!(
        batch.deferred_count >= 1,
        "medium and/or low files should be deferred"
    );
}
