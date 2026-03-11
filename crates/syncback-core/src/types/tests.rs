use super::*;

#[test]
fn erasure_tier_boundaries_are_correct() {
    assert_eq!(ErasureTier::from_importance(0.8), Some(ErasureTier::High));
    assert_eq!(ErasureTier::from_importance(0.79), Some(ErasureTier::Medium));
    assert_eq!(ErasureTier::from_importance(0.4), Some(ErasureTier::Medium));
    assert_eq!(ErasureTier::from_importance(0.39), Some(ErasureTier::Low));
    assert_eq!(ErasureTier::from_importance(0.1), Some(ErasureTier::Low));
    assert_eq!(ErasureTier::from_importance(0.09), None);
    assert_eq!(ErasureTier::from_importance(0.0), None);
    assert_eq!(ErasureTier::from_importance(1.0), Some(ErasureTier::High));
}

#[test]
fn erasure_tier_k_n_values_are_correct() {
    assert_eq!(ErasureTier::High.k(), 5);
    assert_eq!(ErasureTier::High.n_base(), 15);
    assert_eq!(ErasureTier::Medium.k(), 5);
    assert_eq!(ErasureTier::Medium.n_base(), 10);
    assert_eq!(ErasureTier::Low.k(), 5);
    assert_eq!(ErasureTier::Low.n_base(), 7);
}

#[test]
fn timestamp_weeks_elapsed_is_floor_division() {
    let t0 = Timestamp(0);
    let t1 = Timestamp(604_800 * 3 + 86_400); // 3 weeks + 1 day
    assert_eq!(t0.weeks_elapsed(t1), 3);
    assert_eq!(t1.weeks_elapsed(t0), 0); // now < self → 0
}

#[test]
fn timestamp_add_weeks_is_correct() {
    assert_eq!(Timestamp(0).add_weeks(4), Timestamp(4 * 604_800));
    assert_eq!(Timestamp(1000).add_weeks(1), Timestamp(1000 + 604_800));
}

#[test]
fn shard_id_display_is_16_hex_chars() {
    let id = ShardId([
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    assert_eq!(format!("{id}"), "deadbeef01020304");
}

#[test]
fn cbor_roundtrip_file_record() {
    let record = FileRecord {
        file_id: FileId(42),
        path: "/home/user/documents/tax.pdf".to_string(),
        content_hash: [1u8; 32],
        size_bytes: 102_400,
        importance: 0.9,
        dirty: true,
        current_unit_id: Some(UnitId([2u8; 32])),
        last_backed_up: Some(Timestamp(1_700_000_000)),
        backed_up: false,
        first_seen: Timestamp(1_690_000_000),
    };
    let bytes = to_cbor_bytes(&record);
    let decoded: FileRecord = from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.file_id, record.file_id);
    assert_eq!(decoded.path, record.path);
    assert_eq!(decoded.content_hash, record.content_hash);
    assert_eq!(decoded.size_bytes, record.size_bytes);
    assert_eq!(decoded.importance, record.importance);
    assert_eq!(decoded.dirty, record.dirty);
    assert_eq!(decoded.current_unit_id, record.current_unit_id);
    assert_eq!(decoded.last_backed_up, record.last_backed_up);
    assert_eq!(decoded.backed_up, record.backed_up);
    assert_eq!(decoded.first_seen, record.first_seen);
}

#[test]
fn cbor_roundtrip_shard_descriptor() {
    let desc = ShardDescriptor {
        shard_id: ShardId([3u8; 32]),
        unit_id: UnitId([4u8; 32]),
        shard_index: 2,
        rs_k: 5,
        rs_n: 15,
        merkle_root: [5u8; 32],
        owner_pub: IdentityPub([6u8; 32]),
        importance: 0.85,
        file_type: FileType::User,
        created_at: Timestamp(1_700_000_000),
        sig_owner: [7u8; 64],
    };
    let bytes = to_cbor_bytes(&desc);
    let decoded: ShardDescriptor = from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.shard_id, desc.shard_id);
    assert_eq!(decoded.unit_id, desc.unit_id);
    assert_eq!(decoded.shard_index, desc.shard_index);
    assert_eq!(decoded.rs_k, desc.rs_k);
    assert_eq!(decoded.rs_n, desc.rs_n);
    assert_eq!(decoded.merkle_root, desc.merkle_root);
    assert_eq!(decoded.owner_pub, desc.owner_pub);
    assert_eq!(decoded.importance, desc.importance);
    assert_eq!(decoded.file_type, desc.file_type);
    assert_eq!(decoded.created_at, desc.created_at);
    assert_eq!(decoded.sig_owner, desc.sig_owner);
}

#[test]
fn cbor_roundtrip_holding_record() {
    let record = HoldingRecord {
        shard_id: ShardId([8u8; 32]),
        owner_pub: IdentityPub([9u8; 32]),
        importance: 0.5,
        size_bytes: 65_536,
        state: ShardState::MarkedForDelete,
        received_at: Timestamp(1_680_000_000),
        delete_requested_at: Some(Timestamp(1_690_000_000)),
        drop_notice_sent_at: None,
        file_type: FileType::User,
        merkle_root: [10u8; 32],
        rs_k: 5,
        rs_n: 10,
        shard_index: 3,
    };
    let bytes = to_cbor_bytes(&record);
    let decoded: HoldingRecord = from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.shard_id, record.shard_id);
    assert_eq!(decoded.owner_pub, record.owner_pub);
    assert_eq!(decoded.state, record.state);
    assert_eq!(decoded.delete_requested_at, record.delete_requested_at);
    assert_eq!(decoded.drop_notice_sent_at, record.drop_notice_sent_at);
}

#[test]
fn cbor_roundtrip_peer_record() {
    let with_subnet = PeerRecord {
        identity: IdentityPub([11u8; 32]),
        node_id: Some(NodeId([12u8; 32])),
        trust_p: 0.7,
        trust_i: 0.6,
        trust_s: 0.9,
        bytes_sent_to_peer: 1000,
        bytes_received_from_peer: 900,
        first_seen: Timestamp(1_600_000_000),
        last_seen: Timestamp(1_700_000_000),
        weeks_in_network: 52,
        subnet_prefix: Some([192, 168, 1]),
        allowlisted: false,
    };
    let bytes = to_cbor_bytes(&with_subnet);
    let decoded: PeerRecord = from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.identity, with_subnet.identity);
    assert_eq!(decoded.subnet_prefix, Some([192, 168, 1]));
    assert_eq!(decoded.weeks_in_network, 52);

    let without_subnet = PeerRecord {
        identity: IdentityPub([13u8; 32]),
        node_id: None,
        trust_p: 0.0,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: Timestamp(1_700_000_000),
        last_seen: Timestamp(1_700_000_000),
        weeks_in_network: 0,
        subnet_prefix: None,
        allowlisted: true,
    };
    let bytes = to_cbor_bytes(&without_subnet);
    let decoded: PeerRecord = from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.subnet_prefix, None);
    assert!(decoded.allowlisted);
}

#[test]
fn file_type_serializes_as_expected() {
    let user_bytes = to_cbor_bytes(&FileType::User);
    let system_bytes = to_cbor_bytes(&FileType::System);

    let decoded_user: FileType = from_cbor_bytes(&user_bytes).unwrap();
    let decoded_system: FileType = from_cbor_bytes(&system_bytes).unwrap();

    assert_eq!(decoded_user, FileType::User);
    assert_eq!(decoded_system, FileType::System);

    // Verify the wire representation is lowercase strings "user" and "system"
    // ciborium encodes text strings as CBOR major type 3.
    // "user" = 0x64 0x75 0x73 0x65 0x72
    // "system" = 0x66 0x73 0x79 0x73 0x74 0x65 0x6d
    let user_str: String = ciborium::de::from_reader(user_bytes.as_slice()).unwrap();
    let system_str: String = ciborium::de::from_reader(system_bytes.as_slice()).unwrap();
    assert_eq!(user_str, "user");
    assert_eq!(system_str, "system");
}

#[test]
fn from_cbor_bytes_returns_error_on_garbage() {
    let result = from_cbor_bytes::<FileRecord>(b"not cbor garbage");
    assert!(result.is_err());
}
