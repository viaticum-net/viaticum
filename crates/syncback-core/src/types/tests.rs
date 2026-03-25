use super::*;

// ============================================================
// SourceBlockRecord::erasure_params tests
// ============================================================

#[test]
fn erasure_params_returns_stored_values() {
    let record = SourceBlockRecord {
        block_id: SourceBlockId([0; 32]),
        k: 100,
        t: 65535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(0),
        encrypted_size: None,
        n: Some(512),
        overhead: Some(3.0),
    };
    let params = record.erasure_params();
    assert_eq!(params.k, 100);
    assert_eq!(params.k_eff, 103); // k + DECODE_OVERHEAD (3)
    assert_eq!(params.t, 65535);
    assert_eq!(params.n, 512);
    assert!((params.overhead - 3.0).abs() < 1e-10);
}

#[test]
fn erasure_params_legacy_fallback() {
    // n=None, overhead=None → falls back to ErasureParams::compute(k*t, 0.0)
    let k: u32 = 100;
    let t: u16 = 65535;
    let record = SourceBlockRecord {
        block_id: SourceBlockId([0; 32]),
        k,
        t,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(0),
        encrypted_size: None,
        n: None,
        overhead: None,
    };
    let params = record.erasure_params();
    let expected = ErasureParams::compute(k as u64 * t as u64, 0.0);
    assert_eq!(params.k, expected.k);
    assert_eq!(params.k_eff, expected.k_eff);
    assert_eq!(params.t, expected.t);
    assert_eq!(params.n, expected.n);
    assert!((params.overhead - expected.overhead).abs() < 1e-10);
}

#[test]
fn source_block_record_roundtrips_n_and_overhead() {
    let record = SourceBlockRecord {
        block_id: SourceBlockId([0xAB; 32]),
        k: 200,
        t: 65535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(9999),
        encrypted_size: Some(13_107_000),
        n: Some(930),
        overhead: Some(2.4),
    };
    let bytes = to_cbor_bytes(&record);
    let decoded: SourceBlockRecord = from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.n, Some(930));
    assert!(decoded.overhead.is_some());
    assert!((decoded.overhead.unwrap() - 2.4).abs() < 1e-10);
    assert_eq!(decoded.k, 200);
    assert_eq!(decoded.encrypted_size, Some(13_107_000));
}

#[test]
fn source_block_record_legacy_deserializes_as_none() {
    // Serialize a record WITHOUT n/overhead fields by constructing the CBOR manually
    // via a helper struct that doesn't have these fields.
    #[derive(serde::Serialize)]
    struct LegacySourceBlockRecord {
        block_id: SourceBlockId,
        k: u32,
        t: u16,
        block_type: SourceBlockType,
        status: SourceBlockStatus,
        created_at: Timestamp,
        encrypted_size: Option<u64>,
    }
    let legacy = LegacySourceBlockRecord {
        block_id: SourceBlockId([0; 32]),
        k: 50,
        t: 65535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(1000),
        encrypted_size: Some(3_276_750),
    };
    let bytes = to_cbor_bytes(&legacy);
    let decoded: SourceBlockRecord = from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.n, None);
    assert_eq!(decoded.overhead, None);
    assert_eq!(decoded.k, 50);
}

#[test]
fn erasure_params_default_block_size() {
    let params = ErasureParams::compute(128 * 1024 * 1024, 0.6);
    // K = ceil(128MB / 65535) = 2049 (T=65535, not 65536)
    assert_eq!(params.k, 2049);
    assert_eq!(params.k_eff, 2052);
    assert_eq!(params.t, 65535);
    // overhead = 1.5 + 0.6 * 1.5 = 2.4
    assert!((params.overhead - 2.4).abs() < 0.001);
    // n = ceil(2052 * 2.4) = 4925
    assert_eq!(params.n, 4925);
}

#[test]
fn erasure_params_small_block_raspberry_pi() {
    let params = ErasureParams::compute(32 * 1024 * 1024, 0.6);
    // K = ceil(32MB / 65535) = 513
    assert_eq!(params.k, 513);
    assert_eq!(params.k_eff, 516);
    assert_eq!(params.n, (516.0 * 2.4_f64).ceil() as u32);
}

#[test]
fn erasure_params_high_importance() {
    let params = ErasureParams::compute(128 * 1024 * 1024, 1.0);
    // overhead = 1.5 + 1.0 * 1.5 = 3.0
    assert!((params.overhead - 3.0).abs() < 0.001);
}

#[test]
fn erasure_params_low_importance() {
    let params = ErasureParams::compute(128 * 1024 * 1024, 0.0);
    // overhead = 1.5 + 0.0 * 1.5 = 1.5
    assert!((params.overhead - 1.5).abs() < 0.001);
}

#[test]
fn erasure_params_importance_clamped() {
    let params = ErasureParams::compute(128 * 1024 * 1024, 1.5);
    // importance clamped to 1.0, overhead = 3.0
    assert!((params.overhead - 3.0).abs() < 0.001);
}

#[test]
fn max_per_holder_concentration_cap() {
    let params = ErasureParams::compute(128 * 1024 * 1024, 0.6);
    let max = params.max_per_holder();
    // cap = (1 - 1/2.4) * 0.85 * 4925 = 0.5833 * 0.85 * 4925 = ~2442
    // k_eff - 1 = 2051
    // min(2051, 2442) = 2051
    assert_eq!(max, 2051);
}

#[test]
fn max_per_holder_cap_stricter_at_high_overhead() {
    let params = ErasureParams::compute(128 * 1024 * 1024, 0.0);
    let max = params.max_per_holder();
    // overhead = 1.5, cap = (1 - 1/1.5) * 0.85 * n = 0.3333 * 0.85 * n
    // k_eff - 1 = 2050
    // cap_fraction = 0.2833, cap = 0.2833 * 3077 = ~871
    // min(2050, 871) = 871
    assert!(max < params.k_eff - 1);
    assert!(max > 0);
}

#[test]
fn timestamp_weeks_elapsed() {
    let t0 = Timestamp(1_000_000);
    let t1 = t0.add_weeks(3);
    assert_eq!(t0.weeks_elapsed(t1), 3);
    assert_eq!(t1.weeks_elapsed(t0), 0); // future → 0
}

#[test]
fn timestamp_secs_elapsed_saturating() {
    let t0 = Timestamp(100);
    let t1 = Timestamp(50);
    assert_eq!(t0.secs_elapsed(t1), 0);
}

#[test]
fn source_block_id_display_hex() {
    let id = SourceBlockId([0xab; 32]);
    assert_eq!(format!("{id}"), "abababababababab");
}

#[test]
fn file_id_display() {
    let id = FileId(42);
    assert_eq!(format!("{id}"), "42");
}

#[test]
fn symbol_placement_count() {
    let p = SymbolPlacement {
        source_block_id: SourceBlockId([0; 32]),
        holder_id: IdentityPub([1; 32]),
        file_id: FileId(1),
        esi_ranges: vec![(0, 100), (500, 50)],
        binding_seed: [0; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses: 0,
    };
    assert_eq!(p.symbol_count(), 150);
}

#[test]
fn holding_record_count() {
    let h = HoldingRecord {
        source_block_id: SourceBlockId([0; 32]),
        owner_id: IdentityPub([1; 32]),
        esi_ranges: vec![(0, 200), (1000, 50), (2000, 10)],
        importance: 0.5,
        total_bytes: 0,
        status: HoldingStatus::Active,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    assert_eq!(h.symbol_count(), 260);
}

#[test]
fn cbor_roundtrip_file_record() {
    let record = FileRecord {
        file_id: FileId(1),
        path: "photos/img.jpg".to_string(),
        importance: 0.6,
        devices: vec![(DeviceId([0xaa; 16]), LocalState::Present)],
        versions: vec![FileVersion {
            content_hash: [0xbb; 32],
            source_block_id: SourceBlockId([0xcc; 32]),
            k: 2048,
            t: 65535,
            created_at: Timestamp(1000),
            backed_up_at: Some(Timestamp(2000)),
        }],
        first_seen: Timestamp(1000),
    };
    let bytes = to_cbor_bytes(&record);
    let decoded: FileRecord = from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.file_id, record.file_id);
    assert_eq!(decoded.path, record.path);
    assert_eq!(decoded.versions.len(), 1);
    assert_eq!(decoded.versions[0].k, 2048);
}

#[test]
fn cbor_roundtrip_event() {
    let entry = EventEntry {
        timestamp: Timestamp(1000),
        device_id: DeviceId([0; 16]),
        event: Event::SymbolsPlaced {
            source_block_id: SourceBlockId([1; 32]),
            holder_id: IdentityPub([2; 32]),
            esi_range: (0, 100),
        },
    };
    let bytes = to_cbor_bytes(&entry);
    let decoded: EventEntry = from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.timestamp, entry.timestamp);
}

#[test]
fn cbor_roundtrip_source_block_pack() {
    let sb = SourceBlockRecord {
        block_id: SourceBlockId([0; 32]),
        k: 2048,
        t: 65535,
        block_type: SourceBlockType::Pack {
            entries: vec![
                PackEntry { file_id: FileId(1), offset: 0, size: 1000 },
                PackEntry { file_id: FileId(2), offset: 1000, size: 2000 },
            ],
        },
        status: SourceBlockStatus::Active,
        created_at: Timestamp(5000),
        encrypted_size: None,
        n: None,
        overhead: None,
    };
    let bytes = to_cbor_bytes(&sb);
    let decoded: SourceBlockRecord = from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.k, 2048);
    if let SourceBlockType::Pack { entries } = &decoded.block_type {
        assert_eq!(entries.len(), 2);
    } else {
        panic!("expected Pack");
    }
}

#[test]
fn peer_record_is_device_revoked_returns_false_when_list_empty() {
    let peer = PeerRecord {
        identity: IdentityPub([0; 32]),
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        device_id: None,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    };
    assert!(!peer.is_device_revoked(&IdentityPub([1; 32])));
}

#[test]
fn peer_record_is_device_revoked_returns_true_when_key_present() {
    let revoked_key = [0xABu8; 32];
    let peer = PeerRecord {
        identity: IdentityPub([0; 32]),
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        device_id: None,
        revoked_device_pub_keys: vec![revoked_key],
        addrs: vec![],
        x25519_pub: None,
    };
    assert!(peer.is_device_revoked(&IdentityPub(revoked_key)));
}

#[test]
fn peer_record_is_device_revoked_does_not_match_different_key() {
    let revoked_key = [0xABu8; 32];
    let other_key = [0xCDu8; 32];
    let peer = PeerRecord {
        identity: IdentityPub([0; 32]),
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        device_id: None,
        revoked_device_pub_keys: vec![revoked_key],
        addrs: vec![],
        x25519_pub: None,
    };
    assert!(!peer.is_device_revoked(&IdentityPub(other_key)));
}

#[test]
fn peer_record_is_device_revoked_with_multiple_keys() {
    let key_a = [0x01u8; 32];
    let key_b = [0x02u8; 32];
    let key_c = [0x03u8; 32];
    let peer = PeerRecord {
        identity: IdentityPub([0; 32]),
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        device_id: None,
        revoked_device_pub_keys: vec![key_a, key_b],
        addrs: vec![],
        x25519_pub: None,
    };
    assert!(peer.is_device_revoked(&IdentityPub(key_a)));
    assert!(peer.is_device_revoked(&IdentityPub(key_b)));
    assert!(!peer.is_device_revoked(&IdentityPub(key_c)));
}
