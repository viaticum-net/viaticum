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
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
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
    // n=None, overhead=None → falls back to ErasureParams::compute(k*t, 0.0).unwrap()
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
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    };
    let params = record.erasure_params();
    let expected = ErasureParams::compute(k as u64 * t as u64, 0.0).unwrap();
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
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
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
    let params = ErasureParams::compute(128 * 1024 * 1024, 0.6).unwrap();
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
    let params = ErasureParams::compute(32 * 1024 * 1024, 0.6).unwrap();
    // K = ceil(32MB / 65535) = 513
    assert_eq!(params.k, 513);
    assert_eq!(params.k_eff, 516);
    assert_eq!(params.n, (516.0 * 2.4_f64).ceil() as u32);
}

#[test]
fn erasure_params_high_importance() {
    let params = ErasureParams::compute(128 * 1024 * 1024, 1.0).unwrap();
    // overhead = 1.5 + 1.0 * 1.5 = 3.0
    assert!((params.overhead - 3.0).abs() < 0.001);
}

#[test]
fn erasure_params_low_importance() {
    let params = ErasureParams::compute(128 * 1024 * 1024, 0.0).unwrap();
    // overhead = 1.5 + 0.0 * 1.5 = 1.5
    assert!((params.overhead - 1.5).abs() < 0.001);
}

#[test]
fn erasure_params_importance_clamped() {
    let params = ErasureParams::compute(128 * 1024 * 1024, 1.5).unwrap();
    // importance clamped to 1.0, overhead = 3.0
    assert!((params.overhead - 3.0).abs() < 0.001);
}

#[test]
fn max_per_holder_concentration_cap() {
    let params = ErasureParams::compute(128 * 1024 * 1024, 0.6).unwrap();
    let max = params.max_per_holder();
    // cap = (1 - 1/2.4) * 0.85 * 4925 = 0.5833 * 0.85 * 4925 = ~2442
    // k_eff - 1 = 2051
    // min(2051, 2442) = 2051
    assert_eq!(max, 2051);
}

#[test]
fn max_per_holder_cap_stricter_at_high_overhead() {
    let params = ErasureParams::compute(128 * 1024 * 1024, 0.0).unwrap();
    let max = params.max_per_holder();
    // overhead = 1.5, cap = (1 - 1/1.5) * 0.85 * n = 0.3333 * 0.85 * n
    // k_eff - 1 = 2050
    // cap_fraction = 0.2833, cap = 0.2833 * 3077 = ~871
    // min(2050, 871) = 871
    assert!(max < params.k_eff - 1);
    assert!(max > 0);
}

#[test]
fn erasure_params_compute_rejects_empty_block() {
    let result = ErasureParams::compute(0, 0.5);
    assert!(
        matches!(result, Err(ErasureParamsError::EmptySourceBlock)),
        "expected EmptySourceBlock, got {result:?}"
    );
}

#[test]
fn erasure_params_compute_handles_max_size() {
    // Max valid size: k must stay below u32::MAX / 4 to leave headroom for
    // DECODE_OVERHEAD and the importance multiplier without overflow.
    let k_limit: u64 = (u32::MAX / 4) as u64;
    let t: u64 = super::SYMBOL_SIZE as u64;
    let max_ok_size: u64 = k_limit * t;
    let result = ErasureParams::compute(max_ok_size, 0.0);
    assert!(
        result.is_ok(),
        "expected Ok for max valid size, got {result:?}"
    );

    let too_large: u64 = max_ok_size + t + 1;
    let result = ErasureParams::compute(too_large, 0.0);
    assert!(
        matches!(result, Err(ErasureParamsError::TooLarge(_))),
        "expected TooLarge, got {result:?}"
    );
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
        holder_id: DeviceId([1; 32]),
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
        devices: vec![(DeviceId([0xaa; 32]), LocalState::Present)],
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
        device_id: DeviceId([0; 32]),
        event: Event::SymbolsPlaced {
            source_block_id: SourceBlockId([1; 32]),
            holder_id: DeviceId([2; 32]),
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
                PackEntry {
                    file_id: FileId(1),
                    offset: 0,
                    size: 1000,
                },
                PackEntry {
                    file_id: FileId(2),
                    offset: 1000,
                    size: 2000,
                },
            ],
        },
        status: SourceBlockStatus::Active,
        created_at: Timestamp(5000),
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
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

// ============================================================
// Wave 8: new cached fields round-trip and legacy compat
// ============================================================

#[test]
fn source_block_record_round_trip_with_all_new_fields() {
    let original = SourceBlockRecord {
        block_id: SourceBlockId([0xAB; 32]),
        k: 100,
        t: 65535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(5000),
        encrypted_size: Some(6_553_500),
        n: Some(450),
        overhead: Some(2.475),
        drop_notice_sent_at: None,
        // Wave 8 fields — all non-zero/non-default.
        importance: 0.65,
        current_alive: 3,
        current_reliability: 0.9996,
        target_reliability: 0.9996,
    };

    let bytes = to_cbor_bytes(&original);
    let decoded: SourceBlockRecord = from_cbor_bytes(&bytes).unwrap();

    // Existing fields unchanged.
    assert_eq!(decoded.block_id, original.block_id);
    assert_eq!(decoded.k, 100);
    assert_eq!(decoded.t, 65535);
    assert_eq!(decoded.n, Some(450));
    assert!((decoded.overhead.unwrap() - 2.475).abs() < 1e-10);

    // New fields survive round-trip.
    assert!(
        (decoded.importance - 0.65).abs() < 1e-10,
        "importance round-trip, got {}",
        decoded.importance
    );
    assert_eq!(decoded.current_alive, 3);
    assert!(
        (decoded.current_reliability - 0.9996).abs() < 1e-10,
        "current_reliability round-trip, got {}",
        decoded.current_reliability
    );
    assert!(
        (decoded.target_reliability - 0.9996).abs() < 1e-10,
        "target_reliability round-trip, got {}",
        decoded.target_reliability
    );
}

#[test]
fn source_block_record_legacy_format_loads_with_defaults() {
    // Simulate a record serialized by pre-Wave-8 code (no new fields).
    #[derive(serde::Serialize)]
    struct LegacySourceBlockRecordV2 {
        block_id: SourceBlockId,
        k: u32,
        t: u16,
        block_type: SourceBlockType,
        status: SourceBlockStatus,
        created_at: Timestamp,
        encrypted_size: Option<u64>,
        n: Option<u32>,
        overhead: Option<f64>,
        drop_notice_sent_at: Option<Timestamp>,
    }
    let legacy = LegacySourceBlockRecordV2 {
        block_id: SourceBlockId([0xCC; 32]),
        k: 50,
        t: 65535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(1000),
        encrypted_size: Some(3_276_750),
        n: Some(200),
        overhead: Some(2.4),
        drop_notice_sent_at: None,
    };

    let bytes = to_cbor_bytes(&legacy);
    let decoded: SourceBlockRecord = from_cbor_bytes(&bytes).unwrap();

    // Existing fields deserialize correctly.
    assert_eq!(decoded.k, 50);
    assert_eq!(decoded.n, Some(200));
    assert!((decoded.overhead.unwrap() - 2.4).abs() < 1e-10);
    assert_eq!(decoded.encrypted_size, Some(3_276_750));

    // Wave-8 fields default to their zero values.
    assert_eq!(
        decoded.importance, 0.0,
        "legacy: importance must default to 0.0"
    );
    assert_eq!(
        decoded.current_alive, 0,
        "legacy: current_alive must default to 0"
    );
    assert_eq!(
        decoded.current_reliability, 0.0,
        "legacy: current_reliability must default to 0.0"
    );
    assert_eq!(
        decoded.target_reliability, 0.0,
        "legacy: target_reliability must default to 0.0"
    );
}

#[test]
fn peer_record_is_device_revoked_returns_false_when_list_empty() {
    let peer = PeerRecord {
        device_id: DeviceId([0; 32]),
        master_identity: IdentityPub([0xAA; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: crate::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    };
    assert!(!peer.is_device_revoked(&DeviceId([1; 32])));
}

#[test]
fn peer_record_is_device_revoked_returns_true_when_key_present() {
    let revoked_key = [0xABu8; 32];
    let peer = PeerRecord {
        device_id: DeviceId([0; 32]),
        master_identity: IdentityPub([0xAA; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![revoked_key],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: crate::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    };
    assert!(peer.is_device_revoked(&DeviceId(revoked_key)));
}

#[test]
fn peer_record_is_device_revoked_does_not_match_different_key() {
    let revoked_key = [0xABu8; 32];
    let other_key = [0xCDu8; 32];
    let peer = PeerRecord {
        device_id: DeviceId([0; 32]),
        master_identity: IdentityPub([0xAA; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![revoked_key],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: crate::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    };
    assert!(!peer.is_device_revoked(&DeviceId(other_key)));
}

#[test]
fn peer_record_is_device_revoked_with_multiple_keys() {
    let key_a = [0x01u8; 32];
    let key_b = [0x02u8; 32];
    let key_c = [0x03u8; 32];
    let peer = PeerRecord {
        device_id: DeviceId([0; 32]),
        master_identity: IdentityPub([0xAA; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![key_a, key_b],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: crate::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    };
    assert!(peer.is_device_revoked(&DeviceId(key_a)));
    assert!(peer.is_device_revoked(&DeviceId(key_b)));
    assert!(!peer.is_device_revoked(&DeviceId(key_c)));
}

// ============================================================
// EWMA availability formula tests (T-4a)
// ============================================================

#[test]
fn ewma_formulas_are_pure_functions() {
    let avail = 0.5_f64;
    let alpha = 0.05_f64;

    let observed = ewma_contact_observed(avail, alpha);
    assert!(
        (observed - (0.05 + 0.95 * 0.5)).abs() < 1e-12,
        "ewma_contact_observed(0.5, 0.05) must equal 0.525; got {observed}"
    );

    let decayed = ewma_decay_tick(avail, alpha);
    assert!(
        (decayed - (0.95 * 0.5)).abs() < 1e-12,
        "ewma_decay_tick(0.5, 0.05) must equal 0.475; got {decayed}"
    );
}

#[test]
fn avail_ewma_increases_on_repeated_contact() {
    let alpha = crate::constants::AVAIL_EWMA_ALPHA;
    let mut avail = crate::constants::AVAIL_EWMA_INITIAL;
    for _ in 0..28 {
        avail = ewma_contact_observed(avail, alpha);
    }
    assert!(
        avail > 0.7,
        "after 28 contacts from initial 0.1, avail_ewma should be > 0.7; got {avail}"
    );
}

#[test]
fn avail_ewma_decays_when_no_contact() {
    let alpha = crate::constants::AVAIL_EWMA_ALPHA;
    let avail = ewma_decay_n_ticks(1.0, alpha, 14);
    let expected = 0.95_f64.powi(14);
    assert!(
        (avail - expected).abs() < 1e-9,
        "ewma_decay_n_ticks(1.0, 0.05, 14) must be ≈ {expected}; got {avail}"
    );
    assert!(
        (avail - 0.488).abs() < 0.01,
        "14-tick decay from 1.0 should be ≈ 0.488; got {avail}"
    );
}

#[test]
fn new_peer_starts_at_pessimistic_value() {
    // Simulate deserializing old CBOR that has no avail_ewma field.
    // The serde(default = "default_avail_ewma") must inject 0.1.
    use crate::types::{from_cbor_bytes, to_cbor_bytes};

    // The serde(default) only fires during *deserialization* when the field
    // key is absent. To exercise the real migration path we serialize a shadow
    // struct that mirrors the pre-T-4a PeerRecord layout (no avail_ewma /
    // last_avail_sample keys), then deserialize the bytes into the current
    // PeerRecord. Field names and order match the real struct so CBOR (which
    // serializes structs as maps keyed by field name) round-trips correctly.
    #[derive(serde::Serialize)]
    struct OldPeerRecord {
        device_id: DeviceId,
        master_identity: IdentityPub,
        trust_p: f64,
        trust_i: f64,
        trust_s: f64,
        bytes_we_store_for_peer: u64,
        bytes_peer_stores_for_us: u64,
        first_seen: Timestamp,
        last_seen: Timestamp,
        revoked_device_pub_keys: Vec<[u8; 32]>,
        addrs: Vec<String>,
        x25519_pub: Option<[u8; 32]>,
        // NOTE: deliberately no avail_ewma / last_avail_sample — this is the
        // on-disk shape of records written before T-4a.
    }

    let old = OldPeerRecord {
        device_id: DeviceId([0; 32]),
        master_identity: IdentityPub([0xAA; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    };
    let bytes = to_cbor_bytes(&old);
    let decoded: PeerRecord = from_cbor_bytes(&bytes).unwrap();
    assert!(
        (decoded.avail_ewma - crate::constants::AVAIL_EWMA_INITIAL).abs() < 1e-12,
        "avail_ewma must default to AVAIL_EWMA_INITIAL (0.1) for old records; got {}",
        decoded.avail_ewma
    );
    assert_eq!(
        decoded.last_avail_sample, 0,
        "last_avail_sample must default to 0 for old records"
    );
}

// ============================================================
// ImportanceBucketStats serialization (Wave 12)
// ============================================================

#[test]
fn importance_bucket_stats_round_trips_via_cbor() {
    let stats = ImportanceBucketStats {
        bucket: "critical".to_string(),
        block_count: 42,
        mean_p_recoverable: 0.9876,
        target_p: 0.99998,
        status: "healthy".to_string(),
    };
    let bytes = to_cbor_bytes(&stats);
    let decoded: ImportanceBucketStats = from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.bucket, "critical");
    assert_eq!(decoded.block_count, 42);
    assert!((decoded.mean_p_recoverable - 0.9876).abs() < 1e-9);
    assert!((decoded.target_p - 0.99998).abs() < 1e-9);
    assert_eq!(decoded.status, "healthy");
}

// ============================================================
// ranges_to_esi_list checked arithmetic (CS-DR-15)
// ============================================================

#[test]
fn ranges_to_esi_list_expands_normal_ranges() {
    let ranges = vec![(0u32, 3u32), (10u32, 2u32)];
    assert_eq!(ranges_to_esi_list(&ranges), vec![0, 1, 2, 10, 11]);
}

#[test]
fn ranges_to_esi_list_saturates_instead_of_wrapping_on_overflow() {
    // A corrupt/hostile range whose start+count overflows u32 must NOT wrap to a
    // smaller value (which would invert the range or yield garbage ESIs). With
    // saturating math the end clamps to u32::MAX: the range expands to its valid
    // prefix only, and the helper never panics.
    let ranges = vec![(u32::MAX - 2, 10u32)];
    assert_eq!(
        ranges_to_esi_list(&ranges),
        vec![u32::MAX - 2, u32::MAX - 1],
        "end clamps to u32::MAX (exclusive), yielding only the valid prefix"
    );

    // The extreme case start == u32::MAX yields an empty range (start == end)
    // rather than panicking or wrapping — still safe.
    assert_eq!(ranges_to_esi_list(&[(u32::MAX, 5u32)]), Vec::<u32>::new());
}
