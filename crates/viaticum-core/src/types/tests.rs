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

// ============================================================
// PairLedger::elapsed_days — the seconds→days bridge to the four_r kernel
// ============================================================

fn ledger_with_clock_at(secs: u64) -> PairLedger {
    PairLedger {
        last_update: Some(Timestamp(secs)),
        ..PairLedger::default()
    }
}

#[test]
fn elapsed_days_is_none_when_the_clock_never_started() {
    // A fresh ledger has no interval to integrate over. Returning Some(huge) here would
    // hand the kernel "seconds since the unix epoch, in days" on the very first tick.
    let ledger = PairLedger::default();
    assert_eq!(ledger.elapsed_days(Timestamp(1_700_000_000), 1), None);
}

#[test]
fn elapsed_days_converts_seconds_to_days_for_the_kernel() {
    // four_r integrators take dt in DAYS (λ ≈ 1/60 day⁻¹). Storing seconds and forgetting
    // to divide is an 86400× error that still looks like a working integrator.
    let ledger = ledger_with_clock_at(1_000_000);

    assert_eq!(
        ledger.elapsed_days(Timestamp(1_000_000 + 86_400), 1),
        Some(1.0)
    );
    assert_eq!(
        ledger.elapsed_days(Timestamp(1_000_000 + 43_200), 1),
        Some(0.5)
    );
    assert_eq!(ledger.elapsed_days(Timestamp(1_000_000), 1), Some(0.0));
}

#[test]
fn elapsed_days_multiplies_the_interval_by_time_scale() {
    // The clocks this ledger must agree with run on the simulated calendar:
    // db::stored_for_peer_gb_days scales age the same way, and the scheduler divides its
    // intervals by the same factor. (Not every clock does — run_avail_decay_task ticks on
    // the raw constant — so "agrees with the gb·day sums" is the claim, not "agrees with
    // everything".) A ledger that ignored time_scale would accrue 1/time_scale of the
    // history on exactly the accelerated runs where "did the accounting accumulate?" gets
    // verified.
    let ledger = ledger_with_clock_at(1_000_000);
    let one_hour_later = Timestamp(1_000_000 + 3_600);

    assert_eq!(ledger.elapsed_days(one_hour_later, 1), Some(1.0 / 24.0));
    assert_eq!(
        ledger.elapsed_days(one_hour_later, 1_000),
        Some(1_000.0 / 24.0),
        "at time_scale 1000 an hourly tick covers ~41.7 simulated days"
    );
}

#[test]
fn elapsed_days_treats_zero_time_scale_as_one() {
    // Same guard as mailbox::scaled_ttl_secs and db::stored_for_peer_gb_days: a
    // misconfigured 0 must not silently freeze the ledger's clock.
    let ledger = ledger_with_clock_at(1_000_000);
    assert_eq!(
        ledger.elapsed_days(Timestamp(1_000_000 + 86_400), 0),
        Some(1.0)
    );
}

#[test]
fn elapsed_days_is_zero_when_the_wall_clock_jumped_backwards() {
    // A negative Δt would drive the leaky integrator BACKWARDS (g += dt·(v − λg) with
    // dt < 0 discharges it). Clamping to zero leaves the accumulator untouched instead.
    let ledger = ledger_with_clock_at(1_000_000);
    assert_eq!(ledger.elapsed_days(Timestamp(900_000), 1), Some(0.0));
    assert_eq!(
        ledger.elapsed_days(Timestamp(900_000), 1_000),
        Some(0.0),
        "scaling must not turn a backward jump into a large negative Δt"
    );
}

#[test]
fn elapsed_days_returns_an_unclamped_interval_for_a_long_outage() {
    // Documented contract, pinned so it is not "fixed" by a silent clamp: the helper
    // reports the FULL elapsed interval, including values where one explicit Euler step
    // would misbehave (λΔt > 1 at λ = 1/60 means Δt > 60 days; > 2 diverges). Truncating
    // here would quietly discard accrual — the one failure this layer exists to prevent.
    // Sub-stepping is the integrator's job (У-2).
    let ledger = ledger_with_clock_at(1_000_000);
    let three_months_later = Timestamp(1_000_000 + 90 * 86_400);

    let dt = ledger.elapsed_days(three_months_later, 1).unwrap();
    assert_eq!(dt, 90.0);
    assert!(
        dt * (1.0 / 60.0) > 1.0,
        "90 days at λ=1/60 is past the monotonicity bound — the caller must sub-step"
    );
}

// ============================================================
// PairLedger forward compatibility: how a NEW field may be added
// ============================================================

fn ledger_sample() -> PairLedger {
    PairLedger {
        gb_days_they_store_for_us: 3.5,
        gb_days_we_store_for_them: 4.5,
        depth_of_their_service: 60.0,
        v_dem: 2.0,
        observed_volume: 1.5,
        observed_tau: 30.0,
        drop_ann: 1.0,
        drop_silent: 0.0,
        last_update: Some(Timestamp(1_700_000_000)),
    }
}

#[test]
fn pair_ledger_with_a_new_defaulted_field_still_reads_rows_written_today() {
    // The rule written on PairLedger ("every NEW field must carry #[serde(default)]") is
    // only worth anything if it actually works with our CBOR encoder. Rows written today
    // must keep decoding once У-2..У-5 extend the struct. `trend_d` is a real pending
    // field (spec: "what we do not accrue yet"), used here as the stand-in.
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct PairLedgerPlusDefaulted {
        gb_days_they_store_for_us: f64,
        gb_days_we_store_for_them: f64,
        depth_of_their_service: f64,
        v_dem: f64,
        observed_volume: f64,
        observed_tau: f64,
        drop_ann: f64,
        drop_silent: f64,
        last_update: Option<Timestamp>,
        #[serde(default)]
        trend_d: f64,
    }

    let stored = to_cbor_bytes(&ledger_sample());
    let decoded: PairLedgerPlusDefaulted = from_cbor_bytes(&stored).unwrap();

    assert_eq!(
        decoded.trend_d, 0.0,
        "the added field arrives as its default"
    );
    assert_eq!(
        decoded.depth_of_their_service, 60.0,
        "the pre-existing fields still arrive"
    );
}

#[test]
fn pair_ledger_with_a_new_required_field_cannot_read_rows_written_today() {
    // The failure mode the rule guards against, pinned so nobody meets it in the field:
    // a field without a default makes every existing row undecodable, which takes out
    // list_pair_ledgers → snapshot_db → the whole SystemState push (error+skip in the
    // daemon loop), and makes already-published base blobs unrestorable — i.e. no DR.
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct PairLedgerPlusRequired {
        gb_days_they_store_for_us: f64,
        gb_days_we_store_for_them: f64,
        depth_of_their_service: f64,
        v_dem: f64,
        observed_volume: f64,
        observed_tau: f64,
        drop_ann: f64,
        drop_silent: f64,
        last_update: Option<Timestamp>,
        trend_d: f64,
    }

    let stored = to_cbor_bytes(&ledger_sample());

    assert!(
        from_cbor_bytes::<PairLedgerPlusRequired>(&stored).is_err(),
        "a new field without #[serde(default)] breaks every row written before it"
    );
}

/// A `PairLedger` row exactly as this tree encodes it — CBOR of [`ledger_sample`].
///
/// Frozen 2026-08-09 (У-1) and REGENERATED the same day, because У-2 renamed the three
/// capital fields into absolute terms and the field names ride inside the CBOR map. That
/// rename is free today and only today: there is no deployed network, so no row and no
/// published SystemState blob carries the old names. Once one does, this fixture is what
/// makes the next rename visible instead of silent.
///
/// This is the real mine (W-2 follow-up assigned to У-2): the two tests above demonstrate
/// the MECHANISM on stand-in replica structs, so neither of them turns red if a future
/// field lands on the ACTUAL `PairLedger` without `#[serde(default)]`. This one does.
const PAIR_LEDGER_ROW_FROZEN_2026_08_09: &[u8] = &[
    0xa9, 0x78, 0x19, 0x67, 0x62, 0x5f, 0x64, 0x61, 0x79, 0x73, 0x5f, 0x74, 0x68, 0x65, 0x79, 0x5f,
    0x73, 0x74, 0x6f, 0x72, 0x65, 0x5f, 0x66, 0x6f, 0x72, 0x5f, 0x75, 0x73, 0xf9, 0x43, 0x00, 0x78,
    0x19, 0x67, 0x62, 0x5f, 0x64, 0x61, 0x79, 0x73, 0x5f, 0x77, 0x65, 0x5f, 0x73, 0x74, 0x6f, 0x72,
    0x65, 0x5f, 0x66, 0x6f, 0x72, 0x5f, 0x74, 0x68, 0x65, 0x6d, 0xf9, 0x44, 0x80, 0x76, 0x64, 0x65,
    0x70, 0x74, 0x68, 0x5f, 0x6f, 0x66, 0x5f, 0x74, 0x68, 0x65, 0x69, 0x72, 0x5f, 0x73, 0x65, 0x72,
    0x76, 0x69, 0x63, 0x65, 0xf9, 0x53, 0x80, 0x65, 0x76, 0x5f, 0x64, 0x65, 0x6d, 0xf9, 0x40, 0x00,
    0x6f, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x65, 0x64, 0x5f, 0x76, 0x6f, 0x6c, 0x75, 0x6d, 0x65,
    0xf9, 0x3e, 0x00, 0x6c, 0x6f, 0x62, 0x73, 0x65, 0x72, 0x76, 0x65, 0x64, 0x5f, 0x74, 0x61, 0x75,
    0xf9, 0x4f, 0x80, 0x68, 0x64, 0x72, 0x6f, 0x70, 0x5f, 0x61, 0x6e, 0x6e, 0xf9, 0x3c, 0x00, 0x6b,
    0x64, 0x72, 0x6f, 0x70, 0x5f, 0x73, 0x69, 0x6c, 0x65, 0x6e, 0x74, 0xf9, 0x00, 0x00, 0x6b, 0x6c,
    0x61, 0x73, 0x74, 0x5f, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x1a, 0x65, 0x53, 0xf1, 0x00,
];

#[test]
fn pair_ledger_still_decodes_a_row_frozen_before_the_field_was_added() {
    // Rows already on disk (and inside every published SystemState base blob) must keep
    // decoding into the REAL struct. If this goes red, the last field added lacks
    // `#[serde(default)]`, and the blast radius is not one stale row: list_pair_ledgers →
    // snapshot_db → SystemState publication stops with only a log line, and disaster
    // recovery cannot read the blobs already out there.
    let decoded: PairLedger = from_cbor_bytes(PAIR_LEDGER_ROW_FROZEN_2026_08_09)
        .expect("a row written before the change must still decode");

    assert_eq!(decoded, ledger_sample(), "every frozen field round-trips");
}

#[test]
fn the_frozen_pair_ledger_row_is_what_this_tree_writes_today() {
    // Guards the fixture itself: if the encoding (not the schema) ever changes, the test
    // above would keep passing on a fixture that no longer represents a real stored row.
    assert_eq!(
        to_cbor_bytes(&ledger_sample()),
        PAIR_LEDGER_ROW_FROZEN_2026_08_09,
        "the frozen fixture must still be byte-identical to a freshly written row"
    );
}
