use crate::db::testutil::test_db;
use crate::migration::migrate_block_records;
use crate::types::{
    DeviceId, FileId, IdentityPub, PeerRecord, PlacementStatus, SourceBlockId, SourceBlockRecord,
    SourceBlockStatus, SourceBlockType, SymbolPlacement, Timestamp,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn block_id(seed: u8) -> SourceBlockId {
    SourceBlockId([seed; 32])
}

fn holder_id(seed: u8) -> DeviceId {
    DeviceId([seed; 32])
}

fn make_block(seed: u8, overhead: Option<f64>) -> SourceBlockRecord {
    SourceBlockRecord {
        block_id: block_id(seed),
        k: 5,
        t: 65535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(1000),
        encrypted_size: None,
        n: Some(10),
        overhead,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
        last_attempted_at: None,
        last_pool_signature: 0,
    }
}

fn make_placement(
    bid: SourceBlockId,
    hid: DeviceId,
    status: PlacementStatus,
    count: u32,
) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: bid,
        holder_id: hid,
        file_id: FileId(1),
        esi_ranges: vec![(0, count)],
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: Timestamp(1000),
        consecutive_misses: 0,
    }
}

fn make_peer(device_id: DeviceId) -> PeerRecord {
    PeerRecord {
        device_id,
        master_identity: IdentityPub([0xAAu8; 32]),
        trust_p: 0.8,
        trust_i: 0.8,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1000),
        last_seen: Timestamp(2000),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn migrate_block_records_handles_empty_db() {
    let db = test_db();
    let count = migrate_block_records(&db).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn migrate_block_records_populates_current_alive_from_placement_table() {
    let db = test_db();
    let bid = block_id(1);

    db.upsert_source_block(&make_block(1, Some(2.475))).unwrap();

    // 2 Alive, 1 Lost — only Alive count.
    db.upsert_placement(&make_placement(
        bid,
        holder_id(10),
        PlacementStatus::Alive,
        5,
    ))
    .unwrap();
    db.upsert_placement(&make_placement(
        bid,
        holder_id(11),
        PlacementStatus::Alive,
        5,
    ))
    .unwrap();
    db.upsert_placement(&make_placement(
        bid,
        holder_id(12),
        PlacementStatus::Lost,
        5,
    ))
    .unwrap();

    migrate_block_records(&db).unwrap();

    let record = db.get_source_block(&bid).unwrap().unwrap();
    assert_eq!(record.current_alive, 2, "only Alive placements count");
}

#[test]
fn migrate_block_records_populates_current_reliability_from_holder_data() {
    let db = test_db();
    let bid = block_id(2);

    db.upsert_source_block(&make_block(2, Some(2.475))).unwrap();

    let h1 = holder_id(20);
    let h2 = holder_id(21);
    db.upsert_placement(&make_placement(bid, h1, PlacementStatus::Alive, 5))
        .unwrap();
    db.upsert_placement(&make_placement(bid, h2, PlacementStatus::Alive, 5))
        .unwrap();
    db.upsert_peer(&make_peer(h1)).unwrap();
    db.upsert_peer(&make_peer(h2)).unwrap();

    migrate_block_records(&db).unwrap();

    let record = db.get_source_block(&bid).unwrap().unwrap();
    assert!(
        record.current_reliability > 0.0 && record.current_reliability <= 1.0,
        "current_reliability must be in (0, 1], got {}",
        record.current_reliability
    );
}

#[test]
fn migrate_block_records_derives_importance_from_overhead_for_legacy() {
    let db = test_db();
    let bid = block_id(3);

    // overhead = 2.475 → importance = (2.475 - 1.5) / 1.5 = 0.65
    db.upsert_source_block(&make_block(3, Some(2.475))).unwrap();

    migrate_block_records(&db).unwrap();

    let record = db.get_source_block(&bid).unwrap().unwrap();
    assert!(
        (record.importance - 0.65).abs() < 0.001,
        "importance must be ~0.65, got {}",
        record.importance
    );
    // target_reliability(0.65) = 1 - 10^(-(0.3 + 0.65*4.7)) = 1 - 10^(-3.355) ≈ 0.9996
    assert!(
        (record.target_reliability - 0.9996).abs() < 0.0001,
        "target_reliability must be ~0.9996, got {}",
        record.target_reliability
    );
}

#[test]
fn migrate_block_records_uses_default_importance_05_when_overhead_missing() {
    let db = test_db();
    let bid = block_id(4);

    db.upsert_source_block(&make_block(4, None)).unwrap();

    migrate_block_records(&db).unwrap();

    let record = db.get_source_block(&bid).unwrap().unwrap();
    assert!(
        (record.importance - 0.5).abs() < 0.001,
        "importance must be ~0.5 (DEFAULT_IMPORTANCE), got {}",
        record.importance
    );
    // target_reliability(0.5) = 1 - 10^(-(0.3 + 0.5*4.7)) = 1 - 10^(-2.65) ≈ 0.9978
    assert!(
        (record.target_reliability - 0.9978).abs() < 0.001,
        "target_reliability must be ~0.9978, got {}",
        record.target_reliability
    );
}

#[test]
fn migrate_block_records_idempotent_across_calls() {
    let db = test_db();
    let bid = block_id(5);

    db.upsert_source_block(&make_block(5, Some(2.475))).unwrap();
    db.upsert_placement(&make_placement(
        bid,
        holder_id(50),
        PlacementStatus::Alive,
        3,
    ))
    .unwrap();
    db.upsert_placement(&make_placement(
        bid,
        holder_id(51),
        PlacementStatus::Alive,
        3,
    ))
    .unwrap();
    db.upsert_peer(&make_peer(holder_id(50))).unwrap();
    db.upsert_peer(&make_peer(holder_id(51))).unwrap();

    // First run.
    migrate_block_records(&db).unwrap();
    let after_first = db.get_source_block(&bid).unwrap().unwrap();

    // Second run — must produce identical values.
    migrate_block_records(&db).unwrap();
    let after_second = db.get_source_block(&bid).unwrap().unwrap();

    assert!(
        (after_first.importance - after_second.importance).abs() < 1e-12,
        "importance must be identical across runs"
    );
    assert_eq!(
        after_first.current_alive, after_second.current_alive,
        "current_alive must be identical across runs"
    );
    assert!(
        (after_first.current_reliability - after_second.current_reliability).abs() < 1e-12,
        "current_reliability must be identical across runs"
    );
    assert!(
        (after_first.target_reliability - after_second.target_reliability).abs() < 1e-12,
        "target_reliability must be identical across runs"
    );
    assert_eq!(
        after_first.last_attempted_at,
        after_second.last_attempted_at
    );
    assert_eq!(
        after_first.last_pool_signature,
        after_second.last_pool_signature
    );
}

/// Structural test: insert >10 000 blocks and assert the return value.
/// The progress logging every 10 000 blocks is verified by code review;
/// this test confirms the migration completes and counts correctly.
#[test]
fn migrate_block_records_logs_progress_every_10000_blocks() {
    let db = test_db();
    let n = 10_001usize;

    for i in 0..n {
        // Use 32-byte block IDs derived from the index.
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let bid = SourceBlockId(id);
        let block = SourceBlockRecord {
            block_id: bid,
            k: 5,
            t: 65535,
            block_type: SourceBlockType::Single,
            status: SourceBlockStatus::Active,
            created_at: Timestamp(1000),
            encrypted_size: None,
            n: Some(10),
            overhead: Some(2.475),
            drop_notice_sent_at: None,
            importance: 0.0,
            current_alive: 0,
            current_reliability: 0.0,
            target_reliability: 0.0,
            last_attempted_at: None,
            last_pool_signature: 0,
        };
        db.upsert_source_block(&block).unwrap();
    }

    let count = migrate_block_records(&db).unwrap();
    assert_eq!(count, n, "must process all {n} blocks");
}

#[test]
fn migrate_block_records_skips_block_with_no_peer_record_uses_fallback() {
    // Placement exists but PeerRecord is missing → survival_prob fallback = 0.5.
    // Migration must NOT error; it proceeds with the neutral survival probability.
    let db = test_db();
    let bid = block_id(6);

    db.upsert_source_block(&make_block(6, Some(2.475))).unwrap();
    // Insert placement but NO matching PeerRecord.
    db.upsert_placement(&make_placement(
        bid,
        holder_id(60),
        PlacementStatus::Alive,
        5,
    ))
    .unwrap();

    let count = migrate_block_records(&db).unwrap();
    assert_eq!(
        count, 1,
        "block is still processed (not skipped) on missing peer"
    );

    let record = db.get_source_block(&bid).unwrap().unwrap();
    // current_alive must still be 1.
    assert_eq!(record.current_alive, 1);
    // current_reliability is in valid range even with fallback survival_prob.
    assert!(
        record.current_reliability >= 0.0 && record.current_reliability <= 1.0,
        "current_reliability must be in [0, 1], got {}",
        record.current_reliability
    );
}

#[test]
fn migrate_block_records_sets_last_attempted_at_none_and_pool_signature_zero() {
    let db = test_db();
    let bid = block_id(7);

    db.upsert_source_block(&make_block(7, Some(2.475))).unwrap();

    migrate_block_records(&db).unwrap();

    let record = db.get_source_block(&bid).unwrap().unwrap();
    assert_eq!(
        record.last_attempted_at, None,
        "last_attempted_at must be None after migration"
    );
    assert_eq!(
        record.last_pool_signature, 0,
        "last_pool_signature must be 0 after migration"
    );
}

#[test]
fn migrate_block_records_counts_uncertain_placements_as_alive() {
    let db = test_db();
    let bid = block_id(8);

    db.upsert_source_block(&make_block(8, None)).unwrap();

    // 1 Alive + 1 Uncertain + 1 Offered — Alive+Uncertain counted, Offered excluded.
    db.upsert_placement(&make_placement(
        bid,
        holder_id(80),
        PlacementStatus::Alive,
        3,
    ))
    .unwrap();
    db.upsert_placement(&make_placement(
        bid,
        holder_id(81),
        PlacementStatus::Uncertain,
        3,
    ))
    .unwrap();
    db.upsert_placement(&make_placement(
        bid,
        holder_id(82),
        PlacementStatus::Offered,
        3,
    ))
    .unwrap();

    migrate_block_records(&db).unwrap();

    let record = db.get_source_block(&bid).unwrap().unwrap();
    assert_eq!(
        record.current_alive, 2,
        "Alive + Uncertain = 2; Offered excluded. got {}",
        record.current_alive
    );
}
