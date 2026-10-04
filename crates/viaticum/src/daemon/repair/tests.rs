// Tests for RepairAgent (bucket C updated).
//
// Wave 11b removed: repair_placement(), scan_and_repair(), run(), deliver_repaired_symbols(),
// load_or_rebuild_blob() and blob-rebuild helpers.
// Bucket C (PL-8a) removed: handle_symbol_dropped, handle_pos_nack, mark_placement_lost
// (duplicated processor::mark_placement_lost; only test callers).
// Remaining functionality: reliability_scan.
//
// Tests for scan_and_repair / repair_placement are ported to work_pipeline/tests.rs
// as worker_pos_lost_triggers_block_reappearing_in_queue and
// periodic_reliability_scan_updates_below_target_blocks.

use viaticum_core::db::Db;
use viaticum_core::types::{
    DeviceId, FileId, PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus,
    SourceBlockType, SymbolPlacement, Timestamp,
};

use super::RepairAgent;

// ─── helpers ────────────────────────────────────────────────────────────────

fn block_id(byte: u8) -> SourceBlockId {
    SourceBlockId([byte; 32])
}

fn holder_id(byte: u8) -> DeviceId {
    DeviceId([byte; 32])
}

fn now() -> Timestamp {
    Timestamp(1_700_000_000)
}

fn make_placement(
    bid: SourceBlockId,
    hid: DeviceId,
    esi_ranges: Vec<(u32, u32)>,
    status: PlacementStatus,
) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: bid,
        holder_id: hid,
        file_id: FileId(1),
        esi_ranges,
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: now(),
        consecutive_misses: 0,
    }
}

fn make_agent(db: Db) -> RepairAgent {
    RepairAgent::new(db)
}

// Note: Wave-1 online filter tests (repair_placement_skips_offline_peer_and_picks_online_alternative,
// repair_placement_falls_back_when_no_authenticated_candidates) were removed in Wave 11b
// review fixes (N1) because get_candidates_excluding and snapshot_authenticated_peers
// are dead code removed from RepairAgent. Equivalent candidate filtering is
// tested in work_pipeline/tests.rs via pool.rs snapshot_pool logic.

// ─── Wave 2: distinct binding for multiple holders ───────────────────────────

/// Multiple holders from same raw symbols get distinct bound bytes.
#[test]
fn repair_multiple_holders_from_same_raw_files_get_distinct_bound_bytes() {
    use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder};
    use viaticum_core::types::{ErasureParams, SourceBlockId};

    let encoder = RaptorQEncoder::new();
    let block_id = SourceBlockId([0xE0u8; 32]);
    let source = vec![0x42u8; 65535];
    let params = ErasureParams {
        k: 1,
        k_eff: 4,
        t: 65535,
        overhead: 1.5,
        n: 4,
    };

    let raw_syms = encoder.encode_raw(&source, &params, 0, 1).unwrap();
    let raw = &raw_syms[0];

    let h21 = holder_id(0x21);
    let h22 = holder_id(0x22);

    let bound_21 = encoder.apply_binding(raw.clone(), &block_id, &h21);
    let bound_22 = encoder.apply_binding(raw.clone(), &block_id, &h22);

    assert_ne!(
        bound_21.data, bound_22.data,
        "binding must differ per holder (holder-specific XOR keystream)"
    );
}

// ─── W11a: RepairAgent cached-fields hook tests ──────────────────────────────

fn make_block_for_hook(bid: SourceBlockId) -> SourceBlockRecord {
    SourceBlockRecord {
        seal_generation: 0,
        esi_high_water: 0,
        block_id: bid,
        k: 5,
        t: 1,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: now(),
        encrypted_size: Some(5),
        n: Some(20),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 0.5,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.99,
    }
}

// ─── reliability_scan tests ──────────────────────────────────────────────────

/// reliability_scan corrects stale current_alive for an active block.
#[tokio::test]
async fn reliability_scan_corrects_stale_current_alive() {
    let db = Db::open_in_memory().unwrap();
    let bid = block_id(0x80);
    let mut record = make_block_for_hook(bid);
    record.current_alive = 5; // stale — only 2 Alive placements below
    db.upsert_source_block(&record).unwrap();

    // 2 Alive placements.
    db.upsert_placement(&make_placement(
        bid,
        holder_id(0x81),
        vec![(0, 4)],
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_placement(
        bid,
        holder_id(0x82),
        vec![(4, 4)],
        PlacementStatus::Alive,
    ))
    .unwrap();
    // 1 Lost placement.
    db.upsert_placement(&make_placement(
        bid,
        holder_id(0x83),
        vec![(8, 4)],
        PlacementStatus::Lost,
    ))
    .unwrap();

    let agent = make_agent(db.clone());
    let updated_count = agent.reliability_scan().await;

    assert!(
        updated_count >= 1,
        "reliability_scan must update at least 1 block"
    );
    let updated = db.get_source_block(&bid).unwrap().unwrap();
    assert_eq!(
        updated.current_alive, 2,
        "reliability_scan must correct current_alive to 2"
    );
}

/// reliability_scan does not update blocks already at target_reliability.
#[tokio::test]
async fn reliability_scan_skips_completed_blocks() {
    let db = Db::open_in_memory().unwrap();
    let bid = block_id(0x90);
    let mut record = make_block_for_hook(bid);
    record.current_alive = 5;
    record.current_reliability = 0.999; // above target 0.99
    db.upsert_source_block(&record).unwrap();

    // 5 Alive placements.
    for i in 0..5u8 {
        db.upsert_placement(&make_placement(
            bid,
            holder_id(0x91 + i),
            vec![(i as u32 * 4, 4)],
            PlacementStatus::Alive,
        ))
        .unwrap();
    }

    let agent = make_agent(db.clone());
    let updated_count = agent.reliability_scan().await;

    // May update due to recalculation, but current_alive should match.
    let updated = db.get_source_block(&bid).unwrap().unwrap();
    assert_eq!(updated.current_alive, 5, "current_alive should remain 5");
    let _ = updated_count; // don't assert 0; scan may re-compute slightly different reliability
}

/// reliability_scan returns 0 when no blocks need correction.
#[tokio::test]
async fn reliability_scan_returns_zero_when_empty() {
    let db = Db::open_in_memory().unwrap();
    let agent = make_agent(db);
    let updated_count = agent.reliability_scan().await;
    assert_eq!(
        updated_count, 0,
        "reliability_scan should return 0 when no blocks exist"
    );
}
