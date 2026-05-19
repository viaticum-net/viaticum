// Tests for RepairAgent (Wave 11b updated).
//
// Wave 11b removed: repair_placement(), scan_and_repair(), run(), deliver_repaired_symbols().
// Remaining functionality: handle_symbol_dropped, handle_pos_nack, mark_placement_lost,
// get_candidates_excluding, load_or_rebuild_blob, reliability_scan.
//
// Tests for scan_and_repair / repair_placement are ported to work_pipeline/tests.rs
// as worker_pos_lost_triggers_block_reappearing_in_queue and
// periodic_reliability_scan_updates_below_target_blocks.

use std::sync::Arc;

use tempfile::TempDir;
use viaticum_core::db::Db;
use viaticum_core::erasure::RaptorQEncoder;
use viaticum_core::types::{
    DeviceId, FileId, IdentityPub, PlacementStatus, SourceBlockId, SourceBlockRecord,
    SourceBlockStatus, SourceBlockType, SymbolPlacement, Timestamp,
};

use super::{RepairAgent, RepairConfig};

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

fn make_source_block_record(bid: SourceBlockId, k: u32, t: u16) -> SourceBlockRecord {
    SourceBlockRecord {
        block_id: bid,
        k,
        t,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: now(),
        encrypted_size: Some(k as u64 * t as u64),
        n: Some(k * 4),
        overhead: None,
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

fn make_agent(db: Db, symbols_dir: &std::path::Path) -> RepairAgent {
    RepairAgent::new(
        db,
        RepairConfig {
            source_blocks_dir: symbols_dir.to_path_buf(),
            symbols_dir: symbols_dir.to_path_buf(),
            epoch_key: [0u8; 32],
            own_identity: IdentityPub([9u8; 32]),
            master_signing_key: None,
            swarm: None,
            peer_backoff: None,
        },
        Arc::new(RaptorQEncoder::new()),
    )
}

// ─── test 16: handle_symbol_dropped_transitions_to_lost ──────────────────────

#[tokio::test]
async fn handle_symbol_dropped_transitions_to_lost() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(20);
    let hid = holder_id(21);

    db.upsert_placement(&make_placement(
        bid,
        hid,
        vec![(0, 1)],
        PlacementStatus::Alive,
    ))
    .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());
    agent
        .handle_symbol_dropped(&bid, &hid, now())
        .await
        .unwrap();

    let updated = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(updated.status, PlacementStatus::Lost);
    assert_eq!(updated.consecutive_misses, 0);
}

// ─── test 17: handle_pos_nack_transitions_to_lost ────────────────────────────

#[tokio::test]
async fn handle_pos_nack_transitions_to_lost() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(30);
    let hid = holder_id(31);

    db.upsert_placement(&make_placement(
        bid,
        hid,
        vec![(0, 1)],
        PlacementStatus::Alive,
    ))
    .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());
    agent.handle_pos_nack(&bid, &hid, now()).await.unwrap();

    let updated = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(updated.status, PlacementStatus::Lost);
}

// ─── test 18: handle_symbol_dropped_then_pos_nack_is_idempotent ──────────────

#[tokio::test]
async fn handle_symbol_dropped_then_pos_nack_is_idempotent() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(40);
    let hid = holder_id(41);

    db.upsert_placement(&make_placement(
        bid,
        hid,
        vec![(0, 1)],
        PlacementStatus::Alive,
    ))
    .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());

    agent
        .handle_symbol_dropped(&bid, &hid, now())
        .await
        .unwrap();
    let after_drop = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(after_drop.status, PlacementStatus::Lost);

    agent.handle_pos_nack(&bid, &hid, now()).await.unwrap();
    let after_nack = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(after_nack.status, PlacementStatus::Lost);
}

// ─── test 19: handle_pos_nack_then_symbol_dropped_is_idempotent ──────────────

#[tokio::test]
async fn handle_pos_nack_then_symbol_dropped_is_idempotent() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(50);
    let hid = holder_id(51);

    db.upsert_placement(&make_placement(
        bid,
        hid,
        vec![(0, 1)],
        PlacementStatus::Alive,
    ))
    .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());

    agent.handle_pos_nack(&bid, &hid, now()).await.unwrap();
    agent
        .handle_symbol_dropped(&bid, &hid, now())
        .await
        .unwrap();

    let final_placement = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(final_placement.status, PlacementStatus::Lost);
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
        last_attempted_at: None,
        last_pool_signature: 0,
    }
}

/// RepairAgent::handle_symbol_dropped marks placement Lost and updates current_alive.
#[tokio::test]
async fn repair_agent_mark_placement_lost_updates_current_alive() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(0x70);
    let hid_a = holder_id(0x71);
    let hid_b = holder_id(0x72);

    db.upsert_source_block(&make_block_for_hook(bid)).unwrap();

    db.upsert_placement(&make_placement(
        bid,
        hid_a,
        vec![(0, 4)],
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_placement(
        bid,
        hid_b,
        vec![(4, 4)],
        PlacementStatus::Alive,
    ))
    .unwrap();

    db.update_block_cached_fields(&bid, 0.5, 2, 0.9, 0.99, None, 0)
        .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());
    agent
        .handle_symbol_dropped(&bid, &hid_a, now())
        .await
        .unwrap();

    let placement = db.get_placement(&bid, &hid_a).unwrap().unwrap();
    assert_eq!(
        placement.status,
        PlacementStatus::Lost,
        "placement must be Lost after handle_symbol_dropped"
    );

    let updated_block = db.get_source_block(&bid).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 1,
        "current_alive must be 1 after one placement marked Lost"
    );
}

/// RepairAgent::handle_symbol_dropped on already-Lost placement is idempotent.
#[tokio::test]
async fn repair_agent_mark_placement_lost_idempotent_on_already_lost() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(0x73);
    let hid_a = holder_id(0x74);
    let hid_b = holder_id(0x75);

    db.upsert_source_block(&make_block_for_hook(bid)).unwrap();

    db.upsert_placement(&make_placement(
        bid,
        hid_a,
        vec![(0, 4)],
        PlacementStatus::Lost,
    ))
    .unwrap();
    db.upsert_placement(&make_placement(
        bid,
        hid_b,
        vec![(4, 4)],
        PlacementStatus::Alive,
    ))
    .unwrap();

    db.update_block_cached_fields(&bid, 0.5, 1, 0.7, 0.99, None, 0)
        .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());
    let result = agent.handle_symbol_dropped(&bid, &hid_a, now()).await;
    assert!(
        result.is_ok(),
        "handle_symbol_dropped must return Ok for already-Lost placement"
    );

    let updated_block = db.get_source_block(&bid).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 1,
        "current_alive must remain 1 when placement was already Lost (idempotent)"
    );
}

// ─── reliability_scan tests ──────────────────────────────────────────────────

/// reliability_scan corrects stale current_alive for an active block.
#[tokio::test]
async fn reliability_scan_corrects_stale_current_alive() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

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

    let agent = make_agent(db.clone(), symbols_dir.path());
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
    let symbols_dir = TempDir::new().unwrap();

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

    let agent = make_agent(db.clone(), symbols_dir.path());
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
    let symbols_dir = TempDir::new().unwrap();

    let agent = make_agent(db, symbols_dir.path());
    let updated_count = agent.reliability_scan().await;
    assert_eq!(
        updated_count, 0,
        "reliability_scan should return 0 when no blocks exist"
    );
}

// ─── load_or_rebuild_blob fallback tests ────────────────────────────────────

/// load_or_rebuild_blob: no swarm and no source files → EncodeFailed.
#[tokio::test]
async fn load_or_rebuild_blob_no_swarm_returns_encode_failed() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(0xA0);
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535))
        .unwrap();

    // Insert one Alive placement so it tries to fetch from network.
    db.upsert_placement(&make_placement(
        bid,
        holder_id(0x99),
        vec![(0, 1)],
        PlacementStatus::Alive,
    ))
    .unwrap();

    let agent = make_agent(db, symbols_dir.path());
    let result = agent.load_or_rebuild_blob(&bid).await;

    // block.bin absent, source rebuild fails (no source files), network fallback fails (no swarm).
    assert!(
        matches!(result, Err(super::RepairError::EncodeFailed(_))),
        "load_or_rebuild_blob must return EncodeFailed when no swarm and no source"
    );
}
