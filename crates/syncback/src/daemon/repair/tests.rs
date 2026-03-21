// Tests for RepairAgent.
// Uses real Db::open_in_memory(), real RaptorQEncoder, TempDir for file I/O.

use std::sync::Arc;

use syncback_core::db::Db;
use syncback_core::erasure::RaptorQEncoder;
use syncback_core::types::{
    hex_encode, FileId, IdentityPub, PlacementStatus, SourceBlockId, SourceBlockRecord,
    SourceBlockStatus, SourceBlockType, SymbolPlacement, Timestamp,
};
use tempfile::TempDir;

use super::{RepairAgent, RepairConfig, RepairError};

// ─── helpers ────────────────────────────────────────────────────────────────

fn block_id(byte: u8) -> SourceBlockId {
    SourceBlockId([byte; 32])
}

fn holder_id(byte: u8) -> IdentityPub {
    IdentityPub([byte; 32])
}

fn now() -> Timestamp {
    Timestamp(1_700_000_000)
}

/// Write a source block "blob" file at {symbols_dir}/{hex(block_id)}/block.bin
fn write_source_block_file(symbols_dir: &std::path::Path, bid: &SourceBlockId, data: &[u8]) {
    let dir = symbols_dir.join(hex_encode(&bid.0));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("block.bin"), data).unwrap();
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
    }
}

fn make_placement(
    bid: SourceBlockId,
    hid: IdentityPub,
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
            // source_blocks_dir = symbols_dir (block.bin lives inside block subdir)
            source_blocks_dir: symbols_dir.to_path_buf(),
            symbols_dir: symbols_dir.to_path_buf(),
            epoch_key: [0u8; 32],
            own_identity: IdentityPub([9u8; 32]),
        },
        Arc::new(RaptorQEncoder::new()),
    )
}

// ─── test 14: repair_placement_generates_symbol_files ───────────────────────

#[tokio::test]
async fn repair_placement_generates_symbol_files() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(1);
    let hid = holder_id(2);

    // Source data: exactly 1 symbol (65535 bytes)
    let source_data = vec![0xABu8; 65535];

    // Write source block file
    write_source_block_file(symbols_dir.path(), &bid, &source_data);

    // Insert SourceBlockRecord (k=1, t=65535)
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();

    // Insert Lost SymbolPlacement: ESI 0, count 1
    db.upsert_placement(&make_placement(bid, hid, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());
    let outcome = agent.repair_placement(&bid, &hid).await.unwrap();

    assert_eq!(outcome.symbols_written, 1);
    assert_eq!(outcome.new_status, PlacementStatus::Alive);

    // Symbol file must exist at {symbols_dir}/{hex(bid)}/{hex(hid)}/0.sym
    let sym_path = symbols_dir
        .path()
        .join(hex_encode(&bid.0))
        .join(hex_encode(&hid.0))
        .join("0.sym");
    assert!(sym_path.exists(), "symbol file must exist: {:?}", sym_path);

    let sym_data = std::fs::read(&sym_path).unwrap();
    assert_eq!(sym_data.len(), 65535, "symbol must be exactly T bytes");

    // DB placement must be updated to Alive
    let updated = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(updated.status, PlacementStatus::Alive);
    assert_eq!(updated.consecutive_misses, 0);
}

// ─── test 15: repair_placement_missing_source_block_returns_error ────────────

#[tokio::test]
async fn repair_placement_missing_source_block_returns_error() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(10);
    let hid = holder_id(11);

    // No source block file on disk
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid, hid, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    let agent = make_agent(db, symbols_dir.path());
    let result = agent.repair_placement(&bid, &hid).await;

    assert!(matches!(result, Err(RepairError::SourceBlockMissing(_))));
}

// ─── test 16: handle_symbol_dropped_transitions_to_lost ──────────────────────

#[tokio::test]
async fn handle_symbol_dropped_transitions_to_lost() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(20);
    let hid = holder_id(21);

    // Placement starts Alive
    db.upsert_placement(&make_placement(bid, hid, vec![(0, 1)], PlacementStatus::Alive))
        .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());
    agent.handle_symbol_dropped(&bid, &hid, now()).await.unwrap();

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

    // Placement starts Alive
    db.upsert_placement(&make_placement(bid, hid, vec![(0, 1)], PlacementStatus::Alive))
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

    db.upsert_placement(&make_placement(bid, hid, vec![(0, 1)], PlacementStatus::Alive))
        .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());

    // First: SymbolDropped → Lost
    agent.handle_symbol_dropped(&bid, &hid, now()).await.unwrap();
    let after_drop = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(after_drop.status, PlacementStatus::Lost);

    // Second: PosNack → no-op (already Lost)
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

    db.upsert_placement(&make_placement(bid, hid, vec![(0, 1)], PlacementStatus::Alive))
        .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());

    // First: PosNack → Lost
    agent.handle_pos_nack(&bid, &hid, now()).await.unwrap();
    // Second: SymbolDropped → no-op (already Lost)
    agent.handle_symbol_dropped(&bid, &hid, now()).await.unwrap();

    let final_placement = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(final_placement.status, PlacementStatus::Lost);
}

// ─── test 20: scan_and_repair_finds_lost_placement_and_repairs ───────────────

#[tokio::test]
async fn scan_and_repair_finds_lost_placement_and_repairs() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(60);
    let hid = holder_id(61);
    let source_data = vec![0x11u8; 65535];

    write_source_block_file(symbols_dir.path(), &bid, &source_data);
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid, hid, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());
    let count = agent.scan_and_repair().await;
    assert_eq!(count, 1);

    let updated = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(updated.status, PlacementStatus::Alive);
}

// ─── test 21: scan_and_repair_finds_presumed_lost_placement_and_repairs ──────

#[tokio::test]
async fn scan_and_repair_finds_presumed_lost_placement_and_repairs() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(70);
    let hid = holder_id(71);
    let source_data = vec![0x22u8; 65535];

    write_source_block_file(symbols_dir.path(), &bid, &source_data);
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();

    // Status = PresumedLost, consecutive_misses = 3
    let mut placement = make_placement(bid, hid, vec![(0, 1)], PlacementStatus::PresumedLost);
    placement.consecutive_misses = 3;
    db.upsert_placement(&placement).unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());
    let count = agent.scan_and_repair().await;
    assert_eq!(count, 1);

    let updated = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(updated.status, PlacementStatus::Alive);
}

// ─── test 22: scan_and_repair_skips_alive_placements ────────────────────────

#[tokio::test]
async fn scan_and_repair_skips_alive_placements() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(80);
    let hid = holder_id(81);

    // Placement is Alive — no repair needed
    db.upsert_placement(&make_placement(bid, hid, vec![(0, 1)], PlacementStatus::Alive))
        .unwrap();

    let agent = make_agent(db, symbols_dir.path());
    let count = agent.scan_and_repair().await;
    assert_eq!(count, 0);
}

// ─── test 23: gate_holder_evicts_pos_nack_owner_triggers_repair ──────────────
// GATE 1: holder evicts → PosNack → owner triggers repair

#[tokio::test]
async fn gate_holder_evicts_pos_nack_owner_triggers_repair() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(42);
    let hid = holder_id(7);
    let source_data = vec![0xFFu8; 65535];

    // 1. Placement starts Alive
    let placement = make_placement(bid, hid, vec![(0, 1)], PlacementStatus::Alive);
    db.upsert_placement(&placement).unwrap();
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();
    write_source_block_file(symbols_dir.path(), &bid, &source_data);

    let agent = make_agent(db.clone(), symbols_dir.path());

    // 2. Holder sends PosNack (simulated)
    agent.handle_pos_nack(&bid, &hid, now()).await.unwrap();

    // 3. Verify placement is Lost
    let check = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(check.status, PlacementStatus::Lost);

    // 4. Owner triggers repair
    let repaired = agent.scan_and_repair().await;
    assert_eq!(repaired, 1);

    // 5. Verify: symbol file exists, placement is Alive
    let sym_path = symbols_dir
        .path()
        .join(hex_encode(&bid.0))
        .join(hex_encode(&hid.0))
        .join("0.sym");
    assert!(sym_path.exists(), "symbol file must exist after repair");

    let final_placement = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(final_placement.status, PlacementStatus::Alive);
    assert_eq!(final_placement.consecutive_misses, 0);
}
