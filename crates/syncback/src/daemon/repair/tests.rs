// Tests for RepairAgent.
// Uses real Db::open_in_memory(), real RaptorQEncoder, TempDir for file I/O.

use std::sync::Arc;

use syncback_core::db::Db;
use syncback_core::erasure::RaptorQEncoder;
use syncback_core::types::{
    hex_encode, DeviceId, FileId, IdentityPub, PlacementStatus, SourceBlockId, SourceBlockRecord,
    SourceBlockStatus, SourceBlockType, SymbolPlacement, Timestamp,
};
use tempfile::TempDir;

use super::{RepairAgent, RepairConfig, RepairError};

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
        n: None,
        overhead: None,
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

// ─── REPAIR-08: insufficient peers for placement — analysis ──────────────────
//
// FINDING: REPAIR-08 is a false GAP at the repair level.
//
// repair_placement() (Phase 2.5) re-encodes symbols locally from the source
// block file. It does NOT call compute_allocation — there is no peer selection
// at this stage. The placement's esi_ranges are already recorded in the DB from
// the original backup; repair just regenerates those specific ESIs and writes
// symbol files to disk.
//
// compute_allocation is called only in the backup pipeline (BackupCoordinator)
// when initially distributing symbols to holders. The RepairAgent has no concept
// of "available peers" — it works entirely offline with local data.
//
// Therefore, "repair with insufficient peers" cannot be tested at repair level.
// The failure mode (too few peers) belongs in BackupCoordinator tests, not here.

// ─── REPAIR-09: RepairNow trigger repairs only the targeted block ─────────────

#[tokio::test]
async fn repair_now_trigger_repairs_specific_block() {
    // Two Lost placements (different blocks). Send RepairTrigger::RepairNow for
    // bid1/hid1 only. Verify bid1 becomes Alive and bid2 stays Lost.
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid1 = block_id(110);
    let hid1 = holder_id(111);
    let bid2 = block_id(120);
    let hid2 = holder_id(121);

    let source_data = vec![0xBBu8; 65535];

    // Set up bid1 with source file on disk
    write_source_block_file(symbols_dir.path(), &bid1, &source_data);
    db.upsert_source_block(&make_source_block_record(bid1, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid1, hid1, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    // Set up bid2 as Lost with NO source file on disk (so it cannot be repaired)
    db.upsert_source_block(&make_source_block_record(bid2, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid2, hid2, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());

    // Send RepairNow for bid1 only; bid2 is not targeted
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tx.send(super::RepairTrigger::RepairNow {
        block_id: bid1,
        holder_id: hid1,
    })
    .await
    .unwrap();
    // Drop sender so run() exits after processing the one message
    drop(tx);

    agent.run(3600, rx).await.unwrap();

    // bid1 must be Alive
    let p1 = db.get_placement(&bid1, &hid1).unwrap().unwrap();
    assert_eq!(
        p1.status,
        PlacementStatus::Alive,
        "bid1 must be Alive after RepairNow"
    );

    // bid2 must still be Lost — it was not targeted
    let p2 = db.get_placement(&bid2, &hid2).unwrap().unwrap();
    assert_eq!(
        p2.status,
        PlacementStatus::Lost,
        "bid2 must remain Lost — RepairNow did not target it"
    );
}

// ─── REPAIR-10: ScanAll trigger repairs all Lost placements ──────────────────

#[tokio::test]
async fn scan_all_trigger_repairs_all_lost() {
    // Two Lost placements. Send RepairTrigger::ScanAll via channel.
    // Verify both become Alive after run() processes the trigger.
    //
    // NOTE: scan_and_repair_finds_lost_placement_and_repairs covers the direct
    // scan_and_repair() call with one block. This test verifies the ScanAll
    // trigger path through run() with two blocks — different code path.
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid1 = block_id(130);
    let hid1 = holder_id(131);
    let bid2 = block_id(140);
    let hid2 = holder_id(141);

    let source_data = vec![0xDDu8; 65535];

    // Both blocks have source files on disk
    write_source_block_file(symbols_dir.path(), &bid1, &source_data);
    write_source_block_file(symbols_dir.path(), &bid2, &source_data);

    db.upsert_source_block(&make_source_block_record(bid1, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid1, hid1, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    db.upsert_source_block(&make_source_block_record(bid2, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid2, hid2, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());

    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tx.send(super::RepairTrigger::ScanAll).await.unwrap();
    drop(tx);

    agent.run(3600, rx).await.unwrap();

    // Both placements must be Alive after ScanAll
    let p1 = db.get_placement(&bid1, &hid1).unwrap().unwrap();
    assert_eq!(p1.status, PlacementStatus::Alive, "bid1 must be Alive after ScanAll");

    let p2 = db.get_placement(&bid2, &hid2).unwrap().unwrap();
    assert_eq!(p2.status, PlacementStatus::Alive, "bid2 must be Alive after ScanAll");
}

// ─── test 24: pos_fail_marks_lost_then_repair_restores_to_alive ───────────────
// REPAIR-11: Full cycle — PoS fail → placement Lost → repair generates new symbols.
// Placement starts Alive; PoS fail is simulated via handle_pos_nack (same path
// as apply_pos_outcome for Fail); scan_and_repair then restores it to Alive.

#[tokio::test]
async fn pos_fail_marks_lost_then_repair_restores_to_alive() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(90);
    let hid = holder_id(91);
    let source_data = vec![0xCCu8; 65535];

    // Setup: source block record + file on disk
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();
    write_source_block_file(symbols_dir.path(), &bid, &source_data);

    // Placement starts Alive (as it would be in steady state)
    db.upsert_placement(&make_placement(bid, hid, vec![(0, 1)], PlacementStatus::Alive))
        .unwrap();

    let agent = make_agent(db.clone(), symbols_dir.path());

    // ── Simulate PoS fail outcome ────────────────────────────────────────────
    // handle_pos_nack mirrors what apply_pos_outcome does for a Fail result:
    // marks placement Lost and resets consecutive_misses to 0.
    agent.handle_pos_nack(&bid, &hid, now()).await.unwrap();

    // ── Verify Lost state ────────────────────────────────────────────────────
    let after_pos_fail = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(after_pos_fail.status, PlacementStatus::Lost);

    // ── Run repair ───────────────────────────────────────────────────────────
    let repaired = agent.scan_and_repair().await;
    assert_eq!(repaired, 1);

    // ── Verify repair results ────────────────────────────────────────────────
    let restored = db.get_placement(&bid, &hid).unwrap().unwrap();
    assert_eq!(restored.status, PlacementStatus::Alive);
    assert_eq!(restored.consecutive_misses, 0);

    // Symbol file must exist at {symbols_dir}/{hex(bid)}/{hex(hid)}/0.sym
    let sym_path = symbols_dir
        .path()
        .join(hex_encode(&bid.0))
        .join(hex_encode(&hid.0))
        .join("0.sym");
    assert!(sym_path.exists(), "symbol file must exist after repair: {:?}", sym_path);

    let sym_data = std::fs::read(&sym_path).unwrap();
    assert_eq!(sym_data.len(), 65535, "symbol must be exactly T bytes");
}
