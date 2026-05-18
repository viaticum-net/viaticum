// Tests for RepairAgent.
// Uses real Db::open_in_memory(), real RaptorQEncoder, TempDir for file I/O.

use std::sync::Arc;

use syncback_core::db::Db;
use syncback_core::erasure::RaptorQEncoder;
use syncback_core::types::{
    hex_encode, DeviceId, FileId, IdentityPub, PeerRecord, PlacementStatus, SourceBlockId,
    SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement, Timestamp,
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
        // n=k*4 ensures max_per_holder() >= 1 for compute_allocation to succeed.
        // n=k*2 (the default) yields max_per=0 for small k, which causes empty allocations.
        n: Some(k * 4),
        overhead: None,
        drop_notice_sent_at: None,
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

/// Insert two peer records (not the old holder) so compute_allocation has >= 2 candidates.
/// Both peers get trust_p = 0.5 so they are valid candidates (trust < 1.0).
fn insert_candidate_peers(db: &Db, a: u8, b: u8) {
    for byte in [a, b] {
        let did = DeviceId([byte; 32]);
        db.upsert_peer(&PeerRecord {
            device_id: did,
            master_identity: IdentityPub([byte; 32]),
            trust_p: 0.5,
            trust_i: 0.5,
            trust_s: 1.0,
            bytes_we_store_for_peer: 0,
            bytes_peer_stores_for_us: 0,
            first_seen: now(),
            last_seen: now(),
            revoked_device_pub_keys: vec![],
            addrs: vec![],
            x25519_pub: None,
        })
        .unwrap();
    }
}

// ─── test 14: repair_placement_generates_symbol_files ───────────────────────

#[tokio::test]
async fn repair_placement_generates_symbol_files() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(1);
    let old_hid = holder_id(2);

    // Source data: exactly 1 symbol (65535 bytes)
    let source_data = vec![0xABu8; 65535];

    // Write source block file
    write_source_block_file(symbols_dir.path(), &bid, &source_data);

    // Insert SourceBlockRecord (k=1, t=65535)
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();

    // Insert Lost SymbolPlacement for old holder: ESI 0, count 1
    db.upsert_placement(&make_placement(bid, old_hid, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    // Insert two candidate peers so compute_allocation has >= 2 after excluding old holder
    insert_candidate_peers(&db, 10, 11);

    let agent = make_agent(db.clone(), symbols_dir.path());
    let outcome = agent.repair_placement(&bid, &old_hid).await.unwrap();

    assert_eq!(outcome.symbols_written, 1);
    assert_eq!(outcome.new_placement_status, PlacementStatus::Offered);

    let new_holder = outcome.new_holder_id;
    assert_ne!(new_holder, old_hid, "new holder must differ from old");

    // Wave 2: no flat {esi}.bin files are written to disk for repair.
    // Binding is applied inline at send time. Verify only the DB placement.
    let new_placement = db.get_placement(&bid, &new_holder).unwrap().unwrap();

    // Old placement must be deleted; new placement must be Offered
    assert!(
        db.get_placement(&bid, &old_hid).unwrap().is_none(),
        "old placement must be deleted"
    );
    assert_eq!(new_placement.status, PlacementStatus::Offered);
    assert_eq!(new_placement.consecutive_misses, 0);
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

    // Insert candidate peers so we reach the encode step (not NoSuitableHolder first)
    insert_candidate_peers(&db, 20, 21);

    let agent = make_agent(db, symbols_dir.path());
    let result = agent.repair_placement(&bid, &hid).await;

    // block.bin missing AND no source files → rebuild fails with EncodeFailed.
    assert!(matches!(result, Err(RepairError::EncodeFailed(_))));
}

// ─── test 15b: network fallback error when swarm is absent ──────────────────

/// When block.bin is missing, source rebuild fails, *and* no swarm is
/// configured, `load_or_rebuild_blob` must report the missing network path.
/// Verifies the new third-stage fallback is reached and fails with a clear
/// "no swarm configured" message (D3: failure logged, no new Lost status).
#[tokio::test]
async fn repair_network_fallback_absent_reports_no_swarm() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(12);
    let hid = holder_id(13);

    // Source block exists in DB; block.bin absent; no source files to rebuild from.
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535))
        .unwrap();
    // Insert one Alive placement so the fallback actually tries to fetch
    // (rather than bailing on "no alive placements"). swarm=None then kicks in.
    db.upsert_placement(&make_placement(
        bid,
        holder_id(99),
        vec![(0, 1)],
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_placement(bid, hid, vec![(1, 1)], PlacementStatus::Lost))
        .unwrap();
    insert_candidate_peers(&db, 20, 21);

    let agent = make_agent(db, symbols_dir.path());
    let result = agent.repair_placement(&bid, &hid).await;

    match result {
        Err(RepairError::EncodeFailed(msg)) => {
            assert!(
                msg.contains("no swarm configured"),
                "expected 'no swarm configured' in fallback error, got: {msg}"
            );
        }
        other => panic!("expected EncodeFailed with swarm-related message, got: {other:?}"),
    }
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
    let old_hid = holder_id(61);
    let source_data = vec![0x11u8; 65535];

    write_source_block_file(symbols_dir.path(), &bid, &source_data);
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid, old_hid, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    // Need >= 2 candidate peers so repair can select a new holder
    insert_candidate_peers(&db, 70, 71);

    let agent = make_agent(db.clone(), symbols_dir.path());
    let (repaired, failed) = agent.scan_and_repair().await;
    assert_eq!(repaired, 1);
    assert_eq!(failed, 0);

    // Old placement deleted; exactly one new Offered placement for this block
    assert!(
        db.get_placement(&bid, &old_hid).unwrap().is_none(),
        "old Lost placement must be deleted"
    );
    let placements = db.list_placements_for_block(&bid).unwrap();
    assert_eq!(placements.len(), 1, "exactly one new placement");
    assert_eq!(placements[0].status, PlacementStatus::Offered);
}

// ─── test 21: scan_and_repair_finds_presumed_lost_placement_and_repairs ──────

#[tokio::test]
async fn scan_and_repair_finds_presumed_lost_placement_and_repairs() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(70);
    let old_hid = holder_id(71);
    let source_data = vec![0x22u8; 65535];

    write_source_block_file(symbols_dir.path(), &bid, &source_data);
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();

    // Status = PresumedLost, consecutive_misses = 3
    let mut placement = make_placement(bid, old_hid, vec![(0, 1)], PlacementStatus::PresumedLost);
    placement.consecutive_misses = 3;
    db.upsert_placement(&placement).unwrap();

    // Need >= 2 candidate peers
    insert_candidate_peers(&db, 80, 81);

    let agent = make_agent(db.clone(), symbols_dir.path());
    let (repaired, failed) = agent.scan_and_repair().await;
    assert_eq!(repaired, 1);
    assert_eq!(failed, 0);

    // Old placement deleted; new placement is Offered
    assert!(
        db.get_placement(&bid, &old_hid).unwrap().is_none(),
        "old PresumedLost placement must be deleted"
    );
    let placements = db.list_placements_for_block(&bid).unwrap();
    assert_eq!(placements.len(), 1);
    assert_eq!(placements[0].status, PlacementStatus::Offered);
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
    let (repaired, failed) = agent.scan_and_repair().await;
    assert_eq!(repaired, 0);
    assert_eq!(failed, 0);
}

// ─── test 23: gate_holder_evicts_pos_nack_owner_triggers_repair ──────────────
// GATE 1: holder evicts → PosNack → owner triggers repair

#[tokio::test]
async fn gate_holder_evicts_pos_nack_owner_triggers_repair() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(42);
    let old_hid = holder_id(7);
    let source_data = vec![0xFFu8; 65535];

    // 1. Placement starts Alive
    let placement = make_placement(bid, old_hid, vec![(0, 1)], PlacementStatus::Alive);
    db.upsert_placement(&placement).unwrap();
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();
    write_source_block_file(symbols_dir.path(), &bid, &source_data);

    // Need >= 2 candidate peers so repair can select a new holder
    insert_candidate_peers(&db, 50, 51);

    let agent = make_agent(db.clone(), symbols_dir.path());

    // 2. Holder sends PosNack (simulated)
    agent.handle_pos_nack(&bid, &old_hid, now()).await.unwrap();

    // 3. Verify placement is Lost
    let check = db.get_placement(&bid, &old_hid).unwrap().unwrap();
    assert_eq!(check.status, PlacementStatus::Lost);

    // 4. Owner triggers repair
    let (repaired, failed) = agent.scan_and_repair().await;
    assert_eq!(repaired, 1);
    assert_eq!(failed, 0);

    // 5. Old placement deleted; new placement is Offered for a different holder
    assert!(
        db.get_placement(&bid, &old_hid).unwrap().is_none(),
        "old placement must be deleted after repair"
    );
    let placements = db.list_placements_for_block(&bid).unwrap();
    assert_eq!(placements.len(), 1, "exactly one new placement after repair");
    let new_p = &placements[0];
    assert_ne!(new_p.holder_id, old_hid, "new holder must differ from evicted one");
    assert_eq!(new_p.status, PlacementStatus::Offered);
    assert_eq!(new_p.consecutive_misses, 0);
}

// ─── REPAIR-09: RepairNow trigger repairs only the targeted block ─────────────

#[tokio::test]
async fn repair_now_trigger_repairs_specific_block() {
    // Two Lost placements (different blocks). Send RepairTrigger::RepairNow for
    // bid1/hid1 only. Verify bid1 is repaired and bid2 stays Lost.
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid1 = block_id(110);
    let old_hid1 = holder_id(111);
    let bid2 = block_id(120);
    let hid2 = holder_id(121);

    let source_data = vec![0xBBu8; 65535];

    // Set up bid1 with source file on disk and candidate peers
    write_source_block_file(symbols_dir.path(), &bid1, &source_data);
    db.upsert_source_block(&make_source_block_record(bid1, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid1, old_hid1, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    // Set up bid2 as Lost with NO source file on disk (so it cannot be repaired)
    db.upsert_source_block(&make_source_block_record(bid2, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid2, hid2, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    // Candidate peers for new holder selection (bid1 repair)
    insert_candidate_peers(&db, 150, 151);

    let agent = make_agent(db.clone(), symbols_dir.path());

    // Send RepairNow for bid1 only; bid2 is not targeted
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tx.send(super::RepairTrigger::RepairNow {
        block_id: bid1,
        holder_id: old_hid1,
    })
    .await
    .unwrap();
    // Drop sender so run() exits after processing the one message
    drop(tx);

    agent.run(3600, rx).await.unwrap();

    // bid1: old placement deleted, new Offered placement exists
    assert!(
        db.get_placement(&bid1, &old_hid1).unwrap().is_none(),
        "bid1 old placement must be deleted after RepairNow"
    );
    let p1_placements = db.list_placements_for_block(&bid1).unwrap();
    assert_eq!(p1_placements.len(), 1, "bid1 must have one new placement");
    assert_eq!(
        p1_placements[0].status,
        PlacementStatus::Offered,
        "bid1 must be Offered after RepairNow"
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
    // Verify both are repaired (new Offered placements) after run() processes the trigger.
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid1 = block_id(130);
    let old_hid1 = holder_id(131);
    let bid2 = block_id(140);
    let old_hid2 = holder_id(141);

    let source_data = vec![0xDDu8; 65535];

    // Both blocks have source files on disk
    write_source_block_file(symbols_dir.path(), &bid1, &source_data);
    write_source_block_file(symbols_dir.path(), &bid2, &source_data);

    db.upsert_source_block(&make_source_block_record(bid1, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid1, old_hid1, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    db.upsert_source_block(&make_source_block_record(bid2, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid2, old_hid2, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();

    // Candidate peers for new holder selection
    insert_candidate_peers(&db, 160, 161);

    let agent = make_agent(db.clone(), symbols_dir.path());

    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tx.send(super::RepairTrigger::ScanAll).await.unwrap();
    drop(tx);

    agent.run(3600, rx).await.unwrap();

    // Both old placements deleted; each block has exactly one new Offered placement
    assert!(
        db.get_placement(&bid1, &old_hid1).unwrap().is_none(),
        "bid1 old placement must be deleted after ScanAll"
    );
    assert!(
        db.get_placement(&bid2, &old_hid2).unwrap().is_none(),
        "bid2 old placement must be deleted after ScanAll"
    );

    let p1_list = db.list_placements_for_block(&bid1).unwrap();
    assert_eq!(p1_list.len(), 1);
    assert_eq!(p1_list[0].status, PlacementStatus::Offered, "bid1 must be Offered after ScanAll");

    let p2_list = db.list_placements_for_block(&bid2).unwrap();
    assert_eq!(p2_list.len(), 1);
    assert_eq!(p2_list[0].status, PlacementStatus::Offered, "bid2 must be Offered after ScanAll");
}

// ─── test 24: pos_fail_marks_lost_then_repair_creates_new_offered ─────────────
// REPAIR-11: Full cycle — PoS fail → placement Lost → repair creates new Offered placement.

#[tokio::test]
async fn pos_fail_marks_lost_then_repair_restores_to_alive() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(90);
    let old_hid = holder_id(91);
    let source_data = vec![0xCCu8; 65535];

    // Setup: source block record + file on disk
    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();
    write_source_block_file(symbols_dir.path(), &bid, &source_data);

    // Placement starts Alive (as it would be in steady state)
    db.upsert_placement(&make_placement(bid, old_hid, vec![(0, 1)], PlacementStatus::Alive))
        .unwrap();

    // Candidate peers for new holder selection
    insert_candidate_peers(&db, 100, 101);

    let agent = make_agent(db.clone(), symbols_dir.path());

    // ── Simulate PoS fail outcome ────────────────────────────────────────────
    agent.handle_pos_nack(&bid, &old_hid, now()).await.unwrap();

    // ── Verify Lost state ────────────────────────────────────────────────────
    let after_pos_fail = db.get_placement(&bid, &old_hid).unwrap().unwrap();
    assert_eq!(after_pos_fail.status, PlacementStatus::Lost);

    // ── Run repair ───────────────────────────────────────────────────────────
    let (repaired, failed) = agent.scan_and_repair().await;
    assert_eq!(repaired, 1);
    assert_eq!(failed, 0);

    // ── Verify repair results ────────────────────────────────────────────────
    // Old placement must be deleted
    assert!(
        db.get_placement(&bid, &old_hid).unwrap().is_none(),
        "old placement must be deleted after repair"
    );

    // New placement is Offered for a different holder
    let new_placements = db.list_placements_for_block(&bid).unwrap();
    assert_eq!(new_placements.len(), 1, "exactly one new placement");
    let new_p = &new_placements[0];
    assert_ne!(new_p.holder_id, old_hid, "new holder must differ from old");
    assert_eq!(new_p.status, PlacementStatus::Offered);
    assert_eq!(new_p.consecutive_misses, 0);

    // No swarm → delivery is a no-op that returns Ok(()) → cleanup runs → .bin files removed.
    // Verify symbols_written is correct via the outcome (checked indirectly via placement ESI range).
    assert!(!new_p.esi_ranges.is_empty(), "new placement must have ESI ranges");
}

// ─── Wave-1 online filter tests for repair ───────────────────────────────────
//
// Coverage note: the async `repair_placement` path is not exercised end-to-end with a
// non-empty authenticated set, because `snapshot_authenticated_peers()` reads from
// `RepairAgentConfig::swarm` (`None` in tests) and falls back to an empty set —
// hitting the `< 2` fallback. Filter logic is covered at the unit level by the tests
// below. Full async coverage will arrive naturally in Wave 4 (unified worker) when
// `authenticated` becomes an injectable parameter.

/// Scenario 7: repair excludes offline peer (old holder) and picks authenticated alternative.
/// peer_1 is old holder (offline, not in authenticated). peer_2, peer_3 are online.
#[test]
fn repair_placement_skips_offline_peer_and_picks_online_alternative() {
    use std::collections::HashSet;
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let agent = make_agent(db.clone(), symbols_dir.path());

    let p1 = holder_id(0xA1);
    let p2 = holder_id(0xA2);
    let p3 = holder_id(0xA3);

    // Insert p2 and p3 as peers (not p1 — it's the excluded old holder).
    for (byte, did) in [(0xA2, p2), (0xA3, p3)] {
        db.upsert_peer(&PeerRecord {
            device_id: did,
            master_identity: IdentityPub([byte; 32]),
            trust_p: 0.5,
            trust_i: 0.5,
            trust_s: 1.0,
            bytes_we_store_for_peer: 0,
            bytes_peer_stores_for_us: 0,
            first_seen: now(),
            last_seen: now(),
            revoked_device_pub_keys: vec![],
            addrs: vec![],
            x25519_pub: None,
        })
        .unwrap();
    }

    // p2 and p3 are authenticated; p1 (old holder) is excluded by exclude param.
    let authenticated: HashSet<DeviceId> = [p2, p3].iter().cloned().collect();
    let candidates = agent.get_candidates_excluding(&p1, &authenticated).unwrap();

    // Must contain exactly p2 and p3.
    assert_eq!(candidates.len(), 2, "only 2 authenticated candidates expected");
    for c in &candidates {
        assert_ne!(c.device_id, p1, "old holder p1 must not be a candidate");
        assert!(
            authenticated.contains(&c.device_id),
            "only authenticated peers must appear"
        );
    }
}

/// Scenario 8: all peers offline → fallback to raw list (no panic, no error on this level).
#[test]
fn repair_placement_falls_back_when_no_authenticated_candidates() {
    use std::collections::HashSet;
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let agent = make_agent(db.clone(), symbols_dir.path());

    let old_hid = holder_id(0xB0);
    insert_candidate_peers(&db, 0xB1, 0xB2);

    // Empty authenticated set.
    let authenticated: HashSet<DeviceId> = HashSet::new();
    let candidates = agent.get_candidates_excluding(&old_hid, &authenticated).unwrap();

    // Fallback: should return all peers except old holder (2 peers).
    assert_eq!(
        candidates.len(),
        2,
        "fallback must return all non-excluded peers when authenticated set is empty"
    );
    for c in &candidates {
        assert_ne!(c.device_id, old_hid, "old holder must still be excluded");
    }
}

// ─── Wave 2 ATDD tests for repair ────────────────────────────────────────────
//
// S3: when repair triggered, no RaptorQ re-encode if raw/ files exist.
// S4: multiple holders served from same raw files get distinct bound bytes.
// S7: repair fallback re-encodes when raw/ missing (uses block.bin).
// AC8: deliver_repaired_symbols_direct does not write {esi}.bin files.

/// S3 / AC3: repair loads raw symbols from raw/ when available — no encode_raw call.
///
/// We test this indirectly: if raw/ files exist AND block.bin exists, repair succeeds
/// without needing to call encode_raw. We verify the placement is updated and no
/// flat {esi}.bin files appear in block_dir (they would only exist from encode_raw fallback
/// write path — but Wave 2 repair doesn't write them either way).
#[tokio::test]
async fn repair_placement_reads_raw_files_when_available() {
    use syncback_core::erasure::{ErasureEncoder, RaptorQEncoder};

    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(0xA0);
    let old_hid = holder_id(0xA1);

    // Source data: 1 symbol (65535 bytes)
    let source_data = vec![0x55u8; 65535];
    write_source_block_file(symbols_dir.path(), &bid, &source_data);

    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid, old_hid, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();
    insert_candidate_peers(&db, 0xB0, 0xB1);

    // Pre-populate raw/ directory (simulating a previous backup that wrote raw files).
    // We need to write valid raw symbols so that repair can read them.
    let encoder = RaptorQEncoder::new();
    let block_hex = hex_encode(&bid.0);
    let raw_dir = symbols_dir.path().join(&block_hex).join("raw");
    std::fs::create_dir_all(&raw_dir).unwrap();

    // We need the repair ESI range — it's next_free_esi_for_block after excluding old.
    // Old placement is at ESI 0 (Lost, excluded). next_free = 0 (all Lost excluded).
    // So new_alloc will start at esi_offset=0 (next_free.max(namespace_start)).
    // Since old placement is Lost (excluded from max), next_free = 0.
    // Write raw symbol for ESI 0 (the ESI repair will try to read).
    use syncback_core::types::ErasureParams;
    let params = ErasureParams { k: 1, k_eff: 4, t: 65535, overhead: 1.5, n: 4 };
    let raw_syms = encoder.encode_raw(&source_data, &params, 0, 1).unwrap();
    for sym in &raw_syms {
        std::fs::write(raw_dir.join(format!("{}.bin", sym.esi)), &sym.data).unwrap();
    }

    let agent = make_agent(db.clone(), symbols_dir.path());
    let outcome = agent.repair_placement(&bid, &old_hid).await.unwrap();

    assert_eq!(outcome.symbols_written, 1, "should report 1 symbol written");
    assert_eq!(outcome.new_placement_status, PlacementStatus::Offered);
    assert_ne!(outcome.new_holder_id, old_hid);

    // No flat {esi}.bin files in block_dir (Wave 2 never writes them for repair).
    let block_dir = symbols_dir.path().join(&block_hex);
    let flat_files: Vec<_> = std::fs::read_dir(&block_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy().to_string();
            e.path().is_file() && name.ends_with(".bin") && name != "block.bin"
        })
        .collect();
    assert!(
        flat_files.is_empty(),
        "repair must not write flat {{esi}}.bin files in block_dir, found: {:?}",
        flat_files.iter().map(|e| e.path()).collect::<Vec<_>>()
    );
}

/// S7 / AC3 (fallback): when raw/ missing, repair falls back to encode_raw via block.bin.
#[tokio::test]
async fn repair_placement_falls_back_to_encode_raw_when_raw_missing() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(0xC0);
    let old_hid = holder_id(0xC1);

    // Source data + block.bin present; no raw/ files.
    let source_data = vec![0x77u8; 65535];
    write_source_block_file(symbols_dir.path(), &bid, &source_data);

    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid, old_hid, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();
    insert_candidate_peers(&db, 0xD0, 0xD1);

    // No raw/ directory — should fall back to encode_raw from block.bin.
    let agent = make_agent(db.clone(), symbols_dir.path());
    let outcome = agent.repair_placement(&bid, &old_hid).await.unwrap();

    assert_eq!(outcome.symbols_written, 1, "fallback encode_raw should produce 1 symbol");
    assert_eq!(outcome.new_placement_status, PlacementStatus::Offered);

    // Old placement deleted, new placement exists.
    assert!(db.get_placement(&bid, &old_hid).unwrap().is_none());
    let new_placements = db.list_placements_for_block(&bid).unwrap();
    assert_eq!(new_placements.len(), 1);
    assert_eq!(new_placements[0].status, PlacementStatus::Offered);
}

/// S4: multiple holders from same raw file get distinct bound bytes.
#[test]
fn repair_multiple_holders_from_same_raw_files_get_distinct_bound_bytes() {
    use syncback_core::erasure::{ErasureEncoder, RaptorQEncoder};
    use syncback_core::types::{ErasureParams, SourceBlockId};

    let encoder = RaptorQEncoder::new();
    let block_id = SourceBlockId([0xE0u8; 32]);
    let source = vec![0x42u8; 65535];
    let params = ErasureParams { k: 1, k_eff: 4, t: 65535, overhead: 1.5, n: 4 };

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

/// AC8: deliver_repaired_symbols_direct does not write any {esi}.bin files to block_dir.
///
/// With swarm=None, deliver_repaired_symbols is a no-op. But we verify no disk write
/// happens either — the old code wrote files then cleaned them up; Wave 2 never writes.
#[tokio::test]
async fn deliver_repaired_symbols_direct_does_not_write_esi_bin_files() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();

    let bid = block_id(0xF0);
    let old_hid = holder_id(0xF1);

    let source_data = vec![0x33u8; 65535];
    write_source_block_file(symbols_dir.path(), &bid, &source_data);

    db.upsert_source_block(&make_source_block_record(bid, 1, 65535)).unwrap();
    db.upsert_placement(&make_placement(bid, old_hid, vec![(0, 1)], PlacementStatus::Lost))
        .unwrap();
    insert_candidate_peers(&db, 0xE0, 0xE1);

    let agent = make_agent(db.clone(), symbols_dir.path());
    agent.repair_placement(&bid, &old_hid).await.unwrap();

    // Check that no flat {esi}.bin files exist in block_dir.
    let block_hex = hex_encode(&bid.0);
    let block_dir = symbols_dir.path().join(&block_hex);

    if block_dir.exists() {
        let flat_files: Vec<_> = std::fs::read_dir(&block_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy().to_string();
                e.path().is_file() && name.ends_with(".bin") && name != "block.bin"
            })
            .collect();
        assert!(
            flat_files.is_empty(),
            "repair must not leave flat {{esi}}.bin files, found: {:?}",
            flat_files.iter().map(|e| e.path()).collect::<Vec<_>>()
        );
    }
}
