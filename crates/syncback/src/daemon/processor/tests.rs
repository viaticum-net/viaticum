// Tests for Processor handler methods.
//
// Strategy: Connection requires a real iroh endpoint and is not mockable.
// We test the inner/sync handler methods that contain the actual logic,
// bypassing the network layer entirely.
//
// Test coverage:
//   handle_symbol_transfer          — writes files, upserts HoldingRecord
//   handle_pos_challenge_inner      — responds with data or PosNack
//   handle_pos_nack_sync            — marks placement Lost
//   handle_symbol_dropped_sync      — marks placement Lost
//   esi_list_to_ranges / ranges_to_esi_list — round-trip helpers

use std::sync::{Arc, Mutex};

use syncback_core::cluster::{derive_master_key, master_identity, ClusterState};
use syncback_core::db::Db;
use syncback_core::erasure::{ErasureEncoder, RaptorQEncoder};
use syncback_core::messages::{
    PosNackMsg, PosChallengeMsg, SymbolDroppedMsg, SymbolTransferMsg,
};
use syncback_core::types::{
    DeviceId, FileId, HoldingStatus, IdentityPub, PlacementStatus, SourceBlockId, SymbolPlacement,
    Timestamp,
};
use tempfile::TempDir;
use tokio::sync::mpsc;

use super::{
    esi_list_to_ranges, ranges_to_esi_list, Processor,
};
use crate::daemon::cluster_sync::{ClusterSyncConfig, ClusterSyncManager};
use crate::daemon::repair::RepairTrigger;

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn make_identity(seed: u8) -> IdentityPub {
    IdentityPub([seed; 32])
}

fn make_block_id(seed: u8) -> SourceBlockId {
    SourceBlockId([seed; 32])
}

fn make_processor(
    db: Db,
    holdings_dir: &TempDir,
    source_blocks_dir: &TempDir,
) -> (Processor, mpsc::Receiver<RepairTrigger>) {
    let (repair_tx, repair_rx) = mpsc::channel::<RepairTrigger>(16);

    let master_key = derive_master_key(&[42u8; 64]).expect("derive_master_key failed");
    let own_identity = master_identity(&master_key);
    let device_id = DeviceId([1u8; 16]);
    let now = Timestamp::now();

    // Build a minimal ClusterState so ClusterSyncManager can be constructed.
    // ClusterState::init requires a DeviceCertificate. Use a dummy one.
    let device_pub_key = [0u8; 32];
    let cert = syncback_core::cluster::issue_device_certificate(
        &master_key,
        device_id,
        device_pub_key,
        now,
    );
    // Note: master_key is already unwrapped above.
    let cluster_state = ClusterState::init(db.clone(), own_identity, cert, now, now)
        .expect("ClusterState::init failed");
    let cluster_state = Arc::new(Mutex::new(cluster_state));

    let cluster_sync = Arc::new(ClusterSyncManager::new(
        db.clone(),
        ClusterSyncConfig {
            our_device_id: device_id,
            batch_size: 1000,
        },
        cluster_state,
    ));

    let encoder: Arc<dyn ErasureEncoder> = Arc::new(RaptorQEncoder::new());

    let processor = Processor::new(
        db,
        own_identity,
        repair_tx,
        cluster_sync,
        encoder,
        holdings_dir.path().to_path_buf(),
        source_blocks_dir.path().to_path_buf(),
    );

    (processor, repair_rx)
}

fn make_symbol_placement(
    block_id: SourceBlockId,
    holder_id: IdentityPub,
    esi_ranges: Vec<(u32, u32)>,
    status: PlacementStatus,
) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: FileId(1),
        esi_ranges,
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses: 0,
    }
}

// ─── esi_list_to_ranges / ranges_to_esi_list ──────────────────────────────────

#[test]
fn esi_ranges_round_trips_for_contiguous_list() {
    let esis: Vec<u32> = (10..20).collect();
    let ranges = esi_list_to_ranges(&esis);
    assert_eq!(ranges, vec![(10, 10)]);
    let back = ranges_to_esi_list(&ranges);
    assert_eq!(back, esis);
}

#[test]
fn esi_ranges_handles_non_contiguous_list() {
    let esis = vec![0, 1, 2, 5, 6, 10];
    let ranges = esi_list_to_ranges(&esis);
    assert_eq!(ranges, vec![(0, 3), (5, 2), (10, 1)]);
    let back = ranges_to_esi_list(&ranges);
    assert_eq!(back, esis);
}

#[test]
fn esi_ranges_empty_list_returns_empty() {
    assert!(esi_list_to_ranges(&[]).is_empty());
    assert!(ranges_to_esi_list(&[]).is_empty());
}

#[test]
fn esi_ranges_single_element() {
    let esis = vec![7u32];
    let ranges = esi_list_to_ranges(&esis);
    assert_eq!(ranges, vec![(7, 1)]);
    assert_eq!(ranges_to_esi_list(&ranges), esis);
}

// ─── handle_symbol_transfer ───────────────────────────────────────────────────

#[tokio::test]
async fn handle_symbol_transfer_writes_files_to_disk() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx) = make_processor(db.clone(), &holdings_dir, &source_dir);

    let owner = make_identity(1);
    let block_id = make_block_id(2);
    let symbol_data = vec![0xABu8; 64];

    let transfer = SymbolTransferMsg {
        v: 1,
        source_block_id: block_id,
        symbols: vec![syncback_core::erasure::Symbol {
            esi: 5,
            data: symbol_data.clone(),
        }],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_transfer(owner, transfer)
        .await
        .expect("handle_symbol_transfer failed");

    // File must exist on disk.
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let sym_path = holdings_dir.path().join(&block_hex).join("5.bin");
    assert!(sym_path.exists(), "symbol file was not written");
    let content = std::fs::read(&sym_path).unwrap();
    assert_eq!(content, symbol_data);
}

#[tokio::test]
async fn handle_symbol_transfer_creates_holding_record_in_db() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx) = make_processor(db.clone(), &holdings_dir, &source_dir);

    let owner = make_identity(1);
    let block_id = make_block_id(2);

    let symbols: Vec<syncback_core::erasure::Symbol> = (0..3)
        .map(|i| syncback_core::erasure::Symbol {
            esi: i,
            data: vec![i as u8; 32],
        })
        .collect();

    let transfer = SymbolTransferMsg {
        v: 1,
        source_block_id: block_id,
        symbols,
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_transfer(owner, transfer)
        .await
        .unwrap();

    let holding = db.get_holding(&block_id, &owner).unwrap();
    assert!(holding.is_some(), "HoldingRecord not written to DB");
    let holding = holding.unwrap();
    assert_eq!(holding.status, HoldingStatus::Active);
    assert_eq!(holding.esi_ranges, vec![(0, 3)]);
}

#[tokio::test]
async fn handle_symbol_transfer_merges_with_existing_holding() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx) = make_processor(db.clone(), &holdings_dir, &source_dir);

    let owner = make_identity(1);
    let block_id = make_block_id(2);

    // First transfer: ESI 0
    processor
        .handle_symbol_transfer(
            owner,
            SymbolTransferMsg {
                v: 1,
                source_block_id: block_id,
                symbols: vec![syncback_core::erasure::Symbol {
                    esi: 0,
                    data: vec![0u8; 32],
                }],
                timestamp: Timestamp::now(),
            },
        )
        .await
        .unwrap();

    // Second transfer: ESI 1
    processor
        .handle_symbol_transfer(
            owner,
            SymbolTransferMsg {
                v: 1,
                source_block_id: block_id,
                symbols: vec![syncback_core::erasure::Symbol {
                    esi: 1,
                    data: vec![1u8; 32],
                }],
                timestamp: Timestamp::now(),
            },
        )
        .await
        .unwrap();

    let holding = db.get_holding(&block_id, &owner).unwrap().unwrap();
    // Merged: ESI 0 and 1 => range (0, 2)
    assert_eq!(holding.esi_ranges, vec![(0, 2)]);
}

// ─── handle_pos_challenge_inner ───────────────────────────────────────────────

#[tokio::test]
async fn handle_pos_challenge_responds_with_data_when_symbol_held() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx) = make_processor(db.clone(), &holdings_dir, &source_dir);

    let owner = make_identity(1);
    let block_id = make_block_id(2);
    let esi = 7u32;
    let symbol_data = vec![0xDEu8; 64];

    // Write the symbol file manually.
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();
    std::fs::write(block_dir.join(format!("{esi}.bin")), &symbol_data).unwrap();

    let challenge_id = [99u8; 16];
    let challenge = PosChallengeMsg {
        v: 1,
        challenge_id,
        source_block_id: block_id,
        esi,
        timestamp: Timestamp::now(),
    };

    let reply = processor
        .handle_pos_challenge_inner(owner, challenge)
        .await
        .expect("handle_pos_challenge_inner failed");

    match reply {
        syncback_core::messages::Message::PosResponse(resp) => {
            assert_eq!(resp.challenge_id, challenge_id);
            assert_eq!(resp.esi, esi);
            assert_eq!(resp.data, symbol_data);
        }
        other => panic!("expected PosResponse, got {:?}", std::mem::discriminant(&other)),
    }
}

#[tokio::test]
async fn handle_pos_challenge_sends_nack_when_symbol_not_held() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx) = make_processor(db.clone(), &holdings_dir, &source_dir);

    let owner = make_identity(1);
    let block_id = make_block_id(2);
    let esi = 99u32;
    let challenge_id = [77u8; 16];

    let challenge = PosChallengeMsg {
        v: 1,
        challenge_id,
        source_block_id: block_id,
        esi,
        timestamp: Timestamp::now(),
    };

    let reply = processor
        .handle_pos_challenge_inner(owner, challenge)
        .await
        .expect("handle_pos_challenge_inner failed");

    match reply {
        syncback_core::messages::Message::PosNack(nack) => {
            assert_eq!(nack.challenge_id, challenge_id);
            assert_eq!(nack.esi, esi);
            assert_eq!(nack.source_block_id, block_id);
        }
        other => panic!("expected PosNack, got {:?}", std::mem::discriminant(&other)),
    }
}

// ─── handle_pos_nack_sync ─────────────────────────────────────────────────────

#[test]
fn handle_pos_nack_marks_alive_placement_lost() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir);

    let holder = make_identity(1);
    let block_id = make_block_id(2);

    let placement = make_symbol_placement(block_id, holder, vec![(0, 5)], PlacementStatus::Alive);
    db.upsert_placement(&placement).unwrap();

    let nack = PosNackMsg {
        v: 1,
        challenge_id: [0u8; 16],
        source_block_id: block_id,
        esi: 0,
        timestamp: Timestamp::now(),
    };

    let changed = processor
        .handle_pos_nack_sync(holder, &nack)
        .expect("handle_pos_nack_sync failed");
    assert!(changed, "expected placement to be modified");

    let updated = db.get_placement(&block_id, &holder).unwrap().unwrap();
    assert_eq!(updated.status, PlacementStatus::Lost);
}

#[test]
fn handle_pos_nack_is_idempotent_for_lost_placement() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir);

    let holder = make_identity(1);
    let block_id = make_block_id(2);

    let placement = make_symbol_placement(block_id, holder, vec![(0, 5)], PlacementStatus::Lost);
    db.upsert_placement(&placement).unwrap();

    let nack = PosNackMsg {
        v: 1,
        challenge_id: [0u8; 16],
        source_block_id: block_id,
        esi: 0,
        timestamp: Timestamp::now(),
    };

    let changed = processor
        .handle_pos_nack_sync(holder, &nack)
        .expect("handle_pos_nack_sync failed");
    assert!(!changed, "expected no change for already-Lost placement");
}

#[test]
fn handle_pos_nack_returns_false_for_unknown_placement() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir);

    let holder = make_identity(1);
    let block_id = make_block_id(99); // not in DB

    let nack = PosNackMsg {
        v: 1,
        challenge_id: [0u8; 16],
        source_block_id: block_id,
        esi: 0,
        timestamp: Timestamp::now(),
    };

    let changed = processor
        .handle_pos_nack_sync(holder, &nack)
        .expect("handle_pos_nack_sync failed");
    assert!(!changed);
}

// ─── handle_pos_nack triggers repair ─────────────────────────────────────────

#[tokio::test]
async fn handle_pos_nack_sends_repair_trigger() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, mut repair_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir);

    let holder = make_identity(1);
    let block_id = make_block_id(2);

    let placement = make_symbol_placement(block_id, holder, vec![(0, 5)], PlacementStatus::Alive);
    db.upsert_placement(&placement).unwrap();

    let nack = PosNackMsg {
        v: 1,
        challenge_id: [0u8; 16],
        source_block_id: block_id,
        esi: 0,
        timestamp: Timestamp::now(),
    };

    // Call the async version that also sends to repair channel.
    processor
        .handle_pos_nack(holder, nack)
        .await
        .expect("handle_pos_nack failed");

    let trigger = repair_rx
        .try_recv()
        .expect("expected RepairTrigger in channel");
    match trigger {
        RepairTrigger::RepairNow {
            block_id: bid,
            holder_id: hid,
        } => {
            assert_eq!(bid, block_id);
            assert_eq!(hid, holder);
        }
        other => panic!("expected RepairNow, got {other:?}"),
    }
}

// ─── handle_symbol_dropped_sync ───────────────────────────────────────────────

#[test]
fn handle_symbol_dropped_marks_alive_placement_lost() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir);

    let holder = make_identity(3);
    let block_id = make_block_id(4);

    let placement =
        make_symbol_placement(block_id, holder, vec![(10, 8)], PlacementStatus::Uncertain);
    db.upsert_placement(&placement).unwrap();

    let dropped = SymbolDroppedMsg {
        v: 1,
        source_block_id: block_id,
        esi_ranges: vec![(10, 8)],
        timestamp: Timestamp::now(),
    };

    let changed = processor
        .handle_symbol_dropped_sync(holder, &dropped)
        .expect("handle_symbol_dropped_sync failed");
    assert!(changed);

    let updated = db.get_placement(&block_id, &holder).unwrap().unwrap();
    assert_eq!(updated.status, PlacementStatus::Lost);
}

#[test]
fn handle_symbol_dropped_is_idempotent_for_deleting_placement() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir);

    let holder = make_identity(3);
    let block_id = make_block_id(4);

    let placement = make_symbol_placement(
        block_id,
        holder,
        vec![(10, 8)],
        PlacementStatus::Deleting,
    );
    db.upsert_placement(&placement).unwrap();

    let dropped = SymbolDroppedMsg {
        v: 1,
        source_block_id: block_id,
        esi_ranges: vec![(10, 8)],
        timestamp: Timestamp::now(),
    };

    let changed = processor
        .handle_symbol_dropped_sync(holder, &dropped)
        .expect("handle_symbol_dropped_sync failed");
    assert!(!changed, "Deleting placement should not be modified");
}

#[tokio::test]
async fn handle_symbol_dropped_sends_repair_trigger() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, mut repair_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir);

    let holder = make_identity(3);
    let block_id = make_block_id(4);

    let placement = make_symbol_placement(block_id, holder, vec![(0, 4)], PlacementStatus::Alive);
    db.upsert_placement(&placement).unwrap();

    let dropped = SymbolDroppedMsg {
        v: 1,
        source_block_id: block_id,
        esi_ranges: vec![(0, 4)],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_dropped(holder, dropped)
        .await
        .expect("handle_symbol_dropped failed");

    let trigger = repair_rx
        .try_recv()
        .expect("expected RepairTrigger in channel");
    match trigger {
        RepairTrigger::RepairNow {
            block_id: bid,
            holder_id: hid,
        } => {
            assert_eq!(bid, block_id);
            assert_eq!(hid, holder);
        }
        other => panic!("expected RepairNow, got {other:?}"),
    }
}
