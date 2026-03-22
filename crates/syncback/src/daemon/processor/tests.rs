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
//   decide_symbol_offer             — quota check logic
//   handle_restore_request_inner    — returns symbols or empty response
//   handle_board_sync               — forwards to relay_sync_tx
//   handle_peer_announce            — upserts PeerRecord in DB + network.add_peer (Phase 7.10)
//   dispatch_relay                  — PeerAnnounce via relay
//   build_peer_announce             — NetworkHandle helper builds a signed message (Phase 7.10)

use std::sync::{Arc, Mutex};

use syncback_core::cluster::{derive_master_key, master_identity, ClusterState};
use syncback_core::db::Db;
use syncback_core::erasure::{ErasureEncoder, RaptorQEncoder};
use syncback_core::messages::{
    BoardSyncMsg, PeerAnnounceMsg, PosNackMsg, PosChallengeMsg, RestoreRequestMsg,
    SymbolAcceptMsg, SymbolDroppedMsg, SymbolRejectMsg, SymbolTransferMsg,
};
use syncback_core::types::{
    DeviceId, FileId, HoldingRecord, HoldingStatus, IdentityPub, PlacementStatus, SourceBlockId,
    SymbolPlacement, Timestamp,
};
use tempfile::TempDir;
use tokio::sync::mpsc;

use super::{esi_list_to_ranges, ranges_to_esi_list, Processor};
use crate::daemon::cluster_sync::{ClusterSyncConfig, ClusterSyncManager};
use crate::daemon::network::{NetworkConfig, NetworkHandle};
use crate::daemon::relay::{InboundMessage, SyncTrigger};
use crate::daemon::repair::RepairTrigger;

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn make_identity(seed: u8) -> IdentityPub {
    IdentityPub([seed; 32])
}

fn make_block_id(seed: u8) -> SourceBlockId {
    SourceBlockId([seed; 32])
}

async fn make_network() -> Arc<NetworkHandle> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let cfg = NetworkConfig {
        signing_key,
        known_peers: Default::default(),
        device_cert: None,
        iroh_secret_key: None,
        relay_mode: iroh::RelayMode::Disabled,
    };
    let (incoming_tx, _incoming_rx) = mpsc::channel(8);
    Arc::new(NetworkHandle::start(cfg, incoming_tx).await.expect("network start"))
}

async fn make_processor(
    db: Db,
    holdings_dir: &TempDir,
    source_blocks_dir: &TempDir,
) -> (Processor, mpsc::Receiver<RepairTrigger>, mpsc::Receiver<SyncTrigger>) {
    make_processor_with_quota(db, holdings_dir, source_blocks_dir, u64::MAX, u64::MAX).await
}

async fn make_processor_with_quota(
    db: Db,
    holdings_dir: &TempDir,
    source_blocks_dir: &TempDir,
    soft_quota_bytes: u64,
    hard_quota_bytes: u64,
) -> (Processor, mpsc::Receiver<RepairTrigger>, mpsc::Receiver<SyncTrigger>) {
    let (repair_tx, repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let (relay_sync_tx, relay_sync_rx) = mpsc::channel::<SyncTrigger>(16);

    let master_key = derive_master_key(&[42u8; 64]).expect("derive_master_key failed");
    let own_identity = master_identity(&master_key);
    let device_id = DeviceId([1u8; 16]);
    let now = Timestamp::now();

    let device_pub_key = [0u8; 32];
    let cert = syncback_core::cluster::issue_device_certificate(
        &master_key,
        device_id,
        device_pub_key,
        now,
    );
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
    let network = make_network().await;

    let (backup_event_tx, _backup_event_rx) =
        tokio::sync::mpsc::channel::<crate::daemon::backup::BackupEvent>(16);
    let processor = Processor::new(
        db,
        own_identity,
        repair_tx,
        cluster_sync,
        encoder,
        holdings_dir.path().to_path_buf(),
        source_blocks_dir.path().to_path_buf(),
        network,
        relay_sync_tx,
        soft_quota_bytes,
        hard_quota_bytes,
        backup_event_tx,
    );

    (processor, repair_rx, relay_sync_rx)
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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

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

#[tokio::test]
async fn handle_pos_nack_marks_alive_placement_lost() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

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

#[tokio::test]
async fn handle_pos_nack_is_idempotent_for_lost_placement() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

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

#[tokio::test]
async fn handle_pos_nack_returns_false_for_unknown_placement() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

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
    let (processor, mut repair_rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

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

#[tokio::test]
async fn handle_symbol_dropped_marks_alive_placement_lost() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

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

#[tokio::test]
async fn handle_symbol_dropped_is_idempotent_for_deleting_placement() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

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
    let (processor, mut repair_rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

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

// ─── decide_symbol_offer ──────────────────────────────────────────────────────

#[tokio::test]
async fn symbol_offer_accept_when_quota_not_exceeded() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    // 1 GB soft quota, no hard quota
    let soft = 1_073_741_824u64; // 1 GB
    let (processor, _rx, _relay_rx) =
        make_processor_with_quota(db.clone(), &holdings_dir, &source_dir, soft, u64::MAX).await;

    // 10 symbols * 65535 bytes = ~640 KB — well under 1 GB
    let offer_bytes: u64 = 10 * 65_535;
    let accept = processor
        .decide_symbol_offer(offer_bytes)
        .expect("decide_symbol_offer failed");
    assert!(accept, "should accept when under soft quota");
}

#[tokio::test]
async fn symbol_offer_reject_when_hard_quota_exceeded() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    // Hard quota of 100 bytes — already exceeded because we'll store a holding record
    let hard = 100u64;
    let (processor, _rx, _relay_rx) =
        make_processor_with_quota(db.clone(), &holdings_dir, &source_dir, u64::MAX, hard).await;

    // Insert a holding with total_bytes = 200 > 100 (hard floor)
    let owner = make_identity(1);
    let block_id = make_block_id(1);
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 1)],
        importance: 0.5,
        total_bytes: 200,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();

    let accept = processor
        .decide_symbol_offer(65_535)
        .expect("decide_symbol_offer failed");
    assert!(!accept, "should reject when held_bytes >= hard_quota");
}

#[tokio::test]
async fn symbol_offer_reject_when_soft_quota_would_overflow() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    // Soft quota 1000 bytes, held 900 bytes, offer 200 bytes → would exceed
    let soft = 1000u64;
    let (processor, _rx, _relay_rx) =
        make_processor_with_quota(db.clone(), &holdings_dir, &source_dir, soft, u64::MAX).await;

    let owner = make_identity(2);
    let block_id = make_block_id(2);
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 1)],
        importance: 0.5,
        total_bytes: 900,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();

    let accept = processor
        .decide_symbol_offer(200)
        .expect("decide_symbol_offer failed");
    assert!(!accept, "should reject when held + offer > soft_quota");
}

#[tokio::test]
async fn symbol_offer_accept_when_unlimited_quota() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) =
        make_processor_with_quota(db.clone(), &holdings_dir, &source_dir, u64::MAX, u64::MAX)
            .await;

    let accept = processor
        .decide_symbol_offer(1_000_000_000_000)
        .expect("decide_symbol_offer failed");
    assert!(accept, "should accept when quota is unlimited");
}

// ─── handle_restore_request_inner ────────────────────────────────────────────

#[tokio::test]
async fn restore_request_returns_empty_when_no_holding() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner = make_identity(5);
    let block_id = make_block_id(5);

    let request = RestoreRequestMsg {
        v: 1,
        source_block_id: block_id,
        esi_list: vec![],
        timestamp: Timestamp::now(),
    };

    let response = processor
        .handle_restore_request_inner(owner, request)
        .await
        .expect("handle_restore_request_inner failed");

    assert!(
        response.symbols.is_empty(),
        "expected empty response for unknown block"
    );
    assert_eq!(response.source_block_id, block_id);
}

#[tokio::test]
async fn restore_request_returns_held_symbols() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner = make_identity(6);
    let block_id = make_block_id(6);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();

    // Write 3 symbol files
    for esi in 0u32..3 {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 32]).unwrap();
    }

    // Upsert HoldingRecord
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 3)],
        importance: 0.5,
        total_bytes: 3 * 32,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();

    let request = RestoreRequestMsg {
        v: 1,
        source_block_id: block_id,
        esi_list: vec![], // empty = send all
        timestamp: Timestamp::now(),
    };

    let response = processor
        .handle_restore_request_inner(owner, request)
        .await
        .expect("handle_restore_request_inner failed");

    assert_eq!(response.symbols.len(), 3, "expected 3 symbols");
    assert_eq!(response.source_block_id, block_id);
}

#[tokio::test]
async fn restore_request_filters_by_esi_list() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner = make_identity(7);
    let block_id = make_block_id(7);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();

    // Write 5 symbol files (ESI 0..4)
    for esi in 0u32..5 {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 32]).unwrap();
    }

    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 5)],
        importance: 0.5,
        total_bytes: 5 * 32,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();

    let request = RestoreRequestMsg {
        v: 1,
        source_block_id: block_id,
        esi_list: vec![1, 3], // request only ESI 1 and 3
        timestamp: Timestamp::now(),
    };

    let response = processor
        .handle_restore_request_inner(owner, request)
        .await
        .expect("handle_restore_request_inner failed");

    assert_eq!(response.symbols.len(), 2, "expected exactly 2 symbols");
    let esis: Vec<u32> = response.symbols.iter().map(|s| s.esi).collect();
    assert!(esis.contains(&1), "missing ESI 1");
    assert!(esis.contains(&3), "missing ESI 3");
}

// ─── handle_board_sync ───────────────────────────────────────────────────────

#[tokio::test]
async fn board_sync_forwards_to_relay_sync_tx() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, mut relay_sync_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let from = make_identity(10);
    let msg = BoardSyncMsg {
        v: 1,
        entries: vec![], // entries are StoredEntry; empty is fine for routing test
        timestamp: Timestamp::now(),
    };

    processor
        .handle_board_sync(from, msg)
        .await
        .expect("handle_board_sync failed");

    let trigger = relay_sync_rx
        .try_recv()
        .expect("expected SyncTrigger in channel");
    assert_eq!(trigger.partner_identity, from);
    assert!(trigger.partner_entries.is_empty());
}

// ─── handle_peer_announce ────────────────────────────────────────────────────

fn make_peer_announce_msg(identity: IdentityPub) -> PeerAnnounceMsg {
    use syncback_core::types::NodeId;
    PeerAnnounceMsg {
        v: 1,
        identity_pub: identity,
        node_id: NodeId([42u8; 32]),
        timestamp: Timestamp::now(),
        sig: [0u8; 64],
    }
}

#[tokio::test]
async fn peer_announce_creates_new_peer_record() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let identity = make_identity(20);
    let msg = make_peer_announce_msg(identity);
    let expected_node_id = msg.node_id;

    processor
        .handle_peer_announce(msg)
        .await
        .expect("handle_peer_announce failed");

    let record = db.get_peer(&identity).unwrap();
    assert!(record.is_some(), "PeerRecord should have been created");
    let record = record.unwrap();
    assert_eq!(record.node_id, Some(expected_node_id));
    assert_eq!(record.identity, identity);
}

#[tokio::test]
async fn peer_announce_updates_existing_peer_node_id() {
    use syncback_core::types::{NodeId, PeerRecord};

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let identity = make_identity(21);
    let old_node_id = NodeId([10u8; 32]);
    let now = Timestamp::now();

    // Pre-insert existing record with old node_id.
    db.upsert_peer(&PeerRecord {
        identity,
        node_id: Some(old_node_id),
        trust_p: 0.5,
        trust_i: 0.3,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        device_id: None,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
    })
    .unwrap();

    let new_node_id = NodeId([99u8; 32]);
    let announce = PeerAnnounceMsg {
        v: 1,
        identity_pub: identity,
        node_id: new_node_id,
        timestamp: Timestamp::now(),
        sig: [0u8; 64],
    };

    processor
        .handle_peer_announce(announce)
        .await
        .expect("handle_peer_announce failed");

    let updated = db.get_peer(&identity).unwrap().unwrap();
    assert_eq!(updated.node_id, Some(new_node_id), "node_id should be updated");
    // first_seen should remain unchanged
    assert_eq!(updated.first_seen, now, "first_seen should be unchanged");
    // trust values preserved
    assert_eq!(updated.trust_p, 0.5);
}

#[tokio::test]
async fn peer_announce_via_relay_dispatch() {
    use syncback_core::messages::to_cbor;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let identity = make_identity(22);
    let announce_msg = make_peer_announce_msg(identity);
    let expected_node_id = announce_msg.node_id;
    let payload = to_cbor(&announce_msg).expect("cbor encode failed");

    let relay_msg = InboundMessage {
        from: identity,
        payload,
        msg_type: "peer_announce".to_string(),
        msg_id: [0u8; 16],
        created_at: Timestamp::now(),
    };

    processor.dispatch_relay(relay_msg).await;

    let record = db.get_peer(&identity).unwrap();
    assert!(record.is_some(), "PeerRecord should have been upserted via relay");
    assert_eq!(record.unwrap().node_id, Some(expected_node_id));
}

// ─── handle_symbol_accept / handle_symbol_reject (log-only handlers) ─────────

#[tokio::test]
async fn symbol_accept_logs_without_error() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let holder = make_identity(30);
    let accept = SymbolAcceptMsg {
        v: 1,
        source_block_id: make_block_id(30),
        offer_msg_id: [0u8; 16],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_accept(holder, accept)
        .await
        .expect("handle_symbol_accept should return Ok");
}

#[tokio::test]
async fn symbol_reject_logs_without_error() {
    use syncback_core::messages::RejectReason;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let holder = make_identity(31);
    let reject = SymbolRejectMsg {
        v: 1,
        source_block_id: make_block_id(31),
        offer_msg_id: [0u8; 16],
        reason: RejectReason::QuotaFull,
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_reject(holder, reject)
        .await
        .expect("handle_symbol_reject should return Ok");
}

// ─── Phase 7.10: peer gossip on connect ───────────────────────────────────────

/// A valid Ed25519 public key (iroh-compatible) for use in tests.
///
/// Returns both the 32-byte seed and the resulting public key bytes.
fn make_valid_iroh_node_id() -> syncback_core::types::NodeId {
    use syncback_core::types::NodeId;
    // Use a deterministic key: derive from a known signing key so the 32 bytes
    // are a valid Ed25519 (and therefore valid iroh PublicKey) byte sequence.
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    NodeId(sk.verifying_key().to_bytes())
}

#[tokio::test]
async fn peer_announce_with_valid_node_id_registers_in_network() {
    // When handle_peer_announce receives a PeerAnnounceMsg whose NodeId is a
    // valid iroh PublicKey, it should call network.add_peer() so the peer can
    // be reached via get_connection() in the future.
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let identity = make_identity(50);
    let valid_node_id = make_valid_iroh_node_id();

    let msg = PeerAnnounceMsg {
        v: 1,
        identity_pub: identity,
        node_id: valid_node_id,
        timestamp: Timestamp::now(),
        sig: [0u8; 64],
    };

    processor
        .handle_peer_announce(msg)
        .await
        .expect("handle_peer_announce should succeed with valid NodeId");

    // DB record should be created.
    let record = db.get_peer(&identity).unwrap();
    assert!(record.is_some(), "PeerRecord should have been created");
    assert_eq!(record.unwrap().node_id, Some(valid_node_id));

    // The peer should now be in network's known_peers directory.
    assert!(
        processor.network.has_known_peer(&identity).await,
        "peer should be registered in network after PeerAnnounce with valid NodeId"
    );
}

#[tokio::test]
async fn peer_announce_db_upsert_succeeds_regardless_of_node_id_validity() {
    // handle_peer_announce must always succeed and upsert the DB record
    // regardless of whether the NodeId bytes form a valid iroh PublicKey.
    // For invalid NodeIds the network.add_peer() is skipped gracefully.
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let identity = make_identity(51);
    // All-zeros is a special case: the identity point of the Ed25519 group —
    // iroh may or may not accept it as valid, but handle_peer_announce must
    // succeed either way.
    use syncback_core::types::NodeId;
    let node_id = NodeId([0u8; 32]);

    let msg = PeerAnnounceMsg {
        v: 1,
        identity_pub: identity,
        node_id,
        timestamp: Timestamp::now(),
        sig: [0u8; 64],
    };

    processor
        .handle_peer_announce(msg)
        .await
        .expect("handle_peer_announce should return Ok regardless of NodeId validity");

    // DB record must be created in all cases.
    let record = db.get_peer(&identity).unwrap();
    assert!(record.is_some(), "PeerRecord should have been created");
    assert_eq!(record.unwrap().node_id, Some(node_id));
}

#[tokio::test]
async fn build_peer_announce_produces_message_with_our_identity() {
    // NetworkHandle::build_peer_announce should return a PeerAnnounceMsg
    // whose identity_pub and node_id match the network handle's own values.
    let network = make_network().await;
    let now = Timestamp::now();

    let msg = network.build_peer_announce(now);

    assert_eq!(
        msg.identity_pub, network.identity_pub,
        "identity_pub should match our own identity"
    );
    assert_eq!(
        msg.node_id, network.node_id,
        "node_id should match our iroh NodeId"
    );
    assert_eq!(msg.v, 1, "version should be 1");
}

#[tokio::test]
async fn build_peer_announce_signature_is_verifiable() {
    // The signature on the PeerAnnounceMsg built by NetworkHandle must verify
    // against the identity_pub embedded in the message.
    use syncback_core::messages::verify_peer_announce;

    let network = make_network().await;
    let msg = network.build_peer_announce(Timestamp::now());

    verify_peer_announce(&msg).expect("PeerAnnounce signature should verify successfully");
}
