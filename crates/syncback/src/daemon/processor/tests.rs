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
    BoardSyncMsg, CancelDeleteMsg, DeleteMsg, PeerAnnounceMsg, PosNackMsg, PosChallengeMsg,
    RestoreRequestMsg, SymbolAcceptMsg, SymbolDropNoticeMsg, SymbolDroppedMsg, SymbolRejectMsg,
    SymbolTransferMsg,
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
use crate::daemon::relay::{InboundMessage, RelayPost, SyncTrigger};
use crate::daemon::repair::RepairTrigger;

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn make_identity(seed: u8) -> IdentityPub {
    IdentityPub([seed; 32])
}

fn make_block_id(seed: u8) -> SourceBlockId {
    SourceBlockId([seed; 32])
}

fn make_peer_record(identity: IdentityPub) -> syncback_core::types::PeerRecord {
    let now = Timestamp::now();
    syncback_core::types::PeerRecord {
        identity,
        node_id: None,
        trust_p: syncback_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        device_id: None,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    }
}

async fn make_network() -> Arc<NetworkHandle> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let mi = IdentityPub(signing_key.verifying_key().to_bytes());
    let cfg = NetworkConfig {
        signing_key,
        master_identity: mi,
        known_peers: Default::default(),
        device_cert: None,
        iroh_secret_key: None,
        relay_mode: iroh::RelayMode::Disabled,
        x25519_pub: None,
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
    let pending_challenges: crate::daemon::scheduler::PendingChallenges =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
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
        holdings_dir.path().to_path_buf(), // data_dir (for disk space queries in tests)
        0,                                 // disk_reserve_bytes (no reserve in tests)
        backup_event_tx,
        1, // time_scale
        pending_challenges,
        relay_post_tx,
    );

    (processor, repair_rx, relay_sync_rx)
}

async fn make_processor_with_pending(
    db: Db,
    holdings_dir: &TempDir,
    source_blocks_dir: &TempDir,
    pending: crate::daemon::scheduler::PendingChallenges,
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
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
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
        u64::MAX,
        u64::MAX,
        holdings_dir.path().to_path_buf(),
        0,
        backup_event_tx,
        1, // time_scale
        pending,
        relay_post_tx,
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

// ─── PROC-11: symbol_accept_updates_backup_event ─────────────────────────────

/// handle_symbol_accept sends BackupEvent::SymbolAccepted to backup_event_tx.
///
/// The make_processor helper drops the receiver immediately. This test keeps
/// the receiver alive to verify the channel write actually happens.
#[tokio::test]
async fn symbol_accept_updates_backup_event() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();

    // Build processor manually so we can keep backup_event_rx alive.
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let (relay_sync_tx, _relay_sync_rx) = mpsc::channel::<SyncTrigger>(16);
    let master_key = derive_master_key(&[42u8; 64]).unwrap();
    let own_identity = master_identity(&master_key);
    let device_id = DeviceId([1u8; 16]);
    let now = Timestamp::now();
    let cert = syncback_core::cluster::issue_device_certificate(&master_key, device_id, [0u8; 32], now);
    let cluster_state = ClusterState::init(db.clone(), own_identity, cert, now, now).unwrap();
    let cluster_state = Arc::new(Mutex::new(cluster_state));
    let cluster_sync = Arc::new(ClusterSyncManager::new(
        db.clone(),
        ClusterSyncConfig { our_device_id: device_id, batch_size: 1000 },
        cluster_state,
    ));
    let encoder: Arc<dyn ErasureEncoder> = Arc::new(RaptorQEncoder::new());
    let network = make_network().await;
    let (backup_event_tx, mut backup_event_rx) =
        mpsc::channel::<crate::daemon::backup::BackupEvent>(16);
    let pending: crate::daemon::scheduler::PendingChallenges =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let processor = Processor::new(
        db.clone(),
        own_identity,
        repair_tx,
        cluster_sync,
        encoder,
        holdings_dir.path().to_path_buf(),
        source_dir.path().to_path_buf(),
        network,
        relay_sync_tx,
        u64::MAX,
        u64::MAX,
        holdings_dir.path().to_path_buf(),
        0,
        backup_event_tx,
        1,
        pending,
        relay_post_tx,
    );

    let holder = make_identity(7);
    let block_id = make_block_id(7);

    let accept = SymbolAcceptMsg {
        v: 1,
        source_block_id: block_id,
        offer_msg_id: [0u8; 16],
        timestamp: Timestamp::now(),
    };

    processor.handle_symbol_accept(holder, accept).await.unwrap();

    let event = backup_event_rx
        .try_recv()
        .expect("BackupEvent::SymbolAccepted must be sent");
    match event {
        crate::daemon::backup::BackupEvent::SymbolAccepted {
            holder_id,
            source_block_id,
        } => {
            assert_eq!(holder_id, holder);
            assert_eq!(source_block_id, block_id);
        }
        other => panic!("expected SymbolAccepted, got {other:?}"),
    }
}

// ─── PROC-12: symbol_reject_does_not_create_placement ────────────────────────

/// handle_symbol_reject sends BackupEvent::SymbolRejected but creates no
/// placement. The DB must not contain any placement for (block_id, holder_id).
#[tokio::test]
async fn symbol_reject_does_not_create_placement() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let holder = make_identity(8);
    let block_id = make_block_id(8);

    // No placement inserted — call the reject handler.
    let reject = SymbolRejectMsg {
        v: 1,
        source_block_id: block_id,
        offer_msg_id: [0u8; 16],
        reason: syncback_core::messages::RejectReason::QuotaFull,
        timestamp: Timestamp::now(),
    };
    processor
        .handle_symbol_reject(holder, reject)
        .await
        .unwrap();

    // No placement must exist.
    let placement = db.get_placement(&block_id, &holder).unwrap();
    assert!(
        placement.is_none(),
        "handle_symbol_reject must not create a placement"
    );
}

// ─── BACKUP-17: symbol_offer_reject_quota_full_no_placement ──────────────────

/// decide_symbol_offer returns false (reject) when both soft and hard quotas
/// are 1 byte. No holding or placement must exist in DB after the call.
#[tokio::test]
async fn symbol_offer_reject_quota_full_no_placement() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    // Quota of 1 byte: any offer will be rejected.
    let (processor, _repair_rx, _relay_rx) =
        make_processor_with_quota(db.clone(), &holdings_dir, &source_dir, 1, 1).await;

    let offer_bytes: u64 = 10 * 65_535; // ~640 KB
    let accept = processor
        .decide_symbol_offer(offer_bytes)
        .expect("decide_symbol_offer failed");
    assert!(!accept, "should reject when quota is 1 byte");

    // No holding or placement was created.
    let all_holdings = db.list_all_holdings().unwrap();
    let all_placements = db.list_all_placements().unwrap();
    assert!(
        all_holdings.is_empty(),
        "no holdings should exist after a quota-full reject"
    );
    assert!(
        all_placements.is_empty(),
        "no placements should exist after a quota-full reject"
    );
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
    // soft_quota=0 means "use disk-based limit" (effective = disk_free - reserve).
    // With reserve=0, any offer fitting in disk space is accepted.
    let (processor, _rx, _relay_rx) =
        make_processor_with_quota(db.clone(), &holdings_dir, &source_dir, 0, 0)
            .await;

    let accept = processor
        .decide_symbol_offer(65_535) // one symbol — always fits
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
        x25519_pub: None,
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
        x25519_pub: None,
    })
    .unwrap();

    let new_node_id = NodeId([99u8; 32]);
    let announce = PeerAnnounceMsg {
        v: 1,
        identity_pub: identity,
        node_id: new_node_id,
        timestamp: Timestamp::now(),
        sig: [0u8; 64],
        x25519_pub: None,
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
        x25519_pub: None,
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
        x25519_pub: None,
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

// ─── handle_system_state_backup ───────────────────────────────────────────────

#[tokio::test]
async fn handle_system_state_backup_stores_blob_for_known_peer() {
    use syncback_core::db::SystemStateBlobRecord;
    use syncback_core::messages::SystemStateBackupMsg;
    use syncback_core::types::{NodeId, PeerRecord};

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner = make_identity(60);
    let now = Timestamp::now();

    // Register owner as a known peer so the handler accepts the backup.
    db.upsert_peer(&PeerRecord {
        identity: owner,
        node_id: Some(NodeId([60u8; 32])),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        device_id: None,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    })
    .unwrap();

    let blob = vec![0xBEu8; 128];
    let msg = SystemStateBackupMsg {
        v: 1,
        encrypted_blob: blob.clone(),
        timestamp: now,
    };

    processor
        .handle_system_state_backup(owner, msg)
        .await
        .expect("handle_system_state_backup failed");

    let stored: Option<SystemStateBlobRecord> = db.get_system_state_blob(&owner).unwrap();
    assert!(stored.is_some(), "blob should have been stored in DB");
    assert_eq!(stored.unwrap().encrypted_blob, blob);
}

#[tokio::test]
async fn handle_system_state_backup_rejects_unknown_peer() {
    use syncback_core::messages::SystemStateBackupMsg;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let stranger = make_identity(61);
    let msg = SystemStateBackupMsg {
        v: 1,
        encrypted_blob: vec![0xFFu8; 64],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_system_state_backup(stranger, msg)
        .await
        .expect("handle_system_state_backup should return Ok even when rejecting");

    // DB must remain empty — unknown peer must not be stored.
    let stored = db.get_system_state_blob(&stranger).unwrap();
    assert!(stored.is_none(), "blob should not be stored for unknown peer");
}

#[tokio::test]
async fn handle_system_state_backup_ignores_empty_blob() {
    use syncback_core::messages::SystemStateBackupMsg;
    use syncback_core::types::{NodeId, PeerRecord};

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner = make_identity(62);
    let now = Timestamp::now();
    db.upsert_peer(&PeerRecord {
        identity: owner,
        node_id: Some(NodeId([62u8; 32])),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        device_id: None,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    })
    .unwrap();

    let msg = SystemStateBackupMsg {
        v: 1,
        encrypted_blob: vec![],
        timestamp: now,
    };

    processor
        .handle_system_state_backup(owner, msg)
        .await
        .expect("empty blob should return Ok");

    // Empty blob must not be stored.
    let stored = db.get_system_state_blob(&owner).unwrap();
    assert!(stored.is_none(), "empty blob should not be stored");
}

// ─── handle_system_state_request ──────────────────────────────────────────────

#[tokio::test]
async fn handle_system_state_ack_logs_without_error() {
    use syncback_core::messages::SystemStateAckMsg;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let peer = make_identity(63);

    // Both stored=true and stored=false should be handled without panic.
    processor.handle_system_state_ack(
        peer,
        SystemStateAckMsg {
            v: 1,
            stored: true,
            timestamp: Timestamp::now(),
        },
    );
    processor.handle_system_state_ack(
        peer,
        SystemStateAckMsg {
            v: 1,
            stored: false,
            timestamp: Timestamp::now(),
        },
    );
}

// ─── handle_peer_discovery_response ───────────────────────────────────────────

#[tokio::test]
async fn handle_peer_discovery_response_logs_without_error() {
    use syncback_core::messages::{DiscoveredPeer, PeerDiscoveryResponseMsg};
    use syncback_core::types::NodeId;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let peer = make_identity(70);
    let resp = PeerDiscoveryResponseMsg {
        v: 1,
        peers: vec![
            DiscoveredPeer {
                identity_pub: make_identity(71),
                node_id: NodeId([71u8; 32]),
                addrs: vec![],
            },
            DiscoveredPeer {
                identity_pub: make_identity(72),
                node_id: NodeId([72u8; 32]),
                addrs: vec![],
            },
        ],
        timestamp: Timestamp::now(),
    };

    // Should complete without panic.
    processor.handle_peer_discovery_response(peer, resp).await;
}

// ─── handle_pos_response ──────────────────────────────────────────────────────

#[tokio::test]
async fn handle_pos_response_pass_records_trust_and_updates_placement() {
    use std::collections::HashMap;
    use syncback_core::constants::INITIAL_TRUST_P;
    use syncback_core::erasure::ErasureEncoder;
    use syncback_core::messages::PosResponseMsg;
    use syncback_core::pos::VerifyOutcome;
    use syncback_core::types::{ErasureParams, SourceBlockRecord, SourceBlockStatus, SourceBlockType};

    use super::current_week_number_scaled;
    use crate::daemon::scheduler::{PendingChallenge, PendingChallenges};

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();

    let holder_id = make_identity(10);
    let block_id = make_block_id(20);
    let challenge_id = [0xAAu8; 16];

    // Build pending challenges map with one entry.
    let pending_map: HashMap<_, _> = [(
        (block_id, holder_id),
        PendingChallenge {
            source_block_id: block_id,
            holder_id,
            esi: 0,
            issued_at: Timestamp::now(),
            challenge_id,
        },
    )]
    .into_iter()
    .collect();
    let pending: PendingChallenges =
        std::sync::Arc::new(tokio::sync::Mutex::new(pending_map));

    let (processor, _repair_rx, _relay_rx) =
        make_processor_with_pending(db.clone(), &holdings_dir, &source_dir, pending).await;

    // Insert PeerRecord with initial trust.
    db.upsert_peer(&make_peer_record(holder_id)).unwrap();

    // Use legacy erasure params (n=None, overhead=None → ErasureParams::compute(65535, 0.0)).
    let params = ErasureParams::compute(65_535, 0.0);

    // Insert SourceBlockRecord.
    db.upsert_source_block(&SourceBlockRecord {
        block_id,
        k: 1,
        t: 65_535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp::now(),
        encrypted_size: Some(65_535),
        n: None,
        overhead: None,
    })
    .unwrap();

    // Insert Alive placement covering ESI 0.
    let placement = make_symbol_placement(block_id, holder_id, vec![(0, 1)], PlacementStatus::Alive);
    db.upsert_placement(&placement).unwrap();

    // Write source block file (exactly k*t = 65535 bytes).
    let source_data: Vec<u8> = (0u8..=255).cycle().take(65_535).collect();
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_src_dir = source_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_src_dir).unwrap();
    std::fs::write(block_src_dir.join("block.bin"), &source_data).unwrap();

    // Encode the valid bound symbol.
    let encoder = syncback_core::erasure::RaptorQEncoder::new();
    let symbols = encoder
        .encode(&source_data, &params, 0, 1, &block_id, &holder_id)
        .expect("encode failed");
    let bound_data = symbols[0].data.clone();

    let response = PosResponseMsg {
        v: 1,
        challenge_id,
        esi: 0,
        data: bound_data,
        timestamp: Timestamp::now(),
    };

    let outcome = processor
        .handle_pos_response(holder_id, response)
        .await
        .expect("handle_pos_response failed");

    assert_eq!(outcome, VerifyOutcome::Pass, "outcome must be Pass");

    // Placement last_verified is set.
    let updated_placement = db.get_placement(&block_id, &holder_id).unwrap().unwrap();
    assert!(
        updated_placement.last_verified.is_some(),
        "last_verified must be Some after Pass"
    );

    // PoS weekly: challenged=1, passed=1.
    let week = current_week_number_scaled(1);
    let weekly = db.get_pos_weekly(&holder_id, week).unwrap();
    assert!(weekly.is_some(), "pos_weekly entry must exist");
    let weekly = weekly.unwrap();
    assert_eq!(weekly.challenged, 1, "challenged must be 1");
    assert_eq!(weekly.passed, 1, "passed must be 1");

    // Trust P must have been recalculated upward.
    let peer = db.get_peer(&holder_id).unwrap().unwrap();
    assert!(
        peer.trust_p > INITIAL_TRUST_P,
        "trust_p={} must exceed INITIAL_TRUST_P={} after Pass",
        peer.trust_p,
        INITIAL_TRUST_P,
    );
}

#[tokio::test]
async fn handle_pos_response_fail_marks_lost_and_triggers_repair() {
    use std::collections::HashMap;
    use syncback_core::erasure::ErasureEncoder;
    use syncback_core::messages::PosResponseMsg;
    use syncback_core::pos::VerifyOutcome;
    use syncback_core::types::{ErasureParams, SourceBlockRecord, SourceBlockStatus, SourceBlockType};

    use crate::daemon::repair::RepairTrigger;
    use crate::daemon::scheduler::{PendingChallenge, PendingChallenges};

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();

    let holder_id = make_identity(11);
    let block_id = make_block_id(21);
    let challenge_id = [0xBBu8; 16];

    let pending_map: HashMap<_, _> = [(
        (block_id, holder_id),
        PendingChallenge {
            source_block_id: block_id,
            holder_id,
            esi: 0,
            issued_at: Timestamp::now(),
            challenge_id,
        },
    )]
    .into_iter()
    .collect();
    let pending: PendingChallenges =
        std::sync::Arc::new(tokio::sync::Mutex::new(pending_map));

    let (processor, mut repair_rx, _relay_rx) =
        make_processor_with_pending(db.clone(), &holdings_dir, &source_dir, pending).await;

    // Insert PeerRecord.
    db.upsert_peer(&make_peer_record(holder_id)).unwrap();

    let params = ErasureParams::compute(65_535, 0.0);

    db.upsert_source_block(&SourceBlockRecord {
        block_id,
        k: 1,
        t: 65_535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp::now(),
        encrypted_size: Some(65_535),
        n: None,
        overhead: None,
    })
    .unwrap();

    let placement = make_symbol_placement(block_id, holder_id, vec![(0, 1)], PlacementStatus::Alive);
    db.upsert_placement(&placement).unwrap();

    let source_data: Vec<u8> = (0u8..=255).cycle().take(65_535).collect();
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_src_dir = source_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_src_dir).unwrap();
    std::fs::write(block_src_dir.join("block.bin"), &source_data).unwrap();

    // Encode valid symbol then corrupt it.
    let encoder = syncback_core::erasure::RaptorQEncoder::new();
    let symbols = encoder
        .encode(&source_data, &params, 0, 1, &block_id, &holder_id)
        .expect("encode failed");
    let mut corrupt_data = symbols[0].data.clone();
    corrupt_data[0] ^= 0xFF;

    let response = PosResponseMsg {
        v: 1,
        challenge_id,
        esi: 0,
        data: corrupt_data,
        timestamp: Timestamp::now(),
    };

    let outcome = processor
        .handle_pos_response(holder_id, response)
        .await
        .expect("handle_pos_response failed");

    assert!(
        matches!(outcome, VerifyOutcome::Fail { esi: 0 }),
        "outcome must be Fail{{esi:0}}, got {outcome:?}"
    );

    // Placement must be Lost.
    let updated_placement = db.get_placement(&block_id, &holder_id).unwrap().unwrap();
    assert_eq!(
        updated_placement.status,
        PlacementStatus::Lost,
        "placement must be Lost after Fail"
    );

    // PoS weekly: challenged=1, passed=0.
    use super::current_week_number_scaled;
    let week = current_week_number_scaled(1);
    let weekly = db.get_pos_weekly(&holder_id, week).unwrap();
    assert!(weekly.is_some(), "pos_weekly entry must exist");
    let weekly = weekly.unwrap();
    assert_eq!(weekly.challenged, 1, "challenged must be 1");
    assert_eq!(weekly.passed, 0, "passed must be 0");

    // Repair trigger must be sent.
    let trigger = repair_rx
        .try_recv()
        .expect("RepairTrigger must be sent after Fail");
    match trigger {
        RepairTrigger::RepairNow {
            block_id: bid,
            holder_id: hid,
        } => {
            assert_eq!(bid, block_id, "RepairNow block_id mismatch");
            assert_eq!(hid, holder_id, "RepairNow holder_id mismatch");
        }
        other => panic!("expected RepairNow, got {other:?}"),
    }
}

// ─── handle_delete tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn handle_delete_marks_holding_for_deletion() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0xDD);

    // Insert an Active holding.
    let holding = HoldingRecord {
        source_block_id: block_id,
        owner_id,
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes: 1000,
        status: HoldingStatus::Active,
        received_at: Timestamp(100),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();

    // Build a valid delete message.
    let delete_msg = syncback_core::messages::build_delete_msg(block_id, Timestamp::now(), &owner_key);
    processor.handle_delete(owner_id, delete_msg).await.unwrap();

    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::MarkedForDelete);
    assert!(updated.delete_requested_at.is_some());
}

#[tokio::test]
async fn handle_delete_ignores_non_active_holding() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0xDE);

    // Insert a MarkedForDelete holding.
    let holding = HoldingRecord {
        source_block_id: block_id,
        owner_id,
        esi_ranges: vec![(0, 5)],
        importance: 0.5,
        total_bytes: 500,
        status: HoldingStatus::MarkedForDelete,
        received_at: Timestamp(100),
        delete_requested_at: Some(Timestamp(200)),
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();

    let delete_msg = syncback_core::messages::build_delete_msg(block_id, Timestamp::now(), &owner_key);
    processor.handle_delete(owner_id, delete_msg).await.unwrap();

    // Status should not change.
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::MarkedForDelete);
}

#[tokio::test]
async fn handle_delete_ignores_no_holding() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0xDF);

    // No holding in DB — should not panic.
    let delete_msg = syncback_core::messages::build_delete_msg(block_id, Timestamp::now(), &owner_key);
    processor.handle_delete(owner_id, delete_msg).await.unwrap();
}

#[tokio::test]
async fn handle_delete_rejects_invalid_signature() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let wrong_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let block_id = make_block_id(0xE0);

    let holding = HoldingRecord {
        source_block_id: block_id,
        owner_id,
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes: 1000,
        status: HoldingStatus::Active,
        received_at: Timestamp(100),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();

    // Sign with wrong key.
    let delete_msg = syncback_core::messages::build_delete_msg(block_id, Timestamp::now(), &wrong_key);
    processor.handle_delete(owner_id, delete_msg).await.unwrap();

    // Holding should remain Active (bad sig rejected silently).
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::Active);
}

// ─── handle_cancel_delete tests ───────────────────────────────────────────────

#[tokio::test]
async fn handle_cancel_delete_reverts_to_active() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0xE1);

    let holding = HoldingRecord {
        source_block_id: block_id,
        owner_id,
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes: 1000,
        status: HoldingStatus::MarkedForDelete,
        received_at: Timestamp(100),
        delete_requested_at: Some(Timestamp(200)),
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();

    let cancel_msg = syncback_core::messages::build_cancel_delete_msg(block_id, Timestamp::now(), &owner_key);
    processor.handle_cancel_delete(owner_id, cancel_msg).await.unwrap();

    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::Active);
    assert!(updated.delete_requested_at.is_none());
}

#[tokio::test]
async fn handle_cancel_delete_ignores_active_holding() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0xE2);

    let holding = HoldingRecord {
        source_block_id: block_id,
        owner_id,
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes: 1000,
        status: HoldingStatus::Active,
        received_at: Timestamp(100),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();

    let cancel_msg = syncback_core::messages::build_cancel_delete_msg(block_id, Timestamp::now(), &owner_key);
    processor.handle_cancel_delete(owner_id, cancel_msg).await.unwrap();

    // Should remain Active (no-op).
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::Active);
}

#[tokio::test]
async fn handle_cancel_delete_rejects_bad_sig() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let wrong_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let block_id = make_block_id(0xE3);

    let holding = HoldingRecord {
        source_block_id: block_id,
        owner_id,
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes: 1000,
        status: HoldingStatus::MarkedForDelete,
        received_at: Timestamp(100),
        delete_requested_at: Some(Timestamp(200)),
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();

    let cancel_msg = syncback_core::messages::build_cancel_delete_msg(block_id, Timestamp::now(), &wrong_key);
    processor.handle_cancel_delete(owner_id, cancel_msg).await.unwrap();

    // Should remain MarkedForDelete (bad sig).
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::MarkedForDelete);
}

// ─── handle_symbol_drop_notice test ───────────────────────────────────────────

#[tokio::test]
async fn handle_symbol_drop_notice_does_not_panic() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let holder = make_identity(0xF0);
    let notice = SymbolDropNoticeMsg {
        v: 1,
        source_block_id: make_block_id(0xF0),
        esi_ranges: vec![(0, 100)],
        deadline: Timestamp(Timestamp::now().0 + 604_800),
        timestamp: Timestamp::now(),
    };

    // Should not panic — just logs.
    processor.handle_symbol_drop_notice(holder, notice);
}

// ─── dispatch_relay tests for new message types ───────────────────────────────

#[tokio::test]
async fn dispatch_relay_pos_challenge_sends_response_via_board() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();

    // Build processor manually to keep relay_post_rx alive.
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let (relay_sync_tx, _relay_sync_rx) = mpsc::channel::<SyncTrigger>(16);
    let master_key = syncback_core::cluster::derive_master_key(&[42u8; 64]).unwrap();
    let own_identity = syncback_core::cluster::master_identity(&master_key);
    let device_id = DeviceId([1u8; 16]);
    let now = Timestamp::now();
    let cert = syncback_core::cluster::issue_device_certificate(&master_key, device_id, [0u8; 32], now);
    let cluster_state = syncback_core::cluster::ClusterState::init(db.clone(), own_identity, cert, now, now).unwrap();
    let cluster_state = Arc::new(std::sync::Mutex::new(cluster_state));
    let cluster_sync = Arc::new(ClusterSyncManager::new(
        db.clone(),
        ClusterSyncConfig { our_device_id: device_id, batch_size: 1000 },
        cluster_state,
    ));
    let encoder: Arc<dyn syncback_core::erasure::ErasureEncoder> =
        Arc::new(syncback_core::erasure::RaptorQEncoder::new());
    let network = make_network().await;
    let (backup_event_tx, _backup_event_rx) =
        mpsc::channel::<crate::daemon::backup::BackupEvent>(16);
    let pending: crate::daemon::scheduler::PendingChallenges =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let (relay_post_tx, mut relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let processor = Processor::new(
        db.clone(), own_identity, repair_tx, cluster_sync, encoder,
        holdings_dir.path().to_path_buf(), source_dir.path().to_path_buf(),
        network, relay_sync_tx, u64::MAX, u64::MAX,
        holdings_dir.path().to_path_buf(), 0,
        backup_event_tx, 1,
        pending, relay_post_tx,
    );

    // Create a symbol file so PoS can respond.
    let block_id = make_block_id(0xA1);
    let block_hex = syncback_core::types::hex_encode(&block_id.0);
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();
    std::fs::write(block_dir.join("42.bin"), b"test_symbol_data").unwrap();

    // Build a PoS challenge as an InboundMessage.
    let challenger = make_identity(0xB1);
    let challenge = PosChallengeMsg {
        v: 1,
        challenge_id: [0xCC; 16],
        source_block_id: block_id,
        esi: 42,
        timestamp: now,
    };
    let payload = syncback_core::messages::to_cbor(&challenge).unwrap();
    let relay_msg = InboundMessage {
        from: challenger,
        payload,
        msg_type: "pos_challenge".to_string(),
        msg_id: [0xAA; 16],
        created_at: now,
    };

    // Dispatch the relay message.
    processor.dispatch_relay(relay_msg).await;

    // Check that a pos_response was posted to relay_post_tx.
    let post = relay_post_rx.try_recv().expect("expected a RelayPost for pos_response");
    assert_eq!(post.msg_type, "pos_response");
    assert_eq!(post.target, Some(challenger));
}

#[tokio::test]
async fn dispatch_relay_delete_marks_holding() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let source_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) =
        make_processor(db.clone(), &holdings_dir, &source_dir).await;

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0xE5);

    let holding = HoldingRecord {
        source_block_id: block_id,
        owner_id,
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes: 1000,
        status: HoldingStatus::Active,
        received_at: Timestamp(100),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();

    let delete_msg = syncback_core::messages::build_delete_msg(block_id, Timestamp::now(), &owner_key);
    let payload = syncback_core::messages::to_cbor(&delete_msg).unwrap();
    let relay_msg = InboundMessage {
        from: owner_id,
        payload,
        msg_type: "delete".to_string(),
        msg_id: [0xBB; 16],
        created_at: Timestamp::now(),
    };

    processor.dispatch_relay(relay_msg).await;

    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::MarkedForDelete);
}
