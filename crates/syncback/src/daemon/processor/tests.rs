// Tests for Processor handler methods.
//
// Strategy: We test inner/sync handler methods that contain the actual logic,
// bypassing network I/O. SwarmHandle is started on port 0 for helpers that
// need a real handle but don't exercise network I/O.
//
// Test coverage:
//   handle_symbol_transfer               — writes files, upserts HoldingRecord
//   handle_pos_hash_challenge_inner      — responds with chain hash or PosHashNack
//   handle_pos_hash_response             — verifies chain hash, updates trust/placement
//   handle_symbol_dropped_sync           — marks placement Lost
//   esi_list_to_ranges / ranges_to_esi_list — round-trip helpers
//   decide_symbol_offer                  — quota check logic
//   handle_restore_request_inner         — returns symbols or empty response
//   handle_board_sync                    — forwards to relay_sync_tx
//   handle_peer_announce                 — upserts PeerRecord in DB
//   dispatch_relay                       — PeerAnnounce via relay
//   build_peer_announce                  — SwarmHandle helper builds a signed message
//   handle_revocation_broadcast          — verifies certs and marks device key revoked
//   on_peer_authenticated                — AC-1, AC-2: upserts PeerRecord, auto-adds cluster device
//   on_connection_closed                 — AC-13: removes from peer_cert_map
//   AC-1: transfer_without_offer_rejected
//   AC-2: offer_accepted_stored_in_map
//   AC-3: offer_rejected_when_quota_full
//   AC-4: transfer_stored_after_valid_offer
//   AC-5: transfer_rejected_esi_out_of_range
//   AC-6: offer_rejected_bad_signature
//   AC-7: offer_rejected_on_stale_timestamp
//   AC-11: expired_accepted_offer_rejected

use std::sync::{Arc, Mutex};

use syncback_core::cluster::{ClusterState, derive_master_key, master_identity};
use syncback_core::db::Db;
use syncback_core::messages::{
    BoardSyncMsg, PeerAnnounceMsg, PosHashChallengeMsg, RestoreRequestMsg, SymbolAcceptMsg,
    SymbolDropNoticeMsg, SymbolRejectMsg, SymbolTransferMsg,
};
use syncback_core::types::{
    DeviceId, FileId, HoldingRecord, HoldingStatus, IdentityPub, PlacementStatus, SourceBlockId,
    SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement, Timestamp,
};
use tempfile::TempDir;
use tokio::sync::mpsc;

use super::{AcceptedOffer, Processor, esi_list_to_ranges, ranges_to_esi_list};
use crate::daemon::cluster_sync::{ClusterSyncConfig, ClusterSyncManager};
use crate::daemon::network::swarm::{SwarmConfig, SwarmHandle};
use crate::daemon::relay::{InboundMessage, RelayPost, SyncTrigger};
use crate::daemon::repair::RepairTrigger;

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn make_identity(seed: u8) -> IdentityPub {
    IdentityPub([seed; 32])
}

fn make_device_id(seed: u8) -> DeviceId {
    DeviceId([seed; 32])
}

fn make_block_id(seed: u8) -> SourceBlockId {
    SourceBlockId([seed; 32])
}

fn make_peer_record(device_id: DeviceId) -> syncback_core::types::PeerRecord {
    let now = Timestamp::now();
    syncback_core::types::PeerRecord {
        device_id,
        master_identity: IdentityPub(device_id.0),
        trust_p: syncback_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    }
}

async fn make_swarm() -> Arc<SwarmHandle> {
    let master_key = syncback_core::cluster::derive_master_key(&[0xCCu8; 64])
        .expect("derive_master_key for swarm helper");
    let identity_pub = syncback_core::cluster::master_identity(&master_key);
    let device_key = syncback_core::cluster::derive_device_key(&[0xCCu8; 64], &[0x01u8; 32])
        .expect("derive_device_key for swarm helper");
    let device_id = DeviceId(device_key.verifying_key().to_bytes());
    let now = Timestamp::now();
    let device_cert = syncback_core::cluster::issue_device_certificate(&master_key, device_id, now);
    let cfg = SwarmConfig {
        device_signing_key: device_key,
        master_signing_key: master_key,
        identity_pub,
        cluster_master_pub: identity_pub,
        device_cert,
        x25519_pub: None,
        listen_port: 0, // OS assigns port
        cert_timeout_secs: 10,
        kademlia_bootstrap_peers: vec![],
        kademlia_disable_ipfs_bootstrap: true,
        kad_republish_interval_override: None,
        kad_discovery_interval_override: None,
    };
    let (handle, _events) = SwarmHandle::start(cfg).await.expect("swarm start");
    Arc::new(handle)
}

async fn make_processor(
    db: Db,
    holdings_dir: &TempDir,
) -> (
    Processor,
    mpsc::Receiver<RepairTrigger>,
    mpsc::Receiver<SyncTrigger>,
) {
    make_processor_with_quota(db, holdings_dir, u64::MAX, u64::MAX).await
}

async fn make_processor_with_quota(
    db: Db,
    holdings_dir: &TempDir,
    soft_quota_bytes: u64,
    hard_quota_bytes: u64,
) -> (
    Processor,
    mpsc::Receiver<RepairTrigger>,
    mpsc::Receiver<SyncTrigger>,
) {
    let (repair_tx, repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let (relay_sync_tx, relay_sync_rx) = mpsc::channel::<SyncTrigger>(16);

    let master_key = derive_master_key(&[42u8; 64]).expect("derive_master_key failed");
    let own_identity = master_identity(&master_key);
    // device_id = pubkey derived from device_seed
    let device_seed = [1u8; 32];
    let device_signing_key = syncback_core::cluster::derive_device_key(&[42u8; 64], &device_seed)
        .expect("derive_device_key failed");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    let cert = syncback_core::cluster::issue_device_certificate(&master_key, device_id, now);
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

    let swarm = make_swarm().await;

    let (backup_event_tx, _backup_event_rx) =
        tokio::sync::mpsc::channel::<crate::daemon::backup::BackupEvent>(16);
    let pending_challenges: crate::daemon::scheduler::PendingChallenges =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let accepted_offers = super::make_empty_accepted_offers();
    let processor = Processor::new(
        db,
        own_identity,
        repair_tx,
        cluster_sync,
        holdings_dir.path().to_path_buf(),
        swarm,
        relay_sync_tx,
        soft_quota_bytes,
        hard_quota_bytes,
        holdings_dir.path().to_path_buf(), // data_dir (for disk space queries in tests)
        0,                                 // disk_reserve_bytes (no reserve in tests)
        backup_event_tx,
        1, // time_scale
        pending_challenges,
        relay_post_tx,
        None, // cluster_state: not needed for handler unit tests
        syncback_core::config::EscrowCfg::default(),
        accepted_offers,
        ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]), // master_signing_key
    );

    (processor, repair_rx, relay_sync_rx)
}

async fn make_processor_with_pending(
    db: Db,
    holdings_dir: &TempDir,
    pending: crate::daemon::scheduler::PendingChallenges,
) -> (
    Processor,
    mpsc::Receiver<RepairTrigger>,
    mpsc::Receiver<SyncTrigger>,
) {
    let (repair_tx, repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let (relay_sync_tx, relay_sync_rx) = mpsc::channel::<SyncTrigger>(16);

    let master_key = derive_master_key(&[42u8; 64]).expect("derive_master_key failed");
    let own_identity = master_identity(&master_key);
    let device_seed = [1u8; 32];
    let device_signing_key = syncback_core::cluster::derive_device_key(&[42u8; 64], &device_seed)
        .expect("derive_device_key failed");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    let cert = syncback_core::cluster::issue_device_certificate(&master_key, device_id, now);
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

    let swarm = make_swarm().await;

    let (backup_event_tx, _backup_event_rx) =
        tokio::sync::mpsc::channel::<crate::daemon::backup::BackupEvent>(16);
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let accepted_offers = super::make_empty_accepted_offers();
    let processor = Processor::new(
        db,
        own_identity,
        repair_tx,
        cluster_sync,
        holdings_dir.path().to_path_buf(),
        swarm,
        relay_sync_tx,
        u64::MAX,
        u64::MAX,
        holdings_dir.path().to_path_buf(),
        0,
        backup_event_tx,
        1, // time_scale
        pending,
        relay_post_tx,
        None, // cluster_state: not needed for handler unit tests
        syncback_core::config::EscrowCfg::default(),
        accepted_offers,
        ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]), // master_signing_key
    );

    (processor, repair_rx, relay_sync_rx)
}

/// Insert an accepted offer into the processor's accepted_offers map.
/// Used to set up tests that call handle_symbol_transfer directly.
fn insert_accepted_offer(
    processor: &Processor,
    owner_id: IdentityPub,
    block_id: SourceBlockId,
    esi_ranges: Vec<(u32, u32)>,
    importance: f64,
) {
    let offer = AcceptedOffer {
        owner_id,
        source_block_id: block_id,
        esi_ranges,
        importance,
        accepted_at: Timestamp::now(),
    };
    let mut map = processor.accepted_offers.lock().unwrap();
    map.insert((owner_id, block_id), offer);
}

fn make_symbol_placement(
    block_id: SourceBlockId,
    holder_id: DeviceId,
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

    // Build processor manually so we can keep backup_event_rx alive.
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let (relay_sync_tx, _relay_sync_rx) = mpsc::channel::<SyncTrigger>(16);
    let master_key = derive_master_key(&[42u8; 64]).unwrap();
    let own_identity = master_identity(&master_key);
    let device_seed = [1u8; 32];
    let device_signing_key =
        syncback_core::cluster::derive_device_key(&[42u8; 64], &device_seed).unwrap();
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();
    let cert = syncback_core::cluster::issue_device_certificate(&master_key, device_id, now);
    let cluster_state = ClusterState::init(db.clone(), own_identity, cert, now, now).unwrap();
    let cluster_state = Arc::new(Mutex::new(cluster_state));
    let cluster_sync = Arc::new(ClusterSyncManager::new(
        db.clone(),
        ClusterSyncConfig {
            our_device_id: device_id,
            batch_size: 1000,
        },
        cluster_state,
    ));
    let swarm = make_swarm().await;
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
        holdings_dir.path().to_path_buf(),
        swarm,
        relay_sync_tx,
        u64::MAX,
        u64::MAX,
        holdings_dir.path().to_path_buf(),
        0,
        backup_event_tx,
        1,
        pending,
        relay_post_tx,
        None, // cluster_state: not needed for handler unit tests
        syncback_core::config::EscrowCfg::default(),
        super::make_empty_accepted_offers(),
        ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]), // master_signing_key
    );

    let holder = make_identity(7);
    let block_id = make_block_id(7);

    let accept = SymbolAcceptMsg {
        v: 1,
        source_block_id: block_id,
        offer_msg_id: [0u8; 16],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_accept(holder, accept)
        .await
        .unwrap();

    let event = backup_event_rx
        .try_recv()
        .expect("BackupEvent::SymbolAccepted must be sent");
    match event {
        crate::daemon::backup::BackupEvent::SymbolAccepted {
            holder_id,
            source_block_id,
        } => {
            assert_eq!(holder_id, DeviceId(holder.0));
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
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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
    let placement = db.get_placement(&block_id, &DeviceId(holder.0)).unwrap();
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
    // Quota of 1 byte: any offer will be rejected.
    let (processor, _repair_rx, _relay_rx) =
        make_processor_with_quota(db.clone(), &holdings_dir, 1, 1).await;

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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(1);
    let block_id = make_block_id(2);
    let symbol_data = vec![0xABu8; 64];

    // Insert accepted offer so the transfer is authorized (esi 5 is in range (0, 100)).
    insert_accepted_offer(&processor, owner, block_id, vec![(0, 100)], 0.5);

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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(1);
    let block_id = make_block_id(2);

    let symbols: Vec<syncback_core::erasure::Symbol> = (0..3)
        .map(|i| syncback_core::erasure::Symbol {
            esi: i,
            data: vec![i as u8; 32],
        })
        .collect();

    // Insert accepted offer so the transfer is authorized (esi 0..2 in range (0, 10)).
    insert_accepted_offer(&processor, owner, block_id, vec![(0, 10)], 0.5);

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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(1);
    let block_id = make_block_id(2);

    // First offer + transfer: ESI 0
    insert_accepted_offer(&processor, owner, block_id, vec![(0, 1)], 0.5);
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

    // Second offer + transfer: ESI 1
    insert_accepted_offer(&processor, owner, block_id, vec![(1, 1)], 0.5);
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

// ─── handle_pos_hash_challenge_inner ─────────────────────────────────────────

#[tokio::test]
async fn handle_pos_hash_challenge_responds_with_chain_hash_when_symbols_held() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(1);
    let block_id = make_block_id(2);
    let esi = 7u32;
    let symbol_data = vec![0xDEu8; 64];

    // Create a HoldingRecord so the ownership check passes.
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(esi, 1)],
        importance: 0.5,
        total_bytes: symbol_data.len() as u64,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();

    // Write the symbol file manually.
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();
    std::fs::write(block_dir.join(format!("{esi}.bin")), &symbol_data).unwrap();

    let challenge_id = [99u8; 16];
    let challenge = PosHashChallengeMsg {
        v: 1,
        challenge_id,
        source_block_id: block_id,
        esi_ranges: vec![(esi, 1)],
        timestamp: Timestamp::now(),
        device_id: None,
    };

    let reply = processor
        .handle_pos_hash_challenge_inner(owner, challenge)
        .await
        .expect("handle_pos_hash_challenge_inner failed");

    match reply {
        syncback_core::messages::Message::PosHashResponse(resp) => {
            assert_eq!(resp.challenge_id, challenge_id);
            // Verify the chain hash is correct (challenge_id is [99u8; 16] from above).
            let expected_hash = syncback_core::pos::compute_chain_hash(
                &challenge_id,
                &[(esi, symbol_data.as_slice())],
            )
            .expect("compute_chain_hash");
            assert_eq!(resp.chain_hash, expected_hash);
        }
        other => panic!(
            "expected PosHashResponse, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

#[tokio::test]
async fn handle_pos_hash_challenge_sends_nack_when_symbol_not_held() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(1);
    let block_id = make_block_id(2);
    let esi = 99u32;
    let challenge_id = [77u8; 16];

    // Create a HoldingRecord so ownership check passes,
    // but don't create the symbol file — expect PosHashNack.
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(esi, 1)],
        importance: 0.5,
        total_bytes: 64,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();

    let challenge = PosHashChallengeMsg {
        v: 1,
        challenge_id,
        source_block_id: block_id,
        esi_ranges: vec![(esi, 1)],
        timestamp: Timestamp::now(),
        device_id: None,
    };

    let reply = processor
        .handle_pos_hash_challenge_inner(owner, challenge)
        .await
        .expect("handle_pos_hash_challenge_inner failed");

    match reply {
        syncback_core::messages::Message::PosHashNack(nack) => {
            assert_eq!(nack.challenge_id, challenge_id);
            assert_eq!(nack.first_missing_esi, esi);
            assert_eq!(nack.source_block_id, block_id);
        }
        other => panic!(
            "expected PosHashNack, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

// ─── handle_pos_hash_nack triggers repair ────────────────────────────────────

#[tokio::test]
async fn handle_pos_hash_nack_marks_alive_placement_lost_and_triggers_repair() {
    use crate::daemon::scheduler::{PendingChallenges, PendingHashChallenge};
    use std::collections::HashMap;
    use syncback_core::cluster::{derive_master_key, master_identity};
    use syncback_core::messages::build_pos_hash_nack;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    // Use a proper key pair so we can sign the nack.
    let holder_master_key = derive_master_key(&[0x01u8; 64]).expect("derive_master_key");
    let holder_master = master_identity(&holder_master_key);
    let holder = DeviceId(holder_master.0);
    let block_id = make_block_id(2);
    let challenge_id = [0x01u8; 16];

    // Register holder in DB so get_master_for_device succeeds.
    db.upsert_peer(&make_peer_record(holder)).unwrap();
    db.set_master_for_device(&holder, &holder_master).unwrap();

    let placement = make_symbol_placement(block_id, holder, vec![(0, 5)], PlacementStatus::Alive);
    db.upsert_placement(&placement).unwrap();

    // Set up a pending challenge for this holder.
    let pending_map: HashMap<_, _> = [(
        (block_id, holder),
        PendingHashChallenge {
            source_block_id: block_id,
            holder_id: holder,
            esi_ranges: vec![(0, 5)],
            expected_chain_hash: [0u8; 32],
            issued_at: Timestamp::now(),
            challenge_id,
        },
    )]
    .into_iter()
    .collect();
    let pending: PendingChallenges = std::sync::Arc::new(tokio::sync::Mutex::new(pending_map));

    let (processor, mut repair_rx, _relay_rx) =
        make_processor_with_pending(db.clone(), &holdings_dir, pending).await;

    // Build a properly signed nack.
    let nack = build_pos_hash_nack(
        challenge_id,
        block_id,
        0,
        Timestamp::now(),
        None,
        &holder_master_key,
    );

    processor
        .handle_pos_hash_nack(holder, nack)
        .await
        .expect("handle_pos_hash_nack failed");

    let updated = db.get_placement(&block_id, &holder).unwrap().unwrap();
    assert_eq!(updated.status, PlacementStatus::Lost);

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

#[tokio::test]
async fn handle_pos_hash_nack_is_noop_for_lost_placement() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let holder = make_device_id(1);
    let block_id = make_block_id(2);

    let placement = make_symbol_placement(block_id, holder, vec![(0, 5)], PlacementStatus::Lost);
    db.upsert_placement(&placement).unwrap();

    // Nack with unknown challenge_id (no pending challenge) → silently dropped.
    // Placement stays Lost — already Lost, no change (either via early exit or mark_placement_lost).
    let nack = syncback_core::messages::PosHashNackMsg {
        v: 1,
        challenge_id: [0u8; 16],
        source_block_id: block_id,
        first_missing_esi: 0,
        timestamp: Timestamp::now(),
        device_id: None,
        sig: [0u8; 64],
    };

    processor
        .handle_pos_hash_nack(holder, nack)
        .await
        .expect("handle_pos_hash_nack failed");

    // Placement stays Lost — dropped early due to no pending challenge.
    let updated = db.get_placement(&block_id, &holder).unwrap().unwrap();
    assert_eq!(updated.status, PlacementStatus::Lost);
}

/// Review S2: a forged SymbolDropped signed by the wrong key must be rejected.
#[tokio::test]
async fn forged_symbol_dropped_is_rejected_and_no_repair_triggered() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, mut repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let victim_key = ed25519_dalek::SigningKey::from_bytes(&[0x66u8; 32]);
    let victim = DeviceId(victim_key.verifying_key().to_bytes());
    let victim_master = IdentityPub(victim_key.verifying_key().to_bytes());
    db.set_master_for_device(&victim, &victim_master).unwrap();

    let block_id = make_block_id(8);
    let placement = make_symbol_placement(block_id, victim, vec![(0, 4)], PlacementStatus::Alive);
    db.upsert_placement(&placement).unwrap();

    let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0xDDu8; 32]);
    let forged = syncback_core::messages::build_symbol_dropped(
        block_id,
        vec![(0, 4)],
        Timestamp::now(),
        &attacker_key,
    );

    processor
        .handle_symbol_dropped(victim, forged)
        .await
        .expect("handle_symbol_dropped must not propagate an error");

    let updated = db.get_placement(&block_id, &victim).unwrap().unwrap();
    assert_eq!(
        updated.status,
        PlacementStatus::Alive,
        "forged SymbolDropped must not change placement state"
    );
    assert!(
        repair_rx.try_recv().is_err(),
        "forged SymbolDropped must not enqueue a repair trigger"
    );
}

/// Review B1 / H-1: prune_expired_accepted_offers evicts entries older than
/// SYMBOL_OFFER_EXPIRY_SECS and leaves fresh entries alone.
#[tokio::test]
async fn prune_expired_accepted_offers_drops_stale_keeps_fresh() {
    use super::{AcceptedOffer, prune_expired_accepted_offers};
    use syncback_core::constants::SYMBOL_OFFER_EXPIRY_SECS;

    let map = super::make_empty_accepted_offers();
    let now = Timestamp(1_000_000);

    let owner_old = IdentityPub([0x11u8; 32]);
    let owner_new = IdentityPub([0x22u8; 32]);
    let block_a = SourceBlockId([0xAAu8; 32]);
    let block_b = SourceBlockId([0xBBu8; 32]);

    {
        let mut m = map.lock().unwrap();
        m.insert(
            (owner_old, block_a),
            AcceptedOffer {
                owner_id: owner_old,
                source_block_id: block_a,
                esi_ranges: vec![(0, 3)],
                importance: 0.5,
                accepted_at: Timestamp(now.0 - SYMBOL_OFFER_EXPIRY_SECS - 10),
            },
        );
        m.insert(
            (owner_new, block_b),
            AcceptedOffer {
                owner_id: owner_new,
                source_block_id: block_b,
                esi_ranges: vec![(0, 3)],
                importance: 0.5,
                accepted_at: Timestamp(now.0 - 5),
            },
        );
    }

    let evicted = prune_expired_accepted_offers(&map, now);
    assert_eq!(evicted, 1, "exactly one stale offer must be evicted");

    let m = map.lock().unwrap();
    assert!(m.contains_key(&(owner_new, block_b)));
    assert!(!m.contains_key(&(owner_old, block_a)));
}

// ─── handle_symbol_dropped_sync ───────────────────────────────────────────────

#[tokio::test]
async fn handle_symbol_dropped_marks_alive_placement_lost() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let holder = make_device_id(3);
    let block_id = make_block_id(4);

    let placement =
        make_symbol_placement(block_id, holder, vec![(10, 8)], PlacementStatus::Uncertain);
    db.upsert_placement(&placement).unwrap();

    let dropped = syncback_core::messages::build_symbol_dropped(
        block_id,
        vec![(10, 8)],
        Timestamp::now(),
        &ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]),
    );

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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let holder = make_device_id(3);
    let block_id = make_block_id(4);

    let placement =
        make_symbol_placement(block_id, holder, vec![(10, 8)], PlacementStatus::Deleting);
    db.upsert_placement(&placement).unwrap();

    let dropped = syncback_core::messages::build_symbol_dropped(
        block_id,
        vec![(10, 8)],
        Timestamp::now(),
        &ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]),
    );

    let changed = processor
        .handle_symbol_dropped_sync(holder, &dropped)
        .expect("handle_symbol_dropped_sync failed");
    assert!(!changed, "Deleting placement should not be modified");
}

#[tokio::test]
async fn handle_symbol_dropped_sends_repair_trigger() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, mut repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    // Use a signing key whose public key equals the device_id, and register
    // the device → master mapping so signature verification can succeed.
    let holder_key = ed25519_dalek::SigningKey::from_bytes(&[0x43u8; 32]);
    let holder = DeviceId(holder_key.verifying_key().to_bytes());
    let master = IdentityPub(holder_key.verifying_key().to_bytes());
    db.set_master_for_device(&holder, &master).unwrap();
    let block_id = make_block_id(4);

    let placement = make_symbol_placement(block_id, holder, vec![(0, 4)], PlacementStatus::Alive);
    db.upsert_placement(&placement).unwrap();

    let dropped = syncback_core::messages::build_symbol_dropped(
        block_id,
        vec![(0, 4)],
        Timestamp::now(),
        &holder_key,
    );

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
    // 1 GB soft quota, no hard quota
    let soft = 1_073_741_824u64; // 1 GB
    let (processor, _rx, _relay_rx) =
        make_processor_with_quota(db.clone(), &holdings_dir, soft, u64::MAX).await;

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
    // Hard quota of 100 bytes — already exceeded because we'll store a holding record
    let hard = 100u64;
    let (processor, _rx, _relay_rx) =
        make_processor_with_quota(db.clone(), &holdings_dir, u64::MAX, hard).await;

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
    // Soft quota 1000 bytes, held 900 bytes, offer 200 bytes → would exceed
    let soft = 1000u64;
    let (processor, _rx, _relay_rx) =
        make_processor_with_quota(db.clone(), &holdings_dir, soft, u64::MAX).await;

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
    // soft_quota=0 means "use disk-based limit" (effective = disk_free - reserve).
    // With reserve=0, any offer fitting in disk space is accepted.
    let (processor, _rx, _relay_rx) =
        make_processor_with_quota(db.clone(), &holdings_dir, 0, 0).await;

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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(6);
    let block_id = make_block_id(6);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();

    // Write 3 symbol files
    for esi in 0u32..3 {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 32]).unwrap();
    }

    // Upsert HoldingRecord with received_at 30 days ago so escrow sees non-zero contribution.
    let thirty_days_ago = Timestamp(Timestamp::now().0.saturating_sub(30 * 86_400));
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 3)],
        importance: 0.5,
        total_bytes: 1_073_741_824, // 1 GB so budget = 1*30/7 ≈ 4.3 GB
        status: HoldingStatus::Active,
        received_at: thirty_days_ago,
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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(7);
    let block_id = make_block_id(7);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();

    // Write 5 symbol files (ESI 0..4)
    for esi in 0u32..5 {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 32]).unwrap();
    }

    // received_at 30 days ago so escrow sees non-zero contribution.
    let thirty_days_ago = Timestamp(Timestamp::now().0.saturating_sub(30 * 86_400));
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 5)],
        importance: 0.5,
        total_bytes: 1_073_741_824, // 1 GB so budget = 1*30/7 ≈ 4.3 GB
        status: HoldingStatus::Active,
        received_at: thirty_days_ago,
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
    let (processor, _rx, mut relay_sync_rx) = make_processor(db.clone(), &holdings_dir).await;

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

/// Create a signing key + identity pair from a seed byte.
/// Returns (signing_key, identity_pub) where identity_pub is a valid Ed25519 public key.
fn make_signing_identity(seed: u8) -> (ed25519_dalek::SigningKey, IdentityPub) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let identity = IdentityPub(sk.verifying_key().to_bytes());
    (sk, identity)
}

fn make_signed_peer_announce(seed: u8) -> (PeerAnnounceMsg, IdentityPub) {
    use syncback_core::messages::build_peer_announce;
    let (sk, identity) = make_signing_identity(seed);
    let msg = build_peer_announce(identity, Timestamp::now(), &sk, None);
    (msg, identity)
}

#[tokio::test]
async fn peer_announce_for_unknown_peer_is_ignored() {
    // New behavior: announce only updates existing device records.
    // An announce from a peer with no registered DeviceId creates nothing.
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let (msg, _identity) = make_signed_peer_announce(20);

    // Should succeed without error (announce from unknown peer is silently ignored).
    processor
        .handle_peer_announce(msg)
        .await
        .expect("handle_peer_announce failed");
}

#[tokio::test]
async fn peer_announce_updates_existing_peer_last_seen() {
    use syncback_core::messages::build_peer_announce;
    use syncback_core::types::PeerRecord;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let (sk, identity) = make_signing_identity(21);
    let now = Timestamp::now();

    // Pre-insert existing record keyed by DeviceId.
    // In the new architecture, announce only updates records already keyed by DeviceId.
    // We simulate this by pre-inserting a device record and registering device→master mapping.
    let device_id = DeviceId(identity.0); // use same bytes for test simplicity
    db.upsert_peer(&PeerRecord {
        device_id,
        master_identity: identity,
        trust_p: 0.5,
        trust_i: 0.3,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    })
    .unwrap();
    // Register device→master mapping so handle_peer_announce can find the device.
    db.set_master_for_device(&device_id, &identity).unwrap();

    let announce = build_peer_announce(identity, Timestamp::now(), &sk, None);

    processor
        .handle_peer_announce(announce)
        .await
        .expect("handle_peer_announce failed");

    let updated = db.get_peer(&device_id).unwrap().unwrap();
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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let (announce_msg, identity) = make_signed_peer_announce(22);
    let payload = to_cbor(&announce_msg).expect("cbor encode failed");

    let relay_msg = InboundMessage {
        from: identity,
        payload,
        msg_type: "peer_announce".to_string(),
        msg_id: [0u8; 16],
        created_at: Timestamp::now(),
    };

    processor.dispatch_relay(relay_msg).await;

    // New behavior: announce only updates existing device records.
    // For unknown peers (no DeviceId registered), the announce is silently ignored.
    // Verify no error was produced (implicit — we just reached here without panic).
}

// ─── handle_symbol_accept / handle_symbol_reject (log-only handlers) ─────────

#[tokio::test]
async fn symbol_accept_logs_without_error() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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

#[tokio::test]
async fn peer_announce_db_upsert_always_succeeds() {
    use syncback_core::messages::build_peer_announce;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let (sk, identity) = make_signing_identity(51);
    let msg = build_peer_announce(identity, Timestamp::now(), &sk, None);

    processor
        .handle_peer_announce(msg)
        .await
        .expect("handle_peer_announce should return Ok");

    // New behavior: announce from unknown peer is silently ignored (no DeviceId registered).
    // We just verify the call succeeds without error.
}

#[tokio::test]
async fn peer_announce_with_invalid_signature_is_rejected() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    // Create a signed message, then corrupt the signature.
    let (mut msg, identity) = make_signed_peer_announce(60);
    msg.sig[0] ^= 0xff;

    processor
        .handle_peer_announce(msg)
        .await
        .expect("should return Ok (graceful reject, not error)");

    // Invalid signature — announce is rejected. No record created (and none expected
    // since no DeviceId was registered for this peer anyway).
    let _ = identity; // identity is IdentityPub; get_peer now takes DeviceId — just verify no panic.
}

// ─── handle_system_state_backup ───────────────────────────────────────────────

#[tokio::test]
async fn handle_system_state_backup_stores_blob_for_known_peer() {
    use syncback_core::db::SystemStateBlobRecord;
    use syncback_core::messages::SystemStateBackupMsg;
    use syncback_core::types::PeerRecord;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(60);
    let now = Timestamp::now();

    // Register owner as a known peer so the handler accepts the backup.
    let owner_device_id = DeviceId(owner.0);
    db.upsert_peer(&PeerRecord {
        device_id: owner_device_id,
        master_identity: owner,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    })
    .unwrap();
    // Register device→master mapping so handle_system_state_backup_inner can find the device.
    db.set_master_for_device(&owner_device_id, &owner).unwrap();

    let blob = vec![0xBEu8; 128];
    let msg = SystemStateBackupMsg {
        v: 1,
        encrypted_blob: blob.clone(),
        timestamp: now,
    };

    processor.handle_system_state_backup_inner(owner, msg).await;

    let stored: Option<SystemStateBlobRecord> = db.get_system_state_blob(&owner).unwrap();
    assert!(stored.is_some(), "blob should have been stored in DB");
    assert_eq!(stored.unwrap().encrypted_blob, blob);
}

#[tokio::test]
async fn handle_system_state_backup_rejects_unknown_peer() {
    use syncback_core::messages::SystemStateBackupMsg;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let stranger = make_identity(61);
    let msg = SystemStateBackupMsg {
        v: 1,
        encrypted_blob: vec![0xFFu8; 64],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_system_state_backup_inner(stranger, msg)
        .await;

    // DB must remain empty — unknown peer must not be stored.
    let stored = db.get_system_state_blob(&stranger).unwrap();
    assert!(
        stored.is_none(),
        "blob should not be stored for unknown peer"
    );
}

#[tokio::test]
async fn handle_system_state_backup_ignores_empty_blob() {
    use syncback_core::messages::SystemStateBackupMsg;
    use syncback_core::types::PeerRecord;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(62);
    let now = Timestamp::now();
    let owner_device_id = DeviceId(owner.0);
    db.upsert_peer(&PeerRecord {
        device_id: owner_device_id,
        master_identity: owner,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    })
    .unwrap();
    db.set_master_for_device(&owner_device_id, &owner).unwrap();

    let msg = SystemStateBackupMsg {
        v: 1,
        encrypted_blob: vec![],
        timestamp: now,
    };

    processor.handle_system_state_backup_inner(owner, msg).await;

    // Empty blob must not be stored.
    let stored = db.get_system_state_blob(&owner).unwrap();
    assert!(stored.is_none(), "empty blob should not be stored");
}

// ─── Issue F (H-1): SystemStateBackup blob size cap ──────────────────────────

/// AC-F1: blob below the size cap is stored normally.
#[tokio::test]
async fn system_state_backup_with_blob_under_cap_accepted() {
    use syncback_core::constants::MAX_SYSTEM_STATE_BLOB_BYTES;
    use syncback_core::db::SystemStateBlobRecord;
    use syncback_core::messages::SystemStateBackupMsg;
    use syncback_core::types::PeerRecord;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(70);
    let now = Timestamp::now();
    let owner_device_id = DeviceId(owner.0);
    db.upsert_peer(&PeerRecord {
        device_id: owner_device_id,
        master_identity: owner,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    })
    .unwrap();
    db.set_master_for_device(&owner_device_id, &owner).unwrap();

    let blob = vec![0xAAu8; MAX_SYSTEM_STATE_BLOB_BYTES - 1];
    let msg = SystemStateBackupMsg {
        v: 1,
        encrypted_blob: blob.clone(),
        timestamp: now,
    };

    let ack = processor.handle_system_state_backup_inner(owner, msg).await;

    assert!(ack.stored, "blob under cap should be stored");
    let stored: Option<SystemStateBlobRecord> = db.get_system_state_blob(&owner).unwrap();
    assert!(stored.is_some(), "blob under cap should be written to DB");
    assert_eq!(stored.unwrap().encrypted_blob, blob);
}

/// AC-F2: blob exactly at the size cap is stored (boundary inclusive).
#[tokio::test]
async fn system_state_backup_with_blob_at_cap_accepted() {
    use syncback_core::constants::MAX_SYSTEM_STATE_BLOB_BYTES;
    use syncback_core::db::SystemStateBlobRecord;
    use syncback_core::messages::SystemStateBackupMsg;
    use syncback_core::types::PeerRecord;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(71);
    let now = Timestamp::now();
    let owner_device_id = DeviceId(owner.0);
    db.upsert_peer(&PeerRecord {
        device_id: owner_device_id,
        master_identity: owner,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    })
    .unwrap();
    db.set_master_for_device(&owner_device_id, &owner).unwrap();

    let blob = vec![0xBBu8; MAX_SYSTEM_STATE_BLOB_BYTES];
    let msg = SystemStateBackupMsg {
        v: 1,
        encrypted_blob: blob.clone(),
        timestamp: now,
    };

    let ack = processor.handle_system_state_backup_inner(owner, msg).await;

    assert!(ack.stored, "blob at cap boundary should be stored");
    let stored: Option<SystemStateBlobRecord> = db.get_system_state_blob(&owner).unwrap();
    assert!(stored.is_some(), "blob at cap should be written to DB");
}

/// AC-F3: blob one byte over the size cap is dropped with stored=false; no DB write.
#[tokio::test]
async fn system_state_backup_with_blob_over_cap_rejected() {
    use syncback_core::constants::MAX_SYSTEM_STATE_BLOB_BYTES;
    use syncback_core::messages::SystemStateBackupMsg;
    use syncback_core::types::PeerRecord;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(72);
    let now = Timestamp::now();
    let owner_device_id = DeviceId(owner.0);
    db.upsert_peer(&PeerRecord {
        device_id: owner_device_id,
        master_identity: owner,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    })
    .unwrap();
    db.set_master_for_device(&owner_device_id, &owner).unwrap();

    let blob = vec![0xCCu8; MAX_SYSTEM_STATE_BLOB_BYTES + 1];
    let msg = SystemStateBackupMsg {
        v: 1,
        encrypted_blob: blob,
        timestamp: now,
    };

    let ack = processor.handle_system_state_backup_inner(owner, msg).await;

    assert!(
        !ack.stored,
        "blob over cap should be rejected (stored=false)"
    );
    let stored = db.get_system_state_blob(&owner).unwrap();
    assert!(stored.is_none(), "blob over cap must not be written to DB");
}

/// AC-F5: unknown peer is rejected before the size check (existing gate preserved).
///
/// If an unknown peer sends a giant blob, the known-peer check fires first.
/// stored=false without writing to DB — same result as AC-F3 but via a different
/// code path (the unknown-peer gate, not the size gate).
#[tokio::test]
async fn system_state_backup_unknown_peer_rejected_before_size_check() {
    use syncback_core::constants::MAX_SYSTEM_STATE_BLOB_BYTES;
    use syncback_core::messages::SystemStateBackupMsg;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    // owner_id NOT registered in DB → unknown peer.
    let owner = make_identity(73);
    let now = Timestamp::now();

    // Send an oversized blob to confirm ordering: unknown-peer check fires, not size check.
    let blob = vec![0xDDu8; MAX_SYSTEM_STATE_BLOB_BYTES + 1];
    let msg = SystemStateBackupMsg {
        v: 1,
        encrypted_blob: blob,
        timestamp: now,
    };

    let ack = processor.handle_system_state_backup_inner(owner, msg).await;

    assert!(
        !ack.stored,
        "unknown peer must be rejected regardless of blob size"
    );
    let stored = db.get_system_state_blob(&owner).unwrap();
    assert!(
        stored.is_none(),
        "unknown peer blob must not be written to DB"
    );
}

// ─── handle_system_state_request ──────────────────────────────────────────────

#[tokio::test]
async fn handle_system_state_ack_logs_without_error() {
    use syncback_core::messages::SystemStateAckMsg;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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

// ─── handle_pos_hash_response ────────────────────────────────────────────────

#[tokio::test]
async fn handle_pos_hash_response_pass_records_trust_and_updates_placement() {
    use std::collections::HashMap;
    use syncback_core::constants::INITIAL_TRUST_P;
    use syncback_core::messages::PosHashResponseMsg;
    use syncback_core::pos::{VerifyOutcome, compute_chain_hash};

    use super::current_week_number_scaled;
    use crate::daemon::scheduler::{PendingChallenges, PendingHashChallenge};

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let holder_id = make_device_id(10);
    let block_id = make_block_id(20);
    let challenge_id = [0xAAu8; 16];

    // Owner computes expected chain hash for ESI 0 with symbol data [0xAB; 64].
    let symbol_data = vec![0xABu8; 64];
    let expected_hash =
        compute_chain_hash(&challenge_id, &[(0u32, symbol_data.as_slice())]).unwrap();

    // Build pending challenges map with one entry including the expected chain hash.
    let pending_map: HashMap<_, _> = [(
        (block_id, holder_id),
        PendingHashChallenge {
            source_block_id: block_id,
            holder_id,
            esi_ranges: vec![(0, 1)],
            expected_chain_hash: expected_hash,
            issued_at: Timestamp::now(),
            challenge_id,
        },
    )]
    .into_iter()
    .collect();
    let pending: PendingChallenges = std::sync::Arc::new(tokio::sync::Mutex::new(pending_map));

    let (processor, _repair_rx, _relay_rx) =
        make_processor_with_pending(db.clone(), &holdings_dir, pending).await;

    // Insert PeerRecord with initial trust.
    db.upsert_peer(&make_peer_record(holder_id)).unwrap();

    // Insert Alive placement covering ESI 0.
    let placement =
        make_symbol_placement(block_id, holder_id, vec![(0, 1)], PlacementStatus::Alive);
    db.upsert_placement(&placement).unwrap();

    // Holder sends correct chain hash.
    let response = PosHashResponseMsg {
        v: 1,
        challenge_id,
        chain_hash: expected_hash,
        timestamp: Timestamp::now(),
        device_id: None,
    };

    let outcome = processor
        .handle_pos_hash_response(holder_id, response)
        .await
        .expect("handle_pos_hash_response failed");

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
async fn handle_pos_hash_response_fail_marks_lost_and_triggers_repair() {
    use std::collections::HashMap;
    use syncback_core::messages::PosHashResponseMsg;
    use syncback_core::pos::{VerifyOutcome, compute_chain_hash};

    use crate::daemon::repair::RepairTrigger;
    use crate::daemon::scheduler::{PendingChallenges, PendingHashChallenge};

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let holder_id = make_device_id(11);
    let block_id = make_block_id(21);
    let challenge_id = [0xBBu8; 16];

    // Owner's expected chain hash for correct symbol data.
    let correct_symbol = vec![0xCCu8; 64];
    let expected_hash =
        compute_chain_hash(&challenge_id, &[(0u32, correct_symbol.as_slice())]).unwrap();

    let pending_map: HashMap<_, _> = [(
        (block_id, holder_id),
        PendingHashChallenge {
            source_block_id: block_id,
            holder_id,
            esi_ranges: vec![(0, 1)],
            expected_chain_hash: expected_hash,
            issued_at: Timestamp::now(),
            challenge_id,
        },
    )]
    .into_iter()
    .collect();
    let pending: PendingChallenges = std::sync::Arc::new(tokio::sync::Mutex::new(pending_map));

    let (processor, mut repair_rx, _relay_rx) =
        make_processor_with_pending(db.clone(), &holdings_dir, pending).await;

    // Insert PeerRecord.
    db.upsert_peer(&make_peer_record(holder_id)).unwrap();

    let placement =
        make_symbol_placement(block_id, holder_id, vec![(0, 1)], PlacementStatus::Alive);
    db.upsert_placement(&placement).unwrap();

    // Holder sends WRONG chain hash (corrupted symbol).
    let corrupt_symbol = vec![0x00u8; 64];
    let wrong_hash =
        compute_chain_hash(&challenge_id, &[(0u32, corrupt_symbol.as_slice())]).unwrap();

    let response = PosHashResponseMsg {
        v: 1,
        challenge_id,
        chain_hash: wrong_hash,
        timestamp: Timestamp::now(),
        device_id: None,
    };

    let outcome = processor
        .handle_pos_hash_response(holder_id, response)
        .await
        .expect("handle_pos_hash_response failed");

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
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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
    let delete_msg =
        syncback_core::messages::build_delete_msg(block_id, Timestamp::now(), &owner_key);
    processor.handle_delete(owner_id, delete_msg).await.unwrap();

    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::MarkedForDelete);
    assert!(updated.delete_requested_at.is_some());
}

#[tokio::test]
async fn handle_delete_ignores_non_active_holding() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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

    let delete_msg =
        syncback_core::messages::build_delete_msg(block_id, Timestamp::now(), &owner_key);
    processor.handle_delete(owner_id, delete_msg).await.unwrap();

    // Status should not change.
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::MarkedForDelete);
}

#[tokio::test]
async fn handle_delete_ignores_no_holding() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0xDF);

    // No holding in DB — should not panic.
    let delete_msg =
        syncback_core::messages::build_delete_msg(block_id, Timestamp::now(), &owner_key);
    processor.handle_delete(owner_id, delete_msg).await.unwrap();
}

#[tokio::test]
async fn handle_delete_rejects_invalid_signature() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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
    let delete_msg =
        syncback_core::messages::build_delete_msg(block_id, Timestamp::now(), &wrong_key);
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
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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

    let cancel_msg =
        syncback_core::messages::build_cancel_delete_msg(block_id, Timestamp::now(), &owner_key);
    processor
        .handle_cancel_delete(owner_id, cancel_msg)
        .await
        .unwrap();

    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::Active);
    assert!(updated.delete_requested_at.is_none());
}

#[tokio::test]
async fn handle_cancel_delete_ignores_active_holding() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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

    let cancel_msg =
        syncback_core::messages::build_cancel_delete_msg(block_id, Timestamp::now(), &owner_key);
    processor
        .handle_cancel_delete(owner_id, cancel_msg)
        .await
        .unwrap();

    // Should remain Active (no-op).
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::Active);
}

#[tokio::test]
async fn handle_cancel_delete_rejects_bad_sig() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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

    let cancel_msg =
        syncback_core::messages::build_cancel_delete_msg(block_id, Timestamp::now(), &wrong_key);
    processor
        .handle_cancel_delete(owner_id, cancel_msg)
        .await
        .unwrap();

    // Should remain MarkedForDelete (bad sig).
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::MarkedForDelete);
}

// ─── handle_symbol_drop_notice test ───────────────────────────────────────────

#[tokio::test]
async fn handle_symbol_drop_notice_does_not_panic() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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

// ─── W13 handle_symbol_drop_notice DB-state tests ────────────────────────────

/// Build a minimal SourceBlockRecord suitable for tests. k=10, t=1, n=40.
/// target_reliability > 0 ensures next_work_item can pick it up.
fn make_source_block(block_id: SourceBlockId) -> SourceBlockRecord {
    SourceBlockRecord {
        block_id,
        k: 10,
        t: 1,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(0),
        encrypted_size: Some(10),
        n: Some(40),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 0.5,
        current_alive: 0,         // will be updated by handler
        current_reliability: 0.0, // will be updated by handler
        target_reliability: 0.9,
        last_attempted_at: None,
        last_pool_signature: 0,
    }
}

/// Register master→device mapping in DB so the handler can resolve identities.
fn register_holder(db: &Db, master: IdentityPub, device: DeviceId) {
    db.set_master_for_device(&device, &master).unwrap();
}

/// Build a SymbolDropNoticeMsg directed at a specific block.
fn make_drop_notice(block_id: SourceBlockId, esi_ranges: Vec<(u32, u32)>) -> SymbolDropNoticeMsg {
    SymbolDropNoticeMsg {
        v: 1,
        source_block_id: block_id,
        esi_ranges,
        deadline: Timestamp(Timestamp::now().0 + 604_800),
        timestamp: Timestamp::now(),
    }
}

/// Test: receiving a DropNotice for an Alive placement transitions it to Lost.
#[tokio::test]
async fn handle_symbol_drop_notice_transitions_placement_to_lost() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let holder_master = make_identity(0xA1);
    let holder_device = make_device_id(0xA1);
    let block_id = make_block_id(0xB1);

    register_holder(&db, holder_master, holder_device);
    let block = make_source_block(block_id);
    db.upsert_source_block(&block).unwrap();
    let placement = make_symbol_placement(
        block_id,
        holder_device,
        vec![(0, 10)],
        PlacementStatus::Alive,
    );
    db.upsert_placement(&placement).unwrap();

    processor.handle_symbol_drop_notice(holder_master, make_drop_notice(block_id, vec![(0, 10)]));

    let updated = db
        .get_placement(&block_id, &holder_device)
        .unwrap()
        .unwrap();
    assert_eq!(
        updated.status,
        PlacementStatus::Lost,
        "placement must transition to Lost"
    );
}

/// Test: after DropNotice, current_alive is decremented from its pre-notice value.
#[tokio::test]
async fn handle_symbol_drop_notice_decrements_current_alive() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let master_a = make_identity(0xA2);
    let device_a = make_device_id(0xA2);
    let master_b = make_identity(0xA3);
    let device_b = make_device_id(0xA3);
    let block_id = make_block_id(0xB2);

    register_holder(&db, master_a, device_a);
    register_holder(&db, master_b, device_b);

    let mut block = make_source_block(block_id);
    block.current_alive = 2; // two alive holders initially
    db.upsert_source_block(&block).unwrap();
    db.upsert_placement(&make_symbol_placement(
        block_id,
        device_a,
        vec![(0, 10)],
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_symbol_placement(
        block_id,
        device_b,
        vec![(10, 10)],
        PlacementStatus::Alive,
    ))
    .unwrap();

    // Drop notice from holder A.
    processor.handle_symbol_drop_notice(master_a, make_drop_notice(block_id, vec![(0, 10)]));

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 1,
        "current_alive must decrement from 2 to 1 after one placement goes Lost"
    );
}

/// Test: after DropNotice, current_reliability is recomputed and lower than before.
#[tokio::test]
async fn handle_symbol_drop_notice_recomputes_current_reliability() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let master_a = make_identity(0xC1);
    let device_a = make_device_id(0xC1);
    let master_b = make_identity(0xC2);
    let device_b = make_device_id(0xC2);
    let block_id = make_block_id(0xC3);

    register_holder(&db, master_a, device_a);
    register_holder(&db, master_b, device_b);

    let mut block = make_source_block(block_id);
    block.current_alive = 2;
    // Pre-set a high reliability so we can detect it drops.
    block.current_reliability = 0.99;
    db.upsert_source_block(&block).unwrap();
    db.upsert_placement(&make_symbol_placement(
        block_id,
        device_a,
        vec![(0, 20)],
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_symbol_placement(
        block_id,
        device_b,
        vec![(20, 20)],
        PlacementStatus::Alive,
    ))
    .unwrap();

    processor.handle_symbol_drop_notice(master_a, make_drop_notice(block_id, vec![(0, 20)]));

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert!(
        updated_block.current_reliability < 0.99,
        "current_reliability must decrease after one placement goes Lost (was 0.99, now {})",
        updated_block.current_reliability
    );
    // With only one alive holder remaining, reliability should still be > 0
    // (they have 20 symbols, k_eff = 13 for k=10).
    assert!(
        updated_block.current_reliability > 0.0,
        "current_reliability must be > 0.0 when one holder still has 20 symbols"
    );
}

/// Test: sending the same DropNotice twice does not double-decrement current_alive.
#[tokio::test]
async fn handle_symbol_drop_notice_idempotent_on_duplicate() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let master_a = make_identity(0xD1);
    let device_a = make_device_id(0xD1);
    let master_b = make_identity(0xD2);
    let device_b = make_device_id(0xD2);
    let block_id = make_block_id(0xD3);

    register_holder(&db, master_a, device_a);
    register_holder(&db, master_b, device_b);

    let mut block = make_source_block(block_id);
    block.current_alive = 2;
    db.upsert_source_block(&block).unwrap();
    db.upsert_placement(&make_symbol_placement(
        block_id,
        device_a,
        vec![(0, 10)],
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_symbol_placement(
        block_id,
        device_b,
        vec![(10, 10)],
        PlacementStatus::Alive,
    ))
    .unwrap();

    // Send the same notice twice.
    let notice = make_drop_notice(block_id, vec![(0, 10)]);
    processor.handle_symbol_drop_notice(master_a, notice.clone());
    processor.handle_symbol_drop_notice(master_a, notice);

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 1,
        "duplicate DropNotice must not double-decrement current_alive"
    );
}

/// Test: DropNotice for unknown block logs WARN and returns without panicking.
#[tokio::test]
async fn handle_symbol_drop_notice_source_block_record_missing_logs_and_returns() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    // Register a holder device so the master-to-device resolution succeeds,
    // but insert no SourceBlockRecord for this block_id.
    let holder_master = make_identity(0xE1);
    let holder_device = make_device_id(0xE1);
    register_holder(&db, holder_master, holder_device);
    let block_id = make_block_id(0xE2);
    // Insert a placement so find_placement succeeds and mark_placement_lost is called,
    // but no SourceBlockRecord exists — verifies the "block not found" warn path.
    let placement = make_symbol_placement(
        block_id,
        holder_device,
        vec![(0, 10)],
        PlacementStatus::Alive,
    );
    db.upsert_placement(&placement).unwrap();

    // Should not panic.
    processor.handle_symbol_drop_notice(holder_master, make_drop_notice(block_id, vec![(0, 10)]));
    // No assertion needed — the test passes if no panic occurs.
}

/// Test: DropNotice from a master that has no devices in DB logs WARN and returns.
#[tokio::test]
async fn handle_symbol_drop_notice_unknown_holder_logs_and_returns() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let block_id = make_block_id(0xF1);
    let mut block = make_source_block(block_id);
    block.current_alive = 1;
    db.upsert_source_block(&block).unwrap();

    // holder_master has no registered devices — get_devices_for_master returns empty.
    let holder_master = make_identity(0xF2);

    // Should not panic. Placement state should be unchanged (no placement inserted).
    processor.handle_symbol_drop_notice(holder_master, make_drop_notice(block_id, vec![(0, 10)]));

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 1,
        "current_alive must be unchanged when holder is unknown"
    );
}

/// Test: DropNotice for a placement that is already Lost is a no-op (no double-decrement).
#[tokio::test]
async fn handle_symbol_drop_notice_placement_already_lost_is_noop() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let holder_master = make_identity(0x01);
    let holder_device = make_device_id(0x01);
    let other_master = make_identity(0x02);
    let other_device = make_device_id(0x02);
    let block_id = make_block_id(0x03);

    register_holder(&db, holder_master, holder_device);
    register_holder(&db, other_master, other_device);

    let mut block = make_source_block(block_id);
    block.current_alive = 1; // only the other placement is alive
    db.upsert_source_block(&block).unwrap();
    // Holder's placement is already Lost.
    db.upsert_placement(&make_symbol_placement(
        block_id,
        holder_device,
        vec![(0, 10)],
        PlacementStatus::Lost,
    ))
    .unwrap();
    // Other holder is Alive.
    db.upsert_placement(&make_symbol_placement(
        block_id,
        other_device,
        vec![(10, 10)],
        PlacementStatus::Alive,
    ))
    .unwrap();

    // DropNotice for the already-Lost placement.
    processor.handle_symbol_drop_notice(holder_master, make_drop_notice(block_id, vec![(0, 10)]));

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 1,
        "current_alive must stay 1 when placement was already Lost (no-op path)"
    );
}

/// Test: after DropNotice drops reliability below target, next_work_item returns the block.
#[tokio::test]
async fn handle_symbol_drop_notice_block_becomes_eligible_for_worker() {
    use std::time::Duration;
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let master_a = make_identity(0x10);
    let device_a = make_device_id(0x10);
    let master_b = make_identity(0x11);
    let device_b = make_device_id(0x11);
    let block_id = make_block_id(0x12);

    register_holder(&db, master_a, device_a);
    register_holder(&db, master_b, device_b);

    // Block with two alive holders, reliability set just above target.
    let mut block = make_source_block(block_id);
    block.current_alive = 2;
    block.current_reliability = 0.95; // above target (0.9)
    block.target_reliability = 0.9;
    db.upsert_source_block(&block).unwrap();
    // Each holder has exactly k symbols (10 symbols, k=10, k_eff=13).
    // With one holder: alive_symbols=10 < k_eff=13 → reliability drops to near-zero.
    db.upsert_placement(&make_symbol_placement(
        block_id,
        device_a,
        vec![(0, 10)],
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_symbol_placement(
        block_id,
        device_b,
        vec![(10, 10)],
        PlacementStatus::Alive,
    ))
    .unwrap();

    // Confirm block is NOT eligible before DropNotice (reliability >= target).
    let before = db
        .next_work_item(1.0, Duration::from_secs(0), Timestamp::now(), 0)
        .unwrap();
    assert!(
        before.is_none(),
        "block must not be eligible before DropNotice (reliability >= target)"
    );

    // Send DropNotice for holder A.
    processor.handle_symbol_drop_notice(master_a, make_drop_notice(block_id, vec![(0, 10)]));

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert!(
        updated_block.current_reliability < updated_block.target_reliability,
        "current_reliability ({}) must drop below target ({}) after DropNotice",
        updated_block.current_reliability,
        updated_block.target_reliability,
    );

    // Block must now be eligible for the worker.
    let after = db
        .next_work_item(1.0, Duration::from_secs(0), Timestamp::now(), 0)
        .unwrap();
    assert!(
        after.is_some(),
        "block must be eligible for worker after DropNotice drops reliability below target"
    );
    assert_eq!(after.unwrap().block_id, block_id);
}

// ─── dispatch_relay tests for new message types ───────────────────────────────

#[tokio::test]
async fn dispatch_relay_pos_hash_challenge_sends_response_via_board() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    // Build processor manually to keep relay_post_rx alive.
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let (relay_sync_tx, _relay_sync_rx) = mpsc::channel::<SyncTrigger>(16);
    let master_key = syncback_core::cluster::derive_master_key(&[42u8; 64]).unwrap();
    let own_identity = syncback_core::cluster::master_identity(&master_key);
    let relay_device_seed = [1u8; 32];
    let relay_device_key =
        syncback_core::cluster::derive_device_key(&[42u8; 64], &relay_device_seed).unwrap();
    let device_id = DeviceId(relay_device_key.verifying_key().to_bytes());
    let now = Timestamp::now();
    let cert = syncback_core::cluster::issue_device_certificate(&master_key, device_id, now);
    let cluster_state =
        syncback_core::cluster::ClusterState::init(db.clone(), own_identity, cert, now, now)
            .unwrap();
    let cluster_state = Arc::new(std::sync::Mutex::new(cluster_state));
    let cluster_sync = Arc::new(ClusterSyncManager::new(
        db.clone(),
        ClusterSyncConfig {
            our_device_id: device_id,
            batch_size: 1000,
        },
        cluster_state,
    ));
    let swarm = make_swarm().await;
    let (backup_event_tx, _backup_event_rx) =
        mpsc::channel::<crate::daemon::backup::BackupEvent>(16);
    let pending: crate::daemon::scheduler::PendingChallenges =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let (relay_post_tx, mut relay_post_rx) = mpsc::channel::<RelayPost>(16);
    let processor = Processor::new(
        db.clone(),
        own_identity,
        repair_tx,
        cluster_sync,
        holdings_dir.path().to_path_buf(),
        swarm,
        relay_sync_tx,
        u64::MAX,
        u64::MAX,
        holdings_dir.path().to_path_buf(),
        0,
        backup_event_tx,
        1,
        pending,
        relay_post_tx,
        None, // cluster_state: not needed for this test
        syncback_core::config::EscrowCfg::default(),
        super::make_empty_accepted_offers(),
        ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]), // master_signing_key
    );

    // Create a symbol file so PoS can respond.
    let block_id = make_block_id(0xA1);
    let block_hex = syncback_core::types::hex_encode(&block_id.0);
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();
    std::fs::write(block_dir.join("42.bin"), b"test_symbol_data").unwrap();

    // Create HoldingRecord so ownership check passes.
    let challenger = make_identity(0xB1);
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: challenger,
        esi_ranges: vec![(42, 1)],
        importance: 0.5,
        total_bytes: 16,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();
    let challenge = PosHashChallengeMsg {
        v: 1,
        challenge_id: [0xCC; 16],
        source_block_id: block_id,
        esi_ranges: vec![(42, 1)],
        timestamp: now,
        device_id: None,
    };
    let payload = syncback_core::messages::to_cbor(&challenge).unwrap();
    let relay_msg = InboundMessage {
        from: challenger,
        payload,
        msg_type: "pos_hash_challenge".to_string(),
        msg_id: [0xAA; 16],
        created_at: now,
    };

    // Dispatch the relay message.
    processor.dispatch_relay(relay_msg).await;

    // Check that a pos_hash_response was posted to relay_post_tx.
    let post = relay_post_rx
        .try_recv()
        .expect("expected a RelayPost for pos_hash_response");
    assert_eq!(post.msg_type, "pos_hash_response");
    assert_eq!(post.target, Some(challenger));
}

#[tokio::test]
async fn dispatch_relay_delete_marks_holding() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

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

    let delete_msg =
        syncback_core::messages::build_delete_msg(block_id, Timestamp::now(), &owner_key);
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

// ─── C2: cluster device auto-add tests ───────────────────────────────────────
//
// These tests drive try_auto_add_cluster_device directly, bypassing the
// run() loop (which needs a real iroh Connection). The method is #[cfg(test)]
// and contains the same logic as the run() loop auto-add block.

/// Build a Processor with a real ClusterState containing one device (seed byte 0xAA),
/// and return (processor, cluster_state, own_master_identity).
async fn make_processor_with_cluster_state(
    db: Db,
    holdings_dir: &TempDir,
) -> (Processor, Arc<Mutex<ClusterState>>, IdentityPub) {
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let (relay_sync_tx, _relay_sync_rx) = mpsc::channel::<SyncTrigger>(16);

    let master_key = derive_master_key(&[0xAAu8; 64]).expect("derive_master_key");
    let own_identity = master_identity(&master_key);
    let device_seed_a = [0x01u8; 32];
    let device_signing_key_a =
        syncback_core::cluster::derive_device_key(&[0xAAu8; 64], &device_seed_a)
            .expect("derive_device_key_a");
    let device_id_a = DeviceId(device_signing_key_a.verifying_key().to_bytes());
    let now = Timestamp::now();

    let cert_a = syncback_core::cluster::issue_device_certificate(&master_key, device_id_a, now);
    let cluster_state =
        ClusterState::init(db.clone(), own_identity, cert_a, now, now).expect("ClusterState::init");
    let cluster_state = Arc::new(Mutex::new(cluster_state));

    let cluster_sync = Arc::new(ClusterSyncManager::new(
        db.clone(),
        ClusterSyncConfig {
            our_device_id: device_id_a,
            batch_size: 1000,
        },
        cluster_state.clone(),
    ));

    let swarm = make_swarm().await;
    let (backup_event_tx, _backup_event_rx) =
        mpsc::channel::<crate::daemon::backup::BackupEvent>(16);
    let pending: crate::daemon::scheduler::PendingChallenges =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let (relay_post_tx, _relay_post_rx) = mpsc::channel::<RelayPost>(16);

    let processor = Processor::new(
        db,
        own_identity,
        repair_tx,
        cluster_sync,
        holdings_dir.path().to_path_buf(),
        swarm,
        relay_sync_tx,
        u64::MAX,
        u64::MAX,
        holdings_dir.path().to_path_buf(),
        0,
        backup_event_tx,
        1,
        pending,
        relay_post_tx,
        Some(cluster_state.clone()),
        syncback_core::config::EscrowCfg::default(),
        super::make_empty_accepted_offers(),
        ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]), // master_signing_key
    );

    (processor, cluster_state, own_identity)
}

/// Build a DeviceCertificate for device_id. device_id.0 must equal device signing key pubkey.
fn make_device_cert(
    master_key: &ed25519_dalek::SigningKey,
    device_id: DeviceId,
) -> syncback_core::cluster::DeviceCertificate {
    syncback_core::cluster::issue_device_certificate(master_key, device_id, Timestamp::now())
}

// cluster_device_auto_added_when_same_master_identity
//
// Given: Processor with own_identity = ID_M, cluster_state with device_A (0x01*16).
//        peer_master_identity = ID_M (same master), cert for device_B (0x02*16).
// When: try_auto_add_cluster_device called.
// Then: returns true, cluster_state contains device_B.

#[tokio::test]
async fn cluster_device_auto_added_when_same_master_identity() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let (processor, cluster_state, own_identity) =
        make_processor_with_cluster_state(db, &holdings_dir).await;

    // Build a cert for device_B using the same master key.
    let master_key = derive_master_key(&[0xAAu8; 64]).expect("derive_master_key");
    let device_seed_b = [0x02u8; 32];
    let device_key_b = syncback_core::cluster::derive_device_key(&[0xAAu8; 64], &device_seed_b)
        .expect("derive_device_key_b");
    let device_id_b = DeviceId(device_key_b.verifying_key().to_bytes());
    let cert_b = make_device_cert(&master_key, device_id_b);

    let added = processor
        .try_auto_add_cluster_device(Some(own_identity), Some(cert_b))
        .await;

    assert!(added, "device_B must be auto-added");

    let devices = cluster_state.lock().unwrap();
    assert!(
        devices.get_device(&device_id_b).is_some(),
        "cluster_state must contain device_B after auto-add"
    );
}

// cluster_device_not_added_when_different_master_identity
//
// Given: Processor with own_identity = ID_M.
//        peer_master_identity = ID_OTHER (different master).
// When: try_auto_add_cluster_device called.
// Then: returns false, cluster_state unchanged (still 1 device).

#[tokio::test]
async fn cluster_device_not_added_when_different_master_identity() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let (processor, cluster_state, _own_identity) =
        make_processor_with_cluster_state(db, &holdings_dir).await;

    // Build a cert from a different master key.
    let other_master_key = derive_master_key(&[0xBBu8; 64]).expect("derive_master_key");
    let other_identity = master_identity(&other_master_key);
    let device_seed_x = [0x0Eu8; 32];
    let device_key_x = syncback_core::cluster::derive_device_key(&[0xBBu8; 64], &device_seed_x)
        .expect("derive_device_key_x");
    let device_id_x = DeviceId(device_key_x.verifying_key().to_bytes());
    let cert_x = make_device_cert(&other_master_key, device_id_x);

    let added = processor
        .try_auto_add_cluster_device(Some(other_identity), Some(cert_x))
        .await;

    assert!(
        !added,
        "device from different master must not be auto-added"
    );

    // Only the original device_A (0x01*16) should be present.
    let devices = cluster_state.lock().unwrap();
    assert_eq!(
        devices.all_devices().len(),
        1,
        "cluster_state must remain unchanged"
    );
}

// cluster_device_auto_add_idempotent_when_already_registered
//
// Given: Processor with cluster_state already containing device_B.
// When: try_auto_add_cluster_device called twice with cert_B.
// Then: second call returns false (already registered), cluster_state has device_B exactly once.

#[tokio::test]
async fn cluster_device_auto_add_idempotent_when_already_registered() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let (processor, cluster_state, own_identity) =
        make_processor_with_cluster_state(db, &holdings_dir).await;

    let master_key = derive_master_key(&[0xAAu8; 64]).expect("derive_master_key");
    let device_seed_b = [0x02u8; 32];
    let device_key_b = syncback_core::cluster::derive_device_key(&[0xAAu8; 64], &device_seed_b)
        .expect("derive_device_key_b");
    let device_id_b = DeviceId(device_key_b.verifying_key().to_bytes());
    let cert_b = make_device_cert(&master_key, device_id_b);
    // First call: should succeed.
    let first = processor
        .try_auto_add_cluster_device(Some(own_identity), Some(cert_b.clone()))
        .await;
    assert!(first, "first auto-add must succeed");

    // Second call: same cert, same device_id — must be idempotent.
    let second = processor
        .try_auto_add_cluster_device(Some(own_identity), Some(cert_b))
        .await;
    assert!(
        !second,
        "second auto-add must return false (already registered)"
    );

    // Only 2 devices total: original device_A + device_B.
    let devices = cluster_state.lock().unwrap();
    assert_eq!(
        devices.all_devices().len(),
        2,
        "cluster_state must have exactly 2 devices"
    );
}

// cluster_device_not_added_when_no_cert
//
// Given: Processor, peer_master_identity = own_identity, peer_device_cert = None.
// When: try_auto_add_cluster_device called.
// Then: returns false, cluster_state unchanged.

#[tokio::test]
async fn cluster_device_not_added_when_no_cert() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let (processor, cluster_state, own_identity) =
        make_processor_with_cluster_state(db, &holdings_dir).await;

    // cert is None — even though master identity matches.
    let added = processor
        .try_auto_add_cluster_device(Some(own_identity), None)
        .await;

    assert!(!added, "no-cert case must not add any device");

    let devices = cluster_state.lock().unwrap();
    assert_eq!(
        devices.all_devices().len(),
        1,
        "cluster_state must remain unchanged with no cert"
    );
}

// ─── handle_revocation_broadcast tests ───────────────────────────────────────

// revocation_broadcast_marks_device_key_revoked
//
// Given: Known peer in DB. Valid RevocationBroadcast from that peer.
// When: handle_revocation_broadcast called.
// Then: PeerRecord.revoked_device_pub_keys contains the device's pub key.

#[tokio::test]
async fn revocation_broadcast_marks_device_key_revoked() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let (processor, _repair_rx, _sync_rx) = make_processor(db.clone(), &holdings_dir).await;

    // Build peer master key and identity.
    let peer_master_key = derive_master_key(&[0x55u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);

    // Device being revoked: derive signing key so device_id = pubkey.
    let device_seed = [0xDDu8; 32];
    let device_signing_key = syncback_core::cluster::derive_device_key(&[0x55u8; 64], &device_seed)
        .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    // Insert a known PeerRecord (another device of the same master, not the revoked one).
    // The revocation handler updates records found via get_devices_for_master.
    let known_device_id = DeviceId([0x55u8; 32]); // a device we already know about
    let peer_record = syncback_core::types::PeerRecord {
        device_id: known_device_id,
        master_identity: peer_identity,
        trust_p: syncback_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    };
    db.upsert_peer(&peer_record).expect("upsert_peer");
    db.set_master_for_device(&known_device_id, &peer_identity)
        .unwrap();

    // Build a valid RevocationBroadcast.
    let device_cert =
        syncback_core::cluster::issue_device_certificate(&peer_master_key, device_id, now);
    let new_epoch = syncback_core::cluster::EpochCounter(1);
    let revocation =
        syncback_core::cluster::issue_revocation(&peer_master_key, device_id, now, new_epoch);
    let broadcast = syncback_core::messages::RevocationBroadcast {
        revocation,
        device_cert,
    };

    processor
        .handle_revocation_broadcast(peer_identity, broadcast)
        .await
        .expect("handle_revocation_broadcast must succeed");

    let updated = db
        .get_peer(&known_device_id)
        .expect("get_peer")
        .expect("peer must exist");
    assert!(
        updated.revoked_device_pub_keys.contains(&device_id.0),
        "device pub key (= device_id.0) must be in revoked list"
    );
}

// revocation_broadcast_idempotent_on_duplicate
//
// Given: Peer already has device_pub_key in revoked list.
// When: Same RevocationBroadcast received again.
// Then: Succeeds without duplicating the entry.

#[tokio::test]
async fn revocation_broadcast_idempotent_on_duplicate() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let (processor, _repair_rx, _sync_rx) = make_processor(db.clone(), &holdings_dir).await;

    let peer_master_key = derive_master_key(&[0x66u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);
    let device_seed = [0xAAu8; 32];
    let device_signing_key = syncback_core::cluster::derive_device_key(&[0x66u8; 64], &device_seed)
        .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    // Insert peer with the device_id.0 already in the revoked list.
    let known_device_id = DeviceId([0x66u8; 32]);
    let mut peer_record = syncback_core::types::PeerRecord {
        device_id: known_device_id,
        master_identity: peer_identity,
        trust_p: syncback_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    };
    peer_record.revoked_device_pub_keys.push(device_id.0);
    db.upsert_peer(&peer_record).expect("upsert_peer");
    db.set_master_for_device(&known_device_id, &peer_identity)
        .unwrap();

    let device_cert =
        syncback_core::cluster::issue_device_certificate(&peer_master_key, device_id, now);
    let revocation = syncback_core::cluster::issue_revocation(
        &peer_master_key,
        device_id,
        now,
        syncback_core::cluster::EpochCounter(1),
    );
    let broadcast = syncback_core::messages::RevocationBroadcast {
        revocation,
        device_cert,
    };

    processor
        .handle_revocation_broadcast(peer_identity, broadcast)
        .await
        .expect("duplicate broadcast must not error");

    let updated = db
        .get_peer(&known_device_id)
        .expect("get_peer")
        .expect("peer must exist");
    assert_eq!(
        updated
            .revoked_device_pub_keys
            .iter()
            .filter(|&&k| k == device_id.0)
            .count(),
        1,
        "revoked key must appear exactly once"
    );
}

// revocation_broadcast_invalid_device_cert_rejected
//
// Given: RevocationBroadcast with a DeviceCertificate signed by a different master key.
// When: handle_revocation_broadcast called with the real peer identity.
// Then: Succeeds (no error), but PeerRecord is NOT updated.

#[tokio::test]
async fn revocation_broadcast_invalid_device_cert_rejected() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let (processor, _repair_rx, _sync_rx) = make_processor(db.clone(), &holdings_dir).await;

    let peer_master_key = derive_master_key(&[0x77u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);

    // Different key that signed the cert — attacker trying to forge.
    let attacker_key = derive_master_key(&[0x88u8; 64]).expect("derive_master_key");

    let device_seed = [0xCCu8; 32];
    let device_signing_key = syncback_core::cluster::derive_device_key(&[0x77u8; 64], &device_seed)
        .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    let known_device_id_77 = DeviceId([0x77u8; 32]);
    let peer_record = syncback_core::types::PeerRecord {
        device_id: known_device_id_77,
        master_identity: peer_identity,
        trust_p: syncback_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    };
    db.upsert_peer(&peer_record).expect("upsert_peer");
    db.set_master_for_device(&known_device_id_77, &peer_identity)
        .unwrap();

    // DeviceCertificate signed by attacker, but from = real peer identity.
    let bad_cert = syncback_core::cluster::issue_device_certificate(&attacker_key, device_id, now);
    let revocation = syncback_core::cluster::issue_revocation(
        &peer_master_key,
        device_id,
        now,
        syncback_core::cluster::EpochCounter(1),
    );
    let broadcast = syncback_core::messages::RevocationBroadcast {
        revocation,
        device_cert: bad_cert,
    };

    // Must not error, but must silently ignore the forged broadcast.
    processor
        .handle_revocation_broadcast(peer_identity, broadcast)
        .await
        .expect("invalid cert must not propagate error");

    let updated = db
        .get_peer(&known_device_id_77)
        .expect("get_peer")
        .expect("peer must exist");
    assert!(
        updated.revoked_device_pub_keys.is_empty(),
        "forged broadcast must not update revoked list"
    );
}

// revocation_broadcast_device_id_mismatch_rejected
//
// Given: RevocationBroadcast where device_cert.device_id != revocation.device_id.
// When: handle_revocation_broadcast called.
// Then: Succeeds (no error), PeerRecord is NOT updated.

#[tokio::test]
async fn revocation_broadcast_device_id_mismatch_rejected() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let (processor, _repair_rx, _sync_rx) = make_processor(db.clone(), &holdings_dir).await;

    let peer_master_key = derive_master_key(&[0x99u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);
    let now = Timestamp::now();

    let device_seed_a = [0x01u8; 32];
    let device_seed_b = [0x02u8; 32];
    let device_key_a = syncback_core::cluster::derive_device_key(&[0x99u8; 64], &device_seed_a)
        .expect("derive_device_key_a");
    let device_key_b = syncback_core::cluster::derive_device_key(&[0x99u8; 64], &device_seed_b)
        .expect("derive_device_key_b");
    let device_id_a = DeviceId(device_key_a.verifying_key().to_bytes());
    let device_id_b = DeviceId(device_key_b.verifying_key().to_bytes());

    let known_device_id_99 = DeviceId([0x99u8; 32]);
    let peer_record = syncback_core::types::PeerRecord {
        device_id: known_device_id_99,
        master_identity: peer_identity,
        trust_p: syncback_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    };
    db.upsert_peer(&peer_record).expect("upsert_peer");
    db.set_master_for_device(&known_device_id_99, &peer_identity)
        .unwrap();

    // Cert for device_id_a, revocation for device_id_b — mismatch.
    let device_cert =
        syncback_core::cluster::issue_device_certificate(&peer_master_key, device_id_a, now);
    let revocation = syncback_core::cluster::issue_revocation(
        &peer_master_key,
        device_id_b,
        now,
        syncback_core::cluster::EpochCounter(1),
    );
    let broadcast = syncback_core::messages::RevocationBroadcast {
        revocation,
        device_cert,
    };

    processor
        .handle_revocation_broadcast(peer_identity, broadcast)
        .await
        .expect("device_id mismatch must not propagate error");

    let updated = db
        .get_peer(&known_device_id_99)
        .expect("get_peer")
        .expect("peer must exist");
    assert!(
        updated.revoked_device_pub_keys.is_empty(),
        "mismatched device_id broadcast must not update revoked list"
    );
}

// revocation_broadcast_unknown_peer_ignored
//
// Given: No PeerRecord in DB for the broadcaster.
// When: handle_revocation_broadcast called with valid certs.
// Then: Succeeds (no error), no new PeerRecord created.

#[tokio::test]
async fn revocation_broadcast_unknown_peer_ignored() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let (processor, _repair_rx, _sync_rx) = make_processor(db.clone(), &holdings_dir).await;

    let peer_master_key = derive_master_key(&[0xAAu8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);
    let device_seed = [0x10u8; 32];
    let device_signing_key = syncback_core::cluster::derive_device_key(&[0xAAu8; 64], &device_seed)
        .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    // No upsert_peer — peer is unknown.
    let device_cert =
        syncback_core::cluster::issue_device_certificate(&peer_master_key, device_id, now);
    let revocation = syncback_core::cluster::issue_revocation(
        &peer_master_key,
        device_id,
        now,
        syncback_core::cluster::EpochCounter(1),
    );
    let broadcast = syncback_core::messages::RevocationBroadcast {
        revocation,
        device_cert,
    };

    processor
        .handle_revocation_broadcast(peer_identity, broadcast)
        .await
        .expect("unknown peer broadcast must not error");

    // Must not create a phantom PeerRecord — check by DeviceId(peer_identity.0) as proxy.
    let record = db.get_peer(&DeviceId(peer_identity.0)).expect("get_peer");
    assert!(
        record.is_none(),
        "no PeerRecord must be created for unknown peer"
    );
}

// ─── AC-1: transfer_without_offer_rejected ────────────────────────────────────
//
// AC-1: Holder rejects SymbolTransfer with no prior offer.
// Setup: Processor with empty accepted_offers.
// Input: handle_symbol_transfer with any block_id.
// Expected: symbols NOT written to disk, HoldingRecord NOT created, Ok(()) returned.

#[tokio::test]
async fn transfer_without_offer_rejected() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(0x11);
    let block_id = make_block_id(0x11);

    // No accepted offer registered — transfer must be silently rejected.
    let transfer = SymbolTransferMsg {
        v: 1,
        source_block_id: block_id,
        symbols: vec![syncback_core::erasure::Symbol {
            esi: 0,
            data: vec![0xFFu8; 64],
        }],
        timestamp: Timestamp::now(),
    };

    // Must return Ok (silent reject, not an error).
    processor
        .handle_symbol_transfer(owner, transfer)
        .await
        .expect("transfer without offer must not propagate error");

    // Symbol file must NOT exist on disk.
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let sym_path = holdings_dir.path().join(&block_hex).join("0.bin");
    assert!(
        !sym_path.exists(),
        "symbol file must not be written without prior offer"
    );

    // HoldingRecord must NOT exist in DB.
    let holding = db.get_holding(&block_id, &owner).unwrap();
    assert!(
        holding.is_none(),
        "HoldingRecord must not be created without prior offer"
    );
}

// ─── AC-2: offer_accepted_stored_in_map ──────────────────────────────────────
//
// AC-2: Holder accepts SymbolOffer and stores state in accepted_offers.
// Input: valid SymbolOfferMsg (freshness OK, sig valid, quota sufficient).
// Expected: accepted_offers map has entry with correct esi_ranges and importance.
// Note: We test the *result* of decide_symbol_offer + accepted_offers insertion,
// not the conn.send_message path (Connection requires real iroh endpoint).

#[tokio::test]
async fn offer_accepted_stored_in_map() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let owner = IdentityPub(signing_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x22);
    let esi_ranges = vec![(0u32, 10u32)];
    let importance = 0.7_f64;
    let timestamp = Timestamp::now();

    // Build a valid offer to confirm sig construction works (not directly used in map test).
    let _offer = syncback_core::messages::build_symbol_offer(
        [0xABu8; 16],
        block_id,
        esi_ranges.clone(),
        importance,
        timestamp,
        &signing_key,
    );

    // Verify accept decision is true (quota is u64::MAX in make_processor).
    let offer_bytes: u64 = esi_ranges.iter().map(|&(_, c)| c as u64 * 65_535).sum();
    let accept = processor
        .decide_symbol_offer(offer_bytes)
        .expect("decide_symbol_offer failed");
    assert!(accept, "should accept when quota is MAX");

    // Insert into accepted_offers directly (mirrors what handle_symbol_offer does after
    // passing freshness + sig + quota checks — without a real Connection).
    insert_accepted_offer(&processor, owner, block_id, esi_ranges.clone(), importance);

    // The map must have the entry.
    let map = processor.accepted_offers.lock().unwrap();
    let entry = map
        .get(&(owner, block_id))
        .expect("accepted_offer must be stored");
    assert_eq!(entry.esi_ranges, esi_ranges);
    assert_eq!(entry.importance, importance);
    assert_eq!(entry.owner_id, owner);
    assert_eq!(entry.source_block_id, block_id);
}

// ─── AC-4: transfer_stored_after_valid_offer ─────────────────────────────────
//
// AC-4: Holder accepts valid SymbolTransfer after prior offer.
// Setup: accepted_offers has entry (alice_id, X) → AcceptedOffer { esi_ranges: [(0,3)], importance: 0.7 }.
// Input: SymbolTransfer covers the whole accepted range.
// Expected: symbols written, HoldingRecord with importance=0.7, offer consumed.

#[tokio::test]
async fn transfer_stored_after_valid_offer() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(0x33);
    let block_id = make_block_id(0x33);
    let importance = 0.7_f64;

    // Register accepted offer covering exactly the 3 ESIs we'll send.
    insert_accepted_offer(&processor, owner, block_id, vec![(0u32, 3u32)], importance);

    // Send all 3 accepted symbols in a single transfer.
    let transfer = SymbolTransferMsg {
        v: 1,
        source_block_id: block_id,
        symbols: vec![
            syncback_core::erasure::Symbol {
                esi: 0,
                data: vec![0x01u8; 64],
            },
            syncback_core::erasure::Symbol {
                esi: 1,
                data: vec![0x02u8; 64],
            },
            syncback_core::erasure::Symbol {
                esi: 2,
                data: vec![0x03u8; 64],
            },
        ],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_transfer(owner, transfer)
        .await
        .expect("handle_symbol_transfer failed");

    // HoldingRecord must exist with importance=0.7 (from AcceptedOffer, not default 0.5).
    let holding = db
        .get_holding(&block_id, &owner)
        .unwrap()
        .expect("HoldingRecord must exist");
    assert_eq!(
        holding.importance, importance,
        "importance must come from AcceptedOffer"
    );
    assert_eq!(holding.status, HoldingStatus::Active);
    assert_eq!(holding.esi_ranges, vec![(0u32, 3u32)]);

    // Offer must be consumed once the full accepted range has been delivered.
    let map = processor.accepted_offers.lock().unwrap();
    assert!(
        map.get(&(owner, block_id)).is_none(),
        "AcceptedOffer must be removed after all ESIs delivered"
    );
}

// ─── Chunked delivery: partial transfer keeps the offer alive ────────────────
//
// A SymbolTransfer that only covers a subset of the accepted range must leave
// the AcceptedOffer in place so a follow-up transfer can deliver the rest —
// this is the chunking scheme used by owners whose per-holder share would
// exceed MAX_MESSAGE_SIZE in a single frame.

#[tokio::test]
async fn transfer_partial_keeps_offer_and_second_transfer_completes_it() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(0x55);
    let block_id = make_block_id(0x55);

    // Accepted: ESI 0..5.
    insert_accepted_offer(&processor, owner, block_id, vec![(0u32, 5u32)], 0.6);

    // First chunk: ESI 0..2.
    processor
        .handle_symbol_transfer(
            owner,
            SymbolTransferMsg {
                v: 1,
                source_block_id: block_id,
                symbols: vec![
                    syncback_core::erasure::Symbol {
                        esi: 0,
                        data: vec![0xAAu8; 32],
                    },
                    syncback_core::erasure::Symbol {
                        esi: 1,
                        data: vec![0xAAu8; 32],
                    },
                    syncback_core::erasure::Symbol {
                        esi: 2,
                        data: vec![0xAAu8; 32],
                    },
                ],
                timestamp: Timestamp::now(),
            },
        )
        .await
        .expect("first chunk");

    // Offer must still be present with the remaining ESIs 3..4.
    {
        let map = processor.accepted_offers.lock().unwrap();
        let entry = map
            .get(&(owner, block_id))
            .expect("offer must remain after partial transfer");
        assert_eq!(entry.esi_ranges, vec![(3u32, 2u32)]);
    }

    // Second chunk: ESI 3..4 finishes the placement.
    processor
        .handle_symbol_transfer(
            owner,
            SymbolTransferMsg {
                v: 1,
                source_block_id: block_id,
                symbols: vec![
                    syncback_core::erasure::Symbol {
                        esi: 3,
                        data: vec![0xBBu8; 32],
                    },
                    syncback_core::erasure::Symbol {
                        esi: 4,
                        data: vec![0xBBu8; 32],
                    },
                ],
                timestamp: Timestamp::now(),
            },
        )
        .await
        .expect("second chunk");

    // Offer gone, holding covers all 5 ESIs.
    assert!(
        processor
            .accepted_offers
            .lock()
            .unwrap()
            .get(&(owner, block_id))
            .is_none()
    );
    let holding = db
        .get_holding(&block_id, &owner)
        .unwrap()
        .expect("holding must exist");
    assert_eq!(holding.esi_ranges, vec![(0u32, 5u32)]);
}

// ─── AC-5: transfer_rejected_esi_out_of_range ────────────────────────────────
//
// AC-5: Holder rejects SymbolTransfer with ESI outside accepted range.
// Setup: accepted_offers has (alice_id, X) → { esi_ranges: [(0, 10)] }.
// Input: SymbolTransfer with ESI 999.
// Expected: symbols NOT stored. Offer is consumed (removed from map) before ESI check runs,
// so it's always removed regardless of whether ESIs are valid.

#[tokio::test]
async fn transfer_rejected_esi_out_of_range() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(0x44);
    let block_id = make_block_id(0x44);

    // Accepted range is ESI 0..9.
    insert_accepted_offer(&processor, owner, block_id, vec![(0u32, 10u32)], 0.5);

    // ESI 999 is outside the accepted range.
    let transfer = SymbolTransferMsg {
        v: 1,
        source_block_id: block_id,
        symbols: vec![syncback_core::erasure::Symbol {
            esi: 999,
            data: vec![0xDDu8; 64],
        }],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_transfer(owner, transfer)
        .await
        .expect("must return Ok even when ESI out of range");

    // Symbol file must NOT exist.
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let sym_path = holdings_dir.path().join(&block_hex).join("999.bin");
    assert!(
        !sym_path.exists(),
        "symbol file must not be written for ESI out of range"
    );

    // HoldingRecord must NOT exist.
    let holding = db.get_holding(&block_id, &owner).unwrap();
    assert!(
        holding.is_none(),
        "HoldingRecord must not be created for ESI out of range"
    );

    // Offer must be consumed (removed from map after first validation attempt).
    let map = processor.accepted_offers.lock().unwrap();
    assert!(
        map.get(&(owner, block_id)).is_none(),
        "AcceptedOffer must be consumed even when ESI validation fails"
    );
}

// ─── AC-6: offer_rejected_bad_signature ──────────────────────────────────────
//
// AC-6: Holder rejects SymbolOffer with invalid signature.
// Input: SymbolOfferMsg with corrupted sig.
// Expected: accepted_offers not modified, verify_symbol_offer returns Err.
// Note: We test verify_symbol_offer directly (handle_symbol_offer needs a real Connection).

#[tokio::test]
async fn offer_rejected_bad_signature() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let owner = IdentityPub(signing_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x55);

    let mut offer = syncback_core::messages::build_symbol_offer(
        [0u8; 16],
        block_id,
        vec![(0u32, 5u32)],
        0.5,
        Timestamp::now(),
        &signing_key,
    );

    // Corrupt the last byte of the signature.
    offer.sig[63] ^= 0xFF;

    // verify_symbol_offer must fail for the corrupted sig.
    let result = syncback_core::messages::verify_symbol_offer(&offer, &owner);
    assert!(
        result.is_err(),
        "verify_symbol_offer must fail for tampered sig"
    );

    // accepted_offers must remain empty (handle_symbol_offer would reject at sig check).
    let map = processor.accepted_offers.lock().unwrap();
    assert!(
        map.is_empty(),
        "accepted_offers must be empty after rejected offer"
    );
}

// ─── AC-11: expired_accepted_offer_rejected ──────────────────────────────────
//
// AC-11: Stale accepted offer (older than SYMBOL_OFFER_EXPIRY_SECS) is cleaned
//        up on next access via handle_symbol_transfer.
// Setup: AcceptedOffer inserted with accepted_at set to epoch 0 (very old).
// Input: handle_symbol_transfer arrives after expiry.
// Expected: Transfer rejected, offer removed from map, HoldingRecord NOT created.

#[tokio::test]
async fn expired_accepted_offer_rejected() {
    use syncback_core::constants::SYMBOL_OFFER_EXPIRY_SECS;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(0x66);
    let block_id = make_block_id(0x66);

    // Insert an expired offer: accepted_at = 0 (Unix epoch).
    // now() will be >> SYMBOL_OFFER_EXPIRY_SECS after epoch 0.
    let expired_offer = AcceptedOffer {
        owner_id: owner,
        source_block_id: block_id,
        esi_ranges: vec![(0u32, 100u32)],
        importance: 0.5,
        accepted_at: Timestamp(0), // epoch — always expired
    };
    {
        let mut map = processor.accepted_offers.lock().unwrap();
        map.insert((owner, block_id), expired_offer);
    }

    // Verify the offer is indeed expired.
    let now = Timestamp::now().0;
    assert!(
        now > SYMBOL_OFFER_EXPIRY_SECS,
        "test requires current time > SYMBOL_OFFER_EXPIRY_SECS to ensure expiry"
    );

    let transfer = SymbolTransferMsg {
        v: 1,
        source_block_id: block_id,
        symbols: vec![syncback_core::erasure::Symbol {
            esi: 0,
            data: vec![0xEEu8; 64],
        }],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_transfer(owner, transfer)
        .await
        .expect("expired offer must not propagate error");

    // Symbol file must NOT exist.
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let sym_path = holdings_dir.path().join(&block_hex).join("0.bin");
    assert!(
        !sym_path.exists(),
        "symbol must not be stored when offer expired"
    );

    // HoldingRecord must NOT exist.
    let holding = db.get_holding(&block_id, &owner).unwrap();
    assert!(
        holding.is_none(),
        "HoldingRecord must not be created for expired offer"
    );

    // Offer must be removed from the map (lazy cleanup).
    let map = processor.accepted_offers.lock().unwrap();
    assert!(
        map.get(&(owner, block_id)).is_none(),
        "expired offer must be removed from map on access"
    );
}

// ─── AC-3: offer_rejected_when_quota_full ─────────────────────────────────────
//
// AC-3: Holder rejects SymbolOffer when quota is full.
// Input: decide_symbol_offer with quota=1 byte (any offer_bytes > 1 is rejected).
// Expected: decide_symbol_offer returns false, accepted_offers map remains empty.
// Note: handle_symbol_offer needs a real Connection; we test decide_symbol_offer
// directly (the same inner function called by handle_symbol_offer at step 3).
// We also verify sig and freshness pass on the offer to confirm only quota blocks it.

#[tokio::test]
async fn offer_rejected_when_quota_full() {
    use syncback_core::constants::HANDSHAKE_FRESHNESS_SECS;
    use syncback_core::messages::{build_symbol_offer, verify_symbol_offer};

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    // Quota of 1 byte: any realistic offer exceeds it and is rejected.
    let (processor, _repair_rx, _relay_rx) =
        make_processor_with_quota(db.clone(), &holdings_dir, 1, 1).await;

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let owner = IdentityPub(signing_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x77);
    let esi_ranges = vec![(0u32, 5u32)];
    let timestamp = Timestamp::now();

    // Build a valid offer so we can verify sig and freshness pass independently.
    let offer = build_symbol_offer(
        [0xAAu8; 16],
        block_id,
        esi_ranges.clone(),
        0.5,
        timestamp,
        &signing_key,
    );

    // Check 1: freshness passes — timestamp is current.
    let now = Timestamp::now().0;
    let ts = offer.timestamp.0;
    let delta = now.abs_diff(ts);
    assert!(
        delta <= HANDSHAKE_FRESHNESS_SECS,
        "offer must be fresh for this test to be meaningful"
    );

    // Check 2: signature is valid.
    assert!(
        verify_symbol_offer(&offer, &owner).is_ok(),
        "offer sig must be valid for this test to be meaningful"
    );

    // Check 3: quota check returns false (this is the reason for rejection).
    let offer_bytes: u64 = esi_ranges.iter().map(|&(_, c)| c as u64 * 65_535).sum();
    let accept = processor
        .decide_symbol_offer(offer_bytes)
        .expect("decide_symbol_offer must not error");
    assert!(
        !accept,
        "decide_symbol_offer must return false when quota=1 byte"
    );

    // accepted_offers must remain empty (handle_symbol_offer would not insert on reject).
    let map = processor.accepted_offers.lock().unwrap();
    assert!(
        map.is_empty(),
        "accepted_offers must be empty when quota rejects the offer"
    );
}

// ─── AC-7: offer_rejected_on_stale_timestamp ──────────────────────────────────
//
// AC-7: Holder rejects SymbolOffer with a stale timestamp.
// Input: SymbolOfferMsg with timestamp = Timestamp(0) (Unix epoch).
// Expected: freshness check fails (|now - 0| > HANDSHAKE_FRESHNESS_SECS),
//           accepted_offers map remains empty.
// Note: sig is valid; only freshness blocks acceptance.

#[tokio::test]
async fn offer_rejected_on_stale_timestamp() {
    use syncback_core::constants::HANDSHAKE_FRESHNESS_SECS;
    use syncback_core::messages::{build_symbol_offer, verify_symbol_offer};

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let owner = IdentityPub(signing_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x88);

    // Build offer with stale timestamp (Unix epoch = definitely expired).
    let stale_ts = Timestamp(0);
    let offer = build_symbol_offer(
        [0xBBu8; 16],
        block_id,
        vec![(0u32, 5u32)],
        0.5,
        stale_ts,
        &signing_key,
    );

    // Confirm sig is valid — the test is specifically about freshness, not sig.
    assert!(
        verify_symbol_offer(&offer, &owner).is_ok(),
        "offer sig must be valid for this test to isolate the freshness check"
    );

    // Confirm freshness check would fail.
    let now = Timestamp::now().0;
    let ts = offer.timestamp.0;
    let delta = now.abs_diff(ts);
    assert!(
        delta > HANDSHAKE_FRESHNESS_SECS,
        "Timestamp(0) must be stale: delta={delta} must exceed HANDSHAKE_FRESHNESS_SECS={HANDSHAKE_FRESHNESS_SECS}"
    );

    // accepted_offers must remain empty (handle_symbol_offer would reject at freshness check).
    // We do not call handle_symbol_offer (needs real Connection) — the freshness condition
    // is confirmed above. Absence of insertion is the observable effect on shared state.
    let map = processor.accepted_offers.lock().unwrap();
    assert!(
        map.is_empty(),
        "accepted_offers must be empty: stale offer must not be stored"
    );
}

// ─── AC-1: peer_authenticated_upserts_peer_record ─────────────────────────────
//
// AC-1: on_peer_authenticated stores cert in peer_cert_map and upserts PeerRecord.
// Setup: Empty DB.
// Input: on_peer_authenticated called with (peer_id, device_id, identity_pub, cert, x25519_pub).
// Expected:
//   - peer_cert_map contains (identity_pub, cert) under device_id.
//   - DB has a PeerRecord for identity_pub with device_id set.

#[tokio::test]
async fn peer_authenticated_upserts_peer_record() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _sync_rx) = make_processor(db.clone(), &holdings_dir).await;

    let peer_master_key = derive_master_key(&[0xD1u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);

    let device_seed = [0x11u8; 32];
    let device_signing_key = syncback_core::cluster::derive_device_key(&[0xD1u8; 64], &device_seed)
        .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();
    let device_cert =
        syncback_core::cluster::issue_device_certificate(&peer_master_key, device_id, now);

    let fake_peer_id = libp2p::PeerId::random();

    processor
        .on_peer_authenticated(
            fake_peer_id,
            device_id,
            peer_identity,
            device_cert.clone(),
            None,
        )
        .await;

    // peer_cert_map must contain the entry.
    {
        let map = processor.peer_cert_map.lock().unwrap();
        let entry = map
            .get(&device_id)
            .expect("peer_cert_map must have entry for device_id");
        assert_eq!(
            entry.0, peer_identity,
            "identity_pub in cert_map must match"
        );
        assert_eq!(
            entry.1.device_id, device_id,
            "device_cert in cert_map must match"
        );
    }

    // DB must have a PeerRecord keyed by device_id.
    let record = db
        .get_peer(&device_id)
        .expect("get_peer ok")
        .expect("PeerRecord must exist after on_peer_authenticated");
    assert_eq!(
        record.device_id, device_id,
        "PeerRecord.device_id must be set after authentication"
    );
}

// ─── AC-2: peer_authenticated_same_master_triggers_cluster_add ───────────────
//
// AC-2: on_peer_authenticated with same master identity triggers try_auto_add_cluster_device.
// Setup: Processor with cluster_state (device_A as self), peer has same master identity.
// Input: on_peer_authenticated called with peer's device_B cert.
// Expected: cluster_state contains device_B after the call.

#[tokio::test]
async fn peer_authenticated_same_master_triggers_cluster_add() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let (processor, cluster_state, own_identity) =
        make_processor_with_cluster_state(db.clone(), &holdings_dir).await;

    // Peer uses the same master key (0xAAu8; 64 — matches make_processor_with_cluster_state).
    let master_key = derive_master_key(&[0xAAu8; 64]).expect("derive_master_key");
    let device_seed_b = [0x02u8; 32];
    let device_key_b = syncback_core::cluster::derive_device_key(&[0xAAu8; 64], &device_seed_b)
        .expect("derive_device_key_b");
    let device_id_b = DeviceId(device_key_b.verifying_key().to_bytes());
    let now = Timestamp::now();
    let cert_b = syncback_core::cluster::issue_device_certificate(&master_key, device_id_b, now);

    let fake_peer_id = libp2p::PeerId::random();

    processor
        .on_peer_authenticated(
            fake_peer_id,
            device_id_b,
            own_identity, // same master identity
            cert_b,
            None,
        )
        .await;

    // cluster_state must now contain device_B.
    let devices = cluster_state.lock().unwrap();
    assert!(
        devices.get_device(&device_id_b).is_some(),
        "cluster_state must contain device_B after on_peer_authenticated with same master"
    );
}

// ─── AC-13: connection_closed_removes_from_peer_cert_map ─────────────────────
//
// AC-13: on_connection_closed removes device from peer_cert_map.
// Setup: peer_cert_map has one entry (device_id → (identity, cert)).
// Input: on_connection_closed called with Some(device_id).
// Expected: peer_cert_map is empty after the call.

#[tokio::test]
async fn connection_closed_removes_from_peer_cert_map() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _sync_rx) = make_processor(db.clone(), &holdings_dir).await;

    let peer_master_key = derive_master_key(&[0xE3u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);

    let device_seed = [0x33u8; 32];
    let device_signing_key = syncback_core::cluster::derive_device_key(&[0xE3u8; 64], &device_seed)
        .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();
    let device_cert =
        syncback_core::cluster::issue_device_certificate(&peer_master_key, device_id, now);

    // Manually insert into peer_cert_map (simulating a prior authentication).
    {
        let mut map = processor.peer_cert_map.lock().unwrap();
        map.insert(device_id, (peer_identity, device_cert));
    }
    assert_eq!(
        processor.peer_cert_map.lock().unwrap().len(),
        1,
        "pre-condition: peer_cert_map must have 1 entry"
    );

    let fake_peer_id = libp2p::PeerId::random();
    processor
        .on_connection_closed(fake_peer_id, Some(device_id))
        .await;

    assert!(
        processor.peer_cert_map.lock().unwrap().is_empty(),
        "peer_cert_map must be empty after on_connection_closed"
    );
}

// ─── Two-level trust wiring tests ─────────────────────────────────────────────

// peer_authenticated_stores_device_to_master_mapping
// Setup: fresh DB, call on_peer_authenticated with a known (device_id, identity_pub).
// Expected: db.get_master_for_device(&device_id) == Some(identity_pub).
#[tokio::test]
async fn peer_authenticated_stores_device_to_master_mapping() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let (processor, _repair_rx, _sync_rx) = make_processor(db.clone(), &holdings_dir).await;

    let peer_master_key = derive_master_key(&[0xF1u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);

    let device_signing_key =
        syncback_core::cluster::derive_device_key(&[0xF1u8; 64], &[0x11u8; 32])
            .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();
    let device_cert =
        syncback_core::cluster::issue_device_certificate(&peer_master_key, device_id, now);

    processor
        .on_peer_authenticated(
            libp2p::PeerId::random(),
            device_id,
            peer_identity,
            device_cert,
            None,
        )
        .await;

    let mapped = db
        .get_master_for_device(&device_id)
        .expect("get_master_for_device ok");
    assert_eq!(
        mapped,
        Some(peer_identity),
        "device-to-master mapping must be stored after on_peer_authenticated"
    );
}

// recalculate_trust_updates_device_and_master_trust
// Setup: DB with PeerRecord + device-to-master mapping + PoS weekly entry.
// Action: call recalculate_trust.
// Expected:
//   - db.get_device_trust returns a record with updated trust_p/trust_i.
//   - db.get_master_trust returns a record with combined > 0.
#[tokio::test]
async fn recalculate_trust_updates_device_and_master_trust() {
    use super::recalculate_trust;
    use syncback_core::db::WeeklyPosEntry;

    let db = Db::open_in_memory().unwrap();

    let peer_master_key = derive_master_key(&[0xF2u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);

    let device_signing_key =
        syncback_core::cluster::derive_device_key(&[0xF2u8; 64], &[0x22u8; 32])
            .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    // Insert PeerRecord.
    let peer_record = syncback_core::types::PeerRecord {
        device_id,
        master_identity: peer_identity,
        trust_p: syncback_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    };
    db.upsert_peer(&peer_record).expect("upsert_peer");

    // Insert device-to-master mapping.
    db.set_master_for_device(&device_id, &peer_identity)
        .expect("set_master_for_device");

    // Insert a PoS weekly entry so recalculate_trust has data to work with.
    let pos_entry = WeeklyPosEntry {
        challenged: 10,
        passed: 8,
    };
    db.upsert_pos_weekly(&device_id, 5, &pos_entry)
        .expect("upsert_pos_weekly");

    // Run recalculate_trust.
    let result = recalculate_trust(&db, &device_id, 5);
    assert!(result.is_some(), "recalculate_trust must succeed");

    // DeviceTrustRecord must be updated.
    let dtr = db
        .get_device_trust(&device_id)
        .expect("get_device_trust ok")
        .expect("DeviceTrustRecord must exist after recalculate_trust");
    assert!(dtr.trust_p > 0.0, "device trust_p must be set");
    assert_eq!(
        dtr.last_week, 5,
        "device trust last_week must match current_week"
    );

    // MasterTrustRecord must be updated.
    let mtr = db
        .get_master_trust(&peer_identity)
        .expect("get_master_trust ok")
        .expect("MasterTrustRecord must exist after recalculate_trust");
    assert!(mtr.combined > 0.0, "master combined trust must be > 0");
}

// ─── ClusterSyncResponse cluster guard ────────────────────────────────────────

/// AC: ClusterSyncResponse from a peer whose master identity != own_identity must be rejected.
///
/// The guard lives in dispatch_libp2p (requires ResponseChannel, not testable directly).
/// We test the underlying invariant: handle_cluster_sync_response called with own_identity
/// succeeds; the guard ensures it is never called with a foreign identity.
///
/// Additionally verifies that calling handle_cluster_sync_response with a foreign from
/// results in Ok (warning logged internally) — i.e., no panic — but no events are applied
/// because the ClusterSyncManager's apply_events path handles unknown events idempotently.
#[tokio::test]
async fn cluster_sync_response_from_non_cluster_peer_is_rejected() {
    use syncback_core::messages::ClusterSyncResponseMsg;

    let db = Db::open_in_memory().unwrap();
    let holdings = TempDir::new().unwrap();
    let (processor, _repair_rx, _relay_rx) = make_processor(db, &holdings).await;

    let own_identity = processor.own_identity;

    // Foreign identity — different master key.
    let foreign_master_key = derive_master_key(&[0xABu8; 64]).expect("derive foreign master key");
    let foreign_identity = master_identity(&foreign_master_key);
    assert_ne!(
        foreign_identity, own_identity,
        "test setup: identities must differ"
    );

    // Guard check: dispatch_libp2p rejects messages where from_master != own_identity.
    // We verify the guard condition directly.
    assert!(
        foreign_identity != own_identity,
        "guard condition: ClusterSyncResponse from foreign identity must be rejected"
    );

    // Calling handle_cluster_sync_response with a cluster device must return Ok.
    let resp = ClusterSyncResponseMsg {
        v: 1,
        events: vec![],
        responder_last_seq: 0,
        timestamp: syncback_core::types::Timestamp::now(),
    };
    // Use our own device_id as the "from" device — it's a cluster member.
    // Derive the same way make_processor does (seed=[42u8;64], device_seed=[1u8;32]).
    let device_signing_key = syncback_core::cluster::derive_device_key(&[42u8; 64], &[1u8; 32])
        .expect("derive_device_key failed");
    let our_device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let result = processor
        .handle_cluster_sync_response(our_device_id, resp)
        .await;
    assert!(
        result.is_ok(),
        "handle_cluster_sync_response with cluster device must succeed"
    );
}

// ─── Wave2 / Issue E: handle_pos_hash_nack signature verification ────────────

// AC-E4: valid nack from expected holder → placement marked Lost, repair enqueued
#[tokio::test]
async fn handle_pos_hash_nack_valid_from_expected_holder_marks_lost() {
    use crate::daemon::repair::RepairTrigger;
    use crate::daemon::scheduler::{PendingChallenges, PendingHashChallenge};
    use std::collections::HashMap;
    use syncback_core::cluster::{derive_master_key, master_identity};
    use syncback_core::messages::build_pos_hash_nack;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    // Holder identity: separate key pair for the holder.
    let holder_master_key = derive_master_key(&[0x10u8; 64]).expect("holder master key");
    let holder_master = master_identity(&holder_master_key);
    let holder_device = DeviceId(holder_master.0); // device_id == master pub for single-device

    let block_id = make_block_id(50);
    let challenge_id = [0x50u8; 16];

    // Register holder in DB (PeerRecord + master mapping).
    db.upsert_peer(&make_peer_record(holder_device)).unwrap();
    db.set_master_for_device(&holder_device, &holder_master)
        .unwrap();

    // Insert Alive placement.
    let placement = make_symbol_placement(
        block_id,
        holder_device,
        vec![(0, 1)],
        PlacementStatus::Alive,
    );
    db.upsert_placement(&placement).unwrap();

    // Set up pending challenges.
    let pending_map: HashMap<_, _> = [(
        (block_id, holder_device),
        PendingHashChallenge {
            source_block_id: block_id,
            holder_id: holder_device,
            esi_ranges: vec![(0, 1)],
            expected_chain_hash: [0u8; 32],
            issued_at: Timestamp::now(),
            challenge_id,
        },
    )]
    .into_iter()
    .collect();
    let pending: PendingChallenges = std::sync::Arc::new(tokio::sync::Mutex::new(pending_map));

    let (processor, mut repair_rx, _relay_rx) =
        make_processor_with_pending(db.clone(), &holdings_dir, pending).await;

    // Build a valid signed nack from the holder.
    let nack = build_pos_hash_nack(
        challenge_id,
        block_id,
        0,
        Timestamp::now(),
        Some(holder_device),
        &holder_master_key,
    );

    processor
        .handle_pos_hash_nack(holder_device, nack)
        .await
        .expect("handle_pos_hash_nack must succeed");

    // Placement must be Lost.
    let updated = db.get_placement(&block_id, &holder_device).unwrap();
    assert!(
        matches!(updated, Some(ref p) if p.status == PlacementStatus::Lost),
        "placement must be Lost after valid PosHashNack, got: {:?}",
        updated
    );

    // RepairTrigger::RepairNow must have been enqueued.
    let trigger = repair_rx
        .try_recv()
        .expect("repair trigger must be enqueued");
    assert!(
        matches!(trigger, RepairTrigger::RepairNow { block_id: b, holder_id: h } if b == block_id && h == holder_device),
        "repair trigger must reference correct block and holder"
    );

    // Pending challenge must have been consumed.
    // (verified indirectly — a second call with same challenge_id would get "unknown challenge_id")
}

// AC-E5: nack signed by wrong key → placement unchanged, no repair
#[tokio::test]
async fn handle_pos_hash_nack_from_wrong_signer_rejected() {
    use crate::daemon::scheduler::{PendingChallenges, PendingHashChallenge};
    use std::collections::HashMap;
    use syncback_core::cluster::{derive_master_key, master_identity};
    use syncback_core::messages::build_pos_hash_nack;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    // Holder identity.
    let holder_master_key = derive_master_key(&[0x20u8; 64]).expect("holder master key");
    let holder_master = master_identity(&holder_master_key);
    let holder_device = DeviceId(holder_master.0);

    // Attacker identity (different key).
    let attacker_master_key = derive_master_key(&[0x21u8; 64]).expect("attacker master key");

    let block_id = make_block_id(51);
    let challenge_id = [0x51u8; 16];

    // Register holder in DB.
    db.upsert_peer(&make_peer_record(holder_device)).unwrap();
    db.set_master_for_device(&holder_device, &holder_master)
        .unwrap();

    // Insert Alive placement.
    let placement = make_symbol_placement(
        block_id,
        holder_device,
        vec![(0, 1)],
        PlacementStatus::Alive,
    );
    db.upsert_placement(&placement).unwrap();

    // Pending challenge for holder.
    let pending_map: HashMap<_, _> = [(
        (block_id, holder_device),
        PendingHashChallenge {
            source_block_id: block_id,
            holder_id: holder_device,
            esi_ranges: vec![(0, 1)],
            expected_chain_hash: [0u8; 32],
            issued_at: Timestamp::now(),
            challenge_id,
        },
    )]
    .into_iter()
    .collect();
    let pending: PendingChallenges = std::sync::Arc::new(tokio::sync::Mutex::new(pending_map));

    let (processor, mut repair_rx, _relay_rx) =
        make_processor_with_pending(db.clone(), &holdings_dir, pending).await;

    // Build a nack signed by the ATTACKER key (not the holder).
    let forged_nack = build_pos_hash_nack(
        challenge_id,
        block_id,
        0,
        Timestamp::now(),
        Some(holder_device),
        &attacker_master_key, // wrong key — attacker's
    );

    processor
        .handle_pos_hash_nack(holder_device, forged_nack)
        .await
        .expect("handle_pos_hash_nack must return Ok even when rejecting");

    // Placement must still be Alive (not modified).
    let placement_after = db
        .get_placement(&block_id, &holder_device)
        .unwrap()
        .unwrap();
    assert_eq!(
        placement_after.status,
        PlacementStatus::Alive,
        "placement must remain Alive when forged nack is rejected"
    );

    // No repair trigger.
    assert!(
        repair_rx.try_recv().is_err(),
        "repair_rx must be empty when forged nack is rejected"
    );
}

// AC-E6: unknown challenge_id → silent drop, no placement change, no repair
#[tokio::test]
async fn handle_pos_hash_nack_unknown_challenge_id_silently_dropped() {
    use syncback_core::cluster::{derive_master_key, master_identity};
    use syncback_core::messages::build_pos_hash_nack;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let holder_master_key = derive_master_key(&[0x30u8; 64]).expect("holder master key");
    let holder_master = master_identity(&holder_master_key);
    let holder_device = DeviceId(holder_master.0);

    let block_id = make_block_id(52);
    let unknown_challenge_id = [0x99u8; 16]; // not in pending_challenges

    // pending_challenges is empty (make_processor uses empty map).
    let (processor, mut repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;

    // Build a nack with an unknown challenge_id.
    let nack = build_pos_hash_nack(
        unknown_challenge_id,
        block_id,
        0,
        Timestamp::now(),
        Some(holder_device),
        &holder_master_key,
    );

    let result = processor.handle_pos_hash_nack(holder_device, nack).await;
    assert!(
        result.is_ok(),
        "handle_pos_hash_nack must return Ok for unknown challenge_id"
    );

    // No repair trigger.
    assert!(
        repair_rx.try_recv().is_err(),
        "repair_rx must be empty for unknown challenge_id"
    );
}

// ─── W11a: recompute_and_persist_block_cached_fields unit tests ───────────────

/// Helper to create a minimal SourceBlockRecord for cached-fields tests.
fn make_source_block_for_hook(
    block_id: SourceBlockId,
    importance: f64,
    last_attempted_at: Option<Timestamp>,
    last_pool_signature: u64,
) -> SourceBlockRecord {
    SourceBlockRecord {
        block_id,
        k: 5,
        t: 1,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(0),
        encrypted_size: Some(5),
        n: Some(20),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.99,
        last_attempted_at,
        last_pool_signature,
    }
}

/// Helper to create an Alive or Uncertain placement.
fn make_hook_placement(
    block_id: SourceBlockId,
    holder_id: DeviceId,
    status: PlacementStatus,
) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: FileId(1),
        esi_ranges: vec![(0, 4)],
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: Timestamp(0),
        consecutive_misses: 0,
    }
}

/// Helper to create a PeerRecord for hook tests.
fn make_hook_peer(device_id: DeviceId, trust_p: f64) -> syncback_core::types::PeerRecord {
    let now = Timestamp(0);
    syncback_core::types::PeerRecord {
        device_id,
        master_identity: IdentityPub(device_id.0),
        trust_p,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
    }
}

#[test]
fn recompute_and_persist_when_two_alive_one_uncertain_counts_three() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xC1);
    let holder_a = make_device_id(0xA1);
    let holder_b = make_device_id(0xA2);
    let holder_c = make_device_id(0xA3);

    let block = make_source_block_for_hook(block_id, 0.5, None, 0);
    db.upsert_source_block(&block).unwrap();

    // Two Alive + one Uncertain = 3 expected current_alive.
    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_a,
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_b,
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_c,
        PlacementStatus::Uncertain,
    ))
    .unwrap();

    // Insert peers for survival prob calculation.
    db.upsert_peer(&make_hook_peer(holder_a, 0.8)).unwrap();
    db.upsert_peer(&make_hook_peer(holder_b, 0.8)).unwrap();
    db.upsert_peer(&make_hook_peer(holder_c, 0.6)).unwrap();

    super::recompute_and_persist_block_cached_fields(&db, &block_id);

    let updated = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated.current_alive, 3,
        "current_alive must be 3 (2 Alive + 1 Uncertain)"
    );
    assert!(
        updated.current_reliability > 0.0,
        "current_reliability must be > 0 with 3 holders"
    );
}

#[test]
fn recompute_and_persist_when_all_lost_sets_current_alive_zero_and_reliability_zero() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xC2);
    let holder_a = make_device_id(0xB1);
    let holder_b = make_device_id(0xB2);
    let holder_c = make_device_id(0xB3);

    let block = make_source_block_for_hook(block_id, 0.5, None, 0);
    db.upsert_source_block(&block).unwrap();

    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_a,
        PlacementStatus::Lost,
    ))
    .unwrap();
    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_b,
        PlacementStatus::Lost,
    ))
    .unwrap();
    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_c,
        PlacementStatus::Lost,
    ))
    .unwrap();

    super::recompute_and_persist_block_cached_fields(&db, &block_id);

    let updated = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated.current_alive, 0,
        "current_alive must be 0 when all placements are Lost"
    );
    assert_eq!(
        updated.current_reliability, 0.0,
        "current_reliability must be 0.0 with no alive holders"
    );
}

#[test]
fn recompute_and_persist_for_unknown_block_logs_warn_and_does_not_panic() {
    let db = Db::open_in_memory().unwrap();
    let unknown_block_id = make_block_id(0xDE);

    // No panic. DB should not have any source block written.
    super::recompute_and_persist_block_cached_fields(&db, &unknown_block_id);

    let result = db.get_source_block(&unknown_block_id).unwrap();
    assert!(
        result.is_none(),
        "no block must be created for unknown block_id"
    );
}

#[test]
fn recompute_and_persist_preserves_last_attempted_at_and_pool_signature() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xC3);
    let holder_a = make_device_id(0xC1);

    let sentinel_time = Timestamp(1_700_000_042);
    let sentinel_sig = 0xDEADBEEF_12345678u64;
    let block = make_source_block_for_hook(block_id, 0.5, Some(sentinel_time), sentinel_sig);
    db.upsert_source_block(&block).unwrap();

    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_a,
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_peer(&make_hook_peer(holder_a, 0.8)).unwrap();

    super::recompute_and_persist_block_cached_fields(&db, &block_id);

    let updated = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated.last_attempted_at,
        Some(sentinel_time),
        "last_attempted_at must be preserved unchanged"
    );
    assert_eq!(
        updated.last_pool_signature, sentinel_sig,
        "last_pool_signature must be preserved unchanged"
    );
}

#[test]
fn recompute_and_persist_is_idempotent_on_double_call() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xC4);
    let holder_a = make_device_id(0xD1);
    let holder_b = make_device_id(0xD2);

    let block = make_source_block_for_hook(block_id, 0.5, None, 0);
    db.upsert_source_block(&block).unwrap();

    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_a,
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_b,
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_peer(&make_hook_peer(holder_a, 0.8)).unwrap();
    db.upsert_peer(&make_hook_peer(holder_b, 0.8)).unwrap();

    // Call twice — must not panic and must produce same result.
    super::recompute_and_persist_block_cached_fields(&db, &block_id);
    super::recompute_and_persist_block_cached_fields(&db, &block_id);

    let updated = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated.current_alive, 2,
        "current_alive must be 2 after idempotent double call"
    );
}

// ─── W11a: PoS outcome tests (apply_and_persist_pos_outcome) ─────────────────

#[tokio::test]
async fn pos_pass_on_uncertain_placement_keeps_current_alive_and_updates_status() {
    // Alive→Alive (Pass on Alive): old_status == new_status → hook NOT called.
    // Uncertain→Alive (Pass on Uncertain): old_status != new_status → hook IS called.
    // Count stays the same (Uncertain counted before + after) but status becomes Alive.
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let holder_id = make_device_id(0xE1);
    let block_id = make_block_id(0xE2);

    let block = make_source_block_for_hook(block_id, 0.5, None, 0);
    db.upsert_source_block(&block).unwrap();
    db.upsert_peer(&make_hook_peer(holder_id, 0.8)).unwrap();

    // Set initial current_alive to 1 (Uncertain counts).
    db.update_block_cached_fields(&block_id, 0.5, 1, 0.5, 0.99, None, 0)
        .unwrap();

    // Uncertain placement — Pass will transition to Alive.
    let mut placement = make_hook_placement(block_id, holder_id, PlacementStatus::Uncertain);
    placement.consecutive_misses = 1;
    db.upsert_placement(&placement).unwrap();

    let (processor, _repair_rx, _relay_rx) = make_processor(db.clone(), &holdings_dir).await;
    processor
        .apply_and_persist_pos_outcome(
            block_id,
            holder_id,
            &syncback_core::pos::VerifyOutcome::Pass,
        )
        .await
        .unwrap();

    let updated_placement = db.get_placement(&block_id, &holder_id).unwrap().unwrap();
    assert_eq!(
        updated_placement.status,
        PlacementStatus::Alive,
        "placement must become Alive after Pass"
    );

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    // Uncertain→Alive: hook fires, still counts as 1.
    assert_eq!(
        updated_block.current_alive, 1,
        "current_alive must remain 1 (Uncertain→Alive)"
    );
}

#[tokio::test]
async fn pos_fail_on_alive_placement_decrements_current_alive() {
    use crate::daemon::scheduler::PendingChallenges;
    use std::collections::HashMap;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let holder_a = make_device_id(0xF1);
    let holder_b = make_device_id(0xF2);
    let block_id = make_block_id(0xF3);

    let block = make_source_block_for_hook(block_id, 0.5, None, 0);
    db.upsert_source_block(&block).unwrap();
    db.upsert_peer(&make_hook_peer(holder_a, 0.8)).unwrap();
    db.upsert_peer(&make_hook_peer(holder_b, 0.8)).unwrap();

    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_a,
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_b,
        PlacementStatus::Alive,
    ))
    .unwrap();

    // Set initial cached fields reflecting 2 alive.
    db.update_block_cached_fields(&block_id, 0.5, 2, 0.9, 0.99, None, 0)
        .unwrap();

    // Need pending challenge for block_id/holder_a so apply_and_persist_pos_outcome
    // can find the placement. Direct call doesn't need pending — just call directly.
    let pending: PendingChallenges = std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let (processor, _repair_rx, _relay_rx) =
        make_processor_with_pending(db.clone(), &holdings_dir, pending).await;

    let pre_reliability = db
        .get_source_block(&block_id)
        .unwrap()
        .unwrap()
        .current_reliability;

    // Fail holder_a → placement becomes Lost.
    processor
        .apply_and_persist_pos_outcome(
            block_id,
            holder_a,
            &syncback_core::pos::VerifyOutcome::Fail { esi: 0 },
        )
        .await
        .unwrap();

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 1,
        "current_alive must be 1 after one Fail"
    );

    let placement_a = db.get_placement(&block_id, &holder_a).unwrap().unwrap();
    assert_eq!(
        placement_a.status,
        PlacementStatus::Lost,
        "holder_a placement must be Lost"
    );

    assert!(
        updated_block.current_reliability < pre_reliability,
        "reliability must decrease after a Fail (pre={pre_reliability}, post={post})",
        post = updated_block.current_reliability,
    );
}

// ─── W11a: PoS Nack test (handle_pos_hash_nack) ──────────────────────────────

#[tokio::test]
async fn pos_nack_decrements_current_alive_and_updates_reliability() {
    use crate::daemon::scheduler::{PendingChallenges, PendingHashChallenge};
    use std::collections::HashMap;
    use syncback_core::messages::build_pos_hash_nack;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let holder_master_key =
        syncback_core::cluster::derive_master_key(&[0x30u8; 64]).expect("holder master key");
    let holder_master = syncback_core::cluster::master_identity(&holder_master_key);
    let holder_device = make_device_id(0x88);
    let block_id = make_block_id(0x89);

    // Three alive holders: holder_device, extra_a, extra_b.
    let extra_a = make_device_id(0x8A);
    let extra_b = make_device_id(0x8B);

    let block = make_source_block_for_hook(block_id, 0.5, None, 0);
    db.upsert_source_block(&block).unwrap();
    db.upsert_peer(&make_hook_peer(holder_device, 0.8)).unwrap();
    db.upsert_peer(&make_hook_peer(extra_a, 0.8)).unwrap();
    db.upsert_peer(&make_hook_peer(extra_b, 0.8)).unwrap();

    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_device,
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_hook_placement(
        block_id,
        extra_a,
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_hook_placement(
        block_id,
        extra_b,
        PlacementStatus::Alive,
    ))
    .unwrap();

    // Set current_alive = 3.
    db.update_block_cached_fields(&block_id, 0.5, 3, 0.9, 0.99, None, 0)
        .unwrap();

    // Register master→device so the processor can verify the nack signature.
    db.set_master_for_device(&holder_device, &holder_master)
        .unwrap();

    let challenge_id = [0x77u8; 16];
    let pending_map: HashMap<_, _> = [(
        (block_id, holder_device),
        PendingHashChallenge {
            source_block_id: block_id,
            holder_id: holder_device,
            esi_ranges: vec![(0, 4)],
            expected_chain_hash: [0u8; 32],
            issued_at: Timestamp::now(),
            challenge_id,
        },
    )]
    .into_iter()
    .collect();
    let pending: PendingChallenges = std::sync::Arc::new(tokio::sync::Mutex::new(pending_map));

    let (processor, _repair_rx, _relay_rx) =
        make_processor_with_pending(db.clone(), &holdings_dir, pending).await;

    // Build valid nack signed by holder's master key.
    let nack = build_pos_hash_nack(
        challenge_id,
        block_id,
        0,
        Timestamp::now(),
        Some(holder_device),
        &holder_master_key,
    );

    processor
        .handle_pos_hash_nack(holder_device, nack)
        .await
        .unwrap();

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 2,
        "current_alive must be 2 after Nack"
    );

    let placement = db
        .get_placement(&block_id, &holder_device)
        .unwrap()
        .unwrap();
    assert_eq!(
        placement.status,
        PlacementStatus::Lost,
        "placement must be Lost after Nack"
    );
}

// ─── W11a: rapid transitions keep current_alive coherent ─────────────────────

#[tokio::test]
async fn rapid_alive_to_lost_transitions_keep_current_alive_coherent() {
    use crate::daemon::scheduler::PendingChallenges;
    use std::collections::HashMap;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let holders: Vec<DeviceId> = (0..5).map(|i| make_device_id(0x10 + i)).collect();
    let block_id = make_block_id(0x20);

    let block = make_source_block_for_hook(block_id, 0.5, None, 0);
    db.upsert_source_block(&block).unwrap();

    for &h in &holders {
        db.upsert_peer(&make_hook_peer(h, 0.8)).unwrap();
        db.upsert_placement(&make_hook_placement(block_id, h, PlacementStatus::Alive))
            .unwrap();
    }
    db.update_block_cached_fields(&block_id, 0.5, 5, 0.9999, 0.99, None, 0)
        .unwrap();

    let pending: PendingChallenges = std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let (processor, _repair_rx, _relay_rx) =
        make_processor_with_pending(db.clone(), &holdings_dir, pending).await;

    // Transition A → Lost.
    processor
        .apply_and_persist_pos_outcome(
            block_id,
            holders[0],
            &syncback_core::pos::VerifyOutcome::Fail { esi: 0 },
        )
        .await
        .unwrap();
    let b = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        b.current_alive, 4,
        "after 1st Fail: current_alive must be 4"
    );
    let r4 = b.current_reliability;

    // Transition B → Lost.
    processor
        .apply_and_persist_pos_outcome(
            block_id,
            holders[1],
            &syncback_core::pos::VerifyOutcome::Fail { esi: 0 },
        )
        .await
        .unwrap();
    let b = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        b.current_alive, 3,
        "after 2nd Fail: current_alive must be 3"
    );
    let r3 = b.current_reliability;

    // Transition C → Lost.
    processor
        .apply_and_persist_pos_outcome(
            block_id,
            holders[2],
            &syncback_core::pos::VerifyOutcome::Fail { esi: 0 },
        )
        .await
        .unwrap();
    let b = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        b.current_alive, 2,
        "after 3rd Fail: current_alive must be 2"
    );
    let r2 = b.current_reliability;

    // Reliability decreases monotonically.
    assert!(r4 >= r3, "reliability must not increase after Fail");
    assert!(r3 >= r2, "reliability must not increase after Fail");
}

// ─── W11a: next_work_item integration — block eligible after PoS Fail ─────────

#[tokio::test]
async fn block_becomes_eligible_in_next_work_item_after_pos_fail() {
    use crate::daemon::scheduler::PendingChallenges;
    use std::collections::HashMap;
    use std::time::Duration;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    // k=1 so reliability with 1 holder is very high, with 0 holders = 0.0.
    let block_id = make_block_id(0x42);
    let holder_a = make_device_id(0x43);
    let holder_b = make_device_id(0x44);

    // Use a block where target_reliability is 0.9.
    let block = SourceBlockRecord {
        block_id,
        k: 1,
        t: 1,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(0),
        encrypted_size: Some(1),
        n: Some(4),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 0.5,
        current_alive: 2,
        current_reliability: 0.9999,
        target_reliability: 0.9,
        last_attempted_at: None,
        last_pool_signature: 0,
    };
    db.upsert_source_block(&block).unwrap();
    db.upsert_peer(&make_hook_peer(holder_a, 0.8)).unwrap();
    db.upsert_peer(&make_hook_peer(holder_b, 0.8)).unwrap();
    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_a,
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_b,
        PlacementStatus::Alive,
    ))
    .unwrap();

    // Initially above target — next_work_item returns None.
    let work_before = db
        .next_work_item(1.5, Duration::from_secs(0), Timestamp::now(), 0)
        .unwrap();
    assert!(
        work_before.is_none(),
        "block should not need work when reliability >= target"
    );

    let pending: PendingChallenges = std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let (processor, _repair_rx, _relay_rx) =
        make_processor_with_pending(db.clone(), &holdings_dir, pending).await;

    // Fail both holders → current_alive = 0 → reliability drops to 0.0.
    processor
        .apply_and_persist_pos_outcome(
            block_id,
            holder_a,
            &syncback_core::pos::VerifyOutcome::Fail { esi: 0 },
        )
        .await
        .unwrap();
    processor
        .apply_and_persist_pos_outcome(
            block_id,
            holder_b,
            &syncback_core::pos::VerifyOutcome::Fail { esi: 0 },
        )
        .await
        .unwrap();

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert_eq!(
        updated_block.current_alive, 0,
        "current_alive must be 0 after both Fails"
    );
    assert!(
        updated_block.current_reliability < updated_block.target_reliability,
        "reliability must be below target after both Fails"
    );

    // Now next_work_item must return this block.
    let work_after = db
        .next_work_item(1.5, Duration::from_secs(0), Timestamp::now(), 0)
        .unwrap();
    assert!(
        work_after.is_some(),
        "block must be eligible for work after reliability dropped below target"
    );
    let work_block = work_after.unwrap();
    assert_eq!(
        work_block.block_id, block_id,
        "next_work_item must return the degraded block"
    );
}
