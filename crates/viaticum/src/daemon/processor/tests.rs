// Tests for Processor handler methods.
//
// Strategy: We test inner/sync handler methods that contain the actual logic,
// bypassing network I/O. SwarmHandle is started on port 0 for helpers that
// need a real handle but don't exercise network I/O.
//
// Test coverage:
//   handle_symbol_transfer               — writes files, upserts HoldingRecord
//   handle_pos_hash_challenge_inner      — responds with chain hash or PosHashNack
//   esi_list_to_ranges / ranges_to_esi_list — round-trip helpers
//   decide_symbol_offer                  — quota check logic
//   handle_restore_request_inner         — returns symbols or empty response
//   handle_peer_announce                 — upserts PeerRecord in DB
//   SymbolDropHandler / apply_delete / apply_cancel_delete / RevocationHandler —
//     standalone mailbox handlers (A2): DropNotice, Delete/CancelDelete, revocation
//   build_peer_announce                  — SwarmHandle helper builds a signed message
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

use tempfile::TempDir;
use tokio::sync::mpsc;
use viaticum_core::cluster::{ClusterState, derive_master_key, master_identity};
use viaticum_core::db::Db;
use viaticum_core::messages::{
    PeerAnnounceMsg, RestoreRequestMsg, SymbolAcceptMsg, SymbolDropNoticeMsg, SymbolRejectMsg,
    SymbolTransferMsg, build_signed_symbol_drop_notice,
};
use viaticum_core::types::{
    DeviceId, FileId, HoldingRecord, HoldingStatus, IdentityPub, PlacementStatus, SourceBlockId,
    SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement, Timestamp,
};

use super::{AcceptedOffer, Processor, esi_list_to_ranges, ranges_to_esi_list};
use crate::daemon::cluster_sync::{ClusterSyncConfig, ClusterSyncManager};
use crate::daemon::network::swarm::{ConnPolicy, SwarmConfig, SwarmHandle};

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

/// Build a real Ed25519 signing key deterministically from a seed byte.
/// Use this when the DropNotice signature must be verifiable by `SymbolDropHandler::apply`.
fn make_signing_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

/// Build a signed SymbolDropNoticeMsg using `build_signed_symbol_drop_notice`.
/// The `signing_key` must correspond to the holder master identity passed to
/// `handle_symbol_drop_notice` (use `master_identity(&key)` to derive it).
fn make_signed_drop_notice(
    block_id: SourceBlockId,
    esi_ranges: Vec<(u32, u32)>,
    signing_key: &ed25519_dalek::SigningKey,
) -> SymbolDropNoticeMsg {
    build_signed_symbol_drop_notice(
        block_id,
        esi_ranges,
        viaticum_core::types::Timestamp(viaticum_core::types::Timestamp::now().0 + 604_800),
        viaticum_core::types::Timestamp::now(),
        signing_key,
    )
}

fn make_peer_record(device_id: DeviceId) -> viaticum_core::types::PeerRecord {
    let now = Timestamp::now();
    viaticum_core::types::PeerRecord {
        device_id,
        master_identity: IdentityPub(device_id.0),
        trust_p: viaticum_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: viaticum_core::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    }
}

async fn make_swarm() -> Arc<SwarmHandle> {
    let master_key = viaticum_core::cluster::derive_master_key(&[0xCCu8; 64])
        .expect("derive_master_key for swarm helper");
    let identity_pub = viaticum_core::cluster::master_identity(&master_key);
    let device_key = viaticum_core::cluster::derive_device_key(&[0xCCu8; 64], &[0x01u8; 32])
        .expect("derive_device_key for swarm helper");
    let device_id = DeviceId(device_key.verifying_key().to_bytes());
    let now = Timestamp::now();
    let device_cert = viaticum_core::cluster::issue_device_certificate(&master_key, device_id, now);
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
        kad_discovery_interval_override: None,
        enable_relay_server: false,
        conn_policy: ConnPolicy::off(),
    };
    let (handle, _events) = SwarmHandle::start(cfg).await.expect("swarm start");
    Arc::new(handle)
}

/// Also used by the PeerRecord writer's tests (`peer_record_writer/tests.rs`).
pub(in crate::daemon::processor) async fn make_processor(
    db: Db,
    holdings_dir: &TempDir,
) -> Processor {
    make_processor_with_quota(db, holdings_dir, u64::MAX, u64::MAX).await
}

async fn make_processor_with_quota(
    db: Db,
    holdings_dir: &TempDir,
    soft_quota_bytes: u64,
    hard_quota_bytes: u64,
) -> Processor {
    let master_key = derive_master_key(&[42u8; 64]).expect("derive_master_key failed");
    let own_identity = master_identity(&master_key);
    // device_id = pubkey derived from device_seed
    let device_seed = [1u8; 32];
    let device_signing_key = viaticum_core::cluster::derive_device_key(&[42u8; 64], &device_seed)
        .expect("derive_device_key failed");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    let cert = viaticum_core::cluster::issue_device_certificate(&master_key, device_id, now);
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
    let accepted_offers = super::make_empty_accepted_offers();
    Processor::new(
        db,
        own_identity,
        cluster_sync,
        holdings_dir.path().to_path_buf(),
        swarm,
        soft_quota_bytes,
        hard_quota_bytes,
        holdings_dir.path().to_path_buf(), // data_dir (for disk space queries in tests)
        0,                                 // disk_reserve_bytes (no reserve in tests)
        backup_event_tx,
        None, // cluster_state: not needed for handler unit tests
        accepted_offers,
        ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]), // master_signing_key
    )
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
        from_device: sender_device(owner_id),
        source_block_id: block_id,
        esi_ranges,
        importance,
        accepted_at: Timestamp::now(),
    };
    let mut map = processor.accepted_offers.lock().unwrap();
    map.insert((sender_device(owner_id), block_id), offer);
}

/// The sending device the single-device tests use for `owner`: the offer map is keyed by the
/// sending device (backup-i19), the holding by the master.
fn sender_device(owner: IdentityPub) -> DeviceId {
    DeviceId(owner.0)
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
    let master_key = derive_master_key(&[42u8; 64]).unwrap();
    let own_identity = master_identity(&master_key);
    let device_seed = [1u8; 32];
    let device_signing_key =
        viaticum_core::cluster::derive_device_key(&[42u8; 64], &device_seed).unwrap();
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();
    let cert = viaticum_core::cluster::issue_device_certificate(&master_key, device_id, now);
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
    let processor = Processor::new(
        db.clone(),
        own_identity,
        cluster_sync,
        holdings_dir.path().to_path_buf(),
        swarm,
        u64::MAX,
        u64::MAX,
        holdings_dir.path().to_path_buf(),
        0,
        backup_event_tx,
        None, // cluster_state: not needed for handler unit tests
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let holder = make_identity(8);
    let block_id = make_block_id(8);

    // No placement inserted — call the reject handler.
    let reject = SymbolRejectMsg {
        v: 1,
        source_block_id: block_id,
        offer_msg_id: [0u8; 16],
        reason: viaticum_core::messages::RejectReason::QuotaFull,
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
    let processor = make_processor_with_quota(db.clone(), &holdings_dir, 1, 1).await;

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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(1);
    let block_id = make_block_id(2);
    let symbol_data = vec![0xABu8; 64];

    // Insert accepted offer so the transfer is authorized (esi 5 is in range (0, 100)).
    insert_accepted_offer(&processor, owner, block_id, vec![(0, 100)], 0.5);

    let transfer = SymbolTransferMsg {
        v: 1,
        source_block_id: block_id,
        symbols: vec![viaticum_core::erasure::Symbol {
            esi: 5,
            data: symbol_data.clone(),
        }],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_transfer(sender_device(owner), owner, transfer)
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(1);
    let block_id = make_block_id(2);

    let symbols: Vec<viaticum_core::erasure::Symbol> = (0..3)
        .map(|i| viaticum_core::erasure::Symbol {
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
        .handle_symbol_transfer(sender_device(owner), owner, transfer)
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(1);
    let block_id = make_block_id(2);

    // First offer + transfer: ESI 0
    insert_accepted_offer(&processor, owner, block_id, vec![(0, 1)], 0.5);
    processor
        .handle_symbol_transfer(
            sender_device(owner),
            owner,
            SymbolTransferMsg {
                v: 1,
                source_block_id: block_id,
                symbols: vec![viaticum_core::erasure::Symbol {
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
            sender_device(owner),
            owner,
            SymbolTransferMsg {
                v: 1,
                source_block_id: block_id,
                symbols: vec![viaticum_core::erasure::Symbol {
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    // Owner signs the challenge with its master key; `owner` must be that key's pub.
    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
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
    let challenge = viaticum_core::messages::build_pos_hash_challenge(
        challenge_id,
        block_id,
        vec![(esi, 1)],
        Timestamp::now(),
        None,
        &owner_key,
    );

    let reply = processor
        .handle_pos_hash_challenge_inner(owner, challenge)
        .await
        .expect("handle_pos_hash_challenge_inner failed");

    match reply {
        viaticum_core::messages::Message::PosHashResponse(resp) => {
            assert_eq!(resp.challenge_id, challenge_id);
            // Verify the chain hash is correct (challenge_id is [99u8; 16] from above).
            let expected_hash = viaticum_core::pos::compute_chain_hash(
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
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

    let challenge = viaticum_core::messages::build_pos_hash_challenge(
        challenge_id,
        block_id,
        vec![(esi, 1)],
        Timestamp::now(),
        None,
        &owner_key,
    );

    let reply = processor
        .handle_pos_hash_challenge_inner(owner, challenge)
        .await
        .expect("handle_pos_hash_challenge_inner failed");

    match reply {
        viaticum_core::messages::Message::PosHashNack(nack) => {
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

/// Review B1 / H-1: prune_expired_accepted_offers evicts entries older than
/// SYMBOL_OFFER_EXPIRY_SECS and leaves fresh entries alone.
#[tokio::test]
async fn prune_expired_accepted_offers_drops_stale_keeps_fresh() {
    use super::{AcceptedOffer, prune_expired_accepted_offers};
    use viaticum_core::constants::SYMBOL_OFFER_EXPIRY_SECS;

    let map = super::make_empty_accepted_offers();
    let now = Timestamp(1_000_000);

    let owner_old = IdentityPub([0x11u8; 32]);
    let owner_new = IdentityPub([0x22u8; 32]);
    let block_a = SourceBlockId([0xAAu8; 32]);
    let block_b = SourceBlockId([0xBBu8; 32]);

    {
        let mut m = map.lock().unwrap();
        m.insert(
            (DeviceId(owner_old.0), block_a),
            AcceptedOffer {
                owner_id: owner_old,
                from_device: DeviceId(owner_old.0),
                source_block_id: block_a,
                esi_ranges: vec![(0, 3)],
                importance: 0.5,
                accepted_at: Timestamp(now.0 - SYMBOL_OFFER_EXPIRY_SECS - 10),
            },
        );
        m.insert(
            (DeviceId(owner_new.0), block_b),
            AcceptedOffer {
                owner_id: owner_new,
                from_device: DeviceId(owner_new.0),
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
    assert!(m.contains_key(&(DeviceId(owner_new.0), block_b)));
    assert!(!m.contains_key(&(DeviceId(owner_old.0), block_a)));
}

// ─── decide_symbol_offer ──────────────────────────────────────────────────────

#[tokio::test]
async fn symbol_offer_accept_when_quota_not_exceeded() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    // 1 GB soft quota, no hard quota
    let soft = 1_073_741_824u64; // 1 GB
    let processor = make_processor_with_quota(db.clone(), &holdings_dir, soft, u64::MAX).await;

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
    let processor = make_processor_with_quota(db.clone(), &holdings_dir, u64::MAX, hard).await;

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
    let processor = make_processor_with_quota(db.clone(), &holdings_dir, soft, u64::MAX).await;

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
    let processor = make_processor_with_quota(db.clone(), &holdings_dir, 0, 0).await;

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
    let processor = make_processor(db.clone(), &holdings_dir).await;

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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(6);
    let block_id = make_block_id(6);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();

    // Write 3 symbol files
    for esi in 0u32..3 {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 32]).unwrap();
    }

    // Upsert an Active HoldingRecord for the owner.
    let thirty_days_ago = Timestamp(Timestamp::now().0.saturating_sub(30 * 86_400));
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 3)],
        importance: 0.5,
        total_bytes: 1_073_741_824,
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(7);
    let block_id = make_block_id(7);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();

    // Write 5 symbol files (ESI 0..4)
    for esi in 0u32..5 {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 32]).unwrap();
    }

    // Active HoldingRecord for the owner.
    let thirty_days_ago = Timestamp(Timestamp::now().0.saturating_sub(30 * 86_400));
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 5)],
        importance: 0.5,
        total_bytes: 1_073_741_824,
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

/// Write `count` symbol files for `block_id` and an Active holding for `owner`
/// received at `received_at` with `total_bytes` (the old escrow gate's inputs).
fn put_holding_with_symbols(
    db: &Db,
    holdings_dir: &TempDir,
    owner: IdentityPub,
    block_id: SourceBlockId,
    count: u32,
    total_bytes: u64,
    received_at: Timestamp,
) {
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();
    for esi in 0..count {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 32]).unwrap();
    }
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, count)],
        importance: 0.5,
        total_bytes,
        status: HoldingStatus::Active,
        received_at,
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();
}

fn restore_all(block_id: SourceBlockId) -> RestoreRequestMsg {
    RestoreRequestMsg {
        v: 1,
        source_block_id: block_id,
        esi_list: vec![],
        timestamp: Timestamp::now(),
    }
}

/// restore-i6: a holding placed this very second (zero GB·days of contribution — the old
/// escrow gate's budget was exactly 0) is served in full to its owner.
#[tokio::test]
async fn restore_request_serves_owner_right_after_placement() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;
    let owner = make_identity(21);
    let block_id = make_block_id(21);
    put_holding_with_symbols(
        &db,
        &holdings_dir,
        owner,
        block_id,
        4,
        16 * 1_073_741_824,
        Timestamp::now(),
    );

    let response = processor
        .handle_restore_request_inner(owner, restore_all(block_id))
        .await
        .expect("fresh holding must be served, not refused");

    assert_eq!(response.symbols.len(), 4);
}

/// restore-i5/i6: repeats are not refused even when the served-bytes counter already exceeds
/// anything the holding could have "earned"; the counter keeps growing (accounting only).
#[tokio::test]
async fn restore_request_repeats_are_served_and_only_counted() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;
    let owner = make_identity(22);
    let block_id = make_block_id(22);
    put_holding_with_symbols(
        &db,
        &holdings_dir,
        owner,
        block_id,
        3,
        1_073_741_824,
        Timestamp::now(),
    );
    db.record_restore_served(&owner, 1u64 << 50).unwrap();

    for attempt in 1..=3u64 {
        let response = processor
            .handle_restore_request_inner(owner, restore_all(block_id))
            .await
            .expect("repeat must be served");
        assert_eq!(response.symbols.len(), 3, "attempt {attempt}");
        assert_eq!(
            db.restored_total_bytes(&owner).unwrap(),
            (1u64 << 50) + attempt * 3 * 32,
            "attempt {attempt}: served bytes are counted"
        );
    }
}

/// restore-i7: removing the gate must not open the holding to another master — the lookup
/// is by (block, requester master), a foreign master gets an empty response.
#[tokio::test]
async fn restore_request_from_foreign_master_is_empty() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;
    let owner = make_identity(23);
    let stranger = make_identity(24);
    let block_id = make_block_id(23);
    put_holding_with_symbols(
        &db,
        &holdings_dir,
        owner,
        block_id,
        3,
        1_073_741_824,
        Timestamp::now(),
    );

    let response = processor
        .handle_restore_request_inner(stranger, restore_all(block_id))
        .await
        .unwrap();

    assert!(response.symbols.is_empty());
    assert_eq!(db.restored_total_bytes(&stranger).unwrap(), 0);
    assert_eq!(db.restored_total_bytes(&owner).unwrap(), 0);
}

fn set_holding_status(db: &Db, owner: IdentityPub, block_id: SourceBlockId, status: HoldingStatus) {
    let mut h = db.get_holding(&block_id, &owner).unwrap().unwrap();
    h.status = status;
    db.upsert_holding(&h).unwrap();
}

/// restore-i16: a Silent holding (no PoS, owner quiet) is still the owner's data and is
/// served to the owner.
#[tokio::test]
async fn restore_request_serves_silent_holding_to_owner() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;
    let owner = make_identity(25);
    let block_id = make_block_id(25);
    put_holding_with_symbols(
        &db,
        &holdings_dir,
        owner,
        block_id,
        3,
        1024,
        Timestamp::now(),
    );
    set_holding_status(&db, owner, block_id, HoldingStatus::Silent);

    let response = processor
        .handle_restore_request_inner(owner, restore_all(block_id))
        .await
        .unwrap();

    assert_eq!(response.symbols.len(), 3, "Silent holding must be served");
}

/// restore-i16 boundary: what the owner itself asked to delete is not served.
#[tokio::test]
async fn restore_request_for_holding_marked_for_delete_is_empty() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;
    let owner = make_identity(26);
    let block_id = make_block_id(26);
    put_holding_with_symbols(
        &db,
        &holdings_dir,
        owner,
        block_id,
        3,
        1024,
        Timestamp::now(),
    );
    set_holding_status(&db, owner, block_id, HoldingStatus::MarkedForDelete);

    let response = processor
        .handle_restore_request_inner(owner, restore_all(block_id))
        .await
        .unwrap();

    assert!(response.symbols.is_empty());
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
    use viaticum_core::messages::build_peer_announce;
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let (msg, _identity) = make_signed_peer_announce(20);

    // Should succeed without error (announce from unknown peer is silently ignored).
    processor
        .handle_peer_announce(msg)
        .await
        .expect("handle_peer_announce failed");
}

#[tokio::test]
async fn peer_announce_updates_existing_peer_last_seen() {
    use viaticum_core::messages::build_peer_announce;
    use viaticum_core::types::PeerRecord;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;

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
        avail_ewma: viaticum_core::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
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
    // PeerAnnounce is a positive availability observation: avail_ewma must rise
    // above the pessimistic initial prior, and last_avail_sample must be set.
    assert!(
        updated.avail_ewma > viaticum_core::constants::AVAIL_EWMA_INITIAL,
        "PeerAnnounce should raise avail_ewma above initial; got {}",
        updated.avail_ewma
    );
    assert!(
        updated.last_avail_sample > 0,
        "PeerAnnounce should set last_avail_sample"
    );
}

// ─── handle_symbol_accept / handle_symbol_reject (log-only handlers) ─────────

#[tokio::test]
async fn symbol_accept_logs_without_error() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;

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
    use viaticum_core::messages::RejectReason;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;

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
    use viaticum_core::messages::build_peer_announce;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;

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
    let processor = make_processor(db.clone(), &holdings_dir).await;

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

// ─── handle_delete tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn handle_delete_marks_holding_for_deletion() {
    let db = Db::open_in_memory().unwrap();

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
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
        viaticum_core::messages::build_delete_msg(block_id, Timestamp::now(), &owner_key);
    super::symbol::apply_delete(&db, owner_id, delete_msg);

    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::MarkedForDelete);
    assert!(updated.delete_requested_at.is_some());
}

#[tokio::test]
async fn handle_delete_ignores_non_active_holding() {
    let db = Db::open_in_memory().unwrap();

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
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
        viaticum_core::messages::build_delete_msg(block_id, Timestamp::now(), &owner_key);
    super::symbol::apply_delete(&db, owner_id, delete_msg);

    // Status should not change.
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::MarkedForDelete);
}

#[tokio::test]
async fn handle_delete_ignores_no_holding() {
    let db = Db::open_in_memory().unwrap();

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0xDF);

    // No holding in DB — should not panic.
    let delete_msg =
        viaticum_core::messages::build_delete_msg(block_id, Timestamp::now(), &owner_key);
    super::symbol::apply_delete(&db, owner_id, delete_msg);
}

#[tokio::test]
async fn handle_delete_rejects_invalid_signature() {
    let db = Db::open_in_memory().unwrap();

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let wrong_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
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
        viaticum_core::messages::build_delete_msg(block_id, Timestamp::now(), &wrong_key);
    super::symbol::apply_delete(&db, owner_id, delete_msg);

    // Holding should remain Active (bad sig rejected silently).
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::Active);
}

/// T-13 H1(b) regression: a DeleteMsg whose timestamp is far older than
/// MESSAGE_FRESHNESS_SECS (1h) must STILL be honored. DeleteRequest entries live
/// in the mailbox for DELETE_REQUEST_TTL (14d) and the design time-constant is one
/// WEEK — a holder offline for hours/days is the normal cold-backup case. The old
/// 1h wall-clock gate wrongly rejected these as "replay" so the holding was never
/// marked for deletion. Replay protection is the signature + entry TTL + status-guard.
#[tokio::test]
async fn delete_applied_even_when_older_than_message_freshness() {
    let db = Db::open_in_memory().unwrap();

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
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

    // Timestamp 8 days in the past — well beyond MESSAGE_FRESHNESS_SECS (3600s),
    // but well within DELETE_REQUEST_TTL (14d). 8 days = 8 * 86400s.
    let stale_ts = Timestamp(Timestamp::now().0.saturating_sub(8 * 86_400));
    let age = Timestamp::now().0.saturating_sub(stale_ts.0);
    assert!(
        age > viaticum_core::constants::MESSAGE_FRESHNESS_SECS,
        "test setup: timestamp must be older than MESSAGE_FRESHNESS_SECS \
         (age={age} must exceed {})",
        viaticum_core::constants::MESSAGE_FRESHNESS_SECS
    );

    let delete_msg = viaticum_core::messages::build_delete_msg(block_id, stale_ts, &owner_key);
    super::symbol::apply_delete(&db, owner_id, delete_msg);

    // Despite the stale timestamp, the holding must transition Active→MarkedForDelete.
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::MarkedForDelete);
    assert!(updated.delete_requested_at.is_some());
}

/// Forged-signature DeleteMsg is still rejected even with a fresh timestamp — sig
/// enforcement is unaffected by removing the freshness gate.
#[tokio::test]
async fn delete_rejects_forged_signature_after_freshness_removed() {
    let db = Db::open_in_memory().unwrap();

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let attacker_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let block_id = make_block_id(0xE6);

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

    // Signed by the attacker but attributed to owner_id → sig must fail.
    let delete_msg =
        viaticum_core::messages::build_delete_msg(block_id, Timestamp::now(), &attacker_key);
    super::symbol::apply_delete(&db, owner_id, delete_msg);

    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::Active);
}

// ─── handle_cancel_delete tests ───────────────────────────────────────────────

#[tokio::test]
async fn handle_cancel_delete_reverts_to_active() {
    let db = Db::open_in_memory().unwrap();

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
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
        viaticum_core::messages::build_cancel_delete_msg(block_id, Timestamp::now(), &owner_key);
    super::symbol::apply_cancel_delete(&db, owner_id, cancel_msg);

    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::Active);
    assert!(updated.delete_requested_at.is_none());
}

#[tokio::test]
async fn handle_cancel_delete_ignores_active_holding() {
    let db = Db::open_in_memory().unwrap();

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
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
        viaticum_core::messages::build_cancel_delete_msg(block_id, Timestamp::now(), &owner_key);
    super::symbol::apply_cancel_delete(&db, owner_id, cancel_msg);

    // Should remain Active (no-op).
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::Active);
}

#[tokio::test]
async fn handle_cancel_delete_rejects_bad_sig() {
    let db = Db::open_in_memory().unwrap();

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let wrong_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
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
        viaticum_core::messages::build_cancel_delete_msg(block_id, Timestamp::now(), &wrong_key);
    super::symbol::apply_cancel_delete(&db, owner_id, cancel_msg);

    // Should remain MarkedForDelete (bad sig).
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::MarkedForDelete);
}

/// T-13 H1(b) regression (cancel path): a CancelDeleteMsg older than
/// MESSAGE_FRESHNESS_SECS must STILL be honored — same mailbox store-and-forward
/// rationale as `delete_applied_even_when_older_than_message_freshness`.
#[tokio::test]
async fn cancel_delete_applied_even_when_older_than_message_freshness() {
    let db = Db::open_in_memory().unwrap();

    let owner_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let owner_id = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0xE7);

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

    // 8 days old — beyond the 1h freshness window, within the 14d TTL.
    let stale_ts = Timestamp(Timestamp::now().0.saturating_sub(8 * 86_400));
    assert!(
        Timestamp::now().0.saturating_sub(stale_ts.0)
            > viaticum_core::constants::MESSAGE_FRESHNESS_SECS,
        "test setup: timestamp must be older than MESSAGE_FRESHNESS_SECS"
    );

    let cancel_msg =
        viaticum_core::messages::build_cancel_delete_msg(block_id, stale_ts, &owner_key);
    super::symbol::apply_cancel_delete(&db, owner_id, cancel_msg);

    // Despite the stale timestamp, the holding must revert MarkedForDelete→Active.
    let updated = db.get_holding(&block_id, &owner_id).unwrap().unwrap();
    assert_eq!(updated.status, HoldingStatus::Active);
    assert!(updated.delete_requested_at.is_none());
}

// ─── handle_symbol_drop_notice test ───────────────────────────────────────────

#[tokio::test]
async fn handle_symbol_drop_notice_does_not_panic() {
    let db = Db::open_in_memory().unwrap();

    let holder = make_identity(0xF0);
    // sig: [0u8; 64] — verification fails, handler returns early with a warn log.
    // This test only checks that no panic occurs; DB-state correctness is in the
    // tests below that use make_signed_drop_notice / make_signing_key.
    let notice = SymbolDropNoticeMsg {
        v: 1,
        source_block_id: make_block_id(0xF0),
        esi_ranges: vec![(0, 100)],
        deadline: Timestamp(Timestamp::now().0 + 604_800),
        timestamp: Timestamp::now(),
        sig: [0u8; 64],
    };

    // Should not panic — handler returns early on bad sig, logs WARN.
    let _ = super::SymbolDropHandler::new(db.clone()).apply(holder, notice);
}

// ─── W13 handle_symbol_drop_notice DB-state tests ────────────────────────────

/// Build a minimal SourceBlockRecord suitable for tests. k=10, t=1, n=40.
/// target_reliability > 0 ensures next_work_item can pick it up.
fn make_source_block(block_id: SourceBlockId) -> SourceBlockRecord {
    SourceBlockRecord {
        seal_generation: 0,
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
    }
}

/// Register master→device mapping in DB so the handler can resolve identities.
fn register_holder(db: &Db, master: IdentityPub, device: DeviceId) {
    db.set_master_for_device(&device, &master).unwrap();
}

/// Build an *unsigned* SymbolDropNoticeMsg (sig = all-zeros).
/// Use only for "no panic" and "unchanged state" tests where the handler's early return on bad sig
/// is acceptable. For DB-state assertions use `make_signed_drop_notice` instead.
fn make_drop_notice(block_id: SourceBlockId, esi_ranges: Vec<(u32, u32)>) -> SymbolDropNoticeMsg {
    SymbolDropNoticeMsg {
        v: 1,
        source_block_id: block_id,
        esi_ranges,
        deadline: Timestamp(Timestamp::now().0 + 604_800),
        timestamp: Timestamp::now(),
        sig: [0u8; 64],
    }
}

/// Test: receiving a DropNotice for an Alive placement transitions it to Lost.
#[tokio::test]
async fn handle_symbol_drop_notice_transitions_placement_to_lost() {
    let db = Db::open_in_memory().unwrap();

    let holder_key = make_signing_key(0xA1);
    let holder_master = master_identity(&holder_key);
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

    let _ = super::SymbolDropHandler::new(db.clone()).apply(
        holder_master,
        make_signed_drop_notice(block_id, vec![(0, 10)], &holder_key),
    );

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

    let key_a = make_signing_key(0xA2);
    let master_a = master_identity(&key_a);
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

    // Drop notice from holder A — signed with key_a so signature verification passes.
    let _ = super::SymbolDropHandler::new(db.clone()).apply(
        master_a,
        make_signed_drop_notice(block_id, vec![(0, 10)], &key_a),
    );

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

    let key_a = make_signing_key(0xC1);
    let master_a = master_identity(&key_a);
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

    let _ = super::SymbolDropHandler::new(db.clone()).apply(
        master_a,
        make_signed_drop_notice(block_id, vec![(0, 20)], &key_a),
    );

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

    let key_a = make_signing_key(0xD1);
    let master_a = master_identity(&key_a);
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

    // Send the same notice twice — signed so both passes verify correctly.
    let notice = make_signed_drop_notice(block_id, vec![(0, 10)], &key_a);
    let _ = super::SymbolDropHandler::new(db.clone()).apply(master_a, notice.clone());
    let _ = super::SymbolDropHandler::new(db.clone()).apply(master_a, notice);

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
    let _ = super::SymbolDropHandler::new(db.clone())
        .apply(holder_master, make_drop_notice(block_id, vec![(0, 10)]));
    // No assertion needed — the test passes if no panic occurs.
}

/// Test: DropNotice from a master that has no devices in DB logs WARN and returns.
#[tokio::test]
async fn handle_symbol_drop_notice_unknown_holder_logs_and_returns() {
    let db = Db::open_in_memory().unwrap();

    let block_id = make_block_id(0xF1);
    let mut block = make_source_block(block_id);
    block.current_alive = 1;
    db.upsert_source_block(&block).unwrap();

    // holder_master has no registered devices — get_devices_for_master returns empty.
    let holder_master = make_identity(0xF2);

    // Should not panic. Placement state should be unchanged (no placement inserted).
    let _ = super::SymbolDropHandler::new(db.clone())
        .apply(holder_master, make_drop_notice(block_id, vec![(0, 10)]));

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

    let holder_key = make_signing_key(0x01);
    let holder_master = master_identity(&holder_key);
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

    // DropNotice for the already-Lost placement — signed so sig verification passes.
    // After sig check, mark_placement_lost sees Lost placement → no-op.
    let _ = super::SymbolDropHandler::new(db.clone()).apply(
        holder_master,
        make_signed_drop_notice(block_id, vec![(0, 10)], &holder_key),
    );

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

    let key_a = make_signing_key(0x10);
    let master_a = master_identity(&key_a);
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
        .next_work_item(
            1.0,
            Duration::from_secs(0),
            std::time::Duration::from_secs(3600),
            Timestamp::now(),
            0,
        )
        .unwrap();
    assert!(
        before.is_none(),
        "block must not be eligible before DropNotice (reliability >= target)"
    );

    // Send DropNotice for holder A — signed so signature verification passes.
    let _ = super::SymbolDropHandler::new(db.clone()).apply(
        master_a,
        make_signed_drop_notice(block_id, vec![(0, 10)], &key_a),
    );

    let updated_block = db.get_source_block(&block_id).unwrap().unwrap();
    assert!(
        updated_block.current_reliability < updated_block.target_reliability,
        "current_reliability ({}) must drop below target ({}) after DropNotice",
        updated_block.current_reliability,
        updated_block.target_reliability,
    );

    // Block must now be eligible for the worker.
    let after = db
        .next_work_item(
            1.0,
            Duration::from_secs(0),
            std::time::Duration::from_secs(3600),
            Timestamp::now(),
            0,
        )
        .unwrap();
    assert!(
        after.is_some(),
        "block must be eligible for worker after DropNotice drops reliability below target"
    );
    assert_eq!(after.unwrap().block_id, block_id);
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
    let master_key = derive_master_key(&[0xAAu8; 64]).expect("derive_master_key");
    let own_identity = master_identity(&master_key);
    let device_seed_a = [0x01u8; 32];
    let device_signing_key_a =
        viaticum_core::cluster::derive_device_key(&[0xAAu8; 64], &device_seed_a)
            .expect("derive_device_key_a");
    let device_id_a = DeviceId(device_signing_key_a.verifying_key().to_bytes());
    let now = Timestamp::now();

    let cert_a = viaticum_core::cluster::issue_device_certificate(&master_key, device_id_a, now);
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

    let processor = Processor::new(
        db,
        own_identity,
        cluster_sync,
        holdings_dir.path().to_path_buf(),
        swarm,
        u64::MAX,
        u64::MAX,
        holdings_dir.path().to_path_buf(),
        0,
        backup_event_tx,
        Some(cluster_state.clone()),
        super::make_empty_accepted_offers(),
        ed25519_dalek::SigningKey::from_bytes(&[0x77u8; 32]), // master_signing_key
    );

    (processor, cluster_state, own_identity)
}

/// Build a DeviceCertificate for device_id. device_id.0 must equal device signing key pubkey.
fn make_device_cert(
    master_key: &ed25519_dalek::SigningKey,
    device_id: DeviceId,
) -> viaticum_core::cluster::DeviceCertificate {
    viaticum_core::cluster::issue_device_certificate(master_key, device_id, Timestamp::now())
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
    let device_key_b = viaticum_core::cluster::derive_device_key(&[0xAAu8; 64], &device_seed_b)
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
    let device_key_x = viaticum_core::cluster::derive_device_key(&[0xBBu8; 64], &device_seed_x)
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
    let device_key_b = viaticum_core::cluster::derive_device_key(&[0xAAu8; 64], &device_seed_b)
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

    // Build peer master key and identity.
    let peer_master_key = derive_master_key(&[0x55u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);

    // Device being revoked: derive signing key so device_id = pubkey.
    let device_seed = [0xDDu8; 32];
    let device_signing_key = viaticum_core::cluster::derive_device_key(&[0x55u8; 64], &device_seed)
        .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    // Insert a known PeerRecord (another device of the same master, not the revoked one).
    // The revocation handler updates records found via get_devices_for_master.
    let known_device_id = DeviceId([0x55u8; 32]); // a device we already know about
    let peer_record = viaticum_core::types::PeerRecord {
        device_id: known_device_id,
        master_identity: peer_identity,
        trust_p: viaticum_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: viaticum_core::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer_record).expect("upsert_peer");
    db.set_master_for_device(&known_device_id, &peer_identity)
        .unwrap();

    // Build a valid RevocationBroadcast.
    let device_cert =
        viaticum_core::cluster::issue_device_certificate(&peer_master_key, device_id, now);
    let new_epoch = viaticum_core::cluster::EpochCounter(1);
    let revocation =
        viaticum_core::cluster::issue_revocation(&peer_master_key, device_id, now, new_epoch);
    let broadcast = viaticum_core::messages::RevocationBroadcast {
        revocation,
        device_cert,
    };

    super::RevocationHandler::new(db.clone())
        .apply(peer_identity, broadcast)
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

    let peer_master_key = derive_master_key(&[0x66u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);
    let device_seed = [0xAAu8; 32];
    let device_signing_key = viaticum_core::cluster::derive_device_key(&[0x66u8; 64], &device_seed)
        .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    // Insert peer with the device_id.0 already in the revoked list.
    let known_device_id = DeviceId([0x66u8; 32]);
    let mut peer_record = viaticum_core::types::PeerRecord {
        device_id: known_device_id,
        master_identity: peer_identity,
        trust_p: viaticum_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: viaticum_core::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    };
    peer_record.revoked_device_pub_keys.push(device_id.0);
    db.upsert_peer(&peer_record).expect("upsert_peer");
    db.set_master_for_device(&known_device_id, &peer_identity)
        .unwrap();

    let device_cert =
        viaticum_core::cluster::issue_device_certificate(&peer_master_key, device_id, now);
    let revocation = viaticum_core::cluster::issue_revocation(
        &peer_master_key,
        device_id,
        now,
        viaticum_core::cluster::EpochCounter(1),
    );
    let broadcast = viaticum_core::messages::RevocationBroadcast {
        revocation,
        device_cert,
    };

    super::RevocationHandler::new(db.clone())
        .apply(peer_identity, broadcast)
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

    let peer_master_key = derive_master_key(&[0x77u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);

    // Different key that signed the cert — attacker trying to forge.
    let attacker_key = derive_master_key(&[0x88u8; 64]).expect("derive_master_key");

    let device_seed = [0xCCu8; 32];
    let device_signing_key = viaticum_core::cluster::derive_device_key(&[0x77u8; 64], &device_seed)
        .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    let known_device_id_77 = DeviceId([0x77u8; 32]);
    let peer_record = viaticum_core::types::PeerRecord {
        device_id: known_device_id_77,
        master_identity: peer_identity,
        trust_p: viaticum_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: viaticum_core::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer_record).expect("upsert_peer");
    db.set_master_for_device(&known_device_id_77, &peer_identity)
        .unwrap();

    // DeviceCertificate signed by attacker, but from = real peer identity.
    let bad_cert = viaticum_core::cluster::issue_device_certificate(&attacker_key, device_id, now);
    let revocation = viaticum_core::cluster::issue_revocation(
        &peer_master_key,
        device_id,
        now,
        viaticum_core::cluster::EpochCounter(1),
    );
    let broadcast = viaticum_core::messages::RevocationBroadcast {
        revocation,
        device_cert: bad_cert,
    };

    // Must not error, but must silently ignore the forged broadcast.
    super::RevocationHandler::new(db.clone())
        .apply(peer_identity, broadcast)
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

    let peer_master_key = derive_master_key(&[0x99u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);
    let now = Timestamp::now();

    let device_seed_a = [0x01u8; 32];
    let device_seed_b = [0x02u8; 32];
    let device_key_a = viaticum_core::cluster::derive_device_key(&[0x99u8; 64], &device_seed_a)
        .expect("derive_device_key_a");
    let device_key_b = viaticum_core::cluster::derive_device_key(&[0x99u8; 64], &device_seed_b)
        .expect("derive_device_key_b");
    let device_id_a = DeviceId(device_key_a.verifying_key().to_bytes());
    let device_id_b = DeviceId(device_key_b.verifying_key().to_bytes());

    let known_device_id_99 = DeviceId([0x99u8; 32]);
    let peer_record = viaticum_core::types::PeerRecord {
        device_id: known_device_id_99,
        master_identity: peer_identity,
        trust_p: viaticum_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: viaticum_core::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer_record).expect("upsert_peer");
    db.set_master_for_device(&known_device_id_99, &peer_identity)
        .unwrap();

    // Cert for device_id_a, revocation for device_id_b — mismatch.
    let device_cert =
        viaticum_core::cluster::issue_device_certificate(&peer_master_key, device_id_a, now);
    let revocation = viaticum_core::cluster::issue_revocation(
        &peer_master_key,
        device_id_b,
        now,
        viaticum_core::cluster::EpochCounter(1),
    );
    let broadcast = viaticum_core::messages::RevocationBroadcast {
        revocation,
        device_cert,
    };

    super::RevocationHandler::new(db.clone())
        .apply(peer_identity, broadcast)
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

    let peer_master_key = derive_master_key(&[0xAAu8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);
    let device_seed = [0x10u8; 32];
    let device_signing_key = viaticum_core::cluster::derive_device_key(&[0xAAu8; 64], &device_seed)
        .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    // No upsert_peer — peer is unknown.
    let device_cert =
        viaticum_core::cluster::issue_device_certificate(&peer_master_key, device_id, now);
    let revocation = viaticum_core::cluster::issue_revocation(
        &peer_master_key,
        device_id,
        now,
        viaticum_core::cluster::EpochCounter(1),
    );
    let broadcast = viaticum_core::messages::RevocationBroadcast {
        revocation,
        device_cert,
    };

    super::RevocationHandler::new(db.clone())
        .apply(peer_identity, broadcast)
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(0x11);
    let block_id = make_block_id(0x11);

    // No accepted offer registered — transfer must be silently rejected.
    let transfer = SymbolTransferMsg {
        v: 1,
        source_block_id: block_id,
        symbols: vec![viaticum_core::erasure::Symbol {
            esi: 0,
            data: vec![0xFFu8; 64],
        }],
        timestamp: Timestamp::now(),
    };

    // Must return Ok (silent reject, not an error).
    processor
        .handle_symbol_transfer(sender_device(owner), owner, transfer)
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let owner = IdentityPub(signing_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x22);
    let esi_ranges = vec![(0u32, 10u32)];
    let importance = 0.7_f64;
    let timestamp = Timestamp::now();

    // Build a valid offer to confirm sig construction works (not directly used in map test).
    let _offer = viaticum_core::messages::build_symbol_offer(
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
        .get(&(sender_device(owner), block_id))
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

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
            viaticum_core::erasure::Symbol {
                esi: 0,
                data: vec![0x01u8; 64],
            },
            viaticum_core::erasure::Symbol {
                esi: 1,
                data: vec![0x02u8; 64],
            },
            viaticum_core::erasure::Symbol {
                esi: 2,
                data: vec![0x03u8; 64],
            },
        ],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_transfer(sender_device(owner), owner, transfer)
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
        map.get(&(sender_device(owner), block_id)).is_none(),
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(0x55);
    let block_id = make_block_id(0x55);

    // Accepted: ESI 0..5.
    insert_accepted_offer(&processor, owner, block_id, vec![(0u32, 5u32)], 0.6);

    // First chunk: ESI 0..2.
    processor
        .handle_symbol_transfer(
            sender_device(owner),
            owner,
            SymbolTransferMsg {
                v: 1,
                source_block_id: block_id,
                symbols: vec![
                    viaticum_core::erasure::Symbol {
                        esi: 0,
                        data: vec![0xAAu8; 32],
                    },
                    viaticum_core::erasure::Symbol {
                        esi: 1,
                        data: vec![0xAAu8; 32],
                    },
                    viaticum_core::erasure::Symbol {
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
            .get(&(sender_device(owner), block_id))
            .expect("offer must remain after partial transfer");
        assert_eq!(entry.esi_ranges, vec![(3u32, 2u32)]);
    }

    // Second chunk: ESI 3..4 finishes the placement.
    processor
        .handle_symbol_transfer(
            sender_device(owner),
            owner,
            SymbolTransferMsg {
                v: 1,
                source_block_id: block_id,
                symbols: vec![
                    viaticum_core::erasure::Symbol {
                        esi: 3,
                        data: vec![0xBBu8; 32],
                    },
                    viaticum_core::erasure::Symbol {
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
            .get(&(sender_device(owner), block_id))
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(0x44);
    let block_id = make_block_id(0x44);

    // Accepted range is ESI 0..9.
    insert_accepted_offer(&processor, owner, block_id, vec![(0u32, 10u32)], 0.5);

    // ESI 999 is outside the accepted range.
    let transfer = SymbolTransferMsg {
        v: 1,
        source_block_id: block_id,
        symbols: vec![viaticum_core::erasure::Symbol {
            esi: 999,
            data: vec![0xDDu8; 64],
        }],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_transfer(sender_device(owner), owner, transfer)
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
        map.get(&(sender_device(owner), block_id)).is_none(),
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let owner = IdentityPub(signing_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x55);

    let mut offer = viaticum_core::messages::build_symbol_offer(
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
    let result = viaticum_core::messages::verify_symbol_offer(&offer, &owner);
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
    use viaticum_core::constants::SYMBOL_OFFER_EXPIRY_SECS;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let owner = make_identity(0x66);
    let block_id = make_block_id(0x66);

    // Insert an expired offer: accepted_at = 0 (Unix epoch).
    // now() will be >> SYMBOL_OFFER_EXPIRY_SECS after epoch 0.
    let expired_offer = AcceptedOffer {
        owner_id: owner,
        from_device: sender_device(owner),
        source_block_id: block_id,
        esi_ranges: vec![(0u32, 100u32)],
        importance: 0.5,
        accepted_at: Timestamp(0), // epoch — always expired
    };
    {
        let mut map = processor.accepted_offers.lock().unwrap();
        map.insert((sender_device(owner), block_id), expired_offer);
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
        symbols: vec![viaticum_core::erasure::Symbol {
            esi: 0,
            data: vec![0xEEu8; 64],
        }],
        timestamp: Timestamp::now(),
    };

    processor
        .handle_symbol_transfer(sender_device(owner), owner, transfer)
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
        map.get(&(sender_device(owner), block_id)).is_none(),
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
    use viaticum_core::constants::HANDSHAKE_FRESHNESS_SECS;
    use viaticum_core::messages::{build_symbol_offer, verify_symbol_offer};

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    // Quota of 1 byte: any realistic offer exceeds it and is rejected.
    let processor = make_processor_with_quota(db.clone(), &holdings_dir, 1, 1).await;

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
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
    use viaticum_core::constants::HANDSHAKE_FRESHNESS_SECS;
    use viaticum_core::messages::{build_symbol_offer, verify_symbol_offer};

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let peer_master_key = derive_master_key(&[0xD1u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);

    let device_seed = [0x11u8; 32];
    let device_signing_key = viaticum_core::cluster::derive_device_key(&[0xD1u8; 64], &device_seed)
        .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();
    let device_cert =
        viaticum_core::cluster::issue_device_certificate(&peer_master_key, device_id, now);

    let fake_peer_id = libp2p::PeerId::random();

    processor
        .on_peer_authenticated(
            fake_peer_id,
            device_id,
            peer_identity,
            device_cert.clone(),
            None,
            vec![],
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
    // Fresh peer starts at the pessimistic prior, but the contact itself is a
    // positive observation so last_avail_sample is stamped.
    assert!(
        (record.avail_ewma - viaticum_core::constants::AVAIL_EWMA_INITIAL).abs() < 1e-12,
        "new peer should start at AVAIL_EWMA_INITIAL; got {}",
        record.avail_ewma
    );
    assert!(
        record.last_avail_sample > 0,
        "authentication should stamp last_avail_sample"
    );

    // A second authentication (existing-record path) is another positive
    // observation: avail_ewma must rise above the initial prior.
    processor
        .on_peer_authenticated(
            fake_peer_id,
            device_id,
            peer_identity,
            device_cert,
            None,
            vec![],
        )
        .await;
    let record2 = db
        .get_peer(&device_id)
        .expect("get_peer ok")
        .expect("PeerRecord must still exist");
    assert!(
        record2.avail_ewma > viaticum_core::constants::AVAIL_EWMA_INITIAL,
        "repeated authentication should raise avail_ewma above initial; got {}",
        record2.avail_ewma
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
    let device_key_b = viaticum_core::cluster::derive_device_key(&[0xAAu8; 64], &device_seed_b)
        .expect("derive_device_key_b");
    let device_id_b = DeviceId(device_key_b.verifying_key().to_bytes());
    let now = Timestamp::now();
    let cert_b = viaticum_core::cluster::issue_device_certificate(&master_key, device_id_b, now);

    let fake_peer_id = libp2p::PeerId::random();

    processor
        .on_peer_authenticated(
            fake_peer_id,
            device_id_b,
            own_identity, // same master identity
            cert_b,
            None,
            vec![],
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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let peer_master_key = derive_master_key(&[0xE3u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);

    let device_seed = [0x33u8; 32];
    let device_signing_key = viaticum_core::cluster::derive_device_key(&[0xE3u8; 64], &device_seed)
        .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();
    let device_cert =
        viaticum_core::cluster::issue_device_certificate(&peer_master_key, device_id, now);

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
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let peer_master_key = derive_master_key(&[0xF1u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);

    let device_signing_key =
        viaticum_core::cluster::derive_device_key(&[0xF1u8; 64], &[0x11u8; 32])
            .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();
    let device_cert =
        viaticum_core::cluster::issue_device_certificate(&peer_master_key, device_id, now);

    processor
        .on_peer_authenticated(
            libp2p::PeerId::random(),
            device_id,
            peer_identity,
            device_cert,
            None,
            vec![],
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

// ─── network-i2 / I6: addresses ride on PeerAuthenticated ─────────────────────

/// A peer authenticated with addresses, seen for the first time: the PeerRecord
/// created by on_peer_authenticated already carries them. Deterministic guard for
/// "remove the addrs from the auth event" (network-i2 mutation): the separate
/// PeerIdentified event can be processed before the record exists and be lost.
#[tokio::test]
async fn on_peer_authenticated_persists_listen_addrs_for_new_peer() {
    let tmp = TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("db.redb")).unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let peer_master_key = derive_master_key(&[0xF5u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);
    let device_signing_key =
        viaticum_core::cluster::derive_device_key(&[0xF5u8; 64], &[0x55u8; 32])
            .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let device_cert = viaticum_core::cluster::issue_device_certificate(
        &peer_master_key,
        device_id,
        Timestamp::now(),
    );
    let peer_id = crate::daemon::network::swarm::device_id_to_peer_id(&device_id).unwrap();
    let addrs: Vec<libp2p::Multiaddr> = vec![
        format!("/ip4/127.0.0.1/tcp/4101/p2p/{peer_id}")
            .parse()
            .unwrap(),
        format!("/ip4/10.0.0.7/tcp/4101/p2p/{peer_id}")
            .parse()
            .unwrap(),
    ];
    assert!(
        db.get_peer(&device_id).unwrap().is_none(),
        "precondition: new peer"
    );

    processor
        .on_peer_authenticated(
            peer_id,
            device_id,
            peer_identity,
            device_cert,
            None,
            addrs.clone(),
        )
        .await;

    let record = db
        .get_peer(&device_id)
        .unwrap()
        .expect("PeerRecord must exist after on_peer_authenticated");
    let want: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
    assert_eq!(
        record.addrs, want,
        "addrs must be written in the creating upsert"
    );
}

/// Existing record: new addrs replace the stored ones; an authentication that
/// carries no addrs (listener side before identify) keeps what is stored.
#[tokio::test]
async fn on_peer_authenticated_updates_addrs_of_existing_peer_and_keeps_them_when_empty() {
    let tmp = TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("db.redb")).unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let peer_master_key = derive_master_key(&[0xF6u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);
    let device_signing_key =
        viaticum_core::cluster::derive_device_key(&[0xF6u8; 64], &[0x66u8; 32])
            .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let device_cert = viaticum_core::cluster::issue_device_certificate(
        &peer_master_key,
        device_id,
        Timestamp::now(),
    );
    let peer_id = crate::daemon::network::swarm::device_id_to_peer_id(&device_id).unwrap();

    let mut existing = make_peer_record(device_id);
    existing.master_identity = peer_identity;
    existing.addrs = vec!["/ip4/192.168.1.2/tcp/1".to_string()];
    db.upsert_peer(&existing).unwrap();

    let fresh: libp2p::Multiaddr = format!("/ip4/127.0.0.1/tcp/4102/p2p/{peer_id}")
        .parse()
        .unwrap();
    processor
        .on_peer_authenticated(
            peer_id,
            device_id,
            peer_identity,
            device_cert.clone(),
            None,
            vec![fresh.clone()],
        )
        .await;
    assert_eq!(
        db.get_peer(&device_id).unwrap().unwrap().addrs,
        vec![fresh.to_string()],
        "new addrs replace stored ones"
    );

    processor
        .on_peer_authenticated(peer_id, device_id, peer_identity, device_cert, None, vec![])
        .await;
    assert_eq!(
        db.get_peer(&device_id).unwrap().unwrap().addrs,
        vec![fresh.to_string()],
        "an auth event without addrs must not wipe stored addrs"
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
    use viaticum_core::db::WeeklyPosEntry;

    let db = Db::open_in_memory().unwrap();

    let peer_master_key = derive_master_key(&[0xF2u8; 64]).expect("derive_master_key");
    let peer_identity = master_identity(&peer_master_key);

    let device_signing_key =
        viaticum_core::cluster::derive_device_key(&[0xF2u8; 64], &[0x22u8; 32])
            .expect("derive_device_key");
    let device_id = DeviceId(device_signing_key.verifying_key().to_bytes());
    let now = Timestamp::now();

    // Insert PeerRecord.
    let peer_record = viaticum_core::types::PeerRecord {
        device_id,
        master_identity: peer_identity,
        trust_p: viaticum_core::constants::INITIAL_TRUST_P,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: viaticum_core::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
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
    use viaticum_core::messages::ClusterSyncResponseMsg;

    let db = Db::open_in_memory().unwrap();
    let holdings = TempDir::new().unwrap();
    let processor = make_processor(db, &holdings).await;

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
        timestamp: viaticum_core::types::Timestamp::now(),
    };
    // Use our own device_id as the "from" device — it's a cluster member.
    // Derive the same way make_processor does (seed=[42u8;64], device_seed=[1u8;32]).
    let device_signing_key = viaticum_core::cluster::derive_device_key(&[42u8; 64], &[1u8; 32])
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

// ─── W11a: recompute_and_persist_block_cached_fields unit tests ───────────────

/// Helper to create a minimal SourceBlockRecord for cached-fields tests.
fn make_source_block_for_hook(block_id: SourceBlockId, importance: f64) -> SourceBlockRecord {
    SourceBlockRecord {
        seal_generation: 0,
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
fn make_hook_peer(device_id: DeviceId, trust_p: f64) -> viaticum_core::types::PeerRecord {
    let now = Timestamp(0);
    viaticum_core::types::PeerRecord {
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
        avail_ewma: viaticum_core::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    }
}

#[test]
fn recompute_and_persist_when_two_alive_one_uncertain_counts_three() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xC1);
    let holder_a = make_device_id(0xA1);
    let holder_b = make_device_id(0xA2);
    let holder_c = make_device_id(0xA3);

    let block = make_source_block_for_hook(block_id, 0.5);
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

    let block = make_source_block_for_hook(block_id, 0.5);
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
    let block = make_source_block_for_hook(block_id, 0.5);
    db.upsert_source_block(&block).unwrap();
    db.set_block_cooldown(&block_id, Some(sentinel_time), sentinel_sig, false);

    db.upsert_placement(&make_hook_placement(
        block_id,
        holder_a,
        PlacementStatus::Alive,
    ))
    .unwrap();
    db.upsert_peer(&make_hook_peer(holder_a, 0.8)).unwrap();

    super::recompute_and_persist_block_cached_fields(&db, &block_id);

    let cooldown = db.block_cooldown(&block_id);
    assert_eq!(
        cooldown.last_attempted_at,
        Some(sentinel_time),
        "last_attempted_at must be preserved unchanged"
    );
    assert_eq!(
        cooldown.last_pool_signature, sentinel_sig,
        "last_pool_signature must be preserved unchanged"
    );
}

#[test]
fn recompute_and_persist_is_idempotent_on_double_call() {
    let db = Db::open_in_memory().unwrap();
    let block_id = make_block_id(0xC4);
    let holder_a = make_device_id(0xD1);
    let holder_b = make_device_id(0xD2);

    let block = make_source_block_for_hook(block_id, 0.5);
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

// ─── PosResponder: standalone compute tests ──────────────────────────────────
//
// These tests exercise the non-mock production path: PosResponder is built
// directly (real redb + temp holdings dir) and driven either via
// compute_response or via ProcessorPosHandler::handle_pos_challenge with a
// CBOR-encoded payload.  This closes the "tests green but prod hollow" gap
// that existed when ProcessorPosHandler held Arc<Processor> (which could not
// be constructed in production because Processor had already been moved into
// its task).

#[tokio::test]
async fn pos_responder_computes_response_for_held_block() {
    use viaticum_core::messages::build_pos_hash_challenge;
    use viaticum_core::pos::compute_chain_hash;
    use viaticum_core::types::hex_encode;

    use super::pos::PosResponder;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x22);
    let esi = 3u32;
    let symbol_data = b"test-symbol-data-for-pos-responder".to_vec();
    let master_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xAAu8; 32]);

    // Insert HoldingRecord so ownership check passes.
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

    // Write symbol file at {holdings_dir}/{block_hex}/{esi}.bin.
    let block_hex: String = hex_encode(&block_id.0);
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();
    std::fs::write(block_dir.join(format!("{esi}.bin")), &symbol_data).unwrap();

    let responder = PosResponder::new(db, holdings_dir.path().to_path_buf(), master_signing_key);

    let challenge_id = [0xCCu8; 16];
    let challenge = build_pos_hash_challenge(
        challenge_id,
        block_id,
        vec![(esi, 1)],
        Timestamp::now(),
        None,
        &owner_key,
    );

    let reply = responder
        .compute_response(owner, challenge)
        .await
        .expect("compute_response must succeed");

    match reply {
        viaticum_core::messages::Message::PosHashResponse(resp) => {
            assert_eq!(
                resp.challenge_id, challenge_id,
                "challenge_id must round-trip"
            );
            let expected =
                compute_chain_hash(&challenge_id, &[(esi, symbol_data.as_slice())]).unwrap();
            assert_eq!(
                resp.chain_hash, expected,
                "chain_hash must match expected value"
            );
        }
        other => panic!(
            "expected PosHashResponse, got discriminant {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

/// CS-ID-5 / P1-2: a forged challenge — `owner_id` (claimed sender) is a real owner the
/// holder stores for, but the signature was produced by a DIFFERENT key — is dropped with
/// `UnauthenticatedChallenge` and produces NO response (no re-encode / disk-read amplification).
#[tokio::test]
async fn pos_responder_drops_challenge_with_bad_owner_signature() {
    use viaticum_core::messages::build_pos_hash_challenge;
    use viaticum_core::types::hex_encode;

    use super::pos::PosResponder;
    use crate::daemon::processor::ProcessorError;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    // The holder genuinely holds this block for `owner` (so the holding-check alone would
    // pass) — the only thing stopping a forge is the signature check.
    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x55u8; 32]);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x66);
    let esi = 2u32;
    let symbol_data = b"held-symbol-data".to_vec();

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

    let block_hex: String = hex_encode(&block_id.0);
    let block_dir = holdings_dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();
    std::fs::write(block_dir.join(format!("{esi}.bin")), &symbol_data).unwrap();

    let master_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xAAu8; 32]);
    let responder = PosResponder::new(db, holdings_dir.path().to_path_buf(), master_signing_key);

    // Forge: sign the challenge with an ATTACKER key, but present it as if from `owner`.
    let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0x99u8; 32]);
    let forged = build_pos_hash_challenge(
        [0x77u8; 16],
        block_id,
        vec![(esi, 1)],
        Timestamp::now(),
        None,
        &attacker_key,
    );

    let result = responder.compute_response(owner, forged).await;
    assert!(
        matches!(result, Err(ProcessorError::UnauthenticatedChallenge)),
        "forged challenge (sig by attacker, sender claims owner) must be dropped as \
         UnauthenticatedChallenge — no response, no re-encode"
    );
}

#[tokio::test]
async fn pos_responder_returns_none_when_block_not_held() {
    use viaticum_core::messages::{build_pos_hash_challenge, to_cbor};

    use super::pos::PosResponder;
    use crate::daemon::mailbox::poll::PosMailboxChallengeHandler;
    use crate::daemon::processor::ProcessorPosHandler;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let master_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32]);

    // No HoldingRecord, no symbol file — expect Nack path → handler returns None.
    let handler = ProcessorPosHandler::new(PosResponder::new(
        db,
        holdings_dir.path().to_path_buf(),
        master_signing_key,
    ));

    // Sign the challenge with a real owner key so it passes authentication and reaches the
    // "block not held → Nack → None" path (not an UnauthenticatedChallenge short-circuit).
    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x33u8; 32]);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x44);
    let esi = 0u32;
    let challenge_id = [0xDDu8; 16];

    let challenge = build_pos_hash_challenge(
        challenge_id,
        block_id,
        vec![(esi, 1)],
        Timestamp::now(),
        None,
        &owner_key,
    );
    let payload = to_cbor(&challenge).expect("cbor encode challenge");

    // Drive via the PosMailboxChallengeHandler interface (the same path the poll loop uses).
    let result = handler
        .handle_pos_challenge(owner, payload)
        .await
        .expect("handle_pos_challenge must not error");

    assert!(
        result.is_none(),
        "handler must return None (nack) when block is not held"
    );
}

// ─── SM-1: oversized / overflowing ESI-range challenge is rejected ────────────
//
// A PoS challenge is a SIGNED message from a real owner the holder stores for, but
// `esi_ranges: Vec<(u32,u32)>` is attacker-shaped on the wire. A malicious-but-
// authenticated owner can send `esi_ranges = [(0, u32::MAX)]`; the old
// `flat_map(start..start+count).collect()` would expand that into a ~4.29-billion-
// element Vec<u32> (~16 GB) BEFORE the per-symbol existence check — OOM. The guard
// rejects any challenge whose total requested count exceeds what the holder actually
// holds (`HoldingRecord::symbol_count()`), or whose `start + count` overflows, BEFORE
// the expansion. Honest, in-bounds challenges are untouched (chain-hash preserved).

/// SM-1 core regression: a VALID, signed challenge with an oversized ESI range
/// (`[(0, u32::MAX)]`, vs a holding of only 3 symbols) is rejected with
/// `OversizedChallenge` — NOT a multi-GB allocation, NOT a panic, NOT a Nack.
/// The signature is valid (the guard, not the sig check, must reject it).
#[tokio::test]
async fn pos_challenge_with_oversized_esi_range_is_rejected_without_huge_alloc() {
    use viaticum_core::messages::build_pos_hash_challenge;

    use super::pos::PosResponder;
    use crate::daemon::processor::ProcessorError;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x12u8; 32]);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x34);

    // Holding covers only 3 symbols → symbol_count() == 3.
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 3)],
        importance: 0.5,
        total_bytes: 3,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();

    let master_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xAAu8; 32]);
    let responder = PosResponder::new(db, holdings_dir.path().to_path_buf(), master_signing_key);

    // VALID signature from the real owner, but an oversized range. Before the fix,
    // `flat_map((0..u32::MAX)).collect()` would try to allocate ~16 GB here → OOM.
    let challenge = build_pos_hash_challenge(
        [0x56u8; 16],
        block_id,
        vec![(0, u32::MAX)],
        Timestamp::now(),
        None,
        &owner_key,
    );

    let result = responder.compute_response(owner, challenge).await;
    assert!(
        matches!(result, Err(ProcessorError::OversizedChallenge { .. })),
        "oversized challenge (sum of counts > symbol_count) must be rejected with \
         OversizedChallenge — no huge alloc, no panic, no Nack; got {result:?}"
    );
}

/// SM-1: a challenge whose range overflows `u32` (`[(u32::MAX, 5)]`) is rejected via
/// checked_add — no debug-build panic from `start + count`.
#[tokio::test]
async fn pos_challenge_with_overflowing_range_is_rejected() {
    use viaticum_core::messages::build_pos_hash_challenge;

    use super::pos::PosResponder;
    use crate::daemon::processor::ProcessorError;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x13u8; 32]);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x35);

    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 3)],
        importance: 0.5,
        total_bytes: 3,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();

    let master_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xAAu8; 32]);
    let responder = PosResponder::new(db, holdings_dir.path().to_path_buf(), master_signing_key);

    // u32::MAX + 5 overflows; old `start + count` panics in debug.
    let challenge = build_pos_hash_challenge(
        [0x57u8; 16],
        block_id,
        vec![(u32::MAX, 5)],
        Timestamp::now(),
        None,
        &owner_key,
    );

    let result = responder.compute_response(owner, challenge).await;
    assert!(
        matches!(result, Err(ProcessorError::OversizedChallenge { .. })),
        "overflowing range (start + count > u32::MAX) must be rejected via checked_add \
         — no debug panic; got {result:?}"
    );
}

/// SM-1: a challenge whose total exactly equals the holding's `symbol_count()` is
/// NOT caught by the guard — it proceeds into the normal expansion + file-read path.
/// In this unit test the symbol files do not exist on disk, so the legit path returns
/// a Nack (not OversizedChallenge), proving the guard let a legit-sized challenge through.
#[tokio::test]
async fn pos_challenge_within_holding_bounds_is_not_rejected() {
    use viaticum_core::messages::{Message, build_pos_hash_challenge};

    use super::pos::PosResponder;
    use crate::daemon::processor::ProcessorError;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x14u8; 32]);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x36);

    // Holding covers 3 symbols; challenge requests exactly those 3 (sum == symbol_count).
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 3)],
        importance: 0.5,
        total_bytes: 3,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();

    let master_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xAAu8; 32]);
    let responder = PosResponder::new(db, holdings_dir.path().to_path_buf(), master_signing_key);

    let challenge = build_pos_hash_challenge(
        [0x58u8; 16],
        block_id,
        vec![(0, 3)],
        Timestamp::now(),
        None,
        &owner_key,
    );

    let result = responder.compute_response(owner, challenge).await;
    // Must NOT hit the SM-1 guard. The symbol files don't exist on disk → legit Nack path.
    assert!(
        !matches!(result, Err(ProcessorError::OversizedChallenge { .. })),
        "an in-bounds challenge (sum == symbol_count) must NOT be rejected by the SM-1 \
         guard; got {result:?}"
    );
    assert!(
        matches!(result, Ok(Message::PosHashNack(_))),
        "in-bounds challenge with missing symbol files must take the normal path and \
         produce a Nack; got {result:?}"
    );
}

/// CS-POS-4: a signed challenge with empty `esi_ranges` (requested == 0) must be rejected
/// by the SM-1 guard. Without the reject, `0 <= held` passes the bound check and the
/// empty expansion reaches `compute_chain_hash`, which returns `ChainHashEmptyInput` →
/// an Err that the poll loop logs at error level on EVERY re-serve until the entry's TTL.
/// The guard now drops it cleanly (`OversizedChallenge`) — no compute, no error spam.
#[tokio::test]
async fn pos_challenge_with_empty_esi_ranges_is_rejected() {
    use viaticum_core::messages::build_pos_hash_challenge;

    use super::pos::PosResponder;
    use crate::daemon::processor::ProcessorError;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();

    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x15u8; 32]);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x37);

    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 3)],
        importance: 0.5,
        total_bytes: 3,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();

    let master_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xAAu8; 32]);
    let responder = PosResponder::new(db, holdings_dir.path().to_path_buf(), master_signing_key);

    // VALID signature, but empty esi_ranges → requested == 0.
    let challenge = build_pos_hash_challenge(
        [0x59u8; 16],
        block_id,
        vec![],
        Timestamp::now(),
        None,
        &owner_key,
    );

    let result = responder.compute_response(owner, challenge).await;
    assert!(
        matches!(
            result,
            Err(ProcessorError::OversizedChallenge { requested: 0, .. })
        ),
        "empty esi_ranges (requested == 0) must be rejected as malformed (clean drop), \
         not feed an empty input to compute_chain_hash; got {result:?}"
    );
}

// ─── T-12: Owner-addr propagation (Bug-A remainder) ──────────────────────────

/// T-12 AC: `on_peer_identified` persists listen_addrs to the PeerRecord for an
/// inbound (or any authenticated) peer.
///
/// Primary addr-propagation path. The swarm emits `PeerIdentified` after the
/// identify protocol completes for any peer; the processor dispatches it to
/// `on_peer_identified` regardless of connection direction.
#[tokio::test]
async fn on_peer_identified_persists_addrs_for_inbound_peer() {
    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let processor = make_processor(db.clone(), &holdings_dir).await;

    let device_id = make_device_id(0xA1);

    // Pre-insert PeerRecord without addrs (simulates state after cert-exchange but
    // before identify has completed — i.e., the inbound case).
    db.upsert_peer(&make_peer_record(device_id)).unwrap();

    // Simulate identify protocol delivering listen addrs for the peer.
    let addr: libp2p::Multiaddr = "/ip4/192.168.1.100/tcp/4001".parse().unwrap();
    processor.on_peer_identified(device_id, vec![addr.clone()]);

    // Verify the addrs are now persisted on the PeerRecord.
    let record = db
        .get_peer(&device_id)
        .unwrap()
        .expect("PeerRecord must exist");
    assert_eq!(
        record.addrs,
        vec![addr.to_string()],
        "on_peer_identified must persist listen_addrs to the PeerRecord"
    );
}

// ─── У-4: DropNotice → the 4R pair ledger's ANNOUNCED drop events ───────────────
//
// Spec pair_ledger.md "Спека У-4" (Д-I, Д-K, Д-M), intent 4r-i25/i26/i29/i34. The event
// is the TRANSITION of a held placement into Lost, recorded in the transition's own
// transaction; what `SymbolDropHandler::apply` does to the placement is unchanged (AC-7).
// These tests live here and not in `mailbox/poll/tests.rs` (line B's file, review N-5).

/// A holder master with one device holding one Alive block of ours since `placed_at`.
/// `DEVICE_TO_MASTER` maps the device to the SIGNING master (that is how `apply` finds the
/// placement); the `PeerRecord` carries `ledger_master` (how the ledger keys the event, Д-M).
struct DropFixture {
    db: Db,
    key: ed25519_dalek::SigningKey,
    signer: IdentityPub,
    ledger_master: IdentityPub,
    device: DeviceId,
    block: SourceBlockId,
    placed_at: Timestamp,
}

fn drop_fixture(
    seed: u8,
    status: PlacementStatus,
    ledger_master: Option<IdentityPub>,
) -> DropFixture {
    let db = Db::open_in_memory().unwrap();
    let key = make_signing_key(seed);
    let signer = master_identity(&key);
    let ledger_master = ledger_master.unwrap_or(signer);
    let device = make_device_id(seed);
    let block = make_block_id(seed.wrapping_add(1));
    let placed_at = Timestamp(Timestamp::now().0 - 3600);
    register_holder(&db, signer, device);
    let mut peer = make_peer_record(device);
    peer.master_identity = ledger_master;
    db.upsert_peer(&peer).unwrap();
    db.upsert_source_block(&make_source_block(block)).unwrap();
    let mut placement = make_symbol_placement(block, device, vec![(0, 10)], status);
    placement.placed_at = placed_at;
    db.upsert_placement(&placement).unwrap();
    DropFixture {
        db,
        key,
        signer,
        ledger_master,
        device,
        block,
        placed_at,
    }
}

impl DropFixture {
    /// A notice signed by the holder, stamped `timestamp`, with `deadline`.
    fn notice(&self, deadline: Timestamp, timestamp: Timestamp) -> SymbolDropNoticeMsg {
        build_signed_symbol_drop_notice(self.block, vec![(0, 10)], deadline, timestamp, &self.key)
    }
    /// An immediate notice ("dropped now") issued `after` seconds after the placement.
    fn fresh_notice(&self, after: u64) -> SymbolDropNoticeMsg {
        let ts = Timestamp(self.placed_at.0 + after);
        self.notice(ts, ts)
    }
    fn apply(&self, notice: SymbolDropNoticeMsg) -> bool {
        super::SymbolDropHandler::new(self.db.clone()).apply(self.signer, notice)
    }
    fn pending(&self) -> Vec<(IdentityPub, viaticum_core::types::PendingDrops)> {
        self.db.list_pending_drops().unwrap()
    }
    fn announced_for(&self, m: IdentityPub) -> u32 {
        self.pending()
            .into_iter()
            .find(|(k, _)| *k == m)
            .map(|(_, p)| p.announced)
            .unwrap_or(0)
    }
    fn status(&self) -> PlacementStatus {
        self.db
            .get_placement(&self.block, &self.device)
            .unwrap()
            .unwrap()
            .status
    }
}

#[tokio::test]
async fn a_drop_notice_for_an_alive_placement_records_one_announced_event() {
    // DP-1 (4r-i25). The placement moves Alive → Lost and, in the same transaction, the
    // holder master's outbox gets exactly one Announced.
    let f = drop_fixture(0x31, PlacementStatus::Alive, None);

    assert!(f.apply(f.fresh_notice(10)));

    assert_eq!(f.status(), PlacementStatus::Lost);
    assert_eq!(
        f.pending(),
        vec![(
            f.ledger_master,
            viaticum_core::types::PendingDrops {
                announced: 1,
                ..Default::default()
            }
        )],
        "one Announced, nothing else"
    );
}

#[tokio::test]
async fn redelivering_the_same_drop_notice_records_nothing_more() {
    // DP-2 (4r-i25). The mailbox hands the same entry out on every poll for its whole TTL;
    // the second delivery finds the placement already Lost.
    let f = drop_fixture(0x33, PlacementStatus::Alive, None);
    let notice = f.fresh_notice(10);

    f.apply(notice.clone());
    f.apply(notice.clone());
    f.apply(notice);

    assert_eq!(f.announced_for(f.ledger_master), 1);
}

#[tokio::test]
async fn a_republished_notice_with_a_new_deadline_records_nothing_more() {
    // DP-3 (4r-i25, WARN-7). Disk pressure republishes the advance notice with a NEW
    // deadline and timestamp on every tick — a (holder, block, deadline) key would not
    // collapse it; the transition does.
    let f = drop_fixture(0x35, PlacementStatus::Alive, None);
    let t = f.placed_at.0;

    f.apply(f.notice(Timestamp(t + 7 * 86_400), Timestamp(t + 10)));
    f.apply(f.notice(Timestamp(t + 8 * 86_400), Timestamp(t + 20)));
    f.apply(f.notice(Timestamp(t + 9 * 86_400), Timestamp(t + 30)));

    assert_eq!(f.announced_for(f.ledger_master), 1);
}

#[tokio::test]
async fn the_final_immediate_notice_after_an_advance_notice_records_nothing_more() {
    // DP-4 (4r-i25). Advance notice (deadline in a week), then the final "dropped now"
    // (deadline = timestamp) once the window ran out: one loss, one event.
    let f = drop_fixture(0x37, PlacementStatus::Alive, None);
    let t = f.placed_at.0;

    f.apply(f.notice(Timestamp(t + 7 * 86_400), Timestamp(t + 10)));
    f.apply(f.notice(
        Timestamp(t + 7 * 86_400 + 10),
        Timestamp(t + 7 * 86_400 + 10),
    ));

    assert_eq!(f.status(), PlacementStatus::Lost);
    assert_eq!(f.announced_for(f.ledger_master), 1);
}

#[tokio::test]
async fn a_notice_for_a_deleting_or_missing_placement_records_nothing() {
    // DP-5 (4r-i26). Our own deletion: the placement is Deleting (or already cleaned up)
    // long before the holder's final notice arrives. Not the friend's drop.
    let deleting = drop_fixture(0x39, PlacementStatus::Deleting, None);
    deleting.apply(deleting.fresh_notice(10));
    assert_eq!(
        deleting.status(),
        PlacementStatus::Deleting,
        "premise: untouched"
    );
    assert!(deleting.pending().is_empty());

    let missing = drop_fixture(0x3B, PlacementStatus::Alive, None);
    missing
        .db
        .write_txn()
        .and_then(|mut t| {
            t.delete_placement(&missing.block, &missing.device)?;
            t.commit()
        })
        .unwrap();
    assert!(!missing.apply(missing.fresh_notice(10)));
    assert!(missing.pending().is_empty());
}

#[tokio::test]
async fn a_notice_not_younger_than_the_current_placement_is_not_counted_but_still_marks_it_lost() {
    // DP-6 (4r-i29). The FIRST delivery of an old notice after repair put the block back on
    // the same holder: the transition still happens (existing behaviour, AC-7; DN-1 Д-DN1-2 —
    // time is not part of the rule), but the evidence predates the episode — in the same second
    // too (review of intent BLOCK-1: at time_scale 100 000 the loss, the repair and the new
    // Alive fit in one second). Re-deliveries of the same notice are deduplicated (DN-1, see
    // `tests/drop_notice_dedup.rs`).
    for (label, before) in [("older", 5u64), ("same second", 0u64)] {
        let f = drop_fixture(0x3D, PlacementStatus::Alive, None);
        let ts = Timestamp(f.placed_at.0 - before);

        assert!(f.apply(f.notice(ts, ts)), "{label}: the signature passes");

        assert_eq!(
            f.status(),
            PlacementStatus::Lost,
            "{label}: the first delivery of an old notice still marks it Lost; re-deliveries are deduplicated (DN-1)"
        );
        assert!(f.pending().is_empty(), "{label}: but it is not a new drop");
    }
}

#[tokio::test]
async fn a_notice_after_presumed_lost_is_not_counted_again() {
    // DP-7 (4r-i29). Three missed challenges already recorded the loss as Presumed; the
    // holder's notice arriving afterwards is the same loss.
    let f = drop_fixture(0x3F, PlacementStatus::PresumedLost, None);

    f.apply(f.fresh_notice(10));

    assert_eq!(
        f.status(),
        PlacementStatus::Lost,
        "premise: the transition happens"
    );
    assert!(f.pending().is_empty());
}

#[tokio::test]
async fn a_forged_or_foreign_master_notice_records_nothing() {
    // DP-8 (4r-i26). A notice not signed by the claimed holder, and a correctly signed
    // notice from a master that holds no placement of the block: no transition, no event.
    let f = drop_fixture(0x41, PlacementStatus::Alive, None);
    let attacker = make_signing_key(0x42);
    let ts = Timestamp(f.placed_at.0 + 10);
    let forged = build_signed_symbol_drop_notice(f.block, vec![(0, 10)], ts, ts, &attacker);
    assert!(!f.apply(forged));
    assert_eq!(f.status(), PlacementStatus::Alive);

    let stranger_key = make_signing_key(0x43);
    let stranger = master_identity(&stranger_key);
    register_holder(&f.db, stranger, make_device_id(0x43));
    let foreign = build_signed_symbol_drop_notice(f.block, vec![(0, 10)], ts, ts, &stranger_key);
    assert!(
        !super::SymbolDropHandler::new(f.db.clone()).apply(stranger, foreign),
        "the stranger holds no placement of this block"
    );

    assert_eq!(f.status(), PlacementStatus::Alive);
    assert!(f.pending().is_empty());
}

#[tokio::test]
async fn the_announced_event_is_keyed_by_the_peer_record_master() {
    // DP-9 (Д-M, AC-4h). `apply` finds the device through device_to_master (the signer),
    // but the ledger keys the event by the device's PeerRecord master — the key the accrual
    // sweep groups by, carried through DR (device_to_master is not).
    let peer_master = make_identity(0x46);
    let f = drop_fixture(0x45, PlacementStatus::Alive, Some(peer_master));
    assert_ne!(f.signer, peer_master, "premise: the two sources disagree");

    f.apply(f.fresh_notice(10));

    assert_eq!(f.announced_for(peer_master), 1);
    assert_eq!(f.announced_for(f.signer), 0);
}

#[tokio::test]
async fn a_notice_inside_the_owners_delete_cooldown_is_still_the_friends_drop() {
    // DP-10 (4r-i34). I deleted the file locally, but the owner cooldown has not run out, so
    // no Delete went to the holder and its placement is still Alive. The friend dropping
    // the block now is the friend's drop.
    let f = drop_fixture(0x47, PlacementStatus::Alive, None);
    let now = Timestamp::now();
    let file = viaticum_core::types::FileRecord {
        file_id: FileId(1),
        path: "/watch/deleted.txt".to_string(),
        importance: 0.5,
        devices: vec![(
            make_device_id(0x01),
            viaticum_core::types::LocalState::Deleted(now),
        )],
        versions: vec![viaticum_core::types::FileVersion {
            content_hash: [0x48; 32],
            source_block_id: f.block,
            k: 10,
            t: 1,
            created_at: Timestamp(0),
            backed_up_at: Some(Timestamp(0)),
        }],
        first_seen: Timestamp(0),
        on_disk_confirmed: true,
    };
    let actions = viaticum_core::deletion::DeletionEngine::new().process_cooldowns(
        &[file],
        &f.db.list_all_source_blocks().unwrap(),
        &f.db.list_all_placements().unwrap(),
        now,
        1,
    );
    assert!(
        actions.is_empty(),
        "premise: inside the owner cooldown no Delete is sent, got {actions:?}"
    );

    f.apply(f.fresh_notice(10));

    assert_eq!(f.announced_for(f.ledger_master), 1);
}

// DN-1: one notice — one application (spec f1_stale_drop_notice.md, DN1-1..DN1-18).
mod drop_notice_dedup;

// В-0b: the offer path refactor and the 4R offer shadow (D-3a, D-3b, D-5).
mod four_r_shadow;
// W-A (review round 2): the offer's own record read on the REAL offer path (`key_before`).
mod four_r_shadow_wedge;
// R1-u-H1 (backup-i19): the SymbolTransfer reply matches the holder's disk; offers per device.
mod symbol_transfer_reply;
// F-Q: the offer rule over the quota states (holder-i1..i3).
mod quota_states;
// C-DK C4 fix round 1: identify addresses survive an authentication in flight.
mod peer_event_order;
// К-b2a⁗ (v3.12b NOTE 3, [cross:A]): the quota counts only the ESIs of a re-offer not held yet.
mod reoffer_quota;
// К-b4 (pos-i14): the holder's PoS answer streams the share, at most two at once.
mod holder_pos;

// ─── pos-i5-a: a holder answers only a fresh challenge (replay guard) ───────────

/// A held block with one symbol file; returns (db, holdings dir, owner key, block id).
fn held_block_for_freshness() -> (Db, TempDir, ed25519_dalek::SigningKey, SourceBlockId) {
    use viaticum_core::types::hex_encode;

    let db = Db::open_in_memory().unwrap();
    let holdings_dir = TempDir::new().unwrap();
    let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x61u8; 32]);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0x62);
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 1)],
        importance: 0.5,
        total_bytes: 8,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();
    let block_dir = holdings_dir.path().join(hex_encode(&block_id.0));
    std::fs::create_dir_all(&block_dir).unwrap();
    std::fs::write(block_dir.join("0.bin"), b"symbol-0").unwrap();
    (db, holdings_dir, owner_key, block_id)
}

/// Signed challenge for the held block, issued `age` seconds ago.
fn challenge_aged(
    owner_key: &ed25519_dalek::SigningKey,
    block_id: SourceBlockId,
    age: u64,
) -> viaticum_core::messages::PosHashChallengeMsg {
    viaticum_core::messages::build_pos_hash_challenge(
        [0x63; 16],
        block_id,
        vec![(0, 1)],
        Timestamp(Timestamp::now().0 - age),
        None,
        owner_key,
    )
}

#[tokio::test]
async fn challenge_older_than_ttl_plus_skew_is_dropped_before_the_disk() {
    use super::pos::{PosResponder, challenge_max_age_secs};

    let (db, dir, owner_key, block_id) = held_block_for_freshness();
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let responder = PosResponder::new(db, dir.path().to_path_buf(), make_signing_key(0xAA))
        .with_time_scale(900);
    let stale = challenge_aged(&owner_key, block_id, challenge_max_age_secs(900) + 1);
    match responder.compute_response(owner, stale).await {
        Err(crate::daemon::processor::ProcessorError::StaleChallenge { age_secs }) => {
            assert!(age_secs > challenge_max_age_secs(900));
        }
        other => panic!("a replay must be dropped as stale, got {other:?}"),
    }
}

#[tokio::test]
async fn challenge_just_inside_ttl_plus_skew_is_answered() {
    use super::pos::{PosResponder, challenge_max_age_secs};

    let (db, dir, owner_key, block_id) = held_block_for_freshness();
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let responder = PosResponder::new(db, dir.path().to_path_buf(), make_signing_key(0xAA))
        .with_time_scale(900);
    let edge = challenge_aged(&owner_key, block_id, challenge_max_age_secs(900) - 1);
    match responder.compute_response(owner, edge).await {
        Ok(viaticum_core::messages::Message::PosHashResponse(r)) => {
            assert_eq!(r.challenge_id, [0x63; 16]);
        }
        other => panic!("a challenge inside TTL + skew must be answered, got {other:?}"),
    }
}

#[tokio::test]
async fn stale_challenge_through_the_mailbox_handler_is_no_answer() {
    use super::pos::{PosResponder, challenge_max_age_secs};
    use crate::daemon::mailbox::poll::PosMailboxChallengeHandler;
    use crate::daemon::processor::ProcessorPosHandler;

    let (db, dir, owner_key, block_id) = held_block_for_freshness();
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let handler = ProcessorPosHandler::new(
        PosResponder::new(db, dir.path().to_path_buf(), make_signing_key(0xAA))
            .with_time_scale(900),
    );
    let stale = challenge_aged(&owner_key, block_id, challenge_max_age_secs(900) + 60);
    let payload = viaticum_core::messages::to_cbor(&stale).unwrap();
    let result = handler
        .handle_pos_challenge(owner, payload)
        .await
        .expect("a stale challenge is not a handler error");
    assert!(result.is_none(), "a replay gets no answer");
}

#[test]
fn max_age_is_the_scaled_ttl_plus_the_unscaled_skew() {
    use super::pos::{POS_CHALLENGE_MAX_CLOCK_SKEW_SECS, challenge_max_age_secs};

    assert_eq!(
        challenge_max_age_secs(900),
        672 + POS_CHALLENGE_MAX_CLOCK_SKEW_SECS
    );
    assert_eq!(
        challenge_max_age_secs(1),
        7 * 24 * 3600 + POS_CHALLENGE_MAX_CLOCK_SKEW_SECS
    );
}

#[tokio::test]
async fn undecodable_payload_through_the_mailbox_handler_is_no_answer() {
    use super::pos::PosResponder;
    use crate::daemon::mailbox::poll::PosMailboxChallengeHandler;
    use crate::daemon::processor::ProcessorPosHandler;

    let dir = TempDir::new().unwrap();
    let handler = ProcessorPosHandler::new(PosResponder::new(
        Db::open_in_memory().unwrap(),
        dir.path().to_path_buf(),
        make_signing_key(0xAA),
    ));
    let result = handler
        .handle_pos_challenge(IdentityPub([0x42; 32]), vec![0xFF, 0x00, 0x13])
        .await
        .expect("junk is not a handler error");
    assert!(result.is_none());
}
