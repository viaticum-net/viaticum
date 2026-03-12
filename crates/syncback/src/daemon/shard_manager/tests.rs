use syncback_core::budget::BudgetPlanner;
use syncback_core::placement::PlacementEngine;
use syncback_core::trust::TrustEngine;
use syncback_core::types::{
    FileType, IdentityPub, PeerRecord, ShardId, ShardRecord, ShardStatus, Timestamp, UnitId,
    UnitRecord, UnitStatus, UnitType,
};

use super::{
    decrypt_unit,
    encode_unit_test as encode_unit,
    encrypt_unit_test as encrypt_unit,
    PosResponse,
    PosResult,
    ShardManager,
    ShardManagerError,
};
use crate::daemon::merkle;

// ============================================================
// Test helpers
// ============================================================

fn test_db() -> (syncback_core::db::Db, tempfile::NamedTempFile) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db = syncback_core::db::Db::open(tmp.path()).unwrap();
    (db, tmp)
}

fn test_identity_key(seed: u8) -> ed25519_dalek::SigningKey {
    let bytes = [seed; 32];
    ed25519_dalek::SigningKey::from_bytes(&bytes)
}

fn test_identity_pub(key: &ed25519_dalek::SigningKey) -> IdentityPub {
    IdentityPub(key.verifying_key().to_bytes())
}

fn now() -> Timestamp {
    Timestamp(1_700_000_000)
}

fn insert_peer_with_trust(db: &syncback_core::db::Db, peer: IdentityPub, trust: f64) {
    let record = PeerRecord {
        identity: peer,
        node_id: None,
        trust_p: trust,
        trust_i: trust,
        trust_s: 1.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        weeks_in_network: 26,
        subnet_prefix: None,
        allowlisted: false,
    };
    db.upsert_peer(&record).unwrap();
}

fn make_peers(db: &syncback_core::db::Db, count: usize) -> Vec<IdentityPub> {
    let mut peers = Vec::new();
    for i in 0..count {
        let mut bytes = [0u8; 32];
        bytes[0] = (i + 1) as u8;
        bytes[1] = (i >> 8) as u8;
        let peer = IdentityPub(bytes);
        insert_peer_with_trust(db, peer, 0.7);
        peers.push(peer);
    }
    peers
}

fn make_shard_manager(
    db: syncback_core::db::Db,
) -> (
    ShardManager,
    tokio::sync::mpsc::Receiver<crate::daemon::NetCommand>,
) {
    let identity_key = test_identity_key(42);
    let identity_pub = test_identity_pub(&identity_key);
    let trust = TrustEngine::new(db.clone());
    let placement = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let budget = BudgetPlanner::new(db.clone(), trust);
    let (net_tx, net_rx) = tokio::sync::mpsc::channel(256);
    let mgr = ShardManager::new(db, placement, budget, identity_key, identity_pub, net_tx);
    (mgr, net_rx)
}

fn make_unit_record(unit_id: UnitId) -> UnitRecord {
    UnitRecord {
        unit_id,
        unit_type: UnitType::Pack,
        status: UnitStatus::Active,
        member_file_ids: vec![],
        chunk_index: None,
        parent_file_id: None,
        size_bytes: 10_240,
        plaintext_hash: [0u8; 32],
        created_at: now(),
        importance_avg: 0.9,
        rs_k: 5,
        rs_n: 15,
    }
}

fn insert_shard_record(
    db: &syncback_core::db::Db,
    unit_id: UnitId,
    shard_index: u8,
    holder: IdentityPub,
    status: ShardStatus,
) -> ShardId {
    let mut id_bytes = [0u8; 32];
    id_bytes[0] = shard_index;
    id_bytes[1] = 0xaa;
    let shard_id = ShardId(id_bytes);
    let record = ShardRecord {
        shard_id,
        unit_id,
        shard_index,
        holder_id: holder,
        status,
        last_verified: None,
        offered_at: now(),
        stored_at: None,
        merkle_root: [0u8; 32],
    };
    db.upsert_shard(&record).unwrap();
    shard_id
}

// ============================================================
// Encryption tests
// ============================================================

#[test]
fn encrypt_decrypt_roundtrip() {
    let plaintext = b"hello world, this is a test unit for encryption";
    let key = [0u8; 32];
    let ciphertext = encrypt_unit(&key, plaintext).unwrap();
    let recovered = decrypt_unit(&key, &ciphertext).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn encrypt_decrypt_empty_plaintext() {
    let plaintext = b"";
    let key = [0x42u8; 32];
    let ciphertext = encrypt_unit(&key, plaintext).unwrap();
    let recovered = decrypt_unit(&key, &ciphertext).unwrap();
    assert_eq!(recovered.as_slice(), plaintext.as_slice());
}

#[test]
fn encrypt_produces_different_ciphertext_each_time() {
    let plaintext = b"same data";
    let key = [1u8; 32];
    let ct1 = encrypt_unit(&key, plaintext).unwrap();
    let ct2 = encrypt_unit(&key, plaintext).unwrap();
    assert_ne!(ct1, ct2);
}

#[test]
fn decrypt_fails_with_wrong_key() {
    let plaintext = b"secret data";
    let key1 = [1u8; 32];
    let key2 = [2u8; 32];
    let ciphertext = encrypt_unit(&key1, plaintext).unwrap();
    let result = decrypt_unit(&key2, &ciphertext);
    assert!(result.is_err());
}

#[test]
fn decrypt_fails_on_short_input() {
    let key = [0u8; 32];
    let result = decrypt_unit(&key, &[0u8; 5]);
    assert!(result.is_err());
}

// ============================================================
// Reed-Solomon encoding tests
// ============================================================

#[test]
fn erasure_encode_produces_n_shards() {
    let data = vec![0x07u8; 1024];
    let shards = encode_unit(&data, 5, 7).unwrap();
    assert_eq!(shards.len(), 7);
    for s in &shards {
        assert!(!s.is_empty());
    }
}

#[test]
fn erasure_encode_all_shards_same_size() {
    let data = vec![0x01u8; 1000];
    let shards = encode_unit(&data, 5, 7).unwrap();
    let first_len = shards[0].len();
    for s in &shards {
        assert_eq!(s.len(), first_len);
    }
}

#[test]
fn erasure_encode_decode_roundtrip_5_of_7() {
    use reed_solomon_erasure::galois_8::ReedSolomon;

    let original = vec![0x37u8; 1024];
    let shards = encode_unit(&original, 5, 7).unwrap();
    let shard_size = shards[0].len();

    let mut opt_shards: Vec<Option<Vec<u8>>> = shards
        .into_iter()
        .enumerate()
        .map(|(i, s)| if i == 0 || i == 3 { None } else { Some(s) })
        .collect();

    let r = ReedSolomon::new(5, 2).unwrap();
    r.reconstruct(&mut opt_shards).unwrap();

    let recovered: Vec<u8> = opt_shards[..5]
        .iter()
        .flat_map(|s| s.as_ref().unwrap().iter().copied())
        .collect();

    let padded_len = shard_size * 5;
    let mut expected = original.clone();
    expected.resize(padded_len, 0u8);
    assert_eq!(&recovered[..padded_len], expected.as_slice());
}

#[test]
fn erasure_encode_decode_roundtrip_5_of_15() {
    use reed_solomon_erasure::galois_8::ReedSolomon;

    let original = vec![0xabu8; 5000];
    let shards = encode_unit(&original, 5, 15).unwrap();
    assert_eq!(shards.len(), 15);

    let mut opt_shards: Vec<Option<Vec<u8>>> = shards
        .into_iter()
        .enumerate()
        .map(|(i, s)| if i < 10 { None } else { Some(s) })
        .collect();

    let r = ReedSolomon::new(5, 10).unwrap();
    r.reconstruct(&mut opt_shards).unwrap();

    let shard_size = opt_shards[0].as_ref().unwrap().len();
    let padded_len = shard_size * 5;
    let recovered: Vec<u8> = opt_shards[..5]
        .iter()
        .flat_map(|s| s.as_ref().unwrap().iter().copied())
        .collect();
    let mut expected = original.clone();
    expected.resize(padded_len, 0u8);
    assert_eq!(&recovered[..padded_len], expected.as_slice());
}

// ============================================================
// Key derivation tests
// ============================================================

#[test]
fn derive_unit_key_is_deterministic() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db);
    let unit_id = UnitId([7u8; 32]);
    let key1 = mgr.derive_unit_key(unit_id);
    let key2 = mgr.derive_unit_key(unit_id);
    assert_eq!(key1, key2);
}

#[test]
fn derive_unit_key_differs_for_different_unit_ids() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db);
    let uid1 = UnitId([1u8; 32]);
    let uid2 = UnitId([2u8; 32]);
    let key1 = mgr.derive_unit_key(uid1);
    let key2 = mgr.derive_unit_key(uid2);
    assert_ne!(key1, key2);
}

#[test]
fn derive_unit_key_differs_for_different_identity_keys() {
    let (db1, _tmp1) = test_db();
    let (mgr1, _rx1) = make_shard_manager(db1);

    let (db2, _tmp2) = test_db();
    let key2 = test_identity_key(99);
    let pub2 = test_identity_pub(&key2);
    let trust2 = TrustEngine::new(db2.clone());
    let (tx2, _rx2) = tokio::sync::mpsc::channel(256);
    let mgr2 = ShardManager::new(
        db2.clone(),
        PlacementEngine::new(db2.clone(), TrustEngine::new(db2.clone())),
        BudgetPlanner::new(db2, trust2),
        key2,
        pub2,
        tx2,
    );

    let unit_id = UnitId([5u8; 32]);
    assert_ne!(mgr1.derive_unit_key(unit_id), mgr2.derive_unit_key(unit_id));
}

// ============================================================
// Upload unit tests
// ============================================================

#[tokio::test]
async fn upload_unit_produces_n_shards_and_offers() {
    let (db, _tmp) = test_db();
    make_peers(&db, 20);

    let (mgr, mut net_rx) = make_shard_manager(db.clone());

    let unit_id = UnitId([42u8; 32]);
    let unit_record = make_unit_record(unit_id);
    db.upsert_unit(&unit_record).unwrap();

    let plaintext = vec![0x11u8; 10_240];
    let result = mgr
        .upload_unit(unit_id, &unit_record, &plaintext, 0.9, FileType::User, now())
        .await;

    assert!(result.is_ok(), "upload_unit failed: {result:?}");
    let placements = result.unwrap();

    assert!(
        placements.len() >= 15,
        "expected at least 15 placements, got {}",
        placements.len()
    );

    let mut offer_count = 0;
    while let Ok(cmd) = net_rx.try_recv() {
        if let crate::daemon::NetCommand::PublishBoard { msg_type, .. } = cmd {
            if msg_type == "shard_offer" {
                offer_count += 1;
            }
        }
    }
    assert_eq!(offer_count, placements.len());

    let shards = db.list_shards_for_unit(&unit_id).unwrap();
    assert_eq!(shards.len(), placements.len());
    for s in &shards {
        assert_eq!(s.status, ShardStatus::Offered);
    }
}

#[tokio::test]
async fn upload_unit_fails_with_not_enough_peers() {
    let (db, _tmp) = test_db();
    make_peers(&db, 3);

    let (mgr, _rx) = make_shard_manager(db.clone());

    let unit_id = UnitId([1u8; 32]);
    let unit_record = make_unit_record(unit_id);

    let plaintext = vec![0x22u8; 1000];
    let result = mgr
        .upload_unit(unit_id, &unit_record, &plaintext, 0.5, FileType::User, now())
        .await;

    assert!(
        matches!(result, Err(ShardManagerError::NotEnoughPeers { .. })),
        "expected NotEnoughPeers, got {result:?}"
    );
}

#[tokio::test]
async fn upload_unit_fails_with_importance_too_low() {
    let (db, _tmp) = test_db();
    make_peers(&db, 20);

    let (mgr, _rx) = make_shard_manager(db.clone());

    let unit_id = UnitId([2u8; 32]);
    let unit_record = make_unit_record(unit_id);
    let plaintext = vec![0x33u8; 100];
    let result = mgr
        .upload_unit(unit_id, &unit_record, &plaintext, 0.05, FileType::User, now())
        .await;

    assert!(
        matches!(result, Err(ShardManagerError::ImportanceTooLow(_))),
        "expected ImportanceTooLow, got {result:?}"
    );
}

// ============================================================
// Status update tests
// ============================================================

#[tokio::test]
async fn handle_shard_stored_updates_status() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db.clone());

    let unit_id = UnitId([10u8; 32]);
    let holder = IdentityPub([3u8; 32]);
    let shard_id = insert_shard_record(&db, unit_id, 0, holder, ShardStatus::Accepted);

    let result = mgr.handle_shard_stored(shard_id, now());
    assert!(result.is_ok(), "{result:?}");

    let record = db.get_shard(&shard_id).unwrap().unwrap();
    assert_eq!(record.status, ShardStatus::Stored);
}

#[tokio::test]
async fn handle_shard_reject_marks_lost() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db.clone());

    let unit_id = UnitId([11u8; 32]);
    let holder = IdentityPub([4u8; 32]);
    let shard_id = insert_shard_record(&db, unit_id, 0, holder, ShardStatus::Offered);

    let result = mgr.handle_shard_reject(shard_id, now());
    assert!(result.is_ok(), "{result:?}");

    let record = db.get_shard(&shard_id).unwrap().unwrap();
    assert_eq!(record.status, ShardStatus::Lost);
}

#[tokio::test]
async fn handle_shard_dropped_marks_lost() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db.clone());

    let unit_id = UnitId([12u8; 32]);
    let holder = IdentityPub([5u8; 32]);
    let shard_id = insert_shard_record(&db, unit_id, 0, holder, ShardStatus::Stored);

    let result = mgr.handle_shard_dropped(shard_id, now());
    assert!(result.is_ok(), "{result:?}");

    let record = db.get_shard(&shard_id).unwrap().unwrap();
    assert_eq!(record.status, ShardStatus::Lost);
}

#[tokio::test]
async fn handle_shard_stored_fails_when_shard_not_found() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db.clone());

    let missing_id = ShardId([0xffu8; 32]);
    let result = mgr.handle_shard_stored(missing_id, now());
    assert!(
        matches!(result, Err(ShardManagerError::ShardNotFound(_))),
        "{result:?}"
    );
}

// ============================================================
// Repair / under-replication tests
// ============================================================

#[tokio::test]
async fn find_under_replicated_units_detects_partially_lost() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db.clone());

    let unit_id = UnitId([20u8; 32]);
    let unit_record = UnitRecord {
        unit_id,
        unit_type: UnitType::Pack,
        status: UnitStatus::Active,
        member_file_ids: vec![],
        chunk_index: None,
        parent_file_id: None,
        size_bytes: 100,
        plaintext_hash: [0u8; 32],
        created_at: now(),
        importance_avg: 0.5,
        rs_k: 5,
        rs_n: 7,
    };
    db.upsert_unit(&unit_record).unwrap();

    let holder = IdentityPub([9u8; 32]);
    // 5 Stored, 2 Lost → under-replicated (5 >= k=5 but 5 < n=7)
    for i in 0..5u8 {
        insert_shard_record(&db, unit_id, i, holder, ShardStatus::Stored);
    }
    for i in 5..7u8 {
        insert_shard_record(&db, unit_id, i, holder, ShardStatus::Lost);
    }

    let units = mgr.find_under_replicated_units().unwrap();
    assert!(
        units.contains(&unit_id),
        "expected unit to be under-replicated: stored=5, n=7"
    );
}

#[tokio::test]
async fn find_under_replicated_units_excludes_unrecoverable() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db.clone());

    let unit_id = UnitId([21u8; 32]);
    let unit_record = UnitRecord {
        unit_id,
        unit_type: UnitType::Pack,
        status: UnitStatus::Active,
        member_file_ids: vec![],
        chunk_index: None,
        parent_file_id: None,
        size_bytes: 100,
        plaintext_hash: [0u8; 32],
        created_at: now(),
        importance_avg: 0.5,
        rs_k: 5,
        rs_n: 7,
    };
    db.upsert_unit(&unit_record).unwrap();

    let holder = IdentityPub([10u8; 32]);
    // Only 2 stored — fewer than k=5 → irrecoverable
    for i in 0..2u8 {
        insert_shard_record(&db, unit_id, i, holder, ShardStatus::Stored);
    }
    for i in 2..7u8 {
        insert_shard_record(&db, unit_id, i, holder, ShardStatus::Lost);
    }

    let units = mgr.find_under_replicated_units().unwrap();
    assert!(
        !units.contains(&unit_id),
        "unrecoverable unit should not appear in repair list"
    );
}

#[tokio::test]
async fn find_under_replicated_units_excludes_fully_replicated() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db.clone());

    let unit_id = UnitId([22u8; 32]);
    let unit_record = UnitRecord {
        unit_id,
        unit_type: UnitType::Pack,
        status: UnitStatus::Active,
        member_file_ids: vec![],
        chunk_index: None,
        parent_file_id: None,
        size_bytes: 100,
        plaintext_hash: [0u8; 32],
        created_at: now(),
        importance_avg: 0.5,
        rs_k: 5,
        rs_n: 7,
    };
    db.upsert_unit(&unit_record).unwrap();

    let holder = IdentityPub([11u8; 32]);
    for i in 0..7u8 {
        insert_shard_record(&db, unit_id, i, holder, ShardStatus::Stored);
    }

    let units = mgr.find_under_replicated_units().unwrap();
    assert!(
        !units.contains(&unit_id),
        "fully replicated unit should not appear"
    );
}

#[tokio::test]
async fn repair_unit_returns_plaintext_not_available_without_plaintext() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db.clone());

    let unit_id = UnitId([30u8; 32]);
    let result = mgr.repair_unit(unit_id, None, now()).await;
    assert!(
        matches!(result, Err(ShardManagerError::PlaintextNotAvailable)),
        "{result:?}"
    );
}

// ============================================================
// Delete tests
// ============================================================

#[tokio::test]
async fn delete_unit_shards_sends_delete_messages() {
    let (db, _tmp) = test_db();
    let (mgr, mut net_rx) = make_shard_manager(db.clone());

    let unit_id = UnitId([40u8; 32]);
    let holder = IdentityPub([15u8; 32]);

    insert_shard_record(&db, unit_id, 0, holder, ShardStatus::Stored);
    insert_shard_record(&db, unit_id, 1, holder, ShardStatus::Offered);
    insert_shard_record(&db, unit_id, 2, holder, ShardStatus::Lost);

    let count = mgr.delete_unit_shards(unit_id, now()).await.unwrap();
    assert_eq!(count, 2, "expected 2 delete messages (Stored + Offered)");

    let mut delete_count = 0;
    while let Ok(cmd) = net_rx.try_recv() {
        if let crate::daemon::NetCommand::PublishBoard { msg_type, .. } = cmd {
            if msg_type == "delete" {
                delete_count += 1;
            }
        }
    }
    assert_eq!(delete_count, 2);

    let shards = db.list_shards_for_unit(&unit_id).unwrap();
    let deleting: Vec<_> = shards
        .iter()
        .filter(|s| s.status == ShardStatus::Deleting)
        .collect();
    assert_eq!(deleting.len(), 2);
}

// ============================================================
// PoS verification tests
// ============================================================

#[test]
fn pos_response_verification_pass_with_correct_proof() {
    use crate::daemon::merkle::{merkle_proof, merkle_root, merkle_tree, BLOCK_SIZE};

    let (db, _tmp) = test_db();
    let identity_key = test_identity_key(1);
    let identity_pub = test_identity_pub(&identity_key);
    let trust = TrustEngine::new(db.clone());
    let placement = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let budget = BudgetPlanner::new(db.clone(), trust);
    let (net_tx, _rx) = tokio::sync::mpsc::channel(256);
    let mgr = ShardManager::new(
        db.clone(),
        placement,
        budget,
        identity_key,
        identity_pub,
        net_tx,
    );

    let blob = vec![0x77u8; BLOCK_SIZE * 3 + 100];
    let root = merkle_root(&blob);
    let tree = merkle_tree(&blob);

    let block_index = 1u32;
    let start = block_index as usize * BLOCK_SIZE;
    let end = (start + BLOCK_SIZE).min(blob.len());
    // The merkle tree hashes full BLOCK_SIZE padded blocks.
    let block_hash = *blake3::hash(&blob[start..end]).as_bytes();

    let proof = merkle_proof(&tree, block_index as usize);

    let holder = IdentityPub([20u8; 32]);
    let shard_id = ShardId([0xbbu8; 32]);
    let record = ShardRecord {
        shard_id,
        unit_id: UnitId([1u8; 32]),
        shard_index: 0,
        holder_id: holder,
        status: ShardStatus::Stored,
        last_verified: None,
        offered_at: now(),
        stored_at: None,
        merkle_root: root,
    };
    db.upsert_shard(&record).unwrap();

    let result = mgr
        .handle_pos_response(
            PosResponse {
                from: holder,
                shard_id,
                block_index,
                block_data_hash: block_hash,
                merkle_proof: proof,
                nonce: [0u8; 32],
            },
            now(),
            10,
        )
        .unwrap();

    assert_eq!(result, PosResult::Pass);

    let updated = db.get_shard(&shard_id).unwrap().unwrap();
    assert_eq!(updated.last_verified, Some(now()));
}

#[test]
fn pos_response_verification_fail_with_wrong_hash() {
    use crate::daemon::merkle::{merkle_proof, merkle_root, merkle_tree, BLOCK_SIZE};

    let (db, _tmp) = test_db();
    let identity_key = test_identity_key(2);
    let identity_pub = test_identity_pub(&identity_key);
    let trust = TrustEngine::new(db.clone());
    let placement = PlacementEngine::new(db.clone(), TrustEngine::new(db.clone()));
    let budget = BudgetPlanner::new(db.clone(), trust);
    let (net_tx, _rx) = tokio::sync::mpsc::channel(256);
    let mgr = ShardManager::new(
        db.clone(),
        placement,
        budget,
        identity_key,
        identity_pub,
        net_tx,
    );

    let blob = vec![0x55u8; BLOCK_SIZE * 2];
    let root = merkle_root(&blob);
    let tree = merkle_tree(&blob);
    let proof = merkle_proof(&tree, 0);

    let holder = IdentityPub([21u8; 32]);
    let shard_id = ShardId([0xccu8; 32]);
    let record = ShardRecord {
        shard_id,
        unit_id: UnitId([2u8; 32]),
        shard_index: 0,
        holder_id: holder,
        status: ShardStatus::Stored,
        last_verified: None,
        offered_at: now(),
        stored_at: None,
        merkle_root: root,
    };
    db.upsert_shard(&record).unwrap();

    let wrong_hash = [0xffu8; 32];
    let result = mgr
        .handle_pos_response(
            PosResponse {
                from: holder,
                shard_id,
                block_index: 0,
                block_data_hash: wrong_hash,
                merkle_proof: proof,
                nonce: [0u8; 32],
            },
            now(),
            10,
        )
        .unwrap();

    assert_eq!(result, PosResult::Fail);

    let updated = db.get_shard(&shard_id).unwrap().unwrap();
    assert_eq!(updated.status, ShardStatus::Lost);
}

#[test]
fn pos_response_from_wrong_peer_fails() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db.clone());

    let holder = IdentityPub([30u8; 32]);
    let wrong_peer = IdentityPub([31u8; 32]);
    let unit_id = UnitId([3u8; 32]);
    let shard_id = insert_shard_record(&db, unit_id, 0, holder, ShardStatus::Stored);

    let result = mgr
        .handle_pos_response(
            PosResponse {
                from: wrong_peer,
                shard_id,
                block_index: 0,
                block_data_hash: [0u8; 32],
                merkle_proof: vec![],
                nonce: [0u8; 32],
            },
            now(),
            10,
        )
        .unwrap();

    assert_eq!(result, PosResult::Fail);
}

// ============================================================
// Merkle root consistency test
// ============================================================

#[test]
fn merkle_root_matches_between_shard_manager_and_storage() {
    use crate::daemon::merkle::merkle_root as sm_root;
    use crate::daemon::storage::build_merkle_tree;

    let blob = vec![0x42u8; merkle::BLOCK_SIZE * 3 + 100];

    let root_sm = sm_root(&blob);

    let tree_storage = build_merkle_tree(&blob);
    let root_storage = *tree_storage.last().unwrap();

    assert_eq!(
        root_sm, root_storage,
        "merkle roots must match between modules"
    );
}

// ============================================================
// Pending blob buffer tests
// ============================================================

#[test]
fn get_pending_blob_returns_none_when_empty() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db);
    let shard_id = ShardId([1u8; 32]);
    assert!(mgr.get_pending_blob(&shard_id).is_none());
}

#[test]
fn clear_pending_blobs_empties_buffer() {
    let (db, _tmp) = test_db();
    let (mgr, _rx) = make_shard_manager(db);

    {
        let mut pending = mgr.pending_blobs.lock().unwrap();
        pending.insert(ShardId([1u8; 32]), vec![1, 2, 3]);
    }

    assert!(mgr.get_pending_blob(&ShardId([1u8; 32])).is_some());
    mgr.clear_pending_blobs();
    assert!(mgr.get_pending_blob(&ShardId([1u8; 32])).is_none());
}
