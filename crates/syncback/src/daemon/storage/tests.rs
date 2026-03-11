use syncback_core::messages::{FileType as MsgFileType, ShardDescriptor, ShardDescriptorUnsigned};
use syncback_core::testutil::{test_db, test_peer, test_unit_id};
use syncback_core::trust::TrustEngine;
use syncback_core::types::{
    FileType, HoldingRecord, IdentityPub, PeerRecord, ShardId, ShardState, Timestamp,
};

use crate::daemon::storage::{
    build_merkle_tree, merkle_proof_path, OfferDecision, Storage, StorageError, BLOCK_SIZE,
};

// ============================================================
// Test helpers
// ============================================================

fn make_storage(quota_gb: f64) -> (Storage, syncback_core::db::Db, tempfile::TempDir) {
    let (db, _tmp) = test_db();
    let dir = tempfile::TempDir::new().unwrap();
    let shards_dir = dir.path().join("shards");
    let trust = TrustEngine::new(db.clone());
    let storage = Storage::new(db.clone(), shards_dir, quota_gb, trust).unwrap();
    (storage, db, dir)
}

fn make_signing_key() -> ed25519_dalek::SigningKey {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    ed25519_dalek::SigningKey::from_bytes(&bytes)
}

fn identity_from_key(key: &ed25519_dalek::SigningKey) -> IdentityPub {
    IdentityPub(key.verifying_key().to_bytes())
}

fn make_peer_record(identity: IdentityPub) -> PeerRecord {
    PeerRecord {
        identity,
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        weeks_in_network: 26,
        subnet_prefix: None,
        allowlisted: false,
    }
}

fn make_descriptor(
    blob: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
    importance: f32,
    file_type: MsgFileType,
) -> ShardDescriptor {
    let shard_id = ShardId(*blake3::hash(blob).as_bytes());
    let tree = build_merkle_tree(blob);
    let merkle_root = if tree.is_empty() {
        [0u8; 32]
    } else {
        tree[tree.len() - 1]
    };
    let owner_pub = identity_from_key(signing_key);
    let unsigned = ShardDescriptorUnsigned {
        shard_id,
        unit_id: test_unit_id(1),
        shard_index: 0,
        k: 5,
        n: 7,
        merkle_root,
        owner_pub,
        importance,
        file_type,
        created_at: 0,
    };
    ShardDescriptor::sign(unsigned, signing_key).unwrap()
}

fn insert_peer(db: &syncback_core::db::Db, identity: IdentityPub) {
    db.upsert_peer(&make_peer_record(identity)).unwrap();
}

fn insert_holding_record(db: &syncback_core::db::Db, shard_id: ShardId, owner: IdentityPub, size_bytes: u64, importance: f64) {
    let record = HoldingRecord {
        shard_id,
        owner_pub: owner,
        importance,
        size_bytes,
        state: ShardState::Active,
        received_at: Timestamp(0),
        delete_requested_at: None,
        drop_notice_sent_at: None,
        file_type: FileType::User,
        merkle_root: [0u8; 32],
        rs_k: 5,
        rs_n: 7,
        shard_index: 0,
    };
    db.upsert_holding(&record).unwrap();
}

// ============================================================
// Tests
// ============================================================

#[tokio::test]
async fn store_shard_succeeds_with_valid_blob() {
    let (storage, db, _dir) = make_storage(100.0);
    let blob: Vec<u8> = (0u8..=255u8).cycle().take(1024).collect();
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    let shard_id = descriptor.shard_id;

    storage.store_shard(&descriptor, &blob).await.unwrap();

    // File exists on disk
    let hex: String = shard_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let prefix = &hex[..2];
    let path = storage.shards_dir.join(prefix).join(format!("{hex}.shard"));
    assert!(path.exists(), "shard blob file should exist");

    // Record in DB
    let record = db.get_holding(&shard_id).unwrap().unwrap();
    assert_eq!(record.state, ShardState::Active);
    assert_eq!(record.size_bytes, blob.len() as u64);
}

#[tokio::test]
async fn store_shard_rejects_hash_mismatch() {
    let (storage, db, _dir) = make_storage(100.0);
    let blob: Vec<u8> = vec![0u8; 512];
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);

    // Corrupt the blob
    let wrong_blob: Vec<u8> = vec![0xFFu8; 512];
    let result = storage.store_shard(&descriptor, &wrong_blob).await;
    assert!(matches!(result, Err(StorageError::HashMismatch { .. })));

    // No file on disk
    let hex: String = descriptor.shard_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let prefix = &hex[..2];
    let path = storage.shards_dir.join(prefix).join(format!("{hex}.shard"));
    assert!(!path.exists(), "no file should be created on hash mismatch");

    // No record in DB
    assert!(db.get_holding(&descriptor.shard_id).unwrap().is_none());
}

#[tokio::test]
async fn answer_pos_challenge_correct_hash_and_proof() {
    let (storage, db, _dir) = make_storage(100.0);
    // 3 blocks exactly
    let blob: Vec<u8> = vec![0xABu8; 3 * BLOCK_SIZE];
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    storage.store_shard(&descriptor, &blob).await.unwrap();

    let nonce = [0u8; 32];
    let answer = storage
        .answer_pos_challenge(descriptor.shard_id, 1, &nonce)
        .unwrap();

    // Verify block_data_hash
    let block_bytes = &blob[BLOCK_SIZE..2 * BLOCK_SIZE];
    let mut hasher = blake3::Hasher::new();
    hasher.update(block_bytes);
    hasher.update(&nonce);
    let expected_hash = *hasher.finalize().as_bytes();
    assert_eq!(answer.block_data_hash, expected_hash);

    // 3 blocks → padded to 4 leaves → proof length = log2(4) = 2
    assert_eq!(answer.merkle_proof.len(), 2);
}

#[tokio::test]
async fn answer_pos_challenge_block_out_of_range() {
    let (storage, db, _dir) = make_storage(100.0);
    let blob: Vec<u8> = vec![0u8; 100];
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    storage.store_shard(&descriptor, &blob).await.unwrap();

    let result = storage.answer_pos_challenge(descriptor.shard_id, 5, &[0u8; 32]);
    assert!(matches!(result, Err(StorageError::BlockOutOfRange { index: 5, blocks: 1 })));
}

#[tokio::test]
async fn read_shard_for_restore_allows_free_tier() {
    let (storage, db, _dir) = make_storage(100.0);
    let blob: Vec<u8> = vec![0x42u8; 512];
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    storage.store_shard(&descriptor, &blob).await.unwrap();

    // No restore log → bytes_restored = 0 → FreeTier
    let now = Timestamp(1_000_000);
    let result = storage.read_shard_for_restore(descriptor.shard_id, &owner_pub, now);
    assert!(result.is_ok(), "free tier should always be allowed: {result:?}");
    assert_eq!(result.unwrap(), blob);
}

#[tokio::test]
async fn read_shard_for_restore_denies_on_escrow() {
    let (storage, db, _dir) = make_storage(100.0);
    let blob: Vec<u8> = vec![0x42u8; 512];
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);

    // Insert peer with only 5 weeks_in_network (Tier2 requires 13)
    let mut peer = make_peer_record(owner_pub);
    peer.weeks_in_network = 5;
    db.upsert_peer(&peer).unwrap();

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    storage.store_shard(&descriptor, &blob).await.unwrap();

    // Simulate 5 GiB already restored → bytes_restored = 5 GiB → Tier2 (requires 13 weeks)
    let five_gib: u64 = 5 * 1024 * 1024 * 1024;
    let restore_log = syncback_core::types::EscrowRestoreLog {
        owner_pub,
        bytes_restored: five_gib,
        first_restore_at: Some(Timestamp(0)),
        last_restore_at: Some(Timestamp(0)),
    };
    db.upsert_restore_log(&restore_log).unwrap();

    let now = Timestamp(1_000_000);
    let result = storage.read_shard_for_restore(descriptor.shard_id, &owner_pub, now);
    assert!(
        matches!(result, Err(StorageError::EscrowDenied(ref d)) if d.required_weeks == 13 && d.current_weeks == 5),
        "expected EscrowDenied with required_weeks=13, current_weeks=5, got: {result:?}"
    );
}

#[tokio::test]
async fn delete_cooldown_does_not_delete_immediately() {
    let (storage, db, _dir) = make_storage(100.0);
    let blob: Vec<u8> = vec![0x55u8; 512];
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    storage.store_shard(&descriptor, &blob).await.unwrap();

    let now = Timestamp(0);
    storage
        .handle_delete_request(descriptor.shard_id, &owner_pub, now)
        .unwrap();

    // State should be MarkedForDelete
    let record = db.get_holding(&descriptor.shard_id).unwrap().unwrap();
    assert_eq!(record.state, ShardState::MarkedForDelete);

    // Process cooldowns at 1 week — should NOT delete (< 4 weeks)
    let one_week = Timestamp(604_800);
    let deleted = storage.process_expired_cooldowns(one_week).unwrap();
    assert!(deleted.is_empty(), "shard should not be deleted before 4 weeks");

    // Still in DB
    assert!(db.get_holding(&descriptor.shard_id).unwrap().is_some());
}

#[tokio::test]
async fn delete_cooldown_deletes_after_4_weeks() {
    let (storage, db, _dir) = make_storage(100.0);
    let blob: Vec<u8> = vec![0x55u8; 512];
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    let shard_id = descriptor.shard_id;
    storage.store_shard(&descriptor, &blob).await.unwrap();

    let now = Timestamp(0);
    storage.handle_delete_request(shard_id, &owner_pub, now).unwrap();

    // Process at 4 weeks + 1 second
    let four_weeks_plus = Timestamp(4 * 604_800 + 1);
    let deleted = storage.process_expired_cooldowns(four_weeks_plus).unwrap();
    assert!(deleted.contains(&shard_id), "shard_id should be in deleted list");

    // Not in DB
    assert!(db.get_holding(&shard_id).unwrap().is_none());

    // File not on disk
    let hex: String = shard_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let prefix = &hex[..2];
    let path = storage.shards_dir.join(prefix).join(format!("{hex}.shard"));
    assert!(!path.exists(), "blob file should be deleted");
}

#[tokio::test]
async fn evict_shard_removes_blob_and_record() {
    let (storage, db, _dir) = make_storage(100.0);
    let blob: Vec<u8> = vec![0x77u8; 512];
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    let shard_id = descriptor.shard_id;
    storage.store_shard(&descriptor, &blob).await.unwrap();

    let result = storage.evict_shard(shard_id, Timestamp(0)).unwrap();
    assert_eq!(result, owner_pub);

    // Not in DB
    assert!(db.get_holding(&shard_id).unwrap().is_none());

    // File not on disk
    let hex: String = shard_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let prefix = &hex[..2];
    let path = storage.shards_dir.join(prefix).join(format!("{hex}.shard"));
    assert!(!path.exists(), "blob file should be deleted after eviction");
}

#[tokio::test]
async fn should_accept_offer_rejects_unknown_owner() {
    let (storage, _db, _dir) = make_storage(100.0);
    let signing_key = make_signing_key();
    let blob = vec![0u8; 64];
    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);

    // Owner not inserted into DB
    let decision = storage.should_accept_offer(&descriptor).unwrap();
    assert!(
        matches!(decision, OfferDecision::RejectUnknown),
        "expected RejectUnknown, got {decision:?}"
    );
}

#[tokio::test]
async fn should_accept_offer_rejects_when_soft_pressure() {
    // quota_gb = 1.0 GB, fill with enough fake records to exceed soft threshold (85%)
    let (storage, db, _dir) = make_storage(1.0);
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    // Soft threshold = 15% free → we need > 85% used
    // 1.0 GB quota → used > 0.85 GB
    // Insert a fake HoldingRecord with size_bytes = 900 MB
    let shard_id = ShardId([0xAAu8; 32]);
    let size_bytes = 900 * 1024 * 1024u64; // 900 MB
    insert_holding_record(&db, shard_id, test_peer(1), size_bytes, 0.5);

    let blob = vec![0u8; 64];
    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    let decision = storage.should_accept_offer(&descriptor).unwrap();
    assert!(
        matches!(decision, OfferDecision::RejectFull),
        "expected RejectFull at soft pressure, got {decision:?}"
    );
}

#[tokio::test]
async fn should_accept_offer_accepts_known_peer() {
    let (storage, db, _dir) = make_storage(100.0);
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let blob = vec![0u8; 64];
    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    let decision = storage.should_accept_offer(&descriptor).unwrap();
    assert!(
        matches!(decision, OfferDecision::Accept),
        "expected Accept for known peer, got {decision:?}"
    );
}

#[tokio::test]
async fn handle_cancel_delete_reverts_to_active() {
    let (storage, db, _dir) = make_storage(100.0);
    let blob: Vec<u8> = vec![0x33u8; 512];
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    storage.store_shard(&descriptor, &blob).await.unwrap();

    storage
        .handle_delete_request(descriptor.shard_id, &owner_pub, Timestamp(0))
        .unwrap();
    assert_eq!(
        db.get_holding(&descriptor.shard_id).unwrap().unwrap().state,
        ShardState::MarkedForDelete
    );

    storage
        .handle_cancel_delete(descriptor.shard_id, &owner_pub)
        .unwrap();
    assert_eq!(
        db.get_holding(&descriptor.shard_id).unwrap().unwrap().state,
        ShardState::Active
    );
}

#[tokio::test]
async fn record_drop_notice_sets_timestamp() {
    let (storage, db, _dir) = make_storage(100.0);
    let blob: Vec<u8> = vec![0x11u8; 512];
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    storage.store_shard(&descriptor, &blob).await.unwrap();

    let now = Timestamp(999_000);
    storage.record_drop_notice(descriptor.shard_id, now).unwrap();

    let record = db.get_holding(&descriptor.shard_id).unwrap().unwrap();
    assert_eq!(record.drop_notice_sent_at, Some(now));
}

#[tokio::test]
async fn process_expired_drop_notices_deletes_blob() {
    let (storage, db, _dir) = make_storage(100.0);
    let blob: Vec<u8> = vec![0x22u8; 512];
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    let shard_id = descriptor.shard_id;
    storage.store_shard(&descriptor, &blob).await.unwrap();

    // Set drop_notice_sent_at to a time in the past (deadline already passed)
    let deadline = Timestamp(1_000);
    storage.record_drop_notice(shard_id, deadline).unwrap();

    // Process at a time past the deadline
    let now = Timestamp(2_000);
    let deleted = storage.process_expired_drop_notices(now).unwrap();
    assert!(deleted.contains(&shard_id));
    assert!(db.get_holding(&shard_id).unwrap().is_none());
}

#[tokio::test]
async fn used_bytes_and_shard_count_are_correct() {
    let (storage, db, _dir) = make_storage(100.0);
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    assert_eq!(storage.used_bytes().unwrap(), 0);
    assert_eq!(storage.shard_count().unwrap(), 0);

    let blob: Vec<u8> = vec![0xABu8; 1024];
    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    storage.store_shard(&descriptor, &blob).await.unwrap();

    assert_eq!(storage.used_bytes().unwrap(), 1024);
    assert_eq!(storage.shard_count().unwrap(), 1);
}

#[tokio::test]
async fn handle_storage_warning_intact_shard_returns_true() {
    let (storage, db, _dir) = make_storage(100.0);
    let blob: Vec<u8> = vec![0xCCu8; 1024];
    let signing_key = make_signing_key();
    let owner_pub = identity_from_key(&signing_key);
    insert_peer(&db, owner_pub);

    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    storage.store_shard(&descriptor, &blob).await.unwrap();

    let intact = storage.handle_storage_warning(descriptor.shard_id).unwrap();
    assert!(intact, "intact shard should return true");
}

#[test]
fn merkle_tree_single_block() {
    let blob = vec![0xAAu8; BLOCK_SIZE];
    let tree = build_merkle_tree(&blob);
    // Single leaf padded to power of 2 = 1, tree has 1 node (root == leaf)
    assert_eq!(tree.len(), 1);
    let proof = merkle_proof_path(&tree, 0);
    assert!(proof.is_empty(), "single-node tree has empty proof");
}

#[test]
fn merkle_tree_two_blocks() {
    let blob = vec![0xBBu8; 2 * BLOCK_SIZE];
    let tree = build_merkle_tree(&blob);
    // 2 leaves + 1 root = 3 nodes
    assert_eq!(tree.len(), 3);
    let proof0 = merkle_proof_path(&tree, 0);
    assert_eq!(proof0.len(), 1, "2-leaf tree: proof has 1 sibling");
    // Sibling of leaf[0] is leaf[1]
    assert_eq!(proof0[0], tree[1]);
}

#[test]
fn merkle_tree_three_blocks_padded_to_four() {
    let blob = vec![0xCCu8; 3 * BLOCK_SIZE];
    let tree = build_merkle_tree(&blob);
    // 3 blocks → padded to 4 leaves → 4 + 2 + 1 = 7 nodes
    assert_eq!(tree.len(), 7);
    let proof = merkle_proof_path(&tree, 1);
    // log2(4) = 2 levels → 2 siblings
    assert_eq!(proof.len(), 2);
}

#[test]
fn merkle_root_matches_descriptor() {
    // Verify that the merkle root computed in make_descriptor matches the tree root
    let blob: Vec<u8> = vec![0x42u8; 3 * BLOCK_SIZE];
    let signing_key = make_signing_key();
    let descriptor = make_descriptor(&blob, &signing_key, 0.5, MsgFileType::User);
    let tree = build_merkle_tree(&blob);
    let root = tree[tree.len() - 1];
    assert_eq!(descriptor.merkle_root, root);
}

#[test]
fn merkle_proof_verifiable() {
    // Build a tree and verify the proof for each leaf
    let blob: Vec<u8> = vec![0x11u8; 4 * BLOCK_SIZE];
    let tree = build_merkle_tree(&blob);
    let root = tree[tree.len() - 1];

    for leaf_idx in 0..4 {
        let proof = merkle_proof_path(&tree, leaf_idx);
        assert_eq!(proof.len(), 2); // log2(4) = 2

        // Reconstruct root from leaf hash + proof
        let mut current = tree[leaf_idx];
        let mut idx = leaf_idx;
        for sibling in &proof {
            let (left, right) = if idx % 2 == 0 {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            let mut hasher = blake3::Hasher::new();
            hasher.update(&left);
            hasher.update(&right);
            current = *hasher.finalize().as_bytes();
            idx /= 2;
        }
        assert_eq!(current, root, "proof for leaf {leaf_idx} should reconstruct root");
    }
}

#[tokio::test]
async fn check_pressure_normal_when_under_soft_threshold() {
    let (storage, _db, _dir) = make_storage(100.0);
    // No shards stored → used = 0 → Normal pressure
    let result = storage.check_pressure(Timestamp(0)).unwrap();
    assert_eq!(result.pressure, syncback_core::budget::DiskPressure::Normal);
    assert!(result.immediate_evictions.is_empty());
}
