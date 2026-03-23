use super::*;
use crate::db::testutil::test_db;
use crate::db::WeeklyPosEntry;
use crate::types::{
    DeviceId, FileId, FileRecord, IdentityPub, LocalState, PeerRecord,
    PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType,
    SymbolPlacement, Timestamp,
};

// ============================================================
// Test helpers
// ============================================================

fn make_key() -> [u8; 32] {
    [42u8; 32]
}

fn make_alt_key() -> [u8; 32] {
    [99u8; 32]
}

fn make_file(path: &str, id: u64) -> FileRecord {
    FileRecord {
        file_id: FileId(id),
        path: path.to_string(),
        importance: 0.5,
        devices: vec![(DeviceId([0u8; 16]), LocalState::Present)],
        versions: vec![],
        first_seen: Timestamp(1000),
    }
}

fn make_source_block(seed: u8) -> SourceBlockRecord {
    SourceBlockRecord {
        block_id: SourceBlockId([seed; 32]),
        k: 10,
        t: 65535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(1000),
        encrypted_size: None,
        n: None,
        overhead: None,
    }
}

fn make_placement(block_seed: u8, holder: IdentityPub, file_id: FileId) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: SourceBlockId([block_seed; 32]),
        holder_id: holder,
        file_id,
        esi_ranges: vec![(0, 10)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(1000),
        consecutive_misses: 0,
    }
}

fn make_peer(seed: u8) -> PeerRecord {
    PeerRecord {
        identity: IdentityPub([seed; 32]),
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1000),
        last_seen: Timestamp(2000),
        device_id: None,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
    }
}

// ============================================================
// Tests
// ============================================================

#[test]
fn empty_db_roundtrip() {
    // Snapshot empty DB, pack, unpack, restore — all counts = 0.
    let db = test_db();
    let key = make_key();

    let state = snapshot_db(&db).unwrap();
    assert_eq!(state.files.len(), 0);
    assert_eq!(state.peers.len(), 0);
    assert_eq!(state.source_blocks.len(), 0);
    assert_eq!(state.symbol_placements.len(), 0);
    assert_eq!(state.pos_weekly.len(), 0);
    assert!(state.cluster_state.is_none());

    let blob = pack_system_state(&state, &key).unwrap();
    let unpacked = unpack_system_state(&blob, &key).unwrap();
    assert_eq!(unpacked.files.len(), 0);
    assert_eq!(unpacked.peers.len(), 0);
    assert_eq!(unpacked.version, SYSTEM_STATE_VERSION);

    let db2 = test_db();
    restore_db(&db2, &unpacked).unwrap();
    assert_eq!(db2.list_all_files().unwrap().len(), 0);
    assert_eq!(db2.list_all_peers().unwrap().len(), 0);
}

#[test]
fn roundtrip_snapshot_pack_unpack_restore() {
    // Populate DB with test data, snapshot, pack, unpack, restore to new DB, verify.
    let db = test_db();
    let key = make_key();

    // Insert data
    let file1 = make_file("docs/a.txt", 1);
    let file2 = make_file("photos/b.jpg", 2);
    db.upsert_file(&file1).unwrap();
    db.upsert_file(&file2).unwrap();

    let sb1 = make_source_block(1);
    let sb2 = make_source_block(2);
    db.upsert_source_block(&sb1).unwrap();
    db.upsert_source_block(&sb2).unwrap();

    let holder = IdentityPub([7u8; 32]);
    let placement = make_placement(1, holder, FileId(1));
    db.upsert_placement(&placement).unwrap();

    let peer1 = make_peer(10);
    let peer2 = make_peer(20);
    db.upsert_peer(&peer1).unwrap();
    db.upsert_peer(&peer2).unwrap();

    // Insert a pos_weekly entry
    db.upsert_pos_weekly(&IdentityPub([10u8; 32]), 5, &WeeklyPosEntry { challenged: 3, passed: 2 })
        .unwrap();

    // Snapshot + pack + unpack
    let state = snapshot_db(&db).unwrap();
    assert_eq!(state.files.len(), 2);
    assert_eq!(state.source_blocks.len(), 2);
    assert_eq!(state.symbol_placements.len(), 1);
    assert_eq!(state.peers.len(), 2);
    assert_eq!(state.pos_weekly.len(), 1);

    let blob = pack_system_state(&state, &key).unwrap();
    let unpacked = unpack_system_state(&blob, &key).unwrap();

    assert_eq!(unpacked.files.len(), 2);
    assert_eq!(unpacked.source_blocks.len(), 2);
    assert_eq!(unpacked.symbol_placements.len(), 1);
    assert_eq!(unpacked.peers.len(), 2);
    assert_eq!(unpacked.pos_weekly.len(), 1);
    assert_eq!(unpacked.version, SYSTEM_STATE_VERSION);

    // Restore into fresh DB and verify
    let db2 = test_db();
    restore_db(&db2, &unpacked).unwrap();

    assert_eq!(db2.list_all_files().unwrap().len(), 2);
    assert_eq!(db2.list_all_source_blocks().unwrap().len(), 2);
    assert_eq!(db2.list_all_placements().unwrap().len(), 1);
    assert_eq!(db2.list_all_peers().unwrap().len(), 2);

    // Verify pos_weekly was restored
    let pos_entry = db2
        .get_pos_weekly(&IdentityPub([10u8; 32]), 5)
        .unwrap()
        .unwrap();
    assert_eq!(pos_entry.challenged, 3);
    assert_eq!(pos_entry.passed, 2);

    // Verify file paths round-tripped
    let paths: Vec<String> = db2
        .list_all_files()
        .unwrap()
        .iter()
        .map(|f| f.path.clone())
        .collect();
    assert!(paths.contains(&"docs/a.txt".to_string()));
    assert!(paths.contains(&"photos/b.jpg".to_string()));
}

#[test]
fn wrong_key_fails() {
    // Pack with key A, unpack with key B → Encryption error.
    let db = test_db();
    let key_a = make_key();
    let key_b = make_alt_key();

    let state = snapshot_db(&db).unwrap();
    let blob = pack_system_state(&state, &key_a).unwrap();

    let result = unpack_system_state(&blob, &key_b);
    assert!(
        matches!(result, Err(SystemStateError::Encryption(_))),
        "expected Encryption error, got: {result:?}"
    );
}

#[test]
fn blob_too_short_fails() {
    // unpack with blob shorter than 52 bytes → BlobTooShort.
    let key = make_key();

    let result = unpack_system_state(&[0u8; 10], &key);
    assert!(
        matches!(result, Err(SystemStateError::BlobTooShort { expected: 52, got: 10 })),
        "expected BlobTooShort, got: {result:?}"
    );

    // Exactly 51 bytes — still too short.
    let result = unpack_system_state(&[0u8; 51], &key);
    assert!(
        matches!(result, Err(SystemStateError::BlobTooShort { .. })),
        "expected BlobTooShort for 51-byte blob"
    );

    // Empty blob.
    let result = unpack_system_state(&[], &key);
    assert!(matches!(result, Err(SystemStateError::BlobTooShort { .. })));
}

#[test]
fn restore_into_nonempty_db_fails() {
    // Populate DB, try restore_db → DbNotEmpty.
    // restore_db_force should succeed.
    let db = test_db();
    let key = make_key();

    // Get an empty state blob
    let empty_db = test_db();
    let state = snapshot_db(&empty_db).unwrap();
    let blob = pack_system_state(&state, &key).unwrap();
    let unpacked = unpack_system_state(&blob, &key).unwrap();

    // Put data in db
    db.upsert_file(&make_file("x.txt", 1)).unwrap();

    // restore_db should refuse
    let result = restore_db(&db, &unpacked);
    assert!(
        matches!(result, Err(SystemStateError::DbNotEmpty)),
        "expected DbNotEmpty, got: {result:?}"
    );

    // restore_db_force should succeed
    restore_db_force(&db, &unpacked).unwrap();
}

#[test]
fn pack_produces_different_blobs() {
    // Same state packed twice → different blobs (random salt + nonce).
    let db = test_db();
    let key = make_key();

    let state = snapshot_db(&db).unwrap();
    let blob1 = pack_system_state(&state, &key).unwrap();
    let blob2 = pack_system_state(&state, &key).unwrap();

    // Both should decode correctly
    unpack_system_state(&blob1, &key).unwrap();
    unpack_system_state(&blob2, &key).unwrap();

    // But the blobs themselves must differ (random salt)
    assert_ne!(blob1, blob2, "two packs of the same state should produce different blobs");
}

#[test]
fn cluster_state_roundtrip() {
    // SystemState with cluster_state = None round-trips correctly.
    // (Full cluster state test would require cluster module setup.)
    let db = test_db();
    let key = make_key();

    let state = snapshot_db(&db).unwrap();
    assert!(state.cluster_state.is_none());

    let blob = pack_system_state(&state, &key).unwrap();
    let unpacked = unpack_system_state(&blob, &key).unwrap();
    assert!(unpacked.cluster_state.is_none());

    let db2 = test_db();
    restore_db(&db2, &unpacked).unwrap();
    assert!(db2.get_cluster_state().unwrap().is_none());
}

#[test]
fn multiple_pos_weekly_entries_roundtrip() {
    // Multiple pos_weekly entries across different peers and weeks.
    let db = test_db();
    let key = make_key();

    let peer_a = IdentityPub([1u8; 32]);
    let peer_b = IdentityPub([2u8; 32]);

    db.upsert_pos_weekly(&peer_a, 1, &WeeklyPosEntry { challenged: 10, passed: 8 }).unwrap();
    db.upsert_pos_weekly(&peer_a, 2, &WeeklyPosEntry { challenged: 20, passed: 18 }).unwrap();
    db.upsert_pos_weekly(&peer_b, 1, &WeeklyPosEntry { challenged: 5, passed: 5 }).unwrap();

    let state = snapshot_db(&db).unwrap();
    assert_eq!(state.pos_weekly.len(), 3);

    let blob = pack_system_state(&state, &key).unwrap();
    let unpacked = unpack_system_state(&blob, &key).unwrap();

    let db2 = test_db();
    restore_db(&db2, &unpacked).unwrap();

    let a1 = db2.get_pos_weekly(&peer_a, 1).unwrap().unwrap();
    assert_eq!(a1.challenged, 10);
    assert_eq!(a1.passed, 8);

    let a2 = db2.get_pos_weekly(&peer_a, 2).unwrap().unwrap();
    assert_eq!(a2.challenged, 20);
    assert_eq!(a2.passed, 18);

    let b1 = db2.get_pos_weekly(&peer_b, 1).unwrap().unwrap();
    assert_eq!(b1.challenged, 5);
    assert_eq!(b1.passed, 5);
}
