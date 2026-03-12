use syncback_core::db::Db;
use syncback_core::testutil::{test_db, test_peer, test_shard_id, test_unit_id};
use syncback_core::trust::TrustEngine;
use syncback_core::types::{
    BudgetRecord, FileId, FileRecord, FileType, HoldingRecord, IdentityPub, PeerRecord, ShardId,
    ShardRecord, ShardState, ShardStatus, Timestamp, UnitId, UnitRecord, UnitStatus, UnitType,
};

use super::*;

fn test_key() -> [u8; 32] {
    [0u8; 32]
}

fn make_file_record(path: &str, file_id: u64) -> FileRecord {
    FileRecord {
        file_id: FileId(file_id),
        path: path.to_string(),
        content_hash: [file_id as u8; 32],
        size_bytes: 1024 * file_id,
        importance: 0.8,
        dirty: false,
        current_unit_id: Some(test_unit_id(1)),
        last_backed_up: Some(Timestamp(1_700_000_000 + file_id)),
        backed_up: true,
        first_seen: Timestamp(1_700_000_000),
    }
}

fn make_peer_record(identity: IdentityPub, trust_p: f64, trust_i: f64) -> PeerRecord {
    PeerRecord {
        identity,
        node_id: None,
        trust_p,
        trust_i,
        trust_s: 1.0,
        bytes_sent_to_peer: 1024,
        bytes_received_from_peer: 2048,
        first_seen: Timestamp(1_700_000_000),
        last_seen: Timestamp(1_700_000_100),
        weeks_in_network: 10,
        subnet_prefix: None,
        allowlisted: false,
    }
}

fn make_unit_record(unit_id: UnitId) -> UnitRecord {
    UnitRecord {
        unit_id,
        unit_type: UnitType::Pack,
        status: UnitStatus::Active,
        member_file_ids: vec![FileId(1), FileId(2)],
        chunk_index: None,
        parent_file_id: None,
        size_bytes: 2048,
        plaintext_hash: [0u8; 32],
        created_at: Timestamp(1_700_000_000),
        importance_avg: 0.8,
        rs_k: 5,
        rs_n: 15,
    }
}

fn make_shard_record(shard_id: ShardId, unit_id: UnitId, holder: IdentityPub) -> ShardRecord {
    ShardRecord {
        shard_id,
        unit_id,
        shard_index: 0,
        holder_id: holder,
        status: ShardStatus::Stored,
        last_verified: Some(Timestamp(1_700_000_000)),
        offered_at: Timestamp(1_700_000_000),
        stored_at: Some(Timestamp(1_700_000_010)),
        merkle_root: [1u8; 32],
    }
}

fn make_populated_db() -> (Db, tempfile::NamedTempFile) {
    let (db, tmp) = test_db();
    for i in 1u64..=3 {
        db.upsert_file(&make_file_record(&format!("/home/user/doc{i}.txt"), i)).unwrap();
    }
    for i in [1u8, 2] {
        db.upsert_peer(&make_peer_record(test_peer(i), 0.9 - (i as f64 * 0.1), 0.8)).unwrap();
    }
    let unit_id = test_unit_id(1);
    db.upsert_unit(&make_unit_record(unit_id)).unwrap();
    for i in [10u8, 11] {
        db.upsert_shard(&make_shard_record(test_shard_id(i), unit_id, test_peer(i - 9))).unwrap();
    }
    (db, tmp)
}

#[test]
fn roundtrip_snapshot_pack_unpack_restore() {
    let (db, _tmp) = make_populated_db();

    let state = snapshot_db(&db).unwrap();
    assert_eq!(state.files.len(), 3);
    assert_eq!(state.peers.len(), 2);
    assert_eq!(state.units.len(), 1);
    assert_eq!(state.shards.len(), 2);
    assert_eq!(state.version, SYSTEM_STATE_VERSION);

    let key = test_key();
    let blob = pack_system_state(&state, &key).unwrap();
    let state2 = unpack_system_state(&blob, &key).unwrap();

    let (db2, _tmp2) = test_db();
    restore_db(&db2, &state2).unwrap();

    let restored_files = db2.list_all_files().unwrap();
    assert_eq!(restored_files.len(), 3);

    let mut ids: Vec<u64> = restored_files.iter().map(|f| f.file_id.0).collect();
    ids.sort();
    assert_eq!(ids, vec![1, 2, 3]);

    let restored_peers = db2.list_all_peers().unwrap();
    assert_eq!(restored_peers.len(), 2);

    let restored_shards = db2.list_all_shards().unwrap();
    assert_eq!(restored_shards.len(), 2);

    let restored_units = db2.list_units_by_status(UnitStatus::Active).unwrap();
    assert_eq!(restored_units.len(), 1);
    assert_eq!(restored_units[0].unit_id, test_unit_id(1));

    let peer1 = restored_peers.iter().find(|p| p.identity == test_peer(1)).unwrap();
    assert!((peer1.trust_p - 0.8).abs() < 1e-10);
    assert!((peer1.trust_i - 0.8).abs() < 1e-10);
}

#[test]
fn empty_db_roundtrip() {
    let (db, _tmp) = test_db();

    let state = snapshot_db(&db).unwrap();
    assert!(state.files.is_empty());
    assert!(state.units.is_empty());
    assert!(state.shards.is_empty());
    assert!(state.peers.is_empty());
    assert!(state.pos_weekly.is_empty());
    assert!(state.config.is_empty());

    let key = [1u8; 32];
    let blob = pack_system_state(&state, &key).unwrap();
    let state2 = unpack_system_state(&blob, &key).unwrap();

    let (db2, _tmp2) = test_db();
    restore_db(&db2, &state2).unwrap();

    assert!(db2.list_all_files().unwrap().is_empty());
    assert!(db2.list_all_peers().unwrap().is_empty());
}

#[test]
fn large_db_roundtrip() {
    let (db, _tmp) = test_db();

    for i in 0..1000u64 {
        db.upsert_file(&FileRecord {
            file_id: FileId(i),
            path: format!("/home/user/f{i}.txt"),
            content_hash: [(i % 255) as u8; 32],
            size_bytes: 4096 + i,
            importance: 0.8,
            dirty: false,
            current_unit_id: Some(UnitId([(i % 200) as u8; 32])),
            last_backed_up: Some(Timestamp(1_700_000_000 + i)),
            backed_up: true,
            first_seen: Timestamp(1_700_000_000),
        }).unwrap();
    }

    for i in 0..200u8 {
        db.upsert_unit(&UnitRecord {
            unit_id: UnitId([i; 32]),
            unit_type: UnitType::Pack,
            status: UnitStatus::Active,
            member_file_ids: vec![FileId(i as u64 * 5)],
            chunk_index: None,
            parent_file_id: None,
            size_bytes: 8192,
            plaintext_hash: [i; 32],
            created_at: Timestamp(1_700_000_000 + i as u64),
            importance_avg: 0.8,
            rs_k: 5,
            rs_n: 15,
        }).unwrap();
    }

    for i in 0..3000u32 {
        let mut shard_bytes = [0u8; 32];
        shard_bytes[..4].copy_from_slice(&i.to_be_bytes());
        let unit_bytes = [(i % 200) as u8; 32];
        let mut holder_bytes = [0u8; 32];
        holder_bytes[0] = (i % 50) as u8;
        db.upsert_shard(&ShardRecord {
            shard_id: ShardId(shard_bytes),
            unit_id: UnitId(unit_bytes),
            shard_index: (i % 15) as u8,
            holder_id: IdentityPub(holder_bytes),
            status: ShardStatus::Stored,
            last_verified: Some(Timestamp(1_700_000_000)),
            offered_at: Timestamp(1_700_000_000),
            stored_at: Some(Timestamp(1_700_000_010)),
            merkle_root: [1u8; 32],
        }).unwrap();
    }

    for i in 0..50u8 {
        db.upsert_peer(&PeerRecord {
            identity: IdentityPub([i; 32]),
            node_id: None,
            trust_p: 0.9,
            trust_i: 0.8,
            trust_s: 1.0,
            bytes_sent_to_peer: 1000,
            bytes_received_from_peer: 1000,
            first_seen: Timestamp(1_700_000_000),
            last_seen: Timestamp(1_700_000_100),
            weeks_in_network: 20,
            subnet_prefix: None,
            allowlisted: false,
        }).unwrap();
    }

    let state = snapshot_db(&db).unwrap();
    let key = [42u8; 32];
    let blob = pack_system_state(&state, &key).unwrap();

    assert!(blob.len() < 5 * 1024 * 1024, "blob too large: {} bytes", blob.len());

    let state2 = unpack_system_state(&blob, &key).unwrap();
    let (db2, _tmp2) = test_db();
    restore_db(&db2, &state2).unwrap();

    assert_eq!(db2.list_all_files().unwrap().len(), 1000);
    assert_eq!(db2.list_all_shards().unwrap().len(), 3000);
    assert_eq!(db2.list_all_peers().unwrap().len(), 50);
    let mut unit_count = db2.list_units_by_status(UnitStatus::Active).unwrap().len();
    unit_count += db2.list_units_by_status(UnitStatus::Stale).unwrap().len();
    unit_count += db2.list_units_by_status(UnitStatus::Deleting).unwrap().len();
    assert_eq!(unit_count, 200);
}

#[test]
fn corrupt_blob_fails_gracefully() {
    let (db, _tmp) = make_populated_db();
    let state = snapshot_db(&db).unwrap();
    let key = test_key();
    let blob = pack_system_state(&state, &key).unwrap();

    let corrupt_blob = blob[..blob.len() - 1].to_vec();
    let result = unpack_system_state(&corrupt_blob, &key);
    assert!(
        matches!(result, Err(SystemStateError::Encryption(_))),
        "expected Encryption on truncated blob, got: {result:?}"
    );

    let mut corrupted_mid = blob.clone();
    corrupted_mid[50] ^= 0xFF;
    let result2 = unpack_system_state(&corrupted_mid, &key);
    assert!(
        matches!(result2, Err(SystemStateError::Encryption(_))),
        "expected Encryption on mid-corrupt blob, got: {result2:?}"
    );
}

#[test]
fn wrong_key_fails() {
    let (db, _tmp) = make_populated_db();
    let state = snapshot_db(&db).unwrap();
    let blob = pack_system_state(&state, &[0u8; 32]).unwrap();

    let result = unpack_system_state(&blob, &[1u8; 32]);
    assert!(
        matches!(result, Err(SystemStateError::Encryption(_))),
        "expected Encryption with wrong key, got: {result:?}"
    );
}

#[test]
fn version_too_new_fails() {
    let (db, _tmp) = test_db();
    let mut state = snapshot_db(&db).unwrap();
    state.version = 255;

    let key = test_key();
    let blob = pack_system_state(&state, &key).unwrap();
    let result = unpack_system_state(&blob, &key);
    assert!(
        matches!(result, Err(SystemStateError::UnsupportedVersion { found: 255, max: 1 })),
        "expected UnsupportedVersion, got: {result:?}"
    );
}

#[test]
fn blob_too_short_fails() {
    let key = test_key();

    let r1 = unpack_system_state(&[0u8; 51], &key);
    assert!(
        matches!(r1, Err(SystemStateError::BlobTooShort { expected: 52, got: 51 })),
        "expected BlobTooShort {{52, 51}}, got: {r1:?}"
    );

    let r2 = unpack_system_state(&[], &key);
    assert!(
        matches!(r2, Err(SystemStateError::BlobTooShort { expected: 52, got: 0 })),
        "expected BlobTooShort {{52, 0}}, got: {r2:?}"
    );
}

#[test]
fn restore_into_nonempty_db_fails() {
    let (db, _tmp) = test_db();
    db.upsert_file(&make_file_record("/home/user/existing.txt", 99)).unwrap();

    let (db_empty, _tmp2) = test_db();
    let state = snapshot_db(&db_empty).unwrap();

    let result = restore_db(&db, &state);
    assert!(
        matches!(result, Err(SystemStateError::DbNotEmpty)),
        "expected DbNotEmpty, got: {result:?}"
    );
}

#[test]
fn snapshot_excludes_holding_and_budget() {
    let (db, _tmp) = test_db();

    db.upsert_holding(&HoldingRecord {
        shard_id: test_shard_id(1),
        owner_pub: test_peer(1),
        importance: 0.8,
        size_bytes: 1024,
        state: ShardState::Active,
        received_at: Timestamp(1_700_000_000),
        delete_requested_at: None,
        drop_notice_sent_at: None,
        file_type: FileType::User,
        merkle_root: [0u8; 32],
        rs_k: 5,
        rs_n: 15,
        shard_index: 0,
    }).unwrap();

    db.set_budget(&BudgetRecord {
        estimated_gb: 50.0,
        last_calculated: Timestamp(1_700_000_000),
        placement_success_rate: 0.95,
        weekly_stats: vec![],
    }).unwrap();

    let state = snapshot_db(&db).unwrap();
    let key = test_key();
    let blob = pack_system_state(&state, &key).unwrap();
    let state2 = unpack_system_state(&blob, &key).unwrap();

    let (db2, _tmp2) = test_db();
    restore_db(&db2, &state2).unwrap();

    assert!(db2.list_all_holding().unwrap().is_empty(), "holding must not be restored");
    assert!(db2.get_budget().unwrap().is_none(), "budget must not be restored");
}

#[test]
fn pos_weekly_roundtrip() {
    use syncback_core::trust::PosOutcome;

    let (db, _tmp) = test_db();
    let trust = TrustEngine::new(db.clone());
    let peer = test_peer(1);

    trust.upsert_peer(&peer, Timestamp(1_700_000_000)).unwrap();
    trust
        .record_pos_result(&peer, PosOutcome { week_number: 5, challenged: 10, passed: 8 })
        .unwrap();
    trust
        .record_pos_result(&peer, PosOutcome { week_number: 6, challenged: 10, passed: 9 })
        .unwrap();

    let state = snapshot_db(&db).unwrap();
    assert_eq!(state.pos_weekly.len(), 2);

    let key = test_key();
    let blob = pack_system_state(&state, &key).unwrap();
    let state2 = unpack_system_state(&blob, &key).unwrap();
    assert_eq!(state2.pos_weekly.len(), 2);

    let (db2, _tmp2) = test_db();
    restore_db(&db2, &state2).unwrap();

    let trust2 = TrustEngine::new(db2.clone());
    let now = Timestamp(1_700_000_000 + 7 * 604800);
    let score_orig = trust.recalculate(&peer, now, 7).unwrap();
    let score_restored = trust2.recalculate(&peer, now, 7).unwrap();

    assert!(
        (score_orig.p - score_restored.p).abs() < 1e-10,
        "P scores differ: orig={} restored={}",
        score_orig.p,
        score_restored.p
    );
    assert!(
        (score_orig.combined - score_restored.combined).abs() < 1e-10,
        "combined scores differ: orig={} restored={}",
        score_orig.combined,
        score_restored.combined
    );
}

#[test]
fn config_entries_roundtrip() {
    let (db, _tmp) = test_db();

    db.set_config("storage_quota_gb", &100u64).unwrap();
    db.set_config("node_label", &"my-laptop".to_string()).unwrap();

    let state = snapshot_db(&db).unwrap();
    assert_eq!(state.config.len(), 2);

    let key = test_key();
    let blob = pack_system_state(&state, &key).unwrap();
    let state2 = unpack_system_state(&blob, &key).unwrap();

    let (db2, _tmp2) = test_db();
    restore_db(&db2, &state2).unwrap();

    let quota: Option<u64> = db2.get_config("storage_quota_gb").unwrap();
    assert_eq!(quota, Some(100u64));

    let label: Option<String> = db2.get_config("node_label").unwrap();
    assert_eq!(label, Some("my-laptop".to_string()));
}

#[test]
fn pack_produces_different_blobs_but_both_unpack_correctly() {
    let (db, _tmp) = make_populated_db();
    let state = snapshot_db(&db).unwrap();
    let key = test_key();

    let blob1 = pack_system_state(&state, &key).unwrap();
    let blob2 = pack_system_state(&state, &key).unwrap();

    assert_ne!(blob1, blob2, "random salt must produce different blobs");

    let state1 = unpack_system_state(&blob1, &key).unwrap();
    let state2 = unpack_system_state(&blob2, &key).unwrap();

    assert_eq!(state1.files.len(), state2.files.len());
    assert_eq!(state1.peers.len(), state2.peers.len());
    assert_eq!(state1.shards.len(), state2.shards.len());
    assert_eq!(state1.units.len(), state2.units.len());
    assert_eq!(state1.version, state2.version);

    let mut ids1: Vec<u64> = state1.files.iter().map(|f| f.file_id.0).collect();
    let mut ids2: Vec<u64> = state2.files.iter().map(|f| f.file_id.0).collect();
    ids1.sort();
    ids2.sort();
    assert_eq!(ids1, ids2);
}
