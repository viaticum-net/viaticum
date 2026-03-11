use super::*;
use crate::testutil::{test_db, test_peer, test_shard_id, test_unit_id, week};
use crate::types::{
    FileType, HoldingRecord, NodeId, PeerRecord, ShardRecord, ShardState, ShardStatus,
    UnitRecord, UnitStatus, UnitType,
};

fn make_file_record(path: &str, file_id: u64, dirty: bool) -> FileRecord {
    FileRecord {
        file_id: FileId(file_id),
        path: path.to_string(),
        content_hash: [0u8; 32],
        size_bytes: 1024,
        importance: 0.5,
        dirty,
        current_unit_id: None,
        last_backed_up: None,
        backed_up: false,
        first_seen: Timestamp(100),
    }
}

fn make_unit_record(seed: u8, status: UnitStatus) -> UnitRecord {
    UnitRecord {
        unit_id: test_unit_id(seed),
        unit_type: UnitType::Pack,
        status,
        member_file_ids: vec![FileId(1)],
        chunk_index: None,
        parent_file_id: None,
        size_bytes: 4096,
        plaintext_hash: [0u8; 32],
        created_at: Timestamp(1000),
        importance_avg: 0.5,
        rs_k: 5,
        rs_n: 10,
    }
}

fn make_shard_record(
    shard_seed: u8,
    unit_seed: u8,
    holder_seed: u8,
    status: ShardStatus,
    last_verified: Option<Timestamp>,
) -> ShardRecord {
    ShardRecord {
        shard_id: test_shard_id(shard_seed),
        unit_id: test_unit_id(unit_seed),
        shard_index: 0,
        holder_id: test_peer(holder_seed),
        status,
        last_verified,
        offered_at: Timestamp(500),
        stored_at: None,
    }
}

fn make_peer_record(seed: u8) -> PeerRecord {
    PeerRecord {
        identity: test_peer(seed),
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.3,
        trust_s: 0.8,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: Timestamp(100),
        last_seen: Timestamp(200),
        weeks_in_network: 5,
        subnet_prefix: None,
        allowlisted: false,
    }
}

fn make_holding_record(
    shard_seed: u8,
    owner_seed: u8,
    importance: f64,
    size_bytes: u64,
    received_at: Timestamp,
    state: ShardState,
) -> HoldingRecord {
    HoldingRecord {
        shard_id: test_shard_id(shard_seed),
        owner_pub: test_peer(owner_seed),
        importance,
        size_bytes,
        state,
        received_at,
        delete_requested_at: None,
        drop_notice_sent_at: None,
        file_type: FileType::User,
        merkle_root: [0u8; 32],
        rs_k: 5,
        rs_n: 10,
        shard_index: 0,
    }
}

#[test]
fn db_opens_and_creates_all_tables() {
    let (db, _tmp) = test_db();
    // Verify by writing to each table
    let file = make_file_record("/test/file.txt", 1, false);
    db.upsert_file(&file).unwrap();

    let unit = make_unit_record(1, UnitStatus::Active);
    db.upsert_unit(&unit).unwrap();

    let shard = make_shard_record(1, 1, 1, ShardStatus::Offered, None);
    db.upsert_shard(&shard).unwrap();

    let peer = make_peer_record(1);
    db.upsert_peer(&peer).unwrap();

    let holding = make_holding_record(2, 1, 0.5, 1024, Timestamp(100), ShardState::Active);
    db.upsert_holding(&holding).unwrap();

    let budget = BudgetRecord {
        estimated_gb: 10.0,
        last_calculated: Timestamp(1000),
        placement_success_rate: 0.8,
        weekly_stats: vec![],
    };
    db.set_budget(&budget).unwrap();

    let schedule = ScheduleRecord {
        task_name: "weekly_sync".to_string(),
        last_run: None,
        next_run: Timestamp(7 * 86400),
    };
    db.set_schedule(&schedule).unwrap();

    db.set_config("test_key", &42u64).unwrap();
}

#[test]
fn file_upsert_and_get_roundtrip() {
    let (db, _tmp) = test_db();
    let record = FileRecord {
        file_id: FileId(7),
        path: "/home/user/photo.jpg".to_string(),
        content_hash: [0xAB; 32],
        size_bytes: 2048,
        importance: 0.7,
        dirty: false,
        current_unit_id: Some(test_unit_id(3)),
        last_backed_up: Some(Timestamp(999)),
        backed_up: true,
        first_seen: Timestamp(500),
    };
    db.upsert_file(&record).unwrap();
    let got = db.get_file("/home/user/photo.jpg").unwrap().unwrap();
    assert_eq!(got.file_id, record.file_id);
    assert_eq!(got.path, record.path);
    assert_eq!(got.content_hash, record.content_hash);
    assert_eq!(got.size_bytes, record.size_bytes);
    assert_eq!(got.importance, record.importance);
    assert_eq!(got.dirty, record.dirty);
    assert_eq!(got.current_unit_id, record.current_unit_id);
    assert_eq!(got.last_backed_up, record.last_backed_up);
    assert_eq!(got.backed_up, record.backed_up);
    assert_eq!(got.first_seen, record.first_seen);
}

#[test]
fn file_not_found_returns_none() {
    let (db, _tmp) = test_db();
    let result = db.get_file("nonexistent/path");
    assert!(matches!(result, Ok(None)));
}

#[test]
fn mark_file_dirty_updates_index() {
    let (db, _tmp) = test_db();
    let record = make_file_record("/doc.txt", 1, false);
    db.upsert_file(&record).unwrap();

    db.mark_file_dirty("/doc.txt", Timestamp(300)).unwrap();

    let got = db.get_file("/doc.txt").unwrap().unwrap();
    assert!(got.dirty);

    let dirty = db.list_dirty_files().unwrap();
    assert!(dirty.contains(&"/doc.txt".to_string()));
}

#[test]
fn mark_file_clean_removes_from_index() {
    let (db, _tmp) = test_db();
    let mut record = make_file_record("/doc.txt", 1, true);
    record.dirty = true;
    db.upsert_file(&record).unwrap();

    let ts = Timestamp(500);
    let unit_id = test_unit_id(9);
    db.mark_file_clean("/doc.txt", ts, unit_id).unwrap();

    let got = db.get_file("/doc.txt").unwrap().unwrap();
    assert!(!got.dirty);
    assert_eq!(got.last_backed_up, Some(ts));
    assert_eq!(got.current_unit_id, Some(unit_id));
    assert!(got.backed_up);

    let dirty = db.list_dirty_files().unwrap();
    assert!(!dirty.contains(&"/doc.txt".to_string()));
}

#[test]
fn list_dirty_files_returns_oldest_first() {
    let (db, _tmp) = test_db();

    // Insert file records first
    let paths = ["/a.txt", "/b.txt", "/c.txt"];
    for (i, path) in paths.iter().enumerate() {
        let mut r = make_file_record(path, i as u64 + 1, false);
        r.dirty = false;
        db.upsert_file(&r).unwrap();
    }

    // Mark dirty with timestamps: 100, 50, 200
    db.mark_file_dirty("/a.txt", Timestamp(100)).unwrap();
    db.mark_file_dirty("/b.txt", Timestamp(50)).unwrap();
    db.mark_file_dirty("/c.txt", Timestamp(200)).unwrap();

    let dirty = db.list_dirty_files().unwrap();
    assert_eq!(dirty.len(), 3);
    assert_eq!(dirty[0], "/b.txt");
    assert_eq!(dirty[1], "/a.txt");
    assert_eq!(dirty[2], "/c.txt");
}

#[test]
fn unit_upsert_and_get_roundtrip() {
    let (db, _tmp) = test_db();
    let record = make_unit_record(5, UnitStatus::Active);
    db.upsert_unit(&record).unwrap();
    let got = db.get_unit(&record.unit_id).unwrap().unwrap();
    assert_eq!(got.unit_id, record.unit_id);
    assert_eq!(got.status, record.status);
    assert_eq!(got.rs_k, record.rs_k);
    assert_eq!(got.rs_n, record.rs_n);
}

#[test]
fn mark_unit_stale_updates_index() {
    let (db, _tmp) = test_db();
    let record = make_unit_record(5, UnitStatus::Active);
    db.upsert_unit(&record).unwrap();

    db.mark_unit_stale(&record.unit_id, 0.4).unwrap();

    let got = db.get_unit(&record.unit_id).unwrap().unwrap();
    assert_eq!(got.status, UnitStatus::Stale);

    let stale = db.list_stale_units().unwrap();
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].0, record.unit_id);
    assert!((stale[0].1 - 0.4).abs() < f64::EPSILON);
}

#[test]
fn upsert_unit_active_removes_from_stale_index() {
    let (db, _tmp) = test_db();
    let unit_id = test_unit_id(7);
    let record = make_unit_record(7, UnitStatus::Active);
    db.upsert_unit(&record).unwrap();
    db.mark_unit_stale(&unit_id, 0.6).unwrap();

    let mut updated = db.get_unit(&unit_id).unwrap().unwrap();
    updated.status = UnitStatus::Active;
    db.upsert_unit(&updated).unwrap();

    let stale = db.list_stale_units().unwrap();
    assert!(stale.iter().all(|(id, _)| *id != unit_id));
}

#[test]
fn shard_upsert_and_get_roundtrip() {
    let (db, _tmp) = test_db();
    let record = make_shard_record(3, 1, 2, ShardStatus::Stored, None);
    db.upsert_shard(&record).unwrap();
    let got = db.get_shard(&record.shard_id).unwrap().unwrap();
    assert_eq!(got.shard_id, record.shard_id);
    assert_eq!(got.unit_id, record.unit_id);
    assert_eq!(got.status, record.status);
    assert_eq!(got.last_verified, None);
}

#[test]
fn list_shards_for_unit_returns_correct_shards() {
    let (db, _tmp) = test_db();
    let unit_a = test_unit_id(10);
    let unit_b = test_unit_id(11);

    for i in 0..5u8 {
        let mut s = make_shard_record(i, 10, i, ShardStatus::Stored, None);
        s.unit_id = unit_a;
        db.upsert_shard(&s).unwrap();
    }
    for i in 5..8u8 {
        let mut s = make_shard_record(i, 11, i, ShardStatus::Stored, None);
        s.unit_id = unit_b;
        db.upsert_shard(&s).unwrap();
    }

    let shards_a = db.list_shards_for_unit(&unit_a).unwrap();
    assert_eq!(shards_a.len(), 5);
    assert!(shards_a.iter().all(|s| s.unit_id == unit_a));

    let shards_b = db.list_shards_for_unit(&unit_b).unwrap();
    assert_eq!(shards_b.len(), 3);
}

#[test]
fn list_shards_needing_pos_respects_threshold() {
    let (db, _tmp) = test_db();

    // Shard 1: last_verified=None (stored as 0)
    let s1 = make_shard_record(1, 1, 1, ShardStatus::Stored, None);
    db.upsert_shard(&s1).unwrap();

    // Shard 2: last_verified=100 (old)
    let s2 = make_shard_record(2, 1, 2, ShardStatus::Stored, Some(Timestamp(100)));
    db.upsert_shard(&s2).unwrap();

    // Shard 3: last_verified=9999 (recent)
    let s3 = make_shard_record(3, 1, 3, ShardStatus::Stored, Some(Timestamp(9999)));
    db.upsert_shard(&s3).unwrap();

    let needing = db
        .list_shards_needing_pos(Timestamp(500), 10)
        .unwrap();
    assert_eq!(needing.len(), 2);
    assert!(needing.contains(&s1.shard_id));
    assert!(needing.contains(&s2.shard_id));
    assert!(!needing.contains(&s3.shard_id));
}

#[test]
fn record_pos_verified_updates_shard_and_index() {
    let (db, _tmp) = test_db();

    let s = make_shard_record(1, 1, 1, ShardStatus::Stored, None);
    db.upsert_shard(&s).unwrap();

    let ts = Timestamp(1000);
    db.record_pos_verified(&s.shard_id, ts).unwrap();

    let got = db.get_shard(&s.shard_id).unwrap().unwrap();
    assert_eq!(got.last_verified, Some(ts));

    // Should NOT appear in list_shards_needing_pos with older_than = ts+1
    let needing = db
        .list_shards_needing_pos(Timestamp(ts.0 + 1), 10)
        .unwrap();
    assert!(!needing.contains(&s.shard_id));
}

#[test]
fn peer_upsert_and_get_roundtrip() {
    let (db, _tmp) = test_db();

    let peer_with_subnet = PeerRecord {
        identity: test_peer(5),
        node_id: Some(NodeId([9u8; 32])),
        trust_p: 0.6,
        trust_i: 0.4,
        trust_s: 1.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: Timestamp(100),
        last_seen: Timestamp(500),
        weeks_in_network: 8,
        subnet_prefix: Some([10, 0, 0]),
        allowlisted: false,
    };
    db.upsert_peer(&peer_with_subnet).unwrap();
    let got = db.get_peer(&peer_with_subnet.identity).unwrap().unwrap();
    assert_eq!(got.identity, peer_with_subnet.identity);
    assert_eq!(got.subnet_prefix, Some([10, 0, 0]));
    assert_eq!(got.weeks_in_network, 8);

    let peer_no_subnet = PeerRecord {
        identity: test_peer(6),
        node_id: None,
        trust_p: 0.0,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_sent_to_peer: 0,
        bytes_received_from_peer: 0,
        first_seen: Timestamp(50),
        last_seen: Timestamp(50),
        weeks_in_network: 0,
        subnet_prefix: None,
        allowlisted: true,
    };
    db.upsert_peer(&peer_no_subnet).unwrap();
    let got2 = db.get_peer(&peer_no_subnet.identity).unwrap().unwrap();
    assert_eq!(got2.subnet_prefix, None);
    assert!(got2.allowlisted);
}

#[test]
fn increment_peer_weeks_adds_one() {
    let (db, _tmp) = test_db();
    let peer = make_peer_record(3);
    db.upsert_peer(&peer).unwrap();

    db.increment_peer_weeks(&peer.identity).unwrap();

    let got = db.get_peer(&peer.identity).unwrap().unwrap();
    assert_eq!(got.weeks_in_network, 6); // was 5, now 6
}

#[test]
fn increment_peer_weeks_on_missing_peer_returns_error() {
    let (db, _tmp) = test_db();
    let result = db.increment_peer_weeks(&test_peer(99));
    assert!(matches!(result, Err(DbError::NotFound(_))));
}

#[test]
fn holding_upsert_and_get_roundtrip() {
    let (db, _tmp) = test_db();
    let record =
        make_holding_record(5, 2, 0.9, 8192, Timestamp(300), ShardState::Active);
    db.upsert_holding(&record).unwrap();
    let got = db.get_holding(&record.shard_id).unwrap().unwrap();
    assert_eq!(got.shard_id, record.shard_id);
    assert_eq!(got.owner_pub, record.owner_pub);
    assert_eq!(got.importance, record.importance);
    assert_eq!(got.size_bytes, record.size_bytes);
    assert_eq!(got.state, record.state);
    assert_eq!(got.received_at, record.received_at);
}

#[test]
fn list_holding_for_eviction_orders_by_importance_then_age() {
    let (db, _tmp) = test_db();

    let h1 = make_holding_record(1, 1, 0.8, 100, Timestamp(100), ShardState::Active);
    let h2 = make_holding_record(2, 1, 0.2, 100, Timestamp(50), ShardState::Active);
    let h3 = make_holding_record(3, 1, 0.2, 100, Timestamp(200), ShardState::Active);

    db.upsert_holding(&h1).unwrap();
    db.upsert_holding(&h2).unwrap();
    db.upsert_holding(&h3).unwrap();

    let eviction = db.list_holding_for_eviction().unwrap();
    assert_eq!(eviction.len(), 3);
    assert_eq!(eviction[0].shard_id, h2.shard_id); // importance=0.2, t=50
    assert_eq!(eviction[1].shard_id, h3.shard_id); // importance=0.2, t=200
    assert_eq!(eviction[2].shard_id, h1.shard_id); // importance=0.8, t=100
}

#[test]
fn total_holding_bytes_sums_correctly() {
    let (db, _tmp) = test_db();

    let h1 = make_holding_record(1, 1, 0.5, 100, Timestamp(100), ShardState::Active);
    let h2 = make_holding_record(2, 1, 0.5, 200, Timestamp(100), ShardState::Active);
    let h3 = make_holding_record(3, 1, 0.5, 300, Timestamp(100), ShardState::MarkedForDelete);

    db.upsert_holding(&h1).unwrap();
    db.upsert_holding(&h2).unwrap();
    db.upsert_holding(&h3).unwrap();

    assert_eq!(db.total_holding_bytes().unwrap(), 600);
}

#[test]
fn mark_holding_for_delete_sets_state_and_timestamp() {
    let (db, _tmp) = test_db();
    let record = make_holding_record(7, 2, 0.5, 1024, Timestamp(100), ShardState::Active);
    db.upsert_holding(&record).unwrap();

    let ts = Timestamp(5000);
    db.mark_holding_for_delete(&record.shard_id, ts).unwrap();

    let got = db.get_holding(&record.shard_id).unwrap().unwrap();
    assert_eq!(got.state, ShardState::MarkedForDelete);
    assert_eq!(got.delete_requested_at, Some(ts));
}

#[test]
fn list_holding_cooldown_expired_uses_4_week_threshold() {
    let (db, _tmp) = test_db();
    let secs_4_weeks = 4u64 * 604800;

    let mut record = make_holding_record(8, 2, 0.5, 1024, Timestamp(100), ShardState::Active);
    record.state = ShardState::MarkedForDelete;
    record.delete_requested_at = Some(Timestamp(0));
    db.upsert_holding(&record).unwrap();

    // Not yet expired
    let expired_early = db
        .list_holding_cooldown_expired(Timestamp(secs_4_weeks - 1))
        .unwrap();
    assert!(expired_early.is_empty());

    // Exactly at expiry
    let expired = db
        .list_holding_cooldown_expired(Timestamp(secs_4_weeks))
        .unwrap();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].shard_id, record.shard_id);
}

#[test]
fn budget_set_and_get_roundtrip() {
    let (db, _tmp) = test_db();
    let record = BudgetRecord {
        estimated_gb: 45.5,
        last_calculated: Timestamp(1000),
        placement_success_rate: 0.87,
        weekly_stats: vec![],
    };
    db.set_budget(&record).unwrap();
    let got = db.get_budget().unwrap().unwrap();
    assert_eq!(got.estimated_gb, 45.5);
    assert_eq!(got.last_calculated, Timestamp(1000));
    assert_eq!(got.placement_success_rate, 0.87);
}

#[test]
fn budget_get_returns_none_on_fresh_db() {
    let (db, _tmp) = test_db();
    assert!(matches!(db.get_budget(), Ok(None)));
}

#[test]
fn schedule_set_and_get_roundtrip() {
    let (db, _tmp) = test_db();
    let record = ScheduleRecord {
        task_name: "pos_checker".to_string(),
        last_run: Some(week(4)),
        next_run: week(5),
    };
    db.set_schedule(&record).unwrap();
    let got = db.get_schedule("pos_checker").unwrap().unwrap();
    assert_eq!(got.task_name, record.task_name);
    assert_eq!(got.last_run, record.last_run);
    assert_eq!(got.next_run, record.next_run);
}

#[test]
fn config_set_and_get_roundtrip() {
    let (db, _tmp) = test_db();
    db.set_config("storage_quota_gb", &100u64).unwrap();
    let val: u64 = db.get_config("storage_quota_gb").unwrap().unwrap();
    assert_eq!(val, 100);
}

#[test]
fn config_get_returns_none_for_missing_key() {
    let (db, _tmp) = test_db();
    let result: Result<Option<u64>, _> = db.get_config("nonexistent");
    assert!(matches!(result, Ok(None)));
}

#[test]
fn db_open_is_idempotent() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    {
        let _db1 = Db::open(&path).unwrap();
    }
    let _db2 = Db::open(&path).unwrap();
}

#[test]
fn list_stale_units_orders_by_ratio_descending() {
    let (db, _tmp) = test_db();

    let u1 = make_unit_record(1, UnitStatus::Active);
    let u2 = make_unit_record(2, UnitStatus::Active);
    let u3 = make_unit_record(3, UnitStatus::Active);
    db.upsert_unit(&u1).unwrap();
    db.upsert_unit(&u2).unwrap();
    db.upsert_unit(&u3).unwrap();

    db.mark_unit_stale(&u1.unit_id, 0.3).unwrap();
    db.mark_unit_stale(&u2.unit_id, 0.9).unwrap();
    db.mark_unit_stale(&u3.unit_id, 0.6).unwrap();

    let stale = db.list_stale_units().unwrap();
    assert_eq!(stale.len(), 3);
    assert!((stale[0].1 - 0.9).abs() < f64::EPSILON);
    assert!((stale[1].1 - 0.6).abs() < f64::EPSILON);
    assert!((stale[2].1 - 0.3).abs() < f64::EPSILON);
}

#[test]
fn update_shard_status_updates_unverified_index() {
    let (db, _tmp) = test_db();

    // Start as Offered
    let s = make_shard_record(1, 1, 1, ShardStatus::Offered, None);
    db.upsert_shard(&s).unwrap();

    // Should NOT be in unverified index (only Stored shards are)
    let needing = db.list_shards_needing_pos(Timestamp(u64::MAX), 10).unwrap();
    assert!(!needing.contains(&s.shard_id));

    // Transition to Stored
    db.update_shard_status(&s.shard_id, ShardStatus::Stored).unwrap();
    let needing2 = db.list_shards_needing_pos(Timestamp(u64::MAX), 10).unwrap();
    assert!(needing2.contains(&s.shard_id));

    // Transition to Lost — should be removed from index
    db.update_shard_status(&s.shard_id, ShardStatus::Lost).unwrap();
    let needing3 = db.list_shards_needing_pos(Timestamp(u64::MAX), 10).unwrap();
    assert!(!needing3.contains(&s.shard_id));
}

#[test]
fn delete_file_removes_from_dirty_index() {
    let (db, _tmp) = test_db();
    let r = make_file_record("/to_delete.txt", 1, false);
    db.upsert_file(&r).unwrap();
    db.mark_file_dirty("/to_delete.txt", Timestamp(100)).unwrap();

    db.delete_file("/to_delete.txt").unwrap();

    assert!(matches!(db.get_file("/to_delete.txt"), Ok(None)));
    let dirty = db.list_dirty_files().unwrap();
    assert!(!dirty.contains(&"/to_delete.txt".to_string()));
}

#[test]
fn delete_unit_removes_from_stale_index() {
    let (db, _tmp) = test_db();
    let u = make_unit_record(4, UnitStatus::Active);
    db.upsert_unit(&u).unwrap();
    db.mark_unit_stale(&u.unit_id, 0.5).unwrap();

    db.delete_unit(&u.unit_id).unwrap();

    assert!(matches!(db.get_unit(&u.unit_id), Ok(None)));
    let stale = db.list_stale_units().unwrap();
    assert!(stale.iter().all(|(id, _)| *id != u.unit_id));
}

#[test]
fn delete_shard_removes_from_unverified_index() {
    let (db, _tmp) = test_db();
    let s = make_shard_record(5, 1, 1, ShardStatus::Stored, None);
    db.upsert_shard(&s).unwrap();

    db.delete_shard(&s.shard_id).unwrap();

    assert!(matches!(db.get_shard(&s.shard_id), Ok(None)));
    let needing = db.list_shards_needing_pos(Timestamp(u64::MAX), 10).unwrap();
    assert!(!needing.contains(&s.shard_id));
}

#[test]
fn touch_peer_creates_record_if_not_exists() {
    let (db, _tmp) = test_db();
    let identity = test_peer(42);
    db.touch_peer(&identity, Timestamp(9999)).unwrap();
    let got = db.get_peer(&identity).unwrap().unwrap();
    assert_eq!(got.identity, identity);
    assert_eq!(got.last_seen, Timestamp(9999));
    assert_eq!(got.weeks_in_network, 0);
    assert_eq!(got.trust_p, 0.0);
}

#[test]
fn touch_peer_updates_existing_last_seen() {
    let (db, _tmp) = test_db();
    let peer = make_peer_record(11);
    db.upsert_peer(&peer).unwrap();
    db.touch_peer(&peer.identity, Timestamp(99999)).unwrap();
    let got = db.get_peer(&peer.identity).unwrap().unwrap();
    assert_eq!(got.last_seen, Timestamp(99999));
    // weeks_in_network should be unchanged
    assert_eq!(got.weeks_in_network, 5);
}

#[test]
fn update_peer_trust_updates_fields() {
    let (db, _tmp) = test_db();
    let peer = make_peer_record(12);
    db.upsert_peer(&peer).unwrap();

    db.update_peer_trust(&peer.identity, 0.9, 0.8, 0.7).unwrap();

    let got = db.get_peer(&peer.identity).unwrap().unwrap();
    assert_eq!(got.trust_p, 0.9);
    assert_eq!(got.trust_i, 0.8);
    assert_eq!(got.trust_s, 0.7);
}

#[test]
fn update_peer_trust_on_missing_peer_returns_error() {
    let (db, _tmp) = test_db();
    let result = db.update_peer_trust(&test_peer(99), 0.5, 0.5, 0.5);
    assert!(matches!(result, Err(DbError::NotFound(_))));
}

#[test]
fn list_holding_drop_notice_expired_returns_correct_records() {
    let (db, _tmp) = test_db();

    let mut h1 = make_holding_record(1, 1, 0.5, 1024, Timestamp(100), ShardState::Active);
    h1.drop_notice_sent_at = Some(Timestamp(1000));
    db.upsert_holding(&h1).unwrap();

    let mut h2 = make_holding_record(2, 1, 0.5, 1024, Timestamp(100), ShardState::Active);
    h2.drop_notice_sent_at = Some(Timestamp(9999));
    db.upsert_holding(&h2).unwrap();

    let expired = db.list_holding_drop_notice_expired(Timestamp(5000)).unwrap();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].shard_id, h1.shard_id);
}

#[test]
fn get_file_by_id_returns_correct_record() {
    let (db, _tmp) = test_db();
    let r1 = make_file_record("/first.txt", 1, false);
    let r2 = make_file_record("/second.txt", 2, false);
    db.upsert_file(&r1).unwrap();
    db.upsert_file(&r2).unwrap();

    let found = db.get_file_by_id(FileId(2)).unwrap().unwrap();
    assert_eq!(found.path, "/second.txt");

    let not_found = db.get_file_by_id(FileId(99)).unwrap();
    assert!(not_found.is_none());
}

#[test]
fn list_all_peers_returns_all() {
    let (db, _tmp) = test_db();
    for i in 0..5u8 {
        db.upsert_peer(&make_peer_record(i)).unwrap();
    }
    let all = db.list_all_peers().unwrap();
    assert_eq!(all.len(), 5);
}

#[test]
fn list_shards_for_holder_returns_correct_shards() {
    let (db, _tmp) = test_db();
    let holder_a = test_peer(1);
    let holder_b = test_peer(2);

    for i in 0..3u8 {
        let mut s = make_shard_record(i, 1, 1, ShardStatus::Stored, None);
        s.holder_id = holder_a;
        db.upsert_shard(&s).unwrap();
    }
    for i in 3..5u8 {
        let mut s = make_shard_record(i, 2, 2, ShardStatus::Stored, None);
        s.holder_id = holder_b;
        db.upsert_shard(&s).unwrap();
    }

    let for_a = db.list_shards_for_holder(&holder_a).unwrap();
    assert_eq!(for_a.len(), 3);
    let for_b = db.list_shards_for_holder(&holder_b).unwrap();
    assert_eq!(for_b.len(), 2);
}
