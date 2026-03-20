use crate::db::testutil::{test_db, test_peer, test_peers};
use crate::db::WeeklyPosEntry;
use crate::types::{
    BudgetRecord, DeviceId, EventEntry, Event, FileId, FileRecord,
    HoldingRecord, HoldingStatus, IdentityPub, LocalState, PlacementStatus, PeerRecord,
    SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement,
    Timestamp,
};

// ============================================================
// Helpers
// ============================================================

fn block_id(seed: u8) -> SourceBlockId {
    SourceBlockId([seed; 32])
}

fn make_file_record(path: &str, file_id: u64) -> FileRecord {
    FileRecord {
        file_id: FileId(file_id),
        path: path.to_string(),
        importance: 0.5,
        devices: vec![(DeviceId([0u8; 16]), LocalState::Present)],
        versions: vec![],
        first_seen: Timestamp(1000),
    }
}

fn make_source_block(seed: u8, status: SourceBlockStatus) -> SourceBlockRecord {
    SourceBlockRecord {
        block_id: block_id(seed),
        k: 10,
        t: 65535,
        block_type: SourceBlockType::Single,
        status,
        created_at: Timestamp(1000),
    }
}

fn make_placement(
    block_seed: u8,
    holder: IdentityPub,
    file_id: FileId,
    status: PlacementStatus,
    count: u32,
) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: block_id(block_seed),
        holder_id: holder,
        file_id,
        esi_ranges: vec![(0, count)],
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: Timestamp(1000),
    }
}

fn make_holding(
    block_seed: u8,
    owner: IdentityPub,
    status: HoldingStatus,
    total_bytes: u64,
) -> HoldingRecord {
    HoldingRecord {
        source_block_id: block_id(block_seed),
        owner_id: owner,
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes,
        status,
        received_at: Timestamp(1000),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    }
}

fn make_peer(identity: IdentityPub) -> PeerRecord {
    PeerRecord {
        identity,
        node_id: None,
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1000),
        last_seen: Timestamp(2000),
        weeks_in_network: 4,
        device_id: None,
    }
}

fn make_event(n: u8) -> EventEntry {
    EventEntry {
        timestamp: Timestamp(n as u64 * 100),
        device_id: DeviceId([n; 16]),
        event: Event::EpochRotated { epoch: n as u32 },
    }
}

// ============================================================
// 1. file_crud
// ============================================================

#[test]
fn file_crud() {
    let db = test_db();
    let record = make_file_record("photos/a.jpg", 1);

    db.upsert_file(&record).unwrap();
    let got = db.get_file("photos/a.jpg").unwrap().unwrap();
    assert_eq!(got.file_id, FileId(1));
    assert_eq!(got.path, "photos/a.jpg");

    db.delete_file("photos/a.jpg").unwrap();
    assert!(db.get_file("photos/a.jpg").unwrap().is_none());
}

// ============================================================
// 2. file_get_by_id
// ============================================================

#[test]
fn file_get_by_id() {
    let db = test_db();
    let record = make_file_record("docs/test.md", 42);
    db.upsert_file(&record).unwrap();

    let got = db.get_file_by_id(FileId(42)).unwrap().unwrap();
    assert_eq!(got.path, "docs/test.md");

    assert!(db.get_file_by_id(FileId(99)).unwrap().is_none());
}

// ============================================================
// 3. file_list_with_prefix
// ============================================================

#[test]
fn file_list_with_prefix() {
    let db = test_db();
    db.upsert_file(&make_file_record("photos/a.jpg", 1)).unwrap();
    db.upsert_file(&make_file_record("photos/b.jpg", 2)).unwrap();
    db.upsert_file(&make_file_record("docs/c.md", 3)).unwrap();

    let photos = db.list_files_with_prefix("photos/").unwrap();
    assert_eq!(photos.len(), 2);
    assert!(photos.iter().any(|r| r.path == "photos/a.jpg"));
    assert!(photos.iter().any(|r| r.path == "photos/b.jpg"));

    let docs = db.list_files_with_prefix("docs/").unwrap();
    assert_eq!(docs.len(), 1);
    assert_eq!(docs[0].path, "docs/c.md");

    let videos = db.list_files_with_prefix("videos/").unwrap();
    assert!(videos.is_empty());
}

// ============================================================
// 4. placement_crud
// ============================================================

#[test]
fn placement_crud() {
    let db = test_db();
    let holder = test_peer();
    let p = make_placement(1, holder, FileId(10), PlacementStatus::Alive, 50);

    db.upsert_placement(&p).unwrap();
    let got = db.get_placement(&block_id(1), &holder).unwrap().unwrap();
    assert_eq!(got.symbol_count(), 50);
    assert_eq!(got.holder_id, holder);

    db.delete_placement(&block_id(1), &holder).unwrap();
    assert!(db.get_placement(&block_id(1), &holder).unwrap().is_none());
}

// ============================================================
// 5. placement_updates_hot_cache
// ============================================================

#[test]
fn placement_updates_hot_cache() {
    let db = test_db();
    let holder = test_peer();
    let p = make_placement(1, holder, FileId(7), PlacementStatus::Alive, 100);

    db.upsert_placement(&p).unwrap();

    let hot = db.hot();
    let agg = hot.blocks.get(&block_id(1)).unwrap();
    assert_eq!(agg.total_alive_symbols, 100);

    let pagg = hot.placements.get(&(block_id(1), holder)).unwrap();
    assert_eq!(pagg.symbol_count, 100);
}

// ============================================================
// 6. placement_delete_cleans_hot_cache
// ============================================================

#[test]
fn placement_delete_cleans_hot_cache() {
    let db = test_db();
    let holder = test_peer();
    let p = make_placement(2, holder, FileId(8), PlacementStatus::Alive, 75);

    db.upsert_placement(&p).unwrap();
    db.delete_placement(&block_id(2), &holder).unwrap();

    let hot = db.hot();
    assert!(hot.placements.get(&(block_id(2), holder)).is_none());
    // Block entry removed since total_alive_symbols dropped to 0.
    assert!(hot.blocks.get(&block_id(2)).is_none());
}

// ============================================================
// 7. double_index_consistency
// ============================================================

#[test]
fn double_index_consistency() {
    let db = test_db();
    let holder = IdentityPub([9u8; 32]);
    let fid = FileId(7);
    let p = make_placement(3, holder, fid, PlacementStatus::Alive, 50);

    db.upsert_placement(&p).unwrap();

    let holders = db.list_holders_for_file(fid).unwrap();
    assert!(holders.contains(&holder));

    let files = db.list_files_for_holder(&holder).unwrap();
    assert!(files.contains(&fid));

    db.delete_placement(&block_id(3), &holder).unwrap();

    let holders_after = db.list_holders_for_file(fid).unwrap();
    assert!(holders_after.is_empty());

    let files_after = db.list_files_for_holder(&holder).unwrap();
    assert!(files_after.is_empty());
}

// ============================================================
// 8. holder_files_scan_on_holder_departure
// ============================================================

#[test]
fn holder_files_scan_on_holder_departure() {
    let db = test_db();
    let holder = IdentityPub([5u8; 32]);

    // Place holder on 3 different files
    for i in 0..3u8 {
        let p = make_placement(i + 10, holder, FileId(i as u64 + 100), PlacementStatus::Alive, 10);
        db.upsert_placement(&p).unwrap();
    }

    let files = db.list_files_for_holder(&holder).unwrap();
    assert_eq!(files.len(), 3);
    assert!(files.contains(&FileId(100)));
    assert!(files.contains(&FileId(101)));
    assert!(files.contains(&FileId(102)));
}

// ============================================================
// 9. event_log_append_and_query
// ============================================================

#[test]
fn event_log_append_and_query() {
    let db = test_db();

    let s1 = db.append_event(&make_event(1)).unwrap();
    let s2 = db.append_event(&make_event(2)).unwrap();
    let s3 = db.append_event(&make_event(3)).unwrap();
    assert_eq!((s1, s2, s3), (1, 2, 3));

    assert_eq!(db.last_event_seq().unwrap(), 3);

    let all = db.events_after(0, 100).unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].0, 1);
    assert_eq!(all[1].0, 2);
    assert_eq!(all[2].0, 3);

    let after2 = db.events_after(2, 100).unwrap();
    assert_eq!(after2.len(), 1);
    assert_eq!(after2[0].0, 3);

    let after3 = db.events_after(3, 100).unwrap();
    assert!(after3.is_empty());
}

// ============================================================
// 10. event_log_sequence_monotonic
// ============================================================

#[test]
fn event_log_sequence_monotonic() {
    let db = test_db();
    let seqs: Vec<u64> = (0..5).map(|i| db.append_event(&make_event(i)).unwrap()).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
}

// ============================================================
// 11. holding_crud
// ============================================================

#[test]
fn holding_crud() {
    let db = test_db();
    let owner = test_peer();
    let h = make_holding(1, owner, HoldingStatus::Active, 4096);

    db.upsert_holding(&h).unwrap();
    let got = db.get_holding(&block_id(1), &owner).unwrap().unwrap();
    assert_eq!(got.total_bytes, 4096);

    assert_eq!(db.total_holding_bytes().unwrap(), 4096);

    db.delete_holding(&block_id(1), &owner).unwrap();
    assert!(db.get_holding(&block_id(1), &owner).unwrap().is_none());
    assert_eq!(db.total_holding_bytes().unwrap(), 0);
}

// ============================================================
// 12. holding_cooldown_expired
// ============================================================

#[test]
fn holding_cooldown_expired() {
    use crate::constants::HOLDER_DELETE_COOLDOWN_SECS;

    let db = test_db();
    let owner1 = IdentityPub([1u8; 32]);
    let owner2 = IdentityPub([2u8; 32]);
    let owner3 = IdentityPub([3u8; 32]);

    // h1 and h2: delete_requested_at = T(0), should be expired at T(COOLDOWN)
    let mut h1 = make_holding(1, owner1, HoldingStatus::MarkedForDelete, 100);
    h1.delete_requested_at = Some(Timestamp(0));
    let mut h2 = make_holding(2, owner2, HoldingStatus::MarkedForDelete, 200);
    h2.delete_requested_at = Some(Timestamp(0));

    // h3: delete_requested_at = T(1), NOT included at T(COOLDOWN) because 0+COOLDOWN <= T(COOLDOWN) but 1+COOLDOWN > T(COOLDOWN)
    let mut h3 = make_holding(3, owner3, HoldingStatus::MarkedForDelete, 300);
    h3.delete_requested_at = Some(Timestamp(1));

    db.upsert_holding(&h1).unwrap();
    db.upsert_holding(&h2).unwrap();
    db.upsert_holding(&h3).unwrap();

    let now = Timestamp(HOLDER_DELETE_COOLDOWN_SECS);
    let expired = db.list_holdings_cooldown_expired(now).unwrap();
    assert_eq!(expired.len(), 2);
    let ids: Vec<_> = expired.iter().map(|r| r.owner_id).collect();
    assert!(ids.contains(&owner1));
    assert!(ids.contains(&owner2));
    // h3 not included
    assert!(!ids.contains(&owner3));
}

// ============================================================
// 13. peer_crud
// ============================================================

#[test]
fn peer_crud() {
    let db = test_db();
    let identity = test_peer();
    let p = make_peer(identity);

    db.upsert_peer(&p).unwrap();
    let got = db.get_peer(&identity).unwrap().unwrap();
    assert_eq!(got.identity, identity);
    assert_eq!(got.trust_p, 0.5);

    assert_eq!(db.list_all_peers().unwrap().len(), 1);

    db.delete_peer(&identity).unwrap();
    assert!(db.get_peer(&identity).unwrap().is_none());
}

// ============================================================
// 14. pos_weekly_accumulate
// ============================================================

#[test]
fn pos_weekly_accumulate() {
    let db = test_db();
    let peer = test_peer();

    db.upsert_pos_weekly(&peer, 5, &WeeklyPosEntry { challenged: 3, passed: 2 })
        .unwrap();
    // Overwrite with new values (last write wins)
    db.upsert_pos_weekly(&peer, 5, &WeeklyPosEntry { challenged: 2, passed: 2 })
        .unwrap();

    let got = db.get_pos_weekly(&peer, 5).unwrap().unwrap();
    assert_eq!(got.challenged, 2);
    assert_eq!(got.passed, 2);
}

// ============================================================
// 15. hot_cache_rebuilt_after_reopen
// ============================================================

#[test]
fn hot_cache_rebuilt_after_reopen() {
    // We need a file-backed DB for this test (not in-memory, which doesn't persist).
    let tmpfile = tempfile::NamedTempFile::new().unwrap();

    // Drop the tempfile handle but keep the path (tempfile persists until handle dropped).
    // Actually we need the file to persist. Use into_temp_path() to persist.
    let tmp_path = tmpfile.into_temp_path();

    let holder = test_peer();
    let fid = FileId(42);

    // Write placements in first DB handle
    {
        let db = crate::db::Db::open(&tmp_path).unwrap();
        let p = make_placement(1, holder, fid, PlacementStatus::Alive, 200);
        db.upsert_placement(&p).unwrap();
        // Drop db — closes handle
    }

    // Reopen and verify hot cache rebuilt correctly
    let db2 = crate::db::Db::open(&tmp_path).unwrap();
    let hot = db2.hot();
    let agg = hot.blocks.get(&block_id(1)).expect("block agg must exist after rebuild");
    assert_eq!(agg.total_alive_symbols, 200);

    let pagg = hot
        .placements
        .get(&(block_id(1), holder))
        .expect("placement agg must exist after rebuild");
    assert_eq!(pagg.symbol_count, 200);
    assert_eq!(pagg.status, PlacementStatus::Alive);
}

// ============================================================
// Extra: list_placements_for_block
// ============================================================

#[test]
fn list_placements_for_block_returns_all_holders() {
    let db = test_db();
    let peers = test_peers(3);
    let fid = FileId(1);

    for (i, &peer) in peers.iter().enumerate() {
        let p = make_placement(5, peer, fid, PlacementStatus::Alive, (i as u32 + 1) * 10);
        db.upsert_placement(&p).unwrap();
    }

    let placements = db.list_placements_for_block(&block_id(5)).unwrap();
    assert_eq!(placements.len(), 3);
}

// ============================================================
// Extra: source_block_crud
// ============================================================

#[test]
fn source_block_crud() {
    let db = test_db();
    let record = make_source_block(1, SourceBlockStatus::Active);

    db.upsert_source_block(&record).unwrap();
    let got = db.get_source_block(&block_id(1)).unwrap().unwrap();
    assert_eq!(got.k, 10);
    assert_eq!(got.status, SourceBlockStatus::Active);

    db.delete_source_block(&block_id(1)).unwrap();
    assert!(db.get_source_block(&block_id(1)).unwrap().is_none());
}

#[test]
fn list_source_blocks_by_status() {
    let db = test_db();
    db.upsert_source_block(&make_source_block(1, SourceBlockStatus::Active)).unwrap();
    db.upsert_source_block(&make_source_block(2, SourceBlockStatus::Stale)).unwrap();
    db.upsert_source_block(&make_source_block(3, SourceBlockStatus::Active)).unwrap();

    let active = db.list_source_blocks_by_status(SourceBlockStatus::Active).unwrap();
    assert_eq!(active.len(), 2);

    let stale = db.list_source_blocks_by_status(SourceBlockStatus::Stale).unwrap();
    assert_eq!(stale.len(), 1);
}

// ============================================================
// Extra: budget singleton
// ============================================================

#[test]
fn budget_singleton() {
    let db = test_db();
    assert!(db.get_budget().unwrap().is_none());

    let record = BudgetRecord {
        estimated_gb: 10.5,
        last_calculated: Timestamp(5000),
        placement_success_rate: 0.9,
        weekly_stats: vec![(1, 10), (2, 8)],
    };
    db.set_budget(&record).unwrap();

    let got = db.get_budget().unwrap().unwrap();
    assert!((got.estimated_gb - 10.5).abs() < f64::EPSILON);
    assert_eq!(got.weekly_stats.len(), 2);
}

// ============================================================
// Extra: non-alive placements don't count in hot.blocks
// ============================================================

#[test]
fn non_alive_placement_not_counted_in_block_agg() {
    let db = test_db();
    let holder = test_peer();
    let fid = FileId(99);

    // Offered status — not Alive
    let p = make_placement(7, holder, fid, PlacementStatus::Offered, 50);
    db.upsert_placement(&p).unwrap();

    let hot = db.hot();
    // Block entry may exist but alive count must be 0
    let alive = hot
        .blocks
        .get(&block_id(7))
        .map(|a| a.total_alive_symbols)
        .unwrap_or(0);
    assert_eq!(alive, 0);
}

// ============================================================
// Extra: upsert placement updates alive count correctly on status change
// ============================================================

#[test]
fn upsert_placement_updates_alive_count_on_status_change() {
    let db = test_db();
    let holder = test_peer();
    let fid = FileId(55);
    let bid = block_id(8);

    // Insert as Offered (not alive)
    let p1 = make_placement(8, holder, fid, PlacementStatus::Offered, 100);
    db.upsert_placement(&p1).unwrap();
    assert_eq!(db.hot().blocks.get(&bid).map(|a| a.total_alive_symbols).unwrap_or(0), 0);

    // Upsert as Alive
    let p2 = make_placement(8, holder, fid, PlacementStatus::Alive, 100);
    db.upsert_placement(&p2).unwrap();
    assert_eq!(db.hot().blocks.get(&bid).unwrap().total_alive_symbols, 100);

    // Upsert as Lost (no longer alive)
    let p3 = make_placement(8, holder, fid, PlacementStatus::Lost, 100);
    db.upsert_placement(&p3).unwrap();
    assert_eq!(db.hot().blocks.get(&bid).map(|a| a.total_alive_symbols).unwrap_or(0), 0);
}
