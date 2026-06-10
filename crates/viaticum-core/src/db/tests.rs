use crate::db::testutil::{test_db, test_peer, test_peers};
use crate::db::{Db, WeeklyPosEntry};
use crate::trust::{DeviceTrustRecord, MasterTrustRecord};
use crate::types::{
    BudgetRecord, DeviceId, Event, EventEntry, FileId, FileRecord, FileVersion, HoldingRecord,
    HoldingStatus, IdentityPub, LocalState, PeerRecord, PlacementStatus, SourceBlockId,
    SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement, Timestamp,
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
        devices: vec![(DeviceId([0u8; 32]), LocalState::Present)],
        versions: vec![],
        first_seen: Timestamp(1000),
    }
}

fn file_with_versions(path: &str, file_id: u64, versions: &[([u8; 32], bool)]) -> FileRecord {
    let mut rec = make_file_record(path, file_id);
    rec.versions = versions
        .iter()
        .map(|(hash, backed_up)| FileVersion {
            content_hash: *hash,
            source_block_id: SourceBlockId([0u8; 32]),
            k: 1,
            t: 65535,
            created_at: Timestamp(1000),
            backed_up_at: backed_up.then_some(Timestamp(2000)),
        })
        .collect();
    rec
}

fn make_source_block(seed: u8, status: SourceBlockStatus) -> SourceBlockRecord {
    SourceBlockRecord {
        block_id: block_id(seed),
        k: 10,
        t: 65535,
        block_type: SourceBlockType::Single,
        status,
        created_at: Timestamp(1000),
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    }
}

fn make_placement(
    block_seed: u8,
    holder: DeviceId,
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
        consecutive_misses: 0,
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

fn make_peer(device_id: DeviceId) -> PeerRecord {
    PeerRecord {
        device_id,
        master_identity: IdentityPub([0xAAu8; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1000),
        last_seen: Timestamp(2000),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: crate::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    }
}

fn make_event(n: u8) -> EventEntry {
    EventEntry {
        timestamp: Timestamp(n as u64 * 100),
        device_id: DeviceId([n; 32]),
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
    db.upsert_file(&make_file_record("photos/a.jpg", 1))
        .unwrap();
    db.upsert_file(&make_file_record("photos/b.jpg", 2))
        .unwrap();
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

    let deleted = db.delete_placement(&block_id(1), &holder).unwrap();
    assert!(deleted.is_some());
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
    let _ = db.delete_placement(&block_id(2), &holder).unwrap();

    let hot = db.hot();
    assert!(!hot.placements.contains_key(&(block_id(2), holder)));
    // Block entry removed since total_alive_symbols dropped to 0.
    assert!(!hot.blocks.contains_key(&block_id(2)));
}

// ============================================================
// 7. double_index_consistency
// ============================================================

#[test]
fn double_index_consistency() {
    let db = test_db();
    let holder = DeviceId([9u8; 32]);
    let fid = FileId(7);
    let p = make_placement(3, holder, fid, PlacementStatus::Alive, 50);

    db.upsert_placement(&p).unwrap();

    let holders = db.list_holders_for_file(fid).unwrap();
    assert!(holders.contains(&holder));

    let files = db.list_files_for_holder(&holder).unwrap();
    assert!(files.contains(&fid));

    let _ = db.delete_placement(&block_id(3), &holder).unwrap();

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
    let holder = DeviceId([5u8; 32]);

    // Place holder on 3 different files
    for i in 0..3u8 {
        let p = make_placement(
            i + 10,
            holder,
            FileId(i as u64 + 100),
            PlacementStatus::Alive,
            10,
        );
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
    let seqs: Vec<u64> = (0..5)
        .map(|i| db.append_event(&make_event(i)).unwrap())
        .collect();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
}

// ============================================================
// content_hash index (B-1)
// ============================================================

#[test]
fn content_index_finds_backed_up_file_by_hash() {
    let db = test_db();
    let h1 = [11u8; 32];
    let h2 = [22u8; 32];
    db.upsert_file(&file_with_versions("a.txt", 1, &[(h1, true)]))
        .unwrap();
    db.upsert_file(&file_with_versions("b.txt", 2, &[(h2, false)]))
        .unwrap();

    assert!(db.is_content_backed_up(&h1).unwrap());
    assert!(
        !db.is_content_backed_up(&h2).unwrap(),
        "h2 version is not backed up"
    );
    assert!(
        !db.is_content_backed_up(&[33u8; 32]).unwrap(),
        "unknown hash"
    );

    assert_eq!(
        db.find_file_by_content_hash(&h1).unwrap().map(|r| r.path),
        Some("a.txt".to_string())
    );
    assert_eq!(
        db.find_file_by_content_hash(&h2).unwrap().map(|r| r.path),
        Some("b.txt".to_string())
    );
    assert!(db.find_file_by_content_hash(&[33u8; 32]).unwrap().is_none());
}

#[test]
fn content_index_removed_on_delete() {
    let db = test_db();
    let h = [44u8; 32];
    db.upsert_file(&file_with_versions("c.txt", 3, &[(h, true)]))
        .unwrap();
    assert!(db.is_content_backed_up(&h).unwrap());

    db.delete_file("c.txt").unwrap();
    assert!(
        !db.is_content_backed_up(&h).unwrap(),
        "index entry must be removed when the file is deleted"
    );
    assert!(db.find_file_by_content_hash(&h).unwrap().is_none());
}

#[test]
fn content_index_drops_stale_hash_on_version_change() {
    let db = test_db();
    let h_old = [55u8; 32];
    let h_new = [66u8; 32];
    // First versioned with h_old.
    db.upsert_file(&file_with_versions("d.txt", 4, &[(h_old, true)]))
        .unwrap();
    // Replace with a record whose only version is h_new (h_old no longer present).
    db.upsert_file(&file_with_versions("d.txt", 4, &[(h_new, true)]))
        .unwrap();

    assert!(
        !db.is_content_backed_up(&h_old).unwrap(),
        "stale hash key must be removed when the version set changes"
    );
    assert!(db.is_content_backed_up(&h_new).unwrap());
}

#[test]
fn content_index_backfilled_at_open_for_legacy_db() {
    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let tmp_path = tmpfile.into_temp_path();
    let h = [77u8; 32];

    {
        let db = Db::open(&tmp_path).unwrap();
        db.upsert_file(&file_with_versions("e.txt", 5, &[(h, true)]))
            .unwrap();
        // Simulate a database created before B-1: FILES populated, index empty.
        use redb::ReadableTable;
        let tx = db.inner.begin_write().unwrap();
        {
            let mut idx = tx.open_table(super::CONTENT_INDEX).unwrap();
            let keys: Vec<Vec<u8>> = idx
                .iter()
                .unwrap()
                .map(|i| i.unwrap().0.value().to_vec())
                .collect();
            for k in keys {
                idx.remove(k.as_slice()).unwrap();
            }
        }
        tx.commit().unwrap();
    }

    // Reopen → open() must backfill the index from FILES.
    let db2 = Db::open(&tmp_path).unwrap();
    assert!(
        db2.is_content_backed_up(&h).unwrap(),
        "content index must be backfilled at open for a pre-B1 database"
    );
}

// ============================================================
// 11. holding_crud
// ============================================================

#[test]
fn holding_crud() {
    let db = test_db();
    let owner = IdentityPub([1u8; 32]);
    let h = make_holding(1, owner, HoldingStatus::Active, 4096);

    db.upsert_holding(&h).unwrap();
    let got = db.get_holding(&block_id(1), &owner).unwrap().unwrap();
    assert_eq!(got.total_bytes, 4096);

    assert_eq!(db.total_holding_bytes().unwrap(), 4096);

    db.delete_holding(&block_id(1), &owner).unwrap();
    assert!(db.get_holding(&block_id(1), &owner).unwrap().is_none());
    assert_eq!(db.total_holding_bytes().unwrap(), 0);
}

#[test]
fn total_holding_bytes_tracks_upsert_replace_and_delete() {
    // S-9: total_holding_bytes is served from a cached running aggregate, so the
    // aggregate must stay exact across upserts (incl. in-place replacement that
    // changes total_bytes) and deletes — over multiple owners.
    let db = test_db();
    let owner1 = IdentityPub([1u8; 32]);
    let owner2 = IdentityPub([2u8; 32]);

    db.upsert_holding(&make_holding(1, owner1, HoldingStatus::Active, 1000))
        .unwrap();
    db.upsert_holding(&make_holding(2, owner2, HoldingStatus::Active, 2000))
        .unwrap();
    assert_eq!(db.total_holding_bytes().unwrap(), 3000);

    // Replace holding 1 with a larger size → delta must adjust, not double-count.
    db.upsert_holding(&make_holding(1, owner1, HoldingStatus::Active, 1500))
        .unwrap();
    assert_eq!(db.total_holding_bytes().unwrap(), 3500);

    // Status change keeps total_bytes → all statuses count, so total is unchanged.
    db.upsert_holding(&make_holding(
        1,
        owner1,
        HoldingStatus::MarkedForDelete,
        1500,
    ))
    .unwrap();
    assert_eq!(db.total_holding_bytes().unwrap(), 3500);

    db.delete_holding(&block_id(1), &owner1).unwrap();
    assert_eq!(db.total_holding_bytes().unwrap(), 2000);

    db.delete_holding(&block_id(2), &owner2).unwrap();
    assert_eq!(db.total_holding_bytes().unwrap(), 0);
}

#[test]
fn total_holding_bytes_rebuilt_after_reopen() {
    // S-9: the cached aggregate must be rebuilt from the WARM layer at Db::open().
    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let tmp_path = tmpfile.into_temp_path();
    let owner1 = IdentityPub([1u8; 32]);
    let owner2 = IdentityPub([2u8; 32]);

    {
        let db = crate::db::Db::open(&tmp_path).unwrap();
        db.upsert_holding(&make_holding(1, owner1, HoldingStatus::Active, 1000))
            .unwrap();
        db.upsert_holding(&make_holding(2, owner2, HoldingStatus::Silent, 2500))
            .unwrap();
    }

    let db2 = crate::db::Db::open(&tmp_path).unwrap();
    assert_eq!(
        db2.total_holding_bytes().unwrap(),
        3500,
        "cached aggregate must be rebuilt from holdings at open()"
    );
}

#[test]
fn holdings_migrated_from_block_first_to_owner_first_key() {
    // S-4: a database written with the old block‖owner key layout must be
    // re-keyed to owner‖block at open(), so lookups and the owner range-scan work.
    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let tmp_path = tmpfile.into_temp_path();
    let owner = IdentityPub([7u8; 32]);
    let h = make_holding(1, owner, HoldingStatus::Active, 4096);

    {
        let db = Db::open(&tmp_path).unwrap();
        // Write with the OLD key order (block_id ++ owner) and clear the migration
        // flag, simulating a pre-S4 database.
        let mut old_key = [0u8; 64];
        old_key[..32].copy_from_slice(&block_id(1).0);
        old_key[32..].copy_from_slice(&owner.0);
        let tx = db.inner.begin_write().unwrap();
        {
            let mut t = tx.open_table(super::HOLDINGS).unwrap();
            t.insert(&old_key, crate::types::to_cbor_bytes(&h).as_slice())
                .unwrap();
            let mut meta = tx.open_table(super::META).unwrap();
            meta.remove(super::META_KEY_HOLDINGS_OWNER_KEYED).unwrap();
        }
        tx.commit().unwrap();
    }

    // Reopen → migration re-keys to owner‖block.
    let db2 = Db::open(&tmp_path).unwrap();
    let got = db2.get_holding(&block_id(1), &owner).unwrap();
    assert!(got.is_some(), "holding must be found after key migration");
    assert_eq!(got.unwrap().total_bytes, 4096);
    assert_eq!(
        db2.list_holdings_for_owner(&owner).unwrap().len(),
        1,
        "owner range-scan must find the migrated holding"
    );
    assert_eq!(db2.total_holding_bytes().unwrap(), 4096);
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
    let expired = db.list_holdings_cooldown_expired(now, 1).unwrap();
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
    let device_id = test_peer();
    let p = make_peer(device_id);

    db.upsert_peer(&p).unwrap();
    let got = db.get_peer(&device_id).unwrap().unwrap();
    assert_eq!(got.device_id, device_id);
    assert_eq!(got.trust_p, 0.5);

    assert_eq!(db.list_all_peers().unwrap().len(), 1);

    db.delete_peer(&device_id).unwrap();
    assert!(db.get_peer(&device_id).unwrap().is_none());
}

// ============================================================
// 14. pos_weekly_accumulate
// ============================================================

#[test]
fn pos_weekly_accumulate() {
    let db = test_db();
    let peer = test_peer();

    db.upsert_pos_weekly(
        &peer,
        5,
        &WeeklyPosEntry {
            challenged: 3,
            passed: 2,
        },
    )
    .unwrap();
    // Overwrite with new values (last write wins)
    db.upsert_pos_weekly(
        &peer,
        5,
        &WeeklyPosEntry {
            challenged: 2,
            passed: 2,
        },
    )
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
    let agg = hot
        .blocks
        .get(&block_id(1))
        .expect("block agg must exist after rebuild");
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
    db.upsert_source_block(&make_source_block(1, SourceBlockStatus::Active))
        .unwrap();
    db.upsert_source_block(&make_source_block(2, SourceBlockStatus::Stale))
        .unwrap();
    db.upsert_source_block(&make_source_block(3, SourceBlockStatus::Active))
        .unwrap();

    let active = db
        .list_source_blocks_by_status(SourceBlockStatus::Active)
        .unwrap();
    assert_eq!(active.len(), 2);

    let stale = db
        .list_source_blocks_by_status(SourceBlockStatus::Stale)
        .unwrap();
    assert_eq!(stale.len(), 1);
}

// ============================================================
// committed_bytes
// ============================================================

#[test]
fn committed_bytes_sums_active_blocks() {
    let db = test_db();

    // Block A: Active, encrypted_size=Some(1000)
    let block_a = SourceBlockRecord {
        block_id: block_id(10),
        k: 5,
        t: 100,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(1000),
        encrypted_size: Some(1000),
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    };

    // Block B: Active, encrypted_size=None → fallback to k*t = 10*100 = 1000
    let block_b = SourceBlockRecord {
        block_id: block_id(11),
        k: 10,
        t: 100,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(1000),
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    };

    // Block C: Deleted, encrypted_size=Some(500) → must NOT be counted
    let block_c = SourceBlockRecord {
        block_id: block_id(12),
        k: 5,
        t: 100,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Deleted,
        created_at: Timestamp(1000),
        encrypted_size: Some(500),
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    };

    db.upsert_source_block(&block_a).unwrap();
    db.upsert_source_block(&block_b).unwrap();
    db.upsert_source_block(&block_c).unwrap();

    let total = db.committed_bytes().unwrap();
    // A: 1000 (encrypted_size)
    // B: 10 * 100 = 1000 (fallback k*t)
    // C: excluded (Deleted)
    assert_eq!(total, 2000, "expected 1000 + 1000 = 2000, got {total}");
}

// ============================================================
// update_block_cached_fields (Wave 8)
// ============================================================

#[test]
fn update_block_cached_fields_persists_to_db() {
    let db = test_db();
    let bid = block_id(20);

    // Insert a block with default (zero) cached fields.
    let initial = SourceBlockRecord {
        block_id: bid,
        k: 5,
        t: 65535,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(500),
        encrypted_size: Some(327_675),
        n: Some(14),
        overhead: Some(2.475),
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    };
    db.upsert_source_block(&initial).unwrap();

    // Call update with non-zero values.
    db.update_block_cached_fields(&bid, 0.65, 3, 0.9996, 0.9996)
        .unwrap();

    // Read back and assert.
    let record = db.get_source_block(&bid).unwrap().unwrap();
    assert!(
        (record.importance - 0.65).abs() < 1e-10,
        "importance must be ~0.65, got {}",
        record.importance
    );
    assert_eq!(record.current_alive, 3);
    assert!(
        (record.current_reliability - 0.9996).abs() < 1e-10,
        "current_reliability must be ~0.9996, got {}",
        record.current_reliability
    );
    assert!(
        (record.target_reliability - 0.9996).abs() < 1e-10,
        "target_reliability must be ~0.9996, got {}",
        record.target_reliability
    );
    // Existing fields must be unchanged.
    assert_eq!(record.k, 5);
    assert_eq!(record.t, 65535);
    assert_eq!(record.encrypted_size, Some(327_675));
    assert_eq!(record.overhead, Some(2.475));
    assert_eq!(record.status, SourceBlockStatus::Active);
}

#[test]
fn update_block_cached_fields_returns_not_found_for_missing_block() {
    let db = test_db();
    let missing = block_id(99);

    let result = db.update_block_cached_fields(&missing, 0.5, 0, 0.0, 0.0);
    assert!(
        result.is_err(),
        "must return Err for a block_id not in the DB"
    );
    // Check it's a NotFound variant.
    let err = result.unwrap_err();
    assert!(
        matches!(err, crate::db::DbError::NotFound(_)),
        "expected DbError::NotFound, got: {err:?}"
    );
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

// ─── BUDGET-08: set_budget updates — does not duplicate ──────────────────────

#[test]
fn budget_upsert_updates_not_duplicates() {
    // Call set_budget twice with different values. The second call must overwrite
    // the first — there must be exactly one record and it must have the new values.
    let db = test_db();

    let first = BudgetRecord {
        estimated_gb: 5.0,
        last_calculated: Timestamp(1000),
        placement_success_rate: 0.7,
        weekly_stats: vec![(10, 7)],
    };
    db.set_budget(&first).unwrap();

    let second = BudgetRecord {
        estimated_gb: 99.5,
        last_calculated: Timestamp(2000),
        placement_success_rate: 0.9,
        weekly_stats: vec![(20, 18), (30, 27)],
    };
    db.set_budget(&second).unwrap();

    // Only one record must exist and it must have the second call's values.
    let got = db.get_budget().unwrap().unwrap();
    assert!(
        (got.estimated_gb - 99.5).abs() < f64::EPSILON,
        "estimated_gb must be updated to 99.5, got {}",
        got.estimated_gb
    );
    assert_eq!(got.last_calculated, Timestamp(2000));
    assert_eq!(
        got.weekly_stats.len(),
        2,
        "weekly_stats must have 2 entries (from second record), got {}",
        got.weekly_stats.len()
    );
    assert_eq!(got.weekly_stats[0], (20, 18));
    assert_eq!(got.weekly_stats[1], (30, 27));
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
    assert_eq!(
        db.hot()
            .blocks
            .get(&bid)
            .map(|a| a.total_alive_symbols)
            .unwrap_or(0),
        0
    );

    // Upsert as Alive
    let p2 = make_placement(8, holder, fid, PlacementStatus::Alive, 100);
    db.upsert_placement(&p2).unwrap();
    assert_eq!(db.hot().blocks.get(&bid).unwrap().total_alive_symbols, 100);

    // Upsert as Lost (no longer alive)
    let p3 = make_placement(8, holder, fid, PlacementStatus::Lost, 100);
    db.upsert_placement(&p3).unwrap();
    assert_eq!(
        db.hot()
            .blocks
            .get(&bid)
            .map(|a| a.total_alive_symbols)
            .unwrap_or(0),
        0
    );
}

// ============================================================
// Extra: Uncertain counts as alive in hot cache (matches cli_server)
// ============================================================

#[test]
fn uncertain_placement_counts_as_alive_in_block_agg() {
    let db = test_db();
    let holder = test_peer();
    let fid = FileId(77);
    let bid = block_id(9);

    // Uncertain = 1 missed PoS; symbols are likely still held.
    let p = make_placement(9, holder, fid, PlacementStatus::Uncertain, 80);
    db.upsert_placement(&p).unwrap();

    let hot = db.hot();
    let alive = hot
        .blocks
        .get(&bid)
        .map(|a| a.total_alive_symbols)
        .unwrap_or(0);
    assert_eq!(
        alive, 80,
        "Uncertain must contribute to total_alive_symbols"
    );
}

#[test]
fn uncertain_to_lost_removes_alive_count() {
    let db = test_db();
    let holder = test_peer();
    let fid = FileId(78);
    let bid = block_id(15);

    // Start as Uncertain — counts as alive.
    let p1 = make_placement(15, holder, fid, PlacementStatus::Uncertain, 60);
    db.upsert_placement(&p1).unwrap();
    assert_eq!(db.hot().blocks.get(&bid).unwrap().total_alive_symbols, 60);

    // Transition to Lost — should drop to 0.
    let p2 = make_placement(15, holder, fid, PlacementStatus::Lost, 60);
    db.upsert_placement(&p2).unwrap();
    assert_eq!(
        db.hot()
            .blocks
            .get(&bid)
            .map(|a| a.total_alive_symbols)
            .unwrap_or(0),
        0
    );
}

#[test]
fn uncertain_in_rebuilt_hot_cache() {
    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let tmp_path = tmpfile.into_temp_path();
    let holder = test_peer();
    let fid = FileId(79);

    {
        let db = crate::db::Db::open(&tmp_path).unwrap();
        let p = make_placement(16, holder, fid, PlacementStatus::Uncertain, 120);
        db.upsert_placement(&p).unwrap();
    }

    // Rebuild from disk — Uncertain must still count as alive.
    let db2 = crate::db::Db::open(&tmp_path).unwrap();
    let agg = db2.hot().blocks.get(&block_id(16)).cloned();
    assert_eq!(agg.map(|a| a.total_alive_symbols).unwrap_or(0), 120);
}

// ============================================================
// Extra: list_placements_for_holder
// ============================================================

#[test]
fn list_placements_for_holder_returns_all_blocks_for_holder() {
    let db = test_db();
    let holder = DeviceId([0xAAu8; 32]);
    let fid = FileId(20);

    // Place holder on 3 different blocks
    for seed in [10u8, 11, 12] {
        let p = make_placement(seed, holder, fid, PlacementStatus::Alive, 50);
        db.upsert_placement(&p).unwrap();
    }

    let placements = db.list_placements_for_holder(&holder).unwrap();
    assert_eq!(placements.len(), 3);
    for p in &placements {
        assert_eq!(p.holder_id, holder);
    }
}

#[test]
fn list_placements_for_holder_returns_empty_when_no_placements() {
    let db = test_db();
    let holder = DeviceId([0xBBu8; 32]);
    let placements = db.list_placements_for_holder(&holder).unwrap();
    assert!(placements.is_empty());
}

#[test]
fn list_placements_for_holder_does_not_return_other_holders() {
    let db = test_db();
    let holder_a = DeviceId([0x01u8; 32]);
    let holder_b = DeviceId([0x02u8; 32]);
    let fid = FileId(30);

    db.upsert_placement(&make_placement(
        20,
        holder_a,
        fid,
        PlacementStatus::Alive,
        10,
    ))
    .unwrap();
    db.upsert_placement(&make_placement(
        21,
        holder_b,
        fid,
        PlacementStatus::Alive,
        10,
    ))
    .unwrap();

    let a_placements = db.list_placements_for_holder(&holder_a).unwrap();
    assert_eq!(a_placements.len(), 1);
    assert_eq!(a_placements[0].holder_id, holder_a);

    let b_placements = db.list_placements_for_holder(&holder_b).unwrap();
    assert_eq!(b_placements.len(), 1);
    assert_eq!(b_placements[0].holder_id, holder_b);
}

// ============================================================
// Db::open hardening
// ============================================================

#[test]
fn db_open_creates_backup_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.redb");
    let db = crate::db::Db::open(&path).unwrap();
    drop(db);
    let _db2 = crate::db::Db::open(&path).unwrap();
    let bak = path.with_extension("redb.bak");
    assert!(bak.exists(), ".redb.bak should exist after reopening");
}

#[test]
fn db_open_fresh_path_no_backup() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("fresh.redb");
    let _db = crate::db::Db::open(&path).unwrap();
    let bak = path.with_extension("redb.bak");
    assert!(!bak.exists(), ".redb.bak should NOT exist on first open");
}

#[test]
fn db_integrity_check_passes() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("integrity.redb");
    let db = crate::db::Db::open(&path).unwrap();
    assert!(db.list_all_files().unwrap().is_empty());
}

// ─── DB-13: crash recovery (pre-open backup) ───────────────────────────────

#[test]
fn db_crash_recovery_backup_preserves_data() {
    // Scenario: DB has data, then gets corrupted.
    // Verify that .redb.bak was created before corruption and contains the data.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("crash.redb");

    // 1. Create DB with data
    {
        let db = crate::db::Db::open(&path).unwrap();
        let file = FileRecord {
            file_id: FileId(999),
            path: "/crash/test.bin".to_string(),
            importance: 0.5,
            devices: vec![],
            versions: vec![],
            first_seen: Timestamp(100),
        };
        db.upsert_file(&file).unwrap();
        drop(db);
    }

    // 2. Reopen (creates .bak from good DB)
    {
        let db = crate::db::Db::open(&path).unwrap();
        let files = db.list_all_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_id, FileId(999));
        drop(db);
    }

    // 3. Verify .bak exists and is a valid DB
    let bak = path.with_extension("redb.bak");
    assert!(bak.exists());

    // 4. Corrupt the main DB
    std::fs::write(&path, b"CORRUPTED GARBAGE DATA").unwrap();

    // 5. Main DB is now unrecoverable, but .bak has our data
    // Open .bak directly to verify data is preserved
    let bak_db = crate::db::Db::open(&bak).unwrap();
    let files = bak_db.list_all_files().unwrap();
    assert_eq!(files.len(), 1, ".bak must contain the pre-corruption data");
    assert_eq!(files[0].file_id, FileId(999));
}

#[test]
fn table_stats_counts_rows() {
    let db = test_db();
    let stats = db.table_stats().unwrap();
    assert_eq!(stats.files, 0);
    assert_eq!(stats.peers, 0);

    // Insert a peer and check count increments.
    let peer = PeerRecord {
        device_id: DeviceId([0u8; 32]),
        master_identity: IdentityPub([0u8; 32]),
        trust_p: 0.0,
        trust_i: 0.0,
        trust_s: 0.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: crate::constants::AVAIL_EWMA_INITIAL,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer).unwrap();
    let stats = db.table_stats().unwrap();
    assert_eq!(stats.peers, 1);
}

// ============================================================
// DB-11: placement_upsert_updates_holder_indexes
// ============================================================

#[test]
fn placement_upsert_updates_holder_indexes() {
    // After upsert_placement, both the file_holders and holder_files indexes
    // must reflect the new placement so that list_holders_for_file and
    // list_files_for_holder return the correct entries.
    let db = test_db();

    let holder_a = DeviceId([0xAAu8; 32]);
    let holder_b = DeviceId([0xBBu8; 32]);
    let file_id_1 = FileId(1001);
    let file_id_2 = FileId(1002);

    // holder_a holds symbols for two different files.
    let p_a1 = make_placement(0xA1, holder_a, file_id_1, PlacementStatus::Alive, 10);
    let p_a2 = make_placement(0xA2, holder_a, file_id_2, PlacementStatus::Alive, 20);
    // holder_b holds symbols for file_id_1 only.
    let p_b1 = make_placement(0xB1, holder_b, file_id_1, PlacementStatus::Alive, 5);

    db.upsert_placement(&p_a1).unwrap();
    db.upsert_placement(&p_a2).unwrap();
    db.upsert_placement(&p_b1).unwrap();

    // file_holders index: file_id_1 must list both holder_a and holder_b.
    let holders_1 = db.list_holders_for_file(file_id_1).unwrap();
    assert!(
        holders_1.contains(&holder_a),
        "file_id_1 should have holder_a in file_holders index"
    );
    assert!(
        holders_1.contains(&holder_b),
        "file_id_1 should have holder_b in file_holders index"
    );

    // file_holders index: file_id_2 must list only holder_a.
    let holders_2 = db.list_holders_for_file(file_id_2).unwrap();
    assert_eq!(
        holders_2,
        vec![holder_a],
        "file_id_2 should list only holder_a"
    );

    // holder_files index: holder_a must list both file_id_1 and file_id_2.
    let files_a = db.list_files_for_holder(&holder_a).unwrap();
    assert!(
        files_a.contains(&file_id_1),
        "holder_a should list file_id_1"
    );
    assert!(
        files_a.contains(&file_id_2),
        "holder_a should list file_id_2"
    );

    // holder_files index: holder_b must list only file_id_1.
    let files_b = db.list_files_for_holder(&holder_b).unwrap();
    assert_eq!(
        files_b,
        vec![file_id_1],
        "holder_b should list only file_id_1"
    );

    // After upsert with updated symbol_count (re-insert), indexes must remain consistent.
    let mut p_a1_updated = p_a1.clone();
    p_a1_updated.esi_ranges = vec![(0, 15)]; // symbol_count changed from 10 to 15
    db.upsert_placement(&p_a1_updated).unwrap();

    let holders_1_after = db.list_holders_for_file(file_id_1).unwrap();
    assert!(
        holders_1_after.contains(&holder_a),
        "holder_a must still appear in file_holders after re-upsert"
    );
}

// ============================================================
// refresh_peer_storage_bytes
// ============================================================

/// When a peer stores bytes for us (Alive placement) and we store bytes for
/// them (Active holding), refresh_peer_storage_bytes must update all three
/// fields: bytes_we_store_for_peer, bytes_peer_stores_for_us, trust_s.
#[test]
fn refresh_peer_storage_bytes_updates_trust_s() {
    let db = test_db();
    let device = DeviceId([0xA1u8; 32]);
    let master = IdentityPub([0xA1u8; 32]); // master identity for this device

    // Insert peer record keyed by DeviceId.
    db.upsert_peer(&make_peer(device)).unwrap();
    // Register device → master mapping so refresh can look up holdings by master.
    db.set_master_for_device(&device, &master).unwrap();

    // ── Set up: peer holds 10 symbols of our data (owner view) ──────────────
    // Source block t=1000 → bytes = 10 * 1000 = 10_000.
    let block_id_a = SourceBlockId([0xA0u8; 32]);
    let sb_a = SourceBlockRecord {
        block_id: block_id_a,
        k: 10,
        t: 1000,
        block_type: crate::types::SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(1000),
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    };
    db.upsert_source_block(&sb_a).unwrap();

    let placement = SymbolPlacement {
        source_block_id: block_id_a,
        holder_id: device,
        file_id: FileId(1),
        esi_ranges: vec![(0, 10)], // 10 symbols
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(1000),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    // ── Set up: we store 5000 bytes for the peer's master (holder view) ──────
    // Holdings are keyed by master IdentityPub (economic unit).
    let holding = HoldingRecord {
        source_block_id: SourceBlockId([0xB0u8; 32]),
        owner_id: master,
        esi_ranges: vec![(0, 5)],
        importance: 0.5,
        total_bytes: 5000,
        status: HoldingStatus::Active,
        received_at: Timestamp(1000),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).unwrap();

    // ── Refresh and verify ────────────────────────────────────────────────────
    db.refresh_peer_storage_bytes(&device).unwrap();

    let updated = db.get_peer(&device).unwrap().unwrap();
    assert_eq!(
        updated.bytes_we_store_for_peer, 5000,
        "should equal holding.total_bytes"
    );
    assert_eq!(
        updated.bytes_peer_stores_for_us, 10_000,
        "should equal 10 symbols * t=1000"
    );
    // trust_s = 10_000 / 5_000 = 2.0
    let expected_trust_s = 10_000_f64 / 5_000_f64;
    assert!(
        (updated.trust_s - expected_trust_s).abs() < 1e-9,
        "trust_s = {}, expected {}",
        updated.trust_s,
        expected_trust_s,
    );
}

/// When we store nothing for the peer, trust_s must be 1.0 (neutral).
#[test]
fn refresh_peer_storage_bytes_neutral_when_we_store_nothing() {
    let db = test_db();
    let device = DeviceId([0xA2u8; 32]);
    let master = IdentityPub([0xA2u8; 32]);
    db.upsert_peer(&make_peer(device)).unwrap();
    db.set_master_for_device(&device, &master).unwrap();

    // Peer holds 5 symbols of ours (Alive).
    let block_id_b = SourceBlockId([0xC0u8; 32]);
    let sb = SourceBlockRecord {
        block_id: block_id_b,
        k: 5,
        t: 2000,
        block_type: crate::types::SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(1000),
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    };
    db.upsert_source_block(&sb).unwrap();
    let p = SymbolPlacement {
        source_block_id: block_id_b,
        holder_id: device,
        file_id: FileId(2),
        esi_ranges: vec![(0, 5)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(1000),
        consecutive_misses: 0,
    };
    db.upsert_placement(&p).unwrap();

    // No holdings for this master (bytes_we_store = 0).
    db.refresh_peer_storage_bytes(&device).unwrap();

    let updated = db.get_peer(&device).unwrap().unwrap();
    assert_eq!(updated.bytes_we_store_for_peer, 0);
    assert_eq!(updated.bytes_peer_stores_for_us, 10_000); // 5 * 2000
    // trust_s must be 1.0 when we_store == 0 (avoid division by zero).
    assert!(
        (updated.trust_s - 1.0).abs() < 1e-9,
        "trust_s must be 1.0 when bytes_we_store_for_peer == 0, got {}",
        updated.trust_s,
    );
}

/// Non-Alive placements must NOT count towards bytes_peer_stores_for_us.
/// Non-Active holdings must NOT count towards bytes_we_store_for_peer.
#[test]
fn refresh_peer_storage_bytes_only_alive_and_active_count() {
    let db = test_db();
    let device = DeviceId([0xA3u8; 32]);
    let master = IdentityPub([0xA3u8; 32]);
    db.upsert_peer(&make_peer(device)).unwrap();
    db.set_master_for_device(&device, &master).unwrap();

    // Source block for placements.
    let block_id_c = SourceBlockId([0xD0u8; 32]);
    let sb = SourceBlockRecord {
        block_id: block_id_c,
        k: 10,
        t: 500,
        block_type: crate::types::SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: Timestamp(1000),
        encrypted_size: None,
        n: None,
        overhead: None,
        drop_notice_sent_at: None,
        importance: 0.0,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.0,
    };
    db.upsert_source_block(&sb).unwrap();

    // One Lost placement — must NOT count.
    let lost = SymbolPlacement {
        source_block_id: block_id_c,
        holder_id: device,
        file_id: FileId(3),
        esi_ranges: vec![(0, 10)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Lost,
        last_verified: None,
        placed_at: Timestamp(1000),
        consecutive_misses: 0,
    };
    db.upsert_placement(&lost).unwrap();

    // One MarkedForDelete holding — must NOT count.
    let mfd_holding = HoldingRecord {
        source_block_id: SourceBlockId([0xE0u8; 32]),
        owner_id: master,
        esi_ranges: vec![(0, 5)],
        importance: 0.5,
        total_bytes: 9999,
        status: HoldingStatus::MarkedForDelete,
        received_at: Timestamp(1000),
        delete_requested_at: Some(Timestamp(2000)),
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&mfd_holding).unwrap();

    db.refresh_peer_storage_bytes(&device).unwrap();

    let updated = db.get_peer(&device).unwrap().unwrap();
    assert_eq!(
        updated.bytes_we_store_for_peer, 0,
        "MarkedForDelete holdings must not count"
    );
    assert_eq!(
        updated.bytes_peer_stores_for_us, 0,
        "Lost placements must not count"
    );
    assert!(
        (updated.trust_s - 1.0).abs() < 1e-9,
        "trust_s must be 1.0 when both counts are 0"
    );
}

/// refresh_peer_storage_bytes must be a no-op when the peer is not in the DB.
#[test]
fn refresh_peer_storage_bytes_noop_for_unknown_peer() {
    let db = test_db();
    let unknown = DeviceId([0xFFu8; 32]);
    // Must not panic or return an error.
    db.refresh_peer_storage_bytes(&unknown).unwrap();
    assert!(db.get_peer(&unknown).unwrap().is_none());
}

// ============================================================
// max_esi_for_block
// ============================================================

/// max_esi_for_block returns 0 when no placements exist for a block.
#[test]
fn max_esi_for_block_no_placements_returns_zero() {
    let db = test_db();
    let bid = block_id(0xAA);
    let result = db.max_esi_for_block(&bid).unwrap();
    assert_eq!(result, 0);
}

/// max_esi_for_block returns max(start + count) across all placements and ranges.
#[test]
fn max_esi_for_block_returns_high_watermark() {
    let db = test_db();
    let bid = block_id(0xBB);
    let peer_a = DeviceId([1u8; 32]);
    let peer_b = DeviceId([2u8; 32]);
    let fid = FileId(1);

    // Placement A: ESI range (0, 100) → high = 100
    let p_a = SymbolPlacement {
        source_block_id: bid,
        holder_id: peer_a,
        file_id: fid,
        esi_ranges: vec![(0, 100)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(1000),
        consecutive_misses: 0,
    };
    // Placement B: ESI range (100, 50) → high = 150
    let p_b = SymbolPlacement {
        source_block_id: bid,
        holder_id: peer_b,
        file_id: fid,
        esi_ranges: vec![(100, 50)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(1000),
        consecutive_misses: 0,
    };

    db.upsert_source_block(&make_source_block(0xBB, SourceBlockStatus::Active))
        .unwrap();
    db.upsert_placement(&p_a).unwrap();
    db.upsert_placement(&p_b).unwrap();

    let hwm = db.max_esi_for_block(&bid).unwrap();
    assert_eq!(hwm, 150, "expected high-watermark = 150 (100+50)");
}

/// max_esi_for_block handles multiple esi_ranges within a single placement.
#[test]
fn max_esi_for_block_multiple_ranges_in_one_placement() {
    let db = test_db();
    let bid = block_id(0xCC);
    let peer = DeviceId([3u8; 32]);
    let fid = FileId(2);

    // Placement with two non-contiguous ranges: (0, 30) and (500, 20) → high = 520
    let p = SymbolPlacement {
        source_block_id: bid,
        holder_id: peer,
        file_id: fid,
        esi_ranges: vec![(0, 30), (500, 20)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(1000),
        consecutive_misses: 0,
    };

    db.upsert_source_block(&make_source_block(0xCC, SourceBlockStatus::Active))
        .unwrap();
    db.upsert_placement(&p).unwrap();

    let hwm = db.max_esi_for_block(&bid).unwrap();
    assert_eq!(hwm, 520, "expected high-watermark = 520 (500+20)");
}

// ============================================================
// Restore served table tests
// ============================================================

fn make_holding_with_bytes(
    block_seed: u8,
    owner: IdentityPub,
    status: HoldingStatus,
    total_bytes: u64,
    received_at: Timestamp,
) -> HoldingRecord {
    HoldingRecord {
        source_block_id: block_id(block_seed),
        owner_id: owner,
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes,
        status,
        received_at,
        delete_requested_at: None,
        drop_notice_sent_at: None,
    }
}

#[test]
fn stored_for_peer_gb_days_empty_returns_zero() {
    let db = test_db();
    let owner = IdentityPub([0xAAu8; 32]);
    let result = db
        .stored_for_peer_gb_days(&owner, Timestamp(1_000_000), 1)
        .unwrap();
    assert_eq!(result, 0.0);
}

#[test]
fn stored_for_peer_gb_days_sums_active_only() {
    // AC-6: 1 Active (5 GB, 10 days) + 1 MarkedForDelete (10 GB, 10 days) → 50.0 GB·days
    let db = test_db();
    let owner = IdentityPub([0xBBu8; 32]);

    let ten_days_secs = 10 * 86_400u64;
    let received_at = Timestamp(0);
    let now = Timestamp(ten_days_secs);

    let five_gb = 5 * 1_073_741_824u64;
    let ten_gb = 10 * 1_073_741_824u64;

    let active = make_holding_with_bytes(0x01, owner, HoldingStatus::Active, five_gb, received_at);
    let marked = make_holding_with_bytes(
        0x02,
        owner,
        HoldingStatus::MarkedForDelete,
        ten_gb,
        received_at,
    );
    db.upsert_holding(&active).unwrap();
    db.upsert_holding(&marked).unwrap();

    let result = db.stored_for_peer_gb_days(&owner, now, 1).unwrap();
    // 5 GB * 10 days = 50 GB·days (MarkedForDelete excluded)
    let expected = 50.0_f64;
    assert!(
        (result - expected).abs() < 0.001,
        "expected ~50 GB·days, got {result}"
    );
}

#[test]
fn stored_for_peer_gb_days_multiple_holdings() {
    // 2 Active: (10 GB, 7 days) + (20 GB, 14 days) → 70 + 280 = 350.0 GB·days
    let db = test_db();
    let owner = IdentityPub([0xCCu8; 32]);

    let seven_days = 7 * 86_400u64;
    let fourteen_days = 14 * 86_400u64;

    let ten_gb = 10 * 1_073_741_824u64;
    let twenty_gb = 20 * 1_073_741_824u64;

    // First holding: received at t=0, now at 7 days → 7 day age
    let h1 = make_holding_with_bytes(0x01, owner, HoldingStatus::Active, ten_gb, Timestamp(0));
    // Second holding: received at t=0, now at 14 days → 14 day age
    let h2 = make_holding_with_bytes(0x02, owner, HoldingStatus::Active, twenty_gb, Timestamp(0));
    db.upsert_holding(&h1).unwrap();
    db.upsert_holding(&h2).unwrap();

    // Use now = 14 days for h2 and 7 days for h1 is impossible with one `now`.
    // Use separate calls to test incrementally: test at now=7days then now=14days.
    let result_7d = db
        .stored_for_peer_gb_days(&owner, Timestamp(seven_days), 1)
        .unwrap();
    // Both holdings: 10*7 + 20*7 = 70 + 140 = 210
    assert!(
        (result_7d - 210.0).abs() < 0.01,
        "at 7 days expected 210 GB·days, got {result_7d}"
    );

    let result_14d = db
        .stored_for_peer_gb_days(&owner, Timestamp(fourteen_days), 1)
        .unwrap();
    // 10*14 + 20*14 = 140 + 280 = 420
    assert!(
        (result_14d - 420.0).abs() < 0.01,
        "at 14 days expected 420 GB·days, got {result_14d}"
    );
}

#[test]
fn stored_for_peer_gb_days_zero_age_returns_zero() {
    // received_at == now → age=0 → 0.0 GB·days
    let db = test_db();
    let owner = IdentityPub([0xDDu8; 32]);
    let ts = Timestamp(1_000_000);
    let one_gb = 1_073_741_824u64;
    let h = make_holding_with_bytes(0x01, owner, HoldingStatus::Active, one_gb, ts);
    db.upsert_holding(&h).unwrap();

    let result = db.stored_for_peer_gb_days(&owner, ts, 1).unwrap();
    assert_eq!(result, 0.0);
}

#[test]
fn restored_total_bytes_returns_zero_for_unknown_peer() {
    let db = test_db();
    let owner = IdentityPub([0xEEu8; 32]);
    let result = db.restored_total_bytes(&owner).unwrap();
    assert_eq!(result, 0);
}

#[test]
fn record_restore_served_increments_counter() {
    let db = test_db();
    let owner = IdentityPub([0xFFu8; 32]);

    db.record_restore_served(&owner, 1_000_000).unwrap();
    let result = db.restored_total_bytes(&owner).unwrap();
    assert_eq!(result, 1_000_000);
}

#[test]
fn record_restore_served_accumulates_multiple_calls() {
    // Add 1 GB, 2 GB, 3 GB → total = 6 GB
    let db = test_db();
    let owner = IdentityPub([0x11u8; 32]);
    let one_gb = 1_073_741_824u64;

    db.record_restore_served(&owner, one_gb).unwrap();
    db.record_restore_served(&owner, 2 * one_gb).unwrap();
    db.record_restore_served(&owner, 3 * one_gb).unwrap();

    let result = db.restored_total_bytes(&owner).unwrap();
    assert_eq!(result, 6 * one_gb);
}

#[test]
fn record_restore_served_saturates_at_u64_max() {
    // Start near u64::MAX, add more → no overflow panic (saturating_add)
    let db = test_db();
    let owner = IdentityPub([0x22u8; 32]);

    db.record_restore_served(&owner, u64::MAX - 10).unwrap();
    db.record_restore_served(&owner, 100).unwrap();

    let result = db.restored_total_bytes(&owner).unwrap();
    assert_eq!(result, u64::MAX, "saturating_add should cap at u64::MAX");
}

// ─── Two-level trust DB ──────────────────────────────────────────────────────

#[test]
fn db_device_trust_roundtrip() {
    let db = test_db();
    let device_id = DeviceId([0xAA; 32]);
    let record = DeviceTrustRecord {
        device_id,
        trust_p: 0.8,
        trust_i: 0.6,
        last_week: 42,
    };

    db.set_device_trust(&record).unwrap();
    let result = db
        .get_device_trust(&device_id)
        .unwrap()
        .expect("should be present");

    assert_eq!(result.device_id, record.device_id);
    assert!((result.trust_p - record.trust_p).abs() < 1e-10);
    assert!((result.trust_i - record.trust_i).abs() < 1e-10);
    assert_eq!(result.last_week, record.last_week);
}

#[test]
fn db_master_trust_roundtrip() {
    let db = test_db();
    let identity = IdentityPub([0xBB; 32]);
    let record = MasterTrustRecord {
        identity,
        combined: 1.5,
        last_updated: Timestamp(9_999_999),
    };

    db.set_master_trust(&record).unwrap();
    let result = db
        .get_master_trust(&identity)
        .unwrap()
        .expect("should be present");

    assert_eq!(result.identity, record.identity);
    assert!((result.combined - record.combined).abs() < 1e-10);
    assert_eq!(result.last_updated, record.last_updated);
}

#[test]
fn db_device_to_master_mapping() {
    let db = test_db();
    let device = DeviceId([0x11; 32]);
    let master = IdentityPub([0x22; 32]);

    db.set_master_for_device(&device, &master).unwrap();
    let result = db
        .get_master_for_device(&device)
        .unwrap()
        .expect("should be present");

    assert_eq!(result, master);
}

#[test]
fn db_get_devices_for_master_returns_all() {
    let db = test_db();
    let master = IdentityPub([0xFF; 32]);
    let device_a = DeviceId([0x01; 32]);
    let device_b = DeviceId([0x02; 32]);
    let device_c = DeviceId([0x03; 32]);

    db.set_master_for_device(&device_a, &master).unwrap();
    db.set_master_for_device(&device_b, &master).unwrap();
    db.set_master_for_device(&device_c, &master).unwrap();

    let mut devices = db.get_devices_for_master(&master).unwrap();
    devices.sort_by_key(|d| d.0);

    assert_eq!(devices.len(), 3);
    assert!(devices.contains(&device_a));
    assert!(devices.contains(&device_b));
    assert!(devices.contains(&device_c));
}

#[test]
fn db_get_device_trust_absent_returns_none() {
    let db = test_db();
    let unknown = DeviceId([0x99; 32]);
    let result = db.get_device_trust(&unknown).unwrap();
    assert!(result.is_none(), "should return None for unknown device");
}

// ============================================================
// delete_placement returning Option<SymbolPlacement>
// ============================================================

#[test]
fn delete_placement_removes_record() {
    let db = test_db();
    let holder = DeviceId([0xD0u8; 32]);
    let p = make_placement(0xD0, holder, FileId(200), PlacementStatus::Alive, 40);
    db.upsert_placement(&p).unwrap();

    let _ = db.delete_placement(&block_id(0xD0), &holder).unwrap();

    assert!(
        db.get_placement(&block_id(0xD0), &holder)
            .unwrap()
            .is_none(),
        "placement must be absent after delete"
    );
}

#[test]
fn delete_placement_returns_deleted_record() {
    let db = test_db();
    let holder = DeviceId([0xD1u8; 32]);
    let p = make_placement(0xD1, holder, FileId(201), PlacementStatus::Alive, 55);
    db.upsert_placement(&p).unwrap();

    let deleted = db.delete_placement(&block_id(0xD1), &holder).unwrap();

    assert!(deleted.is_some(), "must return Some for existing placement");
    let rec = deleted.unwrap();
    assert_eq!(rec.holder_id, holder);
    assert_eq!(rec.symbol_count(), 55);
    assert_eq!(rec.file_id, FileId(201));
}

#[test]
fn delete_placement_nonexistent_returns_none() {
    let db = test_db();
    let holder = DeviceId([0xD2u8; 32]);

    let result = db.delete_placement(&block_id(0xD2), &holder).unwrap();

    assert!(
        result.is_none(),
        "must return None when placement does not exist"
    );
}

#[test]
fn delete_placement_updates_hot_cache() {
    let db = test_db();
    let holder = DeviceId([0xD3u8; 32]);
    let p = make_placement(0xD3, holder, FileId(203), PlacementStatus::Alive, 70);
    db.upsert_placement(&p).unwrap();

    {
        let hot = db.hot();
        assert_eq!(
            hot.blocks
                .get(&block_id(0xD3))
                .map(|a| a.total_alive_symbols)
                .unwrap_or(0),
            70,
            "alive count must be 70 before delete"
        );
        assert!(hot.placements.contains_key(&(block_id(0xD3), holder)));
    }

    let deleted = db.delete_placement(&block_id(0xD3), &holder).unwrap();
    assert!(deleted.is_some());

    {
        let hot = db.hot();
        assert_eq!(
            hot.blocks
                .get(&block_id(0xD3))
                .map(|a| a.total_alive_symbols)
                .unwrap_or(0),
            0,
            "alive count must drop to 0 after delete"
        );
        assert!(
            !hot.placements.contains_key(&(block_id(0xD3), holder)),
            "placement must be removed from hot cache"
        );
    }
}

#[test]
fn delete_placement_cleans_indexes() {
    let db = test_db();
    let holder = DeviceId([0xD4u8; 32]);
    let fid = FileId(204);
    let p = make_placement(0xD4, holder, fid, PlacementStatus::Alive, 30);
    db.upsert_placement(&p).unwrap();

    assert!(db.list_holders_for_file(fid).unwrap().contains(&holder));
    assert!(db.list_files_for_holder(&holder).unwrap().contains(&fid));

    let _ = db.delete_placement(&block_id(0xD4), &holder).unwrap();

    assert!(
        db.list_holders_for_file(fid).unwrap().is_empty(),
        "FILE_HOLDERS index must be cleaned after delete"
    );
    assert!(
        db.list_files_for_holder(&holder).unwrap().is_empty(),
        "HOLDER_FILES index must be cleaned after delete"
    );
}

// ============================================================
// DbWriteTxn tests
// ============================================================

// Test 1: all writes within a single write_txn commit atomically.
#[test]
fn write_txn_commits_all_writes_atomically() {
    let db = test_db();
    let bob = DeviceId([0xE1u8; 32]);
    let block_a = make_source_block(0xE1, SourceBlockStatus::Active);
    let placement_a_bob = make_placement(0xE1, bob, FileId(0xE1), PlacementStatus::Alive, 5);
    let event_1 = make_event(1);

    let mut txn = db.write_txn().unwrap();
    txn.upsert_source_block(&block_a).unwrap();
    txn.upsert_placement(&placement_a_bob).unwrap();
    txn.append_event(&event_1).unwrap();
    txn.commit().unwrap();

    assert!(
        db.get_source_block(&block_id(0xE1)).unwrap().is_some(),
        "source block must be visible after commit"
    );
    let placements = db.list_placements_for_block(&block_id(0xE1)).unwrap();
    assert_eq!(placements.len(), 1);
    assert_eq!(placements[0].holder_id, bob);

    let events = db.events_after(0, 10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, 1);
}

// Test 2: dropping without commit leaves DB unchanged.
#[test]
fn write_txn_rollback_on_drop_leaves_db_empty() {
    let db = test_db();
    let block_a = make_source_block(0xE2, SourceBlockStatus::Active);

    {
        let mut txn = db.write_txn().unwrap();
        txn.upsert_source_block(&block_a).unwrap();
        // Drop txn here without calling commit — redb rolls back automatically.
    }

    assert!(
        db.get_source_block(&block_id(0xE2)).unwrap().is_none(),
        "source block must NOT be visible after implicit rollback"
    );
}

// Test 3: hot cache is NOT updated until commit() is called.
#[test]
fn write_txn_hot_cache_not_updated_before_commit() {
    let db = test_db();
    let bob = DeviceId([0xE3u8; 32]);
    let fid = FileId(0xE3);

    // Set up: existing Alive placement (5 symbols) already committed.
    let initial = make_placement(0xE3, bob, fid, PlacementStatus::Alive, 5);
    db.upsert_placement(&initial).unwrap();
    assert_eq!(
        db.hot()
            .blocks
            .get(&block_id(0xE3))
            .map(|a| a.total_alive_symbols)
            .unwrap_or(0),
        5,
        "initial hot cache: 5 alive"
    );

    let mut txn = db.write_txn().unwrap();
    // Change status to Lost (0 alive symbols) inside transaction.
    let lost = make_placement(0xE3, bob, fid, PlacementStatus::Lost, 5);
    txn.upsert_placement(&lost).unwrap();

    // Before commit: hot cache still shows Alive.
    assert_eq!(
        db.hot()
            .placements
            .get(&(block_id(0xE3), bob))
            .map(|a| a.status),
        Some(PlacementStatus::Alive),
        "hot cache must NOT be updated before commit"
    );

    txn.commit().unwrap();

    // After commit: hot cache reflects Lost status (0 alive symbols).
    assert_eq!(
        db.hot()
            .placements
            .get(&(block_id(0xE3), bob))
            .map(|a| a.status),
        Some(PlacementStatus::Lost),
        "hot cache must be updated after commit"
    );
    assert_eq!(
        db.hot()
            .blocks
            .get(&block_id(0xE3))
            .map(|a| a.total_alive_symbols)
            .unwrap_or(0),
        0,
        "alive symbols must drop to 0 after committing Lost placement"
    );
}

// Test 4: multiple placements in one txn, hot cache totals correct.
#[test]
fn write_txn_hot_cache_updated_correctly_for_multiple_placements() {
    let db = test_db();
    let bob = DeviceId([0xE4u8; 32]);
    let carol = DeviceId([0xE5u8; 32]);
    let dave = DeviceId([0xE6u8; 32]);
    let fid = FileId(0xE4);

    // First txn: insert three Alive placements (5 alive symbols each).
    {
        let mut txn = db.write_txn().unwrap();
        txn.upsert_placement(&make_placement(0xE4, bob, fid, PlacementStatus::Alive, 5))
            .unwrap();
        txn.upsert_placement(&make_placement(0xE4, carol, fid, PlacementStatus::Alive, 5))
            .unwrap();
        txn.upsert_placement(&make_placement(0xE4, dave, fid, PlacementStatus::Alive, 5))
            .unwrap();
        txn.commit().unwrap();
    }
    assert_eq!(
        db.hot()
            .blocks
            .get(&block_id(0xE4))
            .map(|a| a.total_alive_symbols)
            .unwrap_or(0),
        15,
        "three placements of 5 each = 15 alive symbols"
    );

    // Second txn: mark bob's placement Lost.
    {
        let mut txn = db.write_txn().unwrap();
        txn.upsert_placement(&make_placement(0xE4, bob, fid, PlacementStatus::Lost, 5))
            .unwrap();
        txn.commit().unwrap();
    }
    assert_eq!(
        db.hot()
            .blocks
            .get(&block_id(0xE4))
            .map(|a| a.total_alive_symbols)
            .unwrap_or(0),
        10,
        "after bob goes Lost, alive symbols = 10"
    );
}

// Test 5: append_event inside a txn assigns contiguous sequence numbers.
#[test]
fn write_txn_event_sequence_numbers_are_contiguous() {
    let db = test_db();

    // Pre-seed 3 events so the last seq is 3.
    for i in 1..=3u8 {
        db.append_event(&make_event(i)).unwrap();
    }
    assert_eq!(db.last_event_seq().unwrap(), 3);

    let mut txn = db.write_txn().unwrap();
    let s4 = txn.append_event(&make_event(4)).unwrap();
    let s5 = txn.append_event(&make_event(5)).unwrap();
    let s6 = txn.append_event(&make_event(6)).unwrap();
    txn.commit().unwrap();

    assert_eq!(
        (s4, s5, s6),
        (4, 5, 6),
        "sequence numbers must be contiguous"
    );
    assert_eq!(db.last_event_seq().unwrap(), 6);
    let after_3 = db.events_after(3, 10).unwrap();
    assert_eq!(after_3.len(), 3, "must have exactly 3 events after seq 3");
}

// Test 6: single-operation methods and write_txn interleave correctly.
#[test]
fn write_txn_and_single_operation_methods_interleave_correctly() {
    let db = test_db();
    let bob = DeviceId([0xE7u8; 32]);
    let carol = DeviceId([0xE8u8; 32]);
    let dave = DeviceId([0xE9u8; 32]);
    let fid = FileId(0xE7);

    // Step 1: single-operation write.
    db.upsert_source_block(&make_source_block(0xE7, SourceBlockStatus::Active))
        .unwrap();

    // Step 2: multi-operation txn.
    {
        let mut txn = db.write_txn().unwrap();
        txn.upsert_placement(&make_placement(0xE7, bob, fid, PlacementStatus::Alive, 5))
            .unwrap();
        txn.upsert_placement(&make_placement(0xE7, carol, fid, PlacementStatus::Alive, 5))
            .unwrap();
        txn.commit().unwrap();
    }

    // Step 3: another single-operation write.
    db.upsert_placement(&make_placement(0xE7, dave, fid, PlacementStatus::Alive, 5))
        .unwrap();

    // Verify all writes are visible.
    assert!(db.get_source_block(&block_id(0xE7)).unwrap().is_some());
    let placements = db.list_placements_for_block(&block_id(0xE7)).unwrap();
    assert_eq!(placements.len(), 3);
    assert_eq!(
        db.hot()
            .blocks
            .get(&block_id(0xE7))
            .map(|a| a.total_alive_symbols)
            .unwrap_or(0),
        15,
        "three placements of 5 each = 15 alive symbols"
    );
}

// Test 7: rollback leaves hot cache unchanged.
#[test]
fn write_txn_rollback_leaves_hot_cache_unchanged() {
    let db = test_db();
    let bob = DeviceId([0xEAu8; 32]);
    let fid = FileId(0xEA);

    // Set up: Alive placement with 5 symbols.
    db.upsert_placement(&make_placement(0xEA, bob, fid, PlacementStatus::Alive, 5))
        .unwrap();
    assert_eq!(
        db.hot()
            .blocks
            .get(&block_id(0xEA))
            .map(|a| a.total_alive_symbols)
            .unwrap_or(0),
        5
    );

    // Open txn, queue a delta, then drop without commit.
    {
        let mut txn = db.write_txn().unwrap();
        txn.upsert_placement(&make_placement(0xEA, bob, fid, PlacementStatus::Lost, 5))
            .unwrap();
        // Drop without commit — redb rolls back, hot cache must NOT be touched.
    }

    // Hot cache unchanged: still 5 alive, still Alive status.
    assert_eq!(
        db.hot()
            .blocks
            .get(&block_id(0xEA))
            .map(|a| a.total_alive_symbols)
            .unwrap_or(0),
        5,
        "hot cache alive count must be unchanged after rollback"
    );
    assert_eq!(
        db.hot()
            .placements
            .get(&(block_id(0xEA), bob))
            .map(|a| a.status),
        Some(PlacementStatus::Alive),
        "hot cache placement status must be unchanged after rollback"
    );
    // DB record also unchanged.
    let rec = db.get_placement(&block_id(0xEA), &bob).unwrap().unwrap();
    assert_eq!(
        rec.status,
        PlacementStatus::Alive,
        "DB record must be unchanged after rollback"
    );
}

// Test 8: delete_placement inside a txn queues correct delta and cleans indexes.
#[test]
fn write_txn_delete_placement_queues_correct_delta() {
    let db = test_db();
    let bob = DeviceId([0xEBu8; 32]);
    let fid = FileId(0xEB);

    // Set up: Alive placement with 5 symbols.
    db.upsert_placement(&make_placement(0xEB, bob, fid, PlacementStatus::Alive, 5))
        .unwrap();
    assert_eq!(
        db.hot()
            .blocks
            .get(&block_id(0xEB))
            .map(|a| a.total_alive_symbols)
            .unwrap_or(0),
        5
    );

    // Delete inside txn, then commit.
    let mut txn = db.write_txn().unwrap();
    let deleted = txn.delete_placement(&block_id(0xEB), &bob).unwrap();
    assert!(
        deleted.is_some(),
        "delete_placement must return the old record"
    );
    txn.commit().unwrap();

    // Hot cache: placement entry gone, block entry gone (no more alive symbols).
    assert!(
        !db.hot().placements.contains_key(&(block_id(0xEB), bob)),
        "placement must be removed from hot cache after txn delete"
    );
    assert!(
        !db.hot().blocks.contains_key(&block_id(0xEB)),
        "block entry must be removed from hot cache when all placements deleted"
    );

    // DB: placement gone, indexes cleaned.
    assert!(
        db.list_placements_for_block(&block_id(0xEB))
            .unwrap()
            .is_empty()
    );
    assert!(db.list_holders_for_file(fid).unwrap().is_empty());
    assert!(db.list_files_for_holder(&bob).unwrap().is_empty());
}

// ─── Retention / pruning (review BLOCK-4, Wave 2 B5) ──────────────────────────

#[test]
fn event_log_pruning_reduces_rows() {
    let db = crate::db::Db::open_in_memory().unwrap();
    // Write 100 events.
    for i in 0u8..100 {
        db.append_event(&make_event(i % 250)).unwrap();
    }
    // Verify we have 100 (seqs 1..=100).
    let events = db.events_after(0, 200).unwrap();
    assert_eq!(events.len(), 100);

    // Prune: keep seq >= 81 (i.e. drop seq 1..=80).
    let removed = db.truncate_event_log_before(81).unwrap();
    assert_eq!(removed, 80, "should remove exactly 80 rows");

    let after = db.events_after(0, 200).unwrap();
    assert!(
        after.len() <= 20,
        "after pruning: {} rows (expected ≤ 20)",
        after.len()
    );
    // Verify the first surviving sequence number is 81.
    assert_eq!(after[0].0, 81, "first surviving seq must be 81");
}

#[test]
fn truncate_event_log_before_drops_old_entries_and_keeps_new() {
    let db = crate::db::Db::open_in_memory().unwrap();
    for i in 0..10 {
        db.append_event(&make_event(i)).unwrap();
    }
    // Prune entries with seq < 5 → removes seqs 1..=4.
    let removed = db.truncate_event_log_before(5).unwrap();
    assert_eq!(removed, 4, "four rows expected to be removed");

    // Seqs 5..=10 must still be there.
    let remaining = db.events_after(0, 100).unwrap();
    assert_eq!(remaining.len(), 6);
    assert_eq!(remaining[0].0, 5, "first surviving seq");
    assert_eq!(remaining.last().unwrap().0, 10, "last surviving seq");
}

#[test]
fn truncate_event_log_before_noop_when_seq_zero() {
    let db = crate::db::Db::open_in_memory().unwrap();
    db.append_event(&make_event(1)).unwrap();
    db.append_event(&make_event(2)).unwrap();
    let removed = db.truncate_event_log_before(0).unwrap();
    assert_eq!(removed, 0);
    assert_eq!(db.events_after(0, 100).unwrap().len(), 2);
}

#[test]
fn prune_pos_weekly_before_keeps_recent_weeks() {
    let db = crate::db::Db::open_in_memory().unwrap();
    let dev = DeviceId([1u8; 32]);
    for week in 0..20u32 {
        let entry = WeeklyPosEntry {
            challenged: week,
            passed: week,
        };
        db.upsert_pos_weekly(&dev, week, &entry).unwrap();
    }
    // Prune anything with week < 10 — weeks 0..=9 should disappear.
    let removed = db.prune_pos_weekly_before(10).unwrap();
    assert_eq!(removed, 10);

    let remaining = db.list_pos_weekly_for_peer(&dev).unwrap();
    assert_eq!(remaining.len(), 10);
    let min_week = remaining.iter().map(|(w, _)| *w).min().unwrap();
    assert_eq!(min_week, 10);
}

#[test]
fn next_file_id_persists_across_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("db.redb");
    {
        let db = crate::db::Db::open(&path).unwrap();
        assert_eq!(db.load_next_file_id().unwrap(), 1, "fresh db defaults to 1");
        db.store_next_file_id(42).unwrap();
    }
    // Reopen and verify the counter survived.
    let db2 = crate::db::Db::open(&path).unwrap();
    assert_eq!(db2.load_next_file_id().unwrap(), 42);
}

// ============================================================
// B3: transition_placement_offered_to_alive tests
// ============================================================

#[test]
fn transition_offered_to_alive_updates_status() {
    let db = Db::open_in_memory().unwrap();
    let block_id = SourceBlockId([7; 32]);
    let holder_id = DeviceId([8; 32]);
    let placed_at = Timestamp(1000);
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: FileId(1),
        esi_ranges: vec![(0, 50)],
        binding_seed: [0; 32],
        status: PlacementStatus::Offered,
        last_verified: None,
        placed_at,
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    let alive_at = Timestamp(2000);
    let result = db
        .transition_placement_offered_to_alive(&block_id, &holder_id, alive_at)
        .unwrap();
    assert!(result, "should have transitioned");

    let updated = db.get_placement(&block_id, &holder_id).unwrap().unwrap();
    assert_eq!(updated.status, PlacementStatus::Alive);
    assert_eq!(
        updated.placed_at, alive_at,
        "placed_at should be updated to alive_at"
    );

    // Hot cache should now count these symbols as alive.
    let hot = db.hot();
    let agg = hot.blocks.get(&block_id).unwrap();
    assert_eq!(agg.total_alive_symbols, 50);
}

#[test]
fn transition_offered_to_alive_is_idempotent() {
    let db = Db::open_in_memory().unwrap();
    let block_id = SourceBlockId([9; 32]);
    let holder_id = DeviceId([10; 32]);
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: FileId(1),
        esi_ranges: vec![(0, 30)],
        binding_seed: [0; 32],
        status: PlacementStatus::Offered,
        last_verified: None,
        placed_at: Timestamp(1000),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    let r1 = db
        .transition_placement_offered_to_alive(&block_id, &holder_id, Timestamp(2000))
        .unwrap();
    assert!(r1);

    let r2 = db
        .transition_placement_offered_to_alive(&block_id, &holder_id, Timestamp(3000))
        .unwrap();
    assert!(!r2, "second call should be no-op (already Alive)");

    let final_p = db.get_placement(&block_id, &holder_id).unwrap().unwrap();
    assert_eq!(final_p.status, PlacementStatus::Alive);
    assert_eq!(
        final_p.placed_at,
        Timestamp(2000),
        "placed_at should not change on second call"
    );
}

#[test]
fn transition_non_offered_placement_is_noop() {
    let db = Db::open_in_memory().unwrap();
    let block_id = SourceBlockId([11; 32]);
    let holder_id = DeviceId([12; 32]);
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id,
        file_id: FileId(1),
        esi_ranges: vec![(0, 20)],
        binding_seed: [0; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp(500),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    let result = db
        .transition_placement_offered_to_alive(&block_id, &holder_id, Timestamp(1000))
        .unwrap();
    assert!(!result, "should not transition Alive placement");

    let p = db.get_placement(&block_id, &holder_id).unwrap().unwrap();
    assert_eq!(p.placed_at, Timestamp(500), "placed_at unchanged");
    assert_eq!(p.status, PlacementStatus::Alive);
}

// ============================================================
// next_work_item tests
// ============================================================

#[allow(clippy::too_many_arguments)]
fn make_block_with(
    seed: u8,
    status: SourceBlockStatus,
    importance: f64,
    current_alive: u32,
    n: Option<u32>,
    current_reliability: f64,
    target_reliability: f64,
) -> SourceBlockRecord {
    SourceBlockRecord {
        block_id: SourceBlockId([seed; 32]),
        k: 10,
        t: 65535,
        block_type: SourceBlockType::Single,
        status,
        created_at: Timestamp(1000),
        encrypted_size: None,
        n,
        overhead: None,
        drop_notice_sent_at: None,
        importance,
        current_alive,
        current_reliability,
        target_reliability,
    }
}

#[test]
fn block_cooldown_does_not_survive_reopen() {
    // B-4: worker cooldown is RAM-only. A restart clears it, so every block is
    // re-attempted after a restart — the intended behavior.
    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let tmp_path = tmpfile.into_temp_path();
    let bid = block_id(1);
    {
        let db = Db::open(&tmp_path).unwrap();
        db.set_block_cooldown(&bid, Some(Timestamp(5000)), 0xABCD);
        assert_eq!(db.block_cooldown(&bid).last_pool_signature, 0xABCD);
    }
    let db2 = Db::open(&tmp_path).unwrap();
    let cd = db2.block_cooldown(&bid);
    assert_eq!(
        cd.last_attempted_at, None,
        "cooldown must not survive reopen (RAM-only)"
    );
    assert_eq!(cd.last_pool_signature, 0);
}

#[test]
fn next_work_item_returns_none_when_db_empty() {
    let db = Db::open_in_memory().unwrap();
    let result = db
        .next_work_item(
            1.5,
            std::time::Duration::from_secs(30),
            Timestamp(9999),
            0xABCD,
        )
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn next_work_item_returns_none_when_all_blocks_at_target_reliability() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(9999);

    let a = make_block_with(1, SourceBlockStatus::Active, 0.8, 5, Some(10), 0.999, 0.999);
    let b = make_block_with(
        2,
        SourceBlockStatus::Active,
        0.8,
        5,
        Some(10),
        0.9999,
        0.9996,
    );
    let c = make_block_with(3, SourceBlockStatus::Active, 0.8, 5, Some(10), 1.0, 0.9);
    db.upsert_source_block(&a).unwrap();
    db.upsert_source_block(&b).unwrap();
    db.upsert_source_block(&c).unwrap();

    let result = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn next_work_item_returns_none_when_no_active_blocks_need_work() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(9999);

    let a = make_block_with(1, SourceBlockStatus::Deleting, 0.8, 0, Some(10), 0.5, 0.999);
    let b = make_block_with(2, SourceBlockStatus::Stale, 0.8, 0, Some(10), 0.3, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.upsert_source_block(&b).unwrap();

    let result = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn next_work_item_picks_highest_priority() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(9999);

    // priority(A) = 0.5 * (1 + 1.5 * 12/14) ≈ 1.143
    let a = make_block_with(1, SourceBlockStatus::Active, 0.5, 12, Some(14), 0.5, 0.999);
    // priority(B) = 1.0 * (1 + 0) = 1.0
    let b = make_block_with(2, SourceBlockStatus::Active, 1.0, 0, Some(12), 0.0, 0.999);
    // priority(C) = 0.8 * (1 + 1.5 * 0.5) = 0.8 * 1.75 = 1.4
    let c = make_block_with(3, SourceBlockStatus::Active, 0.8, 6, Some(12), 0.4, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.upsert_source_block(&b).unwrap();
    db.upsert_source_block(&c).unwrap();

    let result = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        result.block_id,
        SourceBlockId([3; 32]),
        "Block C has highest priority (1.4)"
    );
}

#[test]
fn next_work_item_uses_coef_from_param() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(9999);

    // priority(A, coef=0) = 0.5, priority(A, coef=5) = 0.5 * (1 + 5*0.9) = 0.5 * 5.5 = 2.75
    let a = make_block_with(1, SourceBlockStatus::Active, 0.5, 9, Some(10), 0.4, 0.999);
    // priority(B, coef=0) = 0.6, priority(B, coef=5) = 0.6
    let b = make_block_with(2, SourceBlockStatus::Active, 0.6, 0, Some(10), 0.3, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.upsert_source_block(&b).unwrap();

    let result_coef0 = db
        .next_work_item(0.0, std::time::Duration::from_secs(30), now, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        result_coef0.block_id,
        SourceBlockId([2; 32]),
        "Block B wins when coef=0"
    );

    let result_coef5 = db
        .next_work_item(5.0, std::time::Duration::from_secs(30), now, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        result_coef5.block_id,
        SourceBlockId([1; 32]),
        "Block A wins when coef=5"
    );
}

#[test]
fn next_work_item_tiebreaks_by_last_attempted_at_ascending() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(99999);

    let a = make_block_with(1, SourceBlockStatus::Active, 0.8, 5, Some(10), 0.4, 0.999);
    let b = make_block_with(2, SourceBlockStatus::Active, 0.8, 5, Some(10), 0.4, 0.999);
    let c = make_block_with(3, SourceBlockStatus::Active, 0.8, 5, Some(10), 0.4, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.set_block_cooldown(&a.block_id, Some(Timestamp(1000)), 0);
    db.upsert_source_block(&b).unwrap();
    db.set_block_cooldown(&b.block_id, Some(Timestamp(500)), 0);
    db.upsert_source_block(&c).unwrap();
    db.set_block_cooldown(&c.block_id, Some(Timestamp(2000)), 0);

    let result = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        result.block_id,
        SourceBlockId([2; 32]),
        "Block B has earliest last_attempted_at=500"
    );
}

#[test]
fn next_work_item_never_attempted_beats_recently_attempted() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(99999);

    let a = make_block_with(1, SourceBlockStatus::Active, 0.7, 3, Some(10), 0.3, 0.999);
    let b = make_block_with(2, SourceBlockStatus::Active, 0.7, 3, Some(10), 0.3, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.set_block_cooldown(&a.block_id, Some(Timestamp(0)), 0);
    db.upsert_source_block(&b).unwrap();

    let result = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        result.block_id,
        SourceBlockId([2; 32]),
        "Block B (never attempted) wins over Block A"
    );
}

#[test]
fn next_work_item_deterministic_tiebreak_by_block_id() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(9999);

    // Both blocks: same priority, last_attempted_at=None. Block B has seed=0x00 (smaller).
    let a = make_block_with(
        0x01,
        SourceBlockStatus::Active,
        0.8,
        5,
        Some(10),
        0.4,
        0.999,
    );
    let b = make_block_with(
        0x00,
        SourceBlockStatus::Active,
        0.8,
        5,
        Some(10),
        0.4,
        0.999,
    );
    db.upsert_source_block(&a).unwrap();
    db.upsert_source_block(&b).unwrap();

    let result1 = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap()
        .unwrap();
    let result2 = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        result1.block_id,
        SourceBlockId([0x00; 32]),
        "Block with smaller block_id wins"
    );
    assert_eq!(
        result1.block_id, result2.block_id,
        "Result is deterministic across two calls"
    );
}

#[test]
fn next_work_item_excludes_deleting_blocks() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(9999);

    let a = make_block_with(1, SourceBlockStatus::Active, 0.5, 0, Some(10), 0.0, 0.999);
    let b = make_block_with(2, SourceBlockStatus::Deleting, 1.0, 0, Some(10), 0.0, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.upsert_source_block(&b).unwrap();

    let result = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        result.block_id,
        SourceBlockId([1; 32]),
        "Deleting block excluded despite higher importance"
    );
}

#[test]
fn next_work_item_excludes_blocks_in_cooldown() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(1000);

    let a = make_block_with(1, SourceBlockStatus::Active, 0.9, 0, Some(10), 0.0, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.set_block_cooldown(&a.block_id, Some(Timestamp(990)), 0xABCD);

    // Elapsed: 10s < 30s cooldown, same pool sig → in cooldown.
    let result = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0xABCD)
        .unwrap();
    assert!(result.is_none(), "Block A is in cooldown");
}

#[test]
fn next_work_item_includes_block_after_cooldown_expires() {
    let db = Db::open_in_memory().unwrap();

    let a = make_block_with(1, SourceBlockStatus::Active, 0.9, 0, Some(10), 0.0, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.set_block_cooldown(&a.block_id, Some(Timestamp(1000)), 0xABCD);

    // 25s < 30s → still in cooldown.
    let result_during = db
        .next_work_item(
            1.5,
            std::time::Duration::from_secs(30),
            Timestamp(1025),
            0xABCD,
        )
        .unwrap();
    assert!(result_during.is_none(), "25s < 30s: still in cooldown");

    // 31s >= 30s → cooldown expired.
    let result_after = db
        .next_work_item(
            1.5,
            std::time::Duration::from_secs(30),
            Timestamp(1031),
            0xABCD,
        )
        .unwrap();
    assert!(result_after.is_some(), "31s >= 30s: cooldown expired");
    assert_eq!(result_after.unwrap().block_id, SourceBlockId([1; 32]));
}

#[test]
fn next_work_item_includes_block_when_pool_signature_changes() {
    let db = Db::open_in_memory().unwrap();

    let a = make_block_with(1, SourceBlockStatus::Active, 0.9, 0, Some(10), 0.0, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.set_block_cooldown(&a.block_id, Some(Timestamp(1000)), 0xABCD);

    // Same pool: 10s < 30s → in cooldown.
    let result_same_pool = db
        .next_work_item(
            1.5,
            std::time::Duration::from_secs(30),
            Timestamp(1010),
            0xABCD,
        )
        .unwrap();
    assert!(result_same_pool.is_none(), "Same pool: block in cooldown");

    // Pool changed: cooldown bypassed.
    let result_new_pool = db
        .next_work_item(
            1.5,
            std::time::Duration::from_secs(30),
            Timestamp(1010),
            0xDEAD,
        )
        .unwrap();
    assert!(result_new_pool.is_some(), "Pool changed: cooldown bypassed");
    assert_eq!(result_new_pool.unwrap().block_id, SourceBlockId([1; 32]));
}

#[test]
fn next_work_item_skips_cooldown_when_current_pool_signature_zero() {
    let db = Db::open_in_memory().unwrap();

    let a = make_block_with(1, SourceBlockStatus::Active, 0.9, 0, Some(10), 0.0, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.set_block_cooldown(&a.block_id, Some(Timestamp(1000)), 0xABCD);

    // 10s < 30s would be in cooldown, but current_pool_sig=0 bypasses it.
    let result = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), Timestamp(1010), 0)
        .unwrap();
    assert!(result.is_some(), "Cooldown skipped when current_pool_sig=0");
    assert_eq!(result.unwrap().block_id, SourceBlockId([1; 32]));
}

#[test]
fn next_work_item_excludes_blocks_with_target_reliability_zero() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(9999);

    let a = make_block_with(1, SourceBlockStatus::Active, 0.9, 0, Some(10), 0.0, 0.0);
    let b = make_block_with(2, SourceBlockStatus::Active, 0.5, 0, Some(10), 0.0, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.upsert_source_block(&b).unwrap();

    let result = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        result.block_id,
        SourceBlockId([2; 32]),
        "Block A excluded (target_reliability=0.0)"
    );
}

#[test]
fn next_work_item_excludes_blocks_at_or_above_target() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(9999);

    let a = make_block_with(1, SourceBlockStatus::Active, 0.8, 5, Some(10), 0.999, 0.999);
    let b = make_block_with(
        2,
        SourceBlockStatus::Active,
        0.8,
        5,
        Some(10),
        0.9999,
        0.999,
    );
    let c = make_block_with(3, SourceBlockStatus::Active, 0.8, 5, Some(10), 0.99, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.upsert_source_block(&b).unwrap();
    db.upsert_source_block(&c).unwrap();

    let result = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        result.block_id,
        SourceBlockId([3; 32]),
        "Only Block C is below target"
    );
}

#[test]
fn next_work_item_deterministic_for_given_state() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(9999);

    for seed in 0u8..5 {
        let b = make_block_with(
            seed,
            SourceBlockStatus::Active,
            0.3 + seed as f64 * 0.1,
            seed as u32,
            Some(10),
            0.0,
            0.999,
        );
        db.upsert_source_block(&b).unwrap();
    }

    let result1 = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0xABCD)
        .unwrap();
    let result2 = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0xABCD)
        .unwrap();
    assert_eq!(
        result1.map(|b| b.block_id),
        result2.map(|b| b.block_id),
        "Two calls with identical state return identical result"
    );
}

#[test]
fn next_work_item_does_not_mutate_block_records() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(9999);

    let block = make_block_with(1, SourceBlockStatus::Active, 0.8, 3, Some(10), 0.3, 0.999);
    db.upsert_source_block(&block).unwrap();
    db.set_block_cooldown(&block.block_id, Some(Timestamp(500)), 0xABCD);

    let before = db
        .get_source_block(&SourceBlockId([1; 32]))
        .unwrap()
        .unwrap();
    let cooldown_before = db.block_cooldown(&block.block_id);
    db.next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap();
    let after = db
        .get_source_block(&SourceBlockId([1; 32]))
        .unwrap()
        .unwrap();
    let cooldown_after = db.block_cooldown(&block.block_id);

    assert_eq!(
        cooldown_before.last_attempted_at, cooldown_after.last_attempted_at,
        "last_attempted_at unchanged"
    );
    assert_eq!(
        cooldown_before.last_pool_signature, cooldown_after.last_pool_signature,
        "last_pool_signature unchanged"
    );
    assert_eq!(
        before.current_alive, after.current_alive,
        "current_alive unchanged"
    );
    assert_eq!(
        before.current_reliability, after.current_reliability,
        "current_reliability unchanged"
    );
}

#[test]
fn next_work_item_handles_n_none_legacy_blocks() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(9999);

    // n=None → priority = importance = 0.7 (no completion bonus)
    let a = make_block_with(1, SourceBlockStatus::Active, 0.7, 0, None, 0.3, 0.999);
    db.upsert_source_block(&a).unwrap();

    let result = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap();
    assert!(result.is_some(), "Legacy block (n=None) is returned");

    // Add Block B with n=Some(10), current_alive=5: priority = 0.7 * 1.75 = 1.225 > 0.7
    let b = make_block_with(2, SourceBlockStatus::Active, 0.7, 5, Some(10), 0.3, 0.999);
    db.upsert_source_block(&b).unwrap();

    let result2 = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap()
        .unwrap();
    assert_eq!(
        result2.block_id,
        SourceBlockId([2; 32]),
        "Block B wins: completion bonus applies"
    );
}

#[test]
fn next_work_item_with_only_non_active_blocks_returns_none() {
    let db = Db::open_in_memory().unwrap();
    let now = Timestamp(9999);

    let a = make_block_with(1, SourceBlockStatus::Stale, 0.8, 0, Some(10), 0.0, 0.999);
    let b = make_block_with(2, SourceBlockStatus::Deleted, 0.8, 0, Some(10), 0.0, 0.999);
    db.upsert_source_block(&a).unwrap();
    db.upsert_source_block(&b).unwrap();

    let result = db
        .next_work_item(1.5, std::time::Duration::from_secs(30), now, 0)
        .unwrap();
    assert!(result.is_none(), "Non-Active blocks never returned");
}

// ============================================================
// T-4a: EWMA availability decay DB operations
// ============================================================

fn make_peer_with_avail(
    device_id: DeviceId,
    avail_ewma: f64,
    last_avail_sample: u64,
) -> PeerRecord {
    PeerRecord {
        device_id,
        master_identity: IdentityPub([0xAAu8; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(1000),
        last_seen: Timestamp(2000),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma,
        last_avail_sample,
    }
}

#[test]
fn startup_catchup_applies_missed_ticks_correctly() {
    use crate::constants::{AVAIL_DECAY_TICK_SECS, AVAIL_EWMA_ALPHA};

    let db = test_db();
    let tick_secs = AVAIL_DECAY_TICK_SECS;
    let now_secs = 7 * tick_secs + 1000; // 7 full ticks ago + offset
    let last_sample = 1000u64; // exactly 7 ticks before now_secs

    let peer = make_peer_with_avail(DeviceId([0x01u8; 32]), 1.0, last_sample);
    db.upsert_peer(&peer).unwrap();

    let updated = db
        .apply_avail_decay_startup_catchup(AVAIL_EWMA_ALPHA, now_secs, tick_secs)
        .unwrap();
    assert_eq!(updated, 1, "exactly one peer should be updated");

    let stored = db.get_peer(&DeviceId([0x01u8; 32])).unwrap().unwrap();
    let expected = 0.95_f64.powi(7); // (1-alpha)^7 * 1.0
    assert!(
        (stored.avail_ewma - expected).abs() < 1e-9,
        "7-tick decay from 1.0 should be ≈ {expected}; got {}",
        stored.avail_ewma
    );
    assert_eq!(
        stored.last_avail_sample, now_secs,
        "last_avail_sample must be set to now_secs"
    );
}

#[test]
fn no_double_decay_for_long_lived_connection() {
    use crate::constants::{AVAIL_DECAY_TICK_SECS, AVAIL_EWMA_ALPHA};

    let db = test_db();
    let tick_secs = AVAIL_DECAY_TICK_SECS;
    let now_secs = 1_700_000_000u64;
    // last_avail_sample = now - (tick_secs - 1): not yet eligible for decay
    let last_sample = now_secs - (tick_secs - 1);

    let peer = make_peer_with_avail(DeviceId([0x02u8; 32]), 0.8, last_sample);
    db.upsert_peer(&peer).unwrap();

    let updated = db
        .apply_avail_decay_batch(AVAIL_EWMA_ALPHA, now_secs, tick_secs)
        .unwrap();
    assert_eq!(
        updated, 0,
        "peer contacted < tick_secs ago must not be decayed"
    );

    let stored = db.get_peer(&DeviceId([0x02u8; 32])).unwrap().unwrap();
    assert!(
        (stored.avail_ewma - 0.8).abs() < 1e-12,
        "avail_ewma must remain 0.8 when decay not applied; got {}",
        stored.avail_ewma
    );
}

#[test]
fn decay_applies_exactly_one_tick_after_tick_interval() {
    use crate::constants::{AVAIL_DECAY_TICK_SECS, AVAIL_EWMA_ALPHA};

    let db = test_db();
    let tick_secs = AVAIL_DECAY_TICK_SECS;
    let now_secs = 1_700_000_000u64;
    // last_avail_sample = now - tick_secs - 1: eligible for exactly 1 tick
    let last_sample = now_secs - tick_secs - 1;

    let peer = make_peer_with_avail(DeviceId([0x03u8; 32]), 0.8, last_sample);
    db.upsert_peer(&peer).unwrap();

    let updated = db
        .apply_avail_decay_batch(AVAIL_EWMA_ALPHA, now_secs, tick_secs)
        .unwrap();
    assert_eq!(updated, 1, "peer with elapsed >= tick_secs must be decayed");

    let stored = db.get_peer(&DeviceId([0x03u8; 32])).unwrap().unwrap();
    let expected = 0.95 * 0.8; // exactly 1 tick
    assert!(
        (stored.avail_ewma - expected).abs() < 1e-12,
        "exactly 1 tick decay: expected {expected}, got {}",
        stored.avail_ewma
    );
    assert_eq!(
        stored.last_avail_sample, now_secs,
        "last_avail_sample must be updated to now_secs"
    );
}
