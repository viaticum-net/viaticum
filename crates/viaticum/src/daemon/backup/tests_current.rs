// L1 (backup-i9, backup-i23): a path points at what is on disk now, and one vanished
// or changed file does not stop the backup of the others.
//
// Real redb (in memory), real files in a TempDir, real pipeline (mock holders only
// feed the N solver). Spec: private/beta-planning/tasks/c_l0_l1_watcher_rollback.md §2.1.

use std::collections::BTreeSet;
use std::sync::Arc;

use tempfile::TempDir;
use viaticum_core::db::Db;
use viaticum_core::erasure::RaptorQEncoder;
use viaticum_core::types::{
    DeviceId, FileCategory, FileId, FileRecord, FileVersion, LocalState, SourceBlockId, Timestamp,
};

use super::events::{DedupLookup, select_dedup_source};
use super::pipeline::update_backed_up_at;
use super::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind, QueuedFile};

pub(super) const BLOCK: u64 = 128 * 1024;
pub(super) const DEV: DeviceId = DeviceId([1u8; 32]);
const SENTINEL: SourceBlockId = SourceBlockId([0u8; 32]);

pub(super) fn coord(db: &Db) -> BackupCoordinator {
    let config = BackupConfig {
        source_block_size: BLOCK,
        epoch_key: [42u8; 32],
        device_id: DEV,
        mock_holders: (0..5)
            .map(|i| viaticum_core::placement::HolderCandidate {
                device_id: DeviceId([(i + 10) as u8; 32]),
                trust: 0.5,
            })
            .collect(),
        mock_offer_budget_gb: Some(1000.0),
        ..Default::default()
    };
    BackupCoordinator::new(db.clone(), config, Arc::new(RaptorQEncoder::new()))
}

pub(super) fn write(dir: &TempDir, name: &str, content: &[u8]) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, content).unwrap();
    path.to_string_lossy().into_owned()
}

pub(super) fn event(path: &str, kind: DirtyKind) -> DirtyEvent {
    DirtyEvent {
        path: path.to_string(),
        kind,
        device_id: DEV,
    }
}

pub(super) fn hash(content: &[u8]) -> [u8; 32] {
    *blake3::hash(content).as_bytes()
}

/// Distinct incompressible-enough content of `len` bytes.
pub(super) fn content(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[i % 4] ^ seed)
        .collect()
}

pub(super) fn record(db: &Db, path: &str) -> FileRecord {
    db.get_file(path).unwrap().expect("record must exist")
}

pub(super) fn last(db: &Db, path: &str) -> FileVersion {
    record(db, path)
        .versions
        .last()
        .cloned()
        .expect("a version")
}

pub(super) fn queued_paths(c: &BackupCoordinator) -> BTreeSet<String> {
    c.queues
        .values()
        .flatten()
        .map(|qf| qf.path.clone())
        .collect()
}

pub(super) fn flush(c: &mut BackupCoordinator) -> usize {
    c.flush_all(true, &Default::default()).unwrap().len()
}

/// `path` created with `bytes` and backed up; returns its block.
pub(super) fn backed_up(
    c: &mut BackupCoordinator,
    db: &Db,
    path: &str,
    kind: DirtyKind,
) -> SourceBlockId {
    c.process_event(event(path, kind)).unwrap();
    assert_eq!(flush(c), 1, "setup: one block for {path}");
    let v = last(db, path);
    assert!(v.backed_up_at.is_some(), "setup: {path} backed up");
    v.source_block_id
}

/// An `Active` record for a synthetic block `id` with no placement: a block in service,
/// so a version on it is a dedup source (L1b gate, backup-i21).
pub(super) fn active_block(db: &Db, id: SourceBlockId) {
    db.upsert_source_block(&viaticum_core::types::SourceBlockRecord {
        seal_generation: 0,
        block_id: id,
        k: 3,
        t: 1024,
        block_type: viaticum_core::types::SourceBlockType::Single,
        status: viaticum_core::types::SourceBlockStatus::Active,
        created_at: Timestamp(100),
        encrypted_size: Some(3072),
        n: Some(6),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 0.5,
        current_alive: 0,
        current_reliability: 0.0,
        target_reliability: 0.9,
    })
    .unwrap();
}

fn backed_version(h: [u8; 32], block: SourceBlockId, at: u64) -> FileVersion {
    FileVersion {
        content_hash: h,
        source_block_id: block,
        k: 3,
        t: 1024,
        created_at: Timestamp(at),
        backed_up_at: Some(Timestamp(at)),
    }
}

// ─── К1: dedup by the same path (backup-i9) ─────────────────────────────────

/// A → B → A (undo, `git checkout`): the path's current version is A on A's block
/// again, so restore returns A and not the undone edit.
#[test]
fn dedup_same_path_rollback_appends_current_version() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let (a, b) = (content(1, 4096), content(2, 4096));

    let p = write(&dir, "v.bin", &a);
    let xa = backed_up(&mut c, &db, &p, DirtyKind::Added);
    write(&dir, "v.bin", &b);
    let xb = backed_up(&mut c, &db, &p, DirtyKind::Modified);
    assert_ne!(xa, xb);

    write(&dir, "v.bin", &a);
    c.process_event(event(&p, DirtyKind::Modified)).unwrap();

    let rec = record(&db, &p);
    assert_eq!(rec.versions.len(), 3, "A, B, then A again");
    let cur = rec.versions.last().unwrap();
    assert_eq!(cur.content_hash, hash(&a));
    assert_eq!(
        cur.source_block_id, xa,
        "current version points at A's block"
    );
    assert!(cur.backed_up_at.is_some());
    assert_eq!(
        cur.backed_up_at,
        Some(cur.created_at),
        "backed_up_at = the moment the path started pointing at the block"
    );
    assert!(queued_paths(&c).is_empty(), "no traffic: nothing queued");
    assert_eq!(flush(&mut c), 0, "no new block");
}

/// A touch or a rescan of unchanged content adds no version and writes nothing new.
#[test]
fn dedup_same_path_unchanged_content_does_not_append_version() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let a = content(3, 4096);
    let p = write(&dir, "u.bin", &a);
    let xa = backed_up(&mut c, &db, &p, DirtyKind::Added);

    c.process_event(event(&p, DirtyKind::Modified)).unwrap();
    c.process_event(event(&p, DirtyKind::Added)).unwrap();

    let rec = record(&db, &p);
    assert_eq!(rec.versions.len(), 1);
    assert_eq!(rec.versions[0].source_block_id, xa);
    assert!(queued_paths(&c).is_empty());
}

/// Rollback while the edit is still queued: the pending edit is dropped and the path
/// keeps pointing at A — no second A version, no block for the undone edit.
#[test]
fn dedup_same_path_after_supersede_does_not_duplicate_version() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let (a, b) = (content(4, 4096), content(5, 4096));
    let p = write(&dir, "s.bin", &a);
    let xa = backed_up(&mut c, &db, &p, DirtyKind::Added);

    write(&dir, "s.bin", &b);
    c.process_event(event(&p, DirtyKind::Modified)).unwrap();
    assert_eq!(queued_paths(&c).len(), 1, "setup: edit B queued");

    write(&dir, "s.bin", &a);
    c.process_event(event(&p, DirtyKind::Modified)).unwrap();

    let rec = record(&db, &p);
    assert_eq!(rec.versions.len(), 1, "pending B dropped, A not duplicated");
    assert_eq!(rec.versions[0].source_block_id, xa);
    assert!(queued_paths(&c).is_empty(), "queue entry of B dropped");
    assert_eq!(flush(&mut c), 0, "no block for the undone edit");
}

/// A deleted file put back with the same content (restore in place): Present again.
#[test]
fn dedup_same_path_sets_present_after_deleted() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let a = content(6, 4096);
    let p = write(&dir, "d.bin", &a);
    let xa = backed_up(&mut c, &db, &p, DirtyKind::Added);
    std::fs::remove_file(&p).unwrap();
    c.process_event(event(&p, DirtyKind::Deleted)).unwrap();
    assert!(matches!(
        record(&db, &p).devices[0].1,
        LocalState::Deleted(_)
    ));

    write(&dir, "d.bin", &a);
    c.process_event(event(&p, DirtyKind::Added)).unwrap();

    let rec = record(&db, &p);
    assert_eq!(rec.devices, vec![(DEV, LocalState::Present)]);
    assert!(rec.on_disk_confirmed);
    assert_eq!(rec.versions.len(), 1);
    assert_eq!(rec.versions[0].source_block_id, xa);
}

/// Another file's content copied onto a deleted path: Present, pointing at that
/// content's block (was: the record stayed Deleted and got no version).
#[test]
fn dedup_added_over_deleted_record_of_other_content_sets_present_and_appends() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let (a, b) = (content(7, 4096), content(8, 4096));
    let q = write(&dir, "q.bin", &a);
    let xa = backed_up(&mut c, &db, &q, DirtyKind::Added);
    let p = write(&dir, "p.bin", &b);
    let xb = backed_up(&mut c, &db, &p, DirtyKind::Added);
    std::fs::remove_file(&p).unwrap();
    c.process_event(event(&p, DirtyKind::Deleted)).unwrap();

    write(&dir, "p.bin", &a);
    c.process_event(event(&p, DirtyKind::Added)).unwrap();

    let rec = record(&db, &p);
    assert_eq!(rec.devices, vec![(DEV, LocalState::Present)]);
    assert_eq!(rec.versions.len(), 2);
    assert_eq!(rec.versions[0].source_block_id, xb);
    let cur = rec.versions.last().unwrap();
    assert_eq!(cur.content_hash, hash(&a));
    assert_eq!(cur.source_block_id, xa);
    assert!(cur.backed_up_at.is_some());
    assert!(queued_paths(&c).is_empty());
}

/// Content that is only queued elsewhere has no block yet: the copy is queued too,
/// never pointed at the sentinel block.
#[test]
fn dedup_source_is_a_backed_up_version_not_a_pending_one() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let a = content(9, 4096);
    let q = write(&dir, "q.bin", &a);
    c.process_event(event(&q, DirtyKind::Added)).unwrap();
    assert!(matches!(
        select_dedup_source(&db, &hash(&a), None).unwrap(),
        DedupLookup::NotFound
    ));

    let p = write(&dir, "p.bin", &a);
    c.process_event(event(&p, DirtyKind::Added)).unwrap();

    assert!(
        last(&db, &p).backed_up_at.is_none(),
        "p is pending, not deduped"
    );
    assert_eq!(queued_paths(&c), BTreeSet::from([p.clone(), q.clone()]));
    assert_eq!(flush(&mut c), 1);
    for path in [&p, &q] {
        let v = last(&db, path);
        assert!(v.backed_up_at.is_some(), "{path} backed up");
        assert_ne!(v.source_block_id, SENTINEL, "{path} on a real block");
    }
}

/// A path that already points at content A on its own block keeps that block on a
/// rescan, even when A is also backed up on another block under a path that sorts
/// first (a touch adds no version).
#[test]
fn dedup_rescan_keeps_own_block_when_same_content_is_on_another_block() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let a = content(10, 4096);
    let p = write(&dir, "p.bin", &a);
    let (x1, x2) = (SourceBlockId([0x11; 32]), SourceBlockId([0x22; 32]));
    active_block(&db, x1);
    active_block(&db, x2);
    for (id, path, block) in [(1, "/aaa/q.bin".to_string(), x1), (2, p.clone(), x2)] {
        db.upsert_file(&FileRecord {
            file_id: FileId(id),
            path,
            importance: 0.5,
            devices: vec![(DEV, LocalState::Present)],
            versions: vec![backed_version(hash(&a), block, 100)],
            first_seen: Timestamp(100),
            on_disk_confirmed: true,
        })
        .unwrap();
    }
    let mut c = coord(&db);

    c.process_event(event(&p, DirtyKind::Added)).unwrap();

    let rec = record(&db, &p);
    assert_eq!(rec.versions.len(), 1, "no version appended by a rescan");
    assert_eq!(rec.versions[0].source_block_id, x2);
}

// ─── К1: confirmation and pending versions ──────────────────────────────────

/// An event that found the file on disk confirms the record: a new file, a queued
/// one, and a restored (DR, unconfirmed) record whose content is already backed up.
#[test]
fn event_for_existing_file_sets_on_disk_confirmed() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let a = content(11, 4096);
    let p = write(&dir, "restored.bin", &a);
    let x = SourceBlockId([0x33; 32]);
    active_block(&db, x);
    db.upsert_file(&FileRecord {
        file_id: FileId(1),
        path: p.clone(),
        importance: 0.5,
        devices: vec![(DEV, LocalState::Present)],
        versions: vec![backed_version(hash(&a), x, 100)],
        first_seen: Timestamp(100),
        on_disk_confirmed: false,
    })
    .unwrap();
    let mut c = coord(&db);
    let n = write(&dir, "new.bin", &content(12, 4096));

    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    c.process_event(event(&n, DirtyKind::Added)).unwrap();

    let rec = record(&db, &p);
    assert!(
        rec.on_disk_confirmed,
        "restored record confirmed by the scan"
    );
    assert_eq!(rec.versions.len(), 1, "confirmation alone adds no version");
    assert!(
        record(&db, &n).on_disk_confirmed,
        "queued new file confirmed"
    );
}

/// ≤ 1 pending version per path, and it is the last one: a second edit before the
/// flush replaces the first one in the catalog and in the queue.
#[test]
fn enqueue_supersedes_older_pending_version_and_queue_entry() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let (a, b, cc) = (content(13, 4096), content(14, 4096), content(15, 4096));
    let p = write(&dir, "e.bin", &a);
    let xa = backed_up(&mut c, &db, &p, DirtyKind::Added);

    write(&dir, "e.bin", &b);
    c.process_event(event(&p, DirtyKind::Modified)).unwrap();
    write(&dir, "e.bin", &cc);
    c.process_event(event(&p, DirtyKind::Modified)).unwrap();

    let rec = record(&db, &p);
    assert_eq!(rec.versions.len(), 2, "A backed up + one pending");
    assert_eq!(rec.versions[0].source_block_id, xa);
    assert_eq!(rec.versions[1].content_hash, hash(&cc));
    assert!(rec.versions[1].backed_up_at.is_none());
    let queued: Vec<&QueuedFile> = c.queues.values().flatten().collect();
    assert_eq!(queued.len(), 1, "one queue entry per path");
    assert_eq!(queued[0].content_hash, hash(&cc));
}

/// The pack marks the last (pending) version, never an older backed-up version that
/// happens to have the same hash; the packed hash is the one of the bytes read.
#[test]
fn update_backed_up_at_marks_last_pending_version_not_older_same_hash() {
    let db = Db::open_in_memory().unwrap();
    let a = [0xAA; 32];
    let x_old = SourceBlockId([0x44; 32]);
    let x_new = SourceBlockId([0x55; 32]);
    db.upsert_file(&FileRecord {
        file_id: FileId(1),
        path: "/w/p.bin".into(),
        importance: 0.5,
        devices: vec![(DEV, LocalState::Present)],
        versions: vec![
            backed_version(a, x_old, 100),
            FileVersion {
                content_hash: a,
                source_block_id: SENTINEL,
                k: 0,
                t: 0,
                created_at: Timestamp(200),
                backed_up_at: None,
            },
        ],
        first_seen: Timestamp(100),
        on_disk_confirmed: true,
    })
    .unwrap();
    let qf = QueuedFile {
        path: "/w/p.bin".into(),
        file_id: FileId(1),
        content_hash: a,
        size_bytes: 4,
        category: FileCategory::Other,
        importance: 0.5,
    };

    update_backed_up_at(&db, &[(qf, vec![0; 4])], x_new, 7, 1024);

    let rec = record(&db, "/w/p.bin");
    assert_eq!(
        rec.versions[0].source_block_id, x_old,
        "older version untouched"
    );
    assert_eq!(rec.versions[0].backed_up_at, Some(Timestamp(100)));
    assert_eq!(rec.versions[1].source_block_id, x_new);
    assert_eq!(rec.versions[1].k, 7);
    assert!(rec.versions[1].backed_up_at.is_some());
}

// ─── К2a: packing does not abort (backup-i23) ───────────────────────────────

/// q1 vanished between enqueue and flush: q2 and q3 are packed in the same pass.
#[test]
fn flush_skips_vanished_file_and_backs_up_the_rest() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let paths: Vec<String> = (1..=3)
        .map(|i| write(&dir, &format!("q{i}.bin"), &content(20 + i, 4096)))
        .collect();
    for p in &paths {
        c.process_event(event(p, DirtyKind::Added)).unwrap();
    }
    std::fs::remove_file(&paths[0]).unwrap();

    let blocks = c.flush_all(true, &Default::default()).unwrap();

    assert_eq!(blocks.len(), 1);
    assert!(
        last(&db, &paths[0]).backed_up_at.is_none(),
        "q1 not backed up"
    );
    for p in &paths[1..] {
        let v = last(&db, p);
        assert!(v.backed_up_at.is_some(), "{p} backed up");
        assert_eq!(v.source_block_id, blocks[0].source_block_id);
    }
    assert!(queued_paths(&c).is_empty());
}

/// Changed between enqueue and flush to content not in the network: the bytes read are
/// packed, and the version carries their hash (not the hash at enqueue).
#[test]
fn flush_packs_file_changed_since_enqueue_with_its_real_hash() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let (a, b) = (content(30, 4096), content(31, 4096));
    let p = write(&dir, "ch.bin", &a);
    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    write(&dir, "ch.bin", &b);

    assert_eq!(flush(&mut c), 1);

    let rec = record(&db, &p);
    assert_eq!(rec.versions.len(), 1);
    assert_eq!(
        rec.versions[0].content_hash,
        hash(&b),
        "hash of the packed bytes"
    );
    assert!(rec.versions[0].backed_up_at.is_some());
}

/// Changed back to content already in the network: skipped at flush (no block); the
/// event that follows points the path there without traffic.
#[test]
fn flush_skips_file_changed_back_to_content_already_in_network() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let (a, b) = (content(32, 4096), content(33, 4096));
    let p = write(&dir, "back.bin", &a);
    let xa = backed_up(&mut c, &db, &p, DirtyKind::Added);
    write(&dir, "back.bin", &b);
    c.process_event(event(&p, DirtyKind::Modified)).unwrap();
    write(&dir, "back.bin", &a);

    assert_eq!(
        flush(&mut c),
        0,
        "no block for content already in the network"
    );
    assert!(
        last(&db, &p).backed_up_at.is_none(),
        "pending B not marked backed up"
    );

    c.process_event(event(&p, DirtyKind::Modified)).unwrap();
    let rec = record(&db, &p);
    assert_eq!(rec.versions.len(), 1, "pending B dropped by the event");
    assert_eq!(rec.versions[0].source_block_id, xa);
}

/// A DB error before any block record is committed (here: candidate selection): the
/// files go back to the queue and are packed once the error is gone.
#[test]
fn flush_error_before_block_commit_requeues_the_files() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    // Candidates from the DB (not the mock list), so a bad peer row fails the flush.
    c.config.mock_holders.clear();
    let paths: Vec<String> = (1..=3)
        .map(|i| write(&dir, &format!("r{i}.bin"), &content(40 + i, 4096)))
        .collect();
    for p in &paths {
        c.process_event(event(p, DirtyKind::Added)).unwrap();
    }
    let bad_peer = DeviceId([0x77; 32]);
    db.corrupt_peer_row_for_test(&bad_peer).unwrap();

    let res = c.flush_queue(FileCategory::Document, true, &Default::default());

    assert!(res.is_err(), "the DB error is reported");
    assert!(
        db.list_all_source_blocks().unwrap().is_empty(),
        "no block was committed"
    );
    assert_eq!(
        queued_paths(&c),
        paths.iter().cloned().collect::<BTreeSet<_>>(),
        "every file of the failed pass is queued again"
    );
    assert!(
        paths.iter().all(|p| last(&db, p).backed_up_at.is_none()),
        "nothing marked"
    );
}

/// A record that cannot be updated after its block was committed: the others of the
/// batch are marked, nothing is requeued, and the next flush builds no block again
/// (was: requeue → the same batch packed and committed on every idle tick).
#[test]
fn flush_bad_record_after_block_commit_marks_the_others_and_is_not_repacked() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let paths: Vec<String> = (1..=3)
        .map(|i| write(&dir, &format!("m{i}.bin"), &content(45 + i, 4096)))
        .collect();
    for p in &paths {
        c.process_event(event(p, DirtyKind::Added)).unwrap();
    }
    db.corrupt_file_row_for_test(&paths[1]).unwrap();

    let blocks = c
        .flush_queue(FileCategory::Document, true, &Default::default())
        .expect("a bad row after the commit is not a flush error");

    assert_eq!(blocks.len(), 1);
    for p in [&paths[0], &paths[2]] {
        let v = last(&db, p);
        assert!(v.backed_up_at.is_some(), "{p} marked");
        assert_eq!(v.source_block_id, blocks[0].source_block_id);
    }
    assert!(
        db.get_file(&paths[1]).is_err(),
        "the bad row is left as it was (its file stays pending)"
    );
    assert!(queued_paths(&c).is_empty(), "nothing requeued");
    assert_eq!(flush(&mut c), 0, "the next flush builds no block again");
    assert_eq!(db.list_all_source_blocks().unwrap().len(), 1);
}

/// A flush error leaves every category's files queued, and `flush_all` reports it.
/// (The error sources left before a block commit — candidate selection, the block
/// write — are DB-wide, so every category meets the same error.)
#[test]
fn flush_all_error_keeps_every_category_queued() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    c.config.mock_holders.clear();
    let photo = write(&dir, "a.jpg", &content(50, 4096));
    let doc = write(&dir, "b.txt", &content(51, 4096));
    c.process_event(event(&photo, DirtyKind::Added)).unwrap();
    c.process_event(event(&doc, DirtyKind::Added)).unwrap();
    db.corrupt_peer_row_for_test(&DeviceId([0x77; 32])).unwrap();

    let res = c.flush_all(true, &Default::default());

    assert!(res.is_err(), "the error is returned");
    assert_eq!(queued_paths(&c), BTreeSet::from([photo, doc]));
}

/// An rm'd queued file: its pending version and queue entry go with it (no Deleted
/// record with a pending last version, nothing packed for it).
#[test]
fn deleted_event_drops_pending_version_and_queue_entry() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let (a, b) = (content(70, 4096), content(71, 4096));
    let p = write(&dir, "gone.bin", &a);
    let xa = backed_up(&mut c, &db, &p, DirtyKind::Added);
    write(&dir, "gone.bin", &b);
    c.process_event(event(&p, DirtyKind::Modified)).unwrap();
    assert_eq!(queued_paths(&c).len(), 1, "setup: edit B queued");

    std::fs::remove_file(&p).unwrap();
    c.process_event(event(&p, DirtyKind::Deleted)).unwrap();

    let rec = record(&db, &p);
    assert!(matches!(rec.devices[0].1, LocalState::Deleted(_)));
    assert_eq!(rec.versions.len(), 1, "pending B dropped");
    assert_eq!(rec.versions[0].source_block_id, xa);
    assert!(queued_paths(&c).is_empty(), "queue entry dropped");
}

/// Large file: the second read (at packing) sees other bytes than the first — the
/// version records the hash of what went into the block; a vanished one is skipped.
#[test]
fn large_file_changed_between_reads_is_recorded_with_real_hash() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let (l1, l2) = (
        content(60, BLOCK as usize + 1024),
        content(61, BLOCK as usize + 1024),
    );
    let p = write(&dir, "big.bin", &l1);
    let file_id = c.get_or_create_file_id(&p, &DEV, hash(&l1)).unwrap();
    write(&dir, "big.bin", &l2);

    let result = c
        .process_large_file(&p, file_id, hash(&l1), 0.5, &[])
        .unwrap()
        .expect("changed large file is packed");

    let v = last(&db, &p);
    assert_eq!(v.content_hash, hash(&l2), "hash of the packed bytes");
    assert_eq!(v.source_block_id, result.source_block_id);
    assert!(v.backed_up_at.is_some());

    let gone = write(&dir, "gone.bin", &l1);
    let gone_id = c.get_or_create_file_id(&gone, &DEV, hash(&l1)).unwrap();
    std::fs::remove_file(&gone).unwrap();
    assert!(
        c.process_large_file(&gone, gone_id, hash(&l1), 0.5, &[])
            .unwrap()
            .is_none(),
        "vanished large file skipped"
    );
}
