// L0 К2b (delete-i12, dr-i64): deletions by live event, by recheck, and the watch root
// rule. Real redb (in memory), real files in a TempDir, real pipeline.

use tempfile::TempDir;
use viaticum_core::constants::OWNER_DELETE_COOLDOWN_SECS;
use viaticum_core::db::Db;
use viaticum_core::types::{
    DeviceId, LocalState, PlacementStatus, SourceBlockId, SourceBlockStatus, SymbolPlacement,
    Timestamp,
};

use super::tests_current::{DEV, backed_up, content, coord, event, queued_paths, record, write};
use super::{BackupCoordinator, DirtyKind};

fn state(db: &Db, path: &str) -> LocalState {
    record(db, path).devices[0].1
}

fn is_deleted(db: &Db, path: &str) -> bool {
    matches!(state(db, path), LocalState::Deleted(_))
}

fn set_state(db: &Db, path: &str, s: LocalState) {
    let mut r = record(db, path);
    r.devices = vec![(DEV, s)];
    db.upsert_file(&r).unwrap();
}

/// Backed-up file `name` under `dir`; returns its path and block.
fn file(
    c: &mut BackupCoordinator,
    db: &Db,
    dir: &TempDir,
    name: &str,
    seed: u8,
) -> (String, SourceBlockId) {
    let p = write(dir, name, &content(seed, 4096));
    let x = backed_up(c, db, &p, DirtyKind::Added);
    (p, x)
}

fn placement(block: SourceBlockId, status: PlacementStatus) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: block,
        holder_id: DeviceId([99u8; 32]),
        file_id: viaticum_core::types::FileId(1),
        esi_ranges: vec![(0, 3)],
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    }
}

// ─── Live deletion ─────────────────────────────────────────────────────────────

/// A deletion of a path the catalog never knew leaves no record (no tombstone).
#[test]
fn deleted_event_for_unknown_path_creates_no_record() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let p = dir.path().join("never.bin").to_string_lossy().into_owned();

    c.process_event(event(&p, DirtyKind::Deleted)).unwrap();

    assert!(db.get_file(&p).unwrap().is_none());
    assert!(db.list_all_files().unwrap().is_empty());
}

/// A file deleted before it was ever backed up (an atomic-save tmp, a `.part`): its
/// record and its queue entry are gone, nothing of it is in the network.
#[test]
fn deleted_event_for_never_backed_up_record_removes_record_and_queue_entry() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let p = write(&dir, "tmp.part", &content(40, 4096));
    c.process_event(event(&p, DirtyKind::Added)).unwrap();
    assert_eq!(queued_paths(&c).len(), 1, "setup: queued");

    std::fs::remove_file(&p).unwrap();
    c.process_event(event(&p, DirtyKind::Deleted)).unwrap();

    assert!(db.get_file(&p).unwrap().is_none());
    assert!(queued_paths(&c).is_empty());
}

/// A second deletion event does not move the window (delete-i12).
#[test]
fn deleted_event_twice_keeps_first_timestamp() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let (p, _) = file(&mut c, &db, &dir, "t.bin", 41);
    std::fs::remove_file(&p).unwrap();
    c.process_event(event(&p, DirtyKind::Deleted)).unwrap();
    assert!(is_deleted(&db, &p));
    set_state(&db, &p, LocalState::Deleted(Timestamp(5)));

    c.process_event(event(&p, DirtyKind::Deleted)).unwrap();

    assert_eq!(state(&db, &p), LocalState::Deleted(Timestamp(5)));
}

/// A directory reported gone: only the records under it whose path is gone are marked.
#[test]
fn deleted_event_for_directory_marks_only_gone_descendants() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("d")).unwrap();
    let mut c = coord(&db);
    let (x, _) = file(&mut c, &db, &dir, "d/x.bin", 42);
    let (y, _) = file(&mut c, &db, &dir, "d/y.bin", 43);
    std::fs::remove_file(&x).unwrap();
    let d = dir.path().join("d").to_string_lossy().into_owned();

    c.process_event(event(&d, DirtyKind::Deleted)).unwrap();

    assert!(is_deleted(&db, &x));
    assert_eq!(state(&db, &y), LocalState::Present);
}

/// `d` gone does not touch `d2/…`: the prefix ends at a separator.
#[test]
fn deleted_event_directory_prefix_stops_at_separator_boundary() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("d")).unwrap();
    std::fs::create_dir(dir.path().join("d2")).unwrap();
    let mut c = coord(&db);
    let (x, _) = file(&mut c, &db, &dir, "d/x.bin", 44);
    let (y, _) = file(&mut c, &db, &dir, "d2/y.bin", 45);
    std::fs::remove_file(&x).unwrap();
    std::fs::remove_file(&y).unwrap();
    let d = dir.path().join("d").to_string_lossy().into_owned();

    c.process_event(event(&d, DirtyKind::Deleted)).unwrap();

    assert!(is_deleted(&db, &x));
    assert_eq!(state(&db, &y), LocalState::Present, "d2/ is not under d/");
}

// ─── Recheck ───────────────────────────────────────────────────────────────────

/// A recheck deletes only a record this device saw on disk (INV-CONF): after DR or a
/// root change it is unconfirmed and stays (dr-i64). Control: the confirmed one goes.
#[test]
fn recheck_deletion_ignores_unconfirmed_record() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let mut c = coord(&db);
    let (u, _) = file(&mut c, &db, &dir, "u.bin", 46);
    let (k, _) = file(&mut c, &db, &dir, "k.bin", 47);
    let mut ru = record(&db, &u);
    ru.on_disk_confirmed = false;
    db.upsert_file(&ru).unwrap();
    std::fs::remove_file(&u).unwrap();
    std::fs::remove_file(&k).unwrap();

    c.process_event(event(&u, DirtyKind::GoneOnRecheck))
        .unwrap();
    c.process_event(event(&k, DirtyKind::GoneOnRecheck))
        .unwrap();

    assert_eq!(state(&db, &u), LocalState::Present, "unconfirmed: kept");
    assert!(is_deleted(&db, &k), "confirmed: deleted");
}

// ─── The root rule ─────────────────────────────────────────────────────────────

/// Root lost: a recent deletion under it (no Delete out) is undone, every record under
/// it loses the confirmation (guard of M13).
#[test]
fn root_lost_undoes_recent_deletions_under_root_and_unconfirms() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("photos")).unwrap();
    let mut c = coord(&db);
    let (a, _) = file(&mut c, &db, &dir, "photos/a.bin", 48);
    let (b, _) = file(&mut c, &db, &dir, "photos/b.bin", 49);
    std::fs::remove_file(&a).unwrap();
    c.process_event(event(&a, DirtyKind::Deleted)).unwrap();
    assert!(is_deleted(&db, &a), "setup: first file deleted");
    let root = dir.path().join("photos").to_string_lossy().into_owned();

    c.process_event(event(&root, DirtyKind::RootLost)).unwrap();

    assert_eq!(state(&db, &a), LocalState::Present, "deletion undone");
    assert!(!record(&db, &a).on_disk_confirmed);
    assert!(!record(&db, &b).on_disk_confirmed);
    assert_eq!(state(&db, &b), LocalState::Present);
}

/// A deletion whose Delete already went out (a placement in `Deleting`) stays.
#[test]
fn root_lost_keeps_deletion_whose_delete_was_published() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("photos")).unwrap();
    let mut c = coord(&db);
    let (a, x) = file(&mut c, &db, &dir, "photos/a.bin", 50);
    std::fs::remove_file(&a).unwrap();
    c.process_event(event(&a, DirtyKind::Deleted)).unwrap();
    db.upsert_placement(&placement(x, PlacementStatus::Deleting))
        .unwrap();
    let root = dir.path().join("photos").to_string_lossy().into_owned();

    c.process_event(event(&root, DirtyKind::RootLost)).unwrap();

    assert!(is_deleted(&db, &a));
}

/// P-C2: the block is `Deleting` with no acknowledged placement yet (status written
/// before the Delete is published): the deletion stays. A check by placements alone
/// would undo it under a live record and the holders would erase the data.
#[test]
fn root_lost_does_not_undo_deletion_of_block_in_deleting_status_without_acks() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("photos")).unwrap();
    let mut c = coord(&db);
    let (a, x) = file(&mut c, &db, &dir, "photos/a.bin", 51);
    std::fs::remove_file(&a).unwrap();
    c.process_event(event(&a, DirtyKind::Deleted)).unwrap();
    let mut sb = db.get_source_block(&x).unwrap().unwrap();
    sb.status = SourceBlockStatus::Deleting;
    db.upsert_source_block(&sb).unwrap();
    db.upsert_placement(&placement(x, PlacementStatus::Alive))
        .unwrap();
    let root = dir.path().join("photos").to_string_lossy().into_owned();

    c.process_event(event(&root, DirtyKind::RootLost)).unwrap();

    assert!(is_deleted(&db, &a));
}

/// A deletion older than the owner window is not undone.
#[test]
fn root_lost_keeps_deletions_older_than_owner_window() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("photos")).unwrap();
    let mut c = coord(&db);
    let (a, _) = file(&mut c, &db, &dir, "photos/a.bin", 52);
    std::fs::remove_file(&a).unwrap();
    let old = Timestamp::now().0 - OWNER_DELETE_COOLDOWN_SECS - 100;
    set_state(&db, &a, LocalState::Deleted(Timestamp(old)));
    let root = dir.path().join("photos").to_string_lossy().into_owned();

    c.process_event(event(&root, DirtyKind::RootLost)).unwrap();

    assert_eq!(state(&db, &a), LocalState::Deleted(Timestamp(old)));
}

/// Records of a sibling folder sharing the root's name as a prefix are not touched.
#[test]
fn root_lost_does_not_touch_records_outside_root() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("photos")).unwrap();
    std::fs::create_dir(dir.path().join("photos2")).unwrap();
    let mut c = coord(&db);
    let (a, _) = file(&mut c, &db, &dir, "photos2/a.bin", 53);
    let (k, _) = file(&mut c, &db, &dir, "photos2/k.bin", 54);
    std::fs::remove_file(&a).unwrap();
    c.process_event(event(&a, DirtyKind::Deleted)).unwrap();
    let root = dir.path().join("photos").to_string_lossy().into_owned();

    c.process_event(event(&root, DirtyKind::RootLost)).unwrap();

    assert!(is_deleted(&db, &a));
    assert!(record(&db, &k).on_disk_confirmed);
}

/// BLOCK-1 (L0 review): c was edited (current version on Y), its old pack X was cleaned
/// up after its other members were deleted. Moving the root away file by file must still
/// undo c's early deletion — only the blocks reviving c makes live (Y) decide, not X.
#[test]
fn root_lost_undoes_deletion_whose_old_version_block_is_cleaned_up() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    std::fs::create_dir(dir.path().join("photos")).unwrap();
    let mut c = coord(&db);
    let (p, x) = file(&mut c, &db, &dir, "photos/c.bin", 55);
    write(&dir, "photos/c.bin", &content(56, 4096));
    let y = backed_up(&mut c, &db, &p, DirtyKind::Modified);
    assert_ne!(x, y, "setup: the edit is on its own block");
    db.delete_source_block(&x).unwrap();
    std::fs::remove_file(&p).unwrap();
    c.process_event(event(&p, DirtyKind::Deleted)).unwrap();
    assert!(is_deleted(&db, &p), "setup: c deleted before the root went");
    let root = dir.path().join("photos").to_string_lossy().into_owned();

    c.process_event(event(&root, DirtyKind::RootLost)).unwrap();

    assert_eq!(state(&db, &p), LocalState::Present, "deletion undone");
}
