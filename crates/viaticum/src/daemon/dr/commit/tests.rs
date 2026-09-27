// Tests for the DR commit (renames, .dr-bak, rollback) and abort. Real files, a real
// staging redb `Db` built through the same path `run_dr` uses.

use std::collections::BTreeMap;
use std::path::Path;

use super::{
    DbInstallError, FAULT_CRASH_AFTER_STEP_2, FAULT_FAIL_STEP_3_AND_MOVE_BACK,
    FAULT_FORCE_TWO_RENAMES, KeyInstallError, abort, commit, install_by_two_renames, install_db,
    install_new_key, next_backup_path, set_faults, two_rename_stuck_text,
};
use crate::daemon::dr::DrError;
use crate::daemon::dr::preflight::{DrPaths, DrPlan, KeySource, preflight};
use crate::daemon::identity::{init_identity_new_device, load_identity};

const PHRASE_A: &str = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon art";

fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(dir).expect("read_dir") {
        let e = e.expect("entry");
        if e.file_type().expect("type").is_file() {
            out.insert(
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).expect("read"),
            );
        }
    }
    out
}

/// A real db.redb carrying `marker` as its next_file_id.
fn write_db(path: &Path, marker: u64) {
    let db = viaticum_core::db::Db::open(path).expect("db");
    db.store_next_file_id(marker).expect("write");
}

fn read_marker(path: &Path) -> u64 {
    viaticum_core::db::Db::open(path)
        .expect("open")
        .load_next_file_id()
        .expect("read")
}

/// What `run_dr` does between preflight and commit, minus the network: stage the key
/// and build the recovered DB (marked with `marker`) in the claimed staging file.
fn recovered_plan(dir: &Path, marker: u64) -> DrPlan {
    let mut plan = preflight(dir, PHRASE_A).expect("preflight");
    plan.stage_key().expect("stage key");
    let file = plan.staging.file.take().expect("claimed");
    let db = viaticum_core::db::Db::create_from_file(file).expect("staging db");
    db.store_next_file_id(marker).expect("write");
    drop(db);
    plan
}

#[test]
fn commit_moves_old_db_to_dr_bak_with_same_bytes() {
    let dir = tempfile::tempdir().unwrap();
    init_identity_new_device(dir.path(), PHRASE_A).unwrap();
    let db = dir.path().join("db.redb");
    write_db(&db, 111);
    let old_bytes = std::fs::read(&db).unwrap();
    // Db::open leaves a pre-open copy; it is not DR's and DR does not touch it.
    let pre_open_bak = std::fs::read(dir.path().join("db.redb.bak")).ok();

    let plan = recovered_plan(dir.path(), 222);
    let outcome = commit(plan).expect("commit");

    let bak = dir.path().join("db.redb.dr-bak");
    assert_eq!(outcome.db_backup.as_deref(), Some(bak.as_path()));
    assert_eq!(
        std::fs::read(&bak).unwrap(),
        old_bytes,
        "old DB kept byte for byte"
    );
    assert_eq!(
        std::fs::read(dir.path().join("db.redb.bak")).ok(),
        pre_open_bak,
        "db.redb.bak untouched"
    );
    assert!(!dir.path().join("db.redb.dr-new").exists());
    assert_eq!(read_marker(&db), 222, "recovered DB installed");
}

#[test]
fn commit_second_run_does_not_clobber_first_dr_bak() {
    let dir = tempfile::tempdir().unwrap();
    init_identity_new_device(dir.path(), PHRASE_A).unwrap();
    let db = dir.path().join("db.redb");
    write_db(&db, 1);
    commit(recovered_plan(dir.path(), 2)).expect("first DR");
    let first_bak = std::fs::read(dir.path().join("db.redb.dr-bak")).unwrap();
    let second_old = std::fs::read(&db).unwrap();

    let outcome = commit(recovered_plan(dir.path(), 3)).expect("second DR");

    assert_eq!(outcome.db_backup, Some(dir.path().join("db.redb.dr-bak.1")));
    assert_eq!(
        std::fs::read(dir.path().join("db.redb.dr-bak")).unwrap(),
        first_bak,
        ".dr-bak of the first DR untouched"
    );
    assert_eq!(
        std::fs::read(dir.path().join("db.redb.dr-bak.1")).unwrap(),
        second_old
    );
    assert_eq!(read_marker(&db), 3);
}

#[test]
fn commit_installs_staged_db_and_new_key_0600() {
    let dir = tempfile::tempdir().unwrap();
    let plan = recovered_plan(dir.path(), 5);
    assert_eq!(plan.key_source, KeySource::New);
    let expected_device = plan.keyfile.device_id;

    let outcome = commit(plan).expect("commit");
    assert!(outcome.db_backup.is_none(), "no old DB → no .dr-bak");

    let kf = load_identity(dir.path()).expect("installed key");
    assert_eq!(kf.device_id, expected_device);
    assert_eq!(read_marker(&dir.path().join("db.redb")), 5);
    assert!(dir.path().join("config.toml").exists());
    let names: Vec<String> = snapshot(dir.path()).into_keys().collect();
    assert!(
        !names.iter().any(|n| n.ends_with(".dr-new")),
        "no drafts left: {names:?}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("identity.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "got {mode:03o}");
    }
}

#[test]
fn commit_keeps_existing_matching_key_untouched() {
    let dir = tempfile::tempdir().unwrap();
    init_identity_new_device(dir.path(), PHRASE_A).unwrap();
    let key_bytes = std::fs::read(dir.path().join("identity.key")).unwrap();

    let plan = recovered_plan(dir.path(), 8);
    assert_eq!(plan.key_source, KeySource::Existing);
    commit(plan).expect("commit");

    assert_eq!(
        std::fs::read(dir.path().join("identity.key")).unwrap(),
        key_bytes
    );
    assert_eq!(read_marker(&dir.path().join("db.redb")), 8);
}

#[test]
fn commit_refuses_when_db_appeared_and_is_locked() {
    let dir = tempfile::tempdir().unwrap();
    let plan = recovered_plan(dir.path(), 9);
    // A daemon started in the folder during DR.
    let daemon_db = viaticum_core::db::Db::open(&dir.path().join("db.redb")).unwrap();
    daemon_db.store_next_file_id(77).unwrap();

    let err = commit(plan).expect_err("must refuse");
    assert!(matches!(err, DrError::DataDirInUse { .. }), "got {err:?}");
    assert_eq!(
        daemon_db.load_next_file_id().unwrap(),
        77,
        "daemon DB untouched"
    );
    let names: Vec<String> = snapshot(dir.path()).into_keys().collect();
    assert!(
        !names
            .iter()
            .any(|n| n.ends_with(".dr-new") || n.contains(".dr-bak")),
        "{names:?}"
    );
    assert!(!dir.path().join("identity.key").exists());
}

#[test]
fn commit_without_staged_db_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    init_identity_new_device(dir.path(), PHRASE_A).unwrap();
    write_db(&dir.path().join("db.redb"), 10);
    let before = snapshot(dir.path());

    let plan = recovered_plan(dir.path(), 11);
    std::fs::remove_file(&plan.paths.db_staging).unwrap();

    let err = commit(plan).expect_err("must refuse");
    assert!(
        matches!(&err, DrError::Commit(m) if m.contains("missing")),
        "got {err:?}"
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn commit_refuses_before_any_rename_when_identity_key_exists() {
    let dir = tempfile::tempdir().unwrap();
    write_db(&dir.path().join("db.redb"), 12);
    let db_before = std::fs::read(dir.path().join("db.redb")).unwrap();
    let plan = recovered_plan(dir.path(), 13);
    assert_eq!(plan.key_source, KeySource::New);
    // An identity.key appeared while DR was on the network (another process wrote
    // one; `init` itself refuses a folder holding db.redb, dr-i30).
    let foreign = {
        let m = crate::daemon::identity::parse_mnemonic(PHRASE_A).unwrap();
        crate::daemon::identity::build_keyfile(&m, crate::daemon::identity::DeviceSeedMode::Random)
            .unwrap()
    };
    crate::daemon::identity::write_keyfile_at(&dir.path().join("identity.key"), &foreign).unwrap();

    let err = commit(plan).expect_err("must refuse");
    assert!(err.to_string().contains("identity.key appeared"), "{err}");
    assert_eq!(
        std::fs::read(dir.path().join("db.redb")).unwrap(),
        db_before
    );
    assert_eq!(
        load_identity(dir.path()).unwrap().device_id,
        foreign.device_id,
        "the appeared key is untouched"
    );
    let names: Vec<String> = snapshot(dir.path()).into_keys().collect();
    assert!(
        !names
            .iter()
            .any(|n| n.ends_with(".dr-new") || n.contains(".dr-bak")),
        "{names:?}"
    );
}

#[test]
fn commit_rolls_back_install_when_identity_key_appears_after_db_rename() {
    // Prepared state right after commit steps 2-3: recovered DB installed, previous
    // DB at .dr-bak, key draft staged — and a key that appeared meanwhile.
    let dir = tempfile::tempdir().unwrap();
    let paths = DrPaths::new(dir.path());
    std::fs::write(&paths.db, b"RECOVERED").unwrap();
    let bak = dir.path().join("db.redb.dr-bak");
    std::fs::write(&bak, b"PREVIOUS").unwrap();
    std::fs::write(&paths.key_staging, b"STAGED KEY").unwrap();
    std::fs::write(&paths.key, b"KEY FROM INIT").unwrap();

    let err = install_new_key(&paths, Some(&bak)).expect_err("key appeared");
    match err {
        KeyInstallError::RolledBack(e) => {
            assert!(e.to_string().contains("identity.key appeared"), "{e}")
        }
        KeyInstallError::Stuck(e) => panic!("rollback must succeed here: {e}"),
    }
    assert_eq!(std::fs::read(&paths.db).unwrap(), b"PREVIOUS");
    assert_eq!(std::fs::read(&paths.db_staging).unwrap(), b"RECOVERED");
    assert!(!bak.exists());
    assert_eq!(std::fs::read(&paths.key).unwrap(), b"KEY FROM INIT");
}

#[test]
fn abort_removes_only_staging_created_by_this_run() {
    let dir = tempfile::tempdir().unwrap();
    init_identity_new_device(dir.path(), PHRASE_A).unwrap();
    write_db(&dir.path().join("db.redb"), 20);
    let before = snapshot(dir.path());

    let mut plan = preflight(dir.path(), PHRASE_A).unwrap();
    plan.stage_key().unwrap();
    abort(&mut plan);

    assert_eq!(snapshot(dir.path()), before, "only the drafts go");
}

#[cfg(unix)]
#[test]
fn abort_does_not_remove_staging_claimed_by_other_dr() {
    let dir = tempfile::tempdir().unwrap();
    let mut plan = preflight(dir.path(), PHRASE_A).unwrap();
    // Another DR took the path over (our file unlinked, theirs created in its place).
    drop(plan.staging.file.take());
    std::fs::remove_file(&plan.paths.db_staging).unwrap();
    std::fs::write(&plan.paths.db_staging, b"OTHER DR").unwrap();

    abort(&mut plan);
    assert_eq!(
        std::fs::read(&plan.paths.db_staging).unwrap(),
        b"OTHER DR",
        "another DR's staging file survives our abort"
    );
}

#[test]
fn next_backup_path_skips_taken_slots() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db.redb");
    assert_eq!(
        next_backup_path(&db).unwrap(),
        dir.path().join("db.redb.dr-bak")
    );
    std::fs::write(dir.path().join("db.redb.dr-bak"), b"1").unwrap();
    std::fs::write(dir.path().join("db.redb.dr-bak.1"), b"2").unwrap();
    assert_eq!(
        next_backup_path(&db).unwrap(),
        dir.path().join("db.redb.dr-bak.2")
    );
}

// ─── dr-i29: no instant without db.redb (unix: hard link + atomic rename) ──────

#[cfg(unix)]
fn inode(p: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).unwrap().ino()
}

#[cfg(unix)]
#[test]
fn set_aside_by_link_keeps_db_in_place() {
    // The state a crash right after step 2 leaves: db.redb is still the old DB.
    let dir = tempfile::tempdir().unwrap();
    let paths = DrPaths::new(dir.path());
    std::fs::write(&paths.db, b"OLD").unwrap();
    let bak = dir.path().join("db.redb.dr-bak");

    super::set_aside_by_link(&paths, &bak).unwrap();

    assert_eq!(
        std::fs::read(&paths.db).unwrap(),
        b"OLD",
        "db.redb never absent"
    );
    assert_eq!(
        inode(&bak),
        inode(&paths.db),
        "backup is a second name, not a copy"
    );
}

#[cfg(unix)]
#[test]
fn commit_replaces_old_db_in_place_and_keeps_its_inode_as_dr_bak() {
    let dir = tempfile::tempdir().unwrap();
    init_identity_new_device(dir.path(), PHRASE_A).unwrap();
    let db = dir.path().join("db.redb");
    write_db(&db, 30);
    let old_inode = inode(&db);
    let plan = recovered_plan(dir.path(), 31);
    let staged_inode = inode(&plan.paths.db_staging);

    let outcome = commit(plan).expect("commit");

    let bak = outcome.db_backup.expect("backup");
    assert_eq!(
        inode(&bak),
        old_inode,
        "the old DB itself, under the .dr-bak name"
    );
    assert_eq!(inode(&db), staged_inode, "the recovered DB replaced it");
    assert_eq!(read_marker(&db), 31);
}

#[cfg(unix)]
#[test]
fn commit_after_interrupted_link_keeps_old_db() {
    // A previous DR crashed between steps 2 and 3: db.redb and db.redb.dr-bak are
    // two names of the old DB. A repeated DR must lose nothing.
    let dir = tempfile::tempdir().unwrap();
    init_identity_new_device(dir.path(), PHRASE_A).unwrap();
    let db = dir.path().join("db.redb");
    write_db(&db, 40);
    let paths = DrPaths::new(dir.path());
    super::set_aside_by_link(&paths, &dir.path().join("db.redb.dr-bak")).unwrap();

    let outcome = commit(recovered_plan(dir.path(), 41)).expect("repeated DR");

    assert_eq!(outcome.db_backup, Some(dir.path().join("db.redb.dr-bak.1")));
    assert_eq!(read_marker(&dir.path().join("db.redb.dr-bak")), 40);
    assert_eq!(read_marker(&dir.path().join("db.redb.dr-bak.1")), 40);
    assert_eq!(read_marker(&db), 41);
}

#[test]
fn install_by_two_renames_restores_old_db_when_install_fails() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DrPaths::new(dir.path());
    std::fs::write(&paths.db, b"OLD").unwrap();
    // No staging file: the second rename fails.
    let bak = dir.path().join("db.redb.dr-bak");

    let err = install_by_two_renames(&paths, &bak).expect_err("must fail");
    assert!(matches!(err, DbInstallError::Unchanged(_)), "got {err:?}");
    assert_eq!(std::fs::read(&paths.db).unwrap(), b"OLD");
    assert!(!bak.exists());
}

// ─── dr-i25: half-done installs name every file and keep them ─────────────────

#[test]
fn two_rename_stuck_text_names_all_three_files() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DrPaths::new(dir.path());
    let bak = dir.path().join("db.redb.dr-bak");
    let e = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let text = two_rename_stuck_text(&paths, &bak, &e, &e);
    for p in [&paths.db, &paths.db_staging, &bak] {
        assert!(text.contains(&p.display().to_string()), "{text}");
    }
    assert!(text.contains("Move the previous one back"), "{text}");
}

#[test]
fn install_new_key_stuck_rollback_names_files_and_keeps_them() {
    // Key appeared after the DB was installed, and the rollback cannot move the
    // recovered DB out of the way (a non-empty directory sits at the staging path).
    let dir = tempfile::tempdir().unwrap();
    let paths = DrPaths::new(dir.path());
    std::fs::write(&paths.db, b"RECOVERED").unwrap();
    let bak = dir.path().join("db.redb.dr-bak");
    std::fs::write(&bak, b"PREVIOUS").unwrap();
    std::fs::write(&paths.key_staging, b"STAGED KEY").unwrap();
    std::fs::write(&paths.key, b"KEY FROM INIT").unwrap();
    std::fs::create_dir(&paths.db_staging).unwrap();
    std::fs::write(paths.db_staging.join("blocker"), b"x").unwrap();

    let err = install_new_key(&paths, Some(&bak)).expect_err("must fail");
    let text = match err {
        KeyInstallError::Stuck(e) => e.to_string(),
        KeyInstallError::RolledBack(e) => panic!("rollback cannot succeed here: {e}"),
    };
    assert!(text.contains(&paths.db.display().to_string()), "{text}");
    assert!(text.contains(&bak.display().to_string()), "{text}");
    assert!(text.contains("RECOVERED database"), "{text}");
    assert_eq!(std::fs::read(&paths.db).unwrap(), b"RECOVERED");
    assert_eq!(std::fs::read(&bak).unwrap(), b"PREVIOUS");
    assert!(paths.key_staging.exists(), "the key draft is kept");
    assert_eq!(std::fs::read(&paths.key).unwrap(), b"KEY FROM INIT");
}

#[test]
fn commit_stuck_key_install_names_files_and_keeps_them() {
    // The key draft vanished before step 4 (link and rename both fail): the DB is
    // installed, the error tells where everything is, nothing is cleaned up.
    let dir = tempfile::tempdir().unwrap();
    write_db(&dir.path().join("db.redb"), 50);
    let plan = recovered_plan(dir.path(), 51);
    assert_eq!(plan.key_source, KeySource::New);
    let paths = plan.paths.clone();
    std::fs::remove_file(&paths.key_staging).unwrap();

    let err = commit(plan).expect_err("must fail");
    let text = err.to_string();
    assert!(matches!(err, DrError::Commit(_)), "got {err:?}");
    for p in [&paths.db, &paths.key_staging, &paths.key] {
        assert!(text.contains(&p.display().to_string()), "{text}");
    }
    assert_eq!(read_marker(&paths.db), 51, "recovered DB stays installed");
    assert_eq!(
        read_marker(&dir.path().join("db.redb.dr-bak")),
        50,
        "previous DB kept"
    );
    assert!(!paths.key.exists());
}

// ─── Fault points: crash and failed renames inside steps 2-3 ─────────────────

/// Run `commit` with the given fault flags on; the flags are cleared afterwards.
fn commit_with_faults(
    plan: DrPlan,
    flags: u8,
) -> std::thread::Result<Result<super::CommitOutcome, DrError>> {
    set_faults(flags);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| commit(plan)));
    set_faults(0);
    r
}

#[cfg(unix)]
#[test]
fn crash_between_steps_2_and_3_leaves_old_db_in_place() {
    let dir = tempfile::tempdir().unwrap();
    init_identity_new_device(dir.path(), PHRASE_A).unwrap();
    let db = dir.path().join("db.redb");
    write_db(&db, 60);
    let plan = recovered_plan(dir.path(), 61);
    let staging = plan.paths.db_staging.clone();

    let r = commit_with_faults(plan, FAULT_CRASH_AFTER_STEP_2);
    assert!(r.is_err(), "the crash point must fire");

    // identity.key is there (Existing), so db.redb must be too: the old DB.
    assert_eq!(read_marker(&db), 60, "db.redb is the old DB");
    assert_eq!(
        inode(&dir.path().join("db.redb.dr-bak")),
        inode(&db),
        ".dr-bak is a second name of the old DB"
    );
    assert_eq!(read_marker(&staging), 61, "the recovered draft is intact");
}

#[test]
fn crash_between_two_renames_leaves_old_db_as_dr_bak() {
    // The fallback path (no hard links) keeps the documented window: no db.redb for
    // a moment, but nothing is lost.
    let dir = tempfile::tempdir().unwrap();
    init_identity_new_device(dir.path(), PHRASE_A).unwrap();
    let db = dir.path().join("db.redb");
    write_db(&db, 62);
    let plan = recovered_plan(dir.path(), 63);
    let staging = plan.paths.db_staging.clone();

    let r = commit_with_faults(plan, FAULT_CRASH_AFTER_STEP_2 | FAULT_FORCE_TWO_RENAMES);
    assert!(r.is_err(), "the crash point must fire");

    assert!(!db.exists());
    assert_eq!(read_marker(&dir.path().join("db.redb.dr-bak")), 62);
    assert_eq!(read_marker(&staging), 63);
}

#[cfg(unix)]
#[test]
fn replace_db_failure_drops_the_extra_link_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DrPaths::new(dir.path());
    std::fs::write(&paths.db, b"OLD").unwrap();
    // A non-empty directory at the staging path: rename(dir -> file) fails.
    std::fs::create_dir(&paths.db_staging).unwrap();
    std::fs::write(paths.db_staging.join("blocker"), b"x").unwrap();

    let err = install_db(&paths).expect_err("step 3 must fail");
    assert!(matches!(err, DbInstallError::Unchanged(_)), "got {err:?}");
    assert_eq!(std::fs::read(&paths.db).unwrap(), b"OLD");
    assert!(
        !dir.path().join("db.redb.dr-bak").exists(),
        "the extra backup name is dropped again"
    );
}

#[test]
fn commit_stuck_install_does_not_abort_and_keeps_drafts() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db.redb");
    write_db(&db, 70);
    let plan = recovered_plan(dir.path(), 71);
    assert_eq!(plan.key_source, KeySource::New);
    let paths = plan.paths.clone();

    let r = commit_with_faults(
        plan,
        FAULT_FORCE_TWO_RENAMES | FAULT_FAIL_STEP_3_AND_MOVE_BACK,
    );
    let err = r.expect("no panic").expect_err("must be stuck");
    let text = err.to_string();
    let bak = dir.path().join("db.redb.dr-bak");
    for p in [&paths.db, &paths.db_staging, &bak] {
        assert!(text.contains(&p.display().to_string()), "{text}");
    }
    assert!(
        !db.exists(),
        "the half-done state is what the text describes"
    );
    assert_eq!(read_marker(&bak), 70, "previous DB kept");
    assert_eq!(read_marker(&paths.db_staging), 71, "recovered draft kept");
    assert!(paths.key_staging.exists(), "key draft kept (no abort)");
    assert!(!paths.key.exists());
}
