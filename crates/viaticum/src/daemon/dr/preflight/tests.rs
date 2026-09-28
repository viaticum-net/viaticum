// Tests for DR preflight: phrase check, folder checks, lock probes, staging claim.
// Real files in a temp dir and a real redb `Db` wherever a lock is involved.

use std::collections::BTreeMap;
use std::fs::TryLockError;
use std::path::Path;

use super::{DrPaths, KeySource, LockProbe, classify_try_lock, path_is, preflight};
use crate::daemon::dr::DrError;
use crate::daemon::identity::{
    DeviceSeedMode, MnemonicProblem, build_keyfile, init_identity_from_mnemonic,
    init_identity_new_device, parse_mnemonic,
};
use viaticum_core::types::hex_encode;

const PHRASE_A: &str = "abandon abandon abandon abandon abandon abandon \
                                   abandon abandon abandon abandon abandon abandon \
                                   abandon abandon abandon abandon abandon abandon \
                                   abandon abandon abandon abandon abandon art";

const PHRASE_B: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                                   zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";

/// PHRASE_A with word 5 replaced by a word that is not in the list.
fn typo_of_a() -> String {
    let mut w: Vec<&str> = PHRASE_A.split_whitespace().collect();
    w[4] = "zzzz";
    w.join(" ")
}

/// Every regular file in `dir` (non-recursive) → its bytes.
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

/// A stopped node's folder: identity.key from `init` (random device) + a real db.redb.
fn old_node_folder(dir: &Path, phrase: &str) {
    init_identity_new_device(dir, phrase).expect("init");
    let db = viaticum_core::db::Db::open(&dir.join("db.redb")).expect("db");
    db.store_next_file_id(4242).expect("write");
}

fn derived_device_id(phrase: &str) -> [u8; 32] {
    let m = parse_mnemonic(phrase).expect("parse");
    build_keyfile(&m, DeviceSeedMode::DerivedFromSeed)
        .expect("build")
        .device_id
}

// ─── phrase ──────────────────────────────────────────────────────────────────

#[test]
fn preflight_typo_leaves_folder_byte_identical() {
    let dir = tempfile::tempdir().unwrap();
    old_node_folder(dir.path(), PHRASE_A);
    let before = snapshot(dir.path());

    let err = preflight(dir.path(), &typo_of_a()).expect_err("typo must stop DR");
    match err {
        DrError::InvalidPhrase(MnemonicProblem::UnknownWord { position, ref word }) => {
            assert_eq!(position, 5);
            assert_eq!(word, "zzzz");
        }
        other => panic!("expected InvalidPhrase(UnknownWord), got {other:?}"),
    }
    let text = err.to_string();
    assert!(
        text.contains("recovery phrase") && text.contains("word 5"),
        "{text}"
    );
    assert_eq!(snapshot(dir.path()), before, "folder changed");
}

#[test]
fn preflight_typo_does_not_create_missing_data_dir() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("new-machine");
    let abandon_x24 = ["abandon"; 24].join(" ");

    let err = preflight(&dir, &abandon_x24).expect_err("bad checksum must stop DR");
    assert!(
        matches!(err, DrError::InvalidPhrase(MnemonicProblem::Checksum)),
        "got {err:?}"
    );
    assert!(err.to_string().contains("checksum"));
    assert!(
        !dir.exists(),
        "a refused phrase must not create the data dir"
    );
}

// ─── identity.key in the folder ─────────────────────────────────────────────

#[test]
fn preflight_foreign_identity_key_is_refused_without_changes() {
    let dir = tempfile::tempdir().unwrap();
    old_node_folder(dir.path(), PHRASE_A);
    let folder_kf = crate::daemon::identity::load_identity(dir.path()).unwrap();
    let before = snapshot(dir.path());

    let err = preflight(dir.path(), PHRASE_B).expect_err("foreign phrase must stop DR");
    match &err {
        DrError::ForeignIdentity { folder, phrase, .. } => {
            assert_eq!(folder, &hex_encode(&folder_kf.identity_pub));
            let b = parse_mnemonic(PHRASE_B).unwrap();
            let b_kf = build_keyfile(&b, DeviceSeedMode::DerivedFromSeed).unwrap();
            assert_eq!(phrase, &hex_encode(&b_kf.identity_pub));
        }
        other => panic!("expected ForeignIdentity, got {other:?}"),
    }
    assert!(err.to_string().contains("different identity"));
    assert_eq!(snapshot(dir.path()), before, "folder changed");
}

#[test]
fn preflight_matching_key_with_random_device_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    old_node_folder(dir.path(), PHRASE_A);
    let folder_kf = crate::daemon::identity::load_identity(dir.path()).unwrap();
    assert_ne!(folder_kf.device_id, derived_device_id(PHRASE_A));

    // Messy spelling of the same phrase still matches.
    let messy = format!("  {}  ", PHRASE_A.to_uppercase());
    let mut plan = preflight(dir.path(), &messy).expect("same identity");
    assert_eq!(plan.key_source, KeySource::Existing);
    assert_eq!(
        plan.keyfile.device_id, folder_kf.device_id,
        "device id kept"
    );
    assert_eq!(plan.keyfile.device_seed, folder_kf.device_seed);

    // Existing: no key draft is ever written.
    plan.stage_key().unwrap();
    assert!(!plan.paths.key_staging.exists());
    assert!(plan.paths.db_staging.exists());
    crate::daemon::dr::commit::abort(&mut plan);
}

#[test]
fn preflight_without_key_uses_derived_device_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut plan = preflight(dir.path(), PHRASE_A).expect("empty folder");
    assert_eq!(plan.key_source, KeySource::New);
    assert_eq!(plan.keyfile.device_id, derived_device_id(PHRASE_A));
    assert!(!plan.paths.key.exists(), "identity.key only at commit");

    plan.stage_key().unwrap();
    assert!(plan.paths.key_staging.exists());
    assert!(!plan.paths.key.exists());
    crate::daemon::dr::commit::abort(&mut plan);
    assert!(snapshot(dir.path()).is_empty(), "abort leaves nothing");
}

#[test]
fn preflight_corrupt_key_is_refused_without_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("identity.key"), b"not cbor at all").unwrap();
    let before = snapshot(dir.path());

    let err = preflight(dir.path(), PHRASE_A).expect_err("corrupt key must stop DR");
    assert!(
        matches!(err, DrError::KeyfileUnreadable { .. }),
        "got {err:?}"
    );
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn preflight_key_with_inconsistent_identity_is_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let mut kf = init_identity_from_mnemonic(dir.path(), PHRASE_A).unwrap();
    std::fs::remove_file(dir.path().join("identity.key")).unwrap();
    kf.identity_pub[0] ^= 0xFF;
    crate::daemon::identity::write_keyfile_at(&dir.path().join("identity.key"), &kf).unwrap();

    let err = preflight(dir.path(), PHRASE_A).expect_err("tampered key must stop DR");
    assert!(
        matches!(err, DrError::KeyfileUnreadable { .. }),
        "got {err:?}"
    );
}

// ─── db.redb lock ────────────────────────────────────────────────────────────

#[test]
fn preflight_refuses_when_db_locked_by_running_daemon() {
    let dir = tempfile::tempdir().unwrap();
    init_identity_new_device(dir.path(), PHRASE_A).unwrap();
    // The daemon's own open: a real redb Database on db.redb, alive during the DR.
    let daemon_db = viaticum_core::db::Db::open(&dir.path().join("db.redb")).unwrap();
    let names_before: Vec<String> = snapshot(dir.path()).into_keys().collect();

    let err = preflight(dir.path(), PHRASE_A).expect_err("live daemon must stop DR");
    assert!(matches!(err, DrError::DataDirInUse { .. }), "got {err:?}");
    assert!(err.to_string().contains("in use"));
    let names_after: Vec<String> = snapshot(dir.path()).into_keys().collect();
    assert_eq!(names_after, names_before, "no drafts, no .dr-bak");

    // The daemon's DB still works.
    daemon_db.store_next_file_id(7).unwrap();
    assert_eq!(daemon_db.load_next_file_id().unwrap(), 7);
}

#[test]
fn preflight_checks_lock_before_reading_key() {
    let dir = tempfile::tempdir().unwrap();
    // Foreign key AND a live daemon: the daemon wins (neighbour's running node).
    init_identity_new_device(dir.path(), PHRASE_B).unwrap();
    let _daemon_db = viaticum_core::db::Db::open(&dir.path().join("db.redb")).unwrap();

    let err = preflight(dir.path(), PHRASE_A).expect_err("must stop");
    assert!(matches!(err, DrError::DataDirInUse { .. }), "got {err:?}");
}

#[test]
fn classify_try_lock_maps_unsupported_to_continue() {
    assert_eq!(classify_try_lock(Ok(())).unwrap(), LockProbe::Acquired);
    assert_eq!(
        classify_try_lock(Err(TryLockError::WouldBlock)).unwrap(),
        LockProbe::HeldElsewhere
    );
    let unsupported = std::io::Error::from(std::io::ErrorKind::Unsupported);
    assert_eq!(
        classify_try_lock(Err(TryLockError::Error(unsupported))).unwrap(),
        LockProbe::Unsupported
    );
    let other = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert!(classify_try_lock(Err(TryLockError::Error(other))).is_err());
}

// ─── staging claim ──────────────────────────────────────────────────────────

#[test]
fn preflight_removes_stale_unlocked_staging_files() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DrPaths::new(dir.path());
    std::fs::write(&paths.db_staging, b"killed DR leftovers").unwrap();
    std::fs::write(&paths.key_staging, b"killed DR key draft").unwrap();

    let mut plan = preflight(dir.path(), PHRASE_A).expect("stale drafts are not a stop");
    assert_eq!(
        std::fs::metadata(&paths.db_staging).unwrap().len(),
        0,
        "a fresh staging file replaced the stale one"
    );
    assert!(!paths.key_staging.exists(), "stale key draft removed");
    crate::daemon::dr::commit::abort(&mut plan);
}

#[test]
fn preflight_second_dr_cannot_claim_staging_while_first_holds_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut first = preflight(dir.path(), PHRASE_A).expect("first DR");

    let err = preflight(dir.path(), PHRASE_A).expect_err("second DR must stop");
    assert!(matches!(err, DrError::DrInProgress { .. }), "got {err:?}");
    assert!(
        path_is(&first.paths.db_staging, first.staging.id.as_ref()),
        "the first DR's staging file is untouched"
    );
    crate::daemon::dr::commit::abort(&mut first);
}

/// The reason a reused inode number cannot fool `path_is`: after our draft is
/// unlinked, `OwnedFile` still holds that very inode (link count 0, still readable),
/// so the filesystem cannot give its number to another file. Deterministic on any
/// filesystem — no inode allocator involved.
#[cfg(unix)]
#[test]
fn owned_file_keeps_its_unlinked_inode_allocated() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("draft");
    std::fs::write(&path, b"ours").unwrap();
    let ino = std::fs::metadata(&path).unwrap().ino();
    let owned = super::OwnedFile::pin(&path).expect("unix has file identity");

    std::fs::remove_file(&path).unwrap();

    let held = owned.handle.metadata().unwrap();
    assert_eq!(held.ino(), ino, "the handle is on our file");
    assert_eq!(held.nlink(), 0, "unlinked, yet held open");
    assert!(!path_is(&path, Some(&owned)), "no file at the path is ours");
}

/// An `OwnedFile` holds its file open, so a file created at its path after it was
/// unlinked never has its identity — on a filesystem checked to hand the freed
/// inode number to the next file (`inode_reusing_tempdir`).
#[cfg(unix)]
#[test]
fn owned_file_never_matches_a_file_recreated_at_its_path() {
    let dir = super::test_disk::inode_reusing_tempdir();
    let path = dir.path().join("draft");
    std::fs::write(&path, b"ours").unwrap();
    let owned = super::OwnedFile::pin(&path).expect("unix has file identity");
    assert!(path_is(&path, Some(&owned)));

    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"theirs").unwrap();
    assert!(!path_is(&path, Some(&owned)));
}

#[test]
fn preflight_refuses_when_staging_db_locked() {
    let dir = tempfile::tempdir().unwrap();
    let paths = DrPaths::new(dir.path());
    let other = std::fs::File::create(&paths.db_staging).unwrap();
    other.try_lock().expect("other DR's lock");

    let err = preflight(dir.path(), PHRASE_A).expect_err("must stop");
    assert!(matches!(err, DrError::DrInProgress { .. }), "got {err:?}");
    assert!(
        paths.db_staging.exists(),
        "another DR's draft is not removed"
    );
}

#[test]
fn staging_db_opens_on_file_locked_by_preflight() {
    let dir = tempfile::tempdir().unwrap();
    let mut plan = preflight(dir.path(), PHRASE_A).unwrap();
    let file = plan.staging.file.take().expect("claimed file");

    // A15: redb re-locks the descriptor preflight already locked.
    let db = viaticum_core::db::Db::create_from_file(file).expect("create_from_file");
    db.store_next_file_id(99).unwrap();

    // While the staging DB is open, another DR still cannot claim it.
    let err = preflight(dir.path(), PHRASE_A).expect_err("must stop");
    assert!(matches!(err, DrError::DrInProgress { .. }), "got {err:?}");

    drop(db);
    crate::daemon::dr::commit::abort(&mut plan);
    assert!(!plan.paths.db_staging.exists());
}
