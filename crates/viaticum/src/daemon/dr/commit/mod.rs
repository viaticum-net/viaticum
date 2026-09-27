//! DR commit: install the recovered DB and key with a series of renames, only after
//! the network phase succeeded; and `abort`, which removes only this run's drafts.
//!
//! Order (mandatory):
//!   0. re-take the staging DB (it must still be the file THIS run created);
//!   1. `KeySource::New` and `identity.key` exists → abort (someone ran `init`);
//!   2. an existing `db.redb` gets a second name `db.redb.dr-bak[.N]` (hard link;
//!      never deleted, never clobbered);
//!   3. `rename(db.redb.dr-new → db.redb)` atomically replaces the old DB, whose
//!      inode lives on under the `.dr-bak` name;
//!   4. `KeySource::New`: link the staged key to `identity.key` (fails if one
//!      appeared meanwhile → roll 2-3 back); `Existing`: the key is not touched;
//!   5. default `config.toml` if absent.
//!
//! Steps 2-3 leave no instant without a `db.redb` (dr-i29): a crash between them
//! leaves the old DB in place plus an extra `.dr-bak` name for it. Where hard links
//! are unavailable (non-unix, filesystems without links) steps 2-3 fall back to two
//! renames (`db.redb → .dr-bak`, then staging → `db.redb`); a crash between those
//! leaves no `db.redb` for a moment. The key goes last: every state a crash can
//! leave is one where the daemon does not start (no key) or starts on a complete
//! DB, and a repeated DR is safe in all of them (spec B2 §2.5.4).

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use super::DrError;
use super::preflight::{
    DrPaths, DrPlan, KeySource, LockProbe, classify_try_lock, handle_is, path_is,
};
use crate::daemon::identity::write_default_config_if_absent;

#[cfg(test)]
mod tests;

/// Highest `.dr-bak.N` suffix tried before giving up.
const MAX_BACKUP_SUFFIX: u32 = 999;

// ─── Test-only fault points ───────────────────────────────────────────────────
// Unit tests switch these on to reproduce a crash or a failed rename at an exact
// point of the commit. Outside `cfg(test)` `fault_on` is constant false.

/// Panic right after step 2 (old DB set aside), before step 3.
const FAULT_CRASH_AFTER_STEP_2: u8 = 1;
/// Skip the hard-link path (as on a filesystem without links).
#[cfg_attr(not(unix), allow(dead_code))]
const FAULT_FORCE_TWO_RENAMES: u8 = 2;
/// In the two-rename path, fail step 3 and the move-back of the old DB.
const FAULT_FAIL_STEP_3_AND_MOVE_BACK: u8 = 4;

#[cfg(test)]
thread_local! {
    static FAULTS: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn set_faults(flags: u8) {
    FAULTS.with(|f| f.set(flags));
}

#[cfg(test)]
fn fault_on(flag: u8) -> bool {
    FAULTS.with(|f| f.get() & flag != 0)
}

#[cfg(not(test))]
const fn fault_on(_flag: u8) -> bool {
    false
}

fn crash_point_after_step_2() {
    if fault_on(FAULT_CRASH_AFTER_STEP_2) {
        panic!("test fault: crash after commit step 2");
    }
}

fn injected_rename_failure(what: &str) -> std::io::Error {
    std::io::Error::other(format!("test fault: {what}"))
}

#[derive(Debug)]
pub(crate) struct CommitOutcome {
    /// Where the previous `db.redb` was moved, if there was one.
    pub(crate) db_backup: Option<PathBuf>,
}

fn key_appeared(paths: &DrPaths) -> DrError {
    DrError::Commit(format!(
        "identity.key appeared in {} during DR (was 'viaticum init' run?). Nothing was changed.",
        paths.data_dir.display()
    ))
}

/// Install the recovered state. Precondition: the staging `Db` and every clone of it
/// are dropped (redb's lock on the staging file is released). Consumes the plan; on
/// `Err` the folder holds what it held before DR (the drafts are removed), except
/// where the error text says otherwise.
pub(crate) fn commit(mut plan: DrPlan) -> Result<CommitOutcome, DrError> {
    let paths = plan.paths.clone();

    // 0. The staging DB must still be ours; hold its lock through the renames so a
    //    concurrent DR's preflight cannot take it for a stale draft. Between redb
    //    dropping its lock (the staging Db was closed) and this re-lock the draft is
    //    briefly unlocked; another DR's preflight could remove or replace it then.
    //    So: open, lock, and only then check that the LOCKED file is ours and the
    //    path still names it — once locked, no preflight removes it. Missing →
    //    "missing"; locked by another DR → in progress; not ours → "replaced" (sound:
    //    the plan holds our file open, so its inode number is never reused).
    let staging_lock = match OpenOptions::new()
        .read(true)
        .write(true)
        .open(&paths.db_staging)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            abort(&mut plan);
            return Err(DrError::Commit(
                "recovered database missing. Nothing was changed.".to_string(),
            ));
        }
        Err(e) => {
            abort(&mut plan);
            return Err(DrError::Commit(format!(
                "cannot open {}: {e}. Nothing was changed.",
                paths.db_staging.display()
            )));
        }
    };
    if let Ok(LockProbe::HeldElsewhere) = classify_try_lock(staging_lock.try_lock()) {
        // Another DR claimed it; it will clean it up. Leave the drafts alone.
        return Err(DrError::DrInProgress {
            data_dir: paths.data_dir.display().to_string(),
        });
    }
    let ours = plan.staging.id.as_ref();
    if !handle_is(&staging_lock, ours) || !path_is(&paths.db_staging, ours) {
        drop(staging_lock);
        abort(&mut plan);
        return Err(DrError::Commit(format!(
            "{} was replaced by another process during DR. Nothing was changed.",
            paths.db_staging.display()
        )));
    }

    // 1. N-5 pre-check.
    if plan.key_source == KeySource::New && paths.key.exists() {
        abort(&mut plan);
        return Err(key_appeared(&paths));
    }

    // 2. The old DB (if any) must not be held by a daemon started meanwhile.
    let mut late_db_lock: Option<File> = None;
    if paths.db.exists()
        && plan.lock.db.is_none()
        && let Ok(f) = OpenOptions::new().read(true).write(true).open(&paths.db)
    {
        // db.redb appeared after preflight (or locks are unsupported): probe now.
        if let Ok(LockProbe::HeldElsewhere) = classify_try_lock(f.try_lock()) {
            abort(&mut plan);
            return Err(DrError::DataDirInUse {
                data_dir: paths.data_dir.display().to_string(),
            });
        }
        late_db_lock = Some(f);
    }

    // 2-3. Keep the old DB as .dr-bak and install the recovered one.
    let backup = match install_db(&paths) {
        Ok(b) => b,
        Err(DbInstallError::Unchanged(e)) => {
            abort(&mut plan);
            return Err(e);
        }
        // The error text tells the friend which files to move: keep them.
        Err(DbInstallError::Stuck(e)) => return Err(e),
    };

    // 4. The key, last.
    if plan.key_source == KeySource::New {
        match install_new_key(&paths, backup.as_deref()) {
            Ok(()) => plan.staged_key = None, // installed: no longer a draft
            Err(KeyInstallError::RolledBack(e)) => {
                abort(&mut plan);
                return Err(e);
            }
            // The error text tells the friend which files to move: keep them.
            Err(KeyInstallError::Stuck(e)) => return Err(e),
        }
    }

    // 5. Config.
    if let Err(e) = write_default_config_if_absent(&paths.data_dir) {
        tracing::warn!(
            "dr: could not write the default config.toml ({e}); the daemon uses defaults"
        );
    }
    sync_dir(&paths.data_dir);

    // 6. Locks are released when the handles drop.
    drop(staging_lock);
    drop(late_db_lock);
    drop(plan);
    Ok(CommitOutcome { db_backup: backup })
}

/// Why steps 2-3 failed.
#[derive(Debug)]
pub(crate) enum DbInstallError {
    /// Nothing in the folder changed; the drafts may go.
    Unchanged(DrError),
    /// A rename failed half-way; the error says what lies where. Touch nothing.
    Stuck(DrError),
}

fn install_failed_unchanged(paths: &DrPaths, e: &std::io::Error) -> DbInstallError {
    DbInstallError::Unchanged(DrError::Commit(format!(
        "cannot move {} to {}: {e}. Nothing was changed.",
        paths.db_staging.display(),
        paths.db.display()
    )))
}

/// Steps 2-3: keep an existing `db.redb` under the first free `.dr-bak[.N]` name and
/// put the staging DB in its place. Returns the backup path, if there was an old DB.
pub(crate) fn install_db(paths: &DrPaths) -> Result<Option<PathBuf>, DbInstallError> {
    if !paths.db.exists() {
        return std::fs::rename(&paths.db_staging, &paths.db)
            .map(|()| None)
            .map_err(|e| install_failed_unchanged(paths, &e));
    }
    let backup = next_backup_path(&paths.db).map_err(DbInstallError::Unchanged)?;
    #[cfg(unix)]
    if !fault_on(FAULT_FORCE_TWO_RENAMES) {
        match set_aside_by_link(paths, &backup) {
            Ok(()) => {
                sync_dir(&paths.data_dir);
                crash_point_after_step_2();
                return replace_db(paths, &backup).map(|()| Some(backup));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(DbInstallError::Unchanged(DrError::Commit(format!(
                    "{} appeared during DR. Nothing was changed.",
                    backup.display()
                ))));
            }
            Err(e) => tracing::info!(
                "dr: cannot hard-link {} ({e}); keeping the old DB by two renames",
                paths.db.display()
            ),
        }
    }
    install_by_two_renames(paths, &backup).map(|()| Some(backup))
}

/// Unix step 2: the backup name becomes a second link to the old DB; `db.redb` stays
/// where it is. A link never replaces an existing file.
#[cfg(unix)]
pub(crate) fn set_aside_by_link(paths: &DrPaths, backup: &Path) -> std::io::Result<()> {
    std::fs::hard_link(&paths.db, backup)
}

/// Unix step 3: `rename` replaces `db.redb` atomically; the old inode survives under
/// `backup`. On failure the extra backup name is dropped again (the old DB is still
/// `db.redb`), so nothing changed.
#[cfg(unix)]
fn replace_db(paths: &DrPaths, backup: &Path) -> Result<(), DbInstallError> {
    let replaced = std::fs::rename(&paths.db_staging, &paths.db);
    if replaced.is_ok() {
        sync_dir(&paths.data_dir);
    }
    replaced.map_err(|e| {
        if let Err(re) = std::fs::remove_file(backup) {
            tracing::warn!(
                path = %backup.display(),
                "dr: could not drop the extra backup name of the unchanged DB: {re}"
            );
        }
        install_failed_unchanged(paths, &e)
    })
}

/// Steps 2-3 without hard links: `db.redb → backup`, then staging → `db.redb`; if the
/// second rename fails, the old DB is moved back.
pub(crate) fn install_by_two_renames(paths: &DrPaths, backup: &Path) -> Result<(), DbInstallError> {
    std::fs::rename(&paths.db, backup).map_err(|e| {
        DbInstallError::Unchanged(DrError::Commit(format!(
            "cannot move {} to {}: {e}. Nothing was changed.",
            paths.db.display(),
            backup.display()
        )))
    })?;
    sync_dir(&paths.data_dir);
    crash_point_after_step_2();
    let step3 = if fault_on(FAULT_FAIL_STEP_3_AND_MOVE_BACK) {
        Err(injected_rename_failure("install the recovered DB"))
    } else {
        std::fs::rename(&paths.db_staging, &paths.db)
    };
    let Err(e) = step3 else {
        sync_dir(&paths.data_dir);
        return Ok(());
    };
    let moved_back = if fault_on(FAULT_FAIL_STEP_3_AND_MOVE_BACK) {
        Err(injected_rename_failure("move the previous DB back"))
    } else {
        std::fs::rename(backup, &paths.db)
    };
    match moved_back {
        Ok(()) => Err(install_failed_unchanged(paths, &e)),
        Err(re) => Err(DbInstallError::Stuck(DrError::Commit(
            two_rename_stuck_text(paths, backup, &e, &re),
        ))),
    }
}

/// Text of the half-done two-rename install: installing the recovered DB failed
/// (`e`) and moving the previous one back failed too (`re`).
pub(crate) fn two_rename_stuck_text(
    paths: &DrPaths,
    backup: &Path,
    e: &std::io::Error,
    re: &std::io::Error,
) -> String {
    format!(
        "cannot move {} to {}: {e}; and moving the previous database back failed too \
         ({re}). Your previous database is {}; the recovered one is {}. Move the \
         previous one back to {} before starting the daemon.",
        paths.db_staging.display(),
        paths.db.display(),
        backup.display(),
        paths.db_staging.display(),
        paths.db.display()
    )
}

/// Why step 4 failed.
#[derive(Debug)]
pub(crate) enum KeyInstallError {
    /// `identity.key` appeared; steps 2-3 were rolled back, the drafts may go.
    RolledBack(DrError),
    /// A rename failed half-way; the error says what lies where. Touch nothing.
    Stuck(DrError),
}

/// Step 4 for `KeySource::New`: hard-link the staged key to `identity.key`. A link
/// never replaces an existing file, so a key created meanwhile (someone ran `init`)
/// is detected atomically; then steps 2-3 are rolled back. Filesystems without hard
/// links fall back to check-then-rename.
pub(crate) fn install_new_key(
    paths: &DrPaths,
    backup: Option<&Path>,
) -> Result<(), KeyInstallError> {
    let appeared = || match roll_back_install(paths, backup) {
        Ok(()) => KeyInstallError::RolledBack(key_appeared(paths)),
        Err(e) => KeyInstallError::Stuck(e),
    };
    match std::fs::hard_link(&paths.key_staging, &paths.key) {
        Ok(()) => {
            if let Err(e) = std::fs::remove_file(&paths.key_staging) {
                tracing::warn!(
                    path = %paths.key_staging.display(),
                    "dr: installed identity.key but could not remove its draft: {e}"
                );
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(appeared()),
        Err(link_err) => {
            if paths.key.exists() {
                return Err(appeared());
            }
            std::fs::rename(&paths.key_staging, &paths.key).map_err(|e| {
                KeyInstallError::Stuck(DrError::Commit(format!(
                    "the recovered database is installed at {}, but installing \
                     identity.key failed ({link_err}; {e}). The key is at {}: rename it \
                     to {} to finish.",
                    paths.db.display(),
                    paths.key_staging.display(),
                    paths.key.display()
                )))
            })
        }
    }
}

/// Undo steps 2-3: the recovered DB goes back to staging and the previous DB (if
/// any) back to `db.redb`. If a rename fails the error says exactly what lies where.
pub(crate) fn roll_back_install(paths: &DrPaths, backup: Option<&Path>) -> Result<(), DrError> {
    std::fs::rename(&paths.db, &paths.db_staging).map_err(|e| {
        DrError::Commit(format!(
            "identity.key appeared in {} during DR, and moving the recovered database \
             out of the way failed ({e}). {} is the RECOVERED database{}. Stop and sort \
             this out by hand before starting the daemon.",
            paths.data_dir.display(),
            paths.db.display(),
            backup
                .map(|b| format!("; your previous database is {}", b.display()))
                .unwrap_or_default()
        ))
    })?;
    if let Some(b) = backup {
        std::fs::rename(b, &paths.db).map_err(|e| {
            DrError::Commit(format!(
                "identity.key appeared in {} during DR; moving your previous database \
                 back failed ({e}). It is at {}; move it to {} by hand.",
                paths.data_dir.display(),
                b.display(),
                paths.db.display()
            ))
        })?;
    }
    Ok(())
}

/// First free of `db.redb.dr-bak`, `db.redb.dr-bak.1`, … `db.redb.dr-bak.999`.
pub(crate) fn next_backup_path(db: &Path) -> Result<PathBuf, DrError> {
    let name = db
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "db.redb".to_string());
    let dir = db.parent().unwrap_or_else(|| Path::new("."));
    let free = |p: &Path| std::fs::symlink_metadata(p).is_err();
    let first = dir.join(format!("{name}.dr-bak"));
    if free(&first) {
        return Ok(first);
    }
    for n in 1..=MAX_BACKUP_SUFFIX {
        let p = dir.join(format!("{name}.dr-bak.{n}"));
        if free(&p) {
            return Ok(p);
        }
    }
    Err(DrError::Commit(format!(
        "{} already has {} previous-database copies ({name}.dr-bak …); remove old ones. \
         Nothing was changed.",
        dir.display(),
        MAX_BACKUP_SUFFIX + 1
    )))
}

/// Remove ONLY what this run created: the staging DB it claimed and the key draft it
/// wrote, each only while the path still names this run's file (`OwnedFile`: our
/// file is held open until after the check, so a file another DR created at the
/// path never passes for ours). Best-effort.
pub(crate) fn abort(plan: &mut DrPlan) {
    // Close our handle first (Windows cannot delete an open file cleanly).
    drop(plan.staging.file.take());
    if path_is(&plan.paths.db_staging, plan.staging.id.as_ref())
        && let Err(e) = std::fs::remove_file(&plan.paths.db_staging)
    {
        tracing::warn!(
            path = %plan.paths.db_staging.display(),
            "dr: could not remove the staging DB: {e}"
        );
    }
    match plan.staged_key.take() {
        Some(owned) if path_is(&plan.paths.key_staging, owned.as_ref()) => {
            if let Err(e) = std::fs::remove_file(&plan.paths.key_staging) {
                tracing::warn!(
                    path = %plan.paths.key_staging.display(),
                    "dr: could not remove the key draft: {e}"
                );
            }
        }
        // unix, identity not taken when the draft was written: not provably ours.
        Some(None) if cfg!(unix) => tracing::warn!(
            path = %plan.paths.key_staging.display(),
            "dr: cannot tell whether the key draft is this run's; leaving it"
        ),
        _ => {}
    }
}

/// Durability of the renames (unix: fsync the directory). A failure does not undo
/// the commit; it is logged with the path.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Err(e) = File::open(dir).and_then(|d| d.sync_all()) {
        tracing::warn!(
            path = %dir.display(),
            "dr: could not flush the directory after installing the recovered state: {e}"
        );
    }
    #[cfg(not(unix))]
    let _ = dir;
}
