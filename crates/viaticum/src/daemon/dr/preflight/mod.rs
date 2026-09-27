//! DR preflight: every check DR makes before it touches the network, and the claim
//! of its staging files.
//!
//! Order (fixed, each step tested):
//!   1. parse the phrase — a typo stops DR before the data dir is even created;
//!   2. build the phrase's keyfile in memory;
//!   3. create the data dir;
//!   4. probe the lock on an existing `db.redb` (a live daemon / another DR holds it);
//!   5. compare an existing `identity.key` with the phrase (same seed → reuse it and
//!      keep its device id; other seed → stop);
//!   6. claim `db.redb.dr-new` atomically (`create_new` + `try_lock`), removing a
//!      stale unlocked one left by a killed DR;
//!   7. remove a stale `identity.key.dr-new` (it belongs to whoever holds the staging
//!      DB, which is now us).
//!
//! Nothing in the data dir changes before step 6, and every refusal leaves it as it
//! was. Ownership: the process holding the lock on `db.redb` owns the folder; the
//! process holding the lock on `db.redb.dr-new` owns the drafts.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use viaticum_core::cluster::{derive_device_key, derive_master_key, master_identity};
use viaticum_core::types::hex_encode;

use super::DrError;
use crate::daemon::identity::{
    DeviceSeedMode, IdentityError, IdentityKeyFile, MnemonicProblem, build_keyfile, load_identity,
    parse_mnemonic, write_keyfile_at,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod test_disk;

/// The files DR reads and writes inside the data dir.
#[derive(Debug, Clone)]
pub(crate) struct DrPaths {
    pub(crate) data_dir: PathBuf,
    /// `db.redb`
    pub(crate) db: PathBuf,
    /// `db.redb.dr-new`
    pub(crate) db_staging: PathBuf,
    /// `identity.key`
    pub(crate) key: PathBuf,
    /// `identity.key.dr-new`
    pub(crate) key_staging: PathBuf,
}

impl DrPaths {
    pub(crate) fn new(data_dir: &Path) -> Self {
        DrPaths {
            data_dir: data_dir.to_path_buf(),
            db: data_dir.join("db.redb"),
            db_staging: data_dir.join("db.redb.dr-new"),
            key: data_dir.join("identity.key"),
            key_staging: data_dir.join("identity.key.dr-new"),
        }
    }
}

/// Where the identity DR works with comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeySource {
    /// `identity.key` in the folder has the phrase's seed: used as is, device id kept.
    Existing,
    /// No key in the folder: the phrase's keyfile (deterministic device id) is staged
    /// and installed only when DR succeeds.
    New,
}

/// Outcome of a non-blocking lock attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockProbe {
    Acquired,
    HeldElsewhere,
    /// The filesystem has no file locks (some NAS volumes, network filesystems).
    Unsupported,
}

/// Pure mapping of `File::try_lock`'s result. Any error other than "unsupported" is
/// a real I/O error and is returned as such.
pub(crate) fn classify_try_lock(r: Result<(), TryLockError>) -> Result<LockProbe, std::io::Error> {
    match r {
        Ok(()) => Ok(LockProbe::Acquired),
        Err(TryLockError::WouldBlock) => Ok(LockProbe::HeldElsewhere),
        Err(TryLockError::Error(e)) if e.kind() == std::io::ErrorKind::Unsupported => {
            Ok(LockProbe::Unsupported)
        }
        Err(TryLockError::Error(e)) => Err(e),
    }
}

/// (device, inode) of a file. `None` where the platform does not expose it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct FileIdentity {
    dev: u64,
    ino: u64,
}

/// A file this DR created, told apart from any file another DR puts at the same
/// path. A remembered (dev, ino) does not do that: once a file is unlinked and
/// closed its inode number is free, and ext4 may hand it to the next file created —
/// another DR's draft would then look like ours. So this holds the file open and
/// takes its identity from the handle (fstat) at every check: an open inode is never
/// freed, so no other file can have that (dev, ino) while this value lives. The
/// handle is a separate open, not a clone of the creator's handle, so it takes no
/// part in the creator's (redb's) lock.
#[derive(Debug)]
pub(crate) struct OwnedFile {
    handle: File,
}

impl OwnedFile {
    /// Hold the file now at `path` if it is the file with identity `id`. `id` must
    /// come from a handle the caller holds open (so it cannot have been reused yet).
    /// `None`: the path names another file, or is gone.
    pub(crate) fn pin_if_same(path: &Path, id: FileIdentity) -> Option<OwnedFile> {
        let owned = OwnedFile::pin(path)?;
        (owned.identity() == Some(id)).then_some(owned)
    }

    /// Hold the file now at `path` (just written by this run through its path).
    /// `None` where the platform has no file identity.
    pub(crate) fn pin(path: &Path) -> Option<OwnedFile> {
        let owned = OwnedFile {
            handle: File::open(path).ok()?,
        };
        owned.identity().is_some().then_some(owned)
    }

    fn identity(&self) -> Option<FileIdentity> {
        file_identity(&self.handle.metadata().ok()?)
    }
}

pub(crate) fn file_identity(meta: &std::fs::Metadata) -> Option<FileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(FileIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

/// True when `path` names the file `owned`. With no identity: on a platform without
/// inodes the claim is trusted as long as the path exists; on unix (the identity
/// could not be taken) nothing is proven ours.
pub(crate) fn path_is(path: &Path, owned: Option<&OwnedFile>) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => match owned {
            Some(owned) => owned
                .identity()
                .is_some_and(|id| file_identity(&meta) == Some(id)),
            None => !cfg!(unix),
        },
        Err(_) => false,
    }
}

/// True when the open `file` is the file `owned` (same rule as `path_is` without
/// an identity).
pub(crate) fn handle_is(file: &File, owned: Option<&OwnedFile>) -> bool {
    match owned {
        Some(owned) => file
            .metadata()
            .ok()
            .and_then(|m| file_identity(&m))
            .is_some_and(|id| owned.identity() == Some(id)),
        None => !cfg!(unix),
    }
}

/// Holds the lock on an existing `db.redb` for the whole DR (`None` if there was no
/// DB or the filesystem has no locks).
#[derive(Debug)]
pub(crate) struct DataDirLock {
    pub(crate) db: Option<File>,
}

/// The staging DB file this DR created and locked. Only its creator may delete it.
#[derive(Debug)]
pub(crate) struct StagingClaim {
    /// Taken by `Db::create_from_file`; redb keeps the lock from then on.
    pub(crate) file: Option<File>,
    /// `None` only where the platform has no file identity.
    pub(crate) id: Option<OwnedFile>,
}

/// Everything preflight decided; consumed by `commit`, cleaned up by `abort`.
/// (No `Debug` outside tests: the keyfile holds the phrase.)
#[cfg_attr(test, derive(Debug))]
pub(crate) struct DrPlan {
    pub(crate) paths: DrPaths,
    pub(crate) keyfile: IdentityKeyFile,
    pub(crate) key_source: KeySource,
    pub(crate) lock: DataDirLock,
    pub(crate) staging: StagingClaim,
    /// Set by `stage_key` when THIS run wrote `identity.key.dr-new`.
    pub(crate) staged_key: Option<Option<OwnedFile>>,
    /// Warnings already decided to continue with (printed by `run_dr`).
    pub(crate) warnings: Vec<String>,
}

impl DrPlan {
    /// `KeySource::New`: write the phrase's keyfile to `identity.key.dr-new` before
    /// the network phase, so the commit needs no disk space for it.
    pub(crate) fn stage_key(&mut self) -> Result<(), DrError> {
        if self.key_source != KeySource::New {
            return Ok(());
        }
        write_keyfile_at(&self.paths.key_staging, &self.keyfile).map_err(|e| {
            failed(format!(
                "cannot write {}: {e}",
                self.paths.key_staging.display()
            ))
        })?;
        self.staged_key = Some(OwnedFile::pin(&self.paths.key_staging));
        Ok(())
    }
}

fn failed(reason: String) -> DrError {
    DrError::Failed {
        reason,
        hint: String::new(),
    }
}

fn dir_str(p: &Path) -> String {
    p.display().to_string()
}

/// Run the preflight for a DR of `phrase` into `data_dir`. See the module doc for the
/// order. On `Err` the folder is exactly as it was (at most the empty data dir was
/// created).
pub(crate) fn preflight(data_dir: &Path, phrase: &str) -> Result<DrPlan, DrError> {
    // 1. The phrase, before any disk access.
    let mnemonic = parse_mnemonic(phrase).map_err(|e| match e {
        IdentityError::InvalidMnemonic(p) => DrError::InvalidPhrase(p),
        other => DrError::InvalidPhrase(MnemonicProblem::Other(other.to_string())),
    })?;
    // 2. The phrase's keyfile, in memory.
    let phrase_kf = build_keyfile(&mnemonic, DeviceSeedMode::DerivedFromSeed)
        .map_err(|e| failed(format!("cannot derive keys from the phrase: {e}")))?;

    // 3. The data dir.
    let paths = DrPaths::new(data_dir);
    std::fs::create_dir_all(data_dir)
        .map_err(|e| failed(format!("cannot create {}: {e}", data_dir.display())))?;
    let mut warnings = Vec::new();

    // 4. A live daemon (or another DR) holds db.redb.
    let lock = probe_db_lock(&paths, &mut warnings)?;

    // 5. The key in the folder must be the phrase's.
    let (keyfile, key_source) = match load_identity(data_dir) {
        Err(IdentityError::NotInitialized) => (phrase_kf, KeySource::New),
        Err(IdentityError::Corrupt(_, reason)) => {
            return Err(DrError::KeyfileUnreadable {
                data_dir: dir_str(data_dir),
                reason,
            });
        }
        Err(e) => {
            return Err(DrError::KeyfileUnreadable {
                data_dir: dir_str(data_dir),
                reason: e.to_string(),
            });
        }
        Ok(kf) => {
            check_keyfile_consistent(&kf).map_err(|reason| DrError::KeyfileUnreadable {
                data_dir: dir_str(data_dir),
                reason,
            })?;
            if kf.seed != phrase_kf.seed {
                return Err(DrError::ForeignIdentity {
                    data_dir: dir_str(data_dir),
                    folder: hex_encode(&kf.identity_pub),
                    phrase: hex_encode(&phrase_kf.identity_pub),
                });
            }
            (kf, KeySource::Existing)
        }
    };

    // 6. Claim the staging DB (the first write DR makes).
    let staging = claim_staging(&paths, &mut warnings)?;

    let mut plan = DrPlan {
        paths,
        keyfile,
        key_source,
        lock,
        staging,
        staged_key: None,
        warnings,
    };

    // 7. A key draft left by a killed DR is ours now: we hold the staging DB.
    match std::fs::remove_file(&plan.paths.key_staging) {
        Ok(()) => tracing::info!(
            path = %plan.paths.key_staging.display(),
            "dr: removed a key draft left by an interrupted DR"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            let err = failed(format!(
                "cannot remove {}: {e}",
                plan.paths.key_staging.display()
            ));
            super::commit::abort(&mut plan);
            return Err(err);
        }
    }
    Ok(plan)
}

/// Step 4: lock probe on an existing `db.redb`.
fn probe_db_lock(paths: &DrPaths, warnings: &mut Vec<String>) -> Result<DataDirLock, DrError> {
    let file = match OpenOptions::new().read(true).write(true).open(&paths.db) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DataDirLock { db: None });
        }
        Err(e) => return Err(failed(format!("cannot open {}: {e}", paths.db.display()))),
    };
    match classify_try_lock(file.try_lock()) {
        Ok(LockProbe::Acquired) => Ok(DataDirLock { db: Some(file) }),
        Ok(LockProbe::HeldElsewhere) => Err(DrError::DataDirInUse {
            data_dir: dir_str(&paths.data_dir),
        }),
        Ok(LockProbe::Unsupported) => {
            warnings.push(locks_unsupported_warning(&paths.data_dir));
            Ok(DataDirLock { db: None })
        }
        Err(e) => Err(failed(format!("cannot lock {}: {e}", paths.db.display()))),
    }
}

pub(crate) fn locks_unsupported_warning(data_dir: &Path) -> String {
    format!(
        "cannot check whether a Viaticum daemon uses {}: file locks are not supported on \
         this filesystem. Make sure it is stopped.",
        data_dir.display()
    )
}

/// Step 5 sanity: the stored identity and device id must follow from the stored seeds.
fn check_keyfile_consistent(kf: &IdentityKeyFile) -> Result<(), String> {
    let master = derive_master_key(&kf.seed).map_err(|e| format!("bad seed: {e}"))?;
    if master_identity(&master).0 != kf.identity_pub {
        return Err("its identity does not match its own seed".to_string());
    }
    let device = derive_device_key(&kf.seed, &kf.device_seed)
        .map_err(|e| format!("bad device seed: {e}"))?;
    if device.verifying_key().to_bytes() != kf.device_id {
        return Err("its device id does not match its own device seed".to_string());
    }
    Ok(())
}

/// Step 6: claim `db.redb.dr-new`.
fn claim_staging(paths: &DrPaths, warnings: &mut Vec<String>) -> Result<StagingClaim, DrError> {
    let in_progress = || DrError::DrInProgress {
        data_dir: dir_str(&paths.data_dir),
    };

    // 6a. A staging DB already there: another DR's (locked) or a killed DR's (free).
    match OpenOptions::new()
        .read(true)
        .write(true)
        .open(&paths.db_staging)
    {
        Ok(old) => match classify_try_lock(old.try_lock()) {
            Ok(LockProbe::HeldElsewhere) => return Err(in_progress()),
            Ok(LockProbe::Acquired) | Ok(LockProbe::Unsupported) => {
                drop(old);
                match std::fs::remove_file(&paths.db_staging) {
                    Ok(()) => tracing::info!(
                        path = %paths.db_staging.display(),
                        "dr: removed a staging DB left by an interrupted DR"
                    ),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(failed(format!(
                            "cannot remove {}: {e}",
                            paths.db_staging.display()
                        )));
                    }
                }
            }
            Err(e) => {
                return Err(failed(format!(
                    "cannot lock {}: {e}",
                    paths.db_staging.display()
                )));
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(failed(format!(
                "cannot open {}: {e}",
                paths.db_staging.display()
            )));
        }
    }

    // 6b. Atomic creation: of two concurrent DRs exactly one gets the file.
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&paths.db_staging)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(in_progress()),
        Err(e) => {
            return Err(failed(format!(
                "cannot create {}: {e}",
                paths.db_staging.display()
            )));
        }
    };
    let id = file.metadata().ok().and_then(|m| file_identity(&m));

    // 6c. Lock it. Held elsewhere = another DR's 6a got it first: it is theirs to
    // remove, not ours.
    match classify_try_lock(file.try_lock()) {
        Ok(LockProbe::Acquired) => {}
        Ok(LockProbe::HeldElsewhere) => return Err(in_progress()),
        Ok(LockProbe::Unsupported) => {
            let w = locks_unsupported_warning(&paths.data_dir);
            if !warnings.contains(&w) {
                warnings.push(w);
            }
        }
        Err(e) => {
            return Err(failed(format!(
                "cannot lock {}: {e}",
                paths.db_staging.display()
            )));
        }
    }
    // Another DR's 6a may have removed our fresh file before we locked it and put
    // its own at the path: then the path is no longer ours. `file` is still open,
    // so `id` cannot belong to another file yet; the pin keeps it that way.
    let owned = match id {
        Some(id) => match OwnedFile::pin_if_same(&paths.db_staging, id) {
            Some(owned) => Some(owned),
            None => return Err(in_progress()),
        },
        None if paths.db_staging.exists() => None,
        None => return Err(in_progress()),
    };
    Ok(StagingClaim {
        file: Some(file),
        id: owned,
    })
}
