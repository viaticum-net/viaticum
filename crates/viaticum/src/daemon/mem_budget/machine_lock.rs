// The machine's block work lock (К-b3, restore-i39; spec v3.9a #4).
//
// Block work (encode, decode) of ALL viaticum processes of one user on one machine draws on one
// RAM, and each process has its budget `M·14/32`. A node and a `viaticum dr` on the same machine
// would add up to twice that. They meet at ONE file, `/tmp/viaticum-<uid>/blockwork.lock`, which
// is locked exclusively (`flock`) by whoever works on blocks:
//
//   * the node holds it for its whole life and writes `{kind: daemon, pid, data_dir}` — where its
//     `api-port` and `api-token` are, so a DR can ask it for a lease;
//   * a `viaticum dr` that finds it free takes it, writes `{kind: dr, pid}`, works on its own
//     budget and keeps the lock to the end; a node that starts meanwhile brings the network and
//     the API up but opens its budget only when the lock comes free (`start_daemon_budget`,
//     `spawn_keeper`);
//   * a `viaticum dr` that finds it held by a node leases memory from that node.
//
// The path depends on the uid only, never on `TMPDIR` or `XDG_RUNTIME_DIR` (a process with another
// environment must meet the same file; M73). The directory is created 0700; a directory that is
// not ours, or is open to others, is not trusted (`Unavailable`): the caller works without the
// lock, as two nodes on one machine do (outside the border of the promise).

use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::MemBudget;

/// The lock file inside [`machine_lock_dir`].
pub const LOCK_FILE_NAME: &str = "blockwork.lock";

/// How often a node (or a waiting DR) tries the lock again.
pub const RETRY_EVERY: Duration = Duration::from_secs(5);

/// Who holds the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockKind {
    Dr,
    Daemon,
}

/// What the holder writes in the lock file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LockRecord {
    pub kind: LockKind,
    pub pid: u32,
    /// The node's data directory: its `api-port` and `api-token` are there (the CLI protocol of
    /// the node). Absent for a DR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<String>,
}

impl LockRecord {
    pub fn dr() -> Self {
        LockRecord {
            kind: LockKind::Dr,
            pid: std::process::id(),
            data_dir: None,
        }
    }

    pub fn daemon(data_dir: &Path) -> Self {
        LockRecord {
            kind: LockKind::Daemon,
            pid: std::process::id(),
            data_dir: Some(data_dir.to_string_lossy().into_owned()),
        }
    }
}

/// The lock, held: dropping it (or the process ending) releases it.
#[derive(Debug)]
pub struct MachineLock {
    _file: File,
}

/// What a try of the lock found.
#[derive(Debug)]
pub enum LockOutcome {
    Acquired(MachineLock),
    /// Held by another process; its record, when it could be read.
    HeldElsewhere(Option<LockRecord>),
    /// The lock cannot be used (the directory is not ours, or an I/O error): work without it.
    Unavailable(String),
}

/// The uid of this process.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn current_uid() -> u32 {
    0
}

/// The directory of the lock for `uid`. `env` is deliberately NOT consulted: the seam is here so
/// that a unit proves the path is the same under any environment (M73).
pub fn lock_dir_with(uid: u32, env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    let _ = env;
    lock_dir_of(uid)
}

#[cfg(unix)]
fn lock_dir_of(uid: u32) -> PathBuf {
    PathBuf::from(format!("/tmp/viaticum-{uid}"))
}

#[cfg(not(unix))]
fn lock_dir_of(uid: u32) -> PathBuf {
    std::env::temp_dir().join(format!("viaticum-{uid}"))
}

/// The directory of the lock of this user on this machine.
pub fn machine_lock_dir() -> PathBuf {
    lock_dir_with(current_uid(), &|k| std::env::var(k).ok())
}

/// `dir` exists, is ours and closed to others, or is created so (0700).
#[cfg(unix)]
fn prepare_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    for _ in 0..2 {
        match std::fs::symlink_metadata(dir) {
            Ok(m) => {
                if !m.is_dir() {
                    return Err(format!("{} is not a directory", dir.display()));
                }
                if m.uid() != current_uid() {
                    return Err(format!("{} belongs to another user", dir.display()));
                }
                if m.mode() & 0o077 != 0 {
                    return Err(format!(
                        "{} is open to other users (mode {:o})",
                        dir.display(),
                        m.mode() & 0o777
                    ));
                }
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::DirBuilder::new().mode(0o700).create(dir) {
                    Ok(()) => {}
                    // Created by somebody meanwhile: judge it on the next turn.
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(format!("cannot create {}: {e}", dir.display())),
                }
            }
            Err(e) => return Err(format!("cannot read {}: {e}", dir.display())),
        }
    }
    Err(format!("{} keeps changing", dir.display()))
}

#[cfg(not(unix))]
fn prepare_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))
}

/// The record in the lock file, read again a few times: the holder writes it right after it
/// locks, and a reader may come in between.
fn read_record(path: &Path) -> Option<LockRecord> {
    for attempt in 0..5 {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(record) = serde_json::from_str::<LockRecord>(text.trim())
        {
            return Some(record);
        }
        if attempt < 4 {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    None
}

/// Try the lock in `dir` once. Blocking (a file, a few milliseconds).
pub fn try_lock(dir: &Path, record: &LockRecord) -> LockOutcome {
    if let Err(why) = prepare_dir(dir) {
        return LockOutcome::Unavailable(why);
    }
    let path = dir.join(LOCK_FILE_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(&path) {
        Ok(f) => f,
        Err(e) => return LockOutcome::Unavailable(format!("cannot open {}: {e}", path.display())),
    };
    match file.try_lock() {
        Ok(()) => {
            let text = match serde_json::to_string(record) {
                Ok(t) => t,
                Err(e) => return LockOutcome::Unavailable(format!("lock record: {e}")),
            };
            let written = file
                .set_len(0)
                .and_then(|()| (&file).write_all(text.as_bytes()));
            match written {
                Ok(()) => LockOutcome::Acquired(MachineLock { _file: file }),
                Err(e) => LockOutcome::Unavailable(format!("cannot write {}: {e}", path.display())),
            }
        }
        Err(TryLockError::WouldBlock) => LockOutcome::HeldElsewhere(read_record(&path)),
        Err(TryLockError::Error(e)) => {
            LockOutcome::Unavailable(format!("cannot lock {}: {e}", path.display()))
        }
    }
}

/// What the node found at start.
#[derive(Debug)]
pub enum Startup {
    /// The node holds the lock.
    Owns(MachineLock),
    /// A DR holds it: the budget starts closed, the keeper opens it when the DR is done.
    DrHolds,
    /// Another node of this user holds it (outside the border of the promise): works as before.
    OtherNode,
    /// No lock to be had (see the WARN): works as before.
    NoLock,
}

/// The budget of a node that starts now: `total_bytes`, closed while a DR holds the machine's
/// lock (INFO once), open otherwise. Takes the lock when it is free (spec v3.9a #4).
pub fn start_daemon_budget(
    total_bytes: u64,
    dir: &Path,
    record: &LockRecord,
) -> (Arc<MemBudget>, Startup) {
    match try_lock(dir, record) {
        LockOutcome::Acquired(lock) => (MemBudget::new(total_bytes), Startup::Owns(lock)),
        LockOutcome::HeldElsewhere(Some(held)) if held.kind == LockKind::Dr => {
            tracing::info!("memory: DR is running on this machine; block work waits for it");
            (MemBudget::new_closed(total_bytes), Startup::DrHolds)
        }
        LockOutcome::HeldElsewhere(_) => {
            tracing::warn!(
                "memory: another node of this user holds this machine's block work lock; this \
                 node works as it did before, with a budget of its own"
            );
            (MemBudget::new(total_bytes), Startup::OtherNode)
        }
        LockOutcome::Unavailable(why) => {
            tracing::warn!(
                "memory: this machine's block work lock is not used ({why}); this node works \
                 with a budget of its own"
            );
            (MemBudget::new(total_bytes), Startup::NoLock)
        }
    }
}

/// Keeps the node's hold on the lock for its life. While the node does not hold it, tries it
/// every `retry` (blocking calls on the blocking pool); on success opens the budget (a DR that
/// held it has ended) and keeps it until `cancel`.
pub fn spawn_keeper(
    startup: Startup,
    dir: PathBuf,
    record: LockRecord,
    budget: Arc<MemBudget>,
    cancel: CancellationToken,
    retry: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut held = match startup {
            Startup::Owns(lock) => Some(lock),
            _ => None,
        };
        while held.is_none() {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(retry) => {}
            }
            let (d, r) = (dir.clone(), record.clone());
            let outcome = tokio::task::spawn_blocking(move || try_lock(&d, &r)).await;
            if let Ok(LockOutcome::Acquired(lock)) = outcome {
                held = Some(lock);
                if budget.is_closed() {
                    tracing::info!("memory: DR has finished; block work starts");
                }
                budget.open();
            }
        }
        cancel.cancelled().await;
        drop(held);
    })
}
