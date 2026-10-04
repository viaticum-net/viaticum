// Watch root identity (dr-i64): which directory a watch root is, so that a root that
// vanished or was replaced is never read as "every file under it was deleted".
//
// Unix: (st_dev, st_ino, creation time), compared as (inode, creation time) when both
// creation times are known (the device number is unstable, see `RootId::same_dir`),
// else as (device, inode); Windows: the directory's creation time only —
// the file index needs an open handle on stable Rust, so a folder replaced by a copy
// that kept its creation time is not recognised there (boundary of dr-i64, A17). Read
// from `std::fs::metadata`: no descriptor is held, so the root can be unmounted (К8).
// Persisted in `<data_dir>/watch_roots.json` (tmp + rename), so a root changed while
// the daemon was down is caught at the next start. An empty directory is never recorded
// as a root's identity (an unmounted mount point).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// File under the data dir holding the identity of every watch root.
pub(crate) const WATCH_ROOTS_FILE: &str = "watch_roots.json";

/// The identity of a watch root directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct RootId {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    /// Creation time as (seconds, nanoseconds) since the epoch (statx btime on Linux);
    /// `None` on a file system that does not keep one.
    created: Option<(u64, u32)>,
}

impl RootId {
    /// The identity of directory `dir`, or `None` when it is missing or not a directory.
    pub(crate) fn of(dir: &Path) -> Option<RootId> {
        let meta = std::fs::metadata(dir).ok()?;
        if !meta.is_dir() {
            return None;
        }
        let created = meta
            .created()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| (d.as_secs(), d.subsec_nanos()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Some(RootId {
                dev: meta.dev(),
                ino: meta.ino(),
                created,
            })
        }
        #[cfg(not(unix))]
        {
            Some(RootId { created })
        }
    }

    /// Both describe the same directory.
    ///
    /// Unix: when both creation times are known, (inode, creation time) decide and the
    /// device number is ignored — `st_dev` changes on USB re-enumeration, a dm/LUKS
    /// reorder, btrfs subvolumes' anonymous devices or an NFS remount while the directory
    /// is the same, and every false "changed" costs the undo of the folder's recent
    /// deletions (delete-i12 (а), L0 review W1). Without a creation time on either side:
    /// (device, inode). Windows: the creation time only (A17).
    pub(crate) fn same_dir(&self, other: &RootId) -> bool {
        #[cfg(unix)]
        {
            match (self.created, other.created) {
                (Some(a), Some(b)) => self.ino == other.ino && a == b,
                _ => self.dev == other.dev && self.ino == other.ino,
            }
        }
        #[cfg(not(unix))]
        {
            match (self.created, other.created) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
        }
    }
}

#[cfg(all(test, unix))]
impl RootId {
    /// An identity with the given fields (unit tests of `same_dir`).
    pub(crate) fn for_test(dev: u64, ino: u64, created: Option<(u64, u32)>) -> RootId {
        RootId { dev, ino, created }
    }
}

/// `dir` exists, is a directory and has at least one entry. An empty directory is never
/// taken as a new root identity: it is what an unmounted mount point looks like (Р-13).
pub(crate) fn non_empty_dir(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RootEntry {
    path: String,
    id: RootId,
}

/// The recorded identity of every watch root, mirrored in `watch_roots.json`.
pub(crate) struct RootStore {
    file: PathBuf,
    ids: BTreeMap<PathBuf, RootId>,
}

impl RootStore {
    /// Load `<data_dir>/watch_roots.json`. A missing file is an empty store; an
    /// unreadable one too (WARN) — its roots are then recorded anew, which only costs
    /// the confirmation of their records if one of them changed meanwhile.
    pub(crate) fn load(data_dir: &Path) -> RootStore {
        let file = data_dir.join(WATCH_ROOTS_FILE);
        let ids = match std::fs::read(&file) {
            Ok(bytes) => match serde_json::from_slice::<Vec<RootEntry>>(&bytes) {
                Ok(entries) => entries
                    .into_iter()
                    .map(|e| (PathBuf::from(e.path), e.id))
                    .collect(),
                Err(e) => {
                    tracing::warn!(file = %file.display(), error = %e,
                        "watcher: watch_roots.json unreadable; roots recorded anew");
                    BTreeMap::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => {
                tracing::warn!(file = %file.display(), error = %e,
                    "watcher: watch_roots.json unreadable; roots recorded anew");
                BTreeMap::new()
            }
        };
        RootStore { file, ids }
    }

    pub(crate) fn get(&self, root: &Path) -> Option<&RootId> {
        self.ids.get(root)
    }

    /// Record the identity of `root` and write the file.
    pub(crate) fn set(&mut self, root: &Path, id: RootId) {
        if self.ids.get(root) != Some(&id) {
            self.ids.insert(root.to_path_buf(), id);
            self.save();
        }
    }

    /// Forget `root` and write the file.
    pub(crate) fn remove(&mut self, root: &Path) {
        if self.ids.remove(root).is_some() {
            self.save();
        }
    }

    /// Keep only the roots in `roots` (a root dropped from the config while down).
    pub(crate) fn retain(&mut self, roots: &[PathBuf]) {
        let before = self.ids.len();
        self.ids.retain(|p, _| roots.contains(p));
        if self.ids.len() != before {
            self.save();
        }
    }

    /// Atomic write (tmp + rename). A failure is a WARN: the store stays right in
    /// memory; at the next start the roots count as new (safe: nothing is deleted).
    fn save(&self) {
        let entries: Vec<RootEntry> = self
            .ids
            .iter()
            .filter_map(|(p, id)| {
                p.to_str().map(|s| RootEntry {
                    path: s.to_string(),
                    id: *id,
                })
            })
            .collect();
        let tmp = self.file.with_extension("json.tmp");
        let result = serde_json::to_vec_pretty(&entries)
            .map_err(std::io::Error::other)
            .and_then(|bytes| std::fs::write(&tmp, bytes))
            .and_then(|()| std::fs::rename(&tmp, &self.file));
        if let Err(e) = result {
            tracing::warn!(file = %self.file.display(), error = %e,
                "watcher: cannot write watch_roots.json; roots count as new at the next start");
        }
    }
}
