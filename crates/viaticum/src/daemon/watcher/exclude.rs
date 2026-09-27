// What never enters the backup through the watcher, whatever the friend watches
// (backup-i13, backup-i14):
//
// - a Viaticum data directory (this node's, a sibling's, one left behind by a move
//   or a DR) found at or below a watch root: its database, the symbols it holds for
//   friends, restore staging, retained SystemState blobs, the identity key;
// - anything with a hidden component (name starting with '.') below the watch root;
// - a symlink to a file whose target lies in a data dir (backup-i16).
//
// The same functions serve the scan and the live events, so what the scan skips a
// live change cannot bring in (W-5).

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use crate::daemon::identity::{
    self, DB_FILE_NAME, HOLDINGS_DIR_NAME, KEYFILE_NAME, RESTORE_STAGING_DIR_NAME,
    SYMBOLS_DIR_NAME, SYSTEM_STATE_DIR_NAME,
};

/// Daemon-owned subdirectories of a data directory; a watch folder inside one is
/// refused. A folder elsewhere inside a data dir is allowed (every E2E watches
/// `<data-dir>/files`).
pub(crate) const DAEMON_STORAGE_DIRS: [&str; 4] = [
    HOLDINGS_DIR_NAME,
    SYMBOLS_DIR_NAME,
    RESTORE_STAGING_DIR_NAME,
    SYSTEM_STATE_DIR_NAME,
];

/// Largest `identity.key` we parse to recognize a data dir (the real one is a few
/// hundred bytes); a bigger file of that name is not ours.
const KEYFILE_MAX_BYTES: u64 = 64 * 1024;

/// True if `dir` is a Viaticum data directory: it holds `identity.key` as a regular
/// file and either `db.redb` next to it, or an `identity.key` that parses as an
/// `IdentityKeyFile`. The second form covers the window between `init` and the
/// first daemon start (no `db.redb` yet); the first covers a key we cannot read
/// (another user's data dir, mode 0600). Follows symlinks.
pub(crate) fn is_viaticum_data_dir(dir: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(dir.join(KEYFILE_NAME)) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    if dir.join(DB_FILE_NAME).is_file() {
        return true;
    }
    meta.len() <= KEYFILE_MAX_BYTES && identity::load_identity(dir).is_ok()
}

/// Why a watch folder is refused (backup-i13). `Display` is the friend-facing text,
/// shown by `POST /api/watches` and as the folder's error in `/api/watches`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FolderRefusal {
    IsDataDir,
    InsideDaemonStorage,
}

impl std::fmt::Display for FolderRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FolderRefusal::IsDataDir => {
                write!(
                    f,
                    "this is a Viaticum data directory; it is never backed up"
                )
            }
            FolderRefusal::InsideDaemonStorage => write!(
                f,
                "inside Viaticum's own storage (holdings/symbols/restore/system_state); \
                 it is never backed up"
            ),
        }
    }
}

/// Refuse a watch folder that IS a data dir, or lies in holdings/symbols/restore/
/// system_state of the NEAREST data dir among its ancestors. Canonicalizes when
/// possible, so a symlink pointing into daemon storage is refused too.
pub(crate) fn refuse_folder(folder: &Path) -> Option<FolderRefusal> {
    let canon = std::fs::canonicalize(folder).unwrap_or_else(|_| folder.to_path_buf());
    if is_viaticum_data_dir(&canon) {
        return Some(FolderRefusal::IsDataDir);
    }
    for ancestor in canon.ancestors().skip(1) {
        if !is_viaticum_data_dir(ancestor) {
            continue;
        }
        let below = canon
            .strip_prefix(ancestor)
            .ok()
            .and_then(|rel| rel.components().next());
        return match below {
            Some(Component::Normal(name))
                if DAEMON_STORAGE_DIRS
                    .iter()
                    .any(|d| name == std::ffi::OsStr::new(d)) =>
            {
                Some(FolderRefusal::InsideDaemonStorage)
            }
            _ => None,
        };
    }
    None
}

/// True if some component of `path` strictly below `root` (the file name included)
/// starts with '.'. The root itself may lie inside a hidden directory
/// (`~/.local/share/Photos` can be watched). A `path` outside `root` is judged by
/// its file name alone.
pub(crate) fn has_hidden_component_below(root: &Path, path: &Path) -> bool {
    let is_hidden = |name: &std::ffi::OsStr| name.to_string_lossy().starts_with('.');
    match path.strip_prefix(root) {
        Ok(rel) => rel
            .components()
            .any(|c| matches!(c, Component::Normal(name) if is_hidden(name))),
        Err(_) => path.file_name().is_some_and(is_hidden),
    }
}

/// True if a directory from `path`'s parent up to AND including `root` is a Viaticum
/// data dir. Nothing above `root` is looked at (a folder inside a data dir, like
/// `<data-dir>/files`, is a normal folder). `cache` memoizes per directory; the
/// caller scopes it (one flush of live events).
pub(crate) fn data_dir_between(
    root: &Path,
    path: &Path,
    cache: &mut HashMap<PathBuf, bool>,
) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    for dir in parent.ancestors() {
        if !dir.starts_with(root) {
            break;
        }
        let hit = *cache
            .entry(dir.to_path_buf())
            .or_insert_with(|| is_viaticum_data_dir(dir));
        if hit {
            return true;
        }
    }
    false
}

/// True if `link` (a symlink to a file) resolves into a Viaticum data dir: some
/// ancestor of its canonical target is one (backup-i16). Only called for symlinks,
/// so a plain file costs no canonicalization. `cache` as in [`data_dir_between`].
pub(crate) fn symlink_into_data_dir(link: &Path, cache: &mut HashMap<PathBuf, bool>) -> bool {
    let Ok(target) = std::fs::canonicalize(link) else {
        return false;
    };
    let Some(top) = target.ancestors().last() else {
        return false;
    };
    data_dir_between(top, &target, cache)
}

/// Identity of a directory for loop detection during a scan: `(st_dev, st_ino)` on
/// unix, the canonical path elsewhere.
#[cfg(unix)]
pub(crate) type DirKey = (u64, u64);
#[cfg(not(unix))]
pub(crate) type DirKey = PathBuf;

#[cfg(unix)]
pub(crate) fn dir_key(dir: &Path) -> Option<DirKey> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(dir).ok().map(|m| (m.dev(), m.ino()))
}

#[cfg(not(unix))]
pub(crate) fn dir_key(dir: &Path) -> Option<DirKey> {
    std::fs::canonicalize(dir).ok()
}
