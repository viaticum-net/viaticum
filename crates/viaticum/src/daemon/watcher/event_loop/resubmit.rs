// The backup reconcile's paths (L1b: backup-i8, backup-i25; W2 of the intent review).
//
// The reconcile knows the catalog, the watcher knows the roots: a path comes back as
// `Modified` only when its root is not under the root rule and its identity is the recorded
// one (`RootCheck::Same`; a root whose watch failed is scanned and takes it too), it passes the scan filters (`should_watch_path`, no Viaticum data dir
// between the root and it, a symlink only to a file outside data dirs) and it is a file on
// disk. Everything else is only counted (INV-RC: the reconcile never deletes, and a root in
// error or replaced never re-reads or confirms what lies under it, dr-i64).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use super::super::{data_dir_between, should_watch_path, symlink_into_data_dir};
use super::{Closed, RootCheck, WatchLoop};
use crate::daemon::backup::DirtyKind;
use crate::daemon::backup::reconcile::{ResubmitBatch, ResubmitReason};

/// What one batch did under one root.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResubmitCounts {
    /// Re-submitted: a pending version in no queue.
    pub pending: u32,
    /// Re-submitted: the current block is being released or missing.
    pub releasing: u32,
    /// Not on disk.
    pub gone: u32,
    /// Outside every root, ignored, hidden, in a data dir, or not a regular file.
    pub filtered: u32,
    /// The root is under the root rule (lost) or not the recorded directory.
    pub root_unavailable: u32,
}

/// The per-root key of a path under no root.
const NO_ROOT: &str = "(none)";

/// How one path is answered.
enum Verdict {
    Emit,
    Gone,
    Filtered,
    RootUnavailable,
}

impl WatchLoop {
    /// Re-submit what the reconcile handed over; one INFO line per root with its counts.
    /// Returns the counts per root (the key is the root, or `(none)`).
    pub(crate) async fn on_resubmit(
        &mut self,
        batch: ResubmitBatch,
    ) -> Result<BTreeMap<String, ResubmitCounts>, Closed> {
        let ig = self.ignore.load_full();
        let mut data_dirs: HashMap<PathBuf, bool> = HashMap::new();
        let mut counts: BTreeMap<String, ResubmitCounts> = BTreeMap::new();
        for (path, reason) in batch.items {
            let root = ig.root_of(&path).map(Path::to_path_buf);
            let key = root
                .as_ref()
                .map_or_else(|| NO_ROOT.to_string(), |r| r.display().to_string());
            let verdict = match &root {
                None => Verdict::Filtered,
                Some(root) => self.resubmit_verdict(root, &path, &ig, &mut data_dirs),
            };
            let c = counts.entry(key).or_default();
            match verdict {
                Verdict::Emit => {
                    match reason {
                        ResubmitReason::Pending => c.pending += 1,
                        ResubmitReason::Releasing => c.releasing += 1,
                    }
                    self.emit(&path, DirtyKind::Modified).await?;
                }
                Verdict::Gone => c.gone += 1,
                Verdict::Filtered => c.filtered += 1,
                Verdict::RootUnavailable => c.root_unavailable += 1,
            }
        }
        for (root, c) in &counts {
            tracing::info!(
                root = %root,
                pending = c.pending,
                releasing = c.releasing,
                gone = c.gone,
                filtered = c.filtered,
                root_unavailable = c.root_unavailable,
                "reconcile: resubmitted"
            );
        }
        Ok(counts)
    }

    fn resubmit_verdict(
        &self,
        root: &Path,
        path: &Path,
        ig: &super::super::IgnoreSet,
        data_dirs: &mut HashMap<PathBuf, bool>,
    ) -> Verdict {
        // A root whose watch failed (inotify limit, an unreadable subfolder) but is the
        // recorded directory is scanned, so it takes a resubmit too (backup-i25 / backup-i8,
        // 2026-09-30); a lost or replaced root does not (dr-i64).
        if self.lost.contains(root) || self.check_root(root) != RootCheck::Same {
            return Verdict::RootUnavailable;
        }
        if !should_watch_path(path, ig) || data_dir_between(root, path, data_dirs) {
            return Verdict::Filtered;
        }
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Verdict::Gone,
            Err(_) => Verdict::Filtered,
            Ok(m) if m.file_type().is_symlink() => {
                let to_file = path.metadata().is_ok_and(|t| t.is_file());
                if to_file && !symlink_into_data_dir(path, data_dirs) {
                    Verdict::Emit
                } else {
                    Verdict::Filtered
                }
            }
            Ok(m) if m.is_file() => Verdict::Emit,
            Ok(_) => Verdict::Filtered,
        }
    }
}
