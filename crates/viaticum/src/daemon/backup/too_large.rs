// Too-large marks (backup-i4, backup-i7): the coordinator's side of "a file above this
// machine's limit is not backed up and is shown as such".
//
// A mark is a node-local row (`Db::{put,get,remove,list}_too_large`): path, size, limit, first
// and last seen. It is written by `mark_too_large` (an Added/Modified event, a flush that
// found the file grown, the start pass) and removed when the file is evaluated within the
// limit again, when its path is deleted, or when the start pass finds it missing or outside
// the watch directories. `RootLost` / `RootChanged` leave marks alone: they say nothing
// about a file's size. Nothing here touches the catalog beyond what the evaluation of the
// file itself does (a pending edit is superseded, the file is confirmed on disk).

use std::path::{Path, PathBuf};

use viaticum_core::config::expand_watch_path;
use viaticum_core::types::{Timestamp, TooLargeMark};

use super::gone::path_gone;
use super::{BackupCoordinator, DirtyEvent, DirtyKind};

impl BackupCoordinator {
    /// `path` is `size` bytes, above the limit: the mark is written and the file is left
    /// alone. A new mark, or one written at another limit → WARN "file too large to back up
    /// on this machine" (one per appearance or change of the limit, J7); the same limit
    /// again (a touch, a rescan) → DEBUG "too large, mark unchanged".
    ///
    /// An existing record loses its pending edit (and its queue entry, L1) and is
    /// confirmed on disk; its backed-up versions stay: the network keeps the earlier
    /// content (backup-i7). A failed write of the mark is an ERROR: the file is not backed
    /// up either way.
    pub(super) fn mark_too_large(&mut self, path: &str, size: u64) {
        let limit = self.config.max_file_size_bytes;
        let now = Timestamp::now();
        let previous = match self.db.get_too_large(path) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(path = %path, err = %e, "backup: cannot read the too-large mark");
                None
            }
        };
        let mark = TooLargeMark {
            size_bytes: size,
            limit_bytes: limit,
            first_seen: previous.map_or(now, |m| m.first_seen),
            last_seen: now,
        };
        if let Err(e) = self.db.put_too_large(path, &mark) {
            tracing::error!(path = %path, err = %e,
                "backup: cannot record the too-large mark; the file is not backed up");
        }
        if previous.is_none_or(|m| m.limit_bytes != limit) {
            tracing::warn!(path = %path, size_bytes = size, limit_bytes = limit,
                "file too large to back up on this machine");
        } else {
            tracing::debug!(path = %path, size_bytes = size, limit_bytes = limit,
                "too large, mark unchanged");
        }

        match self.db.get_file(path) {
            Ok(Some(mut record)) => {
                let mut changed = self.supersede_pending(&mut record);
                if !record.on_disk_confirmed {
                    record.on_disk_confirmed = true;
                    changed = true;
                }
                // A record that held only the pending edit (the file was queued and grew
                // before its flush) has nothing left to point at: like a never-backed-up
                // deleted file (`mark_deleted`), it goes, and the mark is the file's only
                // trace.
                let device = self.config.device_id;
                let only_here = !record.devices.iter().any(|(d, _)| *d != device);
                let result = if record.versions.is_empty() && only_here {
                    self.db.delete_file(path)
                } else if changed {
                    self.db.upsert_file(&record)
                } else {
                    Ok(())
                };
                if let Err(e) = result {
                    tracing::error!(path = %path, err = %e,
                        "backup: cannot update the record of a too-large file");
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(path = %path, err = %e,
                    "backup: cannot read the record of a too-large file")
            }
        }
    }

    /// `path` was evaluated at or under the limit: its mark, if any, goes (INFO).
    pub(super) fn clear_too_large(&self, path: &str) {
        match self.db.remove_too_large(path) {
            Ok(true) => tracing::info!(path = %path,
                "file is within the size limit again, backing up"),
            Ok(false) => {}
            Err(e) => {
                tracing::error!(path = %path, err = %e, "backup: cannot remove the too-large mark")
            }
        }
    }

    /// A live `Deleted` event for `path`: its mark goes, and so do the marks of the paths
    /// under it as a directory whose file is gone (the marks have no catalog record to be
    /// found by, so the mark table is searched by prefix).
    pub(super) fn clear_too_large_of_deleted(&self, path: &str) {
        match self.db.remove_too_large(path) {
            Ok(true) => {
                tracing::debug!(path = %path, "backup: too-large mark dropped; path deleted")
            }
            Ok(false) => {}
            Err(e) => {
                tracing::error!(path = %path, err = %e, "backup: cannot remove the too-large mark")
            }
        }
        let slash = format!("{path}/");
        let native = format!("{path}{}", std::path::MAIN_SEPARATOR);
        let marks = match self.db.list_too_large() {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(err = %e, "backup: cannot list the too-large marks");
                return;
            }
        };
        for (marked, _) in marks {
            if (marked.starts_with(&slash) || marked.starts_with(&native))
                && path_gone(Path::new(&marked))
            {
                match self.db.remove_too_large(&marked) {
                    Ok(_) => tracing::debug!(path = %marked,
                        "backup: too-large mark dropped; directory deleted"),
                    Err(e) => tracing::error!(path = %marked, err = %e,
                        "backup: cannot remove the too-large mark"),
                }
            }
        }
    }

    /// The pass at the start of `run()` (backup-i4 doors: the limit was raised, the file
    /// left while the daemon was down, a folder was unwatched): every mark is judged again.
    ///
    /// - outside the watch directories → mark dropped;
    /// - the path is missing → mark dropped, the catalog untouched (dr-i63: a file that
    ///   vanished while the daemon was off is not a deletion event);
    /// - at or under the limit now → handed to the ordinary evaluation as `Modified`
    ///   (it removes the mark and backs the file up);
    /// - still above it → the mark is refreshed silently (no second WARN).
    ///
    /// One INFO with the counts.
    pub(super) fn reconcile_too_large_marks(&mut self) {
        let marks = match self.db.list_too_large() {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(err = %e, "backup: cannot list the too-large marks at start");
                return;
            }
        };
        if marks.is_empty() {
            return;
        }
        let roots = self.watch_roots();
        let limit = self.config.max_file_size_bytes;
        let (mut requeued, mut dropped_missing, mut dropped_outside, mut kept) =
            (0u32, 0u32, 0u32, 0u32);
        for (path, mark) in marks {
            let p = Path::new(&path);
            if !roots.iter().any(|root| p.starts_with(root)) {
                self.remove_mark_quietly(&path);
                dropped_outside += 1;
                continue;
            }
            match std::fs::metadata(p) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    self.remove_mark_quietly(&path);
                    dropped_missing += 1;
                }
                Err(e) => {
                    tracing::debug!(path = %path, err = %e,
                        "backup: too-large mark kept; the file cannot be examined");
                    kept += 1;
                }
                Ok(meta) if meta.len() <= limit => {
                    let event = DirtyEvent {
                        path: path.clone(),
                        kind: DirtyKind::Modified,
                        device_id: self.config.device_id,
                    };
                    match self.process_event(event) {
                        Ok(()) => requeued += 1,
                        Err(e) => {
                            tracing::warn!(path = %path, err = %format!("{e:#}"),
                                "backup: a file under the limit again could not be evaluated at start");
                            kept += 1;
                        }
                    }
                }
                Ok(meta) => {
                    let refreshed = TooLargeMark {
                        size_bytes: meta.len(),
                        limit_bytes: limit,
                        last_seen: Timestamp::now(),
                        ..mark
                    };
                    if let Err(e) = self.db.put_too_large(&path, &refreshed) {
                        tracing::error!(path = %path, err = %e,
                            "backup: cannot refresh the too-large mark");
                    }
                    kept += 1;
                }
            }
        }
        tracing::info!(
            requeued,
            dropped_missing,
            kept,
            dropped_outside,
            "too-large marks reconciled"
        );
    }

    fn remove_mark_quietly(&self, path: &str) {
        if let Err(e) = self.db.remove_too_large(path) {
            tracing::error!(path = %path, err = %e, "backup: cannot remove the too-large mark");
        }
    }

    /// The watch directories now (live config when wired), `~` expanded.
    fn watch_roots(&self) -> Vec<PathBuf> {
        let configs = match &self.config.live_watch_configs {
            Some(live) => live
                .read()
                .expect("live_watch_configs lock poisoned")
                .clone(),
            None => self.config.watch_configs.clone(),
        };
        configs
            .iter()
            .map(|wc| expand_watch_path(&wc.path))
            .collect()
    }
}
