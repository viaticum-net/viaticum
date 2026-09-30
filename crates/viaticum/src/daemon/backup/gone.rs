// Deletions (delete-i12, dr-i64): what the watcher reports as gone, and the root rule.
//
// A record becomes `Deleted` only (1) by a live event for a path the watcher found gone
// under an intact watch root (`Deleted`, also every record under a gone directory), or
// (2) by a recheck of a record confirmed on disk (`GoneOnRecheck`). A watch root that
// vanished or was replaced (`RootLost`, `RootChanged`) deletes nothing: recent deletions
// under it whose Delete is not out yet are undone, and its records lose the
// confirmation, so no recheck can delete them until a scan sees them again.

use std::collections::HashMap;
use std::path::Path;

use viaticum_core::constants::OWNER_DELETE_COOLDOWN_SECS;
use viaticum_core::db::Serviceability;
use viaticum_core::types::{DeviceId, FileRecord, LocalState, SourceBlockId, Timestamp};

use super::{BackupCoordinator, DirtyEvent, DirtyKind};

/// Records written per transaction by the root rule.
const ROOT_RULE_CHUNK: usize = 1000;

/// `path` is gone from disk: `symlink_metadata` answers NotFound. Any other answer (it
/// exists, or cannot be stat'ed) is "not gone" — no deletion on doubt.
pub(crate) fn path_gone(path: &Path) -> bool {
    matches!(
        std::fs::symlink_metadata(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    )
}

/// The state of `record` on `device`, if the device is in its list.
fn state_on(record: &FileRecord, device: DeviceId) -> Option<LocalState> {
    record
        .devices
        .iter()
        .find(|(d, _)| *d == device)
        .map(|(_, s)| *s)
}

impl BackupCoordinator {
    /// A live event: `event.path` is gone and its watch root is intact (the watcher
    /// checked both). The exact record, if Present on this device, is marked deleted;
    /// so is every record under `event.path` as a directory whose path is gone. A record
    /// already deleted keeps its timestamp (the window does not move). A path the
    /// catalog does not know leaves no trace: the only producer of events is this
    /// device's watcher (A18: `dirty_tx` has one sender), so no tombstone is needed.
    pub(super) fn handle_deleted(&mut self, event: &DirtyEvent) -> anyhow::Result<()> {
        let now = Timestamp::now();
        let device = event.device_id;
        let mut known = false;
        if let Some(mut record) = self.db.get_file(&event.path)? {
            known = true;
            match state_on(&record, device) {
                Some(LocalState::Present) => self.mark_deleted(record, device, now)?,
                Some(LocalState::Deleted(_)) => {
                    // A pending version left on a deleted record by the code before L1
                    // is dropped; the deletion time stays.
                    if self.supersede_pending(&mut record) {
                        self.db.upsert_file(&record)?;
                    }
                    tracing::debug!(path = %event.path, "backup: already deleted; window kept");
                }
                None => {
                    tracing::debug!(path = %event.path,
                        "backup: deletion of a record this device does not hold; ignored")
                }
            }
        }

        let mut under = 0usize;
        for record in self.records_under(&event.path)? {
            known = true;
            if state_on(&record, device) == Some(LocalState::Present)
                && path_gone(Path::new(&record.path))
            {
                self.mark_deleted(record, device, now)?;
                under += 1;
            }
        }
        if under > 0 {
            tracing::info!(dir = %event.path, files = under,
                "backup: directory gone; files marked deleted");
        }
        if !known {
            tracing::debug!(path = %event.path, "backup: deletion of a path not in the catalog");
        }
        Ok(())
    }

    /// A rebuild did not find `event.path` and the watcher found it gone under an
    /// intact, non-errored root with a non-empty parent (delete-i12 (в)). Only the exact
    /// record, only if this device saw its file on disk (INV-CONF): after DR or a root
    /// change a record is unconfirmed and stays (a leak, not a loss).
    pub(super) fn handle_gone_on_recheck(&mut self, event: &DirtyEvent) -> anyhow::Result<()> {
        let Some(record) = self.db.get_file(&event.path)? else {
            tracing::debug!(path = %event.path, "recheck: path not in the catalog");
            return Ok(());
        };
        if state_on(&record, event.device_id) != Some(LocalState::Present) {
            tracing::debug!(path = %event.path, "recheck: record not present on this device");
            return Ok(());
        }
        if !record.on_disk_confirmed {
            tracing::debug!(path = %event.path, "recheck: record not confirmed on disk; kept");
            return Ok(());
        }
        self.mark_deleted(record, event.device_id, Timestamp::now())
    }

    /// Mark `record` deleted on `device`: its pending edit and queue entry go first; a
    /// record with no backed-up version and no other device is removed outright (nothing
    /// of it is in the network), otherwise the device's state becomes `Deleted(now)`.
    fn mark_deleted(
        &mut self,
        mut record: FileRecord,
        device: DeviceId,
        now: Timestamp,
    ) -> anyhow::Result<()> {
        self.supersede_pending(&mut record);
        let backed_up = record.versions.iter().any(|v| v.backed_up_at.is_some());
        let other_devices = record.devices.iter().any(|(d, _)| *d != device);
        if !backed_up && !other_devices {
            tracing::debug!(path = %record.path, "backup: never backed up; record removed");
            self.db.delete_file(&record.path)?;
            return Ok(());
        }
        match record.devices.iter_mut().find(|(d, _)| *d == device) {
            Some((_, state)) => *state = LocalState::Deleted(now),
            None => record.devices.push((device, LocalState::Deleted(now))),
        }
        tracing::debug!(path = %record.path, "backup: file marked deleted");
        self.db.upsert_file(&record)?;
        Ok(())
    }

    /// The root rule (`RootLost`, `RootChanged`; P-C2): every record under the root
    /// loses its confirmation; a deletion on this device within the owner window whose
    /// live blocks (see `any_block_in_deletion`) are not in deletion (block status not
    /// `Deleting`/`Deleted`, no placement `Deleting`, block record still there) is undone.
    /// The block status is checked, not only placements: after L2 the status is written
    /// before the Delete is published, and with 0 acks there is no `Deleting` placement.
    pub(super) fn handle_root_lost(&mut self, event: &DirtyEvent) -> anyhow::Result<()> {
        let now = Timestamp::now();
        let window = OWNER_DELETE_COOLDOWN_SECS / self.config.time_scale.max(1);
        let since = now.0.saturating_sub(window);
        let device = event.device_id;

        let mut in_deletion: HashMap<SourceBlockId, bool> = HashMap::new();
        let mut changed = Vec::new();
        let (mut undone, mut unconfirmed) = (0usize, 0usize);
        for mut record in self.records_under(&event.path)? {
            let mut touched = false;
            if record.on_disk_confirmed {
                record.on_disk_confirmed = false;
                unconfirmed += 1;
                touched = true;
            }
            if let Some(LocalState::Deleted(t)) = state_on(&record, device)
                && t.0 >= since
                && record.versions.iter().any(|v| v.backed_up_at.is_some())
                && !self.any_block_in_deletion(&record, &mut in_deletion)?
            {
                for (d, state) in record.devices.iter_mut() {
                    if *d == device {
                        *state = LocalState::Present;
                    }
                }
                undone += 1;
                touched = true;
            }
            if touched {
                changed.push(record);
            }
        }
        for chunk in changed.chunks(ROOT_RULE_CHUNK) {
            let mut tx = self.db.write_txn()?;
            for record in chunk {
                tx.upsert_file(record)?;
            }
            tx.commit()?;
        }
        if event.kind == DirtyKind::RootChanged {
            tracing::info!(root = %event.path, files = undone, unconfirmed,
                "backup: watch root changed; recent deletions undone");
        } else {
            tracing::info!(root = %event.path, files = undone, unconfirmed,
                "backup: watch root lost; recent deletions undone");
        }
        Ok(())
    }

    /// A block that reviving `record` makes live is in deletion: its record is gone, its
    /// status is `Deleting`/`Deleted`, or a placement of it is `Deleting` (Serviceability
    /// `Missing` or `Releasing`). Only the block
    /// of the last version and of the last backed-up version count (delete-i12 (а), L0
    /// review BLOCK-1): an older, superseded version may point at a block long released —
    /// `CleanupBlock` strips versions only from the record the block is attributed to —
    /// and reviving the record does not make that block live again.
    fn any_block_in_deletion(
        &self,
        record: &FileRecord,
        cache: &mut HashMap<SourceBlockId, bool>,
    ) -> anyhow::Result<bool> {
        let last = record.versions.last().filter(|v| v.backed_up_at.is_some());
        let last_backed_up = record
            .versions
            .iter()
            .rev()
            .find(|v| v.backed_up_at.is_some());
        for v in last.into_iter().chain(last_backed_up) {
            let block = v.source_block_id;
            let deleting = match cache.get(&block) {
                Some(d) => *d,
                None => {
                    // Р-10: the one serviceability rule (backup-i21); "in deletion" is its
                    // `Releasing` or `Missing`.
                    let d = matches!(
                        self.db.block_serviceability(&block)?,
                        Serviceability::Releasing | Serviceability::Missing
                    );
                    cache.insert(block, d);
                    d
                }
            };
            if deleting {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Records strictly under `dir` (prefix `dir/` and `dir<MAIN_SEPARATOR>`), each once.
    fn records_under(&self, dir: &str) -> anyhow::Result<Vec<FileRecord>> {
        let slash = format!("{dir}/");
        let native = format!("{dir}{}", std::path::MAIN_SEPARATOR);
        let mut out = self.db.list_files_with_prefix(&slash)?;
        if native != slash {
            let seen: std::collections::HashSet<String> =
                out.iter().map(|r| r.path.clone()).collect();
            for record in self.db.list_files_with_prefix(&native)? {
                if !seen.contains(&record.path) {
                    out.push(record);
                }
            }
        }
        Ok(out)
    }
}
