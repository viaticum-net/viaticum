// Event processing: handle_added_or_modified, handle_dedup, get_or_create_file_id.
// Called from BackupCoordinator::process_event (mod.rs); deletions are in gone.rs.
//
// backup-i9: a path points at what is on disk now. An event for content that is
// already in the network (a rollback, a restore put back in place, a copy over an
// existing path) makes that content the path's current version; a pending edit of
// the same path is superseded (at most one pending version per path, and it is the
// last one).

use std::collections::HashMap;
use std::path::Path;

use viaticum_core::config::derive_file_importance;
use viaticum_core::db::Db;
use viaticum_core::types::{
    DeviceId, FileCategory, FileId, FileRecord, FileVersion, LocalState, SourceBlockId, Timestamp,
};

use super::source_read::{SourceReadError, read_source_bounded};
use super::{BackupCoordinator, DirtyEvent, QueuedFile};

/// A backed-up version holding some content: where a path whose bytes have that
/// content can point without any traffic.
#[derive(Debug, Clone)]
pub(crate) struct DedupSource {
    pub(crate) record: FileRecord,
    pub(crate) version: FileVersion,
}

/// The answer of the dedup lookup (backup-i21).
#[derive(Debug, Clone)]
pub(crate) enum DedupLookup {
    /// A backed-up version with this content on a serviceable block: point the path there.
    Source(DedupSource),
    /// The content was backed up, but every block carrying it is not in service (window,
    /// releasing, missing): back it up again.
    Unserviceable { blocks: Vec<SourceBlockId> },
    /// No backed-up version holds this content.
    NotFound,
}

/// The dedup source for `content_hash` (backup-i9, backup-i21).
///
/// Only a backed-up version qualifies (a pending one has no block yet), and only one whose
/// block is in service: record `Active`, no placement `Deleting` (`Serviceability`,
/// memoized per call). The gate filters every candidate BEFORE the ranking, so a returned
/// path never pins itself to its own block being released. Among the records holding a
/// serviceable version: a record whose last backed-up version has this content comes first
/// — `own_path` before the others, so a touch or a rescan of a path that already points at
/// this content keeps its block — then path order. Within the record, its last backed-up
/// version with this content on a serviceable block.
pub(crate) fn select_dedup_source(
    db: &Db,
    content_hash: &[u8; 32],
    own_path: Option<&str>,
) -> anyhow::Result<DedupLookup> {
    let mut serviceable: HashMap<SourceBlockId, bool> = HashMap::new();
    let mut is_serviceable = |block: SourceBlockId| -> anyhow::Result<bool> {
        if let Some(s) = serviceable.get(&block) {
            return Ok(*s);
        }
        let s = db.block_serviceability(&block)?.is_serviceable();
        serviceable.insert(block, s);
        Ok(s)
    };
    let mut unserviceable: Vec<SourceBlockId> = Vec::new();
    let mut best: Option<((u8, String), DedupSource)> = None;
    for record in db.files_with_content_hash(content_hash)? {
        let mut version = None;
        for v in record.versions.iter().rev() {
            if &v.content_hash != content_hash || v.backed_up_at.is_none() {
                continue;
            }
            if is_serviceable(v.source_block_id)? {
                version = Some(v.clone());
                break;
            }
            if !unserviceable.contains(&v.source_block_id) {
                unserviceable.push(v.source_block_id);
            }
        }
        let Some(version) = version else {
            continue;
        };
        let last_backed_up_is_this = record
            .versions
            .iter()
            .rev()
            .find(|v| v.backed_up_at.is_some())
            .is_some_and(|v| &v.content_hash == content_hash);
        let rank = match (
            last_backed_up_is_this,
            own_path == Some(record.path.as_str()),
        ) {
            (true, true) => 0,
            (true, false) => 1,
            (false, _) => 2,
        };
        let key = (rank, record.path.clone());
        if best.as_ref().is_none_or(|(k, _)| key < *k) {
            best = Some((key, DedupSource { record, version }));
        }
    }
    Ok(match best {
        Some((_, src)) => DedupLookup::Source(src),
        None if !unserviceable.is_empty() => DedupLookup::Unserviceable {
            blocks: unserviceable,
        },
        None => DedupLookup::NotFound,
    })
}

/// Mark `device` Present in `record`. Returns whether the record changed.
pub(super) fn set_present(record: &mut FileRecord, device: DeviceId) -> bool {
    match record.devices.iter_mut().find(|(d, _)| *d == device) {
        Some((_, state)) if *state == LocalState::Present => false,
        Some((_, state)) => {
            *state = LocalState::Present;
            true
        }
        None => {
            record.devices.push((device, LocalState::Present));
            true
        }
    }
}

impl BackupCoordinator {
    pub(super) fn handle_added_or_modified(&mut self, event: &DirtyEvent) -> anyhow::Result<()> {
        // backup-i4, backup-i5: the size is judged by `metadata` before the file is opened;
        // the read itself is capped at the limit + 1 byte (a file that grows while it is
        // read is cut and refused). Above the limit: a mark, no read, no version.
        let file_bytes =
            match read_source_bounded(Path::new(&event.path), self.config.max_file_size_bytes, 0) {
                Ok(bytes) => bytes,
                Err(SourceReadError::TooLarge { size, .. }) => {
                    self.mark_too_large(&event.path, size);
                    return Ok(());
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e).context(format!("read file {}", event.path)));
                }
            };
        let size_bytes = file_bytes.len() as u64;
        let content_hash: [u8; 32] = *blake3::hash(&file_bytes).as_bytes();
        // At or under the limit: an earlier mark of this path is over.
        self.clear_too_large(&event.path);

        // Dedup: content already in the network on a block in service → the path points
        // at it, zero traffic. Indexed lookup (CONTENT_INDEX); the cluster branch that
        // scanned every FILES record per event is gone (R1-f A19). Content whose every
        // block is being released is backed up again (backup-i8, backup-i21): the packing
        // seals it at a new generation when the plaintext is the same (delete-i9).
        match select_dedup_source(&self.db, &content_hash, Some(&event.path))? {
            DedupLookup::Source(src) => {
                tracing::debug!(
                    path = %event.path,
                    source = %src.record.path,
                    "dedup: content already backed up"
                );
                return self.handle_dedup(event, &src, content_hash);
            }
            DedupLookup::Unserviceable { blocks } => {
                let blocks: Vec<String> = blocks.iter().map(|b| b.to_string()).collect();
                tracing::info!(
                    path = %event.path,
                    blocks = %blocks.join(","),
                    "backup: content returned but its block is being released; backing up again"
                );
            }
            DedupLookup::NotFound => {}
        }

        // Not a duplicate — classify and enqueue or process immediately (large file).
        let category = Self::classify(&event.path);

        let importance = if let Some(live) = &self.config.live_watch_configs {
            let guard = live.read().expect("live_watch_configs lock poisoned");
            derive_file_importance(&event.path, &guard)
        } else {
            derive_file_importance(&event.path, &self.config.watch_configs)
        };

        if size_bytes >= self.config.source_block_size {
            // Budget check for single large file.
            let offer_budget_gb = self.compute_offer_budget_gb();
            let required_gb = size_bytes as f64 / viaticum_core::constants::BYTES_PER_GB
                * viaticum_core::budget::overhead_factor(importance);
            if required_gb > offer_budget_gb {
                tracing::warn!(
                    path = %event.path,
                    size_bytes,
                    required_gb,
                    offer_budget_gb,
                    "large file exceeds budget this cycle; will retry on next watcher scan"
                );
                return Ok(());
            }
            let file_id =
                self.get_or_create_file_id(&event.path, &event.device_id, content_hash)?;
            // TODO(wave2): pass authenticated snapshot here (currently unfiltered for large files).
            let candidates = self.get_candidates(&Default::default())?;
            // A4: backup creates only the block record; the WorkPipeline worker
            // offers and delivers. No offer count to tally here.
            self.process_large_file(
                &event.path,
                file_id,
                content_hash,
                importance,
                &candidates,
                file_bytes,
            )?;
            return Ok(());
        }

        let file_id = self.get_or_create_file_id(&event.path, &event.device_id, content_hash)?;

        // Small videos go to Other queue; all other categories use their own queue.
        let queue_category = match category {
            FileCategory::Video => FileCategory::Other,
            c => c,
        };

        let qf = QueuedFile {
            path: event.path.clone(),
            file_id,
            content_hash,
            size_bytes,
            category: queue_category,
            importance,
        };

        self.queues.entry(queue_category).or_default().push(qf);
        Ok(())
    }

    /// The path of `event` now holds content that `src` already has in the network:
    /// point the path at it without queuing (backup-i9).
    ///
    /// Existing record: Present on this device, confirmed on disk, its pending edit
    /// superseded; then, unless its last version already is this content on the
    /// source's block and backed up, a new version (content, block, `created_at` =
    /// `backed_up_at` = now) is appended. Written only when something changed, so a
    /// touch or a rescan adds nothing. No record: a new one with a fresh `file_id`.
    fn handle_dedup(
        &mut self,
        event: &DirtyEvent,
        src: &DedupSource,
        content_hash: [u8; 32],
    ) -> anyhow::Result<()> {
        let now = Timestamp::now();
        let current = FileVersion {
            content_hash,
            source_block_id: src.version.source_block_id,
            k: src.version.k,
            t: src.version.t,
            created_at: now,
            backed_up_at: Some(now),
        };

        let Some(mut record) = self.db.get_file(&event.path)? else {
            let record = FileRecord {
                file_id: self.alloc_file_id(),
                path: event.path.clone(),
                importance: 0.5,
                devices: vec![(event.device_id, LocalState::Present)],
                versions: vec![current],
                first_seen: now,
                on_disk_confirmed: true,
            };
            self.db.upsert_file(&record)?;
            return Ok(());
        };

        let mut changed = set_present(&mut record, event.device_id);
        if !record.on_disk_confirmed {
            record.on_disk_confirmed = true;
            changed = true;
        }
        changed |= self.supersede_pending(&mut record);
        let points_there = record.versions.last().is_some_and(|v| {
            v.content_hash == content_hash
                && v.source_block_id == src.version.source_block_id
                && v.backed_up_at.is_some()
        });
        if !points_there {
            tracing::info!(
                path = %event.path,
                block_id = %src.version.source_block_id,
                "dedup: path now points at content already in the network"
            );
            record.versions.push(current);
            changed = true;
        }
        if changed {
            self.db.upsert_file(&record)?;
        }
        Ok(())
    }

    /// Drop the pending (not yet backed-up) versions of `record` and its entries in the
    /// packing queues: whatever the path held before this event is not what is on disk
    /// now (≤ 1 pending version per path, backup-i9). Returns whether a version was
    /// dropped. The coordinator is single-threaded, so no flush is in flight.
    pub(super) fn supersede_pending(&mut self, record: &mut FileRecord) -> bool {
        let before = record.versions.len();
        record.versions.retain(|v| v.backed_up_at.is_some());
        let dropped = before - record.versions.len();
        let mut dequeued = 0usize;
        for queue in self.queues.values_mut() {
            let len = queue.len();
            queue.retain(|qf| qf.path != record.path);
            dequeued += len - queue.len();
        }
        if dropped > 0 || dequeued > 0 {
            tracing::debug!(
                path = %record.path,
                versions = dropped,
                queued = dequeued,
                "backup: pending edit superseded"
            );
        }
        dropped > 0
    }

    /// Get existing FileId for a path, or create a new FileRecord.
    ///
    /// Appends a pending version (sentinel `source_block_id`) after superseding any
    /// older pending one, marks the device Present and the record confirmed on disk
    /// (the caller has just read the file).
    pub(super) fn get_or_create_file_id(
        &mut self,
        path: &str,
        device_id: &DeviceId,
        content_hash: [u8; 32],
    ) -> anyhow::Result<FileId> {
        let now = Timestamp::now();
        let pending = FileVersion {
            content_hash,
            source_block_id: SourceBlockId([0u8; 32]),
            k: 0,
            t: 0,
            created_at: now,
            backed_up_at: None,
        };

        if let Some(mut record) = self.db.get_file(path)? {
            self.supersede_pending(&mut record);
            record.versions.push(pending);
            set_present(&mut record, *device_id);
            record.on_disk_confirmed = true;
            let file_id = record.file_id;
            self.db.upsert_file(&record)?;
            Ok(file_id)
        } else {
            let file_id = self.alloc_file_id();
            let record = FileRecord {
                file_id,
                path: path.to_string(),
                importance: 0.5,
                devices: vec![(*device_id, LocalState::Present)],
                versions: vec![pending],
                first_seen: now,
                on_disk_confirmed: true,
            };
            self.db.upsert_file(&record)?;
            Ok(file_id)
        }
    }
}
