// Event processing: handle_deleted, handle_added_or_modified, get_or_create_file_id.
// Called from BackupCoordinator::process_event (mod.rs).

use viaticum_core::config::derive_file_importance;
use viaticum_core::types::{FileId, FileRecord, FileVersion, LocalState, SourceBlockId, Timestamp};

use super::{BackupCoordinator, DirtyEvent, DirtyKind, QueuedFile};
use viaticum_core::types::FileCategory;

impl BackupCoordinator {
    pub(super) fn handle_deleted(&mut self, event: &DirtyEvent) -> anyhow::Result<()> {
        let now = Timestamp::now();
        if let Some(mut record) = self.db.get_file(&event.path)? {
            let mut found = false;
            for (dev, state) in &mut record.devices {
                if *dev == event.device_id {
                    *state = LocalState::Deleted(now);
                    found = true;
                    break;
                }
            }
            if !found {
                record
                    .devices
                    .push((event.device_id, LocalState::Deleted(now)));
            }
            self.db.upsert_file(&record)?;
        } else {
            // File not in catalog — create a minimal record for the deletion.
            let file_id = self.alloc_file_id();
            let record = FileRecord {
                file_id,
                path: event.path.clone(),
                importance: 0.5,
                devices: vec![(event.device_id, LocalState::Deleted(now))],
                versions: vec![],
                first_seen: now,
            };
            self.db.upsert_file(&record)?;
        }
        Ok(())
    }

    pub(super) fn handle_added_or_modified(&mut self, event: &DirtyEvent) -> anyhow::Result<()> {
        let file_bytes = std::fs::read(&event.path)
            .map_err(|e| anyhow::anyhow!("read file {}: {e}", event.path))?;
        let size_bytes = file_bytes.len() as u64;
        let content_hash: [u8; 32] = *blake3::hash(&file_bytes).as_bytes();

        // Dedup check: content already backed up → zero traffic.
        // Use ClusterState if available (multi-device), else inline scan.
        let is_backed_up = if let Some(cs) = &self.config.cluster_state {
            let guard = cs.lock().expect("cluster_state lock poisoned");
            guard
                .is_content_backed_up(&content_hash)
                .map_err(|e| anyhow::anyhow!("cluster dedup check: {e}"))?
        } else {
            // B-1: indexed lookup instead of an O(N) full FILES scan.
            self.db.is_content_backed_up(&content_hash)?
        };

        if is_backed_up {
            // Content is already fully backed up — update catalog without re-uploading.
            // B-1: indexed lookup of the existing record (was a full FILES scan).
            if let Some(existing) = self.db.find_file_by_content_hash(&content_hash)? {
                tracing::debug!(
                    "dedup: {} matches existing record path={}",
                    event.path,
                    existing.path
                );
                self.handle_dedup(event, &existing, content_hash)?;
                return Ok(());
            }
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
            self.process_large_file(&event.path, file_id, content_hash, importance, &candidates)?;
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

    /// Handle dedup: content already exists, update catalog without queuing.
    fn handle_dedup(
        &mut self,
        event: &DirtyEvent,
        existing: &viaticum_core::types::FileRecord,
        content_hash: [u8; 32],
    ) -> anyhow::Result<()> {
        if event.path == existing.path {
            // Same path, same content — ensure device is listed as Present.
            let mut record = existing.clone();
            let mut found = false;
            for (dev, state) in &mut record.devices {
                if *dev == event.device_id {
                    *state = LocalState::Present;
                    found = true;
                    break;
                }
            }
            if !found {
                record.devices.push((event.device_id, LocalState::Present));
            }
            self.db.upsert_file(&record)?;
        } else {
            // Different path, same content.
            let source_version = existing
                .versions
                .iter()
                .find(|v| v.content_hash == content_hash)
                .expect("dedup match must have a matching version");

            if let Some(mut path_record) = self.db.get_file(&event.path)? {
                // Existing record for this path — add new version for Modified events.
                if event.kind == DirtyKind::Modified {
                    let new_version = FileVersion {
                        content_hash,
                        source_block_id: source_version.source_block_id,
                        k: source_version.k,
                        t: source_version.t,
                        created_at: Timestamp::now(),
                        backed_up_at: source_version.backed_up_at,
                    };
                    path_record.versions.push(new_version);
                    self.db.upsert_file(&path_record)?;
                }
                // Added: nothing to do (same path already registered in catalog).
            } else {
                // New path for existing content — create FileRecord pointing to existing block.
                let file_id = self.alloc_file_id();
                let version = FileVersion {
                    content_hash,
                    source_block_id: source_version.source_block_id,
                    k: source_version.k,
                    t: source_version.t,
                    created_at: Timestamp::now(),
                    backed_up_at: source_version.backed_up_at,
                };
                let record = FileRecord {
                    file_id,
                    path: event.path.clone(),
                    importance: 0.5,
                    devices: vec![(event.device_id, LocalState::Present)],
                    versions: vec![version],
                    first_seen: Timestamp::now(),
                };
                self.db.upsert_file(&record)?;
            }
        }
        Ok(())
    }

    /// Get existing FileId for a path, or create a new FileRecord.
    ///
    /// For Modified events: appends a new FileVersion (with sentinel source_block_id).
    pub(super) fn get_or_create_file_id(
        &mut self,
        path: &str,
        device_id: &viaticum_core::types::DeviceId,
        content_hash: [u8; 32],
    ) -> anyhow::Result<FileId> {
        let now = Timestamp::now();
        let sentinel_block_id = SourceBlockId([0u8; 32]);

        if let Some(mut record) = self.db.get_file(path)? {
            let new_version = FileVersion {
                content_hash,
                source_block_id: sentinel_block_id,
                k: 0,
                t: 0,
                created_at: now,
                backed_up_at: None,
            };
            record.versions.push(new_version);

            let mut found = false;
            for (dev, state) in &mut record.devices {
                if *dev == *device_id {
                    *state = LocalState::Present;
                    found = true;
                    break;
                }
            }
            if !found {
                record.devices.push((*device_id, LocalState::Present));
            }

            let file_id = record.file_id;
            self.db.upsert_file(&record)?;
            Ok(file_id)
        } else {
            let file_id = self.alloc_file_id();
            let version = FileVersion {
                content_hash,
                source_block_id: sentinel_block_id,
                k: 0,
                t: 0,
                created_at: now,
                backed_up_at: None,
            };
            let record = FileRecord {
                file_id,
                path: path.to_string(),
                importance: 0.5,
                devices: vec![(*device_id, LocalState::Present)],
                versions: vec![version],
                first_seen: now,
            };
            self.db.upsert_file(&record)?;
            Ok(file_id)
        }
    }
}
