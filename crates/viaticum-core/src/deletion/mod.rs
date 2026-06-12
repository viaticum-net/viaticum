use crate::constants::{
    HOLDER_DELETE_COOLDOWN_SECS, OWNER_DELETE_COOLDOWN_SECS, VACUUM_INVALID_THRESHOLD,
};
use crate::types::{
    DeviceId, FileId, FileRecord, LocalState, PlacementStatus, SourceBlockId, SourceBlockRecord,
    SourceBlockStatus, SourceBlockType, SymbolPlacement, Timestamp,
};

// ── Actions returned to the daemon ──────────────────────────────────────────

/// Actions the daemon must execute as a result of deletion logic.
/// The engine never mutates DB or sends messages — it returns these.
#[derive(Debug, Clone, PartialEq)]
pub enum DeletionAction {
    /// Owner cooldown elapsed. Send DeleteMsg to each holder and set
    /// SourceBlockRecord.status = Deleting. One action per holder.
    SendDropNotice {
        source_block_id: SourceBlockId,
        holder_id: DeviceId,
    },

    /// Holder cooldown elapsed (delete_requested_at + HOLDER_DELETE_COOLDOWN_SECS).
    /// Daemon should:
    ///   1. delete_placement(source_block_id, holder_id)
    ///   2. If no placements remain for this block: delete_source_block(block_id)
    CleanupPlacement {
        source_block_id: SourceBlockId,
        holder_id: DeviceId,
    },

    /// All placements for this source block have been cleaned up.
    /// Daemon should delete the SourceBlockRecord row and prune the
    /// FileRecord.versions entry that references this block.
    CleanupBlock {
        source_block_id: SourceBlockId,
        /// FileId that owns this block (for pruning the version entry).
        file_id: FileId,
    },

    /// Source block has >50% invalid files. Daemon must:
    ///   1. Repack still-valid file data into a new source block (new backup).
    ///   2. Call mark_source_block_stale(old_block_id) — sets status = Stale.
    ///   3. The stale block then enters the deletion flow on the next tick.
    VacuumBlock {
        source_block_id: SourceBlockId,
        /// File IDs that are still valid and must be repacked.
        valid_file_ids: Vec<FileId>,
    },

    /// File was deleted on one device but is still present on others.
    /// No action needed now; the engine will reconsider on next tick.
    WaitForOtherDevices { file_id: FileId },
}

// ── Result type for mark_deleted ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum MarkDeletedResult {
    /// File is still present on at least one other device. No further action.
    WaitForOtherDevices,
    /// All devices now have Deleted state. Owner cooldown has started.
    /// The daemon must persist `local_state = Deleted(now)` for `device_id`
    /// (it may have already been set before calling this function; idempotent).
    CooldownStarted {
        /// Timestamp when the last device was marked deleted (= now).
        deleted_at: Timestamp,
        /// When the owner cooldown expires and SendDropNotice should be issued.
        notify_after: Timestamp,
    },
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DeletionError {
    #[error("file {0} has no device entry for device {1}")]
    DeviceNotFound(FileId, DeviceId),

    #[error("source block {0} referenced in FileVersion not found in blocks slice")]
    BlockNotFound(SourceBlockId),
}

// ── Engine ───────────────────────────────────────────────────────────────────

/// Pure-logic deletion engine. Stateless between calls.
pub struct DeletionEngine;

impl DeletionEngine {
    pub fn new() -> Self {
        DeletionEngine
    }

    /// Called when the watcher sees a file deleted on `device_id`.
    ///
    /// Returns what should happen next. The daemon must persist the state change:
    /// set `record.devices[device_id].local_state = Deleted(now)`.
    pub fn mark_deleted(
        &self,
        record: &FileRecord,
        device_id: DeviceId,
        now: Timestamp,
    ) -> Result<MarkDeletedResult, DeletionError> {
        let found = record.devices.iter().any(|(id, _)| *id == device_id);
        if !found {
            return Err(DeletionError::DeviceNotFound(record.file_id, device_id));
        }

        let all_deleted = record.devices.iter().all(|(id, state)| {
            if *id == device_id {
                true
            } else {
                matches!(state, LocalState::Deleted(_))
            }
        });

        if all_deleted {
            Ok(MarkDeletedResult::CooldownStarted {
                deleted_at: now,
                notify_after: now.add_secs(OWNER_DELETE_COOLDOWN_SECS),
            })
        } else {
            Ok(MarkDeletedResult::WaitForOtherDevices)
        }
    }

    /// Called by the scheduler on every tick. Scans all provided records and
    /// returns the actions to execute this tick.
    ///
    /// `time_scale` accelerates cooldowns: effective cooldown = constant / time_scale.
    /// Pass 1 for real-time.
    ///
    /// Returns actions sorted: SendDropNotice first, then CleanupPlacement,
    /// then CleanupBlock. VacuumBlock appended last.
    ///
    /// Idempotent: calling twice with the same inputs returns the same actions.
    pub fn process_cooldowns(
        &self,
        files: &[FileRecord],
        blocks: &[SourceBlockRecord],
        placements: &[SymbolPlacement],
        now: Timestamp,
        time_scale: u64,
    ) -> Vec<DeletionAction> {
        let scale = time_scale.max(1);
        let mut send_drop: Vec<DeletionAction> = Vec::new();
        let mut cleanup_placement: Vec<DeletionAction> = Vec::new();
        let mut cleanup_block: Vec<DeletionAction> = Vec::new();

        for file in files {
            let all_deleted_at = match all_devices_deleted_at(file) {
                Some(ts) => ts,
                None => continue,
            };

            let owner_cooldown = OWNER_DELETE_COOLDOWN_SECS / scale;
            let holder_cooldown = HOLDER_DELETE_COOLDOWN_SECS / scale;

            let owner_cooldown_elapsed = all_deleted_at.0 + owner_cooldown <= now.0;
            if !owner_cooldown_elapsed {
                continue;
            }

            let drop_sent_at = all_deleted_at.0 + owner_cooldown;
            let holder_cooldown_elapsed = drop_sent_at + holder_cooldown <= now.0;

            for version in &file.versions {
                let block = match blocks
                    .iter()
                    .find(|b| b.block_id == version.source_block_id)
                {
                    Some(b) => b,
                    None => continue,
                };

                let block_placements: Vec<&SymbolPlacement> = placements
                    .iter()
                    .filter(|p| p.source_block_id == block.block_id)
                    .collect();

                match block.status {
                    SourceBlockStatus::Active | SourceBlockStatus::Stale => {
                        for p in &block_placements {
                            if p.status != PlacementStatus::Deleting {
                                send_drop.push(DeletionAction::SendDropNotice {
                                    source_block_id: block.block_id,
                                    holder_id: p.holder_id,
                                });
                            }
                        }
                    }
                    SourceBlockStatus::Deleting => {
                        let mut all_cleaned = true;

                        for p in &block_placements {
                            if p.status == PlacementStatus::Deleting {
                                if holder_cooldown_elapsed {
                                    cleanup_placement.push(DeletionAction::CleanupPlacement {
                                        source_block_id: block.block_id,
                                        holder_id: p.holder_id,
                                    });
                                } else {
                                    all_cleaned = false;
                                }
                            } else {
                                send_drop.push(DeletionAction::SendDropNotice {
                                    source_block_id: block.block_id,
                                    holder_id: p.holder_id,
                                });
                                all_cleaned = false;
                            }
                        }

                        if holder_cooldown_elapsed && all_cleaned && !block_placements.is_empty() {
                            cleanup_block.push(DeletionAction::CleanupBlock {
                                source_block_id: block.block_id,
                                file_id: file.file_id,
                            });
                        }
                    }
                    SourceBlockStatus::Deleted => {}
                }
            }
        }

        let mut vacuum: Vec<DeletionAction> = Vec::new();
        for block in blocks {
            if block.status != SourceBlockStatus::Active {
                continue;
            }
            let entries = match &block.block_type {
                SourceBlockType::Pack { entries } => entries,
                SourceBlockType::Single => continue,
            };

            let total_files = entries.len() as u32;
            if total_files == 0 {
                continue;
            }

            let mut invalid_count = 0u32;
            let mut valid_file_ids: Vec<FileId> = Vec::new();

            for entry in entries {
                let file_record = files.iter().find(|f| f.file_id == entry.file_id);

                let is_invalid = match file_record {
                    None => true,
                    Some(f) => {
                        let all_dev_deleted = all_devices_deleted_at(f).is_some();
                        if all_dev_deleted {
                            true
                        } else {
                            let latest_version = f.versions.last();
                            match latest_version {
                                None => true,
                                Some(v) => v.source_block_id != block.block_id,
                            }
                        }
                    }
                };

                if is_invalid {
                    invalid_count += 1;
                } else {
                    valid_file_ids.push(entry.file_id);
                }
            }

            if self.should_vacuum(total_files, invalid_count) {
                vacuum.push(DeletionAction::VacuumBlock {
                    source_block_id: block.block_id,
                    valid_file_ids,
                });
            }
        }

        let mut result = Vec::new();
        result.extend(send_drop);
        result.extend(cleanup_placement);
        result.extend(cleanup_block);
        result.extend(vacuum);
        result
    }

    /// Returns true if a source block of type Pack should be vacuumed.
    ///
    /// Formula: `invalid_files as f64 / total_files as f64 > VACUUM_INVALID_THRESHOLD`
    ///
    /// CS-DEL-9: returns `false` for `total_files == 0` (an empty pack has nothing to
    /// vacuum) rather than asserting. Callers already `continue` on a zero-entry pack,
    /// so this branch is unreachable in the current flow, but a public API should not
    /// panic on its input.
    pub fn should_vacuum(&self, total_files: u32, invalid_files: u32) -> bool {
        if total_files == 0 {
            return false;
        }
        invalid_files as f64 / total_files as f64 > VACUUM_INVALID_THRESHOLD
    }
}

impl Default for DeletionEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the timestamp when all devices marked the file deleted, or None if
/// any device is still Present.
fn all_devices_deleted_at(file: &FileRecord) -> Option<Timestamp> {
    if file.devices.is_empty() {
        return None;
    }
    let mut max_ts = Timestamp(0);
    for (_, state) in &file.devices {
        match state {
            LocalState::Present => return None,
            LocalState::Deleted(ts) => {
                if *ts > max_ts {
                    max_ts = *ts;
                }
            }
        }
    }
    Some(max_ts)
}

#[cfg(test)]
mod tests;
