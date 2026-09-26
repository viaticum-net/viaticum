// Block-level view of the catalog for the deletion flow (delete-i3).
//
// Records are the unit of deletion, blocks are the unit of release. A block can be
// shared by several records: every file of a pack points at the pack block, two
// paths with identical content dedup onto one block, and a restored file moved to a
// new path gets a new record on the old block. These helpers turn the per-record
// catalog into the two per-block facts `process_cooldowns` needs.

use std::collections::{HashMap, HashSet};

use crate::types::{FileRecord, LocalState, SourceBlockId, Timestamp};

/// Blocks that must not be released by the deletion flow: referenced by the *current*
/// version of any file record that is not deleted on every device.
///
/// "Current" = the last version, and the last version with `backed_up_at.is_some()` (they
/// differ while a new edit is still queued). Older versions of live files are NOT protected
/// (P2: the network holds the current state, not history). Records with no devices are
/// treated as live (conservative; `all_devices_deleted_at` returns None for them too).
pub fn live_referenced_blocks(files: &[FileRecord]) -> HashSet<SourceBlockId> {
    let mut live = HashSet::new();
    for file in files {
        if all_devices_deleted_at(file).is_some() {
            continue;
        }
        if let Some(last) = file.versions.last() {
            live.insert(last.source_block_id);
        }
        if let Some(last_backed_up) = file
            .versions
            .iter()
            .rev()
            .find(|v| v.backed_up_at.is_some())
        {
            live.insert(last_backed_up.source_block_id);
        }
    }
    live
}

/// For every block referenced by any version of a record that is deleted on all devices: the
/// LATEST such deletion time. The block's owner window runs from this time, so each deleted
/// file gets its full undo window (restore-i9) even if a pack sibling was deleted long ago.
pub fn latest_deletion_per_block(files: &[FileRecord]) -> HashMap<SourceBlockId, Timestamp> {
    let mut latest: HashMap<SourceBlockId, Timestamp> = HashMap::new();
    for file in files {
        let deleted_at = match all_devices_deleted_at(file) {
            Some(ts) => ts,
            None => continue,
        };
        for version in &file.versions {
            latest
                .entry(version.source_block_id)
                .and_modify(|ts| {
                    if deleted_at > *ts {
                        *ts = deleted_at;
                    }
                })
                .or_insert(deleted_at);
        }
    }
    latest
}

/// Returns the timestamp when all devices marked the file deleted, or None if
/// any device is still Present (or the record has no devices at all).
pub(super) fn all_devices_deleted_at(file: &FileRecord) -> Option<Timestamp> {
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
