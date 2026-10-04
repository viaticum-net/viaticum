// The reconcile "current version → serviceable block" (L1b: backup-i8, backup-i25; INV-B1).
//
// By level, not by event: at the coordinator's start and every
// `max(CURRENT_BLOCK_RECONCILE_SECS / time_scale, 60)` s. A record Present on this device
// whose last version is backed up on a block being released or missing (a return racing a
// deletion tick on a stale snapshot, a DR from a snapshot), or is pending while its path is in
// no packing queue (the queues are RAM: `kill -9`, OOM, power loss before the idle flush), is
// handed to the watcher — the one owner of roots, identities and scan filters (W2 of the
// intent review). The watcher re-submits it as `Modified` only under an active, accepted root
// with the recorded identity, through the scan filters, for an existing file. The reconcile
// reads no file, writes nothing, deletes and marks nothing (INV-RC, dr-i64).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use viaticum_core::db::{Db, Serviceability, serviceability_of};
use viaticum_core::types::{
    FileRecord, LocalState, SourceBlockId, SourceBlockRecord, SymbolPlacement, to_cbor_bytes,
};

use super::BackupCoordinator;

/// Why a path is handed to the watcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResubmitReason {
    /// The current version is backed up on a block being released or missing (backup-i8).
    Releasing,
    /// The current version waits for its pack and is in no queue (backup-i25).
    Pending,
}

/// One reconcile pass handed to the watcher.
#[derive(Debug)]
pub struct ResubmitBatch {
    pub items: Vec<(PathBuf, ResubmitReason)>,
}

pub type ResubmitTx = tokio::sync::mpsc::Sender<ResubmitBatch>;

/// Capacity of the resubmit channel: a full channel leaves the batch to the next pass.
pub const RESUBMIT_CHANNEL_CAPACITY: usize = 4;

/// Passes skipped at most between two resubmissions of an unchanged record.
const MAX_SKIP_PASSES: u32 = 24;

/// One reconcile pass: what was handed to the watcher.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ReconcileStats {
    pub releasing: u32,
    pub pending: u32,
    pub backing_off: u32,
    /// The batch was not sent (the channel is full, closed, or not wired): the next pass
    /// computes it again.
    pub channel_full: bool,
}

/// Backoff of one path whose resubmission did not change its record (a large file over the
/// cycle budget, a pack that keeps failing, a path the watcher filters out): skip 1, 2, 4 …
/// `MAX_SKIP_PASSES` passes. Any change of the record starts over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Backoff {
    fingerprint: [u8; 32],
    /// Sent in the last pass that looked at it.
    just_sent: bool,
    skip_left: u32,
    next_skip: u32,
}

impl Backoff {
    /// Whether to send the path this pass, and its backoff after the pass.
    fn step(prev: Option<&Backoff>, fingerprint: [u8; 32]) -> (bool, Backoff) {
        match prev {
            Some(b) if b.fingerprint == fingerprint => {
                if b.skip_left > 0 {
                    (
                        false,
                        Backoff {
                            skip_left: b.skip_left - 1,
                            ..*b
                        },
                    )
                } else if b.just_sent {
                    // Unchanged since its resubmission: start skipping with this pass.
                    (
                        false,
                        Backoff {
                            just_sent: false,
                            skip_left: b.next_skip - 1,
                            next_skip: (b.next_skip * 2).min(MAX_SKIP_PASSES),
                            ..*b
                        },
                    )
                } else {
                    (
                        true,
                        Backoff {
                            just_sent: true,
                            ..*b
                        },
                    )
                }
            }
            _ => (
                true,
                Backoff {
                    fingerprint,
                    just_sent: true,
                    skip_left: 0,
                    next_skip: 1,
                },
            ),
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Loads of blocks and placements (`reconcile_loads_blocks_and_placements_once_per_pass`).
    pub(crate) static SERVICEABILITY_LOADS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Every block's serviceability, from one read of all blocks and one of all placements.
fn load_serviceability(db: &Db) -> anyhow::Result<HashMap<SourceBlockId, Serviceability>> {
    #[cfg(test)]
    SERVICEABILITY_LOADS.with(|c| c.set(c.get() + 1));
    let blocks: Vec<SourceBlockRecord> = db.list_all_source_blocks()?;
    let mut placements: HashMap<SourceBlockId, Vec<SymbolPlacement>> = HashMap::new();
    for p in db.list_all_placements()? {
        placements.entry(p.source_block_id).or_default().push(p);
    }
    Ok(blocks
        .iter()
        .map(|b| {
            let ps = placements
                .get(&b.block_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            (b.block_id, serviceability_of(Some(b), ps))
        })
        .collect())
}

impl BackupCoordinator {
    /// INV-B1 by level (backup-i8, backup-i25). Blocks and placements are loaded once per
    /// pass. For each record Present on this device: last version backed up on a
    /// `Releasing`/`Missing` block, or pending with its path in no queue → into the batch,
    /// unless the path is backing off. The batch goes to the watcher with `try_send`; a full
    /// channel leaves it to the next pass. Reads no file and writes nothing (INV-RC, dr-i64).
    pub(crate) fn reconcile_current_blocks(&mut self) -> anyhow::Result<ReconcileStats> {
        let files = self.db.list_all_files()?;
        let service = load_serviceability(&self.db)?;
        let queued: HashSet<&str> = self
            .queues
            .values()
            .flatten()
            .map(|qf| qf.path.as_str())
            .collect();
        let device = self.config.device_id;
        let mut stats = ReconcileStats::default();
        let mut backoff: HashMap<String, Backoff> = HashMap::new();
        let mut items: Vec<(PathBuf, ResubmitReason)> = Vec::new();
        for record in &files {
            let Some(reason) = resubmit_reason(record, device, &service, &queued) else {
                continue;
            };
            let fingerprint = *blake3::hash(&to_cbor_bytes(record)).as_bytes();
            let (send, next) = Backoff::step(self.reconcile_backoff.get(&record.path), fingerprint);
            backoff.insert(record.path.clone(), next);
            if !send {
                stats.backing_off += 1;
                continue;
            }
            match reason {
                ResubmitReason::Releasing => stats.releasing += 1,
                ResubmitReason::Pending => stats.pending += 1,
            }
            items.push((PathBuf::from(&record.path), reason));
        }
        if items.is_empty() {
            self.reconcile_backoff = backoff;
            return Ok(stats);
        }
        let sent = match &self.config.resubmit_tx {
            Some(tx) => tx.try_send(ResubmitBatch { items }).is_ok(),
            None => false,
        };
        if sent {
            self.reconcile_backoff = backoff;
        } else {
            // Nothing reached the watcher: the backoff stays as it was, the next pass
            // builds the batch again.
            stats.channel_full = true;
        }
        Ok(stats)
    }

    /// One pass from the run loop: DEBUG summary, ERROR on failure (the loop goes on).
    pub(super) fn reconcile_pass(&mut self) {
        match self.reconcile_current_blocks() {
            Ok(stats) => tracing::debug!(
                releasing = stats.releasing,
                pending = stats.pending,
                backing_off = stats.backing_off,
                channel_full = stats.channel_full,
                "backup: reconcile pass"
            ),
            Err(e) => tracing::error!("backup: reconcile pass failed: {e:#}"),
        }
    }
}

/// Why `record` is handed to the watcher, if it is.
fn resubmit_reason(
    record: &FileRecord,
    device: viaticum_core::types::DeviceId,
    service: &HashMap<SourceBlockId, Serviceability>,
    queued: &HashSet<&str>,
) -> Option<ResubmitReason> {
    let present = record
        .devices
        .iter()
        .any(|(d, s)| *d == device && *s == LocalState::Present);
    if !present {
        return None;
    }
    let last = record.versions.last()?;
    if last.backed_up_at.is_some() {
        let s = service
            .get(&last.source_block_id)
            .copied()
            .unwrap_or(Serviceability::Missing);
        return matches!(s, Serviceability::Releasing | Serviceability::Missing)
            .then_some(ResubmitReason::Releasing);
    }
    (!queued.contains(record.path.as_str())).then_some(ResubmitReason::Pending)
}
