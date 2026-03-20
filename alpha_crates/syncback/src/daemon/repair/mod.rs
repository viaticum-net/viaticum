use std::collections::{HashSet, VecDeque};

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use reed_solomon_erasure::galois_8::ReedSolomon;
use tokio::sync::mpsc::Sender;

use syncback_core::db::Db;
use syncback_core::types::{ShardStatus, Timestamp, UnitId, UnitStatus};

use crate::daemon::shard_manager::{ShardManager, ShardManagerError};
use crate::daemon::NetCommand;

#[cfg(test)]
mod tests;

// ============================================================
// Constants
// ============================================================

/// Maximum number of units repaired per repair_check cycle.
/// Cold backup: time constant = 1 week. No urgency to repair everything at once.
const MAX_REPAIRS_PER_CYCLE: usize = 10;

/// Maximum total shard re-upload offers per repair_check cycle.
/// Prevents flooding the network boards with offers.
const MAX_REPAIR_OFFERS_PER_CYCLE: usize = 50;

/// Per-shard download timeout during repair.
/// Generous because this is cold backup and holders may be on slow connections.
const DOWNLOAD_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(300);

// ============================================================
// Error
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("not enough live holders: need {need}, have {have}")]
    NotEnoughLiveHolders { need: usize, have: usize },

    #[error("shard download failed: {0}")]
    DownloadFailed(String),

    #[error("reed-solomon decode error: {0}")]
    ReedSolomon(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),
}

// ============================================================
// Supporting types
// ============================================================

#[derive(Debug, Clone, Default)]
pub struct RepairSummary {
    pub units_repaired: usize,
    pub units_skipped_not_enough_shards: usize,
    pub units_skipped_no_peers: usize,
    pub units_skipped_rate_limited: usize,
    pub shards_offered: usize,
}

// ============================================================
// RepairEngine
// ============================================================

pub struct RepairEngine {
    db: Db,
    pending: VecDeque<UnitId>,
    pending_set: HashSet<UnitId>,
    offers_this_cycle: usize,
}

impl RepairEngine {
    pub fn new(db: Db) -> Self {
        RepairEngine {
            db,
            pending: VecDeque::new(),
            pending_set: HashSet::new(),
            offers_this_cycle: 0,
        }
    }

    /// Called from Processor when repair_unit returns PlaintextNotAvailable.
    /// Adds the unit to the pending queue for restore-and-repair.
    /// Deduplicates: if unit_id is already queued, does nothing.
    pub fn queue_for_restore(&mut self, unit_id: UnitId) {
        if self.pending_set.insert(unit_id) {
            self.pending.push_back(unit_id);
            tracing::debug!(unit = %unit_id, "repair: queued for restore-and-repair");
        }
    }

    /// Returns how many units are currently waiting for restore-and-repair.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Reset per-cycle counters. Called by Processor at the start of each repair check.
    pub fn reset_cycle(&mut self) {
        self.offers_this_cycle = 0;
    }

    /// Process pending units from the queue.
    pub async fn run_pending(
        &mut self,
        shard_manager: &ShardManager,
        now: Timestamp,
        net_cmd_tx: &Sender<NetCommand>,
    ) -> RepairSummary {
        let mut summary = RepairSummary::default();
        let count = self.pending.len();
        tracing::info!(count, "repair: processing pending units");

        let mut processed = 0usize;
        // Drain up to MAX_REPAIRS_PER_CYCLE units from the front of the queue.
        // Units not processed remain in the queue for next cycle.
        let mut remaining: VecDeque<UnitId> = VecDeque::new();
        while let Some(unit_id) = self.pending.pop_front() {
            if processed >= MAX_REPAIRS_PER_CYCLE
                || self.offers_this_cycle >= MAX_REPAIR_OFFERS_PER_CYCLE
            {
                tracing::debug!(unit = %unit_id, "repair: rate limit reached, stopping for this cycle");
                remaining.push_back(unit_id);
                summary.units_skipped_rate_limited += 1;
                continue;
            }

            processed += 1;

            // Look up unit record. Skip if unit no longer exists or status != Active.
            let unit = match self.db.get_unit(&unit_id).expect("get_unit failed") {
                Some(u) if u.status == UnitStatus::Active => u,
                Some(_) => {
                    // Unit is stale/deleted — remove from pending_set, skip.
                    self.pending_set.remove(&unit_id);
                    continue;
                }
                None => {
                    self.pending_set.remove(&unit_id);
                    continue;
                }
            };

            let k = unit.rs_k as usize;
            let n = unit.rs_n as usize;

            // Attempt full restore-and-repair for this unit.
            match self
                .restore_and_repair(unit_id, k, n, shard_manager, now, net_cmd_tx)
                .await
            {
                Ok(n_offers) => {
                    summary.units_repaired += 1;
                    summary.shards_offered += n_offers;
                    self.offers_this_cycle += n_offers;
                    self.pending_set.remove(&unit_id);
                    tracing::info!(
                        unit = %unit_id,
                        shards = n_offers,
                        "repair: offers sent for under-replicated unit"
                    );
                }
                Err(RepairError::NotEnoughLiveHolders { need, have }) => {
                    tracing::debug!(
                        unit = %unit_id,
                        have,
                        need,
                        "repair: not enough live shards for restore, deferring"
                    );
                    summary.units_skipped_not_enough_shards += 1;
                    remaining.push_back(unit_id);
                }
                Err(RepairError::DownloadFailed(msg)) => {
                    tracing::debug!(unit = %unit_id, error = %msg, "repair: shard download failed, deferring");
                    summary.units_skipped_not_enough_shards += 1;
                    remaining.push_back(unit_id);
                }
                Err(e) => {
                    // RS decode or decryption error — keep in queue, may be transient.
                    tracing::debug!(unit = %unit_id, error = %e, "repair: restore failed, deferring");
                    summary.units_skipped_not_enough_shards += 1;
                    remaining.push_back(unit_id);
                }
            }
        }

        // Re-queue units that were rate-limited or had recoverable failures.
        while let Some(unit_id) = self.pending.pop_front() {
            remaining.push_back(unit_id);
        }
        self.pending = remaining;

        summary
    }

    async fn restore_and_repair(
        &self,
        unit_id: UnitId,
        k: usize,
        n: usize,
        shard_manager: &ShardManager,
        now: Timestamp,
        net_cmd_tx: &Sender<NetCommand>,
    ) -> Result<usize, RepairError> {
        // Step 1: identify live holders.
        let shards = self.db.list_shards_for_unit(&unit_id)?;
        let live_shards: Vec<_> = shards
            .iter()
            .filter(|s| s.status == ShardStatus::Stored)
            .collect();

        if live_shards.len() < k {
            return Err(RepairError::NotEnoughLiveHolders {
                need: k,
                have: live_shards.len(),
            });
        }

        // Step 2: download k shard blobs.
        let mut shard_bytes: Vec<Option<Vec<u8>>> = vec![None; n];

        for shard_record in live_shards.iter().take(k) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            tracing::debug!(
                shard = %shard_record.shard_id,
                holder = %shard_record.holder_id,
                "repair: downloading shard for restore"
            );
            net_cmd_tx
                .send(NetCommand::DownloadShard {
                    shard_id: shard_record.shard_id,
                    holder: shard_record.holder_id,
                    reply: tx,
                })
                .await
                .expect("net channel closed");

            match tokio::time::timeout(DOWNLOAD_TIMEOUT, rx).await {
                Ok(Ok(Ok(data))) => {
                    shard_bytes[shard_record.shard_index as usize] = Some(data);
                }
                Ok(Ok(Err(e))) => {
                    tracing::debug!(
                        shard = %shard_record.shard_id,
                        error = %e,
                        "repair: shard download failed"
                    );
                }
                Ok(Err(_)) => {
                    tracing::debug!(
                        shard = %shard_record.shard_id,
                        "repair: download reply channel closed"
                    );
                }
                Err(_) => {
                    tracing::debug!(shard = %shard_record.shard_id, "repair: download timeout");
                }
            }
        }

        let downloaded = shard_bytes.iter().filter(|s| s.is_some()).count();
        if downloaded < k {
            return Err(RepairError::NotEnoughLiveHolders {
                need: k,
                have: downloaded,
            });
        }

        // Step 3: RS-decode to ciphertext.
        let ciphertext = rs_decode(shard_bytes, k, n)?;

        // Step 4: decrypt to plaintext.
        let key = shard_manager.derive_unit_key(unit_id);
        let plaintext = decrypt_ciphertext(&key, &ciphertext)?;

        // Step 5: call shard_manager.repair_unit with plaintext.
        match shard_manager
            .repair_unit(unit_id, Some(&plaintext), now)
            .await
        {
            Ok(n_offers) => Ok(n_offers),
            Err(ShardManagerError::NotEnoughPeers { need, have }) => {
                tracing::info!(
                    unit = %unit_id,
                    need,
                    have,
                    "repair: not enough peers, retry next cycle"
                );
                // Caller will re-queue.
                Err(RepairError::DownloadFailed(format!(
                    "not enough peers: need {need}, have {have}"
                )))
            }
            Err(e) => panic!("repair_unit unexpected error: {e}"),
        }
    }
}

// ============================================================
// Internal helpers
// ============================================================

fn rs_decode(
    shard_bytes: Vec<Option<Vec<u8>>>,
    k: usize,
    n: usize,
) -> Result<Vec<u8>, RepairError> {
    let r = ReedSolomon::new(k, n - k).map_err(|e| RepairError::ReedSolomon(e.to_string()))?;

    let mut shards = shard_bytes;

    r.reconstruct(&mut shards)
        .map_err(|e| RepairError::ReedSolomon(e.to_string()))?;

    let mut ciphertext = Vec::new();
    for shard in shards.into_iter().take(k) {
        ciphertext.extend_from_slice(&shard.expect("reconstruct filled all shards"));
    }

    Ok(ciphertext)
}

fn decrypt_ciphertext(key: &[u8; 32], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, RepairError> {
    if ciphertext_with_nonce.len() < 12 {
        return Err(RepairError::Decryption("ciphertext too short".to_string()));
    }
    let nonce_bytes: [u8; 12] = ciphertext_with_nonce[..12]
        .try_into()
        .expect("slice length is 12");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(nonce, &ciphertext_with_nonce[12..])
        .map_err(|e| RepairError::Decryption(e.to_string()))
}
