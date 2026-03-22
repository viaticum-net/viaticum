// Scheduler: periodic PoS challenge issuance and timeout detection.
//
// Responsibilities:
//   - Issue PoS challenges to holders when they are due (based on due_challenges from pos module).
//   - Track pending challenges (waiting for response) in shared PendingChallenges map.
//   - Detect timed-out challenges and apply PlacementTransition via apply_pos_outcome.
//   - Trigger repair via repair_tx when a transition indicates trigger_repair=true.
//
// The PendingChallenges map is shared with the Processor so it can look up
// the source_block_id when a PosResponse arrives (Processor currently scans by ESI;
// PendingChallenges provides O(1) lookup for Phase 6.5+).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use syncback_core::constants::{POS_TIMEOUT_SECS, KI, KP, S_CLAMP_MAX, S_CLAMP_MIN};
use syncback_core::db::Db;
use syncback_core::messages::{Message, PosChallengeMsg};
use syncback_core::pos::{apply_pos_outcome, due_challenges, outcome_from_verify, select_challenge_esi, VerifyOutcome};
use syncback_core::types::{IdentityPub, PlacementStatus, SourceBlockId, Timestamp};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::daemon::network::NetworkHandle;
use crate::daemon::repair::RepairTrigger;

#[cfg(test)]
mod tests;

// ─── PendingChallenge ──────────────────────────────────────────────────────────

/// Context for a pending PoS challenge awaiting response from a holder.
#[derive(Clone, Debug)]
pub struct PendingChallenge {
    pub source_block_id: SourceBlockId,
    pub holder_id: IdentityPub,
    /// The ESI the holder was asked to prove.
    pub esi: u32,
    /// Wall-clock time when the challenge was issued (for timeout detection).
    pub issued_at: Timestamp,
    /// Raw challenge_id sent in the PosChallengeMsg (matches response challenge_id).
    pub challenge_id: [u8; 16],
}

/// Shared map of in-flight PoS challenges keyed by (source_block_id, holder_id).
/// One pending challenge per (block, holder) pair at a time.
///
/// Shared between Scheduler (writes) and Processor (reads when verifying PosResponse).
pub type PendingChallenges = Arc<Mutex<HashMap<(SourceBlockId, IdentityPub), PendingChallenge>>>;

// ─── SchedulerConfig ──────────────────────────────────────────────────────────

/// Configuration for the Scheduler.
pub struct SchedulerConfig {
    /// How often (wall-clock seconds, before scaling) to check for due challenges.
    pub pos_interval_secs: u64,
    /// How often (wall-clock seconds, before scaling) to check for timed-out challenges.
    pub timeout_check_secs: u64,
    /// Time acceleration factor. 1 = real time. Scales intervals and timeout threshold.
    /// Set > 1 in tests/demos to run weeks of PoS in seconds.
    pub time_scale: u64,
}

impl SchedulerConfig {
    /// Default config for production use (1-hour check interval, real-time scale).
    pub fn default_production() -> Self {
        SchedulerConfig {
            pos_interval_secs: 3600,
            timeout_check_secs: 3600,
            time_scale: 1,
        }
    }
}

// ─── Scheduler ────────────────────────────────────────────────────────────────

/// Periodic PoS challenge scheduler.
pub struct Scheduler {
    db: Db,
    config: SchedulerConfig,
    network: Arc<NetworkHandle>,
    repair_tx: mpsc::Sender<RepairTrigger>,
    /// Shared with Processor for response matching.
    pending: PendingChallenges,
}

impl Scheduler {
    /// Create a new Scheduler.
    pub fn new(
        db: Db,
        config: SchedulerConfig,
        network: Arc<NetworkHandle>,
        repair_tx: mpsc::Sender<RepairTrigger>,
        pending: PendingChallenges,
    ) -> Self {
        Scheduler {
            db,
            config,
            network,
            repair_tx,
            pending,
        }
    }

    /// Main run loop. Fires on two independent timers:
    ///   - pos_timer: call issue_due_challenges()
    ///   - timeout_timer: call check_timeouts()
    ///
    /// Both intervals are divided by time_scale before use.
    /// Exits cleanly when cancel fires.
    pub async fn run(self, cancel: CancellationToken) -> anyhow::Result<()> {
        let scale = self.config.time_scale.max(1);
        let pos_interval = Duration::from_secs((self.config.pos_interval_secs / scale).max(1));
        let timeout_interval =
            Duration::from_secs((self.config.timeout_check_secs / scale).max(1));

        let mut pos_timer = tokio::time::interval(pos_interval);
        let mut timeout_timer = tokio::time::interval(timeout_interval);
        // Skip the first immediate tick so we don't fire right at startup.
        pos_timer.tick().await;
        timeout_timer.tick().await;

        info!(
            pos_interval_secs = self.config.pos_interval_secs / scale,
            timeout_check_secs = self.config.timeout_check_secs / scale,
            "scheduler started"
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("scheduler: cancellation requested, shutting down");
                    break;
                }
                _ = pos_timer.tick() => {
                    if let Err(e) = self.issue_due_challenges().await {
                        error!("scheduler: issue_due_challenges error: {e}");
                    }
                }
                _ = timeout_timer.tick() => {
                    if let Err(e) = self.check_timeouts().await {
                        error!("scheduler: check_timeouts error: {e}");
                    }
                }
            }
        }

        Ok(())
    }

    /// Issue PoS challenges to all holders that are due for a challenge this cycle.
    ///
    /// Steps:
    ///   1. Get current timestamp.
    ///   2. List all placements from DB; filter to challengeable statuses.
    ///   3. Use due_challenges() to find which holders are overdue.
    ///   4. Skip placements that already have a pending challenge (avoid double-issue).
    ///   5. For each due entry: select ESI, build PosChallengeMsg, send via network.
    ///   6. On successful send: insert into pending_challenges.
    ///   7. Per-holder send errors are logged but do not abort the loop.
    pub async fn issue_due_challenges(&self) -> anyhow::Result<()> {
        let now = Timestamp::now();

        let placements = match self.db.list_all_placements() {
            Ok(ps) => ps,
            Err(e) => {
                error!("scheduler: list_all_placements failed: {e}");
                return Ok(());
            }
        };

        // Only challenge placements in a challengeable state.
        let challengeable: Vec<_> = placements
            .into_iter()
            .filter(|p| {
                matches!(
                    p.status,
                    PlacementStatus::Alive
                        | PlacementStatus::Uncertain
                        | PlacementStatus::PresumedLost
                )
            })
            .collect();

        if challengeable.is_empty() {
            debug!("scheduler: no challengeable placements");
            return Ok(());
        }

        // Build last_verified slice for due_challenges.
        let last_verified: Vec<_> = challengeable
            .iter()
            .map(|p| (p.source_block_id, p.holder_id, p.last_verified))
            .collect();

        // Derive trust score from DB peer records.
        let trust_fn = |holder: &IdentityPub| -> f64 {
            match self.db.get_peer(holder) {
                Ok(Some(peer)) => {
                    let s = peer.trust_s.clamp(S_CLAMP_MIN, S_CLAMP_MAX);
                    (KP * peer.trust_p + KI * peer.trust_i) * s
                }
                _ => 0.5, // unknown peer: medium trust
            }
        };

        let due = due_challenges(&challengeable, &last_verified, now, trust_fn);

        if due.is_empty() {
            debug!("scheduler: no challenges due at this interval");
            return Ok(());
        }

        // Snapshot pending keys once to avoid repeatedly locking inside the loop.
        let already_pending: Vec<(SourceBlockId, IdentityPub)> = {
            let guard = self.pending.lock().await;
            guard.keys().copied().collect()
        };

        info!(due = due.len(), "scheduler: issuing PoS challenges");

        for entry in due {
            let key = (entry.source_block_id, entry.holder_id);

            // Skip if we are still waiting for a prior response from this holder/block.
            if already_pending.contains(&key) {
                debug!(
                    block_id = %entry.source_block_id,
                    holder_id = %entry.holder_id,
                    "scheduler: challenge already pending, skipping"
                );
                continue;
            }

            // Find the corresponding SymbolPlacement for select_challenge_esi.
            let placement = match challengeable.iter().find(|p| {
                p.source_block_id == entry.source_block_id && p.holder_id == entry.holder_id
            }) {
                Some(p) => p,
                None => continue, // race: shouldn't happen
            };

            // Select ESI: nonce = timestamp XOR first 8 bytes of holder_id.
            let holder_prefix = entry.holder_id.0[..8].try_into().unwrap_or([0u8; 8]);
            let nonce = now.0 ^ u64::from_le_bytes(holder_prefix);
            let esi = match select_challenge_esi(placement, nonce) {
                Ok(e) => e,
                Err(e) => {
                    warn!(
                        block_id = %entry.source_block_id,
                        holder_id = %entry.holder_id,
                        "scheduler: select_challenge_esi failed: {e}"
                    );
                    continue;
                }
            };

            let challenge_id = random_challenge_id();
            let msg = Message::PosChallenge(PosChallengeMsg {
                v: 1,
                challenge_id,
                source_block_id: entry.source_block_id,
                esi,
                timestamp: now,
            });

            // Attempt to send. Log and continue on failure; don't record as pending.
            match self.network.get_connection(entry.holder_id).await {
                Err(e) => {
                    warn!(
                        holder_id = %entry.holder_id,
                        "scheduler: cannot connect to holder for PoS: {e}"
                    );
                    continue;
                }
                Ok(conn_arc) => {
                    if let Err(e) = conn_arc.send_message(&msg).await {
                        warn!(
                            holder_id = %entry.holder_id,
                            "scheduler: send PosChallenge failed: {e}"
                        );
                        continue;
                    }
                }
            }

            // Challenge successfully sent — track in pending map.
            self.pending.lock().await.insert(
                key,
                PendingChallenge {
                    source_block_id: entry.source_block_id,
                    holder_id: entry.holder_id,
                    esi,
                    issued_at: now,
                    challenge_id,
                },
            );

            info!(
                block_id = %entry.source_block_id,
                holder_id = %entry.holder_id,
                esi,
                "scheduler: PoS challenge issued"
            );
        }

        Ok(())
    }

    /// Check all pending challenges for timeout.
    ///
    /// A challenge is considered timed out when:
    ///   `now.0 - issued_at.0 >= POS_TIMEOUT_SECS / time_scale`
    ///
    /// For each timed-out challenge:
    ///   1. Look up the current placement from DB.
    ///   2. Apply Timeout outcome → get PlacementTransition.
    ///   3. Persist updated placement status/misses to DB.
    ///   4. If transition.trigger_repair: send RepairNow to repair_tx.
    ///   5. Remove from pending_challenges.
    pub async fn check_timeouts(&self) -> anyhow::Result<()> {
        let now = Timestamp::now();
        let scale = self.config.time_scale.max(1);
        let threshold = POS_TIMEOUT_SECS / scale;

        // Collect timed-out entries without holding the lock during DB calls.
        let timed_out: Vec<PendingChallenge> = {
            let guard = self.pending.lock().await;
            guard
                .values()
                .filter(|c| now.0.saturating_sub(c.issued_at.0) >= threshold)
                .cloned()
                .collect()
        };

        if timed_out.is_empty() {
            return Ok(());
        }

        info!(count = timed_out.len(), "scheduler: processing timed-out challenges");

        for challenge in &timed_out {
            let block_id = challenge.source_block_id;
            let holder_id = challenge.holder_id;

            // Load current placement record.
            let placement = match self.db.get_placement(&block_id, &holder_id) {
                Ok(Some(p)) => p,
                Ok(None) => {
                    warn!(
                        block_id = %block_id,
                        holder_id = %holder_id,
                        "scheduler: placement not found for timed-out challenge, removing from pending"
                    );
                    self.pending.lock().await.remove(&(block_id, holder_id));
                    continue;
                }
                Err(e) => {
                    error!("scheduler: DB error reading placement for timeout: {e}");
                    continue;
                }
            };

            let transition = apply_pos_outcome(&placement, &VerifyOutcome::Timeout);

            // Persist updated status.
            let mut updated = placement;
            updated.status = transition.new_status;
            updated.consecutive_misses = transition.new_consecutive_misses;

            if let Err(e) = self.db.upsert_placement(&updated) {
                error!(
                    block_id = %block_id,
                    holder_id = %holder_id,
                    "scheduler: DB error updating placement after timeout: {e}"
                );
                // Don't remove from pending if we couldn't persist — retry next cycle.
                continue;
            }

            // Record timeout as a challenged-but-not-passed event for trust.
            let week = crate::daemon::processor::current_week_number_scaled(scale);
            let pos_outcome = outcome_from_verify(&VerifyOutcome::Timeout, week);
            crate::daemon::processor::record_pos_weekly(&self.db, holder_id, pos_outcome);
            crate::daemon::processor::recalculate_trust(&self.db, &holder_id, week);

            info!(
                block_id = %block_id,
                holder_id = %holder_id,
                new_status = ?transition.new_status,
                misses = transition.new_consecutive_misses,
                trigger_repair = transition.trigger_repair,
                "scheduler: PoS challenge timed out"
            );

            // Trigger repair if the transition requires it.
            if transition.trigger_repair {
                let _ = self
                    .repair_tx
                    .send(RepairTrigger::RepairNow { block_id, holder_id })
                    .await;
            }

            // Remove from pending map — challenge lifecycle is over.
            self.pending.lock().await.remove(&(block_id, holder_id));
        }

        Ok(())
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Generate a 16-byte challenge ID from system time.
///
/// Not cryptographically secure — challenge_id is used only for matching
/// responses to pending challenges, not as a secret.
fn random_challenge_id() -> [u8; 16] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    // LCG mixing to generate two distinct 8-byte halves.
    let a = ns
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    let b = a
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);

    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&a.to_le_bytes());
    id[8..].copy_from_slice(&b.to_le_bytes());
    id
}
