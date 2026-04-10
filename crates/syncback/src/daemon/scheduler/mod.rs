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

use syncback_core::constants::{POS_TIMEOUT_SECS, S_CLAMP_MAX, S_CLAMP_MIN, SYMBOL_OFFER_TIMEOUT_SECS};
use syncback_core::trust::{compute_combined, compute_effective_trust, recalculate_trust};
use syncback_core::db::Db;
use syncback_core::deletion::{DeletionAction, DeletionEngine};
use syncback_core::messages::PosChallengeMsg;
use syncback_core::pos::{apply_pos_outcome, due_challenges, outcome_from_verify, select_challenge_esi, VerifyOutcome};
use syncback_core::types::{DeviceId, IdentityPub, PlacementStatus, SourceBlockId, SourceBlockStatus, Timestamp};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::daemon::relay::RelayPost;
use crate::daemon::repair::RepairTrigger;

#[cfg(test)]
mod tests;

// ─── PendingChallenge ──────────────────────────────────────────────────────────

/// Context for a pending PoS challenge awaiting response from a holder.
#[derive(Clone, Debug)]
pub struct PendingChallenge {
    pub source_block_id: SourceBlockId,
    pub holder_id: DeviceId,
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
pub type PendingChallenges = Arc<Mutex<HashMap<(SourceBlockId, DeviceId), PendingChallenge>>>;

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
    /// Maximum number of event_log rows to retain. Default: 100_000.
    pub event_log_retain_rows: u64,
    /// Number of pos_weekly weeks to retain. Default: P_WINDOW_WEEKS * 2.
    pub pos_weekly_retain_weeks: u32,
}

impl SchedulerConfig {
    /// Default config for production use (1-hour check interval, real-time scale).
    pub fn default_production() -> Self {
        SchedulerConfig {
            pos_interval_secs: 3600,
            timeout_check_secs: 3600,
            time_scale: 1,
            event_log_retain_rows: 100_000,
            pos_weekly_retain_weeks: syncback_core::constants::P_WINDOW_WEEKS * 2,
        }
    }
}

// ─── Scheduler ────────────────────────────────────────────────────────────────

/// Periodic PoS challenge scheduler.
pub struct Scheduler {
    db: Db,
    config: SchedulerConfig,
    repair_tx: mpsc::Sender<RepairTrigger>,
    /// Shared with Processor for response matching.
    pending: PendingChallenges,
    /// Channel to post messages to the relay board.
    relay_post_tx: mpsc::Sender<RelayPost>,
    /// Signing key for building DeleteMsg signatures.
    signing_key: ed25519_dalek::SigningKey,
    /// Directory containing owner-side source block files (`{block_id_hex}/*.bin`).
    /// Used by CleanupBlock to remove leftover symbol files from disk.
    source_blocks_dir: std::path::PathBuf,
    /// Shared accepted-offers map, periodically swept to evict stale entries.
    accepted_offers: crate::daemon::processor::AcceptedOffers,
}

impl Scheduler {
    /// Create a new Scheduler.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Db,
        config: SchedulerConfig,
        repair_tx: mpsc::Sender<RepairTrigger>,
        pending: PendingChallenges,
        relay_post_tx: mpsc::Sender<RelayPost>,
        signing_key: ed25519_dalek::SigningKey,
        source_blocks_dir: std::path::PathBuf,
        accepted_offers: crate::daemon::processor::AcceptedOffers,
    ) -> Self {
        Scheduler {
            db,
            config,
            repair_tx,
            pending,
            relay_post_tx,
            signing_key,
            source_blocks_dir,
            accepted_offers,
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
        // Deletion check: same interval as PoS (hourly, scaled).
        let deletion_interval = Duration::from_secs((3600 / scale).max(1));
        // accepted_offers sweep: 60 seconds / time_scale, min 1.
        let sweep_interval = Duration::from_secs((60 / scale).max(1));

        let mut pos_timer = tokio::time::interval(pos_interval);
        let mut timeout_timer = tokio::time::interval(timeout_interval);
        let mut deletion_timer = tokio::time::interval(deletion_interval);
        let mut sweep_timer = tokio::time::interval(sweep_interval);
        // Skip the first immediate tick so we don't fire right at startup.
        pos_timer.tick().await;
        timeout_timer.tick().await;
        deletion_timer.tick().await;
        sweep_timer.tick().await;

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
                _ = deletion_timer.tick() => {
                    if let Err(e) = self.process_deletion_tick().await {
                        error!("scheduler: process_deletion_tick error: {e}");
                    }
                }
                _ = sweep_timer.tick() => {
                    let evicted = crate::daemon::processor::prune_expired_accepted_offers(
                        &self.accepted_offers,
                        Timestamp::now(),
                    );
                    if evicted > 0 {
                        debug!(evicted, "scheduler: swept expired accepted offers");
                    }

                    // Opportunistic pruning of append-only tables (review BLOCK-4).
                    let event_log_retain_rows = self.config.event_log_retain_rows;
                    if let Ok(last_seq) = self.db.last_event_seq() {
                        if last_seq > event_log_retain_rows {
                            let cutoff = last_seq - event_log_retain_rows;
                            if let Ok(dropped) = self.db.truncate_event_log_before(cutoff) {
                                if dropped > 0 {
                                    debug!(dropped, cutoff, "scheduler: pruned event_log");
                                }
                            }
                        }
                    }
                    // Current scaled week (same formula as trust recalc).
                    let now = Timestamp::now();
                    let scale = self.config.time_scale.max(1);
                    let week_secs = syncback_core::constants::SECS_PER_WEEK / scale;
                    let current_week = (now.0 / week_secs) as u32;
                    let retain_weeks = self.config.pos_weekly_retain_weeks;
                    if current_week > retain_weeks {
                        let keep_after = current_week - retain_weeks;
                        if let Ok(dropped) = self.db.prune_pos_weekly_before(keep_after) {
                            if dropped > 0 {
                                debug!(dropped, keep_after, "scheduler: pruned pos_weekly");
                            }
                        }
                    }

                    // Sweep stale Offered placements → Lost.
                    if let Err(e) = self.sweep_offered_placements().await {
                        error!("scheduler: sweep_offered_placements error: {e}");
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

        // Derive trust score from DB peer records (keyed by DeviceId).
        let trust_fn = |holder: &DeviceId| -> f64 {
            let peer = match self.db.get_peer(holder) {
                Ok(Some(p)) => p,
                _ => return 0.5, // unknown peer: medium trust
            };
            let s = peer.trust_s.clamp(S_CLAMP_MIN, S_CLAMP_MAX);
            let master_identity = peer.master_identity;

            // Look up master_trust and device_trust for two-level trust formula.
            let master_trust = self.db.get_master_trust(&master_identity).ok().flatten();
            let device_trust = self.db.get_device_trust(holder).ok().flatten();

            if device_trust.is_none() && master_trust.is_none() {
                // No two-level data yet: fall back to legacy formula.
                return compute_combined(peer.trust_p, peer.trust_i, 1.0) * s;
            }

            let effective = compute_effective_trust(device_trust.as_ref(), master_trust.as_ref());
            effective * s
        };

        let due = due_challenges(&challengeable, &last_verified, now, trust_fn, self.config.time_scale);

        if due.is_empty() {
            debug!("scheduler: no challenges due at this interval");
            return Ok(());
        }

        // Snapshot pending keys once to avoid repeatedly locking inside the loop.
        let already_pending: Vec<(SourceBlockId, DeviceId)> = {
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

            // Generate the random challenge_id first so its bytes can seed ESI selection.
            // This makes the challenged ESI unpredictable to the holder.
            let challenge_id = random_challenge_id();

            // Select ESI: derive seed from the random challenge_id bytes.
            let seed = u64::from_le_bytes(challenge_id[..8].try_into().unwrap());
            let esi = match select_challenge_esi(placement, seed) {
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

            // Resolve master identity for relay board addressing (board uses IdentityPub).
            let holder_master = self.db.get_master_for_device(&entry.holder_id)
                .ok()
                .flatten()
                .map(|m| IdentityPub(m.0))
                .unwrap_or_else(|| IdentityPub(entry.holder_id.0));
            let challenge_msg = PosChallengeMsg {
                v: 1,
                challenge_id,
                source_block_id: entry.source_block_id,
                esi,
                timestamp: now,
                device_id: Some(entry.holder_id),
            };

            // Post challenge to relay board (directed to holder's master identity).
            // Board always accepts locally — no unreachable fallback needed.
            match syncback_core::messages::to_cbor(&challenge_msg) {
                Ok(payload) => {
                    let _ = self.relay_post_tx.send(crate::daemon::relay::RelayPost {
                        msg_type: "pos_challenge".to_string(),
                        target: Some(holder_master),
                        payload,
                        msg_id: challenge_id,
                    }).await;
                }
                Err(e) => {
                    error!(
                        block_id = %entry.source_block_id,
                        holder_id = %entry.holder_id,
                        "scheduler: failed to encode PosChallenge: {e}"
                    );
                    continue;
                }
            }

            // Challenge posted to board — track in pending map.
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
                "scheduler: PoS challenge issued via board"
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
            recalculate_trust(&self.db, &holder_id, week);

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

    /// Process deletion cooldowns: run DeletionEngine, execute returned actions.
    pub async fn process_deletion_tick(&self) -> anyhow::Result<()> {
        let now = Timestamp::now();
        let engine = DeletionEngine::new();

        let files = self.db.list_all_files().unwrap_or_default();
        let blocks = self.db.list_all_source_blocks().unwrap_or_default();
        let placements = self.db.list_all_placements().unwrap_or_default();

        let actions = engine.process_cooldowns(&files, &blocks, &placements, now, self.config.time_scale);
        if actions.is_empty() {
            return Ok(());
        }

        info!(count = actions.len(), "scheduler: processing deletion actions");

        for action in actions {
            match action {
                DeletionAction::SendDropNotice { source_block_id, holder_id } => {
                    // Dedup: only send once per source block.
                    let source_block = self.db.get_source_block(&source_block_id).ok().flatten();
                    if source_block.as_ref().and_then(|sb| sb.drop_notice_sent_at).is_some() {
                        debug!(
                            block_id = %source_block_id,
                            holder_id = %holder_id,
                            "scheduler: drop notice already sent for this block, skipping"
                        );
                        continue;
                    }

                    // Build signed DeleteMsg, post to board, mark placement Deleting.
                    let delete_msg = syncback_core::messages::build_delete_msg(
                        source_block_id, now, &self.signing_key,
                    );
                    // Relay board uses master IdentityPub as target.
                    let holder_master = self.db.get_master_for_device(&holder_id)
                        .ok()
                        .flatten()
                        .unwrap_or(IdentityPub(holder_id.0));
                    if let Ok(payload) = syncback_core::messages::to_cbor(&delete_msg) {
                        let mut msg_id = [0u8; 16];
                        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut msg_id);
                        let _ = self.relay_post_tx.send(RelayPost {
                            msg_type: "delete".to_string(),
                            target: Some(holder_master),
                            payload,
                            msg_id,
                        }).await;
                    }

                    // Mark placement + source block Deleting, record drop_notice_sent_at atomically.
                    let placement = self.db.get_placement(&source_block_id, &holder_id).ok().flatten();

                    if placement.is_some() || source_block.is_some() {
                        match self.db.write_txn() {
                            Err(e) => error!(block_id = %source_block_id, "deletion: failed to open write txn: {e}"),
                            Ok(mut txn) => {
                                let mut txn_ok = true;
                                if let Some(mut p) = placement {
                                    p.status = PlacementStatus::Deleting;
                                    if let Err(e) = txn.upsert_placement(&p) {
                                        error!(block_id = %source_block_id, holder_id = %holder_id, "deletion: failed to update placement: {e}");
                                        txn_ok = false;
                                    }
                                }
                                if txn_ok {
                                    if let Some(mut sb) = source_block {
                                        sb.drop_notice_sent_at = Some(now);
                                        if sb.status == SourceBlockStatus::Active || sb.status == SourceBlockStatus::Stale {
                                            sb.status = SourceBlockStatus::Deleting;
                                        }
                                        if let Err(e) = txn.upsert_source_block(&sb) {
                                            error!(block_id = %source_block_id, "deletion: failed to update source block: {e}");
                                            txn_ok = false;
                                        }
                                    }
                                }
                                if txn_ok {
                                    if let Err(e) = txn.commit() {
                                        error!(block_id = %source_block_id, "deletion: failed to commit txn: {e}");
                                    }
                                }
                            }
                        }
                    }

                    info!(
                        block_id = %source_block_id,
                        holder_id = %holder_id,
                        "scheduler: sent DeleteMsg via board, placement → Deleting"
                    );
                }
                DeletionAction::CleanupPlacement { source_block_id, holder_id } => {
                    if let Err(e) = self.db.delete_placement(&source_block_id, &holder_id) {
                        error!(block_id = %source_block_id, holder_id = %holder_id, "deletion: failed to delete placement: {e}");
                    }
                    info!(
                        block_id = %source_block_id,
                        holder_id = %holder_id,
                        "scheduler: cleaned up placement"
                    );
                }
                DeletionAction::CleanupBlock { source_block_id, file_id } => {
                    // Read the file record before opening the transaction (read-then-write pattern).
                    let file_opt = self.db.get_file_by_id(file_id).ok().flatten().map(|mut file| {
                        file.versions.retain(|v| v.source_block_id != source_block_id);
                        file
                    });
                    // Delete source block + update file record atomically.
                    match self.db.write_txn() {
                        Err(e) => error!(block_id = %source_block_id, "deletion: failed to open write txn: {e}"),
                        Ok(mut txn) => {
                            let mut txn_ok = true;
                            if let Err(e) = txn.delete_source_block(&source_block_id) {
                                error!(block_id = %source_block_id, "deletion: failed to delete source block: {e}");
                                txn_ok = false;
                            }
                            if txn_ok {
                                if let Some(file) = file_opt {
                                    if let Err(e) = txn.upsert_file(&file) {
                                        error!(file_id = %file_id, "deletion: failed to update file after block cleanup: {e}");
                                        txn_ok = false;
                                    }
                                }
                            }
                            if txn_ok {
                                if let Err(e) = txn.commit() {
                                    error!(block_id = %source_block_id, "deletion: failed to commit cleanup txn: {e}");
                                }
                            }
                        }
                    }
                    // Remove owner-side symbol files from disk (review B2 / Flow 7 BLOCK).
                    // Previously the DB record was cleaned up but `{source_blocks_dir}/{block_id}/*.bin`
                    // remained forever, leaking disk space.
                    let block_hex = syncback_core::types::hex_encode(&source_block_id.0);
                    let block_dir = self.source_blocks_dir.join(&block_hex);
                    if block_dir.exists() {
                        if let Err(e) = std::fs::remove_dir_all(&block_dir) {
                            warn!(
                                block_id = %source_block_id,
                                path = %block_dir.display(),
                                err = %e,
                                "scheduler: failed to remove owner-side source block directory"
                            );
                        }
                    }
                    info!(
                        block_id = %source_block_id,
                        file_id = %file_id,
                        "scheduler: cleaned up source block + file version + disk files"
                    );
                }
                DeletionAction::VacuumBlock { source_block_id, .. } => {
                    // Vacuum (repack) is complex — defer for now, just log.
                    debug!(
                        block_id = %source_block_id,
                        "scheduler: VacuumBlock deferred (repack not implemented)"
                    );
                }
                DeletionAction::WaitForOtherDevices { file_id } => {
                    debug!(
                        file_id = %file_id,
                        "scheduler: waiting for other devices to delete"
                    );
                }
            }
        }

        Ok(())
    }

    /// Sweep Offered placements that have exceeded the timeout threshold.
    ///
    /// For each stale Offered placement:
    ///   1. Transition status to Lost via upsert_placement.
    ///   2. Send RepairTrigger::RepairNow { block_id, holder_id }.
    ///
    /// Called on the sweep_timer tick (same interval as accepted_offers pruning).
    pub async fn sweep_offered_placements(&self) -> anyhow::Result<()> {
        let now = Timestamp::now();
        let scale = self.config.time_scale.max(1);
        let threshold = SYMBOL_OFFER_TIMEOUT_SECS / scale;

        let placements = self.db.list_all_placements()?;
        for p in &placements {
            if p.status != PlacementStatus::Offered {
                continue;
            }
            let age = now.0.saturating_sub(p.placed_at.0);
            if age < threshold {
                continue;
            }
            // Transition Offered → Lost.
            let mut updated = p.clone();
            updated.status = PlacementStatus::Lost;
            self.db.upsert_placement(&updated)?;

            info!(
                block_id = %p.source_block_id,
                holder = %p.holder_id,
                age_secs = age,
                "scheduler: Offered placement timed out → Lost"
            );

            let _ = self
                .repair_tx
                .send(RepairTrigger::RepairNow {
                    block_id: p.source_block_id,
                    holder_id: p.holder_id,
                })
                .await;
        }
        Ok(())
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn random_challenge_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    id
}
