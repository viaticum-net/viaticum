// Scheduler: periodic PoS challenge issuance and timeout detection.
//
// Responsibilities:
//   - Issue PoS challenges to holders when they are due (based on due_challenges from pos module).
//   - Track pending challenges (waiting for response) in the shared PendingIndex.
//   - Detect timed-out challenges and apply PlacementTransition via apply_pos_outcome.
//   - Trigger repair via repair_tx when a transition indicates trigger_repair=true.
//
// The PendingIndex is written by the Scheduler and read by the mailbox poll loop, which
// forwards to the scheduler only the responses whose challenge is still pending (pos-i6).
// A response is resolved by its challenge_id through the index (pos-i7).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use viaticum_core::constants::{
    LONG_ABSENCE_SECS, POS_CHALLENGE_PENDING_TIMEOUT_SECS, S_CLAMP_MAX, S_CLAMP_MIN,
};
use viaticum_core::db::Db;
use viaticum_core::deletion::{DeletionAction, DeletionEngine};
use viaticum_core::mailbox::{DeleteRequestPayload, MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::messages::{PosHashResponseMsg, to_cbor};
use viaticum_core::pair_ledger::{
    AccrualStats, LossCause, PairLedgerError, PairLedgerRecorder, TickReport, tick_interval_secs,
};
use viaticum_core::pos::{VerifyOutcome, apply_pos_outcome, due_challenges, outcome_from_verify};
use viaticum_core::trust::{compute_combined, compute_effective_trust, recalculate_trust};
use viaticum_core::types::{
    DeviceId, IdentityPub, PlacementStatus, SourceBlockId, SourceBlockStatus, SymbolPlacement,
    Timestamp, hex_encode,
};

use crate::daemon::mailbox::routing::MailboxRouter;
use crate::daemon::repair::RepairTrigger;

mod pending;
#[cfg(test)]
mod tests;

// ─── Pending challenges ───────────────────────────────────────────────────────

pub use pending::{
    PendingChallenges, PendingHashChallenge, PendingIndex, PendingKey, new_pending_challenges,
};

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
            pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
        }
    }
}

// ─── Scheduler ────────────────────────────────────────────────────────────────

/// Periodic PoS challenge scheduler.
pub struct Scheduler {
    db: Db,
    config: SchedulerConfig,
    repair_tx: mpsc::Sender<RepairTrigger>,
    /// In-flight challenges: written here, read by the mailbox poll loop (pos-i6).
    pending: PendingChallenges,
    /// Mailbox router for publishing PoS challenges via the mailbox bus (T-6).
    /// Replaces the relay path for PosHashChallengeMsg.
    mailbox_router: Arc<MailboxRouter>,
    /// This node's master identity public key (sent as MailboxEntry.sender so holder
    /// knows where to publish the response).
    my_master_pub: IdentityPub,
    /// Signing key for building DeleteMsg signatures.
    signing_key: ed25519_dalek::SigningKey,
    /// Shared accepted-offers map, periodically swept to evict stale entries.
    accepted_offers: crate::daemon::processor::AcceptedOffers,
    /// Erasure encoder for computing raw symbols during hash challenge issuance.
    encoder: std::sync::Arc<dyn viaticum_core::erasure::ErasureEncoder>,
    /// Epoch encryption key for rebuilding source block blobs.
    epoch_key: [u8; 32],
    /// Base data dir (`~/.viaticum`); SystemState retained block blobs live under
    /// `<data_dir>/system_state/`. Used by `load_source_block_data` to serve PoS
    /// challenges for SS blocks (which have no backing watch-dir file).
    data_dir: std::path::PathBuf,
}

impl Scheduler {
    /// Create a new Scheduler.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Db,
        config: SchedulerConfig,
        repair_tx: mpsc::Sender<RepairTrigger>,
        pending: PendingChallenges,
        mailbox_router: Arc<MailboxRouter>,
        my_master_pub: IdentityPub,
        signing_key: ed25519_dalek::SigningKey,
        accepted_offers: crate::daemon::processor::AcceptedOffers,
        encoder: std::sync::Arc<dyn viaticum_core::erasure::ErasureEncoder>,
        epoch_key: [u8; 32],
        data_dir: std::path::PathBuf,
    ) -> Self {
        Scheduler {
            db,
            config,
            repair_tx,
            pending,
            mailbox_router,
            my_master_pub,
            signing_key,
            accepted_offers,
            encoder,
            epoch_key,
            data_dir,
        }
    }

    /// Main run loop. Fires on five independent timers:
    ///   - pos_timer: call issue_due_challenges()
    ///   - timeout_timer: call check_timeouts()
    ///   - deletion_timer: call process_deletion_tick()
    ///   - ledger_timer: call accrue_pair_ledgers() (4R recorder, decides nothing)
    ///   - sweep_timer: prune expired accepted offers
    ///
    /// Every one of the five intervals is divided by time_scale before use (floor 1 s).
    /// Exits cleanly when cancel fires.
    ///
    /// `pos_response_rx`: receives polled PosHashResponseMsg from run_mailbox_poll.
    /// On receipt, resolves the matching pending challenge (owner side).
    pub async fn run(
        self,
        mut pos_response_rx: mpsc::Receiver<PosHashResponseMsg>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let scale = self.config.time_scale.max(1);
        let pos_interval =
            Duration::from_secs(scaled_timer_secs(self.config.pos_interval_secs, scale));
        let timeout_interval = Duration::from_secs((self.config.timeout_check_secs / scale).max(1));
        // Deletion check: same interval as PoS (hourly, scaled).
        let deletion_interval = Duration::from_secs((3600 / scale).max(1));
        // accepted_offers sweep: 60 seconds / time_scale, min 1.
        let sweep_interval = Duration::from_secs((60 / scale).max(1));
        // 4R pair-ledger accrual: hourly, scaled. Its own timer rather than a passenger on
        // pos_timer — the accrual must not be skipped because challenge issuance failed,
        // and the two have nothing to do with each other.
        //
        // The period comes from `pair_ledger::tick_interval_secs` and not from a local
        // `(PAIR_LEDGER_TICK_SECS / scale).max(1)`, even though the expression is identical:
        // the recorder sizes its observed window in periods of THIS timer, and the local
        // copy of the formula is what let the two drift apart (BLOCK-1, third gate).
        let ledger_interval = Duration::from_secs(tick_interval_secs(scale));

        let mut pos_timer = tokio::time::interval(pos_interval);
        let mut timeout_timer = tokio::time::interval(timeout_interval);
        let mut deletion_timer = tokio::time::interval(deletion_interval);
        let mut sweep_timer = tokio::time::interval(sweep_interval);
        let mut ledger_timer = tokio::time::interval(ledger_interval);
        // ARCH-4a: skip missed ticks instead of bursting to catch up. After the
        // daemon is offline (suspend / long GC pause), the default Burst behavior
        // would fire each timer back-to-back for every missed interval — a thundering
        // herd of PoS-issuance, deletion-publish and sweep passes. Skip collapses the
        // backlog to a single tick, matching poll.rs / work_pipeline.
        pos_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        timeout_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        deletion_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        sweep_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ledger_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the first immediate tick so we don't fire right at startup.
        pos_timer.tick().await;
        timeout_timer.tick().await;
        deletion_timer.tick().await;
        sweep_timer.tick().await;
        ledger_timer.tick().await;

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
                _ = ledger_timer.tick() => {
                    match self.accrue_pair_ledgers_report(Timestamp::now()) {
                        Ok(report) => {
                            let stats = report.stats;
                            debug!(
                                accrued = stats.accrued,
                                seeded = stats.seeded,
                                idle = stats.idle,
                                with_unobserved_gap = stats.with_unobserved_gap,
                                truncated = stats.truncated,
                                believed_not_confirmed = stats.believed_not_confirmed,
                                drop_events_folded = stats.drop_events_folded,
                                "scheduler: pair-ledger accrual tick"
                            );
                            log_ledger_rows(&report);
                            if stats.truncated > 0 {
                                // Only a corrupt `last_update` reaches the sub-step ceiling
                                // (8000 years in one call). Say so instead of swallowing it,
                                // with the SIZE of the shortfall: "one year off" and "2^40
                                // seconds off" are different diagnoses.
                                warn!(
                                    rows = stats.truncated,
                                    uncovered_days = stats.uncovered_days,
                                    "scheduler: pair-ledger interval hit the sub-step ceiling — \
                                     check the clock"
                                );
                            }
                        }
                        Err(e) => error!("scheduler: accrue_pair_ledgers error: {e}"),
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
                    if let Ok(last_seq) = self.db.last_event_seq()
                        && last_seq > event_log_retain_rows {
                            let cutoff = last_seq - event_log_retain_rows;
                            if let Ok(dropped) = self.db.truncate_event_log_before(cutoff)
                                && dropped > 0 {
                                    debug!(dropped, cutoff, "scheduler: pruned event_log");
                                }
                        }
                    // Current scaled week — must match the formula in
                    // processor::current_week_number_scaled. At time_scale > 1 the naive
                    // `now / (SECS_PER_WEEK/scale)` form diverges from `(now*scale)/SECS_PER_WEEK`
                    // by rounding, which caused prune_pos_weekly_before to wipe freshly
                    // written entries.
                    let scale = self.config.time_scale.max(1);
                    let current_week =
                        crate::daemon::processor::current_week_number_scaled(scale);
                    let retain_weeks = self.config.pos_weekly_retain_weeks;
                    if current_week > retain_weeks {
                        let keep_after = current_week - retain_weeks;
                        if let Ok(dropped) = self.db.prune_pos_weekly_before(keep_after)
                            && dropped > 0 {
                                debug!(dropped, keep_after, "scheduler: pruned pos_weekly");
                            }
                    }

                    // TODO(S-9): call redb::Database::compact() after pruning to
                    // reclaim freed pages — redb is append-only MVCC, pruning
                    // releases logical rows but physical pages stay allocated.
                    // Blocked by Arc<Database> wrapper: compact() needs &mut self.
                    // Refactoring Db to Arc<RwLock<Database>> is required —
                    // deferred to Wave C as it's not a mechanical fix.

                    // Sweep stale Offered placements → Lost.
                    if let Err(e) = self.sweep_offered_placements().await {
                        error!("scheduler: sweep_offered_placements error: {e}");
                    }
                }
                // PosResponse arrived via mailbox poll → resolve pending challenge.
                maybe_response = pos_response_rx.recv() => {
                    match maybe_response {
                        None => {
                            // Channel closed: poll loop shut down (cancel propagated).
                            debug!("scheduler: pos_response_rx closed");
                        }
                        Some(response) => {
                            if let Err(e) = self.handle_pos_response_from_mailbox(response).await {
                                error!("scheduler: handle_pos_response_from_mailbox: {e}");
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Owner side: resolve a PosHashResponse received via the mailbox poll channel.
    ///
    /// Finds the matching pending challenge by challenge_id, verifies the hash,
    /// and applies the PoS outcome to the placement.
    async fn handle_pos_response_from_mailbox(
        &self,
        response: PosHashResponseMsg,
    ) -> anyhow::Result<()> {
        // Find the pending challenge by challenge_id through the index (pos-i7). Capture
        // its key + the holder_master we resolved AT ISSUE TIME (CS-POS-3) without
        // consuming the entry — the verify below must leave the pending intact on failure.
        //
        // pos-i6: the poll loop forwards only responses to pending challenges, once per
        // envelope, so this WARN is left for the race "the response arrived while its
        // challenge was timing out" and a second honest envelope of one challenge (a
        // holder restart while this scheduler was busy).
        let found = {
            let guard = self.pending.lock().await;
            guard
                .key_of(&response.challenge_id)
                .and_then(|k| guard.get(&k).map(|v| (k, v.holder_master)))
        };
        let Some((key, holder_master)) = found else {
            warn!(
                challenge_id = %hex_encode(&response.challenge_id),
                "scheduler: PosHashResponse from mailbox with unknown challenge_id (stale or duplicate)"
            );
            return Ok(());
        };

        let block_id = key.0;
        let holder_id = key.1;

        // CS-ID-1 / P1-1 / P1-7: authenticate the response BEFORE consuming the pending entry
        // or applying any outcome. The holder signs the response with its master key; we verify
        // against the holder_master captured when this challenge was issued (CS-POS-3) — the
        // SAME key the challenge was addressed to. A positioned postman forging a wrong-hash
        // response cannot sign for that master → verification fails, we DROP the response and
        // LEAVE the pending entry intact so the honest holder's real response can still resolve
        // it (and so the forge does not frame the holder with a Fail). Verifying against the
        // captured master (rather than a re-resolve here) means a peer-record change between
        // issue and response can no longer flip an honest holder's response to unverifiable.
        if let Err(e) = viaticum_core::messages::verify_pos_hash_response(&response, &holder_master)
        {
            warn!(
                block_id = %block_id,
                holder_id = %holder_id,
                err = %e,
                "scheduler: PosHashResponse signature verification failed — ignoring (forge attempt or unsigned), pending left intact"
            );
            return Ok(());
        }

        // Defence-in-depth: the signed response binds source_block_id, and the challenge_id
        // maps 1:1 to this (block, holder). A valid signature for a different block would only
        // arise from a holder mis-stamping its own response; reject the mismatch rather than
        // apply an outcome to the wrong placement.
        if response.source_block_id != block_id {
            warn!(
                block_id = %block_id,
                holder_id = %holder_id,
                response_block = %response.source_block_id,
                "scheduler: PosHashResponse source_block_id mismatch — ignoring, pending left intact"
            );
            return Ok(());
        }

        // Authenticated — consume the entry; the challenge lifecycle ends here.
        let pending = {
            let mut guard = self.pending.lock().await;
            guard.remove(&key)
        };
        let pending = match pending {
            Some(p) => p,
            None => return Ok(()),
        };
        let first_esi = pending
            .esi_ranges
            .first()
            .map(|&(start, _)| start)
            .unwrap_or(0);

        let outcome = viaticum_core::pos::verify_hash_response(
            &response.chain_hash,
            &pending.expected_chain_hash,
            first_esi,
        );

        // Apply outcome to DB.
        let placement = match self.db.get_placement(&block_id, &holder_id)? {
            Some(p) => p,
            None => {
                warn!(block_id = %block_id, holder_id = %holder_id,
                    "scheduler: mailbox PosResponse — placement missing");
                return Ok(());
            }
        };

        let old_status = placement.status;
        // A verdict on a placement that holds no symbols (Offered, Accepted, Lost,
        // Deleting) is stale: its episode is already closed.
        let stale = !old_status.may_hold_symbols();
        let transition = viaticum_core::pos::apply_pos_outcome(&placement, &outcome);
        let mut updated = placement.clone();
        updated.status = transition.new_status;
        updated.consecutive_misses = transition.new_consecutive_misses;
        // pos-i3: leave the record of a stale verdict untouched so a concurrent worker
        // rewrite is not clobbered.
        if !stale {
            if matches!(outcome, viaticum_core::pos::VerifyOutcome::Pass) {
                updated.last_verified = Some(Timestamp::now());
            }
            // У-4: a proven loss (wrong hash / explicit NotHeld) of a held placement is a SILENT
            // drop for the pair ledger, recorded in the same transaction as this write; the
            // evidence time is when WE issued the challenge.
            let loss_cause = match outcome {
                VerifyOutcome::Fail { .. } => Some(LossCause::PosFail),
                VerifyOutcome::NotHeld { .. } => Some(LossCause::PosNotHeld),
                _ => None,
            };
            crate::daemon::processor::persist_placement_change(
                &self.db,
                &placement,
                &updated,
                loss_cause,
                pending.issued_at,
                None,
            )?;
        }

        if updated.status != old_status {
            crate::daemon::processor::recompute_and_persist_block_cached_fields(
                &self.db, &block_id,
            );
        }

        if let Err(e) = self.db.refresh_peer_storage_bytes(&holder_id) {
            error!(peer = %holder_id, err = %e,
                "scheduler: failed to refresh storage bytes after mailbox PosResponse");
        }

        // pos-i4: a stale verdict is written neither to the weekly PoS counters nor to
        // trust — no second penalty for a drop already accounted (NotHeld, DropNotice),
        // no credit for service in a closed episode.
        let scale = self.config.time_scale.max(1);
        let week = crate::daemon::processor::current_week_number_scaled(scale);
        if !stale {
            crate::daemon::processor::record_pos_weekly(
                &self.db,
                holder_id,
                outcome_from_verify(&outcome, week),
            );
        }
        if !stale
            && let Some((old_p, old_i, new_p, new_i)) =
                viaticum_core::trust::recalculate_trust(&self.db, &holder_id, week)
        {
            let old_combined = compute_combined(old_p, old_i, 1.0);
            let new_combined = compute_combined(new_p, new_i, 1.0);
            info!(
                peer = %holder_id,
                trust_p_before = format!("{old_p:.4}"),
                trust_p_after = format!("{new_p:.4}"),
                trust_i_before = format!("{old_i:.4}"),
                trust_i_after = format!("{new_i:.4}"),
                trust_combined_before = format!("{old_combined:.4}"),
                trust_combined_after = format!("{new_combined:.4}"),
                "trust: score updated after PoS (mailbox)"
            );
        }

        // old_status/new_status make the PoS state machine observable in E2E: a
        // silent holder that comes back leaves PresumedLost only through this line
        // (repair-i2 exit door).
        info!(
            block_id = %block_id,
            holder = %holder_id,
            outcome = ?outcome,
            old_status = ?old_status,
            new_status = ?updated.status,
            stale,
            challenge_id = %hex_encode(&response.challenge_id),
            "scheduler: mailbox PosResponse resolved"
        );

        if transition.trigger_repair {
            let _ = self
                .repair_tx
                .send(crate::daemon::repair::RepairTrigger::Wake)
                .await;
        }

        Ok(())
    }

    /// Issue PoS hash challenges to all holders that are due for a challenge this cycle.
    ///
    /// Steps:
    ///   1. Get current timestamp.
    ///   2. List all placements from DB; filter to challengeable statuses.
    ///   3. Filter out SS-blocks (Bug-B: hash-PoS for SS-blocks is a separate near-term task).
    ///   4. Use due_challenges() to find which holders are overdue.
    ///   5. Skip placements that already have a pending challenge (avoid double-issue).
    ///   6. Group due entries by source_block_id.
    ///   7. For each block: encode_raw once (union of all holders' ESI ranges), then
    ///      per-holder apply binding + compute chain hash in spawn_blocking.
    ///   8. Publish PosHashChallengeMsg to holder via mailbox_router (T-6).
    ///      W-3: insert into pending ONLY after ≥1 MailboxStoreAck; 0 acks = retry next tick.
    ///
    /// pos-i7: linear in the placements — `due_challenges` indexes `last_verified`, the
    /// pending keys are a set, the placements are indexed by (block, holder), and a
    /// holder's trust is read once per tick. A tick with due challenges ends with one
    /// INFO line `scheduler: PoS issue tick` (due, issued, elapsed_ms, cpw_min, cpw_max).
    pub async fn issue_due_challenges(&self) -> anyhow::Result<()> {
        let started = Instant::now();
        let now = Timestamp::now();

        let placements = match self.db.list_all_placements() {
            Ok(ps) => ps,
            Err(e) => {
                error!("scheduler: list_all_placements failed: {e}");
                return Ok(());
            }
        };

        // Bug-B: SS-blocks are excluded from due_challenges until hash-PoS for SS-blocks
        // is implemented (separate near-term task, high priority). See TODO(bug-b) in pos/mod.rs.
        // publish() enforces per-peer ack window (PEER_REQUEST_TIMEOUT in MailboxRouter); the >=1-ack count gate is the W-3 check.
        let ss_ids = match self.db.ss_block_id_set() {
            Ok(ids) => ids,
            Err(e) => {
                warn!(
                    "scheduler: ss_block_id_set failed: {e}; treating as empty (may challenge SS blocks)"
                );
                HashSet::new()
            }
        };

        // Only challenge placements in a challengeable state, excluding SS-blocks.
        let challengeable: Vec<_> = placements
            .into_iter()
            .filter(|p| {
                matches!(
                    p.status,
                    PlacementStatus::Alive
                        | PlacementStatus::Uncertain
                        | PlacementStatus::PresumedLost
                ) && !ss_ids.contains(&p.source_block_id.0)
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

        // 5b (pos-i7): a holder's trust is three redb reads; read it once per holder per
        // tick, not once per placement.
        let trust = holder_trust_map(&challengeable, |h| self.holder_trust(h));

        let due = due_challenges(
            &challengeable,
            &last_verified,
            now,
            |h| trust.get(h).copied().unwrap_or(0.5),
            self.config.time_scale,
        );

        if due.is_empty() {
            debug!("scheduler: no challenges due at this interval");
            return Ok(());
        }
        let mut tick = IssueTick {
            due: due.len(),
            cpw_min: due.iter().map(|e| e.cpw).min().unwrap_or(0),
            cpw_max: due.iter().map(|e| e.cpw).max().unwrap_or(0),
            ..IssueTick::default()
        };

        // Snapshot pending keys once to avoid repeatedly locking inside the loop.
        let already_pending: HashSet<PendingKey> = {
            let guard = self.pending.lock().await;
            guard.keys().copied().collect()
        };

        // The challengeable placements by (block, holder), built once per tick.
        let placement_of: HashMap<PendingKey, &SymbolPlacement> = challengeable
            .iter()
            .map(|p| ((p.source_block_id, p.holder_id), p))
            .collect();

        // Group due entries by source_block_id so we encode each block's raw symbols once.
        let mut by_block: HashMap<SourceBlockId, Vec<&viaticum_core::pos::ChallengeScheduleEntry>> =
            HashMap::new();
        for entry in &due {
            by_block
                .entry(entry.source_block_id)
                .or_default()
                .push(entry);
        }

        for (block_id, block_entries) in by_block {
            // Filter out already-pending entries.
            let before = block_entries.len();
            let block_entries: Vec<_> = block_entries
                .into_iter()
                .filter(|e| !already_pending.contains(&(e.source_block_id, e.holder_id)))
                .collect();
            tick.skipped_pending += before - block_entries.len();
            if block_entries.is_empty() {
                continue;
            }
            let cpw_of: HashMap<DeviceId, u32> =
                block_entries.iter().map(|e| (e.holder_id, e.cpw)).collect();

            // Find corresponding SymbolPlacements.
            let holder_placements: Vec<&SymbolPlacement> = block_entries
                .iter()
                .filter_map(|e| placement_of.get(&(e.source_block_id, e.holder_id)).copied())
                .collect();

            if holder_placements.is_empty() {
                continue;
            }

            // Load source block data (retained SS blob, else rebuild from source files).
            let source_data = match self.load_source_block_data(&block_id).await {
                Ok(d) => d,
                Err(e) => {
                    warn!(
                        block_id = %block_id,
                        err = %e,
                        "scheduler: cannot load source block for PoS hash, skipping"
                    );
                    continue;
                }
            };

            let block_record = match self.db.get_source_block(&block_id) {
                Ok(Some(r)) => r,
                _ => {
                    warn!(block_id = %block_id, "scheduler: source block record missing, skipping");
                    continue;
                }
            };
            let params = block_record.erasure_params();

            // Compute union of all ESI ranges across all holders for this block.
            let mut all_esi_ranges: Vec<(u32, u32)> = Vec::new();
            for p in &holder_placements {
                all_esi_ranges.extend_from_slice(&p.esi_ranges);
            }

            // Per-holder data for the spawn_blocking closure.
            let holder_data: Vec<(DeviceId, Vec<(u32, u32)>)> = holder_placements
                .iter()
                .map(|p| (p.holder_id, p.esi_ranges.clone()))
                .collect();

            // Generate challenge_ids BEFORE spawn_blocking so the OsRng nonce is committed
            // before compute_chain_hash runs. This binds expected_hash to this challenge_id.
            let challenge_ids: HashMap<DeviceId, [u8; 16]> = holder_data
                .iter()
                .map(|(holder_id, _)| (*holder_id, random_challenge_id()))
                .collect();
            let challenge_ids_clone = challenge_ids.clone();

            let encoder = std::sync::Arc::clone(&self.encoder);
            let block_id_clone = block_id;

            // encode_raw once for the block, then compute per-holder chain hashes.
            #[allow(clippy::type_complexity)]
            let hash_results = tokio::task::spawn_blocking(
                move || -> Vec<(DeviceId, [u8; 32], Vec<(u32, u32)>)> {
                    // Encode raw symbols for the union of all holders' ESI ranges.
                    let mut raw_symbols: HashMap<u32, Vec<u8>> = HashMap::new();
                    for &(start, count) in &all_esi_ranges {
                        if count == 0 {
                            continue;
                        }
                        match encoder.encode_raw(&source_data, &params, start, count) {
                            Ok(syms) => {
                                for sym in syms {
                                    raw_symbols.insert(sym.esi, sym.data);
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    block_id = %block_id_clone,
                                    "scheduler: encode_raw failed: {e}"
                                );
                                return vec![];
                            }
                        }
                    }

                    // Per-holder: apply binding, compute chain hash.
                    let mut results = Vec::new();
                    for (holder_id, esi_ranges) in &holder_data {
                        // Expand ranges to sorted ESI list.
                        let mut esis: Vec<u32> = esi_ranges
                            .iter()
                            .flat_map(|&(start, count)| start..start + count)
                            .collect();
                        esis.sort_unstable();

                        // Apply binding keystream and collect bound symbols.
                        let bound_pairs: Vec<(u32, Vec<u8>)> = esis
                            .iter()
                            .filter_map(|&esi| {
                                raw_symbols.get(&esi).map(|raw_data| {
                                    let mut data = raw_data.clone();
                                    let ks = viaticum_core::erasure::binding_keystream(
                                        &block_id_clone,
                                        holder_id,
                                        esi,
                                        data.len(),
                                    );
                                    for (d, k) in data.iter_mut().zip(ks.iter()) {
                                        *d ^= k;
                                    }
                                    (esi, data)
                                })
                            })
                            .collect();

                        let refs: Vec<(u32, &[u8])> = bound_pairs
                            .iter()
                            .map(|(esi, data)| (*esi, data.as_slice()))
                            .collect();

                        // Use the pre-generated challenge_id to seed the chain hash.
                        // Invariant: challenge_ids_clone is built from the same holder_data
                        // iterated here, so the key is always present. Falling back to a
                        // constant seed would silently bind chain_hash to a known value —
                        // expect() surfaces any future invariant violation immediately.
                        let cid = *challenge_ids_clone
                            .get(holder_id)
                            .expect("challenge_id always present: built from same holder_data");
                        match viaticum_core::pos::compute_chain_hash(&cid, &refs) {
                            Ok(hash) => results.push((*holder_id, hash, esi_ranges.clone())),
                            Err(e) => {
                                tracing::error!(
                                    holder = %holder_id,
                                    block_id = %block_id_clone,
                                    "scheduler: chain hash failed: {e}"
                                );
                            }
                        }
                    }
                    results
                },
            )
            .await;

            // CS-POS-8: a JoinError here means the blocking task panicked (e.g. the
            // `expect` inside it). `unwrap_or_default()` would silently swallow that and
            // skip the whole block with zero logs. Log it loudly and degrade gracefully —
            // treat it as "no hashes for this block this tick" rather than re-panicking the
            // scheduler task.
            let hash_results = match hash_results {
                Ok(results) => results,
                Err(join_err) => {
                    error!(
                        block_id = %block_id,
                        err = %join_err,
                        "scheduler: PoS hash compute task failed (panicked or cancelled) — skipping block this tick"
                    );
                    continue;
                }
            };

            // Publish a challenge for each holder we computed a hash for via mailbox (T-6).
            for (holder_id, expected_hash, esi_ranges) in hash_results {
                let challenge_id = challenge_ids[&holder_id];
                let holder_master = self
                    .db
                    .get_master_for_device(&holder_id)
                    .ok()
                    .flatten()
                    .map(|m| IdentityPub(m.0))
                    .unwrap_or_else(|| IdentityPub(holder_id.0));

                // CS-ID-5 / P1-2: sign the challenge with our master key so the holder can
                // authenticate it against MailboxEntry.sender before doing any disk work.
                let challenge_msg = viaticum_core::messages::build_pos_hash_challenge(
                    challenge_id,
                    block_id,
                    esi_ranges.clone(),
                    now,
                    Some(holder_id),
                    &self.signing_key,
                );

                let payload = match to_cbor(&challenge_msg) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(
                            block_id = %block_id,
                            holder_id = %holder_id,
                            err = %e,
                            "scheduler: failed to encode PosHashChallenge"
                        );
                        continue;
                    }
                };

                let ttl_secs = viaticum_core::mailbox::scaled_ttl_secs(
                    viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL.as_secs(),
                    self.config.time_scale,
                );
                let expires_at = now.0 + ttl_secs;
                let entry = MailboxEntry {
                    target: MailboxAddress::for_master(&holder_master),
                    msg_id: challenge_id,
                    class: MailboxClass::PosChallenge,
                    payload_version: 1,
                    payload,
                    expires_at,
                    stored_at: now.0,
                    // W-3: sender is our master_pub so holder knows where to publish the response.
                    sender: Some(self.my_master_pub),
                };

                // W-3: publish via mailbox and gate pending-challenge creation on ≥1 Ack.
                // If 0 acks returned, the challenge is treated as unsent — retry on next tick.
                // MAILBOX_STORE_TIMEOUT_SECS is the per-peer request timeout (enforced in routing.rs).
                match self.mailbox_router.publish(entry, None).await {
                    Ok(0) => {
                        warn!(
                            block_id = %block_id,
                            holder_id = %holder_id,
                            "scheduler: PoS challenge: 0 acks — treating as unsent, will retry next tick"
                        );
                        tick.zero_ack += 1;
                        // Do NOT insert into pending — no confirmed delivery.
                        continue;
                    }
                    Ok(ack_count) => {
                        debug!(
                            block_id = %block_id,
                            holder_id = %holder_id,
                            ack_count,
                            "scheduler: PoS challenge published via mailbox"
                        );
                    }
                    Err(e) => {
                        warn!(
                            block_id = %block_id,
                            holder_id = %holder_id,
                            err = %e,
                            "scheduler: PoS challenge publish error — will retry next tick"
                        );
                        tick.zero_ack += 1;
                        continue;
                    }
                }

                // Insert into pending ONLY after confirmed ack (W-3 requirement).
                // CS-POS-3: capture the holder_master we resolved above so the response
                // is later verified against the SAME key the challenge was addressed to —
                // not a re-resolve that may have degraded to device-pub by then.
                self.pending.lock().await.insert(
                    (block_id, holder_id),
                    PendingHashChallenge {
                        source_block_id: block_id,
                        holder_id,
                        esi_ranges,
                        expected_chain_hash: expected_hash,
                        issued_at: now,
                        challenge_id,
                        holder_master,
                    },
                );

                tick.issued += 1;
                info!(
                    block_id = %block_id,
                    holder_id = %holder_id,
                    challenge_id = %hex_encode(&challenge_id),
                    cpw = cpw_of.get(&holder_id).copied().unwrap_or(0),
                    "scheduler: PoS hash challenge issued via mailbox"
                );
            }
        }

        // pos-i7 observable: one line per tick with due challenges.
        info!(
            due = tick.due,
            issued = tick.issued,
            skipped_pending = tick.skipped_pending,
            zero_ack = tick.zero_ack,
            elapsed_ms = started.elapsed().as_millis() as u64,
            cpw_min = tick.cpw_min,
            cpw_max = tick.cpw_max,
            "scheduler: PoS issue tick"
        );

        Ok(())
    }

    /// Trust of one holder for its challenge rate: the two-level trust (device and
    /// master) when there is any, else the legacy combined score; times its clamped
    /// `trust_s`. An unknown peer gets medium trust (0.5). Three redb reads.
    fn holder_trust(&self, holder: &DeviceId) -> f64 {
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
    }

    /// Load source block data for PoS challenge computation.
    ///
    /// Resolution order (2-tier, post-Wave-11b):
    ///   1. SystemState retained blob (`<data_dir>/system_state/<hex>.bin`) — SS blocks
    ///      have no backing watch-dir file; the owner retains the blob for PoS re-encode.
    ///      Corruption is propagated loudly; absence falls through.
    ///   2. Rebuild from the owner's source files via compress_and_encrypt (same path as
    ///      `Processor::rebuild_blob_for_pos`).
    ///
    /// PL-6: the old on-disk `{source_blocks_dir}/{block_hex}/block.bin` middle tier was
    /// removed. Wave 11b never writes `block.bin` (the symbol pipeline persists nothing
    /// to disk), so that `tokio::fs::read` was always NotFound and always fell through to
    /// the rebuild path below — a dead tier.
    async fn load_source_block_data(&self, block_id: &SourceBlockId) -> anyhow::Result<Vec<u8>> {
        // SystemState blocks: serve the owner-retained blob (verified blake3 == block_id).
        if let Some(blob) =
            crate::daemon::system_state::block::try_load_retained_block(&self.data_dir, block_id)?
        {
            return Ok(blob);
        }

        let block_record = self
            .db
            .get_source_block(block_id)?
            .ok_or_else(|| anyhow::anyhow!("source block record missing: {block_id}"))?;
        let db = self.db.clone();
        let epoch_key = self.epoch_key;
        let expected_id = *block_id;

        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            let plaintext =
                crate::daemon::backup::packing::rebuild_plaintext_from_db(&db, &block_record)?;
            let blob =
                crate::daemon::backup::pipeline::compress_and_encrypt(&plaintext, &epoch_key)?;
            let rebuilt_id: [u8; 32] = *blake3::hash(&blob).as_bytes();
            if rebuilt_id != expected_id.0 {
                anyhow::bail!("rebuilt blob hash mismatch for {expected_id}");
            }
            Ok(blob)
        })
        .await?
    }

    /// Check all pending challenges for timeout.
    ///
    /// A challenge is considered timed out when:
    ///   `now.0 - issued_at.0 >= POS_CHALLENGE_PENDING_TIMEOUT_SECS / time_scale`
    ///
    /// For each timed-out challenge:
    ///   1. Look up the current placement from DB.
    ///   2. Apply Timeout outcome → get PlacementTransition.
    ///   3. Persist updated placement status/misses to DB.
    ///   4. If transition.trigger_repair: send RepairTrigger::Wake to repair_tx.
    ///   5. Remove from pending_challenges.
    pub async fn check_timeouts(&self) -> anyhow::Result<()> {
        let now = Timestamp::now();
        let scale = self.config.time_scale.max(1);
        // T-6: use POS_CHALLENGE_PENDING_TIMEOUT_SECS (≈14d 2h) instead of POS_TIMEOUT_SECS (7d).
        // The extended window accounts for: challenge_TTL (7d) + response_TTL (7d) + 2×poll_interval (2h).
        // A holder offline for up to challenge_TTL can still respond; the response lives in mailbox
        // for response_TTL; the owner needs up to 2 poll intervals to collect it.
        // CS-POS-11: floor at 1s so an extreme time_scale (> ~1.2M) cannot collapse the
        // threshold to 0 — which would time out every fresh challenge instantly. Mirrors the
        // established `(x / time_scale.max(1)).max(1)` cadence pattern used elsewhere.
        let threshold = (POS_CHALLENGE_PENDING_TIMEOUT_SECS / scale).max(1);

        // Collect timed-out entries without holding the lock during DB calls.
        let timed_out: Vec<PendingHashChallenge> = {
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

        info!(
            count = timed_out.len(),
            "scheduler: processing timed-out challenges"
        );

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

            let stale = !placement.status.may_hold_symbols();
            let transition = apply_pos_outcome(&placement, &VerifyOutcome::Timeout);

            // A timeout on a placement that holds no symbols is stale (pos-i3): nothing
            // to persist, and writing the record back would clobber a concurrent rewrite.
            if !stale {
                // Persist updated status. У-4: the timeout that reaches PresumedLost is a
                // PRESUMED drop for the pair ledger (recorded in the same transaction); the
                // evidence time is when we issued the challenge.
                let mut updated = placement.clone();
                updated.status = transition.new_status;
                updated.consecutive_misses = transition.new_consecutive_misses;

                if let Err(e) = crate::daemon::processor::persist_placement_change(
                    &self.db,
                    &placement,
                    &updated,
                    Some(LossCause::PosTimeout),
                    challenge.issued_at,
                    None,
                ) {
                    error!(
                        block_id = %block_id,
                        holder_id = %holder_id,
                        "scheduler: DB error updating placement after timeout: {e}"
                    );
                    // Don't remove from pending if we couldn't persist — retry next cycle.
                    continue;
                }

                // Recompute cached fields after successful placement update (best-effort).
                crate::daemon::processor::recompute_and_persist_block_cached_fields(
                    &self.db, &block_id,
                );
            }

            // Record timeout as a challenged-but-not-passed event for trust — unless the
            // verdict is stale (pos-i4): the episode is closed, a miss was already
            // accounted by the drop that closed it.
            if !stale {
                let week = crate::daemon::processor::current_week_number_scaled(scale);
                let pos_outcome = outcome_from_verify(&VerifyOutcome::Timeout, week);
                crate::daemon::processor::record_pos_weekly(&self.db, holder_id, pos_outcome);
                recalculate_trust(&self.db, &holder_id, week);
            }

            info!(
                block_id = %block_id,
                holder_id = %holder_id,
                new_status = ?transition.new_status,
                misses = transition.new_consecutive_misses,
                trigger_repair = transition.trigger_repair,
                stale,
                challenge_id = %hex_encode(&challenge.challenge_id),
                "scheduler: PoS challenge timed out"
            );

            // Trigger repair if the transition requires it.
            if transition.trigger_repair {
                let _ = self.repair_tx.send(RepairTrigger::Wake).await;
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

        let actions =
            engine.process_cooldowns(&files, &blocks, &placements, now, self.config.time_scale);
        if actions.is_empty() {
            return Ok(());
        }

        info!(
            count = actions.len(),
            "scheduler: processing deletion actions"
        );

        for action in actions {
            match action {
                DeletionAction::SendDropNotice {
                    source_block_id,
                    holder_id,
                } => {
                    // H3 fix: dedup is PER (block, holder), enforced upstream by the
                    // deletion engine (it only emits SendDropNotice for a placement whose
                    // status != Deleting). There is NO per-BLOCK skip gate here — a block
                    // is erasure-coded across many holders, and the old
                    // `source_block.drop_notice_sent_at.is_some()` gate skipped holders
                    // 2..n forever once the first holder's publish set it, leaving their
                    // data un-deleted and the block stuck in Deleting. Each action that
                    // reaches this arm corresponds to a holder that still needs the notice.

                    // Build signed DeleteMsg and publish via mailbox bus (T-13b-1).
                    let delete_msg = viaticum_core::messages::build_delete_msg(
                        source_block_id,
                        now,
                        &self.signing_key,
                    );
                    let holder_master = self
                        .db
                        .get_master_for_device(&holder_id)
                        .ok()
                        .flatten()
                        .unwrap_or(IdentityPub(holder_id.0));
                    let delete_payload = DeleteRequestPayload::Delete(delete_msg);
                    // Publish FIRST, then gate the per-holder state-change txn on delivery
                    // success. mailbox publish is REMOTE (unlike the relay-era guaranteed
                    // local board store) and can genuinely yield 0 acks / Err — in that
                    // case we must NOT transition THIS holder's placement to Deleting, so
                    // the engine re-emits SendDropNotice for it on the next tick (per-holder
                    // retry). The other holders are unaffected — each is its own action.
                    let mut publish_ok = false;
                    if let Ok(payload_bytes) = to_cbor(&delete_payload) {
                        // Stable msg_id derived from (block, holder_master, domain) so
                        // re-publishes of the same Delete dedup as `Duplicate` at candidate
                        // postmen that still hold the entry (instead of piling up a fresh
                        // random entry every tick for the full 14d TTL). A fresh holder still
                        // receives it once; the holder's apply keys idempotency on
                        // (block_id, owner) + the Active→MarkedForDelete status-guard, not on
                        // msg_id, so a stable id does not change holder-side behaviour.
                        let msg_id = stable_delete_msg_id(&source_block_id, &holder_master);
                        let ttl_secs = viaticum_core::mailbox::scaled_ttl_secs(
                            viaticum_core::mailbox::class_config::DELETE_REQUEST_TTL.as_secs(),
                            self.config.time_scale,
                        );
                        let entry = MailboxEntry {
                            target: MailboxAddress::for_master(&holder_master),
                            msg_id,
                            class: MailboxClass::DeleteRequest,
                            payload_version: 1,
                            payload: payload_bytes,
                            expires_at: now.0 + ttl_secs,
                            stored_at: now.0,
                            // sender = owner master so holder knows who owns the block
                            sender: Some(self.my_master_pub),
                        };
                        match self.mailbox_router.publish(entry, None).await {
                            Ok(0) => warn!(
                                block_id = %source_block_id,
                                holder = %holder_master,
                                "scheduler: DeleteMsg publish got 0 acks — deletion not sent, will retry next tick"
                            ),
                            Ok(ack_count) => {
                                publish_ok = true;
                                debug!(
                                    block_id = %source_block_id,
                                    holder = %holder_master,
                                    ack_count,
                                    "scheduler: DeleteMsg published via mailbox"
                                );
                            }
                            Err(e) => warn!(
                                block_id = %source_block_id,
                                holder = %holder_master,
                                err = %e,
                                "scheduler: DeleteMsg mailbox publish failed — deletion not sent, will retry next tick"
                            ),
                        }
                    } else {
                        error!(
                            block_id = %source_block_id,
                            "deletion: failed to encode DeleteMsg payload — will retry next tick"
                        );
                    }

                    // Only advance state if the DeleteMsg was actually delivered (≥1 ack).
                    // On 0 acks / Err / encode failure leave this holder's placement
                    // untouched so the next tick re-attempts it (no Deleting transition).
                    if !publish_ok {
                        continue;
                    }

                    // Transition THIS holder's placement → Deleting; promote the source
                    // block Active/Stale → Deleting (so the engine's Deleting-branch keeps
                    // emitting SendDropNotice for the remaining non-Deleting placements).
                    //
                    // CS-DEL-6 (N13): both reads happen AFTER the awaited publish, so the
                    // txn below rewrites a fresh copy. Reading source_block before the
                    // publish would let a concurrent writer (e.g. current_alive recompute)
                    // during the publish RTT be clobbered by this stale-then-rewritten copy.
                    let placement = self
                        .db
                        .get_placement(&source_block_id, &holder_id)
                        .ok()
                        .flatten();
                    let source_block = self.db.get_source_block(&source_block_id).ok().flatten();

                    let mut committed = false;
                    if placement.is_some() || source_block.is_some() {
                        match self.db.write_txn() {
                            Err(e) => {
                                error!(block_id = %source_block_id, "deletion: failed to open write txn: {e}")
                            }
                            Ok(mut txn) => {
                                let mut txn_ok = true;
                                if let Some(mut p) = placement {
                                    p.status = PlacementStatus::Deleting;
                                    if let Err(e) = txn.upsert_placement(&p) {
                                        error!(block_id = %source_block_id, holder_id = %holder_id, "deletion: failed to update placement: {e}");
                                        txn_ok = false;
                                    }
                                }
                                if txn_ok && let Some(mut sb) = source_block {
                                    // Promote the block to Deleting only — drop_notice_sent_at
                                    // is intentionally NOT written: it was a per-block dedup
                                    // gate (now removed) and has no other consumer for
                                    // SourceBlockRecord, so it is left dead. Holder-cooldown
                                    // timing derives from all_devices_deleted_at + cooldown in
                                    // the engine, not from this field.
                                    if sb.status == SourceBlockStatus::Active
                                        || sb.status == SourceBlockStatus::Stale
                                    {
                                        sb.status = SourceBlockStatus::Deleting;
                                    }
                                    if let Err(e) = txn.upsert_source_block(&sb) {
                                        error!(block_id = %source_block_id, "deletion: failed to update source block: {e}");
                                        txn_ok = false;
                                    }
                                }
                                if txn_ok {
                                    match txn.commit() {
                                        Ok(()) => committed = true,
                                        Err(e) => {
                                            error!(block_id = %source_block_id, "deletion: failed to commit txn: {e}")
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // NOTE-twin fix: only log the transition once the txn actually
                    // committed — otherwise the log claims a Deleting transition that was
                    // never persisted.
                    if committed {
                        info!(
                            block_id = %source_block_id,
                            holder_id = %holder_id,
                            "scheduler: sent DeleteMsg via mailbox, placement → Deleting"
                        );
                    }
                }
                DeletionAction::CleanupPlacement {
                    source_block_id,
                    holder_id,
                } => {
                    if let Err(e) = self.db.delete_placement(&source_block_id, &holder_id) {
                        error!(block_id = %source_block_id, holder_id = %holder_id, "deletion: failed to delete placement: {e}");
                    }
                    info!(
                        block_id = %source_block_id,
                        holder_id = %holder_id,
                        "scheduler: cleaned up placement"
                    );
                }
                DeletionAction::CleanupBlock {
                    source_block_id,
                    file_id,
                } => {
                    // Read the file record before opening the transaction (read-then-write pattern).
                    let file_opt =
                        self.db
                            .get_file_by_id(file_id)
                            .ok()
                            .flatten()
                            .map(|mut file| {
                                file.versions
                                    .retain(|v| v.source_block_id != source_block_id);
                                file
                            });
                    // Delete source block + update file record atomically.
                    match self.db.write_txn() {
                        Err(e) => {
                            error!(block_id = %source_block_id, "deletion: failed to open write txn: {e}")
                        }
                        Ok(mut txn) => {
                            let mut txn_ok = true;
                            if let Err(e) = txn.delete_source_block(&source_block_id) {
                                error!(block_id = %source_block_id, "deletion: failed to delete source block: {e}");
                                txn_ok = false;
                            }
                            if txn_ok
                                && let Some(file) = file_opt
                                && let Err(e) = txn.upsert_file(&file)
                            {
                                error!(file_id = %file_id, "deletion: failed to update file after block cleanup: {e}");
                                txn_ok = false;
                            }
                            if txn_ok && let Err(e) = txn.commit() {
                                error!(block_id = %source_block_id, "deletion: failed to commit cleanup txn: {e}");
                            }
                        }
                    }
                    // PL-6: there are NO owner-side symbol files to remove. Wave 11b
                    // never writes `{source_blocks_dir}/{block_hex}/*` — the symbol
                    // pipeline persists nothing to disk and re-encodes from source on
                    // demand — so that directory is never created. The earlier disk
                    // cleanup here (review B2 / Flow 7) guarded a never-existing path and
                    // was a dead no-op; it has been removed. The DB record + file version
                    // are the only owner-side state, cleaned up in the txn above.
                    info!(
                        block_id = %source_block_id,
                        file_id = %file_id,
                        "scheduler: cleaned up source block + file version"
                    );
                }
                DeletionAction::VacuumBlock {
                    source_block_id, ..
                } => {
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

    /// Sweep Offered placements that have exceeded the long-absence threshold.
    ///
    /// For each stale Offered placement:
    ///   1. Transition status to Lost via upsert_placement.
    ///   2. Send RepairTrigger::Wake (worker rescans + re-encodes below-target blocks).
    ///
    /// Called on the sweep_timer tick (same interval as accepted_offers pruning).
    ///
    /// Threshold: LONG_ABSENCE_SECS (14 days). Offered placements that receive a
    /// real signal (PoS Fail/NotHeld, explicit Reject) transition independently.
    /// This sweep is a safety net for peers that silently disappear for >14 days.
    pub async fn sweep_offered_placements(&self) -> anyhow::Result<()> {
        let now = Timestamp::now();
        // CS-SCH-4: scale the long-absence threshold by time_scale so accelerated
        // E2E runs actually reach it — mirrors the `check_timeouts` cadence pattern.
        // Floor at 1s so an extreme time_scale cannot collapse the threshold to 0
        // (which would sweep every fresh Offered placement instantly). At the
        // production scale of 1 this is byte-for-byte LONG_ABSENCE_SECS.
        let scale = self.config.time_scale.max(1);
        let threshold = (LONG_ABSENCE_SECS / scale).max(1);

        let placements = self.db.list_all_placements()?;
        for p in &placements {
            if p.status != PlacementStatus::Offered {
                continue;
            }
            let age = now.0.saturating_sub(p.placed_at.0);
            if age < threshold {
                continue;
            }
            // Long absence: 14 days without any real signal.
            let mut updated = p.clone();
            updated.status = PlacementStatus::Lost;
            self.db.upsert_placement(&updated)?;

            // W11a hook: every placement-status transition must recompute the
            // block's current_alive/current_reliability cached fields so the
            // worker sees the block as needing work without waiting for the
            // hourly reliability_scan. (Cross-wave review B2 fix.)
            crate::daemon::processor::recompute_and_persist_block_cached_fields(
                &self.db,
                &p.source_block_id,
            );

            info!(
                block_id = %p.source_block_id,
                holder = %p.holder_id,
                age_days = age / 86_400,
                "scheduler: Offered placement absent > 14 days → Lost"
            );

            let _ = self.repair_tx.send(RepairTrigger::Wake).await;
        }
        Ok(())
    }

    /// One 4R pair-ledger accrual tick (У-2, spec `beta-planning/tasks/pair_ledger.md`).
    ///
    /// Pure bookkeeping: it advances the per-master `G`/`D` leaky integrals from the storage
    /// counters this node already keeps, and writes them back. **Nothing reads the result** —
    /// no placement, eviction, offer-admission or PoS-cadence decision changes because of it
    /// (AC-7). The layer ships ahead of the 4R decisions only because an integral over months
    /// cannot be back-computed once the network is live.
    ///
    /// Why here and not inside `Db::refresh_peer_storage_bytes` (spec Д1): the accrual needs
    /// `time_scale` and a wall clock, while that function has eight non-test call sites across
    /// five modules (`holdings_integrity`, `backup`, `processor::symbol` ×2, this one, and
    /// `holder_cleanup` ×3), several of them free functions holding only a `Db`. It is also a
    /// different kind of thing — that one recomputes a SNAPSHOT, this one integrates the
    /// interval between snapshots.
    ///
    /// Synchronous (no await points) and O(one pass per table), because it runs inside the
    /// `select!` loop; `now` is a parameter so tests can drive the clock.
    ///
    /// Signature kept from У-2; delegates to [`Scheduler::accrue_pair_ledgers_report`], so
    /// the tests and the run loop go through one path.
    pub fn accrue_pair_ledgers(&self, now: Timestamp) -> Result<AccrualStats, PairLedgerError> {
        self.accrue_pair_ledgers_report(now).map(|r| r.stats)
    }

    /// [`Scheduler::accrue_pair_ledgers`] plus the rows the tick wrote (У-3), for the
    /// per-row `pair-ledger row` log line. The run loop is the ONLY reader of the report's
    /// rows (AC-7): nothing branches on them.
    pub fn accrue_pair_ledgers_report(
        &self,
        now: Timestamp,
    ) -> Result<TickReport, PairLedgerError> {
        PairLedgerRecorder::new(self.db.clone()).tick_report(
            &self.my_master_pub,
            now,
            self.config.time_scale,
        )
    }
}

/// Real-time period of a scheduler timer built from a base period in seconds:
/// `(base / scale).max(1)` — integer division with a one-second floor, `scale = 0` read as 1.
/// Shared with the tests that rebuild the PoS cycle (AC-9), so they cannot drift from the
/// timer they check.
pub(crate) fn scaled_timer_secs(base_secs: u64, time_scale: u64) -> u64 {
    (base_secs / time_scale.max(1)).max(1)
}

/// One debug line per ACCRUED pair-ledger row (У-3, Part 0) under the fixed target
/// `viaticum::ledger`; enable with `RUST_LOG=info,viaticum::ledger=debug`. At `info` it is
/// silent. Output of the writer, not a reader: nothing branches on it (AC-7).
///
/// CONTRACT with `experiments/local_ledger_test.sh` and
/// `experiments/local_ledger_drop_test.sh`: the message `pair-ledger row`, the target and the
/// field names (`master dt_days believed_gb confirmed_gb v_dem g_they depth observed_volume
/// observed_tau drop_ann drop_silent drop_presumed ann_events silent_events presumed_events`)
/// are parsed by those scenarios. Renaming any of them must break the scenarios — that is
/// intended. `*_events` are the drop events folded into the row on this tick (У-4); the drop
/// counters are after decay + fold. `f64` fields go through `Debug` (shortest round-trip
/// form), so equal values print identical text; `master` is `IdentityPub`'s Display, the
/// first 8 bytes in hex.
fn log_ledger_rows(report: &TickReport) {
    for row in &report.rows {
        debug!(
            target: "viaticum::ledger",
            master = %row.master,
            dt_days = ?row.dt_days,
            believed_gb = ?row.believed_gb,
            confirmed_gb = ?row.confirmed_gb,
            v_dem = ?row.v_dem,
            g_they = ?row.g_they,
            depth = ?row.depth,
            observed_volume = ?row.observed_volume,
            observed_tau = ?row.observed_tau,
            drop_ann = ?row.drop_ann,
            drop_silent = ?row.drop_silent,
            drop_presumed = ?row.drop_presumed,
            ann_events = row.ann_events,
            silent_events = row.silent_events,
            presumed_events = row.presumed_events,
            "pair-ledger row"
        );
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Counters of one PoS issue tick, printed by `scheduler: PoS issue tick` (pos-i7).
#[derive(Debug, Default)]
struct IssueTick {
    /// Placements due this tick (`due_challenges`).
    due: usize,
    /// Challenges published with ≥ 1 ack and put in pending.
    issued: usize,
    /// Due placements skipped because a challenge is already pending for them.
    skipped_pending: usize,
    /// Challenge publishes with 0 acks or an error (retried next tick).
    zero_ack: usize,
    cpw_min: u32,
    cpw_max: u32,
}

/// Trust of every distinct holder of `placements`, `f` called once per holder (pos-i7:
/// the trust lookup is three redb reads; once per placement it was ~27 000 reads a tick
/// at 9 000 placements).
pub(crate) fn holder_trust_map<F: Fn(&DeviceId) -> f64>(
    placements: &[SymbolPlacement],
    f: F,
) -> HashMap<DeviceId, f64> {
    let mut trust: HashMap<DeviceId, f64> = HashMap::new();
    for p in placements {
        trust.entry(p.holder_id).or_insert_with(|| f(&p.holder_id));
    }
    trust
}

fn random_challenge_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
    id
}

/// Deterministic 16-byte mailbox msg_id for a Delete addressed to `holder_master`
/// for `block`. Stable across re-publishes so that retries (the per-holder retry
/// after a 0-ack tick, or the engine re-emitting until the holder acks) dedup as
/// `Duplicate` at candidate postmen that already hold the entry, rather than piling
/// up a fresh random entry every tick for the full DELETE_REQUEST_TTL (14d).
///
/// Derived from SHA256(block_id || holder_master || domain), truncated to 16 bytes.
/// The holder's apply is idempotent on (block_id, owner) + status-guard, not on
/// msg_id, so a stable id does not change holder-side behaviour.
///
/// LOAD-BEARING dependency: the stored-but-ack-lost retry relies on the postman
/// returning **Ack** on a duplicate store (`processor/mailbox::handle_mailbox_store`),
/// since `MailboxRouter::publish` counts only Acks. If that ever becomes
/// `Reject{Duplicate}`, this retry path would starve until TTL/sweep.
fn stable_delete_msg_id(block: &SourceBlockId, holder_master: &IdentityPub) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(block.0);
    hasher.update(holder_master.0);
    hasher.update(b"viaticum-mailbox-delete-v1");
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}
