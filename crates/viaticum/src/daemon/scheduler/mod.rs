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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

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
use viaticum_core::pos::{VerifyOutcome, apply_pos_outcome, outcome_from_verify};
use viaticum_core::trust::{compute_combined, compute_effective_trust, recalculate_trust};
use viaticum_core::types::{
    DeviceId, IdentityPub, PlacementStatus, SourceBlockId, SourceBlockStatus, SymbolPlacement,
    Timestamp, hex_encode,
};

use crate::daemon::mailbox::routing::MailboxRouter;
use crate::daemon::repair::RepairTrigger;

mod issue;
// Public only for the allocation-peak test binary `tests/block_prep_alloc_peak.rs`.
#[doc(hidden)]
pub use issue::fold::{FoldHolder, hash_holders};
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
    /// `<data_dir>/system_state/`. Used by `issue::prepare::load_source_block` to serve PoS
    /// challenges for SS blocks (which have no backing watch-dir file).
    data_dir: std::path::PathBuf,
    /// When each placement's challenge was last tried (its block started by an issue
    /// tick), in RAM only (pos-i7-c): orders the due blocks with `last_verified`, so a block
    /// that cannot be served does not hold the head of every tick. Lost on restart — then
    /// the order falls back to `last_verified` alone for one round.
    last_attempted: std::sync::Mutex<HashMap<PendingKey, Timestamp>>,
    /// Whose records the PoS rebuild reads and where it reports gone paths (К2b).
    /// Default: any Present record, no recheck (tests); the daemon sets this device and
    /// the watcher's recheck channel.
    rebuild_scope: crate::daemon::backup::rebuild::RebuildScope,
    /// When the WARN "cannot load source block for PoS" was last written per block
    /// (backup-i7): once per `POS_LOAD_WARN_INTERVAL` per block, on the monotonic clock. A
    /// block whose source outgrew the size limit fails every tick; the log must not.
    /// Shared with the preparation task, which runs on the blocking pool.
    pos_load_warned: Arc<std::sync::Mutex<HashMap<SourceBlockId, std::time::Instant>>>,
    /// The block work memory budget (backup-i24): PoS preparations take their permits from it.
    /// The daemon sets the real one (`set_mem_budget`); the default is effectively unbounded.
    mem_budget: Arc<crate::daemon::mem_budget::MemBudget>,
    /// Number of the last issue tick (pos-i13): +1 at the start of every tick.
    issue_seq: std::sync::atomic::AtomicU64,
    /// The tick on which each block was first deferred by the memory budget (pos-i13, J11): from
    /// the next tick it waits for memory as an overdue preparation. In RAM only.
    mem_deferred_at: std::sync::Mutex<HashMap<SourceBlockId, u64>>,
    /// Until when a block whose last load failed stays out of the overdue queue (NOTE 7,
    /// backup-i7): such a block is tried only through `try_acquire`. Shared with the
    /// preparation task, which sets and clears it on the blocking pool.
    load_failed: Arc<std::sync::Mutex<HashMap<SourceBlockId, std::time::Instant>>>,
    /// The clock of the batch of overdue PoS checks (its work limit and hard stop, spec v3.7a):
    /// the real one, replaced in tests.
    batch_clock: BatchClock,
    /// Runs before a holder's master is looked up in a preparation (tests: no permit is held).
    #[cfg(test)]
    master_lookup_hook: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Runs at the start of a batch member's sources check (tests: a hung `metadata`).
    #[cfg(test)]
    precheck_hook: std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

/// A source of "now" for the batch of overdue PoS checks.
pub(crate) type BatchClock = Arc<dyn Fn() -> std::time::Instant + Send + Sync>;

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
            last_attempted: std::sync::Mutex::new(HashMap::new()),
            rebuild_scope: Default::default(),
            pos_load_warned: Arc::default(),
            mem_budget: crate::daemon::mem_budget::MemBudget::new(1 << 50),
            issue_seq: std::sync::atomic::AtomicU64::new(0),
            mem_deferred_at: std::sync::Mutex::new(HashMap::new()),
            load_failed: Arc::default(),
            batch_clock: Arc::new(std::time::Instant::now),
            #[cfg(test)]
            master_lookup_hook: std::sync::Mutex::new(None),
            #[cfg(test)]
            precheck_hook: std::sync::Mutex::new(None),
        }
    }

    /// Replace the clock of the batch of overdue PoS checks (tests).
    #[cfg(test)]
    pub(crate) fn set_batch_clock(&mut self, clock: BatchClock) {
        self.batch_clock = clock;
    }

    /// Set the block work memory budget the PoS preparations share with the worker and restore
    /// (backup-i24). Without it a preparation runs under a budget nobody else uses.
    pub fn set_mem_budget(&mut self, budget: Arc<crate::daemon::mem_budget::MemBudget>) {
        self.mem_budget = budget;
    }

    /// Set whose records the PoS rebuild reads and where gone paths go (К2b).
    pub fn set_rebuild_scope(&mut self, scope: crate::daemon::backup::rebuild::RebuildScope) {
        self.rebuild_scope = scope;
    }

    /// Main run loop. Fires on five independent timers:
    ///   - pos_timer: call issue_tick() (bounded by its time budget, pos-i7-a); its
    ///     challenge publishes end later and are settled by a `join_next` arm (pos-i7-c)
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

        // Challenge publishes started by issue ticks, settled here as they end.
        let mut in_flight = issue::InFlight::default();

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("scheduler: cancellation requested, shutting down");
                    break;
                }
                _ = pos_timer.tick() => {
                    if let Err(e) = self.issue_tick(&mut in_flight).await {
                        error!("scheduler: issue_tick error: {e}");
                    }
                }
                // A publish that ended, or a block preparation that outlived its tick.
                Some(ended) = in_flight.join_next_any(), if !in_flight.is_idle() => {
                    self.settle_ended(ended, &mut in_flight).await;
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

        // Abort the publishes in flight and stop waiting for the preparations; their
        // challenges never reached pending.
        in_flight.shutdown().await;

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
        // The owner's verdict, for the E2E (bigfile_limit 3c reads it): log only.
        debug!(
            block_id = %block_id,
            holder = %holder_id,
            outcome = %if matches!(outcome, viaticum_core::pos::VerifyOutcome::Pass) { "pass" } else { "fail" },
            "scheduler: PoS verdict"
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
