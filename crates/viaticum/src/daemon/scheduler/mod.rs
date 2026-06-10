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

use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use viaticum_core::constants::{
    LONG_ABSENCE_SECS, POS_CHALLENGE_PENDING_TIMEOUT_SECS, S_CLAMP_MAX, S_CLAMP_MIN,
};
use viaticum_core::db::Db;
use viaticum_core::deletion::{DeletionAction, DeletionEngine};
use viaticum_core::mailbox::{DeleteRequestPayload, MailboxClass, MailboxEntry};
use viaticum_core::messages::{PosHashResponseMsg, to_cbor};
use viaticum_core::pos::{VerifyOutcome, apply_pos_outcome, due_challenges, outcome_from_verify};
use viaticum_core::trust::{compute_combined, compute_effective_trust, recalculate_trust};
use viaticum_core::types::{
    DeviceId, IdentityPub, PlacementStatus, SourceBlockId, SourceBlockStatus, Timestamp,
};

use crate::daemon::mailbox::routing::MailboxRouter;
use crate::daemon::repair::RepairTrigger;

#[cfg(test)]
mod tests;

// ─── PendingHashChallenge ─────────────────────────────────────────────────────

/// Re-exported from viaticum-core for use in tests and wiring.
pub use viaticum_core::pos::PendingHashChallenge;

/// Shared map of in-flight PoS hash challenges keyed by (source_block_id, holder_id).
/// One pending challenge per (block, holder) pair at a time.
///
/// Shared between Scheduler (writes) and Processor (reads when verifying PosHashResponse).
///
/// NOTE: Uses tokio::sync::Mutex (not std::sync::Mutex) because locks are held
/// across .await points in issue_due_challenges / check_timeouts.
pub type PendingChallenges = Arc<Mutex<HashMap<(SourceBlockId, DeviceId), PendingHashChallenge>>>;

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
    /// Shared with Processor for response matching.
    pending: PendingChallenges,
    /// Mailbox router for publishing PoS challenges via the mailbox bus (T-6).
    /// Replaces the relay path for PosHashChallengeMsg.
    mailbox_router: Arc<MailboxRouter>,
    /// This node's master identity public key (sent as MailboxEntry.sender so holder
    /// knows where to publish the response).
    my_master_pub: IdentityPub,
    /// Signing key for building DeleteMsg signatures.
    signing_key: ed25519_dalek::SigningKey,
    /// Directory containing owner-side source block files (`{block_id_hex}/*.bin`).
    /// Used by CleanupBlock to remove leftover symbol files from disk.
    source_blocks_dir: std::path::PathBuf,
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
        source_blocks_dir: std::path::PathBuf,
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
            source_blocks_dir,
            accepted_offers,
            encoder,
            epoch_key,
            data_dir,
        }
    }

    /// Main run loop. Fires on two independent timers:
    ///   - pos_timer: call issue_due_challenges()
    ///   - timeout_timer: call check_timeouts()
    ///
    /// Both intervals are divided by time_scale before use.
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
        let pos_interval = Duration::from_secs((self.config.pos_interval_secs / scale).max(1));
        let timeout_interval = Duration::from_secs((self.config.timeout_check_secs / scale).max(1));
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
        // Find pending challenge by challenge_id (linear scan, bounded by active placements).
        let pending_key = {
            let guard = self.pending.lock().await;
            guard
                .iter()
                .find(|(_, v)| v.challenge_id == response.challenge_id)
                .map(|(k, _)| *k)
        };

        let key = match pending_key {
            Some(k) => k,
            None => {
                warn!(
                    "scheduler: PosHashResponse from mailbox with unknown challenge_id (stale or duplicate)"
                );
                return Ok(());
            }
        };

        // Consume the entry — challenge lifecycle ends here.
        let pending = {
            let mut guard = self.pending.lock().await;
            guard.remove(&key)
        };
        let pending = match pending {
            Some(p) => p,
            None => return Ok(()),
        };

        let block_id = key.0;
        let holder_id = key.1;
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
        let transition = viaticum_core::pos::apply_pos_outcome(&placement, &outcome);
        let mut updated = placement;
        updated.status = transition.new_status;
        updated.consecutive_misses = transition.new_consecutive_misses;
        if matches!(outcome, viaticum_core::pos::VerifyOutcome::Pass) {
            updated.last_verified = Some(Timestamp::now());
        }
        self.db.upsert_placement(&updated)?;

        if updated.status != old_status {
            crate::daemon::processor::recompute_and_persist_block_cached_fields(
                &self.db, &block_id,
            );
        }

        if let Err(e) = self.db.refresh_peer_storage_bytes(&holder_id) {
            error!(peer = %holder_id, err = %e,
                "scheduler: failed to refresh storage bytes after mailbox PosResponse");
        }

        let scale = self.config.time_scale.max(1);
        let week = crate::daemon::processor::current_week_number_scaled(scale);
        let pos_outcome = outcome_from_verify(&outcome, week);
        crate::daemon::processor::record_pos_weekly(&self.db, holder_id, pos_outcome);
        if let Some((old_p, old_i, new_p, new_i)) =
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

        info!(
            block_id = %block_id,
            holder = %holder_id,
            outcome = ?outcome,
            "scheduler: mailbox PosResponse resolved"
        );

        if transition.trigger_repair {
            let _ = self
                .repair_tx
                .send(crate::daemon::repair::RepairTrigger::RepairNow {
                    block_id,
                    holder_id,
                })
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
    pub async fn issue_due_challenges(&self) -> anyhow::Result<()> {
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
                std::collections::HashSet::new()
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

        let due = due_challenges(
            &challengeable,
            &last_verified,
            now,
            trust_fn,
            self.config.time_scale,
        );

        if due.is_empty() {
            debug!("scheduler: no challenges due at this interval");
            return Ok(());
        }

        // Snapshot pending keys once to avoid repeatedly locking inside the loop.
        let already_pending: Vec<(SourceBlockId, DeviceId)> = {
            let guard = self.pending.lock().await;
            guard.keys().copied().collect()
        };

        info!(due = due.len(), "scheduler: issuing PoS hash challenges");

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
            let block_entries: Vec<_> = block_entries
                .into_iter()
                .filter(|e| !already_pending.contains(&(e.source_block_id, e.holder_id)))
                .collect();
            if block_entries.is_empty() {
                continue;
            }

            // Find corresponding SymbolPlacements.
            let holder_placements: Vec<_> = block_entries
                .iter()
                .filter_map(|e| {
                    challengeable.iter().find(|p| {
                        p.source_block_id == e.source_block_id && p.holder_id == e.holder_id
                    })
                })
                .collect();

            if holder_placements.is_empty() {
                continue;
            }

            // Load source block data (from block.bin or rebuild).
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
            .await
            .unwrap_or_default();

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

                let challenge_msg = viaticum_core::messages::PosHashChallengeMsg {
                    v: 1,
                    challenge_id,
                    source_block_id: block_id,
                    esi_ranges: esi_ranges.clone(),
                    timestamp: now,
                    device_id: Some(holder_id),
                };

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

                let ttl_secs = viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL.as_secs();
                let expires_at = now.0 + ttl_secs;
                let entry = MailboxEntry {
                    target: holder_master,
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
                match self.mailbox_router.publish(&holder_master, entry).await {
                    Ok(0) => {
                        warn!(
                            block_id = %block_id,
                            holder_id = %holder_id,
                            "scheduler: PoS challenge: 0 acks — treating as unsent, will retry next tick"
                        );
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
                        continue;
                    }
                }

                // Insert into pending ONLY after confirmed ack (W-3 requirement).
                self.pending.lock().await.insert(
                    (block_id, holder_id),
                    PendingHashChallenge {
                        source_block_id: block_id,
                        holder_id,
                        esi_ranges,
                        expected_chain_hash: expected_hash,
                        issued_at: now,
                        challenge_id,
                    },
                );

                info!(
                    block_id = %block_id,
                    holder_id = %holder_id,
                    "scheduler: PoS hash challenge issued via mailbox"
                );
            }
        }

        Ok(())
    }

    /// Load source block data for PoS challenge computation.
    ///
    /// Resolution order:
    ///   1. SystemState retained blob (`<data_dir>/system_state/<hex>.bin`) — SS blocks
    ///      have no backing watch-dir file; the owner retains the blob for PoS re-encode.
    ///      Corruption is propagated loudly; absence falls through.
    ///   2. `block.bin` cache on disk.
    ///   3. Rebuild from source files via compress_and_encrypt (same path as
    ///      Processor::rebuild_blob_for_pos).
    async fn load_source_block_data(&self, block_id: &SourceBlockId) -> anyhow::Result<Vec<u8>> {
        // SystemState blocks: serve the owner-retained blob (verified blake3 == block_id).
        if let Some(blob) =
            crate::daemon::system_state::block::try_load_retained_block(&self.data_dir, block_id)?
        {
            return Ok(blob);
        }

        let block_hex = viaticum_core::types::hex_encode(&block_id.0);
        let block_path = self.source_blocks_dir.join(&block_hex).join("block.bin");

        match tokio::fs::read(&block_path).await {
            Ok(data) => return Ok(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Rebuild from source files.
            }
            Err(e) => return Err(e.into()),
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
        // T-6: use POS_CHALLENGE_PENDING_TIMEOUT_SECS (≈14d 2h) instead of POS_TIMEOUT_SECS (7d).
        // The extended window accounts for: challenge_TTL (7d) + response_TTL (7d) + 2×poll_interval (2h).
        // A holder offline for up to challenge_TTL can still respond; the response lives in mailbox
        // for response_TTL; the owner needs up to 2 poll intervals to collect it.
        let threshold = POS_CHALLENGE_PENDING_TIMEOUT_SECS / scale;

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

            // Recompute cached fields after successful placement update (best-effort).
            crate::daemon::processor::recompute_and_persist_block_cached_fields(
                &self.db, &block_id,
            );

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
                    .send(RepairTrigger::RepairNow {
                        block_id,
                        holder_id,
                    })
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
                    // Dedup: only send once per source block.
                    let source_block = self.db.get_source_block(&source_block_id).ok().flatten();
                    if source_block
                        .as_ref()
                        .and_then(|sb| sb.drop_notice_sent_at)
                        .is_some()
                    {
                        debug!(
                            block_id = %source_block_id,
                            holder_id = %holder_id,
                            "scheduler: drop notice already sent for this block, skipping"
                        );
                        continue;
                    }

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
                    // Publish FIRST, then gate the state-change txn on delivery success.
                    // mailbox publish is REMOTE (unlike the relay-era guaranteed local
                    // board store) and can genuinely yield 0 acks / Err — in that case
                    // we must NOT advance state (which would set drop_notice_sent_at and
                    // make the dedup gate above skip this block forever). Leave the block
                    // in its prior state so the deletion engine re-emits SendDropNotice on
                    // the next tick — natural retry.
                    let mut publish_ok = false;
                    if let Ok(payload_bytes) = to_cbor(&delete_payload) {
                        let mut msg_id = [0u8; 16];
                        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut msg_id);
                        let ttl_secs =
                            viaticum_core::mailbox::class_config::DELETE_REQUEST_TTL.as_secs();
                        let entry = MailboxEntry {
                            target: holder_master,
                            msg_id,
                            class: MailboxClass::DeleteRequest,
                            payload_version: 1,
                            payload: payload_bytes,
                            expires_at: now.0 + ttl_secs,
                            stored_at: now.0,
                            // sender = owner master so holder knows who owns the block
                            sender: Some(self.my_master_pub),
                        };
                        match self.mailbox_router.publish(&holder_master, entry).await {
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
                    // On 0 acks / Err / encode failure leave the block untouched so the
                    // next tick re-attempts (no drop_notice_sent_at, no Deleting transition).
                    if !publish_ok {
                        continue;
                    }

                    // Mark placement + source block Deleting, record drop_notice_sent_at atomically.
                    let placement = self
                        .db
                        .get_placement(&source_block_id, &holder_id)
                        .ok()
                        .flatten();

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
                                    sb.drop_notice_sent_at = Some(now);
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
                                if txn_ok && let Err(e) = txn.commit() {
                                    error!(block_id = %source_block_id, "deletion: failed to commit txn: {e}");
                                }
                            }
                        }
                    }

                    info!(
                        block_id = %source_block_id,
                        holder_id = %holder_id,
                        "scheduler: sent DeleteMsg via mailbox, placement → Deleting"
                    );
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
                    // Remove owner-side symbol files from disk (review B2 / Flow 7 BLOCK).
                    // Previously the DB record was cleaned up but `{source_blocks_dir}/{block_id}/*.bin`
                    // remained forever, leaking disk space.
                    let block_hex = viaticum_core::types::hex_encode(&source_block_id.0);
                    let block_dir = self.source_blocks_dir.join(&block_hex);
                    if block_dir.exists()
                        && let Err(e) = std::fs::remove_dir_all(&block_dir)
                    {
                        warn!(
                            block_id = %source_block_id,
                            path = %block_dir.display(),
                            err = %e,
                            "scheduler: failed to remove owner-side source block directory"
                        );
                    }
                    info!(
                        block_id = %source_block_id,
                        file_id = %file_id,
                        "scheduler: cleaned up source block + file version + disk files"
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
    ///   2. Send RepairTrigger::RepairNow { block_id, holder_id }.
    ///
    /// Called on the sweep_timer tick (same interval as accepted_offers pruning).
    ///
    /// Threshold: LONG_ABSENCE_SECS (14 days). Offered placements that receive a
    /// real signal (PoS Fail/NotHeld, explicit Reject) transition independently.
    /// This sweep is a safety net for peers that silently disappear for >14 days.
    pub async fn sweep_offered_placements(&self) -> anyhow::Result<()> {
        let now = Timestamp::now();
        let threshold = LONG_ABSENCE_SECS;

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
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
    id
}
