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

use syncback_core::constants::{OFFERED_PLACEMENT_TIMEOUT_SECS, POS_TIMEOUT_SECS, S_CLAMP_MAX, S_CLAMP_MIN};
use syncback_core::trust::{compute_combined, compute_effective_trust, recalculate_trust};
use syncback_core::db::Db;
use syncback_core::deletion::{DeletionAction, DeletionEngine};
use syncback_core::pos::{apply_pos_outcome, due_challenges, outcome_from_verify, VerifyOutcome};
use syncback_core::types::{DeviceId, IdentityPub, PlacementStatus, SourceBlockId, SourceBlockStatus, Timestamp};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::daemon::relay::RelayPost;
use crate::daemon::repair::RepairTrigger;

#[cfg(test)]
mod tests;

// ─── PendingHashChallenge ─────────────────────────────────────────────────────

/// Re-exported from syncback-core for use in tests and wiring.
pub use syncback_core::pos::PendingHashChallenge;

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
    /// Erasure encoder for computing raw symbols during hash challenge issuance.
    encoder: std::sync::Arc<dyn syncback_core::erasure::ErasureEncoder>,
    /// Epoch encryption key for rebuilding source block blobs.
    epoch_key: [u8; 32],
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
        encoder: std::sync::Arc<dyn syncback_core::erasure::ErasureEncoder>,
        epoch_key: [u8; 32],
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
            encoder,
            epoch_key,
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

    /// Issue PoS hash challenges to all holders that are due for a challenge this cycle.
    ///
    /// Steps:
    ///   1. Get current timestamp.
    ///   2. List all placements from DB; filter to challengeable statuses.
    ///   3. Use due_challenges() to find which holders are overdue.
    ///   4. Skip placements that already have a pending challenge (avoid double-issue).
    ///   5. Group due entries by source_block_id.
    ///   6. For each block: encode_raw once (union of all holders' ESI ranges), then
    ///      per-holder apply binding + compute chain hash in spawn_blocking.
    ///   7. Post PosHashChallengeMsg to relay board and insert into pending map.
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

        info!(due = due.len(), "scheduler: issuing PoS hash challenges");

        // Group due entries by source_block_id so we encode each block's raw symbols once.
        let mut by_block: HashMap<SourceBlockId, Vec<&syncback_core::pos::ChallengeScheduleEntry>> = HashMap::new();
        for entry in &due {
            by_block.entry(entry.source_block_id).or_default().push(entry);
        }

        for (block_id, block_entries) in by_block {
            // Filter out already-pending entries.
            let block_entries: Vec<_> = block_entries.into_iter()
                .filter(|e| !already_pending.contains(&(e.source_block_id, e.holder_id)))
                .collect();
            if block_entries.is_empty() {
                continue;
            }

            // Find corresponding SymbolPlacements.
            let holder_placements: Vec<_> = block_entries.iter()
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
            let holder_data: Vec<(DeviceId, Vec<(u32, u32)>)> = holder_placements.iter()
                .map(|p| (p.holder_id, p.esi_ranges.clone()))
                .collect();

            let encoder = std::sync::Arc::clone(&self.encoder);
            let block_id_clone = block_id;

            // encode_raw once for the block, then compute per-holder chain hashes.
            let hash_results = tokio::task::spawn_blocking(move || -> Vec<(DeviceId, [u8; 32], Vec<(u32, u32)>)> {
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
                    let mut esis: Vec<u32> = esi_ranges.iter()
                        .flat_map(|&(start, count)| start..start + count)
                        .collect();
                    esis.sort_unstable();

                    // Apply binding keystream and collect bound symbols.
                    let bound_pairs: Vec<(u32, Vec<u8>)> = esis.iter()
                        .filter_map(|&esi| {
                            raw_symbols.get(&esi).map(|raw_data| {
                                let mut data = raw_data.clone();
                                let ks = syncback_core::erasure::binding_keystream(
                                    &block_id_clone, holder_id, esi, data.len(),
                                );
                                for (d, k) in data.iter_mut().zip(ks.iter()) {
                                    *d ^= k;
                                }
                                (esi, data)
                            })
                        })
                        .collect();

                    let refs: Vec<(u32, &[u8])> = bound_pairs.iter()
                        .map(|(esi, data)| (*esi, data.as_slice()))
                        .collect();

                    match syncback_core::pos::compute_chain_hash(&refs) {
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
            }).await.unwrap_or_default();

            // Post a challenge for each holder we computed a hash for.
            for (holder_id, expected_hash, esi_ranges) in hash_results {
                let challenge_id = random_challenge_id();
                let holder_master = self.db.get_master_for_device(&holder_id)
                    .ok()
                    .flatten()
                    .map(|m| IdentityPub(m.0))
                    .unwrap_or_else(|| IdentityPub(holder_id.0));

                let challenge_msg = syncback_core::messages::PosHashChallengeMsg {
                    v: 1,
                    challenge_id,
                    source_block_id: block_id,
                    esi_ranges: esi_ranges.clone(),
                    timestamp: now,
                    device_id: Some(holder_id),
                };

                if let Ok(payload) = syncback_core::messages::to_cbor(&challenge_msg) {
                    let _ = self.relay_post_tx.send(crate::daemon::relay::RelayPost {
                        msg_type: "pos_hash_challenge".to_string(),
                        target: Some(holder_master),
                        payload,
                        msg_id: challenge_id,
                    }).await;
                } else {
                    error!(
                        block_id = %block_id,
                        holder_id = %holder_id,
                        "scheduler: failed to encode PosHashChallenge"
                    );
                    continue;
                }

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
                    "scheduler: PoS hash challenge issued"
                );
            }
        }

        Ok(())
    }

    /// Load source block data for PoS challenge computation.
    ///
    /// First tries reading block.bin from disk; if not found, rebuilds from
    /// source files using compress_and_encrypt (same path as Processor::rebuild_blob_for_pos).
    async fn load_source_block_data(&self, block_id: &SourceBlockId) -> anyhow::Result<Vec<u8>> {
        let block_hex = syncback_core::types::hex_encode(&block_id.0);
        let block_path = self.source_blocks_dir.join(&block_hex).join("block.bin");

        match tokio::fs::read(&block_path).await {
            Ok(data) => return Ok(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Rebuild from source files.
            }
            Err(e) => return Err(e.into()),
        }

        let block_record = self.db.get_source_block(block_id)?
            .ok_or_else(|| anyhow::anyhow!("source block record missing: {block_id}"))?;
        let db = self.db.clone();
        let epoch_key = self.epoch_key;
        let expected_id = *block_id;

        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            let plaintext = crate::daemon::backup::packing::rebuild_plaintext_from_db(
                &db, &block_record,
            )?;
            let blob = crate::daemon::backup::pipeline::compress_and_encrypt(
                &plaintext, &epoch_key,
            )?;
            let rebuilt_id: [u8; 32] = *blake3::hash(&blob).as_bytes();
            if rebuilt_id != expected_id.0 {
                anyhow::bail!("rebuilt blob hash mismatch for {expected_id}");
            }
            Ok(blob)
        }).await?
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
        // Offered timeout is real-world network delivery time, NOT protocol time.
        // Do NOT scale by time_scale — delivery takes real seconds regardless of
        // how fast we run PoS/escrow timers.
        let threshold = OFFERED_PLACEMENT_TIMEOUT_SECS;

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
