// BackupCoordinator: orchestrates file -> symbol pipeline.
//
// Phase 2: synchronous API only (process_event, flush_queue, flush_all, process_large_file).
// The async run() method is provided for Phase 3 integration with the network layer.
//
// See docs/beta/backup_flow.md and docs/beta/tasks/backup.md for design.
//
// Module layout:
//   mod.rs      -- BackupCoordinator struct, public API, coordinator logic
//   events.rs   -- process_event helpers: handle_deleted, handle_added_or_modified
//   pipeline.rs -- compress/encrypt/encode/write-symbols inner pipeline
//   packing.rs  -- PackIndex format: build_plaintext, parse_pack_index
//   tests.rs    -- all test scenarios

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use syncback_core::config::WatchConfig;
use syncback_core::constants::DEFAULT_SOURCE_BLOCK_SIZE;
use syncback_core::db::Db;
use syncback_core::erasure::ErasureEncoder;
use syncback_core::placement::HolderCandidate;
use syncback_core::types::{DeviceId, FileCategory, FileId, SourceBlockId};

use pipeline::{flush_queue_inner, run_pipeline, update_backed_up_at, BlockTypeTag};

pub mod events;
pub mod packing;
pub mod pipeline;

#[cfg(test)]
mod tests;

// ─── Public types ─────────────────────────────────────────────────────────────

/// A dirty file event from the watcher.
#[derive(Debug, Clone)]
pub struct DirtyEvent {
    pub path: String,
    pub kind: DirtyKind,
    pub device_id: DeviceId,
}

/// Kind of dirty event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirtyKind {
    Added,
    Modified,
    Deleted,
}

/// Notification from Processor about symbol offer outcomes.
#[derive(Debug, Clone)]
pub enum BackupEvent {
    /// Holder accepted our symbols for this block.
    SymbolAccepted {
        holder_id: DeviceId,
        source_block_id: SourceBlockId,
    },
    /// Holder rejected our symbols for this block.
    SymbolRejected {
        holder_id: DeviceId,
        source_block_id: SourceBlockId,
        reason: String,
    },
}

/// One item waiting in a packing queue.
#[derive(Debug, Clone)]
pub struct QueuedFile {
    pub path: String,
    pub file_id: FileId,
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    pub category: FileCategory,
    /// Importance inherited from FileRecord (default 0.5).
    pub importance: f64,
}

/// Configuration for BackupCoordinator.
#[derive(Clone)]
pub struct BackupConfig {
    /// Source block size in bytes. Default: DEFAULT_SOURCE_BLOCK_SIZE.
    pub source_block_size: u64,
    /// Directory where bound symbol files are written.
    pub symbols_dir: std::path::PathBuf,
    /// Epoch key for file encryption. 32 bytes.
    pub epoch_key: [u8; 32],
    /// This device's ID (for LocalState and EventLog).
    pub device_id: DeviceId,
    /// Holder candidates override (tests only). Production code passes `vec![]`.
    pub mock_holders: Vec<HolderCandidate>,
    /// Optional cluster state for dedup check (multi-device).
    /// If None: use inline DB scan (single-device backward compat).
    pub cluster_state: Option<std::sync::Arc<std::sync::Mutex<syncback_core::cluster::ClusterState>>>,
    /// Per-directory importance overrides from config.
    /// Used to look up the importance of a file when creating a backup event.
    /// When empty, DEFAULT_IMPORTANCE (0.5) is used for all files.
    pub watch_configs: Vec<WatchConfig>,
    /// Time acceleration factor. Divides flush timer intervals.
    pub time_scale: u64,
    /// Override offer_budget_gb for testing. None = compute from DB (production).
    /// Follows the same pattern as mock_holders.
    pub mock_offer_budget_gb: Option<f64>,
    /// Master identity signing key for signing SymbolOfferMsg.
    /// When Some: deliver_to_holder uses the offer/accept/transfer handshake.
    /// When None: symbols are written to disk but not delivered (unit tests).
    pub master_signing_key: Option<ed25519_dalek::SigningKey>,
    /// libp2p swarm handle for symbol delivery.
    /// When Some: deliver_to_holder uses send_to_device (request-response).
    /// When None: symbols are encoded and written to disk but not delivered.
    pub swarm: Option<std::sync::Arc<crate::daemon::network::swarm::SwarmHandle>>,
    /// Live watch configs shared with WatchAdmin.
    /// When Some: derive_file_importance uses this instead of watch_configs.
    /// When None: falls back to watch_configs (static copy for backward compat).
    pub live_watch_configs: Option<Arc<RwLock<Vec<WatchConfig>>>>,
    /// Per-peer rejection backoff. Holders that recently rejected an offer
    /// are soft-filtered from candidate selection until cooldown expires.
    /// Optional: tests pass `None`.
    pub peer_backoff: Option<Arc<crate::daemon::peer_backoff::PeerBackoff>>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        BackupConfig {
            source_block_size: DEFAULT_SOURCE_BLOCK_SIZE,
            symbols_dir: std::path::PathBuf::from("symbols"),
            epoch_key: [0u8; 32],
            device_id: DeviceId([0u8; 32]),
            mock_holders: vec![],
            cluster_state: None,
            watch_configs: vec![],
            time_scale: 1,
            mock_offer_budget_gb: None,
            master_signing_key: None,
            swarm: None,
            live_watch_configs: None,
            peer_backoff: None,
        }
    }
}

/// Result of processing one source block through the pipeline.
///
/// Wave 11b: `raw_symbols` and `esi_offset` removed. The WorkPipeline worker
/// re-encodes from source files on each iteration — no in-memory handoff.
#[derive(Debug)]
pub struct PipelineResult {
    pub source_block_id: SourceBlockId,
    pub k: u32,
    pub n: u32,
    /// Symbol size in bytes (SYMBOL_SIZE).
    pub t: u16,
    pub symbol_count_per_holder: Vec<(DeviceId, u32)>,
    /// Exact byte length of the stored blob ([nonce][ciphertext]).
    /// Required for restore: the decoded erasure block is zero-padded to k*t; trim to stored_size.
    pub stored_size: u64,
    /// Average importance of files packed into this block.
    pub importance: f64,
}

// ─── BackupCoordinator ────────────────────────────────────────────────────────

/// BackupCoordinator: orchestrates file -> symbol pipeline.
pub struct BackupCoordinator {
    pub(crate) db: Db,
    pub(crate) config: BackupConfig,
    pub(crate) encoder: Arc<dyn ErasureEncoder>,
    /// Per-category packing queues.
    pub(crate) queues: HashMap<FileCategory, Vec<QueuedFile>>,
    /// Monotonically increasing FileId counter.
    pub(crate) next_file_id: u64,
    /// Holders offered symbols this flush cycle (reset after persist).
    pub(crate) offered_this_cycle: u32,
    /// Holders that accepted symbols this flush cycle (reset after persist).
    pub(crate) accepted_this_cycle: u32,
}

impl BackupCoordinator {
    /// Create a new coordinator.
    pub fn new(db: Db, config: BackupConfig, encoder: Arc<dyn ErasureEncoder>) -> Self {
        // Prefer the persisted singleton; fall back to scanning files on legacy
        // databases that pre-date the META table.
        let stored = db.load_next_file_id().unwrap_or(0);
        let scanned = db
            .list_all_files()
            .unwrap_or_default()
            .iter()
            .map(|r| r.file_id.0 + 1)
            .max()
            .unwrap_or(1);
        let next_file_id = stored.max(scanned);

        let mut queues = HashMap::new();
        queues.insert(FileCategory::Photo, vec![]);
        queues.insert(FileCategory::Document, vec![]);
        queues.insert(FileCategory::Video, vec![]);
        queues.insert(FileCategory::Other, vec![]);

        BackupCoordinator {
            db,
            config,
            encoder,
            queues,
            next_file_id,
            offered_this_cycle: 0,
            accepted_this_cycle: 0,
        }
    }

    /// Classify a file path into a FileCategory.
    pub(crate) fn classify(path: &str) -> FileCategory {
        let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
        match ext.as_str() {
            "jpg" | "jpeg" | "png" | "gif" | "heic" | "raw" | "cr2" | "nef" | "webp" => {
                FileCategory::Photo
            }
            "mp4" | "mov" | "avi" | "mkv" | "m4v" | "wmv" => FileCategory::Video,
            _ => FileCategory::Document,
        }
    }

    /// Allocate the next FileId.
    ///
    /// Persists the updated counter to the DB so a crash between allocation and
    /// FileRecord write does not reuse the id on restart. Storage failure is
    /// logged but not propagated — we prefer to continue rather than block backup.
    pub(crate) fn alloc_file_id(&mut self) -> FileId {
        let id = FileId(self.next_file_id);
        self.next_file_id += 1;
        if let Err(e) = self.db.store_next_file_id(self.next_file_id) {
            tracing::error!(err = %e, "backup: failed to persist next_file_id");
        }
        id
    }

    /// Total bytes queued across all categories.
    fn total_queued_bytes(&self) -> u64 {
        self.queues
            .values()
            .flat_map(|q| q.iter())
            .map(|qf| qf.size_bytes)
            .sum()
    }

    /// Get holder candidates: mock_holders if configured (tests only), else compute from DB peers.
    /// Soft-filters peers currently on rejection cooldown when peer_backoff is set
    /// (falls back to the unfiltered list if filtering would leave fewer than 2).
    /// Then filters to only authenticated (online) peers; falls back to unfiltered
    /// if fewer than 2 authenticated candidates remain.
    pub(crate) fn get_candidates(
        &self,
        authenticated: &std::collections::HashSet<DeviceId>,
    ) -> anyhow::Result<Vec<HolderCandidate>> {
        if !self.config.mock_holders.is_empty() {
            return Ok(self.config.mock_holders.clone());
        }
        let peers = self.db.list_all_peers()?;
        let candidates: Vec<HolderCandidate> = peers
            .into_iter()
            .map(|p| {
                let trust_raw = (syncback_core::constants::KP * p.trust_p
                    + syncback_core::constants::KI * p.trust_i)
                    * p.trust_s.clamp(
                        syncback_core::constants::S_CLAMP_MIN,
                        syncback_core::constants::S_CLAMP_MAX,
                    );
                HolderCandidate {
                    device_id: p.device_id,
                    trust: trust_raw.clamp(0.0, 0.999),
                }
            })
            .collect();

        let candidates = if let Some(backoff) = self.config.peer_backoff.as_ref() {
            let raw = candidates.clone();
            let filtered = backoff.filter(candidates, 2, |c| &c.device_id);
            if filtered.is_empty() {
                tracing::debug!(
                    "backup: all candidates on backoff, falling back to raw list ({})",
                    raw.len()
                );
                raw
            } else {
                filtered
            }
        } else {
            candidates
        };

        // Online filter: restrict to authenticated peers only.
        let auth_filtered: Vec<HolderCandidate> = candidates
            .iter()
            .filter(|c| authenticated.contains(&c.device_id))
            .cloned()
            .collect();

        if auth_filtered.len() < 2 {
            // Fallback: authenticated set is empty or too small (boot, unit test without swarm).
            tracing::debug!(
                total = candidates.len(),
                authenticated = authenticated.len(),
                "backup: authenticated set too small, using unfiltered candidates"
            );
            return Ok(candidates);
        }

        // Log skipped unauthenticated peers at DEBUG level.
        for c in &candidates {
            if !authenticated.contains(&c.device_id) {
                tracing::debug!(
                    peer_id = %c.device_id,
                    "backup: peer skipped — not authenticated"
                );
            }
        }
        Ok(auth_filtered)
    }

    /// Process a single dirty event synchronously.
    ///
    /// For Added/Modified: read file, compute hash, dedup check, classify, enqueue.
    /// For Deleted: update device state to Deleted(now).
    pub fn process_event(&mut self, event: DirtyEvent) -> anyhow::Result<()> {
        match event.kind {
            DirtyKind::Deleted => self.handle_deleted(&event),
            DirtyKind::Added | DirtyKind::Modified => self.handle_added_or_modified(&event),
        }
    }

    /// Earning-side weight for a master we hold data for.
    ///
    /// We cannot directly reuse the combined trust score: a pure holder trivially
    /// has S=0.1 against every owner (they never stored anything for us), which
    /// clamps combined toward zero and starves earned credit — defeating the
    /// self-awareness story.
    ///
    /// We also cannot reuse just kp×P + ki×I, because `recalculate_trust` only
    /// fires on the PoS OWNER side; a pure-holder daemon never updates trust_p
    /// for any peer, so it stays at INITIAL_TRUST_P (the prior) with no I
    /// evidence — the weight stays tiny relative to peers with real PoS history.
    ///
    /// The decision point that makes a master "legitimate to hold data for" is
    /// the SymbolOffer/Accept handshake: the holder validated signatures and
    /// chose to accept. Once a HoldingRecord exists and at least one PeerRecord
    /// for a device of that master is on file, the master is trust-confirmed
    /// from the holder's point of view. We return MAX_COMBINED_TRUST (= full
    /// weight) in that case, and 0 otherwise.
    ///
    /// Sybil concern — logged in tech-debt: an attacker with many fake masters
    /// could feed us offers for junk data and inflate our earned budget. They
    /// must still burn real disk on our side, and accepting requires passing
    /// quota/signature checks, so the cost is bounded. Future work: weight by
    /// `master_trust.combined` once bi-directional trust propagation lands.
    fn earning_weight_for_master(
        &self,
        master: &syncback_core::types::IdentityPub,
    ) -> f64 {
        use syncback_core::constants::MAX_COMBINED_TRUST;
        let devices = self.db.get_devices_for_master(master).unwrap_or_default();
        for did in devices {
            if matches!(self.db.get_peer(&did), Ok(Some(_))) {
                return MAX_COMBINED_TRUST;
            }
        }
        0.0
    }

    /// Compute how many GB we can offer to the network this cycle.
    /// Returns offer_budget_gb from BudgetEstimate.
    /// On DB error: returns FREE_TIER_GB (safe fallback — never block all backups).
    fn compute_offer_budget_gb(&self) -> f64 {
        if let Some(gb) = self.config.mock_offer_budget_gb {
            return gb;
        }
        let committed_bytes = match self.db.committed_bytes() {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("budget: committed_bytes query failed: {e}");
                return syncback_core::constants::FREE_TIER_GB;
            }
        };
        let budget_record = match self.db.get_budget() {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("budget: get_budget query failed: {e}");
                None
            }
        };

        // Trust-weighted earned offer credit: reward us for being a useful holder
        // so a fresh owner with zero committed can still back up their first files.
        let earned_gb = {
            use syncback_core::constants::OFFER_EARN_K_FACTOR_DAYS;
            use syncback_core::types::Timestamp;
            let now = Timestamp::now();
            let contributions = self
                .db
                .held_contributions_gb_days(now, self.config.time_scale)
                .unwrap_or_default();
            syncback_core::budget::compute_earned_offer_gb(
                &contributions,
                |master| self.earning_weight_for_master(master),
                OFFER_EARN_K_FACTOR_DAYS,
            )
        };

        let estimate = syncback_core::budget::estimate_budget(
            committed_bytes,
            budget_record.as_ref(),
            earned_gb,
        );
        tracing::debug!(
            committed_gb = estimate.committed_gb,
            earned_gb = estimate.earned_gb,
            offer_budget_gb = estimate.offer_budget_gb,
            placement_success_rate = estimate.placement_success_rate,
            "budget estimate"
        );
        estimate.offer_budget_gb
    }

    /// Flush the specified category queue if it meets flush criteria.
    ///
    /// Flushes when: total queue bytes >= source_block_size, OR force=true.
    /// Skips if total bytes across all categories < MIN_BATCH_BYTES and force=false.
    /// Applies budget check: files not selected by select_backup_batch stay in queue.
    /// `authenticated`: snapshot of currently-authenticated peer IDs (from SwarmHandle).
    /// Pass `&Default::default()` in tests that use mock_holders.
    pub fn flush_queue(
        &mut self,
        category: FileCategory,
        force: bool,
        authenticated: &std::collections::HashSet<DeviceId>,
    ) -> anyhow::Result<Vec<PipelineResult>> {
        let total_all = self.total_queued_bytes();
        let queue_bytes: u64 = self
            .queues
            .get(&category)
            .map(|q| q.iter().map(|qf| qf.size_bytes).sum())
            .unwrap_or(0);

        let should_flush = force || queue_bytes >= self.config.source_block_size;
        if !should_flush {
            tracing::debug!(
                "flush_queue({:?}): {} bytes < source_block_size, skipping",
                category,
                queue_bytes
            );
            return Ok(vec![]);
        }

        // Budget check: select which queued files fit within this cycle's budget.
        let offer_budget_gb = self.compute_offer_budget_gb();
        let queue = self.queues.entry(category).or_default();

        let candidates_input: Vec<(String, f64, u64)> = queue
            .iter()
            .map(|qf| (qf.path.clone(), qf.importance, qf.size_bytes))
            .collect();

        let batch = syncback_core::budget::select_backup_batch(&candidates_input, offer_budget_gb);

        // Split: selected files proceed in importance-DESC order; deferred files stay in queue.
        // Build a lookup map from path → QueuedFile, then iterate batch.candidates (already
        // in importance-DESC order from select_backup_batch) to reconstruct selected in order.
        // This preserves the importance ordering that select_backup_batch computed (D1 fix).
        let mut queue_map: std::collections::HashMap<String, QueuedFile> =
            std::mem::take(queue).into_iter().map(|qf| (qf.path.clone(), qf)).collect();

        let selected: Vec<QueuedFile> = batch
            .candidates
            .iter()
            .filter_map(|c| queue_map.remove(&c.path))
            .collect();

        // Remaining entries in queue_map were not selected — defer them.
        let deferred: Vec<QueuedFile> = queue_map.into_values().collect();

        // Put deferred files back.
        *queue = deferred;

        if batch.deferred_count > 0 {
            tracing::warn!(
                category = ?category,
                deferred = batch.deferred_count,
                offer_budget_gb,
                "flush_queue: {} files deferred due to budget constraint",
                batch.deferred_count
            );
        }

        if selected.is_empty() {
            return Ok(vec![]);
        }

        let candidates = self.get_candidates(authenticated)?;
        let mut selected_queue = selected;

        let results = flush_queue_inner(
            &self.db,
            &self.config,
            &self.encoder,
            &mut selected_queue,
            total_all,
            force,
            &candidates,
        )?;

        // Tally the number of distinct holders offered to in this batch.
        for result in &results {
            let holder_count = result.symbol_count_per_holder.len() as u32;
            self.offered_this_cycle = self.offered_this_cycle.saturating_add(holder_count);
        }

        Ok(results)
    }

    /// Flush all categories.
    /// `authenticated`: snapshot of currently-authenticated peer IDs passed through to
    /// `flush_queue` and `get_candidates`. Taken before `block_in_place` in `run()`.
    pub fn flush_all(
        &mut self,
        force: bool,
        authenticated: &std::collections::HashSet<DeviceId>,
    ) -> anyhow::Result<Vec<PipelineResult>> {
        let mut all_results = Vec::new();
        let categories = [
            FileCategory::Photo,
            FileCategory::Document,
            FileCategory::Video,
            FileCategory::Other,
        ];
        for cat in categories {
            let mut results = self.flush_queue(cat, force, authenticated)?;
            all_results.append(&mut results);
        }
        Ok(all_results)
    }

    /// Process one large file (>= source_block_size) into its own source block.
    ///
    /// Uses SourceBlockType::Single. Called directly for large files during process_event.
    pub fn process_large_file(
        &mut self,
        path: &str,
        file_id: FileId,
        content_hash: [u8; 32],
        importance: f64,
        candidates: &[HolderCandidate],
    ) -> anyhow::Result<PipelineResult> {
        let file_bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("read large file {}: {e}", path))?;

        let qf = QueuedFile {
            path: path.to_string(),
            file_id,
            content_hash,
            size_bytes: file_bytes.len() as u64,
            category: FileCategory::Other,
            importance,
        };

        let batch = vec![(qf, file_bytes)];
        let result = run_pipeline(
            &self.db,
            &self.config,
            &self.encoder,
            &batch,
            BlockTypeTag::Single,
            candidates,
            &[],
            importance,
        )?;
        update_backed_up_at(&self.db, &batch, result.source_block_id, result.k, result.t)?;
        Ok(result)
    }

    /// Snapshot the set of currently-authenticated peer IDs from the swarm.
    ///
    /// Returns an empty set if no swarm is configured (unit tests, offline).
    /// Must be called from an async context; the result is then passed into
    /// `flush_all` / `flush_queue` which run inside `block_in_place`.
    async fn snapshot_authenticated_peers(&self) -> std::collections::HashSet<DeviceId> {
        match self.config.swarm.as_ref() {
            Some(swarm) => swarm
                .peer_sets()
                .await
                .map(|(auth, _)| auth)
                .unwrap_or_default(),
            None => std::collections::HashSet::new(),
        }
    }

    /// Run the coordinator as a tokio task (Wave 11b: delivery-only stripped out).
    ///
    /// Reads DirtyEvent from rx channel. Exits when channel is closed.
    /// Runs idle flush (FLUSH_IDLE_SECS) and fallback flush (FLUSH_FALLBACK_SECS) timers.
    ///
    /// After Wave 11b: `flush_all` creates DB records only. The WorkPipeline worker
    /// handles actual symbol delivery (encode → send → Offered→Alive transition).
    /// `deliver_symbols` is removed; `backup_event_rx` is kept for SymbolAccepted/Rejected
    /// events from the processor (used for budget tracking).
    pub async fn run(
        mut self,
        mut rx: tokio::sync::mpsc::Receiver<DirtyEvent>,
        mut backup_event_rx: tokio::sync::mpsc::Receiver<BackupEvent>,
    ) -> anyhow::Result<()> {
        use tokio::time::{interval, Duration, MissedTickBehavior};

        let scale = self.config.time_scale.max(1);
        let mut idle_timer =
            interval(Duration::from_secs((syncback_core::constants::FLUSH_IDLE_SECS / scale).max(1)));
        idle_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut fallback_timer =
            interval(Duration::from_secs((syncback_core::constants::FLUSH_FALLBACK_SECS / scale).max(1)));
        fallback_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                maybe_event = rx.recv() => {
                    match maybe_event {
                        Some(event) => {
                            // process_event reads files from disk; wrap in
                            // block_in_place so other tokio tasks keep running
                            // while we do synchronous I/O (review A1).
                            let res = tokio::task::block_in_place(|| self.process_event(event));
                            if let Err(e) = res {
                                tracing::error!("process_event error: {e}");
                            }
                            idle_timer.reset();
                        }
                        None => {
                            tracing::info!("BackupCoordinator: channel closed, flushing and exiting");
                            let auth_snap = self.snapshot_authenticated_peers().await;
                            let flush_result = tokio::task::block_in_place(|| self.flush_all(true, &auth_snap));
                            match flush_result {
                                Ok(_results) => {
                                    // Wave 11b: delivery is the worker's job.
                                    // flush_all creates DB records; WorkPipeline picks up on next tick.
                                }
                                Err(e) => tracing::error!("final flush error: {e}"),
                            }
                            self.persist_cycle_budget();
                            break;
                        }
                    }
                }
                _ = idle_timer.tick() => {
                    tracing::debug!("idle flush triggered");
                    let auth_snap = self.snapshot_authenticated_peers().await;
                    let flush_result = tokio::task::block_in_place(|| self.flush_all(true, &auth_snap));
                    match flush_result {
                        Ok(_results) => {
                            // Wave 11b: delivery is the worker's job.
                        }
                        Err(e) => tracing::error!("idle flush error: {e}"),
                    }
                    self.persist_cycle_budget();
                }
                _ = fallback_timer.tick() => {
                    tracing::debug!("fallback flush triggered");
                    let auth_snap = self.snapshot_authenticated_peers().await;
                    let flush_result = tokio::task::block_in_place(|| self.flush_all(true, &auth_snap));
                    match flush_result {
                        Ok(_results) => {
                            // Wave 11b: delivery is the worker's job.
                        }
                        Err(e) => tracing::error!("fallback flush error: {e}"),
                    }
                    self.persist_cycle_budget();
                }
                maybe_backup = backup_event_rx.recv() => {
                    if let Some(event) = maybe_backup {
                        self.handle_backup_event(event);
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle a BackupEvent from the Processor.
    fn handle_backup_event(&mut self, event: BackupEvent) {
        match event {
            BackupEvent::SymbolAccepted {
                holder_id,
                source_block_id,
            } => {
                tracing::info!(
                    holder = %holder_id,
                    block_id = %source_block_id,
                    "holder accepted symbols"
                );
                // Update placement status to Alive (confirmed by holder).
                match self.db.get_placement(&source_block_id, &holder_id) {
                    Ok(Some(mut placement)) => {
                        if placement.status == syncback_core::types::PlacementStatus::Alive {
                            // Already alive — nothing to do.
                            return;
                        }
                        placement.status = syncback_core::types::PlacementStatus::Alive;
                        if let Err(e) = self.db.upsert_placement(&placement) {
                            tracing::error!(
                                holder = %holder_id,
                                block_id = %source_block_id,
                                error = %e,
                                "failed to update placement after SymbolAccept"
                            );
                        } else {
                            // Counter is best-effort; failure here is logged but does not
                            // roll back the placement transition. Without this refresh the
                            // owner-side bytes_peer_stores_for_us stays at 0 until the
                            // first PoS round triggers it (could be 6 min in demo, ~1h prod).
                            if let Err(e) = self.db.refresh_peer_storage_bytes(&holder_id) {
                                tracing::error!(
                                    holder = %holder_id,
                                    err = %e,
                                    "failed to refresh storage balance after SymbolAccept"
                                );
                            }
                            crate::daemon::processor::recompute_and_persist_block_cached_fields(
                                &self.db,
                                &source_block_id,
                            );
                        }
                    }
                    Ok(None) => {
                        tracing::warn!(
                            holder = %holder_id,
                            block_id = %source_block_id,
                            "SymbolAccept for unknown placement"
                        );
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "DB error on SymbolAccept");
                    }
                }
                self.accepted_this_cycle = self.accepted_this_cycle.saturating_add(1);
            }
            BackupEvent::SymbolRejected {
                holder_id,
                source_block_id,
                reason,
            } => {
                tracing::warn!(
                    holder = %holder_id,
                    block_id = %source_block_id,
                    reason = %reason,
                    "holder rejected symbols"
                );
                // Mark placement as Lost — triggers repair to find new holder.
                match self.db.get_placement(&source_block_id, &holder_id) {
                    Ok(Some(mut placement)) => {
                        placement.status = syncback_core::types::PlacementStatus::Lost;
                        if let Err(e) = self.db.upsert_placement(&placement) {
                            tracing::error!(
                                error = %e,
                                "failed to update placement after SymbolReject"
                            );
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::error!(error = %e, "DB error on SymbolReject");
                    }
                }
            }
        }
    }

    /// Persist accumulated placement stats to DB and reset cycle counters.
    /// No-op if offered_this_cycle == 0 (nothing was sent this cycle).
    fn persist_cycle_budget(&mut self) {
        if self.offered_this_cycle == 0 {
            return;
        }
        let budget_record = match self.db.get_budget() {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("persist_cycle_budget: get_budget failed: {e}");
                return;
            }
        };
        let updated = syncback_core::budget::record_placement_outcome(
            budget_record,
            self.offered_this_cycle,
            self.accepted_this_cycle,
        );
        if let Err(e) = self.db.set_budget(&updated) {
            tracing::error!("persist_cycle_budget: set_budget failed: {e}");
        } else {
            tracing::info!(
                offered = self.offered_this_cycle,
                accepted = self.accepted_this_cycle,
                placement_success_rate = updated.placement_success_rate,
                "budget: cycle stats persisted"
            );
        }
        self.offered_this_cycle = 0;
        self.accepted_this_cycle = 0;
    }

}
// Note: deliver_symbols, deliver_to_holder, deliver_to_holder_direct, cleanup_block_dir
// were removed in Wave 11b. Symbol delivery is now the WorkPipeline worker's responsibility.
