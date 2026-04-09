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
use std::sync::Arc;

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
        }
    }
}

/// Result of processing one source block through the pipeline.
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
    /// Average importance of files packed into this block (used for SymbolOffer).
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
    pub(crate) fn get_candidates(&self) -> anyhow::Result<Vec<HolderCandidate>> {
        if !self.config.mock_holders.is_empty() {
            return Ok(self.config.mock_holders.clone());
        }
        let peers = self.db.list_all_peers()?;
        let candidates = peers
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
        Ok(candidates)
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
        let estimate = syncback_core::budget::estimate_budget(committed_bytes, budget_record.as_ref());
        tracing::debug!(
            committed_gb = estimate.committed_gb,
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
    pub fn flush_queue(
        &mut self,
        category: FileCategory,
        force: bool,
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

        // Split: selected files proceed, deferred files stay in queue.
        let selected_paths: std::collections::HashSet<&str> =
            batch.candidates.iter().map(|c| c.path.as_str()).collect();

        let (selected, deferred): (Vec<QueuedFile>, Vec<QueuedFile>) =
            std::mem::take(queue).into_iter().partition(|qf| selected_paths.contains(qf.path.as_str()));

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

        let candidates = self.get_candidates()?;
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
    pub fn flush_all(&mut self, force: bool) -> anyhow::Result<Vec<PipelineResult>> {
        let mut all_results = Vec::new();
        let categories = [
            FileCategory::Photo,
            FileCategory::Document,
            FileCategory::Video,
            FileCategory::Other,
        ];
        for cat in categories {
            let mut results = self.flush_queue(cat, force)?;
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
        )?;
        update_backed_up_at(&self.db, &batch, result.source_block_id, result.k, result.t)?;
        Ok(result)
    }

    /// Run the coordinator as a tokio task (Phase 3+).
    ///
    /// Reads DirtyEvent from rx channel. Exits when channel is closed.
    /// Runs idle flush (FLUSH_IDLE_SECS) and fallback flush (FLUSH_FALLBACK_SECS) timers.
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
                            // Wrap the blocking flush in block_in_place so the tokio
                            // runtime can still make progress on other tasks while
                            // we compress, encrypt, encode and write to disk
                            // (review A1 / HIGH blocking-I/O).
                            let flush_result = tokio::task::block_in_place(|| self.flush_all(true));
                            match flush_result {
                                Ok(results) => self.deliver_symbols(&results).await,
                                Err(e) => tracing::error!("final flush error: {e}"),
                            }
                            self.persist_cycle_budget();
                            break;
                        }
                    }
                }
                _ = idle_timer.tick() => {
                    tracing::debug!("idle flush triggered");
                    let flush_result = tokio::task::block_in_place(|| self.flush_all(true));
                    match flush_result {
                        Ok(results) => {
                            if !results.is_empty() {
                                self.deliver_symbols(&results).await;
                            }
                        }
                        Err(e) => tracing::error!("idle flush error: {e}"),
                    }
                    self.persist_cycle_budget();
                }
                _ = fallback_timer.tick() => {
                    tracing::debug!("fallback flush triggered");
                    let flush_result = tokio::task::block_in_place(|| self.flush_all(true));
                    match flush_result {
                        Ok(results) => {
                            if !results.is_empty() {
                                self.deliver_symbols(&results).await;
                            }
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

    /// Deliver encoded symbols to their assigned holders over the network.
    ///
    /// For each `PipelineResult`:
    ///   1. Load `SymbolPlacement` records for the source block from DB.
    ///   2. For each placement, read symbol files from disk, build `SymbolTransferMsg`,
    ///      and deliver via libp2p swarm.
    ///
    /// Errors are logged but not propagated — delivery failures do not abort the backup.
    /// No-op when `config.swarm` is None.
    async fn deliver_symbols(&self, results: &[PipelineResult]) {
        if self.config.swarm.is_none() {
            tracing::debug!("deliver_symbols: no swarm configured, skipping");
            return;
        }

        tracing::info!(
            blocks = results.len(),
            "deliver_symbols: starting delivery"
        );

        for result in results {
            let placements = match self.db.list_placements_for_block(&result.source_block_id) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(
                        block = ?result.source_block_id,
                        error = %e,
                        "deliver_symbols: failed to load placements from DB"
                    );
                    continue;
                }
            };

            for placement in &placements {
                if let Err(e) = self.deliver_to_holder(result, placement).await {
                    tracing::warn!(
                        block = ?result.source_block_id,
                        holder = %placement.holder_id,
                        error = %e,
                        "deliver_symbols: failed to deliver to holder (will retry on repair)"
                    );
                }
            }

            // Clean up block.bin and directory if all symbol files were delivered.
            self.cleanup_block_dir(&result.source_block_id);
        }
    }

    /// Deliver symbols for one (block, holder) pair.
    ///
    /// When `master_signing_key` is configured:
    ///   1. Build SymbolOffer (signed with master key).
    ///   2. Send SymbolOffer via swarm.send_to_device (request-response).
    ///   3. On SymbolAccept reply → send SymbolTransfer.
    ///   4. On SymbolReject/error → log, return Err (caller logs + continues).
    ///
    /// When `master_signing_key` is None: fall back to direct SymbolTransfer.
    async fn deliver_to_holder(
        &self,
        result: &PipelineResult,
        placement: &syncback_core::types::SymbolPlacement,
    ) -> anyhow::Result<()> {
        use syncback_core::messages::Message;
        use syncback_core::types::Timestamp;

        let swarm = match self.config.swarm.as_ref() {
            Some(s) => s.clone(),
            None => {
                tracing::debug!("deliver_to_holder: no swarm, skipping");
                return Ok(());
            }
        };

        let signing_key = match self.config.master_signing_key.as_ref() {
            Some(k) => k,
            None => {
                // No signing key: fall back to direct SymbolTransfer.
                return self.deliver_to_holder_direct(&swarm, result, placement).await;
            }
        };

        let importance = result.importance;

        // Build signed SymbolOffer.
        let msg_id: [u8; 16] = rand::random();
        let timestamp = Timestamp::now();
        let offer = syncback_core::messages::build_symbol_offer(
            msg_id,
            result.source_block_id,
            placement.esi_ranges.clone(),
            importance,
            timestamp,
            signing_key,
        );

        // Send SymbolOffer and wait for reply (request-response via libp2p).
        let reply = swarm
            .send_to_device(placement.holder_id, Message::SymbolOffer(offer))
            .await
            .map_err(|e| anyhow::anyhow!("send SymbolOffer: {e}"))?;

        match reply {
            Message::SymbolAccept(_accept) => {
                // Holder accepted — send SymbolTransfer.
                self.deliver_to_holder_direct(&swarm, result, placement).await
            }
            Message::SymbolReject(reject) => {
                anyhow::bail!(
                    "holder {} rejected offer for block {:?}: {:?}",
                    placement.holder_id,
                    result.source_block_id,
                    reject.reason
                )
            }
            other => {
                anyhow::bail!(
                    "unexpected reply to SymbolOffer from {}: {:?}",
                    placement.holder_id,
                    std::mem::discriminant(&other)
                )
            }
        }
    }

    /// Direct SymbolTransfer delivery via libp2p swarm.
    async fn deliver_to_holder_direct(
        &self,
        swarm: &crate::daemon::network::swarm::SwarmHandle,
        result: &PipelineResult,
        placement: &syncback_core::types::SymbolPlacement,
    ) -> anyhow::Result<()> {
        use syncback_core::messages::{Message, SymbolTransferMsg};
        use syncback_core::types::Timestamp;

        let symbols = pipeline::read_symbols_for_holder(
            &self.config.symbols_dir,
            &result.source_block_id,
            &placement.esi_ranges,
        )?;

        if symbols.is_empty() {
            anyhow::bail!(
                "no symbol files found for block {:?} holder {}",
                result.source_block_id,
                placement.holder_id
            );
        }

        let symbol_count = symbols.len();
        let msg = SymbolTransferMsg {
            v: 1,
            source_block_id: result.source_block_id,
            symbols,
            timestamp: Timestamp::now(),
        };

        swarm
            .send_to_device(placement.holder_id, Message::SymbolTransfer(msg))
            .await
            .map_err(|e| anyhow::anyhow!("send_symbols: {e}"))?;

        tracing::info!(
            holder = %placement.holder_id,
            block_id = %result.source_block_id,
            symbols = symbol_count,
            "backup: symbols delivered"
        );

        // Clean up delivered symbol files from owner's disk.
        let block_hex = syncback_core::types::hex_encode(&result.source_block_id.0);
        let block_dir = self.config.symbols_dir.join(&block_hex);
        for &(start_esi, count) in &placement.esi_ranges {
            for i in 0..count {
                let esi = start_esi + i;
                let path = block_dir.join(format!("{esi}.bin"));
                if let Err(e) = std::fs::remove_file(&path) {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(path = %path.display(), "cleanup: failed to remove symbol file: {e}");
                    }
                }
            }
        }

        Ok(())
    }

    /// Clean up block directory after all symbols have been delivered.
    /// Encryption is deterministic (nonce derived from content), so block.bin
    /// can be rebuilt from source files for PoS/repair. Safe to delete.
    fn cleanup_block_dir(&self, block_id: &syncback_core::types::SourceBlockId) {
        let block_hex = syncback_core::types::hex_encode(&block_id.0);
        let block_dir = self.config.symbols_dir.join(&block_hex);

        if !block_dir.exists() {
            return;
        }

        // Check if any .bin symbol files remain (exclude block.bin).
        let has_remaining_symbols = std::fs::read_dir(&block_dir)
            .map(|entries| {
                entries.filter_map(|e| e.ok()).any(|e| {
                    let name = e.file_name();
                    let name = name.to_string_lossy();
                    name.ends_with(".bin") && name != "block.bin"
                })
            })
            .unwrap_or(true);

        if !has_remaining_symbols {
            // Delete block.bin and the directory.
            let block_bin = block_dir.join("block.bin");
            if let Err(e) = std::fs::remove_file(&block_bin) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %block_bin.display(), "cleanup: failed to remove block.bin: {e}");
                }
            }
            if let Err(e) = std::fs::remove_dir(&block_dir) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %block_dir.display(), "cleanup: failed to remove block dir: {e}");
                }
            }
            tracing::info!(block_id = %block_id, "backup: all symbols delivered, block dir cleaned up");
        }
    }
}
