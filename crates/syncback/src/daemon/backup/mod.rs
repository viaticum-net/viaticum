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
use syncback_core::types::{DeviceId, FileCategory, FileId, IdentityPub, SourceBlockId};

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
        holder_id: IdentityPub,
        source_block_id: SourceBlockId,
    },
    /// Holder rejected our symbols for this block.
    SymbolRejected {
        holder_id: IdentityPub,
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
    /// Network handle for symbol delivery.
    /// When None: symbols are encoded and written to disk but not delivered
    /// (pre-7.5 behavior; also used in unit tests that do not spin up a network).
    pub network: Option<std::sync::Arc<crate::daemon::network::NetworkHandle>>,
    /// Per-directory importance overrides from config.
    /// Used to look up the importance of a file when creating a backup event.
    /// When empty, DEFAULT_IMPORTANCE (0.5) is used for all files.
    pub watch_configs: Vec<WatchConfig>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        BackupConfig {
            source_block_size: DEFAULT_SOURCE_BLOCK_SIZE,
            symbols_dir: std::path::PathBuf::from("symbols"),
            epoch_key: [0u8; 32],
            device_id: DeviceId([0u8; 16]),
            mock_holders: vec![],
            cluster_state: None,
            network: None,
            watch_configs: vec![],
        }
    }
}

/// Result of processing one source block through the pipeline.
#[derive(Debug)]
pub struct PipelineResult {
    pub source_block_id: SourceBlockId,
    pub k: u32,
    pub n: u32,
    pub symbol_count_per_holder: Vec<(IdentityPub, u32)>,
    /// Exact byte length of the stored blob ([nonce][ciphertext]).
    /// Required for restore: the decoded erasure block is zero-padded to k*t; trim to stored_size.
    pub stored_size: u64,
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
}

impl BackupCoordinator {
    /// Create a new coordinator.
    pub fn new(db: Db, config: BackupConfig, encoder: Arc<dyn ErasureEncoder>) -> Self {
        let next_file_id = db
            .list_all_files()
            .unwrap_or_default()
            .iter()
            .map(|r| r.file_id.0 + 1)
            .max()
            .unwrap_or(1);

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
    pub(crate) fn alloc_file_id(&mut self) -> FileId {
        let id = FileId(self.next_file_id);
        self.next_file_id += 1;
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
                    identity: p.identity,
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

    /// Flush the specified category queue if it meets flush criteria.
    ///
    /// Flushes when: total queue bytes >= source_block_size, OR force=true.
    /// Skips if total bytes across all categories < MIN_BATCH_BYTES and force=false.
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

        let candidates = self.get_candidates()?;
        let queue = self.queues.entry(category).or_default();

        flush_queue_inner(
            &self.db,
            &self.config,
            &self.encoder,
            queue,
            total_all,
            force,
            &candidates,
        )
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
        update_backed_up_at(&self.db, &batch, result.source_block_id)?;
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

        let mut idle_timer =
            interval(Duration::from_secs(syncback_core::constants::FLUSH_IDLE_SECS));
        idle_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut fallback_timer =
            interval(Duration::from_secs(syncback_core::constants::FLUSH_FALLBACK_SECS));
        fallback_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                maybe_event = rx.recv() => {
                    match maybe_event {
                        Some(event) => {
                            if let Err(e) = self.process_event(event) {
                                tracing::error!("process_event error: {e}");
                            }
                            idle_timer.reset();
                        }
                        None => {
                            tracing::info!("BackupCoordinator: channel closed, flushing and exiting");
                            match self.flush_all(true) {
                                Ok(results) => self.deliver_symbols(&results).await,
                                Err(e) => tracing::error!("final flush error: {e}"),
                            }
                            break;
                        }
                    }
                }
                _ = idle_timer.tick() => {
                    tracing::debug!("idle flush triggered");
                    match self.flush_all(false) {
                        Ok(results) => {
                            if !results.is_empty() {
                                self.deliver_symbols(&results).await;
                            }
                        }
                        Err(e) => tracing::error!("idle flush error: {e}"),
                    }
                }
                _ = fallback_timer.tick() => {
                    tracing::debug!("fallback flush triggered");
                    match self.flush_all(true) {
                        Ok(results) => {
                            if !results.is_empty() {
                                self.deliver_symbols(&results).await;
                            }
                        }
                        Err(e) => tracing::error!("fallback flush error: {e}"),
                    }
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
    fn handle_backup_event(&self, event: BackupEvent) {
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

    /// Deliver encoded symbols to their assigned holders over the network.
    ///
    /// For each `PipelineResult`:
    ///   1. Load `SymbolPlacement` records for the source block from DB.
    ///   2. For each placement, read symbol files from disk, build `SymbolTransferMsg`,
    ///      and call `network.send_symbols(holder_identity, msg)`.
    ///
    /// Errors are logged but not propagated — delivery failures do not abort the backup.
    /// No-op when `config.network` is None.
    async fn deliver_symbols(&self, results: &[PipelineResult]) {
        let network = match &self.config.network {
            Some(n) => n.clone(),
            None => return,
        };

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
                if let Err(e) = self.deliver_to_holder(&network, result, placement).await {
                    tracing::warn!(
                        block = ?result.source_block_id,
                        holder = %placement.holder_id,
                        error = %e,
                        "deliver_symbols: failed to deliver to holder (will retry on repair)"
                    );
                }
            }
        }
    }

    /// Deliver symbols for one (block, holder) pair.
    async fn deliver_to_holder(
        &self,
        network: &crate::daemon::network::NetworkHandle,
        result: &PipelineResult,
        placement: &syncback_core::types::SymbolPlacement,
    ) -> anyhow::Result<()> {
        use syncback_core::messages::SymbolTransferMsg;
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

        let msg = SymbolTransferMsg {
            v: 1,
            source_block_id: result.source_block_id,
            symbols,
            timestamp: Timestamp::now(),
        };

        network
            .send_symbols(placement.holder_id, msg)
            .await
            .map_err(|e| anyhow::anyhow!("send_symbols: {e}"))
    }
}
