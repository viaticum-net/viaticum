// BackupCoordinator: orchestrates file -> symbol pipeline.
//
// Phase 2: synchronous API only (process_event, flush_queue, flush_all, process_large_file).
// The async run() method is provided for Phase 3 integration with the network layer.
//
// See docs/beta/backup_flow.md and docs/beta/tasks/backup.md for design.
//
// Module layout:
//   mod.rs      -- BackupCoordinator struct, public API, coordinator logic
//   events.rs   -- process_event helpers: handle_added_or_modified, dedup
//   gone.rs     -- deletions, recheck, the root rule (L0: delete-i12, dr-i64)
//   pipeline.rs -- compress/encrypt/encode/write-symbols inner pipeline
//   generation.rs -- L1b N1: the seal generation a packed plaintext takes (delete-i9)
//   packing.rs  -- PackIndex format: build_plaintext, parse_pack_index
//   rebuild.rs  -- rebuild a block's plaintext from this device's files, by content (L0)
//   reconcile.rs -- L1b: current version → serviceable block, pending → queued, by level
//   tests.rs    -- test scenarios
//   tests_current.rs -- L1: a path points at its current content; packing does
//                       not abort on a vanished or changed file (backup-i9, i23)
//   tests_rebuild.rs -- L0: rebuild by content after renames, copies, swaps
//   tests_gone.rs    -- L0: deletion by event and recheck, the watch root rule
//   tests_seal.rs    -- L1b: a generation-0 seal keeps the pre-L1b block id (INV-G0)
//   tests_revive.rs  -- L1b: the serviceable-block dedup gate, the seal generation (N1)
//   tests_reconcile.rs -- L1b: the reconcile hands paths to the watcher (backup-i8, i25)

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use viaticum_core::config::WatchConfig;
use viaticum_core::constants::DEFAULT_SOURCE_BLOCK_SIZE;
use viaticum_core::db::Db;
use viaticum_core::erasure::ErasureEncoder;
use viaticum_core::placement::HolderCandidate;
use viaticum_core::types::{DeviceId, FileCategory, FileId, SourceBlockId};

use pipeline::{
    BlockTypeTag, ReadAtFlush, flush_queue_inner, read_at_flush, run_pipeline, update_backed_up_at,
};

pub mod events;
mod generation;
mod gone;
pub mod packing;
pub mod pipeline;
pub mod rebuild;
pub mod reconcile;

pub(crate) use gone::path_gone;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_current;
#[cfg(test)]
mod tests_gone;
#[cfg(test)]
mod tests_rebuild;
#[cfg(test)]
mod tests_reconcile;
#[cfg(test)]
mod tests_revive;
#[cfg(test)]
mod tests_seal;

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
    /// A live event: the path is gone and its watch root is intact (delete-i12).
    Deleted,
    /// A rebuild did not find the path and the watcher confirmed it gone under an intact
    /// root; marks the exact record deleted only if it is confirmed on disk (dr-i64).
    GoneOnRecheck,
    /// The watch root at `path` vanished or was replaced while watched: no deletion;
    /// recent deletions under it are undone and its records lose the confirmation.
    RootLost,
    /// The watch root at `path` is another directory than the one recorded in
    /// `watch_roots.json` (found at start): handled as `RootLost`.
    RootChanged,
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
    /// Signal channel to wake WorkPipeline after flush. None in unit tests where
    /// WorkPipeline is not running. Without this signal, worker would wait up to
    /// 60s (tick_interval) before noticing new blocks.
    pub work_event_tx: Option<tokio::sync::mpsc::Sender<crate::daemon::work_pipeline::WorkEvent>>,
    /// Paths the reconcile hands to the watcher (L1b, backup-i8, backup-i25). `None` in
    /// unit tests without a watcher: a pass then sends nothing.
    pub resubmit_tx: Option<reconcile::ResubmitTx>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        BackupConfig {
            source_block_size: DEFAULT_SOURCE_BLOCK_SIZE,
            symbols_dir: std::path::PathBuf::from("symbols"),
            epoch_key: [0u8; 32],
            device_id: DeviceId([0u8; 32]),
            mock_holders: vec![],
            watch_configs: vec![],
            time_scale: 1,
            mock_offer_budget_gb: None,
            master_signing_key: None,
            swarm: None,
            live_watch_configs: None,
            peer_backoff: None,
            work_event_tx: None,
            resubmit_tx: None,
        }
    }
}

/// Result of processing one source block through the pipeline.
///
/// Wave 11b: `raw_symbols` and `esi_offset` removed. The WorkPipeline worker
/// re-encodes from source files on each iteration — no in-memory handoff.
///
/// A4: `symbol_count_per_holder` removed. Backup no longer offers symbols — it
/// creates only the `SourceBlockRecord`. The WorkPipeline worker is the sole
/// creator of placements and the sole deliverer, so backup has no per-holder
/// offer counts to report.
#[derive(Debug)]
pub struct PipelineResult {
    pub source_block_id: SourceBlockId,
    pub k: u32,
    pub n: u32,
    /// Symbol size in bytes (SYMBOL_SIZE).
    pub t: u16,
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
    ///
    /// NOTE (post-W11b/A4): backup no longer offers symbols — the WorkPipeline
    /// worker is the sole offerer. This counter is no longer fed by backup;
    /// offer→accept success-rate accounting must be re-homed to the worker.
    /// Tracked for the phase-4R economy redesign. Left in place (not deleted)
    /// because `persist_cycle_budget` / `record_placement_outcome` still
    /// reference it and tests set it directly.
    pub(crate) offered_this_cycle: u32,
    /// Holders that accepted symbols this flush cycle (reset after persist).
    ///
    /// NOTE (post-W11b/A4): a companion to `offered_this_cycle`. It still
    /// increments on `BackupEvent::SymbolAccepted`, only for a placement in `Offered`
    /// (other statuses are ignored), but since `offered_this_cycle`
    /// is now permanently 0, `persist_cycle_budget` early-returns before resetting
    /// it — so it accumulates (saturating) and is never read. Harmless zombie until
    /// the offer→accept accounting is re-homed to the worker in phase-4R.
    pub(crate) accepted_this_cycle: u32,
    /// Reconcile backoff per path (RAM; L1b, backup-i8).
    pub(crate) reconcile_backoff: HashMap<String, reconcile::Backoff>,
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
            reconcile_backoff: HashMap::new(),
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
        // CL-5 T-10: exclude cluster siblings (peers sharing our master identity).
        // Siblings are not an independent failure domain, so holding our blocks on
        // them gives no real redundancy. Only applied when our own master identity
        // is known (master_signing_key set in production; None in unit tests).
        let own_master: Option<viaticum_core::types::IdentityPub> = self
            .config
            .master_signing_key
            .as_ref()
            .map(|sk| viaticum_core::types::IdentityPub(sk.verifying_key().to_bytes()));
        let candidates: Vec<HolderCandidate> = peers
            .into_iter()
            .filter(|p| own_master.as_ref() != Some(&p.master_identity))
            .map(|p| {
                let trust_raw = (viaticum_core::constants::KP * p.trust_p
                    + viaticum_core::constants::KI * p.trust_i)
                    * p.trust_s.clamp(
                        viaticum_core::constants::S_CLAMP_MIN,
                        viaticum_core::constants::S_CLAMP_MAX,
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
    /// For Deleted / GoneOnRecheck / RootLost / RootChanged: see `gone.rs`.
    pub fn process_event(&mut self, event: DirtyEvent) -> anyhow::Result<()> {
        match event.kind {
            DirtyKind::Deleted => self.handle_deleted(&event),
            DirtyKind::GoneOnRecheck => self.handle_gone_on_recheck(&event),
            DirtyKind::RootLost | DirtyKind::RootChanged => self.handle_root_lost(&event),
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
    fn earning_weight_for_master(&self, master: &viaticum_core::types::IdentityPub) -> f64 {
        use viaticum_core::constants::MAX_COMBINED_TRUST;
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
                return viaticum_core::constants::FREE_TIER_GB;
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
            use viaticum_core::constants::OFFER_EARN_K_FACTOR_DAYS;
            use viaticum_core::types::Timestamp;
            let now = Timestamp::now();
            let contributions = self
                .db
                .held_contributions_gb_days(now, self.config.time_scale)
                .unwrap_or_default();
            viaticum_core::budget::compute_earned_offer_gb(
                &contributions,
                |master| self.earning_weight_for_master(master),
                OFFER_EARN_K_FACTOR_DAYS,
            )
        };

        let estimate = viaticum_core::budget::estimate_budget(
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

        let batch = viaticum_core::budget::select_backup_batch(&candidates_input, offer_budget_gb);

        // Split: selected files proceed in importance-DESC order; deferred files stay in queue.
        // Build a lookup map from path → QueuedFile, then iterate batch.candidates (already
        // in importance-DESC order from select_backup_batch) to reconstruct selected in order.
        // This preserves the importance ordering that select_backup_batch computed (D1 fix).
        let mut queue_map: std::collections::HashMap<String, QueuedFile> = std::mem::take(queue)
            .into_iter()
            .map(|qf| (qf.path.clone(), qf))
            .collect();

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

        let candidates = match self.get_candidates(authenticated) {
            Ok(c) => c,
            Err(e) => {
                self.queues.entry(category).or_default().extend(selected);
                return Err(e);
            }
        };
        let mut selected_queue = selected;

        let db = self.db.clone();
        let in_network = |h: &[u8; 32]| content_in_network(&db, h);
        let results = flush_queue_inner(
            &self.db,
            &self.config,
            &self.encoder,
            &mut selected_queue,
            total_all,
            force,
            &candidates,
            &in_network,
        );
        // backup-i23: whatever the flush did not pack (a pipeline error, or the
        // MIN_BATCH_BYTES skip) stays queued.
        self.queues
            .entry(category)
            .or_default()
            .append(&mut selected_queue);

        // A4: backup no longer offers symbols (the WorkPipeline worker is the sole
        // offerer), so there is no per-holder offer count to tally here. See the
        // doc on `offered_this_cycle`.

        results
    }

    /// Flush all categories.
    /// `authenticated`: snapshot of currently-authenticated peer IDs passed through to
    /// `flush_queue` and `get_candidates`. Taken before `block_in_place` in `run()`.
    ///
    /// backup-i23: an error in one category is logged and the other categories still
    /// flush; the first error is returned at the end.
    pub fn flush_all(
        &mut self,
        force: bool,
        authenticated: &std::collections::HashSet<DeviceId>,
    ) -> anyhow::Result<Vec<PipelineResult>> {
        let mut all_results = Vec::new();
        let mut first_err: Option<anyhow::Error> = None;
        let categories = [
            FileCategory::Photo,
            FileCategory::Document,
            FileCategory::Video,
            FileCategory::Other,
        ];
        for cat in categories {
            match self.flush_queue(cat, force, authenticated) {
                Ok(mut results) => all_results.append(&mut results),
                Err(e) => {
                    tracing::error!(
                        category = ?cat,
                        "flush error; files stay queued, other categories go on: {e:#}"
                    );
                    first_err.get_or_insert(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(all_results),
        }
    }

    /// Process one large file (>= source_block_size) into its own source block.
    ///
    /// Uses SourceBlockType::Single. Called directly for large files during process_event.
    /// The second read follows the flush rule (backup-i23, [`read_at_flush`]): a file
    /// that vanished, or now holds content already in the network, is skipped
    /// (`Ok(None)`); a changed one is packed with the hash of the bytes read.
    pub fn process_large_file(
        &mut self,
        path: &str,
        file_id: FileId,
        content_hash: [u8; 32],
        importance: f64,
        candidates: &[HolderCandidate],
    ) -> anyhow::Result<Option<PipelineResult>> {
        let db = self.db.clone();
        let in_network = |h: &[u8; 32]| content_in_network(&db, h);
        let (file_bytes, content_hash) = match read_at_flush(path, &content_hash, &in_network) {
            ReadAtFlush::Pack {
                bytes,
                content_hash,
            } => (bytes, content_hash),
            ReadAtFlush::Skip => return Ok(None),
        };

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
        update_backed_up_at(&self.db, &batch, result.source_block_id, result.k, result.t);
        Ok(Some(result))
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
        use tokio::time::{Duration, MissedTickBehavior, interval};

        let scale = self.config.time_scale.max(1);
        let mut idle_timer = interval(Duration::from_secs(
            (viaticum_core::constants::FLUSH_IDLE_SECS / scale).max(1),
        ));
        idle_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut fallback_timer = interval(Duration::from_secs(
            (viaticum_core::constants::FLUSH_FALLBACK_SECS / scale).max(1),
        ));
        fallback_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // L1b reconcile (backup-i8, backup-i25): one pass now — its batch waits in the
        // channel until the watcher has checked its roots at start — then by the timer.
        let mut reconcile_timer = interval(Duration::from_secs(
            (viaticum_core::constants::CURRENT_BLOCK_RECONCILE_SECS / scale).max(60),
        ));
        reconcile_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        reconcile_timer.tick().await; // the first tick is immediate: this pass
        tokio::task::block_in_place(|| self.reconcile_pass());

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
                    // Wave 11b: delivery is the worker's job. Wake it now instead of
                    // waiting up to 60s (tick_interval) — also after an error, since
                    // the other categories may have produced blocks (backup-i23).
                    self.notify_work_pipeline();
                    if let Err(e) = flush_result {
                        tracing::error!("idle flush error: {e:#}");
                    }
                    self.persist_cycle_budget();
                }
                _ = fallback_timer.tick() => {
                    tracing::debug!("fallback flush triggered");
                    let auth_snap = self.snapshot_authenticated_peers().await;
                    let flush_result = tokio::task::block_in_place(|| self.flush_all(true, &auth_snap));
                    self.notify_work_pipeline();
                    if let Err(e) = flush_result {
                        tracing::error!("fallback flush error: {e:#}");
                    }
                    self.persist_cycle_budget();
                }
                _ = reconcile_timer.tick() => {
                    tokio::task::block_in_place(|| self.reconcile_pass());
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

    /// Wake the WorkPipeline immediately after a flush creates new DB records.
    /// No-op if work_event_tx not wired (tests).
    fn notify_work_pipeline(&self) {
        if let Some(tx) = &self.config.work_event_tx {
            // try_send: non-blocking. If channel full, worker will pick up on
            // next tick anyway — acceptable degradation.
            let _ = tx.try_send(crate::daemon::work_pipeline::WorkEvent::DirtyFileEnqueued);
        }
    }

    /// Handle a BackupEvent from the Processor.
    ///
    /// Rule "an incoming answer without a request is ignored" (repair-i2, agreed with
    /// line A 2026-09-27): a holder's `SymbolAccept` / `SymbolReject` may only move a
    /// placement that is still `Offered` (the one state in which the owner is waiting
    /// for that answer). In any other state the message is not an answer to anything
    /// we asked: applying it would let a silent holder turn `Uncertain`/`PresumedLost`
    /// into `Alive` without a PoS verdict, or turn a verified `Alive` into `Lost`. Such
    /// messages are ignored and logged at DEBUG.
    fn handle_backup_event(&mut self, event: BackupEvent) {
        use viaticum_core::types::PlacementStatus;
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
                // Update placement status to Alive (confirmed by holder) — only from Offered.
                match self.db.get_placement(&source_block_id, &holder_id) {
                    Ok(Some(mut placement)) => {
                        if placement.status != PlacementStatus::Offered {
                            tracing::debug!(
                                holder = %holder_id,
                                block_id = %source_block_id,
                                status = ?placement.status,
                                "SymbolAccept ignored: placement is not Offered (no request outstanding)"
                            );
                            return;
                        }
                        placement.status = PlacementStatus::Alive;
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
                        self.accepted_this_cycle = self.accepted_this_cycle.saturating_add(1);
                    }
                    Ok(None) => {
                        tracing::debug!(
                            holder = %holder_id,
                            block_id = %source_block_id,
                            "SymbolAccept ignored: no placement (no request outstanding)"
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
                // Mark placement as Lost — triggers repair to find new holder. Only from
                // Offered: a reject cannot un-verify symbols the holder already proved.
                match self.db.get_placement(&source_block_id, &holder_id) {
                    Ok(Some(mut placement)) => {
                        if placement.status != PlacementStatus::Offered {
                            tracing::debug!(
                                holder = %holder_id,
                                block_id = %source_block_id,
                                status = ?placement.status,
                                "SymbolReject ignored: placement is not Offered (no request outstanding)"
                            );
                            return;
                        }
                        placement.status = PlacementStatus::Lost;
                        if let Err(e) = self.db.upsert_placement(&placement) {
                            tracing::error!(
                                error = %e,
                                "failed to update placement after SymbolReject"
                            );
                        }
                    }
                    Ok(None) => {
                        tracing::debug!(
                            holder = %holder_id,
                            block_id = %source_block_id,
                            "SymbolReject ignored: no placement (no request outstanding)"
                        );
                    }
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
        let updated = viaticum_core::budget::record_placement_outcome(
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

/// "Is this content already backed up?" for the flush-time check (backup-i23): a dedup
/// source on a block in service exists. A DB error answers "no" (WARN): the file is then packed — traffic,
/// never a skipped backup.
fn content_in_network(db: &Db, content_hash: &[u8; 32]) -> bool {
    match events::select_dedup_source(db, content_hash, None) {
        // Only content on a serviceable block (backup-i21): a file changed to content that
        // lies only on a block being released is packed (К10).
        Ok(lookup) => matches!(lookup, events::DedupLookup::Source(_)),
        Err(e) => {
            tracing::warn!("flush: dedup lookup failed, packing the file: {e:#}");
            false
        }
    }
}
