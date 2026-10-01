// WorkPipeline: unified worker for backup delivery and repair.
//
// Wave 11b replaces the two active delivery workers (BackupCoordinator::deliver_symbols
// and RepairAgent::run) with one sequential worker. See spec:
//   docs/archive/beta-planning/tasks/wave11b_unified_worker.md
//
// Module layout:
//   mod.rs      -- WorkPipeline struct, public API, run_loop, reset_all_cooldowns
//   worker.rs   -- run_block_iteration: plan → encode → deliver
//   offer_plan/ -- exclude → allocate → ESI ranges per holder (repair-i9) → Offered rows
//   pool.rs     -- pool snapshot + pool_signature computation
//   tests.rs    -- all ATDD unit tests

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use viaticum_core::cluster::ClusterState;
use viaticum_core::db::Db;
use viaticum_core::erasure::ErasureEncoder;
use viaticum_core::types::{DeviceId, SourceBlockId, SourceBlockRecord, Timestamp};

use crate::daemon::mem_budget::MemBudget;
use crate::daemon::network::swarm::SwarmHandle;
use crate::daemon::peer_backoff::PeerBackoff;

mod offer_plan;
mod pool;
mod worker;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_budget;

pub use pool::{PoolSnapshot, pool_signature, snapshot_pool};

// ─── Public types ─────────────────────────────────────────────────────────────

/// Events the worker subscribes to.
#[derive(Debug)]
pub enum WorkEvent {
    /// A peer was authenticated. Reset all block cooldowns, wake immediately.
    PeerAuthenticated { device_id: DeviceId },
    /// New files were enqueued (watcher detected changes). Worker may pick up new blocks.
    DirtyFileEnqueued,
    /// Shutdown signal.
    Shutdown,
}

/// Configuration for WorkPipeline.
#[derive(Clone)]
pub struct WorkPipelineConfig {
    /// Cooldown between work attempts for the same block with the same pool.
    /// Default: 30s. Cold backup philosophy — don't thrash.
    pub cooldown: Duration,
    /// Periodic tick interval when idle (no events).
    /// Default: 60s.
    pub tick_interval: Duration,
    /// Completion bonus coefficient for priority formula.
    /// `priority = importance × (1 + coef × current_alive / n_target)`
    pub completion_bonus_coef: f64,
    /// This device's ID. Used for ESI namespace offset computation.
    pub device_id: DeviceId,
    /// This node's own cluster master pub key. Used to exclude siblings from the placement pool.
    pub own_master_pub_key: viaticum_core::types::IdentityPub,
    /// Epoch key (same as BackupCoordinator uses). For `rebuild_source_blob`.
    pub epoch_key: [u8; 32],
    /// Base data dir (`~/.viaticum`). SystemState blocks have no backing watch-dir
    /// file; their encoded blob is retained under `<data_dir>/system_state/` and
    /// loaded directly for the encode step instead of rebuilding from source files.
    pub data_dir: std::path::PathBuf,
    /// Minimum pool size to attempt delivery. Below this, park the block without encoding.
    /// Default: 2.
    pub min_pool_size: usize,
    /// Where a rebuild reports gone paths (К2b, delete-i12 (в)); the watcher rechecks
    /// them. `None` in tests.
    pub recheck_tx: Option<crate::daemon::backup::rebuild::RecheckTx>,
    /// The size limit of this machine: the rebuild reads no source file above it (J1,
    /// backup-i5). Default: the RaptorQ ceiling; the daemon sets the limit in force.
    pub max_source_bytes: u64,
    /// The block work budget (backup-i24): the worker takes one permit per iteration. The daemon
    /// passes the one shared with the scheduler and restore (`handle`).
    pub mem_budget: Arc<MemBudget>,
    /// Bytes of symbols in one `SymbolTransfer` chunk. The production value is
    /// `SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES`; tests shrink it to get several chunks out of a
    /// small block (the worker yields between chunks).
    pub chunk_budget_bytes: usize,
}

// Only tests build a config this way (`..Default::default()`): the daemon sets every field, and
// no production path is left with an unbounded budget (N2).
#[cfg(test)]
impl Default for WorkPipelineConfig {
    fn default() -> Self {
        WorkPipelineConfig {
            cooldown: Duration::from_secs(30),
            tick_interval: Duration::from_secs(60),
            completion_bonus_coef: 1.5,
            device_id: DeviceId([0u8; 32]),
            own_master_pub_key: viaticum_core::types::IdentityPub([0u8; 32]),
            epoch_key: [0u8; 32],
            data_dir: std::path::PathBuf::new(),
            min_pool_size: 2,
            recheck_tx: None,
            max_source_bytes: viaticum_core::constants::MAX_FILE_SIZE_CEILING_BYTES,
            mem_budget: MemBudget::new(u64::MAX),
            chunk_budget_bytes: viaticum_core::constants::SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES,
        }
    }
}

/// Why a block was parked (nobody could take its symbols).
#[derive(Debug, Clone, Copy)]
enum ParkReason {
    PoolTooSmall,
    NoSwarm,
    NoCandidates,
    IterationError,
    /// The block left service before its offers were written (repair-i16).
    LeftService,
}

impl ParkReason {
    fn as_str(self) -> &'static str {
        match self {
            ParkReason::PoolTooSmall => "pool too small",
            ParkReason::NoSwarm => "no swarm",
            ParkReason::NoCandidates => "no candidates",
            ParkReason::IterationError => "iteration error",
            ParkReason::LeftService => "left service (being released)",
        }
    }
}

/// A parked block waits this many ordinary cooldowns before it is retried with an
/// unchanged pool (production: 120 × 30 s = 1 h). Earlier release: pool change,
/// placement-status change of the block, `PeerAuthenticated` (repair-i4).
const PARKED_COOLDOWN_FACTOR: u32 = 120;

/// At most this many blocks are tried per iteration when the picked ones turn out
/// to have nobody to take symbols (cheap: the source is not read). Bounds the cost
/// of one iteration: each `next_work_item` call scans all source blocks.
const MAX_BLOCKS_PER_ITERATION: usize = 16;

/// What one attempt on one block came to (decides whether the iteration goes on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockAttempt {
    /// Offers were sent (whatever the holders answered).
    Offered,
    /// Nobody to offer to for THIS block; parked; the next block may do better.
    NoCandidates,
    /// Pool too small / no swarm: parked; no other block would do better.
    PoolUnusable,
    /// The iteration failed (e.g. unreadable source); parked.
    Error,
    /// The block left service before its offers were written (repair-i16); parked; the
    /// next block may do better.
    LeftService,
}

/// The yield counter of one block after a turn, and with it the turn memory of its holders
/// (`last_attempt`; both RAM only, backup-i24-a): a yield counts; a delivery in full starts the
/// count afresh; a block that left service (or was parked: nobody to offer to) without a full
/// delivery loses both — the memory of a block that is no longer served must not live on
/// (spec v3.5a NOTE 3); anything else leaves them.
fn count_yields(
    yields: &mut std::collections::HashMap<SourceBlockId, u32>,
    last_attempt: &mut std::collections::HashMap<SourceBlockId, HolderTurns>,
    block_id: SourceBlockId,
    outcome: &worker::WorkOutcome,
) {
    let delivered_in_full =
        outcome.failed == 0 && outcome.offered > 0 && outcome.acked == outcome.offered;
    if outcome.yielded {
        *yields.entry(block_id).or_insert(0) += 1;
    } else if delivered_in_full || outcome.left_service || outcome.offered == 0 {
        yields.remove(&block_id);
        last_attempt.remove(&block_id);
    }
    // The turn entered an empty map for the block; do not keep it.
    if last_attempt
        .get(&block_id)
        .is_some_and(HolderTurns::is_empty)
    {
        last_attempt.remove(&block_id);
    }
}

/// Per holder of one block: the number of the yielded turn in which it was last tried.
type HolderTurns = std::collections::HashMap<DeviceId, u32>;

// ─── WorkPipeline ─────────────────────────────────────────────────────────────

/// The unified work pipeline worker.
///
/// Replaces both `BackupCoordinator::deliver_symbols` and `RepairAgent::run`.
/// Single-tokio-task, inflight=1: at most one block encoded at any time.
pub struct WorkPipeline {
    db: Db,
    config: WorkPipelineConfig,
    encoder: Arc<dyn ErasureEncoder>,
    swarm: Option<Arc<SwarmHandle>>,
    master_signing_key: Option<ed25519_dalek::SigningKey>,
    peer_backoff: Option<Arc<PeerBackoff>>,
    cluster_state: Option<Arc<Mutex<ClusterState>>>,
    event_rx: mpsc::Receiver<WorkEvent>,
    /// How many times the worker gave the budget away on each block since it last delivered the
    /// block in full (RAM only; the `yields_for_block` of the yield line, backup-i24-a).
    yields: std::collections::HashMap<SourceBlockId, u32>,
    /// Per block, per holder: the number of the yielded turn in which the holder was last tried
    /// (RAM only; cleared together with `yields`). The next turn goes through the holders by
    /// it, the longest ago first (LRU, backup-i24-a).
    last_attempt: std::collections::HashMap<SourceBlockId, HolderTurns>,
}

impl WorkPipeline {
    /// Create a new WorkPipeline worker.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Db,
        config: WorkPipelineConfig,
        encoder: Arc<dyn ErasureEncoder>,
        swarm: Option<Arc<SwarmHandle>>,
        master_signing_key: Option<ed25519_dalek::SigningKey>,
        peer_backoff: Option<Arc<PeerBackoff>>,
        cluster_state: Option<Arc<Mutex<ClusterState>>>,
        event_rx: mpsc::Receiver<WorkEvent>,
    ) -> Self {
        WorkPipeline {
            db,
            config,
            encoder,
            swarm,
            master_signing_key,
            peer_backoff,
            cluster_state,
            event_rx,
            yields: std::collections::HashMap::new(),
            last_attempt: std::collections::HashMap::new(),
        }
    }

    /// Main worker loop. Runs until `WorkEvent::Shutdown` or `event_rx` is closed.
    pub async fn run(mut self) -> anyhow::Result<()> {
        // tick_interval is already pre-scaled by handle/mod.rs (it divides 60s by
        // time_scale before passing). Don't divide again — that was the W11b
        // shipping bug: cooldown→0 at extreme time_scale, worker spun unbounded.
        let tick_secs = self.config.tick_interval.as_secs().max(1);
        let mut tick = tokio::time::interval(tokio::time::Duration::from_secs(tick_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tracing::info!("work_pipeline: started (tick={}s)", tick_secs);

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    tracing::debug!("work_pipeline: periodic tick");
                    // CS-SCH-10: surface DbErrors from run_iteration (via next_work_item)
                    // instead of swallowing them. A permanent DB fault otherwise looks like
                    // "worker running, queue empty" with no log trail.
                    if let Err(e) = self.run_iteration().await {
                        tracing::error!(error = %e, "work_pipeline: periodic iteration failed");
                    }
                }
                maybe_event = self.event_rx.recv() => {
                    match maybe_event {
                        None | Some(WorkEvent::Shutdown) => {
                            tracing::info!("work_pipeline: shutdown");
                            break;
                        }
                        Some(WorkEvent::PeerAuthenticated { device_id }) => {
                            tracing::debug!(peer = %device_id, "work_pipeline: peer authenticated → reset cooldowns + wake");
                            self.reset_all_cooldowns();
                            // Drain any additional PeerAuthenticated/DirtyFileEnqueued events
                            // that arrived while we were processing so one encode covers all.
                            loop {
                                match self.event_rx.try_recv() {
                                    Ok(WorkEvent::PeerAuthenticated { .. }) | Ok(WorkEvent::DirtyFileEnqueued) => {}
                                    Ok(WorkEvent::Shutdown) => return Ok(()),
                                    Err(_) => break,
                                }
                            }
                            if let Err(e) = self.run_iteration().await {
                                tracing::error!(error = %e, "work_pipeline: peer-authenticated iteration failed");
                            }
                        }
                        Some(WorkEvent::DirtyFileEnqueued) => {
                            tracing::debug!("work_pipeline: dirty file enqueued → wake");
                            if let Err(e) = self.run_iteration().await {
                                tracing::error!(error = %e, "work_pipeline: dirty-file iteration failed");
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Execute one work iteration: pick item, encode, deliver, update cooldown.
    ///
    /// If the picked block's outcome is "nobody to take symbols" (no candidate after
    /// exclusions / empty allocation — cheap, the source is not read), the block is
    /// parked and the iteration moves on to the next eligible block, at most
    /// `MAX_BLOCKS_PER_ITERATION` blocks (repair-i4, backup-i12): one stuck block must
    /// not hold the queue for a whole tick.
    ///
    /// Returns `Ok(true)` if at least one block was picked and work was attempted.
    /// Returns `Ok(false)` if no block needed work (queue empty or all on cooldown).
    ///
    /// `pub` for testability — called from `run()` and from tests directly.
    pub async fn run_iteration(&mut self) -> anyhow::Result<bool> {
        let now = Timestamp::now();
        // cooldown is already pre-scaled by handle/mod.rs. See note in `run()`.
        let cooldown = self.config.cooldown;
        let parked_cooldown = cooldown.saturating_mul(PARKED_COOLDOWN_FACTOR);

        // Snapshot pool first (needed for pool_sig).
        let pool = pool::snapshot_pool(
            self.swarm.as_deref(),
            &self.db,
            self.peer_backoff.as_deref(),
            &self.config.device_id,
            &self.config.own_master_pub_key,
            self.config.min_pool_size,
        )
        .await;

        let mut picked_any = false;
        let mut tried: std::collections::HashSet<SourceBlockId> = std::collections::HashSet::new();
        for _ in 0..MAX_BLOCKS_PER_ITERATION {
            let block = match self.db.next_work_item(
                self.config.completion_bonus_coef,
                cooldown,
                parked_cooldown,
                now,
                pool.signature,
            )? {
                Some(b) => b,
                None => {
                    if !picked_any {
                        tracing::debug!(
                            "work_pipeline: no work item (queue empty or all on cooldown)"
                        );
                    }
                    break;
                }
            };
            // With pool signature 0 `next_work_item` ignores cooldowns and would hand the
            // same block back; never work one block twice in an iteration.
            if !tried.insert(block.block_id) {
                break;
            }
            picked_any = true;

            let attempt = self.work_on_block(&block, &pool, now).await?;
            if !matches!(
                attempt,
                BlockAttempt::NoCandidates | BlockAttempt::LeftService
            ) {
                break;
            }
        }
        Ok(picked_any)
    }

    /// One attempt on one block: log the pick, run the encode+deliver cycle, record
    /// the cooldown (parked when nobody could take symbols).
    async fn work_on_block(
        &mut self,
        block: &SourceBlockRecord,
        pool: &PoolSnapshot,
        now: Timestamp,
    ) -> anyhow::Result<BlockAttempt> {
        tracing::info!(
            block_id = %block.block_id,
            importance = block.importance,
            current_alive = block.current_alive,
            current_reliability = block.current_reliability,
            target_reliability = block.target_reliability,
            pool_size = pool.candidates.len(),
            "work_pipeline: picked block for work"
        );

        // Pool too small to make progress — park and skip encode. A pool-wide
        // condition: the iteration stops (every other block would get the same answer).
        if pool.candidates.len() < self.config.min_pool_size {
            tracing::info!(
                pool = pool.candidates.len(),
                min = self.config.min_pool_size,
                "work_pipeline: pool_too_small — parking block, no encode"
            );
            self.update_block_cooldown(block, pool, now, Some(ParkReason::PoolTooSmall));
            return Ok(BlockAttempt::PoolUnusable);
        }

        // Run the actual encode + deliver.
        let swarm = match self.swarm.as_ref() {
            Some(s) => s,
            None => {
                tracing::debug!("work_pipeline: no swarm, parking block");
                self.update_block_cooldown(block, pool, now, Some(ParkReason::NoSwarm));
                return Ok(BlockAttempt::PoolUnusable);
            }
        };

        let outcome = worker::run_block_iteration(
            &self.db,
            &self.config,
            &self.encoder,
            swarm,
            self.master_signing_key.as_ref(),
            self.peer_backoff.as_deref(),
            self.cluster_state.as_ref(),
            block,
            pool,
            self.yields.get(&block.block_id).copied().unwrap_or(0),
            self.last_attempt.entry(block.block_id).or_default(),
        )
        .await;

        // Cooldown is always updated (even on error) to prevent tight retry loops.
        match outcome {
            Ok(wo) => {
                tracing::info!(
                    block_id = %block.block_id,
                    acked = wo.acked,
                    failed = wo.failed,
                    encoded = wo.encoded,
                    offered = wo.offered,
                    yielded = wo.yielded,
                    "work_pipeline: iteration complete"
                );
                count_yields(
                    &mut self.yields,
                    &mut self.last_attempt,
                    block.block_id,
                    &wo,
                );
                if wo.left_service {
                    self.update_block_cooldown(block, pool, now, Some(ParkReason::LeftService));
                    Ok(BlockAttempt::LeftService)
                } else if wo.offered > 0 {
                    // Offers went out (accepted or not): retry after the normal
                    // cooldown — a network failure is not "nobody can take it".
                    self.update_block_cooldown(block, pool, now, None);
                    Ok(BlockAttempt::Offered)
                } else {
                    self.update_block_cooldown(block, pool, now, Some(ParkReason::NoCandidates));
                    Ok(BlockAttempt::NoCandidates)
                }
            }
            Err(e) => {
                // E.g. the source is unreadable (unplugged external disk): retrying
                // every cooldown only burns CPU and log lines — park it (W3).
                tracing::error!(
                    block_id = %block.block_id,
                    error = %e,
                    "work_pipeline: iteration error — parking block"
                );
                if self
                    .last_attempt
                    .get(&block.block_id)
                    .is_some_and(HolderTurns::is_empty)
                {
                    self.last_attempt.remove(&block.block_id);
                }
                self.update_block_cooldown(block, pool, now, Some(ParkReason::IterationError));
                Ok(BlockAttempt::Error)
            }
        }
    }

    /// Reset cooldowns on all blocks. Called on `PeerAuthenticated` to force
    /// re-evaluation: with the cooldown map cleared, every below-target block is
    /// immediately eligible again in `next_work_item`. RAM-only, no disk writes (B-4).
    pub(crate) fn reset_all_cooldowns(&self) {
        self.db.clear_all_block_cooldowns();
        tracing::debug!("work_pipeline: reset_all_cooldowns complete");
    }

    /// Update cooldown fields for a block after an iteration.
    ///
    /// Sets `last_attempted_at = now` and `last_pool_signature = pool.signature`.
    /// This prevents re-encoding the same block with the same pool immediately.
    /// `park_reason = Some(..)` parks the block (nobody could take its symbols):
    /// it stays out of the queue until the pool or a placement status of the block
    /// changes, cooldowns are reset (`PeerAuthenticated`), or `PARKED_COOLDOWN_FACTOR`
    /// cooldowns elapse (repair-i4).
    fn update_block_cooldown(
        &self,
        block: &SourceBlockRecord,
        pool: &PoolSnapshot,
        now: Timestamp,
        park_reason: Option<ParkReason>,
    ) {
        match park_reason {
            // Pool-wide: a lone node would log this every tick.
            Some(reason @ (ParkReason::PoolTooSmall | ParkReason::NoSwarm)) => tracing::debug!(
                block_id = %block.block_id,
                reason = reason.as_str(),
                "work_pipeline: block parked (nobody can take symbols)"
            ),
            Some(reason @ ParkReason::LeftService) => tracing::info!(
                block_id = %block.block_id,
                reason = reason.as_str(),
                "work_pipeline: block parked (left service before the offers)"
            ),
            Some(reason) => tracing::info!(
                block_id = %block.block_id,
                reason = reason.as_str(),
                "work_pipeline: block parked (nobody can take symbols)"
            ),
            None => {}
        }
        // B-4: cooldown is RAM-only — no disk write per attempt.
        self.db.set_block_cooldown(
            &block.block_id,
            Some(now),
            pool.signature,
            park_reason.is_some(),
        );
    }
}
