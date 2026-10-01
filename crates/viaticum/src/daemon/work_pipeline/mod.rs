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
use crate::daemon::restore::staging::JobId;

mod offer_plan;
mod pool;
mod worker;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_budget;

pub use pool::{PoolSnapshot, pool_signature, snapshot_pool};

// ─── Q-V9: restore or backup first ────────────────────────────────────────────

/// Q-V9 (spec v3.12a): the decision of Ilya, 2026-10-01 — (a), restore first. The value is final;
/// the constant stays so that the pause is one switch and has its mutation (M92).
///
/// `true` (a): while a restore job runs the worker starts no new iteration (`status`: «backup
/// paused while restoring», one INFO line per job); an iteration already running still yields
/// the budget to a waiting restore between two holders (J13). PoS is not affected.
/// `false` (b), kept as the minimal variant behind the switch: the worker works on and gives the
/// budget to a waiting restore at a chunk boundary (after the turn's first attempt, before every
/// next send), then takes it again and re-encodes the rest — restore-i39's bound per block is then
/// the encode of the backup block plus 60 s. Switching is this constant alone; the daemon passes
/// it to `WorkPipelineConfig::restore_pauses_backup`.
pub const RESTORE_PAUSES_BACKUP: bool = true;

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
    /// `RESTORE_PAUSES_BACKUP` (Q-V9): no new iteration while a restore job runs. A field, so the
    /// tests can run both variants; the daemon passes the constant.
    pub restore_pauses_backup: bool,
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
            restore_pauses_backup: RESTORE_PAUSES_BACKUP,
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

/// Forget a block's turn memory: the yield count and the delivery memory of its holders (v3.5a
/// NOTE 3, v3.12 item 5).
fn clear_turn_memory(
    yields: &mut std::collections::HashMap<SourceBlockId, u32>,
    last_attempt: &mut std::collections::HashMap<SourceBlockId, TurnMemory>,
    block_id: SourceBlockId,
) {
    yields.remove(&block_id);
    last_attempt.remove(&block_id);
}

/// The yield counter of one block after a turn, and with it the turn memory of its holders
/// (`last_attempt`; both RAM only, backup-i24-a): a yield counts; a delivery in full starts the
/// count afresh; a block that left service (or was parked: nobody to offer to) without a full
/// delivery loses both — the memory of a block that is no longer served must not live on
/// (spec v3.5a NOTE 3, v3.12 item 5); anything else leaves them.
fn count_yields(
    yields: &mut std::collections::HashMap<SourceBlockId, u32>,
    last_attempt: &mut std::collections::HashMap<SourceBlockId, TurnMemory>,
    block_id: SourceBlockId,
    outcome: &worker::WorkOutcome,
) {
    let delivered_in_full =
        outcome.failed == 0 && outcome.offered > 0 && outcome.acked == outcome.offered;
    if outcome.yielded {
        *yields.entry(block_id).or_insert(0) += 1;
    } else if delivered_in_full || outcome.left_service || outcome.offered == 0 {
        clear_turn_memory(yields, last_attempt, block_id);
    }
    // The turn left no holder in the memory: nothing to keep.
    if last_attempt
        .get(&block_id)
        .is_some_and(|m| m.holders.is_empty())
    {
        last_attempt.remove(&block_id);
    }
}

use worker::TurnMemory;

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
    /// Per block: the turns it has had and, per holder, the turn in which the holder was last
    /// attempted (RAM only; cleared together with `yields`). The next turn goes through the
    /// holders by it, the longest ago first (LRU, backup-i24-a).
    last_attempt: std::collections::HashMap<SourceBlockId, TurnMemory>,
    /// The restore job that runs now, if any (the registry's gate; Q-V9). With
    /// `config.restore_pauses_backup` the worker starts no iteration while it is `Some`.
    restore_gate: Option<tokio::sync::watch::Receiver<Option<JobId>>>,
    /// The job the INFO line «paused while a restore job runs» was written for (once per job).
    pause_announced_for: Option<JobId>,
}

/// Resolves when the restore gate changes; never while there is no gate (or its sender is gone,
/// in which case the gate is dropped: a closed channel must not spin the loop).
async fn restore_gate_changed(
    gate: &mut Option<tokio::sync::watch::Receiver<Option<JobId>>>,
) -> bool {
    match gate {
        Some(rx) => match rx.changed().await {
            Ok(()) => true,
            Err(_) => {
                *gate = None;
                false
            }
        },
        None => std::future::pending().await,
    }
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
            restore_gate: None,
            pause_announced_for: None,
        }
    }

    /// Give the worker the restore gate (`RestoreJobs::running_job_gate`): the job that runs now.
    /// A change wakes the worker, so it starts again when the job ends (Q-V9 (a)).
    pub fn with_restore_gate(mut self, gate: tokio::sync::watch::Receiver<Option<JobId>>) -> Self {
        self.restore_gate = Some(gate);
        self
    }

    /// Q-V9 (a): a restore job runs and the constant says it comes first — no new iteration.
    /// One INFO line per job.
    fn paused_for_restore(&mut self) -> bool {
        if !self.config.restore_pauses_backup {
            return false;
        }
        let Some(job) = self.restore_gate.as_ref().and_then(|g| *g.borrow()) else {
            return false;
        };
        if self.pause_announced_for != Some(job) {
            self.pause_announced_for = Some(job);
            tracing::info!(job = %job, "work_pipeline: paused while a restore job runs");
        }
        true
    }

    /// Forget the turn memory of blocks that left service while nobody looked (v3.12 item 5):
    /// the memory of a block that is no longer served must not live on.
    fn forget_blocks_out_of_service(&mut self) {
        let gone: Vec<SourceBlockId> = self
            .yields
            .keys()
            .chain(self.last_attempt.keys())
            .copied()
            .filter(|b| matches!(self.db.block_serviceability(b), Ok(s) if !s.is_serviceable()))
            .collect();
        for block_id in gone {
            clear_turn_memory(&mut self.yields, &mut self.last_attempt, block_id);
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
        // Its own receiver for the wake-up (the one in `self` is read by `run_iteration`).
        let mut gate = self.restore_gate.clone();

        loop {
            tokio::select! {
                open = restore_gate_changed(&mut gate) => {
                    // A restore job started or ended. Ended: the worker starts again at once
                    // (a started one only makes `run_iteration` say it is paused).
                    if open && let Err(e) = self.run_iteration().await {
                        tracing::error!(error = %e, "work_pipeline: post-restore iteration failed");
                    }
                }
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
        // Q-V9 (a): a restore job runs — the memory is its, the worker starts nothing.
        if self.paused_for_restore() {
            return Ok(false);
        }
        self.forget_blocks_out_of_service();
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
            // A restore job may have started while the previous block was worked.
            if picked_any && self.paused_for_restore() {
                break;
            }
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
            self.park_clearing_memory(block, pool, now, ParkReason::PoolTooSmall);
            return Ok(BlockAttempt::PoolUnusable);
        }

        // Run the actual encode + deliver.
        let swarm = match self.swarm.as_ref() {
            Some(s) => s,
            None => {
                tracing::debug!("work_pipeline: no swarm, parking block");
                self.park_clearing_memory(block, pool, now, ParkReason::NoSwarm);
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
                self.park_clearing_memory(block, pool, now, ParkReason::IterationError);
                Ok(BlockAttempt::Error)
            }
        }
    }

    /// Park a block and forget its turn memory with it (v3.5a NOTE 3).
    fn park_clearing_memory(
        &mut self,
        block: &SourceBlockRecord,
        pool: &PoolSnapshot,
        now: Timestamp,
        reason: ParkReason,
    ) {
        clear_turn_memory(&mut self.yields, &mut self.last_attempt, block.block_id);
        self.update_block_cooldown(block, pool, now, Some(reason));
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
