// WorkPipeline: unified worker for backup delivery and repair.
//
// Wave 11b replaces the two active delivery workers (BackupCoordinator::deliver_symbols
// and RepairAgent::run) with one sequential worker. See spec:
//   docs/archive/beta-planning/tasks/wave11b_unified_worker.md
//
// Module layout:
//   mod.rs      -- WorkPipeline struct, public API, run_loop, reset_all_cooldowns
//   worker.rs   -- run_block_iteration: encode → deliver → cooldown update
//   pool.rs     -- pool snapshot + pool_signature computation
//   tests.rs    -- all ATDD unit tests

use std::sync::{Arc, Mutex};
use std::time::Duration;

use syncback_core::cluster::ClusterState;
use syncback_core::db::Db;
use syncback_core::erasure::ErasureEncoder;
use syncback_core::types::{DeviceId, SourceBlockRecord, SourceBlockStatus, Timestamp};
use tokio::sync::mpsc;

use crate::daemon::network::swarm::SwarmHandle;
use crate::daemon::peer_backoff::PeerBackoff;

mod pool;
mod worker;

#[cfg(test)]
mod tests;

pub use pool::{PoolSnapshot, pool_signature};

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
    /// Epoch key (same as BackupCoordinator uses). For `rebuild_source_blob`.
    pub epoch_key: [u8; 32],
    /// Minimum pool size to attempt delivery. Below this, apply cooldown without encoding.
    /// Default: 2.
    pub min_pool_size: usize,
    /// Time acceleration factor (1 = real time; tests use higher).
    pub time_scale: u64,
}

impl Default for WorkPipelineConfig {
    fn default() -> Self {
        WorkPipelineConfig {
            cooldown: Duration::from_secs(30),
            tick_interval: Duration::from_secs(60),
            completion_bonus_coef: 1.5,
            device_id: DeviceId([0u8; 32]),
            epoch_key: [0u8; 32],
            min_pool_size: 2,
            time_scale: 1,
        }
    }
}

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
                    let _ = self.run_iteration().await;
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
                            let _ = self.run_iteration().await;
                        }
                        Some(WorkEvent::DirtyFileEnqueued) => {
                            tracing::debug!("work_pipeline: dirty file enqueued → wake");
                            let _ = self.run_iteration().await;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Execute one work iteration: pick item, encode, deliver, update cooldown.
    ///
    /// Returns `Ok(true)` if a block was picked and work was attempted.
    /// Returns `Ok(false)` if no block needed work (queue empty or all on cooldown).
    ///
    /// `pub` for testability — called from `run()` and from tests directly.
    pub async fn run_iteration(&mut self) -> anyhow::Result<bool> {
        let now = Timestamp::now();
        // cooldown is already pre-scaled by handle/mod.rs. See note in `run()`.
        let cooldown = self.config.cooldown;

        // Snapshot pool first (needed for pool_sig).
        let pool = pool::snapshot_pool(
            self.swarm.as_deref(),
            &self.db,
            self.peer_backoff.as_deref(),
            &self.config.device_id,
            self.config.min_pool_size,
        )
        .await;

        let block = match self.db.next_work_item(
            self.config.completion_bonus_coef,
            cooldown,
            now,
            pool.signature,
        )? {
            Some(b) => b,
            None => {
                tracing::debug!("work_pipeline: no work item (queue empty or all on cooldown)");
                return Ok(false);
            }
        };

        tracing::info!(
            block_id = %block.block_id,
            importance = block.importance,
            current_alive = block.current_alive,
            current_reliability = block.current_reliability,
            target_reliability = block.target_reliability,
            pool_size = pool.candidates.len(),
            "work_pipeline: picked block for work"
        );

        // Pool too small to make progress — apply cooldown and skip encode.
        if pool.candidates.len() < self.config.min_pool_size {
            tracing::info!(
                pool = pool.candidates.len(),
                min = self.config.min_pool_size,
                "work_pipeline: pool_too_small — applying cooldown, no encode"
            );
            self.update_block_cooldown(&block, &pool, now)?;
            return Ok(true);
        }

        // Run the actual encode + deliver.
        let swarm = match self.swarm.as_ref() {
            Some(s) => s,
            None => {
                tracing::debug!("work_pipeline: no swarm, applying cooldown");
                self.update_block_cooldown(&block, &pool, now)?;
                return Ok(true);
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
            &block,
            &pool,
        )
        .await;

        match outcome {
            Ok(wo) => {
                tracing::info!(
                    block_id = %block.block_id,
                    acked = wo.acked,
                    failed = wo.failed,
                    encoded = wo.encoded,
                    "work_pipeline: iteration complete"
                );
            }
            Err(e) => {
                tracing::error!(
                    block_id = %block.block_id,
                    error = %e,
                    "work_pipeline: iteration error — applying cooldown"
                );
            }
        }

        // Cooldown is always updated (even on error) to prevent tight retry loops.
        self.update_block_cooldown(&block, &pool, now)?;
        Ok(true)
    }

    /// Reset cooldowns on all blocks currently below target reliability.
    ///
    /// Sets `last_pool_signature = 0` (sentinel that bypasses cooldown in
    /// `next_work_item`). Called on `PeerAuthenticated` to force re-evaluation.
    pub(crate) fn reset_all_cooldowns(&self) {
        let blocks = match self.db.list_all_source_blocks() {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("reset_all_cooldowns: list_all_source_blocks failed: {e}");
                return;
            }
        };
        let mut reset_count = 0u32;
        for block in &blocks {
            if block.status != SourceBlockStatus::Active {
                continue;
            }
            if block.current_reliability >= block.target_reliability {
                continue;
            }
            // Set last_pool_signature = 0 to bypass cooldown.
            if let Err(e) = self.db.update_block_cached_fields(
                &block.block_id,
                block.importance,
                block.current_alive,
                block.current_reliability,
                block.target_reliability,
                block.last_attempted_at,
                0, // sentinel: force re-evaluation on next next_work_item call
            ) {
                tracing::error!(
                    block_id = %block.block_id,
                    err = %e,
                    "reset_all_cooldowns: update_block_cached_fields failed"
                );
            } else {
                reset_count += 1;
            }
        }
        tracing::debug!(
            reset = reset_count,
            "work_pipeline: reset_all_cooldowns complete"
        );
    }

    /// Update cooldown fields for a block after an iteration.
    ///
    /// Sets `last_attempted_at = now` and `last_pool_signature = pool.signature`.
    /// This prevents re-encoding the same block with the same pool immediately.
    fn update_block_cooldown(
        &self,
        block: &SourceBlockRecord,
        pool: &PoolSnapshot,
        now: Timestamp,
    ) -> anyhow::Result<()> {
        self.db.update_block_cached_fields(
            &block.block_id,
            block.importance,
            block.current_alive,
            block.current_reliability,
            block.target_reliability,
            Some(now),
            pool.signature,
        )?;
        Ok(())
    }
}
