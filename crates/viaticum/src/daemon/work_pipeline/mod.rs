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
use crate::daemon::system_state::strength::{block_strength, ss_blocks_awaiting_retirement};

mod esi_space;
mod gate;
mod offer_plan;
mod pool;
mod worker;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_budget;
#[cfg(test)]
mod tests_ss_fairness;
#[cfg(test)]
mod tests_ss_order;

pub use esi_space::EsiSpace;
pub use gate::{
    BACKUP_PAUSE_WARN_AFTER, GateWake, PauseWatch, RestoreGate, new_gate_wake, notify_gate,
    restore_gate,
};
pub use pool::{PoolSnapshot, pool_signature, snapshot_pool};

// ─── Q-V9: restore or backup first ────────────────────────────────────────────

/// Q-V9 (spec v3.12a): the decision of Ilya, 2026-10-01 — (a), restore first. The value is final;
/// the constant stays so that the pause is one switch and has its mutation (M92).
///
/// `true` (a): while the gate is up (an unfinished restore job, or a DR session, spec v3.12b) the
/// worker starts no new iteration (`status`: «backup paused while restoring», one INFO line per
/// pause); an iteration already running sees the gate too (it is in its `Turn`): it gives the
/// permit back right after it got it, before the rebuild and the encode, and in the delivery it
/// stops at the chunk boundary after its first attempt. PoS is not affected.
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
    /// Blocks out of ESI numbers (repair-i8 ceiling), shared with `status`.
    pub esi_space: Arc<EsiSpace>,
    /// The block work budget (backup-i24): the worker takes one permit per iteration. The daemon
    /// passes the one shared with the scheduler and restore (`handle`).
    pub mem_budget: Arc<MemBudget>,
    /// Bytes of symbols in one `SymbolTransfer` chunk. The production value is
    /// `SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES`; tests shrink it to get several chunks out of a
    /// small block (the worker yields between chunks).
    pub chunk_budget_bytes: usize,
    /// `RESTORE_PAUSES_BACKUP` (Q-V9): no new iteration, and the running one stops, while the
    /// restore gate is up. A field, so the tests can run both variants; the daemon passes the
    /// constant.
    pub restore_pauses_backup: bool,
    /// The daemon's time scale (1 in production). Only for the strength of SS blocks
    /// (backup-i28-b): a holder counts while seen within `7 days / time_scale`.
    pub time_scale: u64,
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
            esi_space: Arc::default(),
            mem_budget: MemBudget::new(u64::MAX),
            chunk_budget_bytes: viaticum_core::constants::SYMBOL_TRANSFER_CHUNK_BUDGET_BYTES,
            restore_pauses_backup: RESTORE_PAUSES_BACKUP,
            time_scale: 1,
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
    /// The turn stopped before it offered anything: the restore gate went up while it waited for
    /// its permit or while it encoded (spec v3.12b WARN-1). Not parked, no cooldown: the block is picked again when
    /// the gate comes down; the iteration ends.
    Paused,
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
    /// The restore gate (Q-V9, spec v3.12b): an unfinished restore job or a DR session, computed
    /// from their state at every reading. With `config.restore_pauses_backup` the worker starts
    /// no iteration while it is up, and a running turn stops at its boundaries.
    restore_gate: Option<RestoreGate>,
    /// The INFO line «paused» was written for the pause that is on now (once per pause).
    pause_announced: bool,
    /// The last attempt that sent offers was on a SystemState block (backup-i28): while a user
    /// block waits, the next attempt is a user block's. An attempt without offers does not
    /// change it (backup-i28-e). RAM only.
    last_was_ss: bool,
}

/// Resolves when a source of the restore gate changed; never while there is no gate (or its
/// sender is gone, in which case the gate is dropped: a closed channel must not spin the loop).
async fn restore_gate_changed(gate: &mut Option<tokio::sync::watch::Receiver<u64>>) -> bool {
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
            pause_announced: false,
            last_was_ss: false,
        }
    }

    /// Give the worker the restore gate. A change of its sources wakes the worker, so it starts
    /// again when the last job ends or the DR session runs out (Q-V9 (a)).
    pub fn with_restore_gate(mut self, gate: RestoreGate) -> Self {
        self.restore_gate = Some(gate);
        self
    }

    /// The gate for a running turn: `Some` only when the constant says restore comes first.
    fn turn_gate(&self) -> Option<&RestoreGate> {
        self.restore_gate
            .as_ref()
            .filter(|_| self.config.restore_pauses_backup)
    }

    /// Q-V9 (a): the gate is up and the constant says restore comes first — no new iteration.
    /// One INFO line per pause.
    fn paused_for_restore(&mut self) -> bool {
        let Some(gate) = self.turn_gate().filter(|g| g.is_up()) else {
            self.pause_announced = false;
            return false;
        };
        if let Some(held) = gate.take_overlong_warning() {
            tracing::warn!(
                paused_for_h = held.as_secs() / 3600,
                "work_pipeline: the backup has been paused for over {} h — a restore job or a DR \
                 session still holds the gate (a restore job whose coordinator died holds it \
                 until the node restarts)",
                BACKUP_PAUSE_WARN_AFTER.as_secs() / 3600
            );
        }
        if !self.pause_announced {
            self.pause_announced = true;
            tracing::info!(
                "work_pipeline: paused while a restore job runs or a DR session leases memory"
            );
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
        let mut gate = self.restore_gate.as_ref().map(RestoreGate::subscribe);

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
            let block = match self.next_block(cooldown, parked_cooldown, now, pool.signature)? {
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

            // backup-i28: the class of the picked block, from the SS ledger (the record and its
            // ledger entry are written in one transaction, backup-i28-c).
            let ss = self.db.is_ss_block(&block.block_id)?;
            let attempt = self.work_on_block(&block, ss, &pool, now).await?;
            self.end_turn(ss, attempt);
            if !matches!(
                attempt,
                BlockAttempt::NoCandidates | BlockAttempt::LeftService
            ) {
                break;
            }
        }
        Ok(picked_any)
    }

    /// The block of the next attempt (backup-i28). The service blocks of SystemState and the
    /// user's blocks share the worker. (a) After an attempt with offers on an SS block
    /// (backup-i28-e), a user block that waits goes next. (b) Else the oldest SS block that is
    /// not yet restorable (strength < 1) goes first, so the DR catalog catches up: what was
    /// published is finished before what is new (backup-i28-b); a block displaced out of its
    /// place and waiting to be retired (`to_retire`) is not in (b) (backup-i28-d). (c) Else the
    /// plain order of `next_work_item` (re-picks of restorable SS blocks among the rest, by
    /// priority). "SS" is the SS ledger, not importance. (b) reads the ledger, META and the few
    /// SS records one by one; (a) and (c) scan every block, so a pick costs at most two scans.
    fn next_block(
        &self,
        cooldown: std::time::Duration,
        parked_cooldown: std::time::Duration,
        now: Timestamp,
        pool_sig: u64,
    ) -> Result<Option<SourceBlockRecord>, viaticum_core::db::DbError> {
        let coef = self.config.completion_bonus_coef;
        let ss = self.db.list_ss_blocks()?;
        let ss_ids: std::collections::HashSet<[u8; 32]> = ss.iter().map(|(id, _)| id.0).collect();
        let pick = |keep: &dyn Fn(&SourceBlockRecord) -> bool| {
            self.db
                .next_work_item_where(coef, cooldown, parked_cooldown, now, pool_sig, keep)
        };
        if self.last_was_ss
            && let Some(user) = pick(&|b| !ss_ids.contains(&b.block_id.0))?
        {
            return Ok(Some(user));
        }
        if let Some(weak) =
            self.oldest_unrestorable_ss(&ss, cooldown, parked_cooldown, now, pool_sig)?
        {
            return Ok(Some(weak));
        }
        pick(&|_| true)
    }

    /// backup-i28-b: among the SS blocks of the ledger that may be worked now (the eligibility
    /// of `next_work_item`), the oldest one whose strength is below 1 — not restorable by the
    /// owner's estimate (`strength::block_strength`, the DR readiness estimator, dr-i49).
    /// Oldest by the record's `created_at`, then the ledger generation, then the id. Not by the
    /// generation first: it restarts at 1 with every process, while a pointer place may still
    /// refer to the blocks of an earlier process (dr-i48). The membership does not depend on the
    /// RAM cooldown: a cooldown reset (`PeerAuthenticated`, restart) changes only eligibility, as
    /// in the plain order (review W2). backup-i28-d: a block of a pointer's `to_retire`
    /// (displaced out of its place, retired once the replacement reaches the threshold; DR
    /// readiness does not count it) is left to the plain order (c).
    fn oldest_unrestorable_ss(
        &self,
        ss: &[(SourceBlockId, u32)],
        cooldown: std::time::Duration,
        parked_cooldown: std::time::Duration,
        now: Timestamp,
        pool_sig: u64,
    ) -> Result<Option<SourceBlockRecord>, viaticum_core::db::DbError> {
        let eligible_now = |r: &SourceBlockRecord| {
            self.db
                .work_item_eligible(r, cooldown, parked_cooldown, now, pool_sig)
        };
        let meta = self.db.pointer_publications()?;
        let displaced = ss_blocks_awaiting_retirement(meta.as_ref());
        let mut eligible: Vec<(SourceBlockRecord, u32)> = Vec::new();
        for (id, generation) in ss {
            if displaced.contains(id) {
                continue;
            }
            let Some(record) = self.db.get_source_block(id)? else {
                continue;
            };
            if eligible_now(&record) {
                eligible.push((record, *generation));
            }
        }
        eligible.sort_by_key(|(r, g)| (r.created_at, *g, r.block_id.0));
        let ts = self.config.time_scale;
        for (record, _) in eligible {
            if block_strength(&self.db, &record.block_id, now.0, ts)? < 1.0 {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// One attempt on one block: log the pick, run the encode+deliver cycle, record
    /// the cooldown (parked when nobody could take symbols).
    async fn work_on_block(
        &mut self,
        block: &SourceBlockRecord,
        ss: bool,
        pool: &PoolSnapshot,
        now: Timestamp,
    ) -> anyhow::Result<BlockAttempt> {
        tracing::info!(
            block_id = %block.block_id,
            ss,
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
            self.restore_gate
                .as_ref()
                .filter(|_| self.config.restore_pauses_backup),
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
                } else if wo.yielded && wo.offered == 0 {
                    // Stopped by the gate before any offer (before the encode, or after it: the
                    // job started while the encoder ran): nothing was tried, nothing parked.
                    Ok(BlockAttempt::Paused)
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

    /// backup-i28-e/-f/-g: the turn passes with an attempt that sent offers, and with one that
    /// failed on its block (`Error`, `LeftService`): in every such case the next attempt goes to
    /// the other class (`last_was_ss = ss`). Without the second, a broken block of one class,
    /// un-parked by `reset_all_cooldowns` before every iteration, would keep the turn from the
    /// other class for good. An attempt that took nothing from anyone (nobody to offer to, the
    /// pool unusable, a pause of the restore gate) leaves the turn where it was.
    fn end_turn(&mut self, ss: bool, attempt: BlockAttempt) {
        match attempt {
            BlockAttempt::Offered | BlockAttempt::Error | BlockAttempt::LeftService => {
                self.last_was_ss = ss;
            }
            BlockAttempt::NoCandidates | BlockAttempt::PoolUnusable | BlockAttempt::Paused => {}
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
