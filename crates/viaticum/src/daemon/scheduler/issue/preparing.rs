// Block preparations that outlived their tick (pos-i7-d-a), and the overdue ones that wait for
// memory (pos-i13).
//
// A tick waits for a block's preparation only until its deadline. A preparation still
// running then is not dropped: its handle moves here, into a `JoinSet` that the run loop
// drains in its own `select!` arm (like the publishes in `in_flight`), so the loop never
// waits for it and the tick that started it is long over when it ends. The placements of
// a block preparing here are neither started again by a tick nor counted as new starts.
//
// A block the memory budget deferred on tick n is adopted here at tick n + 1 as an OVERDUE
// preparation (`adopt_waiting`): an async wrapper takes one of `MAX_OVERDUE_RUNNING` slots,
// checks the sources by `metadata`, waits for memory with priority (the worker yields to it,
// J13), and only then starts the blocking task with the permit. It does not count in K
// (`MAX_PREPARATIONS`): K bounds the preparations the ticks started.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::{Id, JoinError, JoinHandle, JoinSet};
use tokio::time::Instant;
use tracing::instrument::WithSubscriber;
use tracing::{info, warn};
use viaticum_core::types::{DeviceId, SourceBlockId};

use super::prepare::{
    BlockPrep, Precheck, PrepOutcome, PrepPhase, PrepShared, with_current_dispatch,
};
use crate::daemon::mem_budget::{HolderKind, MemBudget, PriorityKind};

/// Overdue preparations running at once (CPU): their waiting for memory does not count, only
/// the one that holds it and works. The slot is taken BEFORE waiting for memory, so the holders
/// of memory never wait for a slot (no cycle in the wait graph, J12) and the queue for memory
/// carries at most one overdue PoS of its own.
pub(crate) const MAX_OVERDUE_RUNNING: usize = 1;

/// A preparation that ended after its tick: the challenges to publish now.
pub(crate) struct PrepDone {
    pub(in crate::daemon::scheduler) block_id: SourceBlockId,
    /// Challenges per week of each holder, for the issue log line.
    pub(in crate::daemon::scheduler) cpw_of: HashMap<DeviceId, u32>,
    pub(in crate::daemon::scheduler) result: Result<PrepOutcome, JoinError>,
}

/// Who started a preparation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrepKind {
    /// A tick, which cut it at its deadline: counts in K.
    Tick,
    /// The overdue queue: counts in `MAX_OVERDUE_RUNNING` while it runs, nowhere while it waits.
    Overdue,
}

/// What is known of one preparation in flight.
struct Prep {
    block_id: SourceBlockId,
    kind: PrepKind,
    /// Phase, permit handle and start time, shared with the task.
    shared: Arc<PrepShared>,
    /// When it was put here (an overdue one's wait is counted from it).
    queued_at: Instant,
    /// When the stuck-preparation WARN was last logged for it (pos-i7-d-b).
    last_warn: Option<Instant>,
}

/// The preparations in flight past their tick.
pub(crate) struct Preparing {
    set: JoinSet<PrepDone>,
    preps: HashMap<Id, Prep>,
    /// `MAX_OVERDUE_RUNNING` slots of overdue preparations.
    overdue_slots: Arc<Semaphore>,
}

impl Default for Preparing {
    fn default() -> Self {
        Preparing {
            set: JoinSet::new(),
            preps: HashMap::new(),
            overdue_slots: Arc::new(Semaphore::new(MAX_OVERDUE_RUNNING)),
        }
    }
}

impl Preparing {
    pub(super) fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Preparations a tick started that are still running: what K bounds (pos-i7-d-a).
    pub(in crate::daemon::scheduler) fn tick_started(&self) -> usize {
        self.preps
            .values()
            .filter(|p| p.kind == PrepKind::Tick)
            .count()
    }

    /// Preparations working: started by a tick, or an overdue one whose memory was granted.
    pub(in crate::daemon::scheduler) fn running(&self) -> usize {
        self.preps
            .values()
            .filter(|p| p.shared.started().is_some())
            .count()
    }

    /// Overdue preparations still waiting for memory (or for the slot of an overdue one).
    pub(in crate::daemon::scheduler) fn waiting(&self) -> usize {
        self.preps
            .values()
            .filter(|p| p.shared.started().is_none())
            .count()
    }

    /// The blocks preparing or waiting: a tick starts none of them again, for any holder.
    pub(in crate::daemon::scheduler) fn blocks(&self) -> HashSet<SourceBlockId> {
        self.preps.values().map(|p| p.block_id).collect()
    }

    /// Age of the oldest running preparation at `now` (zero when none).
    pub(super) fn oldest_age(&self, now: Instant) -> Duration {
        self.preps
            .values()
            .filter_map(|p| p.shared.started())
            .map(|started| now.saturating_duration_since(started))
            .max()
            .unwrap_or_default()
    }

    /// How long the oldest waiting preparation has waited at `now` (zero when none).
    pub(super) fn oldest_wait(&self, now: Instant) -> Duration {
        self.preps
            .values()
            .filter(|p| p.shared.started().is_none())
            .map(|p| now.saturating_duration_since(p.queued_at))
            .max()
            .unwrap_or_default()
    }

    /// pos-i7-d-b: WARN for each running preparation older than `periods` × `period`, at most
    /// once per `period` for a block; the age is the time it has WORKED (NOTE 6: from its tick's
    /// start, or from the grant of an overdue one's memory — waiting for memory is not hanging).
    /// The WARN names who holds how much and in which phase.
    ///
    /// pos-i7-d-d (variant (a), when `write_off`): a preparation hung in the LOAD phase past the
    /// same age has its permit written off — its bytes go back to the budget while the task
    /// hangs, at most one holder at a time; when the task ends it returns nothing a second time
    /// and its result is published by the usual re-check. The slot is otherwise not freed:
    /// memory matters more than liveness.
    pub(in crate::daemon::scheduler) fn watch_stuck(
        &mut self,
        now: Instant,
        period: Duration,
        periods: u32,
        budget: &MemBudget,
        write_off: bool,
    ) {
        for p in self.preps.values_mut() {
            let Some(started) = p.shared.started() else {
                continue;
            };
            let age = now.saturating_duration_since(started);
            if age < period * periods {
                continue;
            }
            let phase = p.shared.phase();
            if write_off
                && phase == PrepPhase::Load
                && let Some(bytes) = p.shared.write_off(budget)
            {
                warn!(
                    kind = %HolderKind::Pos.as_str(),
                    block = %p.block_id,
                    holds_mib = bytes >> 20,
                    phase = %phase.as_str(),
                    age_s = age.as_secs(),
                    "mem_budget: written off a stuck holder"
                );
            }
            let quiet = p
                .last_warn
                .is_none_or(|w| now.saturating_duration_since(w) >= period);
            if quiet {
                p.last_warn = Some(now);
                warn!(
                    kind = %HolderKind::Pos.as_str(),
                    block = %p.block_id,
                    holds_mib = p.shared.holds_bytes() >> 20,
                    phase = %phase.as_str(),
                    age_s = age.as_secs(),
                    "scheduler: PoS preparation still running"
                );
            }
        }
    }

    /// Adopt a preparation the tick stopped waiting for.
    pub(in crate::daemon::scheduler) fn adopt(
        &mut self,
        block_id: SourceBlockId,
        cpw_of: HashMap<DeviceId, u32>,
        handle: JoinHandle<PrepOutcome>,
        shared: Arc<PrepShared>,
    ) {
        let task = self.set.spawn(async move {
            PrepDone {
                block_id,
                cpw_of,
                result: handle.await,
            }
        });
        self.preps.insert(
            task.id(),
            Prep {
                block_id,
                kind: PrepKind::Tick,
                shared,
                queued_at: Instant::now(),
                last_warn: None,
            },
        );
    }

    /// Adopt a block the budget deferred a tick ago (pos-i13): it waits for a slot of the
    /// overdue ones, checks its sources by `metadata`, waits for memory with priority, then
    /// prepares under the permit it was given. `slow_after`: the wait after which one more INFO
    /// line says it is still waiting.
    pub(super) fn adopt_waiting(
        &mut self,
        block_id: SourceBlockId,
        cpw_of: HashMap<DeviceId, u32>,
        prep: BlockPrep,
        budget: Arc<MemBudget>,
        slow_after: Duration,
    ) {
        let shared = Arc::clone(&prep.state);
        let slots = Arc::clone(&self.overdue_slots);
        let task = self.set.spawn(
            async move {
                PrepDone {
                    block_id,
                    cpw_of,
                    result: run_overdue(prep, budget, slots, slow_after).await,
                }
            }
            .with_current_subscriber(),
        );
        self.preps.insert(
            task.id(),
            Prep {
                block_id,
                kind: PrepKind::Overdue,
                shared,
                queued_at: Instant::now(),
                last_warn: None,
            },
        );
    }

    /// The next preparation to end (None when none is in flight).
    pub(super) async fn join_next(&mut self) -> Option<PrepDone> {
        let done = self.set.join_next_with_id().await?;
        Some(self.forget(done))
    }

    /// Stop waiting for every preparation (shutdown). The blocking tasks themselves run
    /// to their end; nothing is published from them, the placements are due at restart.
    /// An overdue preparation still waiting is cancelled with its wrapper: its place in the
    /// queue for memory and the priority count go with it.
    pub(super) async fn shutdown(&mut self) {
        self.set.abort_all();
        while self.set.join_next().await.is_some() {}
        self.preps.clear();
    }

    fn forget(&mut self, done: Result<(Id, PrepDone), JoinError>) -> PrepDone {
        match done {
            Ok((id, p)) => {
                self.preps.remove(&id);
                p
            }
            // The wrapper only awaits the handle: it fails only when aborted (shutdown) or
            // when the runtime drops it.
            Err(e) => PrepDone {
                block_id: self
                    .preps
                    .remove(&e.id())
                    .map_or(SourceBlockId([0; 32]), |p| p.block_id),
                cpw_of: HashMap::new(),
                result: Err(e),
            },
        }
    }
}

/// The life of an overdue preparation: a slot, the `metadata` precheck (W3, on the blocking
/// pool), the wait for memory as a priority waiter, then the preparation itself under the
/// permit. Holds nothing but the slot while it waits (J12).
async fn run_overdue(
    prep: BlockPrep,
    budget: Arc<MemBudget>,
    slots: Arc<Semaphore>,
    slow_after: Duration,
) -> Result<PrepOutcome, JoinError> {
    let block_id = prep.block_id();
    let state = Arc::clone(&prep.state);
    // The slot is never closed.
    let Ok(_slot) = slots.acquire_owned().await else {
        return Ok(PrepOutcome::Unserved);
    };
    let (prep, check) = tokio::task::spawn_blocking(with_current_dispatch(move || {
        let check = prep.precheck();
        (prep, check)
    }))
    .await?;
    let need_bytes = match check {
        Precheck::Ready { need_bytes } => need_bytes,
        Precheck::Unserved => return Ok(PrepOutcome::Unserved),
    };
    info!(
        block = %block_id,
        need_mib = need_bytes >> 20,
        "pos: overdue, waiting for memory"
    );
    let waited = Instant::now();
    let permit = budget
        .acquire_priority(
            PriorityKind::OverduePos,
            &block_id,
            need_bytes,
            slow_after,
            || {
                info!(
                    block = %block_id,
                    need_mib = need_bytes >> 20,
                    waited_s = waited.elapsed().as_secs(),
                    "pos: overdue, still waiting for memory"
                );
            },
        )
        .await;
    // From here it works: its age for the stuck WARN counts from now, not from the wait.
    state.set_started(Instant::now());
    tokio::task::spawn_blocking(with_current_dispatch(move || prep.run(Some(permit)))).await
}
