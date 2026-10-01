// Block preparations that outlived their tick (pos-i7-d-a), and the batch of overdue ones that
// waits for memory (pos-i13, spec v3.7 / v3.7a).
//
// A tick waits for a block's preparation only until its deadline. A preparation still
// running then is not dropped: its handle moves here, into a `JoinSet` that the run loop
// drains in its own `select!` arm (like the publishes in `in_flight`), so the loop never
// waits for it and the tick that started it is long over when it ends. The placements of
// a block preparing here are neither started again by a tick nor counted as new starts.
//
// Blocks the memory budget deferred (marked on tick n) are prepared from tick n + 1 by ONE batch
// (`adopt_batch`): one wait for memory, sized by the largest member; the members one after the
// other in one blocking task, the permit shrunk to what the rest needs after each; the batch ends
// at half a period of work, at 0.9 of a period from its tick's start (a member is never started
// past it, the first always is), when a restore that does not fit beside it waits, or when it is
// written off; the permit is gone before anything is published. Members are excluded from the
// ticks while the batch holds them; the ones not started go back to the marks. The batch does not
// count in K (`MAX_PREPARATIONS`): K bounds the preparations the ticks started.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use tokio::task::{Id, JoinError, JoinHandle, JoinSet};
use tokio::time::Instant;
use tracing::instrument::WithSubscriber;
use tracing::{info, warn};
use viaticum_core::types::{DeviceId, SourceBlockId};

use super::prepare::{
    BlockPrep, Hashed, Member, PrepOutcome, PrepPhase, PrepShared, with_current_dispatch,
};
use crate::daemon::mem_budget::{HolderKind, MemBudget, MemPermit, PriorityKind};
use crate::daemon::scheduler::BatchClock;

/// A preparation that ended: the challenges to publish now.
pub(crate) struct PrepDone {
    pub(in crate::daemon::scheduler) block_id: SourceBlockId,
    /// Challenges per week of each holder, for the issue log line.
    pub(in crate::daemon::scheduler) cpw_of: HashMap<DeviceId, u32>,
    pub(in crate::daemon::scheduler) result: Result<PrepOutcome, anyhow::Error>,
}

/// What ends in the set: one preparation a tick cut, or a whole batch (its members' results,
/// published one after the other once the batch has given its permit back).
pub(crate) enum Done {
    One(PrepDone),
    Batch(Vec<PrepDone>),
}

/// What a batch is allowed (spec v3.7a WARN-A): the period `P` of the tick (scaled), the clock
/// (injected in tests) and the moment its tick started.
#[derive(Clone)]
pub(super) struct BatchPlan {
    pub(super) period: Duration,
    pub(super) tick_start: StdInstant,
    pub(super) clock: BatchClock,
    /// The wait for memory after which one more INFO line says the batch is still waiting.
    pub(super) slow_after: Duration,
}

/// Which members of a batch the ticks must leave alone, and whether the batch may start more.
#[derive(Default)]
pub(in crate::daemon::scheduler) struct BatchShared {
    inner: Mutex<BatchInner>,
}

#[derive(Default)]
struct BatchInner {
    /// Not started: `false`; started (its result comes with the batch's end): `true`.
    members: HashMap<SourceBlockId, bool>,
    /// A write-off or the end of the batch: no member starts any more.
    stopped: bool,
    /// The member that works now (the stuck-preparation WARN names it).
    current: Option<SourceBlockId>,
}

impl BatchShared {
    fn new(blocks: impl IntoIterator<Item = SourceBlockId>) -> Self {
        BatchShared {
            inner: Mutex::new(BatchInner {
                members: blocks.into_iter().map(|b| (b, false)).collect(),
                ..BatchInner::default()
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BatchInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The members the batch holds now (excluded from the ticks).
    pub(in crate::daemon::scheduler) fn blocks(&self) -> Vec<SourceBlockId> {
        self.lock().members.keys().copied().collect()
    }

    pub(in crate::daemon::scheduler) fn len(&self) -> usize {
        self.lock().members.len()
    }

    /// The member `block` starts now. `false`: the batch is stopped (written off), nothing starts.
    pub(in crate::daemon::scheduler) fn try_start(&self, block: &SourceBlockId) -> bool {
        let mut inner = self.lock();
        if inner.stopped {
            return false;
        }
        if let Some(started) = inner.members.get_mut(block) {
            *started = true;
        }
        inner.current = Some(*block);
        true
    }

    /// A member that is not started goes back to the marks: the ticks may take it again.
    pub(in crate::daemon::scheduler) fn give_back(&self, block: &SourceBlockId) {
        let mut inner = self.lock();
        if inner.members.get(block) == Some(&false) {
            inner.members.remove(block);
        }
    }

    pub(in crate::daemon::scheduler) fn is_stopped(&self) -> bool {
        self.lock().stopped
    }

    /// No member starts from now on, and the ones not started go back at once (written off: the
    /// task hangs in a member, it cannot give them back itself).
    pub(in crate::daemon::scheduler) fn stop(&self) {
        let mut inner = self.lock();
        inner.stopped = true;
        inner.members.retain(|_, started| *started);
    }

    fn current(&self) -> Option<SourceBlockId> {
        self.lock().current
    }
}

/// Who started a preparation.
#[derive(Clone)]
enum PrepKind {
    /// A tick, which cut it at its deadline: counts in K.
    Tick(SourceBlockId),
    /// The batch of overdue ones: counts nowhere in K; at most one in flight.
    Batch(Arc<BatchShared>),
}

/// What is known of one preparation in flight.
struct Prep {
    kind: PrepKind,
    /// Phase, permit handle and start time, shared with the task.
    shared: Arc<PrepShared>,
    /// When it was put here (a batch's wait is counted from it).
    queued_at: Instant,
    /// When the stuck-preparation WARN was last logged for it (pos-i7-d-b).
    last_warn: Option<Instant>,
}

impl Prep {
    fn blocks(&self) -> Vec<SourceBlockId> {
        match &self.kind {
            PrepKind::Tick(b) => vec![*b],
            PrepKind::Batch(batch) => batch.blocks(),
        }
    }
}

/// The preparations in flight past their tick.
#[derive(Default)]
pub(crate) struct Preparing {
    set: JoinSet<Done>,
    preps: HashMap<Id, Prep>,
}

impl Preparing {
    pub(super) fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Preparations a tick started that are still running: what K bounds (pos-i7-d-a).
    pub(in crate::daemon::scheduler) fn tick_started(&self) -> usize {
        self.preps
            .values()
            .filter(|p| matches!(p.kind, PrepKind::Tick(_)))
            .count()
    }

    /// Preparations working: started by a tick, or a batch whose memory was granted.
    pub(in crate::daemon::scheduler) fn running(&self) -> usize {
        self.preps
            .values()
            .filter(|p| p.shared.started().is_some())
            .count()
    }

    /// Batches still waiting for memory (at most one).
    pub(in crate::daemon::scheduler) fn waiting(&self) -> usize {
        self.preps
            .values()
            .filter(|p| p.shared.started().is_none())
            .count()
    }

    /// Members of the batch in flight (zero when there is none).
    pub(in crate::daemon::scheduler) fn batch_members(&self) -> usize {
        self.preps
            .values()
            .map(|p| match &p.kind {
                PrepKind::Batch(batch) => batch.len(),
                PrepKind::Tick(_) => 0,
            })
            .sum()
    }

    /// Whether a batch is in flight: it waits or works, and has not been written off (a written-off
    /// one no longer holds the place, spec v3.7 WARN-1).
    pub(in crate::daemon::scheduler) fn batch_in_flight(&self) -> bool {
        self.preps
            .values()
            .any(|p| matches!(p.kind, PrepKind::Batch(_)) && p.shared.counts_in_flight())
    }

    /// The blocks preparing, waiting or held by a batch: a tick starts none of them again, for
    /// any holder.
    pub(in crate::daemon::scheduler) fn blocks(&self) -> HashSet<SourceBlockId> {
        self.preps.values().flat_map(Prep::blocks).collect()
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
    /// start, or from the grant of a batch's memory / the start of its member — waiting for memory
    /// is not hanging). The WARN names who holds how much and in which phase.
    ///
    /// pos-i7-d-d (variant (a), when `write_off`): a preparation hung in the LOAD phase for at
    /// least `max(periods × period, write_off_floor)` has its permit written off — its bytes go
    /// back to the budget while the task hangs, at most one holder at a time (WARN-4 v3.6: the
    /// floor is real time, so a time-scaled rig does not write off a load that is merely slow);
    /// when the task ends it returns nothing a second time and its result is published by the
    /// usual re-check. A written-off batch stops starting members (the ones not started go back
    /// to the marks at once) and no longer holds the place of the batch in flight.
    pub(in crate::daemon::scheduler) fn watch_stuck(
        &mut self,
        now: Instant,
        period: Duration,
        periods: u32,
        write_off_floor: Duration,
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
            let block = match &p.kind {
                PrepKind::Tick(b) => Some(*b),
                PrepKind::Batch(batch) => batch.current(),
            }
            .unwrap_or(SourceBlockId([0; 32]));
            let phase = p.shared.phase();
            if write_off
                && phase == PrepPhase::Load
                && age >= (period * periods).max(write_off_floor)
                && let Some(bytes) = p.shared.write_off(budget)
            {
                if let PrepKind::Batch(batch) = &p.kind {
                    batch.stop();
                }
                warn!(
                    kind = %HolderKind::Pos.as_str(),
                    block = %block,
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
                    block = %block,
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
            Done::One(PrepDone {
                block_id,
                cpw_of,
                result: handle.await.map_err(anyhow::Error::from),
            })
        });
        self.preps.insert(
            task.id(),
            Prep {
                kind: PrepKind::Tick(block_id),
                shared,
                queued_at: Instant::now(),
                last_warn: None,
            },
        );
    }

    /// Adopt the blocks the budget deferred on an earlier tick (pos-i13) as ONE batch: it waits
    /// for memory with priority once, sized by its largest member, then prepares the members one
    /// after the other under that permit. The caller checks that no batch is in flight.
    pub(super) fn adopt_batch(
        &mut self,
        members: Vec<(BlockPrep, HashMap<DeviceId, u32>)>,
        budget: Arc<MemBudget>,
        plan: BatchPlan,
    ) {
        let batch = Arc::new(BatchShared::new(members.iter().map(|(p, _)| p.block_id())));
        let shared = PrepShared::new(None);
        let (task_batch, task_shared) = (Arc::clone(&batch), Arc::clone(&shared));
        let task =
            self.set.spawn(
                async move {
                    Done::Batch(run_batch(members, budget, task_batch, task_shared, plan).await)
                }
                .with_current_subscriber(),
            );
        self.preps.insert(
            task.id(),
            Prep {
                kind: PrepKind::Batch(batch),
                shared,
                queued_at: Instant::now(),
                last_warn: None,
            },
        );
    }

    /// The next preparation to end (None when none is in flight).
    pub(super) async fn join_next(&mut self) -> Option<Done> {
        let done = self.set.join_next_with_id().await?;
        Some(self.forget(done))
    }

    /// Stop waiting for every preparation (shutdown). The blocking tasks themselves run
    /// to their end; nothing is published from them, the placements are due at restart.
    /// A batch still waiting is cancelled with its wrapper: its place in the queue for memory and
    /// the priority count go with it.
    pub(super) async fn shutdown(&mut self) {
        self.set.abort_all();
        while self.set.join_next().await.is_some() {}
        self.preps.clear();
    }

    fn forget(&mut self, done: Result<(Id, Done), JoinError>) -> Done {
        match done {
            Ok((id, d)) => {
                self.preps.remove(&id);
                d
            }
            // A wrapper only awaits its handle or the batch's steps: it fails when aborted
            // (shutdown), when the runtime drops it, or when it panics.
            Err(e) => {
                let blocks = self
                    .preps
                    .remove(&e.id())
                    .map(|p| p.blocks())
                    .unwrap_or_default();
                let mut failed: Vec<PrepDone> = blocks
                    .into_iter()
                    .map(|block_id| PrepDone {
                        block_id,
                        cpw_of: HashMap::new(),
                        result: Err(anyhow::anyhow!("{e}")),
                    })
                    .collect();
                if failed.len() == 1 {
                    Done::One(failed.remove(0))
                } else {
                    Done::Batch(failed)
                }
            }
        }
    }
}

/// The results of a batch whose blocking steps failed (a panic or a cancelled task): every member
/// is reported failed, so its mark and its place are cleared and it waits one period.
fn all_failed(ids: Vec<SourceBlockId>, e: &JoinError) -> Vec<PrepDone> {
    ids.into_iter()
        .map(|block_id| PrepDone {
            block_id,
            cpw_of: HashMap::new(),
            result: Err(anyhow::anyhow!("{e}")),
        })
        .collect()
}

/// The life of a batch: its members' records and needs (blocking), ONE wait for memory as a
/// priority waiter sized by the largest need, then the members (blocking). Holds nothing while it
/// waits (J12).
async fn run_batch(
    members: Vec<(BlockPrep, HashMap<DeviceId, u32>)>,
    budget: Arc<MemBudget>,
    batch: Arc<BatchShared>,
    state: Arc<PrepShared>,
    plan: BatchPlan,
) -> Vec<PrepDone> {
    let ids: Vec<SourceBlockId> = members.iter().map(|(p, _)| p.block_id()).collect();
    let first = tokio::task::spawn_blocking(with_current_dispatch(move || {
        let mut ready = Vec::new();
        let mut done = Vec::new();
        for (prep, cpw_of) in members {
            let block_id = prep.block_id();
            match prep.into_member() {
                Some(member) => ready.push((member, cpw_of)),
                None => done.push(PrepDone {
                    block_id,
                    cpw_of,
                    result: Ok(PrepOutcome::Unserved),
                }),
            }
        }
        (ready, done)
    }))
    .await;
    let (ready, mut done) = match first {
        Ok(x) => x,
        Err(e) => return all_failed(ids, &e),
    };
    let Some((biggest, need_bytes)) = ready
        .iter()
        .map(|(m, _)| (m.prep.block_id(), m.need_bytes))
        .max_by_key(|(_, need)| *need)
    else {
        return done;
    };
    info!(
        blocks = %ready
            .iter()
            .map(|(m, _)| m.prep.block_id().to_string())
            .collect::<Vec<_>>()
            .join(","),
        need_mib = need_bytes >> 20,
        "pos: overdue batch waiting for memory"
    );
    let waited = Instant::now();
    let permit = budget
        .acquire_priority(
            PriorityKind::OverduePos,
            &biggest,
            need_bytes,
            plan.slow_after,
            || {
                info!(
                    need_mib = need_bytes >> 20,
                    waited_s = waited.elapsed().as_secs(),
                    "pos: overdue batch still waiting for memory"
                );
            },
        )
        .await;
    // From here it works: its age for the stuck WARN counts from now, not from the wait.
    state.set_started(Instant::now());
    let ready_ids: Vec<SourceBlockId> = ready.iter().map(|(m, _)| m.prep.block_id()).collect();
    let worked = tokio::task::spawn_blocking(with_current_dispatch(move || {
        drive_batch(ready, permit, &batch, &state, &budget, &plan)
    }))
    .await;
    match worked {
        Ok(results) => {
            done.extend(results);
            done
        }
        Err(e) => {
            done.extend(all_failed(ready_ids, &e));
            done
        }
    }
}

/// Why a batch started no further member.
fn reason_to_stop(
    batch: &BatchShared,
    budget: &MemBudget,
    permit: &MemPermit,
    now: StdInstant,
    work_deadline: StdInstant,
    hard_stop: StdInstant,
) -> Option<&'static str> {
    if batch.is_stopped() {
        Some("written off")
    } else if now >= work_deadline {
        Some("half a period of work")
    } else if now >= hard_stop {
        Some("nine tenths of the period")
    } else if budget.batch_must_yield_to_restore(permit) {
        Some("a restore does not fit beside it")
    } else {
        None
    }
}

/// The members, one after the other, under the batch's permit (blocking; spec v3.7, v3.7a).
///
/// The first member always starts. Before each further one: the batch is not written off, less
/// than half a period of work has passed since the grant, the tick's 0.9 P has not passed, and no
/// queued restore stands that cannot fit beside the batch (Q-V8, answer (a)). After each member the
/// permit is shrunk to the largest need of the ones left. The permit is dropped BEFORE the
/// holders' masters are looked up; the results are published by the run loop after that.
pub(super) fn drive_batch(
    members: Vec<(Member, HashMap<DeviceId, u32>)>,
    mut permit: MemPermit,
    batch: &BatchShared,
    state: &PrepShared,
    budget: &MemBudget,
    plan: &BatchPlan,
) -> Vec<PrepDone> {
    state.hold(&mut permit);
    let granted = (plan.clock)();
    let work_deadline = granted + plan.period / 2;
    let hard_stop = plan.tick_start + plan.period * 9 / 10;
    // The largest need among the members after position i (suffix maxima).
    let mut left_after = vec![0u64; members.len() + 1];
    for i in (0..members.len()).rev() {
        left_after[i] = left_after[i + 1].max(members[i].0.need_bytes);
    }
    // `left_after[i]` includes member i; the need of the ones AFTER i is `left_after[i + 1]`.
    let total = members.len();
    let mut staged = Vec::new();
    let mut ended: Option<&'static str> = None;
    let mut rest = members.into_iter().enumerate();
    while let Some((i, (member, cpw_of))) = rest.next() {
        let block_id = member.prep.block_id();
        let stop = if i == 0 {
            None
        } else {
            reason_to_stop(
                batch,
                budget,
                &permit,
                (plan.clock)(),
                work_deadline,
                hard_stop,
            )
        };
        if stop.is_some() || !batch.try_start(&block_id) {
            ended = Some(stop.unwrap_or("written off"));
            batch.give_back(&block_id);
            for (_, (m, _)) in rest.by_ref() {
                batch.give_back(&m.prep.block_id());
            }
            break;
        }
        state.set_started(Instant::now());
        let (prep, computed) = BlockPrep::compute_member(member, &mut permit, state);
        staged.push((block_id, cpw_of, prep, computed));
        if left_after[i + 1] > 0 {
            permit.shrink_to(left_after[i + 1]);
        }
    }
    drop(permit);
    if let Some(reason) = ended {
        info!(
            reason,
            served = staged.len(),
            returned = total - staged.len(),
            "pos: overdue batch ended early, the rest goes back to the marks"
        );
    }
    staged
        .into_iter()
        .map(|(block_id, cpw_of, prep, computed)| PrepDone {
            block_id,
            cpw_of,
            result: Ok(match computed {
                Some(hashes) => Hashed { prep, hashes }.finish(),
                None => PrepOutcome::Unserved,
            }),
        })
        .collect()
}
