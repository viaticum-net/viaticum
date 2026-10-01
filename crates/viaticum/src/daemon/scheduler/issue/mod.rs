// Owner side of PoS issuance: the issue tick (pos-i7, pos-i7-a, pos-i7-c).
//
// One tick finds the due placements, orders their blocks least recently tried first, and
// per block re-encodes the source once (`prepare`) and spawns one challenge publish per
// holder, at most `ISSUE_PUBLISH_CONCURRENCY` in flight (`in_flight`). The tick stops
// starting blocks when its time budget (a fifth of the PoS tick period) would run out:
// the rest stays due and goes next tick. It returns right after its last spawn; the
// publishes end later and are settled by the run loop. The tick runs inside the
// scheduler's `select!` loop, so while it runs no response is resolved, no ledger accrues
// and no timeout is checked: the budget is what keeps the loop's other work going.
//
// A block's preparation (source load, encode, hashes) is waited for only until the tick's
// deadline. One still running then is CUT from the tick but not dropped (pos-i7-d-a): its
// handle moves into `InFlight::preparing`, the run loop collects it when it ends and only
// then publishes its challenges (each stamped at its publish, pos-i7-a), after a re-check
// that the holder's placement is still challengeable and not pending. While a block
// prepares, ticks leave it alone; at most `MAX_PREPARATIONS` blocks the ticks started prepare at
// once. So a block whose preparation is longer than a tick budget is served, once per
// preparation, not restarted by every tick.
//
// Memory (R1-d-b, backup-i24, pos-i13, spec v3.7 / v3.7a): a preparation takes its permit from the
// block work budget itself, by `try_acquire`, right after it has read the block's record, and gives
// it back before anything is published. When somebody waits in the budget's queue no `try_acquire`
// can pass (A12-b), so the tick prepares nothing: it MARKS every due block it would have started
// (`mem_deferred_at`, the tick's number) and ends its block loop. A block too big for the free
// memory is marked too, and the tick goes on (a small one behind it may fit). From the next tick
// the marked blocks are prepared by ONE batch (`Preparing::adopt_batch`): one wait for memory
// sized by the largest member, the members one after the other, ahead of the order and the tick's
// time budget; their publication follows the batch's release of the permit.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};
use viaticum_core::pos::{ChallengeScheduleEntry, due_challenges};
use viaticum_core::types::{DeviceId, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp};

use super::{PendingKey, Scheduler, holder_trust_map, scaled_timer_secs};

pub(super) mod fold;
mod in_flight;
mod prepare;
mod preparing;

use in_flight::publish_challenge;
pub(crate) use in_flight::{Ended, InFlight};
pub(crate) use prepare::PrepOutcome;
#[cfg(test)]
pub(crate) use prepare::load_failed_until;
#[cfg(test)]
pub(crate) use prepare::{POS_LOAD_WARN_INTERVAL, log_load_failure, should_warn};
use preparing::BatchPlan;
#[cfg(test)]
pub(crate) use preparing::PrepDone;

/// An issue tick may spend 1 / `ISSUE_BUDGET_DIVISOR` of the PoS tick period (pos-i7-a:
/// ≈ 20 %, the bar of the tick's `elapsed_ms`).
const ISSUE_BUDGET_DIVISOR: u32 = 5;

/// A block starts only while the time spent plus `BLOCK_HEADROOM` × the slowest block of
/// this tick fits the budget. The budget is also the bar of `elapsed_ms` (pos-i7-a), so
/// the last block must end inside it even when it is somewhat slower than the ones before
/// (one spare block: a block up to 2× the slowest still ends within the budget).
const BLOCK_HEADROOM: u32 = 2;

/// A tick waits — for a block's preparation or for a free publish slot — only until this
/// share of its budget, in percent: every wait of the tick ends at one deadline short of
/// the budget, so the tick line comes before the bar whatever the disk or the network do.
const WAIT_DEADLINE_PCT: u32 = 95;

/// Block preparations a tick started that may run at once (pos-i7-d-a, pos-i7-d-c): the one in
/// the tick and up to this many cut from earlier ticks. A bound on CPU, blocking-pool threads and
/// the blocks excluded from the ticks — NOT on memory: memory is the budget's (backup-i24), each
/// preparation holds a permit while it holds its source and symbols. The batch of overdue
/// preparations (pos-i13) is not counted here: there is at most one, and it waits for memory as a
/// priority waiter (CPU: K + 2 at most). Two: one can finish while the next starts. A block that
/// would be the third stays due and counts in `deferred`.
pub(crate) const MAX_PREPARATIONS: usize = 2;

/// A preparation running longer than this many issue-tick periods (scaled like the tick
/// itself) is named by a WARN, once per period per block (pos-i7-d-b). Its slot is not
/// freed: memory matters more than liveness until hangs are seen in the field.
pub(crate) const STUCK_PREPARATION_PERIODS: u32 = 10;

/// pos-i7-d-d, variant (a) — the architect's recommendation, not Ilya's decision (Q-V7 is open):
/// a preparation hung in its load phase for `max(STUCK_PREPARATION_PERIODS × period,
/// WRITE_OFF_MIN_REAL)` is written off (its bytes return to the memory budget while it hangs), at
/// most one at a time. `false` is variant (b): visibility only, the WARN of the stuck preparation.
pub(crate) const WRITE_OFF_STUCK_LOADS: bool = true;

/// The floor of the write-off age, in REAL time (spec v3.6 WARN-4): on a time-scaled rig
/// `STUCK_PREPARATION_PERIODS` periods are seconds, and a load that is merely slow must not be
/// written off. In production (10 h) the floor does not matter. The WARN of a stuck preparation
/// stays at `STUCK_PREPARATION_PERIODS` periods.
pub(crate) const WRITE_OFF_MIN_REAL: Duration = Duration::from_secs(600);

/// Challenge publishes in flight at once (pos-i7-a), across ticks. About one block's
/// holders (8 in the E2E) plus one: a block's re-encode (~110 ms at 1 MiB) is longer than
/// a publish (~15 ms to the first Ack), so the publishes of one block end while the next
/// is encoded. More in flight would not publish faster: every Ack costs the owner a
/// durable redb commit (the postman's contact, `routing/fanout.rs`) before it counts, the
/// commits are serial, and a longer queue of them only delays each publish's first Ack.
pub(crate) const ISSUE_PUBLISH_CONCURRENCY: usize = 9;

/// The time budget of one issue tick: a fifth of the PoS tick period, which is scaled
/// by `time_scale` like the timer itself (`scaled_timer_secs`, floor 1 s). Production
/// (3600 s, scale 1): 720 s; the E2E at scale 900: 800 ms.
pub(crate) fn issue_budget(pos_interval_secs: u64, time_scale: u64) -> Duration {
    Duration::from_secs(scaled_timer_secs(pos_interval_secs, time_scale)) / ISSUE_BUDGET_DIVISOR
}

/// Counters of one PoS issue tick, printed by `scheduler: PoS issue tick` (pos-i7).
#[derive(Debug, Default)]
struct IssueTick {
    /// Placements due this tick (`due_challenges`).
    due: usize,
    /// Challenge publishes this tick started (each goes into pending on its first Ack,
    /// settled by the run loop).
    issued: usize,
    /// Blocks this tick started (re-encoded).
    blocks: usize,
    /// Due placements skipped because a challenge is pending or being published for them,
    /// or their block is preparing (pos-i7-d-a: the whole block, every holder).
    skipped_pending: usize,
    /// Due placements not pending whose challenge the tick did not start: the budget ran
    /// out (pos-i7-a) or `MAX_PREPARATIONS` blocks were already preparing (pos-i7-d-a).
    /// They stay due for the next tick. A block cut by this tick is not counted here.
    deferred: usize,
    /// Due placements of the blocks the memory budget deferred in this tick (R1-d-b): they wait
    /// for memory as overdue ones from the next tick.
    deferred_mem: usize,
    /// Blocks whose preparation was still running at the deadline: the tick stopped
    /// waiting for it and left it to `InFlight::preparing` (pos-i7-d-a).
    cut_blocks: usize,
    cpw_min: u32,
    cpw_max: u32,
}

/// The due entries grouped by block, blocks in the order of their least recently tried
/// entry: the later of its `last_verified` and its last attempt (a never-tried one first);
/// equal blocks keep the order of `due`.
///
/// Fairness of a tick cut by the budget (pos-i7-a, pos-i7-c): the tail of this order stays
/// due. An issued challenge leaves the due set while it is pending, a Pass moves
/// `last_verified` to now, and every start moves the attempt to now — each to the back. So
/// a block that cannot be served (0 acks, a source that does not load) does not hold the
/// head: the others come within ⌈unservable / blocks per tick⌉ ticks.
pub(crate) fn blocks_least_recently_tried_first<'a>(
    due: impl IntoIterator<Item = &'a ChallengeScheduleEntry>,
    last_tried: impl Fn(&PendingKey) -> Option<Timestamp>,
) -> Vec<(SourceBlockId, Vec<&'a ChallengeScheduleEntry>)> {
    let mut order: Vec<SourceBlockId> = Vec::new();
    // Per block: its least recent try (None < Some) and its entries.
    let mut by_block: HashMap<SourceBlockId, (Option<Timestamp>, Vec<&ChallengeScheduleEntry>)> =
        HashMap::new();
    for e in due {
        let tried = last_tried(&(e.source_block_id, e.holder_id));
        let slot = by_block.entry(e.source_block_id).or_insert_with(|| {
            order.push(e.source_block_id);
            (tried, Vec::new())
        });
        slot.0 = slot.0.min(tried);
        slot.1.push(e);
    }
    order.sort_by_key(|b| by_block[b].0);
    order
        .into_iter()
        .filter_map(|b| by_block.remove(&b).map(|(_, entries)| (b, entries)))
        .collect()
}

impl Scheduler {
    /// One issue tick, then wait for its publishes and settle them — for callers without
    /// a run loop (tests, one-shot use). The run loop calls `issue_tick` and settles the
    /// publishes in its own `select!`.
    pub async fn issue_due_challenges(&self) -> anyhow::Result<()> {
        let mut in_flight = InFlight::default();
        let result = self.issue_tick(&mut in_flight).await;
        while let Some(ended) = in_flight.join_next_any().await {
            self.settle_ended(ended, &mut in_flight).await;
        }
        result
    }

    /// Account one thing that ended in `InFlight`: a publish is settled, a preparation
    /// that outlived its tick has its challenges published.
    pub(crate) async fn settle_ended(&self, ended: Ended, in_flight: &mut InFlight) {
        match ended {
            Ended::Published(done) => self.settle_publish(done, &mut in_flight.settled).await,
            Ended::Prepared(done) => self.publish_prepared(done, in_flight).await,
            // The batch has given its permit back; its members' challenges are published one
            // after the other (J12).
            Ended::Batch(done) => {
                for member in done {
                    self.publish_prepared(member, in_flight).await;
                }
            }
        }
    }

    /// Publish the challenges of a preparation that ended after its tick (pos-i7-d-a).
    /// The time passed since the placements were read, so each holder is re-checked
    /// against the database first: its placement must still exist, be challengeable, hold
    /// the ranges the hash was computed for, and have no challenge pending or in flight.
    /// The rest gets no challenge (it is due again by the usual rule). The publishes are
    /// spawned at once, past `ISSUE_PUBLISH_CONCURRENCY` by up to K·R publishes (K =
    /// `MAX_PREPARATIONS` preparations ending, R the holders of a block): waiting for a
    /// slot here would hold the run loop.
    async fn publish_prepared(&self, done: preparing::PrepDone, in_flight: &mut InFlight) {
        let block_id = done.block_id;
        let prepared = match done.result {
            Ok(PrepOutcome::Prepared(p)) => {
                self.clear_mem_deferred(&block_id);
                p
            }
            Ok(PrepOutcome::Unserved) => {
                self.clear_mem_deferred(&block_id);
                return;
            }
            // NOTE 5: a preparation cut from its tick can end deferred too: the block is deferred
            // as of now, and waits for memory from the next tick.
            Ok(PrepOutcome::Deferred) => {
                self.note_mem_deferred(block_id, self.issue_seq.load(Ordering::SeqCst));
                return;
            }
            Err(e) => {
                self.prep_failed(block_id, &e);
                return;
            }
        };
        let pending_keys: HashSet<PendingKey> = {
            let guard = self.pending.lock().await;
            guard.keys().copied().collect()
        };
        let (mut issued, mut dropped) = (0usize, 0usize);
        for challenge in prepared {
            let key = (block_id, challenge.holder_id);
            let still_due = !pending_keys.contains(&key)
                && !in_flight.keys().any(|k| *k == key)
                && match self.db.get_placement(&block_id, &challenge.holder_id) {
                    Ok(Some(p)) => {
                        matches!(
                            p.status,
                            PlacementStatus::Alive
                                | PlacementStatus::Uncertain
                                | PlacementStatus::PresumedLost
                        ) && p.esi_ranges == challenge.esi_ranges
                    }
                    Ok(None) => false,
                    Err(e) => {
                        warn!(block_id = %block_id, err = %e, "scheduler: get_placement failed; late challenge dropped");
                        false
                    }
                };
            if !still_due {
                dropped += 1;
                continue;
            }
            let cpw = done.cpw_of.get(&challenge.holder_id).copied().unwrap_or(0);
            if let Some((entry, pending)) = self.challenge_entry(block_id, challenge) {
                in_flight.spawn(
                    key,
                    publish_challenge(Arc::clone(&self.mailbox_router), entry, pending, cpw),
                );
                issued += 1;
            }
        }
        info!(
            block_id = %block_id,
            issued,
            dropped,
            in_flight = in_flight.len(),
            "scheduler: PoS late preparation published"
        );
    }

    /// Start the PoS hash challenges of the holders that are due, within the tick's budget.
    ///
    /// Steps:
    ///   1. List the challengeable placements (Alive / Uncertain / PresumedLost, SS
    ///      blocks excluded — Bug-B); `due_challenges` picks the due ones.
    ///   2. Skip placements with a challenge pending or being published (no double issue).
    ///   3. Order the blocks least recently tried first (fairness, pos-i7-c, see
    ///      `blocks_least_recently_tried_first`).
    ///   4. Per block, while the budget lasts and fewer than `MAX_PREPARATIONS` blocks are
    ///      preparing: load the source, encode once (union of the holders' ESI ranges), per
    ///      holder the binding + chain hash — one blocking task, waited for until the
    ///      deadline (`WAIT_DEADLINE_PCT` % of the budget); then spawn one publish per
    ///      holder into `in_flight`, a free slot waited for until the same deadline. A
    ///      preparation still running at the deadline is handed to `in_flight.preparing`
    ///      (pos-i7-d-a); the run loop publishes its challenges when it ends.
    ///   5. Each challenge takes its own time when it is published: `timestamp`,
    ///      `expires_at`, `stored_at` and the pending `issued_at` (pos-i7-a).
    ///   6. W-3: a challenge goes into pending ONLY after ≥ 1 MailboxStoreAck, when its
    ///      publish is settled (`settle_publish`); 0 acks = due again next tick.
    ///
    /// Budget: a block starts only if the time spent plus `BLOCK_HEADROOM` × the slowest
    /// block of this tick fits `issue_budget` (the first block always starts, so a block
    /// slower than the headroom is still started). Every wait ends at the deadline — a
    /// block still preparing then is cut from the tick, not dropped — and the tick does
    /// not wait for publishes or for preparations past their tick, so it
    /// returns within the budget whatever the disk, the database or the network do (only
    /// its synchronous scan, `scan_ms`, is not bounded).
    ///
    /// pos-i7: linear in the placements — `due_challenges` indexes `last_verified`, the
    /// pending keys are a set, the placements are indexed by (block, holder), and a
    /// holder's trust is read once per tick. A tick with due challenges ends with one
    /// INFO line `scheduler: PoS issue tick`: due, issued, blocks, skipped_pending,
    /// deferred, deferred_mem (placements of the blocks the memory budget deferred, pos-i13),
    /// budget_closed (1 while a DR keeps the budget closed, pos-i13),
    /// cut_blocks, preparing (preparations running past their ticks, and overdue ones running),
    /// waiting_mem (overdue blocks waiting for memory), oldest_prep_s (age of the oldest running
    /// one, pos-i7-d-b), oldest_wait_s (the longest wait for memory), in_flight, elapsed_ms, scan_ms,
    /// slowest_block_ms, cpw_min, cpw_max, and — over the publishes settled since the
    /// previous line — zero_ack and slowest_publish_ms.
    pub(crate) async fn issue_tick(&self, in_flight: &mut InFlight) -> anyhow::Result<()> {
        let started = Instant::now();
        // The same moment on the batch's clock (spec v3.7a: a batch starts no member past 0.9 of
        // a period from here).
        let tick_start = (self.batch_clock)();
        // The number of this tick (pos-i13): a block the budget defers on tick n waits for memory
        // from tick n + 1, whatever the clock says.
        let tick_no = self.issue_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let budget = issue_budget(self.config.pos_interval_secs, self.config.time_scale);
        // pos-i7-d-b: a preparation that hangs is named once per period, before any early
        // return of the tick; pos-i7-d-d: a load that hangs gives its memory back.
        let period = Duration::from_secs(scaled_timer_secs(
            self.config.pos_interval_secs,
            self.config.time_scale,
        ));
        in_flight.preparing.watch_stuck(
            tokio::time::Instant::now(),
            period,
            STUCK_PREPARATION_PERIODS,
            WRITE_OFF_MIN_REAL,
            &self.mem_budget,
            WRITE_OFF_STUCK_LOADS,
        );
        // Every wait of the tick ends here, short of the budget: a wait cut at the budget
        // itself would end the tick a timer tick past it (≥ 1 ms over the bar).
        let deadline = tokio::time::Instant::now() + budget * WAIT_DEADLINE_PCT / 100;
        // Decides what is due; every challenge takes its own time at publish (pos-i7-a).
        let tick_now = Timestamp::now();

        let placements = match self.db.list_all_placements() {
            Ok(ps) => ps,
            Err(e) => {
                error!("scheduler: list_all_placements failed: {e}");
                return Ok(());
            }
        };

        // Bug-B: SS-blocks are excluded from due_challenges until hash-PoS for SS-blocks
        // is implemented (separate near-term task, high priority). See TODO(bug-b) in pos/mod.rs.
        let ss_ids = match self.db.ss_block_id_set() {
            Ok(ids) => ids,
            Err(e) => {
                warn!(
                    "scheduler: ss_block_id_set failed: {e}; treating as empty (may challenge SS blocks)"
                );
                HashSet::new()
            }
        };

        // Only challenge placements in a challengeable state, excluding SS-blocks.
        let challengeable: Vec<_> = placements
            .into_iter()
            .filter(|p| {
                matches!(
                    p.status,
                    PlacementStatus::Alive
                        | PlacementStatus::Uncertain
                        | PlacementStatus::PresumedLost
                ) && !ss_ids.contains(&p.source_block_id.0)
            })
            .collect();

        if challengeable.is_empty() {
            debug!("scheduler: no challengeable placements");
            let preparing = in_flight.preparing.blocks();
            self.retain_mem_deferred(|b| preparing.contains(b));
            return Ok(());
        }

        // Build last_verified slice for due_challenges.
        let last_verified: Vec<_> = challengeable
            .iter()
            .map(|p| (p.source_block_id, p.holder_id, p.last_verified))
            .collect();

        // 5b (pos-i7): a holder's trust is three redb reads; read it once per holder per
        // tick, not once per placement.
        let trust = holder_trust_map(&challengeable, |h| self.holder_trust(h));

        let due = due_challenges(
            &challengeable,
            &last_verified,
            tick_now,
            |h| trust.get(h).copied().unwrap_or(0.5),
            self.config.time_scale,
        );

        if due.is_empty() {
            debug!("scheduler: no challenges due at this interval");
            let preparing = in_flight.preparing.blocks();
            self.retain_mem_deferred(|b| preparing.contains(b));
            return Ok(());
        }
        let mut tick = IssueTick {
            due: due.len(),
            cpw_min: due.iter().map(|e| e.cpw).min().unwrap_or(0),
            cpw_max: due.iter().map(|e| e.cpw).max().unwrap_or(0),
            ..IssueTick::default()
        };

        // Pending and in-flight keys, snapshot once: neither gets a second challenge.
        let mut already_pending: HashSet<PendingKey> = {
            let guard = self.pending.lock().await;
            guard.keys().copied().collect()
        };
        already_pending.extend(in_flight.keys().copied());
        // A block preparing past its tick is not started again, for any holder (pos-i7-d-a).
        let preparing_blocks = in_flight.preparing.blocks();

        // The challengeable placements by (block, holder), built once per tick.
        let placement_of: HashMap<PendingKey, &SymbolPlacement> = challengeable
            .iter()
            .map(|p| ((p.source_block_id, p.holder_id), p))
            .collect();

        let mut not_pending: Vec<&ChallengeScheduleEntry> = due
            .iter()
            .filter(|e| {
                !already_pending.contains(&(e.source_block_id, e.holder_id))
                    && !preparing_blocks.contains(&e.source_block_id)
            })
            .collect();
        // pos-i13: the blocks marked on an EARLIER tick are prepared now, by one batch — decided
        // here, before the order and the tick's time budget, so neither can keep them from being
        // queued. With no marks this is one lock and a return (the hot path of the tick).
        let batched = self.adopt_overdue(
            in_flight,
            tick_no,
            tick_start,
            period,
            &mut not_pending,
            &placement_of,
        );
        if batched > 0 {
            debug!(
                batched,
                "scheduler: marked blocks now wait for memory as a batch"
            );
        }
        tick.skipped_pending = due.len() - not_pending.len();
        let blocks = {
            let mut attempted = self
                .last_attempted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Forget the attempts of placements no longer challengeable (bounded memory).
            attempted.retain(|k, _| placement_of.contains_key(k));
            blocks_least_recently_tried_first(not_pending, |k| {
                let verified = placement_of.get(k).and_then(|p| p.last_verified);
                verified.max(attempted.get(k).copied())
            })
        };

        // The fixed part of the tick: placements, due scan, order (СТ-0c round 4: the
        // breakdown of `elapsed_ms` on the tick line).
        let scan_ms = started.elapsed().as_millis() as u64;
        let mut slowest_block = Duration::ZERO;
        let mut blocks = blocks.into_iter();
        'blocks: while let Some((block_id, block_entries)) = blocks.next() {
            while let Some(done) = in_flight.try_join_next() {
                self.settle_publish(done, &mut in_flight.settled).await;
            }
            // pos-i13 (spec v3.7): somebody waits in the budget's queue, so no `try_acquire` of
            // this tick can pass (A12-b). The tick prepares nothing: this block and every one
            // left are marked (they wait for memory as a batch from the next tick) and keep their
            // place in the order (`last_attempted` is not moved). Marking costs no CPU, so it
            // comes before the time budget and K.
            let queued = self.mem_budget.queued_waiters();
            if queued > 0 {
                let mut marked = 0usize;
                let mut rest = vec![(block_id, block_entries)];
                rest.extend(blocks.by_ref());
                let ids: Vec<SourceBlockId> = rest.iter().map(|(b, _)| *b).collect();
                for (_, entries) in &rest {
                    tick.deferred_mem += entries.len();
                    marked += 1;
                }
                self.note_mem_deferred_all(ids, tick_no);
                debug!(marked, queued, "pos: blocks marked, memory queue busy");
                break 'blocks;
            }
            // pos-i7-a: start a block only while it fits the budget, with a spare block of
            // headroom. The first block always starts: a tick issues something even if one
            // block outlasts it.
            if tick.blocks > 0 && started.elapsed() + slowest_block * BLOCK_HEADROOM > budget {
                tick.deferred +=
                    block_entries.len() + blocks.by_ref().map(|(_, e)| e.len()).sum::<usize>();
                break;
            }
            // pos-i7-d-a: memory bound. The block is not started (its attempt is not
            // moved: it keeps its place in the order) and stays due.
            if in_flight.preparing.tick_started() >= MAX_PREPARATIONS {
                tick.deferred +=
                    block_entries.len() + blocks.by_ref().map(|(_, e)| e.len()).sum::<usize>();
                break;
            }
            tick.blocks += 1;
            // pos-i7-c: an attempt moves the block back in the order, served or not.
            {
                let mut attempted = self
                    .last_attempted
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                for e in &block_entries {
                    attempted.insert((e.source_block_id, e.holder_id), tick_now);
                }
            }
            let block_started = Instant::now();

            let cpw_of: HashMap<DeviceId, u32> =
                block_entries.iter().map(|e| (e.holder_id, e.cpw)).collect();
            let holder_placements: Vec<&SymbolPlacement> = block_entries
                .iter()
                .filter_map(|e| placement_of.get(&(e.source_block_id, e.holder_id)).copied())
                .collect();

            // The preparation runs on the blocking pool; the tick waits for it only until
            // the deadline (СТ-0c round 4). Past it the block is cut from the tick: the
            // handle moves to `in_flight.preparing` and the run loop publishes the block's
            // challenges when it ends (pos-i7-d-a).
            let (mut prep, shared) = self.spawn_prepare(block_id, &holder_placements);
            let outcome = match tokio::time::timeout_at(deadline, &mut prep).await {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(join_err)) => {
                    // CS-POS-8: the blocking task panicked — name it, skip the block (its mark
                    // goes, it waits one period) rather than re-panic the scheduler task.
                    self.prep_failed(block_id, &anyhow::Error::from(join_err));
                    PrepOutcome::Unserved
                }
                Err(_) => {
                    tick.cut_blocks += 1;
                    in_flight.preparing.adopt(block_id, cpw_of, prep, shared);
                    // The cut block itself is preparing, not deferred: only the blocks
                    // this tick did not reach are.
                    tick.deferred += blocks.by_ref().map(|(_, e)| e.len()).sum::<usize>();
                    slowest_block = slowest_block.max(block_started.elapsed());
                    break 'blocks;
                }
            };
            let prepared = match outcome {
                PrepOutcome::Prepared(prepared) => {
                    self.clear_mem_deferred(&block_id);
                    prepared
                }
                PrepOutcome::Unserved => {
                    self.clear_mem_deferred(&block_id);
                    Vec::new()
                }
                // The block is too big for the free memory (the queue was empty, or a waiter came
                // after the tick looked; logged by the preparation): marked, and the tick goes
                // on — a small block behind a big one may fit (backup-i24, M22), unlike at the
                // time budget and K. The deferral is brief (a record read); it does not count as
                // a slow block.
                PrepOutcome::Deferred => {
                    self.note_mem_deferred(block_id, tick_no);
                    tick.deferred_mem += block_entries.len();
                    continue 'blocks;
                }
            };
            slowest_block = slowest_block.max(block_started.elapsed());
            let mut prepared = prepared.into_iter();
            while let Some(challenge) = prepared.next() {
                // A free slot, waited for at most until the slot deadline: a slow publish
                // (up to 15 s when no postman answers) never stretches the tick.
                while in_flight.len() >= ISSUE_PUBLISH_CONCURRENCY {
                    match tokio::time::timeout_at(deadline, in_flight.join_next()).await {
                        Ok(Some(done)) => self.settle_publish(done, &mut in_flight.settled).await,
                        Ok(None) => break,
                        Err(_) => {
                            tick.deferred += 1
                                + prepared.len()
                                + blocks.by_ref().map(|(_, e)| e.len()).sum::<usize>();
                            break 'blocks;
                        }
                    }
                }
                let key = (block_id, challenge.holder_id);
                let cpw = cpw_of.get(&challenge.holder_id).copied().unwrap_or(0);
                if let Some((entry, pending)) = self.challenge_entry(block_id, challenge) {
                    in_flight.spawn(
                        key,
                        publish_challenge(Arc::clone(&self.mailbox_router), entry, pending, cpw),
                    );
                    tick.issued += 1;
                }
            }
        }

        // pos-i7 observable: one line per tick with due challenges. zero_ack and
        // slowest_publish_ms cover the publishes settled since the previous line.
        let settled = std::mem::take(&mut in_flight.settled);
        info!(
            due = tick.due,
            issued = tick.issued,
            blocks = tick.blocks,
            skipped_pending = tick.skipped_pending,
            deferred = tick.deferred,
            deferred_mem = tick.deferred_mem,
            // pos-i13: 1 while the budget is closed because a DR runs on this machine (v3.9a
            // item 4) — the deferrals of such a tick are not a shortage of memory.
            budget_closed = u8::from(self.mem_budget.is_closed()),
            cut_blocks = tick.cut_blocks,
            preparing = in_flight.preparing.running(),
            waiting_mem = in_flight.preparing.waiting(),
            marked = self.marked_len(),
            batch = in_flight.preparing.batch_members(),
            oldest_prep_s = in_flight
                .preparing
                .oldest_age(tokio::time::Instant::now())
                .as_secs(),
            oldest_wait_s = in_flight
                .preparing
                .oldest_wait(tokio::time::Instant::now())
                .as_secs(),
            in_flight = in_flight.len(),
            zero_ack = settled.zero_ack,
            slowest_publish_ms = settled.slowest_publish.as_millis() as u64,
            elapsed_ms = started.elapsed().as_millis() as u64,
            scan_ms,
            slowest_block_ms = slowest_block.as_millis() as u64,
            cpw_min = tick.cpw_min,
            cpw_max = tick.cpw_max,
            "scheduler: PoS issue tick"
        );

        Ok(())
    }
}

/// The deferral book of the memory budget (pos-i13): the tick a block was first marked on.
impl Scheduler {
    /// `block` was deferred by the budget on tick `tick_no`; the first deferral of an episode
    /// counts, a later one does not move it.
    pub(super) fn note_mem_deferred(&self, block: SourceBlockId, tick_no: u64) {
        self.mem_deferred_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(block)
            .or_insert(tick_no);
    }

    /// The same for many blocks under one lock (a tick that finds the queue busy marks them all).
    fn note_mem_deferred_all(&self, blocks: impl IntoIterator<Item = SourceBlockId>, tick_no: u64) {
        let mut map = self
            .mem_deferred_at
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        for block in blocks {
            map.entry(block).or_insert(tick_no);
        }
    }

    /// `block` got its memory (or cannot be served): the episode is over.
    pub(super) fn clear_mem_deferred(&self, block: &SourceBlockId) {
        self.mem_deferred_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(block);
    }

    fn retain_mem_deferred(&self, keep: impl Fn(&SourceBlockId) -> bool) {
        self.mem_deferred_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|b, _| keep(b));
    }

    /// Blocks marked now (the `marked` field of the tick line).
    fn marked_len(&self) -> usize {
        self.mem_deferred_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// A preparation whose task panicked or was cancelled (spec v3.6 NOTE 4): named, its mark is
    /// cleared (the batch or the tick does not wait for it), and it waits one period before a
    /// batch takes it again — as after any other failure to read the source.
    fn prep_failed(&self, block_id: SourceBlockId, err: &anyhow::Error) {
        warn!(
            block_id = %block_id,
            err = %err,
            "scheduler: PoS hash compute task failed (panicked or cancelled) — skipping block"
        );
        self.clear_mem_deferred(&block_id);
        let period = Duration::from_secs(scaled_timer_secs(
            self.config.pos_interval_secs,
            self.config.time_scale,
        ));
        self.load_failed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(block_id, Instant::now() + period);
    }

    /// Start the batch of the blocks marked on an earlier tick than `tick_no` (J11: marked on n,
    /// prepared from n + 1), if none is in flight; spec v3.7. Their due placements leave
    /// `not_pending` (the ticks leave them alone while the batch holds them). A block whose last
    /// load failed (`load_failed`, backup-i7) is not among them: it stays in the ordinary flow,
    /// where `try_acquire` decides. Marks of blocks no longer due (and not held by a preparation)
    /// are dropped first. Returns the number of blocks in the batch.
    ///
    /// The hot path of the tick: with no marks this is one lock and a return, and nothing here
    /// reads the database or the files — the members' records and sources are looked at by the
    /// batch itself, on the blocking pool.
    fn adopt_overdue(
        &self,
        in_flight: &mut InFlight,
        tick_no: u64,
        tick_start: Instant,
        period: Duration,
        not_pending: &mut Vec<&ChallengeScheduleEntry>,
        placement_of: &HashMap<PendingKey, &SymbolPlacement>,
    ) -> usize {
        if self
            .mem_deferred_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
        {
            return 0;
        }
        let due_blocks: HashSet<SourceBlockId> =
            not_pending.iter().map(|e| e.source_block_id).collect();
        let preparing = in_flight.preparing.blocks();
        let ripe: Vec<(SourceBlockId, u64)> = {
            let mut map = self
                .mem_deferred_at
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            // A mark whose block is no longer due, nor held by a preparation, is stale.
            map.retain(|b, _| due_blocks.contains(b) || preparing.contains(b));
            if in_flight.preparing.batch_in_flight() {
                return 0;
            }
            map.iter()
                .filter(|(b, n)| **n < tick_no && due_blocks.contains(*b))
                .map(|(b, n)| (*b, *n))
                .collect()
        };
        let now = Instant::now();
        let mark_of: HashMap<SourceBlockId, u64> = ripe
            .into_iter()
            .filter(|(b, _)| !self.load_failed_now(b, now))
            .collect();
        if mark_of.is_empty() {
            return 0;
        }
        // Their entries, block by block: the oldest mark first, then the order of pos-i7-c.
        let mut taken: Vec<&ChallengeScheduleEntry> = Vec::new();
        not_pending.retain(|e| {
            if mark_of.contains_key(&e.source_block_id) {
                taken.push(*e);
                return false;
            }
            true
        });
        let mut ordered = {
            let attempted = self
                .last_attempted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            blocks_least_recently_tried_first(taken, |k| {
                let verified = placement_of.get(k).and_then(|p| p.last_verified);
                verified.max(attempted.get(k).copied())
            })
        };
        ordered.sort_by_key(|(b, _)| mark_of[b]);
        let members: Vec<_> = ordered
            .iter()
            .map(|(block_id, entries)| {
                let cpw_of: HashMap<DeviceId, u32> =
                    entries.iter().map(|e| (e.holder_id, e.cpw)).collect();
                let holder_placements: Vec<&SymbolPlacement> = entries
                    .iter()
                    .filter_map(|e| placement_of.get(&(e.source_block_id, e.holder_id)).copied())
                    .collect();
                (self.make_prep(*block_id, &holder_placements, None), cpw_of)
            })
            .collect();
        let count = members.len();
        in_flight.preparing.adopt_batch(
            members,
            Arc::clone(&self.mem_budget),
            BatchPlan {
                period,
                tick_start,
                clock: Arc::clone(&self.batch_clock),
                slow_after: period * STUCK_PREPARATION_PERIODS,
            },
        );
        count
    }
}
