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
// prepares, ticks leave it alone; at most `MAX_PREPARATIONS` blocks prepare at once. So a
// block whose preparation is longer than a tick budget is served, once per preparation,
// not restarted by every tick.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};
use viaticum_core::pos::{ChallengeScheduleEntry, due_challenges};
use viaticum_core::types::{DeviceId, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp};

use super::{PendingKey, Scheduler, holder_trust_map, scaled_timer_secs};

mod in_flight;
mod prepare;
mod preparing;

use in_flight::publish_challenge;
pub(crate) use in_flight::{Ended, InFlight};
#[cfg(test)]
pub(crate) use prepare::{POS_LOAD_WARN_INTERVAL, log_load_failure, should_warn};

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

/// Block preparations in flight at once past their ticks (pos-i7-d-a). Each holds the
/// source block, the raw symbols encoded for the union of its holders' ranges and the
/// bound copies while hashing: memory ≈ K·(5 + R)·E, E the block size, R the number of
/// holders of the block (pos-i7-d-a). Two: one can finish while the next starts, and no
/// queue of big blocks sits in RAM. A block that would be the third stays due and counts
/// in `deferred`.
pub(crate) const MAX_PREPARATIONS: usize = 2;

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
    /// or their block is preparing (pos-i7-d-a).
    skipped_pending: usize,
    /// Due placements not pending whose challenge the tick did not start: the budget ran
    /// out (pos-i7-a). They stay due for the next tick.
    deferred: usize,
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
        }
    }

    /// Publish the challenges of a preparation that ended after its tick (pos-i7-d-a).
    /// The time passed since the placements were read, so each holder is re-checked
    /// against the database first: its placement must still exist, be challengeable, hold
    /// the ranges the hash was computed for, and have no challenge pending or in flight.
    /// The rest gets no challenge (it is due again by the usual rule). The publishes are
    /// spawned at once, past `ISSUE_PUBLISH_CONCURRENCY` by at most one block's holders:
    /// waiting for a slot here would hold the run loop.
    async fn publish_prepared(&self, done: preparing::PrepDone, in_flight: &mut InFlight) {
        let block_id = done.block_id;
        let prepared = match done.result {
            Ok(p) => p,
            Err(e) => {
                error!(
                    block_id = %block_id,
                    err = %e,
                    "scheduler: PoS hash compute task failed (panicked or cancelled) — skipping block"
                );
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
    /// deferred, cut_blocks, preparing (blocks preparing past their ticks), in_flight, elapsed_ms, scan_ms, slowest_block_ms, cpw_min,
    /// cpw_max, and — over the publishes settled since the previous line — zero_ack and
    /// slowest_publish_ms.
    pub(crate) async fn issue_tick(&self, in_flight: &mut InFlight) -> anyhow::Result<()> {
        let started = Instant::now();
        let budget = issue_budget(self.config.pos_interval_secs, self.config.time_scale);
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
        // A block preparing past its tick is not started again (pos-i7-d-a).
        already_pending.extend(in_flight.preparing.keys().copied());

        // The challengeable placements by (block, holder), built once per tick.
        let placement_of: HashMap<PendingKey, &SymbolPlacement> = challengeable
            .iter()
            .map(|p| ((p.source_block_id, p.holder_id), p))
            .collect();

        let not_pending: Vec<&ChallengeScheduleEntry> = due
            .iter()
            .filter(|e| !already_pending.contains(&(e.source_block_id, e.holder_id)))
            .collect();
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
            if in_flight.preparing.len() >= MAX_PREPARATIONS {
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
            let mut prep = self.spawn_prepare(block_id, &holder_placements);
            let prepared = match tokio::time::timeout_at(deadline, &mut prep).await {
                Ok(Ok(prepared)) => prepared,
                Ok(Err(join_err)) => {
                    // CS-POS-8: the blocking task panicked — log it loudly, skip the block
                    // this tick rather than re-panic the scheduler task.
                    error!(
                        block_id = %block_id,
                        err = %join_err,
                        "scheduler: PoS hash compute task failed (panicked or cancelled) — skipping block this tick"
                    );
                    Vec::new()
                }
                Err(_) => {
                    tick.cut_blocks += 1;
                    let keys = block_entries
                        .iter()
                        .map(|e| (e.source_block_id, e.holder_id))
                        .collect();
                    in_flight.preparing.adopt(block_id, cpw_of, keys, prep);
                    // The cut block itself is preparing, not deferred: only the blocks
                    // this tick did not reach are.
                    tick.deferred += blocks.by_ref().map(|(_, e)| e.len()).sum::<usize>();
                    slowest_block = slowest_block.max(block_started.elapsed());
                    break 'blocks;
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
            cut_blocks = tick.cut_blocks,
            preparing = in_flight.preparing.len(),
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
