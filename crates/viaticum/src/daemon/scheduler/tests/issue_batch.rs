// R1-d-b, fix round К-b2b (spec v3.6, v3.7, v3.7a): the batch of overdue PoS preparations and the
// marking of a tick that finds the budget's queue busy.
//
// A tick that finds somebody waiting in the budget's queue prepares nothing and MARKS every due
// block it would have started. From the next tick the marked blocks are prepared by ONE batch:
// one wait for memory sized by the largest member, the members one after the other, publication
// after the permit is released. The batch ends at half a period of work from its grant, at 0.9 of a
// period from its tick's start (never before its first member), when a restore that does not fit
// beside it waits (Q-V8, answer (a)), or when it is written off. Its limits are driven here by an
// injected period (the time scale) and an injected clock.
//
// Every test runs the REAL tick (`issue_tick`); the run loop's part — settling what ends — is
// driven by hand, as in `issue_mem`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};

use tokio::time::Instant;
use viaticum_core::types::{SourceBlockId, Timestamp};

use super::issue_mem::{
    MIB, TOTAL_MIB, block_at, budgeted, budgeted_at, deferred_tick_of, freeze_batch_clock,
    hold_all, logged, pending_len, permit_of_test_block, seed_sized_block, settle_until_idle,
    sized_block_id, tick, tick_lines, until,
};
use super::issue_stall::StallingEncoder;
use super::issue_support::{SlowPostman, owner_with_encoder};
use super::pos_scale::field;
use super::{TEST_K, make_identity, make_placement, make_test_encoder, seed_retained_pos_block};
use crate::daemon::mem_budget::{
    HolderKind, MemBudget, MemPermit, PriorityKind, estimate_pos_issue,
};
use crate::daemon::scheduler::BatchClock;
use crate::daemon::scheduler::issue::{Ended, InFlight};

/// A clock the test moves: the batch's work limit and hard stop read it.
struct FakeClock {
    base: StdInstant,
    ms: AtomicU64,
}

impl FakeClock {
    fn new() -> Arc<Self> {
        Arc::new(FakeClock {
            base: StdInstant::now(),
            ms: AtomicU64::new(0),
        })
    }

    fn now(&self) -> StdInstant {
        self.base + Duration::from_millis(self.ms.load(Ordering::SeqCst))
    }

    fn advance(&self, by: Duration) {
        self.ms.fetch_add(by.as_millis() as u64, Ordering::SeqCst);
    }

    fn batch_clock(self: &Arc<Self>) -> BatchClock {
        let clock = Arc::clone(self);
        Arc::new(move || clock.now())
    }
}

/// An encoder that does nothing special: no stall, only the hook of the test.
fn plain_encoder() -> Arc<StallingEncoder> {
    StallingEncoder::new(0, 0, Duration::ZERO)
}

/// A restore waiting for `mib` MiB, started in the background.
fn spawn_restore(budget: &Arc<MemBudget>, mib: u64) -> tokio::task::JoinHandle<MemPermit> {
    let budget = Arc::clone(budget);
    tokio::spawn(async move {
        budget
            .acquire_priority(
                PriorityKind::Restore,
                &SourceBlockId([0xAB; 32]),
                mib * MIB,
                Duration::from_secs(3600),
                || {},
            )
            .await
    })
}

/// An owner of `blocks` × 1 holder, at the time scale where one period is 100 s, whose batch
/// clock is the returned fake one: every encode takes `step` of fake time.
fn on_a_fake_clock(
    blocks: u8,
    step: Duration,
) -> (
    super::issue_support::Owner,
    Arc<MemBudget>,
    Arc<FakeClock>,
    Arc<StallingEncoder>,
) {
    let encoder = plain_encoder();
    let (mut owner, budget) = budgeted_at(36, blocks, 1, Arc::clone(&encoder) as _);
    let clock = FakeClock::new();
    owner.scheduler.set_batch_clock(clock.batch_clock());
    let ticking = Arc::clone(&clock);
    encoder.set_hook(move |_| ticking.advance(step));
    (owner, budget, clock, encoder)
}

fn mark_count(owner: &super::issue_support::Owner) -> usize {
    owner.scheduler.mem_deferred_at.lock().unwrap().len()
}

// ─── Marking: a busy queue marks every due block of the tick ─────────────────

/// BLOCK-1 (M43′). The queue is busy for good (a restore waits). N = 12 due blocks: the FIRST tick
/// marks all twelve — the unmarked N-th block in the LRU order is not left to wait N periods — and
/// moves no attempt; the next tick puts them all in one batch; when it ends all twelve are issued.
#[tokio::test]
async fn unmarked_nth_block_in_lru_is_marked_on_the_first_busy_tick() {
    let (owner, budget) = budgeted(12, 1, make_test_encoder());
    let hold = hold_all(&budget);
    let restore = spawn_restore(&budget, 1);
    until("the restore queues", || budget.queued_waiters() == 1).await;
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await;
    })
    .await;
    let first = &tick_lines(&buf)[0];
    assert_eq!(
        field(first, "blocks"),
        Some(0),
        "nothing is prepared: {first}"
    );
    assert_eq!(field(first, "marked"), Some(12), "{first}");
    assert_eq!(field(first, "deferred_mem"), Some(12), "{first}");
    for b in 0..12u8 {
        assert_eq!(deferred_tick_of(&owner, &block_at(b)), Some(1), "block {b}");
    }
    assert!(
        owner.scheduler.last_attempted.lock().unwrap().is_empty(),
        "a marked block keeps its place in the order"
    );
    assert!(buf.text().contains("pos: blocks marked, memory queue busy"));

    let buf = logged(async {
        tick(&owner, &mut in_flight).await;
    })
    .await;
    let second = &tick_lines(&buf)[0];
    assert_eq!(
        field(second, "batch"),
        Some(12),
        "one batch for all: {second}"
    );
    assert_eq!(field(second, "waiting_mem"), Some(1), "{second}");
    until("the batch queues behind the restore", || {
        budget.priority_waiters(PriorityKind::OverduePos) == 1
    })
    .await;

    drop(hold);
    drop(restore.await.unwrap());
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(20)).await;
    assert_eq!(pending_len(&owner), 12, "all twelve are issued");
    assert_eq!(mark_count(&owner), 0);
}

/// M22′. A block too big for the free memory (the queue is empty) is marked and the tick goes on:
/// `memory_deferred_block_does_not_stop_the_tick` in `issue_mem` is this rule on real blocks.
/// Here: with the queue empty the marking branch is NOT taken (nothing waits, so `try_acquire` may
/// pass): a free budget prepares everything and marks nothing.
#[tokio::test]
async fn an_empty_queue_marks_nothing_and_prepares() {
    let (owner, _budget) = budgeted(3, 1, make_test_encoder());
    let mut in_flight = InFlight::default();
    let buf = logged(async {
        tick(&owner, &mut in_flight).await;
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(5)).await;
    })
    .await;
    let line = &tick_lines(&buf)[0];
    assert_eq!(field(line, "marked"), Some(0), "{line}");
    assert_eq!(field(line, "issued"), Some(3), "{line}");
}

// ─── One batch: one permit, sized by the largest ─────────────────────────────

/// M44′. N marks make ONE batch: one `granted kind=pos` for the batch (the hold is a worker's),
/// its bytes the largest need among the members, and every member is issued.
#[tokio::test]
async fn one_batch_serves_all_ripe_marks_under_one_permit_sized_by_the_largest() {
    let budget = MemBudget::new(TOTAL_MIB * MIB);
    let holder = make_identity(0x80);
    let mut owner = owner_with_encoder(
        900,
        SlowPostman::acking_after(Duration::from_millis(5)),
        make_test_encoder(),
        |db, dir| {
            // Big: k·t ≈ 640 KiB, a 3 MiB estimate. Small: 640 B, 1 MiB.
            seed_sized_block(dir, db, 1, 65_535);
            for seed in 2..5 {
                seed_sized_block(dir, db, seed, 64);
            }
        },
    );
    owner.scheduler.set_mem_budget(Arc::clone(&budget));
    freeze_batch_clock(&mut owner);
    for (seed, t) in [(1, 65_535), (2, 64), (3, 64), (4, 64)] {
        owner
            .db
            .upsert_placement(&make_placement(sized_block_id(seed, t), holder))
            .unwrap();
    }
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // four marks (the queue is empty, nothing fits)
        tick(&owner, &mut in_flight).await; // one batch
        drop(hold);
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    })
    .await;

    let granted: Vec<String> = buf
        .text()
        .lines()
        .filter(|l| l.contains("mem_budget: granted kind=pos"))
        .map(str::to_owned)
        .collect();
    assert_eq!(granted.len(), 1, "one permit for the batch: {granted:?}");
    let largest = estimate_pos_issue(TEST_K, 65_535);
    assert!(
        granted[0].contains(&format!("bytes={largest}")),
        "sized by the largest member ({largest} B): {}",
        granted[0]
    );
    assert_eq!(pending_len(&owner), 4, "every member is issued");
}

/// M57. After each member the permit is shrunk to the largest need among the members left: the
/// budget the batch holds when each member starts — 3 MiB, 1 MiB, 1 MiB for a big one first.
#[tokio::test]
async fn batch_shrinks_to_the_largest_remaining_need_after_each_member() {
    let budget = MemBudget::new(TOTAL_MIB * MIB);
    let holder = make_identity(0x80);
    let encoder = plain_encoder();
    let mut owner = owner_with_encoder(
        900,
        SlowPostman::acking_after(Duration::from_millis(5)),
        Arc::clone(&encoder) as _,
        |db, dir| {
            seed_sized_block(dir, db, 1, 65_535);
            seed_sized_block(dir, db, 2, 64);
            seed_sized_block(dir, db, 3, 64);
        },
    );
    owner.scheduler.set_mem_budget(Arc::clone(&budget));
    freeze_batch_clock(&mut owner);
    let blocks = [
        sized_block_id(1, 65_535),
        sized_block_id(2, 64),
        sized_block_id(3, 64),
    ];
    for b in blocks {
        owner
            .db
            .upsert_placement(&make_placement(b, holder))
            .unwrap();
    }
    let seen: Arc<Mutex<Vec<u64>>> = Arc::default();
    let (probe, record) = (Arc::clone(&budget), Arc::clone(&seen));
    encoder.set_hook(move |_| record.lock().unwrap().push(probe.outstanding_bytes()));
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    tick(&owner, &mut in_flight).await; // marks
    {
        // The big one first in the order.
        let mut attempted = owner.scheduler.last_attempted.lock().unwrap();
        attempted.insert((blocks[0], holder), Timestamp(1));
        attempted.insert((blocks[1], holder), Timestamp::now());
        attempted.insert((blocks[2], holder), Timestamp::now());
    }
    tick(&owner, &mut in_flight).await; // the batch
    drop(hold);
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;

    let big = estimate_pos_issue(TEST_K, 65_535);
    let small = permit_of_test_block();
    assert_eq!(
        *seen.lock().unwrap(),
        vec![big, small, small],
        "the batch holds the largest need of the members left"
    );
    assert_eq!(pending_len(&owner), 3);
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// M50. The batch has given its permit back by the time its results are handed over: nothing is
/// published under it (J12).
#[tokio::test]
async fn batch_publishes_after_releasing_its_permit() {
    let (owner, budget) = budgeted(2, 1, make_test_encoder());
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await;
    tick(&owner, &mut in_flight).await;
    drop(hold);

    let ended = tokio::time::timeout(Duration::from_secs(10), in_flight.join_next_any())
        .await
        .expect("the batch ends")
        .expect("something ended");
    let Ended::Batch(done) = ended else {
        panic!("a batch ends as a batch");
    };
    assert_eq!(done.len(), 2);
    assert_eq!(
        budget.outstanding_bytes(),
        0,
        "released before anything is published"
    );
    assert_eq!(pending_len(&owner), 0, "nothing is published yet");

    owner
        .scheduler
        .settle_ended(Ended::Batch(done), &mut in_flight)
        .await;
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(5)).await;
    assert_eq!(pending_len(&owner), 2);
}

// ─── At most one batch; only at the start of a tick ──────────────────────────

/// MR3, BLOCK-1. The place of the batch in flight is taken when it is ADOPTED, not when memory is
/// granted: while it waits, a block marked later does not make a second batch. At most one
/// `OverduePos` waiter stands in the budget's queue and nothing is outstanding but the hold.
#[tokio::test]
async fn at_most_one_overdue_waits_in_the_budget_queue() {
    let (owner, budget) = budgeted(2, 1, make_test_encoder());
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await; // marks A, B
    tick(&owner, &mut in_flight).await; // the batch (A, B) waits
    until("the batch queues", || {
        budget.priority_waiters(PriorityKind::OverduePos) == 1
    })
    .await;

    // A third block becomes due: marked on tick 3 (the queue is busy), ripe on tick 4.
    let c = seed_retained_pos_block(owner.data_dir(), &owner.db, 2);
    owner
        .db
        .upsert_placement(&make_placement(c, make_identity(0x80)))
        .unwrap();
    tick(&owner, &mut in_flight).await;
    assert_eq!(deferred_tick_of(&owner, &c), Some(3));
    tick(&owner, &mut in_flight).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(budget.priority_waiters(PriorityKind::OverduePos), 1);
    assert_eq!(budget.queued_waiters(), 1);
    assert_eq!(in_flight.preparing.waiting(), 1);
    assert_eq!(in_flight.preparing.batch_members(), 2, "C is not in it");
    assert_eq!(
        budget.outstanding_bytes(),
        TOTAL_MIB * MIB,
        "nothing but the hold"
    );
    in_flight.shutdown().await;
    drop(hold);
}

/// M52. One batch at a time, and a new one only at the START of a tick: when the batch ends, the
/// block marked meanwhile waits for the next tick — nothing chains at the publication.
#[tokio::test]
async fn at_most_one_batch_in_flight_and_only_at_tick_start() {
    let (owner, budget) = budgeted(2, 1, make_test_encoder());
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await;
    tick(&owner, &mut in_flight).await;
    until("the batch queues", || {
        budget.priority_waiters(PriorityKind::OverduePos) == 1
    })
    .await;
    let c = seed_retained_pos_block(owner.data_dir(), &owner.db, 2);
    owner
        .db
        .upsert_placement(&make_placement(c, make_identity(0x80)))
        .unwrap();
    tick(&owner, &mut in_flight).await; // C marked on tick 3
    // Tick 4: C is ripe, the first batch is still waiting for memory — no second one forms.
    tick(&owner, &mut in_flight).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        budget.priority_waiters(PriorityKind::OverduePos),
        1,
        "one batch at a time"
    );
    assert_eq!(in_flight.preparing.batch_members(), 2, "C is not in it");
    assert_eq!(deferred_tick_of(&owner, &c), Some(3));

    drop(hold);
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    assert_eq!(pending_len(&owner), 2, "the batch's blocks are issued");
    assert_eq!(in_flight.preparing.batch_members(), 0);
    assert!(!in_flight.preparing.batch_in_flight());
    assert_eq!(
        budget.priority_waiters(PriorityKind::OverduePos),
        0,
        "no batch started at the publication"
    );
    assert_eq!(deferred_tick_of(&owner, &c), Some(3), "C waits for a tick");

    tick(&owner, &mut in_flight).await; // tick 5: C's batch
    assert_eq!(in_flight.preparing.batch_members(), 1);
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    assert_eq!(pending_len(&owner), 3);
}

/// M53. The members of a batch are left alone by the ticks while the batch holds them: a tick
/// during the batch's work starts none of them (no second preparation of a block), counts their
/// placements as skipped, and marks nothing.
#[tokio::test]
async fn batch_members_are_excluded_from_ticks_until_returned() {
    let encoder = StallingEncoder::new(0, 1, Duration::from_millis(1500));
    let (owner, budget) = budgeted(3, 1, Arc::clone(&encoder) as _);
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await;
    tick(&owner, &mut in_flight).await; // the batch of three
    drop(hold);
    until("the first member works", || {
        in_flight.preparing.running() == 1 && encoder.calls.load(Ordering::SeqCst) == 1
    })
    .await;

    // The batch holds the permit and nobody waits: the budget is free for a tick's try_acquire,
    // so a member the ticks could start would be prepared a second time.
    let buf = logged(async {
        tick(&owner, &mut in_flight).await;
    })
    .await;
    let line = &tick_lines(&buf)[0];
    assert_eq!(field(line, "blocks"), Some(0), "{line}");
    assert_eq!(field(line, "skipped_pending"), Some(3), "{line}");
    assert_eq!(field(line, "deferred_mem"), Some(0), "{line}");

    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        3,
        "each block was prepared once"
    );
    assert_eq!(pending_len(&owner), 3);
}

// ─── The limits of a batch (injected P and clock) ────────────────────────────

/// M51. A batch works at most half a period from the grant: with P = 100 s and 20 s per member the
/// fourth member would start at 60 s ≥ 50 s. Three are served; the other two stay marked, are not
/// held by the batch any more, and go first into the next batch.
#[tokio::test]
async fn batch_stops_at_half_a_period_and_returns_unstarted_members_to_marks() {
    let (owner, budget, _clock, encoder) = on_a_fake_clock(5, Duration::from_secs(20));
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // five marks
        tick(&owner, &mut in_flight).await; // the batch, its tick starts at 0
        drop(hold);
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    })
    .await;

    assert_eq!(encoder.calls.load(Ordering::SeqCst), 3, "three members");
    assert_eq!(pending_len(&owner), 3);
    assert_eq!(mark_count(&owner), 2, "the other two are marked again");
    assert!(
        in_flight.preparing.blocks().is_empty(),
        "no longer held by the batch: the ticks may take them"
    );
    assert!(
        buf.text().contains("half a period of work"),
        "{}",
        buf.text()
    );

    // The next batch takes the two that were returned.
    tick(&owner, &mut in_flight).await;
    assert_eq!(in_flight.preparing.batch_members(), 2);
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    assert_eq!(pending_len(&owner), 5);
    assert_eq!(mark_count(&owner), 0);
}

/// M55. No member starts later than 0.9 of a period from the start of the tick that formed the
/// batch, whatever the wait for memory took: P = 100 s, the memory comes at 60 s (T_ahead above
/// P/2), 15 s per member. The first starts at 60 s, the second at 75 s, the third would start at
/// 90 s — not started. The batch ends at 90 s, before the next tick (100 s).
#[tokio::test]
async fn batch_starts_no_member_after_nine_tenths_of_the_period() {
    let (owner, budget, clock, encoder) = on_a_fake_clock(4, Duration::from_secs(15));
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await;
    let tick_start = {
        tick(&owner, &mut in_flight).await; // the batch; its tick starts at the clock's 0
        clock.now()
    };
    until("the batch queues", || {
        budget.priority_waiters(PriorityKind::OverduePos) == 1
    })
    .await;
    clock.advance(Duration::from_secs(60)); // the wait for memory
    drop(hold);
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;

    assert_eq!(encoder.calls.load(Ordering::SeqCst), 2, "two members only");
    assert_eq!(pending_len(&owner), 2);
    assert_eq!(mark_count(&owner), 2);
    assert!(
        clock.now() <= tick_start + Duration::from_secs(100),
        "the batch ends before the next tick"
    );
}

/// M56. Between members the batch ends for a restore that does not fit beside it (Q-V8, (a)):
/// the first member is prepared, the restore is granted, the rest goes back to the marks and is
/// served by the next batch.
#[tokio::test]
async fn batch_ends_between_members_for_a_restore_that_does_not_fit_beside_it() {
    let (owner, budget) = budgeted(3, 1, make_test_encoder());
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    let buf = logged(async {
        tick(&owner, &mut in_flight).await;
        tick(&owner, &mut in_flight).await; // the batch (1 MiB) waits
        until("the batch queues", || {
            budget.priority_waiters(PriorityKind::OverduePos) == 1
        })
        .await;
        // A restore of the whole budget queues behind it: 100 > 100 - 1, never beside the batch.
        let restore = spawn_restore(&budget, TOTAL_MIB);
        until("the restore queues", || budget.queued_waiters() == 2).await;

        drop(hold);
        let granted = tokio::time::timeout(Duration::from_secs(10), restore)
            .await
            .expect("the restore gets its memory once the batch ends")
            .unwrap();
        drop(granted);
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    })
    .await;

    let text = buf.text();
    assert!(
        text.contains("reason=a restore does not fit beside it served="),
        "the restore itself is the reason, nobody ahead of it: {text}"
    );
    assert_eq!(pending_len(&owner), 1, "one member before the restore");
    assert_eq!(mark_count(&owner), 2, "two are marked again");

    // The restore is done: the next batch serves the two.
    tick(&owner, &mut in_flight).await;
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    assert_eq!(pending_len(&owner), 3);
}

/// M93 (v3.12a; lesson of v3.12: completion within N). A restore that does not fit beside the
/// batch ends EVERY batch after its first member. Five marks of an earlier tick (the ones due
/// longest) and six blocks that arrive marked a tick later: the members the batch returns keep
/// their marks and go first, so a mark of rank r is published within r + 1 ticks, however many
/// newer ones keep coming — all five within six ticks. Returned members at the END of the order
/// (the newest marks first) would let the newer ones overtake them every tick, for ever.
#[tokio::test]
async fn every_mark_is_published_within_rank_plus_one_ticks_when_restore_cuts_each_batch() {
    let (owner, budget) = budgeted_at(1, 11, 1, make_test_encoder());
    let holder = make_identity(0x80);
    // Blocks 0..5 were marked on tick 0; 5..11 are marked by tick 1 and stay newer.
    for b in 0..5u8 {
        owner.scheduler.note_mem_deferred(block_at(b), 0);
    }
    let published = |owner: &super::issue_support::Owner| -> usize {
        let pending = owner.pending.try_lock().expect("the pending index");
        (0..5u8)
            .filter(|&b| pending.contains_key(&(block_at(b), holder)))
            .count()
    };
    let mut in_flight = InFlight::default();

    for tick_no in 1..=6usize {
        let hold = hold_all(&budget);
        tick(&owner, &mut in_flight).await; // the batch of every ripe mark, behind the hold
        until("the batch queues", || {
            budget.priority_waiters(PriorityKind::OverduePos) == 1
        })
        .await;
        // A restore of the whole budget queues behind it: it never fits beside the batch.
        let restore = spawn_restore(&budget, TOTAL_MIB);
        until("the restore queues", || budget.queued_waiters() == 2).await;
        drop(hold);
        let granted = tokio::time::timeout(Duration::from_secs(10), restore)
            .await
            .expect("the restore gets its memory once the batch's first member is done")
            .unwrap();
        drop(granted);
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
        assert!(
            published(&owner) >= tick_no.min(5),
            "tick {tick_no}: {} of the five old marks are published",
            published(&owner)
        );
    }
    assert_eq!(published(&owner), 5, "all five within six ticks");
}

/// MR-R3 (WARN-3b). The batch yields only to a RESTORE (Q-V8, (a)): a worker waiting in the queue
/// behind it, however big, does not end it between members — the worker takes the budget when the
/// batch is done, as before. All three members are served.
#[tokio::test]
async fn batch_does_not_end_for_a_worker_in_the_queue() {
    let (owner, budget) = budgeted(3, 1, make_test_encoder());
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    let mut worker = None;
    let buf = logged(async {
        tick(&owner, &mut in_flight).await;
        tick(&owner, &mut in_flight).await; // the batch waits
        until("the batch queues", || {
            budget.priority_waiters(PriorityKind::OverduePos) == 1
        })
        .await;
        // A worker for the whole budget queues behind the batch: it never fits beside it.
        worker = Some({
            let budget = Arc::clone(&budget);
            tokio::spawn(async move {
                budget
                    .acquire_plain(
                        HolderKind::Worker,
                        &SourceBlockId([0xAC; 32]),
                        TOTAL_MIB * MIB,
                    )
                    .await
            })
        });
        until("the worker queues", || budget.queued_waiters() == 2).await;

        drop(hold);
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    })
    .await;

    assert_eq!(pending_len(&owner), 3, "no member was left for a worker");
    assert_eq!(mark_count(&owner), 0);
    assert!(
        !buf.text().contains("overdue batch ended early"),
        "{}",
        buf.text()
    );
    let granted = tokio::time::timeout(Duration::from_secs(10), worker.unwrap())
        .await
        .expect("the worker is served once the batch is done")
        .unwrap();
    drop(granted);
}

/// NOTE 5a. The rule counts everyone AHEAD of the restore (spec v3.7a: `max need(1..i)`): a worker
/// that stands before it and does not fit beside the batch ends the batch for the restore behind
/// it — and the line says so (`ahead: worker`), not that the restore does not fit.
#[tokio::test]
async fn batch_yield_names_the_worker_that_stands_ahead_of_the_restore() {
    let (owner, budget) = budgeted(3, 1, make_test_encoder());
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    let buf = logged(async {
        tick(&owner, &mut in_flight).await;
        tick(&owner, &mut in_flight).await; // the batch waits
        until("the batch queues", || {
            budget.priority_waiters(PriorityKind::OverduePos) == 1
        })
        .await;
        let worker = {
            let budget = Arc::clone(&budget);
            tokio::spawn(async move {
                budget
                    .acquire_plain(
                        HolderKind::Worker,
                        &SourceBlockId([0xAC; 32]),
                        TOTAL_MIB * MIB,
                    )
                    .await
            })
        };
        until("the worker queues", || budget.queued_waiters() == 2).await;
        // The restore itself is small: beside the batch it would fit.
        let restore = spawn_restore(&budget, 1);
        until("the restore queues", || budget.queued_waiters() == 3).await;

        drop(hold);
        let granted = tokio::time::timeout(Duration::from_secs(10), worker)
            .await
            .expect("the worker is served once the batch ends")
            .unwrap();
        drop(granted);
        drop(
            tokio::time::timeout(Duration::from_secs(10), restore)
                .await
                .expect("the restore is served")
                .unwrap(),
        );
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    })
    .await;

    let text = buf.text();
    assert!(
        text.contains("reason=a restore does not fit beside it (ahead: worker)"),
        "{text}"
    );
    assert_eq!(pending_len(&owner), 1, "one member, then the batch ends");
}

/// WARN-2 (MR-R6). "At least one member always": the memory comes after 0.9 of the period (here at
/// 95 s of 100), when no further member may start — the first still does, and only it.
#[tokio::test]
async fn memory_granted_after_nine_tenths_of_the_period_still_serves_exactly_one_member() {
    let (owner, budget, clock, encoder) = on_a_fake_clock(4, Duration::from_secs(1));
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await;
    tick(&owner, &mut in_flight).await; // the batch; its tick starts at the clock's 0
    until("the batch queues", || {
        budget.priority_waiters(PriorityKind::OverduePos) == 1
    })
    .await;
    clock.advance(Duration::from_secs(95)); // the wait for memory
    drop(hold);
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;

    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        1,
        "exactly one member"
    );
    assert_eq!(pending_len(&owner), 1);
    assert_eq!(mark_count(&owner), 3, "the rest is marked again");
}

/// NOTE 5b. A grant that comes at once is not a wait: no "waiting for memory" line (a wait that
/// is real prints it, as the worker's does).
#[tokio::test]
async fn batch_granted_at_once_prints_no_waiting_line() {
    let (owner, budget) = budgeted(2, 1, make_test_encoder());
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    let restore = spawn_restore(&budget, 1);
    until("the restore queues", || budget.queued_waiters() == 1).await;

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // the queue is busy: both marked
        drop(hold);
        drop(
            tokio::time::timeout(Duration::from_secs(10), restore)
                .await
                .expect("the restore is served")
                .unwrap(),
        );
        assert_eq!(mark_count(&owner), 2);
        tick(&owner, &mut in_flight).await; // the batch; the budget is free
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    })
    .await;

    assert_eq!(pending_len(&owner), 2, "the batch served both");
    assert!(
        !buf.text().contains("overdue batch waiting for memory"),
        "{}",
        buf.text()
    );
}

// ─── A written-off batch (WARN-1, M54) ───────────────────────────────────────

/// M54. A batch whose member hangs in its load is written off after H periods: the permit goes
/// back, it no longer holds the place of the batch in flight, the members it did not start return
/// to the marks AT ONCE (the next tick forms a new batch with them), and when the hung read
/// returns it starts no further member.
#[tokio::test]
async fn written_off_batch_takes_no_next_member_and_returns_the_rest() {
    let encoder = plain_encoder();
    let (owner, budget) = budgeted(2, 1, Arc::clone(&encoder) as _);
    let (x, y) = (block_at(0), block_at(1));
    let holder = make_identity(0x80);
    let path = crate::daemon::system_state::block::retained_block_path(owner.data_dir(), &x);
    std::fs::remove_file(&path).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let unblock = super::issue_mem::Unblock::new(path);
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // X and Y marked
        {
            // X first in the order.
            let mut attempted = owner.scheduler.last_attempted.lock().unwrap();
            attempted.insert((x, holder), Timestamp(1));
            attempted.insert((y, holder), Timestamp::now());
        }
        tick(&owner, &mut in_flight).await; // the batch (X, Y)
        drop(hold);
        // X's read hangs; ten periods of work later the watch writes the batch off.
        let later = Instant::now() + Duration::from_secs(11);
        until("the batch is written off", || {
            in_flight.preparing.watch_stuck(
                later,
                Duration::from_secs(1),
                10,
                Duration::ZERO,
                &budget,
                true,
            );
            budget.outstanding_bytes() == 0 && in_flight.preparing.running() == 1
        })
        .await;
        assert!(
            !in_flight.preparing.batch_in_flight(),
            "a written-off batch gives up its place"
        );
        let held = in_flight.preparing.blocks();
        assert!(held.contains(&x), "the hung member stays held");
        assert!(!held.contains(&y), "the unstarted member is back at once");

        // The next tick forms a batch with Y; the old one is still stuck in X.
        tick(&owner, &mut in_flight).await;
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(2)).await;
        assert_eq!(encoder.calls.load(Ordering::SeqCst), 1, "Y was prepared");

        // The read returns: the old batch ends X (not the block: nothing to serve) and starts
        // nothing more.
        // Bounded, whatever a broken rule does: a batch started by the publication would read the
        // same FIFO again and hang the runtime's shutdown, so every reader is let go.
        unblock.release_all(Duration::from_secs(1));
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(5)).await;
    })
    .await;

    assert!(
        buf.text().contains("written off a stuck holder"),
        "{}",
        buf.text()
    );
    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        1,
        "Y was not prepared a second time by the written-off batch"
    );
    assert_eq!(pending_len(&owner), 1, "Y alone is issued");
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// M45. The write-off waits for the REAL-time floor: with P = 1 s and H = 10 a load that has hung
/// for 11 s is named (the WARN stays at H·P) but not written off; at the floor (600 s) it is.
#[tokio::test]
async fn write_off_waits_for_the_real_time_floor() {
    let (owner, budget) = budgeted(1, 1, make_test_encoder());
    let block = block_at(0);
    let path = crate::daemon::system_state::block::retained_block_path(owner.data_dir(), &block);
    std::fs::remove_file(&path).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let unblock = super::issue_mem::Unblock::new(path);
    let mut in_flight = InFlight::default();
    let floor = Duration::from_secs(600);

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // the read hangs; the tick cuts the block
        assert_eq!(in_flight.preparing.running(), 1);

        let at_h = Instant::now() + Duration::from_secs(11);
        in_flight
            .preparing
            .watch_stuck(at_h, Duration::from_secs(1), 10, floor, &budget, true);
        assert_eq!(
            budget.outstanding_bytes(),
            permit_of_test_block(),
            "H periods are not enough: the floor is real time"
        );

        let at_floor = Instant::now() + Duration::from_secs(601);
        in_flight
            .preparing
            .watch_stuck(at_floor, Duration::from_secs(1), 10, floor, &budget, true);
        assert_eq!(budget.outstanding_bytes(), 0, "written off at the floor");

        unblock.now();
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    })
    .await;

    let text = buf.text();
    assert!(text.contains("PoS preparation still running"), "{text}");
    assert_eq!(text.matches("written off a stuck holder").count(), 1);
}

// ─── Marks and failures ──────────────────────────────────────────────────────

/// MR4, WARN-3. A mark is stale — and dropped — when its block is no longer due, and when a tick
/// served the block: neither is taken into a batch. Here A leaves the placements (no longer
/// challengeable) while B, still due, keeps the ticks going; C is served by an ordinary tick.
#[tokio::test]
async fn stale_marks_are_dropped_when_the_block_is_no_longer_due_or_served_by_a_tick() {
    let (owner, budget) = budgeted(3, 1, make_test_encoder());
    let (a, c) = (block_at(0), block_at(2));
    let holder = make_identity(0x80);
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await; // A, B, C marked on tick 1
    assert_eq!(mark_count(&owner), 3);

    owner.db.delete_placement(&a, &holder).unwrap();
    // C's last load failed: it is not taken into a batch, the ticks try it.
    owner
        .scheduler
        .load_failed
        .lock()
        .unwrap()
        .insert(c, std::time::Instant::now() + Duration::from_secs(3600));
    drop(hold);
    tick(&owner, &mut in_flight).await; // tick 2: A is stale; B batched; C served by this tick
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;

    assert_eq!(deferred_tick_of(&owner, &a), None, "A is no longer due");
    assert_eq!(deferred_tick_of(&owner, &c), None, "C was served by a tick");
    assert!(!in_flight.preparing.blocks().contains(&a));
    assert_eq!(pending_len(&owner), 2, "B by the batch, C by the tick");
}

/// MR5 (NOTE 1). The permit is gone before a holder's master is looked up: nothing is held while
/// the database is read — on the tick's path and on the batch's.
#[tokio::test]
async fn permit_is_released_before_master_lookup() {
    // The tick's own preparation.
    let (owner, budget) = budgeted(1, 2, make_test_encoder());
    let seen: Arc<Mutex<Vec<u64>>> = Arc::default();
    let (probe, record) = (Arc::clone(&budget), Arc::clone(&seen));
    *owner.scheduler.master_lookup_hook.lock().unwrap() = Some(Arc::new(move || {
        record.lock().unwrap().push(probe.outstanding_bytes());
    }));
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await;
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(5)).await;
    assert_eq!(*seen.lock().unwrap(), vec![0, 0], "the tick's lookups");

    // A batch member's.
    let (owner, budget) = budgeted(2, 1, make_test_encoder());
    let seen: Arc<Mutex<Vec<u64>>> = Arc::default();
    let (probe, record) = (Arc::clone(&budget), Arc::clone(&seen));
    *owner.scheduler.master_lookup_hook.lock().unwrap() = Some(Arc::new(move || {
        record.lock().unwrap().push(probe.outstanding_bytes());
    }));
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await;
    tick(&owner, &mut in_flight).await;
    drop(hold);
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    assert_eq!(*seen.lock().unwrap(), vec![0, 0], "the batch's lookups");
    assert_eq!(pending_len(&owner), 2);
}

/// M47 (NOTE 4). A preparation whose task panics is named; its mark and its place are cleared and
/// it waits one period (`load_failed`) — in a batch and in a tick alike. The permit is gone.
#[tokio::test]
async fn overdue_join_error_clears_the_mark_and_frees_the_place() {
    // A batch member panics.
    let encoder = plain_encoder();
    encoder.set_hook(|_| panic!("the encoder panics"));
    let (owner, budget) = budgeted(1, 1, Arc::clone(&encoder) as _);
    let block = block_at(0);
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    let buf = logged(async {
        tick(&owner, &mut in_flight).await;
        assert_eq!(deferred_tick_of(&owner, &block), Some(1));
        tick(&owner, &mut in_flight).await;
        drop(hold);
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    })
    .await;
    assert!(
        buf.text().contains("PoS hash compute task failed"),
        "{}",
        buf.text()
    );
    assert_eq!(
        deferred_tick_of(&owner, &block),
        None,
        "the mark is cleared"
    );
    assert!(!in_flight.preparing.batch_in_flight(), "the place is free");
    assert!(in_flight.preparing.blocks().is_empty());
    assert!(
        owner
            .scheduler
            .load_failed
            .lock()
            .unwrap()
            .contains_key(&block),
        "it waits one period"
    );
    assert_eq!(budget.outstanding_bytes(), 0);
    assert_eq!(pending_len(&owner), 0);

    // A tick's own preparation panics.
    let encoder = plain_encoder();
    encoder.set_hook(|_| panic!("the encoder panics"));
    let (owner, budget) = budgeted(1, 1, Arc::clone(&encoder) as _);
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await;
    assert!(
        owner
            .scheduler
            .load_failed
            .lock()
            .unwrap()
            .contains_key(&block)
    );
    assert_eq!(budget.outstanding_bytes(), 0);
    assert_eq!(mark_count(&owner), 0);
}

/// WARN-4 (v3.7). A batch member whose sources are gone fails at once, by `metadata`, before any
/// read: `load_failed` for a day, the load-failure WARN, no encode, its mark cleared — and it is
/// not marked into a batch again meanwhile.
#[tokio::test]
async fn batch_member_with_missing_sources_fails_at_once_with_load_failed_for_a_day() {
    let encoder = plain_encoder();
    let (owner, budget) = budgeted(0, 0, Arc::clone(&encoder) as _);
    let doomed = SourceBlockId([0x56; 32]);
    owner
        .db
        .upsert_source_block(&super::make_source_block_record(doomed))
        .unwrap();
    owner
        .db
        .upsert_placement(&make_placement(doomed, make_identity(0x80)))
        .unwrap();
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // marked
        assert_eq!(deferred_tick_of(&owner, &doomed), Some(1));
        tick(&owner, &mut in_flight).await; // the batch
        drop(hold);
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(5)).await;
    })
    .await;

    assert_eq!(encoder.calls.load(Ordering::SeqCst), 0, "nothing was read");
    assert_eq!(
        deferred_tick_of(&owner, &doomed),
        None,
        "the episode is closed"
    );
    let until_when = *owner
        .scheduler
        .load_failed
        .lock()
        .unwrap()
        .get(&doomed)
        .expect("load_failed is set");
    assert!(
        until_when > std::time::Instant::now() + Duration::from_secs(86_000),
        "a day, not a period"
    );
    let text = buf.text();
    assert!(
        text.contains("cannot load source block for PoS hash"),
        "{text}"
    );
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// WARN-3 (v3.7). A marked block whose own tick preparation was cut is held in `preparing`, so no
/// batch takes it while that preparation runs.
#[tokio::test]
async fn marked_block_cut_by_its_tick_preparation_is_not_batched_while_it_runs() {
    let encoder = StallingEncoder::new(0, 1, Duration::from_millis(1500));
    let (owner, budget) = budgeted(1, 1, encoder);
    let block = block_at(0);
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await; // marked (nothing fits)
    assert_eq!(deferred_tick_of(&owner, &block), Some(1));
    // Out of the batches for now: the ticks try the block themselves.
    owner
        .scheduler
        .load_failed
        .lock()
        .unwrap()
        .insert(block, std::time::Instant::now() + Duration::from_secs(3600));
    drop(hold);
    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // its preparation stalls and is cut
    })
    .await;
    let line = &tick_lines(&buf)[0];
    assert_eq!(field(line, "cut_blocks"), Some(1), "{line}");

    // Now it could be batched (ripe, not failed) — but it is preparing.
    owner.scheduler.load_failed.lock().unwrap().clear();
    tick(&owner, &mut in_flight).await;
    assert_eq!(in_flight.preparing.batch_members(), 0, "not in a batch");
    assert_eq!(in_flight.preparing.waiting(), 0);
    assert_eq!(in_flight.preparing.tick_started(), 1, "its own preparation");

    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    assert_eq!(pending_len(&owner), 1);
    assert_eq!(deferred_tick_of(&owner, &block), None);
}

// ─── A member that fails on its own (BLOCK-1, WARN-1 of round 2) ─────────────

/// A `metadata` that does not return: the first call of the hook blocks until released (the guard
/// releases it also when the test fails, so the runtime's shutdown does not wait for it).
struct HungMetadata {
    gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
    entered: Arc<std::sync::atomic::AtomicBool>,
}

impl HungMetadata {
    fn install(owner: &super::issue_support::Owner) -> Self {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (hook_gate, hook_entered) = (Arc::clone(&gate), Arc::clone(&entered));
        *owner.scheduler.precheck_hook.lock().unwrap() = Some(Arc::new(move || {
            if hook_entered.swap(true, Ordering::SeqCst) {
                return; // only the first member's check hangs
            }
            let (open, cv) = &*hook_gate;
            let mut open = open.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
        }));
        HungMetadata { gate, entered }
    }

    fn entered(&self) -> bool {
        self.entered.load(Ordering::SeqCst)
    }

    fn release(&self) {
        let (open, cv) = &*self.gate;
        *open.lock().unwrap() = true;
        cv.notify_all();
    }
}

impl Drop for HungMetadata {
    fn drop(&mut self) {
        self.release();
    }
}

/// BLOCK-1 (round 2; M57). A batch member whose `metadata` hangs (a dead NAS: the `stat` sits in
/// D-state) is a hang in the LOAD phase: the write-off reaches it at the floor, the permit goes
/// back, the batch gives up its place and the member it did not start returns to the marks.
/// (The check ran in phase Start before, which the write-off never touches: the batch held the
/// place for ever.)
#[tokio::test]
async fn hung_metadata_of_a_batch_member_is_written_off_after_the_floor() {
    let encoder = plain_encoder();
    let (owner, budget) = budgeted(2, 1, Arc::clone(&encoder) as _);
    let hung = HungMetadata::install(&owner);
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    let floor = Duration::from_secs(600);

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // both marked
        tick(&owner, &mut in_flight).await; // the batch
        drop(hold);
        until("the first member's check hangs", || hung.entered()).await;
        assert!(in_flight.preparing.batch_in_flight());

        let at_h = Instant::now() + Duration::from_secs(11);
        in_flight
            .preparing
            .watch_stuck(at_h, Duration::from_secs(1), 10, floor, &budget, true);
        assert_eq!(
            budget.outstanding_bytes(),
            permit_of_test_block(),
            "H periods are not enough: the floor is real time"
        );

        let at_floor = Instant::now() + Duration::from_secs(601);
        in_flight
            .preparing
            .watch_stuck(at_floor, Duration::from_secs(1), 10, floor, &budget, true);
        assert_eq!(budget.outstanding_bytes(), 0, "written off at the floor");
        assert!(
            !in_flight.preparing.batch_in_flight(),
            "a written-off batch gives up its place"
        );
        assert_eq!(
            in_flight.preparing.batch_members(),
            1,
            "the member it did not start is back at once"
        );

        hung.release();
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    })
    .await;

    let text = buf.text();
    assert!(text.contains("written off a stuck holder"), "{text}");
    assert!(text.contains("phase=load"), "{text}");
    assert_eq!(budget.outstanding_bytes(), 0);
    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        1,
        "the freed check went on, and the batch started no more"
    );
}

/// WARN-1 (round 2; M58). A member that panics fails alone: its block waits one period and its
/// mark is cleared; the next member of the batch is prepared and published, nobody else is
/// punished (pos-i13: a block that always panics must not starve the others).
#[tokio::test]
async fn a_member_that_panics_fails_alone_and_the_next_one_is_published() {
    let encoder = plain_encoder();
    encoder.set_hook(|call| {
        if call == 0 {
            panic!("the first member panics");
        }
    });
    let (owner, budget) = budgeted(2, 1, Arc::clone(&encoder) as _);
    let (x, y) = (block_at(0), block_at(1));
    let holder = make_identity(0x80);
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // X and Y marked
        {
            // X first in the order.
            let mut attempted = owner.scheduler.last_attempted.lock().unwrap();
            attempted.insert((x, holder), Timestamp(1));
            attempted.insert((y, holder), Timestamp::now());
        }
        tick(&owner, &mut in_flight).await; // the batch (X, Y)
        drop(hold);
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    })
    .await;

    let text = buf.text();
    assert!(text.contains("PoS hash compute task failed"), "{text}");
    assert_eq!(encoder.calls.load(Ordering::SeqCst), 2, "Y was prepared");
    assert_eq!(pending_len(&owner), 1, "Y is published");
    let failed = owner.scheduler.load_failed.lock().unwrap();
    assert!(failed.contains_key(&x), "X waits one period");
    assert!(!failed.contains_key(&y), "Y is not punished");
    drop(failed);
    assert_eq!(mark_count(&owner), 0, "both episodes are closed");
    assert!(!in_flight.preparing.batch_in_flight());
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// WARN-1 (round 2; M59). A failure of the batch's blocking task OUTSIDE a member's turn (here the
/// batch's clock panics before the third member) does not punish the whole batch: the members
/// through are published, the one not started goes back to the marks, nobody is failed.
#[tokio::test]
async fn a_failure_outside_a_member_publishes_the_ready_and_returns_the_rest() {
    let (mut owner, budget) = budgeted(3, 1, make_test_encoder());
    let calls = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&calls);
    let frozen = StdInstant::now();
    owner.scheduler.set_batch_clock(Arc::new(move || {
        // 0, 1: the two ticks' starts; 2: the grant; 3: before member 2; 4: before member 3.
        if counted.fetch_add(1, Ordering::SeqCst) == 4 {
            panic!("the clock fails");
        }
        frozen
    }));
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    tick(&owner, &mut in_flight).await;
    tick(&owner, &mut in_flight).await; // the batch of three
    drop(hold);
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;

    assert_eq!(pending_len(&owner), 2, "the two that were through");
    assert_eq!(mark_count(&owner), 1, "the third is marked again");
    assert!(
        owner.scheduler.load_failed.lock().unwrap().is_empty(),
        "nobody is punished"
    );
    assert!(!in_flight.preparing.batch_in_flight());
    assert!(in_flight.preparing.blocks().is_empty());
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// A panic payload whose drop panics: the batch catches the member's panic, and the failure
/// comes later, in the handling of it — after `try_start`, before the member is staged.
struct PanicOnDrop;

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            panic!("the payload of the member's panic fails to drop");
        }
    }
}

/// K-b2b round 3. A failure of the batch's task AFTER a member was started and BEFORE it was
/// staged (here the handling of the member's own panic): the penalty — `load_failed` for a period,
/// the mark cleared — falls on exactly that member (`current()`), nobody else. The member through
/// before it is published, the one not started goes back to the marks.
#[tokio::test]
async fn a_failure_between_start_and_staging_penalizes_exactly_the_current_member() {
    let encoder = plain_encoder();
    encoder.set_hook(|call| {
        if call == 1 {
            std::panic::panic_any(PanicOnDrop);
        }
    });
    let (owner, budget) = budgeted(3, 1, Arc::clone(&encoder) as _);
    let (x, y, z) = (block_at(0), block_at(1), block_at(2));
    let holder = make_identity(0x80);
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    tick(&owner, &mut in_flight).await; // X, Y, Z marked
    {
        // X, Y, Z in this order.
        let mut attempted = owner.scheduler.last_attempted.lock().unwrap();
        attempted.insert((x, holder), Timestamp(1));
        attempted.insert((y, holder), Timestamp(2));
        attempted.insert((z, holder), Timestamp::now());
    }
    tick(&owner, &mut in_flight).await; // the batch (X, Y, Z)
    drop(hold);
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;

    assert_eq!(encoder.calls.load(Ordering::SeqCst), 2, "Z was not started");
    let failed: Vec<SourceBlockId> = owner
        .scheduler
        .load_failed
        .lock()
        .unwrap()
        .keys()
        .copied()
        .collect();
    assert_eq!(
        failed,
        vec![y],
        "only the member the task was on is penalized"
    );
    assert_eq!(pending_len(&owner), 1, "X, which was through, is published");
    assert_eq!(mark_count(&owner), 1, "only Z is marked again");
    assert_eq!(deferred_tick_of(&owner, &y), None, "Y's mark is cleared");
    assert!(deferred_tick_of(&owner, &z).is_some(), "Z is marked");
    assert!(!in_flight.preparing.batch_in_flight());
    assert!(in_flight.preparing.blocks().is_empty());
    assert_eq!(budget.outstanding_bytes(), 0);
}
