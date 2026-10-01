// R1-d-b (backup-i24, pos-i13, pos-i7-d-c, pos-i7-d-d): the PoS issue tick under the block work
// memory budget. A preparation takes its permit itself by `try_acquire` and gives it back before
// anything is published; a busy budget marks the block, and from the NEXT tick the marked blocks
// are prepared by one batch (by tick number, not by clock) that does not count in K; a load that
// hangs gives its memory back (variant (a)). The batch itself — one permit, the members one after
// the other, its limits — is in `issue_batch`.
//
// Every test runs the REAL tick (`issue_tick`) on a real owner; the run loop's part — settling
// what ends — is driven by hand, as in `issue_prepare`.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;
use tracing::instrument::WithSubscriber;
use viaticum_core::erasure::ErasureEncoder;
use viaticum_core::types::{SourceBlockId, Timestamp};

use super::issue_stall::StallingEncoder;
use super::issue_support::{Owner, SlowPostman, owner_with_encoder, seed_due};
use super::pos_scale::{LogBuf, field};
use super::{
    TEST_K, TEST_T, make_identity, make_placement, make_source_block_record, make_test_encoder,
    pos_block_bytes, seed_retained_pos_block,
};
use crate::daemon::mem_budget::{
    HolderKind, MemBudget, MemPermit, PriorityKind, estimate_pos_issue,
};
use crate::daemon::scheduler::issue::{Ended, InFlight, PrepOutcome, load_failed_until};

pub(super) const MIB: u64 = 1 << 20;
/// The permit of a PoS preparation of a test block (`k·t` = 640 B): one MiB, the estimate's floor.
pub(super) fn permit_of_test_block() -> u64 {
    estimate_pos_issue(TEST_K, TEST_T)
}

/// The budget of these tests: generous, so only what a test holds makes it busy.
pub(super) const TOTAL_MIB: u64 = 100;

/// The block `seed_due` makes at index `b`.
pub(super) fn block_at(b: u8) -> SourceBlockId {
    SourceBlockId(*blake3::hash(&pos_block_bytes(b)).as_bytes())
}

pub(super) fn capture() -> (LogBuf, tracing::Dispatch) {
    let buf = LogBuf::default();
    let writer = buf.clone();
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    );
    (buf, dispatch)
}

/// Run `body` with its log captured.
pub(super) async fn logged<F: Future<Output = ()>>(body: F) -> LogBuf {
    let (buf, dispatch) = capture();
    body.with_subscriber(dispatch).await;
    buf
}

pub(super) fn tick_lines(buf: &LogBuf) -> Vec<String> {
    buf.text()
        .lines()
        .filter(|l| l.contains("scheduler: PoS issue tick"))
        .map(str::to_owned)
        .collect()
}

/// An owner with `blocks` × `holders` due placements, sharing the returned budget.
pub(super) fn budgeted(
    blocks: u8,
    holders: u8,
    encoder: Arc<dyn ErasureEncoder>,
) -> (Owner, Arc<MemBudget>) {
    budgeted_at(900, blocks, holders, encoder)
}

/// `budgeted` at `time_scale` (the period of the tick is 3600 / `time_scale` s).
pub(super) fn budgeted_at(
    time_scale: u64,
    blocks: u8,
    holders: u8,
    encoder: Arc<dyn ErasureEncoder>,
) -> (Owner, Arc<MemBudget>) {
    let budget = MemBudget::new(TOTAL_MIB * MIB);
    let mut owner = owner_with_encoder(
        time_scale,
        SlowPostman::acking_after(Duration::from_millis(5)),
        encoder,
        |db, dir| seed_due(db, dir, blocks, holders),
    );
    owner.scheduler.set_mem_budget(Arc::clone(&budget));
    (owner, budget)
}

/// Take the whole budget: a busy worker.
pub(super) fn hold_all(budget: &Arc<MemBudget>) -> MemPermit {
    budget
        .try_acquire(
            HolderKind::Worker,
            &SourceBlockId([0xEE; 32]),
            TOTAL_MIB * MIB,
        )
        .expect("a free budget")
}

pub(super) async fn tick(owner: &Owner, in_flight: &mut InFlight) {
    owner.scheduler.issue_tick(in_flight).await.expect("tick");
}

/// The run loop's settling: whatever ends within `cap`, until nothing is in flight.
pub(super) async fn settle_until_idle(owner: &Owner, in_flight: &mut InFlight, cap: Duration) {
    let until = Instant::now() + cap;
    while let Ok(Some(ended)) = tokio::time::timeout_at(until, in_flight.join_next_any()).await {
        owner.scheduler.settle_ended(ended, in_flight).await;
    }
}

/// Wait (with a deadline) until `cond` holds.
pub(super) async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub(super) fn pending_len(owner: &Owner) -> usize {
    owner.pending.try_lock().map(|g| g.len()).unwrap_or(0)
}

pub(super) fn deferred_tick_of(owner: &Owner, block: &SourceBlockId) -> Option<u64> {
    owner
        .scheduler
        .mem_deferred_at
        .lock()
        .unwrap()
        .get(block)
        .copied()
}

// ─── The deferral ─────────────────────────────────────────────────────────────

/// A busy budget: the block is not loaded or encoded, takes no permit, issues nothing, and is
/// logged and counted as deferred by memory (`deferred_mem`), not by the time budget.
#[tokio::test]
async fn pos_issue_defers_block_when_budget_busy() {
    let (owner, budget) = budgeted(1, 2, make_test_encoder());
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    let buf = logged(tick(&owner, &mut in_flight)).await;

    assert_eq!(in_flight.len(), 0, "nothing was published");
    assert_eq!(pending_len(&owner), 0);
    assert_eq!(budget.grants(), 1, "no permit but the hold");
    let text = buf.text();
    assert!(
        text.contains("pos: block deferred, memory budget busy"),
        "{text}"
    );
    assert!(
        text.contains("queued=0") && text.contains("outstanding_mib=100"),
        "the DEBUG line names the queue and the outstanding bytes: {text}"
    );
    let line = &tick_lines(&buf)[0];
    assert_eq!(field(line, "issued"), Some(0), "{line}");
    assert_eq!(field(line, "blocks"), Some(1), "{line}");
    assert_eq!(field(line, "deferred_mem"), Some(2), "both holders: {line}");
    assert_eq!(
        field(line, "deferred"),
        Some(0),
        "not the time budget: {line}"
    );
    assert_eq!(deferred_tick_of(&owner, &block_at(0)), Some(1));
    drop(hold);
}

/// The budget is only as busy as its holders: a free one lets the same tick issue.
#[tokio::test]
async fn pos_issue_with_a_free_budget_takes_one_permit_and_issues() {
    let (owner, budget) = budgeted(1, 2, make_test_encoder());
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await;
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(5)).await;
    assert_eq!(pending_len(&owner), 2);
    assert_eq!(budget.grants(), 1, "one permit for the whole block");
    assert_eq!(budget.outstanding_bytes(), 0);
    assert!(
        owner.scheduler.mem_deferred_at.lock().unwrap().is_empty(),
        "a grant ends the deferral"
    );
}

/// M12. Deferred on tick n, waiting from tick n + 1 — by the tick NUMBER, through a real
/// sequence of ticks: never on the tick that deferred it (the deferral is brief), always on the
/// next one; then the block is served once the budget frees up.
#[tokio::test]
async fn pos_deferral_is_capped_at_one_issuance_tick() {
    let (owner, budget) = budgeted(1, 2, make_test_encoder());
    let hold = hold_all(&budget);
    let block = block_at(0);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // tick 1: deferred
        assert_eq!(deferred_tick_of(&owner, &block), Some(1));
        assert_eq!(
            in_flight.preparing.waiting(),
            0,
            "not waiting on its own tick"
        );
        assert_eq!(budget.priority_waiters(PriorityKind::OverduePos), 0);

        tick(&owner, &mut in_flight).await; // tick 2: waiting
        assert_eq!(
            in_flight.preparing.waiting(),
            1,
            "waiting from the next tick, as a batch"
        );
        until("the overdue block queues for memory", || {
            budget.priority_waiters(PriorityKind::OverduePos) == 1
        })
        .await;
        assert_eq!(
            deferred_tick_of(&owner, &block),
            Some(1),
            "the first deferral keeps its number"
        );

        drop(hold); // the worker lets go: the waiter is granted, the block is served
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    })
    .await;

    assert_eq!(pending_len(&owner), 2, "both holders challenged");
    let text = buf.text();
    assert!(
        text.contains("pos: overdue batch waiting for memory"),
        "{text}"
    );
    assert!(
        text.contains("mem_budget: granted kind=pos"),
        "the overdue block holds a pos permit: {text}"
    );
    assert!(text.contains("PoS late preparation published"), "{text}");
    assert_eq!(budget.outstanding_bytes(), 0);
    assert_eq!(
        deferred_tick_of(&owner, &block),
        None,
        "the episode is over"
    );
}

/// M12, independent of the order and of K. Two preparations the ticks started fill K; the
/// block deferred on tick 1 is queued at the START of tick 2 all the same, because the decision
/// comes before the order and before the time budget, which here cannot reach it.
#[tokio::test]
async fn deferred_on_tick_n_waits_from_tick_n_plus_1() {
    let (owner, budget) = budgeted(3, 1, make_test_encoder());
    let hold = hold_all(&budget);
    let holder = make_identity(0x80);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // all three blocks deferred on tick 1
        for b in [1u8, 2] {
            // Two preparations "cut from earlier ticks": K is full.
            let p = owner
                .db
                .get_placement(&block_at(b), &holder)
                .unwrap()
                .unwrap();
            let (handle, shared) = owner.scheduler.spawn_prepare(block_at(b), &[&p]);
            in_flight
                .preparing
                .adopt(block_at(b), HashMap::new(), handle, shared);
        }
        assert_eq!(in_flight.preparing.tick_started(), 2);

        tick(&owner, &mut in_flight).await; // tick 2
    })
    .await;

    let second = &tick_lines(&buf)[1];
    assert_eq!(
        field(second, "blocks"),
        Some(0),
        "K is full, the order starts nothing: {second}"
    );
    assert_eq!(
        field(second, "waiting_mem"),
        Some(1),
        "the deferred block waits: {second}"
    );
    assert!(in_flight.preparing.blocks().contains(&block_at(0)));
    in_flight.shutdown().await;
    drop(hold);
}

/// M21. Preparations waiting for memory do not take K slots: with two blocks waiting, the tick
/// still starts the third one (it is deferred too, but it was tried).
#[tokio::test]
async fn waiting_for_memory_preparations_do_not_take_k_slots() {
    let (owner, budget) = budgeted(2, 1, make_test_encoder());
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // A and B deferred
        let c = seed_retained_pos_block(owner.data_dir(), &owner.db, 2);
        owner
            .db
            .upsert_placement(&make_placement(c, make_identity(0x80)))
            .unwrap();

        tick(&owner, &mut in_flight).await; // A and B wait; C is a new block
    })
    .await;

    let second = &tick_lines(&buf)[1];
    assert_eq!(
        field(second, "waiting_mem"),
        Some(1),
        "A and B wait as one batch: {second}"
    );
    assert_eq!(field(second, "batch"), Some(2), "{second}");
    assert_eq!(in_flight.preparing.tick_started(), 0, "waiting is not K");
    assert_eq!(
        field(second, "blocks"),
        Some(1),
        "the tick still starts the new block: {second}"
    );
    assert_eq!(field(second, "deferred_mem"), Some(1), "{second}");
    in_flight.shutdown().await;
    drop(hold);
}

/// Three marked blocks whose preparation takes 0.5 s each, all granted memory at once (the budget
/// is free again): ONE batch, one after the other — never two preparations at once.
#[tokio::test]
async fn a_batch_prepares_its_members_one_after_the_other() {
    let encoder = StallingEncoder::new(0, usize::MAX, Duration::from_millis(500));
    let (owner, budget) = budgeted(3, 1, Arc::clone(&encoder) as _);
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    tick(&owner, &mut in_flight).await; // marked: the encoder was not reached
    assert_eq!(encoder.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(hold);
    tick(&owner, &mut in_flight).await; // all three in one batch
    assert_eq!(in_flight.preparing.waiting(), 1);
    assert_eq!(in_flight.preparing.batch_members(), 3);
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(20)).await;

    assert_eq!(pending_len(&owner), 3, "all three issued");
    assert_eq!(encoder.calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(
        encoder.peak.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "never two overdue preparations at once"
    );
}

/// M22. A deferral does not stop the tick: a small block behind a big deferred one fits and is
/// served in the same tick.
#[tokio::test]
async fn memory_deferred_block_does_not_stop_the_tick() {
    let budget = MemBudget::new(4 * MIB);
    let holder = make_identity(0x80);
    let mut owner = owner_with_encoder(
        900,
        SlowPostman::acking_after(Duration::from_millis(5)),
        make_test_encoder(),
        |db, dir| {
            // Big: k·t ≈ 640 KiB, a 3 MiB estimate. Small: 640 B, 1 MiB.
            seed_sized_block(dir, db, 1, 65_535);
            seed_sized_block(dir, db, 2, 64);
        },
    );
    owner.scheduler.set_mem_budget(Arc::clone(&budget));
    let (big, small) = (sized_block_id(1, 65_535), sized_block_id(2, 64));
    for b in [big, small] {
        owner
            .db
            .upsert_placement(&make_placement(b, holder))
            .unwrap();
    }
    // The big one first in the order.
    owner
        .scheduler
        .last_attempted
        .lock()
        .unwrap()
        .insert((small, holder), Timestamp::now());
    let _hold = budget
        .try_acquire(HolderKind::Worker, &SourceBlockId([0xEE; 32]), 2 * MIB)
        .unwrap();

    let mut in_flight = InFlight::default();
    let buf = logged(async {
        tick(&owner, &mut in_flight).await;
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(5)).await;
    })
    .await;

    let line = &tick_lines(&buf)[0];
    assert_eq!(
        field(line, "deferred_mem"),
        Some(1),
        "the big block: {line}"
    );
    assert_eq!(field(line, "issued"), Some(1), "the small one: {line}");
    assert_eq!(deferred_tick_of(&owner, &big), Some(1));
    assert_eq!(deferred_tick_of(&owner, &small), None);
}

pub(super) fn sized_blob(seed: u8, t: u16) -> Vec<u8> {
    (0..TEST_K as usize * t as usize)
        .map(|i| ((i + seed as usize) & 0xFF) as u8)
        .collect()
}

pub(super) fn sized_block_id(seed: u8, t: u16) -> SourceBlockId {
    SourceBlockId(*blake3::hash(&sized_blob(seed, t)).as_bytes())
}

/// A retained block of `k·t` bytes with symbol size `t`, and its record.
pub(super) fn seed_sized_block(
    dir: &std::path::Path,
    db: &viaticum_core::db::Db,
    seed: u8,
    t: u16,
) {
    let blob = sized_blob(seed, t);
    let id = SourceBlockId(*blake3::hash(&blob).as_bytes());
    crate::daemon::system_state::block::store_retained_block(dir, &id, &blob).unwrap();
    let mut record = make_source_block_record(id);
    record.t = t;
    record.encrypted_size = Some(TEST_K as u64 * t as u64);
    db.upsert_source_block(&record).unwrap();
}

// ─── The permit is held exactly while the memory is ───────────────────────────

/// M19. The preparation has given its permit back by the time its task has ended: nothing the
/// tick publishes is under the budget (J12).
#[tokio::test]
async fn pos_issue_releases_permit_before_publishing() {
    let (owner, budget) = budgeted(1, 2, make_test_encoder());
    let block = block_at(0);
    let placements: Vec<_> = (0..2u8)
        .map(|h| {
            owner
                .db
                .get_placement(&block, &make_identity(0x80 + h))
                .unwrap()
                .unwrap()
        })
        .collect();
    let refs: Vec<_> = placements.iter().collect();

    let (handle, _shared) = owner.scheduler.spawn_prepare(block, &refs);
    let PrepOutcome::Prepared(prepared) = handle.await.unwrap() else {
        panic!("a free budget prepares");
    };

    assert_eq!(prepared.len(), 2);
    assert_eq!(budget.grants(), 1, "it did take a permit");
    assert_eq!(
        budget.available_bytes(),
        budget.total_bytes(),
        "the challenges it returned hold no memory"
    );
    assert_eq!(budget.outstanding_bytes(), 0);
    drop(prepared);
}

/// M25. A preparation the tick cut at its deadline still holds its permit while it works on:
/// the budget sees the background preparations (J12 by construction), and it is given back only
/// when the task ends.
#[tokio::test]
async fn cut_preparation_holds_permit_until_it_ends() {
    let encoder = StallingEncoder::new(0, 1, Duration::from_millis(1500));
    let (owner, budget) = budgeted(1, 2, encoder);
    let mut in_flight = InFlight::default();

    let buf = logged(tick(&owner, &mut in_flight)).await;

    let line = &tick_lines(&buf)[0];
    assert_eq!(field(line, "cut_blocks"), Some(1), "{line}");
    assert_eq!(in_flight.preparing.running(), 1);
    assert_eq!(
        budget.outstanding_bytes(),
        permit_of_test_block(),
        "the cut preparation still holds its permit"
    );

    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    assert_eq!(budget.outstanding_bytes(), 0, "given back at its end");
    assert_eq!(pending_len(&owner), 2);
}

// ─── load_failed (backup-i7, NOTE 7) ──────────────────────────────────────────

/// M23. A block deferred on tick 1 whose last load failed is not queued for memory on tick 2:
/// it stays in the ordinary flow (and is deferred again there), so the worker never yields
/// memory for a load that would fail.
#[tokio::test]
async fn block_whose_load_failed_never_goes_overdue() {
    let (owner, budget) = budgeted(1, 1, make_test_encoder());
    let hold = hold_all(&budget);
    let block = block_at(0);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // deferred
        owner
            .scheduler
            .load_failed
            .lock()
            .unwrap()
            .insert(block, std::time::Instant::now() + Duration::from_secs(3600));
        tick(&owner, &mut in_flight).await;
    })
    .await;

    let second = &tick_lines(&buf)[1];
    assert_eq!(field(second, "waiting_mem"), Some(0), "{second}");
    assert_eq!(
        field(second, "deferred_mem"),
        Some(1),
        "tried again in the ordinary flow: {second}"
    );
    assert_eq!(budget.priority_waiters(PriorityKind::OverduePos), 0);
    drop(hold);
}

#[test]
fn load_failed_term_is_a_day_for_a_changed_source_and_a_period_for_the_rest() {
    use crate::daemon::backup::pipeline::BlobHashMismatch;
    use crate::daemon::backup::rebuild::RebuildError;
    let now = std::time::Instant::now();
    let period = Duration::from_secs(4);
    let day = Duration::from_secs(86_400);
    let block = SourceBlockId([1; 32]);

    let missing = anyhow::Error::new(RebuildError::SourceMissing {
        block,
        missing: Vec::new(),
    })
    .context("rebuild plaintext");
    assert_eq!(load_failed_until(&missing, now, period), now + day);

    let changed = anyhow::Error::new(BlobHashMismatch {
        got: "00".into(),
        expected: block,
    });
    assert_eq!(load_failed_until(&changed, now, period), now + day);

    let io = anyhow::anyhow!("read retained block: input/output error");
    assert_eq!(load_failed_until(&io, now, period), now + period);
}

/// A failed load is remembered with its term; a load that succeeds clears it.
#[tokio::test]
async fn failed_load_is_remembered_and_a_successful_load_clears_it() {
    let (owner, _budget) = budgeted(1, 1, make_test_encoder());
    let block = block_at(0);
    let path = crate::daemon::system_state::block::retained_block_path(owner.data_dir(), &block);
    let good = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"not the block").unwrap();
    let mut in_flight = InFlight::default();

    tick(&owner, &mut in_flight).await;
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(5)).await;
    {
        let map = owner.scheduler.load_failed.lock().unwrap();
        let until = *map.get(&block).expect("the failure is remembered");
        let ahead = until.saturating_duration_since(std::time::Instant::now());
        assert!(
            ahead > Duration::ZERO && ahead <= Duration::from_secs(5),
            "a transient failure waits one period (4 s at scale 900): {ahead:?}"
        );
    }
    assert_eq!(pending_len(&owner), 0);

    std::fs::write(&path, good).unwrap();
    tick(&owner, &mut in_flight).await;
    settle_until_idle(&owner, &mut in_flight, Duration::from_secs(5)).await;
    assert!(
        owner.scheduler.load_failed.lock().unwrap().is_empty(),
        "a successful load clears the mark"
    );
    assert_eq!(pending_len(&owner), 1);
}

// ─── Shutdown, the tick line, NOTE 5 ──────────────────────────────────────────

/// Shutdown cancels an overdue wait: its place in the queue and the priority count go with it.
#[tokio::test]
async fn overdue_waiter_is_cancelled_on_shutdown_and_priority_counter_drops() {
    let (owner, budget) = budgeted(1, 1, make_test_encoder());
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();
    tick(&owner, &mut in_flight).await;
    tick(&owner, &mut in_flight).await;
    until("the overdue block queues", || {
        budget.priority_waiters(PriorityKind::OverduePos) == 1
    })
    .await;
    assert_eq!(budget.queued_waiters(), 1);

    in_flight.shutdown().await;

    assert_eq!(budget.priority_waiters(PriorityKind::OverduePos), 0);
    assert_eq!(budget.queued_waiters(), 0);
    drop(hold);
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// The tick line carries `deferred_mem` for the blocks the budget deferred in this tick,
/// `waiting_mem` for the batch waiting (at most one), `batch` for its members, `marked` for the
/// marks, and `oldest_wait_s`; `preparing` counts only the running ones.
#[tokio::test]
async fn tick_line_counts_deferred_mem_and_waiting_mem() {
    let (owner, budget) = budgeted(2, 3, make_test_encoder());
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await;
        tick(&owner, &mut in_flight).await;
    })
    .await;

    let lines = tick_lines(&buf);
    let (first, second) = (&lines[0], &lines[1]);
    assert_eq!(
        field(first, "deferred_mem"),
        Some(6),
        "2 blocks x 3 holders: {first}"
    );
    assert_eq!(field(first, "waiting_mem"), Some(0), "{first}");
    assert_eq!(
        field(second, "waiting_mem"),
        Some(1),
        "one batch for both blocks: {second}"
    );
    assert_eq!(field(second, "batch"), Some(2), "{second}");
    assert_eq!(field(second, "marked"), Some(2), "{second}");
    assert_eq!(field(second, "deferred_mem"), Some(0), "{second}");
    assert_eq!(
        field(second, "preparing"),
        Some(0),
        "waiting is not running: {second}"
    );
    assert_eq!(field(second, "skipped_pending"), Some(6), "{second}");
    assert!(field(second, "oldest_wait_s").is_some(), "{second}");
    in_flight.shutdown().await;
    drop(hold);
}

/// NOTE 5. A preparation that was cut from its tick and then ends `Deferred` marks its block
/// deferred as of now (the tick in progress), so it waits from the next tick.
#[tokio::test]
async fn memory_deferred_from_a_cut_preparation_sets_mem_deferred_at() {
    let (owner, _budget) = budgeted(1, 1, make_test_encoder());
    let block = block_at(0);
    owner
        .scheduler
        .issue_seq
        .store(7, std::sync::atomic::Ordering::SeqCst);
    let mut in_flight = InFlight::default();

    let done = crate::daemon::scheduler::issue::PrepDone {
        block_id: block,
        cpw_of: HashMap::new(),
        result: Ok(PrepOutcome::Deferred),
    };
    owner
        .scheduler
        .settle_ended(Ended::Prepared(done), &mut in_flight)
        .await;

    assert_eq!(deferred_tick_of(&owner, &block), Some(7));
    // A later deferral does not move it.
    owner.scheduler.note_mem_deferred(block, 9);
    assert_eq!(deferred_tick_of(&owner, &block), Some(7));
}

// ─── The stuck-preparation WARN counts work, not waiting (NOTE 6, M24) ───────

/// An overdue preparation that waited 0.7 s for memory and was granted it just now is not
/// "still running" for any age below its work time, however long it waited.
#[tokio::test]
async fn stuck_warn_counts_from_grant_not_from_wait() {
    let encoder = StallingEncoder::new(0, 1, Duration::from_millis(1500));
    let (owner, budget) = budgeted(1, 1, encoder);
    let hold = hold_all(&budget);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await;
        tick(&owner, &mut in_flight).await; // adopted: waiting
        tokio::time::sleep(Duration::from_millis(700)).await;
        drop(hold); // granted now
        until("the granted preparation runs", || {
            in_flight.preparing.running() == 1
        })
        .await;
        // The stuck age here is 10 x 50 ms = 500 ms: the wait (700 ms) would exceed it, the work
        // (a few ms so far) does not.
        in_flight.preparing.watch_stuck(
            Instant::now(),
            Duration::from_millis(50),
            10,
            Duration::ZERO,
            &budget,
            false,
        );
    })
    .await;

    assert!(
        !buf.text().contains("PoS preparation still running"),
        "waiting for memory is not hanging: {}",
        buf.text()
    );
    in_flight.shutdown().await;
}

/// NOTE 6. The age of a running preparation is its WORK time, from the tick that started it: a
/// preparation stalled past 10 periods is named, with who holds how much and in which phase.
#[tokio::test]
async fn stuck_warn_counts_run_time_not_memory_wait() {
    let encoder = StallingEncoder::new(0, 1, Duration::from_millis(1500));
    let (owner, budget) = budgeted(1, 1, encoder);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // cut at the deadline: stalled in the encode
        assert_eq!(in_flight.preparing.running(), 1);
        // The tick waited 760 ms for it: its work age is past 10 x 50 ms already.
        in_flight.preparing.watch_stuck(
            Instant::now(),
            Duration::from_millis(50),
            10,
            Duration::ZERO,
            &budget,
            true,
        );
    })
    .await;

    let text = buf.text();
    let holds = format!("holds_mib={}", permit_of_test_block() >> 20);
    let warn = text
        .lines()
        .find(|l| l.contains("PoS preparation still running"))
        .unwrap_or_else(|| panic!("no stuck WARN: {text}"));
    assert!(
        warn.contains("kind=\"pos\"") || warn.contains("kind=pos"),
        "{warn}"
    );
    assert!(warn.contains("phase=encode"), "{warn}");
    assert!(warn.contains(&holds), "{warn}");
    assert!(
        !text.contains("written off"),
        "only a hung LOAD is written off: {text}"
    );
    in_flight.shutdown().await;
}

// ─── pos-i7-d-d (variant (a)): a hung load gives its memory back ─────────────

/// Unblocks a FIFO a preparation hangs on; also when the test fails before it did.
pub(super) struct Unblock {
    path: std::path::PathBuf,
    done: std::cell::Cell<bool>,
}

impl Unblock {
    pub(super) fn new(path: std::path::PathBuf) -> Self {
        Unblock {
            path,
            done: std::cell::Cell::new(false),
        }
    }

    pub(super) fn now(&self) {
        use std::os::unix::fs::OpenOptionsExt;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            // Non-blocking: succeeds only when a reader is waiting on the FIFO.
            if let Ok(w) = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&self.path)
            {
                drop(w);
                self.done.set(true);
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Unblock {
    /// Lets go every reader that comes to the FIFO within `window`, not only the first: a test that
    /// fails (or a mutated rule that starts one more member on the same FIFO) must end, not hang
    /// the runtime's shutdown on a read nobody will ever answer.
    pub(super) fn release_all(&self, window: Duration) {
        use std::os::unix::fs::OpenOptionsExt;
        let deadline = std::time::Instant::now() + window;
        while std::time::Instant::now() < deadline {
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&self.path);
            std::thread::sleep(Duration::from_millis(20));
        }
        self.done.set(true);
    }
}

impl Drop for Unblock {
    fn drop(&mut self) {
        if !self.done.get() {
            self.release_all(Duration::from_secs(2));
        }
    }
}

/// A source on a dead NAS: the read of the block hangs (a FIFO without a writer stands in for
/// it) while the preparation holds its permit. After H periods it is written off: its bytes
/// serve other work; when the read finally returns, nothing is returned a second time.
#[tokio::test]
async fn stuck_load_is_written_off_after_h_and_budget_serves_others() {
    let (owner, budget) = budgeted(1, 1, make_test_encoder());
    let block = block_at(0);
    let path = crate::daemon::system_state::block::retained_block_path(owner.data_dir(), &block);
    std::fs::remove_file(&path).unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo");
    assert!(status.success());
    let unblock = Unblock::new(path);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await; // the read hangs; the tick cuts the block
        assert_eq!(in_flight.preparing.running(), 1);
        assert_eq!(
            budget.outstanding_bytes(),
            permit_of_test_block(),
            "it holds its permit"
        );

        // Ten periods of work later.
        let later = Instant::now() + Duration::from_secs(11);
        in_flight.preparing.watch_stuck(
            later,
            Duration::from_secs(1),
            10,
            Duration::ZERO,
            &budget,
            true,
        );
        assert_eq!(budget.outstanding_bytes(), 0, "written off");
        assert_eq!(budget.semaphore_free_bytes(), budget.total_bytes());

        // The budget serves somebody else, all of it.
        let other = budget
            .try_acquire(
                HolderKind::Restore,
                &SourceBlockId([0xEF; 32]),
                TOTAL_MIB * MIB,
            )
            .expect("the written-off bytes are free");
        // The same stuck holder is not written off again.
        in_flight.preparing.watch_stuck(
            later,
            Duration::from_secs(1),
            10,
            Duration::ZERO,
            &budget,
            true,
        );
        assert_eq!(budget.outstanding_bytes(), TOTAL_MIB * MIB);

        // The read returns (an empty blob: not the block). The task ends; it returns nothing.
        unblock.now();
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
        assert_eq!(budget.semaphore_free_bytes(), 0, "no units returned twice");
        drop(other);
    })
    .await;

    let text = buf.text();
    let holds = format!("holds_mib={}", permit_of_test_block() >> 20);
    let line = text
        .lines()
        .find(|l| l.contains("written off a stuck holder"))
        .unwrap_or_else(|| panic!("no write-off WARN: {text}"));
    assert!(line.contains("phase=load"), "{line}");
    assert!(line.contains(&holds), "{line}");
    assert_eq!(
        text.matches("written off a stuck holder").count(),
        1,
        "{text}"
    );
    assert_eq!(budget.semaphore_free_bytes(), budget.total_bytes());
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// Variant (b) of the recommendation (`write_off = false`): the hung load is named, nothing is
/// given back.
#[tokio::test]
async fn stuck_load_is_only_named_when_write_off_is_off() {
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
    let unblock = Unblock::new(path);
    let mut in_flight = InFlight::default();

    let buf = logged(async {
        tick(&owner, &mut in_flight).await;
        in_flight.preparing.watch_stuck(
            Instant::now() + Duration::from_secs(11),
            Duration::from_secs(1),
            10,
            Duration::ZERO,
            &budget,
            false,
        );
        assert_eq!(
            budget.outstanding_bytes(),
            permit_of_test_block(),
            "nothing given back"
        );
        unblock.now();
        settle_until_idle(&owner, &mut in_flight, Duration::from_secs(10)).await;
    })
    .await;

    let text = buf.text();
    assert!(text.contains("PoS preparation still running"), "{text}");
    assert!(text.contains("phase=load"), "{text}");
    assert!(!text.contains("written off"), "{text}");
    assert_eq!(budget.outstanding_bytes(), 0);
}
