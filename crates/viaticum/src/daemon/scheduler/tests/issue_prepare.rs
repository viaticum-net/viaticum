// pos-i7-d-a: a block whose preparation is longer than the tick budget is not dropped at
// the deadline. It prepares on in the background (once), the run loop publishes its
// challenges when it ends, ticks leave it alone meanwhile, at most `MAX_PREPARATIONS`
// blocks prepare at once, and a holder whose placement stopped being challengeable (or got
// a challenge) meanwhile is not challenged. A block preparing is left alone for EVERY
// holder, also one whose challenge became due meanwhile. A preparation that runs past 10
// periods is named by a WARN with its age (pos-i7-d-b).
//
// The tests drive the run loop's part by hand (`drive`): a tick, then the wait of one tick
// period for the publishes and preparations that end.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::time::Instant;
use viaticum_core::types::{DeviceId, PlacementStatus, Timestamp};

use super::issue_stall::StallingEncoder;
use super::issue_support::{Owner, SlowPostman, owner_with_encoder, seed_due};
use super::pos_scale::{LogBuf, field};
use crate::daemon::scheduler::PendingHashChallenge;
use crate::daemon::scheduler::issue::{InFlight, MAX_PREPARATIONS};

/// Tick lines of one drive, in order.
fn tick_lines(buf: &LogBuf) -> Vec<String> {
    buf.text()
        .lines()
        .filter(|l| l.contains("scheduler: PoS issue tick"))
        .map(str::to_owned)
        .collect()
}

fn capture() -> (LogBuf, tracing::Dispatch) {
    let buf = LogBuf::default();
    let writer = buf.clone();
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish(),
    );
    (buf, dispatch)
}

/// The run loop in small: a tick (budget 800 ms at time_scale 900), then settle whatever
/// ends within `gap`; repeat until `done` or `max_ticks` ticks. Returns the ticks run.
async fn drive(
    owner: &Owner,
    in_flight: &mut InFlight,
    max_ticks: usize,
    gap: Duration,
    done: impl Fn(&Owner) -> bool,
) -> usize {
    for tick in 1..=max_ticks {
        owner.scheduler.issue_tick(in_flight).await.expect("tick");
        let until = Instant::now() + gap;
        while let Ok(Some(ended)) = tokio::time::timeout_at(until, in_flight.join_next_any()).await
        {
            owner.scheduler.settle_ended(ended, in_flight).await;
        }
        if done(owner) && in_flight.is_idle() {
            return tick;
        }
    }
    max_ticks
}

fn pending_len(owner: &Owner) -> usize {
    owner.pending.try_lock().map(|g| g.len()).unwrap_or(0)
}

/// One block of 3 holders whose first preparation takes 3 s, far past the 800 ms tick
/// budget. Dropped at the deadline (the old behaviour), the next tick starts it again —
/// two encodes; here the first tick's preparation is adopted: exactly ONE encode, the
/// next tick reports it `preparing` and starts nothing, and all 3 challenges are pending
/// within a few ticks.
#[tokio::test]
async fn a_block_preparing_longer_than_the_tick_budget_is_issued_with_one_preparation() {
    let encoder = StallingEncoder::new(0, 1, Duration::from_millis(3000));
    let owner = owner_with_encoder(
        900,
        SlowPostman::acking_after(Duration::from_millis(5)),
        Arc::clone(&encoder) as _,
        |db, dir| seed_due(db, dir, 1, 3),
    );
    let (buf, dispatch) = capture();
    let mut in_flight = InFlight::default();
    let ticks = tracing::instrument::WithSubscriber::with_subscriber(
        drive(&owner, &mut in_flight, 8, Duration::from_millis(800), |o| {
            pending_len(o) == 3
        }),
        dispatch,
    )
    .await;
    in_flight.shutdown().await;

    assert_eq!(pending_len(&owner), 3, "the block is issued");
    assert!(ticks <= 5, "issued within a finite few ticks, took {ticks}");
    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        1,
        "the preparation ran exactly once, no tick restarted it"
    );
    let lines = tick_lines(&buf);
    assert_eq!(field(&lines[0], "cut_blocks"), Some(1), "{}", lines[0]);
    assert_eq!(field(&lines[0], "preparing"), Some(1), "{}", lines[0]);
    assert_eq!(field(&lines[0], "deferred"), Some(0), "{}", lines[0]);
    let second = &lines[1];
    assert_eq!(field(second, "blocks"), Some(0), "no new start: {second}");
    assert_eq!(field(second, "preparing"), Some(1), "{second}");
    assert_eq!(field(second, "skipped_pending"), Some(3), "{second}");
}

/// 5 blocks, every preparation 2.5 s. Ticks cut them one by one; no more than
/// `MAX_PREPARATIONS` encodes ever run at once, the ticks that find them busy defer the
/// rest, and all 5 blocks are issued in the end.
#[tokio::test]
async fn no_more_than_the_limit_of_preparations_run_at_once() {
    let encoder = StallingEncoder::new(0, usize::MAX, Duration::from_millis(2500));
    let owner = owner_with_encoder(
        900,
        SlowPostman::acking_after(Duration::from_millis(5)),
        Arc::clone(&encoder) as _,
        |db, dir| seed_due(db, dir, 5, 2),
    );
    let (buf, dispatch) = capture();
    let mut in_flight = InFlight::default();
    tracing::instrument::WithSubscriber::with_subscriber(
        drive(
            &owner,
            &mut in_flight,
            40,
            Duration::from_millis(200),
            |o| pending_len(o) == 10,
        ),
        dispatch,
    )
    .await;
    in_flight.shutdown().await;

    assert_eq!(pending_len(&owner), 10, "all 5 blocks are issued");
    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        5,
        "one encode per block"
    );
    let peak = encoder.peak.load(Ordering::SeqCst);
    assert_eq!(
        peak, MAX_PREPARATIONS,
        "the limit is reached and not passed"
    );
    let lines = tick_lines(&buf);
    assert!(
        lines
            .iter()
            .all(|l| field(l, "preparing") <= Some(MAX_PREPARATIONS as u64)),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| field(l, "preparing") == Some(MAX_PREPARATIONS as u64)
                && field(l, "deferred") > Some(0)
                && field(l, "blocks") == Some(0)),
        "a tick that finds the slots busy starts nothing and defers: {lines:?}"
    );
}

/// The block prepares 1.5 s; meanwhile holder A's placement is marked Lost, B gets a
/// challenge in pending, C's placement is deleted, E's `esi_ranges` are rewritten (a
/// repair appended a range: the hash was computed for the old ones). When the preparation
/// ends only D is challenged: one store reaches the postman, and B keeps the challenge it
/// had.
#[tokio::test]
async fn a_holder_that_stopped_being_challengeable_during_preparation_gets_no_challenge() {
    let encoder = StallingEncoder::new(0, 1, Duration::from_millis(1500));
    let postman = SlowPostman::acking_after(Duration::from_millis(5));
    let owner = owner_with_encoder(900, Arc::clone(&postman), encoder, |db, dir| {
        seed_due(db, dir, 1, 5)
    });
    let placements = owner.db.list_all_placements().unwrap();
    assert_eq!(placements.len(), 5);
    let mut holders: Vec<DeviceId> = placements.iter().map(|p| p.holder_id).collect();
    holders.sort_by_key(|h| h.0);
    let (a, b, c, d, e) = (holders[0], holders[1], holders[2], holders[3], holders[4]);
    let block = placements[0].source_block_id;

    let mut in_flight = InFlight::default();
    owner
        .scheduler
        .issue_tick(&mut in_flight)
        .await
        .expect("tick");
    assert!(!in_flight.is_idle(), "the block is preparing");

    // What happens during the preparation.
    let mut lost = owner.db.get_placement(&block, &a).unwrap().unwrap();
    lost.status = PlacementStatus::Lost;
    owner.db.upsert_placement(&lost).unwrap();
    let theirs = PendingHashChallenge {
        source_block_id: block,
        holder_id: b,
        esi_ranges: vec![(0, 1)],
        expected_chain_hash: [7; 32],
        issued_at: Timestamp::now(),
        challenge_id: [9; 16],
        holder_master: viaticum_core::types::IdentityPub(b.0),
    };
    owner.pending.lock().await.insert((block, b), theirs);
    owner.db.delete_placement(&block, &c).unwrap();
    let mut repaired = owner.db.get_placement(&block, &e).unwrap().unwrap();
    repaired.esi_ranges.push((900, 901));
    owner.db.upsert_placement(&repaired).unwrap();

    let ended = tokio::time::timeout(Duration::from_secs(5), in_flight.join_next_any())
        .await
        .expect("the preparation ends")
        .expect("something ended");
    owner.scheduler.settle_ended(ended, &mut in_flight).await;
    while let Some(ended) = in_flight.join_next_any().await {
        owner.scheduler.settle_ended(ended, &mut in_flight).await;
    }

    let pending = owner.pending.lock().await;
    assert!(pending.contains_key(&(block, d)), "D is challenged");
    assert!(
        !pending.contains_key(&(block, a)),
        "A is Lost: no challenge"
    );
    assert!(
        !pending.contains_key(&(block, c)),
        "C is gone: no challenge"
    );
    assert!(
        !pending.contains_key(&(block, e)),
        "E's ranges changed: no challenge by the old hash"
    );
    assert_eq!(
        pending.get(&(block, b)).unwrap().challenge_id,
        [9; 16],
        "B keeps its own"
    );
    // One publish is a store per candidate postman (the seeded holder peers are candidates too):
    // count the distinct challenges, not the stores.
    let published: std::collections::HashSet<_> = postman
        .stores()
        .iter()
        .map(|(_, r)| r.entry.msg_id)
        .collect();
    assert_eq!(published.len(), 1, "only D's challenge was published");
}

/// Four holders of one block; the 4th is not due when the block is cut (verified just
/// now). During the preparation its `last_verified` goes back to the epoch, so at the next
/// tick it is due too. The block is left alone for every holder: the encoder is called
/// once, the tick reports all 4 placements skipped and starts nothing. Once the
/// preparation ends the 4th is served by a tick of its own (a second encode).
#[tokio::test]
async fn a_holder_that_became_due_during_preparation_does_not_restart_the_block() {
    let encoder = StallingEncoder::new(0, 1, Duration::from_millis(1500));
    let owner = owner_with_encoder(
        900,
        SlowPostman::acking_after(Duration::from_millis(5)),
        Arc::clone(&encoder) as _,
        |db, dir| {
            seed_due(db, dir, 1, 4);
            let mut ps = db.list_all_placements().unwrap();
            ps.sort_by_key(|p| p.holder_id.0);
            ps[3].last_verified = Some(Timestamp::now());
            db.upsert_placement(&ps[3]).unwrap();
        },
    );
    let mut ps = owner.db.list_all_placements().unwrap();
    ps.sort_by_key(|p| p.holder_id.0);
    let (fourth, block) = (ps[3].holder_id, ps[3].source_block_id);

    let (buf, dispatch) = capture();
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let mut in_flight = InFlight::default();
    owner
        .scheduler
        .issue_tick(&mut in_flight)
        .await
        .expect("tick");
    assert!(!in_flight.is_idle(), "the block is preparing");

    let mut due_now = owner.db.get_placement(&block, &fourth).unwrap().unwrap();
    due_now.last_verified = Some(Timestamp(0));
    owner.db.upsert_placement(&due_now).unwrap();
    owner
        .scheduler
        .issue_tick(&mut in_flight)
        .await
        .expect("tick");

    assert_eq!(
        encoder.calls.load(Ordering::SeqCst),
        1,
        "the 4th holder's due did not start the block again"
    );
    let lines = tick_lines(&buf);
    let second = &lines[1];
    assert_eq!(field(second, "due"), Some(4), "{second}");
    assert_eq!(field(second, "blocks"), Some(0), "{second}");
    assert_eq!(field(second, "skipped_pending"), Some(4), "{second}");

    // The preparation ends; the run loop publishes the 3 it was made for.
    while let Some(ended) = in_flight.join_next_any().await {
        owner.scheduler.settle_ended(ended, &mut in_flight).await;
    }
    assert_eq!(pending_len(&owner), 3, "the 3 holders of the first cut");
    assert!(
        !owner.pending.lock().await.contains_key(&(block, fourth)),
        "the 4th waits for the next tick"
    );
    in_flight.shutdown().await;
}

/// pos-i7-d-b, on a paused clock. A preparation held for real 1.5 s is cut by the first
/// tick (the clock advanced past its deadline). Ticks later, 10 periods on, it is named
/// by a WARN with its age; a second tick in the same period is silent, one period later
/// the WARN comes again; the tick line carries the age of the oldest preparation. The
/// slot is not freed.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_preparation_running_past_ten_periods_is_warned_with_its_age() {
    let encoder = StallingEncoder::new(0, 1, Duration::from_millis(1500));
    let owner = owner_with_encoder(
        900,
        SlowPostman::acking_after(Duration::from_millis(5)),
        encoder,
        |db, dir| seed_due(db, dir, 1, 2),
    );
    let (buf, dispatch) = capture();
    let _guard = tracing::dispatcher::set_default(&dispatch);
    let period = Duration::from_secs(4); // 3600 s / 900
    let mut in_flight = InFlight::default();

    // The first tick: the clock jumps past its deadline while the encode runs.
    let (tick, ()) = tokio::join!(owner.scheduler.issue_tick(&mut in_flight), async {
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
    });
    tick.expect("tick");
    assert!(!in_flight.is_idle(), "the block is preparing");

    let warns = |buf: &LogBuf| -> Vec<String> {
        buf.text()
            .lines()
            .filter(|l| l.contains("PoS preparation still running"))
            .map(str::to_owned)
            .collect()
    };
    tokio::time::advance(period * 5).await;
    owner
        .scheduler
        .issue_tick(&mut in_flight)
        .await
        .expect("tick");
    assert!(warns(&buf).is_empty(), "5 periods: not yet");

    tokio::time::advance(period * 5).await; // 1 + 40 s
    owner
        .scheduler
        .issue_tick(&mut in_flight)
        .await
        .expect("tick");
    let first = warns(&buf);
    assert_eq!(first.len(), 1, "{first:?}");
    assert!(first[0].contains("age_s=41"), "{}", first[0]);

    owner
        .scheduler
        .issue_tick(&mut in_flight)
        .await
        .expect("tick");
    assert_eq!(warns(&buf).len(), 1, "once per period per block");

    tokio::time::advance(period).await;
    owner
        .scheduler
        .issue_tick(&mut in_flight)
        .await
        .expect("tick");
    let all = warns(&buf);
    assert_eq!(all.len(), 2, "{all:?}");
    assert!(all[1].contains("age_s=45"), "{}", all[1]);

    let last = tick_lines(&buf).pop().expect("a tick line");
    assert_eq!(field(&last, "oldest_prep_s"), Some(45), "{last}");
    assert_eq!(
        field(&last, "preparing"),
        Some(1),
        "the slot is kept: {last}"
    );
    in_flight.shutdown().await;
}
