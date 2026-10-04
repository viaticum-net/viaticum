// pos-i7-a: the issue tick is bounded by a time budget (a fifth of the PoS tick period),
// leaves what it did not reach due for the next tick, and stamps every challenge at its
// own publish. СТ-0c round 3 (W-1): the tick does not wait for its publishes — they
// settle later through the run loop, which stays free meanwhile.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use viaticum_core::messages::{PosHashChallengeMsg, PosHashResponseMsg};
use viaticum_core::types::{DeviceId, SourceBlockId, Timestamp, from_cbor_bytes};

use super::issue_support::{Owner, SlowPostman, owner_with_due};
use super::pos_scale::{LogBuf, field};
use crate::daemon::scheduler::issue::{ISSUE_PUBLISH_CONCURRENCY, InFlight, issue_budget};
use crate::daemon::scheduler::{PendingChallenges, PendingHashChallenge};

/// A challenge already pending on `owner`, and its holder's signed response.
async fn pending_with_response(owner: &Owner) -> ([u8; 16], PosHashResponseMsg) {
    let holder_key = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    let holder = DeviceId(holder_key.verifying_key().to_bytes());
    let block = SourceBlockId([0xEE; 32]);
    let cid = [0xEE; 16];
    owner.pending.lock().await.insert(
        (block, holder),
        PendingHashChallenge {
            source_block_id: block,
            holder_id: holder,
            esi_ranges: vec![(0, 1)],
            expected_chain_hash: [0u8; 32],
            issued_at: Timestamp::now(),
            challenge_id: cid,
        },
    );
    let response = viaticum_core::messages::build_pos_hash_response(
        cid,
        block,
        [0u8; 32],
        Timestamp::now(),
        &holder_key,
    );
    (cid, response)
}

/// Wait until `postman` saw its first store (the first issue tick is publishing).
async fn first_store(postman: &SlowPostman) {
    let waited = Instant::now();
    while postman.store_count() == 0 {
        assert!(waited.elapsed() < Duration::from_secs(10), "no issue tick");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Send `response` into the run loop; how long its pending took to resolve.
async fn resolve_delay(
    pending: &PendingChallenges,
    response_tx: &mpsc::Sender<PosHashResponseMsg>,
    cid: [u8; 16],
    response: PosHashResponseMsg,
) -> Duration {
    response_tx.send(response).await.expect("scheduler alive");
    let sent = Instant::now();
    while pending.lock().await.contains_challenge(&cid) {
        assert!(sent.elapsed() < Duration::from_secs(10), "never resolved");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    sent.elapsed()
}

// ─── The budget ───────────────────────────────────────────────────────────────

#[test]
fn issue_budget_is_a_fifth_of_the_scaled_pos_period() {
    assert_eq!(issue_budget(3600, 1), Duration::from_secs(720));
    assert_eq!(issue_budget(3600, 900), Duration::from_millis(800));
    assert_eq!(issue_budget(3600, 3600), Duration::from_millis(200));
    // The period floors at 1 s like the timer, so the budget floors at 200 ms.
    assert_eq!(issue_budget(3600, 1_000_000), Duration::from_millis(200));
    assert_eq!(issue_budget(3600, 0), Duration::from_secs(720));
}

/// pos-i7-a: 1000 due placements, publishes of 20-50 ms. Unbounded, the tick takes
/// ≥ 1000 / ISSUE_PUBLISH_CONCURRENCY × 35 ms ≈ 4 s; the budget at time_scale 900 (the
/// E2E's) is 800 ms. One call returns within the budget (tolerance 300 ms: the settling
/// of the last publishes by this test-only caller, and scheduling slack) having issued
/// part of them and deferred the rest; every later call issues more, and all 1000 are
/// issued (nothing starves).
#[tokio::test]
async fn issue_tick_stops_at_its_budget_and_later_ticks_issue_the_rest() {
    const DUE: usize = 1000;
    let owner = owner_with_due(125, 8, 900, SlowPostman::lan());
    let budget = issue_budget(3600, 900);
    let bound = budget + Duration::from_millis(300);

    // First call, with its tick line captured.
    let buf = LogBuf::default();
    let writer = buf.clone();
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish(),
    );
    let t = Instant::now();
    tracing::instrument::WithSubscriber::with_subscriber(
        owner.scheduler.issue_due_challenges(),
        dispatch,
    )
    .await
    .expect("issue_due_challenges");
    let took = t.elapsed();
    let first = owner.pending.lock().await.len();

    assert!(
        took <= bound,
        "the first tick took {took:?}, budget {budget:?}"
    );
    assert!(
        first > 0 && first < DUE,
        "the first tick must issue part of {DUE}, issued {first}"
    );
    let logs = buf.text();
    let line = logs
        .lines()
        .find(|l| l.contains("scheduler: PoS issue tick"))
        .unwrap_or_else(|| panic!("no issue tick line; logs:\n{logs}"));
    assert_eq!(field(line, "due"), Some(DUE as u64), "{line}");
    assert_eq!(field(line, "issued"), Some(first as u64), "{line}");
    assert_eq!(
        field(line, "deferred"),
        Some((DUE - first) as u64),
        "what the budget cut is reported deferred: {line}"
    );
    let blocks = field(line, "blocks").expect("blocks");
    assert!(
        blocks >= first.div_ceil(8) as u64 && blocks <= first.div_ceil(8) as u64 + 1,
        "blocks started for {first} challenges of 8 holders each: {line}"
    );
    assert!(field(line, "slowest_publish_ms").is_some(), "{line}");
    assert!(field(line, "in_flight").is_some(), "{line}");

    // The next calls: each issues more, until all are issued.
    let mut calls = 1;
    while owner.pending.lock().await.len() < DUE {
        calls += 1;
        assert!(calls <= 60, "not all {DUE} issued after 60 calls");
        let before = owner.pending.lock().await.len();
        let t = Instant::now();
        owner
            .scheduler
            .issue_due_challenges()
            .await
            .expect("issue_due_challenges");
        let took = t.elapsed();
        let after = owner.pending.lock().await.len();
        assert!(
            took <= bound,
            "call {calls} took {took:?}, budget {budget:?}"
        );
        assert!(
            after > before,
            "call {calls} issued nothing ({before} of {DUE} pending): the rest starves"
        );
    }
    assert!(
        calls > 1,
        "the budget must spread {DUE} challenges over ticks"
    );
}

/// W-1 (СТ-0c round 3): publishes of 2 s each do not stretch the tick. The tick fills
/// the publish slots (block 1: 8, block 2: 1), waits for a free one at most until its
/// budget (800 ms at time_scale 900) ends, and returns within the budget plus one block
/// encode, its publishes still in flight and nothing pending yet. They settle afterwards.
#[tokio::test]
async fn issue_tick_returns_before_its_slow_publishes_settle() {
    let owner = owner_with_due(5, 8, 900, SlowPostman::acking_after(Duration::from_secs(2)));
    let budget = issue_budget(3600, 900);
    let mut in_flight = InFlight::default();

    let t = Instant::now();
    owner
        .scheduler
        .issue_tick(&mut in_flight)
        .await
        .expect("issue_tick");
    let took = t.elapsed();

    assert!(
        took <= budget + Duration::from_millis(150),
        "the tick took {took:?} (budget {budget:?}): it waited for its publishes"
    );
    assert_eq!(
        in_flight.len(),
        ISSUE_PUBLISH_CONCURRENCY,
        "publishes left in flight"
    );
    assert!(owner.pending.lock().await.is_empty(), "nothing acked yet");

    while let Some(done) = in_flight.join_next().await {
        owner
            .scheduler
            .settle_publish(done, &mut in_flight.settled)
            .await;
    }
    assert_eq!(
        owner.pending.lock().await.len(),
        ISSUE_PUBLISH_CONCURRENCY,
        "every acked publish settles into pending"
    );
}

/// W-1: a placement whose challenge is still being published gets no second one. One
/// block of 8 holders (fewer than the publish slots): the first tick starts all 8 and
/// returns; the second finds all 8 in flight and starts none.
#[tokio::test]
async fn a_placement_being_published_gets_no_second_challenge() {
    let owner = owner_with_due(
        1,
        8,
        3600,
        SlowPostman::acking_after(Duration::from_secs(2)),
    );
    let mut in_flight = InFlight::default();

    owner
        .scheduler
        .issue_tick(&mut in_flight)
        .await
        .expect("first tick");
    assert_eq!(in_flight.len(), 8);
    owner
        .scheduler
        .issue_tick(&mut in_flight)
        .await
        .expect("second tick");

    assert_eq!(
        in_flight.len(),
        8,
        "the second tick started a challenge for a placement already in flight"
    );
    let keys: HashSet<_> = in_flight.keys().copied().collect();
    assert_eq!(keys.len(), 8);
    in_flight.shutdown().await;
}

// ─── The stamp of a challenge ─────────────────────────────────────────────────

/// pos-i7-a: a challenge is stamped when it is published, not when its tick started.
/// 24 challenges, ISSUE_PUBLISH_CONCURRENCY (9) publishes in flight, each 1.1 s: three
/// waves ~1.1 s apart. Every stored entry's `stored_at` and signed `timestamp`, and the
/// pending `issued_at`, are ≥ the unix second its store arrived − 1 (Timestamp is whole
/// seconds). Stamped once per tick, the third wave is ≥ 2 s older than its publish.
#[tokio::test]
async fn challenge_is_stamped_at_its_publish_not_at_the_tick_start() {
    let postman = SlowPostman::acking_after(Duration::from_millis(1100));
    let owner = owner_with_due(3, 8, 1, postman.clone());

    owner
        .scheduler
        .issue_due_challenges()
        .await
        .expect("issue_due_challenges");

    let stores = postman.stores();
    let pending = owner.pending.lock().await;
    assert_eq!(pending.len(), 24, "all 24 issued (the budget is 720 s)");
    let first_sent = stores.iter().map(|(s, _)| *s).min().expect("stores");
    let last_sent = stores.iter().map(|(s, _)| *s).max().expect("stores");
    assert!(
        last_sent >= first_sent + 2,
        "precondition: {ISSUE_PUBLISH_CONCURRENCY} in flight, three waves span ≥ 2 s \
         ({first_sent}..{last_sent})"
    );
    let ttl = viaticum_core::mailbox::scaled_ttl_secs(
        viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL.as_secs(),
        1,
    );
    for (sent, req) in &stores {
        let e = &req.entry;
        let msg: PosHashChallengeMsg = from_cbor_bytes(&e.payload).expect("challenge payload");
        assert!(
            e.stored_at + 1 >= *sent,
            "stored_at {} older than its publish at {sent}",
            e.stored_at
        );
        assert_eq!(
            e.expires_at,
            e.stored_at + ttl,
            "expires_at from the same time"
        );
        assert!(
            msg.timestamp.0 + 1 >= *sent,
            "signed timestamp {} older than its publish at {sent}",
            msg.timestamp.0
        );
        let key = pending
            .key_of(&e.msg_id)
            .expect("an acked challenge is pending");
        let issued_at = pending.get(&key).expect("pending").issued_at;
        assert!(
            issued_at.0 + 1 >= *sent,
            "issued_at {} older than its publish at {sent}",
            issued_at.0
        );
    }
}

// ─── The run loop ─────────────────────────────────────────────────────────────

/// pos-i7-a, the run loop: a response that arrives while a tick with 1000 due challenges
/// runs is resolved within one PoS tick period (1 s at time_scale 3600) — the tick yields
/// the loop after its budget (200 ms). Unbounded, the tick holds the loop ≈ 4 s.
#[tokio::test]
async fn response_during_a_long_tick_resolves_within_a_tick_period() {
    let postman = SlowPostman::lan();
    let owner = owner_with_due(125, 8, 3600, postman.clone());
    let (cid, response) = pending_with_response(&owner).await;

    let (response_tx, response_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let pending = owner.pending.clone();
    let run = tokio::spawn(owner.scheduler.run(response_rx, cancel.clone()));

    first_store(&postman).await;
    let delay = resolve_delay(&pending, &response_tx, cid, response).await;
    cancel.cancel();
    run.await.expect("run task").expect("run");

    assert!(
        delay < Duration::from_secs(1),
        "a response sent during the tick resolved after {delay:?} (> one tick period)"
    );
}

/// W-1, the run loop: publishes of 2 s each are settled by the loop, not by the tick. A
/// response that arrives while they are in flight resolves at once (the loop is free),
/// and the publishes land in pending about 2 s later. Cancel aborts what is left.
#[tokio::test]
async fn slow_publishes_settle_through_the_run_loop() {
    let postman = SlowPostman::acking_after(Duration::from_secs(2));
    let owner = owner_with_due(5, 8, 3600, postman.clone());
    let (cid, response) = pending_with_response(&owner).await;

    let (response_tx, response_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let pending = owner.pending.clone();
    let run = tokio::spawn(owner.scheduler.run(response_rx, cancel.clone()));

    first_store(&postman).await;
    let delay = resolve_delay(&pending, &response_tx, cid, response).await;
    let waited = Instant::now();
    while pending.lock().await.len() < ISSUE_PUBLISH_CONCURRENCY {
        assert!(
            waited.elapsed() < Duration::from_secs(10),
            "the publishes never settled through the loop"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cancel.cancel();
    run.await.expect("run task").expect("run");

    assert!(
        delay < Duration::from_millis(500),
        "a response sent while publishes were in flight resolved after {delay:?}: \
         the loop waited for the publishes"
    );
}
