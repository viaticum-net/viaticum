// pos-i7-a: the issue tick is bounded by a time budget (a fifth of the PoS tick period),
// publishes with bounded concurrency, leaves what it did not reach due for the next tick,
// and stamps every challenge at its own publish, not at the tick's start.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use viaticum_core::db::Db;
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
    PosHashChallengeMsg,
};
use viaticum_core::pos::ChallengeScheduleEntry;
use viaticum_core::types::{DeviceId, IdentityPub, SourceBlockId, Timestamp, from_cbor_bytes};

use super::pos_scale::{LogBuf, field};
use super::{
    TEST_EPOCH_KEY, dummy_master_pub, make_identity, make_peer_record, make_pending_challenges,
    make_placement, make_test_encoder, seed_retained_pos_block,
};
use crate::daemon::mailbox::routing::{MailboxNetworkSender, MailboxRouter};
use crate::daemon::repair::RepairTrigger;
use crate::daemon::scheduler::issue::{
    ISSUE_PUBLISH_CONCURRENCY, blocks_least_recently_verified_first, issue_budget,
};
use crate::daemon::scheduler::{
    PendingChallenges, PendingHashChallenge, Scheduler, SchedulerConfig,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

/// A postman that answers every store with an Ack after a delay, recording each
/// request with the unix second it arrived.
struct SlowAckSender {
    delay: fn(&[u8; 16]) -> Duration,
    stores: std::sync::Mutex<Vec<(u64, MailboxStoreRequest)>>,
}

impl SlowAckSender {
    fn new(delay: fn(&[u8; 16]) -> Duration) -> Arc<Self> {
        Arc::new(SlowAckSender {
            delay,
            stores: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn store_count(&self) -> usize {
        self.stores.lock().unwrap().len()
    }

    fn stores(&self) -> Vec<(u64, MailboxStoreRequest)> {
        self.stores.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl MailboxNetworkSender for SlowAckSender {
    async fn send_store(
        &self,
        _device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        let msg_id = req.entry.msg_id;
        let delay = (self.delay)(&msg_id);
        self.stores.lock().unwrap().push((unix_secs(), req));
        tokio::time::sleep(delay).await;
        Ok(MailboxStoreResponse::Ack { msg_id })
    }
    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        anyhow::bail!("slow ack sender: fetch not used")
    }
}

/// 20-50 ms per store, fixed per challenge (a LAN postman under load).
fn lan_delay(msg_id: &[u8; 16]) -> Duration {
    Duration::from_millis(20 + u64::from(msg_id[0]) % 31)
}

/// Longer than a second: publishes of different waves land in different unix seconds.
fn second_delay(_msg_id: &[u8; 16]) -> Duration {
    Duration::from_millis(1100)
}

struct Owner {
    scheduler: Scheduler,
    pending: PendingChallenges,
    _data_dir: tempfile::TempDir,
}

/// An owner with `blocks` blocks × `holders` holders, every placement due (never
/// verified), publishing through `sender` to its one known peer, a postman with a real
/// Ed25519 id. The holders are no peers (medium trust): one store per publish.
fn owner_with_due(blocks: u8, holders: u8, time_scale: u64, sender: Arc<SlowAckSender>) -> Owner {
    let db = Db::open_in_memory().expect("db open");
    let data_dir = tempfile::TempDir::new().unwrap();
    let holder_ids: Vec<DeviceId> = (0..holders).map(|h| make_identity(0x80 + h)).collect();
    let postman = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]);
    db.upsert_peer(&make_peer_record(DeviceId(
        postman.verifying_key().to_bytes(),
    )))
    .unwrap();
    for b in 0..blocks {
        let block_id = seed_retained_pos_block(data_dir.path(), &db, b);
        for h in &holder_ids {
            db.upsert_placement(&make_placement(block_id, *h)).unwrap();
        }
    }
    let pending = make_pending_challenges();
    let router = Arc::new(MailboxRouter::with_sender(
        sender as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let scheduler = Scheduler::new(
        db,
        SchedulerConfig {
            pos_interval_secs: 3600,
            timeout_check_secs: 3600,
            time_scale,
            event_log_retain_rows: 100_000,
            pos_weekly_retain_weeks: viaticum_core::constants::P_WINDOW_WEEKS * 2,
        },
        repair_tx,
        pending.clone(),
        router,
        dummy_master_pub(),
        ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
        crate::daemon::processor::make_empty_accepted_offers(),
        make_test_encoder(),
        TEST_EPOCH_KEY,
        data_dir.path().to_path_buf(),
    );
    Owner {
        scheduler,
        pending,
        _data_dir: data_dir,
    }
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
/// ≥ 1000 / ISSUE_PUBLISH_CONCURRENCY × 35 ms ≈ 2 s (≈ 4.6 s measured in a debug
/// build); the budget at time_scale 900 (the E2E's) is 800 ms. One call returns within
/// the budget (tolerance 300 ms: a publish in flight and scheduling slack) having issued
/// part of them and deferred the rest; every later call issues more, and all 1000 are
/// issued (nothing starves).
#[tokio::test]
async fn issue_tick_stops_at_its_budget_and_later_ticks_issue_the_rest() {
    const DUE: usize = 1000;
    let sender = SlowAckSender::new(lan_delay);
    let owner = owner_with_due(125, 8, 900, sender);
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

/// pos-i7-a: a challenge is stamped when it is published, not when its tick started.
/// 40 challenges, 16 publishes in flight, each publish 1.1 s: three waves ~1.1 s apart.
/// Every stored entry's `stored_at` and signed `timestamp`, and the pending `issued_at`,
/// are ≥ the unix second its store arrived − 1 (Timestamp is whole seconds). Stamped
/// once per tick, the third wave is ≥ 2 s older than its publish.
#[tokio::test]
async fn challenge_is_stamped_at_its_publish_not_at_the_tick_start() {
    let sender = SlowAckSender::new(second_delay);
    let owner = owner_with_due(5, 8, 1, sender.clone());

    owner
        .scheduler
        .issue_due_challenges()
        .await
        .expect("issue_due_challenges");

    let stores = sender.stores();
    let pending = owner.pending.lock().await;
    assert_eq!(pending.len(), 40, "all 40 issued (the budget is 720 s)");
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

/// pos-i7-a, the run loop: a response that arrives while a tick with 1000 due challenges
/// runs is resolved within one PoS tick period (1 s at time_scale 3600) — the tick yields
/// the loop after its budget (200 ms). Unbounded, the tick holds the loop ≈ 2 s.
#[tokio::test]
async fn response_during_a_long_tick_resolves_within_a_tick_period() {
    let sender = SlowAckSender::new(lan_delay);
    let owner = owner_with_due(125, 8, 3600, sender.clone());

    // A challenge already pending, answered by a holder with a real key.
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
            holder_master: IdentityPub(holder.0),
        },
    );
    let response = viaticum_core::messages::build_pos_hash_response(
        cid,
        block,
        [0u8; 32],
        Timestamp::now(),
        None,
        &holder_key,
    );

    let (response_tx, response_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let pending = owner.pending.clone();
    let run = tokio::spawn(owner.scheduler.run(response_rx, cancel.clone()));

    // Wait for the first issue tick to start publishing, then answer.
    let waited = Instant::now();
    while sender.store_count() == 0 {
        assert!(waited.elapsed() < Duration::from_secs(10), "no issue tick");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    response_tx.send(response).await.expect("scheduler alive");
    let sent = Instant::now();
    while pending.lock().await.contains_challenge(&cid) {
        assert!(sent.elapsed() < Duration::from_secs(10), "never resolved");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let delay = sent.elapsed();
    cancel.cancel();
    run.await.expect("run task").expect("run");

    assert!(
        delay < Duration::from_secs(1),
        "a response sent during the tick resolved after {delay:?} (> one tick period)"
    );
}

// ─── Fairness: the order of blocks ────────────────────────────────────────────

#[test]
fn blocks_least_recently_verified_first_puts_never_verified_then_oldest() {
    let block = |b: u8| SourceBlockId([b; 32]);
    let (h1, h2) = (make_identity(1), make_identity(2));
    let entry = |b: u8, h: DeviceId| ChallengeScheduleEntry {
        holder_id: h,
        source_block_id: block(b),
        cpw: 1,
    };
    // In `due` order: A (300), B (h1 at 50, h2 never), C (100), D (100).
    let due = [
        entry(0xA, h1),
        entry(0xB, h1),
        entry(0xC, h1),
        entry(0xB, h2),
        entry(0xD, h1),
    ];
    let last_verified = |k: &(SourceBlockId, DeviceId)| match (k.0.0[0], k.1 == h2) {
        (0xA, _) => Some(Timestamp(300)),
        (0xB, false) => Some(Timestamp(50)),
        (0xB, true) => None,
        _ => Some(Timestamp(100)),
    };

    let ordered = blocks_least_recently_verified_first(due.iter(), last_verified);

    let order: Vec<u8> = ordered.iter().map(|(b, _)| b.0[0]).collect();
    assert_eq!(
        order,
        vec![0xB, 0xC, 0xD, 0xA],
        "never verified first, then oldest; C and D tie and keep the order of due"
    );
    let b_holders: Vec<DeviceId> = ordered[0].1.iter().map(|e| e.holder_id).collect();
    assert_eq!(b_holders, vec![h1, h2], "a block keeps all its due entries");
}
