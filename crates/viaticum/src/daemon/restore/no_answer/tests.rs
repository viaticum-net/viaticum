// restore-i26: a round nobody answered is retried after a redial and a pause; the
// pause budget belongs to the job. Pattern: what_when_then.
//
// Block-level tests call `decode_block_local` on a paused tokio clock
// (`start_paused`): the minutes are virtual and measured exactly. Job-level tests
// go through `restore()`, which needs the multi-thread runtime (staging writes use
// `block_in_place`), so they run on the real clock with the pauses shrunk by
// `time_scale`, or cancel the pause long before it ends.
//
// `FakeHolders` (restore/tests.rs) with `offline` set fails every request at once,
// as `send_to_device` does without a live connection; `online_after_reconnects`
// makes the N-th `reconnect` bring the holders back.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tempfile::TempDir;
use viaticum_core::db::Db;
use viaticum_core::types::DeviceId;

use super::{NO_ANSWER_PAUSES_SECS, NoAnswerPauses};
use crate::cli::types::{RestoreFailureKind, RestoreOutcome};
use crate::daemon::restore::staging::JobId;
use crate::daemon::restore::tests::{
    FakeHolders, backup_one, coord_with_source, place_on_fake_holders, request,
};
use crate::daemon::restore::{RestoreCoordinator, RestoreError};
use crate::daemon::symbol_fetch::{Round, RoundEnd};

const MIN: Duration = Duration::from_secs(60);

/// The three fake holders `place_on_fake_holders` spreads a block over.
fn fake_holder_ids() -> Vec<DeviceId> {
    (0..3u8).map(|h| DeviceId([0x40 + h; 32])).collect()
}

struct Setup {
    dirs: (TempDir, TempDir, TempDir),
    db: Db,
    holders: Arc<FakeHolders>,
    paths: Vec<String>,
}

/// `files` backed up, each its own block, spread over the fake holders; the
/// sources are deleted so restore must use the network. Holders start offline.
async fn setup(files: &[(&str, &[u8])]) -> Setup {
    let db = Db::open_in_memory().unwrap();
    let dirs = (
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    );
    let holders = Arc::new(FakeHolders::default());
    let mut paths = Vec::new();
    for (name, content) in files {
        let path = backup_one(&db, &dirs.0, dirs.1.path(), name, content);
        place_on_fake_holders(&db, &path, &holders).await;
        paths.push(path);
    }
    for path in &paths {
        std::fs::remove_file(path).unwrap();
    }
    holders.offline.store(true, Ordering::SeqCst);
    Setup {
        dirs,
        db,
        holders,
        paths,
    }
}

impl Setup {
    fn coord(&self) -> RestoreCoordinator {
        coord_with_source(self.db.clone(), &self.dirs.2, Some(self.holders.clone()))
    }

    fn prefix(&self) -> String {
        self.dirs.1.path().to_string_lossy().into_owned() + "/"
    }

    /// Decode the block of `paths[i]` with the given budget.
    async fn decode(
        &self,
        coord: &RestoreCoordinator,
        i: usize,
        pauses: &mut NoAnswerPauses,
    ) -> Result<Vec<u8>, RestoreError> {
        let block = self.db.get_file(&self.paths[i]).unwrap().unwrap().versions[0].source_block_id;
        let rec = self.db.get_source_block(&block).unwrap().unwrap();
        coord
            .decode_block_local(
                &block,
                &rec.erasure_params(),
                rec.encrypted_size.unwrap(),
                pauses,
            )
            .await
    }

    fn reconnect_count(&self) -> usize {
        self.holders.reconnects.lock().unwrap().len()
    }

    fn request_count(&self) -> usize {
        self.holders.requests.lock().unwrap().len()
    }
}

// ─── The budget itself ─────────────────────────────────────────────────────────

#[test]
fn pauses_are_1_5_15_min_then_spent() {
    let mut p = NoAnswerPauses::new(JobId::new(), 1);
    assert_eq!(NO_ANSWER_PAUSES_SECS, [60, 300, 900]);
    assert_eq!(p.take(), Some(MIN));
    assert_eq!(p.take(), Some(5 * MIN));
    assert_eq!(p.take(), Some(15 * MIN));
    assert_eq!(p.take(), None);
    assert_eq!(p.take(), None, "stays spent");
}

fn round(end: RoundEnd, answered: &[DeviceId], failed: &[DeviceId]) -> Round {
    Round {
        end,
        answered: answered.to_vec(),
        failed: failed.to_vec(),
    }
}

/// restore-i34: only a holder that had gone silent (failed in a `NoAnswer` round)
/// refills the budget by answering; a holder that never went silent does not, even
/// with progress; an empty answer from it in a `NoAnswer` round neither (i33).
#[test]
fn observe_refills_only_when_a_silent_holder_answers() {
    let (live, dead) = (DeviceId([1u8; 32]), DeviceId([2u8; 32]));
    let mut p = NoAnswerPauses::new(JobId::new(), 1);
    p.observe(&round(RoundEnd::Progress, &[live], &[dead]));
    assert_eq!(p.take(), Some(MIN));
    p.observe(&round(RoundEnd::NoAnswer, &[live], &[dead]));
    assert_eq!(p.take(), Some(5 * MIN));
    p.observe(&round(RoundEnd::Progress, &[live], &[]));
    assert_eq!(p.take(), Some(15 * MIN), "the live holder proves nothing");
    assert_eq!(p.take(), None);

    p.observe(&round(RoundEnd::Progress, &[dead], &[]));
    assert_eq!(
        p.take(),
        Some(MIN),
        "the silent holder is back: full budget"
    );
    p.observe(&round(RoundEnd::Progress, &[dead], &[]));
    assert_eq!(
        p.take(),
        Some(5 * MIN),
        "no longer silent: its next answer refills nothing"
    );
}

#[test]
fn pauses_are_divided_by_time_scale() {
    let mut p = NoAnswerPauses::new(JobId::new(), 60);
    assert_eq!(p.take(), Some(Duration::from_secs(1)));
    assert_eq!(p.take(), Some(Duration::from_secs(5)));
    assert_eq!(p.take(), Some(Duration::from_secs(15)));
    let mut p0 = NoAnswerPauses::new(JobId::new(), 0);
    assert_eq!(p0.take(), Some(MIN), "time_scale 0 reads as 1");
}

// ─── Block level, virtual clock ───────────────────────────────────────────────

/// (а) Restore starts before any connection is up: the first round gets no
/// answer; the holders are redialed, and after the 1-min pause they answer and
/// the block decodes.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn decode_when_no_holder_answers_redials_pauses_and_decodes_after_reconnect() {
    let content = b"restore right after dr".repeat(40);
    let s = setup(&[("a.bin", &content)]).await;
    *s.holders.online_after_reconnects.lock().unwrap() = Some(1);
    let coord = s.coord();
    // A registered, running job: its progress shows the wait, and only during it.
    let jobs = coord.config.jobs.clone();
    let job_id = JobId::new();
    jobs.submit(job_id, &s.paths[0], 1);
    jobs.mark_running(job_id, &s.paths[0], 1);
    let during = {
        let jobs = jobs.clone();
        tokio::spawn(async move {
            tokio::time::sleep(MIN / 2).await;
            jobs.get(job_id).unwrap().waiting_for_holders_until
        })
    };
    let t0 = tokio::time::Instant::now();

    let plaintext = s
        .decode(&coord, 0, &mut NoAnswerPauses::new(job_id, 1))
        .await
        .expect("holders back after the redial");

    assert!(plaintext.ends_with(&content));
    assert!(
        during.await.unwrap().is_some(),
        "mid-pause the job shows until when it waits"
    );
    assert_eq!(
        jobs.get(job_id).unwrap().waiting_for_holders_until,
        None,
        "after the pause the job no longer shows a wait"
    );
    let calls = s.holders.reconnects.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "one redial for one pause");
    assert_eq!(calls[0].0, t0, "redial before the pause, not after");
    let mut redialed = calls[0].1.clone();
    redialed.sort_by_key(|d| d.0);
    assert_eq!(
        redialed,
        fake_holder_ids(),
        "the block's holders are redialed"
    );
    assert_eq!(t0.elapsed(), MIN, "exactly one 1-min pause");
}

/// (б) Dead holders: 4 rounds nobody answered → 3 pauses (1 + 5 + 15 min), then
/// `holders_unavailable`. One redial per pause, one round per pause plus the first.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn decode_when_holders_never_answer_gives_up_after_three_pauses_21_min() {
    let s = setup(&[("dead.bin", &[7u8; 3000])]).await;
    let coord = s.coord();
    let t0 = tokio::time::Instant::now();

    let err = s
        .decode(&coord, 0, &mut NoAnswerPauses::new(JobId::new(), 1))
        .await
        .unwrap_err();

    assert!(
        matches!(err, RestoreError::InsufficientSymbols { got: 0, .. }),
        "{err:?}"
    );
    assert_eq!(t0.elapsed(), 21 * MIN);
    assert_eq!(s.reconnect_count(), 3);
    assert_eq!(s.request_count(), 4 * 3, "4 rounds over 3 holders");
}

/// (б, scaled) The same budget under `time_scale = 60`: 21 s.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn decode_when_holders_never_answer_waits_21_min_divided_by_time_scale() {
    let s = setup(&[("dead.bin", &[7u8; 3000])]).await;
    let coord = s.coord();
    let t0 = tokio::time::Instant::now();

    s.decode(&coord, 0, &mut NoAnswerPauses::new(JobId::new(), 60))
        .await
        .unwrap_err();

    assert_eq!(t0.elapsed(), Duration::from_secs(21));
}

/// (в) An answer refills the budget: block 1 waits 1 + 5 min and then decodes;
/// block 2 (holders gone again) still gets all three pauses. Total 6 + 21 min;
/// without the refill block 2 would get only the 15-min pause (21 min in all).
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn decode_answer_between_pauses_refills_the_budget() {
    let s = setup(&[("one.bin", &[1u8; 3000]), ("two.bin", &[2u8; 3000])]).await;
    *s.holders.online_after_reconnects.lock().unwrap() = Some(2);
    let coord = s.coord();
    let mut pauses = NoAnswerPauses::new(JobId::new(), 1);
    let t0 = tokio::time::Instant::now();

    s.decode(&coord, 0, &mut pauses)
        .await
        .expect("back after the second redial");
    assert_eq!(t0.elapsed(), 6 * MIN);

    s.holders.offline.store(true, Ordering::SeqCst);
    s.decode(&coord, 1, &mut pauses).await.unwrap_err();
    assert_eq!(
        t0.elapsed(),
        27 * MIN,
        "a full budget again after the answer"
    );
    assert_eq!(s.reconnect_count(), 5);
}

/// restore-i34 (review BLOCK-1): one holder is alive but holds fewer than k_eff
/// symbols, the other two are dead. Its answers prove nothing about the dead ones,
/// so they do not refill the budget: two such blocks cost the job exactly 3 pauses
/// and 21 min, not 3 pauses per block.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn decode_live_holder_short_of_k_eff_and_dead_others_spend_one_budget_21_min() {
    let s = setup(&[("p.bin", &[8u8; 3000]), ("q.bin", &[9u8; 3000])]).await;
    s.holders.offline.store(false, Ordering::SeqCst);
    s.holders
        .dead
        .lock()
        .unwrap()
        .extend([DeviceId([0x41; 32]), DeviceId([0x42; 32])]);
    // The live holder keeps one symbol per block (ESI 0): fewer than k_eff.
    let live = DeviceId([0x40; 32]);
    s.holders
        .symbols
        .lock()
        .unwrap()
        .retain(|(h, _, esi), _| *h != live || *esi == 0);
    let coord = s.coord();
    let mut pauses = NoAnswerPauses::new(JobId::new(), 1);
    let t0 = tokio::time::Instant::now();

    for i in 0..2 {
        let err = s.decode(&coord, i, &mut pauses).await.unwrap_err();
        assert!(
            matches!(err, RestoreError::InsufficientSymbols { got: 1, .. }),
            "the live holder gave some, not enough: {err:?}"
        );
    }

    assert_eq!(t0.elapsed(), 21 * MIN, "one budget for the job");
    assert_eq!(s.reconnect_count(), 3);
}

/// restore-i33: one holder is connected and has nothing for the block, the other
/// two are not connected yet. That is not "holders have nothing": the job pauses,
/// redials, and the two come back with enough.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn decode_one_holder_empty_others_unreachable_pauses_and_decodes() {
    let content = b"one empty, two not connected yet".repeat(30);
    let s = setup(&[("m.bin", &content)]).await;
    s.holders.offline.store(false, Ordering::SeqCst);
    let empty = DeviceId([0x40; 32]);
    s.holders
        .symbols
        .lock()
        .unwrap()
        .retain(|(h, _, _), _| *h != empty);
    let others = [DeviceId([0x41; 32]), DeviceId([0x42; 32])];
    s.holders.dead.lock().unwrap().extend(others);
    let coord = s.coord();
    let holders = s.holders.clone();
    // The redial reconnects the two.
    *s.holders.on_request.lock().unwrap() = Some(Box::new(move || {
        if !holders.reconnects.lock().unwrap().is_empty() {
            holders.dead.lock().unwrap().clear();
        }
    }));
    let t0 = tokio::time::Instant::now();

    let plaintext = s
        .decode(&coord, 0, &mut NoAnswerPauses::new(JobId::new(), 1))
        .await
        .expect("the two answer after the redial");

    assert!(plaintext.ends_with(&content));
    assert_eq!(s.reconnect_count(), 1);
    assert_eq!(t0.elapsed(), MIN);
}

/// (е) Holders answer but have nothing: the restore-i12 verdict at once — no
/// pause, no redial.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn decode_when_holders_answer_empty_fails_at_once_without_pause() {
    let s = setup(&[("empty.bin", &[3u8; 3000])]).await;
    s.holders.symbols.lock().unwrap().clear();
    s.holders.offline.store(false, Ordering::SeqCst);
    let coord = s.coord();
    let t0 = tokio::time::Instant::now();

    let err = s
        .decode(&coord, 0, &mut NoAnswerPauses::new(JobId::new(), 1))
        .await
        .unwrap_err();

    assert!(
        matches!(err, RestoreError::InsufficientSymbols { got: 0, .. }),
        "{err:?}"
    );
    assert_eq!(t0.elapsed(), Duration::ZERO);
    assert_eq!(s.reconnect_count(), 0);
    assert_eq!(s.request_count(), 3, "one round, each holder once");
}

// ─── Job level, real clock ─────────────────────────────────────────────────────

/// (г) The budget is the job's: two blocks with dead holders take 3 pauses in
/// all, not 3 each. The second block gets one round without a pause and is given
/// up; both files are `holders_unavailable`, the job `nothing_restored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_job_with_dead_holders_spends_one_budget_across_blocks() {
    let s = setup(&[("x.bin", &[4u8; 3000]), ("y.bin", &[5u8; 3000])]).await;
    let mut coord = s.coord();
    // 1 ms, 5 ms, 15 ms.
    coord.config.time_scale = 60_000;

    let req = request(&s.prefix());
    let job_id = req.job_id;
    let result = tokio::time::timeout(Duration::from_secs(10), coord.restore(req))
        .await
        .expect("a job with dead holders ends")
        .unwrap();

    assert_eq!(result.files_restored, 0);
    assert_eq!(result.failures.len(), 2);
    assert!(
        result
            .failures
            .iter()
            .all(|f| f.kind == RestoreFailureKind::HoldersUnavailable),
        "{:?}",
        result.failures
    );
    assert_eq!(s.reconnect_count(), 3, "one budget for the job");
    assert_eq!(
        s.request_count(),
        4 * 3 + 3,
        "block 1: 4 rounds; block 2: one round, no pause"
    );
    let record = coord.config.jobs.record(job_id).unwrap();
    assert_eq!(record.outcome, Some(RestoreOutcome::NothingRestored));
}

/// (д) + progress: while the job pauses, its progress says until when it waits
/// (restore-i4); the daemon stopping during the (1-min) pause ends the job at once,
/// `interrupted`, well inside the 10 s drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_cancel_during_pause_interrupts_job_at_once_and_pause_is_visible() {
    let s = setup(&[("w.bin", &[6u8; 3000])]).await;
    let coord = s.coord();
    let (jobs, cancel) = (coord.config.jobs.clone(), coord.config.cancel.clone());
    let req = request(&s.prefix());
    let job_id = req.job_id;

    let watcher = tokio::spawn(async move {
        for _ in 0..500 {
            if let Some(job) = jobs.get(job_id)
                && let Some(until) = job.waiting_for_holders_until
            {
                cancel.cancel();
                return Some(until);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        None
    });
    let t0 = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(5), coord.restore(req))
        .await
        .expect("cancel must end the pause at once")
        .unwrap();

    let until = watcher.await.unwrap().expect("the pause shows in progress");
    assert!(until.ends_with('Z'), "{until}");
    assert!(t0.elapsed() < Duration::from_secs(5));
    assert!(result.interrupted);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].kind, RestoreFailureKind::Interrupted);
    assert_eq!(s.reconnect_count(), 1);
    let done = coord.config.jobs.get(job_id).unwrap();
    assert_eq!(done.outcome, Some(RestoreOutcome::Interrupted));
    assert_eq!(done.waiting_for_holders_until, None, "cleared at the end");
}

// ─── restore-i44: a holder that failed in the job is asked last ───────────────

/// The connected holder (asked first, restore-i43) times out on every request; the two others
/// hold enough. With one budget for the job it is asked on the first block only; with a
/// budget per block (the job's memory lost between blocks) it is asked on each block.
/// Mutation: `fetch_from_holders` without `.in_task(&pauses.failed_in_job)` → reddens.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn holder_failing_in_the_job_is_asked_on_the_first_block_only() {
    const FILES: usize = 4;
    let names: Vec<String> = (0..FILES).map(|i| format!("f{i}.bin")).collect();
    let contents: Vec<Vec<u8>> = (0..FILES).map(|i| vec![i as u8 + 1; 3000]).collect();
    let files: Vec<(&str, &[u8])> = names
        .iter()
        .zip(&contents)
        .map(|(n, c)| (n.as_str(), c.as_slice()))
        .collect();
    let s = setup(&files).await;
    s.holders.offline.store(false, Ordering::SeqCst);
    let silent = fake_holder_ids()[0];
    s.holders.timing_out.lock().unwrap().insert(silent);
    s.holders.connected.lock().unwrap().insert(silent);
    let coord = s.coord();
    let asked_silent = || {
        s.holders
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(h, _)| *h == silent)
            .count()
    };

    let mut job = NoAnswerPauses::new(JobId::new(), 1);
    for i in 0..FILES {
        s.decode(&coord, i, &mut job)
            .await
            .expect("the two others hold enough");
    }
    assert_eq!(asked_silent(), 1, "one timeout for the whole job");

    for i in 0..FILES {
        s.decode(&coord, i, &mut NoAnswerPauses::new(JobId::new(), 1))
            .await
            .expect("the two others hold enough");
    }
    assert_eq!(
        asked_silent(),
        1 + FILES,
        "a fresh job asks it first again, on every block"
    );
}
