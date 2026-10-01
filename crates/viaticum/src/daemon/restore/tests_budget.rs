// Restore under the memory budget (К-b3, restore-i39; spec v3.8 §5, v3.9).
//
// The block work budget is the node's; a restore takes one permit per block as a priority waiter,
// only in its job task, and lets it go before the plaintext reaches the writer. The fixtures are
// small blocks (K = 2): the estimates are exact functions of (k, t) and the decode of the real
// RaptorQ coder runs in milliseconds; the permits and the order of events are what is measured.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::TempDir;
use tracing::instrument::WithSubscriber;
use viaticum_core::db::Db;
use viaticum_core::erasure::{ErasureEncoder, ErasureError, RaptorQEncoder, Symbol, SymbolSink};
use viaticum_core::types::{DeviceId, ErasureParams, SourceBlockId, SourceBlockRecord};

use super::tests::{FakeHolders, TEST_EPOCH_KEY, backup_one, place_on_fake_holders, request};
use super::{RestoreConfig, RestoreCoordinator};
use crate::daemon::mem_budget::{
    HolderKind, MemBudget, PriorityKind, estimate_restore_local, estimate_restore_network,
    estimate_restore_plaintext,
};
use crate::daemon::restore::jobs::RestoreJobs;
use crate::daemon::restore::no_answer::NoAnswerPauses;
use crate::daemon::restore::staging::JobId;
use crate::daemon::symbol_fetch::RestoreSource;

const MIB: u64 = 1 << 20;

// ─── Fixtures ─────────────────────────────────────────────────────────────────

/// An encoder that counts its calls and, when it has a budget, records what the budget held
/// at the moment of each decode.
#[derive(Default)]
struct CountingEncoder {
    inner: RaptorQEncoder,
    encodes: AtomicUsize,
    decodes: AtomicUsize,
    budget: Option<Arc<MemBudget>>,
    held_at_decode: Mutex<Vec<u64>>,
}

impl CountingEncoder {
    fn watching(budget: &Arc<MemBudget>) -> Arc<Self> {
        Arc::new(CountingEncoder {
            budget: Some(Arc::clone(budget)),
            ..Default::default()
        })
    }
}

impl ErasureEncoder for CountingEncoder {
    fn encode(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        start_esi: u32,
        count: u32,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Result<Vec<Symbol>, ErasureError> {
        self.encodes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .encode(source_block, params, start_esi, count, block_id, holder_id)
    }

    fn decode(&self, symbols: &[Symbol], params: &ErasureParams) -> Result<Vec<u8>, ErasureError> {
        self.decodes.fetch_add(1, Ordering::SeqCst);
        if let Some(budget) = &self.budget {
            self.held_at_decode
                .lock()
                .unwrap()
                .push(budget.outstanding_bytes());
        }
        self.inner.decode(symbols, params)
    }

    fn generate_repair(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        esi: u32,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Result<Symbol, ErasureError> {
        self.encodes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .generate_repair(source_block, params, esi, block_id, holder_id)
    }

    fn unbind(&self, symbol: Symbol, block_id: &SourceBlockId, holder_id: &DeviceId) -> Symbol {
        self.inner.unbind(symbol, block_id, holder_id)
    }

    fn encode_raw(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        start_esi: u32,
        count: u32,
    ) -> Result<Vec<Symbol>, ErasureError> {
        self.encodes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .encode_raw(source_block, params, start_esi, count)
    }

    fn encode_raw_ranges(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        ranges: &[(u32, u32)],
    ) -> Result<Vec<Symbol>, ErasureError> {
        self.encodes.fetch_add(1, Ordering::SeqCst);
        self.inner.encode_raw_ranges(source_block, params, ranges)
    }

    fn encode_raw_ranges_each(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        ranges: &[(u32, u32)],
        f: &mut SymbolSink<'_>,
    ) -> Result<(), ErasureError> {
        self.encodes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .encode_raw_ranges_each(source_block, params, ranges, f)
    }

    fn apply_binding(
        &self,
        raw_symbol: Symbol,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Symbol {
        self.inner.apply_binding(raw_symbol, block_id, holder_id)
    }
}

struct World {
    db: Db,
    symbols: TempDir,
    files: TempDir,
    staging: TempDir,
}

impl World {
    fn new() -> World {
        World {
            db: Db::open_in_memory().unwrap(),
            symbols: TempDir::new().unwrap(),
            files: TempDir::new().unwrap(),
            staging: TempDir::new().unwrap(),
        }
    }

    /// Back `content` up as its own block; its path.
    fn backup(&self, name: &str, content: &[u8]) -> String {
        backup_one(&self.db, &self.symbols, self.files.path(), name, content)
    }

    /// Back it up and spread its symbols over fake holders (the source stays).
    async fn backup_placed(&self, name: &str, content: &[u8], holders: &FakeHolders) -> String {
        let path = self.backup(name, content);
        place_on_fake_holders(&self.db, &path, holders).await;
        path
    }

    fn block_of(&self, path: &str) -> (SourceBlockId, SourceBlockRecord) {
        let id = self.db.get_file(path).unwrap().unwrap().versions[0].source_block_id;
        (id, self.db.get_source_block(&id).unwrap().unwrap())
    }

    fn coord(
        &self,
        budget: &Arc<MemBudget>,
        holders: Option<&Arc<FakeHolders>>,
        encoder: Arc<dyn ErasureEncoder>,
    ) -> RestoreCoordinator {
        let staging_root = self.staging.path().join("restore");
        std::fs::create_dir_all(&staging_root).unwrap();
        let mut config = RestoreConfig::new(
            TEST_EPOCH_KEY,
            staging_root,
            self.staging.path().to_path_buf(),
        );
        config.symbols = holders.map(|h| Arc::clone(h) as Arc<dyn RestoreSource>);
        config.mem_budget = Arc::clone(budget);
        RestoreCoordinator::new(self.db.clone(), config, encoder)
    }
}

fn raptorq() -> Arc<dyn ErasureEncoder> {
    Arc::new(RaptorQEncoder::new())
}

fn staged(result: &super::RestoreResult, path: &str) -> Vec<u8> {
    std::fs::read(result.staging_path.join(path.trim_start_matches('/'))).unwrap()
}

/// What a future logs (DEBUG and above), from every task it is polled in.
async fn logged<F: Future>(f: F) -> (F::Output, String) {
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let out = f.with_subscriber(tracing::Dispatch::new(subscriber)).await;
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (out, text)
}

/// The sizes of the restore permits a log shows, in order.
fn granted_bytes(log: &str) -> Vec<u64> {
    log.lines()
        .filter(|l| l.contains("mem_budget: granted kind=restore"))
        .filter_map(|l| {
            l.split("bytes=")
                .nth(1)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .collect()
}

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn need_network(rec: &SourceBlockRecord) -> u64 {
    let p = rec.erasure_params();
    estimate_restore_network(p.k, p.t)
}

// ─── The network tier ─────────────────────────────────────────────────────────

/// M14: the decode of the network tier runs under the restore permit sized for it
/// (`estimate_restore_network`): the budget holds exactly that at the moment of the decode, and
/// nothing while the symbols are fetched or the file is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_network_decodes_under_one_restore_permit() {
    let w = World::new();
    let content = b"network restore content ".repeat(50);
    let holders = Arc::new(FakeHolders::default());
    let path = w.backup_placed("net.bin", &content, &holders).await;
    let (_, rec) = w.block_of(&path);
    std::fs::remove_file(&path).unwrap();

    let budget = MemBudget::new(1 << 30);
    let encoder = CountingEncoder::watching(&budget);
    let coord = w.coord(&budget, Some(&holders), encoder.clone());
    let at_fetch = Arc::new(Mutex::new(Vec::new()));
    let at_write = Arc::new(Mutex::new(Vec::new()));
    {
        let (b, seen) = (Arc::clone(&budget), Arc::clone(&at_fetch));
        *holders.on_request.lock().unwrap() = Some(Box::new(move || {
            seen.lock().unwrap().push(b.outstanding_bytes())
        }));
        let (b, seen) = (Arc::clone(&budget), Arc::clone(&at_write));
        *coord.write_hook.lock().unwrap() = Some(Box::new(move || {
            seen.lock().unwrap().push(b.outstanding_bytes())
        }));
    }

    let result = coord.restore(request(&path)).await.unwrap();

    assert_eq!(result.files_restored, 1, "{:?}", result.failures);
    assert!(staged(&result, &path).ends_with(&content));
    assert_eq!(
        *encoder.held_at_decode.lock().unwrap(),
        vec![need_network(&rec)],
        "one restore permit, the size of the decode, is held while the block decodes"
    );
    let fetch = at_fetch.lock().unwrap();
    assert!(
        !fetch.is_empty() && fetch.iter().all(|&b| b == 0),
        "{fetch:?}"
    );
    let write = at_write.lock().unwrap();
    assert!(
        !write.is_empty() && write.iter().all(|&b| b == 0),
        "{write:?}"
    );
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// M58: the permit is gone before a file is written to staging — a staging directory on a
/// network folder may hang, and the budget must not hang with it (J14). Both tiers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_releases_permit_before_writing_files() {
    for local in [true, false] {
        let w = World::new();
        let content = b"released before the write ".repeat(40);
        let holders = Arc::new(FakeHolders::default());
        let path = w.backup_placed("w.bin", &content, &holders).await;
        if !local {
            std::fs::remove_file(&path).unwrap();
        }
        let budget = MemBudget::new(1 << 30);
        let coord = w.coord(&budget, Some(&holders), raptorq());
        let at_write = Arc::new(Mutex::new(Vec::new()));
        {
            let (b, seen) = (Arc::clone(&budget), Arc::clone(&at_write));
            *coord.write_hook.lock().unwrap() = Some(Box::new(move || {
                seen.lock().unwrap().push(b.outstanding_bytes())
            }));
        }

        let result = coord.restore(request(&path)).await.unwrap();

        assert_eq!(
            result.files_restored, 1,
            "local = {local}: {:?}",
            result.failures
        );
        assert!(budget.grants() >= 1, "local = {local}: a permit was taken");
        assert_eq!(
            *at_write.lock().unwrap(),
            vec![0],
            "local = {local}: nothing is held while the file is written"
        );
    }
}

/// M59 / M60 / M75: every stage of the network tier holds what its permit covers — the decode the
/// network estimate (the window of zstd included: the count of the plaintext runs under it), the
/// plaintext `compressed + S + context`. The measured peaks are in the allocation binary
/// (`block_prep_alloc_peak`); here the order. A SMALL block keeps the permit of its decode stage
/// for the plaintext stage: one grant, the permit cut to the plaintext, no regrant (spec v3.9b W4).
/// The file is 1.5 MiB: with the window in the plaintext stage instead of the decode stage (M75) it
/// would not fit the decode permit and the block would wait twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn small_network_block_shrinks_without_a_regrant() {
    let w = World::new();
    let content = vec![0u8; 3 << 19];
    let holders = Arc::new(FakeHolders::default());
    let path = w.backup_placed("p.bin", &content, &holders).await;
    let (_, rec) = w.block_of(&path);
    std::fs::remove_file(&path).unwrap();
    let budget = MemBudget::new(1 << 30);
    let coord = w.coord(&budget, Some(&holders), raptorq());

    let (result, log) = logged(coord.restore(request(&path))).await;
    let result = result.unwrap();

    assert_eq!(result.files_restored, 1, "{:?}", result.failures);
    assert_eq!(staged(&result, &path), content);
    let need = need_network(&rec);
    let plain = estimate_restore_plaintext(rec.encrypted_size.unwrap(), content.len() as u64);
    assert!(plain <= need, "fixture: {plain} must fit {need}");
    assert_eq!(
        granted_bytes(&log),
        vec![need],
        "one grant per block: {log}"
    );
    assert!(!log.contains("restore: regrant for plaintext"), "{log}");
}

/// A block whose plaintext does not fit its decode permit lets it go and takes a permit of
/// `estimate_restore_plaintext` (the permit cut to it would be a growth). 6 MiB of zeros: a block
/// of 64 KiB and a plaintext above the 5 MiB of its decode stage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_network_permit_is_retaken_when_the_plaintext_needs_more() {
    let w = World::new();
    let content = vec![0u8; 6 << 20];
    let holders = Arc::new(FakeHolders::default());
    let path = w.backup_placed("p.bin", &content, &holders).await;
    let (_, rec) = w.block_of(&path);
    std::fs::remove_file(&path).unwrap();
    let budget = MemBudget::new(1 << 30);
    let coord = w.coord(&budget, Some(&holders), raptorq());

    let (result, log) = logged(coord.restore(request(&path))).await;
    let result = result.unwrap();

    assert_eq!(result.files_restored, 1, "{:?}", result.failures);
    let grants = granted_bytes(&log);
    assert_eq!(grants.len(), 2, "{log}");
    assert_eq!(grants[0], need_network(&rec));
    assert_eq!(
        grants[1],
        estimate_restore_plaintext(rec.encrypted_size.unwrap(), content.len() as u64),
        "{grants:?}"
    );
    assert!(log.contains("restore: regrant for plaintext"), "{log}");
}

/// M61: the plaintext stage lets the decode permit go BEFORE it waits for its own: with a budget
/// that cannot hold both at once the restore still completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_regrant_releases_before_waiting() {
    let w = World::new();
    let content = vec![0u8; 6 << 20];
    let holders = Arc::new(FakeHolders::default());
    let path = w.backup_placed("r.bin", &content, &holders).await;
    let (_, rec) = w.block_of(&path);
    std::fs::remove_file(&path).unwrap();
    // The plaintext permit (7 MiB) is more than the decode one; the budget holds the larger only.
    let need2 = estimate_restore_plaintext(rec.encrypted_size.unwrap(), content.len() as u64);
    assert!(need_network(&rec) < need2 && need_network(&rec) + need2 > need2);
    let budget = MemBudget::new(need2);
    let coord = w.coord(&budget, Some(&holders), raptorq());

    let result = tokio::time::timeout(Duration::from_secs(30), coord.restore(request(&path)))
        .await
        .expect("a budget that holds one permit at a time completes the restore")
        .unwrap();

    assert_eq!(result.files_restored, 1, "{:?}", result.failures);
    assert_eq!(budget.grants(), 2);
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// Competitors that stand in the budget's queue again after every grant: a worker and a batch of
/// overdue PoS checks, each taking the whole budget for a moment. Counts their grants, and those
/// that came while a restore stood in the queue (they were ahead of it).
struct Competition {
    stop: Arc<std::sync::atomic::AtomicBool>,
    grants: Arc<AtomicUsize>,
    ahead_of_restore: Arc<AtomicUsize>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Competition {
    fn start(budget: &Arc<MemBudget>, need: u64) -> Competition {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let grants = Arc::new(AtomicUsize::new(0));
        let ahead_of_restore = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for pos in [false, true] {
            let (budget, stop) = (Arc::clone(budget), Arc::clone(&stop));
            let (grants, ahead) = (Arc::clone(&grants), Arc::clone(&ahead_of_restore));
            tasks.push(tokio::spawn(async move {
                let block = SourceBlockId([if pos { 0xA1 } else { 0xA2 }; 32]);
                while !stop.load(Ordering::SeqCst) {
                    let slow = Duration::from_secs(3600);
                    let permit = if pos {
                        budget
                            .acquire_priority(PriorityKind::OverduePos, &block, need, slow, || {})
                            .await
                    } else {
                        budget
                            .acquire(HolderKind::Worker, &block, need, slow, |_| {})
                            .await
                    };
                    grants.fetch_add(1, Ordering::SeqCst);
                    if budget.priority_waiters(PriorityKind::Restore) > 0 {
                        ahead.fetch_add(1, Ordering::SeqCst);
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    drop(permit);
                }
            }));
        }
        Competition {
            stop,
            grants,
            ahead_of_restore,
            tasks,
        }
    }

    /// (all grants, grants that came while a restore waited).
    async fn end(self) -> (usize, usize) {
        self.stop.store(true, Ordering::SeqCst);
        for task in self.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(10), task).await;
        }
        (
            self.grants.load(Ordering::SeqCst),
            self.ahead_of_restore.load(Ordering::SeqCst),
        )
    }
}

/// v3.12a (lesson of v3.12: completion within N). A block of the network tier needs two permits
/// (the decode, then the plaintext). A worker and a batch of overdue PoS checks stand in the queue
/// again after every grant, for good: the block is restored within three waits, each of them
/// behind the two competitors at most — the restore is not pushed back by whoever comes later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_block_completes_within_three_waits_under_constant_competition() {
    let w = World::new();
    let content = vec![0u8; 6 << 20];
    let holders = Arc::new(FakeHolders::default());
    let path = w.backup_placed("c.bin", &content, &holders).await;
    let (_, rec) = w.block_of(&path);
    std::fs::remove_file(&path).unwrap();
    // A budget that holds one permit at a time: the competitors take all of it.
    let need2 = estimate_restore_plaintext(rec.encrypted_size.unwrap(), content.len() as u64);
    let budget = MemBudget::new(need2);
    let coord = w.coord(&budget, Some(&holders), raptorq());
    let competition = Competition::start(&budget, need2);
    until("the competitors are in", || {
        budget.queued_waiters() >= 1 || budget.grants() >= 1
    })
    .await;

    let result = tokio::time::timeout(Duration::from_secs(60), coord.restore(request(&path)))
        .await
        .expect("the restore completes under constant competition");
    let (competitor_grants, ahead) = competition.end().await;

    let result = result.unwrap();
    assert_eq!(result.files_restored, 1, "{:?}", result.failures);
    // The grants are counted by the budget (a grant to a queued waiter is logged by whoever
    // releases, not by the waiter): the restore's are what the competitors' do not account for.
    let waits = budget.grants() as usize - competitor_grants;
    assert!(
        (1..=3).contains(&waits),
        "at most three waits per block (local, decode, plaintext): {waits}"
    );
    // Each wait stands behind the two competitors (one holds, one queues) and no more: whoever
    // stands in the queue again after a grant is behind the restore.
    assert!(
        ahead <= 2 * waits,
        "{ahead} grants went to the competitors ahead of the restore in {waits} waits"
    );
}

/// M62: the restore waits as a restore-priority waiter (the worker yields to it by the rule of
/// the spec v3.5 (Б′)), in the task of the job.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_yields_to_a_restore_waiting_in_the_network_tier() {
    let w = World::new();
    let content = b"waiting restore ".repeat(70);
    let holders = Arc::new(FakeHolders::default());
    let path = w.backup_placed("y.bin", &content, &holders).await;
    let (_, rec) = w.block_of(&path);
    std::fs::remove_file(&path).unwrap();
    let need = need_network(&rec);
    assert!(need > 2 * MIB && need <= 8 * MIB, "fixture: {need}");
    let budget = MemBudget::new(10 * MIB);
    let worker = budget
        .try_acquire(HolderKind::Worker, &SourceBlockId([7; 32]), 8 * MIB)
        .unwrap();
    let coord = Arc::new(w.coord(&budget, Some(&holders), raptorq()));
    let job = Arc::clone(&coord);
    let req = request(&path);
    let task = tokio::spawn(async move { job.restore(req).await });

    until("the restore waits in the priority queue", || {
        budget.priority_waiters(PriorityKind::Restore) == 1
    })
    .await;
    assert!(
        budget.worker_must_yield(PriorityKind::Restore, &worker),
        "{need} do not fit beside the worker's 8 of 10: it yields"
    );

    drop(worker);
    let result = task.await.unwrap().unwrap();
    assert_eq!(result.files_restored, 1, "{:?}", result.failures);
    assert_eq!(budget.priority_waiters(PriorityKind::Restore), 0);
}

/// M63: a restore that waits for memory shows the phase `waiting_for_memory` and writes ONE INFO
/// line for the job (block, tier, need, queued ahead); the phase ends with the grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_waiting_logs_once_per_job_and_sets_phase() {
    let w = World::new();
    let content = b"phase of a waiting job ".repeat(50);
    let holders = Arc::new(FakeHolders::default());
    let path = w.backup_placed("ph.bin", &content, &holders).await;
    let (_, rec) = w.block_of(&path);
    std::fs::remove_file(&path).unwrap();
    let need = need_network(&rec);
    let budget = MemBudget::new(need + 2 * MIB);
    // What is free (one MiB) is below the block's need: the restore waits.
    let hold = budget
        .try_acquire(HolderKind::Pos, &SourceBlockId([7; 32]), need + MIB)
        .unwrap();
    let coord = w.coord(&budget, Some(&holders), raptorq());
    let jobs = coord.config.jobs.clone();
    let req = request(&path);
    let job_id = req.job_id;
    // R-b3-3: the phase is gone BEFORE the file is written, not only when the job finishes.
    let at_write = Arc::new(Mutex::new(Vec::new()));
    {
        let (jobs, seen) = (jobs.clone(), Arc::clone(&at_write));
        *coord.write_hook.lock().unwrap() = Some(Box::new(move || {
            seen.lock()
                .unwrap()
                .push(jobs.get(job_id).is_some_and(|j| j.waiting_for_memory));
        }));
    }
    jobs.submit(job_id, &path, 1);
    let task = tokio::spawn(logged(async move { coord.restore(req).await }));

    until("the job shows the phase", || {
        jobs.get(job_id).is_some_and(|j| j.waiting_for_memory)
    })
    .await;
    drop(hold);
    let (result, log) = task.await.unwrap();
    assert_eq!(result.unwrap().files_restored, 1);
    assert_eq!(
        *at_write.lock().unwrap(),
        vec![false],
        "the phase is off while the file is written"
    );

    let line = log
        .lines()
        .filter(|l| l.contains("restore: waiting for memory budget"))
        .collect::<Vec<_>>();
    assert_eq!(line.len(), 1, "one INFO line per job: {log}");
    for part in [
        format!("job={job_id}").as_str(),
        "tier=network",
        format!("need_mib={}", need / MIB).as_str(),
        "queued_ahead=0",
        "block=",
    ] {
        assert!(line[0].contains(part), "{part}: {}", line[0]);
    }
    assert!(
        !jobs.get(job_id).unwrap().waiting_for_memory,
        "ended with the job"
    );
}

/// R-b3-2: the stop of the daemon reaches a job that waits for memory — the wait is a part of the
/// restore, and a restore without the cancel token of the daemon would hold the shutdown behind
/// a budget that may never free up. The job ends, restores nothing, and leaves the queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_waiting_for_memory_ends_at_the_daemon_stop() {
    let w = World::new();
    let content = b"stopped while waiting ".repeat(50);
    let holders = Arc::new(FakeHolders::default());
    let path = w.backup_placed("st.bin", &content, &holders).await;
    let (_, rec) = w.block_of(&path);
    std::fs::remove_file(&path).unwrap();
    let need = need_network(&rec);
    let budget = MemBudget::new(need + 2 * MIB);
    let _hold = budget
        .try_acquire(HolderKind::Pos, &SourceBlockId([7; 32]), need + MIB)
        .unwrap();
    let coord = Arc::new(w.coord(&budget, Some(&holders), raptorq()));
    let (jobs, cancel) = (coord.config.jobs.clone(), coord.config.cancel.clone());
    let req = request(&path);
    let job_id = req.job_id;
    jobs.submit(job_id, &path, 1);
    let job = Arc::clone(&coord);
    let task = tokio::spawn(async move { job.restore(req).await });

    until("the job waits for memory", || {
        jobs.get(job_id).is_some_and(|j| j.waiting_for_memory)
    })
    .await;
    assert!(!task.is_finished(), "the budget is busy: the job waits");
    cancel.cancel();

    let ended = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the wait for memory ends at the stop of the daemon")
        .unwrap();
    if let Ok(result) = ended {
        assert_eq!(result.files_restored, 0, "{:?}", result.failures);
    }
    assert_eq!(budget.priority_waiters(PriorityKind::Restore), 0);
    assert!(
        !jobs.get(job_id).unwrap().waiting_for_memory,
        "the phase is off"
    );
}

/// The registry's side of M63: the first wait of a job asks for the INFO line, a second does not,
/// and a job that finished no longer shows the phase.
#[test]
fn job_registry_announces_the_first_memory_wait_only() {
    let jobs = RestoreJobs::new("/nonexistent/viaticum-test/restore".into());
    let job = JobId::new();
    jobs.submit(job, "/p", 1);
    jobs.mark_running(job, "/p", 1);
    assert!(jobs.set_waiting_for_memory(job, true), "the first wait");
    assert!(jobs.get(job).unwrap().waiting_for_memory);
    assert!(!jobs.set_waiting_for_memory(job, false));
    assert!(!jobs.get(job).unwrap().waiting_for_memory);
    assert!(
        !jobs.set_waiting_for_memory(job, true),
        "not announced again"
    );
    assert!(jobs.get(job).unwrap().waiting_for_memory);
    jobs.finish(job, false);
    assert!(!jobs.get(job).unwrap().waiting_for_memory);
    // An unknown job is a no-op.
    assert!(!jobs.set_waiting_for_memory(JobId::new(), true));
}

/// A19: the blocks of a job go one at a time — at every fetch of the next block the budget holds
/// nothing of the previous one, and each block took its own permits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_blocks_of_a_job_are_sequential() {
    let w = World::new();
    let holders = Arc::new(FakeHolders::default());
    let mut paths = Vec::new();
    for i in 0..3u8 {
        let content = vec![i + 1; 3000];
        paths.push(
            w.backup_placed(&format!("seq{i}.bin"), &content, &holders)
                .await,
        );
    }
    let budget = MemBudget::new(1 << 30);
    let coord = w.coord(&budget, Some(&holders), raptorq());
    let seen = Arc::new(Mutex::new(Vec::new()));
    {
        let (b, seen) = (Arc::clone(&budget), Arc::clone(&seen));
        *holders.on_request.lock().unwrap() = Some(Box::new(move || {
            seen.lock().unwrap().push(b.outstanding_bytes())
        }));
    }
    for p in &paths {
        std::fs::remove_file(p).unwrap();
    }

    let result = coord
        .restore(request(&format!("{}/", w.files.path().display())))
        .await
        .unwrap();

    assert_eq!(result.files_restored, 3, "{:?}", result.failures);
    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 3);
    assert!(
        seen.iter().all(|&held| held == 0),
        "a fetch ran while a permit was held: {seen:?}"
    );
    assert_eq!(
        budget.grants(),
        3,
        "one grant per small block (the permit of the decode is cut), one block at a time"
    );
    assert_eq!(budget.outstanding_bytes(), 0);
}

// ─── The local tier ───────────────────────────────────────────────────────────

/// M16 (T4): the local tier decrypts the rebuilt blob; it does not encode it into symbols and
/// decode them again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_local_tier_decrypts_rebuilt_blob_without_encoding() {
    let w = World::new();
    let content = b"local tier content ".repeat(120);
    let path = w.backup("local.bin", &content);
    let budget = MemBudget::new(1 << 30);
    let encoder = CountingEncoder::watching(&budget);
    let coord = w.coord(&budget, None, encoder.clone());

    let result = coord.restore(request(&path)).await.unwrap();

    assert_eq!(result.files_restored, 1, "{:?}", result.failures);
    assert_eq!(staged(&result, &path), content);
    assert_eq!(encoder.encodes.load(Ordering::SeqCst), 0, "no re-encode");
    assert_eq!(encoder.decodes.load(Ordering::SeqCst), 0, "no decode");
    assert_eq!(budget.grants(), 1, "one permit for the local tier");
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// The local permit is `2·E + S` of the files' `metadata` (`SourceCheck::Ready`), taken after the
/// precheck, which holds none: missing or over-limit files go to the network at once, with the
/// network's permits and no local one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_local_tier_skips_budget_when_sources_missing_or_over_limit() {
    let w = World::new();
    let content = b"sized by metadata ".repeat(90);
    let holders = Arc::new(FakeHolders::default());
    let path = w.backup_placed("m.bin", &content, &holders).await;
    let (id, rec) = w.block_of(&path);
    let (params, size) = (rec.erasure_params(), rec.encrypted_size.unwrap());
    let file_len = std::fs::metadata(&path).unwrap().len();
    let decode = |coord: RestoreCoordinator| async move {
        let mut pauses = NoAnswerPauses::new(JobId::new(), 1);
        coord
            .decode_block_local(&id, &params, size, &mut pauses)
            .await
            .unwrap()
    };

    // Control: the source serves the block with ONE permit of 2·E + S.
    let budget = MemBudget::new(1 << 30);
    let (_, log) = logged(decode(w.coord(&budget, Some(&holders), raptorq()))).await;
    assert_eq!(
        granted_bytes(&log),
        vec![estimate_restore_local(params.k, params.t, file_len)],
        "{log}"
    );
    assert!(holders.requests.lock().unwrap().is_empty());

    // Over the limit: the network, with the network's permits.
    let budget = MemBudget::new(1 << 30);
    let mut coord = w.coord(&budget, Some(&holders), raptorq());
    coord.config.max_source_bytes = file_len - 1;
    let (_, log) = logged(decode(coord)).await;
    let grants = granted_bytes(&log);
    assert_eq!(
        grants[0],
        estimate_restore_network(params.k, params.t),
        "{log}"
    );
    assert!(!holders.requests.lock().unwrap().is_empty());

    // Missing: the same.
    holders.requests.lock().unwrap().clear();
    std::fs::remove_file(&path).unwrap();
    let budget = MemBudget::new(1 << 30);
    let (_, log) = logged(decode(w.coord(&budget, Some(&holders), raptorq()))).await;
    let grants = granted_bytes(&log);
    assert_eq!(
        grants[0],
        estimate_restore_network(params.k, params.t),
        "{log}"
    );
    assert!(!holders.requests.lock().unwrap().is_empty());
}

/// M17: a local tier whose rebuild fails lets its permit go before the network tier asks for its
/// own. The budget is smaller than both together (and than the local estimate: clamped to the
/// total); holding the first would stall the second for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_local_fail_then_network_completes_with_budget_clamped_to_total() {
    let w = World::new();
    let content = b"changed under the restore ".repeat(60);
    let holders = Arc::new(FakeHolders::default());
    let path = w.backup_placed("c.bin", &content, &holders).await;
    // The same length, other bytes: the precheck says Ready, the rebuild's block check fails.
    std::fs::write(&path, vec![b'x'; content.len()]).unwrap();
    let budget = MemBudget::new(4 * MIB);
    let coord = w.coord(&budget, Some(&holders), raptorq());

    let result = tokio::time::timeout(Duration::from_secs(30), coord.restore(request(&path)))
        .await
        .expect("the local permit is released before the network tier waits")
        .unwrap();

    assert_eq!(result.files_restored, 1, "{:?}", result.failures);
    assert_eq!(staged(&result, &path), content);
    assert_eq!(budget.outstanding_bytes(), 0);
    assert!(
        budget.warned_over(HolderKind::Restore),
        "the local estimate was clamped"
    );
}

/// M20: a source that changed since the backup is not served as the block (the rebuilt blob is
/// checked against the block id): the network gives the bytes of the backup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_local_tier_with_changed_source_goes_to_network_not_aead_error() {
    let w = World::new();
    let content = b"the content that was backed up ".repeat(50);
    let holders = Arc::new(FakeHolders::default());
    let path = w.backup_placed("h.bin", &content, &holders).await;
    std::fs::write(&path, vec![b'y'; content.len()]).unwrap();
    let budget = MemBudget::new(1 << 30);
    let coord = w.coord(&budget, Some(&holders), raptorq());

    let result = coord.restore(request(&path)).await.unwrap();

    assert_eq!(result.files_restored, 1, "{:?}", result.failures);
    assert_eq!(
        staged(&result, &path),
        content,
        "the backed up bytes, not the changed file"
    );
    assert!(
        !holders.requests.lock().unwrap().is_empty(),
        "the holders were asked"
    );
}

// ─── Pure ─────────────────────────────────────────────────────────────────────

/// The count the restore sizes its permit by is the length of the decompressed plaintext, for
/// compressible and incompressible data, and `decompress_exact` makes the same bytes.
#[test]
fn plaintext_len_equals_decompressed_len() {
    use crate::daemon::backup::pipeline::{
        compress_and_encrypt, decompress_exact, decrypt, decrypt_and_decompress, plaintext_len,
    };
    let key = TEST_EPOCH_KEY;
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut noise = |n: usize| -> Vec<u8> {
        (0..n)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    };
    let cases: Vec<Vec<u8>> = vec![
        b"x".to_vec(),
        vec![0u8; 1000],
        b"a repeated phrase ".repeat(50_000),
        noise(300_000),
        [noise(100_000), vec![7u8; 3 << 20]].concat(),
    ];
    for plain in cases {
        let stored = compress_and_encrypt(&plain, &key).unwrap();
        let compressed = decrypt(&stored, &key).unwrap();
        let len = plaintext_len(&compressed).unwrap();
        assert_eq!(len, plain.len() as u64);
        assert_eq!(
            len as usize,
            decrypt_and_decompress(&stored, &key).unwrap().len()
        );
        let exact = decompress_exact(&compressed, len).unwrap();
        assert_eq!(exact, plain);
        // A capacity that is too small is an error, not a truncated block.
        if len > 1 {
            assert!(decompress_exact(&compressed, len - 1).is_err());
        }
    }
}
