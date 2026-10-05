// СТ-0c round 4: the issue tick keeps its budget when the process around it stalls — the
// overrun of `pos_scale` run 20260929-224644 (step 2 p95 974 ms, 7b 834 ms against 800).
//
// Cause, from O's log: in every overrun tick the scheduler logged nothing for 0.5-2 s
// while its publishes' first Acks took ~1 s (slowest_publish_ms p95 1295, median 521 in
// overrun ticks vs 216). Each Ack is recorded as a contact — a durable redb commit — and
// that commit ran on an async worker: a publish fans out to ~9 postmen, 9 publishes are
// in flight, so dozens of workers sat in `begin_write` behind one slow commit and the
// runtime (timers included) stalled. The tick's deadline could not fire and its last
// block's preparation, admitted with headroom, finished a second late.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use viaticum_core::erasure::{ErasureEncoder, ErasureError, RaptorQEncoder, Symbol, SymbolSink};
use viaticum_core::types::{DeviceId, ErasureParams, SourceBlockId};

use super::issue_support::{SlowPostman, owner_with_due, owner_with_encoder, seed_due};
use super::pos_scale::{LogBuf, field};
use crate::daemon::scheduler::issue::{InFlight, issue_budget};

/// Another writer's durable commit holds redb's one write lock for 2 s while a tick runs
/// on a runtime of 2 workers. The postman acks in 5 ms, and every Ack's contact commit
/// waits for the lock. The tick still returns within its budget (tolerance 150 ms): the
/// contact commits wait on the blocking pool, not on the async workers. With the commits
/// on the workers, both workers park in `begin_write`, the tick's deadline never fires,
/// and the tick ends only when the lock is released (≈ 2 s).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue_tick_keeps_its_budget_while_a_commit_holds_the_database() {
    let owner = owner_with_due(
        5,
        8,
        900,
        SlowPostman::acking_after(Duration::from_millis(5)),
    );
    let budget = issue_budget(3600, 900);

    let db = owner.db.clone();
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let txn = db.write_txn().expect("write txn");
        held_tx.send(()).expect("test alive");
        std::thread::sleep(Duration::from_secs(2));
        drop(txn);
    });
    held_rx.recv().expect("the write lock is held");

    // The tick runs on a worker, as in the daemon.
    let tick = tokio::spawn(async move {
        let mut in_flight = InFlight::default();
        let t = Instant::now();
        owner
            .scheduler
            .issue_tick(&mut in_flight)
            .await
            .expect("issue_tick");
        let took = t.elapsed();
        in_flight.shutdown().await;
        took
    });
    let took = tick.await.expect("tick task");
    writer.join().expect("writer thread");

    assert!(
        took <= budget + Duration::from_millis(150),
        "the tick took {took:?} (budget {budget:?}) while a commit held the database"
    );
}

/// An encoder that sleeps in `encode_raw_ranges_each` in its calls `stall_from..stall_upto`
/// (a block whose preparation is held up by the disk or the CPU), counting the calls and
/// the most calls running at once.
pub(super) struct StallingEncoder {
    inner: RaptorQEncoder,
    pub(super) calls: AtomicUsize,
    running: AtomicUsize,
    pub(super) peak: AtomicUsize,
    stall_from: usize,
    stall_upto: usize,
    stall: Duration,
    /// Runs at the start of every `encode_raw_ranges_each` with the call's index (tests: advance
    /// a fake clock, read the budget, panic).
    hook: std::sync::Mutex<Option<CallHook>>,
}

/// What a test runs at the start of each preparation's encode.
pub(super) type CallHook = Arc<dyn Fn(usize) + Send + Sync>;

impl StallingEncoder {
    pub(super) fn new(stall_from: usize, stall_upto: usize, stall: Duration) -> Arc<Self> {
        Arc::new(StallingEncoder {
            inner: RaptorQEncoder::new(),
            calls: AtomicUsize::new(0),
            running: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            stall_from,
            stall_upto,
            stall,
            hook: std::sync::Mutex::new(None),
        })
    }

    /// Run `hook(call_index)` at the start of every encode from now on.
    pub(super) fn set_hook(&self, hook: impl Fn(usize) + Send + Sync + 'static) {
        *self.hook.lock().unwrap() = Some(Arc::new(hook));
    }
}

impl ErasureEncoder for StallingEncoder {
    fn encode(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        start_esi: u32,
        count: u32,
        block_id: &SourceBlockId,
        holder_id: &DeviceId,
    ) -> Result<Vec<Symbol>, ErasureError> {
        self.inner
            .encode(source_block, params, start_esi, count, block_id, holder_id)
    }
    fn decode(&self, symbols: &[Symbol], params: &ErasureParams) -> Result<Vec<u8>, ErasureError> {
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
        self.inner
            .encode_raw(source_block, params, start_esi, count)
    }
    fn encode_raw_ranges(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        ranges: &[(u32, u32)],
    ) -> Result<Vec<Symbol>, ErasureError> {
        self.inner.encode_raw_ranges(source_block, params, ranges)
    }
    /// The PoS preparation's entry point (F8'): counted, and stalled when its call is in the
    /// stall window.
    fn encode_raw_ranges_each(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        ranges: &[(u32, u32)],
        f: &mut SymbolSink<'_>,
    ) -> Result<(), ErasureError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let hook = self.hook.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook(call);
        }
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        if (self.stall_from..self.stall_upto).contains(&call) {
            std::thread::sleep(self.stall);
        }
        let out = self
            .inner
            .encode_raw_ranges_each(source_block, params, ranges, f);
        self.running.fetch_sub(1, Ordering::SeqCst);
        out
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

/// Block 1 prepares normally; block 2, admitted with headroom, takes 1.5 s to prepare.
/// The tick stops waiting for it at its deadline and returns within the budget
/// (tolerance 150 ms), the block reported cut (preparing in the background, pos-i7-d-a)
/// and the block it did not reach deferred. Waiting for the preparation to finish, the
/// tick takes ≈ 1.6 s.
#[tokio::test]
async fn a_block_still_preparing_at_the_deadline_is_cut() {
    let encoder = StallingEncoder::new(1, usize::MAX, Duration::from_millis(1500));
    let owner = owner_with_encoder(
        900,
        SlowPostman::acking_after(Duration::from_millis(5)),
        encoder,
        |db, dir| seed_due(db, dir, 3, 8),
    );
    let budget = issue_budget(3600, 900);

    let buf = LogBuf::default();
    let writer = buf.clone();
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish(),
    );
    let mut in_flight = InFlight::default();
    let t = Instant::now();
    tracing::instrument::WithSubscriber::with_subscriber(
        owner.scheduler.issue_tick(&mut in_flight),
        dispatch,
    )
    .await
    .expect("issue_tick");
    let took = t.elapsed();
    in_flight.shutdown().await;

    assert!(
        took <= budget + Duration::from_millis(150),
        "the tick took {took:?} (budget {budget:?}): it waited for a stalled preparation"
    );
    let logs = buf.text();
    let line = logs
        .lines()
        .find(|l| l.contains("scheduler: PoS issue tick"))
        .unwrap_or_else(|| panic!("no issue tick line; logs:\n{logs}"));
    assert_eq!(field(line, "cut_blocks"), Some(1), "{line}");
    assert_eq!(field(line, "issued"), Some(8), "block 1 only: {line}");
    assert_eq!(
        field(line, "preparing"),
        Some(1),
        "block 2 prepares on: {line}"
    );
    assert_eq!(
        field(line, "deferred"),
        Some(8),
        "block 3 was not reached and stays due: {line}"
    );
    assert!(field(line, "scan_ms").is_some(), "{line}");
    assert!(field(line, "slowest_block_ms").is_some(), "{line}");
}
