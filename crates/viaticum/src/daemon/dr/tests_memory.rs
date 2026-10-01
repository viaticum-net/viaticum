// DR's block work memory (К-b3, restore-i39; spec v3.8 §2, v3.9a): the decode of an SS block runs
// on the blocking pool under ONE permit, of DR's own budget or leased from the node on this
// machine, and the permit is back before the plaintext is parsed. The node is a real
// `web_api` router over a socket; the machine's lock lives in a temporary directory.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use viaticum_core::erasure::{
    ErasureEncoder, ErasureError, RaptorQEncoder, Symbol, SymbolSink, pad_for_encoding,
};
use viaticum_core::types::{DeviceId, ErasureParams, SourceBlockId};

use super::DrError;
use super::memory::Memory;
use super::net::decode_ss_block;
use crate::daemon::backup::pipeline::compress_and_encrypt;
use crate::daemon::mem_budget::machine_lock::{
    LockKind, LockOutcome, LockRecord, MachineLock, try_lock,
};
use crate::daemon::mem_budget::{DrLeases, HolderKind, MemBudget, estimate_restore_network};
use crate::daemon::system_state::block::SYSTEM_STATE_IMPORTANCE;

const MIB: u64 = 1 << 20;
const KEY: [u8; 32] = [7u8; 32];

// ─── Fixtures ─────────────────────────────────────────────────────────────────

/// An SS block as DR meets it: the symbols (every source ESI and three repair ones), the
/// parameters and the value (CBOR, compressed, encrypted) they decode to.
struct SsBlock {
    id: SourceBlockId,
    value: Vec<u8>,
    encrypted_size: u64,
    params: ErasureParams,
    symbols: Vec<Symbol>,
}

fn ss_block(seed: u8, len: usize) -> SsBlock {
    let value: Vec<u8> = (0..len)
        .map(|i| ((i / 7) as u8).wrapping_add(seed) % 23)
        .collect();
    let plaintext = viaticum_core::types::to_cbor_bytes(&value);
    let mut stored = compress_and_encrypt(&plaintext, &KEY).unwrap();
    let encrypted_size = stored.len() as u64;
    let params = ErasureParams::compute(encrypted_size, SYSTEM_STATE_IMPORTANCE).unwrap();
    pad_for_encoding(&mut stored, &params);
    let symbols = RaptorQEncoder::new()
        .encode_raw(&stored, &params, 0, params.k_eff)
        .unwrap();
    SsBlock {
        id: SourceBlockId([seed; 32]),
        value,
        encrypted_size,
        params,
        symbols,
    }
}

impl SsBlock {
    fn need(&self) -> u64 {
        estimate_restore_network(self.params.k, self.params.t)
    }
}

/// A coder that watches the node's budget (and may stall) at every decode.
struct Observing {
    inner: RaptorQEncoder,
    budget: Option<Arc<MemBudget>>,
    stall: Duration,
    held_at_decode: Mutex<Vec<u64>>,
}

impl Observing {
    fn new(budget: Option<&Arc<MemBudget>>, stall: Duration) -> Arc<Self> {
        Arc::new(Observing {
            inner: RaptorQEncoder::new(),
            budget: budget.cloned(),
            stall,
            held_at_decode: Mutex::new(Vec::new()),
        })
    }
}

impl ErasureEncoder for Observing {
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
        if let Some(budget) = &self.budget {
            self.held_at_decode
                .lock()
                .unwrap()
                .push(budget.outstanding_bytes());
        }
        // A decode that takes its time: on the async runtime it would stop every task.
        std::thread::sleep(self.stall);
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

    fn encode_raw_ranges_each(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        ranges: &[(u32, u32)],
        f: &mut SymbolSink<'_>,
    ) -> Result<(), ErasureError> {
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

fn acquired(outcome: LockOutcome) -> MachineLock {
    match outcome {
        LockOutcome::Acquired(l) => l,
        other => panic!("expected the lock, got {other:?}"),
    }
}

type Lines = Arc<Mutex<Vec<String>>>;
type SayFn = Arc<dyn Fn(String) + Send + Sync>;

/// Where DR's lines go in a test.
fn collector() -> (Lines, SayFn) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    (lines, Arc::new(move |l| sink.lock().unwrap().push(l)))
}

/// A directory with the files of a node's CLI protocol: `api-port` and `api-token`.
fn node_dir(port: u16) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    crate::daemon::web_auth::write_port_file(dir.path(), port).unwrap();
    std::fs::write(
        dir.path().join("api-token"),
        crate::daemon::web_api::tests::TOKEN,
    )
    .unwrap();
    dir
}

/// A real node: `web_api` routes over a socket, its budget, its DR leases. The lock the node
/// holds is in `lock_dir`.
struct Node {
    budget: Arc<MemBudget>,
    leases: Arc<DrLeases>,
    _dir: tempfile::TempDir,
    _lock: Option<MachineLock>,
    lock_dir: PathBuf,
}

impl Node {
    /// The node stops holding the machine's lock (it ended, or hangs and is killed).
    fn release_lock(&mut self) {
        self._lock = None;
    }
}

async fn start_node(root: &Path, total: u64) -> Node {
    let budget = MemBudget::new(total);
    let leases = DrLeases::with_keepalive(
        Arc::clone(&budget),
        Duration::from_secs(3600),
        Duration::from_millis(50),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = crate::daemon::web_api::tests::lease_app(Arc::clone(&leases));
    tokio::spawn(async move { axum::serve(listener, app).await });
    let dir = node_dir(port);
    let lock_dir = root.join("viaticum-test");
    let lock = acquired(try_lock(&lock_dir, &LockRecord::daemon(dir.path())));
    Node {
        budget,
        leases,
        _dir: dir,
        _lock: Some(lock),
        lock_dir,
    }
}

fn leasing_memory(node: &Node) -> Memory {
    Memory::open_in(node.lock_dir.clone(), || {
        panic!("DR must not build a budget of its own beside a live node")
    })
    .expect("a node holds the lock: DR leases from it")
}

// ─── Own budget ───────────────────────────────────────────────────────────────

/// M64: the decode of an SS block runs on the blocking pool, under the permit. The detector is a
/// heartbeat: a task on the same single-threaded runtime ticks every 10 ms and must not stall
/// while a decode that sleeps 500 ms runs (a decode on the runtime would stall it for the 500; the
/// bar is 250 ms, so that a loaded machine's hiccups do not trip it); and the budget holds the
/// block's estimate at the moment of the decode and nothing after.
#[tokio::test(flavor = "current_thread")]
async fn dr_ss_block_decodes_under_one_permit_on_the_blocking_pool() {
    let block = ss_block(1, 200_000);
    let budget = MemBudget::new(1 << 30);
    let mut memory = Memory::own_for_test(Arc::clone(&budget));
    let coder = Observing::new(Some(&budget), Duration::from_millis(500));
    let encoder: Arc<dyn ErasureEncoder> = coder.clone();

    let stop = Arc::new(AtomicBool::new(false));
    let gaps = Arc::new(Mutex::new(Vec::<Duration>::new()));
    let ticker = {
        let (stop, gaps) = (Arc::clone(&stop), Arc::clone(&gaps));
        tokio::spawn(async move {
            let mut last = Instant::now();
            while !stop.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
                let now = Instant::now();
                gaps.lock().unwrap().push(now - last);
                last = now;
            }
        })
    };
    tokio::time::sleep(Duration::from_millis(40)).await;

    let plaintext = decode_ss_block::<Vec<u8>>(
        &mut memory,
        &encoder,
        block.symbols.clone(),
        &block.id,
        block.encrypted_size,
        &block.params,
        &KEY,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    stop.store(true, Ordering::SeqCst);
    ticker.await.unwrap();

    assert_eq!(plaintext, block.value);
    let worst = gaps.lock().unwrap().iter().max().copied().unwrap();
    assert!(
        worst < Duration::from_millis(250),
        "the runtime stalled for {worst:?}: the decode ran in the async context"
    );
    assert_eq!(*coder.held_at_decode.lock().unwrap(), vec![block.need()]);
    assert_eq!(budget.outstanding_bytes(), 0, "the permit is back");
}

/// `dr: waiting for memory (N MiB)` after 5 s of waiting (the safeguard; a DR process has no
/// competitor of its own), once.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn dr_cli_prints_waiting_line_after_5s() {
    let block = ss_block(2, 100_000);
    let need = block.need();
    let budget = MemBudget::new(need + MIB);
    let hold = budget
        .try_acquire(HolderKind::Dr, &SourceBlockId([9; 32]), 2 * MIB)
        .unwrap();
    let (lines, say) = collector();
    let mut memory =
        Memory::own_for_test(Arc::clone(&budget)).with_test_seams(say, Duration::from_secs(30));
    let (id, size, params) = (block.id, block.encrypted_size, block.params);
    let task = tokio::spawn(async move { memory.acquire(&id, size, &params).await.ok() });

    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(lines.lock().unwrap().is_empty(), "not yet");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        *lines.lock().unwrap(),
        vec![format!("dr: waiting for memory ({} MiB)", need / MIB)]
    );
    drop(hold);
    let held = task
        .await
        .unwrap()
        .expect("the permit comes when the memory is free");
    assert_eq!(lines.lock().unwrap().len(), 1, "once");
    held.release().await;
}

/// A DR that finds the machine's lock free takes it, with a budget of its own; a second DR on the
/// machine is told to wait.
#[tokio::test]
async fn dr_takes_the_machine_lock_and_a_budget_of_its_own_when_it_is_free() {
    let root = tempfile::tempdir().unwrap();
    let lock_dir = root.path().join("viaticum-test");
    let first = Memory::open_in(lock_dir.clone(), || MemBudget::new(64 * MIB)).expect("free lock");
    match try_lock(&lock_dir, &LockRecord::daemon(Path::new("/data/node"))) {
        LockOutcome::HeldElsewhere(Some(r)) => assert_eq!(r.kind, LockKind::Dr),
        other => panic!("the DR must hold the lock, got {other:?}"),
    }
    match Memory::open_in(lock_dir.clone(), || MemBudget::new(64 * MIB)) {
        Err(DrError::Failed { reason, .. }) => {
            assert!(reason.contains("another viaticum dr"), "{reason}")
        }
        other => panic!("a second DR must wait, got {:?}", other.err()),
    }
    drop(first);
    assert!(matches!(
        try_lock(&lock_dir, &LockRecord::dr()),
        LockOutcome::Acquired(_)
    ));
}

// ─── Leasing from the node ────────────────────────────────────────────────────

/// M66: with a live node on the machine (another data directory, its own budget) DR does not take
/// a budget of its own: it leases the memory of the block from the node. At the moment of the
/// decode the NODE's budget holds the block's estimate; it holds nothing once the block is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dr_with_a_live_node_on_another_data_dir_leases_from_its_budget() {
    let root = tempfile::tempdir().unwrap();
    let node = start_node(root.path(), 1 << 30).await;
    let mut memory = leasing_memory(&node);
    let block = ss_block(3, 150_000);
    let coder = Observing::new(Some(&node.budget), Duration::ZERO);
    let encoder: Arc<dyn ErasureEncoder> = coder.clone();

    let plaintext = decode_ss_block::<Vec<u8>>(
        &mut memory,
        &encoder,
        block.symbols.clone(),
        &block.id,
        block.encrypted_size,
        &block.params,
        &KEY,
    )
    .await
    .unwrap();

    assert_eq!(plaintext, block.value);
    assert_eq!(
        *coder.held_at_decode.lock().unwrap(),
        vec![block.need()],
        "the decode ran inside the node's budget"
    );
    assert_eq!(node.budget.outstanding_bytes(), 0);
    assert!(node.leases.status().is_none());
}

/// M69: the node holds no lease for DR between two SS blocks — it is given back (the node
/// answers `released`) before the plaintext is parsed and before the next fetch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_holds_no_dr_lease_between_ss_blocks() {
    let root = tempfile::tempdir().unwrap();
    let node = start_node(root.path(), 1 << 30).await;
    let mut memory = leasing_memory(&node);
    let encoder: Arc<dyn ErasureEncoder> = Observing::new(None, Duration::ZERO);

    for seed in 4..7u8 {
        let block = ss_block(seed, 120_000);
        let plaintext = decode_ss_block::<Vec<u8>>(
            &mut memory,
            &encoder,
            block.symbols.clone(),
            &block.id,
            block.encrypted_size,
            &block.params,
            &KEY,
        )
        .await
        .unwrap();
        assert_eq!(plaintext, block.value);
        assert_eq!(
            node.budget.outstanding_bytes(),
            0,
            "block {seed}: the lease is back before the next block"
        );
        assert!(node.leases.status().is_none(), "block {seed}");
    }
}

/// A node that waits for memory (a big block of its own) makes the lease wait, as it makes a
/// restore wait: DR gets the memory when the node frees it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dr_lease_waits_for_the_node_budget_and_gets_it_when_it_is_free() {
    let root = tempfile::tempdir().unwrap();
    let block = ss_block(8, 150_000);
    let node = start_node(root.path(), block.need() + MIB).await;
    let hold = node
        .budget
        .try_acquire(HolderKind::Worker, &SourceBlockId([9; 32]), 2 * MIB)
        .unwrap();
    let mut memory = leasing_memory(&node);
    let encoder: Arc<dyn ErasureEncoder> = Observing::new(None, Duration::ZERO);
    let (symbols, id, size, params) = (
        block.symbols.clone(),
        block.id,
        block.encrypted_size,
        block.params,
    );
    let task = tokio::spawn(async move {
        decode_ss_block::<Vec<u8>>(&mut memory, &encoder, symbols, &id, size, &params, &KEY).await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!task.is_finished(), "the node's budget is busy");
    assert_eq!(
        node.budget
            .priority_waiters(crate::daemon::mem_budget::PriorityKind::Restore),
        1
    );

    drop(hold);
    let plaintext = tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .expect("the lease is granted when the memory is free")
        .unwrap()
        .unwrap();
    assert_eq!(plaintext, block.value);
}

/// The node holds the lock and does not answer: DR says so once and waits, trying again; when the
/// node stops (its lock is free) DR takes the lock and works on a budget of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dr_waits_for_a_silent_locked_node_and_takes_its_own_budget_after_it_stops() {
    let root = tempfile::tempdir().unwrap();
    let lock_dir = root.path().join("viaticum-test");
    // A node whose API answers nothing: a port nobody listens on.
    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let dir = node_dir(dead_port);
    let node_lock = acquired(try_lock(&lock_dir, &LockRecord::daemon(dir.path())));
    let (lines, say) = collector();
    let mut memory = Memory::open_in(lock_dir.clone(), || MemBudget::new(64 * MIB))
        .expect("locked by a node: leasing")
        .with_test_seams(say, Duration::from_millis(60));
    let block = ss_block(9, 80_000);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        drop(node_lock);
    });

    let held = tokio::time::timeout(
        Duration::from_secs(20),
        memory.acquire(&block.id, block.encrypted_size, &block.params),
    )
    .await
    .expect("DR goes on once the node is gone")
    .expect("a permit of the budget of its own");

    let said = lines.lock().unwrap().clone();
    assert_eq!(
        said,
        vec![
            "dr: the node on this machine does not answer; waiting for it to answer or stop \
             (Ctrl+C to cancel)"
                .to_string()
        ],
        "said once"
    );
    drop(held);
    // DR holds the machine's lock now.
    match try_lock(&lock_dir, &LockRecord::daemon(Path::new("/data/node"))) {
        LockOutcome::HeldElsewhere(Some(r)) => assert_eq!(r.kind, LockKind::Dr),
        other => panic!("DR must hold the lock now, got {other:?}"),
    }
}

/// A node that does not know the lease request (an older version answers an unknown route with
/// its web page): DR ends with the message, and the failure is the one that ends DR for any
/// pointer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dr_exits_with_a_message_on_an_old_node() {
    use axum::http::header;
    let root = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new().fallback(|| async {
        (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            "<html>the web UI</html>",
        )
    });
    tokio::spawn(async move { axum::serve(listener, app).await });
    let dir = node_dir(port);
    let lock_dir = root.path().join("viaticum-test");
    let _lock = acquired(try_lock(&lock_dir, &LockRecord::daemon(dir.path())));
    let mut memory =
        Memory::open_in(lock_dir, || MemBudget::new(64 * MIB)).expect("locked by a node");
    let block = ss_block(10, 80_000);

    let err = memory
        .acquire(&block.id, block.encrypted_size, &block.params)
        .await
        .err()
        .expect("an old node cannot lend memory");

    assert!(matches!(err, DrError::NodeCannotShareMemory));
    assert!(
        err.to_string().contains(
            "the node on this machine is older and cannot share memory; update or stop it"
        ),
        "{err}"
    );
    assert!(memory.is_fatal());
    assert!(matches!(
        memory.take_fatal(),
        Some(DrError::NodeCannotShareMemory)
    ));
}

/// A lock directory open to other users is not trusted: DR works on a budget of its own, as two
/// nodes on one machine do.
#[cfg(unix)]
#[tokio::test]
async fn dr_with_an_untrusted_lock_directory_works_on_its_own_budget() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let lock_dir = root.path().join("viaticum-test");
    std::fs::create_dir(&lock_dir).unwrap();
    std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let budget = MemBudget::new(64 * MIB);
    let mut memory =
        Memory::open_in(lock_dir, || Arc::clone(&budget)).expect("no lock: a budget of its own");
    let block = ss_block(11, 80_000);
    let held = memory
        .acquire(&block.id, block.encrypted_size, &block.params)
        .await
        .ok()
        .unwrap();
    assert_eq!(budget.outstanding_bytes(), block.need());
    held.release().await;
    assert_eq!(budget.outstanding_bytes(), 0);
}

// ─── A node that does not answer, and one that answers otherwise (v3.9b W1, p.5, p.7) ──────────

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

const SILENT_LINE: &str = "dr: the node on this machine does not answer; waiting for it to \
                           answer or stop (Ctrl+C to cancel)";

/// A node's web API answering every request with `status` and `content_type`; its port.
async fn serve_answering(status: u16, content_type: &'static str) -> u16 {
    use axum::http::{StatusCode, header};
    let app = axum::Router::new().fallback(move || async move {
        (
            StatusCode::from_u16(status).unwrap(),
            [(header::CONTENT_TYPE, content_type)],
            "no",
        )
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await });
    port
}

/// A DR beside a node whose data directory is `data_dir`: the node's lock, the DR's memory (a
/// silent node is tried again after 60 ms and is silent after 200 ms) and the lines it says.
fn dr_beside_node_at(root: &Path, data_dir: &Path) -> (MachineLock, Memory, Lines) {
    let lock_dir = root.join("viaticum-test");
    let lock = acquired(try_lock(&lock_dir, &LockRecord::daemon(data_dir)));
    let (lines, say) = collector();
    let memory = Memory::open_in(lock_dir, || MemBudget::new(64 * MIB))
        .expect("locked by a node: leasing")
        .with_test_seams(say, Duration::from_millis(60))
        .with_silence(Duration::from_millis(200));
    (lock, memory, lines)
}

/// W1: a node in SIGSTOP takes the connection in its kernel and sends not a byte. DR must not wait
/// on it for ever in the `send()`: it says it does not answer, once, and tries again; when the node
/// stops (its lock is free) DR takes the lock and a budget of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dr_does_not_hang_on_a_node_that_takes_the_connection_and_says_nothing() {
    let root = tempfile::tempdir().unwrap();
    // Listening, never accepting: the handshake is the kernel's, the request is never read.
    let stopped = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dir = node_dir(stopped.local_addr().unwrap().port());
    let (node_lock, mut memory, lines) = dr_beside_node_at(root.path(), dir.path());
    let block = ss_block(12, 80_000);
    let (id, size, params) = (block.id, block.encrypted_size, block.params);
    let task = tokio::spawn(async move { memory.acquire(&id, size, &params).await });

    until("DR says the node does not answer", || {
        !lines.lock().unwrap().is_empty()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(!task.is_finished(), "DR waits for the node, trying again");
    assert_eq!(
        *lines.lock().unwrap(),
        vec![SILENT_LINE.to_string()],
        "said once"
    );

    drop(node_lock);
    let held = tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .expect("DR goes on once the node is gone")
        .unwrap()
        .expect("a permit of the budget of its own");
    held.release().await;
    drop(stopped);
}

/// W1, the other `send()`: the release of a lease to a node that stopped answering after it gave
/// the memory. DR gives up on the answer and goes on (the dropped connection is the node's other
/// way to release).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dr_gives_up_on_a_node_that_does_not_answer_the_release() {
    use axum::http::header;
    use axum::routing::post;
    use futures::StreamExt;
    let app = axum::Router::new()
        .route(
            "/api/budget/lease",
            post(|| async {
                let granted = futures::stream::once(async {
                    Ok::<_, std::convert::Infallible>(axum::body::Bytes::from_static(
                        b"{\"lease\":\"granted\",\"id\":1}\n",
                    ))
                });
                (
                    [(header::CONTENT_TYPE, "application/x-ndjson")],
                    axum::body::Body::from_stream(granted.chain(futures::stream::pending())),
                )
            }),
        )
        .route(
            "/api/budget/release",
            post(|| async { std::future::pending::<&'static str>().await }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await });
    let root = tempfile::tempdir().unwrap();
    let dir = node_dir(port);
    let (_lock, mut memory, lines) = dr_beside_node_at(root.path(), dir.path());
    let block = ss_block(13, 80_000);

    let held = memory
        .acquire(&block.id, block.encrypted_size, &block.params)
        .await
        .expect("the node gives the lease");
    tokio::time::timeout(Duration::from_secs(10), held.release())
        .await
        .expect("the release does not wait for a node that does not answer");
    assert!(lines.lock().unwrap().is_empty(), "nothing to say about it");
}

/// Spec v3.9b p.5: an old node (404, 405, or its web page) ends DR with the message; a node that
/// refuses us (401, 403: another user) ends it with the other one; a status nobody expects ends it
/// with the status. All of them end DR whatever pointer is tried next.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dr_classifies_the_answers_of_the_node_to_the_lease() {
    let block = ss_block(14, 80_000);
    for (status, content_type) in [
        (404u16, "text/plain"),
        (405, "text/plain"),
        (200, "text/html; charset=utf-8"),
        (401, "text/plain"),
        (403, "text/plain"),
        (400, "text/plain"),
        (409, "text/plain"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let dir = node_dir(serve_answering(status, content_type).await);
        let (_lock, mut memory, lines) = dr_beside_node_at(root.path(), dir.path());

        let err = memory
            .acquire(&block.id, block.encrypted_size, &block.params)
            .await
            .err()
            .unwrap_or_else(|| panic!("{status} {content_type}: no lease"));

        let said = err.to_string();
        match status {
            404 | 405 | 200 => {
                assert!(
                    matches!(err, DrError::NodeCannotShareMemory),
                    "{status}: {said}"
                );
                assert!(said.contains("is older and cannot share memory"), "{said}");
            }
            401 | 403 => {
                assert!(
                    matches!(err, DrError::NodeRefusedLease { .. }),
                    "{status}: {said}"
                );
                assert!(
                    said.contains(&format!("the node refused the request (status {status})")),
                    "{said}"
                );
                assert!(
                    said.contains("run dr as the same user as the node"),
                    "{said}"
                );
            }
            _ => {
                assert!(
                    matches!(err, DrError::NodeUnexpectedStatus { .. }),
                    "{status}: {said}"
                );
                assert!(said.contains(&format!("status {status}")), "{said}");
            }
        }
        assert!(memory.is_fatal(), "{status}: ends DR for any pointer");
        assert!(
            lines.lock().unwrap().is_empty(),
            "{status}: no waiting line"
        );
    }
}

/// Spec v3.9b p.5: a 5xx, a dropped connection and a node that sends nothing are "does not answer":
/// DR says so once and waits, trying again; none of them ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dr_waits_on_5xx_and_on_a_dropped_connection() {
    let block = ss_block(15, 80_000);
    let dropper = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dropper_port = dropper.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in dropper.incoming() {
            drop(stream);
        }
    });
    for port in [
        serve_answering(500, "text/plain").await,
        serve_answering(503, "text/plain").await,
        dropper_port,
    ] {
        let root = tempfile::tempdir().unwrap();
        let dir = node_dir(port);
        let (_lock, mut memory, lines) = dr_beside_node_at(root.path(), dir.path());

        let ended = tokio::time::timeout(
            Duration::from_millis(600),
            memory.acquire(&block.id, block.encrypted_size, &block.params),
        )
        .await;

        assert!(ended.is_err(), "port {port}: DR keeps waiting for the node");
        assert!(!memory.is_fatal(), "port {port}");
        assert_eq!(*lines.lock().unwrap(), vec![SILENT_LINE.to_string()]);
    }
}

/// Spec v3.9b p.7: a node without the web API (no `api-port` in its data directory) is a setting,
/// not a state to wait out: DR ends with the hint.
#[tokio::test]
async fn dr_exits_with_a_hint_when_the_node_has_its_web_api_off() {
    let root = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (_lock, mut memory, _lines) = dr_beside_node_at(root.path(), dir.path());
    let block = ss_block(16, 80_000);

    let err = memory
        .acquire(&block.id, block.encrypted_size, &block.params)
        .await
        .err()
        .expect("no API, no lease");

    assert!(matches!(err, DrError::NodeWebApiOff), "{err}");
    assert!(
        err.to_string().contains(
            "the node on this machine has its web API off; enable it (or stop the node) and run \
             dr again"
        ),
        "{err}"
    );
    assert!(memory.is_fatal());
}

// ─── The owner of the lock changes between two blocks (v3.9b W2) ───────────────────────────────

/// The node that held the lock stops and another one starts (another data directory, another
/// port): the next block is leased from the new one. A DR that went on with the old client would
/// lease from a node that is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dr_leases_from_the_new_node_when_the_owner_of_the_lock_changes() {
    let root = tempfile::tempdir().unwrap();
    let mut first = start_node(root.path(), 1 << 30).await;
    let mut memory = leasing_memory(&first);
    let one = ss_block(17, 100_000);
    let two = ss_block(18, 100_000);

    let coder = Observing::new(Some(&first.budget), Duration::ZERO);
    let encoder: Arc<dyn ErasureEncoder> = coder.clone();
    let parsed = decode_ss_block::<Vec<u8>>(
        &mut memory,
        &encoder,
        one.symbols.clone(),
        &one.id,
        one.encrypted_size,
        &one.params,
        &KEY,
    )
    .await
    .unwrap();
    assert_eq!(parsed, one.value);
    assert_eq!(*coder.held_at_decode.lock().unwrap(), vec![one.need()]);

    first.release_lock();
    let second = start_node(root.path(), 1 << 30).await;
    let coder = Observing::new(Some(&second.budget), Duration::ZERO);
    let encoder: Arc<dyn ErasureEncoder> = coder.clone();
    let parsed = decode_ss_block::<Vec<u8>>(
        &mut memory,
        &encoder,
        two.symbols.clone(),
        &two.id,
        two.encrypted_size,
        &two.params,
        &KEY,
    )
    .await
    .unwrap();

    assert_eq!(parsed, two.value);
    assert_eq!(
        *coder.held_at_decode.lock().unwrap(),
        vec![two.need()],
        "the decode ran inside the budget of the node that holds the lock now"
    );
    assert_eq!(first.budget.grants(), 1, "the old node is not asked again");
    assert_eq!(second.budget.grants(), 1);
}

/// The owner of the lock became a DR: this one ends (two DRs at once is a user's mistake).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dr_ends_when_the_lock_passes_to_another_dr() {
    let root = tempfile::tempdir().unwrap();
    let mut node = start_node(root.path(), 1 << 30).await;
    let mut memory = leasing_memory(&node);
    node.release_lock();
    let _other_dr = acquired(try_lock(&node.lock_dir, &LockRecord::dr()));
    let block = ss_block(19, 80_000);

    let err = memory
        .acquire(&block.id, block.encrypted_size, &block.params)
        .await
        .err()
        .expect("another DR holds the machine");

    match &err {
        DrError::Failed { reason, .. } => {
            assert!(reason.contains("another viaticum dr"), "{reason}")
        }
        other => panic!("{other}"),
    }
    assert!(memory.is_fatal());
}

/// The lock is free when the next block comes (the node ended): DR takes it and a budget of its
/// own, with no word to the node that is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dr_takes_the_free_lock_and_its_own_budget_between_two_blocks() {
    let root = tempfile::tempdir().unwrap();
    let mut node = start_node(root.path(), 1 << 30).await;
    let mut memory = leasing_memory(&node);
    node.release_lock();
    let block = ss_block(20, 80_000);

    let held = memory
        .acquire(&block.id, block.encrypted_size, &block.params)
        .await
        .expect("a permit of the budget of its own");

    assert_eq!(node.budget.grants(), 0, "the node is not asked");
    drop(held);
    match try_lock(&node.lock_dir, &LockRecord::daemon(Path::new("/data/node"))) {
        LockOutcome::HeldElsewhere(Some(r)) => assert_eq!(r.kind, LockKind::Dr),
        other => panic!("DR must hold the lock now, got {other:?}"),
    }
}
