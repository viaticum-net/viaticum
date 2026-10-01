// The worker and the block work memory budget (backup-i24, backup-i24-a, J8, J10, J12-ex, J13).
//
// Real swarms: the owner runs `run_block_iteration` against holders that answer SymbolOffer with
// Accept and SymbolTransfer with Stored (a holder task per swarm) and can be told to run a hook
// at chosen moments — that is how a test puts a waiter into the budget at a precise point of the
// worker's turn.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::tempdir;
use tokio::task::JoinHandle;
use viaticum_core::db::Db;
use viaticum_core::erasure::{ErasureEncoder, ErasureError, RaptorQEncoder, Symbol, SymbolSink};
use viaticum_core::messages::{
    AckMsg, Message, RejectReason, SymbolAcceptMsg, SymbolRejectMsg, SymbolStoredMsg,
};
use viaticum_core::placement::HolderCandidate;
use viaticum_core::types::{
    DeviceId, ErasureParams, PlacementStatus, SourceBlockId, SourceBlockRecord, SourceBlockStatus,
    Timestamp,
};

use super::worker::{self, Turn, WorkOutcome};
use super::{PoolSnapshot, WorkPipelineConfig};
use crate::daemon::mem_budget::{
    HolderKind, MemBudget, MemPermit, PriorityKind, estimate_worker, estimate_worker_delivery,
};
use crate::daemon::network::swarm::{ProtocolEvent, SwarmHandle};
use crate::daemon::network::swarm_test_helpers::{
    get_listen_addr, make_swarm_config, wait_for_authenticated,
};

const MIB: u64 = 1 << 20;

fn db() -> Db {
    let dir = tempdir().unwrap();
    Db::open(&dir.keep().join("test.redb")).unwrap()
}

fn slow() -> Duration {
    Duration::from_secs(3600)
}

/// Wait (with a deadline) until `cond` holds.
async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !cond() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ─── Log capture (this thread only; the tests run on a current-thread runtime) ───

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuf {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn capture_logs() -> (LogBuf, tracing::subscriber::DefaultGuard) {
    let buf = LogBuf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    (buf, tracing::subscriber::set_default(subscriber))
}

// ─── Blocks ───────────────────────────────────────────────────────────────────

/// A block of `k` symbols of `t` bytes whose retained blob is 500 bytes SHORT of `k·t` (the
/// worker pads it), stored where the worker loads SystemState blocks from.
fn retained(data_dir: &std::path::Path, seed: u8, k: u32, t: u16) -> SourceBlockRecord {
    let len = k as usize * t as usize - 500;
    let blob: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect();
    let bid = SourceBlockId(*blake3::hash(&blob).as_bytes());
    crate::daemon::system_state::block::store_retained_block(data_dir, &bid, &blob).unwrap();
    let mut rec = super::tests::make_block_record(bid, 1.0, 0.99999);
    rec.k = k;
    rec.t = t;
    rec.encrypted_size = Some(len as u64);
    rec
}

fn params_of(rec: &SourceBlockRecord) -> ErasureParams {
    ErasureParams {
        k: rec.k,
        k_eff: rec.k + viaticum_core::constants::DECODE_OVERHEAD,
        t: rec.t,
        overhead: 1.5,
        n: rec.n.unwrap_or(0),
    }
}

fn pool_of(devices: &[DeviceId]) -> PoolSnapshot {
    PoolSnapshot {
        candidates: devices
            .iter()
            .map(|&device_id| HolderCandidate {
                device_id,
                trust: 0.9,
            })
            .collect(),
        signature: 7,
    }
}

// ─── An encoder that reports what it is asked to encode ──────────────────────

type EncodeHook = Arc<dyn Fn(usize) + Send + Sync>;

struct SpyEncoder {
    inner: RaptorQEncoder,
    /// Called with the length of the input each time a block is encoded.
    on_encode: EncodeHook,
}

impl SpyEncoder {
    fn spying(on_encode: impl Fn(usize) + Send + Sync + 'static) -> Arc<dyn ErasureEncoder> {
        Arc::new(SpyEncoder {
            inner: RaptorQEncoder::new(),
            on_encode: Arc::new(on_encode),
        })
    }
}

impl ErasureEncoder for SpyEncoder {
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
        (self.on_encode)(source_block.len());
        self.inner
            .encode_raw(source_block, params, start_esi, count)
    }
    fn encode_raw_ranges(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        ranges: &[(u32, u32)],
    ) -> Result<Vec<Symbol>, ErasureError> {
        (self.on_encode)(source_block.len());
        self.inner.encode_raw_ranges(source_block, params, ranges)
    }
    fn encode_raw_ranges_each(
        &self,
        source_block: &[u8],
        params: &ErasureParams,
        ranges: &[(u32, u32)],
        f: &mut SymbolSink<'_>,
    ) -> Result<(), ErasureError> {
        (self.on_encode)(source_block.len());
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

fn plain_encoder() -> Arc<dyn ErasureEncoder> {
    Arc::new(RaptorQEncoder::new())
}

// ─── Holders that answer ──────────────────────────────────────────────────────

type Hook = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

fn hook<F, Fut>(f: F) -> Hook
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    Arc::new(move || -> Pin<Box<dyn Future<Output = ()> + Send>> { Box::pin(f()) })
}

#[derive(Default)]
struct HolderLog {
    offers: usize,
    /// Symbols of each SymbolTransfer received, in order.
    transfers: Vec<usize>,
    /// What the budget held when the first transfer arrived.
    outstanding_at_first_transfer: Option<u64>,
    grants_at_first_transfer: Option<u64>,
}

struct Holder {
    device_id: DeviceId,
    log: Arc<Mutex<HolderLog>>,
}

impl Holder {
    fn transfers(&self) -> usize {
        self.log.lock().unwrap().transfers.len()
    }
    fn offers(&self) -> usize {
        self.log.lock().unwrap().offers
    }
}

#[derive(Default, Clone)]
struct Hooks {
    /// Run before replying to a SymbolOffer.
    on_offer: Option<Hook>,
    /// Run before replying to the first SymbolTransfer this holder gets.
    on_first_transfer: Option<Hook>,
    /// While set, the holder answers every SymbolOffer with `SymbolReject` (a dead or full
    /// holder: the offer ends without an accept).
    reject_offers: Option<Arc<AtomicBool>>,
    /// Answer a SymbolTransfer with a bare `Ack` instead of `SymbolStored`.
    ack_transfers: bool,
}

struct Net {
    owner: Arc<SwarmHandle>,
    events: Option<tokio::sync::mpsc::Receiver<ProtocolEvent>>,
}

impl Net {
    async fn new(owner_seed: u8) -> Net {
        let (handle, events) = SwarmHandle::start(make_swarm_config(owner_seed))
            .await
            .unwrap();
        Net {
            owner: Arc::new(handle),
            events: Some(events),
        }
    }

    /// A holder swarm, dialed to the owner and authenticated on both sides. `budget` is what its
    /// log reads at its first transfer.
    async fn holder(&mut self, seed: u8, budget: &Arc<MemBudget>, hooks: Hooks) -> Holder {
        let (handle, mut events) = SwarmHandle::start(make_swarm_config(seed)).await.unwrap();
        let handle = Arc::new(handle);
        let owner_addr = get_listen_addr(&self.owner).await;
        handle.dial(self.owner.peer_id, owner_addr).await.unwrap();
        let owner_events = self.events.as_mut().expect("owner events still held");
        wait_for_authenticated(owner_events, handle.device_id).await;
        wait_for_authenticated(&mut events, self.owner.device_id).await;

        let log = Arc::new(Mutex::new(HolderLog::default()));
        let (task_log, task_handle, budget) =
            (Arc::clone(&log), Arc::clone(&handle), Arc::clone(budget));
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let ProtocolEvent::InboundRequest {
                    message,
                    response_channel,
                    ..
                } = event
                else {
                    continue;
                };
                let reply = match message {
                    Message::SymbolOffer(offer) => {
                        task_log.lock().unwrap().offers += 1;
                        if let Some(h) = &hooks.on_offer {
                            h().await;
                        }
                        if hooks
                            .reject_offers
                            .as_ref()
                            .is_some_and(|r| r.load(Ordering::SeqCst))
                        {
                            Message::SymbolReject(SymbolRejectMsg {
                                v: 1,
                                source_block_id: offer.source_block_id,
                                offer_msg_id: offer.msg_id,
                                reason: RejectReason::QuotaFull,
                                timestamp: Timestamp::now(),
                            })
                        } else {
                            Message::SymbolAccept(SymbolAcceptMsg {
                                v: 1,
                                source_block_id: offer.source_block_id,
                                offer_msg_id: offer.msg_id,
                                timestamp: Timestamp::now(),
                            })
                        }
                    }
                    Message::SymbolTransfer(transfer) => {
                        let first = {
                            let mut l = task_log.lock().unwrap();
                            l.transfers.push(transfer.symbols.len());
                            if l.transfers.len() == 1 {
                                l.outstanding_at_first_transfer = Some(budget.outstanding_bytes());
                                l.grants_at_first_transfer = Some(budget.grants());
                                true
                            } else {
                                false
                            }
                        };
                        if first && let Some(h) = &hooks.on_first_transfer {
                            h().await;
                        }
                        if hooks.ack_transfers {
                            Message::Ack(AckMsg { v: 1 })
                        } else {
                            Message::SymbolStored(SymbolStoredMsg {
                                v: 1,
                                source_block_id: transfer.source_block_id,
                                esi_ranges: transfer.symbols.iter().map(|s| (s.esi, 1)).collect(),
                                timestamp: Timestamp::now(),
                            })
                        }
                    }
                    _ => continue,
                };
                task_handle.respond_logged(response_channel, reply);
            }
        });
        Holder {
            device_id: handle.device_id,
            log,
        }
    }

    /// Keep the owner's event channel open (a dropped receiver must not be what fails a send).
    fn ready(&mut self) -> Arc<SwarmHandle> {
        if let Some(mut events) = self.events.take() {
            tokio::spawn(async move { while events.recv().await.is_some() {} });
        }
        Arc::clone(&self.owner)
    }
}

fn signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
}

struct Rig {
    db: Db,
    data_dir: tempfile::TempDir,
    budget: Arc<MemBudget>,
    config: WorkPipelineConfig,
    /// What the pipeline keeps between the turns of one block (`last_attempt`, RAM only).
    last_attempt: tokio::sync::Mutex<HashMap<DeviceId, u32>>,
}

impl Rig {
    fn new(budget_mib: u64, chunk_budget_bytes: usize) -> Rig {
        let data_dir = tempdir().unwrap();
        let budget = MemBudget::new(budget_mib * MIB);
        let mut config = super::tests::make_config();
        config.data_dir = data_dir.path().to_path_buf();
        config.mem_budget = Arc::clone(&budget);
        config.chunk_budget_bytes = chunk_budget_bytes;
        Rig {
            db: db(),
            data_dir,
            budget,
            config,
            last_attempt: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    async fn turn(
        &self,
        encoder: &Arc<dyn ErasureEncoder>,
        swarm: &Arc<SwarmHandle>,
        rec: &SourceBlockRecord,
        pool: &PoolSnapshot,
        yields_before: u32,
    ) -> anyhow::Result<WorkOutcome> {
        let key = signing_key();
        let mut last_attempt = self.last_attempt.lock().await;
        tokio::time::timeout(
            Duration::from_secs(120),
            worker::run_block_iteration(
                &self.db,
                &self.config,
                encoder,
                swarm,
                Some(&key),
                None,
                None,
                rec,
                pool,
                yields_before,
                &mut last_attempt,
            ),
        )
        .await
        .expect("the worker turn hangs")
    }
}

/// A waiter of `kind` for `need_mib`, started in the background; its permit comes back from the
/// handle.
fn spawn_waiter(
    budget: &Arc<MemBudget>,
    kind: PriorityKind,
    need_mib: u64,
) -> JoinHandle<MemPermit> {
    let budget = Arc::clone(budget);
    tokio::spawn(async move {
        budget
            .acquire_priority(
                kind,
                &SourceBlockId([0xEE; 32]),
                need_mib * MIB,
                slow(),
                || {},
            )
            .await
    })
}

/// A hook that puts ONE waiter of `kind` (`need_mib`) into the budget, once, and returns when the
/// budget counts it. The waiter handle lands in `slot`.
fn register_waiter_once(
    budget: &Arc<MemBudget>,
    kind: PriorityKind,
    need_mib: u64,
    armed: &Arc<AtomicBool>,
    slot: &Arc<Mutex<Option<JoinHandle<MemPermit>>>>,
) -> Hook {
    let (budget, armed, slot) = (Arc::clone(budget), Arc::clone(armed), Arc::clone(slot));
    hook(move || {
        let (budget, armed, slot) = (Arc::clone(&budget), Arc::clone(&armed), Arc::clone(&slot));
        async move {
            if armed.swap(false, Ordering::SeqCst) {
                // Precondition of every yield test (spec v3.5a): the worker holds ITS permit
                // only, and the waiter cannot fit beside it — `need > total − W`. Otherwise the
                // worker would not yield, for another reason than the one under test, and a
                // mutation of the yield rule could not turn the unit red.
                let worker_mib = budget.outstanding_bytes() / MIB;
                let total_mib = budget.total_bytes() / MIB;
                assert!(
                    need_mib > total_mib - worker_mib,
                    "stand: the waiter ({need_mib} MiB) must not fit beside the worker \
                     ({worker_mib} of {total_mib} MiB)"
                );
                *slot.lock().unwrap() = Some(spawn_waiter(&budget, kind, need_mib));
                until("the waiter is counted", || {
                    budget.priority_waiters(kind) == 1
                })
                .await;
            }
        }
    })
}

fn placement_statuses(db: &Db, bid: &SourceBlockId) -> Vec<PlacementStatus> {
    db.list_placements_for_block(bid)
        .unwrap()
        .into_iter()
        .map(|p| p.status)
        .collect()
}

// ─── Padding, order, sizes ───────────────────────────────────────────────────

/// The worker pads the loaded blob to `k·t` IN PLACE before it encodes (B2 of the spec): the
/// encoder then borrows the input instead of copying it (F5). A blob short of `k·t` reaching
/// the encoder as is would mean a second, padded copy inside `make_block_encoder`.
#[tokio::test]
async fn worker_encode_input_is_padded_in_place() {
    let rig = Rig::new(512, 80 << 20);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_in = Arc::clone(&seen);
    let encoder = SpyEncoder::spying(move |len| seen_in.lock().unwrap().push(len));
    let rec = retained(rig.data_dir.path(), 0x11, 3, 1024);
    assert!(
        rec.encrypted_size.unwrap() < 3 * 1024,
        "the blob is short of k·t"
    );
    rig.db.upsert_source_block(&rec).unwrap();

    let peers = [DeviceId([0x91; 32]), DeviceId([0x92; 32])];
    let mut net = Net::new(0x40).await;
    let swarm = net.ready();
    let outcome = rig
        .turn(&encoder, &swarm, &rec, &pool_of(&peers), 0)
        .await
        .unwrap();

    assert!(outcome.encoded);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![3 * 1024],
        "one encode, of the blob padded to k·t"
    );
}

/// J8 + J12-ex (a): ONE permit for the whole iteration. It is taken before the encode (sized by
/// `estimate_worker`), shrunk after it to `estimate_worker_delivery`, held unchanged while the
/// symbols go out, and gone when the iteration ends. The worker takes no second permit.
#[tokio::test]
async fn worker_takes_budget_before_rebuild_shrinks_after_encode_releases_after_delivery() {
    let rig = Rig::new(1024, 80 << 20);
    let at_encode = Arc::new(Mutex::new(None));
    let (budget, slot) = (Arc::clone(&rig.budget), Arc::clone(&at_encode));
    let encoder = SpyEncoder::spying(move |_| {
        *slot.lock().unwrap() = Some((budget.outstanding_bytes(), budget.grants()));
    });
    // ~1 MiB of block, 64 KiB symbols: 2.1·E = 2.1 MiB is what the shrink gives back.
    let rec = retained(rig.data_dir.path(), 0x12, 16, 65535);
    rig.db.upsert_source_block(&rec).unwrap();

    let mut net = Net::new(0x41).await;
    let holders = [
        net.holder(0x50, &rig.budget, Hooks::default()).await,
        net.holder(0x51, &rig.budget, Hooks::default()).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    let outcome = rig
        .turn(&encoder, &swarm, &rec, &pool_of(&devices), 0)
        .await
        .unwrap();
    assert!(outcome.acked > 0 && outcome.failed == 0, "{outcome:?}");

    // What the plan asked of the encoder.
    let placements = rig.db.list_placements_for_block(&rec.block_id).unwrap();
    let out_symbols: u64 = placements.iter().map(|p| p.symbol_count() as u64).sum();
    let e_pad = rec.k as u64 * rec.t as u64;
    let est = estimate_worker(rec.k, rec.t, out_symbols);
    let kept = estimate_worker_delivery(e_pad, out_symbols, rec.t);
    assert!(kept < est, "the shrink has something to give back");

    let (held_at_encode, grants_at_encode) = at_encode.lock().unwrap().expect("encoded");
    assert_eq!(
        held_at_encode, est,
        "the permit of the estimate is held during the encode"
    );
    assert_eq!(grants_at_encode, 1);

    let first = holders
        .iter()
        .find_map(|h| h.log.lock().unwrap().outstanding_at_first_transfer)
        .expect("a transfer arrived");
    assert_eq!(first, kept, "shrunk after the encode, before the delivery");
    for h in &holders {
        if let Some(g) = h.log.lock().unwrap().grants_at_first_transfer {
            assert_eq!(
                g, 1,
                "J12-ex: the worker acquires nothing while it delivers"
            );
        }
    }
    assert_eq!(rig.budget.grants(), 1, "one permit for the whole iteration");
    assert_eq!(
        rig.budget.outstanding_bytes(),
        0,
        "released after the delivery"
    );
    assert_eq!(rig.budget.available_bytes(), rig.budget.total_bytes());
}

/// J12-ex (a), on its own: nothing is taken while the symbols go out.
#[tokio::test]
async fn worker_delivery_holds_one_permit_and_acquires_nothing() {
    let rig = Rig::new(512, 1024);
    let rec = retained(rig.data_dir.path(), 0x13, 3, 1024);
    rig.db.upsert_source_block(&rec).unwrap();
    let mut net = Net::new(0x42).await;
    let holders = [
        net.holder(0x52, &rig.budget, Hooks::default()).await,
        net.holder(0x53, &rig.budget, Hooks::default()).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    let outcome = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool_of(&devices), 0)
        .await
        .unwrap();

    assert!(outcome.acked > 0, "{outcome:?}");
    let transfers: usize = holders.iter().map(Holder::transfers).sum();
    assert!(transfers >= 2, "several chunks went out: {transfers}");
    for h in &holders {
        let l = h.log.lock().unwrap();
        if let Some(g) = l.grants_at_first_transfer {
            assert_eq!(g, 1, "the worker's one permit, nothing else was granted");
        }
    }
    assert_eq!(rig.budget.grants(), 1);
    assert_eq!(rig.budget.outstanding_bytes(), 0);
}

/// The permit is taken BEFORE the source is read: with the budget full, a worker whose source is
/// unreadable waits (and does not fail) until the budget frees. The early exits (nobody to offer
/// to) never touch the budget.
#[tokio::test]
async fn worker_waits_for_the_budget_before_reading_the_source() {
    let rig = Rig::new(200, 80 << 20);
    let mut net = Net::new(0x43).await;
    let swarm = net.ready();
    // No retained blob and no source files: the load fails — once the worker gets that far.
    let missing = {
        let mut r = super::tests::make_block_record(SourceBlockId([0x77; 32]), 1.0, 0.99999);
        r.k = 3;
        r.t = 1024;
        r.encrypted_size = Some(3000);
        r
    };
    let peers = [DeviceId([0x93; 32]), DeviceId([0x94; 32])];
    let pool = pool_of(&peers);

    let everything = rig
        .budget
        .try_acquire(HolderKind::Pos, &SourceBlockId([1; 32]), 200 * MIB)
        .unwrap();
    let encoder = plain_encoder();
    let worker = {
        let (db, config, swarm, rec, pool) = (
            rig.db.clone(),
            rig.config.clone(),
            Arc::clone(&swarm),
            missing.clone(),
            pool_of(&peers),
        );
        tokio::spawn(async move {
            worker::run_block_iteration(
                &db,
                &config,
                &encoder,
                &swarm,
                None,
                None,
                None,
                &rec,
                &pool,
                0,
                &mut HashMap::new(),
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !worker.is_finished(),
        "the worker waits for the budget; it has not tried to load the source"
    );
    drop(everything);
    let result = tokio::time::timeout(Duration::from_secs(30), worker)
        .await
        .expect("the worker goes on when the budget frees")
        .unwrap();
    assert!(result.is_err(), "now the load fails: {result:?}");
    assert_eq!(
        rig.budget.outstanding_bytes(),
        0,
        "the failed load released the permit"
    );

    // The early exit: every candidate already holds (or is awaiting a verdict on) the block.
    let held = retained(rig.data_dir.path(), 0x14, 3, 1024);
    rig.db.upsert_source_block(&held).unwrap();
    for p in &peers {
        let mut row = super::tests::placement(held.block_id, *p, PlacementStatus::Alive, 0);
        row.esi_ranges = vec![(0, 1)];
        rig.db.upsert_placement(&row).unwrap();
    }
    let everything = rig
        .budget
        .try_acquire(HolderKind::Pos, &SourceBlockId([1; 32]), 200 * MIB)
        .unwrap();
    let grants_before = rig.budget.grants();
    let outcome = rig
        .turn(&plain_encoder(), &swarm, &held, &pool, 0)
        .await
        .expect("no candidates: returns without waiting for the budget");
    assert!(!outcome.encoded);
    assert_eq!(
        rig.budget.grants(),
        grants_before,
        "no permit for an early exit"
    );
    drop(everything);
}

/// A block that left service between the plan and the offers: the iteration ends at once and the
/// permit goes with it.
#[tokio::test]
async fn worker_left_service_releases_permit() {
    let rig = Rig::new(512, 80 << 20);
    let rec = retained(rig.data_dir.path(), 0x15, 3, 1024);
    let mut in_db = rec.clone();
    in_db.status = SourceBlockStatus::Deleting;
    rig.db.upsert_source_block(&in_db).unwrap();
    let mut net = Net::new(0x44).await;
    let swarm = net.ready();
    let peers = [DeviceId([0x95; 32]), DeviceId([0x96; 32])];

    let outcome = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool_of(&peers), 0)
        .await
        .unwrap();

    assert!(outcome.left_service && outcome.encoded);
    assert_eq!(
        rig.budget.grants(),
        1,
        "the permit was taken (the plan was fine)"
    );
    assert_eq!(rig.budget.outstanding_bytes(), 0, "and is gone");
    assert_eq!(rig.budget.available_bytes(), rig.budget.total_bytes());
}

// ─── Yielding ─────────────────────────────────────────────────────────────────

/// Budget and waiter sizes of the yield tests: the worker holds ~161 MiB of 512, a waiter that
/// needs 400 MiB cannot run beside it.
const YIELD_BUDGET_MIB: u64 = 512;
const YIELD_WAITER_MIB: u64 = 400;
// Rule (Б′) of the spec v3.5: the worker yields only to a waiter that does not fit beside its
// permit, `need > total − W`. W after the shrink is at least the delivery slack (160 MiB), so
// `need + 160 > total` guarantees it for every turn below; `register_waiter_once` checks it
// against the real permit when the waiter is put in.
const _: () = assert!(YIELD_WAITER_MIB + 160 > YIELD_BUDGET_MIB);
/// A block of 16 symbols of 64 KiB (1 MiB): each holder gets many of them, one per chunk.
const BIG_K: u32 = 16;
const BIG_T: u16 = 65535;
const BIG_CHUNK: usize = 65535;

/// backup-i24-a / M18: an overdue PoS waiting for the budget stops the worker between two chunks
/// of a holder (after the first one went out). The undelivered placements stay `Offered`, the
/// yield is not a failure, and the line names the count.
#[tokio::test]
async fn worker_yields_before_next_chunk_when_overdue_pos_waits() {
    let (logs, _guard) = capture_logs();
    let rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    let rec = retained(rig.data_dir.path(), 0x16, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let armed = Arc::new(AtomicBool::new(true));
    let slot = Arc::new(Mutex::new(None));
    let h = register_waiter_once(
        &rig.budget,
        PriorityKind::OverduePos,
        YIELD_WAITER_MIB,
        &armed,
        &slot,
    );
    let hooks = Hooks {
        on_first_transfer: Some(h),
        ..Hooks::default()
    };
    let mut net = Net::new(0x45).await;
    let holders = [
        net.holder(0x54, &rig.budget, hooks.clone()).await,
        net.holder(0x55, &rig.budget, hooks).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();

    let outcome = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool_of(&devices), 0)
        .await
        .unwrap();

    assert!(outcome.yielded, "{outcome:?}");
    let transfers: Vec<usize> = holders.iter().map(Holder::transfers).collect();
    assert_eq!(
        transfers.iter().sum::<usize>(),
        1,
        "one chunk went out, then the worker gave the budget away: {transfers:?}"
    );
    assert_eq!(
        (outcome.acked, outcome.failed),
        (0, 0),
        "yielding is not a failure, and nothing was fully delivered"
    );
    assert!(outcome.offered >= 1);
    let statuses = placement_statuses(&rig.db, &rec.block_id);
    assert!(
        !statuses.is_empty() && statuses.iter().all(|s| *s == PlacementStatus::Offered),
        "yield leaves the placements Offered: {statuses:?}"
    );

    // The waiter got the budget.
    let granted = slot.lock().unwrap().take().unwrap();
    let permit = tokio::time::timeout(Duration::from_secs(10), granted)
        .await
        .expect("the waiter is served after the yield")
        .unwrap();
    assert_eq!(permit.bytes(), YIELD_WAITER_MIB * MIB);
    drop(permit);

    let text = logs.text();
    let line = text
        .lines()
        .find(|l| l.contains("work_pipeline: yielding memory to overdue PoS"))
        .unwrap_or_else(|| panic!("no yield line:\n{text}"));
    assert!(line.contains("INFO"), "{line}");
    assert!(line.contains("yields_for_block=1"), "{line}");
    assert!(
        line.contains("holders_done=0") && line.contains("of=2"),
        "{line}"
    );
    assert!(line.contains(&format!("block={}", rec.block_id)), "{line}");
}

/// backup-i24-a / M28: with an overdue PoS ALREADY waiting when the delivery starts, a turn still
/// delivers one chunk before it yields — and so does every following turn. The worker is slower,
/// not stopped.
#[tokio::test]
async fn worker_delivers_at_least_one_chunk_per_turn_under_constant_overdue_pos() {
    let rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    let rec = retained(rig.data_dir.path(), 0x17, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let armed = Arc::new(AtomicBool::new(true));
    let slot = Arc::new(Mutex::new(None));
    // On the OFFER: the waiter is there before the first chunk is considered.
    let h = register_waiter_once(
        &rig.budget,
        PriorityKind::OverduePos,
        YIELD_WAITER_MIB,
        &armed,
        &slot,
    );
    let hooks = Hooks {
        on_offer: Some(h),
        ..Hooks::default()
    };
    let mut net = Net::new(0x46).await;
    let holders = [
        net.holder(0x56, &rig.budget, hooks.clone()).await,
        net.holder(0x57, &rig.budget, hooks).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    let pool = pool_of(&devices);
    let encoder = plain_encoder();
    let total = |holders: &[Holder]| holders.iter().map(Holder::transfers).sum::<usize>();

    for turn in 1..=3u32 {
        let yields = turn - 1;
        armed.store(true, Ordering::SeqCst);
        let before = total(&holders);
        let outcome = rig
            .turn(&encoder, &swarm, &rec, &pool, yields)
            .await
            .unwrap();
        assert!(outcome.yielded, "turn {turn}: {outcome:?}");
        assert_eq!(
            total(&holders) - before,
            1,
            "turn {turn}: exactly one chunk, never zero (M28), never the whole holder"
        );
        // The waiter is served; it finishes before the next turn.
        let granted = slot.lock().unwrap().take().unwrap();
        let permit = tokio::time::timeout(Duration::from_secs(10), granted)
            .await
            .unwrap()
            .unwrap();
        drop(permit);
    }
    assert_eq!(total(&holders), 3, "three turns, three chunks");
}

/// J13: a restore waiting for the budget stops the worker between holders — but only after the
/// current holder got everything.
#[tokio::test]
async fn worker_yields_before_next_holder_when_restore_waits_but_finishes_current_holder() {
    let (logs, _guard) = capture_logs();
    let rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    let rec = retained(rig.data_dir.path(), 0x18, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let armed = Arc::new(AtomicBool::new(true));
    let slot = Arc::new(Mutex::new(None));
    let h = register_waiter_once(
        &rig.budget,
        PriorityKind::Restore,
        YIELD_WAITER_MIB,
        &armed,
        &slot,
    );
    let hooks = Hooks {
        on_first_transfer: Some(h),
        ..Hooks::default()
    };
    let mut net = Net::new(0x47).await;
    let holders = [
        net.holder(0x58, &rig.budget, hooks.clone()).await,
        net.holder(0x59, &rig.budget, hooks).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();

    let outcome = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool_of(&devices), 0)
        .await
        .unwrap();

    assert!(outcome.yielded, "{outcome:?}");
    assert_eq!(
        (outcome.acked, outcome.failed),
        (1, 0),
        "the holder in hand was finished, the next one left alone"
    );
    let served: Vec<&Holder> = holders.iter().filter(|h| h.offers() > 0).collect();
    assert_eq!(served.len(), 1, "the second holder got no offer");
    assert!(
        served[0].transfers() >= 2,
        "it got every chunk, not just the first"
    );
    let statuses = placement_statuses(&rig.db, &rec.block_id);
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == PlacementStatus::Alive)
            .count(),
        1,
        "{statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == PlacementStatus::Offered)
            .count(),
        statuses.len() - 1,
        "the rest stay Offered, not failed: {statuses:?}"
    );

    let granted = slot.lock().unwrap().take().unwrap();
    let permit = tokio::time::timeout(Duration::from_secs(10), granted)
        .await
        .expect("the restore is served after the yield")
        .unwrap();
    assert_eq!(permit.kind(), HolderKind::Restore);
    let text = logs.text();
    let line = text
        .lines()
        .find(|l| l.contains("work_pipeline: yielding memory to restore"))
        .unwrap_or_else(|| panic!("no yield line:\n{text}"));
    assert!(
        line.contains("holders_done=1") && line.contains("yields_for_block=1"),
        "{line}"
    );
}

/// NOTE 4: a waiter the worker's own shrink satisfied does not make it yield. The waiter needs a
/// little more than is free while the worker holds its encode-stage permit, and less than is free
/// after the shrink; all chunks go out.
#[tokio::test]
async fn worker_does_not_yield_to_a_waiter_granted_by_its_shrink() {
    const TOTAL_MIB: u64 = 400;
    let rig = Rig::new(TOTAL_MIB, 65535);
    let rec = retained(rig.data_dir.path(), 0x19, 16, 65535);
    rig.db.upsert_source_block(&rec).unwrap();
    // The encoder holds the worker at the encode until the waiter is queued.
    let budget = Arc::clone(&rig.budget);
    let encoder = SpyEncoder::spying(move |_| {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while budget.priority_waiters(PriorityKind::OverduePos) != 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "the waiter never came"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let mut net = Net::new(0x48).await;
    let holders = [
        net.holder(0x5a, &rig.budget, Hooks::default()).await,
        net.holder(0x5b, &rig.budget, Hooks::default()).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();

    let worker = {
        let (db, config, swarm, rec, pool) = (
            rig.db.clone(),
            rig.config.clone(),
            Arc::clone(&swarm),
            rec.clone(),
            pool_of(&devices),
        );
        tokio::spawn(async move {
            worker::run_block_iteration(
                &db,
                &config,
                &encoder,
                &swarm,
                None,
                None,
                None,
                &rec,
                &pool,
                0,
                &mut HashMap::new(),
            )
            .await
        })
    };
    until("the worker holds its permit", || {
        rig.budget.outstanding_bytes() > 0
    })
    .await;
    let free_during_encode = rig.budget.available_bytes();
    // 2 MiB more than is free now; the shrink gives back 2.1·E ≈ 2.1 MiB or more.
    let waiter = spawn_waiter(
        &rig.budget,
        PriorityKind::OverduePos,
        free_during_encode / MIB + 2,
    );

    let outcome = tokio::time::timeout(Duration::from_secs(120), worker)
        .await
        .expect("the worker finishes")
        .unwrap()
        .unwrap();
    assert!(
        !outcome.yielded,
        "the waiter was served by the shrink: {outcome:?}"
    );
    assert!(outcome.acked > 0 && outcome.failed == 0, "{outcome:?}");
    let transfers: usize = holders.iter().map(Holder::transfers).sum();
    assert!(transfers >= 2, "several chunks: {transfers}");
    let permit = tokio::time::timeout(Duration::from_secs(10), waiter)
        .await
        .unwrap()
        .unwrap();
    assert!(permit.bytes() > free_during_encode);
}

/// The yield rules, without a network: never before the first attempt (overdue PoS) or the first
/// holder (restore) of a turn; afterwards only while the waiter does not fit beside the permit.
#[tokio::test]
async fn worker_turn_yields_only_after_its_first_attempt_or_holder() {
    fn turn<'a>(
        budget: &'a MemBudget,
        permit: &'a MemPermit,
        holders_started: usize,
        attempts: u32,
    ) -> Turn<'a> {
        Turn {
            budget,
            permit,
            chunk_budget_bytes: 1024,
            holders_started,
            attempts,
        }
    }
    let budget = MemBudget::new(100 * MIB);
    let mut held = budget
        .try_acquire(HolderKind::Worker, &SourceBlockId([1; 32]), 80 * MIB)
        .unwrap();
    let _overdue = spawn_waiter(&budget, PriorityKind::OverduePos, 50);
    let _restore = spawn_waiter(&budget, PriorityKind::Restore, 60);
    until("both wait", || {
        budget.priority_waiters(PriorityKind::OverduePos) == 1
            && budget.priority_waiters(PriorityKind::Restore) == 1
    })
    .await;
    assert_eq!(budget.queued_waiters(), 2, "precondition: both are queued");

    assert!(
        !turn(&budget, &held, 0, 0).overdue_pos_wants_the_budget(),
        "not before the first attempt"
    );
    assert!(
        turn(&budget, &held, 0, 0)
            .yield_before_next_holder()
            .is_none(),
        "nor before the first holder"
    );
    assert!(
        turn(&budget, &held, 1, 0)
            .yield_before_next_holder()
            .is_some(),
        "a holder is done: restore is next"
    );
    assert!(turn(&budget, &held, 1, 1).overdue_pos_wants_the_budget());
    assert!(
        turn(&budget, &held, 0, 1)
            .yield_before_next_holder()
            .is_some()
    );

    // The shrink leaves 90 beside the worker: both needs fit, nobody is to be yielded to (even
    // though the waiters have not had a chance to run yet).
    held.shrink_to(10 * MIB);
    assert!(
        budget.priority_waiters(PriorityKind::OverduePos) == 1,
        "not polled yet"
    );
    assert!(!turn(&budget, &held, 5, 5).overdue_pos_wants_the_budget());
    assert!(
        turn(&budget, &held, 5, 5)
            .yield_before_next_holder()
            .is_none()
    );
}

// ─── J10 ──────────────────────────────────────────────────────────────────────

/// J10: however the pool looks, a plan never asks for more than `10·k_eff` symbols.
#[test]
fn worker_iteration_symbols_never_exceed_ten_k_eff() {
    for (k, t, importance) in [
        (1u32, 1024u16, 0.0),
        (3, 1024, 1.0),
        (16, 65535, 0.5),
        (200, 65535, 1.0),
    ] {
        let len = (k as u64 * t as u64).saturating_sub(10);
        let db = db();
        let mut rec =
            super::tests::make_block_record(SourceBlockId([k as u8; 32]), importance, 0.99999);
        rec.k = k;
        rec.t = t;
        rec.encrypted_size = Some(len);
        let k_eff = params_of(&rec).k_eff as u64;
        for size in [1usize, 2, 3, 5, 10, 30, 60] {
            let pool: Vec<HolderCandidate> = (0..size)
                .map(|i| HolderCandidate {
                    device_id: DeviceId([i as u8 + 1; 32]),
                    trust: 0.5 + (i % 5) as f64 / 10.0,
                })
                .collect();
            let plan = super::offer_plan::plan_offers(&db, &rec, &pool, 0).unwrap();
            if let super::offer_plan::OfferPlan::Planned { offers, .. } = plan {
                let total: u64 = super::offer_plan::union_ranges(&offers)
                    .iter()
                    .map(|&(_, c)| c as u64)
                    .sum();
                assert!(
                    total <= 10 * k_eff,
                    "k={k} pool={size}: {total} symbols > 10·k_eff = {}",
                    10 * k_eff
                );
            }
        }
    }
}

// ─── The count of yields ─────────────────────────────────────────────────────

/// `yields_for_block` of the yield line: counted per block, reset by a delivery in full, left
/// alone by a turn that neither yielded nor finished; the holders' turn memory (`last_attempt`)
/// goes with it, and with a block that left service or was parked (v3.5a NOTE 3).
#[test]
fn yield_counter_counts_per_block_and_resets_on_full_delivery() {
    let outcome = |acked, failed, offered, yielded, left_service| WorkOutcome {
        acked,
        failed,
        encoded: true,
        offered,
        left_service,
        yielded,
    };
    let (a, b) = (SourceBlockId([1; 32]), SourceBlockId([2; 32]));
    let holder = DeviceId([9; 32]);
    let mut yields = HashMap::new();
    let mut last = HashMap::new();
    for id in [a, b] {
        last.insert(id, HashMap::from([(holder, 0u32)]));
    }

    super::count_yields(&mut yields, &mut last, a, &outcome(0, 0, 2, true, false));
    super::count_yields(&mut yields, &mut last, a, &outcome(1, 0, 2, true, false));
    super::count_yields(&mut yields, &mut last, b, &outcome(0, 0, 2, true, false));
    assert_eq!((yields[&a], yields[&b]), (2, 1), "per block");

    // Some holders failed: not a full delivery, the count and the memory stay.
    super::count_yields(&mut yields, &mut last, a, &outcome(1, 1, 2, false, false));
    assert_eq!(yields[&a], 2);
    assert!(last.contains_key(&a));
    // Every offer acked: reset, for this block only — the memory of its holders too.
    super::count_yields(&mut yields, &mut last, a, &outcome(2, 0, 2, false, false));
    assert!(!yields.contains_key(&a) && !last.contains_key(&a));
    assert_eq!(yields[&b], 1);
    assert!(last.contains_key(&b));
    // The block left service without a full delivery: both go.
    super::count_yields(&mut yields, &mut last, b, &outcome(0, 0, 0, false, true));
    assert!(!yields.contains_key(&b) && !last.contains_key(&b));
    // Parked (nobody to offer to): both go too.
    yields.insert(a, 3);
    last.insert(a, HashMap::from([(holder, 2u32)]));
    super::count_yields(&mut yields, &mut last, a, &outcome(0, 0, 0, false, false));
    assert!(!yields.contains_key(&a) && !last.contains_key(&a));
    // A turn that entered an empty map leaves none behind.
    last.insert(b, HashMap::new());
    super::count_yields(&mut yields, &mut last, b, &outcome(1, 1, 2, false, false));
    assert!(!last.contains_key(&b));
}

// ─── Attempts, not stored chunks (spec v3.5 BLOCK-1, M30, M34) ────────────────

/// Holders that reject every offer while `flag` is set, and put ONE waiter of `kind` into the
/// budget on an offer (once per `armed`).
fn dead_holder_hooks(flag: &Arc<AtomicBool>, waiter: Hook) -> Hooks {
    Hooks {
        on_offer: Some(waiter),
        reject_offers: Some(Arc::clone(flag)),
        ..Hooks::default()
    }
}

fn offers_total(holders: &[Holder]) -> usize {
    holders.iter().map(Holder::offers).sum()
}

fn transfers_total(holders: &[Holder]) -> usize {
    holders.iter().map(Holder::transfers).sum()
}

/// Serve the waiter a yield made room for, and let it go.
async fn drain_waiter(slot: &Arc<Mutex<Option<JoinHandle<MemPermit>>>>) {
    let granted = slot.lock().unwrap().take().expect("a waiter was put in");
    let permit = tokio::time::timeout(Duration::from_secs(10), granted)
        .await
        .expect("the waiter is served after the yield")
        .unwrap();
    drop(permit);
}

/// M30: an offer that ended without an accept is an attempt. The first holder rejects; before the
/// second one an overdue PoS that does not fit beside the worker gets the budget. Counting only
/// stored chunks would see zero attempts and offer the second holder too.
#[tokio::test]
async fn worker_yields_to_overdue_pos_after_a_failed_first_offer() {
    let (logs, _guard) = capture_logs();
    let rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    let rec = retained(rig.data_dir.path(), 0x1a, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let (armed, slot) = (Arc::new(AtomicBool::new(true)), Arc::new(Mutex::new(None)));
    let reject = Arc::new(AtomicBool::new(true));
    let waiter = register_waiter_once(
        &rig.budget,
        PriorityKind::OverduePos,
        YIELD_WAITER_MIB,
        &armed,
        &slot,
    );
    let mut net = Net::new(0x49).await;
    let holders = [
        net.holder(
            0x5c,
            &rig.budget,
            dead_holder_hooks(&reject, waiter.clone()),
        )
        .await,
        net.holder(0x5d, &rig.budget, dead_holder_hooks(&reject, waiter))
            .await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();

    let outcome = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool_of(&devices), 0)
        .await
        .unwrap();

    assert!(outcome.yielded, "{outcome:?}");
    assert_eq!(
        outcome.failed, 1,
        "the rejected offer is a failure, not a yield"
    );
    assert_eq!(
        offers_total(&holders),
        1,
        "the second holder was not offered: the budget went to the PoS"
    );
    assert_eq!(transfers_total(&holders), 0);
    let text = logs.text();
    let line = text
        .lines()
        .find(|l| l.contains("work_pipeline: yielding memory to overdue PoS"))
        .unwrap_or_else(|| panic!("no yield line:\n{text}"));
    assert!(line.contains("holders_done=1"), "{line}");
    drain_waiter(&slot).await;
}

/// M30: a chunk answered with a bare `Ack` (no `SymbolStored`) is an attempt, and leaves a
/// `chunk sent ... reply=ack` line; the worker yields before the next chunk. Counting stored
/// chunks only would send every chunk.
#[tokio::test]
async fn worker_yields_to_overdue_pos_after_an_ack_without_symbol_stored() {
    let (logs, _guard) = capture_logs();
    let rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    let rec = retained(rig.data_dir.path(), 0x1b, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let (armed, slot) = (Arc::new(AtomicBool::new(true)), Arc::new(Mutex::new(None)));
    let waiter = register_waiter_once(
        &rig.budget,
        PriorityKind::OverduePos,
        YIELD_WAITER_MIB,
        &armed,
        &slot,
    );
    let hooks = Hooks {
        on_first_transfer: Some(waiter),
        ack_transfers: true,
        ..Hooks::default()
    };
    let mut net = Net::new(0x4a).await;
    let holders = [
        net.holder(0x5e, &rig.budget, hooks.clone()).await,
        net.holder(0x5f, &rig.budget, hooks).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();

    let outcome = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool_of(&devices), 0)
        .await
        .unwrap();

    assert!(outcome.yielded, "{outcome:?}");
    assert_eq!(
        transfers_total(&holders),
        1,
        "one chunk sent (and answered with an Ack), then the budget went away"
    );
    let text = logs.text();
    let sent: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("work_pipeline: chunk sent"))
        .collect();
    assert_eq!(sent.len(), 1, "{text}");
    assert!(
        sent[0].contains("DEBUG") && sent[0].contains("reply=ack"),
        "{}",
        sent[0]
    );
    assert!(
        sent[0].contains("chunk=1/") && sent[0].contains(&format!("block_id={}", rec.block_id)),
        "{}",
        sent[0]
    );
    assert!(sent[0].contains("holder="), "{}", sent[0]);
    drain_waiter(&slot).await;
}

/// Every chunk sent leaves its DEBUG line with the holder's reply (`stored` here) — the observable
/// of backup-i24-a.
#[tokio::test]
async fn worker_logs_every_chunk_sent_with_its_reply() {
    let (logs, _guard) = capture_logs();
    let rig = Rig::new(512, 1024);
    let rec = retained(rig.data_dir.path(), 0x1c, 3, 1024);
    rig.db.upsert_source_block(&rec).unwrap();
    let mut net = Net::new(0x4b).await;
    let holders = [
        net.holder(0x60, &rig.budget, Hooks::default()).await,
        net.holder(0x61, &rig.budget, Hooks::default()).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    let outcome = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool_of(&devices), 0)
        .await
        .unwrap();
    assert!(outcome.acked > 0, "{outcome:?}");
    let text = logs.text();
    let sent = text
        .lines()
        .filter(|l| l.contains("work_pipeline: chunk sent") && l.contains("reply=stored"))
        .count();
    assert_eq!(
        sent,
        transfers_total(&holders),
        "one line per chunk: {text}"
    );
    assert!(sent >= 2);
}

/// M34: a restore is served after the first holder's attempt has come to an outcome, whatever the
/// outcome: the first holder rejects, the restore waits (it does not fit beside the worker), the
/// worker yields before the second. Counting only delivered holders would offer the second too.
#[tokio::test]
async fn worker_yields_to_restore_after_a_failed_first_holder() {
    let (logs, _guard) = capture_logs();
    let rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    let rec = retained(rig.data_dir.path(), 0x1d, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let (armed, slot) = (Arc::new(AtomicBool::new(true)), Arc::new(Mutex::new(None)));
    let reject = Arc::new(AtomicBool::new(true));
    let waiter = register_waiter_once(
        &rig.budget,
        PriorityKind::Restore,
        YIELD_WAITER_MIB,
        &armed,
        &slot,
    );
    let mut net = Net::new(0x4c).await;
    let holders = [
        net.holder(
            0x62,
            &rig.budget,
            dead_holder_hooks(&reject, waiter.clone()),
        )
        .await,
        net.holder(0x63, &rig.budget, dead_holder_hooks(&reject, waiter))
            .await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();

    let outcome = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool_of(&devices), 0)
        .await
        .unwrap();

    assert!(outcome.yielded, "{outcome:?}");
    assert_eq!(
        offers_total(&holders),
        1,
        "the second holder was not offered"
    );
    let text = logs.text();
    let line = text
        .lines()
        .find(|l| l.contains("work_pipeline: yielding memory to restore"))
        .unwrap_or_else(|| panic!("no yield line:\n{text}"));
    assert!(line.contains("holders_done=1"), "{line}");
    drain_waiter(&slot).await;
}

// ─── Rotation: least recently tried first (spec v3.5 WARN-4, M35) ─────────────

/// One turn under a constant overdue PoS: the waiter is put in at the first offer of the turn.
async fn constant_pos_turn(
    rig: &Rig,
    swarm: &Arc<SwarmHandle>,
    rec: &SourceBlockRecord,
    pool: &PoolSnapshot,
    yields_before: u32,
    armed: &Arc<AtomicBool>,
    slot: &Arc<Mutex<Option<JoinHandle<MemPermit>>>>,
) -> WorkOutcome {
    armed.store(true, Ordering::SeqCst);
    let outcome = rig
        .turn(&plain_encoder(), swarm, rec, pool, yields_before)
        .await
        .unwrap();
    assert!(outcome.yielded, "turn {yields_before}: {outcome:?}");
    drain_waiter(slot).await;
    outcome
}

/// M35: a dead first holder does not eat every yielded turn. Holders [D, L]: D rejects. Turn 0
/// offers D only (the PoS takes the budget after that attempt); turn 1 starts with the holder
/// tried least recently — L — which gets a chunk. Without the rotation D is first again and L
/// never gets one.
#[tokio::test]
async fn a_dead_first_holder_does_not_stall_live_holders_under_constant_overdue_pos() {
    let rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    let rec = retained(rig.data_dir.path(), 0x1e, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let (armed, slot) = (Arc::new(AtomicBool::new(true)), Arc::new(Mutex::new(None)));
    let waiter = register_waiter_once(
        &rig.budget,
        PriorityKind::OverduePos,
        YIELD_WAITER_MIB,
        &armed,
        &slot,
    );
    let flags = [
        Arc::new(AtomicBool::new(true)),
        Arc::new(AtomicBool::new(true)),
    ];
    let mut net = Net::new(0x4d).await;
    let holders = [
        net.holder(
            0x64,
            &rig.budget,
            dead_holder_hooks(&flags[0], waiter.clone()),
        )
        .await,
        net.holder(0x65, &rig.budget, dead_holder_hooks(&flags[1], waiter))
            .await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    let pool = pool_of(&devices);

    // Turn 0: both reject; the holder the plan puts first is the dead one.
    constant_pos_turn(&rig, &swarm, &rec, &pool, 0, &armed, &slot).await;
    assert_eq!(offers_total(&holders), 1);
    let dead = holders.iter().position(|h| h.offers() == 1).unwrap();
    let live = 1 - dead;
    flags[live].store(false, Ordering::SeqCst);

    // Turn 1: the live holder, never tried, goes first and gets its chunk.
    constant_pos_turn(&rig, &swarm, &rec, &pool, 1, &armed, &slot).await;
    assert_eq!(
        holders[live].transfers(),
        1,
        "the live holder got a chunk within two turns (dead: {} offers)",
        holders[dead].offers()
    );
    assert_eq!(
        holders[dead].offers(),
        1,
        "the dead one was not first again"
    );
}

/// M35, the shrinking list (WARN-4): holders [D, X, Y]. D rejects; X completes its whole share in
/// one chunk on turn 1 and drops out of the plan; on turn 2 the plan is [D, Y] and Y must be
/// first. A rotation by `yields mod len` starts turn 2 with D (2 mod 2 = 0) and Y waits for turn 3.
#[tokio::test]
async fn a_dead_first_holder_does_not_stall_live_holders_when_a_holder_completes_and_drops_out() {
    // One chunk holds a whole share.
    let rig = Rig::new(YIELD_BUDGET_MIB, 80 << 20);
    let rec = retained(rig.data_dir.path(), 0x1f, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let (armed, slot) = (Arc::new(AtomicBool::new(true)), Arc::new(Mutex::new(None)));
    let waiter = register_waiter_once(
        &rig.budget,
        PriorityKind::OverduePos,
        YIELD_WAITER_MIB,
        &armed,
        &slot,
    );
    let flags: Vec<Arc<AtomicBool>> = (0..3).map(|_| Arc::new(AtomicBool::new(true))).collect();
    let mut net = Net::new(0x4e).await;
    let mut holders = Vec::new();
    for (i, flag) in flags.iter().enumerate() {
        holders.push(
            net.holder(
                0x66 + i as u8,
                &rig.budget,
                dead_holder_hooks(flag, waiter.clone()),
            )
            .await,
        );
    }
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    let pool = pool_of(&devices);

    // Turn 0: all reject; the first in the plan is D.
    constant_pos_turn(&rig, &swarm, &rec, &pool, 0, &armed, &slot).await;
    assert_eq!(offers_total(&holders), 1);
    let dead = holders.iter().position(|h| h.offers() == 1).unwrap();
    for (i, flag) in flags.iter().enumerate() {
        flag.store(i == dead, Ordering::SeqCst);
    }

    // Turn 1: a never-tried holder first; its whole share is one chunk, so it completes.
    constant_pos_turn(&rig, &swarm, &rec, &pool, 1, &armed, &slot).await;
    let first_live = holders
        .iter()
        .position(|h| h.transfers() == 1)
        .expect("a live holder got its chunk on turn 1");
    assert_ne!(first_live, dead);
    let statuses = placement_statuses(&rig.db, &rec.block_id);
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == PlacementStatus::Alive)
            .count(),
        1,
        "it completed and dropped out of the plan: {statuses:?}"
    );

    // Turn 2: the plan is [D, Y]; Y (never tried) is first and gets its chunk.
    constant_pos_turn(&rig, &swarm, &rec, &pool, 2, &armed, &slot).await;
    let second_live = (0..3)
        .find(|&i| i != dead && i != first_live)
        .expect("the third holder");
    assert_eq!(
        holders[second_live].transfers(),
        1,
        "the second live holder got its chunk by turn 2 (dead holder offers: {})",
        holders[dead].offers()
    );
}

// ─── N4: the wait for the budget is visible ──────────────────────────────────

/// A worker that waits for the budget says so once, after `WAIT_LOG_AFTER`, with the numbers; the
/// `granted` line of the same permit carries `waited_ms`. Virtual time while it waits (the clock
/// is paused only around the wait: the network work before and after runs in real time).
#[tokio::test]
async fn worker_wait_logs_once_after_slow_after() {
    let (logs, _guard) = capture_logs();
    let rig = Rig::new(200, 80 << 20);
    let rec = retained(rig.data_dir.path(), 0x20, 3, 1024);
    rig.db.upsert_source_block(&rec).unwrap();
    let mut net = Net::new(0x4f).await;
    let holders = [
        net.holder(0x68, &rig.budget, Hooks::default()).await,
        net.holder(0x69, &rig.budget, Hooks::default()).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    let everything = rig
        .budget
        .try_acquire(HolderKind::Pos, &SourceBlockId([1; 32]), 200 * MIB)
        .unwrap();

    tokio::time::pause();
    let worker = {
        let (db, config, swarm, rec, pool) = (
            rig.db.clone(),
            rig.config.clone(),
            Arc::clone(&swarm),
            rec.clone(),
            pool_of(&devices),
        );
        tokio::spawn(async move {
            let key = signing_key();
            worker::run_block_iteration(
                &db,
                &config,
                &plain_encoder(),
                &swarm,
                Some(&key),
                None,
                None,
                &rec,
                &pool,
                0,
                &mut HashMap::new(),
            )
            .await
        })
    };
    let wait_lines = || {
        logs.text()
            .lines()
            .filter(|l| l.contains("work_pipeline: waiting for memory budget"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    // The worker has reached the wait (its 5 s timer is armed) before the clock moves.
    until("the worker waits for the budget", || {
        rig.budget.queued_waiters() == 1
    })
    .await;
    tokio::time::advance(Duration::from_secs(4)).await;
    assert!(
        wait_lines().is_empty(),
        "not before 5 s: {:?}",
        wait_lines()
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    until("the line after 5 s", || !wait_lines().is_empty()).await;
    tokio::time::advance(Duration::from_secs(30)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(wait_lines().len(), 1, "once per wait, not per period");
    tokio::time::resume();

    let line = wait_lines().remove(0);
    assert!(line.contains("INFO"), "{line}");
    assert!(
        line.contains(&format!("block={}", rec.block_id))
            && line.contains("need_mib=")
            && line.contains("outstanding_mib=200")
            && line.contains("queued_ahead=0"),
        "{line}"
    );

    drop(everything);
    let outcome = tokio::time::timeout(Duration::from_secs(60), worker)
        .await
        .expect("the worker goes on when the budget frees")
        .unwrap()
        .unwrap();
    assert!(outcome.acked > 0, "{outcome:?}");
    let text = logs.text();
    let granted = text
        .lines()
        .find(|l| l.contains("mem_budget: granted kind=worker"))
        .unwrap_or_else(|| panic!("no granted line:\n{text}"));
    let waited: u64 = granted
        .split("waited_ms=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no waited_ms: {granted}"));
    assert!(waited >= 36_000, "waited_ms = {waited}: {granted}");
    assert_eq!(wait_lines().len(), 1);
}
