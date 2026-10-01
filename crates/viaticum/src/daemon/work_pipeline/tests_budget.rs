// The worker and the block work memory budget (backup-i24, backup-i24-a, J8, J10, J12-ex, J13).
//
// Real swarms: the owner runs `run_block_iteration` against holders that answer SymbolOffer with
// Accept and SymbolTransfer with Stored (a holder task per swarm) and can be told to run a hook
// at chosen moments — that is how a test puts a waiter into the budget at a precise point of the
// worker's turn.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    /// Every ESI received, in order (a repeat is a re-sent symbol, К-b2a‴).
    esis: Vec<u32>,
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
    fn esis(&self) -> Vec<u32> {
        self.log.lock().unwrap().esis.clone()
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
    /// Answer with `SymbolStored` naming THIS block instead of the transferred one (M101).
    stored_names_block: Option<SourceBlockId>,
    /// Answer with a `SymbolStored` whose range is far wider than the chunk (M101).
    stored_wide: bool,
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
                            l.esis.extend(transfer.symbols.iter().map(|s| s.esi));
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
                                source_block_id: hooks
                                    .stored_names_block
                                    .unwrap_or(transfer.source_block_id),
                                esi_ranges: if hooks.stored_wide {
                                    vec![(0, 100_000)]
                                } else {
                                    transfer.symbols.iter().map(|s| (s.esi, 1)).collect()
                                },
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
    last_attempt: tokio::sync::Mutex<worker::TurnMemory>,
    /// The restore gate the turns see (spec v3.12b); `None`: no gate.
    gate: Option<super::RestoreGate>,
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
            last_attempt: tokio::sync::Mutex::new(worker::TurnMemory::default()),
            gate: None,
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
                self.gate.as_ref(),
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
                &mut worker::TurnMemory::default(),
                None,
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
                &mut worker::TurnMemory::default(),
                None,
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
            restore_at_chunk: false,
            gate: None,
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
    let marked = |holder, turn| worker::TurnMemory {
        turns: turn + 1,
        holders: HashMap::from([(
            holder,
            worker::HolderDelivery {
                acked: vec![(0, 1)],
                state: worker::HolderState::Failed(turn),
            },
        )]),
    };
    let mut yields = HashMap::new();
    let mut last = HashMap::new();
    for id in [a, b] {
        last.insert(id, marked(holder, 0));
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
    last.insert(a, marked(holder, 2));
    super::count_yields(&mut yields, &mut last, a, &outcome(0, 0, 0, false, false));
    assert!(!yields.contains_key(&a) && !last.contains_key(&a));
    // A turn that entered an empty map leaves none behind.
    last.insert(b, worker::TurnMemory::default());
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

// ─── Rotation: in progress, never tried, failed longest ago (spec v3.5 WARN-4, v3.12) ──────

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

/// M36 (16', WARN-1 b): the marks of the rotation follow a counter of ALL turns of the block, not
/// the yield count. Holders [B, C], both dead. Turn 0 (no waiter, no yield) tries both; turn 1
/// (yield) tries the one the plan puts first, P; turn 2 must start with the other one, Q, which
/// was tried longest ago. Marks equal to the yield count make turn 0 and turn 1 the same
/// "turn 0": P and Q tie and the plan puts P first again.
#[tokio::test]
async fn the_rotation_counts_turns_without_a_yield_too() {
    let rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    let rec = retained(rig.data_dir.path(), 0x21, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let (armed, slot) = (Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(None)));
    let waiter = register_waiter_once(
        &rig.budget,
        PriorityKind::OverduePos,
        YIELD_WAITER_MIB,
        &armed,
        &slot,
    );
    let flag = Arc::new(AtomicBool::new(true));
    let mut net = Net::new(0x50).await;
    let holders = [
        net.holder(0x6b, &rig.budget, dead_holder_hooks(&flag, waiter.clone()))
            .await,
        net.holder(0x6c, &rig.budget, dead_holder_hooks(&flag, waiter))
            .await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    let pool = pool_of(&devices);

    // Turn 0: no yield; both are tried and fail.
    let outcome = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool, 0)
        .await
        .unwrap();
    assert!(!outcome.yielded, "{outcome:?}");
    assert_eq!(offers_total(&holders), 2);

    // Turn 1: the first yield; the plan's first holder P is tried.
    constant_pos_turn(&rig, &swarm, &rec, &pool, 0, &armed, &slot).await;
    assert_eq!(offers_total(&holders), 3);
    let first = holders.iter().position(|h| h.offers() == 2).unwrap();

    // Turn 2: the other holder is first.
    constant_pos_turn(&rig, &swarm, &rec, &pool, 1, &armed, &slot).await;
    assert_eq!(
        holders[1 - first].offers(),
        2,
        "the holder tried longest ago goes first (offers: {} and {})",
        holders[0].offers(),
        holders[1].offers()
    );
    assert_eq!(holders[first].offers(), 2, "P was not first again");
}

/// M37 (16', WARN-1 a): a holder is marked when it was put through an attempt, not when the turn
/// reached it. Holders [X, Y]: X rejects (an attempt); Y accepts, and the overdue PoS that came
/// during its offer takes the budget before its first chunk — Y had no attempt. The next turn
/// starts with Y (never attempted), not with X (plan order). Marking at the start would tie them.
#[tokio::test]
async fn a_holder_the_turn_yielded_before_its_first_attempt_is_not_marked() {
    let rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    let rec = retained(rig.data_dir.path(), 0x22, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let (armed, slot) = (Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(None)));
    let waiter = register_waiter_once(
        &rig.budget,
        PriorityKind::OverduePos,
        YIELD_WAITER_MIB,
        &armed,
        &slot,
    );
    // Offer 0 (X): reject. Offer 1 (Y): accept, and the waiter comes. Offer 2: the waiter again.
    let flag = Arc::new(AtomicBool::new(true));
    let seen = Arc::new(AtomicUsize::new(0));
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut net = Net::new(0x51).await;
    let mut holders = Vec::new();
    for i in 0..2usize {
        let reject = Arc::clone(&flag);
        let (flag, seen, order, waiter) = (
            Arc::clone(&flag),
            Arc::clone(&seen),
            Arc::clone(&order),
            waiter.clone(),
        );
        let on_offer = hook(move || {
            let n = seen.fetch_add(1, Ordering::SeqCst);
            order.lock().unwrap().push(i);
            if n == 1 {
                flag.store(false, Ordering::SeqCst);
            }
            let waiter = waiter.clone();
            async move {
                if n >= 1 {
                    waiter().await;
                }
            }
        });
        let hooks = Hooks {
            on_offer: Some(on_offer),
            reject_offers: Some(reject),
            ..Hooks::default()
        };
        holders.push(net.holder(0x6d + i as u8, &rig.budget, hooks).await);
    }
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    let pool = pool_of(&devices);

    // Turn 1: X fails, Y accepts and the turn yields before Y's first chunk.
    constant_pos_turn(&rig, &swarm, &rec, &pool, 0, &armed, &slot).await;
    let (x, y) = {
        let order = order.lock().unwrap();
        assert_eq!(order.len(), 2, "both were offered: {order:?}");
        (order[0], order[1])
    };
    assert_ne!(x, y);
    assert_eq!(transfers_total(&holders), 0, "Y got no chunk");

    // Turn 2: Y, never attempted, is first (and gets its first chunk).
    constant_pos_turn(&rig, &swarm, &rec, &pool, 1, &armed, &slot).await;
    assert_eq!(
        order.lock().unwrap().as_slice(),
        &[x, y, y],
        "the second turn starts with the holder that was not attempted"
    );
    assert_eq!(holders[y].transfers(), 1);
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
                &mut worker::TurnMemory::default(),
                None,
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

// ─── Delivery memory: progress through the yields (К-b2a‴, spec v3.12, v3.12a) ───────────────
//
// The liveness of the worker is pre-registered as COMPLETION within N turns, not as activity of a
// turn (the lesson of v3.12): a chunk sent twice looked like progress to the old tests.

/// The chunk budget (bytes) that cuts the largest share of the plan for `pool` into three chunks
/// (a symbol is `BIG_T` bytes, so `n` symbols per chunk is `n · BIG_T`).
fn three_chunk_budget(rig: &Rig, rec: &SourceBlockRecord, pool: &PoolSnapshot) -> usize {
    let plan = super::offer_plan::plan_offers(&rig.db, rec, &pool.candidates, 0).unwrap();
    let super::offer_plan::OfferPlan::Planned { offers, .. } = plan else {
        panic!("stand: the plan has offers");
    };
    let share = offers
        .iter()
        .map(|o| o.esi_ranges.iter().map(|r| r.1).sum::<u32>())
        .max()
        .unwrap();
    assert!(share >= 3, "stand: a share of {share} symbols");
    share.div_ceil(3) as usize * BIG_T as usize
}

fn alive_count(db: &Db, bid: &SourceBlockId) -> usize {
    placement_statuses(db, bid)
        .iter()
        .filter(|s| **s == PlacementStatus::Alive)
        .count()
}

/// One turn under a constant overdue PoS: the waiter is put in on the first offer of the turn
/// and served (and let go) after it, if the turn put one in.
async fn pos_turn(
    rig: &Rig,
    swarm: &Arc<SwarmHandle>,
    rec: &SourceBlockRecord,
    pool: &PoolSnapshot,
    turn_no: u32,
    armed: &Arc<AtomicBool>,
    slot: &Arc<Mutex<Option<JoinHandle<MemPermit>>>>,
) -> WorkOutcome {
    armed.store(true, Ordering::SeqCst);
    let outcome = rig
        .turn(&plain_encoder(), swarm, rec, pool, turn_no)
        .await
        .unwrap();
    if slot.lock().unwrap().is_some() {
        drain_waiter(slot).await;
    }
    outcome
}

/// ESIs of a `chunk sent` line: `esis=a..b,c..d` (inclusive ends).
fn esis_of_line(line: &str) -> Vec<u32> {
    let text = line
        .split("esis=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no esis field: {line}"));
    text.split(',')
        .flat_map(|range| {
            let (a, b) = range.split_once("..").unwrap();
            a.parse::<u32>().unwrap()..=b.parse::<u32>().unwrap()
        })
        .collect()
}

fn field_of<'a>(line: &'a str, name: &str) -> &'a str {
    line.split(&format!("{name}="))
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no {name} field: {line}"))
}

/// The `symbols` of every `encoded raw symbols` line, in order.
fn encoded_symbols(text: &str) -> Vec<usize> {
    text.lines()
        .filter(|l| l.contains("work_pipeline: encoded raw symbols"))
        .map(|l| field_of(l, "symbols").parse().unwrap())
        .collect()
}

/// The stand of the delivery tests: a block, a constant overdue PoS, `n` live holders.
struct PosStand {
    rig: Rig,
    rec: SourceBlockRecord,
    armed: Arc<AtomicBool>,
    slot: Arc<Mutex<Option<JoinHandle<MemPermit>>>>,
    flags: Vec<Arc<AtomicBool>>,
    holders: Vec<Holder>,
    swarm: Arc<SwarmHandle>,
    pool: PoolSnapshot,
}

impl PosStand {
    async fn new(seed: u8, net_seed: u8, holders: u8, dead: bool) -> PosStand {
        let mut rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
        let rec = retained(rig.data_dir.path(), seed, BIG_K, BIG_T);
        rig.db.upsert_source_block(&rec).unwrap();
        let (armed, slot) = (Arc::new(AtomicBool::new(true)), Arc::new(Mutex::new(None)));
        let waiter = register_waiter_once(
            &rig.budget,
            PriorityKind::OverduePos,
            YIELD_WAITER_MIB,
            &armed,
            &slot,
        );
        let mut net = Net::new(net_seed).await;
        let mut flags = Vec::new();
        let mut list = Vec::new();
        for i in 0..holders {
            let flag = Arc::new(AtomicBool::new(dead));
            list.push(
                net.holder(
                    net_seed + 0x10 + i,
                    &rig.budget,
                    dead_holder_hooks(&flag, waiter.clone()),
                )
                .await,
            );
            flags.push(flag);
        }
        let swarm = net.ready();
        let devices: Vec<DeviceId> = list.iter().map(|h| h.device_id).collect();
        let pool = pool_of(&devices);
        rig.config.chunk_budget_bytes = three_chunk_budget(&rig, &rec, &pool);
        PosStand {
            rig,
            rec,
            armed,
            slot,
            flags,
            holders: list,
            swarm,
            pool,
        }
    }

    async fn turn(&self, turn_no: u32) -> WorkOutcome {
        pos_turn(
            &self.rig,
            &self.swarm,
            &self.rec,
            &self.pool,
            turn_no,
            &self.armed,
            &self.slot,
        )
        .await
    }
}

/// M85 (v3.12). Two live holders with three chunks each, an overdue PoS that stands in the queue
/// again on every send: both placements are `Alive` within seven turns, and no ESI is accepted
/// twice by a holder — the delivery goes on from where it stopped. Without the memory every turn
/// sends the first chunk again, and nothing is ever finished (the finding of the К-b6 run).
#[tokio::test]
async fn delivery_completes_under_constant_overdue_pos() {
    let (logs, _guard) = capture_logs();
    let st = PosStand::new(0x30, 0x60, 2, false).await;

    let mut turns = 0u32;
    while alive_count(&st.rig.db, &st.rec.block_id) < 2 && turns < 7 {
        let outcome = st.turn(turns).await;
        turns += 1;
        assert!(
            outcome.yielded || alive_count(&st.rig.db, &st.rec.block_id) == 2,
            "turn {turns}: {outcome:?}"
        );
    }

    assert_eq!(
        alive_count(&st.rig.db, &st.rec.block_id),
        2,
        "both placements are Alive within 7 turns (turns used: {turns}, chunks: {:?})",
        st.holders.iter().map(Holder::transfers).collect::<Vec<_>>()
    );
    for (i, h) in st.holders.iter().enumerate() {
        let esis = h.esis();
        let unique: std::collections::HashSet<u32> = esis.iter().copied().collect();
        assert_eq!(
            unique.len(),
            esis.len(),
            "holder {i} got an ESI twice: {esis:?}"
        );
        assert_eq!(h.transfers(), 3, "stand: three chunks per holder");
    }
    // The log says the same, with the field `esis` (the E2E guard reads it): no (holder, ESI)
    // pair twice among the stored chunks, and the lines add up to what the holders received.
    let text = logs.text();
    let mut seen = std::collections::HashSet::new();
    for line in text
        .lines()
        .filter(|l| l.contains("work_pipeline: chunk sent") && l.contains("reply=stored"))
    {
        let holder = field_of(line, "holder").to_string();
        for esi in esis_of_line(line) {
            assert!(
                seen.insert((holder.clone(), esi)),
                "({holder}, {esi}) twice"
            );
        }
    }
    let received: usize = st.holders.iter().map(|h| h.esis().len()).sum();
    assert_eq!(seen.len(), received, "every received ESI is in a line");
}

/// M86 (v3.12, v3.12a NOTE 6). The holder that was put through a chunk and was cut goes FIRST
/// next turn, ahead of the ones never tried; a dead holder goes last once a live one is waiting.
/// Holders [D, X, Y]: D rejects (turn 0). Turn 1: a never-tried X gets its first chunk. Turn 2: X
/// again (in progress), not Y. Turn 3: X completes. Turn 4: Y (never tried) before D (failed).
#[tokio::test]
async fn in_progress_holder_goes_first_dead_holder_goes_last() {
    let st = PosStand::new(0x31, 0x62, 3, true).await;

    // Turn 0: all reject; the one the plan puts first is D.
    st.turn(0).await;
    assert_eq!(offers_total(&st.holders), 1);
    let dead = st.holders.iter().position(|h| h.offers() == 1).unwrap();
    for (i, flag) in st.flags.iter().enumerate() {
        flag.store(i == dead, Ordering::SeqCst);
    }

    // Turn 1: a never-tried holder first, one chunk, cut.
    let outcome = st.turn(1).await;
    assert!(outcome.yielded, "{outcome:?}");
    let x = st
        .holders
        .iter()
        .position(|h| h.transfers() == 1)
        .expect("a live holder got its first chunk");
    assert_ne!(x, dead);
    let y = (0..3).find(|&i| i != dead && i != x).unwrap();

    // Turn 2: X is in progress and goes first: its second chunk. Y was not even offered.
    st.turn(2).await;
    assert_eq!(
        st.holders[x].transfers(),
        2,
        "the holder in progress goes first"
    );
    assert_eq!(st.holders[y].offers(), 0, "the never-tried one waited");
    assert_eq!(st.holders[dead].offers(), 1);

    // Turn 3: its third chunk covers the range: Alive.
    st.turn(3).await;
    assert_eq!(st.holders[x].transfers(), 3);
    assert_eq!(alive_count(&st.rig.db, &st.rec.block_id), 1);

    // Turn 4: Y, never tried, goes before the dead one.
    st.turn(4).await;
    assert_eq!(st.holders[y].transfers(), 1, "Y got its first chunk");
    assert_eq!(st.holders[dead].offers(), 1, "the dead holder went last");
}

/// v3.12a (lesson of v3.12: completion within N). A dead holder that the plan puts first, and two
/// live ones with three chunks each, under a constant overdue PoS: both live placements are
/// `Alive` within eight turns — the dead one costs one turn, then goes behind the live ones.
#[tokio::test]
async fn delivery_completes_with_a_dead_first_holder_under_constant_overdue_pos() {
    let st = PosStand::new(0x32, 0x64, 3, true).await;

    st.turn(0).await;
    let dead = st.holders.iter().position(|h| h.offers() == 1).unwrap();
    for (i, flag) in st.flags.iter().enumerate() {
        flag.store(i == dead, Ordering::SeqCst);
    }
    let mut turns = 1u32;
    while alive_count(&st.rig.db, &st.rec.block_id) < 2 && turns < 8 {
        st.turn(turns).await;
        turns += 1;
    }

    assert_eq!(
        alive_count(&st.rig.db, &st.rec.block_id),
        2,
        "both live holders are Alive within 8 turns (used {turns}; chunks {:?})",
        st.holders.iter().map(Holder::transfers).collect::<Vec<_>>()
    );
    let statuses = placement_statuses(&st.rig.db, &st.rec.block_id);
    assert!(
        statuses.iter().any(|s| *s != PlacementStatus::Alive),
        "the dead holder is not Alive: {statuses:?}"
    );
    for (i, h) in st.holders.iter().enumerate().filter(|(i, _)| *i != dead) {
        let esis = h.esis();
        let unique: std::collections::HashSet<u32> = esis.iter().copied().collect();
        assert_eq!(unique.len(), esis.len(), "holder {i} got an ESI twice");
    }
}

/// M89 (v3.12 item 3). The encoder is asked for the ESIs that are not acknowledged yet: after a
/// turn that put one chunk on the wire, the next turn encodes that many symbols fewer.
#[tokio::test]
async fn turn_encodes_only_the_unacked_esis() {
    let (logs, _guard) = capture_logs();
    let st = PosStand::new(0x33, 0x66, 2, false).await;

    st.turn(0).await;
    let sent: usize = st
        .holders
        .iter()
        .map(|h| h.log.lock().unwrap().transfers.iter().sum::<usize>())
        .sum();
    assert!(sent >= 1, "stand: the first turn sent a chunk");
    st.turn(1).await;

    let encoded = encoded_symbols(&logs.text());
    assert_eq!(encoded.len(), 2, "{encoded:?}");
    assert_eq!(
        encoded[1],
        encoded[0] - sent,
        "the second turn encodes the rest only: {encoded:?} after {sent} acknowledged"
    );
}

/// M91 (v3.12a NOTE 2). Binding takes the rest of the range, `esi_ranges − acked`: a turn that
/// encoded only the rest binds without error, and what it binds is exactly the rest.
#[test]
fn bind_covers_only_the_unacked_rest() {
    let encoder = RaptorQEncoder::new();
    let mut placement = super::tests::placement(
        SourceBlockId([0xD1; 32]),
        DeviceId([0xD2; 32]),
        PlacementStatus::Offered,
        0,
    );
    placement.esi_ranges = vec![(100, 6), (200, 2)];
    let acked = [(100, 2), (104, 1)];
    // What the turn encoded: the rest only — 102..104, 105, 200..202.
    let raw: Vec<Symbol> = [102u32, 103, 105, 200, 201]
        .iter()
        .map(|&esi| Symbol {
            esi,
            data: esi.to_le_bytes().repeat(4),
        })
        .collect();

    let bound = worker::bind_placement_symbols(
        &encoder,
        &placement.source_block_id,
        &placement,
        &acked,
        &raw,
    )
    .expect("the rest is all the binding looks for");

    assert_eq!(
        bound.iter().map(|s| s.esi).collect::<Vec<_>>(),
        vec![102, 103, 105, 200, 201]
    );
    for s in &bound {
        let want = encoder.apply_binding(
            Symbol {
                esi: s.esi,
                data: s.esi.to_le_bytes().repeat(4),
            },
            &placement.source_block_id,
            &placement.holder_id,
        );
        assert_eq!(s.data, want.data, "ESI {} bound to its holder", s.esi);
    }
}

/// M90 (v3.12, Q-V9 (b): `restore_pauses_backup = false`). A restore waiting for the budget stops
/// the worker at a CHUNK boundary: after the turn's first attempt, before the next send — not only
/// between holders. One chunk goes out, the restore gets the budget, the placements stay `Offered`.
#[tokio::test]
async fn worker_yields_to_restore_at_a_chunk_boundary_after_one_attempt() {
    let (logs, _guard) = capture_logs();
    let mut rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    rig.config.restore_pauses_backup = false;
    let rec = retained(rig.data_dir.path(), 0x34, BIG_K, BIG_T);
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
    let mut net = Net::new(0x68).await;
    let holders = [
        net.holder(0x78, &rig.budget, hooks.clone()).await,
        net.holder(0x79, &rig.budget, hooks).await,
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
        "one chunk, then the restore: not the whole holder"
    );
    assert_eq!(
        (outcome.acked, outcome.failed),
        (0, 0),
        "a yield is not a failure, nothing was delivered in full"
    );
    let statuses = placement_statuses(&rig.db, &rec.block_id);
    assert!(
        statuses.iter().all(|s| *s == PlacementStatus::Offered),
        "{statuses:?}"
    );
    drain_waiter(&slot).await;
    let text = logs.text();
    let line = text
        .lines()
        .find(|l| l.contains("work_pipeline: yielding memory to restore"))
        .unwrap_or_else(|| panic!("no yield line:\n{text}"));
    assert!(line.contains("holders_done=0"), "{line}");
}

/// The chunk-boundary rule of the turn without a network (Q-V9 (b)): never before the first
/// attempt; afterwards only while the restore does not fit beside the permit; and only when the
/// turn is built for it — with `restore_at_chunk = false` the rule is not there.
#[tokio::test]
async fn turn_yields_to_restore_at_a_chunk_only_when_built_for_it() {
    fn turn<'a>(
        budget: &'a MemBudget,
        permit: &'a MemPermit,
        attempts: u32,
        restore_at_chunk: bool,
    ) -> Turn<'a> {
        Turn {
            budget,
            permit,
            chunk_budget_bytes: 1024,
            holders_started: 1,
            attempts,
            restore_at_chunk,
            gate: None,
        }
    }
    let budget = MemBudget::new(100 * MIB);
    let held = budget
        .try_acquire(HolderKind::Worker, &SourceBlockId([1; 32]), 80 * MIB)
        .unwrap();
    let _restore = spawn_waiter(&budget, PriorityKind::Restore, 60);
    until("the restore waits", || {
        budget.priority_waiters(PriorityKind::Restore) == 1
    })
    .await;

    assert!(!turn(&budget, &held, 0, true).restore_wants_the_budget_at_a_chunk());
    assert!(turn(&budget, &held, 1, true).restore_wants_the_budget_at_a_chunk());
    assert!(!turn(&budget, &held, 1, false).restore_wants_the_budget_at_a_chunk());
}

// ─── The memory is cleared (M88) ──────────────────────────────────────────────

fn memory_of(holder: DeviceId) -> worker::TurnMemory {
    worker::TurnMemory {
        turns: 4,
        holders: HashMap::from([(
            holder,
            worker::HolderDelivery {
                acked: vec![(0, 2)],
                state: worker::HolderState::InProgress,
            },
        )]),
    }
}

/// M88 (v3.12 item 5). The delivery memory of a block goes when the block is parked, when it
/// leaves service, and — per holder — when the holder drops out of the plan; the memory of the
/// holders that stay is kept.
#[tokio::test]
async fn delivery_memory_is_dropped_on_park_and_when_the_holder_leaves_the_plan() {
    use super::tests::{add_pool_peers, block_id, device_id, lonely_swarm, pipeline_with};

    // The holder leaves the plan: Z is not in the pool of this turn, P is.
    let data_dir = tempfile::tempdir().unwrap();
    let rig_db = db();
    let (p, z) = (device_id(0xB1), device_id(0xB2));
    let other = device_id(0xB3);
    add_pool_peers(&rig_db, &[p, other]);
    let rec = super::tests::retained_block(data_dir.path(), 0xB4, 1.0);
    rig_db.upsert_source_block(&rec).unwrap();
    let mut config = super::tests::make_config();
    config.data_dir = data_dir.path().to_path_buf();
    let swarm = lonely_swarm(0x3c).await;
    let mut memory = memory_of(z);
    memory.holders.insert(
        p,
        worker::HolderDelivery {
            acked: vec![(0, 1)],
            state: worker::HolderState::InProgress,
        },
    );
    let _ = worker::run_block_iteration(
        &rig_db,
        &config,
        &plain_encoder(),
        &swarm,
        None,
        None,
        None,
        &rec,
        &pool_of(&[p, other]),
        0,
        &mut memory,
        None,
    )
    .await;
    assert!(
        !memory.holders.contains_key(&z),
        "Z is not in the plan: its entry is gone"
    );
    assert!(
        memory.holders.contains_key(&p),
        "P is in the plan: its entry stays (failed, with what it acknowledged)"
    );

    // Parked: the pool is too small for the block.
    let db2 = db();
    let bid = block_id(0xB5);
    let mut rec2 = super::tests::make_block_record(bid, 1.0, 0.99999);
    rec2.current_reliability = 0.0;
    db2.upsert_source_block(&rec2).unwrap();
    add_pool_peers(&db2, &[p]);
    let swarm2 = lonely_swarm(0x3d).await;
    let mut pipeline = pipeline_with(&db2, super::tests::make_config(), Some(swarm2));
    pipeline.yields.insert(bid, 1);
    pipeline.last_attempt.insert(bid, memory_of(p));
    assert!(pipeline.run_iteration().await.unwrap());
    assert!(
        db2.block_cooldown(&bid).parked,
        "the pool is too small: parked"
    );
    assert!(
        !pipeline.last_attempt.contains_key(&bid),
        "the memory went with it"
    );
    assert!(!pipeline.yields.contains_key(&bid));
}

/// M88 (v3.12 item 5): a block that left service while nobody worked it loses its memory at the
/// start of the next iteration (`forget_blocks_out_of_service`); the memory of a block still in
/// service is kept.
#[tokio::test]
async fn delivery_memory_of_a_block_that_left_service_is_dropped() {
    use super::tests::{block_id, device_id, lonely_swarm, pipeline_with};

    let db = db();
    let (gone, kept) = (block_id(0xB6), block_id(0xB7));
    let holder = device_id(0xB8);
    let mut leaving = super::tests::make_block_record(gone, 1.0, 0.99999);
    leaving.status = SourceBlockStatus::Deleting;
    db.upsert_source_block(&leaving).unwrap();
    let mut staying = super::tests::make_block_record(kept, 1.0, 0.99999);
    staying.status = SourceBlockStatus::Active;
    db.upsert_source_block(&staying).unwrap();

    let swarm = lonely_swarm(0x3e).await;
    let mut pipeline = pipeline_with(&db, super::tests::make_config(), Some(swarm));
    for b in [gone, kept] {
        pipeline.yields.insert(b, 2);
        pipeline.last_attempt.insert(b, memory_of(holder));
    }
    pipeline.forget_blocks_out_of_service();

    assert!(!pipeline.last_attempt.contains_key(&gone) && !pipeline.yields.contains_key(&gone));
    assert!(pipeline.last_attempt.contains_key(&kept) && pipeline.yields.contains_key(&kept));
}

// ─── The restore gate (К-b2a⁗, spec v3.12b WARN-1..3, Q-V9 (a)) ───────────────────────────────

/// A gate the test raises and lowers by hand; the notifier is returned too (a gate whose
/// notifier is dropped closes the wake of a running loop).
fn flag_gate() -> (Arc<AtomicBool>, super::RestoreGate, super::GateWake) {
    let wake = super::new_gate_wake();
    let flag = Arc::new(AtomicBool::new(false));
    let f = Arc::clone(&flag);
    let gate = super::RestoreGate::new(&wake, move || f.load(Ordering::SeqCst));
    (flag, gate, wake)
}

/// A hook that raises the flag ONCE (a restore job starts at that moment); holders that share the
/// hook share the shot.
fn raise_gate(flag: &Arc<AtomicBool>) -> Hook {
    let (flag, armed) = (Arc::clone(flag), Arc::new(AtomicBool::new(true)));
    hook(move || {
        let (flag, armed) = (Arc::clone(&flag), Arc::clone(&armed));
        async move {
            if armed.swap(false, Ordering::SeqCst) {
                flag.store(true, Ordering::SeqCst);
            }
        }
    })
}

/// M94 (v3.12b WARN-1). A restore job starts while the turn delivers, and NO restore waits for
/// the memory (the budget has no waiter): the turn stops at the next chunk boundary — after the
/// chunk that was on the wire — not at the end of the holder or of the block. The placements stay
/// `Offered`; the next turn, with the gate down, sends the rest and encodes only that.
#[tokio::test]
async fn job_started_mid_turn_stops_the_turn_at_the_next_chunk_boundary() {
    let (logs, _guard) = capture_logs();
    let (flag, gate, _wake) = flag_gate();
    let mut rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    rig.gate = Some(gate);
    let rec = retained(rig.data_dir.path(), 0x35, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let hooks = Hooks {
        on_first_transfer: Some(raise_gate(&flag)),
        ..Hooks::default()
    };
    let mut net = Net::new(0x69).await;
    let holders = [
        net.holder(0x7a, &rig.budget, hooks.clone()).await,
        net.holder(0x7b, &rig.budget, hooks).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    assert_eq!(
        rig.budget.priority_waiters(PriorityKind::Restore),
        0,
        "stand: no restore waits for the memory"
    );

    let outcome = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool_of(&devices), 0)
        .await
        .unwrap();

    assert!(outcome.yielded, "{outcome:?}");
    assert_eq!(
        transfers_total(&holders),
        1,
        "one chunk, then the turn stops: not the holder, not the block"
    );
    assert_eq!((outcome.acked, outcome.failed), (0, 0));
    let statuses = placement_statuses(&rig.db, &rec.block_id);
    assert!(
        !statuses.is_empty() && statuses.iter().all(|s| *s == PlacementStatus::Offered),
        "{statuses:?}"
    );
    assert_eq!(rig.budget.outstanding_bytes(), 0, "the permit is back");
    assert!(
        logs.text()
            .lines()
            .any(|l| l.contains("work_pipeline: yielding memory to restore")),
        "{}",
        logs.text()
    );

    // The job is over: the next turn goes on from where it stopped (one re-encode, of the rest).
    flag.store(false, Ordering::SeqCst);
    let next = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool_of(&devices), 1)
        .await
        .unwrap();
    assert!(!next.yielded, "{next:?}");
    let encoded = encoded_symbols(&logs.text());
    assert_eq!(encoded.len(), 2, "{encoded:?}");
    assert!(
        encoded[1] < encoded[0],
        "the second turn encodes the rest only: {encoded:?}"
    );
}

/// The boundary rule of the turn without a network: with the gate up the turn stops before a next
/// chunk and before a next holder, never before the first attempt; with the gate down, or not
/// given, the rule is not there (no restore waits: the budget has none).
#[tokio::test]
async fn turn_stops_at_a_boundary_only_while_the_gate_is_up_and_after_an_attempt() {
    let (flag, gate, _wake) = flag_gate();
    let budget = MemBudget::new(100 * MIB);
    let held = budget
        .try_acquire(HolderKind::Worker, &SourceBlockId([1; 32]), 10 * MIB)
        .unwrap();
    fn turn<'a>(
        budget: &'a MemBudget,
        permit: &'a MemPermit,
        attempts: u32,
        gate: Option<&'a super::RestoreGate>,
    ) -> Turn<'a> {
        Turn {
            budget,
            permit,
            chunk_budget_bytes: 1024,
            holders_started: 1,
            attempts,
            restore_at_chunk: false,
            gate,
        }
    }
    let turn = |attempts, gate| turn(&budget, &held, attempts, gate);

    flag.store(true, Ordering::SeqCst);
    assert!(!turn(0, Some(&gate)).restore_wants_the_budget_at_a_chunk());
    assert!(turn(0, Some(&gate)).yield_before_next_holder().is_none());
    assert!(turn(1, Some(&gate)).restore_wants_the_budget_at_a_chunk());
    assert!(turn(1, Some(&gate)).yield_before_next_holder().is_some());
    assert!(!turn(1, None).restore_wants_the_budget_at_a_chunk());
    assert!(turn(1, None).yield_before_next_holder().is_none());
    flag.store(false, Ordering::SeqCst);
    assert!(!turn(1, Some(&gate)).restore_wants_the_budget_at_a_chunk());
    assert!(turn(1, Some(&gate)).yield_before_next_holder().is_none());
}

/// M95 (v3.12b WARN-1). A restore job starts while the worker WAITS for its permit: the moment it
/// is granted the turn gives it back — before the rebuild and the encode. Nothing is encoded,
/// nothing is offered, no holder is asked, the budget is whole again. Without the check after the
/// grant the turn rebuilds and encodes the block first.
#[tokio::test]
async fn job_started_while_the_worker_waits_for_its_permit_stops_it_before_encoding() {
    let (flag, gate, _wake) = flag_gate();
    let mut rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    rig.gate = Some(gate);
    let rec = retained(rig.data_dir.path(), 0x36, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let mut net = Net::new(0x6a).await;
    let holders = [
        net.holder(0x7c, &rig.budget, Hooks::default()).await,
        net.holder(0x7d, &rig.budget, Hooks::default()).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    let encodes = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&encodes);
    let encoder = SpyEncoder::spying(move |_| {
        counted.fetch_add(1, Ordering::SeqCst);
    });
    // Everything is taken: the worker waits for its permit.
    let everything = rig
        .budget
        .try_acquire(
            HolderKind::Pos,
            &SourceBlockId([1; 32]),
            YIELD_BUDGET_MIB * MIB,
        )
        .unwrap();
    let budget = Arc::clone(&rig.budget);
    let driver = async {
        until("the worker waits for its permit", || {
            budget.queued_waiters() == 1
        })
        .await;
        // The job starts now; then the memory comes free.
        flag.store(true, Ordering::SeqCst);
        drop(everything);
    };

    let pool = pool_of(&devices);
    let (outcome, ()) = tokio::join!(rig.turn(&encoder, &swarm, &rec, &pool, 0), driver);
    let outcome = outcome.unwrap();

    assert!(outcome.yielded && !outcome.encoded, "{outcome:?}");
    assert_eq!(outcome.offered, 0, "{outcome:?}");
    assert_eq!(encodes.load(Ordering::SeqCst), 0, "nothing was encoded");
    assert_eq!(offers_total(&holders), 0, "nobody was asked");
    assert!(placement_statuses(&rig.db, &rec.block_id).is_empty());
    assert_eq!(rig.budget.outstanding_bytes(), 0, "the permit is back");
}

/// M92, rewritten for the computed gate (v3.12b). With the gate up the worker starts no iteration
/// — nothing is picked, the block keeps no cooldown — and says so ONCE per pause; a second pause
/// gets its own line; when the gate comes down the next iteration works. With
/// `restore_pauses_backup = false` the gate is not looked at.
#[tokio::test]
async fn worker_does_not_start_while_the_restore_gate_is_up() {
    use super::tests::{add_pool_peers, device_id, lonely_swarm, pipeline_with, retained_block};

    let (logs, _guard) = capture_logs();
    let data_dir = tempfile::tempdir().unwrap();
    let db_a = db();
    let peers = [device_id(0xC1), device_id(0xC2)];
    add_pool_peers(&db_a, &peers);
    let rec = retained_block(data_dir.path(), 0xC3, 1.0);
    db_a.upsert_source_block(&rec).unwrap();
    let mut config = super::tests::make_config();
    config.data_dir = data_dir.path().to_path_buf();
    let (flag, gate, _wake) = flag_gate();
    let mut pipeline = pipeline_with(&db_a, config.clone(), Some(lonely_swarm(0x3f).await))
        .with_restore_gate(gate);

    flag.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        assert!(
            !pipeline.run_iteration().await.unwrap(),
            "paused: nothing picked"
        );
    }
    assert!(
        db_a.block_cooldown(&rec.block_id)
            .last_attempted_at
            .is_none(),
        "the block was not worked"
    );
    let text = logs.text();
    assert!(!text.contains("picked block for work"), "{text}");
    let paused = |t: &str| {
        t.lines()
            .filter(|l| l.contains("work_pipeline: paused while a restore job runs"))
            .count()
    };
    assert_eq!(paused(&text), 1, "once per pause:\n{text}");
    assert!(
        text.lines()
            .any(|l| l.contains("INFO") && l.contains("work_pipeline: paused while")),
        "{text}"
    );

    // The next pause gets its own line.
    flag.store(false, Ordering::SeqCst);
    assert!(
        pipeline.run_iteration().await.unwrap(),
        "the gate is down: works"
    );
    assert!(
        db_a.block_cooldown(&rec.block_id)
            .last_attempted_at
            .is_some()
    );
    db_a.clear_all_block_cooldowns();
    flag.store(true, Ordering::SeqCst);
    assert!(!pipeline.run_iteration().await.unwrap());
    assert_eq!(paused(&logs.text()), 2, "{}", logs.text());

    // (b): not paused at all.
    let db_b = db();
    add_pool_peers(&db_b, &peers);
    db_b.upsert_source_block(&rec).unwrap();
    let mut config_b = config;
    config_b.restore_pauses_backup = false;
    let (flag_b, gate_b, _wake_b) = flag_gate();
    flag_b.store(true, Ordering::SeqCst);
    let mut pipeline_b =
        pipeline_with(&db_b, config_b, Some(lonely_swarm(0x40).await)).with_restore_gate(gate_b);
    assert!(
        pipeline_b.run_iteration().await.unwrap(),
        "(b) works beside a restore"
    );
}

/// M96 (v3.12b WARN-2). The gate is what the registry of jobs says at every reading: any job
/// `Queued` or `Running` raises it; `finish` or `remove` of the last one lowers it, and the
/// RUNNING worker loop starts a turn at once (the wake), not at some later tick. The tick of the
/// loop is an hour here: a gate that `finish` does not lower leaves the block unworked until the
/// deadline of the `until` — the unit goes red, it does not hang.
#[tokio::test]
async fn backup_resumes_when_the_last_restore_job_finishes_or_is_removed() {
    use super::tests::{add_pool_peers, device_id, lonely_swarm, retained_block};
    use crate::daemon::restore::{jobs::RestoreJobs, staging::JobId};

    let staging = tempfile::tempdir().unwrap();
    let wake = super::new_gate_wake();
    let jobs = RestoreJobs::new(staging.path().to_path_buf()).with_gate_wake(Arc::clone(&wake));
    let gate = {
        let jobs = jobs.clone();
        super::RestoreGate::new(&wake, move || jobs.has_unfinished())
    };

    let data_dir = tempfile::tempdir().unwrap();
    let db = db();
    add_pool_peers(&db, &[device_id(0xC4), device_id(0xC5)]);
    let rec = retained_block(data_dir.path(), 0xC6, 1.0);
    db.upsert_source_block(&rec).unwrap();
    let mut config = super::tests::make_config();
    config.data_dir = data_dir.path().to_path_buf();
    config.tick_interval = Duration::from_secs(3600);
    let (_events_tx, events_rx) = tokio::sync::mpsc::channel(4);
    let pipeline = super::WorkPipeline::new(
        db.clone(),
        config,
        plain_encoder(),
        Some(lonely_swarm(0x41).await),
        None,
        None,
        None,
        events_rx,
    )
    .with_restore_gate(gate.clone());

    // submit -> the gate is up, the loop's first tick finds it so.
    let first = JobId::new();
    jobs.submit(first, "a", 1);
    assert!(gate.is_up(), "a queued job raises the gate");
    let worker = tokio::spawn(pipeline.run());
    let worked = || db.block_cooldown(&rec.block_id).last_attempted_at.is_some();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!worked(), "queued: the worker stands");

    // mark_running -> still up.
    jobs.mark_running(first, "a", 1);
    assert!(gate.is_up());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!worked(), "running: the worker stands");

    // finish -> down, the worker starts a turn.
    jobs.finish(first, false);
    assert!(!gate.is_up(), "the last job finished: the gate is down");
    until("the worker works after the last job finished", worked).await;

    // The second job: submit -> up; removed (never reached the coordinator) -> the worker goes on.
    db.clear_all_block_cooldowns();
    let second = JobId::new();
    jobs.submit(second, "b", 1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!worked(), "a second queued job: the worker stands");
    jobs.remove(second);
    assert!(!gate.is_up());
    until("the worker works after the last job was removed", worked).await;

    worker.abort();
}

/// M99 (v3.12b NOTE 1). A holder that has acknowledged its whole range has nothing left to send:
/// the turn turns the placement `Alive` WITHOUT a network call — no offer, no chunk — and counts
/// it acked.
#[tokio::test]
async fn empty_rest_turns_alive_without_network() {
    let rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    let rec = retained(rig.data_dir.path(), 0x37, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let mut net = Net::new(0x6b).await;
    let holders = [
        net.holder(0x7e, &rig.budget, Hooks::default()).await,
        net.holder(0x7f, &rig.budget, Hooks::default()).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    let pool = pool_of(&devices);
    // Every holder has acknowledged its whole range in an earlier turn.
    let plan = super::offer_plan::plan_offers(&rig.db, &rec, &pool.candidates, 0).unwrap();
    let super::offer_plan::OfferPlan::Planned { offers, .. } = plan else {
        panic!("stand: the plan has offers");
    };
    {
        let mut memory = rig.last_attempt.lock().await;
        for o in &offers {
            memory.holders.insert(
                o.device_id,
                worker::HolderDelivery {
                    acked: o.esi_ranges.clone(),
                    state: worker::HolderState::InProgress,
                },
            );
        }
    }

    let outcome = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool, 3)
        .await
        .unwrap();

    assert_eq!(outcome.acked, offers.len(), "{outcome:?}");
    assert_eq!((outcome.failed, outcome.yielded), (0, false), "{outcome:?}");
    assert_eq!(offers_total(&holders), 0, "no offer was sent");
    assert_eq!(transfers_total(&holders), 0, "no chunk was sent");
    assert_eq!(alive_count(&rig.db, &rec.block_id), offers.len());
}

/// M100 (v3.12b NOTE 2). `run_iteration` forgets the delivery memory of a block that left service
/// — the unit goes through the iteration, not through a direct call of the helper (a helper nobody
/// calls is dead code that only its own test keeps alive).
#[tokio::test]
async fn out_of_service_block_memory_is_forgotten_by_the_pipeline() {
    use super::tests::{block_id, device_id, lonely_swarm, pipeline_with};

    let db = db();
    let (gone, kept) = (block_id(0xB9), block_id(0xBA));
    let holder = device_id(0xBB);
    let mut leaving = super::tests::make_block_record(gone, 1.0, 0.99999);
    leaving.status = SourceBlockStatus::Deleting;
    db.upsert_source_block(&leaving).unwrap();
    let mut staying = super::tests::make_block_record(kept, 1.0, 0.99999);
    staying.status = SourceBlockStatus::Active;
    db.upsert_source_block(&staying).unwrap();

    let mut pipeline = pipeline_with(
        &db,
        super::tests::make_config(),
        Some(lonely_swarm(0x42).await),
    );
    for b in [gone, kept] {
        pipeline.yields.insert(b, 2);
        pipeline.last_attempt.insert(b, memory_of(holder));
    }

    pipeline.run_iteration().await.unwrap();

    assert!(
        !pipeline.last_attempt.contains_key(&gone) && !pipeline.yields.contains_key(&gone),
        "the iteration dropped the memory of the block that left service"
    );
}

/// M101 (v3.12b NOTE 4). What goes into `acked` is the ESIs of THIS chunk of THIS block. A holder
/// that answers `SymbolStored` with a range far wider than the chunk is acknowledged for the
/// chunk only (the memory ends up with exactly the ESIs that went out); one that answers for
/// ANOTHER block is acknowledged for nothing and the placement stays `Offered`.
#[tokio::test]
async fn acked_takes_only_this_block_and_the_chunk_esis() {
    // A wide answer; the gate cuts the turn after the first chunk, so the memory is not wiped by
    // an `Alive` and shows what the first answer was counted for.
    let (flag, gate, _wake) = flag_gate();
    let mut rig = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    rig.gate = Some(gate);
    let rec = retained(rig.data_dir.path(), 0x38, BIG_K, BIG_T);
    rig.db.upsert_source_block(&rec).unwrap();
    let wide_hooks = Hooks {
        stored_wide: true,
        on_first_transfer: Some(raise_gate(&flag)),
        ..Hooks::default()
    };
    let mut net = Net::new(0x6c).await;
    let holders = [
        net.holder(0x80, &rig.budget, wide_hooks.clone()).await,
        net.holder(0x81, &rig.budget, wide_hooks).await,
    ];
    let swarm = net.ready();
    let devices: Vec<DeviceId> = holders.iter().map(|h| h.device_id).collect();
    let outcome = rig
        .turn(&plain_encoder(), &swarm, &rec, &pool_of(&devices), 0)
        .await
        .unwrap();
    assert!(outcome.yielded, "{outcome:?}");
    let first = holders
        .iter()
        .find(|h| h.transfers() > 0)
        .expect("stand: one holder got the first chunk");
    let sent = first.esis();
    assert!(!sent.is_empty());
    let memory = rig.last_attempt.lock().await;
    let acked: Vec<u32> = memory
        .holders
        .get(&first.device_id)
        .expect("the holder is in progress")
        .acked
        .iter()
        .flat_map(|&(s, c)| s..s + c)
        .collect();
    assert_eq!(
        acked, sent,
        "acked = the ESIs of the chunk that went out, not the range of the answer"
    );
    drop(memory);

    // An answer for another block: nothing is acknowledged.
    let rig2 = Rig::new(YIELD_BUDGET_MIB, BIG_CHUNK);
    let rec2 = retained(rig2.data_dir.path(), 0x39, BIG_K, BIG_T);
    rig2.db.upsert_source_block(&rec2).unwrap();
    let mut net2 = Net::new(0x6d).await;
    let liar = net2
        .holder(
            0x82,
            &rig2.budget,
            Hooks {
                stored_names_block: Some(SourceBlockId([0x5A; 32])),
                ..Hooks::default()
            },
        )
        .await;
    let swarm2 = net2.ready();
    let outcome = rig2
        .turn(
            &plain_encoder(),
            &swarm2,
            &rec2,
            &pool_of(&[liar.device_id, DeviceId([0x83; 32])]),
            0,
        )
        .await
        .unwrap();
    let memory = rig2.last_attempt.lock().await;
    assert!(
        memory
            .holders
            .get(&liar.device_id)
            .is_none_or(|h| h.acked.is_empty()),
        "an answer for another block acknowledges nothing: {:?}",
        memory.holders.get(&liar.device_id)
    );
    assert_ne!(
        rig2.db
            .get_placement(&rec2.block_id, &liar.device_id)
            .unwrap()
            .map(|p| p.status),
        Some(PlacementStatus::Alive),
        "{outcome:?}"
    );
}
