// The block work memory budget (backup-i24, J8): the one owner of "how much RAM block work
// may hold at once". Heavy block work (encode, decode) takes a permit sized by an estimate
// of its peak BEFORE the first big buffer and holds it until the last; a path without a
// permit does not compile (clippy `disallowed-methods` on the erasure calls; the wrappers
// below are the only callers).
//
// Units: the semaphore counts MiB, so a permit is a whole number of MiB and every estimate is
// rounded UP (a 0-byte `try_acquire` would pass a queue).
//
// Who waits: the worker (plain `acquire`, J12-ex: it keeps ONE permit, shrunk after the
// encode, while it delivers), restore and an overdue PoS preparation (`acquire_priority`).
// EVERY waiter stands in one list, in the order of the semaphore's queue (`Queued`): the
// worker reads it to decide whether to yield (`worker_must_yield`, J13). A permit holder never
// takes a second permit (J12).
//
// The order of the list equals the order of the semaphore because (1) a waiter is listed under
// our lock in the same critical section as its first poll of the tokio `Acquire` (tokio queues
// it on that poll), (2) the `Acquire` is polled inside `tokio::task::unconstrained`: with the
// cooperative budget spent it would answer `Pending` WITHOUT queueing, and the list and the
// queue would part, (3) the lock order is ours, then tokio's — nothing that holds tokio's takes
// ours (`MemPermit::drop` and `shrink_to` do not), (4) a waiter leaves the list under the same
// lock that grants it (`held` grows there) or that drops its `Acquire` (`Queued::drop`).
//
// Spec: private/beta-planning/tasks/r1_bigfile_refusal.md §2B.2, v3.2 V2, v3.3.

// The wrappers below are the only place in the daemon that calls the erasure entry points.
#![allow(clippy::disallowed_methods)]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use viaticum_core::constants::RAPTORQ_MAX_SOURCE_SYMBOLS;
use viaticum_core::erasure::{ErasureEncoder, ErasureError, Symbol, SymbolSink, encoder_bytes};
use viaticum_core::types::{ErasureParams, SourceBlockId};

pub use viaticum_core::erasure::POS_SYMBOL_BUFFERS;

const MIB: u64 = 1 << 20;

/// What delivery holds on top of the symbols and the copy of one share: the wire frame and its
/// CBOR copy.
pub const DELIVERY_SLACK_BYTES: u64 = 160 << 20;

// ─── Who holds / who waits ────────────────────────────────────────────────────

/// Whose permit it is (log `kind=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderKind {
    Worker,
    Pos,
    Restore,
    Dr,
}

impl HolderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            HolderKind::Worker => "worker",
            HolderKind::Pos => "pos",
            HolderKind::Restore => "restore",
            HolderKind::Dr => "dr",
        }
    }
}

/// Kinds of waiters the worker yields to (J13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityKind {
    /// A PoS preparation of a block the budget deferred for a whole tick (pos-i13).
    OverduePos,
    /// A restore job's decode.
    Restore,
}

impl PriorityKind {
    fn holder_kind(self) -> HolderKind {
        match self {
            PriorityKind::OverduePos => HolderKind::Pos,
            PriorityKind::Restore => HolderKind::Restore,
        }
    }
}

impl HolderKind {
    fn index(self) -> usize {
        match self {
            HolderKind::Worker => 0,
            HolderKind::Pos => 1,
            HolderKind::Restore => 2,
            HolderKind::Dr => 3,
        }
    }
}

/// Who a queued waiter is: a plain `acquire` (the worker; J12-ex) or a priority waiter the worker
/// yields to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitKind {
    Plain(HolderKind),
    Priority(PriorityKind),
}

/// One waiter in the list: `need_mib` is what it asks the semaphore for.
struct Waiter {
    id: u64,
    kind: WaitKind,
    need_mib: u32,
}

/// Every waiter in the semaphore's queue, in its order.
#[derive(Default)]
struct Waiters {
    next_id: u64,
    queued: Vec<Waiter>,
}

type AcquireFut = Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send>>;

/// A wait for the semaphore that is listed while it is queued (spec v3.5 WARN-1).
///
/// The first poll registers the waiter under our lock together with the poll of the tokio
/// `Acquire` (tokio queues it on that poll), so the list is in the semaphore's order. The grant
/// removes the entry and counts the bytes held under the same lock. Cancelling (drop) removes the
/// entry and drops the `Acquire` under the lock as well: `Acquire::drop` hands partly assigned
/// units to the next waiter at once, and an entry that outlived it would count a need whose units
/// are already somebody else's (a false yield). Lock order: ours, then the semaphore's.
struct Queued {
    budget: Arc<MemBudget>,
    kind: WaitKind,
    mib: u32,
    acquire: Option<AcquireFut>,
    /// `Some` while the entry is in the list. A granted `Queued` has `None`: its drop takes no
    /// lock.
    id: Option<u64>,
}

impl Queued {
    fn new(budget: &Arc<MemBudget>, kind: WaitKind, mib: u32) -> Queued {
        Queued {
            budget: Arc::clone(budget),
            kind,
            mib,
            acquire: None,
            id: None,
        }
    }

    /// Waiters queued ahead of this one now.
    fn ahead(&self) -> usize {
        let Some(id) = self.id else { return 0 };
        let w = self.budget.lock_waiters();
        w.queued.iter().position(|x| x.id == id).unwrap_or(0)
    }
}

impl Future for Queued {
    type Output = OwnedSemaphorePermit;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<OwnedSemaphorePermit> {
        let this = self.get_mut();
        let budget = Arc::clone(&this.budget);
        let mut w = budget.lock_waiters();
        let mib = this.mib;
        let acquire = this.acquire.get_or_insert_with(|| {
            // `unconstrained`: a spent cooperative budget would make `Acquire::poll` answer
            // `Pending` without queueing, and this entry would stand in the list without a place
            // in the semaphore's queue.
            Box::pin(tokio::task::unconstrained(
                Arc::clone(&budget.sem).acquire_many_owned(mib),
            ))
        });
        match acquire.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                if let Some(id) = this.id.take() {
                    w.queued.retain(|x| x.id != id);
                }
                budget.held_mib.fetch_add(mib as u64, Ordering::SeqCst);
                Poll::Ready(permit)
            }
            // The semaphore is private and never closed.
            Poll::Ready(Err(_)) => unreachable!("the memory budget semaphore is never closed"),
            Poll::Pending => {
                if this.id.is_none() {
                    w.next_id += 1;
                    let id = w.next_id;
                    w.queued.push(Waiter {
                        id,
                        kind: this.kind,
                        need_mib: mib,
                    });
                    this.id = Some(id);
                }
                Poll::Pending
            }
        }
    }
}

impl Drop for Queued {
    fn drop(&mut self) {
        // Only a cancelled waiter is still in the list.
        if let Some(id) = self.id.take() {
            let mut w = self.budget.lock_waiters();
            w.queued.retain(|x| x.id != id);
            // Under the lock, after the `retain` (WARN-1 b).
            drop(self.acquire.take());
            drop(w);
        }
    }
}

// ─── The budget ───────────────────────────────────────────────────────────────

/// The one owner of "how much RAM block work may hold at once" (backup-i24, J8).
pub struct MemBudget {
    sem: Arc<Semaphore>,
    total_mib: u32,
    /// MiB held by live permits. Counts a grant only once the permit exists, so a unit the
    /// semaphore already assigned to a waiter that has not run yet still counts as free.
    held_mib: AtomicU64,
    waiters: Mutex<Waiters>,
    /// The over-budget WARN was printed, per kind of holder (N7): the worker's WARN does not hide
    /// the first WARN of a restore.
    warned_over: [AtomicBool; 4],
    /// Permits written off (pos-i7-d-d) whose holder has not ended yet.
    written_off_live: AtomicUsize,
    #[cfg(test)]
    grants: AtomicU64,
}

impl MemBudget {
    /// A budget of `total_bytes` (whole MiB, at least 1).
    pub fn new(total_bytes: u64) -> Arc<Self> {
        let total_mib = (total_bytes / MIB).clamp(1, u32::MAX as u64) as u32;
        Arc::new(MemBudget {
            sem: Arc::new(Semaphore::new(total_mib as usize)),
            total_mib,
            held_mib: AtomicU64::new(0),
            waiters: Mutex::new(Waiters::default()),
            warned_over: [const { AtomicBool::new(false) }; 4],
            written_off_live: AtomicUsize::new(0),
            #[cfg(test)]
            grants: AtomicU64::new(0),
        })
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_mib as u64 * MIB
    }

    /// Bytes held by live permits.
    pub fn outstanding_bytes(&self) -> u64 {
        self.held_mib.load(Ordering::SeqCst) * MIB
    }

    /// `total − outstanding`: what a new permit could take if nobody were queued.
    pub fn available_bytes(&self) -> u64 {
        self.total_bytes().saturating_sub(self.outstanding_bytes())
    }

    fn lock_waiters(&self) -> std::sync::MutexGuard<'_, Waiters> {
        // A poisoned lock only means a panic elsewhere; the list of waiters is still valid.
        self.waiters.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Permits for `estimate_bytes`: whole MiB, at least 1, at most the total. An estimate above
    /// the total runs alone (clamped) with one WARN per kind of holder — refusing it would stop
    /// the work for good.
    fn permits_for(&self, estimate_bytes: u64, kind: HolderKind, block: &SourceBlockId) -> u32 {
        let mib = to_mib(estimate_bytes);
        if mib > self.total_mib as u64 {
            if !self.warned_over[kind.index()].swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    kind = %kind.as_str(),
                    block = %block,
                    estimate_mib = mib,
                    budget_mib = self.total_mib,
                    "mem_budget: block work exceeds the memory budget; it runs alone"
                );
            }
            return self.total_mib;
        }
        mib as u32
    }

    /// The permit for units already counted as held (the queued path counts them under the lock
    /// that removes the waiter from the list).
    fn permit_counted(
        self: &Arc<Self>,
        permit: OwnedSemaphorePermit,
        kind: HolderKind,
        block: &SourceBlockId,
        mib: u32,
        waited: Duration,
    ) -> MemPermit {
        #[cfg(test)]
        self.grants.fetch_add(1, Ordering::SeqCst);
        tracing::debug!(
            kind = %kind.as_str(),
            block = %block,
            bytes = mib as u64 * MIB,
            waited_ms = waited.as_millis() as u64,
            "mem_budget: granted"
        );
        MemPermit {
            budget: Arc::clone(self),
            permit: Some(permit),
            kind,
            block: *block,
            mib,
            shared: None,
        }
    }

    /// Waits for the permit, behind everybody already queued (FIFO). `on_slow(queued_ahead)` runs
    /// once if the wait outlasts `slow_after`. The caller holds no other permit (J12).
    pub async fn acquire(
        self: &Arc<Self>,
        kind: HolderKind,
        block: &SourceBlockId,
        estimate_bytes: u64,
        slow_after: Duration,
        on_slow: impl FnOnce(usize),
    ) -> MemPermit {
        self.wait(
            WaitKind::Plain(kind),
            kind,
            block,
            estimate_bytes,
            slow_after,
            on_slow,
        )
        .await
    }

    /// Never waits; `None` when the budget is busy. Does not pass a queue: while somebody waits,
    /// released units go to the head of the queue first (A12-b).
    pub fn try_acquire(
        self: &Arc<Self>,
        kind: HolderKind,
        block: &SourceBlockId,
        estimate_bytes: u64,
    ) -> Option<MemPermit> {
        let mib = self.permits_for(estimate_bytes, kind, block);
        let permit = Arc::clone(&self.sem).try_acquire_many_owned(mib).ok()?;
        self.held_mib.fetch_add(mib as u64, Ordering::SeqCst);
        Some(self.permit_counted(permit, kind, block, mib, Duration::ZERO))
    }

    /// The one path into the semaphore's queue (B1): plain and priority waiters alike stand in the
    /// list while they wait.
    async fn wait(
        self: &Arc<Self>,
        wait_kind: WaitKind,
        holder: HolderKind,
        block: &SourceBlockId,
        estimate_bytes: u64,
        slow_after: Duration,
        on_slow: impl FnOnce(usize),
    ) -> MemPermit {
        let started = Instant::now();
        let mib = self.permits_for(estimate_bytes, holder, block);
        let queued = Queued::new(self, wait_kind, mib);
        tokio::pin!(queued);
        let permit = tokio::select! {
            p = &mut queued => p,
            _ = tokio::time::sleep(slow_after) => {
                on_slow(queued.ahead());
                queued.await
            }
        };
        self.permit_counted(permit, holder, block, mib, started.elapsed())
    }

    /// Like `acquire`, but the waiter is one the worker yields to while it is queued (J13); it
    /// leaves the list on grant or when the future is dropped. `on_slow` runs once if the wait
    /// outlasts `slow_after`. The caller holds no other permit (J12).
    pub async fn acquire_priority(
        self: &Arc<Self>,
        kind: PriorityKind,
        block: &SourceBlockId,
        estimate_bytes: u64,
        slow_after: Duration,
        on_slow: impl FnOnce(),
    ) -> MemPermit {
        self.wait(
            WaitKind::Priority(kind),
            kind.holder_kind(),
            block,
            estimate_bytes,
            slow_after,
            move |_ahead| on_slow(),
        )
        .await
    }

    /// Callers waiting in the queue now, of any kind (the DEBUG line of a deferred PoS block).
    pub fn queued_waiters(&self) -> usize {
        self.lock_waiters().queued.len()
    }

    /// Priority waiters of `kind` queued now.
    pub fn priority_waiters(&self, kind: PriorityKind) -> usize {
        self.lock_waiters()
            .queued
            .iter()
            .filter(|x| x.kind == WaitKind::Priority(kind))
            .count()
    }

    /// Whether the worker, holding `permit` (after its shrink), must give the budget to a waiter
    /// of `kind` (J13, rule (Б′) of the spec v3.5): some `kind` waiter has, at or before it in the
    /// queue, a need that does not fit beside the worker EVER — `max need(1..i) > total − W`.
    /// Everyone else releases by himself (J14), so a waiter whose prefix fits beside the worker is
    /// served without a yield; the bytes held now do not enter the rule.
    pub fn worker_must_yield(&self, kind: PriorityKind, permit: &MemPermit) -> bool {
        let fits_beside_worker = self.total_mib.saturating_sub(permit.mib);
        let w = self.lock_waiters();
        debug_assert!(
            !w.queued
                .iter()
                .any(|x| x.kind == WaitKind::Plain(HolderKind::Worker)),
            "A4: a worker waits for the budget while another worker holds a permit"
        );
        let mut prefix_max = 0u32;
        for x in &w.queued {
            prefix_max = prefix_max.max(x.need_mib);
            if x.kind == WaitKind::Priority(kind) && prefix_max > fits_beside_worker {
                return true;
            }
        }
        false
    }

    /// Write a stuck holder's permit off (pos-i7-d-d, variant (a)): its bytes go back to the budget
    /// now, while the holder still runs, and will not be returned a second time when it ends. At
    /// most one permit is written off at a time — the overspend is bounded by one estimate. `None`
    /// when another written-off holder has not ended yet, or this permit is already gone or
    /// written off. Returns the bytes given back.
    pub fn write_off(&self, handle: &WriteOffHandle) -> Option<u64> {
        if self.written_off_live.fetch_add(1, Ordering::SeqCst) >= 1 {
            self.written_off_live.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        if handle
            .shared
            .state
            .compare_exchange(LIVE, WRITTEN_OFF, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            self.written_off_live.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        // The state flag is ours now: the holder's drop will only forget its semaphore units.
        // `held` shrinks and the units reach the semaphore (and its first waiter) under the lock
        // that also grants waiters, so no waiter is granted between the two halves.
        {
            let _queue = self.lock_waiters();
            self.held_mib.fetch_sub(handle.mib as u64, Ordering::SeqCst);
            self.sem.add_permits(handle.mib as usize);
        }
        tracing::debug!(
            kind = %handle.kind.as_str(),
            block = %handle.block,
            bytes = handle.mib as u64 * MIB,
            "mem_budget: released (written off)"
        );
        Some(handle.mib as u64 * MIB)
    }

    /// `acquire` without the slow-wait line (tests).
    #[cfg(test)]
    pub(crate) async fn acquire_plain(
        self: &Arc<Self>,
        kind: HolderKind,
        block: &SourceBlockId,
        estimate_bytes: u64,
    ) -> MemPermit {
        self.acquire(
            kind,
            block,
            estimate_bytes,
            Duration::from_secs(3600),
            |_| {},
        )
        .await
    }

    /// The needs (MiB) of the queued waiters, in the list's order (tests).
    #[cfg(test)]
    pub(crate) fn queued_needs_mib(&self) -> Vec<u32> {
        self.lock_waiters()
            .queued
            .iter()
            .map(|x| x.need_mib)
            .collect()
    }

    /// Units the semaphore itself has free (tests: nothing is returned twice).
    #[cfg(test)]
    pub(crate) fn semaphore_free_bytes(&self) -> u64 {
        self.sem.available_permits() as u64 * MIB
    }

    /// Permits granted so far (tests: "the worker takes exactly one").
    #[cfg(test)]
    pub(crate) fn grants(&self) -> u64 {
        self.grants.load(Ordering::SeqCst)
    }

    /// Whether the over-budget WARN of this kind of holder has been printed.
    #[cfg(test)]
    pub(crate) fn warned_over(&self, kind: HolderKind) -> bool {
        self.warned_over[kind.index()].load(Ordering::Relaxed)
    }
}

/// Whole MiB, rounded up, at least 1.
fn to_mib(bytes: u64) -> u64 {
    bytes.div_ceil(MIB).max(1)
}

// ─── The permit ───────────────────────────────────────────────────────────────

/// The right to hold `bytes()` of RAM for block work. Dropping it gives the bytes back.
pub struct MemPermit {
    budget: Arc<MemBudget>,
    /// `None` only inside `drop`.
    permit: Option<OwnedSemaphorePermit>,
    kind: HolderKind,
    block: SourceBlockId,
    mib: u32,
    /// Set by [`write_off_handle`](Self::write_off_handle): the state another thread may change.
    shared: Option<Arc<PermitShared>>,
}

/// State of a permit that can be written off: live, written off by [`MemBudget::write_off`], or
/// dropped by its holder. The one atomic decides who returns the bytes.
struct PermitShared {
    state: AtomicU8,
}

const LIVE: u8 = 0;
const WRITTEN_OFF: u8 = 1;
const DROPPED: u8 = 2;

/// What a watcher needs to write a permit off while its holder runs (see
/// [`MemBudget::write_off`]).
pub struct WriteOffHandle {
    shared: Arc<PermitShared>,
    kind: HolderKind,
    block: SourceBlockId,
    mib: u32,
}

impl WriteOffHandle {
    pub fn kind(&self) -> HolderKind {
        self.kind
    }

    pub fn bytes(&self) -> u64 {
        self.mib as u64 * MIB
    }
}

impl MemPermit {
    pub fn bytes(&self) -> u64 {
        self.mib as u64 * MIB
    }

    pub fn kind(&self) -> HolderKind {
        self.kind
    }

    /// A handle to write this permit off from another thread (pos-i7-d-d). Taken on a permit that
    /// is not shrunk afterwards: the handle keeps the size it saw.
    pub fn write_off_handle(&mut self) -> WriteOffHandle {
        let shared = Arc::clone(self.shared.get_or_insert_with(|| {
            Arc::new(PermitShared {
                state: AtomicU8::new(LIVE),
            })
        }));
        WriteOffHandle {
            shared,
            kind: self.kind,
            block: self.block,
            mib: self.mib,
        }
    }

    /// Release down to `keep_bytes` (whole MiB, rounded up, at least 1): the difference goes back
    /// to the budget and to whoever is queued. A no-op when the permit is already that small.
    pub fn shrink_to(&mut self, keep_bytes: u64) {
        let keep = to_mib(keep_bytes).min(self.mib as u64) as u32;
        let diff = self.mib - keep;
        if diff == 0 {
            return;
        }
        debug_assert!(
            self.shared.is_none(),
            "a permit with a write-off handle is not shrunk"
        );
        // Count the bytes free before the semaphore hands them to a waiter.
        self.budget
            .held_mib
            .fetch_sub(diff as u64, Ordering::SeqCst);
        if let Some(part) = self.permit.as_mut().and_then(|p| p.split(diff as usize)) {
            drop(part);
        }
        self.mib = keep;
        tracing::debug!(
            kind = %self.kind.as_str(),
            block = %self.block,
            bytes = diff as u64 * MIB,
            kept_bytes = keep as u64 * MIB,
            "mem_budget: released (shrunk)"
        );
    }
}

impl Drop for MemPermit {
    fn drop(&mut self) {
        if let Some(shared) = &self.shared
            && shared.state.swap(DROPPED, Ordering::SeqCst) == WRITTEN_OFF
        {
            // Written off while its holder ran: the budget already took the bytes back and
            // counted them free. Forget the semaphore units instead of returning them twice.
            if let Some(p) = self.permit.take() {
                p.forget();
            }
            self.budget.written_off_live.fetch_sub(1, Ordering::SeqCst);
            tracing::debug!(
                kind = %self.kind.as_str(),
                block = %self.block,
                bytes = self.mib as u64 * MIB,
                "mem_budget: released (holder ended after a write-off; nothing returned)"
            );
            return;
        }
        self.budget
            .held_mib
            .fetch_sub(self.mib as u64, Ordering::SeqCst);
        tracing::debug!(
            kind = %self.kind.as_str(),
            block = %self.block,
            bytes = self.mib as u64 * MIB,
            "mem_budget: released"
        );
        // `self.permit` drops after this body and gives the units back to the semaphore.
    }
}

// ─── Erasure entry points (the only ones in the daemon, J8) ──────────────────

/// Encode the raw (unbound) symbols of `ranges` with ONE encoder build; `padded` is the block
/// padded to `k·t` (`pad_for_encoding`).
pub fn encode_block(
    _permit: &MemPermit,
    enc: &dyn ErasureEncoder,
    padded: &[u8],
    params: &ErasureParams,
    ranges: &[(u32, u32)],
) -> Result<Vec<Symbol>, ErasureError> {
    enc.encode_raw_ranges(padded, params, ranges)
}

/// The same walk, each raw symbol handed to `f` and dropped (F8′): the peak does not grow with
/// the number of symbols. `ranges` ascending and disjoint.
pub fn encode_ranges_each(
    _permit: &MemPermit,
    enc: &dyn ErasureEncoder,
    padded: &[u8],
    params: &ErasureParams,
    ranges: &[(u32, u32)],
    f: &mut SymbolSink<'_>,
) -> Result<(), ErasureError> {
    enc.encode_raw_ranges_each(padded, params, ranges, f)
}

/// Decode a block from unbound symbols.
pub fn decode_block(
    _permit: &MemPermit,
    enc: &dyn ErasureEncoder,
    symbols: &[Symbol],
    params: &ErasureParams,
) -> Result<Vec<u8>, ErasureError> {
    enc.decode(symbols, params)
}

// ─── Estimates (peak bytes, rounded up to whole MiB, at least 1 MiB) ─────────

fn round_up_mib(bytes: u128) -> u64 {
    let mib = bytes.div_ceil(MIB as u128).max(1);
    (mib.min(u64::MAX as u128 / MIB as u128) as u64) * MIB
}

/// What the encoder holds beyond its input: `encoder_bytes` of the core (K source-symbol copies,
/// `L(K)` intermediate symbols from the RFC 6330 table, the plan). A K the encoder refuses
/// (above the RaptorQ limit) is clamped: it fails at once, before it allocates, and an estimate
/// must not panic on it.
fn encoder_held(k: u32, t: u16) -> u128 {
    encoder_bytes(k.min(RAPTORQ_MAX_SOURCE_SYMBOLS), t) as u128
}

/// The worker encoding one block (spec v3.4 N1): the input (`k·t`, padded in place), the encoder
/// (`encoder_bytes`), the `out_symbols` raw symbols it returns (`out·(T + σ)`, σ = the `Symbol`
/// struct), the packet `repair_packets` hands out (`T`) and the delivery slack.
pub fn estimate_worker(k: u32, t: u16, out_symbols: u64) -> u64 {
    round_up_mib(
        k as u128 * t as u128
            + encoder_held(k, t)
            + out_symbols as u128 * (t as u128 + std::mem::size_of::<Symbol>() as u128)
            + t as u128
            + DELIVERY_SLACK_BYTES as u128,
    )
}

/// The worker delivering: the symbols (`out·T`), the copy of one share (≤ E_pad) and the slack.
/// The permit shrinks to this after the encode.
pub fn estimate_worker_delivery(e_pad: u64, out_symbols: u64, t: u16) -> u64 {
    round_up_mib(out_symbols as u128 * t as u128 + e_pad as u128 + DELIVERY_SLACK_BYTES as u128)
}

/// A PoS preparation: the input, one encoder build (`encoder_bytes`) and a few symbol buffers,
/// whatever the number of holders (F8′, NOTE 2).
pub fn estimate_pos_issue(k: u32, t: u16) -> u64 {
    round_up_mib(
        k as u128 * t as u128 + encoder_held(k, t) + POS_SYMBOL_BUFFERS as u128 * t as u128,
    )
}

/// Restore from the network: the fetched symbols, the decoder's copy and work area, the output,
/// and the decryption — `5·E_pad`.
pub fn estimate_restore_network(e_pad: u64) -> u64 {
    round_up_mib(e_pad as u128 * 5)
}

/// Restore from the local source: the rebuilt blob (`E_pad`) and the decrypted and compressed
/// copy (≈ E_pad) plus the plaintext `s` — `2·E_pad + S`. A caller that does not know the
/// plaintext size passes an upper bound (zstd's `decode_all` may grow its buffer to twice S).
pub fn estimate_restore_local(e_pad: u64, s: u64) -> u64 {
    round_up_mib(e_pad as u128 * 2 + s as u128)
}

/// The block work budget of a machine with `ram_limit_bytes` of RAM: `M·14/32`.
pub fn block_work_budget_bytes(ram_limit_bytes: u64) -> u64 {
    (ram_limit_bytes as u128 * 14 / 32) as u64
}

/// The environment variable a test sets to a budget in MiB (the E2E emulates a small machine's
/// budget on a big server; it cannot emulate memory pressure).
pub const TEST_BUDGET_ENV: &str = "VIATICUM_TEST_BLOCK_WORK_BUDGET_MB";

/// The budget of this daemon run: `test_override_mb` (the value of [`TEST_BUDGET_ENV`]) when it is a
/// positive number of MiB, with a WARN saying so; else [`block_work_budget_bytes`] of `ram`.
pub fn resolve_block_work_budget(ram_bytes: u64, test_override_mb: Option<&str>) -> u64 {
    if let Some(text) = test_override_mb {
        match text.trim().parse::<u64>() {
            Ok(mb) if mb > 0 => {
                tracing::warn!(
                    budget_mib = mb,
                    "memory: block work budget set by {TEST_BUDGET_ENV} (test only)"
                );
                return mb.saturating_mul(MIB);
            }
            _ => tracing::warn!(
                value = text,
                "memory: {TEST_BUDGET_ENV} is not a positive number of MiB; ignored"
            ),
        }
    }
    block_work_budget_bytes(ram_bytes)
}

#[cfg(test)]
mod tests;
