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
// encode, while it delivers), restore and an overdue PoS preparation (`acquire_priority`:
// they are counted, so the worker can see them and yield, J13). A permit holder never takes a
// second permit (J12).
//
// Spec: private/beta-planning/tasks/r1_bigfile_refusal.md §2B.2, v3.2 V2, v3.3.

// The wrappers below are the only place in the daemon that calls the erasure entry points.
#![allow(clippy::disallowed_methods)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use viaticum_core::erasure::{ErasureEncoder, ErasureError, Symbol, SymbolSink};
use viaticum_core::types::{ErasureParams, SourceBlockId};

const MIB: u64 = 1 << 20;

/// Volumes of one block the encoder holds at the build stage: the source, the raptorq
/// source symbols' share, the intermediate symbols (≈ 1.03) and the plan (0.035) —
/// `3.1`, in hundredths (spec §1.3, frozen).
pub const ENCODE_BASE_X100: u64 = 310;
/// What delivery holds on top of the symbols and the copy of one share: the wire frame and its
/// CBOR copy.
pub const DELIVERY_SLACK_BYTES: u64 = 160 << 20;
/// `Vec` buffers per symbol a PoS preparation holds at a time: the raptorq symbol, the binding
/// buffer, the keystream (NOTE 2, v3.3: ≈ 3; one more as margin).
pub const POS_SYMBOL_BUFFERS: u64 = 4;

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

#[derive(Default)]
struct Waiters {
    next_id: u64,
    /// `(id, kind, need in MiB)` of every priority waiter now queued.
    queued: Vec<(u64, PriorityKind, u32)>,
}

/// Removes a waiter from the count when its wait ends: granted, or the future dropped.
struct WaiterGuard {
    budget: Arc<MemBudget>,
    id: u64,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        let mut w = self.budget.lock_waiters();
        w.queued.retain(|(id, _, _)| *id != self.id);
    }
}

// ─── The budget ───────────────────────────────────────────────────────────────

/// The one owner of "how much RAM block work may hold at once" (backup-i24, J8).
pub struct MemBudget {
    sem: Arc<Semaphore>,
    total_mib: u32,
    /// MiB held by live permits. Counts a grant only once the permit exists, so a unit the
    /// semaphore already assigned to a waiter that has not run yet still counts as free (the
    /// worker must not yield to a waiter its own shrink has just satisfied).
    held_mib: AtomicU64,
    waiters: Mutex<Waiters>,
    warned_over: AtomicBool,
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
            warned_over: AtomicBool::new(false),
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
    /// the total runs alone (clamped) with one WARN — refusing it would stop the work for good.
    fn permits_for(&self, estimate_bytes: u64, kind: HolderKind, block: &SourceBlockId) -> u32 {
        let mib = to_mib(estimate_bytes);
        if mib > self.total_mib as u64 {
            if !self.warned_over.swap(true, Ordering::Relaxed) {
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

    fn grant(
        self: &Arc<Self>,
        permit: OwnedSemaphorePermit,
        kind: HolderKind,
        block: &SourceBlockId,
        mib: u32,
    ) -> MemPermit {
        self.held_mib.fetch_add(mib as u64, Ordering::SeqCst);
        #[cfg(test)]
        self.grants.fetch_add(1, Ordering::SeqCst);
        tracing::debug!(
            kind = %kind.as_str(),
            block = %block,
            bytes = mib as u64 * MIB,
            "mem_budget: granted"
        );
        MemPermit {
            budget: Arc::clone(self),
            permit,
            kind,
            block: *block,
            mib,
        }
    }

    /// Waits for the permit, behind everybody already queued (FIFO). The caller holds no other
    /// permit (J12).
    pub async fn acquire(
        self: &Arc<Self>,
        kind: HolderKind,
        block: &SourceBlockId,
        estimate_bytes: u64,
    ) -> MemPermit {
        let mib = self.permits_for(estimate_bytes, kind, block);
        let permit = self.take(mib).await;
        self.grant(permit, kind, block, mib)
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
        Some(self.grant(permit, kind, block, mib))
    }

    async fn take(&self, mib: u32) -> OwnedSemaphorePermit {
        match Arc::clone(&self.sem).acquire_many_owned(mib).await {
            Ok(p) => p,
            // The semaphore is private and never closed.
            Err(_) => unreachable!("the memory budget semaphore is never closed"),
        }
    }

    /// Like `acquire`, but counted in [`priority_waiters`](Self::priority_waiters) while it waits
    /// (and forgotten on grant or when the future is dropped), so the worker can yield to it
    /// (J13). `on_slow` runs once if the wait outlasts `slow_after`. The caller holds no other
    /// permit (J12).
    pub async fn acquire_priority(
        self: &Arc<Self>,
        kind: PriorityKind,
        block: &SourceBlockId,
        estimate_bytes: u64,
        slow_after: Duration,
        on_slow: impl FnOnce(),
    ) -> MemPermit {
        let holder = kind.holder_kind();
        let mib = self.permits_for(estimate_bytes, holder, block);
        let guard = {
            let mut w = self.lock_waiters();
            w.next_id += 1;
            let id = w.next_id;
            w.queued.push((id, kind, mib));
            WaiterGuard {
                budget: Arc::clone(self),
                id,
            }
        };
        let taking = self.take(mib);
        tokio::pin!(taking);
        let permit = tokio::select! {
            p = &mut taking => p,
            _ = tokio::time::sleep(slow_after) => {
                on_slow();
                taking.await
            }
        };
        // The permit counts as held BEFORE the waiter stops counting: no moment shows a
        // waiter gone and its bytes free.
        let granted = self.grant(permit, holder, block, mib);
        drop(guard);
        granted
    }

    /// Priority waiters of `kind` queued now.
    pub fn priority_waiters(&self, kind: PriorityKind) -> usize {
        self.lock_waiters()
            .queued
            .iter()
            .filter(|(_, k, _)| *k == kind)
            .count()
    }

    /// The smallest need of the `kind` waiters queued now.
    pub fn min_need_bytes(&self, kind: PriorityKind) -> Option<u64> {
        self.lock_waiters()
            .queued
            .iter()
            .filter(|(_, k, _)| *k == kind)
            .map(|(_, _, need)| *need as u64 * MIB)
            .min()
    }

    /// A `kind` waiter is queued AND the free budget does not cover even the smallest need among
    /// them: only then does a holder's release help, and only then does the worker yield (NOTE 4).
    /// A waiter the holder's own shrink has just satisfied does not count: the free budget
    /// already covers it, even if its task has not run yet.
    pub fn priority_is_starved(&self, kind: PriorityKind) -> bool {
        match self.min_need_bytes(kind) {
            Some(need) => self.available_bytes() < need,
            None => false,
        }
    }

    /// Permits granted so far (tests: "the worker takes exactly one").
    #[cfg(test)]
    pub(crate) fn grants(&self) -> u64 {
        self.grants.load(Ordering::SeqCst)
    }

    /// Whether the over-budget WARN has been printed.
    #[cfg(test)]
    pub(crate) fn warned_over(&self) -> bool {
        self.warned_over.load(Ordering::Relaxed)
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
    permit: OwnedSemaphorePermit,
    kind: HolderKind,
    block: SourceBlockId,
    mib: u32,
}

impl MemPermit {
    pub fn bytes(&self) -> u64 {
        self.mib as u64 * MIB
    }

    pub fn kind(&self) -> HolderKind {
        self.kind
    }

    /// Release down to `keep_bytes` (whole MiB, rounded up, at least 1): the difference goes back
    /// to the budget and to whoever is queued. A no-op when the permit is already that small.
    pub fn shrink_to(&mut self, keep_bytes: u64) {
        let keep = to_mib(keep_bytes).min(self.mib as u64) as u32;
        let diff = self.mib - keep;
        if diff == 0 {
            return;
        }
        // Count the bytes free before the semaphore hands them to a waiter.
        self.budget
            .held_mib
            .fetch_sub(diff as u64, Ordering::SeqCst);
        if let Some(part) = self.permit.split(diff as usize) {
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

/// `3.1·E_pad` in bytes.
fn encode_base(e_pad: u64) -> u128 {
    e_pad as u128 * ENCODE_BASE_X100 as u128 / 100
}

/// The worker encoding one block: the encoder (3.1·E_pad), the `out_symbols` raw symbols it
/// returns (`out·T`) and the delivery slack.
pub fn estimate_worker(e_pad: u64, out_symbols: u64, t: u16) -> u64 {
    round_up_mib(
        encode_base(e_pad) + out_symbols as u128 * t as u128 + DELIVERY_SLACK_BYTES as u128,
    )
}

/// The worker delivering: the symbols (`out·T`), the copy of one share (≤ E_pad) and the slack.
/// The permit shrinks to this after the encode.
pub fn estimate_worker_delivery(e_pad: u64, out_symbols: u64, t: u16) -> u64 {
    round_up_mib(out_symbols as u128 * t as u128 + e_pad as u128 + DELIVERY_SLACK_BYTES as u128)
}

/// A PoS preparation: one encoder build (3.1·E_pad) and a few symbol buffers, whatever the number
/// of holders (F8′, NOTE 2).
pub fn estimate_pos_issue(e_pad: u64, t: u16) -> u64 {
    round_up_mib(encode_base(e_pad) + POS_SYMBOL_BUFFERS as u128 * t as u128)
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
