// A DR's lease on a running node's block work budget (К-b3, restore-i39; spec v3.9a).
//
// `viaticum dr` on a machine where a node runs does not start a second budget from the same RAM:
// for each SS block of the catalog it asks the node for a lease (`DrLeases::lease`), decodes the
// block, and gives the lease back. The DR names the block and its encrypted size, never a number
// of bytes: the node sizes the lease itself (`estimate_restore_network` of the SS block's
// parameters, K clamped). The lease waits in the budget's queue as a restore waiter, so the
// worker and the batch of PoS checks yield to it as they do to a restore, and it stands in the
// log as `kind=dr`.
//
// A lease lives while its guard lives (the HTTP response of the lease request owns it: a dropped
// connection releases it) or until `release`; at the ceiling `max(H·P, 600 s)` of real time the
// node takes it back like a written-off holder (pos-i7-d-d): the bytes return to the budget, the
// count of "written off, still alive" (shared with the PoS write-off, at most one) keeps the
// overspend within one estimate, and the DR's next call answers `Revoked`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::task::AbortHandle;
use tokio::time::Instant;
use viaticum_core::types::{ErasureParams, SourceBlockId};

use super::{MIB, MemBudget, MemPermit, WriteOffHandle, estimate_restore_network};

/// The ceiling of a lease is `H` periods of the PoS tick, like the write-off of a stuck
/// preparation (pos-i7-d-d: `STUCK_PREPARATION_PERIODS`), ...
pub(super) const LEASE_HOLD_PERIODS: u32 = 10;

/// ... but not less than this, in REAL time (spec v3.6 WARN-4, `WRITE_OFF_MIN_REAL`): on a
/// time-scaled rig a lease that is merely slow must not be taken back.
pub(super) const LEASE_MIN_REAL: Duration = Duration::from_secs(600);

/// `max(H·P, 600 s)` for the PoS tick period `P` of this node.
pub fn lease_ceiling(period: Duration) -> Duration {
    (period * LEASE_HOLD_PERIODS).max(LEASE_MIN_REAL)
}

/// A lease that waits this long is named in the log.
const SLOW_AFTER: Duration = Duration::from_secs(5);

/// A revoke the shared write-off counter refused is tried again after this.
const REVOKE_RETRY: Duration = Duration::from_secs(5);

/// The beat of a lease response: a byte every so often, so that a dropped connection is noticed
/// by the failed write while the lease waits or is held.
pub(super) const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(5);

/// Why a lease was not given.
#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("the SS block size {0} has no erasure parameters: {1}")]
    BadSize(u64, String),
}

/// How a `release` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// The lease was held and its bytes are back.
    Released,
    /// The node had taken it back at the ceiling (the bytes were back already).
    Revoked,
    /// No such lease (released before, or never given).
    Unknown,
}

/// What `status` shows of the leases now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseStatus {
    pub holds_mib: u64,
    pub age_s: u64,
    /// The node took the lease back at its ceiling, and the DR's connection is still there: the
    /// bytes are the budget's again, but the DR still has them in its process (spec v3.9b N4).
    pub revoked: bool,
}

struct Entry {
    _permit: MemPermit,
    handle: WriteOffHandle,
    since: Instant,
    revoked: bool,
    watcher: AbortHandle,
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    leases: HashMap<u64, Entry>,
}

/// The leases a DR holds on this node's budget.
pub struct DrLeases {
    budget: Arc<MemBudget>,
    /// `max(H·P, 600 s)` of real time.
    ceiling: Duration,
    keepalive: Duration,
    inner: Mutex<Inner>,
}

/// A lease that is held: dropping it gives the bytes back.
pub struct LeaseGuard {
    leases: Arc<DrLeases>,
    id: u64,
}

impl LeaseGuard {
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        self.leases.release(self.id);
    }
}

enum Revoke {
    Done,
    Gone,
    Busy,
}

impl DrLeases {
    pub fn new(budget: Arc<MemBudget>, ceiling: Duration) -> Arc<Self> {
        Self::with_keepalive(budget, ceiling, DEFAULT_KEEPALIVE)
    }

    pub fn with_keepalive(
        budget: Arc<MemBudget>,
        ceiling: Duration,
        keepalive: Duration,
    ) -> Arc<Self> {
        Arc::new(DrLeases {
            budget,
            ceiling,
            keepalive,
            inner: Mutex::new(Inner::default()),
        })
    }

    pub fn keepalive(&self) -> Duration {
        self.keepalive
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What a lease for an SS block of `encrypted_size` bytes asks of the budget: the network
    /// restore estimate of the block's parameters (the DR cannot name a number, v3.9a).
    pub fn need_for(encrypted_size: u64) -> Result<u64, LeaseError> {
        let importance = crate::daemon::system_state::block::SYSTEM_STATE_IMPORTANCE;
        let params = ErasureParams::compute(encrypted_size, importance)
            .map_err(|e| LeaseError::BadSize(encrypted_size, e.to_string()))?;
        Ok(estimate_restore_network(params.k, params.t))
    }

    /// Wait for the budget (as a restore waiter, behind everybody queued) and take a lease for
    /// the SS block. Dropping the future leaves the queue.
    pub async fn lease(
        self: &Arc<Self>,
        block: SourceBlockId,
        encrypted_size: u64,
    ) -> Result<LeaseGuard, LeaseError> {
        let need = Self::need_for(encrypted_size)?;
        let mut permit = self
            .budget
            .acquire_dr_lease(&block, need, SLOW_AFTER, || {
                tracing::info!(
                    block = %block,
                    need_mib = need.min(self.budget.total_bytes()).div_ceil(MIB),
                    "mem_budget: a DR on this machine waits for a lease on the memory budget"
                );
            })
            .await;
        let handle = permit.write_off_handle();
        let mut inner = self.lock();
        inner.next_id += 1;
        let id = inner.next_id;
        let me = Arc::clone(self);
        let watcher = tokio::spawn(async move { me.watch_ceiling(id).await }).abort_handle();
        inner.leases.insert(
            id,
            Entry {
                _permit: permit,
                handle,
                since: Instant::now(),
                revoked: false,
                watcher,
            },
        );
        drop(inner);
        Ok(LeaseGuard {
            leases: Arc::clone(self),
            id,
        })
    }

    /// Give a lease back. A lease the ceiling took back answers `Revoked` (once).
    pub fn release(&self, id: u64) -> ReleaseOutcome {
        let entry = self.lock().leases.remove(&id);
        match entry {
            None => ReleaseOutcome::Unknown,
            Some(entry) => {
                entry.watcher.abort();
                let revoked = entry.revoked;
                // The permit goes here, outside our lock: a written-off permit forgets its
                // units, a live one returns them.
                drop(entry);
                if revoked {
                    ReleaseOutcome::Revoked
                } else {
                    ReleaseOutcome::Released
                }
            }
        }
    }

    /// The leases held now. A lease the ceiling took back stays here, marked `revoked`, while the
    /// DR's connection lives (its bytes are the budget's again, but the DR's process still
    /// has them, and the one place of the write-off is taken: spec v3.9b N4). Live leases show
    /// first; revoked ones when there is no live one.
    pub fn status(&self) -> Option<LeaseStatus> {
        let inner = self.lock();
        for revoked in [false, true] {
            let group: Vec<&Entry> = inner
                .leases
                .values()
                .filter(|e| e.revoked == revoked)
                .collect();
            let Some(age) = group.iter().map(|e| e.since.elapsed()).max() else {
                continue;
            };
            let holds: u64 = group.iter().map(|e| e.handle.bytes()).sum();
            return Some(LeaseStatus {
                holds_mib: holds / MIB,
                age_s: age.as_secs(),
                revoked,
            });
        }
        None
    }

    /// At the ceiling the lease is taken back like a written-off holder; the shared counter
    /// ("written off, still alive" ≤ 1) may refuse, and the revoke is tried again.
    async fn watch_ceiling(self: Arc<Self>, id: u64) {
        tokio::time::sleep(self.ceiling).await;
        loop {
            match self.revoke(id) {
                Revoke::Done | Revoke::Gone => return,
                Revoke::Busy => tokio::time::sleep(REVOKE_RETRY).await,
            }
        }
    }

    fn revoke(&self, id: u64) -> Revoke {
        let mut inner = self.lock();
        let Some(entry) = inner.leases.get_mut(&id) else {
            return Revoke::Gone;
        };
        if entry.revoked {
            return Revoke::Done;
        }
        let holds_mib = entry.handle.bytes() / MIB;
        let age_s = entry.since.elapsed().as_secs();
        if self.budget.write_off(&entry.handle).is_none() {
            return Revoke::Busy;
        }
        entry.revoked = true;
        tracing::warn!(
            held_by = %"dr-lease",
            holds_mib,
            age_s,
            "mem_budget: lease revoked"
        );
        Revoke::Done
    }
}
