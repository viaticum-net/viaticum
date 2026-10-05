// Tests of the DR's lease on the node's budget (К-b3, restore-i39; spec v3.9a): the node's side.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use viaticum_core::types::{ErasureParams, SourceBlockId};

use super::*;

fn block(byte: u8) -> SourceBlockId {
    SourceBlockId([byte; 32])
}

/// An SS block of 16 MiB: K = 257.
const SS_SIZE: u64 = 16 * MIB;

/// What the node's budget must be asked for an SS block of `size` bytes: the network restore
/// estimate of its parameters.
fn need_of(size: u64) -> u64 {
    let p = ErasureParams::compute(size, 1.0).unwrap();
    estimate_restore_network(p.k, p.t)
}

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

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

/// Log from now on, on this thread, at DEBUG and above (a current-thread runtime runs every
/// task here); the guard ends it.
fn capture() -> (tracing::subscriber::DefaultGuard, LogBuf) {
    let buf = LogBuf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    (tracing::subscriber::set_default(subscriber), buf)
}

impl LogBuf {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// M68: the lease waits in the budget's queue as a restore waiter — the worker (and the batch of
/// PoS checks) yield to it by the rule of a restore (Б′), and `status` of the queue counts it.
#[tokio::test]
async fn budget_lease_is_a_restore_priority_waiter() {
    let need = need_of(SS_SIZE);
    let budget = MemBudget::new(need + MIB);
    // 2 MiB held: `need − 1 MiB` is free, the lease cannot start.
    let held = budget
        .try_acquire(HolderKind::Pos, &block(1), 2 * MIB)
        .unwrap();
    let leases = DrLeases::new(Arc::clone(&budget), Duration::from_secs(3600));
    let waiting = Arc::clone(&leases);
    let task = tokio::spawn(async move { waiting.lease(block(2), SS_SIZE).await });

    until("the lease queues as a restore waiter", || {
        budget.priority_waiters(PriorityKind::Restore) == 1
    })
    .await;
    assert_eq!(budget.queued_needs_mib(), vec![(need / MIB) as u32]);
    assert!(
        budget.worker_must_yield(PriorityKind::Restore, &held),
        "the holder next to a lease that does not fit beside it yields"
    );

    drop(held);
    let guard = task.await.unwrap().expect("the lease is granted");
    assert_eq!(budget.outstanding_bytes(), need);
    assert_eq!(budget.priority_waiters(PriorityKind::Restore), 0);
    drop(guard);
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// The lease stands in the log as `kind=dr`, and a waiting one says so.
#[tokio::test]
async fn budget_lease_stands_in_the_log_as_kind_dr() {
    let (_guard, logs) = capture();
    let budget = MemBudget::new(1 << 30);
    let leases = DrLeases::new(Arc::clone(&budget), Duration::from_secs(3600));
    let lease = leases.lease(block(1), SS_SIZE).await.unwrap();
    assert!(
        logs.text().contains("mem_budget: granted kind=dr"),
        "{}",
        logs.text()
    );
    drop(lease);
}

/// M72: the node sizes the lease itself — the network restore estimate of the SS block's
/// parameters. The request has no number of bytes, and a block no one could code is refused.
#[tokio::test]
async fn dr_lease_need_is_the_ss_block_estimate() {
    let budget = MemBudget::new(1 << 30);
    let leases = DrLeases::new(Arc::clone(&budget), Duration::from_secs(3600));
    for size in [1_000_000u64, SS_SIZE, 100 * MIB] {
        let guard = leases.lease(block(3), size).await.unwrap();
        assert_eq!(budget.outstanding_bytes(), need_of(size), "size {size}");
        assert_eq!(leases.status().unwrap().holds_mib, need_of(size) / MIB);
        drop(guard);
    }
    assert_eq!(DrLeases::need_for(SS_SIZE).unwrap(), need_of(SS_SIZE));
    // K above the RaptorQ limit: refused, nothing taken.
    assert!(matches!(
        leases.lease(block(4), 100 << 30).await,
        Err(LeaseError::BadSize(..))
    ));
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// M70: past `max(H·P, 600 s)` of real time the node takes the lease back like a written-off
/// holder: the bytes return, `status` shows it as revoked, a WARN names it, and the DR's next call
/// (`release`) answers `Revoked`.
#[tokio::test(start_paused = true)]
async fn dr_lease_is_revoked_after_the_ceiling_with_warn() {
    let (_guard, logs) = capture();
    let budget = MemBudget::new(1 << 30);
    let leases = DrLeases::new(Arc::clone(&budget), Duration::from_secs(600));
    let guard = leases.lease(block(1), SS_SIZE).await.unwrap();
    let id = guard.id();

    tokio::time::sleep(Duration::from_secs(599)).await;
    assert_eq!(
        budget.outstanding_bytes(),
        need_of(SS_SIZE),
        "held below the ceiling"
    );
    assert!(leases.status().is_some());
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(budget.outstanding_bytes(), 0, "taken back at the ceiling");
    assert!(leases.status().is_some_and(|s| s.revoked));
    let text = logs.text();
    assert!(
        text.contains("mem_budget: lease revoked held_by=dr-lease holds_mib="),
        "{text}"
    );
    assert!(text.contains("age_s=600"), "{text}");

    assert_eq!(leases.release(id), ReleaseOutcome::Revoked);
    assert_eq!(leases.release(id), ReleaseOutcome::Unknown);
    assert!(leases.status().is_none(), "released: gone from status");
    drop(guard);
    assert_eq!(
        budget.semaphore_free_bytes(),
        1 << 30,
        "nothing is returned twice"
    );
}

/// M76 (spec v3.9b N4): a lease the node took back stays in `status`, marked revoked, while the
/// DR's connection is open — its memory is real in the DR's process and the one place of the
/// write-off is taken; it leaves with the connection.
#[tokio::test(start_paused = true)]
async fn revoked_lease_stays_in_status_until_the_connection_closes() {
    let budget = MemBudget::new(1 << 30);
    let leases = DrLeases::new(Arc::clone(&budget), Duration::from_secs(600));
    let guard = leases.lease(block(1), SS_SIZE).await.unwrap();
    assert!(leases.status().is_some_and(|s| !s.revoked));

    tokio::time::sleep(Duration::from_secs(700)).await;
    assert_eq!(budget.outstanding_bytes(), 0, "the bytes are the budget's");
    let status = leases.status().expect("the revoked lease is still shown");
    assert!(status.revoked);
    assert_eq!(status.holds_mib, need_of(SS_SIZE) / MIB);
    assert_eq!(status.age_s, 700);

    drop(guard);
    assert!(leases.status().is_none(), "the connection is closed");
}

/// The revoke is a write-off: at most one holder written off and still alive, shared with the PoS
/// write-off (v3.9a #2). While another one lives, the lease stays and the revoke is tried again.
#[tokio::test(start_paused = true)]
async fn dr_lease_revoke_waits_while_another_written_off_holder_lives() {
    let budget = MemBudget::new(1 << 30);
    let mut stuck = budget
        .try_acquire(HolderKind::Pos, &block(9), 8 * MIB)
        .unwrap();
    let handle = stuck.write_off_handle();
    assert_eq!(budget.write_off(&handle), Some(8 * MIB));

    let leases = DrLeases::new(Arc::clone(&budget), Duration::from_secs(600));
    let guard = leases.lease(block(1), SS_SIZE).await.unwrap();
    tokio::time::sleep(Duration::from_secs(700)).await;
    assert_eq!(
        budget.outstanding_bytes(),
        need_of(SS_SIZE),
        "the counter is taken: the lease is not revoked"
    );

    drop(stuck);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(
        budget.outstanding_bytes(),
        0,
        "revoked once the counter is free"
    );
    drop(guard);
}

/// `status` shows what is held and how long.
#[tokio::test(start_paused = true)]
async fn dr_lease_status_shows_holds_and_age() {
    let budget = MemBudget::new(1 << 30);
    let leases = DrLeases::new(Arc::clone(&budget), Duration::from_secs(3600));
    assert!(leases.status().is_none());
    let guard = leases.lease(block(1), SS_SIZE).await.unwrap();
    tokio::time::sleep(Duration::from_secs(42)).await;
    let status = leases.status().unwrap();
    assert_eq!(status.holds_mib, need_of(SS_SIZE) / MIB);
    assert_eq!(status.age_s, 42);
    drop(guard);
    assert!(leases.status().is_none());
}

/// A lease request that is dropped while it waits leaves the queue.
#[tokio::test]
async fn budget_lease_that_is_dropped_while_waiting_leaves_the_queue() {
    let need = need_of(SS_SIZE);
    let budget = MemBudget::new(need);
    let held = budget
        .try_acquire(HolderKind::Worker, &block(1), MIB)
        .unwrap();
    let leases = DrLeases::new(Arc::clone(&budget), Duration::from_secs(3600));
    let waiting = Arc::clone(&leases);
    let task = tokio::spawn(async move { waiting.lease(block(2), SS_SIZE).await.ok() });
    until("it queues", || {
        budget.priority_waiters(PriorityKind::Restore) == 1
    })
    .await;
    task.abort();
    until("it leaves", || {
        budget.priority_waiters(PriorityKind::Restore) == 0
    })
    .await;
    drop(held);
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// M97 (v3.12b WARN-3, Q-V9 (a)). A DR session on this node's budget raises the backup worker's
/// gate: from the first lease request (even one that still waits for the memory) until 30 s of
/// REAL time after the last lease was given back or dropped — the pause between two SS blocks
/// does not let the worker start. The clock is the runtime's, paused here. The wake fires when the
/// window runs out. Without the session in the gate (a lease that raises nothing) the first
/// assertion after the request fails.
#[tokio::test(start_paused = true)]
async fn dr_lease_session_pauses_the_worker_and_releases_it_30s_after_the_last_lease() {
    use crate::daemon::work_pipeline::{RestoreGate, new_gate_wake};

    let wake = new_gate_wake();
    let need = need_of(SS_SIZE);
    let budget = MemBudget::new(need + MIB);
    let leases = DrLeases::with_gate_wake(
        Arc::clone(&budget),
        Duration::from_secs(3600),
        Arc::clone(&wake),
    );
    let gate = {
        let leases = Arc::clone(&leases);
        RestoreGate::new(&wake, move || leases.session_active())
    };
    let mut woken = wake.subscribe();
    let linger = Duration::from_secs(30);
    assert!(!gate.is_up(), "no DR: the gate is down");

    // A request that waits for the memory is already the session.
    let held = budget
        .try_acquire(HolderKind::Pos, &block(1), 2 * MIB)
        .unwrap();
    let waiting = Arc::clone(&leases);
    let task = tokio::spawn(async move { waiting.lease(block(2), SS_SIZE).await });
    until("the lease queues", || {
        budget.priority_waiters(PriorityKind::Restore) == 1
    })
    .await;
    assert!(gate.is_up(), "the first lease request raises the gate");
    assert!(woken.has_changed().unwrap(), "and wakes the worker");
    drop(held);
    let first = task.await.unwrap().expect("granted");
    assert!(gate.is_up());

    // The lease is given back: the window keeps the gate up for 30 s.
    drop(first);
    tokio::time::advance(linger - Duration::from_secs(1)).await;
    assert!(gate.is_up(), "29 s after the last lease: still up");
    // The DR fetches the next SS block and leases again: one session, the window starts afresh.
    let second = leases.lease(block(3), SS_SIZE).await.unwrap();
    tokio::time::advance(Duration::from_secs(120)).await;
    assert!(gate.is_up(), "a lease held for minutes keeps the gate up");
    drop(second);
    woken.borrow_and_update();
    tokio::time::advance(linger - Duration::from_secs(1)).await;
    assert!(gate.is_up(), "29 s after the last lease: up");
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!gate.is_up(), "30 s after the last lease: down");
    // Let the timer of the window run: it wakes the worker.
    tokio::task::yield_now().await;
    assert!(
        woken.has_changed().unwrap(),
        "the worker is woken when the window runs out"
    );

    // A DR that gives up while its request waits leaves the session the same way.
    let held = budget
        .try_acquire(HolderKind::Pos, &block(1), 2 * MIB)
        .unwrap();
    let waiting = Arc::clone(&leases);
    let task = tokio::spawn(async move { waiting.lease(block(4), SS_SIZE).await });
    until("the lease queues again", || {
        budget.priority_waiters(PriorityKind::Restore) == 1
    })
    .await;
    assert!(gate.is_up());
    task.abort();
    let _ = task.await;
    tokio::time::advance(Duration::from_secs(29)).await;
    assert!(gate.is_up(), "a dropped request: the window runs");
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!gate.is_up());
    drop(held);
}

/// K-b2a^5 NOTE 3. A lease the ceiling took back does not hold the backup pause: a hung DR whose
/// stream stays open (the revoked lease stays in `leases` while the connection lives) would
/// otherwise keep the gate up for ever. The session ends with the revoke — after the 30 s window
/// like any last lease — although the guard is still held, and the worker is woken when the window
/// runs out. Counting the revoked lease in `session_active` leaves the gate up: the unit fails at
/// the last assertion.
#[tokio::test(start_paused = true)]
async fn revoked_lease_does_not_hold_the_session() {
    use crate::daemon::work_pipeline::new_gate_wake;

    let wake = new_gate_wake();
    let mut woken = wake.subscribe();
    let budget = MemBudget::new(1 << 30);
    let leases = DrLeases::with_gate_wake(
        Arc::clone(&budget),
        Duration::from_secs(600),
        Arc::clone(&wake),
    );
    let guard = leases.lease(block(1), SS_SIZE).await.unwrap();
    assert!(leases.session_active(), "a live lease: the session is on");

    tokio::time::sleep(Duration::from_secs(590)).await;
    assert!(leases.session_active(), "below the ceiling: on");
    tokio::time::sleep(Duration::from_secs(11)).await;
    assert!(leases.status().is_some_and(|s| s.revoked), "stand: revoked");
    assert!(
        leases.session_active(),
        "the window of the last lease runs from the revoke"
    );
    woken.borrow_and_update();

    tokio::time::sleep(Duration::from_secs(40)).await;
    assert!(
        leases.status().is_some_and(|s| s.revoked),
        "the revoked lease is still held by the open connection"
    );
    assert!(
        !leases.session_active(),
        "a revoked lease does not hold the session"
    );
    assert!(woken.has_changed().unwrap(), "the worker was woken");
    drop(guard);
}
