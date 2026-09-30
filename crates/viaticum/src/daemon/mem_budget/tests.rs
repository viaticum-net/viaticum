// MemBudget tests: the budget itself, the permit, the estimates, the wrappers.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder};
use viaticum_core::types::{ErasureParams, SourceBlockId};

use super::*;

const MIB: u64 = 1 << 20;

fn block(byte: u8) -> SourceBlockId {
    SourceBlockId([byte; 32])
}

/// Wait (with a deadline) until `cond` holds.
async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Let spawned tasks run and settle.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(60)).await;
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

/// Run `f` and return what it logged at DEBUG and above (this thread only).
fn logged(f: impl FnOnce()) -> String {
    let buf = LogBuf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    f();
    drop(guard);
    String::from_utf8(buf.0.lock().unwrap().clone()).unwrap()
}

// ─── Numbers ──────────────────────────────────────────────────────────────────

#[test]
fn block_work_budget_is_fourteen_thirty_seconds_of_the_ram() {
    assert_eq!(block_work_budget_bytes(32 << 30), 14 << 30);
    assert_eq!(block_work_budget_bytes(0), 0);
    // The §1.1 machine: 7.6 GiB of RAM → 3.3 GiB.
    let m = 8_160_437_862; // 7.6 GiB
    let g = block_work_budget_bytes(m);
    assert_eq!(g, m / 32 * 14 + (m % 32) * 14 / 32);
    assert!(
        (3.32..3.34).contains(&(g as f64 / (1u64 << 30) as f64)),
        "{g}"
    );
    // Nothing overflows on a huge machine.
    assert_eq!(
        block_work_budget_bytes(u64::MAX),
        (u64::MAX as u128 * 14 / 32) as u64
    );
}

#[test]
fn estimate_functions_match_model() {
    // A 200 MiB block (t = 1024 → 204 800 symbols to the block), R = 6 (1 228 800 symbols out).
    let e = 200 * MIB;
    let t = 1024u16;
    let out = 6 * (e / t as u64);
    // 3.1·200 + 6·200 + 160 = 1980 MiB; (R + 1)·E + 160 = 1560 MiB (§1.1).
    assert_eq!(estimate_worker(e, out, t), 1980 * MIB);
    assert_eq!(estimate_worker_delivery(e, out, t), 1560 * MIB);
    // 5·E.
    assert_eq!(estimate_restore_network(e), 1000 * MIB);
    // 2·E + S.
    assert_eq!(estimate_restore_local(e, 180 * MIB), 580 * MIB);
    // A PoS preparation of a 240 MiB block: 3.1·240 = 744 MiB + 4·T → 745 MiB (spec v3.2 V6).
    assert_eq!(estimate_pos_issue(240 * MIB, 65535), 745 * MIB);
    // It does not grow with anything but the block.
    assert_eq!(
        estimate_pos_issue(240 * MIB, 65535),
        estimate_pos_issue(240 * MIB, 65535)
    );
    // The worker shrinks: delivery never needs more than the encode (R ≥ 0).
    assert!(estimate_worker_delivery(e, out, t) < estimate_worker(e, out, t));
}

#[test]
fn estimates_round_up_and_are_at_least_one_mib() {
    // Every estimate is a whole number of MiB, never 0 (a 0-byte try_acquire would pass a queue).
    assert_eq!(estimate_pos_issue(0, 0), MIB);
    assert_eq!(estimate_restore_network(0), MIB);
    assert_eq!(estimate_restore_local(0, 0), MIB);
    assert_eq!(estimate_restore_network(1), MIB);
    // One byte over a MiB boundary → the next MiB.
    assert_eq!(estimate_restore_network(MIB / 5 + 1), 2 * MIB);
    assert_eq!(estimate_restore_network(MIB / 5), MIB);
    // The worker's slack alone is 160 MiB.
    assert_eq!(estimate_worker(0, 0, 1024), 160 * MIB);
    assert_eq!(estimate_worker(1, 1, 1), 161 * MIB);
    for v in [
        estimate_worker(12_345, 7, 1024),
        estimate_worker_delivery(12_345, 7, 1024),
        estimate_pos_issue(12_345, 1024),
        estimate_restore_network(12_345),
        estimate_restore_local(12_345, 999),
    ] {
        assert_eq!(v % MIB, 0);
        assert!(v >= MIB);
    }
    // Huge inputs saturate instead of overflowing.
    assert!(estimate_worker(u64::MAX, u64::MAX, u16::MAX) >= u64::MAX / 2);
}

// ─── The budget ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn mem_budget_try_acquire_fails_when_busy_and_succeeds_after_release() {
    let budget = MemBudget::new(10 * MIB);
    assert_eq!(budget.total_bytes(), 10 * MIB);
    let a = budget
        .try_acquire(HolderKind::Pos, &block(1), 6 * MIB)
        .unwrap();
    assert_eq!(a.bytes(), 6 * MIB);
    assert_eq!(budget.outstanding_bytes(), 6 * MIB);
    assert_eq!(budget.available_bytes(), 4 * MIB);
    assert!(
        budget
            .try_acquire(HolderKind::Pos, &block(2), 5 * MIB)
            .is_none(),
        "busy: 5 MiB do not fit beside 6 MiB of 10"
    );
    let b = budget.try_acquire(HolderKind::Pos, &block(3), 4 * MIB);
    assert!(b.is_some(), "4 MiB still fit");
    drop(b);
    drop(a);
    assert_eq!(budget.outstanding_bytes(), 0);
    assert!(
        budget
            .try_acquire(HolderKind::Pos, &block(2), 5 * MIB)
            .is_some()
    );
}

#[test]
fn mem_budget_estimate_above_total_is_clamped_and_warns_once() {
    let budget = MemBudget::new(64 * MIB);
    let logs = logged(|| {
        let p = budget
            .try_acquire(HolderKind::Worker, &block(1), 100 * MIB)
            .expect("an idle budget runs an oversized estimate alone");
        assert_eq!(p.bytes(), 64 * MIB, "clamped to the total");
        assert!(
            budget
                .try_acquire(HolderKind::Pos, &block(2), MIB)
                .is_none(),
            "alone"
        );
        drop(p);
        let p = budget
            .try_acquire(HolderKind::Worker, &block(1), 200 * MIB)
            .unwrap();
        assert_eq!(p.bytes(), 64 * MIB);
    });
    let warns = logs
        .lines()
        .filter(|l| l.contains("WARN") && l.contains("exceeds the memory budget"))
        .count();
    assert_eq!(
        warns, 1,
        "one WARN for the budget, not one per permit: {logs}"
    );
    assert!(budget.warned_over());
    // An estimate within the total does not warn.
    let quiet = MemBudget::new(64 * MIB);
    let logs = logged(|| {
        let _p = quiet
            .try_acquire(HolderKind::Worker, &block(1), 64 * MIB)
            .unwrap();
    });
    assert!(!logs.contains("WARN"), "{logs}");
    assert!(!quiet.warned_over());
}

#[tokio::test]
async fn mem_budget_worker_acquire_waits_fifo() {
    let budget = MemBudget::new(10 * MIB);
    let holder = budget.acquire(HolderKind::Worker, &block(1), 6 * MIB).await;
    let order = Arc::new(Mutex::new(Vec::new()));

    // B needs 6 MiB (4 free: queued), C needs 2 MiB — it would fit into the 4 free, but B is ahead.
    let spawn_waiter = |tag: &'static str, bytes: u64| {
        let budget = Arc::clone(&budget);
        let order = Arc::clone(&order);
        tokio::spawn(async move {
            let p = budget.acquire(HolderKind::Pos, &block(9), bytes).await;
            order.lock().unwrap().push(tag);
            p
        })
    };
    let b = spawn_waiter("b", 6 * MIB);
    settle().await;
    let c = spawn_waiter("c", 2 * MIB);
    settle().await;
    assert!(
        order.lock().unwrap().is_empty(),
        "nobody is served while the holder holds"
    );

    drop(holder);
    let pb = b.await.unwrap();
    let pc = c.await.unwrap();
    assert_eq!(*order.lock().unwrap(), vec!["b", "c"], "FIFO");
    drop((pb, pc));
    assert_eq!(budget.outstanding_bytes(), 0);
}

#[tokio::test]
async fn try_acquire_fails_while_a_larger_waiter_is_queued() {
    // A12-b: the units the holder releases go to the head of the queue first; a small
    // try_acquire does not pass it even when bytes look free.
    let budget = MemBudget::new(10 * MIB);
    let holder = budget
        .try_acquire(HolderKind::Worker, &block(1), 8 * MIB)
        .unwrap();
    let waiter = {
        let budget = Arc::clone(&budget);
        tokio::spawn(async move { budget.acquire(HolderKind::Pos, &block(2), 6 * MIB).await })
    };
    settle().await;
    assert_eq!(
        budget.available_bytes(),
        2 * MIB,
        "2 MiB are not held by any permit"
    );
    assert!(
        budget
            .try_acquire(HolderKind::Pos, &block(3), MIB)
            .is_none(),
        "the queue head takes the free units first"
    );
    drop(holder);
    let granted = waiter.await.unwrap();
    assert_eq!(granted.bytes(), 6 * MIB);
    assert!(
        budget
            .try_acquire(HolderKind::Pos, &block(3), 4 * MIB)
            .is_some()
    );
}

// ─── The permit ───────────────────────────────────────────────────────────────

#[test]
fn mem_permit_shrink_releases_the_difference() {
    let budget = MemBudget::new(10 * MIB);
    let mut p = budget
        .try_acquire(HolderKind::Worker, &block(1), 8 * MIB)
        .unwrap();
    assert!(
        budget
            .try_acquire(HolderKind::Pos, &block(2), 3 * MIB)
            .is_none()
    );

    p.shrink_to(3 * MIB);
    assert_eq!(p.bytes(), 3 * MIB);
    assert_eq!(budget.outstanding_bytes(), 3 * MIB);
    assert_eq!(budget.available_bytes(), 7 * MIB);
    let q = budget.try_acquire(HolderKind::Pos, &block(2), 7 * MIB);
    assert!(q.is_some(), "the released 5 MiB are really free");
    drop(q);

    // Growing is not shrinking: a no-op.
    p.shrink_to(9 * MIB);
    assert_eq!(p.bytes(), 3 * MIB);
    // A partial MiB rounds up; 0 keeps one MiB.
    p.shrink_to(2 * MIB + 1);
    assert_eq!(p.bytes(), 3 * MIB);
    p.shrink_to(0);
    assert_eq!(p.bytes(), MIB);
    assert_eq!(budget.outstanding_bytes(), MIB);
    drop(p);
    assert_eq!(budget.outstanding_bytes(), 0);
    assert_eq!(budget.available_bytes(), 10 * MIB);
}

#[test]
fn granted_and_released_lines_carry_kind_block_and_bytes() {
    let budget = MemBudget::new(100 * MIB);
    let logs = logged(|| {
        let mut p = budget
            .try_acquire(HolderKind::Worker, &block(0xab), 40 * MIB)
            .unwrap();
        p.shrink_to(10 * MIB);
        drop(p);
    });
    let b = block(0xab).to_string();
    let granted = format!(
        "mem_budget: granted kind=worker block={b} bytes={}",
        40 * MIB
    );
    let shrunk = format!(
        "mem_budget: released (shrunk) kind=worker block={b} bytes={}",
        30 * MIB
    );
    let released = format!(
        "mem_budget: released kind=worker block={b} bytes={}",
        10 * MIB
    );
    for line in [&granted, &shrunk, &released] {
        assert!(logs.contains(line.as_str()), "missing `{line}` in:\n{logs}");
    }
    assert!(logs.lines().all(|l| !l.contains("WARN")), "{logs}");
}

// ─── Priority waiters ─────────────────────────────────────────────────────────

fn slow() -> Duration {
    Duration::from_secs(3600)
}

#[tokio::test]
async fn priority_waiters_are_counted_while_they_wait_and_forgotten_on_grant_or_cancel() {
    let budget = MemBudget::new(10 * MIB);
    let holder = budget
        .try_acquire(HolderKind::Worker, &block(1), 9 * MIB)
        .unwrap();
    assert_eq!(budget.priority_waiters(PriorityKind::OverduePos), 0);
    assert_eq!(budget.min_need_bytes(PriorityKind::OverduePos), None);

    let waiter = |kind, bytes| {
        let budget = Arc::clone(&budget);
        tokio::spawn(async move {
            budget
                .acquire_priority(kind, &block(2), bytes, slow(), || {})
                .await
        })
    };
    let w1 = waiter(PriorityKind::OverduePos, 5 * MIB);
    let w2 = waiter(PriorityKind::OverduePos, 3 * MIB);
    let w3 = waiter(PriorityKind::Restore, 4 * MIB);
    settle().await;
    assert_eq!(budget.priority_waiters(PriorityKind::OverduePos), 2);
    assert_eq!(budget.priority_waiters(PriorityKind::Restore), 1);
    assert_eq!(
        budget.min_need_bytes(PriorityKind::OverduePos),
        Some(3 * MIB)
    );
    assert_eq!(budget.min_need_bytes(PriorityKind::Restore), Some(4 * MIB));

    // Cancelled: the drop guard takes it out of the count.
    w2.abort();
    let _ = w2.await;
    assert_eq!(budget.priority_waiters(PriorityKind::OverduePos), 1);
    assert_eq!(
        budget.min_need_bytes(PriorityKind::OverduePos),
        Some(5 * MIB)
    );

    // Granted: out of the count, and the permit is a Pos / Restore one.
    drop(holder);
    let p1 = w1.await.unwrap();
    assert_eq!(p1.kind(), HolderKind::Pos);
    assert_eq!(budget.priority_waiters(PriorityKind::OverduePos), 0);
    drop(p1);
    let p3 = w3.await.unwrap();
    assert_eq!(p3.kind(), HolderKind::Restore);
    assert_eq!(budget.priority_waiters(PriorityKind::Restore), 0);
}

#[tokio::test]
async fn priority_is_starved_only_while_the_free_budget_is_below_the_smallest_need() {
    let budget = MemBudget::new(10 * MIB);
    assert!(
        !budget.priority_is_starved(PriorityKind::OverduePos),
        "nobody waits"
    );
    let mut holder = budget
        .try_acquire(HolderKind::Worker, &block(1), 9 * MIB)
        .unwrap();
    let waiter = {
        let budget = Arc::clone(&budget);
        tokio::spawn(async move {
            budget
                .acquire_priority(PriorityKind::OverduePos, &block(2), 5 * MIB, slow(), || {})
                .await
        })
    };
    settle().await;
    assert_eq!(budget.priority_waiters(PriorityKind::OverduePos), 1);
    assert!(
        budget.priority_is_starved(PriorityKind::OverduePos),
        "1 MiB free < 5 MiB needed"
    );
    assert!(
        !budget.priority_is_starved(PriorityKind::Restore),
        "another kind"
    );

    // The holder's own shrink covers the waiter's need. Its task has not run yet, so the count
    // still says 1 — but the worker must not yield to it: NOTE 4 of the spec.
    holder.shrink_to(4 * MIB);
    assert_eq!(budget.priority_waiters(PriorityKind::OverduePos), 1);
    assert!(
        !budget.priority_is_starved(PriorityKind::OverduePos),
        "6 MiB free ≥ 5 MiB: a waiter granted by the shrink is not starved"
    );
    let granted = waiter.await.unwrap();
    assert_eq!(granted.bytes(), 5 * MIB);
    assert_eq!(budget.priority_waiters(PriorityKind::OverduePos), 0);
    // Free 1 MiB of 10 — nobody waits, so nobody is starved.
    assert!(!budget.priority_is_starved(PriorityKind::OverduePos));
}

#[tokio::test]
async fn acquire_priority_calls_on_slow_once_after_the_wait_outlasts_the_limit() {
    let budget = MemBudget::new(4 * MIB);
    let holder = budget
        .try_acquire(HolderKind::Worker, &block(1), 4 * MIB)
        .unwrap();
    let calls = Arc::new(Mutex::new(0u32));
    let waiter = {
        let (budget, calls) = (Arc::clone(&budget), Arc::clone(&calls));
        tokio::spawn(async move {
            budget
                .acquire_priority(
                    PriorityKind::Restore,
                    &block(2),
                    3 * MIB,
                    Duration::from_millis(30),
                    move || *calls.lock().unwrap() += 1,
                )
                .await
        })
    };
    until("on_slow", || *calls.lock().unwrap() == 1).await;
    settle().await;
    assert_eq!(*calls.lock().unwrap(), 1, "once, not once per period");
    assert!(!waiter.is_finished());
    drop(holder);
    let _ = waiter.await.unwrap();
    assert_eq!(*calls.lock().unwrap(), 1);

    // A wait that ends before the limit never calls it.
    let quick = Arc::new(Mutex::new(0u32));
    let q = Arc::clone(&quick);
    let _p = budget
        .acquire_priority(PriorityKind::Restore, &block(3), MIB, slow(), move || {
            *q.lock().unwrap() += 1
        })
        .await;
    assert_eq!(*quick.lock().unwrap(), 0);
}

// ─── Wrappers ─────────────────────────────────────────────────────────────────

#[test]
fn erasure_wrappers_encode_and_decode_like_the_encoder() {
    let budget = MemBudget::new(64 * MIB);
    let permit = budget
        .try_acquire(HolderKind::Worker, &block(1), MIB)
        .unwrap();
    let enc = RaptorQEncoder::new();
    let (k, t) = (8u32, 64u16);
    let params = ErasureParams {
        k,
        k_eff: k + viaticum_core::constants::DECODE_OVERHEAD,
        t,
        overhead: 1.5,
        n: 16,
    };
    let data: Vec<u8> = (0..(k as usize * t as usize))
        .map(|i| (i * 7) as u8)
        .collect();

    let ranges = [(0u32, 4u32), (10, 6)];
    let symbols = encode_block(&permit, &enc, &data, &params, &ranges).unwrap();
    assert_eq!(
        symbols,
        enc.encode_raw_ranges(&data, &params, &ranges).unwrap()
    );
    assert_eq!(symbols.len(), 10);

    let mut each = Vec::new();
    encode_ranges_each(&permit, &enc, &data, &params, &ranges, &mut |esi, bytes| {
        each.push((esi, bytes.to_vec()));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        each,
        symbols
            .iter()
            .map(|s| (s.esi, s.data.clone()))
            .collect::<Vec<_>>()
    );

    let all = encode_block(&permit, &enc, &data, &params, &[(0, params.k_eff)]).unwrap();
    let decoded = decode_block(&permit, &enc, &all, &params).unwrap();
    assert_eq!(decoded, data);
}

// ─── The budget of a daemon run ──────────────────────────────────────────────

#[test]
fn test_env_sets_the_budget_with_a_warn_and_garbage_is_ignored() {
    let ram = 8u64 << 30;
    let auto = block_work_budget_bytes(ram);

    let logs = logged(|| assert_eq!(resolve_block_work_budget(ram, None), auto));
    assert!(!logs.contains("WARN"), "{logs}");

    let logs = logged(|| assert_eq!(resolve_block_work_budget(ram, Some(" 1792 ")), 1792 * MIB));
    let warn = logs
        .lines()
        .find(|l| l.contains("WARN"))
        .unwrap_or_else(|| panic!("the override is announced: {logs}"));
    assert!(warn.contains("VIATICUM_TEST_BLOCK_WORK_BUDGET_MB") && warn.contains("(test only)"));

    for bad in ["", "0", "abc", "-5", "1.5"] {
        let logs = logged(|| assert_eq!(resolve_block_work_budget(ram, Some(bad)), auto));
        assert!(
            logs.contains("WARN") && logs.contains("ignored"),
            "`{bad}`: {logs}"
        );
    }
}

// ─── Queue count and write-off (R1-d-b, pos-i7-d-d) ──────────────────────────

#[tokio::test]
async fn queued_waiters_counts_only_callers_waiting_in_the_queue() {
    let budget = MemBudget::new(4 * MIB);
    assert_eq!(budget.queued_waiters(), 0);
    let hold = budget.acquire(HolderKind::Worker, &block(1), 4 * MIB).await;
    assert_eq!(budget.queued_waiters(), 0, "a grant at once is not a wait");
    let waiter = {
        let budget = Arc::clone(&budget);
        tokio::spawn(async move { budget.acquire(HolderKind::Pos, &block(2), MIB).await })
    };
    until("the waiter queues", || budget.queued_waiters() == 1).await;
    drop(hold);
    let granted = waiter.await.unwrap();
    assert_eq!(budget.queued_waiters(), 0);
    drop(granted);

    // A cancelled wait leaves the count.
    let hold = budget.acquire(HolderKind::Worker, &block(1), 4 * MIB).await;
    let cancelled = {
        let budget = Arc::clone(&budget);
        tokio::spawn(async move { budget.acquire(HolderKind::Pos, &block(3), MIB).await })
    };
    until("it queues", || budget.queued_waiters() == 1).await;
    cancelled.abort();
    let _ = cancelled.await;
    assert_eq!(budget.queued_waiters(), 0);
    drop(hold);
}

#[test]
fn written_off_permit_gives_its_bytes_back_once_and_the_holder_returns_nothing_more() {
    let budget = MemBudget::new(10 * MIB);
    let mut stuck = budget
        .try_acquire(HolderKind::Pos, &block(1), 6 * MIB)
        .unwrap();
    let handle = stuck.write_off_handle();
    assert_eq!(handle.bytes(), 6 * MIB);
    assert_eq!(budget.outstanding_bytes(), 6 * MIB);

    let text = logged(|| {
        assert_eq!(budget.write_off(&handle), Some(6 * MIB));
    });
    assert!(text.contains("released (written off)"), "{text}");
    assert_eq!(budget.outstanding_bytes(), 0);
    assert_eq!(budget.available_bytes(), 10 * MIB);
    assert_eq!(budget.semaphore_free_bytes(), 10 * MIB);
    // The bytes serve another holder now.
    let other = budget
        .try_acquire(HolderKind::Restore, &block(2), 10 * MIB)
        .expect("the written-off bytes are free");
    assert_eq!(budget.write_off(&handle), None, "not written off twice");

    // The stuck holder finally ends: nothing goes back a second time.
    drop(stuck);
    assert_eq!(budget.outstanding_bytes(), 10 * MIB, "the other holder's");
    assert_eq!(budget.semaphore_free_bytes(), 0, "no units returned twice");
    drop(other);
    assert_eq!(budget.semaphore_free_bytes(), 10 * MIB);
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// The overspend of a write-off is one holder's permit: a second stuck holder is not written off
/// until the first one has ended.
#[test]
fn at_most_one_holder_is_written_off() {
    let budget = MemBudget::new(10 * MIB);
    let mut a = budget
        .try_acquire(HolderKind::Pos, &block(1), 3 * MIB)
        .unwrap();
    let mut b = budget
        .try_acquire(HolderKind::Pos, &block(2), 3 * MIB)
        .unwrap();
    let (ha, hb) = (a.write_off_handle(), b.write_off_handle());

    assert_eq!(budget.write_off(&ha), Some(3 * MIB));
    assert_eq!(budget.write_off(&hb), None, "one at a time");
    assert_eq!(budget.outstanding_bytes(), 3 * MIB, "b still counts");

    drop(a);
    assert_eq!(budget.write_off(&hb), Some(3 * MIB), "the first has ended");
    assert_eq!(budget.outstanding_bytes(), 0);
    drop(b);
    assert_eq!(budget.semaphore_free_bytes(), 10 * MIB);
}

#[test]
fn a_permit_that_ended_cannot_be_written_off() {
    let budget = MemBudget::new(10 * MIB);
    let mut p = budget
        .try_acquire(HolderKind::Pos, &block(1), 3 * MIB)
        .unwrap();
    let handle = p.write_off_handle();
    drop(p);
    assert_eq!(budget.write_off(&handle), None);
    assert_eq!(budget.semaphore_free_bytes(), 10 * MIB);
    assert_eq!(budget.outstanding_bytes(), 0);
    // And it did not use up the one write-off the budget allows.
    let mut q = budget
        .try_acquire(HolderKind::Pos, &block(2), 3 * MIB)
        .unwrap();
    assert_eq!(budget.write_off(&q.write_off_handle()), Some(3 * MIB));
}
