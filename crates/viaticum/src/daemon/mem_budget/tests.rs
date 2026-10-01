// MemBudget tests: the budget itself, the permit, the estimates, the wrappers.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use viaticum_core::erasure::{ErasureEncoder, RaptorQEncoder, encoder_bytes, intermediate_symbols};
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
    // The estimates are functions of K (spec v3.4 N1): K = 4096, T = 65 535 (a block of 256 MiB),
    // L(4096) = 4260 from RFC 6330 table 2.
    let (k, t) = (4096u32, 65_535u16);
    assert_eq!(intermediate_symbols(k), 4260);
    let input = k as u64 * t as u64;
    let held = (k as u64 + 4260) * t as u64 + 3277 * k as u64;
    assert_eq!(encoder_bytes(k, t), held);
    // Worker, R = 6: input + encoder + 6k symbols of (T + 32) + one packet + the 160 MiB slack.
    let out = 6 * k as u64;
    let worker = input + held + out * (t as u64 + 32) + t as u64 + 160 * MIB;
    assert_eq!(estimate_worker(k, t, out), worker.div_ceil(MIB) * MIB);
    assert_eq!(estimate_worker(k, t, out), 2488 * MIB);
    // Delivery (unchanged): the symbols, the copy of one share and the slack.
    assert_eq!(
        estimate_worker_delivery(input, out, t),
        (out * t as u64 + input + 160 * MIB).div_ceil(MIB) * MIB
    );
    // A PoS preparation: the input, the encoder, four symbol buffers; nothing grows with holders.
    assert_eq!(estimate_pos_issue(k, t), 792 * MIB);
    // The spec's step-3b knobs: a block of 240 MiB (K = 3841) ≈ 744, a pack of 32 MiB (K = 513).
    assert_eq!(estimate_pos_issue(3841, t), 744 * MIB);
    assert_eq!(estimate_pos_issue(513, t), 103 * MIB);
    // The 200 MiB block of the worker knob (K = 3201, R = 4): 1581 before the shrink, 1161 after.
    let out = 4 * 3201u64;
    assert_eq!(estimate_worker(3201, t, out), 1581 * MIB);
    assert_eq!(
        estimate_worker_delivery(3201 * t as u64, out, t),
        1161 * MIB
    );
    // Restore (К-b3, spec v3.9 WARN-1): the (k, t) form, K = 4096 → 4.09·E_pad.
    let network = (2 * (k as u64 + 3) + 4260 + 3 + k as u64 + 1) * t as u64 + 3277 * k as u64;
    assert_eq!(estimate_restore_network(k, t), network.div_ceil(MIB) * MIB);
    assert_eq!(estimate_restore_network(k, t), 1048 * MIB);
    let local = 2 * input + 180 * MIB + 8 * MIB;
    assert_eq!(
        estimate_restore_local(k, t, 180 * MIB),
        local.div_ceil(MIB) * MIB
    );
    assert_eq!(estimate_restore_plaintext(100 * MIB, 400 * MIB), 508 * MIB);
    // The worker shrinks: delivery never needs more than the encode (R ≥ 0).
    assert!(estimate_worker_delivery(input, out, t) < estimate_worker(k, t, out));
    // σ is the size of the `Symbol` struct.
    assert_eq!(std::mem::size_of::<viaticum_core::erasure::Symbol>(), 32);
}

/// Every estimate covers what the encoder holds beyond its input, at every K — the small K
/// where L/K is 27 (K = 1) and the large ones alike (spec v3.4 M36; a pure function, so it
/// guards the SHAPE; the measured side is the alloc-peak tests).
#[test]
fn estimates_cover_the_encoder_at_every_k() {
    let t = 65_535u16;
    for k in [
        1u32, 2, 10, 11, 20, 50, 257, 306, 513, 1307, 3889, 4253, 16_385, 56_403,
    ] {
        let l = intermediate_symbols(k) as u64;
        let held = (k as u64 + l) * t as u64 + 3277 * k as u64;
        let input = k as u64 * t as u64;
        assert!(
            estimate_pos_issue(k, t) >= input + held,
            "pos, K = {k}: {} < {}",
            estimate_pos_issue(k, t),
            input + held
        );
        assert!(estimate_worker(k, t, 0) >= input + held, "worker, K = {k}");
        // L/K shows: a K of 1 asks for ≈ 27 symbols, not 2.
        assert!(estimate_pos_issue(k, t) as f64 >= (input as f64) * (1.0 + l as f64 / k as f64));
    }
    // A K the encoder refuses must not panic an estimate.
    assert!(estimate_pos_issue(1_000_000, t) >= MIB);
}

#[test]
fn estimates_round_up_and_are_at_least_one_mib() {
    // Every estimate is a whole number of MiB, never 0 (a 0-byte try_acquire would pass a queue).
    assert_eq!(estimate_pos_issue(0, 0), MIB);
    assert_eq!(estimate_restore_network(0, 0), MIB);
    // The window of zstd is always there: 8 MiB.
    assert_eq!(estimate_restore_local(0, 0, 0), 8 * MIB);
    assert_eq!(estimate_restore_network(1, 1), MIB);
    // Over a MiB boundary → the next MiB: K = 1 is (2·4 + 27 + 3 + 1 + 1)·t + 3277 bytes.
    assert_eq!(estimate_restore_network(1, 26_214), 2 * MIB);
    assert_eq!(estimate_restore_network(1, 25_000), MIB);
    // The worker's slack alone is 160 MiB; the encoder of one symbol (27 of 1024 bytes) pushes it
    // into the next MiB.
    assert_eq!(estimate_worker(0, 1024, 0), 161 * MIB);
    assert_eq!(estimate_worker(1, 1, 1), 161 * MIB);
    for v in [
        estimate_worker(12_345, 1024, 7),
        estimate_worker_delivery(12_345, 7, 1024),
        estimate_pos_issue(12_345, 1024),
        estimate_restore_network(12_345, 1024),
        estimate_restore_local(12_345, 1024, 999),
        estimate_restore_plaintext(12_345, 999),
    ] {
        assert_eq!(v % MIB, 0);
        assert!(v >= MIB);
    }
    // Huge inputs saturate instead of overflowing.
    assert!(estimate_worker(u32::MAX, u16::MAX, u64::MAX) >= u64::MAX / 2);
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
    assert!(budget.warned_over(HolderKind::Worker));
    // An estimate within the total does not warn.
    let quiet = MemBudget::new(64 * MIB);
    let logs = logged(|| {
        let _p = quiet
            .try_acquire(HolderKind::Worker, &block(1), 64 * MIB)
            .unwrap();
    });
    assert!(!logs.contains("WARN"), "{logs}");
    assert!(!quiet.warned_over(HolderKind::Worker));
}

/// N7: the over-budget WARN is printed once per KIND of holder — the worker's WARN does not hide
/// the first WARN of a restore.
#[test]
fn over_budget_warns_once_per_kind() {
    let budget = MemBudget::new(64 * MIB);
    let logs = logged(|| {
        for (kind, n) in [
            (HolderKind::Worker, 1),
            (HolderKind::Worker, 2),
            (HolderKind::Restore, 3),
            (HolderKind::Restore, 4),
            (HolderKind::Pos, 5),
            (HolderKind::Dr, 6),
            (HolderKind::Dr, 7),
        ] {
            let p = budget
                .try_acquire(kind, &block(n), 100 * MIB)
                .expect("an idle budget runs an oversized estimate alone");
            drop(p);
        }
    });
    let warns: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("WARN") && l.contains("exceeds the memory budget"))
        .collect();
    assert_eq!(warns.len(), 4, "one per kind: {logs}");
    for kind in ["worker", "restore", "pos", "dr"] {
        assert_eq!(
            warns
                .iter()
                .filter(|l| l.contains(&format!("kind={kind}")))
                .count(),
            1,
            "{kind}: {logs}"
        );
    }
    for kind in [
        HolderKind::Worker,
        HolderKind::Restore,
        HolderKind::Pos,
        HolderKind::Dr,
    ] {
        assert!(budget.warned_over(kind));
    }
}

#[tokio::test]
async fn mem_budget_worker_acquire_waits_fifo() {
    let budget = MemBudget::new(10 * MIB);
    let holder = budget
        .acquire_plain(HolderKind::Worker, &block(1), 6 * MIB)
        .await;
    let order = Arc::new(Mutex::new(Vec::new()));

    // B needs 6 MiB (4 free: queued), C needs 2 MiB — it would fit into the 4 free, but B is ahead.
    let spawn_waiter = |tag: &'static str, bytes: u64| {
        let budget = Arc::clone(&budget);
        let order = Arc::clone(&order);
        tokio::spawn(async move {
            let p = budget
                .acquire_plain(HolderKind::Pos, &block(9), bytes)
                .await;
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
        tokio::spawn(async move {
            budget
                .acquire_plain(HolderKind::Pos, &block(2), 6 * MIB)
                .await
        })
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
        "mem_budget: granted kind=worker block={b} bytes={} waited_ms=0",
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
    assert_eq!(budget.queued_waiters(), 0);

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
        budget.queued_needs_mib(),
        vec![5, 3, 4],
        "the order of the queue"
    );

    // Cancelled: the drop guard takes it out of the count.
    w2.abort();
    let _ = w2.await;
    assert_eq!(budget.priority_waiters(PriorityKind::OverduePos), 1);
    assert_eq!(
        budget.queued_needs_mib(),
        vec![5, 4],
        "the cancelled one left the list"
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
    let hold = budget
        .acquire_plain(HolderKind::Worker, &block(1), 4 * MIB)
        .await;
    assert_eq!(budget.queued_waiters(), 0, "a grant at once is not a wait");
    let waiter = {
        let budget = Arc::clone(&budget);
        tokio::spawn(async move { budget.acquire_plain(HolderKind::Pos, &block(2), MIB).await })
    };
    until("the waiter queues", || budget.queued_waiters() == 1).await;
    drop(hold);
    let granted = waiter.await.unwrap();
    assert_eq!(budget.queued_waiters(), 0);
    drop(granted);

    // A cancelled wait leaves the count.
    let hold = budget
        .acquire_plain(HolderKind::Worker, &block(1), 4 * MIB)
        .await;
    let cancelled = {
        let budget = Arc::clone(&budget);
        tokio::spawn(async move { budget.acquire_plain(HolderKind::Pos, &block(3), MIB).await })
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

// ─── The yield rule (Б′) and the order of the queue (spec v3.5, v3.5a) ────────

/// A priority waiter of `kind` for `need_mib`, started in the background.
fn spawn_prio(
    budget: &Arc<MemBudget>,
    kind: PriorityKind,
    need_mib: u64,
) -> tokio::task::JoinHandle<MemPermit> {
    let budget = Arc::clone(budget);
    tokio::spawn(async move {
        budget
            .acquire_priority(kind, &block(0xEE), need_mib * MIB, slow(), || {})
            .await
    })
}

/// A plain waiter (`acquire`) of `need_mib`.
fn spawn_plain(budget: &Arc<MemBudget>, need_mib: u64) -> tokio::task::JoinHandle<MemPermit> {
    let budget = Arc::clone(budget);
    tokio::spawn(async move {
        budget
            .acquire_plain(HolderKind::Pos, &block(0xDD), need_mib * MIB)
            .await
    })
}

/// Start the waiters one by one, each only after the previous one stands in the queue (the order
/// is then the order of the list), and check the precondition of every probe below: EVERY waiter
/// is in the queue, none is granted.
async fn queue_up(
    budget: &Arc<MemBudget>,
    waiters: &[(Option<PriorityKind>, u64)],
) -> Vec<tokio::task::JoinHandle<MemPermit>> {
    let mut handles = Vec::new();
    for (i, (kind, need)) in waiters.iter().enumerate() {
        handles.push(match kind {
            Some(kind) => spawn_prio(budget, *kind, *need),
            None => spawn_plain(budget, *need),
        });
        until("the waiter stands in the queue", || {
            budget.queued_waiters() == i + 1
        })
        .await;
    }
    assert_eq!(
        budget.queued_needs_mib(),
        waiters.iter().map(|(_, n)| *n as u32).collect::<Vec<_>>(),
        "precondition: the waiters are queued, in this order"
    );
    assert!(
        handles.iter().all(|h| !h.is_finished()),
        "precondition: nobody is granted"
    );
    handles
}

fn worker_permit(budget: &Arc<MemBudget>, mib: u64) -> MemPermit {
    budget
        .try_acquire(HolderKind::Worker, &block(1), mib * MIB)
        .expect("the worker's permit")
}

fn third_holder(budget: &Arc<MemBudget>, mib: u64) -> MemPermit {
    budget
        .try_acquire(HolderKind::Pos, &block(2), mib * MIB)
        .expect("a third holder X")
}

const OD: PriorityKind = PriorityKind::OverduePos;
const RS: PriorityKind = PriorityKind::Restore;

/// M31: the rule of NOTE 4 v3.3 (the smallest need of the kind). [R 5, P 2], total 10, W 6, no
/// X: R needs 5 and only 4 fit beside the worker ever; P stands behind it. (Б′): 5 > 4 → yield to
/// both; the smallest-need rule sees P's 2 ≤ 4 and stays.
#[tokio::test]
async fn pos_behind_a_restore_head_that_never_fits_beside_the_worker_yields() {
    let budget = MemBudget::new(10 * MIB);
    let w = worker_permit(&budget, 6);
    let waiters = queue_up(&budget, &[(Some(RS), 5), (Some(OD), 2)]).await;
    assert!(
        budget.worker_must_yield(OD, &w),
        "P waits behind R, which never fits"
    );
    assert!(budget.worker_must_yield(RS, &w));
    drop(w);
    drop(waiters);
}

/// M32: the rule of the head's need. [R 3, P 7], total 10, W 6, X 2 (2 free): the head fits
/// beside the worker (3 ≤ 4), P does not (7 > 4). (Б′): yield to P; the head rule sees 3 ≤ 4.
#[tokio::test]
async fn pos_behind_a_fitting_head_but_not_fitting_itself_yields() {
    let budget = MemBudget::new(10 * MIB);
    let w = worker_permit(&budget, 6);
    let x = third_holder(&budget, 2);
    let waiters = queue_up(&budget, &[(Some(RS), 3), (Some(OD), 7)]).await;
    assert!(
        budget.worker_must_yield(OD, &w),
        "P's own need does not fit beside the worker"
    );
    assert!(
        !budget.worker_must_yield(RS, &w),
        "the head fits: X releases and it is served without a yield"
    );
    drop((w, x, waiters));
}

/// M33: only the first waiter of the kind. [P 1, R 10, P 1], total 12, W 3, X 9 (0 free): the
/// second P has R (10 > 9) ahead of it. (Б′): yield; the first-of-kind rule sees 1 ≤ 9.
#[tokio::test]
async fn a_later_waiter_of_the_kind_counts() {
    let budget = MemBudget::new(12 * MIB);
    let w = worker_permit(&budget, 3);
    let x = third_holder(&budget, 9);
    let waiters = queue_up(&budget, &[(Some(OD), 1), (Some(RS), 10), (Some(OD), 1)]).await;
    assert!(
        budget.worker_must_yield(OD, &w),
        "the second P stands behind R 10 > 9"
    );
    assert!(budget.worker_must_yield(RS, &w));
    drop((w, x, waiters));
}

/// M41: the rule (Б), the sum of the prefix. [R 3, P 2], total 10, W 6, X 2 (2 free): the prefix
/// 3 + 2 = 5 > 4 would yield, but R fits beside the worker, runs, releases, and P follows. (Б′):
/// max 3 ≤ 4 → no yield; rule (А) (free 2 < 5) would yield too.
#[tokio::test]
async fn pos_behind_a_fitting_restore_head_waits_without_a_yield() {
    let budget = MemBudget::new(10 * MIB);
    let w = worker_permit(&budget, 6);
    let x = third_holder(&budget, 2);
    let waiters = queue_up(&budget, &[(Some(RS), 3), (Some(OD), 2)]).await;
    assert!(!budget.worker_must_yield(OD, &w));
    assert!(!budget.worker_must_yield(RS, &w));
    // And it is true: X's release serves the head, the head's release serves P.
    drop(x);
    let mut it = waiters.into_iter();
    let r = it.next().unwrap().await.unwrap();
    drop(r);
    let p = it.next().unwrap().await.unwrap();
    assert_eq!(p.bytes(), 2 * MIB);
    drop(w);
}

/// The edge of (Б′): `max need == total − W` fits beside the worker (the waiter is served once the
/// others release) and is no reason to yield; one MiB more is. Total 10, W 6, X 4 (0 free): the
/// need 4 is no yield, 5 is. `>` read as `>=` would yield at 4.
#[tokio::test]
async fn a_need_equal_to_what_fits_beside_the_worker_does_not_yield() {
    for (need, yields) in [(4u64, false), (5, true)] {
        let budget = MemBudget::new(10 * MIB);
        let w = worker_permit(&budget, 6);
        let x = third_holder(&budget, 4);
        let waiters = queue_up(&budget, &[(Some(OD), need)]).await;
        assert_eq!(
            budget.worker_must_yield(OD, &w),
            yields,
            "need {need} beside W 6 of 10"
        );
        drop((w, x, waiters));
    }
}

/// M40: the rule (А), the free budget instead of `total − W`. Knob 3b: total 1792, the worker
/// 1000, a pack preparation holds 100 (692 free), the big block needs 745 ≤ 792 beside the
/// worker: the short holder releases, no yield and no re-encode of 200 MiB. (А) would yield
/// (692 < 745).
#[tokio::test]
async fn short_holders_serve_the_waiter_without_a_yield() {
    let budget = MemBudget::new(1792 * MIB);
    let w = worker_permit(&budget, 1000);
    let pack = third_holder(&budget, 100);
    let waiters = queue_up(&budget, &[(Some(OD), 745)]).await;
    assert_eq!(budget.available_bytes(), 692 * MIB);
    assert!(!budget.worker_must_yield(OD, &w), "745 <= 1792 - 1000");
    drop(pack);
    let big = waiters.into_iter().next().unwrap().await.unwrap();
    assert_eq!(big.bytes(), 745 * MIB);
    drop(w);
}

/// A plain waiter stands in the prefix too: the worker does not wait for a budget while it holds
/// one (A4), but anything else that waits with `acquire` is ahead of the waiters behind it.
#[tokio::test]
async fn a_plain_waiter_ahead_counts_in_the_prefix() {
    let budget = MemBudget::new(10 * MIB);
    let w = worker_permit(&budget, 3); // 7 fit beside it
    let x = third_holder(&budget, 7); // nothing free
    let waiters = queue_up(&budget, &[(None, 8), (Some(OD), 2)]).await;
    assert!(
        budget.worker_must_yield(OD, &w),
        "P stands behind a plain 8 > 7"
    );
    assert!(
        !budget.worker_must_yield(RS, &w),
        "nobody of that kind waits"
    );
    drop((w, x, waiters));

    // A plain waiter that fits beside the worker does not make P yield.
    let budget = MemBudget::new(10 * MIB);
    let w = worker_permit(&budget, 3);
    let x = third_holder(&budget, 7);
    let waiters = queue_up(&budget, &[(None, 5), (Some(OD), 2)]).await;
    assert!(!budget.worker_must_yield(OD, &w));
    drop((w, x, waiters));
}

/// The rule reads the worker's permit as it is NOW: after a shrink the room beside it grows.
#[tokio::test]
async fn the_rule_reads_the_permit_after_its_shrink() {
    let budget = MemBudget::new(10 * MIB);
    let mut w = worker_permit(&budget, 8);
    let waiters = queue_up(&budget, &[(Some(OD), 5)]).await;
    assert!(budget.worker_must_yield(OD, &w), "5 > 10 - 8");
    w.shrink_to(4 * MIB);
    assert!(!budget.worker_must_yield(OD, &w), "5 <= 10 - 4");
    drop(w);
    drop(waiters);
}

/// The list stands in the order of the semaphore's queue: waiters are granted in the order the
/// list shows, on a multi-threaded runtime where the tasks run in parallel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queue_order_is_the_semaphore_order() {
    let needs: [u64; 6] = [3, 1, 2, 5, 4, 1];
    let total: u64 = needs.iter().sum();
    let budget = MemBudget::new(total * MIB);
    // The whole budget in 1 MiB permits, released one at a time.
    let mut units: Vec<MemPermit> = (0..total)
        .map(|i| {
            budget
                .try_acquire(HolderKind::Worker, &block(i as u8), MIB)
                .unwrap()
        })
        .collect();
    let granted = Arc::new(Mutex::new(Vec::new()));
    let mut held = Vec::new();
    for (i, need) in needs.iter().enumerate() {
        let (budget_c, granted) = (Arc::clone(&budget), Arc::clone(&granted));
        let need = *need;
        held.push(tokio::spawn(async move {
            let p = budget_c
                .acquire_priority(OD, &block(0xEE), need * MIB, slow(), || {})
                .await;
            granted.lock().unwrap().push(need);
            p
        }));
        until("the waiter stands in the queue", || {
            budget.queued_waiters() == i + 1
        })
        .await;
    }
    assert_eq!(
        budget.queued_needs_mib(),
        needs.iter().map(|n| *n as u32).collect::<Vec<_>>()
    );

    let mut expected = Vec::new();
    let mut freed = 0;
    for need in needs {
        while freed < expected.iter().sum::<u64>() + need {
            drop(units.pop().unwrap());
            freed += 1;
        }
        expected.push(need);
        until("the next waiter is granted", || {
            granted.lock().unwrap().len() == expected.len()
        })
        .await;
        assert_eq!(
            *granted.lock().unwrap(),
            expected,
            "grant order = list order"
        );
    }
    for h in held {
        drop(h.await.unwrap());
    }
    assert_eq!(budget.queued_waiters(), 0);
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// WARN-1 (a), M42: with the task's cooperative budget spent, a first `poll` of a plain tokio
/// `Acquire` answers `Pending` WITHOUT queueing, while our list already holds the waiter: the
/// list and the semaphore's queue part, and a waiter that starts later (fresh budget) is granted
/// first. The capture is `unconstrained`, so A is queued at once. `Queued` is polled DIRECTLY here,
/// not through `wait` (whose `select!` refuses to poll anything while the budget is depleted and
/// would hide the defect): A spends its budget, polls its `Queued` once, starts B, and only then
/// goes on; B's first poll falls between A's first poll and its retry.
#[tokio::test]
async fn queue_order_holds_when_the_coop_budget_is_spent() {
    let budget = MemBudget::new(4 * MIB);
    let holder = budget
        .try_acquire(HolderKind::Worker, &block(1), 4 * MIB)
        .unwrap();
    let granted = Arc::new(Mutex::new(Vec::new()));

    let a = {
        let (budget, granted) = (Arc::clone(&budget), Arc::clone(&granted));
        tokio::spawn(async move {
            // Spend the task's cooperative budget (128 units) down to nothing, without yielding
            // on the way: the next coop-aware poll of this task answers `Pending`.
            let mut spent = 0;
            while tokio::task::coop::has_budget_remaining() {
                tokio::task::consume_budget().await;
                spent += 1;
                assert!(spent <= 1024, "the budget never runs out");
            }
            let mut queued = Box::pin(Queued::new(&budget, WaitKind::Priority(OD), 3));
            assert!(poll_once(queued.as_mut()).await.is_pending());
            // B starts now, with a fresh budget of its own.
            let b = {
                let (budget, granted) = (Arc::clone(&budget), Arc::clone(&granted));
                tokio::spawn(async move {
                    let p = budget
                        .acquire_priority(RS, &block(0xB), 2 * MIB, slow(), || {})
                        .await;
                    granted.lock().unwrap().push("b");
                    p
                })
            };
            // Let B run its first poll before A goes on.
            until("B stands in the list", || budget.queued_waiters() == 2).await;
            let permit = queued.await;
            granted.lock().unwrap().push("a");
            (permit, b)
        })
    };
    until("both stand in the list", || budget.queued_waiters() == 2).await;
    assert_eq!(budget.queued_needs_mib(), vec![3, 2], "the list: A, then B");
    drop(holder);
    until("somebody is granted", || {
        !granted.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(
        granted.lock().unwrap()[0],
        "a",
        "the first grant goes to the first in the list"
    );
    let (permit_a, b) = a.await.unwrap();
    drop(permit_a);
    drop(b.await.unwrap());
    assert_eq!(*granted.lock().unwrap(), vec!["a", "b"]);
}

/// Through `acquire_priority` a waiter with a spent budget may be delayed (the `select!` in `wait`
/// declines to poll while the budget is depleted), but it still stands in the list exactly where
/// it stands in the semaphore's queue: the grants go in the order of the list.
#[tokio::test]
async fn a_delayed_waiter_keeps_its_place_in_the_list_and_the_queue() {
    let budget = MemBudget::new(4 * MIB);
    let holder = budget
        .try_acquire(HolderKind::Worker, &block(1), 4 * MIB)
        .unwrap();
    let granted = Arc::new(Mutex::new(Vec::new()));
    let spawn_waiter = |tag: &'static str, need: u64, spend: bool| {
        let (budget, granted) = (Arc::clone(&budget), Arc::clone(&granted));
        tokio::spawn(async move {
            if spend {
                while tokio::task::coop::has_budget_remaining() {
                    tokio::task::consume_budget().await;
                }
            }
            let p = budget
                .acquire_priority(OD, &block(0xC), need * MIB, slow(), || {})
                .await;
            granted.lock().unwrap().push(tag);
            p
        })
    };
    let a = spawn_waiter("a", 3, true);
    let b = spawn_waiter("b", 2, false);
    until("both stand in the list", || budget.queued_waiters() == 2).await;
    let head_is_a = budget.queued_needs_mib()[0] == 3;
    drop(holder);
    until("somebody is granted", || {
        !granted.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(
        granted.lock().unwrap()[0] == "a",
        head_is_a,
        "the first grant goes to the head of the list"
    );
    // 3 + 2 do not fit into 4 at once: the first grant's permit goes before the second is served.
    let (first, second) = if head_is_a { (a, b) } else { (b, a) };
    drop(first.await.unwrap());
    drop(second.await.unwrap());
}

/// One poll of a pinned future, from the test's own task.
async fn poll_once<F: std::future::Future>(
    mut f: std::pin::Pin<&mut F>,
) -> std::task::Poll<F::Output> {
    std::future::poll_fn(|cx| std::task::Poll::Ready(f.as_mut().poll(cx))).await
}

/// WARN-1 (b): a waiter cancelled while it holds part of the free units leaves the list and gives
/// the units on in the same step (under one lock): nothing is left that counts a need whose units
/// are already somebody else's. Polled by hand so that nothing runs in between.
#[tokio::test]
async fn a_cancelled_waiter_leaves_the_list_and_its_units_go_on() {
    let budget = MemBudget::new(10 * MIB);
    let holder = worker_permit(&budget, 7); // 3 free
    let (b1, b2) = (block(1), block(2));
    let mut r = Box::pin(budget.acquire_priority(RS, &b1, 6 * MIB, slow(), || {}));
    assert!(poll_once(r.as_mut()).await.is_pending());
    let mut p = Box::pin(budget.acquire_priority(OD, &b2, 2 * MIB, slow(), || {}));
    assert!(poll_once(p.as_mut()).await.is_pending());
    // R holds the 3 free units part-way (A12-b); P stands behind it.
    assert_eq!(budget.queued_needs_mib(), vec![6, 2]);

    drop(r);
    assert_eq!(
        budget.queued_needs_mib(),
        vec![2],
        "the cancelled waiter left the list"
    );
    assert_eq!(budget.priority_waiters(RS), 0);
    assert_eq!(
        budget.outstanding_bytes(),
        7 * MIB,
        "nothing was granted to anyone"
    );
    // Its units went on to P: one poll grants it, the list empties and `held` counts it.
    let granted = match poll_once(p.as_mut()).await {
        std::task::Poll::Ready(permit) => permit,
        std::task::Poll::Pending => panic!("P got the cancelled waiter's units"),
    };
    assert_eq!(granted.bytes(), 2 * MIB);
    assert_eq!(budget.queued_waiters(), 0);
    assert_eq!(budget.outstanding_bytes(), 9 * MIB);
    drop((holder, granted));
    assert_eq!(budget.outstanding_bytes(), 0);
    assert_eq!(budget.semaphore_free_bytes(), 10 * MIB);
}

/// The wait API: a waiter granted at once is never listed; a granted one leaves the list and
/// `held` counts it in the same step.
#[tokio::test]
async fn a_waiter_is_listed_only_while_it_waits_and_held_counts_its_grant() {
    let budget = MemBudget::new(4 * MIB);
    let p = budget
        .acquire_priority(OD, &block(1), 2 * MIB, slow(), || {})
        .await;
    assert_eq!(budget.queued_waiters(), 0, "free at once: not listed");
    assert_eq!(budget.outstanding_bytes(), 2 * MIB);
    let waiter = spawn_prio(&budget, RS, 3);
    until("it waits", || budget.queued_waiters() == 1).await;
    drop(p);
    let granted = waiter.await.unwrap();
    assert_eq!(budget.queued_waiters(), 0);
    assert_eq!(budget.outstanding_bytes(), 3 * MIB);
    drop(granted);
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// The `granted` line names how long the caller waited (N4).
#[tokio::test(start_paused = true)]
async fn granted_line_carries_waited_ms() {
    let budget = MemBudget::new(4 * MIB);
    let holder = budget
        .try_acquire(HolderKind::Worker, &block(1), 4 * MIB)
        .unwrap();
    let (buf, _guard) = {
        let buf = LogBuf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        (buf, tracing::subscriber::set_default(subscriber))
    };
    let waiter = spawn_prio(&budget, RS, 2);
    until("it waits", || budget.queued_waiters() == 1).await;
    tokio::time::advance(Duration::from_millis(1500)).await;
    drop(holder);
    let _p = waiter.await.unwrap();
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.lines()
            .any(|l| l.contains("mem_budget: granted kind=restore") && l.contains("waited_ms=15")),
        "{text}"
    );
}

/// A permit shrunk after its write-off handle was taken (the batch of overdue checks shrinks
/// after every member): the write-off gives back what it holds NOW, not what it held at the
/// handle; and a shrink after the write-off returns nothing a second time.
#[test]
fn write_off_follows_the_size_of_a_shrunk_permit() {
    let budget = MemBudget::new(10 * MIB);
    let mut p = budget
        .try_acquire(HolderKind::Pos, &block(1), 8 * MIB)
        .unwrap();
    let handle = p.write_off_handle();
    p.shrink_to(3 * MIB);
    assert_eq!(handle.bytes(), 3 * MIB, "the handle sees the shrink");
    assert_eq!(budget.outstanding_bytes(), 3 * MIB);

    assert_eq!(budget.write_off(&handle), Some(3 * MIB));
    assert_eq!(budget.outstanding_bytes(), 0);
    assert_eq!(budget.semaphore_free_bytes(), 10 * MIB);

    // A shrink after the write-off is a no-op: nothing is released twice.
    p.shrink_to(MIB);
    assert_eq!(budget.outstanding_bytes(), 0);
    assert_eq!(budget.semaphore_free_bytes(), 10 * MIB);
    drop(p);
    assert_eq!(budget.semaphore_free_bytes(), 10 * MIB, "no units twice");
    assert_eq!(budget.outstanding_bytes(), 0);
}

/// The batch's rule toward restore is the worker's (Б′): a queued restore that cannot fit beside
/// the batch makes it end; one that fits, or a queued worker, does not. A worker waiting behind
/// the batch is not the worker's A4 case (no assertion).
#[tokio::test]
async fn batch_yields_to_a_restore_that_does_not_fit_beside_it() {
    let budget = MemBudget::new(10 * MIB);
    let batch = budget
        .try_acquire(HolderKind::Pos, &block(1), 6 * MIB)
        .unwrap();
    let other = third_holder(&budget, 4);
    let waiters = queue_up(&budget, &[(None, 3), (Some(PriorityKind::Restore), 5)]).await;
    // The plain waiter stands for the worker's `acquire` shape; restore needs 5 > 10 - 6.
    assert_eq!(
        budget.batch_must_yield_to_restore(&batch),
        Some(HolderKind::Restore)
    );
    drop((batch, other, waiters));

    let budget = MemBudget::new(10 * MIB);
    let batch = budget
        .try_acquire(HolderKind::Pos, &block(1), 4 * MIB)
        .unwrap();
    let other = third_holder(&budget, 6);
    let waiters = queue_up(&budget, &[(Some(PriorityKind::Restore), 5)]).await;
    assert_eq!(
        budget.batch_must_yield_to_restore(&batch),
        None,
        "5 <= 10 - 4: it is served when the others' units come back, no yield needed"
    );
    drop((batch, other, waiters));

    // Only a worker is queued, however big: the batch yields to restores alone (MR-R3).
    let budget = MemBudget::new(10 * MIB);
    let batch = budget
        .try_acquire(HolderKind::Pos, &block(1), 6 * MIB)
        .unwrap();
    let other = third_holder(&budget, 4);
    let waiters = queue_up(&budget, &[(None, 9)]).await;
    assert_eq!(budget.batch_must_yield_to_restore(&batch), None);
    drop((batch, other, waiters));

    // A worker stands AHEAD of a restore that would fit by itself: the prefix maximum counts
    // the worker (spec v3.7a), and the answer names it.
    let budget = MemBudget::new(10 * MIB);
    let batch = budget
        .try_acquire(HolderKind::Pos, &block(1), 6 * MIB)
        .unwrap();
    let other = third_holder(&budget, 4);
    let waiters = queue_up(&budget, &[(None, 9), (Some(PriorityKind::Restore), 1)]).await;
    // (`queue_up`'s plain waiter is a `Pos` acquire: not a restore, the rule's point.)
    assert_eq!(
        budget.batch_must_yield_to_restore(&batch),
        Some(HolderKind::Pos)
    );
    drop((batch, other, waiters));
}
