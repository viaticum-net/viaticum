// Tests for bounded shutdown draining (network-i1, network-i3) and stop
// signal handling (network-i10).

use std::time::{Duration, Instant};

use super::{NamedTask, ShutdownOutcome, TaskFailure, wait_tasks_with_deadline};

fn ok_task(name: &'static str) -> NamedTask {
    (name, tokio::spawn(async { Ok(()) }))
}

fn hanging_task(name: &'static str) -> NamedTask {
    (
        name,
        tokio::spawn(async {
            std::future::pending::<()>().await;
            Ok(())
        }),
    )
}

#[tokio::test]
async fn wait_with_deadline_ok_when_tasks_finish() {
    let slow_but_in_time: NamedTask = (
        "slow",
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(())
        }),
    );
    let tasks = vec![ok_task("a"), slow_but_in_time, ok_task("b")];

    let started = Instant::now();
    let outcome = wait_tasks_with_deadline(tasks, Duration::from_secs(5)).await;

    assert_eq!(
        outcome,
        ShutdownOutcome {
            finished: 3,
            failed: vec![],
            abandoned: vec![],
        }
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "must return as soon as all tasks are done, not at the deadline"
    );
    assert!(outcome.report().is_ok());
}

/// A task that never observes cancellation must not hold the process: at the
/// deadline it is reported as abandoned and the stop still counts as clean.
#[tokio::test]
async fn wait_with_deadline_reports_timeout_when_task_hangs() {
    let tasks = vec![ok_task("fast"), hanging_task("stuck")];

    let started = Instant::now();
    let outcome = wait_tasks_with_deadline(tasks, Duration::from_millis(200)).await;
    let elapsed = started.elapsed();

    assert_eq!(outcome.finished, 1);
    assert_eq!(outcome.abandoned, vec!["stuck"]);
    assert!(outcome.failed.is_empty());
    assert!(
        elapsed >= Duration::from_millis(200) && elapsed < Duration::from_secs(3),
        "must give up at the deadline, took {elapsed:?}"
    );
    assert!(
        outcome.report().is_ok(),
        "abandoned tasks alone do not make the exit code non-zero"
    );
}

/// Errors and panics are collected from every task (one failure does not stop
/// the wait for the others) and turn the outcome into an error.
#[tokio::test]
async fn wait_with_deadline_collects_errors_and_panics_when_tasks_fail() {
    let failing: NamedTask = (
        "failing",
        tokio::spawn(async { Err(anyhow::anyhow!("disk gone")) }),
    );
    let panicking: NamedTask = (
        "panicking",
        tokio::spawn(async {
            panic!("boom");
        }),
    );
    let tasks = vec![failing, ok_task("fine"), panicking];

    let mut outcome = wait_tasks_with_deadline(tasks, Duration::from_secs(5)).await;
    outcome.failed.sort_by_key(|f| f.task);

    assert_eq!(outcome.finished, 1);
    assert!(outcome.abandoned.is_empty());
    assert_eq!(outcome.failed.len(), 2);
    assert_eq!(
        outcome.failed[0],
        TaskFailure {
            task: "failing",
            reason: "disk gone".to_string(),
        }
    );
    assert_eq!(outcome.failed[1].task, "panicking");
    assert!(
        outcome.failed[1].reason.contains("panic"),
        "join error must say it panicked: {}",
        outcome.failed[1].reason
    );
    let err = outcome
        .report()
        .expect_err("failures make the exit non-zero");
    assert_eq!(err.count, 2);
}

/// Both stop signals reach `recv` (network-i10). The handlers are installed
/// before the signals are sent, so the default action (terminate) never runs;
/// nextest runs each test in its own process, and under `cargo test` a signal
/// caught by an installed tokio handler is harmless to other tests.
#[cfg(unix)]
#[allow(unsafe_code)] // libc::kill is FFI; the target is our own pid
#[tokio::test]
async fn shutdown_signals_recv_resolves_when_sigterm_or_sigint_sent_to_self() {
    let mut signals = super::ShutdownSignals::install().expect("install signal handlers");

    for (sig, expected) in [(libc::SIGTERM, "SIGTERM"), (libc::SIGINT, "Ctrl-C")] {
        let rc = unsafe { libc::kill(libc::getpid(), sig) };
        assert_eq!(rc, 0, "kill({sig}) failed");
        let got = tokio::time::timeout(Duration::from_secs(5), signals.recv())
            .await
            .unwrap_or_else(|_| panic!("recv did not resolve on {expected}"));
        assert_eq!(got, expected);
    }
}
