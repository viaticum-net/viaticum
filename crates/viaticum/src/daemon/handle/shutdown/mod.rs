// Daemon shutdown: stop signals and bounded draining of subsystem tasks
// (network-i1, network-i3, network-i6).
//
// Path of a stop (SIGTERM, Ctrl-C, internal restart), driven by main():
//   1. `ShutdownSignals` is installed BEFORE `DaemonHandle::start`, so a signal
//      that arrives while the daemon is still starting is ours, not the default
//      "terminate" (exit 143).
//   2. `DaemonHandle::stop()` cancels the token; every task finishes its current
//      step and returns.
//   3. `DaemonHandle::wait_with_deadline(SHUTDOWN_DRAIN)` joins them. A task
//      still running at the deadline is abandoned: main returns, the runtime is
//      dropped and cancels it at its next `.await`. redb transactions are
//      synchronous (no `.await` inside one), so the database is consistent at
//      every await point; the last `Db` clone drops with the runtime and redb
//      closes cleanly (no repair on the next start). Blocking tasks
//      (`spawn_blocking`) are awaited by the runtime drop — bounded by their work.
//   4. A second signal during the drain exits immediately (code 1): the user
//      asked twice; repair on the next start is expected then.

#[cfg(test)]
mod tests;

use std::time::Duration;

use futures::StreamExt;
use futures::stream::FuturesUnordered;
use tokio::task::JoinHandle;

/// How long stopped tasks get to finish their current step before they are
/// abandoned. Well inside systemd's default `TimeoutStopSec` (90 s).
pub const SHUTDOWN_DRAIN: Duration = Duration::from_secs(10);

/// A daemon subsystem task with a name for shutdown diagnostics.
pub(crate) type NamedTask = (&'static str, JoinHandle<anyhow::Result<()>>);

/// A task that ended with an error or a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskFailure {
    /// Task name (see `DaemonHandle::start`).
    pub task: &'static str,
    /// Error text, or the panic / cancellation description.
    pub reason: String,
}

/// Result of waiting for the daemon's tasks after `stop()`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShutdownOutcome {
    /// Tasks that returned `Ok(())`.
    pub finished: usize,
    /// Tasks that returned an error or panicked.
    pub failed: Vec<TaskFailure>,
    /// Tasks still running when the drain deadline passed (abandoned: their
    /// work resumes after the next start).
    pub abandoned: Vec<&'static str>,
}

/// Shutdown ended with failed tasks: the process must exit non-zero.
#[derive(Debug, thiserror::Error)]
#[error("{count} daemon task(s) failed: {summary}")]
pub struct ShutdownError {
    /// Number of failed tasks.
    pub count: usize,
    /// `name: reason` list.
    pub summary: String,
}

impl ShutdownOutcome {
    /// Log the outcome and turn it into the process result.
    ///
    /// Abandoned tasks are a WARN, not an error: the stop was still clean for
    /// the database (see module docs), so the exit code stays 0 — for systemd a
    /// non-zero code would mark the unit failed after an ordinary stop.
    /// Failed tasks (error or panic) make it `Err` → non-zero exit.
    pub fn report(&self) -> Result<(), ShutdownError> {
        if !self.abandoned.is_empty() {
            tracing::warn!(
                abandoned = self.abandoned.len(),
                tasks = ?self.abandoned,
                drain_secs = SHUTDOWN_DRAIN.as_secs(),
                "{} tasks abandoned at the shutdown deadline (work resumes after start)",
                self.abandoned.len()
            );
        }
        if self.failed.is_empty() {
            tracing::info!(finished = self.finished, "shutdown complete");
            return Ok(());
        }
        for f in &self.failed {
            tracing::error!(task = f.task, reason = %f.reason, "daemon task failed");
        }
        let summary = self
            .failed
            .iter()
            .map(|f| format!("{}: {}", f.task, f.reason))
            .collect::<Vec<_>>()
            .join("; ");
        Err(ShutdownError {
            count: self.failed.len(),
            summary,
        })
    }
}

/// Join all `tasks` concurrently, but for at most `deadline`.
///
/// Unlike a sequential `for t in tasks { t.await }`, one slow task does not
/// hide the state of the others, and an error in one does not stop waiting for
/// the rest. Tasks not done at the deadline are reported as abandoned (their
/// `JoinHandle`s are dropped, which detaches — it does not abort — them).
pub(crate) async fn wait_tasks_with_deadline(
    tasks: Vec<NamedTask>,
    deadline: Duration,
) -> ShutdownOutcome {
    let mut remaining: Vec<&'static str> = tasks.iter().map(|(name, _)| *name).collect();
    let mut pending: FuturesUnordered<_> = tasks
        .into_iter()
        .map(|(name, handle)| async move { (name, handle.await) })
        .collect();
    let mut outcome = ShutdownOutcome::default();

    let timer = tokio::time::sleep(deadline);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            next = pending.next() => {
                let Some((name, joined)) = next else { break };
                if let Some(pos) = remaining.iter().position(|n| *n == name) {
                    remaining.swap_remove(pos);
                }
                match joined {
                    Ok(Ok(())) => outcome.finished += 1,
                    Ok(Err(e)) => outcome.failed.push(TaskFailure {
                        task: name,
                        reason: format!("{e:#}"),
                    }),
                    Err(join_err) => outcome.failed.push(TaskFailure {
                        task: name,
                        reason: join_err.to_string(),
                    }),
                }
            }
            _ = &mut timer => {
                remaining.sort_unstable();
                outcome.abandoned = remaining;
                break;
            }
        }
    }
    outcome
}

/// Stop signals, registered at construction (so a signal that arrives before
/// the first `recv` is not lost and does not kill the process).
pub struct ShutdownSignals {
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(unix)]
    int: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
}

impl ShutdownSignals {
    /// Register the handlers now. Must be called inside the tokio runtime and
    /// BEFORE `DaemonHandle::start` (network-i6).
    pub fn install() -> std::io::Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            term: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            #[cfg(unix)]
            int: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            #[cfg(windows)]
            ctrl_c: tokio::signal::windows::ctrl_c()?,
        })
    }

    /// Wait for the next stop signal; returns its name for the log.
    pub async fn recv(&mut self) -> &'static str {
        #[cfg(unix)]
        {
            tokio::select! {
                Some(()) = self.term.recv() => "SIGTERM",
                Some(()) = self.int.recv() => "Ctrl-C",
                // Both streams ended (runtime shutting down): never resolve.
                else => std::future::pending().await,
            }
        }
        #[cfg(windows)]
        {
            match self.ctrl_c.recv().await {
                Some(()) => "Ctrl-C",
                None => std::future::pending().await,
            }
        }
    }
}
