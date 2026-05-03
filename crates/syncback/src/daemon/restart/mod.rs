// RestartGate: idempotent self-rexec trigger for the daemon.
//
// On the first call, spawns a child process running the same binary with the
// same CLI args (so --data-dir / --config / etc. are preserved), then cancels
// the global shutdown token. The current process drains and exits; the child
// proceeds with normal startup. Subsequent calls return false without spawning.

use std::sync::OnceLock;

use tokio_util::sync::CancellationToken;

#[cfg(test)]
mod tests;

pub struct RestartGate {
    triggered: OnceLock<()>,
}

impl Default for RestartGate {
    fn default() -> Self {
        Self::new()
    }
}

impl RestartGate {
    pub const fn new() -> Self {
        Self {
            triggered: OnceLock::new(),
        }
    }

    /// Returns true if THIS call is the first one to trigger restart.
    /// Subsequent concurrent calls return false (no-op).
    ///
    /// `spawn_child` is invoked exactly once on the winning call. This indirection
    /// exists so unit tests can substitute a non-fork closure.
    pub fn trigger_with<F>(&self, shutdown: &CancellationToken, spawn_child: F) -> bool
    where
        F: FnOnce() -> Result<(), String>,
    {
        if self.triggered.set(()).is_err() {
            return false;
        }
        match spawn_child() {
            Ok(()) => {
                tracing::info!("restart: child spawn requested, cancelling shutdown");
            }
            Err(e) => {
                tracing::error!("restart: spawn_child failed: {e}");
                // Still cancel shutdown? No — without a child the daemon would
                // simply exit. Caller must retry or restart manually.
                return true;
            }
        }
        shutdown.cancel();
        true
    }

    /// Production trigger: spawn a child running the same binary + args, then
    /// cancel the shutdown token.
    pub fn trigger(&self, shutdown: &CancellationToken) -> bool {
        self.trigger_with(shutdown, default_spawn_child)
    }
}

fn default_spawn_child() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let child = std::process::Command::new(&exe)
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    tracing::info!(pid = child.id(), exe = %exe.display(), "restart: child spawned");
    Ok(())
}
