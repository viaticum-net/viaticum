// The restore gate of the backup worker (Q-V9 (a), spec v3.12b WARN-1..3).
//
// "Restore first": the worker stands while the gate is up. The gate is NOT a flag set by events —
// it is a question asked of the state of its sources at every reading, so a missed publication
// cannot leave it wrong: the sources are the registry of restore jobs (any job `Queued` or
// `Running`) and the DR's session on the budget (`DrLeases::session_active`). The wake only tells
// the worker's loop that it is worth asking again.

use std::sync::Arc;

use tokio::sync::watch;

/// The notifier the gate's sources share: every change of what the gate is computed from bumps
/// the counter, and the worker's loop wakes.
pub type GateWake = Arc<watch::Sender<u64>>;

/// A new notifier.
pub fn new_gate_wake() -> GateWake {
    Arc::new(watch::channel(0u64).0)
}

/// Tell the worker's loop that the gate may have changed.
pub fn notify_gate(wake: &GateWake) {
    wake.send_modify(|v| *v = v.wrapping_add(1));
}

/// Read-only view of the gate: "is a restore (a job or a DR session) in the way of the backup
/// worker now". Cheap to clone.
#[derive(Clone)]
pub struct RestoreGate {
    up: Arc<dyn Fn() -> bool + Send + Sync>,
    wake: watch::Receiver<u64>,
}

impl RestoreGate {
    /// `up` is evaluated at every `is_up`; `wake` is the notifier its sources bump.
    pub fn new(wake: &GateWake, up: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        RestoreGate {
            up: Arc::new(up),
            wake: wake.subscribe(),
        }
    }

    /// The gate now, computed from the state of its sources.
    pub fn is_up(&self) -> bool {
        (self.up)()
    }

    /// A receiver that wakes when a source changed.
    pub(super) fn subscribe(&self) -> watch::Receiver<u64> {
        self.wake.clone()
    }
}

impl std::fmt::Debug for RestoreGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoreGate")
            .field("up", &self.is_up())
            .finish()
    }
}
