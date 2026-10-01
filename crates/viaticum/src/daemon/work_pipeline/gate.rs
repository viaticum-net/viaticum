// The restore gate of the backup worker (Q-V9 (a), spec v3.12b WARN-1..3).
//
// "Restore first": the worker stands while the gate is up. The gate is NOT a flag set by events —
// it is a question asked of the state of its sources at every reading, so a missed publication
// cannot leave it wrong: the sources are the registry of restore jobs (any job `Queued` or
// `Running`) and the DR's session on the budget (`DrLeases::session_active`). The wake only tells
// the worker's loop that it is worth asking again.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::daemon::mem_budget::DrLeases;
use crate::daemon::restore::jobs::RestoreJobs;

/// A backup pause longer than this is a warning in the log (once per pause) and a line in
/// `status`: a restore job whose coordinator died (a panic) holds the gate until the node is
/// restarted, and there is no cancel API (spec v3.12b NOTE 2).
///
/// 6 h is the recommendation of line V, NOT a decision of Ilya: the value is a guess about how
/// long an honest restore of a big catalog takes, and the product owner may change it.
pub const BACKUP_PAUSE_WARN_AFTER: Duration = Duration::from_secs(6 * 3600);

/// How long the gate has been up without a break, by the readings of the worker (it reads the
/// gate at every tick and at every wake). The clock is injected: the units move it by hand.
pub struct PauseWatch {
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
    state: Mutex<PauseState>,
}

#[derive(Default)]
struct PauseState {
    /// When the reading that found the gate up first happened (the pause is on since).
    since: Option<Instant>,
    /// The warning was given for this pause.
    warned: bool,
}

impl PauseWatch {
    /// With the system clock.
    pub fn new() -> Arc<Self> {
        Self::with_clock(Instant::now)
    }

    /// With the clock of the caller.
    pub fn with_clock(clock: impl Fn() -> Instant + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(PauseWatch {
            clock: Box::new(clock),
            state: Mutex::new(PauseState::default()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PauseState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A reading of the gate: up starts (or goes on with) the pause, down ends it.
    pub fn observe(&self, up: bool) {
        let mut st = self.lock();
        if !up {
            *st = PauseState::default();
        } else if st.since.is_none() {
            st.since = Some((self.clock)());
        }
    }

    fn elapsed(&self, st: &PauseState) -> Option<Duration> {
        st.since.map(|t| (self.clock)().saturating_duration_since(t))
    }

    /// The pause that is on has lasted longer than `BACKUP_PAUSE_WARN_AFTER`.
    pub fn overlong(&self) -> bool {
        let st = self.lock();
        self.elapsed(&st).is_some_and(|d| d > BACKUP_PAUSE_WARN_AFTER)
    }

    /// The length of the pause when it is overlong and nobody was told yet; once per pause.
    pub fn take_warning(&self) -> Option<Duration> {
        let mut st = self.lock();
        let d = self.elapsed(&st).filter(|d| *d > BACKUP_PAUSE_WARN_AFTER)?;
        if st.warned {
            return None;
        }
        st.warned = true;
        Some(d)
    }
}

impl std::fmt::Debug for PauseWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PauseWatch")
            .field("overlong", &self.overlong())
            .finish()
    }
}

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
    watch: Arc<PauseWatch>,
}

/// THE gate of the daemon (spec v3.12b WARN-2): up while a restore job is unfinished or a DR
/// session is on the budget. The daemon and the units build it through this function, so a unit
/// of the wiring is a unit of the real thing.
pub fn restore_gate(jobs: &RestoreJobs, leases: &Arc<DrLeases>, wake: &GateWake) -> RestoreGate {
    let (jobs_now, leases_now) = (jobs.clone(), Arc::clone(leases));
    RestoreGate::new(wake, move || {
        jobs_now.has_unfinished() || leases_now.session_active()
    })
    .with_pause_watch(jobs.pause_watch())
}

impl RestoreGate {
    /// `up` is evaluated at every `is_up`; `wake` is the notifier its sources bump.
    pub fn new(wake: &GateWake, up: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        RestoreGate {
            up: Arc::new(up),
            wake: wake.subscribe(),
            watch: PauseWatch::new(),
        }
    }

    /// The watch of the pause length that `status` reads too.
    pub fn with_pause_watch(mut self, watch: Arc<PauseWatch>) -> Self {
        self.watch = watch;
        self
    }

    /// The pause that is on has been going longer than `BACKUP_PAUSE_WARN_AFTER`, and this is the
    /// first one to ask since it began: its length (the caller logs the warning).
    pub(super) fn take_overlong_warning(&self) -> Option<Duration> {
        self.watch.take_warning()
    }

    /// The gate now, computed from the state of its sources.
    pub fn is_up(&self) -> bool {
        let up = (self.up)();
        self.watch.observe(up);
        up
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
