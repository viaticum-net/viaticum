// Kademlia lookup cadence (C-DK Р-17 v3.3, network-i43).
//
// libp2p's periodic bootstrap is off; our own timer runs both lookups on every
// tick — the discovery lookup (get_closest_peers of our own id), then the
// Kademlia bootstrap. Until the cadence settles the tick comes every 5 min
// (divided by time_scale, or the test override); after, every
// max(30 min / time_scale, 60 s real). Settling happens once and never goes
// back, on whichever comes first:
//   - the swarm knows ≥ KAD_SETTLE_KNOWN peers of other masters, or
//   - KAD_SETTLE_QUIET_ROUNDS discovery rounds in a row found peers and none
//     of them unknown — without this a circle of ≤ 20 owners never settles.
// An EMPTY round does not count and resets the streak: the lookup did not reach
// the network, and the slow cadence would cut the node off for 30 min.
// With no time_scale (ConnPolicy::off: the DR swap, tests) it never settles.
//
// libp2p's automatic bootstrap (on every new table entry while the table holds
// fewer than 20) cannot be turned off; it is logged as origin=auto.
//
// Pure: no swarm, no clock.

#[cfg(test)]
mod tests;

use std::time::Duration;

use viaticum_core::constants::{KAD_DISCOVERY_SETTLED_INTERVAL_SECS, KAD_SETTLED_FLOOR_SECS};

/// Known peers (another master) at which the cadence settles.
pub(crate) const KAD_SETTLE_KNOWN: usize = 20;

/// Discovery rounds in a row that found peers and no unknown one.
pub(crate) const KAD_SETTLE_QUIET_ROUNDS: u32 = 2;

/// Why the cadence settled (`kademlia lookup cadence settled reason=…`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettleReason {
    Known,
    Quiet,
}

impl SettleReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SettleReason::Known => "known",
            SettleReason::Quiet => "quiet",
        }
    }
}

/// Who started a Kademlia bootstrap (`kademlia bootstrap started origin=…`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootstrapOrigin {
    /// Once, before the event loop starts.
    Start,
    /// Our lookup timer.
    Timer,
    /// libp2p on its own (a new table entry while the table holds < 20).
    Auto,
}

impl BootstrapOrigin {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            BootstrapOrigin::Start => "start",
            BootstrapOrigin::Timer => "timer",
            BootstrapOrigin::Auto => "auto",
        }
    }
}

/// A bootstrap progress event: is it the start of one we did not start? Ours
/// (start, timer) were logged when we started them; libp2p's own shows up only
/// as its first progress step.
pub(crate) fn bootstrap_origin(ours: bool, step_count: usize) -> Option<BootstrapOrigin> {
    (!ours && step_count == 1).then_some(BootstrapOrigin::Auto)
}

/// The settled period: max(30 min / time_scale, 60 s).
pub(crate) fn settled_interval(time_scale: u64) -> Duration {
    let secs = KAD_DISCOVERY_SETTLED_INTERVAL_SECS / time_scale.max(1);
    Duration::from_secs(secs.max(KAD_SETTLED_FLOOR_SECS))
}

/// The lookup cadence state of one swarm.
#[derive(Debug)]
pub(crate) struct KadCadence {
    /// None: never settles (ConnPolicy::off).
    time_scale: Option<u64>,
    settled: Option<SettleReason>,
    quiet_rounds: u32,
}

impl KadCadence {
    pub(crate) fn new(time_scale: Option<u64>) -> Self {
        Self {
            time_scale,
            settled: None,
            quiet_rounds: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn settled(&self) -> Option<SettleReason> {
        self.settled
    }

    /// The period after settling, None while not settled (or never settling).
    pub(crate) fn settled_period(&self) -> Option<Duration> {
        match (self.settled, self.time_scale) {
            (Some(_), Some(ts)) => Some(settled_interval(ts)),
            _ => None,
        }
    }

    fn settle(&mut self, reason: SettleReason) -> Option<SettleReason> {
        if self.settled.is_some() || self.time_scale.is_none() {
            return None;
        }
        self.settled = Some(reason);
        Some(reason)
    }

    /// The swarm's known set grew (or was seeded) to `known`. Returns the
    /// reason when this call settled the cadence.
    pub(crate) fn on_known(&mut self, known: usize) -> Option<SettleReason> {
        if known >= KAD_SETTLE_KNOWN {
            self.settle(SettleReason::Known)
        } else {
            None
        }
    }

    /// One discovery round of the timer finished: did it find anybody, and was
    /// any of them unknown? Returns the reason when this round settled it.
    pub(crate) fn on_discovery_round(
        &mut self,
        found_any: bool,
        found_unknown: bool,
    ) -> Option<SettleReason> {
        if !found_any || found_unknown {
            self.quiet_rounds = 0;
            return None;
        }
        self.quiet_rounds += 1;
        if self.quiet_rounds >= KAD_SETTLE_QUIET_ROUNDS {
            self.settle(SettleReason::Quiet)
        } else {
            None
        }
    }

    /// After a tick ran its lookups: the new period if the timer still runs at
    /// the fast period and the cadence has settled (the timer is re-created then:
    /// a tick already scheduled — the first one included — is kept).
    pub(crate) fn slow_down(&self, timer_is_slow: bool) -> Option<Duration> {
        if timer_is_slow {
            None
        } else {
            self.settled_period()
        }
    }
}
