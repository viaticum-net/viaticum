// How often a re-authentication wakes the work pipeline (C-DK Р-18).
//
// Every `WorkEvent::PeerAuthenticated` resets all cooldowns of the pipeline.
// Under the connection cache a peer may close and come back (an on-demand dial,
// an eviction) many times an hour; each return must not become a wake, or the
// cache and the pipeline drive each other in a loop. A NEW peer always wakes it;
// a returning one at most once per WORK_WAKE_MIN_SECS / time_scale per device.
// Without a time_scale (tests, no policy) there is no limit: as before C4.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use viaticum_core::constants::WORK_WAKE_MIN_SECS;
use viaticum_core::types::DeviceId;

/// The minimum interval between two wakes by the same device; None = no limit.
pub(crate) fn work_wake_min(time_scale: Option<u64>) -> Option<Duration> {
    time_scale.map(|ts| Duration::from_millis(WORK_WAKE_MIN_SECS * 1000 / ts.max(1)))
}

/// The last wake per device.
#[derive(Debug, Default)]
pub(crate) struct WorkWakeLimiter {
    last: HashMap<DeviceId, Instant>,
}

impl WorkWakeLimiter {
    /// Should the authentication of `device` wake the pipeline now? Records
    /// the wake when it does.
    pub(crate) fn allow(
        &mut self,
        device: DeviceId,
        is_new_peer: bool,
        min: Option<Duration>,
        now: Instant,
    ) -> bool {
        let due = is_new_peer
            || match (min, self.last.get(&device)) {
                (None, _) | (_, None) => true,
                (Some(min), Some(last)) => now.duration_since(*last) >= min,
            };
        if due {
            self.last.insert(device, now);
        }
        due
    }
}
