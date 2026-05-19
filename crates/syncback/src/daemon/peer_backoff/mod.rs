//! Per-peer rejection backoff for placement engine.
//!
//! When a holder rejects a SymbolOffer (QuotaFull, TrustTooLow, transport
//! timeout, etc.), it usually means the peer is in pressure or otherwise
//! unable to take new holdings. Continuing to offer them blocks creates a
//! ping-pong: scheduler marks the placement Lost after timeout, repair
//! immediately re-offers to the same set of saturated peers, which reject
//! again. Owners never converge to peers that have free capacity (e.g. fresh
//! bootstrap nodes with empty holdings dirs).
//!
//! Fix: every peer rejection records a cooldown timestamp. The placement
//! engine soft-filters candidates whose cooldown is still active. "Soft"
//! means: if filtering would leave fewer than 2 candidates (compute_allocation
//! requires >= 2), we fall back to the unfiltered list — placement never
//! stalls completely just because every peer is on cooldown.
//!
//! Successful Accept clears the cooldown for that peer.
//!
//! State is in-memory (not persisted). On daemon restart cooldowns reset,
//! which is acceptable: a stale eviction-pressure peer will reject the next
//! offer and re-enter cooldown immediately.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use syncback_core::types::DeviceId;

#[cfg(test)]
mod tests;

/// Default production cooldown: 6 hours. Peers in eviction pressure typically
/// stay there for hours (slow to reclaim space, repair backpressure to other
/// owners). With time_scale > 1 the cooldown shrinks proportionally so demo
/// clusters and tests don't hang for 6h.
pub const DEFAULT_COOLDOWN_SECS: u64 = 6 * 3600;

#[derive(Debug)]
pub struct PeerBackoff {
    cooldowns: Mutex<HashMap<DeviceId, Instant>>,
    cooldown: Duration,
}

impl PeerBackoff {
    /// `cooldown_secs` is the unscaled production cooldown; the caller is
    /// expected to apply `time_scale` (so daemons with `--time-scale 10`
    /// pass 600 instead of 6000 for the demo equivalent of 6h).
    pub fn new(cooldown_secs: u64) -> Self {
        Self {
            cooldowns: Mutex::new(HashMap::new()),
            cooldown: Duration::from_secs(cooldown_secs.max(1)),
        }
    }

    /// Record that `peer` rejected an offer (any reason). Subsequent
    /// candidate filters will skip this peer until the cooldown elapses.
    pub fn record_reject(&self, peer: DeviceId) {
        if let Ok(mut map) = self.cooldowns.lock() {
            map.insert(peer, Instant::now() + self.cooldown);
        }
    }

    /// Clear cooldown for `peer` (e.g. after a successful Accept). Idempotent.
    pub fn record_accept(&self, peer: &DeviceId) {
        if let Ok(mut map) = self.cooldowns.lock() {
            map.remove(peer);
        }
    }

    /// True if `peer` is currently on cooldown.
    pub fn is_in_backoff(&self, peer: &DeviceId) -> bool {
        let now = Instant::now();
        match self.cooldowns.lock() {
            Ok(map) => map.get(peer).is_some_and(|deadline| *deadline > now),
            Err(_) => false,
        }
    }

    /// Soft-filter `candidates`: drop any device on cooldown.
    /// If filtering leaves fewer than `min_required`, returns the original
    /// list unchanged — placement must always have a chance to make progress.
    pub fn filter<T, F>(&self, candidates: Vec<T>, min_required: usize, key: F) -> Vec<T>
    where
        F: Fn(&T) -> &DeviceId,
    {
        let filtered: Vec<T> = match self.cooldowns.lock() {
            Ok(map) => {
                let now = Instant::now();
                let in_backoff =
                    |id: &DeviceId| map.get(id).is_some_and(|deadline| *deadline > now);
                let kept: Vec<T> = candidates
                    .into_iter()
                    .filter(|c| !in_backoff(key(c)))
                    .collect();
                if kept.len() < min_required {
                    return Vec::new(); // sentinel: caller falls back to raw list
                }
                kept
            }
            Err(_) => return Vec::new(),
        };
        filtered
    }

    /// GC entries whose deadline has already passed. Optional housekeeping —
    /// `is_in_backoff` is correct without it; this just bounds memory growth
    /// in long-running daemons with many transient peers.
    pub fn gc(&self) {
        let now = Instant::now();
        if let Ok(mut map) = self.cooldowns.lock() {
            map.retain(|_, deadline| *deadline > now);
        }
    }
}

impl Default for PeerBackoff {
    fn default() -> Self {
        Self::new(DEFAULT_COOLDOWN_SECS)
    }
}
