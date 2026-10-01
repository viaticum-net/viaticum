// Connection cache bookkeeping (C-DK Р-11, network-i41).
//
// One entry per connected peer (several connections to one peer — a duplicate
// from simultaneous dials, later TCP + QUIC — are one entry). The cache is the
// single owner of VOLUNTARY closes: R2 adds its cold-connection rule and the
// relay-reservation exemption here and nowhere else (T13, T8).
//
// What the cache counts against its cap is the set of peers that are neither
// busy nor infrastructure:
//   - busy: a cert exchange not finished yet (bounded by the cert timeout: a
//     connection that never sends a cert — a foreign Kademlia client in the open
//     network — must not hold a place outside the cap forever), a /viaticum/1
//     request in flight
//     (either direction), an on-demand dial waiting, or "protected" — only a
//     handshake (cert, PeerAnnounce) so far, younger than the grace and among the
//     MAX_HANDSHAKE_PROTECTED youngest such (a Kademlia lookup is asking it);
//   - infrastructure: decided once per connection by `is_infra` (a friend's
//     first ≤ 2 bootstrap peers; every peer of a seed up to INFRA_CONN_LIMIT).
// Activity is application traffic only: /viaticum/1 except PeerAnnounce. A cert
// exchange, PeerAnnounce, identify and Kademlia are handshake, not activity.
//
// Eviction order when more than `cap` peers are neither busy nor infra:
//   0. connections without a cert past the cert timeout, oldest first;
//   1. handshake-only peers (cert done, no activity), oldest establishment first;
//   2. peers with activity, least recent activity first (tie: PeerId order).
// A victim's entry is REMOVED here; the swarm moves it to `closing` and closes it.
//
// Pure: no swarm, no clock of its own — every call takes `now`.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::PeerId;

/// The swarm warns `lru: tick late` when two cache ticks are further apart than
/// this (the event loop stood still: an overloaded host). It tells a stalled
/// stand from a tick that does not run its pass.
pub(crate) const LRU_TICK_LATE_MS: u64 = 12_000;

/// Who is infrastructure: outside the cap, never evicted (network-i41). The
/// single point: R2 replaces the seed rule with "holds a relay reservation"
/// (Р-8 (а)) here and nowhere else (T8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfraRule {
    /// Nobody (the DR swap, tests).
    None,
    /// A friend: the first ≤ 2 DISTINCT PeerIds of `kademlia_bootstrap_peers`
    /// ("1–2 connections with the relay", Р-8 (б)).
    Peers(Vec<PeerId>),
    /// A seed (`relay_role = "punch"`): every peer while fewer than this many
    /// infrastructure entries exist (Д-2, Р-8 (а)).
    AllUpTo(usize),
}

/// Why the cache closed a peer (the `reason=` of `lru: evicted peer`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VictimReason {
    /// No cert exchange within the cert timeout.
    CertMissing,
    /// Only a handshake, and older than the grace.
    HandshakeExpired,
    /// Only a handshake, young, but not among the protected youngest.
    HandshakeBeyond16,
    /// Application traffic, the least recent.
    Idle,
}

impl VictimReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            VictimReason::CertMissing => "cert_missing",
            VictimReason::HandshakeExpired => "handshake_expired",
            VictimReason::HandshakeBeyond16 => "handshake_beyond_16",
            VictimReason::Idle => "idle",
        }
    }
}

/// One peer the eviction pass removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Victim {
    pub peer: PeerId,
    pub reason: VictimReason,
    /// now − max(when it stopped being busy, the previous pass): an upper bound
    /// of how long the cache let it stay over the cap (bar ≤ 11 s).
    pub evictable_for: Duration,
    /// now − last activity (or establishment for a handshake-only peer).
    pub idle: Duration,
}

/// The cache's view for `ConnStats` (network-i41). `busy` counts connected
/// non-infra entries only; `protected` ⊂ `busy`; `cert_pending` ⊂ `busy`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LruCounts {
    pub entries: usize,
    pub busy: usize,
    pub protected: usize,
    pub cert_pending: usize,
    pub infra: usize,
}

/// Where an outbound connection came from (the `origin=` of `lru: re-dial of
/// evicted peer`, the carousel bar of network-i43).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialOrigin {
    /// `send_to_device` to a known peer without a connection (network-i42).
    OnDemand,
    /// The redial pass (network-i2, i43).
    Redial,
    /// restore-i26's redial of a block's holders before a retry.
    Restore,
    /// A discovery lookup's unknown peer (Р-5′).
    Discovery,
    /// `connect`, cluster sync, DR — an explicit dial by address.
    Manual,
    /// None of ours: Kademlia dialing on its own during a lookup.
    Kad,
}

impl DialOrigin {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DialOrigin::OnDemand => "on_demand",
            DialOrigin::Redial => "redial",
            DialOrigin::Restore => "restore",
            DialOrigin::Discovery => "discovery",
            DialOrigin::Manual => "manual",
            DialOrigin::Kad => "kad",
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    established: Instant,
    /// False from ConnectionEstablished until record_authenticated: busy, never
    /// a victim (a peer closed before its cert would not become known).
    cert_done: bool,
    /// App traffic only: /viaticum/1 except PeerAnnounce, either direction.
    last_activity: Option<Instant>,
    /// /viaticum/1 requests in flight (either direction) + on-demand waiters.
    in_flight: u32,
    /// Decided once by `is_infra` in `on_connected`.
    infra: bool,
    /// When the entry last stopped being busy (cert done, in_flight → 0).
    evictable_since: Option<Instant>,
}

impl Entry {
    fn handshake_only(&self) -> bool {
        self.cert_done && self.last_activity.is_none() && self.in_flight == 0
    }
}

/// Connection cache bookkeeping, one entry per connected peer (network-i41).
#[derive(Debug)]
pub(crate) struct ConnLru {
    cap: usize,
    infra_rule: InfraRule,
    grace: Duration,
    max_protected: usize,
    /// How long a connection without a cert exchange counts as busy.
    cert_grace: Duration,
    entries: HashMap<PeerId, Entry>,
    /// `begin` for a peer without an entry yet (an on-demand dial waiting for
    /// its connection): merged into the entry by `on_connected`.
    pending_busy: HashMap<PeerId, u32>,
    evictions_total: u64,
    last_pass: Option<Instant>,
}

impl ConnLru {
    pub(crate) fn new(
        cap: usize,
        infra_rule: InfraRule,
        grace: Duration,
        max_protected: usize,
        cert_grace: Duration,
    ) -> Self {
        Self {
            cap,
            infra_rule,
            grace,
            max_protected,
            cert_grace,
            entries: HashMap::new(),
            pending_busy: HashMap::new(),
            evictions_total: 0,
            last_pass: None,
        }
    }

    pub(crate) fn cap(&self) -> usize {
        self.cap
    }

    pub(crate) fn evictions_total(&self) -> u64 {
        self.evictions_total
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, peer: &PeerId) -> bool {
        self.entries.contains_key(peer)
    }

    /// The single point that decides infrastructure (T8): an existing entry
    /// keeps what was decided when it connected; a new peer is judged by the rule.
    pub(crate) fn is_infra(&self, peer: &PeerId) -> bool {
        if let Some(e) = self.entries.get(peer) {
            return e.infra;
        }
        match &self.infra_rule {
            InfraRule::None => false,
            InfraRule::Peers(peers) => peers.contains(peer),
            InfraRule::AllUpTo(limit) => self.entries.values().filter(|e| e.infra).count() < *limit,
        }
    }

    /// First connection to `peer`: a busy entry (cert pending). Merges the
    /// waiters `begin` counted before the connection. A second call for a peer
    /// already present changes nothing (one entry per peer).
    pub(crate) fn on_connected(&mut self, peer: PeerId, now: Instant) {
        if self.entries.contains_key(&peer) {
            return;
        }
        let infra = self.is_infra(&peer);
        let in_flight = self.pending_busy.remove(&peer).unwrap_or(0);
        self.entries.insert(
            peer,
            Entry {
                established: now,
                cert_done: false,
                last_activity: None,
                in_flight,
                infra,
                evictable_since: None,
            },
        );
    }

    /// Cert exchange done (record_authenticated). Runs the pass: the newcomer
    /// may push the oldest protected peer out of the protected youngest.
    #[must_use]
    pub(crate) fn on_authenticated(&mut self, peer: &PeerId, now: Instant) -> Vec<Victim> {
        if let Some(e) = self.entries.get_mut(peer)
            && !e.cert_done
        {
            e.cert_done = true;
            if e.in_flight == 0 {
                e.evictable_since = Some(now);
            }
        }
        self.victims(now)
    }

    /// Last connection to `peer` closed.
    pub(crate) fn on_disconnected(&mut self, peer: &PeerId) {
        self.entries.remove(peer);
    }

    /// Application traffic with `peer` (not PeerAnnounce, not a cert).
    pub(crate) fn touch(&mut self, peer: &PeerId, now: Instant) {
        if let Some(e) = self.entries.get_mut(peer) {
            e.last_activity = Some(now);
        }
    }

    /// A request or an on-demand waiter is in flight with `peer`: never evicted
    /// meanwhile. Works for a peer without an entry yet (counted until it
    /// connects).
    pub(crate) fn begin(&mut self, peer: &PeerId) {
        match self.entries.get_mut(peer) {
            Some(e) => e.in_flight += 1,
            None => *self.pending_busy.entry(*peer).or_default() += 1,
        }
    }

    /// A request with `peer` ended. Returns the victims to close NOW when this
    /// freed the peer while the cache is over the cap (v3.1 B1: the overshoot
    /// ends in the same event-loop turn). A request of a peer whose entry is gone
    /// (it disconnected meanwhile) changes nothing.
    #[must_use]
    pub(crate) fn end(&mut self, peer: &PeerId, now: Instant) -> Vec<Victim> {
        let Some(e) = self.entries.get_mut(peer) else {
            return Vec::new();
        };
        e.in_flight = e.in_flight.saturating_sub(1);
        if e.in_flight > 0 {
            return Vec::new();
        }
        if e.cert_done {
            e.evictable_since = Some(now);
        }
        self.victims(now)
    }

    /// An on-demand waiter of `peer` is resolved without a request (failure,
    /// deadline): undoes its `begin` wherever it was counted.
    #[must_use]
    pub(crate) fn release_waiter(&mut self, peer: &PeerId, now: Instant) -> Vec<Victim> {
        if self.entries.contains_key(peer) {
            return self.end(peer, now);
        }
        if let Some(n) = self.pending_busy.get_mut(peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.pending_busy.remove(peer);
            }
        }
        Vec::new()
    }

    /// The young handshake-only peers that are protected now: younger than the
    /// grace, the `max_protected` youngest (tie: PeerId order).
    fn protected_set(&self, now: Instant) -> Vec<PeerId> {
        let mut young: Vec<(&PeerId, Instant)> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                !e.infra && e.handshake_only() && now.duration_since(e.established) < self.grace
            })
            .map(|(p, e)| (p, e.established))
            .collect();
        // Youngest first: later establishment first, then PeerId.
        young.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        young
            .into_iter()
            .take(self.max_protected)
            .map(|(p, _)| *p)
            .collect()
    }

    fn cert_pending(&self, e: &Entry, now: Instant) -> bool {
        !e.cert_done && now.saturating_duration_since(e.established) < self.cert_grace
    }

    fn is_busy(&self, e: &Entry, peer: &PeerId, protected: &[PeerId], now: Instant) -> bool {
        !e.infra && (self.cert_pending(e, now) || e.in_flight > 0 || protected.contains(peer))
    }

    /// The eviction pass (tick, ConnStats, auth, end). REMOVES the victims'
    /// entries and returns them, so that at most `cap` non-busy non-infra
    /// entries stay. Never: busy, infra.
    #[must_use]
    pub(crate) fn victims(&mut self, now: Instant) -> Vec<Victim> {
        let previous_pass = self.last_pass.replace(now);
        let protected = self.protected_set(now);
        let mut free: Vec<(PeerId, &Entry)> = self
            .entries
            .iter()
            .filter(|(p, e)| !e.infra && !self.is_busy(e, p, &protected, now))
            .map(|(p, e)| (*p, e))
            .collect();
        if free.len() <= self.cap {
            return Vec::new();
        }
        let excess = free.len() - self.cap;
        // Without a cert first, then handshake-only (oldest establishment first),
        // then by activity (least recent first).
        let class = |e: &Entry| -> (u8, Instant) {
            match (e.cert_done, e.last_activity) {
                (false, _) => (0, e.established),
                (true, None) => (1, e.established),
                (true, Some(t)) => (2, t),
            }
        };
        free.sort_by(|(pa, a), (pb, b)| class(a).cmp(&class(b)).then_with(|| pa.cmp(pb)));
        let victims: Vec<Victim> = free
            .into_iter()
            .take(excess)
            .map(|(peer, e)| {
                let reason = if !e.cert_done {
                    VictimReason::CertMissing
                } else if e.last_activity.is_some() {
                    VictimReason::Idle
                } else if now.duration_since(e.established) >= self.grace {
                    VictimReason::HandshakeExpired
                } else {
                    VictimReason::HandshakeBeyond16
                };
                let mut since = e.evictable_since.unwrap_or(e.established);
                match reason {
                    VictimReason::HandshakeExpired => since = since.max(e.established + self.grace),
                    VictimReason::CertMissing => since = since.max(e.established + self.cert_grace),
                    _ => {}
                }
                if let Some(prev) = previous_pass {
                    since = since.max(prev);
                }
                Victim {
                    peer,
                    reason,
                    evictable_for: now.saturating_duration_since(since),
                    idle: now.saturating_duration_since(e.last_activity.unwrap_or(e.established)),
                }
            })
            .collect();
        for v in &victims {
            self.entries.remove(&v.peer);
        }
        self.evictions_total += victims.len() as u64;
        victims
    }

    /// Entries that count against the cap if not busy: non-infra entries.
    pub(crate) fn non_infra_len(&self) -> usize {
        self.entries.values().filter(|e| !e.infra).count()
    }

    pub(crate) fn counts(&self, now: Instant) -> LruCounts {
        let protected = self.protected_set(now);
        let mut c = LruCounts {
            entries: self.entries.len(),
            protected: protected.len(),
            ..LruCounts::default()
        };
        for (p, e) in &self.entries {
            if e.infra {
                c.infra += 1;
            } else if self.is_busy(e, p, &protected, now) {
                c.busy += 1;
                if self.cert_pending(e, now) {
                    c.cert_pending += 1;
                }
            }
        }
        c
    }

    /// Tests: (cert_done, has app activity, in_flight) of `peer`.
    #[cfg(test)]
    pub(crate) fn entry_state(&self, peer: &PeerId) -> Option<(bool, bool, u32)> {
        self.entries
            .get(peer)
            .map(|e| (e.cert_done, e.last_activity.is_some(), e.in_flight))
    }
}
