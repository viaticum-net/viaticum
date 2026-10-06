// On-demand dial bookkeeping (C-DK Р-12, network-i42).
//
// `send_to_device` to a known peer that is not authenticated becomes ONE command
// of the event loop (SendOrDial): the request waits here — at most
// ON_DEMAND_AUTH_TIMEOUT_SECS — for the peer's cert exchange, then leaves as an
// ordinary request. This module keeps the waiters and decides; the swarm event
// loop dials and sends.
//
// A peer with waiters is in one of four states:
//   Queued     — every on-demand slot is taken (≤ MAX_ON_DEMAND_DIALS dials);
//   OurDial    — our dial (by ConnectionId) is under way, or its connection is up
//                but the cert exchange is not done yet;
//   Foreign    — somebody else's dial or connection will bring the peer (a
//                Kademlia or discovery dial, an inbound connection);
//   Closing    — the cache just evicted it; we dial once its connection is gone.
// What resolves waiters:
//   - the peer authenticates → all waiters are sent;
//   - OUR dial fails (an error on our ConnectionId, our connection closed before
//     the cert, the deadline while our dial or our connection is pending) →
//     `Unreachable`, and the peer goes to the negative cache;
//   - the deadline while Queued / Foreign / Closing → `Unreachable("queued")`
//     WITHOUT the cache: we never tried the peer, so we learned nothing about it.
// Somebody else's dial failing resolves nothing (v3.1 W1 a); we then dial
// ourselves.
//
// Negative cache: a peer our dial failed to reach answers `Unreachable` at once
// for ON_DEMAND_NEG_TTL_SECS, doubled on each repeated failure up to
// max(ON_DEMAND_NEG_MAX_SECS / time_scale, TTL). Any established connection with
// the peer (inbound too) and its authentication clear it. Redial and
// `redial_devices` never read it.

#[cfg(test)]
mod tests;

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use libp2p::swarm::ConnectionId;
use libp2p::{Multiaddr, PeerId};
use tokio::sync::oneshot;
use viaticum_core::constants::{
    MAX_ON_DEMAND_DIALS, ON_DEMAND_AUTH_TIMEOUT_SECS, ON_DEMAND_NEG_MAX_SECS,
    ON_DEMAND_NEG_TTL_SECS,
};
use viaticum_core::messages::Message;
use viaticum_core::types::DeviceId;

use super::swarm::SwarmError;

/// An abandoned dial (its waiters gave up) is forgotten after this long even if
/// its error never arrives; the transport timeout (20 s) normally ends it first.
const ABANDONED_DIAL_FORGET: Duration = Duration::from_secs(30);

/// The variant name of a message: the `msg=` field of the on-demand log lines.
pub(crate) fn message_kind(m: &Message) -> &'static str {
    match m {
        Message::Handshake(_) => "Handshake",
        Message::PeerAnnounce(_) => "PeerAnnounce",
        Message::PosHashChallenge(_) => "PosHashChallenge",
        Message::PosHashResponse(_) => "PosHashResponse",
        Message::PosHashNack(_) => "PosHashNack",
        Message::SymbolOffer(_) => "SymbolOffer",
        Message::SymbolAccept(_) => "SymbolAccept",
        Message::SymbolReject(_) => "SymbolReject",
        Message::SymbolStored(_) => "SymbolStored",
        Message::SymbolTransfer(_) => "SymbolTransfer",
        Message::Delete(_) => "Delete",
        Message::CancelDelete(_) => "CancelDelete",
        Message::StorageWarning(_) => "StorageWarning",
        Message::SymbolDropped(_) => "SymbolDropped",
        Message::SymbolDropNotice(_) => "SymbolDropNotice",
        Message::RestoreRequest(_) => "RestoreRequest",
        Message::RestoreResponse(_) => "RestoreResponse",
        Message::ClusterSyncRequest(_) => "ClusterSyncRequest",
        Message::MailboxFetchRequest(_) => "MailboxFetchRequest",
        Message::MailboxFetchResponse(_) => "MailboxFetchResponse",
        Message::MailboxStoreRequest(_) => "MailboxStoreRequest",
        Message::MailboxStoreResponse(_) => "MailboxStoreResponse",
        Message::ClusterSyncResponse(_) => "ClusterSyncResponse",
        Message::Ack(_) => "Ack",
        Message::Unknown => "Unknown",
    }
}

/// One request waiting for its peer's authentication.
pub(crate) struct Waiter {
    pub kind: &'static str,
    pub message: Box<Message>,
    pub reply: oneshot::Sender<Result<Message, SwarmError>>,
    pub deadline: Instant,
}

/// What a peer's waiters are waiting on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitOn {
    Queued,
    OurDial(ConnectionId),
    Foreign,
    Closing,
}

impl WaitOn {
    /// The `reason=` of `on-demand: gave up` for a deadline in this state.
    fn gave_up_reason(self) -> &'static str {
        match self {
            WaitOn::Queued => "queued",
            WaitOn::Foreign => "foreign_dial",
            WaitOn::Closing => "closing",
            WaitOn::OurDial(_) => "timeout",
        }
    }
}

struct PeerWait {
    device: DeviceId,
    on: WaitOn,
    waiters: Vec<Waiter>,
    addrs: Vec<Multiaddr>,
}

/// What the peer looks like to the event loop when a request arrives.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Situation {
    /// Evicted by the cache, its connection still closing.
    pub closing: bool,
    /// A connection (or a dial) of somebody else is there, no cert yet.
    pub connected: bool,
}

/// The loop's next move after `admit` / `on_closed` / a foreign dial error.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// Nothing to do: the waiter waits.
    Wait,
    /// Dial the peer now (a slot is free); then `dial_started` or `dial_refused`.
    Dial,
}

/// Waiters resolved together, and how.
pub(crate) struct Resolved {
    pub peer: PeerId,
    pub device: DeviceId,
    pub waiters: Vec<Waiter>,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Our dial failed (cached): the reason for `on-demand dial failed`.
    Failed(String),
    /// The deadline passed before anybody tried the peer (not cached): the
    /// `reason=` of `on-demand: gave up`.
    GaveUp(&'static str),
}

impl Resolved {
    /// The distinct message kinds of the waiters, comma-separated (`msg=`).
    pub(crate) fn kinds(&self) -> String {
        kinds_of(&self.waiters)
    }
}

fn kinds_of(waiters: &[Waiter]) -> String {
    let mut kinds: Vec<&str> = Vec::new();
    for w in waiters {
        if !kinds.contains(&w.kind) {
            kinds.push(w.kind);
        }
    }
    kinds.join(",")
}

#[derive(Debug, Clone, Copy)]
struct Neg {
    until: Instant,
    backoff: Duration,
}

/// The on-demand dial state of one swarm.
pub(crate) struct OnDemand {
    max_dials: usize,
    wait: Duration,
    neg_ttl: Duration,
    neg_max: Duration,
    peers: HashMap<PeerId, PeerWait>,
    queue: VecDeque<PeerId>,
    inflight: usize,
    /// Our dials not yet connected or failed: peer, start, abandoned.
    our_dials: HashMap<ConnectionId, (PeerId, Instant, bool)>,
    neg: HashMap<PeerId, Neg>,
    ok_total: u64,
    failed_total: u64,
}

/// Counters for `ConnStats`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct OnDemandCounts {
    pub inflight: usize,
    pub queued: usize,
    pub abandoned: usize,
    pub neg_cached: usize,
    pub ok_total: u64,
    pub failed_total: u64,
}

impl OnDemand {
    /// `time_scale` sets the negative-cache ceiling (None = production scale).
    pub(crate) fn new(time_scale: Option<u64>) -> Self {
        let ts = time_scale.unwrap_or(1).max(1);
        Self::with_limits(
            MAX_ON_DEMAND_DIALS,
            Duration::from_secs(ON_DEMAND_AUTH_TIMEOUT_SECS),
            Duration::from_secs(ON_DEMAND_NEG_TTL_SECS),
            Duration::from_secs((ON_DEMAND_NEG_MAX_SECS / ts).max(ON_DEMAND_NEG_TTL_SECS)),
        )
    }

    pub(crate) fn with_limits(
        max_dials: usize,
        wait: Duration,
        neg_ttl: Duration,
        neg_max: Duration,
    ) -> Self {
        Self {
            max_dials,
            wait,
            neg_ttl,
            neg_max,
            peers: HashMap::new(),
            queue: VecDeque::new(),
            inflight: 0,
            our_dials: HashMap::new(),
            neg: HashMap::new(),
            ok_total: 0,
            failed_total: 0,
        }
    }

    /// When a waiter that arrives now gives up.
    pub(crate) fn deadline(&self, now: Instant) -> Instant {
        now + self.wait
    }

    /// The peer is in the negative cache now.
    pub(crate) fn is_cached(&self, peer: &PeerId, now: Instant) -> bool {
        self.neg.get(peer).is_some_and(|n| n.until > now)
    }

    /// Our dial of `peer` failed: cache it (doubling the period on a repeated
    /// failure; a failure while still cached changes nothing).
    fn neg_fail(&mut self, peer: PeerId, now: Instant) {
        let next = match self.neg.get(&peer) {
            Some(n) if n.until > now => return,
            Some(n) => (n.backoff * 2).min(self.neg_max),
            None => self.neg_ttl,
        };
        self.neg.insert(
            peer,
            Neg {
                until: now + next,
                backoff: next,
            },
        );
    }

    /// The period the peer is cached for now.
    #[cfg(test)]
    pub(crate) fn neg_period(&self, peer: &PeerId) -> Option<Duration> {
        self.neg.get(peer).map(|n| n.backoff)
    }

    /// A request for `peer` arrives. The caller already handled "authenticated"
    /// and "cached". Appends to the peer's waiters, or starts its wait.
    pub(crate) fn admit(
        &mut self,
        peer: PeerId,
        device: DeviceId,
        waiter: Waiter,
        addrs: Vec<Multiaddr>,
        sit: Situation,
    ) -> Next {
        if let Some(pw) = self.peers.get_mut(&peer) {
            pw.waiters.push(waiter);
            for a in addrs {
                if !pw.addrs.contains(&a) {
                    pw.addrs.push(a);
                }
            }
            return Next::Wait;
        }
        let on = if sit.closing {
            WaitOn::Closing
        } else if sit.connected {
            WaitOn::Foreign
        } else {
            WaitOn::Queued
        };
        self.peers.insert(
            peer,
            PeerWait {
                device,
                on,
                waiters: vec![waiter],
                addrs,
            },
        );
        if on == WaitOn::Queued {
            self.want_dial(peer)
        } else {
            Next::Wait
        }
    }

    /// A dial for `peer` is wanted: a free slot → Dial, else the queue.
    pub(crate) fn want_dial(&mut self, peer: PeerId) -> Next {
        let Some(pw) = self.peers.get_mut(&peer) else {
            return Next::Wait;
        };
        if matches!(pw.on, WaitOn::OurDial(_)) {
            return Next::Wait;
        }
        if self.inflight < self.max_dials {
            Next::Dial
        } else {
            pw.on = WaitOn::Queued;
            if !self.queue.contains(&peer) {
                self.queue.push_back(peer);
            }
            Next::Wait
        }
    }

    /// The addresses to dial `peer` on (from the callers' PeerRecords).
    pub(crate) fn addrs(&self, peer: &PeerId) -> Vec<Multiaddr> {
        self.peers
            .get(peer)
            .map(|pw| pw.addrs.clone())
            .unwrap_or_default()
    }

    /// The distinct message kinds waiting on `peer` (`msg=`).
    pub(crate) fn kinds(&self, peer: &PeerId) -> String {
        self.peers
            .get(peer)
            .map(|pw| kinds_of(&pw.waiters))
            .unwrap_or_default()
    }

    /// Our dial of `peer` started: it takes a slot.
    pub(crate) fn dial_started(&mut self, peer: PeerId, cid: ConnectionId, now: Instant) {
        if let Some(pw) = self.peers.get_mut(&peer) {
            pw.on = WaitOn::OurDial(cid);
            self.inflight += 1;
            self.queue.retain(|p| *p != peer);
        }
        self.our_dials.insert(cid, (peer, now, false));
    }

    /// Somebody else is dialing `peer` already (`DialPeerConditionFalse`): wait
    /// for that dial.
    pub(crate) fn set_foreign(&mut self, peer: PeerId) {
        if let Some(pw) = self.peers.get_mut(&peer) {
            pw.on = WaitOn::Foreign;
            self.queue.retain(|p| *p != peer);
        }
    }

    /// Remove `peer`'s wait: frees its slot (an unfinished dial of ours is kept
    /// as abandoned until its error arrives) and its queue place.
    fn take(&mut self, peer: &PeerId) -> Option<(DeviceId, Vec<Waiter>, WaitOn)> {
        let pw = self.peers.remove(peer)?;
        match pw.on {
            WaitOn::OurDial(cid) => {
                self.inflight = self.inflight.saturating_sub(1);
                if let Some(d) = self.our_dials.get_mut(&cid) {
                    d.2 = true;
                }
            }
            WaitOn::Queued => self.queue.retain(|p| p != peer),
            WaitOn::Foreign | WaitOn::Closing => {}
        }
        Some((pw.device, pw.waiters, pw.on))
    }

    /// The dial could not even start (`NoAddresses`, another synchronous
    /// error): every waiter is handed back to the caller. Not cached.
    pub(crate) fn dial_refused(&mut self, peer: &PeerId) -> Option<(DeviceId, Vec<Waiter>)> {
        self.take(peer).map(|(d, w, _)| (d, w))
    }

    /// `peer` authenticated: its waiters go out now; the cache entry is cleared.
    pub(crate) fn on_authenticated(&mut self, peer: &PeerId) -> Option<(DeviceId, Vec<Waiter>)> {
        self.neg.remove(peer);
        let (device, waiters, on) = self.take(peer)?;
        if matches!(on, WaitOn::OurDial(_)) {
            self.ok_total += 1;
        }
        Some((device, waiters))
    }

    /// A connection with `peer` is established (`cid`; ours or not). Clears the
    /// negative cache; a queued or closing wait now waits on that connection.
    pub(crate) fn on_established(&mut self, peer: PeerId, cid: ConnectionId) {
        self.neg.remove(&peer);
        let ours = self.our_dials.remove(&cid).is_some();
        if let Some(pw) = self.peers.get_mut(&peer)
            && matches!(pw.on, WaitOn::Queued | WaitOn::Closing)
            && !ours
        {
            pw.on = WaitOn::Foreign;
            self.queue.retain(|p| *p != peer);
        }
    }

    /// An outbound connection `cid` (to `peer`, if known) failed. Ours → its
    /// waiters fail (`Resolved`, cached). Somebody else's → nothing fails; if
    /// waiters were waiting on it, `Next::Dial` asks the loop to dial itself.
    pub(crate) fn on_dial_error(
        &mut self,
        peer: Option<PeerId>,
        cid: ConnectionId,
        reason: &str,
        now: Instant,
    ) -> (Option<Resolved>, Next) {
        if let Some((p, _, abandoned)) = self.our_dials.remove(&cid) {
            if abandoned {
                return (None, Next::Wait);
            }
            let is_ours = self
                .peers
                .get(&p)
                .is_some_and(|pw| pw.on == WaitOn::OurDial(cid));
            if !is_ours {
                return (None, Next::Wait);
            }
            return (self.fail_ours(p, reason, now), Next::Wait);
        }
        match peer {
            Some(p)
                if self
                    .peers
                    .get(&p)
                    .is_some_and(|pw| pw.on == WaitOn::Foreign) =>
            {
                (None, self.want_dial(p))
            }
            _ => (None, Next::Wait),
        }
    }

    fn fail_ours(&mut self, peer: PeerId, reason: &str, now: Instant) -> Option<Resolved> {
        let (device, waiters, _) = self.take(&peer)?;
        self.failed_total += 1;
        self.neg_fail(peer, now);
        Some(Resolved {
            peer,
            device,
            waiters,
            outcome: Outcome::Failed(reason.to_string()),
        })
    }

    /// Our dial to `peer` is under way and its connection is not up yet.
    pub(crate) fn our_dial_pending(&self, peer: &PeerId) -> bool {
        match self.peers.get(peer).map(|pw| pw.on) {
            Some(WaitOn::OurDial(cid)) => self.our_dials.contains_key(&cid),
            _ => false,
        }
    }

    /// The last connection of `peer` closed. Closing / Foreign → the loop dials
    /// now; our own connection closed before the cert → our dial failed.
    /// `refused`: the closed connection was one the test-only e2e hold refused
    /// (always false in a user build); while our dial to the peer is still under
    /// way it was not ours — the waiters stay with that dial.
    pub(crate) fn on_closed(
        &mut self,
        peer: PeerId,
        now: Instant,
        refused: bool,
    ) -> (Option<Resolved>, Next) {
        if refused && self.our_dial_pending(&peer) {
            return (None, Next::Wait);
        }
        let Some(on) = self.peers.get(&peer).map(|pw| pw.on) else {
            return (None, Next::Wait);
        };
        match on {
            WaitOn::Closing | WaitOn::Foreign => (None, self.want_dial(peer)),
            WaitOn::OurDial(_) => (
                self.fail_ours(peer, "connection closed before the cert exchange", now),
                Next::Wait,
            ),
            WaitOn::Queued => (None, Next::Wait),
        }
    }

    /// Deadlines (the 1-second tick): waiters past their deadline are resolved —
    /// `Failed("timeout")` (cached) while our dial or our connection is pending,
    /// `GaveUp(..)` (not cached) otherwise. A peer whose last waiter went frees
    /// its slot. Also forgets abandoned dials older than 30 s.
    pub(crate) fn expire(&mut self, now: Instant) -> Vec<Resolved> {
        self.our_dials.retain(|_, (_, started, abandoned)| {
            !*abandoned || now.duration_since(*started) < ABANDONED_DIAL_FORGET
        });
        let due: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, pw)| pw.waiters.iter().any(|w| w.deadline <= now))
            .map(|(p, _)| *p)
            .collect();
        let mut out = Vec::new();
        for peer in due {
            let Some(pw) = self.peers.get_mut(&peer) else {
                continue;
            };
            let on = pw.on;
            let device = pw.device;
            let (expired, kept): (Vec<Waiter>, Vec<Waiter>) =
                pw.waiters.drain(..).partition(|w| w.deadline <= now);
            pw.waiters = kept;
            let empty = pw.waiters.is_empty();
            let outcome = match on {
                WaitOn::OurDial(_) => {
                    if !self.is_cached(&peer, now) {
                        self.failed_total += 1;
                    }
                    self.neg_fail(peer, now);
                    Outcome::Failed("timeout".to_string())
                }
                other => Outcome::GaveUp(other.gave_up_reason()),
            };
            if empty {
                let _ = self.take(&peer);
            }
            out.push(Resolved {
                peer,
                device,
                waiters: expired,
                outcome,
            });
        }
        out
    }

    /// The next queued peer to dial while a slot is free.
    pub(crate) fn next_queued(&mut self) -> Option<PeerId> {
        if self.inflight >= self.max_dials {
            return None;
        }
        while let Some(p) = self.queue.pop_front() {
            if self.peers.get(&p).is_some_and(|pw| pw.on == WaitOn::Queued) {
                return Some(p);
            }
        }
        None
    }

    pub(crate) fn counts(&self, now: Instant) -> OnDemandCounts {
        OnDemandCounts {
            inflight: self.inflight,
            queued: self.queue.len(),
            abandoned: self.our_dials.values().filter(|d| d.2).count(),
            neg_cached: self.neg.values().filter(|n| n.until > now).count(),
            ok_total: self.ok_total,
            failed_total: self.failed_total,
        }
    }
}
