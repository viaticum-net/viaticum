// The event-loop side of the connection cache (network-i41) and the on-demand
// dial (network-i42): what `swarm.rs`'s event and command handlers call. The
// decisions live in `conn_lru` and `on_demand` (pure); here they meet the swarm.

use std::time::{Duration, Instant};

use libp2p::request_response::{InboundRequestId, OutboundRequestId};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{ConnectionId, DialError};
use libp2p::{Multiaddr, PeerId};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};
use viaticum_core::constants::LRU_REDIAL_WINDOW_SECS;
use viaticum_core::messages::Message;
use viaticum_core::types::DeviceId;

use super::{
    ConnStats, EventLoopState, ProtocolEvent, SwarmError, device_id_to_peer_id, emit_event,
    strip_peer_suffix,
};
use crate::daemon::network::conn_lru::{DialOrigin, LRU_TICK_LATE_MS, Victim};
use crate::daemon::network::on_demand::{Next, Outcome, Resolved, Situation, Waiter, message_kind};

/// `lru: over cap, every peer busy` only when the overshoot has had no
/// protected or cert-pending peer behind it this long, and not more often.
const ALL_BUSY_WARN_AFTER: Duration = Duration::from_secs(60);

/// Is `m` application traffic for the cache? PeerAnnounce is a handshake.
fn is_app_traffic(m: &Message) -> bool {
    !matches!(m, Message::PeerAnnounce(_))
}

impl EventLoopState {
    // ── Sending ──────────────────────────────────────────────────────────────

    /// `SendOrDial` (network-i42): send now if authenticated; otherwise (when
    /// `dial` and the policy allows) wait for the peer — dialing it if nobody
    /// else is — and send once it authenticates. One event-loop turn decides.
    pub(super) fn send_or_dial(
        &mut self,
        device: DeviceId,
        addrs: Vec<Multiaddr>,
        message: Box<Message>,
        reply: oneshot::Sender<Result<Message, SwarmError>>,
        dial: bool,
    ) {
        if let Some(peer) = self.device_to_peer.get(&device).copied()
            && self.authenticated.contains_key(&peer)
        {
            self.send_app_request(peer, message, reply);
            return;
        }
        if !(dial && self.dial_on_demand) {
            let _ = reply.send(Err(SwarmError::PeerNotAuthenticated(device)));
            return;
        }
        let Ok(peer) = device_id_to_peer_id(&device) else {
            let _ = reply.send(Err(SwarmError::PeerNotAuthenticated(device)));
            return;
        };
        let now = Instant::now();
        let kind = message_kind(&message);
        if self.on_demand.is_cached(&peer, now) {
            info!(peer_id = %peer, msg = %kind, "on-demand: unreachable (cached)");
            let _ = reply.send(Err(SwarmError::Unreachable(
                device,
                "cached: the last on-demand dial failed".to_string(),
            )));
            return;
        }
        let waiter = Waiter {
            kind,
            message,
            reply,
            deadline: self.on_demand.deadline(now),
        };
        if let Some(lru) = self.lru.as_mut() {
            lru.add_waiter(&peer);
        }
        let sit = Situation {
            closing: self.closing.contains_key(&peer),
            connected: self.swarm.is_connected(&peer) || self.dialing.contains(&peer),
        };
        if self.on_demand.admit(peer, device, waiter, addrs, sit) == Next::Dial {
            self.on_demand_dial(peer);
        }
    }

    /// Send a /viaticum/1 request to an authenticated `peer`. The cache counts
    /// it in flight until its response or failure; app traffic (not
    /// PeerAnnounce) is activity, stamped when the exchange ends — while it is
    /// in flight the peer is busy anyway (fix round 1: one touch, not two).
    pub(super) fn send_app_request(
        &mut self,
        peer: PeerId,
        message: Box<Message>,
        reply: oneshot::Sender<Result<Message, SwarmError>>,
    ) {
        let app = is_app_traffic(&message);
        let req_id = self
            .swarm
            .behaviour_mut()
            .viaticum
            .send_request(&peer, *message);
        self.pending_requests.insert(req_id, reply);
        if let Some(lru) = self.lru.as_mut() {
            lru.begin(&peer);
            self.lru_out.insert(req_id, (peer, app));
        }
    }

    /// An outbound request ended (response or failure).
    pub(super) fn outbound_request_ended(&mut self, req_id: OutboundRequestId) {
        let Some((peer, app)) = self.lru_out.remove(&req_id) else {
            return;
        };
        self.lru_request_ended(peer, app, false);
    }

    /// An inbound request from an authenticated peer is being delivered.
    pub(super) fn inbound_request_started(
        &mut self,
        peer: PeerId,
        req_id: InboundRequestId,
        message: &Message,
    ) {
        let Some(lru) = self.lru.as_mut() else {
            return;
        };
        lru.begin(&peer);
        // Activity is stamped when the response is sent (`lru_request_ended`).
        self.lru_in.insert(req_id, (peer, is_app_traffic(message)));
    }

    /// An inbound request ended (response sent, or failed / dropped).
    pub(super) fn inbound_request_ended(&mut self, req_id: InboundRequestId) {
        let Some((peer, app)) = self.lru_in.remove(&req_id) else {
            return;
        };
        self.lru_request_ended(peer, app, true);
    }

    /// `inbound`: we answered — the peer lingers (ANSWER_LINGER) so the answer
    /// is not cut off by closing the connection in this turn.
    fn lru_request_ended(&mut self, peer: PeerId, app: bool, inbound: bool) {
        let now = Instant::now();
        let Some(lru) = self.lru.as_mut() else {
            return;
        };
        if app {
            lru.touch(&peer, now);
        }
        let victims = if inbound {
            lru.end_inbound(&peer, now)
        } else {
            lru.end(&peer, now)
        };
        self.evict(victims, "end", now);
    }

    // ── On-demand dial ────────────────────────────────────────────────────────

    /// Dial `peer` for its waiters: PeerRecord addresses ∪ what the swarm knows
    /// ∪ Kademlia's (network-i42).
    fn on_demand_dial(&mut self, peer: PeerId) {
        let now = Instant::now();
        let mut addrs = self.on_demand.addrs(&peer);
        for a in self.peer_known_addrs(&peer) {
            if let Ok(t) = strip_peer_suffix(&a, peer)
                && !addrs.contains(&t)
            {
                addrs.push(t);
            }
        }
        let n = addrs.len();
        let kinds = self.on_demand.kinds(&peer);
        let opts = DialOpts::peer_id(peer)
            .addresses(addrs)
            .extend_addresses_through_behaviour()
            .build();
        let cid = opts.connection_id();
        match self.swarm.dial(opts) {
            Ok(()) => {
                self.on_demand.dial_started(peer, cid, now);
                self.dial_origin
                    .insert(cid, (peer, DialOrigin::OnDemand, now));
                info!(peer_id = %peer, addrs = n, msg = %kinds, "swarm: on-demand dial");
            }
            Err(DialError::DialPeerConditionFalse(_)) => {
                // Somebody is dialing it already: wait for that dial.
                self.on_demand.set_foreign(peer);
            }
            Err(DialError::NoAddresses) => {
                // An unknown peer without addresses: as before C4.
                if let Some((device, waiters)) = self.on_demand.dial_refused(&peer) {
                    for w in waiters {
                        self.remove_waiter(&peer, now);
                        let _ = w.reply.send(Err(SwarmError::PeerNotAuthenticated(device)));
                    }
                }
            }
            Err(e) => {
                let reason = e.to_string();
                info!(peer_id = %peer, msg = %kinds, reason = %reason, "swarm: on-demand dial failed");
                if let Some((device, waiters)) = self.on_demand.dial_refused(&peer) {
                    for w in waiters {
                        self.remove_waiter(&peer, now);
                        let _ = w
                            .reply
                            .send(Err(SwarmError::Unreachable(device, reason.clone())));
                    }
                }
            }
        }
    }

    /// A resolved waiter leaves the cache's waiter count.
    fn remove_waiter(&mut self, peer: &PeerId, now: Instant) {
        if let Some(lru) = self.lru.as_mut() {
            let victims = lru.remove_waiter(peer, now);
            self.evict(victims, "end", now);
        }
    }

    /// Failed / given-up waiters get `Unreachable`; one log line per batch.
    fn resolve_unreachable(&mut self, r: Resolved, now: Instant) {
        let kinds = r.kinds();
        let reason = match &r.outcome {
            Outcome::Failed(reason) => {
                info!(peer_id = %r.peer, msg = %kinds, reason = %reason, "swarm: on-demand dial failed");
                reason.clone()
            }
            Outcome::GaveUp(reason) => {
                // The peer was never tried: "queued" whatever it waited on
                // (the slots, a foreign dial, a close) — and never cached.
                info!(peer_id = %r.peer, msg = %kinds, reason = %reason, "on-demand: gave up");
                "queued".to_string()
            }
        };
        for w in r.waiters {
            self.remove_waiter(&r.peer, now);
            let _ = w
                .reply
                .send(Err(SwarmError::Unreachable(r.device, reason.clone())));
        }
    }

    /// Dial queued peers while on-demand slots are free.
    fn promote_queued(&mut self) {
        while let Some(peer) = self.on_demand.next_queued() {
            if self.swarm.is_connected(&peer) {
                self.on_demand.set_foreign(peer);
                continue;
            }
            self.on_demand_dial(peer);
        }
    }

    /// The 1-second tick: waiters past their deadline.
    pub(super) fn on_demand_expire(&mut self) {
        let now = Instant::now();
        for r in self.on_demand.expire(now) {
            self.resolve_unreachable(r, now);
        }
        self.promote_queued();
    }

    // ── Connection events ─────────────────────────────────────────────────────

    /// A connection with `peer` is established (`cid`).
    pub(super) fn conn_established(
        &mut self,
        peer: PeerId,
        cid: ConnectionId,
        dialer: bool,
        now: Instant,
    ) {
        self.pending_close.remove(&peer);
        if self.closing.remove(&peer).is_some() {
            // A new connection of a peer the cache just evicted: it is alive
            // again and re-authenticates on this connection.
            debug!(peer_id = %peer, "lru: evicted peer connected again");
        }
        if let Some(lru) = self.lru.as_mut() {
            lru.on_connected(peer, now);
        }
        self.on_demand.on_established(peer, cid);
        let origin = self
            .dial_origin
            .remove(&cid)
            .map(|(_, o, _)| o)
            .unwrap_or(DialOrigin::Kad);
        if dialer
            && let Some(at) = self.evicted_at.get(&peer)
            && now.duration_since(*at) <= Duration::from_secs(LRU_REDIAL_WINDOW_SECS)
        {
            info!(
                peer_id = %peer,
                origin = %origin.as_str(),
                evicted_secs_ago = now.duration_since(*at).as_secs(),
                "lru: re-dial of evicted peer"
            );
            #[cfg(test)]
            self.test_redial_origins.push((peer, origin.as_str()));
        }
        self.check_over_cap(now);
    }

    /// The last connection of `peer` closed.
    pub(super) fn conn_closed(&mut self, peer: PeerId, now: Instant) {
        self.pending_close.remove(&peer);
        if let Some(lru) = self.lru.as_mut() {
            lru.on_disconnected(&peer);
        }
        let (resolved, next) = self.on_demand.on_closed(peer, now);
        if let Some(r) = resolved {
            self.resolve_unreachable(r, now);
        }
        if next == Next::Dial {
            self.on_demand_dial(peer);
        }
        self.promote_queued();
        self.check_over_cap(now);
    }

    /// An outbound connection failed. Returns whether it was an on-demand dial
    /// (its WARN becomes DEBUG + one INFO `swarm: on-demand dial failed`).
    pub(super) fn outgoing_conn_error(
        &mut self,
        peer: Option<PeerId>,
        cid: ConnectionId,
        error: &DialError,
        now: Instant,
    ) -> bool {
        let origin = self.dial_origin.remove(&cid).map(|(_, o, _)| o);
        let (resolved, next) = self
            .on_demand
            .on_dial_error(peer, cid, &error.to_string(), now);
        if let Some(r) = resolved {
            self.resolve_unreachable(r, now);
        }
        if next == Next::Dial
            && let Some(p) = peer
            && !self.swarm.is_connected(&p)
        {
            self.on_demand_dial(p);
        }
        self.promote_queued();
        origin == Some(DialOrigin::OnDemand)
    }

    /// `peer` completed the cert exchange: its waiters go out; when
    /// `cert_finished` (the dialer side — the listener's ends with its answer,
    /// `cert_answer_sent`) the cache's pass (the newcomer may push the oldest
    /// protected out).
    pub(super) fn conn_authenticated(&mut self, peer: PeerId, now: Instant, cert_finished: bool) {
        if let Some((_, waiters)) = self.on_demand.on_authenticated(&peer) {
            for w in waiters {
                // The request counts by itself before the waiter goes: the
                // peer is never free in between.
                self.send_app_request(peer, w.message, w.reply);
                self.remove_waiter(&peer, now);
            }
        }
        if cert_finished && let Some(lru) = self.lru.as_mut() {
            let victims = lru.on_authenticated(&peer, now);
            self.evict(victims, "auth", now);
        }
        self.promote_queued();
    }

    /// Listener side: our cert answer to `peer` was sent — the exchange is
    /// finished for the cache (fix round 1, N-1).
    pub(super) fn cert_answer_sent(&mut self, peer: PeerId, now: Instant) {
        if !self.authenticated.contains_key(&peer) {
            return;
        }
        if let Some(lru) = self.lru.as_mut() {
            // Our cert answer may still be on its way out: linger first.
            lru.linger(&peer, now);
            let victims = lru.on_authenticated(&peer, now);
            self.evict(victims, "auth", now);
        }
    }

    /// Remember where an outbound dial came from (`origin=`).
    pub(super) fn note_dial(&mut self, cid: ConnectionId, peer: PeerId, origin: DialOrigin) {
        self.dial_origin.insert(cid, (peer, origin, Instant::now()));
    }

    // ── The cache ─────────────────────────────────────────────────────────────

    /// Close the victims of a pass: out of `authenticated` at once (closing),
    /// then `disconnect_peer_id` (every connection of the peer).
    pub(super) fn evict(&mut self, victims: Vec<Victim>, trigger: &'static str, now: Instant) {
        if victims.is_empty() {
            return;
        }
        for v in victims {
            let device = self.authenticated.remove(&v.peer).map(|(d, _, _)| d);
            if let Some(d) = device {
                self.device_to_peer.remove(&d);
            }
            self.pending_cert.remove(&v.peer);
            self.evicted_at.insert(v.peer, now);
            if v.close_at > now && self.swarm.is_connected(&v.peer) {
                // Deferred close (fix round 2): we answered it just now; the
                // connection goes at `close_at` (`close_due`, 1-second tick).
                self.closing.insert(v.peer, device);
                self.pending_close.insert(v.peer, v.close_at);
            } else if self.swarm.disconnect_peer_id(v.peer).is_ok() {
                self.closing.insert(v.peer, device);
            } else {
                // Not connected after all: nothing will close; tell the processor now.
                emit_event(
                    &self.event_tx,
                    ProtocolEvent::ConnectionClosed {
                        peer_id: v.peer,
                        device_id: device,
                    },
                );
            }
            let (connected, busy, cap) = self.lru_log_counts(now);
            info!(
                peer_id = %v.peer,
                reason = %v.reason.as_str(),
                trigger = %trigger,
                evictable_for_ms = v.evictable_for.as_millis() as u64,
                close_in_ms = v.close_at.saturating_duration_since(now).as_millis() as u64,
                idle_secs = v.idle.as_secs(),
                connected,
                busy,
                cap,
                "lru: evicted peer"
            );
        }
        self.check_over_cap(now);
    }

    /// Close the evicted peers whose linger is over (deferred close; the
    /// 1-second tick). A peer that is gone by then is reported closed here.
    pub(super) fn close_due(&mut self) {
        let now = Instant::now();
        let due: Vec<PeerId> = self
            .pending_close
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(p, _)| *p)
            .collect();
        for peer in due {
            self.pending_close.remove(&peer);
            if !self.closing.contains_key(&peer) {
                continue; // connected again meanwhile, or already closed
            }
            if self.swarm.disconnect_peer_id(peer).is_err() {
                let device = self.closing.remove(&peer).flatten();
                emit_event(
                    &self.event_tx,
                    ProtocolEvent::ConnectionClosed {
                        peer_id: peer,
                        device_id: device,
                    },
                );
            }
        }
    }

    fn lru_log_counts(&self, now: Instant) -> (usize, usize, usize) {
        let connected = self.swarm.connected_peers().count();
        match self.lru.as_ref() {
            Some(lru) => (connected, lru.counts(now).busy, lru.cap()),
            None => (connected, 0, 0),
        }
    }

    /// `lru: over cap` when non-infra peers (closing excluded) exceed the cap,
    /// `lru: under cap` when they are back (v3.1 B1).
    fn check_over_cap(&mut self, now: Instant) {
        let Some(lru) = self.lru.as_ref() else {
            return;
        };
        let over = lru.non_infra_len() > lru.cap();
        match (over, self.over_cap_since) {
            (true, None) => {
                self.over_cap_since = Some(now);
                let (connected, busy, cap) = self.lru_log_counts(now);
                info!(connected, busy, cap, "lru: over cap");
            }
            (false, Some(since)) => {
                self.over_cap_since = None;
                self.all_busy_since = None;
                info!(
                    after_ms = now.duration_since(since).as_millis() as u64,
                    "lru: under cap"
                );
            }
            _ => {}
        }
    }

    /// The cache's 10-second tick: `tick late`, the pass, the hard-overshoot
    /// WARN, old evictions forgotten.
    pub(super) fn lru_tick(&mut self) {
        let now = Instant::now();
        let lag = now.duration_since(self.last_lru_tick);
        self.last_lru_tick = now;
        if lag > Duration::from_millis(LRU_TICK_LATE_MS) {
            warn!(lag_ms = lag.as_millis() as u64, "lru: tick late");
        }
        self.evicted_at
            .retain(|_, at| now.duration_since(*at) <= Duration::from_secs(LRU_REDIAL_WINDOW_SECS));
        let Some(lru) = self.lru.as_mut() else {
            return;
        };
        let victims = lru.victims(now);
        self.evict(victims, "tick", now);
        let Some(lru) = self.lru.as_ref() else {
            return;
        };
        let counts = lru.counts(now);
        let hard =
            self.over_cap_since.is_some() && counts.protected == 0 && counts.cert_pending == 0;
        if !hard {
            self.all_busy_since = None;
            return;
        }
        let since = *self.all_busy_since.get_or_insert(now);
        let due = self
            .last_all_busy_warn
            .is_none_or(|t| now.duration_since(t) >= ALL_BUSY_WARN_AFTER);
        if now.duration_since(since) >= ALL_BUSY_WARN_AFTER && due {
            self.last_all_busy_warn = Some(now);
            warn!(
                busy = counts.busy,
                entries = counts.entries,
                cap = lru.cap(),
                "lru: over cap, every peer busy"
            );
        }
    }

    /// `ConnStats` (network-i41): the same pass as the tick, then one snapshot.
    pub(super) fn conn_stats_snapshot(&mut self) -> ConnStats {
        let now = Instant::now();
        if let Some(lru) = self.lru.as_mut() {
            let victims = lru.victims(now);
            self.evict(victims, "stats", now);
        }
        let od = self.on_demand.counts(now);
        let (busy, protected, infra, cap, evictions_total) = match self.lru.as_ref() {
            Some(lru) => {
                let c = lru.counts(now);
                (
                    c.busy,
                    c.protected,
                    c.infra,
                    Some(lru.cap() as u32),
                    lru.evictions_total(),
                )
            }
            None => (0, 0, 0, None, 0),
        };
        ConnStats {
            connected: self.swarm.connected_peers().count() as u32,
            authenticated: self.authenticated.len() as u32,
            busy: busy as u32,
            protected: protected as u32,
            infra: infra as u32,
            closing: self.closing.len() as u32,
            cap,
            evictions_total,
            on_demand_ok: od.ok_total,
            on_demand_failed: od.failed_total,
            on_demand_inflight: od.inflight as u32,
            on_demand_queued: od.queued as u32,
            on_demand_abandoned: od.abandoned as u32,
            on_demand_neg_cached: od.neg_cached as u32,
            seed_role: self.seed_role,
            infra_peers: self.infra_peers.clone(),
        }
    }

    /// Unit tests only: evict `peer` as a pass would.
    #[cfg(test)]
    pub(super) fn test_evict(&mut self, peer: PeerId) -> bool {
        use crate::daemon::network::conn_lru::VictimReason;
        let now = Instant::now();
        let Some(lru) = self.lru.as_mut() else {
            return false;
        };
        if !lru.contains(&peer) {
            return false;
        }
        lru.on_disconnected(&peer);
        let victim = Victim {
            peer,
            reason: VictimReason::Idle,
            evictable_for: Duration::ZERO,
            idle: Duration::ZERO,
            close_at: now,
        };
        self.evict(vec![victim], "test", now);
        true
    }
}
