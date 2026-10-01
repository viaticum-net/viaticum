// Connection policy of a swarm and the cache snapshot it reports (C-DK Р-15,
// Р-11, network-i41..i43).

#[cfg(test)]
mod tests;

use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use viaticum_core::config::RelayRole;
use viaticum_core::constants::{CONN_CAP, CONN_HANDSHAKE_GRACE_SECS, INFRA_CONN_LIMIT};

use super::peer_id_from_multiaddr;
use crate::daemon::network::address_book::AddressBook;
use crate::daemon::network::conn_lru::InfraRule;

/// How many of a friend's bootstrap peers are infrastructure ("1–2 connections
/// with the relay", Ilya's Р-8 (б)).
const FRIEND_INFRA_PEERS: usize = 2;

/// Connection policy of a swarm (C-DK Р-15). One field of `SwarmConfig`, so the
/// daemon and the DR swap differ by one expression.
pub struct ConnPolicy {
    /// Connection cache cap (network-i41); None = no cache (the DR swap, most
    /// tests).
    pub cap: Option<usize>,
    /// Dial a known but unconnected peer inside `send_to_device` (network-i42).
    pub dial_on_demand: bool,
    /// The PeerRecord table: seeds the known set (Р-5′) and gives the on-demand
    /// dial its addresses. None = the known set holds only peers met since start.
    pub address_book: Option<AddressBook>,
    /// Who is infrastructure (network-i41).
    pub infra: InfraRule,
    /// The daemon's time_scale. Some(ts): the Kademlia cadence settles (Р-17),
    /// the negative-cache ceiling is max(1800 / ts, 60) s and a re-authentication
    /// wakes the work pipeline at most every 600 / ts s per device (Р-18).
    /// None: the cadence never settles (DR swap, tests) — discovery + bootstrap
    /// at the fixed interval, as libp2p's periodic bootstrap did before C4.
    pub time_scale: Option<u64>,
    /// How long a handshake-only connection is protected (CONN_HANDSHAKE_GRACE_SECS;
    /// tests shorten it).
    pub handshake_grace: Duration,
}

impl ConnPolicy {
    /// A friend: cache cap 48, dial on demand; infrastructure = the first ≤ 2
    /// DISTINCT PeerIds (`/p2p/`) of `bootstrap` (two addresses of one seed are
    /// one peer).
    pub fn friend(book: AddressBook, bootstrap: &[Multiaddr], time_scale: u64) -> Self {
        Self {
            cap: Some(CONN_CAP),
            dial_on_demand: true,
            address_book: Some(book),
            infra: InfraRule::Peers(friend_infra_peers(bootstrap)),
            time_scale: Some(time_scale.max(1)),
            handshake_grace: Duration::from_secs(CONN_HANDSHAKE_GRACE_SECS),
        }
    }

    /// A seed (`relay_role = "punch"`): cache cap 48, dial on demand;
    /// infrastructure = every peer up to INFRA_CONN_LIMIT; redial dials every
    /// known peer (floor = ∞).
    pub fn seed(book: AddressBook, time_scale: u64) -> Self {
        Self {
            cap: Some(CONN_CAP),
            dial_on_demand: true,
            address_book: Some(book),
            infra: InfraRule::AllUpTo(INFRA_CONN_LIMIT),
            time_scale: Some(time_scale.max(1)),
            handshake_grace: Duration::from_secs(CONN_HANDSHAKE_GRACE_SECS),
        }
    }

    /// The daemon's policy by its `relay_role`: `punch` → [`ConnPolicy::seed`],
    /// otherwise [`ConnPolicy::friend`].
    pub fn for_role(
        role: RelayRole,
        book: AddressBook,
        bootstrap: &[Multiaddr],
        time_scale: u64,
    ) -> Self {
        match role {
            RelayRole::Punch => Self::seed(book, time_scale),
            RelayRole::Off => Self::friend(book, bootstrap, time_scale),
        }
    }

    /// No cache, no on-demand dial, no address book, nobody is infrastructure,
    /// the cadence never settles: the DR swap and tests. Discovery still skips
    /// peers met since start (v3.1 N2).
    pub fn off() -> Self {
        Self {
            cap: None,
            dial_on_demand: false,
            address_book: None,
            infra: InfraRule::None,
            time_scale: None,
            handshake_grace: Duration::from_secs(CONN_HANDSHAKE_GRACE_SECS),
        }
    }

    /// The seed role: redial dials every known peer.
    pub(crate) fn is_seed(&self) -> bool {
        matches!(self.infra, InfraRule::AllUpTo(_))
    }
}

/// The first ≤ 2 distinct PeerIds named by `bootstrap` (addresses without a
/// `/p2p/` are skipped, as Kademlia skips them).
pub(crate) fn friend_infra_peers(bootstrap: &[Multiaddr]) -> Vec<PeerId> {
    let mut out: Vec<PeerId> = Vec::new();
    for addr in bootstrap {
        if out.len() == FRIEND_INFRA_PEERS {
            break;
        }
        if let Some(p) = peer_id_from_multiaddr(addr)
            && !out.contains(&p)
        {
            out.push(p);
        }
    }
    out
}

/// One snapshot of the connection cache, taken in one event-loop turn right
/// after an eviction pass (network-i41, `status --json`). The invariant on any
/// snapshot: `connected − busy − infra − closing ≤ cap` and `protected ≤ 16`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnStats {
    /// Peers with a live connection (closing ones included).
    pub connected: u32,
    /// Peers that completed the cert exchange (closing ones excluded).
    pub authenticated: u32,
    /// Connected non-infra peers that are busy (cert pending, request in
    /// flight, waiter, protected).
    pub busy: u32,
    /// Busy because only a handshake, young, among the youngest 16.
    pub protected: u32,
    /// Infrastructure peers (outside the cap).
    pub infra: u32,
    /// Evicted, connection not closed yet.
    pub closing: u32,
    /// The cache cap; None = no cache.
    pub cap: Option<u32>,
    pub evictions_total: u64,
    pub on_demand_ok: u64,
    pub on_demand_failed: u64,
    pub on_demand_inflight: u32,
    pub on_demand_queued: u32,
    pub on_demand_abandoned: u32,
    pub on_demand_neg_cached: u32,
    /// The seed role (redial floor = ∞).
    pub seed_role: bool,
    /// A friend's infrastructure peers (redial dials them every pass).
    pub infra_peers: Vec<PeerId>,
}
