// What a peer's Kademlia record is fed from identify (C-DK Р-3, network-i18, i20).
//
// Our node answers FIND_NODE with up to k = 20 closer peers and every address it
// holds for each of them. Fed raw, a peer with dozens of interfaces (a NAS with
// docker, IPv6, a VPN — or the e2e amplifier) makes that answer outgrow the
// 16 KiB Kademlia frame, the asker fails to decode it, and discovery goes deaf
// for everyone (H1, measured in C1: 24724 B and 45124 B answers). So identify
// feeds Kademlia a bounded set:
//   - addresses no other machine can dial are dropped (link-local, unspecified,
//     documentation ranges), so are relay circuits and addresses whose terminal
//     `/p2p/` names another peer;
//   - so is any address longer than MAX_KAD_ADDR_BYTES (a DNS name may be 255
//     characters, and nothing else bounds an announced address);
//   - the rest are ranked global → private → loopback and taken in that order
//     while they fit MAX_KAD_ADDRS_PER_PEER and the per-peer byte budget
//     MAX_KAD_ADDR_BYTES_PER_PEER;
//   - the address we dialed the peer on comes first and is kept beyond the
//     count cap (inside the byte budget): it is known to work (network-i4), and
//     it is never removed from the record, so a record never empties while its
//     addresses are replaced.
// The byte budget, not the count, is what bounds the answer: see the arithmetic
// at MAX_KAD_ADDR_BYTES_PER_PEER. The PeerRecord is NOT touched by this: it
// keeps every identify address (R2, network-i2/i4).

#[cfg(test)]
mod tests;

use std::net::{Ipv4Addr, Ipv6Addr};

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

use super::swarm::strip_peer_suffix;

/// Identify addresses per peer that go into our Kademlia table (network-i18),
/// on top of the address we dialed the peer on.
pub(crate) const MAX_KAD_ADDRS_PER_PEER: usize = 6;

/// Longest address (bytes, `/p2p/<peer>` suffix included — the form Kademlia
/// stores and sends) that goes into our Kademlia table (network-i20). Real
/// routes are far shorter: `/ip6/…/tcp/…/p2p/<ed25519 id>` is 61 B,
/// `/dns4/<40 characters>/tcp/…/p2p/…` 86 B. A longer one is dropped, not cut.
pub(crate) const MAX_KAD_ADDR_BYTES: usize = 128;

/// Bytes of addresses per peer in our Kademlia table, the dialed address
/// included (network-i20). This, not the count, is what bounds our largest
/// answer, FIND_NODE with k = 20 closer peers, each a protobuf `Peer` of
/// ≈ 45 B (id 38 B + tags, connection type) plus its addresses with ≤ 2 B of
/// tag and length each (≤ 7 of them):
///   20 × (≈45 + 640 + 7 × 2) ≈ 14 KB < 16384 (`KAD_MAX_PACKET_SIZE`).
/// Without it, nine peers announcing six 300 B DNS names each (it fits a
/// 4 KiB identify) are enough to push an answer over the frame.
pub(crate) const MAX_KAD_ADDR_BYTES_PER_PEER: usize = 640;

/// Rank of an address for the Kademlia record: lower goes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Reach {
    /// Routable from anywhere (and DNS names).
    Global,
    /// RFC 1918, 100.64/10 (CGNAT), fc00::/7.
    Private,
    /// 127/8, ::1.
    Loopback,
}

/// The rank of `transport` (no `/p2p/` suffix), or `None` when no other machine
/// can dial it (dropped from the record).
fn reach(transport: &Multiaddr) -> Option<Reach> {
    if transport
        .iter()
        .any(|p| matches!(p, Protocol::P2pCircuit | Protocol::P2p(_)))
    {
        // A relay circuit names the relay, not a route to the peer (R2); a
        // `/p2p/` left in the middle is the same kind of address.
        return None;
    }
    match transport.iter().next() {
        Some(Protocol::Ip4(ip)) => reach_v4(ip),
        Some(Protocol::Ip6(ip)) => reach_v6(ip),
        // DNS names and anything else we cannot classify are taken as global:
        // dropping what we do not understand would lose working routes.
        Some(_) => Some(Reach::Global),
        None => None,
    }
}

fn reach_v4(ip: Ipv4Addr) -> Option<Reach> {
    let o = ip.octets();
    let documentation = matches!(
        (o[0], o[1], o[2]),
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
    );
    if ip.is_unspecified() || ip.is_link_local() || documentation {
        return None;
    }
    if ip.is_loopback() {
        return Some(Reach::Loopback);
    }
    let cgnat = o[0] == 100 && (o[1] & 0xC0) == 64;
    if ip.is_private() || cgnat {
        return Some(Reach::Private);
    }
    Some(Reach::Global)
}

fn reach_v6(ip: Ipv6Addr) -> Option<Reach> {
    let s = ip.segments();
    let link_local = (s[0] & 0xFFC0) == 0xFE80;
    let documentation = s[0] == 0x2001 && s[1] == 0x0DB8;
    if ip.is_unspecified() || link_local || documentation {
        return None;
    }
    if ip.is_loopback() {
        return Some(Reach::Loopback);
    }
    if (s[0] & 0xFE00) == 0xFC00 {
        return Some(Reach::Private);
    }
    Some(Reach::Global)
}

/// The address we dialed `peer` on as it may stay in our Kademlia record
/// (`/p2p/<peer>` suffix), or `None`: not dialed, a terminal `/p2p/` naming
/// another peer, or longer than MAX_KAD_ADDR_BYTES. An oversized dialed address
/// gets no exemption: the caller does not protect it in [`kad_replace_plan`],
/// so it is removed like any stale one (network-i20 over "the dialed address
/// stays"). It cannot arise today — we dial over TCP only, with no DNS
/// transport, so a dialed address is ≤ 61 B; the rule keeps the bound from
/// resting on that.
pub(crate) fn kad_dialed_addr(peer: PeerId, dialed: Option<&Multiaddr>) -> Option<Multiaddr> {
    dialed
        .and_then(|a| strip_peer_suffix(a, peer).ok())
        .map(|t| t.with(Protocol::P2p(peer)))
        .filter(|a| a.len() <= MAX_KAD_ADDR_BYTES)
}

/// network-i18, i20: the addresses of `peer` to hold in our Kademlia table
/// after it announced `identify_addrs`, each ending in exactly one
/// `/p2p/<peer>`.
///
/// The address we dialed `peer` on (`dialed`, relay circuits never stored there)
/// comes first ([`kad_dialed_addr`] decides whether it may) and is not counted
/// against the count cap, only against the byte budget. Then identify
/// addresses: dialable from another machine, at most MAX_KAD_ADDR_BYTES each,
/// deduplicated, ranked global → private → loopback (announcement order kept
/// within a rank), taken in that order while they fit MAX_KAD_ADDRS_PER_PEER
/// and MAX_KAD_ADDR_BYTES_PER_PEER (one that does not fit the budget is
/// skipped, a shorter one after it may still fit).
pub(crate) fn kad_feed_addrs(
    peer: PeerId,
    identify_addrs: &[Multiaddr],
    dialed: Option<&Multiaddr>,
) -> Vec<Multiaddr> {
    let dialed_transport = dialed.and_then(|a| strip_peer_suffix(a, peer).ok());
    let mut ranked: Vec<(Reach, Multiaddr)> = Vec::new();
    for addr in identify_addrs {
        let Ok(transport) = strip_peer_suffix(addr, peer) else {
            continue; // the terminal /p2p/ names another peer
        };
        let Some(rank) = reach(&transport) else {
            continue;
        };
        if dialed_transport.as_ref() == Some(&transport)
            || ranked.iter().any(|(_, t)| *t == transport)
        {
            continue;
        }
        ranked.push((rank, transport));
    }
    // Stable: announcement order stays within a rank.
    ranked.sort_by_key(|(rank, _)| *rank);

    let mut out: Vec<Multiaddr> = kad_dialed_addr(peer, dialed).into_iter().collect();
    let mut bytes: usize = out.iter().map(Multiaddr::len).sum();
    let mut taken = 0;
    for (_, transport) in ranked {
        if taken == MAX_KAD_ADDRS_PER_PEER {
            break;
        }
        let addr = transport.with(Protocol::P2p(peer));
        if addr.len() > MAX_KAD_ADDR_BYTES || bytes + addr.len() > MAX_KAD_ADDR_BYTES_PER_PEER {
            continue;
        }
        bytes += addr.len();
        taken += 1;
        out.push(addr);
    }
    out
}

/// How to turn the record `current` (what our table holds for `peer`) into
/// `want` (from [`kad_feed_addrs`]): addresses to add, then addresses to remove.
/// The caller applies them in that order, so the record never empties on the
/// way (removing a peer's last address drops the peer from the table). The
/// address we dialed `peer` on — as [`kad_dialed_addr`] passes it, `None` when
/// it is oversized — is never removed. Addresses are compared without
/// their `/p2p/` suffix (libp2p stores the dialed one without it).
pub(crate) fn kad_replace_plan(
    peer: PeerId,
    current: &[Multiaddr],
    want: &[Multiaddr],
    dialed: Option<&Multiaddr>,
) -> (Vec<Multiaddr>, Vec<Multiaddr>) {
    let bare = |a: &Multiaddr| strip_peer_suffix(a, peer).ok();
    let current_bare: Vec<Option<Multiaddr>> = current.iter().map(bare).collect();
    let want_bare: Vec<Option<Multiaddr>> = want.iter().map(bare).collect();
    let dialed_bare = dialed.and_then(bare);
    let add = want
        .iter()
        .zip(&want_bare)
        .filter(|(_, b)| !current_bare.contains(b))
        .map(|(a, _)| a.clone())
        .collect();
    let remove = current
        .iter()
        .zip(&current_bare)
        .filter(|(_, b)| !want_bare.contains(b))
        .filter(|(_, b)| dialed_bare.is_none() || **b != dialed_bare)
        .map(|(a, _)| a.clone())
        .collect();
    (add, remove)
}
