// Unit tests for the Kademlia feed from identify (C-DK Р-3, network-i18).

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

use super::{
    MAX_KAD_ADDR_BYTES, MAX_KAD_ADDR_BYTES_PER_PEER, MAX_KAD_ADDRS_PER_PEER, kad_dialed_addr,
    kad_feed_addrs, kad_replace_plan,
};

fn ma(s: &str) -> Multiaddr {
    s.parse().expect("valid multiaddr")
}

fn p2p(addr: &str, peer: PeerId) -> Multiaddr {
    ma(addr).with(Protocol::P2p(peer))
}

#[test]
fn kad_feed_drops_link_local_unspecified_and_documentation_ranges() {
    let peer = PeerId::random();
    let dropped = [
        "/ip4/169.254.3.4/tcp/4001",
        "/ip4/0.0.0.0/tcp/4001",
        "/ip4/192.0.2.7/tcp/4001",
        "/ip4/198.51.100.7/tcp/4001",
        "/ip4/203.0.113.7/tcp/4001",
        "/ip6/fe80::1/tcp/4001",
        "/ip6/febf::1/tcp/4001",
        "/ip6/::/tcp/4001",
        "/ip6/2001:db8::7/tcp/4001",
    ];
    let mut input: Vec<Multiaddr> = dropped.iter().map(|s| ma(s)).collect();
    let relay = PeerId::random();
    input.push(ma(&format!(
        "/ip4/1.2.3.4/tcp/4001/p2p/{relay}/p2p-circuit"
    )));
    let kept = ma("/ip4/1.2.3.4/tcp/4001");
    input.push(kept.clone());

    let out = kad_feed_addrs(peer, &input, None);
    assert_eq!(
        out,
        vec![kept.with(Protocol::P2p(peer))],
        "only the dialable global address survives"
    );
}

#[test]
fn kad_feed_ranks_global_then_private_then_loopback_and_caps_at_six() {
    let peer = PeerId::random();
    let input = vec![
        ma("/ip4/127.0.0.1/tcp/1"),
        ma("/ip6/::1/tcp/2"),
        ma("/ip4/10.0.0.1/tcp/3"),
        ma("/ip4/100.64.0.1/tcp/4"),
        ma("/ip6/fd00::1/tcp/5"),
        ma("/ip4/8.8.8.8/tcp/6"),
        ma("/ip4/192.168.1.1/tcp/7"),
        ma("/ip6/2a01::1/tcp/8"),
        ma("/ip4/172.16.0.1/tcp/9"),
    ];
    let out = kad_feed_addrs(peer, &input, None);
    let want: Vec<Multiaddr> = [
        "/ip4/8.8.8.8/tcp/6",
        "/ip6/2a01::1/tcp/8",
        "/ip4/10.0.0.1/tcp/3",
        "/ip4/100.64.0.1/tcp/4",
        "/ip6/fd00::1/tcp/5",
        "/ip4/192.168.1.1/tcp/7",
    ]
    .iter()
    .map(|s| p2p(s, peer))
    .collect();
    assert_eq!(out.len(), MAX_KAD_ADDRS_PER_PEER);
    assert_eq!(
        out, want,
        "global first, then private in announcement order, loopback cut by the cap"
    );
}

#[test]
fn kad_feed_always_keeps_dialed_addr_beyond_cap() {
    let peer = PeerId::random();
    // Twenty loopback aliases (the e2e amplifier) plus the address we dialed.
    let input: Vec<Multiaddr> = (2..22)
        .map(|k| ma(&format!("/ip4/127.0.0.{k}/tcp/4001")))
        .collect();
    let dialed = ma("/ip4/127.0.0.1/tcp/4001");
    let out = kad_feed_addrs(peer, &input, Some(&dialed));
    assert_eq!(out.len(), MAX_KAD_ADDRS_PER_PEER + 1);
    assert_eq!(out[0], dialed.with(Protocol::P2p(peer)), "dialed first");

    // The dialed address announced by identify too is not counted twice.
    let mut with_dialed = input.clone();
    with_dialed.insert(0, ma("/ip4/127.0.0.1/tcp/4001"));
    let out2 = kad_feed_addrs(
        peer,
        &with_dialed,
        Some(&p2p("/ip4/127.0.0.1/tcp/4001", peer)),
    );
    assert_eq!(out2, out);
}

#[test]
fn kad_feed_dedups_with_and_without_p2p_suffix() {
    let peer = PeerId::random();
    let input = vec![
        ma("/ip4/10.0.0.1/tcp/4001"),
        p2p("/ip4/10.0.0.1/tcp/4001", peer),
        ma("/ip4/10.0.0.2/tcp/4001"),
    ];
    let out = kad_feed_addrs(peer, &input, None);
    assert_eq!(
        out,
        vec![
            p2p("/ip4/10.0.0.1/tcp/4001", peer),
            p2p("/ip4/10.0.0.2/tcp/4001", peer)
        ]
    );
}

#[test]
fn kad_feed_drops_foreign_p2p_target() {
    let peer = PeerId::random();
    let other = PeerId::random();
    let input = vec![
        p2p("/ip4/10.0.0.1/tcp/4001", other),
        ma("/ip4/10.0.0.2/tcp/4001"),
    ];
    let out = kad_feed_addrs(peer, &input, None);
    assert_eq!(out, vec![p2p("/ip4/10.0.0.2/tcp/4001", peer)]);
}

#[test]
fn kad_replace_plan_adds_new_removes_stale_keeps_dialed() {
    let peer = PeerId::random();
    // libp2p keeps the dialed address without the /p2p/ suffix.
    let dialed = ma("/ip4/10.0.0.9/tcp/4001");
    let current = vec![
        dialed.clone(),
        p2p("/ip4/10.0.0.1/tcp/4001", peer),
        p2p("/ip4/10.0.0.2/tcp/4001", peer),
    ];
    // The peer restarted on a new port: the old identify addresses are stale.
    let want = vec![
        p2p("/ip4/10.0.0.1/tcp/5001", peer),
        p2p("/ip4/10.0.0.2/tcp/4001", peer),
    ];
    let (add, remove) = kad_replace_plan(peer, &current, &want, Some(&dialed));
    assert_eq!(add, vec![p2p("/ip4/10.0.0.1/tcp/5001", peer)]);
    assert_eq!(
        remove,
        vec![p2p("/ip4/10.0.0.1/tcp/4001", peer)],
        "the dialed address stays though identify no longer announces it"
    );
}

#[test]
fn kad_replace_plan_is_empty_when_record_matches() {
    let peer = PeerId::random();
    let want = vec![p2p("/ip4/10.0.0.1/tcp/4001", peer)];
    let current = vec![ma("/ip4/10.0.0.1/tcp/4001")];
    let (add, remove) = kad_replace_plan(peer, &current, &want, None);
    assert!(add.is_empty(), "same address with and without /p2p/");
    assert!(remove.is_empty());
}

/// `/dns4/<name of `len` characters>/tcp/<port>`: Global rank, length chosen.
fn dns(len: usize, port: u16) -> Multiaddr {
    ma(&format!("/dns4/{}/tcp/{port}", "a".repeat(len)))
}

/// The DNS name length whose address, `/p2p/<peer>` included, is `bytes` long
/// (names under 128 characters: one length byte).
fn dns_of_bytes(peer: PeerId, bytes: usize, port: u16) -> Multiaddr {
    let overhead = dns(0, port).with(Protocol::P2p(peer)).len();
    let addr = dns(bytes - overhead, port);
    assert_eq!(addr.clone().with(Protocol::P2p(peer)).len(), bytes);
    addr
}

/// network-i20: an address longer than MAX_KAD_ADDR_BYTES (suffix included)
/// is dropped, however well it ranks; one at the limit is kept. A 255-character
/// DNS name — what a hostile peer announces to inflate our answers — is out.
#[test]
fn kad_feed_drops_oversized_addresses() {
    let peer = PeerId::random();
    let at_limit = dns_of_bytes(peer, MAX_KAD_ADDR_BYTES, 1);
    let over_limit = dns_of_bytes(peer, MAX_KAD_ADDR_BYTES + 1, 2);
    let input = vec![
        dns(255, 3),
        over_limit,
        at_limit.clone(),
        ma("/ip4/10.0.0.1/tcp/4001"),
    ];
    let out = kad_feed_addrs(peer, &input, None);
    assert_eq!(
        out,
        vec![
            at_limit.with(Protocol::P2p(peer)),
            p2p("/ip4/10.0.0.1/tcp/4001", peer)
        ],
        "oversized names dropped, not counted against the cap"
    );
    assert!(out.iter().all(|a| a.len() <= MAX_KAD_ADDR_BYTES));
}

/// network-i20: the byte budget holds the dialed address (first) and the
/// identify addresses taken in rank order; one that does not fit is skipped
/// and a shorter one after it still goes in. Four 120 B names fit next to a
/// ≈ 45 B dialed address (≈ 525 B), a fifth would make ≈ 645 B > 640.
#[test]
fn kad_feed_respects_per_peer_byte_budget() {
    let peer = PeerId::random();
    let dialed = ma("/ip4/127.0.0.1/tcp/4001");
    let names: Vec<Multiaddr> = (1..=6).map(|k| dns_of_bytes(peer, 120, k)).collect();
    let mut input = names.clone();
    input.push(ma("/ip4/8.8.8.8/tcp/1")); // Global too, announced last, ≈ 45 B
    let out = kad_feed_addrs(peer, &input, Some(&dialed));

    let mut want = vec![dialed.with(Protocol::P2p(peer))];
    want.extend(
        names[..4]
            .iter()
            .map(|a| a.clone().with(Protocol::P2p(peer))),
    );
    want.push(p2p("/ip4/8.8.8.8/tcp/1", peer));
    assert_eq!(out, want);
    let bytes: usize = out.iter().map(Multiaddr::len).sum();
    assert!(
        bytes <= MAX_KAD_ADDR_BYTES_PER_PEER,
        "{bytes} B over the budget"
    );
    assert!(out.len() <= MAX_KAD_ADDRS_PER_PEER + 1);
}

/// network-i20 over i18: a dialed address over MAX_KAD_ADDR_BYTES is neither
/// fed nor protected, so the record left by libp2p with it is cleaned by the
/// replace plan (after the new addresses go in).
#[test]
fn kad_feed_oversized_dialed_addr_is_not_kept() {
    let peer = PeerId::random();
    let dialed = dns_of_bytes(peer, MAX_KAD_ADDR_BYTES + 1, 4001);
    assert_eq!(kad_dialed_addr(peer, Some(&dialed)), None);
    let short = ma("/ip4/127.0.0.1/tcp/4001");
    assert_eq!(
        kad_dialed_addr(peer, Some(&short)),
        Some(short.with(Protocol::P2p(peer)))
    );

    let identify = vec![ma("/ip4/10.0.0.1/tcp/4001")];
    let want = kad_feed_addrs(peer, &identify, Some(&dialed));
    assert_eq!(want, vec![p2p("/ip4/10.0.0.1/tcp/4001", peer)]);
    let current = vec![dialed.clone().with(Protocol::P2p(peer))];
    let keep = kad_dialed_addr(peer, Some(&dialed));
    let (add, remove) = kad_replace_plan(peer, &current, &want, keep.as_ref());
    assert_eq!(add, want);
    assert_eq!(remove, current, "the oversized dialed address goes");
}
