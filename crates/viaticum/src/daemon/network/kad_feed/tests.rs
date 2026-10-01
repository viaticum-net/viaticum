// Unit tests for the Kademlia feed from identify (C-DK Р-3, network-i18).

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

use super::{MAX_KAD_ADDRS_PER_PEER, kad_feed_addrs, kad_replace_plan};

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
