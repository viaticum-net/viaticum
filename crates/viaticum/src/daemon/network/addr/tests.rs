// `node_addr` of `status` (network-i27, R2a part: no relay circuits).

use libp2p::Multiaddr;

use super::{NodeAddr, select_node_addr};

fn ma(v: &str) -> Multiaddr {
    v.parse().expect("multiaddr")
}

fn pick(external: &[&str], listen: &[&str]) -> Option<(String, bool)> {
    let e: Vec<Multiaddr> = external.iter().map(|a| ma(a)).collect();
    let l: Vec<Multiaddr> = listen.iter().map(|a| ma(a)).collect();
    select_node_addr(&e, &l).map(|NodeAddr { addr, lan_only }| (addr.to_string(), lan_only))
}

#[test]
fn node_addr_is_none_without_addresses() {
    assert_eq!(pick(&[], &[]), None);
}

// A home node with no confirmed external address: its LAN address, said to
// be LAN only. Mutation: lan_only always false → red.
#[test]
fn node_addr_without_external_is_lan_address_marked_lan_only() {
    let listen = [
        "/ip6/::1/tcp/46181",
        "/ip4/127.0.0.1/tcp/23817",
        "/ip6/fe80::1/tcp/23817",
        "/ip4/192.168.12.87/tcp/23817",
    ];
    assert_eq!(
        pick(&[], &listen),
        Some(("/ip4/192.168.12.87/tcp/23817".to_string(), true))
    );
}

// Mutation: listen addresses before external ones → the LAN address wins, red.
#[test]
fn node_addr_prefers_confirmed_external_over_listen() {
    let external = ["/ip4/198.18.0.7/tcp/23817"];
    let listen = ["/ip4/192.168.1.5/tcp/23817"];
    assert_eq!(
        pick(&external, &listen),
        Some(("/ip4/198.18.0.7/tcp/23817".to_string(), false))
    );
}

#[test]
fn node_addr_prefers_quic_over_tcp_and_global_over_private() {
    let external = [
        "/ip4/10.0.0.2/udp/23817/quic-v1",
        "/ip4/198.18.0.7/tcp/23817",
        "/ip4/198.18.0.7/udp/23817/quic-v1",
    ];
    assert_eq!(
        pick(&external, &[]),
        Some(("/ip4/198.18.0.7/udp/23817/quic-v1".to_string(), false))
    );
}

// R2a: a relay circuit is never node_addr (it comes with R2b, after the
// direct addresses).
#[test]
fn node_addr_skips_relay_circuit() {
    let external = [
        "/ip4/198.18.0.2/tcp/27210/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit",
    ];
    let listen = ["/ip4/192.168.1.5/tcp/23817"];
    assert_eq!(
        pick(&external, &listen),
        Some(("/ip4/192.168.1.5/tcp/23817".to_string(), true))
    );
}

#[test]
fn node_addr_prefers_ipv4_within_the_same_reach() {
    let listen = ["/ip6/fd00::5/tcp/23817", "/ip4/10.147.17.26/tcp/23817"];
    assert_eq!(
        pick(&[], &listen),
        Some(("/ip4/10.147.17.26/tcp/23817".to_string(), true))
    );
}

// Only addresses nobody else can dial: the first one, LAN only (as before:
// a node always shows something).
#[test]
fn node_addr_falls_back_to_first_listen_address() {
    let listen = ["/ip6/fe80::1/tcp/40817", "/ip4/0.0.0.0/tcp/40817"];
    assert_eq!(
        pick(&[], &listen),
        Some(("/ip6/fe80::1/tcp/40817".to_string(), true))
    );
}

// The caller appends `/p2p/<us>`: an external address carrying it already
// comes back without it (no double suffix).
#[test]
fn node_addr_drops_terminal_p2p_of_external() {
    let external =
        ["/ip4/198.18.0.7/tcp/23817/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"];
    assert_eq!(
        pick(&external, &[]),
        Some(("/ip4/198.18.0.7/tcp/23817".to_string(), false))
    );
}

// Review W1: an unconfirmed global IPv6 we listen on does not beat a private
// IPv4 and, when it is all there is, is still LAN only (a home router usually
// drops inbound IPv6). Mutation: listen ranked reach-first or lan_only from
// reach alone → red.
#[test]
fn node_addr_unconfirmed_global_ipv6_is_lan_only_and_after_ipv4() {
    let listen = ["/ip6/2a01:4f8::5/tcp/23817", "/ip4/192.168.1.5/tcp/23817"];
    assert_eq!(
        pick(&[], &listen),
        Some(("/ip4/192.168.1.5/tcp/23817".to_string(), true))
    );
    assert_eq!(
        pick(&[], &["/ip6/2a01:4f8::5/tcp/23817"]),
        Some(("/ip6/2a01:4f8::5/tcp/23817".to_string(), true))
    );
    // A global IPv4 we listen on (a VPS) is reachable as is.
    assert_eq!(
        pick(
            &[],
            &["/ip4/192.168.1.5/tcp/23817", "/ip4/198.18.0.7/tcp/23817"]
        ),
        Some(("/ip4/198.18.0.7/tcp/23817".to_string(), false))
    );
}
