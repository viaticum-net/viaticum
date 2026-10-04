// Unit tests for the test-only peer-record amplifier (C-DK Р-10).

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

use super::{MAX_LOOPBACK_ALIASES, loopback_alias_addrs, parse_alias_count};

#[test]
fn alias_count_absent_or_empty_is_zero() {
    assert_eq!(parse_alias_count(None), Ok(0));
    assert_eq!(parse_alias_count(Some("")), Ok(0));
    assert_eq!(parse_alias_count(Some(" 20 ")), Ok(20));
}

#[test]
fn alias_count_rejects_garbage_and_too_many() {
    assert!(parse_alias_count(Some("twenty")).is_err());
    assert!(parse_alias_count(Some("-1")).is_err());
    assert!(parse_alias_count(Some(&(MAX_LOOPBACK_ALIASES + 1).to_string())).is_err());
    assert_eq!(
        parse_alias_count(Some(&MAX_LOOPBACK_ALIASES.to_string())),
        Ok(MAX_LOOPBACK_ALIASES)
    );
}

#[test]
fn aliases_reuse_the_ipv4_listen_port_from_127_0_0_2() {
    let listen: Multiaddr = "/ip4/192.168.1.5/tcp/27001".parse().unwrap();
    let got = loopback_alias_addrs(&listen, 3);
    let want: Vec<Multiaddr> = [
        "/ip4/127.0.0.2/tcp/27001",
        "/ip4/127.0.0.3/tcp/27001",
        "/ip4/127.0.0.4/tcp/27001",
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect();
    assert_eq!(got, want);
}

/// The v6 listener of a node with an ephemeral port has its own port: aliases of
/// that port on 127.0.0.k would be dead and melt out of the peers' tables.
#[test]
fn aliases_empty_for_an_ipv6_listener() {
    let v6: Multiaddr = "/ip6/::1/tcp/27001".parse().unwrap();
    assert!(loopback_alias_addrs(&v6, 3).is_empty());
}

#[test]
fn aliases_empty_for_zero_or_non_tcp_listen_addr() {
    let listen: Multiaddr = "/ip4/127.0.0.1/tcp/27001".parse().unwrap();
    assert!(loopback_alias_addrs(&listen, 0).is_empty());
    let udp: Multiaddr = "/ip4/127.0.0.1/udp/27001/quic-v1".parse().unwrap();
    assert!(loopback_alias_addrs(&udp, 5).is_empty());
    let circuit = "/ip4/1.2.3.4/tcp/4001"
        .parse::<Multiaddr>()
        .unwrap()
        .with(Protocol::P2p(PeerId::random()))
        .with(Protocol::P2pCircuit);
    assert!(loopback_alias_addrs(&circuit, 5).is_empty());
}

#[test]
fn aliases_capped_at_127_0_0_255() {
    let listen: Multiaddr = "/ip4/0.0.0.0/tcp/1".parse().unwrap();
    let got = loopback_alias_addrs(&listen, 10_000);
    assert_eq!(got.len(), MAX_LOOPBACK_ALIASES);
    assert_eq!(got.last().unwrap().to_string(), "/ip4/127.0.0.255/tcp/1");
}
