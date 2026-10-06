// Unit tests of the listen-port pick (network-i31): real sockets on 127.0.0.1.

use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};

use viaticum_core::constants::LISTEN_PORT_RANGE;

use super::{PortProtocols, is_denied, pick_from, pick_listen_port};

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A port free for TCP and UDP on 127.0.0.1 right now (bound to 0, released).
fn free_port() -> u16 {
    loop {
        let port = TcpListener::bind((LOCAL, 0))
            .expect("bind 0")
            .local_addr()
            .unwrap()
            .port();
        if UdpSocket::bind((LOCAL, port)).is_ok() {
            return port;
        }
    }
}

#[test]
fn pick_listen_port_returns_free_allowed_port_in_range() {
    let port = pick_listen_port(LISTEN_PORT_RANGE, &[], PortProtocols::TcpAndUdp, LOCAL)
        .expect("a free port among 32 random candidates");
    assert!(LISTEN_PORT_RANGE.contains(&port), "{port} out of range");
    assert!(!is_denied(port), "{port} is denylisted");
}

// Mutation: drop the denylist / exclude / busy check → the first candidate wins
// and the test goes red.
#[test]
fn pick_listen_port_skips_denylist_excluded_and_busy_port() {
    let busy = TcpListener::bind((LOCAL, 0)).expect("bind busy");
    let busy_port = busy.local_addr().unwrap().port();
    let excluded = free_port();
    let free = free_port();
    let got = pick_from(
        [27015, 0, busy_port, excluded, free],
        &[excluded],
        PortProtocols::TcpAndUdp,
        LOCAL,
    );
    assert_eq!(got, Some(free));
    drop(busy);
}

// Mutation: probe only TCP for the libp2p port → the UDP-busy number is picked,
// test red.
#[test]
fn pick_listen_port_skips_number_busy_only_on_udp() {
    // A UDP socket whose number is free on TCP (almost always the first one).
    let (udp, udp_port) = (0..20)
        .map(|_| {
            let udp = UdpSocket::bind((LOCAL, 0)).expect("bind udp");
            let port = udp.local_addr().unwrap().port();
            (udp, port)
        })
        .find(|(_, port)| TcpListener::bind((LOCAL, *port)).is_ok())
        .expect("a UDP port whose number is free on TCP");
    let free = free_port();
    let both = pick_from([udp_port, free], &[], PortProtocols::TcpAndUdp, LOCAL);
    assert_eq!(both, Some(free), "the libp2p port needs UDP free too");
    let tcp = pick_from([udp_port, free], &[], PortProtocols::Tcp, LOCAL);
    assert_eq!(tcp, Some(udp_port), "the web port needs only TCP");
    drop(udp);
}

#[test]
fn pick_listen_port_is_none_when_every_candidate_fails() {
    let busy = TcpListener::bind((LOCAL, 0)).expect("bind busy");
    let busy_port = busy.local_addr().unwrap().port();
    assert_eq!(
        pick_from([busy_port, 27210, 22000], &[], PortProtocols::Tcp, LOCAL),
        None
    );
    drop(busy);
}

// ── port_change_notice (network-i47) ──

// Mutation: drop the `new == old` comparison → `..._same_port_...` red; return
// `None` always → this one red.
#[test]
fn port_change_notice_when_old_port_differs_then_names_both() {
    assert_eq!(
        super::port_change_notice(Some(24_567), 21_034).as_deref(),
        Some("listen port changed: 24567 → 21034; update the router's port forward")
    );
}

#[test]
fn port_change_notice_when_same_port_then_silent() {
    assert_eq!(super::port_change_notice(Some(24_567), 24_567), None);
}

#[test]
fn port_change_notice_when_old_port_unknown_then_silent() {
    assert_eq!(super::port_change_notice(None, 21_034), None);
    assert_eq!(
        super::port_change_notice(Some(0), 21_034),
        None,
        "an ephemeral old port had no forward"
    );
}

#[test]
fn port_change_notice_when_new_port_ephemeral_then_silent() {
    assert_eq!(super::port_change_notice(Some(24_567), 0), None);
}
