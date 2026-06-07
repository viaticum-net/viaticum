use super::*;

fn s(v: &str) -> String {
    v.to_string()
}

#[test]
fn select_display_addr_returns_none_for_empty() {
    assert_eq!(select_display_base_addr(&[]), None);
}

#[test]
fn select_display_addr_prefers_routable_ipv4_over_ipv6_loopback() {
    // Regression: ::1 is loopback too. With ip6 loopback ordered first, the old
    // filter (only excluding 127.0.0.1) picked the useless /ip6/::1/ address.
    let addrs = vec![
        s("/ip6/::1/tcp/46181"),
        s("/ip4/127.0.0.1/tcp/35707"),
        s("/ip4/192.168.12.87/tcp/35707"),
    ];
    assert_eq!(
        select_display_base_addr(&addrs),
        Some(s("/ip4/192.168.12.87/tcp/35707"))
    );
}

#[test]
fn select_display_addr_prefers_routable_ipv4_even_when_listed_last() {
    let addrs = vec![
        s("/ip6/fe80::1/tcp/40817"),
        s("/ip4/10.147.17.26/tcp/37001"),
    ];
    assert_eq!(
        select_display_base_addr(&addrs),
        Some(s("/ip4/10.147.17.26/tcp/37001"))
    );
}

#[test]
fn select_display_addr_falls_back_to_routable_ipv6_when_no_ipv4() {
    let addrs = vec![s("/ip6/::1/tcp/40817"), s("/ip6/2001:db8::5/tcp/40817")];
    assert_eq!(
        select_display_base_addr(&addrs),
        Some(s("/ip6/2001:db8::5/tcp/40817"))
    );
}

#[test]
fn select_display_addr_excludes_ipv6_loopback() {
    let addrs = vec![s("/ip6/::1/tcp/40817"), s("/ip4/127.0.0.1/tcp/35707")];
    // Both are loopback → no routable candidate → falls back to first.
    assert_eq!(
        select_display_base_addr(&addrs),
        Some(s("/ip6/::1/tcp/40817"))
    );
}

#[test]
fn select_display_addr_returns_only_address_when_single() {
    let addrs = vec![s("/ip4/192.168.1.5/tcp/12345")];
    assert_eq!(
        select_display_base_addr(&addrs),
        Some(s("/ip4/192.168.1.5/tcp/12345"))
    );
}
