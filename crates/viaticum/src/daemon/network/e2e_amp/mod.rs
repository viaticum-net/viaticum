// Test-only amplifier of peer-record size (C-DK Р-10). Compiled only with the
// `e2e-tools` feature; a user build has none of it.
//
// With env VIATICUM_E2E_LOOPBACK_ALIASES=N the node advertises N loopback
// aliases `/ip4/127.0.0.k/tcp/P` (k = 2..=N+1) of its TCP listen port P as
// external addresses. identify announces external addresses together with the
// listen ones, so every peer's Kademlia record and PeerRecord grow the way a
// NAS with dozens of interfaces makes them grow — through the real path, up to
// the real frame limit. The aliases are WORKING addresses (all of 127/8 reaches
// a listener on 0.0.0.0): a dead fake address would be dropped from the record
// after a failed dial and the amplifier would melt, and a fake private/global
// address would outrank loopback and make a fixed build hand out dead routes.

#[cfg(test)]
mod tests;

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;

/// Env variable with the number of aliases to advertise (unset / empty = 0).
pub(crate) const LOOPBACK_ALIASES_ENV: &str = "VIATICUM_E2E_LOOPBACK_ALIASES";

#[cfg(test)]
thread_local! {
    /// Test override of the env value for swarms started on this thread
    /// (unsafe `set_var` is denied): `Some(n)` wins over the env.
    pub(crate) static TEST_ALIAS_COUNT: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// The alias count this process should advertise: the env value (a test on
/// this thread may override it). `Err` = a bad value (the caller warns).
pub(crate) fn alias_count_from_env() -> Result<usize, String> {
    #[cfg(test)]
    if let Some(n) = TEST_ALIAS_COUNT.with(|c| c.get()) {
        return Ok(n);
    }
    parse_alias_count(std::env::var(LOOPBACK_ALIASES_ENV).ok().as_deref())
}

/// Most aliases one node can advertise: 127.0.0.2 ..= 127.0.0.255.
pub(crate) const MAX_LOOPBACK_ALIASES: usize = 254;

/// The alias count from the env value: absent or empty = 0; not a number or
/// above [`MAX_LOOPBACK_ALIASES`] = `Err` (the caller warns and advertises none).
pub(crate) fn parse_alias_count(raw: Option<&str>) -> Result<usize, String> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(0);
    };
    let n: usize = raw
        .parse()
        .map_err(|e| format!("{LOOPBACK_ALIASES_ENV}={raw:?} is not a count: {e}"))?;
    if n > MAX_LOOPBACK_ALIASES {
        return Err(format!(
            "{LOOPBACK_ALIASES_ENV}={n} exceeds {MAX_LOOPBACK_ALIASES} (127.0.0.2..=127.0.0.255)"
        ));
    }
    Ok(n)
}

/// `n` loopback aliases of the TCP port of an IPv4 listen address
/// (`/ip4/<any>/tcp/P`): `/ip4/127.0.0.k/tcp/P` for k = 2..=n+1. Empty for an
/// IPv6 listener — with an ephemeral port the v6 listener has its own port
/// (libp2p-tcp binds v6 only-v6), so 127.0.0.k on it would be dead — and for a
/// relay circuit, another transport, or `n` = 0.
pub(crate) fn loopback_alias_addrs(listen: &Multiaddr, n: usize) -> Vec<Multiaddr> {
    let mut parts = listen.iter();
    let ip4_first = matches!(parts.next(), Some(Protocol::Ip4(_)));
    let port = match parts.next() {
        Some(Protocol::Tcp(p)) if ip4_first => p,
        _ => return Vec::new(),
    };
    if listen.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
        return Vec::new();
    }
    (2..=n.min(MAX_LOOPBACK_ALIASES) + 1)
        .map(|k| {
            Multiaddr::empty()
                .with(Protocol::Ip4(std::net::Ipv4Addr::new(127, 0, 0, k as u8)))
                .with(Protocol::Tcp(port))
        })
        .collect()
}
