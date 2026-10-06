// The libp2p listen port `init` writes into config.toml (network-i31, R2 Р2-1′).
//
// A random number from LISTEN_PORT_RANGE, not on LISTEN_PORT_DENYLIST, free right
// now. For the libp2p port the number must be free for TCP and for UDP: R2b
// listens QUIC on the same number. The probe binds WITHOUT SO_REUSEPORT, like the
// start's own check (`wait_for_tcp_port_free`), so a port somebody listens on is
// taken even if that somebody set SO_REUSEPORT.

#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::ops::RangeInclusive;

use viaticum_core::constants::LISTEN_PORT_DENYLIST;

/// Random candidates tried before giving up.
pub const PICK_ATTEMPTS: usize = 32;

/// Which protocols the picked number must be free for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortProtocols {
    /// The web port.
    Tcp,
    /// The libp2p port: TCP and QUIC (UDP) on one number.
    TcpAndUdp,
}

/// A random port of `range` that is not denylisted, not in `exclude` and free on
/// `bind_ip` for `protocols`; `None` after PICK_ATTEMPTS candidates failed.
pub fn pick_listen_port(
    range: RangeInclusive<u16>,
    exclude: &[u16],
    protocols: PortProtocols,
    bind_ip: IpAddr,
) -> Option<u16> {
    let candidates = (0..PICK_ATTEMPTS).map(|_| rand::random_range(range.clone()));
    pick_from(candidates, exclude, protocols, bind_ip)
}

/// The first of `candidates` that passes (the random draw stays outside, so the
/// tests choose the order).
pub(crate) fn pick_from(
    candidates: impl IntoIterator<Item = u16>,
    exclude: &[u16],
    protocols: PortProtocols,
    bind_ip: IpAddr,
) -> Option<u16> {
    candidates.into_iter().find(|&port| {
        port != 0
            && !is_denied(port)
            && !exclude.contains(&port)
            && is_free(port, protocols, bind_ip)
    })
}

/// The port is on LISTEN_PORT_DENYLIST.
pub fn is_denied(port: u16) -> bool {
    LISTEN_PORT_DENYLIST.iter().any(|r| r.contains(&port))
}

/// Nobody holds `port` on `ip` now (for UDP too when asked). Both probes are
/// released at once.
fn is_free(port: u16, protocols: PortProtocols, ip: IpAddr) -> bool {
    let addr = SocketAddr::new(ip, port);
    if TcpListener::bind(addr).is_err() {
        return false;
    }
    match protocols {
        PortProtocols::Tcp => true,
        PortProtocols::TcpAndUdp => UdpSocket::bind(addr).is_ok(),
    }
}
