// Address format utilities for Viaticum node addresses.
//
// Format: "<device_id_hex>@<ip>:<port>"
//      or "<device_id_hex>@<relay_url>,<ip>:<port>"
// - device_id_hex: 64 lowercase hex chars (32-byte Ed25519 pubkey = DeviceId)
// - relay_url: optional https://... URL (relay hint for NAT traversal)
// - ip: IPv4 or IPv6 address (IPv6 in brackets: [...])
// - port: decimal u16
//
// Examples:
//   abcd1234...ef98@192.168.1.5:12345
//   abcd1234...ef98@[::1]:12345
//   abcd1234...ef98@https://relay.example.com,192.168.1.5:12345
//
// Used by handle/mod.rs to load stored peer addresses from DB on startup.
// Also picks the libp2p address `status` shows (`select_node_addr`).

use std::net::SocketAddr;

use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use viaticum_core::types::DeviceId;

use super::kad_feed::{Reach, reach};

#[cfg(test)]
mod tests;

/// The address `status` shows as `node_addr` (network-i27; R2a: no relay
/// circuits yet), without the `/p2p/` of this node (the caller appends it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAddr {
    pub addr: Multiaddr,
    /// Nothing says another home can dial it: neither confirmed external nor a
    /// global IPv4 we listen on. `status` says "(LAN only)".
    pub lan_only: bool,
}

/// Pick `node_addr`: a confirmed external address first, else the best listen
/// address. Circuit, unspecified, link-local and documentation addresses are
/// never picked (`kad_feed::reach`); when nothing else is left, the first
/// listen address.
///
/// - External: global before private before loopback, QUIC before TCP, IPv4
///   before IPv6. Confirmed, so never LAN only.
/// - Listen: IPv4 first (a home router usually drops inbound IPv6, and the
///   E2E scripts read `/ip4/` from `node_addr`), then global before private
///   before loopback, then QUIC before TCP. Only a global IPv4 (a VPS) is not
///   LAN only; an unconfirmed global IPv6 is.
///
/// `None` only for two empty sets.
pub fn select_node_addr(external: &[Multiaddr], listen: &[Multiaddr]) -> Option<NodeAddr> {
    /// The address without a terminal `/p2p/<us>` (not a relay hop), its reach,
    /// whether it is IPv4 and its transport rank (QUIC 0, TCP 1, other 2); `None`
    /// when nobody else can dial it.
    fn parts(a: &Multiaddr) -> Option<(Multiaddr, Reach, bool, u8)> {
        let mut addr = a.clone();
        if matches!(addr.iter().last(), Some(Protocol::P2p(_))) {
            addr.pop();
        }
        let reach = reach(&addr)?;
        let ip4 = matches!(addr.iter().next(), Some(Protocol::Ip4(_)));
        let transport = if addr.iter().any(|p| matches!(p, Protocol::QuicV1)) {
            0
        } else if addr.iter().any(|p| matches!(p, Protocol::Tcp(_))) {
            1
        } else {
            2
        };
        Some((addr, reach, ip4, transport))
    }
    let confirmed = external
        .iter()
        .filter_map(parts)
        .min_by_key(|(_, reach, ip4, transport)| (*reach, *transport, !*ip4))
        .map(|(addr, ..)| NodeAddr {
            addr,
            lan_only: false,
        });
    let listened = || {
        listen
            .iter()
            .filter_map(parts)
            .min_by_key(|(_, reach, ip4, transport)| (!*ip4, *reach, *transport))
            .map(|(addr, reach, ip4, _)| NodeAddr {
                addr,
                lan_only: !(ip4 && reach == Reach::Global),
            })
    };
    confirmed.or_else(listened).or_else(|| {
        listen.first().map(|a| NodeAddr {
            addr: a.clone(),
            lan_only: true,
        })
    })
}

/// Error returned by `parse_node_addr`.
#[derive(Debug, thiserror::Error)]
pub enum AddrParseError {
    #[error("missing '@' separator")]
    MissingAt,

    #[error("device_id is not 64 hex chars: got {0} chars")]
    BadDeviceIdLength(usize),

    #[error("device_id is not valid hex: {0}")]
    BadDeviceIdHex(String),

    #[error("socket address parse failed: {0}")]
    BadSocketAddr(String),
}

/// Parsed result of a node address string.
/// The relay_url field is present when the address was formatted with a relay hint.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedNodeAddr {
    pub device_id: DeviceId,
    pub socket_addr: SocketAddr,
    /// Optional relay URL. Kept for backward compatibility with stored addresses.
    pub relay_url: Option<String>,
}

/// Format a DeviceId and SocketAddr into a node address string.
///
/// When `relay_url` is Some, the format is `<device_id_hex>@<relay_url>,<ip>:<port>`.
/// When `relay_url` is None, the format is `<device_id_hex>@<ip>:<port>`.
/// The DeviceId is encoded as 64 lowercase hex chars.
/// IPv6 addresses are wrapped in brackets per standard notation: `[::1]:port`.
pub fn format_node_addr(device_id: &DeviceId, addr: SocketAddr, relay_url: Option<&str>) -> String {
    let hex = viaticum_core::types::hex_encode(&device_id.0);
    match relay_url {
        Some(relay) => format!("{hex}@{relay},{addr}"),
        None => format!("{hex}@{addr}"),
    }
}

/// Parse a node address string into its components.
///
/// Accepts two formats:
///   `<device_id_hex>@<ip>:<port>`                      (no relay)
///   `<device_id_hex>@<relay_url>,<ip>:<port>`           (with relay hint)
///
/// `device_id_hex` must be exactly 64 lowercase hex chars.
/// `ip:port` must be a valid SocketAddr (IPv4 or IPv6 with brackets).
pub fn parse_node_addr(s: &str) -> Result<ParsedNodeAddr, AddrParseError> {
    let at = s.find('@').ok_or(AddrParseError::MissingAt)?;
    let hex_part = &s[..at];
    let rest = &s[at + 1..];

    if hex_part.len() != 64 {
        return Err(AddrParseError::BadDeviceIdLength(hex_part.len()));
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in hex_part.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0]).map_err(AddrParseError::BadDeviceIdHex)?;
        let lo = hex_nibble(chunk[1]).map_err(AddrParseError::BadDeviceIdHex)?;
        bytes[i] = (hi << 4) | lo;
    }
    let device_id = DeviceId(bytes);

    // Check for relay URL: relay URLs start with "http://" or "https://".
    // If rest contains a comma AND the text before the comma starts with
    // "http://" or "https://", split on the LAST comma before the port.
    // The socket address never contains a comma, so splitting on the last
    // comma is unambiguous.
    let (relay_url, addr_part) = if rest.starts_with("http://") || rest.starts_with("https://") {
        match rest.rfind(',') {
            Some(comma) => {
                let relay = rest[..comma].to_string();
                let addr = &rest[comma + 1..];
                (Some(relay), addr)
            }
            None => {
                return Err(AddrParseError::BadSocketAddr(
                    "relay URL present but no ip:port after comma".to_string(),
                ));
            }
        }
    } else {
        (None, rest)
    };

    let socket_addr: SocketAddr = addr_part
        .parse()
        .map_err(|e: std::net::AddrParseError| AddrParseError::BadSocketAddr(e.to_string()))?;

    Ok(ParsedNodeAddr {
        device_id,
        socket_addr,
        relay_url,
    })
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("non-hex byte: {b:#x}")),
    }
}
