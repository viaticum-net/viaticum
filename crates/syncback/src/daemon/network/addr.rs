// Address format utilities for SyncBack node addresses.
//
// Format: "<node_id_hex>@<ip>:<port>"
//      or "<node_id_hex>@<relay_url>,<ip>:<port>"
// - node_id_hex: 64 lowercase hex chars (32-byte Ed25519 pubkey)
// - relay_url: optional https://... URL (relay hint for NAT traversal)
// - ip: IPv4 or IPv6 address (IPv6 in brackets: [...])
// - port: decimal u16
//
// Examples:
//   abcd1234...ef98@192.168.1.5:12345
//   abcd1234...ef98@[::1]:12345
//   abcd1234...ef98@https://relay.iroh.network,192.168.1.5:12345

use std::net::SocketAddr;

use syncback_core::types::{hex_encode, NodeId};

use super::NetworkHandle;

/// Error returned by `parse_node_addr`.
#[derive(Debug, thiserror::Error)]
pub enum AddrParseError {
    #[error("missing '@' separator")]
    MissingAt,

    #[error("node_id is not 64 hex chars: got {0} chars")]
    BadNodeIdLength(usize),

    #[error("node_id is not valid hex: {0}")]
    BadNodeIdHex(String),

    #[error("socket address parse failed: {0}")]
    BadSocketAddr(String),
}

/// Error returned by `to_endpoint_addr`.
#[derive(Debug, thiserror::Error)]
pub enum ToEndpointAddrError {
    #[error("invalid node id: {0}")]
    InvalidNodeId(String),
}

/// Parsed result of a node address string.
/// The relay_url field is present when the address was formatted with a relay hint.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedNodeAddr {
    pub node_id: NodeId,
    pub socket_addr: SocketAddr,
    /// Optional relay URL. When present, callers may pass it to iroh's
    /// EndpointAddr to hint which relay server to use.
    pub relay_url: Option<String>,
}

/// Format a NodeId and SocketAddr into a node address string.
///
/// When `relay_url` is Some, the format is `<node_id_hex>@<relay_url>,<ip>:<port>`.
/// When `relay_url` is None, the format is `<node_id_hex>@<ip>:<port>`.
/// The NodeId is encoded as 64 lowercase hex chars.
/// IPv6 addresses are wrapped in brackets per standard notation: `[::1]:port`.
pub fn format_node_addr(node_id: &NodeId, addr: SocketAddr, relay_url: Option<&str>) -> String {
    let hex = hex_encode(&node_id.0);
    match relay_url {
        Some(relay) => format!("{hex}@{relay},{addr}"),
        None => format!("{hex}@{addr}"),
    }
}

/// Parse a node address string into its components.
///
/// Accepts two formats:
///   `<node_id_hex>@<ip>:<port>`                      (no relay)
///   `<node_id_hex>@<relay_url>,<ip>:<port>`           (with relay hint)
///
/// `node_id_hex` must be exactly 64 lowercase hex chars.
/// `ip:port` must be a valid SocketAddr (IPv4 or IPv6 with brackets).
pub fn parse_node_addr(s: &str) -> Result<ParsedNodeAddr, AddrParseError> {
    let at = s.find('@').ok_or(AddrParseError::MissingAt)?;
    let hex_part = &s[..at];
    let rest = &s[at + 1..];

    if hex_part.len() != 64 {
        return Err(AddrParseError::BadNodeIdLength(hex_part.len()));
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in hex_part.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0]).map_err(AddrParseError::BadNodeIdHex)?;
        let lo = hex_nibble(chunk[1]).map_err(AddrParseError::BadNodeIdHex)?;
        bytes[i] = (hi << 4) | lo;
    }
    let node_id = NodeId(bytes);

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
        node_id,
        socket_addr,
        relay_url,
    })
}

/// Convert a ParsedNodeAddr to an iroh EndpointAddr.
///
/// When relay_url is Some, the relay hint is set on the EndpointAddr so iroh
/// will prefer connecting via that relay for NAT traversal.
pub fn to_endpoint_addr(
    parsed: &ParsedNodeAddr,
) -> Result<iroh::EndpointAddr, ToEndpointAddrError> {
    let pubkey = iroh::PublicKey::from_bytes(&parsed.node_id.0)
        .map_err(|e| ToEndpointAddrError::InvalidNodeId(e.to_string()))?;

    let mut ea = iroh::EndpointAddr::new(pubkey).with_ip_addr(parsed.socket_addr);

    if let Some(relay_url_str) = &parsed.relay_url {
        match relay_url_str.parse::<iroh::RelayUrl>() {
            Ok(relay_url) => {
                ea = ea.with_relay_url(relay_url);
            }
            Err(e) => {
                tracing::warn!(
                    relay_url = %relay_url_str,
                    error = %e,
                    "to_endpoint_addr: ignoring unparseable relay URL"
                );
            }
        }
    }

    Ok(ea)
}

/// Resolve the local node's address string for display (e.g. `syncback status`).
///
/// Combines:
/// - IP from iroh's address discovery (STUN/relay) — non-loopback
/// - Port from `bound_sockets()` (actual listening port, not NAT-mapped)
/// - Relay URL from iroh (for NAT traversal)
///
/// Returns the formatted `NodeId@relay,ip:port` string, or falls back to
/// hex-encoded NodeId if IP/port cannot be determined.
pub fn resolve_local_addr(network: &NetworkHandle) -> String {
    let endpoint_addr = network.local_addr().ok();

    let relay_url: Option<String> = endpoint_addr.as_ref().and_then(|ea| {
        ea.addrs.iter().find_map(|a| match a {
            iroh::TransportAddr::Relay(url) => Some(url.to_string()),
            _ => None,
        })
    });

    let discovered_ip = endpoint_addr.as_ref().and_then(|ea| {
        ea.addrs
            .iter()
            .filter_map(|a| match a {
                iroh::TransportAddr::Ip(addr) => Some(addr.ip()),
                _ => None,
            })
            .find(|ip| !ip.is_loopback())
    });

    let bound = network.bound_sockets();
    let bound_port = bound
        .iter()
        .find(|a| a.is_ipv4())
        .or(bound.first())
        .map(|a| a.port());

    match (discovered_ip, bound_port) {
        (Some(ip), Some(port)) => {
            let addr = SocketAddr::new(ip, port);
            format_node_addr(&network.node_id, addr, relay_url.as_deref())
        }
        _ => hex_encode(&network.node_id.0),
    }
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("non-hex byte: {b:#x}")),
    }
}
