// Address format utilities for SyncBack node addresses.
//
// Format: "<node_id_hex>@<ip>:<port>"
// - node_id_hex: 64 lowercase hex chars (32-byte Ed25519 pubkey)
// - ip: IPv4 or IPv6 address (IPv6 in brackets: [...])
// - port: decimal u16
//
// Examples:
//   abcd1234...ef98@192.168.1.5:12345
//   abcd1234...ef98@[::1]:12345

use std::net::SocketAddr;

use syncback_core::types::NodeId;

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

/// Format a NodeId and SocketAddr into a `NodeId_hex@ip:port` string.
///
/// The NodeId is encoded as 64 lowercase hex chars.
/// IPv6 addresses are wrapped in brackets per standard notation: `[::1]:port`.
pub fn format_node_addr(node_id: &NodeId, addr: SocketAddr) -> String {
    let hex: String = node_id.0.iter().map(|b| format!("{b:02x}")).collect();
    format!("{hex}@{addr}")
}

/// Parse a `NodeId_hex@ip:port` string into (NodeId, SocketAddr).
///
/// Splits on the first '@'. The left part must be exactly 64 lowercase hex chars.
/// The right part must be a valid `SocketAddr` (IPv4 or IPv6).
pub fn parse_node_addr(s: &str) -> Result<(NodeId, SocketAddr), AddrParseError> {
    let at = s.find('@').ok_or(AddrParseError::MissingAt)?;
    let hex_part = &s[..at];
    let addr_part = &s[at + 1..];

    if hex_part.len() != 64 {
        return Err(AddrParseError::BadNodeIdLength(hex_part.len()));
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in hex_part.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0]).map_err(AddrParseError::BadNodeIdHex)?;
        let lo = hex_nibble(chunk[1]).map_err(AddrParseError::BadNodeIdHex)?;
        bytes[i] = (hi << 4) | lo;
    }

    let addr: SocketAddr = addr_part
        .parse()
        .map_err(|e: std::net::AddrParseError| AddrParseError::BadSocketAddr(e.to_string()))?;

    Ok((NodeId(bytes), addr))
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("non-hex byte: {b:#x}")),
    }
}
