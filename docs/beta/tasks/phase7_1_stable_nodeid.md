# Phase 7.1 — Stable iroh NodeId + Address Format

**Goal:** Make the iroh endpoint use a deterministic key derived from the BIP39 seed so the NodeId
is stable across restarts. Add a human-readable address format `NodeId_hex@ip:port` for
`syncback connect`.

---

## Scope of changes

Five files change, one new utility module is added:

| File | Change |
|------|--------|
| `crates/syncback-core/src/cluster/mod.rs` | Add `derive_iroh_key` function |
| `crates/syncback-core/src/cluster/tests.rs` | Add tests for `derive_iroh_key` |
| `crates/syncback-core/src/types/mod.rs` | Add `addrs: Vec<String>` field to `PeerRecord` |
| `crates/syncback/src/daemon/identity/mod.rs` | `derive_keys` returns 4-tuple with iroh key bytes |
| `crates/syncback/src/daemon/identity/tests.rs` | Add tests for iroh key derivation |
| `crates/syncback/src/daemon/network/mod.rs` | Add `iroh_secret_key` to `NetworkConfig`; wire `.secret_key()` in `start()` |
| `crates/syncback/src/daemon/network/addr.rs` | **New file:** `format_node_addr` / `parse_node_addr` |
| `crates/syncback/src/daemon/network/mod.rs` | `pub mod addr;` declaration |
| `crates/syncback/src/daemon/network/tests.rs` | Add tests for addr format |
| `crates/syncback/src/daemon/handle/mod.rs` | Wire iroh key from `derive_keys` into `NetworkConfig` |
| `crates/syncback/src/daemon/cli_server/mod.rs` | `dispatch_status`: use `format_node_addr` instead of `format!("{a:?}")` |

---

## 1. `derive_iroh_key` in `syncback-core/src/cluster/mod.rs`

### Purpose

Derives a stable 32-byte Ed25519 secret for the iroh transport layer. Separate from the SyncBack
protocol identity key (domain `syncback-device-ed25519`) and the epoch key (domain
`syncback-encryption`). Per-device so two devices in the same cluster have different iroh NodeIds.

### HKDF parameters

```
HKDF-SHA256(ikm = seed_bytes, salt = device_id.0 (16 bytes), info = b"syncback-iroh-ed25519") → 32 bytes
```

Same salt mechanism as `derive_device_key` (uses device_id as salt). Different info string.

### Signature

```rust
/// Derive iroh transport secret key from seed + device_id.
///
/// HKDF-SHA256(ikm=seed_bytes, salt=device_id.0, info=b"syncback-iroh-ed25519") → 32 bytes
/// The returned bytes are used directly as an iroh::SecretKey.
///
/// Separate from derive_device_key (different domain string), so the iroh NodeId
/// is independent from the SyncBack protocol identity.
pub fn derive_iroh_key(
    seed_bytes: &[u8],
    device_id: &DeviceId,
) -> Result<[u8; 32], ClusterError> {
    let hk = Hkdf::<Sha256>::new(Some(&device_id.0), seed_bytes);
    let mut okm = [0u8; 32];
    hk.expand(b"syncback-iroh-ed25519", &mut okm)
        .map_err(|e| ClusterError::KeyDerivation(e.to_string()))?;
    Ok(okm)
}
```

Add to `crates/syncback-core/src/cluster/mod.rs`, after `derive_epoch_key`.

Export: already in the `pub fn` position; no additional re-exports needed in `lib.rs` because
`cluster` is `pub mod cluster`.

---

## 2. `PeerRecord.addrs` in `syncback-core/src/types/mod.rs`

Add one field to `PeerRecord`:

```rust
pub struct PeerRecord {
    pub identity: IdentityPub,
    pub node_id: Option<NodeId>,
    // ... (all existing fields unchanged) ...
    #[serde(default)]
    pub addrs: Vec<String>,   // NEW: known addresses in "NodeId_hex@ip:port" format
}
```

The `#[serde(default)]` attribute means existing CBOR records that lack this field deserialize with
`addrs = vec![]`. No DB migration needed.

---

## 3. `derive_keys` in `crates/syncback/src/daemon/identity/mod.rs`

Change the return type from a 3-tuple to a 4-tuple. The fourth element is the raw iroh key bytes.

### Current signature

```rust
pub fn derive_keys(
    keyfile: &IdentityKeyFile,
    epoch: u32,
) -> Result<(ed25519_dalek::SigningKey, ed25519_dalek::SigningKey, [u8; 32]), IdentityError>
```

### New signature

```rust
pub fn derive_keys(
    keyfile: &IdentityKeyFile,
    epoch: u32,
) -> Result<(ed25519_dalek::SigningKey, ed25519_dalek::SigningKey, [u8; 32], [u8; 32]), IdentityError>
```

Return order:
1. `master_signing_key` — Ed25519 signing key for the master identity
2. `device_signing_key` — Ed25519 signing key for this device
3. `epoch_key_bytes` — 32-byte ChaCha20 symmetric key for `epoch`
4. `iroh_key_bytes` — 32-byte raw bytes for `iroh::SecretKey`

### Import to add

```rust
use syncback_core::cluster::{derive_device_key, derive_epoch_key, derive_iroh_key, derive_master_key, master_identity, EpochCounter};
```

### Implementation delta

After deriving the three existing keys, add:

```rust
let iroh_key_bytes = derive_iroh_key(&keyfile.seed, &DeviceId(keyfile.device_id))
    .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
Ok((master_key, device_key, epoch_key.key_bytes, iroh_key_bytes))
```

**Callers that must be updated:** only `handle/mod.rs` (see section 5). No other call site exists.

---

## 4. `NetworkConfig` and `NetworkHandle::start` in `crates/syncback/src/daemon/network/mod.rs`

### `NetworkConfig` change

Add one field:

```rust
#[derive(Clone)]
pub struct NetworkConfig {
    pub signing_key: SigningKey,
    pub known_peers: HashMap<IdentityPub, EndpointAddr>,
    pub device_cert: Option<syncback_core::cluster::DeviceCertificate>,
    /// When Some, the iroh endpoint uses this key (stable NodeId).
    /// When None, iroh generates a random key (ephemeral NodeId — tests only).
    pub iroh_secret_key: Option<iroh::SecretKey>,  // NEW
}
```

### `NetworkHandle::start` change

In the endpoint builder block, conditionally apply `.secret_key()`:

```rust
let mut builder = Endpoint::builder()
    .alpns(vec![ALPN.to_vec()])
    .relay_mode(RelayMode::Disabled);

if let Some(key) = config.iroh_secret_key {
    builder = builder.secret_key(key);
}

let endpoint = builder
    .bind()
    .await
    .map_err(|e| NetworkError::Iroh(anyhow::anyhow!("{e}")))?;
```

### Import to add

```rust
use iroh::SecretKey as IrohSecretKey;
```

Or simply use `iroh::SecretKey` inline — whichever is cleaner. The existing import line is:
`use iroh::{Endpoint, EndpointAddr, RelayMode};` — add `SecretKey` to it.

### No other changes to `NetworkHandle`

The `node_id` field assignment `let node_id = NodeId(*iroh_id.as_bytes());` is unchanged. It reads
the actual (now stable) id from the endpoint after binding.

---

## 5. New module `crates/syncback/src/daemon/network/addr.rs`

This module provides two public functions for the `NodeId_hex@ip:port` address format.

Create file `crates/syncback/src/daemon/network/addr.rs`:

```rust
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
        let hi = hex_nibble(chunk[0]).map_err(|e| AddrParseError::BadNodeIdHex(e))?;
        let lo = hex_nibble(chunk[1]).map_err(|e| AddrParseError::BadNodeIdHex(e))?;
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
```

### Declare the module in `network/mod.rs`

Add after the existing `mod handshake;` line:

```rust
pub mod addr;
```

---

## 6. `handle/mod.rs` wiring

In `DaemonHandle::start`, the call to `derive_keys` currently destructures 3 elements. Update to 4:

```rust
let (master_key, device_key, epoch_key_bytes, iroh_key_bytes) = derive_keys(&keyfile, 0)?;
```

When building `NetworkConfig`, supply the iroh key:

```rust
let net_config = NetworkConfig {
    signing_key: device_key.clone(),
    known_peers: HashMap::new(),
    device_cert: device_cert_for_network,
    iroh_secret_key: Some(iroh::SecretKey::from_bytes(&iroh_key_bytes)),
};
```

The `iroh::SecretKey::from_bytes` call takes `&[u8; 32]`, which `iroh_key_bytes` satisfies directly.

---

## 7. `cli_server/mod.rs` — `dispatch_status` fix

Replace the `format!("{a:?}")` Debug format with the proper address format.

Current code (lines 253–256):

```rust
let node_addr = state
    .network
    .local_addr()
    .map(|a| format!("{a:?}"))
    .unwrap_or_default();
```

New code:

```rust
let node_addr = state
    .network
    .local_addr()
    .ok()
    .and_then(|endpoint_addr| {
        // EndpointAddr may have zero or more direct addresses.
        // Use the first non-loopback socket addr; fall back to first if all are loopback.
        endpoint_addr
            .direct_addresses
            .iter()
            .find(|a| !a.addr.ip().is_loopback())
            .or_else(|| endpoint_addr.direct_addresses.first())
            .map(|da| {
                crate::daemon::network::addr::format_node_addr(
                    &state.network.node_id,
                    da.addr,
                )
            })
    })
    .unwrap_or_else(|| {
        // Endpoint not yet listening or no direct addresses known yet.
        // Format NodeId alone without an address.
        state
            .network
            .node_id
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });
```

Note: `iroh::EndpointAddr` has a `direct_addresses: Vec<DirectAddr>` field where each `DirectAddr`
has an `addr: SocketAddr`. The node is freshly bound and may not have discovered external addresses
yet — the fallback to the NodeId hex alone ensures `StatusData.node_addr` is never an opaque Debug
string.

DECISION NEEDED: Confirm the exact field name for direct addresses in `iroh::EndpointAddr` (it may
be `direct_addresses` or `addr` or something else). The implementer must inspect
`iroh::EndpointAddr`'s fields with `cargo doc` or source inspection before writing this code. The
fallback to NodeId-only string is safe regardless.

---

## 8. Tests to add

### 8.1 `crates/syncback-core/src/cluster/tests.rs`

Add to the existing test file (inside the existing `#[cfg(test)]` module):

```rust
// ============================================================
// derive_iroh_key tests
// ============================================================

use crate::cluster::derive_iroh_key;

#[test]
fn derive_iroh_key_is_deterministic() {
    let seed = [42u8; 64];
    let device_id = DeviceId([1u8; 16]);
    let key1 = derive_iroh_key(&seed, &device_id).unwrap();
    let key2 = derive_iroh_key(&seed, &device_id).unwrap();
    assert_eq!(key1, key2, "same seed+device_id must produce same iroh key");
}

#[test]
fn derive_iroh_key_differs_per_device() {
    let seed = [42u8; 64];
    let device_a = DeviceId([1u8; 16]);
    let device_b = DeviceId([2u8; 16]);
    let key_a = derive_iroh_key(&seed, &device_a).unwrap();
    let key_b = derive_iroh_key(&seed, &device_b).unwrap();
    assert_ne!(key_a, key_b, "different device_ids must produce different iroh keys");
}

#[test]
fn derive_iroh_key_differs_from_device_key() {
    // Ensures domain separation: iroh key != device signing key.
    let seed = [42u8; 64];
    let device_id = DeviceId([1u8; 16]);
    let iroh_bytes = derive_iroh_key(&seed, &device_id).unwrap();
    let device_signing = derive_device_key(&seed, &device_id).unwrap();
    let device_bytes = device_signing.to_bytes();
    assert_ne!(iroh_bytes, device_bytes, "iroh key must differ from device signing key");
}

#[test]
fn derive_iroh_key_output_is_32_bytes() {
    let seed = [0u8; 32];
    let device_id = DeviceId([0u8; 16]);
    let key = derive_iroh_key(&seed, &device_id).unwrap();
    assert_eq!(key.len(), 32);
}
```

### 8.2 `crates/syncback/src/daemon/identity/tests.rs`

Add to existing test file:

```rust
// ============================================================
// derive_keys iroh key tests
// ============================================================

#[test]
fn derive_keys_returns_iroh_key() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");
    // Four-tuple: (master, device, epoch_bytes, iroh_bytes)
    let (_master, _device, _epoch, iroh) = derive_keys(&keyfile, 0).expect("derive_keys");
    assert_eq!(iroh.len(), 32, "iroh key must be 32 bytes");
}

#[test]
fn derive_keys_iroh_key_is_deterministic() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");
    let (_, _, _, iroh1) = derive_keys(&keyfile, 0).expect("first call");
    let (_, _, _, iroh2) = derive_keys(&keyfile, 0).expect("second call");
    assert_eq!(iroh1, iroh2, "iroh key must be deterministic");
}

#[test]
fn derive_keys_iroh_key_differs_from_device_key() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");
    let (_, device, _, iroh) = derive_keys(&keyfile, 0).expect("derive_keys");
    assert_ne!(
        iroh,
        device.to_bytes(),
        "iroh key bytes must differ from device signing key bytes"
    );
}
```

### 8.3 `crates/syncback/src/daemon/network/tests.rs`

The existing `tests.rs` already imports from `network`. Add addr-format tests in a new section or
at the bottom of the existing file. These are sync tests (no `#[tokio::test]` needed):

```rust
// ============================================================
// addr format tests
// ============================================================

use crate::daemon::network::addr::{format_node_addr, parse_node_addr, AddrParseError};
use syncback_core::types::NodeId;

#[test]
fn format_and_parse_roundtrip_ipv4() {
    let node_id = NodeId([0xab; 32]);
    let addr: std::net::SocketAddr = "192.168.1.5:12345".parse().unwrap();
    let formatted = format_node_addr(&node_id, addr);
    let (parsed_id, parsed_addr) = parse_node_addr(&formatted).unwrap();
    assert_eq!(parsed_id, node_id);
    assert_eq!(parsed_addr, addr);
}

#[test]
fn format_and_parse_roundtrip_ipv6() {
    let node_id = NodeId([0x01; 32]);
    let addr: std::net::SocketAddr = "[::1]:9000".parse().unwrap();
    let formatted = format_node_addr(&node_id, addr);
    let (parsed_id, parsed_addr) = parse_node_addr(&formatted).unwrap();
    assert_eq!(parsed_id, node_id);
    assert_eq!(parsed_addr, addr);
}

#[test]
fn format_node_addr_produces_64_hex_prefix() {
    let node_id = NodeId([0u8; 32]);
    let addr: std::net::SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let formatted = format_node_addr(&node_id, addr);
    let hex_part = formatted.split('@').next().unwrap();
    assert_eq!(hex_part.len(), 64, "NodeId hex must be 64 chars");
    assert_eq!(hex_part, "0".repeat(64), "all-zero NodeId encodes as 64 zeros");
}

#[test]
fn parse_node_addr_rejects_missing_at() {
    let result = parse_node_addr("abcd1234noatsign");
    assert!(matches!(result, Err(AddrParseError::MissingAt)));
}

#[test]
fn parse_node_addr_rejects_short_node_id() {
    // Only 8 hex chars instead of 64.
    let result = parse_node_addr("abcd1234@127.0.0.1:1234");
    assert!(matches!(result, Err(AddrParseError::BadNodeIdLength(_))));
}

#[test]
fn parse_node_addr_rejects_non_hex_node_id() {
    // 64 chars but contains 'z'.
    let bad: String = "z".repeat(64) + "@127.0.0.1:1234";
    let result = parse_node_addr(&bad);
    assert!(matches!(result, Err(AddrParseError::BadNodeIdHex(_))));
}

#[test]
fn parse_node_addr_rejects_bad_socket_addr() {
    let node_id_hex = "ab".repeat(32); // valid 64 hex chars
    let s = format!("{node_id_hex}@not_a_valid_addr");
    let result = parse_node_addr(&s);
    assert!(matches!(result, Err(AddrParseError::BadSocketAddr(_))));
}
```

### 8.4 Existing tests must still pass

The changes in `NetworkConfig` add an optional field with no breaking impact on existing tests
**if** test helpers that construct `NetworkConfig` are updated to set
`iroh_secret_key: None`. The test helper in `cli_server/tests.rs` must add this field:

```rust
let net_config = NetworkConfig {
    signing_key,
    known_peers: Default::default(),
    device_cert: None,
    iroh_secret_key: None,   // ADD THIS
};
```

The `network/tests.rs` must be checked for any direct `NetworkConfig { ... }` construction and
updated similarly. The implementer must grep for `NetworkConfig {` across the codebase and update
every struct literal.

---

## 9. Dependencies

This task has no new crate dependencies. All crates used (`iroh`, `hkdf`, `sha2`, `ed25519-dalek`,
`thiserror`) are already in `Cargo.toml`.

The `iroh::SecretKey` type is available as `use iroh::SecretKey;` — confirmed for iroh 0.96.
The builder method is `Endpoint::builder().secret_key(key)` — confirmed for iroh 0.96.

---

## 10. Acceptance criteria

All of the following must pass before the task is considered done:

1. `cargo test -p syncback-core` — no regressions, new cluster tests pass
2. `cargo test -p syncback` — no regressions, new identity + network addr tests pass
3. Two daemon instances started from the same seed+device_id produce the same NodeId (can be
   verified by starting daemon twice with `syncback status` and comparing `node_addr` prefix).
4. `syncback status` output for `node_addr` no longer shows `EndpointAddr { ... }` Debug format;
   it shows either `<64 hex chars>@<ip>:<port>` or `<64 hex chars>` if no direct addr is known.
5. `cargo clippy -- -D warnings` clean.
6. No `#[cfg(test)]` blocks inline in `mod.rs` or `addr.rs` — tests go in `tests.rs` per convention.

---

## 11. File layout after this task

```
crates/syncback-core/src/cluster/
  mod.rs      ← derive_iroh_key added
  tests.rs    ← 4 new tests

crates/syncback-core/src/types/
  mod.rs      ← PeerRecord.addrs field added

crates/syncback/src/daemon/identity/
  mod.rs      ← derive_keys returns 4-tuple
  tests.rs    ← 3 new tests

crates/syncback/src/daemon/network/
  mod.rs      ← NetworkConfig.iroh_secret_key, builder wired, pub mod addr
  addr.rs     ← NEW: format_node_addr, parse_node_addr, AddrParseError
  tests.rs    ← 7 new addr tests

crates/syncback/src/daemon/handle/
  mod.rs      ← 4-tuple destructure, iroh_secret_key in NetworkConfig

crates/syncback/src/daemon/cli_server/
  mod.rs      ← dispatch_status uses format_node_addr
  tests.rs    ← iroh_secret_key: None in make_test_state
```

---

## 12. Known callsite audit

Run before submitting:

```
grep -rn "NetworkConfig {" crates/
grep -rn "derive_keys(" crates/
```

Both must return only patched locations. The second grep should find exactly one call site in
`handle/mod.rs` which must destructure 4 elements.
