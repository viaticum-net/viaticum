# Task spec: Phase 7.3 — Real connect

**Target files:**
- `crates/syncback/src/daemon/network/addr.rs` — add `to_endpoint_addr` helper
- `crates/syncback/src/daemon/network/mod.rs` — wrap `known_peers` in `Mutex`, add `add_peer`
- `crates/syncback/src/daemon/cli_server/mod.rs` — implement `dispatch_connect`
- `crates/syncback/src/daemon/handle/mod.rs` — load peers from DB on startup
- `crates/syncback/src/daemon/cli_server/tests.rs` — update stub test, add new tests
- `crates/syncback/src/daemon/network/tests.rs` — add `add_peer` test

**Phase:** 7.3 (P2P wiring — real outbound connect)

---

## Overview

`syncback connect <addr>` currently echoes the address back without doing anything. This task wires it to the real network layer:

1. Parse the `NodeId@ip:port` string to get `(NodeId, SocketAddr)`.
2. Convert to an iroh `EndpointAddr` (no identity constraint — we do not know the peer's `IdentityPub` before connecting).
3. Call `network.connect(endpoint_addr, None)` — performs the SyncBack handshake, returns a `Connection` with `peer_identity` verified.
4. Upsert the peer into the DB (`PeerRecord` with the addr string saved).
5. Call `network.add_peer(peer_identity, endpoint_addr)` so subsequent `get_connection` calls by identity work.
6. Return `CliResponse::Connected { peer_id: <full 64-char hex of peer_identity> }`.

Additionally, on daemon startup, existing peers are loaded from DB and pre-populated into `known_peers` so that `get_connection` by identity works immediately after restart.

This task introduces no new protocol messages. It only wires existing components.

---

## Dependencies

- `crates/syncback/src/daemon/network/addr.rs` — `parse_node_addr` (exists), add `to_endpoint_addr`
- `crates/syncback/src/daemon/network/mod.rs` — `NetworkHandle::connect` (exists), add `add_peer`
- `crates/syncback-core/src/db/mod.rs` — `upsert_peer`, `list_all_peers`, `get_peer` (all exist)
- `iroh::PublicKey::from_bytes` — converts `[u8; 32]` → `PublicKey` (fallible)
- `iroh::EndpointAddr::new(id).with_ip_addr(addr)` — constructs EndpointAddr

---

## Change 1: `addr.rs` — add `to_endpoint_addr`

### New public function

```rust
/// Convert a (NodeId, SocketAddr) pair to an iroh EndpointAddr for direct connection.
///
/// Returns Err if the NodeId bytes do not represent a valid Ed25519 public key.
pub fn to_endpoint_addr(
    node_id: &NodeId,
    addr: SocketAddr,
) -> Result<iroh::EndpointAddr, ToEndpointAddrError> {
    let pubkey = iroh::PublicKey::from_bytes(&node_id.0)
        .map_err(|e| ToEndpointAddrError::InvalidNodeId(e.to_string()))?;
    Ok(iroh::EndpointAddr::new(pubkey).with_ip_addr(addr))
}
```

### New error type

```rust
#[derive(Debug, thiserror::Error)]
pub enum ToEndpointAddrError {
    #[error("invalid node id (not a valid Ed25519 public key): {0}")]
    InvalidNodeId(String),
}
```

### Imports to add in `addr.rs`

```rust
use std::net::SocketAddr; // already present
use iroh::EndpointAddr;   // add
use iroh::PublicKey;       // add (used internally only; not re-exported)
```

Note: `iroh::PublicKey` is the type that `EndpointAddr::id` holds. `iroh::PublicKey::from_bytes` takes `&[u8; 32]` and returns `Result<PublicKey, KeyParsingError>`. The `KeyParsingError` does not implement `std::error::Error` in some versions — convert it with `.to_string()` as shown.

---

## Change 2: `network/mod.rs` — mutable `known_peers`, add `add_peer`

### Problem

`known_peers` is currently `HashMap<IdentityPub, EndpointAddr>` owned directly by `NetworkHandle`. There is no way to mutate it after construction because `NetworkHandle` is behind `Arc` (immutable shared reference).

### Solution

Wrap `known_peers` in `Arc<tokio::sync::RwLock<HashMap<IdentityPub, EndpointAddr>>>`. This allows `add_peer` to take `&self` (not `&mut self`) and mutate through the lock. Prefer `RwLock` over `Mutex` because `get_connection` reads frequently; writes (from `add_peer`) are rare.

### Field change in `NetworkHandle`

```rust
// Before:
known_peers: HashMap<IdentityPub, EndpointAddr>,

// After:
known_peers: Arc<tokio::sync::RwLock<HashMap<IdentityPub, EndpointAddr>>>,
```

### `NetworkConfig` field stays unchanged

`NetworkConfig.known_peers` remains `HashMap<IdentityPub, EndpointAddr>`. The constructor wraps it:

```rust
// In NetworkHandle::start(), where `known_peers` is assigned:
known_peers: Arc::new(tokio::sync::RwLock::new(config.known_peers)),
```

### `get_connection` update

The one call to `self.known_peers.get(...)` must change to hold a read guard:

```rust
// Before:
let peer_addr = self
    .known_peers
    .get(&peer_identity)
    .cloned()
    .ok_or(NetworkError::PeerNotFound(peer_identity))?;

// After:
let peer_addr = {
    let peers = self.known_peers.read().await;
    peers.get(&peer_identity).cloned()
}.ok_or(NetworkError::PeerNotFound(peer_identity))?;
```

The `read().await` must complete before calling `self.connect(...)` to avoid holding the guard across an await that may take seconds. The block drops the guard as soon as `.cloned()` produces an owned value.

### New public method

```rust
/// Register a peer in the known_peers directory.
///
/// After this call, `get_connection(identity)` will find the peer's address.
/// If the peer was already present, the address is updated.
pub async fn add_peer(&self, identity: IdentityPub, addr: EndpointAddr) {
    let mut peers = self.known_peers.write().await;
    peers.insert(identity, addr);
}
```

### Import changes in `network/mod.rs`

```rust
// Change:
use tokio::sync::Mutex;
// To:
use tokio::sync::{Mutex, RwLock};
```

---

## Change 3: `cli_server/mod.rs` — implement `dispatch_connect`

### Replace the stub

Current code (lines 170-175):
```rust
CliRequest::Connect { addr } => {
    tracing::info!(addr = %addr, "connect request received (stub — Processor not wired yet)");
    CliResponse::Connected { peer_id: addr }
}
```

Replace with a call to `dispatch_connect(state, addr).await`.

### New function

```rust
async fn dispatch_connect(state: &DaemonState, addr: String) -> CliResponse {
    use crate::daemon::network::addr::{parse_node_addr, to_endpoint_addr};
    use syncback_core::types::{PeerRecord, Timestamp};

    // 1. Parse the addr string.
    let (node_id, socket_addr) = match parse_node_addr(&addr) {
        Ok(pair) => pair,
        Err(e) => {
            return CliResponse::Error(format!("invalid peer address '{addr}': {e}"));
        }
    };

    // 2. Build iroh EndpointAddr.
    let endpoint_addr = match to_endpoint_addr(&node_id, socket_addr) {
        Ok(ea) => ea,
        Err(e) => {
            return CliResponse::Error(format!("cannot build endpoint addr: {e}"));
        }
    };

    // 3. Connect and perform SyncBack handshake.
    //    expected_identity = None because we do not yet know the peer's IdentityPub.
    let conn = match state.network.connect(endpoint_addr.clone(), None).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(addr = %addr, error = %e, "connect failed");
            return CliResponse::Error(format!("connect failed: {e}"));
        }
    };

    let peer_identity = conn.peer_identity;
    let now = Timestamp::now();

    // 4. Upsert peer into DB.
    //    Preserve existing trust fields if peer already known; zero them for new peers.
    let existing = state.db.get_peer(&peer_identity).unwrap_or(None);
    let record = if let Some(mut existing) = existing {
        // Update addr list: replace or add this addr string.
        if !existing.addrs.contains(&addr) {
            existing.addrs.push(addr.clone());
        }
        existing.last_seen = now;
        existing.node_id = Some(node_id);
        existing
    } else {
        PeerRecord {
            identity: peer_identity,
            node_id: Some(node_id),
            trust_p: 0.0,
            trust_i: 0.0,
            trust_s: 1.0,
            bytes_we_store_for_peer: 0,
            bytes_peer_stores_for_us: 0,
            first_seen: now,
            last_seen: now,
            device_id: Some(state.device_id),
            revoked_device_pub_keys: vec![],
            addrs: vec![addr.clone()],
        }
    };

    if let Err(e) = state.db.upsert_peer(&record) {
        tracing::error!(peer = %peer_identity, error = %e, "failed to upsert peer in db");
        // Non-fatal: connection worked, DB write failed. Return error so the user knows.
        return CliResponse::Error(format!("connected but db write failed: {e}"));
    }

    // 5. Register in NetworkHandle known_peers for future get_connection() calls.
    state.network.add_peer(peer_identity, endpoint_addr).await;

    tracing::info!(
        peer = %peer_identity,
        addr = %addr,
        "peer connected and registered"
    );

    // 6. Return the peer's full IdentityPub as hex.
    let peer_id_hex = bytes_to_hex_full(&peer_identity.0);
    CliResponse::Connected { peer_id: peer_id_hex }
}
```

### Import additions in `cli_server/mod.rs`

```rust
use syncback_core::types::PeerRecord; // add to existing use syncback_core::types::{...} block
```

The `to_endpoint_addr` and `parse_node_addr` imports are local (`use` inside the function body as shown above, to keep the function self-contained and avoid a top-level import that is only used in one place).

---

## Change 4: `handle/mod.rs` — load peers from DB on startup

### Where to insert

After step 3 (open DB, line 110) and before step 8 (start network, line 175). Insert as a new step 3a between DB open and network config construction.

### Code

```rust
// ── 3a. Load known peers from DB → populate known_peers map ──────────────
// This lets get_connection() find existing peers immediately after restart.
let known_peers: std::collections::HashMap<
    syncback_core::types::IdentityPub,
    iroh::EndpointAddr,
> = {
    use crate::daemon::network::addr::{parse_node_addr, to_endpoint_addr};
    let peers = db.list_all_peers().unwrap_or_default();
    let mut map = std::collections::HashMap::new();
    for peer in peers {
        // Use the first parseable addr in the peer's addr list.
        // Peers with no addrs (legacy or incomplete records) are skipped.
        for addr_str in &peer.addrs {
            match parse_node_addr(addr_str) {
                Ok((node_id, socket_addr)) => {
                    match to_endpoint_addr(&node_id, socket_addr) {
                        Ok(ea) => {
                            map.insert(peer.identity, ea);
                            break; // use first valid addr
                        }
                        Err(e) => {
                            tracing::warn!(
                                peer = %peer.identity,
                                addr = %addr_str,
                                error = %e,
                                "startup: skipping unparseable peer addr"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        peer = %peer.identity,
                        addr = %addr_str,
                        error = %e,
                        "startup: skipping malformed peer addr"
                    );
                }
            }
        }
    }
    tracing::info!(count = map.len(), "loaded peers from db");
    map
};
```

### Update `net_config` construction

```rust
// Before:
let net_config = NetworkConfig {
    signing_key: device_key.clone(),
    known_peers: HashMap::new(), // Populated by Processor in 6.3
    ...
};

// After:
let net_config = NetworkConfig {
    signing_key: device_key.clone(),
    known_peers,  // loaded from DB above
    ...
};
```

Remove the comment `// Populated by Processor in 6.3`.

### Import additions in `handle/mod.rs`

`iroh::EndpointAddr` is already reachable via the `iroh` crate which is already in scope through the `network` module. However, the type must be named in `handle/mod.rs` for the `HashMap` type annotation. Add:

```rust
use iroh::EndpointAddr;
```

Or drop the explicit type annotation and let the compiler infer it (simpler):

```rust
let mut map = std::collections::HashMap::new();
// ... inserts of (IdentityPub, EndpointAddr) ...
```

Inference works here; no explicit annotation needed.

---

## Public API summary

### New in `addr.rs`

```rust
pub enum ToEndpointAddrError { InvalidNodeId(String) }

pub fn to_endpoint_addr(
    node_id: &NodeId,
    addr: SocketAddr,
) -> Result<iroh::EndpointAddr, ToEndpointAddrError>
```

### New in `network/mod.rs`

```rust
impl NetworkHandle {
    pub async fn add_peer(&self, identity: IdentityPub, addr: iroh::EndpointAddr)
}
```

### Changed in `network/mod.rs` (internal field, not public)

`known_peers: Arc<RwLock<HashMap<IdentityPub, EndpointAddr>>>` — field is private, only affects `get_connection` and `add_peer`.

### No new public types in `cli_server/mod.rs` or `handle/mod.rs`

---

## Types

| Type | Source | Used in |
|------|--------|---------|
| `NodeId` | `syncback_core::types` | Parsed from addr string |
| `IdentityPub` | `syncback_core::types` | Peer identity from handshake |
| `PeerRecord` | `syncback_core::types` | Upserted to DB |
| `Timestamp` | `syncback_core::types` | `first_seen`, `last_seen` |
| `iroh::EndpointAddr` | `iroh` | Passed to `connect()`, stored in `known_peers` |
| `iroh::PublicKey` | `iroh` | Intermediate conversion in `to_endpoint_addr` |
| `ToEndpointAddrError` | `addr.rs` (new) | Error from `to_endpoint_addr` |

---

## DB operations

| Operation | Table | When |
|-----------|-------|------|
| `db.get_peer(&peer_identity)` | `peers` | Before upsert: check if peer exists to preserve trust fields |
| `db.upsert_peer(&record)` | `peers` | After successful connect: save peer with addr |
| `db.list_all_peers()` | `peers` | On daemon startup: populate known_peers map |

---

## Business rules

1. **trust_s initial value is 1.0 for new peers.** A brand-new peer has no storage history. `trust_s = 1.0` is neutral (clamp lower bound is 0.1, so it does not advantage or disadvantage). Do not set it to 0.0 (that would suppress the peer entirely via the multiplicative formula).

2. **Trust fields preserved on reconnect.** If `get_peer` returns an existing record, keep `trust_p`, `trust_i`, `trust_s`, `bytes_we_store_for_peer`, `bytes_peer_stores_for_us`, `first_seen` from the stored record. Only update `last_seen`, `node_id`, and `addrs`.

3. **`expected_identity = None` on first connect.** We do not know the peer's `IdentityPub` before the handshake completes. Passing `None` means the handshake accepts whoever responds (but still verifies the signature). This is intentional: the user chose to connect to this address.

4. **DB failure on upsert is non-fatal for networking but fatal for the response.** The connection is live; return an error response so the operator knows the DB write failed. Do not silently swallow DB errors.

5. **`add_peer` is called after successful DB upsert.** If DB write fails, `add_peer` is not called. The in-memory map and DB stay consistent: both have the peer, or neither does.

6. **Addr string format in `PeerRecord.addrs`.** Store the original `addr` string (the full `NodeId_hex@ip:port` as the user typed it). This is what `list_all_peers` returns on next startup, and `parse_node_addr` re-parses it identically.

7. **Startup peer loading uses first valid addr only.** If a peer has multiple addrs (future feature), only the first parseable one populates `known_peers`. All addrs remain in DB. This is a simplification acceptable for Phase 7.3; later phases may try addrs in order.

8. **`device_id` on PeerRecord.** Set to `Some(state.device_id)` for new peers. This records peer-to-device affinity: this device initiated the connection. For existing peers, preserve the existing `device_id` (already in the stored record).

---

## Test scenarios

### `addr.rs` tests (in `network/tests.rs` or a new `addr/tests.rs`)

All addr tests currently live in `crates/syncback/src/daemon/network/tests.rs`. Add the new tests there.

#### Test 1: `to_endpoint_addr_roundtrip_ipv4`

```rust
#[test]
fn to_endpoint_addr_roundtrip_ipv4() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use syncback_core::types::NodeId;
    use crate::daemon::network::addr::to_endpoint_addr;

    // Use a valid Ed25519 public key (all-zero is NOT a valid curve point;
    // use a known valid key derived from a signing key).
    let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let pk_bytes = sk.verifying_key().to_bytes();
    let node_id = NodeId(pk_bytes);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 12345);

    let endpoint_addr = to_endpoint_addr(&node_id, addr).expect("should succeed");
    // The EndpointAddr should contain our IP address.
    let ip_addrs: Vec<_> = endpoint_addr.ip_addrs().collect();
    assert_eq!(ip_addrs.len(), 1);
    assert_eq!(*ip_addrs[0], addr);
}
```

#### Test 2: `to_endpoint_addr_invalid_node_id_returns_error`

```rust
#[test]
fn to_endpoint_addr_invalid_node_id_returns_error() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use syncback_core::types::NodeId;
    use crate::daemon::network::addr::{ToEndpointAddrError, to_endpoint_addr};

    // All-zero bytes are not a valid Ed25519 public key.
    let node_id = NodeId([0u8; 32]);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000);

    let result = to_endpoint_addr(&node_id, addr);
    assert!(matches!(result, Err(ToEndpointAddrError::InvalidNodeId(_))));
}
```

Note: all-zero bytes are not guaranteed to be invalid in every version of the `iroh` crate. If this test fails because `iroh::PublicKey::from_bytes([0u8; 32])` succeeds, use a clearly invalid value (e.g., `[0xFF; 32]`) or construct a valid key for the positive test and skip the negative test. Add a `DECISION NEEDED` comment in the test if unsure.

#### Test 3: `add_peer_makes_get_connection_find_peer`

This is an integration test using two real iroh endpoints. Add to `network/tests.rs`.

```rust
#[tokio::test]
async fn add_peer_makes_get_connection_find_peer() {
    // Arrange: two NetworkHandles, A and B.
    let (sk_a, _) = keygen();
    let (sk_b, pk_b) = keygen();

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(10);
    let (tx_b, _rx_b) = tokio::sync::mpsc::channel(10);

    let handle_a = NetworkHandle::start(make_config(sk_a), tx_a)
        .await
        .expect("handle_a");
    let handle_b = NetworkHandle::start(make_config(sk_b), tx_b)
        .await
        .expect("handle_b");

    let addr_b = handle_b.local_addr().expect("addr_b");

    // Act: connect manually (no expected_identity), then add_peer.
    let conn = handle_a
        .connect(addr_b.clone(), None)
        .await
        .expect("connect");
    let peer_identity = conn.peer_identity;
    assert_eq!(peer_identity, pk_b, "peer identity from handshake matches B's key");

    handle_a.add_peer(peer_identity, addr_b).await;

    // Assert: get_connection now resolves by identity.
    let _arc = handle_a
        .get_connection(peer_identity)
        .await
        .expect("get_connection should succeed after add_peer");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}
```

### `cli_server/tests.rs` tests

#### Update existing stub test

The existing test `dispatch_connect_returns_connected_with_addr` sends `"192.168.1.1:12345"` (not a `NodeId@ip:port` format) and asserts `peer_id == addr`. This test must be updated because the real implementation will return an error for an invalid addr format:

```rust
#[tokio::test]
async fn dispatch_connect_invalid_addr_returns_error() {
    let state = make_test_state().await;
    // Not a NodeId@ip:port format — should parse-fail.
    let response = dispatch(
        CliRequest::Connect { addr: "192.168.1.1:12345".to_string() },
        &state,
    )
    .await;
    assert!(
        matches!(response, CliResponse::Error(_)),
        "expected Error for invalid addr format, got {response:?}"
    );
}
```

The old test name `dispatch_connect_returns_connected_with_addr` should be renamed to `dispatch_connect_invalid_addr_returns_error` and its assertion changed as shown.

#### New test: `dispatch_connect_valid_addr_but_no_peer_returns_error`

A well-formed addr string that points to a non-listening port. The connect will fail at the network level.

```rust
#[tokio::test]
async fn dispatch_connect_valid_addr_but_unreachable_returns_error() {
    let state = make_test_state().await;

    // Generate a valid Ed25519 key so the NodeId bytes are valid.
    let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let node_id_bytes = sk.verifying_key().to_bytes();
    let node_id_hex: String = node_id_bytes.iter().map(|b| format!("{b:02x}")).collect();

    // Port 1 is almost certainly not listening; this will fail at iroh connect.
    let addr = format!("{node_id_hex}@127.0.0.1:1");

    let response = dispatch(CliRequest::Connect { addr }, &state).await;
    assert!(
        matches!(response, CliResponse::Error(_)),
        "expected Error for unreachable peer, got {response:?}"
    );
}
```

Note: this test makes a real network call that will time out or be refused. Set a short iroh connect timeout or accept that this test may be slow. Mark it `#[ignore = "network"]` if network tests are not run by default in the project. Check existing network tests — `two_nodes_connect_and_handshake` is not ignored, so this test should also be non-ignored (the refusal is fast).

#### New test: `dispatch_connect_two_daemons_end_to_end`

This is a heavier integration test using two real `DaemonState` objects with real `NetworkHandle` instances.

```rust
#[tokio::test]
async fn dispatch_connect_two_daemons_registers_peer() {
    use syncback_core::db::Db;
    use syncback_core::types::{DeviceId, IdentityPub};

    // Build two DaemonStates backed by real NetworkHandles.
    let (sk_a, pk_a) = {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let pk = IdentityPub(sk.verifying_key().to_bytes());
        (sk, pk)
    };
    let (sk_b, pk_b) = {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let pk = IdentityPub(sk.verifying_key().to_bytes());
        (sk, pk)
    };

    // State B (the peer we will connect to).
    let (tx_b, _rx_b) = tokio::sync::mpsc::channel::<crate::daemon::network::connection::Connection>(4);
    let handle_b = Arc::new(
        NetworkHandle::start(
            crate::daemon::network::NetworkConfig {
                signing_key: sk_b,
                known_peers: Default::default(),
                device_cert: None,
                iroh_secret_key: None,
            },
            tx_b,
        )
        .await
        .expect("handle_b"),
    );
    let addr_b_endpoint = handle_b.local_addr().expect("addr_b");
    // Extract SocketAddr from EndpointAddr for formatting.
    let socket_addr_b = addr_b_endpoint
        .ip_addrs()
        .next()
        .copied()
        .expect("B must have a local IP addr");
    let addr_b_str = crate::daemon::network::addr::format_node_addr(&handle_b.node_id, socket_addr_b);

    // State A (the node running the CLI).
    let db_a = Db::open_in_memory().expect("db_a");
    let (tx_a, _rx_a) = tokio::sync::mpsc::channel::<crate::daemon::network::connection::Connection>(4);
    let handle_a = Arc::new(
        NetworkHandle::start(
            crate::daemon::network::NetworkConfig {
                signing_key: sk_a,
                known_peers: Default::default(),
                device_cert: None,
                iroh_secret_key: None,
            },
            tx_a,
        )
        .await
        .expect("handle_a"),
    );
    let (restore_tx, _restore_rx) = tokio::sync::mpsc::channel(4);
    let state_a = Arc::new(DaemonState {
        db: db_a.clone(),
        identity_pub: pk_a,
        device_id: DeviceId([1u8; 16]),
        network: handle_a.clone(),
        restore_tx,
        cluster_state: None,
    });

    // Act: dispatch Connect.
    let response = dispatch(CliRequest::Connect { addr: addr_b_str }, &state_a).await;

    // Assert: Connected response with B's identity hex.
    let CliResponse::Connected { peer_id } = response else {
        panic!("expected Connected, got {response:?}");
    };
    let expected_hex: String = pk_b.0.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(peer_id, expected_hex, "peer_id should be B's full identity hex");

    // Assert: peer saved in DB.
    let stored = db_a.get_peer(&pk_b).expect("db get_peer").expect("peer in db");
    assert_eq!(stored.identity, pk_b);
    assert!(!stored.addrs.is_empty(), "addr should be stored");

    // Assert: add_peer registered in NetworkHandle (get_connection resolves).
    let _ = handle_a.get_connection(pk_b).await.expect("get_connection after connect");

    handle_a.shutdown().await;
    handle_b.shutdown().await;
}
```

This test makes real network connections. If the project's CI policy requires isolation, mark it `#[ignore = "network"]`. The test name follows the `what_when_then` convention.

---

## Implementation order

1. **`addr.rs`:** Add `ToEndpointAddrError` and `to_endpoint_addr`. Run `cargo build -p syncback`.
2. **`network/mod.rs`:** Change `known_peers` field to `Arc<RwLock<...>>`. Update `start()` constructor. Update `get_connection()`. Add `add_peer()`. Run `cargo build -p syncback`.
3. **`cli_server/mod.rs`:** Add `dispatch_connect` function. Wire it into `dispatch`. Run `cargo build -p syncback`.
4. **`handle/mod.rs`:** Add peer loading block (step 3a). Update `net_config` construction. Run `cargo build -p syncback`.
5. **Run `cargo test -p syncback`** — confirm all existing tests still pass.
6. **Update `cli_server/tests.rs`:** Rename and update the stub Connect test. Add the two new tests.
7. **Update `network/tests.rs`:** Add `to_endpoint_addr_roundtrip_ipv4`, `to_endpoint_addr_invalid_node_id_returns_error`, `add_peer_makes_get_connection_find_peer`.
8. **Run `cargo test -p syncback`** — confirm all tests pass.
9. **Run `cargo clippy -p syncback -- -D warnings`** — confirm no warnings.

---

## Potential pitfalls

- **`all-zero NodeId` may be valid.** `iroh::PublicKey::from_bytes([0u8; 32])` may succeed in iroh 0.96 (some Ed25519 implementations accept the identity point). If the negative test for `to_endpoint_addr_invalid_node_id_returns_error` fails, replace with a clearly invalid byte pattern or simply remove that test case and note the iroh crate accepts all 32-byte arrays.

- **`EndpointAddr::ip_addrs()` returns an iterator of references, not owned values.** The test code copies with `copied()` for `SocketAddr` (which is `Copy`). If the iterator returns `&SocketAddr`, use `.copied()` or `.cloned()`.

- **`get_connection` creates a new connection if none exists.** After `add_peer`, `get_connection(peer_identity)` will create a new iroh connection (it is not pooling the `conn` we opened in `dispatch_connect`). The existing `conn` from the handshake is returned to `dispatch_connect` and then dropped. This means two connections may exist briefly. This is acceptable for Phase 7.3; connection pooling improvements are a later concern.

- **`RwLock` vs `Mutex` on `known_peers`.** The `read()` and `write()` calls are `async` (tokio `RwLock`). The guard must not be held across an `await` that may block long (e.g., `self.connect(...)`). The spec shows releasing the guard into an owned `Option<EndpointAddr>` before calling `connect`. Do not hold a `RwLockReadGuard` across `connect`.

- **`iroh::EndpointAddr::new` vs `EndpointAddr::from_parts`.** The WebFetch showed both `EndpointAddr::new(id)` and `EndpointAddr::from_parts(id, addrs)`. Use `EndpointAddr::new(pubkey).with_ip_addr(addr)` per the WebFetch result. If this API is not available in the exact iroh 0.96 version in the Cargo.lock, use `EndpointAddr::from_parts(pubkey, [TransportAddr::Ip(socket_addr)])` as an alternative. The implementer must verify against the actual iroh 0.96 docs or source.

- **`DeviceId` for new peer record.** The spec sets `device_id: Some(state.device_id)`. This records which device of ours manages this peer. The `device_id` field on `PeerRecord` is about peer-to-device affinity on our side (not the remote peer's device).

- **`trust_s = 1.0` for new peers.** The trust formula is `trust = (kp*P + ki*I) * clamp(S, 0.1, 1.0)`. A new peer has `P=0, I=0`, so combined trust = 0 regardless of `S`. Setting `S=1.0` is conventional for "no data yet".

---

## Checklist for reviewer

- [ ] `to_endpoint_addr` added to `addr.rs` with correct signature.
- [ ] `ToEndpointAddrError` defined and exported from `addr.rs`.
- [ ] `known_peers` in `NetworkHandle` is `Arc<RwLock<HashMap<...>>>`.
- [ ] `NetworkConfig.known_peers` still `HashMap` (unchanged).
- [ ] `NetworkHandle::start` wraps `config.known_peers` in `Arc::new(RwLock::new(...))`.
- [ ] `get_connection` reads `known_peers` via `read().await`, drops guard before `connect`.
- [ ] `add_peer` takes `&self` (not `&mut self`), uses `write().await`.
- [ ] `dispatch_connect` replaces the stub in `cli_server/mod.rs`.
- [ ] `dispatch_connect` calls `parse_node_addr`, `to_endpoint_addr`, `network.connect(_, None)`.
- [ ] On success: `db.get_peer` checked first, `upsert_peer` called, then `add_peer`.
- [ ] `add_peer` NOT called if DB upsert failed.
- [ ] Response is `Connected { peer_id: full_64_char_hex }`.
- [ ] `handle/mod.rs` loads peers from DB before constructing `NetworkConfig`.
- [ ] `net_config.known_peers` uses loaded map (not `HashMap::new()`).
- [ ] Existing test `dispatch_connect_returns_connected_with_addr` renamed and updated to expect `Error`.
- [ ] New tests: `dispatch_connect_invalid_addr_returns_error`, `dispatch_connect_valid_addr_but_unreachable_returns_error`, `dispatch_connect_two_daemons_registers_peer`.
- [ ] New tests: `to_endpoint_addr_roundtrip_ipv4`, `to_endpoint_addr_invalid_node_id_returns_error`, `add_peer_makes_get_connection_find_peer`.
- [ ] `cargo build -p syncback` passes.
- [ ] `cargo test -p syncback` passes.
- [ ] `cargo clippy -p syncback -- -D warnings` passes.
