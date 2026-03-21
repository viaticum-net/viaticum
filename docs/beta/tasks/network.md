# Task: network — iroh transport layer (β)

Module: `crates/syncback/src/daemon/network/`
Files: `mod.rs` + `connection.rs` + `tests.rs`

---

## Overview

The network module wraps iroh as a pure transport layer. It provides direct QUIC
connections with ALPN `"syncback/1"`, handshake authentication, and framed CBOR message
send/receive. It does NOT use iroh-blobs or iroh-docs. Everything above the byte stream
level is handled by other modules (BackupCoordinator, RestoreCoordinator, relay).

**Phase 2 gate requirement:** `два node'а, отправка символов` — two nodes on localhost,
one sends `SymbolTransferMsg` to the other, receiver decodes it correctly.

**What this module does:**

1. **iroh endpoint management** — create and manage one `iroh::Endpoint` per daemon
   instance. Bind to a random UDP port. Expose the node's `iroh::NodeId` and
   `iroh::NodeAddr` for peer_announce messages.

2. **Outbound connections** — connect to a peer by `iroh::NodeAddr`. Authenticate with
   SyncBack handshake (identity_pub + timestamp + sig, both directions). Return an
   authenticated `Connection` handle.

3. **Inbound connections** — accept incoming connections, perform handshake, return
   authenticated `Connection`.

4. **Framed message I/O** — on an authenticated connection: send a `Message` as
   `[u32 BE len][CBOR]`, receive a `Message` by reading length prefix then CBOR.
   The `frame_message` / `unframe_message` functions from the messages module are used.

5. **Connection pool** — maintain a pool of live connections keyed by `IdentityPub`.
   Reuse existing connections for the same peer. Evict on connection error.

6. **Symbol transfer** — high-level helpers: `send_symbols(conn, msg)` and
   `receive_symbols(conn)` that send/receive `SymbolTransferMsg` with correct framing.

The network module is deliberately thin. It is a byte transport with handshake
authentication. Business logic (PoS, backup, restore) lives in other modules that use
network's `Connection` type.

---

## Dependencies

- `syncback_core::messages::{Message, frame_message, unframe_message, build_handshake,
    verify_handshake, HandshakeMsg, SymbolTransferMsg, MessageError}`
- `syncback_core::types::{IdentityPub, NodeId, Timestamp}`
- `syncback_core::constants::{ALPN, MAX_MESSAGE_SIZE}`
- `iroh::{Endpoint, NodeAddr, NodeId as IrohNodeId}`
- `ed25519_dalek::{SigningKey, VerifyingKey}`
- `tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::Mutex}`
- `anyhow::{Context, Result}`
- `tracing::{info, debug, error, warn}`
- `std::collections::HashMap`

New deps for `syncback/Cargo.toml`:
```toml
iroh = { workspace = true }
ed25519-dalek = { workspace = true }
```

---

## Types

```rust
/// A successfully authenticated direct connection to a peer.
/// Wraps an iroh QUIC bidirectional stream.
pub struct Connection {
    /// Authenticated remote identity.
    pub peer_identity: IdentityPub,
    /// iroh connection (owned).
    inner: iroh::endpoint::Connection,
    /// Bidirectional stream for protocol messages.
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

/// Configuration for the network layer.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Ed25519 signing key for handshake signing and identity.
    /// identity_pub = signing_key.verifying_key()
    pub signing_key: ed25519_dalek::SigningKey,
    /// Known peer directory: IdentityPub → iroh NodeAddr.
    /// Used to find transport address for a given identity.
    /// Populated from DB PeerRecords by the caller.
    pub known_peers: HashMap<IdentityPub, iroh::NodeAddr>,
}

/// Handle to the running network layer.
pub struct NetworkHandle {
    endpoint: iroh::Endpoint,
    /// Our identity public key.
    pub identity_pub: IdentityPub,
    /// iroh NodeId (transport identity, distinct from identity_pub).
    pub node_id: NodeId,
    signing_key: ed25519_dalek::SigningKey,
    /// Live authenticated connections, keyed by peer IdentityPub.
    connections: Arc<tokio::sync::Mutex<HashMap<IdentityPub, ConnectionState>>>,
}

/// Internal connection state.
enum ConnectionState {
    Live(Arc<tokio::sync::Mutex<Connection>>),
}

/// Error type for network operations.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("iroh error: {0}")]
    Iroh(#[from] anyhow::Error),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("message error: {0}")]
    Message(#[from] MessageError),

    #[error("peer not found in directory: {0}")]
    PeerNotFound(IdentityPub),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("peer identity mismatch: expected {expected}, got {got}")]
    IdentityMismatch { expected: IdentityPub, got: IdentityPub },
}
```

---

## Public API

```rust
impl NetworkHandle {
    /// Start a new network handle.
    ///
    /// Creates an iroh Endpoint with ALPN "syncback/1".
    /// Spawns an accept loop as a background tokio task.
    ///
    /// incoming_tx: channel to send authenticated inbound Connection handles to
    /// the daemon's connection dispatcher.
    pub async fn start(
        config: NetworkConfig,
        incoming_tx: tokio::sync::mpsc::Sender<Connection>,
    ) -> Result<Self, NetworkError>;

    /// Get the iroh NodeAddr for this endpoint (for peer_announce).
    /// Includes the bound UDP address.
    pub fn local_addr(&self) -> Result<iroh::NodeAddr, NetworkError>;

    /// Connect to a peer by iroh NodeAddr.
    ///
    /// 1. iroh connect (QUIC + TLS, ALPN "syncback/1")
    /// 2. Open bidirectional stream
    /// 3. Send our HandshakeMsg
    /// 4. Receive peer's HandshakeMsg
    /// 5. Verify peer's handshake (sig + freshness)
    /// 6. If expected_identity is Some, verify peer.identity_pub == expected_identity
    /// 7. Return authenticated Connection
    pub async fn connect(
        &self,
        peer_addr: iroh::NodeAddr,
        expected_identity: Option<IdentityPub>,
    ) -> Result<Connection, NetworkError>;

    /// Get or create a connection to a peer by IdentityPub.
    ///
    /// Looks up peer_addr in connection pool, then in config.known_peers.
    /// Returns existing live connection or creates new one.
    /// Returns Err(PeerNotFound) if identity not in known_peers.
    pub async fn get_connection(
        &self,
        peer_identity: IdentityPub,
    ) -> Result<Arc<tokio::sync::Mutex<Connection>>, NetworkError>;

    /// Send a Message on a connection. Frames with [u32 BE len][CBOR].
    pub async fn send_message(
        conn: &mut Connection,
        msg: &Message,
    ) -> Result<(), NetworkError>;

    /// Receive next Message from a connection.
    /// Reads u32 BE length prefix, then CBOR payload.
    /// Returns Err(ConnectionClosed) on clean close, Err(Io) on error.
    pub async fn recv_message(
        conn: &mut Connection,
    ) -> Result<Message, NetworkError>;

    /// Send symbols to a peer. High-level helper.
    /// Wraps symbols in SymbolTransferMsg and sends.
    pub async fn send_symbols(
        &self,
        peer_identity: IdentityPub,
        msg: syncback_core::messages::SymbolTransferMsg,
    ) -> Result<(), NetworkError>;

    /// Shutdown the endpoint gracefully.
    pub async fn shutdown(self);
}
```

---

## Business Rules

### iroh vs SyncBack identity

iroh uses its own `NodeId` (Ed25519 key) for QUIC transport. SyncBack uses `IdentityPub`
for protocol-level identity. They are distinct:

```
identity_pub  = SigningKey.verifying_key()  (our key, stored as IdentityPub)
iroh NodeId   = derived separately by iroh from its own keypair

Both are deterministically derived from seed phrase in the full system, but they are
different keys. The mapping is published via peer_announce messages.
```

For Phase 2, the network test just needs two iroh endpoints to connect; the identity keys
can be generated fresh per test.

### Handshake protocol

```
A connects to B:
  A opens bidirectional stream with ALPN "syncback/1"
  A sends: frame_message(Message::Handshake(build_handshake(our_identity, now, signing_key)))
  A receives: Message::Handshake(peer_hs)
  A calls: verify_handshake(&peer_hs, now)
  A checks: if expected_identity.is_some() && peer_hs.identity_pub != expected_identity → Err

B (in accept loop):
  B receives connection from A
  B receives: Message::Handshake(a_hs)
  B calls: verify_handshake(&a_hs, now)
  B sends: frame_message(Message::Handshake(build_handshake(our_identity, now, signing_key)))
  B has authenticated Connection with peer_identity = a_hs.identity_pub
```

After handshake completion, the stream is used for further protocol messages. There is no
"command type" routing at the network layer — callers read `recv_message()` in a loop and
dispatch by variant.

### Framing

All messages on the wire: `[u32 BE length][CBOR payload]`.

Use `frame_message()` from messages module to produce wire bytes.
Use `unframe_message()` to parse.

Never write raw CBOR directly to the stream — the length prefix is mandatory. The messages
module documents this rule explicitly.

### Symbol transfer size

A `SymbolTransferMsg` with 328 symbols × 65535 bytes = ~21 MB. This is within
MAX_MESSAGE_SIZE (64 MB). For larger batches (e.g., all symbols for one holder at once),
the caller should chunk into multiple SymbolTransferMsg messages if needed.

In Phase 2, the gate test sends all symbols for one source block to one peer in a single
SymbolTransferMsg. This works because the test uses small source blocks.

### Connection pool

The connection pool (`connections: HashMap<IdentityPub, ConnectionState>`) prevents
reconnecting for every message. On send error, remove the entry from the pool. The caller
can retry, which will establish a new connection.

The pool is protected by `tokio::sync::Mutex`. Each `Connection` is wrapped in an
`Arc<Mutex<Connection>>` so multiple callers can schedule sends sequentially (connections
are not multiplexed in Phase 2 — one logical stream per connection).

### Accept loop

The `start()` method spawns a background tokio task:
```rust
while let Some(incoming) = endpoint.accept().await {
    tokio::spawn(async move {
        let conn = incoming.await;
        // open bidirectional stream
        // perform handshake (B side)
        // send Connection to incoming_tx
    });
}
```

Errors in the accept loop are logged and the individual connection is dropped (not fatal
to the accept loop).

---

## DB Operations

None. The network module does not touch DB. It receives peer addresses from the caller.

---

## Test Scenarios

Tests in `network/tests.rs`. Pattern: `what_when_then`.

All tests use `#[tokio::test]`. Tests run two iroh endpoints on localhost with random
ports.

### 1. `two_nodes_connect_and_handshake`

```
// Create two endpoints with distinct signing keys
config_a = NetworkConfig { signing_key: keygen(), known_peers: {} }
config_b = NetworkConfig { signing_key: keygen(), known_peers: {} }
(tx_a, _rx_a) = mpsc::channel(10)
(tx_b, rx_b) = mpsc::channel(10)

handle_a = NetworkHandle::start(config_a, tx_a).await.unwrap()
handle_b = NetworkHandle::start(config_b, tx_b).await.unwrap()

addr_b = handle_b.local_addr().unwrap()
conn = handle_a.connect(addr_b, None).await.unwrap()

// B side: wait for incoming connection
incoming = rx_b.recv().await.unwrap()
assert conn.peer_identity == handle_b.identity_pub
assert incoming.peer_identity == handle_a.identity_pub
```

### 2. `send_and_receive_message_roundtrip`

```
// After establishing conn (from test 1)
msg = Message::PosChallenge(PosChallengeMsg {
    v: 1,
    challenge_id: [0u8; 16],
    source_block_id: SourceBlockId([1u8; 32]),
    esi: 42,
    timestamp: Timestamp::now(),
})

NetworkHandle::send_message(&mut conn_a_to_b, &msg).await.unwrap()
received = NetworkHandle::recv_message(&mut conn_b_from_a).await.unwrap()
assert received == msg
```

### 3. `send_symbol_transfer_roundtrip`

```
// Create a small SymbolTransferMsg
symbols = (0..5).map(|esi| Symbol { esi, data: vec![0u8; 65535] }).collect()
msg = SymbolTransferMsg {
    v: 1,
    source_block_id: SourceBlockId([2u8;32]),
    symbols,
    timestamp: Timestamp::now(),
}

NetworkHandle::send_message(&mut conn, &Message::SymbolTransfer(msg.clone())).await.unwrap()
received = NetworkHandle::recv_message(&mut other_conn).await.unwrap()
assert matches!(received, Message::SymbolTransfer(m) if m == msg)
```

### 4. `handshake_rejects_stale_timestamp`

```
// Manually craft a handshake with an old timestamp
signing_key = SigningKey::generate(&mut OsRng)
identity_pub = IdentityPub(signing_key.verifying_key().to_bytes())
stale_ts = Timestamp(0)  // Unix epoch — definitely stale
hs = build_handshake(identity_pub, stale_ts, &signing_key)

// verify_handshake should fail
result = verify_handshake(&hs, Timestamp::now())
assert matches!(result, Err(MessageError::HandshakeStale { .. }))
```

### 5. `handshake_rejects_bad_signature`

```
signing_key = SigningKey::generate(&mut OsRng)
identity_pub = IdentityPub(signing_key.verifying_key().to_bytes())
mut hs = build_handshake(identity_pub, Timestamp::now(), &signing_key)
hs.sig[0] ^= 0xFF  // corrupt

result = verify_handshake(&hs, Timestamp::now())
assert matches!(result, Err(MessageError::BadSignature))
```

### 6. `connect_with_expected_identity_mismatch_fails`

```
// Connect to B but expect a different identity
wrong_identity = IdentityPub([0xFF; 32])
result = handle_a.connect(addr_b, Some(wrong_identity)).await
assert matches!(result, Err(NetworkError::IdentityMismatch { .. }))
```

### 7. `multiple_messages_on_same_connection`

```
// Send 10 messages in sequence, verify all received in order
for i in 0..10 {
    msg = Message::StorageWarning(StorageWarningMsg { ..., details: format!("msg {i}"), ... })
    NetworkHandle::send_message(&mut conn_a, &msg).await.unwrap()
    received = NetworkHandle::recv_message(&mut conn_b).await.unwrap()
    assert matches!(received, Message::StorageWarning(m) if m.details == format!("msg {i}"))
}
```

---

## Module Structure

```
network/
  mod.rs          — NetworkHandle, NetworkConfig, NetworkError, public API
  connection.rs   — Connection struct, send_message/recv_message impl
  tests.rs        — all test scenarios above
```

---

## Notes for implementer

- iroh 0.96: the API for creating endpoints uses `iroh::Endpoint::builder()`. Check the
  actual 0.96 API — iroh releases change APIs frequently. Key types:
  `iroh::Endpoint`, `iroh::endpoint::Connection`, `iroh::endpoint::SendStream`,
  `iroh::endpoint::RecvStream`, `iroh::NodeAddr`.
  Use `endpoint.accept().await` for inbound connections.
  Use `endpoint.connect(peer_addr, ALPN)` for outbound.

- ALPN: pass `ALPN` constant (`b"syncback/1"`) to both the endpoint builder (as accepted
  ALPN) and to `connect()`. iroh uses ALPN to route connections to the right handler.

- The `Connection` struct wraps split send/recv streams from one bidirectional QUIC
  stream. After the handshake exchange (2 messages), the same stream is used for all
  subsequent messages. Do not open a new stream per message.

- `recv_message` reads exactly the declared length. Use
  `recv.read_exact(&mut len_buf[..4])` then `recv.read_exact(&mut payload_buf)`.
  Handle `UnexpectedEof` as `ConnectionClosed`.

- For the gate test, two nodes on the same machine are sufficient. iroh does not need a
  relay server for localhost connections.

- The `known_peers` in `NetworkConfig` is a `HashMap<IdentityPub, iroh::NodeAddr>`.
  This is populated from DB `PeerRecord.node_id` by the daemon startup. In Phase 2 tests,
  it is populated manually in the test setup.

- The SyncBack `NodeId` type is `[u8; 32]`. The iroh `NodeId` is also a 32-byte public
  key. Conversion: `iroh::NodeId::from_bytes(&node_id.0)`. The `PeerRecord.node_id` field
  stores the iroh NodeId that was announced in the peer's latest `peer_announce`.

- All tests in `network/tests.rs`. Use `#[tokio::test]` for async tests.
  Tests must handle port availability — use random ports (iroh binds to `0.0.0.0:0`
  by default). Do not hardcode port numbers.
