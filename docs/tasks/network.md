# Task spec: network module (Phase 2)

Target file: `crates/syncback/src/daemon/network.rs`

## Overview

`NetworkTask` is the iroh-facing tokio task. It owns the `Endpoint`, runs an accept loop for
incoming QUIC connections, opens outgoing connections on command, performs the SyncBack
handshake (§1.1 of overview.md), and pipes authenticated messages to `Processor` via a
channel. It does not touch the DB. The only writer of shared state is `Processor`.

Communication:
- `Processor` sends `NetCommand` to `NetworkTask` via `tokio::mpsc`
- `NetworkTask` sends `NetEvent` to `Processor` via `tokio::mpsc`

---

## Dependencies

- `syncback-core::messages` — `DirectMessage`, `DirectBody`, `HandshakeMsg`, `RestoreRequestMsg`,
  `RestoreDeniedMsg`, `BlobReadyMsg`, `frame_message`, `parse_framed`
- `syncback-core::types` — `IdentityPub`, `NodeId`
- `iroh::endpoint::{Endpoint, RelayMode, Incoming, Connection, SendStream, RecvStream}`
- `iroh::SecretKey`
- `tokio::sync::mpsc`
- `tokio_util::sync::CancellationToken`
- `ed25519_dalek::SigningKey`

---

## Public API

### `NetworkTask` struct

```rust
/// Owns the iroh Endpoint and drives all QUIC connections.
pub struct NetworkTask {
    endpoint: Endpoint,
    /// iroh NodeId bytes (for logging / identity mapping).
    node_id: NodeId,
    /// Our identity key — used to sign HandshakeMsg.
    identity_key: ed25519_dalek::SigningKey,
    /// Our identity_pub — sent in HandshakeMsg.
    identity_pub: IdentityPub,
    /// Commands from Processor.
    cmd_rx: tokio::sync::mpsc::Receiver<NetCommand>,
    /// Events to Processor.
    event_tx: tokio::sync::mpsc::Sender<NetEvent>,
    /// Graceful shutdown token.
    cancel: tokio_util::sync::CancellationToken,
}
```

### Constructor

```rust
impl NetworkTask {
    /// Create NetworkTask and return its channel handles.
    ///
    /// `secret_key` — iroh SecretKey (derived from seed phrase via
    ///     HKDF-SHA256(seed, info="syncback-iroh-ed25519")).
    /// `identity_key` — Ed25519 SigningKey (separate from iroh key).
    ///
    /// For production: use `Endpoint::builder()` (N0 relay preset).
    /// For tests:      use `Endpoint::empty_builder(RelayMode::Disabled)`.
    pub async fn new(
        iroh_secret_key: iroh::SecretKey,
        identity_key: ed25519_dalek::SigningKey,
        identity_pub: IdentityPub,
        cancel: tokio_util::sync::CancellationToken,
        relay_mode: iroh::endpoint::RelayMode,
    ) -> Result<(NetworkTask, NetworkHandle), NetworkError>;
}
```

`new` creates the `Endpoint` internally. The `relay_mode` parameter lets callers pass
`RelayMode::Disabled` in tests and `RelayMode::Default` (N0 preset) in production.

The function returns `(NetworkTask, NetworkHandle)` where `NetworkHandle` is the Processor-side
view (see below). Channel buffer sizes: cmd=64, event=256.

### `NetworkHandle`

```rust
/// Processor-side handle to the network task.
/// Clone-able — Processor and CLI Server each hold a clone.
#[derive(Clone)]
pub struct NetworkHandle {
    pub cmd_tx: tokio::sync::mpsc::Sender<NetCommand>,
    pub endpoint_addr: iroh::endpoint::EndpointAddr,
    pub node_id: NodeId,
}
```

`endpoint_addr` and `node_id` are captured at bind time and stored here so Processor can
include them in `peer_announce` messages without asking Network.

### `NetworkTask::run`

```rust
impl NetworkTask {
    /// Main event loop. Drive until `cancel` is triggered.
    /// Spawned by daemon main as a dedicated tokio task.
    pub async fn run(mut self);
}
```

The run loop uses `tokio::select!` with three arms:
1. `self.endpoint.accept()` — handle incoming connection
2. `self.cmd_rx.recv()` — handle command from Processor
3. `self.cancel.cancelled()` — shutdown: call `self.endpoint.close().await` then return

### `NetCommand` enum

```rust
#[derive(Debug)]
pub enum NetCommand {
    /// Open an outgoing connection to a peer and send a DirectMessage.
    /// The message must already be a complete DirectMessage (framed by network.rs).
    Connect {
        peer_addr: iroh::endpoint::EndpointAddr,
        peer_identity: IdentityPub,
        message: DirectMessage,
    },
    /// Send a DirectMessage over an already-established connection.
    /// If no live connection exists, establish one first.
    SendMessage {
        peer_identity: IdentityPub,
        peer_addr: iroh::endpoint::EndpointAddr,
        message: DirectMessage,
    },
}
```

### `NetEvent` enum

```rust
#[derive(Debug)]
pub enum NetEvent {
    /// Handshake completed successfully on an incoming connection.
    PeerConnected {
        peer_identity: IdentityPub,
        peer_node_id: NodeId,
    },
    /// A DirectMessage was received from an authenticated peer.
    MessageReceived {
        from: IdentityPub,
        message: DirectMessage,
    },
    /// Handshake failed (log and ignore — peer simply disconnects).
    HandshakeFailed {
        reason: String,
    },
}
```

### `NetworkError` enum

```rust
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("iroh endpoint bind failed: {0}")]
    BindFailed(String),

    #[error("connection failed to {peer:?}: {reason}")]
    ConnectFailed { peer: IdentityPub, reason: String },

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("framing error: {0}")]
    Framing(#[from] syncback_core::messages::MessageError),

    #[error("io error: {0}")]
    Io(String),
}
```

### Framing helpers (module-level, pub(crate))

These wrap `messages::frame_message` / `messages::parse_framed` for stream I/O.

```rust
/// Write one framed message to a SendStream.
/// [u32 BE length][CBOR bytes] — max 64 KB per message.
pub(crate) async fn write_message(
    send: &mut SendStream,
    msg: &DirectMessage,
) -> Result<(), NetworkError>;

/// Read one framed message from a RecvStream.
/// Reads exactly (4 + length) bytes. Returns error if > 64 KB.
pub(crate) async fn read_message(
    recv: &mut RecvStream,
) -> Result<DirectMessage, NetworkError>;
```

`write_message` implementation:
1. Call `messages::frame_message(msg)?` to get `Vec<u8>`
2. `send.write_all(&framed).await` mapping I/O errors to `NetworkError::Io`

`read_message` implementation:
1. Read 4 bytes for length prefix
2. Validate `len <= MAX_MESSAGE_SIZE` (64 KB), else return `NetworkError::Framing`
3. Read `len` more bytes
4. Call `messages::parse_framed(&buf)` and return the message

---

## Handshake Protocol (§1.1)

### Outgoing connection (initiator side)

```
1. endpoint.connect(peer_addr, b"syncback/1").await  → Connection
2. conn.open_bi().await  → (SendStream, RecvStream)
3. Build HandshakeMsg::new(identity_pub, now_unix, &identity_key)
4. wrap in DirectMessage { v: 1, body: DirectBody::Handshake(msg) }
5. write_message(&mut send, &direct_msg).await
6. read_message(&mut recv).await  → DirectMessage
7. Extract DirectBody::Handshake(their_msg)
8. their_msg.verify()?   — sig valid?
9. their_msg.check_freshness(now_unix)?  — ±5 min
10. Extract peer identity_pub from their_msg
11. Emit NetEvent::PeerConnected { peer_identity, peer_node_id }
12. Send the application-level message that triggered Connect/SendMessage
```

### Incoming connection (acceptor side)

```
1. endpoint.accept().await  → Option<Incoming>
   None → endpoint closed, break loop
2. incoming.accept()?  → Accepting
3. Accepting.await?  → Connection
4. Spawn tokio task: handle_connection(conn, event_tx.clone(), identity_key.clone(), identity_pub)
   — each connection handled in its own task so accept loop stays live
5. In handle_connection:
   a. conn.accept_bi().await  → (SendStream, RecvStream)
   b. read_message(&mut recv).await  → DirectMessage
   c. Extract DirectBody::Handshake(their_msg)
   d. their_msg.verify()?
   e. their_msg.check_freshness(now_unix)?
   f. Build our HandshakeMsg and write it back
   g. Emit NetEvent::PeerConnected { ... }
   h. Loop: read_message → emit NetEvent::MessageReceived for each subsequent message
```

### Handshake verification rules

From overview.md §1.1:
1. `sig` must be valid for the claimed `identity_pub` — use `HandshakeMsg::verify()`
2. `timestamp` must be within ±300 seconds of local clock — use `HandshakeMsg::check_freshness()`
3. `identity_pub` must be known (present in peer directory) **or** connection is from a seed node

Rule 3 for alpha: **skip the allowlist check**. Accept any peer that presents a valid signature
and fresh timestamp. Rationale: we have no iroh-docs board sync yet (that's a separate module).
The allowlist enforcement belongs in the message-processing layer (Processor), not the
transport layer. Mark with `// TODO(Phase2): enforce peer allowlist` comment.

Seed nodes (bootstrap): same rule — accept any valid handshake. No special code path needed.

---

## Endpoint Lifecycle

### Creation (inside `NetworkTask::new`)

```rust
// Tests
let ep = Endpoint::empty_builder(relay_mode)
    .secret_key(iroh_secret_key)
    .alpns(vec![b"syncback/1".to_vec()])
    .bind()
    .await
    .map_err(|e| NetworkError::BindFailed(e.to_string()))?;

// Production (relay_mode == RelayMode::Default handled by builder())
let ep = Endpoint::builder()
    .secret_key(iroh_secret_key)
    .alpns(vec![b"syncback/1".to_vec()])
    .bind()
    .await
    .map_err(|e| NetworkError::BindFailed(e.to_string()))?;
```

Actual implementation: always use `Endpoint::empty_builder(relay_mode)` to keep one code path.
For production the caller passes `relay_mode = RelayMode::Default` (which adds N0 relays via
iroh's `From<RelayMode>` impl). For tests the caller passes `RelayMode::Disabled`.

Extract `node_id` after binding:
```rust
let ep_addr = ep.addr();
// EndpointId is the iroh NodeId. Extract its bytes.
// iroh::endpoint::EndpointAddr wraps EndpointId which wraps PublicKey (32 bytes).
// Use ep_addr.node_id().as_bytes() to get [u8; 32].
let node_id = NodeId(ep_addr.node_id().as_bytes().try_into().expect("32 bytes"));
```

DECISION NEEDED: Confirm that `EndpointAddr::node_id()` exists and returns the public key.
The smoke test uses `ep_b.addr()` and passes it to `ep_a.connect(addr_b, ...)` directly.
Check iroh 0.96 `EndpointAddr` API for the exact method to extract `[u8; 32]`.

### Shutdown

On `cancel.cancelled()`:
```rust
tracing::info!("network task shutting down");
self.endpoint.close().await;
return;
```

`Endpoint::close()` is `async fn close(&self)` with no return value (see endpoint.rs:1325).
After close, any pending `accept()` returns `None`, which terminates the accept arm naturally.

---

## Connection handling details

### Per-connection task

Each accepted connection spawns a new `tokio::task`. The task holds:
- `conn: Connection` — the iroh connection
- `event_tx: mpsc::Sender<NetEvent>` — to send events to Processor
- Identity signing key (for responding to handshake)

If the handshake fails, the task emits `NetEvent::HandshakeFailed { reason }`, closes the
connection, and exits. The accept loop continues unaffected.

If the connection drops mid-message (I/O error), the task exits silently (DEBUG log). Not an
error — peers go offline.

### Connection reuse (alpha: NOT implemented)

In alpha, each `NetCommand::SendMessage` opens a fresh connection. No connection pool.
This is acceptable: direct connections are rare (restore, blob transfer). Mark with
`// TODO: connection pool for frequent peers`.

### Multiple streams per connection

The handshake uses exactly one bidi stream (the first one opened/accepted). After handshake,
the connection can carry additional messages. For MVP: each logical message exchange opens a
new bidi stream. The reader loop in `handle_connection` calls `conn.accept_bi()` in a loop
for subsequent streams after handshake.

---

## iroh API surface used

All validated in `crates/syncback/tests/iroh_smoke.rs`:

```rust
use iroh::endpoint::{Endpoint, RecvStream, SendStream, RelayMode};
use iroh::SecretKey;

// Build
Endpoint::empty_builder(RelayMode::Disabled)
    .secret_key(iroh_secret_key)
    .alpns(vec![ALPN.to_vec()])
    .bind()
    .await?

// Accept loop
let incoming: Option<Incoming> = ep.accept().await;
let accepting: Accepting = incoming.accept()?;   // note: ? not .await
let conn: Connection = accepting.await?;

// Outgoing
let conn: Connection = ep.connect(addr, ALPN).await?;

// Streams
let (mut send, mut recv): (SendStream, RecvStream) = conn.open_bi().await?;
let (mut send, mut recv): (SendStream, RecvStream) = conn.accept_bi().await?;

// I/O
send.write_all(&bytes).await?;
send.finish()?;
send.stopped().await?;
recv.read_to_end(MAX_SIZE).await?;

// Address
ep.addr()  // returns EndpointAddr

// Shutdown
ep.close().await;

// Key
SecretKey::from_bytes(&[u8; 32])
```

Note: the smoke test shows `incoming.accept()?.await?` — `accept()` is NOT async (returns
`Result<Accepting, ConnectionError>`), and `Accepting` implements `Future` which yields
`Result<Connection, ConnectingError>`.

---

## Channel integration with Processor

### NetworkTask side

```rust
// Emit event
let _ = self.event_tx.send(NetEvent::MessageReceived { from, message }).await;
// If send returns Err, Processor has dropped — exit the task.
```

Use `event_tx.send(...).await` (async, backpressure). If Processor is gone, network task
shuts down. Buffer of 256 events handles bursts (50 partners × a few messages each).

### Processor side (not implemented here, just the contract)

Processor owns `net_rx: mpsc::Receiver<NetEvent>` and `net_handle: NetworkHandle`.

To send a command:
```rust
net_handle.cmd_tx.send(NetCommand::SendMessage { ... }).await?;
```

---

## Error handling (alpha)

| Situation | Action |
|-----------|--------|
| iroh bind fails | `NetworkError::BindFailed` → propagate to daemon main → panic |
| Handshake sig invalid | log DEBUG, emit `HandshakeFailed`, close conn |
| Handshake stale timestamp | log DEBUG, emit `HandshakeFailed`, close conn |
| Connection refused/timeout | log DEBUG, emit nothing (peer offline = normal) |
| I/O error mid-stream | log DEBUG, task exits |
| `event_tx` full | `send(...).await` blocks — backpressure. Processor must drain. |
| `event_tx` closed | exit per-conn task silently |

Do not panic on peer-caused errors. Panic only on invariant violations (e.g. framing that
should never fail on our own messages).

---

## Logging

```
INFO  peer connected: {peer_id}           — after successful handshake
INFO  network task shutting down          — on cancel
DEBUG handshake failed: {reason} from {addr}
DEBUG connection failed: {peer_id} {reason}
DEBUG message received: {type} from {peer_id}
DEBUG outgoing connect: {peer_id} at {addr}
TRACE raw frame: len={len} bytes          — only at TRACE
```

Use structured fields:
```rust
tracing::info!(peer_id = %peer_identity, "peer connected");
tracing::debug!(reason = %reason, addr = %remote_addr, "handshake failed");
```

---

## DB operations

None. NetworkTask does not touch redb. All state mutations go through Processor.

---

## File layout

Per memory note: tests go in a separate file.

```
crates/syncback/src/daemon/network/
  mod.rs      — NetworkTask, NetworkHandle, NetCommand, NetEvent, NetworkError, run()
  tests.rs    — unit and integration tests
```

Or (simpler for a single-file module):
```
crates/syncback/src/daemon/network.rs   — all of the above
```

Use a single file `network.rs` with `#[cfg(test)] mod tests;` referring to `network/tests.rs`
only if the test file grows large. Start with a single `network.rs`.

---

## Test scenarios

### Unit tests (fast, no real iroh)

These test the framing helpers and message construction — no network needed.

```rust
// 1. frame_and_parse_roundtrip
// Input: a HandshakeMsg wrapped in DirectMessage
// Expected: parse_framed(frame_message(msg)) == msg
fn frame_and_parse_roundtrip_for_handshake()

// 2. frame_rejects_oversized_message
// Input: DirectMessage with body containing Vec<u8> of 65536 bytes
// Expected: frame_message returns Err(MessageError::TooLarge)
fn frame_rejects_message_over_64kb()

// 3. read_message_returns_error_on_short_buffer
// Input: 3 bytes (too short for length prefix)
// Expected: NetworkError::Framing(BufferTooShort { need: 4, have: 3 })
fn read_message_detects_truncated_length_prefix()
```

### Integration tests (real iroh, `crates/syncback/tests/`)

Add to the existing integration test file or create `network_handshake.rs`.

```rust
// 1. two_nodes_connect_and_handshake
// Setup: two NetworkTask instances with random iroh keys and random identity keys
// Action: A connects to B (NetCommand::Connect)
// Expected:
//   - B emits NetEvent::PeerConnected { peer_identity = A.identity_pub }
//   - A emits NetEvent::PeerConnected { peer_identity = B.identity_pub }
// Timeout: 5 seconds
#[tokio::test]
async fn two_nodes_connect_and_handshake()

// 2. handshake_fails_on_invalid_signature
// Setup: two endpoints; A sends a HandshakeMsg where sig_author is all zeros (invalid)
// Expected: B emits NetEvent::HandshakeFailed; B's accept loop keeps running
// Implementation note: craft raw message manually, bypass NetworkTask on A's side
#[tokio::test]
async fn handshake_fails_on_invalid_signature()

// 3. handshake_fails_on_stale_timestamp
// Setup: two endpoints; A sends HandshakeMsg with timestamp = now - 400 seconds
// Expected: B emits NetEvent::HandshakeFailed { reason contains "timestamp" }
#[tokio::test]
async fn handshake_fails_on_stale_timestamp()

// 4. message_received_after_handshake
// Setup: two NetworkTask instances; A and B complete handshake
// Action: A sends NetCommand::SendMessage with DirectBody::RestoreRequest(...)
// Expected: B emits NetEvent::MessageReceived { from = A.identity_pub, message = RestoreRequest }
#[tokio::test]
async fn message_received_after_successful_handshake()

// 5. network_task_shuts_down_cleanly
// Setup: one NetworkTask; trigger cancel
// Expected: run() returns within 1 second; endpoint closed
#[tokio::test]
async fn network_task_shuts_down_on_cancel()
```

### Test helpers

```rust
// In tests module
async fn make_test_network_pair() -> (NetworkHandle, mpsc::Receiver<NetEvent>,
                                      NetworkHandle, mpsc::Receiver<NetEvent>) {
    // Create two NetworkTask instances with RelayMode::Disabled
    // Spawn both run() loops
    // Return handles and event receivers for each
}

fn random_identity_key() -> (ed25519_dalek::SigningKey, IdentityPub) {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
    let pub_bytes: [u8; 32] = key.verifying_key().to_bytes();
    (key, IdentityPub(pub_bytes))
}

fn random_iroh_key() -> iroh::SecretKey {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    iroh::SecretKey::from_bytes(&bytes)
}
```

---

## Open decisions

### DECISION NEEDED: `EndpointAddr` → `NodeId` bytes

The smoke test shows `ep_b.addr()` returns `EndpointAddr`. To populate `NetworkHandle::node_id`
we need to extract 32 bytes from it. Check iroh 0.96 whether `EndpointAddr::node_id()` or
similar exists that gives access to the underlying `PublicKey`/`[u8; 32]`. If not, derive
`NodeId` from the `SecretKey` directly: `SecretKey::public()` returns the `PublicKey`.

Preferred: `let node_id = NodeId(iroh_secret_key.public().as_bytes().try_into().unwrap());`
— done before `bind()`, does not require querying the endpoint.

### DECISION NEEDED: iroh-docs board sync scope

This spec covers only direct QUIC connections (handshake, DirectMessage). The board sync
(iroh-docs, shard_offer, PoS challenge/response delivery) is a separate concern. The
`NetEvent::MessageReceived` event only fires for direct connection messages. Board-based
messages are processed by a separate module. Confirm this scope split is correct before
implementing.

### DECISION NEEDED: Connection reuse in SendMessage

Current spec says: open fresh connection per command. If Processor needs to send multiple
messages to the same peer in a burst (e.g. restore flow: RestoreRequest × k shards), this
creates k separate connections. For alpha this is acceptable but may need a connection map
(`HashMap<IdentityPub, Connection>`). Decide at implementation time whether to add it.

---

## Implementation checklist

- [ ] `NetworkTask::new` — bind endpoint, create channels, populate `NetworkHandle`
- [ ] `NetworkTask::run` — tokio::select! over accept/cmd/cancel
- [ ] `handle_incoming(conn, ...)` — handshake acceptor, per-conn task
- [ ] `handle_outgoing(ep, cmd, ...)` — open connection, do handshake, send message
- [ ] `write_message(send, msg)` — framing write
- [ ] `read_message(recv)` — framing read
- [ ] Unit tests: framing roundtrip, oversized rejection, truncation detection
- [ ] Integration tests: two nodes handshake, invalid sig, stale ts, message delivery, shutdown
