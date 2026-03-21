# Phase 7.8: Reconnection + dead connection cleanup

## Scope

Currently `NetworkHandle::connections` is a pool of `ConnectionState::Live(Arc<Mutex<Connection>>)`
entries. Once a connection breaks (QUIC stream EOF, timeout, remote close), subsequent
`send_message` / `recv_message` calls on the stale `Arc<Mutex<Connection>>` return an error.
The pool is never cleaned up, so dead entries accumulate and every subsequent call to
`get_connection` returns the dead entry from the pool and immediately fails.

This phase adds:
1. Dead-entry removal from the pool on send/recv failure.
2. Backoff: after a connection failure, do not retry for N seconds (avoid hammering an offline
   peer).
3. A `get_connection` retry: after removing dead entry, attempt one fresh connect.

## Files changed

- `crates/syncback/src/daemon/network/mod.rs` — `ConnectionState` enum, `get_connection`,
  new `BackoffMap`, new `send_to_peer` helper
- `crates/syncback/src/daemon/network/tests.rs` — new tests

## Current state

```rust
// mod.rs line 106:
enum ConnectionState {
    Live(Arc<Mutex<Connection>>),
}
```

Only `Live` variant exists. `get_connection` checks the pool, creates if missing, stores
`ConnectionState::Live`, and returns. No error path removes dead entries.

## New `ConnectionState`

```rust
/// Internal pool entry.
enum ConnectionState {
    /// Live authenticated connection.
    Live(Arc<Mutex<Connection>>),
    /// Connection failed recently. Don't retry until `retry_after` unix timestamp.
    Backoff { retry_after: u64 },
}
```

## New `NetworkHandle` field

```rust
/// Per-peer backoff state. Keys are IdentityPub.
/// Stored separately from `connections` to allow backoff to outlive a pool eviction.
/// Backoff duration: RECONNECT_BACKOFF_SECS.
///
/// NOTE: This is the same map as `connections` conceptually, but kept as a separate
/// field so the backoff state can be checked before acquiring the connections lock
/// (avoiding lock nesting). Alternatively, fold into ConnectionState::Backoff.
///
/// DECISION: fold into ConnectionState::Backoff (single lock, simpler).
/// The connections map will contain either Live or Backoff entries.
```

**Decision:** fold into `ConnectionState::Backoff`. The `connections` map already holds one entry
per peer; making it `Live | Backoff` keeps all state in one place.

## Backoff constant

```rust
// In crates/syncback-core/src/constants.rs — add:
/// Seconds before retrying a failed peer connection.
pub const RECONNECT_BACKOFF_SECS: u64 = 30;
```

Add the import in `network/mod.rs`:
```rust
use syncback_core::constants::RECONNECT_BACKOFF_SECS;
```

## Modified `get_connection`

```rust
pub async fn get_connection(
    &self,
    peer_identity: IdentityPub,
) -> Result<Arc<Mutex<Connection>>, NetworkError> {
    // ── 1. Check pool ──────────────────────────────────────────────────────
    {
        let pool = self.connections.lock().await;
        match pool.get(&peer_identity) {
            Some(ConnectionState::Live(arc)) => {
                return Ok(arc.clone());
            }
            Some(ConnectionState::Backoff { retry_after }) => {
                let now = unix_now();
                if now < *retry_after {
                    // Still in backoff window.
                    return Err(NetworkError::PeerNotFound(peer_identity));
                    // NOTE: PeerNotFound is reused here; a dedicated
                    // ConnectionBackoff variant would be cleaner but adds API surface.
                    // DECISION NEEDED: add NetworkError::ConnectionBackoff?
                    // For now, callers treat PeerNotFound and backoff the same way
                    // (skip this holder, try next).
                }
                // Backoff expired; fall through to reconnect.
            }
            None => {
                // Not in pool; fall through to fresh connect.
            }
        }
    }

    // ── 2. Resolve address ─────────────────────────────────────────────────
    let peer_addr = {
        let peers = self.known_peers.read().await;
        peers.get(&peer_identity).cloned()
    }
    .ok_or(NetworkError::PeerNotFound(peer_identity))?;

    // ── 3. Connect ─────────────────────────────────────────────────────────
    match self.connect(peer_addr, Some(peer_identity)).await {
        Ok(conn) => {
            let arc = Arc::new(Mutex::new(conn));
            self.connections
                .lock()
                .await
                .insert(peer_identity, ConnectionState::Live(arc.clone()));
            Ok(arc)
        }
        Err(e) => {
            // Record backoff so we don't spam connect attempts.
            let retry_after = unix_now() + RECONNECT_BACKOFF_SECS;
            self.connections
                .lock()
                .await
                .insert(peer_identity, ConnectionState::Backoff { retry_after });
            Err(e)
        }
    }
}
```

## New `send_to_peer` helper

Callers like `send_symbols` currently call `get_connection` then lock the conn and call
`send_message`. If `send_message` fails, the dead entry remains. Introduce a helper that
removes the dead entry on failure and records backoff:

```rust
/// Send a message to a peer by identity. On send failure, removes the dead pool
/// entry and records a backoff entry so the next `get_connection` attempt
/// reconnects rather than returning the dead arc.
///
/// Returns the error from the failed send so the caller can decide how to handle it.
pub async fn send_to_peer(
    &self,
    peer_identity: IdentityPub,
    msg: &Message,
) -> Result<(), NetworkError> {
    let arc = self.get_connection(peer_identity).await?;
    let mut guard = arc.lock().await;
    match guard.send_message(msg).await {
        Ok(()) => Ok(()),
        Err(e) => {
            debug!(
                peer = %peer_identity,
                err = %e,
                "send_to_peer: send failed, evicting from pool"
            );
            drop(guard); // release conn lock before pool lock
            let retry_after = unix_now() + RECONNECT_BACKOFF_SECS;
            self.connections
                .lock()
                .await
                .insert(peer_identity, ConnectionState::Backoff { retry_after });
            Err(e)
        }
    }
}
```

## Modified `send_symbols`

Replace `get_connection` + manual send with `send_to_peer`:

```rust
pub async fn send_symbols(
    &self,
    peer_identity: IdentityPub,
    msg: SymbolTransferMsg,
) -> Result<(), NetworkError> {
    self.send_to_peer(peer_identity, &Message::SymbolTransfer(msg)).await
}
```

## Dead-connection eviction in Processor read loop

The Processor's per-connection read loop (in `run`) already handles `recv_message` errors by
breaking the loop:

```rust
Err(e) => {
    debug!(peer = %peer_id, err = %e, "processor: connection closed");
    break;
}
```

This is correct — the read loop exits, no more messages from this conn. But the dead `Arc` is
still in `NetworkHandle::connections`. To evict it, the Processor needs a reference to
`NetworkHandle`. It already holds one after Phase 7.6.

Add eviction call when the read loop breaks due to error:

```rust
// After break due to error:
// Evict the dead connection so get_connection reconnects next time.
// Use best-effort: ignore errors (pool lock unavailable, etc.).
this_network.evict_connection(peer_id);
```

New method on `NetworkHandle`:

```rust
/// Remove a connection from the pool and record a backoff entry.
/// Called by the Processor read loop when a connection dies.
pub async fn evict_connection(&self, peer_identity: IdentityPub) {
    let retry_after = unix_now() + RECONNECT_BACKOFF_SECS;
    self.connections
        .lock()
        .await
        .insert(peer_identity, ConnectionState::Backoff { retry_after });
    debug!(peer = %peer_identity, "connection evicted, backoff recorded");
}
```

For Processor to call this, it needs `Arc<NetworkHandle>` in its per-connection read loop
closure. The `this` Arc in the read loop is `Arc<Processor>`. Add `network` access via
`this2.network` (already available after Phase 7.6 adds it as a field).

The read loop spawned task currently captures only `conn_arc2`, `tx`, and `peer_id`. Extend it
to also capture `network_arc: Arc<NetworkHandle>` from `this.network.clone()`.

## Private helper

```rust
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
```

This already exists as an inline in `processor/mod.rs` (`current_week_number`). Add a shared
version here.

## `NetworkError` — no new variants

DECISION NEEDED: add `ConnectionBackoff { peer: IdentityPub }` variant to `NetworkError` so
callers can distinguish "backoff, try later" from "never heard of this peer"? The distinction
is useful for logging but callers (BackupCoordinator, RestoreCoordinator) handle both the same
way: skip this holder, try the next. Defer to a follow-up task.

## Test scenarios

All tests go in `crates/syncback/src/daemon/network/tests.rs`.

### Unit: get_connection returns backoff error during backoff window

```
get_connection_returns_error_during_backoff
  Setup:   Insert ConnectionState::Backoff { retry_after: now + 3600 } for peer_b
  Action:  handle_a.get_connection(peer_b_identity)
  Expect:  Err(NetworkError::PeerNotFound) or similar
           (the backoff entry is checked before connecting)

  Note: cannot easily test with real network; test by directly manipulating the
  connections pool. This requires exposing a test-only method
  `inject_backoff(identity, retry_after)` or making connections pub(crate).
```

For the test-only injection approach:
```rust
#[cfg(any(test, feature = "testutil"))]
pub async fn inject_backoff_for_test(&self, peer: IdentityPub, retry_after: u64) {
    self.connections.lock().await.insert(peer, ConnectionState::Backoff { retry_after });
}
```

### Unit: backoff expires and reconnects

```
get_connection_reconnects_after_backoff_expires
  Setup:   handle_b running. Insert Backoff { retry_after: unix_now() - 1 } (expired)
           for peer_b in handle_a's pool. handle_a knows peer_b's address.
  Action:  handle_a.get_connection(peer_b_identity)
  Expect:  Succeeds — a new live connection is established.
           Pool now has ConnectionState::Live for peer_b.
```

### Integration: send_symbols on dead connection evicts and succeeds on retry

```
send_to_peer_evicts_dead_connection_and_retries
  Setup:
    - handle_a connected to handle_b (live connection in pool).
    - Manually close handle_b (shutdown).
    - handle_b_replacement started on same address.

  Action:
    - handle_a.send_to_peer(peer_b_identity, &msg)

  Expect (first call):
    - send fails → dead entry evicted → Backoff recorded → Err returned.

  Then (wait for backoff to expire OR use zero-backoff for test):
    - handle_a.get_connection(peer_b_identity) returns fresh connection.

  Note: Testing "same address, new node" is non-trivial with iroh. Simplification:
  just verify the eviction behavior (dead entry → Backoff) without the reconnect part.
```

Simplified test:

```
send_to_peer_records_backoff_on_send_failure
  Setup:
    - handle_a and handle_b connected.
    - Close handle_b (endpoint.close()).
    - Wait briefly for connection to die.
  Action:
    - handle_a.send_to_peer(handle_b.identity_pub, &some_message)
  Expect:
    - Err(NetworkError::*) returned.
    - handle_a.connections pool contains ConnectionState::Backoff for peer_b.
      (verify via inspect_connection_state_for_test helper)
```

Add test helper:
```rust
#[cfg(any(test, feature = "testutil"))]
pub async fn is_peer_in_backoff(&self, peer: &IdentityPub) -> bool {
    matches!(
        self.connections.lock().await.get(peer),
        Some(ConnectionState::Backoff { .. })
    )
}
```

### Integration: `evict_connection` removes live entry

```
evict_connection_removes_live_entry
  Setup:   handle_a connected to handle_b (live in pool).
  Action:  handle_a.evict_connection(handle_b.identity_pub).await
  Expect:  Pool contains Backoff for handle_b (not Live).
           is_peer_in_backoff(handle_b.identity_pub) == true.
```

### Regression: existing `get_connection` creates pool entry

```
add_peer_makes_get_connection_find_peer  (already exists as Test 10c)
  Must continue to pass without modification.
```

### Regression: `send_symbols` roundtrip

```
send_symbol_transfer_roundtrip  (already exists as Test 3)
  Must continue to pass.
```

## Constants file change summary

```rust
// crates/syncback-core/src/constants.rs — add:
pub const RECONNECT_BACKOFF_SECS: u64 = 30;
```

## Acceptance criteria

- `#[allow(dead_code)]` removed from any field made live by this phase.
- `cargo test -p syncback` and `cargo test -p syncback-core` pass.
- All existing network tests pass unchanged.
- After `evict_connection`, calling `get_connection` for that peer during the backoff window
  returns an error (does not spin-connect).
- After backoff expires, `get_connection` attempts a fresh connect (verified by the
  `get_connection_reconnects_after_backoff_expires` test).
- `send_symbols` uses `send_to_peer` and records backoff on failure.
- No `unwrap()` in new production code.
