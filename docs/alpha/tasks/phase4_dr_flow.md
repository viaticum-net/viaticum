# Task spec: Phase 4 DR flow

**Target files:**
- `crates/syncback-core/src/messages/mod.rs` — add new `DirectBody` variants
- `crates/syncback/src/daemon/mod.rs` — new `ScheduledCmd` and `CliCmd` variants
- `crates/syncback/src/daemon/processor/mod.rs` — four new handlers
- `crates/syncback/src/daemon/network/mod.rs` — dispatch new `DirectBody` variants
- `crates/syncback/src/daemon/scheduler.rs` — schedule `SystemStateBackup`
- `crates/syncback/src/daemon/cli_server/mod.rs` — new CLI command + request/response types
- `crates/syncback/src/cli.rs` — new `restore` subcommand entry point

**Phase:** 4 (Full Disaster Recovery)
**Role:** Orchestration layer — system state backup scheduling, sending, holding, and DR boot

---

## Overview

Phase 4 adds two capabilities:

1. **Automatic system state backup**: after every WeeklySync, the owner serializes its DB to a compact encrypted blob and pushes plain copies to up to 15 peers. Peers store the blob in a dedicated `SYSTEM_STATE_BLOBS` table and reply with an ack.

2. **DR boot from seed phrase**: `syncback restore --seed "24 words" --peer "addr"` starts a minimal daemon, connects to a peer, retrieves the stored system state blob, decrypts and deserializes it, then populates the local DB. After this, the node knows all its files, shards, and peers — normal shard restore flow follows.

This spec covers the orchestration layer only (new messages, channel types, processor handlers, scheduler, CLI). It depends on two prerequisite Phase 4 specs:
- `phase4_packer_update.md` — unit_size=32 MB, `MAX_MESSAGE_SIZE=64 MB`, zstd compression in packer
- `phase4_system_state.md` — `SystemState` struct, `snapshot_db`, `pack_system_state`, `unpack_system_state`, `restore_db`

---

## Dependencies

**syncback-core:**
- `db::Db` — all table access
- `messages::*` — new `DirectBody` variants and message structs defined here
- `types::*` — `IdentityPub`, `Timestamp`

**syncback (same crate, other modules):**
- `daemon::processor` — four new handler methods
- `daemon::network` — dispatch of four new message types
- `daemon::scheduler` — adds `SystemStateBackup` command
- `daemon::cli_server` — new `CliRequest::DrRestore` and response handling
- `daemon::system_state` — new module (defined in `phase4_system_state.md`):
  `snapshot_db`, `pack_system_state`, `unpack_system_state`, `restore_db`
- `daemon::packer` — key derivation helper (already present: `derive_unit_key`)

---

## New message types — messages/mod.rs

Add four variants to the existing `DirectBody` enum. The enum already has:
`Handshake`, `RestoreRequest`, `RestoreDenied`, `BlobReady`, `ShardData`.

```rust
// In DirectBody enum, add:
SystemStateRequest {
    /// The requesting node's IdentityPub (verified via handshake before dispatch).
    requester: IdentityPub,
},
SystemStateResponse {
    /// Encrypted system state blob, or empty vec if not found.
    blob: Vec<u8>,
    /// Unix timestamp when this backup was created. Zero when not found.
    created_at: Timestamp,
},
SystemStateBackup {
    /// Encrypted system state blob for the holder to store.
    blob: Vec<u8>,
    /// Unix timestamp when this backup was created.
    created_at: Timestamp,
},
SystemStateAck {
    /// True if the holder successfully stored the blob.
    stored: bool,
},
```

Add corresponding structs (follow the existing pattern — each message body is its own struct even when used inline in DirectBody; this matches the existing `HandshakeMsg`, `RestoreRequestMsg` pattern).

```rust
/// Owner → Holder. Push a system state backup blob for the holder to store.
/// DirectBody::SystemStateBackup(SystemStateBackupMsg).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemStateBackupMsg {
    pub blob: Vec<u8>,
    pub created_at: Timestamp,
}

/// Holder → Owner. Confirms (or denies) storage of a system state blob.
/// DirectBody::SystemStateAck(SystemStateAckMsg).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemStateAckMsg {
    pub stored: bool,
}

/// Requester → Holder. Ask for the stored system state blob for requester's identity.
/// DirectBody::SystemStateRequest(SystemStateRequestMsg).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemStateRequestMsg {
    /// The identity requesting its own system state.
    /// The holder verifies this matches the handshake identity before sending.
    pub requester: IdentityPub,
}

/// Holder → Requester. The stored blob (or empty on not-found).
/// DirectBody::SystemStateResponse(SystemStateResponseMsg).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemStateResponseMsg {
    /// Empty vec means "not found".
    pub blob: Vec<u8>,
    /// Zero when not found.
    pub created_at: Timestamp,
}
```

Update `DirectBody::variant_name()` in `network/mod.rs` (the private `VariantName` trait impl) to cover the four new variants. This is required or the match will fail to compile.

**Size constraint:** `SystemStateBackupMsg` and `SystemStateResponseMsg` carry the full blob (~13 MB compressed). The `MAX_MESSAGE_SIZE` constant must be updated to 64 MB before these messages are framed. This update is in `phase4_packer_update.md`. The framing code in `frame_message` already checks against the constant, so changing the constant is sufficient.

---

## New channel types — daemon/mod.rs

### ScheduledCmd

```rust
#[derive(Debug, Clone)]
pub enum ScheduledCmd {
    WeeklySync,
    PosRound,
    Vacuum,
    RepairCheck,
    SystemStateBackup,   // NEW: runs after WeeklySync completes
}
```

### CliCmd

```rust
pub enum CliCmd {
    // ... existing variants unchanged ...
    DrRestore {
        seed_phrase: Vec<String>,     // 24 BIP39 words
        peer_addr: String,            // JSON-encoded iroh EndpointAddr
        reply: tokio::sync::oneshot::Sender<Result<(), String>>,
    },
}
```

---

## New CLI types — cli_server/mod.rs

### CliRequest

```rust
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum CliRequest {
    // ... existing variants unchanged ...
    DrRestore {
        /// Space-separated 24 BIP39 words, or a JSON array of words.
        seed_phrase: String,
        /// JSON-encoded iroh EndpointAddr of a known peer.
        peer_addr: String,
    },
}
```

The CLI binary parses `syncback restore --seed "word1 word2 ..." --peer "addr"` and
sends `CliRequest::DrRestore` over the Unix socket. The daemon must be running for this
to work. See the DR boot flow section for how the daemon handles this.

---

## DB operations

### New table: SYSTEM_STATE_BLOBS

Location: `crates/syncback-core/src/db/mod.rs`

```rust
/// System state blobs held for other nodes (holder view).
/// Key = IdentityPub bytes (32 bytes). Value = CBOR(SystemStateBlobRecord).
/// One entry per owner — new backup overwrites old.
const SYSTEM_STATE_BLOBS: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("system_state_blobs");
```

Add the table to `Db::open` (the table must be created during DB initialization or
lazily on first write — follow the existing pattern where all tables are opened in
`open_tables` within a write transaction at startup).

### New record type: SystemStateBlobRecord (types/mod.rs)

```rust
/// Stored in SYSTEM_STATE_BLOBS. Keyed by owner IdentityPub.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemStateBlobRecord {
    /// Encrypted system state blob (only readable by the owner's identity key).
    pub blob: Vec<u8>,
    /// When the owner created this backup (from the message).
    pub created_at: Timestamp,
    /// When this node received and stored it.
    pub received_at: Timestamp,
}
```

### DB methods to add to Db (db/mod.rs)

```rust
impl Db {
    /// Store a system state blob for the given owner. Overwrites any previous blob.
    pub fn store_system_state_blob(
        &self,
        owner: &IdentityPub,
        record: &SystemStateBlobRecord,
    ) -> Result<(), DbError>;

    /// Retrieve the stored system state blob for an owner, if any.
    pub fn get_system_state_blob(
        &self,
        owner: &IdentityPub,
    ) -> Result<Option<SystemStateBlobRecord>, DbError>;

    /// Delete the stored system state blob for an owner (used during eviction).
    pub fn delete_system_state_blob(
        &self,
        owner: &IdentityPub,
    ) -> Result<(), DbError>;

    /// List all owners for which a system state blob is stored.
    /// Returns (IdentityPub, received_at) pairs.
    pub fn list_system_state_blob_owners(
        &self,
    ) -> Result<Vec<(IdentityPub, Timestamp)>, DbError>;
}
```

---

## Processor handlers — processor/mod.rs

Add four new handler methods to `Processor`. All are `async fn` that take `&mut self`
(or appropriate borrows).

### Handler 1: handle_system_state_backup

Triggered by `ScheduledCmd::SystemStateBackup`. Called from the main select! loop
after `handle_weekly_sync` returns.

```rust
async fn handle_system_state_backup(&mut self) {
    // 1. Call system_state::snapshot_db(&self.db) → SystemState
    // 2. Call system_state::pack_system_state(&state, &self.identity_key)
    //    → encrypted blob (Vec<u8>)
    //    Key derivation: HKDF-SHA256(identity_priv, salt=b"system-state", info=b"syncback-system-state-encryption")
    //    This is defined in phase4_system_state.md.
    // 3. Select up to 15 peers by trust:
    //    - Read all peers from DB: self.db.list_peers()
    //    - Sort by trust score (descending): self.trust_engine.score(peer)
    //    - Take top 15
    //    - If fewer than 3 peers available: log INFO "too few peers for system state backup,
    //      skipping"; return.
    // 4. For each selected peer:
    //    - Construct DirectMessage { v: PROTOCOL_VERSION,
    //        body: DirectBody::SystemStateBackup(SystemStateBackupMsg {
    //            blob: blob.clone(),
    //            created_at: now_unix_secs(),
    //        })
    //      }
    //    - Look up peer's EndpointAddr from DB peer record (node_addr field)
    //    - Send via NetCommand::SendMessage { peer_identity, peer_addr, message }
    //    - No waiting for ack here — fire and forget, acks logged on receipt.
    // 5. Log INFO "system_state_backup: sent to N peers, blob_bytes=M"
}
```

**Trust engine access:** The Processor already holds `self.trust_engine`. Use
`self.trust_engine.score(peer_identity)` (or the equivalent existing method) to rank peers.

**Peer addr lookup:** Use the existing DB `list_peers()` method that returns `PeerRecord`s.
The `PeerRecord` contains `node_addr: Option<Vec<u8>>` (serialized EndpointAddr). Skip
peers with no known addr.

### Handler 2: handle_system_state_request (holder side)

Called from the message dispatch loop when `NetEvent::MessageReceived` contains
`DirectBody::SystemStateRequest`.

```rust
async fn handle_system_state_request(
    &self,
    from: IdentityPub,
    msg: SystemStateRequestMsg,
) {
    // 1. Verify msg.requester == from (peer verified by handshake).
    //    If mismatch: log DEBUG "system_state_request: requester mismatch, ignoring"; return.
    // 2. Look up blob: self.db.get_system_state_blob(&msg.requester)
    // 3. Build response:
    //    - Found: SystemStateResponseMsg { blob: record.blob, created_at: record.created_at }
    //    - Not found: SystemStateResponseMsg { blob: vec![], created_at: 0 }
    // 4. Send response via NetCommand::SendDirect (already framed):
    //    - frame_message(&DirectMessage { v: PROTOCOL_VERSION,
    //        body: DirectBody::SystemStateResponse(response) })
    //    - NetCommand::SendDirect { peer: from, payload: framed_bytes }
    // 5. Log DEBUG "system_state_request: responded to {from}, found={found}"
}
```

**Why SendDirect:** The response blob is large (~13 MB). `SendDirect` uses the existing
QUIC connection infrastructure. The `MAX_MESSAGE_SIZE` update (64 MB) in
`phase4_packer_update.md` must be in place before this works.

### Handler 3: handle_system_state_response (DR side, owner receives)

Called when `NetEvent::MessageReceived` contains `DirectBody::SystemStateResponse`.
This only fires during the DR boot flow.

```rust
async fn handle_system_state_response(
    &mut self,
    from: IdentityPub,
    msg: SystemStateResponseMsg,
    reply_tx: Option<tokio::sync::oneshot::Sender<Result<SystemStateResponseMsg, String>>>,
) {
    // DR boot flow passes a reply_tx via Processor state (see DR boot section).
    // 1. If msg.blob is empty: signal failure via reply_tx ("not found at peer {from}")
    // 2. If msg.blob is non-empty: signal success via reply_tx(Ok(msg))
    // 3. If reply_tx is None (unexpected response outside DR flow): log DEBUG and ignore.
}
```

The Processor holds a transient field `pending_dr_reply: Option<oneshot::Sender<...>>`
that is set when the DR boot flow sends the request and cleared when the response arrives.

### Handler 4: handle_system_state_ack (owner receives ack from holder)

```rust
async fn handle_system_state_ack(
    &self,
    from: IdentityPub,
    msg: SystemStateAckMsg,
) {
    // Informational only — no retry logic in alpha.
    if msg.stored {
        tracing::info!(peer = %from, "system_state_ack: holder stored backup");
    } else {
        tracing::info!(peer = %from, "system_state_ack: holder rejected backup");
    }
}
```

### Changes to handle_system_state_backup_received (holder receives push)

This is called when the holder receives `DirectBody::SystemStateBackup`:

```rust
async fn handle_system_state_backup_received(
    &mut self,
    from: IdentityPub,
    msg: SystemStateBackupMsg,
) {
    // 1. Validate: blob non-empty and created_at > 0. If invalid: send ack(stored=false).
    // 2. Check disk pressure: system state blobs are small (~13 MB each).
    //    Max 15 owners × 13 MB = 195 MB. No special quota check — holder accepts if
    //    it has accepted the peer at all (simple policy for alpha).
    //    If total system_state_blobs storage exceeds soft threshold, skip.
    //    DECISION NEEDED: define threshold for refusing system state blobs. For alpha:
    //    always accept from known peers (any peer we have a PeerRecord for), reject from unknown.
    // 3. Check: is 'from' a known peer?
    //    self.db.get_peer(&from).is_some() → accept; else reject.
    // 4. Build record:
    //    SystemStateBlobRecord { blob: msg.blob, created_at: msg.created_at,
    //                             received_at: now_unix_secs() }
    // 5. Store: self.db.store_system_state_blob(&from, &record)
    // 6. Send ack:
    //    frame SystemStateAck { stored: true } → NetCommand::SendDirect { peer: from, payload }
    // 7. Log INFO "system_state_backup_received: stored blob for {from}, bytes={N}"
}
```

### Dispatch in message loop

In `processor::run`'s main `tokio::select!` loop, the `NetEvent::MessageReceived`
dispatch arm must be extended:

```rust
NetEvent::MessageReceived { from, message } => {
    match message.body {
        // ... existing arms ...
        DirectBody::SystemStateBackup(msg) => {
            processor.handle_system_state_backup_received(from, msg).await;
        }
        DirectBody::SystemStateRequest(msg) => {
            processor.handle_system_state_request(from, msg).await;
        }
        DirectBody::SystemStateResponse(msg) => {
            processor.handle_system_state_response(from, msg,
                processor.pending_dr_reply.take()).await;
        }
        DirectBody::SystemStateAck(msg) => {
            processor.handle_system_state_ack(from, msg).await;
        }
    }
}
```

### Scheduled dispatch

In the `ProcessorMsg::Scheduled(cmd)` arm:

```rust
ScheduledCmd::WeeklySync => {
    processor.handle_weekly_sync().await;
    // After weekly sync, trigger system state backup.
    processor.handle_system_state_backup().await;
}
ScheduledCmd::SystemStateBackup => {
    // Can also be triggered standalone (e.g., after DrRestore completes).
    processor.handle_system_state_backup().await;
}
```

---

## Processor struct changes

Add one field to `Processor`:

```rust
pub struct Processor {
    // ... existing fields ...
    /// Set during DR boot. Cleared when SystemStateResponse arrives.
    pending_dr_reply: Option<tokio::sync::oneshot::Sender<Result<SystemStateResponseMsg, String>>>,
}
```

---

## Scheduler changes — scheduler.rs

Add `SystemStateBackup` to the scheduler. This command fires once per week, offset by
1 day after WeeklySync (so it doesn't fire before the first sync).

```rust
const SYSTEM_STATE_BACKUP_FIRST_OFFSET: Duration = Duration::from_secs(8 * 24 * 3600); // 8 days

// In run():
let mut system_state_backup_due = start + SYSTEM_STATE_BACKUP_FIRST_OFFSET;

// In the tick handler:
if now >= system_state_backup_due {
    send_cmd(&processor_tx, ScheduledCmd::SystemStateBackup, "system_state_backup").await;
    system_state_backup_due = now + WEEKLY;
}
```

**Note:** The Processor also triggers `SystemStateBackup` inline after `WeeklySync` completes
(see Processor handler above). The scheduler's `SystemStateBackup` is a safety net in case
`WeeklySync` was skipped or the inline trigger was not reached.

---

## CLI changes — cli_server/mod.rs and cli.rs

### cli_server/mod.rs

Add `DrRestore` to `CliRequest`:

```rust
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum CliRequest {
    // ... existing variants unchanged ...
    DrRestore {
        /// 24 BIP39 words, space-separated.
        seed_phrase: String,
        /// JSON-encoded iroh EndpointAddr of a peer holding the system state.
        peer_addr: String,
    },
}
```

Add dispatch in `dispatch()`:

```rust
CliRequest::DrRestore { seed_phrase, peer_addr } => {
    let words: Vec<String> = seed_phrase
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    if words.len() != 24 {
        return CliResponse::Error {
            message: format!("seed phrase must be 24 words, got {}", words.len()),
        };
    }
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let cmd = ProcessorMsg::Cli(CliCmd::DrRestore {
        seed_phrase: words,
        peer_addr: peer_addr.clone(),
        reply: reply_tx,
    });
    if processor_tx.send(cmd).await.is_err() {
        return CliResponse::Error { message: "daemon not responding".into() };
    }
    match reply_rx.await {
        Ok(Ok(())) => CliResponse::Ok {
            message: "DR restore completed: DB populated. Run 'syncback restore <file>' to restore files.".into(),
        },
        Ok(Err(e)) => CliResponse::Error { message: e },
        Err(_) => CliResponse::Error { message: "processor dropped reply".into() },
    }
}
```

### cli.rs

Add `restore` subcommand to the clap CLI definition. The existing `restore` subcommand
restores a single file. DR is a different subcommand: `dr-restore`.

```rust
// In the clap App / Commands enum:
DrRestore {
    /// 24-word BIP39 seed phrase (quoted).
    #[arg(long, required = true)]
    seed: String,
    /// JSON-encoded iroh EndpointAddr of a peer that holds your system state.
    #[arg(long, required = true)]
    peer: String,
},
```

Handler in `cli.rs`:

```rust
Commands::DrRestore { seed, peer } => {
    let request = CliRequest::DrRestore {
        seed_phrase: seed,
        peer_addr: peer,
    };
    let response = send_request(&socket_path, &request).await?;
    print_response(response);
}
```

---

## DR boot flow — Processor handler for CliCmd::DrRestore

This is the most complex handler. It runs inline in the Processor's event loop (no
separate task — follows the existing pattern).

```rust
async fn handle_dr_restore(
    &mut self,
    seed_phrase: Vec<String>,
    peer_addr: String,
    reply: tokio::sync::oneshot::Sender<Result<(), String>>,
) {
    // Step 1: Verify the seed phrase matches our own identity.
    // The daemon is already running with a loaded identity.
    // DR restore is only valid if the seed phrase matches our identity_pub.
    // Re-derive identity from seed phrase and compare to self.identity_pub.
    let derived_identity = match derive_identity_from_seed(&seed_phrase) {
        Ok(id) => id,
        Err(e) => {
            let _ = reply.send(Err(format!("invalid seed phrase: {e}")));
            return;
        }
    };
    if derived_identity != self.identity_pub {
        let _ = reply.send(Err(
            "seed phrase does not match daemon identity. \
             Re-run 'syncback init' with your seed phrase first.".to_string()
        ));
        return;
    }

    // Step 2: Connect to the peer.
    // Parse peer_addr as EndpointAddr.
    let peer_endpoint_addr: iroh::EndpointAddr = match serde_json::from_str(&peer_addr) {
        Ok(a) => a,
        Err(e) => {
            let _ = reply.send(Err(format!("invalid peer addr: {e}")));
            return;
        }
    };
    // Use NetCommand::Connect to connect (fire and forget; PeerConnected event follows).
    // We don't have the peer's identity_pub yet — use ConnectAddr to get it from handshake.
    self.net_cmd_tx
        .send(NetCommand::ConnectAddr { node_addr: peer_addr.clone() })
        .await
        .unwrap_or_else(|_| panic!("net channel closed"));

    // Step 3: Wait for PeerConnected event.
    // The Processor's select! loop will receive NetEvent::PeerConnected.
    // We need the peer's identity_pub to send the request.
    // Set a flag in Processor state so the next PeerConnected event triggers the DR request.
    // This is a simple state machine: pending_dr_peer_addr + pending_dr_reply.
    self.pending_dr_peer_addr = Some(peer_addr.clone());
    self.pending_dr_cli_reply = Some(reply);
    // The actual request is sent when PeerConnected fires (see handle_peer_connected_for_dr).
}
```

**State machine approach:** Rather than blocking the event loop, the DR flow uses Processor
fields to track pending state:

```rust
pub struct Processor {
    // ... existing fields ...

    /// Set during DR restore; cleared when PeerConnected fires.
    pending_dr_peer_addr: Option<String>,

    /// CLI reply sender for DR restore; cleared when response arrives or fails.
    pending_dr_cli_reply: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,

    /// Set when DR request is sent; cleared when SystemStateResponse arrives.
    pending_dr_reply: Option<tokio::sync::oneshot::Sender<Result<SystemStateResponseMsg, String>>>,
}
```

When `NetEvent::PeerConnected { peer_identity, .. }` fires and `pending_dr_peer_addr` is set:

```rust
fn handle_peer_connected_for_dr(&mut self, peer_identity: IdentityPub) {
    if self.pending_dr_peer_addr.take().is_none() {
        return; // not a DR connect
    }
    // Send SystemStateRequest.
    let msg = DirectMessage {
        v: PROTOCOL_VERSION,
        body: DirectBody::SystemStateRequest(SystemStateRequestMsg {
            requester: self.identity_pub,
        }),
    };
    let framed = frame_message(&msg).expect("SystemStateRequest frames cleanly");
    let _ = self.net_cmd_tx
        .try_send(NetCommand::SendDirect { peer: peer_identity, payload: framed });
    // pending_dr_cli_reply stays set until SystemStateResponse arrives.
}
```

When `SystemStateResponse` arrives, `handle_system_state_response` completes the flow:

```rust
async fn handle_system_state_response(
    &mut self,
    from: IdentityPub,
    msg: SystemStateResponseMsg,
) {
    let cli_reply = match self.pending_dr_cli_reply.take() {
        Some(r) => r,
        None => {
            tracing::debug!(peer = %from, "unexpected SystemStateResponse, ignoring");
            return;
        }
    };

    if msg.blob.is_empty() {
        let _ = cli_reply.send(Err(format!(
            "peer {from} does not have a system state backup for this identity"
        )));
        return;
    }

    // Decrypt and deserialize.
    let state = match system_state::unpack_system_state(&msg.blob, &self.identity_key) {
        Ok(s) => s,
        Err(e) => {
            let _ = cli_reply.send(Err(format!("failed to unpack system state: {e}")));
            return;
        }
    };

    // Populate DB.
    if let Err(e) = system_state::restore_db(&self.db, &state) {
        let _ = cli_reply.send(Err(format!("failed to restore DB: {e}")));
        return;
    }

    tracing::info!(
        peer = %from,
        files = state.files.len(),
        shards = state.shards.len(),
        peers = state.peers.len(),
        "DR restore: DB populated from system state"
    );

    let _ = cli_reply.send(Ok(()));
}
```

---

## Network changes — network/mod.rs

The `VariantName` trait implementation (private, used for logging) must be updated:

```rust
impl VariantName for DirectBody {
    fn variant_name(&self) -> &'static str {
        match self {
            DirectBody::Handshake(_)             => "Handshake",
            DirectBody::RestoreRequest(_)        => "RestoreRequest",
            DirectBody::RestoreDenied(_)         => "RestoreDenied",
            DirectBody::BlobReady(_)             => "BlobReady",
            DirectBody::ShardData(_)             => "ShardData",
            DirectBody::SystemStateRequest(_)    => "SystemStateRequest",
            DirectBody::SystemStateResponse(_)   => "SystemStateResponse",
            DirectBody::SystemStateBackup(_)     => "SystemStateBackup",
            DirectBody::SystemStateAck(_)        => "SystemStateAck",
        }
    }
}
```

No other changes to network.rs — all new messages use the existing
`NetEvent::MessageReceived` path and are dispatched by the Processor.

---

## Business rules

### Backup selection: top-15 by trust score

Peers are selected for system state backup by sorting all known peers descending by
`trust_engine.score(peer)`. Take the top min(15, peer_count) peers. Skip peers with no
known `node_addr` in their `PeerRecord`. Minimum: 3 peers. If fewer than 3 peers have
a known addr, skip this backup cycle and log INFO.

The constant 15 reflects the Phase 4 decision: "~15 encrypted copies to different peers."
Any one copy is sufficient for restore (no RS coding — each copy is the full blob).

### Overwrite semantics: latest wins

When a holder receives a new `SystemStateBackup` for an identity it already has a blob
for, it unconditionally overwrites the old one. There is no version comparison. The
owner always pushes the latest state; holders store only the latest.

### Identity verification: requester must match handshake

When the holder receives `SystemStateRequest`, it sends the blob only if
`msg.requester == from` (the peer identity established by the handshake). A peer cannot
request another peer's system state by forging the `requester` field. The handshake
already authenticated `from`.

### Eviction: system state blobs are low-priority in disk pressure

During disk pressure eviction in `storage.rs`, system state blobs are NOT evicted (they
are not in the `HOLDING` table and thus not touched by the existing eviction code). They
are excluded from disk pressure calculations in alpha. Post-alpha: add them to quota
accounting and evict oldest when under extreme pressure.

### DR identity check: seed must match daemon identity

The daemon checks that the seed phrase re-derives to the same `identity_pub` as the
running daemon. If not, DR restore is rejected with a clear error message. The user must
run `syncback init --seed "..."` to initialize the daemon with their own identity before
using DR restore.

### Timeout for DR response

The DR flow is entirely asynchronous (the CLI command returns immediately if
`reply_tx` is set; the result arrives when `SystemStateResponse` is received). However,
the CLI blocks waiting on the oneshot receiver. To avoid hanging indefinitely:

The `CliServer` dispatch wraps the reply with a timeout (30 seconds):

```rust
match tokio::time::timeout(
    std::time::Duration::from_secs(30),
    reply_rx,
).await {
    Ok(Ok(Ok(()))) => CliResponse::Ok { message: "...".into() },
    Ok(Ok(Err(e))) => CliResponse::Error { message: e },
    Ok(Err(_))     => CliResponse::Error { message: "processor dropped reply".into() },
    Err(_)         => CliResponse::Error { message: "DR restore timed out after 30s".into() },
}
```

If timeout fires, `pending_dr_cli_reply` is leaked (set in Processor but never consumed).
Add a cleanup: if `pending_dr_cli_reply` is Some when the next event loop tick fires,
check if the sender is closed (try_send probe). If closed, clear it. This is an alpha
simplification — in production, use a proper timeout on the Processor side.

---

## Test scenarios

Tests live in `crates/syncback/src/daemon/processor/tests.rs` (unit) and
`crates/syncback/tests/phase4_gate.rs` (integration/gate).

### Unit tests (processor/tests.rs)

#### 1. `system_state_backup_roundtrip`

**Setup:** Two in-process `Processor` instances (A = owner, B = holder) sharing a test
channel pair. Use `testutil::test_db()` for both.

**Steps:**
1. Populate A's DB with a few files, units, shards, and 1 peer (B's identity).
2. Call A's `handle_system_state_backup()`.
3. Verify that `NetCommand::SendMessage` was sent to B with a `SystemStateBackup` body.
4. Feed the message into B's `handle_system_state_backup_received()`.
5. Verify B's DB has a `SystemStateBlobRecord` for A's identity.
6. Verify B sent `NetCommand::SendDirect` with a `SystemStateAck { stored: true }` body.

**Expected:** blob stored on B, ack sent.

#### 2. `system_state_request_found`

**Setup:** B's DB already has a blob for A. Simulate A sending `SystemStateRequest`.

**Steps:**
1. Call `B.handle_system_state_request(from=A_identity, msg)`.
2. Verify B sent `NetCommand::SendDirect` with `SystemStateResponse { blob: non_empty, created_at: non_zero }`.

#### 3. `system_state_request_not_found`

**Steps:**
1. Call `B.handle_system_state_request(from=A_identity, msg)` when B has no blob for A.
2. Verify `SystemStateResponse { blob: vec![], created_at: 0 }`.

#### 4. `system_state_response_triggers_db_restore`

This test requires the `system_state` module from `phase4_system_state.md` to be
implemented first. Mark with `// requires phase4_system_state` comment if not yet available.

**Steps:**
1. Create a `SystemState` with 3 files, 6 shards, 2 peers.
2. Pack it: `system_state::pack_system_state(&state, &identity_key)` → blob.
3. Call `processor.handle_system_state_response(from, SystemStateResponseMsg { blob, created_at: 1000 })`.
4. Verify processor sent `Ok(())` via pending_dr_cli_reply.
5. Verify `processor.db` now has entries matching the original `SystemState`.

#### 5. `dr_restore_rejects_wrong_seed`

**Steps:**
1. Processor has `identity_pub` derived from entropy A.
2. Call `handle_dr_restore(seed_phrase=derived_from_entropy_B, ...)`.
3. Verify `reply.send(Err("seed phrase does not match daemon identity"))`.

#### 6. `system_state_backup_too_few_peers`

**Setup:** A's DB has 0 or 2 peers (below minimum of 3).

**Steps:**
1. Call `handle_system_state_backup()`.
2. Verify no `NetCommand::SendMessage` was sent.
3. Verify a log event at INFO level contains "too few peers".

#### 7. `system_state_backup_overwrites_old`

**Setup:** B already has a blob for A (received_at = T1).

**Steps:**
1. B receives a new `SystemStateBackup` for A (created_at = T2 > T1).
2. Verify the stored record is updated with the new blob and created_at.
3. Verify only one record for A in SYSTEM_STATE_BLOBS (no accumulation).

#### 8. `system_state_request_requester_mismatch`

**Setup:** Peer C sends `SystemStateRequest { requester: A_identity }` (forged).

**Steps:**
1. Call `handle_system_state_request(from=C_identity, msg.requester=A_identity)`.
2. Verify: no response sent (early return on mismatch).

### Integration/gate tests (tests/phase4_gate.rs)

#### Gate test: `full_dr_from_seed_only`

This is the Phase 4 GATE test. It replaces the Phase 3 test 3 "DB copy" approach
with a true DR flow (no DB copy).

```rust
#[tokio::test]
async fn full_dr_from_seed_only() {
    tokio::time::timeout(
        std::time::Duration::from_secs(120),
        run_full_dr(),
    )
    .await
    .expect("test timed out after 120s")
    .expect("test failed");
}
```

**Flow:**
1. Create `dir_a`, `dir_b`. Init node A (`entropy=[0u8;32]`) and node B (`entropy=[1u8;32]`).
2. Start daemon B (holder). Start daemon A (owner, with `files_dir` in backup config).
3. Create test files in `files_dir` (~80 KB total).
4. Connect A → B (`ConnectPeer`).
5. Trigger backup on A (`BackupNow`). Wait for `shards_placed >= 1`.
6. Send `ScheduledCmd::SystemStateBackup` to A via processor channel directly
   (or call `BackupNow` which also triggers the backup).

   **DECISION NEEDED:** The test needs to trigger `SystemStateBackup` without waiting
   7 days for the scheduler. Option 1: expose a `TriggerSystemStateBackup` CLI command
   (ugly). Option 2: after `BackupNow`, the Processor automatically runs system state
   backup as part of the weekly sync flow. Option 3: add a test-only `BackupNow` that
   also runs system state backup. **Recommended:** make `handle_weekly_sync` (and
   therefore `BackupNow`) always trigger `handle_system_state_backup` at the end.
   This avoids any test-only code path.

7. Wait until A has sent system state backup to B. Detect by polling B for a stored blob:
   add a temporary Status check or wait 2 seconds (alpha: use sleep).
8. Shut down daemon A. Delete `dir_a` completely (simulating device loss).
9. Start daemon A' (fresh — no DB, no files, no identity.key) with `entropy=[0u8;32]`
   (same seed as A).
   - `init_with_mnemonic(&dir_a_prime, &mnemonic_a)` creates identity.
   - `DaemonHandle::start(config_a_prime)`.
10. Send `DrRestore { seed_phrase: mnemonic_a_words, peer_addr: node_b_addr }` to A'.
11. Wait for `CliResponse::Ok`.
12. Verify A' DB has files/shards matching what A backed up:
    `send_cli_request_raw(&sock_a_prime, &CliRequest::Status).shards_placed >= 1`.
13. Restore `docs/notes.txt` to `restore_dir` using A' daemon. Verify content matches original.
14. Shut down B and A'.

**Expected:** Full DR cycle completes in < 120 seconds on localhost.

---

## File layout

Tests in separate files per user preference:

```
crates/syncback/src/daemon/processor/
    mod.rs      — implementation (all four new handlers)
    tests.rs    — unit tests (scenarios 1-8 above)

crates/syncback/tests/
    phase4_gate.rs   — integration gate test
```

New types added to existing files:
```
crates/syncback-core/src/messages/mod.rs   — 4 new DirectBody variants + 4 new message structs
crates/syncback-core/src/types/mod.rs     — SystemStateBlobRecord
crates/syncback-core/src/db/mod.rs        — SYSTEM_STATE_BLOBS table + 4 new Db methods
crates/syncback/src/daemon/mod.rs         — ScheduledCmd::SystemStateBackup, CliCmd::DrRestore
crates/syncback/src/daemon/scheduler.rs   — SystemStateBackup scheduling
crates/syncback/src/daemon/cli_server/mod.rs — CliRequest::DrRestore + dispatch
crates/syncback/src/cli.rs               — dr-restore subcommand
```

---

## Checklist for implementer

### Step 1: Data types (syncback-core)

- [ ] `SystemStateBlobRecord` added to `types/mod.rs`
- [ ] `SYSTEM_STATE_BLOBS` table defined in `db/mod.rs`
- [ ] Table added to `Db::open` initialization
- [ ] Four `Db` methods implemented: `store_system_state_blob`, `get_system_state_blob`,
      `delete_system_state_blob`, `list_system_state_blob_owners`
- [ ] Four new `DirectBody` variants added to `messages/mod.rs`
- [ ] Four new message structs defined
- [ ] `frame_message` / `parse_framed` still work (CBOR handles new variants via serde tag)

### Step 2: Channel types (syncback daemon/mod.rs)

- [ ] `ScheduledCmd::SystemStateBackup` added
- [ ] `CliCmd::DrRestore { seed_phrase, peer_addr, reply }` added

### Step 3: Processor (processor/mod.rs)

- [ ] Three new Processor fields: `pending_dr_peer_addr`, `pending_dr_cli_reply`, `pending_dr_reply`
- [ ] `handle_system_state_backup()` implemented
- [ ] `handle_system_state_backup_received()` implemented
- [ ] `handle_system_state_request()` implemented
- [ ] `handle_system_state_response()` implemented
- [ ] `handle_system_state_ack()` implemented
- [ ] `handle_dr_restore()` implemented (CLI command handler)
- [ ] `handle_peer_connected_for_dr()` added to `PeerConnected` dispatch
- [ ] `ScheduledCmd::SystemStateBackup` dispatched in select! loop
- [ ] `WeeklySync` handler calls `handle_system_state_backup()` at end
- [ ] `CliCmd::DrRestore` dispatched to `handle_dr_restore()`
- [ ] All four `DirectBody` variants dispatched in `MessageReceived` arm

### Step 4: Network (network/mod.rs)

- [ ] `VariantName` impl updated for 4 new variants

### Step 5: Scheduler (scheduler.rs)

- [ ] `SYSTEM_STATE_BACKUP_FIRST_OFFSET` constant added
- [ ] `system_state_backup_due` timer added to `run()`
- [ ] `SystemStateBackup` fired on schedule

### Step 6: CLI (cli_server/mod.rs + cli.rs)

- [ ] `CliRequest::DrRestore` added
- [ ] `dispatch()` handles `DrRestore` with 30s timeout
- [ ] `cli.rs` has `dr-restore` subcommand

### Step 7: Tests

- [ ] 8 unit tests in `processor/tests.rs` (scenarios 1-8)
- [ ] Gate test `full_dr_from_seed_only` in `tests/phase4_gate.rs`
- [ ] All existing 344 tests still pass

### Step 8: `cargo clippy` clean

- [ ] No unused variants, no dead code warnings
- [ ] `match` exhaustiveness: all new `DirectBody` arms covered everywhere a match exists

---

## Key decisions (settled)

- **Plain copies, no RS:** Each holder gets the full encrypted blob. Any 1 peer = full restore.
  Rationale: ~13 MB × 15 peers = 195 MB total across the network — negligible.
- **Overwrite, no versioning:** Latest push always wins. No version numbering in alpha.
- **Identity check in DR:** Seed must match daemon identity. The user must `init` first.
- **DR request requires running daemon:** The `dr-restore` CLI command connects to a running
  daemon over the Unix socket. It does not start a minimal daemon itself (that would require
  a separate code path and is not necessary given the existing daemon architecture).
- **No explicit DR state machine in a separate task:** The Processor handles DR state
  via three fields. This avoids adding a 6th tokio task for a rare operation.
- **30s CLI timeout:** Generous for localhost. On slow network, the user will see a timeout
  and can retry. No automatic retry in alpha.
