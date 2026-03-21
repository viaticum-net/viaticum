# Phase 7.6: Processor full dispatch table

## Scope

Add handlers for 5 currently-unhandled `Message` variants in `Processor::dispatch`, and wire relay
inbound messages into the Processor instead of the dead-drain task in `handle/mod.rs`.

Currently the dispatch match arm `other => debug!("unhandled …")` silently drops:
- `Message::SymbolOffer`
- `Message::SymbolAccept`
- `Message::SymbolReject`
- `Message::RestoreRequest`
- `Message::RestoreDenied`
- `Message::BoardSync`
- `Message::PeerAnnounce`

This phase implements all seven.

## Files changed

- `crates/syncback/src/daemon/processor/mod.rs` — add handlers + new constructor parameter
- `crates/syncback/src/daemon/processor/tests.rs` — new tests
- `crates/syncback/src/daemon/handle/mod.rs` — remove drain task, add `inbound_rx` to Processor, wire relay `inbound_tx`

## Dependencies

- `syncback_core::messages` — all message structs (already imported)
- `syncback_core::db::Db` — `get_budget`, `total_holding_bytes`, `get_peer`, `upsert_peer`, `get_holding`, `list_holdings_for_owner`
- `syncback_core::escrow` — no direct use (quota logic is simpler, see below)
- `syncback_core::budget::DiskPressure` — to gate Accept/Reject
- `crate::daemon::relay::{InboundMessage, SyncTrigger}` — relay inbound routing
- `crate::daemon::network::NetworkHandle` — to send Accept/Reject/RestoreResponse replies

## New Processor field

```rust
/// Network handle for sending replies (SymbolAccept, SymbolReject, RestoreResponse).
network: Arc<NetworkHandle>,
```

Update `Processor::new` signature:

```rust
pub fn new(
    db: Db,
    own_identity: IdentityPub,
    repair_tx: mpsc::Sender<RepairTrigger>,
    cluster_sync: Arc<ClusterSyncManager>,
    encoder: Arc<dyn ErasureEncoder>,
    holdings_dir: PathBuf,
    source_blocks_dir: PathBuf,
    network: Arc<NetworkHandle>,   // NEW
) -> Self
```

Remove `#[allow(dead_code)]` from `own_identity` (it will now be used in SymbolOffer reply
signature verification).

## New Processor fields for relay routing

```rust
/// Channel to relay manager: push BoardSync entries from incoming connections.
relay_sync_tx: mpsc::Sender<crate::daemon::relay::SyncTrigger>,
```

Update `Processor::new` again:

```rust
pub fn new(
    db: Db,
    own_identity: IdentityPub,
    repair_tx: mpsc::Sender<RepairTrigger>,
    cluster_sync: Arc<ClusterSyncManager>,
    encoder: Arc<dyn ErasureEncoder>,
    holdings_dir: PathBuf,
    source_blocks_dir: PathBuf,
    network: Arc<NetworkHandle>,
    relay_sync_tx: mpsc::Sender<crate::daemon::relay::SyncTrigger>,
) -> Self
```

## `Processor::run` signature change

Add `inbound_rx` so relay messages flow through the same dispatch loop:

```rust
pub async fn run(
    self,
    incoming_rx: mpsc::Receiver<Connection>,          // existing
    inbound_rx: mpsc::Receiver<InboundMessage>,       // NEW: from relay
    cancel: CancellationToken,
) -> anyhow::Result<()>
```

The relay `InboundMessage` carries raw CBOR `payload` and `msg_type`. Deserialize into a
`Message` via `syncback_core::messages::from_cbor::<Message>(&msg.payload)`. If deserialization
fails, log `tracing::warn!` and skip. Pass `msg.from` as the `from: IdentityPub` argument to
`dispatch`. For relay messages there is no live `Connection` to reply on; pass a sentinel
`Arc<Mutex<()>>` — BUT: this design means reply-requiring handlers (SymbolAccept, RestoreResponse)
cannot reply over relay. That is intentional for this phase; relay is one-way for PoS challenges
and PeerAnnounce. Handlers that need to reply (SymbolOffer, RestoreRequest) must only be called
when a live `conn` is present.

**Simpler design:** keep the existing `(IdentityPub, Message, Arc<Mutex<Connection>>)` type for
direct-connection messages. Add a second select arm in `run` for `inbound_rx: mpsc::Receiver<InboundMessage>`.
Relay messages go to a separate dispatch path that only calls handlers that do NOT need a conn:
`handle_board_sync_from_relay`, `handle_peer_announce`, `handle_pos_challenge_relay` (out of scope
for 7.6), etc.

For this phase, relay inbound dispatch handles only:
- `PeerAnnounce` → `handle_peer_announce(from, msg)`
- All other relay msg_types: log debug, ignore

```rust
// In run(), new select arm:
maybe_relay = inbound_rx.recv() => {
    match maybe_relay {
        None => {
            info!("processor: inbound_rx closed");
            // Not a fatal condition; relay may be disabled.
        }
        Some(relay_msg) => {
            let this2 = this.clone();
            tokio::spawn(async move {
                this2.dispatch_relay(relay_msg).await;
            });
        }
    }
}
```

```rust
async fn dispatch_relay(&self, msg: InboundMessage) {
    if msg.msg_type == "peer_announce" {
        match from_cbor::<PeerAnnounceMsg>(&msg.payload) {
            Ok(pa) => {
                if let Err(e) = self.handle_peer_announce(pa).await {
                    warn!(err = %e, "processor: PeerAnnounce via relay failed");
                }
            }
            Err(e) => {
                warn!(err = %e, "processor: failed to decode PeerAnnounce from relay");
            }
        }
    } else {
        debug!(msg_type = %msg.msg_type, "processor: relay message, no handler");
    }
}
```

## Handler specifications

### 1. `handle_symbol_offer` — we are the holder

Role: receive offer, decide Accept or Reject, send reply on `conn`.

```rust
pub(crate) async fn handle_symbol_offer(
    &self,
    owner_id: IdentityPub,
    offer: SymbolOfferMsg,
    conn: Arc<Mutex<Connection>>,
) -> Result<(), ProcessorError>
```

**Quota check logic (holder side):**

1. Compute `held_bytes = db.total_holding_bytes()?`
2. Read `budget = db.get_budget()?`. If `None`, use `soft_quota_bytes = u64::MAX` (no limit configured).

   DECISION NEEDED: `Db::get_budget` returns `Option<BudgetRecord>`. `BudgetRecord` does not have
   quota fields — it is the *owner*'s budget estimate (placement capacity), not the holder's disk
   quota. The holder disk quota lives in `AppConfig` (config.toml `[storage] soft_quota_gb`,
   `hard_quota_gb`). The `Processor` does not currently hold an `AppConfig` reference.

   **Resolution for this phase:** add a `soft_quota_bytes: u64` field to `Processor`. Default
   `u64::MAX` (unlimited). Set from `AppConfig` in `handle/mod.rs` during Processor construction.
   `hard_quota_bytes: u64` is the floor; if `held_bytes >= hard_quota_bytes` → reject immediately.

   ```rust
   pub struct Processor {
       // ... existing fields ...
       soft_quota_bytes: u64,   // 0 = unlimited (treat as u64::MAX internally)
       hard_quota_bytes: u64,   // floor; never accept above this
   }
   ```

3. Compute `offer_bytes`: sum of `count * SYMBOL_SIZE` for each `(start, count)` in
   `offer.esi_ranges`, where `SYMBOL_SIZE = 65_535u64`.

4. Disk pressure check:
   - If `held_bytes >= hard_quota_bytes` → Reject with `RejectReason::QuotaFull`
   - Else if `soft_quota_bytes < u64::MAX` and `held_bytes + offer_bytes > soft_quota_bytes`
     → Reject with `RejectReason::QuotaFull`
   - Else → Accept

5. On **Accept**:
   - Send `Message::SymbolAccept(SymbolAcceptMsg { v:1, source_block_id: offer.source_block_id, offer_msg_id: offer.msg_id, timestamp: Timestamp::now() })` on `conn`.
   - Log `info!`.

6. On **Reject**:
   - Send `Message::SymbolReject(SymbolRejectMsg { v:1, source_block_id, offer_msg_id, reason, timestamp })`.
   - Log `debug!`.

**Important:** do NOT create a `HoldingRecord` here. The record is created in `handle_symbol_transfer`
when the symbols actually arrive. The offer/accept just gates the transfer.

### 2. `handle_symbol_accept` — we are the owner

Role: holder accepted our offer. Notify BackupCoordinator so it can proceed with SymbolTransfer.
For this phase, **log only** — BackupCoordinator wiring is Phase 7.5.

```rust
async fn handle_symbol_accept(
    &self,
    holder_id: IdentityPub,
    accept: SymbolAcceptMsg,
) -> Result<(), ProcessorError>
```

Implementation:
```rust
info!(
    holder = %holder_id,
    block_id = %accept.source_block_id,
    offer_msg_id = ?accept.offer_msg_id,
    "processor: SymbolAccept received (log only, Phase 7.5 wires to BackupCoordinator)"
);
Ok(())
```

### 3. `handle_symbol_reject` — we are the owner

Role: holder rejected our offer. Log.

```rust
async fn handle_symbol_reject(
    &self,
    holder_id: IdentityPub,
    reject: SymbolRejectMsg,
) -> Result<(), ProcessorError>
```

Implementation:
```rust
info!(
    holder = %holder_id,
    block_id = %reject.source_block_id,
    reason = ?reject.reason,
    "processor: SymbolReject received"
);
Ok(())
```

### 4. `handle_restore_request` — we are the holder

Role: owner wants their symbols back. Check HoldingRecord, load symbol files, send
`RestoreResponse`.

```rust
pub(crate) async fn handle_restore_request(
    &self,
    owner_id: IdentityPub,
    request: RestoreRequestMsg,
    conn: Arc<Mutex<Connection>>,
) -> Result<(), ProcessorError>
```

Steps:
1. `db.get_holding(&request.source_block_id, &owner_id)?`
   - If `None` or `status != HoldingStatus::Active` → send empty `RestoreResponse` (symbols=[]) and return.
   - This is not a protocol error; holder may have evicted legitimately.

2. Determine which ESIs to send:
   - If `request.esi_list` is empty → send all held ESIs (from `holding.esi_ranges`).
   - Else → intersect `request.esi_list` with held ESIs (only send what we actually have).

3. Load symbol files from `holdings_dir/{block_id_hex}/{esi}.bin`.
   - Skip files that don't exist (log `debug!`).
   - Collect into `Vec<Symbol>`.

4. If loaded symbols is empty (nothing on disk despite DB record) → send empty `RestoreResponse`,
   log `warn!`.

5. Send `Message::RestoreResponse(RestoreResponseMsg { v:1, source_block_id, symbols, timestamp })`.

6. Log `info!` with count of symbols sent.

**No escrow check on this path** — the holder-side escrow gate was designed for the wire protocol
but is not implemented in this phase. Phase 2.6 implemented escrow for the *owner*-side restore
budget, which is different. Escrow on the holder side (checking that the owner has earned back what
they stored) is marked DECISION NEEDED below.

DECISION NEEDED: should `handle_restore_request` perform an escrow check (verify owner has
enough trust to unlock restore)? The protocol spec and `RestoreDeniedMsg` wire type imply yes.
`check_restore(trust, restore_gb, DEFAULT_ESCROW_TRUST_FACTOR)` from `syncback_core::escrow`.
But we need the owner's trust score from `db.get_peer(&owner_id)` and the restore size from the
holding record. Punting to a follow-up task is acceptable because the test cluster has zero
malicious peers and we need the feature working first. Mark the escrow check location with a
`// TODO Phase 7.6+: escrow check` comment.

### 5. `handle_restore_denied` — we are the owner

Role: holder denied our restore request. Log and propagate if there's a pending restore.

```rust
async fn handle_restore_denied(
    &self,
    holder_id: IdentityPub,
    denied: RestoreDeniedMsg,
) -> Result<(), ProcessorError>
```

Implementation:
```rust
warn!(
    holder = %holder_id,
    block_id = %denied.source_block_id,
    current_trust = denied.current_trust,
    needed_trust = denied.needed_trust,
    restore_budget_gb = denied.restore_budget_gb,
    "processor: RestoreDenied received"
);
Ok(())
```

### 6. `handle_board_sync` — relay sync with a partner

Role: peer sent us their board entries. Forward to `relay_sync_tx`.

```rust
async fn handle_board_sync(
    &self,
    from: IdentityPub,
    msg: BoardSyncMsg,
) -> Result<(), ProcessorError>
```

Implementation:
```rust
let trigger = crate::daemon::relay::SyncTrigger {
    partner_identity: from,
    partner_entries: msg.entries,
};
if self.relay_sync_tx.send(trigger).await.is_err() {
    warn!(peer = %from, "processor: relay_sync_tx closed, dropping BoardSync");
}
Ok(())
```

### 7. `handle_peer_announce` — upsert peer, update network handle

Role: learn about a peer's network address. Upsert `PeerRecord` in DB and call
`network.add_peer`.

```rust
pub(crate) async fn handle_peer_announce(
    &self,
    msg: PeerAnnounceMsg,
) -> Result<(), ProcessorError>
```

Note: `PeerAnnounceMsg` carries `identity_pub` (SyncBack identity), `node_id` (iroh transport
identity), and `timestamp`. It does NOT carry a socket address. `node_id` is the iroh public key;
the actual `EndpointAddr` requires iroh to resolve it, which cannot be done here without the
iroh endpoint. For this phase:

1. Upsert `PeerRecord` in DB:
   - `db.get_peer(&msg.identity_pub)?` → `Option<PeerRecord>`
   - If `None`: create new `PeerRecord` with `trust_p = INITIAL_TRUST_P`, `trust_i = 0.0`,
     `trust_s = 1.0`, `first_seen = now`, `last_seen = now`, `node_id = Some(msg.node_id)`.
   - If `Some(existing)`: update `node_id = Some(msg.node_id)`, `last_seen = now`.
   - `db.upsert_peer(&record)?`

2. Log `info!`.

Note: `network.add_peer` requires an `EndpointAddr`, which we cannot construct from just a
`NodeId` without an IP. Registering the IP → EndpointAddr mapping happens in Phase 7.9 (bootstrap
peers) and 7.3 (connect). For now, skip the `add_peer` call in this handler.

DECISION NEEDED: should `PeerAnnounceMsg` include the socket address? The current wire message
struct does not have it. Phase 7.3 adds `--peer` CLI flag and parses `NodeId@ip:port`. A
`PeerAnnounce` via relay board typically only carries `identity_pub` + `node_id` and lets the
receiver connect via iroh relay. If direct-IP announce is wanted, the message struct needs a
`socket_addr: Option<SocketAddr>` field.

## `handle/mod.rs` changes

1. Remove the drain task (lines 373–383):
   ```rust
   // DELETE this block:
   tokio::spawn(async move {
       while let Some(msg) = inbound_rx.recv().await { ... }
   });
   ```

2. Thread `inbound_tx` into `RelayManager::run` as before (unchanged).

3. Thread `inbound_rx` to `Processor::run` as the new parameter.

4. Pass `relay_sync_tx` to `Processor::new`.

5. Pass `network.clone()` to `Processor::new`.

6. Pass `soft_quota_bytes` and `hard_quota_bytes` from `AppConfig` to `Processor::new`.
   ```rust
   let soft_quota_bytes = (app_config.storage.soft_quota_gb * 1024.0 * 1024.0 * 1024.0) as u64;
   let hard_quota_bytes = (app_config.storage.hard_quota_gb * 1024.0 * 1024.0 * 1024.0) as u64;
   ```
   If `soft_quota_gb == 0.0`, set `soft_quota_bytes = u64::MAX`.

7. Update Processor spawn to pass `inbound_rx`:
   ```rust
   tasks.push(tokio::spawn(async move {
       processor.run(incoming_rx, inbound_rx, cancel_processor).await
   }));
   ```

## Updated dispatch match arms

```rust
Message::SymbolOffer(offer) => {
    self.handle_symbol_offer(from, offer, conn).await?;
}
Message::SymbolAccept(accept) => {
    self.handle_symbol_accept(from, accept).await?;
}
Message::SymbolReject(reject) => {
    self.handle_symbol_reject(from, reject).await?;
}
Message::RestoreRequest(req) => {
    self.handle_restore_request(from, req, conn).await?;
}
Message::RestoreDenied(denied) => {
    self.handle_restore_denied(from, denied).await?;
}
Message::BoardSync(board_sync) => {
    self.handle_board_sync(from, board_sync).await?;
}
Message::PeerAnnounce(pa) => {
    self.handle_peer_announce(pa).await?;
}
```

## `ProcessorError` additions

No new variants needed. Existing variants cover all failure paths:
- `Io` — file reads
- `Db` — DB operations
- `Network` — sending replies

## Test scenarios

All tests go in `crates/syncback/src/daemon/processor/tests.rs`. Use the existing `make_processor`
helper, which must be extended to accept `soft_quota_bytes` and `hard_quota_bytes` parameters (or
use sensible defaults). Since `network` is now required, use the existing pattern from
`restore/tests.rs`: start a throwaway `NetworkHandle` with `RelayMode::Disabled`.

### handle_symbol_offer

```
symbol_offer_accept_when_quota_not_exceeded
  Setup:   soft_quota_bytes = 1 GB, held_bytes = 0
  Input:   SymbolOfferMsg with esi_ranges [(0,10)], ~640 KB offer
  Expect:  SymbolAccept sent on conn (verify via recv on other end)
           No HoldingRecord created

symbol_offer_reject_when_hard_quota_exceeded
  Setup:   hard_quota_bytes = 100, held_bytes (from mock) = 200
  Input:   SymbolOfferMsg
  Expect:  SymbolReject with reason=QuotaFull

symbol_offer_reject_when_soft_quota_would_overflow
  Setup:   soft_quota_bytes = 1000, total_holding_bytes = 900,
           offer_bytes = 200 (> 100 remaining)
  Input:   SymbolOfferMsg with esi_ranges [(0,4)] → 4 * 65535 = ~256 KB
  Expect:  SymbolReject with reason=QuotaFull

symbol_offer_accept_when_unlimited_quota
  Setup:   soft_quota_bytes = u64::MAX, hard_quota_bytes = u64::MAX
  Input:   any SymbolOfferMsg
  Expect:  SymbolAccept
```

Test structure note: to verify the reply was sent, use a real two-node iroh setup (like
`network/tests.rs`) OR use the `handle_symbol_offer_inner` pattern (extract inner logic to a
testable sync method that returns `Accept | Reject` enum without touching the conn, then test
that separately from the conn-send path). The inner method approach is preferred to avoid the
two-node overhead.

Add:
```rust
pub(crate) fn decide_symbol_offer(
    &self,
    offer_bytes: u64,
) -> Result<bool, ProcessorError>   // true = accept
```

This is a sync helper that checks quota. `handle_symbol_offer` calls it then sends the reply.

### handle_restore_request

```
restore_request_returns_held_symbols
  Setup:   Write 3 symbol files to holdings_dir/{block_hex}/{esi}.bin
           Upsert HoldingRecord with status=Active, esi_ranges=[(0,3)]
  Input:   RestoreRequestMsg with empty esi_list (send all)
  Expect:  RestoreResponse sent with 3 symbols matching written data
           (test via real two-node connection OR inner method)

restore_request_returns_empty_when_no_holding
  Setup:   Empty DB
  Input:   RestoreRequestMsg for unknown block
  Expect:  RestoreResponse with symbols=[] (empty, no error)

restore_request_filters_by_esi_list
  Setup:   HoldingRecord with esi_ranges=[(0,5)], 5 files on disk
  Input:   RestoreRequestMsg with esi_list=[1,3]
  Expect:  RestoreResponse with exactly 2 symbols (ESI 1 and 3)
```

For conn-based tests, use the `handle_restore_request_inner` pattern returning
`RestoreResponseMsg` directly (same pattern as `handle_pos_challenge_inner`).

Add:
```rust
pub(crate) async fn handle_restore_request_inner(
    &self,
    owner_id: IdentityPub,
    request: RestoreRequestMsg,
) -> Result<RestoreResponseMsg, ProcessorError>
```

### handle_board_sync

```
board_sync_forwards_to_relay_sync_tx
  Setup:   relay_sync_tx + relay_sync_rx pair
  Input:   BoardSyncMsg with 2 StoredEntry items
  Expect:  relay_sync_rx receives SyncTrigger with same entries
```

Use a dummy `Arc<Mutex<Connection>>` (via tokio mock or skip conn for BoardSync which doesn't need it).

### handle_peer_announce

```
peer_announce_creates_new_peer_record
  Setup:   Empty peers table
  Input:   PeerAnnounceMsg { identity_pub, node_id, timestamp=now, sig=valid }
  Expect:  db.get_peer(identity_pub) returns Some(PeerRecord)
           record.node_id == Some(node_id)
           record.first_seen <= now

peer_announce_updates_existing_peer_node_id
  Setup:   Existing PeerRecord with node_id=Some(old_node_id)
  Input:   PeerAnnounceMsg with new node_id
  Expect:  db.get_peer returns record with updated node_id
           first_seen unchanged, last_seen updated

peer_announce_via_relay_dispatch
  Setup:   InboundMessage with msg_type="peer_announce", payload=cbor(PeerAnnounceMsg)
  Input:   processor.dispatch_relay(relay_msg)
  Expect:  db.get_peer returns Some record (upserted)
```

Note: `PeerAnnounceMsg` has a signature field. The signature covers
`identity_pub || node_id || timestamp`. For tests, build a valid signed message using
`ed25519_dalek::SigningKey::sign`. The handler does NOT verify the signature (that is the relay
board's job — `verify_board_entry_sig` already runs during `process_remote_entries`). The handler
trusts the `from` field from the relay which already verified the entry.

### handle_symbol_accept / handle_symbol_reject

```
symbol_accept_logs_without_error
  Input:   SymbolAcceptMsg
  Expect:  Returns Ok(())

symbol_reject_logs_without_error
  Input:   SymbolRejectMsg
  Expect:  Returns Ok(())
```

## Acceptance criteria

- `cargo test -p syncback` passes with all new tests.
- No `#[allow(dead_code)]` on `own_identity` or `network`.
- The drain task comment in `handle/mod.rs` is removed (the drain task itself is removed).
- `processor.run(incoming_rx, inbound_rx, cancel)` compiles.
- Existing processor tests continue to pass without modification (the `make_processor` helper
  gets new optional parameters with defaults).
