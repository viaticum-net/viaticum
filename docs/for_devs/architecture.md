# Viaticum Architecture

*Reflects actual code through Wave 11b (unified work pipeline, hash-chain PoS, HTTP API). Some lower-level details (full config field list, exact DB-table set) drift between releases — when in doubt, the code is authoritative.*

*See also: [overview.md](../overview.md) for end-to-end flows, [logic.md](logic.md) for algorithms, [protocol.md](protocol.md) for wire format.*

---

## Overall structure

```
┌─────────────────────────── viaticum-core ───────────────────────────────┐
│  (pure Rust, no async, no network)                                       │
│                                                                          │
│  types ──► db ──────────────────────────────────────────────────────    │
│   │         (Db, HotCache, 21 redb tables)                          │    │
│   │                                                                  │    │
│   ├──► trust    (TrustEngine: P, I, S)                              │    │
│   ├──► budget   (BudgetEngine: GB estimate, willingness)            │    │
│   ├──► placement (SymbolBudgetEngine: weight = trust/√(1-trust))   │    │
│   ├──► erasure  (ErasureEncoder trait + RaptorQ impl + binding)    │    │
│   ├──► cluster  (key derivation, certs, ClusterState, epochs)      │    │
│   ├──► pos      (PosEngine: challenge, verify, adaptive schedule)  │    │
│   ├──► messages (wire format, all message structs)                  │    │
│   ├──► system_state (SystemState: snapshot, restore, pack/unpack)   │    │
│   └──► constants (all numeric protocol parameters)                  │    │
└──────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────── viaticum (daemon) ───────────────────────────┐
│  (tokio async, libp2p transport, coordinators)                           │
│                                                                          │
│  handle ────── DaemonHandle: owns & wires all subsystems                │
│     │                                                                    │
│     ├──► network      (libp2p TCP+Noise, DHT, DCUtR, SwarmHandle)       │
│     ├──► processor    (message router: dispatches all incoming msgs)     │
│     ├──► backup       (BackupCoordinator: watcher → symbols)            │
│     ├──► restore      (RestoreCoordinator: symbols → files)             │
│     ├──► work_pipeline(unified queue: backup, repair, PoS tasks)        │
│     ├──► repair       (thin: reliability scan + placement events)       │
│     ├──► scheduler    (PoS challenge scheduling, timeout detection)     │
│     ├──► watcher      (fs-notify: recursive watch → DirtyEvent)         │
│     ├──► mailbox      (MailboxRouter: postman store-and-forward)        │
│     ├──► cluster_sync (ClusterSyncManager: event log exchange)          │
│     ├──► web_api      (HTTP+token API: CLI + web UI → DaemonState)      │
│     ├──► identity     (BIP39 → HKDF → keys, identity file mgmt)        │
│     ├──► system_state (SS-block encode + self-pointer publish)          │
│     └──► dr           (disaster recovery: Kademlia + self-pointer walk) │
└──────────────────────────────────────────────────────────────────────────┘
```

The crate split is intentional: `viaticum-core` is testable without tokio and without a network —
unit tests run instantly. Daemon-side code in `viaticum` uses `viaticum-core` as a library.

---

## Crate structure

### viaticum-core

Pure logic. No async, no network calls, no tokio.

```
crates/viaticum-core/src/
  lib.rs          — pub mod for all modules
  constants.rs    — all numeric parameters in one file
  types/          — all shared types and record structs
  db/             — Db newtype + HotCache + CRUD methods for all tables
  trust/          — TrustEngine (P/I/S formula)
  budget/         — BudgetEngine (GB estimate, eviction priority)
  placement/      — SymbolBudgetEngine (weighted allocation)
  erasure/        — ErasureEncoder trait + RaptorQ impl + per-holder binding
  cluster/        — DeviceCertificate, RevocationCertificate, ClusterState, epochs
  pos/            — PosEngine (challenge selection, verify, adaptive schedule)
  messages/       — all wire messages + mailbox entry types (MailboxEntry, MailboxClass)
  config/         — TOML config loading and validation (AppConfig)
  commitment/     — Holder eviction risk estimation (CommitmentScore)
  reliability/    — P(block recoverable) forecast (Binomial model)
  deletion/       — Double cooldown deletion flow + vacuum
  system_state/   — SystemState struct, snapshot_db, restore_db, pack/unpack (CBOR+zstd+ChaCha20)
  importance/     — file-importance classification by type + burst (rare-moment) detection
  migration/      — redb schema migrations
  path_safety/    — path validation / traversal guards
  priority/       — work prioritisation helpers
```

### viaticum

Daemon + CLI. Uses tokio. Imports `viaticum-core`.

```
crates/viaticum/src/
  main.rs         — binary entry point: CLI dispatch, tracing setup
  lib.rs          — pub mod daemon
  cli/            — Clap CLI, CliRequest/CliResponse types, output formatting
  daemon/
    mod.rs        — pub mod for all daemon modules
    handle/       — DaemonHandle: top-level wiring, DaemonState
    processor/    — Processor: message router for all incoming messages
    network/      — SwarmHandle (swarm.rs)
    backup/       — BackupCoordinator (+ events.rs, pipeline.rs, packing.rs)
    restore/      — RestoreCoordinator (+ pipeline.rs)
    repair/       — thin: reliability scan + placement-event handlers (active repair lives in work_pipeline)
    scheduler/    — Scheduler: PoS challenge timing, PendingChallenges
    watcher/      — fs-notify watcher: recursive, debounce, DirtyEvent
    mailbox/      — MailboxRouter: routing (publish/poll/dr_walk), candidate selection, poll dispatch, TTL/membership cleanup
    cluster_sync/ — ClusterSyncManager
    web_api/      — HTTP + token API server (axum/TCP): serves both CLI and web UI
    web_auth/     — token auth for web_api
    work_pipeline/— unified work queue: backup, repair and PoS tasks (+ worker.rs)
    watch_admin/  — live add/remove of watched folders without restart
    symbol_fetch/ — fetch unbound symbols from holders (restore + repair-from-peers)
    holdings_integrity/ — periodic scan that held symbols still exist on disk
    holder_cleanup/ — evict holdings after drop-notice window
    dispatch/     — shared request dispatch (web_api + mailbox)
    metrics/      — Prometheus metrics + status aggregation
    identity/     — BIP39/HKDF key derivation, identity.key file
    system_state/ — snapshot+encrypt → erasure-coded SS-block, publish/refresh the DR self-pointer via mailbox
    dr/           — disaster recovery CLI: Kademlia discovery → mailbox self-pointer walk → standalone restore
```

---

## viaticum-core modules

### types

All newtype ID wrappers, record structs, and helper types.

**Key types:**

| Type | Description |
|------|-------------|
| `SourceBlockId([u8; 32])` | BLAKE3 hash of the encrypted source block |
| `IdentityPub([u8; 32])` | Ed25519 public key (master identity) |
| `DeviceId([u8; 32])` | Ed25519 pubkey bytes of device signing key |
| `FileId(u64)` | Monotonic file ID, assigned on first indexing |
| `Timestamp(u64)` | Unix timestamp in seconds |
| `ErasureParams` | Computed parameters: K, K_eff, T, overhead, N |
| `FileRecord` | Catalog entry: path, importance, devices, versions |
| `FileVersion` | One file version: content_hash, source_block_id, created_at |
| `SourceBlockRecord` | Source block metadata: K, T, type, status, encrypted_size |
| `SymbolPlacement` | Symbol placement at a holder: esi_ranges, binding_seed, status |
| `PlacementStatus` | Offered → Accepted → Alive → Uncertain → PresumedLost → Lost / Deleting |
| `PeerRecord` | Peer data: trust_p, trust_i, trust_s, byte counters, device_id |
| `HoldingRecord` | Symbols we hold on behalf of another owner |
| `HoldingStatus` | Active / MarkedForDelete / Silent |
| `BudgetRecord` | Singleton: estimated_gb, placement_success_rate |
| `BlockAgg` | RAM aggregate: K, total_alive_symbols for a source block |
| `PlacementAgg` | RAM aggregate: symbol_count, status, last_pos for (block, holder) |
| `Event` / `EventEntry` | Typed event log entries (for cluster sync) |
| `FileCategory` | Photo / Document / Video / Other (for packing queues) |
| `LocalState` | Present / Deleted(Timestamp) (file state on a specific device) |
| `SourceBlockType` | Pack { entries } / Single |

**Dependencies:** only `constants`, no external logic.

---

### trust

`TrustEngine` — computes a trust score for each peer.

**Formula:** `trust = (KP × P + KI × I) × clamp(S, 0.1, 1.0)`

- P — rolling 4-week PoS pass rate
- I — cumulative mean PoS pass rate
- S — pairwise GB ratio (what we store for them / what they store for us)
- KP = 0.4, KI = 1.75 (from `constants.rs`)

**Key methods:** `record_pos_outcome`, `recalculate`, `score`.

**Storage:** in-memory HashMap; populated at startup from the `POS_WEEKLY` redb table via `Db`.

---

### budget

`BudgetEngine` — estimates how many GB we can place at other peers.

Accounts for placement_success_rate (rolling 4-week), willingness_factor (1.0), FREE_TIER_GB bootstrap (1 GB), offer_budget_gb (inflated by 1/sr).

Singleton `BudgetRecord` is stored in the redb table `BUDGET`.

---

### placement

`SymbolBudgetEngine` — computes how many symbols to assign to each holder.

**Weight formula:** `weight = trust / sqrt(1 - trust)` (mean-variance optimum)

**Constraints:**
- `MAX_HOLDERS_PER_BLOCK = 30`
- `MIN_SYMBOLS_PER_HOLDER = 32` (2 MB at T=64 KB)
- Concentration cap: `max_per_holder = min(K_eff - 1, floor((1 - 1/overhead) × 0.85 × N))`

**Input:** `Vec<HolderCandidate>` with trust score + `ErasureParams`.
**Output:** `Vec<HolderAllocation>` with symbol_count and start_esi per holder.

---

### erasure

**trait ErasureEncoder** — abstraction over erasure coding. Single implementation: RaptorQ.

```rust
fn encode(source_block, params, start_esi, count, block_id, holder_id) -> Vec<Symbol>
fn decode(symbols, params) -> Vec<u8>
fn generate_repair(source_block, params, esi, block_id, holder_id) -> Symbol
fn unbind(symbol, block_id, holder_id) -> Symbol
```

**Per-holder binding (anti-collusion):**
```
keystream = ChaCha20(HKDF-SHA256(source_block_id || holder_id), nonce=0)
bound_symbol_data = raw_symbol_data XOR keystream[esi*T..(esi+1)*T]
```

A symbol is fungible, identified by ESI. T = 65535 bytes (fixed: limit of the raptorq crate).

---

### cluster

Handles device keys and certificates. No networking.

**Key types:**
- `DeviceCertificate` — master_key.sign(device_id, device_pub_key, issued_at)
- `RevocationCertificate` — master_key.sign("revoke", device_id, revoked_at, new_epoch)
- `EpochCounter(u32)` — incremented on each revocation
- `ClusterState` — in-memory: set of devices, revoked keys, sync cursors

**Storage:** `StoredClusterState` in the redb table `CLUSTER_STATE`.

Key hierarchy: BIP39 (24 words) → HKDF-SHA256 → master Ed25519 key → device keys.

---

### pos

`PosEngine` — challenge selection, verification, adaptive scheduling.

**Adaptive schedule:**
```
challenges_per_week = POS_BASE_CHALLENGES_PER_WEEK
                    × ceil(holder_symbols / POS_VOLUME_DIVISOR)
                    × trust_factor
```

- `POS_BASE_CHALLENGES_PER_WEEK = 1`
- `POS_VOLUME_DIVISOR = 1000`
- Timeout = 7 days (`POS_TIMEOUT_SECS`)

**PlacementStatus state machine (PoS timeouts):**
```
Alive → 1 miss → Uncertain → 3+ misses → PresumedLost → repair
Alive → Fail / NotHeld → Lost → immediate repair
```

**On-the-fly verification:** the owner re-encodes the symbol locally and compares it against the holder's response. No PoS hashes are stored on disk.

**VerifyOutcome:** Pass / Fail { esi } / Timeout / NotHeld { esi }

**Weekly statistics:** table `POS_WEEKLY` in redb, key = (peer || week_number_BE).

---

### messages

All wire messages + mailbox entry types. Wire format: CBOR + u32 BE length prefix.

**Direct request-response messages** (all ride `/viaticum/1`):

| Type | Direction | Description |
|------|-----------|-------------|
| `HandshakeMsg` | ↔ | Mutual authentication on connection open |
| `PeerAnnounceMsg` | on connect | Peer address + key announcement (discovery) |
| `PosHashChallengeMsg` | owner → holder | Challenge an ESI range (chain-hash PoS) |
| `PosHashResponseMsg` | holder → owner | Response: SHA256 chain hash over bound symbols |
| `PosHashNackMsg` | holder → owner | Symbol(s) not held (evicted / missed), signed |
| `SymbolOfferMsg` | owner → holder | Offer to receive symbols |
| `SymbolAcceptMsg` | holder → owner | Acceptance |
| `SymbolRejectMsg` | holder → owner | Rejection (QuotaFull / LowPriority / ...) |
| `SymbolStoredMsg` | holder → owner | Confirmation of storage |
| `SymbolTransferMsg` | ↔ | Symbol transfer (backup + restore) |
| `SymbolDroppedMsg` | holder → owner | Holder dropped symbols (disk pressure) |
| `ClusterSyncRequestMsg` | device → device | Request event log after cursor |
| `ClusterSyncResponseMsg` | device → device | Response with events |
| `MailboxStoreRequest` | sender → postman | Deposit a mailbox entry for a target |
| `MailboxStoreResponse` | postman → sender | Ack / Reject{reason} |
| `MailboxFetchRequest` | target → postman | Poll own mailbox |
| `MailboxFetchResponse` | postman → target | Entries addressed to the requester |

**Deferred payloads** (holder offline) do not have their own top-level message: they travel *inside* mailbox entries (see [protocol.md §1.5](protocol.md)). Classes: `SelfPointer`, `PosChallenge`, `PosResponse`, `DropNotice` (carries `SymbolDropNoticeBatchMsg`), `DeleteRequest` (Delete/CancelDelete), `Revocation` (carries `RevocationBroadcast`).

ALPN: `"viaticum/1"`. HandshakeMsg is Ed25519-signed: `sign("handshake" || identity_pub || timestamp_be)`.

---

### db

`Db` — newtype over `Arc<redb::Database>` + `Arc<RwLock<HotCache>>`.

Cheaply cloneable: `clone()` = increment refcount. All methods take `&self`.
MVCC in redb provides read parallelism. Write-lock on HotCache only during mutations.

Opening: `Db::open(path)` — pre-open backup (.redb.bak), `DatabaseBuilder` with `repair_callback`, `check_integrity()`, creates all tables and builds HotCache via a full scan of SYMBOL_PLACEMENTS.

**Two layers:**
- **HOT (RAM, ~13 MB at 5 TB):** HashMap aggregates `BlockAgg` and `PlacementAgg` in `HotCache`
- **WARM (redb, ~133 MB at 5 TB):** all redb tables (see DB Schema below), CBOR values

---

## DB Schema

### redb tables (WARM layer)

| Table | Key | Value | Description |
|-------|-----|-------|-------------|
| `files` | `&str` (path) | CBOR(`FileRecord`) | File catalog |
| `source_blocks` | `&[u8; 32]` (block_id) | CBOR(`SourceBlockRecord`) | Source block metadata |
| `symbol_placements` | `&[u8; 64]` (block_id ∥ holder DeviceId) | CBOR(`SymbolPlacement`) | Symbol placements (owner side) |
| `peers` | `&[u8; 32]` (device_id) | CBOR(`PeerRecord`) | Peer data, keyed by DeviceId |
| `holdings` | `&[u8; 64]` (block_id ∥ owner_id) | CBOR(`HoldingRecord`) | Held symbols (holder side) |
| `event_log` | `u64` (seq, 1-based monotonic) | CBOR(`EventEntry`) | Append-only event log for cluster sync |
| `budget` | `"budget"` | CBOR(`BudgetRecord`) | Singleton: GB estimate |
| `pos_weekly` | `&[u8; 36]` (peer ∥ week_number_BE4) | CBOR(`WeeklyPosEntry`) | Weekly PoS statistics |
| `cluster_state` | `"cluster_state"` | CBOR(`StoredClusterState`) | Singleton: cluster state |
| `file_holders` | `&[u8; 40]` (file_id_BE8 ∥ holder_id) | `u32` (symbol_count) | Index file → holders |
| `holder_files` | `&[u8; 40]` (holder_id ∥ file_id_BE8) | `u32` (symbol_count) | Index holder → files |
| `mailbox_entries` | `&[u8; 49]` (target ∥ msg_id ∥ class) | CBOR(`MailboxEntry`) | Stored mailbox entries (postman side) |
| `mailbox_bytes_by_target` | `&[u8; 32]` (target identity_pub) | `u64` | Per-target mailbox byte accounting (quota) |
| `ss_blocks` | `&[u8; 32]` (block_id) | `u32` (generation) | Marks which source blocks are SystemState replicas |
| `restore_served` | `&[u8; 32]` (requester identity_pub) | CBOR(`u64`) | Bytes served per requester (accounting only; nothing gates restore on it) |
| `device_trust` | `&[u8; 32]` (device_id) | CBOR(`DeviceTrustRecord`) | Per-device trust |
| `master_trust` | `&[u8; 32]` (master identity_pub) | CBOR(`MasterTrustRecord`) | Aggregated cluster trust |
| `device_to_master` | `&[u8; 32]` (device_id) | CBOR(`IdentityPub`) | Device → master identity mapping |
| `content_index` | `&[u8]` (content_hash ∥ path) | *(empty)* | Index content_hash → paths, for O(1) import dedup |
| `pair_ledger` | `&[u8; 32]` (master identity_pub) | CBOR(`PairLedger`) | 4R accumulators per economic pair (recorder only — no decision reads it) |
| `meta` | `&str` | CBOR | Misc singletons (e.g. next_file_id) |

### HotCache (RAM layer)

```rust
pub struct HotCache {
    // source_block_id → { k, total_alive_symbols }
    pub blocks: HashMap<SourceBlockId, BlockAgg>,
    // (source_block_id, holder DeviceId) → { symbol_count, status, last_pos }
    pub placements: HashMap<(SourceBlockId, DeviceId), PlacementAgg>,
}
```

Rebuilt at `Db::open()` via a full scan of `symbol_placements`. Updated synchronously inside a redb write transaction on every placement mutation.

---

## Daemon modules (viaticum)

### network

`SwarmHandle` — the single libp2p swarm per daemon instance.

**Responsibilities:**
- Creates the libp2p swarm: TCP+Noise+Yamux, Kademlia DHT, DCUtR+Relay for NAT traversal
- Runs the background swarm event loop (authenticates incoming connections)
- DeviceCertExchange on connect: binds libp2p PeerId to IdentityPub
- Handshake: DeviceCertExchange + Ed25519 verification + freshness check (±300 s)

**API (SwarmHandle):**
- `start(config) → (SwarmHandle, Receiver<ProtocolEvent>)` — start swarm + event loop
- `send_to_device(device: DeviceId, msg)` — send a message to a device by DeviceId
- `send_to_master(master: IdentityPub, msg)` — send to any device belonging to a master
- `dial(peer_id, addr)` — explicit dial by libp2p PeerId + Multiaddr
- `listen_addrs()` — list of addresses we are listening on
- `respond(channel, msg)` — respond to an inbound request via ResponseChannel
- `build_peer_announce(...)` — constructs a signed PeerAnnounceMsg

---

### backup

`BackupCoordinator` — orchestrates the file → symbol pipeline.

**Event lifecycle:**
```
DirtyEvent(path, kind, device_id)
  │
  ├─ Deleted  → FileRecord.devices[device].local_state = Deleted(now)
  │             (no network traffic)
  │
  └─ Added/Modified
       → content_hash = blake3(file)
       → dedup: content_hash in catalog? → add version/device, done
       → classify(path) → FileCategory
       → size ≥ source_block_size? → process_large_file()
       → otherwise → enqueue into per-category queue
```

**Packing queues:** four queues by category (Photo, Document, Video, Other).

**Flush conditions (any of):**
- `queue_bytes ≥ source_block_size`
- 1 hour idle (FLUSH_IDLE_SECS)
- 24 hour fallback (FLUSH_FALLBACK_SECS)
- Explicit force=true

**Pipeline inside flush:**
```
batch plaintext = [PackIndex CBOR] + [file1 bytes] + [file2 bytes] + ...
  → zstd compress (streaming)
  → ChaCha20-Poly1305 encrypt (epoch_key, random nonce prepended)
  → ciphertext = source block
  → source_block_id = blake3(nonce || ciphertext)
  → ErasureParams (against target reliability + holder trust)
  → SymbolBudgetEngine.compute_allocation(candidates, params)
  → for each holder:
      encode(source_block, params, start_esi, count, block_id, holder_id)
      → bound symbols (per-holder XOR binding)
      → held in RAM, sent to the holder, then dropped (no own-symbol disk writes since Wave 11b)
  → DB: upsert FileRecord, SourceBlockRecord, SymbolPlacement × N_holders
  → EventLog: append SymbolsPlaced events
  → RAM hot: update BlockAgg, PlacementAgg
```

**Async run():** receives `DirtyEvent` from an mpsc channel. Three timers: idle, fallback, channel close.

---

### restore

`RestoreCoordinator` — orchestrates symbol fetch → decode → file write.

**Supports:**
- Exact restore of a single file by path
- Prefix request (path ending in `/` → all files with that prefix)
- Version selection: Latest / Index(n) / BeforeDate(timestamp)

**Pipeline:**
```
RestoreRequest(path, VersionSelector, output_dir, device_id)
  → resolve_path → Vec<FileRecord>
  → select_version → (FileRecord, FileVersion) pairs
  → deduplicate by source_block_id
  → for each unique source block:
      list_placements_for_block → alive placements
      → fetch symbols from holders, or read local cache at {symbols_dir}/{hex(block_id)}/raw/{esi}.bin
      → unbind: symbol XOR ChaCha20(HKDF(block_id, holder_id))
      → collect ≥ K_eff unbound symbols
      → ErasureEncoder.decode → padded block
      → trim to encrypted_size (from SourceBlockRecord)
      → ChaCha20-Poly1305 decrypt → compressed
      → zstd decompress → plaintext
  → Pack: extract_from_pack(plaintext, file_id) → file bytes
  → Single: plaintext directly
  → write file to output_dir
  → update FileRecord.devices: device_id → Present
```

Local restore: symbols on disk from BackupCoordinator.
Network restore: fetch from holders via NetworkHandle (`fetch_from_holder`).

**Async run():** receives `(RestoreRequest, oneshot::Sender)` from mpsc, processes sequentially.

---

### repair

Since Wave 11b, `RepairAgent` is thin: it runs a periodic reliability scan and handles placement events. The active repair loop (re-encode + deliver to new holders) lives in `work_pipeline/worker.rs`.

**Triggers:**
- Periodic reliability scan (flags blocks below the target)
- Placement transitions to Lost/PresumedLost (PoS miss, SymbolDropped, PosHashNack)

**Repair (in the work pipeline):**
```
1. Read SourceBlockRecord from DB → K, T
2. Rebuild the source blob from the source files (deterministic; no block.bin on disk)
3. Re-encode the missing ESIs, apply per-holder binding
4. Place on new holders via a fresh placement round
5. Update placement.status = Alive
```

If the source files are gone, the worker cannot rebuild and the placement stays Lost — recovery is then via `viaticum dr` + `viaticum restore` (the DR-only recovery model for source loss).

**handle_symbol_dropped / handle_pos_nack:** both `mark_placement_lost` (idempotent).

---

### cluster_sync

`ClusterSyncManager` — exchanges the event log between devices in the same cluster.

**Synchronous API** (not async). Callers manage connections.

**Methods:**
- `build_sync_request(peer_identity)` → `ClusterSyncRequestMsg` with cursor
- `process_sync_response(peer_identity, response)` → applies events, updates cursor
- `handle_sync_request(request)` → returns events from the event log, checks membership
- `build_revocation_broadcast(revocation, device_cert)` → `RevocationBroadcast` payload for the `Revocation` mailbox class

**Cursor persistence:** sync cursors are stored in `ClusterState` (in-memory) and persisted to the `CLUSTER_STATE` redb table via `ClusterState::update_sync_cursor`.

Incoming request validation: `device_id` must be in the cluster and not revoked.

---

### mailbox

`MailboxRouter` — directed store-and-forward bus for deferred messaging (replaced the epidemic relay board; see [protocol.md §1.5](protocol.md), [ADR-004](decisions/ADR-004-mailbox-bus.md)).

**Model:** every entry is addressed to one recipient's master identity. The peers Kademlia-closest to `SHA256(target_pub)` act as **postmen** and store entries on the target's behalf. No hops, no gossip, no per-message ECDH — Noise IX + a per-payload Ed25519 signature provide confidentiality and authenticity.

**Router methods** (`routing.rs`):
- `publish(target, entry)` — deposit with the `MAILBOX_WRITE_FANOUT` (30) closest postmen; durable once ≥1 Acks
- `poll(my_master_pub, since)` — fetch from the `MAILBOX_READ_FANOUT` (300) closest postmen, dedup by msg_id
- `dr_collect_pointers(my_master_pub)` — expanding-batch [100, 300, 1000] collection of every signed `SelfPointer` of the identity, each peer asked once (disaster recovery; the choice between catalog histories is `system_state::catalog::select_catalog`)

**Postman side** (`processor/mailbox`): `handle_mailbox_store` runs the candidate-set `should_store` check then persists (idempotent on duplicate msg_id); `handle_mailbox_fetch` returns entries only to their own target.

**Cleanup loops** (`cleanup/`): `run_mailbox_ttl_sweep` (every 6h / time_scale) deletes expired entries for all classes; `run_mailbox_self_cleanup` drops non-high-trust entries for targets this node no longer serves. `SelfPointer` is high-trust — only TTL removes it.

**Poll loop** (`poll.rs`): `poll_interval_secs` (1h / time_scale) fetches own mail and dispatches each entry by class to its handler.

---

### handle

`DaemonHandle` — top-level entry point. Owns and wires all subsystems.

**DaemonState** (shared via `Arc`):
```rust
DaemonState {
    db, identity_pub, device_id, network, restore_tx,
    cluster_state, incoming_tx, master_key, seed,
    data_dir, soft_quota_bytes, disk_reserve_bytes,
}
```

**Startup sequence:**
1. Load/create identity (BIP39 → keys)
2. Open DB (with repair callback + pre-open backup)
3. Start SwarmHandle (libp2p swarm + event loop)
4. Spawn Processor (message router)
5. Spawn BackupCoordinator, RestoreCoordinator, WorkPipeline (+ thin RepairAgent)
6. Spawn Scheduler (PoS), MailboxRouter poll + cleanup loops, ClusterSyncManager
7. Spawn SystemState periodic self-pointer publish (interval = 6h / time_scale, min 60s)
8. Start Watcher (fs-notify) for configured directories
9. Start web_api (HTTP + token API for CLI and web UI)
10. Load peers from DB → known_peers in network
11. Bootstrap: connect to bootstrap peers, join Kademlia DHT

---

### processor

`Processor` — thin message router. Receives incoming connections from network, dispatches messages to appropriate handlers.

**Dispatch table:**
- `Handshake` → auth (handled by network accept loop)
- `PeerAnnounce` → upsert peer, add to known_peers, store addrs + keys
- `PosHashChallenge` → compute the chain hash over held symbols, send PosHashResponse or PosHashNack
- `PosHashResponse` → verify the chain hash, update placement status + trust
- `PosHashNack` → mark placement Lost, trigger repair
- `SymbolOffer` → check quota → SymbolAccept / SymbolReject
- `SymbolAccept` → update placement to Alive (via BackupEvent channel)
- `SymbolReject` → update placement, log
- `SymbolTransfer` → write symbols to disk, update HoldingRecord
- `SymbolStored` → log confirmation
- `RestoreRequest` → holding lookup by (block, requester master) → read symbols → RestoreResponse (empty if no holding, or the owner asked to delete it)
- `ClusterSync*` → forwarded to ClusterSyncManager
- `Delete/CancelDelete` → update HoldingRecord status
- `StorageWarning/SymbolDropped/SymbolDropNotice` → log, update placements
- `MailboxStoreRequest` → `should_store` check → persist entry → Ack / Reject
- `MailboxFetchRequest` → return this requester's own entries
- `MailboxStoreResponse/MailboxFetchResponse` → routed to the MailboxRouter's publish/poll waiters
- `Ack` → generic ack for request-response streams

Deferred payloads (PoS, Delete, DropNotice, Revocation, SelfPointer) arrive as `MailboxFetchResponse` entries and are dispatched by the mailbox poll loop, not here. (PeerDiscovery messages were removed in ε.2 — peers are found via the Kademlia DHT.)

**On new connection (PeerAuthenticated event):** upserts PeerRecord, sends PeerAnnounce, auto-adds cluster device.

---

### watcher

`WatcherConfig` → fs-notify recursive watcher on configured directories.

**Pipeline:**
```
fs event → notify::Event → std channel → tokio task → debounce (30 min)
  → DirtyEvent { path, kind: Added/Modified/Deleted, device_id }
  → mpsc → BackupCoordinator
```

Filters (the same for the scan and for live events): hidden files and folders
(any component below the watch root starting with `.`), Viaticum data directories
(a directory holding `identity.key`, found at or below the watch root, is skipped
whole), `.viaticumignore` rules and built-in ignores. Symlinks to directories are
not followed. A watch folder that is a data directory, or lies in its
`holdings/`, `symbols/`, `restore/` or `system_state/`, is refused.
A full scan at start (when the last one is older than the rescan interval) and a
weekly rescan emit every file; live events cover changes in between.

---

### scheduler

`Scheduler` — periodic PoS challenge issuance.

- Computes `due_challenges()` from placements + last_verified timestamps
- Issues PosHashChallenge via network, stores in `PendingChallenges` (shared with Processor)
- On timeout (7 days): records as Timeout, updates placement status
- Adaptive rate: `challenges/week = base * volume_factor * trust_factor`

---

### web_api

HTTP + token API server (axum, TCP); port and token in `{data_dir}/api-port` + `{data_dir}/api-token`. Serves both the CLI and the web UI; `web_auth` checks the token. Replaced the old Unix-socket `cli_server` in the macOS HTTP-unification work.

**Endpoints (mirror the CLI):** status, files, versions, restore, connect, device (add/revoke/list), folders (watch admin), settings.

Bridges requests → DaemonState for reads, → RestoreCoordinator for restores, → SwarmHandle for connections.

---

### identity

BIP39 mnemonic (24 words) → seed → HKDF key derivation.

**Derived keys:**
- master_key (Ed25519): `HKDF(seed, info="viaticum-identity-ed25519")`
- device_key (Ed25519): `HKDF(seed, salt=device_id, info="viaticum-device-ed25519")`
- epoch_key: `HKDF(seed, salt=epoch_counter, info="viaticum-encryption")`
Identity file: `{data_dir}/identity.key` (mode 0600), stores encrypted seed.

---

## Data flows

### Backup

```
File system
  │
  ├─ fs-notify (watcher)
  │    debounce 30 min → dirty_files
  │
  └─ DirtyEvent → BackupCoordinator.process_event()
                        │
                  dedup check (content_hash in catalog?)
                        │
              ┌─ yes → add version/device, done (zero traffic)
              │
              └─ no → classify → packing queue
                           │
                    flush trigger (size / idle / fallback)
                           │
              compress(zstd) → encrypt(ChaCha20-Poly1305)
                           │
                  source_block_id = blake3(ciphertext)
                           │
               ErasureParams::compute(size, importance)
                           │
          SymbolBudgetEngine.compute_allocation(candidates, params)
                           │
                   for each holder:
                     encode → bind → write {esi}.bin
                           │
                   DB update: Files, SourceBlocks,
                   SymbolPlacements, EventLog, HotCache
```

### Restore

```
RestoreRequest(path, VersionSelector, output_dir)
  │
  DB: get_file / list_files_with_prefix
  DB: list_placements_for_block → alive
  │
  for each source block:
    read {esi}.bin → Symbol
    unbind(XOR ChaCha20 keystream) → raw symbol
    collect ≥ K_eff
    decode → padded_block[k×t]
    trim → encrypted_block[encrypted_size]
    decrypt(ChaCha20-Poly1305, epoch_key)
    decompress(zstd)
    │
    Pack → extract_from_pack(plaintext, file_id)
    Single → plaintext directly
    │
    write output_dir/{rel_path}
    DB: update LocalState → Present
```

### Proof of Storage

```
PosEngine.compute_schedule(placements, now)
  → challenges_per_week = base × volume_factor × trust_factor
  │
  for each challenge:
    PosHashChallengeMsg { challenge_id, source_block_id, esi_ranges } → holder
    │
    holder replies PosHashResponseMsg { chain_hash } or PosHashNackMsg
    │
    verify_response():
      re-encode + per-holder bind the esi_ranges from the local source block
      chain_hash(seed = SHA256(challenge_id)) == response.chain_hash?
      │
    VerifyOutcome: Pass / Fail / Timeout / NotHeld
    │
    update_placement_status(outcome, now):
      Pass    → status=Alive, consecutive_misses=0
      Fail    → status=Lost (immediate)
      NotHeld → status=Lost (immediate)
      Timeout → consecutive_misses++
                1 miss  → Uncertain
                3+ miss → PresumedLost
    │
    TrustEngine.record_pos_outcome(peer, week, outcome)
    DB: upsert_placement, upsert_pos_weekly
```

### Repair

```
WorkPipeline worker (repair task)
  │
  DB: placements needing repair  ← status=Lost/PresumedLost
  │
  for each block:
    rebuild source blob from the source files (deterministic; no block.bin on disk)
    SourceBlockRecord: K, T;  SymbolPlacement: esi_ranges, holder_id
    │
    for each missing ESI:
      encode + per-holder binding (held in RAM)
    │
    place on new holders via a fresh placement round
    network: send symbols to holder
    DB: upsert_placement(status=Alive, consecutive_misses=0)
```

### Cluster sync

```
ClusterSyncManager.build_sync_request(peer_identity)
  → ClusterSyncRequestMsg { last_known_seq: cursor }
  │
  → send over network connection
  ↓
peer returns ClusterSyncResponseMsg { events, responder_last_seq }
  │
process_sync_response():
  ClusterState.apply_events(events)   ← idempotent
  ClusterState.update_sync_cursor(peer, responder_last_seq)
  DB: set_cluster_state()
```

---

## Configuration (what is configurable)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `source_block_size` | 128 MB | Source block size. Reduce for low-memory hardware (32 MB → ~65 MB peak RAM) |
| `symbols_dir` | `"symbols"` | Directory for symbol files |
| `epoch_key` | — | 32-byte encryption key (derived from master key) |
| `device_id` | — | Device identifier |
| `soft_quota` | 0 (no ceiling) | Soft holding limit in bytes |
| `hard_quota` | 0 (no floor) | Hard minimum: do not evict below this |
| `disk_reserve` | 20 GB | Reserved free disk space |
| `effective_quota` | computed | `min(soft_quota, disk_free - disk_reserve)` |
| `backup_dirs` | — | Directories to back up + importance per directory |
| `max_versions` | 5 | Maximum versions per path |
| `max_version_age` | 90 days | Maximum age of old versions |
| `parallel_holders` | 5 | Parallel connections during restore |

All numeric protocol parameters are defined in `viaticum-core/src/constants.rs`.
