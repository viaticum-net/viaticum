# Viaticum Architecture

*2026-03-22. Reflects actual code — all phases + δ.1 complete (716 tests, ~34K lines Rust).*

*See also: [overview.md](../overview.md) for end-to-end flows, [logic.md](logic.md) for algorithms, [protocol.md](protocol.md) for wire format.*

---

## Overall structure

```
┌─────────────────────────── viaticum-core ───────────────────────────────┐
│  (pure Rust, no async, no network)                                       │
│                                                                          │
│  types ──► db ──────────────────────────────────────────────────────    │
│   │         (Db, HotCache, 12 redb tables)                          │    │
│   │                                                                  │    │
│   ├──► trust    (TrustEngine: P, I, S)                              │    │
│   ├──► escrow   (EscrowChecker: trust-based budget gate)            │    │
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
│     ├──► repair       (RepairAgent: Lost/PresumedLost → re-encode)      │
│     ├──► scheduler    (PoS challenge scheduling, timeout detection)     │
│     ├──► watcher      (fs-notify: recursive watch → DirtyEvent)         │
│     ├──► relay        (RelayManager: epidemic board, hop≤2)             │
│     ├──► cluster_sync (ClusterSyncManager: event log exchange)          │
│     ├──► cli_server   (Unix socket: CLI commands → DaemonState)         │
│     ├──► identity     (BIP39 → HKDF → keys, identity file mgmt)        │
│     ├──► system_state (periodic DB push, bootstrap discovery)           │
│     └──► dr           (disaster recovery: BFS, standalone restore)      │
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
  escrow/         — EscrowChecker (trust-based gate)
  budget/         — BudgetEngine (GB estimate, eviction priority)
  placement/      — SymbolBudgetEngine (weighted allocation)
  erasure/        — ErasureEncoder trait + RaptorQ impl + per-holder binding
  cluster/        — DeviceCertificate, RevocationCertificate, ClusterState, epochs
  pos/            — PosEngine (challenge selection, verify, adaptive schedule)
  messages/       — all wire messages + relay board helpers
  config/         — TOML config loading and validation (AppConfig)
  commitment/     — Holder eviction risk estimation (CommitmentScore)
  reliability/    — P(block recoverable) forecast (Binomial model)
  deletion/       — Double cooldown deletion flow + vacuum
  system_state/   — SystemState struct, snapshot_db, restore_db, pack/unpack (CBOR+zstd+ChaCha20)
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
    repair/       — RepairAgent
    scheduler/    — Scheduler: PoS challenge timing, PendingChallenges
    watcher/      — fs-notify watcher: recursive, debounce, DirtyEvent
    relay/        — RelayManager (+ board.rs)
    cluster_sync/ — ClusterSyncManager
    cli_server/   — Unix socket server: bridges CLI to DaemonState
    identity/     — BIP39/HKDF key derivation, identity.key file
    system_state/ — periodic DB push to peers, bootstrap discovery
    dr/           — disaster recovery CLI: BFS peer discovery, standalone restore
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

### escrow

`EscrowChecker` — gate for restore requests.

**Formula:** `restore_budget_gb = stored_gb_days / k_factor`

- `k_factor = DEFAULT_ESCROW_K_FACTOR = 7.0` (days of storage required per 1 GB of restore credit)
- `stored_gb_days` = bytes_we_store_for_peer × days_held (summed across all holding records)

Contribution-based: earn restore credit by storing data for others.

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

All wire messages + relay board helpers. Wire format: CBOR + u32 BE length prefix.

**Direct-connection messages:**

| Type | Direction | Description |
|------|-----------|-------------|
| `HandshakeMsg` | ↔ | Mutual authentication on connection open |
| `PeerAnnounceMsg` | broadcast relay | Peer address announcement (discovery) |
| `PosChallengeMsg` | owner → holder | Request symbol data by ESI |
| `PosResponseMsg` | holder → owner | Response: symbol data |
| `PosNackMsg` | holder → owner | Symbol not held (evicted / missed) |
| `SymbolOfferMsg` | owner → holder | Offer to receive symbols |
| `SymbolAcceptMsg` | holder → owner | Acceptance |
| `SymbolRejectMsg` | holder → owner | Rejection (QuotaFull / LowPriority / ...) |
| `SymbolStoredMsg` | holder → owner | Confirmation of storage |
| `SymbolTransferMsg` | ↔ | Symbol transfer (backup + restore) |
| `SymbolDroppedMsg` | holder → owner | Holder dropped symbols (disk pressure) |
| `ClusterSyncRequestMsg` | device → device | Request event log after cursor |
| `ClusterSyncResponseMsg` | device → device | Response with events |
| `RevocationBroadcast` | relay broadcast | Broadcast of a revocation certificate |

ALPN: `"viaticum/1"`. HandshakeMsg is Ed25519-signed: `sign("handshake" || identity_pub || timestamp_be)`.

---

### db

`Db` — newtype over `Arc<redb::Database>` + `Arc<RwLock<HotCache>>`.

Cheaply cloneable: `clone()` = increment refcount. All methods take `&self`.
MVCC in redb provides read parallelism. Write-lock on HotCache only during mutations.

Opening: `Db::open(path)` — pre-open backup (.redb.bak), `DatabaseBuilder` with `repair_callback`, `check_integrity()`, creates all tables and builds HotCache via a full scan of SYMBOL_PLACEMENTS.

**Two layers:**
- **HOT (RAM, ~13 MB at 5 TB):** HashMap aggregates `BlockAgg` and `PlacementAgg` in `HotCache`
- **WARM (redb, ~133 MB at 5 TB):** all 12 tables, CBOR values

---

## DB Schema

### redb tables (WARM layer)

| Table | Key | Value | Description |
|-------|-----|-------|-------------|
| `files` | `&str` (path) | CBOR(`FileRecord`) | File catalog |
| `source_blocks` | `&[u8; 32]` (block_id) | CBOR(`SourceBlockRecord`) | Source block metadata |
| `symbol_placements` | `&[u8; 64]` (block_id ∥ holder_id) | CBOR(`SymbolPlacement`) | Symbol placements (owner side) |
| `peers` | `&[u8; 32]` (identity_pub) | CBOR(`PeerRecord`) | Peer data |
| `holdings` | `&[u8; 64]` (block_id ∥ owner_id) | CBOR(`HoldingRecord`) | Held symbols (holder side) |
| `event_log` | `u64` (seq, 1-based monotonic) | CBOR(`EventEntry`) | Append-only event log for cluster sync |
| `budget` | `"budget"` | CBOR(`BudgetRecord`) | Singleton: GB estimate |
| `pos_weekly` | `&[u8; 36]` (peer ∥ week_number_BE4) | CBOR(`WeeklyPosEntry`) | Weekly PoS statistics |
| `cluster_state` | `"cluster_state"` | CBOR(`StoredClusterState`) | Singleton: cluster state |
| `file_holders` | `&[u8; 40]` (file_id_BE8 ∥ holder_id) | `u32` (symbol_count) | Index file → holders |
| `holder_files` | `&[u8; 40]` (holder_id ∥ file_id_BE8) | `u32` (symbol_count) | Index holder → files |
| `system_state_blobs` | `&[u8; 32]` (owner identity_pub) | CBOR(`SystemStateBlobRecord`) | Encrypted DB snapshots from peers (1 per owner, TTL 365 days) |

### HotCache (RAM layer)

```rust
pub struct HotCache {
    // source_block_id → { k, total_alive_symbols }
    pub blocks: HashMap<SourceBlockId, BlockAgg>,
    // (source_block_id, holder IdentityPub) → { symbol_count, status, last_pos }
    pub placements: HashMap<(SourceBlockId, IdentityPub), PlacementAgg>,
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
  → source_block_id = blake3(ciphertext)
  → ErasureParams::compute(block_size, importance)
  → SymbolBudgetEngine.compute_allocation(candidates, params)
  → for each holder:
      encode(source_block, params, start_esi, count, block_id, holder_id)
      → bound symbols (per-holder XOR binding)
      → write to symbols_dir/{hex(block_id)}/{esi}.bin
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
      → read symbol files: {symbols_dir}/{hex(block_id)}/{esi}.bin
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

`RepairAgent` — monitors Lost/PresumedLost placements, regenerates symbols locally.

**Triggers:**
- Periodic scan (every `scan_interval_secs`)
- `RepairTrigger::RepairNow { block_id, holder_id }` — immediate repair
- `RepairTrigger::ScanAll` — full scan

**Pipeline repair_placement:**
```
1. Read SourceBlockRecord from DB → K, T
2. Read SymbolPlacement → esi_ranges, binding_seed, holder_id
3. Read source block file: {symbols_dir}/{hex(block_id)}/block.bin
4. For each ESI in esi_ranges:
     encode(source_data, params, esi, 1, block_id, holder_id)
     → bound symbol → write to {symbols_dir}/{hex(block_id)}/{hex(holder_id)}/{esi}.sym
5. Update placement.status = Alive, consecutive_misses = 0
```

**handle_symbol_dropped / handle_pos_nack:** both do the same thing — `mark_placement_lost` (idempotent: if already Lost/Deleting — no-op).

Repair: local re-encode + network delivery to new holders.

---

### cluster_sync

`ClusterSyncManager` — exchanges the event log between devices in the same cluster.

**Synchronous API** (not async). Callers manage connections.

**Methods:**
- `build_sync_request(peer_identity)` → `ClusterSyncRequestMsg` with cursor
- `process_sync_response(peer_identity, response)` → applies events, updates cursor
- `handle_sync_request(request)` → returns events from the event log, checks membership
- `build_revocation_broadcast(revocation, device_cert)` → payload for relay board

**Cursor persistence:** sync cursors are stored in `ClusterState` (in-memory) and persisted to the `CLUSTER_STATE` redb table via `ClusterState::update_sync_cursor`.

Incoming request validation: `device_id` must be in the cluster and not revoked.

---

### relay

`RelayManager` — epidemic gossip board for deferred messaging.

**Model:** each node maintains an append-only board file. When two peers connect, they exchange board entries. Messages propagate hop=0 → hop=1 → hop=2 and are not relayed further.

**Entry types:**
- `Broadcast` — open payload (PeerAnnounce, RevocationBroadcast)
- `Directed` — encrypted for a specific recipient (ECDH ChaCha20-Poly1305)

**Entry lifecycle:**
```
post_broadcast / post_directed_with_key  → hop=0, write to disk
process_remote_entries (from peer):
  → dedup by msg_id
  → TTL check (RELAY_TTL_SECS = 7 days)
  → hop check (MAX_RELAY_HOP = 2)
  → verify Ed25519 signature
  → relay_copy: hop+1, append
scan_for_self → decrypt directed → inbound_tx channel
prune: TTL + size limits (MAX_BOARD_ENTRIES=2000, MAX_BOARD_SIZE_BYTES=8MB)
```

**Board file:** append-only, periodically rewritten during prune.

**Async run():** listens on `SyncTrigger` (incoming connections), periodic prune timer.

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
5. Spawn BackupCoordinator, RestoreCoordinator, RepairAgent
6. Spawn Scheduler (PoS), RelayManager, ClusterSyncManager
7. Spawn SystemState periodic push (interval = 6h / time_scale, min 60s)
8. Start Watcher (fs-notify) for configured directories
9. Start CliServer (Unix socket)
10. Load peers from DB → known_peers in network
11. Bootstrap discovery: connect to bootstrap peers, PeerDiscoveryRequest (1-hop)

---

### processor

`Processor` — thin message router. Receives incoming connections from network, dispatches messages to appropriate handlers.

**Dispatch table (26 message types):**
- `Handshake` → auth (handled by network accept loop)
- `PeerAnnounce` → upsert peer, add to known_peers, store addrs
- `PosChallenge` → look up holding, re-read symbol, send PosResponse or PosNack
- `PosResponse` → verify, update placement status + trust
- `PosNack` → mark placement Lost, trigger repair
- `SymbolOffer` → check quota → SymbolAccept / SymbolReject
- `SymbolAccept` → update placement to Alive (via BackupEvent channel)
- `SymbolReject` → update placement, log
- `SymbolTransfer` → write symbols to disk, update HoldingRecord
- `SymbolStored` → log confirmation
- `RestoreRequest` → escrow check → read symbols → RestoreResponse or RestoreDenied
- `BoardSync` → relay_sync_tx (forwarded to RelayManager)
- `ClusterSync*` → forwarded to ClusterSyncManager
- `Delete/CancelDelete` → update HoldingRecord status
- `StorageWarning/SymbolDropped/SymbolDropNotice` → log, update placements
- `SystemStateBackup` → store blob (known peers only) → SystemStateAck
- `SystemStateRequest` → return stored blob → SystemStateResponse
- `SystemStateAck/Response` → log / forward to DR
- `PeerDiscoveryRequest` → return peer list (any authenticated connection)
- `PeerDiscoveryResponse` → forward to DR / bootstrap

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

Filters: hidden files (dotfiles), temporary files.
Only detects changes AFTER daemon start — pre-existing files not scanned.

---

### scheduler

`Scheduler` — periodic PoS challenge issuance.

- Computes `due_challenges()` from placements + last_verified timestamps
- Issues PosChallenge via network, stores in `PendingChallenges` (shared with Processor)
- On timeout (7 days): records as Timeout, updates placement status
- Adaptive rate: `challenges/week = base * volume_factor * trust_factor`

---

### cli_server

Unix socket server at `{data_dir}/viaticum.sock`.

**Commands:** status, files, versions, peers, restore, connect, device (add/revoke/list), backup (force flush)

Bridges CLI → DaemonState for reads, CLI → RestoreCoordinator for restores, CLI → NetworkHandle for connections.

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
    PosChallengeMsg { challenge_id, source_block_id, esi } → holder
    │
    holder replies PosResponseMsg { data } or PosNackMsg
    │
    verify_response():
      re-encode(source_block, params, esi, block_id, holder_id)
      expected_bound_data == response.data?
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
RepairAgent.scan_and_repair()
  │
  DB: list_placements_needing_repair()  ← status=Lost/PresumedLost
  │
  for each placement:
    read {symbols_dir}/{hex(block_id)}/block.bin  (source data)
    SourceBlockRecord: K, T
    SymbolPlacement: esi_ranges, holder_id
    │
    for each ESI:
      encode(source_data, params, esi, 1, block_id, holder_id)
      write {symbols_dir}/{hex(block_id)}/{hex(holder_id)}/{esi}.sym
    │
    DB: upsert_placement(status=Alive, consecutive_misses=0)
    │
    [Phase 3] network: send symbols to holder
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
| `escrow_k_factor` | 7.0 | `DEFAULT_ESCROW_K_FACTOR` — GB·days required per 1 GB restore credit |
| `prune_interval_secs` | 3600 | Relay board cleanup interval |

All numeric protocol parameters are defined in `viaticum-core/src/constants.rs`.
