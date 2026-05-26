# Viaticum: Wire Protocol Specification

*2026-03-21. Version β. Authoritative protocol spec.*

*See also: [logic.md](logic.md) for algorithm quick-reference, [overview.md](../overview.md) for end-to-end flows.*

---

## 0. Technology Stack

| Component | Choice | Notes |
|-----------|--------|-------|
| Erasure coding | RaptorQ (RFC 6330), crate `raptorq` | NOT Reed-Solomon |
| Transport | libp2p (TCP + Noise + Yamux, Kademlia DHT, DCUtR) | transport only |
| Gossip / deferred | Epidemic relay (board-based) | NOT pubsub |
| Wire format | CBOR + u32 BE length-prefix | `ciborium` crate |
| ALPN | `"viaticum/1"` | byte string |
| File encryption | ChaCha20-Poly1305 | epoch-keyed |
| Per-holder binding | ChaCha20 XOR stream | anti-collusion |
| Signatures | Ed25519 | identity + device certs |
| ECDH (relay) | X25519 | ephemeral per message |
| KDF | HKDF-SHA256 | domain-separated |
| Hashes | BLAKE3 | content-addressed IDs |

Direct connections + epidemic relay fully cover the needs of cold backup.

---

## 0.1. Message Format

### Framing

Each message = `[u32 BE length][CBOR payload]`.

```
┌──────────────────┬──────────────────────────────────────┐
│  4 bytes (u32 BE)│  N bytes (CBOR)                      │
│  payload length  │  Message enum (CBOR tagged)           │
└──────────────────┴──────────────────────────────────────┘
```

- Maximum frame size: `MAX_MESSAGE_SIZE = 64 MiB`
- CBOR enum tag: `{"type": "snake_case_variant_name", ...fields...}`

### Versioning

- ALPN level: `b"viaticum/1"` — when the protocol version changes, the ALPN string changes
- Message level: field `v: u8` in every message. Current version: `PROTOCOL_VERSION = 1`
- Unknown enum variant: the receiving side logs and ignores it; the connection is not dropped

### Top-level enum

```rust
pub enum Message {
    Handshake(HandshakeMsg),
    PeerAnnounce(PeerAnnounceMsg),
    PosChallenge(PosChallengeMsg),
    PosResponse(PosResponseMsg),
    PosNack(PosNackMsg),
    SymbolOffer(SymbolOfferMsg),
    SymbolAccept(SymbolAcceptMsg),
    SymbolReject(SymbolRejectMsg),
    SymbolStored(SymbolStoredMsg),
    SymbolTransfer(SymbolTransferMsg),
    Delete(DeleteMsg),
    CancelDelete(CancelDeleteMsg),
    StorageWarning(StorageWarningMsg),
    SymbolDropped(SymbolDroppedMsg),
    SymbolDropNotice(SymbolDropNoticeMsg),
    RestoreRequest(RestoreRequestMsg),
    RestoreResponse(RestoreResponseMsg),
    RestoreDenied(RestoreDeniedMsg),
    BoardSync(BoardSyncMsg),
    ClusterSyncRequest(ClusterSyncRequestMsg),
    ClusterSyncResponse(ClusterSyncResponseMsg),
    SystemStateBackup(SystemStateBackupMsg),
    SystemStateAck(SystemStateAckMsg),
    SystemStateRequest(SystemStateRequestMsg),
    SystemStateResponse(SystemStateResponseMsg),
    PeerDiscoveryRequest(PeerDiscoveryRequestMsg),
    PeerDiscoveryResponse(PeerDiscoveryResponseMsg),
    Ack(AckMsg),  // generic ack for request-response streams that expect a reply
}
```

---

## 1. What the Protocol Defines (mandatory behaviour)

This section describes what is verifiable and mandatory for interoperability. Recommended parameter values (non-mandatory) are in section 2.

---

### 1.1. Identity and Devices

#### Key Hierarchy

```
Seed phrase (BIP39, 24 words)
│
├─ Master identity key (Ed25519)
│   HKDF-SHA256(ikm=seed_bytes, salt=b"", info=b"viaticum-identity-ed25519")
│   IdentityPub = master_key.verifying_key()  ←── stable owner ID
│
├─ Device key (Ed25519, per device)
│   HKDF-SHA256(ikm=seed_bytes, salt=device_id.0, info=b"viaticum-device-ed25519")
│   DeviceId = device_key.verifying_key()  ←── transport identity (libp2p PeerId derived from this)
│
└─ Epoch encryption key (ChaCha20, per epoch)
    HKDF-SHA256(ikm=seed_bytes, salt=epoch.0.to_be_bytes(), info=b"viaticum-encryption")
```

- `DeviceId` = Ed25519 pubkey bytes of device signing key (32 bytes) — stable transport ID
- The seed phrase is erased from RAM after key derivation
- A device stores persistently: `device_key`, `epoch_key[current]`, `epoch_key[current-1]`

#### Device certificate

```rust
pub struct DeviceCertificate {
    pub device_id: DeviceId,        // 32 bytes (Ed25519 pubkey of device key)
    pub issued_at: Timestamp,
    pub signature: [u8; 64],        // Ed25519: master_key.sign(payload)
    pub master_pub_key: IdentityPub,
}
// signed payload = device_id.0 (32) || issued_at.0.to_be_bytes() (8)
// device_id.0 IS the device pubkey — no separate device_pub_key field
```

#### Revocation certificate

```rust
pub struct RevocationCertificate {
    pub device_id: DeviceId,
    pub revoked_at: Timestamp,
    pub new_epoch: EpochCounter,
    pub signature: [u8; 64],  // Ed25519: master_key.sign(payload)
    pub master_pub_key: IdentityPub,
}
// signed payload = b"revoke" (6) || device_id.0 (16) || revoked_at.0.to_be_bytes() (8)
//                  || new_epoch.0.to_be_bytes() (4)
```

---

### 1.2. Handshake (connection authentication)

The Viaticum handshake runs on top of the libp2p Noise IX layer. After the Noise handshake, both sides exchange a `DeviceCertExchangeMsg` that binds the libp2p PeerId to an `IdentityPub`.

#### Exchange order

```
Initiator (A)          Acceptor (B)
     │                      │
     │── HandshakeMsg ──────>│   A sends first
     │<─ HandshakeMsg ───────│   B reads, then replies
     │                      │   both verify
```

#### HandshakeMsg

```rust
pub struct HandshakeMsg {
    pub v: u8,                             // PROTOCOL_VERSION = 1
    pub identity_pub: IdentityPub,         // Ed25519 pubkey (32 bytes)
    pub timestamp: Timestamp,             // Unix seconds
    pub sig: [u8; 64],                    // Ed25519 signature
    pub device_cert: Option<DeviceCertificate>,  // only for multi-device
}
// sig covers: b"handshake" || identity_pub.0 (32) || timestamp.0.to_be_bytes() (8)
// device_cert is NOT included in sig (cert is self-signed by master key, verified separately)
```

#### Verification rules

1. `|timestamp - now| <= HANDSHAKE_FRESHNESS_SECS` (300 seconds)
2. Verify the Ed25519 signature `sig` against `identity_pub`
3. If `device_cert` is present:
   - `cert.device_id.0 == handshake.identity_pub.0` (device_id IS the pubkey)
   - Verify `cert.signature` against `cert.master_pub_key`
   - Return `master_pub_key` as the peer's cluster identity
4. If a specific peer is expected: `received.identity_pub == expected_identity`

#### Handshake result

After a successful handshake the node knows:
- `peer_identity: IdentityPub` — who signed the handshake (device key)
- `peer_master_identity: Option<IdentityPub>` — master identity if multi-device

---

### 1.3. Source Blocks and Symbols (NOT units and shards)

#### Terminology

| β (current) | α (deprecated) | What it is |
|-------------|----------------|-----------|
| Source block | Unit | Data for erasure coding |
| Symbol | Shard | One encoded chunk, T bytes |
| ESI (Encoding Symbol ID) | shard_id | Symbol identifier (u32, 0, 1, 2...) |
| K source symbols | k (fixed) | Minimum needed for decode |
| N distributed | n (fixed k-of-n) | How many were distributed |

#### Parameters (from `constants.rs`)

```
T = 65_535 bytes (SYMBOL_SIZE) — symbol size, fixed (u16 limit crate)
DEFAULT_SOURCE_BLOCK_SIZE = 128 MB (configurable via config.toml)
DECODE_OVERHEAD = 3   → K_eff = K + 3
OVERHEAD_BASE = 1.5, OVERHEAD_SCALE = 1.5 → overhead = 1.5 + importance × 1.5
```

#### Formulas

```
K = ceil(source_block_size / T)      // 2048 for a 128 MB block
K_eff = K + 3                        // 2051 for K=2048
overhead = 1.5 + importance × 1.5   // 1.5x (importance=0) .. 3.0x (importance=1)
N = ceil(K_eff × overhead)           // total symbols to distribute
```

#### Source block ID

```
source_block_id = BLAKE3(ciphertext)
```

Content-addressed: the same file on different devices produces the same ciphertext, the same `source_block_id`, and therefore zero-traffic deduplication.

#### Encryption (two layers)

**Layer 1 — file encryption:**
```
file_key = HKDF-SHA256(epoch_key, content_hash || b"viaticum-file-encryption")
ciphertext = ChaCha20-Poly1305_encrypt(key=file_key, plaintext=compressed_data)
```

**Layer 2 — per-holder binding (anti-collusion):**
```
binding_key = HKDF-SHA256(source_block_id || holder_id, b"viaticum-binding")
stored_symbol = symbol XOR ChaCha20_stream(binding_key)
```

Per-holder binding is mandatory. Without it, K colluding holders can store a single copy and regenerate on demand — redundancy becomes an illusion.

Restore: the owner knows `holder_id` → XOR back → clean symbol → RaptorQ decode.

#### Grouping files into source blocks

```
< 128 MB  → batch multiple files into one source block (by file category)
≥ 128 MB  → one file is split into chunks of source_block_size
```

Categories: Photo, Document, Video, Other. Files of the same category are batched together.

The pack index is stored in `SourceBlockType::Pack { entries: Vec<PackEntry> }` where `PackEntry = { file_id, offset, size }`.

---

### 1.4. PoS (Proof of Storage)

PoS is the mechanism for verifying that a holder is actually storing the assigned symbols.

#### Messages

**PosChallengeMsg** (Owner → Holder):
```rust
pub struct PosChallengeMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],    // random nonce for response matching
    pub source_block_id: SourceBlockId,
    pub esi: u32,                   // specific ESI to verify
    pub timestamp: Timestamp,
}
```

**PosResponseMsg** (Holder → Owner):
```rust
pub struct PosResponseMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],
    pub esi: u32,
    pub data: Vec<u8>,              // BOUND symbol, exactly T bytes (65_535)
    pub timestamp: Timestamp,
}
```

**PosNackMsg** (Holder → Owner):
```rust
pub struct PosNackMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],
    pub source_block_id: SourceBlockId,
    pub esi: u32,
    pub timestamp: Timestamp,
}
```

`PosNack` means: "I am not storing this symbol" (evicted under disk pressure, or never received). A holder must send `PosNack` instead of staying silent if it knows it does not hold the symbol.

#### Verification (Owner)

```
Received PosResponse { esi, data }:
  1. Confirm that the source block file exists on disk
  2. Recompute RaptorQ symbol(esi) from the source block
  3. Compute binding: XOR ChaCha20(HKDF(source_block_id, holder_id))
  4. bound_expected = symbol XOR binding_stream
  5. Compare data == bound_expected byte-for-byte

Symbol hashes are NOT stored in the DB — verification is done on the fly.
```

#### VerifyOutcome and response

| Outcome | Condition | Action |
|---------|-----------|--------|
| `Pass` | data matches | trust P +1, all good |
| `NotHeld` | PosNack received | do NOT penalise trust, immediate repair (holder is honest) |
| `Fail` | data does not match | trust P −1, immediate repair (corruption or fraud) |
| `Timeout` | no response within 7 days | trust P −1, graduated response (see below) |

Penalising for NotHeld is wrong — it would reduce the incentive for holders to report honestly when they do not have a symbol.

#### Graduated response on Timeout (PlacementStatus)

```
Alive
  │ 1st miss (Timeout)
  ↓
Uncertain    ← consecutive_misses = 1, 2
  │ 3+ misses
  ↓
PresumedLost ← triggers repair
  │ repair complete
  ↓
Alive (new holder)

Separate path (Pass/Fail/NotHeld):
Alive/Uncertain → Lost (immediately) → triggers repair
```

Constants: `POS_CONSECUTIVE_MISS_UNCERTAIN = 1`, `POS_CONSECUTIVE_MISS_PRESUMED_LOST = 3`.

Rationale: Timeout = uncertainty (the peer may be on holiday; for cold backup, 1–2 weeks offline is normal). NotHeld/Fail = certainty → react immediately.

#### Adaptive frequency

```
challenges_per_week = POS_BASE_CHALLENGES_PER_WEEK
                      × ceil(holder_symbols / POS_VOLUME_DIVISOR)
                      × (2.0 - trust)

POS_BASE_CHALLENGES_PER_WEEK = 1
POS_VOLUME_DIVISOR = 1000
```

A holder with more symbols is challenged more often. A holder with lower trust is challenged more often.

#### Timeout

`POS_TIMEOUT_SECS = 7 × 24 × 3600` (7 days). Uniform for all cases. Covers:
- Direct connections (peer temporarily offline)
- Cluster forwarding (challenge arrived at device A, symbols are on device B)

#### Challenge delivery (relay fallback)

When sending a PoS challenge the scheduler chooses a path:

1. **Direct RR**: if the holder is online (an authenticated connection exists), send via `send_to_device` (libp2p request-response). The owner waits for a response within a short timeout.

2. **Relay board fallback**: if the holder is offline (no live connection or `send_to_device` returns `PeerNotAuthenticated`), the challenge is placed on the local relay board as a directed message (encrypted via ECDH with the holder's `x25519_pub`). Delivery guarantee: best-effort epidemic propagation within `RELAY_TTL_SECS = 7 days`.

3. **No retry fallback**: if the relay board is full (`MAX_BOARD_ENTRIES`) or the TTL expired before delivery, the challenge is marked Pending. The next scheduler tick tries again.

Note: `idle_connection_timeout = 600s` in libp2p means that in normal operation peer-to-peer connections are **ephemeral** — peers do not maintain persistent connections. For cold backup, most challenges go through the relay board (offline holders dominate), and this is by design.

When a peer comes back online after a long absence (>7 days), all challenges from that period are treated as Lost (3+ Timeouts) → repair triggered. This is the correct behaviour for a cold backup system with a time constant of 1 week.

#### PoS limitations

- PoS is not run for source blocks in `Deleting` or `Deleted` status
- If a file has been deleted locally and its block is in cooldown, PoS stops
- Bandwidth overhead: `T × 15 holders = ~1 MB/week` — negligible

---

### 1.5. Epidemic Relay (gossip board)

The epidemic relay is the mechanism for delivering messages when a direct connection is not possible (peer offline).

#### How it works

```
Sender: publishes an entry to the relay board (append-only file)
  → hop=0

On sync with a partner:
  → BoardSync: exchange entries the partner does not have
  → partner stores entries with hop+1

hop=0 → hop=1 → hop=2 → DROP (MAX_RELAY_HOP = 2)
```

With 2 hops and 15 partners: coverage reaches ~100 nodes within a few days.

#### Entry types

```rust
pub enum BoardEntryKind { Broadcast, Directed }

pub struct BoardEntry {
    pub kind: BoardEntryKind,
    pub target_pub: Option<IdentityPub>,  // only for directed
    pub payload: Vec<u8>,                  // CBOR (broadcast) or encrypted (directed)
    pub sig_author: [u8; 64],             // Ed25519, signed by original author
    pub author: IdentityPub,
    pub hop: u8,                           // 0..MAX_RELAY_HOP
    pub created_at: Timestamp,            // for TTL
}
```

Relay nodes do NOT re-sign entries. `sig_author` is the original author's signature and remains unchanged.

#### TTL and limits

- `RELAY_TTL_SECS = 7 × 24 × 3600` (7 days)
- `MAX_RELAY_HOP = 2`
- `MAX_BOARD_ENTRIES = 2000`
- `MAX_BOARD_SIZE_BYTES = 8 MiB`

Entries older than the TTL are removed during periodic cleanup.

#### Directed messages

Messages addressed to a specific recipient are encrypted via ephemeral ECDH:

```rust
pub struct DirectedEnvelope {
    pub sender_x25519_pub: [u8; 32],   // ephemeral public key
    pub nonce: [u8; 12],               // ChaCha20-Poly1305 nonce
    pub ciphertext: Vec<u8>,           // encrypted CBOR payload
}
// KDF: HKDF-SHA256(ikm=ECDH_shared, salt=sender_pub||receiver_pub,
//                  info=b"viaticum-directed")
```

An ephemeral key is generated fresh for every message (forward secrecy).

#### Board entry signature

```
sig_input = msg_type_bytes || msg_id (16) || kind_str || target_pub_or_empty || payload
sig_author = author_signing_key.sign(sig_input)
```

#### BoardSync message

```rust
pub struct BoardSyncMsg {
    pub v: u8,
    pub entries: Vec<StoredEntry>,   // entries the partner does not have
    pub timestamp: Timestamp,
}

pub struct StoredEntry {
    pub msg_type: String,    // "peer_announce", "pos_challenge", etc.
    pub msg_id: [u8; 16],
    pub entry: BoardEntry,
}
```

`BoardSync` is sent as the first message after the handshake. Older nodes that do not recognise this variant log and ignore it (the connection is not dropped).

#### Relay usage

| Purpose | Entry type |
|---------|------------|
| PeerAnnounce (discovery) | broadcast |
| PoS challenge (peer offline) | directed |
| DeviceRevocation | broadcast (`RevocationBroadcast`) |
| ClusterSync events | via direct connection (not relay) |

---

### 1.6. Symbol Placement

#### Holder weights

```
weight_i = trust_i / sqrt(1 - trust_i)    // mean-variance optimum
share_i  = weight_i / sum(all_weights)
```

Not `trust²` — that concentrates too aggressively. `t/sqrt(1-t)` is the optimum in a mean-variance model that accounts for risk.

#### Constraints

```
max_share = (1 - 1/overhead) × CONCENTRATION_CAP_FACTOR    // 0.85
max_per_holder = min(K_eff - 1, floor(max_share × N))

MAX_HOLDERS_PER_BLOCK = 30   // > 30 = linear growth in restore/PoS overhead
MIN_SYMBOLS_PER_HOLDER = 32  // < 32 = 2 MB, accounting overhead not justified
```

`K_eff - 1` is a hard ceiling: holding more than that makes no sense (one holder would own the entire file).

#### Distribution algorithm

```
1. weight_i = trust_i / sqrt(1 - trust_i)
2. share_i  = weight_i / sum(all_weights)
3. symbols_i = clamp(round(N × share_i), 1, max_per_holder)
4. Redistribute remainder from capped holders → uncapped
5. Remove holders with symbols_i < MIN_SYMBOLS_PER_HOLDER
   → redistribute their symbols proportionally
6. For m ≤ 10 and N ≤ 100: exact DP (guaranteed optimum)
```

#### ESI namespace (multi-device)

```
device_index 0: ESI [0,          1_048_576)   (2^20)
device_index 1: ESI [1_048_576,  2_097_152)
...
device_index 15: ESI [15_728_640, 16_777_216)  (max ESI in RaptorQ = 2^24)
```

`ESI = device_index × 2^20 + local_counter`. Devices generate symbols without real-time coordination.

#### Rebalancing

Rebalancing = adding new symbols only (new ESIs), never moving existing ones.

```
Trust dropped for holder A:
  Do NOT remove symbols (they are still valid)
  Generate new symbols → place them with more reliable holders
  total_alive_symbols grows → reliability grows

Holder B gone (PoS fails):
  Status → Lost
  Repair: generate new ESIs → place at another holder
```

---

### 1.7. Symbol Lifecycle Messages

#### Backup flow

```
Owner                          Holder
  │── SymbolOffer ────────────>│   offer: source_block_id, esi_ranges, importance
  │<─ SymbolAccept ────────────│   or SymbolReject (quota_full, etc.)
  │── SymbolTransfer (×N) ────>│   push symbols in batches
  │<─ SymbolStored ────────────│   acknowledgement of receipt
```

**SymbolOfferMsg**:
```rust
pub struct SymbolOfferMsg {
    pub v: u8,
    pub msg_id: [u8; 16],
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,   // (start_esi, count)
    pub importance: f64,
    pub timestamp: Timestamp,
    pub sig: [u8; 64],   // Ed25519 owner_key.sign(source_block_id || esi_ranges_cbor
                         //                         || importance_be_f64 || timestamp)
}
```

**RejectReason**:
```rust
pub enum RejectReason {
    QuotaFull, LowPriority, UnknownOwner, HashMismatch, Other,
}
```

**SymbolTransferMsg** (used for both backup push and restore response):
```rust
pub struct SymbolTransferMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub symbols: Vec<Symbol>,   // bound symbols
    pub timestamp: Timestamp,
}
```

#### Restore flow

```
Owner                          Holder
  │── RestoreRequest ─────────>│   esi_list: [] = "any K_eff from your set"
  │<─ RestoreResponse ──────────│   bound symbols
  │   (or RestoreDenied)
```

**RestoreRequestMsg**:
```rust
pub struct RestoreRequestMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi_list: Vec<u32>,    // empty = "any K_eff"
    pub timestamp: Timestamp,
}
```

**RestoreDeniedMsg** (escrow check failed):
```rust
pub struct RestoreDeniedMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub reason: String,
    pub required_weeks: u32,   // DEPRECATED — kept for compatibility
    pub current_weeks: u32,    // DEPRECATED — kept for compatibility
    pub timestamp: Timestamp,
}
// In β escrow is trust-based. required_weeks/current_weeks are not used in logic.
```

#### Symbol deletion

Double cooldown — ransomware protection:

```
Owner:
  local file Deleted → wait OWNER_DELETE_COOLDOWN_SECS (4 weeks)
  → Send DeleteMsg
  → (optionally) CancelDeleteMsg while cooldown has not expired

Holder:
  DeleteMsg received → wait HOLDER_DELETE_COOLDOWN_SECS (4 weeks)
  → physical deletion of symbols
```

Total cooldown: 4 + 4 = 8 weeks.

**DeleteMsg / CancelDeleteMsg**:
```rust
pub struct DeleteMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub timestamp: Timestamp,
    pub sig: [u8; 64],   // Ed25519 owner_key.sign(source_block_id || timestamp)
}
```

#### Eviction (disk pressure)

```
Holder → Owner: SymbolDropNotice (advance warning, deadline)
  deadline DROP_NOTICE_WINDOW_SECS (7 days) before the drop

Holder → Owner: SymbolDropped (eviction confirmed)
  → owner: PlacementStatus → Lost → trigger repair
```

**SymbolDropNoticeMsg**:
```rust
pub struct SymbolDropNoticeMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,
    pub deadline: Timestamp,   // when the drop will occur
    pub timestamp: Timestamp,
}
```

#### StorageWarning

Owner notifies holder of bitrot (PoS Fail):
```rust
pub struct StorageWarningMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi: u32,
    pub details: String,
    pub timestamp: Timestamp,
}
```

---

### 1.8. Escrow (contribution-based)

Escrow controls access to restore. The goal is to block hit-and-run behaviour (take symbols, contribute nothing back) and incentivise mutual contribution.

#### Formula

```
restore_budget_gb = stored_gb_days / k_factor

k_factor = DEFAULT_ESCROW_K_FACTOR = 7.0  // storage days per 1 GB of restore
```

Example: store 1 GB for 7 days → earn 1 GB restore budget.

`stored_gb_days` is calculated as the sum of `bytes_we_store_for_peer × days_held` across all holding records for a peer.

#### Check

The holder verifies before sending symbols for restore:
```
total_bytes_in_request <= restore_budget_gb × 1024³
```

If the check fails, the holder sends `RestoreDeniedMsg`.

The time-based escrow (weeks_in_network) from α has been removed. Trust already contains a temporal component (I = cumulative mean).

---

### 1.9. Personal Cluster

A Personal Cluster is several devices belonging to the same owner acting as a single identity.

#### What the cluster provides

- A single `IdentityPub` (master key) for all devices
- Continuous reputation: partners do not notice a device change
- Deduplication: one file on N devices → one copy in the network
- Device revocation on theft
- ESI namespace without real-time coordination

#### Multi-device handshake

A cluster device includes `device_cert` in the handshake:
```
HandshakeMsg.identity_pub = DeviceId.0          (device pubkey bytes = device identity)
HandshakeMsg.device_cert  = DeviceCertificate   (master_key.sign(device_id.0 || issued_at))
```

Upon receiving such a handshake, the partner extracts `master_pub_key` from `device_cert` as the cluster identity. All subsequent trust/escrow operations use `master_pub_key`.

#### Device registration

```
1. New device enters seed phrase → derive device_key
2. device_id = DeviceId(device_key.verifying_key().to_bytes())  // 32 bytes Ed25519 pubkey
3. Create DeviceCertificate = master_key.sign(device_id.0 || issued_at)
4. Publish cert via relay board → partners accept the device as part of the identity
5. Seed is erased from RAM
6. Sync state (file catalog, placements) via ClusterSync
```

Device limit: 16 (`MAX_DEVICES = 16`). Determined by the ESI namespace: `ESI space = 2^24`, `2^20 per device`.

#### Device revocation

```
1. viaticum device revoke <device_id>
2. Create RevocationCertificate = master_key.sign(b"revoke" || device_id || revoked_at || new_epoch)
3. epoch_counter += 1, new epoch_key
4. Publish via relay board: RevocationBroadcast { revocation_cert, device_cert }
5. Partners: add device to revoked list, deny restore/PoS for revoked device key
6. Owner: gradually re-encrypt old files with the new epoch
```

**RevocationBroadcast** (broadcast relay entry):
```rust
pub struct RevocationBroadcast {
    pub revocation: RevocationCertificate,
    pub device_cert: DeviceCertificate,
}
```

Revocation delivery is eventual consistency via gossip (hop≤2, TTL 7 days). Threat model: "lazy not malicious" — a thief is unlikely to actively interfere.

#### ClusterSync

State synchronisation between devices via event log:

```rust
// Device A → Device B:
pub struct ClusterSyncRequestMsg {
    pub v: u8,
    pub from_device_id: DeviceId,
    pub last_known_seq: u64,   // "give me events after this seq"
    pub timestamp: Timestamp,
}

// Device B → Device A:
pub struct ClusterSyncResponseMsg {
    pub v: u8,
    pub events: Vec<(u64, EventEntry)>,   // (seq, event)
    pub responder_last_seq: u64,
    pub timestamp: Timestamp,
}
```

Event log is commutative by design — order does not matter for the final state.

#### Event log types

```rust
pub enum Event {
    SymbolsPlaced { source_block_id, holder_id, esi_range },
    SymbolsLost   { source_block_id, holder_id },
    SymbolsVerified { source_block_id, holder_id },
    FileAdded     { file_id, path },
    FileModified  { file_id, content_hash },
    FileDeleted   { file_id, device_id },
    DeviceAdded   { device_id },
    DeviceRevoked { device_id },
    EpochRotated  { epoch },
}
```

#### Deduplication

Content-addressed dedup is automatic:
```
file_key = HKDF(epoch_key, content_hash, ...)
ciphertext = ChaCha20-Poly1305(file_key, plaintext)
source_block_id = BLAKE3(ciphertext)
```

The same file on two devices → same `content_hash` → same key → same `ciphertext` → same `source_block_id` → symbols already in the network → zero extra traffic.

#### Peer-to-device affinity

```
Device A (online in the evenings): manages peers {P1, P3, P5}
Device B (NAS, always-on):         manages peers {P2, P4, P6}
```

Blast radius isolation: device A offline → only relationships with P1, P3, P5 are affected. The overall trust identity is the average.

S-score: per (device, peer) pair — the protocol has no knowledge of clusters. An external peer sees a device as an ordinary node.

---

### 1.10. System State Backup and Peer Discovery (δ.1)

#### SystemState backup

Periodic push of an encrypted DB snapshot to all peers. One blob per owner, overwritten on each push.

```rust
// Owner → Holder. Push encrypted DB snapshot.
pub struct SystemStateBackupMsg { pub v: u8, pub encrypted_blob: Vec<u8>, pub timestamp: Timestamp }

// Holder → Owner. Acknowledge storage.
pub struct SystemStateAckMsg { pub v: u8, pub stored: bool, pub timestamp: Timestamp }

// Requester → Holder. Request stored blob (identity from handshake).
pub struct SystemStateRequestMsg { pub v: u8, pub timestamp: Timestamp }

// Holder → Requester. Return blob (empty vec = not found).
pub struct SystemStateResponseMsg { pub v: u8, pub encrypted_blob: Vec<u8>, pub timestamp: Timestamp }
```

**Encryption:** HKDF-SHA256(ikm=seed, salt=random_24, info=b"viaticum-system-state") → ChaCha20-Poly1305. Wire format: `[salt(24)][nonce(12)][ciphertext+tag]`.

**Serialization:** SystemState → CBOR → zstd compress → encrypt.

**Security:**
- `SystemStateBackup` — accepted only from **known peers** (prevents storage spam)
- `SystemStateRequest/Response` — responds to anyone (blob is encrypted, useless without the owner's key)
- TTL = 365 days, expired blobs are auto-deleted on read

**Table:** `system_state_blobs` — key: `[u8; 32]` (owner identity_pub), value: CBOR(`SystemStateBlobRecord`).

#### Peer Discovery

BFS discovery for DR and initial peer bootstrap.

```rust
// Requester → Peer. "Give me your peer list."
pub struct PeerDiscoveryRequestMsg { pub v: u8, pub timestamp: Timestamp }

// Peer → Requester. List of known peers.
pub struct PeerDiscoveryResponseMsg {
    pub v: u8,
    pub peers: Vec<DiscoveredPeer>,
    pub timestamp: Timestamp,
}

pub struct DiscoveredPeer {
    pub identity_pub: IdentityPub,
    pub addrs: Vec<String>,  // multiaddrs
}
```

**Security:** `PeerDiscoveryRequest` — answered by **any authenticated connection** (handshake is sufficient). The peer list is not a secret in a P2P network. Works for both DR (old peer) and first bootstrap (new node).

---

## 2. What the Protocol Does NOT Define (implementation recommendations)

The following parameters are recommended values, not interoperability requirements.

| Parameter | Recommendation | Rationale |
|-----------|---------------|-----------|
| Trust formula | `(KP×P + KI×I) × clamp(S, 0.1, 1.0)` | Experiments exp.01-27 |
| KP, KI | `KP=0.4, KI=1.75` | Balance between reactivity and stability |
| Overhead | `1.5 + importance × 1.5` | 99.9% reliability at K=2048 |
| PoS frequency | adaptive (see 1.4) | Proportional to volume and trust |
| Partner selection | weighted by trust | Bias towards reliable peers |
| Holder eviction priority | `importance × trust × (1 + age_bonus)` | Preserve important and long-held symbols |
| Source block size | 128 MB | Peak RAM ~250 MB |
| Block size (weak hw) | 32 MB | Peak RAM ~65 MB |
| Vacuum threshold | >50% invalid files | `VACUUM_INVALID_THRESHOLD = 0.5` |
| Max file versions | 5 | `DEFAULT_MAX_VERSIONS = 5` |
| Max version age | 90 days | `DEFAULT_MAX_VERSION_AGE_SECS` |
| Disk reserve | 20 GB | `DEFAULT_DISK_RESERVE_BYTES` |

---

## 3. Lifecycle

### 3.1. Bootstrap (first run)

```
1. User enters seed phrase (24 BIP39 words)
2. derive_master_key(seed) → master signing key
3. derive_device_key(seed, device_seed) → device signing key → save
4. device_id = DeviceId(device_signing_key.verifying_key().to_bytes())  // 32 bytes Ed25519 pubkey
5. derive_epoch_key(seed, epoch=0) → epoch_key[0] → save
6. Erase seed phrase from RAM
7. issue_device_certificate(master_key, device_id, now) → save cert
8. ClusterState::init(db, master_pub, first_device_cert, ...)
9. PeerAnnounce via relay board: "I exist, my NodeId = ..."
10. Bootstrap auto-connect: connect to bootstrap peers → PeerDiscoveryRequest → learn peer list (1-hop)
```

### 3.2. Normal Operation

```
Watcher: fs event → debounce 30 min → dirty_files

Packing queue (per file category):
  Flush if: ≥ 256 MB accumulated
         OR 1 hour idle
         OR 24 hours fallback
  Min batch: 1 MB

Backup flow (per source block):
  1. Dedup check: content_hash already backed up? → skip
  2. compress (zstd) + encrypt (ChaCha20-Poly1305 with epoch_key)
  3. source_block_id = BLAKE3(ciphertext)
  4. ErasureParams::compute(block_size, importance) → K, K_eff, N
  5. SymbolBudgetEngine: distribute N symbols among holders
  6. Per holder: generate symbols, apply per-holder binding, send via SymbolOffer/Transfer
  7. SymbolStored received → PlacementStatus → Alive

PoS: adaptive scheduler
  picks random ESI from holder's esi_ranges
  → PosChallengeMsg (direct or via relay)
  → verify PosResponse, update trust + PlacementStatus

Repair (triggered by PresumedLost / Lost):
  File on disk → generate new symbols (new ESIs) → place at new holder
  File not on disk → collect K_eff symbols → unbind → decode → new symbols
```

### 3.3. Restore

```
viaticum restore <path> [--version N] [--date YYYY-MM-DD]

1. DB lookup: path → FileRecord → FileVersion
2. FileVersion → source_block_id
3. Dedup: multiple files in same batch → single download
4. Per source_block:
   a. Find holders: SymbolPlacement WHERE status=Alive
   b. Escrow check: `remaining = stored_gb_days/k_factor - already_restored_gb` sufficient?
   c. RestoreRequest to K_eff holders in parallel
   d. Collect K_eff bound symbols (any ESI)
   e. Unbind: XOR ChaCha20(HKDF(block_id, holder_id))
   f. RaptorQ decode → ciphertext
   g. decrypt (epoch_key) → decompress → plaintext
5. Pack → PackIndex → extract files by offset+size
6. Write to disk, FileRecord.local_state → Present
```

Version selection:
- `--version N`: specific (0 = oldest, -1 or default = latest)
- `--date D`: nearest version ≤ D

### 3.4. Disaster Recovery

```
All devices lost, only the seed phrase remains:

viaticum dr --mnemonic "24 words" --peer <addr>

1. Derive identity from seed → IdentityPub
2. Open fresh DB (remove stale db.redb if any)
3. Start minimal SwarmHandle (libp2p, no Processor)
4. BFS over peers:
   - Connect to seed --peer addresses
   - Send SystemStateRequest → collect encrypted DB snapshots
   - Send PeerDiscoveryRequest → discover more peers (visited set)
   - Limits: 500 peers, 10 blobs, 120s timeout
5. Select freshest blob (max created_at)
6. Decrypt (ChaCha20-Poly1305 with HKDF-derived key from seed)
7. Restore DB: files, source blocks, placements, peers, pos_weekly, cluster_state
8. "Run viaticum daemon, then viaticum restore <path>"

DB snapshots pushed periodically (6h) by daemon → SystemStateBackup → peers store one blob per owner (TTL 365 days).
```

### 3.5. File Deletion

```
Watcher: file deleted → FileRecord.local_state = Deleted(timestamp)

The backup catalog is independent of the filesystem.
File deleted from disk ≠ backup deleted.

Cleanup:
  owner 4-week cooldown → DeleteMsg → holders
  holders 4-week cooldown → physical deletion

Multi-device: cooldown starts only when ALL devices have marked the file Deleted.
```

---

## 4. Attack Resistance

### 4.1. Collusion Attack (K holders store 1 copy)

**Attack:** K colluding holders together store one copy of a file and pass PoS by regenerating on demand.

**Defence:** Per-holder binding is mandatory.

```
stored_symbol[holder_A] = symbol XOR ChaCha20(HKDF(block_id, holder_A))
stored_symbol[holder_B] = symbol XOR ChaCha20(HKDF(block_id, holder_B))
```

Symbols at A and B differ → deduplication is impossible. Each holder must store a unique version.

### 4.2. Hit-and-run (take symbols, contribute nothing)

**Attack:** a peer accepts symbols for storage (S-score grows) but stores nothing for others.

**Defence:** Escrow (trust-based).

- Trust = 0 → max 1 GB restore
- No mutual storage → S-score → 0 → trust → 0 → escrow → empty

### 4.3. Lazy Deletion (ransomware)

**Attack:** the owner is compromised, an attacker deletes all files.

**Defence:** Double cooldown of 4+4 weeks.

- Owner side: `OWNER_DELETE_COOLDOWN_SECS = 4 × SECS_PER_WEEK`
- Holder side: `HOLDER_DELETE_COOLDOWN_SECS = 4 × SECS_PER_WEEK`

Within 8 weeks the owner should notice the deletion and cancel it via `CancelDeleteMsg`.

### 4.4. Sybil Attack (many fake nodes)

**Partial defence:**

- Trust requires real storage (S-score) — a Sybil node without disk has trust ≈ 0
- Placement: `weight = trust / sqrt(1-trust)` — zero trust = zero weight
- Soft geo-hint (not in β): reduce weight of homogeneous subnet clusters

No complete defence: VPN/VPS can simulate geographic diversity. Acceptable for cold backup.

### 4.5. Replay Attack (old messages)

- Handshake: `HANDSHAKE_FRESHNESS_SECS = 300`
- PoS: `challenge_id = [u8; 16]` — random nonce, response matched by challenge_id
- Relay entries: `created_at + TTL <= now → expired`

### 4.6. Device Theft

- Revoke device key → partners receive `RevocationBroadcast` via gossip
- New epoch → new files are encrypted with a key the stolen device does not have
- Old files: partners block restore for the revoked device key
- Owner gradually re-encrypts old files

Threat model: "lazy not malicious". For an active adversary (with `epoch_key` compromised before rotation), re-encryption must happen immediately.

---

## Appendix A: Constants Reference

| Constant | Value | Description |
|----------|-------|-------------|
| `SYMBOL_SIZE` (T) | 65_535 bytes | Symbol size (u16 max) |
| `DEFAULT_SOURCE_BLOCK_SIZE` | 128 MB | Default source block size |
| `DECODE_OVERHEAD` | 3 | K_eff = K + 3 |
| `OVERHEAD_BASE` | 1.5 | Minimum overhead (importance=0) |
| `OVERHEAD_SCALE` | 1.5 | Range: 1.5x..3.0x |
| `MAX_HOLDERS_PER_BLOCK` | 30 | Holders per source block |
| `MIN_SYMBOLS_PER_HOLDER` | 32 | Minimum symbols per holder |
| `CONCENTRATION_CAP_FACTOR` | 0.85 | cap = (1-1/overhead) × 0.85 |
| `POS_TIMEOUT_SECS` | 604_800 (7 days) | PoS timeout |
| `POS_BASE_CHALLENGES_PER_WEEK` | 1 | Base PoS frequency |
| `POS_VOLUME_DIVISOR` | 1000 | volume_factor = ceil(symbols/1000) |
| `POS_CONSECUTIVE_MISS_UNCERTAIN` | 1 | Misses until Uncertain |
| `POS_CONSECUTIVE_MISS_PRESUMED_LOST` | 3 | Misses until PresumedLost |
| `OWNER_DELETE_COOLDOWN_SECS` | 2_419_200 (4 wk) | Owner cooldown before delete |
| `HOLDER_DELETE_COOLDOWN_SECS` | 2_419_200 (4 wk) | Holder cooldown after delete |
| `DROP_NOTICE_WINDOW_SECS` | 604_800 (7 days) | Advance notice before drop |
| `DEFAULT_ESCROW_K_FACTOR` | 7.0 | Storage days per 1 GB restore |
| `MAX_RELAY_HOP` | 2 | Maximum relay hops |
| `RELAY_TTL_SECS` | 604_800 (7 days) | Relay entry TTL |
| `MAX_BOARD_ENTRIES` | 2000 | Entries on relay board |
| `MAX_BOARD_SIZE_BYTES` | 8 MB | Relay board size |
| `MAX_MESSAGE_SIZE` | 128 MB | Maximum frame size |
| `PROTOCOL_VERSION` | 1 | Protocol version |
| `ALPN` | `b"viaticum/1"` | ALPN identifier |
| `SYSTEM_STATE_TTL_SECS` | 31_536_000 (365 days) | TTL for stored system state blobs |
| `HANDSHAKE_FRESHNESS_SECS` | 300 | Handshake freshness window (±5 min) |
| `KP` | 0.4 | Weight of P in trust formula |
| `KI` | 1.75 | Weight of I in trust formula |
| `S_CLAMP_MIN` | 0.1 | Minimum S in trust formula |
| `S_CLAMP_MAX` | 1.0 | Maximum S |
| `DEBOUNCE_SECS` | 1_800 (30 min) | Debounce fs events |
| `FLUSH_IDLE_SECS` | 3_600 (1 hour) | Flush on idle |
| `FLUSH_FALLBACK_SECS` | 86_400 (24 hours) | Fallback flush |
| `MIN_BATCH_BYTES` | 1 MB | Minimum batch size |
| `DEFAULT_MAX_VERSIONS` | 5 | Versions per file |
| `DEFAULT_MAX_VERSION_AGE_SECS` | 7_776_000 (90 days) | Age limit for old versions |
| `VACUUM_INVALID_THRESHOLD` | 0.5 (50%) | Vacuum threshold |
| `DEFAULT_DISK_RESERVE_BYTES` | 20 GB | Disk reserve |

---

## Appendix B: DB Schema (summary)

```
HOT (RAM, ~13 MB for 5 TB):
  source_block_id → BlockAgg { k, total_alive_symbols }
  (source_block_id, holder_id) → PlacementAgg { symbol_count, status, last_pos }

WARM (redb):
  FileRecord    { file_id, path, importance, devices, versions, first_seen }
  FileVersion   { content_hash, source_block_id, k, t, created_at, backed_up_at }
  SourceBlockRecord { block_id, k, t, block_type, status, created_at, encrypted_size }
  SymbolPlacement   { source_block_id, holder_id, file_id, esi_ranges,
                      binding_seed, status, last_verified, placed_at, consecutive_misses }
  HoldingRecord { source_block_id, owner_id, esi_ranges, importance, total_bytes,
                  status, received_at, delete_requested_at, drop_notice_sent_at }
  PeerRecord    { identity, trust_p, trust_i, trust_s,
                  bytes_we_store_for_peer, bytes_peer_stores_for_us,
                  first_seen, last_seen, device_id, revoked_device_pub_keys, addrs, x25519_pub }
  BudgetRecord  { estimated_gb, last_calculated, placement_success_rate, weekly_stats }
  EventLog (append-only): Vec<(seq: u64, EventEntry)>
  Indices: file→holders, holder→files (double index)
  ClusterState (singleton): StoredClusterState
  SystemStateBlobRecord { owner, encrypted_blob, created_at, stored_at } — 1 per owner, TTL 365d
```

Values = CBOR (`ciborium`). DB = `Arc<redb::Database>`.

Advantage vs α: ~3.4 MB per 1000 files vs ~50 MB (15x smaller). Fungible symbols → aggregates instead of per-symbol records.

---

## Appendix C: Differences Between β and α

| | α (archive) | β (current) |
|--|-------------|-------------|
| Erasure | Reed-Solomon | RaptorQ (RFC 6330) |
| Storage unit | Shard (fixed index) | Symbol (fungible, ESI) |
| Encoding unit | Unit (32 MB) | Source block (128 MB default, configurable) |
| Placement | k-of-n fixed | Weighted budget (trust/sqrt(1-t)) |
| Overhead | Fixed k/n | Continuous: 1.5 + importance × 1.5 |
| Escrow | Time-based (weeks_in_network) | Trust-based (FREE_TIER + trust × factor) |
| DB metadata | ~50 MB/1000 files | ~3.4 MB/1000 files (15x smaller) |
| Multi-device | None | Personal Cluster, device certs |
| PoS | Stub | Real (64 KB response + on-the-fly verify) |
| PoS not held | Silence | PosNack (explicit response) |
| Repair | Basic | Graduated (Uncertain→PresumedLost), NotHeld→immediate |
| Relay | None | Epidemic relay (hop≤2, TTL 7d) |
| Dedup | None | Content-addressed (same hash → zero traffic) |
| Backup trigger | Weekly | Event-driven + flush conditions |
| File versioning | None | Vec\<FileVersion\>, restore by version/date |
