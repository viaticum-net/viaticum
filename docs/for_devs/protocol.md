# Viaticum: Wire Protocol Specification

*2026-03-21. Version β. Authoritative protocol spec.*

*See also: [logic.md](logic.md) for algorithm quick-reference, [overview.md](../overview.md) for end-to-end flows.*

---

## 0. Technology Stack

| Component | Choice | Notes |
|-----------|--------|-------|
| Erasure coding | RaptorQ (RFC 6330), crate `raptorq` | NOT Reed-Solomon |
| Transport | libp2p (TCP + Noise + Yamux, Kademlia DHT, DCUtR) | transport only |
| Store-and-forward | Directed mailbox bus | NOT gossip/pubsub |
| Wire format | CBOR + u32 BE length-prefix | `ciborium` crate |
| ALPN | `"viaticum/1"` | byte string |
| libp2p protocols | `/viaticum/1` (messages), `/viaticum/cert/1` (handshake), `/viaticum/kad/1.0.0` (DHT) | own Kademlia, not IPFS's `/ipfs/kad/1.0.0` (ADR-003) |
| File encryption | ChaCha20-Poly1305 | epoch-keyed |
| Per-holder binding | ChaCha20 XOR stream | anti-collusion |
| Signatures | Ed25519 | identity + device certs |
| KDF | HKDF-SHA256 | domain-separated |
| Hashes | BLAKE3 | content-addressed IDs |

Direct connections + a directed mailbox bus fully cover the needs of cold backup.
Deferred messages (holder offline) are stored by a handful of Kademlia-close
"postman" peers and polled by the addressee — there is no epidemic gossip.

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

- Maximum frame size: `MAX_MESSAGE_SIZE = 128 MiB`
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
    PosHashChallenge(PosHashChallengeMsg),
    PosHashResponse(PosHashResponseMsg),
    PosHashNack(PosHashNackMsg),
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
    ClusterSyncRequest(ClusterSyncRequestMsg),
    MailboxFetchRequest(MailboxFetchRequest),      // poll my own mail from a postman
    MailboxFetchResponse(MailboxFetchResponse),    // entries addressed to the requester
    MailboxStoreRequest(MailboxStoreRequest),      // deposit an entry with a postman
    MailboxStoreResponse(MailboxStoreResponse),    // Ack | Reject{reason}
    ClusterSyncResponse(ClusterSyncResponseMsg),
    Ack(AckMsg),               // generic ack for request-response streams that expect a reply
    #[serde(other)]
    Unknown,                   // forward-compat: unknown variants decode here, logged and ignored
}
```

`DeviceCertExchange` is **not** in this enum — it runs on a separate libp2p protocol (`/viaticum/cert/1`) as the connection handshake (see 1.2). `PeerDiscoveryRequest`/`PeerDiscoveryResponse` were removed in ε.2 (peers are found via the Kademlia DHT, protocol `/viaticum/kad/1.0.0`, FIND_NODE only; a peer that does not announce it is not kept in the routing table — see [ADR-003](decisions/ADR-003-own-kademlia.md)). The `BoardSync` and `SystemState{Backup,Ack,Request,Response}` variants were removed when the epidemic relay board and the push-to-all SystemState blob were replaced by the mailbox bus (see 1.5); deferred delivery now rides `MailboxStore*`/`MailboxFetch*`.

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
│   HKDF-SHA256(ikm=seed_bytes, salt=device_seed, info=b"viaticum-device-ed25519")
│   device_seed = random 32 bytes, generated once per device and stored locally
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

Connection authentication is not a `Message`-enum handshake. After the libp2p TCP+Noise+Yamux connection is up, both sides run a `DeviceCertExchange` on a separate libp2p protocol `/viaticum/cert/1` (request-response, CBOR). This is what proves cluster membership and binds the libp2p PeerId to a master identity. It runs automatically right after the connection establishes.

#### DeviceCertExchangeMsg (on `/viaticum/cert/1`)

```rust
pub struct DeviceCertExchangeMsg {
    pub cert: DeviceCertificate,        // signed by the cluster master key
    pub x25519_pub: Option<[u8; 32]>,   // legacy: relay-board ECDH key, no longer consumed
}
```

> `x25519_pub` is a vestige of the epidemic-relay era, when directed board entries
> were sealed with per-message ECDH. The mailbox bus (1.5) delivers point-to-point
> over Noise IX and authenticates each entry with an Ed25519 signature *inside* the
> payload, so no per-message ECDH is performed. The key is still derived, advertised
> and stored in `PeerRecord`, but no code path consumes it today. Treat it as reserved.

#### Exchange order

```
Initiator (A)              Acceptor (B)
     │                          │
     │── DeviceCertExchange ───>│   sent automatically after TCP+Noise connects
     │<─ DeviceCertExchange ────│   B replies with its own cert
     │                          │   both verify
```

#### Verification rules

1. Verify `cert.signature` against `cert.master_pub_key` (the cert is self-contained: the master key signs `device_id.0 (32) || issued_at (8)`).
2. Anchor the cert against the expected cluster identity: the carried `master_pub_key` must match `ClusterState.master_pub`, not merely be internally consistent — so two independently bootstrapped peers correctly reject each other.
3. On success the peer is authenticated and authorised for placement / restore / PoS traffic; `x25519_pub` (if present) is stored on the peer record but not currently used (see the note above).

#### Handshake result

After a successful exchange the node knows the peer's `master_pub_key` (cluster identity) and `DeviceId` (transport identity). All trust / restore / placement operations key on the master identity.

> A `HandshakeMsg` struct still exists in the message enum from the earlier design, but the live authentication path is the `DeviceCertExchange` above.

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
source_block_id = BLAKE3(stored_blob)   // stored_blob = nonce (12) || ciphertext
```

Content-addressed: the same file produces the same compressed bytes, the same deterministic nonce, the same ciphertext and blob, hence the same `source_block_id` — therefore zero-traffic deduplication.

#### Encryption (two layers)

**Layer 1 — block encryption:**
```
block_key   = HKDF-SHA256(ikm=epoch_key, info=b"viaticum-block-key")
nonce       = HKDF-SHA256(ikm=epoch_key, salt=BLAKE3(compressed_data), info=b"viaticum-block-nonce")[..12]
ciphertext  = ChaCha20-Poly1305_encrypt(key=block_key, nonce=nonce, plaintext=compressed_data)
stored_blob = nonce || ciphertext
```
The nonce is derived deterministically from the compressed content, so identical content yields an identical blob — this is what makes dedup work.

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

A challenge covers an ESI **range** and is answered with a single chain hash over all the bound symbols in it — raw symbol bytes never cross the wire (PoS proves possession without shipping data).

**PosHashChallengeMsg** (Owner → Holder):
```rust
pub struct PosHashChallengeMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],          // random nonce; seeds the chain hash and matches the response
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,     // (start_esi, count) — one challenge covers a whole range
    pub timestamp: Timestamp,
    pub device_id: DeviceId,             // the placement's holder DEVICE (required, signed)
    pub sig: [u8; 64],                   // OWNER's master key
}
// sig input: b"viaticum-pos-challenge-v2" || challenge_id || source_block_id || device_id
//            || CBOR(esi_ranges) || timestamp_be
```

**PosHashResponseMsg** (Holder → Owner):
```rust
pub struct PosHashResponseMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],
    pub source_block_id: SourceBlockId,
    pub chain_hash: [u8; 32],            // SHA256 chain over the bound symbols, not the symbols themselves
    pub timestamp: Timestamp,
    pub device_id: DeviceId,             // the responding device (required, signed)
    pub sig: [u8; 64],                   // the responding DEVICE's key
}
// sig input: b"viaticum-pos-resp-v2" || challenge_id || source_block_id || device_id
//            || chain_hash || timestamp_be
```

**PosHashNackMsg** (Holder → Owner):
```rust
pub struct PosHashNackMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],
    pub source_block_id: SourceBlockId,
    pub first_missing_esi: u32,          // first ESI in the range the holder does not have
    pub timestamp: Timestamp,
    pub device_id: DeviceId,             // the responding device (required, signed)
    pub sig: [u8; 64],                   // the responding DEVICE's key — a Nack cannot be forged
}
// sig input: b"viaticum-pos-nack-v2" || challenge_id || source_block_id || device_id || timestamp_be
```

**Device addressing.** A placement belongs to one holder *device*; the challenge goes to the
holder's *master* mailbox, which every device of that master reads. `device_id` in the
challenge names the addressed device and is under the owner's signature, so a postman cannot
re-address it. The holder checks, in order: owner signature → freshness → addressee → holding
→ disk. A challenge addressed to another device of its own master (a sibling, known from the
device→master table or the cluster state) is not served at all: no response, no Nack, no disk
read; the poll remembers it as *not mine* until it expires. A challenge addressed to a device it
does not know as its own is dropped like junk.

The response and the Nack are signed with the responding device's key (`DeviceId` is that
key's public half). The owner accepts a response only if `response.device_id ==
pending.holder_id` and the signature verifies under `holder_id`
(`verify_pos_hash_response(msg, &holder_id)` → `WrongDevice` / `BadSignature`). A response from
a sibling device, a forgery, or one signed with the master key is ignored and the pending
challenge is left intact for the addressed device's own answer. Siblings share the master and
epoch keys (they are not cryptographically isolated from each other), but one device cannot
pass or fail a PoS challenge for another.

`PosHashNack` means: "I am not storing (some of) these symbols" (evicted under disk pressure, or never received). A holder must send `PosHashNack` instead of staying silent if it knows it does not hold them.

#### Verification (Owner)

```
On PosHashResponse { chain_hash }:
  1. Re-encode the symbols in esi_ranges from the local source block
  2. Apply per-holder binding to each: symbol XOR ChaCha20(HKDF(source_block_id, holder_id))
  3. Compute the chain hash over the bound symbols, ESI ascending:
       h0  = SHA256(challenge_id)
       h_i = SHA256(h_{i-1} || bound_symbol_i)
  4. Pass iff h_n == response.chain_hash

Only the 32-byte hash crosses the wire. Symbol hashes are not stored in the DB —
the expected hash is recomputed on the fly per challenge.
```

#### VerifyOutcome and response

| Outcome | Condition | Action |
|---------|-----------|--------|
| `Pass` | chain hash matches | trust P +1, all good |
| `NotHeld` | PosHashNack received | do NOT penalise trust, immediate repair (holder is honest) |
| `Fail` | chain hash mismatch | trust P −1, immediate repair (corruption or fraud) |
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

#### Challenge delivery (via mailbox)

Both legs of a PoS round-trip travel over the mailbox bus (1.5) — there is no
direct-vs-relay branching. The holder is usually offline (cold backup), so the
challenge is always deposited, not delivered synchronously:

1. **Challenge**: the scheduler publishes a `PosChallenge` mailbox entry addressed to the holder's master identity (`target = holder_master`, `sender = owner_master`), carrying the signed `PosHashChallengeMsg`. `publish` deposits it with the holder's Kademlia-close postmen; the placement is only moved to Pending once at least one postman Acks (challenge is durably stored before the owner starts its timeout).

2. **Response**: when the addressed holder device next polls its master mailbox it finds the challenge, recomputes the chain hash and publishes a `PosResponse` entry back (`target = owner_master`, `sender = holder_master`), signed by its device key. Sibling devices reading the same mailbox skip the challenge. The response uses a stable `msg_id` derived from the chain hash, so a retried response is idempotent.

3. **No live connection required**: `idle_connection_timeout = 600s` in libp2p means peer-to-peer connections are **ephemeral** — peers do not hold persistent links. The mailbox absorbs this: challenge and response each wait in postman storage (TTL 7 days, `POS_CHALLENGE_TTL`) until the addressee polls.

When a peer stays offline past the PoS timeout (7 days), the outstanding challenges are treated as Lost (3+ Timeouts) → repair triggered. This is the correct behaviour for a cold backup system with a time constant of 1 week.

#### PoS limitations

- PoS is not run for source blocks in `Deleting` or `Deleted` status
- If a file has been deleted locally and its block is in cooldown, PoS stops
- Bandwidth overhead: `T × 15 holders = ~1 MB/week` — negligible

---

### 1.5. Mailbox Bus

The mailbox bus is the mechanism for delivering messages when a direct connection is not possible (the addressee is offline — the normal case for cold backup). It replaced the epidemic relay board and the push-to-all SystemState blob wholesale (see `decisions/ADR-004-mailbox-bus.md`).

#### How it works

Every entry is **directed** to a single addressee (its master identity). There is no gossip, no hop counter, no epidemic propagation:

```
Sender (write-fanout):
  MailboxRouter::publish(target, entry)
  → rank all known peers by XOR distance to SHA256(target_pub)
  → deposit the entry with the MAILBOX_WRITE_FANOUT (30) closest "postman" peers
  → count Acks; the send is durable once ≥1 postman Acks

Addressee (read-fanout):
  MailboxRouter::poll(my_master_pub, since_stored_at)
  → fetch from the MAILBOX_READ_FANOUT (300) closest postman peers
  → dedup entries by msg_id (highest stored_at wins)
  → dispatch each entry by class
```

Postmen store entries **on behalf of** the target; the target — and only the target — polls to collect them. Write-fanout to 30 and read-fanout to 300 gives redundancy against churn without any peer-to-peer flooding.

#### Mailbox entry

```rust
pub struct MailboxEntry {
    pub target: IdentityPub,          // owner the entry is addressed to
    pub msg_id: [u8; 16],             // sender-chosen; dedup + idempotent retry
    pub class: MailboxClass,
    pub payload_version: u8,          // receivers skip unknown versions
    pub payload: Vec<u8>,             // CBOR of the inner (signed) message
    pub expires_at: u64,              // unix secs (absolute TTL)
    pub stored_at: u64,              // LRU / poll cursor ordering
    pub sender: Option<IdentityPub>,
}
```

The envelope itself is **not signed**. Authenticity is carried by the Ed25519 signature *inside* each payload (e.g. `PosHashChallengeMsg.sig`, `DeleteMsg.sig`), verified against `entry.sender`. Point-to-point delivery over Noise IX plus per-payload signatures replace the old relay-era per-message ECDH.

#### Entry classes and TTLs

```rust
#[repr(u8)]
pub enum MailboxClass {
    SelfPointer  = 0,   // DR pointer, self-addressed        TTL 5 years
    PosChallenge = 1,   // owner → holder                    TTL 7 days
    PosResponse  = 2,   // holder → owner                    TTL 7 days
    DropNotice   = 3,   // holder → owner (eviction)         TTL 14 days
    Generic      = 4,   // no producer; polled + dropped     TTL 90 days
    DeleteRequest = 5,  // owner → holder (Delete/Cancel)    TTL 14 days
    Revocation   = 6,   // revoking master → storage peers   TTL 30 days
}
```

Only `SelfPointer` is **high-trust** (`is_high_trust()`): it is the DR lifeline and is never dropped by membership or LRU eviction, only by TTL. `store()` clamps a sender-supplied `expires_at` down to `now + class TTL` so a sender cannot squat a postman's storage indefinitely.

#### Transport

Mailbox messages ride the main `/viaticum/1` protocol as ordinary request-response `Message` variants — there is no separate mailbox protocol path:

```rust
pub struct MailboxStoreRequest  { pub v: u8, pub target: IdentityPub, pub entry: MailboxEntry }
pub enum   MailboxStoreResponse { Ack { msg_id }, Reject { msg_id, reason } }
pub struct MailboxFetchRequest  { pub v: u8, pub target: IdentityPub, pub since_stored_at: Option<u64> }
pub struct MailboxFetchResponse { pub v: u8, pub entries: Vec<MailboxEntry>, pub served_msg_ids: Vec<[u8;16]> }

pub enum MailboxRejectReason { NotInCandidateSet, QuotaExceeded, EntryTooLarge, Duplicate }
```

(`served_msg_ids` is reserved for a future delivery-reward accounting; nothing consumes it today.)

Postman-side rules:
- **Store**: accept iff this node is within the target's candidate set (`should_store`: top-`MAILBOX_CANDIDATES_N` = 1000 closest known peers to `SHA256(target_pub)`); a redb-duplicate `msg_id` returns an idempotent `Ack`.
- **Fetch**: `req.target` must equal the requester's own master identity — you may only poll your own mail.

#### Limits

- `MAILBOX_CANDIDATES_N = 1000` — how close a peer must rank to store for a target
- `MAILBOX_WRITE_FANOUT = 30`, `MAILBOX_READ_FANOUT = 300`
- `MAX_ENTRY_BYTES = 256 KiB` — per-entry cap
- `MAX_MAILBOX_BYTES_PER_PEER = 100 MiB` — per-target quota; overflow → `Reject{QuotaExceeded}`

#### Sweeping and eviction

- **TTL sweep** (`mailbox_sweep_expired`, every 6h + on startup): deletes `expires_at < now` for **all** classes, including high-trust. This is the only path that removes a `SelfPointer`.
- **Membership self-cleanup**: if a postman drifts out of a target's candidate set (routing table changed), it deletes that target's **non-high-trust** entries. `SelfPointer` is exempt (its 5-year TTL is the DR guarantee).

#### Mailbox usage

| Purpose | Class | Direction |
|---------|-------|-----------|
| DR pointer (self-backup location) | `SelfPointer` | self → own postmen |
| PoS challenge | `PosChallenge` | owner → holder |
| PoS response | `PosResponse` | holder → owner |
| Symbol drop / eviction notice | `DropNotice` | holder → owner |
| Delete (and CancelDelete) | `DeleteRequest` | owner → holder |
| Device revocation | `Revocation` | revoking master → storage peers |
| ClusterSync events | — | direct connection (not mailbox) |

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
  │<─ SymbolStored ────────────│   every ESI of this chunk is on the holder's disk, else Ack
```

The holder answers each `SymbolTransfer` with `SymbolStored` (the chunk's ESIs) only when every
ESI of the chunk is on its disk under an Active holding: written now, or already held (listed in
the owner's Active holding record and the file has the symbol's length). Otherwise it answers
`Ack`: no accepted offer, offer expired, an ESI neither held nor in the offer's remaining ranges,
an oversized symbol, an empty chunk, or a write error. The owner reads `Ack` as "not stored".

The holder keys accepted offers by the sending device and block, so two devices of one master
offering the same block keep separate offers. The holding itself is kept per master.

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
  │<─ RestoreResponse ──────────│   bound symbols (empty if no holding for this owner, or the owner asked to delete it)
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
    pub sig: [u8; 64],   // Ed25519 owner_key.sign(b"d" || source_block_id || timestamp)
}
// Domain-separated signatures: Delete uses prefix b"d", CancelDelete b"c", SymbolOffer b"so".
```

#### Eviction (disk pressure)

Both advance warnings and confirmed drops travel as `DropNotice` mailbox entries (1.5); the `deadline` field distinguishes them:

```
Holder → Owner: DropNotice mailbox entry, deadline = now + DROP_NOTICE_WINDOW_SECS (7 days)
  advance warning — owner has a window to pre-repair

Holder → Owner: DropNotice mailbox entry, deadline = now (immediate eviction)
  → owner (on poll): PlacementStatus → Lost → trigger repair
```

Notices for the same owner are batched into one mailbox entry (`SymbolDropNoticeBatchMsg`) to avoid fan-out storms during mass eviction; a batch that exceeds `MAX_ENTRY_BYTES` (256 KiB) is split across entries. Each notice is **signed by the holder's master key** and verified on receipt (`verify_symbol_drop_notice`) — an unsigned or forged drop notice is rejected, so it cannot be used to trigger spurious repair storms.

**SymbolDropNoticeMsg**:
```rust
pub struct SymbolDropNoticeMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,
    pub deadline: Timestamp,   // when the drop will occur (now = immediate)
    pub timestamp: Timestamp,
    pub sig: [u8; 64],         // Ed25519 holder_master_key.sign(...) — forgery-proof
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

### 1.8. Restore access (no gate in v1)

v1 has no restore gate: the holder serves the owner's own symbols while it holds them. The holding is looked up by the pair (block, master of the requesting connection); any other master gets an empty `RestoreResponse`. Only what the owner itself asked to delete (`MarkedForDelete`) is not served (restore-i16). Served bytes are counted per owner (`restore_served`) for a future escrow-as-debt; nothing reads the counter today.

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

Upon receiving such a handshake, the partner extracts `master_pub_key` from `device_cert` as the cluster identity. All subsequent trust/restore operations use `master_pub_key`.

#### Device registration

```
1. New device enters seed phrase → derive device_key
2. device_id = DeviceId(device_key.verifying_key().to_bytes())  // 32 bytes Ed25519 pubkey
3. Create DeviceCertificate = master_key.sign(device_id.0 || issued_at)
4. Present the cert on connect via DeviceCertExchange (1.2) → partners accept the device as part of the identity (learned lazily on first contact, not broadcast)
5. Seed is erased from RAM
6. Sync state (file catalog, placements) via ClusterSync
```

Device limit: 16 (`MAX_DEVICES = 16`). Determined by the ESI namespace: `ESI space = 2^24`, `2^20 per device`.

#### Device revocation

```
1. viaticum device revoke <device_id>
2. Create RevocationCertificate = master_key.sign(b"revoke" || device_id || revoked_at || new_epoch)
3. epoch_counter += 1, new epoch_key
4. Publish `Revocation` mailbox entries carrying RevocationBroadcast { revocation_cert, device_cert }, addressed to the master's **storage-relationship peers only** (holders of our data ∪ owners we hold for), not broadcast to everyone
5. Partners: add device to revoked list, deny restore/PoS for revoked device key
6. Owner: gradually re-encrypt old files with the new epoch
```

**RevocationBroadcast** (payload of a `Revocation` mailbox entry):
```rust
pub struct RevocationBroadcast {
    pub revocation: RevocationCertificate,
    pub device_cert: DeviceCertificate,
}
```

Revocation is delivered as directed mailbox entries (`Revocation` class, TTL 30 days) to the peers with which the master has an actual storage relationship — the set that needs to deny the stolen device. This is narrower than the old epidemic broadcast by design: the parties who must act are our holders and the owners we hold for; other peers learn the revocation lazily if they ever transact with the master. Threat model: "lazy not malicious" — a thief is unlikely to actively interfere.

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
block_key = HKDF(epoch_key, info="viaticum-block-key")
nonce     = HKDF(epoch_key, salt=BLAKE3(compressed), info="viaticum-block-nonce")
ciphertext = ChaCha20-Poly1305(block_key, nonce, compressed)
source_block_id = BLAKE3(nonce || ciphertext)
```

The same file on two devices → same compressed bytes → same deterministic nonce → same `ciphertext` → same `source_block_id` → symbols already in the network → zero extra traffic.

#### Peer-to-device affinity

```
Device A (online in the evenings): manages peers {P1, P3, P5}
Device B (NAS, always-on):         manages peers {P2, P4, P6}
```

Blast radius isolation: device A offline → only relationships with P1, P3, P5 are affected. The overall trust identity is the average.

S-score: per (device, peer) pair — the protocol has no knowledge of clusters. An external peer sees a device as an ordinary node.

---

### 1.10. System State Backup (self-pointer)

The daemon backs up its own metadata DB so a total-loss owner can recover it from
the mnemonic alone. The δ.1 design — one encrypted blob per owner, pushed to every
peer and stored in a `system_state_blobs` table — was replaced (see 1.5 / ADR-004).
The blob push does not scale and duplicated the redundancy machinery the backup
pipeline already has. The current design reuses that machinery:

#### How it works

```
1. Snapshot the DB → SystemState (CBOR → zstd → ChaCha20-Poly1305, key derived
   from the seed so DR can decrypt with only the mnemonic)
2. Erasure-code the encrypted snapshot as an ordinary "SS-block" (base + diffs),
   place its symbols with holders exactly like user data (SS_IMPORTANCE)
3. Build a SelfPointer: a tiny (KB) signed index naming the SS-block(s) and, for
   each, the holders to fetch it from — then publish it as a self-addressed
   `SelfPointer` mailbox entry (1.5) to the owner's own postmen
```

The DB is thus protected by the same erasure coding, per-holder binding and PoS as
the user's files. The only thing that must be found "from nothing" at DR is the
pointer — and that lives in the mailbox under the owner's own identity.

```rust
pub struct HolderHint {
    pub holder_id: DeviceId,
    pub addrs: Vec<String>,         // best-effort dial hints; re-resolved via Kademlia if stale
    pub esi_ranges: Vec<(u32, u32)>, // carried in-pointer: DR has no placements table yet
}

pub struct BlockRef {
    pub block_id: SourceBlockId,
    pub holders: Vec<HolderHint>,
    pub encrypted_size: u64,        // DR recomputes ErasureParams from this
}

pub struct CatalogSummary {
    pub lineage: CatalogLineageId,  // 16 random bytes: this DB's history, minted once per DB
    pub publisher: DeviceId,        // the device that published the pointer
    pub files: u32,                 // live files of the state this pointer restores
}

pub struct SelfPointer {
    pub generation: u32,            // resets to 1 per owner restart — NOT a global freshness key
    pub base: BlockRef,
    pub diffs: Vec<BlockRef>,
    pub created_at: Timestamp,      // freshness key INSIDE one history
    pub catalog: CatalogSummary,
    pub signature: [u8; 64],        // Ed25519 master_key.sign("viaticum-self-pointer-v2" ||
                                    //   cbor(gen, base, diffs, created_at, catalog))
}
```

**Catalog history.** Every database is its own history: the daemon mints a random
`lineage` when its pointer-push task starts on a database that has none, and a DR mints a NEW one for the database it
restores (the id lives in the DB's meta table, not in the SystemState snapshot, so it
never travels with restored state). Two installations of one identity — the lost
machine and a node started with `init --mnemonic`, or a DR node left running — are
therefore always two histories. `files` counts live file records (not deleted on every
device). `publisher` lets DR move the restored files from the lost device to its own
(otherwise a deletion on the recovered machine would wait forever for the lost device).

The pointer carries holder identities and ESI ranges directly because at DR the
`symbol_placements` table does not exist yet — it is part of what is being recovered
(the DR circular dependency, Bug-A). No `master_pub` is embedded: the verifier already
knows the expected identity from the mnemonic, and omitting it binds verification to
that identity.

#### Publish cadence

`run_periodic_push` republishes the pointer when the state changes structurally, or
every 30 days otherwise. The `SelfPointer` mailbox entry is **high-trust**: postmen
never evict it under membership churn or disk pressure — only its 5-year TTL removes
it. Inside one history the freshest pointer wins by `created_at` (wall clock), with
`generation` only as a same-timestamp tiebreak, because generation resets on restart.
Between histories time does not decide: DR restores the only history it finds, and when
it finds several it lists them (history, live files, date of the newest pointer,
publisher) and requires `--catalog <first 8 hex>`.

#### Peer discovery

Peer discovery is no longer a protocol message. `PeerDiscoveryRequest`/`PeerDiscoveryResponse`
were removed in ε.2; peers are found through the Kademlia DHT. Disaster recovery (3.4)
uses Kademlia `get_closest_peers` to populate its peer set, then polls the mailbox for
the self-pointer — there is no blob request and no BFS peer-list expansion.

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
9. Bootstrap auto-connect: connect to bootstrap peers → join the Kademlia DHT → learn more peers
10. On each authenticated connection, exchange DeviceCertExchange (1.2) and PeerAnnounce (address + keys)
```

### 3.2. Normal Operation

```
Watcher: fs event → debounce 30 min → dirty_files

Packing queue (per file category):
  Flush if: ≥ source-block size (default 128 MB, configurable)
         OR 1 hour idle
         OR 24 hours fallback
  Min batch: 1 MB

Backup flow (per source block):
  1. Dedup check: content_hash already backed up? → skip
  2. compress (zstd) + encrypt (ChaCha20-Poly1305, key+nonce from epoch_key)
  3. source_block_id = BLAKE3(stored_blob = nonce || ciphertext)
  4. ErasureParams → K, K_eff, N (against target reliability + holder trust)
  5. SymbolBudgetEngine: distribute N symbols among holders
  6. Per holder: generate symbols, apply per-holder binding, send via SymbolOffer/Transfer
  7. SymbolStored received → PlacementStatus → Alive

PoS: adaptive scheduler
  picks random ESI from holder's esi_ranges
  → PosHashChallengeMsg (via mailbox)
  → verify PosHashResponse chain hash, update trust + PlacementStatus

Repair (triggered by PresumedLost / Lost):
  File on disk → generate new symbols (new ESIs) → place at new holder
  File not on disk → collect K_eff symbols → unbind → decode → new symbols
```

### 3.3. Restore

```
viaticum restore <path> [--version N] [--date YYYY-MM-DD] [--no-wait] [--json]
viaticum restore --status [JOB_ID] [--json]

Restore is a job in the daemon: POST /api/restore → 202 + the job (id, queued);
GET /api/restore/jobs/{id}, GET /api/restore/jobs. A path not in the catalog, or with
no backed-up version under it, is refused at once (404 / 422), as is a --version N
that is not backed up there (404 version_not_found, with the available numbers);
no job, no staging dir.
The CLI polls every 2 s with no overall deadline; Ctrl-C detaches the terminal, the
job goes on. Exit code: 0 all restored / 2 some / 1 none, refused, interrupted, or
lost contact with the daemon.

1. DB lookup: path → FileRecord → FileVersion (a prefix matches only at a '/')
2. FileVersion → source_block_id
3. Dedup: several files in one block → one download
4. Per source_block (by importance):
   a. source files present → rebuild the block locally, no network
   b. otherwise candidates: SymbolPlacement status ∈ {Alive, Uncertain, PresumedLost}
   c. (no restore gate on the holder side, §1.8)
   d. rounds over the holders: each gets RestoreRequests of ≤ 4 MiB of its ESIs;
      a holder that does not answer within 30 s is skipped for the round and asked
      again in the next; no deadline per block — give up only after a round with no
      new ESI. Only holders with a live authenticated connection are asked; a holder
      not connected refuses at once and is not dialled (a retry that redials is the
      separate slice restore-i26)
   e. Unbind: XOR ChaCha20(HKDF(block_id, holder_id))
   f. RaptorQ decode → ciphertext
   g. decrypt (epoch_key) → decompress → plaintext
5. Pack → PackIndex → extract files by offset+size
6. Write into staging <data_dir>/restore/<job>/<path>: a temp file in .viaticum-partial/,
   visible under its name only when complete; the job outcome in .viaticum-job.json.
   LocalState is not touched; every file ends restored or as a failure with a kind.
7. Daemon shutdown: the job is recorded interrupted (requests abandoned, 10 s drain).
```

Version selection:
- `--version N`: specific, 1-based as listed by `versions` (default = latest backed up)
- `--date D`: nearest version ≤ D

### 3.4. Disaster Recovery

```
All devices lost, only the seed phrase remains:

viaticum dr --mnemonic "24 words" --peer <addr>

1. Derive identity from seed → IdentityPub
2. Preflight (phrase, folder, locks) and claim a staging DB (db.redb.dr-new); the --peer
   addresses are the Kademlia bootstrap peers, and peers are written to the staging DB as they
   authenticate
3. Start minimal SwarmHandle (libp2p, no Processor)
4. wait_for_kad_bootstrap_stable: join the DHT, drain PeerAuthenticated, upsert discovered peers into the DB
5. get_closest_peers(master_pub) — the preimage: libp2p hashes it to SHA256(master_pub), where
   the postmen are ranked → dial + authenticate candidates
6. dr_collect_pointers: ask every candidate once, in expanding batches [100, 300, 1000], keep every
   SelfPointer whose signature verifies against the mnemonic identity (no early exit)
7. Choose the catalog: group by catalog history; one history → its freshest pointer; several →
   print them all and stop unless --catalog <prefix> names one
8. From the pointer's base + diffs, dial each HolderHint (one dial over all its addrs, all holders
   at once; the rest via get_closest_peers(holder_id)) → fetch the SS-block symbols
9. RaptorQ decode → decrypt (ChaCha20-Poly1305, key derived from seed) → SystemState
10. Replace the publishing (lost) device by this device in every file record; restore DB (files,
    source blocks, placements, peers, pos_weekly, cluster_state); merge the peers seen live back
    over the snapshot (the --peer address first); mint a new catalog history
11. All of 2-10 runs on drafts (db.redb.dr-new, identity.key.dr-new) and is installed by renames at
    the end: a failed or interrupted (Ctrl-C) DR changes nothing; an old db.redb is kept as
    db.redb.dr-bak[.N]
12. "Run viaticum daemon, then viaticum restore <path>"

The self-pointer is published periodically by the daemon (1.10) as a high-trust mailbox
entry under the owner's own identity (5-year TTL), so it outlives long owner outages.
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

**Defence (v1):** contribution-weighted placement and offer budget. A peer that stores nothing for others earns no offer credit and loses trust weight. There is no restore gate: restore of the owner's own data is never refused (a legitimate owner must get their files back on the worst day). A debt-style escrow for an open network is future work.

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
- Mailbox entries: `expires_at < now → swept`; `store()` clamps sender-supplied TTL to the per-class maximum

### 4.6. Device Theft

- Revoke device key → storage-relationship partners receive `RevocationBroadcast` via directed mailbox (1.9)
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
| `MAILBOX_CANDIDATES_N` | 1000 | Closest peers that store for a target (postman set) |
| `MAILBOX_WRITE_FANOUT` | 30 | Postmen an entry is deposited with on publish |
| `MAILBOX_READ_FANOUT` | 300 | Postmen polled when fetching own mail |
| `MAILBOX_POLL_INTERVAL_SECS` | 3600 (1 h) | Base mailbox poll cadence (÷ time_scale) |
| `MAILBOX_SWEEP_INTERVAL_SECS` | 21_600 (6 h) | Base TTL/membership sweep cadence (÷ time_scale) |
| `MAX_ENTRY_BYTES` | 262_144 (256 KiB) | Per mailbox-entry cap |
| `MAX_MAILBOX_BYTES_PER_PEER` | 104_857_600 (100 MiB) | Per-target mailbox quota |
| `SELF_POINTER_TTL` | 157_680_000 (5 years) | DR self-pointer TTL (high-trust) |
| `POS_CHALLENGE_TTL` | 604_800 (7 days) | PoS challenge/response mailbox TTL |
| `DROP_NOTICE_TTL` | 1_209_600 (14 days) | Drop-notice mailbox TTL |
| `DELETE_REQUEST_TTL` | 1_209_600 (14 days) | Delete/CancelDelete mailbox TTL |
| `REVOCATION_TTL` | 2_592_000 (30 days) | Device-revocation mailbox TTL |
| `UNKNOWN_SENDER_TTL` | 7_776_000 (90 days) | Generic-class mailbox TTL |
| `MAX_MESSAGE_SIZE` | 128 MB | Maximum frame size |
| `PROTOCOL_VERSION` | 1 | Protocol version |
| `ALPN` | `b"viaticum/1"` | ALPN identifier |
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
  mailbox_entries       key = target_pub(32) || msg_id(16) || class(1) → CBOR(MailboxEntry)
  mailbox_bytes_by_target  key = target_pub(32) → u64 (per-target quota accounting)
  ss_blocks             key = block_id(32) → generation — marks which source blocks are SystemState replicas
```

(The δ.1 `system_state_blobs` table was removed; a one-time `drop_legacy_system_state_blobs` migration deletes it on DB open.)

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
| Escrow | Time-based (weeks_in_network) | None: no restore gate (v1) |
| DB metadata | ~50 MB/1000 files | ~3.4 MB/1000 files (15x smaller) |
| Multi-device | None | Personal Cluster, device certs |
| PoS | Stub | Real (64 KB response + on-the-fly verify) |
| PoS not held | Silence | PosHashNack (explicit response) |
| Repair | Basic | Graduated (Uncertain→PresumedLost), NotHeld→immediate |
| Deferred delivery | None | Directed mailbox bus (postman store-and-forward) |
| Dedup | None | Content-addressed (same hash → zero traffic) |
| Backup trigger | Weekly | Event-driven + flush conditions |
| File versioning | None | Vec\<FileVersion\>, restore by version/date |
