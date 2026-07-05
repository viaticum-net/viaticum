# Migration to libp2p

> **Historical document.** This is the design record for the iroh → libp2p migration, which has since been completed and shipped. It captures *why* the switch was made and how it was planned, not the current state of the code. Forward-looking language ("we will remove", "Phase 1–5", file lists) describes the migration plan as written at the time. For the current network stack, see [`../protocol.md`](../protocol.md) and [`../architecture.md`](../architecture.md). Some details here diverged during implementation (the "Implementation clarifications" section at the end already records several); the doc is preserved as rationale, not synced to code.
>
> **Superseded: the "Board".** This doc makes the store-and-forward **Board** (a.k.a. epidemic relay) the primary transport for deferred protocol messages. That design was later replaced wholesale by the directed **mailbox bus** — see [`../protocol.md` §1.5](../protocol.md) and [ADR-004](../decisions/ADR-004-mailbox-bus.md). Wherever this doc says "Board", "board sync", or "x25519 for board encryption", read it as the *former* mechanism. **Note the two unrelated senses of "relay" below:** the **Board/epidemic relay** is gone; **libp2p Circuit Relay v2 + DCUtR** (NAT-traversal holepunch coordination) remain current and are unaffected.

*Decision: iroh -> libp2p. Full design of the new network stack.*
*Version 5 (final) -- after two rounds of review.*
*No DB migration needed: no users yet.*

---

## Context

Viaticum uses iroh 0.96 as its QUIC transport. Problems:

1. **Relay is broken** -- QUIC through the iroh relay dies after 6-7s, handshake never completes
2. **Dual identity** -- iroh SecretKey + IdentityPub, mapped via PeerAnnounce
3. **QUIC is blocked** -- UDP is dropped in corporate networks, DPI identifies QUIC
4. **Dependency on third-party servers** -- iroh relay (n0.computer), pkarr
5. **iroh pre-1.0** -- unstable API

## Decision: libp2p

libp2p v0.56 -- a modular P2P framework. Battle-tested in production (Polkadot, Filecoin, IPFS, Ethereum).

### What we take

| Component | What it does | Replaces |
|-----------|-------------|----------|
| TCP transport | Byte delivery | iroh QUIC endpoint |
| Noise protocol | Encryption + Ed25519 authentication | iroh TLS + our HandshakeMsg |
| Yamux | Stream multiplexing (16 KiB frames) | Our single bi-stream |
| Kademlia DHT | Peer discovery without servers | PeerAnnounce + iroh pkarr |
| DCUtR | Holepunching (~70% success, TCP = UDP) | iroh relay (broken) |
| Circuit Relay v2 | Fallback relay through any peer | iroh relay servers |
| identify | Address exchange on connect | Manual EndpointAddr management |
| request-response | Request/response over streams | Our framed CBOR on bi-stream |

### What we do NOT take

- IPFS Bitswap (private data, own transfer protocol)
- GossipSub (board handles broadcast)
- QUIC transport (may add later as an option)

---

## Architecture

```
+----------------------------------------------+
|  Viaticum Protocol                           |
|  Trust, PoS, Escrow, Backup, Restore         |
|  Message enum (CBOR)                         |
|  --- unchanged ---                           |
+----------------------------------------------+
|  SwarmHandle                                 |
|  send_to_device(DeviceId, Message) -> Resp   |
|  events() -> Stream<ProtocolEvent>           |
+----------------------------------------------+
|  libp2p Swarm                                |
|  +----------------------------------------+  |
|  | ViaticumBehaviour (NetworkBehaviour)   |  |
|  |                                       |  |
|  |  request_response -- CBOR messages    |  |
|  |  kademlia         -- peer discovery   |  |
|  |  dcutr            -- holepunching     |  |
|  |  relay_client     -- relay (client)   |  |
|  |  relay_server     -- relay (server)   |  |
|  |  identify         -- addr exchange    |  |
|  +----------------------------------------+  |
|  TCP + Noise + Yamux                         |
+----------------------------------------------+
|  Board (store-and-forward)                   |
|  --- primary transport for protocol msgs --- |
+----------------------------------------------+
```

### Two delivery channels

Board = **primary** for protocol messages. Direct connection = for heavy data.

**Board (store-and-forward, offline-tolerant):**
- PoS Challenge / Response / Nack
- Delete, CancelDelete
- SymbolDropped, SymbolDropNotice, StorageWarning
- DeviceRevocation (broadcast)

**Direct connection (libp2p request-response):**
- SymbolTransfer (megabytes of data)
- SymbolOffer / Accept / Reject (pipeline)
- RestoreRequest / Response (user is waiting)
- SystemStateRequest / Response (DR)
- SystemStateBackup (push)
- ClusterSync
- Board sync

**PoS response policy:** a holder always replies via board, even if a direct connection is available. One path, simpler logic.

**PeerDiscoveryRequest / Response:** removed, replaced by Kademlia DHT.

---

## Identity: device-visible model

### Key decision

External peers see specific **devices**, not an abstract "cluster". DeviceId -- primary key for routing, placement, PoS. IdentityPub (master) -- aggregation key for trust and escrow.

### Current: three keys, mapping via PeerAnnounce

```
master_signing_key -> IdentityPub (Ed25519, 32 bytes) -- master identity
device_signing_key -> DeviceId ([u8; 16], random)     -- device identity
IrohSecretKey      -> NodeId (Ed25519, 32 bytes)      -- transport identity

Relationships:
  DeviceCertificate: device_key -> master_key (signed by master)
  PeerAnnounce:      IdentityPub -> NodeId    (signed by master)
```

### After: two keys, no mapping needed

```
master_signing_key -> IdentityPub (Ed25519, 32 bytes) -- master (trust agg, escrow)
device_signing_key -> DeviceId (Ed25519 pubkey, 32 bytes) -- device (routing, placement, PoS)
                   -> PeerId = hash(DeviceId)             -- libp2p transport (network)
```

**DeviceId type change:** from `[u8; 16]` (random) to `[u8; 32]` (Ed25519 pubkey). This simplifies the identity model -- DeviceId = public key, PeerId is derived from it. Consequences:
- `DeviceCertificate` structure simplifies: `device_id` and `device_pub_key` merge into a single field
- Signed cert payload changes
- No DB migration needed (no users)

```
DeviceId = our type in core (raw Ed25519 pubkey, 32 bytes)
PeerId   = libp2p type, only in daemon (multihash, ~38 bytes)

Conversion DeviceId -> PeerId: one function (hash), no table.
PeerId -> DeviceId: not possible (hash), but DeviceId is always in DeviceCertificate.
```

Conversion (daemon only):
```rust
use libp2p_identity::ed25519;

let secret = ed25519::SecretKey::try_from_bytes(device_seed)?;
let ed_keypair = ed25519::Keypair::from(secret);
let libp2p_keypair = libp2p::identity::Keypair::from(ed_keypair);
let peer_id = libp2p_keypair.public().to_peer_id();
```

### What an external peer sees

```
PeerRecord {
    device_id: DeviceId,              // primary key, who to connect to
    master_identity: IdentityPub,     // trust/escrow aggregation
    device_cert: DeviceCertificate,   // proof of ownership
    x25519_pub: [u8; 32],            // board encryption
}
```

Cluster device discovery is **lazy**: a peer learns about a new device when it connects (DeviceCertExchange). No proactive announcements.

### PeerId -> DeviceId in the event loop

The Swarm event loop maintains a table of authenticated peers `HashMap<PeerId, (DeviceId, IdentityPub)>`. Populated from DeviceCertExchange. Used to convert PeerId to ProtocolEvent with DeviceId.

---

## Two-level trust

### Problem

Trust = "will my data be safe". A property of both the **device** (NAS 24/7 vs laptop) and the **person** (reliable participant, years in the system).

Per-master (current): hides the difference between NAS and laptop. Per-device: reputation is lost when a device is replaced.

### Solution: two layers

```
device_trust(DeviceId)      -- "this device responds to PoS"
                               Earned through PoS responses.
                               Starts at zero. Dies with the device.

master_trust(IdentityPub)   -- "this person is a reliable participant"
                               Aggregated from device_trust of all devices.
                               Survives device replacement.

effective_trust(DeviceId)   -- combination: used by placement
```

### Formula

```rust
fn effective_trust(db: &Db, device: DeviceId) -> TrustScore {
    let dt = db.get_device_trust(device);
    let master = db.get_master_identity(device);
    let mt = db.get_master_trust(master);

    // New device of an established user:
    //   dt = 0, mt = high -> effective ~30-50% of master trust
    let base = mt * INHERITANCE_FACTOR;  // 0.3-0.5, tune experimentally
    base + dt * (1.0 - base / MAX_TRUST)
}

fn update_master_trust(db: &Db, master: IdentityPub) {
    let devices = db.get_devices_for_master(master);
    // Weighted average by number of stored symbols
    // + tenure bonus (duration of participation)
}
```

### Lifecycle

```
New user, NAS:              dt=0, mt=0 -> effective=0, must earn trust
After a year:               dt=high, mt=high
Adds a laptop:              dt(laptop)=0, mt=high -> effective=30-50%, fast start
NAS dies, buys a new one:   dt(new)=0, mt=high -> effective=30-50%, reputation preserved
Laptop offline for a month: dt(laptop) drops, mt slightly, NAS unaffected
```

### DB tables

```
device_trust:   keyed by DeviceId    -- updated on each PoS
master_trust:   keyed by IdentityPub -- aggregated periodically
peer_records:   keyed by DeviceId    -- stores master_identity as a field
escrow/budget:  keyed by IdentityPub -- economics between people
```

### Sybil

"10 devices = 10x trust" -- no: trust is earned through real storage + PoS. Budget is per-master.

---

## Handshake: simplification

### Current

1. iroh QUIC+TLS (iroh identity -- untrusted)
2. `open_bi()` -- single stream
3. Our `HandshakeMsg`: identity + timestamp + Ed25519 sig
4. Verify sig + freshness (300s window)
5. Exchange `DeviceCertificate`

### After

1. TCP connect
2. Noise IX -- encryption + Ed25519 authentication (forward secrecy, replay protection)
3. Yamux negotiation
4. DeviceCertExchange (first request-response on `/viaticum/1`)
5. Verification: cert.device_pub == authenticated PeerId's key

`HandshakeMsg`, `build_handshake()`, `verify_handshake()` are removed. Noise is better.

### DeviceCertExchange

Implemented as a regular request-response on the main protocol `/viaticum/1`. The dialer sends first:

```
Dialer  -> Request(DeviceCertExchange { cert, x25519_pub })
Listener -> Response(DeviceCertExchange { cert, x25519_pub })
```

In libp2p every connection always has a clear dialer/listener (libp2p deduplicates simultaneous dials).

### State machine

```
ConnectionEstablished(PeerId)
  -> PendingCert { peer_id, deadline: now + 10s }
  -> Processor does NOT receive an event

DeviceCertExchange received and verified
  -> Authenticated { peer_id, device_id, master_identity }
  -> Processor receives PeerAuthenticated event
  -> Mapping PeerId -> (DeviceId, IdentityPub) saved in event loop

Timeout 10s -> close connection
```

### x25519_pub

Passed in DeviceCertExchange. The Noise channel provides integrity -- a separate signature over x25519_pub is not needed (MITM is impossible after the Noise IX handshake). Stored in PeerRecord for board directed encryption.

---

## Discovery: Kademlia DHT

### Strategy: shared IPFS DHT initially, own namespace later

Initially use the shared IPFS DHT (`/ipfs/kad/1.0.0`):
- 200K+ nodes, bootstrap out of the box (IPFS bootstrap nodes)
- No chicken-and-egg problem
- Privacy is a minimal concern (we expose only provider queries, not data)
- Foreign DHT traffic is negligible (tens of KiB/s routing)

When the number of Viaticum nodes is sufficient (~100+) -- switch to the own namespace `/viaticum/kad/1.0.0` + own bootstrap nodes. One line in config.

### Discovery pattern

```rust
// Announce: "I am a Viaticum node"
let namespace_key = Key::from(sha256(b"/viaticum/peers/v1"));
kademlia.start_providing(namespace_key)?;

// Find Viaticum nodes:
kademlia.get_providers(namespace_key);
// -> list of PeerId + Multiaddr

// Address of a specific peer: identify + Kademlia routing table
```

Republish every 30 min. MemoryStore with a limit of **10240 records** (default 1024 is too small for 500+ nodes).

---

## NAT traversal: DCUtR + Circuit Relay v2

```
A finds relay R (any Viaticum peer with a public IP)
A publishes its relayed address in DHT
B -> R -> A: relay connection
DCUtR holepunch -> ~70% direct connection A<->B
Fallback: relay stays up
```

Transparent to code: `swarm.dial(peer_id)`.

### All nodes = relay

`relay::Behaviour` (server) and `relay::client::Behaviour` on all nodes. If a peer has a public IP -- libp2p automatically starts accepting relay connections. No user configuration.

### Circuit Relay v2: limits

Defaults: **2 minutes**, **128 KiB total** (aggregate volume, not rate).

The main protocol (PoS, Delete) goes through board -- relay limits are not a problem. Relay is needed for holepunch coordination. Heavy data (SymbolTransfer) -- direct connection only (after holepunch, or if at least one peer is public).

---

## Protocol: request-response with batch transfer

### Direct-connection operations

| Operation | Request | Response |
|-----------|---------|----------|
| Cert exchange | DeviceCertExchange | DeviceCertExchange |
| Symbol transfer | SymbolTransferBatch | SymbolStored |
| Symbol offer | SymbolOffer | SymbolAccept / SymbolReject |
| Restore | RestoreRequest | RestoreResponse |
| Board sync | BoardSyncRequest | BoardSyncResponse |
| Cluster sync | ClusterSyncRequest | ClusterSyncResponse |
| System state (DR) | SystemStateRequest | SystemStateResponse |
| System state push | SystemStateBackup | Ack |

### Batch transfer

One request = all symbols for one holder for one source block:

```
Source block 128 MB = 2048 symbols
/ 5 holders = ~410 symbols per holder = ~26 MB per request
```

Single stream, single response. Yamux automatically slices into 16 KiB frames (window auto-tuned). On disconnect -- retry the single request.

### MAX_MESSAGE_SIZE = 128 MB

Limit enforced in ViaticumCodec. With margin.

### Codec

```rust
impl request_response::Codec for ViaticumCodec {
    type Protocol = StreamProtocol;
    type Request = Message;
    type Response = Message;  // SymbolStored, SymbolAccept, RestoreResponse, Ack, etc.
}
```

Wire format `[u32 BE length][CBOR]` is unchanged. `frame_message()` and `from_cbor()` are reused.

```rust
const VIATICUM_PROTOCOL: StreamProtocol = StreamProtocol::new("/viaticum/1");
```

---

## NetworkBehaviour

```rust
#[derive(NetworkBehaviour)]
struct ViaticumBehaviour {
    viaticum: request_response::Behaviour<ViaticumCodec>,
    kademlia: kad::Behaviour<MemoryStore>,
    dcutr: dcutr::Behaviour,
    relay_client: relay::client::Behaviour,
    relay_server: relay::Behaviour,
    identify: identify::Behaviour,
}
```

MemoryStore: limit 10240 records. On restart -- DHT bootstrap again. A redb-backed store can be added later.

---

## SwarmHandle

```rust
pub struct SwarmHandle {
    cmd_tx: mpsc::Sender<SwarmCommand>,
    pub peer_id: PeerId,
    pub device_id: DeviceId,
    pub identity_pub: IdentityPub,
    master_signing_key: SigningKey,
    x25519_pub: [u8; 32],
}

enum SwarmCommand {
    SendMessage { peer_id: PeerId, message: Message, reply: oneshot::Sender<Result<Message>> },
    Dial { peer_id: PeerId },
    PublishDht,
}

enum ProtocolEvent {
    PeerAuthenticated {
        peer_id: PeerId,
        device_id: DeviceId,
        identity_pub: IdentityPub,
        device_cert: DeviceCertificate,
        x25519_pub: Option<[u8; 32]>,
    },
    InboundRequest {
        from_device: DeviceId,
        from_master: IdentityPub,
        message: Message,
        response_channel: ResponseChannel<Message>,
    },
    ConnectionClosed { peer_id: PeerId, device_id: DeviceId },
}

impl SwarmHandle {
    /// Send a message by DeviceId. Converts to PeerId internally.
    pub async fn send_to_device(&self, device: DeviceId, msg: &Message) -> Result<Message>;

    /// PeerAnnounce for board.
    pub fn build_peer_announce(&self, timestamp: Timestamp) -> PeerAnnounceMsg;

    /// Listen addresses.
    pub fn listen_addrs(&self) -> Vec<Multiaddr>;
}
```

---

## What changes in the code

### Remove

```
daemon/network/: connection.rs, handshake.rs, addr.rs
viaticum-core/messages/: HandshakeMsg, build_handshake, verify_handshake
viaticum-core/messages/: PeerDiscoveryRequestMsg, PeerDiscoveryResponseMsg (replaced by DHT)
viaticum-core/types/: NodeId
viaticum-core/constants/: ALPN
```

### Rewrite (10+ files)

```
daemon/network/mod.rs      -- NetworkHandle -> SwarmHandle
daemon/processor/mod.rs    -- ProtocolEvent dispatch
daemon/handle/mod.rs       -- Swarm creation
daemon/cli_server/mod.rs   -- addr format (Multiaddr)
daemon/system_state/mod.rs -- SwarmHandle
daemon/restore/mod.rs      -- SwarmHandle
daemon/cluster_sync/mod.rs -- SwarmHandle
daemon/dr/mod.rs           -- full rewrite

viaticum-core/types/mod.rs    -- DeviceId: [u8;16] -> [u8;32], PeerRecord keyed by DeviceId
viaticum-core/messages/mod.rs -- PeerAnnounceMsg without node_id, remove PeerDiscovery*
viaticum-core/cluster/        -- DeviceCertificate: device_id + device_pub_key -> single field
viaticum-core/trust/          -- two-level trust (device + master)
```

### Tests (~150 of ~895)

```
network/tests.rs      -- 37, full replacement
processor/tests.rs    -- ~40-50 (3279 lines)
backup/tests.rs       -- ~10-15
restore/tests.rs      -- ~28
cli_server/tests.rs   -- ~16
messages/tests.rs     -- NodeId, PeerDiscovery
trust/tests.rs        -- two-level model
cluster/tests.rs      -- DeviceCertificate
```

### Leave untouched

```
viaticum-core/: pos/, escrow/, placement/, budget/, erasure/, db/, config/
daemon/: relay/ (board), backup/ (send signature only), scheduler/, watcher/, identity/
```

---

## Board

libp2p has no store-and-forward. Board -- **primary transport** for protocol messages (PoS, Delete, Drop, broadcast). Board sync is unified as request-response `BoardSyncRequest/Response` over libp2p.

x25519_pub for board encryption is passed through DeviceCertExchange.

---

## Config

```toml
[network]
listen_port = 0
bootstrap_peers = []    # additional, optional
```

Relay is enabled on all nodes by default, not configurable.

---

## Implementation phases

### Phase 1: libp2p skeleton

- `libp2p = "0.56"` in Cargo.toml
- SwarmHandle, ViaticumCodec, ViaticumBehaviour
- DeviceCertExchange (first r-r after connect)
- PendingCert state machine
- Static peer directory for testing without DHT
- Unit tests: two peers, message exchange

### Phase 1.5: Two-level trust (core, no network)

- device_trust, master_trust, effective_trust in viaticum-core
- DeviceId [u8;32], updated DeviceCertificate
- Trust tests
- Update `docs/logic.md` (trust algorithm changes)

### Phase 2: Processor + DR

- ProtocolEvent dispatch
- Board sync after PeerAuthenticated
- Rewrite DR
- Update E2E scripts
- Processor tests

### Phase 3: Kademlia DHT

- Shared IPFS DHT (`/ipfs/kad/1.0.0`)
- Bootstrap, periodic publish (start_providing)
- PeerRecord keyed by DeviceId
- MemoryStore limit 10240

### Phase 4: NAT traversal

- relay_client + relay_server + dcutr
- E2E: Docker with two NAT networks

### Phase 5: Cleanup + documentation

- Remove iroh
- Remove HandshakeMsg, NodeId, EndpointAddr, ALPN, PeerDiscoveryRequest/Response
- Update documentation:
  - `docs/protocol.md` -- wire format, DeviceCertExchange, batch transfer, remove Handshake/NodeId/PeerDiscovery
  - `docs/architecture.md` -- crate structure (iroh->libp2p), SwarmHandle, network module
  - `docs/overview.md` -- identity model, network description
  - `docs/tech-debt.md` -- close iroh relay issue, remove per-exchange QUIC streams
  - `docs/features.md` -- update priorities (NAT resolved)
  - `CLAUDE.md` -- minor edits if iroh is mentioned

### Rollback

- Phase 1-2: branch `feat/libp2p`, rollback = don't merge
- Phase 3+: committed to libp2p

---

## Open questions

1. **DHT bootstrap from restricted-network countries.** IPFS bootstrap nodes may be unreachable. Self-hosted bootstrap as fallback. Needs testing.

2. **INHERITANCE_FACTOR (0.3-0.5).** Determine experimentally. Too high -- sybil risk, too low -- slow start.

3. **Switch to own DHT namespace.** At ~100+ Viaticum nodes, switch to `/viaticum/kad/1.0.0` + own bootstrap. One line in config.

---

## Implementation clarifications

Minor discrepancies between this design and the current protocol.md. Not architectural, but worth recording:

1. **RestoreResponse** -- in the current protocol, restore is answered via `SymbolTransfer` + `RestoreDenied`, not a separate type. During implementation: either introduce `RestoreResponse { symbols }`, or use the existing `SymbolTransfer`. `RestoreDenied` -- an alternative response, add to the operations table.

2. **BoardSync** -- currently a single type `BoardSyncMsg`. During implementation, split into `BoardSyncRequest` / `BoardSyncResponse` for the r-r model.

3. **SystemStateAck** -- the table says `Ack`, the enum has `SystemStateAck(SystemStateAckMsg)`. Use the existing type.

4. **SymbolTransferBatch** -- the table says `SymbolTransferBatch`, the enum has `SymbolTransfer(SymbolTransferMsg)`. Batch semantics via content (Vec of symbols), not a new type. Clarify during implementation.

5. **PeerAnnounceMsg** -- explicitly board (broadcast). Not listed in the "Two delivery channels" section, but obvious.

6. **Phase 1.5 and Phase 1** -- DeviceId changes in 1.5, SwarmHandle uses DeviceId in 1. Implement 1.5 before or in parallel with 1, not after.
