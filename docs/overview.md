# Viaticum Overview

Decentralized P2P cold backup system. Peers store encrypted fragments of each other's files. Trust is earned through Proof-of-Storage over time. No tokens, no governance — GB-days as currency, reputation as credit limit.

**Competitor is "nothing"**, not AWS. 98% reliability >> 0%.

## How It Works (end-to-end)

### Backup

1. **Watcher** monitors directories (notify crate), debounces events (30 min)
2. **DirtyEvent** sent to BackupCoordinator with file path, size, content hash, importance
3. **Packing** — files queue by category (photo/video/document/other); flush when queue >= source-block size (default 128 MB, configurable), or 1 hr idle, or 24 hr fallback (min batch 1 MB)
4. **Dedup** — same content_hash = same ciphertext = same source_block_id = zero traffic
5. **Encrypt** — block key = HKDF(epoch_key) -> ChaCha20-Poly1305
6. **Encode** — RaptorQ (RFC 6330): source block -> N repair symbols (N = k_eff * overhead, overhead = 1.5 + importance * 1.5)
7. **Per-holder binding** — each holder's symbols XOR'd with ChaCha20(HKDF(block_id, holder_id)) -> anti-collusion
8. **Placement** — select holders by trust-weighted allocation, distribute symbols
9. **Write** — symbols stored locally + sent to holders via SymbolTransfer messages

### Restore

1. CLI: `viaticum restore <path>` (selective, by path/version/date)
2. Look up FileRecord -> versions -> source_block_ids -> placements
3. Fetch symbols from holders (RestoreRequest -> RestoreResponse) or local disk
4. Need K_eff = K + 3 symbols to decode (any K_eff of N suffice — RaptorQ is rateless)
5. Decode -> decrypt -> extract files -> write to disk

### Proof-of-Storage (PoS)

1. Scheduler issues challenges adaptively: `challenges/week = base * ceil(symbols/1000) * (2 - trust)`
2. Owner computes the expected Samsara chain hash from its local source block (re-encode + per-holder binding), sends PosChallenge over an ESI range
3. Holder computes the same chain hash over its stored symbols and returns only the hash -> owner compares (no raw symbols on the wire)
4. Pass -> trust grows. Timeout: Alive -> Uncertain (1 miss) -> PresumedLost (3 misses, triggers Repair). Explicit Fail/NotHeld -> Lost directly (skips the chain)
5. PoS timeout: 7 days (covers relay forwarding)

### Repair

1. RepairAgent scans for Lost/PresumedLost placements
2. Re-encode symbols from local source block blob
3. Re-place on new holders via fresh placement round

### Peer Discovery

1. Bootstrap peers from config: `[network] bootstrap_peers = ["DeviceId@ip:port"]`
2. **Bootstrap auto-connect:** on daemon startup, connect to bootstrap peers and send PeerDiscoveryRequest to learn their peer lists (1-hop)
3. On connect: PeerAnnounce exchange (identity, node_id, addresses)
4. PeerDiscoveryRequest/Response: request peer list from any authenticated connection
5. Epidemic relay: BoardSync messages gossip peer info (hop <= 2, TTL 7 days)
6. libp2p (TCP+Noise+Yamux) transport with NAT traversal (relay + DCUtR)

### Disaster Recovery

1. `viaticum dr --mnemonic "24 words" --peer <addr>` — standalone, no daemon needed
2. Derive identity from seed phrase, open fresh DB
3. Visit the provided seed peers, send SystemStateRequest to each (no peer-discovery expansion since ε.2)
4. Limits: 500 peers, 10 blobs; per-connection auth timeout 15s, request timeout 10s
5. Select freshest blob (max created_at), decrypt with identity key, restore DB
6. Run `viaticum daemon` then `viaticum restore <path>` to recover files

### Deletion

1. Watcher detects file deleted -> mark device state = Deleted
2. Multi-device: wait until ALL devices mark deleted
3. Owner cooldown: 4 weeks (ransomware protection)
4. Send DropNotice to holders -> holder cooldown: 4 weeks
5. Total: 8 weeks before physical symbol deletion
6. Vacuum: if > 50% files in a packed block are invalid -> repack valid files

## Module Map

### viaticum-core (pure logic, no async, no network)

| Module | Description |
|--------|-------------|
| `types` | Newtype ID wrappers (SourceBlockId, IdentityPub, DeviceId, FileId, NodeId), domain structs (FileRecord, SourceBlockRecord, SymbolPlacement, PeerRecord) |
| `constants` | All tunable protocol constants |
| `trust` | TrustEngine: `trust = (KP*P + KI*I) * clamp(S, 0.1, 1.0)` |
| `escrow` | Contribution-based restore gating: `restore_budget_gb = stored_gb_days / factor` |
| `placement` | Symbol allocation: `weight = trust/sqrt(1-trust)`, cap, MAX_HOLDERS=30 |
| `budget` | Owner backup budget estimation, holder eviction priority |
| `erasure` | ErasureEncoder trait + RaptorQ impl, per-holder XOR binding |
| `cluster` | Multi-device identity: device certs, epoch keys, revocation |
| `db` | redb schema: files, source blocks, placements, peers, holdings, events |
| `messages` | Wire messages (CBOR): 20+ message types |
| `config` | TOML config loading and validation |
| `system_state` | SystemState snapshot/restore, CBOR+zstd+ChaCha20-Poly1305 pack/unpack |
| `pos` | PoS challenge/verify, adaptive scheduling, state machine |
| `commitment` | Holder eviction risk estimation from PoS history + disk pressure |
| `reliability` | P(block recoverable) = P(Binomial(N,p) >= K_eff) |
| `deletion` | Double cooldown (4wk+4wk), vacuum, multi-device coordination |
| `importance` | File-importance classification by type + burst (rare-moment) detection |

### viaticum (daemon + CLI)

| Module | Description |
|--------|-------------|
| `handle` | Top-level wiring: starts all subsystems, owns DaemonState |
| `processor` | Message router: dispatches all incoming messages to handlers |
| `network` | libp2p transport: SwarmHandle, Kademlia DHT, NAT traversal (relay + DCUtR) |
| `backup` | BackupCoordinator: watcher events -> dedup -> pack -> encode -> distribute |
| `restore` | RestoreCoordinator: fetch symbols -> decode -> decrypt -> write files |
| `repair` | RepairAgent: scan lost placements -> re-encode -> re-place |
| `watcher` | Filesystem watcher (notify): recursive, debounce, DirtyEvent emission |
| `scheduler` | PoS challenge scheduling, timeout detection |
| `web_api` | HTTP + token API: serves both the CLI and the web UI (status, files, restore, etc.) |
| `relay` | Epidemic relay board: store-and-forward, hop-limited gossip |
| `cluster_sync` | Event log exchange between devices of same cluster |
| `identity` | BIP39 mnemonic -> seed -> HKDF key derivation, identity file management |
| `system_state` | Daemon wrappers: snapshot+encrypt, periodic push to peers, bootstrap discovery |
| `dr` | Disaster recovery CLI: seed-peer visit, blob collection, DB restore from seed phrase |
| `work_pipeline` | Unified work queue: backup, repair and PoS tasks scheduled and run together |
| `watch_admin` | Live add/remove of watched folders without restarting the daemon |
| `symbol_fetch` | Fetch unbound symbols from holders (shared by restore and repair-from-peers) |
| `holdings_integrity` | Periodic scan that symbols held for others still exist on disk |
| `cli` | Clap CLI: daemon, init, status, files, versions, restore, device, dr, connect, open, token |

## Current State

- **Full test suite green, clippy clean**
- Phases 1-7 complete (core logic, daemon wiring, P2P networking)
- δ.1 Database Reliability complete: crash safety, DB backup to peers, DR from seed phrase
- Real-world P2P tested: LAN (Netbird) + NAT (relay + DCUtR, both peers behind NAT)
- All features wired: escrow check, effective_quota, device add/revoke, SymbolAccept->BackupCoordinator

See [features.md](features.md) for the roadmap and [usage.md](usage.md) for how to use it.
