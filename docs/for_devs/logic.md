# Viaticum Logic

All algorithms and formulas in one place. Constants are in `viaticum-core::constants`.

## Trust

Pairwise score computed from Proof-of-Storage history and storage reciprocity.

```
trust = (KP * P + KI * I) * clamp(S, S_MIN, S_MAX)
```

| Component | What | Range |
|-----------|------|-------|
| P | 4-week rolling PoS pass rate (challenged/passed) | [0, 1] |
| I | Cumulative mean of all weekly pass rates | [0, 1] |
| S | Pairwise storage ratio: `bytes_they_store_for_us / bytes_we_store_for_them` | clamped [0.1, 1.0] |

**Constants:** KP=0.4, KI=1.75, P_WINDOW=4 weeks, INITIAL_P=0.5, S_MIN=0.1, S_MAX=1.0

**Behavior:**
- New peer: P=0.5, I=0, S=1.0 -> trust = KP*0.5 = 0.20 (low but nonzero — raised from 0.1 so a new peer can still win some holder slots)
- After 4 weeks of perfect PoS: P=1.0, I=1.0 -> trust up to (0.4+1.75)*S = 2.15*S
- Free-rider (S near 0): multiplied by 0.1 -> trust capped at ~10% of full value
- P reacts to recent behavior (4-week window), I stabilizes long-term reputation

## Two-level trust (from ε.0)

Trust is computed at two levels: device and master.

**device_trust(DeviceId):** earned via PoS responses. Starts at zero. Specific to hardware.
**master_trust(IdentityPub):** aggregated from device_trust of all known devices. Survives device replacement.
**effective_trust(DeviceId):** what placement uses.

Formula:
  dt   = compute_combined(device.trust_p, device.trust_i, s=1.0)
  mt   = master.combined
  base = mt * TRUST_INHERITANCE_FACTOR  (= 0.3)
  effective = base + dt * (1.0 - base / MAX_COMBINED_TRUST)

S-component (storage reciprocity) is NOT part of effective_trust.
It is applied by callers on top: effective * clamp(S, S_MIN, S_MAX).

master_trust update:
  weighted_average(dt_combined per device, weight = symbols_stored for that device)

Constants: TRUST_INHERITANCE_FACTOR=0.3, MAX_COMBINED_TRUST=KP+KI=2.15

### Partition healing

Trust state is **per-node local** by design — there is no gossip protocol for trust reconciliation. After a network partition heals, nodes on each side hold divergent trust views for the same peer (one side saw PoS responses, the other side did not).

**Behavior:** the side that saw the peer go silent treats it as Timeout/Lost; the side where the peer was active retains accumulated trust. After partition heals, the silent-side nodes:
1. Challenge the peer aggressively (low trust → high PoS frequency)
2. Trust rebuilds over P_WINDOW_WEEKS (4 weeks rolling window)
3. Repair may have already migrated some symbols during the partition — duplicates are tolerated

**Recovery time:** O(P_WINDOW_WEEKS) = 4 weeks. Acceptable for cold backup (time constant = 1 week). Repair guarantees data survival even in worst case.

This is intentional: P2P trust by definition is pairwise and local. Cross-node trust reconciliation would require additional protocol surface (gossip, conflicts, weights) with marginal benefit for cold backup workload.

## Placement

Distributes repair symbols across holders proportional to trust.

**Weight formula:** `weight = trust / sqrt(1 - trust)` (mean-variance optimum from portfolio theory)

**Algorithm:**
1. Filter candidates with trust >= 1.0 (degenerate)
2. Enforce limits: min(MAX_HOLDERS_PER_BLOCK, N/MIN_SYMBOLS_PER_HOLDER) holders
3. Keep top candidates by weight, discard rest
4. Compute normalized shares: `share_i = weight_i / sum(weights)`
5. Initial counts: `round(N * share_i)`, minimum 1 per holder
6. Cap redistribution: excess above `max_per_holder` redistributed proportionally (10 iterations)
7. Adjust total to exactly N symbols (reduce from lowest-weight, add to highest-weight)
8. Assign ESI ranges sorted by descending symbol count

**Limits:**
- MAX_HOLDERS_PER_BLOCK = 30
- MIN_SYMBOLS_PER_HOLDER = 32 (2 MB at T=64KB)
- Concentration cap: `max_per_holder = (1 - 1/overhead) * 0.85 * N` (from ErasureParams)
- Hard limit: K_eff - 1 per holder (more = one holder can decode entire file)

## Erasure Coding

RaptorQ (RFC 6330) via `raptorq` crate.

| Parameter | Value | Notes |
|-----------|-------|-------|
| Symbol size T | 64 KB (65535 bytes) | Fixed, max for raptorq crate (u16 limit) |
| Source block | 128 MB default | Configurable: 16-128 MB via config.toml |
| K | block_size / T | 2048 at 128 MB |
| K_eff | K + 3 | Decode overhead (conservative) |
| Overhead | 1.5 + importance * 1.5 | Range 1.5x (importance=0) to 3.0x (importance=1) |
| N (total symbols) | ceil(K_eff * overhead) | Total repair symbols to generate |
| Peak RAM | ~2x block_size | RaptorQ needs full block in memory |

**Per-holder binding:** Each holder's symbols are XOR'd with `ChaCha20(HKDF(block_id, holder_id))`. Prevents collusion — two holders can't pool symbols because each has unique binding.

**Dedup:** Content-addressed. Same content_hash -> same ciphertext -> same source_block_id -> zero additional traffic/storage.
The dedup target is only a block the owner keeps **in service**: its record exists, its
status is `Active`, and none of its placements is `Deleting`. The same rule
(`Serviceability`) is used by the dedup of an event, the flush-time "already in the
network" check, the choice of a block generation, the reconcile, `is_safe_to_delete`,
the files view's `effective_status` and the watch-root rule. A file whose content lies
only on a block being released (a file put back after its Delete went out, the same PDF
downloaded again) is backed up again.

**Block generation (N1).** The seal is deterministic, so the same packed plaintext (a
file returned to its path in a pack of one, a large file) would get the id of the block
being released — the id an old Delete, still replayed by mailbox postmen, addresses. The
nonce is therefore derived with a generation `g`: HKDF-SHA256(salt = blake3(compressed),
ikm = epoch key, info = `"viaticum-block-nonce"` for `g = 0`, `"viaticum-block-nonce/generation" || g`
(LE) otherwise). The packing takes the lowest `g` whose id has no record (free) or is in
service (kept as it is); ids in the release window or being released are skipped. The
choice is re-checked inside the write transaction. `g` is stored in the block record
(`seal_generation`, omitted when 0, so blocks and SystemState from before are unchanged)
and rides SystemState; every rebuild (worker, PoS, local restore tier) seals at it.
Decryption reads the nonce from the blob and needs no generation. An id becomes free only
after `CleanupBlock`, no earlier than the holder window after the Delete (until L2 that
window is counted from the theoretical release time — owner deletion + owner window — not
from the moment the Delete was actually published; a node that was off longer than the
owner window can therefore free an id while its late Delete still lives), and a Delete
lives at a postman at most its TTL plus one sweep: `TTL + sweep < holder window` is a
compile-time assertion.

**Reconcile.** At start and every `max(1 h / time_scale, 60 s)` the backup coordinator
lists records present on this device whose current version is on a block being released
or missing, or is pending and in no packing queue (a `kill -9` before the idle flush),
and hands the paths to the watcher. The watcher re-submits a path as `Modified` only under
an active, accepted watch root with the recorded identity, through the scan filters, for
an existing file; one INFO line per root per batch. The reconcile never deletes, marks or
reads a file; a path whose record does not change after its re-submission backs off
(1, 2, 4 … 24 passes).

## Proof-of-Storage (PoS)

Verifies holders still store our symbols. Adaptive scheduling, state machine for status tracking.

### Challenge Scheduling

```
volume_factor = ceil(symbol_count / 1000)
trust_factor  = 2.0 - trust    (range [1.0, 2.0])
challenges_per_week = base * volume_factor * trust_factor    (ceil, min = base)
```

base = 1 challenge/week. Low-trust holders challenged more often. Large holders (many symbols) challenged more.

### Verification

Owner re-encodes the challenged symbols from its local source block, applies per-holder binding, and computes the expected Samsara chain hash (`h0 = SHA256(challenge_id)`, then `h_i = SHA256(h_{i-1} || symbol_data)` over the ESI range, ascending). It sends a PosChallenge covering that ESI range; the holder computes the same chain hash over its stored symbols and returns only the hash. Owner compares hashes — no raw symbol data crosses the wire.

### State Machine

```
             Pass
Alive ←──────────────── any state
  │
  │ Timeout (1 miss)
  ↓
Uncertain ────────────→ Alive (on Pass)
  │
  │ Timeout (3 cumulative misses)
  ↓
PresumedLost ─────────→ Alive (on Pass)
  │                     triggers Repair
  │ Fail / NotHeld
  ↓
Lost ─────────────────→ (terminal, triggers Repair)

Fail / NotHeld from any state → Lost (immediate, triggers Repair)
Lost / Deleting + any outcome → no-op
```

**Timeout:** 7 days (POS_TIMEOUT_SECS).

### Trust manipulation window (acceptable trade-off)

Attacker can accumulate honest trust over 4+ weeks, then suddenly stop holding symbols. PoS state machine takes up to 3 consecutive Timeouts (3 weeks worst case) before placement transitions Lost → Repair. So worst-case data exposure = ~3 weeks × N blocks before repair triggers.

This is acceptable for cold backup (time constant = 1 week):
- Restore window in DR is days-to-weeks anyway
- Repair starts well before critical loss
- Tightening detection requires either expensive per-block heartbeats (defeating cold semantics) or randomized PoS challenges that don't compose with chain-hash binding

If shortening this window becomes important: lower POS_TIMEOUT_SECS for high-importance blocks (e.g. 2 days for importance ≥ 0.8).

### Outsourcing attack (documented limitation)

Malicious holder can keep zero local storage and reconstruct symbols on demand: at challenge time, download K_eff symbols from other honest holders, decode source block, re-encode with own chain-hash binding, respond correctly. Chain hash prevents collusion-pooling but does not cryptographically force local storage.

Economically irrational for cold backup target (home NAS, metered upload):
- Storage saved per block ≈ K/N × block_size (~17 MB for 128 MB block, 274 symbols)
- Bandwidth cost per week ≈ K_eff × symbol_size (~128 MB download to reconstruct)
- Cost > savings, so honest behavior is the rational equilibrium

Acknowledged limitation — not fixed in alpha. Would require either random ESI subset challenges (incompatible with current chain hash) or shorter timeouts forcing constant reconstruction.

## Restore access (no escrow gate in v1)

The holder serves the owner's own symbols while it holds them. There is no restore budget and no
refusal: a legitimate owner must get their files back on the worst day, including the first week
after install and on every retry. The holding is found by the pair (block, requester master), so a
foreign master gets an empty response. Every holding status is served except `MarkedForDelete`
(the owner itself asked to delete it; restore-i16).

**Accounting only:** `record_restore_served` keeps a per-owner count of bytes served (atomic
read-modify-write). Nothing reads it for a decision; it is input for a future escrow-as-debt in an
open network.

## Repair

Triggered by PoS state machine (PresumedLost or Lost).

1. RepairAgent scans placements with status PresumedLost or Lost
2. For each affected source block: re-encode symbols from local blob (same as original encoding)
3. Run fresh placement round to assign new holders
4. Write new symbols, update placement records

Graduated response: PresumedLost triggers repair but doesn't zero trust (holder may come back). Lost = permanent, trust penalized via PoS outcome recording.

### ESI numbering (repair-i8, repair-i9, repair-i10)

An ESI number of a block is given to one placement row only and is never given out again while the block lives:

- **Cursor.** Fresh numbers start at `max(esi_high_water, end of every placement row of the block, cluster namespace start)`. Rows of every status count: a `Lost` or `Deleting` holder may still have its symbols on disk (an advance DropNotice holds until its deadline; a PoS `Fail` leaves bad bytes). `esi_high_water` is a field of `SourceBlockRecord`, raised in the same transaction that writes the `Offered` rows, never lowered (the DB keeps the larger value on every write) and carried in SystemState with the record — so an overwritten or deleted top row does not move the cursor back.
- **Re-offer.** A device with an `Offered` row (a `SymbolReject`, an unfinished delivery) gets its own range again — the only repeat of numbers (repair-i9). Every other device gets fresh numbers, including a device whose row is `Lost`: its old files may be bad, and the holder treats a symbol file of the right length as "already held" (repair-i10).
- **Ceiling.** raptorq accepts ESIs below 2^24 (`MAX_ESI_EXCLUSIVE`), for every device whatever its cluster namespace. Fresh numbers stop there: the plan offers only what is left, and the block is reported as not repairable (`blocks_esi_exhausted` in `status --json`, a line on the Dashboard, a WARN once a day per block; another WARN once per block when the cursor passes 2^23). Old numbers are not reused.

Consequence for DropNotice and PoS: the ranges of different rows of a block never overlap, so a notice or a challenge names one placement.

## Deletion

Double cooldown protects against ransomware and accidental deletion.

### Flow

1. File deleted on device -> `local_state = Deleted(timestamp)`
2. **Multi-device check:** wait until ALL cluster devices mark file deleted
3. **Owner cooldown:** 4 weeks (OWNER_DELETE_COOLDOWN_SECS)
4. Send DropNotice to each holder
5. **Holder cooldown:** 4 weeks (HOLDER_DELETE_COOLDOWN_SECS)
6. Physical symbol deletion after holder cooldown
7. Source block cleanup when all placements cleaned

**Total protection window:** 8 weeks (4 owner + 4 holder).

### Shared blocks (release guard)

Records are the unit of deletion; blocks are the unit of release. One block can be
referenced by several records: every file of a pack, two paths with identical content
(dedup), a restored file moved to a new path. `DeletionEngine::process_cooldowns`
therefore decides per block, over the whole catalog:

- **Live reference wins.** A block referenced by the current version (the last version,
  and the last backed-up one) of any record not deleted on every device gets no
  DropNotice, placement cleanup or block cleanup. Deleting one file of a pack never
  releases its live siblings. Old versions of live files are not protected (the network
  holds the current state, not history).
- **Latest deletion starts the clock.** When no live record references the block, the
  owner and holder cooldowns run from the latest deletion among the records that
  reference it, so each deleted file keeps its full undo window even if a pack sibling
  was deleted long ago.
- A block whose DropNotice already went out is not recalled if a live record starts
  referencing it again; it just gets no further deletion actions. A file put back after
  that is not deduplicated onto the released block: it is backed up again, under a new
  block generation when the plaintext is the same (see Erasure Coding, "Block generation").

Deleted files inside a still-live pack stay in the network (and restorable) as long as
the pack lives; reclaiming that space is vacuum's job (not implemented).

### Vacuum

Pack-type source blocks with > 50% invalid files -> repack valid files into new block, mark old block Stale -> enters deletion flow.

## Mailbox Bus

Directed store-and-forward for offline peers (replaced the epidemic relay board — see
[protocol.md §1.5](protocol.md), [ADR-004](decisions/ADR-004-mailbox-bus.md)).

- Directed, not gossip: every entry is addressed to one recipient's master identity. No hops, no flooding.
- Postmen: the peers Kademlia-closest to SHA256(target_pub) store entries for that target.
- Publish: deposit with the closest MAILBOX_WRITE_FANOUT (30); durable once >=1 Acks.
- Poll: the addressee fetches from the closest MAILBOX_READ_FANOUT (300), dedups by msg_id.
- Classes + TTL: SelfPointer 5y, PosChallenge/PosResponse 7d, DropNotice/DeleteRequest 14d, Revocation 30d, Generic 90d.
- Authenticity: envelope unsigned; each payload carries an Ed25519 sig verified against the sender (Noise IX gives confidentiality — no per-message ECDH).
- Limits: 256 KB per entry, 100 MB per target; TTL sweep + membership sweep reclaim storage; SelfPointer is high-trust (TTL-only eviction).

## Backup Flush Triggers

Files queue in packing queues (one per watched directory).

| Trigger | Condition | Force? |
|---------|-----------|--------|
| Size | Queue >= source_block_size (128 MB default) | No (natural) |
| Idle | No new events for 1 hour (FLUSH_IDLE_SECS) | Yes (flush any size >= MIN_BATCH) |
| Fallback | 24 hours since last flush (FLUSH_FALLBACK_SECS) | Yes |
| Manual | `viaticum backup` CLI command | Yes |

MIN_BATCH_BYTES = 1 MB. Force=true flushes any queue >= 1 MB regardless of source_block_size.

## Commitment & Reliability

### Commitment Score

Estimates holder's likelihood of keeping our symbols. Range [0, 1].

```
score = w_pos * pos_signal + w_pressure * (1 - pressure) + w_age * age_signal + w_priority * priority_signal
```

Weights: pos=0.5, pressure=0.25, age=0.15, priority=0.10

Tiers: High (>=0.75), Medium (>=0.45), Low (>=0.20), AtRisk (<0.20).

### Reliability Forecast

Probability that a source block can be decoded in the future.

```
P(block alive) = P(Binomial(N, p) >= K_eff)
```

N = total alive symbols across holders, p = weighted mean survival probability (from commitment scores), K_eff = minimum symbols for decode.

Blocks below RELIABILITY_REPAIR_THRESHOLD (99%) flagged as needs_repair.

## Eviction (Holder-Side)

When disk pressure rises, holder must choose which symbols to drop.

```
priority = importance * trust_of_owner * (1 + age_bonus)
age_bonus = min(weeks / 26, AGE_BONUS_CAP=0.3)
```

Hysteresis: new data must beat existing priority by 20% to displace (EVICTION_HYSTERESIS).

Eviction order: lowest priority first. Drop notice sent to owner 7 days before deletion (DROP_NOTICE_WINDOW_SECS).

## Multi-Device Cluster

One identity (seed phrase) across multiple devices.

### Key Hierarchy

```
BIP39 mnemonic (24 words)
  -> seed (HKDF-SHA256)
    -> master_key (HKDF, domain "viaticum-master")
      -> device_key (HKDF, domain "viaticum-device-{label}")
        -> device_id = BLAKE3(identity_pub + label)
      -> epoch_key (HKDF, domain "viaticum-epoch-{counter}")
        -> file encryption keys

```

### Device Registration

- DeviceCertificate: device_pub + label, signed by master_key
- RevocationCertificate: device_pub, signed by master_key -> epoch rotation
- ClusterState: tracks active devices, revoked keys, epoch counter

### ClusterSync

Event log exchange between devices: ClusterSyncRequest/Response over P2P connection. Cursor-based incremental sync.
