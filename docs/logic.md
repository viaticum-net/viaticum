# SyncBack Logic

All algorithms and formulas in one place. Constants are in `syncback-core::constants`.

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

**Constants:** KP=0.4, KI=1.75, P_WINDOW=4 weeks, INITIAL_P=0.1, S_MIN=0.1, S_MAX=1.0

**Behavior:**
- New peer: P=0.1, I=0, S=1.0 -> trust = KP*0.1 = 0.04 (low but nonzero)
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
| N (total symbols) | ceil(K * overhead) | Total repair symbols to generate |
| Peak RAM | ~2x block_size | RaptorQ needs full block in memory |

**Per-holder binding:** Each holder's symbols are XOR'd with `ChaCha20(HKDF(block_id, holder_id))`. Prevents collusion — two holders can't pool symbols because each has unique binding.

**Dedup:** Content-addressed. Same content_hash -> same ciphertext -> same source_block_id -> zero additional traffic/storage.

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

Owner picks random ESI (deterministic: FNV-1a hash of block_id + holder_id + nonce), sends PosChallenge. Holder returns bound symbol data. Owner re-encodes from local source block and compares byte-for-byte.

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

## Escrow

Trust-based restore gating. Prevents hit-and-run: new peer can't dump data and immediately restore.

```
max_restorable_gb = FREE_TIER_GB + trust * escrow_trust_factor
```

**Constants:** FREE_TIER_GB = 1.0, DEFAULT_ESCROW_TRUST_FACTOR = 20.0

**Example:** trust=2.0 -> budget = 1 + 2.0 * 20.0 = 41 GB. Trust=0 -> 1 GB (demo credit, always available).

Holder checks on RestoreRequest. If restore_gb > budget -> RestoreDenied with current_trust, needed_trust, budget.

## Repair

Triggered by PoS state machine (PresumedLost or Lost).

1. RepairAgent scans placements with status PresumedLost or Lost
2. For each affected source block: re-encode symbols from local blob (same as original encoding)
3. Run fresh placement round to assign new holders
4. Write new symbols, update placement records

Graduated response: PresumedLost triggers repair but doesn't zero trust (holder may come back). Lost = permanent, trust penalized via PoS outcome recording.

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

### Vacuum

Pack-type source blocks with > 50% invalid files -> repack valid files into new block, mark old block Stale -> enters deletion flow.

## Epidemic Relay

Store-and-forward gossip for offline peers.

- Board: append-only file, entries with hop count and TTL
- Hop limit: <= 2 (MAX_RELAY_HOP). Each forward increments hop.
- TTL: 7 days (RELAY_TTL_SECS). Expired entries pruned.
- Directed entries: encrypted with ECDH(sender, recipient) -> ChaCha20-Poly1305
- Broadcast entries: signed but unencrypted
- Board limits: max 2000 entries, max 8 MB total
- Exchange: BoardSync message on peer connect

## Backup Flush Triggers

Files queue in packing queues (one per watched directory).

| Trigger | Condition | Force? |
|---------|-----------|--------|
| Size | Queue >= source_block_size (128 MB default) | No (natural) |
| Idle | No new events for 1 hour (FLUSH_IDLE_SECS) | Yes (flush any size >= MIN_BATCH) |
| Fallback | 24 hours since last flush (FLUSH_FALLBACK_SECS) | Yes |
| Manual | `syncback backup` CLI command | Yes |

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
    -> master_key (HKDF, domain "syncback-master")
      -> device_key (HKDF, domain "syncback-device-{label}")
        -> device_id = BLAKE3(identity_pub + label)
      -> epoch_key (HKDF, domain "syncback-epoch-{counter}")
        -> file encryption keys

```

### Device Registration

- DeviceCertificate: device_pub + label, signed by master_key
- RevocationCertificate: device_pub, signed by master_key -> epoch rotation
- ClusterState: tracks active devices, revoked keys, epoch counter

### ClusterSync

Event log exchange between devices: ClusterSyncRequest/Response over P2P connection. Cursor-based incremental sync.
