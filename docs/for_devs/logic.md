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

## Escrow

Contribution-based restore gating. Prevents hit-and-run: a peer cannot dump data and immediately restore — it must first store other peers' data for some time to accumulate restore budget.

```
restore_budget_gb = stored_gb_days / k_factor
remaining_budget  = restore_budget_gb - already_restored_gb
```

Where `stored_gb_days` is the cumulative GB·day contribution the owner earned by hosting symbols for other peers (integrated over time since each placement was `received_at`).

**Constants:** `DEFAULT_ESCROW_K_FACTOR = 7.0` (i.e. store 1 GB for 7 days → earn 1 GB of restore credit). See `viaticum-core/src/constants.rs`.

**Example:** hold 100 GB for 14 days → `stored_gb_days = 1400`, budget = `1400 / 7 = 200 GB`. After restoring 50 GB, `remaining_budget = 150 GB`.

Unlike the earlier trust-based formula, the new scheme has NO free tier: a brand-new peer with zero contribution has zero restore budget. `FREE_TIER_GB` still exists but now belongs to the owner-side budget planner (minimum outgoing backup budget), not escrow.

**Accounting:**
- `stored_gb_days` grows monotonically as time passes (holder-side, `db::stored_for_peer_gb_days`).
- `already_restored_gb` is `restored_total_bytes / BYTES_PER_GB` from `record_restore_served` — also monotonic.
- Budget therefore always grows unless a restore is served.
- Atomic read-modify-write in `record_restore_served` closes a TOCTOU race on concurrent restores (see db/mod.rs).

**Check on RestoreRequest:**
1. Holder looks up `stored_gb_days(owner, now)` and `already_restored_gb(owner)`.
2. Computes `remaining = (stored_gb_days / k_factor) - already_restored_gb`.
3. If `requested_gb > remaining` → `RestoreDenied { restore_budget_gb, already_restored_gb, needed_gb_days }`.

**No trust dependency.** The earlier `max_restorable_gb = FREE_TIER_GB + trust * escrow_trust_factor` formula is obsolete — trust now controls only placement weights (P, I, S factors), not restore gating.

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
  referencing it again; it just gets no further deletion actions.

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
