# RaptorQ in β: how it works

*Decision made: RS → RaptorQ. This document is a reference sheet for the concrete design.*

---

## Terminology

| α (old) | β (new) | What it is |
|---------|---------|------------|
| Unit (32 MB) | Source block | Data to be encoded (a file or a batch of files) |
| Shard | Symbol (encoding symbol) | A single chunk of encoded data, T bytes |
| shard_id | ESI (Encoding Symbol ID) | Symbol identifier (integer 0, 1, 2, ...) |
| k-of-n (fixed) | K source symbols, N distributed | K = minimum needed to decode, N = how many were distributed |
| Reed-Solomon | RaptorQ (RFC 6330) | Erasure coding algorithm |

---

## Key parameters

### T = 64 KB (symbol size, fixed)

One symbol = 64 KB = transfer unit = max message payload. Maximum for the raptorq crate (u16).

### Source block = 128 MB (the only parameter)

Everything is source blocks of 128 MB. Small files → batched up to 128 MB. Large files → chunked at 128 MB.
K = 2048. Peak RAM ≈ 250 MB (safe for low-end machines and NAS devices).
Max file size: no limit.

### Formulas

```
K = 2048                                // fixed (128 MB / 64 KB)
K_eff = K + 3 = 2051                    // decode overhead
N = K_eff × overhead(importance)
overhead = 1.5 + importance × 1.5       // 1.5x..3.0x
reliability = P(Binomial(N, p) ≥ K_eff)
```

Overhead for 99.9% reliability at K=2048: ~1.55x. Max file size: no limit.

---

## File grouping

```
< 128 MB   → batch up to 128 MB (grouped by data type)
≥ 128 MB   → chunk at 128 MB
```

No max file size limit.

Files are grouped by type: photos with photos, documents with documents, video with video.

### Versioning and vacuum (universal rules)

A file is changed or deleted → new version goes into a NEW batch (the old batch is not touched).

Vacuum: >50% of files in a batch are invalid → repack the current files, invalidate the old batch (cooldown → delete symbols). Periodic, not urgent.

### Concrete numbers

| Data | chunks | K/chunk | imp | overhead | N/chunk | Per holder (15) |
|------|--------|---------|-----|----------|---------|-----------------|
| Photo batch 128 MB | 1 | 2048 | 0.6 | 2.4x | 4922 | 328 sym (21 MB) |
| Document batch | 1 | 2048 | 0.9 | 2.85x | 5845 | 390 sym (25 MB) |
| Video 2 GB | 16 | 2048 | 0.3 | 1.95x | 3999 | 267 sym (17 MB) ×16 |
| Video 8 GB | 64 | 2048 | 0.2 | 1.8x | 3692 | 246 sym (16 MB) ×64 |

### Placement formula

```
weight_i = trust_i / sqrt(1 - trust_i)      // mean-variance optimum
share_i = weight_i / sum(all weights)
max_share = (1 - 1/overhead) × 0.85
max_per_holder = min(K_eff - 1, max_share × N)  // K_eff-1: more is pointless (one holder = entire file)
symbols_i = clamp(round(N × share_i), 1, max_per_holder)
```

For m ≤ 10 and N ≤ 100: exact DP search (instant, guaranteed optimum).

Rebalancing = adding new symbols only (new ESIs), not relocating existing ones.

---

## How RaptorQ works (mechanics)

### Encoding

1. Source block (encrypted file/batch) → split into K symbols of T bytes each
2. Build intermediate representation (LDPC+HDPC) — O(K)
3. Generate any number of encoding symbols, each with an ESI (0, 1, 2, ...)
4. **Systematic**: ESI 0..K-1 = source data verbatim. ESI ≥ K = repair symbols

### Decoding

1. Collect any K+3 symbols (K_eff) (any ESIs, from any holders)
2. Solve the system → recover source data — O(K)

### Key property

The encoder can generate a symbol with **any ESI at any time**, given only the source data. No intermediate state needs to be stored. File on disk → generate symbol ESI=999999 a year later.

---

## Per-holder binding (anti-collusion)

### Attack without binding

K colluding holders collect K symbols → decode → store one copy → regenerate for PoS. Redundancy becomes an illusion.

### Protection

Each holder stores a **unique** version of the symbol:

```
stored_symbol = symbol XOR ChaCha20_stream(HKDF(source_block_id, holder_id))
```

- Deduplication across holders is impossible
- CPU cost: negligible (ChaCha20 = GB/s)
- Restore: owner knows holder_id → XOR back → clean symbol
- Mandatory, not optional

---

## Pipeline

```
BACKUP:
  file → zstd compress (streaming) → ChaCha20 encrypt (streaming) → source block
  → K = ceil(size / T), N = K × overhead(importance)
  → placement: select holders by trust/sqrt(1-t)
  → per holder:
      generate symbols (ESI unique per holder)
      → XOR bind with holder-specific key
      → send (direct connection, 256 KB at a time)
      → forget (RAM = 1 symbol)

RESTORE:
  DB lookup: path → source_block_id → holders
  → escrow check (trust-based)   [removed in v1: no restore gate, restore-i6]
  → collect K_eff symbols from holders
  → unbind (XOR back) → RaptorQ decode → decrypt → decompress → file

REPAIR (file on disk):
  generate new symbol (new ESI) → bind → send to new holder
  (no network download needed!)

REPAIR (file deleted):
  download K_eff symbols → unbind → decode → source block
  → generate new symbols → bind → send to new holders
```

---

## PoS (Proof of Storage)

> **Wire format superseded.** This section describes the original β design, where the holder returned the raw 64 KB symbol and the owner recomputed and byte-compared it. The shipped protocol uses a **Samsara-style chain hash** instead: the owner challenges an ESI range, the holder folds its stored symbols into a single chain hash (`h_i = SHA256(h_{i-1} ‖ symbol)`) and returns **only the hash** — no raw symbols on the wire. This closed an escrow-bypass at the time (you could otherwise harvest restore data through PoS; the escrow restore gate itself was removed in v1) and cuts bandwidth further. The trust/timeout reaction below (Pass / NotHeld / Fail / graduated Timeout) is unchanged and still current. For the authoritative PoS algorithm see [`../logic.md`](../logic.md); for the wire messages see [`../protocol.md`](../protocol.md).

```
Once a week, per holder:

Owner:
  pick random ESI from esi_ranges for this holder
  → pos_challenge { source_block_id, esi: 47 }

Holder:
  symbol present → pos_response { esi: 47, data: [64 KB] }
  symbol absent  → pos_nack { reason: SymbolNotHeld }

Owner verifies:
  pos_response → recompute symbol + binding → compare ✓ (hashes are NOT stored)
  pos_nack     → immediate repair (holder honestly reported "not held")
  timeout      → graduated response (see below)
  File deleted → cooldown → no PoS (symbols will be deleted soon)
```

Bandwidth: 64 KB × 15 holders = **0.94 MB/week**. Negligible.

### VerifyOutcome and response

```
Pass     → trust P +1, all good
NotHeld  → do NOT touch trust, immediate repair
           (holders have the right to evict; penalising honesty is an error)
Fail     → trust P -1, immediate repair
           (data is corrupt or forged)
Timeout  → trust P -1, graduated repair:
           1 miss  → Uncertain (do nothing, wait)
           2 misses → Uncertain (wait)
           3+ misses → PresumedLost → trigger repair
```

Graduated response for Timeout — idea borrowed from Samsara (probabilistic discard).
Rationale: timeout = "we don't know what happened". The peer may have gone on holiday
(1–2 weeks offline is normal for cold backup). 3 misses = 3+ weeks → most likely gone.

NotHeld and Fail = certainty → react immediately. Timeout = uncertainty →
react gradually.

---

## DB model

### Two layers

```
HOT (RAM, ~1 MB per 1000 files):
  source_block_id → { K, total_alive_symbols }
  (source_block_id, holder_id) → { symbol_count, status, last_pos }
  All decisions: placement, budget, repair, reliability

WARM (redb):
  FileRecord { file_id, path, importance, versions: [FileVersion] }
  FileVersion { content_hash, source_block_id, K, T, ts_created, ts_backed }
  SymbolPlacement { source_block_id, holder_id, esi_ranges, binding_seed, status }
  EventLog (append-only): placed / lost / verified events
```

Cold layer (pos_hashes) removed: file on disk → PoS on the fly. File deleted → cooldown → symbols deleted, PoS not needed.

### ESI ranges

Symbols are assigned sequentially:
```
holder_A: [(0, 32)]                    // ESI 0-31, initial
holder_A: [(0, 32), (500, 5)]          // + repair symbols ESI 500-504
```

### Dual index

```
file_holders: (file_id, holder_id) → symbol_count
holder_files: (holder_id, file_id) → symbol_count
```

"Holder B left" → scan holder_files[B] → recalculate reliability for all files. One scan.

### Comparison with α

| | RS (α) | RaptorQ (β) |
|---|--------|-------------|
| 1000 files | ~50 MB metadata | ~3.4 MB metadata |
| Entity levels | File → Unit → Shard | File → SymbolPlacement |
| Records | 15,000 ShardRecord | 10,000 SymbolPlacement |

**15x less metadata.** Fungible symbols → aggregates instead of individual records.

---

## Reliability: the math

### Formula

```
P(file survives) = P(Binomial(N, p) ≥ K_eff)
```

N = distributed symbols, K = needed for decode, p = peer survival (1 - churn_rate).

If symbols are **in hand** — decoding is deterministic (RS: 100%, RaptorQ: 99.98% at K_eff (K+3)).
Reliability is a question of survival (will K symbols still be alive in a year), not of decoding.

### Table (annual churn 30%, p=0.7)

| K | N | Overhead | P(survives one year) |
|---|---|----------|----------------------|
| 5 | 10 | 2.0x | 95.3% |
| 5 | 15 | 3.0x | 99.93% |
| 5 | 20 | 4.0x | 99.9994% |
| 200 | 480 | 2.4x | ~99.999% |
| 8000 | 15600 | 1.95x | ~100% |

### Larger K is more efficient

| K | N for 99.9% | Overhead |
|---|-------------|----------|
| 5 | ~17 | 3.4x |
| 100 | ~170 | 1.7x |
| 1000 | ~1550 | 1.55x |

Law of large numbers: larger K → smaller relative overhead.
Batches (K=200) are more reliable than individual files (K=20) at the same overhead.

---

## 16 advantages vs RS (summary)

1. **Dynamic N** — generate symbols without re-encoding
2. **No probability multiplication** — 1 file = 1 source block (up to 14 GB)
3. **Streaming RAM** — O(1 symbol) instead of O(k×n)
4. **Symbol size ≠ RAM** — T is a transport parameter
5. **No critical symbols** — any K symbols will do
6. **Heterogeneous storage** — different symbol counts per holder
7. **Reliability = simple fraction** — alive/K
8. **Versioning is implicit** — via symbol generations
9. **Incremental reliability** — add symbols without re-encoding
10. **Repair = generate new** — not reconstruction of a specific lost symbol
11. **Continuous importance** — overhead as a function, not 3 tiers
12. **Simpler DB** — 15x less metadata
13. **Symbol budget** — fine-grained placement
14. **Per-peer reliability** — "if holder leaves, reliability = X"
15. **Natural S-score** — calculated in symbols of uniform size
16. **"More files, less overhead"** — continuous trade-off

## Disadvantages

1. **Chunking for large files** — source block=128 MB, files >128 MB are split. P(file)=P(chunk)^n. Video 2 GB=16 chunks, P^16
2. **No partial recovery** — K-1 = 0% (same as RS)
3. **Repair without file = download K** — same as RS
4. **CPU** — raptorq crate benchmarks needed (not critical for cold backup)
5. **Maturity** — raptorq crate ~200 stars (vs RS with dozens of production deployments)
6. **Probabilistic decode** — K+2 instead of exactly K (negligible)

---

## Resolved questions

1. **raptorq crate benchmarks** — K=2048: encode ~500 ms, decode ~100 ms (extrapolated). GO.
2. **Crate API** — streaming encode is not possible (Encoder::new(&[u8])). Solution: chunk at 128 MB, peak RAM ~250 MB.
3. **Placement** — `weight = trust/sqrt(1-t)`, cap = `(1-1/overhead)×0.85`, hard limit K_eff-1. Agent calculated: +10–21 pp vs uniform.
4. **T and block size** — T=64 KB (crate max), source block=128 MB, no max file size.

## Open questions

1. Game theory — prove that "20% less reliable > 10% reliable"
2. Migration path α → β

## Historical note (serendipity)

Research into RaptorQ began with the idea of solving the RAM problem (α RS peak ~180 MB). In theory, RaptorQ supports streaming encode at O(1 symbol), but the `raptorq` crate requires the entire source block in RAM. Peak RAM in β (~250 MB) is actually slightly higher than in α.

Along the way, however, 16 other advantages emerged: dynamic N, fungible symbols, per-holder binding, continuous importance, 15x less DB metadata, repair without reconstructing a specific symbol, and more. Each one individually justifies the switch.

RAM streaming may be possible via C FFI (nanorq, supports mmap/stream). Post-β optimisation if needed.
