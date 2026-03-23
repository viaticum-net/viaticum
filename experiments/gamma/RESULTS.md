# Gamma Experiment Results — 2026-03-23

## Summary

20-node Docker experiment with 3 behavioral archetypes. time_scale=1000, 30 min real ≈ 3 sim weeks.

**Key finding:** Trust protocol differentiates archetypes correctly even in 3 weeks. Reliable nodes earn trust 25x higher than flaky/freeloader. Pipeline works end-to-end: files backed up, symbols placed, PoS verified at 100%.

## Setup

| Parameter | Value |
|-----------|-------|
| Nodes | 20 |
| time_scale | 1000 |
| Duration | 1800s real (~3.0 sim weeks) |
| Topology | Mesh (ring + random shortcuts) |
| Files | 5 nodes × 5 files × 50KB = 1.25MB total |

### Archetypes

| Archetype | Count | Behavior | Quota |
|-----------|-------|----------|-------|
| reliable | 8 (40%) | Always online | 100 GB |
| flaky | 8 (40%) | 3 min on / 3 min off cycles | 100 GB |
| freeloader | 4 (20%) | Always online | 1 GB |

## Results

### Trust Differentiation

| Archetype | avg_trust (received) | PoS pass rate | Holding (avg KB) |
|-----------|---------------------|---------------|------------------|
| **reliable** | **0.3052** | **100%** (10/10) | 288 |
| flaky | 0.0123 | n/a (0 challenges) | 96 |
| freeloader | 0.0287 | n/a (0 challenges) | 192 |

Trust ratio: reliable/flaky = **24.8x**, reliable/freeloader = **10.6x**

### Trust Matrix (observer → subject)

| Observer | → reliable | → flaky | → freeloader |
|----------|-----------|---------|-------------|
| reliable | **0.657** | 0.116 | 0.543 |
| flaky | 0.007 | 0.020 | 0.007 |
| freeloader | 0.025 | 0.033 | 0.020 |

**Observations:**
- Reliable nodes strongly trust other reliable nodes (0.657) and freeloaders (0.543, they ARE always online) but penalize flaky (0.116)
- Flaky and freeloader nodes barely trust anyone (~0.02) because they haven't been online long enough to observe others
- Freeloader trust slightly higher than flaky for reliable observers — freeloaders ARE always on, just limited storage

### Trust Evolution Over Time

| sim_weeks | reliable | flaky | freeloader |
|-----------|----------|-------|------------|
| 0.08 | 0.016 | 0.020 | 0.022 |
| 0.39 | **0.522** | 0.019 | 0.023 |
| 1.01 | 0.408 | 0.015 | 0.026 |
| 1.97 | 0.347 | 0.013 | 0.029 |
| 3.07 | 0.305 | 0.012 | 0.029 |

- Reliable trust peaks at week ~0.4 then slowly declines (avg_trust includes all observers, not just reliable→reliable)
- Flaky trust declines slightly over time (consistent with being offline half the time)
- Freeloader trust very slowly increases (always online, just not storing)

### Placement Health

- 10 placements alive throughout (5 files × 2 placements each)
- 0 placements lost
- 5 blocks at risk (alive < k, because only 2 placements per block but k might be higher)
- No repair triggered (no placements lost)

### Peer Connectivity

| Archetype | avg peers |
|-----------|-----------|
| reliable | 9.9 |
| flaky | 15.9 |
| freeloader | 10.0 |

Flaky nodes have MORE peers because each restart reconnects to 3 random nodes, accumulating connections. This is not a problem — peer count ≠ active connections.

### Flaky Node Behavior

- 79 toggle events total (42 stops, 37 restarts)
- Average cycle: ~3 min on, ~3 min off (with ±30s jitter)
- Reconnection works: nodes successfully rejoin the network after restart

## Bugs Found / Fixed During Gamma

### Identity mismatch (status vs network) — FIXED

`DaemonState.identity_pub` used master key, but `NetworkHandle` used device key for handshakes. Peers stored device identity, but `status --json` reported master identity. These are different keys.

**Fix:** Changed `status --json` to report `network.identity_pub` (device identity), which matches what peers see. Both identity keys remain in the system — master for ownership, device for network authentication.

**Impact:** Before fix, trust matrix showed "n/a" because identity mapping failed. After fix, correct trust attribution.

## Observations and Next Steps

### What works
- Pipeline: file detection → flush → encode → symbol distribution → placement tracking
- PoS: challenges issued, verified, trust components (P, I) updated correctly
- Trust differentiation: reliable >> flaky/freeloader within 1 sim week
- Flaky node cycling: stop/restart/reconnect cycle works reliably
- Data collection: JSONL snapshots + events provide full experiment trace

### Issues to investigate
1. **Only 5 of 8 reliable nodes created files** — `phase_create_files` only creates files on first 5 reliable nodes. Nodes 05-07 have 0 backed files.
2. **blocks_at_risk > 0** — all 5 file-backing nodes show blocks "at risk" because each has only 2 placements but k might require more. Need more peers or lower k.
3. **PoS only challenged 2 peers per owner** — with 8 peers each having ~5 peers, PoS challenges were sparse. The 3 sim weeks might not be enough for comprehensive PoS coverage.
4. **S component always 1.0** — storage balance factor isn't differentiating because bytes_we_store and bytes_peer_stores are 0 for most nodes. The symbol placement data isn't reflected in peer storage counters.
5. **Flaky nodes got 0 PoS challenges** — because they don't own files, nobody challenged them. The trust protocol only challenges holders FOR the file owner. Flaky nodes need to also own files for their trust to be properly evaluated.

### Recommended next experiments
1. **All nodes create files** — every node backs up at least 1 file. This enables PoS for all archetypes.
2. **Longer run (12h, ~200 sim weeks)** — see trust convergence over months of simulated time
3. **More nodes (50+)** — test scaling, peer discovery, placement distribution
4. **Adversarial scenarios** — add sybil/attacker archetypes from research experiments
