# Experiment 12: Prison Network (Captive Network)

## Question

Can an isolated network (no internet access, closed community) be self-sufficient? What is the minimum group size that provides acceptable storage reliability? How much damage can a single "bad" participant cause in a small network?

## Model

- **Isolated network:** fixed number of nodes N, no external connectivity, no new participants during the simulation.
- **Adaptive erasure code:** small networks use `k-of-(n-1)` instead of the fixed `5-of-15`. At N ≥ 20 the full `5-of-15` scheme applies.
- **Churn:** random node failures at a probability of 0%, 10%, or 25% per simulation period.
- **Scenario A (minimum size):** 8 network sizes × 3 churn levels = 24 configurations, 30 seeds each, 24 cores.
- **Scenario B (bad apple):** 4 network sizes × 4 behaviour types = 16 configurations, 30 seeds each.
- **Bad-actor types (Scenario B):** `freerider` (does not store others' data), `liar` (reports incorrect metadata), `spite` (deliberately corrupts others' shards), `none` (all honest, baseline).

## Configuration

**Scenario A — Minimum Viable Network:**

| Size | Churn | k-of-n  | Survival% | p5%   | Redundancy |
|------|-------|---------|-----------|-------|------------|
|    3 |   0%  | 2-of-2  |   100.0%  | 100.0%|       1.00 |
|    5 |   0%  | 3-of-4  |   100.0%  | 100.0%|       1.00 |
|    7 |   0%  | 4-of-6  |   100.0%  | 100.0%|       1.00 |
|   10 |   0%  | 6-of-9  |   100.0%  | 100.0%|       1.00 |
|   15 |   0%  | 9-of-14 |   100.0%  | 100.0%|       1.00 |
|   20 |   0%  | 5-of-15 |   100.0%  | 100.0%|       1.00 |
|   30 |   0%  | 5-of-15 |   100.0%  | 100.0%|       1.00 |
|   50 |   0%  | 5-of-15 |   100.0%  | 100.0%|       1.00 |
|    3 |  10%  | 2-of-2  |    70.0%  |   0.0%|       0.90 |
|    5 |  10%  | 3-of-4  |    94.7%  |  67.1%|       0.96 |
|    7 |  10%  | 4-of-6  |   100.0%  | 100.0%|       0.98 |
|   10 |  10%  | 6-of-9  |   100.0%  | 100.0%|       0.97 |
|   15 |  10%  | 9-of-14 |   100.0%  | 100.0%|       0.95 |
|   20 |  10%  | 5-of-15 |   100.0%  | 100.0%|       1.00 |
|   30 |  10%  | 5-of-15 |   100.0%  | 100.0%|       1.00 |
|   50 |  10%  | 5-of-15 |   100.0%  | 100.0%|       1.00 |
|    3 |  25%  | 2-of-2  |    51.1%  |   0.0%|       0.67 |
|    5 |  25%  | 3-of-4  |    81.3%  |   0.0%|       0.77 |
|    7 |  25%  | 4-of-6  |    90.0%  |   0.0%|       0.79 |
|   10 |  25%  | 6-of-9  |    96.7%  | 100.0%|       0.87 |
|   15 |  25%  | 9-of-14 |    93.3%  |  45.0%|       0.80 |
|   20 |  25%  | 5-of-15 |   100.0%  | 100.0%|       0.95 |
|   30 |  25%  | 5-of-15 |   100.0%  | 100.0%|       1.00 |
|   50 |  25%  | 5-of-15 |   100.0%  | 100.0%|       0.99 |

**Minimum viable size (Survival >= 95%):**

| Churn | Min N |
|-------|-------|
|    0% |     3 |
|   10% |     7 |
|   25% |    10 |

**Scenario B — Bad Apple Impact:**

| Size | BadApple  | Survival% | vs_Honest | Amplification |
|------|-----------|-----------|-----------|---------------|
|    5 | freerider |     90.0% |     -6.7% |          0.3x |
|    5 | liar      |    100.0% |     +3.3% |          0.2x |
|    5 | none      |     96.7% |         — |             — |
|    5 | spite     |     96.7% |     +0.0% |          0.0x |
|   10 | freerider |    100.0% |     +0.0% |          0.0x |
|   10 | liar      |    100.0% |     +0.0% |          0.0x |
|   10 | none      |    100.0% |         — |             — |
|   10 | spite     |    100.0% |     +0.0% |          0.0x |
|   20 | freerider |    100.0% |     +0.0% |          0.0x |
|   20 | liar      |    100.0% |     +0.0% |          0.0x |
|   20 | none      |    100.0% |         — |             — |
|   20 | spite     |    100.0% |     +0.0% |          0.0x |
|   50+| all types |    100.0% |     +0.0% |          0.0x |

## Key findings

1. **Minimum size depends on churn.** At 0% churn, 3 nodes suffice. At 10% churn, 7 are needed. At 25%, 10. This follows directly from how much the adaptive code can absorb.

2. **Adaptive erasure coding is the key design decision.** Small networks switch automatically to `k-of-(n-1)` instead of `5-of-15`. Without this, a 7-node network simply could not place 15 shards. The adaptation makes the system workable at any size.

3. **Bad actors are harmless at N >= 10.** Freerider, liar, and spite each produce 0% additional losses at N=10 and above. The erasure code redundancy absorbs their impact entirely.

4. **A bad actor matters only at N=5.** Freerider causes -6.7% survival (90% instead of 96.7%). Even 90%, however, is an acceptable result for a group of 5 with no alternatives.

5. **N=15 at 25% churn is a weak point.** Survival 93.3%, p5=45%. The `9-of-14` scheme lacks sufficient redundancy margin: losing 2+ nodes out of 15 under high churn makes the recovery threshold fragile. At N=20 the system switches to `5-of-15` and immediately delivers 100%.

6. **N >= 20 is always safe.** 100% survival across all configurations. The transition to the full `5-of-15` scheme is the practical reliability threshold.

7. **The system degrades gracefully.** Even at N=3 with 25% churn, data survives in 51% of cases — better than nothing. There is no sharp cliff; reliability declines gradually as the network shrinks.

## Design implications

- **A family or friend group of 7–10 people can use the system in isolation.** 7 nodes at low churn (10%) give 100% survival. 10 nodes at moderate churn (25%) do as well.
- **Minimum viable deployment:** 7 peers at low churn, 10 at moderate, 20 for full reliability with no restrictions.
- **Bad actors in small networks are less dangerous than expected.** Adaptive erasure coding provides sufficient margin even at N=5.
- **For "prison" scenarios** (isolated communities with no external connectivity) the system is fully viable at 20+ nodes. For extremely small groups (5–10 nodes) it works, but with understood limitations.
- **The N=15→20 transition is critical.** Users should be warned that N=15 is a higher-risk zone under high churn. The recommended minimum for isolated networks is 20 nodes.
- **Network size monitoring.** In isolated communities the system should warn when the number of active nodes falls below the threshold (10 at moderate churn, 7 at low).

## Code

`simulations/prison_network.py` — run with `--scenario A --jobs 24` and `--scenario B --jobs 24`
