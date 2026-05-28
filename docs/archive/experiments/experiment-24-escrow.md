# Experiment 24: Escrow as Credit System

## Question

Escrow as a credit mechanism — how effectively does it block hit-and-run attacks? How do escrow and adaptive n interact across the metrics of bootstrap speed, overhead, and file survival?

## Model

Four configurations: escrow on/off × adaptive n on/off. A network with 7 archetypes, including HitAndRun (HAR) — a peer that uploads a file, stores 0% of others' data, and leaves after 4 weeks.

**HitAndRun archetype:**

| Parameter | Value |
|-----------|-------|
| Share of arrivals | 15% |
| File size | 10 GB |
| Storage capacity | 0% |
| Time in network | 4 weeks, then departure |
| Goal | Retrieve a file without contributing anything |

**Escrow thresholds (by weeks_in_network, not by I-score):**

| Tier | File size | Delay |
|------|-----------|-------|
| Tier 1 | ≤ 5 GB | 4 weeks |
| Tier 2 | ≤ 50 GB | 13 weeks |
| Tier 3 | > 50 GB | 26 weeks |

Mechanism: shards are stored in the network from the moment of upload, but the restore keys become available to the peer only after the escrow period expires. The HAR peer leaves after 4 weeks, never reaching the key-release point for Tier 2 or Tier 3.

## Configuration

```
peers             = 3000
duration          = 156 weeks  (3 years)
seeds             = 10
jobs              = 6
trust formula     = multiplicative S: (0.5*P + 2.0*I) × clamp(S, 0.1, 1.0)
erasure           = 5-of-15 (base)
adaptive n        = on/off (Config C, D)
escrow            = on/off (Config B, D)
HAR share         = 15% of arrivals
HAR file size     = 10 GB
HAR storage       = 0%
HAR lifetime      = 4 weeks
```

## Results

### Summary table by configuration

| Config | HAR Success | HAR Cost | T1 Bootstrap | T2 Bootstrap | T3 Bootstrap | Survival Y3 | Overhead | Retention |
|--------|-------------|----------|--------------|--------------|--------------|-------------|----------|-----------|
| A: No escrow, fixed n=15 | 100% | 30 GB·wk | 0 wk | 0 wk | 0 wk | 100% | 3.00x | 99.3% |
| B: Escrow ON, fixed n=15 | **0%** | 119 GB·wk | 4 wk | 13 wk | 26 wk | 100% | 3.00x | 99.5% |
| C: No escrow, adaptive n | 100% | 80 GB·wk | 0 wk | 0 wk | 0 wk | 100% | **2.13x** | 99.5% |
| D: Escrow ON, adaptive n | **0%** | **317 GB·wk** | 4 wk | 13 wk | 26 wk | 100% | 2.19x | 99.4% |

HAR Success = share of HAR peers that successfully retrieved the file before leaving.
HAR Cost = total storage cost of the attacker's shards (GB·weeks) — network resources spent for nothing.
Bootstrap = delay until first file access for honest new peers in the corresponding Tier.

### Effect of escrow on HAR attacks

| Transition | HAR Success | HAR Cost | Effect |
|------------|-------------|----------|--------|
| A → B (fixed n) | 100% → **0%** | 30 → 119 GB·wk | Blocked + cost ×4 |
| C → D (adaptive n) | 100% → **0%** | 80 → 317 GB·wk | Blocked + cost ×4 |

### Effect of adaptive n on overhead

| Transition | Overhead | Saving |
|------------|----------|--------|
| A → C (no escrow) | 3.00x → 2.13x | **−29%** |
| B → D (escrow ON) | 3.00x → 2.19x | **−27%** |

Adaptive n saves 27–29% overhead regardless of whether escrow is enabled.

### Bootstrap timing

Bootstrap delays match the configured thresholds exactly: 4, 13, 26 weeks. The timer counts weeks_in_network — calendar time in the network, not accumulated I-score. This makes the behaviour deterministic and predictable for the user.

## Key findings

1. **Escrow blocks 100% of hit-and-run attacks.** The HAR peer leaves after 4 weeks — before any Tier threshold for files ≥5 GB. Success rate: 100% → 0% in both configurations (A→B and C→D).

2. **Escrow raises the cost of the attack.** The HAR peer's shards remain in the network, consuming space, but the attacker receives nothing. Cost: 30 → 119 GB·wk (fixed n) and 80 → 317 GB·wk (adaptive n). The attack becomes unprofitable.

3. **Adaptive n saves 29% overhead.** 3.00x → 2.13x without escrow, 3.00x → 2.19x with escrow. The combination of escrow + adaptive n (Config D) delivers both benefits.

4. **File survival is 100% in all configurations.** With 3000 nodes and a 5-of-15 scheme the network is resilient enough to survive even a 15% HAR share of arrivals.

5. **Retention of honest peers is unaffected.** ~99.4% across all configurations — honest users do not leave the network due to escrow delays.

6. **The best combination is Config D.** Escrow ON + adaptive n: 0% HAR success, 2.19x overhead, 100% survival.

## Design implications

- **Escrow is a mandatory protocol component.** It is the only mechanism that prevents hit-and-run. The acceptance gate (Exp 21) proved harmful: it reduced the partner pool. Escrow is better — data is already safely stored in the network; only restore is gated.

- **Escrow is credit, not punishment.** The right framing for the user: "Your files are already protected. Earn the right to access them by contributing to the network."

- **Escrow + adaptive n = recommended default.** Config D combines abuse protection with overhead savings without sacrificing reliability.

- **1 GB free demo credit** — a possible UX improvement for onboarding (not tested). It would allow new users to see the system working immediately, without waiting.

- **Bootstrap timing should be visible to the user.** The deterministic timer (4/13/26 weeks) allows showing a progress bar: "File access in X weeks." This is managed expectation, not uncertainty.

- **Next step — Exp 25.** Test 1 GB free demo credit and/or mixed escrow strategies (partial access as reputation accumulates).

## Code

`simulations/pis_escrow.py` — results in `results/pis_escrow/pis_escrow_results.json`
