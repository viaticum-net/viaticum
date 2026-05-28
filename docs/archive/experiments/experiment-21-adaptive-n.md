# Experiment 21: Adaptive Shard Count

## Question

Does adaptive n (shard count computed from partner trust) achieve target reliability without an acceptance gate? Is there any reason to keep an acceptance gate in the system at all?

## Model

Trust formula: multiplicative S — `trust_AB = (kp×P_B + ki×I_B) × clamp(S_AB, 0.1, 1.0)`

Four scenarios across two axes: fixed/adaptive n × gate on/off.

**Adaptive n:** `n = ceil(k × safety_margin(avg_partner_trust))` with a pre-computed safety margin table. When average partner trust is low, n grows; when it is high, n shrinks.

**Acceptance gate:** a trust threshold below which a node refuses to accept a new partner. Reduces the pool of available partners.

## Configuration

```
peers             = 2000
duration          = 5 years
churn             = 25%/yr
seeds             = 10
jobs              = 6
kp, ki            = 0.5, 2.0
erasure (fixed)   = 5-of-15
S                 = pairwise (S_AB = r_B / r_A)
```

## Results

### Year 5 — summary table

| Scenario | Survival | Overhead | Mean n | Bootstrap | Wasted |
|---|---|---|---|---|---|
| 1. Fixed n=15, gate=ON | 97.93% | 2.92x | 14.6 | 1.1 wks | 39.6% |
| 2. Fixed n=15, gate=OFF | 99.00% | 2.95x | 14.7 | 1.0 wks | 39.3% |
| 3. Adaptive n, gate=OFF | 97.00% | 2.55x | 12.8 | 1.0 wks | 39.8% |
| 4. Adaptive n, gate=ON | 95.73% | 2.53x | 12.7 | 1.1 wks | 39.8% |

### Gate: the cost of filtering partners

| n | gate=ON | gate=OFF | Delta |
|---|---|---|---|
| Fixed n=15 | 97.93% | **99.00%** | **−1.07 pp** |
| Adaptive n | 95.73% | **97.00%** | **−1.27 pp** |

The gate reduces survival in both cases. A smaller partner pool means worse file coverage.

### Adaptive n: overhead saving vs survival loss

| Config | Survival | Overhead | Delta survival | Delta overhead |
|---|---|---|---|---|
| Fixed n=15, gate=OFF | **99.00%** | 2.95x | — | — |
| Adaptive n, gate=OFF | 97.00% | **2.55x** | −2.00 pp | **−0.40x (−13%)** |

Adaptive n saves ~13% overhead at the cost of ~2 pp survival.

### Bootstrap and churn

| Metric | All scenarios |
|---|---|
| Bootstrap time | ~1 week |
| Wasted shards | ~39–40% |

Bootstrap time is the same across all scenarios — new nodes are useful from the first week. The wasted-shard fraction (~40%) does not change regardless of gate or adaptive n: churn is the dominant loss factor.

## Key findings

1. **The gate is harmful.** The acceptance gate reduces survival by 1.07–1.27 pp in both n modes. Filtering partners shrinks the pool, leading to fewer partnerships and worse file coverage. The mechanism was intended as protection but hurts reliability more than it helps.

2. **Adaptive n saves 13% overhead.** Moving from fixed n=15 to adaptive reduces overhead from 2.95x to 2.55x (−0.40x) while losing only 2 pp survival. This is a tradeoff, not a free gain.

3. **The best absolute result is Scenario 2.** Fixed n=15 with gate=OFF delivers 99.00% survival — the highest of all configurations.

4. **Bootstrap is near-instant (~1 week)** in all scenarios. Newcomers are useful from day one; there is no cold-start problem.

5. **~40% of shards are lost to churn** regardless of strategy. Neither the gate nor adaptive n affects this figure. Churn is the dominant loss factor, not the configuration choice.

6. **Adaptive n and escrow are compatible.** Adaptive n reduces storage cost; escrow (Exp 24) prevents abuse. Both mechanisms can be used together without conflict.

## Design implications

- **Remove the acceptance gate.** It reduces survival in both modes. Escrow (Exp 24) addresses abuse more effectively without shrinking the partner pool.
- **Adaptive n is an opinionated tradeoff.** A 13% overhead saving at −2 pp survival is justified for users with constrained storage. It can be offered as a user-configurable policy.
- **Churn (~40% losses) is unavoidable.** Fighting churn with a gate or a conservative fixed n is the wrong approach. The right strategy is to reduce repair cost, not to try to prevent losses.
- **Combined recommendation:** adaptive n (gate=OFF) + escrow = 97% survival + 2.55x overhead + protection against hit-and-run. This is the best balance of all tested configurations.

## Code

`simulations/pis_adaptive_n.py` — results in `results/pis_adaptive_n/run.json`
