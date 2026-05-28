# Experiment 26: Weighted Shard Placement

## Question

Does weighted shard placement (core + insurance, w_i = p_i^α) solve the survival problem from Exp 25, where the FULL model (tau=1.000) had lower survival (96.1%) than the S2 baseline (97.6%)?

## Model

Three configurations are compared:

| Model | S-formula | n | Gate | Placement | Escrow |
|--------|-----------|---|------|-----------|--------|
| **EQUAL** | multiplicative | adaptive | OFF | proportional to trust (1 shard/partner) | ON |
| **WEIGHTED** | multiplicative | adaptive | OFF | w_i = p_i^2, up to 6 shards/partner | ON |
| **S2** | additive (0.3/1.5/0.3) | fixed n=15 | ON | uniform (1 shard/partner) | ON |

EQUAL = FULL model from Exp 25 (baseline for comparison).

Weighted placement: each partner receives n_i = round(n_total × w_i') shards, where w_i = p_i^α (α=2.0), p_i = clip(trust_i / MAX_TRUST, 0.1, 1.0). A partner may hold up to 6 shards of the same file (MAX_SHARDS_PER_PARTNER=6).

## Configuration

```
nodes             = 10000
duration          = 10 years
churn             = 25% annual
archetypes        = 6 standard + HitAndRun (15% of arrivals)
seeds             = 20
jobs              = 24
scenarios         = A (baseline), D (40% free-rider flood)
```

## Results

### Scenario A: Baseline

| Year | EQUAL surv | WEIGHTED surv | S2 surv | EQUAL tau | WGT tau |
|------|-----------|--------------|---------|----------|---------|
| 1 | 98.66% | 98.88% | 99.93% | 0.97 | 0.97 |
| 3 | 98.55% | 99.08% | 99.13% | 1.00 | 1.00 |
| 5 | 97.88% | 98.85% | 98.44% | 0.99 | 0.99 |
| 7 | 97.03% | 98.52% | 98.08% | 1.00 | 1.00 |
| 10 | 96.20% | **98.06%** | 97.69% | 0.99 | **1.00** |

| Metric | EQUAL | WEIGHTED | S2 |
|--------|-------|----------|-----|
| Storage overhead | 3.16x | 3.62x | 2.93x |
| Bootstrap time | 13.94 wk | 13.78 wk | 14.01 wk |
| Gini (shard concentration) | 0.00 | 0.12 | 0.00 |
| Mean shards/partner | 1.00 | 1.56 | 1.00 |
| Max shards/partner | 1.00 | 6.00 | 1.00 |

### Scenario D: Free-rider Flood (40% arrivals)

| Year | EQUAL surv | WEIGHTED surv | S2 surv | EQUAL tau | WGT tau |
|------|-----------|--------------|---------|----------|---------|
| 1 | 97.93% | 98.09% | 99.98% | 0.63 | 0.63 |
| 3 | 96.92% | 97.65% | 99.17% | 0.59 | 0.59 |
| 5 | 95.18% | 96.70% | 98.62% | 0.60 | 0.60 |
| 7 | 93.51% | 95.55% | 98.18% | 0.60 | 0.60 |
| 10 | 91.63% | 93.96% | 97.74% | 0.60 | 0.60 |

| Metric | EQUAL | WEIGHTED | S2 |
|--------|-------|----------|-----|
| Honest node survival | 97.39% | **99.40%** | 97.60% |
| Freeloader survival | 85.19% | 87.86% | 97.89% |
| Storage overhead | 3.59x | 4.09x | 2.93x |
| Gini (shard concentration) | 0.00 | 0.11 | 0.00 |

## Key findings

1. **WEIGHTED solves the Exp 25 problem.** In the baseline (Scenario A): survival 98.06% vs S2 97.69% (+0.37pp) at tau=1.000 (vs 0.670). For the first time, both ranking quality and survival are improved simultaneously.

2. **Shard concentration works.** Gini=0.12, mean 1.56 shards/partner, max 6. Reliable partners receive 2-6 shards; unreliable ones receive 0-1. Losing an unreliable partner costs few shards.

3. **Honest survival in Scenario D: WEIGHTED is best.** 99.40% — higher than both EQUAL (97.39%) and S2 (97.60%). Weighted placement protects honest nodes by concentrating their shards on reliable partners.

4. **Overall survival in Scenario D: S2 is still better.** 97.74% vs 93.96%. Reason: the S2 gate prevents free-riders from storing shards, so their files are "freely" protected at fixed n=15. WEIGHTED honestly gives free-riders fewer shards, so their files are lost more often, pulling overall survival down. This is the **correct** behaviour: free-riders SHOULD lose files.

5. **WEIGHTED overhead > S2.** 3.62x vs 2.93x in the baseline. The cost of concentration: reliable partners receive more shards, but n_total does not adapt downward (still Binom(n, avg_p)). Optimisation: replacing Binom(n, avg_p) with Poisson binomial will reduce n_total for mixed-trust scenarios.

6. **Bootstrap time is identical.** ~14 weeks across all models — weighted placement does not affect the rate at which partners are acquired.

## Design implications

- **Weighted placement is the recommended default** for the reference implementation. Survival ≥ S2 at tau=1.000.
- **Gate is not needed.** WEIGHTED without a gate achieves better honest survival than S2 with one.
- **Overhead can be optimised later.** Replacing Binom(n, avg_p) with Poisson binomial should bring n_total from 3.62x closer to 3.0x.
- **Scenario D is the design envelope.** 40% free-riders is an extreme condition. Overall survival of 94% is acceptable; honest survival of 99.4% is excellent.

## Code

`simulations/pis_weighted_placement.py` — results in `results/pis_weighted_placement/pis_weighted_placement_results.json`
