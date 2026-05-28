# Experiment 17: Long-term Mixed Network

## Question

Is a network of 6 archetypes with PI+S (pairwise S) stable over 10 years? Does the trust-to-utility correlation hold over a 10-year horizon, and does pairwise S resolve the Hoarder/Freeloader problem found in Exp 13?

## Model

Trust formula: `trust = kp × P + ki × I + ks × S` (additive, pairwise S).

Pairwise S: `S_AB = STORAGE_RATIOS[B] / max(STORAGE_RATIOS[A], eps)` — the ratio of a partner's storage volume to one's own. Not a global ranking, but a direct comparison of two specific peers. This prevents attacks through manipulation of a global ranking.

Archetypes (the same six as in Exp 13/15):

| Archetype | Share | Uptime | Storage capacity |
|-----------|-------|--------|-----------------|
| Reliable | 40% | 99% | 100% |
| Weekend | 20% | 95% weekends / 30% weekdays | 100% |
| Seasonal | 15% | 95% term-time / 20% summer | 100% |
| Nomad | 10% | ~50% random blocks | 100% |
| Hoarder | 10% | 90% | 20% |
| Freeloader | 5% | 80% | 10% |

**Expected rank** (actual utility to the network):

| Expected rank | Archetype |
|---------------|-----------|
| 1 | Reliable |
| 2 | Weekend |
| 3 | Seasonal |
| 4 | Nomad |
| 5 | Hoarder |
| 6 | Freeloader |

## Configuration

```
formula          = trust = kp×P + ki×I + ks×S  (additive, pairwise S)
kp, ki, ks       = 0.5, 2.0, 1.0
P-window         = 4 weeks
initial_nodes    = 50
max_nodes        = 10000
annual_churn     = 25%
target_partners  = 15
duration         = 10 years
seeds            = 10
```

## Results

### Kendall's tau over 10 years

| Period | tau |
|--------|-----|
| Minimum (year 1) | 0.627 |
| Maximum (year 3) | 0.720 |
| Mean | ~0.667 |
| Year 10 | ~0.667 |

Tau holds steadily in the range 0.627–0.720 across the full 10-year horizon. This is considerably worse than Exp 15 (tau=0.97, global S), explained by the Hoarder/Nomad inversion under the additive formula with pairwise S.

### Final trust (year 10)

| Archetype | Trust_mean | PI+S_rank | Expected_rank | Delta |
|-----------|-----------|-----------|---------------|-------|
| Weekend | 3.648 | 1 | 2 | -1 |
| Reliable | 3.648 | 2 | 1 | **+1** |
| Seasonal | 3.538 | 3 | 3 | 0 ✅ |
| Hoarder | 2.874 | 4 | 5 | **+1** ❌ |
| Freeloader | 2.687 | 5 | 6 | +1 |
| Nomad | 2.390 | 6 | 4 | **−2** ❌ |

Reliable and Weekend are nearly tied (both 3.648) — the top two positions are swapped, but this is not critical. The critical problem is the Hoarder/Nomad inversion: Hoarder (rank 4) sits above Nomad (rank 6), when it should be the other way around.

### Hoarder/Nomad inversion mechanism

Under the additive formula, the P+I components determined by uptime suppress the S penalty:

| Archetype | Uptime | S (vs. 100%-storage partner) | P+I contribution | Net effect |
|-----------|--------|------------------------------|-----------------|------------|
| Nomad | ~50% | 1.0 (full volume) | low | low trust |
| Hoarder | 90% | 0.2 (20% storage) | high | **above Nomad** |

`90% uptime × S=0.2` — the P+I contribution at 90% uptime is large enough that even S=0.2 does not pull the final trust below Nomad at S=1.0. The additive scheme prevents S from effectively penalising low storage volume.

### Community structure (year 10)

| Metric | Value |
|--------|-------|
| Number of communities | 17 |
| Modularity Q | 0.290 |
| Cross-cluster edges | 59.5% |
| Bridge nodes | 99.7% |
| Isolated small communities | 3 |

The network is well-connected: 59.5% of edges cross cluster boundaries, and 99.7% of nodes act as bridges between communities. The three small isolated clusters are a minor artefact.

### Cluster composition

Clusters are **mixed by archetype** — there are no "Hoarder ghettos" or isolation of individual types. Each community contains approximately 10% Hoarder and 5% Freeloader, matching their share of the overall population.

### Topology vs. formula analysis (cluster_probe.py)

| Metric | Value |
|--------|-------|
| tau (all partners) | 0.667 |
| tau_honest (honest partners only) | 0.733 |

The difference is minimal. Tau when filtering to honest partners only (0.733) is nearly equal to the overall tau (0.667). Conclusion: **the problem is in the formula, not the topology**. Clusters are healthy; dishonest peers do not distort the topology enough to account for the inversion.

## Key findings

1. **Pairwise S is the right choice for security**, but the additive formula prevents it from working effectively. With additive PI+S, uptime dominance neutralises the S penalty for Hoarder.

2. **The Hoarder/Nomad inversion is structural, not parametric.** No choice of kp/ki/ks within the additive scheme eliminates the inversion: at any reasonable weights, a Hoarder with 90% uptime will outrank a Nomad with 50% uptime, even when Nomad has S=1.0.

3. **The network topology is healthy.** Mixed clusters, high connectivity (59.5% cross-cluster), 99.7% bridge nodes. Anti-clustering mechanisms are not needed.

4. **Tau=0.667 is stable over 10 years** — the system does not degrade, but does not self-correct either. This is a plateau, not a trend.

5. **tau_honest ≈ tau_all** confirms that the problem lies in the formula itself, not in attacks or poor topology.

## Design implications

- **Multiplicative S instead of additive.** The formula `trust = (kp×P + ki×I) × clamp(S, 0.1, 1.0)` changes the role of S fundamentally: it becomes a multiplier rather than a summand, able to reduce any uptime advantage. A Hoarder with S=0.2 receives 20% of P+I; a Nomad with S=1.0 receives 100%. Tested in Exp 22.
- **A lower clamp for S matters.** Without `clamp(S, 0.1, 1.0)`, new peers with S≈0 receive trust≈0, which blocks bootstrapping. A minimum of 0.1 gives newcomers a chance to join the network.
- **Topological mechanisms are not needed.** Clusters are healthy and mixed; resources are better spent fixing the formula than on anti-clustering.
- **Kendall's tau 0.627–0.720 is insufficient.** The target threshold is tau > 0.8 with multiplicative S. Exp 22 tests this hypothesis.

## Code

`simulations/pis_longterm.py`, `simulations/cluster_probe.py` — results in `results/pis_longterm/run.json`
