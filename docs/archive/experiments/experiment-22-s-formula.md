# Experiment 22: Multiplicative vs Additive S

## Question

Which S formula gives better Kendall's tau in a living network (10K nodes, pairwise S, churn)? Can the Hoarder/Nomad inversion (Exp 17) be fixed without sacrificing parameter robustness?

## Model

Three trust formula variants with pairwise S:

| Formula | Expression |
|---------|-----------|
| A (additive) | `trust = kp×P + ki×I + ks×S` |
| B (multiplicative) | `trust = (kp×P + ki×I) × clamp(S, 0.1, 1.0)` |
| C (hybrid) | `trust = (kp×P + ki×I) × clamp(S, 0.1, 1.0) + ks_bonus × max(S−1, 0)` |

Pairwise S: `S_AB = STORAGE_RATIOS[B] / STORAGE_RATIOS[A]` — the ratio of a partner's storage volume to the observer's own volume.

**True utility ranking of archetypes:**

| Actual rank | Archetype | Rationale |
|-------------|-----------|-----------|
| 1 | Reliable | High uptime + full capacity |
| 2 | Weekend | Full capacity + predictable schedule |
| 3 | Seasonal | Full capacity, predictable pattern |
| 4 | Nomad | Full capacity, but unpredictable |
| 5 | Hoarder | High uptime, but little space |
| 6 | Freeloader | Average uptime, minimal space |

Reference problem (Exp 17): the additive formula with global S inverts Hoarder and Nomad — Hoarder (90% uptime × S=0.2) receives a higher score than Nomad (50% uptime × S=1.0).

## Configuration

```
nodes             = 5000
duration          = 5 years
seeds             = 10
S                 = pairwise
metrics           = Kendall's tau at years 1, 3, 5 (all-partners + honest-only)

Formula A: 16 configs — kp∈{0.3,0.5} × ki∈{1.5,2.0} × ks∈{0.3,0.5,1.0,2.0}
Formula B:  4 configs — kp∈{0.3,0.5} × ki∈{1.5,2.0}
Formula C:  8 configs — kp∈{0.3,0.5} × ki∈{1.5,2.0} × ks_bonus∈{0.1,0.3}
Total: 28 configs × 10 seeds
```

## Results

### Formula A (additive) — best configs

| Config | tau_y1 | tau_y3 | tau_y5 | tau_hon_y5 |
|--------|--------|--------|--------|------------|
| kp=0.3 ki=1.5 ks=0.3 | 0.653 | 0.653 | 0.667 | 0.733 |
| kp=0.3 ki=1.5 ks=2.0 | 0.880 | 0.920 | 0.920 | 1.000 |
| kp=0.5 ki=2.0 ks=2.0 | 0.933 | 0.960 | 0.920 | 1.000 |

tau_y5 range: 0.640–0.933. tau≥0.9 is only reached at ks=2.0, where S suppresses the PI components. tau_hon (honest nodes only) is always ≥0.733 — honest nodes rank more accurately.

### Formula B (multiplicative) — all configs

| Config | tau_y1 | tau_y3 | tau_y5 | tau_hon_y5 |
|--------|--------|--------|--------|------------|
| kp=0.3 ki=1.5 | 1.000 | 1.000 | 1.000 | 1.000 |
| kp=0.3 ki=2.0 | 0.960 | 1.000 | 1.000 | 1.000 |
| kp=0.5 ki=1.5 | 0.969 | 0.997 | 1.000 | 1.000 |
| kp=0.5 ki=2.0 | 0.969 | 0.997 | 1.000 | 1.000 |

All 4 configs converge to tau=1.000 by year 5. Parameters kp and ki have no effect on the final result — the formula is maximally robust.

### Formula C (hybrid) — representative configs

| Config | tau_y5 | tau_hon_y5 |
|--------|--------|------------|
| kp=0.3 ki=1.5 ks_bonus=0.1 | 0.947 | 1.000 |
| kp=0.5 ki=2.0 ks_bonus=0.1 | 0.960 | 1.000 |

tau_y5 range: 0.920–0.960. Better than A, worse than B. The bonus for S>1 adds noise without improving over Formula B.

### Archetype ranking (Formula B, kp=0.3 ki=1.5, year 5)

| Rank | Archetype | Trust_mean | TrustHon_mean |
|------|-----------|-----------|---------------|
| 1 | Reliable | 1.800 | — |
| 2 | Weekend | 1.800 | — |
| 3 | Seasonal | 1.718 | — |
| 4 | **Nomad** | **0.904** | — |
| 5 | **Hoarder** | **0.809** | 0.360 |
| 6 | Freeloader | 0.561 | — |

The Hoarder/Nomad inversion is eliminated: Nomad (rank 4) is correctly above Hoarder (rank 5). Honest nodes recognise Hoarder even more clearly: TrustHon=0.360.

### Inversion-fix mechanism

| Archetype | Uptime | S | Additive (ks=0.3) | Multiplicative |
|-----------|--------|---|-------------------|----------------|
| Hoarder | 90% | 0.2 | 0.9 + 0.06 = **0.96** | 0.9 × 0.2 = **0.18** |
| Nomad | 50% | 1.0 | 0.5 + 0.30 = **0.80** | 0.5 × 1.0 = **0.50** |

With additive S, Hoarder's high uptime compensates for low storage. With multiplicative S, storage becomes a multiplier — compensation is impossible.

## Key findings

1. **Multiplicative S gives perfect ranking (tau=1.000).** The Hoarder/Nomad inversion from Exp 17 is fully eliminated.

2. **Formula B is maximally robust.** All 4 tested parameter configs give the same result — kp and ki have no effect on final tau.

3. **Additive S (Formula A) reaches tau≈0.93 only at ks=2.0.** At that weight, S suppresses the PI components, negating the value of accumulated history.

4. **Hybrid (Formula C) is redundant.** The bonus for S>1 adds a parameter without improving over Formula B.

5. **clamp(S, 0.1, 1.0) is critical.** The floor of 0.1 prevents new participants from being zeroed out completely. The cap of 1.0 prevents low uptime from being compensated by large storage volume.

6. **Convergence speed:** Formula B — tau=1.000 by year 3–5. Formula A — plateaus at 0.667 with small ks.

## Design implications

- **Adopt multiplicative S:** `trust = (kp×P + ki×I) × clamp(S, 0.1, 1.0)`. Remove the ks parameter from the formula — it is not needed.
- **Parameters are non-critical:** any kp∈[0.3, 0.5] and ki∈[1.5, 2.0] works. Recommendation: kp=0.5, ki=2.0 for continuity with Series 2.
- **Keep the clamp.** The floor of 0.1 matters for bootstrapping new nodes; the cap of 1.0 matters for correct semantics.
- **No ks parameter — one fewer variable** to tune in production.

## Code

`simulations/pis_s_formula.py` — results in `results/pis_s_formula/results.json`
