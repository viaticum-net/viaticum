# Experiment 25: Full Model Integration

## Question

Does the full model (adaptive n + multiplicative S + no gate + no eviction + escrow) hold up against all attacks? Is it an improvement over the Series 2 baseline?

## Model

Two variants are compared on identical scenarios:

| Model | S-formula | n | Gate | Eviction | Escrow |
|-------|-----------|---|------|----------|--------|
| **FULL** | multiplicative `(kp×P + ki×I) × clamp(S, 0.1, 1.0)`, kp=0.5 ki=2.0 | adaptive | OFF | OFF | ON |
| **S2** (Series 2 baseline) | additive `kp×P + ki×I + ks×S`, kp=0.3 ki=1.5 ks=0.3 | fixed n=15 | ON | ON | ON |

Escrow is enabled in both variants — Exp 24 showed it is always beneficial.

**Attack scenarios:**

| Scenario | Description |
|----------|----------|
| A — Baseline | No attacks, 6 archetypes + HitAndRun 15% arrivals |
| B — Sybil | 200 Sybil nodes across 10 /24 subnets |
| C — Mass departure | 30% of nodes leave simultaneously at year 5 |
| D — Free-rider flood | 40% of arrivals are free-riders |
| E — Spite | 50 attackers, 3yr wait before attack |

## Configuration

```
nodes             = 10000
duration          = 10 years
churn             = 25% annual
archetypes        = 6 standard + HitAndRun (15% of arrivals)
seeds             = 20
jobs              = 24
scenarios         = A, B, C, D, E (5 total)
metrics           = survival_y10, Kendall's tau, HAR rate, storage overhead,
                    bootstrap time, denial rate
```

## Results

### Summary table (year 10)

| Scenario | FULL surv% | S2 surv% | FULL tau | S2 tau | FULL HAR | S2 HAR |
|----------|-----------|---------|---------|--------|---------|--------|
| A Baseline | 96.1% | 97.6% | 1.000 | 0.640 | 0% | 0% |
| B Sybil | 96.2% | 97.7% | 1.000 | 0.667 | 0% | 0% |
| C Mass departure | 96.4% | 97.7% | 1.000 | 0.693 | 0% | 0% |
| D Free-rider flood | **91.7%** | 97.8% | 0.600 | 0.927 | 0% | 0% |
| E Spite | 96.0% | 97.7% | 1.000 | 0.660 | 0% | 0% |

### Year-by-year dynamics — Scenario E (Spite, representative)

| Year | FULL surv | S2 surv | FULL tau | S2 tau |
|------|-----------|---------|---------|--------|
| 1 | 98.66% | 99.93% | 0.97 | 0.67 |
| 3 | 98.56% | 99.16% | 0.99 | 0.68 |
| 5 | 97.75% | 98.54% | 0.99 | 0.66 |
| 7 | 96.95% | 98.02% | 0.99 | 0.69 |
| 10 | 96.00% | 97.69% | 1.00 | 0.66 |

### Additional metrics — Scenario E

| Metric | FULL | S2 |
|---------|------|----|
| Storage overhead | 3.16x | 2.93x |
| Bootstrap time | 13.94 wk | 14.01 wk |
| Denial rate | **0.67%** | 1.32% |

## Key findings

1. **FULL model tau=1.000 in 4/5 scenarios.** Multiplicative S correctly ranks archetypes under all attacks except the free-rider flood. This confirms Exp 22 against a realistic attack surface.

2. **Escrow blocks HAR at 100%.** HAR rate = 0% in all 10 configurations. The mechanism works regardless of the S formula and adaptive n parameters.

3. **FULL model has lower survival than S2** (96% vs ~98%). The reason: adaptive n reduces redundancy — with multiplicative S, unreliable partners receive low trust, which raises n, but shards are still distributed among them and some are lost.

4. **Scenario D is the problem case.** At 40% free-rider arrivals: survival=91.7%, tau=0.600. Without a gate, free-riders fill partner slots; their low trust triggers high n, which paradoxically worsens coverage. This is an edge condition outside the system's design envelope.

5. **Spite resistance improved.** FULL denial rate 0.67% versus S2 1.32% — multiplicative S penalises attackers more strongly, reducing the probability of a successful denial of service.

6. **S2 has consistently high survival** (~97.7% across all scenarios) despite poor tau. Fixed n=15 provides constant redundancy regardless of ranking accuracy — protection through overprovisioning.

## Open questions

1. **Why does FULL underperform S2 on survival?** Hypothesis: adaptive n is computed from the mean trust of partners. With multiplicative S, unreliable nodes receive very low trust, so n rises, but shards still end up with unreliable partners and losses persist. It is worth testing whether imposing a minimum trust threshold for partner selection helps.

2. **Scenario D:** 40% free-rider arrivals may exceed the design envelope. The adaptive n table needs testing to determine whether it is too aggressive for a high fraction of unreliable nodes.

3. **FULL overhead (3.16x) > S2 (2.93x)** despite adaptive n in Scenario E. Adaptive n likely over-compensates for low-trust partners by generating more shards than fixed n=15.

## Design implications

- **Multiplicative S + escrow are confirmed** as core mechanisms: tau=1.000, HAR=0%.
- **Adaptive n needs tuning.** The current table may be too aggressive: FULL overhead exceeds S2 and survival is lower. More conservative thresholds need investigation.
- **Fixed n=15 is the safe default** for the reference implementation: stable survival and predictable behaviour without parametric tuning.
- **Gate removal is acceptable in 4/5 scenarios**, but is vulnerable to free-rider flooding. Possible mitigations: a conditional gate based on the fraction of unreliable nodes, or a minimum trust threshold for shard allocation.
- **Optimising tau (ranking) and survival (redundancy) are partially competing goals.** Multiplicative S improves ranking accuracy, but adaptive n reacts to that by reducing actual redundancy. The design should explicitly specify which matters more in each scenario.

## Code

`simulations/pis_integration.py` — results in `results/pis_integration/pis_integration_results.json`
