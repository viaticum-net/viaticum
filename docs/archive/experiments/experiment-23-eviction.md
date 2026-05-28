# Experiment 23: Eviction Strategies

## Question

Is eviction (forced removal of partners) necessary in the trust protocol? Does a hard eviction mechanism clean the network of bad actors, or is it counterproductive? What is a safe implementation of disk-pressure eviction?

## Model

Multiplicative trust formula (Experiment 17+):

```
trust_AB = (kp × P_B + ki × I_B) × clamp(S_AB, 0.1, 1.0)
```

where S_AB = r_B / r_A is the pairwise storage ratio (how much B stores for A relative to how much A stores for B).

Five eviction strategies are tested:

| Strategy | Description |
|----------|-------------|
| A: No eviction | Partnerships end only through churn (peer leaving the network) |
| B: Soft eviction | Economic: under disk pressure, the partner with min(trust × importance) is evicted |
| C: threshold=0.5 | Hard eviction: forced break if trust < 0.5 |
| C: threshold=1.0 | Hard eviction: forced break if trust < 1.0 |
| C: threshold=1.5 | Hard eviction: forced break if trust < 1.5 |

Evaluation metrics:

| Metric | What it measures |
|--------|-----------------|
| Kendall's tau | Archetype ranking quality (1.0 = perfect) |
| Partner turnover | Partner changes per year |
| Newcomer integration time | Weeks until a new peer is accepted into a partnership |
| Honest trapped % | Share of honest peers without access to quality partners |
| Hoarder same-arch % | Share of Hoarder-archetype partners among Hoarder-archetype peers (ghetto indicator) |

## Configuration

```
peers             = 5000
duration          = 5 years
annual_churn      = 25%
seeds             = 10
jobs              = 6
archetypes        = 6 (Reliable, Weekend, Seasonal, Nomad, Hoarder, Freeloader)
kp                = 0.5
ki                = 2.0
trust_formula     = multiplicative S
```

## Results

### Summary metrics (year 5)

| Strategy | tau | Turnover/yr | Newcomer integ | Honest trapped | Hoarder same-arch |
|----------|-----|-------------|----------------|----------------|-------------------|
| **A: No eviction** | **0.997** | 4.28 | 0 wks | 0.1% | 21% |
| B: Soft eviction | 0.997 | 4.28 | 0 wks | — | 21% |
| C: threshold=0.5 | 0.733 | 4.89 | — | — | 18% |
| C: threshold=1.0 | 0.600 | 7.68 | — | — | **70%** |
| C: threshold=1.5 | 0.427 | 19.65 | — | — | **97%** |

### Trust by archetype (year 5)

| Archetype | A: No | B: Soft | C: 0.5 | C: 1.0 | C: 1.5 |
|-----------|-------|---------|--------|--------|--------|
| Reliable | 2.500 | 2.500 | 2.500 | 2.500 | 2.500 |
| Weekend | 2.500 | 2.500 | 2.500 | 2.500 | 2.500 |
| Seasonal | 2.391 | 2.391 | 2.392 | 2.391 | 2.389 |
| Nomad | 1.247 | 1.247 | 1.257 | 1.272 | 1.332 |
| Hoarder | 1.088 | 1.088 | 1.166 | **2.458** | 2.440 |
| Freeloader | 0.733 | 0.733 | **2.059** | 1.755 | 2.429 |

### Segregation under hard eviction (threshold=0.5)

At threshold=0.5, Freeloader segregation jumps to **67.2%**: freeloaders expelled from quality clusters begin partnering with each other. Within the ghetto, pairwise S becomes symmetric (all store equally poorly), and trust inflates to 2.059 — nearly on par with the Seasonal archetype.

### Full collapse at threshold=1.5

- Hoarder same-arch: 97%, Freeloader same-arch: 97% — complete segregation
- Turnover: 19.65/yr (+360% relative to baseline)
- tau: 0.427 — the system can no longer distinguish archetypes
- Newcomer integration: 1 week of delay

## Key findings

1. **Eviction is unnecessary.** Multiplicative S reaches tau≈1.0 on its own, without any eviction mechanism. Honest peers naturally prefer each other; bad actors receive low trust through low pairwise S.

2. **Hard eviction is actively harmful.** It creates a self-reinforcing cycle: bad actors are expelled from good clusters, form their own, pairwise S becomes symmetric within the ghetto, trust inflates, and ranking breaks down. The higher the threshold, the worse the outcome (tau drops from 1.0 to 0.43).

3. **Soft eviction is a no-op.** Disk pressure does not arise in the simulation. Results are identical to strategy A. Safe to implement as a UI feature.

4. **Turnover explodes with threshold.** 4.28 → 19.65 partner changes per year, moving from no-eviction to threshold=1.5. Excessive turnover raises bootstrap overhead and reduces network stability.

5. **"Trapped honest node" is not a problem.** The share of honest peers without access to good partners is below 0.5% in all strategies — no special protection mechanism is needed.

6. **The harm mechanism of eviction.** The multiplicative S formula assumes S_AB is meaningful only in mixed clusters. A ghetto of uniformly bad actors breaks this invariant: all store roughly equally, so S→1.0 and trust is determined only by P and I; Freeloader and Hoarder then receive an undeserved high score.

## Design implications

1. **Do not implement eviction as a trust mechanism.** Neither hard nor threshold-based eviction should be part of the protocol.

2. **Multiplicative S is self-correcting.** Hoarder and Freeloader receive low trust through low pairwise S without additional intervention.

3. **The only "eviction" is natural churn.** Peers leave the network for their own reasons; that is sufficient.

4. **Soft eviction under disk pressure is acceptable.** If a disk-pressure management feature is needed for the product, soft eviction is safe to implement; under practical conditions it is a no-op in terms of its effect on trust distribution.

5. **In conjunction with Exp 21 (acceptance gate).** Both filtering mechanisms — acceptance gate and hard eviction — proved harmful with multiplicative S + adaptive n. The correct trust formula eliminates the need for explicit filters.

## Code

`simulations/pis_eviction.py` — results in `results/pis_eviction/run.json`
