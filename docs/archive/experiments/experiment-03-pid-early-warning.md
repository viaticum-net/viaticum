# Experiment 03: D-component as Early Warning for Repair

## Question
Does monitoring the D (derivative/trend) component of peer reputation allow earlier repair and improve data survival?

## Model
- Peers have dynamic lifecycle: healthy → declining (reliability drops over 14-30 days) → departed
- Two strategies compared on identical scenarios:
  - **PI-trigger:** repair when P_score drops below threshold (peer already bad)
  - **PID-trigger:** repair when D_score goes negative (peer declining, not yet bad) + PI as fallback
- Same erasure coding (7-of-10), same churn, same repair delay
- 30 peers, extreme stress conditions

## Key Result

**D-component provides +30% survival advantage under stress.**

| Churn | Decline | Repair delay | PI-only | PID | Delta |
|---|---|---|---|---|---|
| 70% | 30d | 30d | 61.8% | 92.6% | **+30.8%** |
| 70% | 14d | 30d | 56.6% | 83.8% | **+27.2%** |
| 50% | 14d | 30d | 87.8% | 96.6% | **+8.9%** |
| 50% | 30d | 30d | 90.6% | 98.9% | **+8.2%** |
| 70% | 14d | 14d | 92.3% | 98.7% | **+6.4%** |
| 70% | 30d | 7d | ~100% | ~100% | ~0% |

## Key Findings

1. **D matters when repair is slow.** At 7-day repair, both PI and PID give ~100%. At 30-day repair, D provides massive advantage. This makes sense: D buys you lead time, and lead time matters when repair takes weeks.

2. **D threshold doesn't matter much.** -0.005, -0.01, -0.02 give identical results. The signal is clear enough that any reasonable threshold catches it. This simplifies the protocol — no need to tune D-threshold precisely.

3. **D is useless for ranking but critical for repair.** Experiment 1 showed D doesn't improve static ranking (Kendall's tau). Experiment 3 shows it's essential for **dynamic** decisions (when to repair). Different roles for different components.

4. **Longer decline = more D advantage.** 30-day decline (slow degradation) gives D more time to detect the trend. 14-day decline (fast crash) gives less time but D still helps significantly.

## Design implications

Revise conclusion from Experiment 1: **the system IS a PID controller, not PI.**
- P (window=30d): "how is this peer doing recently?" → used for scoring
- I (cumulative): "how has this peer done historically?" → used for scoring (dominant)
- D (trend): "is this peer getting worse?" → used for **repair triggering** (not scoring)

Trust score = 0.5*P + 2.0*I (PI, for ranking/selection)
Repair trigger = D < any_negative_threshold (PID, for early warning)

This is actually cleaner than using D in the score: D has a specific operational role (early warning) rather than being mixed into a general trust number.

## Conditions for experiment
- 30 peers, 7-of-10 erasure coding
- 36 configs swept (2 churn × 2 decline × 3 repair_delay × 3 d_threshold)
- 30 seeds per config, 24 cores, 11.4 minutes

## Code
`simulations/pid_repair.py` — run with `--sweep --jobs 24 --peers 30 --k 7 --n-shards 10`
