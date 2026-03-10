# Experiment 01: PID Reputation Convergence

## Question
Does PID-style reputation correctly rank peers by reliability? How fast?

## Model
- N peers (1000) with true reliability from 3 classes:
  - 20% reliable (90-99%), 60% normal (50-80%), 20% lazy (10-40%)
- Each timestep = 1 day, proof-of-storage check (Bernoulli)
- PID controller per peer:
  - P = rolling window average over last W days
  - I = cumulative average over all time (GB·days analog)
  - D = rate of change of P
- Trust = Kp*P + Ki*I + Kd*D
- Metric: Kendall's tau (perceived rank vs true reliability rank)

## Results

### EMA mode (first pass, alpha instead of window)
Best: Kp=0.5, Ki=2.0, Kd=0.0, alpha=0.05 → tau=0.911, 0.8 at day 41, 0.9 at day 261

### Rolling window mode (108 configs, 24 cores, 42s)
Best: Kp=0.5, Ki=2.0, Kd=0.0, window=30 → tau=0.907, 0.8 at day 39, 0.9 at day 290

### Divergence boundary (window size)
```
window=30: tau 0.86-0.91 — works
window=14: tau 0.82-0.89 — works, worse
window=7:  tau 0.73-0.87 — borderline
window=3:  tau 0.49-0.84 — most configs fail to reach 0.8
```

## Key findings

1. **I (history) is the dominant signal.** Ki=2.0 beats Ki=0.5 and 1.0 across all configs. Accumulated history (GB·days) is the most reliable indicator — unforgeable, requires time investment.

2. **P (current state) should be dampened.** Kp=0.5 beats Kp=1.0 and 2.0. Current state is noisy — one failed check shouldn't change the picture.

3. **D (derivative) is useless for scoring.** Kd=0.0 is best everywhere. D may still be useful for UI alerts ("this peer is declining") but doesn't improve ranking accuracy.

4. **Longer P window = better.** Window=30d beats 14d beats 7d. The system needs a month of P observations to distinguish signal from noise.

5. **Effectively a PI controller, not PID.** D adds noise, not value. Simplifies the design.

6. **Convergence timeline:**
   - Day 1: tau ~0.39 (PID knows nothing)
   - Day 7: tau ~0.63 (distinguishes classes)
   - Day 30: tau ~0.76 (good)
   - Day 40: tau >= 0.80 (reliable ranking)
   - Day 290: tau >= 0.90 (precise ranking)

## Design implications for RESEARCH.md

- Trust formula: Trust = 0.5 * P_30d + 2.0 * I_cumulative
- Newcomer needs ~40 days to be reliably ranked
- Aligns with "insurance model": newcomer stores for others 40 days before restore unlocks
- D-component: keep for monitoring/alerts, remove from trust score

## Code
`simulations/pid_convergence.py` — run with `--sweep --jobs 24`
