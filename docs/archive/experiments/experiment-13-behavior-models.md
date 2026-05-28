# Experiment 13: Behavior Models / Archetypes

## Question

How do real usage patterns affect PI reputation? How well does PI ranking match the actual "usefulness" of a peer? Are there user archetypes that the system systematically over- or underestimates?

## Model

Six user archetypes reflecting real availability and storage patterns:

| Archetype | Share | Uptime | Storage capacity | Description |
|-----------|-------|--------|-----------------|-------------|
| Reliable | 40% | 99% | 100% | Always online, full capacity |
| Weekend | 20% | 95% weekends / 30% weekdays | 100% | Online at weekends, rarely on weekdays |
| Seasonal | 15% | 95% semester / 20% summer | 100% | Student: active autumn–spring, disappears in summer |
| Nomad | 10% | ~50% random ON/OFF blocks | 100% | Unpredictable online/offline periods |
| Hoarder | 10% | 90% | 20% | Almost always online but contributes little storage |
| Freeloader | 5% | 80% | 10% | Online most of the time, contributes minimal storage |

**Actual usefulness rank** (from the network's perspective; higher = more useful):

| Actual rank | Archetype | Rationale |
|-------------|-----------|-----------|
| 1 | Reliable | High uptime + full capacity |
| 2 | Weekend | Full capacity + predictable schedule |
| 3 | Seasonal | Full capacity, predictable pattern |
| 4 | Nomad | Full capacity, but unpredictable |
| 5 | Hoarder | High uptime, but little storage |
| 5 | Freeloader | Moderate uptime, minimal storage |

## Configuration

```
peers             = 200
duration          = 730 days  (24 months)
seeds             = 50
kp, ki            = 0.5, 2.0
P-window          = 30 days
kd                = 0
erasure           = 5-of-15
```

## Results

### Final trust (month 24)

| Archetype | Trust_mean | PI_rank | Actual_rank | Delta |
|-----------|-----------|---------|-------------|-------|
| Reliable | 2.475 | 1 | 1 | 0 |
| Hoarder | 2.251 | 2 | 5 | **+3** |
| Freeloader | 2.000 | 3 | 5 | **+2** |
| Seasonal | 1.992 | 4 | 3 | -1 |
| Weekend | 1.458 | 5 | 2 | **-3** |
| Nomad | 1.248 | 6 | 4 | -2 |

**Kendall's tau = 0.000** — PI ranking does not correlate with actual usefulness.

### Kendall's tau over time

| Period | Months | tau |
|--------|--------|-----|
| Early | 1–5 | 0.276 |
| Mid | 6–12 | 0.000 |
| Late-1 | 13–17 | 0.138 |
| Late-2 | 18–24 | 0.000 |

Maximum of 0.276 reached only in the first months. Over the long term the correlation is consistently near zero.

### Seasonal dynamics (Seasonal archetype)

| Event | Month | Trust | Change |
|-------|-------|-------|--------|
| Semester (year 1) | 1–5 | ~2.37 | — |
| Year 1 summer drop | 6 | 2.373 → 1.446 | **−0.927** |
| Year 1 Sep recovery | 9 | 1.446 → 1.827 | +0.381 |
| Semester (year 2) | 10–17 | ~2.10 | — |
| Year 2 summer drop | 18 | 2.105 → 1.560 | **−0.545** |
| Year 2 Sep recovery | 21 | 1.560 → 1.837 | +0.277 |

The I-component softens the summer drop in year 2: −0.545 vs −0.927 in year 1 (41% smaller).

### Storage blind spot

| Archetype | Uptime | Storage | Trust | PI_rank | Actual_rank | Verdict |
|-----------|--------|---------|-------|---------|-------------|---------|
| Hoarder | 90% | 20% | 2.251 | 2 | 5 | Overrated by 3 positions |
| Freeloader | 80% | 10% | 2.000 | 3 | 5 | Overrated by 2 positions |
| Weekend | 95%/30% | 100% | 1.458 | 5 | 2 | Underrated by 3 positions |

The PI controller only measures reliability of check responses (uptime). The volume of storage contributed to others is not part of the formula.

## Key findings

1. **PI correctly identifies the extremes.** Reliable (#1) and Nomad (#6) are placed correctly. The middle is scrambled.

2. **Hoarder/Freeloader exploit.** High uptime + low storage contribution → high trust. PI does not see the storage imbalance. This is the most serious vulnerability: a peer can free-ride on the network simply by answering checks without contributing real space.

3. **Weekend Warrior is seriously underrated.** The peer contributes 100% storage capacity and is available 3 days a week, yet PI places it at #5 — because weekday checks (70% of days) frequently fail. By actual contribution this is the second-best archetype.

4. **Seasonal recovery works well.** The I-component buffers the summer drop: the fall in year 2 is 41% smaller than in year 1. Trust "memory" protects seasonal users, giving them time to recover.

5. **Kendall's tau = 0.0 is not a parameter problem.** It is a structural problem with the formula: PI measures the wrong thing. No tuning of kp/ki can fix the fact that storage volume does not enter the calculation at all.

6. **Implication for Exp 05.** A storage-balance term is needed: `GB stored for others / GB stored by others`. Without it, Hoarder/Freeloader will be systematically overrated.

7. **Weekend users need a different window.** A P-window of 30 days (with daily checks) penalises regular but periodic availability. A weekly check cadence, or treating a 7-day window as the unit, would remove this bias.

## Design implications

- **Add a storage term to the trust formula.** `trust += w_s × (gb_stored_for_others / gb_stored_by_others)` — this directly penalises Hoarder/Freeloader and rewards real contribution. Candidate for Exp 14.
- **Reconsider P-window granularity.** A weekly check cadence instead of daily would eliminate the systematic underrating of the Weekend archetype without sacrificing sensitivity to real problems.
- **The I-component is sufficient for seasonal users** — no special "freeze" mechanism is needed. Buffering based on accumulated history works.
- **Kendall's tau as a protocol quality metric.** Worth including in the standard simulation metric set: if tau < 0.5, the trust formula inadequately reflects actual usefulness.
- **Do not rely on uptime as the sole signal.** Uptime is necessary but not sufficient. A Hoarder with 90% uptime is objectively less useful than a Weekend user with full capacity who happens to be offline during weekday checks.

## Code

`simulations/behavior_models.py` — run with `--peers 200 --days 730 --seeds 50`
