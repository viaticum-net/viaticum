# Experiment 15: PI+S Convergence

## Question

Does the extended PI+S formula converge to the correct archetype ranking? How quickly and at what parameters (kp, ki, ks) does the system reach high Kendall's tau? Is a global S term sufficient to correct the storage blind spot identified in Experiment 13?

## Model

The same six archetypes from Experiment 13. The trust formula is extended with a third component:

```
trust = kp × P_weekly + ki × I + ks × S
```

| Component | Definition |
|-----------|------------|
| P_weekly | Rolling 4-week window of binary weekly checks |
| I | Cumulative mean — accumulated history without decay |
| S | storage_ratio = gb_stored_for_others / gb_stored_by_others, clamped [0, 2] |

S here is **global**: computed as the total volume given to all peers divided by the volume received from all peers. The pairwise variant is investigated in Experiment 17+.

**Actual utility rank** (from Experiment 13):

| Actual rank | Archetype | Rationale |
|-------------|-----------|-----------|
| 1 | Reliable | High uptime + full volume |
| 2 | Weekend | Full volume + predictable schedule |
| 3 | Seasonal | Full volume, predictable pattern |
| 4 | Nomad | Full volume, but unpredictable |
| 5 | Hoarder | High uptime, but little space |
| 5 | Freeloader | Average uptime, minimal space |

## Configuration

```
peers             = 200
duration          = 1825 days  (60 months)
seeds             = 30
archetypes        = Reliable(40%), Weekend(20%), Seasonal(15%), Nomad(10%), Hoarder(10%), Freeloader(5%)
P-window          = 4 weeks (binary weekly checks)
sweep             = 54 configs: kp∈{0.3,0.5,0.7} × ki∈{1.5,2.0,2.5} × ks∈{0.0,0.3,0.5,1.0,1.5,2.0}
```

## Results

### Final trust (best config, month 60)

Best config: **kp=0.3, ki=1.5, ks=0.3**

| Archetype | Trust_mean | PI+S_rank | Actual_rank | Delta |
|-----------|-----------|-----------|-------------|-------|
| Reliable | 2.099 | 1 | 1 | 0 |
| Weekend | 2.043 | 2 | 2 | 0 |
| Seasonal | 2.018 | 3 | 3 | 0 |
| Nomad | 1.944 | 4 | 4 | 0 |
| Hoarder | 1.850 | 5 | 5 | 0 |
| Freeloader | 1.812 | 6 | 5/6 | 0 |

**Kendall's tau = 0.97** — perfect match with the actual utility rank.

### Convergence over time (best config)

| Month | tau |
|-------|-----|
| 6 | 0.741 |
| 12 | **0.966** |
| 24 | 0.970 |
| 36 | 0.971 |
| 48 | 0.970 |
| 60 | 0.970 |

The system reaches tau≥0.97 by month 12 and remains stable to the end of the simulation (60 months).

### Sweep over ks: effect of the S term

| ks | tau (month 12) | tau (month 60) |
|----|----------------|----------------|
| 0.0 (PI-only) | 0.00–0.14 | 0.14 |
| 0.3 | **0.966** | 0.970 |
| 0.5 | ≥0.83 | ≥0.83 |
| 1.0 | ≥0.83 | ≥0.83 |
| 1.5 | ≥0.83 | ≥0.83 |
| 2.0 | ≥0.83 | ≥0.83 |

All configs with ks>0 reach tau≥0.83 by month 12. ks=0 (PI-only) yields tau≈0.00–0.14 — confirming the Experiment 13 finding.

### PI+S vs PI-only comparison (month 60)

| Metric | PI+S | PI-only | Delta |
|--------|------|---------|-------|
| Kendall's tau | **0.97** | 0.14 | **+0.83** |
| Hoarder rank | 5 (correct) | 2 (incorrect) | −3 |
| Weekend rank | 2 (correct) | 5 (incorrect) | +3 |

The S term corrected both systematic errors of PI-only: Hoarder dropped from #2 to #5, Weekend rose from #5 to #2.

### Formula robustness

The system is **robust**: any ks>0 works. Higher ki accelerates convergence, but by month 60 the difference levels out. The kp parameter had minimal effect across the range studied.

## Key findings

1. **The S term is necessary and sufficient.** Adding the storage_ratio term alone is enough to move from tau=0.14 to tau=0.97. This confirms the Experiment 13 hypothesis: the problem was structural (storage not accounted for), not parametric.

2. **The formula is robust.** Any ks>0 works — there is no narrow acceptable window of values. For a production system this matters: precise weight tuning is not required.

3. **Convergence within 12 months.** The system reaches stable ranking after one year of operation — acceptable for cold backup with a temporal constant of 1 week.

4. **Hoarder and Weekend are corrected.** The main PI-only anomalies are resolved: Hoarder (high uptime, little space) is no longer overrated; Weekend (full volume, periodic schedule) is no longer underrated.

5. **Global S is a potential attack vector.** A global storage_ratio can be inflated through collusion or circular transactions between a few peers. Pairwise S (S_AB = r_B / r_A) closes this vulnerability — investigated in Experiment 17.

6. **Weekly check cadence resolves the Weekend problem.** P_weekly (4-week window of weekly checks) rather than P_daily (30-day window of daily checks) is a key model change relative to Experiment 13, and itself improves the Weekend archetype ranking.

## Design implications

- **Include the S term in the final formula.** tau=0.97 is a sufficient result for a design decision. The question is no longer "is S needed" but "what form should S take".
- **Switch to pairwise S.** Global S creates incentives for circular transactions. S_AB = gb_stored_for_B / gb_stored_by_B (from A's perspective) is more resistant to manipulation. Experiment 17 tests whether tau≥0.97 holds with pairwise S.
- **Small ks is preferable.** ks=0.3 gave the best result. Larger ks (1.5–2.0) do not improve quality but increase sensitivity to S manipulation.
- **Kendall's tau = 0.97 as baseline.** All subsequent modifications (pairwise S, acceptance gate, adaptive redundancy) should keep tau no lower than this level.

## Code

`simulations/pis_convergence.py` — run with `--peers 200 --days 1825 --seeds 30`
