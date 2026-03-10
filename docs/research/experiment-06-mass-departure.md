# Experiment 06: Mass Departure (Shock Event)

## Question
What happens when 30-50% of the network leaves simultaneously? How does instant shock compare to gradual churn?

## Model
- 500 peers, 1000 files, 6-month buildup phase with normal trust accumulation
- At month 6: shock event — selected fraction departs
- **Four departure modes:**
  - `instant` — peers vanish simultaneously, no warning
  - `gradual_3mo` — same fraction departs over 3 months (distributed)
  - `gradual_6mo` — same fraction departs over 6 months
  - `death_scream` — peers vanish but notify (instant repair trigger)
- D-trigger for early repair: D < -0.01 → preemptive repair
- Recovery tracked: weekly repair cycles, capacity limits on surviving peers

## Sweep Parameters
- Shock fraction: [10%, 20%, 30%, 50%, 70%]
- Departure mode: [instant, gradual_3mo, gradual_6mo, death_scream]
- Erasure profiles: 5-of-15, 7-of-10
- 40 configs, 30 seeds each, 24 cores, 3.8 minutes

## Key Results

### 5-of-15 (documents profile) — resilient up to 50%

| Shock | Instant | Gradual 3mo | Gradual 6mo | Death Scream |
|-------|---------|------------|------------|-------------|
| 10% | **100%** | 100% | 100% | 100% |
| 20% | **100%** | 100% | 100% | 100% |
| 30% | **99.94%** | 100% | 100% | 99.94% |
| 50% | **94.44%** | 100% | 100% | 94.44% |
| 70% | **48.41%** | 97.77% | 94.81% | 48.41% |

5-of-15 survives 20% instant shock with zero losses, 30% with only 0.06% loss. At 50%, ~5.6% of files lose enough shards. At 70%, half the files are unrecoverable.

### 7-of-10 (media profile) — fragile under shock

| Shock | Instant | Gradual 3mo | Gradual 6mo | Death Scream |
|-------|---------|------------|------------|-------------|
| 10% | **98.79%** | 100% | 100% | 98.79% |
| 20% | **87.97%** | 99.99% | 100% | 87.97% |
| 30% | **65.16%** | 99.89% | 99.99% | 65.16% |
| 50% | **16.90%** | 98.31% | 99.72% | 16.90% |
| 70% | **1.02%** | 79.49% | 58.44% | 1.02% |

7-of-10 loses files even at 10% instant shock. At 30%, over a third of files are permanently lost. At 70%, effectively total wipeout.

## Key Findings

1. **Instant shock vs gradual: night and day.** 70% instant shock on 7-of-10 → 1.0% survival. Same 70% spread over 3 months → 79.5% survival. Weekly repair cycles can keep pace with gradual departure but not instant.

2. **Death scream provides ZERO benefit for instant shock.** Death_scream results are identical to instant in every single configuration. Files that drop below k shards can't be reconstructed regardless of notification speed.

3. **5-of-15 is dramatically more shock-resistant.** The wider erasure code (tolerance = 10 shard losses) handles 20% shock with zero losses, 30% with only 0.06% loss. 7-of-10 (tolerance = 3) loses 12% of files at just 20% instant shock.

4. **Gradual 6mo is worse than 3mo at extreme shock.** At 70% shock, 3-month gradual gives 97.8% survival (5-of-15) vs 94.8% for 6-month. The longer window spreads repairs but also means continuous damage accumulation.

5. **The repair capacity bottleneck is real.** Surviving peers must absorb all the shards of departed peers. At 70% shock, each survivor handles ~2.3x their normal load. Capacity limits prevent full recovery.

## Recovery Time

| Config | Recovery |
|--------|----------|
| 5-of-15, ≤30% any mode | 0 weeks (no damage) |
| 5-of-15, 70% gradual_3mo | **12 weeks** |
| 5-of-15, 70% gradual_6mo | **never** (still declining) |
| 7-of-10, 50% gradual_3mo | **10 weeks** |
| 7-of-10, 50% gradual_6mo | **1 week** |
| 7-of-10, 70% gradual_3mo | **12 weeks** |
| 7-of-10, 70% gradual_6mo | **never** (still declining at end) |

## Design Implications

- **5-of-15 should be the minimum erasure profile** for any data the user cares about. The 2x overhead pays for resilience.
- **Death scream is useful only for gradual degradation**, not instant shock. The protocol should include it (it's cheap) but not rely on it.
- **Network partition is the real threat.** If an ISP blocks the protocol and 30% of users are on that ISP, 7-of-10 files lose 35% of data instantly. Wider erasure + geographic diversity (from Exp 10) are the combined defense.
- **Recovery planning:** the protocol should monitor network size and warn when it drops rapidly. A 20% drop in active peers within a week should trigger emergency repair priority.
- **Capacity reservation:** peers should pre-commit emergency capacity for shock scenarios. The "commitment levels" (Stable→Pressured→Evicting) from section 4.11 handle this.

## Code
`simulations/mass_departure.py` — run with `--sweep --jobs 24`
