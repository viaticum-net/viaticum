# Experiment 14: Individual Node Perspective

## Question

How does the system look from the perspective of a single concrete node in three practically important situations: operating with unreliable partners, an extended absence (holiday), and gradual disk fill? How "quiet" is the system in normal operation? What exactly should be shown to the user?

## Model

Three independent scenarios, each modelling one protagonist surrounded by 100 background peers. Common parameters:

- **Erasure:** 5-of-15 (k=5, n=15)
- **PID:** kp=0.5, ki=2.0, kd=0 (defaults)
- **Seeds:** 50 per scenario

**Scenario 1 — Flaky Partners:** heterogeneous network with varying reliability levels, 12 months, 30% annual churn.

**Scenario 2 — Vacation:** homogeneous network @0.90, three phases: 6 months before departure, 14 days offline, 3 months after return.

**Scenario 3 — Disk Pressure:** homogeneous network @0.90, 18 months, disk with 100 slots, 50% free at the start, occupancy growing at 3.0 slots/month, 30 initial partners.

## Configuration

```
seeds             = 50
background_peers  = 100
erasure           = 5-of-15

# Scenario 1
reliability_mix   = {reliable: 60%@0.95, moderate: 25%@0.80, flaky: 15%@0.50}
duration          = 12 months
annual_churn      = 30%

# Scenario 2
reliability       = 0.90 (uniform)
pre_vacation      = 6 months
vacation          = 14 days
post_vacation     = 3 months

# Scenario 3
reliability       = 0.90 (uniform)
duration          = 18 months
disk_slots        = 100
disk_free_initial = 50%
disk_growth       = 3.0 slots/month
initial_partners  = 30
eviction_buffer   = 5%
```

---

## Scenario 1: Flaky Partners

### Conditions

100 peers with varying reliability: 60 reliable (@0.95), 25 moderate (@0.80), 15 flaky (@0.50). Annual churn of 30% — unreliable peers naturally drop out faster. Simulation runs for 12 months.

### Results

| Month | OwnShards | AtRisk | Repairs | D-warns | P_restore |
|-------|-----------|--------|---------|---------|-----------|
|     1 |      15.0 |    2.2 |    1.00 |    5.76 |    100.0% |
|     2 |      15.0 |    1.7 |    1.14 |    5.54 |    100.0% |
|     3 |      15.0 |    1.4 |    0.90 |    5.18 |    100.0% |
|     6 |      15.0 |    0.9 |    0.66 |    3.86 |    100.0% |
|     9 |      15.0 |    0.6 |    0.64 |    3.46 |    100.0% |
|    12 |      15.0 |    0.1 |    0.66 |    3.48 |    100.0% |

D-warning events: avg 55.2/year [p5=42.4, p95=68.5]
True positive rate: 9% (warning before an actual departure within 30 days)
False positive rate: 91%

### Key findings

1. **The system self-heals invisibly.** All 15/15 shards are retained throughout the year; P(restore) = 100% at every point. Repairs (~0.8/month) happen automatically without intervention.

2. **Storage quality improves over time.** AtRisk shards (placed with unreliable holders) fall from 2.2 to 0.1 as bad peers are eliminated by churn and their slots are taken by proven partners.

3. **D-warnings are too noisy for direct UX.** 55 events per year at a 91% false-positive rate cannot be shown to the user as-is. Aggregation or filtering is required before display.

---

## Scenario 2: Vacation (14 days offline)

### Conditions

The protagonist is active on the network for 6 months (accumulating trust), then goes offline for 14 days, then returns. Network of 100 peers @0.90 reliability.

### Results

Pre-vacation trust: 2.367 [p5=2.283, p95=2.439]
Trust loss during vacation: 0.357 [p5=0.334, p95=0.373]

| Phase        |  Day | Trust | P_score | I_score | OwnShards | P_restore |
|--------------|------|-------|---------|---------|-----------|-----------|
| Pre-vacation |  179 | 2.367 |   0.945 |   0.947 |      15.0 |    100.0% |
| Vacation d1  |  180 | 2.340 |   0.913 |   0.942 |      15.0 |    100.0% |
| Vacation d7  |  186 | 2.184 |   0.722 |   0.912 |      14.8 |    100.0% |
| Vacation d14 |  193 | 2.009 |   0.503 |   0.879 |      14.6 |    100.0% |
| Post d1      |  194 | 2.010 |   0.504 |   0.879 |      14.6 |    100.0% |
| Post d7      |  200 | 2.014 |   0.504 |   0.881 |      14.6 |    100.0% |
| Post d30     |  223 | 2.251 |   0.949 |   0.888 |      14.6 |    100.0% |

### Key findings

1. **Data is completely safe during the holiday.** P(restore) = 100% throughout, including all 14 offline days. 14.6/15 shards remain at the end of the absence; natural losses from network churn, but k=5 provides ample margin.

2. **The P-component and I-component behave differently.** P-score halves (0.945 → 0.503) — it reflects current activity and reacts quickly. I-score drops only 7.2% (0.947 → 0.879) — six months of accumulated history absorbs a short absence.

3. **Trust recovers within 30 days.** After returning, trust is 2.251 — 95.1% of the pre-holiday level (2.367). Not full recovery, but the difference is practically negligible.

4. **UX conclusion: a holiday is completely safe.** Users need not worry about disconnecting for two weeks. Neither data nor reputation is lost irreversibly.

---

## Scenario 3: Disk Pressure

### Conditions

The protagonist starts with 30 partners and holds their shards. Disk fills at 3.0 slots/month. Once free space reaches the 5% buffer, the system begins evicting the lowest-trust partners.

### Results

| Month | FreeSpace% | StoredFor | OwnShards |  Trust | Evictions | P_restore |
|-------|------------|-----------|-----------|--------|-----------|-----------|
|     1 |      38.1% |      30.0 |      15.0 |  2.377 |      0.00 |    100.0% |
|     3 |      32.1% |      30.0 |      15.0 |  2.372 |      0.00 |    100.0% |
|     6 |      23.1% |      30.0 |      15.0 |  2.368 |      0.00 |    100.0% |
|     9 |      14.1% |      30.0 |      15.0 |  2.374 |      0.00 |    100.0% |
|    12 |       5.1% |      30.0 |      15.0 |  2.378 |      0.00 |    100.0% |
|    15 |       4.1% |      22.0 |      15.0 |  2.380 |      3.00 |    100.0% |
|    18 |       4.1% |      13.0 |      15.0 |  2.378 |      3.00 |    100.0% |

Total evictions: avg 17.0 [p5=17.0, p95=17.0]

### Key findings

1. **Disk fill is linear; eviction only starts at the threshold.** 12 months of free fall (38% → 5%) with no evictions at all. The system does nothing while space is available.

2. **Eviction is gradual and ordered.** Once the threshold is reached, the system removes 3 partners per month (lowest-trust partners go first). 30 → 22 → 13 over 6 months of eviction; 17 total evictions out of 30 initial partners.

3. **Own data is always protected.** OwnShards = 15.0 throughout all 18 months; P(restore) = 100%. Eviction only affects shards held for others — own shards are always prioritised.

4. **Trust is unaffected by eviction.** Trust remains stable at 2.37–2.38 throughout, including the active eviction phase. Reducing "store for others" commitments does not affect reputation.

5. **UX conclusion: disk fills up and the system quietly frees space.** The user only needs to know that space is running low. What exactly gets evicted is an implementation detail, not a UX concern.

---

## Key findings

1. **In normal operation the system is invisible.** Repairs, evictions, warnings — all happen automatically. The user need not know anything as long as P(restore) = 100%.

2. **14-day holiday: −15.1% trust, recovery within 30 days.** Data is fully safe. The I-component acts as a buffer that absorbs brief pauses.

3. **Disk pressure: smooth degradation through automatic eviction.** Zero impact on own data. Priority is always with the user's own files.

4. **D-warnings: 91% false-positive rate.** A valuable internal metric for repair decisions, but unsuitable for direct display in the UI without aggregation.

## Design and UX implications

- **Primary metrics to display:** P(restore) — always (the core guarantee), trust trend (rising/stable/falling), free disk space. Everything else belongs in an "advanced" section.

- **D-warnings only behind a disclosure.** At a 91% false-positive rate, showing them directly clutters the interface. Apply aggregation: show only when several D-events occur in a short window, or only for specific partners.

- **No alarmism about holidays.** If the user knows they are going offline for two weeks, no scaremongering is needed. A forecast is appropriate: "Back in 14 days — trust will recover within a month. Data is safe."

- **Disk: notify early.** When free space drops below 15%, send a notification. Below 5%, warn that evictions are starting. No action required from the user; this is purely informational.

- **Eviction is transparent but not alarming.** If a partner was evicted, it can appear in the event log, but as normal system operation ("Disk full, space freed"), not as an error.

- **Trust as a dashboard, not an alert.** A 15% trust drop over two weeks is not an incident. Show a trend line, not red warnings, as long as P(restore) remains high.

## Code

`simulations/node_perspective.py` — run with `--scenario flaky`, `--scenario vacation`, `--scenario disk` and `--seeds 50`
