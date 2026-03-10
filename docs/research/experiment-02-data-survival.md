# Experiment 02: Data Survival Under Churn

## Question
What fraction of files survive 1-5 years with realistic churn? Where is the breaking point?

## Model
- N peers with daily leave probability (derived from annual churn rate)
- Departed peers may rejoin (50% chance, ~30 day delay)
- New peers join (10/month)
- Each file = k-of-n erasure coded shards on distinct peers
- File LOST when < k shards are on live peers at check time
- Owner checks shard health every 7 days, repair takes R days
- Metric: file survival rate at 1, 2, 3 years

## Results

### Full sweep (60 configs, 24 cores, 5.8 min)
At 500 peers: **everything survives.** Even 6-of-10 at 50% churn with 14d repair = 99.9%.

The system is extremely resilient with enough peers. Erasure coding + weekly repair handles normal churn effortlessly.

### Stress tests (finding the breaking point)

| Peers | Churn | k-of-n | Repair | 1y | 3y | 3y worst |
|---|---|---|---|---|---|---|
| 500 | 50% | 6-of-10 | 14d | 100% | 100% | 99.9% |
| 50 | 50% | 6-of-10 | 7d | 100% | 100% | 99.9% |
| 50 | 50% | 6-of-10 | 14d | 100% | 99.97% | 99.7% |
| 50 | 50% | 5-of-15 | 14d | 100% | 100% | 100% |
| 100 | 50% | 6-of-10 | 14d | 100% | 99.95% | 99.7% |
| **50** | **70%** | **6-of-10** | **30d** | **97.4%** | **92.2%** | **87.7%** |

### Key findings

1. **System is very hard to break.** Even 50 peers with 50% annual churn and 14-day repair gives 99.97% survival over 3 years. Need extreme conditions (70% churn + 30d repair) to see meaningful loss.

2. **Repair delay is the critical variable.** At 50 peers/50% churn:
   - 7d repair → 100%
   - 14d repair → 99.97%
   - 30d repair + 70% churn → 92%
   This confirms: cold backup model (weekly checks, week-long repair) works fine.

3. **More shards > more redundancy.** 5-of-15 (same overhead as 6-of-10) survives better because it tolerates 10 shard losses vs 4. More peers holding shards = more resilience.

4. **Network size barely matters above 50.** 50 peers vs 500 peers: almost identical survival. What matters is k-of-n ratio and repair speed, not network size.

5. **Repair traffic is manageable.** Worst case (50 peers, 50% churn, 5-of-15): 18 shards/file/year. For 100GB of data in 15 shards = ~120 GB repair traffic/year = ~2.3 GB/week upload. Easily handled by home internet.

## Design implications

- Default 5-of-15 for documents is massively overkill (great — that's the point)
- 6-of-10 for video is fine even under stress
- Weekly check + weekly repair is the sweet spot
- The system fails gracefully: even in extreme scenarios, 88%+ of files survive
- D-component from PID could help: early detection of declining peers → earlier repair → better survival (experiment 3 candidate)

## Code
`simulations/data_survival.py` — run with `--sweep --jobs 24`
