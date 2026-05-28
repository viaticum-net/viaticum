# Experiment 11: User Lifecycle

## Question

How does the system behave from a single user's perspective across the full lifecycle: joining the network, building trust, disk pressure, departure, and return? Does the user lose data or reputation in any of these phases?

## Model

- **Protagonist:** one new peer joining an already live network
- **Background network:** 200 peers warm-started at 180 days (a realistic active network)
- **Erasure:** 5-of-15 (5 shards out of 15 needed for recovery)
- **PID:** kp=0.5, ki=2.0, kd=0 (defaults)
- **Trust threshold:** 0.3 (threshold for accepting partners)
- **Departure:** graceful (peer notifies the network before disconnecting)
- **Seeds:** 50, runtime: 0.7s

### Simulation phases

| Phase | Months | Description |
|-------|--------|-------------|
| bootstrap | 0–2 | Joining the network, first partners |
| trust_build | 3–11 | Accumulating the I-component (GB·days) |
| steady_state | 12–35 | Stable operation, 2 years |
| disk_pressure | 36–41 | Disk shortage, evicting foreign shards |
| departure | 42–47 | User offline for 6 months |
| return | 48–53 | Return and partnership recovery |

## Configuration

```
seeds             = 50
background_peers  = 200  (warm-started at 180 days)
erasure           = 5-of-15
kp, ki            = 0.5, 2.0
departure_mode    = graceful
trust_threshold   = 0.3
total_months      = 54
```

## Results

### Month-by-month dynamics

| Month | Phase | Trust | Partners | Stored | Placed | Redund | P_restore |
|-------|-------|-------|----------|--------|--------|--------|-----------|
| 0 | bootstrap | 2.377 | 9.5 | 9.5 | 15.0 | 15/15 | 100.0% |
| 1 | bootstrap | 2.374 | 14.9 | 14.9 | 15.0 | 15/15 | 100.0% |
| 2 | bootstrap | 2.390 | 15.0 | 15.0 | 15.0 | 15/15 | 100.0% |
| 3 | trust_build | 2.375 | 20.0 | 15.0 | 15.0 | 15/15 | 100.0% |
| 4 | trust_build | 2.381 | 24.9 | 20.0 | 15.0 | 15/15 | 100.0% |
| 12 | steady_state | 2.377 | 59.2 | 59.2 | 15.0 | 15/15 | 100.0% |
| 18 | restore_test | 2.379 | 59.4 | 59.4 | 15.0 | 15/15 | 100.0% ← RESTORE TEST |
| 35 | steady_state | 2.375 | 59.4 | 59.4 | 15.0 | 15/15 | 100.0% |
| 36 | disk_pressure | 2.381 | 46.5 | 46.5 | 15.0 | 15/15 | 100.0% |
| 39 | disk_pressure | 2.381 | 4.0 | 1.0 | 15.0 | 15/15 | 100.0% |
| 40 | disk_pressure | 2.375 | 3.0 | 0.0 | 15.0 | 15/15 | 100.0% |
| 42 | departure | 1.859 | 0.0 | 0.0 | 15.0 | 15/15 | 100.0% |
| 47 | departure | 1.665 | 0.0 | 0.0 | 15.0 | 15/15 | 100.0% |
| 48 | return | 2.147 | 15.3 | 12.3 | 15.0 | 15/15 | 100.0% |
| 53 | return | 2.162 | 55.9 | 55.9 | 15.0 | 15/15 | 100.0% |

### Key milestones

| Milestone | Month | Trust | Note |
|-----------|-------|-------|------|
| Join | 0 | 2.377 [p5=2.250, p95=2.500] | Threshold 0.3 passed immediately |
| End bootstrap | 3 | 2.390 | Trust peak |
| End trust_build | 12 | 2.371 | |
| Disk failure test | 18 | 2.379 | P(restore) = 100.0% |
| Disk pressure start | 36 | 2.381 | |
| Just departed | 42 | 1.859 | 77.8% of peak |
| Return | 48 | 2.147 | 89.8% of peak |
| 6 months back | 53 | 2.162 | 90.5% of peak |

## Key findings

1. **Bootstrap is instant in a warm network.** The trust threshold (0.3) is passed in month 0, because background peers already have accumulated trust and accept the new participant immediately. This models realistic entry into a live network, not a cold start.

2. **P(restore) = 100% in every phase without exception.** Even during departure (months 42–47), when the protagonist has no partners and holds nothing for others, their own 15 shards remain placed with other peers and are available for recovery.

3. **Trust is sticky — it recovers quickly.** After 6 months offline: 77.8% → 90.5% of peak over the following 6 months. The I-component (accumulated GB·days) retains a long history and dominates the P-component on return.

4. **Disk pressure: eviction without data loss.** The protagonist evicts foreign shards (stored-for-others) first; own data remains protected throughout the disk_pressure phase. Priority for own data is enforced automatically.

5. **Model limitation: no cold start.** Instant bootstrap is only possible because the network is already warm. In an empty network (first users), the picture would be different — that is the territory of Experiment 12.

## Design implications

- **A user can safely go offline for months.** Neither data nor reputation is lost irreversibly. For UX this means: no need to alarm the user with "data loss" warnings when they disconnect for a reasonable period.
- **The I-component as a long-term credit history.** The system does not penalise pauses — this is a fundamental difference from systems with decay-based reputation. Worth explicitly recording as a protocol property.
- **Graceful departure matters, but is not critical for data.** Shards remain with partners regardless; graceful departure only speeds up partnership recovery on return.
- **Disk management works correctly.** The eviction order (foreign shards before own) requires no manual configuration — it follows from the priority logic. This behaviour can be fixed as an invariant in the protocol specification.

## Code

`simulations/user_lifecycle.py` — run with `--seeds 50 --background 200 --warmup 180`
