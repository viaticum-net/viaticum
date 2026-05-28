# Experiment 27: Shard Placement in Saturated Network

## Question

In a saturated network (all disks full), every shard placement displaces something. Which hysteresis strategy minimises eviction cascades and data loss? Does the Budget Planner help (by skipping placement when success is unlikely)?

## Motivation

The rational strategy for any node is to replicate as much as possible. A fully mature network therefore tends to have no free space. Experiments 1-26 modelled a growing network, not a saturated one. This is a different regime.

## Model

### Eviction priority (holder side)

```
eviction_priority = importance × trust_of_owner × (1 + age_bonus)
age_bonus = min(weeks_stored / 26, 0.3)
```

The shard with the lowest priority is evicted first. An evicted shard attempts to move to another partner (cascade).

### Hysteresis strategies

| Strategy | Description |
|----------|-------------|
| A | No hysteresis (evict if new_priority > min_priority) |
| B | Threshold H=0.2 (new_priority > min × 1.2) |
| C | Time bonus +30% (old shards gain a bonus of up to 30% over 26 weeks) |
| D | Combined (B+C) |
| E | D + Budget Planner (skip placement if fewer than K partners will accept) |

### Scenarios

| Scenario | Description |
|----------|-------------|
| 1 | Saturated steady-state: 200 nodes, pre-fill 90%, 52 weeks of dirty data |
| 2 | Newcomer: same network + one newcomer every 4 weeks, bandwidth 30 GB/wk |

### Configuration

```
nodes              = 200
bootstrap          = 52 weeks (trust build-up)
simulation         = 52 weeks
pre-fill           = 90% utilization
chunk_size         = 20 GB per entry
data_gb            = 500 ± 200 (min 50)
dirty_gb/week      = 5 ± 2
offer_ratios       = [1.0, 1.5, 2.0, 3.0]
trust              = (0.5×P + 2.0×I) × clamp(S, 0.1, 1.0)
RS                 = k=5, n_high=15, n_low=5
partners           = 15
cascade_limit      = 10
importance         = beta(2, 1.5), mean ~0.57
seeds              = 10
```

## Results v2: Hysteresis Strategies (A-D)

### Scenario 1: Saturated steady-state

| Strat | Ratio | Success% | Evict/wk | Cascade | Coverage | Loss GB |
|-------|-------|----------|----------|---------|----------|---------|
| A | 1.0 | 71.9% | 2354 | 0.63 | 36.0% | 37001 |
| A | 1.5 | 78.7% | 2128 | 0.59 | 49.4% | 39580 |
| A | 3.0 | 87.0% | 1572 | 0.46 | 69.3% | 36103 |
| B | 1.0 | 65.3% | 1705 | 0.49 | 35.1% | 37281 |
| B | 1.5 | 74.0% | 1669 | 0.50 | 48.9% | 39504 |
| B | 3.0 | 84.6% | 1331 | 0.41 | 69.6% | 36186 |
| C | 1.0 | 64.6% | 1953 | 0.57 | 36.3% | 33590 |
| C | 1.5 | 72.2% | 1847 | 0.57 | 49.0% | 35441 |
| C | 3.0 | 83.1% | 1498 | 0.48 | 70.5% | 32682 |
| **D** | **1.0** | **56.2%** | **1347** | **0.42** | **36.3%** | **31952** |
| **D** | **1.5** | **66.3%** | **1398** | **0.45** | **49.2%** | **34562** |
| **D** | **3.0** | **79.7%** | **1277** | **0.42** | **70.1%** | **32351** |

### Scenario 2: Newcomer integration

| Strat | Ratio | To 50% | To 80% | Coverage (est) | Loss GB |
|-------|-------|--------|--------|----------------|---------|
| A | 1.5 | 2.0 wk | 4.0 wk | 52.0% | 35607 |
| B | 1.5 | 2.9 wk | 4.2 wk | 51.2% | 36111 |
| C | 1.5 | 1.9 wk | 4.3 wk | 51.7% | 32857 |
| **D** | **1.5** | **3.1 wk** | **5.9 wk** | **51.5%** | **31756** |

## Results v3: Budget Planner (D vs E)

### Scenario 1

| Strat | Ratio | Success% | Evict/wk | Coverage | Loss GB |
|-------|-------|----------|----------|----------|---------|
| D | 1.0 | 56.2% | 1347 | 36.3% | 31952 |
| **E** | **1.0** | **65.0%** | **1263** | **36.6%** | **29594** |
| D | 1.5 | 66.3% | 1398 | 49.2% | 34562 |
| **E** | **1.5** | **72.7%** | **1349** | **49.3%** | **33151** |
| D | 3.0 | 79.7% | 1277 | 70.1% | 32351 |
| **E** | **3.0** | **83.3%** | **1249** | **69.7%** | **31911** |

### Scenario 2

| Strat | Ratio | To 50% | Success% | Loss GB |
|-------|-------|--------|----------|---------|
| D | 1.5 | 3.1 wk | 67.9% | 31756 |
| E | 1.5 | 2.0 wk | 73.1% | 30509 |

## Findings

### 1. Coverage depends on offer ratio, not on strategy

All strategies produce the same coverage at a given ratio (~36% at 1:1, ~70% at 3:1). Hysteresis neither creates nor destroys space; it only affects stability.

### 2. Strategy D (combined hysteresis) is optimal

- **-34% evictions** vs A (no hysteresis): 1398 vs 2128/wk at ratio 1.5
- **-13% data loss** vs A: 34562 vs 39580 GB
- Cascades are shallow: 65-70% of placements require no cascade, mean depth 0.4-0.6
- Cascades are self-dampening: fresh shards (age=0) are evicted back out easily
- Newcomer entry is slightly slower (3 vs 2 wk to 50%), but acceptable

### 3. Budget Planner helps moderately

E vs D at ratio 1.0 (the tightest condition):
- **+8.8pp success rate** (65.0% vs 56.2%) — the primary effect
- **-6.2% evictions** (1263 vs 1347/wk)
- **-7.4% data loss** (29594 vs 31952 GB)
- Coverage unchanged — the budget does not create space, it only saves bandwidth

### 4. Final choice: Strategy E (D + Budget Planner)

Combined hysteresis (threshold H=0.2 + time bonus +30%) plus budget estimation before placement.

## Files

- `simulations/shard_placement.py` — simulation code (strategies A-E)
- `simulations/results/shard_placement/shard_placement_v2_results.json` — v2 raw results (A-D)
- `simulations/results/shard_placement_budget/shard_placement_v2_results.json` — v3 raw results (D vs E)
- `simulations/results/shard_placement/exp27v2_*.png` — v2 plots
- `simulations/results/shard_placement_budget/exp27v2_*.png` — v3 plots
