# Experiment 27: Shard Placement in Saturated Network

## Вопрос

В насыщенной сети (все диски заполнены) каждое размещение шарда = вытеснение чего-то. Какая стратегия гистерезиса минимизирует eviction cascades и data loss? Помогает ли Budget Planner (не пытаться размещать если заведомо не получится)?

## Мотивация

Рациональная стратегия любой ноды — реплицироваться максимально. Значит нормальное состояние зрелой сети — свободного места нет. Предыдущие эксперименты (1-26) моделировали растущую сеть, не насыщенную. Это другой режим.

## Модель

### Eviction priority (holder side)

```
eviction_priority = importance × trust_of_owner × (1 + age_bonus)
age_bonus = min(weeks_stored / 26, 0.3)
```

Шард с наименьшим priority вытесняется первым. Вытесненный шард пытается переместиться к другому партнёру (cascade).

### Стратегии гистерезиса

| Стратегия | Описание |
|-----------|----------|
| A | Без гистерезиса (evict если new_priority > min_priority) |
| B | Threshold H=0.2 (new_priority > min × 1.2) |
| C | Time bonus +30% (старые шарды получают бонус до 30% за 26 недель) |
| D | Combined (B+C) |
| E | D + Budget Planner (skip placement если < K партнёров примут) |

### Сценарии

| Сценарий | Описание |
|----------|----------|
| 1 | Saturated steady-state: 200 нод, pre-fill 90%, 52 недели dirty data |
| 2 | Newcomer: та же сеть + новичок каждые 4 недели, bandwidth 30 GB/wk |

### Конфигурация

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

## Результаты v2: Hysteresis Strategies (A-D)

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

## Результаты v3: Budget Planner (D vs E)

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

## Выводы

### 1. Coverage зависит от offer ratio, не от стратегии

Все стратегии дают одинаковое покрытие при одном ratio (~36% при 1:1, ~70% при 3:1). Гистерезис не создаёт и не уничтожает место — только влияет на стабильность.

### 2. Strategy D (combined hysteresis) оптимальна

- **-34% evictions** vs A (no hysteresis): 1398 vs 2128/wk при ratio 1.5
- **-13% data loss** vs A: 34562 vs 39580 GB
- Каскады неглубокие: 65-70% размещений без каскадов, mean depth 0.4-0.6
- Cascades самозатухают: свежие шарды (age=0) легко вытесняются обратно
- Newcomer entry чуть медленнее (3 vs 2 wk to 50%), но приемлемо

### 3. Budget Planner помогает умеренно

E vs D при ratio 1.0 (самый жёсткий):
- **+8.8pp success rate** (65.0% vs 56.2%) — главный эффект
- **-6.2% evictions** (1263 vs 1347/wk)
- **-7.4% data loss** (29594 vs 31952 GB)
- Coverage не меняется — бюджет не создаёт места, только экономит bandwidth

### 4. Финальный выбор: Strategy E (D + Budget Planner)

Combined hysteresis (threshold H=0.2 + time bonus +30%) + budget estimation перед размещением.

## Файлы

- `simulations/shard_placement.py` — simulation code (strategies A-E)
- `simulations/results/shard_placement/shard_placement_v2_results.json` — v2 raw results (A-D)
- `simulations/results/shard_placement_budget/shard_placement_v2_results.json` — v3 raw results (D vs E)
- `simulations/results/shard_placement/exp27v2_*.png` — v2 plots
- `simulations/results/shard_placement_budget/exp27v2_*.png` — v3 plots
