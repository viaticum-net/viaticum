# Experiment 26: Weighted Shard Placement

## Вопрос

Решает ли взвешенное размещение шардов (core + insurance, w_i = p_i^α) проблему survival из Exp 25, где FULL model (tau=1.000) имела меньшую выживаемость (96.1%), чем S2 baseline (97.6%)?

## Модель

Три конфигурации сравниваются:

| Модель | S-formula | n | Gate | Placement | Escrow |
|--------|-----------|---|------|-----------|--------|
| **EQUAL** | multiplicative | adaptive | OFF | пропорционально trust (1 shard/partner) | ON |
| **WEIGHTED** | multiplicative | adaptive | OFF | w_i = p_i^2, до 6 shards/partner | ON |
| **S2** | additive (0.3/1.5/0.3) | fixed n=15 | ON | равномерный (1 shard/partner) | ON |

EQUAL = FULL model из Exp 25 (baseline для сравнения).

Weighted placement: каждый партнёр получает n_i = round(n_total × w_i') шардов, где w_i = p_i^α (α=2.0), p_i = clip(trust_i / MAX_TRUST, 0.1, 1.0). Партнёр может держать до 6 шардов одного файла (MAX_SHARDS_PER_PARTNER=6).

## Конфигурация

```
nodes             = 10000
duration          = 10 years
churn             = 25% annual
archetypes        = 6 standard + HitAndRun (15% of arrivals)
seeds             = 20
jobs              = 24
scenarios         = A (baseline), D (40% free-rider flood)
```

## Результаты

### Scenario A: Baseline

| Year | EQUAL surv | WEIGHTED surv | S2 surv | EQUAL tau | WGT tau |
|------|-----------|--------------|---------|----------|---------|
| 1 | 98.66% | 98.88% | 99.93% | 0.97 | 0.97 |
| 3 | 98.55% | 99.08% | 99.13% | 1.00 | 1.00 |
| 5 | 97.88% | 98.85% | 98.44% | 0.99 | 0.99 |
| 7 | 97.03% | 98.52% | 98.08% | 1.00 | 1.00 |
| 10 | 96.20% | **98.06%** | 97.69% | 0.99 | **1.00** |

| Метрика | EQUAL | WEIGHTED | S2 |
|---------|-------|----------|-----|
| Storage overhead | 3.16x | 3.62x | 2.93x |
| Bootstrap time | 13.94 wk | 13.78 wk | 14.01 wk |
| Gini (shard concentration) | 0.00 | 0.12 | 0.00 |
| Mean shards/partner | 1.00 | 1.56 | 1.00 |
| Max shards/partner | 1.00 | 6.00 | 1.00 |

### Scenario D: Free-rider Flood (40% arrivals)

| Year | EQUAL surv | WEIGHTED surv | S2 surv | EQUAL tau | WGT tau |
|------|-----------|--------------|---------|----------|---------|
| 1 | 97.93% | 98.09% | 99.98% | 0.63 | 0.63 |
| 3 | 96.92% | 97.65% | 99.17% | 0.59 | 0.59 |
| 5 | 95.18% | 96.70% | 98.62% | 0.60 | 0.60 |
| 7 | 93.51% | 95.55% | 98.18% | 0.60 | 0.60 |
| 10 | 91.63% | 93.96% | 97.74% | 0.60 | 0.60 |

| Метрика | EQUAL | WEIGHTED | S2 |
|---------|-------|----------|-----|
| Honest node survival | 97.39% | **99.40%** | 97.60% |
| Freeloader survival | 85.19% | 87.86% | 97.89% |
| Storage overhead | 3.59x | 4.09x | 2.93x |
| Gini (shard concentration) | 0.00 | 0.11 | 0.00 |

## Ключевые выводы

1. **WEIGHTED решает проблему Exp 25.** В baseline (Scenario A): survival 98.06% vs S2 97.69% (+0.37pp) при tau=1.000 (vs 0.670). Впервые достигнуто одновременное улучшение И ранжирования И выживаемости.

2. **Концентрация шардов работает.** Gini=0.12, mean 1.56 shards/partner, max 6. Надёжные партнёры получают 2-6 шардов, ненадёжные — 0-1. Потеря ненадёжного партнёра уносит мало шардов.

3. **Honest survival в Scenario D: WEIGHTED лучший.** 99.40% — выше и EQUAL (97.39%) и S2 (97.60%). Weighted placement защищает честных, концентрируя их шарды на надёжных партнёрах.

4. **Общий survival в Scenario D: S2 всё ещё лучше.** 97.74% vs 93.96%. Причина: S2 gate не даёт free-rider'ам хранить шарды, их файлы "бесплатно" защищены fixed n=15. WEIGHTED честно даёт free-rider'ам меньше шардов → их файлы чаще теряются → общий survival ниже. Это **правильное** поведение: free-rider'ы ДОЛЖНЫ терять файлы.

5. **Overhead WEIGHTED > S2.** 3.62x vs 2.93x в baseline. Плата за концентрацию: надёжные партнёры получают больше шардов, но n_total адаптивно не уменьшается (всё ещё Binom(n, avg_p)). Оптимизация: Poisson binomial вместо Binom(n, avg_p) снизит n_total для mixed-trust сценариев.

6. **Bootstrap time идентичен.** ~14 недель во всех моделях — weighted placement не влияет на скорость набора партнёров.

## Импликации для дизайна

- **Weighted placement — рекомендуемый default** для reference implementation. Survival ≥ S2 при tau=1.000.
- **Gate не нужен.** WEIGHTED без gate даёт лучший honest survival чем S2 с gate.
- **Overhead оптимизируем позже.** Poisson binomial вместо Binom(n, avg_p) должен снизить n_total с 3.62x ближе к 3.0x.
- **Scenario D — design envelope.** 40% free-riders = экстремальное условие. Общий survival 94% приемлем, honest survival 99.4% — отлично.

## Код

`simulations/pis_weighted_placement.py` — результаты в `results/pis_weighted_placement/pis_weighted_placement_results.json`
