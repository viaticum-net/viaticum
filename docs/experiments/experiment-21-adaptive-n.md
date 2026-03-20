# Experiment 21: Adaptive Shard Count

## Вопрос

Обеспечивает ли адаптивный n (количество шардов, вычисляемое на основе trust партнёров) целевую reliability без acceptance gate? Стоит ли вообще держать acceptance gate в системе?

## Модель

Trust formula: multiplicative S — `trust_AB = (kp×P_B + ki×I_B) × clamp(S_AB, 0.1, 1.0)`

Четыре сценария по двум осям: fixed/adaptive n × gate on/off.

**Adaptive n:** `n = ceil(k × safety_margin(avg_partner_trust))` с предвычисленной таблицей safety margin. При низком среднем доверии партнёров n растёт, при высоком — снижается.

**Acceptance gate:** порог доверия, ниже которого узел отказывается принимать нового партнёра. Снижает pool доступных партнёров.

## Конфигурация

```
peers             = 2000
duration          = 5 years
churn             = 25%/yr
seeds             = 10
jobs              = 6
kp, ki            = 0.5, 2.0
erasure (fixed)   = 5-of-15
S                 = pairwise (S_AB = r_B / r_A)
```

## Результаты

### Year 5 — сводная таблица

| Scenario | Survival | Overhead | Mean n | Bootstrap | Wasted |
|---|---|---|---|---|---|
| 1. Fixed n=15, gate=ON | 97.93% | 2.92x | 14.6 | 1.1 wks | 39.6% |
| 2. Fixed n=15, gate=OFF | 99.00% | 2.95x | 14.7 | 1.0 wks | 39.3% |
| 3. Adaptive n, gate=OFF | 97.00% | 2.55x | 12.8 | 1.0 wks | 39.8% |
| 4. Adaptive n, gate=ON | 95.73% | 2.53x | 12.7 | 1.1 wks | 39.8% |

### Gate: вред от фильтрации партнёров

| n | gate=ON | gate=OFF | Delta |
|---|---|---|---|
| Fixed n=15 | 97.93% | **99.00%** | **−1.07 pp** |
| Adaptive n | 95.73% | **97.00%** | **−1.27 pp** |

Gate снижает survival в обоих случаях. Чем меньше pool партнёров, тем хуже покрытие файлов.

### Adaptive n: экономия против потери survival

| Config | Survival | Overhead | Delta survival | Delta overhead |
|---|---|---|---|---|
| Fixed n=15, gate=OFF | **99.00%** | 2.95x | — | — |
| Adaptive n, gate=OFF | 97.00% | **2.55x** | −2.00 pp | **−0.40x (−13%)** |

Adaptive n экономит ~13% overhead ценой ~2 pp survival.

### Bootstrap и churn

| Metric | All scenarios |
|---|---|
| Bootstrap time | ~1 week |
| Wasted shards | ~39–40% |

Bootstrap одинаков во всех сценариях — новые узлы полезны с первой недели. Доля потраченных шардов (~40%) не меняется независимо от gate или adaptive n: churn является доминирующим фактором потерь.

## Ключевые выводы

1. **Gate вреден.** Acceptance gate снижает survival на 1.07–1.27 pp в обоих режимах n. Фильтрация партнёров уменьшает pool → меньше партнёрств → хуже покрытие файлов. Механизм задуман для защиты, но вредит надёжности больше, чем помогает.

2. **Adaptive n экономит 13% overhead.** Переход с fixed n=15 на adaptive снижает overhead с 2.95x до 2.55x (−0.40x) при потере всего 2 pp survival. Это tradeoff, а не бесплатный выигрыш.

3. **Лучший абсолютный результат — Scenario 2.** Fixed n=15 без gate даёт 99.00% survival — максимум среди всех конфигураций.

4. **Bootstrap мгновенный (~1 неделя)** во всех сценариях. Newcomers полезны с первого дня — проблемы холодного старта нет.

5. **~40% шардов теряется на churn** независимо от стратегии. Ни gate, ни adaptive n не влияют на эту цифру. Churn — доминирующий фактор потерь, а не выбор конфигурации.

6. **Adaptive n и escrow совместимы.** Adaptive n снижает стоимость хранения, escrow (Exp 24) предотвращает abuse. Оба механизма можно использовать одновременно без конфликта.

## Импликации для дизайна

- **Убрать acceptance gate.** Он снижает survival в обоих режимах. Escrow (Exp 24) решает проблему abuse эффективнее, не уменьшая partner pool.
- **Adaptive n — opinionated tradeoff.** 13% экономия overhead при −2 pp survival оправдана для пользователей с ограниченным местом. Можно предложить как пользовательскую настройку политики.
- **Churn (~40% потерь) — неизбежен.** Нет смысла бороться с churn через gate или conservative n. Правильная стратегия — снижать стоимость repair, а не пытаться предотвратить потери.
- **Комбинированная рекомендация:** adaptive n (gate=OFF) + escrow = 97% survival + 2.55x overhead + защита от hit-and-run. Это лучший баланс из всех протестированных конфигураций.

## Код

`simulations/pis_adaptive_n.py` — результаты в `results/pis_adaptive_n/run.json`
