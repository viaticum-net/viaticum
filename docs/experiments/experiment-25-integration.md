# Experiment 25: Full Model Integration

## Вопрос

Работает ли полная модель (adaptive n + multiplicative S + no gate + no eviction + escrow) против всех атак? Является ли она улучшением по сравнению с Series 2 baseline?

## Модель

Два варианта сравниваются на одних и тех же сценариях:

| Модель | S-formula | n | Gate | Eviction | Escrow |
|--------|-----------|---|------|----------|--------|
| **FULL** | multiplicative `(kp×P + ki×I) × clamp(S, 0.1, 1.0)`, kp=0.5 ki=2.0 | adaptive | OFF | OFF | ON |
| **S2** (Series 2 baseline) | additive `kp×P + ki×I + ks×S`, kp=0.3 ki=1.5 ks=0.3 | fixed n=15 | ON | ON | ON |

Escrow включён в обоих вариантах — Exp 24 показал, что он всегда полезен.

**Сценарии атак:**

| Сценарий | Описание |
|----------|----------|
| A — Baseline | Без атак, 6 архетипов + HitAndRun 15% arrivals |
| B — Sybil | 200 sybil-нод в 10 подсетях /24 |
| C — Mass departure | 30% нод покидают сеть одновременно на год 5 |
| D — Free-rider flood | 40% arrivals — free-riders |
| E — Spite | 50 attackers, 3yr wait before attack |

## Конфигурация

```
nodes             = 10000
duration          = 10 years
churn             = 25% annual
archetypes        = 6 standard + HitAndRun (15% of arrivals)
seeds             = 20
jobs              = 24
scenarios         = A, B, C, D, E (5 total)
metrics           = survival_y10, Kendall's tau, HAR rate, storage overhead,
                    bootstrap time, denial rate
```

## Результаты

### Сводная таблица (год 10)

| Scenario | FULL surv% | S2 surv% | FULL tau | S2 tau | FULL HAR | S2 HAR |
|----------|-----------|---------|---------|--------|---------|--------|
| A Baseline | 96.1% | 97.6% | 1.000 | 0.640 | 0% | 0% |
| B Sybil | 96.2% | 97.7% | 1.000 | 0.667 | 0% | 0% |
| C Mass departure | 96.4% | 97.7% | 1.000 | 0.693 | 0% | 0% |
| D Free-rider flood | **91.7%** | 97.8% | 0.600 | 0.927 | 0% | 0% |
| E Spite | 96.0% | 97.7% | 1.000 | 0.660 | 0% | 0% |

### Динамика по годам — Scenario E (Spite, репрезентативный)

| Year | FULL surv | S2 surv | FULL tau | S2 tau |
|------|-----------|---------|---------|--------|
| 1 | 98.66% | 99.93% | 0.97 | 0.67 |
| 3 | 98.56% | 99.16% | 0.99 | 0.68 |
| 5 | 97.75% | 98.54% | 0.99 | 0.66 |
| 7 | 96.95% | 98.02% | 0.99 | 0.69 |
| 10 | 96.00% | 97.69% | 1.00 | 0.66 |

### Дополнительные метрики — Scenario E

| Метрика | FULL | S2 |
|---------|------|----|
| Storage overhead | 3.16x | 2.93x |
| Bootstrap time | 13.94 wk | 14.01 wk |
| Denial rate | **0.67%** | 1.32% |

## Ключевые выводы

1. **FULL model tau=1.000 в 4/5 сценариях.** Multiplicative S корректно ранжирует архетипы под всеми атаками, кроме свободного flood'а. Результат подтверждает Exp 22 на реальной attack surface.

2. **Escrow блокирует HAR на 100%.** HAR rate = 0% во всех 10 конфигурациях. Механизм работает независимо от формулы S и параметров adaptive n.

3. **FULL model имеет меньшую выживаемость, чем S2** (96% vs ~98%). Причина: adaptive n снижает избыточность — с multiplicative S ненадёжные партнёры получают низкий trust → высокий n → но шарды всё равно распределяются между ними → часть теряется.

4. **Scenario D — проблемный случай.** При 40% free-rider arrivals: survival=91.7%, tau=0.600. Без gate free-riders заполняют партнёрские слоты; их низкий trust вызывает высокий n → парадоксально ухудшает coverage. Это граничное условие за пределами design envelope системы.

5. **Spite resistance улучшилась.** FULL denial rate 0.67% против S2 1.32% — multiplicative S сильнее штрафует атакующих, что снижает вероятность успешного отказа в обслуживании.

6. **S2 имеет стабильно высокую выживаемость** (~97.7% во всех сценариях) несмотря на плохой tau. Fixed n=15 даёт постоянную избыточность независимо от точности ранжирования — это защита за счёт overprovisioning.

## Нерешённые вопросы

1. **Почему FULL уступает S2 по выживаемости?** Гипотеза: adaptive n вычисляется на основе среднего trust партнёров. При multiplicative S ненадёжные ноды получают очень низкий trust → n растёт → но шарды всё равно попадают к ненадёжным партнёрам → потери сохраняются. Нужно проверить, помогает ли ограничение минимального trust при выборе партнёров.

2. **Scenario D:** 40% free-rider arrivals могут превышать design envelope. Необходимо протестировать, не слишком ли агрессивна таблица adaptive n для высокой доли ненадёжных нод.

3. **Overhead FULL (3.16x) > S2 (2.93x)** несмотря на adaptive n в scenario E. Adaptive n, вероятно, перекомпенсирует low-trust партнёров, создавая больше шардов, чем фиксированный n=15.

## Импликации для дизайна

- **Multiplicative S + escrow подтверждены** как core механизмы: tau=1.000, HAR=0%.
- **Adaptive n требует настройки.** Текущая таблица может быть слишком агрессивной: FULL overhead превышает S2, а survival ниже. Нужно исследовать более консервативные пороги.
- **Fixed n=15 — безопасный default** для reference implementation: стабильная выживаемость и предсказуемое поведение без параметрической настройки.
- **Gate removal приемлемо для 4/5 сценариев**, но уязвимо к free-rider flood. Возможные решения: conditional gate по доле ненадёжных нод, либо минимальный trust threshold для выделения шардов.
- **Оптимизация tau (ранжирование) и survival (избыточность) частично конкурирующие цели.** Multiplicative S улучшает точность ранжирования, но adaptive n, реагируя на это, снижает фактическую избыточность. Дизайн должен явно фиксировать, что важнее в каждом сценарии.

## Код

`simulations/pis_integration.py` — результаты в `results/pis_integration/pis_integration_results.json`
