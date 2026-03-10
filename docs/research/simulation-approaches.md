# Обзор подходов к симуляции P2P storage систем

## Вывод: что используем

**Python + numpy + SimPy.** Вычислительно несложно — PID репутация это арифметика на массивах, 10K пиров × 10K шагов = секунды. 24 ядра используем для параллельных Monte Carlo прогонов (joblib.Parallel). Rust/Go — overkill для симуляции, пригодится для реализации протокола.

## Фреймворки: что живо в 2025-2026

| Инструмент | Статус | Для нас |
|---|---|---|
| **Mesa 3** (Python ABM) | Живой, JOSS 2025, Python ≥3.12 | Потолок ~10-50K агентов без векторизации. mesa-frames (Polars backend) — до 1M |
| **Agents.jl** (Julia) | Живой, 3-160x быстрее Mesa | Запас если Python не хватит |
| **PeerSim** (Java) | Мёртв (последний релиз ~2013) | Не использовать |
| **OverSim** (OMNeT++) | Мёртв (2019) | Не использовать |
| **ns-3** | Живой, но слишком низкоуровневый | Не для нашего случая |
| **SimPy 4** (Python DES) | Живой, PyPI | Для моделирования churn и repair |

**Вывод:** специализированные P2P симуляторы мертвы. Академические группы пишут своё на numpy/SimPy/MATLAB. Это нормально и правильно.

## Как делали предшественники

### Samsara (Cox & Noble, SOSP 2003)
- Кастомная дискретная симуляция, не именованный фреймворк
- Фокус на adversarial behavior, не на случайный churn
- Прототип Pastiche оценивался на модифицированном Andrew Benchmark (7.4% overhead)
- Доступность задавалась параметрически

### INRIA/Eurecom (Kermarrec group, 2007-2012) — лучший академический референс
- Основной инструмент: **Markov chain аналитические модели** для MTTDL (Mean Time To Data Loss)
- Где симулировали — NS-2 + кастомный MATLAB генератор churn
- Статья 2009 "A Realistic Simulation Model for P2P Storage Systems" — критика нереалистичных моделей

### EigenTrust (Kamvar et al., WWW 2003) — референс для репутации
- 1000 пиров, 100 циклов запросов, сходимость за <10 итераций power method
- Даже при 70% вредоносных нод — подавляет фейковые загрузки
- Кастомный Python/MATLAB

## Модели churn

| Модель | Описание | Когда используется |
|---|---|---|
| **Exponential** | session ~ Exp(λ), memoryless | Первый проход, аналитически удобно |
| **Weibull** (k≈0.34-0.6) | Лучше fit на эмпирику Gnutella/BitTorrent | Второй проход, Stutzbach & Rejaie 2006 |
| **Empirical traces** | Replay логов KaZaA/Gnutella | Максимальная точность, минимальная общность |

Для бекап-систем сессии длиннее чем в file-sharing (дни, не минуты). Калибровать под наш use case.

## Моделирование data survival

- Storage = per-peer capacity (GB), track used/free
- Данные = K+M фрагментов (erasure coding) на разных пирах
- Repair trigger: live fragments < threshold
- **Bandwidth — критический constraint**, не CPU и не storage
- Метрика: MTTDL (Mean Time To Data Loss), fraction of surviving files
- Markov chain аналитика быстрее и информативнее симуляции для exponential churn

## Моделирование репутации (PID)

Никто не делал PID для P2P storage (новизна проекта). Ближайшие аналоги:
- EigenTrust — линейная алгебра (power method)
- TCP congestion control — PI контроллеры для ресурсов
- Общий подход ABM trust: agents с true reliability (Beta distribution) → perceived reputation → measure convergence (Kendall's tau)

## Масштаб на 24-core Xeon / 64GB

| Подход | Реалистичный масштаб |
|---|---|
| Pure Python Mesa | 10K-50K агентов |
| mesa-frames (Polars) | 100K-1M |
| Custom numpy vectorized | 1M+ агентов/шаг |
| SimPy DES | 1M событий за секунды |

Узкое место: N×N trust matrix = O(N²). Sparse trust graph (каждый знает K соседей) → O(N×K), нормально до 100K.

## Два отдельных эксперимента

**A. PID Reputation Convergence** — чистый numpy, без сети
- N агентов, Beta-distributed true reliability
- PID контроллер на каждого наблюдателя
- Метрика: Kendall's tau (perceived rank vs true rank) vs time
- 10K агентов × 10K шагов = секунды

**B. Data Survival Under Churn** — SimPy DES или Markov chain
- N пиров, exponential on/off
- Erasure coding k-of-n
- Repair process с bandwidth constraint
- Метрика: fraction of files with < k live fragments

Потом объединить: reputation влияет на выбор пиров для размещения шардов.

## Источники

- Cox & Noble. "Samsara: Honor Among Thieves in Peer-to-Peer Storage." SOSP 2003
- Stutzbach & Rejaie. "Understanding Churn in Peer-to-Peer Networks." SIGCOMM 2006
- Kamvar et al. "The EigenTrust Algorithm for Reputation Management in P2P Networks." WWW 2003
- INRIA. "P2P Storage Systems: Data Life Time for Different Placement Policies." 2009
- INRIA. "A Realistic Simulation Model for Peer-to-Peer Storage Systems." 2009
- Mesa 3: https://joss.theoj.org/papers/10.21105/joss.07668
- Agents.jl: https://journals.sagepub.com/doi/10.1177/00375497211068820
- SimPy: https://simpy.readthedocs.io/
