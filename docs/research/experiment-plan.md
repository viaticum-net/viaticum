# Plan: Experiments 04-19

## Experiment 04: Sybil Attack ✅
**Question:** How many fake nodes needed to compromise a target's files with PID reputation + rate limiting?
**Result:** 5-of-15 coding practically immune (3.15% loss at 500 sybils/10 subnets/12 months). 6-of-10 vulnerable (58.9% at same). Subnet rate-limiting is the primary defense. See experiment-04-sybil-attack.md.

## Experiment 05: Free-rider Detection ✅
**Question:** Does PI reputation automatically prevent free-riding?
**Result:** 0-10% reliability free-riders excluded in 1-2 months. 25% gaming works at threshold=0.3, blocked at 0.5+. 50% reliability undetectable. Honest peers always 100% unaffected. See experiment-05-free-rider.md.

## Experiment 06: Mass Departure (Shock Event) ✅
**Question:** What happens when 30-50% of network leaves simultaneously?
**Result:** 5-of-15 survives 30% instant shock perfectly, 50% → 94.4%. 7-of-10 loses 35% at 30% shock. Death scream provides zero benefit. Gradual departure dramatically better. See experiment-06-mass-departure.md.

## Experiment 07: Targeted Spite ("Обиженка") ✅
**Question:** How many colluding nodes needed to deny restore to a specific target?
**Result:** 5-of-15 completely immune (0% in all 60 configs). 7-of-10: max 7.35% denial at 100 attackers/10 subnets/5 years. Cost: 50,000 GB-years. Economically irrational. See experiment-07-spite-attack.md.

## Experiment 08: Storage Lie + Proof-of-Storage ✅
**Question:** How quickly does proof-of-storage detect liars, and does repair outpace the lie?
**Result:** 100% file survival in ALL 72 configurations. Storage lying is completely harmless with 5-of-15 erasure. Detection in 3-30 days depending on check interval. D-trigger provides 0% advantage (system too resilient). See experiment-08-storage-lie.md.

## Experiment 09: Automatic Federation ⚠️
**Question:** Does "nobody trusts us, let's be friends" naturally produce geographic diversity?
**Result:** Initial model too simple — threshold had zero effect across all configs. Replaced by Experiment 10 (cluster formation with acceptance gate).

## Experiment 10: Cluster Formation (Living Network) ✅
**Question:** Do trust-based partnerships naturally form stable communities in a growing/churning network?
**Result:** Q≈0.42 at steady state (10 years), peaks at 0.64 during growth. 11-12 communities of 700-900 nodes. 66% cross-cohort edges, 73% bridge nodes. Acceptance gate drives initial clustering, churn creates healthy integration. See experiment-10-cluster-formation.md.

## Experiment 11: User Lifecycle ✅
**Question:** How does a single user experience the system from day 0 to year N?
**Result:** In warm-started network, bootstrap is instant (trust gate crossed month 0). 100% restore in ALL phases including departure and return. Trust drops to 77.8% after 6-month absence, recovers to 90.5% within 6 months back. Disk pressure handled gracefully via automatic eviction of low-trust partners. See experiment-11-user-lifecycle.md.

## Experiment 12: "Prison" Scenario (Captive Network) ✅
**Question:** What's the minimum viable network size? How does a bad apple affect a small network?
**Result:** Minimum viable size: N≥3 at 0% churn, N≥7 at 10%, N≥10 at 25%. Adaptive erasure coding (k-of-(n-1) for small networks) is critical. Bad apples have zero impact at N≥10; at N=5, freerider causes only -6.7% survival. N≥20 always 100% with full 5-of-15. See experiment-12-prison-network.md.

## Experiment 13: Behavior Models / Archetypes ✅
**Question:** Does PI reputation correctly rank diverse behavioral archetypes?
**Result:** Kendall's tau = 0.0 (near-random) — PI does NOT correctly rank archetypes by actual usefulness. Hoarder (90% uptime, 20% storage) ranked #2 despite being #5 useful — PI measures uptime, not storage contribution. Weekend Warrior under-ranked (#5 vs actual #2). Seasonal recovery works well (year 2 summer drop 41% smaller than year 1). Design implication: need storage-balance term in trust formula. See experiment-13-behavior-models.md.

## Experiment 14: Individual Node Perspective ✅
**Question:** What does the system look like from one node's point of view?
**Result:** Three scenarios. (1) Flaky partners: 15/15 shards maintained, 100% restore, ~0.8 repairs/month, D-warnings 91% false positive rate. (2) Vacation 14d: trust drops 15.1%, recovers to 95.1% in 30 days, data 100% safe. (3) Disk pressure: automatic eviction of low-trust partners (30→13 over 18mo), own data untouched, trust stable. UX: system is invisible in normal operation. See experiment-14-node-perspective.md.

---

# Серия 2: Исправленная модель PI+S

Формула доверия обновлена на основе выводов серии 1:
```
trust = kp × P_weekly + ki × I + ks × S

P_weekly = скользящее окно 4 недели (бинарно: прошёл ≥1 проверку за неделю?)
I = кумулятивная средняя всех недельных оценок (без decay)
S = GB_stored_for_others / GB_stored_by_others, clamp [0, 2]

Лучшие параметры (Exp 15): kp=0.3, ki=1.5, ks=0.3
```

## Experiment 15: PI+S Convergence ✅
**Question:** Сходится ли расширенная формула PI+S к правильному ранжированию архетипов?
**Result:** Kendall's tau = 0.97 (vs 0.0 для PI-only) к месяцу 12. Все 6 архетипов ранжированы корректно. Hoarder упал с #2 на #5, Weekend поднялся с #5 на #2. Система робастна: любой ks > 0 даёт tau ≥ 0.83. Лучшая конфигурация: kp=0.3, ki=1.5, ks=0.3. See experiment-15-pis-convergence.md.

## Experiment 16: PI+S Under Threats
**Question:** Не ломает ли S-term существующие защиты от Sybil, free-rider, spite?
- Scenario A: Sybil с реальным vs фейковым storage (S=1.0 vs S=0.1)
- Scenario B: Free-rider с PI+S gate — блокирует ли S тех, кого PI пропускал?
- Scenario C: Spite — меняет ли S динамику целенаправленной атаки?

## Experiment 17: Long-term Mixed Network ✅
**Question:** Стабильна ли сеть из 6 архетипов с PI+S (попарный S) за 10 лет?
**Result:** tau=0.667 (хуже Exp 15 из-за Hoarder/Nomad инверсии). Hoarder (rank 4, expected 5) > Nomad (rank 6, expected 4) — 90% uptime перевешивает S-penalty при additive формуле. Кластеры смешанные (не по архетипам): 17 communities, Q=0.290, 59.5% cross-cluster edges, 0 чистых hoarder-кластеров. Trust from honest-only = тот же rank (tau_honest=0.733). Вывод: проблема в формуле (additive S), не в кластеризации. See cluster_probe.py results.
- **Попарный S:** S_AB = GB_B_stores_for_A / GB_A_stores_for_B (не глобальный)
- **Кластеризация:** Hoarder/Freeloader НЕ образуют отдельные кластеры, равномерно размазаны (13-17% в каждом)

## Experiment 18: Corrected UX (Node Perspective with PI+S)
**Question:** Улучшается ли UX с PI+S + weekly checks + D-hysteresis?
- Scenario 1: flaky partners — D-warning FP rate (было 91%)
- Scenario 2: vacation — trust drop с weekly P (должно быть меньше)
- Scenario 3: disk pressure — S падает при eviction, видно ли в trust?

## Experiment 19: Trust Referral (Verifiable Evidence Sharing)
**Question:** Ускоряет ли обмен подписанными proof-of-storage логами bootstrap?
- Новичок получает от друга подписанные challenge-response логи работы с N пирами
- Новичок проверяет подписи и вычисляет trust из чужих наблюдений (со скидкой)
- Вопрос 1: насколько ускоряется bootstrap (время до первого restore)?
- Вопрос 2: какой discount (0.3x? 0.5x? 0.7x?) нужен чтобы не открыть Sybil-вектор?
- Вопрос 3: может ли A скрыть негативные записи? Как B это детектирует?
- Связь с Personal Cluster: внутри кластера — полное разделение (discount=1.0)

## Experiment 20: Gossip Relay & Message Loss
**Question:** Как задержка доставки и потеря сообщений в gossip-relay влияют на точность trust?
- Dedicated relay заменяется gossip: каждая нода хранит "почту" для соседей (~2-4 МБ), пересылает при встрече
- Параметры:
  - Частота PoS проверок: 1/день, 3/нед, 2/нед, 1/нед
  - Message loss rate: 0%, 5%, 10%, 20%
  - Gossip hop limit: 3, 5, 7
  - Сетевая связность: средний uptime 4h/день, 8h/день, 16h/день
- Метрики:
  - Trust accuracy (Kendall's tau vs ground truth)
  - False negative rate (честный пир наказан из-за потери сообщения)
  - Delivery latency distribution (сколько hops, сколько дней)
  - Время обнаружения лжеца (vs мгновенная доставка)
  - Суммарный bandwidth и storage overhead на сеть
- Ключевой insight: ежедневные проверки + недельная агрегация (≥1 OK → 1) делают систему устойчивой к потерям (p_loss=10% → P(miss week) = 0.1^7 ≈ 0). Но 1 проверка/неделю при 10% потерь → 10% ложных штрафов.
- Связь: если gossip работает — dedicated relay не нужен, убирается точка централизации

---

# Серия 3: Адаптивная избыточность

Смена парадигмы: от "фильтруй плохих" к "используй всех, управляй риском".
Низкий trust ≠ бесполезен. Низкий trust = ненадёжен → компенсируем избыточностью (больше шардов).
Ключевой вопрос: какие механизмы фильтрации (gate, eviction, escrow) остаются нужными, а какие заменяются адаптивным n?

## Experiment 21: Adaptive Shard Count (trust → n)
**Question:** Обеспечивает ли адаптивный n (количество шардов на основе trust партнёров) целевую reliability без acceptance gate?
- Базовая модель: n = ceil(k × safety_margin(avg_partner_trust))
- Safety margin: монотонно убывающая функция trust → overhead
- Сравнение: fixed n=15 vs adaptive n∈[10, 30] при одинаковом target reliability
- Сценарии:
  - Все reliable → n снижается → меньше overhead
  - Микс с newcomers → n растёт → newcomers хранят "дешёвые" копии
  - Много ненадёжных → n высокий → overhead выше, но files safe
- Метрики: file survival rate, storage overhead, bootstrap time (newcomer → first useful contribution)
- Без acceptance gate: любой пир получает шарды сразу

## Experiment 22: Multiplicative vs Additive S
**Question:** Какая формула S даёт лучший tau в living network?
- Три варианта:
  - A: additive — trust = kp×P + ki×I + ks×S (текущий, tau=0.667)
  - B: multiplicative — trust = (kp×P + ki×I) × clamp(S, 0.1, 1.0) (ожидание: tau→1.0)
  - C: гибрид — trust = (kp×P + ki×I) × S_mult + ks_bonus×max(S-1, 0)
- Для каждого варианта: sweep параметров, 10 seeds, 10 лет, 10K нод
- Метрики: Kendall's tau, trust distribution, Hoarder vs Nomad ranking
- С адаптивным n (Exp 21) и без — влияет ли формула когда n адаптивный?

## Experiment 23: Eviction Strategies
**Question:** Нужен ли eviction, и если да — какой?
- Три стратегии:
  - A: без eviction (партнёрства только через churn)
  - B: soft eviction (при disk pressure: выгнать min trust×importance)
  - C: hard eviction (trust < threshold → разрыв каждые K недель)
- Для каждой: file survival, partner turnover rate, newcomer integration time
- С адаптивным n — eviction менее критичен? Ненадёжный партнёр остаётся как "дешёвая" копия
- Метрика: "trapped honest node" — попадают ли honest ноды в плохое окружение без выхода?

## Experiment 24: Escrow as Credit System
**Question:** Escrow как кредитование — bootstrap speed и free-rider resistance
- Escrow ON vs OFF при адаптивном n:
  - Без escrow + adaptive n: newcomer сразу полезен, restore когда?
  - С escrow + adaptive n: newcomer полезен сразу, restore по I-score
- Сценарии:
  - Честный newcomer: сколько ждёт до restore документов / фото / видео?
  - Hit-and-run: загрузил → вытянул → ушёл. Что потеряла сеть?
  - Авансовый кредит (1 ГБ free): ускоряет ли retention?
- Метрики: bootstrap time to first restore, network cost of hit-and-run, user retention proxy

## Experiment 25: Full Model Integration
**Question:** Работает ли полная модель (adaptive n + best S formula + best eviction + escrow)?
- Берём лучшие варианты из Exp 21-24
- Living network 10 лет, все 6 архетипов, 25% churn
- Все атаки из серии 1 (sybil, free-rider, spite, mass departure)
- Сравнение: full model vs series 2 best (additive S + fixed n + gate)
- Метрики: file survival, tau, overhead, bootstrap time, attack resistance
- Это финальный "acceptance test" перед reference implementation
