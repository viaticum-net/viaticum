# Viaticum: технический обзор

*Март 2026 · α complete, β в проектировании*

---

## 1. Задача и мотивация

Личные данные обычного человека (документы, фото — 30-160 ГБ) не защищены от потери. Облачные сервисы требуют оплаты и доверия третьей стороне, второй диск требует денег и дисциплины, NAS требует экспертизы. Viaticum решает задачу иначе: участники сети хранят зашифрованные фрагменты данных друг друга, не платя за инфраструктуру и не зная содержимого чужих файлов.

Ключевой тезис: erasure coding, шифрование, P2P-транспорт — всё это решённые задачи с production-grade библиотеками. **Единственная нерешённая проблема — механизм доверия:** как незнакомцы договариваются хранить данные друг друга без посредника, токенов и глобального консенсуса.

Концепция "холодного бекапа" (временная константа = 1 неделя) радикально упрощает все остальные проблемы: churn, repair storm, NAT traversal, требования к uptime — всё решается фразой "попробуй позже".

---

## 2. Текущее состояние

**α (alpha)** — proof of concept. Работающий Rust daemon, E2E протестирован (5 Docker-нод). Reed-Solomon erasure coding, одно устройство, inline transfer.

**β (beta)** — проектируется. RaptorQ (замена RS), Personal Cluster (multi-device), relay mailbox, file versioning. Цель: можно реально пользоваться.

Версионирование: α → β → 1.0, дальше semver.

---

## 3. Архитектура

### Trust: PI+S контроллер

Каждый пир локально считает репутацию своих партнёров:

```
trust = (kp × P + ki × I) × clamp(S, 0.1, 1.0)

P = доля успешных proof-of-storage за 4-week rolling window
I = cumulative mean (GB·days за всё время)
S = pairwise storage ratio (я_для_них / они_для_меня)
```

Ключевой инсайт: **время неподделываемо**. I-компонент нельзя ускорить — это реальные байты на реальном диске за реальное время. Лучший anti-Sybil без блокчейна.

S-компонент решает storage fairness: хранишь мало для других → S низкий → trust × 0.1 → natural punishment.

Нет глобального консенсуса: каждый пир ведёт собственный локальный лог и сам решает кому доверять.

### Erasure coding

**α:** Reed-Solomon (5-of-7/10/15 по importance). Фиксированный k-of-n.

**β (планируется):** RaptorQ (RFC 6330). Преимущества: динамический N (генерируй символы на лету), streaming (O(1 символ) RAM), fungible символы (любые K достаточны), непрерывная importance (не 3 тира).

Per-holder binding: каждый символ XOR с holder-specific keystream → anti-collusion (holders не могут дедуплицировать между собой).

### Backup flow

```
Файл → zstd compress → ChaCha20-Poly1305 encrypt → erasure encode → символы
→ placement engine (trust² × importance) → symbol_offer → holder accepts → transfer
```

File catalog в DB независим от диска: удаление файла ≠ удаление из бекапа (cooldown 4+4 = 8 недель, ransomware protection). File versioning: Vec<FileVersion> per path, restore by version/date.

### Restore flow

```
viaticum restore photos/vacation/ [--version N] [--date D]
→ DB lookup → collect K+ символов от holders → decode → decrypt → decompress → файл
```

Escrow: restore гейтится по weeks_in_network (документы сразу, фото через 4 недели, видео через 13).

### Eviction (holder-initiated)

```
eviction_priority = importance × trust_of_owner × (1 + age_bonus)
effective_quota = min(soft_quota, disk_free - disk_reserve)
hard_quota = пол, ниже которого не вытеснять автоматически
```

Commitment telemetry: holder автоматически сообщает eviction risk per owner → owner видит тренд → repair ДО фактического drop.

### PoS verification

Еженедельный challenge: "предъяви символ ESI=X". 7-дневный таймаут (единый для direct и relay). Асинхронный: два пира могут никогда не быть online одновременно — challenge/response через relay peers ("почтальоны"). Relay не может подделать ответ (подпись holder'а).

### Personal Cluster (β)

Пользователь — не одна нода, а кластер устройств с общим master key:

```
Identity (seed phrase)
├── Laptop   (device key, manages peers A, C, E)
├── NAS      (device key, manages peers B, D, F)
└── Desktop  (device key, manages peers G, H)
```

Peer-to-device affinity: каждое устройство — "менеджер" своих пиров. Blast radius isolated: ноутбук offline → пострадали только его пиры, NAS не затронут.

S-score per device-peer pair. Протокол не знает про кластеры — каждое устройство выглядит как обычная нода.

Device revocation: кража → отозвать device key → encryption epoch rotation → партнёры отказывают revoked key.

### Network transport

iroh для direct connections и NAT traversal. **Без iroh-blobs, без iroh-docs** — лишние абстракции для нашего use case. Символы передаются через direct connection + bytes. Deferred messaging: relay mailbox через mutual peers (relay_store/relay_fetch, 2 message types).

---

## 4. Ключевые design decisions

**Почему PI+S, а не blockchain.** Blockchain требует глобального консенсуса и привлекает спекулянтов. Autonomi (ex-MaidSafe, 20 лет разработки) закрылся в марте 2026: токен-эмиссия привлекла farming-ноды, их уход вызвал repair storm. PI+S считается локально, не требует токенов, использует время как неподделываемый ресурс.

**Почему холодный бекап.** Wuala, CrashPlan, BuddyBackup пытались конкурировать с AWS по SLA и проиграли. Repair storm → "лёгкий ветер" (160 ГБ за 7 дней = 260 КБ/с). Churn → "ноутбук закрыт, подождём". NAT failures → retry (за неделю — десятки попыток).

**Почему нет токенов.** GB·days как "валюта", reputation как "кредитный лимит" — по аналогии с долговой экономикой Грейбера. Токены привлекают фармеров, долг привлекает участников.

**Почему RaptorQ вместо Reed-Solomon (β).** 16 преимуществ: динамический N (добавь символов без re-encode), streaming RAM, per-holder binding, symbol budget вместо shard placement, непрерывная importance. Главный недостаток RS: фиксированный n при encode, перемножение вероятностей для крупных файлов (video 10 ГБ = 320 чанков, P^320).

**Почему relay mailbox вместо iroh-docs/blobs.** iroh-blobs: resumability не нужна для <4 МБ символов, verification мы делаем сами (blake3). iroh-docs: CRDT-синхронизация документов — нам нужен почтовый ящик, а не синхронизированный документ. Два message types (relay_store/fetch) решают задачу.

---

## 5. Результаты экспериментов (27 симуляций)

| # | Вопрос | Ключевой результат |
|---|--------|--------------------|
| 01 | Сходимость PI-репутации | Kendall's tau = 0.91 при Kp=0.5, Ki=2.0. I доминирует |
| 02 | Выживаемость при churn | 50 peers, 50% churn, repair 14d → 99.97% за 3 года |
| 03 | D-компонент для repair | +30% выживаемости как repair trigger (не как trust score) |
| 04 | Sybil-устойчивость | 5-of-15 + subnet limit: 500 sybil → 3.15% потерь. 6-of-10: 58.9% |
| 05 | Фрирайдеры | Не вредят честным. Natural punishment через S-score |
| 06 | Массовый уход | 5-of-15: 30% мгновенный уход → 99.94%. 50% → 94.4% |
| 07 | Spite-атака | 5-of-15: 0% потерь во всех 60 конфигурациях |
| 13 | Storage fairness | PI без S не различает hoarder/contributor → S-компонент обязателен |
| 15-17 | PI+S калибровка | tau=1.0 во всех конфигах. kp∈[0.3,0.5], ki∈[1.5,2.0] |
| 23-27 | Eviction/budget | Strategy E (hysteresis + budget planner): +8.8pp success, -7.4% data loss |

Полные результаты: `docs/experiments/`

---

## 6. Архитектура реализации

### α (текущая)

```
Rust workspace, 2 crates:
  viaticum-core  — pure logic (trust, escrow, placement, budget, messages, db)
  viaticum       — daemon (5 tokio tasks: watcher, scheduler, network, processor, cli_server)

Storage: redb (embedded). Wire: CBOR, u32 BE framing, ALPN "viaticum/1".
Transport: iroh (direct connections, NAT traversal).
Crypto: ChaCha20-Poly1305, BLAKE3, HKDF-SHA256, BIP39 seed.
```

### β (планируется)

```
Processor split: BackupCoordinator, RestoreCoordinator, RepairAgent, ClusterSync
Erasure: trait ErasureEncoder + RaptorQ impl (замена RS)
DB: три слоя (RAM hot / redb warm / redb cold), ~15x меньше metadata
Pipeline: streaming encode (O(1 символ) RAM вместо batch)
Cluster: device keys, epochs, revocation в core
```

---

## 7. Открытые вопросы

- Бенчмарки `raptorq` crate (скорость encode/decode для разных K)
- Symbol size T: decided T=64КБ default, variable T for files >3.5ГБ
- Migration path α → β (чистый старт или миграция данных?)
- Formal game theory proof: "20% менее надёжно > 10% надёжно"
- NAT traversal testing (iroh relay across real NATs)
- Минимальный жизнеспособный размер сети: 7 (10% churn) или 20 (25% churn)
