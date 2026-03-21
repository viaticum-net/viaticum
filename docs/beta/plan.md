# β (beta) — план

*2026-03-15. Статус: проектирование.*

α = proof of concept (RS, single device, inline transfer).
β = можно реально пользоваться (RaptorQ, Personal Cluster, iroh transport only).

После β → semver (1.0, 1.1, ...).

---

## Архитектурные решения

### Что хорошо показало себя в α (НЕ менять)

- **Two-crate split** — core без tokio тестируется мгновенно
- **redb** — embedded, быстрый, без внешних зависимостей
- **CBOR** — компактный, schema-free
- **tokio + mpsc channels** — понятная модель
- **Trust/escrow/budget как модули в core** — проще чем отдельные tasks
- **"Wrote fn → wrote tests"** — обязательно

### Что вызвало проблемы в α (уроки)

| Проблема | Баг | Урок |
|----------|-----|------|
| Packer per-call creation | unit_id collision (все паки = один unit) | Lifecycle stateful модулей — явный контроль |
| Trust recalculate() implicit defaults | P=0 при отсутствии PoS данных, убивает placement | State machine для peer lifecycle |
| RS параметры размазаны по 5+ файлам | — | Erasure coding за абстракцией |
| Unit → Shard → File (3 уровня) | Сложные lookup'ы | Не плодить entity без необходимости |
| Processor god-object | — пока, но не масштабируется | Разделить на координаторы |

---

## Архитектурные изменения для β

### 1. Erasure coding за trait'ом

```rust
trait ErasureEncoder {
    fn encode(&self, data: &[u8], params: &ErasureParams) -> Vec<Symbol>;
    fn decode(&self, symbols: &[Symbol]) -> Result<Vec<u8>>;
    fn generate_repair(&self, source: &[u8], esi: u32) -> Symbol;
}
```

Единственная реализация: RaptorQ. Но изоляция от остального кода — замена = один файл.

### 2. Packer → StreamingPipeline

```rust
// α (batch): всё в RAM
fn pack_unit(&self, files: Vec<PathBuf>) -> Result<Unit>

// β (streaming): O(1 символ) RAM
fn encode_file(&self, path: &Path) -> impl Stream<Item = BoundSymbol>
```

### 3. ShardManager → SymbolBudgetManager

Не "какую шарду кому", а "сколько символов кому, исходя из trust и importance". Fungible символы — нет индивидуальной идентичности.

### 4. Processor split

```
α Processor (god-object):
  backup + restore + trust + placement + PoS + repair + cluster

β — разделение на координаторы:

  BackupCoordinator   — file → compress → encrypt → symbols → distribute
  RestoreCoordinator  — collect symbols → decode → decrypt → decompress → file
  RepairAgent         — monitor reliability, trigger repair
  ClusterSync         — device state, event log, epoch rotation
  TrustEngine         — уже отдельный модуль в core, без изменений

  Processor = тонкий роутер:
    FileChanged     → BackupCoordinator
    PosChallenge    → TrustEngine
    SymbolsLost     → RepairAgent
    RestoreRequest  → RestoreCoordinator
    ClusterEvent    → ClusterSync
```

### 5. Crate structure

```
syncback-core/        — pure logic, no async, no network
  types               — Symbol, ESI, SymbolPlacement, DeviceId, EpochCounter...
  trust               — TrustEngine (без изменений)
  escrow              — EscrowChecker (trust-based, rewritten in Phase 2.6)
  placement           — SymbolBudgetEngine (бывший PlacementEngine)
  budget              — BudgetEngine (без изменений)
  messages            — wire format (обновлённый для символов)
  erasure             — ErasureEncoder trait + RaptorQ impl
  cluster             — device keys, epochs, revocation, certificates (no network)

syncback/             — daemon + CLI
  daemon/
    network           — iroh transport (direct connections only)
    backup            — BackupCoordinator (streaming pipeline)
    restore           — RestoreCoordinator
    repair            — RepairAgent
    cluster_sync      — event log exchange, device discovery
    processor         — thin router
    watcher           — fs notify (без изменений)
    scheduler         — weekly sync, PoS triggers (без изменений)
    cli_server        — unix socket (+ device management commands)
  cli/                — `syncback status`, `syncback device add/revoke`, ...
```

Вариант: `cluster` в отдельный crate (`syncback-cluster`), если вырастет. Пока в core.

### 6. DB schema

Два слоя (подробнее в `docs/beta/raptorq.md`):

```
HOT (RAM, ~13 МБ для 5 ТБ):
  source_block_id → { K, total_alive_symbols }
  (source_block_id, holder_id) → { symbol_count, status, last_pos }

WARM (redb, ~133 МБ для 5 ТБ):
  FileRecord, SourceBlock, SymbolPlacement (ESI ranges), EventLog
  Indices: file→holders, holder→files
```

Холодный слой убран: PoS верифицируется на лету из локального файла. Файл удалён → cooldown → символы удаляются, PoS не нужен.
~3.4 МБ на 1000 файлов вместо ~50 МБ (15x меньше).

### 7. Error handling

- α: panic on unexpected
- β: panic только на data corruption. Network errors, timeouts, peer misbehavior → graceful + tracing::error

---

## Фичи β

### Ядро

| # | Фича | Описание | Зависимости |
|---|------|----------|-------------|
| 1 | **RaptorQ** | Замена RS. Динамический N, streaming, fungible символы | erasure trait |
| 2 | **Per-holder binding** | Anti-collusion XOR с holder-specific keystream | RaptorQ |
| 3 | **Personal Cluster** | Device keys, revocation, epochs, peer-to-device affinity | cluster module |
| 4 | **Epidemic relay** | Deferred messaging через epidemic gossip (hop≤2). Peer пишет в свой board → подписчики копируют с hop+1 → ~100 peers за пару дней. Хранение: append-only файл, TTL 7 дней. Без iroh-blobs, без iroh-docs | network |
| 5 | **Новая DB** | Два слоя (RAM hot + redb warm), event log, двойной индекс | — |
| 6 | **Continuous importance** | importance → кол-во символов (не 3 тира) | SymbolBudgetEngine |
| 7 | **File versioning** | Vec\<FileVersion\> per path, max_versions + max_age + cooldown, restore by version/date | DB schema |

### Улучшения протокола

| # | Фича | Описание |
|---|------|----------|
| 8 | **Symbol budget** | Распределение символов по trust^2 весам |
| 9 | **Commitment telemetry** | Holder автоматически сообщает eviction risk per owner (computed, не self-reported) |
| 10 | **Reliability forecast** | `syncback status --forecast` — прогноз per file/folder |
| 11 | **Selective restore** | `syncback restore photos/vacation/` по DB каталогу |
| 12 | **"Больше файлов, меньше overhead"** | Стратегия при ограниченном бюджете |

### Фиксы из α

| # | Фича | Описание |
|---|------|----------|
| 13 | Chunk restore | Файлы >32 МБ |
| 14 | PoS SendPosChallenge | Реальная реализация (сейчас stub) |
| 14b | **PosNack** | Holder отвечает NotHeld вместо молчания при отсутствии символа. Graduated repair: NotHeld/Fail → немедленный repair, Timeout → graduated (3 misses → PresumedLost). Вдохновлено Samsara probabilistic discard |
| 15 | Vacuum / stale cleanup | Очистка мёртвых записей |
| 16 | File deletion | Watcher → local_state=Deleted → cooldown 4+4 → удаление символов |
| 17 | **Disk pressure rework** | effective_quota = min(soft_quota, disk_free - reserve), hard_quota = floor |
| 18 | Fractional quota | `quota_gb = 0.5` |

### Если влезет

| # | Фича | Описание |
|---|------|----------|
| 19 | Optional email | Публикация для человеческого доверия |
| 20 | Lossy fallback | Resize фото/видео при нехватке бюджета |

### НЕ в β

- ML ranking → γ или 1.0
- Observability/telemetry → γ
- Hop-based allowlist
- Geo-diversity
- Dead man's switch / inheritance
- Streaming restore
- Compression (zstd уже есть, дальнейшая оптимизация позже)
- Commitment spectrum как self-reported (game theory: cheap talk, не работает; заменён computed telemetry #9)

---

## Порядок реализации (предварительный)

```
Phase β.1 — Фундамент (можно параллельно):
  erasure trait + RaptorQ impl + benchmarks
  новая DB schema (два слоя: RAM hot + redb warm, file versioning)
  PoS реализация (не stub — столп системы, тестировать сразу)
  Processor split на координаторы
  cluster module в core (device keys, epochs, certificates)

Phase β.2 — Pipeline:
  StreamingPipeline (backup)
  RestoreCoordinator (selective restore, restore by version/date)
  SymbolBudgetManager
  Per-holder binding
  Relay mailbox (relay_store/fetch через mutual peers, ~100 строк)

Phase β.2.5 — PosNack + repair:
  Обновить PoS engine: VerifyOutcome::NotHeld, PosNackMsg
  PlacementStatus state machine (Alive/Uncertain/PresumedLost)
  RepairAgent: graduated repair trigger
  Гонка SymbolDropped vs PosNack: idempotent transitions

Phase β.2.6 — Trust-based escrow:
  Переписать escrow: time-based → trust-based
  Формула: max_restorable_gb = FREE_TIER_GB + trust × ESCROW_TRUST_FACTOR
  FREE_TIER_GB = 1.0, ESCROW_TRUST_FACTOR = 20.0 (configurable, calibrate later)
  Убрать EscrowTier, tier constants. Одна непрерывная формула
  Мотивация: время — плохой proxy для вклада, trust уже содержит время (I) + взаимность (S)

Phase β.3 — Personal Cluster:
  Device registration / revocation
  ClusterSync (event log)
  Peer-to-device affinity
  Epoch rotation

Phase β.4 — Polish:
  Reliability forecast
  Commitment telemetry (computed eviction risk)
  Disk pressure rework (effective_quota, hard_quota floor)
  File deletion flow (Watcher → Deleted → cooldown → symbol cleanup)
  α bug fixes (chunk restore, PoS, vacuum)
  Continuous importance

GATE: E2E тест — 2+ устройства, RaptorQ, backup → versioned restore → device revocation
```

---

## Решения из обсуждений (2026-03-15)

- **iroh-blobs и iroh-docs не нужны.** Оба online → direct connection. Peer оффлайн → epidemic relay (peer пишет в свой board, подписчики копируют с hop+1, hop≤2 → drop). Покрытие: ~100 peers за пару дней при 15 партнёрах. Хранение relay: append-only файл, TTL 7 дней, periodic cleanup. Символы = direct connection + bytes (уже работает в α). iroh используется только как transport.
- **File catalog ≠ filesystem:** DB хранит каталог бекапа независимо от диска. `local_state: Present | Deleted(ts)`. Удаление файла ≠ удаление из бекапа.
- **File versioning:** Vec<FileVersion> per path. max_versions (default 5), max_version_age (default 90 days). Cooldown на удаление старых версий (ransomware protection). `syncback restore path --version N` или `--date`.
- **Disk pressure:** `effective_quota = min(soft_quota, disk_free - disk_reserve)`. `hard_quota` = пол, ниже которого не вытеснять. По умолчанию soft_quota=0 (без потолка), hard_quota=0 (без пола), disk_reserve=20GB.
- **Commitment spectrum (self-reported):** отклонён по результатам game theory анализа (cheap talk, pooling NE). Заменён computed commitment telemetry (eviction risk signal).
- **DB два слоя, не три:** HOT (RAM ~13 МБ для 5 ТБ) + WARM (redb ~133 МБ). Холодный слой (PoS hashes) убран — верификация на лету из локального файла.
- **PoS adaptive:** challenges_per_week = base × volume_factor × trust_factor. Не фиксированный per holder.
- **Backup trigger:** event-driven, не раз в неделю. Flush: ≥128 МБ OR 1hr idle OR 24hr fallback. Min batch 1 МБ.
- **Block size configurable:** default 128 МБ, user может менять (32 МБ для Raspberry Pi → ~65 МБ peak RAM). T=64 КБ всегда фиксирован.
- **Placement formula:** `weight = trust / sqrt(1-trust)`, cap = `(1-1/overhead)×0.85`, hard limit `K_eff - 1` per holder. +10-21pp vs uniform.

---

## Связанные документы

- `docs/beta/raptorq.md` — полный анализ RaptorQ (DB модель, reliability math, anti-collusion)
- `docs/beta/personal_cluster.md` — Personal Cluster (key hierarchy, revocation, state sync)
- `docs/beta/ideas.md` — непроработанные идеи
- `docs/alpha/ADR-003-implementation-architecture.md` — α архитектура (базовый контекст)
- `docs/research/protocol.md` — протокол (source of truth, обновлён disk pressure)
