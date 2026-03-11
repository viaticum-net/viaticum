# ADR-003: Как строим (implementation architecture)

*2026-03-11 · Accepted*

Целевая платформа: альфа, консольный клиент, Linux (+ Mac).

## Один процесс

Десктопный демон, не серверная система. Один бинарник, один процесс. Никаких микросервисов, внешних очередей, message broker'ов.

## Async runtime: tokio

iroh уже тянет tokio — берём его. Все I/O операции async.

## Workspace: два crate'а

```
syncback/
  Cargo.toml              # workspace
  crates/
    syncback-core/         # библиотека, чистая логика (Фаза 1 по ADR-002)
      src/
        lib.rs
        trust.rs           # Trust engine (P, I, S)
        escrow.rs          # Escrow тиры
        placement.rs       # Weighted placement
        budget.rs          # Budget planner (работает с данными из DB, не с сетью)
        types.rs           # FileRecord, ShardRecord, PeerRecord...
        db.rs              # Обёртка над redb
    syncback/              # бинарник, daemon + CLI
      src/
        main.rs
        cli.rs             # subcommands: daemon, status, backup, restore
        daemon/
          mod.rs
          watcher.rs       # File watching (notify)
          scheduler.rs     # Timer loop, periodic tasks
          network.rs       # iroh endpoint, connections
          processor.rs     # Центральный обработчик команд
          packer.rs        # Файлы → units (pack/chunk, delta, vacuum)
          storage.rs       # Holder: приём/хранение чужих шардов
          shard_manager.rs # Encrypt → erasure → placement → upload
          cli_server.rs    # Unix socket, обслуживает CLI
```

**syncback-core** — ноль сетевых зависимостей. Только redb, blake3, reed-solomon, chacha20, serde, ciborium. Тестируется без сети и без tokio.

**`Db`** — newtype-обёртка над `Arc<redb::Database>`, передаётся по clone между модулями.

**syncback** — зависит от core + iroh + notify + tokio. Daemon, интеграция, CLI.

Третий crate добавим если появится причина. При ~3700 строках мельче нарезать — бюрократия.

## Tokio tasks (~5 штук)

Отдельный task нужен только компонентам со своим event loop:

| Task | Event loop | Что делает |
|---|---|---|
| Watcher | `notify_rx.recv()` | Помечает файлы dirty в DB |
| Scheduler | `tokio::time::sleep()` | Отправляет команды по таймеру |
| Network | `endpoint.accept()` | iroh соединения, gossip |
| Processor | `cmd_rx.recv()` + `net_rx.recv()` | Оркестрирует всю логику |
| CLI Server | `listener.accept()` | Unix socket для CLI |

Trust Engine, Shard Manager, Budget Planner, Escrow, Packer — **не отдельные tasks**, а модули (struct с методами). Вызываются из Processor как `trust_engine.update(&event)`. Делать их tasks = ненужная сложность с каналами.

**Processor** — центральный task. Держит все модули, принимает команды от Scheduler и CLI, события от Network. Единственный writer в DB (redb: один WriteTransaction за раз). Watcher пишет только в `dirty_files`, но не уведомляет Processor напрямую — Scheduler запрашивает dirty файлы из DB по таймеру (WeeklySync).

## Коммуникация между tasks

```
Watcher ──(пишет dirty в DB)───────────────────
                                                │
Scheduler ──(Command)──► Processor              │
                            │                   │
CLI ────────(Command)──►    │  ◄── читает DB ───┘
                            │
                            ├──► trust_engine.update()
                            ├──► packer.pack_dirty()
                            ├──► shard_manager.process()
                            │
Network ◄──(NetCommand)── Processor
   │
   └──(NetEvent)──► Processor
```

`tokio::mpsc` каналы. Никаких внешних очередей.

**Важно:** все записи в DB — только из Processor task. Network и CLI Server только читают. Watcher — исключение: пишет в `dirty_files` (отдельная таблица, не пересекается с Processor).

## Scheduler: внутренний timer loop

Вместо cron — tokio task с таймером. Timestamps последнего запуска хранятся в redb, переживают рестарт.

```
loop {
    if now - last_weekly_sync >= 1 week  → send(WeeklySync)
    if now - last_pos_round  >= 1 day    → send(PosRound)
    if now - last_vacuum     >= 1 month  → send(Vacuum)
    sleep(5 min)
}
```

## CLI ↔ Daemon: Unix socket

- `syncback daemon` — запускает демон в foreground
- `syncback status`, `syncback backup`, ... — CLI-команды, общаются с демоном через Unix domain socket
- Протокол: JSON request/response (для альфы достаточно)
- Автозапуск: systemd (Linux) / launchd (Mac), не daemonize в коде

## Runtime paths

```
~/.syncback/
  config.toml          # конфигурация пользователя
  syncback.redb        # основная DB
  identity.key         # приватный ключ (seed-derived, 0600)
  syncback.sock        # Unix socket для CLI ↔ daemon
```

Единственная директория. Всё в одном месте — проще backup, проще удалить.

`XDG_DATA_HOME` и прочие freedesktop-конвенции — потом. Для альфы `~/.syncback/` достаточно.

## Graceful shutdown

`CancellationToken` из tokio-util. Один токен на все tasks:

```
Ctrl+C → cancel.cancel() → все tasks завершаются → flush DB → exit
```

**Panic в task:** tokio::spawn по умолчанию глотает панику — task умирает, остальные продолжают в зомби-режиме. Все JoinHandle'ы мониторятся в main:

```rust
tokio::select! {
    r = watcher_handle => r.expect("watcher panicked"),
    r = processor_handle => r.expect("processor panicked"),
    r = network_handle => r.expect("network panicked"),
    // panic в любом task → panic в main → процесс падает → systemd перезапустит
}
```

## Storage: redb

Embedded key-value DB, pure Rust, ACID, MVCC (читатели не блокируют писателей).

Таблицы — из architecture.md + индексные таблицы для hot paths:

```
# Основные
files:     file_path    → {hash, size, importance, dirty, current_unit_id, ...}
units:     unit_id      → {type, status, member_files, size, hash, ...}
shards:    shard_id     → {unit_id, shard_index, holder_id, status, last_verified}
peers:     identity_pub → {trust_P, trust_I, trust_S, first_seen, last_seen, ...}
holding:   shard_id     → {owner_pub, importance, size, state, received_at, delete_requested_at}
budget:    "budget"     → {estimated_gb, last_calculated, placement_success_rate}
config:    key          → value
schedule:  task_name    → {last_run, next_run}

# Индексы (secondary tables для hot paths)
dirty_files:       file_path → timestamp
stale_units:       unit_id   → stale_ratio
unverified_shards: shard_id  → last_verified
```

Значения — CBOR-сериализованные структуры.

### Известный компромисс

При 500K–1M файлов размер DB: ~500 MB – 1 GB (B-tree overhead ~2×). Приемлемо на фоне 200 GB фотоархива. При необходимости: компактные ключи (u64 вместо path) или миграция на SQLite.

## Conventions (код пишет ИИ)

Программист — ИИ. Приоритет: явность, однозначность, невозможность сделать неправильно. Гибкость и краткость — вторичны.

### Типы вместо строк

Newtype wrappers для всех идентификаторов. Компилятор не даст перепутать shard_id и unit_id:

```rust
pub struct ShardId(pub [u8; 32]);
pub struct UnitId(pub [u8; 32]);
pub struct FileId(pub u64);
pub struct IdentityPub(pub [u8; 32]);
```

Никаких `String` или `&[u8]` где можно типизировать.

### Ошибки: thiserror, по модулю

Каждый модуль — свой enum ошибок. Компилятор не даст забыть обработать вариант:

```rust
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("unknown peer: {0:?}")]
    UnknownPeer(IdentityPub),
    #[error("db error: {0}")]
    Db(#[from] redb::Error),
}
```

Никаких `anyhow` в библиотечном коде (syncback-core). `anyhow` допустим только в бинарнике (daemon/CLI) на верхнем уровне.

### Единообразие модулей

Каждый модуль в syncback-core — одинаковая структура:

```rust
// trust.rs
pub struct TrustEngine { db: Db }

impl TrustEngine {
    pub fn new(db: Db) -> Self { ... }
    pub fn record_pos_result(&mut self, ...) -> Result<(), TrustError> { ... }
    pub fn score(&self, peer: &IdentityPub) -> Result<TrustScore, TrustError> { ... }
}
```

Struct + impl + Error enum. Никаких trait'ов "на будущее", никаких builder pattern'ов.

### Никакой магии

- Никаких proc-macro ради красоты
- Явные вызовы вместо implicit behavior (Deref, From повсюду)
- `From`/`Into` только для error conversion (`#[from]` в thiserror)
- Минимум generics — конкретные типы где возможно

### Тесты рядом с кодом

Unit тесты — в том же файле. Интеграционные — в `tests/` директории crate'а.

```rust
// trust.rs
pub struct TrustEngine { ... }
impl TrustEngine { ... }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pos_success_increases_trust() { ... }

    #[test]
    fn four_week_window_decays() { ... }
}
```

## Тестирование

Код пишет ИИ. TDD (тесты первыми) не работает — ИИ может неправильно понять спец и написать тесты под своё неправильное понимание. Вместо этого: **тесты обязательно**. ИИ пишет функцию и тесты к ней в одной задаче. Порядок не важен.

Ценность тестов при AI-разработке:
- **Регрессия:** ИИ в сессии N+5 правит код и ломает старое — тесты ловят
- **Самопроверка:** тест и код написаны по одной спеке независимо — расхождение = баг
- **Документация:** следующая сессия ИИ читает тесты и понимает поведение

Правило: **написал публичную функцию → написал тесты. Без тестов — задача не закончена.**

### Три уровня

```
        /\
       /  \  Smoke (2-3)
      /    \  — демон стартует, ноды видят друг друга
     /──────\
    /        \  Integration (~10)
   /          \  — сквозные сценарии, два реальных endpoint'а
  /────────────\
 /              \  Unit (50-100)
/                \  — каждая функция в core
──────────────────
```

### Unit (syncback-core) — 90% тестов

Чистая логика, без сети, без async. Миллисекунды.

```
trust:      формула, decay, accumulation, edge cases
escrow:     тиры, граничные значения, free tier
placement:  weighted selection, cap, adaptive n
budget:     estimation, sorting, cutoff
db:         CRUD, индексы, dirty query
types:      сериализация/десериализация CBOR
```

DB в тестах — реальный redb на tmpfile, не мок:

```rust
fn test_db() -> Db {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    Db::open(tmp.path())
}
```

### Integration (syncback, `tests/`) — ~10 тестов

Два реальных iroh endpoint на localhost. Медленные (секунды), но проверяют что компоненты работают вместе. Моков нет.

```
two_nodes_connect_and_handshake
shard_offer_accept_transfer
pos_challenge_response
shard_upload_then_restore
trust_updates_after_pos_round
placement_and_upload_full_flow
weekly_sync_dirty_files_to_shards
escrow_denies_low_trust_restore
disk_pressure_triggers_eviction
repair_after_holder_disconnect
```

### Smoke (2-3 теста)

"Демон жив?" — минимум:

```
daemon_starts_and_responds_to_status
two_daemons_discover_each_other
```

### Когда запускать

| Когда | Что | Время |
|---|---|---|
| `cargo test -p syncback-core` | Unit | <1 сек |
| `cargo test -p syncback` | Integration + smoke | 10-30 сек |
| Перед коммитом | Всё | <1 мин |

### Именование

```rust
// Паттерн: what_when_then
fn trust_score_is_zero_for_unknown_peer() { ... }
fn placement_fails_when_fewer_peers_than_n() { ... }
fn escrow_denies_restore_when_i_score_below_tier() { ... }
```

### Тест-хелперы

```rust
// testutil.rs в syncback-core
pub fn test_peer() -> IdentityPub { ... }
pub fn test_peers(n: usize) -> Vec<IdentityPub> { ... }
pub fn week(n: u32) -> Timestamp { ... }
pub fn test_shard() -> ShardRecord { ... }
```

### Чего НЕ делаем в тестах

- Property-based testing — формулы проверены симуляциями (Exp 1-27)
- Моки — конкретные типы, реальная DB, реальный iroh
- Coverage targets — рабочий код цель, не процент покрытия
- Fuzzing — для альфы рано

### Правило для ИИ

```
Модуль в syncback-core → unit тесты обязательно
Новый сценарий в daemon → integration тест если затрагивает >1 компонент
Smoke не трогать — они стабильны
```

## Error handling (альфа)

Альфа ищет баги. Лучше упасть и увидеть, чем молча проглотить. systemd поднимет.

### Три категории

| Категория | Пример | Реакция |
|---|---|---|
| **Штатная** | Пир оффлайн, мало пиров для placement, escrow denied | Лог info/debug, продолжаем, retry на следующем цикле |
| **Нештатная** | DB ошибка, невалидное сообщение, нарушен инвариант | **panic** — в альфе это баг, его надо увидеть |
| **Фатальная** | iroh endpoint closed, невалидный identity key | Лог error, graceful shutdown |

### syncback-core: thiserror, строгие типы

Каждый модуль — свой error enum. Никаких `Other(String)`, `Unknown`, `anyhow`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("unknown peer: {0:?}")]
    UnknownPeer(IdentityPub),
    #[error("db: {0}")]
    Db(#[from] redb::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum PlacementError {
    #[error("no eligible peers (need {need}, have {have})")]
    NotEnoughPeers { need: usize, have: usize },
    #[error("trust: {0}")]
    Trust(#[from] TrustError),
}
```

### syncback (daemon): expect + panic

В альфе — `expect()` везде кроме явно штатных ситуаций:

```rust
// Штатная ситуация — обрабатываем
match self.placement.select_holders(unit) {
    Ok(holders) => { /* upload */ }
    Err(PlacementError::NotEnoughPeers { need, have }) => {
        tracing::info!(need, have, "not enough peers, retry next week");
        return Ok(());
    }
    Err(e) => panic!("placement failed: {e}"),  // в альфе — падаем
}

// DB — всегда panic в альфе
self.db.insert_shard(&shard).expect("db write failed");
```

### Переход к продакшну

Позже, когда баги найдены: `panic` → `Result` + graceful handling. Проще чем наоборот.

## Logging: tracing

iroh уже использует tracing — единый лог.

### Вывод

Альфа — всё в stderr. systemd journal подхватит (`journalctl -u syncback`). Никаких файлов, ротации.

```rust
tracing_subscriber::fmt()
    .with_env_filter("syncback=debug,iroh=info")
    .init();
```

`RUST_LOG=syncback=trace` для детальной отладки без перекомпиляции.

### Уровни

```
ERROR — демон сейчас упадёт (panic после лога, или graceful shutdown)
INFO  — ключевые события, ~5-10 в день
DEBUG — каждая операция
TRACE — байты, хеши, внутренности (только при отладке)
```

WARN не используем — в альфе нет смысла: либо штатно (info), либо падаем (error).

### Что логируем

```
INFO:
  daemon started, listening on {socket}
  peer connected: {peer_id}
  weekly sync: {n} files, {size} MB, {shards} shards placed
  pos round: {n} challenges sent
  restore complete: {path}

DEBUG:
  file dirty: {path} ({hash})
  shard placed: {shard_id} → {holder_id}
  pos challenge sent: {shard_id} → {holder_id}
  pos response: {holder_id} ok/fail
  trust updated: {peer_id} P={p} I={i} S={s}

TRACE:
  raw message: {cbor_hex}
  db write: table={table} key={key}
```

### Structured fields

```rust
tracing::info!(
    files = dirty_count,
    size_mb = total_size / 1_000_000,
    shards = placed_count,
    "weekly sync complete"
);
```

Именованные поля, не строковая интерполяция.

### Правило: логировать контекст операции

Не перед каждым `?`, а перед логической операцией (группой вызовов):

```rust
// Плохо — лог на каждой строке, шум
tracing::debug!("inserting shard");
self.db.insert_shard(&shard).expect("db write");
tracing::debug!("updating trust");
self.trust.record_transfer(&holder).expect("trust update");

// Хорошо — один лог на операцию
tracing::debug!(shard = %shard.id, holder = %holder, "storing shard");
self.db.insert_shard(&shard).expect("db write failed");
self.trust.record_transfer(&holder).expect("trust update failed");
```

## Чего НЕ делаем

- Внешняя очередь (kafka, redis) — оверкилл для десктопа
- gRPC для CLI — JSON over socket хватит
- Daemonize в коде — systemd/launchd справятся
- Plugin system — всё статически скомпилировано
- Больше двух crate'ов — при 3700 строках не нужно
