# SyncBack Architecture

*2026-03-22. Reflects actual code — all phases + δ.1 complete (716 tests, ~34K lines Rust).*

*See also: [overview.md](overview.md) for end-to-end flows, [logic.md](logic.md) for algorithms, [protocol.md](protocol.md) for wire format.*

---

## Общая схема

```
┌─────────────────────────── syncback-core ───────────────────────────────┐
│  (pure Rust, no async, no network)                                       │
│                                                                          │
│  types ──► db ──────────────────────────────────────────────────────    │
│   │         (Db, HotCache, 12 redb tables)                          │    │
│   │                                                                  │    │
│   ├──► trust    (TrustEngine: P, I, S)                              │    │
│   ├──► escrow   (EscrowChecker: trust-based budget gate)            │    │
│   ├──► budget   (BudgetEngine: GB estimate, willingness)            │    │
│   ├──► placement (SymbolBudgetEngine: weight = trust/√(1-trust))   │    │
│   ├──► erasure  (ErasureEncoder trait + RaptorQ impl + binding)    │    │
│   ├──► cluster  (key derivation, certs, ClusterState, epochs)      │    │
│   ├──► pos      (PosEngine: challenge, verify, adaptive schedule)  │    │
│   ├──► messages (wire format, all message structs)                  │    │
│   ├──► system_state (SystemState: snapshot, restore, pack/unpack)   │    │
│   └──► constants (все числовые параметры протокола)                 │    │
└──────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────── syncback (daemon) ───────────────────────────┐
│  (tokio async, libp2p transport, координаторы)                          │
│                                                                          │
│  handle ────── DaemonHandle: owns & wires all subsystems                │
│     │                                                                    │
│     ├──► network      (libp2p TCP+Noise, DHT, DCUtR, SwarmHandle)       │
│     ├──► processor    (message router: dispatches all incoming msgs)     │
│     ├──► backup       (BackupCoordinator: watcher → symbols)            │
│     ├──► restore      (RestoreCoordinator: symbols → files)             │
│     ├──► repair       (RepairAgent: Lost/PresumedLost → re-encode)      │
│     ├──► scheduler    (PoS challenge scheduling, timeout detection)     │
│     ├──► watcher      (fs-notify: recursive watch → DirtyEvent)         │
│     ├──► relay        (RelayManager: epidemic board, hop≤2)             │
│     ├──► cluster_sync (ClusterSyncManager: event log exchange)          │
│     ├──► cli_server   (Unix socket: CLI commands → DaemonState)         │
│     ├──► identity     (BIP39 → HKDF → keys, identity file mgmt)        │
│     ├──► system_state (periodic DB push, bootstrap discovery)           │
│     └──► dr           (disaster recovery: BFS, standalone restore)      │
└──────────────────────────────────────────────────────────────────────────┘
```

Crate разделён намеренно: `syncback-core` тестируется без tokio и без сети —
юнит-тесты запускаются мгновенно. Daemon-кратный код в `syncback` использует
`syncback-core` как библиотеку.

---

## Структура крейтов

### syncback-core

Чистая логика. Никакого async, никаких сетевых вызовов, никакого tokio.

```
crates/syncback-core/src/
  lib.rs          — pub mod на все модули
  constants.rs    — все числовые параметры в одном файле
  types/          — все shared типы и record-структуры
  db/             — Db newtype + HotCache + CRUD методы для всех таблиц
  trust/          — TrustEngine (P/I/S формула)
  escrow/         — EscrowChecker (trust-based gate)
  budget/         — BudgetEngine (GB estimate, eviction priority)
  placement/      — SymbolBudgetEngine (weighted allocation)
  erasure/        — ErasureEncoder trait + RaptorQ impl + per-holder binding
  cluster/        — DeviceCertificate, RevocationCertificate, ClusterState, epochs
  pos/            — PosEngine (challenge selection, verify, adaptive schedule)
  messages/       — все wire-сообщения + relay board helpers
  config/         — TOML config loading and validation (AppConfig)
  commitment/     — Holder eviction risk estimation (CommitmentScore)
  reliability/    — P(block recoverable) forecast (Binomial model)
  deletion/       — Double cooldown deletion flow + vacuum
  system_state/   — SystemState struct, snapshot_db, restore_db, pack/unpack (CBOR+zstd+ChaCha20)
```

### syncback

Daemon + CLI. Использует tokio. Импортирует `syncback-core`.

```
crates/syncback/src/
  main.rs         — binary entry point: CLI dispatch, tracing setup
  lib.rs          — pub mod daemon
  cli/            — Clap CLI, CliRequest/CliResponse types, output formatting
  daemon/
    mod.rs        — pub mod на все daemon модули
    handle/       — DaemonHandle: top-level wiring, DaemonState
    processor/    — Processor: message router for all incoming messages
    network/      — SwarmHandle (swarm.rs)
    backup/       — BackupCoordinator (+ events.rs, pipeline.rs, packing.rs)
    restore/      — RestoreCoordinator (+ pipeline.rs)
    repair/       — RepairAgent
    scheduler/    — Scheduler: PoS challenge timing, PendingChallenges
    watcher/      — fs-notify watcher: recursive, debounce, DirtyEvent
    relay/        — RelayManager (+ board.rs)
    cluster_sync/ — ClusterSyncManager
    cli_server/   — Unix socket server: bridges CLI to DaemonState
    identity/     — BIP39/HKDF key derivation, identity.key file
    system_state/ — periodic DB push to peers, bootstrap discovery
    dr/           — disaster recovery CLI: BFS peer discovery, standalone restore
```

---

## Модули syncback-core

### types

Все newtype ID-обёртки, record-структуры и вспомогательные типы.

**Ключевые типы:**

| Тип | Описание |
|-----|----------|
| `SourceBlockId([u8; 32])` | BLAKE3-хэш зашифрованного source block |
| `IdentityPub([u8; 32])` | Ed25519 публичный ключ (мастер-идентичность) |
| `DeviceId([u8; 32])` | Ed25519 pubkey bytes of device signing key |
| `FileId(u64)` | Монотонный ID файла, присваивается при первом индексировании |
| `Timestamp(u64)` | Unix timestamp в секундах |
| `ErasureParams` | Вычисленные параметры: K, K_eff, T, overhead, N |
| `FileRecord` | Запись каталога: path, importance, devices, versions |
| `FileVersion` | Одна версия файла: content_hash, source_block_id, created_at |
| `SourceBlockRecord` | Метаданные source block: K, T, type, status, encrypted_size |
| `SymbolPlacement` | Размещение символов у holder'а: esi_ranges, binding_seed, status |
| `PlacementStatus` | Offered → Accepted → Alive → Uncertain → PresumedLost → Lost / Deleting |
| `PeerRecord` | Данные пира: trust_p, trust_i, trust_s, byte счётчики, device_id |
| `HoldingRecord` | Символы, которые мы держим для другого owner'а |
| `HoldingStatus` | Active / MarkedForDelete / Silent |
| `BudgetRecord` | Singleton: estimated_gb, placement_success_rate |
| `BlockAgg` | RAM-агрегат: K, total_alive_symbols для source block |
| `PlacementAgg` | RAM-агрегат: symbol_count, status, last_pos для (block, holder) |
| `Event` / `EventEntry` | Типизированные события event log (для cluster sync) |
| `FileCategory` | Photo / Document / Video / Other (для packing queues) |
| `LocalState` | Present / Deleted(Timestamp) (состояние файла на конкретном device) |
| `SourceBlockType` | Pack { entries } / Single |

**Зависимости:** только `constants`, no external logic.

---

### trust

`TrustEngine` — вычисляет trust score для каждого peer'а.

**Формула:** `trust = (KP × P + KI × I) × clamp(S, 0.1, 1.0)`

- P — rolling 4-week PoS pass rate
- I — cumulative mean PoS pass rate
- S — pairwise GB ratio (мы для него / он для нас)
- KP = 0.4, KI = 1.75 (из `constants.rs`)

**Ключевые методы:** `record_pos_outcome`, `recalculate`, `score`.

**Хранение:** в-памяти HashMap; при запуске загружается из `POS_WEEKLY` redb-таблицы через `Db`.

---

### escrow

`EscrowChecker` — gate для restore-запросов.

**Формула:** `restore_budget_gb = stored_gb_days / k_factor`

- `k_factor = DEFAULT_ESCROW_K_FACTOR = 7.0` (дней хранения на 1 GB restore)
- `stored_gb_days` = bytes_we_store_for_peer × days_held (суммарно по всем holding записям)

Contribution-based: earn restore credit by storing data for others.

---

### budget

`BudgetEngine` — оценивает, сколько GB мы можем разместить у других peer'ов.

Учитывает placement_success_rate (rolling 4-week), willingness_factor (1.0), FREE_TIER_GB bootstrap (1 GB), offer_budget_gb (inflated by 1/sr).

Singleton `BudgetRecord` хранится в redb таблице `BUDGET`.

---

### placement

`SymbolBudgetEngine` — вычисляет, сколько символов отдать каждому holder'у.

**Формула веса:** `weight = trust / sqrt(1 - trust)` (mean-variance optimum)

**Ограничения:**
- `MAX_HOLDERS_PER_BLOCK = 30`
- `MIN_SYMBOLS_PER_HOLDER = 32` (2 МБ при T=64 KB)
- Concentration cap: `max_per_holder = min(K_eff - 1, floor((1 - 1/overhead) × 0.85 × N))`

**Вход:** `Vec<HolderCandidate>` с trust score + `ErasureParams`.
**Выход:** `Vec<HolderAllocation>` с symbol_count и start_esi для каждого holder'а.

---

### erasure

**trait ErasureEncoder** — абстракция над erasure coding. Единственная реализация: RaptorQ.

```rust
fn encode(source_block, params, start_esi, count, block_id, holder_id) -> Vec<Symbol>
fn decode(symbols, params) -> Vec<u8>
fn generate_repair(source_block, params, esi, block_id, holder_id) -> Symbol
fn unbind(symbol, block_id, holder_id) -> Symbol
```

**Per-holder binding (anti-collusion):**
```
keystream = ChaCha20(HKDF-SHA256(source_block_id || holder_id), nonce=0)
bound_symbol_data = raw_symbol_data XOR keystream[esi*T..(esi+1)*T]
```

Символ = fungible, идентифицируется ESI. T = 65535 байт (фиксирован: лимит raptorq crate).

---

### cluster

Работает с ключами и сертификатами устройств. Без сети.

**Ключевые типы:**
- `DeviceCertificate` — master_key.sign(device_id, device_pub_key, issued_at)
- `RevocationCertificate` — master_key.sign("revoke", device_id, revoked_at, new_epoch)
- `EpochCounter(u32)` — инкрементируется при каждой revocation
- `ClusterState` — in-memory: набор устройств, revoked keys, sync cursors

**Хранение:** `StoredClusterState` в redb таблице `CLUSTER_STATE`.

Ключевая иерархия: BIP39 (24 слова) → HKDF-SHA256 → master Ed25519 key → device keys.

---

### pos

`PosEngine` — challenge selection, verification, adaptive scheduling.

**Adaptive schedule:**
```
challenges_per_week = POS_BASE_CHALLENGES_PER_WEEK
                    × ceil(holder_symbols / POS_VOLUME_DIVISOR)
                    × trust_factor
```

- `POS_BASE_CHALLENGES_PER_WEEK = 1`
- `POS_VOLUME_DIVISOR = 1000`
- Timeout = 7 дней (`POS_TIMEOUT_SECS`)

**PlacementStatus state machine (PoS timeouts):**
```
Alive → 1 miss → Uncertain → 3+ misses → PresumedLost → repair
Alive → Fail / NotHeld → Lost → immediate repair
```

**Verify on-the-fly:** owner перекодирует symbol локально и сравнивает с ответом holder'а. Никакого хранения PoS hashes на диске.

**VerifyOutcome:** Pass / Fail { esi } / Timeout / NotHeld { esi }

**Еженедельная статистика:** таблица `POS_WEEKLY` в redb, ключ = (peer || week_number_BE).

---

### messages

Все wire-сообщения + relay board helpers. Wire format: CBOR + u32 BE length prefix.

**Сообщения прямых соединений:**

| Тип | Направление | Описание |
|-----|-------------|----------|
| `HandshakeMsg` | ↔ | Взаимная аутентификация при открытии соединения |
| `PeerAnnounceMsg` | broadcast relay | Объявление адреса пира (discovery) |
| `PosChallengeMsg` | owner → holder | Запрос данных символа по ESI |
| `PosResponseMsg` | holder → owner | Ответ: данные символа |
| `PosNackMsg` | holder → owner | Символ не хранится (evicted / missed) |
| `SymbolOfferMsg` | owner → holder | Предложение принять символы |
| `SymbolAcceptMsg` | holder → owner | Согласие на приём |
| `SymbolRejectMsg` | holder → owner | Отказ (QuotaFull / LowPriority / ...) |
| `SymbolStoredMsg` | holder → owner | Подтверждение сохранения |
| `SymbolTransferMsg` | ↔ | Передача символов (backup + restore) |
| `SymbolDroppedMsg` | holder → owner | Holder сбросил символы (disk pressure) |
| `ClusterSyncRequestMsg` | device → device | Запрос event log после cursor |
| `ClusterSyncResponseMsg` | device → device | Ответ с событиями |
| `RevocationBroadcast` | relay broadcast | Трансляция revocation certificate |

ALPN: `"syncback/1"`. HandshakeMsg подписывается Ed25519: `sign("handshake" || identity_pub || timestamp_be)`.

---

### db

`Db` — newtype над `Arc<redb::Database>` + `Arc<RwLock<HotCache>>`.

Cheaply cloneable: `clone()` = increment refcount. Все методы принимают `&self`.
MVCC в redb обеспечивает read-параллелизм. Write-lock только на HotCache при мутациях.

Открытие: `Db::open(path)` — pre-open backup (.redb.bak), `DatabaseBuilder` с `repair_callback`, `check_integrity()`, создаёт все таблицы и строит HotCache full scan из SYMBOL_PLACEMENTS.

**Два слоя:**
- **HOT (RAM, ~13 МБ на 5 ТБ):** HashMap агрегаты `BlockAgg` и `PlacementAgg` в `HotCache`
- **WARM (redb, ~133 МБ на 5 ТБ):** все 12 таблиц, CBOR-значения

---

## DB Schema

### redb таблицы (WARM слой)

| Таблица | Ключ | Значение | Описание |
|---------|------|----------|----------|
| `files` | `&str` (path) | CBOR(`FileRecord`) | Каталог файлов |
| `source_blocks` | `&[u8; 32]` (block_id) | CBOR(`SourceBlockRecord`) | Метаданные source block'ов |
| `symbol_placements` | `&[u8; 64]` (block_id ∥ holder_id) | CBOR(`SymbolPlacement`) | Размещение символов (owner side) |
| `peers` | `&[u8; 32]` (identity_pub) | CBOR(`PeerRecord`) | Данные peer'ов |
| `holdings` | `&[u8; 64]` (block_id ∥ owner_id) | CBOR(`HoldingRecord`) | Удерживаемые символы (holder side) |
| `event_log` | `u64` (seq, 1-based monotonic) | CBOR(`EventEntry`) | Append-only event log для cluster sync |
| `budget` | `"budget"` | CBOR(`BudgetRecord`) | Singleton: оценка GB |
| `pos_weekly` | `&[u8; 36]` (peer ∥ week_number_BE4) | CBOR(`WeeklyPosEntry`) | Еженедельная PoS статистика |
| `cluster_state` | `"cluster_state"` | CBOR(`StoredClusterState`) | Singleton: состояние кластера |
| `file_holders` | `&[u8; 40]` (file_id_BE8 ∥ holder_id) | `u32` (symbol_count) | Индекс file → holders |
| `holder_files` | `&[u8; 40]` (holder_id ∥ file_id_BE8) | `u32` (symbol_count) | Индекс holder → files |
| `system_state_blobs` | `&[u8; 32]` (owner identity_pub) | CBOR(`SystemStateBlobRecord`) | Encrypted DB snapshots from peers (1 per owner, TTL 365 days) |

### HotCache (RAM слой)

```rust
pub struct HotCache {
    // source_block_id → { k, total_alive_symbols }
    pub blocks: HashMap<SourceBlockId, BlockAgg>,
    // (source_block_id, holder IdentityPub) → { symbol_count, status, last_pos }
    pub placements: HashMap<(SourceBlockId, IdentityPub), PlacementAgg>,
}
```

Пересчитывается при `Db::open()` полным сканом `symbol_placements`. Обновляется синхронно внутри redb write-транзакции при каждой мутации placement'а.

---

## Модули daemon (syncback)

### network

`SwarmHandle` — единственный libp2p swarm на экземпляр daemon'а.

**Ответственности:**
- Создаёт libp2p swarm: TCP+Noise+Yamux, Kademlia DHT, DCUtR+Relay для NAT traversal
- Запускает background swarm event loop (аутентификация входящих соединений)
- DeviceCertExchange при подключении: связывает libp2p PeerId с IdentityPub
- Handshake: DeviceCertExchange + Ed25519 verification + freshness check (±300 сек)

**API (SwarmHandle):**
- `start(config) → (SwarmHandle, Receiver<ProtocolEvent>)` — запуск swarm + event loop
- `send_to_device(device: DeviceId, msg)` — отправить сообщение устройству по DeviceId
- `send_to_master(master: IdentityPub, msg)` — отправить любому устройству данного master
- `dial(peer_id, addr)` — явный dial по libp2p PeerId + Multiaddr
- `listen_addrs()` — список адресов, на которых слушаем
- `respond(channel, msg)` — ответ на inbound request через ResponseChannel
- `build_peer_announce(...)` — строит подписанный PeerAnnounceMsg

---

### backup

`BackupCoordinator` — оркестрирует пайплайн file → symbol.

**Жизненный цикл события:**
```
DirtyEvent(path, kind, device_id)
  │
  ├─ Deleted  → FileRecord.devices[device].local_state = Deleted(now)
  │             (никакого сетевого трафика)
  │
  └─ Added/Modified
       → content_hash = blake3(file)
       → dedup: content_hash в catalog? → добавить version/device, done
       → classify(path) → FileCategory
       → size ≥ source_block_size? → process_large_file()
       → иначе → enqueue в per-category queue
```

**Packing queues:** четыре очереди по категории (Photo, Document, Video, Other).

**Flush условия (любое из):**
- `queue_bytes ≥ source_block_size`
- 1 час idle (FLUSH_IDLE_SECS)
- 24 часа fallback (FLUSH_FALLBACK_SECS)
- Принудительный force=true

**Pipeline внутри flush:**
```
batch plaintext = [PackIndex CBOR] + [file1 bytes] + [file2 bytes] + ...
  → zstd compress (streaming)
  → ChaCha20-Poly1305 encrypt (epoch_key, random nonce prepended)
  → ciphertext = source block
  → source_block_id = blake3(ciphertext)
  → ErasureParams::compute(block_size, importance)
  → SymbolBudgetEngine.compute_allocation(candidates, params)
  → для каждого holder:
      encode(source_block, params, start_esi, count, block_id, holder_id)
      → bound symbols (per-holder XOR binding)
      → запись в symbols_dir/{hex(block_id)}/{esi}.bin
  → DB: upsert FileRecord, SourceBlockRecord, SymbolPlacement × N_holders
  → EventLog: append SymbolsPlaced events
  → RAM hot: обновление BlockAgg, PlacementAgg
```

**Async run():** принимает `DirtyEvent` из mpsc channel. Три таймера: idle, fallback, channel close.

---

### restore

`RestoreCoordinator` — оркестрирует symbol fetch → decode → file write.

**Поддерживает:**
- Точное восстановление одного файла по пути
- Prefix-запрос (путь с `/` в конце → все файлы с этим префиксом)
- Выбор версии: Latest / Index(n) / BeforeDate(timestamp)

**Pipeline:**
```
RestoreRequest(path, version_selector, output_dir, device_id)
  → resolve_path → Vec<FileRecord>
  → select_version → (FileRecord, FileVersion) pairs
  → дедупликация по source_block_id
  → для каждого уникального source block:
      list_placements_for_block → alive placements
      → читать symbol files: {symbols_dir}/{hex(block_id)}/{esi}.bin
      → unbind: symbol XOR ChaCha20(HKDF(block_id, holder_id))
      → collect ≥ K_eff unbound symbols
      → ErasureEncoder.decode → padded block
      → trim до encrypted_size (из SourceBlockRecord)
      → ChaCha20-Poly1305 decrypt → compressed
      → zstd decompress → plaintext
  → для Pack: extract_from_pack(plaintext, file_id) → file bytes
  → для Single: plaintext напрямую
  → write файл в output_dir
  → update FileRecord.devices: device_id → Present
```

Local restore: символы на диске из BackupCoordinator.
Network restore: fetch from holders через NetworkHandle (`fetch_from_holder`).

**Async run():** принимает `(RestoreRequest, oneshot::Sender)` из mpsc, обрабатывает последовательно.

---

### repair

`RepairAgent` — мониторит Lost/PresumedLost placement'ы, регенерирует символы локально.

**Триггеры:**
- Периодический scan (каждые `scan_interval_secs`)
- `RepairTrigger::RepairNow { block_id, holder_id }` — немедленный repair
- `RepairTrigger::ScanAll` — полный scan

**Pipeline repair_placement:**
```
1. Читает SourceBlockRecord из DB → K, T
2. Читает SymbolPlacement → esi_ranges, binding_seed, holder_id
3. Читает source block file: {symbols_dir}/{hex(block_id)}/block.bin
4. Для каждого ESI в esi_ranges:
     encode(source_data, params, esi, 1, block_id, holder_id)
     → bound symbol → запись в {symbols_dir}/{hex(block_id)}/{hex(holder_id)}/{esi}.sym
5. Обновляет placement.status = Alive, consecutive_misses = 0
```

**handle_symbol_dropped / handle_pos_nack:** оба делают одно — `mark_placement_lost` (idempotent: если уже Lost/Deleting — no-op).

Repair: local re-encode + network delivery to new holders.

---

### cluster_sync

`ClusterSyncManager` — обмен event log между устройствами одного кластера.

**Синхронный API** (не async). Callers управляют соединениями.

**Методы:**
- `build_sync_request(peer_identity)` → `ClusterSyncRequestMsg` с cursor
- `process_sync_response(peer_identity, response)` → применяет events, обновляет cursor
- `handle_sync_request(request)` → отдаёт события из event log, проверяет membership
- `build_revocation_broadcast(revocation, device_cert)` → payload для relay board

**Cursor persistence:** sync cursors хранятся в `ClusterState` (in-memory), сохраняются в `CLUSTER_STATE` redb-таблице через `ClusterState::update_sync_cursor`.

Проверка входящих запросов: `device_id` должен быть в кластере и не revoked.

---

### relay

`RelayManager` — epidemic gossip доска для deferred messaging.

**Модель:** каждый узел ведёт append-only board file. При соединении партнёры обмениваются записями. Сообщения распространяются hop=0 → hop=1 → hop=2, дальше не копируются.

**Типы записей:**
- `Broadcast` — открытый payload (PeerAnnounce, RevocationBroadcast)
- `Directed` — зашифровано для конкретного получателя (ECDH ChaCha20-Poly1305)

**Жизненный цикл записи:**
```
post_broadcast / post_directed_with_key  → hop=0, запись на диск
process_remote_entries (от партнёра):
  → dedup по msg_id
  → TTL check (RELAY_TTL_SECS = 7 дней)
  → hop check (MAX_RELAY_HOP = 2)
  → verify Ed25519 signature
  → relay_copy: hop+1, append
scan_for_self → decrypt directed → inbound_tx channel
prune: TTL + size limits (MAX_BOARD_ENTRIES=2000, MAX_BOARD_SIZE_BYTES=8MB)
```

**Board file:** append-only, periodic rewrite при prune.

**Async run():** listens `SyncTrigger` (incoming connections), periodic prune timer.

---

### handle

`DaemonHandle` — top-level entry point. Owns and wires all subsystems.

**DaemonState** (shared via `Arc`):
```rust
DaemonState {
    db, identity_pub, device_id, network, restore_tx,
    cluster_state, incoming_tx, master_key, seed,
    data_dir, soft_quota_bytes, disk_reserve_bytes,
}
```

**Startup sequence:**
1. Load/create identity (BIP39 → keys)
2. Open DB (with repair callback + pre-open backup)
3. Start SwarmHandle (libp2p swarm + event loop)
4. Spawn Processor (message router)
5. Spawn BackupCoordinator, RestoreCoordinator, RepairAgent
6. Spawn Scheduler (PoS), RelayManager, ClusterSyncManager
7. Spawn SystemState periodic push (interval = 6h / time_scale, min 60s)
8. Start Watcher (fs-notify) for configured directories
9. Start CliServer (Unix socket)
10. Load peers from DB → known_peers in network
11. Bootstrap discovery: connect to bootstrap peers, PeerDiscoveryRequest (1-hop)

---

### processor

`Processor` — thin message router. Receives incoming connections from network, dispatches messages to appropriate handlers.

**Dispatch table (26 message types):**
- `Handshake` → auth (handled by network accept loop)
- `PeerAnnounce` → upsert peer, add to known_peers, store addrs
- `PosChallenge` → look up holding, re-read symbol, send PosResponse or PosNack
- `PosResponse` → verify, update placement status + trust
- `PosNack` → mark placement Lost, trigger repair
- `SymbolOffer` → check quota → SymbolAccept / SymbolReject
- `SymbolAccept` → update placement to Alive (via BackupEvent channel)
- `SymbolReject` → update placement, log
- `SymbolTransfer` → write symbols to disk, update HoldingRecord
- `SymbolStored` → log confirmation
- `RestoreRequest` → escrow check → read symbols → RestoreResponse or RestoreDenied
- `BoardSync` → relay_sync_tx (forwarded to RelayManager)
- `ClusterSync*` → forwarded to ClusterSyncManager
- `Delete/CancelDelete` → update HoldingRecord status
- `StorageWarning/SymbolDropped/SymbolDropNotice` → log, update placements
- `SystemStateBackup` → store blob (known peers only) → SystemStateAck
- `SystemStateRequest` → return stored blob → SystemStateResponse
- `SystemStateAck/Response` → log / forward to DR
- `PeerDiscoveryRequest` → return peer list (any authenticated connection)
- `PeerDiscoveryResponse` → forward to DR / bootstrap

**On new connection (PeerAuthenticated event):** upserts PeerRecord, sends PeerAnnounce, auto-adds cluster device.

---

### watcher

`WatcherConfig` → fs-notify recursive watcher on configured directories.

**Pipeline:**
```
fs event → notify::Event → std channel → tokio task → debounce (30 min)
  → DirtyEvent { path, kind: Added/Modified/Deleted, device_id }
  → mpsc → BackupCoordinator
```

Filters: hidden files (dotfiles), temporary files.
Only detects changes AFTER daemon start — pre-existing files not scanned.

---

### scheduler

`Scheduler` — periodic PoS challenge issuance.

- Computes `due_challenges()` from placements + last_verified timestamps
- Issues PosChallenge via network, stores in `PendingChallenges` (shared with Processor)
- On timeout (7 days): records as Timeout, updates placement status
- Adaptive rate: `challenges/week = base * volume_factor * trust_factor`

---

### cli_server

Unix socket server at `{data_dir}/syncback.sock`.

**Commands:** status, files, versions, peers, restore, connect, device (add/revoke/list), backup (force flush)

Bridges CLI → DaemonState for reads, CLI → RestoreCoordinator for restores, CLI → NetworkHandle for connections.

---

### identity

BIP39 mnemonic (24 words) → seed → HKDF key derivation.

**Derived keys:**
- master_key (Ed25519): `HKDF(seed, info="syncback-identity-ed25519")`
- device_key (Ed25519): `HKDF(seed, salt=device_id, info="syncback-device-ed25519")`
- epoch_key: `HKDF(seed, salt=epoch_counter, info="syncback-encryption")`
Identity file: `{data_dir}/identity.key` (mode 0600), stores encrypted seed.

---

## Потоки данных

### Backup

```
Файловая система
  │
  ├─ fs-notify (watcher)
  │    debounce 30 мин → dirty_files
  │
  └─ DirtyEvent → BackupCoordinator.process_event()
                        │
                  dedup check (content_hash в catalog?)
                        │
              ┌─ yes → добавить version/device, done (zero traffic)
              │
              └─ no → classify → packing queue
                           │
                    flush trigger (size / idle / fallback)
                           │
              compress(zstd) → encrypt(ChaCha20-Poly1305)
                           │
                  source_block_id = blake3(ciphertext)
                           │
               ErasureParams::compute(size, importance)
                           │
          SymbolBudgetEngine.compute_allocation(candidates, params)
                           │
                   для каждого holder:
                     encode → bind → write {esi}.bin
                           │
                   DB update: Files, SourceBlocks,
                   SymbolPlacements, EventLog, HotCache
```

### Restore

```
RestoreRequest(path, VersionSelector, output_dir)
  │
  DB: get_file / list_files_with_prefix
  DB: list_placements_for_block → alive
  │
  для каждого source block:
    read {esi}.bin → Symbol
    unbind(XOR ChaCha20 keystream) → raw symbol
    collect ≥ K_eff
    decode → padded_block[k×t]
    trim → encrypted_block[encrypted_size]
    decrypt(ChaCha20-Poly1305, epoch_key)
    decompress(zstd)
    │
    Pack → extract_from_pack(plaintext, file_id)
    Single → plaintext напрямую
    │
    write output_dir/{rel_path}
    DB: update LocalState → Present
```

### Proof of Storage

```
PosEngine.compute_schedule(placements, now)
  → challenges_per_week = base × volume_factor × trust_factor
  │
  для каждого challenge:
    PosChallengeMsg { challenge_id, source_block_id, esi } → holder
    │
    holder отвечает PosResponseMsg { data } или PosNackMsg
    │
    verify_response():
      re-encode(source_block, params, esi, block_id, holder_id)
      expected_bound_data == response.data?
      │
    VerifyOutcome: Pass / Fail / Timeout / NotHeld
    │
    update_placement_status(outcome, now):
      Pass    → status=Alive, consecutive_misses=0
      Fail    → status=Lost (immediate)
      NotHeld → status=Lost (immediate)
      Timeout → consecutive_misses++
                1 miss  → Uncertain
                3+ miss → PresumedLost
    │
    TrustEngine.record_pos_outcome(peer, week, outcome)
    DB: upsert_placement, upsert_pos_weekly
```

### Repair

```
RepairAgent.scan_and_repair()
  │
  DB: list_placements_needing_repair()  ← status=Lost/PresumedLost
  │
  для каждого placement:
    read {symbols_dir}/{hex(block_id)}/block.bin  (source data)
    SourceBlockRecord: K, T
    SymbolPlacement: esi_ranges, holder_id
    │
    для каждого ESI:
      encode(source_data, params, esi, 1, block_id, holder_id)
      write {symbols_dir}/{hex(block_id)}/{hex(holder_id)}/{esi}.sym
    │
    DB: upsert_placement(status=Alive, consecutive_misses=0)
    │
    [Phase 3] network: send symbols to holder
```

### Cluster sync

```
ClusterSyncManager.build_sync_request(peer_identity)
  → ClusterSyncRequestMsg { last_known_seq: cursor }
  │
  → send over network connection
  ↓
peer returns ClusterSyncResponseMsg { events, responder_last_seq }
  │
process_sync_response():
  ClusterState.apply_events(events)   ← idempotent
  ClusterState.update_sync_cursor(peer, responder_last_seq)
  DB: set_cluster_state()
```

---

## Конфигурация (что настраивается)

| Параметр | Default | Описание |
|----------|---------|----------|
| `source_block_size` | 128 МБ | Размер source block. Менять для слабого железа (32 МБ → ~65 МБ peak RAM) |
| `symbols_dir` | `"symbols"` | Директория для symbol files |
| `epoch_key` | — | 32-байтный ключ шифрования (производится из master key) |
| `device_id` | — | Идентификатор устройства |
| `soft_quota` | 0 (без потолка) | Мягкое ограничение holding в байтах |
| `hard_quota` | 0 (без пола) | Жёсткий минимум: ниже него не вытеснять |
| `disk_reserve` | 20 ГБ | Резерв свободного места на диске |
| `effective_quota` | вычисляется | `min(soft_quota, disk_free - disk_reserve)` |
| `backup_dirs` | — | Директории для backup + importance per dir |
| `max_versions` | 5 | Максимум версий на один путь |
| `max_version_age` | 90 дней | Максимальный возраст старых версий |
| `parallel_holders` | 5 | Параллельные соединения при restore |
| `escrow_trust_factor` | 20.0 | ESCROW_TRUST_FACTOR (GB per trust unit) |
| `prune_interval_secs` | 3600 | Интервал очистки relay board |

Все числовые протокольные параметры вынесены в `syncback-core/src/constants.rs`.
