# Viaticum: Wire Protocol Specification

*2026-03-21. Version β. Authoritative protocol spec.*

*See also: [logic.md](logic.md) for algorithm quick-reference, [overview.md](overview.md) for end-to-end flows.*

---

## 0. Технологический стек

| Компонент | Выбор | Примечание |
|-----------|-------|------------|
| Erasure coding | RaptorQ (RFC 6330), crate `raptorq` | НЕ Reed-Solomon |
| Transport | libp2p (TCP + Noise + Yamux, Kademlia DHT, DCUtR) | transport only |
| Gossip / deferred | Epidemic relay (board-based) | НЕ pubsub |
| Wire format | CBOR + u32 BE length-prefix | `ciborium` crate |
| ALPN | `"viaticum/1"` | строка байт |
| File encryption | ChaCha20-Poly1305 | epoch-keyed |
| Per-holder binding | ChaCha20 XOR stream | anti-collusion |
| Подписи | Ed25519 | identity + device certs |
| ECDH (relay) | X25519 | ephemeral per message |
| KDF | HKDF-SHA256 | domain-separated |
| Хеши | BLAKE3 | content-addressed IDs |

Прямые соединения + epidemic relay полностью покрывают потребности cold backup.

---

## 0.1. Формат сообщений

### Framing

Каждое сообщение = `[u32 BE length][CBOR payload]`.

```
┌──────────────────┬──────────────────────────────────────┐
│  4 bytes (u32 BE)│  N bytes (CBOR)                      │
│  payload length  │  Message enum (CBOR tagged)           │
└──────────────────┴──────────────────────────────────────┘
```

- Максимальный размер фрейма: `MAX_MESSAGE_SIZE = 64 MiB`
- CBOR enum-тег: `{"type": "snake_case_variant_name", ...fields...}`

### Версионирование

- ALPN уровень: `b"viaticum/1"` — при смене версии протокола ALPN меняется
- Уровень сообщений: поле `v: u8` в каждом сообщении. Текущая версия: `PROTOCOL_VERSION = 1`
- Неизвестный вариант enum'а: сторона логирует и игнорирует, соединение не разрывается

### Верхнеуровневый enum

```rust
pub enum Message {
    Handshake(HandshakeMsg),
    PeerAnnounce(PeerAnnounceMsg),
    PosChallenge(PosChallengeMsg),
    PosResponse(PosResponseMsg),
    PosNack(PosNackMsg),
    SymbolOffer(SymbolOfferMsg),
    SymbolAccept(SymbolAcceptMsg),
    SymbolReject(SymbolRejectMsg),
    SymbolStored(SymbolStoredMsg),
    SymbolTransfer(SymbolTransferMsg),
    Delete(DeleteMsg),
    CancelDelete(CancelDeleteMsg),
    StorageWarning(StorageWarningMsg),
    SymbolDropped(SymbolDroppedMsg),
    SymbolDropNotice(SymbolDropNoticeMsg),
    RestoreRequest(RestoreRequestMsg),
    RestoreResponse(RestoreResponseMsg),
    RestoreDenied(RestoreDeniedMsg),
    BoardSync(BoardSyncMsg),
    ClusterSyncRequest(ClusterSyncRequestMsg),
    ClusterSyncResponse(ClusterSyncResponseMsg),
    SystemStateBackup(SystemStateBackupMsg),
    SystemStateAck(SystemStateAckMsg),
    SystemStateRequest(SystemStateRequestMsg),
    SystemStateResponse(SystemStateResponseMsg),
    PeerDiscoveryRequest(PeerDiscoveryRequestMsg),
    PeerDiscoveryResponse(PeerDiscoveryResponseMsg),
    Ack(AckMsg),  // generic ack for request-response streams that expect a reply
}
```

---

## 1. Что протокол определяет (обязательное поведение)

Раздел описывает то, что верифицируемо и обязательно для совместимости. Рекомендуемые значения параметров (не обязательные) — в разделе 2.

---

### 1.1. Identity и устройства

#### Иерархия ключей

```
Seed phrase (BIP39, 24 слова)
│
├─ Master identity key (Ed25519)
│   HKDF-SHA256(ikm=seed_bytes, salt=b"", info=b"viaticum-identity-ed25519")
│   IdentityPub = master_key.verifying_key()  ←── стабильный ID владельца
│
├─ Device key (Ed25519, per device)
│   HKDF-SHA256(ikm=seed_bytes, salt=device_id.0, info=b"viaticum-device-ed25519")
│   DeviceId = device_key.verifying_key()  ←── transport identity (libp2p PeerId derived from this)
│
└─ Epoch encryption key (ChaCha20, per epoch)
    HKDF-SHA256(ikm=seed_bytes, salt=epoch.0.to_be_bytes(), info=b"viaticum-encryption")
```

- `DeviceId` = Ed25519 pubkey bytes of device signing key (32 bytes) — стабильный транспортный ID
- Seed phrase стирается из RAM после деривации ключей
- Устройство постоянно хранит: `device_key`, `epoch_key[current]`, `epoch_key[current-1]`

#### Device certificate

```rust
pub struct DeviceCertificate {
    pub device_id: DeviceId,        // 32 bytes (Ed25519 pubkey of device key)
    pub issued_at: Timestamp,
    pub signature: [u8; 64],        // Ed25519: master_key.sign(payload)
    pub master_pub_key: IdentityPub,
}
// signed payload = device_id.0 (32) || issued_at.0.to_be_bytes() (8)
// device_id.0 IS the device pubkey — no separate device_pub_key field
```

#### Revocation certificate

```rust
pub struct RevocationCertificate {
    pub device_id: DeviceId,
    pub revoked_at: Timestamp,
    pub new_epoch: EpochCounter,
    pub signature: [u8; 64],  // Ed25519: master_key.sign(payload)
    pub master_pub_key: IdentityPub,
}
// signed payload = b"revoke" (6) || device_id.0 (16) || revoked_at.0.to_be_bytes() (8)
//                  || new_epoch.0.to_be_bytes() (4)
```

---

### 1.2. Handshake (аутентификация соединения)

Протокол Viaticum handshake выполняется поверх libp2p Noise IX слоя. После Noise-хэндшейка стороны обмениваются `DeviceCertExchangeMsg`, связывающим libp2p PeerId с `IdentityPub`.

#### Порядок обмена

```
Initiator (A)          Acceptor (B)
     │                      │
     │── HandshakeMsg ──────>│   A отправляет первым
     │<─ HandshakeMsg ───────│   B читает, затем отвечает
     │                      │   оба верифицируют
```

#### HandshakeMsg

```rust
pub struct HandshakeMsg {
    pub v: u8,                             // PROTOCOL_VERSION = 1
    pub identity_pub: IdentityPub,         // Ed25519 pubkey (32 bytes)
    pub timestamp: Timestamp,             // Unix seconds
    pub sig: [u8; 64],                    // Ed25519 подпись
    pub device_cert: Option<DeviceCertificate>,  // только для multi-device
}
// sig покрывает: b"handshake" || identity_pub.0 (32) || timestamp.0.to_be_bytes() (8)
// device_cert НЕ входит в sig (cert самоподписан master key, верифицируется отдельно)
```

#### Правила верификации

1. `|timestamp - now| <= HANDSHAKE_FRESHNESS_SECS` (300 секунд)
2. Проверить Ed25519 подпись `sig` на `identity_pub`
3. Если `device_cert` присутствует:
   - `cert.device_id.0 == handshake.identity_pub.0` (device_id IS the pubkey)
   - Проверить `cert.signature` на `cert.master_pub_key`
   - Вернуть `master_pub_key` как cluster identity пира
4. Если ожидается конкретный peer: `received.identity_pub == expected_identity`

#### Результат handshake

После успешного handshake, нода знает:
- `peer_identity: IdentityPub` — кем подписывал handshake (device key)
- `peer_master_identity: Option<IdentityPub>` — master identity если multi-device

---

### 1.3. Source blocks и symbols (НЕ units и shards)

#### Терминология

| β (текущее) | α (устаревшее) | Что это |
|-------------|----------------|---------|
| Source block | Unit | Данные для erasure coding |
| Symbol | Shard | Один encoded кусок, T байт |
| ESI (Encoding Symbol ID) | shard_id | Идентификатор символа (u32, 0, 1, 2...) |
| K source symbols | k (фиксированный) | Минимум для decode |
| N distributed | n (фиксированный k-of-n) | Сколько раздали |

#### Параметры (из `constants.rs`)

```
T = 65_535 байт (SYMBOL_SIZE) — размер символа, фиксированный (u16 limit crate)
DEFAULT_SOURCE_BLOCK_SIZE = 128 МБ (configurable via config.toml)
DECODE_OVERHEAD = 3   → K_eff = K + 3
OVERHEAD_BASE = 1.5, OVERHEAD_SCALE = 1.5 → overhead = 1.5 + importance × 1.5
```

#### Формулы

```
K = ceil(source_block_size / T)      // 2048 при 128 МБ блоке
K_eff = K + 3                        // 2051 при K=2048
overhead = 1.5 + importance × 1.5   // 1.5x (importance=0) .. 3.0x (importance=1)
N = ceil(K_eff × overhead)           // всего символов к распределению
```

#### Source block ID

```
source_block_id = BLAKE3(ciphertext)
```

Content-addressed: один и тот же файл на разных устройствах → одинаковый ciphertext → одинаковый `source_block_id` → zero-traffic deduplication.

#### Encryption (два слоя)

**Слой 1 — шифрование файла:**
```
file_key = HKDF-SHA256(epoch_key, content_hash || b"viaticum-file-encryption")
ciphertext = ChaCha20-Poly1305_encrypt(key=file_key, plaintext=compressed_data)
```

**Слой 2 — per-holder binding (anti-collusion):**
```
binding_key = HKDF-SHA256(source_block_id || holder_id, b"viaticum-binding")
stored_symbol = symbol XOR ChaCha20_stream(binding_key)
```

Per-holder binding обязателен. Без него K colluding holders могут хранить одну копию и regenerate on demand — redundancy становится иллюзией.

Restore: owner знает `holder_id` → XOR обратно → чистый символ → RaptorQ decode.

#### Группировка файлов в source blocks

```
< 128 МБ  → batch несколько файлов в один source block (по категории типа)
≥ 128 МБ  → один файл нарезается на chunks по source_block_size
```

Категории: Photo, Document, Video, Other. Файлы одной категории объединяются в пачки.

Pack index хранится в `SourceBlockType::Pack { entries: Vec<PackEntry> }` где `PackEntry = { file_id, offset, size }`.

---

### 1.4. PoS (Proof of Storage)

PoS — механизм верификации того, что holder действительно хранит назначенные символы.

#### Сообщения

**PosChallengeMsg** (Owner → Holder):
```rust
pub struct PosChallengeMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],    // random nonce для матчинга ответа
    pub source_block_id: SourceBlockId,
    pub esi: u32,                   // конкретный ESI к проверке
    pub timestamp: Timestamp,
}
```

**PosResponseMsg** (Holder → Owner):
```rust
pub struct PosResponseMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],
    pub esi: u32,
    pub data: Vec<u8>,              // BOUND символ, ровно T байт (65_535)
    pub timestamp: Timestamp,
}
```

**PosNackMsg** (Holder → Owner):
```rust
pub struct PosNackMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],
    pub source_block_id: SourceBlockId,
    pub esi: u32,
    pub timestamp: Timestamp,
}
```

`PosNack` означает: "символ у меня не хранится" (вытеснен disk pressure, или никогда не получен). Holder обязан отправить `PosNack` вместо молчания если знает что не держит символ.

#### Верификация (Owner)

```
Получен PosResponse { esi, data }:
  1. Убедиться что source block файл существует на диске
  2. Recompute RaptorQ symbol(esi) из source block
  3. Compute binding: XOR ChaCha20(HKDF(source_block_id, holder_id))
  4. bound_expected = symbol XOR binding_stream
  5. Сравнить data == bound_expected байт-в-байт

Хеши символов НЕ хранятся в DB — верификация на лету.
```

#### VerifyOutcome и реакция

| Исход | Условие | Действие |
|-------|---------|---------|
| `Pass` | data совпадает | trust P +1, всё ок |
| `NotHeld` | получен PosNack | trust НЕ трогать, немедленный repair (holder честен) |
| `Fail` | data не совпадает | trust P −1, немедленный repair (повреждение или мошенничество) |
| `Timeout` | нет ответа за 7 дней | trust P −1, graduated response (см. ниже) |

Наказывать за NotHeld нельзя — это снижает стимул holder'а честно сообщать об отсутствии символов.

#### Graduated response на Timeout (PlacementStatus)

```
Alive
  │ 1-я miss (Timeout)
  ↓
Uncertain    ← consecutive_misses = 1, 2
  │ 3+ misses
  ↓
PresumedLost ← триггер repair
  │ repair завершён
  ↓
Alive (новый holder)

Отдельный путь (Pass/Fail/NotHeld):
Alive/Uncertain → Lost (немедленно) → триггер repair
```

Константы: `POS_CONSECUTIVE_MISS_UNCERTAIN = 1`, `POS_CONSECUTIVE_MISS_PRESUMED_LOST = 3`.

Логика: Timeout = неопределённость (peer мог уехать в отпуск; для cold backup 1-2 недели offline — норма). NotHeld/Fail = определённость → реагируем сразу.

#### Адаптивная частота

```
challenges_per_week = POS_BASE_CHALLENGES_PER_WEEK
                      × ceil(holder_symbols / POS_VOLUME_DIVISOR)
                      × (2.0 - trust)

POS_BASE_CHALLENGES_PER_WEEK = 1
POS_VOLUME_DIVISOR = 1000
```

Holder с большим количеством символов проверяется чаще. Holder с низким trust — чаще.

#### Таймаут

`POS_TIMEOUT_SECS = 7 × 24 × 3600` (7 дней). Единый для всех. Покрывает:
- Прямые соединения (peer временно offline)
- Cluster forwarding (challenge пришёл к device A, символы на device B)

#### Ограничения PoS

- PoS не проводится для source blocks в статусе `Deleting` или `Deleted`
- Если файл удалён локально и блок в cooldown — PoS прекращается
- Overhead на bandwidth: `T × 15 holders = ~1 МБ/неделю` — пренебрежимо мал

---

### 1.5. Epidemic relay (gossip board)

Epidemic relay — механизм доставки сообщений когда прямое соединение невозможно (peer offline).

#### Принцип работы

```
Sender: публикует запись в relay board (append-only файл)
  → hop=0

При синхронизации с партнёром:
  → BoardSync: обмен записями которых нет у партнёра
  → партнёр сохраняет записи с hop+1

hop=0 → hop=1 → hop=2 → DROP (MAX_RELAY_HOP = 2)
```

За 2 хопа при 15 партнёрах: покрытие ~100 нод за несколько дней.

#### Типы записей

```rust
pub enum BoardEntryKind { Broadcast, Directed }

pub struct BoardEntry {
    pub kind: BoardEntryKind,
    pub target_pub: Option<IdentityPub>,  // только для directed
    pub payload: Vec<u8>,                  // CBOR (broadcast) или зашифрованный (directed)
    pub sig_author: [u8; 64],             // Ed25519, подписан оригинальным автором
    pub author: IdentityPub,
    pub hop: u8,                           // 0..MAX_RELAY_HOP
    pub created_at: Timestamp,            // для TTL
}
```

Relay nodes НЕ перепосдписывают записи. `sig_author` — подпись оригинального автора, сохраняется неизменной.

#### TTL и лимиты

- `RELAY_TTL_SECS = 7 × 24 × 3600` (7 дней)
- `MAX_RELAY_HOP = 2`
- `MAX_BOARD_ENTRIES = 2000`
- `MAX_BOARD_SIZE_BYTES = 8 MiB`

Записи старше TTL удаляются при periodic cleanup.

#### Directed messages

Адресованные конкретному получателю сообщения шифруются через ephemeral ECDH:

```rust
pub struct DirectedEnvelope {
    pub sender_x25519_pub: [u8; 32],   // ephemeral public key
    pub nonce: [u8; 12],               // ChaCha20-Poly1305 nonce
    pub ciphertext: Vec<u8>,           // encrypted CBOR payload
}
// KDF: HKDF-SHA256(ikm=ECDH_shared, salt=sender_pub||receiver_pub,
//                  info=b"viaticum-directed")
```

Ephemeral key генерируется заново для каждого сообщения (forward secrecy).

#### Подпись board entry

```
sig_input = msg_type_bytes || msg_id (16) || kind_str || target_pub_or_empty || payload
sig_author = author_signing_key.sign(sig_input)
```

#### BoardSync сообщение

```rust
pub struct BoardSyncMsg {
    pub v: u8,
    pub entries: Vec<StoredEntry>,   // записи которых нет у партнёра
    pub timestamp: Timestamp,
}

pub struct StoredEntry {
    pub msg_type: String,    // "peer_announce", "pos_challenge", etc.
    pub msg_id: [u8; 16],
    pub entry: BoardEntry,
}
```

`BoardSync` отправляется первым сообщением после handshake. Старые ноды не знающие этот вариант — логируют и игнорируют (соединение не разрывается).

#### Использование relay

| Назначение | Тип записи |
|------------|------------|
| PeerAnnounce (discovery) | broadcast |
| PoS challenge (peer offline) | directed |
| DeviceRevocation | broadcast (`RevocationBroadcast`) |
| ClusterSync events | через прямое соединение (не relay) |

---

### 1.6. Размещение символов (Symbol Placement)

#### Веса holders

```
weight_i = trust_i / sqrt(1 - trust_i)    // mean-variance оптимум
share_i  = weight_i / sum(all_weights)
```

Не `trust²` — слишком агрессивная концентрация. `t/sqrt(1-t)` — оптимум в модели mean-variance с учётом риска.

#### Ограничения

```
max_share = (1 - 1/overhead) × CONCENTRATION_CAP_FACTOR    // 0.85
max_per_holder = min(K_eff - 1, floor(max_share × N))

MAX_HOLDERS_PER_BLOCK = 30   // > 30 = линейный рост overhead restore/PoS
MIN_SYMBOLS_PER_HOLDER = 32  // < 32 = 2 МБ, overhead учёта не оправдан
```

`K_eff - 1` — жёсткий потолок: больше смысла нет (один holder владеет всем файлом).

#### Алгоритм распределения

```
1. weight_i = trust_i / sqrt(1 - trust_i)
2. share_i  = weight_i / sum(all_weights)
3. symbols_i = clamp(round(N × share_i), 1, max_per_holder)
4. Перераспределить остаток от capped holders → uncapped
5. Убрать holders с symbols_i < MIN_SYMBOLS_PER_HOLDER
   → перераспределить их символы пропорционально
6. При m ≤ 10 и N ≤ 100: exact DP (гарантированный оптимум)
```

#### ESI namespace (multi-device)

```
device_index 0: ESI [0,          1_048_576)   (2^20)
device_index 1: ESI [1_048_576,  2_097_152)
...
device_index 15: ESI [15_728_640, 16_777_216)  (max ESI в RaptorQ = 2^24)
```

`ESI = device_index × 2^20 + local_counter`. Устройства генерируют символы без координации в real-time.

#### Rebalancing

Rebalancing = только добавление новых символов (новые ESI), никогда не перенос старых.

```
Trust упал у holder A:
  НЕ забираем символы (они валидны)
  Генерируем новые символы → размещаем у более надёжных
  total_alive_symbols растёт → reliability растёт

Holder B ушёл (PoS fails):
  Статус → Lost
  Repair: generate новые ESI → разместить у другого holder'а
```

---

### 1.7. Lifecycle сообщений для символов

#### Backup flow

```
Owner                          Holder
  │── SymbolOffer ────────────>│   offer: source_block_id, esi_ranges, importance
  │<─ SymbolAccept ────────────│   или SymbolReject (quota_full, etc.)
  │── SymbolTransfer (×N) ────>│   push символов батчами
  │<─ SymbolStored ────────────│   подтверждение получения
```

**SymbolOfferMsg**:
```rust
pub struct SymbolOfferMsg {
    pub v: u8,
    pub msg_id: [u8; 16],
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,   // (start_esi, count)
    pub importance: f64,
    pub timestamp: Timestamp,
    pub sig: [u8; 64],   // Ed25519 owner_key.sign(source_block_id || esi_ranges_cbor
                         //                         || importance_be_f64 || timestamp)
}
```

**RejectReason**:
```rust
pub enum RejectReason {
    QuotaFull, LowPriority, UnknownOwner, HashMismatch, Other,
}
```

**SymbolTransferMsg** (используется и для backup push, и для restore response):
```rust
pub struct SymbolTransferMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub symbols: Vec<Symbol>,   // bound symbols
    pub timestamp: Timestamp,
}
```

#### Restore flow

```
Owner                          Holder
  │── RestoreRequest ─────────>│   esi_list: [] = "любые K_eff из твоих"
  │<─ RestoreResponse ──────────│   bound symbols
  │   (или RestoreDenied)
```

**RestoreRequestMsg**:
```rust
pub struct RestoreRequestMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi_list: Vec<u32>,    // пусто = "любые K_eff"
    pub timestamp: Timestamp,
}
```

**RestoreDeniedMsg** (escrow не пройден):
```rust
pub struct RestoreDeniedMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub reason: String,
    pub required_weeks: u32,   // DEPRECATED — оставлено для совместимости
    pub current_weeks: u32,    // DEPRECATED — оставлено для совместимости
    pub timestamp: Timestamp,
}
// В β escrow trust-based. required_weeks/current_weeks не используются в логике.
```

#### Удаление символов

Двойной cooldown — защита от ransomware:

```
Owner:
  local file Deleted → wait OWNER_DELETE_COOLDOWN_SECS (4 недели)
  → Send DeleteMsg
  → (опционально) CancelDeleteMsg пока не истёк cooldown

Holder:
  получен DeleteMsg → wait HOLDER_DELETE_COOLDOWN_SECS (4 недели)
  → физическое удаление символов
```

Суммарный cooldown: 4 + 4 = 8 недель.

**DeleteMsg / CancelDeleteMsg**:
```rust
pub struct DeleteMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub timestamp: Timestamp,
    pub sig: [u8; 64],   // Ed25519 owner_key.sign(source_block_id || timestamp)
}
```

#### Вытеснение (disk pressure)

```
Holder → Owner: SymbolDropNotice (advance warning, deadline)
  deadline за DROP_NOTICE_WINDOW_SECS (7 дней) до drop

Holder → Owner: SymbolDropped (факт вытеснения)
  → owner: PlacementStatus → Lost → trigger repair
```

**SymbolDropNoticeMsg**:
```rust
pub struct SymbolDropNoticeMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,
    pub deadline: Timestamp,   // когда произойдёт drop
    pub timestamp: Timestamp,
}
```

#### StorageWarning

Owner уведомляет holder о битрот (PoS Fail):
```rust
pub struct StorageWarningMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi: u32,
    pub details: String,
    pub timestamp: Timestamp,
}
```

---

### 1.8. Escrow (contribution-based)

Escrow контролирует доступ к restore. Цель: блокировать hit-and-run (взять символы, не вернуть взамен) и мотивировать взаимный вклад.

#### Формула

```
restore_budget_gb = stored_gb_days / k_factor

k_factor = DEFAULT_ESCROW_K_FACTOR = 7.0  // дни хранения на 1 GB restore
```

Пример: хранишь 1 GB 7 дней → зарабатываешь 1 GB restore budget.

`stored_gb_days` рассчитывается как сумма `bytes_we_store_for_peer × days_held` по всем holding записям пира.

#### Проверка

Holder проверяет перед отправкой символов на restore:
```
total_bytes_in_request <= restore_budget_gb × 1024³
```

Если проверка не проходит — holder отправляет `RestoreDeniedMsg`.

Time-based escrow (weeks_in_network) из α — удалён. Trust уже содержит временную компоненту (I = cumulative mean).

---

### 1.9. Personal Cluster

Personal Cluster = несколько устройств одного владельца как единая identity.

#### Что кластер обеспечивает

- Одна `IdentityPub` (master key) для всех устройств
- Непрерывная репутация: partners не замечают смену устройства
- Deduplication: один файл на N устройствах → одна копия в сети
- Device revocation при краже
- ESI namespace без координации в real-time

#### Multi-device handshake

Устройство кластера включает `device_cert` в handshake:
```
HandshakeMsg.identity_pub = DeviceId.0          (device pubkey bytes = device identity)
HandshakeMsg.device_cert  = DeviceCertificate   (master_key.sign(device_id.0 || issued_at))
```

Получив такой handshake, partner извлекает `master_pub_key` из `device_cert` как cluster identity. Все дальнейшие trust/escrow операции ведутся по `master_pub_key`.

#### Device registration

```
1. Новое устройство вводит seed phrase → derive device_key
2. device_id = DeviceId(device_key.verifying_key().to_bytes())  // 32 bytes Ed25519 pubkey
3. Создаёт DeviceCertificate = master_key.sign(device_id.0 || issued_at)
4. Публикует cert через relay board → партнёры принимают устройство как часть identity
5. Seed стирается из RAM
6. Синхронизация state (file catalog, placements) через ClusterSync
```

Лимит устройств: 16 (`MAX_DEVICES = 16`). Определяется ESI namespace: `ESI space = 2^24`, `2^20 per device`.

#### Device revocation

```
1. viaticum device revoke <device_id>
2. Создать RevocationCertificate = master_key.sign(b"revoke" || device_id || revoked_at || new_epoch)
3. epoch_counter += 1, новый epoch_key
4. Публикация через relay board: RevocationBroadcast { revocation_cert, device_cert }
5. Partners: добавляют device в revoked list, отказывают в restore/PoS для revoked device key
6. Owner: постепенно re-encrypt старых файлов новым epoch
```

**RevocationBroadcast** (broadcast relay entry):
```rust
pub struct RevocationBroadcast {
    pub revocation: RevocationCertificate,
    pub device_cert: DeviceCertificate,
}
```

Доставка revocation — eventual consistency через gossip (hop≤2, TTL 7 дней). Threat model: "lazy not malicious" — вор скорее всего не будет активно противодействовать.

#### ClusterSync

Синхронизация state между устройствами через event log:

```rust
// Device A → Device B:
pub struct ClusterSyncRequestMsg {
    pub v: u8,
    pub from_device_id: DeviceId,
    pub last_known_seq: u64,   // "дай мне события после этого seq"
    pub timestamp: Timestamp,
}

// Device B → Device A:
pub struct ClusterSyncResponseMsg {
    pub v: u8,
    pub events: Vec<(u64, EventEntry)>,   // (seq, event)
    pub responder_last_seq: u64,
    pub timestamp: Timestamp,
}
```

Event log commutative by design — порядок не важен для финального state.

#### Типы event log

```rust
pub enum Event {
    SymbolsPlaced { source_block_id, holder_id, esi_range },
    SymbolsLost   { source_block_id, holder_id },
    SymbolsVerified { source_block_id, holder_id },
    FileAdded     { file_id, path },
    FileModified  { file_id, content_hash },
    FileDeleted   { file_id, device_id },
    DeviceAdded   { device_id },
    DeviceRevoked { device_id },
    EpochRotated  { epoch },
}
```

#### Deduplication

Content-addressed dedup — автоматический:
```
file_key = HKDF(epoch_key, content_hash, ...)
ciphertext = ChaCha20-Poly1305(file_key, plaintext)
source_block_id = BLAKE3(ciphertext)
```

Тот же файл на двух устройствах → тот же `content_hash` → тот же ключ → тот же `ciphertext` → тот же `source_block_id` → символы уже в сети → zero extra traffic.

#### Peer-to-device affinity

```
Device A (online вечерами): управляет peers {P1, P3, P5}
Device B (NAS, always-on):  управляет peers {P2, P4, P6}
```

Blast radius isolation: device A offline → страдают только отношения с P1, P3, P5. Trust identity в целом — среднее.

S-score: per (device, peer) pair — протокол не знает про кластеры. Внешний peer видит device как обычную ноду.

---

### 1.10. System State backup и Peer Discovery (δ.1)

#### SystemState backup

Периодический push зашифрованного DB-снапшота на всех пиров. Один blob per owner, перезаписывается при каждом push.

```rust
// Owner → Holder. Push encrypted DB snapshot.
pub struct SystemStateBackupMsg { pub v: u8, pub encrypted_blob: Vec<u8>, pub timestamp: Timestamp }

// Holder → Owner. Acknowledge storage.
pub struct SystemStateAckMsg { pub v: u8, pub stored: bool, pub timestamp: Timestamp }

// Requester → Holder. Request stored blob (identity from handshake).
pub struct SystemStateRequestMsg { pub v: u8, pub timestamp: Timestamp }

// Holder → Requester. Return blob (empty vec = not found).
pub struct SystemStateResponseMsg { pub v: u8, pub encrypted_blob: Vec<u8>, pub timestamp: Timestamp }
```

**Encryption:** HKDF-SHA256(ikm=seed, salt=random_24, info=b"viaticum-system-state") → ChaCha20-Poly1305. Wire format: `[salt(24)][nonce(12)][ciphertext+tag]`.

**Serialization:** SystemState → CBOR → zstd compress → encrypt.

**Security:**
- `SystemStateBackup` — принимает только от **known peers** (prevents storage spam)
- `SystemStateRequest/Response` — отвечает любому (blob зашифрован, бесполезен без ключа владельца)
- TTL = 365 дней, автоудаление expired blob'ов при чтении

**Таблица:** `system_state_blobs` — key: `[u8; 32]` (owner identity_pub), value: CBOR(`SystemStateBlobRecord`).

#### Peer Discovery

BFS-обнаружение для DR и начальной загрузки пиров.

```rust
// Requester → Peer. "Give me your peer list."
pub struct PeerDiscoveryRequestMsg { pub v: u8, pub timestamp: Timestamp }

// Peer → Requester. List of known peers.
pub struct PeerDiscoveryResponseMsg {
    pub v: u8,
    pub peers: Vec<DiscoveredPeer>,
    pub timestamp: Timestamp,
}

pub struct DiscoveredPeer {
    pub identity_pub: IdentityPub,
    pub addrs: Vec<String>,  // multiaddrs
}
```

**Security:** `PeerDiscoveryRequest` — отвечает **любому authenticated connection** (handshake достаточен). Peer list не секрет в P2P сети. Работает и для DR (old peer), и для first bootstrap (new node).

---

## 2. Что протокол НЕ определяет (рекомендации реализации)

Следующие параметры — рекомендуемые значения, не требования совместимости.

| Параметр | Рекомендация | Обоснование |
|----------|-------------|-------------|
| Trust formula | `(KP×P + KI×I) × clamp(S, 0.1, 1.0)` | Эксперименты exp.01-27 |
| KP, KI | `KP=0.4, KI=1.75` | Баланс реактивность vs стабильность |
| Overhead | `1.5 + importance × 1.5` | 99.9% reliability при K=2048 |
| PoS frequency | adaptive (см. 1.4) | Пропорционально volume и trust |
| Partner selection | weighted by trust | Bias к надёжным |
| Holder eviction priority | `importance × trust × (1 + age_bonus)` | Сохранять важные и старые |
| Source block size | 128 МБ | Peak RAM ~250 МБ |
| Block size (weak hw) | 32 МБ | Peak RAM ~65 МБ |
| Vacuum threshold | >50% invalid files | `VACUUM_INVALID_THRESHOLD = 0.5` |
| Max file versions | 5 | `DEFAULT_MAX_VERSIONS = 5` |
| Max version age | 90 дней | `DEFAULT_MAX_VERSION_AGE_SECS` |
| Disk reserve | 20 GB | `DEFAULT_DISK_RESERVE_BYTES` |

---

## 3. Жизненный цикл

### 3.1. Bootstrap (первый запуск)

```
1. Пользователь вводит seed phrase (24 слова BIP39)
2. derive_master_key(seed) → master signing key
3. derive_device_key(seed, device_seed) → device signing key → сохранить
4. device_id = DeviceId(device_signing_key.verifying_key().to_bytes())  // 32 bytes Ed25519 pubkey
5. derive_epoch_key(seed, epoch=0) → epoch_key[0] → сохранить
6. Стереть seed phrase из RAM
7. issue_device_certificate(master_key, device_id, now) → сохранить cert
8. ClusterState::init(db, master_pub, first_device_cert, ...)
9. PeerAnnounce через relay board: "я существую, мой NodeId = ..."
10. Bootstrap auto-connect: connect to bootstrap peers → PeerDiscoveryRequest → learn peer list (1-hop)
```

### 3.2. Нормальная работа

```
Watcher: fs event → debounce 30 мин → dirty_files

Packing queue (per file category):
  Flush если: ≥ 256 МБ накопилось
           OR 1 час idle
           OR 24 часа fallback
  Min batch: 1 МБ

Backup flow (per source block):
  1. Dedup check: content_hash уже забекаплен? → skip
  2. compress (zstd) + encrypt (ChaCha20-Poly1305 с epoch_key)
  3. source_block_id = BLAKE3(ciphertext)
  4. ErasureParams::compute(block_size, importance) → K, K_eff, N
  5. SymbolBudgetEngine: distribute N symbols among holders
  6. Per holder: generate symbols, apply per-holder binding, send via SymbolOffer/Transfer
  7. SymbolStored получен → PlacementStatus → Alive

PoS: adaptive scheduler
  picks random ESI from holder's esi_ranges
  → PosChallengeMsg (direct или via relay)
  → verify PosResponse, update trust + PlacementStatus

Repair (triggered by PresumedLost / Lost):
  File on disk → generate new symbols (new ESIs) → place at new holder
  File not on disk → collect K_eff symbols → unbind → decode → new symbols
```

### 3.3. Restore

```
viaticum restore <path> [--version N] [--date YYYY-MM-DD]

1. DB lookup: path → FileRecord → FileVersion
2. FileVersion → source_block_id
3. Dedup: multiple files in same batch → один download
4. Per source_block:
   a. Find holders: SymbolPlacement WHERE status=Alive
   b. Escrow check: `remaining = stored_gb_days/k_factor - already_restored_gb` достаточен?
   c. RestoreRequest к K_eff holders параллельно
   d. Collect K_eff bound symbols (любые ESI)
   e. Unbind: XOR ChaCha20(HKDF(block_id, holder_id))
   f. RaptorQ decode → ciphertext
   g. decrypt (epoch_key) → decompress → plaintext
5. Pack → PackIndex → extract files по offset+size
6. Write to disk, FileRecord.local_state → Present
```

Выбор версии:
- `--version N`: конкретная (0 = самая старая, -1 или default = последняя)
- `--date D`: ближайшая версия ≤ D

### 3.4. Disaster recovery

```
Все устройства потеряны, остался только seed phrase:

viaticum dr --mnemonic "24 words" --peer <addr>

1. Derive identity from seed → IdentityPub
2. Open fresh DB (remove stale db.redb if any)
3. Start minimal SwarmHandle (libp2p, no Processor)
4. BFS over peers:
   - Connect to seed --peer addresses
   - Send SystemStateRequest → collect encrypted DB snapshots
   - Send PeerDiscoveryRequest → discover more peers (visited set)
   - Limits: 500 peers, 10 blobs, 120s timeout
5. Select freshest blob (max created_at)
6. Decrypt (ChaCha20-Poly1305 with HKDF-derived key from seed)
7. Restore DB: files, source blocks, placements, peers, pos_weekly, cluster_state
8. "Run viaticum daemon, then viaticum restore <path>"

DB snapshots pushed periodically (6h) by daemon → SystemStateBackup → peers store one blob per owner (TTL 365 days).
```

### 3.5. File deletion

```
Watcher: файл удалён → FileRecord.local_state = Deleted(timestamp)

Каталог бекапа независим от файловой системы.
Файл на диске удалён ≠ бекап удалён.

Cleanup:
  owner 4 недели cooldown → DeleteMsg → holders
  holders 4 недели cooldown → физическое удаление

Multi-device: cooldown начинается только когда ВСЕ устройства пометили Deleted.
```

---

## 4. Устойчивость к атакам

### 4.1. Collusion attack (K holders хранят 1 копию)

**Атака:** K colluding holders хранят вместе одну копию файла, а PoS проходят через regenerate on demand.

**Защита:** Per-holder binding обязателен.

```
stored_symbol[holder_A] = symbol XOR ChaCha20(HKDF(block_id, holder_A))
stored_symbol[holder_B] = symbol XOR ChaCha20(HKDF(block_id, holder_B))
```

Symbols у A и B различаются → дедупликация невозможна. Каждый holder обязан хранить уникальную версию.

### 4.2. Hit-and-run (взял символы, не отдал)

**Атака:** peer принимает символы для хранения (S-score растёт), но ничего не хранит для других.

**Защита:** Escrow (trust-based).

- Trust = 0 → max 1 GB restore
- Нет взаимного хранения → S-score → 0 → trust → 0 → escrow → пусто

### 4.3. Lazy deletion (ransomware)

**Атака:** владелец скомпрометирован, злоумышленник удаляет все файлы.

**Защита:** Двойной cooldown 4+4 недели.

- Owner side: `OWNER_DELETE_COOLDOWN_SECS = 4 × SECS_PER_WEEK`
- Holder side: `HOLDER_DELETE_COOLDOWN_SECS = 4 × SECS_PER_WEEK`

За 8 недель владелец должен заметить удаление и отозвать через `CancelDeleteMsg`.

### 4.4. Sybil attack (много фальшивых нод)

**Частичная защита:**

- Trust требует реального хранения (S-score) — Sybil нода без диска имеет trust ≈ 0
- Placement: `weight = trust / sqrt(1-trust)` — нулевой trust = нулевой вес
- Soft geo-hint (не в β): снизить вес однородных subnet кластеров

Полной защиты нет: VPN/VPS может симулировать гео-разнообразие. Для cold backup приемлемо.

### 4.5. Replay attack (старые сообщения)

- Handshake: `HANDSHAKE_FRESHNESS_SECS = 300`
- PoS: `challenge_id = [u8; 16]` — случайный nonce, ответ матчится по challenge_id
- Relay entries: `created_at + TTL <= now → expired`

### 4.6. Кража устройства

- Revoke device key → партнёры получают `RevocationBroadcast` через gossip
- Новый epoch → новые файлы зашифрованы ключом которого нет на краденом устройстве
- Старые файлы: партнёры блокируют restore для revoked device key
- Owner постепенно re-encrypt старых файлов

Threat model: "lazy not malicious". Для активного противника (`epoch_key` скомпрометирован до ротации) re-encryption нужна немедленно.

---

## Приложение A: Сводная таблица констант

| Константа | Значение | Описание |
|-----------|----------|----------|
| `SYMBOL_SIZE` (T) | 65_535 байт | Размер символа (u16 max) |
| `DEFAULT_SOURCE_BLOCK_SIZE` | 128 МБ | Source block по умолчанию |
| `DECODE_OVERHEAD` | 3 | K_eff = K + 3 |
| `OVERHEAD_BASE` | 1.5 | Минимальный overhead (importance=0) |
| `OVERHEAD_SCALE` | 1.5 | Диапазон: 1.5x..3.0x |
| `MAX_HOLDERS_PER_BLOCK` | 30 | Holders per source block |
| `MIN_SYMBOLS_PER_HOLDER` | 32 | Минимум символов у holder'а |
| `CONCENTRATION_CAP_FACTOR` | 0.85 | cap = (1-1/overhead) × 0.85 |
| `POS_TIMEOUT_SECS` | 604_800 (7 дней) | Таймаут PoS |
| `POS_BASE_CHALLENGES_PER_WEEK` | 1 | Базовая частота PoS |
| `POS_VOLUME_DIVISOR` | 1000 | volume_factor = ceil(symbols/1000) |
| `POS_CONSECUTIVE_MISS_UNCERTAIN` | 1 | Misses до Uncertain |
| `POS_CONSECUTIVE_MISS_PRESUMED_LOST` | 3 | Misses до PresumedLost |
| `OWNER_DELETE_COOLDOWN_SECS` | 2_419_200 (4 нед.) | Owner cooldown перед delete |
| `HOLDER_DELETE_COOLDOWN_SECS` | 2_419_200 (4 нед.) | Holder cooldown после delete |
| `DROP_NOTICE_WINDOW_SECS` | 604_800 (7 дней) | Advance notice перед drop |
| `DEFAULT_ESCROW_K_FACTOR` | 7.0 | Дней хранения на 1 GB restore |
| `MAX_RELAY_HOP` | 2 | Максимум хопов в relay |
| `RELAY_TTL_SECS` | 604_800 (7 дней) | TTL relay записей |
| `MAX_BOARD_ENTRIES` | 2000 | Записей на relay board |
| `MAX_BOARD_SIZE_BYTES` | 8 МБ | Размер relay board |
| `MAX_MESSAGE_SIZE` | 128 МБ | Максимальный фрейм |
| `PROTOCOL_VERSION` | 1 | Версия протокола |
| `ALPN` | `b"viaticum/1"` | ALPN идентификатор |
| `SYSTEM_STATE_TTL_SECS` | 31_536_000 (365 дней) | TTL stored system state blobs |
| `HANDSHAKE_FRESHNESS_SECS` | 300 | Окно свежести handshake (±5 мин) |
| `KP` | 0.4 | Вес P в trust формуле |
| `KI` | 1.75 | Вес I в trust формуле |
| `S_CLAMP_MIN` | 0.1 | Минимум S в trust формуле |
| `S_CLAMP_MAX` | 1.0 | Максимум S |
| `DEBOUNCE_SECS` | 1_800 (30 мин) | Debounce fs events |
| `FLUSH_IDLE_SECS` | 3_600 (1 час) | Flush при idle |
| `FLUSH_FALLBACK_SECS` | 86_400 (24 часа) | Fallback flush |
| `MIN_BATCH_BYTES` | 1 МБ | Минимальный размер пачки |
| `DEFAULT_MAX_VERSIONS` | 5 | Версий на файл |
| `DEFAULT_MAX_VERSION_AGE_SECS` | 7_776_000 (90 дней) | Возраст старых версий |
| `VACUUM_INVALID_THRESHOLD` | 0.5 (50%) | Порог vacuum |
| `DEFAULT_DISK_RESERVE_BYTES` | 20 ГБ | Резерв диска |

---

## Приложение B: DB схема (краткая)

```
HOT (RAM, ~13 МБ для 5 ТБ):
  source_block_id → BlockAgg { k, total_alive_symbols }
  (source_block_id, holder_id) → PlacementAgg { symbol_count, status, last_pos }

WARM (redb):
  FileRecord    { file_id, path, importance, devices, versions, first_seen }
  FileVersion   { content_hash, source_block_id, k, t, created_at, backed_up_at }
  SourceBlockRecord { block_id, k, t, block_type, status, created_at, encrypted_size }
  SymbolPlacement   { source_block_id, holder_id, file_id, esi_ranges,
                      binding_seed, status, last_verified, placed_at, consecutive_misses }
  HoldingRecord { source_block_id, owner_id, esi_ranges, importance, total_bytes,
                  status, received_at, delete_requested_at, drop_notice_sent_at }
  PeerRecord    { identity, trust_p, trust_i, trust_s,
                  bytes_we_store_for_peer, bytes_peer_stores_for_us,
                  first_seen, last_seen, device_id, revoked_device_pub_keys, addrs, x25519_pub }
  BudgetRecord  { estimated_gb, last_calculated, placement_success_rate, weekly_stats }
  EventLog (append-only): Vec<(seq: u64, EventEntry)>
  Indices: file→holders, holder→files (двойной индекс)
  ClusterState (singleton): StoredClusterState
  SystemStateBlobRecord { owner, encrypted_blob, created_at, stored_at } — 1 per owner, TTL 365d
```

Values = CBOR (`ciborium`). DB = `Arc<redb::Database>`.

Преимущество vs α: ~3.4 МБ на 1000 файлов против ~50 МБ (15x меньше). Fungible символы → агрегаты вместо записей на каждый символ.

---

## Приложение C: Отличия β от α

| | α (архив) | β (текущее) |
|--|-----------|-------------|
| Erasure | Reed-Solomon | RaptorQ (RFC 6330) |
| Единица хранения | Shard (фиксированный индекс) | Symbol (fungible, ESI) |
| Единица кодирования | Unit (32 МБ) | Source block (128 МБ default, configurable) |
| Placement | k-of-n fixed | Weighted budget (trust/sqrt(1-t)) |
| Overhead | Фиксированный k/n | Continuous: 1.5 + importance × 1.5 |
| Escrow | Временной (weeks_in_network) | Trust-based (FREE_TIER + trust × factor) |
| DB metadata | ~50 МБ/1000 файлов | ~3.4 МБ/1000 файлов (15x меньше) |
| Multi-device | Нет | Personal Cluster, device certs |
| PoS | Stub | Реальный (64 KB response + on-the-fly verify) |
| PoS не держит | Молчание | PosNack (явный ответ) |
| Repair | Базовый | Graduated (Uncertain→PresumedLost), NotHeld→немедленный |
| Relay | Нет | Epidemic relay (hop≤2, TTL 7d) |
| Dedup | Нет | Content-addressed (same hash → zero traffic) |
| Backup trigger | Раз в неделю | Event-driven + flush conditions |
| File versioning | Нет | Vec\<FileVersion\>, restore by version/date |
