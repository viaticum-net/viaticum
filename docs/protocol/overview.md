# SyncBack: описание протокола

*Март 2026 · v0.2 draft*

---

## Что такое SyncBack

Децентрализованная P2P система холодного бекапа. Участники сети хранят зашифрованные фрагменты данных друг друга. Нет сервера, нет токенов, нет блокчейна.

"Холодный бекап" означает: временная константа = 1 неделя. Restore за дни, не секунды. Это радикально упрощает все инженерные проблемы: churn, repair storm, NAT traversal, bandwidth.

---

## 0. Technology stack

SyncBack — тонкая обёртка над существующими технологиями. Единственная оригинальная часть — протокол доверия.

### Архитектура: ядро + сменный транспорт

```
┌──────────────────────────────┐
│  SyncBack core               │  ← наше: identity, trust, escrow,
│  (identity + reputation +    │     PoS, placement
│   shard management)          │
├──────────────────────────────┤
│  Transport abstraction       │  ← trait: send_message,
│                              │     transfer_blob, sync_mailbox
├──────────┬───────────────────┤
│  iroh    │  (другие адаптеры │  ← реализации
│  adapter │   в будущем)      │
└──────────┴───────────────────┘
```

Протокол НЕ привязан к конкретному транспорту. Ядро SyncBack (identity, trust state, PoS logic) переносимо на любой P2P стек. Transport adapter — сменный модуль.

### Reference implementation: iroh

[iroh](https://iroh.computer) (Rust, n0-computer) — P2P networking stack:

- **iroh core** — QUIC соединения, NAT traversal (hole punching), relay через WSS:443
- **iroh-blobs** — content-addressed передача данных (BLAKE3 verified streaming)
- **iroh-docs** — replicated key-value documents (range-based set reconciliation)

Приоритет транспортов:
1. **QUIC/UDP direct** — где работает (большинство мира)
2. **iroh relay (WebSocket/TLS:443)** — где UDP заблокирован (выглядит как HTTPS)
3. **Self-hosted relay** — где зарубежный трафик режут

**Важно:** `identity_pub` (Ed25519, наш) ≠ `iroh NodeId` (их). Identity — "кто ты". NodeId — "как подключиться". Оба деривируются из seed phrase детерминированно. Маппинг публикуется через peer_announce. При смене транспорта identity и trust сохраняются.

### Шифрование данных: ChaCha20-Poly1305

Файлы шифруются до erasure coding. Ключ шифрования деривируется из identity. Holder не может прочитать содержимое шарда.

### Erasure coding: Reed-Solomon

Файл разбивается на k частей, кодируется в n шардов. Для восстановления достаточно любых k из n.

### Что пишем сами

- Trust protocol (P, I, S — локальная оценка партнёров)
- Escrow logic (право holder'а на отказ в выдаче)
- Shard placement strategy (weighted, adaptive n)
- Proof-of-Storage challenge-response logic
- Gossip relay rules (что копировать, TTL, rate limits)

---

## 0.1. Wire format

### Сериализация: CBOR (RFC 8949)

Все сообщения протокола сериализуются в CBOR — компактный самоописывающийся бинарный формат. Rust: `ciborium` (serde-совместимый).

Почему CBOR:
- Самоописывающийся — можно инспектировать без схемы (отладка)
- RFC стандарт, не привязан к компании или языку
- Компактный бинарный формат (~110 байт на handshake, ~200 байт на shard_offer)
- Версионирование бесплатно: новые поля игнорируются старыми нодами

### Framing

**Прямое соединение (ALPN `"syncback/1"`):**

```
[u32 BE длина][CBOR payload][u32 BE длина][CBOR payload]...
```

Каждое сообщение = 4 байта длины (big-endian) + CBOR bytes. Максимальный размер одного сообщения: 64 МБ (inline shard transfer в альфе, MAX_MESSAGE_SIZE). Стрим открывается поверх QUIC-соединения iroh.

**API дисциплина:** В коде ОБЯЗАТЕЛЬНО различать `frame_message()` (CBOR + u32 BE prefix = wire-ready) и `to_cbor()` (голый CBOR, для вложенных payload'ов). Если отправить голый CBOR в сокет, получатель прочитает первые 4 байта CBOR-header как length prefix и получит мусор (например, 0xA2626964 = 2.7 ГБ "длина"). Публичный API для отправки по сети — только `frame_message()`.

**Записи на доске (iroh-docs):**

```
key:   "{type}/{msg_id}"        (UTF-8 строка)
value: CBOR bytes               (opaque для iroh, интерпретируется SyncBack)
```

iroh-docs хранит и синхронизирует записи. SyncBack читает value и десериализует из CBOR.

### Версионирование протокола

```
Уровень 1 — транспорт (мажорная версия):
  ALPN: "syncback/1"
  При ломающих изменениях → "syncback/2"
  Нода может поддерживать несколько ALPN одновременно

Уровень 2 — сообщение (минорные изменения):
  Каждое CBOR-сообщение содержит поле "v": 1
  Новые optional поля — старые ноды игнорируют неизвестное
  Убрать обязательное поле — только при смене ALPN
```

### Пример: HandshakeMsg

```cbor
{
  "type": "handshake",
  "v": 1,
  "identity_pub": h'<32 bytes>',
  "timestamp": 1741689600,
  "sig_author": h'<64 bytes>'
}
→ ~110 байт
```

### Пример: directed запись на доске

```cbor
{
  "type": "shard_offer",
  "v": 1,
  "kind": "directed",
  "target_pub": h'<32 bytes>',
  "payload": h'<encrypted CBOR>',
  "sig_author": h'<64 bytes>'
}
→ ~250 байт (зависит от ShardDescriptor)
```

---

## 1. Что определяет протокол (enforceable)

Протокол определяет **формат сообщений** и **правила верификации** — то, что каждая нода может проверить у других. Протокол НЕ определяет, как нода принимает решения внутри себя.

### 1.1. Identity

- Каждый участник = пара ключей (Ed25519): `identity_pub`, `identity_priv`
- Identity создаётся из seed phrase (BIP39 или аналог)
- Все сообщения подписаны `identity_priv`
- `identity_pub` ≠ iroh `NodeId`. Identity — "кто ты". NodeId — "как подключиться". Маппинг публикуется через `peer_announce` (подписан identity).
- Personal Cluster (experimental): несколько устройств с derived device keys от одного master key. Протокол видит кластер как одну identity.

**Аутентификация (handshake):**

Handshake нужен при прямом соединении через iroh (передача blob'ов: restore, shard upload). Для досок handshake не нужен — записи аутентифицируются подписями.

```
A                                    B
|                                    |
|--- iroh connect(B_NodeId) -------->|   QUIC + TLS, канал зашифрован
|                                    |   iroh гарантирует NodeId обеих сторон
|                                    |
|--- stream ALPN "syncback/1" ----->|   открываем SyncBack протокол
|                                    |   поверх QUIC соединения
|                                    |
|--- HandshakeMsg --------------->|   первое сообщение:
|    { identity_pub_A,               |   { identity_pub, timestamp,
|      timestamp,                    |     sig(identity_priv, "handshake"
|      sig_A }                       |         + identity_pub + timestamp) }
|                                    |
|                                    |   B проверяет: sig валидна?
|                                    |   B ищет: identity_pub_A в peer directory?
|                                    |
|<--- HandshakeMsg ------------------|   второе сообщение (аналогичное)
|    { identity_pub_B,               |
|      timestamp,                    |
|      sig_B }                       |
|                                    |
|   A проверяет sig_B                |
|                                    |
|======= AUTHENTICATED =============|
|                                    |
|--- blob requests, commands ------->|   теперь B знает кто просит
|<--- blob data ---------------------|   и может проверить escrow
```

Проверки при получении HandshakeMsg:
1. `sig` валидна для заявленного `identity_pub`
2. `timestamp` свежий (±5 минут) — защита от replay
3. `identity_pub` известен (есть в peer directory или allowlist)

Seed nodes принимают handshake от любых identity (роль bootstrap). Обычные ноды — только от известных.

Handshake — ~100 байт в каждую сторону, один раз при подключении. После аутентификации стрим используется для команд и blob transfer.

### 1.2. Units и erasure coding

**Два правила обработки файлов:**

```
Unit size = U (default 256 МБ, конфигурируемо)

Файл < U  → pack с другими мелкими в unit размером ~U
Файл ≥ U  → split на chunks по U, каждый chunk = отдельный unit
```

Каждый unit → шифрование (ChaCha20-Poly1305, ключ из identity) → erasure coding (Reed-Solomon, k-of-n) → n шардов.

- Для восстановления достаточно любых k из n шардов
- Параметры k и n — решение владельца файла, не протокола
- Каждый шард = iroh blob (идентифицируется BLAKE3 hash)
- Метаданные шарда описываются подписанной структурой **ShardDescriptor**

**ShardDescriptor (подписан owner'ом):**

```
ShardDescriptor {
    shard_id:     BLAKE3 hash содержимого шарда
    unit_id:      ID unit'а (encryption scope)
    shard_index:  номер шарда в RS-наборе (0..n-1)
    k:            минимум шардов для восстановления
    n:            общее количество шардов
    merkle_root:  корень BLAKE3 merkle tree (для PoS)
                  Размер блока для Merkle tree: 64 КБ.
                  Шард ~17 МБ → ~260 листьев в дереве.
    owner_pub:    Ed25519 public key владельца
    importance:   0.0–1.0 (приоритет хранения)
    file_type:    "user" | "system" (для system state backup, см. §1.9)
    created_at:   timestamp создания
    sig_owner:    Ed25519 подпись всех полей выше
}
```

Holder ОБЯЗАН проверить при получении шарда:
1. `sig_owner` валидна для `owner_pub`
2. `blake3(blob_content) == shard_id`
3. `owner_pub` в allowlist (партнёр или сосед партнёра)

Без валидного ShardDescriptor шард отклоняется. Это защита от подброса чужих шардов: атакующий не может создать валидный descriptor для чужого `owner_pub`.

**Pack:** несколько мелких файлов объединяются в один unit с индексом (offset + size каждого файла). Один файл изменился → перепаковать unit.

**Chunks:** большой файл разбивается на units. Один chunk изменился → пересоздать только его шарды.

**Объёмы (типичный пользователь, 500 ГБ):**

```
500 ГБ / 256 МБ ≈ 2,000 units × 15 шардов = 30,000 шардов
Размер шарда: ~51 МБ (256 МБ / 5)
Метаданные: ~6 МБ
```

### 1.3. Proof-of-Storage (challenge-response)

Единственный механизм верификации, который протокол ОБЯЗЫВАЕТ поддерживать:

```
1. Challenger → Holder:
   {challenge_id, unit_id, shard_index, block_range, nonce, timestamp, sig_challenger}

2. Holder → Challenger:
   {challenge_id, block_data_hash, merkle_proof, timestamp, sig_holder}

3. Challenger верифицирует:
   - подпись holder валидна
   - merkle_proof соответствует сохранённому merkle_root
   - block_data_hash корректен для запрошенного block_range + nonce
   - ответ получен в пределах TTL (7 дней)
```

- Доставка через gossip relay (см. 1.5), не требует одновременного online
- Результат проверки (pass/fail) — локальное знание challenger'а
- **TTL записи на доске (7 дней) = естественный deadline для PoS response.** Если за 7 дней response не появился на доске holder'а — fail.

**Sampling PoS:** при большом количестве шардов проверять все каждую неделю нереально. Вместо этого — случайная выборка N шардов на партнёра в неделю (рекомендация: 5). Нам важна надёжность партнёра, а не статус конкретного шарда.

```
50 партнёров × 5 challenges/week = 250 сообщений/week ≈ 50 КБ
```

**Вероятность обнаружения мухлежа** (5 проверок/week, 4 недели):
- Удалил 1% шардов → 18% обнаружение
- Удалил 10% → 88%
- Удалил 50% → 99.9999%

**Реакция на failed challenge:**

| Ситуация | Интерпретация | Действие |
|---|---|---|
| 1 fail на 1 шарде | Bit rot / случайность | Repair этого шарда, повторная проверка + `storage_warning` |
| 2+ fails на разных шардах | Враждебное поведение | Trust → 0, убрать ВСЕ шарды с партнёра, repair |
| Нет ответа (timeout 7d) | Партнёр офлайн | P снижается, но не наказание |

**Наказание за мухлёж: потеря всех отношений.** Пойман на одном — теряет все shard relationships с этим owner'ом. Если партнёр хранит 1000 наших шардов → теряет 1000 holders для своих данных. EV мухлежа глубоко отрицательный.

**Storage warning (уведомление "проверь диск"):**

```
Challenger → Holder (directed, зашифровано):
  storage_warning { shard_id, details, ts }
```

При 1 failed challenge — challenger отправляет holder'у предупреждение: "шард повреждён, возможно bit rot, проверь диск". Holder может:
- Запустить selfcheck всех хранимых шардов
- Проверить SMART-состояние диска
- Уведомить пользователя

Это не наказание, а помощь: bit rot — общая проблема, и партнёр может не знать о ней.

### 1.4. Subnet rate-limiting

Протокол РЕКОМЕНДУЕТ (но не может энфорсить без центра):

- Не более 1 шарда одного файла на пиры из одной /24-подсети
- Не более 2 шардов одного файла на пиры из одного ASN

Это anti-Sybil мера. Каждая нода применяет это правило самостоятельно при размещении СВОИХ шардов. Нода не может заставить другие ноды следовать этому правилу.

### 1.5. Доска объявлений (gossip relay)

Каждая нода = одна iroh-doc = открытая доска.

**Модель:**

- Запись: только хозяин доски (у него write key)
- Чтение: любой партнёр (subscribe по read-only ticket)
- Два типа записей: **broadcast** (видны всем) и **directed** (зашифрованы для конкретного получателя)

**Шифрование directed-записей:**

Если у записи есть конкретный получатель — payload шифруется ECDH:

```
shared_key = X25519(sender_priv, receiver_pub)
encrypted_payload = ChaCha20-Poly1305(payload, shared_key, nonce)
```

Только получатель может расшифровать. Relay-ноды копируют не читая.

**Единый формат записи:**

```
{type}/{msg_id} → {
    kind:          "broadcast" | "directed"
    target_pub:    Ed25519 pub получателя (только для directed)
    payload:       открытый (broadcast) или зашифрованный (directed)
    sig_author:    Ed25519 подпись (type + msg_id + kind + target_pub + payload)
}
```

**Типы записей:**

```
BROADCAST (видны всем):
  peer_announce/{msg_id}    → {identity_pub, node_addr, ts}

DIRECTED (зашифрованы для получателя):
  pos_challenge/{msg_id}    → target: holder   | {shard_id, block_range, nonce, ts}
  pos_response/{msg_id}     → target: challenger | {challenge_id, hash, merkle_proof, ts}
  shard_offer/{msg_id}      → target: holder   | {ShardDescriptor, ts}
  shard_accept/{msg_id}     → target: owner    | {shard_id, offer_msg_id, ts}
  shard_reject/{msg_id}     → target: owner    | {shard_id, offer_msg_id, reason, ts}
  shard_stored/{msg_id}     → target: owner    | {shard_id, ts}
  delete/{msg_id}           → target: holder   | {shard_id, ts}
  cancel_delete/{msg_id}    → target: holder   | {shard_id, ts}
  storage_warning/{msg_id}  → target: holder   | {shard_id, details, ts}
  shard_dropped/{msg_id}    → target: owner    | {shard_id, ts}
  shard_drop_notice/{msg_id}   → target: owner    | {shard_id, deadline (absolute unix ts), ts}
  restore_denied/{msg_id}   → target: owner    | {shard_id, reason, required_weeks, current_weeks}

RELAY (копия чужой записи, формат сохраняется):
  relay/{author}/{msg_id}   → копия, kind/target/payload/sig не меняются, hop увеличивается

Поле hop: u8 присутствует в каждой relay-записи:
  Оригинальная запись на доске автора: hop = 0
  При копировании чужой записи к себе: hop = original.hop + 1
  Если hop >= 2 → не копировать далее
```

**Почему шифруем:** без шифрования shard_offer виден всем партнёрам (shard_id, importance, кто куда кладёт). Атаки: спам-accepts на чужие offers, нецелевой pull blob'ов, корреляция трафика. С шифрованием наблюдатель видит только `A → B: [encrypted]`.

**Relay (полу-эпидемик):**

Нода читает доски партнёров, копирует записи к себе → её партнёры видят их при синке:

```
hop 0: мои записи (я автор)
hop 1: записи моих партнёров (копирую из их досок)
hop 2: записи партнёров моих партнёров
hop 3+: не копирую
```

Dedup по msg_id (уже есть → не копировать). Каждая запись подписана оригинальным автором — relay не может подделать. Relay-нода не может прочитать directed payload, но может его скопировать.

**Как считаются hops:** нода знает, из чьей доски пришла запись. Если author == доска, то hop 0 (оригинал). Если запись пришла из чужой доски, а author != владелец доски, то это relay (hop +1). Нода копирует записи только от прямых партнёров (hop 0→1) и из relay-секций их досок (hop 1→2). Записи из `relay/` с автором, который находится на hop ≥ 2 от нас, не копируются.

**Ограничения доски:**

- TTL = 7 дней. Записи старше TTL удаляются.
- Max entries: ~2000 записей на доску
- Max size: 8 МБ на доску
- При переполнении → drop oldest

**Объём трафика (50 партнёров):**

```
hop 0: ~20 записей/week (мои PoS challenges + announces + offers)
hop 1: ~1000 записей/week (50 партнёров × 20)
hop 2: ~1500 записей/week (с пересечениями)
Итого: ~2000 записей × 300 байт ≈ 600 КБ/week
```

**Почему iroh-docs:** range-based set reconciliation эффективно синхронизирует только новые записи. Store-and-forward бесплатно (данные на диске). Dedup по ключу.

**Минимальные требования к подключению:** нода принимает subscribe запросы только от пиров с минимальным trust. Seed nodes принимают от всех (роль bootstrap).

### 1.6. Peer discovery

Обнаружение партнёров — через те же доски объявлений.

**Bootstrap (первый запуск):**

```
1. syncback init → подключение к seed nodes (обычные ноды с высоким uptime)
2. Seed node видит нового peer → пишет peer_announce на свою доску
3. Другие ноды видят announce → подписываются на доску новичка
4. Новичок начинает получать shard_offer'ы
5. Новичок принимает шарды → начинает хранить → S растёт
```

Seed node — обычная нода без специальной роли. Единственная особенность: высокий uptime и принимает handshake от незнакомых identity. Hardcoded список seed nodes встроен в бинарник.

**Рост (нормальная работа):**

```
Партнёр A пишет peer_announce в свою доску: "рекомендую пира C"
  → мы синкаем доску A → видим рекомендацию → подключаемся к C
```

**Reconnect (после перерыва):**

```
NodeId партнёров в DB → iroh DNS/DHT discovery → найти текущий IP/relay → connect
```

**Disaster recovery:**

```
Seed phrase → derive identity keypair + iroh keypair (детерминированно)
  → NodeId восстановлен → iroh discovery работает
  → connect к seed nodes → партнёры узнают нас по identity_pub
  → system state recovery → полный restore
```

### 1.7. Shard placement и transfer

Передача данных — через **iroh-blobs** (content-addressed, BLAKE3 verified streaming). Размещение шардов использует **ask-then-push**: owner спрашивает через доску, holder скачивает blob после accept.

Все сообщения placement flow — directed (зашифрованы для получателя, см. §1.5). Сторонний наблюдатель не видит shard_id, importance, кто куда кладёт.

**Upload flow (ask-then-push):**

```
1. Owner выбирает n партнёров (weighted by trust)
   Budget Planner оценивает: хватит ли бюджета? (см. architecture.md)
   Если < K партнёров примут → skip, retry позже.

2. Owner → Holder (directed, зашифровано для holder'а):
     shard_offer { ShardDescriptor, ts }
     ShardDescriptor содержит shard_id (BLAKE3 hash blob'а)

3. Holder расшифровывает, проверяет:
     a) sig_owner в ShardDescriptor валидна          ← защита от подброса
     b) owner_pub в allowlist                        ← знаю ли owner'а?
     c) Оценка eviction_priority:
        - Есть место? → accept
        - Нет места, но priority нового > min? → accept (eviction при получении)
        - Не проходит? → reject

4. Holder → Owner (directed, зашифровано для owner'а):
     shard_accept { shard_id, offer_msg_id, ts }
     или
     shard_reject { shard_id, offer_msg_id, reason, ts }

5. При accept: Holder делает iroh-blobs pull(shard_id) от Owner'а.
   Оба должны быть онлайн (iroh relay помогает с NAT).

6. Holder проверяет полученный blob:
     blake3(blob) == shard_id из ShardDescriptor     ← защита от подмены
     Если не совпадает → удалить blob, отправить shard_reject { shard_id, reason: hash_mismatch }.

7. Holder ПОВТОРНО оценивает место (lazy reservation):
     - Место ещё есть → сохранить
     - Нет места, но eviction priority позволяет → вытеснить и сохранить
     - За время ожидания пришли более приоритетные данные → отклонить blob

8. Holder → Owner (directed):
     shard_stored { shard_id, ts }
     Owner видит при следующем sync → шард размещён ✓
```

**Holder state machine (offer→accept→blob→stored):**
```
shard_offer received
  → verify sig, check allowlist, check quota
  → Accept: СОХРАНИТЬ ShardDescriptor в памяти (pending_descriptors[shard_id])
  → отправить shard_accept

ShardData received (blob от owner)
  → lookup descriptor в pending_descriptors[shard_id]
  → verify blake3(blob) == shard_id
  → lazy reservation check (шаг 7)
  → записать blob на диск + HoldingRecord в DB
  → удалить из pending_descriptors
  → отправить shard_stored
```
Критично: holder ДОЛЖЕН хранить descriptor между accept и получением blob. Без него невозможно проверить hash и создать HoldingRecord. Потеря descriptor → blob отклоняется.

**ShardData — двунаправленный message type:**
- Upload flow: Owner → Holder (ShardData с blob'ом после shard_accept)
- Restore flow: Holder → Owner (ShardData с blob'ом после RestoreRequest)
Обработчик на получателе должен различать оба направления по наличию pending state (pending_descriptors для upload, pending_shard_to_restore для restore).

**Lazy reservation:** accept — мягкое намерение, не жёсткое бронирование. Holder НЕ вытесняет данные при accept. Eviction только в момент получения blob'а (шаг 7). Если owner не пришёл — ничего не потеряно.

**Таймауты:**
- Offer без ответа за 7 дней (TTL доски) → считается reject
- Blob download не завершён за 24ч connected time → abort, удалить partial
- Accept без blob за 7 дней → аннулирован

**Пакетные offers:** owner отправляет shard_offer нескольким партнёрам параллельно. Первые n shard_stored → размещение завершено. Оставшиеся accepts → ignore. Winner-takes-all: проигравшие holders не уведомляются. Accept автоматически аннулируется по TTL (7 дней).

**Restore flow (устройство живо, нужен файл):**

Restore — прямое соединение через iroh, не через доски. Скорость важна.

```
1. Local DB: file_id → current_unit_id → shard map → [(shard_id, holder_id), ...]
   Нужно k=5 из n шардов

2. Owner сортирует holders по trust (надёжные первые)
   Подключается напрямую через iroh (NAT traversal / relay)

3. Для каждого holder'а:
   Owner → iroh connect → запрос blob по shard_id
   Holder проверяет:
     a) ShardDescriptor.owner_pub == запрашивающий identity?
     b) Escrow: weeks_in_network owner'а достаточно для tier?
     c) Шард в состоянии active?
   → отдаёт blob, или отправляет restore_denied если escrow не пройден:
       restore_denied { shard_id, reason, required_weeks, current_weeks }
   Owner показывает пользователю "restore доступен через ~N недель" вместо retry

4. Holder офлайн → пропустить, следующий
   Набрали k → достаточно
   Набрали < k за сутки → подождать, попробовать позже

5. k шардов → Reed-Solomon decode → расшифровка (ChaCha20) → файл
```

**Disaster recovery (устройство потеряно, есть только seed phrase):**

```
Фаза 1 — Identity (минуты):
  seed phrase → deterministic key derivation:
    → identity keypair (Ed25519)
    → iroh keypair (NodeId)

Фаза 2 — Найти партнёров (минуты-часы):
  → connect к seed nodes (hardcoded)
  → seed nodes опрашивают сеть: "кто знает identity_pub X?"
  → owner получает список партнёров

Фаза 3 — System state (минуты):
  → system state шарды хранятся с max redundancy (5-of-25), max priority, TTL 5 лет
  → escrow проходит: weeks_in_network кумулятивный, не обнуляется при потере устройства
  → скачать k шардов system state → RS decode → расшифровка
  → получаем: file manifest, shard map, trust state, peer directory
  → нода знает ВСЁ

Фаза 4 — Файлы (дни):
  → обычный restore flow, приоритет по importance (документы → фото → видео)
  → ~30-50 ГБ/день → 500 ГБ за 10-14 дней

Фаза 5 — Полная функциональность (недели):
  → P восстановится за 4 недели (rolling window)
  → начинаем хранить чужие шарды → S-score растёт
  → нода полностью функциональна
```

**Escrow при disaster:** holder видит знакомый identity_pub, но P=0. Escrow проходит по `weeks_in_network` — этот счётчик кумулятивный и не обнуляется при потере устройства (identity сохраняется из seed phrase). Пользователь с годами в сети → weeks_in_network >> 26 → tier 3 проходит. Новичок → только demo credit (1 ГБ).

**Repair flow:**

```
1. PoS обнаружил: unit X имеет < n живых шардов (или shard_dropped от holder'а)
2. Owner скачивает k шардов от живых holders → восстанавливает unit
3. Пересоздаёт недостающие шарды → shard_offer новым партнёрам
```

### 1.8. Shard lifecycle messages

Протокол определяет два сообщения управления шардами. Оба — directed (зашифрованы для конкретного holder'а, см. §1.5).

**Delete request:**
```
Owner → Holder (directed):
  delete { shard_id, ts }
```

Owner сообщает holder'у что конкретный шард больше не нужен. Holder SHOULD удалить шард, но НЕ сразу — рекомендуется cooldown (см. 2.8). Это защита от ransomware: вирус может удалить файлы локально, но не может заставить holders немедленно удалить шарды.

При удалении файла owner отправляет delete для каждого шарда этого файла (все shard_id из unit'ов файла).

**Cancel delete:**
```
Owner → Holder (directed):
  cancel_delete { shard_id, ts }
```

Owner отменяет ранее отправленный delete. Если cooldown ещё не истёк — шард сохраняется. Сценарий: пользователь обнаружил ransomware, восстановил identity из seed phrase, отменил удаление.

**Три состояния шарда на holder'е:**

| Состояние | PoS приходит? | Delete msg? | Поведение holder'а |
|-----------|:---:|:---:|---|
| Active | Да | Нет | Хранить, высокий приоритет |
| Marked for delete | Да (cooldown) | Да | Хранить до истечения cooldown, потом удалить |
| Silent | Нет | Нет | Хранить; приоритет определяется owner's trust (см. 2.8) |

**Silent ≠ delete.** Молчание owner'а означает "что-то случилось" (потеря устройства, болезнь, тюрьма), а не "удали мои данные". Owner с высоким I-score (годы в сети) → holder хранит шарды пока может. Owner с низким I-score → holder дропает при нехватке места.

### 1.9. System state backup

Зашифрованный снимок состояния ноды, который сам бекапится в сеть как обычный файл. Необходим для disaster recovery.

**Содержимое:**

| Данные | ~Размер (формула) | Зачем |
|---|---|---|
| File manifest | files × ~100 Б | Какие файлы забекаплены: path, hash, k/n, encryption nonce |
| Shard map | shards × ~100 Б | shard_id → unit_id → holder_id (где что лежит) |
| Trust state | peers × ~100 Б | P/I/S на каждого партнёра |
| Peer directory | peers × ~100 Б | identity → last known node_id, subnet, last_seen |

```
Примеры:
  1K файлов, 50 партнёров:   ~100 КБ + 10 КБ ≈ 110 КБ
  100K файлов, 50 партнёров:  ~10 МБ + 10 КБ ≈ 10 МБ
  500K файлов, 50 партнёров:  ~50 МБ + 10 КБ ≈ 50 МБ
```

**Правила:**

- Зашифрован ключом из identity (как любой файл). Holder не может прочитать.
- Обновляется при каждом существенном изменении (новый файл, новый партнёр, weekly trust update).
- Максимальная redundancy (напр. 5-of-25).
- **Максимальный приоритет хранения.** Holder дропает system state shards последними (после всех пользовательских файлов). TTL = 5 лет с момента последнего обновления.
- Holder хранит только текущую версию (MVP).
- При disaster recovery: восстанавливается первым. После этого нода знает всё: файлы, партнёров, шарды, trust.

**Как holder отличает system state от обычного файла:**

Метаданные шарда содержат `file_type: "system"` (подписано owner'ом). Holder видит тип, но не содержимое.

### 1.10. Escrow (правила restore)

Протокол определяет механизм, параметры — решение реализации:

- **Upload:** всегда разрешён. Любой участник может разложить шарды в сеть.
- **Restore:** holder шарда МОЖЕТ отказать в выдаче, если owner не соответствует локальным критериям holder'а.
- Протокол гарантирует: holder не может прочитать содержимое шарда (зашифровано ключом owner'а). Holder может только хранить или удалить.

Escrow — это не запрет на уровне протокола. Это ПРАВО holder'а не отдавать шард. Каждый holder решает сам, по каким критериям отдавать. Рекомендуемая реализация: по `weeks_in_network` owner'а — сколько недель он в сети (см. §2.5). I-score (кумулятивные GB·days) — отдельная метрика для disaster recovery, не для escrow порогов.

---

## 2. Что НЕ определяет протокол (implementation)

Всё нижеперечисленное — рекомендации reference implementation. Каждая нода вольна использовать свои алгоритмы. Нода, использующая плохой алгоритм, навредит только себе (потеряет свои данные или будет исключена другими нодами).

### 2.1. Trust formula

Как нода оценивает партнёров — её личное дело. Рекомендуемая формула:

```
trust_AB = (kp × P_B + ki × I_B) × clamp(S_AB, 0.1, 1.0)
```

Но нода может:
- Использовать другие веса (kp, ki)
- Добавить свои компоненты
- Использовать ML/AI для оценки
- Вообще не считать trust и выбирать партнёров случайно

Единственное ограничение: нода, игнорирующая trust, будет размещать шарды на ненадёжных партнёрах и потеряет свои данные. Это самонаказание, не нарушение протокола.

**Bootstrap trust (INITIAL_TRUST_P):** Для нового пира P=0, I=0, S=1.0 → combined trust = 0. Placement фильтрует пиров с trust > 0.0, поэтому при P=0 ни один пир не проходит. Решение: `INITIAL_TRUST_P = 0.1` — "кредит доверия" для новых пиров. Combined = kp × 0.1 × 1.0 = 0.04 — ненулевой, но низкий. Без этого свежая сеть не может разместить ни одного шарда (chicken-and-egg problem).

### 2.2. Параметры erasure coding

Рекомендуемые defaults зависят от importance:

| importance | схема | overhead |
|---|---|---|
| ≥ 0.8 (критичные данные) | 5-of-15 | ×3.0 |
| ≥ 0.4 | 5-of-10 | ×2.0 |
| ≥ 0.1 | 5-of-7 | ×1.4 |

Поверх базовых параметров — adaptive n: `n_actual = n_base + extra(avg_trust)` для компенсации ненадёжных партнёров (см. §2.7).

Нода может выбрать 3-of-5 (меньше overhead, ниже надёжность) или 7-of-21 (больше overhead, выше надёжность). Это её данные, её решение.

### 2.3. Частота proof-of-storage

Рекомендация: 5 случайных шардов на партнёра в неделю (см. §1.3). Нода может проверять реже (2-3) или чаще — это влияет только на скорость обнаружения проблем.

### 2.4. Выбор партнёров

Количество партнёров не ограничено протоколом. Партнёрство (знакомство, обмен PoS) и хранение (размещение шардов) — разные вещи. Нода может знать сотни пиров, а шарды размещать на десятках лучших. Чем больше партнёров — тем лучше diversity (subnet, geography, timezone). Нода может выбирать партнёров по любому критерию: trust, geography, uptime, личное знакомство.

### 2.5. Escrow policy

Рекомендуемые пороги для отказа в выдаче шардов:
- Tier 1 (< 5 ГБ): после 4 недель в сети
- Tier 2 (< 50 ГБ): после 13 недель
- Tier 3 (> 50 ГБ): после 26 недель
- Первый 1 ГБ: бесплатный демо-кредит

Holder может отдать шард кому угодно и когда угодно. Или не отдать никому. Это его решение. Рекомендация — для устойчивости экономики сети.

### 2.6. Размещение шардов (weighted vs equal)

Рекомендация: weighted placement (больше шардов надёжным партнёрам, w_i = trust^2). Нода может раскладывать шарды равномерно или по любой другой схеме.

**MAX_SHARDS_PER_PARTNER = 6:** Один партнёр может хранить до 6 шардов одного юнита. Это позволяет работать при малом числе пиров: 4 пира × 6 слотов = 24 слота ≥ 17 (n при 5-of-17). Placement pool считает не уникальных пиров, а доступные слоты (capacity). При выборе каждый пир декрементирует свой capacity, а не удаляется из пула. Без этого при n > числа пиров placement невозможен — критичный edge case при малом числе пиров.

### 2.7. Adaptive n

Рекомендация: увеличивать n при низком среднем trust партнёров. Нода может использовать фиксированный n.

### 2.8. Holder storage policy

**Eviction priority** — единая формула для принятия решений о хранении:

```
eviction_priority = importance × trust_of_owner × (1 + age_bonus)
age_bonus = min(weeks_stored / 26, 0.3)   // до +30% за полгода хранения
```

- `importance` (0.0–1.0) — задаётся owner'ом, прикреплена к шарду (подписана)
- `trust_of_owner` — holder считает локально
- `age_bonus` — бонус за длительное хранение (гистерезис, защита от thrashing)
- **Hysteresis:** combined strategy (Exp 27). Threshold H=0.2 (новый шард должен быть на 20% приоритетнее) + time bonus +30% (старые шарды труднее вытеснить). Снижает evictions на 34%, data loss на 13%.

**Особые случаи (до формулы):**

```
1. Marked-for-delete + cooldown истёк     → удалить (owner сам попросил)
2. Silent + low I-score (< 4 weeks)       → вероятно ушёл навсегда, priority → 0
3. System state shards (file_type=system)  → max priority, TTL 5 лет
```

**Cooldown на delete (двойной барьер):** owner ждёт 4 недели после обнаружения удаления файла, прежде чем отправить delete сообщение. После получения delete holder ждёт ещё 4 недели перед фактическим удалением шарда. Итого: 8 недель от момента локального удаления до физического уничтожения шарда. Если за это время придёт cancel_delete — шард сохраняется. Два независимых барьера защищают от ransomware. **Cooldown применяется только к owner-requested delete, не к holder-initiated eviction.**

**Disk pressure management (holder-initiated eviction):**

Пользователь может в любой момент занять место на диске (скачать файл, установить программу). Daemon мониторит свободное место в рамках `storage_quota` — объёма, который пользователь выделил под чужие шарды в конфигурации. "Свободно" считается относительно storage_quota, не всего диска.

```
soft_threshold (< 15% от storage_quota свободно):
  → прекратить принимать новые shard_offer (shard_reject: "full")
  → уведомить пользователя: "квота заполняется, шарды под угрозой"

hard_threshold (< 5% от storage_quota свободно):
  → Фаза 1 (экстренная): немедленно удалить шарды с наименьшим
    eviction_priority до тех пор, пока свободное место в рамках квоты
    не вернётся к soft threshold (15%). Holder запрашивает trust_of_owner через
    Processor (TrustEngine) при каждом eviction. Trust не кешируется
    в holding-таблице — eviction редкая операция.
    → отправить shard_dropped каждому owner'у (directed, хороший тон)
    → без cooldown — это право holder'а на свой диск

  → Фаза 2 (плавная): пометить дополнительные шарды на удаление
    через 7 дней, чтобы создать буфер свободного места
    → отправить shard_drop_notice каждому owner'у (directed):
      "заберите в течение недели, потом удалю"
    → owner имеет время переразместить шард у другого партнёра
    → через 7 дней: удалить независимо от того, забрал owner или нет
    → результат: у holder'а снова есть буфер для следующей подобной ситуации
```

Пример: диск 600 ГБ, 500 ГБ шарды, 50 ГБ свои файлы, 50 ГБ свободно. Пользователь качает 90 ГБ:
1. Свободное место падает ниже hard_threshold
2. Фаза 1: немедленно удалить ~40 ГБ наименее ценных шардов → shard_dropped
3. Фаза 2: пометить ещё ~50 ГБ → shard_drop_notice (7 дней) → буфер
4. Owners получают уведомления, запускают repair/re-place
5. Через неделю: 540 ГБ занято, 60 ГБ свободно, буфер восстановлен

**Shard_dropped и shard_drop_notice — не требование протокола, а рекомендация.** Owner всё равно обнаружит потерю при следующем PoS (1-7 дней). Уведомление — хороший тон, ускоряет repair.

**Гейминг importance:** owner может завысить importance на всех файлах. Но это самонаказание: higher importance → higher n → больше RS overhead → больше хранилища потребляет → S-score падает → trust падает → priority падает.

**Trusted identities (allowlist):** holder может вручную пометить identities как trusted — их шарды не дропаются и не подлежат escrow. Use case: NAS помогает другу с бекапом.

### 2.9. File versioning

Рекомендация: при изменении файла локально — создать новый file_id, новые шарды. Старые шарды НЕ удалять немедленно (cooldown). При disaster recovery — восстанавливаются все доступные версии.

---

## 3. Жизненный цикл

```
УСТАНОВКА
  Seed phrase → identity keypair → готов к работе

BOOTSTRAP (неделя 1-4)
  → Seed nodes (hardcoded) → первые контакты → iroh-docs sync → находит партнёров
  → Начинает хранить чужие шарды (сразу полезен)
  → Свои данные: шифрование → erasure coding → размещение на партнёров (iroh-blobs)
  → Escrow: restore первого 1 ГБ бесплатно

НОРМАЛЬНАЯ РАБОТА
  → Еженедельно: PoS challenge-response через iroh-docs gossip
  → Партнёры уходят → repair (перераспределение шардов через iroh-blobs)
  → Новые партнёры появляются → постепенное расширение
  → Всё автоматически, невидимо для пользователя

RESTORE
  → Запрос k шардов у живых holder'ов (iroh-blobs download)
  → Reed-Solomon декодирование → расшифровка → исходный файл
  → Холодный: часы-дни, не секунды
```

---

## 4. Атакоустойчивость

| Атака | Защита | Уровень |
|-------|--------|---------|
| Sybil (фейковые ноды) | subnet rate-limit | реализация (самозащита) |
| Free-rider (не хранит) | PoS detection + trust | реализация (самозащита) |
| Spite (целенаправленный вред) | 5-of-15 + случайное распределение | erasure coding (протокол) |
| Mass departure | repair + erasure coding | протокол + реализация |
| Hit-and-run | escrow (право holder'а) | реализация |
| Storage lie | PoS challenge-response | протокол |
| Перехват данных | E2E encryption | протокол |
| Подделка сообщений | Ed25519 подписи | протокол |
| Message flood (DDoS) | rate limit + identity filter | протокол |

Ключевое разделение: **протокол** защищает целостность (подписи, шифрование, PoS). **Реализация** защищает экономику (trust, escrow, shard placement). Нода с плохой реализацией навредит себе, не другим.

### Message flood (DDoS сообщениями)

Атакующий пытается перегрузить ноду или сеть потоком сообщений: фейковые PoS challenges, мусорная "почта" для пересылки, исчерпание outbox storage.

**Вектора атаки:**

| Вектор | Цель | Стоимость для атакующего |
|--------|------|--------------------------|
| PoS challenge flood | CPU жертвы (проверка подписей) | 1 identity + bandwidth |
| Gossip spam | storage relay-нод (забить outbox) | N identities × 257 КБ |
| Sybil + flood | всё вышеперечисленное | N identities + N IP-адресов |

**Защиты на уровне протокола (enforceable):**

1. **Identity allowlist.** Нода принимает сообщения ТОЛЬКО от известных identities: свои партнёры + их соседи (до 2 hops). Сообщение от неизвестного identity → drop без проверки payload. Это первый фильтр, O(1) lookup.

2. **Rate limit per identity.** Максимум сообщений от одного identity:
   - PoS challenge: 1/неделю на файл
   - Gossip relay: 1 msg/peer/week
   - Превышение → drop + пометка identity как подозрительного

3. **Signature-first processing.** Подпись проверяется ДО чтения payload. Невалидная подпись → drop. Стоимость проверки Ed25519: ~50 мкс. Стоимость генерации для атакующего: ~50 мкс. Нет асимметрии — но rate limit делает массовую генерацию бесполезной.

4. **Outbox cap.** Gossip outbox ограничен (~8 МБ). При переполнении → drop oldest. Атакующий не может исчерпать storage relay-ноды.

5. **TTL = 7 дней.** Мусор самоочищается. Нет накопления.

**Почему Sybil + flood не работает:**

Атакующий создаёт 1000 identities и шлёт сообщения. Но:
- Identity allowlist: жертва принимает сообщения только от партнёров и их соседей. 1000 sybil-identities не попадут в этот круг, если не стали партнёрами.
- Чтобы стать партнёром → нужно время (I-score растёт неделями). Hit-and-run flood невозможен.
- Subnet rate-limit: 1000 нод из одной /24 → жертва видит их как 1 источник.

**Остаточный риск:** атакующий с доступом к множеству реальных подсетей (botnet), который становится легитимным партнёром и через недели начинает flood. Ущерб: повышенная нагрузка на CPU жертвы (~50 партнёров × 1 challenge/week = 50 проверок подписей/week — пренебрежимо). Атака экономически бессмысленна.

---

## 5. Что НЕ входит в v1

- Personal Cluster: синхронизация между устройствами (experimental, через iroh-docs или iroh-willow)
- Bootstrap: протокол обнаружения seed nodes (hardcoded list на старте)
- Версионирование файлов (append/update vs full replace)
- Bandwidth throttling / QoS
- Pluggable transports (Tor, BLE — когда iroh добавит)
