# Personal Cluster: проектирование

*2026-03-15. Статус: проектирование, нужно для реального старта (не post-MVP).*

---

## Зачем

Целевой пользователь через 1-3 года: ноутбук + десктоп, или ноутбук + NAS, или ноутбук → новый ноутбук. Одна identity, непрерывная репутация, один бекап без дублей.

Не file sync (это Syncthing). Это **backup identity continuity across devices**.

---

## Сценарии (по приоритету)

### MVP (нужно на старте)

1. **Новый ноутбук.** Пользователь купил новый. Вводит seed phrase → восстанавливает identity → видит свои бекапы → продолжает с того же места. Партнёры не замечают разницы.

2. **Ноутбук + десктоп.** Оба бекапят файлы. Фото есть на обоих → бекапятся один раз. Оба хранят чужие символы → общий S-score. Один оффлайн → второй отвечает на PoS.

3. **Кража устройства.** Отозвать device key с другого устройства. Заблокировать доступ к новым файлам. Партнёры отказывают в restore для revoked key.

### Post-MVP

4. **NAS как always-on.** NAS отвечает на PoS 24/7, делает repair автономно. Ноутбук может быть offline неделями.

5. **Trusted partner.** Друг получает delegated key — может делать repair, но не может читать файлы.

6. **Семейный кластер.** 2-3 человека, общий dashboard, раздельные файлы.

---

## Ключевые архитектурные вопросы

### 1. Key Hierarchy

```
Seed phrase (BIP39, 24 words)
│
├── Master identity key (Ed25519)
│   └── Используется для: подпись device certificates, derivation encryption keys
│
├── Device key 0 (Ed25519)
│   └── HKDF(seed, "syncback-device-ed25519", device_id)
│   └── Уникальный NodeId для iroh
│
├── Device key 1
│   └── HKDF(seed, "syncback-device-ed25519", device_id)
│
└── Encryption epoch key (ChaCha20)
    └── HKDF(seed, "syncback-encryption", epoch_counter)
    └── Ротируется при revocation
```

**Открытый вопрос: device_id**
- Вариант A: `device_id = hash(hardware_id)` — автоматически, но hardware_id может меняться
- Вариант B: `device_id = random` при первой инициализации на устройстве, сохраняется в `~/.syncback/device_id`
- Вариант C: `device_id = sequential_counter`, хранится в master state
- **Склоняюсь к B** — просто, надёжно, не зависит от железа

### 2. Encryption Epochs (ротация при краже)

**Проблема:** `file_key = HKDF(identity_priv, unit_id, ...)`. identity_priv на каждом устройстве → кража любого = доступ ко всем файлам.

**Решение: epoch-based encryption**

```
file_key = HKDF(epoch_key, unit_id, "syncback-file-encryption")
epoch_key = HKDF(seed, "syncback-encryption", epoch_counter)
```

- `epoch_counter` = монотонно растущее число, хранится в cluster state
- При revocation: `epoch_counter += 1` → новый `epoch_key`
- **Будущие файлы** шифруются новым epoch → украденное устройство не может расшифровать
- **Старые файлы** (зашифрованы старым epoch):
  - Партнёры видят revocation → отказывают в restore для revoked device key
  - Owner постепенно re-encrypt: скачать символы → decode → encrypt новым epoch → redistribute
  - Гонка со временем, но вор тоже должен скачать K символов → партнёры блокируют

**Что хранит каждое устройство:**
```
~/.syncback/
  device_id           # unique per device
  device_key          # derived from seed + device_id
  epoch_counter       # current encryption epoch
  epoch_keys_cache    # current + previous epoch keys (для decrypt старых файлов)
```

**Что НЕ хранится на устройстве:**
- Seed phrase (вводится при init, потом стирается из памяти)
- Но seed нужен для derivation epoch key... → нужно хранить epoch_key, не seed

**Уточнение:** устройство хранит `epoch_key[current]` и `epoch_key[current-1]` (для расшифровки файлов предыдущего epoch). Seed phrase нужен только при добавлении нового устройства или ротации epoch. Можно вводить seed по запросу (как пароль), не хранить постоянно.

### 3. Device Registration

**Сценарий: добавление нового устройства**
```
1. Новое устройство: пользователь вводит seed phrase
2. Derive device_key из seed + new device_id
3. Device certificate = master_key.sign(device_id, device_pub_key, timestamp)
4. Новое устройство публикует certificate в сеть → партнёры принимают как часть identity
5. Seed стирается из RAM
6. Получение cluster state (file catalog, placements, trust) через iroh-blobs от другого устройства
   или через сеть (если единственное устройство — disaster recovery)
```

**Если другое устройство доступно:** state sync через direct iroh connection. Быстро, полный state.

**Если нет (disaster recovery):** bootstrap из сети — скачать encrypted metadata от партнёров → расшифровать → восстановить state. Медленно, но работает.

### 4. Device Revocation

```
1. Owner на живом устройстве: `syncback device revoke <device_id>`
2. Генерируется revocation certificate = master_key.sign("revoke", device_id, timestamp)
3. epoch_counter += 1, новый epoch_key
4. Публикация в сеть:
   - revocation certificate (через board/gossip)
   - new epoch announcement
5. Партнёры:
   - Добавляют device_id в revoked list
   - Отказывают в restore/PoS для revoked device key
   - Принимают только запросы от не-revoked device keys этой identity
6. Owner: постепенно re-encrypt старых файлов новым epoch
```

**Edge case: все устройства украдены, кроме seed phrase на бумажке**
1. Новое устройство, ввод seed → derive master key
2. Revoke все предыдущие device keys (broadcast revocation для каждого)
3. Новый epoch → все будущие файлы защищены
4. Старые файлы: re-encrypt по мере скачивания из сети

### 5. State Synchronization

**Что синхронизировать между устройствами:**
- File catalog (path → content_hash → source_block_id)
- Symbol placements (source_block_id → holders → ESI ranges)
- Trust scores (per-peer P, I, S)
- Epoch counter + current epoch key
- Revocation list
- Config (include/exclude patterns, importance per folder)

**Как синхронизировать:**

**Вариант A: Event log sync (рекомендуемый)**
```
Каждое устройство ведёт свой event log:
  [ts, device_id, event_type, payload]

Sync = обмен хвостами логов:
  Device A: "мой последний event от B = ts=1000"
  Device B: "вот все мои events после ts=1000" → iroh-blob
  Device A: применяет events → state обновлён
```
- CRDT-like: events commutative, порядок не важен для финального state
- Компактно: events маленькие (placement, trust update — десятки байт)
- Работает при долгом offline: устройство приходит через месяц → получает лог за месяц → догнало

**Вариант B: State snapshot sync**
- Периодический snapshot всего state → iroh-blob → другие устройства скачивают
- Проще, но не инкрементально. При расхождении — merge конфликты.

**Вариант C: iroh-docs (board per identity)**
- Один board для cluster metadata
- Каждое устройство = author
- iroh-docs handles sync автоматически
- Зависимость от iroh-docs maturity

**Рекомендация: A (event log) с fallback на B (snapshot для disaster recovery).**

### 6. Deduplicated Backup

**Проблема:** фото `IMG_1234.jpg` есть и на ноутбуке, и на десктопе. Не бекапить дважды.

**Почему dedup бесплатный (content-addressed design):**
```
source_block_id = blake3(ciphertext)
ciphertext = encrypt(HKDF(epoch_key, content_hash, ...), plaintext)
```
Один файл на двух устройствах → тот же content_hash → тот же key → тот же ciphertext → тот же source_block_id. Символы уже в сети. Zero extra traffic.

**DB модель:**
```
FileRecord {
  path: "photos/img.jpg",
  importance: 0.6,
  devices: [
    (device_A, Present),    // на ноутбуке
    (device_B, Present),    // на десктопе
  ],
  versions: [{ content_hash, source_block_id, ... }]
}
```

**Flow:**
```
Device A: backup img.jpg → content_hash=XYZ → source_block_id=ABC → uploaded
Device B: backup img.jpg → content_hash=XYZ → уже есть → skip, добавить device_B в devices
```

**Delete:** cooldown начинается только когда ВСЕ устройства пометили файл как Deleted. Одно устройство ещё имеет → бекап живёт.

**Dedup проверка:** до пакования. Device B хочет бекапить → проверить shared catalog (синхронизирован через event log) → content_hash уже забекаплен → skip.

**Dedup на одной машине тоже работает:** один файл в двух папках → одинаковый content_hash → один source_block_id → символы не дублируются. Каждый path = отдельный FileRecord, но все ссылаются на один source_block.

**Known limitation (β):** packing race condition. Два устройства могут запаковать одни и те же файлы в разные пачки до синхронизации event log. Результат: дублирование символов (waste), не потеря данных. Vacuum почистит.

### 7. ESI Allocation

**Проблема:** два устройства генерируют символы для одного файла → ESI не должны пересекаться.

**Решение: ESI namespace per device**
```
device_0: ESI range [0, 1_000_000)
device_1: ESI range [1_000_000, 2_000_000)
device_2: ESI range [2_000_000, 3_000_000)
...
```

Миллион символов на устройство — хватит на любой реальный сценарий. Не нужна координация в реальном времени.

Или проще: `ESI = device_index * 2^20 + local_counter`. Пространство ESI в RaptorQ = 2^24 → до 16 устройств без коллизий.

### 8. Peer-to-Device Affinity (blast radius isolation)

**Ключевой принцип:** каждое устройство — "менеджер" своего набора внешних пиров.

```
Ноутбук (online вечерами): пиры A, C, E
NAS (always-on):           пиры B, D, F
Десктоп (выходные):        пиры G, H
```

**Зачем:** изоляция blast radius. Ноутбук offline неделю → пострадали отношения только с A, C, E (PoS failures). NAS стабилен → B, D, F не затронуты. Reputation identity в целом — средневзвешенная, но damage contained.

Если бы все пиры общались с "кластером как целым" → один flaky device портит trust со ВСЕМИ пирами.

**Как это работает:**
- Каждое устройство имеет свой NodeId (device key)
- Внешний пир A общается с конкретным NodeId (ноутбук), не с абстрактным кластером
- PoS, shard offers, restore — всё через назначенное устройство
- Внутренний placement: надёжные устройства (NAS) получают больше пиров

**Упрощает архитектуру:** не нужно "any device answers any PoS". Каждое устройство — почти независимая нода, sharing только identity + file catalog + placement metadata.

**S-score:** per device-peer pair, обычная pairwise формула. Протокол не знает про кластеры. Peer X видит Device A как обычную ноду.

**Переназначение пира между устройствами:**
- Стараться не переназначать (stable affinity)
- Если пришлось → Device B наследует trust history от Device A внутри кластера
- Пиру ничего не сообщаем — для него просто "партнёр немного изменил поведение"
- Trust формула адаптируется через P (4-week rolling) за несколько недель
- Ноль изменений в протоколе

**Внутренний trust (internal reliability):**
- NAS = high internal reliability → назначить больше внешних пиров
- Ноутбук = medium → меньше пиров, и тех которые сами intermittent
- Старый десктоп = low → минимум пиров или только storage

### 9. PoS & Repair

**PoS timing:** единый таймаут (7 дней) для всех, независимо от способа доставки. Peer online ≠ обязан ответить сразу. Даже при direct connection — ждём стандартный срок. Покрывает случай когда device получил challenge, но символы на другом устройстве кластера (нужна внутренняя пересылка).

```
Challenger → pos_challenge → Device A (online)
  Device A: символы у меня? → ответить
  Device A: символы на Device B? → переслать внутри кластера
  Device B (придёт online позже) → ответить
  Всё в рамках стандартных 7 дней
```

**PoS:** каждое устройство отвечает на PoS для шардов/символов, которые ОНО хранит, от СВОИХ назначенных пиров. Не нужна синхронизация MMR peaks между устройствами — каждое знает свои.

**Repair:**
- Устройство видит что символы у его пира потеряны (holder ушёл)
- Если файл есть локально → генерирует новые символы → раздаёт
- Если файла нет → скачивает K символов → decode → генерирует repair символы
- NAS как идеальный repair agent: always-on, большой диск, файлы часто локально

### 10. Network Identity

**Как сеть видит кластер:**
```
Identity (master pub key) — shared reputation baseline
├── Device A (NodeId A) — manages peers {A, C, E}, own trust history
├── Device B (NodeId B) — manages peers {B, D, F}, own trust history
└── Device C (NodeId C, REVOKED)
```

- Каждый внешний пир знает конкретный device NodeId, не абстрактную identity
- Device certificate в handshake: `master_key.sign(device_pub_key)` → пир проверяет что device принадлежит identity
- Trust: per device-peer pair (протокол не знает про кластеры)
- S-score: per device-peer pair (каждое устройство = обычная нода для внешних пиров)

### 10. Network Transport

**iroh-blobs и iroh-docs не нужны.** iroh используется только как transport (direct connections, NAT traversal).

- Symbol transfer: direct connection + bytes
- Cluster state sync: event log exchange через direct connection
- Deferred messaging: epidemic relay (hop≤2, append-only файл, TTL 7 дней)
- Restore: direct connection с holders

---

## MVP scope для Personal Cluster

### Must have (на реальный старт)

1. **Device registration:** seed → device key derivation, device certificate
2. **Multi-device identity:** сеть принимает несколько device keys как одну identity
3. **Dedup:** content-addressed file catalog, не бекапить одно дважды
4. **State sync:** event log sync между устройствами (через iroh direct connection)
5. **Device revocation:** отзыв device key, epoch rotation, partner notification

### Nice to have (можно итеративно)

6. **Autonomous repair:** NAS делает repair без owner
7. **Trusted partner:** delegated key с ограниченными полномочиями
8. **Old epoch re-encryption:** постепенная ре-шифровка файлов после revocation

### Не нужно

9. File sync (пусть Syncthing делает)
10. Real-time collaboration
11. Shared editing

---

## Открытые вопросы

1. **Seed storage:** хранить epoch_key (derivable from seed) или seed на устройстве? Seed = полный контроль, утечка = катастрофа. Epoch_key = ограниченный ущерб при утечке.
2. **Device discovery:** как устройства находят друг друга? По master pub key через DHT? Через board? Hardcoded addresses?
3. **Conflict resolution:** два устройства одновременно забекапили разные файлы → event log merge. Должно быть commutative by design.
4. **Offline duration:** устройство offline 6 месяцев → event log вырос → как эффективно догнать? Periodic snapshots + incremental log?
5. **Max devices:** какое ограничение? ESI namespace = 2^20 per device → max 16 devices при ESI 2^24. Достаточно?
6. **Re-encryption priority:** после revocation, какие файлы re-encrypt первыми? По importance? По возрасту?
7. **Revocation propagation:** как гарантировать что все партнёры узнали о revocation? TTL? Repeat broadcast?
