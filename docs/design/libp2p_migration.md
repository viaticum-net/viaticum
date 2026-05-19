# Миграция на libp2p

*Решение: iroh -> libp2p. Полный дизайн нового сетевого стека.*
*Версия 5 (финальная) -- после двух раундов ревью.*
*DB migration не нужна: системой ещё никто не пользуется.*

---

## Контекст

Viaticum использует iroh 0.96 как QUIC-транспорт. Проблемы:

1. **Relay сломан** -- QUIC через iroh relay умирает после 6-7с, handshake не проходит
2. **Двойная identity** -- iroh SecretKey + IdentityPub, маппинг через PeerAnnounce
3. **QUIC блокируют** -- UDP режут в корпоративных сетях, DPI определяет QUIC
4. **Зависимость от чужих серверов** -- iroh relay (n0.computer), pkarr
5. **iroh pre-1.0** -- API нестабилен

## Решение: libp2p

libp2p v0.56 -- модульный P2P-фреймворк. Проверен в production (Polkadot, Filecoin, IPFS, Ethereum).

### Что берём

| Компонент | Что делает | Заменяет |
|-----------|-----------|----------|
| TCP transport | Передача байтов | iroh QUIC endpoint |
| Noise protocol | Шифрование + аутентификация Ed25519 | iroh TLS + наш HandshakeMsg |
| Yamux | Мультиплексирование стримов (фрейм 16 KiB) | Наш single bi-stream |
| Kademlia DHT | Peer discovery без серверов | PeerAnnounce + iroh pkarr |
| DCUtR | Holepunching (~70% success, TCP = UDP) | iroh relay (сломан) |
| Circuit Relay v2 | Fallback relay через любой пир | iroh relay серверы |
| identify | Обмен адресами при подключении | Ручное управление EndpointAddr |
| request-response | Request/response поверх стримов | Наш framed CBOR на bi-stream |

### Что НЕ берём

- IPFS Bitswap (приватные данные, свой протокол передачи)
- GossipSub (есть board для broadcast)
- QUIC transport (может добавить позже как опцию)

---

## Архитектура

```
+----------------------------------------------+
|  Viaticum Protocol                           |
|  Trust, PoS, Escrow, Backup, Restore         |
|  Message enum (CBOR)                         |
|  --- не меняется ---                         |
+----------------------------------------------+
|  SwarmHandle                                 |
|  send_to_device(DeviceId, Message) -> Resp   |
|  events() -> Stream<ProtocolEvent>           |
+----------------------------------------------+
|  libp2p Swarm                                |
|  +----------------------------------------+  |
|  | ViaticumBehaviour (NetworkBehaviour)   |  |
|  |                                       |  |
|  |  request_response -- CBOR messages    |  |
|  |  kademlia         -- peer discovery   |  |
|  |  dcutr            -- holepunching     |  |
|  |  relay_client     -- relay (client)   |  |
|  |  relay_server     -- relay (server)   |  |
|  |  identify         -- addr exchange    |  |
|  +----------------------------------------+  |
|  TCP + Noise + Yamux                         |
+----------------------------------------------+
|  Board (store-and-forward)                   |
|  --- primary transport для протокола ---     |
+----------------------------------------------+
```

### Два канала доставки

Board = **primary** для протокольных сообщений. Прямое соединение = для тяжёлых данных.

**Board (store-and-forward, offline-tolerant):**
- PoS Challenge / Response / Nack
- Delete, CancelDelete
- SymbolDropped, SymbolDropNotice, StorageWarning
- DeviceRevocation (broadcast)

**Прямое соединение (libp2p request-response):**
- SymbolTransfer (мегабайты данных)
- SymbolOffer / Accept / Reject (pipeline)
- RestoreRequest / Response (пользователь ждёт)
- SystemStateRequest / Response (DR)
- SystemStateBackup (push)
- ClusterSync
- Board sync

**PoS response policy:** holder всегда отвечает через board, даже если прямое соединение доступно. Один путь, проще логика.

**PeerDiscoveryRequest / Response:** убираются, заменяются Kademlia DHT.

---

## Identity: device-visible модель

### Ключевое решение

Внешние пиры видят конкретные **устройства**, а не абстрактный "кластер". DeviceId -- primary key для routing, placement, PoS. IdentityPub (master) -- aggregation key для trust и escrow.

### Сейчас: три ключа, маппинг через PeerAnnounce

```
master_signing_key -> IdentityPub (Ed25519, 32 bytes) -- master identity
device_signing_key -> DeviceId ([u8; 16], random)     -- device identity
IrohSecretKey      -> NodeId (Ed25519, 32 bytes)      -- транспортная identity

Связи:
  DeviceCertificate: device_key -> master_key (подпись master)
  PeerAnnounce:      IdentityPub -> NodeId    (подпись master)
```

### После: два ключа, маппинг не нужен

```
master_signing_key -> IdentityPub (Ed25519, 32 bytes) -- master (trust agg, escrow)
device_signing_key -> DeviceId (Ed25519 pubkey, 32 bytes) -- device (routing, placement, PoS)
                   -> PeerId = hash(DeviceId)             -- libp2p transport (сеть)
```

**Изменение типа DeviceId:** с `[u8; 16]` (случайный) на `[u8; 32]` (Ed25519 pubkey). Это упрощает identity model -- DeviceId = public key, из него выводится PeerId. Следствия:
- `DeviceCertificate` структура упрощается: `device_id` и `device_pub_key` сливаются в одно поле
- Signed payload cert меняется
- DB migration не нужна (нет пользователей)

```
DeviceId = наш тип в core (raw Ed25519 pubkey, 32 bytes)
PeerId   = libp2p тип, только в daemon (multihash, ~38 bytes)

Конвертация DeviceId -> PeerId: одна функция (хэш), без таблицы.
PeerId -> DeviceId: невозможна (хэш), но DeviceId всегда в DeviceCertificate.
```

Конвертация (только в daemon):
```rust
use libp2p_identity::ed25519;

let secret = ed25519::SecretKey::try_from_bytes(device_seed)?;
let ed_keypair = ed25519::Keypair::from(secret);
let libp2p_keypair = libp2p::identity::Keypair::from(ed_keypair);
let peer_id = libp2p_keypair.public().to_peer_id();
```

### Что видит внешний пир

```
PeerRecord {
    device_id: DeviceId,              // primary key, кому коннектиться
    master_identity: IdentityPub,     // trust/escrow aggregation
    device_cert: DeviceCertificate,   // доказательство принадлежности
    x25519_pub: [u8; 32],            // board encryption
}
```

Обнаружение устройств кластера -- **ленивое**: пир узнаёт о новом устройстве при подключении (DeviceCertExchange). Никаких проактивных анонсов.

### PeerId -> DeviceId в event loop

Swarm event loop хранит таблицу аутентифицированных пиров `HashMap<PeerId, (DeviceId, IdentityPub)>`. Заполняется из DeviceCertExchange. Используется для конвертации PeerId в ProtocolEvent с DeviceId.

---

## Двухуровневый trust

### Проблема

Trust = "будут ли мои данные в безопасности". Свойство и **устройства** (NAS 24/7 vs ноутбук), и **человека** (надёжный участник, годы в системе).

Per-master (сейчас): скрывает разницу NAS vs ноутбук. Per-device: теряет репутацию при замене.

### Решение: два слоя

```
device_trust(DeviceId)      -- "это устройство отвечает на PoS"
                               Зарабатывается PoS-ответами.
                               Начинается с нуля. Умирает с устройством.

master_trust(IdentityPub)   -- "этот человек надёжный участник"
                               Агрегируется из device_trust всех устройств.
                               Переживает замену устройств.

effective_trust(DeviceId)   -- комбинация: placement использует это
```

### Формула

```rust
fn effective_trust(db: &Db, device: DeviceId) -> TrustScore {
    let dt = db.get_device_trust(device);
    let master = db.get_master_identity(device);
    let mt = db.get_master_trust(master);

    // Новое устройство старого пользователя:
    //   dt = 0, mt = высокий -> effective ~30-50% master trust
    let base = mt * INHERITANCE_FACTOR;  // 0.3-0.5, подобрать экспериментально
    base + dt * (1.0 - base / MAX_TRUST)
}

fn update_master_trust(db: &Db, master: IdentityPub) {
    let devices = db.get_devices_for_master(master);
    // Weighted average по количеству хранимых символов
    // + tenure bonus (длительность участия)
}
```

### Жизненный цикл

```
Новый пользователь, NAS:    dt=0, mt=0 -> effective=0, нужно заработать
Год работы:                 dt=высокий, mt=высокий
Добавляет ноутбук:          dt(laptop)=0, mt=высокий -> effective=30-50%, быстрый старт
NAS сдох, купил новый:      dt(new)=0, mt=высокий -> effective=30-50%, репутация не потеряна
Ноутбук месяц оффлайн:     dt(laptop) падает, mt немного, NAS не страдает
```

### DB таблицы

```
device_trust:   keyed by DeviceId    -- обновляется каждый PoS
master_trust:   keyed by IdentityPub -- агрегируется периодически
peer_records:   keyed by DeviceId    -- хранит master_identity как поле
escrow/budget:  keyed by IdentityPub -- экономика между людьми
```

### Sybil

"10 устройств = 10x trust" -- нет: trust зарабатывается реальным хранением + PoS. Budget per-master.

---

## Handshake: упрощение

### Сейчас

1. iroh QUIC+TLS (iroh identity -- не доверяем)
2. `open_bi()` -- один стрим
3. Наш `HandshakeMsg`: identity + timestamp + Ed25519 sig
4. Verify sig + freshness (300s window)
5. Exchange `DeviceCertificate`

### После

1. TCP connect
2. Noise IX -- шифрование + аутентификация Ed25519 (forward secrecy, replay protection)
3. Yamux negotiation
4. DeviceCertExchange (первый request-response на `/viaticum/1`)
5. Проверка: cert.device_pub == authenticated PeerId's key

`HandshakeMsg`, `build_handshake()`, `verify_handshake()` удаляются. Noise лучше.

### DeviceCertExchange

Реализуется как обычный request-response на основном протоколе `/viaticum/1`. Dialer отправляет первым:

```
Dialer  -> Request(DeviceCertExchange { cert, x25519_pub })
Listener -> Response(DeviceCertExchange { cert, x25519_pub })
```

В libp2p у каждого соединения всегда чёткий dialer/listener (libp2p дедуплицирует одновременные dial).

### State machine

```
ConnectionEstablished(PeerId)
  -> PendingCert { peer_id, deadline: now + 10s }
  -> Processor НЕ получает событие

DeviceCertExchange получен и верифицирован
  -> Authenticated { peer_id, device_id, master_identity }
  -> Processor получает PeerAuthenticated event
  -> Маппинг PeerId -> (DeviceId, IdentityPub) сохраняется в event loop

Timeout 10s -> закрываем соединение
```

### x25519_pub

Передаётся в DeviceCertExchange. Noise-канал обеспечивает integrity -- отдельная подпись x25519_pub не требуется (MITM невозможен после Noise IX handshake). Сохраняется в PeerRecord для board directed encryption.

---

## Discovery: Kademlia DHT

### Стратегия: общий IPFS DHT на старте, свой namespace позже

На старте используем общий IPFS DHT (`/ipfs/kad/1.0.0`):
- 200K+ нод, bootstrap из коробки (IPFS bootstrap ноды)
- Нет chicken-and-egg проблемы
- Privacy минимальная проблема (светим только provider-запросы, не данные)
- Чужой DHT трафик ничтожен (десятки KiB/s routing)

Когда количество Viaticum нод достаточно (~100+) -- переключиться на свой namespace `/viaticum/kad/1.0.0` + свои bootstrap ноды. Одна строка в конфиге.

### Паттерн discovery

```rust
// Публикация: "я -- Viaticum нода"
let namespace_key = Key::from(sha256(b"/viaticum/peers/v1"));
kademlia.start_providing(namespace_key)?;

// Поиск Viaticum-нод:
kademlia.get_providers(namespace_key);
// -> список PeerId + Multiaddr

// Адрес конкретного пира: identify + Kademlia routing table
```

Republish каждые 30 мин. MemoryStore с лимитом **10240 записей** (дефолт 1024 мал для 500+ нод).

---

## NAT traversal: DCUtR + Circuit Relay v2

```
A находит relay R (любой Viaticum пир с публичным IP)
A публикует в DHT relayed-адрес
B -> R -> A: relay-соединение
DCUtR holepunch -> ~70% прямое соединение A<->B
Fallback: relay остаётся
```

Для кода прозрачно: `swarm.dial(peer_id)`.

### Все ноды = relay

`relay::Behaviour` (server) и `relay::client::Behaviour` у всех нод. Если у пира публичный IP -- libp2p автоматически начинает принимать relay-соединения. Никакой настройки пользователем.

### Circuit Relay v2: лимиты

Дефолты: **2 минуты**, **128 KiB суммарно** (общий объём, не скорость).

Основной протокол (PoS, Delete) идёт через board -- relay лимиты не проблема. Relay нужен для holepunch координации. Тяжёлые данные (SymbolTransfer) -- только по прямому соединению (после holepunch или если хотя бы один пир публичный).

---

## Protocol: request-response с batch transfer

### Операции по прямому соединению

| Операция | Request | Response |
|----------|---------|----------|
| Cert exchange | DeviceCertExchange | DeviceCertExchange |
| Symbol transfer | SymbolTransferBatch | SymbolStored |
| Symbol offer | SymbolOffer | SymbolAccept / SymbolReject |
| Restore | RestoreRequest | RestoreResponse |
| Board sync | BoardSyncRequest | BoardSyncResponse |
| Cluster sync | ClusterSyncRequest | ClusterSyncResponse |
| System state (DR) | SystemStateRequest | SystemStateResponse |
| System state push | SystemStateBackup | Ack |

### Batch transfer

Один запрос = все символы для одного holder'а за один source block:

```
Source block 128 MB = 2048 символов
/ 5 holders = ~410 символов на holder = ~26 MB на запрос
```

Один стрим, один response. Yamux нарезает на фреймы по 16 KiB автоматически (window авто-тюнится). При обрыве -- повтор одного запроса.

### MAX_MESSAGE_SIZE = 128 MB

Ограничение на уровне ViaticumCodec. С запасом.

### Кодек

```rust
impl request_response::Codec for ViaticumCodec {
    type Protocol = StreamProtocol;
    type Request = Message;
    type Response = Message;  // SymbolStored, SymbolAccept, RestoreResponse, Ack, etc.
}
```

Wire format `[u32 BE length][CBOR]` не меняется. `frame_message()` и `from_cbor()` переиспользуются.

```rust
const VIATICUM_PROTOCOL: StreamProtocol = StreamProtocol::new("/viaticum/1");
```

---

## NetworkBehaviour

```rust
#[derive(NetworkBehaviour)]
struct ViaticumBehaviour {
    viaticum: request_response::Behaviour<ViaticumCodec>,
    kademlia: kad::Behaviour<MemoryStore>,
    dcutr: dcutr::Behaviour,
    relay_client: relay::client::Behaviour,
    relay_server: relay::Behaviour,
    identify: identify::Behaviour,
}
```

MemoryStore: лимит 10240 записей. При рестарте -- DHT bootstrap заново. Позже можно redb-backed store.

---

## SwarmHandle

```rust
pub struct SwarmHandle {
    cmd_tx: mpsc::Sender<SwarmCommand>,
    pub peer_id: PeerId,
    pub device_id: DeviceId,
    pub identity_pub: IdentityPub,
    master_signing_key: SigningKey,
    x25519_pub: [u8; 32],
}

enum SwarmCommand {
    SendMessage { peer_id: PeerId, message: Message, reply: oneshot::Sender<Result<Message>> },
    Dial { peer_id: PeerId },
    PublishDht,
}

enum ProtocolEvent {
    PeerAuthenticated {
        peer_id: PeerId,
        device_id: DeviceId,
        identity_pub: IdentityPub,
        device_cert: DeviceCertificate,
        x25519_pub: Option<[u8; 32]>,
    },
    InboundRequest {
        from_device: DeviceId,
        from_master: IdentityPub,
        message: Message,
        response_channel: ResponseChannel<Message>,
    },
    ConnectionClosed { peer_id: PeerId, device_id: DeviceId },
}

impl SwarmHandle {
    /// Отправить сообщение по DeviceId. Конвертирует в PeerId внутри.
    pub async fn send_to_device(&self, device: DeviceId, msg: &Message) -> Result<Message>;

    /// PeerAnnounce для board.
    pub fn build_peer_announce(&self, timestamp: Timestamp) -> PeerAnnounceMsg;

    /// Listen addresses.
    pub fn listen_addrs(&self) -> Vec<Multiaddr>;
}
```

---

## Что меняется в коде

### Удаляем

```
daemon/network/: connection.rs, handshake.rs, addr.rs
viaticum-core/messages/: HandshakeMsg, build_handshake, verify_handshake
viaticum-core/messages/: PeerDiscoveryRequestMsg, PeerDiscoveryResponseMsg (заменяет DHT)
viaticum-core/types/: NodeId
viaticum-core/constants/: ALPN
```

### Переписываем (10+ файлов)

```
daemon/network/mod.rs      -- NetworkHandle -> SwarmHandle
daemon/processor/mod.rs    -- ProtocolEvent dispatch
daemon/handle/mod.rs       -- Swarm creation
daemon/cli_server/mod.rs   -- addr format (Multiaddr)
daemon/system_state/mod.rs -- SwarmHandle
daemon/restore/mod.rs      -- SwarmHandle
daemon/cluster_sync/mod.rs -- SwarmHandle
daemon/dr/mod.rs           -- полная переработка

viaticum-core/types/mod.rs    -- DeviceId: [u8;16] -> [u8;32], PeerRecord keyed by DeviceId
viaticum-core/messages/mod.rs -- PeerAnnounceMsg без node_id, убрать PeerDiscovery*
viaticum-core/cluster/        -- DeviceCertificate: device_id + device_pub_key -> одно поле
viaticum-core/trust/          -- двухуровневый trust (device + master)
```

### Тесты (~150 из ~895)

```
network/tests.rs      -- 37, полная замена
processor/tests.rs    -- ~40-50 (3279 строк)
backup/tests.rs       -- ~10-15
restore/tests.rs      -- ~28
cli_server/tests.rs   -- ~16
messages/tests.rs     -- NodeId, PeerDiscovery
trust/tests.rs        -- двухуровневая модель
cluster/tests.rs      -- DeviceCertificate
```

### Не трогаем

```
viaticum-core/: pos/, escrow/, placement/, budget/, erasure/, db/, config/
daemon/: relay/ (board), backup/ (только send сигнатура), scheduler/, watcher/, identity/
```

---

## Board

libp2p не имеет store-and-forward. Board -- **primary transport** для протокольных сообщений (PoS, Delete, Drop, broadcast). Board sync унифицируется как request-response `BoardSyncRequest/Response` поверх libp2p.

x25519_pub для board encryption передаётся через DeviceCertExchange.

---

## Конфиг

```toml
[network]
listen_port = 0
bootstrap_peers = []    # дополнительные, опционально
```

Relay включён у всех по умолчанию, не настраивается.

---

## Этапы реализации

### Фаза 1: Скелет libp2p

- `libp2p = "0.56"` в Cargo.toml
- SwarmHandle, ViaticumCodec, ViaticumBehaviour
- DeviceCertExchange (первый r-r после connect)
- PendingCert state machine
- Статический peer directory для тестирования без DHT
- Unit-тесты: два пира, обмен Message

### Фаза 1.5: Двухуровневый trust (core, без сети)

- device_trust, master_trust, effective_trust в viaticum-core
- DeviceId [u8;32], обновлённый DeviceCertificate
- Тесты trust
- Обновить `docs/logic.md` (алгоритм trust меняется)

### Фаза 2: Processor + DR

- ProtocolEvent dispatch
- Board sync после PeerAuthenticated
- DR переписать
- E2E скрипты обновить
- Тесты processor

### Фаза 3: Kademlia DHT

- Общий IPFS DHT (`/ipfs/kad/1.0.0`)
- Bootstrap, periodic publish (start_providing)
- PeerRecord keyed by DeviceId
- MemoryStore limit 10240

### Фаза 4: NAT traversal

- relay_client + relay_server + dcutr
- E2E: Docker с двумя NAT-сетями

### Фаза 5: Cleanup + документация

- Удалить iroh
- Удалить HandshakeMsg, NodeId, EndpointAddr, ALPN, PeerDiscoveryRequest/Response
- Обновить документацию:
  - `docs/protocol.md` -- wire format, DeviceCertExchange, batch transfer, убрать Handshake/NodeId/PeerDiscovery
  - `docs/architecture.md` -- crate structure (iroh->libp2p), SwarmHandle, network module
  - `docs/overview.md` -- identity model, network description
  - `docs/tech-debt.md` -- закрыть iroh relay issue, убрать per-exchange QUIC streams
  - `docs/features.md` -- обновить приоритеты (NAT решён)
  - `CLAUDE.md` -- минимальные правки если упоминает iroh

### Rollback

- Фаза 1-2: ветка `feat/libp2p`, откат = не мержим
- Фаза 3+: коммитимся к libp2p

---

## Открытые вопросы

1. **DHT bootstrap из стран с ограничениями.** IPFS bootstrap-ноды могут быть недоступны. Self-hosted bootstrap как fallback. Тестировать.

2. **INHERITANCE_FACTOR (0.3-0.5).** Определить экспериментально. Слишком высокий -- sybil, слишком низкий -- медленный старт.

3. **Переход на свой DHT namespace.** При ~100+ Viaticum нод перейти на `/viaticum/kad/1.0.0` + свои bootstrap. Одна строка в конфиге.

---

## Уточнения при реализации

Мелкие несоответствия между этим дизайном и текущим protocol.md. Не архитектурные, но зафиксировать:

1. **RestoreResponse** -- в текущем протоколе restore отвечается через `SymbolTransfer` + `RestoreDenied`, не отдельным типом. При реализации: либо ввести `RestoreResponse { symbols }`, либо использовать существующий `SymbolTransfer`. `RestoreDenied` -- альтернативный response, добавить в таблицу операций.

2. **BoardSync** -- сейчас один тип `BoardSyncMsg`. При реализации разбить на `BoardSyncRequest` / `BoardSyncResponse` для r-r модели.

3. **SystemStateAck** -- в таблице написано `Ack`, в enum -- `SystemStateAck(SystemStateAckMsg)`. Использовать существующий тип.

4. **SymbolTransferBatch** -- в таблице `SymbolTransferBatch`, в enum -- `SymbolTransfer(SymbolTransferMsg)`. Batch-семантика через содержимое (Vec символов), не новый тип. Уточнить при реализации.

5. **PeerAnnounceMsg** -- явно board (broadcast). Не указано в разделе "Два канала доставки", но очевидно.

6. **Фаза 1.5 и Фаза 1** -- DeviceId меняется в 1.5, SwarmHandle использует DeviceId в 1. Реализовывать 1.5 до или параллельно с 1, не после.
