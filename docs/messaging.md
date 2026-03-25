# Messaging Policy

Два транспорта доставки сообщений: QUIC (прямое соединение) и Relay Board (epidemic gossip, hop <= 2, TTL 7 дней).

## Принцип выбора транспорта

- **Доска** — основной транспорт для протокольных сообщений. Tolerant к задержкам (часы/дни). Маленький payload. Работает когда получатель offline. Естественно поддерживает кластеры (любое устройство кластера видит сообщение и может ответить).
- **QUIC** — для тяжёлых данных (символы, DB snapshot) и срочных операций (restore — пользователь ждёт).

Cold backup, time constant = 1 неделя. Разница между ответом за секунды и за дни — несущественна для протокольных операций.

## Классификация сообщений

### Через доску (directed)

| Сообщение | Направление | Зачем через доску |
|-----------|-------------|-------------------|
| PosChallenge | Owner → Holder | Holder может быть offline; в кластере — отвечает устройство с символом |
| PosResponse | Holder → Owner | Owner может быть offline; в кластере — любое устройство подбирает ответ |
| PosNack | Holder → Owner | Символ не найден — аналогично PosResponse |
| Delete | Owner → Holder | Holder offline неделями — символы не удалятся без доставки |
| CancelDelete | Owner → Holder | Парный к Delete |
| SymbolDropped | Holder → Owner | Owner offline когда holder дропает; ускоряет repair |
| SymbolDropNotice | Holder → Owner | Предупреждение о будущем дропе |
| StorageWarning | Owner → Holder | Bit rot alert, не срочно |

### Через доску (broadcast)

| Сообщение | Зачем |
|-----------|-------|
| DeviceRevocation | Все peers должны узнать об отзыве устройства |
| PeerDiscovery (announce) | "Я существую, вот мой NodeId" — gossip discovery |

### Только QUIC (онлайн)

| Сообщение | Причина |
|-----------|---------|
| RestoreRequest / RestoreResponse / RestoreDenied | Пользователь ждёт файл, нужен мгновенный ответ |
| SymbolTransfer | Мегабайты данных, доска не для больших payload |
| SymbolOffer / SymbolAccept / SymbolReject | Часть backup pipeline, repair как fallback |
| SystemStateBackup / SystemStateAck | Blob ~200KB, periodic push с retry |
| SystemStateRequest / SystemStateResponse | DR flow, req/resp |
| PeerAnnounce | На уже установленном соединении |
| ClusterSyncRequest / ClusterSyncResponse | Внутрикластерный протокол |
| PeerDiscoveryRequest / PeerDiscoveryResponse | Req/resp, periodic retry |
| BoardSync | Мета-сообщение: синхронизация самих досок |
| Handshake | Установка соединения |

## Timeout и PoS через доску

Текущая логика: 3 пропущенных challenge подряд → PresumedLost → repair.

Через доску round-trip challenge→response занимает часы/дни вместо секунд. Это нормально для cold backup. Timeout считается от момента отправки challenge; если ответ приходит через неделю — challenge засчитывается.

Точность обнаружения проблем — недели, не минуты. Для системы с time constant = 1 неделя это приемлемо. SymbolDropped через доску ускоряет обнаружение потерь (минуты вместо недель).

## Кластерная совместимость

Кластер снаружи — одна сущность (один IdentityPub). Сеть не знает про внутреннее устройство.

Доска решает кластерную проблему естественно:
- PosChallenge приходит на доску holder-кластера → устройство С символом отвечает
- PosResponse приходит на доску owner-кластера → любое устройство подбирает
- Delete/SymbolDropped — аналогично

QUIC сообщения работают с тем устройством, которое online. Для restore это нормально (символы реплицированы внутри кластера через ClusterSync).

## Паттерн доставки для board-сообщений

Для сообщений через доску:

1. Отправитель вызывает `RelayManager::post_directed(target, payload)` или `post_broadcast(payload)`
2. Запись появляется на локальной доске (hop=0)
3. BoardSync разносит запись партнёрам (hop=1, hop=2)
4. Получатель видит запись через `scan_for_self` → `InboundMessage` → dispatch в Processor

Доска — append-only, TTL 7 дней, max 2000 entries, max 8 MB. Достаточно для протокольных сообщений (десятки байт каждое).
