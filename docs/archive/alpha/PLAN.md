# Протокол SyncBack: план проработки

## Порядок разделов

Каждый пункт — решения, которые нужно принять. Идём сверху вниз: каждый следующий зависит от предыдущих.

### 1. Транспорт
Как две ноды физически соединяются. TCP, UDP, QUIC? Шифрование канала (Noise? TLS?). NAT traversal.

### 2. Identity и аутентификация
Handshake: как ноды доказывают друг другу кто они. Формат ключей, подпись, взаимная аутентификация.

### 3. Формат сообщений
Сериализация (protobuf, CBOR, msgpack). Framing (как отделить одно сообщение от другого в потоке). Версионирование протокола.

### 4. Каталог сообщений
Полный список message types: handshake, peer exchange, PoS challenge/response, shard upload/download, gossip relay.

### 5. Peer discovery и bootstrap
Как новая нода находит первых партнёров. Seed nodes, peer exchange, DHT vs gossip.

### 6. Gossip relay
Store-and-forward механика. Outbox, доставка, дедупликация, приоритизация.

### 7. Операции с шардами
Upload flow, download flow, repair. Кто инициирует, как подтверждается, как обрабатываются ошибки.

### 8. Proof-of-Storage flow
Конкретная механика challenge-response поверх gossip. Timing, retry, агрегация.

### 9. Personal Cluster
Key derivation, device registration, синхронизация metadata между устройствами.

---

## Статус

- [x] 1. Транспорт → ADR-001 (iroh)
- [x] 2. Identity и аутентификация → overview.md §1.1 (handshake over ALPN "syncback/1")
- [x] 3. Формат сообщений → overview.md §0.1 (CBOR, u32 framing, ALPN versioning)
- [x] 4. Каталог сообщений → overview.md §1.5 (типы записей), §1.2 (ShardDescriptor)
- [x] 5. Peer discovery и bootstrap → overview.md §1.6
- [x] 6. Gossip relay → overview.md §1.5
- [x] 7. Операции с шардами → overview.md §1.7 (ask-then-push), §1.8 (lifecycle), §2.8 (eviction)
- [x] 8. Proof-of-Storage flow → overview.md §1.3
- [ ] 9. Personal Cluster

## Build plan → ADR-002
