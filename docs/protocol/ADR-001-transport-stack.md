# ADR-001: Transport stack — iroh

*2026-03-10 · Accepted*

## Контекст

SyncBack нужен P2P транспортный слой: соединения между нодами, NAT traversal, передача шардов (content-addressed blobs), доставка сообщений (store-and-forward gossip). Проект — тонкая обёртка над существующими технологиями; единственная оригинальная часть — протокол доверия.

## Рассмотренные варианты

### A. iroh (n0-computer)

QUIC-based P2P stack. iroh-blobs (BLAKE3 verified streaming), iroh-docs (replicated KV с range reconciliation), iroh-gossip (epidemic broadcast). Rust-native.

- (+) Blobs + docs из коробки — покрывают ~70% инфраструктуры
- (+) iroh-docs как mailbox = естественный store-and-forward
- (+) NAT traversal + managed relay из коробки
- (+) Простой API, быстрый старт (~2000 строк нашего кода для MVP)
- (-) Pre-1.0 (v0.96), API ломается между версиями
- (-) iroh-blobs 0.98 "not production quality" (stable = 0.35)
- (-) QUIC-only для прямых соединений (WSS через relay)
- (-) Нет interop с libp2p / IPFS ecosystem
- (-) Vendor lock на iroh ecosystem

### B. rust-libp2p

Зрелый P2P фреймворк. gossipsub, Kademlia, DCUtR (NAT), multiple transports (TCP, QUIC, WebSocket).

- (+) Production-proven (IPFS, Ethereum, Polkadot)
- (+) Interop с Go/JS нодами через libp2p spec
- (+) Множество транспортов (TCP, QUIC, WebSocket)
- (-) Нет blob protocol — пишем сами (~1500 строк)
- (-) Нет KV sync / mailbox — пишем сами (~1000 строк)
- (-) Сложный API (event loop, swarm, manual dispatch, ~5000 строк для MVP)
- (-) Тоже pre-1.0 (v0.56), ломающие изменения

### C. Руками (rustls + yamux + tokio)

Минимальные зависимости, полный контроль.

- (+) Понимаем каждую строку, минимум зависимостей
- (+) TCP+TLS — работает везде, DPI-устойчив
- (-) Всё сами: blob transfer, sync, NAT traversal, relay (~10000+ строк)
- (-) NAT traversal — месяцы работы
- (-) Нет relay-инфраструктуры

## Решение

**iroh** как transport adapter для reference implementation.

## Обоснование

1. **Скорость старта.** iroh-blobs + iroh-docs закрывают две самые трудоёмкие задачи (content-addressed transfer и store-and-forward). Это позволяет сфокусироваться на единственной оригинальной части — протоколе доверия.

2. **iroh-docs как gossip relay.** Ключевой инсайт: replicated document = "почтовый ящик". Нода пишет сообщения в свой doc, партнёры синхронизируют при подключении. Полу-эпидемик: ноды копируют сообщения для соседей. Store-and-forward — бесплатно.

3. **Миграция реальна.** Протокол НЕ привязан к iroh:
   - Identity = наш Ed25519, не iroh NodeId
   - Trust state = наша локальная БД
   - Формат сообщений = наш (подписан identity_priv)
   - Transport abstraction trait изолирует ядро от транспорта
   - Стоимость миграции на libp2p: ~3000 строк в адаптере

4. **QUIC + блокировки.** QUIC работает в большинстве мира. Где заблокирован — iroh relay через WSS:443 (выглядит как HTTPS). Self-hosted relay для закрытых сетей. P2P трафик между домашними IP не попадает под целевые блокировки (ТСПУ, GFW фильтруют known targets, не весь UDP).

## Риски и митигация

| Риск | Вероятность | Митигация |
|------|-------------|-----------|
| iroh не дойдёт до 1.0 | Средняя | Transport trait → миграция на libp2p |
| Ломающие API changes | Высокая (pre-1.0) | Pin версию, обновляться пакетно |
| iroh-blobs не станет production | Низкая | Fallback на 0.35 (stable) или свой blob protocol |
| QUIC заблокируют тотально | Низкая | WSS relay; в будущем iroh добавит pluggable transports |
| n0-computer закроется | Низкая | Код open source (Apache 2.0 / MIT), форк возможен |

## Следствия

- Reference implementation пишется на Rust с iroh 0.96+ (или 0.35 для production blobs)
- Ядро SyncBack (trust, escrow, PoS, placement) изолировано от iroh через transport trait
- `identity_pub` (Ed25519) — первичный идентификатор; `iroh::NodeId` — транспортный адрес
- Маппинг `identity_pub ↔ NodeId` хранится локально и не является частью протокола
- При необходимости миграции: пишем новый адаптер, ядро не трогаем
