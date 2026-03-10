# ADR-002: Что строим, что берём готовое

*2026-03-10 · Accepted*

## Принцип

SyncBack — тонкая обёртка. Единственная оригинальная часть — протокол доверия. Всё остальное — готовые библиотеки и интеграция.

## Стек

### Транспорт и инфраструктура (iroh) — см. ADR-001

| Задача | Компонент |
|---|---|
| P2P connectivity, NAT, relay | iroh core |
| Передача шардов (content-addressed) | iroh-blobs |
| Mailbox / store-and-forward | iroh-docs |

### Библиотеки (Rust crates)

| Задача | Библиотека | Наш код |
|---|---|---|
| File watching | notify | Интеграция, ~100 строк |
| Local DB | redb или sqlite | Схема + логика, ~400 строк |
| Encryption | chacha20poly1305 (RustCrypto) | Key derivation из identity, ~50 строк |
| Erasure coding | reed-solomon-erasure / reed-solomon-simd | Конфиг k/n, ~100 строк |
| Merkle tree / PoS verification | BLAKE3 (встроен в iroh-blobs) | Challenge logic, ~300 строк |
| Identity keys | ed25519-dalek | Seed → keypair, подписи, ~50 строк |

### 100% наше (ни у кого нет)

| Модуль | ~Строк | Описание |
|---|---|---|
| Trust engine | ~500 | P (4-week rolling window), I (cumulative mean), S (pairwise ratio). Формула: (kp×P + ki×I) × clamp(S, 0.1, 1.0). Persist в локальную DB. |
| Escrow | ~200 | Право holder'а отказать в restore. Тиры по I-score: <5GB/4wk, <50GB/13wk, >50GB/26wk. Первый 1GB бесплатно. |
| Placement | ~300 | Weighted: w_i = trust^α, cap per partner. Adaptive n: больше шардов при низком trust. |
| Mailbox relay rules | ~400 | Формат сообщений в iroh-docs. Relay: копировать для соседей. TTL=7d, hop_limit=7, identity allowlist, rate limit, outbox cap 8MB. |
| Peer management | ~300 | Bootstrap от seed nodes, peer exchange, subnet tracking (/24, ASN). |

**Итого уникального кода: ~1700 строк.**

### Интеграционный клей

| Модуль | ~Строк | Описание |
|---|---|---|
| PoS scheduler + verification | ~300 | Генерация challenges, верификация responses, расписание 2-3/week. BLAKE3 merkle proof из iroh-blobs. |
| File catalog | ~500 | Конфиг папок, change detection (notify), file index (path→hash→file_id), dedup. |
| Shard manager | ~400 | Encrypt → erasure code → upload blobs. Repair: detect lost shards → re-place. Shard registry: file_id → shards → holders. |
| Node daemon | ~500 | Запуск iroh endpoint, регистрация протоколов, periodic tasks (PoS, repair, cleanup). |
| CLI | ~300 | init, backup, restore, status, peers. |

**Итого клея: ~2000 строк.**

### Сводка

| Категория | Строк |
|---|---|
| Наш уникальный код (trust, escrow, placement, relay, peers) | ~1700 |
| Интеграция (PoS, file catalog, shard manager, daemon, CLI) | ~2000 |
| Библиотеки (iroh, notify, reed-solomon, chacha20, redb) | 0 (готовое) |
| **Всего** | **~3700** |

## Порядок разработки

**Фаза 1 — ядро (100% наше, без зависимостей от iroh)**

1. Trust engine — P, I, S вычисление, DB, unit tests
2. Escrow — логика тиров, unit tests
3. Placement — weighted allocation, adaptive n, unit tests
4. Mailbox format — message types, подпись/верификация, serialization

Результат: библиотека `syncback-core` с чистой логикой, тестируемая без сети.

**Фаза 2 — интеграция с iroh**

5. Node daemon — iroh endpoint, blobs + docs протоколы
6. Mailbox relay — iroh-docs adapter, relay rules
7. PoS — challenge/response поверх mailbox
8. Shard manager — encrypt + erasure + upload через iroh-blobs

Результат: работающая нода, можно запустить два инстанса и проверить.

**Фаза 3 — пользовательский слой**

9. File catalog — notify watcher, index, change detection
10. CLI — init, backup, restore, status
11. Repair loop — автоматическое восстановление потерянных шардов

Результат: юзабельный MVP.

## Решения, которые могут измениться

- redb vs sqlite (решим когда начнём Фазу 1)
- reed-solomon-erasure vs reed-solomon-simd (бенчмарк в Фазе 2)
- iroh 0.35 (stable blobs) vs 0.96+ (новый API) — решим при интеграции
- CLI framework (clap vs минимальный) — решим в Фазе 3
