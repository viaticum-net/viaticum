# Архитектура демона SyncBack

*Март 2026 · draft*

## Общая схема

```
┌─────────────────────────────────────────────────────┐
│                    syncback daemon                   │
├──────────┬──────────┬──────────┬────────────────────┤
│  Watcher │ Network  │ Storage  │    Scheduler       │
│  (owner) │ (peer)   │ (holder) │    (cron)          │
├──────────┴──────────┴──────────┴────────────────────┤
│                   Local DB (redb)                    │
├─────────────────────────────────────────────────────┤
│              Transport (iroh adapter)                │
└─────────────────────────────────────────────────────┘
```

## Watcher (роль: owner)

Отвечает за мои файлы.

- Мониторит настроенные папки (notify: inotify/FSEvents)
- Детектит изменения: new/modified/deleted
- Pipeline: file → encrypt (ChaCha20) → erasure code (Reed-Solomon) → upload shards (iroh-blobs)
- Шарды НЕ хранятся локально — стримятся партнёрам, удаляются после подтверждения
- При изменении файла: новый file_id, новые шарды. Старые — delete с cooldown.
- File catalog: path → hash → file_id → shard map

## Network (роль: peer)

Отвечает за отношения с партнёрами.

- Mailbox sync: при подключении к партнёру — sync iroh-docs, получить/отправить сообщения
- Relay: копировать сообщения для соседей (semi-epidemic, hop < 7, identity allowlist)
- Trust engine: P (rolling 4wk), I (cumulative), S (pairwise GB ratio)
- PoS challenger: генерировать challenges для holder'ов своих шардов
- Peer management: bootstrap, peer exchange, allowlist (partners + 2 hops)

## Storage (роль: holder)

Отвечает за чужие шарды на моём диске.

- Принимать входящие шарды (iroh-blobs) если есть место и owner в allowlist
- Отвечать на PoS challenges (hash(range + nonce) + merkle proof)
- Escrow: проверять I-score при restore request
- Shard lifecycle: active → marked-for-delete (cooldown 4wk) → deleted
- При нехватке места: дропать по приоритетам (2.8 в overview.md)
- Silent shards: owner замолчал — хранить если high I-score, дропать если low

## Scheduler (периодические задачи)

- Каждые ~2 дня: PoS challenges для своих шардов
- Еженедельно: trust update (агрегация P), repair check, mailbox cleanup (TTL 7d)
- Event-driven: при подключении партнёра — sync mailbox, pending transfers

## Local DB (redb)

```
files:    file_id   → {path, hash, size, version, status, created_at}
shards:   shard_id  → {file_id, shard_index, holder_id, status, last_verified}
peers:    identity  → {node_id, trust_P, trust_I, trust_S, first_seen, last_seen, subnet}
holding:  shard_id  → {owner_pub, size, state, received_at, delete_requested_at}
config:   key       → value
```

## Поток данных: backup

```
Файл на диске
  → notify: file changed
  → hash → сравнить с file catalog → изменился?
  → encrypt (ChaCha20, ключ из identity, nonce из file_hash)
  → erasure code (k-of-n, Reed-Solomon)
  → placement: выбрать n партнёров (weighted by trust)
  → каждый шард → iroh-blobs local store (временно)
  → iroh передаёт партнёру → подтверждение
  → удалить шард из local store
  → записать shard map в DB
```

## Поток данных: repair

```
Scheduler: repair check
  → для каждого file_id: сколько живых шардов?
  → если < n (но ≥ k): repair возможен
    → файл не изменился? → пересоздать потерянные шарды из оригинала
    → файл изменился? → скачать k шардов от живых holders
      → восстановить файл → пересоздать потерянные шарды
    → разместить на новых партнёрах
  → если < k: данные потеряны (не должно случиться при 5-of-15)
```

## System state backup

Зашифрованный снимок состояния ноды (~8-24 МБ в зависимости от объёма данных), сам бекапится в сеть с максимальной redundancy. Обновляется при каждом существенном изменении.

Содержимое: file manifest, shard map, trust state, peer directory.

Подробности: overview.md §1.8.

## Поток данных: disaster recovery

```
День 1: Новое устройство
  → syncback restore --seed "witch collapse practice..."
  → seed phrase → identity keypair (детерминированно)
  → подключение к seed nodes

День 1: System state recovery
  → seed nodes находят партнёров, знающих наш identity_pub
  → партнёры: "у меня system state shards для identity X"
  → скачать k шардов system state (~8 МБ = минуты)
  → расшифровать → file manifest + shard map + trust state + peer directory
  → нода знает ВСЁ: файлы, где шарды, кто партнёры, trust

День 1-14: Восстановление файлов
  → по shard map: запросить k шардов каждого unit'а у holder'ов
  → escrow check: I-score высокий (кумулятивный, не обнуляется) → ок
  → Reed-Solomon decode → расшифровка → файлы на диске
  → приоритет: мелкие файлы (документы) → крупные (фото) → огромные (видео)

Неделя 4+: Полная функциональность
  → trust к партнёрам стабилизируется (P накопится за 4 недели)
  → начинаем хранить чужие шарды → S восстановится
  → нода полностью функциональна
```

## Units и размер шардов

Два правила, один концепт (unit):

```
Unit size = U (default 256 МБ)

Файл < U  → pack с другими мелкими в unit ~U
Файл ≥ U  → split на chunks по U, каждый chunk = unit
```

Каждый unit → encrypt → erasure code → n шардов по ~U/k.

- При изменении файла в pack → перепаковать unit
- При изменении chunk'а большого файла → пересоздать только этот unit
- RS encoding: max 256 МБ в памяти (вместо размера всего файла)

## Конфигурация пользователя

- Какие папки бекапить (include/exclude patterns)
- Сколько места отдать под чужие шарды (GB или % свободного)
- Seed nodes (default: hardcoded list)
- k и n (default: 5-of-15)
- Bandwidth limit (default: без ограничений)
