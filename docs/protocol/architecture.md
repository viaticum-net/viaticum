# Архитектура демона SyncBack

*Март 2026 · draft*

## Общая схема

```
┌──────────────────────────────────────────────────────┐
│                    syncback daemon                    │
├──────────┬──────────┬───────────┬────────────────────┤
│  Watcher │ Packer   │ Network   │    Scheduler       │
│  (files) │ (units)  │ (peers)   │    (cron)          │
├──────────┴──────────┼───────────┤                    │
│  Budget Planner     │ Storage   │                    │
│  (importance+budget)│ (holder)  │                    │
├─────────────────────┤           │                    │
│  Shard Manager      │           │                    │
│  (encrypt+erasure)  │           │                    │
├─────────────────────┴───────────┴────────────────────┤
│                   Local DB (redb)                     │
├──────────────────────────────────────────────────────┤
│              Transport (iroh adapter)                 │
└──────────────────────────────────────────────────────┘
```

## Watcher (роль: owner)

Отвечает за мои файлы. Только локальные операции, никакой сетевой активности.

- Мониторит настроенные папки (notify: inotify/FSEvents)
- Детектит изменения: new/modified/deleted
- Отправляет DirtyEvent в Processor через канал; Processor записывает в DB
- **Не запускает backup сразу.** Только сигнализирует об изменениях.

## Packer (роль: owner)

Превращает файлы в units. Вызывается Scheduler'ом (weekly sync), не Watcher'ом.

```
Unit size = U (default 256 МБ)

Файл < U  → pack с другими мелкими в unit ~U
Файл ≥ U  → split на chunks по U, каждый chunk = unit
```

### Batch model (не реагируем на каждый чих)

```
РЕАЛЬНОЕ ВРЕМЯ (Watcher)
  файл изменился → dirty=true в DB
  Всё. Никаких сетевых операций.

WEEKLY SYNC (Scheduler → Budget Planner → Packer → Shard Manager)
  → Budget Planner: оценить budget_gb
  → собрать все dirty файлы, отсортировать по importance
  → отсечь по бюджету: dirty файлы ниже порога → остаются dirty (в следующий раз)
  → мелкие: создать delta packs (только изменённые файлы в рамках бюджета)
  → крупные: пересоздать только изменённые chunks
  → encrypt → erasure (n зависит от importance) → upload
  → dirty=false, обновить current_unit_id
  → старые units с изменёнными файлами → status=stale

VACUUM (раз в месяц, Scheduler → Packer)
  → найти stale packs где >50% файлов устарело
  → пересобрать: живые файлы → новые чистые packs
  → старые stale packs → delete с cooldown
```

### Пример lifecycle

```
Неделя 1: initial backup
  Pack A: [file1, file2, file3, file4, file5]  → в сети

Неделя 2: file2 и file4 изменились
  Pack A: всё ещё в сети (stale — 2 из 5 устарели)
  Pack B: [file2_v2, file4_v2]  → delta pack, в сети
  file2.current_unit = Pack B
  file4.current_unit = Pack B

Неделя 3: file1 изменился
  Pack A: stale (3 из 5 устарели)
  Pack B: живёт
  Pack C: [file1_v2]  → delta pack

Месяц 1: vacuum
  Pack A: 3/5 устарели → удалить
  Pack B, C: тоже stale после repacking
  Pack D: [file1_v2, file2_v2, file3, file4_v2, file5]  → чистый pack
```

### Restore

Каждый файл знает свой `current_unit_id`. Скачиваем только актуальные units:

```
file_id → current_unit_id → скачать unit → извлечь файл
```

Stale packs не нужны для restore (только для cooldown ransomware protection).

## Network (роль: peer)

Отвечает за отношения с партнёрами.

- Mailbox sync: при подключении к партнёру — sync iroh-docs, получить/отправить сообщения
- Relay: копировать сообщения для соседей (semi-epidemic, hop ≤ 2, identity allowlist)
- Trust engine: P (rolling 4wk), I (cumulative), S (pairwise GB ratio)
- PoS challenger: генерировать challenges для holder'ов своих шардов
- Peer management: bootstrap, peer exchange, allowlist (partners + 2 hops)

## Shard Manager (роль: owner)

Превращает units в шарды и управляет их lifecycle.

- Encrypt unit (ChaCha20-Poly1305, ключ из identity)
- Erasure code (Reed-Solomon, k-of-n, где n зависит от importance)
- Placement: выбрать n партнёров (weighted by trust)
- Upload: шарды стримятся партнёрам через iroh-blobs, не хранятся локально
- Repair: обнаружить потерянные шарды → пересоздать → разместить на новых партнёрах
- **Budget estimation:** оценка доступного бюджета сети (см. Budget Planner)

## Budget Planner (роль: owner)

Нода не может бекапить больше, чем сеть готова хранить. Budget Planner оценивает доступный бюджет и определяет, какие файлы бекапить в первую очередь.

### Оценка бюджета

```
Для каждого партнёра i:
  capacity_i = сколько он реально хранит наших шардов (из shard registry)
  headroom_i = оценка свободного места (из последнего PoS/handshake)
  willingness_i = trust_i × history_factor  (принимал ли раньше?)

budget_gb = Σ capacity_i + Σ min(headroom_i, expected_acceptance_i)
```

Точного бюджета не знаем (партнёры не обязаны сообщать), но есть сигналы:
- Сколько уже хранят (факт)
- Принимали ли новые шарды на прошлой неделе (тренд)
- Отказывали ли в placement (перегружены)

### Importance scoring

Каждый файл получает importance (0.0–1.0):

```
Конфигурация пользователя (папки → importance):
  ~/Documents/**          → 1.0
  ~/Photos/Favorites/**   → 0.9
  ~/Photos/**             → 0.5  (MVP: случайная выборка в рамках бюджета)
  ~/Videos/**             → 0.2
  ~/Downloads/**          → 0.1

Эвристики (v1, без ML):
  + favorited (EXIF rating, macOS favorites)  → +0.2
  + has faces (EXIF face regions)             → +0.1
  + rare moment (< 5 фото в этот день)       → +0.1
  + старое фото (> 3 лет)                    → +0.1
  + высокое разрешение                        → +0.05
  clamp(0.0, 1.0)
```

### Budget-aware backup strategy

```
1. Оценить budget_gb
2. Рассчитать required_gb для каждого файла:
     required_gb = file_size × (n/k)  где n зависит от importance
     importance ≥ 0.8 → 5-of-15 (×3.0 overhead)
     importance ≥ 0.4 → 5-of-10 (×2.0)
     importance ≥ 0.1 → 5-of-7  (×1.4)
     importance < 0.1 → не бекапить
3. Отсортировать файлы по importance (desc)
4. Включить в backup пока Σ required_gb ≤ budget_gb
5. Файлы ниже бюджета → не бекапятся, пока бюджет не вырастет
```

### Рост бюджета

По мере роста trust → партнёры охотнее принимают наши шарды → бюджет растёт → больше файлов попадает в backup. Пользователь видит прогресс:

```
Backup coverage:
  Documents:   100%  (5 GB, 15 replicas)
  Photos:       12%  (24 GB of 200 GB, top by importance)
  Video:         3%  (9 GB of 300 GB)
  Trust growing. Full backup estimated in ~4 months.
```

### Eviction priority (на стороне holder'а)

Когда holder'у не хватает места, он решает что удалить:

```
eviction_priority = importance × trust_of_owner × (1 + age_bonus)
age_bonus = min(weeks_stored / 26, 0.3)  // до +30% за полгода
```

Lowest priority → evict first. Hysteresis: evict только если new_priority > existing × (1 + H). Конкретный механизм hysteresis — определить экспериментально (Exp #27).

## Storage (роль: holder)

Отвечает за чужие шарды на моём диске.

- Принимать входящие шарды (inline ShardData или iroh-blobs) если есть место и owner в allowlist
- Отвечать на PoS challenges (hash(range + nonce) + merkle proof)
- Escrow: проверять weeks_in_network при restore request
- Shard lifecycle: active → marked-for-delete (cooldown 4wk) → deleted
- При нехватке места: дропать по приоритетам (2.8 в overview.md)
- Silent shards: owner замолчал — хранить если high I-score, дропать если low
- Storage warning: получил уведомление о bit rot → selfcheck, уведомить пользователя

### In-memory state Processor'а (промежуточные состояния протокола)

Processor держит в памяти промежуточные состояния для stateful протокольных flow:

```
pending_descriptors: HashMap<ShardId, SignedShardDescriptor>
  — holder side: сохраняется при shard_accept, используется при получении ShardData blob
  — удаляется после store_shard() или по таймауту

pending_shard_to_restore: HashMap<ShardId, (restore_id, shard_index)>
  — owner side: маппинг ожидаемых шардов к активному restore
  — удаляется при получении ShardData или restore_denied

pending_pos_challenges: HashMap<nonce, PendingPosChallenge>
  — owner side: отправленные PoS challenges, ожидающие ответа

pending_restores: HashMap<restore_id, PendingRestore>
  — owner side: активные restore операции (k шардов, буферы)
```

**Критично:** потеря промежуточного состояния (например, pending_descriptors) приводит к молчаливому отбрасыванию сообщений. ShardData от owner будет проигнорирован, если descriptor не сохранён при accept.

## Scheduler (периодические задачи)

```
Еженедельно:
  → Budget estimation: оценить budget_gb, обновить importance scoring
  → Weekly sync: Budget Planner → Packer → Shard Manager → upload
  → PoS sampling: для каждого партнёра → 5 случайных шардов → challenge
  → Trust update: агрегация P за неделю
  → Repair check: есть ли units с < n живых шардов?
  → Mailbox cleanup: удалить записи старше TTL (7 дней)
  → System state backup: обновить если были изменения

Ежемесячно:
  → Vacuum: пересобрать stale packs, delete старые с cooldown

Event-driven:
  → Подключение партнёра → sync mailbox, pending transfers
```

## Local DB (redb)

> Актуальная схема с индексными таблицами — см. ADR-003.

```
files:    file_id   → {path, hash, size, importance, dirty, current_unit_id,
                       last_backed_up, backed_up (bool)}
units:    unit_id   → {type(pack|chunk), status(active|stale|deleted),
                       member_files[], parent_file_id, chunk_index,
                       size, hash, created_at, importance_avg}
shards:   shard_id  → {unit_id, shard_index, holder_id, status, last_verified}
peers:    identity  → {node_id, trust_P, trust_I, trust_S, first_seen, last_seen, subnet}
holding:  shard_id  → {owner_pub, importance, size, state, received_at,
                       delete_requested_at}
budget:   singleton → {estimated_gb, last_calculated, placement_success_rate}
config:   key       → value
```

## Поток данных: repair

```
Scheduler: repair check
  → для каждого unit_id: сколько живых шардов?
  → если < n (но ≥ k): repair
    → unit = chunk? → пересоздать из локального файла (если не изменился)
    → unit = pack? → пересоздать из локальных файлов (если все на месте)
    → иначе: скачать k шардов от живых holders → восстановить unit → пересоздать
    → разместить на новых партнёрах
  → если < k: данные потеряны (не должно случиться при 5-of-15)
```

## System state backup

Зашифрованный снимок состояния ноды (размер зависит от количества файлов, см. overview.md §1.9), сам бекапится в сеть с максимальной redundancy. Обновляется еженедельно (или при существенных изменениях).

Содержимое: file manifest, shard map, trust state, peer directory.

Подробности: overview.md §1.9.

## Поток данных: disaster recovery

```
День 1: Новое устройство
  → syncback restore --seed "witch collapse practice..."
  → seed phrase → identity keypair (детерминированно)
  → подключение к seed nodes

День 1: System state recovery
  → seed nodes находят партнёров, знающих наш identity_pub
  → партнёры: "у меня system state shards для identity X"
  → скачать k шардов system state (минуты-часы в зависимости от размера архива)
  → расшифровать → file manifest + shard map + trust state + peer directory
  → нода знает ВСЁ: файлы, где шарды, кто партнёры, trust

День 1-14: Восстановление файлов
  → для каждого файла: current_unit_id → скачать k шардов unit'а
  → escrow check: I-score высокий (кумулятивный, не обнуляется) → ок
  → Reed-Solomon decode → расшифровка → извлечь файл из unit'а
  → приоритет: документы → фото → видео

Неделя 4+: Полная функциональность
  → trust к партнёрам стабилизируется (P накопится за 4 недели)
  → начинаем хранить чужие шарды → S восстановится
  → нода полностью функциональна
```

## Конфигурация пользователя

- Какие папки бекапить (include/exclude patterns)
- Сколько места отдать под чужие шарды (GB или % свободного)
- Seed nodes (default: hardcoded list)
- k и n (default: 5-of-15)
- Unit size U (default: 256 МБ)
- Sync frequency (default: weekly)
- Vacuum frequency (default: monthly)
- Bandwidth limit (default: без ограничений)
