# Backup flow: подробная схема

---

## 1. Обнаружение изменений

### Watcher (непрерывно)

fs-notify следит за backup-директориями. Классифицирует события:

```
Событие              Действие
──────────           ──────────────────────────
Файл создан          → dirty_files.insert(path, Added)
Файл изменён         → dirty_files.insert(path, Modified)
Файл удалён          → dirty_files.insert(path, Deleted)
```

**Debounce:** 30 минут после последнего события для path. Редактор сохраняет 10 раз — одна dirty entry. Импорт 50 фото за 5 минут — ждём 30 мин после последнего, потом flush.

**dirty_files** — set в RAM, периодически persist в DB (crash safety).

### Full scan (fallback)

Watcher может пропустить события (restart daemon'а, sleep, overflow буфера fs-notify).

При старте daemon'а: walk all backup dirs → content_hash каждого файла → сравнить с catalog → расхождения → добавить в dirty.

Не каждую неделю, только при restart.

---

## 2. Backup trigger

**Event-driven, НЕ раз в неделю.** "Постоянная времени = 1 неделя" — это про PoS/repair/trust, не про backup.

### Packing queues

Три очереди по типу данных:

```
photo_queue:    [img1.jpg, img2.jpg, ...]
document_queue: [report.docx, notes.md, ...]
large_files:    [video.mp4]                    // ≥128 МБ (source_block_size), сразу отдельно
```

### Flush условия (любое из)

```
1. Очередь ≥ source_block_size (128 МБ) → flush сразу (полная пачка)
2. Нет активности 1 час    → flush что есть (юзер закончил работу)
3. Прошло 24 часа           → flush что есть (fallback)

Min batch size: 1 МБ. Меньше — ждём до следующего flush.
```

---

## 3. BackupCoordinator: обработка dirty

```
for each (path, event) in dirty_files:

  DELETED:
    → FileRecord.local_state = Deleted(ts) на этом device
    → если ВСЕ devices = Deleted → start cooldown (4+4 = 8 недель)
    → никакой сетевой активности
    → done

  ADDED:
    → read file → content_hash = blake3(file)
    → dedup: content_hash уже в catalog?
      → да: добавить device/path в FileRecord → done (zero traffic)
      → нет: classify file type → добавить в packing queue

  MODIFIED:
    → read file → new content_hash
    → dedup: new content_hash уже в catalog?
      → да: добавить как новую версию → done (zero traffic)
      → нет: classify → packing queue
    → FileRecord.versions.push(new_version)
```

---

## 4. Packing → source blocks

```
Flush photo_queue (≥128 МБ или timer):
  files = photo_queue.drain()

  group into batches ~128 МБ:
    batch_1: [img1(5MB), img2(8MB), img3(3MB), ...] = ~128 МБ
    batch_2: [img11(10MB), img12(7MB), ...]          = ~128 МБ
    last_batch: [img45(3MB), img46(5MB)]              = ~8 МБ (< 50, ок)

  for each batch:
    plaintext = [PackIndex (CBOR)] + [file1 bytes] + [file2 bytes] + ...
    → zstd compress (streaming)
    → ChaCha20-Poly1305 encrypt (streaming)
    → ciphertext = source block
    → source_block_id = blake3(ciphertext)

Flush large_files:
  for each file ≥ 128 МБ (source_block_size):
    → compress → encrypt → own source block
```

---

## 5. Encode → placement → distribute

```
for each source_block:
  K = ceil(source_block_size / T)         // T = 64 КБ default
  N = K × overhead(importance)            // overhead = 1.5 + imp × 1.5

  // Placement
  holders = placement_engine.compute_allocation(
    candidates,
    weight: trust / sqrt(1 - trust),     // mean-variance optimum
    max_per_holder: min(K_eff - 1, concentration_cap × N),
    max_holders: 30,                      // MAX_HOLDERS_PER_BLOCK
    min_symbols: 32,                      // MIN_SYMBOLS_PER_HOLDER
  )
  // Symbols allocated proportionally to weight (NOT equally!)

  // ESI allocation
  esi_offset = 0
  for each holder:
    esi_range = (esi_offset, holder.symbols_allocated)
    esi_offset += holder.symbols_allocated

    // Generate + encrypt + send
    for esi in esi_range:
      symbol = raptorq.encode(source_block, esi)
      bound = symbol XOR ChaCha20(HKDF(source_block_id, holder_id))

      try direct_connection(holder):
        send(bound)                        // 64 КБ
      fail:
        queue symbol_offer via epidemic relay
        // holder подберёт offer → direct connection позже → send
```

---

## 6. Holder принимает символы

```
Holder получает symbol_offer:
  → проверить: есть ли место? (effective_quota)
  → проверить: eviction priority нового > min existing?
  → accept / reject

Holder получает символы:
  → verify: hash(received) matches expected
  → store to disk
  → update held_symbols DB
  → send symbol_stored confirmation

Owner получает confirmation:
  → SymbolPlacement.status = Alive
  → RAM hot: total_alive += symbols_stored
  → EventLog: Placed { source_block_id, holder_id, esi_range }
```

---

## 7. DB updates (summary)

```
После успешного backup cycle:

FileRecord:
  new: { path, importance, devices: [(this_device, Present)],
         versions: [{ content_hash, source_block_id, ts }] }
  или: existing → добавить version / добавить device

SourceBlock:
  new: { block_id, K, T, type: Pack{index}/Single, status: Active }

SymbolPlacement × N_holders:
  new: { holder_id, esi_ranges, binding_seed, status: Alive }

EventLog:
  append: Placed events

RAM hot:
  BlockAgg: { K, total_alive }
  PlacementAgg: { symbol_count, status, last_pos }
```

---

## 8. Одна картинка

```
         Watcher (fs-notify, continuous)
                  │
                  ▼
         dirty_files (RAM + persist)
                  │
         debounce 30 мин
                  │
                  ▼
         BackupCoordinator
                  │
      ┌───────────┼────────────┐
      ▼           ▼            ▼
   DELETED     DEDUP?      ADDED/MODIFIED
   → mark      → skip      │
   → cooldown   (zero       classify by type
                traffic)    │
                    ┌───────┼────────┐
                    ▼       ▼        ▼
                 photos   docs    large files
                 queue    queue   (immediate)
                    │       │        │
              ──────┼───────┼────────┼──── flush trigger:
              │  ≥128MB / 1hr idle / 24hr fallback
              │  min batch: 1 МБ
                    │       │        │
                    ▼       ▼        ▼
                  batch   batch   source
                  ~128MB   ~128MB   block
                    │       │        │
                    └───────┼────────┘
                            ▼
                   compress → encrypt → source block
                            │
                            ▼
                   RaptorQ encode (K symbols, N total)
                            │
                            ▼
                   per-holder ChaCha20 bind
                            │
                   placement (trust/√(1-t) weight)
                            │
                   ┌────────┼────────┐
                   ▼        ▼        ▼
                holder   holder   holder
                online   online   offline
                → send   → send   → relay offer
                → stored → stored → send later
                            │
                            ▼
                   DB update: FileRecord, SourceBlock,
                   SymbolPlacement, EventLog, RAM hot
```

---

## 9. Timing примеры

```
Фотограф импортировал 50 фото (500 МБ):
  17:00 — импорт
  17:01 — watcher: 50 dirty
  17:30 — debounce expired
  17:31 — flush: 4 batches × 128 МБ
  17:35 — encode + distribute done
  Итого: 35 минут от импорта до backed up.

Один документ изменился (200 КБ):
  10:00 — save
  10:30 — debounce expired
  10:30 — < 1 МБ in queue → ждём
  ... ещё 3 документа за день ...
  18:00 — 1 час нет активности → flush (4 файла, 800 КБ < 1 МБ → ждём)
  Следующий день 10:30 — 24hr fallback → flush что есть
  Или: ещё файлы добавились → ≥ 1 МБ → flush.

Видео 2 ГБ:
  20:00 — file created
  20:30 — debounce expired
  20:31 — ≥ 128 МБ (source_block_size) → 16 source blocks
  20:35 — encode (K=2048, N≈3999 при imp=0.3)
  20:40 — distribute to 15 holders (~260 МБ each)
  ~21:00 — backed up (зависит от upload speed)
```
