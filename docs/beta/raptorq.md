# RaptorQ в β: как это работает

*Решение принято: RS → RaptorQ. Этот документ = шпаргалка по конкретному дизайну.*

---

## Терминология

| α (старое) | β (новое) | Что это |
|------------|-----------|---------|
| Unit (32 МБ) | Source block | Данные для кодирования (файл или пачка файлов) |
| Shard | Symbol (encoding symbol) | Один кусок закодированных данных, T байт |
| shard_id | ESI (Encoding Symbol ID) | Идентификатор символа (число 0, 1, 2...) |
| k-of-n (фиксированно) | K source symbols, N distributed | K = минимум для decode, N = сколько раздали |
| Reed-Solomon | RaptorQ (RFC 6330) | Алгоритм erasure coding |

---

## Ключевые параметры

### T = 64 КБ (symbol size, фиксированный)

Один символ = 64 КБ = transfer unit = max message payload. Max для raptorq crate (u16).

### Source block = 128 МБ (единственный параметр)

Всё = source blocks по 128 МБ. Мелкие файлы → batch до 128 МБ. Крупные → chunk по 128 МБ.
K = 2048. Peak RAM ≈ 250 МБ (безопасно для слабых машин и NAS).
Max file size: нет ограничения.

### Формулы

```
K = 2048                                // фиксированный (128 МБ / 64 КБ)
K_eff = K + 3 = 2051                    // decode overhead
N = K_eff × overhead(importance)
overhead = 1.5 + importance × 1.5       // 1.5x..3.0x
reliability = P(Binomial(N, p) ≥ K_eff)
```

Overhead для 99.9% reliability при K=2048: ~1.55x. Max file size: нет ограничения.

---

## Группировка файлов

```
< 128 МБ   → batch до 128 МБ (по типу данных)
≥ 128 МБ   → chunk по 128 МБ
```

Нет ограничения на max file size.

Группируем по типу: фото с фото, документы с документами, видео с видео.

### Версионирование и vacuum (универсальные правила)

Файл изменился или удалён → новая версия в НОВУЮ пачку (старая не трогается).

Vacuum: >50% файлов в пачке невалидны → перепаковать актуальные, старую инвалидировать (cooldown → удалить символы). Periodic, не срочно.

### Конкретные числа

| Данные | chunks | K/chunk | imp | overhead | N/chunk | На holder'а (15) |
|--------|--------|---------|-----|----------|---------|-----------------|
| Batch фото 128 МБ | 1 | 2048 | 0.6 | 2.4x | 4922 | 328 sym (21 МБ) |
| Batch документов | 1 | 2048 | 0.9 | 2.85x | 5845 | 390 sym (25 МБ) |
| Видео 2 ГБ | 16 | 2048 | 0.3 | 1.95x | 3999 | 267 sym (17 МБ) ×16 |
| Видео 8 ГБ | 64 | 2048 | 0.2 | 1.8x | 3692 | 246 sym (16 МБ) ×64 |

### Placement формула

```
weight_i = trust_i / sqrt(1 - trust_i)      // mean-variance оптимум
share_i = weight_i / sum(all weights)
max_share = (1 - 1/overhead) × 0.85
max_per_holder = min(K_eff - 1, max_share × N)  // K_eff-1: больше бессмысленно (один holder = весь файл)
symbols_i = clamp(round(N × share_i), 1, max_per_holder)
```

При m ≤ 10 и N ≤ 100: точный DP-поиск (мгновенно, гарантированный оптимум).

Rebalancing = только добавление новых символов (новые ESI), не перенос старых.

---

## Как RaptorQ работает (механика)

### Encoding

1. Source block (зашифрованный файл/пачка) → разбить на K символов по T байт
2. Построить intermediate representation (LDPC+HDPC) — O(K)
3. Генерировать любое количество encoding symbols, каждый с ESI (0, 1, 2, ...)
4. **Systematic**: ESI 0..K-1 = source data в чистом виде. ESI ≥ K = repair symbols

### Decoding

1. Собрать любые K+2 символов (любые ESI, от любых holders)
2. Решить систему → восстановить source data — O(K)

### Ключевое свойство

Encoder может генерировать символ с **любым ESI в любое время**, имея только source data. Не нужно хранить промежуточное состояние. Файл на диске → сгенерируй символ ESI=999999 через год.

---

## Per-holder binding (anti-collusion)

### Атака без binding

K colluding holders собирают K символов → decode → хранят одну копию → regenerate для PoS. Redundancy = иллюзия.

### Защита

Каждый holder хранит **уникальную** версию символа:

```
stored_symbol = symbol XOR ChaCha20_stream(HKDF(source_block_id, holder_id))
```

- Дедупликация между holders невозможна
- CPU: бесплатно (ChaCha20 = ГБ/с)
- Restore: owner знает holder_id → XOR обратно → чистый символ
- Обязательно, не optional

---

## Pipeline

```
BACKUP:
  файл → zstd compress (streaming) → ChaCha20 encrypt (streaming) → source block
  → K = ceil(size / T), N = K × overhead(importance)
  → placement: выбрать holders по trust² × importance
  → per holder:
      generate symbols (ESI unique per holder)
      → XOR bind с holder-specific key
      → send (direct connection, 256 КБ за раз)
      → forget (RAM = 1 символ)

RESTORE:
  DB lookup: path → source_block_id → holders
  → escrow check (weeks_in_network)
  → collect K+2 symbols от holders
  → unbind (XOR back) → RaptorQ decode → decrypt → decompress → файл

REPAIR (файл на диске):
  generate new symbol (new ESI) → bind → send to new holder
  (не нужно ничего скачивать из сети!)

REPAIR (файл удалён):
  download K+2 symbols → unbind → decode → source block
  → generate new symbols → bind → send to new holders
```

---

## PoS (Proof of Storage)

```
Раз в неделю, per holder:

Owner:
  pick random ESI из esi_ranges этого holder'а
  → pos_challenge { source_block_id, esi: 47 }

Holder:
  read bound symbol ESI=47 from disk (256 КБ)
  → pos_response { esi: 47, data: [256 КБ] }

Owner verifies:
  Файл на диске → recompute symbol + binding → compare ✓ (хеши НЕ хранятся)
  Файл удалён → cooldown → PoS не делаем (символы скоро удалятся)
```

Bandwidth: 256 КБ × 15 holders = **3.75 МБ/неделю**. Ничто.

---

## DB модель

### Два слоя

```
HOT (RAM, ~1 МБ на 1000 файлов):
  file_id → { K, total_alive_symbols }
  (file_id, holder_id) → { symbol_count, status, last_pos }
  Все решения: placement, budget, repair, reliability

WARM (redb):
  FileRecord { file_id, path, importance, versions: [FileVersion] }
  FileVersion { content_hash, source_block_id, K, T, ts_created, ts_backed }
  SymbolPlacement { source_block_id, holder_id, esi_ranges, binding_seed, status }
  EventLog (append-only): placed / lost / verified events
```

Холодный слой (pos_hashes) убран: файл на диске → PoS на лету. Файл удалён → cooldown → символы удаляются, PoS не нужен.

### ESI ranges

Символы назначаются последовательно:
```
holder_A: [(0, 32)]                    // ESI 0-31, initial
holder_A: [(0, 32), (500, 5)]          // + repair symbols ESI 500-504
```

### Двойной индекс

```
file_holders: (file_id, holder_id) → symbol_count
holder_files: (holder_id, file_id) → symbol_count
```

"Holder B ушёл" → scan holder_files[B] → пересчёт reliability для всех файлов. Один scan.

### Сравнение с α

| | RS (α) | RaptorQ (β) |
|---|--------|-------------|
| 1000 файлов | ~50 МБ metadata | ~3.4 МБ metadata |
| Уровни entity | File → Unit → Shard | File → SymbolPlacement |
| Записей | 15,000 ShardRecord | 10,000 SymbolPlacement |

**15x меньше metadata.** Fungible символы → агрегаты вместо индивидуальных записей.

---

## Reliability: математика

### Формула

```
P(файл жив) = P(Binomial(N, p) ≥ K)
```

N = distributed symbols, K = needed for decode, p = peer survival (1 - churn_rate).

Если символы **на руках** — decode детерминистский (RS: 100%, RaptorQ: 99.98% при K+2).
Reliability = вопрос survival (будут ли K символов живы через год), не decode.

### Таблица (annual churn 30%, p=0.7)

| K | N | Overhead | P(жив через год) |
|---|---|----------|-----------------|
| 5 | 10 | 2.0x | 95.3% |
| 5 | 15 | 3.0x | 99.93% |
| 5 | 20 | 4.0x | 99.9994% |
| 200 | 480 | 2.4x | ~99.999% |
| 8000 | 15600 | 1.95x | ~100% |

### Большой K экономнее

| K | N для 99.9% | Overhead |
|---|-------------|----------|
| 5 | ~17 | 3.4x |
| 100 | ~170 | 1.7x |
| 1000 | ~1550 | 1.55x |

Закон больших чисел: больший K → меньший relative overhead.
Пачки (K=200) надёжнее отдельных файлов (K=20) при том же overhead.

---

## 16 преимуществ vs RS (summary)

1. **Динамический N** — генерируй символы без re-encode
2. **Нет перемножения вероятностей** — 1 файл = 1 source block (до 14 ГБ)
3. **Streaming RAM** — O(1 символ) вместо O(k×n)
4. **Symbol size ≠ RAM** — T = transport parameter
5. **Нет критических символов** — любые K годятся
6. **Гетерогенное хранение** — разное количество символов у разных holders
7. **Reliability = простая дробь** — alive/K
8. **Версионирование имплицитно** — через symbol generations
9. **Инкрементальная надёжность** — добавь символов без re-encode
10. **Repair = generate new** — не воссоздание конкретного потерянного
11. **Continuous importance** — overhead как функция, не 3 тира
12. **Проще DB** — 15x меньше metadata
13. **Symbol budget** — гранулярный placement
14. **Per-peer reliability** — "если holder уйдёт, reliability = X"
15. **Natural S-score** — считается в символах единого размера
16. **"Больше файлов, меньше overhead"** — continuous trade-off

## Недостатки

1. **Chunking для больших файлов** — source block=128МБ, файлы >128МБ нарезаются. P(файл)=P(chunk)^n. Видео 2ГБ=16 chunks, P^16
2. **Нет partial recovery** — K-1 = 0% (как RS)
3. **Repair без файла = скачать K** — как RS
4. **CPU** — бенчмарки raptorq crate нужны (для cold backup не критично)
5. **Зрелость** — raptorq crate ~200 stars (vs RS десятки production deployments)
6. **Probabilistic decode** — K+2 вместо exactly K (negligible)

---

## Решённые вопросы

1. **Бенчмарки raptorq crate** — K=2048: encode ~500мс, decode ~100мс (экстраполяция). GO.
2. **API crate** — streaming encode невозможен (Encoder::new(&[u8])). Решение: chunk по 128МБ, peak RAM ~250МБ.
3. **Placement** — `weight = trust/sqrt(1-t)`, cap = `(1-1/overhead)×0.85`, hard limit K_eff-1. Агент посчитал: +10-21pp vs uniform.
4. **T и block size** — T=64КБ (max crate), source block=128МБ, нет max file size.

## Открытые вопросы

1. Теория игр — доказать "20% менее надёжно > 10% надёжно"
2. Migration path α → β

## Историческая заметка (serendipity)

Исследование RaptorQ началось с идеи решить проблему RAM (α RS peak ~180 МБ). Теоретически RaptorQ поддерживает streaming encode O(1 символ), но crate `raptorq` требует весь source block в RAM. Peak RAM в β (~250 МБ) даже чуть больше чем в α.

Зато по дороге обнаружились 16 других преимуществ: динамический N, fungible символы, per-holder binding, непрерывная importance, 15x меньше DB metadata, repair без воссоздания конкретного символа, и др. Каждое отдельно стоит перехода.

RAM streaming — возможно через C FFI (nanorq, поддерживает mmap/stream). Post-β оптимизация если понадобится.
