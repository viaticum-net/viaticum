# RaptorQ: шпаргалка (как конкретно работает)

---

## Терминология (новая vs альфа)

```
α                          β
─────────────────────      ─────────────────────
Unit (32 MB chunk)     →   Source block (весь файл или пачка файлов)
Shard                  →   Symbol (encoding symbol)
shard_id               →   ESI (Encoding Symbol ID, число 0, 1, 2...)
k-of-n (фиксированно) →   K source symbols, N total distributed
Reed-Solomon encode    →   RaptorQ encode
```

---

## Ключевые параметры

### T = 64 КБ (symbol size, фиксированный)

Один символ = 64 КБ = transfer unit = max message payload.
Max для raptorq crate (u16 limit).

### Source block = 128 МБ (default, configurable)

Всё = source blocks по 128 МБ (default):
- Мелкие файлы → batch до 128 МБ (по типу данных)
- Крупные файлы → chunk по 128 МБ

K = 2048 (128 МБ / 64 КБ) при дефолте.
Peak RAM ≈ 2× block size ≈ 250 МБ.
Max file size: нет ограничения (файл любого размера = чанки по block size).

**Configurable** через `config.toml`:
```toml
[backup]
source_block_size_mb = 128  # default; 32 for Raspberry Pi, 256 for beefy NAS
```

| Block size | K | Peak RAM | Overhead (99.9%) |
|-----------|-----|---------|-------------------|
| 128 МБ | 2048 | ~250 МБ | ~1.55x |
| 64 МБ | 1024 | ~130 МБ | ~1.57x |
| 32 МБ | 512 | ~65 МБ | ~1.60x |

T=64КБ всегда. Holders не знают про block size — совместимость полная.

### Формулы

```
K = 2048                                // фиксированный (128 МБ / 64 КБ)
K_eff = K + 3 = 2051                    // decode overhead
N = K_eff × overhead(importance)
overhead = 1.5 + importance × 1.5       // 1.5x..3.0x
```

Overhead для 99.9% reliability при K=2048: ~1.55x.

---

## Группировка файлов

```
< 128 МБ  → batch до 128 МБ (по типу данных)
≥ 128 МБ  → chunk по 128 МБ
```

Нет ограничения на max file size. Файл 20 ГБ = 160 чанков по 128 МБ.

### По типу данных

Фото с фото, документы с документами, видео с видео.

### Версионирование и vacuum

```
Файл изменился или удалён → новая версия в НОВУЮ пачку (старая не трогается)
Vacuum: >50% файлов в пачке невалидны (обновлены/удалены)
  → перепаковать актуальные в новую пачку
  → старую инвалидировать (cooldown → удалить символы)
```

---

## Конкретные числа

```
Данные                  chunks  K/chunk  imp   overhead  N/chunk  На holder'а (15)
──────────────────────  ──────  ───────  ────  ────────  ───────  ────────────────
Batch 128 МБ фото       1       2048    0.6   2.4x      4922    328 sym (21 МБ)
Batch 128 МБ документов 1       2048    0.9   2.85x     5845    390 sym (25 МБ)
Видео 2 ГБ              16      2048    0.3   1.95x     3999    267 sym (17 МБ) ×16
Видео 8 ГБ              64      2048    0.2   1.8x      3692    246 sym (16 МБ) ×64
```

K = 2048 всегда (source block = 128 МБ). Overhead для 99.9% reliability: ~1.55x.

---

## Placement: формула распределения символов

### Вес holder'а

```
weight_i = trust_i / sqrt(1 - trust_i)
```

Не trust² (слишком агрессивно концентрирует). `t/sqrt(1-t)` = mean-variance оптимум:
больше надёжным, но с штрафом за риск.

### Concentration cap

```
max_share = (1 - 1/overhead) × 0.85      // 85% от теоретического потолка
max_per_holder = min(K_eff - 1, max_share × N)

// K_eff-1: больше бессмысленно (один holder = весь файл)
// max_share: portfolio diversification
```

| Overhead | Теор. потолок | Cap (×0.85) |
|----------|---------------|-------------|
| 1.5x     | 33%           | 28%         |
| 2.0x     | 50%           | 42%         |
| 2.4x     | 58%           | 49%         |
| 3.0x     | 67%           | 57%         |

### Алгоритм

```
1. weight_i = trust_i / sqrt(1 - trust_i)
2. share_i = weight_i / sum(all weights)
3. symbols_i = clamp(round(N × share_i), 1, max_per_holder)
4. Redistribute excess from capped holders to uncapped
5. При m ≤ 10 и N ≤ 100: запустить точный DP (мгновенно, гарантированный оптимум)
```

### Пример (batch 256 МБ, N=9838, overhead=2.4x, cap=49%)

```
Holder   trust   weight   share    symbols   доля
──────   ─────   ──────   ─────    ───────   ────
NAS      0.95    4.36     27%      2656      27%
Desktop  0.80    1.79     11%      1082      11%
Peer C   0.70    1.28     8%       787       8%
Peer D   0.60    0.95     6%       590       6%
...остальные 11 peers...
                                   ─────
                                   9838 ✓
```

### Rebalancing = только добавление (не перенос)

```
Trust упал → НЕ забираем символы (они валидны)
  → генерируем новые (новые ESI) → размещаем у более надёжных
  → total_alive растёт → reliability растёт

Trust вырос → можно добавить ещё символов у этого holder'а

Удаление: только holder evict (disk pressure) или PoS fail
```

---

## PoS (Proof of Storage)

```
Owner:
  pick random ESI из esi_range holder'а
  → pos_challenge { source_block_id, esi: 47 }
  → timeout: 7 дней

Holder:
  read bound symbol ESI=47 from disk (64 КБ)
  → pos_response { esi: 47, data: [64 КБ] }

Owner verifies:
  Файл на диске → recompute symbol + binding → compare ✓
    (хеши НЕ хранятся в DB — вычисляются на лету!)
  Файл удалён → cooldown → PoS не делаем (символы скоро удалятся)

Частота — адаптивная per holder:
  challenges_per_week = base × volume_factor × trust_factor
  volume_factor = ceil(holder_symbols / 1000)
  trust_factor  = 2.0 - trust
```

---

## Anti-collusion: per-holder binding

```
stored_symbol = symbol XOR ChaCha20(HKDF(source_block_id, holder_id))
```

Два слоя шифрования:
1. ChaCha20-Poly1305 — шифрование файла (confidentiality + integrity)
2. Per-holder ChaCha20 — binding к holder'у (anti-collusion)

CPU: бесплатно (ChaCha20 = ГБ/с). Обязательно, не optional.

---

## Selective restore

```
syncback restore photos/vacation/                   -- папка
syncback restore photos/img.jpg                     -- файл
syncback restore photos/img.jpg --version 2         -- конкретная версия
syncback restore photos/img.jpg --date 2026-01-15   -- ближайшая к дате

Flow:
  1. DB lookup: path prefix → FileRecords
     photos/vacation/ → [img1.jpg, img2.jpg, ..., img47.jpg]

  2. Выбрать version per file:
     --version N → конкретная
     --date D    → ближайшая ≤ D
     default     → последняя

  3. FileVersion → source_block_id
     Deduplicate source_blocks: 47 файлов в 3 batches → скачать 3, не 47

  4. Per source_block:
     → найти holders (SymbolPlacement, status=Alive)
     → escrow check (trust-based)
     → collect K_eff symbols (parallel, от разных holders)
     → unbind → RaptorQ decode → decrypt → decompress

  5. Извлечь файлы:
     Pack → PackIndex → offset + size → extract
     Single → весь source block = файл

  6. Записать на диск, FileRecord.local_state = Present
```

Оптимизация: шаг 3. Файлы из одного batch = один download.
Friction: restore одного файла = скачать весь batch (128 МБ). Для cold backup — ок.

---

## Incremental backup: когда и как

```
Watcher (continuous):
  fs event → debounce 30 мин → dirty_files set

Backup trigger — event-driven, НЕ раз в неделю.
"Неделя" = постоянная времени для PoS/repair/trust, не для backup.

Packing queue per file type (photos, docs, video):
  Flush условие (любое из):
    1. Очередь ≥ source_block_size (128 МБ) → flush сразу (полная пачка)
    2. Нет активности 1 час    → flush что есть
    3. Прошло 24 часа           → flush что есть (fallback)
  Min batch size: 1 МБ.

Dedup: content_hash уже в catalog? → skip (zero traffic)
```

---

## DB модель

### Два слоя (без cold — PoS хеши не нужны)

```
HOT (RAM):
  source_block_id → { K, total_alive_symbols }
  (source_block_id, holder_id) → { symbol_count, status, last_pos }

WARM (redb):
  FileRecord { file_id, path, importance, devices, versions: [FileVersion] }
  FileVersion { content_hash, source_block_id, K, T, ts_created, ts_backed }
  SourceBlock { block_id, K, T, type: Pack{index}/Single, status }
  SymbolPlacement { source_block_id, holder_id, esi_ranges, binding_seed, status }
  EventLog (append-only)
  Indices: file→holders, holder→files
```

### Объём (5 ТБ фотограф, 500K файлов, source block=128 МБ)

```
Source blocks: ~35K
DB records: 35K × 15 holders = 525K SymbolPlacement
FileRecords: 500K × 150 B = 75 МБ
SymbolPlacement: 525K × 110 B = 58 МБ
Total DB: ~133 МБ
RAM hot: ~13 МБ
Peak encode RAM: ~250 МБ
```

---

## Одна картинка

```
┌─────────────────────────────────────────────────────────┐
│ Source block 128 МБ (batch фото, importance=0.6)        │
│                                                         │
│ → compress → encrypt → ~120 МБ source block             │
│                                                         │
│ → RaptorQ(K=2048, T=64KB) → K_eff=2051 → N=4922        │
│                                                         │
│ ESI: 0..327  │ 328..655  │ ...  │ 4594..4921            │
│ ─────────────┼───────────┼──────┼─────────────          │
│ Holder A     │ Holder B  │ ...  │ Holder O              │
│ w=4.36 (NAS) │ w=1.79    │      │ w=0.29                │
│ 328 sym      │ 328 sym   │      │ ~150 sym               │
│ bound:XOR(A) │ XOR(B)    │      │ XOR(O)                │
│                                                         │
│ Placement: weight = trust / sqrt(1-trust)               │
│ Cap: min(K_eff-1, (1-1/2.4)×0.85×N)                    │
│                                                         │
│ PoS: "Holder A, give me ESI=153" → 64 КБ → verify ✓    │
│ Repair: symbol lost → generate new ESI → send           │
└─────────────────────────────────────────────────────────┘
```
