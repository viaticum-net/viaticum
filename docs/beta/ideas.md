# Идеи и исследования для β и далее

*Собрано из notes.md + research-post-alpha.md. Проработанные идеи вынесены в отдельные документы.*

---

## Проработано (отдельные документы)

- **RaptorQ** → `docs/beta/raptorq.md` (16 преимуществ, anti-collusion, DB модель)
- **Personal Cluster** → `docs/beta/personal_cluster.md` (device keys, revocation, peer-to-device affinity)
- **Два инстанса из одного сида** → решается Personal Cluster (device keys)

---

## Тестовые кейсы (из α, частично покрыто E2E)

- [x] Мелкие файлы в одну шарду
- [x] Восстановление
- [x] Re-backup после изменения файла
- [x] PoS
- [ ] NAT traversal (отложено)
- [ ] Сборка шард при восстановлении от нескольких пиров
- [ ] Работа сообщений при асинхронном online
- [ ] Вытеснение, квоты, удаление
- [ ] Chunk restore (файлы >32 МБ, баг)

---

## Непроработанные идеи

### Lossy media + erasure coding

Есть ли алгоритмы сжатия фото/видео с подмешанным erasure coding? Много копий = хорошее качество, мало = плохое. Аналогия с радиосвязью, цифровым ТВ.

**Проблема:** encrypt-then-split ломает progressive decode. Шифрование делает partial ciphertext бесполезным. Вероятно несовместимо с нашей архитектурой.

**Альтернатива:** lossy fallback backup (resize фото/видео перед бекапом при нехватке бюджета) — проще и не конфликтует с шифрованием. См. `docs/alpha/FEATURES.md`.

### Малая закрытая сеть (post-β)

2-5 друзей без публичной сети. Другие trade-offs: мало holders → concentration limit (K_eff-1) становится реальным ограничением. Возможно нужна другая стратегия placement: один holder с полной копией + erasure coding по остальным, или простая репликация вместо RaptorQ. Отдельный сценарий с отдельными правилами.

### Configurable block size (β, Phase 1)

Source block size в config.toml, default 128 МБ. Единственная ручка для RAM:

| Block size | K | Peak RAM | Overhead (99.9%) |
|-----------|-----|---------|-------------------|
| 128 МБ | 2048 | ~250 МБ | ~1.55x |
| 64 МБ | 1024 | ~130 МБ | ~1.57x |
| 32 МБ | 512 | ~65 МБ | ~1.60x |
| 16 МБ | 256 | ~35 МБ | ~1.65x |

Raspberry Pi (512 МБ RAM) → block=32 МБ, overhead чуть выше (+3%), зато влезает. T=64КБ всегда (фиксирован). Holders не знают про block size — хранят символы по 64 КБ. Совместимость полная.

### Variable T (post-β)

β: T=64КБ фиксированный, source block=128МБ. Меньший T при том же chunk size → больший K → меньший overhead (1.55x→1.45x). Или variable T по размеру файла: мелкие T=4КБ (K=32768), крупные T=64КБ (K=2048). Усложняет логику, прирост ~5-10% overhead. Исследовать если overhead станет узким местом.

### PoS для удалённых файлов / "pin backup" (post-β)

β: файл удалён → cooldown → символы удаляются → PoS не делаем. Если добавить "pin backup" (сохранить бекап навсегда, даже если файл удалён локально) — нужен pos_hashes cold layer: хранить хеши символов для верификации без локального файла.

### Symbol storage layout (tech debt)

Как хранить символы на диске: отдельные файлы vs один файл на source_block (seek по offset) vs дерево директорий (hash-based sharding). Для β: один файл на source_block (просто, достаточно). Оптимизировать при масштабировании.

### Smart vacuum (post-β)

β: простое правило (>50% невалидных в пачке → перепаковать). За годы использования может накопиться много "полумёртвых" пачек. Нужны более умные правила: приоритеты vacuum по типу данных, частота, disk IO budget, сетевая нагрузка на redistribute символов. Отдельная задача.

### Optional email publication

Разрешить пользователям опционально публиковать свой email:
- Можно написать человеку просьбу о помощи (аварийное восстановление)
- Можно пообщаться живьём со своим доверенным партнёром
- Человеческое доверие поверх алгоритмического

Минус — анонимность. Опционально.

### Edge case: гонка SymbolDropped vs PosNack (β, Phase 2)

При вытеснении символов holder может одновременно послать `SymbolDropped` и ответить `PosNack` на pending challenge. Два сигнала о потере одних и тех же символов — порядок прихода не определён.

**Сценарии:**

```
A) PosNack приходит первым:
   Owner → NotHeld → marks placement as lost → starts repair
   Позже: SymbolDropped → placement уже lost → idempotent, ignore

B) SymbolDropped приходит первым:
   Owner → marks placement as lost → starts repair
   Позже: PosNack → placement уже lost → idempotent, ignore

C) SymbolDropped приходит, но challenge был ДО вытеснения:
   Holder получил challenge когда символ ещё был → PosResponse (Pass)
   Owner получает SymbolDropped → marks as lost → starts repair
   Позже: PosResponse (Pass) → символ WAS valid, но теперь lost
   → Accept Pass для trust (он ответил честно), но repair не отменять
```

**Решение:** idempotent transitions. `Stored → Lost` — однонаправленный переход. Повторный `Lost` — no-op. RepairAgent проверяет текущий статус placement перед действием.

**Ключевое правило:** `SymbolDropped` авторитетен. Даже если `PosResponse(Pass)` пришёл позже — символы уже потеряны на момент получения `SymbolDropped`.

---

## Исследовательские вопросы

### 1. Bandwidth throttling

**Verdict: не нужно.** Естественные защиты протокола достаточны:
- PoS timeout (7 дней) ловит крайние случаи → trust decay
- Placement by trust → медленные ноды получают меньше шардов
- Erasure coding → restore не зависит от одной ноды
- Нет рационального incentive throttle'ить

### 2. Commitment spectrum

Вместо binary accept/reject, холдер отвечает commitment level ∈ [0.0, 1.0]. High commitment + drop = big penalty. Low commitment + drop = expected.

**Проблема:** incentive to lie (всегда говори 0.3). Нужен game theory analysis.

**Связь с RaptorQ:** частично решается иначе — символы fungible, потеря одного не критична.

**Verdict:** deferred. Requires dedicated research if goes forward.

### 3. Explicit negotiations

**Verdict: не нужно.** Silent negotiation через trust + S достаточно. Explicit negotiations добавляют complexity без identified benefit.

### 4. Formal methods — game theory, combinatorics

Применить формальную математику к модели:
- Доказать что trust formula incentive-compatible
- Доказать что freeloading long-term unprofitable
- Доказать что "20% менее надёжно > 10% надёжно" (optimal symbol budget)
- Доказать что per-holder binding делает collusion невыгодной
- Optimal placement как комбинаторная оптимизация
- Closed-form формулы для restore probability vs network size/churn

**Порядок:** β работает → formalize current model → game theory для новых механик.

### 5. Restore drill — защита от вымогательства holder'ов

Периодическое учебное восстановление: owner эмулирует restore, запрашивая символы у holders пока файл ещё доступен локально.

**Цель:** обнаружить holders, которые отказывают в выдаче (неожиданный escrow, вымогательство, молчание). Поскольку файл ещё у owner'а — потери нет, можно безопасно:
1. Пометить отказавшего holder'а низким trust
2. Запустить repair: сгенерировать новые символы из локального файла, разместить на честных holders
3. Со временем "вымогатель" теряет все размещения и leverage

**Почему работает:** атака "храню и жду рестор → требую $$$" строится на том, что owner узнаёт об отказе только в момент реальной нужды (когда локального файла уже нет). Drill переносит обнаружение в безопасный момент.

**Частота:** редко (cold backup, time constant = 1 week). Достаточно ~1 drill на файл в месяц. Можно совмещать с PoS циклом.

**Отличие от PoS:** PoS проверяет "хранишь ли ты символ". Drill проверяет "отдашь ли ты символ". Разные вопросы — holder может честно хранить и проходить PoS, но отказать в restore.

### 6. Теория игр для importance-balance-eviction

Кажется мы делаем два раза одно и то же (importance + eviction). Может можно проще, учитывая что цель (часто, не всегда) — сохранить лучшие 10-20% архива, с допустимой случайностью.

Связано с RaptorQ "больше файлов, меньше overhead" стратегией.
