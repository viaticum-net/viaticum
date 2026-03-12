# Фичи на потом (post-MVP)

Не входят в MVP, но записаны для реализации.

---

## Importance ranking

**MVP:** случайная выборка в рамках бюджета (какие файлы бекапить если бюджет < 100%).

**v1 (эвристики, без ML):**
- Favorited (EXIF rating, macOS favorites) → +0.2
- Has faces (EXIF face regions) → +0.1
- Rare moment (< 5 фото в этот день) → +0.1
- Старое фото (> 3 лет) → +0.1
- Высокое разрешение → +0.05

**v2+ (ML):** open-source модель для importance scoring. Обучение на пользовательских сигналах (какие файлы открывают, шарят, редактируют). Отдать на open-source сразу — community допилит.

---

## Relay transfer (скачать через друга)

**Проблема:** нужен шард с holder'а X, но owner и X никогда не пересекаются онлайн (разные часовые пояса, нестабильное подключение).

**Решение:** owner просит партнёра-посредника Y скачать шард и отдать.

```
Owner → доска: relay_request { shard_id, holder_id, ts, sig_owner }
Partner Y видит запрос, знает holder X
Partner Y: iroh-blobs pull(shard_id) от holder X
Partner Y: iroh-blobs serve(shard_id) для owner
Owner: pull(shard_id) от partner Y
Owner: verify blake3(blob) == shard_id ✓
```

**Безопасность:** шард зашифрован — посредник не может прочитать. Целостность гарантирована BLAKE3 (content-addressed). Посредник не может подменить данные.

**Мотивация посредника:** помощь повышает S-score (transfer counted as storage cooperation). Или просто доброта — партнёр и так хранит наши данные.

**Ограничения:**
- Посредник тратит свой bandwidth → rate limit (N relay requests / week)
- Только для партнёров (не произвольных нод)
- Посредник может отказать (не обязан)

---

## Personal Cluster

Key derivation от master seed, device registration, синхронизация metadata между устройствами одного пользователя. Протокол видит кластер как одну identity.

---

## Pluggable transports

Tor, BLE, mesh networking — когда iroh добавит поддержку или через альтернативный transport adapter.

---

## Bandwidth throttling / QoS

Ограничение bandwidth на уровне демона. Полезно для мобильных подключений и metered connections.

---

## File versioning

При изменении файла — хранить N предыдущих версий (не только текущую). Cooldown на delete старых версий (ransomware protection).

---

## Hop-based allowlist

Принимать сообщения только от identity в пределах hop ≤ 2 от своих партнёров. Сейчас allowlist строится по списку партнёров и их соседей вручную; в post-MVP — автоматическая фильтрация на основе hop-поля relay-записей.

---

## Observability / telemetry (P1)

Сбор статистики и наблюдение за сетью — для разработчиков, не для пользователей. Приоритет #1.

- Churn rate (ноды приходят/уходят за неделю)
- PoS success rate (глобальный и per-node)
- Trust distribution (гистограмма, outliers)
- Shard health (сколько шардов ниже k, repair needed)
- Storage utilization (отдано vs получено, S ratio distribution)
- Latency метрики (PoS response time, restore time)
- Placement efficiency (offer → accept/reject ratio)

Формат: `syncback stats --json` + opt-in отправка на endpoint.

---

## Reliability forecast (P1)

Прогноз вероятности restore через 1/3/6 месяцев на основе текущего churn, trust, erasure tier. Per-file и per-folder.

`syncback status --forecast`:
```
photos/       97.2% (1m)  95.8% (3m)  93.1% (6m)
documents/    94.1% (1m)  91.3% (3m)  87.5% (6m)
```

Предупреждение если прогноз ниже порога: "добавьте партнёров", "файл X нуждается в re-placement".
Так же полезная метрика - можно восттановить 33(лучших, когда буедт оценка) из 100 фотографий в папке. То есть не какова вероятность что восстановим конкретный файл, а сколько файлов получится восстановить.

---

## Selective restore (P1)

Восстановление конкретного файла или папки, а не всего бекапа. Must-have для реального использования.

- `syncback restore photos/vacation/`
- `syncback restore document.pdf --version 2` (когда будет versioning)
- Требует file catalog с маппингом file → shards → holders

---

## Progress / ETA (P2)

При restore показывать прогресс: какие шарды скачаны, сколько осталось, примерное время.

---

## Notifications (P3)

"Шард потерян, repair запущен", "trust с нодой X упал", "диск заполняется". Push/email/telegram. Для гиков.

---

## Invite flow

Простой onboarding для friends-and-family: "вот ссылка, установи, мы станем партнёрами". Дополнение к bootstrap через seed ноды.

---

## Groups / circles

Объединение 5-10 друзей в группу с общим dashboard. "Семейный бекап".

---

## Geo-diversity

Placement учитывает географию — не все шарды в одном городе/стране. Защита от локальных катастроф.

---

## Health dashboard

Сколько шардов здоровы, какие нуждаются в repair, общая reliability estimate. CLI: `syncback health`.

---

## Deduplication

Одинаковые блоки между файлами хранить один раз. Экономия для похожих файлов.

---

## Compression

Сжатие перед erasure coding. Не для фото/видео, но для документов/кода значительный выигрыш.

---

## Streaming restore

Начать использовать файл до полного восстановления (для больших файлов).

---

## Restore dry run (P2)

Периодическая проверка что restore реально работает end-to-end. Скачать шарды, собрать файл, сравнить hash, удалить. Автоматически по расписанию.

- PoS проверяет что шард жив, но не проверяет full download pipeline
- Dry run одновременно тестирует bandwidth/availability холдеров
- Если шард хранится (PoS pass), но скачать нельзя за разумное время — холдер де-факто бесполезен → снижение trust
- `syncback restore --dry-run photos/`

---

## Lossy fallback backup (P1)

При недостатке trust/budget на полный бекап — бекап сжатых фото/видео на лету. Теряем качество, но память сохранена. Киллер-фича.

- Фото: resize JPEG (например 4000px → 1200px, ~10x экономия)
- Видео: transcode → lower bitrate/resolution (4K → 720p, ~10x)
- Оригинал остаётся локально, compressed = fallback в сети
- По мере роста trust/budget — постепенная замена compressed → original
- Приоритет замены: importance ranking (важные файлы → оригинал первыми)

Сценарий: 50GB фото, budget на 10GB. Без фичи: 10GB в оригинале, 40GB потеряны. С фичей: все 50GB сохранены (в сжатом виде).

---

## Dead man's switch / inheritance

Если owner не появляется в сети X месяцев — передача доступа доверенным лицам.

- Seed phrase разбивается через Shamir's Secret Sharing на N частей, порог M (любые M из N восстанавливают секрет)
- Каждое доверенное лицо получает свою часть оффлайн (бумага, USB)
- Daemon мониторит активность owner'а (PoS, бекапы)
- Через X месяцев неактивности — уведомление доверенным через board
- M доверенных собираются, объединяют части → seed → расшифровывают бекап
- Split делается при init: `syncback seed split --threshold 2 --shares 3`
- Daemon-часть минимальна — только мониторинг и оповещение

---

## Local bit rot detection

Периодическая проверка целостности локальных файлов. Обнаружить повреждение на собственном диске до того как повреждённая версия попадёт в бекап.

- `syncback verify --local`
- Сравнение hash файлов с сохранёнными в каталоге
- Уведомление: "файл X повреждён, восстановить из бекапа?"

---

## Private network (закрытая группа)

Полностью изолированная сеть для своих: семья, компания друзей, малый бизнес. Протокол тот же, но без публичного discovery — только участники видят друг друга.

- Своя seed нода, свой bootstrap
- Whitelist identity keys (только явно добавленные участники)
- Нет случайных нод, нет открытого discovery
- `network_mode = "private"` в конфиге

Отличие от Personal Cluster (одна identity, несколько устройств) и Groups (dashboard поверх открытой сети).
