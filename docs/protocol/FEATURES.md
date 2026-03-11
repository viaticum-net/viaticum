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
