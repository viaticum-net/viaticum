# Alpha Limitations

Осознанные ограничения альфа-версии. Каждое — кандидат на исправление в будущем.

## Inline shard transfer (no iroh-blobs)

Шарды передаются целиком внутри CBOR-сообщения (`DirectBody::ShardData`). MAX_MESSAGE_SIZE = 64 MiB.

**Последствия:**
- ~100 МБ RAM на один активный transfer (sender + receiver)
- Нет resume: обрыв = retry с нуля (~20с на шард при 20 Мбит/с)
- Нет verified streaming (BLAKE3 проверяется после получения, не в процессе)

**Когда станет проблемой:** при нестабильном соединении или если поднимать unit size выше 256 МБ.

**Решение:** iroh-blobs (content-addressed transfer с verified streaming и resume).

## No iroh-docs (gossip boards)

iroh-docs объявлены в зависимостях, но не используются. Peer discovery, PoS challenges, shard offers — всё через прямые соединения.

**Последствия:**
- Нет асинхронной доставки сообщений (оба peer должны быть онлайн)
- Нет gossip relay (peer_announce не распространяется)
- Peer discovery — ручное (ConnectPeer)

**Решение:** интеграция iroh-docs для board-based messaging.

## In-memory packer и RAM profile

Всё обрабатывается in-memory: файл → zstd compress → encrypt → RS encode → шарды → transfer.

**RAM по режимам (unit = 32 МБ, k=5):**

| Режим | Peak RAM | Что в памяти |
|---|---|---|
| Idle | ~50-100 МБ | runtime, redb mmap, iroh |
| Backup (5-of-7) | ~110 МБ | plaintext + compressed + ciphertext + 7 шардов |
| Backup (5-of-15) | ~160 МБ | plaintext + compressed + ciphertext + 15 шардов |
| Restore | ~100 МБ | k шардов + ciphertext + compressed + plaintext |
| Holder receive | ~10 МБ | 1 шард в CBOR buffer (~6.4 МБ) |

**Когда станет проблемой:** параллельные операции, unit size > 32 МБ.

**Оптимизации (по приоритету):**
1. Шарды на диск после RS encode — читать по одному для transfer
2. Streaming compress+encrypt — не читать весь файл целиком
3. Streaming RS — encode по мере шифрования
4. Restore шарды на диск — RS decode читает с диска

## No file versioning

При изменении файла старый unit помечается stale, создаётся новый. Старые шарды удаляются по cooldown.

**Последствия:**
- Нельзя восстановить предыдущую версию файла (только текущую)

**Решение:** хранить несколько version-ов file_id, restore по timestamp.
