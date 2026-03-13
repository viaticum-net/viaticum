# Alpha Limitations

Осознанные ограничения альфа-версии. Каждое — кандидат на исправление в будущем.

## Inline shard transfer (no iroh-blobs)

Шарды передаются целиком внутри CBOR-сообщения (`DirectBody::ShardData`). MAX_MESSAGE_SIZE = 64 MiB.

`ShardData` — двунаправленный message type:
- Upload flow (Owner → Holder): после shard_accept, owner отправляет blob через `NetCommand::UploadShard` → `connect_and_send` с `ShardData` message
- Restore flow (Holder → Owner): после RestoreRequest, holder отправляет blob через `NetCommand::SendDirect` с `ShardData` message

Получатель различает направления по наличию pending state: `pending_descriptors` (upload) или `pending_shard_to_restore` (restore).

**Последствия:**
- ~100 МБ RAM на один активный transfer (sender + receiver)
- Нет resume: обрыв = retry с нуля (~20с на шард при 20 Мбит/с)
- Нет verified streaming (BLAKE3 проверяется после получения, не в процессе)

**Когда станет проблемой:** при нестабильном соединении или если поднимать unit size выше 256 МБ.

**Решение:** iroh-blobs (content-addressed transfer с verified streaming и resume).

## No iroh-docs (gossip boards) → BoardProxy

iroh-docs объявлены в зависимостях, но не используются. Все board messages (shard_offer, shard_accept, shard_stored, pos_challenge, etc.) доставляются как `DirectBody::BoardProxy` — прямое QUIC-соединение, handshake, framed CBOR message.

**Механизм:** `NetCommand::PublishBoard { msg_type, payload, directed_to }` → network открывает connection к `directed_to`, отправляет `DirectMessage { body: BoardProxy(BoardProxyMsg { msg_type, payload }) }`. Получатель в `handle_direct_message` маршрутизирует по `msg_type` в `handle_board_message`.

**Последствия:**
- Оба peer должны быть онлайн одновременно для обмена сообщениями
- Нет gossip relay (peer_announce не распространяется — каждый пир знает только тех, к кому подключился)
- Peer discovery — ручное (ConnectPeer CLI команда)
- Каждое board message = новое QUIC connection + handshake (нет connection pool)

**Решение:** интеграция iroh-docs для board-based messaging (асинхронная доставка, gossip relay, offline message delivery).

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

## Trust bootstrap

Новые пиры получают `INITIAL_TRUST_P = 0.1` вместо 0. Без этого P=0, I=0 → combined trust = 0 → placement фильтрует всех → невозможно разместить ни одного шарда в свежей сети.

Combined trust нового пира = KP × 0.1 × 1.0 = 0.04 — достаточно для placement, но trust^2 = 0.0016 → вес при placement крайне низкий. Это "кредит доверия" — доказать надёжность можно только через PoS.

**Когда станет проблемой:** если INITIAL_TRUST_P слишком высокий — Sybil атака легче. Текущий 0.1 — компромисс.

## No file versioning

При изменении файла старый unit помечается stale, создаётся новый. Старые шарды удаляются по cooldown.

**Последствия:**
- Нельзя восстановить предыдущую версию файла (только текущую)

**Решение:** хранить несколько version-ов file_id, restore по timestamp.
