# Уроки тестирования: слабые места

Документ собран по результатам 5-нодового smoke-теста (2026-03-13).
Цель — запомнить, где были баги, чтобы при переписывании знать, на что ставить тесты.

## 1. Trust bootstrap (chicken-and-egg)

**Проблема:** Новые пиры получали P=0, I=0 → combined trust = 0 → placement фильтрует всех по `> 0.0` → ни один пир не проходит → шарды не размещаются.

**Причина:** Система не допускала "кредит доверия" — новый пир ничем не отличался от заблокированного.

**Решение:** `INITIAL_TRUST_P = 0.1` → combined = KP × 0.1 = 0.04 — ненулевой, но низкий.

**Урок:** Любая формула с произведением может дать 0 при 0 в любом множителе. Тест `placement_with_all_new_peers_succeeds` — ОБЯЗАТЕЛЕН.

## 2. Placement: уникальные пиры vs слоты

**Проблема:** Старый placement требовал N уникальных пиров. При 4 пирах и n=17 (5-of-17 erasure coding) — невозможно.

**Причина:** Код не учитывал `MAX_SHARDS_PER_PARTNER = 6`. Каждый пир может держать до 6 шардов одного юнита.

**Решение:** Пул с capacity: 4 пира × 6 = 24 слота ≥ 17. При выборе пира декрементируем capacity.

**Урок:** При малом числе пиров multi-shard-per-peer — не edge case, а основной сценарий. Тест: `placement_4_peers_n17_succeeds`.

## 3. Framing: CBOR без length prefix

**Проблема:** `BoardProxy` сообщения сериализовались через `to_cbor()` (голый CBOR), но `send_direct_payload` писал байты как есть. Получатель читал первые 4 байта как u32 BE length prefix → 0xA2626964 = 2.7 ГБ → `message too large`.

**Причина:** `to_cbor()` vs `frame_message()` — первая возвращает чистый CBOR, вторая добавляет u32 BE prefix. Путаница в API.

**Решение:** Заменить `to_cbor(&proxy)` на `frame_message(&proxy)`.

**Урок:** Два функции сериализации с разными контрактами — ловушка. Тест: `board_proxy_message_roundtrip_over_wire` — сериализовать, десериализовать через framing. Или лучше: сделать `to_cbor` приватной и экспортировать только `frame_message`.

## 4. UploadShard — stub в production path

**Проблема:** `NetCommand::UploadShard` был заглушкой `debug!("not yet implemented")`. Shard_accept приходил, blob upload ставился в очередь, но данные не отправлялись.

**Причина:** UploadShard реализовывался через iroh-blobs (Phase 3), но в alpha используем inline transfer. Stub остался.

**Решение:** Inline ShardData через direct connection (connect → handshake → ShardData message).

**Урок:** Stub'ы в продовом пути — молчаливые баги. Логирование `debug` недостаточно. Минимум: `warn!` или `error!` для нереализованных команд на пути данных. Или лучше: compile-time проверка что все варианты enum реализованы (не через `_ =>`).

## 5. ShardData — holder не различал upload и restore

**Проблема:** `DirectBody::ShardData` на получателе обрабатывался только как restore (ищем в `pending_shard_to_restore`). Для upload (holder получает blob от owner) не было обработки → `"no pending restore, ignoring"`.

**Причина:** Один message type для двух flows. В restore owner получает ShardData, в upload holder получает ShardData.

**Решение:** Проверяем оба пути: если есть в `pending_shard_to_restore` → restore flow, если есть в `pending_descriptors` → upload flow.

**Урок:** Когда один message type используется в обе стороны — всегда тестировать оба направления. Тест: `holder_receives_shard_data_and_stores`.

## 6. Holder не хранил descriptor при accept

**Проблема:** При `shard_offer → Accept → shard_accept`, holder не сохранял `SignedShardDescriptor`. Когда blob приходил, не было descriptor'а для `storage.store_shard()`.

**Причина:** В протоколе "accept" — лёгкое решение (проверка квоты). Дескриптор нужен позже для hash verify и создания HoldingRecord.

**Решение:** `pending_descriptors: HashMap<ShardId, SignedShardDescriptor>` — заполняется при accept, удаляется при получении blob.

**Урок:** Stateful протокол требует хранения промежуточного состояния. Тест: `shard_offer_accept_stores_descriptor`.

## 7. Docker + socat: JSON escaping

**Проблема:** `echo '{"cmd":"status"}'` через `docker exec` не пробрасывался корректно. Shell в контейнере re-интерпретировал кавычки.

**Решение:** Пайпинг с хоста: `echo '...' | docker exec -i container socat - UNIX:sock`.

**Урок:** Не передавать JSON как аргумент shell-команды в Docker. Всегда stdin pipe.

## 8. CLI response format: flat vs nested

**Проблема:** Python-скрипт пытался `d.get('status_ok', {}).get('own_node_id')`, но ответ плоский: `{"status": "status_ok", "own_node_id": "..."}`.

**Причина:** `#[serde(tag = "status")]` в Rust делает flat discriminant, не обёртку.

**Урок:** Документировать wire format CLI ответов. Интеграционный тест: `cli_status_response_is_flat_json`.

## 9. Логи демона невидимы в detached mode

**Проблема:** `docker exec -d syncback daemon ...` — stderr теряется. Никаких ошибок не видно.

**Решение:** `docker exec -d sh -c '... 2>/tmp/daemon.log'`.

**Урок:** В e2e-тестах ВСЕГДА собирать логи. Иначе отладка слепая.

---

## Паттерны для будущих тестов

### Must-have интеграционные тесты

1. **Full pipeline: 2+ nodes, files → shards → stored** — то что только что заработало
2. **Trust bootstrap: new peers can receive shards** — P=0 ловушка
3. **Multi-shard placement with few peers** — 4 пира, n > 4
4. **BoardProxy roundtrip** — frame/parse через сеть
5. **ShardData bidirectional** — и upload (owner→holder) и restore (holder→owner)
6. **Holder stores blob and sends shard_stored** — полный holder-side flow

### Антипаттерны

- **Stub на data path** → должен быть минимум `warn!` или `unimplemented!`
- **Два формата сериализации** (`to_cbor` vs `frame_message`) → путаница
- **Один message type в обе стороны** → забыли handler для одного направления
- **Stateless accept** → потеряли descriptor между accept и blob arrival
- **Trust = 0 для новых пиров** → placement невозможен
