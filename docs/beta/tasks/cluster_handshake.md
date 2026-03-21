# Task: cluster_handshake — Handshake Extension + Dedup Integration (β Phase 3)

Это составной task, покрывающий три связанных изменения:
1. **HandshakeMsg extension**: добавить `device_cert: Option<DeviceCertificate>`
2. **Partner-side revocation check**: отклонять соединения от revoked device keys
3. **Dedup in BackupCoordinator**: перенаправить через `ClusterState.is_content_backed_up()`

---

## Часть 1: HandshakeMsg Extension

### Файл: `crates/syncback-core/src/messages/mod.rs`

### Изменение типа

**Текущий HandshakeMsg:**
```rust
pub struct HandshakeMsg {
    pub v: u8,
    pub identity_pub: IdentityPub,
    pub timestamp: Timestamp,
    pub sig: [u8; 64],
}
```

**Новый HandshakeMsg:**
```rust
pub struct HandshakeMsg {
    pub v: u8,
    pub identity_pub: IdentityPub,
    pub timestamp: Timestamp,
    /// Ed25519 signature. 64 bytes.
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
    /// Device certificate: master_key.sign(device_pub_key).
    /// Present when this node is part of a multi-device identity.
    /// Absent for single-device nodes (legacy compatibility).
    /// If present: identity_pub == certificate.device_pub_key (as IdentityPub),
    ///             and certificate.master_pub_key is the cluster master identity.
    #[serde(default)]
    pub device_cert: Option<DeviceCertificate>,
}
```

**Backward compatibility:** поле опциональное с `#[serde(default)]`. Старые nodes (без device_cert) могут подключаться к новым и работать как обычно — device_cert = None означает одиночный узел или не-кластерный пир.

### Изменение `build_handshake()`

**Текущая сигнатура:**
```rust
pub fn build_handshake(
    identity_pub: IdentityPub,
    timestamp: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
) -> HandshakeMsg
```

**Новая сигнатура:**
```rust
pub fn build_handshake(
    identity_pub: IdentityPub,
    timestamp: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
    device_cert: Option<DeviceCertificate>,
) -> HandshakeMsg
```

Добавляется параметр `device_cert: Option<DeviceCertificate>`. Подпись (`sig`) не меняется — покрывает только `"handshake" || identity_pub || timestamp`, как раньше. Сертификат не входит в подпись handshake (он самоподписан мастер-ключом).

**Сигнатура не меняется:** `verify_handshake()` остаётся без изменений — верифицирует только `sig` поле.

### Добавляем: `extract_cluster_identity()`

```rust
/// Extract the cluster master identity from a handshake message.
///
/// If device_cert is present and valid:
///   Returns Ok(Some(cert.master_pub_key))
/// If device_cert is None:
///   Returns Ok(None) — single-device node, identity_pub IS the master identity
/// If device_cert is present but invalid:
///   Returns Err(MessageError::BadSignature)
pub fn extract_cluster_identity(
    msg: &HandshakeMsg,
) -> Result<Option<IdentityPub>, MessageError>;
```

Логика:
```
if let Some(cert) = &msg.device_cert {
    // Verify the cert's signature
    let verifying_key = VerifyingKey::from_bytes(&cert.master_pub_key.0)?;
    // Verify cert signature (same as verify_device_certificate logic)
    // If invalid → Err(BadSignature)
    // Check consistency: cert.device_pub_key must match msg.identity_pub
    if cert.device_pub_key != msg.identity_pub.0 {
        return Err(MessageError::BadSignature);
    }
    Ok(Some(cert.master_pub_key))
} else {
    Ok(None)
}
```

---

## Часть 2: Handshake Extension in Daemon

### Файл: `crates/syncback/src/daemon/network/handshake.rs`

### Изменение `send_handshake_on_stream()`

**Текущая сигнатура:**
```rust
async fn send_handshake_on_stream(
    send: &mut iroh::endpoint::SendStream,
    signing_key: &SigningKey,
    our_identity: IdentityPub,
) -> Result<(), NetworkError>
```

**Новая сигнатура:**
```rust
async fn send_handshake_on_stream(
    send: &mut iroh::endpoint::SendStream,
    signing_key: &SigningKey,
    our_identity: IdentityPub,
    device_cert: Option<DeviceCertificate>,
) -> Result<(), NetworkError>
```

Вызывает `build_handshake(our_identity, now, signing_key, device_cert)`.

### Изменение `handshake_initiator()` и `handshake_acceptor()`

```rust
pub(super) async fn handshake_initiator(
    iroh_conn: IrohConnection,
    signing_key: &SigningKey,
    our_identity: IdentityPub,
    expected_identity: Option<IdentityPub>,
    device_cert: Option<DeviceCertificate>,  // добавлено
) -> Result<Connection, NetworkError>

pub(super) async fn handshake_acceptor(
    iroh_conn: IrohConnection,
    signing_key: &SigningKey,
    our_identity: IdentityPub,
    device_cert: Option<DeviceCertificate>,  // добавлено
) -> Result<Connection, NetworkError>
```

### Изменение `Connection` struct

`Connection` нужно сохранять cluster identity из handshake:

```rust
pub struct Connection {
    /// Peer's device-level IdentityPub (from handshake sig).
    pub peer_identity: IdentityPub,
    /// Peer's cluster master identity, if they are a cluster device.
    /// None if peer has no device_cert (single-device node).
    pub peer_master_identity: Option<IdentityPub>,
    // ... inner, send, recv
}
```

`peer_master_identity` заполняется из `extract_cluster_identity(&peer_handshake_msg)`.

### Revocation check в `recv_and_verify_handshake()`

Добавить параметр `revoked_check: Option<Arc<dyn Fn(&IdentityPub, &DeviceId) -> bool + Send + Sync>>`.

Или проще: revocation check вынести из handshake в более высокий уровень (в `NetworkHandle.connect()` или обработчик входящих соединений). После установки Connection → проверить `peer_identity` против revocation list.

**Рекомендация для простоты:** не менять `recv_and_verify_handshake`. Вместо этого:

После accept: если `conn.peer_master_identity == Some(known_identity)`, проверить против `PeerRecord.revoked_device_ids`. Это делается в принимающем коде daemon (процессор входящих соединений), не в handshake.rs.

### Изменение `NetworkHandle.start()`

```rust
pub struct NetworkConfig {
    pub signing_key: SigningKey,
    pub known_peers: HashMap<IdentityPub, EndpointAddr>,
    /// Optional device certificate for cluster nodes.
    pub device_cert: Option<DeviceCertificate>,  // добавлено
}
```

`NetworkHandle` хранит `device_cert: Option<DeviceCertificate>` и передаёт его в `send_handshake_on_stream`.

---

## Часть 3: Partner-Side Revocation Check

### Файл: `crates/syncback/src/daemon/network/mod.rs` (или обработчик входящих)

После успешного handshake (accept side), перед добавлением в connection pool:

```rust
// Pseudo-code in accept loop or connection dispatcher:
let conn: Connection = handshake_acceptor(...).await?;

// If peer presented a cluster cert, check for revocation
if let Some(master_id) = conn.peer_master_identity {
    let peer_record = db.get_peer(&master_id)?;
    if let Some(pr) = peer_record {
        // Check if this device is in revoked list for this peer
        if pr.revoked_device_ids.contains_device_pub(&conn.peer_identity) {
            warn!("rejecting revoked cluster device {}", conn.peer_identity);
            drop(conn);
            return; // или Err(HandshakeFailed)
        }
    }
}
```

Вспомогательный метод для `PeerRecord`:
```rust
impl PeerRecord {
    /// Check if a device IdentityPub is in revoked list.
    pub fn is_device_revoked(&self, device_identity: &IdentityPub) -> bool {
        // Comparison: RevocationCertificate.device_id is DeviceId (16 bytes),
        // but connection uses device_pub_key (32 bytes) as IdentityPub.
        // DECISION NEEDED: the revocation cert contains device_id (random 16 bytes),
        // but in handshake we have device_pub_key (32 bytes).
        // We need to match these. Two options:
        //   A) Store revoked device_pub_keys (32 bytes) in PeerRecord
        //   B) Store DeviceId separately and match by device_id
        // Recommended: store revoked_device_pub_keys: Vec<[u8; 32]>
        // (the 32-byte pub key from the device cert, not the 16-byte device_id)
        self.revoked_device_pub_keys.contains(&device_identity.0)
    }
}
```

### Расширение PeerRecord (types.rs)

```rust
pub struct PeerRecord {
    // ... existing fields ...
    /// Device public keys we know are revoked for this peer identity.
    /// Populated when we receive a valid RevocationCertificate via relay board.
    #[serde(default)]
    pub revoked_device_pub_keys: Vec<[u8; 32]>,
}
```

### Обработка incoming relay "device_revocation"

В `relay/mod.rs` при получении broadcast entry:

```rust
// In daemon's relay message processor:
if msg_type == "device_revocation" {
    let cert: RevocationCertificate = from_cbor(&entry.payload)?;
    // Find PeerRecord by cert.master_pub_key
    if let Some(mut peer) = db.get_peer(&IdentityPub(cert.master_pub_key.0))? {
        // Verify the revocation cert
        verify_revocation(&cert, &IdentityPub(cert.master_pub_key.0))?;
        // Look up the device_pub_key from any known DeviceCertificate
        // Problem: we only have device_id (16 bytes), not device_pub_key (32 bytes)
        // DECISION NEEDED (see below)
    }
}
```

**DECISION NEEDED:** Revocation broadcast содержит `RevocationCertificate` с `device_id` (16 байт), но нам нужен `device_pub_key` (32 байта) для сравнения при handshake.

**Рекомендация:** расширить relay broadcast для revocation, включив `DeviceCertificate` в payload:

```rust
/// Payload for relay board "device_revocation" broadcast.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RevocationBroadcast {
    /// The revocation itself.
    pub revocation: RevocationCertificate,
    /// The original device cert (so recipients can extract device_pub_key).
    /// Must have been issued by revocation.master_pub_key.
    pub device_cert: DeviceCertificate,
}
```

Верификация на принимающей стороне:
1. `verify_revocation(&broadcast.revocation, &peer_identity)` — signature valid
2. `verify_device_certificate(&broadcast.device_cert, &peer_identity)` — cert valid
3. `broadcast.revocation.device_id == broadcast.device_cert.device_id` — same device
4. Добавить `broadcast.device_cert.device_pub_key` в `PeerRecord.revoked_device_pub_keys`

Добавить тип в `messages/mod.rs`:
```rust
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RevocationBroadcast {
    pub revocation: syncback_core::cluster::RevocationCertificate,
    pub device_cert: syncback_core::cluster::DeviceCertificate,
}
```

---

## Часть 4: Dedup Integration in BackupCoordinator

### Файл: `crates/syncback/src/daemon/backup/events.rs`

**Текущая деdup-логика** в `handle_added_or_modified()`:
```rust
let all_files = self.db.list_all_files()?;
let dedup_match = all_files
    .iter()
    .find(|r| r.versions.iter().any(|v| v.content_hash == content_hash));
```

Это уже работает и охватывает single-device dedup. Для multi-device кластера это также работает, поскольку все устройства используют одну DB.

**Что нужно изменить:** убедиться что при dedup проверяется `backed_up_at.is_some()`, то есть файл действительно уже загружен, а не просто стоит в очереди.

**Текущая проблема:** `is_content_backed_up()` в `ClusterState` уже делает правильную проверку (включая `backed_up_at.is_some()`). Нужно использовать именно её вместо inline сканирования.

### Изменения в BackupCoordinator

Добавить опциональный `ClusterState` в конфигурацию или как параметр:

```rust
pub struct BackupConfig {
    // ... existing fields ...
    /// Optional cluster state for dedup check (multi-device).
    /// If None: use inline DB scan (single-device backward compat).
    pub cluster_state: Option<Arc<tokio::sync::Mutex<ClusterState>>>,
}
```

В `handle_added_or_modified()`:

```rust
// Dedup check via ClusterState if available, else inline scan
let is_backed_up = if let Some(cs) = &self.config.cluster_state {
    // ClusterState handles both single-device and multi-device dedup
    let guard = cs.blocking_lock(); // or restructure to async
    guard.is_content_backed_up(&content_hash)?
} else {
    // Existing inline scan for backward compat
    let all_files = self.db.list_all_files()?;
    all_files.iter().any(|r| {
        r.versions.iter().any(|v| {
            v.content_hash == content_hash && v.backed_up_at.is_some()
        })
    })
};
```

**Замечание:** `BackupCoordinator` сейчас синхронный. `ClusterState` тоже синхронный (нет async). Если `Arc<Mutex<ClusterState>>` = `std::sync::Mutex`, тогда `lock()` синхронный. Использовать `std::sync::Mutex<ClusterState>`.

**Рекомендация:** использовать `Arc<std::sync::Mutex<ClusterState>>` в BackupConfig.

### find_source_block_for_content при dedup

При dedup match нужно найти `source_block_id` чтобы правильно заполнить новый `FileVersion`:

```rust
// In handle_dedup (existing method):
// Already works via existing.versions.find(content_hash).source_block_id
// No changes needed here — ClusterState.find_source_block_for_content()
// is a convenience helper that does the same thing
```

Метод `ClusterState.find_source_block_for_content()` можно использовать вместо прямого поиска по all_files, но это рефактор. Для Phase 3 минимальное изменение: убедиться что dedup check включает `backed_up_at.is_some()`.

---

## Test Scenarios

### Часть 1 тесты: `messages/tests.rs`

#### 1. `handshake_with_device_cert_round_trip`
```
master_key = derive_master_key(&[1u8; 32])
device_id = DeviceId([2u8; 16])
device_key = derive_device_key(&[1u8; 32], &device_id)
cert = issue_device_certificate(&master_key, device_id, device_key.verifying_key().to_bytes(), Timestamp(100))

msg = build_handshake(IdentityPub(device_key.verifying_key().to_bytes()), Timestamp(1000), &device_key, Some(cert))
bytes = frame_message(&Message::Handshake(msg.clone()))
decoded = unframe_message(&bytes)
assert decoded.Handshake.device_cert == Some(cert)
```

#### 2. `handshake_without_device_cert_backward_compat`
```
msg = build_handshake(identity, timestamp, &signing_key, None)
assert msg.device_cert == None
verify_handshake(&msg, now) == Ok(())
```

#### 3. `extract_cluster_identity_valid_cert`
```
cert valid, cert.device_pub_key == msg.identity_pub.0
extract_cluster_identity(&msg) == Ok(Some(cert.master_pub_key))
```

#### 4. `extract_cluster_identity_none_for_no_cert`
```
msg.device_cert = None
extract_cluster_identity(&msg) == Ok(None)
```

#### 5. `extract_cluster_identity_rejects_mismatched_device_pub`
```
cert.device_pub_key = [0xFF; 32] (differs from msg.identity_pub.0)
extract_cluster_identity(&msg) == Err(BadSignature)
```

#### 6. `extract_cluster_identity_rejects_invalid_cert_signature`
```
cert.signature[0] ^= 1
extract_cluster_identity(&msg) == Err(BadSignature)
```

#### 7. `revocation_broadcast_round_trip`
```
RevocationBroadcast { revocation, device_cert }
CBOR round-trip
decoded == original
```

### Часть 2 тесты: `network/tests.rs` (добавить)

#### 8. `handshake_initiator_includes_device_cert`
```
device_cert = Some(valid_cert)
Perform handshake pair (mock streams)
Acceptor's connection has peer_master_identity = Some(cert.master_pub_key)
```

#### 9. `handshake_without_cert_peer_master_identity_is_none`
```
device_cert = None
Acceptor's connection has peer_master_identity = None
```

### Часть 3 тесты: `network/tests.rs` или integration

#### 10. `revocation_check_rejects_revoked_device_pub_key`
```
PeerRecord { revoked_device_pub_keys: [[3u8; 32]], ... }
Incoming connection peer_identity = IdentityPub([3u8; 32])
Connection should be rejected / is_device_revoked returns true
```

#### 11. `peer_record_revoked_device_pub_keys_default_empty`
```
Old PeerRecord CBOR (without revoked_device_pub_keys field)
Deserialize with from_cbor_bytes
record.revoked_device_pub_keys == [] (via serde default)
```

### Часть 4 тесты: `backup/tests.rs` (добавить)

#### 12. `dedup_skips_file_already_backed_up`
```
DB has FileRecord with version { content_hash: H, backed_up_at: Some(Timestamp(100)) }
BackupCoordinator processes event for same content_hash H
Result: no new QueuedFile added, no new version created
```

#### 13. `dedup_does_not_skip_file_not_yet_backed_up`
```
DB has FileRecord with version { content_hash: H, backed_up_at: None }
BackupCoordinator processes event for same content_hash H
Result: file IS queued (backup not complete yet)
```

#### 14. `dedup_registers_second_device_for_same_content`
```
Device A backed up content H (backed_up_at: Some)
Device B events: new file with same H, different path
Result: new FileRecord created for Device B path, pointing to same source_block_id
        Device B listed in devices
        No symbol redistribution
```

---

## Зависимости между частями

```
Часть 1 (messages) ←── зависит от cluster types (DeviceCertificate, RevocationCertificate)
Часть 2 (handshake) ←── depends on Часть 1
Часть 3 (revocation check) ←── depends on Часть 1, cluster_state task (PeerRecord.revoked_device_pub_keys)
Часть 4 (dedup) ←── depends on cluster_state task (ClusterState.is_content_backed_up)
```

**Порядок реализации:** Часть 1 → Часть 2 → Часть 3 → Часть 4

---

## Затронутые файлы

| Файл | Изменение |
|------|-----------|
| `syncback-core/src/messages/mod.rs` | HandshakeMsg + device_cert, build_handshake, extract_cluster_identity, RevocationBroadcast |
| `syncback-core/src/types/mod.rs` | PeerRecord + revoked_device_pub_keys (default Vec) |
| `syncback/src/daemon/network/handshake.rs` | send_handshake_on_stream, handshake_initiator, handshake_acceptor |
| `syncback/src/daemon/network/mod.rs` | NetworkConfig + device_cert, Connection + peer_master_identity, revocation check |
| `syncback/src/daemon/network/connection.rs` | Connection struct update |
| `syncback/src/daemon/backup/mod.rs` | BackupConfig + cluster_state |
| `syncback/src/daemon/backup/events.rs` | handle_added_or_modified dedup logic |

---

## Замечания для имплементора

- `HandshakeMsg.device_cert` поле с `#[serde(default)]` обеспечивает backward compatibility — CBOR десериализует старые сообщения без device_cert как None.
- Сигнатура `build_handshake` меняется, но только в daemon слое, не в protocol-level verify. Все вызывающие места нужно обновить.
- `Connection.peer_master_identity` — CBOR не сериализуется (Connection не персистентен), поэтому serde не нужен.
- Тест 13 (`dedup_does_not_skip_file_not_yet_backed_up`) важен: race condition когда два устройства начали backup одного и того же файла одновременно. Оба должны дойти до конца, vacuum почистит дублированные символы (из design doc: "Known limitation β").
- Для Phase 3 достаточно что revocation check работает при новых входящих соединениях. Graceful disconnect уже active connections после revocation — отложить на Phase 4 или Phase 5.
