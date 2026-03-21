# Task: cluster_sync — Daemon-Level Cluster Synchronization (β Phase 3)

Module: `crates/syncback/src/daemon/cluster_sync/`
Files: `mod.rs` + `tests.rs`

---

## Назначение

`ClusterSyncManager` — daemon-уровень, координирует обмен event log между устройствами одного кластера.
Использует существующий `NetworkHandle` (iroh transport) для direct connections.
Обновляет `ClusterState` полученными событиями.

**Не является** универсальной peer-sync системой. Работает только между устройствами одной identity (cluster-internal).

---

## Зависимости

### Daemon-side:
- `crate::daemon::network::{NetworkHandle, Connection, NetworkError}` — iroh transport
- `syncback_core::cluster::ClusterState` — из cluster_state task
- `syncback_core::db::Db`
- `syncback_core::types::{IdentityPub, DeviceId, EventEntry, Timestamp}`
- `syncback_core::messages::{Message, frame_message, from_cbor}` — для cluster sync messages

### Новые message types (добавить в `syncback-core/src/messages/mod.rs`):
См. раздел "Message Types" ниже.

---

## Новые Message Types

Добавить в `syncback-core/src/messages/mod.rs`:

```rust
/// Initiator asks: "what events do you have after seq N?"
/// Sent by device that wants to sync from peer device.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClusterSyncRequestMsg {
    pub v: u8,
    /// Our device_id (so peer knows which device is asking).
    pub from_device_id: DeviceId,
    /// Last event sequence number we already have from this peer device.
    /// Peer will send events after this seq.
    /// 0 = "send everything".
    pub last_known_seq: u64,
    pub timestamp: Timestamp,
}

/// Response: batch of events after the requested seq.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClusterSyncResponseMsg {
    pub v: u8,
    /// Events from the responding device's event log, seq > last_known_seq.
    pub events: Vec<(u64, EventEntry)>,
    /// Responding device's current last seq (so caller knows if more events exist).
    pub responder_last_seq: u64,
    pub timestamp: Timestamp,
}
```

Добавить варианты в `Message` enum:
```rust
ClusterSyncRequest(ClusterSyncRequestMsg),
ClusterSyncResponse(ClusterSyncResponseMsg),
```

---

## Public API

```rust
// crates/syncback/src/daemon/cluster_sync/mod.rs

use std::collections::HashMap;
use syncback_core::cluster::ClusterState;
use syncback_core::db::Db;
use syncback_core::messages::{ClusterSyncRequestMsg, ClusterSyncResponseMsg, Message};
use syncback_core::types::{DeviceId, IdentityPub, Timestamp};
use crate::daemon::network::{NetworkHandle, Connection, NetworkError};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Error type for ClusterSyncManager.
#[derive(Debug, thiserror::Error)]
pub enum ClusterSyncError {
    #[error("network error: {0}")]
    Network(#[from] NetworkError),

    #[error("cluster state error: {0}")]
    ClusterState(#[from] syncback_core::cluster::ClusterStateError),

    #[error("message error: {0}")]
    Message(#[from] syncback_core::messages::MessageError),

    #[error("device not known: {device_id:?}")]
    DeviceNotKnown { device_id: DeviceId },

    #[error("peer identity mismatch: expected cluster device, got {got:?}")]
    NotClusterDevice { got: IdentityPub },

    #[error("sync timeout after {secs}s")]
    Timeout { secs: u64 },
}

/// Per-device sync cursor: last event seq we received from each peer device.
/// Keyed by the peer device's IdentityPub (its iroh transport identity = device_pub_key bytes).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncCursors {
    /// Map: peer_device_node_id → last known seq from that device.
    pub cursors: HashMap<IdentityPub, u64>,
}

/// Configuration for ClusterSyncManager.
#[derive(Clone)]
pub struct ClusterSyncConfig {
    /// This device's DeviceId.
    pub our_device_id: DeviceId,
    /// Max events per sync batch.
    pub batch_size: usize,
    /// Sync timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for ClusterSyncConfig {
    fn default() -> Self {
        ClusterSyncConfig {
            our_device_id: DeviceId([0u8; 16]),
            batch_size: 1000,
            timeout_secs: 30,
        }
    }
}

/// Manages event log exchange between devices in the same cluster.
pub struct ClusterSyncManager {
    db: Db,
    config: ClusterSyncConfig,
    /// Sync cursors persisted to DB (as part of cluster_state or separate key).
    cursors: SyncCursors,
    network: Arc<NetworkHandle>,
    /// Shared cluster state (also updated by other modules).
    cluster_state: Arc<Mutex<ClusterState>>,
}

impl ClusterSyncManager {
    /// Create a new manager.
    pub fn new(
        db: Db,
        config: ClusterSyncConfig,
        network: Arc<NetworkHandle>,
        cluster_state: Arc<Mutex<ClusterState>>,
    ) -> Self;

    // =========================================================
    // Outbound sync: we pull events from a peer device
    // =========================================================

    /// Sync with one peer device.
    ///
    /// Opens/reuses connection to peer_node_id, requests events after our cursor,
    /// applies received events to ClusterState.
    ///
    /// peer_node_id: IdentityPub of the peer device (its device key = iroh NodeId).
    ///   This is the IdentityPub used in NetworkHandle — for device-to-device connections
    ///   it's the device's IdentityPub (derived from device key), NOT the master IdentityPub.
    ///
    /// DECISION NEEDED: NetworkHandle currently maps IdentityPub → iroh EndpointAddr.
    ///   For cluster connections we need to route by device pub key (which IS used as
    ///   iroh NodeId since device_key = iroh transport key per architecture).
    ///   The caller must ensure peer_node_id is in NetworkHandle.known_peers.
    ///
    /// Returns number of events applied.
    pub async fn sync_with_device(
        &mut self,
        peer_identity: IdentityPub,
    ) -> Result<usize, ClusterSyncError>;

    /// Sync with all known cluster devices.
    ///
    /// Iterates active devices from ClusterState, skips our own device_id.
    /// Attempts sync with each; logs errors but continues.
    /// Returns map of device_identity → events_applied.
    pub async fn sync_all_devices(
        &mut self,
    ) -> HashMap<IdentityPub, Result<usize, ClusterSyncError>>;

    // =========================================================
    // Inbound sync: we serve events to a peer device
    // =========================================================

    /// Handle an incoming ClusterSyncRequest from a connected peer device.
    ///
    /// Validates that the requesting device belongs to our identity
    /// (its certificate must be in ClusterState.all_devices() and not revoked).
    /// Reads events after last_known_seq from our event log.
    /// Sends ClusterSyncResponse.
    ///
    /// conn: authenticated Connection (peer identity already verified by handshake).
    /// msg: decoded ClusterSyncRequestMsg.
    pub async fn handle_sync_request(
        &self,
        conn: &mut Connection,
        msg: ClusterSyncRequestMsg,
    ) -> Result<(), ClusterSyncError>;

    // =========================================================
    // Revocation broadcast
    // =========================================================

    /// Broadcast a revocation certificate to all known external peers via relay board.
    ///
    /// Called after revoke_device(). Uses RelayManager to post a broadcast entry.
    /// Payload: CBOR-serialized RevocationCertificate.
    /// msg_type: "device_revocation".
    ///
    /// relay: reference to the daemon's RelayManager (wrapped in Arc<Mutex<_>>).
    pub async fn broadcast_revocation(
        &self,
        revocation: syncback_core::cluster::RevocationCertificate,
        signing_key: &ed25519_dalek::SigningKey,
        relay: Arc<tokio::sync::Mutex<crate::daemon::relay::RelayManager>>,
        now: Timestamp,
    ) -> Result<(), ClusterSyncError>;

    // =========================================================
    // Device discovery
    // =========================================================

    /// Register a peer device's network address so we can connect to it.
    ///
    /// Called when we receive a PeerAnnounce from a device that shares our master_pub.
    /// Checks that the device's certificate is valid and not revoked.
    /// Updates NetworkHandle's known_peers (in practice: daemon passes updated config).
    ///
    /// Returns true if this device belongs to our cluster and was registered.
    pub async fn register_cluster_device_addr(
        &self,
        device_identity: IdentityPub,
        device_cert: &syncback_core::cluster::DeviceCertificate,
    ) -> Result<bool, ClusterSyncError>;

    // =========================================================
    // Cursor persistence
    // =========================================================

    /// Load sync cursors from DB (stored in cluster_state or budget singleton).
    /// Called at startup.
    pub fn load_cursors(db: &Db) -> SyncCursors;

    /// Persist current cursors to DB.
    fn save_cursors(&self) -> Result<(), ClusterSyncError>;
}
```

---

## Внутренняя логика

### `sync_with_device()` — полный flow

```
1. Посмотреть cursor: last_known_seq = cursors.get(peer_identity).unwrap_or(0)
2. get_connection(peer_identity) через NetworkHandle → получить Connection
3. Отправить ClusterSyncRequestMsg { from_device_id: our_device_id, last_known_seq, timestamp: now }
4. Получить ClusterSyncResponseMsg (с timeout_secs)
5. Если events.is_empty() → ничего не делать, return Ok(0)
6. cluster_state.lock().apply_events(&response.events) → N применено
7. cursors.insert(peer_identity, response.responder_last_seq)
8. save_cursors()
9. return Ok(N)
```

**Важно:** соединение уже аутентифицировано на уровне handshake через `NetworkHandle`. Дополнительная верификация identity не нужна.

### `handle_sync_request()` — серверная сторона

```
1. Проверить что msg.from_device_id принадлежит нашей identity:
   - cluster_state.lock().get_device(&msg.from_device_id).is_some()
   - cluster_state.lock().is_device_revoked(&msg.from_device_id) == false
   - Если нет → закрыть connection, return Err(NotClusterDevice)
2. events = db.events_after(msg.last_known_seq, config.batch_size)
3. responder_last_seq = db.last_event_seq()
4. Отправить ClusterSyncResponseMsg { events, responder_last_seq, timestamp: now }
```

### `broadcast_revocation()` — relay board

```
1. payload = to_cbor(&revocation)
2. msg_id = random [u8; 16]
3. relay.lock().add_broadcast_entry("device_revocation", msg_id, payload, our_identity, signing_key, now)
```

Партнёры при получении broadcast "device_revocation" с relay board должны:
- Декодировать `RevocationCertificate`
- Верифицировать подпись через `verify_revocation(&cert, &peer.identity)` (master pub = peer.identity)
- Добавить device_id в свой локальный revoked-list (peer-side revocation check)

**Замечание:** внешние пиры не имеют `ClusterState`. Для них revocation = "отказывать в restore/PoS для этого device_pub_key". Это реализуется в `handshake.rs` (см. Handshake Extension task).

### Cursor persistence

`SyncCursors` хранится как отдельная запись в таблице `CLUSTER_STATE` с ключом `"sync_cursors"`. Можно использовать тот же singleton подход что и `StoredClusterState`.

Альтернативно: добавить `sync_cursors: SyncCursors` в `StoredClusterState`. Проще.

**Рекомендация:** добавить `sync_cursors` поле в `StoredClusterState` (из cluster_state task) с `#[serde(default)]`. Тогда cursor save = просто обновить поле и `set_cluster_state`.

---

## Верификация принадлежности к кластеру

Peer device аутентифицируется на уровне handshake по своему `IdentityPub` (device key).
Для верификации что это наше устройство:

```
Peer.IdentityPub == DeviceEntry.device_pub_key (as IdentityPub)
```

Потому что в SyncBack архитектуре `device_key` = iroh transport key, и `IdentityPub` в handshake = verifying key от signing key. Device signing key → IdentityPub(device_key.verifying_key()).

Так что проверка:
```rust
let device_identity_bytes = conn.peer_identity.0; // peer's IdentityPub = device pub key
let is_cluster_device = cluster_state.all_devices()
    .iter()
    .any(|d| d.device_pub_key == device_identity_bytes);
```

---

## Relay: verifiable revocation on partner side

Когда внешний партнёр получает broadcast "device_revocation":
1. Декодирует `RevocationCertificate`
2. Находит `PeerRecord` с `identity == cert.master_pub_key`
3. Верифицирует `verify_revocation(&cert, &peer_identity)`
4. Если Ok → сохраняет revoked device_id в специальном поле `PeerRecord.revoked_devices: Vec<DeviceId>` (потребует расширения типа)

**DECISION NEEDED:** `PeerRecord` сейчас не имеет поля `revoked_devices`. Нужно добавить:
```rust
pub struct PeerRecord {
    // ... existing fields ...
    /// Device IDs we have revoked for this peer (received via relay broadcast).
    #[serde(default)]
    pub revoked_device_ids: Vec<DeviceId>,
}
```

Handshake при входящем соединении: проверить что device_pub_key incoming peer не в `PeerRecord.revoked_device_ids`. Если в списке → отклонить соединение.

---

## Test Scenarios

Тесты в `cluster_sync/tests.rs`. Тесты используют in-memory DB и mock network (без реального iroh).

### Вспомогательный паттерн: mock network
Для тестов без iroh: использовать `tokio::io::duplex` для создания пары связанных потоков.
Или тестировать через unit-тесты отдельных методов (handle_sync_request, apply_events logic).

### 1. `sync_request_msg_serialization_round_trip`
```
msg = ClusterSyncRequestMsg { v: 1, from_device_id: DeviceId([1u8;16]), last_known_seq: 42, timestamp: Timestamp(1000) }
bytes = to_cbor(&msg)
decoded: ClusterSyncRequestMsg = from_cbor(&bytes)
assert decoded == msg
```

### 2. `sync_response_msg_serialization_round_trip`
```
entry = EventEntry { timestamp: Timestamp(100), device_id: DeviceId([2u8;16]), event: Event::EpochRotated { epoch: 1 } }
msg = ClusterSyncResponseMsg { v: 1, events: vec![(5, entry)], responder_last_seq: 5, timestamp: Timestamp(200) }
round-trip via CBOR
assert decoded == msg
```

### 3. `handle_sync_request_returns_events_after_seq`
```
Setup:
  db with 5 events (seq 1..=5)
  cluster_state with device D1 registered
  conn.peer_identity = device D1's IdentityPub

msg = ClusterSyncRequestMsg { last_known_seq: 2, from_device_id: D1.device_id, ... }
Call handle_sync_request(mock_conn, msg)

Verify response: events contain seq 3, 4, 5 only
responder_last_seq == 5
```

### 4. `handle_sync_request_rejects_revoked_device`
```
device D1 registered and then revoked in cluster_state
msg from D1
handle_sync_request returns Err(NotClusterDevice)
```

### 5. `handle_sync_request_rejects_unknown_device`
```
msg from DeviceId([0xFF; 16]) (not in cluster_state)
returns Err(NotClusterDevice)
```

### 6. `cursor_advances_after_successful_sync`
```
Mock peer returns events (1, E1), (2, E2), (3, E3), responder_last_seq=3
Before sync: cursor for peer = 0
After sync_with_device: cursor for peer = 3
```

### 7. `sync_applies_epoch_rotated_to_cluster_state`
```
cluster_state: current_epoch = EpochCounter(0)
Peer sends events including EpochRotated { epoch: 1 }
After sync: cluster_state.current_epoch() == EpochCounter(1)
```

### 8. `sync_applies_device_revoked_to_cluster_state`
```
cluster_state: devices A and B (both active)
Peer sends event DeviceRevoked { device_id: A }
After sync: cluster_state.is_device_revoked(&A) == true
```

### 9. `sync_all_devices_skips_own_device`
```
cluster_state has devices: our_device + peer_device
sync_all_devices() connects only to peer_device (not to ourselves)
```

### 10. `sync_all_devices_continues_after_peer_error`
```
cluster_state has peer_A and peer_B
peer_A returns network error
peer_B is healthy
result: { peer_A: Err(_), peer_B: Ok(N) }
No panic, all results returned
```

### 11. `broadcast_revocation_posts_to_relay`
```
Mock RelayManager
broadcast_revocation(cert, &signing_key, relay, now)
relay.board contains entry with msg_type "device_revocation"
entry payload decodes to RevocationCertificate == cert
```

### 12. `register_cluster_device_addr_accepts_valid_cert`
```
device with valid cert (master_pub matches cluster_state.master_pub())
register_cluster_device_addr returns Ok(true)
```

### 13. `register_cluster_device_addr_rejects_wrong_master`
```
cert signed by different master key
register_cluster_device_addr returns Ok(false)
```

### 14. `register_cluster_device_addr_rejects_revoked`
```
device registered and revoked in cluster_state
register_cluster_device_addr returns Ok(false)
```

---

## Интеграция с daemon

Daemon создаёт `ClusterSyncManager` в `daemon/mod.rs`:
```rust
pub mod cluster_sync;
```

При обработке входящего соединения: если incoming `Message::ClusterSyncRequest(msg)` → передать в `manager.handle_sync_request(conn, msg)`.

Периодический sync (из scheduler): `manager.sync_all_devices().await`.

При revoke command из CLI: после `cluster_state.revoke_device(...)`, вызвать `manager.broadcast_revocation(cert, ...)`.

---

## Заметки для имплементора

- Реальный network тест (с двумя iroh endpoints) не нужен в Phase 3. Достаточно unit-тестов на protocol logic. Integration test — в Phase 5.
- Timeout реализовать через `tokio::time::timeout(Duration::from_secs(timeout_secs), ...)`.
- `ClusterSyncManager` должен быть `Send + Sync` (используется в async context с Arc<Mutex<_>>).
- Если `NetworkHandle` не поддерживает соединения с device keys напрямую (только внешние peers), то первоначально device-to-device sync можно сделать через специальный флаг в NetworkConfig. Или добавить метод `connect_to_device(EndpointAddr)` минуя peer directory check.
- В Phase 3 достаточно базового sync. Periodic auto-sync (через Scheduler) делается в Phase 4.
