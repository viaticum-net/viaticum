# Task: cluster_state — Stateful Cluster Registry (β Phase 3)

Module: `crates/syncback-core/src/cluster/` (extends existing module)
Files: `mod.rs` (add `ClusterState` struct) + `tests.rs` (add new tests)

---

## Назначение

`ClusterState` — stateful надстройка над существующими чистыми функциями кластера.
Хранит зарегистрированные устройства, эпохи, revocation list, peer-to-device affinity.
Персистентность через DB (event log + отдельная таблица `cluster_state`).

**Существующий код (`cluster/mod.rs`) не изменяется** — только добавляется новый struct.

---

## Зависимости

### Уже существует:
- `crate::cluster::{derive_master_key, derive_device_key, derive_epoch_key, master_identity}`
- `crate::cluster::{issue_device_certificate, verify_device_certificate}`
- `crate::cluster::{issue_revocation, verify_revocation}`
- `crate::cluster::{EpochCounter, DeviceCertificate, RevocationCertificate, EpochKey, ClusterError}`
- `crate::cluster::{next_epoch, epoch_for_time, esi_namespace_start, esi_namespace_end}`
- `crate::db::{Db, DbError}`
- `crate::types::{DeviceId, IdentityPub, Timestamp, Event, EventEntry, FileRecord}`

### Новые DB операции:
- Новая таблица `CLUSTER_STATE` (синглтон CBOR): `get_cluster_state()`, `set_cluster_state()`
- Существующая `append_event()`, `events_after()` — для синхронизации
- Существующая `list_all_files()` — для dedup check

### Cargo.toml: зависимости уже есть. Ничего нового.

---

## Новая DB таблица

Добавить в `crates/syncback-core/src/db/mod.rs`:

```rust
/// Cluster state singleton. Key = "cluster_state". Value = CBOR(StoredClusterState).
const CLUSTER_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("cluster_state");
```

Добавить в `Db::create_tables()`:
```rust
tx.open_table(CLUSTER_STATE)?;
```

Добавить два метода в `impl Db`:
```rust
pub fn get_cluster_state(&self) -> Result<Option<StoredClusterState>, DbError>;
pub fn set_cluster_state(&self, state: &StoredClusterState) -> Result<(), DbError>;
```

---

## Types

Все новые типы определяются в `cluster/mod.rs`.

```rust
/// Persistent snapshot of cluster state stored in DB.
/// Used for fast load at startup without replaying entire event log.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredClusterState {
    /// Our master public key (identifies the cluster/identity).
    pub master_pub: IdentityPub,
    /// All registered devices (including revoked).
    pub devices: Vec<DeviceEntry>,
    /// Current epoch counter.
    pub current_epoch: EpochCounter,
    /// Epoch rotation history: (epoch_counter, activated_at).
    /// Sorted ascending by activated_at.
    pub epoch_history: Vec<(EpochCounter, Timestamp)>,
    /// Revoked device IDs. Append-only (revocation is permanent).
    pub revoked_devices: Vec<DeviceId>,
    /// Peer-to-device affinity: which local device manages each external peer.
    pub peer_affinity: Vec<(IdentityPub, DeviceId)>,
    /// Last applied event log sequence number (for incremental sync).
    pub last_applied_seq: u64,
}

/// One registered device in the cluster.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceEntry {
    pub device_id: DeviceId,
    /// Device's Ed25519 public key (= iroh NodeId bytes).
    pub device_pub_key: [u8; 32],
    /// Certificate issued by master key.
    pub certificate: DeviceCertificate,
    /// Index assigned at registration (used for ESI namespace).
    /// Immutable once assigned. Range: 0..=15.
    pub device_index: u8,
}

/// Error type for ClusterState operations.
#[derive(Debug, thiserror::Error)]
pub enum ClusterStateError {
    #[error("db error: {0}")]
    Db(#[from] crate::db::DbError),

    #[error("cluster crypto error: {0}")]
    Cluster(#[from] ClusterError),

    #[error("device already registered: {0:?}")]
    DeviceAlreadyRegistered(DeviceId),

    #[error("device not found: {0:?}")]
    DeviceNotFound(DeviceId),

    #[error("device is revoked: {0:?}")]
    DeviceRevoked(DeviceId),

    #[error("max devices reached (limit: 16)")]
    MaxDevicesReached,

    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("not initialized")]
    NotInitialized,
}
```

---

## Public API

```rust
/// Stateful cluster registry. Persisted via Db.
pub struct ClusterState {
    db: crate::db::Db,
    /// In-memory snapshot (kept in sync with DB on every mutation).
    state: StoredClusterState,
}

impl ClusterState {
    // =========================================================
    // Initialization
    // =========================================================

    /// Load existing cluster state from DB.
    /// Returns Err(NotInitialized) if no state exists.
    pub fn load(db: crate::db::Db) -> Result<Self, ClusterStateError>;

    /// Initialize a new cluster (first device registration).
    ///
    /// master_pub: IdentityPub of this cluster (from derive_master_key → master_identity).
    /// first_device_cert: certificate for the first device (signed by master key).
    /// device_pub_key: Ed25519 public key of the first device.
    /// epoch0_activated_at: timestamp when epoch 0 became active (= now on first init).
    ///
    /// Persists to DB. Returns Err if state already exists.
    pub fn init(
        db: crate::db::Db,
        master_pub: IdentityPub,
        first_device_cert: DeviceCertificate,
        epoch0_activated_at: Timestamp,
        now: Timestamp,
    ) -> Result<Self, ClusterStateError>;

    // =========================================================
    // Device registry
    // =========================================================

    /// Register a new device. Appends DeviceAdded event.
    ///
    /// certificate must be signed by our master_pub.
    /// device_index is auto-assigned (next available 0..=15).
    /// Returns Err(DeviceAlreadyRegistered) if device_id already exists.
    /// Returns Err(MaxDevicesReached) if 16 devices already registered.
    /// Returns Err(InvalidCertificate) if signature verification fails.
    pub fn add_device(
        &mut self,
        certificate: DeviceCertificate,
        now: Timestamp,
    ) -> Result<(), ClusterStateError>;

    /// Revoke a device. Rotates epoch. Appends DeviceRevoked + EpochRotated events.
    ///
    /// revocation_cert must be signed by our master_pub.
    /// epoch_activated_at: timestamp when the new epoch takes effect (= now).
    /// Returns Err(DeviceNotFound) if device_id not registered.
    /// Returns Err(DeviceRevoked) if already revoked.
    /// Returns Err(InvalidCertificate) if signature verification fails.
    pub fn revoke_device(
        &mut self,
        revocation_cert: RevocationCertificate,
        epoch_activated_at: Timestamp,
        now: Timestamp,
    ) -> Result<(), ClusterStateError>;

    /// List all active (non-revoked) devices.
    pub fn active_devices(&self) -> Vec<&DeviceEntry>;

    /// List all devices (including revoked).
    pub fn all_devices(&self) -> &[DeviceEntry];

    /// Get device entry by device_id. None if not registered.
    pub fn get_device(&self, device_id: &DeviceId) -> Option<&DeviceEntry>;

    /// Check if a device is revoked.
    pub fn is_device_revoked(&self, device_id: &DeviceId) -> bool;

    // =========================================================
    // Epoch management
    // =========================================================

    /// Current epoch counter.
    pub fn current_epoch(&self) -> EpochCounter;

    /// Full epoch history (for epoch_for_time lookups).
    /// Returns slice of (epoch_counter, activated_at) sorted ascending.
    pub fn epoch_history(&self) -> &[(EpochCounter, Timestamp)];

    // =========================================================
    // Peer-to-device affinity
    // =========================================================

    /// Assign a peer to a device (or reassign).
    /// Persists to DB (updates StoredClusterState directly — not an event).
    pub fn set_peer_affinity(
        &mut self,
        peer: IdentityPub,
        device_id: DeviceId,
    ) -> Result<(), ClusterStateError>;

    /// Get the device managing a peer. None if no affinity set.
    pub fn peer_device(&self, peer: &IdentityPub) -> Option<DeviceId>;

    /// List all peers assigned to a specific device.
    pub fn peers_for_device(&self, device_id: &DeviceId) -> Vec<IdentityPub>;

    // =========================================================
    // Dedup
    // =========================================================

    /// Check if a content_hash is already backed up.
    /// Scans DB file catalog for any FileVersion with matching content_hash.
    /// Returns true if found (zero-traffic dedup).
    pub fn is_content_backed_up(
        &self,
        content_hash: &[u8; 32],
    ) -> Result<bool, ClusterStateError>;

    /// Find the source_block_id for an already-backed-up content_hash.
    /// Returns None if not backed up.
    pub fn find_source_block_for_content(
        &self,
        content_hash: &[u8; 32],
    ) -> Result<Option<crate::types::SourceBlockId>, ClusterStateError>;

    // =========================================================
    // Event log application
    // =========================================================

    /// Apply a batch of events from another device.
    /// Events are commutative: applying them in any order yields same final state.
    /// Unknown event variants are silently ignored (forward compatibility).
    ///
    /// After applying, persists updated state to DB and sets last_applied_seq.
    /// Returns count of events applied.
    pub fn apply_events(
        &mut self,
        events: &[(u64, EventEntry)],
    ) -> Result<usize, ClusterStateError>;

    /// Last applied event sequence number (per-device tracking is in ClusterSync).
    /// This is the local event log's last seq, used to tell peers what we have.
    pub fn local_last_seq(&self) -> Result<u64, ClusterStateError>;

    // =========================================================
    // Identity
    // =========================================================

    /// Our master public key.
    pub fn master_pub(&self) -> IdentityPub;

    /// ESI namespace for a device_id.
    /// Returns (start, end) ESI range for this device.
    /// Returns None if device not registered.
    pub fn esi_namespace(&self, device_id: &DeviceId) -> Option<(u32, u32)>;
}
```

---

## Внутренняя логика

### `init()`
1. Проверить что в DB ещё нет `cluster_state`.
2. Верифицировать `first_device_cert` через `verify_device_certificate`.
3. Создать `StoredClusterState` с `devices = [DeviceEntry { device_index: 0, ... }]`, `current_epoch = EpochCounter(0)`, `epoch_history = [(EpochCounter(0), epoch0_activated_at)]`.
4. `append_event(EventEntry { DeviceAdded { device_id: first_device_cert.device_id }, device_id: first_device_cert.device_id, timestamp: now })`.
5. `set_cluster_state(&state)`.

### `load()`
1. `get_cluster_state()` → если None → `Err(NotInitialized)`.
2. Возвращает `ClusterState { db, state }`.

**Замечание:** `load()` не реплицирует event log. State snapshot достаточен для работы. Event log используется только для sync с другими устройствами.

### `add_device()`
1. Проверить что device_id не уже зарегистрирован.
2. Проверить что всего < 16 устройств.
3. `verify_device_certificate(&cert, &state.master_pub)` — если ошибка → `InvalidCertificate`.
4. Назначить `device_index = state.devices.len() as u8` (следующий доступный).
5. Добавить `DeviceEntry` в `state.devices`.
6. `append_event(EventEntry { DeviceAdded { device_id }, ... })`.
7. `set_cluster_state(&state)`.

### `revoke_device()`
1. Проверить что device_id зарегистрирован.
2. Проверить что device не уже revoked.
3. `verify_revocation(&cert, &state.master_pub)` — если ошибка → `InvalidCertificate`.
4. Добавить device_id в `state.revoked_devices`.
5. Обновить `state.current_epoch = cert.new_epoch`.
6. Добавить `(cert.new_epoch, epoch_activated_at)` в `state.epoch_history`.
7. `append_event(EventEntry { DeviceRevoked { device_id }, ... })`.
8. `append_event(EventEntry { EpochRotated { epoch: cert.new_epoch.0 }, ... })`.
9. `set_cluster_state(&state)`.

### `apply_events()` — логика обработки событий (commutative)
```
DeviceAdded { device_id }:
    Если не уже в state.devices → попытаться добавить.
    Проблема: у нас нет сертификата в Event::DeviceAdded!
    → ClusterSync должен передавать DeviceCertificate отдельно,
      либо Event::DeviceAdded должен включать сертификат.

    DECISION NEEDED: Event::DeviceAdded не содержит DeviceCertificate.
    Для apply_events нам нужен сертификат чтобы верифицировать.

    **Рекомендация: расширить Event::DeviceAdded, добавив поле certificate.**

    Изменить в `types/mod.rs`:
    ```rust
    DeviceAdded {
        device_id: DeviceId,
        certificate: crate::cluster::DeviceCertificate,
    },
    ```

    Это breaking change: нужно обновить единственный вызывающий test в
    `crates/syncback-core/tests/phase1_gate.rs:434` — добавить dummy certificate.

    Если это неприемлемо — apply_events может добавлять device без re-verify
    (trust on source: события пришли через аутентифицированный канал от нашего
    другого устройства). В этом случае ClusterSync верифицирует перед вызовом
    apply_events, а apply_events просто добавляет без проверки.

DeviceRevoked { device_id }:
    Добавить в revoked_devices если не уже там. Idempotent.
    Не меняем epoch_history (epoch rotation приходит отдельным событием).

EpochRotated { epoch }:
    Если epoch > current_epoch → добавить в epoch_history, обновить current_epoch.
    Idempotent: если уже применено → skip.

FileAdded, FileModified, FileDeleted, SymbolsPlaced, SymbolsLost, SymbolsVerified:
    Применяются для обновления file catalog и symbol placements.
    Каждое из этих событий должно обновлять соответствующие DB записи.
    Реализация: для β минимальный subset.

    FileAdded { file_id, path }:
        Если нет в DB → создать FileRecord с пустым devices/versions.
        Если уже есть → update device list.

    FileDeleted { file_id, device_id }:
        Обновить LocalState для device_id → Deleted(event.timestamp).
```

### `is_content_backed_up()`
1. `db.list_all_files()` → scan versions → ищем `v.content_hash == content_hash`.
2. Возвращает `true` если нашли AND у найденной версии `backed_up_at.is_some()`.

### `set_peer_affinity()` и `peer_device()`
- Данные хранятся в `state.peer_affinity: Vec<(IdentityPub, DeviceId)>`.
- Upsert: заменить если уже есть запись для peer.
- После изменения → `set_cluster_state(&state)`.

---

## DB Schema additions (db/mod.rs)

```rust
// Добавить константу таблицы:
const CLUSTER_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("cluster_state");

// Добавить в Db::create_tables():
tx.open_table(CLUSTER_STATE)?;

// Добавить в impl Db:
pub fn get_cluster_state(&self) -> Result<Option<StoredClusterState>, DbError> {
    let tx = self.inner.begin_read()?;
    let table = tx.open_table(CLUSTER_STATE)?;
    match table.get("cluster_state")? {
        Some(v) => Ok(Some(from_cbor_bytes(v.value())?)),
        None => Ok(None),
    }
}

pub fn set_cluster_state(&self, state: &StoredClusterState) -> Result<(), DbError> {
    let bytes = to_cbor_bytes(state);
    let tx = self.inner.begin_write()?;
    {
        let mut table = tx.open_table(CLUSTER_STATE)?;
        table.insert("cluster_state", bytes.as_slice())?;
    }
    tx.commit()?;
    Ok(())
}
```

---

## Test Scenarios

Все тесты в `cluster/tests.rs` (продолжение существующего файла), в отдельном внутреннем `mod cluster_state_tests`.

```rust
fn make_cluster_state() -> ClusterState { /* seed=[1u8;32], device_id=[2u8;16] */ }
```

### 1. `cluster_state_init_creates_first_device`
```
seed = [1u8; 32]
master_key = derive_master_key(&seed)
device_id = DeviceId([2u8; 16])
device_key = derive_device_key(&seed, &device_id)
cert = issue_device_certificate(&master_key, device_id, device_key.verifying_key().to_bytes(), now)
state = ClusterState::init(db, master_identity(&master_key), cert, now, now)
assert state.active_devices().len() == 1
assert state.current_epoch() == EpochCounter(0)
assert state.epoch_history().len() == 1
```

### 2. `cluster_state_load_after_init`
```
init state, drop it
loaded = ClusterState::load(same db)
assert loaded.active_devices().len() == 1
assert loaded.master_pub() == original master_pub
```

### 3. `cluster_state_load_fails_when_not_initialized`
```
db = Db::open_in_memory()
result = ClusterState::load(db)
assert matches!(result, Err(ClusterStateError::NotInitialized))
```

### 4. `add_device_increments_count`
```
state = make_cluster_state() // 1 device
device_b_id = DeviceId([3u8; 16])
cert_b = issue_device_certificate(&master_key, device_b_id, ...)
state.add_device(cert_b, now)
assert state.active_devices().len() == 2
assert state.get_device(&device_b_id).unwrap().device_index == 1
```

### 5. `add_device_duplicate_fails`
```
state = make_cluster_state()
add same device_id again
assert matches!(result, Err(ClusterStateError::DeviceAlreadyRegistered(_)))
```

### 6. `add_device_with_wrong_master_fails`
```
cert signed by different master key
state.add_device(cert, now)
assert matches!(result, Err(ClusterStateError::InvalidCertificate(_)))
```

### 7. `add_device_max_16_enforced`
```
Add 15 devices (total 16 including first). 17th add returns MaxDevicesReached.
```

### 8. `revoke_device_marks_revoked`
```
state with devices A and B
revoke A: issue_revocation(&master_key, device_a_id, now, EpochCounter(1))
state.revoke_device(cert, now, now)
assert state.is_device_revoked(&device_a_id) == true
assert state.active_devices().len() == 1  // only B
assert state.current_epoch() == EpochCounter(1)
assert state.epoch_history().len() == 2
```

### 9. `revoke_already_revoked_fails`
```
Revoke device A. Then revoke A again.
Second call returns Err(DeviceRevoked).
```

### 10. `revoke_unknown_device_fails`
```
state.revoke_device(cert for DeviceId([0xFF; 16]), ...)
assert matches!(result, Err(ClusterStateError::DeviceNotFound(_)))
```

### 11. `peer_affinity_set_and_get`
```
state = make_cluster_state() with device_id = D1
peer_A = IdentityPub([10u8; 32])
state.set_peer_affinity(peer_A, D1)
assert state.peer_device(&peer_A) == Some(D1)
assert state.peers_for_device(&D1).contains(&peer_A)
```

### 12. `peer_affinity_reassign`
```
state with D1 and D2
assign peer_A → D1
reassign peer_A → D2
assert state.peer_device(&peer_A) == Some(D2)
assert state.peers_for_device(&D1).is_empty()
assert state.peers_for_device(&D2).contains(&peer_A)
```

### 13. `peer_affinity_persisted_across_load`
```
init, set affinity, drop state
loaded = ClusterState::load(db)
assert loaded.peer_device(&peer_A) == Some(D1)
```

### 14. `is_content_backed_up_true_when_version_exists`
```
Insert FileRecord into DB with version {content_hash=H, backed_up_at=Some(now)}
state.is_content_backed_up(&H) == Ok(true)
```

### 15. `is_content_backed_up_false_when_not_backed_up_yet`
```
FileRecord exists with version {content_hash=H, backed_up_at=None}
state.is_content_backed_up(&H) == Ok(false)
```

### 16. `is_content_backed_up_false_when_no_file`
```
Empty DB
state.is_content_backed_up(&[0u8; 32]) == Ok(false)
```

### 17. `esi_namespace_correct_for_device`
```
state with 2 devices (indices 0 and 1)
esi_namespace(device_0) == Some((0, 1_048_576))
esi_namespace(device_1) == Some((1_048_576, 2_097_152))
esi_namespace(unknown_device) == None
```

### 18. `apply_events_device_revoked_is_idempotent`
```
events = [(1, EventEntry { DeviceRevoked { device_id: D1 }, ... })]
state.apply_events(&events) // first time
state.apply_events(&events) // second time
assert state.is_device_revoked(&D1) == true  // applied once, not doubled
```

### 19. `apply_events_epoch_rotated_does_not_regress`
```
current_epoch = EpochCounter(3)
apply_events with EpochRotated { epoch: 2 } // older epoch
assert state.current_epoch() == EpochCounter(3)  // no regression
```

---

## Заметки для имплементора

- `StoredClusterState` сериализуется в CBOR через `to_cbor_bytes` / `from_cbor_bytes` из `types`.
- `apply_events` применяет только события, касающиеся cluster state. Остальные (SymbolsPlaced и т.д.) обрабатывает отдельный код; здесь их можно просто игнорировать или делегировать в DB напрямую.
- `DECISION NEEDED`: `Event::DeviceAdded` не содержит `DeviceCertificate`. ClusterSync (отдельный модуль) должен передавать сертификаты отдельно, или нужно расширить Event enum. Для Phase 3 рекомендация: пусть `apply_events` добавляет устройства без re-verify (trust on source: события пришли от нашего другого устройства через аутентифицированный канал). Если это неприемлемо — добавить `certificate: Option<DeviceCertificate>` в `Event::DeviceAdded`.
- `DeviceEntry::device_index` назначается локально при `add_device`. При применении events от другого устройства индекс может быть другим. Это нормально: ESI namespace per-device, конфликтов нет если устройства используют свой локально назначенный index. Альтернативно — ClusterSync синхронизирует индексы явно. Проще всего: canonical ordering by DeviceCertificate.issued_at.
- `epoch_history` должна быть всегда сортирована ascending по `activated_at`. При `apply_events` вставлять в правильную позицию или re-sort после.
