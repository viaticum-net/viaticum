# Task spec: Phase 7.5 — Symbol delivery after backup

**Target files:**
- `crates/syncback/src/daemon/backup/mod.rs` — add `network` field to `BackupConfig` and `BackupCoordinator`; add `deliver_symbols` method; call it after each `flush_queue_inner` result
- `crates/syncback/src/daemon/backup/pipeline.rs` — no structural changes; `run_pipeline` return value (`PipelineResult`) is already sufficient
- `crates/syncback/src/daemon/handle/mod.rs` — pass `network: Some(network.clone())` in `BackupConfig`
- `crates/syncback/src/daemon/backup/tests.rs` — add delivery test scenarios

**Phase:** 7.5 (P2P wiring — symbol delivery)

---

## Overview

After `flush_queue_inner` completes and produces `PipelineResult` entries, the encoded symbol files sit on disk but have not been delivered to holders. This task wires the network layer into `BackupCoordinator` so that, after each pipeline flush, symbols are read from disk and sent to each assigned holder via `network.send_symbols(holder_identity, msg)`.

The full negotiation protocol (SymbolOffer → SymbolAccept → SymbolTransfer → SymbolStored) is handled by the `Processor` on the holder side. The owner side in this phase uses `SymbolTransfer` only (push without prior offer-accept). The Processor dispatch for `SymbolStored` acknowledgement is handled in Phase 7.6; here we fire-and-forget at the send level and log any errors.

---

## Dependencies

- `crates/syncback/src/daemon/network/mod.rs` — `NetworkHandle::send_symbols` (exists)
- `crates/syncback-core/src/messages` — `SymbolTransferMsg`, `Symbol` (both exist)
- `crates/syncback-core/src/types` — `SymbolPlacement`, `IdentityPub`, `SourceBlockId`, `Timestamp`
- `crates/syncback-core/src/db` — `list_placements_for_block` (exists)
- `crates/syncback/src/daemon/backup/pipeline.rs` — `PipelineResult` (exists)
- Phase 7.3 / 7.4: `NetworkHandle` is behind `Arc<NetworkHandle>` in `DaemonState`

---

## Change 1: `backup/mod.rs` — add `network` to `BackupConfig` and `BackupCoordinator`

### Updated `BackupConfig`

```rust
/// Configuration for BackupCoordinator.
#[derive(Clone)]
pub struct BackupConfig {
    /// Source block size in bytes. Default: DEFAULT_SOURCE_BLOCK_SIZE.
    pub source_block_size: u64,
    /// Directory where bound symbol files are written.
    pub symbols_dir: std::path::PathBuf,
    /// Epoch key for file encryption. 32 bytes.
    pub epoch_key: [u8; 32],
    /// This device's ID (for LocalState and EventLog).
    pub device_id: DeviceId,
    /// Holder candidates for Phase 2 testing. Overrides DB peers when non-empty.
    pub mock_holders: Vec<HolderCandidate>,
    /// Optional cluster state for dedup check (multi-device).
    pub cluster_state: Option<std::sync::Arc<std::sync::Mutex<syncback_core::cluster::ClusterState>>>,
    /// Network handle for symbol delivery.
    /// When None: symbols are encoded and written to disk but not delivered
    /// (pre-7.5 behavior; also used in unit tests that do not spin up a network).
    pub network: Option<std::sync::Arc<crate::daemon::network::NetworkHandle>>,
}
```

### Updated `BackupConfig::default`

```rust
impl Default for BackupConfig {
    fn default() -> Self {
        BackupConfig {
            source_block_size: DEFAULT_SOURCE_BLOCK_SIZE,
            symbols_dir: std::path::PathBuf::from("symbols"),
            epoch_key: [0u8; 32],
            device_id: DeviceId([0u8; 16]),
            mock_holders: vec![],
            cluster_state: None,
            network: None,
        }
    }
}
```

### Updated `BackupCoordinator` struct

```rust
pub struct BackupCoordinator {
    pub(crate) db: Db,
    pub(crate) config: BackupConfig,
    pub(crate) encoder: Arc<dyn ErasureEncoder>,
    pub(crate) queues: HashMap<FileCategory, Vec<QueuedFile>>,
    pub(crate) next_file_id: u64,
}
```

The `network` handle is accessed via `self.config.network` — no separate field needed.

### New method: `deliver_symbols`

```rust
impl BackupCoordinator {
    /// Deliver encoded symbols to their assigned holders over the network.
    ///
    /// For each `PipelineResult`:
    ///   1. Load `SymbolPlacement` records for the source block from DB.
    ///   2. For each placement, read symbol files from disk, build `SymbolTransferMsg`,
    ///      and call `network.send_symbols(holder_identity, msg)`.
    ///
    /// Errors are logged but not propagated — delivery failures do not abort the backup.
    /// The caller (flush path) is responsible for DB consistency; delivery is best-effort.
    ///
    /// No-op when `config.network` is None.
    async fn deliver_symbols(&self, results: &[PipelineResult]) {
        let network = match &self.config.network {
            Some(n) => n.clone(),
            None => return,
        };

        for result in results {
            let placements = match self.db.list_placements_for_block(&result.source_block_id) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(
                        block = ?result.source_block_id,
                        error = %e,
                        "deliver_symbols: failed to load placements from DB"
                    );
                    continue;
                }
            };

            for placement in &placements {
                if let Err(e) = self
                    .deliver_to_holder(&network, result, placement)
                    .await
                {
                    tracing::warn!(
                        block = ?result.source_block_id,
                        holder = %placement.holder_id,
                        error = %e,
                        "deliver_symbols: failed to deliver to holder (will retry on repair)"
                    );
                }
            }
        }
    }

    /// Deliver symbols for one (block, holder) pair.
    async fn deliver_to_holder(
        &self,
        network: &crate::daemon::network::NetworkHandle,
        result: &PipelineResult,
        placement: &syncback_core::types::SymbolPlacement,
    ) -> anyhow::Result<()> {
        use syncback_core::erasure::Symbol;
        use syncback_core::messages::SymbolTransferMsg;
        use syncback_core::types::Timestamp;

        let symbols = read_symbols_for_holder(
            &self.config.symbols_dir,
            &result.source_block_id,
            &placement.esi_ranges,
        )?;

        if symbols.is_empty() {
            anyhow::bail!(
                "no symbol files found for block {:?} holder {}",
                result.source_block_id,
                placement.holder_id
            );
        }

        let msg = SymbolTransferMsg {
            v: 1,
            source_block_id: result.source_block_id,
            symbols,
            timestamp: Timestamp::now(),
        };

        network.send_symbols(placement.holder_id, msg).await
            .map_err(|e| anyhow::anyhow!("send_symbols: {e}"))
    }
}
```

### New free function: `read_symbols_for_holder`

This is a module-level (not `pub`) helper. Placed in `pipeline.rs` (alongside existing disk-write code) or at the bottom of `mod.rs` — prefer `pipeline.rs` since that is where symbol files are written.

```rust
/// Read symbol files for a given holder from the symbols directory.
///
/// Reads files named `{esi}.bin` for each ESI in `esi_ranges`.
/// Returns `Vec<Symbol>` in ESI order.
/// Returns error if any file cannot be read.
pub(crate) fn read_symbols_for_holder(
    symbols_dir: &std::path::Path,
    block_id: &syncback_core::types::SourceBlockId,
    esi_ranges: &[(u32, u32)],
) -> anyhow::Result<Vec<syncback_core::erasure::Symbol>> {
    use crate::daemon::backup::pipeline::hex_encode;
    use syncback_core::erasure::Symbol;

    let block_dir = symbols_dir.join(hex_encode(&block_id.0));
    let mut symbols = Vec::new();

    for &(start_esi, count) in esi_ranges {
        for esi in start_esi..start_esi + count {
            let path = block_dir.join(format!("{esi}.bin"));
            let data = std::fs::read(&path)
                .map_err(|e| anyhow::anyhow!("read symbol {}: {e}", path.display()))?;
            symbols.push(Symbol { esi, data });
        }
    }

    Ok(symbols)
}
```

---

## Change 2: call `deliver_symbols` after flush

### In `flush_queue`

`flush_queue` is currently `fn` (sync). Since `deliver_symbols` is `async`, `flush_queue` must either be changed to `async fn` or the delivery must be spawned as a detached task.

**Decision:** change `flush_queue`, `flush_all`, and `flush_queue_inner` callers inside `BackupCoordinator` to be called from within the `async fn run()` loop which already exists. The synchronous `flush_queue` / `flush_all` public methods remain synchronous (they are called from sync test code). Delivery is triggered only from the `run()` loop.

**Concretely:** in the `async fn run()` loop, after calling `self.flush_all(force)`, call `self.deliver_symbols(&results).await`.

```rust
pub async fn run(
    mut self,
    mut rx: tokio::sync::mpsc::Receiver<DirtyEvent>,
) -> anyhow::Result<()> {
    use tokio::time::{interval, Duration, MissedTickBehavior};

    let mut idle_timer = interval(Duration::from_secs(syncback_core::constants::FLUSH_IDLE_SECS));
    idle_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut fallback_timer = interval(Duration::from_secs(syncback_core::constants::FLUSH_FALLBACK_SECS));
    fallback_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        if let Err(e) = self.process_event(event) {
                            tracing::error!("process_event error: {e}");
                        }
                        idle_timer.reset();
                    }
                    None => {
                        tracing::info!("BackupCoordinator: channel closed, flushing and exiting");
                        match self.flush_all(true) {
                            Ok(results) => self.deliver_symbols(&results).await,
                            Err(e) => tracing::error!("final flush error: {e}"),
                        }
                        break;
                    }
                }
            }
            _ = idle_timer.tick() => {
                tracing::debug!("idle flush triggered");
                match self.flush_all(false) {
                    Ok(results) => {
                        if !results.is_empty() {
                            self.deliver_symbols(&results).await;
                        }
                    }
                    Err(e) => tracing::error!("idle flush error: {e}"),
                }
            }
            _ = fallback_timer.tick() => {
                tracing::debug!("fallback flush triggered");
                match self.flush_all(true) {
                    Ok(results) => {
                        if !results.is_empty() {
                            self.deliver_symbols(&results).await;
                        }
                    }
                    Err(e) => tracing::error!("fallback flush error: {e}"),
                }
            }
        }
    }
    Ok(())
}
```

The synchronous `flush_queue` and `flush_all` methods are **not** changed. They remain non-async and do not call `deliver_symbols`. Delivery only happens from `run()`.

This design avoids introducing async into the sync pipeline path, which would break all existing sync tests.

---

## Change 3: `handle/mod.rs` — pass `network` to `BackupConfig`

### Updated `BackupCoordinator::new` call in `handle/mod.rs`

```rust
let backup = BackupCoordinator::new(
    db.clone(),
    BackupConfig {
        source_block_size,
        symbols_dir: symbols_dir.clone(),
        epoch_key: epoch_key_bytes,
        device_id,
        mock_holders: vec![],
        cluster_state: cluster_state.clone(),
        network: Some(network.clone()),  // NEW
    },
    encoder.clone(),
);
```

`network` is `Arc<NetworkHandle>` constructed in step 8 and is already in scope at step 10 where `BackupCoordinator::new` is called.

---

## Public API summary

### `backup/mod.rs`

```rust
pub struct BackupConfig {
    // ... existing fields ...
    pub network: Option<Arc<crate::daemon::network::NetworkHandle>>,  // NEW
}

impl BackupCoordinator {
    // NEW (async, private — called from run())
    async fn deliver_symbols(&self, results: &[PipelineResult]);

    // NEW (async, private — called from deliver_symbols())
    async fn deliver_to_holder(
        &self,
        network: &NetworkHandle,
        result: &PipelineResult,
        placement: &SymbolPlacement,
    ) -> anyhow::Result<()>;
}
```

### `backup/pipeline.rs`

```rust
// NEW (pub(crate))
pub(crate) fn read_symbols_for_holder(
    symbols_dir: &Path,
    block_id: &SourceBlockId,
    esi_ranges: &[(u32, u32)],
) -> anyhow::Result<Vec<Symbol>>
```

---

## Types

| Type | Source | Used in |
|------|--------|---------|
| `NetworkHandle` | `daemon::network` | `BackupConfig.network`, `deliver_to_holder` |
| `SymbolTransferMsg` | `syncback_core::messages` | Built in `deliver_to_holder` |
| `Symbol` | `syncback_core::erasure` | Populated by `read_symbols_for_holder` |
| `SymbolPlacement` | `syncback_core::types` | Loaded from DB in `deliver_symbols` |
| `SourceBlockId` | `syncback_core::types` | Block identifier |
| `PipelineResult` | `backup/mod.rs` | Carries `source_block_id` and `symbol_count_per_holder` |
| `Timestamp` | `syncback_core::types` | `SymbolTransferMsg.timestamp` |

---

## DB operations

| Operation | Table | When |
|-----------|-------|------|
| `db.list_placements_for_block(&block_id)` | `symbol_placements` | In `deliver_symbols` — once per `PipelineResult` |

No writes: delivery does not modify any DB state. Placement status transitions (e.g., `Alive` → confirmation of receipt) happen in Phase 7.6 when `SymbolStored` messages are processed by the `Processor`.

---

## Business rules

1. **Fire-and-forget delivery.** Delivery errors are logged at `WARN` level and not propagated. The pipeline has already committed the source block and placements to disk and DB. If delivery fails, the `RepairAgent` will detect the missing symbols via PoS failures and re-deliver.

2. **`network = None` → no delivery.** All pre-7.5 unit tests pass `BackupConfig::default()` or construct `BackupConfig` without `network`. They continue to work unchanged.

3. **Delivery only from `run()`.** The synchronous `flush_queue` / `flush_all` methods do not deliver. This keeps the sync API clean and avoids blocking executor issues in tests.

4. **`SymbolTransferMsg.v = 1`.** Protocol version 1 for all symbol transfers.

5. **Symbol data on disk is already bound** (per-holder XOR with `HKDF(block_id, holder_id)` applied during encode in `run_pipeline`). The `SymbolTransferMsg` carries bound symbols; the holder stores them as-is.

6. **ESI ranges come from `SymbolPlacement.esi_ranges`.** The `esi_ranges` field is `Vec<(u32, u32)>` where each tuple is `(start_esi, count)`. `read_symbols_for_holder` iterates these ranges to enumerate the ESIs to load from disk.

7. **Symbol file names are `{esi}.bin`** (written in `run_pipeline` as `format!("{}.bin", symbol.esi)`). `read_symbols_for_holder` constructs paths with the same pattern.

8. **One `SymbolTransferMsg` per holder per source block.** Do not batch multiple blocks into one message.

9. **Holder not reachable → log warning, continue.** `NetworkHandle::send_symbols` returns `NetworkError::PeerNotFound` if the holder is not in `known_peers`. This is normal for freshly-placed holders who have never been directly connected to. The repair path handles re-delivery.

10. **`deliver_symbols` is called after `flush_all` in the `run()` loop, not inline in `flush_queue_inner`.** This keeps pipeline code (sync, no network deps) separate from delivery code (async, network).

---

## Test scenarios

Tests go in `crates/syncback/src/daemon/backup/tests.rs`.

### Test infrastructure note

`BackupCoordinator` tests use `Db::open_in_memory()` (already established). Delivery tests need a mock or stub for `NetworkHandle`. Since `NetworkHandle` requires a live iroh endpoint and tokio runtime, the recommended approach is:

- Tests that verify delivery is **called** use `network = None` and assert on DB state only (all pre-7.5 tests).
- Tests that verify `read_symbols_for_holder` use it directly (unit test, no network).
- An integration delivery test creates two real `NetworkHandle` instances (similar to Phase 7.3 integration tests).

### Test 1: `read_symbols_for_holder_reads_correct_files`

```rust
#[test]
fn read_symbols_for_holder_reads_correct_files() {
    use crate::daemon::backup::pipeline::read_symbols_for_holder;
    use syncback_core::types::SourceBlockId;

    let dir = tempfile::tempdir().unwrap();
    let block_id = SourceBlockId([0x01u8; 32]);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();

    // Write 3 symbol files.
    for esi in [0u32, 1, 2] {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 64]).unwrap();
    }

    // ESI range: start=0, count=3.
    let symbols = read_symbols_for_holder(dir.path(), &block_id, &[(0, 3)]).unwrap();

    assert_eq!(symbols.len(), 3);
    assert_eq!(symbols[0].esi, 0);
    assert_eq!(symbols[1].esi, 1);
    assert_eq!(symbols[2].esi, 2);
    assert_eq!(symbols[0].data, vec![0u8; 64]);
}
```

### Test 2: `read_symbols_for_holder_missing_file_returns_error`

```rust
#[test]
fn read_symbols_for_holder_missing_file_returns_error() {
    use crate::daemon::backup::pipeline::read_symbols_for_holder;
    use syncback_core::types::SourceBlockId;

    let dir = tempfile::tempdir().unwrap();
    let block_id = SourceBlockId([0x02u8; 32]);
    // Do NOT create any files.

    let result = read_symbols_for_holder(dir.path(), &block_id, &[(0, 1)]);
    assert!(result.is_err(), "must return error when symbol file is missing");
}
```

### Test 3: `read_symbols_for_holder_multiple_ranges`

```rust
#[test]
fn read_symbols_for_holder_multiple_ranges() {
    use crate::daemon::backup::pipeline::read_symbols_for_holder;
    use syncback_core::types::SourceBlockId;

    let dir = tempfile::tempdir().unwrap();
    let block_id = SourceBlockId([0x03u8; 32]);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();

    // ESIs 0, 1, 5, 6, 7 (two non-contiguous ranges).
    for esi in [0u32, 1, 5, 6, 7] {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 8]).unwrap();
    }

    let symbols = read_symbols_for_holder(
        dir.path(),
        &block_id,
        &[(0, 2), (5, 3)],  // range 1: ESIs 0-1, range 2: ESIs 5-7
    )
    .unwrap();

    assert_eq!(symbols.len(), 5);
    let esis: Vec<u32> = symbols.iter().map(|s| s.esi).collect();
    assert_eq!(esis, vec![0, 1, 5, 6, 7]);
}
```

### Test 4: `backup_config_default_network_is_none`

```rust
#[test]
fn backup_config_default_network_is_none() {
    let cfg = BackupConfig::default();
    assert!(cfg.network.is_none(), "default config must have network=None");
}
```

### Test 5: `deliver_symbols_no_op_when_network_none` (async)

```rust
#[tokio::test]
async fn deliver_symbols_no_op_when_network_none() {
    // This test verifies that deliver_symbols with network=None does not panic
    // and does not attempt any DB reads (it should return immediately).
    // Use a real DB but no real placements — if the function tried to use DB,
    // it would succeed (empty results); the key assertion is no panic.
    let db = syncback_core::db::Db::open_in_memory().unwrap();
    let coordinator = BackupCoordinator::new(
        db,
        BackupConfig {
            network: None,
            ..BackupConfig::default()
        },
        std::sync::Arc::new(syncback_core::erasure::RaptorQEncoder::new()),
    );

    // deliver_symbols with empty results — must not panic.
    coordinator.deliver_symbols(&[]).await;

    // deliver_symbols with a non-empty PipelineResult but network=None.
    // It must return immediately without touching DB.
    let fake_result = PipelineResult {
        source_block_id: syncback_core::types::SourceBlockId([0u8; 32]),
        k: 1,
        n: 2,
        symbol_count_per_holder: vec![],
        stored_size: 0,
    };
    coordinator.deliver_symbols(&[fake_result]).await;
    // No panic = pass.
}
```

### Test 6: `deliver_symbols_logs_warn_on_peer_not_found` (integration, real network)

This test verifies the full delivery path with a real `NetworkHandle`. It confirms that when the holder is not in `known_peers`, the error is logged and `deliver_symbols` does not propagate the error.

```rust
#[tokio::test]
async fn deliver_symbols_logs_warn_on_peer_not_found() {
    use ed25519_dalek::SigningKey;
    use syncback_core::types::{DeviceId, IdentityPub, SourceBlockId, SymbolPlacement, PlacementStatus, Timestamp};
    use crate::daemon::network::{NetworkConfig, NetworkHandle};

    // Set up owner NetworkHandle (no peers registered).
    let sk_owner = SigningKey::from_bytes(&[10u8; 32]);
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let network = std::sync::Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: sk_owner.clone(),
                known_peers: Default::default(),
                device_cert: None,
                iroh_secret_key: None,
                relay_mode: iroh::RelayMode::Disabled,
            },
            tx,
        )
        .await
        .unwrap(),
    );

    let db = syncback_core::db::Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();

    // Write symbol file so read_symbols_for_holder succeeds.
    let block_id = SourceBlockId([0xAAu8; 32]);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();
    std::fs::write(block_dir.join("0.bin"), vec![0u8; 64]).unwrap();

    // Insert a placement for an unknown holder.
    let unknown_holder = IdentityPub([0xFFu8; 32]);
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id: unknown_holder,
        file_id: syncback_core::types::FileId(1),
        esi_ranges: vec![(0, 1)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    let coordinator = BackupCoordinator::new(
        db,
        BackupConfig {
            symbols_dir: dir.path().to_path_buf(),
            network: Some(network.clone()),
            ..BackupConfig::default()
        },
        std::sync::Arc::new(syncback_core::erasure::RaptorQEncoder::new()),
    );

    let result = PipelineResult {
        source_block_id: block_id,
        k: 1,
        n: 2,
        symbol_count_per_holder: vec![(unknown_holder, 1)],
        stored_size: 64,
    };

    // Must not panic or return error — delivery failure is fire-and-forget.
    coordinator.deliver_symbols(&[result]).await;

    network.shutdown().await;
}
```

### Test 7: `deliver_symbols_sends_to_reachable_holder` (integration, two real networks)

Full end-to-end: encode symbols, store on disk, deliver via network, verify holder receives the message.

```rust
#[tokio::test]
async fn deliver_symbols_sends_to_reachable_holder() {
    use ed25519_dalek::SigningKey;
    use syncback_core::messages::Message;
    use syncback_core::types::{
        DeviceId, IdentityPub, SourceBlockId, SymbolPlacement, PlacementStatus, Timestamp,
    };
    use crate::daemon::network::{NetworkConfig, NetworkHandle};

    // ── Build two network handles ──────────────────────────────────────────
    let sk_owner = SigningKey::from_bytes(&[20u8; 32]);
    let sk_holder = SigningKey::from_bytes(&[21u8; 32]);
    let holder_identity = IdentityPub(sk_holder.verifying_key().to_bytes());

    let (tx_owner, _rx_owner) = tokio::sync::mpsc::channel(4);
    let (tx_holder, mut rx_holder) = tokio::sync::mpsc::channel(4);

    let network_owner = std::sync::Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: sk_owner.clone(),
                known_peers: Default::default(),
                device_cert: None,
                iroh_secret_key: None,
                relay_mode: iroh::RelayMode::Disabled,
            },
            tx_owner,
        )
        .await
        .unwrap(),
    );

    let network_holder = std::sync::Arc::new(
        NetworkHandle::start(
            NetworkConfig {
                signing_key: sk_holder,
                known_peers: Default::default(),
                device_cert: None,
                iroh_secret_key: None,
                relay_mode: iroh::RelayMode::Disabled,
            },
            tx_holder,
        )
        .await
        .unwrap(),
    );

    // Register holder in owner's known_peers.
    let holder_addr = network_holder.local_addr().unwrap();
    network_owner.add_peer(holder_identity, holder_addr).await;

    // ── Set up DB and symbol files ─────────────────────────────────────────
    let db = syncback_core::db::Db::open_in_memory().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let block_id = SourceBlockId([0x99u8; 32]);
    let block_hex: String = block_id.0.iter().map(|b| format!("{b:02x}")).collect();
    let block_dir = dir.path().join(&block_hex);
    std::fs::create_dir_all(&block_dir).unwrap();

    // Write 2 symbol files.
    for esi in 0u32..2 {
        std::fs::write(block_dir.join(format!("{esi}.bin")), vec![esi as u8; 64]).unwrap();
    }

    // Insert placement.
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id: holder_identity,
        file_id: syncback_core::types::FileId(1),
        esi_ranges: vec![(0, 2)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).unwrap();

    // ── Build coordinator and deliver ──────────────────────────────────────
    let coordinator = BackupCoordinator::new(
        db,
        BackupConfig {
            symbols_dir: dir.path().to_path_buf(),
            network: Some(network_owner.clone()),
            ..BackupConfig::default()
        },
        std::sync::Arc::new(syncback_core::erasure::RaptorQEncoder::new()),
    );

    let result = PipelineResult {
        source_block_id: block_id,
        k: 2,
        n: 4,
        symbol_count_per_holder: vec![(holder_identity, 2)],
        stored_size: 128,
    };

    coordinator.deliver_symbols(&[result]).await;

    // ── Verify holder received the message ────────────────────────────────
    // The accept loop pushes incoming connections to rx_holder.
    // Wait up to 2 seconds for the connection to arrive.
    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        rx_holder.recv(),
    )
    .await
    .expect("timeout waiting for connection")
    .expect("channel closed");

    // Read the SymbolTransfer message from the connection.
    let mut conn = conn;
    let msg = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        conn.recv_message(),
    )
    .await
    .expect("timeout waiting for message")
    .expect("recv_message failed");

    match msg {
        Message::SymbolTransfer(transfer) => {
            assert_eq!(transfer.source_block_id, block_id);
            assert_eq!(transfer.symbols.len(), 2);
            assert_eq!(transfer.symbols[0].esi, 0);
            assert_eq!(transfer.symbols[1].esi, 1);
        }
        other => panic!("expected SymbolTransfer, got {other:?}"),
    }

    network_owner.shutdown().await;
    network_holder.shutdown().await;
}
```

---

## Implementation order

1. **`backup/pipeline.rs`**: add `read_symbols_for_holder`. Run `cargo build -p syncback`.
2. **`backup/mod.rs`**: add `network: Option<Arc<NetworkHandle>>` to `BackupConfig`. Update `Default`. Add `deliver_symbols` and `deliver_to_holder`. Update `run()` to call `deliver_symbols`. Run `cargo build -p syncback`.
3. **`handle/mod.rs`**: add `network: Some(network.clone())` to `BackupConfig` in step 10. Run `cargo build -p syncback`.
4. **`backup/tests.rs`**: add tests 1-7. Run `cargo test -p syncback`.
5. **`cargo clippy -p syncback -- -D warnings`** — confirm clean.

---

## Potential pitfalls

- **`BackupCoordinator` is `!Send` if `NetworkHandle` is not `Send`.** `Arc<NetworkHandle>` is `Send` if `NetworkHandle: Send`. `NetworkHandle` contains `Arc<Mutex<...>>` and `Arc<RwLock<...>>` (from Phase 7.3), which are `Send`. The iroh `Endpoint` should also be `Send`. Verify with `cargo build` — if the compiler rejects `deliver_symbols` inside a `tokio::spawn`, check which field is not `Send`.

- **`deliver_symbols` takes `&self` not `&mut self`.** It only reads from `self.config.network` and `self.db` (read operations). `deliver_to_holder` also takes `&self`. No mutation occurs. This is correct.

- **`PipelineResult.symbol_count_per_holder` vs DB placements.** `PipelineResult` contains `symbol_count_per_holder` from the pipeline, but `deliver_symbols` reads placements from DB to get `esi_ranges`. Do not use `symbol_count_per_holder` for routing — it only has counts, not ESI start positions. Always read from DB placements for the actual ESI ranges.

- **Symbol file existence.** `read_symbols_for_holder` will error if a symbol file is missing. This can happen if encoding succeeded but a write failed (rare). `deliver_to_holder` logs a warning and continues. The `RepairAgent` handles missing symbol files during its repair cycle.

- **`Connection` type in test 7.** The `rx_holder` channel in the accept loop yields `Connection` objects (raw, post-handshake connections). In Phase 7.5 tests we read one message from the connection directly. In production the `Processor` would consume these connections.

- **`BackupCoordinator` sync/async split.** `flush_queue` and `flush_all` remain `fn` (sync). Only `run()` is `async fn`. Since `deliver_symbols` is `async`, it can only be called from `run()`. If a caller wants sync delivery (e.g., from an integration test that does not use `run()`), it must use `tokio::runtime::Handle::current().block_on(...)` — but this is an anti-pattern in tests. For tests, use the approach in test 7 (build the coordinator, call `run()` in a spawned task, trigger via the channel).

- **`use iroh::RelayMode` in tests.** After Phase 7.4, all `NetworkConfig` construction must include `relay_mode: iroh::RelayMode::Disabled`. Add this to the test helper in `backup/tests.rs` if it constructs `NetworkConfig`.

---

## Checklist for reviewer

- [ ] `BackupConfig.network: Option<Arc<NetworkHandle>>` added.
- [ ] `BackupConfig::default()` sets `network: None`.
- [ ] `read_symbols_for_holder` added to `pipeline.rs` as `pub(crate)`.
- [ ] `deliver_symbols` and `deliver_to_holder` added to `BackupCoordinator` impl.
- [ ] `deliver_symbols` returns immediately (no-op) when `config.network` is `None`.
- [ ] `deliver_symbols` logs `WARN` on per-holder error, does not propagate.
- [ ] `deliver_symbols` logs `ERROR` on DB read failure (list_placements_for_block), continues to next result.
- [ ] `run()` calls `deliver_symbols(&results).await` after each `flush_all` call.
- [ ] `flush_queue` and `flush_all` remain sync (no async change).
- [ ] `handle/mod.rs` passes `network: Some(network.clone())` to `BackupConfig`.
- [ ] Tests 1-7 added and passing.
- [ ] `cargo build -p syncback` passes.
- [ ] `cargo test -p syncback` passes.
- [ ] `cargo clippy -p syncback -- -D warnings` passes.
