# Roadmap: α → working β

---

## Phase 0: подготовка

```
□ Benchmark raptorq crate (encode/decode K=200, K=4096, K=32000)
  → если непригоден — альтернативы? (go/no-go)
□ Fresh workspace, переиспользовать trust/escrow/budget из α core
□ CI: cargo test, clippy
```

## Phase 1: фундамент (параллельно, нет зависимостей)

```
□ Новые типы: Symbol, ESI, SourceBlock, SymbolPlacement, DeviceId, EpochKey
□ ErasureEncoder trait + RaptorQ impl
  GATE: encode → decode roundtrip, streaming API
□ Новая DB schema (redb): FileRecord, SourceBlock, SymbolPlacement, EventLog
  GATE: CRUD + двойной индекс
□ PoS engine (реальный)
  GATE: challenge → response → verify на лету
□ Trust/escrow/budget — портировать из α
□ Cluster module: device keys, epochs, certificates (pure logic)
  GATE: derive key, sign/verify certificate, epoch rotation

Milestone: "кирпичики компилируются и тестируются отдельно"
```

## Phase 2: pipeline (последовательно)

```
□ BackupCoordinator: file → compress → encrypt → encode → symbols
  GATE: roundtrip без сети
□ Per-holder binding: XOR ChaCha20
  GATE: bind → unbind roundtrip
□ SymbolBudgetManager: placement formula (trust/sqrt(1-t), cap)
  GATE: distribute N across mock peers, verify constraints
□ Network: iroh direct + symbol transfer
  GATE: два node'а, отправка символов
□ RestoreCoordinator: selective, versioned
  GATE: backup на A → restore на B
□ Epidemic relay: deferred messaging (hop≤2)
  GATE: сообщение через третий peer

Milestone: "два node'а, backup → restore end-to-end"
```

## Phase 2.5: PosNack + repair

```
□ Обновить PoS engine: VerifyOutcome::NotHeld, PosNackMsg
□ PlacementStatus state machine: Alive → Uncertain → PresumedLost
  consecutive_misses tracking per placement
□ RepairAgent: graduated repair trigger
  NotHeld/Fail → immediate repair
  Timeout → graduated (1-2 misses = Uncertain, 3+ = PresumedLost → repair)
□ Обновить messages: PosNack variant в Message enum
□ Гонка SymbolDropped vs PosNack: idempotent transitions
  GATE: holder evicts → PosNack → owner triggers repair
  GATE: SymbolDropped + PosNack в любом порядке → одинаковый результат

Milestone: "repair agent реагирует на потерю символов"
```

## Phase 2.6: trust-based escrow

```
□ Переписать escrow модуль: time-based → trust-based
  check_restore(trust, restore_gb) вместо check_restore(weeks, bytes)
  Формула: max_restorable_gb = FREE_TIER_GB + trust × ESCROW_TRUST_FACTOR
  FREE_TIER_GB = 1.0 (demo credit), ESCROW_TRUST_FACTOR = 20.0 (configurable)
□ Убрать EscrowTier enum, tier-based константы
□ Добавить restore_budget(trust) → f64
□ Обновить RestoreConfig: убрать weeks_in_network
□ Обновить RestoreError::EscrowDenied: trust-based поля
□ Новые тесты
  GATE: hit-and-run (trust=0) blocked, honest user (trust≥2) gets full access

Milestone: "escrow на базе trust, не времени"
```

## Phase 2.7: holder limits

```
☑ MAX_HOLDERS_PER_BLOCK = 30
  Защита от разрастания числа пиров на блок.
  При 1 ТБ и 50+ холдерах: PoS/restore overhead растёт линейно.
  30 = sweet spot: restore ≤14 connections, PoS ~246K/нед на 1 ТБ.
☑ MIN_SYMBOLS_PER_HOLDER = 32 (2 МБ)
  Защита для маленьких блоков (32 МБ, overhead 1.5x → N=768).
  Ниже 32 символов overhead трекинга не оправдан.
☑ compute_allocation: pre-filter кандидатов
  effective = min(candidates, MAX_HOLDERS, N/MIN_SYMBOLS).max(2)
  Top-N по весу. 3 новых теста.

Milestone: "placement защищён от O(N_peers) разрастания"
```

## Phase 3: cluster

```
□ Device registration: seed → device key → certificate → handshake
□ ClusterSync: event log exchange
□ Dedup: content_hash → skip if backed up
□ Peer-to-device affinity
□ Epoch rotation + revocation
  GATE: revoke → partners reject revoked key

Milestone: "два устройства, shared identity, dedup"
```

## Phase 4: polish

```
□ Disk pressure: effective_quota, soft/hard quota
□ File deletion: watcher → Deleted → cooldown → cleanup
□ Commitment telemetry
□ Reliability forecast
□ CLI: status, restore, device, files, versions
□ Config format

Milestone: "feature complete"
```

## Phase 5: gate

```
□ Unit tests per module
□ Integration: 2 nodes, основные flows
□ Cluster: 2+ devices, backup/restore/dedup/revocation
□ Stress: 5 ТБ scenario (симуляция)
□ E2E: backup → versioned selective restore → device revocation

Milestone: "β ready"
```
