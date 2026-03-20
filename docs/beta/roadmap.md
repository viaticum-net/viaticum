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
□ Variable T для файлов > 3.5 ГБ
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
