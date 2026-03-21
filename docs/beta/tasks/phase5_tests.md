# Task: Phase 5 Gate Tests

Phases: 5.2 (integration), 5.3 (cluster), 5.4 (stress), 5.5 (E2E)

Files to create:
- `crates/syncback/tests/phase4_gate.rs` — integration tests for Phase 4 modules (5.2)
- `crates/syncback/tests/phase5_cluster.rs` — cluster integration tests (5.3)
- `crates/syncback/tests/stress_5tb.rs` — stress test (5.4)
- `crates/syncback/tests/e2e.rs` — end-to-end lifecycle test (5.5)

---

## Context

Phases 1–3 are complete (324 tests passing). Phase 4 adds:
- `syncback-core`: `config`, `deletion`, `commitment`, `reliability`, disk pressure (`budget` upgrade)
- `syncback`: no new daemon modules in Phase 4 (config/deletion/commitment/reliability are pure-core)

Phase 5 gate tests verify that all Phase 4 modules work correctly in cross-module scenarios
and that the overall system lifetime flows are correct.

---

## Dependencies

All four test files live in `crates/syncback/tests/` and share the same
`[dev-dependencies]` as `phase2_gate.rs` and `phase3_gate.rs`. No new
Cargo dependencies are needed beyond what is already present.

Key imports the test files will use:

```rust
// syncback-core
use syncback_core::budget::{compute_effective_quota, evaluate_pressure, should_reject_offers};
use syncback_core::cluster::{ClusterState, derive_epoch_key, derive_master_key,
    derive_device_key, issue_device_certificate, issue_revocation, master_identity, EpochCounter};
use syncback_core::commitment::{
    compute_commitment, CommitmentScore, CommitmentTier, HolderProfile,
    flag_for_proactive_repair, eviction_risk,
};
use syncback_core::config::{AppConfig, BackupCfg, source_block_size_bytes};
use syncback_core::constants::{
    OWNER_DELETE_COOLDOWN_SECS, HOLDER_DELETE_COOLDOWN_SECS,
    RELIABILITY_REPAIR_THRESHOLD, DEFAULT_SOURCE_BLOCK_SIZE,
};
use syncback_core::db::Db;
use syncback_core::deletion::{DeletionEngine, DeletionAction, MarkDeletedResult};
use syncback_core::erasure::RaptorQEncoder;
use syncback_core::placement::{compute_allocation, HolderCandidate};
use syncback_core::reliability::{
    BlockReliabilityInput, HolderReliabilityInput, ReliabilityReport,
    block_reliability, build_report, commitment_to_survival_prob, per_holder_impact,
};
use syncback_core::types::{
    DeviceId, ErasureParams, Event, EventEntry, FileId, FileRecord, FileVersion,
    HoldingRecord, HoldingStatus, IdentityPub, LocalState, PlacementStatus,
    SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType,
    SymbolPlacement, Timestamp,
};

// syncback daemon
use syncback::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};
use syncback::daemon::backup::pipeline::{compress_and_encrypt, decrypt_and_decompress};
use syncback::daemon::cluster_sync::{ClusterSyncConfig, ClusterSyncManager};
use syncback::daemon::repair::{RepairAgent, RepairConfig};
use syncback::daemon::restore::{RestoreConfig, RestoreCoordinator, RestoreRequest, VersionSelector};
use syncback::daemon::network::{NetworkConfig, NetworkHandle};

// misc
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
```

---

## 5.2 — Integration tests (`crates/syncback/tests/phase4_gate.rs`)

### File header

```rust
// Phase 4 Gate: integration tests for Phase 4 modules.
//
// Tests in this file exercise cross-module flows involving:
//   config, deletion, commitment, reliability, disk pressure
//   together with the existing pipeline (backup, restore, repair).
//
//   1. config_source_block_size_drives_backup
//      — custom source_block_size_mb → BackupCoordinator uses it
//   2. deletion_cooldown_full_lifecycle
//      — delete file → cooldown → SendDropNotice → cleanup actions
//   3. commitment_plus_reliability_flags_weak_holder
//      — compute scores → build report → flag for proactive repair
//   4. disk_pressure_effective_quota_blocks_over_soft_cap
//      — compute_effective_quota + should_reject_offers integration
//   5. full_pipeline_with_phase4_integration
//      — backup → mark holder Lost → check reliability → proactive repair
//
// GATE CRITERIA: all 5 tests pass → Phase 4 integration is verified.
```

### Test 1: `config_source_block_size_drives_backup`

Verify that `AppConfig.backup.source_block_size_mb` is correctly threaded
through to `BackupCoordinator` via `source_block_size_bytes()`.

Setup:
- Build `AppConfig` with `backup.source_block_size_mb = 1` (1 MB, smallest power of two >= 1)
- Call `source_block_size_bytes(&cfg)` → expect 1_048_576
- Build `AppConfig::default()` → `source_block_size_bytes` → expect `DEFAULT_SOURCE_BLOCK_SIZE` (128 MB)
- Build a `BackupCoordinator` with a custom config derived from `AppConfig` with `source_block_size_mb = 2`
- Back up a file that is larger than 2 MB but smaller than 4 MB
- Call `flush_all(true)` — verify it produces exactly 2 source blocks (file split across two 2MB blocks)

Implementation notes:
- Use `source_block_size: 2 * 1_048_576` in BackupConfig
- File content: 3 MB of deterministic bytes (pattern `i as u8`)
- File is a single large file so `process_large_file` path is used (size > source_block_size)

Expected assertions:
```rust
assert_eq!(source_block_size_bytes(&one_mb_cfg), 1_048_576);
assert_eq!(source_block_size_bytes(&AppConfig::default()), DEFAULT_SOURCE_BLOCK_SIZE);
// Backup of 3MB file with 2MB block size → 2 PipelineResults
assert_eq!(results.len(), 2, "3MB file split into 2 source blocks at 2MB each");
```

### Test 2: `deletion_cooldown_full_lifecycle`

Verify the full deletion pipeline from watcher event through all action phases.

Setup:
- `DeletionEngine::new()`
- One `FileRecord` with `devices = [(DEVICE_A, Present)]` and one `FileVersion`
- One `SourceBlockRecord` with `status = Active`, `block_type = SourceBlockType::Single`
- Two `SymbolPlacement` records for the block, both `status = Alive`

Phase 1 — mark deleted on the only device:
```rust
let result = engine.mark_deleted(&file, DEVICE_A, now)?;
// Expected: CooldownStarted { deleted_at: now, notify_after: now + OWNER_DELETE_COOLDOWN_SECS }
```

Phase 2 — process_cooldowns before owner cooldown elapsed:
```rust
let file_with_deleted = /* update devices to Deleted(now) */;
let actions = engine.process_cooldowns(&[file_with_deleted.clone()], &[block], &placements, now);
assert!(actions.is_empty(), "before owner cooldown, no actions");
```

Phase 3 — process_cooldowns after owner cooldown, before holder cooldown:
```rust
let after_owner = Timestamp(now.0 + OWNER_DELETE_COOLDOWN_SECS + 1);
let actions = engine.process_cooldowns(&[file_with_deleted.clone()], &[block], &placements, after_owner);
// Expect 2 SendDropNotice actions (one per holder)
let send_drops: Vec<_> = actions.iter()
    .filter(|a| matches!(a, DeletionAction::SendDropNotice { .. }))
    .collect();
assert_eq!(send_drops.len(), 2);
```

Phase 4 — process_cooldowns after both cooldowns:
```rust
let after_both = Timestamp(now.0 + OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS + 1);
// Update both placements to status = Deleting
let deleting_placements = /* set status = PlacementStatus::Deleting */;
let actions = engine.process_cooldowns(&[file_with_deleted], &[block_deleting], &deleting_placements, after_both);
// Expect 2 CleanupPlacement + 1 CleanupBlock
let cleanups: Vec<_> = actions.iter()
    .filter(|a| matches!(a, DeletionAction::CleanupPlacement { .. }))
    .collect();
assert_eq!(cleanups.len(), 2);
let block_cleanups: Vec<_> = actions.iter()
    .filter(|a| matches!(a, DeletionAction::CleanupBlock { .. }))
    .collect();
assert_eq!(block_cleanups.len(), 1);
```

Numeric inputs:
- `now = Timestamp(1_700_000_000)`
- `OWNER_DELETE_COOLDOWN_SECS = 4 * 604_800 = 2_419_200`
- `HOLDER_DELETE_COOLDOWN_SECS = 4 * 604_800 = 2_419_200`

### Test 3: `commitment_plus_reliability_flags_weak_holder`

Verify that commitment score + reliability forecast integration correctly
identifies a weak holder and flags it for proactive repair.

Setup:
- `block_id = SourceBlockId([0x01; 32])`
- `k_eff = 5` (small for fast test)
- 3 holders:
  - Holder H1 (strong): 100 recent challenges, 98 passes, 0 misses, not rejected, not dropped, first_seen 52 weeks ago → CommitmentTier::High
  - Holder H2 (medium): 20 challenges, 14 passes, 1 miss, not rejected → CommitmentTier::Medium
  - Holder H3 (at-risk): 5 challenges, 1 pass, 4 misses (`consecutive_misses >= POS_CONSECUTIVE_MISS_PRESUMED_LOST`), rejected recently → CommitmentTier::AtRisk

Compute commitment scores:
```rust
let score_h1 = compute_commitment(&profile_h1)?;
let score_h2 = compute_commitment(&profile_h2)?;
let score_h3 = compute_commitment(&profile_h3)?;
assert_eq!(score_h1.tier(), CommitmentTier::High);
assert_eq!(score_h3.tier(), CommitmentTier::AtRisk);
```

Convert to survival probabilities via `commitment_to_survival_prob`:
```rust
let p_h1 = commitment_to_survival_prob(score_h1); // high → close to 1.0
let p_h3 = commitment_to_survival_prob(score_h3); // at-risk → close to 0.0
assert!(p_h1 > p_h3, "strong holder has higher survival prob");
```

Build reliability report:
```rust
let input = BlockReliabilityInput {
    block_id,
    k_eff: 5,
    holders: vec![
        HolderReliabilityInput { holder_id: h1, alive_symbols: 50, survival_prob: p_h1 },
        HolderReliabilityInput { holder_id: h2, alive_symbols: 30, survival_prob: p_h2 },
        HolderReliabilityInput { holder_id: h3, alive_symbols: 20, survival_prob: p_h3 },
    ],
};
let report = build_report(&input)?;
assert_eq!(report.symbols_alive, 100);
assert_eq!(report.symbols_needed, 5);
// weakest_holder_impact must point to H3 (most critical)
let weakest = report.weakest_holder_impact.as_ref().unwrap();
assert_eq!(weakest.holder_id, h3);
```

Flag for proactive repair at importance=0.8:
```rust
let pairs = vec![
    (h1, score_h1),
    (h2, score_h2),
    (h3, score_h3),
];
let flagged = flag_for_proactive_repair(&pairs, 0.8);
assert!(flagged.contains(&h3), "AtRisk holder flagged");
assert!(!flagged.contains(&h1), "High holder not flagged");
```

### Test 4: `disk_pressure_effective_quota_blocks_over_soft_cap`

Verify the disk pressure two-tier quota integration.

```rust
// Scenario: soft_quota = 50 GiB, disk is large, used = 47 GiB → should_reject_offers = true
let soft_quota_bytes = 50 * 1024 * 1024 * 1024u64;
let disk_free = 200 * 1024 * 1024 * 1024u64;
let disk_reserve = 20 * 1024 * 1024 * 1024u64;
let effective = compute_effective_quota(soft_quota_bytes, disk_free, disk_reserve);
// effective = min(50 GiB, 180 GiB) = 50 GiB
assert_eq!(effective, soft_quota_bytes);

let used = 47 * 1024 * 1024 * 1024u64;
// free_ratio = (50 - 47) / 50 = 0.06 < 0.15 threshold → reject
assert!(should_reject_offers(effective, used), "near cap → reject new offers");

// Scenario: disk full overrides soft_quota
let disk_free_tight = 22 * 1024 * 1024 * 1024u64; // only 2 GiB available after reserve
let effective_tight = compute_effective_quota(soft_quota_bytes, disk_free_tight, disk_reserve);
// available_from_disk = 22 - 20 = 2 GiB; min(50, 2) = 2 GiB
assert_eq!(effective_tight, 2 * 1024 * 1024 * 1024u64, "disk free overrides soft_quota");

// Scenario: no soft cap, disk is the only limit
let effective_no_cap = compute_effective_quota(0, disk_free, disk_reserve);
assert_eq!(effective_no_cap, 180 * 1024 * 1024 * 1024u64);
```

### Test 5: `full_pipeline_with_phase4_integration`

End-to-end flow: backup → mark placement Lost → build reliability report → flag for repair.
Validates that Phase 4 modules (commitment, reliability) hook into Phase 2/2.5 state.

Setup:
- Back up a small file (same pattern as phase2_gate.rs `full_backup_restore_roundtrip`)
- After backup, look up all placements from the DB
- Take the first placement and call `repair_agent.handle_pos_nack()` on it → status becomes Lost
- Build a `HolderProfile` for that holder (simulated: 0 challenges, 0 passes, consecutive_misses = 3)
- Compute `CommitmentScore` → expect `CommitmentTier::AtRisk`
- Build `BlockReliabilityInput` from DB state:
  - Include all placements with `status = Alive` only (exclude the Lost one)
  - Use `commitment_to_survival_prob(CommitmentScore::new(0.9))` for alive holders (mock high commitment)
- Call `build_report()` → verify `needs_repair` reflects reduced symbol count
- Call `flag_for_proactive_repair` with the Lost holder's score → Lost holder is flagged

This test does NOT do an actual network repair delivery — it verifies the
decision logic works end-to-end given DB state produced by the backup pipeline.

Pseudo-structure:
```rust
#[tokio::test]
async fn full_pipeline_with_phase4_integration() {
    let db = Db::open_in_memory().unwrap();
    let symbols_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    // Phase 2: backup a file
    let content: Vec<u8> = (0..8192u32).map(|i| (i * 7) as u8).collect();
    let path = write_file(&files_dir, "report.bin", &content);
    let mut backup = BackupCoordinator::new(db.clone(), backup_config(&symbols_dir), Arc::new(RaptorQEncoder::new()));
    backup.process_event(DirtyEvent { path: path.clone(), kind: DirtyKind::Added, device_id: DEVICE_A }).unwrap();
    let results = backup.flush_all(true).unwrap();
    assert!(!results.is_empty());

    // Phase 2.5: mark first placement as Lost via PosNack
    let block_id = results[0].source_block_id;
    let placements = db.list_placements_for_block(&block_id).unwrap();
    assert!(!placements.is_empty());
    let victim = &placements[0];

    let repair_agent = RepairAgent::new(db.clone(), repair_config(&symbols_dir), Arc::new(RaptorQEncoder::new()));
    repair_agent.handle_pos_nack(&victim.source_block_id, &victim.holder_id, Timestamp::now()).await.unwrap();

    // Verify status is now Lost
    let updated = db.get_placement(&victim.source_block_id, &victim.holder_id).unwrap().unwrap();
    assert_eq!(updated.status, PlacementStatus::Lost);

    // Phase 4 commitment: build profile for the lost holder
    let lost_profile = HolderProfile {
        holder_id: victim.holder_id,
        recent_challenges: 5,
        recent_passes: 0,
        consecutive_misses: 3,
        offers_rejected_recently: true,
        drop_notice_sent_recently: true,
        our_eviction_priority: 0.9,
        max_known_eviction_priority: 1.0,
        first_seen: Timestamp(Timestamp::now().0.saturating_sub(10 * 7 * 86400)),
        now: Timestamp::now(),
    };
    let lost_score = compute_commitment(&lost_profile).unwrap();
    assert_eq!(lost_score.tier(), CommitmentTier::AtRisk);

    // Phase 4 reliability: build report from alive placements only
    let alive_placements: Vec<_> = db.list_placements_for_block(&block_id).unwrap()
        .into_iter()
        .filter(|p| p.status == PlacementStatus::Alive)
        .collect();

    let block_record = db.get_source_block(&block_id).unwrap().unwrap();
    let k_eff = block_record.k + 3;

    let reliability_input = BlockReliabilityInput {
        block_id,
        k_eff,
        holders: alive_placements.iter().map(|p| HolderReliabilityInput {
            holder_id: p.holder_id,
            alive_symbols: p.symbol_count(),
            survival_prob: 0.9_f64.powi(2), // mock: score=0.9 → p=0.81
        }).collect(),
    };
    let report = build_report(&reliability_input).unwrap();

    // With one placement lost, alive symbol count is reduced
    let total_from_alive: u32 = alive_placements.iter().map(|p| p.symbol_count()).sum();
    assert_eq!(report.symbols_alive, total_from_alive);

    // Proactive repair flag
    let alive_scores: Vec<_> = alive_placements.iter()
        .map(|p| (p.holder_id, CommitmentScore::new(0.9)))
        .collect();
    let flagged = flag_for_proactive_repair(&alive_scores, 0.5);
    // No alive holder is AtRisk (all have score 0.9)
    assert!(flagged.is_empty(), "no alive holder should be flagged when commitment is high");

    // But the lost holder would be flagged
    let all_scores = vec![(victim.holder_id, lost_score)];
    let flagged_lost = flag_for_proactive_repair(&all_scores, 0.5);
    assert!(flagged_lost.contains(&victim.holder_id));
}
```

---

## 5.3 — Cluster integration tests (`crates/syncback/tests/phase5_cluster.rs`)

### File header

```rust
// Phase 5 Cluster: cluster integration tests.
//
// Exercises multi-device flows end-to-end.
//
//   1. two_devices_backup_then_dedup_on_second
//      — Device A backs up a file. Device B (same cluster) skips it as dedup.
//   2. device_revocation_epoch_rotation_rejects_revoked_key
//      — Revoke device A. Partners (via PeerRecord) reject A's old device key.
//   3. cluster_sync_propagates_file_deletion_event
//      — Device A deletes a file (Event::FileDeleted). Device B syncs → sees deletion.
//
// GATE CRITERIA: all 3 tests pass → Phase 5 cluster is verified.
```

### Constants and helpers (shared within file)

```rust
const SEED: &[u8] = &[0xBB_u8; 64];
const DEVICE_A_ID: DeviceId = DeviceId([0xA1u8; 16]);
const DEVICE_B_ID: DeviceId = DeviceId([0xB1u8; 16]);
const NOW: Timestamp = Timestamp(1_700_000_000);
const EPOCH_KEY: [u8; 32] = [0x55u8; 32];
const SMALL_BLOCK_SIZE: u64 = 65_535 * 2;

fn mk() -> ed25519_dalek::SigningKey { derive_master_key(SEED).unwrap() }
fn device_pub(id: DeviceId) -> [u8; 32] {
    derive_device_key(SEED, &id).unwrap().verifying_key().to_bytes()
}
fn init_cluster(db: Db) -> ClusterState {
    let master = mk();
    let mp = master_identity(&master);
    let cert_a = issue_device_certificate(&master, DEVICE_A_ID, device_pub(DEVICE_A_ID), NOW);
    let mut state = ClusterState::init(db, mp, cert_a, NOW, NOW).unwrap();
    let cert_b = issue_device_certificate(&master, DEVICE_B_ID, device_pub(DEVICE_B_ID), NOW);
    state.add_device(cert_b, NOW).unwrap();
    state
}
fn holders_5() -> Vec<HolderCandidate> {
    (0..5).map(|i| HolderCandidate { identity: IdentityPub([(i + 1) as u8; 32]), trust: 0.3 + i as f64 * 0.1 }).collect()
}
fn backup_cfg_with_cluster(symbols_dir: &TempDir, cluster_state: Arc<Mutex<ClusterState>>) -> BackupConfig {
    BackupConfig {
        source_block_size: SMALL_BLOCK_SIZE,
        symbols_dir: symbols_dir.path().to_path_buf(),
        epoch_key: EPOCH_KEY,
        device_id: DEVICE_A_ID,
        mock_holders: holders_5(),
        cluster_state: Some(cluster_state),
    }
}
fn write_file(dir: &TempDir, name: &str, content: &[u8]) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, content).unwrap();
    path.to_string_lossy().into_owned()
}
```

### Test 1: `two_devices_backup_then_dedup_on_second`

Shared identity, two devices. Device A backs up a file. Device B encounters
the same file and the BackupCoordinator skips it via dedup check.

Steps:
1. Shared DB (simulates devices sharing a DB on same hardware, or post-sync state)
2. Device A: `BackupCoordinator::new(db, config_with_cluster_state, encoder)`
3. Back up a file. `flush_all(true)` → produces one source block.
4. Verify `FileRecord.versions[0].backed_up_at = Some(...)` via `db.get_file(path)`
5. Device B: new `BackupCoordinator` pointing at same DB, same cluster state, but `device_id = DEVICE_B_ID`
6. `process_event` with the same file path and a content hash that matches the already-backed-up version
7. `flush_all(true)` → should produce zero new source blocks (dedup skip)
8. Assert the DB still has exactly one source block for that content

Note: The dedup check in `BackupCoordinator::handle_added_or_modified` calls
`cluster_state.is_content_backed_up(content_hash)`. The implementation must
return true when a matching version with `backed_up_at = Some(...)` exists.

Expected:
```rust
let results_a = backup_a.flush_all(true).unwrap();
assert_eq!(results_a.len(), 1, "device A creates one source block");

// Device B with same content → dedup skips it
let results_b = backup_b.flush_all(true).unwrap();
assert_eq!(results_b.len(), 0, "device B dedup skips already-backed-up content");

let blocks = db.list_all_source_blocks().unwrap();
assert_eq!(blocks.len(), 1, "only one source block in DB");
```

### Test 2: `device_revocation_epoch_rotation_rejects_revoked_key`

Revoke device A. Verify:
- Epoch increments
- A is in the revoked list
- Partners learn about revocation via `PeerRecord::revoked_device_pub_keys`
- `is_device_revoked` returns true for A's device key

Steps:
1. Create `ClusterState` with both devices
2. Revoke DEVICE_A_ID → new epoch = EpochCounter(1)
3. Build a `RevocationBroadcast` (same as phase3_gate test 5)
4. Create a `PeerRecord` for an external peer. Simulate receiving the broadcast by
   appending the revoked device pub key to `PeerRecord::revoked_device_pub_keys`
5. Assert `peer_record.is_device_revoked(&IdentityPub(device_pub(DEVICE_A_ID)))` = true
6. Assert `peer_record.is_device_revoked(&IdentityPub(device_pub(DEVICE_B_ID)))` = false
7. Derive epoch keys before and after: `derive_epoch_key(SEED, EpochCounter(0))` vs `derive_epoch_key(SEED, EpochCounter(1))`
   — verify they differ

```rust
assert!(state.is_device_revoked(&DEVICE_A_ID));
assert!(!state.is_device_revoked(&DEVICE_B_ID));
assert_eq!(state.current_epoch(), EpochCounter(1));
assert!(peer_record.is_device_revoked(&IdentityPub(device_pub(DEVICE_A_ID))));
assert!(!peer_record.is_device_revoked(&IdentityPub(device_pub(DEVICE_B_ID))));
let ek0 = derive_epoch_key(SEED, EpochCounter(0)).unwrap();
let ek1 = derive_epoch_key(SEED, EpochCounter(1)).unwrap();
assert_ne!(ek0.key_bytes, ek1.key_bytes);
```

### Test 3: `cluster_sync_propagates_file_deletion_event`

Device A deletes a file (records `Event::FileDeleted`). Device B syncs from A
and the event appears in B's event log.

Steps:
1. Separate DBs for A and B (both start with same ClusterState seed)
2. Add a file to A's DB and emit `Event::FileAdded`
3. Emit `Event::FileDeleted` on A's DB for the same file
4. B requests sync from A via ClusterSyncManager
5. A responds with both events
6. B applies the response
7. Verify B's DB `last_event_seq` advanced
8. Verify at least one `Event::FileDeleted` is in the events returned from A

```rust
let events_returned = &response.events;
let has_deletion = events_returned.iter().any(|entry| {
    matches!(&entry.event, Event::FileDeleted { file_id, .. } if *file_id == file_id_a)
});
assert!(has_deletion, "FileDeleted event must be present in sync response");

// After applying, B's cursor for A advances
let req2 = sync_b.build_sync_request(&a_identity);
assert_eq!(req2.last_known_seq, a_last_seq, "cursor advances after sync");
```

---

## 5.4 — Stress test (`crates/syncback/tests/stress_5tb.rs`)

### Purpose

Simulate the metadata scale of a 5 TB photographer scenario without moving
5 TB of data. Tests DB performance, placement correctness, and reliability
forecast at scale. All file data is fake (zero/pattern bytes, not read from disk).

### File header

```rust
// Stress test: 5 TB photographer scenario simulation.
//
// Does NOT move 5 TB of actual data. Simulates metadata at scale:
//   - 500_000 FileRecords
//   - 35_000 SourceBlocks (128 MB each → ~4.4 TB total)
//   - 15 holders per block → 525_000 SymbolPlacement records
//   - Computes reliability forecasts for all blocks
//
// Target: verify that DB operations, placement, and reliability work at scale
// within reasonable time and memory bounds. Not a benchmark.
//
// Run with: cargo test -p syncback --test stress_5tb -- --ignored --nocapture
//
// GATE: all assertions pass. No OOM (< 2 GB RSS at peak).

#[cfg(test)]
mod tests {
    // all tests are #[ignore] — run explicitly with --ignored
}
```

### Test: `stress_5tb_metadata_scale`

Attribute: `#[test] #[ignore]`

Parameters (defined as constants at top of file):
```rust
const N_FILES: usize = 500_000;
const N_BLOCKS: usize = 35_000;
const HOLDERS_PER_BLOCK: usize = 15;
const SYMBOLS_PER_HOLDER: u32 = 100; // simplified: fixed count
const K_EFF: u32 = 2051; // K=2048 + DECODE_OVERHEAD=3
const IMPORTANCE: f64 = 0.5;
```

Phase 1 — DB insertion:
1. Open `Db::open_in_memory()`
2. Insert `N_BLOCKS` `SourceBlockRecord` entries. Use sequential IDs (block_id = BLAKE3 of block index as u64 LE bytes). Set `status = Active`, `block_type = Single`, `k = 2048`, `t = 65535`
3. For each block, insert `HOLDERS_PER_BLOCK` `SymbolPlacement` records. Holder IDs are cycled from 30 distinct mock holders (rotate through `holder_ids[holder_idx % 30]`). `status = Alive`, `esi_ranges = [(holder_idx as u32 * SYMBOLS_PER_HOLDER, SYMBOLS_PER_HOLDER)]`
4. Insert `N_FILES` `FileRecord` entries. Each references one source block.

Time assertions (wall-clock, not CPU):
```rust
let start = std::time::Instant::now();
// ... all inserts ...
let elapsed = start.elapsed();
assert!(elapsed.as_secs() < 120, "500K files + 35K blocks + 525K placements must insert in < 120s");
```

Phase 2 — DB reads:
1. `db.list_all_source_blocks()` → verify count = `N_BLOCKS`
2. `db.list_placements_for_block(&block_ids[0])` → verify count = `HOLDERS_PER_BLOCK`
3. For a random block (block 17500): list its placements and verify symbol counts

Phase 3 — placement correctness on one block:
1. Build 30 `HolderCandidate`s with varying trust (trust = 0.3 + i * 0.02, i in 0..30)
2. Use `ErasureParams::compute(128 * 1024 * 1024, IMPORTANCE)` → K=2048, K_eff=2051
3. Call `compute_allocation(&candidates, &params)` → verify:
   - `allocations.len() <= MAX_HOLDERS_PER_BLOCK` (30)
   - `allocations.len() >= 2`
   - Each allocation has `symbol_count >= MIN_SYMBOLS_PER_HOLDER` (32)
   - Total allocated symbols `>= K_eff` (can reconstruct)

Phase 4 — reliability forecast at scale:
1. For a sample of 1000 blocks (blocks 0, 35, 70, ... every 35th): compute `block_reliability` using `survival_prob = 0.81` (score=0.9 → p=0.81) for all holders
2. For each sampled block: assert `reliability > 0.999` (with 15 holders × 100 symbols each = 1500 alive, K_eff=2051, p=0.81 → should be extremely reliable)
3. Record max, min, mean reliability — assert `min_reliability > 0.99`

Note: `block_reliability` at K_eff=2051 with N=1500 and p=0.81 will actually be < 1.0 because
N < K_eff (1500 < 2051). Adjust the scenario: use `K_eff = 500` for the reliability test,
or use `SYMBOLS_PER_HOLDER = 200` so total = 30 * 200 = 6000 > 2051.

**CORRECTION — use these parameters for the reliability phase:**
```rust
const STRESS_K_EFF: u32 = 500;   // small k_eff for fast math
const STRESS_HOLDERS: usize = 15;
const STRESS_SYMS_PER_HOLDER: u32 = 200; // total = 3000 > 500
```

Phase 5 — memory bound:
The test must not exceed 2 GB RSS. This is asserted informally by the CI
passing on the 64 GB server. No explicit assert in code — just verify it does
not crash with OOM.

Expected output (with `--nocapture`):
```
stress_5tb: inserted 500000 files, 35000 blocks, 525000 placements in Xs
stress_5tb: placement check on block #0: 30 holders, 9000 total symbols, all >= 32
stress_5tb: reliability sample (1000 blocks): min=0.9999, mean=1.0000
PASSED
```

Use `eprintln!` for progress output (goes to stderr with `--nocapture`).

---

## 5.5 — E2E test (`crates/syncback/tests/e2e.rs`)

### Purpose

Full lifecycle of a single node: backup → version → selective restore → cluster
join → dedup → device revocation → file deletion.

All operations are in-process (no actual network, no actual filesystem watch).
Uses `BackupCoordinator`, `RestoreCoordinator`, `ClusterState`, `DeletionEngine` directly.

### File header

```rust
// E2E: full lifecycle test — backup → version → selective restore →
//      cluster → dedup → revocation → deletion.
//
// One test function covers the complete SyncBack β user story.
// No network, no filesystem watcher — direct API calls only.
//
// Run with: cargo test -p syncback --test e2e -- --nocapture
```

### Test: `full_lifecycle_e2e`

Attribute: `#[tokio::test]`

#### Step 1 — Backup 3 files

Files:
- `photo.jpg` — 8 KB pattern bytes (importance=0.8, FileCategory::Photo)
- `document.txt` — 2 KB ASCII text (importance=0.5, FileCategory::Document)
- `archive.tar` — 16 KB pattern bytes (importance=0.3, FileCategory::Other)

```rust
// Write files to TempDir, process_event for each, flush_all(true)
let results = backup.flush_all(true).unwrap();
assert!(!results.is_empty(), "at least one source block created");

// All 3 files present in DB
let all_files = db.list_all_files().unwrap();
assert_eq!(all_files.len(), 3);
// All backed up
for f in &all_files {
    assert!(f.versions[0].backed_up_at.is_some(), "file must be backed up: {}", f.path);
}
```

#### Step 2 — Modify `photo.jpg` → creates second version

```rust
// Write new content to photo.jpg
let new_content: Vec<u8> = (0..8192u32).map(|i| ((i * 13 + 5) % 256) as u8).collect();
std::fs::write(&photo_path, &new_content).unwrap();

backup.process_event(DirtyEvent { path: photo_path.clone(), kind: DirtyKind::Modified, device_id: DEVICE_A }).unwrap();
backup.flush_all(true).unwrap();

let photo_record = db.get_file(&photo_path).unwrap().expect("photo must exist in DB");
assert_eq!(photo_record.versions.len(), 2, "photo must have 2 versions after modification");
let v0_hash = photo_record.versions[0].content_hash;
let v1_hash = photo_record.versions[1].content_hash;
assert_ne!(v0_hash, v1_hash, "versions must have different content hashes");
```

#### Step 3 — Selective restore

Sub-test 3a — restore photo.jpg at Latest version:
```rust
let result = restore.restore(RestoreRequest {
    path: photo_path.clone(),
    version_selector: VersionSelector::Latest,
    output_dir: out_dir.path().to_path_buf(),
    device_id: DEVICE_B,
}).await.unwrap();
assert_eq!(result.files_restored, 1);
let rel = photo_path.trim_start_matches('/');
let restored_bytes = std::fs::read(out_dir.path().join(rel)).unwrap();
assert_eq!(restored_bytes, new_content, "Latest restore must return v1 content");
```

Sub-test 3b — restore photo.jpg at Version(0):
```rust
let result_v0 = restore.restore(RestoreRequest {
    path: photo_path.clone(),
    version_selector: VersionSelector::Version(0),
    output_dir: out_dir_v0.path().to_path_buf(),
    device_id: DEVICE_B,
}).await.unwrap();
let restored_v0 = std::fs::read(out_dir_v0.path().join(rel)).unwrap();
assert_eq!(restored_v0, original_photo_content, "Version(0) restore must return v0 content");
```

Sub-test 3c — restore by directory prefix (all 3 files):
```rust
let prefix = files_dir.path().to_string_lossy().to_string() + "/";
let result_all = restore.restore(RestoreRequest {
    path: prefix,
    version_selector: VersionSelector::Latest,
    output_dir: out_dir_all.path().to_path_buf(),
    device_id: DEVICE_B,
}).await.unwrap();
assert_eq!(result_all.files_restored, 3, "all 3 files restored");
assert!(result_all.failures.is_empty());
```

#### Step 4 — Add second device → verify dedup

```rust
// Shared DB. Device B joins the cluster.
let cluster_state = Arc::new(Mutex::new(init_cluster(db.clone())));

// Reconfigure backup to use cluster_state
let mut backup_with_cluster = BackupCoordinator::new(
    db.clone(),
    BackupConfig {
        cluster_state: Some(Arc::clone(&cluster_state)),
        device_id: DEVICE_B_ID,
        ..backup_config(&symbols_dir)
    },
    Arc::new(RaptorQEncoder::new()),
);

// Device B tries to back up the same photo.jpg — same content hash → dedup
let b_photo_path = write_file(&files_dir_b, "photo.jpg", &new_content);
backup_with_cluster.process_event(DirtyEvent {
    path: b_photo_path.clone(),
    kind: DirtyKind::Added,
    device_id: DEVICE_B_ID,
}).unwrap();
let results_b = backup_with_cluster.flush_all(true).unwrap();

// The content was already backed up by A → 0 new source blocks
assert_eq!(results_b.len(), 0, "device B dedup: no new source blocks for already-backed content");

let blocks_after = db.list_all_source_blocks().unwrap();
let photo_blocks_before = /* count blocks associated with photo before */;
// Same number of blocks: no new block created for B's photo
assert_eq!(blocks_after.len(), photo_blocks_before);
```

#### Step 5 — Revoke device B → verify key rejection

```rust
let master = derive_master_key(SEED).unwrap();
let new_epoch = EpochCounter(1);
let rev = issue_revocation(&master, DEVICE_B_ID, NOW, new_epoch);
let cluster_guard = cluster_state.lock().unwrap();
// revoke_device() is tested here using the ClusterState API from phase3_gate
let mut state = cluster_state.lock().unwrap();
state.revoke_device(rev.clone(), NOW, NOW).unwrap();

assert!(state.is_device_revoked(&DEVICE_B_ID), "B must be revoked");
assert_eq!(state.current_epoch(), EpochCounter(1));

// PeerRecord for an external partner now has B's device key in revoked list
let b_device_pub = device_pub(DEVICE_B_ID);
let mut peer = PeerRecord { /* ... */ revoked_device_pub_keys: vec![], /* ... */ };
peer.revoked_device_pub_keys.push(b_device_pub);
assert!(peer.is_device_revoked(&IdentityPub(b_device_pub)));
assert!(!peer.is_device_revoked(&IdentityPub(device_pub(DEVICE_A_ID))));
```

#### Step 6 — Delete file → verify cooldown → cleanup actions

```rust
let engine = DeletionEngine::new();

// Get the document.txt FileRecord from DB
let doc_record = db.get_file(&doc_path).unwrap().expect("doc must be in DB");

// Mark deleted on the only device (DEVICE_A)
let result = engine.mark_deleted(&doc_record, DEVICE_A, NOW)?;
assert!(matches!(result, MarkDeletedResult::CooldownStarted { .. }));
if let MarkDeletedResult::CooldownStarted { notify_after, .. } = result {
    assert_eq!(notify_after.0, NOW.0 + OWNER_DELETE_COOLDOWN_SECS);
}

// Update doc FileRecord in DB to have Deleted(NOW) state
let mut updated_doc = doc_record.clone();
updated_doc.devices[0].1 = LocalState::Deleted(NOW);
db.upsert_file(&updated_doc).unwrap();

// Before cooldown: no actions
let blocks = db.list_all_source_blocks().unwrap();
let placements: Vec<_> = blocks.iter()
    .flat_map(|b| db.list_placements_for_block(&b.block_id).unwrap())
    .collect();
let pre_cooldown_actions = engine.process_cooldowns(
    &[updated_doc.clone()], &blocks, &placements, NOW);
assert!(pre_cooldown_actions.is_empty(), "no actions before cooldown");

// After owner cooldown: SendDropNotice actions
let after_owner = Timestamp(NOW.0 + OWNER_DELETE_COOLDOWN_SECS + 1);
let actions = engine.process_cooldowns(&[updated_doc], &blocks, &placements, after_owner);
let drop_notices: Vec<_> = actions.iter()
    .filter(|a| matches!(a, DeletionAction::SendDropNotice { .. }))
    .collect();
assert!(!drop_notices.is_empty(), "drop notices must be generated after owner cooldown");
```

### E2E success criteria

All 6 steps pass without panic. The test logs each step result via `eprintln!`
for traceability:
```
[E2E] Step 1: 3 files backed up (2 source blocks)
[E2E] Step 2: photo.jpg has 2 versions, content hashes differ
[E2E] Step 3a: Latest restore — byte-for-byte match (v1)
[E2E] Step 3b: Version(0) restore — byte-for-byte match (v0)
[E2E] Step 3c: directory restore — 3 files restored
[E2E] Step 4: dedup — 0 new source blocks for device B
[E2E] Step 5: device B revoked, epoch=1, peer rejects B's key
[E2E] Step 6: delete cooldown — drop notices generated after 4 weeks
[E2E] ALL STEPS PASSED
```

---

## Implementation notes for the implementer

### Regarding Phase 4 module availability

At the time these tests are written, Phase 4 modules (config, deletion, commitment, reliability, disk_pressure budget upgrade) are assumed to be implemented. If any module is not yet present, the corresponding test file will not compile — that is intentional and serves as a compilation gate.

### Test file organization

Each test file is standalone (not a mod.rs + tests.rs pair) — these are
integration tests in `crates/syncback/tests/`, consistent with `phase2_gate.rs`
and `phase3_gate.rs`.

### Helper deduplication

The helpers `write_file`, `backup_config`, `restore_config`, `test_holders` are
duplicated across test files (same pattern as existing gate files). Do NOT
extract to a shared module — test files in `tests/` cannot easily share helpers
without a `tests/common/mod.rs` and explicit `mod common` in each file. Keep
each file self-contained.

### Handling missing DB methods

If `Db::list_placements_for_block`, `Db::list_all_source_blocks`, or
`Db::get_file` do not exist yet in `syncback-core/src/db/mod.rs`, the
implementer must add them. They should be simple key scans matching what
existing methods do.

### stress_5tb.rs ignored attribute

The `#[ignore]` attribute is placed on each test function, not on the module.
The test is run on CI with `cargo test -p syncback --test stress_5tb -- --ignored`.
Do not add it to the default `cargo test` suite — it is too slow.

### Tolerance for Phase 4 API changes

If the exact signature of `evaluate_pressure` differs from what the disk_pressure
task spec describes (e.g., `hard_quota_bytes` is not yet added), adjust the test
to call the available API. Document any discrepancy with a `// TODO: update when
Phase 4.2 disk pressure is complete` comment.

---

## Definition of done

- `phase4_gate.rs`: 5 tests, all pass, no `#[ignore]`
- `phase5_cluster.rs`: 3 tests, all pass, no `#[ignore]`
- `stress_5tb.rs`: 1 test, `#[ignore]`, passes when run with `--ignored`
- `e2e.rs`: 1 test (`full_lifecycle_e2e`), passes, no `#[ignore]`
- `cargo test -p syncback` (without `--ignored`) passes: 9 new tests visible and green
- `cargo test -p syncback --test stress_5tb -- --ignored --nocapture` passes: 1 test green
- `cargo clippy -p syncback -- -D warnings` clean across all 4 new files
- No `unwrap()` in assertions — use `expect("descriptive message")` or `?` in `#[tokio::test]`
  (convention from existing gate tests: `unwrap()` is acceptable in tests where the intent is clear)
