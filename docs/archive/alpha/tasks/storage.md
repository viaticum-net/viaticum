# Task spec: storage module (Phase 2)

**Target file:** `crates/syncback/src/daemon/storage.rs`
**Phase:** 2
**Role:** Holder — stores foreign shards on disk, responds to PoS challenges, manages eviction

---

## Overview

`Storage` is the **holder-role** module. It handles everything that happens to shards we
hold for other owners:

- Validating and storing incoming shard blobs on disk
- Answering PoS challenges (read block, compute hash, build Merkle proof)
- Evicting shards under disk pressure (using `BudgetPlanner::evaluate_pressure`)
- Handling owner lifecycle messages: delete, cancel_delete
- Checking cooldowns and drop notices

`Storage` is **not a tokio task**. It is a struct called synchronously (well, async fn
calls) from within the Processor task. Processor is the only DB writer; Storage calls
`db.*` methods that write to `holding` table, but these are coordinated through Processor
which owns the `Storage` instance.

All blob files live under `{syncback_dir}/shards/{shard_id_hex[0..2]}/{shard_id_hex}.shard`.
The two-character prefix is for filesystem efficiency (same pattern as git objects).

---

## Dependencies

**syncback-core:**
- `db::Db` — CRUD on `holding` table, `peers` table (for allowlist check)
- `types::{ShardId, IdentityPub, HoldingRecord, ShardState, FileType, Timestamp}`
- `escrow::{EscrowChecker, RestoreDecision, DeleteDecision, DropNoticeDecision}`
- `budget::{BudgetPlanner, DiskPressure, PressureResult, EvictionTarget, DropNoticeTarget}`
- `messages::{ShardDescriptor, StorageWarningMsg}`
- `trust::TrustEngine` — score lookup for eviction priority (via BudgetPlanner)

**std:**
- `std::path::{Path, PathBuf}`
- `std::fs::{self, File, OpenOptions}`
- `std::io::{Read, Write, Seek, SeekFrom}`

**tokio (for async I/O):**
- `tokio::fs` — async file write for blob storage

**External:**
- `blake3` — blob hash verification
- `tracing`

---

## Public API

```rust
pub struct Storage {
    db: syncback_core::db::Db,
    shards_dir: PathBuf,          // {syncback_dir}/shards/
    quota_gb: f64,                // from StorageConfig.quota_gb
    escrow: syncback_core::escrow::EscrowChecker,
    budget: syncback_core::budget::BudgetPlanner,
}

impl Storage {
    /// Create and initialize. Creates `shards_dir` if it does not exist.
    pub fn new(
        db: syncback_core::db::Db,
        shards_dir: PathBuf,
        quota_gb: f64,
        trust: syncback_core::trust::TrustEngine,
    ) -> Result<Self, StorageError>;

    // -------------------------------------------------------------------------
    // Inbound shard acceptance (called from Processor on shard_offer / blob arrival)
    // -------------------------------------------------------------------------

    /// Check whether we should accept a shard offer (before the blob is transferred).
    /// Returns true if we have capacity and the owner is allowed.
    ///
    /// Does NOT persist anything. Processor decides whether to send shard_accept.
    pub fn should_accept_offer(
        &self,
        descriptor: &syncback_core::messages::ShardDescriptor,
    ) -> Result<OfferDecision, StorageError>;

    /// Store a shard blob after it has been transferred.
    ///
    /// Steps:
    ///   1. Verify blake3(blob) == descriptor.shard_id  (hash mismatch → StorageError::HashMismatch)
    ///   2. Verify descriptor.sig_owner is valid        (sig invalid → StorageError::InvalidSig)
    ///   3. Check disk pressure: if Hard → check if new priority > lowest held priority
    ///      (lazy reservation: re-evaluate space after blob arrives)
    ///   4. Write blob to shards_dir/{prefix}/{shard_id}.shard
    ///   5. Insert HoldingRecord in DB (state = Active)
    ///
    /// Returns Ok(()) on success.
    /// Returns Err(StorageError::NoBudget) if disk is too full even after considering eviction.
    pub async fn store_shard(
        &self,
        descriptor: &syncback_core::messages::ShardDescriptor,
        blob: &[u8],
    ) -> Result<(), StorageError>;

    // -------------------------------------------------------------------------
    // PoS challenge response (called from Processor on pos_challenge arrival)
    // -------------------------------------------------------------------------

    /// Respond to a PoS challenge.
    ///
    /// Steps:
    ///   1. Load blob from disk
    ///   2. Read the requested block range (64 KB blocks indexed from 0)
    ///   3. Compute hash = blake3(block_bytes || nonce)
    ///   4. Build Merkle proof path for the challenged block
    ///
    /// Returns PosAnswer { block_data_hash, merkle_proof }.
    pub fn answer_pos_challenge(
        &self,
        shard_id: ShardId,
        block_index: u32,
        nonce: &[u8; 32],
    ) -> Result<PosAnswer, StorageError>;

    // -------------------------------------------------------------------------
    // Restore (called from Processor on RestoreRequest direct message)
    // -------------------------------------------------------------------------

    /// Check escrow and return the shard blob for restore.
    ///
    /// Steps:
    ///   1. escrow.check_restore(shard_id, owner_pub, now) → Allowed / Denied
    ///   2. If Denied: return Err(StorageError::EscrowDenied(denial))
    ///   3. Load blob from disk, return bytes
    ///   4. Call escrow.record_restore(shard_id, owner_pub, blob.len() as u64, now)
    pub fn read_shard_for_restore(
        &self,
        shard_id: ShardId,
        owner_pub: &IdentityPub,
        now: Timestamp,
    ) -> Result<Vec<u8>, StorageError>;

    // -------------------------------------------------------------------------
    // Shard lifecycle (called from Processor on message dispatch)
    // -------------------------------------------------------------------------

    /// Handle owner's delete request. Marks shard as MarkedForDelete in DB.
    /// Does NOT delete blob yet (4-week cooldown applies).
    pub fn handle_delete_request(
        &self,
        shard_id: ShardId,
        owner_pub: &IdentityPub,
        now: Timestamp,
    ) -> Result<(), StorageError>;

    /// Handle owner's cancel_delete. Reverts shard to Active state.
    pub fn handle_cancel_delete(
        &self,
        shard_id: ShardId,
        owner_pub: &IdentityPub,
    ) -> Result<(), StorageError>;

    /// Process expired cooldowns: delete blobs for MarkedForDelete shards past 4 weeks.
    /// Called by Processor during weekly maintenance.
    /// Returns list of deleted shard IDs (for logging).
    pub fn process_expired_cooldowns(&self, now: Timestamp) -> Result<Vec<ShardId>, StorageError>;

    /// Process expired drop notices: delete blobs for Phase-2 eviction shards past 7 days.
    /// Called by Processor during weekly maintenance.
    /// Returns list of deleted shard IDs.
    pub fn process_expired_drop_notices(&self, now: Timestamp) -> Result<Vec<ShardId>, StorageError>;

    // -------------------------------------------------------------------------
    // Disk pressure (called from Processor on StorageWarning or periodic check)
    // -------------------------------------------------------------------------

    /// Evaluate current disk pressure and return eviction/drop-notice targets.
    ///
    /// Steps:
    ///   1. Compute used_gb = db.total_holding_bytes() / 1_073_741_824
    ///   2. Call budget.evaluate_pressure(quota_gb, used_gb, now.0)
    ///   3. Return PressureResult
    ///
    /// Caller (Processor) acts on PressureResult:
    ///   - For immediate_evictions: call evict_shard() for each
    ///   - For drop_notices: call record_drop_notice() and send shard_drop_notice message
    pub fn check_pressure(&self, now: Timestamp) -> Result<PressureResult, StorageError>;

    /// Immediately evict a shard (Phase 1 hard pressure). No cooldown.
    ///
    /// Steps:
    ///   1. Delete blob file from disk
    ///   2. db.delete_holding(shard_id)
    ///   3. Return owner_pub (so Processor can send shard_dropped message)
    pub fn evict_shard(
        &self,
        shard_id: ShardId,
        now: Timestamp,
    ) -> Result<IdentityPub, StorageError>;

    /// Record that we sent shard_drop_notice for a shard (Phase 2).
    /// Sets drop_notice_sent_at in HoldingRecord.
    pub fn record_drop_notice(
        &self,
        shard_id: ShardId,
        now: Timestamp,
    ) -> Result<(), StorageError>;

    // -------------------------------------------------------------------------
    // Storage warning (bit rot notification from challenger)
    // -------------------------------------------------------------------------

    /// Handle a storage_warning from a challenger (one of our stored shards may be corrupted).
    /// Verifies the shard blob's hash against the stored merkle_root.
    /// Returns true if the shard is intact, false if corrupted.
    pub fn handle_storage_warning(
        &self,
        shard_id: ShardId,
    ) -> Result<bool, StorageError>;

    // -------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------

    /// Return total bytes held on disk (from DB, not filesystem scan).
    pub fn used_bytes(&self) -> Result<u64, StorageError>;

    /// Return total number of shards held.
    pub fn shard_count(&self) -> Result<usize, StorageError>;
}
```

---

## Supporting types

```rust
/// Result of should_accept_offer().
#[derive(Debug)]
pub enum OfferDecision {
    /// Accept: we have space and owner is known.
    Accept,
    /// Reject: quota is at soft threshold (disk pressure soft).
    RejectFull,
    /// Reject: owner is not in peer directory (not a known partner).
    RejectUnknown,
    /// Reject: owner is not in allowlist and trust is zero.
    RejectNotAllowed,
}

/// PoS challenge answer.
#[derive(Debug)]
pub struct PosAnswer {
    /// blake3(block_bytes_in_range || nonce)
    pub block_data_hash: [u8; 32],
    /// Merkle proof path from the challenged block to the root.
    /// Each entry is a sibling node hash (for verification: combine left+right at each level).
    pub merkle_proof: Vec<[u8; 32]>,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("shard blob hash mismatch: expected {expected:?}, got {actual:?}")]
    HashMismatch {
        expected: syncback_core::types::ShardId,
        actual: [u8; 32],
    },

    #[error("invalid signature on shard descriptor: {0:?}")]
    InvalidSig(syncback_core::types::ShardId),

    #[error("escrow denied: {0:?}")]
    EscrowDenied(syncback_core::escrow::EscrowDenial),

    #[error("no budget: quota exceeded")]
    NoBudget,

    #[error("shard not found: {0:?}")]
    ShardNotFound(syncback_core::types::ShardId),

    #[error("shard blob file missing on disk: {0:?}")]
    BlobMissing(std::path::PathBuf),

    #[error("block index out of range: index {index}, shard has {blocks} blocks")]
    BlockOutOfRange { index: u32, blocks: u32 },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),

    #[error("escrow error: {0}")]
    Escrow(#[from] syncback_core::escrow::EscrowError),

    #[error("budget error: {0}")]
    Budget(#[from] syncback_core::budget::BudgetError),

    #[error("message error: {0}")]
    Message(#[from] syncback_core::messages::MessageError),
}
```

---

## DB operations

All DB reads/writes go through the `Db` handle (owned by Processor, shared via Arc clone).

| Operation | DB method | When |
|---|---|---|
| Check if owner is known | `db.get_peer(&owner_pub)` | `should_accept_offer` |
| Check disk pressure | `db.total_holding_bytes()` | `check_pressure`, `should_accept_offer` |
| Insert holding record | `db.upsert_holding(&record)` | `store_shard` |
| Read holding record | `db.get_holding(&shard_id)` | `answer_pos_challenge`, `read_shard_for_restore`, `evict_shard` |
| Mark for delete | `db.mark_holding_for_delete(&shard_id, ts)` | `handle_delete_request` |
| Cancel delete | `escrow.cancel_delete()` → `db.upsert_holding` | `handle_cancel_delete` |
| List expired cooldowns | `db.list_holding_cooldown_expired(now)` | `process_expired_cooldowns` |
| List expired drop notices | `db.list_holding_drop_notice_expired(now)` | `process_expired_drop_notices` |
| Delete holding record | `db.delete_holding(&shard_id)` | `evict_shard`, `process_expired_cooldowns`, `process_expired_drop_notices` |
| Set drop_notice_sent_at | `db.set_drop_notice_sent_at(&shard_id, deadline)` | `record_drop_notice` |
| Read restore log | `db.get_restore_log(&owner_pub)` | `read_shard_for_restore` (via `EscrowChecker`) |
| Update restore log | `db.upsert_restore_log(&log)` | `read_shard_for_restore` (via `EscrowChecker`) |
| List all held shards | `db.list_all_holding()` | `check_pressure` (via `BudgetPlanner`) |
| Count all held bytes | `db.total_holding_bytes()` | `used_bytes`, `check_pressure` |
| Count all held shards | scan holding table | `shard_count` |

---

## Blob file layout

```
{syncback_dir}/shards/
  ab/
    abcdef...shard    ← first 2 hex chars = subdir (256 subdirs max)
  cd/
    cdef12...shard
```

Shard file path:
```rust
fn shard_path(shards_dir: &Path, shard_id: &ShardId) -> PathBuf {
    let hex = shard_id.0.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let prefix = &hex[..2];
    shards_dir.join(prefix).join(format!("{hex}.shard"))
}
```

On `Storage::new()`, create the `shards_dir` if it does not exist:
```rust
tokio::fs::create_dir_all(&shards_dir).await?
```
Or use `std::fs::create_dir_all` since this is a one-time startup operation (not hot path).

---

## Business rules

### Offer acceptance (`should_accept_offer`)

1. Check soft threshold: `budget.should_reject_offers(quota_gb, used_gb)` → if true, return `RejectFull`
2. Check peer directory: `db.get_peer(&descriptor.owner_pub)` → if None, return `RejectUnknown`
   (alpha: we only store for known peers from our peer directory)
3. If peer is `allowlisted = true` → always `Accept` (bypass trust check)
4. Otherwise: `Accept` (if soft threshold not hit and peer is known)

Note: importanced-based priority check against existing shards is done at blob arrival
time (lazy reservation), not at offer time. This matches the protocol spec §1.7 step 3.

### Blob storage (`store_shard`)

1. **Hash verify:** `blake3(blob) != shard_id.0` → `StorageError::HashMismatch`
2. **Sig verify:** `descriptor.verify_sig()` → `StorageError::InvalidSig`
3. **Lazy disk check:** re-check pressure at blob arrival
   - If `DiskPressure::Normal`: proceed
   - If `DiskPressure::Soft`: `StorageError::NoBudget` (stop accepting during soft pressure)
   - If `DiskPressure::Hard`: evaluate priority of new shard vs lowest-priority held shard
     via `budget.eviction_priority()`. If new priority > lowest: evict lowest, store new.
     Otherwise: `StorageError::NoBudget`
4. **Write to disk:** `tokio::fs::write(path, blob).await?`
   - Create parent directory if needed: `tokio::fs::create_dir_all(parent).await?`
5. **Insert HoldingRecord:**
   ```rust
   HoldingRecord {
       shard_id: descriptor.shard_id,
       owner_pub: descriptor.owner_pub,
       importance: descriptor.importance as f64,
       size_bytes: blob.len() as u64,
       state: ShardState::Active,
       received_at: now,
       delete_requested_at: None,
       drop_notice_sent_at: None,
       file_type: convert_file_type(descriptor.file_type),
       merkle_root: descriptor.merkle_root,
       rs_k: descriptor.k,
       rs_n: descriptor.n,
       shard_index: descriptor.shard_index,
   }
   ```

### PoS challenge response (`answer_pos_challenge`)

Block size: 64 KB = 65536 bytes (from overview.md §1.2 and §1.3).

```
1. Load blob from disk: read_to_end → Vec<u8>
2. block_count = ceil(blob.len() / BLOCK_SIZE)
3. If block_index >= block_count → StorageError::BlockOutOfRange
4. block_start = block_index as usize * BLOCK_SIZE
5. block_end = min(block_start + BLOCK_SIZE, blob.len())
6. block_bytes = &blob[block_start..block_end]
7. hash_input = block_bytes || nonce (concatenate)
8. block_data_hash = blake3(hash_input).into()
9. merkle_proof = compute_merkle_proof(&blob, block_index)
10. Return PosAnswer { block_data_hash, merkle_proof }
```

**Merkle tree construction** (BLAKE3, 64 KB blocks):
- Leaf hashes: `blake3(block_bytes)` for each block (right-pad last block with zeros to 64 KB if < 64 KB)
- Internal nodes: `blake3(left_child_hash || right_child_hash)`
- Tree is padded to next power of 2 (duplicate last leaf to fill)
- Root must match `HoldingRecord::merkle_root`

Merkle proof = list of sibling hashes from leaf to root (not including leaf itself, not including root). Length = log2(next_power_of_2(block_count)).

### Restore logic (`read_shard_for_restore`)

The escrow check is delegated to `EscrowChecker::check_restore()`:
- `RestoreDecision::Allowed` → read and return blob
- `RestoreDecision::Denied(denial)` → return `StorageError::EscrowDenied(denial)`

After serving blob: `escrow.record_restore(shard_id, owner_pub, blob.len(), now)`.

If blob file is missing on disk but HoldingRecord exists in DB:
- This is a data integrity problem (bit rot or fs issue)
- Log ERROR, return `StorageError::BlobMissing(path)`
- Caller (Processor) should mark shard as Lost in shards table for the owner

### Delete cooldown (overview.md §2.8)

- Owner sends `delete` → `handle_delete_request` → `escrow.mark_for_delete` → state = `MarkedForDelete`, `delete_requested_at = now`
- Holder cooldown: 4 weeks (`HOLDER_DELETE_COOLDOWN_SECS = 4 * 604800`)
- `process_expired_cooldowns(now)`:
  - Query `db.list_holding_cooldown_expired(now)`
  - For each: delete blob file, `db.delete_holding(shard_id)`
  - Return list of deleted shard IDs

### Disk pressure eviction (overview.md §2.8)

Two-phase, no cooldown (holder-initiated eviction is owner-agnostic):

**Phase 1 (immediate, hard threshold < 5% free):**
- `evict_shard(shard_id, now)`:
  - Delete blob file from disk
  - `db.delete_holding(shard_id)`
  - Return owner_pub (Processor sends `shard_dropped` to owner)
  - No cooldown — this is holder's right to reclaim disk space

**Phase 2 (7-day notice, soft threshold 5-15%):**
- `record_drop_notice(shard_id, now)`:
  - `db.set_drop_notice_sent_at(shard_id, now)`
  - Processor sends `shard_drop_notice { shard_id, deadline: now + 7 days }` to owner
- `process_expired_drop_notices(now)`:
  - `db.list_holding_drop_notice_expired(now)`
  - For each: delete blob file, `db.delete_holding(shard_id)`

### System state shards

`HoldingRecord.file_type == FileType::System` → never evict.
`BudgetPlanner::evaluate_pressure` already skips system shards.
`evict_shard` should check: if `record.file_type == FileType::System` → panic (invariant
violation: evicting system shard = bug).

### Silent shards

If owner has been silent (no PoS challenges) for a long time:
- `EscrowChecker::mark_silent(shard_id)` is called by Processor (on WeeklySync, when no
  PoS challenge has been seen for > N weeks for a given shard)
- Storage module does NOT decide when to mark shards silent — that is Processor's decision
- Silent shards have reduced eviction priority (through trust_of_owner in BudgetPlanner)

### Allowlist bypass

If `PeerRecord::allowlisted == true` for the owner:
- `should_accept_offer` → always `Accept`
- `read_shard_for_restore` → skip escrow check, return blob directly
- `evict_shard` → log a DEBUG note but still evict if disk is critical (allowlist does not
  override hard disk pressure — protocol says "trusted identities are never evicted",
  but in alpha under critical disk pressure we still evict everything)

DECISION NEEDED: Confirm whether allowlisted peers bypass eviction entirely in Phase 2
or only in normal operation. Current spec (CLAUDE.md key decisions): "Trusted identities
(allowlist): holder may manually mark identities as trusted — their shards are not dropped
and do not undergo escrow." For Phase 2 alpha, implement: allowlisted shards are skipped
in BudgetPlanner eviction candidate list. This is already handled by `FileType::System`
logic; add a similar check for `allowlisted` owner.

---

## Constants

```rust
/// Block size for PoS Merkle tree (64 KB).
const BLOCK_SIZE: usize = 65_536;

/// Shard blob file extension.
const SHARD_EXT: &str = ".shard";
```

Import from syncback-core constants:
- `HOLDER_DELETE_COOLDOWN_SECS = 4 * 604_800` (from constants.rs)
- `DROP_NOTICE_WINDOW_SECS = 7 * 86_400` (from constants.rs)
- `SOFT_PRESSURE_THRESHOLD = 0.15` (from constants.rs)
- `HARD_PRESSURE_THRESHOLD = 0.05` (from constants.rs)

---

## Test scenarios

Tests live in `crates/syncback/src/daemon/storage/tests.rs` (or inline `#[cfg(test)] mod tests`).
All tests use real DB (testutil::test_db() pattern) and real filesystem (tempfile::TempDir).

### `store_shard_succeeds_with_valid_blob`

```
Setup:
  TempDir, test DB, Storage::new()
  Create a valid blob: Vec<u8> of 1024 bytes
  Compute shard_id = ShardId(blake3(blob).into())
  Create a valid signed ShardDescriptor (need signing key for this — use random ed25519 key)
  Insert owner PeerRecord into DB (so owner is known)

Action:
  storage.store_shard(&descriptor, &blob).await

Expected:
  Ok(())
  Blob file exists at expected path
  db.get_holding(&shard_id) returns Some(record) with state = Active
```

### `store_shard_rejects_hash_mismatch`

```
Setup:
  Valid descriptor for shard_id X
  Blob whose blake3 != X

Action:
  storage.store_shard(&descriptor, &wrong_blob).await

Expected:
  Err(StorageError::HashMismatch { .. })
  No file created on disk
  No HoldingRecord inserted
```

### `answer_pos_challenge_correct_hash_and_proof`

```
Setup:
  Store a shard blob of exactly 3 * BLOCK_SIZE bytes (3 blocks)
  Insert HoldingRecord with valid merkle_root (pre-computed)

Action:
  storage.answer_pos_challenge(shard_id, block_index=1, nonce=&[0u8; 32])

Expected:
  Ok(PosAnswer { block_data_hash, merkle_proof })
  block_data_hash == blake3(&blob[BLOCK_SIZE..2*BLOCK_SIZE] || &[0u8; 32])
  merkle_proof has length == ceil(log2(4)) == 2 entries (tree padded to 4 leaves)
```

### `answer_pos_challenge_block_out_of_range`

```
Setup:
  Store a shard blob of 100 bytes (1 block)

Action:
  storage.answer_pos_challenge(shard_id, block_index=5, nonce=&[0; 32])

Expected:
  Err(StorageError::BlockOutOfRange { index: 5, blocks: 1 })
```

### `read_shard_for_restore_allows_free_tier`

```
Setup:
  Store shard, no restore log entry (bytes_restored = 0 → FreeTier)
  Owner weeks_in_network = 0 (new user)

Action:
  storage.read_shard_for_restore(shard_id, &owner_pub, now)

Expected:
  Ok(blob_bytes) — FreeTier always allowed
```

### `read_shard_for_restore_denies_on_escrow`

```
Setup:
  Store shard (size > FREE_TIER_BYTES = 1 GiB)
  Insert restore_log with bytes_restored = 5 * 1024^3 (5 GiB → Tier2)
  Insert peer with weeks_in_network = 5 (< 13 required for Tier2)

Action:
  storage.read_shard_for_restore(shard_id, &owner_pub, now)

Expected:
  Err(StorageError::EscrowDenied(EscrowDenial {
      required_weeks: 13,
      current_weeks: 5,
      tier: EscrowTier::Tier2,
      ..
  }))
```

### `delete_cooldown_does_not_delete_immediately`

```
Setup:
  Store shard, owner sends delete

Action:
  storage.handle_delete_request(shard_id, &owner_pub, now)
  storage.process_expired_cooldowns(now + 1_week_secs)

Expected:
  After delete_request: HoldingRecord.state == MarkedForDelete
  After process (1 week later, < 4 weeks): shard still in DB and on disk
```

### `delete_cooldown_deletes_after_4_weeks`

```
Setup:
  Store shard, handle_delete_request at now

Action:
  storage.process_expired_cooldowns(now + 4_weeks_secs + 1)

Expected:
  HoldingRecord removed from DB
  Blob file deleted from disk
  Return includes shard_id
```

### `disk_pressure_evicts_lowest_priority_first`

```
Setup:
  Two shards stored: shard_A (importance=0.9, recent owner with high trust) and
  shard_B (importance=0.1, unknown owner)
  Simulate hard pressure: used_gb just below quota_gb (> 95%)

Action:
  result = storage.check_pressure(now)

Expected:
  result.pressure == DiskPressure::Hard
  result.immediate_evictions contains shard_B (lower priority)
  result.immediate_evictions does not contain shard_A
```

### `evict_shard_removes_blob_and_record`

```
Setup:
  Store shard with valid blob

Action:
  owner_pub = storage.evict_shard(shard_id, now)

Expected:
  Ok(owner_pub)
  Blob file no longer exists on disk
  db.get_holding(&shard_id) == Ok(None)
```

### `should_accept_offer_rejects_unknown_owner`

```
Setup:
  Descriptor with owner_pub not in peers table

Action:
  storage.should_accept_offer(&descriptor)

Expected:
  Ok(OfferDecision::RejectUnknown)
```

### `should_accept_offer_rejects_when_soft_pressure`

```
Setup:
  Insert enough fake HoldingRecords to exceed soft threshold
  Known owner

Action:
  storage.should_accept_offer(&descriptor)

Expected:
  Ok(OfferDecision::RejectFull)
```

---

## Notes for implementer

1. **`Storage` owns `EscrowChecker` and `BudgetPlanner`**, which both hold a clone of
   `Db`. This is fine — all are backed by the same `Arc<redb::Database>` inside `Db`.

2. **Async vs sync:** `store_shard` is async (writes blob to disk). `answer_pos_challenge`
   and `read_shard_for_restore` can be sync (read operations). For consistency, make the
   heavy disk I/O async and keep short operations sync. Processor calls these from an
   async context anyway.

3. **Merkle tree implementation:** Write a standalone function
   `fn build_merkle_tree(blob: &[u8], block_size: usize) -> Vec<[u8; 32]>` that returns
   all tree nodes (leaves + internal nodes, root last). Then a separate
   `fn merkle_proof(tree: &[[u8; 32]], leaf_idx: usize) -> Vec<[u8; 32]>` that extracts
   the proof path. Test these independently. The proof must be compatible with the
   challenger's verification code.

4. **Challenger verification** (not in this module, but must be compatible): The Processor
   verifies incoming `PosResponseMsg` by:
   - Recomputing `expected_hash = blake3(block_bytes || nonce)` — but we don't have block
     bytes when verifying! Verification is: apply merkle_proof to verify `block_data_hash`
     is in the tree at `block_index` under the stored `merkle_root`.
   - Verify `merkle_proof` proves `block_data_hash` is a valid leaf at `block_index`
     under `merkle_root` from ShardDescriptor.
   - This is standard Merkle inclusion proof.

5. **File not found on disk but in DB:** if `read_shard_for_restore` or
   `answer_pos_challenge` cannot find the blob file, log `ERROR` (this is a serious
   integrity issue) and return `StorageError::BlobMissing`. Caller (Processor) should
   mark the shard as corrupted and notify the owner.

6. **`convert_file_type`:** the `messages::FileType` (used in `ShardDescriptor`) and
   `types::FileType` (used in `HoldingRecord`) are two separate enums with the same
   variants. Write a trivial conversion:
   ```rust
   fn convert_file_type(ft: syncback_core::messages::FileType) -> syncback_core::types::FileType {
       match ft {
           messages::FileType::User => types::FileType::User,
           messages::FileType::System => types::FileType::System,
       }
   }
   ```

7. **`shard_count()`:** count records in holding table. Can be implemented as
   `db.list_all_holding()?.len()` — acceptable for alpha (no hot path).

8. **Blob write is atomic:** write to a temp file then rename to avoid partial writes.
   Use `tempfile` crate or manual `.shard.tmp` rename pattern:
   ```rust
   let tmp_path = path.with_extension("shard.tmp");
   tokio::fs::write(&tmp_path, blob).await?;
   tokio::fs::rename(&tmp_path, &path).await?;
   ```
