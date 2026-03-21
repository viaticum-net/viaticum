# Task: File Deletion (Phase 4.3)

Module: `crates/syncback-core/src/deletion/`
Files: `mod.rs` + `tests.rs`

---

## Overview

When a user deletes a file, SyncBack must not immediately remove the backup.
The double cooldown (owner 4 weeks + holder 4 weeks = 8 weeks total) protects
against ransomware: encrypted files cannot be deleted faster than the attacker
can be detected.

This module provides `DeletionEngine`, a pure-logic component that:

1. Accepts deletion events from the watcher and advances per-file state.
2. Is polled periodically (the scheduler calls `process_cooldowns`) to advance
   the state machine and produce the next set of actions for the daemon.
3. Decides when to trigger vacuum for source blocks that have become mostly
   stale.

The module does **not** touch the DB, send network messages, or call any async
code. It reads snapshots of DB records passed in by the caller and returns
`DeletionAction` values for the daemon to execute.

---

## Dependencies

- `crate::constants::{OWNER_DELETE_COOLDOWN_SECS, HOLDER_DELETE_COOLDOWN_SECS, VACUUM_INVALID_THRESHOLD}`
- `crate::types::{FileId, FileRecord, LocalState, SourceBlockId, SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement, PlacementStatus, IdentityPub, Timestamp, DeviceId}`
- No DB access, no async, no network.

---

## State machine

Every file has a deletion lifecycle. The states are encoded in the existing
`FileRecord` and `SourceBlockRecord` — there is no new persisted enum. The
engine infers the current state from those records at call time.

```
Active
  │  (all devices have local_state = Present, or file never deleted)
  │
  ▼  mark_deleted() called when watcher sees Deleted event
WaitingForAllDevices
  │  (some devices still Present; file visible on other cluster devices)
  │  When the last device transitions → Deleted(ts), cooldown starts.
  ▼
OwnerCooldown(deleted_at: Timestamp)
  │  Owner keeps SourceBlock status = Active. No network activity.
  │  Duration: OWNER_DELETE_COOLDOWN_SECS (4 weeks)
  ▼
SendingDropNotice
  │  Owner sends DeleteMsg to each holder. Sets SourceBlock status = Deleting.
  │  Daemon transitions each SymbolPlacement → Deleting.
  ▼
HolderCooldown(drop_sent_at: Timestamp)
  │  Holders keep symbols for HOLDER_DELETE_COOLDOWN_SECS (4 weeks).
  │  No PoS during this window (per raptorq.md: "file deleted → cooldown →
  │  PoS не делаем").
  ▼
Cleaned
  │  Daemon removes SymbolPlacement rows and SourceBlock row from DB.
  │  FileRecord is retained as a tombstone (local_state = Deleted, no versions).
```

Total: 8 weeks from the moment the last device marks the file deleted.

### PoS suppression

While a source block's `SourceBlockStatus` is `Deleting`, the scheduler must
not issue new PoS challenges for its placements. The deletion engine does not
enforce this directly — it signals via `DeletionAction` and the daemon updates
`SourceBlockStatus`. The scheduler reads that status.

### Multi-device behaviour

`FileRecord.devices: Vec<(DeviceId, LocalState)>` tracks per-device state.

- When device A deletes a file, only A's entry becomes `Deleted(ts)`.
- The owner cooldown starts only when **all** devices have `Deleted` state.
- If device B still has `Present`, the file is considered alive on the cluster.

`mark_deleted` returns `WaitForOtherDevices` if other devices are still
`Present`. No cooldown starts yet.

### Vacuum

Vacuum is independent of the deletion state machine. It applies to source
blocks of type `Pack` where many constituent files have been deleted or
superseded:

```
valid_files   = files in pack whose latest version still points to this block
invalid_files = total_in_pack - valid_files
ratio         = invalid_files / total_in_pack
if ratio > VACUUM_INVALID_THRESHOLD (0.50) → trigger vacuum
```

Vacuum does not apply to `Single`-type source blocks (one file → one block;
if the file is deleted, the whole block is deleted, not repacked).

The vacuum action is: repack the still-valid files into a new source block,
then mark the old block `Stale`. The `Stale` block then flows through the
normal deletion state machine (owner cooldown → drop notice → holder
cooldown → cleaned).

---

## Public API

### `deletion/mod.rs`

```rust
use crate::constants::{OWNER_DELETE_COOLDOWN_SECS, HOLDER_DELETE_COOLDOWN_SECS, VACUUM_INVALID_THRESHOLD};
use crate::types::{
    DeviceId, FileId, FileRecord, IdentityPub, LocalState, SourceBlockId,
    SourceBlockRecord, SourceBlockStatus, SourceBlockType, SymbolPlacement,
    PlacementStatus, Timestamp,
};

// ── Actions returned to the daemon ──────────────────────────────────────────

/// Actions the daemon must execute as a result of deletion logic.
/// The engine never mutates DB or sends messages — it returns these.
#[derive(Debug, Clone, PartialEq)]
pub enum DeletionAction {
    /// Owner cooldown elapsed. Send DeleteMsg to each holder and set
    /// SourceBlockRecord.status = Deleting. One action per holder.
    SendDropNotice {
        source_block_id: SourceBlockId,
        holder_id: IdentityPub,
    },

    /// Holder cooldown elapsed (delete_requested_at + HOLDER_DELETE_COOLDOWN_SECS).
    /// Daemon should:
    ///   1. delete_placement(source_block_id, holder_id)
    ///   2. If no placements remain for this block: delete_source_block(block_id)
    CleanupPlacement {
        source_block_id: SourceBlockId,
        holder_id: IdentityPub,
    },

    /// All placements for this source block have been cleaned up.
    /// Daemon should delete the SourceBlockRecord row and prune the
    /// FileRecord.versions entry that references this block.
    CleanupBlock {
        source_block_id: SourceBlockId,
        /// FileId that owns this block (for pruning the version entry).
        file_id: FileId,
    },

    /// Source block has >50% invalid files. Daemon must:
    ///   1. Repack still-valid file data into a new source block (new backup).
    ///   2. Call mark_source_block_stale(old_block_id) — sets status = Stale.
    ///   3. The stale block then enters the deletion flow on the next tick.
    VacuumBlock {
        source_block_id: SourceBlockId,
        /// File IDs that are still valid and must be repacked.
        valid_file_ids: Vec<FileId>,
    },

    /// File was deleted on one device but is still present on others.
    /// No action needed now; the engine will reconsider on next tick.
    WaitForOtherDevices {
        file_id: FileId,
    },
}

// ── Engine ───────────────────────────────────────────────────────────────────

/// Pure-logic deletion engine. Stateless between calls.
/// The daemon constructs a fresh instance per scheduler tick or passes
/// one around — either way is fine since it holds no mutable state.
pub struct DeletionEngine;

impl DeletionEngine {
    pub fn new() -> Self {
        DeletionEngine
    }

    /// Called when the watcher sees a file deleted on `device_id`.
    ///
    /// Inspects the current `FileRecord` and returns what action (if any)
    /// to take immediately. The daemon must then persist the updated state:
    ///
    /// - Always: set `record.devices[device_id].local_state = Deleted(now)`.
    /// - If returns `WaitForOtherDevices`: nothing else to do now.
    /// - If returns `SendDropNotice`: this should not happen from mark_deleted
    ///   directly (cooldown must elapse first) — this variant will not appear
    ///   here. The return type is `MarkDeletedResult`, not `DeletionAction`.
    ///
    /// This function is deterministic: same inputs → same output.
    pub fn mark_deleted(
        &self,
        record: &FileRecord,
        device_id: DeviceId,
        now: Timestamp,
    ) -> MarkDeletedResult;

    /// Called by the scheduler on every tick. Scans all provided records and
    /// returns the actions to execute this tick.
    ///
    /// The caller provides:
    ///   - All `FileRecord`s that have at least one `Deleted` device.
    ///   - All `SourceBlockRecord`s referenced by those files.
    ///   - All `SymbolPlacement`s for those source blocks.
    ///
    /// Returns actions sorted by type:
    ///   SendDropNotice first, then CleanupPlacement, then CleanupBlock.
    ///   VacuumBlock is appended last (it requires separate repack work).
    ///
    /// Idempotent: calling twice with the same inputs returns the same actions.
    pub fn process_cooldowns(
        &self,
        files: &[FileRecord],
        blocks: &[SourceBlockRecord],
        placements: &[SymbolPlacement],
        now: Timestamp,
    ) -> Vec<DeletionAction>;

    /// Returns true if a source block of type Pack should be vacuumed.
    ///
    /// `total_files`: total number of files referenced by this pack block
    ///   (the len of PackEntry entries in SourceBlockType::Pack).
    /// `invalid_files`: how many of those are now invalid (deleted or
    ///   superseded by a newer version in a different block).
    ///
    /// Formula: `invalid_files as f64 / total_files as f64 > VACUUM_INVALID_THRESHOLD`
    ///
    /// Panics if `total_files == 0` (caller must not call for empty blocks).
    /// Returns false if block is of type Single (vacuuming is nonsensical).
    pub fn should_vacuum(
        &self,
        total_files: u32,
        invalid_files: u32,
    ) -> bool;
}

// ── Result type for mark_deleted ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum MarkDeletedResult {
    /// File is still present on at least one other device. No further action.
    WaitForOtherDevices,
    /// All devices now have Deleted state. Owner cooldown has started.
    /// The daemon must persist `local_state = Deleted(now)` for `device_id`
    /// (it may have already been set before calling this function; idempotent).
    CooldownStarted {
        /// Timestamp when the last device was marked deleted (= now).
        deleted_at: Timestamp,
        /// When the owner cooldown expires and SendDropNotice should be issued.
        notify_after: Timestamp,
    },
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DeletionError {
    #[error("file {0} has no device entry for device {1}")]
    DeviceNotFound(FileId, DeviceId),

    #[error("source block {0} referenced in FileVersion not found in blocks slice")]
    BlockNotFound(SourceBlockId),
}
```

---

## Business rules

### `mark_deleted`

1. Find `device_id` in `record.devices`. If not present, the engine cannot
   proceed — return `Err(DeletionError::DeviceNotFound)`. (This should not
   happen in production; the daemon must have registered the device first.)
2. Update the in-memory snapshot: set `local_state = Deleted(now)` for that
   entry. (The caller persists this; the engine just reasons about the state.)
3. Check if **all** entries in `record.devices` have `LocalState::Deleted`.
   - Yes → `CooldownStarted { deleted_at: now, notify_after: now.add_secs(OWNER_DELETE_COOLDOWN_SECS) }`
   - No → `WaitForOtherDevices`

Note: a file with `devices` vec that is empty is treated as "all deleted" (no
device claims it is present). This is a degenerate case; the daemon should not
create files with empty device lists, but the engine handles it gracefully.

### `process_cooldowns`

For each `FileRecord` in `files`:

**Step 1 — Check if all devices deleted.**

Compute `all_deleted_at`: the maximum `Deleted(ts)` timestamp across all
devices (i.e. the last device to delete). If any device is still `Present`,
skip this file.

**Step 2 — Owner cooldown check.**

```
owner_cooldown_elapsed = all_deleted_at.0 + OWNER_DELETE_COOLDOWN_SECS <= now.0
```

If not elapsed: no action for this file's blocks.

If elapsed: for each source block referenced in `file.versions`:
- Look up the `SourceBlockRecord`. If not found in `blocks` slice, skip (may
  have been cleaned already).
- If `block.status == SourceBlockStatus::Deleting`: owner cooldown already
  sent, proceed to Step 3.
- If `block.status == SourceBlockStatus::Active` or `Stale`: emit
  `SendDropNotice { source_block_id, holder_id }` for each `SymbolPlacement`
  where `placement.status != PlacementStatus::Deleting`.

**Step 3 — Holder cooldown check (per SymbolPlacement).**

For each `SymbolPlacement` where `placement.status == PlacementStatus::Deleting`:
- The holder receives the `DeleteMsg` at roughly `drop_sent_at`. The owner
  records `delete_requested_at` in `HoldingRecord` (holder side); but from
  the owner's perspective, we use `placed_at` is not the right timestamp.

  DECISION NEEDED: The `SymbolPlacement` struct does not have a
  `delete_sent_at` field. The daemon must record when `DeleteMsg` was sent.
  Two options:

  a. Add `delete_sent_at: Option<Timestamp>` to `SymbolPlacement`.
  b. Use the `FileRecord`'s `all_deleted_at + OWNER_DELETE_COOLDOWN_SECS` as
     a proxy (the drop notice was sent at approximately that moment).

  **Recommended: option (b) for now.** The engine computes:
  ```
  drop_sent_at = all_deleted_at.0 + OWNER_DELETE_COOLDOWN_SECS
  holder_cooldown_elapsed = drop_sent_at + HOLDER_DELETE_COOLDOWN_SECS <= now.0
  ```

  This is conservative (slightly overestimates cooldown) but avoids a schema
  change. If exact tracking is needed in the future, add option (a).

If `holder_cooldown_elapsed`:
- Emit `CleanupPlacement { source_block_id, holder_id }`.

**Step 4 — Block cleanup.**

After emitting `CleanupPlacement` for all placements of a block: if **all**
placements for that block are `Deleting` and `holder_cooldown_elapsed` for
all of them, emit `CleanupBlock { source_block_id, file_id }`.

Note: `CleanupPlacement` and `CleanupBlock` may be emitted in the same tick
for the same block. The daemon must execute `CleanupPlacement` for all
holders first, then `CleanupBlock`.

**Step 5 — Vacuum scan (independent pass).**

After processing all files, iterate over all `SourceBlockRecord`s where
`block.block_type == SourceBlockType::Pack` and `block.status == Active`.

For each pack block:
- Count `total_files`: the number of `PackEntry` elements in the pack index.
- Count `invalid_files`: for each `PackEntry.file_id`, look up the
  `FileRecord` (from `files` slice). A file is **invalid for this block** if:
  - Its `versions` vec has no entry with `source_block_id == block.block_id`,
    OR
  - Its latest version references a different `source_block_id` (superseded),
    OR
  - All of its devices are `Deleted`.
- If `should_vacuum(total_files, invalid_files)` returns true: emit
  `VacuumBlock { source_block_id, valid_file_ids }` where `valid_file_ids`
  is the list of `PackEntry.file_id` for files that are still valid.

The vacuum pass does NOT inspect blocks with status `Stale` or `Deleting`
(they are already in the deletion pipeline).

### `should_vacuum`

```
if total_files == 0 { panic!("should_vacuum called with total_files=0") }
invalid_files as f64 / total_files as f64 > VACUUM_INVALID_THRESHOLD
```

`VACUUM_INVALID_THRESHOLD = 0.5` (from `constants.rs`).

Strictly greater than: a block that is exactly 50% invalid does NOT trigger
vacuum. More than 50% does.

---

## DB operations (owner of this module does NOT touch DB)

The module returns actions. The daemon uses existing `Db` methods:

| Action | Db calls daemon makes |
|--------|-----------------------|
| `SendDropNotice` | `db.upsert_placement(...)` with `status = Deleting`; `db.upsert_source_block(...)` with `status = Deleting` |
| `CleanupPlacement` | `db.delete_placement(block_id, holder_id)` |
| `CleanupBlock` | `db.delete_source_block(block_id)`; prune the matching `FileVersion` from `FileRecord.versions` via `db.upsert_file(...)` |
| `VacuumBlock` | Pack `valid_file_ids` into new source block (BackupCoordinator); `db.upsert_source_block(old, status=Stale)` |
| `WaitForOtherDevices` | Persist `local_state = Deleted(now)` for the device via `db.upsert_file(...)` |

The engine does not need any new DB methods; all required queries are already
present (`list_source_blocks_by_status`, `list_placements_for_block`, etc.).

---

## Module location

```
crates/syncback-core/src/deletion/mod.rs
crates/syncback-core/src/deletion/tests.rs
```

Register in `crates/syncback-core/src/lib.rs`:

```rust
pub mod deletion;
```

---

## Test scenarios

All tests in `deletion/tests.rs`. Use `Db::open_in_memory()` where needed for
building test fixtures; the engine itself takes slices, so most tests need
only plain struct construction.

Use the naming convention `what_when_then`.

---

### Test 1: `mark_deleted_single_device_starts_cooldown`

```
FileRecord.devices = [(device_A, Present)]
Call mark_deleted(record, device_A, now=T(1000))
→ CooldownStarted {
    deleted_at: T(1000),
    notify_after: T(1000 + OWNER_DELETE_COOLDOWN_SECS),
  }
```

### Test 2: `mark_deleted_multi_device_waits_for_others`

```
FileRecord.devices = [(device_A, Present), (device_B, Present)]
Call mark_deleted(record, device_A, now=T(1000))
→ WaitForOtherDevices
```

### Test 3: `mark_deleted_last_device_starts_cooldown`

```
FileRecord.devices = [(device_A, Deleted(T(500))), (device_B, Present)]
Call mark_deleted(record, device_B, now=T(1000))
→ CooldownStarted {
    deleted_at: T(1000),
    notify_after: T(1000 + OWNER_DELETE_COOLDOWN_SECS),
  }
```

### Test 4: `mark_deleted_unknown_device_returns_error`

```
FileRecord.devices = [(device_A, Present)]
Call mark_deleted(record, device_B, now=T(1000))
→ Err(DeletionError::DeviceNotFound(file_id, device_B))
```

### Test 5: `process_cooldowns_owner_cooldown_not_elapsed`

```
File: all devices Deleted at T(0)
now = T(OWNER_DELETE_COOLDOWN_SECS - 1)  // one second before expiry
SourceBlock: status = Active
→ process_cooldowns returns []
```

### Test 6: `process_cooldowns_sends_drop_notice_at_owner_cooldown_expiry`

```
File: all devices Deleted at T(0)
now = T(OWNER_DELETE_COOLDOWN_SECS)
SourceBlock: status = Active, block_id = B1
Placements: [
  (B1, holder_A, status=Alive),
  (B1, holder_B, status=Alive),
]
→ process_cooldowns returns [
    SendDropNotice { source_block_id: B1, holder_id: holder_A },
    SendDropNotice { source_block_id: B1, holder_id: holder_B },
  ]
```

### Test 7: `process_cooldowns_skip_already_deleting_placements`

```
File: all devices Deleted at T(0)
now = T(OWNER_DELETE_COOLDOWN_SECS + 10)
SourceBlock: status = Deleting
Placements: [
  (B1, holder_A, status=Deleting),
  (B1, holder_B, status=Alive),   // somehow not yet updated
]
→ only SendDropNotice for holder_B (holder_A already Deleting)
```

### Test 8: `process_cooldowns_cleanup_after_holder_cooldown`

```
File: all devices Deleted at T(0)
now = T(OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS)
SourceBlock: status = Deleting
Placements: [
  (B1, holder_A, status=Deleting),
]
→ process_cooldowns returns [
    CleanupPlacement { source_block_id: B1, holder_id: holder_A },
    CleanupBlock { source_block_id: B1, file_id: F1 },
  ]
```

### Test 9: `process_cooldowns_cleanup_waits_for_all_holders`

```
File: all devices Deleted at T(0)
now = T(OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS)
SourceBlock: status = Deleting
Placements: [
  (B1, holder_A, status=Deleting),
  (B1, holder_B, status=Alive),   // drop notice not yet sent (hypothetical)
]
→ process_cooldowns returns [
    CleanupPlacement { source_block_id: B1, holder_id: holder_A },
    SendDropNotice { source_block_id: B1, holder_id: holder_B },
    // No CleanupBlock: holder_B not cleaned yet
  ]
```

### Test 10: `process_cooldowns_file_still_present_on_one_device_skipped`

```
File: devices = [(device_A, Deleted(T(0))), (device_B, Present)]
now = T(OWNER_DELETE_COOLDOWN_SECS + 1_000_000)  // far in future
→ process_cooldowns returns []  // not all devices deleted
```

### Test 11: `should_vacuum_above_threshold`

```
total_files = 10, invalid_files = 6
6.0/10.0 = 0.60 > 0.50
→ true
```

### Test 12: `should_vacuum_at_threshold_returns_false`

```
total_files = 10, invalid_files = 5
5.0/10.0 = 0.50, NOT strictly greater than 0.50
→ false
```

### Test 13: `should_vacuum_below_threshold`

```
total_files = 10, invalid_files = 4
4.0/10.0 = 0.40 < 0.50
→ false
```

### Test 14: `should_vacuum_all_invalid`

```
total_files = 5, invalid_files = 5
5.0/5.0 = 1.0 > 0.50
→ true
```

### Test 15: `should_vacuum_one_invalid_of_two`

```
total_files = 2, invalid_files = 1
1.0/2.0 = 0.50 — exactly at threshold
→ false  (strictly greater required)
```

### Test 16: `process_cooldowns_vacuum_triggered_for_stale_pack`

```
SourceBlock B1: type = Pack { entries: [F1, F2, F3, F4] }, status = Active
Files:
  F1: latest version → B1, all devices Present (valid)
  F2: latest version → B2 (superseded, no longer points to B1)
  F3: all devices Deleted (deleted file)
  F4: no version pointing to B1 (shouldn't happen, but handle gracefully)
invalid_count = 3 (F2, F3, F4)
total = 4
3/4 = 0.75 > 0.50
→ VacuumBlock { source_block_id: B1, valid_file_ids: [F1] }
```

### Test 17: `process_cooldowns_no_vacuum_for_single_block_type`

```
SourceBlock B1: type = Single, status = Active
File F1: latest version → B1, all devices Deleted
→ No VacuumBlock emitted (Single blocks are not repacked, they are deleted
  directly through the cooldown path)
```

### Test 18: `process_cooldowns_no_vacuum_for_stale_block`

```
SourceBlock B1: type = Pack { entries: [F1, F2] }, status = Stale
Both files invalid
→ No VacuumBlock (already in deletion pipeline)
```

### Test 19: `process_cooldowns_idempotent`

```
Same inputs called twice → same Vec<DeletionAction> both times
(order matters: two identical calls produce same ordered output)
```

### Test 20: `process_cooldowns_empty_inputs_returns_empty`

```
files = [], blocks = [], placements = [], now = any
→ []
```

---

## What NOT to do

- Do not add any `use redb::*` or DB access to this module.
- Do not use `tokio`, `async`, or any runtime primitives.
- Do not add `tracing` calls. This is a pure logic module.
- Do not introduce a new persisted struct for `DeletionState`. The state is
  derived from `FileRecord.devices` and `SourceBlockRecord.status` at call time.
- Do not change `FileRecord`, `SourceBlockRecord`, or `SymbolPlacement`
  structs in this task. If a schema change is needed, flag it with
  `DECISION NEEDED:` in a code comment and proceed with the conservative
  approximation described above (option b for `drop_sent_at`).
- Do not implement the vacuum repack itself (that is `BackupCoordinator`'s
  job). Only emit `VacuumBlock` and let the daemon route it.
- Do not emit `SendDropNotice` from `mark_deleted`. That function only
  determines whether the cooldown has started; the scheduler's
  `process_cooldowns` is what discovers elapsed cooldowns.

---

## Files to create

1. `/home/ilya/projects/syncback/crates/syncback-core/src/deletion/mod.rs`
   — `DeletionEngine`, `DeletionAction`, `MarkDeletedResult`, `DeletionError`

2. `/home/ilya/projects/syncback/crates/syncback-core/src/deletion/tests.rs`
   — All 20 test scenarios above

3. Edit `/home/ilya/projects/syncback/crates/syncback-core/src/lib.rs`
   — Add `pub mod deletion;`

---

## Definition of done

- `cargo test -p syncback-core` passes with no failures.
- `cargo clippy -p syncback-core -- -D warnings` is clean.
- All 20 test functions present and named according to the `what_when_then` pattern.
- `DeletionEngine`, `DeletionAction`, `MarkDeletedResult`, `DeletionError`
  all `pub` and usable from outside the module.
- No DB, async, or network imports in `deletion/mod.rs`.
- Any schema ambiguity documented with `// DECISION NEEDED:` comments in code.
