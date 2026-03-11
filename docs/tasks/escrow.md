# Task Spec: escrow.rs

Module: `crates/syncback-core/src/escrow.rs`
Phase: 1 (syncback-core, pure logic)
Depends on: `types.rs`, `db.rs`, `trust.rs` (for `PeerRecord` — read-only, no call to TrustEngine)

---

## Overview

EscrowChecker implements the holder's right to withhold shards from an owner who hasn't
established sufficient network tenure. It also manages the double-cooldown barrier for
owner-requested deletes (ransomware protection) and the shard lifecycle state machine.

EscrowChecker has no shard transfer logic — it only answers questions: "can this owner
restore?" and "should this shard be deleted yet?". All state is persisted in redb.

---

## Protocol Reference

- overview.md §1.7 (restore flow, escrow check step 3b)
- overview.md §1.8 (shard lifecycle: active / marked-for-delete / silent)
- overview.md §1.10 (escrow policy: tiers, free tier)
- overview.md §2.5 (escrow policy, weeks_in_network thresholds)
- overview.md §2.8 (cooldown rules, double barrier, holder eviction)
- CLAUDE.md "Key Decisions": escrow uses weeks_in_network (calendar time), NOT I-score

---

## Types

All types below are defined in escrow.rs unless marked otherwise.

```rust
/// The three escrow tiers plus the free demo tier and a bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EscrowTier {
    /// First 1 GB: always available without any weeks requirement.
    FreeTier,
    /// < 5 GB total restored: requires >= 4 weeks in network.
    Tier1,
    /// < 50 GB total restored: requires >= 13 weeks in network.
    Tier2,
    /// >= 50 GB total restored: requires >= 26 weeks in network.
    Tier3,
}

/// Reason a restore was denied by escrow.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EscrowDenial {
    pub shard_id: ShardId,
    pub tier: EscrowTier,
    pub required_weeks: u32,
    pub current_weeks: u32,
}

/// Decision returned by check_restore().
#[derive(Debug)]
pub enum RestoreDecision {
    /// Holder should serve the shard.
    Allowed,
    /// Holder should send restore_denied with this info.
    Denied(EscrowDenial),
}

/// The lifecycle state of a shard held by us (as holder).
/// Mirrors the three states in overview.md §1.8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ShardState {
    /// Normal: owner is active, PoS challenges expected.
    Active,
    /// Owner requested delete; we are in cooldown (4 weeks from delete_requested_at).
    MarkedForDelete,
    /// No PoS challenges received from owner for extended period.
    /// Owner may be offline, lost device, etc.
    Silent,
}

/// Decision returned by should_delete_now().
#[derive(Debug)]
pub enum DeleteDecision {
    /// Keep the shard; cooldown has not expired.
    Keep,
    /// Cooldown expired; delete the shard now.
    Delete,
    /// Cooldown expired AND a cancel_delete arrived — keep the shard, clear delete marker.
    CancelledByOwner,
}

/// Decision returned by check_drop_notice().
/// Used when holder is running Phase 2 disk pressure eviction.
#[derive(Debug)]
pub enum DropNoticeDecision {
    /// 7-day notice period has expired; delete the shard.
    DeleteNow,
    /// Still within 7-day notice window; keep waiting.
    StillWaiting,
}
```

The following types are defined in types.rs (referenced here):

```rust
// types.rs (already defined there):
pub struct ShardId(pub [u8; 32]);
pub struct IdentityPub(pub [u8; 32]);
pub struct Timestamp(pub u64);  // Unix seconds
```

### HoldingRecord (defined in types.rs)

The holding table records shards we hold on behalf of other owners. EscrowChecker reads and
writes this table.

```rust
// In types.rs:
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HoldingRecord {
    pub shard_id: ShardId,
    pub owner_pub: IdentityPub,
    /// Importance set by owner in ShardDescriptor (0.0–1.0).
    pub importance: f64,
    /// Blob size in bytes.
    pub size: u64,
    /// Current lifecycle state.
    pub state: ShardState,
    /// When we received and stored the blob.
    pub received_at: Timestamp,
    /// Set when owner sent a delete message. None if not requested.
    pub delete_requested_at: Option<Timestamp>,
    /// Set when holder sent shard_drop_notice (Phase 2 disk pressure).
    /// None if not in drop-notice state.
    pub drop_notice_sent_at: Option<Timestamp>,
    /// file_type from ShardDescriptor: "user" | "system".
    pub file_type: FileType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FileType {
    User,
    System,
}
```

---

## Constants

All constants are imported from `crate::constants` (see `docs/tasks/constants.md`).
This module uses: `FREE_TIER_BYTES`, `TIER1_MAX_BYTES`, `TIER2_MAX_BYTES`,
`ESCROW_TIER1_WEEKS`, `ESCROW_TIER2_WEEKS`, `ESCROW_TIER3_WEEKS`,
`OWNER_DELETE_COOLDOWN_SECS`, `HOLDER_DELETE_COOLDOWN_SECS`, `DROP_NOTICE_WINDOW_SECS`.

---

## DB Tables

### Table: `holding`

Key: `ShardId` (32 bytes, raw)
Value: CBOR-serialized `HoldingRecord`

EscrowChecker reads and writes this table exclusively through Db.

### Table: `escrow_restore_log`

Tracks cumulative bytes restored per owner. Used to determine which tier applies.

Key: `IdentityPub` (32 bytes)
Value: CBOR-serialized `EscrowRestoreLog`

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EscrowRestoreLog {
    pub owner_pub: IdentityPub,
    /// Total bytes we have served to this owner via restore.
    pub bytes_restored: u64,
    /// Timestamp of first restore we served.
    pub first_restore_at: Option<Timestamp>,
    /// Timestamp of most recent restore we served.
    pub last_restore_at: Option<Timestamp>,
}
```

DECIDED: bytes_restored = cumulative bytes served by this holder to this owner.
Holder-local heuristic — holder has no visibility into network-wide restore volume.
Consistent with protocol philosophy (each holder decides independently).

### Table: `peers` (read-only from escrow.rs)

EscrowChecker reads `PeerRecord.weeks_in_network` from the peers table to determine if an
owner meets the minimum tenure requirement. It does NOT write to this table.

---

## Public API

```rust
pub struct EscrowChecker {
    db: Db,
}

impl EscrowChecker {
    pub fn new(db: Db) -> Self;

    // -------------------------------------------------------------------------
    // Restore decisions
    // -------------------------------------------------------------------------

    /// Check whether this holder should serve a shard to the requesting owner.
    ///
    /// Algorithm:
    ///   1. Look up HoldingRecord for shard_id. If not found: return Denied
    ///      (we don't hold it; caller should treat this as shard_reject).
    ///   2. Verify owner_pub matches HoldingRecord.owner_pub. If mismatch: Denied.
    ///   3. If state == MarkedForDelete and cooldown has expired: Denied
    ///      (shard is past the point of no return; owner should have sent cancel_delete earlier).
    ///      If state == MarkedForDelete but cooldown NOT expired: proceed to escrow check
    ///      (owner can still cancel_delete; shard physically exists; normal escrow rules apply).
    ///   4. Determine tier based on bytes_restored_so_far (from escrow_restore_log):
    ///        bytes_restored_so_far < FREE_TIER_BYTES → tier = FreeTier → Always Allowed
    ///        bytes_restored_so_far < TIER1_MAX_BYTES → tier = Tier1
    ///        bytes_restored_so_far < TIER2_MAX_BYTES → tier = Tier2
    ///        else                                    → tier = Tier3
    ///   5. For Tier1/2/3: read PeerRecord.weeks_in_network for owner_pub.
    ///      If owner not in peers table: weeks_in_network = 0.
    ///   6. If weeks_in_network >= tier.required_weeks: Allowed
    ///      Else: Denied(EscrowDenial { shard_id, tier, required_weeks, current_weeks })
    ///
    /// Does NOT update bytes_restored — call record_restore() after serving the blob.
    pub fn check_restore(
        &self,
        shard_id: &ShardId,
        owner_pub: &IdentityPub,
        now: Timestamp,
    ) -> Result<RestoreDecision, EscrowError>;

    /// Record that we successfully served a shard blob to an owner.
    /// Adds shard.size bytes to escrow_restore_log for owner_pub.
    /// Called after blob transfer is confirmed complete.
    pub fn record_restore(
        &self,
        shard_id: &ShardId,
        owner_pub: &IdentityPub,
        bytes_served: u64,
        now: Timestamp,
    ) -> Result<(), EscrowError>;

    // -------------------------------------------------------------------------
    // Shard lifecycle (delete flow)
    // -------------------------------------------------------------------------

    /// Record that a delete message was received from the owner for a shard.
    /// Sets state = MarkedForDelete, delete_requested_at = now.
    /// No-op if shard is already MarkedForDelete (delete messages are idempotent).
    /// Returns EscrowError::ShardNotHeld if shard_id not in holding table.
    pub fn mark_for_delete(
        &self,
        shard_id: &ShardId,
        owner_pub: &IdentityPub,
        now: Timestamp,
    ) -> Result<(), EscrowError>;

    /// Cancel a pending delete for a shard (owner sent cancel_delete).
    /// Sets state = Active, clears delete_requested_at.
    /// No-op if shard is already Active.
    /// Returns EscrowError::ShardNotHeld if shard_id not in holding table.
    pub fn cancel_delete(
        &self,
        shard_id: &ShardId,
        owner_pub: &IdentityPub,
    ) -> Result<(), EscrowError>;

    /// Check whether the holder cooldown has expired for a MarkedForDelete shard.
    ///
    /// Rules:
    ///   - State != MarkedForDelete → Keep (not in delete flow)
    ///   - delete_requested_at is None → panic (invariant violated)
    ///   - now - delete_requested_at >= HOLDER_DELETE_COOLDOWN_SECS → Delete
    ///   - else → Keep
    ///
    /// Note: the cancel_delete check is NOT done here — caller must first check
    /// if cancel_delete arrived (via the cancel_delete() method) before calling this.
    pub fn should_delete_now(
        &self,
        shard_id: &ShardId,
        now: Timestamp,
    ) -> Result<DeleteDecision, EscrowError>;

    /// Transition a shard from Active to Silent.
    /// Called by Scheduler when no PoS challenge has arrived from owner for > N weeks.
    /// Does NOT affect MarkedForDelete shards.
    pub fn mark_silent(
        &self,
        shard_id: &ShardId,
    ) -> Result<(), EscrowError>;

    /// Reactivate a Silent shard when the owner comes back online (PoS received).
    /// No-op if already Active.
    pub fn mark_active(
        &self,
        shard_id: &ShardId,
    ) -> Result<(), EscrowError>;

    // -------------------------------------------------------------------------
    // Disk pressure (holder-initiated eviction, Phase 2)
    // -------------------------------------------------------------------------

    /// Record that a shard_drop_notice was sent to the owner.
    /// Sets drop_notice_sent_at = now in HoldingRecord.
    pub fn record_drop_notice(
        &self,
        shard_id: &ShardId,
        now: Timestamp,
    ) -> Result<(), EscrowError>;

    /// Check whether the 7-day drop notice window has expired.
    ///
    /// Rules:
    ///   - drop_notice_sent_at is None → StillWaiting (no notice was sent)
    ///   - now - drop_notice_sent_at >= DROP_NOTICE_WINDOW_SECS → DeleteNow
    ///   - else → StillWaiting
    pub fn check_drop_notice(
        &self,
        shard_id: &ShardId,
        now: Timestamp,
    ) -> Result<DropNoticeDecision, EscrowError>;

    // -------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------

    /// Return all shards in MarkedForDelete state whose holder cooldown has expired.
    /// Used by Scheduler for batch cleanup.
    pub fn expired_deletes(&self, now: Timestamp) -> Result<Vec<ShardId>, EscrowError>;

    /// Return all shards where drop_notice_sent_at is set and window has expired.
    /// Used by Scheduler for Phase 2 cleanup.
    pub fn expired_drop_notices(&self, now: Timestamp) -> Result<Vec<ShardId>, EscrowError>;

    /// Return all shards in Silent state.
    /// Used by Scheduler to decide eviction priority.
    pub fn silent_shards(&self) -> Result<Vec<ShardId>, EscrowError>;

    /// Return the HoldingRecord for a shard. None if not held.
    pub fn get_holding(&self, shard_id: &ShardId) -> Result<Option<HoldingRecord>, EscrowError>;

    /// Return all HoldingRecords. Used by eviction priority calculations (storage.rs).
    pub fn all_holdings(&self) -> Result<Vec<HoldingRecord>, EscrowError>;

    /// Insert a new HoldingRecord when a shard is first received.
    /// Called by storage.rs after blob is verified and saved.
    pub fn insert_holding(
        &self,
        record: HoldingRecord,
    ) -> Result<(), EscrowError>;

    /// Remove a HoldingRecord after the shard has been physically deleted.
    /// Called by storage.rs after disk delete completes.
    pub fn remove_holding(&self, shard_id: &ShardId) -> Result<(), EscrowError>;
}
```

### Error enum

```rust
#[derive(Debug, thiserror::Error)]
pub enum EscrowError {
    #[error("shard not held: {0:?}")]
    ShardNotHeld(ShardId),

    #[error("owner mismatch for shard {shard:?}: expected {expected:?}, got {actual:?}")]
    OwnerMismatch {
        shard: ShardId,
        expected: IdentityPub,
        actual: IdentityPub,
    },

    #[error("db error: {0}")]
    Db(#[from] redb::Error),

    #[error("serialization error: {0}")]
    Cbor(String),
}
```

---

## Business Rules (exact)

### Tier classification

```
bytes_restored_so_far = escrow_restore_log[owner_pub].bytes_restored (0 if no record)

tier = match bytes_restored_so_far:
    0 .. FREE_TIER_BYTES      → FreeTier  (always allowed, no weeks check)
    FREE_TIER_BYTES .. TIER1_MAX_BYTES → Tier1  (requires >= 4 weeks)
    TIER1_MAX_BYTES .. TIER2_MAX_BYTES → Tier2  (requires >= 13 weeks)
    TIER2_MAX_BYTES ..         → Tier3  (requires >= 26 weeks)
```

Ranges are inclusive at the lower bound, exclusive at the upper bound.
Example: bytes_restored = 1_073_741_823 (1 GiB - 1 byte) → FreeTier.
Example: bytes_restored = 1_073_741_824 (exactly 1 GiB) → Tier1.

### Required weeks per tier

```
FreeTier → required_weeks = 0  (always allowed)
Tier1    → required_weeks = TIER1_MIN_WEEKS = 4
Tier2    → required_weeks = TIER2_MIN_WEEKS = 13
Tier3    → required_weeks = TIER3_MIN_WEEKS = 26
```

### EscrowTier helper

```rust
impl EscrowTier {
    pub fn required_weeks(self) -> u32 {
        match self {
            EscrowTier::FreeTier => 0,
            EscrowTier::Tier1 => TIER1_MIN_WEEKS,
            EscrowTier::Tier2 => TIER2_MIN_WEEKS,
            EscrowTier::Tier3 => TIER3_MIN_WEEKS,
        }
    }
}
```

### Double cooldown (anti-ransomware)

```
Owner side (enforced by Processor, defined here for reference):
  Owner discovers file deleted locally → waits OWNER_DELETE_COOLDOWN_SECS (4 weeks)
  → sends delete message to holder

Holder side (enforced by EscrowChecker):
  Receives delete message → sets delete_requested_at = now, state = MarkedForDelete
  → waits HOLDER_DELETE_COOLDOWN_SECS (4 weeks) from delete_requested_at
  → calls should_delete_now() → Delete
  → physically deletes blob → calls remove_holding()

Total from local file deletion to physical blob deletion: 8 weeks minimum.
cancel_delete can arrive at any point during either cooldown period and stops the process.
```

Important: HOLDER_DELETE_COOLDOWN_SECS is measured from delete_requested_at, NOT from
when the owner originally deleted the file. The two cooldowns are independent and sequential.

### Holder-initiated eviction has NO cooldown

```
Disk pressure Phase 1 (hard threshold): holder deletes shards immediately.
  → No mark_for_delete, no cooldown. This is the holder's right.
  → Holder sends shard_dropped to owner (best effort, not enforced).

Disk pressure Phase 2 (soft threshold): holder sends 7-day notice.
  → record_drop_notice() records the timestamp.
  → check_drop_notice() returns DeleteNow after 7 days.
  → No owner consent required.
```

EscrowChecker does NOT implement disk pressure decisions — that is storage.rs. EscrowChecker
only stores the drop_notice timestamps and answers "has the window expired?".

### Restore during MarkedForDelete cooldown

During cooldown (state == MarkedForDelete, cooldown not expired):
- Shard physically exists on holder's disk
- Owner can send cancel_delete to revert to Active state
- Restore request goes through **normal escrow check** (tenure tiers apply as usual)
- MarkedForDelete status does NOT bypass or override escrow — owner still needs weeks_in_network

After cooldown expires:
- check_restore() returns Denied (shard is logically gone, pending physical deletion)
- Owner should have sent cancel_delete earlier

Anti-ransomware scenario: virus deletes files → owner's daemon sends delete after 4wk owner
cooldown → owner discovers ransomware → sends cancel_delete (returns to Active) → requests
restore through normal escrow flow (tenure check applies).

Key point: cancel_delete and restore are separate mechanisms. cancel_delete = undo the delete.
restore = download the shard (always gated by escrow tenure).

### Silent shards and eviction

Silent shards (no PoS for extended time) have lower eviction priority — the eviction_priority
formula in storage.rs uses trust_of_owner. If owner is silent and has low I-score (< 4 weeks
in network), priority approaches zero. EscrowChecker marks shards as Silent; storage.rs reads
this and adjusts priority.

The threshold for "how long until Silent" is not specified precisely in the protocol. This spec
leaves it to the Scheduler to call mark_silent() after a configurable number of weeks (suggested
default: 8 weeks with no PoS from owner). This is NOT a constant in escrow.rs — the Scheduler
decides the policy.

---

## DB Operations (detailed)

### check_restore

```
READ  holding[shard_id]        → HoldingRecord (or ShardNotHeld)
READ  escrow_restore_log[owner_pub] → bytes_restored (default 0)
READ  peers[owner_pub]         → PeerRecord.weeks_in_network (default 0 if absent)
NO WRITES (read-only)
```

### record_restore

```
READ  escrow_restore_log[owner_pub] → or default EscrowRestoreLog
UPDATE bytes_restored += bytes_served
UPDATE last_restore_at = now
UPDATE first_restore_at = now (if None)
WRITE escrow_restore_log[owner_pub]
```

### mark_for_delete

```
READ  holding[shard_id]
  → verify owner_pub matches (OwnerMismatch if not)
  → if state == MarkedForDelete: return Ok(()) (idempotent)
UPDATE state = MarkedForDelete
UPDATE delete_requested_at = Some(now)
WRITE holding[shard_id]
```

### cancel_delete

```
READ  holding[shard_id]
  → verify owner_pub matches
  → if state == Active: return Ok(()) (idempotent)
UPDATE state = Active
UPDATE delete_requested_at = None
WRITE holding[shard_id]
```

### should_delete_now

```
READ  holding[shard_id]
  → if state != MarkedForDelete: return Keep
  → delete_requested_at is None: panic! ("invariant: MarkedForDelete without timestamp")
  → if now - delete_requested_at >= HOLDER_DELETE_COOLDOWN_SECS: return Delete
  → else: return Keep
```

### expired_deletes

```
SCAN  holding table (all records)
FILTER state == MarkedForDelete
       AND delete_requested_at is Some
       AND now - delete_requested_at >= HOLDER_DELETE_COOLDOWN_SECS
RETURN Vec<ShardId> of matching records
```

---

## Test Scenarios

All tests use `testutil::test_db()`, `testutil::test_peer()`, `testutil::test_shard()`.

### free_tier_always_allowed

```
Setup:  insert_holding(HoldingRecord { owner_pub: peer, size: 100, ... })
        [no escrow_restore_log for peer → bytes_restored = 0]
        peer.weeks_in_network = 0  (upsert_peer, t0)
        check_restore(&shard_id, &peer, now)
Expect: RestoreDecision::Allowed
```

### tier1_denied_below_4_weeks

```
Setup:  insert_holding(record with size = 2_GiB)
        [mock: bytes_restored_so_far = FREE_TIER_BYTES + 1, e.g., record_restore for 1 GiB + 1 already]
        peer.weeks_in_network = 3  (upsert_peer, set recalculate with 3*604800 elapsed)
        check_restore(...)
Expect: RestoreDecision::Denied(EscrowDenial {
            tier: Tier1,
            required_weeks: 4,
            current_weeks: 3,
        })
```

### tier1_allowed_at_4_weeks

```
Setup:  bytes_restored = FREE_TIER_BYTES + 1
        peer.weeks_in_network = 4
        check_restore(...)
Expect: RestoreDecision::Allowed
```

### tier2_denied_below_13_weeks

```
Setup:  bytes_restored = TIER1_MAX_BYTES + 1
        peer.weeks_in_network = 12
        check_restore(...)
Expect: Denied(tier=Tier2, required_weeks=13, current_weeks=12)
```

### tier2_allowed_at_13_weeks

```
Setup:  bytes_restored = TIER1_MAX_BYTES + 1
        peer.weeks_in_network = 13
        check_restore(...)
Expect: Allowed
```

### tier3_denied_below_26_weeks

```
Setup:  bytes_restored = TIER2_MAX_BYTES + 1
        peer.weeks_in_network = 25
        check_restore(...)
Expect: Denied(tier=Tier3, required_weeks=26, current_weeks=25)
```

### tier3_allowed_at_26_weeks

```
Setup:  bytes_restored = TIER2_MAX_BYTES + 1
        peer.weeks_in_network = 26
        check_restore(...)
Expect: Allowed
```

### unknown_owner_gets_zero_weeks

```
Setup:  insert_holding(record for owner=peer_x)
        [peer_x NOT in peers table]
        bytes_restored = FREE_TIER_BYTES + 1  (past free tier)
        check_restore(shard, peer_x, now)
Expect: Denied(required_weeks=4, current_weeks=0)
```

### veteran_always_passes_tier3

```
Setup:  bytes_restored = TIER2_MAX_BYTES + 1
        peer.weeks_in_network = 200  (4 years)
        check_restore(...)
Expect: Allowed
```

### record_restore_accumulates

```
Setup:  record_restore(shard_a, peer, bytes=500_000_000, now=t1)
        record_restore(shard_b, peer, bytes=600_000_000, now=t2)
        [escrow_restore_log for peer].bytes_restored == 1_100_000_000
Expect: bytes_restored = 1_100_000_000
        first_restore_at = t1
        last_restore_at = t2
```

### mark_for_delete_sets_state

```
Setup:  insert_holding(active shard)
        mark_for_delete(&shard_id, &owner, now=Timestamp(0))
        get_holding(&shard_id)
Expect: state == MarkedForDelete
        delete_requested_at == Some(Timestamp(0))
```

### mark_for_delete_is_idempotent

```
Setup:  mark_for_delete(&shard_id, &owner, Timestamp(100))
        mark_for_delete(&shard_id, &owner, Timestamp(200))
        get_holding(&shard_id)
Expect: delete_requested_at == Some(Timestamp(100))  (first call wins)
```

### holder_cooldown_not_expired_keeps_shard

```
Setup:  mark_for_delete(&shard_id, &owner, now=Timestamp(0))
        should_delete_now(&shard_id, now=Timestamp(HOLDER_DELETE_COOLDOWN_SECS - 1))
Expect: DeleteDecision::Keep
```

### holder_cooldown_expired_deletes_shard

```
Setup:  mark_for_delete(&shard_id, &owner, now=Timestamp(0))
        should_delete_now(&shard_id, now=Timestamp(HOLDER_DELETE_COOLDOWN_SECS))
Expect: DeleteDecision::Delete
```

### cancel_delete_restores_active_state

```
Setup:  mark_for_delete(&shard_id, &owner, Timestamp(0))
        [still in cooldown]
        cancel_delete(&shard_id, &owner)
        get_holding(&shard_id)
Expect: state == Active
        delete_requested_at == None
```

### cancel_delete_after_cooldown_expired

```
Setup:  mark_for_delete(&shard_id, &owner, Timestamp(0))
        [cooldown has passed in wall clock but owner sent cancel_delete]
        cancel_delete(&shard_id, &owner)
        should_delete_now(&shard_id, now=very_late)
Expect: DeleteDecision::Keep  (cancel wins regardless of timing — caller must cancel before remove_holding)
```

### drop_notice_window_not_expired

```
Setup:  record_drop_notice(&shard_id, now=Timestamp(0))
        check_drop_notice(&shard_id, now=Timestamp(DROP_NOTICE_WINDOW_SECS - 1))
Expect: DropNoticeDecision::StillWaiting
```

### drop_notice_window_expired

```
Setup:  record_drop_notice(&shard_id, now=Timestamp(0))
        check_drop_notice(&shard_id, now=Timestamp(DROP_NOTICE_WINDOW_SECS))
Expect: DropNoticeDecision::DeleteNow
```

### no_drop_notice_sent_is_still_waiting

```
Setup:  insert_holding(record with drop_notice_sent_at=None)
        check_drop_notice(&shard_id, now=any)
Expect: DropNoticeDecision::StillWaiting
```

### expired_deletes_returns_correct_shards

```
Setup:  shard_a: mark_for_delete at T=0
        shard_b: mark_for_delete at T=0
        shard_c: mark_for_delete at T=HOLDER_DELETE_COOLDOWN_SECS  (just now)
        expired_deletes(now=HOLDER_DELETE_COOLDOWN_SECS)
Expect: [shard_a, shard_b] (both expired)
        shard_c NOT in result (cooldown started at T, now==T+cooldown, just barely expired)
        Wait: Timestamp(0) + cooldown = cooldown. now = cooldown. diff = 0. >= 0. → expired.
        So all three are expired at exactly now=cooldown? Let's be precise:
          condition: now - delete_requested_at >= HOLDER_DELETE_COOLDOWN_SECS
          shard_a: cooldown - 0 = cooldown >= cooldown → true
          shard_b: same → true
          shard_c: cooldown - cooldown = 0 >= cooldown → false
        Expect: [shard_a, shard_b]
```

### owner_mismatch_is_error

```
Setup:  insert_holding(record with owner_pub=peer_a)
        mark_for_delete(&shard_id, &peer_b, now)
Expect: EscrowError::OwnerMismatch { expected: peer_a, actual: peer_b }
```

### check_restore_shard_not_held

```
Setup:  [empty holding table]
        check_restore(&shard_id, &owner, now)
Expect: EscrowError::ShardNotHeld(shard_id)

Note: caller (storage.rs) should translate this into a shard_reject message, not a
restore_denied — the shard is genuinely absent, not escrow-blocked.
```

### free_tier_boundary_exact

```
Input:  bytes_restored = FREE_TIER_BYTES - 1 → FreeTier (Allowed)
Input:  bytes_restored = FREE_TIER_BYTES     → Tier1
Input:  bytes_restored = FREE_TIER_BYTES + 1 → Tier1
```

### mark_silent_and_back_to_active

```
Setup:  insert_holding(active shard)
        mark_silent(&shard_id)
        get_holding(&shard_id)
Expect: state == Silent

        mark_active(&shard_id)
        get_holding(&shard_id)
Expect: state == Active
```

### all_holdings_returns_all

```
Setup:  insert_holding(shard_a), insert_holding(shard_b), insert_holding(shard_c)
        all_holdings()
Expect: Vec of length 3 containing all three records
```

---

## Dependencies

- `types.rs` — `ShardId`, `IdentityPub`, `Timestamp`, `HoldingRecord`, `ShardState`, `FileType`
- `db.rs` — `Db` newtype, table definitions for `holding`, `escrow_restore_log`, `peers` (read-only)
- `redb` — read/write transactions
- `serde` + `ciborium` — CBOR
- `thiserror` — EscrowError

escrow.rs does NOT depend on trust.rs, placement.rs, budget.rs, or messages.rs.
It reads the `peers` table directly for weeks_in_network — it does not call TrustEngine methods
(to avoid circular dependency and keep escrow logic self-contained).

---

## Notes for Implementer

1. The ShardNotHeld error from check_restore signals "we don't have this shard at all" — which
   is distinct from "escrow denied". The caller (storage.rs) must map this to the correct
   wire message: shard_reject (if called during upload) vs a log warning (if called during restore).

2. The peers table is shared between trust.rs and escrow.rs. Both read it; only trust.rs writes it.
   Since Db wraps Arc<redb::Database>, concurrent reads are safe (MVCC). escrow.rs reads only
   weeks_in_network from PeerRecord.

3. All Timestamp arithmetic uses u64 saturating subtraction. Never panic on underflow:
   `let elapsed = now.0.saturating_sub(delete_requested_at.0);`

4. expired_deletes() and expired_drop_notices() do a full table scan. With 30,000 held shards
   this is ~30K CBOR deserializations — acceptable for a weekly batch job. If performance
   becomes an issue, add a secondary index table (e.g., `deletes_pending: shard_id → deadline_ts`).
   For alpha this is not needed.

5. System state shards (file_type == FileType::System) are given max priority by storage.rs.
   EscrowChecker stores file_type in HoldingRecord but does not use it for any decision —
   it is purely informational for storage.rs.

6. Log at DEBUG for every state transition (mark_for_delete, cancel_delete, mark_silent).
   Log at DEBUG for every check_restore call and its outcome.
