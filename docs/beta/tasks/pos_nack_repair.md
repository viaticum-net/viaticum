# Task: pos_nack_repair — Phase 2.5: PosNack + PlacementStatus state machine + RepairAgent

Modules touched:
- `crates/syncback-core/src/pos/` — extend types and `outcome_from_verify`
- `crates/syncback-core/src/types/mod.rs` — extend `PlacementStatus` and `SymbolPlacement`
- `crates/syncback-core/src/messages/mod.rs` — add `PosNackMsg` and `Message::PosNack`
- `crates/syncback/src/daemon/repair/` — new module `mod.rs` + `tests.rs`
- `crates/syncback/src/daemon/mod.rs` — re-export `repair`

All files follow the convention: `mod.rs` + `tests.rs`. No inline `#[cfg(test)]`.

---

## Overview

Phase 2.5 closes the reliability loop: when a holder loses symbols (disk wipe, eviction,
corruption), the owner must detect it and re-distribute replacement symbols to a new or
existing holder. This phase introduces:

1. **`VerifyOutcome::NotHeld`** — the holder's explicit "I do not have this symbol" signal.
   Distinct from `Fail` (data present but wrong) and `Timeout` (no response at all).

2. **`PlacementStatus::Uncertain` / `PresumedLost`** — graduated degradation for timeout
   chains. Explicit failures (`Fail`, `NotHeld`) skip the graduation and go directly to
   `Lost`.

3. **`consecutive_misses: u32`** on `SymbolPlacement` — tracks how many consecutive
   timeouts have been observed for this (block, holder) pair.

4. **`PosNackMsg`** — the wire message a holder sends when it cannot answer a PoS
   challenge because it no longer holds the symbols.

5. **`RepairAgent`** — daemon module that scans for `Lost` / `PresumedLost` placements
   and generates replacement symbols from the local source block file, writing them to
   `symbols_dir` and inserting new `SymbolPlacement` records into DB.

6. **Idempotent transitions** — `SymbolDropped` (explicit drop notice) and `PosNack`
   (response to challenge) both route through the same placement-transition function.
   Receiving both in any order produces the same final state.

Phase 2.5 does **no network sending** of repaired symbols. The RepairAgent writes
repaired symbols to disk and records them in DB. Network delivery is Phase 3+.

---

## Dependencies

### syncback-core changes (pure, no async)

- `crate::pos::{VerifyOutcome, PosChallenge, PosResponse, PosError, outcome_from_verify}`
- `crate::types::{SymbolPlacement, PlacementStatus, SourceBlockId, IdentityPub, Timestamp,
    ErasureParams, SourceBlockRecord}`
- `crate::messages::{Message, PosNackMsg}`
- `crate::db::Db`
- `crate::erasure::{ErasureEncoder, RaptorQEncoder, Symbol}`
- `crate::constants::{POS_CONSECUTIVE_MISS_UNCERTAIN, POS_CONSECUTIVE_MISS_PRESUMED_LOST}`

### syncback (daemon, async)

- `syncback_core::db::Db`
- `syncback_core::types::{SymbolPlacement, PlacementStatus, SourceBlockId, IdentityPub,
    Timestamp, ErasureParams}`
- `syncback_core::erasure::{ErasureEncoder, RaptorQEncoder}`
- `syncback_core::pos::{apply_pos_outcome, PlacementTransition}`
- `tokio` (task, fs, sync)
- `tracing::{info, debug, error, warn}`
- `anyhow::{Context, Result}`
- `std::path::PathBuf`

---

## Part 1: Changes to syncback-core

### 1.1 New constants (`crates/syncback-core/src/constants.rs`)

Add two constants at the end of `constants.rs`:

```rust
/// Number of consecutive PoS timeouts before a placement is marked Uncertain.
/// First timeout → Uncertain immediately (1 miss = Uncertain).
pub const POS_CONSECUTIVE_MISS_UNCERTAIN: u32 = 1;

/// Number of consecutive PoS timeouts before a placement is marked PresumedLost.
/// 3+ consecutive misses → PresumedLost → triggers repair.
pub const POS_CONSECUTIVE_MISS_PRESUMED_LOST: u32 = 3;
```

The roadmap says "1-2 misses = Uncertain, 3+ = PresumedLost". The constants encode:
- After 1st timeout miss → `Uncertain` (consecutive_misses == 1)
- After 3rd timeout miss → `PresumedLost` (consecutive_misses >= 3)

### 1.2 Types changes (`crates/syncback-core/src/types/mod.rs`)

#### 1.2.1 Extend `PlacementStatus`

Replace the existing enum with:

```rust
/// Status of symbols from the owner's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PlacementStatus {
    /// symbol_offer sent, waiting for response.
    Offered,
    /// Holder accepted, transfer in progress.
    Accepted,
    /// Symbols stored and confirmed. PoS challenges active.
    Alive,
    /// Holder missed 1-2 consecutive PoS challenges (timeout). Not yet confirmed lost.
    Uncertain,
    /// Holder missed 3+ consecutive PoS challenges. Repair will be triggered.
    PresumedLost,
    /// Holder dropped symbols or explicitly failed PoS. Repair triggered.
    Lost,
    /// Delete in progress.
    Deleting,
}
```

#### 1.2.2 Extend `SymbolPlacement`

Add `consecutive_misses: u32` field:

```rust
/// Symbol placement from owner's perspective. Key: (SourceBlockId, holder IdentityPub).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SymbolPlacement {
    pub source_block_id: SourceBlockId,
    pub holder_id: IdentityPub,
    /// File that owns this source block (for O(1) index updates).
    pub file_id: FileId,
    /// Ranges of ESIs assigned to this holder: (start_esi, count).
    pub esi_ranges: Vec<(u32, u32)>,
    /// Seed for per-holder binding: HKDF(source_block_id, holder_id).
    pub binding_seed: [u8; 32],
    pub status: PlacementStatus,
    pub last_verified: Option<Timestamp>,
    pub placed_at: Timestamp,
    /// Consecutive PoS timeout misses. Reset to 0 on Pass. Not incremented on Fail/NotHeld
    /// (those are immediate: status → Lost without graduation).
    #[serde(default)]
    pub consecutive_misses: u32,
}
```

The `#[serde(default)]` on `consecutive_misses` ensures that existing DB records that
predate this field deserialize without error (default value 0).

#### 1.2.3 Extend `PlacementAgg`

The hot cache aggregate mirrors placement status. Since `consecutive_misses` is only
used in repair logic (which reads from warm DB), it does not need to be in `PlacementAgg`.
However, the status field must reflect the new variants:

```rust
/// Per-(source_block, holder) aggregate (RAM layer).
#[derive(Debug, Clone, Copy)]
pub struct PlacementAgg {
    pub symbol_count: u32,
    pub status: PlacementStatus,
    pub last_pos: Option<Timestamp>,
}
```

No structural change to `PlacementAgg` — the new `PlacementStatus` variants are already
handled by the enum extension.

### 1.3 PoS engine changes (`crates/syncback-core/src/pos/mod.rs`)

#### 1.3.1 Extend `VerifyOutcome`

```rust
/// Outcome of verifying a PoS response.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyOutcome {
    /// Response data matches re-encoded expected bytes.
    Pass,
    /// Response data does not match (holder corrupted or lost the symbol).
    Fail { esi: u32 },
    /// Response was not received before the deadline (7 days).
    Timeout,
    /// Holder explicitly responded that it does not hold this symbol (PosNack received).
    NotHeld { esi: u32 },
}
```

#### 1.3.2 Update `outcome_from_verify`

```rust
/// Classify a completed PoS result for one holder into a PosOutcome
/// ready to pass to TrustEngine::record_pos_result.
///
/// NotHeld counts as challenged=1, passed=0 (same as Fail — holder no longer holds data).
pub fn outcome_from_verify(result: &VerifyOutcome, week_number: u32) -> PosOutcome {
    let passed = match result {
        VerifyOutcome::Pass => 1,
        VerifyOutcome::Fail { .. }
        | VerifyOutcome::Timeout
        | VerifyOutcome::NotHeld { .. } => 0,
    };
    PosOutcome {
        week_number,
        challenged: 1,
        passed,
    }
}
```

#### 1.3.3 New function: `apply_pos_outcome`

This is the placement state machine. It takes the current placement record and a
`VerifyOutcome` and returns a `PlacementTransition` describing what changed.

```rust
/// Result of applying a PoS outcome to a placement.
#[derive(Debug, Clone, PartialEq)]
pub struct PlacementTransition {
    /// New status for the placement.
    pub new_status: PlacementStatus,
    /// New consecutive_misses count.
    pub new_consecutive_misses: u32,
    /// Whether repair should be triggered for this placement.
    pub trigger_repair: bool,
}

/// Apply a PoS outcome to a placement record and return the resulting transition.
///
/// State machine rules:
///
///   Any status + Pass        → Alive, misses=0, repair=false
///   Any status + Fail        → Lost,  misses=0, repair=true   (explicit wrong data)
///   Any status + NotHeld     → Lost,  misses=0, repair=true   (explicit no-hold)
///   Any status + Timeout:
///     misses+1 < UNCERTAIN_THRESHOLD  → Alive (stays Alive, misses++)
///     Wait — see exact thresholds below.
///
/// Timeout graduation based on new consecutive_misses count (misses + 1):
///   new_misses < POS_CONSECUTIVE_MISS_UNCERTAIN  → Alive (not yet uncertain; stays Alive)
///   new_misses == POS_CONSECUTIVE_MISS_UNCERTAIN → Uncertain
///   new_misses > POS_CONSECUTIVE_MISS_UNCERTAIN
///      && new_misses < POS_CONSECUTIVE_MISS_PRESUMED_LOST → Uncertain (stays Uncertain)
///   new_misses >= POS_CONSECUTIVE_MISS_PRESUMED_LOST → PresumedLost, repair=true
///
/// With the default constants (UNCERTAIN=1, PRESUMED_LOST=3):
///   Alive + Timeout → Uncertain (misses=1)
///   Uncertain + Timeout → Uncertain (misses=2)
///   Uncertain + Timeout → PresumedLost, repair (misses=3)
///   PresumedLost + Pass → Alive, misses=0        (peer was just offline temporarily)
///   PresumedLost + Fail → Lost, repair
///   PresumedLost + NotHeld → Lost, repair
///   PresumedLost + Timeout → PresumedLost (misses++, repair still pending)
///
/// Note: for placements already in Lost or Deleting status, all transitions are no-ops
/// (return current status unchanged, trigger_repair=false). The RepairAgent already
/// handles these states.
pub fn apply_pos_outcome(
    placement: &SymbolPlacement,
    outcome: &VerifyOutcome,
) -> PlacementTransition;
```

Full implementation logic:

```
apply_pos_outcome(placement, outcome):
  // Dead placements: no further transitions
  if placement.status == Lost || placement.status == Deleting:
    return PlacementTransition {
      new_status: placement.status,
      new_consecutive_misses: placement.consecutive_misses,
      trigger_repair: false,
    }

  match outcome:
    Pass =>
      PlacementTransition { new_status: Alive, new_consecutive_misses: 0, trigger_repair: false }

    Fail { .. } | NotHeld { .. } =>
      PlacementTransition { new_status: Lost, new_consecutive_misses: 0, trigger_repair: true }

    Timeout =>
      new_misses = placement.consecutive_misses + 1
      if new_misses >= POS_CONSECUTIVE_MISS_PRESUMED_LOST:
        PlacementTransition { new_status: PresumedLost, new_consecutive_misses: new_misses, trigger_repair: true }
      else if new_misses >= POS_CONSECUTIVE_MISS_UNCERTAIN:
        PlacementTransition { new_status: Uncertain, new_consecutive_misses: new_misses, trigger_repair: false }
      else:
        // Should not happen with UNCERTAIN=1 (new_misses is always >= 1 after first timeout),
        // but keep the else branch for correctness if constants change.
        PlacementTransition { new_status: Alive, new_consecutive_misses: new_misses, trigger_repair: false }
```

The caller applies the transition:
1. Update `placement.status` and `placement.consecutive_misses` from the result.
2. Update `placement.last_verified` to `now` on Pass (other outcomes: leave unchanged or
   set to `now` per caller policy — spec does not mandate either; Pass is the only case
   that resets the PoS interval timer).
3. Call `db.upsert_placement(&placement)`.
4. If `trigger_repair`: send placement key to `RepairAgent` via channel (or flag in DB).

### 1.4 Messages changes (`crates/syncback-core/src/messages/mod.rs`)

#### 1.4.1 New `PosNackMsg`

```rust
/// Holder → Owner. Holder received a PoS challenge but does not hold the symbol.
///
/// Sent in response to PosChallengeMsg when:
///   - The holder has evicted the symbols for this source block.
///   - The holder never received the symbols (missed transfer).
///   - The holder's HoldingRecord for this block has status != Active.
///
/// The owner treats this as VerifyOutcome::NotHeld → PlacementStatus::Lost → repair.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PosNackMsg {
    pub v: u8,
    /// challenge_id from the PosChallengeMsg this is responding to.
    pub challenge_id: [u8; 16],
    pub source_block_id: SourceBlockId,
    /// The challenged ESI the holder cannot serve.
    pub esi: u32,
    pub timestamp: Timestamp,
}
```

#### 1.4.2 Add `Message::PosNack` variant

In the `Message` enum, add after `PosResponse`:

```rust
pub enum Message {
    Handshake(HandshakeMsg),
    PeerAnnounce(PeerAnnounceMsg),
    PosChallenge(PosChallengeMsg),
    PosResponse(PosResponseMsg),
    PosNack(PosNackMsg),           // ← NEW
    SymbolOffer(SymbolOfferMsg),
    SymbolAccept(SymbolAcceptMsg),
    SymbolReject(SymbolRejectMsg),
    SymbolStored(SymbolStoredMsg),
    SymbolTransfer(SymbolTransferMsg),
    Delete(DeleteMsg),
    CancelDelete(CancelDeleteMsg),
    StorageWarning(StorageWarningMsg),
    SymbolDropped(SymbolDroppedMsg),
    SymbolDropNotice(SymbolDropNoticeMsg),
    RestoreRequest(RestoreRequestMsg),
    RestoreResponse(RestoreResponseMsg),
    RestoreDenied(RestoreDeniedMsg),
    BoardSync(BoardSyncMsg),
}
```

The `#[serde(tag = "type", rename_all = "snake_case")]` attribute on the enum means the
new variant serializes with tag `"pos_nack"` — consistent with the existing naming
convention. No migration needed for existing messages.

### 1.5 DB: `list_placements_needing_repair`

Add a new method to `Db` for the RepairAgent to query which placements need attention:

```rust
impl Db {
    /// Return all placements with status Lost or PresumedLost.
    /// Used by RepairAgent to find work.
    pub fn list_placements_needing_repair(&self) -> Result<Vec<SymbolPlacement>, DbError> {
        let tx = self.inner.begin_read()?;
        let table = tx.open_table(SYMBOL_PLACEMENTS)?;
        let mut records = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            let record: SymbolPlacement = from_cbor_bytes(v.value())?;
            if record.status == PlacementStatus::Lost
                || record.status == PlacementStatus::PresumedLost
            {
                records.push(record);
            }
        }
        Ok(records)
    }
}
```

---

## Part 2: RepairAgent (syncback daemon)

New module: `crates/syncback/src/daemon/repair/`

### 2.1 Module structure

```
crates/syncback/src/daemon/repair/
  mod.rs      — RepairAgent struct, public API, run loop
  tests.rs    — all test scenarios
```

Add to `crates/syncback/src/daemon/mod.rs`:
```rust
pub mod repair;
```

### 2.2 Types

```rust
/// Configuration for the RepairAgent.
#[derive(Debug, Clone)]
pub struct RepairConfig {
    /// Directory where local source block files are stored.
    /// Each file is named by its SourceBlockId hex.
    pub source_blocks_dir: std::path::PathBuf,
    /// Directory where generated repair symbols are written.
    /// Format: `{symbols_dir}/{source_block_id_hex}/{holder_id_hex}/{esi}.sym`
    pub symbols_dir: std::path::PathBuf,
    /// Epoch key for deriving binding key (same as BackupCoordinator uses).
    pub epoch_key: [u8; 32],
    /// This node's identity (for choosing self as repair holder if no peers available).
    pub own_identity: IdentityPub,
}

/// One repair job: regenerate symbols for a Lost/PresumedLost placement.
#[derive(Debug, Clone)]
pub struct RepairJob {
    pub source_block_id: SourceBlockId,
    pub holder_id: IdentityPub,
    pub file_id: FileId,
}

/// Outcome of executing one repair job.
#[derive(Debug)]
pub struct RepairOutcome {
    pub job: RepairJob,
    pub symbols_written: u32,
    pub new_status: PlacementStatus,
}

/// Error type for repair operations.
#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("source block file not found: {0}")]
    SourceBlockMissing(SourceBlockId),

    #[error("source block record missing from DB: {0}")]
    RecordMissing(SourceBlockId),

    #[error("placement record missing from DB: block={0} holder={1}")]
    PlacementMissing(SourceBlockId, IdentityPub),

    #[error("erasure encode failed: {0}")]
    EncodeFailed(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),
}
```

### 2.3 Public API

```rust
/// RepairAgent: scans for Lost/PresumedLost placements and regenerates symbols locally.
///
/// Phase 2.5 scope: symbol generation only (no network delivery). Symbols are
/// written to symbols_dir and placement status is updated to Alive in DB.
/// Network delivery of repaired symbols is out of scope until Phase 3.
pub struct RepairAgent {
    db: Db,
    config: RepairConfig,
    encoder: Arc<dyn ErasureEncoder>,
}

impl RepairAgent {
    /// Create a new RepairAgent.
    pub fn new(
        db: Db,
        config: RepairConfig,
        encoder: Arc<dyn ErasureEncoder>,
    ) -> Self;

    /// Scan DB for placements needing repair and execute all repair jobs.
    ///
    /// Calls db.list_placements_needing_repair(), then for each placement calls
    /// repair_placement(). Logs outcomes via tracing.
    ///
    /// Returns the number of placements successfully repaired.
    ///
    /// Individual placement failures are logged at ERROR but do not abort the scan.
    pub async fn scan_and_repair(&self) -> usize;

    /// Repair a single placement: regenerate its symbols from local source data.
    ///
    /// Steps:
    /// 1. Read SourceBlockRecord from DB → get K, T.
    /// 2. Read SymbolPlacement from DB → get esi_ranges, binding_seed, holder_id.
    /// 3. Compute source block file path:
    ///    `{source_blocks_dir}/{hex(source_block_id)}`
    /// 4. Read source block file into memory.
    ///    If missing: return Err(SourceBlockMissing).
    /// 5. Compute ErasureParams from K and T (see note below).
    /// 6. For each ESI in placement.esi_ranges:
    ///    a. Call encoder.encode(source_data, params, esi, 1, block_id, holder_id).
    ///    b. Write symbol to:
    ///       `{symbols_dir}/{hex(source_block_id)}/{hex(holder_id)}/{esi}.sym`
    ///       Create parent directories as needed.
    /// 7. Update SymbolPlacement:
    ///    placement.status = PlacementStatus::Alive
    ///    placement.consecutive_misses = 0
    ///    placement.last_verified = None  (reset: no PoS yet for new symbols)
    /// 8. db.upsert_placement(&placement).
    /// 9. Return Ok(RepairOutcome { symbols_written, new_status: Alive }).
    ///
    /// Note on ErasureParams: use ErasureParams { k, k_eff: k + DECODE_OVERHEAD,
    /// t: T from SourceBlockRecord, overhead: 1.5 (conservative default), n: computed
    /// from esi_ranges total }. The overhead field only affects n (total symbols), but
    /// for repair we re-encode specific ESIs from existing esi_ranges — we do not need
    /// to re-run placement. So `n` can be set to any value >= max_esi used.
    /// Recommended: set n = k_eff * 2 (safe upper bound) and pass params to encode.
    pub async fn repair_placement(
        &self,
        block_id: &SourceBlockId,
        holder_id: &IdentityPub,
    ) -> Result<RepairOutcome, RepairError>;

    /// Process an incoming SymbolDropped message.
    ///
    /// Transitions placement → Lost and queues for repair (equivalent to NotHeld).
    /// This is the idempotent entry point: calling it multiple times for the same
    /// (block_id, holder_id) is safe — if placement is already Lost, it's a no-op.
    ///
    /// Called by the network message handler when a SymbolDroppedMsg is received.
    pub async fn handle_symbol_dropped(
        &self,
        block_id: &SourceBlockId,
        holder_id: &IdentityPub,
        now: Timestamp,
    ) -> Result<(), RepairError>;

    /// Process an incoming PosNack message.
    ///
    /// Equivalent to handle_symbol_dropped from the owner's perspective.
    /// Transitions placement → Lost and marks for repair.
    /// Idempotent: if placement is already Lost, no-op.
    ///
    /// Called by the network message handler when a PosNackMsg is received.
    pub async fn handle_pos_nack(
        &self,
        block_id: &SourceBlockId,
        holder_id: &IdentityPub,
        now: Timestamp,
    ) -> Result<(), RepairError>;

    /// Run as a periodic background task.
    ///
    /// Every scan_interval_secs, calls scan_and_repair().
    /// Also accepts repair triggers via the rx channel for immediate repairs
    /// (used when PosNack or SymbolDropped arrives between scheduled scans).
    ///
    /// Exits cleanly when rx is dropped (channel closed).
    pub async fn run(
        self,
        scan_interval_secs: u64,
        rx: tokio::sync::mpsc::Receiver<RepairTrigger>,
    ) -> anyhow::Result<()>;
}

/// Trigger message sent to the RepairAgent via channel.
#[derive(Debug)]
pub enum RepairTrigger {
    /// Immediate repair of a specific placement.
    RepairNow {
        block_id: SourceBlockId,
        holder_id: IdentityPub,
    },
    /// Full scan (same as periodic).
    ScanAll,
}
```

### 2.4 Source block file path convention

The RepairAgent reads source block files from `source_blocks_dir`. The naming convention
matches BackupCoordinator's output:

```
{source_blocks_dir}/{lowercase hex of SourceBlockId.0}
```

The repaired symbol files are written to:

```
{symbols_dir}/{lowercase hex of SourceBlockId.0}/{lowercase hex of holder IdentityPub.0}/{esi}.sym
```

The `.sym` files are raw symbol bytes (exactly T = 65535 bytes each), bound to the holder
(same format BackupCoordinator produces). A holder can serve these files directly in
response to `RestoreRequest` or `PosChallenge`.

### 2.5 ErasureParams reconstruction for repair

`SourceBlockRecord` stores `k` and `t` but not `overhead` or `importance`. For repair,
the RepairAgent does not need to reconstruct the exact original `n` — it only needs
to produce the correct bound bytes for specific ESIs the holder is supposed to hold.
The encoder's `encode(source_data, params, esi, 1, block_id, holder_id)` only requires
`params.k`, `params.t`, `params.k_eff` and the specific ESI value. Set:

```rust
let params = ErasureParams {
    k:        record.k,
    k_eff:    record.k + DECODE_OVERHEAD,
    t:        record.t,
    overhead: 1.5,           // not used by encode, only affects n
    n:        record.k * 4,  // safe over-estimate, not used by encode
};
```

This is safe because `encode` only uses `k`, `k_eff`, and `t` for the actual computation.

### 2.6 Idempotent transition logic

Both `handle_symbol_dropped` and `handle_pos_nack` use the same internal helper:

```rust
async fn mark_placement_lost(
    &self,
    block_id: &SourceBlockId,
    holder_id: &IdentityPub,
    now: Timestamp,
) -> Result<(), RepairError> {
    let placement = self.db.get_placement(block_id, holder_id)?
        .ok_or_else(|| RepairError::PlacementMissing(*block_id, *holder_id))?;

    // Idempotent: already lost or deleting → no-op
    if placement.status == PlacementStatus::Lost
        || placement.status == PlacementStatus::Deleting
    {
        return Ok(());
    }

    let mut updated = placement;
    updated.status = PlacementStatus::Lost;
    updated.consecutive_misses = 0;
    self.db.upsert_placement(&updated)?;

    tracing::info!(
        block_id = %block_id,
        holder_id = %holder_id,
        "placement marked Lost (explicit drop/nack)"
    );
    Ok(())
}
```

The idempotency guarantee: calling `mark_placement_lost` a second time for a placement
already in `Lost` state returns `Ok(())` without any DB write. The `scan_and_repair` call
that follows will process it once.

---

## Business Rules

### State machine summary

| Current status | Outcome  | New status    | consecutive_misses | trigger_repair |
|---------------|----------|---------------|--------------------|----------------|
| Any           | Pass     | Alive         | 0                  | false          |
| Any (not Lost/Deleting) | Fail | Lost  | 0                  | true           |
| Any (not Lost/Deleting) | NotHeld | Lost | 0               | true           |
| Alive         | Timeout  | Uncertain     | 1                  | false          |
| Uncertain     | Timeout  | Uncertain     | 2                  | false          |
| Uncertain     | Timeout  | PresumedLost  | 3                  | true           |
| PresumedLost  | Timeout  | PresumedLost  | misses+1           | true (already) |
| Lost          | any      | Lost          | unchanged          | false (no-op)  |
| Deleting      | any      | Deleting      | unchanged          | false (no-op)  |

Note: `Offered` and `Accepted` status placements should not receive PoS challenges
(the daemon scheduler should filter them out before calling `apply_pos_outcome`). If
they somehow do, the state machine treats them as `Alive` for outcome purposes.

### PosNack vs SymbolDropped: identical effect

From the owner's perspective:
- `SymbolDropped` — holder says "I have evicted your symbols"
- `PosNack` — holder says "I got your challenge but I don't have that symbol"

Both produce the same owner-side result: placement → `Lost`, `consecutive_misses = 0`,
trigger repair. The distinction matters only for trust: `SymbolDropped` is cooperative
(holder warned the owner), `PosNack` may indicate uncooperative eviction. In this phase,
both are handled identically. Trust differentiation can be added in Phase 4.

### When SymbolDroppedMsg arrives before PosNack

Sequence: owner sends challenge → holder has already evicted → holder sends SymbolDropped
(on eviction) → then PosNack (in response to challenge still in flight).

Timeline:
1. `handle_symbol_dropped`: placement → Lost (trigger repair queued)
2. `handle_pos_nack`: placement already Lost → no-op (idempotent)
3. `scan_and_repair` runs once → repairs Lost placement

Result: one repair, correct state. Order does not matter.

### When PosNack arrives before SymbolDropped

Timeline:
1. `handle_pos_nack`: placement → Lost (trigger repair queued)
2. `handle_symbol_dropped`: placement already Lost → no-op (idempotent)
3. `scan_and_repair` runs once → repairs Lost placement

Same result.

### Repair: new symbols for the same holder

Phase 2.5 keeps the same holder for repaired symbols (same `esi_ranges`, same
`holder_id`). This is correct for Phase 2.5 because:
1. We have no network to redistribute to a different holder.
2. The holder may have temporarily lost the symbols (e.g., disk replaced) and will
   receive them again when network is available (Phase 3).

In Phase 3, the RepairAgent can optionally select a new holder if the original holder's
trust score is too low. This is out of scope here.

### Local source block availability

`repair_placement` requires the source block to be present locally. If it is not:
- Return `Err(SourceBlockMissing)`.
- Log at ERROR level.
- Continue with other placements in `scan_and_repair`.

Source blocks may be absent if the owner deleted the local backup (user deleted files
and the vacuum ran). In this case, repair is impossible locally. Phase 3+ will handle
distributed repair (another cluster device may have the source block).

---

## DB Operations

### Reads

- `db.list_placements_needing_repair()` — new method, returns `Vec<SymbolPlacement>` with
  status `Lost` or `PresumedLost`
- `db.get_placement(block_id, holder_id)` — single placement lookup in `handle_symbol_dropped`
  and `handle_pos_nack`
- `db.get_source_block(block_id)` — get K and T for ErasureParams reconstruction

### Writes

- `db.upsert_placement(record)` — update status and consecutive_misses after state
  transition; update status back to Alive after successful repair

---

## Test Scenarios

Tests in `crates/syncback-core/src/pos/tests.rs` (for `apply_pos_outcome`) and
`crates/syncback/src/daemon/repair/tests.rs` (for `RepairAgent`).

Pattern: `what_when_then`.

### Core state machine tests (in `pos/tests.rs`)

#### 1. `apply_pos_outcome_pass_resets_to_alive`

```
placement = alive_placement(consecutive_misses=2)  // was Uncertain
outcome = VerifyOutcome::Pass
result = apply_pos_outcome(&placement, &outcome)
assert result.new_status == PlacementStatus::Alive
assert result.new_consecutive_misses == 0
assert result.trigger_repair == false
```

#### 2. `apply_pos_outcome_fail_immediately_marks_lost`

```
placement = alive_placement(consecutive_misses=0)
outcome = VerifyOutcome::Fail { esi: 42 }
result = apply_pos_outcome(&placement, &outcome)
assert result.new_status == PlacementStatus::Lost
assert result.new_consecutive_misses == 0
assert result.trigger_repair == true
```

#### 3. `apply_pos_outcome_not_held_immediately_marks_lost`

```
placement = alive_placement(consecutive_misses=0)
outcome = VerifyOutcome::NotHeld { esi: 7 }
result = apply_pos_outcome(&placement, &outcome)
assert result.new_status == PlacementStatus::Lost
assert result.new_consecutive_misses == 0
assert result.trigger_repair == true
```

#### 4. `apply_pos_outcome_first_timeout_gives_uncertain`

```
placement = alive_placement(consecutive_misses=0)
outcome = VerifyOutcome::Timeout
result = apply_pos_outcome(&placement, &outcome)
assert result.new_status == PlacementStatus::Uncertain
assert result.new_consecutive_misses == 1
assert result.trigger_repair == false
```

#### 5. `apply_pos_outcome_second_timeout_stays_uncertain`

```
placement = uncertain_placement(consecutive_misses=1)
outcome = VerifyOutcome::Timeout
result = apply_pos_outcome(&placement, &outcome)
assert result.new_status == PlacementStatus::Uncertain
assert result.new_consecutive_misses == 2
assert result.trigger_repair == false
```

#### 6. `apply_pos_outcome_third_timeout_gives_presumed_lost`

```
placement = uncertain_placement(consecutive_misses=2)
outcome = VerifyOutcome::Timeout
result = apply_pos_outcome(&placement, &outcome)
assert result.new_status == PlacementStatus::PresumedLost
assert result.new_consecutive_misses == 3
assert result.trigger_repair == true
```

#### 7. `apply_pos_outcome_presumed_lost_pass_recovers_to_alive`

```
placement = presumed_lost_placement(consecutive_misses=3)
outcome = VerifyOutcome::Pass
result = apply_pos_outcome(&placement, &outcome)
assert result.new_status == PlacementStatus::Alive
assert result.new_consecutive_misses == 0
assert result.trigger_repair == false
```

#### 8. `apply_pos_outcome_lost_is_noop_for_all_outcomes`

```
placement = lost_placement(consecutive_misses=0)
for outcome in [Pass, Fail{esi:0}, NotHeld{esi:0}, Timeout]:
    result = apply_pos_outcome(&placement, &outcome)
    assert result.new_status == PlacementStatus::Lost
    assert result.trigger_repair == false
```

#### 9. `apply_pos_outcome_deleting_is_noop_for_all_outcomes`

```
placement = deleting_placement(consecutive_misses=0)
for outcome in [Pass, Fail{esi:0}, Timeout]:
    result = apply_pos_outcome(&placement, &outcome)
    assert result.new_status == PlacementStatus::Deleting
    assert result.trigger_repair == false
```

#### 10. `outcome_from_verify_not_held_counts_as_challenged`

```
outcome = outcome_from_verify(&VerifyOutcome::NotHeld { esi: 3 }, week_number=7)
assert outcome.week_number == 7
assert outcome.challenged == 1
assert outcome.passed == 0
```

#### 11. `verify_outcome_enum_has_not_held_variant`

```
// Compile-time check that the variant exists and matches correctly
let o = VerifyOutcome::NotHeld { esi: 0 };
assert matches!(o, VerifyOutcome::NotHeld { .. })
```

### Message tests (in `messages/tests.rs`)

#### 12. `pos_nack_msg_roundtrip`

```
msg = PosNackMsg {
    v: 1,
    challenge_id: [0xAB; 16],
    source_block_id: SourceBlockId([1u8; 32]),
    esi: 42,
    timestamp: Timestamp(1_000_000),
}
encoded = to_cbor(&Message::PosNack(msg.clone())).unwrap()
decoded: Message = from_cbor(&encoded).unwrap()
assert matches!(decoded, Message::PosNack(m) if m == msg)
```

#### 13. `pos_nack_framing_roundtrip`

```
msg = Message::PosNack(PosNackMsg { ... })
framed = frame_message(&msg).unwrap()
(decoded, consumed) = unframe_message(&framed).unwrap()
assert decoded == msg
assert consumed == framed.len()
```

### RepairAgent tests (in `repair/tests.rs`)

Use real `Db::open_in_memory()`, real `RaptorQEncoder`, `tempfile::TempDir` for
`source_blocks_dir` and `symbols_dir`. Source block size: 1 symbol worth of data
(65535 bytes) to keep encoding fast.

#### 14. `repair_placement_generates_symbol_files`

```
db = Db::open_in_memory()
source_data = vec![0xABu8; 65535]  // exactly 1 symbol
block_id = SourceBlockId([1u8; 32])
holder = IdentityPub([2u8; 32])

// Write source block file
source_path = source_blocks_dir.join(hex(block_id))
std::fs::write(&source_path, &source_data).unwrap()

// Insert SourceBlockRecord
record = SourceBlockRecord { block_id, k: 1, t: 65535, ... }
db.upsert_source_block(&record).unwrap()

// Insert SymbolPlacement
placement = SymbolPlacement {
    source_block_id: block_id,
    holder_id: holder,
    esi_ranges: vec![(0, 1)],  // ESI 0, count 1
    status: PlacementStatus::Lost,
    consecutive_misses: 0,
    ...
}
db.upsert_placement(&placement).unwrap()

// Run repair
agent = RepairAgent::new(db.clone(), config, Arc::new(RaptorQEncoder::new()))
outcome = agent.repair_placement(&block_id, &holder).await.unwrap()
assert outcome.symbols_written == 1
assert outcome.new_status == PlacementStatus::Alive

// Symbol file must exist
sym_path = symbols_dir.join(hex(block_id)).join(hex(holder)).join("0.sym")
assert sym_path.exists()
sym_data = std::fs::read(&sym_path).unwrap()
assert sym_data.len() == 65535

// DB placement must be updated to Alive
updated = db.get_placement(&block_id, &holder).unwrap().unwrap()
assert updated.status == PlacementStatus::Alive
assert updated.consecutive_misses == 0
```

#### 15. `repair_placement_missing_source_block_returns_error`

```
// No source block file on disk
outcome = agent.repair_placement(&block_id, &holder).await
assert matches!(outcome, Err(RepairError::SourceBlockMissing(_)))
```

#### 16. `handle_symbol_dropped_transitions_to_lost`

```
// Placement is Alive
placement.status = PlacementStatus::Alive
db.upsert_placement(&placement).unwrap()

agent.handle_symbol_dropped(&block_id, &holder, now).await.unwrap()

updated = db.get_placement(&block_id, &holder).unwrap().unwrap()
assert updated.status == PlacementStatus::Lost
assert updated.consecutive_misses == 0
```

#### 17. `handle_pos_nack_transitions_to_lost`

```
// Placement is Alive
placement.status = PlacementStatus::Alive
db.upsert_placement(&placement).unwrap()

agent.handle_pos_nack(&block_id, &holder, now).await.unwrap()

updated = db.get_placement(&block_id, &holder).unwrap().unwrap()
assert updated.status == PlacementStatus::Lost
```

#### 18. `handle_symbol_dropped_then_pos_nack_is_idempotent`

```
// GATE test 2: SymbolDropped + PosNack in any order → same result
placement.status = PlacementStatus::Alive
db.upsert_placement(&placement).unwrap()

// First: SymbolDropped
agent.handle_symbol_dropped(&block_id, &holder, now).await.unwrap()
after_drop = db.get_placement(&block_id, &holder).unwrap().unwrap()
assert after_drop.status == PlacementStatus::Lost

// Second: PosNack (should be no-op)
agent.handle_pos_nack(&block_id, &holder, now).await.unwrap()
after_nack = db.get_placement(&block_id, &holder).unwrap().unwrap()
assert after_nack.status == PlacementStatus::Lost  // unchanged
```

#### 19. `handle_pos_nack_then_symbol_dropped_is_idempotent`

```
// GATE test 2 (reversed order)
placement.status = PlacementStatus::Alive
db.upsert_placement(&placement).unwrap()

agent.handle_pos_nack(&block_id, &holder, now).await.unwrap()
agent.handle_symbol_dropped(&block_id, &holder, now).await.unwrap()

final_placement = db.get_placement(&block_id, &holder).unwrap().unwrap()
assert final_placement.status == PlacementStatus::Lost
```

#### 20. `scan_and_repair_finds_lost_placement_and_repairs`

```
// Insert source block + file + placement with status=Lost
// Write source block file to disk
// Call scan_and_repair
count = agent.scan_and_repair().await
assert count == 1

// Verify placement now Alive and symbol file exists
updated = db.get_placement(&block_id, &holder).unwrap().unwrap()
assert updated.status == PlacementStatus::Alive
```

#### 21. `scan_and_repair_finds_presumed_lost_placement_and_repairs`

```
// Same as 20 but placement.status = PresumedLost, consecutive_misses = 3
count = agent.scan_and_repair().await
assert count == 1
updated.status == PlacementStatus::Alive
```

#### 22. `scan_and_repair_skips_alive_placements`

```
// Placement is Alive — no repair needed
placement.status = PlacementStatus::Alive
db.upsert_placement(&placement).unwrap()

count = agent.scan_and_repair().await
assert count == 0  // nothing to repair
```

#### 23. `gate_holder_evicts_pos_nack_owner_triggers_repair` (GATE test 1)

This is the full gate scenario:

```
// Setup
db = Db::open_in_memory()
block_id = SourceBlockId([42u8; 32])
holder = IdentityPub([7u8; 32])
source_data = vec![0xFFu8; 65535]

// 1. Simulate holder eviction: placement starts Alive
placement = SymbolPlacement {
    source_block_id: block_id,
    holder_id: holder,
    esi_ranges: vec![(0, 1)],
    status: PlacementStatus::Alive,
    consecutive_misses: 0,
    ...
}
db.upsert_placement(&placement).unwrap()
db.upsert_source_block(&source_block_record).unwrap()
write_source_file(&source_blocks_dir, &block_id, &source_data)

// 2. Holder sends PosNack (simulated by calling handle_pos_nack)
agent.handle_pos_nack(&block_id, &holder, now).await.unwrap()

// 3. Verify placement is Lost
check = db.get_placement(&block_id, &holder).unwrap().unwrap()
assert check.status == PlacementStatus::Lost

// 4. Owner triggers repair (scan_and_repair)
repaired = agent.scan_and_repair().await
assert repaired == 1

// 5. Verify: new symbol file exists, placement is Alive
sym_path = symbols_dir.join(hex(block_id)).join(hex(holder)).join("0.sym")
assert sym_path.exists()
final = db.get_placement(&block_id, &holder).unwrap().unwrap()
assert final.status == PlacementStatus::Alive
assert final.consecutive_misses == 0
```

---

## Module Structure

```
crates/syncback-core/src/pos/
  mod.rs    — add VerifyOutcome::NotHeld, PlacementTransition, apply_pos_outcome;
              update outcome_from_verify
  tests.rs  — test scenarios 1-11 (state machine + outcome tests)

crates/syncback-core/src/types/
  mod.rs    — add PlacementStatus::Uncertain, PresumedLost;
              add consecutive_misses to SymbolPlacement

crates/syncback-core/src/messages/
  mod.rs    — add PosNackMsg, Message::PosNack variant
  tests.rs  — test scenarios 12-13 (message roundtrip)

crates/syncback-core/src/db/
  mod.rs    — add list_placements_needing_repair()

crates/syncback-core/src/constants.rs
              — add POS_CONSECUTIVE_MISS_UNCERTAIN, POS_CONSECUTIVE_MISS_PRESUMED_LOST

crates/syncback/src/daemon/repair/
  mod.rs    — RepairAgent, RepairConfig, RepairJob, RepairOutcome, RepairError,
              RepairTrigger; all public functions
  tests.rs  — test scenarios 14-23
```

---

## Gate Criteria

Phase 2.5 is complete when both gates pass:

**GATE 1: holder evicts → PosNack → owner triggers repair**
- Test 23 passes.
- Steps: placement Alive → `handle_pos_nack` → placement Lost → `scan_and_repair` →
  placement Alive + symbol file on disk.

**GATE 2: SymbolDropped + PosNack in any order → same result (idempotent)**
- Tests 18 and 19 both pass.
- Both orderings: SymbolDropped-then-PosNack and PosNack-then-SymbolDropped produce
  identical final DB state (placement Lost after first message; no-op after second).

---

## Notes for Implementer

- `apply_pos_outcome` is a pure function (no DB, no async). It belongs in
  `syncback-core/src/pos/mod.rs`. The caller (daemon processor or RepairAgent) reads
  the placement, calls this function, applies the returned transition to the placement
  struct, and then writes back to DB. This keeps the state machine logic testable without
  a real DB.

- The `consecutive_misses` field has `#[serde(default)]` to survive deserialization of
  existing DB records that lack the field. Rust's ciborium CBOR decoder will use
  `Default::default()` (= 0) when the field is absent.

- For the RepairAgent, symbol file writes use `tokio::fs` for async I/O. The
  `encoder.encode(...)` call is CPU-bound; wrap it in `tokio::task::spawn_blocking` if
  it takes more than ~1 ms (for K=1 source blocks in tests it is fast; for K=2048 it is
  not). In Phase 2.5 tests use K=1 (65535 bytes source) to keep tests fast.

- `hex(bytes)` helper function: use `bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()`.
  This is the same pattern used in the existing `Display` impls in `types/mod.rs`. Add a
  free function `fn to_hex(bytes: &[u8]) -> String` in `repair/mod.rs` (do not import
  from types — types's Display only shows first 8 bytes).

- The RepairAgent in `run()` uses `tokio::time::interval` for the periodic scan and
  `tokio::select!` to also process immediate-trigger messages from `rx`. When `rx` is
  closed (all senders dropped), the loop exits gracefully.

- Do not add `repair` module to the daemon's main runtime in this phase. The RepairAgent
  is used directly in tests. Integration into the daemon's startup sequence is Phase 3.

- All tests use `#[tokio::test]`. Tests that don't need async (state machine tests in
  `pos/tests.rs`) are plain `#[test]`.

- DECISION NEEDED: should `handle_pos_nack` / `handle_symbol_dropped` directly call
  `scan_and_repair` for the specific placement, or only mark it Lost and let the periodic
  scan handle it? The spec above uses the "mark Lost, let scan handle it" approach. This
  avoids immediate re-encoding on every received message (which is correct for a cold
  backup system). If the user needs faster repair reaction, the `RepairTrigger::RepairNow`
  channel message can be used instead.
