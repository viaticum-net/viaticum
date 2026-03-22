# Task spec: repair module (Phase 3)

**Target files:**
- `crates/syncback/src/daemon/repair/mod.rs`
- `crates/syncback/src/daemon/repair/tests.rs`

**Phase:** 3
**Role:** Owner-side repair orchestration — detect under-replicated units, reconstruct
missing shards via network download or local plaintext, re-upload to new holders.

---

## Overview

The repair module is a thin orchestration layer that fills the Phase 2 gap in
`run_repair_check` inside the Processor. In Phase 2, `repair_unit(unit_id, None, now)`
returns `Err(PlaintextNotAvailable)` and the processor logs "need restore flow (Phase 3)".

In Phase 3, the `RepairEngine` handles that case:

1. Downloads k shards from live holders via iroh-blobs
2. Decodes them with Reed-Solomon to recover the unit plaintext
3. Decrypts the plaintext (ChaCha20-Poly1305)
4. Passes plaintext to `shard_manager.repair_unit(unit_id, Some(&plaintext), now)`
   which then re-encodes and re-uploads missing shards to new holders

The module also enforces a **rate limit** so a daemon with many under-replicated units
does not flood the network with repair offers in a single repair cycle.

**What this module does NOT do:**
- It does not detect under-replicated units — that is `shard_manager.find_under_replicated_units()`
- It does not send shard_offers or track shard status — that is `ShardManager.repair_unit()`
- It is not a tokio task — it is a struct with methods, called from Processor

---

## Where it fits in the processor

In Phase 2, `processor::run_repair_check` looks like this (simplified):

```rust
async fn run_repair_check(&mut self) {
    let under_replicated = self.shard_manager.find_under_replicated_units()?;

    for unit_id in under_replicated {
        match self.shard_manager.repair_unit(unit_id, None, now).await {
            Ok(n) => { /* log */ }
            Err(ShardManagerError::PlaintextNotAvailable) => {
                // Phase 2 stub: "need restore flow (Phase 3)"
            }
            // ...
        }
    }
}
```

In Phase 3, the processor replaces the `PlaintextNotAvailable` branch with a call to
`RepairEngine`:

```rust
Err(ShardManagerError::PlaintextNotAvailable) => {
    self.repair_engine.queue_for_restore(unit_id);
}
```

And at the end of `run_repair_check` (or as a separate `RepairEngine::run_pending`
call), the repair engine processes the queue:

```rust
self.repair_engine.run_pending(&self.shard_manager, &self.db, now, net_cmd_tx).await;
```

The processor owns `RepairEngine` alongside `ShardManager`.

---

## Dependencies

**Same crate (syncback):**
- `daemon::shard_manager::{ShardManager, ShardManagerError}`
- `daemon::NetCommand` — for sending `DownloadShard` requests

**syncback-core:**
- `db::Db` — read `shards`, `units`, `peers` tables
- `types::{UnitId, ShardId, ShardRecord, ShardStatus, UnitRecord, IdentityPub, Timestamp}`
- `constants::SECS_PER_WEEK`

**External (already in Cargo.toml):**
- `reed_solomon_erasure::galois_8::ReedSolomon` — decode shards back to plaintext
- `chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, NewAead}}` — decrypt
- `tokio::sync::mpsc::Sender<NetCommand>` — request shard downloads

---

## Public API

```rust
pub struct RepairEngine {
    db: syncback_core::db::Db,
    // Units queued for full restore-and-repair (plaintext not locally available)
    pending: std::collections::VecDeque<UnitId>,
    // Count of shard offers sent this repair cycle (rate limit enforcement)
    offers_this_cycle: usize,
}

impl RepairEngine {
    pub fn new(db: syncback_core::db::Db) -> Self;

    /// Called from Processor when repair_unit returns PlaintextNotAvailable.
    /// Adds the unit to the pending queue for restore-and-repair.
    /// Deduplicates: if unit_id is already queued, does nothing.
    pub fn queue_for_restore(&mut self, unit_id: UnitId);

    /// Process pending units from the queue.
    ///
    /// For each pending unit (up to MAX_REPAIRS_PER_CYCLE):
    ///   1. Look up unit record. Skip if unit no longer exists or status != Active.
    ///   2. Download k shards from live holders (see "Shard download" below).
    ///   3. RS-decode to ciphertext, decrypt to plaintext.
    ///   4. Call shard_manager.repair_unit(unit_id, Some(&plaintext), now).await.
    ///   5. Remove from queue if repair was submitted (even if not yet confirmed stored).
    ///
    /// Rate limit: stop submitting new repair offers after MAX_REPAIR_OFFERS_PER_CYCLE
    /// total offers across all units in this run.
    ///
    /// Expected errors (log info, skip unit, keep in queue for next cycle):
    ///   - NotEnoughLiveHolders: fewer than k shards are in Stored status
    ///   - DownloadFailed: network could not deliver all k shards within timeout
    ///   - NotEnoughPeers: placement has no peers for re-upload
    ///
    /// Panics on DB errors (alpha error strategy).
    pub async fn run_pending(
        &mut self,
        shard_manager: &crate::daemon::shard_manager::ShardManager,
        now: syncback_core::types::Timestamp,
        net_cmd_tx: &tokio::sync::mpsc::Sender<crate::daemon::NetCommand>,
    ) -> RepairSummary;

    /// Reset per-cycle counters. Called by Processor at the start of each repair check.
    pub fn reset_cycle(&mut self);

    /// Returns how many units are currently waiting for restore-and-repair.
    pub fn pending_count(&self) -> usize;
}
```

---

## Supporting types

```rust
#[derive(Debug, Clone, Default)]
pub struct RepairSummary {
    /// Units for which repair offers were successfully submitted.
    pub units_repaired: usize,
    /// Units skipped because fewer than k shards were available online.
    pub units_skipped_not_enough_shards: usize,
    /// Units skipped because placement had no available peers.
    pub units_skipped_no_peers: usize,
    /// Units skipped because the rate limit was reached.
    pub units_skipped_rate_limited: usize,
    /// Total shard re-upload offers sent this cycle.
    pub shards_offered: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("not enough live holders: need {need}, have {have}")]
    NotEnoughLiveHolders { need: usize, have: usize },

    #[error("shard download failed: {0}")]
    DownloadFailed(String),

    #[error("reed-solomon decode error: {0}")]
    ReedSolomon(String),

    #[error("decryption error: {0}")]
    Decryption(String),

    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),
}
```

---

## Constants

```rust
/// Maximum number of units repaired per repair_check cycle.
/// Cold backup: time constant = 1 week. No urgency to repair everything at once.
const MAX_REPAIRS_PER_CYCLE: usize = 10;

/// Maximum total shard re-upload offers per repair_check cycle.
/// Prevents flooding the network boards with offers.
/// At 10 shards/unit (mid tier), 10 units = up to 100 offers — this cap is 50.
const MAX_REPAIR_OFFERS_PER_CYCLE: usize = 50;
```

These constants should be in `repair/mod.rs`, not in `constants.rs` — they are
implementation details, not protocol constants.

---

## Shard download flow

The `run_pending` method needs to fetch k shard blobs from live holders. This is the
restore flow applied to repair.

### Step 1: Identify live holders

```rust
let shards: Vec<ShardRecord> = db.list_shards_for_unit(&unit_id)?;
let unit: UnitRecord = db.get_unit(&unit_id)?.expect("unit must exist");
let k = unit.rs_k as usize;
let n = unit.rs_n as usize;

let live_shards: Vec<&ShardRecord> = shards
    .iter()
    .filter(|s| s.status == ShardStatus::Stored)
    .collect();

if live_shards.len() < k {
    return Err(RepairError::NotEnoughLiveHolders {
        need: k,
        have: live_shards.len(),
    });
}
```

### Step 2: Request shard downloads

Send `NetCommand::DownloadShard` for each of the k shards. Wait for responses via a
`tokio::sync::oneshot` or pre-allocated response channel.

**New NetCommand variant required:**

```rust
// In daemon/mod.rs, add to NetCommand enum:
DownloadShard {
    shard_id: syncback_core::types::ShardId,
    holder: syncback_core::types::IdentityPub,
    /// Channel to receive the downloaded blob bytes (or error message).
    reply: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
},
```

The network task, on receiving `DownloadShard`, connects to the holder via iroh-blobs
and delivers the blob. The holder already serves blobs via the restore flow.

**In `run_pending`, collect k shard blobs:**

```rust
let mut shard_bytes: Vec<Option<Vec<u8>>> = vec![None; n];

// Pick first k live shards (sorted by trust descending for reliability).
for shard_record in live_shards.iter().take(k) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    net_cmd_tx
        .send(NetCommand::DownloadShard {
            shard_id: shard_record.shard_id,
            holder: shard_record.holder_id,
            reply: tx,
        })
        .await
        .expect("net channel closed");

    match tokio::time::timeout(DOWNLOAD_TIMEOUT, rx).await {
        Ok(Ok(Ok(data))) => {
            shard_bytes[shard_record.shard_index as usize] = Some(data);
        }
        Ok(Ok(Err(e))) => {
            tracing::debug!(
                shard = %shard_record.shard_id,
                error = e,
                "repair: shard download failed"
            );
        }
        Ok(Err(_)) => {
            tracing::debug!(shard = %shard_record.shard_id, "repair: download reply channel closed");
        }
        Err(_) => {
            tracing::debug!(shard = %shard_record.shard_id, "repair: download timeout");
        }
    }
}

let downloaded = shard_bytes.iter().filter(|s| s.is_some()).count();
if downloaded < k {
    return Err(RepairError::NotEnoughLiveHolders { need: k, have: downloaded });
}
```

**Timeout constant:**

```rust
/// Per-shard download timeout during repair.
/// Generous because this is cold backup and holders may be on slow connections.
const DOWNLOAD_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(300); // 5 minutes
```

### Step 3: Reed-Solomon decode

After collecting k shard blobs, decode back to ciphertext:

```rust
fn rs_decode(
    shard_bytes: Vec<Option<Vec<u8>>>,
    k: usize,
    n: usize,
) -> Result<Vec<u8>, RepairError> {
    use reed_solomon_erasure::galois_8::ReedSolomon;

    let r = ReedSolomon::new(k, n - k)
        .map_err(|e| RepairError::ReedSolomon(e.to_string()))?;

    // Convert Option<Vec<u8>> to Option<Vec<u8>> format expected by crate.
    let mut shards: Vec<Option<Vec<u8>>> = shard_bytes;

    // Reconstruct missing shards.
    r.reconstruct(&mut shards)
        .map_err(|e| RepairError::ReedSolomon(e.to_string()))?;

    // Concatenate data shards (first k) to recover ciphertext.
    let mut ciphertext = Vec::new();
    for shard in shards.into_iter().take(k) {
        ciphertext.extend_from_slice(&shard.expect("reconstruct filled all shards"));
    }

    Ok(ciphertext)
}
```

Note: `reed-solomon-erasure` crate's `reconstruct` method takes `&mut [Option<Vec<u8>>]`
and fills in missing shards. Missing shards must be `None`, present shards must be `Some`.

### Step 4: Decrypt

```rust
fn decrypt_ciphertext(
    key: &[u8; 32],
    ciphertext_with_nonce: &[u8],
) -> Result<Vec<u8>, RepairError> {
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, NewAead}};

    if ciphertext_with_nonce.len() < 12 {
        return Err(RepairError::Decryption("ciphertext too short".to_string()));
    }
    let nonce_bytes: [u8; 12] = ciphertext_with_nonce[..12]
        .try_into()
        .expect("slice length is 12");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(nonce, &ciphertext_with_nonce[12..])
        .map_err(|e| RepairError::Decryption(e.to_string()))
}
```

### Step 5: Call shard_manager.repair_unit

```rust
let plaintext = decrypt_ciphertext(&key, &ciphertext)?;
match shard_manager.repair_unit(unit_id, Some(&plaintext), now).await {
    Ok(n_offers) => {
        summary.units_repaired += 1;
        summary.shards_offered += n_offers;
        self.offers_this_cycle += n_offers;
    }
    Err(ShardManagerError::NotEnoughPeers { need, have }) => {
        tracing::info!(unit = %unit_id, need, have, "repair: not enough peers, retry next cycle");
        summary.units_skipped_no_peers += 1;
        // Keep in queue for next cycle.
        self.pending.push_back(unit_id);
    }
    Err(e) => panic!("repair_unit unexpected error: {e}"),
}
```

---

## Integration with Processor

### Changes to `daemon/mod.rs`

Add `DownloadShard` to `NetCommand`:

```rust
pub enum NetCommand {
    // ... existing variants ...

    /// Download a shard blob from a holder peer via iroh-blobs.
    /// reply receives Ok(blob_bytes) on success, Err(message) on failure.
    DownloadShard {
        shard_id: syncback_core::types::ShardId,
        holder: syncback_core::types::IdentityPub,
        reply: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
    },
}
```

### Changes to `daemon/mod.rs` (module declaration)

```rust
// Add in daemon/mod.rs:
pub(crate) mod repair;
```

### Changes to `daemon/processor/mod.rs`

1. Add `repair_engine: RepairEngine` to `Processor` struct.
2. Construct it in `run()`: `let repair_engine = RepairEngine::new(db.clone());`
3. Update `run_repair_check` to use it:

```rust
async fn run_repair_check(&mut self) {
    let now = Timestamp::now();

    self.repair_engine.reset_cycle();

    let under_replicated = self
        .shard_manager
        .find_under_replicated_units()
        .expect("find_under_replicated_units failed");

    tracing::info!(count = under_replicated.len(), "repair check: under-replicated units");

    for unit_id in under_replicated {
        match self.shard_manager.repair_unit(unit_id, None, now).await {
            Ok(n) => {
                tracing::info!(unit = %unit_id, shards = n, "repair: repaired from local plaintext");
            }
            Err(ShardManagerError::PlaintextNotAvailable) => {
                // Phase 3: queue for restore-and-repair.
                self.repair_engine.queue_for_restore(unit_id);
            }
            Err(ShardManagerError::NotEnoughPeers { need, have }) => {
                tracing::info!(
                    unit = %unit_id, need, have,
                    "repair: not enough peers, retry next week"
                );
            }
            Err(e) => panic!("repair_unit unexpected error: {e}"),
        }
    }

    // Process units that need network restore.
    let summary = self
        .repair_engine
        .run_pending(&self.shard_manager, now, &self.net_cmd_tx)
        .await;

    tracing::info!(
        repaired = summary.units_repaired,
        skipped_shards = summary.units_skipped_not_enough_shards,
        skipped_peers = summary.units_skipped_no_peers,
        rate_limited = summary.units_skipped_rate_limited,
        offers_sent = summary.shards_offered,
        "repair check: complete"
    );

    self.db
        .set_schedule(&ScheduleRecord {
            task_name: "repair_check".to_string(),
            last_run: Some(now),
            next_run: Timestamp(now.0 + SECS_PER_WEEK),
        })
        .expect("set_schedule failed");
}
```

### Changes to `daemon/network.rs`

Add handling for `NetCommand::DownloadShard` in the network task's command loop:

```rust
NetCommand::DownloadShard { shard_id, holder, reply } => {
    // Connect to holder and download blob via iroh-blobs.
    // On success: reply.send(Ok(blob_bytes))
    // On failure: reply.send(Err(message))
    // Implementation uses the same iroh-blobs pull mechanism as the restore flow.
    self.handle_download_shard(shard_id, holder, reply).await;
}
```

The network module already has blob transfer infrastructure from Phase 2. Adding
`handle_download_shard` mirrors the existing `handle_upload_shard` in reverse.

DECISION NEEDED: The Phase 2 network module may not have implemented blob download
(only upload was needed for Phase 2). Check `network.rs` for existing download
infrastructure. If missing, the implementer must add:
- `iroh-blobs` client-side `BlobsClient::download` call (or equivalent iroh 0.96 API)
- Connection establishment to holder using their `IdentityPub` → lookup `PeerRecord.node_id`
  → convert to iroh `NodeAddr`

---

## DB operations

All DB reads, no writes. Repair never updates DB directly — that is done by
`ShardManager` when repair offers are confirmed via `shard_stored` messages.

| Operation | DB method | When |
|---|---|---|
| Get unit record | `db.get_unit(&unit_id)` | Before attempting restore |
| List shards for unit | `db.list_shards_for_unit(&unit_id)` | Find live holders |
| Get peer record | `db.get_peer(&holder_id)` | Look up NodeAddr for download |

**RepairEngine does not write to DB.** All status updates happen through the
existing `ShardManager` event handlers (`handle_shard_stored`, `handle_shard_reject`
etc.) when the re-uploaded shards are confirmed by holders.

---

## Business rules

### Under-replication criteria (from shard_manager — not re-implemented here)

A unit is under-replicated when `stored_count < rs_n` AND `stored_count >= rs_k`.
A unit with `stored_count < rs_k` is unrecoverable — repair engine never receives it
because `find_under_replicated_units` excludes those units (logs ERROR separately).

### When to use local plaintext vs network restore

The Packer module (Phase 3) provides plaintext to `shard_manager.repair_unit(unit_id, Some(plaintext), now)` when it can reconstruct the unit from local files. The Processor calls Packer to attempt this first. If Packer cannot reconstruct (files deleted, moved, pack vs individual), Processor calls `shard_manager.repair_unit(unit_id, None, now)` which returns `PlaintextNotAvailable`, and the repair engine handles the network path.

This decision tree lives in the Processor, not RepairEngine. RepairEngine only handles
the network-restore path.

### Rate limiting — justification

Cold backup has a time constant of 1 week. If 50 units are under-replicated, sending
750 repair offers simultaneously would spike network board traffic well above the normal
50 offers/week baseline. The rate limit (MAX_REPAIRS_PER_CYCLE=10 units,
MAX_REPAIR_OFFERS_PER_CYCLE=50 offers) spreads repair over multiple weekly cycles.

Prioritization within the queue: process in FIFO order (VecDeque). Future improvement:
sort by importance descending (process high-importance units first).

DECISION NEEDED: Should `pending` queue be sorted by unit importance before each
`run_pending` call? The protocol says importance is owner's decision, and data loss risk
is equal for all under-replicated units (stored_count >= k for all of them). For MVP:
FIFO is acceptable. The implementer may add importance-based sorting as a bonus.

### Deduplication in queue

`queue_for_restore` must not add the same `UnitId` twice. Use a `HashSet` as a
companion to `VecDeque`:

```rust
pub struct RepairEngine {
    db: syncback_core::db::Db,
    pending: std::collections::VecDeque<UnitId>,
    pending_set: std::collections::HashSet<UnitId>,
    offers_this_cycle: usize,
}
```

On `queue_for_restore`:
```rust
if self.pending_set.insert(unit_id) {
    self.pending.push_back(unit_id);
}
```

On completing a unit (either repaired or definitively failed), remove from `pending_set`.

### Retry semantics

- On `NotEnoughLiveHolders`: keep in queue, try next cycle (holders may come online).
- On `DownloadFailed` (partial): keep in queue.
- On `NotEnoughPeers` (for re-upload): keep in queue.
- On successful `repair_unit` call: remove from queue. The unit remains under-replicated
  until shard_stored confirmations arrive, but the repair offers are in flight.
  The next `find_under_replicated_units` scan will re-detect it if offers expire.

### shard_drop_notice integration

When a holder sends `shard_drop_notice` (7-day warning before eviction), the processor's
existing `handle_net_event` path marks the shard status as `DropNotice` (or similar).
The `find_under_replicated_units` call should treat shards in `DropNotice` state as
effectively lost for repair purposes — initiate repair before the 7-day window closes.

DECISION NEEDED: Does `find_under_replicated_units` in shard_manager currently treat
`ShardStatus::DropNotice` as "not Stored"? Check `shard_manager.rs`:

```rust
let stored_count = shards
    .iter()
    .filter(|s| s.status == ShardStatus::Stored)  // only Stored counts!
    .count();
```

If `DropNotice` is not a variant of `ShardStatus`, shard_drop_notice handling in the
processor currently just marks the shard as `Lost`. Verify: look up how processor
handles `ShardDropNoticeMsg` in `net_event` dispatch.

If `DropNotice` status exists and `find_under_replicated_units` treats it as Stored
(wrong), the implementer must fix the filter. Protocol intent: start repair when a
drop notice arrives, not only after the shard is gone.

---

## File layout

```
crates/syncback/src/daemon/
  repair/
    mod.rs      — RepairEngine, RepairError, RepairSummary, constants, rs_decode, decrypt_ciphertext
    tests.rs    — unit and integration tests
```

Add to `daemon/mod.rs`:
```rust
pub(crate) mod repair;
```

Tests in `tests.rs` (separate file per project convention), not inline in `mod.rs`.

---

## Test scenarios

All tests are in `crates/syncback/src/daemon/repair/tests.rs`.

### `queue_for_restore_deduplicates`

```
Setup:
  let db = test_db();
  let mut engine = RepairEngine::new(db);
  let unit_id = test_unit_id();

Action:
  engine.queue_for_restore(unit_id);
  engine.queue_for_restore(unit_id);  // duplicate

Expected:
  engine.pending_count() == 1
```

### `queue_and_pending_count`

```
Setup:
  RepairEngine::new(test_db())

Action:
  engine.queue_for_restore(unit_id_a);
  engine.queue_for_restore(unit_id_b);

Expected:
  engine.pending_count() == 2
```

### `reset_cycle_clears_offer_counter`

```
Setup:
  RepairEngine with offers_this_cycle = 40 (set via run_pending in test)

Action:
  engine.reset_cycle()

Expected:
  engine.offers_this_cycle == 0
```

### `rs_decode_roundtrip`

```
// Verify encode->partial_erase->decode recovers original data.
// Use the same parameters as shard_manager encode to confirm compatibility.

let plaintext = vec![42u8; 5 * 1024];
let k = 5usize;
let n = 7usize;

// Encode with ReedSolomon.
let r = ReedSolomon::new(k, n - k).unwrap();
let shard_size = plaintext.len() / k;
let mut shards: Vec<Option<Vec<u8>>> = plaintext
    .chunks(shard_size)
    .map(|c| Some(c.to_vec()))
    .collect();
for _ in 0..(n - k) {
    shards.push(Some(vec![0u8; shard_size]));
}
// Convert to mutable for encode.
let mut enc_shards: Vec<Vec<u8>> = shards.iter().map(|s| s.clone().unwrap()).collect();
r.encode(&mut enc_shards).unwrap();
let encoded: Vec<Option<Vec<u8>>> = enc_shards.into_iter().map(Some).collect();

// Erase shards 0 and 3.
let mut to_decode = encoded.clone();
to_decode[0] = None;
to_decode[3] = None;

// Reconstruct.
r.reconstruct(&mut to_decode).unwrap();

// Concatenate first k shards.
let mut recovered = Vec::new();
for i in 0..k {
    recovered.extend_from_slice(&to_decode[i].as_ref().unwrap());
}
assert_eq!(&recovered[..plaintext.len()], &plaintext[..]);
```

### `decrypt_after_encrypt_roundtrip`

```
// Verify that decrypt_ciphertext reverses the same encryption used in shard_manager.

let key = [7u8; 32];
let plaintext = b"cold backup test data";

// Encrypt (replicate shard_manager logic).
let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
let nonce_bytes = [0u8; 12];  // zero nonce for determinism in test
let nonce = Nonce::from_slice(&nonce_bytes);
let mut ciphertext_with_nonce = nonce_bytes.to_vec();
ciphertext_with_nonce.extend_from_slice(
    &cipher.encrypt(nonce, plaintext.as_ref()).unwrap()
);

// Decrypt via repair helper.
let decrypted = decrypt_ciphertext(&key, &ciphertext_with_nonce).unwrap();
assert_eq!(decrypted, plaintext);
```

### `run_pending_skips_unit_when_no_live_shards`

```
Setup:
  DB with UnitRecord (rs_k=5, rs_n=7, status=Active).
  7 ShardRecords for the unit, all with status=Lost (no live holders).
  RepairEngine with the unit queued.

Action:
  engine.run_pending(&shard_manager, now, &net_cmd_tx).await

Expected:
  summary.units_skipped_not_enough_shards == 1
  summary.units_repaired == 0
  engine.pending_count() == 1  // unit stays in queue for retry
```

Note: this test does not need a real iroh network — the check happens before any
network call. Use a mock `net_cmd_tx` (mpsc channel that is never read) and a real
`shard_manager` backed by the test DB.

### `run_pending_respects_rate_limit`

```
Setup:
  20 units in the pending queue.
  Each unit has rs_k=5, rs_n=7, 5 shards with status=Stored.
  (Simulate successful download by pre-populating test data such that the download
   oneshot channels receive Ok(data).)

  MAX_REPAIRS_PER_CYCLE = 10 (the constant).

Action:
  engine.run_pending(...)

Expected:
  summary.units_repaired + summary.units_skipped_* <= MAX_REPAIRS_PER_CYCLE
  summary.units_skipped_rate_limited >= 10
  engine.pending_count() >= 10  // remaining units stay in queue
```

Note: This test verifies the cap, not the download. Simplification: have all 20 units
return `NotEnoughLiveHolders` (0 Stored shards) so the test does not need network.
Check only that at most 10 units are processed and the rest are rate-limited.

### `run_pending_removes_unit_on_success`

```
Setup:
  1 unit in pending queue, rs_k=5, rs_n=7.
  5 ShardRecords with status=Stored.
  Shard manager configured with enough test peers for placement.

  Simulate downloads: pre-populate 5 shard blobs that when RS-decoded and decrypted
  produce valid plaintext. (Use a deterministic key and known plaintext in test.)

Expected:
  summary.units_repaired == 1
  engine.pending_count() == 0  // removed from queue
```

Note: This is the hardest test to write because it requires:
- A real `ShardManager` with test DB and test identity key
- Enough peers in DB for placement (≥ 7 for Low tier)
- Pre-computed shard blobs that decode correctly
- A working `net_cmd_tx`/`net_cmd_rx` pair for reading `DownloadShard` commands and
  replying with blob data

Consider this an integration test rather than a unit test. It can live in
`crates/syncback/tests/` instead of `repair/tests.rs` if it requires full daemon
infrastructure.

### `integration: repair_after_holder_disconnect`

This is one of the Phase 2 gate tests (`gate_tests.rs`). Phase 3 enhances it:

```
// Already exists in gate_tests.rs (Phase 2 version).
// The Phase 2 version tests find_under_replicated → repair_unit(plaintext=None) → PlaintextNotAvailable.
// Phase 3 version tests the full loop:
//   mark shards Lost → find_under_replicated → repair_unit(plaintext=None) →
//   queue_for_restore → run_pending → download k shards → rs_decode → decrypt →
//   repair_unit(plaintext=Some(...)) → shard offers sent

// This requires two iroh nodes. One acts as holder, serves k shard blobs.
// Owner node runs repair_engine.run_pending().
// Verify: repair offers are sent for the missing shards.
```

This integration test is in `crates/syncback/tests/` (or `gate_tests.rs`), not in
`repair/tests.rs`. It requires the full Phase 3 setup.

---

## Logging

```rust
// INFO: key events (~1-2 per repair cycle)
tracing::info!(count = pending.len(), "repair: processing pending units");
tracing::info!(
    unit = %unit_id, shards = n_offers,
    "repair: offers sent for under-replicated unit"
);

// DEBUG: per-unit decisions
tracing::debug!(unit = %unit_id, "repair: queued for restore-and-repair");
tracing::debug!(
    unit = %unit_id, have = downloaded, need = k,
    "repair: not enough live shards for restore, deferring"
);
tracing::debug!(
    unit = %unit_id,
    "repair: rate limit reached, stopping for this cycle"
);

// DEBUG: per-shard download
tracing::debug!(
    shard = %shard_id, holder = %holder_id,
    "repair: downloading shard for restore"
);
```

No WARN level (alpha convention from ADR-003).

---

## Notes for implementer

1. **`NetCommand::DownloadShard` must be added** — this is a new variant not in the
   Phase 2 code. Add it to `daemon/mod.rs` `NetCommand` enum, and handle it in
   `daemon/network.rs`. The handler connects to the holder via iroh and downloads
   the blob. The holder serves blobs via the existing restore flow.

2. **Holder blob serving** — the holder's `Storage` module (Phase 2) already stores
   shard blobs on disk at `shards/{shard_id_hex}`. The network module needs to serve
   these blobs on iroh-blobs pull requests. Check `network.rs` Phase 2 implementation
   for existing blob serving infrastructure.

3. **`rs_decode` uses the same RS parameters** as `shard_manager::encode_unit`. The
   shard size and padding must match exactly. The easiest approach: expose
   `encode_unit` and `decode_unit` as `pub(crate)` helpers in `shard_manager/mod.rs`
   and re-use them from `repair/mod.rs`. This avoids re-implementing RS logic.

4. **Decryption key** — use `shard_manager.derive_unit_key(unit_id)` to get the
   decryption key. `RepairEngine` needs access to `ShardManager` for this. The
   `run_pending` signature already takes `&ShardManager`.

5. **Hold plaintext only briefly** — the decrypted plaintext is passed to
   `shard_manager.repair_unit` and then dropped. Do not store plaintext in `RepairEngine`.

6. **Shard index for download** — when downloading k shards for RS decode, you must
   track which shard index each downloaded blob corresponds to (so the RS decoder knows
   which positions are present). Use `shard_record.shard_index` to populate the
   `Vec<Option<Vec<u8>>>` at the correct index.

7. **Test helper for unit + shards** — add `test_unit_record(rs_k, rs_n)` and
   `test_shard_record(unit_id, shard_index, holder, status)` helpers to `repair/tests.rs`
   (or reuse from `testutil.rs` if they exist).

8. **`UnitId: Hash`** — verify that `UnitId` derives `Hash` and `Eq` (needed for
   `HashSet<UnitId>`). Check `types/mod.rs`. If not, add derives. Both `PartialEq` and
   `Hash` are already derived on `UnitId` per the spec.

9. **Phase 3 packer integration** — this spec assumes the Packer module is also
   implemented in Phase 3. The `run_repair_check` flow should attempt Packer-provided
   plaintext first:
   ```rust
   let plaintext = packer.try_reconstruct_unit(unit_id);
   match shard_manager.repair_unit(unit_id, plaintext.as_deref(), now).await {
       Err(ShardManagerError::PlaintextNotAvailable) => {
           repair_engine.queue_for_restore(unit_id);
       }
       // ...
   }
   ```
   If Packer is implemented before or alongside Repair, integrate at that point.
   If Repair is implemented first (without Packer), the `None` path runs exclusively
   and all repair goes through the network restore path.

10. **`DownloadShard` vs iroh-blobs pull semantics** — in iroh-blobs, the client
    pulls from the provider using the blob hash (`shard_id` is the BLAKE3 hash of the
    blob content). The network task needs the holder's NodeAddr to establish a
    connection. Get it from `db.get_peer(&holder_id)?.node_id` → convert to
    `iroh::NodeAddr`. If the peer record has no NodeAddr (peer never announced), skip
    and try next live shard holder.
