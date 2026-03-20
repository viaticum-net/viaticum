# Task spec: shard_manager module (Phase 2)

**Target file:** `crates/syncback/src/daemon/shard_manager.rs`
**Phase:** 2
**Role:** Owner — encrypt→erasure→place→upload pipeline, repair flow

---

## Overview

`ShardManager` is the **owner-role** module. Given a plaintext unit (from Packer in Phase 3,
or a raw byte slice for testing), it:

1. Derives the encryption key using HKDF-SHA256 from the identity private key and unit_id
2. Encrypts the unit with ChaCha20-Poly1305
3. Splits the ciphertext into Reed-Solomon shards
4. Computes the BLAKE3 Merkle root for each shard (for PoS)
5. Selects holders via `PlacementEngine`
6. Sends `shard_offer` messages to each selected holder (via `NetCommand::PublishBoard`)
7. Tracks placement state in DB (shard records, offered → accepted → stored)
8. Handles repair: detect under-replicated units, restore missing shards, re-upload

`ShardManager` is **not a tokio task**. It is called from Processor synchronously within
the Processor's async context. Network operations (sending shard blob) go through
`NetCommand` channel.

Phase 3 note: the Packer module will call `shard_manager.pack_unit(files)` to produce the
plaintext unit bytes. In Phase 2, the interface accepts raw plaintext bytes directly
(Packer is a Phase 3 module, spec not written yet). All shard_manager methods that need
unit plaintext take `&[u8]`.

---

## Dependencies

**syncback-core:**
- `db::Db` — CRUD on `shards`, `units` tables
- `types::{ShardId, UnitId, IdentityPub, ShardRecord, ShardStatus, UnitRecord, UnitStatus, Timestamp, ErasureTier, FileType}`
- `messages::{ShardDescriptor, ShardDescriptorUnsigned, ShardOfferMsg, MsgId, to_cbor, encrypt_payload}`
- `placement::{PlacementEngine, PlacementPlan, PlacementError}`
- `trust::TrustEngine`
- `budget::BudgetPlanner`

**External crates (in syncback crate):**
- `reed_solomon_erasure::galois_8::ReedSolomon` — erasure coding
- `chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, NewAead}}` — encryption
- `hkdf::Hkdf` — key derivation
- `sha2::Sha256` — HKDF hash function
- `blake3` — shard ID (content hash) + Merkle tree
- `ed25519_dalek::SigningKey` — signing ShardDescriptors

**tokio:**
- `tokio::sync::mpsc::Sender<NetCommand>` — for sending network commands

---

## Public API

```rust
pub struct ShardManager {
    db: syncback_core::db::Db,
    placement: syncback_core::placement::PlacementEngine,
    budget: syncback_core::budget::BudgetPlanner,
    identity_key: ed25519_dalek::SigningKey,
    identity_pub: syncback_core::types::IdentityPub,
    net_tx: tokio::sync::mpsc::Sender<crate::daemon::NetCommand>,
}

impl ShardManager {
    pub fn new(
        db: syncback_core::db::Db,
        placement: syncback_core::placement::PlacementEngine,
        budget: syncback_core::budget::BudgetPlanner,
        identity_key: ed25519_dalek::SigningKey,
        identity_pub: syncback_core::types::IdentityPub,
        net_tx: tokio::sync::mpsc::Sender<crate::daemon::NetCommand>,
    ) -> Self;

    // -------------------------------------------------------------------------
    // Main pipeline: unit → shards → upload
    // -------------------------------------------------------------------------

    /// Encrypt, erasure-code, and upload a unit.
    ///
    /// Steps:
    ///   1. Derive encryption key: HKDF-SHA256(identity_priv, salt=unit_id, info="syncback-file-encryption")
    ///   2. Encrypt plaintext → ciphertext (ChaCha20-Poly1305, random nonce prepended)
    ///   3. Determine erasure tier from importance
    ///   4. Split ciphertext into k data shards + (n-k) parity shards via Reed-Solomon
    ///   5. For each shard: compute shard_id = blake3(shard_bytes), build Merkle tree
    ///   6. Select n holders via PlacementEngine
    ///   7. For each holder: build signed ShardDescriptor, send shard_offer via board
    ///   8. Insert n ShardRecords in DB (status = Offered)
    ///
    /// Returns the list of (shard_id, holder) pairs (for logging and state tracking).
    ///
    /// Errors:
    ///   - PlacementError::NotEnoughPeers → Ok with partial list (caller logs and retries next week)
    ///   - RS encoding failure → panic (invariant violation, invalid k/n)
    pub async fn upload_unit(
        &self,
        unit_id: UnitId,
        unit_record: &UnitRecord,
        plaintext: &[u8],
        importance: f64,
        file_type: FileType,
        now: Timestamp,
    ) -> Result<Vec<(ShardId, IdentityPub)>, ShardManagerError>;

    // -------------------------------------------------------------------------
    // State updates (called from Processor on board message dispatch)
    // -------------------------------------------------------------------------

    /// Called when a shard_accept arrives for one of our shards.
    /// Sends the actual blob to the holder via NetCommand::UploadShard.
    /// Updates shard status: Offered → Accepted.
    pub async fn handle_shard_accept(
        &self,
        shard_id: ShardId,
        holder: IdentityPub,
        offer_msg_id: MsgId,
        now: Timestamp,
    ) -> Result<(), ShardManagerError>;

    /// Called when a shard_stored arrives (holder confirmed receipt).
    /// Updates shard status: Accepted → Stored.
    /// Updates budget placement stats.
    pub fn handle_shard_stored(
        &self,
        shard_id: ShardId,
        now: Timestamp,
    ) -> Result<(), ShardManagerError>;

    /// Called when a shard_reject arrives or offer TTL expires.
    /// Updates shard status: Offered/Accepted → Lost.
    pub fn handle_shard_reject(
        &self,
        shard_id: ShardId,
        now: Timestamp,
    ) -> Result<(), ShardManagerError>;

    /// Called when shard_dropped arrives (holder evicted our shard).
    /// Updates shard status: Stored → Lost.
    pub fn handle_shard_dropped(
        &self,
        shard_id: ShardId,
        now: Timestamp,
    ) -> Result<(), ShardManagerError>;

    // -------------------------------------------------------------------------
    // Repair flow (called from Processor on RepairCheck scheduled command)
    // -------------------------------------------------------------------------

    /// Scan all active units for under-replication.
    ///
    /// For each active unit: count shards with status == Stored.
    /// If count < unit.rs_k: data is unrecoverable (log ERROR, mark unit as Lost).
    /// If count < unit.rs_n but >= unit.rs_k: unit is under-replicated → trigger repair.
    ///
    /// Returns list of units that need repair.
    pub fn find_under_replicated_units(&self) -> Result<Vec<UnitId>, ShardManagerError>;

    /// Attempt to repair an under-replicated unit.
    ///
    /// Steps:
    ///   1. Collect Stored shard_ids for the unit
    ///   2. If we have the plaintext locally (unit files still intact) → re-encode from plaintext
    ///      Otherwise: download k shards, decode, re-encrypt
    ///      (In Phase 2: assume plaintext is NOT available; download path only)
    ///   3. Identify which shard_indices are missing (status != Stored)
    ///   4. Upload missing shards to new holders
    ///
    /// Phase 2 simplification: if unit plaintext is not available, this function returns
    /// Err(ShardManagerError::PlaintextNotAvailable). Caller (Processor) queues the unit
    /// for restore-and-reupload (full restore flow). Full repair via download is Phase 3.
    pub async fn repair_unit(
        &self,
        unit_id: UnitId,
        plaintext: Option<&[u8]>,  // Some if caller has plaintext from local files
        now: Timestamp,
    ) -> Result<usize, ShardManagerError>; // returns count of shards re-uploaded

    // -------------------------------------------------------------------------
    // Delete (called from Processor when file is deleted locally)
    // -------------------------------------------------------------------------

    /// Send delete messages to all holders of a unit's shards.
    /// Updates all shard statuses to Deleting.
    /// Owner cooldown: Processor waits 4 weeks before calling this.
    pub async fn delete_unit_shards(
        &self,
        unit_id: UnitId,
        now: Timestamp,
    ) -> Result<usize, ShardManagerError>; // returns count of delete messages sent

    // -------------------------------------------------------------------------
    // PoS challenge generation (called from Processor on PosRound scheduled command)
    // -------------------------------------------------------------------------

    /// Sample shards for PoS challenge.
    ///
    /// For each peer holding our shards: pick up to MAX_POS_CHALLENGES_PER_PEER random shards.
    /// Returns list of (shard_id, holder, block_index, nonce) tuples.
    /// Caller (Processor) sends NetCommand::SendPosChallenge for each.
    pub fn sample_pos_challenges(
        &self,
        now: Timestamp,
    ) -> Result<Vec<PosChallenge>, ShardManagerError>;

    /// Process a PoS response. Verify the proof against stored merkle_root.
    ///
    /// Steps:
    ///   1. Look up ShardRecord, get unit_id, then HoldingRecord (we don't hold it) —
    ///      actually look up the ShardRecord from owner's perspective.
    ///   2. Get merkle_root from the shard: look up unit → get shard descriptor info.
    ///      Problem: we don't store merkle_root in ShardRecord (owner view).
    ///      Resolution: store merkle_root in ShardRecord on creation. Add field.
    ///      (See "DB operations" section — ShardRecord needs merkle_root field.)
    ///   3. Verify: block_data_hash is proven by merkle_proof at block_index under merkle_root
    ///   4. If valid: update shard last_verified, update trust (record pos success)
    ///   5. If invalid: mark shard Lost, initiate repair
    ///
    /// Returns PoS outcome (pass/fail) for trust recording.
    pub fn handle_pos_response(
        &self,
        from: IdentityPub,
        shard_id: ShardId,
        block_index: u32,
        block_data_hash: [u8; 32],
        merkle_proof: Vec<[u8; 32]>,
        nonce: [u8; 32],
        now: Timestamp,
        current_week: u32,
    ) -> Result<PosResult, ShardManagerError>;

    // -------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------

    /// Return the current encryption key for a unit (for restore decryption).
    /// HKDF-SHA256(identity_priv, salt=unit_id, info="syncback-file-encryption") → 32 bytes
    pub fn derive_unit_key(&self, unit_id: UnitId) -> [u8; 32];

    /// Return the blob bytes for a specific shard_index from a stored unit.
    /// Used when the blob is in our local upload buffer (transient — Phase 2 simplification).
    /// Returns None if not in buffer.
    ///
    /// Note: shards are not stored locally after upload. This is only for the
    /// accept→upload window. The implementer must decide on the buffering strategy.
    /// See "Implementation notes" section.
    pub fn get_pending_blob(&self, shard_id: &ShardId) -> Option<Vec<u8>>;
}
```

---

## Supporting types

```rust
/// One PoS challenge to send to a holder.
#[derive(Debug, Clone)]
pub struct PosChallenge {
    pub shard_id: ShardId,
    pub holder: IdentityPub,
    pub block_index: u32,
    pub nonce: [u8; 32],
}

/// Result of verifying a PoS response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosResult {
    Pass,
    Fail,
}

#[derive(Debug, thiserror::Error)]
pub enum ShardManagerError {
    #[error("not enough peers for placement: need {need}, have {have}")]
    NotEnoughPeers { need: usize, have: usize },

    #[error("importance too low to back up: {0}")]
    ImportanceTooLow(f64),

    #[error("shard not found: {0:?}")]
    ShardNotFound(ShardId),

    #[error("unit not found: {0:?}")]
    UnitNotFound(UnitId),

    #[error("plaintext not available for repair (Phase 3 feature)")]
    PlaintextNotAvailable,

    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),

    #[error("placement error: {0}")]
    Placement(#[from] syncback_core::placement::PlacementError),

    #[error("message error: {0}")]
    Message(#[from] syncback_core::messages::MessageError),

    #[error("net channel closed")]
    NetChannelClosed,

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("reed-solomon error: {0}")]
    ReedSolomon(String),
}
```

---

## Encryption (key derivation + ChaCha20-Poly1305)

From CLAUDE.md key decisions:

```
HKDF-SHA256(identity_priv, salt=unit_id, info="syncback-file-encryption") → 32-byte key
```

Implementation:

```rust
pub fn derive_unit_key(&self, unit_id: UnitId) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    // ikm = identity_priv key bytes (32 bytes)
    let ikm: [u8; 32] = self.identity_key.to_bytes();
    // salt = unit_id bytes (32 bytes)
    let salt = &unit_id.0;
    // info = "syncback-file-encryption"
    let info = b"syncback-file-encryption";

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key).expect("HKDF expand: 32-byte output always valid");
    key
}
```

Encryption:

```rust
fn encrypt_unit(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, ShardManagerError> {
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, NewAead}};
    use rand_core::{OsRng, RngCore};

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| ShardManagerError::Encryption(e.to_string()))?;

    // Prepend nonce: [12 bytes nonce][ciphertext + 16 byte tag]
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_unit(key: &[u8; 32], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, ShardManagerError> {
    // First 12 bytes = nonce, remainder = ciphertext+tag
    let nonce_bytes: [u8; 12] = ciphertext_with_nonce[..12].try_into()
        .map_err(|_| ShardManagerError::Encryption("ciphertext too short".to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(nonce, &ciphertext_with_nonce[12..])
        .map_err(|e| ShardManagerError::Encryption(e.to_string()))
}
```

---

## Erasure coding (Reed-Solomon)

Using `reed-solomon-erasure` crate (galois_8 backend, selected in CLAUDE.md).

```rust
fn encode_unit(ciphertext: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, ShardManagerError> {
    use reed_solomon_erasure::galois_8::ReedSolomon;

    let r = ReedSolomon::new(k, n - k)
        .map_err(|e| ShardManagerError::ReedSolomon(e.to_string()))?;

    // Pad ciphertext so length is divisible by k
    let shard_size = ciphertext.len().div_ceil(k);
    let padded_len = shard_size * k;
    let mut padded = ciphertext.to_vec();
    padded.resize(padded_len, 0u8);

    // Split into k data shards of shard_size bytes each
    let mut shards: Vec<Vec<u8>> = padded.chunks(shard_size)
        .map(|s| s.to_vec())
        .collect();

    // Append (n-k) parity shards (initially all zeros)
    for _ in 0..(n - k) {
        shards.push(vec![0u8; shard_size]);
    }

    // Encode in-place
    let shard_refs: Vec<&mut [u8]> = shards.iter_mut().map(|s| s.as_mut_slice()).collect();
    // reed-solomon-erasure encode takes &mut [&mut [u8]]
    r.encode_sep(
        &shards[..k].iter().map(|s| s.as_slice()).collect::<Vec<_>>(),
        &mut shards[k..].iter_mut().map(|s| s.as_mut_slice()).collect::<Vec<_>>(),
    ).map_err(|e| ShardManagerError::ReedSolomon(e.to_string()))?;

    Ok(shards)
}
```

DECISION NEEDED: Check `reed-solomon-erasure` crate API for exact encode method signature.
The `galois_8::ReedSolomon::new(data_shards, parity_shards)` constructor takes parity
count (n-k), not total. The encode method may be `encode_sep(data, parity)` or
`encode(shards)`. Verify against the crate's docs. Adjust implementation accordingly.

---

## Shard ID and Merkle root

```rust
fn compute_shard_id(shard_bytes: &[u8]) -> ShardId {
    ShardId(*blake3::hash(shard_bytes).as_bytes())
}

fn build_merkle_root(shard_bytes: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 65_536;
    // Same logic as storage.rs Merkle tree — must be identical for PoS to work.
    // Leaf hashes: blake3(block) for each 64KB block (pad last block to 64KB with zeros).
    // Internal nodes: blake3(left || right).
    // Pad tree to next power of 2 by duplicating last leaf.
    // Return root hash.
    // ...
    // See storage.rs for canonical implementation — share a helper in a common module.
    todo!()
}
```

Important: the Merkle tree implementation in `shard_manager.rs` (build_root) must produce
the same root as the Merkle tree in `storage.rs` (answer_pos_challenge). To avoid
duplication and divergence, extract the Merkle tree logic into a shared helper:

**Recommended approach:** create `crates/syncback/src/daemon/merkle.rs` with:
```rust
pub const BLOCK_SIZE: usize = 65_536;

/// Compute the BLAKE3 Merkle root over 64KB blocks of data.
/// Pads last block to BLOCK_SIZE with zeros.
/// Pads leaf count to next power of 2 by duplicating last leaf.
pub fn merkle_root(data: &[u8]) -> [u8; 32] { ... }

/// Build full Merkle tree (leaves + internal nodes, root last).
pub fn merkle_tree(data: &[u8]) -> Vec<[u8; 32]> { ... }

/// Extract Merkle proof for leaf at `leaf_index`.
pub fn merkle_proof(tree: &[[u8; 32]], leaf_index: usize) -> Vec<[u8; 32]> { ... }

/// Verify a Merkle proof.
pub fn verify_merkle_proof(
    root: &[u8; 32],
    leaf_hash: &[u8; 32],
    leaf_index: usize,
    proof: &[[u8; 32]],
) -> bool { ... }
```

Both `storage.rs` and `shard_manager.rs` import from `merkle.rs`.

---

## Shard offer flow

For each shard and its assigned holder:

```rust
// 1. Build ShardDescriptorUnsigned
let unsigned = ShardDescriptorUnsigned {
    shard_id,
    unit_id,
    shard_index,
    k: params.k as u8,
    n: params.n as u8,
    merkle_root: build_merkle_root(&shard_bytes),
    owner_pub: self.identity_pub,
    importance: importance as f32,
    file_type: convert_file_type(file_type),
    created_at: now.0,
};

// 2. Sign descriptor
let descriptor = ShardDescriptor::sign(unsigned, &self.identity_key)?;

// 3. Serialize ShardOfferMsg
let offer_msg = ShardOfferMsg { v: 1, descriptor, ts: now.0 };
let payload = to_cbor(&offer_msg)?;

// 4. Get holder's X25519 public key for ECDH encryption
//    For now: derive X25519 pub from identity_pub Ed25519 key.
//    This is a simplification — ideally holders publish separate X25519 keys.
//    Alpha decision: use the Ed25519 public key bytes as X25519 input (lossy but functional).
// DECISION NEEDED: How does the sender encrypt for the holder? The holder's X25519 key
//    is not stored in PeerRecord. Options:
//    a) Use Ed25519 pubkey bytes as X25519 pubkey directly (wrong curve, not secure)
//    b) Store X25519 pubkey separately in PeerRecord (peer publishes it in peer_announce)
//    c) Skip directed encryption for Phase 2 — send as broadcast (security regression)
//    Recommended: b) — add x25519_pub: Option<[u8; 32]> to PeerRecord and derive/publish
//    it as part of peer_announce. For Phase 2 alpha, use option c) with a TODO comment.

// 5. Send via board (for Phase 2: skip encryption, send as broadcast)
self.net_tx.send(NetCommand::PublishBoard {
    msg_type: "shard_offer".to_string(),
    payload,
    directed_to: Some(holder),
}).await.map_err(|_| ShardManagerError::NetChannelClosed)?;
```

---

## Pending blob buffer

After encoding shards, we need to hold the blob data temporarily so that when
`shard_accept` arrives (from a holder reading our board), we can send the blob via
`NetCommand::UploadShard`. The holder then pulls it via iroh-blobs.

**Phase 2 approach:** store a map of `shard_id → blob_bytes` in memory within
`ShardManager`. When `handle_shard_accept` is called, look up the blob and send it.

```rust
// Inside ShardManager struct:
pending_blobs: std::sync::Mutex<std::collections::HashMap<ShardId, Vec<u8>>>,
```

Cleanup: when `handle_shard_stored` fires (stored confirmed) OR after 7 days TTL (offer
expired), remove from map. A simple approach: keep only for the duration of the sync
cycle — Processor calls `clear_pending_blobs()` at end of weekly sync.

```rust
pub fn clear_pending_blobs(&self);
```

Alternative: persist blobs to disk under `{syncback_dir}/upload_staging/{shard_id_hex}.staged`
and delete on `shard_stored`. This is more robust on restart. Phase 2 can use the simpler
in-memory map; Phase 3 can add disk staging.

DECISION NEEDED: The network module sends blobs via `NetCommand::UploadShard { data: Vec<u8> }`.
With 15 shards per unit and up to 256 MB / 5 shards ≈ 51 MB per shard, the in-memory
map can hold hundreds of MB. For Phase 2 with test data (small blobs), this is fine.
For production, disk staging is needed. The implementer may use disk staging from the
start to avoid refactoring.

---

## DB operations

| Operation | DB method | When |
|---|---|---|
| Insert shard record | `db.upsert_shard(&record)` | `upload_unit` (status=Offered) |
| Update shard status | `db.update_shard_status(shard_id, status)` | `handle_shard_accept`, `handle_shard_stored`, `handle_shard_reject`, `handle_shard_dropped` |
| Update last_verified | `db.record_pos_verified(shard_id, ts)` | `handle_pos_response` (pass) |
| List shards for unit | `db.list_shards_for_unit(&unit_id)` | `find_under_replicated_units`, `delete_unit_shards`, `sample_pos_challenges` |
| List all shards | `db.list_all_shards()` | `find_under_replicated_units` |
| List shards needing PoS | `db.list_shards_needing_pos(threshold, limit)` | `sample_pos_challenges` |
| Get shard record | `db.get_shard(&shard_id)` | `handle_shard_accept`, `handle_pos_response` |
| Get unit record | `db.get_unit(&unit_id)` | `repair_unit`, `find_under_replicated_units` |
| List units by status | `db.list_units_by_status(Active)` | `find_under_replicated_units` |
| Budget: record placement | `budget.record_placement_outcome(offered, accepted)` | after weekly sync upload round |

**ShardRecord needs `merkle_root` field:** The current `ShardRecord` in types.rs does not
include `merkle_root`. The PoS verification in `handle_pos_response` needs it to verify
the holder's proof. Add it:

```rust
// In ShardRecord (types.rs — but we cannot modify Phase 1 types without re-review)
pub merkle_root: [u8; 32],
```

DECISION NEEDED: `ShardRecord` is defined in `syncback-core/src/types/mod.rs` (Phase 1).
Adding a new field to it requires either:
  a) Asking the integrator to add the field before Phase 2 starts (requires re-review of
     Phase 1)
  b) Storing `merkle_root` in a separate secondary table keyed by shard_id (in db.rs)
  c) Looking up the merkle_root from HoldingRecord or by re-deriving from the blob
     (not possible — we don't store our own shards)

Recommended: option a) — add `merkle_root: [u8; 32]` to `ShardRecord` with a
`#[serde(default)]` of `[0u8; 32]` for backward compatibility. The integrator can apply
this change before starting Phase 2 implementation.

---

## Business rules

### Erasure coding parameters

From CLAUDE.md (erasure tiers by importance):

| importance | k | n_base | overhead |
|---|---|---|---|
| >= 0.8 | 5 | 15 | 3.0x |
| >= 0.4 | 5 | 10 | 2.0x |
| >= 0.1 | 5 | 7 | 1.4x |
| < 0.1  | — | — | skip |

Adaptive n: add 1-2 extra shards if avg peer trust is low (see `PlacementEngine::adaptive_n`).

### PoS challenge sampling

From overview.md §1.3: 5 random shards per partner per week.

```rust
const MAX_POS_CHALLENGES_PER_PEER: usize = 5;
```

In `sample_pos_challenges`:
1. Query `list_shards_needing_pos(older_than = now - 1_week, limit = very_large)` to get
   all Stored shards not recently verified
2. Group by holder_id
3. For each holder: randomly pick min(5, count) shard_ids
4. For each picked shard: generate random `block_index` (0..block_count), random `nonce`
5. Return Vec<PosChallenge>

`block_count` for a shard: the shard blob size determines block count, but we don't store
shard size in ShardRecord (owner view). Use unit's `size_bytes / rs_n / BLOCK_SIZE` as
approximation, rounding up.

DECISION NEEDED: Store shard blob size in ShardRecord, or approximate via unit lookup.
Phase 2: approximate via unit. Phase 3: store actual shard size.

### PoS response verification

The challenger (us) verifies:
1. `block_data_hash` is a valid leaf at `block_index` in the Merkle tree with the stored root
2. Verification does NOT require re-reading the block — it's a Merkle inclusion proof

Verification algorithm:
```
leaf_hash = block_data_hash
for (i, sibling) in proof.iter().enumerate() {
    if bit i of leaf_index is 0: parent = blake3(leaf_hash || sibling)
    else:                         parent = blake3(sibling || leaf_hash)
    leaf_hash = parent
}
return leaf_hash == stored_merkle_root
```

### Batch offer completion

Owner sends n offers simultaneously. As `shard_stored` confirmations arrive:
- If >= k confirmations received: unit is recoverable ✓
- If >= n confirmations received: unit is fully placed ✓
- Track per-unit state in DB (count of Stored shards)

`record_placement_outcome(offered=n, accepted=count_stored)` is called once per unit
after the sync cycle (Processor calls it at end of WeeklySync, after scanning for new
shard_stored confirmations).

### Owner cooldown on delete

The owner 4-week cooldown is enforced in **Processor**, not ShardManager. When a user
deletes a file:
1. Watcher sends DirtyEvent (kind=Deleted) → Processor marks file deleted
2. Processor sets a "delete_scheduled_at" marker (implementation detail for Processor)
3. After 4 weeks: Processor calls `shard_manager.delete_unit_shards(unit_id, now)`
4. `delete_unit_shards` sends `delete` message to each holder and marks shards Deleting

---

## Constants

```rust
const MAX_POS_CHALLENGES_PER_PEER: usize = 5;
const BLOCK_SIZE: usize = 65_536; // import from merkle.rs
const FILE_ENCRYPTION_INFO: &[u8] = b"syncback-file-encryption";
```

---

## File layout

```
crates/syncback/src/daemon/
  shard_manager.rs    — ShardManager, ShardManagerError, PosChallenge, PosResult
  merkle.rs           — merkle_root(), merkle_tree(), merkle_proof(), verify_merkle_proof()
```

Tests in `#[cfg(test)] mod tests` inline in each file, or in separate `tests.rs` if large.

---

## Test scenarios

### `upload_unit_produces_n_shards`

```
Setup:
  Insert N >= 15 test peers with positive trust scores
  10 KB plaintext bytes, importance=0.9 (tier: 5-of-15)
  ShardManager with test DB and a random identity key

Action:
  shard_manager.upload_unit(unit_id, &unit_record, &plaintext, 0.9, FileType::User, now).await

Expected:
  Ok(placements) with len == 15 (or adaptive_n result)
  15 ShardRecords in DB with status=Offered
  net_tx received 15 PublishBoard commands with msg_type="shard_offer"
```

### `upload_unit_fails_with_not_enough_peers`

```
Setup:
  Insert only 3 peers (< 7 needed for Low tier)
  Plaintext, importance=0.5

Action:
  shard_manager.upload_unit(...)

Expected:
  Err(ShardManagerError::NotEnoughPeers { need: 10, have: 3 })
```

### `handle_shard_stored_updates_status`

```
Setup:
  Insert ShardRecord with status=Accepted

Action:
  shard_manager.handle_shard_stored(shard_id, now)

Expected:
  Ok(())
  db.get_shard(&shard_id).unwrap().status == ShardStatus::Stored
```

### `handle_shard_reject_marks_lost`

```
Setup:
  Insert ShardRecord with status=Offered

Action:
  shard_manager.handle_shard_reject(shard_id, now)

Expected:
  Ok(())
  db.get_shard(&shard_id).unwrap().status == ShardStatus::Lost
```

### `merkle_root_matches_between_owner_and_holder`

```
// This is a cross-module property test
// Given a blob, verify that merkle_root(blob) computed by shard_manager
// matches merkle_root(blob) computed by storage (via merkle.rs shared helper)

let blob = vec![42u8; 3 * 65_536 + 100]; // 3 full blocks + partial
let root_owner = shard_manager_merkle::merkle_root(&blob);
let root_holder = storage_merkle::merkle_root(&blob);
assert_eq!(root_owner, root_holder);
```

### `derive_unit_key_is_deterministic`

```
Setup:
  Fixed identity_key (seed [1u8; 32])
  Fixed unit_id

Action:
  let key1 = manager.derive_unit_key(unit_id);
  let key2 = manager.derive_unit_key(unit_id);

Expected:
  key1 == key2
```

### `encrypt_decrypt_roundtrip`

```
let plaintext = b"hello world, this is a test unit";
let key = [0u8; 32];
let ciphertext = encrypt_unit(&key, plaintext).unwrap();
let recovered = decrypt_unit(&key, &ciphertext).unwrap();
assert_eq!(recovered, plaintext);
```

### `erasure_encode_decode_roundtrip`

```
let plaintext = vec![7u8; 1024];
let shards = encode_unit(&plaintext, 5, 7).unwrap();
assert_eq!(shards.len(), 7);

// Simulate loss of 2 shards (indices 0 and 3)
let mut available = shards.clone();
available[0] = vec![];  // erase shard 0
available[3] = vec![];  // erase shard 3

// Decode (should succeed with 5 of 7)
// ... (verification that RS decode recovers original plaintext)
```

### `find_under_replicated_units_detects_lost_shards`

```
Setup:
  UnitRecord with rs_n=7, rs_k=5
  7 ShardRecords: 3 with status=Stored, 4 with status=Lost

Action:
  let units = shard_manager.find_under_replicated_units()

Expected:
  units contains the unit_id (3 < 7 stored but >= 5 → under-replicated, not lost)
```

### `find_under_replicated_units_marks_data_lost`

```
Setup:
  UnitRecord with rs_n=7, rs_k=5
  7 ShardRecords: 2 with status=Stored, 5 with status=Lost

Expected:
  units returned does NOT include this unit (2 < 5 = unrecoverable)
  Unit logged as ERROR in Processor
```

### `pos_response_verification_pass`

```
// Build a blob, compute root, generate challenge at block_index=0, nonce=[0;32]
// Build PosAnswer with storage::answer_pos_challenge
// Verify with shard_manager::handle_pos_response

Expected: PosResult::Pass
```

### `pos_response_verification_fail_wrong_hash`

```
// Same setup but tamper with block_data_hash
Expected: PosResult::Fail
```

---

## Notes for implementer

1. **`reed-solomon-erasure` crate:** use `galois_8::ReedSolomon` (Galois Field GF(2^8)).
   Check that `new(data_shards, parity_shards)` takes parity_shards = n - k (not n).
   The crate's `encode` method signature varies by version — check Cargo.toml for pinned version.

2. **Pending blob storage:** for Phase 2, use `tokio::sync::Mutex<HashMap<ShardId, Vec<u8>>>`.
   Use `tokio::sync::Mutex` (not `std::sync::Mutex`) because ShardManager methods are
   async and the mutex is held across await points in `handle_shard_accept`.

3. **NetCommand::UploadShard vs PublishBoard:** the shard offer goes via `PublishBoard`
   (board message). The actual blob upload goes via `NetCommand::UploadShard`. The network
   task handles the iroh-blobs transfer. When `shard_accept` arrives, call
   `NetCommand::UploadShard { shard_id, holder, data: pending_blob }`.

4. **ShardDescriptor `file_type` conversion:** `messages::FileType` ≠ `types::FileType`.
   Write conversion helper as in storage.rs.

5. **`handle_shard_accept` must re-check pending_blobs:** if the blob was cleared
   (accept arrived after sync cycle ended), log DEBUG and return Ok(()) — the offer TTL
   will expire on its own and Processor handles the cleanup.

6. **`sample_pos_challenges` randomness:** use `rand::thread_rng()` for block_index and
   nonce selection. The nonce should be cryptographically random: use `OsRng` instead.

7. **`merkle.rs` module:** must be declared in `daemon/mod.rs`:
   ```rust
   mod merkle;  // pub(crate)
   ```
   Or make it `pub(crate)` so both storage and shard_manager can use it.
