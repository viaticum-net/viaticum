# Task spec: types.rs

**Module:** `crates/syncback-core/src/types.rs`
**Phase:** 1 (foundation — no other module may be implemented before this)
**Implements:** All shared types, newtype wrappers, record structs, CBOR serialization

---

## Overview

`types.rs` depends only on `crate::constants` (for `SECS_PER_WEEK`, erasure tier thresholds/values). Every other module imports from it. It defines:

- Newtype wrappers for all IDs (compiler-enforced, cannot be mixed up)
- Record structs (one per DB table row)
- Enumerations for state machines
- `Timestamp` type
- CBOR serialization via `serde` + `ciborium`

No logic, no DB access, no crypto operations in this file. Pure data definitions.

---

## Dependencies

**Crate dependencies (from Cargo.toml — already present):**
- `serde` with `derive` feature
- `ciborium` (CBOR via serde)
- `ed25519-dalek` (for `VerifyingKey` and `Signature` types)
- `thiserror`

**Other modules:** none. This is the leaf.

---

## Public API

### Newtype ID wrappers

```rust
/// BLAKE3 hash of shard blob content. 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ShardId(pub [u8; 32]);

/// Identifier of a unit (pack or chunk). Derived from owner+index+hash.
/// 32 bytes, opaque — exact derivation is in shard_manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct UnitId(pub [u8; 32]);

/// Ed25519 public key of a peer identity. 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct IdentityPub(pub [u8; 32]);

/// Monotonically-increasing file identifier. u64, assigned on first index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FileId(pub u64);

/// iroh NodeId — the transport-layer peer identity. 32 bytes (Ed25519 pubkey).
/// Distinct from IdentityPub: IdentityPub = "who you are", NodeId = "how to reach you".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct NodeId(pub [u8; 32]);
```

All newtypes implement `Display` for tracing log fields:

```rust
impl std::fmt::Display for ShardId { ... }     // hex, first 8 bytes: "a1b2c3d4e5f6a7b8"
impl std::fmt::Display for UnitId { ... }      // same pattern
impl std::fmt::Display for IdentityPub { ... } // same pattern
impl std::fmt::Display for FileId { ... }      // decimal: "42"
impl std::fmt::Display for NodeId { ... }      // hex, first 8 bytes
```

Display shows only the first 8 bytes (16 hex chars) — enough for log correlation, not too noisy.

All newtypes implement `AsRef<[u8]>`:

```rust
impl AsRef<[u8]> for ShardId { fn as_ref(&self) -> &[u8] { &self.0 } }
// ... same for UnitId, IdentityPub, NodeId
```

### Timestamp

```rust
/// Unix timestamp in seconds. u64 — no negatives, good until year 2554.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Current wall-clock time (seconds since Unix epoch).
    /// Uses std::time::SystemTime — no tokio dependency.
    pub fn now() -> Self;

    /// Add a number of seconds.
    pub fn add_secs(self, secs: u64) -> Self;

    /// Add a number of weeks (1 week = 604800 seconds).
    pub fn add_weeks(self, weeks: u64) -> Self;

    /// How many whole weeks have elapsed since `self` as of `now`.
    /// Returns 0 if `now` < `self`.
    pub fn weeks_elapsed(self, now: Timestamp) -> u64;

    /// How many whole seconds have elapsed since `self` as of `now`.
    pub fn secs_elapsed(self, now: Timestamp) -> u64;
}
```

### Erasure coding tier

```rust
/// Reed-Solomon tier derived from importance score.
/// Tiers are fixed by the protocol recommendation (overview.md §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ErasureTier {
    /// importance >= 0.8 → 5-of-15 (×3.0 overhead)
    High,
    /// importance >= 0.4 → 5-of-10 (×2.0 overhead)
    Medium,
    /// importance >= 0.1 → 5-of-7 (×1.4 overhead)
    Low,
}

impl ErasureTier {
    /// Minimum shards required for reconstruction (k).
    pub fn k(self) -> usize;
    /// Total shards before adaptive adjustment (n_base).
    pub fn n_base(self) -> usize;
    /// Overhead multiplier (n_base / k), as a float.
    pub fn overhead(self) -> f64;
    /// Derive tier from importance score [0.0, 1.0].
    /// importance < 0.1 → None (do not back up).
    pub fn from_importance(importance: f64) -> Option<Self>;
}
```

### File type

```rust
/// Whether a shard belongs to user data or the system state backup.
/// Stored in ShardDescriptor, signed by owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FileType {
    /// Normal user file shard.
    User,
    /// System state backup shard. Holder stores with max priority, TTL 5 years.
    System,
}
```

### Shard state (holder side)

```rust
/// Lifecycle state of a shard on the holder's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ShardState {
    /// Stored, PoS challenges expected. High priority.
    Active,
    /// Owner sent `delete`. Cooling down (4 weeks). Then delete.
    MarkedForDelete,
    /// No PoS challenges, no delete message. Owner silent.
    /// Priority determined by owner trust.
    Silent,
}
```

### Unit type and status

```rust
/// How the unit was created from the source file(s).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UnitType {
    /// Multiple small files packed into one unit.
    Pack,
    /// One chunk of a large file (≥ U bytes). Index stored in UnitRecord.
    Chunk,
}

/// Lifecycle status of a unit on the owner's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UnitStatus {
    /// Current version, shards distributed in network.
    Active,
    /// One or more member files have changed. Unit exists in network but is outdated.
    Stale,
    /// Delete message sent to all holders. Waiting for cooldown.
    Deleting,
    /// Cooldown elapsed, treated as removed.
    Deleted,
}
```

### Shard status (owner side)

```rust
/// Status of a shard from the owner's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ShardStatus {
    /// shard_offer sent, no shard_accept/reject yet.
    Offered,
    /// shard_accept received, blob transfer in progress.
    Accepted,
    /// shard_stored received. Holder confirmed storage.
    Stored,
    /// Holder dropped or lost the shard (shard_dropped, PoS fail, timeout).
    Lost,
    /// delete message sent. Cooldown in progress.
    Deleting,
}
```

### FileRecord

```rust
/// Stored in the `files` table. Key: file_path (UTF-8 string bytes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileRecord {
    pub file_id: FileId,
    /// Canonical absolute path (UTF-8).
    pub path: String,
    /// BLAKE3 hash of the file's last-seen content.
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    /// Importance score from config, range [0.0, 1.0].
    pub importance: f64,
    /// File has changed since last backup. Watcher sets this.
    pub dirty: bool,
    /// Current unit containing this file's latest version.
    /// None before first backup or after deletion.
    pub current_unit_id: Option<UnitId>,
    /// When this file was last successfully backed up.
    pub last_backed_up: Option<Timestamp>,
    /// Whether this file has ever been fully backed up.
    pub backed_up: bool,
    /// When the file was first indexed.
    pub first_seen: Timestamp,
}
```

### UnitRecord

```rust
/// Stored in the `units` table. Key: UnitId (32 bytes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnitRecord {
    pub unit_id: UnitId,
    pub unit_type: UnitType,
    pub status: UnitStatus,
    /// File IDs that are members of this pack. For Chunk units: single element.
    pub member_file_ids: Vec<FileId>,
    /// For Chunk units: which chunk (0-indexed) of the parent file.
    pub chunk_index: Option<u32>,
    /// For Chunk units: the parent file.
    pub parent_file_id: Option<FileId>,
    /// Unencrypted size of this unit's content in bytes.
    pub size_bytes: u64,
    /// BLAKE3 hash of the unencrypted plaintext unit content.
    pub plaintext_hash: [u8; 32],
    /// When this unit was created.
    pub created_at: Timestamp,
    /// Average importance of member files. Used for erasure tier selection.
    pub importance_avg: f64,
    /// Reed-Solomon k parameter used when sharding this unit.
    pub rs_k: u8,
    /// Reed-Solomon n parameter (actual, post-adaptive adjustment).
    pub rs_n: u8,
}
```

### ShardRecord

```rust
/// Stored in the `shards` table. Key: ShardId (32 bytes).
/// Represents a shard the local node has placed in the network (owner view).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardRecord {
    pub shard_id: ShardId,
    pub unit_id: UnitId,
    /// Index of this shard in the RS set (0-indexed).
    pub shard_index: u8,
    /// Peer holding this shard.
    pub holder_id: IdentityPub,
    pub status: ShardStatus,
    /// Timestamp of last successful PoS verification.
    pub last_verified: Option<Timestamp>,
    /// When this shard was offered.
    pub offered_at: Timestamp,
    /// When shard_stored was received.
    pub stored_at: Option<Timestamp>,
}
```

### PeerRecord

```rust
/// Stored in the `peers` table. Key: IdentityPub (32 bytes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerRecord {
    pub identity: IdentityPub,
    /// Last known iroh NodeId for transport connection.
    pub node_id: Option<NodeId>,
    /// P component: rolling 4-week PoS success rate.
    /// Range [0.0, 1.0].
    pub trust_p: f64,
    /// I component: cumulative mean PoS success rate.
    /// Range [0.0, 1.0].
    pub trust_i: f64,
    /// S component: pairwise storage ratio (their_stored_for_us / our_stored_for_them).
    /// Range [0.0, ∞), clamped to [0.1, 1.0] in trust formula.
    pub trust_s: f64,
    /// When this peer was first seen.
    pub first_seen: Timestamp,
    /// When we last received any message from this peer.
    pub last_seen: Timestamp,
    /// How many weeks this peer has been in the network (cumulative, never decrements).
    pub weeks_in_network: u32,
    /// IPv4 /24 subnet prefix (first 3 octets), or None if unknown/IPv6.
    /// Used for Sybil resistance: max 1 shard per /24.
    pub subnet_prefix: Option<[u8; 3]>,
    /// Whether this peer is manually trusted (trusted identity / allowlist).
    /// Shards from allowlisted peers are never evicted and bypass escrow.
    pub allowlisted: bool,
}
```

### HoldingRecord

```rust
/// Stored in the `holding` table. Key: ShardId (32 bytes).
/// Represents a shard we are holding for someone else (holder view).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HoldingRecord {
    pub shard_id: ShardId,
    pub owner_pub: IdentityPub,
    /// Importance claimed by owner in ShardDescriptor. Verified via signature.
    pub importance: f64,
    /// Shard blob size on disk in bytes.
    pub size_bytes: u64,
    /// Lifecycle state on our side.
    pub state: ShardState,
    /// When we received and stored this shard.
    pub received_at: Timestamp,
    /// When we received a `delete` message from owner. None if no delete request.
    pub delete_requested_at: Option<Timestamp>,
    /// When we should send shard_drop_notice or execute phase-2 eviction.
    /// Set during disk pressure phase 2.
    pub drop_notice_deadline: Option<Timestamp>,
    /// file_type from ShardDescriptor: User or System.
    pub file_type: FileType,
    /// Merkle root from ShardDescriptor (for PoS verification).
    pub merkle_root: [u8; 32],
    /// RS k parameter from ShardDescriptor.
    pub rs_k: u8,
    /// RS n parameter from ShardDescriptor.
    pub rs_n: u8,
    /// Shard index in RS set (0-indexed).
    pub shard_index: u8,
}
```

### BudgetRecord

```rust
/// Stored in the `budget` table. Singleton, key = "budget".
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BudgetRecord {
    /// Estimated network storage budget available for our backups, in GB.
    pub estimated_gb: f64,
    /// When the last budget estimation ran.
    pub last_calculated: Timestamp,
    /// Fraction of recent shard_offer attempts that got shard_stored.
    /// Range [0.0, 1.0].
    pub placement_success_rate: f64,
}
```

### ScheduleRecord

```rust
/// Stored in the `schedule` table. Key = task name (UTF-8).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScheduleRecord {
    pub task_name: String,
    pub last_run: Option<Timestamp>,
    pub next_run: Timestamp,
}
```

### ShardDescriptor

```rust
/// Signed descriptor attached to a shard. Sent in shard_offer messages.
/// Holder verifies this before accepting blob.
/// See overview.md §1.2 and §1.7.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardDescriptor {
    /// BLAKE3 hash of the raw shard blob content.
    pub shard_id: ShardId,
    /// Unit this shard belongs to (encryption scope).
    pub unit_id: UnitId,
    /// Zero-indexed position in the RS set.
    pub shard_index: u8,
    /// Minimum shards required for reconstruction.
    pub rs_k: u8,
    /// Total shards in the RS set.
    pub rs_n: u8,
    /// Root of the BLAKE3 Merkle tree over 64 KB blocks (for PoS).
    pub merkle_root: [u8; 32],
    /// Owner's Ed25519 public key.
    pub owner_pub: IdentityPub,
    /// Importance score [0.0, 1.0].
    pub importance: f64,
    /// User data or system state backup.
    pub file_type: FileType,
    /// When this descriptor was created.
    pub created_at: Timestamp,
    /// Ed25519 signature over all fields above, by owner's identity key.
    /// Covers CBOR encoding of all preceding fields in field order.
    pub sig_owner: [u8; 64],
}
```

### CBOR serialization helpers

```rust
/// Serialize a value to CBOR bytes.
/// Panics if serialization fails (only possible with non-serializable types —
/// all types in this module serialize cleanly).
pub fn to_cbor_bytes<T: serde::Serialize>(value: &T) -> Vec<u8>;

/// Deserialize a value from CBOR bytes.
pub fn from_cbor_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CborError>;

#[derive(Debug, thiserror::Error)]
pub enum CborError {
    #[error("cbor decode: {0}")]
    Decode(String),
}
```

Note: `to_cbor_bytes` panics on failure — valid because all types in the codebase are designed to serialize cleanly. A panic here means a programming error, not a runtime condition.

---

## Business rules and invariants

### Importance → ErasureTier mapping (overview.md §2.2)

```
importance >= 0.8  →  High   (k=5, n=15, overhead ×3.0)
importance >= 0.4  →  Medium (k=5, n=10, overhead ×2.0)
importance >= 0.1  →  Low    (k=5, n=7,  overhead ×1.4)
importance <  0.1  →  None   (do not back up)
```

These thresholds are exact. Do not round. `0.4` maps to Medium, not Low.

### Timestamp::weeks_elapsed

```
weeks_elapsed = (now.0 - self.0) / 604800
```

Integer division — no partial weeks counted. If `now < self`, return 0.

### Display format

All 32-byte ID types display as lowercase hex of the first 8 bytes (16 characters). This is intentional: short enough for logs, unique enough for correlation.

```
ShardId([0xa1, 0xb2, ...]) → "a1b2c3d4e5f6a7b8"
```

### ShardDescriptor signature coverage

The `sig_owner` covers a CBOR encoding of the struct with `sig_owner` set to `[0u8; 64]`. Implementer of `messages.rs` handles signing/verification; `types.rs` only defines the struct shape.

### f64 in serde

Importance scores use `f64`. CBOR encodes f64 as IEEE 754 double (major type 7). `ciborium` handles this correctly. Do not use `f32`.

---

## Test scenarios

All tests live in `#[cfg(test)] mod tests` at the bottom of `types.rs`.

### `erasure_tier_boundaries_are_correct`

```
ErasureTier::from_importance(0.8)  → Some(High)
ErasureTier::from_importance(0.79) → Some(Medium)
ErasureTier::from_importance(0.4)  → Some(Medium)
ErasureTier::from_importance(0.39) → Some(Low)
ErasureTier::from_importance(0.1)  → Some(Low)
ErasureTier::from_importance(0.09) → None
ErasureTier::from_importance(0.0)  → None
ErasureTier::from_importance(1.0)  → Some(High)
```

### `erasure_tier_k_n_values_are_correct`

```
High.k() == 5, High.n_base() == 15
Medium.k() == 5, Medium.n_base() == 10
Low.k() == 5, Low.n_base() == 7
```

### `timestamp_weeks_elapsed_is_floor_division`

```
t0 = Timestamp(0)
t1 = Timestamp(604800 * 3 + 86400)  // 3 weeks + 1 day
t0.weeks_elapsed(t1) == 3
t1.weeks_elapsed(t0) == 0  // now < self → 0
```

### `timestamp_add_weeks_is_correct`

```
Timestamp(0).add_weeks(4) == Timestamp(4 * 604800)
Timestamp(1000).add_weeks(1) == Timestamp(1000 + 604800)
```

### `shard_id_display_is_16_hex_chars`

```
id = ShardId([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, ...rest zeros...])
format!("{}", id) == "deadbeef01020304"
```

### `cbor_roundtrip_file_record`

Construct a `FileRecord` with all fields set, serialize to CBOR, deserialize, assert equality.

### `cbor_roundtrip_shard_descriptor`

Construct a `ShardDescriptor`, serialize, deserialize, assert equality.

### `cbor_roundtrip_holding_record`

Construct a `HoldingRecord` with `state: ShardState::MarkedForDelete`, `delete_requested_at: Some(...)`, serialize, deserialize, assert equality.

### `cbor_roundtrip_peer_record`

Cover `subnet_prefix: Some([192, 168, 1])` and `subnet_prefix: None` variants.

### `file_type_serializes_as_expected`

`FileType::System` and `FileType::User` round-trip through CBOR. Check that the string representation in CBOR matches `"system"` and `"user"` (ciborium uses serde enum serialization — by default uses variant name).

DECIDED: Add `#[serde(rename_all = "lowercase")]` to `FileType`. This makes
`User → "user"`, `System → "system"` in CBOR, matching overview.md §1.9.

### `from_cbor_bytes_returns_error_on_garbage`

```rust
let result = from_cbor_bytes::<FileRecord>(b"not cbor garbage");
assert!(result.is_err());
```

---

## testutil.rs

The testutil module is defined in `crates/syncback-core/src/testutil.rs`. It uses types from `types.rs`. The implementer of `types.rs` should also create `testutil.rs` since it depends only on `types.rs` at this stage.

```rust
// crates/syncback-core/src/testutil.rs

/// Create a deterministic IdentityPub from a small integer seed.
/// Used to generate stable, unique peer identities in tests.
pub fn test_peer(seed: u8) -> IdentityPub {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    IdentityPub(bytes)
}

/// Create n distinct IdentityPub values.
pub fn test_peers(n: usize) -> Vec<IdentityPub> {
    (0..n).map(|i| test_peer(i as u8)).collect()
}

/// Create a Timestamp representing the start of week n (week 0 = Unix epoch).
/// week(1) = Timestamp(604800), week(4) = Timestamp(4 * 604800), etc.
pub fn week(n: u32) -> Timestamp {
    Timestamp(n as u64 * 604800)
}

/// Create a deterministic ShardId from a small integer seed.
pub fn test_shard_id(seed: u8) -> ShardId {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    ShardId(bytes)
}

/// Create a deterministic UnitId from a small integer seed.
pub fn test_unit_id(seed: u8) -> UnitId {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    UnitId(bytes)
}
```

The `testutil` module is gated with `#[cfg(any(test, feature = "testutil"))]` in `lib.rs`. The `testutil` feature must be added to `syncback-core/Cargo.toml` under `[features]`:

```toml
[features]
testutil = []
```

---

## File structure

```
crates/syncback-core/src/types.rs     ← main file
crates/syncback-core/src/testutil.rs  ← test helpers (created in this task)
```

Both files are created in this task.

---

## Notes for implementer

1. All structs should derive `Debug`, `Clone`. Add `Copy` only where the type has no heap allocations (e.g., all newtype IDs, `Timestamp`, `ErasureTier`, `FileType`, `ShardState`, `UnitType`, `UnitStatus`, `ShardStatus`). `FileRecord`, `UnitRecord`, `ShardRecord`, `PeerRecord`, `HoldingRecord`, `BudgetRecord`, `ScheduleRecord`, `ShardDescriptor` should NOT derive `Copy` — they contain `Vec` or `String` or `Option<...>`.

2. The `sig_owner` field in `ShardDescriptor` is `[u8; 64]`, not a dalek `Signature` type — keeping it as raw bytes avoids pulling ed25519-dalek's type into every serde consumer. Conversion to/from `ed25519_dalek::Signature` happens in `messages.rs`.

3. `NodeId` is not an iroh `NodeId` — it is our own newtype. When iroh integration happens in Phase 2, a conversion will be written there. Do not import iroh types in `types.rs`.

4. Do not implement `Default` for any record type — incomplete default values cause silent bugs. Tests should construct records explicitly.

5. `to_cbor_bytes` uses `ciborium::ser::into_writer`. `from_cbor_bytes` uses `ciborium::de::from_reader`. The `CborError` wraps the decode error as a `String` (via `Display`) to avoid exposing ciborium's error type in the public API.

6. `#[serde(rename_all = "lowercase")]` on `FileType`. All other enums use default serde naming (variant names). Check CBOR output in tests to confirm.
