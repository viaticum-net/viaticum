# Task: relay — Epidemic relay (β)

Module: `crates/syncback/src/daemon/relay/`
Files: `mod.rs` + `board.rs` + `tests.rs`

---

## Overview

The epidemic relay implements SyncBack's "board of announcements" — an append-only file
per node that stores broadcast and directed messages. Relay nodes copy messages from their
partners' boards to their own, propagating up to 2 hops. This gives deferred
store-and-forward messaging without requiring both parties to be online simultaneously.

**Phase 2 gate requirement:** `сообщение через третий peer` — Node A posts a directed
message, Node B (intermediate relay) copies it to its board, Node C reads it from B's
board. Message reaches C without A ever connecting directly to C.

**What this module does:**

1. **Local board management** — maintain an append-only board file on disk. Write new
   entries (authored by this node, hop=0). Read entries for outbound sync.

2. **Board sync** — when connecting to a partner peer, exchange boards: read their board,
   identify entries we don't have yet (by msg_id), copy eligible ones (hop < MAX_RELAY_HOP,
   not expired, sig valid) to our board with hop incremented.

3. **Relay policy** — apply hop limit (hop < MAX_RELAY_HOP = 2) and TTL check
   (created_at + RELAY_TTL_SECS <= now → expired, skip). Dedup by msg_id (already have
   it → skip). Verify sig_author before relaying.

4. **Board reading for self** — scan the local board for entries directed at us
   (target_pub == our identity), decrypt directed payloads, deliver to the daemon message
   dispatcher.

5. **Board pruning** — periodically remove entries older than RELAY_TTL_SECS. Also enforce
   board size limits (MAX_BOARD_ENTRIES and MAX_BOARD_SIZE_BYTES); when exceeded, drop
   oldest entries first.

6. **Posting helpers** — build and sign broadcast and directed board entries, append to
   local board.

The relay module does NOT decide what to do with received messages — it delivers decoded
payloads to the daemon via a callback/channel. Business logic lives in BackupCoordinator,
RestoreCoordinator, PoS engine, etc.

---

## Dependencies

- `syncback_core::messages::{BoardEntry, BoardEntryKind, DirectedEnvelope,
    build_broadcast_entry, build_directed_entry, verify_board_entry_sig,
    is_board_entry_expired, check_relay_hop, relay_copy, encrypt_directed,
    decrypt_directed, to_cbor, from_cbor, MessageError}`
- `syncback_core::types::{IdentityPub, NodeId, Timestamp}`
- `syncback_core::constants::{MAX_RELAY_HOP, RELAY_TTL_SECS}`
- `ed25519_dalek::{SigningKey}`
- `x25519_dalek::{StaticSecret, PublicKey}`
- `tokio::{sync::mpsc, time, fs}`
- `anyhow::{Context, Result}`
- `tracing::{info, debug, error, warn}`
- `std::collections::{HashMap, HashSet}`

---

## Types

```rust
/// A decoded inbound message directed at us, delivered to the daemon.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    /// Who sent this message (author of the board entry).
    pub from: IdentityPub,
    /// Raw CBOR bytes of the inner message (already decrypted if directed).
    pub payload: Vec<u8>,
    /// Message type string (from board entry key prefix, e.g. "pos_challenge").
    pub msg_type: String,
    /// Unique message identifier (16 bytes).
    pub msg_id: [u8; 16],
    /// When the entry was created (for logging/TTL checks).
    pub created_at: Timestamp,
}

/// Configuration for the relay module.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Path to the local board file. Entries are CBOR-serialized BoardEntries,
    /// newline-delimited (one JSON-adjacent CBOR entry per line is NOT the format;
    /// use a length-prefixed binary format: [u32 BE len][CBOR bytes]).
    pub board_path: std::path::PathBuf,
    /// Our identity public key. Used to filter entries directed at us.
    pub identity_pub: IdentityPub,
    /// Our X25519 private key for decrypting directed messages.
    pub x25519_priv: x25519_dalek::StaticSecret,
    /// Our Ed25519 signing key for authoring board entries.
    pub signing_key: ed25519_dalek::SigningKey,
    /// Max entries on our board before oldest are pruned.
    pub max_entries: usize,
    /// Max total board size in bytes before oldest entries are pruned.
    pub max_size_bytes: usize,
    /// How often to prune the board (seconds).
    pub prune_interval_secs: u64,
}

impl RelayConfig {
    pub fn defaults_for_test(board_path: std::path::PathBuf) -> Self;
}

/// One entry stored in the board file (on disk) or received during sync.
/// This is BoardEntry from messages module plus its key components.
#[derive(Debug, Clone)]
pub struct StoredEntry {
    /// Type string (e.g. "pos_challenge", "peer_announce").
    pub msg_type: String,
    /// 16-byte unique ID.
    pub msg_id: [u8; 16],
    /// The board entry itself.
    pub entry: BoardEntry,
}

/// Errors from relay operations.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("io error reading/writing board: {0}")]
    Io(#[from] std::io::Error),

    #[error("message error: {0}")]
    Message(#[from] MessageError),

    #[error("board corrupted at entry {index}: {reason}")]
    BoardCorrupted { index: usize, reason: String },

    #[error("board size limit exceeded (max {max} entries)")]
    BoardFull { max: usize },
}
```

---

## Public API

```rust
/// RelayManager: manages the local board and syncs with partner boards.
pub struct RelayManager {
    config: RelayConfig,
    /// In-memory index of msg_ids we already have (for dedup).
    known_ids: HashSet<[u8; 16]>,
    /// Entries currently on our board (in append order).
    entries: Vec<StoredEntry>,
}

impl RelayManager {
    /// Create a new manager. Loads existing board from disk if it exists.
    /// Builds known_ids index from loaded entries.
    /// Prunes expired entries on startup.
    pub fn new(config: RelayConfig) -> Result<Self, RelayError>;

    /// Post a new broadcast entry authored by us (hop=0).
    ///
    /// Builds a BoardEntry via messages::build_broadcast_entry with our signing_key.
    /// Appends to board file and in-memory list.
    /// Returns the StoredEntry (for callers that need the msg_id).
    pub fn post_broadcast(
        &mut self,
        msg_type: &str,
        msg_id: [u8; 16],
        payload: Vec<u8>,
        now: Timestamp,
    ) -> Result<StoredEntry, RelayError>;

    /// Post a new directed entry authored by us (hop=0).
    ///
    /// Encrypts payload for target_pub using our x25519_priv.
    /// Builds a BoardEntry via messages::build_directed_entry with our signing_key.
    /// Appends to board file and in-memory list.
    pub fn post_directed(
        &mut self,
        msg_type: &str,
        msg_id: [u8; 16],
        target_pub: IdentityPub,
        plaintext_payload: &[u8],
        now: Timestamp,
    ) -> Result<StoredEntry, RelayError>;

    /// Process entries received from a partner's board during sync.
    ///
    /// For each entry in `remote_entries`:
    ///   1. Skip if msg_id already in known_ids (dedup).
    ///   2. Skip if is_board_entry_expired(entry, now).
    ///   3. Skip if check_relay_hop(entry).is_err() (hop >= MAX_RELAY_HOP).
    ///   4. Verify sig: verify_board_entry_sig(entry, msg_type, msg_id).
    ///      On failure: log and skip (bad entries from partners must not crash us).
    ///   5. Accept: relay_copy(entry) → append to our board.
    ///
    /// Returns count of entries accepted.
    ///
    /// Note: this does NOT deliver messages to our inbox. That is done by
    /// scan_for_self() called separately.
    pub fn process_remote_entries(
        &mut self,
        remote_entries: &[StoredEntry],
        now: Timestamp,
    ) -> Result<usize, RelayError>;

    /// Scan our board for entries directed at us (target_pub == our identity_pub).
    ///
    /// For each such entry:
    ///   1. Decrypt payload using our x25519_priv.
    ///   2. Build InboundMessage.
    ///   3. Send to inbound_tx channel.
    ///
    /// Entries that fail decryption are logged and skipped.
    /// Also scans for broadcast entries from trusted parties (delivered as-is).
    ///
    /// Returns count of messages delivered to inbound_tx.
    pub fn scan_for_self(
        &self,
        inbound_tx: &tokio::sync::mpsc::Sender<InboundMessage>,
        now: Timestamp,
    ) -> usize;

    /// Remove entries older than RELAY_TTL_SECS or beyond board size limits.
    ///
    /// TTL rule: entry.created_at + RELAY_TTL_SECS <= now → remove.
    /// Size rule: if entries.len() > max_entries OR total_bytes > max_size_bytes →
    ///   remove oldest (lowest created_at) entries until within limits.
    ///
    /// Rewrites the board file after pruning.
    pub fn prune(&mut self, now: Timestamp) -> Result<usize, RelayError>;

    /// Return a snapshot of all current (non-expired) entries for sharing with a partner.
    /// Called when a partner connects and wants to sync our board.
    pub fn entries_for_sync(&self, now: Timestamp) -> Vec<StoredEntry>;

    /// Return entry count and approximate size in bytes.
    pub fn stats(&self) -> (usize, usize);

    /// Run the relay manager as a tokio task.
    ///
    /// Listens for sync triggers (partner connections) via sync_rx.
    /// On each trigger: exchange board entries with partner.
    /// Runs prune timer every prune_interval_secs.
    /// Delivers inbound messages to inbound_tx.
    pub async fn run(
        mut self,
        sync_rx: tokio::sync::mpsc::Receiver<SyncTrigger>,
        inbound_tx: tokio::sync::mpsc::Sender<InboundMessage>,
    ) -> anyhow::Result<()>;
}

/// A trigger to sync boards with a partner (sent when a connection is established).
#[derive(Debug)]
pub struct SyncTrigger {
    pub partner_identity: IdentityPub,
    /// Partner's current board entries, already fetched by network layer.
    pub partner_entries: Vec<StoredEntry>,
}
```

---

## Business Rules

### Board file format

The board is stored as a binary file with length-prefixed CBOR entries:

```
[u32 BE length of CBOR][CBOR(StoredEntry)] [u32 BE][CBOR(StoredEntry)] ...
```

This matches the wire framing used for direct connections (for consistency).

On load: read entries sequentially. On append: open file in append mode, write one
length-prefixed CBOR entry. On prune: rewrite the whole file (atomic: write to temp,
rename).

`StoredEntry` serialized to CBOR includes the `msg_type`, `msg_id`, and the full
`BoardEntry` (which contains `kind`, `target_pub`, `payload`, `sig_author`, `author`,
`hop`, `created_at`).

### Relay policy (complete algorithm)

```
process_remote_entries(remote_entries, now):
  for entry in remote_entries:
    if entry.msg_id in known_ids: continue          // dedup
    if is_board_entry_expired(&entry.entry, now): continue  // TTL check
    if check_relay_hop(&entry.entry).is_err(): continue     // hop >= 2, stop propagation
    match verify_board_entry_sig(&entry.entry, &entry.msg_type, &entry.msg_id):
      Err(e): log warning; continue                // bad sig from partner
      Ok(()): ()
    relay_copy = relay_copy(&entry.entry)           // hop + 1
    stored = StoredEntry { msg_type: entry.msg_type, msg_id: entry.msg_id, entry: relay_copy }
    append_to_board(&stored)?
    known_ids.insert(entry.msg_id)
    entries.push(stored)
  return accepted_count
```

The relay never re-signs entries. The original `sig_author` and `author` are preserved
exactly. The relay only increments `hop`. A relay node can be caught if it increments hop
more than once or changes any other field (signature covers all content).

### Directed message delivery

```
scan_for_self(inbound_tx, now):
  for stored in entries:
    if is_board_entry_expired(&stored.entry, now): continue
    match stored.entry.kind:
      Broadcast:
        msg = InboundMessage {
            from: stored.entry.author,
            payload: stored.entry.payload.clone(),   // raw CBOR of inner msg
            msg_type: stored.msg_type.clone(),
            msg_id: stored.msg_id,
            created_at: stored.entry.created_at,
        }
        inbound_tx.try_send(msg)

      Directed:
        if stored.entry.target_pub != Some(our identity_pub): continue
        // Decrypt
        envelope: DirectedEnvelope = from_cbor(&stored.entry.payload)?
        plaintext = decrypt_directed(&envelope, &our_x25519_priv)?
        msg = InboundMessage {
            from: stored.entry.author,
            payload: plaintext,
            msg_type: stored.msg_type.clone(),
            msg_id: stored.msg_id,
            created_at: stored.entry.created_at,
        }
        inbound_tx.try_send(msg)
```

Delivery is non-blocking (`try_send`): if the channel is full, drop the message and log a
warning. The caller can call `scan_for_self` periodically to re-deliver.

### Hop semantics

```
hop = 0:  authored on this node. We don't relay our own entries (no copy needed).
hop = 1:  copied from a direct partner's board.
          MAX_RELAY_HOP = 2 → check_relay_hop returns Ok(()) for hop 0 and 1.
hop >= 2: do NOT copy further (check_relay_hop returns Err for hop >= 2).
```

When we relay a partner's entry (hop=1 entry): the copy has hop=2. When our partner relays
our entry (hop=0→1) and a third party sees that (hop=1), they can relay it one more time
(hop=1→2). Any entry with hop=2 is not relayed further. This achieves the 3-hop coverage
(originator + 1 relay hop + 1 more relay hop = 3 nodes).

Wait — re-read protocol: MAX_RELAY_HOP = 2 means "drop if hop >= 2". So:
- hop 0: original author's board
- hop 1: partner copied it (hop = 0 + 1 = 1 < 2 → was allowed to copy)
- hop 2: partner's partner copied it (hop = 1 + 1 = 2 → allowed? check_relay_hop checks hop >= MAX_RELAY_HOP)

`check_relay_hop` returns `Err(HopLimitExceeded)` if `entry.hop >= MAX_RELAY_HOP`.
So an entry with hop=1 can be relayed (resulting copy has hop=2). An entry with hop=2
cannot be relayed further.

Entry with hop=2 is stored on our board (we relayed it there from a partner's hop=1) and
served to our partners when they sync, but we do NOT relay it further.

### Board size limits

```
MAX_BOARD_ENTRIES = 2000  (from protocol.md)
MAX_BOARD_SIZE_BYTES = 8 * 1024 * 1024  (8 MB, from protocol.md)

If after append: entries.len() > MAX_BOARD_ENTRIES OR total_bytes > MAX_BOARD_SIZE_BYTES:
  drop_count = entries.len() - MAX_BOARD_ENTRIES  (if by count)
  OR enough entries to get under MAX_BOARD_SIZE_BYTES (if by bytes)
  Remove oldest `drop_count` entries from front of list.
  Rewrite board file.
```

Note: the board limits are per RelayConfig (they can be overridden in tests). The protocol
recommends 2000 entries / 8 MB; the defaults in RelayConfig should match these.

### Dedup

`known_ids` is a `HashSet<[u8; 16]>` built from all entries currently in `entries`. On
append (own posts or relayed copies), insert the msg_id. On startup, rebuild from loaded
entries. On prune, rebuild from remaining entries.

### Sync protocol

The sync is triggered by the network layer when a connection is established. The network
layer fetches the partner's board entries and sends them via `SyncTrigger`. The relay
manager processes them via `process_remote_entries`.

In Phase 2, "fetching partner's board" is implemented as: during a direct connection, send
a new message type (or a request/response pattern). However, since the relay board is
primarily for asynchronous messaging (not real-time), and Phase 2 focuses on direct
connections for symbol transfer, the relay board sync is simplified:

- Each node sends its full board snapshot when a connection is established.
- Use a new `Message::BoardSync(BoardSyncMsg)` (a batch of StoredEntries).
- This is sent as the first message after handshake, before other protocol traffic.

DECISION NEEDED: `BoardSyncMsg` is not defined in the current `messages.md` spec.
Add it to `syncback-core/src/messages/` as:
```rust
pub struct BoardSyncMsg {
    pub v: u8,
    pub entries: Vec<StoredEntry>,
    pub timestamp: Timestamp,
}
```
And add `BoardSync(BoardSyncMsg)` to `Message` enum. This requires a minor update to the
messages module (additive, no breaking changes — old nodes see unknown variant and ignore).

---

## DB Operations

None. The relay module has no DB dependency. Its state is the board file on disk and the
in-memory `entries` + `known_ids`. The daemon can read `PeerRecord` from DB to decide
which partners to sync with, but that logic lives in the daemon's connection layer, not
the relay module.

---

## Test Scenarios

Tests in `relay/tests.rs`. Pattern: `what_when_then`.

Use `tempfile::TempDir` for board file path. Tests are synchronous (no tokio needed for
unit tests; async only for `run()` test).

### 1. `post_broadcast_appends_to_board`

```
manager = RelayManager::new(test_config(tmpdir))
msg_id = [0u8; 16]
payload = b"hello world".to_vec()
entry = manager.post_broadcast("peer_announce", msg_id, payload.clone(), Timestamp(1000)).unwrap()

assert entry.msg_id == msg_id
assert entry.entry.hop == 0
assert entry.entry.kind == BoardEntryKind::Broadcast
assert manager.stats().0 == 1
```

### 2. `post_broadcast_persists_to_disk`

```
manager = RelayManager::new(test_config(tmpdir))
manager.post_broadcast("peer_announce", [0u8;16], b"data".to_vec(), Timestamp(1000)).unwrap()

// Reload manager from same path
manager2 = RelayManager::new(test_config_same_path(tmpdir))
assert manager2.stats().0 == 1
```

### 3. `post_directed_encrypts_payload`

```
target_priv = StaticSecret::random_from_rng(OsRng)
target_pub = PublicKey::from(&target_priv)
target_identity = IdentityPub([3u8; 32])

manager = RelayManager::new(test_config(tmpdir))
msg_id = [1u8; 16]
plaintext = b"secret message"
entry = manager.post_directed("pos_challenge", msg_id, target_identity, plaintext, Timestamp(1000)).unwrap()

assert entry.entry.kind == BoardEntryKind::Directed
assert entry.entry.target_pub == Some(target_identity)
// payload should be encrypted (not equal to plaintext)
assert entry.entry.payload != plaintext
```

### 4. `process_remote_entries_accepts_valid_hop1_entry`

```
// Create an entry authored by partner with hop=0
partner_signing_key = SigningKey::generate(&mut OsRng)
partner_identity = IdentityPub(partner_signing_key.verifying_key().to_bytes())
raw_entry = build_broadcast_entry("peer_announce", [2u8;16], b"data".to_vec(), partner_identity, Timestamp(500), &partner_signing_key)
remote = StoredEntry { msg_type: "peer_announce".into(), msg_id: [2u8;16], entry: raw_entry }

manager = RelayManager::new(test_config(tmpdir))
count = manager.process_remote_entries(&[remote], Timestamp(1000)).unwrap()
assert count == 1
assert manager.stats().0 == 1
// The stored copy should have hop=1
let stored = &manager.entries[0]
assert stored.entry.hop == 1
```

### 5. `process_remote_entries_deduplicates_known_msg_id`

```
// Same msg_id twice
count1 = manager.process_remote_entries(&[entry_with_msg_id_X], now).unwrap()
count2 = manager.process_remote_entries(&[entry_with_msg_id_X], now).unwrap()
assert count1 == 1
assert count2 == 0
assert manager.stats().0 == 1
```

### 6. `process_remote_entries_rejects_expired_entry`

```
// Entry created 8 days ago (> RELAY_TTL_SECS = 7 days)
old_entry.entry.created_at = Timestamp(1000)
now = Timestamp(1000 + RELAY_TTL_SECS + 1)

count = manager.process_remote_entries(&[old_entry], now).unwrap()
assert count == 0
```

### 7. `process_remote_entries_rejects_hop2_entry`

```
// Entry with hop=2 should not be relayed further
entry_hop2 = StoredEntry { entry: BoardEntry { hop: 2, ... }, ... }
count = manager.process_remote_entries(&[entry_hop2], now).unwrap()
assert count == 0
```

### 8. `process_remote_entries_rejects_bad_signature`

```
// Build valid entry then corrupt sig
bad_sig_entry = build_broadcast_entry(...)
bad_sig_entry.entry.sig_author[0] ^= 0xFF

count = manager.process_remote_entries(&[bad_sig_entry], now).unwrap()
assert count == 0  // invalid sig → dropped
```

### 9. `scan_for_self_delivers_directed_message`

```
// Post a directed entry targeting our own identity
our_priv = StaticSecret::random_from_rng(OsRng)
our_pub = PublicKey::from(&our_priv)
our_identity = IdentityPub([10u8; 32])

// Config with our_identity and our_priv
config = RelayConfig { identity_pub: our_identity, x25519_priv: our_priv, ... }
manager = RelayManager::new(config)

// Another party sends a directed message to us
sender_signing_key = SigningKey::generate(&mut OsRng)
sender_identity = IdentityPub(sender_signing_key.verifying_key().to_bytes())
plaintext = b"pos_challenge_payload"
// Build directed board entry targeting our_identity
// (encrypt with our_pub)
sender_x25519 = StaticSecret::random_from_rng(OsRng)
envelope = encrypt_directed(plaintext, &sender_x25519, &our_pub).unwrap()
envelope_cbor = to_cbor(&envelope).unwrap()
entry = build_directed_entry(
    "pos_challenge", [5u8;16], our_identity, envelope_cbor,
    sender_identity, Timestamp(1000), &sender_signing_key
)
manager.entries.push(StoredEntry { msg_type: "pos_challenge".into(), msg_id: [5u8;16], entry })

(inbound_tx, mut inbound_rx) = mpsc::channel(10)
count = manager.scan_for_self(&inbound_tx, Timestamp(2000))
assert count == 1
msg = inbound_rx.try_recv().unwrap()
assert msg.payload == plaintext
assert msg.from == sender_identity
assert msg.msg_type == "pos_challenge"
```

### 10. `scan_for_self_ignores_directed_to_other`

```
// Entry targeting a different identity
other_identity = IdentityPub([99u8; 32])
entry = build_directed_entry(..., target=other_identity, ...)
manager.entries.push(...)

(inbound_tx, inbound_rx) = mpsc::channel(10)
count = manager.scan_for_self(&inbound_tx, Timestamp(2000))
assert count == 0  // not for us
```

### 11. `prune_removes_expired_entries`

```
manager = RelayManager::new(test_config(tmpdir))

// Add 3 entries at different times
manager.post_broadcast(..., Timestamp(1000))   // will expire
manager.post_broadcast(..., Timestamp(2000))   // will expire
manager.post_broadcast(..., Timestamp(100_000)) // still valid

now = Timestamp(1000 + RELAY_TTL_SECS + 1)
pruned = manager.prune(now).unwrap()
assert pruned == 2
assert manager.stats().0 == 1
```

### 12. `prune_respects_max_entries_limit`

```
// Fill board with max_entries + 5 entries
config = RelayConfig { max_entries: 10, ... }
manager = RelayManager::new(config)
for i in 0..15 {
    manager.post_broadcast("peer_announce", [i as u8; 16], ..., Timestamp(1000 + i as u64))
}

now = Timestamp(2000)  // nothing expired yet
pruned = manager.prune(now).unwrap()
assert manager.stats().0 == 10  // trimmed to max
```

### 13. `entries_for_sync_excludes_expired`

```
manager = RelayManager::new(test_config(tmpdir))
manager.post_broadcast(..., Timestamp(1000))   // will expire
manager.post_broadcast(..., Timestamp(100_000)) // still valid

now = Timestamp(1000 + RELAY_TTL_SECS + 1)
sync_entries = manager.entries_for_sync(now)
assert sync_entries.len() == 1
assert sync_entries[0].entry.created_at == Timestamp(100_000)
```

### 14. `relay_three_hop_propagation`

```
// Gate test: A posts, B relays (via process_remote_entries), C reads from B.

// Step 1: A posts a directed message to C.
config_a = test_config_for_identity(identity_a, board_path_a)
manager_a = RelayManager::new(config_a)
msg_id = [7u8; 16]
manager_a.post_directed("pos_challenge", msg_id, identity_c, b"challenge_data", Timestamp(1000)).unwrap()

// Step 2: B syncs from A (B sees A's entries, copies hop=0 → hop=1).
config_b = test_config_for_identity(identity_b, board_path_b)
manager_b = RelayManager::new(config_b)
a_entries = manager_a.entries_for_sync(Timestamp(1000))
accepted = manager_b.process_remote_entries(&a_entries, Timestamp(1000)).unwrap()
assert accepted == 1

// Step 3: C syncs from B (C sees B's hop=1 entry, copies hop=1 → hop=2).
config_c = test_config_for_identity_with_x25519(identity_c, x25519_c_priv, board_path_c)
manager_c = RelayManager::new(config_c)
b_entries = manager_b.entries_for_sync(Timestamp(1000))
accepted = manager_c.process_remote_entries(&b_entries, Timestamp(1000)).unwrap()
assert accepted == 1

// Step 4: C scans its board for messages directed to itself.
(inbound_tx, inbound_rx) = mpsc::channel(10)
count = manager_c.scan_for_self(&inbound_tx, Timestamp(1000))
assert count == 1
msg = inbound_rx.try_recv().unwrap()
assert msg.payload == b"challenge_data"
assert msg.from == identity_a

// Step 5: Verify C cannot relay further (hop=2 entry not propagated).
config_d = test_config_for_identity(identity_d, board_path_d)
manager_d = RelayManager::new(config_d)
c_entries = manager_c.entries_for_sync(Timestamp(1000))
// hop=2 entry in c_entries → process_remote_entries skips it
accepted_d = manager_d.process_remote_entries(&c_entries, Timestamp(1000)).unwrap()
assert accepted_d == 0
```

### 15. `board_survives_reload`

```
// Write entries, reload manager, verify all entries still there.
manager = RelayManager::new(test_config(tmpdir))
for i in 0..5 {
    manager.post_broadcast("peer_announce", [i as u8; 16], b"payload".to_vec(), Timestamp(1000))
}
assert manager.stats().0 == 5
drop(manager)

// Reload
manager2 = RelayManager::new(test_config_same_path(tmpdir))
assert manager2.stats().0 == 5
```

---

## Module Structure

```
relay/
  mod.rs    — RelayManager, RelayConfig, InboundMessage, SyncTrigger, run()
  board.rs  — board file I/O: load_board(), append_entry(), rewrite_board()
  tests.rs  — all test scenarios above
```

---

## Notes for implementer

- The `StoredEntry` type needs to be serializable for the board file (CBOR) and for
  network transfer (`BoardSyncMsg`). Derive `serde::Serialize, serde::Deserialize` on it.

- Board file I/O is in `board.rs`. Use synchronous file I/O (no async needed) since
  `RelayManager` methods are synchronous. The `run()` method wraps blocking I/O in
  `tokio::task::spawn_blocking` if needed, or simply uses the in-memory state and
  persists asynchronously.

- The `BoardSyncMsg` is not yet in the messages module. The implementer must add it.
  It is a simple wrapper:
  ```rust
  pub struct BoardSyncMsg {
      pub v: u8,
      pub entries: Vec<StoredEntry>,
      pub timestamp: Timestamp,
  }
  ```
  Add `BoardSync(BoardSyncMsg)` to `Message` enum in `messages/mod.rs`. Add
  `BoardSync` to `MessageType`. This is an additive change — no existing tests break.

- The `StoredEntry` contains `BoardEntry` from the messages module. Since `BoardEntry`
  has `payload: Vec<u8>` (which for directed entries is the CBOR-serialized
  `DirectedEnvelope`), the relay manager copies bytes without interpreting them. Only
  `scan_for_self` decrypts directed payloads.

- For directed message encryption: the sender uses the **recipient's X25519 public key**,
  not the recipient's Ed25519 identity key. In the full system, a peer's X25519 key is
  derived from its seed phrase (or published via peer_announce). In Phase 2 tests, pass
  X25519 keys explicitly. DECISION NEEDED: how does a node learn a partner's X25519
  public key? Recommend publishing it in `PeerAnnounceMsg`. For now, tests pass it
  directly.

- `prune()` rewrites the board file atomically: write to a temp file adjacent to
  `board_path`, then `std::fs::rename`. This prevents data loss on crash during rewrite.

- The board is append-only during normal operation (cheap). Prune is a periodic
  rewrite (expensive but rare). The `known_ids` HashSet avoids O(n) dedup scans.

- For test 14 (three-hop propagation): create separate `RelayManager` instances for A,
  B, C, D with distinct identities and X25519 keys. This is the Phase 2 gate test — it
  must pass for the gate to be satisfied.

- `relay_copy` from the messages module creates a copy with hop+1. The original
  `sig_author` is preserved. The relay does NOT change any signed fields — doing so would
  invalidate the signature and future verifiers would reject the entry.

- Constants not yet in `constants.rs` that may be needed:
  - `MAX_BOARD_ENTRIES: usize = 2000` (from protocol.md §1.5)
  - `MAX_BOARD_SIZE_BYTES: usize = 8 * 1024 * 1024` (from protocol.md §1.5)
  Add these to `constants.rs`.

- All tests in `relay/tests.rs`. No inline `#[cfg(test)]`.
