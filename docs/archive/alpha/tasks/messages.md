# Task Spec: messages.rs

Module in `crates/syncback-core/src/messages.rs`.

## Overview

`messages.rs` defines all SyncBack protocol message types, their CBOR
serialization/deserialization, signing/verification, and directed ECDH
encryption. It is a pure serialization module: no DB, no network, no async.

This module is the wire-format boundary. Everything that leaves or enters the
node passes through these types. Implementers of Phase 2 (Network module) will
use `messages.rs` as the sole source of truth for on-wire format.

## Dependencies

- `types.rs` — `IdentityPub`, `ShardId`, `UnitId`
- `constants` — `MAX_MESSAGE_SIZE`, `ALPN`, `PROTOCOL_VERSION`, `HANDSHAKE_FRESHNESS_SECS`,
  `MAX_RELAY_HOP`, `DIRECTED_ENCRYPTION_INFO`, `BOARD_TTL_SECS`
- Crypto crates: `ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `ciborium`, `blake3`

No DB access. No `TrustEngine`, `EscrowChecker`, or `PlacementEngine`.

## Public API

### Top-level envelope

Every board entry and every direct connection message uses one of two envelope
types:

```rust
/// An entry on a node's iroh-docs board.
/// key: "{type}/{msg_id}"  (e.g. "shard_offer/abcd1234...")
/// value: serialized BoardEntry (CBOR bytes)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BoardEntry {
    /// "broadcast" or "directed"
    pub kind: EntryKind,
    /// Present only for directed entries. Identifies the intended recipient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pub: Option<IdentityPub>,
    /// For broadcast: raw CBOR payload. For directed: ECDH-encrypted CBOR payload.
    pub payload: Vec<u8>,
    /// Ed25519 signature over: type_bytes || msg_id_bytes || kind_byte || target_pub_bytes || payload_bytes
    pub sig_author: Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    Broadcast,
    Directed,
}

/// A relay copy of a foreign board entry.
/// Board key: "relay/{author_hex}/{msg_id}"
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayEntry {
    /// Original author's identity (who signed it).
    pub author: IdentityPub,
    /// Original msg_id (blake3 hex of payload || timestamp, 32 bytes).
    pub msg_id: MsgId,
    /// Hop count. Original = 0. Each relay copy increments by 1.
    /// Do not relay if hop >= 2.
    pub hop: u8,
    /// The original BoardEntry, preserved exactly.
    pub entry: BoardEntry,
}

/// A framed message for direct QUIC connections (ALPN "syncback/1").
/// Wire format: [u32 BE length][CBOR bytes of DirectMessage]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DirectMessage {
    pub v: u8,   // protocol version, always 1
    pub body: DirectBody,
}

/// The inner body of a direct (non-board) message.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DirectBody {
    Handshake(HandshakeMsg),
    RestoreRequest(RestoreRequestMsg),
    RestoreDenied(RestoreDeniedMsg),
    BlobReady(BlobReadyMsg),
}
```

### Message ID

```rust
/// 32-byte message identifier, derived as blake3(payload_bytes || timestamp_le_bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MsgId(pub [u8; 32]);

impl MsgId {
    /// Derive a MsgId from payload bytes and a unix timestamp (seconds).
    pub fn derive(payload: &[u8], timestamp: u64) -> Self;

    /// Hex-encode for use in board keys.
    pub fn to_hex(&self) -> String;
}
```

### Signature newtype

```rust
/// Ed25519 signature, 64 bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Signature(pub [u8; 64]);
```

### Crypto helpers

```rust
/// ECDH-encrypted payload for directed board entries.
pub struct EncryptedPayload {
    /// X25519 ephemeral public key used for this encryption.
    pub ephemeral_pub: [u8; 32],
    /// ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: [u8; 12],
    /// Ciphertext + 16-byte Poly1305 tag.
    pub ciphertext: Vec<u8>,
}

impl EncryptedPayload {
    /// Serialize to CBOR bytes (for BoardEntry.payload field).
    pub fn to_cbor(&self) -> Vec<u8>;
    /// Deserialize from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, MessageError>;
}
```

### Signing and verification

```rust
/// Sign a board entry payload.
///
/// signed_data = type_bytes || msg_id.0 || kind_byte || target_pub_bytes || payload_bytes
/// where:
///   type_bytes: UTF-8 bytes of the message type string (e.g. "shard_offer")
///   kind_byte: 0x00 for Broadcast, 0x01 for Directed
///   target_pub_bytes: 32 zero bytes if no target, else identity bytes
///   payload_bytes: raw payload (plaintext for broadcast, ciphertext for directed)
///
pub fn sign_entry(
    msg_type: &str,
    msg_id: MsgId,
    kind: EntryKind,
    target_pub: Option<&IdentityPub>,
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
) -> Signature;

/// Verify a board entry signature.
pub fn verify_entry(
    msg_type: &str,
    msg_id: MsgId,
    entry: &BoardEntry,
    author_pub: &IdentityPub,
) -> Result<(), MessageError>;
```

### ECDH encryption/decryption

```rust
/// Encrypt a CBOR payload for a directed recipient.
///
/// Algorithm:
///   1. Generate ephemeral X25519 keypair.
///   2. shared = X25519(ephemeral_priv, recipient_x25519_pub)
///   3. key = HKDF-SHA256(shared, salt="", info="syncback-directed")  [32 bytes]
///   4. nonce = random 12 bytes
///   5. ciphertext = ChaCha20-Poly1305(key, nonce, plaintext)
///
/// sender_priv: the sender's static X25519 private key (derived from identity).
/// recipient_pub: the recipient's static X25519 public key.
pub fn encrypt_payload(
    plaintext: &[u8],
    recipient_x25519_pub: &[u8; 32],
) -> Result<EncryptedPayload, MessageError>;

/// Decrypt a directed payload.
///
/// Algorithm (inverse of encrypt_payload):
///   1. shared = X25519(recipient_priv, ephemeral_pub)
///   2. key = HKDF-SHA256(shared, salt="", info="syncback-directed")
///   3. plaintext = ChaCha20-Poly1305::decrypt(key, nonce, ciphertext)
pub fn decrypt_payload(
    encrypted: &EncryptedPayload,
    recipient_x25519_priv: &[u8; 32],
) -> Result<Vec<u8>, MessageError>;
```

### Wire framing (direct connections)

```rust
/// Serialize a DirectMessage to framed wire bytes: [u32 BE length][CBOR payload].
/// Returns the full bytes to write to the QUIC stream.
/// Errors if CBOR payload > 65535 bytes (64 KB DoS limit).
pub fn frame_message(msg: &DirectMessage) -> Result<Vec<u8>, MessageError>;

/// Parse one framed message from a byte slice.
/// Returns (DirectMessage, bytes_consumed).
/// Errors if length prefix > 65535 or CBOR parsing fails.
pub fn parse_framed(buf: &[u8]) -> Result<(DirectMessage, usize), MessageError>;
```

### CBOR helpers

```rust
/// Serialize any serde-serializable value to CBOR bytes.
pub fn to_cbor<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, MessageError>;

/// Deserialize from CBOR bytes.
pub fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, MessageError>;
```

---

## All Message Types

### Board messages (broadcast)

#### PeerAnnounceMsg

Posted to the author's own board. Tells others how to reach this node.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerAnnounceMsg {
    pub v: u8,
    /// The author's SyncBack identity (Ed25519 pub key).
    pub identity_pub: IdentityPub,
    /// iroh NodeAddr: contains NodeId + relay URL + direct addresses.
    /// Stored as opaque CBOR bytes (iroh type, not parsed in core).
    pub node_addr: Vec<u8>,
    pub ts: u64,  // Unix seconds
}
```

Board key: `"peer_announce/{msg_id}"`. Kind: Broadcast.

---

### Board messages (directed)

All directed messages are encrypted for the target. The payload field of
`BoardEntry` is an `EncryptedPayload` serialized to CBOR. The recipient
decrypts it to get the inner message CBOR.

#### PosChallengMsg (PoS challenge)

Owner → Holder. Requests a proof-of-storage for a specific shard.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PosChallengeMsg {
    pub v: u8,
    /// Unique challenge identifier (random 32 bytes or MsgId).
    pub challenge_id: [u8; 32],
    pub shard_id: ShardId,
    pub unit_id: UnitId,
    pub shard_index: u8,
    /// Start and end block indices (0-based) to prove.
    pub block_range: (u32, u32),
    /// Random nonce to prevent pre-computation.
    pub nonce: [u8; 32],
    pub ts: u64,
}
```

Board key: `"pos_challenge/{msg_id}"`. Kind: Directed, target = holder.

#### PosResponseMsg (PoS response)

Holder → Challenger. Responds with proof.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PosResponseMsg {
    pub v: u8,
    pub challenge_id: [u8; 32],
    /// blake3(block_data || nonce) for the requested block_range.
    pub block_data_hash: [u8; 32],
    /// BLAKE3 Merkle proof: sequence of sibling hashes from leaf to root.
    pub merkle_proof: Vec<[u8; 32]>,
    pub ts: u64,
}
```

Board key: `"pos_response/{msg_id}"`. Kind: Directed, target = challenger.

#### ShardOfferMsg

Owner → Holder. Offers a shard for storage.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardOfferMsg {
    pub v: u8,
    pub descriptor: ShardDescriptor,
    pub ts: u64,
}
```

Board key: `"shard_offer/{msg_id}"`. Kind: Directed, target = holder.

#### ShardAcceptMsg

Holder → Owner. Accepts a shard offer. Holder will pull the blob.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardAcceptMsg {
    pub v: u8,
    pub shard_id: ShardId,
    /// msg_id of the shard_offer being accepted.
    pub offer_msg_id: MsgId,
    pub ts: u64,
}
```

Board key: `"shard_accept/{msg_id}"`. Kind: Directed, target = owner.

#### ShardRejectMsg

Holder → Owner. Rejects a shard offer or rejects a received blob.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardRejectMsg {
    pub v: u8,
    pub shard_id: ShardId,
    /// msg_id of the shard_offer being rejected.
    pub offer_msg_id: MsgId,
    pub reason: RejectReason,
    pub ts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// Holder is at quota (>= soft threshold).
    Full,
    /// Blob hash does not match shard_id in ShardDescriptor.
    HashMismatch,
    /// Owner not in holder's allowlist.
    NotAllowed,
    /// Eviction priority of new shard is too low (did not beat hysteresis).
    LowPriority,
    /// Offer TTL expired before holder could respond.
    Expired,
}
```

Board key: `"shard_reject/{msg_id}"`. Kind: Directed, target = owner.

#### ShardStoredMsg

Holder → Owner. Confirms a shard was successfully received and stored.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardStoredMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub ts: u64,
}
```

Board key: `"shard_stored/{msg_id}"`. Kind: Directed, target = owner.

#### DeleteMsg

Owner → Holder. Requests deletion of a shard after cooldown.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeleteMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub ts: u64,
}
```

Board key: `"delete/{msg_id}"`. Kind: Directed, target = holder.

#### CancelDeleteMsg

Owner → Holder. Cancels a previously sent delete request (ransomware protection).

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CancelDeleteMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub ts: u64,
}
```

Board key: `"cancel_delete/{msg_id}"`. Kind: Directed, target = holder.

#### StorageWarningMsg

Challenger → Holder. Notifies holder that a shard may be corrupted (bit rot).

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageWarningMsg {
    pub v: u8,
    pub shard_id: ShardId,
    /// Human-readable description of what failed.
    pub details: String,
    pub ts: u64,
}
```

Board key: `"storage_warning/{msg_id}"`. Kind: Directed, target = holder.

#### ShardDroppedMsg

Holder → Owner. Notifies owner that a shard was evicted immediately (Phase 1).
Sent as courtesy; owner will detect via PoS anyway.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardDroppedMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub ts: u64,
}
```

Board key: `"shard_dropped/{msg_id}"`. Kind: Directed, target = owner.

#### ShardDropNoticeMsg

Holder → Owner. 7-day advance notice before eviction (Phase 2).

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardDropNoticeMsg {
    pub v: u8,
    pub shard_id: ShardId,
    /// Absolute Unix timestamp: shard will be dropped at or after this time.
    pub deadline: u64,
    pub ts: u64,
}
```

Board key: `"shard_drop_notice/{msg_id}"`. Kind: Directed, target = owner.

#### RestoreDeniedMsg (board variant)

Holder → Owner. Sent on the board when escrow check fails during restore.
Also exists as a `DirectBody` variant for direct connections.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RestoreDeniedMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub reason: DenyReason,
    /// Minimum weeks_in_network required by holder's escrow policy.
    pub required_weeks: u32,
    /// Owner's current weeks_in_network as seen by holder.
    pub current_weeks: u32,
    pub ts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// Owner does not yet meet the weeks_in_network threshold.
    EscrowNotMet,
    /// Shard not found (holder doesn't have it).
    NotFound,
    /// Shard is in MarkedForDelete state (cooldown period).
    InCooldown,
}
```

Board key: `"restore_denied/{msg_id}"`. Kind: Directed, target = owner.

---

### Direct connection messages (ALPN "syncback/1")

These are sent over a live QUIC connection, not through the board. Framed as
`[u32 BE length][CBOR of DirectMessage]`.

#### HandshakeMsg

Sent by both sides at connection open. Establishes SyncBack identity on top of
the iroh TLS layer.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HandshakeMsg {
    pub v: u8,
    /// The sender's SyncBack Ed25519 identity.
    pub identity_pub: IdentityPub,
    /// Unix seconds. Must be within ±300 seconds of receiver's clock.
    pub timestamp: u64,
    /// Ed25519 signature over: "handshake" || identity_pub || timestamp_le_8bytes
    pub sig_author: Signature,
}
```

`DirectBody::Handshake(HandshakeMsg)`.

#### RestoreRequestMsg

Owner → Holder. Requests a specific shard blob over direct connection.
Sent after handshake, before iroh-blobs pull.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RestoreRequestMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub ts: u64,
}
```

`DirectBody::RestoreRequest(RestoreRequestMsg)`.

#### BlobReadyMsg

Holder → Owner. Signals that the blob is available for iroh-blobs pull.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlobReadyMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub ts: u64,
}
```

`DirectBody::BlobReady(BlobReadyMsg)`.

---

### ShardDescriptor

Signed by the owner. Included inside `ShardOfferMsg`. Binds the shard to its
owner and erasure coding parameters.

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardDescriptor {
    /// BLAKE3 hash of shard blob contents. Also the shard's identity.
    pub shard_id: ShardId,
    /// The unit this shard belongs to.
    pub unit_id: UnitId,
    /// Position in the RS set (0..n-1).
    pub shard_index: u8,
    /// Minimum shards to reconstruct (k).
    pub k: u8,
    /// Total shards in set (n).
    pub n: u8,
    /// BLAKE3 Merkle tree root over 64 KB blocks.
    pub merkle_root: [u8; 32],
    /// Owner's Ed25519 public key.
    pub owner_pub: IdentityPub,
    /// Importance (0.0–1.0). Encoded as f32 to ensure deterministic serialization.
    pub importance: f32,
    /// Type of file this shard belongs to.
    pub file_type: FileType,
    /// Unix seconds when this shard was created.
    pub created_at: u64,
    /// Ed25519 signature over CBOR of all fields above (excluding sig_owner itself).
    pub sig_owner: Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    User,
    System,
}
```

#### ShardDescriptor signing

```rust
impl ShardDescriptor {
    /// Sign a descriptor. The signing key must belong to owner_pub.
    /// Computes sig over CBOR of ShardDescriptorUnsigned (same fields minus sig_owner).
    pub fn sign(
        unsigned: ShardDescriptorUnsigned,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<ShardDescriptor, MessageError>;

    /// Verify the owner's signature on this descriptor.
    pub fn verify_sig(&self) -> Result<(), MessageError>;

    /// Verify that blake3(blob) == self.shard_id.
    pub fn verify_blob(&self, blob: &[u8]) -> Result<(), MessageError>;
}

/// The unsigned fields of ShardDescriptor (for signature computation).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardDescriptorUnsigned {
    pub shard_id: ShardId,
    pub unit_id: UnitId,
    pub shard_index: u8,
    pub k: u8,
    pub n: u8,
    pub merkle_root: [u8; 32],
    pub owner_pub: IdentityPub,
    pub importance: f32,
    pub file_type: FileType,
    pub created_at: u64,
}
```

---

### HandshakeMsg signing

```rust
impl HandshakeMsg {
    /// Create and sign a handshake message.
    /// signed_data = b"handshake" || identity_pub.0 || timestamp.to_le_bytes()
    pub fn new(
        identity_pub: IdentityPub,
        timestamp: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self;

    /// Verify the handshake signature.
    pub fn verify(&self) -> Result<(), MessageError>;

    /// Check timestamp freshness. Returns Err if |now - self.timestamp| > 300.
    pub fn check_freshness(&self, now_secs: u64) -> Result<(), MessageError>;
}
```

---

## Error Enum

```rust
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("cbor serialize error: {0}")]
    CborSerialize(String),

    #[error("cbor deserialize error: {0}")]
    CborDeserialize(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("message too large: {size} bytes (max 65535)")]
    TooLarge { size: usize },

    #[error("buffer too short: need {need} bytes, have {have}")]
    BufferTooShort { need: usize, have: usize },

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("decryption error (wrong key or corrupted ciphertext)")]
    Decryption,

    #[error("timestamp not fresh: delta {delta_secs}s exceeds 300s")]
    StaleTimestamp { delta_secs: u64 },

    #[error("blob hash mismatch")]
    BlobHashMismatch,
}
```

---

## Wire Format Details

### Board entry board keys

```
"{msg_type}/{msg_id_hex}"

Examples:
  "peer_announce/a1b2c3..."
  "shard_offer/deadbeef..."
  "pos_challenge/12345678..."
  "relay/abcdef01.../deadbeef..."   ← relay: "relay/{author_hex}/{msg_id_hex}"
```

`msg_id_hex` = `MsgId::to_hex()` (64 hex chars, lowercase).
`author_hex` in relay keys = `IdentityPub` as 64 hex chars.

### Direct message framing

```
[4 bytes: u32 big-endian payload length]
[N bytes: CBOR-encoded DirectMessage]
```

Maximum payload size: 65535 bytes (enforced in `frame_message` and `parse_framed`).

### CBOR field naming convention

All struct fields use `snake_case` as the CBOR map key (serde default).
Enum variants in `#[serde(tag = "type")]` contexts use `snake_case` via
`rename_all = "snake_case"`. The `v: u8` field is always first in CBOR map
(serde-cbor respects field order for maps).

### Version field

Every top-level message has `v: u8 = 1`. Old nodes that receive an unknown `v`
value should log at DEBUG and drop the message (future compatibility).
This is enforced in Phase 2 (Network); messages.rs just defines the field.

### HKDF info string for directed encryption

```
info = b"syncback-directed"
salt = &[]  (empty)
```

The HKDF output is 32 bytes used directly as the ChaCha20-Poly1305 key.

---

## Types Required from types.rs

The following types MUST be defined in `types.rs` before this module can
compile:

```rust
pub struct IdentityPub(pub [u8; 32]);
pub struct ShardId(pub [u8; 32]);
pub struct UnitId(pub [u8; 32]);
```

These are the only types imported from `types.rs`. All other types in this
module are self-contained.

---

## Test Scenarios

All tests are `#[test]`, synchronous. No DB, no iroh, no network.

### 1. `handshake_msg_roundtrip`

Create `HandshakeMsg::new(identity, ts, &signing_key)`.
Serialize with `to_cbor`. Deserialize with `from_cbor::<HandshakeMsg>`.
Call `.verify()`. Expected: Ok.

### 2. `handshake_verify_fails_with_wrong_key`

Create a valid handshake for key A. Mutate `identity_pub` to a different key B.
Call `.verify()`. Expected: Err(InvalidSignature).

### 3. `handshake_check_freshness_passes_within_window`

ts = 1_000_000. now = 1_000_200 (200s delta). Expected: Ok.

### 4. `handshake_check_freshness_fails_outside_window`

ts = 1_000_000. now = 1_000_400 (400s delta > 300). Expected: Err(StaleTimestamp).

### 5. `shard_descriptor_sign_and_verify`

Create `ShardDescriptorUnsigned` with valid fields.
Call `ShardDescriptor::sign(unsigned, &key)`.
Call `descriptor.verify_sig()`. Expected: Ok.

### 6. `shard_descriptor_verify_sig_fails_on_tamper`

Sign a valid descriptor. Mutate `importance` field. Call `verify_sig()`.
Expected: Err(InvalidSignature).

### 7. `shard_descriptor_verify_blob_passes`

blob = random 100 bytes. shard_id = ShardId(blake3::hash(&blob).into()).
Expected: `descriptor.verify_blob(&blob)` → Ok.

### 8. `shard_descriptor_verify_blob_fails_on_mismatch`

shard_id = some fixed value. blob = different bytes.
Expected: Err(BlobHashMismatch).

### 9. `board_entry_sign_and_verify_broadcast`

Create a broadcast `BoardEntry` for `peer_announce`.
`verify_entry("peer_announce", msg_id, &entry, &author_pub)`. Expected: Ok.

### 10. `board_entry_verify_fails_with_wrong_author`

Sign entry with key A. Verify with different key B's identity_pub.
Expected: Err(InvalidSignature).

### 11. `directed_payload_encrypt_decrypt_roundtrip`

plaintext = b"hello shard offer".
Generate recipient X25519 keypair.
`encrypt_payload(plaintext, &recipient_pub_bytes)` → EncryptedPayload.
`decrypt_payload(&encrypted, &recipient_priv_bytes)` → decrypted.
Expected: decrypted == plaintext.

### 12. `directed_payload_decrypt_fails_with_wrong_key`

Encrypt for key A. Try to decrypt with key B.
Expected: Err(Decryption).

### 13. `frame_and_parse_roundtrip`

msg = DirectMessage { v: 1, body: DirectBody::Handshake(...) }.
`frame_message(&msg)` → bytes.
`parse_framed(&bytes)` → (msg2, consumed).
Expected: msg == msg2 (fields equal), consumed == bytes.len().

### 14. `parse_framed_error_on_truncated_buffer`

Construct 6-byte buffer where length prefix says 100 bytes but only 6 bytes present.
Expected: Err(BufferTooShort).

### 15. `frame_message_error_on_oversized_payload`

Construct a DirectMessage with a body whose CBOR exceeds 65535 bytes.
(Use a BlobReadyMsg with a shard_id and pad it, or craft a large HandshakeMsg.)
Expected: Err(TooLarge).

### 16. `msg_id_derive_is_deterministic`

Same payload + same timestamp → same MsgId. Different timestamp → different MsgId.

### 17. `msg_id_to_hex_is_64_chars`

Any MsgId → `to_hex()` returns string of length 64, all lowercase hex.

### 18. `shard_offer_msg_cbor_roundtrip`

Create `ShardOfferMsg` with a valid `ShardDescriptor`.
`to_cbor(&msg)` → `from_cbor::<ShardOfferMsg>(&bytes)`.
Expected: fields equal original.

### 19. `pos_challenge_response_cbor_roundtrip`

Create `PosChallengeMsg` and `PosResponseMsg` with realistic merkle_proof (5 hashes).
Serialize and deserialize both. Expected: all fields equal.

### 20. `reject_reason_all_variants_roundtrip`

For each `RejectReason` variant: serialize to CBOR, deserialize, compare.
Expected: all variants round-trip correctly.

### 21. `deny_reason_all_variants_roundtrip`

Same as above for `DenyReason`.

### 22. `file_type_roundtrip`

`FileType::User` and `FileType::System` serialize to CBOR strings "user" and
"system" respectively. Deserialize back correctly.

### 23. `relay_entry_hop_preserved`

Create `RelayEntry { hop: 1, ... }`. Serialize to CBOR. Deserialize. Check hop == 1.

### 24. `encrypted_payload_cbor_roundtrip`

Create `EncryptedPayload { ephemeral_pub, nonce, ciphertext }`. Call
`to_cbor()` → `from_cbor()`. All fields equal.

### 25. `board_entry_sign_verify_directed`

Create a directed entry (kind = Directed, target_pub = Some(peer)).
Sign with `sign_entry(...)`. Verify with `verify_entry(...)`. Expected: Ok.
Then change one byte of payload. Verify again. Expected: Err(InvalidSignature).

---

## Implementation Notes

### ciborium usage

```rust
// Serialize
let mut buf = Vec::new();
ciborium::into_writer(&value, &mut buf).map_err(|e| MessageError::CborSerialize(e.to_string()))?;

// Deserialize
let value: T = ciborium::from_reader(bytes).map_err(|e| MessageError::CborDeserialize(e.to_string()))?;
```

### ed25519-dalek usage

```rust
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier};

// Sign
let sig = signing_key.sign(&data_to_sign);
let sig_bytes: [u8; 64] = sig.to_bytes();

// Verify
let verifying_key = VerifyingKey::from_bytes(&identity_pub.0)?;
verifying_key.verify(&data, &sig)?;
```

### x25519-dalek + HKDF usage

```rust
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::Sha256;

// Encrypt
let ephemeral_secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
let ephemeral_pub = PublicKey::from(&ephemeral_secret);
let shared = ephemeral_secret.diffie_hellman(&PublicKey::from(*recipient_x25519_pub));
let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
let mut key = [0u8; 32];
hk.expand(b"syncback-directed", &mut key).unwrap();
// Then ChaCha20-Poly1305::new(&key.into()).encrypt(&nonce.into(), plaintext)
```

### ChaCha20-Poly1305 usage

```rust
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace, Nonce};

let cipher = ChaCha20Poly1305::new(&key.into());
let nonce = Nonce::from(nonce_bytes);
let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| MessageError::Encryption("...".into()))?;
```

### Importance as f32

`ShardDescriptor.importance` is `f32` (not `f64`). This ensures deterministic
CBOR serialization across platforms (f64 mantissa differences could cause
signature mismatches). The owner converts `ImportanceScore(f64)` to `f32`
before signing.

### X25519 key from identity

The node's X25519 key is derived separately from the Ed25519 identity key
(using HKDF, as defined in ADR-003). The `messages.rs` module receives the
X25519 bytes directly as `[u8; 32]` — it does not perform key derivation itself.
Key derivation is the responsibility of the daemon initialization code
(Phase 2).

---

## Module Skeleton

```rust
// messages.rs
use crate::types::{IdentityPub, ShardId, UnitId};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier};
use x25519_dalek::{EphemeralSecret, PublicKey};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;

pub struct MsgId(pub [u8; 32]);
pub struct Signature(pub [u8; 64]);

pub enum EntryKind { Broadcast, Directed }
pub struct BoardEntry { ... }
pub struct RelayEntry { ... }
pub struct DirectMessage { ... }
pub enum DirectBody { ... }

pub struct EncryptedPayload { ... }

// All message types:
pub struct PeerAnnounceMsg { ... }
pub struct PosChallengeMsg { ... }
pub struct PosResponseMsg { ... }
pub struct ShardDescriptorUnsigned { ... }
pub struct ShardDescriptor { ... }
pub struct ShardOfferMsg { ... }
pub struct ShardAcceptMsg { ... }
pub struct ShardRejectMsg { ... }
pub struct ShardStoredMsg { ... }
pub struct DeleteMsg { ... }
pub struct CancelDeleteMsg { ... }
pub struct StorageWarningMsg { ... }
pub struct ShardDroppedMsg { ... }
pub struct ShardDropNoticeMsg { ... }
pub struct RestoreDeniedMsg { ... }
pub struct HandshakeMsg { ... }
pub struct RestoreRequestMsg { ... }
pub struct BlobReadyMsg { ... }

pub enum RejectReason { ... }
pub enum DenyReason { ... }
pub enum FileType { User, System }

#[derive(Debug, thiserror::Error)]
pub enum MessageError { ... }

// Public functions:
pub fn sign_entry(...) -> Signature;
pub fn verify_entry(...) -> Result<(), MessageError>;
pub fn encrypt_payload(...) -> Result<EncryptedPayload, MessageError>;
pub fn decrypt_payload(...) -> Result<Vec<u8>, MessageError>;
pub fn frame_message(msg: &DirectMessage) -> Result<Vec<u8>, MessageError>;
pub fn parse_framed(buf: &[u8]) -> Result<(DirectMessage, usize), MessageError>;
pub fn to_cbor<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, MessageError>;
pub fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, MessageError>;

#[cfg(test)]
mod tests { ... }
```
