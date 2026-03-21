# Task: messages — Wire format messages (β)

Module: `crates/syncback-core/src/messages/`
Files: `mod.rs` + `tests.rs`

---

## Overview

The messages module defines the complete wire-format type system for SyncBack β. It is
pure data — no networking, no async, no I/O. Other modules (network, relay, backup,
restore) import these types and use the framing helpers to send/receive over iroh streams.

**What this module does:**

1. **Define all message envelopes** — the top-level `Message` enum covering every message
   type the protocol uses (handshake, PoS, symbol transfer, relay board entries, lifecycle).

2. **CBOR serialization** — serialize any `Message` to CBOR bytes and back. All types
   derive serde. The CBOR bytes are the inner payload; framing is a separate concern.

3. **Wire framing** — `frame_message(msg)` → `[u32 BE length][CBOR bytes]`. This is the
   only correct form to put on the wire. `unframe_message(bytes)` → `Message`.

4. **Directed message encryption/decryption** — encrypt a directed payload for a target
   using X25519 ECDH + ChaCha20-Poly1305. Decrypt using own private key.

5. **Relay board entry types** — `BoardEntry` (what goes on an append-only board file)
   and `RelayEntry` (a copy of someone else's board entry with hop incremented).

6. **Validation helpers** — `verify_handshake()`, `verify_board_entry_sig()`, freshness
   checks.

This module is the single source of truth for the wire protocol. The network module and
relay module import from here; they do not define their own message structs.

---

## Dependencies

- `crate::types::{SourceBlockId, IdentityPub, NodeId, Timestamp}`
- `crate::erasure::Symbol`
- `crate::constants::{HANDSHAKE_FRESHNESS_SECS, MAX_RELAY_HOP, RELAY_TTL_SECS,
    MAX_MESSAGE_SIZE, PROTOCOL_VERSION, DIRECTED_ENCRYPTION_INFO}`
- `ed25519_dalek::{Signature, SigningKey, VerifyingKey}`
- `x25519_dalek::{StaticSecret, PublicKey}`
- `chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadInPlace}`
- `hkdf::Hkdf`, `sha2::Sha256`
- No DB. No async. No network. Pure logic.

---

## Types

### Message type tag

```rust
/// Top-level message discriminant (CBOR "type" field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    Handshake,
    PeerAnnounce,
    PosChallenge,
    PosResponse,
    PosNack,
    SymbolOffer,
    SymbolAccept,
    SymbolReject,
    SymbolStored,
    SymbolTransfer,
    Delete,
    CancelDelete,
    StorageWarning,
    SymbolDropped,
    SymbolDropNotice,
    RestoreRequest,
    RestoreResponse,
    RestoreDenied,
}
```

### Handshake

```rust
/// Sent in both directions at connection open on ALPN "syncback/1".
/// sig covers: "handshake" || identity_pub || timestamp_be_u64.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HandshakeMsg {
    pub v: u8,
    pub identity_pub: IdentityPub,
    pub timestamp: Timestamp,
    /// Ed25519 signature. 64 bytes.
    pub sig: [u8; 64],
}
```

### Broadcast messages (relay board, plaintext)

```rust
/// Broadcast peer announcement. Relay board key: "peer_announce/{msg_id}".
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PeerAnnounceMsg {
    pub v: u8,
    pub identity_pub: IdentityPub,
    /// iroh transport address (NodeId bytes).
    pub node_id: NodeId,
    pub timestamp: Timestamp,
    /// Ed25519 signature of identity_pub || node_id || timestamp. 64 bytes.
    pub sig: [u8; 64],
}
```

### Directed message payloads (encrypted on the board, plaintext over direct connection)

```rust
/// Owner → Holder. Challenge ESI to prove possession.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PosChallengeMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],
    pub source_block_id: SourceBlockId,
    pub esi: u32,
    pub timestamp: Timestamp,
}

/// Holder → Owner. Response to a PoS challenge.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PosResponseMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],
    pub esi: u32,
    /// Bound symbol data. Exactly T bytes.
    pub data: Vec<u8>,
    pub timestamp: Timestamp,
}

/// Holder → Owner. Negative ack: holder does not have the challenged symbol.
/// Sent instead of PosResponse when symbol was evicted or never stored.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PosNackMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],
    pub reason: NackReason,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NackReason {
    /// Holder does not have this symbol (evicted or never stored).
    SymbolNotHeld,
}

/// Owner → Holder. Offer to store symbols for a source block.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SymbolOfferMsg {
    pub v: u8,
    pub msg_id: [u8; 16],
    pub source_block_id: SourceBlockId,
    /// ESI ranges being offered: (start_esi, count).
    pub esi_ranges: Vec<(u32, u32)>,
    pub importance: f64,
    pub timestamp: Timestamp,
    /// Ed25519 signature over source_block_id || esi_ranges_cbor || importance_be_f64 || timestamp. 64 bytes.
    pub sig: [u8; 64],
}

/// Holder → Owner. Accept a symbol offer.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SymbolAcceptMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub offer_msg_id: [u8; 16],
    pub timestamp: Timestamp,
}

/// Holder → Owner. Reject a symbol offer.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SymbolRejectMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub offer_msg_id: [u8; 16],
    pub reason: RejectReason,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    QuotaFull,
    LowPriority,
    UnknownOwner,
    HashMismatch,
    Other,
}

/// Holder → Owner. Symbols received and stored.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SymbolStoredMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,
    pub timestamp: Timestamp,
}

/// Direct transfer: owner pushes symbols to holder after accept.
/// Also used: holder sends symbols to owner during restore.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SymbolTransferMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    /// The bound symbols being transferred.
    pub symbols: Vec<Symbol>,
    pub timestamp: Timestamp,
}

/// Owner → Holder. Request to delete stored symbols (with cooldown on holder side).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeleteMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub timestamp: Timestamp,
    /// Ed25519 signature. 64 bytes.
    pub sig: [u8; 64],
}

/// Owner → Holder. Cancel a previously sent delete.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CancelDeleteMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub timestamp: Timestamp,
    /// Ed25519 signature. 64 bytes.
    pub sig: [u8; 64],
}

/// Owner → Holder. Notify that a stored symbol failed PoS (bit rot alert).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StorageWarningMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi: u32,
    pub details: String,
    pub timestamp: Timestamp,
}

/// Holder → Owner. Holder evicted symbols (disk pressure).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SymbolDroppedMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,
    pub timestamp: Timestamp,
}

/// Holder → Owner. Advance notice: will drop these symbols by deadline.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SymbolDropNoticeMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,
    /// Absolute unix timestamp when drop will occur.
    pub deadline: Timestamp,
    pub timestamp: Timestamp,
}

/// Owner → Holder. Request symbols for restore.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RestoreRequestMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    /// Which ESIs are wanted (empty = "any K_eff from your holdings").
    pub esi_list: Vec<u32>,
    pub timestamp: Timestamp,
}

/// Holder → Owner. Deliver requested symbols.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RestoreResponseMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub symbols: Vec<Symbol>,
    pub timestamp: Timestamp,
}

/// Holder → Owner. Escrow not satisfied, restore denied.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RestoreDeniedMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub reason: String,
    pub required_weeks: u32,
    pub current_weeks: u32,
    pub timestamp: Timestamp,
}
```

### Relay board types

```rust
/// One entry on a relay board (append-only file).
/// key: "{type}/{msg_id}"
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BoardEntry {
    /// "broadcast" or "directed".
    pub kind: BoardEntryKind,
    /// Only present for directed entries.
    pub target_pub: Option<IdentityPub>,
    /// For broadcast: raw CBOR of the inner message.
    /// For directed: encrypted CBOR (ECDH + ChaCha20-Poly1305), see DirectedEnvelope.
    pub payload: Vec<u8>,
    /// Ed25519 sig over: type_str || msg_id || kind_str || target_pub_or_empty || payload.
    /// Signed by original author (preserved by relay nodes — never re-signed).
    pub sig_author: [u8; 64],
    /// Author's identity_pub (needed to verify sig_author).
    pub author: IdentityPub,
    /// Hop count. Original entry = 0. Each relay copy increments by 1.
    /// Entries with hop >= MAX_RELAY_HOP (2) are not copied further.
    pub hop: u8,
    /// When this entry was created (for TTL = RELAY_TTL_SECS).
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardEntryKind {
    Broadcast,
    Directed,
}

/// Encrypted envelope for directed payloads.
/// Inner payload is CBOR-serialized directed message struct.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DirectedEnvelope {
    /// Sender's X25519 ephemeral public key (32 bytes).
    pub sender_x25519_pub: [u8; 32],
    /// ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: [u8; 12],
    /// Encrypted + authenticated CBOR payload.
    pub ciphertext: Vec<u8>,
}
```

### Top-level Message enum

```rust
/// All direct-connection messages. Framed with [u32 BE len][CBOR].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Handshake(HandshakeMsg),
    PeerAnnounce(PeerAnnounceMsg),
    PosChallenge(PosChallengeMsg),
    PosResponse(PosResponseMsg),
    PosNack(PosNackMsg),
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
}
```

---

## Error types

```rust
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    /// CBOR serialization failed.
    #[error("cbor encode error: {0}")]
    CborEncode(String),

    /// CBOR deserialization failed.
    #[error("cbor decode error: {0}")]
    CborDecode(String),

    /// Framed message exceeds MAX_MESSAGE_SIZE.
    #[error("message too large: {size} bytes, max {}", crate::constants::MAX_MESSAGE_SIZE)]
    TooLarge { size: usize },

    /// Frame length prefix mismatch.
    #[error("frame length mismatch: prefix says {declared}, got {actual}")]
    FrameLengthMismatch { declared: u32, actual: usize },

    /// Input buffer too short to read length prefix.
    #[error("buffer too short for length prefix")]
    BufferTooShort,

    /// Ed25519 signature verification failed.
    #[error("signature verification failed")]
    BadSignature,

    /// Handshake timestamp outside freshness window.
    #[error("handshake timestamp too old or future: delta {delta_secs}s")]
    HandshakeStale { delta_secs: i64 },

    /// Directed encryption/decryption failed.
    #[error("directed encryption error: {0}")]
    EncryptionError(String),

    /// Relay hop limit exceeded (should not relay this entry).
    #[error("relay hop limit exceeded: hop={hop}")]
    HopLimitExceeded { hop: u8 },
}
```

---

## Public API

```rust
// ---- Framing ----

/// Serialize msg to CBOR and prepend u32 BE length prefix.
/// Returns Err(TooLarge) if CBOR size exceeds MAX_MESSAGE_SIZE.
pub fn frame_message(msg: &Message) -> Result<Vec<u8>, MessageError>;

/// Parse the first framed message from buf.
/// Returns (Message, bytes_consumed) so caller can advance the read cursor.
/// Returns Err(BufferTooShort) if buf has fewer than 4 bytes.
/// Returns Err(FrameLengthMismatch) if declared length > available bytes.
pub fn unframe_message(buf: &[u8]) -> Result<(Message, usize), MessageError>;

// ---- CBOR (bare, no length prefix — for relay board payloads) ----

/// Serialize to CBOR bytes (no framing). For relay board payload field.
pub fn to_cbor<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, MessageError>;

/// Deserialize from CBOR bytes. For relay board payload field.
pub fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, MessageError>;

// ---- Handshake ----

/// Build a HandshakeMsg signed with signing_key.
/// sig_input = b"handshake" || identity_pub.0 || timestamp.0.to_be_bytes()
pub fn build_handshake(
    identity_pub: IdentityPub,
    timestamp: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
) -> HandshakeMsg;

/// Verify a received HandshakeMsg.
/// Checks: (1) sig valid, (2) timestamp within HANDSHAKE_FRESHNESS_SECS of `now`.
/// Returns Err(BadSignature) or Err(HandshakeStale).
pub fn verify_handshake(msg: &HandshakeMsg, now: Timestamp) -> Result<(), MessageError>;

// ---- Directed encryption ----

/// Encrypt a directed payload for target_pub.
/// shared_key = X25519(our_x25519_priv, target_x25519_pub)
/// → HKDF-SHA256(shared_key, info=DIRECTED_ENCRYPTION_INFO) → 32-byte ChaCha20-Poly1305 key
/// Returns DirectedEnvelope.
pub fn encrypt_directed(
    plaintext: &[u8],
    our_x25519_priv: &x25519_dalek::StaticSecret,
    target_x25519_pub: &x25519_dalek::PublicKey,
) -> Result<DirectedEnvelope, MessageError>;

/// Decrypt a directed payload.
/// own_x25519_priv: our private key. sender_x25519_pub: from envelope.
/// Returns plaintext bytes.
pub fn decrypt_directed(
    envelope: &DirectedEnvelope,
    own_x25519_priv: &x25519_dalek::StaticSecret,
) -> Result<Vec<u8>, MessageError>;

// ---- Board entry helpers ----

/// Build and sign a broadcast BoardEntry.
/// sig_input = type_str_bytes || msg_id || b"broadcast" || payload
/// hop = 0, created_at = now.
pub fn build_broadcast_entry(
    msg_type: &str,
    msg_id: [u8; 16],
    payload: Vec<u8>,
    author: IdentityPub,
    now: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
) -> BoardEntry;

/// Build and sign a directed BoardEntry (payload already encrypted by caller).
/// sig_input = type_str_bytes || msg_id || b"directed" || target_pub.0 || encrypted_payload
/// hop = 0, created_at = now.
pub fn build_directed_entry(
    msg_type: &str,
    msg_id: [u8; 16],
    target_pub: IdentityPub,
    encrypted_payload: Vec<u8>,
    author: IdentityPub,
    now: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
) -> BoardEntry;

/// Verify a board entry's signature.
/// Reconstructs sig_input from entry fields and verifies against entry.sig_author + entry.author.
pub fn verify_board_entry_sig(entry: &BoardEntry, msg_type: &str, msg_id: &[u8; 16])
    -> Result<(), MessageError>;

/// Check if a board entry has expired (created_at + RELAY_TTL_SECS <= now).
pub fn is_board_entry_expired(entry: &BoardEntry, now: Timestamp) -> bool;

/// Check if this entry can be relayed further (hop < MAX_RELAY_HOP).
/// Returns Err(HopLimitExceeded) if hop >= MAX_RELAY_HOP.
pub fn check_relay_hop(entry: &BoardEntry) -> Result<(), MessageError>;

/// Produce a relay copy of an entry with hop incremented by 1.
/// Caller must call check_relay_hop first.
pub fn relay_copy(entry: &BoardEntry) -> BoardEntry;
```

---

## Business Rules

### Framing discipline (CRITICAL)

The protocol documentation contains an explicit warning: never send bare CBOR on the
wire without the u32 BE length prefix. The receiver reads 4 bytes as the length; if
those 4 bytes are the start of a CBOR header (e.g., `0xA2626964`), the receiver
interprets them as a 2.7 GB length and stalls or crashes.

Rule: the only function that produces bytes safe to write to an iroh stream is
`frame_message()`. Internal serialization (`to_cbor()`) is for relay board payloads
only.

### Handshake freshness window

```
delta = |msg.timestamp.0 as i64 - now.0 as i64|
if delta > HANDSHAKE_FRESHNESS_SECS (300): return Err(HandshakeStale)
```

Protects against replay attacks. Both sides generate fresh timestamps; the connection is
short-lived enough that 5 minutes is sufficient.

### Handshake signing

```
sig_input = b"handshake" || identity_pub.0[32] || msg.timestamp.0.to_be_bytes()[8]
sig = Ed25519Sign(signing_key, sig_input)
```

### Directed encryption

```
ephemeral_x25519_priv = X25519StaticSecret::random()
sender_x25519_pub     = PublicKey::from(&ephemeral_x25519_priv)
shared                = ephemeral_x25519_priv.diffie_hellman(&target_x25519_pub)
(_, chacha_key)       = Hkdf::<Sha256>::extract(None, shared.as_bytes())
chacha_key            = chacha_key.expand(DIRECTED_ENCRYPTION_INFO, &mut [0u8; 32])
nonce                 = random 12 bytes
ciphertext            = ChaCha20Poly1305(chacha_key, nonce).encrypt(plaintext)
```

Decryption reverses the steps using own_x25519_priv + sender_x25519_pub from envelope.

### Board entry signature input

```
sig_input for broadcast:
    msg_type as UTF-8 bytes
    || msg_id (16 bytes)
    || b"broadcast"
    || payload bytes

sig_input for directed:
    msg_type as UTF-8 bytes
    || msg_id (16 bytes)
    || b"directed"
    || target_pub.0 (32 bytes)
    || encrypted_payload bytes
```

The sig is over the concatenation as plain bytes (not CBOR-encoded fields). Relay nodes
copy `sig_author` and `author` unchanged — they never re-sign.

### Hop counting

- hop = 0: authored by this node (on our own board)
- hop = 1: copied from a direct partner's board
- hop = 2: copied from a second-hop node's board
- hop >= MAX_RELAY_HOP (2): do NOT copy further. `check_relay_hop` returns
  `Err(HopLimitExceeded)` so callers can skip the copy operation.

### Message version field

All message structs have `v: u8 = PROTOCOL_VERSION`. Receivers SHOULD accept unknown
fields (CBOR schema evolution). Receivers SHOULD NOT reject messages with `v` higher
than their own — treat unknown `v` as forward-compatible minor revision.

---

## DB Operations

None. This module is pure logic with no DB dependency.

---

## Test Scenarios

Tests in `messages/tests.rs`. Pattern: `what_when_then`.

### 1. `frame_message_roundtrip_handshake`

```
msg = Message::Handshake(HandshakeMsg { v: 1, identity_pub: [1u8;32].into(), timestamp: Timestamp(1000), sig: [0u8;64] })
framed = frame_message(&msg).unwrap()
assert framed.len() >= 4
(decoded, consumed) = unframe_message(&framed).unwrap()
assert decoded == msg
assert consumed == framed.len()
```

### 2. `frame_message_length_prefix_is_big_endian`

```
msg = Message::PeerAnnounce(...)
framed = frame_message(&msg).unwrap()
declared_len = u32::from_be_bytes(framed[0..4].try_into().unwrap()) as usize
assert declared_len == framed.len() - 4
```

### 3. `unframe_message_returns_buffer_too_short_for_3_bytes`

```
result = unframe_message(&[0x00, 0x00, 0x01])
assert matches!(result, Err(MessageError::BufferTooShort))
```

### 4. `unframe_message_returns_frame_length_mismatch`

```
// Declare length 100 but only provide 10 bytes of payload
buf = [0, 0, 0, 100, /* 10 cbor bytes */]
result = unframe_message(&buf)
assert matches!(result, Err(MessageError::FrameLengthMismatch { .. }))
```

### 5. `frame_message_too_large_returns_error`

```
// Construct a SymbolTransferMsg with > MAX_MESSAGE_SIZE worth of symbol data
// (unrealistic in practice, but validates the guard)
big_symbols = vec![Symbol { esi: 0, data: vec![0u8; 65535] }; 1100]  // ~72 MB
msg = Message::SymbolTransfer(SymbolTransferMsg { symbols: big_symbols, ... })
result = frame_message(&msg)
assert matches!(result, Err(MessageError::TooLarge { .. }))
```

### 6. `build_and_verify_handshake_passes`

```
signing_key = SigningKey::generate(&mut OsRng)
identity_pub = IdentityPub(signing_key.verifying_key().to_bytes())
now = Timestamp(1_000_000)
msg = build_handshake(identity_pub, now, &signing_key)
result = verify_handshake(&msg, now)
assert result.is_ok()
```

### 7. `verify_handshake_fails_bad_signature`

```
signing_key = SigningKey::generate(&mut OsRng)
identity_pub = IdentityPub(signing_key.verifying_key().to_bytes())
msg = build_handshake(identity_pub, Timestamp(1_000_000), &signing_key)
// Corrupt the signature
msg.sig[0] ^= 0xFF
result = verify_handshake(&msg, Timestamp(1_000_000))
assert matches!(result, Err(MessageError::BadSignature))
```

### 8. `verify_handshake_fails_stale_timestamp`

```
signing_key = SigningKey::generate(&mut OsRng)
identity_pub = IdentityPub(signing_key.verifying_key().to_bytes())
old_ts = Timestamp(1_000_000)
now = Timestamp(1_000_000 + HANDSHAKE_FRESHNESS_SECS + 1)
msg = build_handshake(identity_pub, old_ts, &signing_key)
result = verify_handshake(&msg, now)
assert matches!(result, Err(MessageError::HandshakeStale { .. }))
```

### 9. `encrypt_decrypt_directed_roundtrip`

```
our_priv = StaticSecret::random_from_rng(OsRng)
their_priv = StaticSecret::random_from_rng(OsRng)
their_pub = PublicKey::from(&their_priv)
plaintext = b"hello world directed message"
envelope = encrypt_directed(plaintext, &our_priv, &their_pub).unwrap()
recovered = decrypt_directed(&envelope, &their_priv).unwrap()
assert recovered == plaintext
```

### 10. `decrypt_directed_fails_with_wrong_key`

```
our_priv = StaticSecret::random_from_rng(OsRng)
wrong_priv = StaticSecret::random_from_rng(OsRng)
their_pub = PublicKey::from(&StaticSecret::random_from_rng(OsRng))
envelope = encrypt_directed(b"secret", &our_priv, &their_pub).unwrap()
result = decrypt_directed(&envelope, &wrong_priv)
assert result.is_err()
```

### 11. `build_broadcast_entry_verify_sig_passes`

```
signing_key = SigningKey::generate(&mut OsRng)
author = IdentityPub(signing_key.verifying_key().to_bytes())
msg_id = [0u8; 16]
payload = b"test broadcast payload".to_vec()
entry = build_broadcast_entry("peer_announce", msg_id, payload, author, Timestamp(1000), &signing_key)
assert entry.hop == 0
assert entry.kind == BoardEntryKind::Broadcast
result = verify_board_entry_sig(&entry, "peer_announce", &msg_id)
assert result.is_ok()
```

### 12. `build_directed_entry_verify_sig_passes`

```
signing_key = SigningKey::generate(&mut OsRng)
author = IdentityPub(signing_key.verifying_key().to_bytes())
target = IdentityPub([2u8; 32])
msg_id = [1u8; 16]
encrypted_payload = vec![0u8; 32]
entry = build_directed_entry("pos_challenge", msg_id, target, encrypted_payload, author, Timestamp(1000), &signing_key)
assert entry.target_pub == Some(target)
result = verify_board_entry_sig(&entry, "pos_challenge", &msg_id)
assert result.is_ok()
```

### 13. `verify_board_entry_sig_fails_corrupted_payload`

```
// Build valid entry, then corrupt payload
entry.payload[0] ^= 0xFF
result = verify_board_entry_sig(&entry, msg_type, &msg_id)
assert matches!(result, Err(MessageError::BadSignature))
```

### 14. `is_board_entry_expired_false_before_ttl`

```
entry.created_at = Timestamp(1_000_000)
now = Timestamp(1_000_000 + RELAY_TTL_SECS - 1)
assert !is_board_entry_expired(&entry, now)
```

### 15. `is_board_entry_expired_true_at_ttl`

```
entry.created_at = Timestamp(1_000_000)
now = Timestamp(1_000_000 + RELAY_TTL_SECS)
assert is_board_entry_expired(&entry, now)
```

### 16. `check_relay_hop_allows_hop_zero_and_one`

```
entry.hop = 0
assert check_relay_hop(&entry).is_ok()
entry.hop = 1
assert check_relay_hop(&entry).is_ok()
```

### 17. `check_relay_hop_rejects_hop_two`

```
entry.hop = MAX_RELAY_HOP  // 2
result = check_relay_hop(&entry)
assert matches!(result, Err(MessageError::HopLimitExceeded { hop: 2 }))
```

### 18. `relay_copy_increments_hop`

```
entry.hop = 0
copy = relay_copy(&entry)
assert copy.hop == 1
assert copy.sig_author == entry.sig_author  // signature preserved
assert copy.author == entry.author
```

### 19. `all_message_variants_frame_roundtrip`

```
// For each variant construct a minimal valid instance and round-trip through frame/unframe
for msg in [handshake, peer_announce, pos_challenge, ..., restore_denied]:
    framed = frame_message(&msg).unwrap()
    (decoded, _) = unframe_message(&framed).unwrap()
    assert decoded == msg
```

### 20. `to_cbor_from_cbor_roundtrip`

```
offer = SymbolOfferMsg { v: 1, msg_id: [0;16], source_block_id: ..., esi_ranges: [(0, 100)], importance: 0.7, timestamp: Timestamp(1000), sig: [0;64] }
bytes = to_cbor(&offer).unwrap()
decoded: SymbolOfferMsg = from_cbor(&bytes).unwrap()
assert decoded == offer
```

---

## Module Structure

```
messages/
  mod.rs    — all types and public functions above
  tests.rs  — all test scenarios above
```

---

## Notes for implementer

- `Symbol` is imported from `crate::erasure` — it is already defined in Phase 1. Do not
  redefine it here.

- The `Message` enum uses `#[serde(tag = "type", rename_all = "snake_case")]`. This
  means CBOR maps will have a `"type"` field with the snake_case variant name. New nodes
  can add variants; old nodes see an unknown `"type"` and should treat it as an
  unrecognized but parseable map (CBOR's schema-free property handles this).

- `DirectedEnvelope` is a separate struct serialized as CBOR and placed in
  `BoardEntry.payload`. The relay module never needs to look inside it — it copies the
  bytes opaquely.

- For `encrypt_directed`: use an **ephemeral** X25519 keypair per call (not the node's
  long-term key). This ensures forward secrecy: an attacker who later compromises the
  recipient's long-term key cannot decrypt past messages.

- For tests 6-8: `SigningKey::generate` needs an RNG. Use `rand::rngs::OsRng` from the
  `rand` workspace dep. Import `ed25519_dalek::SigningKey`.

- `v: u8` in all message structs must be set to `PROTOCOL_VERSION` (= 1 from
  `constants.rs`) when constructing messages. The build helpers should do this
  automatically.

- `SymbolOfferMsg.sig` is an optional-but-required field: the holder verifies it to
  confirm the offer is from a known identity. The sig covers the offer parameters so the
  holder can't be tricked into accepting different ESI ranges than the owner intended.
  Signature input: `source_block_id.0[32] || cbor(esi_ranges) || importance.to_be_bytes()[8] || timestamp.0.to_be_bytes()[8]`.

- `DeleteMsg.sig` and `CancelDeleteMsg.sig` cover: `b"delete"` (or `b"cancel_delete"`)
  || `source_block_id.0` || `timestamp.0.to_be_bytes()`. Holders must verify before
  acting on these.
