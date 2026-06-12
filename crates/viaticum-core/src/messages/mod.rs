use crate::constants::{HANDSHAKE_FRESHNESS_SECS, MAX_MESSAGE_SIZE, PROTOCOL_VERSION};
use crate::erasure::Symbol;
use crate::mailbox::{MailboxEntry, MailboxRejectReason};
use crate::types::{DeviceId, IdentityPub, SourceBlockId, Timestamp, sig_serde};
use ed25519_dalek::Signer;

// ============================================================
// Message structs
// ============================================================

/// Sent in both directions at connection open on ALPN "viaticum/1".
/// sig covers: "handshake" || identity_pub.0 || timestamp.0.to_be_bytes()
/// The device_cert, if present, is NOT covered by sig (it is self-signed by master key).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HandshakeMsg {
    pub v: u8,
    pub identity_pub: IdentityPub,
    pub timestamp: Timestamp,
    /// Ed25519 signature. 64 bytes.
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
    /// Device certificate: master_key.sign(device_pub_key).
    /// Present when this node is part of a multi-device identity.
    #[serde(default)]
    pub device_cert: Option<crate::cluster::DeviceCertificate>,
}

/// Broadcast peer announcement. Relay board key: "peer_announce/{msg_id}".
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PeerAnnounceMsg {
    pub v: u8,
    pub identity_pub: IdentityPub,
    pub timestamp: Timestamp,
    /// Ed25519 signature. 64 bytes.
    /// Sig input: b"pa" (2) || identity_pub (32) || timestamp_be (8) || x25519_pub_or_zeroes (32)
    /// Total: 74 bytes. If x25519_pub is None, the last 32 bytes are [0u8; 32].
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
    /// X25519 public key for directed relay board encryption.
    /// Covered by sig (see above).
    #[serde(default)]
    pub x25519_pub: Option<[u8; 32]>,
}

/// Owner → Holder. Block-level chain hash challenge.
/// Covers all ESI ranges for this holder for this source block.
/// Response: holder computes SHA256-chain over all bound symbols (ESIs sorted ascending).
///
/// sig covers: b"pc" (2) || challenge_id (16) || source_block_id (32)
///   || CBOR(esi_ranges) || timestamp_be (8). Signed by the OWNER's master identity key.
/// The holder verifies the sig against `MailboxEntry.sender` (the claimed owner) before
/// doing any re-encode / disk work. An all-zero sig is the `#[serde(default)]` value for
/// messages that predate this field and is unconditionally rejected (A2 = hard cut-over).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PosHashChallengeMsg {
    pub v: u8,
    /// Unique identifier for this challenge (random 16 bytes).
    pub challenge_id: [u8; 16],
    pub source_block_id: SourceBlockId,
    /// ESI ranges assigned to this holder.
    pub esi_ranges: Vec<(u32, u32)>,
    pub timestamp: Timestamp,
    #[serde(default)]
    pub device_id: Option<DeviceId>,
    /// Ed25519 signature by the owner's master identity key. 64 bytes.
    /// Defaults to [0u8; 64] on deserialization (old unsigned messages) which will
    /// fail verify_pos_hash_challenge — old messages are silently rejected.
    #[serde(with = "sig_serde")]
    #[serde(default = "default_sig")]
    pub sig: [u8; 64],
}

/// Holder → Owner. Response to PosHashChallengeMsg.
/// chain_hash = SHA256-chain over bound symbol data for all assigned ESIs (sorted ascending):
///   h0 = SHA256(challenge_id), h_i = SHA256(h_{i-1} || symbol[esi_i]), chain_hash = h_n
///
/// sig covers: b"pr" (2) || challenge_id (16) || source_block_id (32) || chain_hash (32)
///   || timestamp_be (8) = 90 bytes. Signed by the HOLDER's master identity key.
/// The owner verifies the sig against the master of `pending.holder_id` before applying any
/// Pass/Fail outcome (closes the forged-response framing vector). An all-zero sig is the
/// `#[serde(default)]` value for old unsigned messages and is unconditionally rejected.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PosHashResponseMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],
    /// Source block this response is for. Bound by the signature so a postman cannot
    /// retarget a captured response to a different block.
    pub source_block_id: SourceBlockId,
    /// Chain hash over all assigned ESIs.
    pub chain_hash: [u8; 32],
    pub timestamp: Timestamp,
    #[serde(default)]
    pub device_id: Option<DeviceId>,
    /// Ed25519 signature by the holder's master identity key. 64 bytes.
    /// Defaults to [0u8; 64] on deserialization (old unsigned messages) which will
    /// fail verify_pos_hash_response — old messages are silently rejected.
    #[serde(with = "sig_serde")]
    #[serde(default = "default_sig")]
    pub sig: [u8; 64],
}

/// Holder → Owner. Cannot serve the chain hash challenge (symbols missing).
/// Sent when ANY of the challenged ESIs is missing on disk.
///
/// sig covers: b"pn" (2) || challenge_id (16) || source_block_id (32) || timestamp_be (8)
/// Total: 58 bytes. Signed by holder's master identity key.
/// If sig is all-zero, the message is unsigned (old format) and will be rejected by the handler.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PosHashNackMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],
    pub source_block_id: SourceBlockId,
    /// First missing ESI (ascending sort).
    pub first_missing_esi: u32,
    pub timestamp: Timestamp,
    #[serde(default)]
    pub device_id: Option<DeviceId>,
    /// Ed25519 signature by the holder's master identity key. 64 bytes.
    /// Defaults to [0u8; 64] on deserialization (old unsigned messages) which will
    /// fail verify_pos_hash_nack — old messages are silently rejected.
    #[serde(with = "sig_serde")]
    #[serde(default = "default_sig")]
    pub sig: [u8; 64],
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
    #[serde(with = "sig_serde")]
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
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
}

/// Owner → Holder. Cancel a previously sent delete.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CancelDeleteMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub timestamp: Timestamp,
    /// Ed25519 signature. 64 bytes.
    #[serde(with = "sig_serde")]
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
///
/// sig covers: b"sd" || source_block_id || esi_ranges_cbor || timestamp_be
/// Signed by the holder's master identity key.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SymbolDroppedMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,
    pub timestamp: Timestamp,
    /// Ed25519 signature by the holder's master identity key. 64 bytes.
    /// Covers: b"sd" || source_block_id || esi_ranges_cbor || timestamp_be.
    #[serde(with = "sig_serde")]
    #[serde(default = "default_sig")]
    pub sig: [u8; 64],
}

/// Holder → Owner. Advance notice: will drop these symbols by deadline.
///
/// sig covers: SYMBOL_DROP_NOTICE_DOMAIN || CBOR((source_block_id, esi_ranges, deadline, timestamp))
/// Signed by the holder's master identity key.
/// Defaults to [0u8; 64] on deserialization (legacy/missing sig) which will
/// fail verify_symbol_drop_notice — old unsigned messages are silently rejected.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SymbolDropNoticeMsg {
    pub v: u8,
    pub source_block_id: SourceBlockId,
    pub esi_ranges: Vec<(u32, u32)>,
    /// Absolute unix timestamp when drop will occur.
    pub deadline: Timestamp,
    pub timestamp: Timestamp,
    /// Ed25519 signature by the holder's master identity key. 64 bytes.
    #[serde(with = "sig_serde")]
    #[serde(default = "default_sig")]
    pub sig: [u8; 64],
}

/// Holder → Owner. Batched advance drop notices for one owner.
///
/// Multiple `SymbolDropNoticeMsg` entries for the same owner are grouped into a single
/// mailbox entry to prevent fan-out storms during mass eviction.
/// Max payload size: `class_config::MAX_ENTRY_BYTES` (256 KB) per batch.
/// If an owner has more notices than fit in one entry, multiple entries are sent.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SymbolDropNoticeBatchMsg {
    pub v: u8,
    pub notices: Vec<SymbolDropNoticeMsg>,
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
    pub current_trust: f64,
    pub needed_trust: f64,
    pub restore_budget_gb: f64,
    pub timestamp: Timestamp,
}

/// Payload for relay board "device_revocation" broadcast.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RevocationBroadcast {
    pub revocation: crate::cluster::RevocationCertificate,
    pub device_cert: crate::cluster::DeviceCertificate,
}

/// Cluster device → cluster device. Request event log entries since last_known_seq.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClusterSyncRequestMsg {
    pub v: u8,
    pub from_device_id: crate::types::DeviceId,
    pub last_known_seq: u64,
    pub timestamp: Timestamp,
}

/// Response to ClusterSyncRequestMsg. Contains event log entries.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClusterSyncResponseMsg {
    pub v: u8,
    pub events: Vec<(u64, crate::types::EventEntry)>,
    pub responder_last_seq: u64,
    pub timestamp: Timestamp,
}

/// Generic acknowledgement. Sent as a response to one-way messages delivered
/// via libp2p request-response when the sender expects a reply to close the
/// stream (Assumption A4 in ε.2 spec).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AckMsg {
    pub v: u8,
}

// ============================================================
// Mailbox wire types (T-3)
// ============================================================

/// Sender → Postman. Store a mailbox entry for `target`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MailboxStoreRequest {
    pub v: u8,
    pub target: IdentityPub,
    pub entry: MailboxEntry,
}

/// Postman → Sender. Store response.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum MailboxStoreResponse {
    Ack {
        msg_id: [u8; 16],
    },
    Reject {
        msg_id: [u8; 16],
        reason: MailboxRejectReason,
    },
}

/// Target → Postman. Fetch all entries addressed to me.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MailboxFetchRequest {
    pub v: u8,
    /// Target = my own master_pub (fetching my own mail).
    pub target: IdentityPub,
    /// Only return entries newer than this timestamp (optional, for incremental polling).
    pub since_stored_at: Option<u64>,
}

/// Postman → Target. Fetch response.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MailboxFetchResponse {
    pub v: u8,
    pub entries: Vec<MailboxEntry>,
    /// msg_ids of entries served. Field retained for future delivery-reward accounting;
    /// no reward is computed in A2 (T-5 deferred).
    pub served_msg_ids: Vec<[u8; 16]>,
}

// ============================================================
// Top-level Message enum
// ============================================================

/// All direct-connection messages. Framed with [u32 BE len][CBOR].
///
/// The `Unknown` unit variant catches any unrecognised `"type"` tag value
/// (via `#[serde(other)]`).  It is used for graceful rolling-upgrade
/// compatibility: a node running an older protocol version decodes the
/// message successfully as `Unknown` instead of returning an
/// `io::Error`, so the libp2p stream is not closed and the peer is not
/// disconnected.  `dispatch_libp2p` already has a catch-all `other =>`
/// arm that logs a warning and sends an Ack for any unhandled variant.
///
/// `Unknown` is a decode-only sentinel and must never be *sent* on the wire.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Handshake(HandshakeMsg),
    PeerAnnounce(PeerAnnounceMsg),
    PosHashChallenge(PosHashChallengeMsg),
    PosHashResponse(PosHashResponseMsg),
    PosHashNack(PosHashNackMsg),
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
    ClusterSyncRequest(ClusterSyncRequestMsg),
    MailboxFetchRequest(MailboxFetchRequest),
    MailboxFetchResponse(MailboxFetchResponse),
    MailboxStoreRequest(MailboxStoreRequest),
    MailboxStoreResponse(MailboxStoreResponse),
    ClusterSyncResponse(ClusterSyncResponseMsg),
    Ack(AckMsg),
    /// Decode-only sentinel: any unrecognised `"type"` tag value is decoded
    /// as this variant instead of returning a deserialisation error.
    /// Must never be constructed or sent.
    #[serde(other)]
    Unknown,
}

// ============================================================
// Error type
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("cbor encode error: {0}")]
    CborEncode(String),

    #[error("cbor decode error: {0}")]
    CborDecode(String),

    #[error(
        "message too large: {size} bytes, max {}",
        crate::constants::MAX_MESSAGE_SIZE
    )]
    TooLarge { size: usize },

    #[error("frame length mismatch: prefix says {declared}, got {actual}")]
    FrameLengthMismatch { declared: u32, actual: usize },

    #[error("buffer too short for length prefix")]
    BufferTooShort,

    #[error("signature verification failed")]
    BadSignature,

    #[error("handshake timestamp too old or future: delta {delta_secs}s")]
    HandshakeStale { delta_secs: i64 },
}

// ============================================================
// Serde helpers
// ============================================================

/// Default value for optional sig fields (all-zero signature, used for backward compat).
fn default_sig() -> [u8; 64] {
    [0u8; 64]
}

// ============================================================
// CBOR helpers (local, returns MessageError)
// ============================================================

/// Serialize to CBOR bytes (no framing). For relay board payload field.
pub fn to_cbor<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, MessageError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)
        .map_err(|e| MessageError::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// Deserialize from CBOR bytes. For relay board payload field.
pub fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, MessageError> {
    ciborium::de::from_reader(bytes).map_err(|e| MessageError::CborDecode(e.to_string()))
}

// ============================================================
// Framing
// ============================================================

/// Serialize msg to CBOR and prepend u32 BE length prefix.
pub fn frame_message(msg: &Message) -> Result<Vec<u8>, MessageError> {
    let cbor = to_cbor(msg)?;
    let size = cbor.len();
    if size > MAX_MESSAGE_SIZE as usize {
        return Err(MessageError::TooLarge { size });
    }
    let len_prefix = (size as u32).to_be_bytes();
    let mut out = Vec::with_capacity(4 + size);
    out.extend_from_slice(&len_prefix);
    out.extend_from_slice(&cbor);
    Ok(out)
}

/// Parse the first framed message from buf.
/// Returns (Message, bytes_consumed).
pub fn unframe_message(buf: &[u8]) -> Result<(Message, usize), MessageError> {
    if buf.len() < 4 {
        return Err(MessageError::BufferTooShort);
    }
    let declared = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    if declared > MAX_MESSAGE_SIZE {
        return Err(MessageError::TooLarge {
            size: declared as usize,
        });
    }
    let declared_usize = declared as usize;
    let available = buf.len() - 4;
    if available < declared_usize {
        return Err(MessageError::FrameLengthMismatch {
            declared,
            actual: available,
        });
    }
    let payload = &buf[4..4 + declared_usize];
    let msg = from_cbor(payload)?;
    Ok((msg, 4 + declared_usize))
}

// ============================================================
// Handshake
// ============================================================

fn handshake_sig_input(identity_pub: &IdentityPub, timestamp: &Timestamp) -> Vec<u8> {
    let mut input = Vec::with_capacity(9 + 32 + 8);
    input.extend_from_slice(b"handshake");
    input.extend_from_slice(&identity_pub.0);
    input.extend_from_slice(&timestamp.0.to_be_bytes());
    input
}

/// Build a HandshakeMsg signed with signing_key.
///
/// The sig covers only "handshake" || identity_pub || timestamp, NOT the device_cert.
/// The cert is self-signed by master key and verified separately.
pub fn build_handshake(
    identity_pub: IdentityPub,
    timestamp: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
    device_cert: Option<crate::cluster::DeviceCertificate>,
) -> HandshakeMsg {
    let sig_input = handshake_sig_input(&identity_pub, &timestamp);
    let signature = signing_key.sign(&sig_input);
    HandshakeMsg {
        v: PROTOCOL_VERSION,
        identity_pub,
        timestamp,
        sig: signature.to_bytes(),
        device_cert,
    }
}

// ============================================================
// PeerAnnounce
// ============================================================

/// Compute the signing input for PeerAnnounceMsg.
///
/// Input: b"pa" (2) || identity_pub (32) || timestamp_be (8) || x25519_pub_or_zeroes (32)
/// Total: 74 bytes.
/// If x25519_pub is None, the last 32 bytes are [0u8; 32] (so None and Some([0u8;32]) produce
/// the same sig_input and are interchangeable for signature purposes).
pub(crate) fn peer_announce_sig_input(
    identity_pub: &IdentityPub,
    timestamp: &Timestamp,
    x25519_pub: Option<&[u8; 32]>,
) -> Vec<u8> {
    let zeroes = [0u8; 32];
    let x25519_bytes = x25519_pub.unwrap_or(&zeroes);
    let mut input = Vec::with_capacity(2 + 32 + 8 + 32);
    input.extend_from_slice(b"pa");
    input.extend_from_slice(&identity_pub.0);
    input.extend_from_slice(&timestamp.0.to_be_bytes());
    input.extend_from_slice(x25519_bytes);
    input
}

/// Build a signed PeerAnnounceMsg.
///
/// Sig covers: b"pa" || identity_pub || timestamp || x25519_pub_or_zeroes (74 bytes).
pub fn build_peer_announce(
    identity_pub: IdentityPub,
    timestamp: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
    x25519_pub: Option<[u8; 32]>,
) -> PeerAnnounceMsg {
    let sig_input = peer_announce_sig_input(&identity_pub, &timestamp, x25519_pub.as_ref());
    let signature = signing_key.sign(&sig_input);
    PeerAnnounceMsg {
        v: PROTOCOL_VERSION,
        identity_pub,
        timestamp,
        sig: signature.to_bytes(),
        x25519_pub,
    }
}

/// Verify a received PeerAnnounceMsg signature.
pub fn verify_peer_announce(msg: &PeerAnnounceMsg) -> Result<(), MessageError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&msg.identity_pub.0)
        .map_err(|_| MessageError::BadSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&msg.sig);
    let sig_input =
        peer_announce_sig_input(&msg.identity_pub, &msg.timestamp, msg.x25519_pub.as_ref());
    verifying_key
        .verify_strict(&sig_input, &signature)
        .map_err(|_| MessageError::BadSignature)?;
    Ok(())
}

// ============================================================
// Delete / CancelDelete signatures
// ============================================================

fn delete_sig_input(source_block_id: &SourceBlockId, timestamp: &Timestamp) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 32 + 8);
    v.push(b'd');
    v.extend_from_slice(&source_block_id.0);
    v.extend_from_slice(&timestamp.0.to_be_bytes());
    v
}

/// Build a signed DeleteMsg.
///
/// Sig covers: `'d' || source_block_id(32) || timestamp(8 BE)`.
pub fn build_delete_msg(
    source_block_id: SourceBlockId,
    timestamp: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
) -> DeleteMsg {
    let sig_input = delete_sig_input(&source_block_id, &timestamp);
    let sig = signing_key.sign(&sig_input).to_bytes();
    DeleteMsg {
        v: 1,
        source_block_id,
        timestamp,
        sig,
    }
}

/// Verify a DeleteMsg signature against the claimed owner identity.
pub fn verify_delete_msg(msg: &DeleteMsg, owner: &IdentityPub) -> Result<(), MessageError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&owner.0)
        .map_err(|_| MessageError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&msg.sig);
    let input = delete_sig_input(&msg.source_block_id, &msg.timestamp);
    vk.verify_strict(&input, &sig)
        .map_err(|_| MessageError::BadSignature)?;
    Ok(())
}

fn cancel_delete_sig_input(source_block_id: &SourceBlockId, timestamp: &Timestamp) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 32 + 8);
    v.push(b'c');
    v.extend_from_slice(&source_block_id.0);
    v.extend_from_slice(&timestamp.0.to_be_bytes());
    v
}

/// Build a signed CancelDeleteMsg.
///
/// Sig covers: `'c' || source_block_id(32) || timestamp(8 BE)`.
pub fn build_cancel_delete_msg(
    source_block_id: SourceBlockId,
    timestamp: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
) -> CancelDeleteMsg {
    let sig_input = cancel_delete_sig_input(&source_block_id, &timestamp);
    let sig = signing_key.sign(&sig_input).to_bytes();
    CancelDeleteMsg {
        v: 1,
        source_block_id,
        timestamp,
        sig,
    }
}

/// Verify a CancelDeleteMsg signature against the claimed owner identity.
pub fn verify_cancel_delete_msg(
    msg: &CancelDeleteMsg,
    owner: &IdentityPub,
) -> Result<(), MessageError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&owner.0)
        .map_err(|_| MessageError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&msg.sig);
    let input = cancel_delete_sig_input(&msg.source_block_id, &msg.timestamp);
    vk.verify_strict(&input, &sig)
        .map_err(|_| MessageError::BadSignature)?;
    Ok(())
}

// ============================================================
// SymbolOffer signature
// ============================================================

/// Compute the signing input for SymbolOfferMsg.
///
/// Input: b"so" (2) || source_block_id (32) || esi_ranges_cbor (N)
///     || importance_be_f64 (8) || timestamp_be_u64 (8)
fn symbol_offer_sig_input(
    source_block_id: &SourceBlockId,
    esi_ranges: &[(u32, u32)],
    importance: f64,
    timestamp: &Timestamp,
) -> Vec<u8> {
    let mut esi_cbor = Vec::new();
    ciborium::ser::into_writer(esi_ranges, &mut esi_cbor)
        .expect("CBOR encode of (u32,u32) slice is infallible");
    let mut input = Vec::with_capacity(2 + 32 + esi_cbor.len() + 8 + 8);
    input.extend_from_slice(b"so");
    input.extend_from_slice(&source_block_id.0);
    input.extend_from_slice(&esi_cbor);
    input.extend_from_slice(&importance.to_be_bytes());
    input.extend_from_slice(&timestamp.0.to_be_bytes());
    input
}

/// Build a signed SymbolOfferMsg.
///
/// `signing_key` must be the master identity signing key so the holder can
/// verify against the `from` field (which is the master identity from the handshake).
pub fn build_symbol_offer(
    msg_id: [u8; 16],
    source_block_id: SourceBlockId,
    esi_ranges: Vec<(u32, u32)>,
    importance: f64,
    timestamp: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
) -> SymbolOfferMsg {
    let sig_input = symbol_offer_sig_input(&source_block_id, &esi_ranges, importance, &timestamp);
    let sig = signing_key.sign(&sig_input).to_bytes();
    SymbolOfferMsg {
        v: PROTOCOL_VERSION,
        msg_id,
        source_block_id,
        esi_ranges,
        importance,
        timestamp,
        sig,
    }
}

/// Verify a SymbolOfferMsg signature against the claimed owner identity.
///
/// `owner` is the IdentityPub extracted from the QUIC handshake (master identity).
pub fn verify_symbol_offer(msg: &SymbolOfferMsg, owner: &IdentityPub) -> Result<(), MessageError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&owner.0)
        .map_err(|_| MessageError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&msg.sig);
    let input = symbol_offer_sig_input(
        &msg.source_block_id,
        &msg.esi_ranges,
        msg.importance,
        &msg.timestamp,
    );
    vk.verify_strict(&input, &sig)
        .map_err(|_| MessageError::BadSignature)?;
    Ok(())
}

/// Extract the cluster master identity from a handshake message.
///
/// If no device_cert is present, returns Ok(None).
/// If a cert is present, verifies it and returns Ok(Some(master_pub_key)) on success.
pub fn extract_cluster_identity(msg: &HandshakeMsg) -> Result<Option<IdentityPub>, MessageError> {
    let cert = match &msg.device_cert {
        None => return Ok(None),
        Some(c) => c,
    };

    // device_id.0 IS the device public key — it must match the identity_pub in the handshake.
    if cert.device_id.0 != msg.identity_pub.0 {
        return Err(MessageError::BadSignature);
    }

    // Verify the cert signature using the master pub key embedded in the cert.
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&cert.master_pub_key.0)
        .map_err(|_| MessageError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&cert.signature);
    let payload = device_cert_payload_for_verify(cert);
    verifying_key
        .verify_strict(&payload, &sig)
        .map_err(|_| MessageError::BadSignature)?;

    Ok(Some(cert.master_pub_key))
}

/// Reconstruct the signed payload for a DeviceCertificate (mirrors cluster::device_cert_payload).
/// Payload: device_id.0 (32 bytes) || issued_at.0.to_be_bytes() (8 bytes) = 40 bytes
fn device_cert_payload_for_verify(cert: &crate::cluster::DeviceCertificate) -> Vec<u8> {
    let mut payload = Vec::with_capacity(40);
    payload.extend_from_slice(&cert.device_id.0);
    payload.extend_from_slice(&cert.issued_at.0.to_be_bytes());
    payload
}

/// Verify a received HandshakeMsg.
pub fn verify_handshake(msg: &HandshakeMsg, now: Timestamp) -> Result<(), MessageError> {
    let msg_ts = msg.timestamp.0 as i64;
    let now_ts = now.0 as i64;
    let delta = (msg_ts - now_ts).abs();
    if delta > HANDSHAKE_FRESHNESS_SECS as i64 {
        return Err(MessageError::HandshakeStale { delta_secs: delta });
    }

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&msg.identity_pub.0)
        .map_err(|_| MessageError::BadSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&msg.sig);
    let sig_input = handshake_sig_input(&msg.identity_pub, &msg.timestamp);
    verifying_key
        .verify_strict(&sig_input, &signature)
        .map_err(|_| MessageError::BadSignature)?;

    Ok(())
}

// ============================================================
// SymbolDropped signature
// ============================================================

/// Compute the signing input for SymbolDroppedMsg.
///
/// Input: b"sd" (2) || source_block_id (32) || esi_ranges_cbor (N) || timestamp_be (8)
fn symbol_dropped_sig_input(
    source_block_id: &SourceBlockId,
    esi_ranges: &[(u32, u32)],
    timestamp: &Timestamp,
) -> Vec<u8> {
    let mut esi_cbor = Vec::new();
    ciborium::ser::into_writer(esi_ranges, &mut esi_cbor)
        .expect("CBOR encode of (u32,u32) slice is infallible");
    let mut input = Vec::with_capacity(2 + 32 + esi_cbor.len() + 8);
    input.extend_from_slice(b"sd");
    input.extend_from_slice(&source_block_id.0);
    input.extend_from_slice(&esi_cbor);
    input.extend_from_slice(&timestamp.0.to_be_bytes());
    input
}

/// Build a signed SymbolDroppedMsg.
///
/// `signing_key` must be the holder's master identity key.
pub fn build_symbol_dropped(
    source_block_id: SourceBlockId,
    esi_ranges: Vec<(u32, u32)>,
    timestamp: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
) -> SymbolDroppedMsg {
    let sig_input = symbol_dropped_sig_input(&source_block_id, &esi_ranges, &timestamp);
    let sig = signing_key.sign(&sig_input).to_bytes();
    SymbolDroppedMsg {
        v: PROTOCOL_VERSION,
        source_block_id,
        esi_ranges,
        timestamp,
        sig,
    }
}

/// Verify a SymbolDroppedMsg signature against the claimed holder identity.
///
/// `holder` is the IdentityPub of the peer who sent this message.
pub fn verify_symbol_dropped(
    msg: &SymbolDroppedMsg,
    holder: &IdentityPub,
) -> Result<(), MessageError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&holder.0)
        .map_err(|_| MessageError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&msg.sig);
    let input = symbol_dropped_sig_input(&msg.source_block_id, &msg.esi_ranges, &msg.timestamp);
    vk.verify_strict(&input, &sig)
        .map_err(|_| MessageError::BadSignature)?;
    Ok(())
}

// ============================================================
// PosHashNack signature
// ============================================================

/// Compute the signing input for PosHashNackMsg.
///
/// Input: b"pn" (2) || challenge_id (16) || source_block_id (32) || timestamp_be (8)
/// Total: 58 bytes.
fn pos_hash_nack_sig_input(
    challenge_id: &[u8; 16],
    source_block_id: &SourceBlockId,
    timestamp: &Timestamp,
) -> Vec<u8> {
    let mut input = Vec::with_capacity(2 + 16 + 32 + 8);
    input.extend_from_slice(b"pn");
    input.extend_from_slice(challenge_id);
    input.extend_from_slice(&source_block_id.0);
    input.extend_from_slice(&timestamp.0.to_be_bytes());
    input
}

/// Build a signed PosHashNackMsg.
///
/// `signing_key` must be the holder's master identity key.
/// Sig covers: b"pn" || challenge_id || source_block_id || timestamp_be (58 bytes).
pub fn build_pos_hash_nack(
    challenge_id: [u8; 16],
    source_block_id: SourceBlockId,
    first_missing_esi: u32,
    timestamp: Timestamp,
    device_id: Option<DeviceId>,
    signing_key: &ed25519_dalek::SigningKey,
) -> PosHashNackMsg {
    let sig_input = pos_hash_nack_sig_input(&challenge_id, &source_block_id, &timestamp);
    let sig = signing_key.sign(&sig_input).to_bytes();
    PosHashNackMsg {
        v: PROTOCOL_VERSION,
        challenge_id,
        source_block_id,
        first_missing_esi,
        timestamp,
        device_id,
        sig,
    }
}

/// Verify a PosHashNackMsg signature against the expected holder's master identity.
///
/// `expected_holder_master` is the IdentityPub of the peer who was originally challenged.
/// Returns Err(BadSignature) if the signature is invalid or all-zero (unsigned legacy message).
pub fn verify_pos_hash_nack(
    msg: &PosHashNackMsg,
    expected_holder_master: &IdentityPub,
) -> Result<(), MessageError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&expected_holder_master.0)
        .map_err(|_| MessageError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&msg.sig);
    let input = pos_hash_nack_sig_input(&msg.challenge_id, &msg.source_block_id, &msg.timestamp);
    vk.verify_strict(&input, &sig)
        .map_err(|_| MessageError::BadSignature)?;
    Ok(())
}

// ============================================================
// PosHashChallenge signature (owner-authenticated)
// ============================================================

/// Compute the signing input for PosHashChallengeMsg.
///
/// Input: b"pc" (2) || challenge_id (16) || source_block_id (32)
///   || CBOR(esi_ranges) || timestamp_be (8)
///
/// `esi_ranges` is encoded as canonical CBOR (deterministic for a given Vec), binding the
/// exact set of ESIs the holder is asked to compute over so a postman cannot widen the
/// work / retarget the challenge.
fn pos_hash_challenge_sig_input(
    challenge_id: &[u8; 16],
    source_block_id: &SourceBlockId,
    esi_ranges: &[(u32, u32)],
    timestamp: &Timestamp,
) -> Vec<u8> {
    let mut input = Vec::with_capacity(2 + 16 + 32 + 8 + 8 * esi_ranges.len());
    input.extend_from_slice(b"pc");
    input.extend_from_slice(challenge_id);
    input.extend_from_slice(&source_block_id.0);
    let mut cbor_ranges = Vec::new();
    ciborium::ser::into_writer(&esi_ranges, &mut cbor_ranges)
        .expect("CBOR encode of esi_ranges is infallible");
    input.extend_from_slice(&cbor_ranges);
    input.extend_from_slice(&timestamp.0.to_be_bytes());
    input
}

/// Build a signed PosHashChallengeMsg.
///
/// `signing_key` must be the OWNER's master identity key.
/// Sig covers: b"pc" || challenge_id || source_block_id || CBOR(esi_ranges) || timestamp_be.
#[allow(clippy::too_many_arguments)]
pub fn build_pos_hash_challenge(
    challenge_id: [u8; 16],
    source_block_id: SourceBlockId,
    esi_ranges: Vec<(u32, u32)>,
    timestamp: Timestamp,
    device_id: Option<DeviceId>,
    signing_key: &ed25519_dalek::SigningKey,
) -> PosHashChallengeMsg {
    let sig_input =
        pos_hash_challenge_sig_input(&challenge_id, &source_block_id, &esi_ranges, &timestamp);
    let sig = signing_key.sign(&sig_input).to_bytes();
    PosHashChallengeMsg {
        v: PROTOCOL_VERSION,
        challenge_id,
        source_block_id,
        esi_ranges,
        timestamp,
        device_id,
        sig,
    }
}

/// Verify a PosHashChallengeMsg signature against the claimed owner's master identity.
///
/// `owner_master` is the IdentityPub of the peer who published the challenge
/// (`MailboxEntry.sender`). Returns Err(BadSignature) if the signature is invalid or
/// all-zero (unsigned legacy message). The holder MUST call this before any re-encode /
/// disk work — a forged challenge with a `sender` the holder does not have the key of
/// cannot produce a valid signature.
pub fn verify_pos_hash_challenge(
    msg: &PosHashChallengeMsg,
    owner_master: &IdentityPub,
) -> Result<(), MessageError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&owner_master.0)
        .map_err(|_| MessageError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&msg.sig);
    let input = pos_hash_challenge_sig_input(
        &msg.challenge_id,
        &msg.source_block_id,
        &msg.esi_ranges,
        &msg.timestamp,
    );
    vk.verify_strict(&input, &sig)
        .map_err(|_| MessageError::BadSignature)?;
    Ok(())
}

// ============================================================
// PosHashResponse signature (holder-authenticated)
// ============================================================

/// Compute the signing input for PosHashResponseMsg.
///
/// Input: b"pr" (2) || challenge_id (16) || source_block_id (32) || chain_hash (32)
///   || timestamp_be (8). Total: 90 bytes.
fn pos_hash_response_sig_input(
    challenge_id: &[u8; 16],
    source_block_id: &SourceBlockId,
    chain_hash: &[u8; 32],
    timestamp: &Timestamp,
) -> Vec<u8> {
    let mut input = Vec::with_capacity(2 + 16 + 32 + 32 + 8);
    input.extend_from_slice(b"pr");
    input.extend_from_slice(challenge_id);
    input.extend_from_slice(&source_block_id.0);
    input.extend_from_slice(chain_hash);
    input.extend_from_slice(&timestamp.0.to_be_bytes());
    input
}

/// Build a signed PosHashResponseMsg.
///
/// `signing_key` must be the HOLDER's master identity key.
/// Sig covers: b"pr" || challenge_id || source_block_id || chain_hash || timestamp_be (90 bytes).
pub fn build_pos_hash_response(
    challenge_id: [u8; 16],
    source_block_id: SourceBlockId,
    chain_hash: [u8; 32],
    timestamp: Timestamp,
    device_id: Option<DeviceId>,
    signing_key: &ed25519_dalek::SigningKey,
) -> PosHashResponseMsg {
    let sig_input =
        pos_hash_response_sig_input(&challenge_id, &source_block_id, &chain_hash, &timestamp);
    let sig = signing_key.sign(&sig_input).to_bytes();
    PosHashResponseMsg {
        v: PROTOCOL_VERSION,
        challenge_id,
        source_block_id,
        chain_hash,
        timestamp,
        device_id,
        sig,
    }
}

/// Verify a PosHashResponseMsg signature against the expected holder's master identity.
///
/// `expected_holder_master` is the IdentityPub of the holder the owner challenged
/// (resolved from `pending.holder_id`). Returns Err(BadSignature) if the signature is
/// invalid or all-zero (unsigned legacy message). The owner MUST call this before applying
/// any Pass/Fail outcome — a forged response from a positioned postman cannot carry a valid
/// signature for the challenged holder's master key.
pub fn verify_pos_hash_response(
    msg: &PosHashResponseMsg,
    expected_holder_master: &IdentityPub,
) -> Result<(), MessageError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&expected_holder_master.0)
        .map_err(|_| MessageError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&msg.sig);
    let input = pos_hash_response_sig_input(
        &msg.challenge_id,
        &msg.source_block_id,
        &msg.chain_hash,
        &msg.timestamp,
    );
    vk.verify_strict(&input, &sig)
        .map_err(|_| MessageError::BadSignature)?;
    Ok(())
}

// ============================================================
// SymbolDropNotice signature
// ============================================================

/// Domain tag for SymbolDropNoticeMsg signing. Distinguishes this signature from
/// other Ed25519 signatures in the protocol.
const SYMBOL_DROP_NOTICE_DOMAIN: &[u8] = b"viaticum-drop-notice-v1";

/// Compute the signing payload for SymbolDropNoticeMsg.
///
/// Payload: SYMBOL_DROP_NOTICE_DOMAIN || CBOR((source_block_id, esi_ranges, deadline, timestamp))
fn symbol_drop_notice_sig_payload(
    source_block_id: &SourceBlockId,
    esi_ranges: &[(u32, u32)],
    deadline: &Timestamp,
    timestamp: &Timestamp,
) -> Vec<u8> {
    let mut payload = SYMBOL_DROP_NOTICE_DOMAIN.to_vec();
    let cbor_tuple = (source_block_id, esi_ranges, deadline, timestamp);
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&cbor_tuple, &mut cbor_bytes)
        .expect("CBOR encode of drop-notice payload is infallible");
    payload.extend_from_slice(&cbor_bytes);
    payload
}

/// Build a signed SymbolDropNoticeMsg.
///
/// `signing_key` must be the holder's master identity key.
/// Sig covers: SYMBOL_DROP_NOTICE_DOMAIN || CBOR((source_block_id, esi_ranges, deadline, timestamp)).
pub fn build_signed_symbol_drop_notice(
    source_block_id: SourceBlockId,
    esi_ranges: Vec<(u32, u32)>,
    deadline: Timestamp,
    timestamp: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
) -> SymbolDropNoticeMsg {
    let payload =
        symbol_drop_notice_sig_payload(&source_block_id, &esi_ranges, &deadline, &timestamp);
    let sig = signing_key.sign(&payload).to_bytes();
    SymbolDropNoticeMsg {
        v: PROTOCOL_VERSION,
        source_block_id,
        esi_ranges,
        deadline,
        timestamp,
        sig,
    }
}

/// Verify a SymbolDropNoticeMsg signature against the expected holder's master identity.
///
/// Returns Err(BadSignature) if the signature is invalid or all-zero (unsigned legacy message).
/// An all-zero signature is the `#[serde(default)]` value that deserialization inserts for
/// messages that predate this field — those are unconditionally rejected, which is correct:
/// A2 is a hard cut-over with no rolling upgrade.
pub fn verify_symbol_drop_notice(
    msg: &SymbolDropNoticeMsg,
    holder_master: &IdentityPub,
) -> Result<(), MessageError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&holder_master.0)
        .map_err(|_| MessageError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&msg.sig);
    let payload = symbol_drop_notice_sig_payload(
        &msg.source_block_id,
        &msg.esi_ranges,
        &msg.deadline,
        &msg.timestamp,
    );
    vk.verify_strict(&payload, &sig)
        .map_err(|_| MessageError::BadSignature)?;
    Ok(())
}

#[cfg(test)]
mod tests;
