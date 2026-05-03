use crate::constants::{
    DIRECTED_ENCRYPTION_INFO, HANDSHAKE_FRESHNESS_SECS, MAX_MESSAGE_SIZE, MAX_RELAY_HOP,
    PROTOCOL_VERSION, RELAY_TTL_SECS,
};
use crate::erasure::Symbol;
use crate::types::{sig_serde, DeviceId, IdentityPub, SourceBlockId, Timestamp};
use chacha20poly1305::aead::{AeadInPlace, NewAead};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::Signer;
use hkdf::Hkdf;
use sha2::Sha256;

// ============================================================
// Message structs
// ============================================================

/// Sent in both directions at connection open on ALPN "syncback/1".
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
    /// Ed25519 signature of identity_pub || timestamp. 64 bytes.
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
    /// X25519 public key for directed relay board encryption.
    /// Not covered by sig — informational field only.
    #[serde(default)]
    pub x25519_pub: Option<[u8; 32]>,
}

/// Owner → Holder. Block-level chain hash challenge.
/// Covers all ESI ranges for this holder for this source block.
/// Response: holder computes SHA256-chain over all bound symbols (ESIs sorted ascending).
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
}

/// Holder → Owner. Response to PosHashChallengeMsg.
/// chain_hash = SHA256-chain over bound symbol data for all assigned ESIs (sorted ascending):
///   h0 = [0u8; 32], h_i = SHA256(h_{i-1} || symbol[esi_i]), chain_hash = h_n
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PosHashResponseMsg {
    pub v: u8,
    pub challenge_id: [u8; 16],
    /// Chain hash over all assigned ESIs.
    pub chain_hash: [u8; 32],
    pub timestamp: Timestamp,
    #[serde(default)]
    pub device_id: Option<DeviceId>,
}

/// Holder → Owner. Cannot serve the chain hash challenge (symbols missing).
/// Sent when ANY of the challenged ESIs is missing on disk.
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

/// Owner → Holder. Push encrypted DB snapshot for safekeeping.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SystemStateBackupMsg {
    pub v: u8,
    #[serde(with = "serde_bytes")]
    pub encrypted_blob: Vec<u8>,
    pub timestamp: Timestamp,
}

/// Holder → Owner. Acknowledge receipt of system state backup.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SystemStateAckMsg {
    pub v: u8,
    pub stored: bool,
    pub timestamp: Timestamp,
}

/// Requester → Holder. Request stored system state blob. Identity from handshake.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SystemStateRequestMsg {
    pub v: u8,
    pub timestamp: Timestamp,
}

/// Holder → Requester. Return stored blob (empty vec = not found).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SystemStateResponseMsg {
    pub v: u8,
    #[serde(with = "serde_bytes")]
    pub encrypted_blob: Vec<u8>,
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
// Top-level Message enum
// ============================================================

/// All direct-connection messages. Framed with [u32 BE len][CBOR].
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
    BoardSync(BoardSyncMsg),
    ClusterSyncRequest(ClusterSyncRequestMsg),
    ClusterSyncResponse(ClusterSyncResponseMsg),
    SystemStateBackup(SystemStateBackupMsg),
    SystemStateAck(SystemStateAckMsg),
    SystemStateRequest(SystemStateRequestMsg),
    SystemStateResponse(SystemStateResponseMsg),
    Ack(AckMsg),
}

// ============================================================
// Relay board types
// ============================================================

/// One entry stored in the board file (on disk) or exchanged during board sync.
///
/// Wraps a [`BoardEntry`] with its identifying metadata so the board file and
/// wire format carry a self-contained, independently verifiable record.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredEntry {
    /// Type string (e.g. "pos_challenge", "peer_announce").
    pub msg_type: String,
    /// 16-byte unique ID.
    pub msg_id: [u8; 16],
    /// The board entry itself.
    pub entry: BoardEntry,
}

/// Batch of relay board entries exchanged on connection setup.
///
/// Sent as the first message after handshake to let each peer populate its
/// board with entries it may have missed while offline. Old nodes that do not
/// recognise the `BoardSync` variant will log an unknown-variant decode error
/// and skip it — no connection is terminated.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BoardSyncMsg {
    pub v: u8,
    pub entries: Vec<StoredEntry>,
    pub timestamp: Timestamp,
}

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
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    /// Ed25519 sig over: type_str || msg_id || kind_str || target_pub_or_empty || payload.
    /// Signed by original author (preserved by relay nodes — never re-signed).
    #[serde(with = "sig_serde")]
    pub sig_author: [u8; 64],
    /// Author's identity_pub (needed to verify sig_author).
    pub author: IdentityPub,
    /// Hop count. Original entry = 0. Each relay copy increments by 1.
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

// ============================================================
// Error type
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("cbor encode error: {0}")]
    CborEncode(String),

    #[error("cbor decode error: {0}")]
    CborDecode(String),

    #[error("message too large: {size} bytes, max {}", crate::constants::MAX_MESSAGE_SIZE)]
    TooLarge { size: usize },

    #[error("frame length mismatch: prefix says {declared}, got {actual}")]
    FrameLengthMismatch { declared: u32, actual: usize },

    #[error("buffer too short for length prefix")]
    BufferTooShort,

    #[error("signature verification failed")]
    BadSignature,

    #[error("handshake timestamp too old or future: delta {delta_secs}s")]
    HandshakeStale { delta_secs: i64 },

    #[error("directed encryption error: {0}")]
    EncryptionError(String),

    #[error("relay hop limit exceeded: hop={hop}")]
    HopLimitExceeded { hop: u8 },
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
        return Err(MessageError::TooLarge { size: declared as usize });
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

fn peer_announce_sig_input(identity_pub: &IdentityPub, timestamp: &Timestamp) -> Vec<u8> {
    let mut input = Vec::with_capacity(32 + 8);
    input.extend_from_slice(&identity_pub.0);
    input.extend_from_slice(&timestamp.0.to_be_bytes());
    input
}

/// Build a signed PeerAnnounceMsg.
///
/// The sig covers identity_pub || timestamp.
/// `x25519_pub` is NOT part of the signature — it is an informational field.
pub fn build_peer_announce(
    identity_pub: IdentityPub,
    timestamp: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
    x25519_pub: Option<[u8; 32]>,
) -> PeerAnnounceMsg {
    let sig_input = peer_announce_sig_input(&identity_pub, &timestamp);
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
    let sig_input = peer_announce_sig_input(&msg.identity_pub, &msg.timestamp);
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
pub fn extract_cluster_identity(
    msg: &HandshakeMsg,
) -> Result<Option<IdentityPub>, MessageError> {
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
// Directed encryption
// ============================================================

/// Encrypt a directed payload for target_pub.
///
/// Generates an ephemeral X25519 keypair internally for forward secrecy.
/// The ephemeral public key is embedded in the envelope for the recipient.
pub fn encrypt_directed(
    plaintext: &[u8],
    target_x25519_pub: &x25519_dalek::PublicKey,
) -> Result<DirectedEnvelope, MessageError> {
    use rand::rngs::OsRng;
    let ephemeral_priv = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral_priv);
    let shared = ephemeral_priv.diffie_hellman(target_x25519_pub);

    let chacha_key = derive_chacha_key(
        shared.as_bytes(),
        &ephemeral_pub.to_bytes(),
        &target_x25519_pub.to_bytes(),
    )?;
    let cipher = ChaCha20Poly1305::new(&chacha_key.into());

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = chacha20poly1305::Nonce::from(nonce_bytes);

    let mut buffer = plaintext.to_vec();
    cipher
        .encrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|e| MessageError::EncryptionError(e.to_string()))?;

    Ok(DirectedEnvelope {
        sender_x25519_pub: ephemeral_pub.to_bytes(),
        nonce: nonce_bytes,
        ciphertext: buffer,
    })
}

/// Decrypt a directed payload.
pub fn decrypt_directed(
    envelope: &DirectedEnvelope,
    own_x25519_priv: &x25519_dalek::StaticSecret,
) -> Result<Vec<u8>, MessageError> {
    let sender_pub = x25519_dalek::PublicKey::from(envelope.sender_x25519_pub);
    let own_pub = x25519_dalek::PublicKey::from(own_x25519_priv);
    let shared = own_x25519_priv.diffie_hellman(&sender_pub);

    let chacha_key = derive_chacha_key(
        shared.as_bytes(),
        &envelope.sender_x25519_pub,
        &own_pub.to_bytes(),
    )?;
    let cipher = ChaCha20Poly1305::new(&chacha_key.into());

    let nonce = chacha20poly1305::Nonce::from(envelope.nonce);

    let mut buffer = envelope.ciphertext.clone();
    cipher
        .decrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|e| MessageError::EncryptionError(e.to_string()))?;

    Ok(buffer)
}

/// HKDF with salt = sender_pub || receiver_pub for standard ECIES security.
fn derive_chacha_key(
    shared_bytes: &[u8],
    sender_pub: &[u8; 32],
    receiver_pub: &[u8; 32],
) -> Result<[u8; 32], MessageError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(sender_pub);
    salt[32..].copy_from_slice(receiver_pub);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_bytes);
    let mut okm = [0u8; 32];
    hk.expand(DIRECTED_ENCRYPTION_INFO, &mut okm)
        .map_err(|e| MessageError::EncryptionError(e.to_string()))?;
    Ok(okm)
}

// ============================================================
// Board entry helpers
// ============================================================

fn board_entry_sig_input(
    msg_type: &str,
    msg_id: &[u8; 16],
    kind: BoardEntryKind,
    target_pub: Option<&IdentityPub>,
    payload: &[u8],
) -> Vec<u8> {
    let kind_str: &[u8] = match kind {
        BoardEntryKind::Broadcast => b"broadcast",
        BoardEntryKind::Directed => b"directed",
    };
    let mut input = Vec::new();
    input.extend_from_slice(msg_type.as_bytes());
    input.extend_from_slice(msg_id);
    input.extend_from_slice(kind_str);
    if let Some(tp) = target_pub {
        input.extend_from_slice(&tp.0);
    }
    input.extend_from_slice(payload);
    input
}

/// Build and sign a broadcast BoardEntry.
pub fn build_broadcast_entry(
    msg_type: &str,
    msg_id: [u8; 16],
    payload: Vec<u8>,
    author: IdentityPub,
    now: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
) -> BoardEntry {
    let sig_input =
        board_entry_sig_input(msg_type, &msg_id, BoardEntryKind::Broadcast, None, &payload);
    let signature = signing_key.sign(&sig_input);
    BoardEntry {
        kind: BoardEntryKind::Broadcast,
        target_pub: None,
        payload,
        sig_author: signature.to_bytes(),
        author,
        hop: 0,
        created_at: now,
    }
}

/// Build and sign a directed BoardEntry (payload already encrypted by caller).
pub fn build_directed_entry(
    msg_type: &str,
    msg_id: [u8; 16],
    target_pub: IdentityPub,
    encrypted_payload: Vec<u8>,
    author: IdentityPub,
    now: Timestamp,
    signing_key: &ed25519_dalek::SigningKey,
) -> BoardEntry {
    let sig_input = board_entry_sig_input(
        msg_type,
        &msg_id,
        BoardEntryKind::Directed,
        Some(&target_pub),
        &encrypted_payload,
    );
    let signature = signing_key.sign(&sig_input);
    BoardEntry {
        kind: BoardEntryKind::Directed,
        target_pub: Some(target_pub),
        payload: encrypted_payload,
        sig_author: signature.to_bytes(),
        author,
        hop: 0,
        created_at: now,
    }
}

/// Verify a board entry's signature.
pub fn verify_board_entry_sig(
    entry: &BoardEntry,
    msg_type: &str,
    msg_id: &[u8; 16],
) -> Result<(), MessageError> {
    let sig_input = board_entry_sig_input(
        msg_type,
        msg_id,
        entry.kind,
        entry.target_pub.as_ref(),
        &entry.payload,
    );
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&entry.author.0)
        .map_err(|_| MessageError::BadSignature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&entry.sig_author);
    verifying_key
        .verify_strict(&sig_input, &signature)
        .map_err(|_| MessageError::BadSignature)?;
    Ok(())
}

/// Check if a board entry has expired (created_at + RELAY_TTL_SECS <= now).
pub fn is_board_entry_expired(entry: &BoardEntry, now: Timestamp) -> bool {
    entry.created_at.0.saturating_add(RELAY_TTL_SECS) <= now.0
}

/// Check if this entry can be relayed further (hop < MAX_RELAY_HOP).
pub fn check_relay_hop(entry: &BoardEntry) -> Result<(), MessageError> {
    if entry.hop >= MAX_RELAY_HOP {
        return Err(MessageError::HopLimitExceeded { hop: entry.hop });
    }
    Ok(())
}

/// Produce a relay copy of an entry with hop incremented by 1.
pub fn relay_copy(entry: &BoardEntry) -> BoardEntry {
    BoardEntry {
        hop: entry.hop + 1,
        ..entry.clone()
    }
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
pub fn verify_symbol_dropped(msg: &SymbolDroppedMsg, holder: &IdentityPub) -> Result<(), MessageError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&holder.0)
        .map_err(|_| MessageError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&msg.sig);
    let input = symbol_dropped_sig_input(&msg.source_block_id, &msg.esi_ranges, &msg.timestamp);
    vk.verify_strict(&input, &sig)
        .map_err(|_| MessageError::BadSignature)?;
    Ok(())
}

#[cfg(test)]
mod tests;
