use crate::constants::{HANDSHAKE_FRESHNESS_SECS, MAX_MESSAGE_SIZE, PROTOCOL_VERSION};
use crate::types::{IdentityPub, ShardId, UnitId};

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signer, Verifier};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// --- Error enum ---

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

// --- MsgId ---

/// 32-byte message identifier, derived as blake3(payload_bytes || timestamp_le_bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MsgId(pub [u8; 32]);

impl MsgId {
    /// Derive a MsgId from payload bytes and a unix timestamp (seconds).
    pub fn derive(payload: &[u8], timestamp: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(payload);
        hasher.update(&timestamp.to_le_bytes());
        MsgId(*hasher.finalize().as_bytes())
    }

    /// Hex-encode for use in board keys.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// --- Signature newtype ---

/// Ed25519 signature, 64 bytes.
/// Serializes as CBOR bytes.
#[derive(Debug, Clone)]
pub struct Signature(pub [u8; 64]);

impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct BytesVisitor;
        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Signature;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "64 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Signature, E> {
                let arr: [u8; 64] = v
                    .try_into()
                    .map_err(|_| E::invalid_length(v.len(), &"64"))?;
                Ok(Signature(arr))
            }
        }
        d.deserialize_bytes(BytesVisitor)
    }
}

// --- EntryKind ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    Broadcast,
    Directed,
}

// --- BoardEntry ---

/// An entry on a node's iroh-docs board.
/// key: "{type}/{msg_id}"  (e.g. "shard_offer/abcd1234...")
/// value: serialized BoardEntry (CBOR bytes)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BoardEntry {
    pub kind: EntryKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pub: Option<IdentityPub>,
    pub payload: Vec<u8>,
    pub sig_author: Signature,
}

// --- RelayEntry ---

/// A relay copy of a foreign board entry.
/// Board key: "relay/{author_hex}/{msg_id}"
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayEntry {
    pub author: IdentityPub,
    pub msg_id: MsgId,
    pub hop: u8,
    pub entry: BoardEntry,
}

// --- DirectMessage ---

/// A framed message for direct QUIC connections (ALPN "syncback/1").
/// Wire format: [u32 BE length][CBOR bytes of DirectMessage]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DirectMessage {
    pub v: u8,
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

// --- EncryptedPayload ---

/// ECDH-encrypted payload for directed board entries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedPayload {
    pub ephemeral_pub: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedPayload {
    /// Serialize to CBOR bytes (for BoardEntry.payload field).
    pub fn to_cbor(&self) -> Vec<u8> {
        to_cbor(self).expect("EncryptedPayload serializes cleanly")
    }

    /// Deserialize from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, MessageError> {
        from_cbor(bytes)
    }
}

// --- FileType ---

/// Whether a shard belongs to user data or the system state backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    User,
    System,
}

// --- Board messages ---

/// Posted to the author's own board.
/// Board key: "peer_announce/{msg_id}". Kind: Broadcast.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerAnnounceMsg {
    pub v: u8,
    pub identity_pub: IdentityPub,
    pub node_addr: Vec<u8>,
    pub ts: u64,
}

/// Owner → Holder. Requests a proof-of-storage for a specific shard.
/// Board key: "pos_challenge/{msg_id}". Kind: Directed, target = holder.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PosChallengeMsg {
    pub v: u8,
    pub challenge_id: [u8; 32],
    pub shard_id: ShardId,
    pub unit_id: UnitId,
    pub shard_index: u8,
    pub block_range: (u32, u32),
    pub nonce: [u8; 32],
    pub ts: u64,
}

/// Holder → Challenger. Responds with proof.
/// Board key: "pos_response/{msg_id}". Kind: Directed, target = challenger.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PosResponseMsg {
    pub v: u8,
    pub challenge_id: [u8; 32],
    pub block_data_hash: [u8; 32],
    pub merkle_proof: Vec<[u8; 32]>,
    pub ts: u64,
}

/// Owner → Holder. Offers a shard for storage.
/// Board key: "shard_offer/{msg_id}". Kind: Directed, target = holder.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardOfferMsg {
    pub v: u8,
    pub descriptor: SignedShardDescriptor,
    pub ts: u64,
}

/// Holder → Owner. Accepts a shard offer.
/// Board key: "shard_accept/{msg_id}". Kind: Directed, target = owner.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardAcceptMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub offer_msg_id: MsgId,
    pub ts: u64,
}

/// Holder → Owner. Rejects a shard offer or received blob.
/// Board key: "shard_reject/{msg_id}". Kind: Directed, target = owner.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardRejectMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub offer_msg_id: MsgId,
    pub reason: RejectReason,
    pub ts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    Full,
    HashMismatch,
    NotAllowed,
    LowPriority,
    Expired,
}

/// Holder → Owner. Confirms shard received and stored.
/// Board key: "shard_stored/{msg_id}". Kind: Directed, target = owner.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardStoredMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub ts: u64,
}

/// Owner → Holder. Requests deletion of a shard after cooldown.
/// Board key: "delete/{msg_id}". Kind: Directed, target = holder.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeleteMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub ts: u64,
}

/// Owner → Holder. Cancels a previously sent delete request.
/// Board key: "cancel_delete/{msg_id}". Kind: Directed, target = holder.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CancelDeleteMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub ts: u64,
}

/// Challenger → Holder. Notifies holder that a shard may be corrupted.
/// Board key: "storage_warning/{msg_id}". Kind: Directed, target = holder.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageWarningMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub details: String,
    pub ts: u64,
}

/// Holder → Owner. Notifies owner that a shard was evicted immediately (Phase 1).
/// Board key: "shard_dropped/{msg_id}". Kind: Directed, target = owner.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardDroppedMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub ts: u64,
}

/// Holder → Owner. 7-day advance notice before eviction (Phase 2).
/// Board key: "shard_drop_notice/{msg_id}". Kind: Directed, target = owner.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardDropNoticeMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub deadline: u64,
    pub ts: u64,
}

/// Holder → Owner. Sent when escrow check fails during restore.
/// Board key: "restore_denied/{msg_id}". Kind: Directed, target = owner.
/// Also exists as a DirectBody variant.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RestoreDeniedMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub reason: DenyReason,
    pub required_weeks: u32,
    pub current_weeks: u32,
    pub ts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    EscrowNotMet,
    NotFound,
    InCooldown,
}

// --- Direct connection messages ---

/// Sent by both sides at connection open.
/// DirectBody::Handshake(HandshakeMsg).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HandshakeMsg {
    pub v: u8,
    pub identity_pub: IdentityPub,
    pub timestamp: u64,
    pub sig_author: Signature,
}

impl HandshakeMsg {
    /// Create and sign a handshake message.
    /// signed_data = b"handshake" || identity_pub.0 || timestamp.to_le_bytes()
    pub fn new(
        identity_pub: IdentityPub,
        timestamp: u64,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        let signed_data = handshake_signed_data(&identity_pub, timestamp);
        let sig = signing_key.sign(&signed_data);
        HandshakeMsg {
            v: PROTOCOL_VERSION,
            identity_pub,
            timestamp,
            sig_author: Signature(sig.to_bytes()),
        }
    }

    /// Verify the handshake signature.
    pub fn verify(&self) -> Result<(), MessageError> {
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&self.identity_pub.0)
            .map_err(|_| MessageError::InvalidSignature)?;
        let signed_data = handshake_signed_data(&self.identity_pub, self.timestamp);
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig_author.0);
        verifying_key
            .verify(&signed_data, &sig)
            .map_err(|_| MessageError::InvalidSignature)
    }

    /// Check timestamp freshness. Returns Err if |now - self.timestamp| > 300.
    pub fn check_freshness(&self, now_secs: u64) -> Result<(), MessageError> {
        let delta = now_secs.abs_diff(self.timestamp);
        if delta > HANDSHAKE_FRESHNESS_SECS {
            return Err(MessageError::StaleTimestamp { delta_secs: delta });
        }
        Ok(())
    }
}

fn handshake_signed_data(identity_pub: &IdentityPub, timestamp: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(b"handshake".len() + 32 + 8);
    data.extend_from_slice(b"handshake");
    data.extend_from_slice(&identity_pub.0);
    data.extend_from_slice(&timestamp.to_le_bytes());
    data
}

/// Owner → Holder. Requests a specific shard blob over direct connection.
/// DirectBody::RestoreRequest(RestoreRequestMsg).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RestoreRequestMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub ts: u64,
}

/// Holder → Owner. Signals that the blob is available for iroh-blobs pull.
/// DirectBody::BlobReady(BlobReadyMsg).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlobReadyMsg {
    pub v: u8,
    pub shard_id: ShardId,
    pub ts: u64,
}

// --- SignedShardDescriptor ---

/// Signed descriptor attached to a shard. Sent in shard_offer messages.
/// Uses f32 importance (deterministic CBOR across platforms) and Signature newtype.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedShardDescriptor {
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
    pub sig_owner: Signature,
}

/// The unsigned fields of SignedShardDescriptor (for signature computation).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedShardDescriptorUnsigned {
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

impl SignedShardDescriptor {
    /// Sign a descriptor. The signing key must belong to owner_pub.
    pub fn sign(
        unsigned: SignedShardDescriptorUnsigned,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<SignedShardDescriptor, MessageError> {
        let cbor = to_cbor(&unsigned)?;
        let sig = signing_key.sign(&cbor);
        Ok(SignedShardDescriptor {
            shard_id: unsigned.shard_id,
            unit_id: unsigned.unit_id,
            shard_index: unsigned.shard_index,
            k: unsigned.k,
            n: unsigned.n,
            merkle_root: unsigned.merkle_root,
            owner_pub: unsigned.owner_pub,
            importance: unsigned.importance,
            file_type: unsigned.file_type,
            created_at: unsigned.created_at,
            sig_owner: Signature(sig.to_bytes()),
        })
    }

    /// Verify the owner's signature on this descriptor.
    pub fn verify_sig(&self) -> Result<(), MessageError> {
        let unsigned = SignedShardDescriptorUnsigned {
            shard_id: self.shard_id,
            unit_id: self.unit_id,
            shard_index: self.shard_index,
            k: self.k,
            n: self.n,
            merkle_root: self.merkle_root,
            owner_pub: self.owner_pub,
            importance: self.importance,
            file_type: self.file_type,
            created_at: self.created_at,
        };
        let cbor = to_cbor(&unsigned)?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&self.owner_pub.0)
            .map_err(|_| MessageError::InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&self.sig_owner.0);
        verifying_key
            .verify(&cbor, &sig)
            .map_err(|_| MessageError::InvalidSignature)
    }

    /// Verify that blake3(blob) == self.shard_id.
    pub fn verify_blob(&self, blob: &[u8]) -> Result<(), MessageError> {
        let hash = blake3::hash(blob);
        if hash.as_bytes() != &self.shard_id.0 {
            return Err(MessageError::BlobHashMismatch);
        }
        Ok(())
    }
}

// --- Signing and verification for board entries ---

/// Sign a board entry.
/// signed_data = type_bytes || msg_id.0 || kind_byte || target_pub_bytes || payload_bytes
pub fn sign_entry(
    msg_type: &str,
    msg_id: MsgId,
    kind: EntryKind,
    target_pub: Option<&IdentityPub>,
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
) -> Signature {
    let data = entry_signed_data(msg_type, msg_id, kind, target_pub, payload);
    let sig = signing_key.sign(&data);
    Signature(sig.to_bytes())
}

/// Verify a board entry signature.
pub fn verify_entry(
    msg_type: &str,
    msg_id: MsgId,
    entry: &BoardEntry,
    author_pub: &IdentityPub,
) -> Result<(), MessageError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&author_pub.0)
        .map_err(|_| MessageError::InvalidSignature)?;
    let data = entry_signed_data(
        msg_type,
        msg_id,
        entry.kind,
        entry.target_pub.as_ref(),
        &entry.payload,
    );
    let sig = ed25519_dalek::Signature::from_bytes(&entry.sig_author.0);
    verifying_key
        .verify(&data, &sig)
        .map_err(|_| MessageError::InvalidSignature)
}

fn entry_signed_data(
    msg_type: &str,
    msg_id: MsgId,
    kind: EntryKind,
    target_pub: Option<&IdentityPub>,
    payload: &[u8],
) -> Vec<u8> {
    let kind_byte: u8 = match kind {
        EntryKind::Broadcast => 0x00,
        EntryKind::Directed => 0x01,
    };
    let target_bytes: [u8; 32] = match target_pub {
        Some(t) => t.0,
        None => [0u8; 32],
    };
    let mut data = Vec::new();
    data.extend_from_slice(msg_type.as_bytes());
    data.extend_from_slice(&msg_id.0);
    data.push(kind_byte);
    data.extend_from_slice(&target_bytes);
    data.extend_from_slice(payload);
    data
}

// --- ECDH encryption/decryption ---

/// Encrypt a CBOR payload for a directed recipient.
///
/// Algorithm:
///   1. Generate ephemeral X25519 keypair.
///   2. shared = X25519(ephemeral_priv, recipient_x25519_pub)
///   3. key = HKDF-SHA256(shared, salt="", info="syncback-directed")  [32 bytes]
///   4. nonce = random 12 bytes
///   5. ciphertext = ChaCha20-Poly1305(key, nonce, plaintext)
pub fn encrypt_payload(
    plaintext: &[u8],
    recipient_x25519_pub: &[u8; 32],
) -> Result<EncryptedPayload, MessageError> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pub_key = PublicKey::from(&ephemeral_secret);
    let recipient_pub = PublicKey::from(*recipient_x25519_pub);
    let shared = ephemeral_secret.diffie_hellman(&recipient_pub);

    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key_bytes = [0u8; 32];
    hk.expand(crate::constants::DIRECTED_ENCRYPTION_INFO, &mut key_bytes)
        .expect("HKDF expand always succeeds for 32-byte output");

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| MessageError::Encryption(e.to_string()))?;

    Ok(EncryptedPayload {
        ephemeral_pub: ephemeral_pub_key.to_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt a directed payload.
///
/// Algorithm (inverse of encrypt_payload):
///   1. shared = X25519(recipient_priv, ephemeral_pub)
///   2. key = HKDF-SHA256(shared, salt="", info="syncback-directed")
///   3. plaintext = ChaCha20-Poly1305::decrypt(key, nonce, ciphertext)
pub fn decrypt_payload(
    encrypted: &EncryptedPayload,
    recipient_x25519_priv: &[u8; 32],
) -> Result<Vec<u8>, MessageError> {
    let recipient_secret = StaticSecret::from(*recipient_x25519_priv);
    let ephemeral_pub = PublicKey::from(encrypted.ephemeral_pub);
    let shared = recipient_secret.diffie_hellman(&ephemeral_pub);

    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key_bytes = [0u8; 32];
    hk.expand(crate::constants::DIRECTED_ENCRYPTION_INFO, &mut key_bytes)
        .expect("HKDF expand always succeeds for 32-byte output");

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&encrypted.nonce);

    cipher
        .decrypt(nonce, encrypted.ciphertext.as_slice())
        .map_err(|_| MessageError::Decryption)
}

// --- Wire framing ---

/// Serialize a DirectMessage to framed wire bytes: [u32 BE length][CBOR payload].
/// Errors if CBOR payload > 65535 bytes (64 KB DoS limit).
pub fn frame_message(msg: &DirectMessage) -> Result<Vec<u8>, MessageError> {
    let cbor = to_cbor(msg)?;
    if cbor.len() > MAX_MESSAGE_SIZE as usize {
        return Err(MessageError::TooLarge { size: cbor.len() });
    }
    let mut out = Vec::with_capacity(4 + cbor.len());
    out.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
    out.extend_from_slice(&cbor);
    Ok(out)
}

/// Parse one framed message from a byte slice.
/// Returns (DirectMessage, bytes_consumed).
/// Errors if length prefix > 65535 or CBOR parsing fails.
pub fn parse_framed(buf: &[u8]) -> Result<(DirectMessage, usize), MessageError> {
    if buf.len() < 4 {
        return Err(MessageError::BufferTooShort {
            need: 4,
            have: buf.len(),
        });
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_MESSAGE_SIZE as usize {
        return Err(MessageError::TooLarge { size: len });
    }
    let total = 4 + len;
    if buf.len() < total {
        return Err(MessageError::BufferTooShort {
            need: total,
            have: buf.len(),
        });
    }
    let msg = from_cbor::<DirectMessage>(&buf[4..total])?;
    Ok((msg, total))
}

// --- CBOR helpers ---

/// Serialize any serde-serializable value to CBOR bytes.
pub fn to_cbor<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, MessageError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| MessageError::CborSerialize(e.to_string()))?;
    Ok(buf)
}

/// Deserialize from CBOR bytes.
pub fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, MessageError> {
    ciborium::from_reader(bytes).map_err(|e| MessageError::CborDeserialize(e.to_string()))
}


#[cfg(test)]
mod tests;
