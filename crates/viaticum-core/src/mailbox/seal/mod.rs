// Mailbox envelopes (CROWN-1, slice C1): the pure crypto core.
//
// A postman stores envelopes, never contents. Two schemes, one envelope layout:
//
// - self (class SelfPointer only): the owner seals its DR pointer to itself with
//   `self_seal_e = HKDF(seed, salt=e, "viaticum-mailbox-self-seal-v1")` and puts it
//   into the rendezvous box `address_e = pub(Ed25519(HKDF(seed, salt=e,
//   "viaticum-mailbox-rendezvous-sign-v1")))`. Both keys come from the seed and the
//   wall-clock epoch only, so DR on a clean machine derives them from the mnemonic.
//   payload = nonce (12, random) ‖ ChaCha20Poly1305(self_seal_e, nonce, AAD, SealedBody)
//
// - directed (every other class): the "X25519 stanza" of age v1 with our own info
//   string and AAD. Ephemeral-static X25519 to the recipient master's x25519 key,
//   k_msg = HKDF(ikm=X25519(esk, recipient_pub), salt=epk ‖ recipient_pub,
//   "viaticum-mailbox-directed-v1"), ChaCha20Poly1305 with a zero nonce (k_msg is
//   single-use because epk is fresh per envelope).
//   payload = epk (32) ‖ ChaCha20Poly1305(k_msg, 0^12, AAD, SealedBody)
//
// AAD = b"viaticum-mailbox-aad-v1" ‖ payload_version (1) ‖ class (1) ‖ target (32):
// moving an envelope to another box or relabelling its class breaks it. `msg_id`,
// `expires_at`, `stored_at` are deliberately outside the AAD (spec §7.3).
//
// SealedBody = CBOR { sender: Option<IdentityPub>, body: bytes }: the sender is
// named only inside the ciphertext. The directed envelope does NOT authenticate
// the sender (anyone may seal to anyone, as in age): `sender` is a claim, and every
// receiver handler must verify the inner signature of `body` against it. Nor does it
// authenticate `msg_id` / `stored_at` / `expires_at`: a postman can rewrite them, or
// plant its own openable envelope under an honest `msg_id` — so receivers must never
// dedup distinct envelopes by `msg_id` alone (C1 review W1, mailbox-i26).
//
// Spec: private/beta-planning/tasks/crown1_mailbox_encryption.md §7.2-§7.4.2.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroizing;

use super::{MailboxAddress, MailboxClass, MailboxEntry, class_config};
use crate::types::{DeviceId, IdentityPub, from_cbor_bytes, to_cbor_bytes};

#[cfg(test)]
mod tests;

// ============================================================
// Constants
// ============================================================

/// `payload_version` of a sealed entry. Version 1 = legacy plaintext CBOR.
pub const SEALED_PAYLOAD_VERSION: u8 = 2;

/// Length of one rendezvous epoch: 30 days. Deliberately NOT scaled by
/// `time_scale`: DR is a separate process without a time scale.
pub const RENDEZVOUS_EPOCH_SECS: u64 = 30 * 24 * 3600;

/// Worst-case number of bytes a sealed entry adds on top of its body, measured
/// exactly as the postman measures it (`MailboxEntry::serialized_size`, the CBOR of
/// the whole entry). A body of at most `MAX_ENTRY_BYTES - SEAL_OVERHEAD_BYTES`
/// bytes therefore always yields an entry the postman accepts by size; producers
/// that chunk (DropNotice batches) must budget their body against this, not
/// against `MAX_ENTRY_BYTES`.
///
/// Derivation (directed envelope = the larger scheme; body length L > 65535, where
/// every CBOR length header is at its 5-byte maximum; every u8 array element ≥ 24,
/// which ciborium encodes in 2 bytes; timestamps ≥ 2^32, 9 bytes):
///
/// - payload = epk 32 + Poly1305 tag 16 + SealedBody CBOR (84 + L):
///   map header 1 + `"sender"` 7 + `IdentityPub` as array(32) 2 + 64
///   + `"body"` 5 + bstr header 5 = 84.   → payload = 132 + L
/// - entry CBOR around the payload (current `MailboxEntry`, 8 fields) = 211:
///   map header 1; `"target"` 7 + array(32) 66; `"msg_id"` 7 + array(16) 33;
///   `"class"` 6 + longest variant name `"DeleteRequest"` 14; `"payload_version"`
///   16 + 1; `"payload"` 8 + bstr header 5; `"expires_at"` 11 + 9;
///   `"stored_at"` 10 + 9; `"sender"` 7 + null 1.
///
/// Total 211 + 132 = 343. The self scheme adds 211 + 12 + 16 + 19 = 258 ≤ 343.
/// The unit test `max_body_sealed_fits_entry_cap` builds exactly this worst case and
/// asserts the entry is exactly `MAX_ENTRY_BYTES`, so any change to the entry or
/// envelope layout (e.g. C4 removing the header `sender`, -8 bytes) fails the test
/// until this constant is recomputed. A new `MailboxClass` variant with a name
/// longer than 13 characters also raises the overhead: update the test's class.
pub const SEAL_OVERHEAD_BYTES: usize = 343;

/// Largest body `seal_*` accepts.
pub const MAX_SEALED_BODY_BYTES: usize = class_config::MAX_ENTRY_BYTES - SEAL_OVERHEAD_BYTES;

const RENDEZVOUS_SIGN_INFO: &[u8] = b"viaticum-mailbox-rendezvous-sign-v1";
const SELF_SEAL_INFO: &[u8] = b"viaticum-mailbox-self-seal-v1";
const DIRECTED_INFO: &[u8] = b"viaticum-mailbox-directed-v1";
const AAD_DOMAIN: &[u8] = b"viaticum-mailbox-aad-v1";

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const EPK_LEN: usize = 32;

// ============================================================
// Rendezvous epoch + keys
// ============================================================

/// Time bucket for the DR pointer rendezvous address. NOT the cluster EpochCounter:
/// DR must compute it before any state is restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RendezvousEpoch(pub u64);

impl RendezvousEpoch {
    /// The epoch containing `unix_secs`.
    pub fn at(unix_secs: u64) -> Self {
        RendezvousEpoch(unix_secs / RENDEZVOUS_EPOCH_SECS)
    }

    /// The previous epoch; `None` for epoch 0.
    pub fn prev(self) -> Option<Self> {
        self.0.checked_sub(1).map(RendezvousEpoch)
    }

    /// The next epoch.
    pub fn next(self) -> Self {
        RendezvousEpoch(self.0.saturating_add(1))
    }
}

/// Seed-derived keys for one rendezvous epoch. The only secret input is the seed:
/// nothing here is computable from `master_pub`. Identical on every device that
/// shares the mnemonic (master-scoped, P6).
pub struct RendezvousKeys {
    pub epoch: RendezvousEpoch,
    pub address: MailboxAddress,
    signing_key: ed25519_dalek::SigningKey,
    seal_key: Zeroizing<[u8; 32]>,
}

impl RendezvousKeys {
    /// `rv_sign_e = HKDF(seed, salt=e_be8, RENDEZVOUS_SIGN_INFO)` → Ed25519 secret;
    /// `address_e = pub(rv_sign_e)`; `self_seal_e = HKDF(seed, salt=e_be8, SELF_SEAL_INFO)`.
    pub fn derive(seed: &[u8], epoch: RendezvousEpoch) -> Self {
        let salt = epoch.0.to_be_bytes();
        let sign_bytes = hkdf32(seed, &salt, RENDEZVOUS_SIGN_INFO);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&sign_bytes);
        let address = MailboxAddress(signing_key.verifying_key().to_bytes());
        RendezvousKeys {
            epoch,
            address,
            signing_key,
            seal_key: hkdf32(seed, &salt, SELF_SEAL_INFO),
        }
    }

    /// Store signature (`target_sig`) of an entry addressed to this rendezvous box.
    pub fn sign_store(&self, entry: &MailboxEntry) -> [u8; 64] {
        super::sign_store(&self.signing_key, entry)
    }

    /// Read proof (`target_proof`) for this rendezvous box, bound to `requester`.
    pub fn fetch_proof(&self, requester: &DeviceId) -> [u8; 64] {
        super::sign_fetch_proof(&self.signing_key, &self.address, requester)
    }
}

impl std::fmt::Debug for RendezvousKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RendezvousKeys")
            .field("epoch", &self.epoch)
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

// ============================================================
// Sealed entry
// ============================================================

/// An entry that has been sealed. Fields are private: the only constructors are
/// `seal_self_pointer` / `seal_directed`, so holding one proves the payload is an
/// envelope (the publish path will accept only this type, AC-3).
#[derive(Debug, Clone)]
pub struct SealedMailboxEntry {
    entry: MailboxEntry,
    target_sig: Option<[u8; 64]>,
}

impl SealedMailboxEntry {
    pub fn entry(&self) -> &MailboxEntry {
        &self.entry
    }

    /// The box this envelope is addressed to.
    pub fn target(&self) -> MailboxAddress {
        self.entry.target
    }

    /// Store signature by the target's key: `Some` for SelfPointer, `None` for directed.
    pub fn target_sig(&self) -> Option<[u8; 64]> {
        self.target_sig
    }
}

/// Opened directed envelope. `sender` is the sender's CLAIM: the envelope does not
/// authenticate it; the handler must verify `body`'s own signature against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedDirected {
    pub sender: IdentityPub,
    pub body: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("body too large: {size} > {max}")]
    BodyTooLarge { size: usize, max: usize },
    #[error("unsupported payload version {0}")]
    UnsupportedVersion(u8),
    #[error("wrong class for this seal scheme: {0:?}")]
    WrongClass(MailboxClass),
    #[error("payload too short")]
    Truncated,
    #[error("low-order X25519 point")]
    LowOrderPoint,
    #[error("AEAD open failed")]
    Open,
    #[error("sealed body decode: {0}")]
    Decode(String),
    #[error("directed entry has no sender")]
    MissingSender,
}

/// Plaintext inside every envelope (serialize side, borrows the body).
#[derive(serde::Serialize)]
struct SealedBodyRef<'a> {
    sender: Option<IdentityPub>,
    #[serde(with = "serde_bytes")]
    body: &'a [u8],
}

/// Plaintext inside every envelope (deserialize side).
#[derive(serde::Deserialize)]
struct SealedBody {
    sender: Option<IdentityPub>,
    #[serde(with = "serde_bytes")]
    body: Vec<u8>,
}

// ============================================================
// Self scheme (SelfPointer)
// ============================================================

/// Seal a CBOR(SelfPointer) into the rendezvous box of `keys.epoch`, with the
/// store signature of the box key attached.
pub fn seal_self_pointer(
    keys: &RendezvousKeys,
    msg_id: [u8; 16],
    pointer_cbor: &[u8],
    expires_at: u64,
    stored_at: u64,
) -> Result<SealedMailboxEntry, SealError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    seal_self_pointer_with_nonce(keys, msg_id, pointer_cbor, expires_at, stored_at, nonce)
}

fn seal_self_pointer_with_nonce(
    keys: &RendezvousKeys,
    msg_id: [u8; 16],
    pointer_cbor: &[u8],
    expires_at: u64,
    stored_at: u64,
    nonce: [u8; NONCE_LEN],
) -> Result<SealedMailboxEntry, SealError> {
    check_body_len(pointer_cbor)?;
    let class = MailboxClass::SelfPointer;
    let plaintext = encode_sealed_body(None, pointer_cbor);
    let aad = aad(SEALED_PAYLOAD_VERSION, class, &keys.address.0);
    let payload = seal_self_raw(&keys.seal_key, nonce, &aad, &plaintext);
    let entry = envelope(keys.address, class, msg_id, payload, expires_at, stored_at);
    let target_sig = Some(keys.sign_store(&entry));
    Ok(SealedMailboxEntry { entry, target_sig })
}

/// Returns the inner CBOR(SelfPointer). Caller decodes + `verify_self_pointer`
/// (the master signature inside is what makes the pointer authentic).
pub fn open_self_pointer(
    keys: &RendezvousKeys,
    entry: &MailboxEntry,
) -> Result<Vec<u8>, SealError> {
    check_version(entry)?;
    if entry.class != MailboxClass::SelfPointer {
        return Err(SealError::WrongClass(entry.class));
    }
    let aad = aad(entry.payload_version, entry.class, &entry.target.0);
    let plaintext = open_self_raw(&keys.seal_key, &aad, &entry.payload)?;
    let body = decode_sealed_body(&plaintext)?;
    if body.sender.is_some() {
        return Err(SealError::Decode("self envelope names a sender".into()));
    }
    Ok(body.body)
}

fn seal_self_raw(key: &[u8; 32], nonce: [u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("ChaCha20-Poly1305 encrypt cannot fail for bodies below the entry cap");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn open_self_raw(key: &[u8; 32], aad: &[u8], payload: &[u8]) -> Result<Vec<u8>, SealError> {
    if payload.len() < NONCE_LEN + TAG_LEN {
        return Err(SealError::Truncated);
    }
    let (nonce, ct) = payload.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| SealError::Open)
}

// ============================================================
// Directed scheme (every class except SelfPointer)
// ============================================================

/// Seal `body` to the master whose x25519 public key is `recipient_x25519_pub`,
/// into box `target` (the recipient's master box). `sender` travels inside the
/// ciphertext only; the header `sender` stays `None`.
#[allow(clippy::too_many_arguments)]
pub fn seal_directed(
    recipient_x25519_pub: &[u8; 32],
    target: MailboxAddress,
    class: MailboxClass,
    msg_id: [u8; 16],
    sender: IdentityPub,
    body: &[u8],
    expires_at: u64,
    stored_at: u64,
) -> Result<SealedMailboxEntry, SealError> {
    let esk = StaticSecret::random_from_rng(OsRng);
    seal_directed_with_esk(
        &esk,
        recipient_x25519_pub,
        target,
        class,
        msg_id,
        sender,
        body,
        expires_at,
        stored_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn seal_directed_with_esk(
    esk: &StaticSecret,
    recipient_x25519_pub: &[u8; 32],
    target: MailboxAddress,
    class: MailboxClass,
    msg_id: [u8; 16],
    sender: IdentityPub,
    body: &[u8],
    expires_at: u64,
    stored_at: u64,
) -> Result<SealedMailboxEntry, SealError> {
    if class == MailboxClass::SelfPointer {
        return Err(SealError::WrongClass(class));
    }
    check_body_len(body)?;
    let plaintext = encode_sealed_body(Some(sender), body);
    let aad = aad(SEALED_PAYLOAD_VERSION, class, &target.0);
    let payload = seal_directed_raw(esk, recipient_x25519_pub, &aad, &plaintext)?;
    let entry = envelope(target, class, msg_id, payload, expires_at, stored_at);
    Ok(SealedMailboxEntry {
        entry,
        target_sig: None,
    })
}

/// Open a directed envelope with this master's x25519 secret.
pub fn open_directed(
    my_x25519: &StaticSecret,
    entry: &MailboxEntry,
) -> Result<OpenedDirected, SealError> {
    check_version(entry)?;
    if entry.class == MailboxClass::SelfPointer {
        return Err(SealError::WrongClass(entry.class));
    }
    let aad = aad(entry.payload_version, entry.class, &entry.target.0);
    let plaintext = open_directed_raw(my_x25519, &aad, &entry.payload)?;
    let body = decode_sealed_body(&plaintext)?;
    let sender = body.sender.ok_or(SealError::MissingSender)?;
    Ok(OpenedDirected {
        sender,
        body: body.body,
    })
}

fn seal_directed_raw(
    esk: &StaticSecret,
    recipient_pub: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    let epk = PublicKey::from(esk).to_bytes();
    let shared = esk.diffie_hellman(&PublicKey::from(*recipient_pub));
    let key = directed_key(&shared, &epk, recipient_pub)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let ct = cipher
        .encrypt(
            &Nonce::default(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("ChaCha20-Poly1305 encrypt cannot fail for bodies below the entry cap");
    let mut out = Vec::with_capacity(EPK_LEN + ct.len());
    out.extend_from_slice(&epk);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_directed_raw(
    my_secret: &StaticSecret,
    aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, SealError> {
    if payload.len() < EPK_LEN + TAG_LEN {
        return Err(SealError::Truncated);
    }
    let (epk, ct) = payload.split_at(EPK_LEN);
    let epk: [u8; EPK_LEN] = epk.try_into().expect("split_at yields EPK_LEN bytes");
    let shared = my_secret.diffie_hellman(&PublicKey::from(epk));
    let my_pub = PublicKey::from(my_secret).to_bytes();
    let key = directed_key(&shared, &epk, &my_pub)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    cipher
        .decrypt(&Nonce::default(), Payload { msg: ct, aad })
        .map_err(|_| SealError::Open)
}

/// `k_msg = HKDF(ikm=shared, salt=epk ‖ recipient_pub, DIRECTED_INFO)`. Rejects a
/// non-contributory (all-zero) shared secret, i.e. a low-order point on either side.
fn directed_key(
    shared: &SharedSecret,
    epk: &[u8; 32],
    recipient_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, SealError> {
    if !shared.was_contributory() {
        return Err(SealError::LowOrderPoint);
    }
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(epk);
    salt[32..].copy_from_slice(recipient_pub);
    Ok(hkdf32(shared.as_bytes(), &salt, DIRECTED_INFO))
}

// ============================================================
// Shared helpers
// ============================================================

/// `AAD = AAD_DOMAIN ‖ payload_version (1) ‖ class (1) ‖ target (32)`; fixed width.
fn aad(payload_version: u8, class: MailboxClass, target: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_DOMAIN.len() + 2 + 32);
    out.extend_from_slice(AAD_DOMAIN);
    out.push(payload_version);
    out.push(class.as_u8());
    out.extend_from_slice(target);
    out
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut okm[..])
        .expect("HKDF expand: 32-byte output always valid");
    okm
}

fn check_body_len(body: &[u8]) -> Result<(), SealError> {
    if body.len() > MAX_SEALED_BODY_BYTES {
        return Err(SealError::BodyTooLarge {
            size: body.len(),
            max: MAX_SEALED_BODY_BYTES,
        });
    }
    Ok(())
}

fn check_version(entry: &MailboxEntry) -> Result<(), SealError> {
    if entry.payload_version != SEALED_PAYLOAD_VERSION {
        return Err(SealError::UnsupportedVersion(entry.payload_version));
    }
    Ok(())
}

fn encode_sealed_body(sender: Option<IdentityPub>, body: &[u8]) -> Vec<u8> {
    to_cbor_bytes(&SealedBodyRef { sender, body })
}

fn decode_sealed_body(plaintext: &[u8]) -> Result<SealedBody, SealError> {
    from_cbor_bytes(plaintext).map_err(|e| SealError::Decode(e.to_string()))
}

fn envelope(
    target: MailboxAddress,
    class: MailboxClass,
    msg_id: [u8; 16],
    payload: Vec<u8>,
    expires_at: u64,
    stored_at: u64,
) -> MailboxEntry {
    MailboxEntry {
        target,
        msg_id,
        class,
        payload_version: SEALED_PAYLOAD_VERSION,
        payload,
        expires_at,
        stored_at,
        sender: None,
    }
}
