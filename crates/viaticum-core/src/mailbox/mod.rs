// Mailbox: unified store-and-forward primitive for async P2P messaging.
// T-1: types + redb storage + TTL/cleanup.
//
// Design: each MailboxEntry is addressed to a target (owner master_pub).
// Postman nodes store entries on behalf of the target (write-fanout),
// target nodes poll for their own entries (read-fanout).
// See A2 spec §2.2 for full design.

use crate::db::{Db, DbError};
use crate::types::{DeviceId, IdentityPub, hex_encode};

pub mod seal;

// ============================================================
// Per-class configuration
// ============================================================

/// Per-message-class limits and defaults.
pub mod class_config {
    use std::time::Duration;

    pub const POS_CHALLENGE_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
    pub const DROP_NOTICE_TTL: Duration = Duration::from_secs(14 * 24 * 3600);
    pub const SELF_POINTER_TTL: Duration = Duration::from_secs(5 * 365 * 24 * 3600);
    pub const UNKNOWN_SENDER_TTL: Duration = Duration::from_secs(90 * 24 * 3600);
    /// Delete/CancelDelete request TTL = 14 days.
    ///
    /// Deletion is not time-critical (owner has already started its cooldown clock)
    /// but the holder must see it before the holder-side cooldown window closes.
    /// 14 days matches DROP_NOTICE_TTL; both are bounded by the same deletion
    /// cooldown clocks (OWNER_DELETE_COOLDOWN_SECS + HOLDER_DELETE_COOLDOWN_SECS).
    pub const DELETE_REQUEST_TTL: Duration = Duration::from_secs(14 * 24 * 3600);
    /// Device revocation notice TTL = 30 days.
    ///
    /// Delivery window for currently-offline storage peers. 30 days is generous
    /// relative to the cold-backup time constant (1 week), so peers that come back
    /// within a month learn about the revocation before doing any sensitive work.
    ///
    /// Known limitation: a storage-peer offline > 30 days misses the revocation.
    /// This is the same gap that the old relay broadcast had past RELAY_TTL.
    /// Complete fix = future pull-on-verify (receiver queries sender's revocation list
    /// on connection), tracked as a separate future task.
    pub const REVOCATION_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
    /// Hard cap per entry: 256 KB.
    pub const MAX_ENTRY_BYTES: usize = 256 * 1024;
    /// Global mailbox quota per target: 100 MB.
    pub const MAX_MAILBOX_BYTES_PER_PEER: u64 = 100 * 1024 * 1024;

    // P1-5: pin each named TTL to its intended value at compile time. These guard
    // the source-of-truth constants themselves: `MailboxClass::default_ttl_secs`
    // delegates here, so if a literal below is changed by accident the named
    // contract (e.g. "SelfPointer = 5 years") is enforced rather than silently
    // drifting.
    const _: () = assert!(SELF_POINTER_TTL.as_secs() == 5 * 365 * 24 * 3600);
    const _: () = assert!(POS_CHALLENGE_TTL.as_secs() == 7 * 24 * 3600);
    const _: () = assert!(DROP_NOTICE_TTL.as_secs() == 14 * 24 * 3600);
    const _: () = assert!(DELETE_REQUEST_TTL.as_secs() == 14 * 24 * 3600);
    const _: () = assert!(REVOCATION_TTL.as_secs() == 30 * 24 * 3600);
    const _: () = assert!(UNKNOWN_SENDER_TTL.as_secs() == 90 * 24 * 3600);
}

/// Scale a mailbox-entry TTL by `time_scale`, mirroring the daemon scheduler.
///
/// The daemon divides every wall-clock cadence (PoS interval, deletion interval,
/// timeouts, sweep, mailbox poll) by `time_scale`: `time_scale = 1` is production
/// (real time), `> 1` is accelerated demos/tests. Mailbox-entry TTLs are baked into
/// `expires_at = now + ttl` at publish time; if they were NOT scaled while the
/// producers fire challenges/deletes/drop-notices every few accelerated seconds, the
/// entries would not expire within a test (a 7-day TTL is 7 *real* days regardless of
/// acceleration) and would accumulate, and late PoS responses arriving after the
/// scaled pending-timeout would race a never-shrinking TTL. So the publishing side
/// scales the TTL the same way the scheduler scales everything else.
///
/// Correctness:
/// - `time_scale = 1` → `ttl / 1 = ttl` exactly: production is untouched.
/// - `time_scale = 0` is treated as 1 (guard against division by zero).
/// - Floored at 1 second so an entry never gets `expires_at == stored_at` (which the
///   sweep/poll `<= now` checks would treat as already-expired) even when the divisor
///   exceeds the raw TTL.
///
/// Note: the receiving side (sweep, poll) compares `now` against the absolute
/// `expires_at` and needs NO `time_scale` — the scaling is already baked into the
/// stored `expires_at`. All nodes in a given demo/test run share one `time_scale`,
/// so absolute timestamps stay consistent across publisher and sweeper.
pub fn scaled_ttl_secs(ttl_secs: u64, time_scale: u64) -> u64 {
    (ttl_secs / time_scale.max(1)).max(1)
}

// ============================================================
// MailboxClass
// ============================================================

/// Message class — determines TTL, priority, eviction order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum MailboxClass {
    /// Signed SelfPointer. TTL = 5 years. High-trust = TTL-only eviction.
    SelfPointer = 0,
    /// PoS challenge: owner→holder. TTL = 7 days. Time-critical.
    PosChallenge = 1,
    /// PoS response: holder→owner. TTL = 7 days.
    PosResponse = 2,
    /// Symbol drop notice: holder→owner. TTL = 14 days. Reliable-ish.
    DropNotice = 3,
    /// Generic directed message (future use). TTL = unknown_sender_ttl.
    Generic = 4,
    /// Delete or CancelDelete request: owner→holder. TTL = 14 days.
    ///
    /// Payload is CBOR-encoded `DeleteRequestPayload` (tagged union distinguishing
    /// Delete from CancelDelete). Not high-trust: membership-evictable.
    DeleteRequest = 5,
    /// Device revocation notice: revoking master → storage-relationship peers. TTL = 30 days.
    ///
    /// Payload is CBOR-encoded `RevocationBroadcast` (revocation + device_cert, both
    /// signed by the revoking master). Sent ONLY to peers with a storage relationship
    /// (our holders + owners we hold for); not broadcast to all known peers.
    /// Not high-trust: membership-evictable.
    Revocation = 6,
}

impl MailboxClass {
    /// Default TTL in seconds for this class.
    ///
    /// P1-5: `class_config` is the single source of truth for per-class TTLs. This
    /// method delegates to those `Duration` constants rather than re-stating the
    /// literals, so the two can never drift. `Generic` has no producer (see the
    /// poll-loop guard) and maps to the conservative `UNKNOWN_SENDER_TTL`.
    pub fn default_ttl_secs(self) -> u64 {
        match self {
            MailboxClass::SelfPointer => class_config::SELF_POINTER_TTL.as_secs(),
            MailboxClass::PosChallenge => class_config::POS_CHALLENGE_TTL.as_secs(),
            MailboxClass::PosResponse => class_config::POS_CHALLENGE_TTL.as_secs(),
            MailboxClass::DropNotice => class_config::DROP_NOTICE_TTL.as_secs(),
            MailboxClass::Generic => class_config::UNKNOWN_SENDER_TTL.as_secs(),
            MailboxClass::DeleteRequest => class_config::DELETE_REQUEST_TTL.as_secs(),
            MailboxClass::Revocation => class_config::REVOCATION_TTL.as_secs(),
        }
    }

    /// SelfPointer is high-trust: evicted only on TTL expiry, never on membership check failure.
    /// Used by Bug-D eviction policy (T-11): high-trust entries survive candidate-set changes.
    /// All other classes (including Revocation) are membership-evictable.
    pub fn is_high_trust(self) -> bool {
        matches!(self, MailboxClass::SelfPointer)
    }

    /// Encode to u8 for use in composite DB key.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decode from u8. Returns None for unknown variants.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(MailboxClass::SelfPointer),
            1 => Some(MailboxClass::PosChallenge),
            2 => Some(MailboxClass::PosResponse),
            3 => Some(MailboxClass::DropNotice),
            4 => Some(MailboxClass::Generic),
            5 => Some(MailboxClass::DeleteRequest),
            6 => Some(MailboxClass::Revocation),
            _ => None,
        }
    }
}

// ============================================================
// DeleteRequestPayload: tagged union for DeleteMsg / CancelDeleteMsg
// ============================================================

/// Tagged payload for `MailboxClass::DeleteRequest` entries.
///
/// Distinguishes `Delete` (owner instructs holder to delete) from `CancelDelete`
/// (owner rescinds a previously sent delete). Both are signed by the owner master key
/// and self-authenticating (see `verify_delete_msg` / `verify_cancel_delete_msg`).
///
/// Encoding: CBOR. `payload_version = 1`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeleteRequestPayload {
    Delete(crate::messages::DeleteMsg),
    CancelDelete(crate::messages::CancelDeleteMsg),
}

// ============================================================
// MailboxEntry
// ============================================================

fn default_payload_version() -> u8 {
    1
}

/// One entry in the mailbox store.
///
/// `payload_version` is a forward-compatibility field: SelfPointer entries
/// have TTL = 5 years, so entries may survive until 2031+. Receivers MUST skip
/// entries with unknown version (not error), to tolerate future format evolution.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MailboxEntry {
    /// Target (owner) identity this entry is addressed to.
    pub target: IdentityPub,
    /// Unique 16-byte message identifier (random, from sender).
    pub msg_id: [u8; 16],
    /// Message class (determines TTL, priority).
    pub class: MailboxClass,
    /// Payload schema version for forward-compat evolution.
    /// Current version = 1. Receiver MUST skip entries with unknown version (not error).
    #[serde(default = "default_payload_version")]
    pub payload_version: u8,
    /// Raw payload bytes (CBOR-encoded inner message).
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    /// Unix timestamp (seconds) when this entry expires.
    pub expires_at: u64,
    /// Unix timestamp when first stored (for LRU eviction ordering).
    pub stored_at: u64,
    /// Sender identity (optional, for delivery-reward tracking).
    pub sender: Option<IdentityPub>,
}

impl MailboxEntry {
    /// Exact serialized size for quota tracking — matches the bytes
    /// `Db::mailbox_insert` stores in the per-target counter, so the pre-store
    /// size/quota check and the persisted counter never diverge (WARN-1).
    pub fn serialized_size(&self) -> usize {
        crate::types::to_cbor_bytes(self).len()
    }
}

// ============================================================
// MailboxAddress + write/read authorization (CROWN-1)
// ============================================================

/// Mailbox address: an Ed25519 public key. The box belongs to whoever holds the
/// matching secret key. Directed boxes use the recipient's master key; the DR
/// pointer box uses a seed-derived per-epoch rendezvous key (see [`seal`]).
///
/// CROWN-1 slice C1 introduces the type; `MailboxEntry.target` still carries an
/// `IdentityPub` with the same 32 bytes until slice C2 retypes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MailboxAddress(pub [u8; 32]);

impl MailboxAddress {
    /// The directed-mail box of `master`: the address IS the master public key.
    pub fn for_master(master: &IdentityPub) -> Self {
        MailboxAddress(master.0)
    }

    /// The address as an Ed25519 verifying key. `None` if the 32 bytes are not
    /// a valid compressed Edwards point (such an address can never authorize a
    /// write or a read).
    pub fn verifying_key(&self) -> Option<ed25519_dalek::VerifyingKey> {
        ed25519_dalek::VerifyingKey::from_bytes(&self.0).ok()
    }
}

impl std::fmt::Display for MailboxAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex_encode(&self.0[..8]))
    }
}

/// Domain prefix of the store signature (`target_sig`).
const STORE_SIG_DOMAIN: &[u8] = b"viaticum-mailbox-store-v1";
/// Domain prefix of the fetch proof (`target_proof`).
const FETCH_PROOF_DOMAIN: &[u8] = b"viaticum-mailbox-fetch-v1";

/// Store-signature input (domain-separated, fixed layout, pure):
///
/// `b"viaticum-mailbox-store-v1" ‖ target (32) ‖ class (1) ‖ msg_id (16) ‖
///  payload_version (1) ‖ expires_at_be (8) ‖ stored_at_be (8) ‖ SHA256(payload) (32)`
///
/// Every field has a fixed width, so the encoding is injective. The postman must
/// verify it BEFORE clamping `expires_at` (the signature covers the sender's value).
pub fn store_sig_input(entry: &MailboxEntry) -> Vec<u8> {
    use sha2::Digest;
    let payload_hash: [u8; 32] = sha2::Sha256::digest(&entry.payload).into();
    let mut out = Vec::with_capacity(STORE_SIG_DOMAIN.len() + 32 + 1 + 16 + 1 + 8 + 8 + 32);
    out.extend_from_slice(STORE_SIG_DOMAIN);
    out.extend_from_slice(&entry.target.0);
    out.push(entry.class.as_u8());
    out.extend_from_slice(&entry.msg_id);
    out.push(entry.payload_version);
    out.extend_from_slice(&entry.expires_at.to_be_bytes());
    out.extend_from_slice(&entry.stored_at.to_be_bytes());
    out.extend_from_slice(&payload_hash);
    out
}

/// Sign `entry` for store with the secret key of its target address.
pub fn sign_store(signing_key: &ed25519_dalek::SigningKey, entry: &MailboxEntry) -> [u8; 64] {
    use ed25519_dalek::Signer;
    signing_key.sign(&store_sig_input(entry)).to_bytes()
}

/// Verify a store signature against the entry's own target address
/// (`verify_strict`). `Unauthorized` if the target is not a valid key or the
/// signature does not verify.
pub fn verify_store_sig(entry: &MailboxEntry, sig: &[u8; 64]) -> Result<(), MailboxError> {
    let key = MailboxAddress(entry.target.0)
        .verifying_key()
        .ok_or(MailboxError::Unauthorized)?;
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    key.verify_strict(&store_sig_input(entry), &sig)
        .map_err(|_| MailboxError::Unauthorized)
}

/// Fetch-proof input: `b"viaticum-mailbox-fetch-v1" ‖ target (32) ‖ requester_device (32)`.
///
/// No timestamp on purpose: the proof is bound to the requester's device id,
/// which the postman takes from the Noise-authenticated connection, so a proof
/// forwarded by anyone else is useless; and a clean DR machine must not depend
/// on its clock for reading.
pub fn fetch_proof_input(target: &MailboxAddress, requester: &DeviceId) -> Vec<u8> {
    let mut out = Vec::with_capacity(FETCH_PROOF_DOMAIN.len() + 64);
    out.extend_from_slice(FETCH_PROOF_DOMAIN);
    out.extend_from_slice(&target.0);
    out.extend_from_slice(&requester.0);
    out
}

/// Prove possession of the secret key of `target` to a postman, bound to `requester`.
pub fn sign_fetch_proof(
    signing_key: &ed25519_dalek::SigningKey,
    target: &MailboxAddress,
    requester: &DeviceId,
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    signing_key
        .sign(&fetch_proof_input(target, requester))
        .to_bytes()
}

/// Verify a fetch proof (`verify_strict`). `false` for an invalid target key.
pub fn verify_fetch_proof(target: &MailboxAddress, requester: &DeviceId, sig: &[u8; 64]) -> bool {
    let Some(key) = target.verifying_key() else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(sig);
    key.verify_strict(&fetch_proof_input(target, requester), &sig)
        .is_ok()
}

// ============================================================
// MailboxRejectReason
// ============================================================

/// Reason for rejecting a mailbox store request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MailboxRejectReason {
    NotInCandidateSet,
    QuotaExceeded,
    EntryTooLarge,
    Duplicate,
}

// ============================================================
// MailboxError
// ============================================================

/// Error type for mailbox operations.
#[derive(Debug, thiserror::Error)]
pub enum MailboxError {
    #[error("db error: {0}")]
    Db(#[from] DbError),
    #[error("entry too large: {size} > {max}")]
    TooLarge { size: usize, max: usize },
    #[error("quota exceeded for target {target}")]
    QuotaExceeded { target: IdentityPub },
    #[error("not in candidate set for target")]
    NotInCandidateSet,
    #[error("duplicate msg_id")]
    Duplicate,
    #[error("unauthorized write to mailbox address")]
    Unauthorized,
}

// ============================================================
// MailboxEngine: high-level operations on top of Db
// ============================================================

/// High-level mailbox operations. Wraps Db for quota/size validation.
pub struct MailboxEngine {
    db: Db,
}

impl MailboxEngine {
    pub fn new(db: Db) -> Self {
        MailboxEngine { db }
    }

    /// Store an entry, enforcing size cap and per-target quota.
    ///
    /// Returns `MailboxError::TooLarge` if serialized entry exceeds MAX_ENTRY_BYTES.
    /// Returns `MailboxError::QuotaExceeded` if target is already at MAX_MAILBOX_BYTES_PER_PEER.
    /// Returns `MailboxError::Duplicate` if msg_id already stored for this target+class.
    ///
    /// CS-POS-2: `expires_at` is sender-controlled. A signed challenge with
    /// `expires_at = u64::MAX` would otherwise be stored forever (the sweep only
    /// compares against `now`) and re-served to the holder on EVERY poll → unbounded
    /// recompute + a permanent store squat. The postman clamps `expires_at` to at most
    /// `now + class.default_ttl_secs()` (the per-class RAW TTL). Clamping by the raw TTL
    /// is safe under time-scale acceleration: the publisher already scales the TTL DOWN,
    /// so a scaled `expires_at` is always below the raw cap and `min()` leaves it
    /// unchanged — the clamp only caps the MAXIMUM, never shortens a legitimate entry.
    pub fn store(&self, entry: &MailboxEntry, now_secs: u64) -> Result<(), MailboxError> {
        let mut entry = entry.clone();
        let max_expires_at = now_secs.saturating_add(entry.class.default_ttl_secs());
        entry.expires_at = entry.expires_at.min(max_expires_at);
        let entry = &entry;

        let size = entry.serialized_size();
        if size > class_config::MAX_ENTRY_BYTES {
            return Err(MailboxError::TooLarge {
                size,
                max: class_config::MAX_ENTRY_BYTES,
            });
        }

        let current_bytes = self.db.mailbox_bytes_for_target(&entry.target)?;
        if current_bytes.saturating_add(size as u64) > class_config::MAX_MAILBOX_BYTES_PER_PEER {
            return Err(MailboxError::QuotaExceeded {
                target: entry.target,
            });
        }

        // Map the storage-layer duplicate into the typed mailbox variant the
        // docstring promises (BLOCK-2): callers match `MailboxError::Duplicate`,
        // not a leaked `Db(DbError::Duplicate)`.
        self.db
            .mailbox_insert(entry, now_secs)
            .map_err(|e| match e {
                DbError::Duplicate => MailboxError::Duplicate,
                other => MailboxError::Db(other),
            })?;
        Ok(())
    }

    /// Fetch all non-expired entries for a target.
    pub fn fetch(
        &self,
        target: &IdentityPub,
        now_secs: u64,
    ) -> Result<Vec<MailboxEntry>, MailboxError> {
        Ok(self.db.mailbox_list_for_target(target, now_secs)?)
    }

    /// Delete one entry.
    pub fn delete(
        &self,
        target: &IdentityPub,
        msg_id: [u8; 16],
        class: MailboxClass,
    ) -> Result<(), MailboxError> {
        Ok(self.db.mailbox_delete(target, msg_id, class)?)
    }

    /// Sweep expired entries across all targets.
    pub fn sweep_expired(&self, now_secs: u64) -> Result<u64, MailboxError> {
        Ok(self.db.mailbox_sweep_expired(now_secs)?)
    }
}

#[cfg(test)]
mod tests;
