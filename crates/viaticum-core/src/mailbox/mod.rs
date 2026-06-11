// Mailbox: unified store-and-forward primitive for async P2P messaging.
// T-1: types + redb storage + TTL/cleanup.
//
// Design: each MailboxEntry is addressed to a target (owner master_pub).
// Postman nodes store entries on behalf of the target (write-fanout),
// target nodes poll for their own entries (read-fanout).
// See A2 spec §2.2 for full design.

use crate::db::{Db, DbError};
use crate::types::IdentityPub;

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
    pub fn default_ttl_secs(self) -> u64 {
        match self {
            MailboxClass::SelfPointer => 5 * 365 * 24 * 3600,
            MailboxClass::PosChallenge => 7 * 24 * 3600,
            MailboxClass::PosResponse => 7 * 24 * 3600,
            MailboxClass::DropNotice => 14 * 24 * 3600,
            MailboxClass::Generic => 90 * 24 * 3600,
            MailboxClass::DeleteRequest => 14 * 24 * 3600,
            MailboxClass::Revocation => 30 * 24 * 3600,
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
    pub fn store(&self, entry: &MailboxEntry, now_secs: u64) -> Result<(), MailboxError> {
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
