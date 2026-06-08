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
    /// Hard cap per entry: 256 KB.
    pub const MAX_ENTRY_BYTES: usize = 256 * 1024;
    /// Global mailbox quota per target: 100 MB.
    pub const MAX_MAILBOX_BYTES_PER_PEER: u64 = 100 * 1024 * 1024;
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
        }
    }

    /// SelfPointer is high-trust: evicted only on TTL expiry, never on membership check failure.
    /// Used by Bug-D eviction policy (T-11): high-trust entries survive candidate-set changes.
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
            _ => None,
        }
    }
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
