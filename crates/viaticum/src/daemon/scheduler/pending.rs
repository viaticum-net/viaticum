// In-flight PoS challenges of the owner (pos-i6, pos-i7).
//
// Written by the Scheduler only (insert after ≥ 1 mailbox Ack, W-3; remove on a
// resolved response or a timeout). Read by the mailbox poll loop, which forwards to the
// scheduler only the responses whose challenge is still pending (pos-i6). Both take the
// lock briefly and never hold it across a network await.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;
use viaticum_core::types::{DeviceId, SourceBlockId};

pub use viaticum_core::pos::PendingHashChallenge;

/// (block, holder device): one pending challenge per placement at a time.
pub type PendingKey = (SourceBlockId, DeviceId);

/// In-flight PoS challenges, by (block, holder) and by challenge_id.
///
/// INV-9: the two maps change only together, through `insert` and `remove`; there is no
/// direct access to the fields. The challenge_id index makes the response lookup O(1)
/// (pos-i7) and lets the poll loop drop responses to challenges no longer pending
/// without a scan (pos-i6).
#[derive(Debug, Default)]
pub struct PendingIndex {
    by_key: HashMap<PendingKey, PendingHashChallenge>,
    by_challenge: HashMap<[u8; 16], PendingKey>,
}

impl PendingIndex {
    /// Insert `c` under `key`, replacing a pending challenge of the same key (whose old
    /// challenge_id is unindexed). `key` must be `(c.source_block_id, c.holder_id)`.
    pub fn insert(
        &mut self,
        key: PendingKey,
        c: PendingHashChallenge,
    ) -> Option<PendingHashChallenge> {
        debug_assert_eq!(
            key,
            (c.source_block_id, c.holder_id),
            "pending key must be the challenge's (block, holder)"
        );
        let challenge_id = c.challenge_id;
        let old = self.by_key.insert(key, c);
        if let Some(o) = &old {
            // Only unindex the old id while it still points at this key: an id collision
            // with another key (16 random bytes) must not unindex that other entry.
            if self.by_challenge.get(&o.challenge_id) == Some(&key) {
                self.by_challenge.remove(&o.challenge_id);
            }
        }
        if let Some(other) = self.by_challenge.insert(challenge_id, key)
            && other != key
        {
            // A challenge_id collision (never for 16 random bytes): the older key keeps
            // its challenge but loses the id index; it resolves by timeout.
            tracing::error!(
                "scheduler: pending challenge_id collision — the older challenge loses its index"
            );
        }
        old
    }

    /// Remove the pending challenge of `key` and its challenge_id index.
    pub fn remove(&mut self, key: &PendingKey) -> Option<PendingHashChallenge> {
        let old = self.by_key.remove(key)?;
        if self.by_challenge.get(&old.challenge_id) == Some(key) {
            self.by_challenge.remove(&old.challenge_id);
        }
        Some(old)
    }

    pub fn get(&self, key: &PendingKey) -> Option<&PendingHashChallenge> {
        self.by_key.get(key)
    }

    pub fn contains_key(&self, key: &PendingKey) -> bool {
        self.by_key.contains_key(key)
    }

    /// The (block, holder) of the pending challenge with this id.
    pub fn key_of(&self, challenge_id: &[u8; 16]) -> Option<PendingKey> {
        self.by_challenge.get(challenge_id).copied()
    }

    /// Whether a challenge with this id is pending.
    pub fn contains_challenge(&self, challenge_id: &[u8; 16]) -> bool {
        self.by_challenge.contains_key(challenge_id)
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &PendingKey> {
        self.by_key.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = &PendingHashChallenge> {
        self.by_key.values()
    }
}

/// In-flight PoS challenges shared by the Scheduler (the only writer) and the mailbox
/// poll loop (reads under the lock, never across a network await).
///
/// tokio::sync::Mutex: the scheduler takes the lock inside async fns; no holder of the
/// lock awaits the network while holding it.
pub type PendingChallenges = Arc<Mutex<PendingIndex>>;

/// A fresh, empty shared pending index.
pub fn new_pending_challenges() -> PendingChallenges {
    Arc::new(Mutex::new(PendingIndex::default()))
}
