// The fetch fanout of one poll (mailbox-i63) and the poll's merge key (mailbox-i69).
//
// Every postman gets its own task in a `JoinSet`. A postman's answer goes to the
// caller's channel as soon as it arrives, so the caller handles the records of a quick
// postman while a sleeping one (a half-open connection of a laptop that went to sleep)
// is still inside its 15 s. The task that receives an answer records the contact itself
// (avail + `last_seen`, dr-i50), as the store fanout does: an answer that arrives after
// the caller stopped reading is recorded the same way.
//
// Records of several postmen merge only when they are the same bytes
// (`poll_entry_key`): a forgery a postman stores under an honest `msg_id` must not hide
// the honest record, whichever postman answers first.

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, warn};
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxClass, MailboxEntry};
use viaticum_core::messages::MailboxFetchRequest;
use viaticum_core::types::{DeviceId, IdentityPub};

use super::fanout::{record_contact_off_runtime, unix_now};
use super::{MailboxNetworkSender, PEER_REQUEST_TIMEOUT};

/// What one poll merges records by: `msg_id`, class, blake3 of the payload and the
/// unsigned `sender` header. `sender` is in the key because a PosChallenge's holder
/// answers to the `sender` box: a copy with the honest payload under another `sender`,
/// arriving first, must not hide the honest copy (mailbox-i69).
pub(crate) type PollEntryKey = ([u8; 16], MailboxClass, [u8; 32], Option<IdentityPub>);

/// The merge key of `entry` (mailbox-i69). A postman stores per `(target, msg_id, class)`,
/// so one `msg_id` may legitimately carry records of several classes; records sharing a
/// `msg_id` but differing in class or payload are different records.
pub(crate) fn poll_entry_key(entry: &MailboxEntry) -> PollEntryKey {
    (
        entry.msg_id,
        entry.class,
        *blake3::hash(&entry.payload).as_bytes(),
        entry.sender,
    )
}

/// The records one poll has already let through (mailbox-i63 + mailbox-i69).
///
/// Holds the keys of one poll: a record whose key was seen in an earlier answer (or
/// earlier in the same answer) is skipped, a record with a new key goes on. Expired
/// records are dropped (the postman filters them; clock skew).
pub struct PollSeen {
    seen: HashSet<PollEntryKey>,
    now_secs: u64,
}

impl PollSeen {
    pub fn new(now_secs: u64) -> Self {
        PollSeen {
            seen: HashSet::new(),
            now_secs,
        }
    }

    /// The records of `answer` that are alive and not seen earlier in this poll.
    pub fn admit(&mut self, answer: Vec<MailboxEntry>) -> Vec<MailboxEntry> {
        answer
            .into_iter()
            .filter(|e| e.expires_at > self.now_secs && self.seen.insert(poll_entry_key(e)))
            .collect()
    }
}

/// Send `req` to every postman of `read_peers` and stream their answers.
///
/// Each answer `(postman, entries)` is sent to the returned channel as it arrives; a
/// postman that fails or stays silent for `PEER_REQUEST_TIMEOUT` sends nothing. The
/// channel closes when every postman answered or timed out. The channel holds one slot
/// per postman, so a slow reader never holds a postman's task.
pub(super) fn fetch_fanout(
    sender: &Arc<dyn MailboxNetworkSender>,
    db: &Db,
    read_peers: Vec<DeviceId>,
    req: MailboxFetchRequest,
) -> mpsc::Receiver<(DeviceId, Vec<MailboxEntry>)> {
    let (tx, rx) = mpsc::channel(read_peers.len().max(1));
    let mut set = JoinSet::new();
    for device in read_peers {
        let sender = Arc::clone(sender);
        let db = db.clone();
        let req = req.clone();
        set.spawn(async move { fetch_one(sender.as_ref(), &db, device, req).await });
    }
    tokio::spawn(async move {
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(Some(answer)) => {
                    // The caller may have stopped reading: the contact is already
                    // recorded, the records are its loss.
                    let _ = tx.send(answer).await;
                }
                Ok(None) => {}
                Err(join_err) => warn!("mailbox poll: fetch task panicked: {join_err}"),
            }
        }
    });
    rx
}

/// One postman: fetch, record the contact on an answer. Bounded by
/// `PEER_REQUEST_TIMEOUT` whatever the sender, so the task ends.
async fn fetch_one(
    sender: &dyn MailboxNetworkSender,
    db: &Db,
    device: DeviceId,
    req: MailboxFetchRequest,
) -> Option<(DeviceId, Vec<MailboxEntry>)> {
    let answer = timeout(PEER_REQUEST_TIMEOUT, sender.send_fetch(device, req))
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("mailbox fetch timeout to {device}")));
    match answer {
        Ok(resp) => {
            record_contact_off_runtime(db, device, unix_now());
            Some((device, resp.entries))
        }
        Err(e) => {
            debug!(device = %device, err = %e, "mailbox poll: fetch failed");
            None
        }
    }
}

#[cfg(test)]
mod tests;
