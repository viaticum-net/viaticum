// Mailbox handlers: receiver-side for MailboxStoreRequest and MailboxFetchRequest.
//
// T-3: two inbound RR handlers (postman role):
//   handle_mailbox_store — candidate-set check + MailboxEngine::store
//   handle_mailbox_fetch — identity check + MailboxEngine::fetch with optional since_stored_at filter
//
// Delivery-reward (T-5) is NOT implemented here — deferred from A2.
// served_msg_ids field is populated and returned but nothing acts on it yet.
//
// See A2 spec §2.4 for full design.

use libp2p::PeerId;
use tracing::{debug, warn};
use viaticum_core::constants::MAILBOX_CANDIDATES_N;
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxEngine, MailboxError, MailboxRejectReason};
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
};
use viaticum_core::types::IdentityPub;

use crate::daemon::mailbox::candidate::{KademliaRoutingView, should_store};

/// Handle an incoming MailboxStoreRequest (receiver/postman side).
///
/// Steps:
/// 1. Candidate-set check: is this node in the top-N closest to `req.target`?
///    If not → `Reject { NotInCandidateSet }`.
/// 2. Attempt MailboxEngine::store:
///    - Ok  → `Ack { msg_id }`
///    - Err(TooLarge)       → `Reject { EntryTooLarge }`
///    - Err(QuotaExceeded)  → `Reject { QuotaExceeded }`
///    - Err(Duplicate)      → `Ack { msg_id }` (idempotent: entry already stored, correct state)
///    - Err(other)          → `Reject { QuotaExceeded }` (DB error treated conservatively)
///
/// Duplicate handling rationale: returning Ack on duplicate is idempotent and safe.
/// The entry is already present with the correct content. Returning Reject would
/// cause the sender to retry unnecessarily and would not match the actual state.
pub fn handle_mailbox_store(
    db: &Db,
    routing_view: &KademliaRoutingView,
    my_peer_id: &PeerId,
    req: MailboxStoreRequest,
) -> MailboxStoreResponse {
    let msg_id = req.entry.msg_id;

    // Step 1: candidate-set check.
    if !should_store(routing_view, &req.target, my_peer_id, MAILBOX_CANDIDATES_N) {
        debug!(
            target = %req.target,
            "mailbox: store rejected — not in candidate set"
        );
        return MailboxStoreResponse::Reject {
            msg_id,
            reason: MailboxRejectReason::NotInCandidateSet,
        };
    }

    // Step 2: attempt store.
    let engine = MailboxEngine::new(db.clone());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    match engine.store(&req.entry, now) {
        Ok(()) => {
            debug!(target = %req.target, "mailbox: stored entry");
            MailboxStoreResponse::Ack { msg_id }
        }
        Err(MailboxError::Duplicate) => {
            // Idempotent: entry already stored with the same content.
            // Return Ack so the sender knows the entry is present.
            debug!(target = %req.target, "mailbox: duplicate entry — returning Ack (idempotent)");
            MailboxStoreResponse::Ack { msg_id }
        }
        Err(MailboxError::TooLarge { size, max }) => {
            warn!(
                target = %req.target,
                size,
                max,
                "mailbox: store rejected — entry too large"
            );
            MailboxStoreResponse::Reject {
                msg_id,
                reason: MailboxRejectReason::EntryTooLarge,
            }
        }
        Err(MailboxError::QuotaExceeded { .. }) => {
            warn!(target = %req.target, "mailbox: store rejected — quota exceeded");
            MailboxStoreResponse::Reject {
                msg_id,
                reason: MailboxRejectReason::QuotaExceeded,
            }
        }
        Err(e) => {
            warn!(target = %req.target, err = %e, "mailbox: store failed with db error");
            MailboxStoreResponse::Reject {
                msg_id,
                reason: MailboxRejectReason::QuotaExceeded,
            }
        }
    }
}

/// Handle an incoming MailboxFetchRequest (receiver/postman side).
///
/// Security: verifies `req.target == requester_master`. A node may only fetch
/// its own mail. On mismatch → return empty response (no error leak).
///
/// Filtering: if `req.since_stored_at` is set, only entries with
/// `stored_at > since_stored_at` are returned (incremental polling).
///
/// Delivery-reward: `served_msg_ids` is populated with the msg_ids of returned
/// entries. No reward call is made in A2 (T-5 deferred).
pub fn handle_mailbox_fetch(
    db: &Db,
    req: MailboxFetchRequest,
    requester_master: IdentityPub,
    now_secs: u64,
) -> MailboxFetchResponse {
    let empty_response = MailboxFetchResponse {
        v: 1,
        entries: vec![],
        served_msg_ids: vec![],
    };

    // Security: only the target itself may fetch its own mail.
    if req.target != requester_master {
        warn!(
            req_target = %req.target,
            requester = %requester_master,
            "mailbox: fetch rejected — requester is not the target"
        );
        return empty_response;
    }

    let engine = MailboxEngine::new(db.clone());
    let entries = match engine.fetch(&req.target, now_secs) {
        Ok(e) => e,
        Err(err) => {
            warn!(target = %req.target, err = %err, "mailbox: fetch db error");
            return empty_response;
        }
    };

    // Apply incremental filter if requested.
    let filtered: Vec<_> = match req.since_stored_at {
        Some(since) => entries
            .into_iter()
            .filter(|e| e.stored_at > since)
            .collect(),
        None => entries,
    };

    let served_msg_ids: Vec<[u8; 16]> = filtered.iter().map(|e| e.msg_id).collect();

    MailboxFetchResponse {
        v: 1,
        entries: filtered,
        served_msg_ids,
    }
}

#[cfg(test)]
mod tests;
