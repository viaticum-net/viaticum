// Mailbox handlers: receiver-side for MailboxStoreRequest and MailboxFetchRequest
// (postman role).
//
// CROWN-1 C2 rules (spec §7.5):
//   store — one address (`req.entry.target`) for the candidate-set check, the write
//           authorization and the storage key (AC-10, closes F3); SelfPointer needs a
//           `target_sig` by the address key (AC-7); postman clock rule (AC-22); then
//           MailboxEngine::store (size, quota / pointer budget, duplicate → Ack).
//   fetch — own master box by transport identity (all entries), any other box with a
//           fetch proof bound to the requester's device (SelfPointer entries only,
//           AC-9, AC-20); otherwise empty.
//
// The plaintext rule (§7.5 item 1, `payload_version < 2` → PlaintextPayload) is not
// here yet: it lands with sealing (C3 for SelfPointer, C4 for all classes).
//
// Delivery-reward (T-5) is NOT implemented here — deferred from A2.
// served_msg_ids field is populated and returned but nothing acts on it yet.

use libp2p::PeerId;
use tracing::{debug, info, warn};
use viaticum_core::constants::MAILBOX_CANDIDATES_N;
use viaticum_core::db::Db;
use viaticum_core::mailbox::{
    MailboxAddress, MailboxClass, MailboxEngine, MailboxError, MailboxRejectReason,
    check_entry_clock, verify_fetch_proof, verify_store_sig,
};
use viaticum_core::messages::{
    MAILBOX_WIRE_VERSION, MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest,
    MailboxStoreResponse,
};
use viaticum_core::types::{DeviceId, IdentityPub};

use crate::daemon::mailbox::candidate::{KademliaRoutingView, should_store};

/// Handle an incoming MailboxStoreRequest (receiver/postman side).
///
/// Order of checks (§7.5):
/// 0. `req.v != MAILBOX_WIRE_VERSION` → `Reject { UnsupportedWireVersion }` (review N5).
/// 1. Candidate-set: is this node in the top-N closest to `req.entry.target`?
///    If not → `Reject { NotInCandidateSet }`. The same field is the storage key, so a
///    request cannot pass the check for one address and be stored under another.
/// 2. `SelfPointer`: `req.target_sig` must verify against `req.entry.target`
///    (`verify_store_sig`, before the `expires_at` clamp) → else `Reject { Unauthorized }`.
///    Other classes: `target_sig` ignored (a sender never holds the recipient's key).
/// 3. Clock: `expires_at <= now`, or a SelfPointer `stored_at` more than one rendezvous
///    epoch from `now_secs` → `Reject { ClockSkew }`.
/// 4. MailboxEngine::store:
///    - Ok / Err(Duplicate) → `Ack { msg_id }` (duplicate: idempotent, already present)
///    - Err(TooLarge)       → `Reject { EntryTooLarge }`
///    - Err(QuotaExceeded)  → `Reject { QuotaExceeded }`
///    - Err(other)          → `Reject { QuotaExceeded }` (DB error treated conservatively)
///
/// The `Unauthorized` and `ClockSkew` refusals log at `warn!` with fixed text (N1): the
/// E2E guards grep for them.
pub fn handle_mailbox_store(
    db: &Db,
    routing_view: &KademliaRoutingView,
    my_peer_id: &PeerId,
    req: MailboxStoreRequest,
    now_secs: u64,
) -> MailboxStoreResponse {
    let entry = &req.entry;
    let msg_id = entry.msg_id;
    let target = entry.target;
    let reject = |reason| MailboxStoreResponse::Reject { msg_id, reason };

    // 0. Wire version (review N5): a request of another layout is refused explicitly.
    if req.v != MAILBOX_WIRE_VERSION {
        warn!(
            target = %target,
            v = req.v,
            "mailbox: store rejected — unsupported wire version"
        );
        return reject(MailboxRejectReason::UnsupportedWireVersion);
    }

    // 1. Candidate-set check on the one address this request carries.
    if !should_store(routing_view, &target, my_peer_id, MAILBOX_CANDIDATES_N) {
        debug!(target = %target, "mailbox: store rejected — not in candidate set");
        return reject(MailboxRejectReason::NotInCandidateSet);
    }

    // 2. Write authorization for the pointer box.
    if entry.class == MailboxClass::SelfPointer {
        let authorized = req
            .target_sig
            .as_ref()
            .is_some_and(|sig| verify_store_sig(entry, sig).is_ok());
        if !authorized {
            warn!(
                target = %target,
                msg_id = ?msg_id,
                class = ?entry.class,
                has_sig = req.target_sig.is_some(),
                "mailbox: store rejected — unauthorized"
            );
            return reject(MailboxRejectReason::Unauthorized);
        }
    }

    // 3. Postman clock rule (before the expires_at clamp inside the engine).
    if let Err(e) = check_entry_clock(entry, now_secs) {
        warn!(
            target = %target,
            msg_id = ?msg_id,
            class = ?entry.class,
            err = %e,
            "mailbox: store rejected — clock skew"
        );
        return reject(MailboxRejectReason::ClockSkew);
    }

    // 4. Store.
    let engine = MailboxEngine::new(db.clone());
    match engine.store(entry, now_secs) {
        Ok(()) => {
            // Spec B2 §2.8: a stored SelfPointer is the postman-side oracle of DR
            // readiness (dr-i9). No catalog fields: the postman does not decode payloads.
            if entry.class == MailboxClass::SelfPointer {
                info!(target = %target, msg_id = ?msg_id, "mailbox: stored SelfPointer entry");
            } else {
                debug!(target = %target, class = ?entry.class, "mailbox: stored entry");
            }
            MailboxStoreResponse::Ack { msg_id }
        }
        Err(MailboxError::Duplicate) => {
            debug!(target = %target, "mailbox: duplicate entry — returning Ack (idempotent)");
            MailboxStoreResponse::Ack { msg_id }
        }
        Err(MailboxError::TooLarge { size, max }) => {
            warn!(target = %target, size, max, "mailbox: store rejected — entry too large");
            reject(MailboxRejectReason::EntryTooLarge)
        }
        Err(MailboxError::QuotaExceeded { .. }) => {
            warn!(target = %target, class = ?entry.class, "mailbox: store rejected — quota exceeded");
            reject(MailboxRejectReason::QuotaExceeded)
        }
        Err(e) => {
            warn!(target = %target, err = %e, "mailbox: store failed with db error");
            reject(MailboxRejectReason::QuotaExceeded)
        }
    }
}

/// Handle an incoming MailboxFetchRequest (receiver/postman side).
///
/// `requester_master` / `requester_device` come from the Noise-authenticated
/// connection (never from the request). Access (§7.5, AC-9, AC-20):
/// - `req.target == MailboxAddress::for_master(requester_master)` → every entry of the
///   box (the owner reads its own master box, as before);
/// - else `req.target_proof` verifies for (`req.target`, `requester_device`) → only the
///   `SelfPointer` entries (the only legitimate content of a pointer box; directed junk
///   planted in the same address is neither served nor able to bloat the answer, which
///   stays within the pointer budget — mailbox-i20);
/// - otherwise, or `req.v != MAILBOX_WIRE_VERSION` → empty response (no error leak).
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
    requester_device: DeviceId,
    now_secs: u64,
) -> MailboxFetchResponse {
    let empty_response = MailboxFetchResponse {
        v: MAILBOX_WIRE_VERSION,
        entries: vec![],
        served_msg_ids: vec![],
    };

    if req.v != MAILBOX_WIRE_VERSION {
        warn!(
            req_target = %req.target,
            v = req.v,
            "mailbox: fetch rejected — unsupported wire version"
        );
        return empty_response;
    }

    let own_master_box = req.target == MailboxAddress::for_master(&requester_master);
    let pointers_only = if own_master_box {
        false
    } else if req
        .target_proof
        .as_ref()
        .is_some_and(|p| verify_fetch_proof(&req.target, &requester_device, p))
    {
        true
    } else {
        warn!(
            req_target = %req.target,
            requester = %requester_master,
            device = %requester_device,
            has_proof = req.target_proof.is_some(),
            "mailbox: fetch rejected — requester is not the box owner"
        );
        return empty_response;
    };

    let engine = MailboxEngine::new(db.clone());
    let entries = match engine.fetch(&req.target, now_secs) {
        Ok(e) => e,
        Err(err) => {
            warn!(target = %req.target, err = %err, "mailbox: fetch db error");
            return empty_response;
        }
    };

    let filtered: Vec<_> = entries
        .into_iter()
        .filter(|e| !pointers_only || e.class == MailboxClass::SelfPointer)
        .filter(|e| req.since_stored_at.is_none_or(|since| e.stored_at > since))
        .collect();

    let served_msg_ids: Vec<[u8; 16]> = filtered.iter().map(|e| e.msg_id).collect();

    MailboxFetchResponse {
        v: MAILBOX_WIRE_VERSION,
        entries: filtered,
        served_msg_ids,
    }
}

#[cfg(test)]
mod tests;
