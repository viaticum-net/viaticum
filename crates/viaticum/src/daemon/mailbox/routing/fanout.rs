// The store fanout of one publication (mailbox-i60).
//
// Every postman gets its own task. The task that receives an answer records it itself:
// an Ack is a contact (avail + `last_seen`, dr-i50), a refusal or an error goes to the
// log. The task owns a `Db` handle, so the record does not depend on anyone still
// waiting for it: a postman answering after the publication returned (or after the
// caller dropped it) is recorded the same way.
//
// The publication only counts: it returns as soon as `need` postmen acked, or when
// every postman answered, or after `PEER_REQUEST_TIMEOUT`, whichever comes first. One
// sleeping postman (a half-open connection of a laptop that went to sleep) therefore
// no longer holds every publication for 15 s.

use std::sync::Arc;

use libp2p::Multiaddr;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{Instant, timeout, timeout_at};
use tracing::{debug, warn};
use viaticum_core::constants::AVAIL_EWMA_ALPHA;
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxRejectReason};
use viaticum_core::messages::{MailboxStoreRequest, MailboxStoreResponse};
use viaticum_core::types::{DeviceId, Timestamp, ewma_contact_observed, hex_encode};

use super::{MailboxNetworkSender, NearPeer, PEER_REQUEST_TIMEOUT, PublishOutcome};

/// dr-i63: Kademlia-near postmen of a pointer stored at once. Each may need an on-demand
/// dial; the swarm has `MAX_ON_DEMAND_DIALS` (16) slots for every consumer (PoS,
/// restore), so the pointer takes at most half.
pub(crate) const POINTER_NEAR_CONCURRENCY: usize = 8;

/// One postman's answer to a store, as its task reports it.
enum StoreAnswer {
    Ack,
    Reject(MailboxRejectReason),
    Error,
}

/// Unix seconds now.
pub(super) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Send `req` to every postman of `write_peers` and return what arrived by the time
/// `need` (≥ 1) of them acked, or all answered, or `PEER_REQUEST_TIMEOUT` passed.
/// Answers already in when the wait ends are counted too; the rest are `pending`.
pub(super) async fn store_fanout(
    sender: &Arc<dyn MailboxNetworkSender>,
    db: &Db,
    write_peers: &[DeviceId],
    req: MailboxStoreRequest,
    need: usize,
) -> PublishOutcome {
    let deadline = Instant::now() + PEER_REQUEST_TIMEOUT;
    let asked = write_peers.len();
    let (tx, mut rx) = mpsc::unbounded_channel();
    for &device in write_peers {
        let sender = Arc::clone(sender);
        let db = db.clone();
        let req = req.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let answer = store_one(sender.as_ref(), &db, device, None, req).await;
            // The publication may have returned already: its receiver is gone and the
            // answer was recorded above anyway.
            let _ = tx.send((device, answer));
        });
    }
    drop(tx);

    let need = need.max(1);
    let mut outcome = PublishOutcome::default();
    let mut answered = 0;
    while outcome.acks.len() < need {
        match timeout_at(deadline, rx.recv()).await {
            Ok(Some((device, answer))) => {
                answered += 1;
                count(&mut outcome, device, answer);
            }
            // Every task is gone: those that sent nothing panicked.
            Ok(None) => {
                outcome.errors += asked - answered;
                answered = asked;
                break;
            }
            Err(_) => break,
        }
    }
    while let Ok((device, answer)) = rx.try_recv() {
        answered += 1;
        count(&mut outcome, device, answer);
    }
    outcome.pending = asked - answered;
    outcome
}

/// dr-i63: the store fanout of a pointer envelope to the trust-top `write_peers` and to
/// the Kademlia-near postmen of its box (`near`, disjoint from `write_peers`, sent with
/// the addresses of the lookup; `permits` = the router's `POINTER_NEAR_CONCURRENCY`
/// near stores at a time over all its pointer publications).
///
/// mailbox-i60 counted on the near set: returns as soon as `need` NEAR postmen acked
/// (the acks DR readiness counts), or every near postman answered, or the waves'
/// deadline passed. A trust-top ack never ends the wait; what the trust-top answered by
/// then is counted, the rest is `pending` (late acks record the contact, as in
/// `store_fanout`). A near ack that comes later is not needed: either the threshold is
/// already met, or the wait lasted until every near postman answered or timed out.
/// With no near postman it is `store_fanout(…, need)`.
pub(super) async fn store_fanout_pointer(
    sender: &Arc<dyn MailboxNetworkSender>,
    db: &Db,
    write_peers: &[DeviceId],
    near: &[NearPeer],
    req: MailboxStoreRequest,
    need: usize,
    permits: &Arc<Semaphore>,
) -> PublishOutcome {
    if near.is_empty() {
        return store_fanout(sender, db, write_peers, req, need).await;
    }
    let waves = near.len().div_ceil(POINTER_NEAR_CONCURRENCY) as u32;
    // Each wave: its permits' sends end within PEER_REQUEST_TIMEOUT; one more for the
    // task scheduling around them.
    let deadline = Instant::now() + PEER_REQUEST_TIMEOUT * (waves + 1);
    let asked = write_peers.len() + near.len();
    let (tx, mut rx) = mpsc::unbounded_channel();
    for &device in write_peers {
        let sender = Arc::clone(sender);
        let db = db.clone();
        let req = req.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let answer = store_one(sender.as_ref(), &db, device, None, req).await;
            let _ = tx.send((device, answer, false));
        });
    }
    for p in near {
        let sender = Arc::clone(sender);
        let db = db.clone();
        let req = req.clone();
        let tx = tx.clone();
        let permits = Arc::clone(permits);
        let (device, addrs) = (p.device, p.addrs.clone());
        tokio::spawn(async move {
            let answer = match permits.acquire_owned().await {
                Ok(_permit) => store_one(sender.as_ref(), &db, device, Some(addrs), req).await,
                Err(_) => StoreAnswer::Error,
            };
            let _ = tx.send((device, answer, true));
        });
    }
    drop(tx);

    let need = need.max(1);
    let mut outcome = PublishOutcome::default();
    let mut answered = 0;
    let mut near_answered = 0;
    let mut near_acked = 0;
    while near_answered < near.len() && near_acked < need {
        match timeout_at(deadline, rx.recv()).await {
            Ok(Some((device, answer, is_near))) => {
                answered += 1;
                if is_near {
                    near_answered += 1;
                    near_acked += usize::from(matches!(answer, StoreAnswer::Ack));
                }
                count(&mut outcome, device, answer);
            }
            Ok(None) => {
                outcome.errors += asked - answered;
                answered = asked;
                break;
            }
            Err(_) => break,
        }
    }
    while let Ok((device, answer, _)) = rx.try_recv() {
        answered += 1;
        count(&mut outcome, device, answer);
    }
    outcome.pending = asked - answered;
    outcome
}

fn count(outcome: &mut PublishOutcome, device: DeviceId, answer: StoreAnswer) {
    match answer {
        StoreAnswer::Ack => outcome.acks.push(device),
        StoreAnswer::Reject(reason) => outcome.rejects.push((device, reason)),
        StoreAnswer::Error => outcome.errors += 1,
    }
}

/// One postman: send, then record the answer (contact on Ack, log otherwise). The
/// send is bounded by `PEER_REQUEST_TIMEOUT` whatever the sender, so the task ends.
/// `addrs`: a Kademlia-near postman, sent with the lookup's addresses (dr-i63).
async fn store_one(
    sender: &dyn MailboxNetworkSender,
    db: &Db,
    device: DeviceId,
    addrs: Option<Vec<Multiaddr>>,
    req: MailboxStoreRequest,
) -> StoreAnswer {
    let target = req.entry.target;
    let msg_id = req.entry.msg_id;
    let class = req.entry.class;
    let send = async {
        match addrs {
            Some(addrs) => sender.send_store_via(device, addrs, req).await,
            None => sender.send_store(device, req).await,
        }
    };
    let answer = timeout(PEER_REQUEST_TIMEOUT, send)
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("mailbox store timeout to {device}")));
    match answer {
        Ok(MailboxStoreResponse::Ack { .. }) => {
            record_contact_off_runtime(db, device, unix_now());
            StoreAnswer::Ack
        }
        Ok(MailboxStoreResponse::Reject { reason, .. }) => {
            log_store_refusal(device, &target, &msg_id, class, &reason);
            StoreAnswer::Reject(reason)
        }
        Err(e) => {
            debug!(device = %device, err = %e, "mailbox publish: store failed");
            StoreAnswer::Error
        }
    }
}

/// Apply a positive avail observation for `device_id` in the DB.
///
/// Called after a successful MailboxStoreAck or MailboxFetchResponse. The peer
/// answered, so it is also SEEN now: `last_seen` moves forward (CROWN-1 V.17.1 —
/// the strength of an SS base counts only holders seen within 7 days / time_scale;
/// without this, a holder on a long-lived connection would look gone, because
/// `last_seen` otherwise moves only at (re)authentication).
/// Non-fatal: logs warning on DB error.
///
/// Read and write in one transaction (`Db::update_peer`): addresses or trust written
/// concurrently by another task are not overwritten with a stale snapshot.
pub(super) fn record_avail_contact(db: &Db, device_id: DeviceId, now_secs: u64) {
    let updated = db.update_peer(&device_id, |r| {
        r.map(|mut record| {
            record.avail_ewma = ewma_contact_observed(record.avail_ewma, AVAIL_EWMA_ALPHA);
            record.last_avail_sample = now_secs;
            record.last_seen = Timestamp(record.last_seen.0.max(now_secs));
            record
        })
    });
    match updated {
        Ok(Some(_)) => {}
        Ok(None) => {
            // Peer not in DB (a Kademlia-near postman not yet authenticated). No-op.
            debug!(device = %device_id, "mailbox router: avail contact for unknown peer");
        }
        Err(e) => {
            warn!(
                device = %device_id,
                err = %e,
                "mailbox router: failed to persist avail_ewma contact observation"
            );
        }
    }
}

/// `record_avail_contact` from an async task without holding an async worker (СТ-0c round
/// 4). The contact is a durable redb commit, and a commit waits for redb's one write lock:
/// a publication fans out to ~9 postmen and the issue tick keeps 9 publications in
/// flight, so a burst of Acks parked dozens of workers in `begin_write` behind one slow
/// commit, and the whole runtime — timers, the scheduler's issue tick — stalled until the
/// commits drained. On the daemon's multi-thread runtime the write runs in
/// `block_in_place`: the worker hands its other tasks to a fresh one first. Same order and
/// timing for the caller as before (the contact is recorded before the answer counts). A
/// current-thread runtime (tests) cannot hand off; there it is a plain call, as before.
pub(super) fn record_contact_off_runtime(db: &Db, device_id: DeviceId, now_secs: u64) {
    let record = || record_avail_contact(db, device_id, now_secs);
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(record),
        _ => record(),
    }
}

/// One postman's refusal of a store: a refusal that is our own fault (`Unauthorized`,
/// `PlaintextPayload`) is a `warn!`; `ClockSkew` / `Superseded` of a SelfPointer are
/// `debug!` (the publisher logs the verdict); `ClockSkew` of a directed entry stays
/// `warn!`. `Expired` (mailbox-i61: the entry died in transit) is `debug!` for every
/// class — not a key or clock fault.
fn log_store_refusal(
    device_id: DeviceId,
    target: &MailboxAddress,
    msg_id: &[u8; 16],
    class: MailboxClass,
    reason: &MailboxRejectReason,
) {
    let ours = matches!(
        reason,
        MailboxRejectReason::Unauthorized | MailboxRejectReason::PlaintextPayload
    );
    let directed_clock =
        class != MailboxClass::SelfPointer && matches!(reason, MailboxRejectReason::ClockSkew);
    if *reason == MailboxRejectReason::Expired {
        debug!(
            device = %device_id,
            msg_id = %hex_encode(msg_id),
            ?class,
            "mailbox publish: postman refused the entry — expired in transit"
        );
    } else if ours || directed_clock {
        warn!(
            device = %device_id,
            target = %target,
            msg_id = %hex_encode(msg_id),
            ?class,
            ?reason,
            "mailbox publish: postman refused the entry — check keys and system clock"
        );
    } else {
        debug!(
            device = %device_id,
            msg_id = %hex_encode(msg_id),
            ?class,
            ?reason,
            "mailbox publish: peer rejected store"
        );
    }
}

#[cfg(test)]
mod tests;
