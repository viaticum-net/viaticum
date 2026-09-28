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

use tokio::sync::mpsc;
use tokio::time::{Instant, timeout_at};
use tracing::{debug, warn};
use viaticum_core::constants::AVAIL_EWMA_ALPHA;
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxRejectReason};
use viaticum_core::messages::{MailboxStoreRequest, MailboxStoreResponse};
use viaticum_core::types::{DeviceId, Timestamp, ewma_contact_observed, hex_encode};

use super::{MailboxNetworkSender, PEER_REQUEST_TIMEOUT, PublishOutcome};

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
            let answer = store_one(sender.as_ref(), &db, device, req).await;
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

fn count(outcome: &mut PublishOutcome, device: DeviceId, answer: StoreAnswer) {
    match answer {
        StoreAnswer::Ack => outcome.acks.push(device),
        StoreAnswer::Reject(reason) => outcome.rejects.push((device, reason)),
        StoreAnswer::Error => outcome.errors += 1,
    }
}

/// One postman: send, then record the answer (contact on Ack, log otherwise).
async fn store_one(
    sender: &dyn MailboxNetworkSender,
    db: &Db,
    device: DeviceId,
    req: MailboxStoreRequest,
) -> StoreAnswer {
    let target = req.entry.target;
    let msg_id = req.entry.msg_id;
    let class = req.entry.class;
    match sender.send_store(device, req).await {
        Ok(MailboxStoreResponse::Ack { .. }) => {
            record_avail_contact(db, device, unix_now());
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
pub(super) fn record_avail_contact(db: &Db, device_id: DeviceId, now_secs: u64) {
    match db.get_peer(&device_id) {
        Ok(Some(mut record)) => {
            record.avail_ewma = ewma_contact_observed(record.avail_ewma, AVAIL_EWMA_ALPHA);
            record.last_avail_sample = now_secs;
            record.last_seen = Timestamp(record.last_seen.0.max(now_secs));
            if let Err(e) = db.upsert_peer(&record) {
                warn!(
                    device = %device_id,
                    err = %e,
                    "mailbox router: failed to persist avail_ewma contact observation"
                );
            }
        }
        Ok(None) => {
            // Peer not in DB (unusual — they were a candidate). No-op.
            debug!(device = %device_id, "mailbox router: avail contact for unknown peer");
        }
        Err(e) => {
            warn!(
                device = %device_id,
                err = %e,
                "mailbox router: failed to load peer for avail update"
            );
        }
    }
}

/// One postman's refusal of a store: a refusal that is our own fault (`Unauthorized`,
/// `PlaintextPayload`) is a `warn!`; `ClockSkew` / `Superseded` of a SelfPointer are
/// `debug!` (the publisher logs the verdict); `ClockSkew` of a directed entry stays
/// `warn!`.
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
    if ours || directed_clock {
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
