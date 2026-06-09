// T-6/T-7: Mailbox poll loop — periodic mailbox polling and entry dispatch.
//
// Polls this node's mailbox from read-fanout candidates every MAILBOX_POLL_INTERVAL_SECS.
// Also polls immediately on startup (per spec §2.17: "poll on startup after Kademlia stabilize";
// for T-6 we poll on first tick alongside other periodic tasks — T-9 adds the explicit
// stabilize wait).
//
// Entry dispatch (§2.17):
//   PosChallenge   → handle_pos_challenge_from_mailbox (compute response, publish PosResponse)
//   PosResponse    → pos_response_tx.try_send (scheduler resolves pending challenge)
//   SelfPointer    → if entry.target == my_master_pub: verify + update in-memory (W-2, no DB store)
//                    if entry.target != my_master_pub:  store in mailbox DB (we are postman)
//   DropNotice     → DropNoticeHandler::handle_drop_notice (T-7: decode batch, apply each notice)
//   Generic/other  → ignore

use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use viaticum_core::constants::MAILBOX_POLL_INTERVAL_SECS;
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxClass, MailboxEngine, MailboxEntry};
use viaticum_core::messages::{
    PosHashResponseMsg, SymbolDropNoticeBatchMsg, SymbolDropNoticeMsg, to_cbor,
};
use viaticum_core::system_state::{SelfPointer, verify_self_pointer};
use viaticum_core::types::IdentityPub;
use viaticum_core::types::from_cbor_bytes;

use super::routing::MailboxRouter;

/// Run the periodic mailbox poll loop.
///
/// Polls immediately on first tick, then every MAILBOX_POLL_INTERVAL_SECS.
/// Dispatches entries to the appropriate handlers.
///
/// Parameters:
/// - `db`: redb handle for mailbox DB operations (SelfPointer store)
/// - `router`: the MailboxRouter used to poll and publish responses
/// - `pos_response_tx`: bounded channel (capacity 256) to scheduler for PosResponse entries
/// - `challenge_handler`: called with (owner_master, challenge_payload_bytes) to process a
///   PosChallenge and return an optional PosHashResponseMsg + owner_master for publishing
/// - `drop_handler`: called for each DropNotice decoded from a SymbolDropNoticeBatchMsg entry
/// - `my_master_pub`: this node's master identity (used to detect own SelfPointers)
/// - `cancel`: cancellation token
pub async fn run_mailbox_poll(
    db: Db,
    router: Arc<MailboxRouter>,
    pos_response_tx: mpsc::Sender<PosHashResponseMsg>,
    challenge_handler: Arc<dyn PosMailboxChallengeHandler>,
    drop_handler: Arc<dyn DropNoticeHandler>,
    my_master_pub: IdentityPub,
    cancel: CancellationToken,
) {
    // Poll immediately on startup (first tick = no delay).
    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(MAILBOX_POLL_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("mailbox_poll: cancelled, shutting down");
                break;
            }
            _ = interval.tick() => {
                let now_secs = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Poll our own mailbox from read-fanout peers.
                let entries = match router.poll(&my_master_pub, None).await {
                    Ok(e) => e,
                    Err(err) => {
                        warn!(err = %err, "mailbox_poll: poll failed");
                        continue;
                    }
                };

                if entries.is_empty() {
                    debug!("mailbox_poll: no entries");
                    continue;
                }

                info!(count = entries.len(), "mailbox_poll: received entries");

                for entry in entries {
                    dispatch_entry(
                        &db,
                        &router,
                        &pos_response_tx,
                        &challenge_handler,
                        &drop_handler,
                        &my_master_pub,
                        entry,
                        now_secs,
                    )
                    .await;
                }
            }
        }
    }
}

/// Dispatch a single polled MailboxEntry to the appropriate handler.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch_entry(
    db: &Db,
    router: &Arc<MailboxRouter>,
    pos_response_tx: &mpsc::Sender<PosHashResponseMsg>,
    challenge_handler: &Arc<dyn PosMailboxChallengeHandler>,
    drop_handler: &Arc<dyn DropNoticeHandler>,
    my_master_pub: &IdentityPub,
    entry: MailboxEntry,
    now_secs: u64,
) {
    match entry.class {
        MailboxClass::PosChallenge => {
            dispatch_pos_challenge(router, challenge_handler, entry).await;
        }
        MailboxClass::PosResponse => {
            dispatch_pos_response(pos_response_tx, entry);
        }
        MailboxClass::SelfPointer => {
            dispatch_self_pointer(db, my_master_pub, entry, now_secs);
        }
        MailboxClass::DropNotice => {
            dispatch_drop_notice(drop_handler, entry);
        }
        MailboxClass::Generic => {
            debug!(msg_id = ?entry.msg_id, "mailbox_poll: ignoring Generic entry");
        }
    }
}

/// Handle a PosChallenge entry: compute response and publish to owner via mailbox.
///
/// The owner's master_pub comes from `entry.sender` (set by the scheduler when publishing
/// the challenge — see scheduler::issue_due_challenges).
async fn dispatch_pos_challenge(
    router: &Arc<MailboxRouter>,
    challenge_handler: &Arc<dyn PosMailboxChallengeHandler>,
    entry: MailboxEntry,
) {
    let owner_master = match entry.sender {
        Some(s) => s,
        None => {
            warn!(
                msg_id = ?entry.msg_id,
                "mailbox_poll: PosChallenge has no sender — cannot publish response"
            );
            return;
        }
    };

    // Pass owner_master as the first arg — PosMailboxChallengeHandler uses it as owner_id
    // to look up our HoldingRecord (owner = the one who sent the challenge).
    match challenge_handler
        .handle_pos_challenge(owner_master, entry.payload.clone())
        .await
    {
        Ok(Some(response)) => {
            // Publish PosResponse back to the owner via mailbox.
            let response_payload = match to_cbor(&response) {
                Ok(p) => p,
                Err(e) => {
                    error!(err = %e, "mailbox_poll: failed to encode PosHashResponseMsg");
                    return;
                }
            };

            // PosResponse TTL = same as challenge TTL (7 days).
            let ttl_secs = viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL.as_secs();
            let now_secs = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let mut msg_id = [0u8; 16];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut msg_id);

            let response_entry = MailboxEntry {
                target: owner_master,
                msg_id,
                class: MailboxClass::PosResponse,
                payload_version: 1,
                payload: response_payload,
                expires_at: now_secs + ttl_secs,
                stored_at: now_secs,
                // sender: None — not needed for PosResponse routing
                sender: None,
            };

            match router.publish(&owner_master, response_entry).await {
                Ok(0) => {
                    warn!(
                        owner = %owner_master,
                        "mailbox_poll: PosResponse publish got 0 acks — response may be lost"
                    );
                }
                Ok(ack_count) => {
                    debug!(
                        owner = %owner_master,
                        ack_count,
                        "mailbox_poll: PosResponse published"
                    );
                }
                Err(e) => {
                    error!(
                        owner = %owner_master,
                        err = %e,
                        "mailbox_poll: PosResponse publish failed"
                    );
                }
            }
        }
        Ok(None) => {
            // Nack or CannotCompute — challenge_handler already logged
            debug!(msg_id = ?entry.msg_id, "mailbox_poll: PosChallenge handler returned no response (nack)");
        }
        Err(e) => {
            error!(
                msg_id = ?entry.msg_id,
                err = %e,
                "mailbox_poll: PosChallenge handler error"
            );
        }
    }
}

/// Handle a PosResponse entry: forward to scheduler via pos_response_tx.
pub(crate) fn dispatch_pos_response(
    pos_response_tx: &mpsc::Sender<PosHashResponseMsg>,
    entry: MailboxEntry,
) {
    match from_cbor_bytes::<PosHashResponseMsg>(&entry.payload) {
        Ok(response) => {
            // N-5: bounded channel, try_send + WARN on Full.
            match pos_response_tx.try_send(response) {
                Ok(()) => {
                    debug!(msg_id = ?entry.msg_id, "mailbox_poll: PosResponse forwarded to scheduler");
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        msg_id = ?entry.msg_id,
                        "mailbox_poll: pos_response_tx full — dropping PosResponse (N-5)"
                    );
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    debug!("mailbox_poll: pos_response_tx closed (scheduler shut down)");
                }
            }
        }
        Err(e) => {
            warn!(
                msg_id = ?entry.msg_id,
                err = %e,
                "mailbox_poll: failed to decode PosHashResponseMsg"
            );
        }
    }
}

/// Handle a SelfPointer entry.
///
/// W-2: if entry.target == my_master_pub, verify and update in-memory; do NOT store in mailbox DB.
/// If entry.target != my_master_pub, we are the postman — store in mailbox DB.
pub(crate) fn dispatch_self_pointer(
    db: &Db,
    my_master_pub: &IdentityPub,
    entry: MailboxEntry,
    now_secs: u64,
) {
    if &entry.target == my_master_pub {
        // Own SelfPointer returned from candidate-set — verify, do NOT store (W-2).
        match from_cbor_bytes::<SelfPointer>(&entry.payload) {
            Ok(pointer) => {
                if verify_self_pointer(&pointer, my_master_pub).is_ok() {
                    debug!(
                        generation = pointer.generation,
                        created_at = pointer.created_at.0,
                        "mailbox_poll: own SelfPointer verified (W-2: not stored in DB)"
                    );
                    // NOTE(T-8): update in-memory current_pointer for periodic push.
                    // T-8 wires this into run_periodic_push; for T-6 the hook is here (log only).
                } else {
                    warn!(msg_id = ?entry.msg_id, "mailbox_poll: own SelfPointer signature verification failed");
                }
            }
            Err(e) => {
                warn!(
                    msg_id = ?entry.msg_id,
                    err = %e,
                    "mailbox_poll: failed to decode own SelfPointer"
                );
            }
        }
    } else {
        // Foreign SelfPointer — we are the postman. Store in mailbox DB (T-1 ops).
        let engine = MailboxEngine::new(db.clone());
        match engine.store(&entry, now_secs) {
            Ok(()) | Err(viaticum_core::mailbox::MailboxError::Duplicate) => {
                debug!(
                    target = %entry.target,
                    msg_id = ?entry.msg_id,
                    "mailbox_poll: foreign SelfPointer stored"
                );
            }
            Err(e) => {
                warn!(
                    target = %entry.target,
                    msg_id = ?entry.msg_id,
                    err = %e,
                    "mailbox_poll: failed to store foreign SelfPointer"
                );
            }
        }
    }
}

/// Handle a DropNotice entry (T-7).
///
/// Decodes the entry payload as `SymbolDropNoticeBatchMsg` (a batch of one or more
/// single-block drop notices for the same owner). For each notice in the batch,
/// calls `drop_handler.handle_drop_notice(sender, notice)`.
///
/// Requires `entry.sender` to identify the holder. Warns and returns if absent.
pub(crate) fn dispatch_drop_notice(drop_handler: &Arc<dyn DropNoticeHandler>, entry: MailboxEntry) {
    let sender = match entry.sender {
        Some(s) => s,
        None => {
            warn!(
                msg_id = ?entry.msg_id,
                target = %entry.target,
                "mailbox_poll: DropNotice has no sender — cannot identify holder, dropping"
            );
            return;
        }
    };

    match from_cbor_bytes::<SymbolDropNoticeBatchMsg>(&entry.payload) {
        Ok(batch) => {
            debug!(
                msg_id = ?entry.msg_id,
                target = %entry.target,
                notice_count = batch.notices.len(),
                "mailbox_poll: dispatching DropNotice batch"
            );
            for notice in batch.notices {
                drop_handler.handle_drop_notice(sender, notice);
            }
        }
        Err(e) => {
            warn!(
                msg_id = ?entry.msg_id,
                target = %entry.target,
                err = %e,
                "mailbox_poll: failed to decode SymbolDropNoticeBatchMsg — dropping entry"
            );
        }
    }
}

// ─── DropNoticeHandler trait ──────────────────────────────────────────────────

/// Abstraction for handling a DropNotice batch from the mailbox (T-7).
///
/// Called once per individual `SymbolDropNoticeMsg` decoded from a
/// `SymbolDropNoticeBatchMsg` mailbox entry. Each call processes one block's notice.
///
/// Production impl: `ProcessorDropHandler` wraps `SymbolDropHandler::apply`.
/// Exists as a trait seam for testing without a full Processor.
pub trait DropNoticeHandler: Send + Sync {
    fn handle_drop_notice(&self, from: IdentityPub, notice: SymbolDropNoticeMsg);
}

// ─── PosMailboxChallengeHandler trait ────────────────────────────────────────

/// Abstraction for handling a PosChallenge from the mailbox.
///
/// Exists as a trait seam so the poll loop can be tested without a full Processor.
/// Production impl: `ProcessorPosHandler` wraps `Processor::handle_pos_hash_challenge_inner`.
///
/// Returns:
///   Ok(Some(response)) — computed PosHashResponseMsg to publish back to owner
///   Ok(None)           — nack (missing symbols etc.); handler already logged
///   Err(e)             — unexpected error
/// Handler trait for PoS challenges received from the mailbox.
///
/// Parameters to `handle_pos_challenge`:
/// - `owner_master_pub`: owner's master_pub from `MailboxEntry.sender` (the identity who sent the
///   challenge). Passed as `owner_id` to `handle_pos_hash_challenge_inner` to look up our
///   HoldingRecord.
/// - `payload`: raw CBOR-encoded `PosHashChallengeMsg` bytes.
#[async_trait::async_trait]
pub trait PosMailboxChallengeHandler: Send + Sync {
    async fn handle_pos_challenge(
        &self,
        owner_master_pub: IdentityPub,
        payload: Vec<u8>,
    ) -> anyhow::Result<Option<PosHashResponseMsg>>;
}

#[cfg(test)]
mod tests;
