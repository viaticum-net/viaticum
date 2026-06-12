// T-6/T-7/T-13b-1/T-13b-2: Mailbox poll loop — periodic mailbox polling and entry dispatch.
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
//   DeleteRequest  → DeleteMailboxHandler::handle_delete_request (T-13b-1: Delete/CancelDelete)
//   Revocation     → RevocationMailboxHandler::handle_revocation (T-13b-2: device revocation)
//   Generic/other  → ignore

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use viaticum_core::constants::MAILBOX_POLL_INTERVAL_SECS;
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxClass, MailboxEntry};
use viaticum_core::messages::{
    PosHashResponseMsg, SymbolDropNoticeBatchMsg, SymbolDropNoticeMsg, to_cbor,
};
use viaticum_core::system_state::{SelfPointer, verify_self_pointer};
use viaticum_core::types::IdentityPub;
use viaticum_core::types::from_cbor_bytes;

use super::routing::MailboxRouter;
use crate::daemon::processor::{DeleteMailboxHandler, RevocationMailboxHandler};

/// Mailbox poll cadence in seconds, scaled by `time_scale`.
///
/// Mirrors the scheduler, which divides every cadence by `time_scale`
/// (`scheduler/mod.rs`: pos_interval / deletion_interval / timeout / sweep). The
/// mailbox is the bus for PoS / Delete / DropNotice / SelfPointer round-trips, so
/// if the poll loop ran at a fixed wall-clock hour while the scheduler fired
/// challenges/deletes every few accelerated seconds, no round-trip could ever
/// complete under time acceleration (demos/tests). Production (`time_scale = 1`)
/// keeps the full `MAILBOX_POLL_INTERVAL_SECS` cadence. Floored at 1s so the loop
/// never busy-spins on a 0s interval; `time_scale = 0` is treated as 1.
pub(crate) fn poll_interval_secs(time_scale: u64) -> u64 {
    (MAILBOX_POLL_INTERVAL_SECS / time_scale.max(1)).max(1)
}

/// Run the periodic mailbox poll loop.
///
/// Polls immediately on first tick, then every `poll_interval_secs(time_scale)`.
/// Dispatches entries to the appropriate handlers.
///
/// Parameters:
/// - `db`: redb handle for mailbox DB operations (SelfPointer store)
/// - `router`: the MailboxRouter used to poll and publish responses
/// - `pos_response_tx`: bounded channel (capacity 256) to scheduler for PosResponse entries
/// - `challenge_handler`: called with (owner_master, challenge_payload_bytes) to process a
///   PosChallenge and return an optional PosHashResponseMsg + owner_master for publishing
/// - `drop_handler`: called for each DropNotice decoded from a SymbolDropNoticeBatchMsg entry
/// - `delete_handler`: called for each DeleteRequest entry (T-13b-1)
/// - `revocation_handler`: called for each Revocation entry (T-13b-2)
/// - `my_master_pub`: this node's master identity (used to detect own SelfPointers)
/// - `current_pointer`: shared handle with run_periodic_push. On receiving our own verified
///   SelfPointer, update this handle (W-2: restart-recovery — re-learn latest published pointer).
/// - `time_scale`: time-acceleration factor; the poll cadence is divided by it
///   (see `poll_interval_secs`). Production passes 1.
/// - `cancel`: cancellation token
#[allow(clippy::too_many_arguments)]
pub async fn run_mailbox_poll(
    db: Db,
    router: Arc<MailboxRouter>,
    pos_response_tx: mpsc::Sender<PosHashResponseMsg>,
    challenge_handler: Arc<dyn PosMailboxChallengeHandler>,
    drop_handler: Arc<dyn DropNoticeHandler>,
    delete_handler: Arc<dyn DeleteMailboxHandler>,
    revocation_handler: Arc<dyn RevocationMailboxHandler>,
    my_master_pub: IdentityPub,
    current_pointer: Arc<Mutex<Option<SelfPointer>>>,
    time_scale: u64,
    cancel: CancellationToken,
) {
    // Poll immediately on startup (first tick = no delay), then every
    // poll_interval_secs(time_scale) — scaled like the scheduler's cadences.
    let poll_secs = poll_interval_secs(time_scale);
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_secs));
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
                        &delete_handler,
                        &revocation_handler,
                        &my_master_pub,
                        &current_pointer,
                        entry,
                        now_secs,
                        time_scale,
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
    delete_handler: &Arc<dyn DeleteMailboxHandler>,
    revocation_handler: &Arc<dyn RevocationMailboxHandler>,
    my_master_pub: &IdentityPub,
    current_pointer: &Arc<Mutex<Option<SelfPointer>>>,
    entry: MailboxEntry,
    now_secs: u64,
    time_scale: u64,
) {
    match entry.class {
        MailboxClass::PosChallenge => {
            dispatch_pos_challenge(router, challenge_handler, my_master_pub, entry, time_scale)
                .await;
        }
        MailboxClass::PosResponse => {
            dispatch_pos_response(pos_response_tx, entry);
        }
        MailboxClass::SelfPointer => {
            dispatch_self_pointer(db, my_master_pub, current_pointer, entry, now_secs);
        }
        MailboxClass::DropNotice => {
            dispatch_drop_notice(drop_handler, my_master_pub, entry);
        }
        MailboxClass::Generic => {
            // P1-10: Generic has NO dispatch handler by design — there is currently no
            // producer of `MailboxClass::Generic` entries anywhere in the codebase, so
            // any Generic entry we receive is unexpected. We deliberately drop it (no
            // effect), but log loudly so this is not a *silent* no-op: if a Generic
            // producer is ever added, wire its handler in this arm — otherwise its
            // entries will be discarded here. The entry still expires via its TTL.
            warn!(
                msg_id = ?entry.msg_id,
                target = ?entry.target,
                "mailbox_poll: received a Generic mailbox entry but no Generic handler is \
                 wired (no producer exists by design) — dropping with no effect"
            );
        }
        MailboxClass::DeleteRequest => {
            dispatch_delete_request(delete_handler, my_master_pub, entry).await;
        }
        MailboxClass::Revocation => {
            dispatch_revocation(revocation_handler, my_master_pub, entry).await;
        }
    }
}

/// Handle a PosChallenge entry: compute response and publish to owner via mailbox.
///
/// The owner's master_pub comes from `entry.sender` (set by the scheduler when publishing
/// the challenge — see scheduler::issue_due_challenges).
///
/// `my_master_pub` is this (holder) node's master identity. It is stamped as the response
/// `sender` so the owner can resolve who to verify the response signature against (CS-ID-1).
async fn dispatch_pos_challenge(
    router: &Arc<MailboxRouter>,
    challenge_handler: &Arc<dyn PosMailboxChallengeHandler>,
    my_master_pub: &IdentityPub,
    entry: MailboxEntry,
    time_scale: u64,
) {
    // CS-ID-6 / SM-8 (defense-in-depth): we only ever poll our own mailbox
    // (`router.poll(&my_master_pub, ...)`), so a PosChallenge that reaches dispatch
    // must be addressed to us. Effects are already gated by signature verification
    // (the holding lookup keys on owner_master from `entry.sender`), but this guard
    // documents and enforces the routing invariant: a buggy or hostile postman that
    // returns a mis-targeted entry is rejected here rather than processed.
    // `dispatch_self_pointer` makes the same own-vs-postman distinction.
    if &entry.target != my_master_pub {
        warn!(
            msg_id = ?entry.msg_id,
            entry_target = ?entry.target,
            "mailbox_poll: PosChallenge not addressed to this node — dropping (routing invariant)"
        );
        return;
    }

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

            // PosResponse TTL = same as challenge TTL (7 days), scaled by time_scale
            // so it matches the scheduler's scaled pending-challenge timeout — a late
            // response must not outlive (or be outlived by) the timeout window.
            let ttl_secs = viaticum_core::mailbox::scaled_ttl_secs(
                viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL.as_secs(),
                time_scale,
            );
            let now_secs = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // A3 (P1-4 / M1 / WARN-1): deterministic-but-UNPREDICTABLE msg_id.
            //
            // The PoS challenge entry stays in our (holder's) mailbox until its TTL, so
            // `dispatch_pos_challenge` re-runs on every poll while the challenge is alive
            // — this IS the retry: if a publish gets 0 acks (all of the owner's write-
            // fanout postmen were unreachable), the next poll re-publishes the same
            // response. The owner's pending lives longer (POS_CHALLENGE_PENDING ≈14d2h)
            // than the challenge TTL (7d), so a late retry is still accepted.
            //
            // The msg_id must be (a) STABLE across re-dispatch so postmen dedup re-
            // published responses (closes M1 pile-up), and (b) UNPREDICTABLE to a third
            // party so a postman that has merely seen the challenge cannot pre-occupy the
            // response key. We derive it from the chain_hash — which only a node that
            // actually holds the symbols can compute:
            //
            //     msg_id = BLAKE3("viaticum-pos-resp-msgid-v1" ‖ challenge_id ‖ chain_hash)[..16]
            //
            // Stable: the same challenge yields the same chain_hash, hence the same msg_id
            // on every re-dispatch. Unpredictable: a postman storing the challenge sees
            // `challenge_id` (plaintext in the challenge entry) but NOT the symbols, so it
            // cannot compute chain_hash → cannot predict this key. Using the raw
            // `challenge_id` would let any postman pre-store garbage under (owner_master,
            // challenge_id, PosResponse); the honest store would then collide → keep-first
            // Duplicate→Ack (we believe we delivered) while the postman keeps the garbage,
            // the owner's signature verify fails, and the pending dies at Timeout — re-
            // creating the very P1-4 false-penalty this fix prevents (WARN-1).
            //
            // Store dedup is KEEP-FIRST: an existing (target, msg_id, class) key returns
            // Duplicate→Ack (mailbox_insert / handle_mailbox_store), so a re-dispatch is an
            // idempotent no-op Ack, not an overwrite. No cross-class collision: this entry
            // is keyed under (owner_master, msg_id, PosResponse) while the challenge sits
            // under (holder_master, challenge_id, PosChallenge).
            let msg_id: [u8; 16] = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"viaticum-pos-resp-msgid-v1");
                hasher.update(&response.challenge_id);
                hasher.update(&response.chain_hash);
                hasher.finalize().as_bytes()[..16]
                    .try_into()
                    .expect("blake3 digest is 32 bytes, slice of 16 always fits")
            };

            let response_entry = MailboxEntry {
                target: owner_master,
                msg_id,
                class: MailboxClass::PosResponse,
                payload_version: 1,
                payload: response_payload,
                expires_at: now_secs + ttl_secs,
                stored_at: now_secs,
                // CS-ID-1: stamp our (holder) master so the owner can resolve and verify
                // the response signature. The owner does not trust this hint blindly — it
                // verifies the payload sig against the master of its own pending.holder_id.
                sender: Some(*my_master_pub),
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
/// W-2: if entry.target == my_master_pub, verify and update in-memory current_pointer;
/// do NOT store in mailbox DB.
///
/// CS-MBX-3: a poll only ever returns OUR own mail (`router.poll(&my_master_pub, ...)`),
/// so a SelfPointer with `target != my_master_pub` in a poll response is never legitimately
/// ours to store. We drop it with a warn. The previous code stored such foreign-target
/// entries DIRECTLY via `MailboxEngine::store`, bypassing both the candidate-set
/// `should_store()` gate (the real postman path's admission check) AND `verify_self_pointer`
/// — letting a hostile read-fanout postman inject arbitrary unverified entries for
/// third-party targets into our local mailbox DB (disk/quota amplification + pollution).
///
/// T-8: The `current_pointer` handle is shared with `run_periodic_push`. When the node
/// re-learns its own pointer from the candidate-set (restart-recovery), we update the
/// handle so that the periodic push loop doesn't re-publish unchanged state. Only update
/// if the incoming generation is strictly greater than what we have, preventing regression
/// to an older pointer.
pub(crate) fn dispatch_self_pointer(
    // CS-MBX-3: `db`/`now_secs` were only used by the removed foreign-store branch.
    // Kept in the signature (prefixed `_`) so the poll-loop's resource threading and
    // the call sites stay unchanged; a poll never yields a foreign-target entry to store.
    _db: &Db,
    my_master_pub: &IdentityPub,
    current_pointer: &Arc<Mutex<Option<SelfPointer>>>,
    entry: MailboxEntry,
    _now_secs: u64,
) {
    if &entry.target == my_master_pub {
        // Own SelfPointer returned from candidate-set — verify, do NOT store (W-2).
        match from_cbor_bytes::<SelfPointer>(&entry.payload) {
            Ok(pointer) => {
                if verify_self_pointer(&pointer, my_master_pub).is_ok() {
                    // T-8: update in-memory current_pointer for restart-recovery.
                    // Only store if None OR incoming.generation > current.generation.
                    let mut guard = current_pointer.lock().expect("current_pointer lock");
                    let should_update = match guard.as_ref() {
                        None => true,
                        Some(existing) => pointer.generation > existing.generation,
                    };
                    if should_update {
                        let prev_gen = guard.as_ref().map(|p| p.generation);
                        debug!(
                            generation = pointer.generation,
                            prev_generation = ?prev_gen,
                            created_at = pointer.created_at.0,
                            "mailbox_poll: own SelfPointer updated in-memory (W-2: not stored in DB)"
                        );
                        *guard = Some(pointer);
                    } else {
                        debug!(
                            generation = pointer.generation,
                            created_at = pointer.created_at.0,
                            "mailbox_poll: own SelfPointer received but generation not newer — not updating (W-2)"
                        );
                    }
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
        // CS-MBX-3: foreign-target SelfPointer in a poll response — never legitimately
        // ours. Drop with warn instead of storing it (the old foreign-store path bypassed
        // candidate-set admission and signature verification). The postman storage path
        // is the dedicated `handle_mailbox_store`, not this poll-dispatch arm.
        warn!(
            msg_id = ?entry.msg_id,
            entry_target = ?entry.target,
            "mailbox_poll: SelfPointer not addressed to this node — dropping (routing invariant, CS-MBX-3)"
        );
    }
}

/// Handle a DropNotice entry (T-7).
///
/// Decodes the entry payload as `SymbolDropNoticeBatchMsg` (a batch of one or more
/// single-block drop notices for the same owner). For each notice in the batch,
/// calls `drop_handler.handle_drop_notice(sender, notice)`.
///
/// Requires `entry.sender` to identify the holder. Warns and returns if absent.
pub(crate) fn dispatch_drop_notice(
    drop_handler: &Arc<dyn DropNoticeHandler>,
    my_master_pub: &IdentityPub,
    entry: MailboxEntry,
) {
    // SM-8 / CS-DEL-7 (defense-in-depth): we only ever poll our own mailbox, so a
    // DropNotice that reaches dispatch must be addressed to us. Effects are already
    // gated by holder-sig verification + a placement check, but this guard enforces
    // the routing invariant — a buggy or hostile postman that returns a mis-targeted
    // entry is rejected here. Mirrors `dispatch_pos_challenge`.
    if &entry.target != my_master_pub {
        warn!(
            msg_id = ?entry.msg_id,
            entry_target = ?entry.target,
            "mailbox_poll: DropNotice not addressed to this node — dropping (routing invariant)"
        );
        return;
    }

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

/// Handle a DeleteRequest entry (T-13b-1).
///
/// Requires `entry.sender` to identify the owner (whose key is verified against the
/// payload sig). Warns and returns if absent — cannot authenticate without it.
pub(crate) async fn dispatch_delete_request(
    delete_handler: &Arc<dyn DeleteMailboxHandler>,
    my_master_pub: &IdentityPub,
    entry: MailboxEntry,
) {
    // SM-8 / CS-DEL-7 (defense-in-depth): we only ever poll our own mailbox, so a
    // DeleteRequest that reaches dispatch must be addressed to us. The handler already
    // re-authenticates (owner-sig verify + holding lookup keyed on owner), but this
    // guard enforces the routing invariant. Mirrors `dispatch_pos_challenge`.
    if &entry.target != my_master_pub {
        warn!(
            msg_id = ?entry.msg_id,
            entry_target = ?entry.target,
            "mailbox_poll: DeleteRequest not addressed to this node — dropping (routing invariant)"
        );
        return;
    }

    let owner_master = match entry.sender {
        Some(s) => s,
        None => {
            warn!(
                msg_id = ?entry.msg_id,
                target = %entry.target,
                "mailbox_poll: DeleteRequest has no sender — cannot authenticate, dropping"
            );
            return;
        }
    };

    if let Err(e) = delete_handler
        .handle_delete_request(owner_master, entry.payload)
        .await
    {
        error!(
            msg_id = ?entry.msg_id,
            owner = %owner_master,
            err = %e,
            "mailbox_poll: DeleteRequest handler error"
        );
    }
}

/// Handle a Revocation entry (T-13b-2).
///
/// Requires `entry.sender` to identify the revoking master. Warns and returns if absent —
/// cannot authenticate without a sender identity.
pub(crate) async fn dispatch_revocation(
    revocation_handler: &Arc<dyn RevocationMailboxHandler>,
    my_master_pub: &IdentityPub,
    entry: MailboxEntry,
) {
    // SM-8 / CS-DEL-7 (defense-in-depth): we only ever poll our own mailbox, so a
    // Revocation that reaches dispatch must be addressed to us. The handler already
    // verifies both certs against the revoking master, but this guard enforces the
    // routing invariant. Mirrors `dispatch_pos_challenge`.
    if &entry.target != my_master_pub {
        warn!(
            msg_id = ?entry.msg_id,
            entry_target = ?entry.target,
            "mailbox_poll: Revocation not addressed to this node — dropping (routing invariant)"
        );
        return;
    }

    let revoking_master = match entry.sender {
        Some(s) => s,
        None => {
            warn!(
                msg_id = ?entry.msg_id,
                target = %entry.target,
                "mailbox_poll: Revocation has no sender — cannot authenticate, dropping"
            );
            return;
        }
    };

    if let Err(e) = revocation_handler
        .handle_revocation(revoking_master, entry.payload)
        .await
    {
        error!(
            msg_id = ?entry.msg_id,
            revoking_master = %revoking_master,
            err = %e,
            "mailbox_poll: Revocation handler error"
        );
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
