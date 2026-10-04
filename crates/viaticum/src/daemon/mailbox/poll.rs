// T-6/T-7/T-13b-1/T-13b-2: Mailbox poll loop — periodic mailbox polling and entry dispatch.
//
// Polls this node's mailbox from read-fanout candidates every MAILBOX_POLL_INTERVAL_SECS.
// Also polls immediately on startup (per spec §2.17: "poll on startup after Kademlia stabilize";
// for T-6 we poll on first tick alongside other periodic tasks — T-9 adds the explicit
// stabilize wait).
//
// Entry dispatch (§2.17):
//   PosChallenge   → compute the response once, publish it, keep it in memory and
//                    re-publish the same entry rarely (pos-i5, see `pos_memo`)
//   PosResponse    → pos_response_tx.try_send, only for a challenge still pending and once
//                    per envelope; a full channel defers it to the next poll (pos-i6, see
//                    `forward_pos_responses`)
//   SelfPointer    → dropped with a warn: pointers live in the rendezvous box, which the
//                    daemon never reads (CROWN-1 РС3.1, mailbox-i37; only DR reads it)
//   DropNotice     → DropNoticeHandler::handle_drop_notice (T-7: decode batch, apply each notice)
//   DeleteRequest  → DeleteMailboxHandler::handle_delete_request (T-13b-1: Delete/CancelDelete)
//   Revocation     → RevocationMailboxHandler::handle_revocation (T-13b-2: device revocation)
//   Generic/other  → ignore

use std::sync::Arc;
use std::time::{Instant, SystemTime};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use viaticum_core::constants::MAILBOX_POLL_INTERVAL_SECS;
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::messages::{
    PosHashChallengeMsg, PosHashResponseMsg, SymbolDropNoticeBatchMsg, SymbolDropNoticeMsg, to_cbor,
};
use viaticum_core::types::{IdentityPub, from_cbor_bytes, hex_encode};

use super::routing::{MailboxRouter, PollSeen};
use crate::daemon::pos_memo::{
    AnsweredChallenges, ChallengeKey, ChallengeStep, PollCounts, PosPollState,
};
use crate::daemon::processor::{DeleteMailboxHandler, RevocationMailboxHandler};
use crate::daemon::scheduler::PendingChallenges;

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
/// - `router`: the MailboxRouter used to poll and publish responses
/// - `pos_response_tx`: bounded channel (capacity 256) to scheduler for PosResponse entries
/// - `pending`: the owner's in-flight challenges, written by the scheduler; only responses
///   to these are forwarded (pos-i6)
/// - `challenge_handler`: called with (owner_master, challenge_payload_bytes) to process a
///   PosChallenge and return an optional PosHashResponseMsg + owner_master for publishing
/// - `drop_handler`: called for each DropNotice decoded from a SymbolDropNoticeBatchMsg entry
/// - `delete_handler`: called for each DeleteRequest entry (T-13b-1)
/// - `revocation_handler`: called for each Revocation entry (T-13b-2)
/// - `my_master_pub`: this node's master identity (its master box is polled)
/// - `time_scale`: time-acceleration factor; the poll cadence is divided by it
///   (see `poll_interval_secs`). Production passes 1.
/// - `cancel`: cancellation token
#[allow(clippy::too_many_arguments)]
pub async fn run_mailbox_poll(
    router: Arc<MailboxRouter>,
    pos_response_tx: mpsc::Sender<PosHashResponseMsg>,
    pending: PendingChallenges,
    challenge_handler: Arc<dyn PosMailboxChallengeHandler>,
    drop_handler: Arc<dyn DropNoticeHandler>,
    delete_handler: Arc<dyn DeleteMailboxHandler>,
    revocation_handler: Arc<dyn RevocationMailboxHandler>,
    my_master_pub: IdentityPub,
    time_scale: u64,
    cancel: CancellationToken,
) {
    // Poll immediately on startup (first tick = no delay), then every
    // poll_interval_secs(time_scale) — scaled like the scheduler's cadences.
    let poll_secs = poll_interval_secs(time_scale);
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // pos-i5/pos-i6: what this task remembers about PoS between polls. RAM only: a
    // restart starts empty, computes every live challenge once, and (the owner's pending
    // being empty too) forwards no stale response.
    let mut pos = PosPollState::new(pending, time_scale);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("mailbox_poll: cancelled, shutting down");
                break;
            }
            _ = interval.tick() => {
                poll_once(
                    &router,
                    &pos_response_tx,
                    &mut pos,
                    &challenge_handler,
                    &drop_handler,
                    &delete_handler,
                    &revocation_handler,
                    &my_master_pub,
                    time_scale,
                    unix_now(),
                )
                .await;
            }
        }
    }
}

/// One poll of our own master box: forget expired PoS memory, then handle every
/// postman's answer as it arrives (mailbox-i63): drop the records already seen in this
/// poll (same bytes, `PollSeen`, mailbox-i69) or expired, forward the answer's
/// PosResponse entries as one batch (pos-i6), dispatch its other entries one by one.
/// A sleeping postman delays only its own records. At the end print
/// `mailbox_poll: poll done` (INFO when the poll had entries, DEBUG when it was empty).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn poll_once(
    router: &Arc<MailboxRouter>,
    pos_response_tx: &mpsc::Sender<PosHashResponseMsg>,
    pos: &mut PosPollState,
    challenge_handler: &Arc<dyn PosMailboxChallengeHandler>,
    drop_handler: &Arc<dyn DropNoticeHandler>,
    delete_handler: &Arc<dyn DeleteMailboxHandler>,
    revocation_handler: &Arc<dyn RevocationMailboxHandler>,
    my_master_pub: &IdentityPub,
    time_scale: u64,
    now_secs: u64,
) -> PollCounts {
    let started = Instant::now();
    let forgotten = pos.begin_poll(now_secs);

    // Poll our own mailbox from read-fanout peers. No watermark (`since_stored_at` =
    // None): a holder's re-published PoS response keeps its first `stored_at` and must
    // still come back (mailbox-i63, `pos_memo`).
    let mut answers = router.poll_stream(&MailboxAddress::for_master(my_master_pub), None, None);
    let mut seen = PollSeen::new(now_secs);
    let mut entry_count = 0usize;
    let mut first_entry_ms: Option<u64> = None;
    let mut counts = PollCounts::default();
    let mut responses_forwarded = false;

    while let Some((_postman, answer)) = answers.recv().await {
        let entries = seen.admit(answer);
        if entries.is_empty() {
            continue;
        }
        first_entry_ms.get_or_insert(started.elapsed().as_millis() as u64);
        entry_count += entries.len();
        // pos-i6: the answer's responses go as one batch — one lock of `pending` for
        // all of them — and first, before the challenges' publishes. Sequential, one
        // entry after another: the holder's answer limit is not bypassed.
        let (responses, others): (Vec<MailboxEntry>, Vec<MailboxEntry>) = entries
            .into_iter()
            .partition(|e| e.class == MailboxClass::PosResponse);
        if !responses.is_empty() {
            forward_pos_responses(pos, pos_response_tx, responses, now_secs, &mut counts).await;
            responses_forwarded = true;
        }
        for entry in others {
            dispatch_entry(
                router,
                pos_response_tx,
                pos,
                &mut counts,
                challenge_handler,
                drop_handler,
                delete_handler,
                revocation_handler,
                my_master_pub,
                entry,
                time_scale,
                now_secs,
            )
            .await;
        }
    }
    if !responses_forwarded {
        // Release the sent marks of resolved challenges even when no response came.
        forward_pos_responses(pos, pos_response_tx, vec![], now_secs, &mut counts).await;
    }

    // One line per poll (pos-i5 observables): INFO with entries, DEBUG when empty.
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let memo_answered = pos.answered.len();
    let memo_refused = pos.answered.refused();
    let memo_forwarded = pos.forwarded.len();
    if let Some(first_entry_ms) = first_entry_ms {
        info!(
            elapsed_ms,
            first_entry_ms,
            entries = entry_count,
            computed = counts.computed,
            no_answer = counts.no_answer,
            handler_error = counts.handler_error,
            republished = counts.republished,
            skipped = counts.skipped,
            publish_zero_ack = counts.publish_zero_ack,
            forwarded = counts.forwarded,
            not_pending = counts.not_pending,
            in_flight = counts.in_flight,
            deferred_full = counts.deferred_full,
            undecodable = counts.undecodable,
            memo_answered,
            memo_forwarded,
            memo_forgotten = forgotten,
            memo_refused,
            "mailbox_poll: poll done"
        );
    } else {
        debug!(
            elapsed_ms,
            entries = 0,
            memo_answered,
            memo_forwarded,
            memo_forgotten = forgotten,
            memo_refused,
            "mailbox_poll: poll done"
        );
    }
    counts
}

/// Unix seconds now.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Dispatch a single polled MailboxEntry to the appropriate handler.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch_entry(
    router: &Arc<MailboxRouter>,
    pos_response_tx: &mpsc::Sender<PosHashResponseMsg>,
    pos: &mut PosPollState,
    counts: &mut PollCounts,
    challenge_handler: &Arc<dyn PosMailboxChallengeHandler>,
    drop_handler: &Arc<dyn DropNoticeHandler>,
    delete_handler: &Arc<dyn DeleteMailboxHandler>,
    revocation_handler: &Arc<dyn RevocationMailboxHandler>,
    my_master_pub: &IdentityPub,
    entry: MailboxEntry,
    time_scale: u64,
    now_secs: u64,
) {
    match entry.class {
        MailboxClass::PosChallenge => {
            dispatch_pos_challenge(
                router,
                challenge_handler,
                &mut pos.answered,
                counts,
                my_master_pub,
                entry,
                time_scale,
                now_secs,
            )
            .await;
        }
        MailboxClass::PosResponse => {
            // The poll loop batches each answer's responses (`poll_once`); a single
            // entry takes the same path.
            forward_pos_responses(pos, pos_response_tx, vec![entry], now_secs, counts).await;
        }
        MailboxClass::SelfPointer => {
            drop_self_pointer_from_master_box(&entry);
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
                msg_id = %hex_encode(&entry.msg_id),
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

/// Handle a PosChallenge entry: compute the response once, publish it to the owner via
/// the mailbox, and keep it in `answered` (pos-i5).
///
/// The owner's master_pub comes from `entry.sender` (set by the scheduler when publishing
/// the challenge — see scheduler::issue_due_challenges).
///
/// `my_master_pub` is this (holder) node's master identity. It is stamped as the response
/// `sender` so the owner can resolve who to verify the response signature against (CS-ID-1).
///
/// The challenge entry stays in our box until its TTL, so the poll sees it on every poll.
/// Only the first sight computes (reads the symbols, hashes, signs). Later sights skip
/// it, or re-publish the remembered response entry (the same bytes, the same msg_id):
/// on the next poll after a 0-ack publish, otherwise once per quarter TTL while the
/// challenge and the response entry live. That re-publish is the retry (trap W-1: a
/// postman that lost the entry after acking it). A no-answer (Nack, unauthenticated,
/// oversized) is remembered too and re-checked once per quarter TTL; a handler error
/// is not remembered and is retried on the next poll.
#[allow(clippy::too_many_arguments)]
async fn dispatch_pos_challenge(
    router: &Arc<MailboxRouter>,
    challenge_handler: &Arc<dyn PosMailboxChallengeHandler>,
    answered: &mut AnsweredChallenges,
    counts: &mut PollCounts,
    my_master_pub: &IdentityPub,
    entry: MailboxEntry,
    time_scale: u64,
    now_secs: u64,
) {
    // CS-ID-6 / SM-8 (defense-in-depth): we only ever poll our own mailbox
    // (`router.poll(&my_master_pub, ...)`), so a PosChallenge that reaches dispatch
    // must be addressed to us. Effects are already gated by signature verification
    // (the holding lookup keys on owner_master from `entry.sender`), but this guard
    // documents and enforces the routing invariant: a buggy or hostile postman that
    // returns a mis-targeted entry is rejected here rather than processed.
    if entry.target != MailboxAddress::for_master(my_master_pub) {
        warn!(
            msg_id = %hex_encode(&entry.msg_id),
            entry_target = ?entry.target,
            "mailbox_poll: PosChallenge not addressed to this node — dropping (routing invariant)"
        );
        return;
    }

    let owner_master = match entry.sender {
        Some(s) => s,
        None => {
            warn!(
                msg_id = %hex_encode(&entry.msg_id),
                "mailbox_poll: PosChallenge has no sender — cannot publish response"
            );
            return;
        }
    };

    // pos-i5-a: decode first and key the memory by what the owner signed, so no
    // re-encoding of the same signed challenge is computed twice. An undecodable payload
    // is keyed by its raw bytes and ends as a no-answer here, without the handler (no
    // disk read). After mailbox encryption (C4) the entry is opened before this point.
    let decoded = from_cbor_bytes::<PosHashChallengeMsg>(&entry.payload).ok();
    let key = match &decoded {
        Some(c) => ChallengeKey::signed(Some(&owner_master), c),
        None => ChallengeKey::undecodable(&entry),
    };

    match answered.step(key, now_secs) {
        ChallengeStep::Skip => {
            counts.skipped += 1;
            return;
        }
        ChallengeStep::Republish {
            response,
            challenge_id,
        } => {
            let acks =
                publish_pos_response(router, response, &owner_master, &challenge_id, true).await;
            counts.republished += 1;
            if acks == 0 {
                counts.publish_zero_ack += 1;
            }
            answered.record_republish(key, acks, now_secs);
            return;
        }
        ChallengeStep::Compute => {}
    }

    if decoded.is_none() {
        counts.no_answer += 1;
        answered.remember_no_answer(key, now_secs);
        warn!(
            msg_id = %hex_encode(&entry.msg_id),
            owner = %owner_master,
            "mailbox_poll: undecodable PosChallenge — no answer (re-checked once per quarter TTL)"
        );
        return;
    }

    // Pass owner_master as the first arg — PosMailboxChallengeHandler uses it as owner_id
    // to look up our HoldingRecord (owner = the one who sent the challenge).
    match challenge_handler
        .handle_pos_challenge(owner_master, entry.payload.clone())
        .await
    {
        Ok(Some(response)) => {
            counts.computed += 1;
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
            let built_at = unix_now();

            // A3 (P1-4 / M1 / WARN-1): deterministic-but-UNPREDICTABLE msg_id.
            //
            // The response entry is kept in memory and re-published as is (see the fn
            // doc), so every copy the postmen see carries the same msg_id and bytes. The
            // owner's pending lives longer (POS_CHALLENGE_PENDING ≈14d2h) than the
            // challenge TTL (7d), so a late re-publish is still accepted. After a restart
            // the memory is empty and the response is computed again: the msg_id is the
            // same (same chain_hash), the timestamp and signature are new.
            //
            // The msg_id must be (a) STABLE across re-computes so postmen dedup re-
            // published responses (closes M1 pile-up), and (b) UNPREDICTABLE to a third
            // party so a postman that has merely seen the challenge cannot pre-occupy the
            // response key. We derive it from the chain_hash — which only a node that
            // actually holds the symbols can compute:
            //
            //     msg_id = BLAKE3("viaticum-pos-resp-msgid-v1" ‖ challenge_id ‖ chain_hash)[..16]
            //
            // Stable: the same challenge yields the same chain_hash, hence the same msg_id
            // on every re-compute. Unpredictable: a postman storing the challenge sees
            // `challenge_id` (plaintext in the challenge entry) but NOT the symbols, so it
            // cannot compute chain_hash → cannot predict this key. Using the raw
            // `challenge_id` would let any postman pre-store garbage under (owner_master,
            // challenge_id, PosResponse); the honest store would then collide → keep-first
            // Duplicate→Ack (we believe we delivered) while the postman keeps the garbage,
            // the owner's signature verify fails, and the pending dies at Timeout — re-
            // creating the very P1-4 false-penalty this fix prevents (WARN-1).
            //
            // Store dedup is KEEP-FIRST: an existing (target, msg_id, class) key returns
            // Duplicate→Ack (mailbox_insert / handle_mailbox_store), so a re-publish is an
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
                target: MailboxAddress::for_master(&owner_master),
                msg_id,
                class: MailboxClass::PosResponse,
                payload_version: 1,
                payload: response_payload,
                expires_at: built_at + ttl_secs,
                stored_at: built_at,
                // CS-ID-1: stamp our (holder) master so the owner can resolve and verify
                // the response signature. The owner does not trust this hint blindly — it
                // verifies the payload sig against the master of its own pending.holder_id.
                sender: Some(*my_master_pub),
            };

            let acks = publish_pos_response(
                router,
                response_entry.clone(),
                &owner_master,
                &response.challenge_id,
                false,
            )
            .await;
            if acks == 0 {
                counts.publish_zero_ack += 1;
            }
            answered.remember_response(key, response_entry, response.challenge_id, acks, now_secs);
        }
        Ok(None) => {
            // Nack or CannotCompute — challenge_handler already logged
            counts.no_answer += 1;
            answered.remember_no_answer(key, now_secs);
            debug!(msg_id = %hex_encode(&entry.msg_id), "mailbox_poll: PosChallenge handler returned no response (nack)");
        }
        Err(e) => {
            counts.handler_error += 1;
            error!(
                msg_id = %hex_encode(&entry.msg_id),
                err = %e,
                "mailbox_poll: PosChallenge handler error"
            );
        }
    }
}

/// Publish one PosResponse entry (fresh or from memory) and return its acks; a publish
/// error counts as 0 acks (the memory then re-publishes on the next poll).
async fn publish_pos_response(
    router: &Arc<MailboxRouter>,
    response_entry: MailboxEntry,
    owner_master: &IdentityPub,
    challenge_id: &[u8; 16],
    cached: bool,
) -> usize {
    match router.publish(response_entry, None).await {
        Ok(0) => {
            warn!(
                owner = %owner_master,
                challenge_id = %hex_encode(challenge_id),
                cached,
                "mailbox_poll: PosResponse publish got 0 acks — re-publishing from memory on the next poll"
            );
            0
        }
        Ok(acks) => {
            debug!(
                owner = %owner_master,
                challenge_id = %hex_encode(challenge_id),
                acks,
                cached,
                "mailbox_poll: PosResponse published"
            );
            acks
        }
        Err(e) => {
            error!(
                owner = %owner_master,
                challenge_id = %hex_encode(challenge_id),
                cached,
                err = %e,
                "mailbox_poll: PosResponse publish failed"
            );
            0
        }
    }
}

/// Capacity of the poll → scheduler PosResponse channel (pos-i6-b).
///
/// A poll puts at most this many responses into the channel; the rest wait at the
/// postmen for the next poll. A response lives at the postmen one TTL
/// (`POS_CHALLENGE_TTL` = 1 week) and the poll runs every `MAILBOX_POLL_INTERVAL_SECS`
/// (1 h), both divided by the same `time_scale`: 168 polls per TTL, so the owner can
/// take in at most `168 × POS_RESPONSE_CHANNEL_CAP` responses per TTL (fewer polls once
/// the poll interval floors at 1 s, `time_scale` > 3600).
///
/// The owner receives ≈ placements × cpw responses per week (`pos::challenges_per_week`,
/// cpw 1..2 for a placement under 1000 symbols). The former 256 capped it at 43 008 per
/// TTL: 5 376 blocks × 8 placements at cpw 1, ≈ 0.7 TB of 128 MiB blocks (≈ 0.35 TB at
/// cpw 2) — beyond that honest responses expired at the postmen and became timeouts.
/// 8192 ⇒ 1 376 256 responses per TTL ≈ 172 000 blocks × 8 at cpw 1 ≈ 21 TiB of
/// 128 MiB blocks (≈ 10.5 TiB at cpw 2).
///
/// Cost: a `PosHashResponseMsg` is fixed-size, no heap (~190 B), and tokio's bounded
/// channel allocates its slots in blocks of 32 as they fill: ≈ 1.5 MB with the channel
/// full, nothing extra when it is empty. A longer queue does not delay a response: one
/// not admitted waits a whole poll period at the postmen instead. The scheduler takes one
/// response per `select!` turn and holds `pending` only for that response's lookup and
/// removal, so its timers are not starved by a long queue.
pub(crate) const POS_RESPONSE_CHANNEL_CAP: usize = 8192;

/// The poll → scheduler PosResponse channel, `POS_RESPONSE_CHANNEL_CAP` deep.
pub(crate) fn pos_response_channel() -> (
    mpsc::Sender<PosHashResponseMsg>,
    mpsc::Receiver<PosHashResponseMsg>,
) {
    mpsc::channel(POS_RESPONSE_CHANNEL_CAP)
}

/// Hand the PosResponse entries of one poll to the scheduler (pos-i6).
///
/// One lock of `pending` covers the selection (no await inside it): only responses to
/// challenges still pending, each envelope once while it is pending, one envelope per
/// challenge per poll. Then `try_send` outside the lock: a sent envelope is marked; a
/// full channel leaves it unmarked and the next poll sends it (the entry lives at the
/// postmen until its TTL) — N-5 bounds the channel, nothing is dropped. Resolved,
/// foreign and duplicate responses are dropped silently and counted in `poll done`.
pub(crate) async fn forward_pos_responses(
    pos: &mut PosPollState,
    pos_response_tx: &mpsc::Sender<PosHashResponseMsg>,
    responses: Vec<MailboxEntry>,
    now_secs: u64,
    counts: &mut PollCounts,
) {
    if responses.is_empty() && pos.forwarded.is_empty() {
        return;
    }
    let (to_send, selected) = {
        let pending = pos.pending.lock().await;
        pos.forwarded.select(&pending, responses, now_secs)
    };
    counts.add_forward(selected);

    let mut deferred = 0u32;
    for r in to_send {
        match pos_response_tx.try_send(r.msg.clone()) {
            Ok(()) => {
                pos.forwarded.mark_sent(&r);
                counts.forwarded += 1;
                debug!(
                    challenge_id = %hex_encode(&r.challenge_id),
                    "mailbox_poll: PosResponse forwarded to scheduler"
                );
            }
            Err(mpsc::error::TrySendError::Full(_)) => deferred += 1,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                debug!("mailbox_poll: pos_response_tx closed (scheduler shut down)");
                break;
            }
        }
    }
    if deferred > 0 {
        counts.deferred_full += deferred;
        debug!(
            deferred,
            "mailbox_poll: pos_response_tx full — deferring to the next poll"
        );
    }
}

/// A SelfPointer polled from the master box (CROWN-1 РС3.1, mailbox-i37).
///
/// Pointers live in the seed-derived rendezvous box, and the daemon never reads its
/// own pointer box: only DR does. A SelfPointer in the master box is either a
/// pre-C3a leftover or a postman's plant; it is dropped with a warn and no effect
/// (nothing is stored, nothing in the push loop changes).
pub(crate) fn drop_self_pointer_from_master_box(entry: &MailboxEntry) {
    warn!(
        msg_id = %hex_encode(&entry.msg_id),
        target = %entry.target,
        "mailbox_poll: SelfPointer in the master box — dropped (pointers live in the rendezvous box)"
    );
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
    if entry.target != MailboxAddress::for_master(my_master_pub) {
        warn!(
            msg_id = %hex_encode(&entry.msg_id),
            entry_target = ?entry.target,
            "mailbox_poll: DropNotice not addressed to this node — dropping (routing invariant)"
        );
        return;
    }

    let sender = match entry.sender {
        Some(s) => s,
        None => {
            warn!(
                msg_id = %hex_encode(&entry.msg_id),
                target = %entry.target,
                "mailbox_poll: DropNotice has no sender — cannot identify holder, dropping"
            );
            return;
        }
    };

    match from_cbor_bytes::<SymbolDropNoticeBatchMsg>(&entry.payload) {
        Ok(batch) => {
            debug!(
                msg_id = %hex_encode(&entry.msg_id),
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
                msg_id = %hex_encode(&entry.msg_id),
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
    if entry.target != MailboxAddress::for_master(my_master_pub) {
        warn!(
            msg_id = %hex_encode(&entry.msg_id),
            entry_target = ?entry.target,
            "mailbox_poll: DeleteRequest not addressed to this node — dropping (routing invariant)"
        );
        return;
    }

    let owner_master = match entry.sender {
        Some(s) => s,
        None => {
            warn!(
                msg_id = %hex_encode(&entry.msg_id),
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
            msg_id = %hex_encode(&entry.msg_id),
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
    if entry.target != MailboxAddress::for_master(my_master_pub) {
        warn!(
            msg_id = %hex_encode(&entry.msg_id),
            entry_target = ?entry.target,
            "mailbox_poll: Revocation not addressed to this node — dropping (routing invariant)"
        );
        return;
    }

    let revoking_master = match entry.sender {
        Some(s) => s,
        None => {
            warn!(
                msg_id = %hex_encode(&entry.msg_id),
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
            msg_id = %hex_encode(&entry.msg_id),
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
