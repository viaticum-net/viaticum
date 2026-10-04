//! Owner side of the PoS poll memory (pos-i6): `ForwardedResponses`.
//!
//! A holder's response stays in the owner's master box until its TTL, and every live
//! response comes back on every poll. The poll hands the scheduler only the responses
//! whose challenge is still pending, and each response envelope once while it is pending:
//! the scheduler channel (bounded) is not flooded by answers already resolved, and the
//! log is not flooded by `unknown challenge_id` WARNs.
//!
//! A full channel loses nothing: an envelope is marked sent only after a successful
//! `try_send`, so an unsent one is selected again on the next poll (the entry lives at
//! the postmen until its TTL).
//!
//! The envelope's identity is what the holder signed plus the signature
//! (`ResponseKey::signed`), not the raw payload bytes or the msg_id (pos-i5-a, applied to
//! the owner): a postman's re-encoding of an honest response is the same envelope, and a
//! forgery under the honest challenge_id (another signature) is another envelope, so a
//! forgery forwarded first cannot lock the honest response out.

use std::collections::{HashMap, HashSet};

use tracing::warn;
use viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL;
use viaticum_core::mailbox::{MailboxEntry, scaled_ttl_secs};
use viaticum_core::messages::PosHashResponseMsg;
use viaticum_core::types::{from_cbor_bytes, hex_encode};

use super::MEMO_FULL_WARN_EVERY;
use crate::daemon::scheduler::PendingIndex;

/// Cap on remembered sent envelopes.
///
/// Honest bound: one pending challenge per placement, one honest envelope per challenge
/// (two after a holder restart), released as soon as the challenge leaves pending. A
/// postman can add one forged envelope per pending challenge per poll (one envelope per
/// challenge_id per poll is selected), each kept until its challenge resolves or one TTL
/// passes. ~100 B per entry ≈ 20 MB at the cap. Above the cap an envelope is not marked:
/// it is forwarded again on the next poll while its challenge is pending (the pre-pos-i6
/// behaviour, bounded by the channel).
pub const MAX_FORWARDED_RESPONSES: usize = 200_000;

/// The identity of one PosResponse envelope (pos-i6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResponseKey([u8; 32]);

impl ResponseKey {
    /// blake3 over the fields the holder signs (challenge_id, source_block_id,
    /// device_id, chain_hash, timestamp — decoded values in one fixed layout) and the
    /// signature. `v` and the entry's `sender` are not signed and not in the key. The
    /// responding `device_id` is signed and in the key: a sibling's response under the
    /// same challenge_id is another envelope, so it cannot lock out the addressed device's
    /// response (pos-i16).
    pub fn signed(r: &PosHashResponseMsg) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"viaticum-pos-memo-signed-response-v2");
        h.update(&r.challenge_id);
        h.update(&r.source_block_id.0);
        h.update(&r.device_id.0);
        h.update(&r.chain_hash);
        h.update(&r.timestamp.0.to_le_bytes());
        h.update(&r.sig);
        ResponseKey(*h.finalize().as_bytes())
    }
}

/// One response the poll may send to the scheduler.
#[derive(Debug, Clone)]
pub struct ResponseToForward {
    pub key: ResponseKey,
    pub challenge_id: [u8; 16],
    /// When the sent mark is dropped at the latest (first sight + TTL).
    pub forget_at: u64,
    pub msg: PosHashResponseMsg,
}

/// What `ForwardedResponses::select` did with one poll's PosResponse entries.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ForwardCounts {
    /// Chosen to be sent to the scheduler.
    pub selected: u32,
    /// Their challenge is not pending (resolved, timed out, someone else's, or the
    /// owner restarted): dropped without a WARN.
    pub not_pending: u32,
    /// Already sent and still pending, or a second envelope of a challenge already
    /// selected in this poll.
    pub in_flight: u32,
    /// Did not decode as a PosHashResponseMsg.
    pub undecodable: u32,
}

#[derive(Debug, Clone, Copy)]
struct Sent {
    challenge_id: [u8; 16],
    forget_at: u64,
}

/// The owner's memory of the response envelopes already handed to the scheduler.
#[derive(Debug)]
pub struct ForwardedResponses {
    sent: HashMap<ResponseKey, Sent>,
    ttl_secs: u64,
    max_sent: usize,
    refused: u64,
}

impl ForwardedResponses {
    /// `ttl` = the scaled PoS challenge TTL (the response entry's TTL).
    pub fn new(time_scale: u64) -> Self {
        Self::with_cap(time_scale, MAX_FORWARDED_RESPONSES)
    }

    /// `new` with another cap (tests exercise the cap without 200 000 entries).
    pub(crate) fn with_cap(time_scale: u64, max_sent: usize) -> Self {
        ForwardedResponses {
            sent: HashMap::new(),
            ttl_secs: scaled_ttl_secs(POS_CHALLENGE_TTL.as_secs(), time_scale),
            max_sent,
            refused: 0,
        }
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Release the sent envelopes whose challenge left `pending` or whose `forget_at`
    /// passed, then pick among `responses` (the PosResponse entries of this poll) the
    /// ones to send: challenge pending, envelope not sent yet, one envelope per
    /// challenge_id per call. Nothing is marked here: `mark_sent` after a successful send.
    pub fn select(
        &mut self,
        pending: &PendingIndex,
        responses: Vec<MailboxEntry>,
        now_secs: u64,
    ) -> (Vec<ResponseToForward>, ForwardCounts) {
        self.sent
            .retain(|_, s| pending.contains_challenge(&s.challenge_id) && s.forget_at > now_secs);

        let mut counts = ForwardCounts::default();
        let mut out = Vec::new();
        let mut chosen: HashSet<[u8; 16]> = HashSet::new();
        for entry in responses {
            let msg = match from_cbor_bytes::<PosHashResponseMsg>(&entry.payload) {
                Ok(m) => m,
                Err(e) => {
                    counts.undecodable += 1;
                    warn!(
                        msg_id = %hex_encode(&entry.msg_id),
                        err = %e,
                        "mailbox_poll: failed to decode PosHashResponseMsg"
                    );
                    continue;
                }
            };
            if !pending.contains_challenge(&msg.challenge_id) {
                counts.not_pending += 1;
                continue;
            }
            let key = ResponseKey::signed(&msg);
            if self.sent.contains_key(&key) || !chosen.insert(msg.challenge_id) {
                counts.in_flight += 1;
                continue;
            }
            counts.selected += 1;
            out.push(ResponseToForward {
                key,
                challenge_id: msg.challenge_id,
                forget_at: now_secs.saturating_add(self.ttl_secs),
                msg,
            });
        }
        (out, counts)
    }

    /// Mark `r` as handed to the scheduler. Call after a successful `try_send` only (a
    /// full channel leaves it unmarked, so the next poll selects it again).
    pub fn mark_sent(&mut self, r: &ResponseToForward) {
        if self.sent.len() >= self.max_sent && !self.sent.contains_key(&r.key) {
            self.refused += 1;
            if self.refused % MEMO_FULL_WARN_EVERY == 1 {
                warn!(
                    sent = self.sent.len(),
                    refused_total = self.refused,
                    "pos_memo: forwarded-response memory cap reached — not remembering this \
                     envelope (forwarded again while its challenge is pending)"
                );
            }
            return;
        }
        self.sent.insert(
            r.key,
            Sent {
                challenge_id: r.challenge_id,
                forget_at: r.forget_at,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.sent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sent.is_empty()
    }

    /// Mark refusals since start (the cap was reached).
    pub fn refused(&self) -> u64 {
        self.refused
    }
}

#[cfg(test)]
mod tests;
