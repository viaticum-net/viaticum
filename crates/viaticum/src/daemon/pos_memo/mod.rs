//! What the mailbox poll remembers about PoS between polls (pos-i5, pos-i6).
//!
//! Owner side: `ForwardedResponses` (see `forwarded`): a response envelope goes to the
//! scheduler once while its challenge is pending.
//!
//! Holder side: `AnsweredChallenges`. A PoS challenge stays in the holder's master box
//! until its TTL, and the poll sees it on every poll. The holder computes it once
//! (reads the symbols, hashes, signs), keeps the signed response entry, and re-publishes
//! those same bytes rarely: on the next poll if the publish got 0 acks, otherwise once
//! per quarter TTL while the challenge and the response entry are alive. The re-publish
//! is insurance against a postman that lost the entry after acking it (trap W-1); since
//! mailbox-i60 the entry reaches every reachable postman of the write fanout anyway.
//!
//! RAM only (INV-4): after a restart the memory is empty and every live challenge is
//! computed once more (pre-registered burst, pos-i5-c). Pure: no I/O, `now_secs` is
//! passed in.
//!
//! pos-i5-a: nothing a postman controls without a signature steers the memory. The key
//! of a decodable challenge is its owner-signed content plus the signature
//! (`ChallengeKey::signed`): not the `msg_id`, not the raw payload bytes (a postman can re-encode
//! a signed challenge many ways without breaking the signature: another `v` or
//! `device_id`, another key order, an extra field, a trailing byte). An entry lives `ttl`
//! from first sight, not until the envelope's `expires_at`; the number of entries is capped
//! per kind (see `MAX_REMEMBERED_RESPONSES`, `MAX_REMEMBERED_NO_ANSWERS`). The holder
//! answers only a fresh challenge (`PosResponder`: age ≤ TTL + clock skew), so a postman
//! can only replay challenges within that window, and each distinct signed challenge is
//! computed at most once per TTL of memory.

use std::collections::HashMap;

use tracing::warn;
use viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL;
use viaticum_core::mailbox::{MailboxClass, MailboxEntry, scaled_ttl_secs};
use viaticum_core::messages::PosHashChallengeMsg;
use viaticum_core::types::IdentityPub;

use crate::daemon::scheduler::PendingChallenges;

mod forwarded;
pub use forwarded::{
    ForwardCounts, ForwardedResponses, MAX_FORWARDED_RESPONSES, ResponseKey, ResponseToForward,
};

/// Cap on remembered responses (pos-i5-a).
///
/// A response entry is created only for a fresh challenge signed by the owner over a block
/// this holder really holds. A postman cannot mint one; it can only replay challenges the
/// owner issued within the last TTL + clock skew, and each distinct signed challenge is
/// computed at most once per TTL of memory (the key is its signed content, not its
/// encoding). So the responses are bounded by what the owners issued. Honest bound: one
/// challenge is alive per
/// interval, `challenges_per_week` is 1-2 for a placement below 1000 symbols (base 1 ×
/// volume 1 × (2 − trust)), and the challenge TTL is one week, so live challenges ≤ 2 ×
/// placements held. A friend with ~100 GB of others' data at ~1 MiB per placement holds
/// ~100 000 placements → ≤ 200 000 live challenges; a friends-circle node holds thousands.
/// RAM at the cap: ~450 B per entry (the signed response entry ~300 B + key + map
/// overhead) ≈ 90 MB, reachable only by an owner issuing that many signed challenges
/// for its own blocks (each of which costs a real compute anyway). Above the cap a
/// response is not remembered: that challenge is computed on every poll, as before pos-i5.
pub const MAX_REMEMBERED_RESPONSES: usize = 200_000;

/// Cap on remembered no-answers (pos-i5-a).
///
/// A no-answer is what a postman's junk becomes (undecodable, a bad signature, a stale
/// replay), so this is the entry kind a hostile postman can mint without limit. Kept
/// separate and small so junk never takes the responses' room (then the honest answers
/// stay remembered and the disk is not re-read). Honest no-answers are Nacks (a block
/// dropped, a volume not mounted yet, pos-i5-b), a small share of the live challenges.
/// ~100 B per entry ≈ 1 MB at the cap. Above it junk is re-checked on every poll: a decode,
/// a signature check or a freshness check, all before any disk read.
pub const MAX_REMEMBERED_NO_ANSWERS: usize = 10_000;

/// A refusal to remember (cap reached) is logged on the 1st, then every this many.
pub const MEMO_FULL_WARN_EVERY: u64 = 1_000;

/// The memory key of one PoS challenge (pos-i5-a).
///
/// The poll decodes the challenge first and keys the memory by what the owner signed
/// (`signed`); a payload that does not decode gets a key over its raw bytes
/// (`undecodable`) and ends as a no-answer without a disk read. After mailbox encryption
/// (C4, line B) the poll opens the entry before this step and passes the opened
/// challenge: nothing here changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChallengeKey([u8; 32]);

impl ChallengeKey {
    /// blake3 over the class, the claimed sender (the owner whose key the signature is
    /// checked against), the fields the owner signs (challenge_id, source_block_id,
    /// esi_ranges, timestamp — decoded values in one fixed layout) and the signature.
    ///
    /// Every re-encoding a postman can make without breaking the signature (another key
    /// order, an extra field, a trailing byte, another `v` or `device_id`) maps to the
    /// same key: `v` and `device_id` are not signed and the chain hash does not depend on
    /// them. The signature is in the key: a forgery with the honest `challenge_id` and a
    /// junk signature is another key, so it cannot occupy the honest challenge's entry.
    pub fn signed(sender: Option<&IdentityPub>, c: &PosHashChallengeMsg) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"viaticum-pos-memo-signed-challenge-v1");
        h.update(&[MailboxClass::PosChallenge as u8]);
        update_sender(&mut h, sender);
        h.update(&c.challenge_id);
        h.update(&c.source_block_id.0);
        h.update(&(c.esi_ranges.len() as u64).to_le_bytes());
        for (start, count) in &c.esi_ranges {
            h.update(&start.to_le_bytes());
            h.update(&count.to_le_bytes());
        }
        h.update(&c.timestamp.0.to_le_bytes());
        h.update(&c.sig);
        ChallengeKey(*h.finalize().as_bytes())
    }

    /// blake3 over the class, the claimed sender and the raw payload bytes: the key of an
    /// entry whose payload is not a decodable challenge.
    pub fn undecodable(entry: &MailboxEntry) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"viaticum-pos-memo-envelope-v1");
        h.update(&[entry.class as u8]);
        update_sender(&mut h, entry.sender.as_ref());
        h.update(&(entry.payload.len() as u64).to_le_bytes());
        h.update(&entry.payload);
        ChallengeKey(*h.finalize().as_bytes())
    }
}

fn update_sender(h: &mut blake3::Hasher, sender: Option<&IdentityPub>) {
    match sender {
        Some(s) => {
            h.update(&[1]);
            h.update(&s.0);
        }
        None => {
            h.update(&[0]);
        }
    }
}

/// What the poll does with one challenge entry this time.
#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeStep {
    /// Not in memory (or another envelope, or a no-answer due for a re-check): ask the
    /// handler.
    Compute,
    /// Publish this remembered response entry as is, under its own msg_id (0 acks last
    /// time, or TTL/4 passed).
    Republish {
        response: MailboxEntry,
        challenge_id: [u8; 16],
    },
    /// Nothing to do this poll.
    Skip,
}

#[derive(Debug, Clone)]
enum Outcome {
    /// The signed response entry and the acks of its last publish.
    Response {
        entry: MailboxEntry,
        challenge_id: [u8; 16],
        last_acks: usize,
    },
    /// The handler gave no answer (Nack, junk, unauthenticated or oversized challenge).
    NoAnswer,
}

impl Outcome {
    fn is_response(&self) -> bool {
        matches!(self, Outcome::Response { .. })
    }
}

#[derive(Debug, Clone)]
struct Answered {
    /// First sight + ttl: the entry is dropped once `now >= forget_at`.
    forget_at: u64,
    /// Last compute or publish of this entry.
    last_try_at: u64,
    outcome: Outcome,
}

/// The holder's memory of PoS challenges it already answered (pos-i5).
#[derive(Debug)]
pub struct AnsweredChallenges {
    by_key: HashMap<ChallengeKey, Answered>,
    ttl_secs: u64,
    retry_secs: u64,
    max_responses: usize,
    max_no_answers: usize,
    responses: usize,
    no_answers: usize,
    refused: u64,
}

impl AnsweredChallenges {
    /// `ttl` = the scaled PoS challenge TTL; `retry` = max(1, ttl / 4).
    pub fn new(time_scale: u64) -> Self {
        Self::with_caps(
            time_scale,
            MAX_REMEMBERED_RESPONSES,
            MAX_REMEMBERED_NO_ANSWERS,
        )
    }

    /// `new` with other caps (tests exercise the cap without 200 000 entries).
    pub(crate) fn with_caps(time_scale: u64, max_responses: usize, max_no_answers: usize) -> Self {
        let ttl_secs = scaled_ttl_secs(POS_CHALLENGE_TTL.as_secs(), time_scale);
        AnsweredChallenges {
            by_key: HashMap::new(),
            ttl_secs,
            retry_secs: (ttl_secs / 4).max(1),
            max_responses,
            max_no_answers,
            responses: 0,
            no_answers: 0,
            refused: 0,
        }
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    pub fn retry_secs(&self) -> u64 {
        self.retry_secs
    }

    /// Decide what to do with `challenge` at `now_secs`.
    ///
    /// A clock step backwards only delays the next re-publish or re-check (the elapsed
    /// time saturates at 0); a step forwards makes `forget_expired` drop the entry and
    /// the challenge is computed once more. Neither skips a live challenge.
    pub fn step(&self, key: ChallengeKey, now_secs: u64) -> ChallengeStep {
        let Some(a) = self.by_key.get(&key) else {
            return ChallengeStep::Compute;
        };
        if now_secs >= a.forget_at {
            return ChallengeStep::Compute;
        }
        let due = now_secs.saturating_sub(a.last_try_at) >= self.retry_secs;
        match &a.outcome {
            Outcome::Response {
                entry,
                challenge_id,
                last_acks,
            } => {
                if now_secs >= entry.expires_at {
                    ChallengeStep::Skip
                } else if *last_acks == 0 || due {
                    ChallengeStep::Republish {
                        response: entry.clone(),
                        challenge_id: *challenge_id,
                    }
                } else {
                    ChallengeStep::Skip
                }
            }
            Outcome::NoAnswer => {
                if due {
                    ChallengeStep::Compute
                } else {
                    ChallengeStep::Skip
                }
            }
        }
    }

    /// Remember a computed response entry and how many acks its first publish got.
    pub fn remember_response(
        &mut self,
        key: ChallengeKey,
        response: MailboxEntry,
        challenge_id: [u8; 16],
        acks: usize,
        now_secs: u64,
    ) {
        self.remember(
            key,
            Outcome::Response {
                entry: response,
                challenge_id,
                last_acks: acks,
            },
            now_secs,
        );
    }

    /// Remember that the handler gave no answer (Nack, unauthenticated, oversized).
    pub fn remember_no_answer(&mut self, key: ChallengeKey, now_secs: u64) {
        self.remember(key, Outcome::NoAnswer, now_secs);
    }

    /// Record a re-publish of the remembered response and its acks.
    pub fn record_republish(&mut self, key: ChallengeKey, acks: usize, now_secs: u64) {
        if let Some(a) = self.by_key.get_mut(&key) {
            a.last_try_at = now_secs;
            if let Outcome::Response { last_acks, .. } = &mut a.outcome {
                *last_acks = acks;
            }
        }
    }

    /// Drop entries whose `forget_at` passed; returns how many.
    pub fn forget_expired(&mut self, now_secs: u64) -> usize {
        let (mut responses, mut no_answers) = (0usize, 0usize);
        self.by_key.retain(|_, a| {
            let keep = a.forget_at > now_secs;
            if !keep {
                if a.outcome.is_response() {
                    responses += 1;
                } else {
                    no_answers += 1;
                }
            }
            keep
        });
        self.responses -= responses;
        self.no_answers -= no_answers;
        responses + no_answers
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Remember refusals since start (a cap was reached).
    pub fn refused(&self) -> u64 {
        self.refused
    }

    /// A re-compute of a remembered envelope keeps its `forget_at` (the challenge's life
    /// does not restart); a new envelope gets `now + ttl` (the envelope's `expires_at` is
    /// not signed, pos-i5-a). A new entry of a kind whose cap is reached is not stored
    /// (and an entry that would change into that kind is dropped): the challenge is then
    /// computed on every poll, the pre-pos-i5 behaviour.
    fn remember(&mut self, key: ChallengeKey, outcome: Outcome, now_secs: u64) {
        let is_response = outcome.is_response();
        let was_response = self.by_key.get(&key).map(|a| a.outcome.is_response());
        if was_response != Some(is_response) {
            let full = if is_response {
                self.responses >= self.max_responses
            } else {
                self.no_answers >= self.max_no_answers
            };
            if full {
                if let Some(old) = was_response {
                    self.by_key.remove(&key);
                    self.uncount(old);
                }
                self.refuse(is_response);
                return;
            }
            if let Some(old) = was_response {
                self.uncount(old);
            }
            if is_response {
                self.responses += 1;
            } else {
                self.no_answers += 1;
            }
        }
        let forget_at = now_secs.saturating_add(self.ttl_secs);
        self.by_key
            .entry(key)
            .and_modify(|a| {
                // An entry past its life (not yet forgotten) starts a new one.
                if a.forget_at <= now_secs {
                    a.forget_at = forget_at;
                }
                a.last_try_at = now_secs;
                a.outcome = outcome.clone();
            })
            .or_insert(Answered {
                forget_at,
                last_try_at: now_secs,
                outcome,
            });
    }

    fn uncount(&mut self, was_response: bool) {
        if was_response {
            self.responses -= 1;
        } else {
            self.no_answers -= 1;
        }
    }

    fn refuse(&mut self, is_response: bool) {
        self.refused += 1;
        if self.refused % MEMO_FULL_WARN_EVERY == 1 {
            warn!(
                kind = if is_response { "response" } else { "no_answer" },
                responses = self.responses,
                no_answers = self.no_answers,
                refused_total = self.refused,
                "pos_memo: memory cap reached — not remembering this challenge (computed on every poll)"
            );
        }
    }
}

/// Counters of one poll, printed by `mailbox_poll: poll done`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PollCounts {
    /// Postmen whose answer the poll read before its deadline (mailbox-i63).
    pub responders: u32,
    /// Challenges the handler answered with a response this poll (symbols read).
    pub computed: u32,
    /// Challenges the handler gave no answer to (Nack, unauthenticated, oversized).
    pub no_answer: u32,
    /// Challenges the handler failed on (not remembered, retried next poll).
    pub handler_error: u32,
    /// Remembered responses published again from memory.
    pub republished: u32,
    /// Challenges answered before and not due for anything this poll.
    pub skipped: u32,
    /// Response publishes (fresh or from memory) that got 0 acks.
    pub publish_zero_ack: u32,
    /// PosResponse entries handed to the scheduler.
    pub forwarded: u32,
    /// PosResponse entries not handed over because the channel was full (the entry
    /// stays at the postmen and comes back on the next poll).
    pub deferred_full: u32,
    /// PosResponse entries that did not decode.
    pub undecodable: u32,
    /// PosResponse entries whose challenge is not pending (resolved, timed out, not
    /// ours): dropped without a WARN (pos-i6).
    pub not_pending: u32,
    /// PosResponse entries already handed over and still pending, or a second envelope
    /// of one challenge in the same postman's answer (pos-i6, mailbox-i63).
    pub in_flight: u32,
}

impl PollCounts {
    /// Add what `ForwardedResponses::select` counted (`selected` is counted as
    /// `forwarded` / `deferred_full` by the send).
    pub fn add_forward(&mut self, f: ForwardCounts) {
        self.not_pending += f.not_pending;
        self.in_flight += f.in_flight;
        self.undecodable += f.undecodable;
    }
}

/// Everything the poll loop keeps about PoS between polls.
#[derive(Debug)]
pub struct PosPollState {
    /// The owner's in-flight challenges (written by the scheduler, read here).
    pub pending: PendingChallenges,
    pub answered: AnsweredChallenges,
    pub forwarded: ForwardedResponses,
}

impl PosPollState {
    pub fn new(pending: PendingChallenges, time_scale: u64) -> Self {
        PosPollState {
            pending,
            answered: AnsweredChallenges::new(time_scale),
            forwarded: ForwardedResponses::new(time_scale),
        }
    }

    /// Start of one poll: forget what expired; returns how many entries were dropped.
    pub fn begin_poll(&mut self, now_secs: u64) -> usize {
        self.answered.forget_expired(now_secs)
    }
}

#[cfg(test)]
mod tests;
