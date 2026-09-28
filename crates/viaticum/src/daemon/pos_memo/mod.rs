//! What the mailbox poll remembers about PoS between polls (pos-i5).
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
//! is the envelope digest (class, sender, payload), not the `msg_id`; an entry lives
//! `ttl` from first sight, not until the envelope's `expires_at`; the number of entries
//! is capped per kind (see `MAX_REMEMBERED_RESPONSES`, `MAX_REMEMBERED_NO_ANSWERS`).

use std::collections::HashMap;

use tracing::warn;
use viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL;
use viaticum_core::mailbox::{MailboxEntry, scaled_ttl_secs};

/// Cap on remembered responses (pos-i5-a).
///
/// A response entry exists only for an owner-signed challenge over a block this holder
/// really holds, so a postman cannot create one. Honest bound: one challenge is alive per
/// interval, `challenges_per_week` is 1-2 for a placement below 1000 symbols (base 1 ×
/// volume 1 × (2 − trust)), and the challenge TTL is one week, so live challenges ≤ 2 ×
/// placements held. A friend with ~100 GB of others' data at ~1 MiB per placement holds
/// ~100 000 placements → ≤ 200 000 live challenges; a friends-circle node holds thousands.
/// RAM at the cap: ~450 B per entry (the signed response entry ~300 B + key + map
/// overhead) ≈ 90 MB, reachable only by a malicious owner flooding signed challenges
/// for its own blocks (each of which costs a real compute anyway). Above the cap a
/// response is not remembered: that challenge is computed on every poll, as before pos-i5.
pub const MAX_REMEMBERED_RESPONSES: usize = 200_000;

/// Cap on remembered no-answers (pos-i5-a).
///
/// A no-answer is what a postman's junk becomes (undecodable, unsigned, oversized), so this
/// is the entry kind a hostile postman can mint without limit. Kept separate and small so
/// junk never takes the responses' room (then the honest answers stay remembered and the
/// disk is not re-read). Honest no-answers are Nacks (a block dropped, a volume not mounted
/// yet, pos-i5-b), a small share of the live challenges. ~100 B per entry ≈ 1 MB at the cap.
/// Above it junk is re-checked on every poll: a decode or a signature check, no disk read.
pub const MAX_REMEMBERED_NO_ANSWERS: usize = 10_000;

/// A refusal to remember (cap reached) is logged on the 1st, then every this many.
pub const MEMO_FULL_WARN_EVERY: u64 = 1_000;

/// blake3 over what the handler's answer depends on: the class, the claimed sender (the
/// owner whose signature the challenge is checked against) and the payload. It is the
/// memory key (pos-i5-a): the `msg_id` is not in it, so a postman rotating the `msg_id`
/// of the same challenge gets no second compute; a forgery (another payload, or the same
/// payload under another sender) is another envelope and gets its own entry, so it can
/// neither borrow nor lock out the honest challenge's answer.
pub fn envelope_digest(entry: &MailboxEntry) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"viaticum-pos-memo-envelope-v1");
    h.update(&[entry.class as u8]);
    match &entry.sender {
        Some(s) => {
            h.update(&[1]);
            h.update(&s.0);
        }
        None => {
            h.update(&[0]);
        }
    }
    h.update(&(entry.payload.len() as u64).to_le_bytes());
    h.update(&entry.payload);
    *h.finalize().as_bytes()
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

fn key_of(challenge: &MailboxEntry) -> [u8; 32] {
    envelope_digest(challenge)
}

/// The holder's memory of PoS challenges it already answered (pos-i5).
#[derive(Debug)]
pub struct AnsweredChallenges {
    by_envelope: HashMap<[u8; 32], Answered>,
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
            by_envelope: HashMap::new(),
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
    pub fn step(&self, challenge: &MailboxEntry, now_secs: u64) -> ChallengeStep {
        let Some(a) = self.by_envelope.get(&key_of(challenge)) else {
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
        challenge: &MailboxEntry,
        response: MailboxEntry,
        challenge_id: [u8; 16],
        acks: usize,
        now_secs: u64,
    ) {
        self.remember(
            challenge,
            Outcome::Response {
                entry: response,
                challenge_id,
                last_acks: acks,
            },
            now_secs,
        );
    }

    /// Remember that the handler gave no answer (Nack, unauthenticated, oversized).
    pub fn remember_no_answer(&mut self, challenge: &MailboxEntry, now_secs: u64) {
        self.remember(challenge, Outcome::NoAnswer, now_secs);
    }

    /// Record a re-publish of the remembered response and its acks.
    pub fn record_republish(&mut self, challenge: &MailboxEntry, acks: usize, now_secs: u64) {
        if let Some(a) = self.by_envelope.get_mut(&key_of(challenge)) {
            a.last_try_at = now_secs;
            if let Outcome::Response { last_acks, .. } = &mut a.outcome {
                *last_acks = acks;
            }
        }
    }

    /// Drop entries whose `forget_at` passed; returns how many.
    pub fn forget_expired(&mut self, now_secs: u64) -> usize {
        let (mut responses, mut no_answers) = (0usize, 0usize);
        self.by_envelope.retain(|_, a| {
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
        self.by_envelope.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_envelope.is_empty()
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
    fn remember(&mut self, challenge: &MailboxEntry, outcome: Outcome, now_secs: u64) {
        let key = key_of(challenge);
        let is_response = outcome.is_response();
        let was_response = self.by_envelope.get(&key).map(|a| a.outcome.is_response());
        if was_response != Some(is_response) {
            let full = if is_response {
                self.responses >= self.max_responses
            } else {
                self.no_answers >= self.max_no_answers
            };
            if full {
                if let Some(old) = was_response {
                    self.by_envelope.remove(&key);
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
        self.by_envelope
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
}

/// Everything the poll loop keeps about PoS between polls.
#[derive(Debug)]
pub struct PosPollState {
    pub answered: AnsweredChallenges,
}

impl PosPollState {
    pub fn new(time_scale: u64) -> Self {
        PosPollState {
            answered: AnsweredChallenges::new(time_scale),
        }
    }

    /// Start of one poll: forget what expired; returns how many entries were dropped.
    pub fn begin_poll(&mut self, now_secs: u64) -> usize {
        self.answered.forget_expired(now_secs)
    }
}

#[cfg(test)]
mod tests;
