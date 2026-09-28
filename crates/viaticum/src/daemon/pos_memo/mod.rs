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
//! computed once more (pre-registered burst). Pure: no I/O, `now_secs` is passed in.

use std::collections::HashMap;

use viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL;
use viaticum_core::mailbox::{MailboxEntry, scaled_ttl_secs};

/// blake3 over what the handler's answer depends on besides the `msg_id`: the class,
/// the claimed sender (the owner whose signature the challenge is checked against) and
/// the payload. A postman's forgery under the same `msg_id` (another payload, or the
/// same payload under another sender) is another envelope and gets its own memory entry,
/// so it can neither borrow nor lock out the honest challenge's answer.
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
    /// Publish this remembered response entry as is (0 acks last time, or TTL/4 passed).
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
    /// The handler gave no answer (Nack, unauthenticated or oversized challenge).
    NoAnswer,
}

#[derive(Debug, Clone)]
struct Answered {
    /// The entry is dropped once `now >= forget_at` (the challenge expired).
    forget_at: u64,
    /// Last compute or publish of this entry.
    last_try_at: u64,
    outcome: Outcome,
}

type Key = ([u8; 16], [u8; 32]);

fn key_of(challenge: &MailboxEntry) -> Key {
    (challenge.msg_id, envelope_digest(challenge))
}

/// The holder's memory of PoS challenges it already answered (pos-i5).
#[derive(Debug)]
pub struct AnsweredChallenges {
    by_envelope: HashMap<Key, Answered>,
    ttl_secs: u64,
    retry_secs: u64,
}

impl AnsweredChallenges {
    /// `ttl` = the scaled PoS challenge TTL; `retry` = max(1, ttl / 4).
    pub fn new(time_scale: u64) -> Self {
        let ttl_secs = scaled_ttl_secs(POS_CHALLENGE_TTL.as_secs(), time_scale);
        AnsweredChallenges {
            by_envelope: HashMap::new(),
            ttl_secs,
            retry_secs: (ttl_secs / 4).max(1),
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
        let before = self.by_envelope.len();
        self.by_envelope.retain(|_, a| a.forget_at > now_secs);
        before - self.by_envelope.len()
    }

    pub fn len(&self) -> usize {
        self.by_envelope.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_envelope.is_empty()
    }

    /// A re-compute of a remembered envelope keeps its `forget_at` (the challenge's
    /// life does not restart); a new envelope gets
    /// `min(challenge.expires_at, now + ttl)`.
    fn remember(&mut self, challenge: &MailboxEntry, outcome: Outcome, now_secs: u64) {
        let forget_at = challenge
            .expires_at
            .min(now_secs.saturating_add(self.ttl_secs));
        self.by_envelope
            .entry(key_of(challenge))
            .and_modify(|a| {
                a.last_try_at = now_secs;
                a.outcome = outcome.clone();
            })
            .or_insert(Answered {
                forget_at,
                last_try_at: now_secs,
                outcome,
            });
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
}

#[cfg(test)]
mod tests;
