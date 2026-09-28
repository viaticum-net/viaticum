// Tests for the holder's PoS memory (pos-i5). Pure logic: time is passed in.

use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::types::IdentityPub;

use super::{AnsweredChallenges, ChallengeStep, PollCounts, PosPollState, envelope_digest};

/// time_scale 900: TTL 672 s, retry 168 s (the scenario's scale).
const TS: u64 = 900;
const T0: u64 = 1_000_000;

fn holder() -> IdentityPub {
    IdentityPub([0xAA; 32])
}

fn owner() -> IdentityPub {
    IdentityPub([0x42; 32])
}

fn challenge(msg_id: u8, payload: Vec<u8>, issued_at: u64, ttl: u64) -> MailboxEntry {
    MailboxEntry {
        target: MailboxAddress::for_master(&holder()),
        msg_id: [msg_id; 16],
        class: MailboxClass::PosChallenge,
        payload_version: 1,
        payload,
        expires_at: issued_at + ttl,
        stored_at: issued_at,
        sender: Some(owner()),
    }
}

fn response(tag: u8, computed_at: u64, ttl: u64) -> MailboxEntry {
    MailboxEntry {
        target: MailboxAddress::for_master(&owner()),
        msg_id: [tag; 16],
        class: MailboxClass::PosResponse,
        payload_version: 1,
        payload: vec![tag; 300],
        expires_at: computed_at + ttl,
        stored_at: computed_at,
        sender: Some(holder()),
    }
}

fn is_republish(step: &ChallengeStep) -> bool {
    matches!(step, ChallengeStep::Republish { .. })
}

#[test]
fn new_challenge_is_computed() {
    let memo = AnsweredChallenges::new(TS);
    let c = challenge(1, vec![1, 2, 3], T0, memo.ttl_secs());
    assert_eq!(memo.step(&c, T0), ChallengeStep::Compute);
}

#[test]
fn retry_is_a_quarter_of_the_scaled_ttl() {
    let memo = AnsweredChallenges::new(TS);
    assert_eq!(memo.ttl_secs(), 672);
    assert_eq!(memo.retry_secs(), 168);
    // Production: 7 days and 42 hours.
    let prod = AnsweredChallenges::new(1);
    assert_eq!(prod.retry_secs(), 42 * 3600);
    // A huge scale floors at 1 s, never 0 (no re-publish on every poll).
    assert_eq!(AnsweredChallenges::new(u64::MAX).retry_secs(), 1);
}

#[test]
fn answered_challenge_is_skipped_within_quarter_ttl() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let c = challenge(1, vec![1, 2, 3], T0, ttl);
    memo.remember_response(&c, response(9, T0, ttl), [1; 16], 1, T0);
    for dt in [0, 4, 100, memo.retry_secs() - 1] {
        assert_eq!(
            memo.step(&c, T0 + dt),
            ChallengeStep::Skip,
            "an acked answer is neither recomputed nor re-published {dt} s later"
        );
    }
}

#[test]
fn answered_challenge_is_republished_from_cache_after_quarter_ttl() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let c = challenge(1, vec![1, 2, 3], T0, ttl);
    let cached = response(9, T0, ttl);
    memo.remember_response(&c, cached.clone(), [1; 16], 1, T0);
    match memo.step(&c, T0 + memo.retry_secs()) {
        ChallengeStep::Republish {
            response,
            challenge_id,
        } => {
            assert_eq!(response, cached, "the re-publish is the same bytes");
            assert_eq!(response.msg_id, cached.msg_id, "under the same msg_id");
            assert_eq!(challenge_id, [1; 16]);
        }
        other => panic!("expected a re-publish from memory, got {other:?}"),
    }
}

#[test]
fn zero_ack_answer_is_republished_on_next_poll() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let c = challenge(1, vec![1, 2, 3], T0, ttl);
    memo.remember_response(&c, response(9, T0, ttl), [1; 16], 0, T0);
    // Next poll (4 s later at TS 900): re-publish although TTL/4 has not passed.
    assert!(is_republish(&memo.step(&c, T0 + 4)));
    // Still 0 acks: keep trying on every poll.
    memo.record_republish(&c, 0, T0 + 4);
    assert!(is_republish(&memo.step(&c, T0 + 8)));
    // Acked: back to the quarter-TTL rhythm.
    memo.record_republish(&c, 1, T0 + 8);
    assert_eq!(memo.step(&c, T0 + 12), ChallengeStep::Skip);
}

#[test]
fn republish_stops_when_the_response_entry_expired() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    // A challenge alive for 2 TTL (capped by first-seen + TTL anyway) whose response
    // entry lives only 100 s.
    let c = challenge(1, vec![1, 2, 3], T0, 2 * ttl);
    memo.remember_response(&c, response(9, T0, 100), [1; 16], 0, T0);
    assert!(is_republish(&memo.step(&c, T0 + 4)));
    assert_eq!(
        memo.step(&c, T0 + 100),
        ChallengeStep::Skip,
        "an expired response entry is never re-published"
    );
    assert_eq!(memo.step(&c, T0 + memo.retry_secs()), ChallengeStep::Skip);
}

#[test]
fn at_most_three_republishes_over_the_challenge_life() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let poll = 4;
    let c = challenge(1, vec![1, 2, 3], T0, ttl);
    let mut computed = 0;
    let mut republished = 0;
    let mut now = T0;
    while now < c.expires_at {
        memo.forget_expired(now);
        match memo.step(&c, now) {
            ChallengeStep::Compute => {
                computed += 1;
                memo.remember_response(&c, response(9, now, ttl), [1; 16], 1, now);
            }
            ChallengeStep::Republish { .. } => {
                republished += 1;
                memo.record_republish(&c, 1, now);
            }
            ChallengeStep::Skip => {}
        }
        now += poll;
    }
    assert_eq!(computed, 1, "the symbols are read once per challenge");
    assert_eq!(
        republished, 3,
        "one re-publish per quarter TTL: 3 over the challenge's life"
    );
}

#[test]
fn forged_payload_under_same_msg_id_is_computed_separately() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let honest = challenge(1, vec![1, 2, 3], T0, ttl);
    let forged = challenge(1, vec![6, 6, 6], T0, ttl);
    // The forgery is seen first and gives no answer (no owner signature).
    memo.remember_no_answer(&forged, T0);
    assert_eq!(
        memo.step(&honest, T0 + 4),
        ChallengeStep::Compute,
        "the honest challenge is not locked out by a forgery under its msg_id"
    );
    memo.remember_response(&honest, response(9, T0 + 4, ttl), [1; 16], 1, T0 + 4);
    assert_eq!(memo.len(), 2, "two envelopes, two memory entries");
    assert_eq!(memo.step(&forged, T0 + 8), ChallengeStep::Skip);
    assert_eq!(memo.step(&honest, T0 + 8), ChallengeStep::Skip);
}

#[test]
fn forged_sender_under_same_msg_id_is_computed_separately() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let honest = challenge(1, vec![1, 2, 3], T0, ttl);
    let forged = MailboxEntry {
        sender: Some(IdentityPub([0x66; 32])),
        ..honest.clone()
    };
    assert_ne!(envelope_digest(&honest), envelope_digest(&forged));
    memo.remember_no_answer(&forged, T0);
    assert_eq!(memo.step(&honest, T0 + 4), ChallengeStep::Compute);
}

#[test]
fn envelope_digest_ignores_times_and_target() {
    let a = challenge(1, vec![1, 2, 3], T0, 672);
    let b = MailboxEntry {
        stored_at: T0 + 50,
        expires_at: T0 + 999,
        ..a.clone()
    };
    assert_eq!(envelope_digest(&a), envelope_digest(&b));
}

#[test]
fn no_answer_is_rechecked_only_after_quarter_ttl() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let c = challenge(1, vec![1, 2, 3], T0, ttl);
    memo.remember_no_answer(&c, T0);
    assert_eq!(memo.step(&c, T0 + 4), ChallengeStep::Skip);
    assert_eq!(
        memo.step(&c, T0 + memo.retry_secs() - 1),
        ChallengeStep::Skip
    );
    assert_eq!(
        memo.step(&c, T0 + memo.retry_secs()),
        ChallengeStep::Compute
    );
}

#[test]
fn recomputed_no_answer_keeps_the_challenge_forget_at() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let c = challenge(1, vec![1, 2, 3], T0, ttl);
    memo.remember_no_answer(&c, T0);
    let later = T0 + memo.retry_secs();
    memo.remember_response(&c, response(9, later, ttl), [1; 16], 1, later);
    assert_eq!(memo.len(), 1);
    assert_eq!(memo.forget_expired(c.expires_at - 1), 0);
    assert_eq!(
        memo.forget_expired(c.expires_at),
        1,
        "the life of the challenge does not restart on a re-check"
    );
}

#[test]
fn expired_entries_are_forgotten() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let short = challenge(1, vec![1], T0, 100);
    let long = challenge(2, vec![2], T0, ttl);
    memo.remember_response(&short, response(8, T0, ttl), [1; 16], 1, T0);
    memo.remember_no_answer(&long, T0);
    assert_eq!(memo.forget_expired(T0 + 99), 0);
    assert_eq!(memo.forget_expired(T0 + 100), 1);
    assert_eq!(memo.len(), 1);
    assert_eq!(memo.forget_expired(T0 + ttl), 1);
    assert!(memo.is_empty());
}

#[test]
fn forget_at_is_capped_by_first_seen_plus_ttl() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    // A challenge entry claiming a life far beyond the class TTL.
    let c = challenge(1, vec![1], T0, 100 * ttl);
    memo.remember_no_answer(&c, T0);
    assert_eq!(memo.forget_expired(T0 + ttl - 1), 0);
    assert_eq!(memo.forget_expired(T0 + ttl), 1);
}

#[test]
fn memory_survives_clock_steps_without_skipping_a_live_challenge() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let c = challenge(1, vec![1, 2, 3], T0, ttl);
    memo.remember_response(&c, response(9, T0, ttl), [1; 16], 1, T0);

    // Clock steps back an hour: the answer stays remembered, nothing is re-published
    // on every poll (the elapsed time saturates at 0).
    let back = T0 - 3600;
    memo.forget_expired(back);
    assert_eq!(memo.step(&c, back), ChallengeStep::Skip);
    assert_eq!(memo.step(&c, back + 4), ChallengeStep::Skip);
    // ...and once the clock is past the retry again, the re-publish comes.
    assert!(is_republish(&memo.step(&c, T0 + memo.retry_secs())));

    // Clock steps forward past the challenge's life: memory drops it, and a challenge
    // still shown by the postmen is computed once more, not skipped.
    let fwd = T0 + 10 * ttl;
    memo.forget_expired(fwd);
    assert!(memo.is_empty());
    assert_eq!(memo.step(&c, fwd), ChallengeStep::Compute);
}

#[test]
fn record_republish_of_unknown_challenge_is_a_no_op() {
    let mut memo = AnsweredChallenges::new(TS);
    let c = challenge(1, vec![1], T0, memo.ttl_secs());
    memo.record_republish(&c, 1, T0);
    assert!(memo.is_empty());
}

#[test]
fn restart_memory_is_empty_and_every_live_challenge_is_computed_once() {
    // RAM only (INV-4): a fresh poll state knows nothing, so the first poll after a
    // restart computes every live challenge (the pre-registered burst).
    let state = PosPollState::new(TS);
    let ttl = state.answered.ttl_secs();
    assert!(state.answered.is_empty());
    for id in 0..5u8 {
        let c = challenge(id, vec![id], T0, ttl);
        assert_eq!(state.answered.step(&c, T0), ChallengeStep::Compute);
    }
    assert_eq!(PollCounts::default().computed, 0);
}
