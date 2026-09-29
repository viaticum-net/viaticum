// Tests for the holder's PoS memory (pos-i5). Pure logic: time is passed in.

use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::types::IdentityPub;

use viaticum_core::messages::{PosHashChallengeMsg, build_pos_hash_challenge, to_cbor};
use viaticum_core::types::{SourceBlockId, Timestamp, from_cbor_bytes};

use super::{
    AnsweredChallenges, ChallengeKey, ChallengeStep, MAX_REMEMBERED_NO_ANSWERS,
    MAX_REMEMBERED_RESPONSES, PollCounts, PosPollState,
};

/// The key the poll uses for `e`: signed content when the payload decodes as a
/// challenge, the raw bytes otherwise (as `dispatch_pos_challenge` does).
fn k(e: &MailboxEntry) -> ChallengeKey {
    match from_cbor_bytes::<PosHashChallengeMsg>(&e.payload) {
        Ok(c) => ChallengeKey::signed(e.sender.as_ref(), &c),
        Err(_) => ChallengeKey::undecodable(e),
    }
}

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
    assert_eq!(memo.step(k(&c), T0), ChallengeStep::Compute);
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
    memo.remember_response(k(&c), response(9, T0, ttl), [1; 16], 1, T0);
    for dt in [0, 4, 100, memo.retry_secs() - 1] {
        assert_eq!(
            memo.step(k(&c), T0 + dt),
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
    memo.remember_response(k(&c), cached.clone(), [1; 16], 1, T0);
    match memo.step(k(&c), T0 + memo.retry_secs()) {
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
    memo.remember_response(k(&c), response(9, T0, ttl), [1; 16], 0, T0);
    // Next poll (4 s later at TS 900): re-publish although TTL/4 has not passed.
    assert!(is_republish(&memo.step(k(&c), T0 + 4)));
    // Still 0 acks: keep trying on every poll.
    memo.record_republish(k(&c), 0, T0 + 4);
    assert!(is_republish(&memo.step(k(&c), T0 + 8)));
    // Acked: back to the quarter-TTL rhythm.
    memo.record_republish(k(&c), 1, T0 + 8);
    assert_eq!(memo.step(k(&c), T0 + 12), ChallengeStep::Skip);
}

#[test]
fn republish_stops_when_the_response_entry_expired() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    // A challenge alive for 2 TTL (capped by first-seen + TTL anyway) whose response
    // entry lives only 100 s.
    let c = challenge(1, vec![1, 2, 3], T0, 2 * ttl);
    memo.remember_response(k(&c), response(9, T0, 100), [1; 16], 0, T0);
    assert!(is_republish(&memo.step(k(&c), T0 + 4)));
    assert_eq!(
        memo.step(k(&c), T0 + 100),
        ChallengeStep::Skip,
        "an expired response entry is never re-published"
    );
    assert_eq!(
        memo.step(k(&c), T0 + memo.retry_secs()),
        ChallengeStep::Skip
    );
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
        match memo.step(k(&c), now) {
            ChallengeStep::Compute => {
                computed += 1;
                memo.remember_response(k(&c), response(9, now, ttl), [1; 16], 1, now);
            }
            ChallengeStep::Republish { .. } => {
                republished += 1;
                memo.record_republish(k(&c), 1, now);
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
    memo.remember_no_answer(k(&forged), T0);
    assert_eq!(
        memo.step(k(&honest), T0 + 4),
        ChallengeStep::Compute,
        "the honest challenge is not locked out by a forgery under its msg_id"
    );
    memo.remember_response(k(&honest), response(9, T0 + 4, ttl), [1; 16], 1, T0 + 4);
    assert_eq!(memo.len(), 2, "two envelopes, two memory entries");
    assert_eq!(memo.step(k(&forged), T0 + 8), ChallengeStep::Skip);
    assert_eq!(memo.step(k(&honest), T0 + 8), ChallengeStep::Skip);
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
    assert_ne!(k(&honest), k(&forged));
    memo.remember_no_answer(k(&forged), T0);
    assert_eq!(memo.step(k(&honest), T0 + 4), ChallengeStep::Compute);
}

#[test]
fn undecodable_key_ignores_times_and_target() {
    let a = challenge(1, vec![1, 2, 3], T0, 672);
    let b = MailboxEntry {
        stored_at: T0 + 50,
        expires_at: T0 + 999,
        ..a.clone()
    };
    assert_eq!(k(&a), k(&b));
}

#[test]
fn no_answer_is_rechecked_only_after_quarter_ttl() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let c = challenge(1, vec![1, 2, 3], T0, ttl);
    memo.remember_no_answer(k(&c), T0);
    assert_eq!(memo.step(k(&c), T0 + 4), ChallengeStep::Skip);
    assert_eq!(
        memo.step(k(&c), T0 + memo.retry_secs() - 1),
        ChallengeStep::Skip
    );
    assert_eq!(
        memo.step(k(&c), T0 + memo.retry_secs()),
        ChallengeStep::Compute
    );
}

#[test]
fn recomputed_no_answer_keeps_the_challenge_forget_at() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    // The envelope claims a long life; the memory still counts from first sight.
    let c = challenge(1, vec![1, 2, 3], T0, 100 * ttl);
    memo.remember_no_answer(k(&c), T0);
    let later = T0 + memo.retry_secs();
    memo.remember_response(k(&c), response(9, later, ttl), [1; 16], 1, later);
    assert_eq!(memo.len(), 1);
    assert_eq!(memo.forget_expired(T0 + ttl - 1), 0);
    assert_eq!(
        memo.forget_expired(T0 + ttl),
        1,
        "the life of the challenge does not restart on a re-check"
    );
}

#[test]
fn expired_entries_are_forgotten() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let first = challenge(1, vec![1], T0, ttl);
    let second = challenge(2, vec![2], T0 + 100, ttl);
    memo.remember_response(k(&first), response(8, T0, ttl), [1; 16], 1, T0);
    memo.remember_no_answer(k(&second), T0 + 100);
    assert_eq!(memo.forget_expired(T0 + ttl - 1), 0);
    assert_eq!(memo.forget_expired(T0 + ttl), 1);
    assert_eq!(memo.len(), 1);
    assert_eq!(memo.forget_expired(T0 + ttl + 100), 1);
    assert!(memo.is_empty());
}

#[test]
fn forget_at_is_first_seen_plus_ttl_even_for_a_long_envelope() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    // A challenge entry claiming a life far beyond the class TTL.
    let c = challenge(1, vec![1], T0, 100 * ttl);
    memo.remember_no_answer(k(&c), T0);
    assert_eq!(memo.forget_expired(T0 + ttl - 1), 0);
    assert_eq!(memo.forget_expired(T0 + ttl), 1);
}

#[test]
fn memory_survives_clock_steps_without_skipping_a_live_challenge() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let c = challenge(1, vec![1, 2, 3], T0, ttl);
    memo.remember_response(k(&c), response(9, T0, ttl), [1; 16], 1, T0);

    // Clock steps back an hour: the answer stays remembered, nothing is re-published
    // on every poll (the elapsed time saturates at 0).
    let back = T0 - 3600;
    memo.forget_expired(back);
    assert_eq!(memo.step(k(&c), back), ChallengeStep::Skip);
    assert_eq!(memo.step(k(&c), back + 4), ChallengeStep::Skip);
    // ...and once the clock is past the retry again, the re-publish comes.
    assert!(is_republish(&memo.step(k(&c), T0 + memo.retry_secs())));

    // Clock steps forward past the challenge's life: memory drops it, and a challenge
    // still shown by the postmen is computed once more, not skipped.
    let fwd = T0 + 10 * ttl;
    memo.forget_expired(fwd);
    assert!(memo.is_empty());
    assert_eq!(memo.step(k(&c), fwd), ChallengeStep::Compute);
}

#[test]
fn record_republish_of_unknown_challenge_is_a_no_op() {
    let mut memo = AnsweredChallenges::new(TS);
    let c = challenge(1, vec![1], T0, memo.ttl_secs());
    memo.record_republish(k(&c), 1, T0);
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
        assert_eq!(state.answered.step(k(&c), T0), ChallengeStep::Compute);
    }
    assert_eq!(PollCounts::default().computed, 0);
}

// ─── pos-i5-a: unsigned envelope fields do not steer the memory; caps ────────────

#[test]
fn rotated_msg_id_of_the_same_challenge_is_not_recomputed() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let c = challenge(1, vec![1, 2, 3], T0, ttl);
    memo.remember_response(k(&c), response(9, T0, ttl), [1; 16], 1, T0);
    for id in 2..20u8 {
        let rotated = MailboxEntry {
            msg_id: [id; 16],
            ..c.clone()
        };
        assert_eq!(
            memo.step(k(&rotated), T0 + 4),
            ChallengeStep::Skip,
            "a postman renaming the same challenge gets no second compute"
        );
    }
    assert_eq!(memo.len(), 1);
}

#[test]
fn rotated_msg_id_republishes_under_the_response_own_msg_id() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let c = challenge(1, vec![1, 2, 3], T0, ttl);
    let cached = response(9, T0, ttl);
    memo.remember_response(k(&c), cached.clone(), [1; 16], 0, T0);
    let rotated = MailboxEntry {
        msg_id: [0x77; 16],
        ..c
    };
    match memo.step(k(&rotated), T0 + 4) {
        ChallengeStep::Republish { response, .. } => assert_eq!(response.msg_id, cached.msg_id),
        other => panic!("expected a re-publish, got {other:?}"),
    }
}

#[test]
fn short_envelope_expires_at_does_not_shorten_the_memory() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    // The (unsigned) expires_at says 10 s; the memory keeps the entry a full TTL.
    let c = challenge(1, vec![1, 2, 3], T0, 10);
    memo.remember_response(k(&c), response(9, T0, ttl), [1; 16], 1, T0);
    assert_eq!(memo.forget_expired(T0 + 11), 0);
    assert_eq!(memo.step(k(&c), T0 + 12), ChallengeStep::Skip);
    assert_eq!(memo.forget_expired(T0 + ttl), 1);
}

#[test]
fn memory_does_not_grow_past_the_response_cap() {
    let mut memo = AnsweredChallenges::with_caps(TS, 3, 3);
    let ttl = memo.ttl_secs();
    for id in 0..10u8 {
        let c = challenge(id, vec![id], T0, ttl);
        memo.remember_response(k(&c), response(id, T0, ttl), [id; 16], 1, T0);
    }
    assert_eq!(memo.len(), 3, "above the cap nothing is stored");
    assert_eq!(memo.refused(), 7);
    // Not remembered = computed as before pos-i5, never silently skipped.
    let over = challenge(9, vec![9], T0, ttl);
    assert_eq!(memo.step(k(&over), T0 + 4), ChallengeStep::Compute);
}

#[test]
fn junk_no_answers_do_not_take_the_responses_room() {
    let mut memo = AnsweredChallenges::with_caps(TS, 3, 2);
    let ttl = memo.ttl_secs();
    // A postman floods junk: only the no-answer room fills.
    for id in 0..50u8 {
        memo.remember_no_answer(k(&challenge(id, vec![0xEE, id], T0, ttl)), T0);
    }
    assert_eq!(memo.len(), 2);
    // The honest answers are still remembered.
    let honest = challenge(200, vec![1, 2, 3], T0, ttl);
    memo.remember_response(k(&honest), response(9, T0, ttl), [1; 16], 1, T0);
    assert_eq!(memo.step(k(&honest), T0 + 4), ChallengeStep::Skip);
    assert_eq!(memo.len(), 3);
}

#[test]
fn forgetting_frees_room_under_the_cap() {
    let mut memo = AnsweredChallenges::with_caps(TS, 1, 1);
    let ttl = memo.ttl_secs();
    let a = challenge(1, vec![1], T0, ttl);
    let b = challenge(2, vec![2], T0, ttl);
    memo.remember_response(k(&a), response(1, T0, ttl), [1; 16], 1, T0);
    memo.remember_response(k(&b), response(2, T0, ttl), [2; 16], 1, T0);
    assert_eq!(memo.len(), 1);
    memo.forget_expired(T0 + ttl);
    memo.remember_response(k(&b), response(2, T0 + ttl, ttl), [2; 16], 1, T0 + ttl);
    assert_eq!(memo.len(), 1, "the room of the forgotten entry is reused");
    assert_eq!(memo.step(k(&b), T0 + ttl + 4), ChallengeStep::Skip);
}

#[test]
fn no_answer_turning_into_response_at_a_full_cap_is_dropped_not_kept_stale() {
    let mut memo = AnsweredChallenges::with_caps(TS, 1, 5);
    let ttl = memo.ttl_secs();
    let full = challenge(1, vec![1], T0, ttl);
    memo.remember_response(k(&full), response(1, T0, ttl), [1; 16], 1, T0);
    let c = challenge(2, vec![2], T0, ttl);
    memo.remember_no_answer(k(&c), T0);
    let later = T0 + memo.retry_secs();
    memo.remember_response(k(&c), response(2, later, ttl), [2; 16], 1, later);
    // It cannot be stored as a response and must not stay a stale no-answer (that would
    // skip the challenge for another quarter TTL while its answer is never published).
    assert_eq!(memo.step(k(&c), later + 4), ChallengeStep::Compute);
    assert_eq!(memo.len(), 1);
}

#[test]
fn production_caps_are_the_documented_ones() {
    assert_eq!(MAX_REMEMBERED_RESPONSES, 200_000);
    assert_eq!(MAX_REMEMBERED_NO_ANSWERS, 10_000);
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    for i in 0..(MAX_REMEMBERED_NO_ANSWERS as u32 + 100) {
        let c = challenge(0, i.to_le_bytes().to_vec(), T0, ttl);
        memo.remember_no_answer(k(&c), T0);
    }
    assert_eq!(memo.len(), MAX_REMEMBERED_NO_ANSWERS);
    assert_eq!(memo.refused(), 100);
}

#[test]
fn begin_poll_forgets_what_expired() {
    let mut state = PosPollState::new(TS);
    let ttl = state.answered.ttl_secs();
    let c = challenge(1, vec![1], T0, ttl);
    state.answered.remember_no_answer(k(&c), T0);
    assert_eq!(state.begin_poll(T0 + ttl - 1), 0);
    assert_eq!(state.begin_poll(T0 + ttl), 1);
    assert!(state.answered.is_empty());
}

#[test]
fn challenge_seen_after_its_memory_expired_is_computed_once_more_not_every_poll() {
    // Without a forget in between (a poll that skipped `begin_poll`), an entry past its
    // forget_at is computed once and remembered afresh, not recomputed on every poll.
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let c = challenge(1, vec![1, 2, 3], T0, ttl);
    memo.remember_response(k(&c), response(9, T0, ttl), [1; 16], 1, T0);
    let late = T0 + ttl + 4;
    assert_eq!(memo.step(k(&c), late), ChallengeStep::Compute);
    memo.remember_response(k(&c), response(9, late, ttl), [1; 16], 1, late);
    assert_eq!(memo.step(k(&c), late + 4), ChallengeStep::Skip);
}

// ─── pos-i5-a: the key is the owner-signed content, not its encoding ─────────────

fn owner_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
}

fn signed() -> PosHashChallengeMsg {
    build_pos_hash_challenge(
        [0x5A; 16],
        SourceBlockId([8; 32]),
        vec![(0, 3), (10, 2)],
        Timestamp(1_700_000_000),
        None,
        &owner_key(),
    )
}

fn entry_with(payload: Vec<u8>) -> MailboxEntry {
    MailboxEntry {
        sender: Some(IdentityPub(owner_key().verifying_key().to_bytes())),
        ..challenge(1, payload, T0, 672)
    }
}

/// Re-encode `c` through a generic CBOR value and let `f` edit it.
fn reencoded(c: &PosHashChallengeMsg, f: impl FnOnce(&mut ciborium::Value)) -> Vec<u8> {
    let bytes = to_cbor(c).unwrap();
    let mut v: ciborium::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    f(&mut v);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&v, &mut out).unwrap();
    out
}

/// Every re-encoding a postman can make without breaking the signature: each decodes
/// as the same signed challenge and gets the same key.
fn postman_variants() -> Vec<(&'static str, Vec<u8>)> {
    let c = signed();
    let honest = to_cbor(&c).unwrap();
    let mut with_tail = honest.clone();
    with_tail.push(0x00);
    vec![
        (
            "device_id",
            to_cbor(&PosHashChallengeMsg {
                device_id: Some(viaticum_core::types::DeviceId([7; 32])),
                ..c.clone()
            })
            .unwrap(),
        ),
        (
            "v",
            to_cbor(&PosHashChallengeMsg { v: 9, ..c.clone() }).unwrap(),
        ),
        (
            "extra field",
            reencoded(&c, |v| {
                if let ciborium::Value::Map(m) = v {
                    m.push((
                        ciborium::Value::Text("zz".into()),
                        ciborium::Value::Integer(1.into()),
                    ));
                }
            }),
        ),
        ("trailing byte", with_tail),
        (
            "key order",
            reencoded(&c, |v| {
                if let ciborium::Value::Map(m) = v {
                    m.reverse();
                }
            }),
        ),
        ("honest", honest),
    ]
}

#[test]
fn every_reencoding_of_a_signed_challenge_has_the_same_key() {
    let honest = k(&entry_with(to_cbor(&signed()).unwrap()));
    for (name, payload) in postman_variants() {
        let e = entry_with(payload);
        assert!(
            from_cbor_bytes::<PosHashChallengeMsg>(&e.payload).is_ok(),
            "variant '{name}' must still decode (else it is not a door)"
        );
        assert_eq!(k(&e), honest, "variant '{name}' must map to the honest key");
    }
}

#[test]
fn reencoded_challenge_is_not_computed_again() {
    let mut memo = AnsweredChallenges::new(TS);
    let ttl = memo.ttl_secs();
    let first = entry_with(to_cbor(&signed()).unwrap());
    memo.remember_response(k(&first), response(9, T0, ttl), [0x5A; 16], 1, T0);
    for (name, payload) in postman_variants() {
        assert_eq!(
            memo.step(k(&entry_with(payload)), T0 + 4),
            ChallengeStep::Skip,
            "variant '{name}' is the same challenge"
        );
    }
    assert_eq!(memo.len(), 1);
}

#[test]
fn junk_signature_under_the_honest_challenge_id_is_another_key() {
    let honest = signed();
    let forged = PosHashChallengeMsg {
        sig: [0x13; 64],
        ..honest.clone()
    };
    let hk = k(&entry_with(to_cbor(&honest).unwrap()));
    let fk = k(&entry_with(to_cbor(&forged).unwrap()));
    assert_ne!(
        hk, fk,
        "a forgery cannot occupy the honest challenge's entry"
    );

    let mut memo = AnsweredChallenges::new(TS);
    memo.remember_no_answer(fk, T0);
    assert_eq!(memo.step(hk, T0 + 4), ChallengeStep::Compute);
}

#[test]
fn signed_fields_are_all_in_the_key() {
    let c = signed();
    let base = k(&entry_with(to_cbor(&c).unwrap()));
    let edits: Vec<PosHashChallengeMsg> = vec![
        PosHashChallengeMsg {
            challenge_id: [1; 16],
            ..c.clone()
        },
        PosHashChallengeMsg {
            source_block_id: SourceBlockId([9; 32]),
            ..c.clone()
        },
        PosHashChallengeMsg {
            esi_ranges: vec![(0, 3)],
            ..c.clone()
        },
        PosHashChallengeMsg {
            timestamp: Timestamp(1),
            ..c.clone()
        },
    ];
    for e in edits {
        assert_ne!(k(&entry_with(to_cbor(&e).unwrap())), base);
    }
    let other_sender = MailboxEntry {
        sender: Some(IdentityPub([0x66; 32])),
        ..entry_with(to_cbor(&c).unwrap())
    };
    assert_ne!(k(&other_sender), base);
}
