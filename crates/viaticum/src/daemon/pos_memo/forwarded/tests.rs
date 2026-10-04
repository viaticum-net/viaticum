// Tests for the owner's PoS poll memory (pos-i6): which responses go to the scheduler.
// Pure logic: the pending index is built by hand, time is passed in.

use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::messages::{PosHashResponseMsg, build_pos_hash_response, to_cbor};
use viaticum_core::types::{DeviceId, IdentityPub, SourceBlockId, Timestamp};

use super::{ForwardCounts, ForwardedResponses, ResponseKey};
use crate::daemon::scheduler::{PendingHashChallenge, PendingIndex};

/// time_scale 900: TTL 672 s (the scenario's scale).
const TS: u64 = 900;
const T0: u64 = 1_000_000;

fn owner() -> IdentityPub {
    IdentityPub([0x42; 32])
}

fn block() -> SourceBlockId {
    SourceBlockId([8; 32])
}

fn holder_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x31; 32])
}

fn postman_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x66; 32])
}

/// A pending challenge `cid` to holder device `[cid[0]; 32]`.
fn pending_challenge(cid: [u8; 16]) -> PendingHashChallenge {
    PendingHashChallenge {
        source_block_id: block(),
        holder_id: DeviceId([cid[0]; 32]),
        esi_ranges: vec![(0, 1)],
        expected_chain_hash: [0; 32],
        issued_at: Timestamp(T0),
        challenge_id: cid,
        holder_master: IdentityPub(holder_key().verifying_key().to_bytes()),
    }
}

fn pending_with(cids: &[[u8; 16]]) -> PendingIndex {
    let mut p = PendingIndex::default();
    for cid in cids {
        let c = pending_challenge(*cid);
        p.insert((c.source_block_id, c.holder_id), c);
    }
    p
}

fn resolve(p: &mut PendingIndex, cid: [u8; 16]) {
    let key = p.key_of(&cid).expect("pending");
    p.remove(&key);
}

/// A response to `cid` signed by `key`, at `at`.
fn response_msg(cid: [u8; 16], key: &ed25519_dalek::SigningKey, at: u64) -> PosHashResponseMsg {
    build_pos_hash_response(cid, block(), [9; 32], Timestamp(at), None, key)
}

fn entry_of(msg: &PosHashResponseMsg, msg_id: u8) -> MailboxEntry {
    entry_with_payload(to_cbor(msg).unwrap(), msg_id)
}

fn entry_with_payload(payload: Vec<u8>, msg_id: u8) -> MailboxEntry {
    MailboxEntry {
        target: MailboxAddress::for_master(&owner()),
        msg_id: [msg_id; 16],
        class: MailboxClass::PosResponse,
        payload_version: 1,
        payload,
        expires_at: T0 + 10_000,
        stored_at: T0,
        sender: Some(IdentityPub(holder_key().verifying_key().to_bytes())),
    }
}

/// The honest response to `cid` as a mailbox entry.
fn honest(cid: [u8; 16]) -> MailboxEntry {
    entry_of(&response_msg(cid, &holder_key(), T0), cid[0])
}

/// One poll with one answer: select, then "send" everything selected (a channel with
/// room).
fn poll_and_send(
    memo: &mut ForwardedResponses,
    pending: &PendingIndex,
    entries: Vec<MailboxEntry>,
    now: u64,
) -> (Vec<[u8; 16]>, ForwardCounts) {
    memo.begin_poll();
    answer_and_send(memo, pending, entries, now)
}

/// One more postman's answer in the current poll: select, then "send" what was selected.
fn answer_and_send(
    memo: &mut ForwardedResponses,
    pending: &PendingIndex,
    entries: Vec<MailboxEntry>,
    now: u64,
) -> (Vec<[u8; 16]>, ForwardCounts) {
    let (out, counts) = memo.select(pending, entries, now);
    for r in &out {
        memo.mark_sent(r);
    }
    (out.iter().map(|r| r.challenge_id).collect(), counts)
}

const C1: [u8; 16] = [1; 16];
const C2: [u8; 16] = [2; 16];

#[test]
fn pending_response_is_selected_once_with_its_message() {
    let pending = pending_with(&[C1]);
    let mut memo = ForwardedResponses::new(TS);
    let (out, counts) = memo.select(&pending, vec![honest(C1)], T0);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].challenge_id, C1);
    assert_eq!(out[0].msg, response_msg(C1, &holder_key(), T0));
    assert_eq!(out[0].forget_at, T0 + memo.ttl_secs());
    assert_eq!(
        counts,
        ForwardCounts {
            selected: 1,
            ..ForwardCounts::default()
        }
    );
}

/// M0-b: a response whose challenge is already resolved does not go to the scheduler.
#[test]
fn resolved_response_is_not_selected() {
    let mut pending = pending_with(&[C1]);
    resolve(&mut pending, C1);
    let mut memo = ForwardedResponses::new(TS);
    let (out, counts) = memo.select(&pending, vec![honest(C1)], T0);
    assert!(out.is_empty());
    assert_eq!(counts.not_pending, 1);
}

/// M0-b′: the envelope already handed over is not sent again while its challenge is
/// pending (the scheduler has not read it yet).
#[test]
fn second_copy_of_pending_response_is_not_selected() {
    let pending = pending_with(&[C1]);
    let mut memo = ForwardedResponses::new(TS);
    let (first, _) = poll_and_send(&mut memo, &pending, vec![honest(C1)], T0);
    assert_eq!(first, vec![C1]);
    for poll in 1..=3u64 {
        let (again, counts) = poll_and_send(&mut memo, &pending, vec![honest(C1)], T0 + 4 * poll);
        assert!(again.is_empty(), "poll {poll}: not sent twice");
        assert_eq!(counts.in_flight, 1);
    }
    assert_eq!(memo.len(), 1);
}

/// The sent mark lives only while the challenge is pending: once it resolves, the mark
/// is released (and the late copy counts as not pending, not in flight).
#[test]
fn sent_entry_is_released_when_pending_resolves() {
    let mut pending = pending_with(&[C1, C2]);
    let mut memo = ForwardedResponses::new(TS);
    poll_and_send(&mut memo, &pending, vec![honest(C1), honest(C2)], T0);
    assert_eq!(memo.len(), 2);

    resolve(&mut pending, C1);
    let (out, counts) = poll_and_send(&mut memo, &pending, vec![honest(C1)], T0 + 4);

    assert!(out.is_empty());
    assert_eq!(memo.len(), 1, "C1's mark released, C2's kept");
    assert_eq!((counts.not_pending, counts.in_flight), (1, 0));
}

/// K0-4: a postman's forgery under the honest challenge_id, sent first, does not lock
/// the honest response out: the honest envelope is another key and goes on the next poll
/// (only one envelope per challenge per poll is selected).
#[test]
fn forged_response_does_not_lock_out_the_honest_one() {
    let pending = pending_with(&[C1]);
    let mut memo = ForwardedResponses::new(TS);
    let forged = entry_of(&response_msg(C1, &postman_key(), T0), 0xF0);

    let (first, counts) = poll_and_send(&mut memo, &pending, vec![forged.clone()], T0);
    assert_eq!(
        first,
        vec![C1],
        "the forgery goes first (the scheduler rejects it)"
    );
    assert_eq!(counts.selected, 1);

    // The scheduler rejected the forgery: the challenge stays pending.
    let (second, counts) = poll_and_send(
        &mut memo,
        &pending,
        vec![forged.clone(), honest(C1)],
        T0 + 4,
    );
    assert_eq!(second, vec![C1], "the honest envelope is selected");
    assert_eq!(counts.in_flight, 1, "the forgery is in flight");

    // Both orders of one poll: the honest one is never shadowed by a sent forgery.
    let mut memo = ForwardedResponses::new(TS);
    poll_and_send(&mut memo, &pending, vec![forged.clone()], T0);
    memo.begin_poll();
    let (out, _) = memo.select(&pending, vec![honest(C1), forged], T0 + 4);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].msg, response_msg(C1, &holder_key(), T0));
}

/// pos-i5-a on the owner: a postman's re-encoding of the honest response (another `v`,
/// another `device_id`, another sender or msg_id) is the same envelope — it is not sent
/// to the scheduler again.
#[test]
fn reencoded_response_is_the_same_envelope() {
    let pending = pending_with(&[C1]);
    let mut memo = ForwardedResponses::new(TS);
    let msg = response_msg(C1, &holder_key(), T0);
    poll_and_send(&mut memo, &pending, vec![entry_of(&msg, 1)], T0);

    let variants = vec![
        entry_of(
            &PosHashResponseMsg {
                v: 9,
                ..msg.clone()
            },
            2,
        ),
        entry_of(
            &PosHashResponseMsg {
                device_id: Some(DeviceId([7; 32])),
                ..msg.clone()
            },
            3,
        ),
        MailboxEntry {
            sender: Some(IdentityPub([0x77; 32])),
            ..entry_of(&msg, 4)
        },
    ];
    for (i, e) in variants.into_iter().enumerate() {
        let (out, counts) = poll_and_send(&mut memo, &pending, vec![e], T0 + 4 * (i as u64 + 1));
        assert!(out.is_empty(), "variant {i} is the same envelope");
        assert_eq!(counts.in_flight, 1);
    }
    assert_eq!(
        ResponseKey::signed(&msg),
        ResponseKey::signed(&PosHashResponseMsg {
            v: 9,
            ..msg.clone()
        })
    );
}

/// A holder restart re-computes the response (new timestamp and signature): a second
/// honest envelope of a still-pending challenge is forwarded once.
#[test]
fn recomputed_response_after_holder_restart_is_forwarded() {
    let pending = pending_with(&[C1]);
    let mut memo = ForwardedResponses::new(TS);
    poll_and_send(&mut memo, &pending, vec![honest(C1)], T0);
    let recomputed = entry_of(&response_msg(C1, &holder_key(), T0 + 100), 1);
    let (out, _) = poll_and_send(&mut memo, &pending, vec![honest(C1), recomputed], T0 + 104);
    assert_eq!(out, vec![C1]);
    assert_eq!(memo.len(), 2);
}

/// pos-i6 under mailbox-i63 (review W1): the poll selects once per postman's answer, but
/// one envelope per challenge_id per POLL goes to the scheduler. Two honest envelopes of
/// one challenge (a holder restart) in two answers of one poll: the second is in flight;
/// it goes on the next poll, the challenge being still pending.
#[test]
fn second_envelope_of_a_challenge_in_a_later_answer_of_the_same_poll_is_in_flight() {
    let pending = pending_with(&[C1]);
    let mut memo = ForwardedResponses::new(TS);
    let recomputed = entry_of(&response_msg(C1, &holder_key(), T0 + 100), 1);

    let (first, _) = poll_and_send(&mut memo, &pending, vec![honest(C1)], T0);
    assert_eq!(first, vec![C1]);
    let (second, counts) = answer_and_send(&mut memo, &pending, vec![recomputed.clone()], T0);
    assert!(second.is_empty(), "one envelope per challenge per poll");
    assert_eq!((counts.selected, counts.in_flight), (0, 1));

    let (next_poll, counts) =
        poll_and_send(&mut memo, &pending, vec![honest(C1), recomputed], T0 + 4);
    assert_eq!(
        next_poll,
        vec![C1],
        "the other envelope goes on the next poll"
    );
    assert_eq!(counts.in_flight, 1, "the first one is in flight");
}

/// An envelope selected but not sent (full channel) still counts as this poll's choice:
/// a second envelope of its challenge later in the poll does not overtake it.
#[test]
fn deferred_choice_still_holds_the_challenge_for_the_poll() {
    let pending = pending_with(&[C1]);
    let mut memo = ForwardedResponses::new(TS);
    memo.begin_poll();
    let (out, _) = memo.select(&pending, vec![honest(C1)], T0);
    assert_eq!(out.len(), 1);
    // try_send failed (Full): no mark_sent.
    let recomputed = entry_of(&response_msg(C1, &holder_key(), T0 + 100), 1);
    let (out, counts) = memo.select(&pending, vec![recomputed], T0);
    assert!(out.is_empty());
    assert_eq!(counts.in_flight, 1);
}

/// N-5 / K0-5: a full channel loses nothing — `select` marks nothing by itself, so an
/// envelope that was not sent is selected again on the next poll.
#[test]
fn unsent_after_full_channel_is_selected_again() {
    let pending = pending_with(&[C1]);
    let mut memo = ForwardedResponses::new(TS);
    let (out, _) = memo.select(&pending, vec![honest(C1)], T0);
    assert_eq!(out.len(), 1);
    // try_send failed (Full): no mark_sent.
    assert!(memo.is_empty());
    memo.begin_poll();
    let (again, counts) = memo.select(&pending, vec![honest(C1)], T0 + 4);
    assert_eq!(again.len(), 1, "selected again on the next poll");
    assert_eq!(counts.selected, 1);
}

/// pos-i6: a response to a challenge we never issued (or forgot on a restart) is
/// counted, not forwarded — it never reaches the scheduler's `unknown challenge_id` WARN.
#[test]
fn unknown_challenge_response_is_counted_not_warned() {
    let pending = pending_with(&[C1]);
    let mut memo = ForwardedResponses::new(TS);
    let (out, counts) = memo.select(&pending, vec![honest(C2), honest([3; 16])], T0);
    assert!(out.is_empty());
    assert_eq!(
        counts,
        ForwardCounts {
            not_pending: 2,
            ..ForwardCounts::default()
        }
    );
}

#[test]
fn undecodable_response_is_counted() {
    let pending = pending_with(&[C1]);
    let mut memo = ForwardedResponses::new(TS);
    let (out, counts) = memo.select(&pending, vec![entry_with_payload(vec![0xFF, 0], 1)], T0);
    assert!(out.is_empty());
    assert_eq!(counts.undecodable, 1);
}

/// A sent mark lives at most one TTL from first sight (bounded memory even for a
/// challenge the scheduler never resolves — a forgery it keeps rejecting).
#[test]
fn sent_mark_is_forgotten_one_ttl_later() {
    let pending = pending_with(&[C1]);
    let mut memo = ForwardedResponses::new(TS);
    let ttl = memo.ttl_secs();
    poll_and_send(&mut memo, &pending, vec![honest(C1)], T0);
    memo.select(&pending, vec![], T0 + ttl - 1);
    assert_eq!(memo.len(), 1);
    memo.select(&pending, vec![], T0 + ttl);
    assert!(memo.is_empty());
}

/// The mark's lifetime is the owner's own clock (first sight + TTL), not the entry's
/// `expires_at`: that field is not signed, a postman sets it. An envelope stamped to
/// expire one second after first sight and still served, its challenge still pending,
/// eight seconds later is in flight, not handed to the scheduler a second time.
#[test]
fn sent_mark_outlives_an_entry_expires_at_in_the_past() {
    let pending = pending_with(&[C1]);
    let mut memo = ForwardedResponses::new(TS);
    let short_lived = MailboxEntry {
        expires_at: T0 + 1,
        ..honest(C1)
    };
    let (first, _) = poll_and_send(&mut memo, &pending, vec![short_lived.clone()], T0);
    assert_eq!(first, vec![C1]);

    let (again, counts) = poll_and_send(&mut memo, &pending, vec![short_lived], T0 + 8);

    assert!(again.is_empty(), "not re-selected");
    assert_eq!((counts.selected, counts.in_flight), (0, 1));
    assert_eq!(memo.len(), 1);
}

/// Above the cap an envelope is not marked (forwarded again while pending).
#[test]
fn sent_marks_are_capped() {
    let cids: Vec<[u8; 16]> = (0..5u8).map(|i| [i + 10; 16]).collect();
    let pending = pending_with(&cids);
    let mut memo = ForwardedResponses::with_cap(TS, 3);
    let (out, _) = poll_and_send(
        &mut memo,
        &pending,
        cids.iter().map(|c| honest(*c)).collect(),
        T0,
    );
    assert_eq!(out.len(), 5);
    assert_eq!(memo.len(), 3);
    assert_eq!(memo.refused(), 2);
}
