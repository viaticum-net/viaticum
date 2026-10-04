// Postman handler tests on real redb.
//
// T-3 scenarios (spec A2 §2.4), adapted to the CROWN-1 C2 wire:
//   handle_mailbox_store_accepts_valid_entry
//   handle_mailbox_store_rejects_when_not_in_candidate_set
//   handle_mailbox_store_rejects_oversized_entry
//   handle_mailbox_fetch_returns_entries_for_correct_target
//   handle_mailbox_fetch_rejects_wrong_target
//   handle_mailbox_fetch_returns_only_non_expired_entries
//   handle_mailbox_fetch_incremental_since_stored_at
//
// CROWN-1 C2 postman rules (spec §7.5), intent mailbox-i10, i11, i20, i22, i23:
//   AC-7  store_self_pointer_without_target_sig_is_rejected
//         store_self_pointer_signed_by_other_key_is_rejected
//         store_self_pointer_sig_for_other_target_is_rejected
//   AC-8  signed_self_pointer_is_accepted_when_general_quota_is_full
//   AC-9  fetch_rendezvous_without_proof_returns_empty
//         fetch_rendezvous_proof_bound_to_other_device_returns_empty
//         fetch_rendezvous_with_valid_proof_returns_entries
//   AC-10 store_checks_candidate_set_against_entry_target
//   AC-20 proof_fetch_returns_only_self_pointers
//   §7.5 п.1 store_rejects_plaintext_self_pointer
//   AC-22′ store_rejects_self_pointer_more_than_a_day_ahead
//         store_rejects_already_expired_entry
//         store_accepts_old_unexpired_self_pointer
//
// CROWN-1 C3a pointer slots (V.5 п.3, mailbox-i40/i46/i50, AC-29):
//   store_superseded_pointer_is_rejected_with_superseded
//   store_newer_pointer_in_same_slot_replaces_it
//   store_same_pointer_again_is_acked_without_change

use ed25519_dalek::SigningKey;
use libp2p::PeerId;
use viaticum_core::db::Db;
use viaticum_core::db::testutil::test_db;
use viaticum_core::mailbox::SELF_POINTER_MAX_FUTURE_SKEW_SECS;
use viaticum_core::mailbox::class_config::{MAX_ENTRY_BYTES, MAX_MAILBOX_BYTES_PER_PEER};
use viaticum_core::mailbox::seal::{RendezvousKeys, SEALED_PAYLOAD_VERSION};
use viaticum_core::mailbox::{
    MailboxAddress, MailboxClass, MailboxEngine, MailboxEntry, MailboxRejectReason, sign_store,
};
use viaticum_core::messages::{
    MAILBOX_WIRE_VERSION, MailboxFetchRequest, MailboxStoreRequest, MailboxStoreResponse,
};
use viaticum_core::types::{DeviceId, IdentityPub};

use crate::daemon::mailbox::candidate::KademliaRoutingView;
use crate::daemon::mailbox::test_postman::view_with_closer_peers;

use super::{handle_mailbox_fetch, handle_mailbox_store};

// ============================================================
// Helpers
// ============================================================

/// Postman clock for every test (a fixed wall-clock second in 2027).
const NOW: u64 = 1_800_000_000;

fn make_target(seed: u8) -> MailboxAddress {
    MailboxAddress([seed; 32])
}

fn make_msg_id(seed: u8) -> [u8; 16] {
    [seed; 16]
}

fn make_entry(
    target: MailboxAddress,
    msg_id: [u8; 16],
    payload_size: usize,
    stored_at: u64,
    ttl_secs: u64,
) -> MailboxEntry {
    MailboxEntry {
        target,
        msg_id,
        class: MailboxClass::PosChallenge,
        payload_version: 1,
        payload: vec![0u8; payload_size],
        expires_at: stored_at + ttl_secs,
        stored_at,
        sender: None,
    }
}

/// A SelfPointer entry with the sealed payload version (the bytes are opaque to the
/// postman, so a fixed body stands in for a real envelope).
fn pointer_entry(target: MailboxAddress, msg_id: u8, stored_at: u64) -> MailboxEntry {
    MailboxEntry {
        class: MailboxClass::SelfPointer,
        payload_version: SEALED_PAYLOAD_VERSION,
        payload: b"pointer".to_vec(),
        ..make_entry(target, make_msg_id(msg_id), 0, stored_at, 3600)
    }
}

fn make_store_request(entry: MailboxEntry) -> MailboxStoreRequest {
    MailboxStoreRequest {
        v: MAILBOX_WIRE_VERSION,
        entry,
        target_sig: None,
    }
}

fn signed_store_request(key: &SigningKey, entry: MailboxEntry) -> MailboxStoreRequest {
    let sig = sign_store(key, &entry);
    MailboxStoreRequest {
        v: MAILBOX_WIRE_VERSION,
        entry,
        target_sig: Some(sig),
    }
}

fn make_fetch_request(target: MailboxAddress, since: Option<u64>) -> MailboxFetchRequest {
    MailboxFetchRequest {
        v: MAILBOX_WIRE_VERSION,
        target,
        since_stored_at: since,
        target_proof: None,
    }
}

/// A box key and its address (a master box in C2 terms: address = public key).
fn box_key(seed: u8) -> (SigningKey, MailboxAddress) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let addr = MailboxAddress(sk.verifying_key().to_bytes());
    (sk, addr)
}

/// A routing view where `my_peer_id` is the only peer → should_store = true.
fn routing_view_accepts(my_peer_id: PeerId) -> KademliaRoutingView {
    KademliaRoutingView::new(vec![my_peer_id])
}

/// Store through the real handler on a postman that is always a candidate.
fn store(db: &Db, req: MailboxStoreRequest, now: u64) -> MailboxStoreResponse {
    let me = PeerId::random();
    handle_mailbox_store(db, &routing_view_accepts(me), &me, req, now)
}

fn is_reject(resp: &MailboxStoreResponse, want: MailboxRejectReason) -> bool {
    matches!(resp, MailboxStoreResponse::Reject { reason, .. } if *reason == want)
}

fn stored(db: &Db, target: &MailboxAddress) -> Vec<MailboxEntry> {
    db.mailbox_list_for_target(target, 0).unwrap()
}

fn requester() -> (IdentityPub, DeviceId) {
    (IdentityPub([0x51; 32]), DeviceId([0x52; 32]))
}

// ============================================================
// T-3 scenarios
// ============================================================

#[test]
fn handle_mailbox_store_accepts_valid_entry() {
    let db = test_db();
    let target = make_target(1);
    let entry = make_entry(target, make_msg_id(1), 100, NOW, 3600);

    let resp = store(&db, make_store_request(entry.clone()), NOW);
    assert!(
        matches!(resp, MailboxStoreResponse::Ack { msg_id } if msg_id == entry.msg_id),
        "valid entry should be accepted with Ack, got {resp:?}"
    );
    let fetched = MailboxEngine::new(db).fetch(&target, NOW).unwrap();
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].msg_id, entry.msg_id);
}

/// Formerly flaky (Ack after 45 s under load): the old helper sampled random peers
/// and gave up after 200 000 tries, silently returning a view with < 1000 closer
/// peers whenever our own id happened to be close to the target (≈ 0.5 % of runs).
/// The postman check itself has no timeout path: `should_store` is a pure count.
/// The view is now built deterministically with exactly 1000 closer peers.
#[test]
fn handle_mailbox_store_rejects_when_not_in_candidate_set() {
    let db = test_db();
    let target = make_target(2);
    let entry = make_entry(target, make_msg_id(2), 100, NOW, 3600);
    let (me, view) = view_with_closer_peers(&target, 1000);

    let resp = handle_mailbox_store(&db, &view, &me, make_store_request(entry), NOW);
    assert!(
        is_reject(&resp, MailboxRejectReason::NotInCandidateSet),
        "should reject when not in candidate set, got {resp:?}"
    );
    assert!(stored(&db, &target).is_empty());
}

#[test]
fn handle_mailbox_store_rejects_oversized_entry() {
    let db = test_db();
    let target = make_target(3);
    let entry = make_entry(target, make_msg_id(3), MAX_ENTRY_BYTES + 1, NOW, 3600);
    let resp = store(&db, make_store_request(entry), NOW);
    assert!(
        is_reject(&resp, MailboxRejectReason::EntryTooLarge),
        "oversized entry should be rejected with EntryTooLarge, got {resp:?}"
    );
}

#[test]
fn handle_mailbox_fetch_returns_entries_for_correct_target() {
    let db = test_db();
    let master = IdentityPub([4; 32]);
    let target = MailboxAddress::for_master(&master);
    let entry = make_entry(target, make_msg_id(4), 50, NOW, 3600);
    MailboxEngine::new(db.clone()).store(&entry, NOW).unwrap();

    let resp = handle_mailbox_fetch(
        &db,
        make_fetch_request(target, None),
        master,
        DeviceId([9; 32]),
        NOW,
    );
    assert_eq!(resp.v, MAILBOX_WIRE_VERSION);
    assert_eq!(
        resp.entries.len(),
        1,
        "should return 1 entry for correct target"
    );
    assert_eq!(resp.entries[0].msg_id, entry.msg_id);
    assert_eq!(resp.served_msg_ids, vec![entry.msg_id]);
}

#[test]
fn handle_mailbox_fetch_rejects_wrong_target() {
    let db = test_db();
    let target = make_target(5);
    let requester = IdentityPub([6; 32]); // different from target
    let entry = make_entry(target, make_msg_id(5), 50, NOW, 3600);
    MailboxEngine::new(db.clone()).store(&entry, NOW).unwrap();

    let resp = handle_mailbox_fetch(
        &db,
        make_fetch_request(target, None),
        requester,
        DeviceId([9; 32]),
        NOW,
    );
    assert!(
        resp.entries.is_empty(),
        "should return empty when requester != target (no error leak)"
    );
    assert!(resp.served_msg_ids.is_empty());
}

#[test]
fn handle_mailbox_fetch_returns_only_non_expired_entries() {
    let db = test_db();
    let master = IdentityPub([7; 32]);
    let target = MailboxAddress::for_master(&master);
    let engine = MailboxEngine::new(db.clone());
    let live_entry = make_entry(target, make_msg_id(10), 50, NOW, 3600);
    let expiring_entry = make_entry(target, make_msg_id(11), 50, NOW, 100);
    engine.store(&live_entry, NOW).unwrap();
    engine.store(&expiring_entry, NOW).unwrap();

    let resp = handle_mailbox_fetch(
        &db,
        make_fetch_request(target, None),
        master,
        DeviceId([9; 32]),
        NOW + 200,
    );
    assert_eq!(
        resp.entries.len(),
        1,
        "only non-expired entries should be returned"
    );
    assert_eq!(resp.entries[0].msg_id, live_entry.msg_id);
}

#[test]
fn handle_mailbox_fetch_incremental_since_stored_at() {
    let db = test_db();
    let master = IdentityPub([8; 32]);
    let target = MailboxAddress::for_master(&master);
    let engine = MailboxEngine::new(db.clone());
    let old_entry = make_entry(target, make_msg_id(20), 50, NOW, 3600);
    let new_entry = make_entry(target, make_msg_id(21), 50, NOW + 100, 3600);
    engine.store(&old_entry, NOW).unwrap();
    engine.store(&new_entry, NOW + 100).unwrap();

    let resp = handle_mailbox_fetch(
        &db,
        make_fetch_request(target, Some(NOW)),
        master,
        DeviceId([9; 32]),
        NOW + 200,
    );
    assert_eq!(
        resp.entries.len(),
        1,
        "incremental fetch returns only newer entries"
    );
    assert_eq!(resp.entries[0].msg_id, new_entry.msg_id);
    assert_eq!(resp.served_msg_ids, vec![new_entry.msg_id]);
}

// ============================================================
// AC-7 / AC-8: write authorization of the pointer box (mailbox-i10, i23)
// ============================================================

#[test]
fn store_self_pointer_without_target_sig_is_rejected() {
    let db = test_db();
    let (_sk, target) = box_key(10);
    let resp = store(&db, make_store_request(pointer_entry(target, 1, NOW)), NOW);
    assert!(
        is_reject(&resp, MailboxRejectReason::Unauthorized),
        "got {resp:?}"
    );
    assert!(stored(&db, &target).is_empty());
}

#[test]
fn store_self_pointer_signed_by_other_key_is_rejected() {
    let db = test_db();
    let (_sk, target) = box_key(11);
    let (other_sk, _) = box_key(12);
    let resp = store(
        &db,
        signed_store_request(&other_sk, pointer_entry(target, 1, NOW)),
        NOW,
    );
    assert!(
        is_reject(&resp, MailboxRejectReason::Unauthorized),
        "got {resp:?}"
    );
    assert!(stored(&db, &target).is_empty());
}

/// §7.5 п.1 (C3a): a plaintext SelfPointer (`payload_version` 1) is refused even with a
/// valid store signature by the box key, and nothing is stored. Directed classes are
/// not judged by this rule until C4.
#[test]
fn store_rejects_plaintext_self_pointer() {
    let db = test_db();
    let (sk, target) = box_key(17);
    let mut plain = pointer_entry(target, 1, NOW);
    plain.payload_version = 1;
    let resp = store(&db, signed_store_request(&sk, plain), NOW);
    assert!(
        is_reject(&resp, MailboxRejectReason::PlaintextPayload),
        "got {resp:?}"
    );
    assert!(stored(&db, &target).is_empty());

    let directed = make_entry(target, make_msg_id(2), 10, NOW, 3600);
    assert_eq!(directed.payload_version, 1);
    assert!(matches!(
        store(&db, make_store_request(directed), NOW),
        MailboxStoreResponse::Ack { .. }
    ));
}

/// A valid signature by the right key, but over an entry addressed to another box:
/// re-addressing a signed pointer (e.g. into a box the attacker picked) must fail.
#[test]
fn store_self_pointer_sig_for_other_target_is_rejected() {
    let db = test_db();
    let (sk, target) = box_key(13);
    let (_, other) = box_key(14);
    let sig = sign_store(&sk, &pointer_entry(target, 1, NOW));
    let moved = pointer_entry(other, 1, NOW);
    let req = MailboxStoreRequest {
        v: MAILBOX_WIRE_VERSION,
        entry: moved,
        target_sig: Some(sig),
    };
    let resp = store(&db, req, NOW);
    assert!(
        is_reject(&resp, MailboxRejectReason::Unauthorized),
        "got {resp:?}"
    );
    assert!(stored(&db, &other).is_empty());
    assert!(stored(&db, &target).is_empty());
}

/// Positive control for AC-7: the key holder's signed pointer is stored, in a
/// master box (C2) and in a seed-derived rendezvous box (C3 layout).
#[test]
fn store_self_pointer_with_valid_target_sig_is_accepted() {
    let db = test_db();
    let (sk, master_box) = box_key(15);
    let resp = store(
        &db,
        signed_store_request(&sk, pointer_entry(master_box, 1, NOW)),
        NOW,
    );
    assert!(
        matches!(resp, MailboxStoreResponse::Ack { .. }),
        "got {resp:?}"
    );
    assert_eq!(stored(&db, &master_box).len(), 1);

    let rv = RendezvousKeys::derive(&[7u8; 64]);
    let entry = pointer_entry(rv.address, 2, NOW);
    let req = MailboxStoreRequest {
        v: MAILBOX_WIRE_VERSION,
        target_sig: Some(rv.sign_store(&entry)),
        entry,
    };
    let resp = store(&db, req, NOW);
    assert!(
        matches!(resp, MailboxStoreResponse::Ack { .. }),
        "got {resp:?}"
    );
    assert_eq!(stored(&db, &rv.address).len(), 1);
}

/// Directed classes are never signed by the box key (the sender does not hold the
/// recipient's key): `target_sig` is not required for them.
#[test]
fn store_directed_entry_needs_no_target_sig() {
    let db = test_db();
    let (_sk, target) = box_key(16);
    for (i, class) in [
        MailboxClass::PosChallenge,
        MailboxClass::PosResponse,
        MailboxClass::DropNotice,
        MailboxClass::DeleteRequest,
        MailboxClass::Revocation,
    ]
    .into_iter()
    .enumerate()
    {
        let entry = MailboxEntry {
            class,
            ..make_entry(target, make_msg_id(i as u8), 10, NOW, 3600)
        };
        let resp = store(&db, make_store_request(entry), NOW);
        assert!(
            matches!(resp, MailboxStoreResponse::Ack { .. }),
            "{class:?}: {resp:?}"
        );
    }
    assert_eq!(stored(&db, &target).len(), 5);
}

#[test]
fn signed_self_pointer_is_accepted_when_general_quota_is_full() {
    let db = test_db();
    let (sk, target) = box_key(17);
    // Fill the general quota with directed junk through the real handler: big
    // entries first, then 1 KB ones, so less than ~1.2 KB of slack is left.
    let mut n: u32 = 0;
    for junk_len in [200_000usize, 1_000] {
        loop {
            let mut junk = make_entry(target, [0; 16], junk_len, NOW, 3600);
            junk.class = MailboxClass::DropNotice;
            junk.msg_id[..4].copy_from_slice(&n.to_be_bytes());
            n += 1;
            let resp = store(&db, make_store_request(junk), NOW);
            if is_reject(&resp, MailboxRejectReason::QuotaExceeded) {
                break;
            }
            assert!(
                matches!(resp, MailboxStoreResponse::Ack { .. }),
                "junk #{n}: {resp:?}"
            );
        }
    }
    let used = db.mailbox_bytes_for_target(&target).unwrap();
    assert!(
        used > MAX_MAILBOX_BYTES_PER_PEER - 1_300,
        "general quota must be full (used {used})"
    );

    // A 4 KB pointer could never fit into the remaining slack of the general quota.
    let mut pointer = pointer_entry(target, 1, NOW);
    pointer.payload = vec![0x5A; 4_096];
    let resp = store(&db, signed_store_request(&sk, pointer), NOW);
    assert!(
        matches!(resp, MailboxStoreResponse::Ack { .. }),
        "got {resp:?}"
    );
    assert!(
        stored(&db, &target)
            .iter()
            .any(|e| e.class == MailboxClass::SelfPointer),
        "the pointer is stored next to 100 MB of junk"
    );
}

// ============================================================
// AC-10: one address for check and storage (F3)
// ============================================================

/// The request carries a single address (`entry.target`): a postman outside that
/// address's neighbourhood refuses, even for a pointer with a valid signature.
#[test]
fn store_checks_candidate_set_against_entry_target() {
    let db = test_db();
    let (sk, target) = box_key(18);
    let (me, view) = view_with_closer_peers(&target, 1000);
    let req = signed_store_request(&sk, pointer_entry(target, 1, NOW));
    let resp = handle_mailbox_store(&db, &view, &me, req, NOW);
    assert!(
        is_reject(&resp, MailboxRejectReason::NotInCandidateSet),
        "got {resp:?}"
    );
    assert!(stored(&db, &target).is_empty());

    // Positive control: the same postman with a view in which it is a candidate
    // (sole known peer) accepts.
    let near = MailboxAddress([0x77; 32]);
    let near_view = KademliaRoutingView::new(vec![me]);
    let resp = handle_mailbox_store(
        &db,
        &near_view,
        &me,
        make_store_request(make_entry(near, make_msg_id(2), 10, NOW, 3600)),
        NOW,
    );
    assert!(
        matches!(resp, MailboxStoreResponse::Ack { .. }),
        "got {resp:?}"
    );
}

// ============================================================
// AC-22: postman clock (mailbox-i22)
// ============================================================

/// Expired past the transit window (mailbox-i61): the sender's clock is off.
#[test]
fn store_rejects_already_expired_entry() {
    let db = test_db();
    let target = make_target(19);
    for expires_at in [NOW - 60, NOW - 3600, 0] {
        let mut entry = make_entry(target, make_msg_id(1), 10, NOW - 7200, 0);
        entry.expires_at = expires_at;
        let resp = store(&db, make_store_request(entry), NOW);
        assert!(
            is_reject(&resp, MailboxRejectReason::ClockSkew),
            "expires_at {expires_at} vs now {NOW}: {resp:?}"
        );
    }
    assert!(stored(&db, &target).is_empty());
}

/// mailbox-i61: an entry whose TTL ran out on the way (within the last minute, sealed
/// in the postman's past) is refused as `Expired`, not as clock skew, and not stored.
#[test]
fn store_rejects_entry_expired_in_transit_as_expired() {
    let db = test_db();
    let target = make_target(21);
    for expires_at in [NOW, NOW - 1, NOW - 59] {
        let mut entry = make_entry(target, make_msg_id(1), 10, NOW - 7200, 0);
        entry.expires_at = expires_at;
        let resp = store(&db, make_store_request(entry), NOW);
        assert!(
            is_reject(&resp, MailboxRejectReason::Expired),
            "expires_at {expires_at} vs now {NOW}: {resp:?}"
        );
    }
    assert!(stored(&db, &target).is_empty());
}

/// mailbox-i42: a pointer more than a day ahead of the postman's clock would freeze
/// its slot; refused as ClockSkew. Up to a day ahead is accepted.
#[test]
fn store_rejects_self_pointer_more_than_a_day_ahead() {
    let db = test_db();
    let (sk, target) = box_key(20);
    let mut entry = pointer_entry(target, 1, NOW + SELF_POINTER_MAX_FUTURE_SKEW_SECS + 1);
    entry.expires_at = entry.stored_at + 3600;
    let resp = store(&db, signed_store_request(&sk, entry), NOW);
    assert!(
        is_reject(&resp, MailboxRejectReason::ClockSkew),
        "got {resp:?}"
    );
    assert!(stored(&db, &target).is_empty());
    let mut entry = pointer_entry(target, 2, NOW + SELF_POINTER_MAX_FUTURE_SKEW_SECS);
    entry.expires_at = entry.stored_at + 3600;
    let resp = store(&db, signed_store_request(&sk, entry), NOW);
    assert!(
        matches!(resp, MailboxStoreResponse::Ack { .. }),
        "got {resp:?}"
    );
}

/// mailbox-i42: no past bound — an old unexpired pointer is accepted.
#[test]
fn store_accepts_old_unexpired_self_pointer() {
    let db = test_db();
    let (sk, target) = box_key(24);
    let mut entry = pointer_entry(target, 1, NOW - 4 * 365 * 24 * 3600);
    entry.expires_at = NOW + 3600;
    let resp = store(&db, signed_store_request(&sk, entry), NOW);
    assert!(
        matches!(resp, MailboxStoreResponse::Ack { .. }),
        "got {resp:?}"
    );
    assert_eq!(stored(&db, &target).len(), 1);
}

// ============================================================
// AC-29: one pointer per slot (mailbox-i40/i46/i50)
// ============================================================

/// A signed pointer in slot `slot` whose payload differs per `stored_at`.
fn slot_pointer(
    sk: &SigningKey,
    target: MailboxAddress,
    slot: u8,
    stored_at: u64,
) -> MailboxStoreRequest {
    let mut entry = pointer_entry(target, slot, stored_at);
    entry.payload = format!("pointer@{stored_at}").into_bytes();
    signed_store_request(sk, entry)
}

#[test]
fn store_superseded_pointer_is_rejected_with_superseded() {
    let db = test_db();
    let (sk, target) = box_key(25);
    let newer = slot_pointer(&sk, target, 1, NOW);
    assert!(matches!(
        store(&db, newer.clone(), NOW),
        MailboxStoreResponse::Ack { .. }
    ));
    // Older in the same slot, and same time with another payload: both Superseded.
    let older = slot_pointer(&sk, target, 1, NOW - 10);
    let mut same_time_other = pointer_entry(target, 1, NOW);
    same_time_other.payload = b"another pointer".to_vec();
    for req in [older, signed_store_request(&sk, same_time_other)] {
        let resp = store(&db, req, NOW);
        assert!(
            is_reject(&resp, MailboxRejectReason::Superseded),
            "got {resp:?}"
        );
    }
    assert_eq!(stored(&db, &target), vec![newer.entry]);
}

#[test]
fn store_newer_pointer_in_same_slot_replaces_it() {
    let db = test_db();
    let (sk, target) = box_key(26);
    store(&db, slot_pointer(&sk, target, 1, NOW - 100), NOW);
    let newer = slot_pointer(&sk, target, 1, NOW);
    assert!(matches!(
        store(&db, newer.clone(), NOW),
        MailboxStoreResponse::Ack { .. }
    ));
    assert_eq!(
        stored(&db, &target),
        vec![newer.entry],
        "one entry per slot"
    );
}

/// A re-offer of the same envelope is an idempotent Ack (i47: the publisher re-sends
/// the same bytes until enough postmen hold it) and changes nothing.
#[test]
fn store_same_pointer_again_is_acked_without_change() {
    let db = test_db();
    let (sk, target) = box_key(27);
    let req = slot_pointer(&sk, target, 1, NOW);
    store(&db, req.clone(), NOW);
    let resp = store(&db, req.clone(), NOW + 50);
    assert!(
        matches!(resp, MailboxStoreResponse::Ack { .. }),
        "got {resp:?}"
    );
    assert_eq!(stored(&db, &target), vec![req.entry]);
}

/// Seal + postman together (V.16.3, mailbox-i50): the two places of one history are
/// two slots in the permanent rendezvous box; republishing a place replaces its own
/// entry and never touches the other place or another history's slot.
#[test]
fn sealed_pointer_places_hold_one_entry_each_at_the_postman() {
    use viaticum_core::mailbox::seal::{PointerPlace, seal_self_pointer};
    let db = test_db();
    let rv = RendezvousKeys::derive(&[9u8; 64]);
    let publish = |lineage: &[u8; 16], place, stored_at: u64, body: &[u8]| {
        let sealed =
            seal_self_pointer(&rv, lineage, place, body, stored_at + 3600, stored_at).unwrap();
        let req = MailboxStoreRequest {
            v: MAILBOX_WIRE_VERSION,
            entry: sealed.entry().clone(),
            target_sig: sealed.target_sig(),
        };
        store(&db, req, NOW)
    };
    let mine = [0x4Cu8; 16];
    let dormant = [0xD0u8; 16];
    for (lineage, place, at) in [
        (&dormant, PointerPlace::A, NOW - 100),
        (&mine, PointerPlace::A, NOW - 50),
        (&mine, PointerPlace::B, NOW - 40),
        (&mine, PointerPlace::A, NOW - 30),
        (&mine, PointerPlace::A, NOW),
    ] {
        let resp = publish(lineage, place, at, format!("{at}").as_bytes());
        assert!(matches!(resp, MailboxStoreResponse::Ack { .. }), "{resp:?}");
    }
    let held = stored(&db, &rv.address);
    let slots: std::collections::HashMap<[u8; 16], u64> =
        held.iter().map(|e| (e.msg_id, e.stored_at)).collect();
    assert_eq!(held.len(), 3, "dormant A + mine A + mine B");
    assert_eq!(slots[&rv.pointer_slot(&mine, PointerPlace::A)], NOW);
    assert_eq!(slots[&rv.pointer_slot(&mine, PointerPlace::B)], NOW - 40);
    assert_eq!(
        slots[&rv.pointer_slot(&dormant, PointerPlace::A)],
        NOW - 100
    );
}

// ============================================================
// AC-9 / AC-20: proof-gated reads (mailbox-i11, i20)
// ============================================================

/// A rendezvous box holding 2 pointers and 50 directed-junk entries.
fn rendezvous_box_with_junk(db: &Db) -> RendezvousKeys {
    let rv = RendezvousKeys::derive(&[3u8; 64]);
    for i in 0..2u8 {
        let entry = pointer_entry(rv.address, i, NOW + i as u64);
        let req = MailboxStoreRequest {
            v: MAILBOX_WIRE_VERSION,
            target_sig: Some(rv.sign_store(&entry)),
            entry,
        };
        assert!(matches!(
            store(db, req, NOW),
            MailboxStoreResponse::Ack { .. }
        ));
    }
    for i in 0..50u8 {
        let mut junk = make_entry(rv.address, make_msg_id(100 + i), 1000, NOW, 3600);
        junk.class = MailboxClass::DropNotice;
        assert!(matches!(
            store(db, make_store_request(junk), NOW),
            MailboxStoreResponse::Ack { .. }
        ));
    }
    assert_eq!(stored(db, &rv.address).len(), 52);
    rv
}

#[test]
fn fetch_rendezvous_without_proof_returns_empty() {
    let db = test_db();
    let rv = rendezvous_box_with_junk(&db);
    let (master, device) = requester();
    let resp = handle_mailbox_fetch(
        &db,
        make_fetch_request(rv.address, None),
        master,
        device,
        NOW,
    );
    assert!(resp.entries.is_empty());
    assert!(resp.served_msg_ids.is_empty());
}

/// A proof overheard from (or forwarded by) another device is useless: the postman
/// binds it to the device of the authenticated connection.
#[test]
fn fetch_rendezvous_proof_bound_to_other_device_returns_empty() {
    let db = test_db();
    let rv = rendezvous_box_with_junk(&db);
    let (master, device) = requester();
    let owners_device = DeviceId([0x99; 32]);
    let req = MailboxFetchRequest {
        target_proof: Some(rv.fetch_proof(&owners_device)),
        ..make_fetch_request(rv.address, None)
    };
    let resp = handle_mailbox_fetch(&db, req, master, device, NOW);
    assert!(resp.entries.is_empty());
}

#[test]
fn fetch_rendezvous_with_valid_proof_returns_entries() {
    let db = test_db();
    let rv = rendezvous_box_with_junk(&db);
    let (master, device) = requester();
    let req = MailboxFetchRequest {
        target_proof: Some(rv.fetch_proof(&device)),
        ..make_fetch_request(rv.address, None)
    };
    let resp = handle_mailbox_fetch(&db, req, master, device, NOW);
    assert_eq!(resp.entries.len(), 2);
    assert_eq!(resp.served_msg_ids.len(), 2);
}

#[test]
fn proof_fetch_returns_only_self_pointers() {
    let db = test_db();
    let rv = rendezvous_box_with_junk(&db);
    let (master, device) = requester();
    let req = MailboxFetchRequest {
        target_proof: Some(rv.fetch_proof(&device)),
        ..make_fetch_request(rv.address, None)
    };
    let resp = handle_mailbox_fetch(&db, req, master, device, NOW);
    assert!(
        !resp.entries.is_empty(),
        "positive control: pointers are served"
    );
    assert!(
        resp.entries
            .iter()
            .all(|e| e.class == MailboxClass::SelfPointer),
        "directed junk in the pointer box must not be served: {:?}",
        resp.entries.iter().map(|e| e.class).collect::<Vec<_>>()
    );
    assert_eq!(resp.entries.len(), 2);
}

/// The owner's own master box is still read by transport identity, and there it
/// gets every class (directed mail + the C2 pointer), no proof needed.
#[test]
fn own_master_box_fetch_returns_all_classes_without_proof() {
    let db = test_db();
    let (sk, target) = box_key(21);
    let master = IdentityPub(target.0);
    let resp = store(
        &db,
        signed_store_request(&sk, pointer_entry(target, 1, NOW)),
        NOW,
    );
    assert!(matches!(resp, MailboxStoreResponse::Ack { .. }));
    let resp = store(
        &db,
        make_store_request(make_entry(target, make_msg_id(2), 10, NOW, 3600)),
        NOW,
    );
    assert!(matches!(resp, MailboxStoreResponse::Ack { .. }));

    let resp = handle_mailbox_fetch(
        &db,
        make_fetch_request(target, None),
        master,
        DeviceId([1; 32]),
        NOW,
    );
    assert_eq!(resp.entries.len(), 2);
}

// ============================================================
// Review N5: wire version
// ============================================================

#[test]
fn store_rejects_unsupported_wire_version() {
    let db = test_db();
    let target = make_target(22);
    for v in [1u8, 3] {
        let req = MailboxStoreRequest {
            v,
            ..make_store_request(make_entry(target, make_msg_id(v), 10, NOW, 3600))
        };
        let resp = store(&db, req, NOW);
        assert!(
            is_reject(&resp, MailboxRejectReason::UnsupportedWireVersion),
            "v={v}: {resp:?}"
        );
    }
    assert!(stored(&db, &target).is_empty());
}

#[test]
fn fetch_with_unsupported_wire_version_returns_empty() {
    let db = test_db();
    let master = IdentityPub([23; 32]);
    let target = MailboxAddress::for_master(&master);
    let resp = store(
        &db,
        make_store_request(make_entry(target, make_msg_id(1), 10, NOW, 3600)),
        NOW,
    );
    assert!(matches!(resp, MailboxStoreResponse::Ack { .. }));
    let req = MailboxFetchRequest {
        v: 1,
        ..make_fetch_request(target, None)
    };
    let resp = handle_mailbox_fetch(&db, req, master, DeviceId([1; 32]), NOW);
    assert!(
        resp.entries.is_empty(),
        "positive control above: the box is not empty"
    );
}
