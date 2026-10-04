// pos-i16 (C-SP К1): the owner rules on a placement only by a response signed with the key of
// that placement's device. A sibling device of the holder's master (it reads the same master
// box) or anything signed with the master key is ignored: the pending stays, nothing is written
// to the placement, the weekly PoS counters, trust or the pair ledger, and the addressed
// device's own answer still resolves the challenge.

use ed25519_dalek::Signer;
use viaticum_core::messages::{
    PosHashResponseMsg, build_pos_hash_response, pos_hash_response_sig_input,
};
use viaticum_core::types::{DeviceId, IdentityPub, PlacementStatus, Timestamp, hex_encode};

use super::stale_verdict::logged;
use super::{PosDropFixture, pos_drop_fixture};

/// A sibling device of the fixture holder's master (registered under the same master).
fn sibling_of(f: &PosDropFixture, seed: u8) -> ed25519_dalek::SigningKey {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let master: IdentityPub = f.db.get_master_for_device(&f.holder).unwrap().unwrap();
    f.db.set_master_for_device(&DeviceId(key.verifying_key().to_bytes()), &master)
        .unwrap();
    key
}

/// The fixture holder's master key (`pos_drop_fixture` derives it from `seed + 2`).
fn master_key_of(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed.wrapping_add(2); 32])
}

async fn deliver(f: &PosDropFixture, response: PosHashResponseMsg) {
    f.scheduler
        .handle_pos_response_from_mailbox(response)
        .await
        .expect("a response is never a handler error");
}

/// Nothing ruled: the pending of `cid` is still there, the placement is as it was and
/// unverified, no weekly PoS row, no pair-ledger event, trust untouched.
async fn assert_nothing_ruled(f: &PosDropFixture, cid: [u8; 16], trust: (f64, f64), case: &str) {
    assert!(
        f.pending.lock().await.contains_challenge(&cid),
        "{case}: pending left intact"
    );
    let p = f.placement();
    assert_eq!(p.status, PlacementStatus::Alive, "{case}: no verdict");
    assert!(p.last_verified.is_none(), "{case}: no Pass");
    assert!(
        f.db.list_pos_weekly_for_peer(&f.holder).unwrap().is_empty(),
        "{case}: no weekly PoS row"
    );
    assert!(
        f.db.list_pending_drops().unwrap().is_empty(),
        "{case}: no pair-ledger event"
    );
    let peer = f.db.get_peer(&f.holder).unwrap().unwrap();
    assert_eq!(
        (peer.trust_p, peer.trust_i),
        trust,
        "{case}: trust untouched"
    );
}

fn trust_of(f: &PosDropFixture) -> (f64, f64) {
    let peer = f.db.get_peer(&f.holder).unwrap().unwrap();
    (peer.trust_p, peer.trust_i)
}

// M2: a response of a sibling device (its own key, its stale bytes → a wrong hash) is
// ignored with the "another device" WARN carrying the challenge_id.
#[tokio::test]
async fn mailbox_response_signed_by_sibling_device_is_ignored_and_pending_kept() {
    let f = pos_drop_fixture(0xC1, PlacementStatus::Alive, 0, 0);
    let trust = trust_of(&f);
    let (cid, _) = f.challenge(Timestamp::now(), 0xC1).await;
    let sibling = sibling_of(&f, 0xC9);
    let response = build_pos_hash_response(cid, f.block, [0xFF; 32], Timestamp::now(), &sibling);

    let ((), log) = logged(deliver(&f, response)).await;

    assert_nothing_ruled(&f, cid, trust, "sibling response").await;
    let line = log
        .lines()
        .find(|l| l.contains("from another device of the holder's master"))
        .unwrap_or_else(|| panic!("the WARN is printed:\n{log}"));
    assert!(
        line.contains(&hex_encode(&cid)),
        "with the challenge_id: {line}"
    );
}

// M2′: a response naming the holder's device but signed with the holder's MASTER key (the
// old scheme) is ignored; so is one built by the master key as its own "device".
#[tokio::test]
async fn mailbox_response_signed_by_master_key_is_ignored_and_pending_kept() {
    let f = pos_drop_fixture(0xC2, PlacementStatus::Alive, 0, 0);
    let trust = trust_of(&f);
    let (cid, _) = f.challenge(Timestamp::now(), 0xC2).await;
    let master = master_key_of(0xC2);
    let ts = Timestamp::now();
    let input = pos_hash_response_sig_input(&cid, &f.block, &f.holder, &[0xFF; 32], &ts);
    let as_holder = PosHashResponseMsg {
        v: 1,
        challenge_id: cid,
        source_block_id: f.block,
        chain_hash: [0xFF; 32],
        timestamp: ts,
        device_id: f.holder,
        sig: master.sign(&input).to_bytes(),
    };
    let as_itself = build_pos_hash_response(cid, f.block, [0xFF; 32], ts, &master);

    let ((), log) = logged(async {
        deliver(&f, as_holder).await;
        deliver(&f, as_itself).await;
    })
    .await;

    assert_nothing_ruled(&f, cid, trust, "master-signed responses").await;
    let line = log
        .lines()
        .find(|l| l.contains("signature verification failed"))
        .unwrap_or_else(|| panic!("the signature WARN is printed:\n{log}"));
    assert!(
        line.contains(&hex_encode(&cid)),
        "with the challenge_id: {line}"
    );
}

// The sibling's answer first (ignored), then the addressed device's own: Pass by the
// same challenge.
#[tokio::test]
async fn mailbox_response_from_sibling_then_placement_device_passes() {
    let f = pos_drop_fixture(0xC3, PlacementStatus::Alive, 0, 0);
    let trust = trust_of(&f);
    let (cid, expected) = f.challenge(Timestamp::now(), 0xC3).await;
    let sibling = sibling_of(&f, 0xCA);
    // Even the right hash from the sibling (case d, one key on two machines aside) is ignored.
    deliver(
        &f,
        build_pos_hash_response(cid, f.block, expected, Timestamp::now(), &sibling),
    )
    .await;
    assert_nothing_ruled(&f, cid, trust, "sibling first").await;

    deliver(
        &f,
        build_pos_hash_response(cid, f.block, expected, Timestamp::now(), &f.holder_key),
    )
    .await;

    assert!(f.pending.lock().await.is_empty(), "resolved by the holder");
    let p = f.placement();
    assert_eq!(p.status, PlacementStatus::Alive);
    assert!(p.last_verified.is_some(), "Pass");
    assert_eq!(f.db.list_pos_weekly_for_peer(&f.holder).unwrap().len(), 1);
}

#[tokio::test]
async fn mailbox_response_from_placement_device_passes() {
    let f = pos_drop_fixture(0xC4, PlacementStatus::Alive, 0, 0);
    let (cid, expected) = f.challenge(Timestamp::now(), 0xC4).await;

    deliver(
        &f,
        build_pos_hash_response(cid, f.block, expected, Timestamp::now(), &f.holder_key),
    )
    .await;

    assert!(f.pending.lock().await.is_empty());
    assert!(f.placement().last_verified.is_some(), "Pass");
}
