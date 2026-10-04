// pos-i15 / pos-i16 (C-SP К1): the PoS challenge goes to the holder's MASTER box, which every
// device of that master reads. Only the addressed device answers, and it signs with its device
// key. Order at the holder: signature -> freshness -> addressee -> holding -> disk.
//
// Every test drives the real `PosResponder` (real redb, temp holdings dir); the mailbox-facing
// tests go through `ProcessorPosHandler`, the path the poll uses.

use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use viaticum_core::cluster::{ClusterState, issue_device_certificate, master_identity};
use viaticum_core::db::Db;
use viaticum_core::messages::{
    Message, PosHashChallengeMsg, build_pos_hash_challenge, to_cbor, verify_pos_hash_response,
};
use viaticum_core::pos::compute_chain_hash;
use viaticum_core::types::{
    DeviceId, HoldingRecord, HoldingStatus, IdentityPub, SourceBlockId, Timestamp, hex_encode,
};

use super::super::ProcessorError;
use super::super::pos::PosResponder;
use super::{make_block_id, make_signing_key, pos_device_id, pos_own_master, pos_responder};
use crate::daemon::mailbox::poll::{PosChallengeAnswer, PosMailboxChallengeHandler};
use crate::daemon::processor::ProcessorPosHandler;

/// The sibling device the challenges of these tests are addressed to (H1 in the spec).
fn sibling_device() -> DeviceId {
    DeviceId(make_signing_key(0xA1).verifying_key().to_bytes())
}

/// A held block for `owner` at ESIs 0..3 with every symbol file on disk: the responder
/// (H2) has stale symbols at exactly the addressed device's ESIs (case c of the spec).
fn held_block(db: &Db, dir: &TempDir, owner: IdentityPub, block_id: SourceBlockId) {
    db.upsert_holding(&HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 3)],
        importance: 0.5,
        total_bytes: 3 * 16,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();
    let block_dir = dir.path().join(hex_encode(&block_id.0));
    std::fs::create_dir_all(&block_dir).unwrap();
    for esi in 0..3u32 {
        std::fs::write(block_dir.join(format!("{esi}.bin")), [esi as u8; 16]).unwrap();
    }
}

fn challenge_to(
    owner_key: &ed25519_dalek::SigningKey,
    block_id: SourceBlockId,
    device: DeviceId,
) -> PosHashChallengeMsg {
    build_pos_hash_challenge(
        [0x5C; 16],
        block_id,
        vec![(0, 3)],
        Timestamp::now(),
        device,
        owner_key,
    )
}

/// Owner key, its identity, a fresh db with `sibling_device()` known as a device of our
/// own master (device→master table, learned from its certificate).
fn setup() -> (Db, TempDir, ed25519_dalek::SigningKey, IdentityPub) {
    let db = Db::open_in_memory().unwrap();
    db.set_master_for_device(&sibling_device(), &pos_own_master())
        .unwrap();
    let dir = TempDir::new().unwrap();
    let owner_key = make_signing_key(0x0E);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    (db, dir, owner_key, owner)
}

// pos-i15, case c: the sibling holds stale symbols at all the addressed device's ESIs and
// still does not answer (no response, no Nack).
#[tokio::test]
async fn compute_response_is_not_mine_when_challenge_addressed_to_sibling_device() {
    let (db, dir, owner_key, owner) = setup();
    let block_id = make_block_id(0xB1);
    held_block(&db, &dir, owner, block_id);
    let responder = pos_responder(db, dir.path().to_path_buf());

    let result = responder
        .compute_response(owner, challenge_to(&owner_key, block_id, sibling_device()))
        .await;
    assert!(
        matches!(result, Err(ProcessorError::NotAddressedToThisDevice)),
        "a sibling's challenge must not be served, got {result:?}"
    );
}

// pos-i15 (M6): the addressee is checked before the holding — without a holding the sibling
// does not Nack either.
#[tokio::test]
async fn compute_response_is_not_mine_without_holding() {
    let (db, dir, owner_key, owner) = setup();
    let block_id = make_block_id(0xB2);
    let responder = pos_responder(db, dir.path().to_path_buf());

    let result = responder
        .compute_response(owner, challenge_to(&owner_key, block_id, sibling_device()))
        .await;
    assert!(
        matches!(result, Err(ProcessorError::NotAddressedToThisDevice)),
        "no holding: still not-mine, not a Nack; got {result:?}"
    );
}

// pos-i15: no disk read for a sibling's challenge. Every symbol path is a directory, so
// any read would fail with an I/O error instead of the not-mine verdict.
#[tokio::test]
async fn compute_response_does_not_read_disk_for_sibling_challenge() {
    let (db, dir, owner_key, owner) = setup();
    let block_id = make_block_id(0xB3);
    held_block(&db, &dir, owner, block_id);
    let block_dir = dir.path().join(hex_encode(&block_id.0));
    for esi in 0..3u32 {
        let path = block_dir.join(format!("{esi}.bin"));
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
    }
    let responder = pos_responder(db, dir.path().to_path_buf());

    // Control: the addressed device itself does read the disk (and trips on the trap).
    let own = responder
        .compute_response(owner, challenge_to(&owner_key, block_id, pos_device_id()))
        .await;
    assert!(
        matches!(own, Err(ProcessorError::Io(_))),
        "control: our own challenge reads the trapped files, got {own:?}"
    );

    let sibling = responder
        .compute_response(owner, challenge_to(&owner_key, block_id, sibling_device()))
        .await;
    assert!(
        matches!(sibling, Err(ProcessorError::NotAddressedToThisDevice)),
        "a sibling's challenge must be refused before any read, got {sibling:?}"
    );
}

// pos-i15 (M7): a device we do not know as ours is a plain no-answer (junk), not not-mine.
#[tokio::test]
async fn compute_response_is_no_answer_for_unknown_foreign_device() {
    let (db, dir, owner_key, owner) = setup();
    let block_id = make_block_id(0xB4);
    held_block(&db, &dir, owner, block_id);
    let stranger = DeviceId(make_signing_key(0xF0).verifying_key().to_bytes());
    let responder = pos_responder(db, dir.path().to_path_buf());

    let result = responder
        .compute_response(owner, challenge_to(&owner_key, block_id, stranger))
        .await;
    assert!(
        matches!(result, Err(ProcessorError::NotAddressedToThisMaster)),
        "an unknown device's challenge is not-this-master, got {result:?}"
    );

    let handler = ProcessorPosHandler::new(responder);
    let payload = to_cbor(&challenge_to(&owner_key, block_id, stranger)).unwrap();
    let answer = handler.handle_pos_challenge(owner, payload).await.unwrap();
    assert_eq!(answer, PosChallengeAnswer::NoAnswer);
}

// pos-i15: order — the signature comes before the addressee. A forged challenge naming a
// sibling is unauthenticated, never not-mine (a postman cannot fill the not-mine memory).
#[tokio::test]
async fn compute_response_checks_signature_before_addressee() {
    let (db, dir, _owner_key, owner) = setup();
    let block_id = make_block_id(0xB5);
    held_block(&db, &dir, owner, block_id);
    let responder = pos_responder(db, dir.path().to_path_buf());

    let forged = challenge_to(&make_signing_key(0x99), block_id, sibling_device());
    let result = responder.compute_response(owner, forged).await;
    assert!(
        matches!(result, Err(ProcessorError::UnauthenticatedChallenge)),
        "a forged sibling challenge must be unauthenticated, got {result:?}"
    );
}

// pos-i16: our own challenge is answered, signed by the device key: it verifies for our
// device and not for anything else.
#[tokio::test]
async fn compute_response_answers_own_device_signed_with_device_key() {
    let (db, dir, owner_key, owner) = setup();
    let block_id = make_block_id(0xB6);
    held_block(&db, &dir, owner, block_id);
    let responder = pos_responder(db, dir.path().to_path_buf());

    let challenge = challenge_to(&owner_key, block_id, pos_device_id());
    let reply = responder.compute_response(owner, challenge).await.unwrap();
    let Message::PosHashResponse(r) = reply else {
        panic!("expected a PosHashResponse");
    };
    assert_eq!(r.device_id, pos_device_id());
    verify_pos_hash_response(&r, &pos_device_id()).expect("verifies for our device");
    assert!(verify_pos_hash_response(&r, &sibling_device()).is_err());
    let expected = compute_chain_hash(
        &[0x5C; 16],
        &[
            (0, &[0u8; 16][..]),
            (1, &[1u8; 16][..]),
            (2, &[2u8; 16][..]),
        ],
    )
    .unwrap();
    assert_eq!(r.chain_hash, expected);
}

// pos-i15: through the mailbox handler a sibling's challenge is `NotMine` (remembered
// without re-check by the poll), not `NoAnswer`.
#[tokio::test]
async fn sibling_challenge_through_the_mailbox_handler_is_not_mine() {
    let (db, dir, owner_key, owner) = setup();
    let block_id = make_block_id(0xB7);
    held_block(&db, &dir, owner, block_id);
    let handler = ProcessorPosHandler::new(pos_responder(db, dir.path().to_path_buf()));

    let payload = to_cbor(&challenge_to(&owner_key, block_id, sibling_device())).unwrap();
    let answer = handler.handle_pos_challenge(owner, payload).await.unwrap();
    assert_eq!(answer, PosChallengeAnswer::NotMine);
}

// pos-i15: a sibling known only to the cluster state (not yet in the device→master table)
// is a sibling too.
#[tokio::test]
async fn compute_response_is_not_mine_for_sibling_known_only_to_cluster_state() {
    let db = Db::open_in_memory().unwrap();
    let dir = TempDir::new().unwrap();
    let master_key = make_signing_key(0x3A);
    let own_master = master_identity(&master_key);
    let device_key = make_signing_key(0x3B);
    let own_device = DeviceId(device_key.verifying_key().to_bytes());
    let sibling = DeviceId(make_signing_key(0x3C).verifying_key().to_bytes());
    let now = Timestamp::now();
    let mut cs = ClusterState::init(
        db.clone(),
        own_master,
        issue_device_certificate(&master_key, own_device, now),
        now,
        now,
    )
    .unwrap();
    cs.add_device(issue_device_certificate(&master_key, sibling, now), now)
        .unwrap();
    assert!(db.get_devices_for_master(&own_master).unwrap().is_empty());

    let owner_key = make_signing_key(0x0E);
    let owner = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = make_block_id(0xB8);
    held_block(&db, &dir, owner, block_id);
    let responder = PosResponder::new(
        db,
        dir.path().to_path_buf(),
        device_key,
        own_master,
        Some(Arc::new(Mutex::new(cs))),
    );

    let result = responder
        .compute_response(owner, challenge_to(&owner_key, block_id, sibling))
        .await;
    assert!(
        matches!(result, Err(ProcessorError::NotAddressedToThisDevice)),
        "a cluster-state sibling's challenge is not-mine, got {result:?}"
    );
}
