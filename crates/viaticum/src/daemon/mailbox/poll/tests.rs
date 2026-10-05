// Tests for the mailbox poll dispatch logic.
//
// Strategy: exercise the per-class dispatch_* fns directly with an in-memory DB and
// stub handlers / a recording MailboxNetworkSender (no live network needed). Verify
// routing and effects for each MailboxClass.

use std::sync::Arc;

use tokio::sync::mpsc;
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::messages::{
    PosHashResponseMsg, SymbolDropNoticeBatchMsg, build_signed_symbol_drop_notice, to_cbor,
};
use viaticum_core::types::{
    DeviceId, HoldingRecord, HoldingStatus, IdentityPub, PlacementStatus, SourceBlockId,
    SymbolPlacement, Timestamp,
};

use crate::daemon::processor::{
    DeleteMailboxHandler, ProcessorDeleteHandler, ProcessorDropHandler,
};
use crate::daemon::repair::RepairTrigger;

// ─── Test helpers ─────────────────────────────────────────────────────────────

fn make_identity(seed: u8) -> IdentityPub {
    IdentityPub([seed; 32])
}

fn make_entry(class: MailboxClass, target: IdentityPub, payload: Vec<u8>) -> MailboxEntry {
    let now = Timestamp::now().0;
    MailboxEntry {
        target: MailboxAddress::for_master(&target),
        msg_id: [1u8; 16],
        class,
        payload_version: 1,
        payload,
        expires_at: now + 3600,
        stored_at: now,
        sender: Some(make_identity(42)),
    }
}

/// Owner key of the test challenges.
fn owner_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
}

/// The holder DEVICE key of the poll tests (the device the test challenges address).
fn holder_device_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])
}

/// The device of `holder_device_key()`.
fn holder_device() -> DeviceId {
    DeviceId(holder_device_key().verifying_key().to_bytes())
}

/// A decodable PosHashChallengeMsg signed by `owner_signing_key` (issued now), addressed
/// to `holder_device()`.
fn signed_challenge() -> viaticum_core::messages::PosHashChallengeMsg {
    viaticum_core::messages::build_pos_hash_challenge(
        [0x5A; 16],
        SourceBlockId([8u8; 32]),
        vec![(0, 1)],
        Timestamp::now(),
        holder_device(),
        &owner_signing_key(),
    )
}

/// CBOR payload of `signed_challenge()`: the poll decodes a PosChallenge before its
/// memory step (pos-i5-a), so test challenges must decode.
fn signed_challenge_payload() -> Vec<u8> {
    to_cbor(&signed_challenge()).expect("encode challenge")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// A response to challenge `cid` (unsigned: the poll does not verify, the scheduler does).
fn response_to(cid: [u8; 16]) -> PosHashResponseMsg {
    PosHashResponseMsg {
        v: 1,
        challenge_id: cid,
        source_block_id: SourceBlockId([8u8; 32]),
        chain_hash: [99u8; 32],
        timestamp: Timestamp::now(),
        device_id: holder_device(),
        sig: [0u8; 64],
    }
}

/// The owner's pending index with one challenge per id in `cids`.
fn pending_for(cids: &[[u8; 16]]) -> crate::daemon::scheduler::PendingChallenges {
    let mut index = crate::daemon::scheduler::PendingIndex::default();
    for (i, cid) in cids.iter().enumerate() {
        let holder_id = DeviceId([i as u8 + 1; 32]);
        index.insert(
            (SourceBlockId([8u8; 32]), holder_id),
            crate::daemon::scheduler::PendingHashChallenge {
                source_block_id: SourceBlockId([8u8; 32]),
                holder_id,
                esi_ranges: vec![(0, 1)],
                expected_chain_hash: [0u8; 32],
                issued_at: Timestamp::now(),
                challenge_id: *cid,
            },
        );
    }
    Arc::new(tokio::sync::Mutex::new(index))
}

/// A PosResponse to a pending challenge is forwarded to pos_response_tx, decoded.
#[tokio::test]
async fn poll_dispatches_pos_response_to_channel() {
    let (tx, mut rx) = mpsc::channel::<PosHashResponseMsg>(16);
    let payload = to_cbor(&response_to([7u8; 16])).expect("encode");
    let entry = make_entry(MailboxClass::PosResponse, make_identity(1), payload);
    let mut pos = PosPollState::new(pending_for(&[[7u8; 16]]), 1);
    let mut counts = PollCounts::default();

    super::forward_pos_responses(&mut pos, &tx, vec![entry], Timestamp::now().0, &mut counts).await;

    let received = rx.try_recv().expect("message should be in channel");
    assert_eq!(received.challenge_id, [7u8; 16]);
    assert_eq!(received.chain_hash, [99u8; 32]);
    assert_eq!(counts.forwarded, 1);
}

/// PosResponse with invalid payload is dropped and counted (no panic).
#[tokio::test]
async fn poll_pos_response_bad_payload_does_not_panic() {
    let (tx, mut rx) = mpsc::channel::<PosHashResponseMsg>(16);
    let entry = make_entry(
        MailboxClass::PosResponse,
        make_identity(1),
        vec![0xFF, 0x00],
    );
    let mut pos = PosPollState::new(pending_for(&[[7u8; 16]]), 1);
    let mut counts = PollCounts::default();

    super::forward_pos_responses(&mut pos, &tx, vec![entry], Timestamp::now().0, &mut counts).await;

    // Nothing should be sent — invalid payload is dropped gracefully.
    assert!(rx.try_recv().is_err());
    assert_eq!(counts.undecodable, 1);
}

/// CROWN-1 РС3.1 / AC-16 (mailbox-i37): a SelfPointer polled from the master box —
/// own-target or foreign-target alike — is dropped: nothing is stored in the mailbox DB
/// and nothing else happens (the daemon never reads its pointer box; only DR does).
#[tokio::test]
async fn self_pointer_in_master_box_is_dropped() {
    let db = Db::open_in_memory().expect("db");
    let my_master = make_identity(0xAA);
    let foreign = make_identity(0xBB);
    for target in [my_master, foreign] {
        let entry = make_entry(MailboxClass::SelfPointer, target, vec![0x01, 0x02]);
        super::drop_self_pointer_from_master_box(&entry);
        let entries = db
            .mailbox_list_for_target(&MailboxAddress::for_master(&target), 0)
            .expect("list");
        assert!(entries.is_empty(), "a polled SelfPointer is never stored");
    }
}

/// N-5 / pos-i6: a full channel defers the response to the next poll — it is counted,
/// not marked as sent, and the next poll (with room in the channel) sends it.
#[tokio::test]
async fn full_channel_defers_response_to_next_poll() {
    let (tx, mut rx) = mpsc::channel::<PosHashResponseMsg>(1);
    let cid = [1u8; 16];
    // Fill the channel with something else.
    tx.try_send(response_to([0xEE; 16])).expect("first send");
    let entry = make_entry(
        MailboxClass::PosResponse,
        make_identity(1),
        to_cbor(&response_to(cid)).expect("encode"),
    );
    let mut pos = PosPollState::new(pending_for(&[cid]), 1);
    let now = Timestamp::now().0;

    let mut counts = PollCounts::default();
    super::forward_pos_responses(&mut pos, &tx, vec![entry.clone()], now, &mut counts).await;
    assert_eq!((counts.forwarded, counts.deferred_full), (0, 1));
    assert!(
        pos.forwarded.is_empty(),
        "a deferred response is not marked"
    );

    // The scheduler drains the channel; the next poll sends the deferred response.
    assert_eq!(rx.try_recv().expect("filler").challenge_id, [0xEE; 16]);
    pos.begin_poll(now + 4);
    let mut counts = PollCounts::default();
    super::forward_pos_responses(&mut pos, &tx, vec![entry], now + 4, &mut counts).await;
    assert_eq!((counts.forwarded, counts.deferred_full), (1, 0));
    assert_eq!(rx.try_recv().expect("deferred response").challenge_id, cid);
}

// ─── T-7: DropNotice dispatch tests ──────────────────────────────────────────

/// DropNotice entry with no sender is dropped gracefully (no panic).
#[tokio::test]
async fn poll_drop_notice_no_sender_does_not_panic() {
    use crate::daemon::repair::RepairTrigger;
    let db = Db::open_in_memory().expect("db");
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let handler: Arc<dyn super::DropNoticeHandler> =
        Arc::new(ProcessorDropHandler::new(db.clone(), repair_tx));

    let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let now = Timestamp::now();
    let batch = SymbolDropNoticeBatchMsg {
        v: 1,
        notices: vec![build_signed_symbol_drop_notice(
            SourceBlockId([0x01; 32]),
            vec![(0, 1)],
            Timestamp(now.0 + 86400 * 14),
            now,
            &sk,
        )],
    };
    let payload = to_cbor(&batch).expect("encode");
    let now_secs = now.0;

    // Entry with no sender — dispatch_drop_notice exits early before verifying.
    let my_master = make_identity(0xAA);
    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&my_master),
        msg_id: [2u8; 16],
        class: MailboxClass::DropNotice,
        payload_version: 1,
        payload,
        expires_at: now_secs + 86400 * 14,
        stored_at: now_secs,
        sender: None, // no sender
    };

    // Should not panic.
    super::dispatch_drop_notice(&handler, &my_master, entry);
}

/// DropNotice entry with invalid payload is dropped gracefully (no panic).
#[tokio::test]
async fn poll_drop_notice_bad_payload_does_not_panic() {
    use crate::daemon::repair::RepairTrigger;
    let db = Db::open_in_memory().expect("db");
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let handler: Arc<dyn super::DropNoticeHandler> =
        Arc::new(ProcessorDropHandler::new(db.clone(), repair_tx));

    let now_secs = Timestamp::now().0;
    let my_master = make_identity(0xAA);
    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&my_master),
        msg_id: [3u8; 16],
        class: MailboxClass::DropNotice,
        payload_version: 1,
        payload: vec![0xFF, 0x00, 0xDE, 0xAD], // invalid CBOR
        expires_at: now_secs + 86400 * 14,
        stored_at: now_secs,
        sender: Some(make_identity(0xBB)),
    };

    // Should not panic.
    super::dispatch_drop_notice(&handler, &my_master, entry);
}

/// Helper: create a deterministic Ed25519 signing key from a seed byte.
fn make_signing_key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

/// T-7: Feeding a SymbolDropNoticeBatchMsg through dispatch_drop_notice with a
/// prod ProcessorDropHandler marks each referenced placement Lost and updates
/// block cached fields (recomputes current_alive).
///
/// Setup: 2 holdings of holder H for blocks B1 and B2. Owner O has Alive placements
/// with holder H on both blocks. We feed a 2-notice batch with valid signatures →
/// both placements become Lost.
#[tokio::test]
async fn drop_notice_batch_dispatch_marks_each_placement_lost() {
    use viaticum_core::types::{PeerRecord, SourceBlockRecord, SourceBlockStatus, SourceBlockType};

    let db = Db::open_in_memory().expect("db");

    // Owner and holder identities. Use a real signing key for the holder so notices can be signed.
    let owner_master = IdentityPub([0xAA; 32]);
    let holder_signing_key = make_signing_key(0xBB);
    let holder_master = IdentityPub(holder_signing_key.verifying_key().to_bytes());
    let holder_device = DeviceId(holder_signing_key.verifying_key().to_bytes());

    // Register holder device → master mapping so get_devices_for_master finds it.
    let now = Timestamp::now();
    let peer = PeerRecord {
        device_id: holder_device,
        master_identity: holder_master,
        trust_p: 0.5,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.1,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer).expect("upsert holder peer");
    // DEVICE_TO_MASTER table is separate from the peers table; must be set explicitly
    // so that get_devices_for_master returns holder_device when called with holder_master.
    db.set_master_for_device(&holder_device, &holder_master)
        .expect("set master for device");

    let block_id_1 = SourceBlockId([0x01; 32]);
    let block_id_2 = SourceBlockId([0x02; 32]);

    // Insert source blocks so get_source_block succeeds.
    let block1 = SourceBlockRecord {
        seal_generation: 0,
        esi_high_water: 0,
        block_id: block_id_1,
        k: 6,
        t: 512,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: now,
        encrypted_size: None,
        n: Some(10),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 1.0,
        current_alive: 1,
        current_reliability: 0.9,
        target_reliability: 0.99,
    };
    let block2 = SourceBlockRecord {
        seal_generation: 0,
        esi_high_water: 0,
        block_id: block_id_2,
        ..block1.clone()
    };
    db.upsert_source_block(&block1).expect("insert block1");
    db.upsert_source_block(&block2).expect("insert block2");

    // Create Alive placements: holder_device holds both blocks.
    let placement1 = SymbolPlacement {
        source_block_id: block_id_1,
        holder_id: holder_device,
        file_id: viaticum_core::types::FileId(1),
        esi_ranges: vec![(0, 5)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: now,
        consecutive_misses: 0,
    };
    let placement2 = SymbolPlacement {
        source_block_id: block_id_2,
        ..placement1.clone()
    };
    db.upsert_placement(&placement1).expect("upsert placement1");
    db.upsert_placement(&placement2).expect("upsert placement2");

    // Build a 2-notice batch from holder H to owner O, signed with holder's key.
    let now = Timestamp::now();
    let batch = SymbolDropNoticeBatchMsg {
        v: 1,
        notices: vec![
            build_signed_symbol_drop_notice(
                block_id_1,
                vec![(0, 5)],
                Timestamp(now.0 + 86400 * 14),
                now,
                &holder_signing_key,
            ),
            build_signed_symbol_drop_notice(
                block_id_2,
                vec![(0, 5)],
                Timestamp(now.0 + 86400 * 14),
                now,
                &holder_signing_key,
            ),
        ],
    };
    let payload = to_cbor(&batch).expect("encode batch");

    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&owner_master),
        msg_id: [4u8; 16],
        class: MailboxClass::DropNotice,
        payload_version: 1,
        payload,
        expires_at: now.0 + 86400 * 14,
        stored_at: now.0,
        sender: Some(holder_master), // sender = holder's master_pub
    };

    use crate::daemon::repair::RepairTrigger;
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let handler: Arc<dyn super::DropNoticeHandler> =
        Arc::new(ProcessorDropHandler::new(db.clone(), repair_tx));

    super::dispatch_drop_notice(&handler, &owner_master, entry);

    // Both placements must now be Lost.
    let p1 = db
        .get_placement(&block_id_1, &holder_device)
        .expect("db ok")
        .expect("exists");
    let p2 = db
        .get_placement(&block_id_2, &holder_device)
        .expect("db ok")
        .expect("exists");

    assert_eq!(
        p1.status,
        PlacementStatus::Lost,
        "placement 1 must be Lost after DropNotice dispatch"
    );
    assert_eq!(
        p2.status,
        PlacementStatus::Lost,
        "placement 2 must be Lost after DropNotice dispatch"
    );

    // Block cached fields must have been recomputed (current_alive should now be 0,
    // since the only holder went Lost).
    let updated_block1 = db
        .get_source_block(&block_id_1)
        .expect("db ok")
        .expect("exists");
    let updated_block2 = db
        .get_source_block(&block_id_2)
        .expect("db ok")
        .expect("exists");

    assert_eq!(
        updated_block1.current_alive, 0,
        "block1 current_alive must be 0 after sole holder went Lost"
    );
    assert_eq!(
        updated_block2.current_alive, 0,
        "block2 current_alive must be 0 after sole holder went Lost"
    );
}

// ─── W-3: DropNotice security tests ──────────────────────────────────────────

/// W-3: A DropNotice with deadline ≤ now wakes the repair worker on the repair channel.
///
/// Setup: holder H has a placement on block B. Owner receives a DropNotice with
/// deadline = now (immediate drop). ProcessorDropHandler must:
///   1. Mark placement Lost (via SymbolDropHandler::apply).
///   2. Send RepairTrigger::Wake on repair_tx.
#[tokio::test]
async fn drop_notice_immediate_deadline_triggers_repair_now() {
    use viaticum_core::types::{PeerRecord, SourceBlockRecord, SourceBlockStatus, SourceBlockType};

    let db = Db::open_in_memory().expect("db");

    let holder_signing_key = make_signing_key(0xCC);
    let holder_master = IdentityPub(holder_signing_key.verifying_key().to_bytes());
    let holder_device = DeviceId(holder_signing_key.verifying_key().to_bytes());
    let owner_master = IdentityPub([0xAA; 32]);

    let now = Timestamp::now();

    // Register holder device → master mapping.
    let peer = PeerRecord {
        device_id: holder_device,
        master_identity: holder_master,
        trust_p: 0.5,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.1,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer).expect("upsert peer");
    db.set_master_for_device(&holder_device, &holder_master)
        .expect("set master");

    let block_id = SourceBlockId([0xCC; 32]);

    // Insert source block.
    let block = SourceBlockRecord {
        seal_generation: 0,
        esi_high_water: 0,
        block_id,
        k: 6,
        t: 512,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: now,
        encrypted_size: None,
        n: Some(10),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 1.0,
        current_alive: 1,
        current_reliability: 0.9,
        target_reliability: 0.99,
    };
    db.upsert_source_block(&block).expect("insert block");

    // Create Alive placement.
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id: holder_device,
        file_id: viaticum_core::types::FileId(1),
        esi_ranges: vec![(0, 5)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: now,
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).expect("upsert placement");

    // Build a signed immediate-drop notice (deadline = now).
    let notice = build_signed_symbol_drop_notice(
        block_id,
        vec![(0, 5)],
        now, // deadline = now → immediate drop
        now,
        &holder_signing_key,
    );
    let batch = SymbolDropNoticeBatchMsg {
        v: 1,
        notices: vec![notice],
    };
    let payload = to_cbor(&batch).expect("encode");

    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&owner_master),
        msg_id: [0xCCu8; 16],
        class: MailboxClass::DropNotice,
        payload_version: 1,
        payload,
        expires_at: now.0 + 3600,
        stored_at: now.0,
        sender: Some(holder_master),
    };

    let (repair_tx, mut repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let handler: Arc<dyn super::DropNoticeHandler> =
        Arc::new(ProcessorDropHandler::new(db.clone(), repair_tx));

    super::dispatch_drop_notice(&handler, &owner_master, entry);

    // Placement must be Lost.
    let p = db
        .get_placement(&block_id, &holder_device)
        .expect("db ok")
        .expect("exists");
    assert_eq!(
        p.status,
        PlacementStatus::Lost,
        "placement must be Lost after immediate drop"
    );

    // A repair wake must have been sent (PL-8c: unit Wake — no addressing; the
    // placement is already marked Lost in the DB, asserted above).
    let trigger = repair_rx
        .try_recv()
        .expect("repair wake must be in channel after immediate drop");
    assert!(
        matches!(trigger, RepairTrigger::Wake),
        "expected RepairTrigger::Wake, got {trigger:?}"
    );
}

/// W-3: A DropNotice whose signature does NOT verify against the claimed sender
/// is rejected: placement NOT marked Lost, NO RepairNow triggered.
///
/// Threat: a malicious postman inserts a DropNotice claiming to be from holder H,
/// but the sig was made with a different key (or is all-zero). The owner must reject it.
#[tokio::test]
async fn drop_notice_forged_signature_is_rejected() {
    use viaticum_core::types::{PeerRecord, SourceBlockRecord, SourceBlockStatus, SourceBlockType};

    let db = Db::open_in_memory().expect("db");

    // Legitimate holder key and a different attacker key.
    let holder_signing_key = make_signing_key(0xDD);
    let holder_master = IdentityPub(holder_signing_key.verifying_key().to_bytes());
    let holder_device = DeviceId(holder_signing_key.verifying_key().to_bytes());
    let attacker_key = make_signing_key(0xEE); // different key — forged sig
    let owner_master = IdentityPub([0xAA; 32]);

    let now = Timestamp::now();

    // Register holder device → master mapping.
    let peer = PeerRecord {
        device_id: holder_device,
        master_identity: holder_master,
        trust_p: 0.5,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.1,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer).expect("upsert peer");
    db.set_master_for_device(&holder_device, &holder_master)
        .expect("set master");

    let block_id = SourceBlockId([0xDD; 32]);

    // Insert source block.
    let block = SourceBlockRecord {
        seal_generation: 0,
        esi_high_water: 0,
        block_id,
        k: 6,
        t: 512,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: now,
        encrypted_size: None,
        n: Some(10),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 1.0,
        current_alive: 1,
        current_reliability: 0.9,
        target_reliability: 0.99,
    };
    db.upsert_source_block(&block).expect("insert block");

    // Create Alive placement for the legitimate holder.
    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id: holder_device,
        file_id: viaticum_core::types::FileId(2),
        esi_ranges: vec![(0, 5)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: now,
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).expect("upsert placement");

    // Build a DropNotice signed by the ATTACKER key, but claiming to come from the holder.
    // The sig will not verify against holder_master → must be rejected.
    let forged_notice = build_signed_symbol_drop_notice(
        block_id,
        vec![(0, 5)],
        now,
        now,
        &attacker_key, // attacker's key, not holder's
    );
    let batch = SymbolDropNoticeBatchMsg {
        v: 1,
        notices: vec![forged_notice],
    };
    let payload = to_cbor(&batch).expect("encode");

    // entry.sender = holder_master, but sig is from attacker_key → mismatch.
    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&owner_master),
        msg_id: [0xDDu8; 16],
        class: MailboxClass::DropNotice,
        payload_version: 1,
        payload,
        expires_at: now.0 + 3600,
        stored_at: now.0,
        sender: Some(holder_master), // claimed sender = legitimate holder
    };

    let (repair_tx, mut repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let handler: Arc<dyn super::DropNoticeHandler> =
        Arc::new(ProcessorDropHandler::new(db.clone(), repair_tx));

    super::dispatch_drop_notice(&handler, &owner_master, entry);

    // Placement must remain Alive — forged notice must be rejected.
    let p = db
        .get_placement(&block_id, &holder_device)
        .expect("db ok")
        .expect("exists");
    assert_eq!(
        p.status,
        PlacementStatus::Alive,
        "placement must remain Alive when DropNotice has forged signature"
    );

    // No RepairNow must have been triggered.
    assert!(
        repair_rx.try_recv().is_err(),
        "no RepairNow should be triggered for a forged DropNotice"
    );
}

// ─── T-13b-1: DeleteRequest dispatch tests ───────────────────────────────────

/// Helper: build a holding in the DB with the given status.
fn make_holding(db: &Db, block_id: SourceBlockId, owner: IdentityPub, status: HoldingStatus) {
    let holding = HoldingRecord {
        source_block_id: block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 5)],
        importance: 0.5,
        total_bytes: 512,
        status,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    };
    db.upsert_holding(&holding).expect("upsert holding");
}

/// Helper: build a DeleteRequest entry carrying a signed DeleteMsg.
fn make_delete_entry(
    target: IdentityPub,
    owner: IdentityPub,
    owner_key: &ed25519_dalek::SigningKey,
    block_id: SourceBlockId,
) -> MailboxEntry {
    use viaticum_core::mailbox::DeleteRequestPayload;
    let delete_msg =
        viaticum_core::messages::build_delete_msg(block_id, Timestamp::now(), owner_key);
    let payload_obj = DeleteRequestPayload::Delete(delete_msg);
    let payload = to_cbor(&payload_obj).expect("encode");
    let now = Timestamp::now().0;
    MailboxEntry {
        target: MailboxAddress::for_master(&target),
        msg_id: [0xDAu8; 16],
        class: MailboxClass::DeleteRequest,
        payload_version: 1,
        payload,
        expires_at: now + 86400 * 14,
        stored_at: now,
        sender: Some(owner),
    }
}

/// delete_request_dispatch_marks_holding_for_delete:
/// Poll dispatch of a signed DeleteMsg entry → holding goes Active→MarkedForDelete (real DB).
#[tokio::test]
async fn delete_request_dispatch_marks_holding_for_delete() {
    let db = Db::open_in_memory().expect("db");
    let owner_key = make_signing_key(0x11);
    let owner_master = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = SourceBlockId([0xAB; 32]);

    // Insert an Active holding for this block+owner.
    make_holding(&db, block_id, owner_master, HoldingStatus::Active);

    let entry = make_delete_entry(make_identity(0xFF), owner_master, &owner_key, block_id);

    let handler =
        Arc::new(ProcessorDeleteHandler::new(db.clone())) as Arc<dyn DeleteMailboxHandler>;

    super::dispatch_delete_request(&handler, &make_identity(0xFF), entry).await;

    let holding = db
        .get_holding(&block_id, &owner_master)
        .expect("db ok")
        .expect("exists");
    assert_eq!(
        holding.status,
        HoldingStatus::MarkedForDelete,
        "delete_request_dispatch_marks_holding_for_delete: holding must be MarkedForDelete"
    );
    assert!(
        holding.delete_requested_at.is_some(),
        "delete_request_dispatch_marks_holding_for_delete: delete_requested_at must be set"
    );
}

/// delete_request_forged_signature_rejected:
/// Entry whose DeleteMsg sig doesn't verify against entry.sender → holding NOT marked.
#[tokio::test]
async fn delete_request_forged_signature_rejected() {
    use viaticum_core::mailbox::DeleteRequestPayload;
    use viaticum_core::types::HoldingStatus;

    let db = Db::open_in_memory().expect("db");
    let real_owner_key = make_signing_key(0x22);
    let real_owner = IdentityPub(real_owner_key.verifying_key().to_bytes());
    let attacker_key = make_signing_key(0x33); // different key — forged sig
    let block_id = SourceBlockId([0xBC; 32]);

    // Insert an Active holding for the real owner.
    make_holding(&db, block_id, real_owner, HoldingStatus::Active);

    // Build a DeleteMsg signed by attacker key, but claimed to be from real_owner.
    let forged_delete =
        viaticum_core::messages::build_delete_msg(block_id, Timestamp::now(), &attacker_key);
    let payload_obj = DeleteRequestPayload::Delete(forged_delete);
    let payload = to_cbor(&payload_obj).expect("encode");
    let now = Timestamp::now().0;
    // entry.sender = real_owner, but sig is from attacker_key → mismatch.
    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&make_identity(0xFF)),
        msg_id: [0xBCu8; 16],
        class: MailboxClass::DeleteRequest,
        payload_version: 1,
        payload,
        expires_at: now + 86400 * 14,
        stored_at: now,
        sender: Some(real_owner),
    };

    let handler =
        Arc::new(ProcessorDeleteHandler::new(db.clone())) as Arc<dyn DeleteMailboxHandler>;

    super::dispatch_delete_request(&handler, &make_identity(0xFF), entry).await;

    let holding = db
        .get_holding(&block_id, &real_owner)
        .expect("db ok")
        .expect("exists");
    assert_eq!(
        holding.status,
        HoldingStatus::Active,
        "delete_request_forged_signature_rejected: holding must remain Active"
    );
}

/// delete_request_stale_timestamp_still_honored (T-13 H1(b) regression):
/// A DeleteMsg older than MESSAGE_FRESHNESS_SECS must STILL be honored via the
/// mailbox dispatch path. DeleteRequest entries live in the mailbox for
/// DELETE_REQUEST_TTL (14d) and the design time-constant is one WEEK, so a holder
/// offline for hours/days is the normal cold-backup case. The previous 1h wall-clock
/// freshness gate (removed in H1) wrongly rejected these legitimately-delayed Deletes
/// as "replay" and the owner's erasure request was silently lost. Replay protection
/// is now the signature + the entry TTL + the Active→MarkedForDelete status-guard.
#[tokio::test]
async fn delete_request_stale_timestamp_still_honored() {
    use viaticum_core::constants::MESSAGE_FRESHNESS_SECS;
    use viaticum_core::mailbox::DeleteRequestPayload;
    use viaticum_core::types::HoldingStatus;

    let db = Db::open_in_memory().expect("db");
    let owner_key = make_signing_key(0x44);
    let owner_master = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = SourceBlockId([0xCD; 32]);

    // Insert an Active holding.
    make_holding(&db, block_id, owner_master, HoldingStatus::Active);

    // Build a DeleteMsg with a stale timestamp (way beyond the old 1h window) but
    // well within the 14d DELETE_REQUEST_TTL.
    let stale_timestamp = Timestamp(
        Timestamp::now()
            .0
            .saturating_sub(MESSAGE_FRESHNESS_SECS + 3600),
    );
    let stale_delete =
        viaticum_core::messages::build_delete_msg(block_id, stale_timestamp, &owner_key);
    let payload_obj = DeleteRequestPayload::Delete(stale_delete);
    let payload = to_cbor(&payload_obj).expect("encode");
    let now = Timestamp::now().0;
    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&make_identity(0xFF)),
        msg_id: [0xCDu8; 16],
        class: MailboxClass::DeleteRequest,
        payload_version: 1,
        payload,
        expires_at: now + 86400 * 14,
        stored_at: now,
        sender: Some(owner_master),
    };

    let handler =
        Arc::new(ProcessorDeleteHandler::new(db.clone())) as Arc<dyn DeleteMailboxHandler>;

    super::dispatch_delete_request(&handler, &make_identity(0xFF), entry).await;

    let holding = db
        .get_holding(&block_id, &owner_master)
        .expect("db ok")
        .expect("exists");
    assert_eq!(
        holding.status,
        HoldingStatus::MarkedForDelete,
        "delete_request_stale_timestamp_still_honored: stale-but-signed Delete must mark holding for deletion"
    );
    assert!(
        holding.delete_requested_at.is_some(),
        "delete_request_stale_timestamp_still_honored: delete_requested_at must be set"
    );
}

/// delete_request_no_sender_is_dropped_gracefully:
/// Entry with no sender field: dispatch must warn and return without panicking.
#[tokio::test]
async fn delete_request_no_sender_is_dropped_gracefully() {
    let db = Db::open_in_memory().expect("db");
    let owner_key = make_signing_key(0x55);
    let owner_master = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = SourceBlockId([0xDE; 32]);

    make_holding(&db, block_id, owner_master, HoldingStatus::Active);

    let now = Timestamp::now().0;
    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&make_identity(0xFF)),
        msg_id: [0xDEu8; 16],
        class: MailboxClass::DeleteRequest,
        payload_version: 1,
        payload: vec![0x01, 0x02], // junk payload — never reached anyway
        expires_at: now + 86400,
        stored_at: now,
        sender: None, // no sender
    };

    let handler =
        Arc::new(ProcessorDeleteHandler::new(db.clone())) as Arc<dyn DeleteMailboxHandler>;

    // Should not panic.
    super::dispatch_delete_request(&handler, &make_identity(0xFF), entry).await;

    // Holding should remain Active — early-exit path taken.
    let holding = db
        .get_holding(&block_id, &owner_master)
        .expect("db ok")
        .expect("exists");
    assert_eq!(holding.status, HoldingStatus::Active);
}

// ─── T-13b-2: Revocation dispatch tests ──────────────────────────────────────

use crate::daemon::processor::{ProcessorRevocationHandler, RevocationMailboxHandler};
use viaticum_core::cluster::{EpochCounter, issue_device_certificate, issue_revocation};
use viaticum_core::messages::RevocationBroadcast;
use viaticum_core::types::PeerRecord;

/// Build a valid RevocationBroadcast signed by `master_key` revoking `device_id`.
fn make_revocation_broadcast(
    master_key: &ed25519_dalek::SigningKey,
    device_id: viaticum_core::types::DeviceId,
) -> RevocationBroadcast {
    let now = Timestamp::now();
    let cert = issue_device_certificate(master_key, device_id, now);
    let revocation = issue_revocation(master_key, device_id, now, EpochCounter(1));
    RevocationBroadcast {
        revocation,
        device_cert: cert,
    }
}

/// Insert a PeerRecord + device→master mapping into DB.
fn register_peer(db: &Db, device_id: viaticum_core::types::DeviceId, master: IdentityPub) {
    let peer = PeerRecord {
        device_id,
        master_identity: master,
        trust_p: 0.5,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp::now(),
        last_seen: Timestamp::now(),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.1,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer).expect("upsert peer");
    db.set_master_for_device(&device_id, &master)
        .expect("set master");
}

/// revocation_dispatch_marks_device_revoked:
/// Poll dispatch of a signed Revocation entry → revoked device key in the relevant
/// PeerRecord.revoked_device_pub_keys (real DB), matching the old handler.
#[tokio::test]
async fn revocation_dispatch_marks_device_revoked() {
    let db = Db::open_in_memory().expect("db");

    // Build a revoking master + a device to revoke.
    let master_key = ed25519_dalek::SigningKey::from_bytes(&[0x10u8; 32]);
    let master_pub = IdentityPub(master_key.verifying_key().to_bytes());
    let device_id = viaticum_core::types::DeviceId([0x11u8; 32]);

    // Register the peer device in DB so the handler can find it.
    register_peer(&db, device_id, master_pub);

    let broadcast = make_revocation_broadcast(&master_key, device_id);
    let payload = to_cbor(&broadcast).expect("encode");
    let now = Timestamp::now().0;
    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&make_identity(0xFF)), // target = us (the receiving peer)
        msg_id: [0xE0u8; 16],
        class: MailboxClass::Revocation,
        payload_version: 1,
        payload,
        expires_at: now + 86400 * 30,
        stored_at: now,
        sender: Some(master_pub), // sender = revoking master
    };

    let handler =
        Arc::new(ProcessorRevocationHandler::new(db.clone())) as Arc<dyn RevocationMailboxHandler>;

    super::dispatch_revocation(&handler, &make_identity(0xFF), entry).await;

    // PeerRecord for device_id must now have the revoked pub key.
    let peer = db
        .get_peer(&device_id)
        .expect("db ok")
        .expect("peer exists");
    assert!(
        peer.revoked_device_pub_keys.contains(&device_id.0),
        "revocation_dispatch_marks_device_revoked: device pub key must be in revoked list"
    );
}

/// revocation_forged_signature_rejected:
/// Certs signed by the wrong key → verify_device_certificate fails → no revocation applied.
#[tokio::test]
async fn revocation_forged_signature_rejected() {
    let db = Db::open_in_memory().expect("db");

    let legitimate_key = ed25519_dalek::SigningKey::from_bytes(&[0x20u8; 32]);
    let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0x21u8; 32]);
    let legitimate_pub = IdentityPub(legitimate_key.verifying_key().to_bytes());
    let device_id = viaticum_core::types::DeviceId([0x22u8; 32]);

    register_peer(&db, device_id, legitimate_pub);

    // Build a broadcast signed by attacker_key but claimed to be from legitimate_pub.
    let broadcast = make_revocation_broadcast(&attacker_key, device_id);
    let payload = to_cbor(&broadcast).expect("encode");
    let now = Timestamp::now().0;
    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&make_identity(0xFF)),
        msg_id: [0xE1u8; 16],
        class: MailboxClass::Revocation,
        payload_version: 1,
        payload,
        expires_at: now + 86400 * 30,
        stored_at: now,
        sender: Some(legitimate_pub), // claimed from legitimate, but sig is from attacker
    };

    let handler =
        Arc::new(ProcessorRevocationHandler::new(db.clone())) as Arc<dyn RevocationMailboxHandler>;

    super::dispatch_revocation(&handler, &make_identity(0xFF), entry).await;

    // PeerRecord must have NO revoked keys — forged cert must be rejected.
    let peer = db
        .get_peer(&device_id)
        .expect("db ok")
        .expect("peer exists");
    assert!(
        peer.revoked_device_pub_keys.is_empty(),
        "revocation_forged_signature_rejected: no device key must be revoked for forged cert"
    );
}

/// revocation_unknown_master_ignored:
/// Revocation for a master with no known devices → silently ignored, no panic.
#[tokio::test]
async fn revocation_unknown_master_ignored() {
    let db = Db::open_in_memory().expect("db");

    let master_key = ed25519_dalek::SigningKey::from_bytes(&[0x30u8; 32]);
    let master_pub = IdentityPub(master_key.verifying_key().to_bytes());
    let device_id = viaticum_core::types::DeviceId([0x31u8; 32]);

    // Do NOT register any device for this master — unknown master scenario.

    let broadcast = make_revocation_broadcast(&master_key, device_id);
    let payload = to_cbor(&broadcast).expect("encode");
    let now = Timestamp::now().0;
    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&make_identity(0xFF)),
        msg_id: [0xE2u8; 16],
        class: MailboxClass::Revocation,
        payload_version: 1,
        payload,
        expires_at: now + 86400 * 30,
        stored_at: now,
        sender: Some(master_pub),
    };

    let handler =
        Arc::new(ProcessorRevocationHandler::new(db.clone())) as Arc<dyn RevocationMailboxHandler>;

    // Must not panic — unknown master is silently ignored.
    super::dispatch_revocation(&handler, &make_identity(0xFF), entry).await;

    // No peer record should have been created.
    assert!(
        db.get_peer(&device_id).expect("db ok").is_none(),
        "revocation_unknown_master_ignored: no PeerRecord should exist for unknown master"
    );
}

/// revocation_no_sender_is_dropped_gracefully:
/// Entry with no sender field: dispatch warns and returns without panic.
#[tokio::test]
async fn revocation_no_sender_is_dropped_gracefully() {
    let db = Db::open_in_memory().expect("db");
    let now = Timestamp::now().0;
    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&make_identity(0xFF)),
        msg_id: [0xE3u8; 16],
        class: MailboxClass::Revocation,
        payload_version: 1,
        payload: vec![0x01, 0x02],
        expires_at: now + 86400 * 30,
        stored_at: now,
        sender: None, // no sender
    };

    let handler =
        Arc::new(ProcessorRevocationHandler::new(db.clone())) as Arc<dyn RevocationMailboxHandler>;

    // Must not panic.
    super::dispatch_revocation(&handler, &make_identity(0xFF), entry).await;
}

// ─── CS-DEL-7 / SM-8: foreign-target poll-dispatch guards ─────────────────────
// A poll only ever returns OUR own mail, so any entry whose target != my_master_pub
// is a misrouted/hostile postman reply. The per-class dispatch arms drop it with a
// warn and apply no effect (defense-in-depth; effects are already sig+relationship
// gated, but the routing invariant is now enforced consistently with PosChallenge).

/// CS-DEL-7: a DeleteRequest addressed to a DIFFERENT master is dropped — the holding
/// is never marked for deletion even though the signature would verify.
#[tokio::test]
async fn delete_request_dispatch_drops_entry_not_addressed_to_us() {
    let db = Db::open_in_memory().expect("db");
    let owner_key = make_signing_key(0x66);
    let owner_master = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = SourceBlockId([0xEF; 32]);

    make_holding(&db, block_id, owner_master, HoldingStatus::Active);

    // Entry target is a foreign master (0xBB), but we are 0xAA.
    let foreign_target = make_identity(0xBB);
    let my_master = make_identity(0xAA);
    let entry = make_delete_entry(foreign_target, owner_master, &owner_key, block_id);

    let handler =
        Arc::new(ProcessorDeleteHandler::new(db.clone())) as Arc<dyn DeleteMailboxHandler>;

    super::dispatch_delete_request(&handler, &my_master, entry).await;

    // Holding must remain Active — the foreign-target entry was dropped before handling.
    let holding = db
        .get_holding(&block_id, &owner_master)
        .expect("db ok")
        .expect("exists");
    assert_eq!(
        holding.status,
        HoldingStatus::Active,
        "DeleteRequest not addressed to us must be dropped (CS-DEL-7)"
    );
}

/// CS-DEL-7: a Revocation addressed to a DIFFERENT master is dropped — no device key is
/// revoked even though the certs would verify.
#[tokio::test]
async fn revocation_dispatch_drops_entry_not_addressed_to_us() {
    let db = Db::open_in_memory().expect("db");

    let master_key = ed25519_dalek::SigningKey::from_bytes(&[0x40u8; 32]);
    let master_pub = IdentityPub(master_key.verifying_key().to_bytes());
    let device_id = viaticum_core::types::DeviceId([0x41u8; 32]);

    register_peer(&db, device_id, master_pub);

    let broadcast = make_revocation_broadcast(&master_key, device_id);
    let payload = to_cbor(&broadcast).expect("encode");
    let now = Timestamp::now().0;
    // Entry target is a foreign master (0xBB), but we are 0xAA.
    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&make_identity(0xBB)),
        msg_id: [0xE4u8; 16],
        class: MailboxClass::Revocation,
        payload_version: 1,
        payload,
        expires_at: now + 86400 * 30,
        stored_at: now,
        sender: Some(master_pub),
    };

    let handler =
        Arc::new(ProcessorRevocationHandler::new(db.clone())) as Arc<dyn RevocationMailboxHandler>;

    super::dispatch_revocation(&handler, &make_identity(0xAA), entry).await;

    // No device key must be revoked — the foreign-target entry was dropped.
    let peer = db
        .get_peer(&device_id)
        .expect("db ok")
        .expect("peer exists");
    assert!(
        peer.revoked_device_pub_keys.is_empty(),
        "Revocation not addressed to us must be dropped (CS-DEL-7)"
    );
}

/// CS-DEL-7: a DropNotice addressed to a DIFFERENT master is dropped — the placement is
/// never marked Lost even though the holder signature would verify.
#[tokio::test]
async fn drop_notice_dispatch_drops_entry_not_addressed_to_us() {
    use viaticum_core::types::{PeerRecord, SourceBlockRecord, SourceBlockStatus, SourceBlockType};

    let db = Db::open_in_memory().expect("db");

    let holder_signing_key = make_signing_key(0xF1);
    let holder_master = IdentityPub(holder_signing_key.verifying_key().to_bytes());
    let holder_device = DeviceId(holder_signing_key.verifying_key().to_bytes());
    let owner_master = make_identity(0xAA);

    let now = Timestamp::now();
    let peer = PeerRecord {
        device_id: holder_device,
        master_identity: holder_master,
        trust_p: 0.5,
        trust_i: 0.0,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: now,
        last_seen: now,
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.1,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer).expect("upsert peer");
    db.set_master_for_device(&holder_device, &holder_master)
        .expect("set master");

    let block_id = SourceBlockId([0xF1; 32]);
    let block = SourceBlockRecord {
        seal_generation: 0,
        esi_high_water: 0,
        block_id,
        k: 6,
        t: 512,
        block_type: SourceBlockType::Single,
        status: SourceBlockStatus::Active,
        created_at: now,
        encrypted_size: None,
        n: Some(10),
        overhead: Some(1.5),
        drop_notice_sent_at: None,
        importance: 1.0,
        current_alive: 1,
        current_reliability: 0.9,
        target_reliability: 0.99,
    };
    db.upsert_source_block(&block).expect("insert block");

    let placement = SymbolPlacement {
        source_block_id: block_id,
        holder_id: holder_device,
        file_id: viaticum_core::types::FileId(1),
        esi_ranges: vec![(0, 5)],
        binding_seed: [0u8; 32],
        status: PlacementStatus::Alive,
        last_verified: None,
        placed_at: now,
        consecutive_misses: 0,
    };
    db.upsert_placement(&placement).expect("upsert placement");

    let batch = SymbolDropNoticeBatchMsg {
        v: 1,
        notices: vec![build_signed_symbol_drop_notice(
            block_id,
            vec![(0, 5)],
            Timestamp(now.0 + 86400 * 14),
            now,
            &holder_signing_key,
        )],
    };
    let payload = to_cbor(&batch).expect("encode");

    // Entry target is the owner (0xAA), but we dispatch as a DIFFERENT master (0xBB).
    let entry = MailboxEntry {
        target: MailboxAddress::for_master(&owner_master),
        msg_id: [0xF1u8; 16],
        class: MailboxClass::DropNotice,
        payload_version: 1,
        payload,
        expires_at: now.0 + 86400 * 14,
        stored_at: now.0,
        sender: Some(holder_master),
    };

    let (repair_tx, mut repair_rx) = mpsc::channel::<RepairTrigger>(16);
    let handler: Arc<dyn super::DropNoticeHandler> =
        Arc::new(ProcessorDropHandler::new(db.clone(), repair_tx));

    super::dispatch_drop_notice(&handler, &make_identity(0xBB), entry);

    // Placement must remain Alive and no repair wake fired — entry dropped as misrouted.
    let p = db
        .get_placement(&block_id, &holder_device)
        .expect("db ok")
        .expect("exists");
    assert_eq!(
        p.status,
        PlacementStatus::Alive,
        "DropNotice not addressed to us must be dropped (CS-DEL-7)"
    );
    assert!(
        repair_rx.try_recv().is_err(),
        "no repair wake for a misrouted DropNotice (CS-DEL-7)"
    );
}

// ─── E1: poll cadence scales with time_scale ──────────────────────────────────
// run_mailbox_poll must divide MAILBOX_POLL_INTERVAL_SECS by time_scale, exactly
// like the scheduler scales every cadence (scheduler/mod.rs:162-168). Without this,
// accelerated demos/tests poll the mailbox once per real hour while challenges /
// deletes fire every few seconds, so no mailbox round-trip (PoS / Delete /
// DropNotice / SelfPointer) can complete under time acceleration. Production
// (time_scale=1) keeps the full hourly cadence.
#[test]
fn poll_interval_scales_with_time_scale() {
    use super::poll_interval_secs;
    use viaticum_core::constants::MAILBOX_POLL_INTERVAL_SECS;

    // Production: full hourly cadence, unchanged.
    assert_eq!(poll_interval_secs(1), MAILBOX_POLL_INTERVAL_SECS);
    // Moderate scale divides cleanly.
    assert_eq!(poll_interval_secs(60), MAILBOX_POLL_INTERVAL_SECS / 60);
    // High scale floors at 1s so the loop never busy-spins on a 0s interval.
    assert_eq!(poll_interval_secs(100_000), 1);
    assert_eq!(poll_interval_secs(MAILBOX_POLL_INTERVAL_SECS), 1);
    // Zero time_scale must not divide-by-zero; treated as 1 (production cadence).
    assert_eq!(poll_interval_secs(0), MAILBOX_POLL_INTERVAL_SECS);
}

// ─── A2: PosResponse entry TTL is scaled by time_scale ─────────────────────────
// dispatch_pos_challenge is the ONLY site that constructs a PosResponse MailboxEntry.
// Its TTL must be scaled by time_scale (scaled_ttl_secs), mirroring the scheduler's
// scaled pending-challenge timeout — under acceleration a late response must not
// outlive the timeout window. The implementing agent for A2 died mid-flight (its TDD
// RED observation was lost), and this publish site had NO test coverage (reviewer
// WARN-1), so this behavioral test pins the scaling. expires_at and stored_at are
// both derived from one `now_secs` inside dispatch, so their delta equals ttl_secs
// exactly (no clock tolerance needed).

use viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL;
use viaticum_core::mailbox::scaled_ttl_secs;
use viaticum_core::messages::{
    MailboxFetchRequest, MailboxFetchResponse, MailboxStoreRequest, MailboxStoreResponse,
};

use crate::daemon::mailbox::routing::{MailboxNetworkSender, MailboxRouter};
use crate::daemon::pos_memo::{AnsweredChallenges, PollCounts, PosPollState};

use super::PosChallengeAnswer;

/// Stub PosMailboxChallengeHandler: returns a canned response regardless of payload,
/// so dispatch_pos_challenge proceeds to build + publish the PosResponse entry.
struct StubChallengeHandler {
    response: PosHashResponseMsg,
}

#[async_trait::async_trait]
impl super::PosMailboxChallengeHandler for StubChallengeHandler {
    async fn handle_pos_challenge(
        &self,
        _owner_master_pub: IdentityPub,
        _payload: Vec<u8>,
    ) -> anyhow::Result<PosChallengeAnswer> {
        Ok(PosChallengeAnswer::Respond(self.response.clone()))
    }
}

/// Records every MailboxStoreRequest the router publishes, so the test can inspect
/// the published entry's TTL.
struct RecordingSender {
    stored: tokio::sync::Mutex<Vec<MailboxStoreRequest>>,
}

#[async_trait::async_trait]
impl MailboxNetworkSender for RecordingSender {
    async fn send_store(
        &self,
        _device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        let msg_id = req.entry.msg_id;
        self.stored.lock().await.push(req);
        Ok(MailboxStoreResponse::Ack { msg_id })
    }

    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        Ok(MailboxFetchResponse {
            v: 1,
            entries: vec![],
            served_msg_ids: vec![],
        })
    }
}

/// Real Ed25519 DeviceId so device_id_to_peer_id succeeds and the router has a
/// publish candidate.
fn gen_device_id() -> DeviceId {
    use libp2p::identity::Keypair;
    let kp = Keypair::generate_ed25519();
    DeviceId(kp.try_into_ed25519().unwrap().public().to_bytes())
}

#[tokio::test]
async fn pos_response_entry_ttl_is_scaled_by_time_scale() {
    let db = Db::open_in_memory().expect("db");

    // One valid peer so the router has at least one publish candidate.
    let peer = PeerRecord {
        device_id: gen_device_id(),
        master_identity: IdentityPub([0xAB; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.5,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer).expect("upsert peer");

    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = Arc::new(MailboxRouter::with_sender(
        Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>,
        db.clone(),
    ));

    let response = PosHashResponseMsg {
        v: 1,
        challenge_id: [7u8; 16],
        source_block_id: SourceBlockId([8u8; 32]),
        chain_hash: [9u8; 32],
        timestamp: Timestamp::now(),
        device_id: holder_device(),
        sig: [0u8; 64],
    };
    let handler: Arc<dyn super::PosMailboxChallengeHandler> =
        Arc::new(StubChallengeHandler { response });

    let owner_master = make_identity(0x42);
    let my_master = make_identity(0xAA);
    // Payload is opaque to the stub handler; entry.sender = the challenging owner.
    let base = make_entry(
        MailboxClass::PosChallenge,
        my_master,
        signed_challenge_payload(),
    );
    let entry = MailboxEntry {
        sender: Some(owner_master),
        ..base
    };

    let time_scale = 60;
    let mut memo = AnsweredChallenges::new(time_scale);
    let mut counts = PollCounts::default();
    super::dispatch_pos_challenge(
        &router,
        &handler,
        &mut memo,
        &mut counts,
        &my_master,
        entry,
        time_scale,
        Timestamp::now().0,
    )
    .await;

    let stored = sender.stored.lock().await;
    assert_eq!(stored.len(), 1, "exactly one PosResponse must be published");
    let published = &stored[0].entry;
    assert_eq!(
        published.class,
        MailboxClass::PosResponse,
        "published entry must be a PosResponse"
    );

    let ttl = published.expires_at - published.stored_at;
    assert_eq!(
        ttl,
        scaled_ttl_secs(POS_CHALLENGE_TTL.as_secs(), time_scale),
        "PosResponse TTL must be the challenge TTL scaled by time_scale"
    );
    assert!(
        ttl < POS_CHALLENGE_TTL.as_secs(),
        "scaled TTL must be strictly less than the full unscaled TTL"
    );
}

/// CS-ID-6 / SM-8: a PosChallenge whose `target` is NOT this node's master_pub is
/// dropped by `dispatch_pos_challenge` — no PosResponse is published. We only poll
/// our own mailbox, so a mis-targeted entry can only come from a buggy/hostile
/// postman; the routing guard rejects it before any effect.
#[tokio::test]
async fn pos_challenge_not_addressed_to_us_is_dropped() {
    let db = Db::open_in_memory().expect("db");
    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);

    let response = PosHashResponseMsg {
        v: 1,
        challenge_id: [7u8; 16],
        source_block_id: SourceBlockId([8u8; 32]),
        chain_hash: [9u8; 32],
        timestamp: Timestamp::now(),
        device_id: holder_device(),
        sig: [0u8; 64],
    };
    let handler: Arc<dyn super::PosMailboxChallengeHandler> =
        Arc::new(StubChallengeHandler { response });

    let owner_master = make_identity(0x42);
    let my_master = make_identity(0xAA);
    let someone_else = make_identity(0xBB);
    // Entry addressed to `someone_else`, not us. sender is a valid owner so the only
    // thing stopping a publish is the target guard.
    let base = make_entry(
        MailboxClass::PosChallenge,
        someone_else,
        signed_challenge_payload(),
    );
    let entry = MailboxEntry {
        sender: Some(owner_master),
        ..base
    };

    let mut memo = AnsweredChallenges::new(1);
    let mut counts = PollCounts::default();
    super::dispatch_pos_challenge(
        &router,
        &handler,
        &mut memo,
        &mut counts,
        &my_master,
        entry,
        1,
        Timestamp::now().0,
    )
    .await;

    assert!(
        memo.is_empty(),
        "a mis-targeted challenge is not remembered"
    );
    let stored = sender.stored.lock().await;
    assert!(
        stored.is_empty(),
        "a PosChallenge not addressed to this node must be dropped — no PosResponse published"
    );
}

/// P1-10: a `MailboxClass::Generic` entry has no handler by design — `dispatch_entry`
/// drops it with no effect (no panic, no publish, no channel send). This pins the
/// "loud no-op" guard so a future Generic producer cannot be silently dropped.
#[tokio::test]
async fn generic_entry_is_ignored_without_effect() {
    use std::sync::Arc as StdArc;

    let db = Db::open_in_memory().expect("db");
    let sender = StdArc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, StdArc::clone(&sender) as Arc<dyn MailboxNetworkSender>);

    let (pos_tx, mut pos_rx) = mpsc::channel::<PosHashResponseMsg>(8);
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let challenge_handler: Arc<dyn super::PosMailboxChallengeHandler> =
        Arc::new(StubChallengeHandler {
            response: PosHashResponseMsg {
                v: 1,
                challenge_id: [0u8; 16],
                source_block_id: SourceBlockId([0u8; 32]),
                chain_hash: [0u8; 32],
                timestamp: Timestamp::now(),
                device_id: holder_device(),
                sig: [0u8; 64],
            },
        });
    let drop_handler: Arc<dyn super::DropNoticeHandler> =
        Arc::new(ProcessorDropHandler::new(db.clone(), repair_tx));
    let delete_handler: Arc<dyn DeleteMailboxHandler> =
        Arc::new(ProcessorDeleteHandler::new(db.clone()));
    let revocation_handler: Arc<dyn crate::daemon::processor::RevocationMailboxHandler> = Arc::new(
        crate::daemon::processor::ProcessorRevocationHandler::new(db.clone()),
    );
    let my_master = make_identity(0xAA);

    let entry = make_entry(MailboxClass::Generic, my_master, vec![0xDE, 0xAD]);

    // Must not panic, must not publish, must not forward anything.
    let mut pos = PosPollState::new(pending_for(&[]), 1);
    let mut counts = PollCounts::default();
    super::dispatch_entry(
        &router,
        &pos_tx,
        &mut pos,
        &mut counts,
        &challenge_handler,
        &drop_handler,
        &delete_handler,
        &revocation_handler,
        &my_master,
        entry,
        1,
        Timestamp::now().0,
    )
    .await;
    assert_eq!(
        counts,
        PollCounts::default(),
        "a Generic entry counts nothing"
    );

    assert!(
        sender.stored.lock().await.is_empty(),
        "Generic entry must not publish anything"
    );
    assert!(
        pos_rx.try_recv().is_err(),
        "Generic entry must not forward to the PoS channel"
    );
}

// ─── A3: PosResponse delivery is reliable (deterministic msg_id + retry) ───────
//
// P1-4: a PosResponse must not be lost on a single 0-ack publish. The PoS challenge
// entry stays in the holder's mailbox until TTL, so dispatch_pos_challenge sees it on
// every poll; since pos-i5 it computes once and re-publishes the remembered entry (next
// poll after 0 acks, else once per quarter TTL) — that re-publish is the retry. M1:
// re-published responses must dedup, not pile up; the msg_id must therefore be
// deterministic — derived from (challenge_id ‖ chain_hash) so it is stable across
// re-computes (a restart) yet unpredictable to a postman that lacks the symbols
// (WARN-1), not a fresh random value each poll.

/// A sender that fails (network error → 0 acks) for the first N store attempts, then
/// records and Acks every store after that. Captures the entry of every attempt
/// (failed and succeeded) so the test can compare msg_ids across re-dispatch.
struct FlakyRecordingSender {
    fail_first: tokio::sync::Mutex<usize>,
    attempts: tokio::sync::Mutex<Vec<MailboxStoreRequest>>,
    acked: tokio::sync::Mutex<Vec<MailboxStoreRequest>>,
}

#[async_trait::async_trait]
impl MailboxNetworkSender for FlakyRecordingSender {
    async fn send_store(
        &self,
        _device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        self.attempts.lock().await.push(req.clone());
        let mut remaining = self.fail_first.lock().await;
        if *remaining > 0 {
            *remaining -= 1;
            anyhow::bail!("simulated postman unreachable");
        }
        let msg_id = req.entry.msg_id;
        self.acked.lock().await.push(req);
        Ok(MailboxStoreResponse::Ack { msg_id })
    }

    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        Ok(MailboxFetchResponse {
            v: 1,
            entries: vec![],
            served_msg_ids: vec![],
        })
    }
}

/// Build a router whose single publish candidate is a real Ed25519 peer, backed by
/// the given sender. Shared setup for the A3 retry/idempotency tests.
fn router_with_one_peer(db: &Db, sender: Arc<dyn MailboxNetworkSender>) -> Arc<MailboxRouter> {
    let peer = PeerRecord {
        device_id: gen_device_id(),
        master_identity: IdentityPub([0xAB; 32]),
        trust_p: 0.5,
        trust_i: 0.5,
        trust_s: 1.0,
        bytes_we_store_for_peer: 0,
        bytes_peer_stores_for_us: 0,
        first_seen: Timestamp(0),
        last_seen: Timestamp(0),
        revoked_device_pub_keys: vec![],
        addrs: vec![],
        x25519_pub: None,
        avail_ewma: 0.5,
        last_avail_sample: 0,
    };
    db.upsert_peer(&peer).expect("upsert peer");
    Arc::new(MailboxRouter::with_sender(sender, db.clone()))
}

/// A3 (M1 + WARN-1): the PosResponse msg_id is deterministic-but-UNPREDICTABLE —
/// derived from the chain_hash (which only a symbol-holder can compute), NOT the
/// plaintext challenge_id. It is STABLE across re-dispatch of the same challenge (so
/// postmen dedup re-published responses instead of piling up a row per poll — M1), yet
/// it is NOT the challenge_id, so a postman that has only seen the challenge cannot
/// predict the response key and pre-squat a forged response under it (WARN-1).
#[tokio::test]
async fn pos_response_msg_id_is_derived_from_chain_hash_and_stable_across_redispatch() {
    let db = Db::open_in_memory().expect("db");
    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);

    let challenge_id = [0x5Au8; 16];
    let response = PosHashResponseMsg {
        v: 1,
        challenge_id,
        source_block_id: SourceBlockId([8u8; 32]),
        chain_hash: [9u8; 32],
        timestamp: Timestamp::now(),
        device_id: holder_device(),
        sig: [0u8; 64],
    };
    let handler: Arc<dyn super::PosMailboxChallengeHandler> =
        Arc::new(StubChallengeHandler { response });

    let owner_master = make_identity(0x42);
    let my_master = make_identity(0xAA);
    let base = make_entry(
        MailboxClass::PosChallenge,
        my_master,
        signed_challenge_payload(),
    );
    let entry = MailboxEntry {
        sender: Some(owner_master),
        ..base
    };

    // Two polls of the SAME challenge entry a quarter TTL apart (the challenge is still
    // alive in our mailbox): computed once, published twice (the second from memory).
    // time_scale 900: the quarter TTL (168 s) falls inside the entry's hour of life.
    let (handler, calls) = CountingChallengeHandler::wrap(handler);
    let mut memo = AnsweredChallenges::new(900);
    let mut counts = PollCounts::default();
    let now = Timestamp::now().0;
    let retry = memo.retry_secs();
    for at in [now, now + retry] {
        super::dispatch_pos_challenge(
            &router,
            &handler,
            &mut memo,
            &mut counts,
            &my_master,
            entry.clone(),
            900,
            at,
        )
        .await;
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the challenge is computed once"
    );
    assert_eq!((counts.computed, counts.republished), (1, 1));

    let stored = sender.stored.lock().await;
    assert_eq!(stored.len(), 2, "a publish and a re-publish from memory");
    assert_eq!(
        stored[0].entry, stored[1].entry,
        "the re-publish is the same entry bytes"
    );
    let msg_id = stored[0].entry.msg_id;
    assert_eq!(
        msg_id, stored[1].entry.msg_id,
        "re-dispatching the same challenge must reuse the same msg_id (idempotent, dedupable — M1)"
    );
    assert_ne!(
        msg_id, challenge_id,
        "msg_id must NOT be the plaintext challenge_id — a postman that has seen the \
         challenge could otherwise predict the key and squat a forged response (WARN-1)"
    );
}

/// A3 (WARN-1): the PosResponse msg_id DEPENDS on the chain_hash — two responses to the
/// same challenge_id but with different chain_hashes get different msg_ids. A postman that
/// cannot compute the chain_hash (it lacks the symbols) therefore cannot predict the key.
#[tokio::test]
async fn pos_response_msg_id_depends_on_chain_hash() {
    let db = Db::open_in_memory().expect("db");
    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);
    let my_master = make_identity(0xAA);
    let owner_master = make_identity(0x42);

    let mk = |chain_hash: [u8; 32]| PosHashResponseMsg {
        v: 1,
        challenge_id: [0x5Au8; 16],
        source_block_id: SourceBlockId([8u8; 32]),
        chain_hash,
        timestamp: Timestamp::now(),
        device_id: holder_device(),
        sig: [0u8; 64],
    };
    let base = make_entry(
        MailboxClass::PosChallenge,
        my_master,
        signed_challenge_payload(),
    );
    let entry = MailboxEntry {
        sender: Some(owner_master),
        ..base
    };

    // A fresh memory per handler (as after a restart), so both compute.
    let now = Timestamp::now().0;
    for chain_hash in [[9u8; 32], [0xA5u8; 32]] {
        let h: Arc<dyn super::PosMailboxChallengeHandler> = Arc::new(StubChallengeHandler {
            response: mk(chain_hash),
        });
        let mut memo = AnsweredChallenges::new(1);
        let mut counts = PollCounts::default();
        super::dispatch_pos_challenge(
            &router,
            &h,
            &mut memo,
            &mut counts,
            &my_master,
            entry.clone(),
            1,
            now,
        )
        .await;
    }

    let stored = sender.stored.lock().await;
    assert_eq!(stored.len(), 2);
    assert_ne!(
        stored[0].entry.msg_id, stored[1].entry.msg_id,
        "different chain_hash must yield a different msg_id (a postman without the symbols \
         cannot compute chain_hash, so cannot predict the response key)"
    );
}

/// A3 (P1-4): a single 0-ack publish does NOT lose the response. The first dispatch
/// gets 0 acks (its only postman is unreachable); the next dispatch (the next poll's
/// re-run) delivers. The honest holder thus delivers with the SAME msg_id — no false
/// Timeout from a one-shot publish failure.
#[tokio::test]
async fn pos_response_zero_ack_is_recovered_by_redispatch() {
    let db = Db::open_in_memory().expect("db");
    let sender = Arc::new(FlakyRecordingSender {
        fail_first: tokio::sync::Mutex::new(1), // first store attempt fails (0 acks)
        attempts: tokio::sync::Mutex::new(vec![]),
        acked: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);

    let challenge_id = [0x3Cu8; 16];
    let response = PosHashResponseMsg {
        v: 1,
        challenge_id,
        source_block_id: SourceBlockId([8u8; 32]),
        chain_hash: [9u8; 32],
        timestamp: Timestamp::now(),
        device_id: holder_device(),
        sig: [0u8; 64],
    };
    let handler: Arc<dyn super::PosMailboxChallengeHandler> =
        Arc::new(StubChallengeHandler { response });

    let owner_master = make_identity(0x42);
    let my_master = make_identity(0xAA);
    let base = make_entry(
        MailboxClass::PosChallenge,
        my_master,
        signed_challenge_payload(),
    );
    let entry = MailboxEntry {
        sender: Some(owner_master),
        ..base
    };

    let (handler, calls) = CountingChallengeHandler::wrap(handler);
    let mut memo = AnsweredChallenges::new(1);
    let mut counts = PollCounts::default();
    let now = Timestamp::now().0;

    // First poll: publish gets 0 acks (postman unreachable). No panic, response not lost.
    super::dispatch_pos_challenge(
        &router,
        &handler,
        &mut memo,
        &mut counts,
        &my_master,
        entry.clone(),
        1,
        now,
    )
    .await;
    assert!(
        sender.acked.lock().await.is_empty(),
        "first dispatch must get 0 acks (simulated unreachable postman)"
    );
    assert_eq!(counts.publish_zero_ack, 1);

    // Next poll (well within a quarter TTL): the 0-ack answer is re-published from
    // memory, this time acked — the honest holder delivers without a second compute.
    super::dispatch_pos_challenge(
        &router,
        &handler,
        &mut memo,
        &mut counts,
        &my_master,
        entry,
        1,
        now + 1,
    )
    .await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the re-publish comes from memory"
    );
    assert_eq!(counts.republished, 1);

    let acked = sender.acked.lock().await;
    assert_eq!(
        acked.len(),
        1,
        "re-dispatch must eventually deliver the PosResponse (no false Timeout)"
    );
    assert_ne!(
        acked[0].entry.msg_id, challenge_id,
        "the recovered delivery carries the derived (not plaintext-challenge_id) msg_id"
    );
}

// ─── pos-i5: the holder computes a challenge once ──────────────────────────────

use std::sync::atomic::{AtomicUsize, Ordering};

/// Wraps a challenge handler and counts its calls (a call = the symbols are read).
struct CountingChallengeHandler {
    inner: Arc<dyn super::PosMailboxChallengeHandler>,
    calls: Arc<AtomicUsize>,
}

impl CountingChallengeHandler {
    fn wrap(
        inner: Arc<dyn super::PosMailboxChallengeHandler>,
    ) -> (Arc<dyn super::PosMailboxChallengeHandler>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let h = CountingChallengeHandler {
            inner,
            calls: Arc::clone(&calls),
        };
        (Arc::new(h), calls)
    }
}

#[async_trait::async_trait]
impl super::PosMailboxChallengeHandler for CountingChallengeHandler {
    async fn handle_pos_challenge(
        &self,
        owner_master_pub: IdentityPub,
        payload: Vec<u8>,
    ) -> anyhow::Result<PosChallengeAnswer> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .handle_pos_challenge(owner_master_pub, payload)
            .await
    }
}

/// A handler that never answers (Nack, unauthenticated or oversized challenge).
struct NoAnswerHandler;

#[async_trait::async_trait]
impl super::PosMailboxChallengeHandler for NoAnswerHandler {
    async fn handle_pos_challenge(
        &self,
        _owner_master_pub: IdentityPub,
        _payload: Vec<u8>,
    ) -> anyhow::Result<PosChallengeAnswer> {
        Ok(PosChallengeAnswer::NoAnswer)
    }
}

fn stub_response(challenge_id: [u8; 16]) -> PosHashResponseMsg {
    PosHashResponseMsg {
        v: 1,
        challenge_id,
        source_block_id: SourceBlockId([8u8; 32]),
        chain_hash: [9u8; 32],
        timestamp: Timestamp::now(),
        device_id: holder_device(),
        sig: [0u8; 64],
    }
}

/// A PosChallenge entry to `my_master` from `owner`.
fn challenge_entry(my_master: IdentityPub, owner: IdentityPub) -> MailboxEntry {
    MailboxEntry {
        sender: Some(owner),
        ..make_entry(
            MailboxClass::PosChallenge,
            my_master,
            signed_challenge_payload(),
        )
    }
}

/// pos-i5: polls inside a quarter TTL neither call the handler again nor publish.
#[tokio::test]
async fn second_poll_does_not_recompute_answered_challenge() {
    let db = Db::open_in_memory().expect("db");
    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);
    let (handler, calls) = CountingChallengeHandler::wrap(Arc::new(StubChallengeHandler {
        response: stub_response([0x11; 16]),
    }));
    let my_master = make_identity(0xAA);
    let entry = challenge_entry(my_master, make_identity(0x42));
    let mut memo = AnsweredChallenges::new(900);
    let mut counts = PollCounts::default();
    let now = Timestamp::now().0;

    for poll in 0..5u64 {
        super::dispatch_pos_challenge(
            &router,
            &handler,
            &mut memo,
            &mut counts,
            &my_master,
            entry.clone(),
            900,
            now + 4 * poll,
        )
        .await;
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1, "symbols are read once");
    assert_eq!(sender.stored.lock().await.len(), 1, "published once");
    assert_eq!((counts.computed, counts.skipped), (1, 4));
}

/// pos-i5 (trap W-1): a postman that lost the response after acking it gets the same
/// entry again a quarter TTL later, from memory — the symbols are not read again.
#[tokio::test]
async fn lost_response_is_republished_from_cache_after_quarter_ttl() {
    let db = Db::open_in_memory().expect("db");
    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);
    let (handler, calls) = CountingChallengeHandler::wrap(Arc::new(StubChallengeHandler {
        response: stub_response([0x22; 16]),
    }));
    let my_master = make_identity(0xAA);
    let entry = challenge_entry(my_master, make_identity(0x42));
    let mut memo = AnsweredChallenges::new(900);
    let mut counts = PollCounts::default();
    let now = Timestamp::now().0;

    super::dispatch_pos_challenge(
        &router,
        &handler,
        &mut memo,
        &mut counts,
        &my_master,
        entry.clone(),
        900,
        now,
    )
    .await;
    let retry = memo.retry_secs();
    // The postman acked, then lost the entry (wiped / reinstalled).
    let first = sender
        .stored
        .lock()
        .await
        .pop()
        .expect("first publish")
        .entry;

    super::dispatch_pos_challenge(
        &router,
        &handler,
        &mut memo,
        &mut counts,
        &my_master,
        entry.clone(),
        900,
        now + retry,
    )
    .await;
    // The re-publish is recorded: the very next poll does not publish again.
    super::dispatch_pos_challenge(
        &router,
        &handler,
        &mut memo,
        &mut counts,
        &my_master,
        entry,
        900,
        now + retry + 4,
    )
    .await;

    let stored = sender.stored.lock().await;
    assert_eq!(
        stored.len(),
        1,
        "the response reaches the postman again, once"
    );
    assert_eq!(
        stored[0].entry, first,
        "the same bytes under the same msg_id"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "no second compute");
    assert_eq!(counts.republished, 1);
    assert_eq!(counts.skipped, 1);
}

/// pos-i5: a challenge the handler gave no answer to is not asked again on every poll,
/// only once per quarter TTL.
#[tokio::test]
async fn no_answer_challenge_is_rechecked_once_per_quarter_ttl() {
    let db = Db::open_in_memory().expect("db");
    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);
    let (handler, calls) = CountingChallengeHandler::wrap(Arc::new(NoAnswerHandler));
    let my_master = make_identity(0xAA);
    let entry = challenge_entry(my_master, make_identity(0x42));
    let mut memo = AnsweredChallenges::new(900);
    let mut counts = PollCounts::default();
    let now = Timestamp::now().0;
    let retry = memo.retry_secs();

    for at in [now, now + 4, now + 8, now + retry] {
        super::dispatch_pos_challenge(
            &router,
            &handler,
            &mut memo,
            &mut counts,
            &my_master,
            entry.clone(),
            900,
            at,
        )
        .await;
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "first sight + one re-check"
    );
    assert_eq!((counts.no_answer, counts.skipped), (2, 2));
    assert!(sender.stored.lock().await.is_empty());
}

/// pos-i5 observable: `mailbox_poll: poll done` is printed on every poll, the empty
/// one included (at DEBUG; a poll with entries is INFO).
#[tokio::test]
async fn poll_done_line_is_printed_for_an_empty_poll() {
    use std::io::Write;
    use std::sync::Mutex as StdMutex;

    #[derive(Clone, Default)]
    struct LogBuf(Arc<StdMutex<Vec<u8>>>);
    impl Write for LogBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let db = Db::open_in_memory().expect("db");
    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);
    let (pos_tx, _pos_rx) = mpsc::channel::<PosHashResponseMsg>(8);
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let buf = LogBuf::default();
    let writer = buf.clone();
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    );
    let cancel = tokio_util::sync::CancellationToken::new();
    let fut = super::run_mailbox_poll(
        router,
        pos_tx,
        pending_for(&[]),
        Arc::new(NoAnswerHandler),
        Arc::new(ProcessorDropHandler::new(db.clone(), repair_tx)),
        Arc::new(ProcessorDeleteHandler::new(db.clone())),
        Arc::new(crate::daemon::processor::ProcessorRevocationHandler::new(
            db.clone(),
        )),
        make_identity(0xAA),
        1,
        cancel.clone(),
    );
    let task = tokio::spawn(tracing::instrument::WithSubscriber::with_subscriber(
        fut, dispatch,
    ));

    // The first tick polls at once; wait for its line (bounded).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let logs = loop {
        let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        if logs.contains("mailbox_poll: poll done") || std::time::Instant::now() > deadline {
            break logs;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    cancel.cancel();
    task.await.unwrap();

    let line = logs
        .lines()
        .find(|l| l.contains("mailbox_poll: poll done"))
        .unwrap_or_else(|| panic!("no poll done line for an empty poll; logs:\n{logs}"));
    assert!(line.contains("entries=0"), "{line}");
    assert!(line.contains("elapsed_ms="), "{line}");
    assert!(
        line.contains("DEBUG"),
        "an empty poll is a DEBUG line (N4): {line}"
    );
}

// ─── Fix round 1: the poll's own start forgets, junk and sender-less entries ─────

/// A postman that serves `entries` on the first fetch only, then an empty box.
struct OneShotFetchSender {
    entries: tokio::sync::Mutex<Option<Vec<MailboxEntry>>>,
    stored: tokio::sync::Mutex<Vec<MailboxStoreRequest>>,
}

#[async_trait::async_trait]
impl MailboxNetworkSender for OneShotFetchSender {
    async fn send_store(
        &self,
        _device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        let msg_id = req.entry.msg_id;
        self.stored.lock().await.push(req);
        Ok(MailboxStoreResponse::Ack { msg_id })
    }

    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        Ok(MailboxFetchResponse {
            v: 1,
            entries: self.entries.lock().await.take().unwrap_or_default(),
            served_msg_ids: vec![],
        })
    }
}

/// B1: a poll starts by forgetting what expired — the memory of a challenge is gone
/// one TTL after it was first seen, through the poll path itself.
#[tokio::test]
async fn poll_forgets_an_answered_challenge_one_ttl_later() {
    let db = Db::open_in_memory().expect("db");
    let my_master = make_identity(0xAA);
    let sender = Arc::new(OneShotFetchSender {
        entries: tokio::sync::Mutex::new(Some(vec![challenge_entry(
            my_master,
            make_identity(0x42),
        )])),
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);
    let (pos_tx, _pos_rx) = mpsc::channel::<PosHashResponseMsg>(8);
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let challenge_handler: Arc<dyn super::PosMailboxChallengeHandler> =
        Arc::new(StubChallengeHandler {
            response: stub_response([0x33; 16]),
        });
    let drop_handler: Arc<dyn super::DropNoticeHandler> =
        Arc::new(ProcessorDropHandler::new(db.clone(), repair_tx));
    let delete_handler: Arc<dyn DeleteMailboxHandler> =
        Arc::new(ProcessorDeleteHandler::new(db.clone()));
    let revocation_handler: Arc<dyn crate::daemon::processor::RevocationMailboxHandler> = Arc::new(
        crate::daemon::processor::ProcessorRevocationHandler::new(db.clone()),
    );
    let mut pos = PosPollState::new(pending_for(&[]), 900);
    let ttl = pos.answered.ttl_secs();
    let now = Timestamp::now().0;

    for (at, want) in [(now, 1usize), (now + 4, 1), (now + ttl, 0)] {
        let counts = super::poll_once(
            &router,
            &pos_tx,
            &mut pos,
            &challenge_handler,
            &drop_handler,
            &delete_handler,
            &revocation_handler,
            &my_master,
            900,
            at,
        )
        .await;
        assert_eq!(
            pos.answered.len(),
            want,
            "memo_answered at +{} s (counts {counts:?})",
            at - now
        );
    }
    assert_eq!(
        sender.stored.lock().await.len(),
        1,
        "computed and published once"
    );
}

/// B NOTE (3): a PosChallenge without a sender is dropped before the memory — nothing
/// is remembered (it cannot be answered, and it must not occupy the memory).
#[tokio::test]
async fn challenge_without_sender_is_not_remembered() {
    let db = Db::open_in_memory().expect("db");
    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);
    let (handler, calls) = CountingChallengeHandler::wrap(Arc::new(StubChallengeHandler {
        response: stub_response([0x44; 16]),
    }));
    let my_master = make_identity(0xAA);
    let entry = MailboxEntry {
        sender: None,
        ..make_entry(
            MailboxClass::PosChallenge,
            my_master,
            signed_challenge_payload(),
        )
    };
    let mut memo = AnsweredChallenges::new(900);
    let mut counts = PollCounts::default();
    super::dispatch_pos_challenge(
        &router,
        &handler,
        &mut memo,
        &mut counts,
        &my_master,
        entry,
        900,
        Timestamp::now().0,
    )
    .await;
    assert!(memo.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(counts, PollCounts::default());
    assert!(sender.stored.lock().await.is_empty());
}

/// B NOTE (4): a junk PosChallenge payload is a no-answer: the poll does not decode it,
/// so the handler is never called (no disk read), it is remembered and re-checked once per
/// quarter TTL, not an error on every poll.
#[tokio::test]
async fn junk_challenge_payload_is_remembered_as_no_answer() {
    let db = Db::open_in_memory().expect("db");
    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);
    let (handler, calls) = CountingChallengeHandler::wrap(Arc::new(StubChallengeHandler {
        response: stub_response([0x55; 16]),
    }));
    let my_master = make_identity(0xAA);
    let entry = MailboxEntry {
        sender: Some(make_identity(0x42)),
        ..make_entry(
            MailboxClass::PosChallenge,
            my_master,
            vec![0xFF, 0x00, 0x13],
        )
    };
    let mut memo = AnsweredChallenges::new(900);
    let mut counts = PollCounts::default();
    let now = Timestamp::now().0;
    for at in [now, now + 4] {
        super::dispatch_pos_challenge(
            &router,
            &handler,
            &mut memo,
            &mut counts,
            &my_master,
            entry.clone(),
            900,
            at,
        )
        .await;
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "junk never reaches the handler"
    );
    assert_eq!(counts.handler_error, 0, "junk is not a handler error");
    assert_eq!((counts.no_answer, counts.skipped), (1, 1));
    assert_eq!(memo.len(), 1);
    assert!(sender.stored.lock().await.is_empty());
}

// ─── Fix round 2: the memory key is the signed challenge, not its encoding ───────

/// Re-encode `c` through a generic CBOR value and let `f` edit it.
fn reencoded(
    c: &viaticum_core::messages::PosHashChallengeMsg,
    f: impl FnOnce(&mut ciborium::Value),
) -> Vec<u8> {
    let bytes = to_cbor(c).unwrap();
    let mut v: ciborium::Value = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    f(&mut v);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&v, &mut out).unwrap();
    out
}

/// pos-i5-a: a postman re-encodes one signed challenge five ways without breaking the
/// signature. The poll computes it once and remembers one entry.
#[tokio::test]
async fn reencoded_signed_challenge_is_computed_once() {
    use viaticum_core::messages::PosHashChallengeMsg;

    let db = Db::open_in_memory().expect("db");
    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);
    let (handler, calls) = CountingChallengeHandler::wrap(Arc::new(StubChallengeHandler {
        response: stub_response([0x5A; 16]),
    }));
    let my_master = make_identity(0xAA);
    let owner = IdentityPub(owner_signing_key().verifying_key().to_bytes());
    let c = signed_challenge();
    let honest = to_cbor(&c).unwrap();
    let mut with_tail = honest.clone();
    with_tail.extend_from_slice(&[0x00, 0x01]);
    let payloads = vec![
        honest,
        to_cbor(&PosHashChallengeMsg { v: 9, ..c.clone() }).unwrap(),
        reencoded(&c, |v| {
            if let ciborium::Value::Map(m) = v {
                m.push((
                    ciborium::Value::Text("zz".into()),
                    ciborium::Value::Integer(1.into()),
                ));
            }
        }),
        with_tail,
        reencoded(&c, |v| {
            if let ciborium::Value::Map(m) = v {
                m.reverse();
            }
        }),
    ];
    let mut memo = AnsweredChallenges::new(900);
    let mut counts = PollCounts::default();
    let now = Timestamp::now().0;
    for (i, payload) in payloads.into_iter().enumerate() {
        let entry = MailboxEntry {
            msg_id: [i as u8; 16],
            sender: Some(owner),
            ..make_entry(MailboxClass::PosChallenge, my_master, payload)
        };
        super::dispatch_pos_challenge(
            &router,
            &handler,
            &mut memo,
            &mut counts,
            &my_master,
            entry,
            900,
            now + i as u64,
        )
        .await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the symbols are read once");
    assert_eq!(memo.len(), 1, "one entry for one signed challenge");
    assert_eq!(counts.skipped, 4);
    assert_eq!(sender.stored.lock().await.len(), 1);
}

/// pos-i5-a: a forgery with the honest challenge_id and a junk signature arrives FIRST
/// (a no-answer through the production handler); the honest challenge is still computed
/// and answered on the next poll.
#[tokio::test]
async fn forgery_seen_first_does_not_block_the_honest_challenge() {
    use crate::daemon::processor::{PosResponder, ProcessorPosHandler};
    use viaticum_core::messages::PosHashChallengeMsg;
    use viaticum_core::types::hex_encode;

    let db = Db::open_in_memory().expect("db");
    let holdings = tempfile::TempDir::new().expect("tempdir");
    let owner = IdentityPub(owner_signing_key().verifying_key().to_bytes());
    let c = signed_challenge();
    db.upsert_holding(&HoldingRecord {
        source_block_id: c.source_block_id,
        owner_id: owner,
        esi_ranges: vec![(0, 1)],
        importance: 0.5,
        total_bytes: 8,
        status: HoldingStatus::Active,
        received_at: Timestamp::now(),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .expect("holding");
    let block_dir = holdings.path().join(hex_encode(&c.source_block_id.0));
    std::fs::create_dir_all(&block_dir).unwrap();
    std::fs::write(block_dir.join("0.bin"), b"symbol-0").unwrap();

    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);
    let handler: Arc<dyn super::PosMailboxChallengeHandler> =
        Arc::new(ProcessorPosHandler::new(PosResponder::new(
            db.clone(),
            holdings.path().to_path_buf(),
            holder_device_key(),
            make_identity(0xAA),
            None,
        )));
    let my_master = make_identity(0xAA);
    let entry_of = |payload: Vec<u8>| MailboxEntry {
        sender: Some(owner),
        ..make_entry(MailboxClass::PosChallenge, my_master, payload)
    };
    let forged = PosHashChallengeMsg {
        sig: [0x13; 64],
        ..c.clone()
    };
    let mut memo = AnsweredChallenges::new(900);
    let mut counts = PollCounts::default();
    let now = Timestamp::now().0;
    for (at, payload) in [
        (now, to_cbor(&forged).unwrap()),
        (now + 4, to_cbor(&c).unwrap()),
    ] {
        super::dispatch_pos_challenge(
            &router,
            &handler,
            &mut memo,
            &mut counts,
            &my_master,
            entry_of(payload),
            900,
            at,
        )
        .await;
    }
    assert_eq!((counts.no_answer, counts.computed), (1, 1));
    assert_eq!(memo.len(), 2);
    assert_eq!(
        sender.stored.lock().await.len(),
        1,
        "the honest challenge is answered"
    );
}

// ─── pos-i6: the owner forwards only pending responses, once ───────────────────

/// A postman that serves the same `entries` on every fetch (the responses live in the
/// owner's box until their TTL).
struct RepeatFetchSender {
    entries: Vec<MailboxEntry>,
}

#[async_trait::async_trait]
impl MailboxNetworkSender for RepeatFetchSender {
    async fn send_store(
        &self,
        _device: DeviceId,
        req: MailboxStoreRequest,
    ) -> anyhow::Result<MailboxStoreResponse> {
        Ok(MailboxStoreResponse::Ack {
            msg_id: req.entry.msg_id,
        })
    }

    async fn send_fetch(
        &self,
        _device: DeviceId,
        _req: MailboxFetchRequest,
    ) -> anyhow::Result<MailboxFetchResponse> {
        Ok(MailboxFetchResponse {
            v: 1,
            entries: self.entries.clone(),
            served_msg_ids: vec![],
        })
    }
}

/// pos-i6 (M0-b, M0-b′): three polls of a box holding a response to a pending challenge
/// and two responses to challenges not pending, the scheduler not reading the channel:
/// the pending one is in the channel once, the others never; nothing is WARNed about.
#[tokio::test]
async fn poll_forwards_only_pending_responses_once() {
    let db = Db::open_in_memory().expect("db");
    let my_master = make_identity(0xAA);
    let pending_cid = [1u8; 16];
    let entries: Vec<MailboxEntry> = [pending_cid, [2u8; 16], [3u8; 16]]
        .iter()
        .map(|cid| MailboxEntry {
            msg_id: *cid,
            ..make_entry(
                MailboxClass::PosResponse,
                my_master,
                to_cbor(&response_to(*cid)).expect("encode"),
            )
        })
        .collect();
    let router = router_with_one_peer(
        &db,
        Arc::new(RepeatFetchSender { entries }) as Arc<dyn MailboxNetworkSender>,
    );
    let (pos_tx, mut pos_rx) = mpsc::channel::<PosHashResponseMsg>(16);
    let (repair_tx, _repair_rx) = mpsc::channel::<RepairTrigger>(8);
    let challenge_handler: Arc<dyn super::PosMailboxChallengeHandler> = Arc::new(NoAnswerHandler);
    let drop_handler: Arc<dyn super::DropNoticeHandler> =
        Arc::new(ProcessorDropHandler::new(db.clone(), repair_tx));
    let delete_handler: Arc<dyn DeleteMailboxHandler> =
        Arc::new(ProcessorDeleteHandler::new(db.clone()));
    let revocation_handler: Arc<dyn crate::daemon::processor::RevocationMailboxHandler> = Arc::new(
        crate::daemon::processor::ProcessorRevocationHandler::new(db.clone()),
    );
    let mut pos = PosPollState::new(pending_for(&[pending_cid]), 900);
    let now = Timestamp::now().0;
    let mut total = PollCounts::default();

    for poll in 0..3u64 {
        let counts = super::poll_once(
            &router,
            &pos_tx,
            &mut pos,
            &challenge_handler,
            &drop_handler,
            &delete_handler,
            &revocation_handler,
            &my_master,
            900,
            now + 4 * poll,
        )
        .await;
        total.forwarded += counts.forwarded;
        total.not_pending += counts.not_pending;
        total.in_flight += counts.in_flight;
    }

    let mut in_channel = vec![];
    while let Ok(r) = pos_rx.try_recv() {
        in_channel.push(r.challenge_id);
    }
    assert_eq!(
        in_channel,
        vec![pending_cid],
        "one copy, only the pending one"
    );
    assert_eq!(
        (total.forwarded, total.not_pending, total.in_flight),
        (1, 6, 2)
    );
    assert_eq!(pos.forwarded.len(), 1);
}

/// pos-i6-b: the daemon's poll → scheduler channel takes a poll of 3000 responses to
/// pending challenges (the old channel of 256 deferred all but 256 of them to later
/// polls, and a response deferred past its TTL became a false timeout), the scheduler
/// not reading meanwhile: every one is forwarded once, none deferred.
#[tokio::test]
async fn production_channel_forwards_a_3000_response_poll_without_deferring() {
    const BURST: u16 = 3000;
    let cids: Vec<[u8; 16]> = (0..BURST)
        .map(|i| {
            let mut cid = [0u8; 16];
            cid[..2].copy_from_slice(&i.to_le_bytes());
            cid
        })
        .collect();
    let mut index = crate::daemon::scheduler::PendingIndex::default();
    for (i, cid) in cids.iter().enumerate() {
        let mut block = [0u8; 32];
        block[..2].copy_from_slice(&(i as u16).to_le_bytes());
        let holder_id = DeviceId([7u8; 32]);
        index.insert(
            (SourceBlockId(block), holder_id),
            crate::daemon::scheduler::PendingHashChallenge {
                source_block_id: SourceBlockId(block),
                holder_id,
                esi_ranges: vec![(0, 1)],
                expected_chain_hash: [0u8; 32],
                issued_at: Timestamp::now(),
                challenge_id: *cid,
            },
        );
    }
    let entries: Vec<MailboxEntry> = cids
        .iter()
        .map(|cid| MailboxEntry {
            msg_id: *cid,
            ..make_entry(
                MailboxClass::PosResponse,
                make_identity(1),
                to_cbor(&response_to(*cid)).expect("encode"),
            )
        })
        .collect();
    let (tx, mut rx) = super::pos_response_channel();
    let mut pos = PosPollState::new(Arc::new(tokio::sync::Mutex::new(index)), 1);
    let mut counts = PollCounts::default();

    super::forward_pos_responses(&mut pos, &tx, entries, Timestamp::now().0, &mut counts).await;

    assert_eq!(
        (counts.forwarded, counts.deferred_full),
        (u32::from(BURST), 0)
    );
    let mut received = std::collections::HashSet::new();
    while let Ok(r) = rx.try_recv() {
        assert!(received.insert(r.challenge_id), "one copy of each");
    }
    assert_eq!(received.len(), usize::from(BURST));
}

// ─── pos-i15 [cross:B]: a challenge addressed to a sibling device ─────────────

/// The real handler of a holder device that is NOT `holder_device()` but its sibling
/// (same master `my_master`, the sibling known through the device→master table).
fn sibling_responder_handler(
    db: &Db,
    holdings: &tempfile::TempDir,
    my_master: IdentityPub,
) -> Arc<dyn super::PosMailboxChallengeHandler> {
    use crate::daemon::processor::{PosResponder, ProcessorPosHandler};
    db.set_master_for_device(&holder_device(), &my_master)
        .expect("sibling mapping");
    Arc::new(ProcessorPosHandler::new(PosResponder::new(
        db.clone(),
        holdings.path().to_path_buf(),
        ed25519_dalek::SigningKey::from_bytes(&[0xB2u8; 32]),
        my_master,
        None,
    )))
}

/// pos-i15: the sibling publishes nothing for a challenge addressed to another device of
/// its master, and the poll counts it as not-mine (not a no-answer, not computed).
#[tokio::test]
async fn sibling_challenge_publishes_nothing_and_counts_not_mine() {
    let db = Db::open_in_memory().expect("db");
    let holdings = tempfile::TempDir::new().unwrap();
    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);
    let my_master = make_identity(0xAA);
    let handler = sibling_responder_handler(&db, &holdings, my_master);
    let owner = IdentityPub(owner_signing_key().verifying_key().to_bytes());
    let mut memo = AnsweredChallenges::new(900);
    let mut counts = PollCounts::default();

    super::dispatch_pos_challenge(
        &router,
        &handler,
        &mut memo,
        &mut counts,
        &my_master,
        challenge_entry(my_master, owner),
        900,
        Timestamp::now().0,
    )
    .await;

    assert_eq!(
        (counts.not_mine, counts.no_answer, counts.computed),
        (1, 0, 0)
    );
    assert!(
        sender.stored.lock().await.is_empty(),
        "nothing is published"
    );
    assert_eq!(memo.len(), 1, "remembered as not-mine");
}

/// pos-i15 (M5): across polls, one quarter TTL and more apart, the sibling's challenge
/// reaches the handler once: not-mine is not re-checked like a no-answer.
#[tokio::test]
async fn sibling_challenge_calls_handler_once_across_polls() {
    let db = Db::open_in_memory().expect("db");
    let holdings = tempfile::TempDir::new().unwrap();
    let sender = Arc::new(RecordingSender {
        stored: tokio::sync::Mutex::new(vec![]),
    });
    let router = router_with_one_peer(&db, Arc::clone(&sender) as Arc<dyn MailboxNetworkSender>);
    let my_master = make_identity(0xAA);
    let (handler, calls) =
        CountingChallengeHandler::wrap(sibling_responder_handler(&db, &holdings, my_master));
    let owner = IdentityPub(owner_signing_key().verifying_key().to_bytes());
    let entry = challenge_entry(my_master, owner);
    let mut memo = AnsweredChallenges::new(900);
    let mut counts = PollCounts::default();
    let now = Timestamp::now().0;
    let retry = memo.retry_secs();

    for at in [now, now + 4, now + retry, now + 2 * retry + 1] {
        super::dispatch_pos_challenge(
            &router,
            &handler,
            &mut memo,
            &mut counts,
            &my_master,
            entry.clone(),
            900,
            at,
        )
        .await;
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1, "one look, then remembered");
    assert_eq!((counts.not_mine, counts.skipped), (1, 3));
    assert!(sender.stored.lock().await.is_empty());
}

mod stream;
