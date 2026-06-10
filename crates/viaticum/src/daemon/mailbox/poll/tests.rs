// Tests for the mailbox poll dispatch logic.
//
// Strategy: test dispatch_entry directly using the MockPosMailboxChallengeHandler
// (no live network needed). Verify routing decisions for each MailboxClass.

use std::sync::Arc;

use tokio::sync::mpsc;
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxClass, MailboxEntry};
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
        target,
        msg_id: [1u8; 16],
        class,
        payload_version: 1,
        payload,
        expires_at: now + 3600,
        stored_at: now,
        sender: Some(make_identity(42)),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// PosResponse dispatch forwards the decoded message to pos_response_tx.
#[tokio::test]
async fn poll_dispatches_pos_response_to_channel() {
    let (tx, mut rx) = mpsc::channel::<PosHashResponseMsg>(16);
    let expected_response = PosHashResponseMsg {
        v: 1,
        challenge_id: [7u8; 16],
        chain_hash: [99u8; 32],
        timestamp: Timestamp::now(),
        device_id: None,
    };
    let payload = to_cbor(&expected_response).expect("encode");
    let entry = make_entry(MailboxClass::PosResponse, make_identity(1), payload);

    super::dispatch_pos_response(&tx, entry);

    let received = rx.try_recv().expect("message should be in channel");
    assert_eq!(received.challenge_id, [7u8; 16]);
    assert_eq!(received.chain_hash, [99u8; 32]);
}

/// PosResponse with invalid payload is silently dropped (no panic).
#[tokio::test]
async fn poll_pos_response_bad_payload_does_not_panic() {
    let (tx, mut rx) = mpsc::channel::<PosHashResponseMsg>(16);
    let entry = make_entry(
        MailboxClass::PosResponse,
        make_identity(1),
        vec![0xFF, 0x00],
    );

    super::dispatch_pos_response(&tx, entry);

    // Nothing should be sent — invalid payload is dropped gracefully.
    assert!(rx.try_recv().is_err());
}

/// SelfPointer with target == my_master_pub is NOT stored in the DB (W-2).
#[tokio::test]
async fn poll_self_pointer_own_not_stored_in_db() {
    use std::sync::{Arc, Mutex};
    use viaticum_core::system_state::SelfPointer;

    let db = Db::open_in_memory().expect("db");
    let my_master = make_identity(0xAA);
    let current_pointer: Arc<Mutex<Option<SelfPointer>>> = Arc::new(Mutex::new(None));

    // Build a trivial payload (not a real SelfPointer; verify_self_pointer will fail gracefully).
    let entry = make_entry(MailboxClass::SelfPointer, my_master, vec![0x01]);
    let now_secs = Timestamp::now().0;

    super::dispatch_self_pointer(&db, &my_master, &current_pointer, entry, now_secs);

    // Mailbox DB should have no entries for my_master.
    let entries = db
        .mailbox_list_for_target(&my_master, now_secs)
        .expect("list");
    assert!(
        entries.is_empty(),
        "own SelfPointer must NOT be stored in mailbox DB (W-2)"
    );
}

/// SelfPointer with target != my_master_pub IS stored in the DB (postman role).
#[tokio::test]
async fn poll_foreign_self_pointer_is_stored() {
    use std::sync::{Arc, Mutex};
    use viaticum_core::system_state::SelfPointer;

    let db = Db::open_in_memory().expect("db");
    let my_master = make_identity(0xAA);
    let foreign_target = make_identity(0xBB);
    let current_pointer: Arc<Mutex<Option<SelfPointer>>> = Arc::new(Mutex::new(None));

    let entry = make_entry(MailboxClass::SelfPointer, foreign_target, vec![0x01, 0x02]);
    let now_secs = Timestamp::now().0;

    super::dispatch_self_pointer(&db, &my_master, &current_pointer, entry, now_secs);

    // Mailbox DB should have the entry stored for foreign_target.
    let entries = db
        .mailbox_list_for_target(&foreign_target, now_secs)
        .expect("list");
    assert_eq!(
        entries.len(),
        1,
        "foreign SelfPointer should be stored in mailbox DB"
    );
}

/// PosResponse channel full: warn but do not panic (N-5).
#[tokio::test]
async fn poll_pos_response_channel_full_does_not_panic() {
    // Channel capacity = 1; fill it first.
    let (tx, _rx) = mpsc::channel::<PosHashResponseMsg>(1);
    let response = PosHashResponseMsg {
        v: 1,
        challenge_id: [1u8; 16],
        chain_hash: [2u8; 32],
        timestamp: Timestamp::now(),
        device_id: None,
    };
    let payload = to_cbor(&response).expect("encode");
    // Fill the channel.
    tx.try_send(response.clone()).expect("first send");

    // Second send via dispatch_pos_response should WARN and not panic.
    let entry = make_entry(MailboxClass::PosResponse, make_identity(1), payload);
    // Should not panic — just warn.
    super::dispatch_pos_response(&tx, entry);
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
    let entry = MailboxEntry {
        target: make_identity(0xAA),
        msg_id: [2u8; 16],
        class: MailboxClass::DropNotice,
        payload_version: 1,
        payload,
        expires_at: now_secs + 86400 * 14,
        stored_at: now_secs,
        sender: None, // no sender
    };

    // Should not panic.
    super::dispatch_drop_notice(&handler, entry);
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
    let entry = MailboxEntry {
        target: make_identity(0xAA),
        msg_id: [3u8; 16],
        class: MailboxClass::DropNotice,
        payload_version: 1,
        payload: vec![0xFF, 0x00, 0xDE, 0xAD], // invalid CBOR
        expires_at: now_secs + 86400 * 14,
        stored_at: now_secs,
        sender: Some(make_identity(0xBB)),
    };

    // Should not panic.
    super::dispatch_drop_notice(&handler, entry);
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
        target: owner_master,
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

    super::dispatch_drop_notice(&handler, entry);

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

/// W-3: A DropNotice with deadline ≤ now triggers RepairNow on the repair channel.
///
/// Setup: holder H has a placement on block B. Owner receives a DropNotice with
/// deadline = now (immediate drop). ProcessorDropHandler must:
///   1. Mark placement Lost (via SymbolDropHandler::apply).
///   2. Send RepairTrigger::RepairNow on repair_tx.
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
        target: owner_master,
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

    super::dispatch_drop_notice(&handler, entry);

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

    // RepairNow must have been sent.
    let trigger = repair_rx
        .try_recv()
        .expect("RepairNow must be in channel after immediate drop");
    match trigger {
        RepairTrigger::RepairNow {
            block_id: bid,
            holder_id,
        } => {
            assert_eq!(bid, block_id, "RepairNow block_id must match");
            assert_eq!(holder_id, holder_device, "RepairNow holder_id must match");
        }
        other => panic!("expected RepairNow, got {other:?}"),
    }
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
        target: owner_master,
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

    super::dispatch_drop_notice(&handler, entry);

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
        target,
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

    super::dispatch_delete_request(&handler, entry).await;

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
        target: make_identity(0xFF),
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

    super::dispatch_delete_request(&handler, entry).await;

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

/// delete_request_stale_timestamp_rejected:
/// Freshness check still applies — entry older than MESSAGE_FRESHNESS_SECS is dropped.
#[tokio::test]
async fn delete_request_stale_timestamp_rejected() {
    use viaticum_core::constants::MESSAGE_FRESHNESS_SECS;
    use viaticum_core::mailbox::DeleteRequestPayload;
    use viaticum_core::types::HoldingStatus;

    let db = Db::open_in_memory().expect("db");
    let owner_key = make_signing_key(0x44);
    let owner_master = IdentityPub(owner_key.verifying_key().to_bytes());
    let block_id = SourceBlockId([0xCD; 32]);

    // Insert an Active holding.
    make_holding(&db, block_id, owner_master, HoldingStatus::Active);

    // Build a DeleteMsg with a stale timestamp (way in the past).
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
        target: make_identity(0xFF),
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

    super::dispatch_delete_request(&handler, entry).await;

    let holding = db
        .get_holding(&block_id, &owner_master)
        .expect("db ok")
        .expect("exists");
    assert_eq!(
        holding.status,
        HoldingStatus::Active,
        "delete_request_stale_timestamp_rejected: holding must remain Active (stale msg rejected)"
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
        target: make_identity(0xFF),
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
    super::dispatch_delete_request(&handler, entry).await;

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
        target: make_identity(0xFF), // target = us (the receiving peer)
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

    super::dispatch_revocation(&handler, entry).await;

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
        target: make_identity(0xFF),
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

    super::dispatch_revocation(&handler, entry).await;

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
        target: make_identity(0xFF),
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
    super::dispatch_revocation(&handler, entry).await;

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
        target: make_identity(0xFF),
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
    super::dispatch_revocation(&handler, entry).await;
}
