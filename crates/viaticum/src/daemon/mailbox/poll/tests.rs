// Tests for the mailbox poll dispatch logic.
//
// Strategy: exercise the per-class dispatch_* fns directly with an in-memory DB and
// stub handlers / a recording MailboxNetworkSender (no live network needed). Verify
// routing and effects for each MailboxClass.

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
        source_block_id: SourceBlockId([8u8; 32]),
        chain_hash: [99u8; 32],
        timestamp: Timestamp::now(),
        device_id: None,
        sig: [0u8; 64],
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

/// CS-MBX-3: a SelfPointer whose `target != my_master_pub` arriving in a poll response
/// is NEVER stored. A poll only returns OUR own mail, so a foreign-target SelfPointer is
/// a misrouted/hostile postman reply. The old code stored it directly (bypassing the
/// candidate-set admission gate and signature verification), letting a hostile read-fanout
/// postman inject arbitrary unverified entries for third-party targets into our DB. The
/// fix drops it with a warn, writing nothing.
#[tokio::test]
async fn poll_does_not_store_foreign_self_pointer() {
    use std::sync::{Arc, Mutex};
    use viaticum_core::system_state::SelfPointer;

    let db = Db::open_in_memory().expect("db");
    let my_master = make_identity(0xAA);
    let foreign_target = make_identity(0xBB);
    let current_pointer: Arc<Mutex<Option<SelfPointer>>> = Arc::new(Mutex::new(None));

    let entry = make_entry(MailboxClass::SelfPointer, foreign_target, vec![0x01, 0x02]);
    let now_secs = Timestamp::now().0;

    super::dispatch_self_pointer(&db, &my_master, &current_pointer, entry, now_secs);

    // Mailbox DB must have NOTHING stored for the foreign target — the foreign-store
    // path was removed (CS-MBX-3).
    let entries = db
        .mailbox_list_for_target(&foreign_target, now_secs)
        .expect("list");
    assert!(
        entries.is_empty(),
        "foreign-target SelfPointer must NOT be stored from the poll path (CS-MBX-3)"
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
        source_block_id: SourceBlockId([3u8; 32]),
        chain_hash: [2u8; 32],
        timestamp: Timestamp::now(),
        device_id: None,
        sig: [0u8; 64],
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
    let my_master = make_identity(0xAA);
    let entry = MailboxEntry {
        target: my_master,
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
        target: my_master,
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
        target: make_identity(0xBB),
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
        target: owner_master,
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
    ) -> anyhow::Result<Option<PosHashResponseMsg>> {
        Ok(Some(self.response.clone()))
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
        device_id: None,
        sig: [0u8; 64],
    };
    let handler: Arc<dyn super::PosMailboxChallengeHandler> =
        Arc::new(StubChallengeHandler { response });

    let owner_master = make_identity(0x42);
    let my_master = make_identity(0xAA);
    // Payload is opaque to the stub handler; entry.sender = the challenging owner.
    let base = make_entry(MailboxClass::PosChallenge, my_master, vec![0x00]);
    let entry = MailboxEntry {
        sender: Some(owner_master),
        ..base
    };

    let time_scale = 60;
    super::dispatch_pos_challenge(&router, &handler, &my_master, entry, time_scale).await;

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
        device_id: None,
        sig: [0u8; 64],
    };
    let handler: Arc<dyn super::PosMailboxChallengeHandler> =
        Arc::new(StubChallengeHandler { response });

    let owner_master = make_identity(0x42);
    let my_master = make_identity(0xAA);
    let someone_else = make_identity(0xBB);
    // Entry addressed to `someone_else`, not us. sender is a valid owner so the only
    // thing stopping a publish is the target guard.
    let base = make_entry(MailboxClass::PosChallenge, someone_else, vec![0x00]);
    let entry = MailboxEntry {
        sender: Some(owner_master),
        ..base
    };

    super::dispatch_pos_challenge(&router, &handler, &my_master, entry, 1).await;

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
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use viaticum_core::system_state::SelfPointer;

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
                device_id: None,
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
    let current_pointer: Arc<StdMutex<Option<SelfPointer>>> = Arc::new(StdMutex::new(None));

    let entry = make_entry(MailboxClass::Generic, my_master, vec![0xDE, 0xAD]);
    let now_secs = entry.stored_at;

    // Must not panic, must not publish, must not forward anything.
    super::dispatch_entry(
        &db,
        &router,
        &pos_tx,
        &challenge_handler,
        &drop_handler,
        &delete_handler,
        &revocation_handler,
        &my_master,
        &current_pointer,
        entry,
        now_secs,
        1,
    )
    .await;

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
// entry stays in the holder's mailbox until TTL, so dispatch_pos_challenge re-runs on
// every poll — that re-run is the retry. M1: re-published responses must dedup, not
// pile up; the msg_id must therefore be deterministic — derived from
// (challenge_id ‖ chain_hash) so it is stable across re-dispatch yet unpredictable to a
// postman that lacks the symbols (WARN-1), not a fresh random value each poll.

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
        device_id: None,
        sig: [0u8; 64],
    };
    let handler: Arc<dyn super::PosMailboxChallengeHandler> =
        Arc::new(StubChallengeHandler { response });

    let owner_master = make_identity(0x42);
    let my_master = make_identity(0xAA);
    let base = make_entry(MailboxClass::PosChallenge, my_master, vec![0x00]);
    let entry = MailboxEntry {
        sender: Some(owner_master),
        ..base
    };

    // Two re-dispatches of the SAME challenge entry (simulating two polls while the
    // challenge is still alive in our mailbox).
    super::dispatch_pos_challenge(&router, &handler, &my_master, entry.clone(), 1).await;
    super::dispatch_pos_challenge(&router, &handler, &my_master, entry, 1).await;

    let stored = sender.stored.lock().await;
    assert_eq!(stored.len(), 2, "two re-dispatches must publish twice");
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
        device_id: None,
        sig: [0u8; 64],
    };
    let base = make_entry(MailboxClass::PosChallenge, my_master, vec![0x00]);
    let entry = MailboxEntry {
        sender: Some(owner_master),
        ..base
    };

    let h1: Arc<dyn super::PosMailboxChallengeHandler> = Arc::new(StubChallengeHandler {
        response: mk([9u8; 32]),
    });
    super::dispatch_pos_challenge(&router, &h1, &my_master, entry.clone(), 1).await;
    let h2: Arc<dyn super::PosMailboxChallengeHandler> = Arc::new(StubChallengeHandler {
        response: mk([0xA5u8; 32]),
    });
    super::dispatch_pos_challenge(&router, &h2, &my_master, entry, 1).await;

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
        device_id: None,
        sig: [0u8; 64],
    };
    let handler: Arc<dyn super::PosMailboxChallengeHandler> =
        Arc::new(StubChallengeHandler { response });

    let owner_master = make_identity(0x42);
    let my_master = make_identity(0xAA);
    let base = make_entry(MailboxClass::PosChallenge, my_master, vec![0x00]);
    let entry = MailboxEntry {
        sender: Some(owner_master),
        ..base
    };

    // First poll: publish gets 0 acks (postman unreachable). No panic, response not lost.
    super::dispatch_pos_challenge(&router, &handler, &my_master, entry.clone(), 1).await;
    assert!(
        sender.acked.lock().await.is_empty(),
        "first dispatch must get 0 acks (simulated unreachable postman)"
    );

    // Next poll: the challenge is still alive in our mailbox, so dispatch re-runs and
    // this time the publish is acked — the honest holder delivers.
    super::dispatch_pos_challenge(&router, &handler, &my_master, entry, 1).await;

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
