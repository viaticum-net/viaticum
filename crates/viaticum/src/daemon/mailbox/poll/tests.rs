// Tests for the mailbox poll dispatch logic.
//
// Strategy: test dispatch_entry directly using the MockPosMailboxChallengeHandler
// (no live network needed). Verify routing decisions for each MailboxClass.

use std::sync::Arc;

use tokio::sync::mpsc;
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxClass, MailboxEntry};
use viaticum_core::messages::{
    PosHashResponseMsg, SymbolDropNoticeBatchMsg, SymbolDropNoticeMsg, to_cbor,
};
use viaticum_core::types::{
    DeviceId, IdentityPub, PlacementStatus, SourceBlockId, SymbolPlacement, Timestamp,
};

use crate::daemon::processor::ProcessorDropHandler;

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
    let db = Db::open_in_memory().expect("db");
    let my_master = make_identity(0xAA);

    // Build a trivial payload (not a real SelfPointer; verify_self_pointer will fail gracefully).
    let entry = make_entry(MailboxClass::SelfPointer, my_master, vec![0x01]);
    let now_secs = Timestamp::now().0;

    super::dispatch_self_pointer(&db, &my_master, entry, now_secs);

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
    let db = Db::open_in_memory().expect("db");
    let my_master = make_identity(0xAA);
    let foreign_target = make_identity(0xBB);

    let entry = make_entry(MailboxClass::SelfPointer, foreign_target, vec![0x01, 0x02]);
    let now_secs = Timestamp::now().0;

    super::dispatch_self_pointer(&db, &my_master, entry, now_secs);

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
    let db = Db::open_in_memory().expect("db");
    let handler: Arc<dyn super::DropNoticeHandler> =
        Arc::new(ProcessorDropHandler::new(db.clone()));

    let batch = SymbolDropNoticeBatchMsg {
        v: 1,
        notices: vec![SymbolDropNoticeMsg {
            v: 1,
            source_block_id: SourceBlockId([0x01; 32]),
            esi_ranges: vec![(0, 1)],
            deadline: Timestamp(Timestamp::now().0 + 86400 * 14),
            timestamp: Timestamp::now(),
        }],
    };
    let payload = to_cbor(&batch).expect("encode");
    let now_secs = Timestamp::now().0;

    // Entry with no sender.
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
    let db = Db::open_in_memory().expect("db");
    let handler: Arc<dyn super::DropNoticeHandler> =
        Arc::new(ProcessorDropHandler::new(db.clone()));

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

/// T-7: Feeding a SymbolDropNoticeBatchMsg through dispatch_drop_notice with a
/// prod ProcessorDropHandler marks each referenced placement Lost and updates
/// block cached fields (recomputes current_alive).
///
/// Setup: 2 holdings of holder H for blocks B1 and B2. Owner O has Alive placements
/// with holder H on both blocks. We feed a 2-notice batch → both placements become Lost.
#[tokio::test]
async fn drop_notice_batch_dispatch_marks_each_placement_lost() {
    use viaticum_core::types::{PeerRecord, SourceBlockRecord, SourceBlockStatus, SourceBlockType};

    let db = Db::open_in_memory().expect("db");

    // Owner and holder identities.
    let owner_master = IdentityPub([0xAA; 32]);
    let holder_master = IdentityPub([0xBB; 32]);
    let holder_device = DeviceId([0xBB; 32]);

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

    // Build a 2-notice batch from holder H to owner O.
    let now = Timestamp::now();
    let batch = SymbolDropNoticeBatchMsg {
        v: 1,
        notices: vec![
            SymbolDropNoticeMsg {
                v: 1,
                source_block_id: block_id_1,
                esi_ranges: vec![(0, 5)],
                deadline: Timestamp(now.0 + 86400 * 14),
                timestamp: now,
            },
            SymbolDropNoticeMsg {
                v: 1,
                source_block_id: block_id_2,
                esi_ranges: vec![(0, 5)],
                deadline: Timestamp(now.0 + 86400 * 14),
                timestamp: now,
            },
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

    let handler: Arc<dyn super::DropNoticeHandler> =
        Arc::new(ProcessorDropHandler::new(db.clone()));

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
