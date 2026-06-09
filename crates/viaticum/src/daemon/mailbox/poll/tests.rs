// Tests for the mailbox poll dispatch logic.
//
// Strategy: test dispatch_entry directly using the MockPosMailboxChallengeHandler
// (no live network needed). Verify routing decisions for each MailboxClass.

use tokio::sync::mpsc;
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxClass, MailboxEntry};
use viaticum_core::messages::{PosHashResponseMsg, to_cbor};
use viaticum_core::types::{IdentityPub, Timestamp};

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
