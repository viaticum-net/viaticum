// mailbox-probe inject --replace: the hostile-postman swap of one pointer place.

use viaticum_core::db::testutil::test_db;
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};

use super::*;

fn sp(msg_id: u8, payload: u8, stored_at: u64) -> MailboxEntry {
    MailboxEntry {
        target: MailboxAddress([0xAD; 32]),
        msg_id: [msg_id; 16],
        class: MailboxClass::SelfPointer,
        payload_version: 2,
        payload: vec![payload; 64],
        expires_at: stored_at + 600,
        stored_at,
        sender: None,
    }
}

fn held(db: &Db) -> Vec<MailboxEntry> {
    db.mailbox_list_for_target(&MailboxAddress([0xAD; 32]), 0)
        .unwrap()
}

#[test]
fn inject_replace_overwrites_the_entry_of_the_same_slot() {
    let db = test_db();
    store_injected(&db, &sp(1, 0x11, 1_000), false).unwrap();
    store_injected(&db, &sp(2, 0x22, 1_000), false).unwrap();
    let replaced = store_injected(&db, &sp(1, 0x99, 1_001), true).unwrap();
    assert!(replaced, "slot 1 was held");
    let entries = held(&db);
    assert_eq!(entries.len(), 2, "replaced, not added");
    let slot1 = entries.iter().find(|e| e.msg_id == [1; 16]).unwrap();
    assert_eq!(slot1.payload, vec![0x99; 64]);
    assert!(
        entries.iter().any(|e| e.msg_id == [2; 16]),
        "other slot untouched"
    );
}

#[test]
fn inject_replace_into_an_empty_slot_just_inserts() {
    let db = test_db();
    let replaced = store_injected(&db, &sp(3, 0x33, 1_000), true).unwrap();
    assert!(!replaced);
    assert_eq!(held(&db).len(), 1);
}

#[test]
fn inject_without_replace_refuses_an_occupied_slot() {
    let db = test_db();
    store_injected(&db, &sp(1, 0x11, 1_000), false).unwrap();
    assert!(store_injected(&db, &sp(1, 0x99, 1_001), false).is_err());
    assert_eq!(held(&db)[0].payload, vec![0x11; 64]);
}

// ─── --pos-response: the forged PoS responses of C-SP step 4 (pos-i16) ─────────

use viaticum_core::messages::{MessageError, verify_pos_hash_response};
use viaticum_core::types::{DeviceId, SourceBlockId, Timestamp};

#[test]
fn pos_response_spec_parses_cid_block_device() {
    let spec = format!(
        "{}:{}:{}",
        "11".repeat(16),
        "22".repeat(32),
        "33".repeat(32)
    );
    let (cid, block, device) = parse_pos_response_spec(&spec).expect("parses");
    assert_eq!(cid, [0x11; 16]);
    assert_eq!(block, SourceBlockId([0x22; 32]));
    assert_eq!(device, DeviceId([0x33; 32]));
    for bad in [
        format!("{}:{}", "11".repeat(16), "22".repeat(32)),
        format!(
            "{}:{}:{}",
            "11".repeat(15),
            "22".repeat(32),
            "33".repeat(32)
        ),
        format!(
            "{}:{}:{}",
            "11".repeat(16),
            "22".repeat(32),
            "33".repeat(16)
        ),
        format!("{spec}:44"),
    ] {
        assert!(parse_pos_response_spec(&bad).is_none(), "{bad}");
    }
    assert_eq!(parse_forge_key("device"), Some(ForgeKey::Device));
    assert_eq!(parse_forge_key("master"), Some(ForgeKey::Master));
    assert_eq!(parse_forge_key("other"), None);
}

#[test]
fn forged_pos_response_names_the_given_device_and_verifies_only_for_its_signer() {
    let sibling_key = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]);
    let sibling = DeviceId(sibling_key.verifying_key().to_bytes());
    let master_key = ed25519_dalek::SigningKey::from_bytes(&[0x52; 32]);
    let addressed = DeviceId([0x53; 32]);
    let block = SourceBlockId([0x54; 32]);

    // F1: the sibling's device key, naming itself → the owner sees WrongDevice.
    let f1 = forged_pos_response([0x55; 16], block, sibling, &sibling_key, Timestamp(7));
    assert_eq!(f1.device_id, sibling);
    assert_eq!(f1.chain_hash, FORGED_CHAIN_HASH);
    assert_eq!((f1.challenge_id, f1.source_block_id), ([0x55; 16], block));
    verify_pos_hash_response(&f1, &sibling).expect("a valid device signature");
    assert!(matches!(
        verify_pos_hash_response(&f1, &addressed),
        Err(MessageError::WrongDevice { .. })
    ));

    // F2: the master key, naming the addressed device → BadSignature for that device.
    let f2 = forged_pos_response([0x55; 16], block, addressed, &master_key, Timestamp(7));
    assert_eq!(f2.device_id, addressed);
    assert!(matches!(
        verify_pos_hash_response(&f2, &addressed),
        Err(MessageError::BadSignature)
    ));
}
