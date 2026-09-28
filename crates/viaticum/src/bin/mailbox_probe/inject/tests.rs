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
