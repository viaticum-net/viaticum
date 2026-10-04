// mailbox-probe remove: which entries go, which stay.

use viaticum_core::db::testutil::test_db;
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};

use super::*;

const BOX: MailboxAddress = MailboxAddress([0xAD; 32]);
const OTHER: MailboxAddress = MailboxAddress([0xBE; 32]);

fn put(db: &Db, target: MailboxAddress, msg_id: u8, class: MailboxClass) {
    let entry = MailboxEntry {
        target,
        msg_id: [msg_id; 16],
        class,
        payload_version: 2,
        payload: vec![msg_id; 64],
        expires_at: 1_600,
        stored_at: 1_000,
        sender: None,
    };
    db.mailbox_insert(&entry, entry.stored_at).unwrap();
}

fn held(db: &Db, target: &MailboxAddress) -> Vec<([u8; 16], MailboxClass)> {
    db.mailbox_list_for_target(target, 0)
        .unwrap()
        .into_iter()
        .map(|e| (e.msg_id, e.class))
        .collect()
}

fn seeded() -> Db {
    let db = test_db();
    put(&db, BOX, 1, MailboxClass::PosResponse);
    put(&db, BOX, 2, MailboxClass::PosResponse);
    put(&db, BOX, 1, MailboxClass::DropNotice);
    put(&db, OTHER, 1, MailboxClass::PosResponse);
    db
}

#[test]
fn remove_with_msg_id_and_class_deletes_only_that_entry() {
    let db = seeded();
    let n = remove_matching(&db, &BOX, Some([1; 16]), Some(MailboxClass::PosResponse)).unwrap();
    assert_eq!(n, 1);
    let left = held(&db, &BOX);
    assert_eq!(left.len(), 2);
    assert!(left.contains(&([2; 16], MailboxClass::PosResponse)));
    assert!(left.contains(&([1; 16], MailboxClass::DropNotice)));
    assert_eq!(held(&db, &OTHER).len(), 1, "other address untouched");
}

#[test]
fn remove_without_msg_id_deletes_every_entry_of_the_class() {
    let db = seeded();
    let n = remove_matching(&db, &BOX, None, Some(MailboxClass::PosResponse)).unwrap();
    assert_eq!(n, 2);
    assert_eq!(held(&db, &BOX), vec![([1; 16], MailboxClass::DropNotice)]);
    assert_eq!(held(&db, &OTHER).len(), 1);
}

#[test]
fn remove_without_filters_empties_the_address_only() {
    let db = seeded();
    assert_eq!(remove_matching(&db, &BOX, None, None).unwrap(), 3);
    assert!(held(&db, &BOX).is_empty());
    assert_eq!(held(&db, &OTHER).len(), 1);
    assert_eq!(
        db.mailbox_bytes_for_target(&BOX).unwrap(),
        0,
        "byte counter follows"
    );
}

#[test]
fn remove_with_no_match_removes_nothing() {
    let db = seeded();
    let n = remove_matching(&db, &BOX, Some([9; 16]), None).unwrap();
    assert_eq!(n, 0);
    assert_eq!(held(&db, &BOX).len(), 3);
}
