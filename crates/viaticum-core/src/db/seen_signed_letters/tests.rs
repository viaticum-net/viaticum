// DN-1: `seen_signed_letters` + its expiry index (spec f1_stale_drop_notice.md DN1-10, DN1-13).

use super::{SEEN_SIGNED_LETTERS, SEEN_SIGNED_LETTERS_BY_EXPIRY, expiry_key};
use crate::db::Db;
use crate::db::testutil::test_db;
use crate::types::{SignedLetterClass, Timestamp};

fn sig(seed: u8) -> [u8; 64] {
    [seed; 64]
}

const DN: SignedLetterClass = SignedLetterClass::DropNotice;

/// Record `sig` at `now` (= first_seen) with `forget_after`, stand-alone.
fn record(db: &Db, s: u8, now: u64, forget_after: u64) -> usize {
    db.record_signed_letter_seen(&sig(s), DN, Timestamp(now), Timestamp(forget_after))
        .unwrap()
}

/// Write raw bytes under `sig` in the seen table, bypassing the API (a damaged row).
fn put_raw_row(db: &Db, sig: &[u8; 64], bytes: &[u8]) {
    let tx = db.inner.begin_write().unwrap();
    {
        let mut t = tx.open_table(SEEN_SIGNED_LETTERS).unwrap();
        t.insert(sig, bytes).unwrap();
    }
    tx.commit().unwrap();
}

/// Write an index key directly (the index entry that an old write of a damaged row left).
fn put_index_key(db: &Db, forget_after: u64, sig: &[u8; 64]) {
    let tx = db.inner.begin_write().unwrap();
    {
        let mut t = tx.open_table(SEEN_SIGNED_LETTERS_BY_EXPIRY).unwrap();
        t.insert(&expiry_key(Timestamp(forget_after), sig), ())
            .unwrap();
    }
    tx.commit().unwrap();
}

fn has_raw_row(db: &Db, sig: &[u8; 64]) -> bool {
    use redb::ReadableDatabase;
    let tx = db.inner.begin_read().unwrap();
    let t = tx.open_table(SEEN_SIGNED_LETTERS).unwrap();
    t.get(sig).unwrap().is_some()
}

#[test]
fn seen_drop_notices_expire_through_the_expiry_index() {
    // DN1-10. (1) A row whose forget_after <= now is not "seen"; the next insert prunes it and
    // reports 1. (2) Re-recording a live row keeps its first `first_seen`. (3) A stale index key
    // (left behind when the row was rewritten with a later expiry) does not delete the live row.
    let db = test_db();

    // (1) expiry at 1000.
    assert_eq!(record(&db, 1, 900, 1000), 0);
    assert!(db.signed_letter_seen(&sig(1), Timestamp(999)).unwrap());
    assert!(
        !db.signed_letter_seen(&sig(1), Timestamp(1000)).unwrap(),
        "forget_after <= now is forgotten"
    );
    let pruned = record(&db, 2, 1000, 5000);
    assert_eq!(pruned, 1, "the expired row is pruned by the next insert");
    let rows = db.list_seen_signed_letters().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, sig(2));
    assert_eq!(
        db.seen_signed_letter_index_len().unwrap(),
        1,
        "its index key went too"
    );

    // (2) the same key again: the first first_seen stays, no second index key.
    record(&db, 2, 2000, 6000);
    let rows = db.list_seen_signed_letters().unwrap();
    assert_eq!(rows[0].1.first_seen, Timestamp(1000), "first_seen is kept");
    assert_eq!(rows[0].1.forget_after, Timestamp(5000));
    assert_eq!(db.seen_signed_letter_index_len().unwrap(), 1);

    // (3) a stale index key at 3000 for the live row sig(2) (forget_after 5000).
    put_index_key(&db, 3000, &sig(2));
    let pruned = record(&db, 3, 3000, 9000);
    assert_eq!(
        pruned, 0,
        "the stale key is dropped, the live row is not counted as pruned"
    );
    assert!(
        db.signed_letter_seen(&sig(2), Timestamp(3000)).unwrap(),
        "the live row survives its stale index key"
    );
    assert_eq!(
        db.seen_signed_letter_index_len().unwrap(),
        2,
        "keys of sig(2)@5000 and sig(3)@9000"
    );

    // An expired row of the SAME signature is replaced, not kept (pruned first).
    let pruned = record(&db, 2, 7000, 8000);
    assert_eq!(pruned, 1);
    assert!(db.signed_letter_seen(&sig(2), Timestamp(7000)).unwrap());
    let r2 = db
        .list_seen_signed_letters()
        .unwrap()
        .into_iter()
        .find(|(k, _)| *k == sig(2))
        .unwrap();
    assert_eq!(r2.1.first_seen, Timestamp(7000), "a fresh row after expiry");
}

#[test]
fn an_undecodable_seen_row_does_not_disable_dedup() {
    // DN1-13 (FW-2). Garbage under a key: `signed_letter_seen` is Err (the caller applies the
    // notice as not seen); `record_*` overwrites the garbage; and a garbage row whose index key
    // expired is removed by pruning.
    let db = test_db();
    put_raw_row(&db, &sig(7), &[0xff, 0x00]);
    assert!(db.signed_letter_seen(&sig(7), Timestamp(100)).is_err());
    assert!(
        db.list_seen_signed_letters().unwrap().is_empty(),
        "skipped, not decoded"
    );

    record(&db, 7, 100, 1000);
    assert!(
        db.signed_letter_seen(&sig(7), Timestamp(100)).unwrap(),
        "the garbage was overwritten"
    );

    // A garbage row with an index key that expires at 200.
    put_raw_row(&db, &sig(8), &[0xff]);
    put_index_key(&db, 200, &sig(8));
    let pruned = record(&db, 9, 300, 2000);
    assert_eq!(pruned, 1, "the undecodable row is pruned");
    assert!(!has_raw_row(&db, &sig(8)));
    assert!(has_raw_row(&db, &sig(7)) && has_raw_row(&db, &sig(9)));
}

#[test]
fn a_dropped_transaction_records_no_seen_row() {
    // DN1-18 (DB half, the DD-2 seam). The seen row written through `DbWriteTxn` exists only
    // if that transaction commits.
    let db = test_db();
    {
        let mut txn = db.write_txn().unwrap();
        txn.record_signed_letter_seen(&sig(4), DN, Timestamp(10), Timestamp(1000))
            .unwrap();
        // dropped without commit
    }
    assert!(!db.signed_letter_seen(&sig(4), Timestamp(10)).unwrap());
    assert_eq!(db.seen_signed_letter_index_len().unwrap(), 0);

    let mut txn = db.write_txn().unwrap();
    txn.record_signed_letter_seen(&sig(4), DN, Timestamp(10), Timestamp(1000))
        .unwrap();
    txn.commit().unwrap();
    assert!(db.signed_letter_seen(&sig(4), Timestamp(10)).unwrap());
    assert_eq!(db.seen_signed_letter_index_len().unwrap(), 1);
}
