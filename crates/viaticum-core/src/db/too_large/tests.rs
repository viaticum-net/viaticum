use tempfile::TempDir;

use crate::db::Db;
use crate::db::testutil::test_db;
use crate::types::{Timestamp, TooLargeMark};

fn mark(size: u64, limit: u64, first: u64, last: u64) -> TooLargeMark {
    TooLargeMark {
        size_bytes: size,
        limit_bytes: limit,
        first_seen: Timestamp(first),
        last_seen: Timestamp(last),
    }
}

#[test]
fn db_too_large_mark_roundtrip_and_remove() {
    let db = test_db();
    assert_eq!(db.get_too_large("/w/a.mkv").unwrap(), None);
    assert!(db.list_too_large().unwrap().is_empty());
    assert!(!db.remove_too_large("/w/a.mkv").unwrap());

    let a = mark(4_294_967_296, 268_435_456, 100, 100);
    let b = mark(300, 200, 50, 60);
    db.put_too_large("/w/b.bin", &b).unwrap();
    db.put_too_large("/w/a.mkv", &a).unwrap();
    assert_eq!(db.get_too_large("/w/a.mkv").unwrap(), Some(a));
    assert_eq!(
        db.list_too_large().unwrap(),
        vec![("/w/a.mkv".to_string(), a), ("/w/b.bin".to_string(), b)]
    );

    // Replace keeps one row per path.
    let a2 = mark(5_000_000_000, 268_435_456, 100, 200);
    db.put_too_large("/w/a.mkv", &a2).unwrap();
    assert_eq!(db.get_too_large("/w/a.mkv").unwrap(), Some(a2));
    assert_eq!(db.list_too_large().unwrap().len(), 2);

    assert!(db.remove_too_large("/w/a.mkv").unwrap());
    assert_eq!(db.get_too_large("/w/a.mkv").unwrap(), None);
    assert_eq!(
        db.list_too_large().unwrap(),
        vec![("/w/b.bin".to_string(), b)]
    );
}

#[test]
fn too_large_mark_survives_closing_and_reopening_the_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("db.redb");
    let m = mark(10, 5, 1, 2);
    {
        let db = Db::open(&path).unwrap();
        db.put_too_large("/w/x", &m).unwrap();
    }
    let db = Db::open(&path).unwrap();
    assert_eq!(db.get_too_large("/w/x").unwrap(), Some(m));
}
