use std::io::Cursor;
use std::path::Path;

use tempfile::TempDir;

use super::{SourceReadError, read_at_most, read_source_bounded, source_exceeds_limit};

fn file(dir: &TempDir, name: &str, len: usize) -> std::path::PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, vec![7u8; len]).unwrap();
    p
}

#[test]
fn source_read_bounded_rejects_by_metadata_without_reading() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let p = dir.path().join("huge.bin");
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(1 << 30).unwrap(); // sparse: reading it would allocate 1 GiB
    drop(f);
    // Unreadable: an attempt to open it would be an `Io` error, not `TooLarge`.
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();

    match read_source_bounded(&p, 1 << 20, 0) {
        Err(SourceReadError::TooLarge { size, limit }) => {
            assert_eq!(size, 1 << 30);
            assert_eq!(limit, 1 << 20);
        }
        other => panic!("expected TooLarge by metadata, got {other:?}"),
    }
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn source_read_bounded_reads_file_of_exactly_the_limit() {
    let dir = TempDir::new().unwrap();
    let p = file(&dir, "edge.bin", 1000);
    let bytes = read_source_bounded(&p, 1000, 16).unwrap();
    assert_eq!(bytes.len(), 1000);
    assert!(bytes.capacity() >= 1016, "extra capacity reserved up front");
    assert!(matches!(
        read_source_bounded(&p, 999, 0),
        Err(SourceReadError::TooLarge {
            size: 1000,
            limit: 999
        })
    ));
}

#[test]
fn source_read_bounded_missing_file_is_not_found() {
    let dir = TempDir::new().unwrap();
    let err = read_source_bounded(&dir.path().join("nope"), 100, 0).unwrap_err();
    assert!(err.is_not_found());
    assert!(!SourceReadError::TooLarge { size: 2, limit: 1 }.is_not_found());
}

#[test]
fn source_exceeds_limit_answers_from_metadata() {
    let dir = TempDir::new().unwrap();
    let p = file(&dir, "a.bin", 500);
    assert_eq!(source_exceeds_limit(&p, 500).unwrap(), None);
    assert_eq!(source_exceeds_limit(&p, 499).unwrap(), Some(500));
    let missing = source_exceeds_limit(Path::new("/nonexistent/viaticum/x"), 1).unwrap_err();
    assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn read_at_most_rejects_stream_longer_than_limit() {
    assert_eq!(
        read_at_most(Cursor::new(vec![1u8; 10]), 10, 10)
            .unwrap()
            .len(),
        10
    );
    match read_at_most(Cursor::new(vec![1u8; 11]), 10, 0) {
        Err(SourceReadError::TooLarge {
            size: 11,
            limit: 10,
        }) => {}
        other => panic!("expected TooLarge, got {other:?}"),
    }
    // An endless stream (a file growing without end) is cut at limit + 1 bytes.
    match read_at_most(std::io::repeat(0), 100, 0) {
        Err(SourceReadError::TooLarge {
            size: 101,
            limit: 100,
        }) => {}
        other => panic!("expected TooLarge, got {other:?}"),
    }
}
