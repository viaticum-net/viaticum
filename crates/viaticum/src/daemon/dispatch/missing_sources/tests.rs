use std::sync::Arc;
use std::time::Duration;

use viaticum_core::db::Db;
use viaticum_core::types::{DeviceId, FileId, FileRecord, LocalState, Timestamp};

use super::*;

fn record(id: u64, path: &std::path::Path, state: LocalState) -> FileRecord {
    FileRecord {
        file_id: FileId(id),
        path: path.display().to_string(),
        importance: 0.5,
        devices: vec![(DeviceId([1; 32]), state)],
        versions: vec![],
        first_seen: Timestamp(1),
        on_disk_confirmed: true,
    }
}

#[test]
fn count_skips_present_files_and_files_deleted_everywhere() {
    let dir = tempfile::tempdir().unwrap();
    let here = dir.path().join("here");
    std::fs::write(&here, b"x").unwrap();
    let db = Db::open_in_memory().unwrap();
    db.upsert_file(&record(1, &here, LocalState::Present))
        .unwrap();
    db.upsert_file(&record(2, &dir.path().join("gone"), LocalState::Present))
        .unwrap();
    db.upsert_file(&record(
        3,
        &dir.path().join("deleted"),
        LocalState::Deleted(Timestamp(2)),
    ))
    .unwrap();
    assert_eq!(count_files_without_source(&db).unwrap(), 1);
}

#[tokio::test]
async fn cache_counts_once_then_serves_the_cached_value_until_stale() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f");
    let db = Db::open_in_memory().unwrap();
    db.upsert_file(&record(1, &path, LocalState::Present))
        .unwrap();

    let cache = Arc::new(MissingSourceCache::new(Duration::from_secs(3600)));
    assert_eq!(cache.get(&db).await, 1, "first call waits for the count");
    std::fs::write(&path, b"back").unwrap();
    assert_eq!(
        cache.get(&db).await,
        1,
        "within the refresh period the cached value is served (no stat per call)"
    );
}

#[tokio::test]
async fn cache_recounts_in_the_background_once_stale() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f");
    let db = Db::open_in_memory().unwrap();
    db.upsert_file(&record(1, &path, LocalState::Present))
        .unwrap();

    let cache = Arc::new(MissingSourceCache::new(Duration::ZERO));
    assert_eq!(cache.get(&db).await, 1);
    std::fs::write(&path, b"back").unwrap();
    // Stale: this call returns the old value and starts a recount.
    let _ = cache.get(&db).await;
    let mut now = 1;
    for _ in 0..100 {
        now = cache.get(&db).await;
        if now == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(now, 0, "the background recount sees the file back in place");
}
