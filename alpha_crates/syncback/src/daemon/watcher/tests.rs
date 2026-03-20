use std::path::{Path, PathBuf};

use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::daemon::{BackupConfig, DirtyKind, IncludeEntry};

use super::{WatcherError, WatcherState, run};

// ---- test helpers ----

fn make_test_daemon_config(
    backup: &BackupConfig,
    syncback_dir: &Path,
) -> crate::daemon::Config {
    crate::daemon::Config {
        syncback_dir: syncback_dir.to_path_buf(),
        backup: backup.clone(),
        storage: crate::daemon::StorageConfig { quota_gb: 10 },
        network: crate::daemon::NetworkConfig {
            seed_nodes: vec![],
            bandwidth_limit_mbps: 0,
        },
        schedule: crate::daemon::ScheduleConfig {
            sync: crate::daemon::SyncFrequency::Weekly,
            vacuum: crate::daemon::VacuumFrequency::Monthly,
        },
        time_scale: 1,
    }
}

/// Returns (db, db_dir) — db_dir is separate from watched dir.
fn open_test_db() -> (syncback_core::db::Db, TempDir) {
    let db_dir = TempDir::new().unwrap();
    let db = syncback_core::db::Db::open(&db_dir.path().join("test.redb")).unwrap();
    (db, db_dir)
}

// ============================================================
// Scenario 1: pattern_matching_excludes_tmp_files
// ============================================================

#[test]
fn pattern_matching_excludes_tmp_files() {
    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: PathBuf::from("/some/dir"),
            importance: 0.8,
        }],
        exclude: vec!["*.tmp".to_string()],
    };
    let state = WatcherState::from_config(&config).unwrap();
    assert!(state.is_included(Path::new("/some/dir/notes.txt")));
    assert!(!state.is_included(Path::new("/some/dir/session.tmp")));
    assert!(state.is_included(Path::new("/some/dir/sub/file.rs")));
    assert!(!state.is_included(Path::new("/other/dir/notes.txt")));
}

// ============================================================
// Scenario 2: pattern_matching_excludes_directory_component
// ============================================================

#[test]
fn pattern_matching_excludes_directory_component() {
    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: PathBuf::from("/proj"),
            importance: 0.5,
        }],
        exclude: vec!["node_modules".to_string()],
    };
    let state = WatcherState::from_config(&config).unwrap();
    assert!(state.is_included(Path::new("/proj/src/index.js")));
    assert!(!state.is_included(Path::new("/proj/node_modules/lodash/index.js")));
}

// ============================================================
// Scenario 3: pattern_matching_longest_include_wins
// ============================================================

#[test]
fn pattern_matching_longest_include_wins() {
    let home = std::env::var("HOME").unwrap();
    let photos = PathBuf::from(&home).join("Photos");
    let favs = PathBuf::from(&home).join("Photos/Favorites");
    let config = BackupConfig {
        include: vec![
            IncludeEntry {
                path: photos.clone(),
                importance: 0.5,
            },
            IncludeEntry {
                path: favs.clone(),
                importance: 0.9,
            },
        ],
        exclude: vec![],
    };
    let state = WatcherState::from_config(&config).unwrap();
    assert_eq!(state.importance_for(&favs.join("img.jpg")), 0.9);
    assert_eq!(state.importance_for(&photos.join("Other/img.jpg")), 0.5);
}

// ============================================================
// Scenario 4: initial_scan_emits_created_for_new_file
// ============================================================

#[tokio::test]
async fn initial_scan_emits_created_for_new_file() {
    let watch_dir = TempDir::new().unwrap();
    let file_path = watch_dir.path().join("test.txt");
    std::fs::write(&file_path, b"hello").unwrap();

    let (db, _db_dir) = open_test_db();

    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: watch_dir.path().to_path_buf(),
            importance: 0.8,
        }],
        exclude: vec![],
    };

    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let daemon_config = make_test_daemon_config(&config, watch_dir.path());

    tokio::spawn(async move {
        run(cancel_clone, tx, db, daemon_config).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    cancel.cancel();

    let event = rx.try_recv().expect("expected at least one DirtyEvent");
    assert_eq!(event.path, file_path);
    assert_eq!(event.kind, DirtyKind::Created);
}

// ============================================================
// Scenario 5: initial_scan_skips_unchanged_file
// ============================================================

#[tokio::test]
async fn initial_scan_skips_unchanged_file() {
    let watch_dir = TempDir::new().unwrap();
    let file_path = watch_dir.path().join("unchanged.txt");
    let contents = b"same content";
    std::fs::write(&file_path, contents).unwrap();

    let hash: [u8; 32] = blake3::hash(contents).into();

    let (db, _db_dir) = open_test_db();
    db.upsert_file(&syncback_core::types::FileRecord {
        file_id: syncback_core::types::FileId(1),
        path: file_path.to_string_lossy().into_owned(),
        content_hash: hash,
        size_bytes: contents.len() as u64,
        importance: 0.8,
        dirty: false,
        current_unit_id: None,
        last_backed_up: Some(syncback_core::types::Timestamp::now()),
        backed_up: true,
        first_seen: syncback_core::types::Timestamp::now(),
    })
    .unwrap();

    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: watch_dir.path().to_path_buf(),
            importance: 0.8,
        }],
        exclude: vec![],
    };

    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let daemon_config = make_test_daemon_config(&config, watch_dir.path());

    tokio::spawn(async move {
        run(cancel_clone, tx, db, daemon_config).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    cancel.cancel();

    assert!(
        rx.try_recv().is_err(),
        "should not emit event for unchanged file"
    );
}

// ============================================================
// Scenario 6: initial_scan_emits_modified_for_changed_file
// ============================================================

#[tokio::test]
async fn initial_scan_emits_modified_for_changed_file() {
    let watch_dir = TempDir::new().unwrap();
    let file_path = watch_dir.path().join("changed.txt");
    std::fs::write(&file_path, b"new content").unwrap();

    let old_hash = [0u8; 32]; // different from blake3("new content")

    let (db, _db_dir) = open_test_db();
    db.upsert_file(&syncback_core::types::FileRecord {
        file_id: syncback_core::types::FileId(1),
        path: file_path.to_string_lossy().into_owned(),
        content_hash: old_hash,
        size_bytes: 7,
        importance: 0.8,
        dirty: false,
        current_unit_id: None,
        last_backed_up: None,
        backed_up: false,
        first_seen: syncback_core::types::Timestamp::now(),
    })
    .unwrap();

    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: watch_dir.path().to_path_buf(),
            importance: 0.8,
        }],
        exclude: vec![],
    };

    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let daemon_config = make_test_daemon_config(&config, watch_dir.path());

    tokio::spawn(async move {
        run(cancel_clone, tx, db, daemon_config).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    cancel.cancel();

    let event = rx.try_recv().expect("expected DirtyEvent");
    assert_eq!(event.kind, DirtyKind::Modified);
}

// ============================================================
// Scenario 7: initial_scan_skips_already_dirty_file
// ============================================================

#[tokio::test]
async fn initial_scan_skips_already_dirty_file() {
    let watch_dir = TempDir::new().unwrap();
    let file_path = watch_dir.path().join("dirty.txt");
    std::fs::write(&file_path, b"content").unwrap();

    let (db, _db_dir) = open_test_db();
    db.upsert_file(&syncback_core::types::FileRecord {
        file_id: syncback_core::types::FileId(1),
        path: file_path.to_string_lossy().into_owned(),
        content_hash: [0u8; 32],
        size_bytes: 7,
        importance: 0.8,
        dirty: true,
        current_unit_id: None,
        last_backed_up: None,
        backed_up: false,
        first_seen: syncback_core::types::Timestamp::now(),
    })
    .unwrap();

    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: watch_dir.path().to_path_buf(),
            importance: 0.8,
        }],
        exclude: vec![],
    };

    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let daemon_config = make_test_daemon_config(&config, watch_dir.path());

    tokio::spawn(async move {
        run(cancel_clone, tx, db, daemon_config).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    cancel.cancel();

    assert!(
        rx.try_recv().is_err(),
        "should not emit event for already-dirty file"
    );
}

// ============================================================
// Scenario 8: watch_roots_returns_unique_deduplicated_roots
// ============================================================

#[test]
fn watch_roots_returns_unique_deduplicated_roots() {
    let config = BackupConfig {
        include: vec![
            IncludeEntry {
                path: PathBuf::from("/home/user/docs"),
                importance: 0.8,
            },
            IncludeEntry {
                path: PathBuf::from("/home/user/docs"),
                importance: 0.9,
            },
        ],
        exclude: vec![],
    };
    let state = WatcherState::from_config(&config).unwrap();
    let roots = state.watch_roots();
    assert_eq!(roots.len(), 1);
}

// ============================================================
// Scenario 9: invalid_glob_pattern_returns_error
// ============================================================

#[test]
fn invalid_glob_pattern_returns_error() {
    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: PathBuf::from("/some/[invalid"),
            importance: 0.5,
        }],
        exclude: vec![],
    };
    let result = WatcherState::from_config(&config);
    assert!(matches!(result, Err(WatcherError::InvalidGlob { .. })));
}

// ============================================================
// Scenario 10: watcher_shuts_down_on_cancel
// ============================================================

#[tokio::test]
async fn watcher_shuts_down_on_cancel() {
    let syncback_dir = TempDir::new().unwrap();
    let (db, _db_dir) = open_test_db();
    let (tx, _rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let config = make_test_daemon_config(
        &BackupConfig {
            include: vec![],
            exclude: vec![],
        },
        syncback_dir.path(),
    );

    let handle = tokio::spawn(async move {
        run(cancel_clone, tx, db, config).await;
    });

    cancel.cancel();
    tokio::time::timeout(std::time::Duration::from_millis(500), handle)
        .await
        .expect("watcher did not shut down within timeout")
        .expect("watcher panicked");
}

// ============================================================
// Extra: is_included returns false for non-included path
// ============================================================

#[test]
fn is_included_returns_false_for_path_outside_all_roots() {
    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: PathBuf::from("/home/user/docs"),
            importance: 0.8,
        }],
        exclude: vec![],
    };
    let state = WatcherState::from_config(&config).unwrap();
    assert!(!state.is_included(Path::new("/tmp/file.txt")));
    assert!(!state.is_included(Path::new("/home/user/other/file.txt")));
}

// ============================================================
// Extra: importance_for returns 0.0 for excluded path
// ============================================================

#[test]
fn importance_for_returns_zero_for_excluded_path() {
    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: PathBuf::from("/proj"),
            importance: 0.7,
        }],
        exclude: vec!["*.log".to_string()],
    };
    let state = WatcherState::from_config(&config).unwrap();
    assert_eq!(state.importance_for(Path::new("/proj/app.log")), 0.0);
    assert_eq!(state.importance_for(Path::new("/proj/main.rs")), 0.7);
}

// ============================================================
// Extra: invalid exclude glob returns error
// ============================================================

#[test]
fn invalid_exclude_glob_returns_error() {
    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: PathBuf::from("/home/user"),
            importance: 0.5,
        }],
        exclude: vec!["[bad".to_string()],
    };
    let result = WatcherState::from_config(&config);
    assert!(matches!(result, Err(WatcherError::InvalidGlob { .. })));
}

// ============================================================
// Extra: initial_scan_skips_excluded_files
// ============================================================

#[tokio::test]
async fn initial_scan_skips_excluded_files() {
    let watch_dir = TempDir::new().unwrap();
    let tmp_file = watch_dir.path().join("session.tmp");
    std::fs::write(&tmp_file, b"scratch").unwrap();

    let (db, _db_dir) = open_test_db();

    let config = BackupConfig {
        include: vec![IncludeEntry {
            path: watch_dir.path().to_path_buf(),
            importance: 0.8,
        }],
        exclude: vec!["*.tmp".to_string()],
    };

    let (tx, mut rx) = mpsc::channel(64);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let daemon_config = make_test_daemon_config(&config, watch_dir.path());

    tokio::spawn(async move {
        run(cancel_clone, tx, db, daemon_config).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    cancel.cancel();

    assert!(
        rx.try_recv().is_err(),
        "should not emit event for excluded .tmp file"
    );
}
