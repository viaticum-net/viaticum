// Tests for WatchAdmin — all what_when_then naming convention.
#![allow(clippy::cloned_ref_to_slice_refs)]

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use tempfile::TempDir;
use tokio::sync::mpsc;

use viaticum_core::config::{DEFAULT_IMPORTANCE, DEFAULT_IMPORTANCE_MULTIPLIER, WatchConfig};
use viaticum_core::db::Db;
use viaticum_core::types::{
    DeviceId, FileId, FileRecord, FileVersion, LocalState, PlacementStatus, SourceBlockId,
    SymbolPlacement, Timestamp,
};

use super::{
    AddWatchRequest, CachedRollup, FolderRollup, PatchWatchRequest, WatchAdmin, WatchAdminError,
    WatchStatus, WatcherStatusSignal, decode_path_b64, derive_status, encode_path_b64,
    save_watches, traffic_light,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn test_db() -> Db {
    Db::open_in_memory().expect("failed to open test DB")
}

fn dummy_device_id() -> DeviceId {
    DeviceId([42u8; 32])
}

fn make_watch_admin_with_config(
    config_path: PathBuf,
    configs: Vec<WatchConfig>,
    db: Db,
) -> (
    WatchAdmin,
    mpsc::Receiver<super::super::watcher::WatcherCommand>,
) {
    let live_configs = Arc::new(RwLock::new(configs));
    let (tx, rx) = mpsc::channel(64);
    let admin = WatchAdmin::new(config_path, live_configs, tx, db);
    (admin, rx)
}

/// Create a minimal FileRecord with one version.
fn make_file_record(file_id: u64, path: &str, k: u32, t: u16, backed_up: bool) -> FileRecord {
    let now = Timestamp::now();
    FileRecord {
        file_id: FileId(file_id),
        path: path.to_string(),
        importance: 0.5,
        devices: vec![(dummy_device_id(), LocalState::Present)],
        versions: vec![FileVersion {
            content_hash: [file_id as u8; 32],
            source_block_id: SourceBlockId([file_id as u8; 32]),
            k,
            t,
            created_at: now,
            backed_up_at: if backed_up { Some(now) } else { None },
        }],
        first_seen: now,
    }
}

/// Create a SymbolPlacement.
fn make_placement(file_id: u64, block_id: u8, status: PlacementStatus) -> SymbolPlacement {
    SymbolPlacement {
        source_block_id: SourceBlockId([block_id; 32]),
        holder_id: DeviceId([99u8; 32]),
        file_id: FileId(file_id),
        esi_ranges: vec![(0, 3)],
        binding_seed: [0u8; 32],
        status,
        last_verified: None,
        placed_at: Timestamp::now(),
        consecutive_misses: 0,
    }
}

// ─── list_watches tests ───────────────────────────────────────────────────────

#[test]
fn list_watches_returns_empty_when_no_configs() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let (admin, _rx) = make_watch_admin_with_config(config_path, vec![], db);

    let entries = admin.list_watches();
    assert!(
        entries.is_empty(),
        "expected empty list, got {:?}",
        entries.len()
    );
}

#[test]
fn list_watches_returns_configured_entries_with_correct_path_and_importance() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();
    let configs = vec![WatchConfig {
        path: watch_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.7,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    }];
    let (admin, _rx) = make_watch_admin_with_config(config_path, configs, db);

    let entries = admin.list_watches();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, watch_dir.path().to_string_lossy().as_ref());
    assert!((entries[0].importance - 0.7).abs() < 1e-9);
}

// ─── defaults test ────────────────────────────────────────────────────────────

#[test]
fn get_watches_defaults_returns_default_importance() {
    // DEFAULT_IMPORTANCE is 0.5 (fallback for unmatched paths).
    assert!((DEFAULT_IMPORTANCE - 0.5).abs() < 1e-9);
    // DEFAULT_IMPORTANCE_MULTIPLIER is 1.0 (per-folder default).
    assert!((DEFAULT_IMPORTANCE_MULTIPLIER - 1.0).abs() < 1e-9);
}

// ─── add_watch tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn add_watch_with_valid_dir_appends_to_live_configs() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();
    let (admin, _rx) = make_watch_admin_with_config(config_path, vec![], db);

    let result = admin
        .add_watch(AddWatchRequest {
            path: watch_dir.path().to_string_lossy().into_owned(),
            importance_multiplier: Some(0.6),
            importance_legacy: None,
        })
        .await;

    assert!(result.is_ok(), "add_watch should succeed: {:?}", result);
    let entry = result.unwrap();
    assert_eq!(entry.path, watch_dir.path().to_string_lossy().as_ref());
    assert!((entry.importance - 0.6).abs() < 1e-9);

    // Verify it's now in live_configs.
    let configs = admin.live_configs.read().unwrap();
    assert_eq!(configs.len(), 1);
    assert!(
        configs[0]
            .path
            .contains(watch_dir.path().to_string_lossy().as_ref())
    );
}

#[tokio::test]
async fn add_watch_writes_entry_to_config_toml_preserving_other_sections() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();

    // Write a config.toml with an existing section.
    std::fs::write(
        &config_path,
        "[network]\nrelay_max_entries = 100\n\n# Important comment\n",
    )
    .unwrap();

    let (admin, _rx) = make_watch_admin_with_config(config_path.clone(), vec![], db);

    admin
        .add_watch(AddWatchRequest {
            path: watch_dir.path().to_string_lossy().into_owned(),
            importance_multiplier: Some(0.5),
            importance_legacy: None,
        })
        .await
        .unwrap();

    let written = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        written.contains("relay_max_entries"),
        "network section should be preserved"
    );
    assert!(
        written.contains("[[watch]]"),
        "watch entry should be written"
    );
    assert!(
        written.contains(&watch_dir.path().to_string_lossy().as_ref().to_string()),
        "watch path should appear in config"
    );
}

#[tokio::test]
async fn add_watch_fails_with_not_a_directory_for_nonexistent_path() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let (admin, _rx) = make_watch_admin_with_config(config_path, vec![], db);

    let result = admin
        .add_watch(AddWatchRequest {
            path: "/nonexistent/path/does/not/exist".to_string(),
            importance_multiplier: Some(0.5),
            importance_legacy: None,
        })
        .await;

    assert!(
        matches!(result, Err(WatchAdminError::NotADirectory(_))),
        "expected NotADirectory, got {:?}",
        result
    );
}

#[tokio::test]
async fn add_watch_fails_with_nested_when_path_is_child_of_existing_watch() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let parent_dir = TempDir::new().unwrap();

    // Create a subdirectory.
    let child_path = parent_dir.path().join("subdir");
    std::fs::create_dir(&child_path).unwrap();

    let existing = WatchConfig {
        path: parent_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    let (admin, _rx) = make_watch_admin_with_config(config_path, vec![existing], db);

    let result = admin
        .add_watch(AddWatchRequest {
            path: child_path.to_string_lossy().into_owned(),
            importance_multiplier: Some(0.5),
            importance_legacy: None,
        })
        .await;

    assert!(
        matches!(result, Err(WatchAdminError::Nested { .. })),
        "expected Nested error, got {:?}",
        result
    );
}

#[tokio::test]
async fn add_watch_fails_with_nested_when_existing_watch_is_child_of_new_path() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let parent_dir = TempDir::new().unwrap();

    // Create a subdirectory that is already watched.
    let child_path = parent_dir.path().join("subdir");
    std::fs::create_dir(&child_path).unwrap();

    let existing = WatchConfig {
        path: child_path.to_string_lossy().into_owned(),
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    let (admin, _rx) = make_watch_admin_with_config(config_path, vec![existing], db);

    // Try to add the parent — would contain the existing subdir.
    let result = admin
        .add_watch(AddWatchRequest {
            path: parent_dir.path().to_string_lossy().into_owned(),
            importance_multiplier: Some(0.5),
            importance_legacy: None,
        })
        .await;

    assert!(
        matches!(result, Err(WatchAdminError::Nested { .. })),
        "expected Nested error when new path contains existing watch, got {:?}",
        result
    );
}

// ─── patch_watch tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn patch_watch_updates_importance_in_live_configs_and_toml() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();

    let existing = WatchConfig {
        path: watch_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    // Write initial config.
    save_watches(&config_path, &[existing.clone()]).unwrap();

    let (admin, _rx) = make_watch_admin_with_config(config_path.clone(), vec![existing], db);

    let path_b64 = encode_path_b64(watch_dir.path());
    let result = admin
        .patch_watch(
            &path_b64,
            PatchWatchRequest {
                importance_multiplier: Some(0.9),
                importance_legacy: None,
            },
        )
        .await;

    assert!(result.is_ok(), "patch_watch should succeed: {:?}", result);
    let entry = result.unwrap();
    assert!((entry.importance - 0.9).abs() < 1e-9);

    // Check live_configs.
    let cfgs = admin.live_configs.read().unwrap();
    assert_eq!(cfgs.len(), 1);
    assert!((cfgs[0].importance_multiplier - 0.9).abs() < 1e-9);

    // Check config file.
    let written = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        written.contains("0.9"),
        "new importance should appear in config.toml"
    );
}

#[tokio::test]
async fn patch_watch_returns_not_found_for_unknown_path() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let (admin, _rx) = make_watch_admin_with_config(config_path, vec![], db);

    // Encode a path that is not watched.
    let path_b64 = encode_path_b64(&PathBuf::from("/not/a/watch"));
    let result = admin
        .patch_watch(
            &path_b64,
            PatchWatchRequest {
                importance_multiplier: Some(0.5),
                importance_legacy: None,
            },
        )
        .await;

    assert!(
        matches!(result, Err(WatchAdminError::NotFound(_))),
        "expected NotFound, got {:?}",
        result
    );
}

// ─── remove_watch tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn remove_watch_without_purge_removes_from_live_configs_and_toml() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();

    let existing = WatchConfig {
        path: watch_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    save_watches(&config_path, &[existing.clone()]).unwrap();

    let (admin, _rx) = make_watch_admin_with_config(config_path.clone(), vec![existing], db);

    let path_b64 = encode_path_b64(watch_dir.path());
    let result = admin.remove_watch(&path_b64, false).await;
    assert!(result.is_ok(), "remove_watch should succeed: {:?}", result);

    // live_configs should be empty.
    let cfgs = admin.live_configs.read().unwrap();
    assert!(cfgs.is_empty(), "live_configs should be empty after remove");

    // Config file should have no [[watch]] entry.
    let written = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        !written.contains("[[watch]]"),
        "config should have no watch entries"
    );
}

#[tokio::test]
async fn remove_watch_without_purge_does_not_touch_file_records() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();

    // Insert a file record under the watch dir.
    let record = make_file_record(
        1,
        &format!("{}/test.txt", watch_dir.path().display()),
        10,
        64,
        true,
    );
    db.upsert_file(&record).unwrap();

    let existing = WatchConfig {
        path: watch_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    save_watches(&config_path, &[existing.clone()]).unwrap();

    let (admin, _rx) = make_watch_admin_with_config(config_path, vec![existing], db.clone());
    let path_b64 = encode_path_b64(watch_dir.path());
    admin.remove_watch(&path_b64, false).await.unwrap();

    // File record should still be Present.
    let files = db.list_all_files().unwrap();
    assert_eq!(files.len(), 1);
    let (_, state) = &files[0].devices[0];
    assert_eq!(*state, LocalState::Present, "file should still be Present");
}

#[tokio::test]
async fn remove_watch_with_purge_marks_all_file_records_deleted() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();

    // Insert file records under watch dir.
    for i in 1..=3u64 {
        let record = make_file_record(
            i,
            &format!("{}/file{}.txt", watch_dir.path().display(), i),
            10,
            64,
            true,
        );
        db.upsert_file(&record).unwrap();
    }

    let existing = WatchConfig {
        path: watch_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    save_watches(&config_path, &[existing.clone()]).unwrap();

    let (admin, _rx) = make_watch_admin_with_config(config_path, vec![existing], db.clone());
    let path_b64 = encode_path_b64(watch_dir.path());
    admin.remove_watch(&path_b64, true).await.unwrap();

    // All file records should be Deleted.
    let files = db.list_all_files().unwrap();
    assert_eq!(files.len(), 3);
    for file in &files {
        for (_, state) in &file.devices {
            assert!(
                matches!(state, LocalState::Deleted(_)),
                "expected Deleted, got {:?}",
                state
            );
        }
    }
}

#[tokio::test]
async fn remove_watch_with_purge_marks_all_devices_deleted_for_each_file() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();

    // File with two device entries.
    let now = Timestamp::now();
    let record = FileRecord {
        file_id: FileId(1),
        path: format!("{}/multi.txt", watch_dir.path().display()),
        importance: 0.5,
        devices: vec![
            (DeviceId([1u8; 32]), LocalState::Present),
            (DeviceId([2u8; 32]), LocalState::Present),
        ],
        versions: vec![FileVersion {
            content_hash: [1u8; 32],
            source_block_id: SourceBlockId([1u8; 32]),
            k: 10,
            t: 64,
            created_at: now,
            backed_up_at: Some(now),
        }],
        first_seen: now,
    };
    db.upsert_file(&record).unwrap();

    let existing = WatchConfig {
        path: watch_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    save_watches(&config_path, &[existing.clone()]).unwrap();

    let (admin, _rx) = make_watch_admin_with_config(config_path, vec![existing], db.clone());
    let path_b64 = encode_path_b64(watch_dir.path());
    admin.remove_watch(&path_b64, true).await.unwrap();

    let files = db.list_all_files().unwrap();
    assert_eq!(files.len(), 1);
    for (_, state) in &files[0].devices {
        assert!(
            matches!(state, LocalState::Deleted(_)),
            "all devices should be Deleted"
        );
    }
}

// ─── scan_watch tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn scan_watch_returns_not_found_for_unwatched_path() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let (admin, _rx) = make_watch_admin_with_config(config_path, vec![], db);

    let path_b64 = encode_path_b64(&PathBuf::from("/not/watched"));
    let result = admin.scan_watch(&path_b64).await;

    assert!(
        matches!(result, Err(WatchAdminError::NotFound(_))),
        "expected NotFound for unwatched path, got {:?}",
        result
    );
}

// ─── rollup tests ─────────────────────────────────────────────────────────────

#[test]
fn compute_rollup_counts_backed_up_files_correctly() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();

    let prefix = watch_dir.path().to_string_lossy().to_string();

    // 2 backed-up, 1 not.
    db.upsert_file(&make_file_record(
        1,
        &format!("{}/a.txt", prefix),
        10,
        64,
        true,
    ))
    .unwrap();
    db.upsert_file(&make_file_record(
        2,
        &format!("{}/b.txt", prefix),
        10,
        64,
        true,
    ))
    .unwrap();
    db.upsert_file(&make_file_record(
        3,
        &format!("{}/c.txt", prefix),
        10,
        64,
        false,
    ))
    .unwrap();

    let configs = vec![WatchConfig {
        path: prefix,
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    }];
    let (admin, _rx) = make_watch_admin_with_config(config_path, configs, db);
    admin.recompute_all_rollups().unwrap();

    let entries = admin.list_watches();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].total_files, 3);
    assert_eq!(entries[0].backed_up, 2);
}

#[test]
fn compute_rollup_counts_at_risk_when_any_placement_is_uncertain() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();
    let prefix = watch_dir.path().to_string_lossy().to_string();

    let record = make_file_record(1, &format!("{}/a.txt", prefix), 10, 64, true);
    db.upsert_file(&record).unwrap();
    db.upsert_placement(&make_placement(1, 1, PlacementStatus::Uncertain))
        .unwrap();

    let configs = vec![WatchConfig {
        path: prefix,
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    }];
    let (admin, _rx) = make_watch_admin_with_config(config_path, configs, db);
    admin.recompute_all_rollups().unwrap();

    let entries = admin.list_watches();
    assert_eq!(entries[0].at_risk, 1);
    assert_eq!(entries[0].lost, 0);
}

#[test]
fn compute_rollup_counts_lost_when_all_placements_are_lost() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();
    let prefix = watch_dir.path().to_string_lossy().to_string();

    let record = make_file_record(1, &format!("{}/a.txt", prefix), 10, 64, true);
    db.upsert_file(&record).unwrap();
    db.upsert_placement(&make_placement(1, 1, PlacementStatus::Lost))
        .unwrap();
    db.upsert_placement(&make_placement(1, 2, PlacementStatus::Lost))
        .unwrap();

    // Second placement uses a different holder_id so it doesn't overwrite the first.
    // Actually they share the same source_block_id prefix — let me use distinct block IDs.

    let configs = vec![WatchConfig {
        path: prefix,
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    }];
    let (admin, _rx) = make_watch_admin_with_config(config_path, configs, db);
    admin.recompute_all_rollups().unwrap();

    let entries = admin.list_watches();
    assert_eq!(entries[0].lost, 1);
    assert_eq!(entries[0].at_risk, 0);
}

// ─── traffic_light tests ─────────────────────────────────────────────────────

#[test]
fn traffic_light_is_green_when_idle_and_all_backed_up() {
    let rollup = FolderRollup {
        total_files: 5,
        backed_up: 5,
        ..FolderRollup::default()
    };
    assert_eq!(traffic_light(&WatchStatus::Idle, &rollup), "green");
}

#[test]
fn traffic_light_is_yellow_when_working() {
    let rollup = FolderRollup {
        encoding: 2,
        ..FolderRollup::default()
    };
    // derive_status would give Working; pass it directly.
    assert_eq!(traffic_light(&WatchStatus::Working, &rollup), "yellow");
}

#[test]
fn traffic_light_is_yellow_when_at_risk_positive() {
    let rollup = FolderRollup {
        at_risk: 1,
        ..FolderRollup::default()
    };
    assert_eq!(traffic_light(&WatchStatus::Idle, &rollup), "yellow");
}

#[test]
fn traffic_light_is_red_when_lost_positive() {
    let rollup = FolderRollup {
        lost: 1,
        ..FolderRollup::default()
    };
    assert_eq!(traffic_light(&WatchStatus::Idle, &rollup), "red");
}

#[test]
fn traffic_light_is_orange_when_status_is_error() {
    let rollup = FolderRollup::default();
    assert_eq!(traffic_light(&WatchStatus::Error, &rollup), "orange");
}

// ─── save_watches tests ───────────────────────────────────────────────────────

#[test]
fn save_watches_preserves_existing_toml_sections_and_comments() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");

    // Write a config with a network section and a comment.
    std::fs::write(
        &config_path,
        "[network]\nrelay_max_entries = 100\n\n# This is a comment\n",
    )
    .unwrap();

    let watch_dir = TempDir::new().unwrap();
    let configs = vec![WatchConfig {
        path: watch_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    }];

    save_watches(&config_path, &configs).unwrap();

    let written = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        written.contains("relay_max_entries"),
        "network section preserved"
    );
    assert!(written.contains("[[watch]]"), "watch section written");
}

#[test]
fn save_watches_removes_watch_section_when_configs_empty() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");

    std::fs::write(
        &config_path,
        "[[watch]]\npath = \"/tmp/old\"\nimportance = 0.5\n",
    )
    .unwrap();

    save_watches(&config_path, &[]).unwrap();

    let written = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        !written.contains("[[watch]]"),
        "watch section should be removed"
    );
    assert!(!written.contains("/tmp/old"), "old path should be gone");
}

// ─── save_watches writes importance_multiplier key ───────────────────────────

#[test]
fn save_watches_writes_importance_multiplier_key() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();

    let configs = vec![WatchConfig {
        path: watch_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.8,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    }];
    save_watches(&config_path, &configs).unwrap();

    let written = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        written.contains("importance_multiplier"),
        "save_watches must write canonical key, got: {written}"
    );
    assert!(
        !written.contains("was_legacy_importance"),
        "skip field must not be written"
    );

    // Round-trip: load full config from disk → assert no legacy flag fires.
    // Catches regression where save_watches writes the legacy "importance" key.
    let reloaded_app = viaticum_core::config::AppConfig::load(&config_path).unwrap();
    let reloaded = &reloaded_app.watch[0];
    assert!(
        !reloaded.was_legacy_importance,
        "saved config must load without triggering legacy flag"
    );
    assert!(
        (reloaded.importance_multiplier - 0.8).abs() < 1e-9,
        "multiplier should round-trip exactly, got {}",
        reloaded.importance_multiplier
    );
}

// ─── patch_watch preserves classification ────────────────────────────────────

#[tokio::test]
async fn patch_watch_preserves_classification_when_changing_multiplier() {
    use viaticum_core::importance::FolderClassification;

    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();

    let existing = WatchConfig {
        path: watch_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: Some(FolderClassification {
            is_media_folder: true,
            importance_multiplier: 1.0,
        }),
        bursts: None,
    };
    save_watches(&config_path, std::slice::from_ref(&existing)).unwrap();

    let (admin, _rx) = make_watch_admin_with_config(config_path.clone(), vec![existing], db);

    let path_b64 = encode_path_b64(watch_dir.path());
    admin
        .patch_watch(
            &path_b64,
            PatchWatchRequest {
                importance_multiplier: Some(0.9),
                importance_legacy: None,
            },
        )
        .await
        .unwrap();

    let cfgs = admin.live_configs.read().unwrap();
    assert_eq!(cfgs.len(), 1);
    assert!(
        cfgs[0]
            .classification
            .as_ref()
            .map(|c| c.is_media_folder)
            .unwrap_or(false),
        "classification should be preserved after patch"
    );
    assert!(
        (cfgs[0].importance_multiplier - 0.9).abs() < 1e-9,
        "multiplier should be updated"
    );
}

// ─── path encoding tests ─────────────────────────────────────────────────────

#[test]
fn decode_path_b64_round_trips_absolute_path() {
    let path = PathBuf::from("/home/alice/Documents");
    let encoded = encode_path_b64(&path);
    let decoded = decode_path_b64(&encoded).unwrap();
    assert_eq!(decoded, path);
}

#[test]
fn decode_path_b64_round_trips_path_with_spaces() {
    let path = PathBuf::from("/home/alice/My Documents/Photos");
    let encoded = encode_path_b64(&path);
    let decoded = decode_path_b64(&encoded).unwrap();
    assert_eq!(decoded, path);
}

// ─── recompute_all_rollups tests ──────────────────────────────────────────────

#[test]
fn recompute_all_rollups_single_scan_populates_all_watches() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");

    let dir1 = TempDir::new().unwrap();
    let dir2 = TempDir::new().unwrap();

    db.upsert_file(&make_file_record(
        1,
        &format!("{}/a.txt", dir1.path().display()),
        10,
        64,
        true,
    ))
    .unwrap();
    db.upsert_file(&make_file_record(
        2,
        &format!("{}/b.txt", dir2.path().display()),
        10,
        64,
        false,
    ))
    .unwrap();

    let configs = vec![
        WatchConfig {
            path: dir1.path().to_string_lossy().into_owned(),
            importance_multiplier: 0.5,
            was_legacy_importance: false,
            classification: None,
            bursts: None,
        },
        WatchConfig {
            path: dir2.path().to_string_lossy().into_owned(),
            importance_multiplier: 0.5,
            was_legacy_importance: false,
            classification: None,
            bursts: None,
        },
    ];
    let (admin, _rx) = make_watch_admin_with_config(config_path, configs, db);
    admin.recompute_all_rollups().unwrap();

    let entries = admin.list_watches();
    assert_eq!(entries.len(), 2);

    let e1 = entries
        .iter()
        .find(|e| e.path.contains(dir1.path().to_str().unwrap()))
        .unwrap();
    let e2 = entries
        .iter()
        .find(|e| e.path.contains(dir2.path().to_str().unwrap()))
        .unwrap();
    assert_eq!(e1.total_files, 1);
    assert_eq!(e1.backed_up, 1);
    assert_eq!(e2.total_files, 1);
    assert_eq!(e2.backed_up, 0);
}

#[test]
fn get_watches_reads_cached_rollup_without_db_scan() {
    // This test verifies that list_watches reads from cached_rollups, not from DB.
    // We manually inject a CachedRollup and verify it's returned.
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();

    let configs = vec![WatchConfig {
        path: watch_dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    }];
    let (admin, _rx) = make_watch_admin_with_config(config_path, configs, db);

    // Manually inject a rollup with non-default values.
    {
        let mut cache = admin.cached_rollups.write().unwrap();
        cache.insert(
            watch_dir.path().to_path_buf(),
            CachedRollup {
                rollup: FolderRollup {
                    total_files: 42,
                    backed_up: 40,
                    at_risk: 1,
                    lost: 1,
                    encoding: 0,
                    queued: 0,
                    total_bytes: 1000,
                },
                computed_at: std::time::Instant::now(),
            },
        );
    }

    let entries = admin.list_watches();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].total_files, 42,
        "should read from cached_rollups"
    );
    assert_eq!(entries[0].backed_up, 40);
    assert_eq!(entries[0].at_risk, 1);
    assert_eq!(entries[0].lost, 1);
}

#[test]
fn post_refresh_triggers_recompute_and_updates_computed_at() {
    let tmp = TempDir::new().unwrap();
    let db = test_db();
    let config_path = tmp.path().join("config.toml");
    let watch_dir = TempDir::new().unwrap();
    let prefix = watch_dir.path().to_string_lossy().to_string();

    db.upsert_file(&make_file_record(
        1,
        &format!("{}/a.txt", prefix),
        10,
        64,
        true,
    ))
    .unwrap();

    let configs = vec![WatchConfig {
        path: prefix,
        importance_multiplier: 0.5,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    }];
    let (admin, _rx) = make_watch_admin_with_config(config_path, configs, db);

    // First recompute.
    admin.recompute_all_rollups().unwrap();
    let age1 = {
        let cache = admin.cached_rollups.read().unwrap();
        cache[watch_dir.path()].computed_at
    };

    // Small sleep so computed_at changes.
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Second recompute (simulates POST /api/watches/refresh).
    admin.recompute_all_rollups().unwrap();
    let age2 = {
        let cache = admin.cached_rollups.read().unwrap();
        cache[watch_dir.path()].computed_at
    };

    assert!(age2 > age1, "computed_at should be updated after refresh");
}

// ─── derive_status tests ─────────────────────────────────────────────────────

#[test]
fn derive_status_returns_working_when_signal_idle_and_encoding_positive() {
    let rollup = FolderRollup {
        encoding: 3,
        ..FolderRollup::default()
    };
    assert_eq!(
        derive_status(&WatcherStatusSignal::Idle, &rollup),
        WatchStatus::Working
    );
}

#[test]
fn derive_status_returns_idle_when_signal_idle_and_no_encoding() {
    let rollup = FolderRollup::default();
    assert_eq!(
        derive_status(&WatcherStatusSignal::Idle, &rollup),
        WatchStatus::Idle
    );
}

#[test]
fn derive_status_returns_error_regardless_of_rollup_when_signal_error() {
    let rollup = FolderRollup {
        encoding: 5,
        ..FolderRollup::default()
    };
    assert_eq!(
        derive_status(&WatcherStatusSignal::Error, &rollup),
        WatchStatus::Error
    );
}

// ─── Wave 12: WatchEntry rename / alias tests ─────────────────────────────────

#[test]
fn watch_entry_json_key_is_importance_multiplier() {
    use super::WatchEntry;
    let entry = WatchEntry {
        path: "/tmp/test".to_string(),
        importance: 1.5,
        status: WatchStatus::Idle,
        error: None,
        last_event_age_secs: None,
        total_files: 0,
        total_bytes: 0,
        backed_up: 0,
        at_risk: 0,
        lost: 0,
        encoding: 0,
        queued: 0,
        rollup_age_secs: None,
        traffic_light: "green".to_string(),
    };
    let json = serde_json::to_value(&entry).unwrap();
    assert_eq!(
        json["importance_multiplier"], 1.5,
        "must serialize as importance_multiplier"
    );
    assert!(
        json.get("importance").is_none(),
        "legacy 'importance' key must not appear in output"
    );
}

#[test]
fn add_watch_request_accepts_legacy_importance_key() {
    let json = r#"{"path": "/tmp", "importance": 0.7}"#;
    let req: AddWatchRequest = serde_json::from_str(json).unwrap();
    assert!(
        (req.resolved_multiplier() - 0.7).abs() < 1e-9,
        "legacy key must be accepted, got {}",
        req.resolved_multiplier()
    );
}

#[test]
fn add_watch_request_accepts_importance_multiplier_key() {
    let json = r#"{"path": "/tmp", "importance_multiplier": 1.2}"#;
    let req: AddWatchRequest = serde_json::from_str(json).unwrap();
    assert!(
        (req.resolved_multiplier() - 1.2).abs() < 1e-9,
        "canonical key must be accepted, got {}",
        req.resolved_multiplier()
    );
}

#[test]
fn add_watch_request_importance_multiplier_wins_over_legacy() {
    let json = r#"{"path": "/tmp", "importance": 0.5, "importance_multiplier": 1.8}"#;
    let req: AddWatchRequest = serde_json::from_str(json).unwrap();
    assert!(
        (req.resolved_multiplier() - 1.8).abs() < 1e-9,
        "canonical key must win over legacy, got {}",
        req.resolved_multiplier()
    );
}

#[test]
fn patch_watch_request_accepts_legacy_importance_key() {
    let json = r#"{"importance": 0.9}"#;
    let req: PatchWatchRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.resolved_multiplier(), Some(0.9));
}

#[test]
fn patch_watch_request_accepts_importance_multiplier_key() {
    let json = r#"{"importance_multiplier": 0.9}"#;
    let req: PatchWatchRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.resolved_multiplier(), Some(0.9));
}

#[test]
fn watch_defaults_json_key_is_importance_multiplier() {
    use super::WatchDefaults;
    let defaults = WatchDefaults {
        importance_multiplier: DEFAULT_IMPORTANCE_MULTIPLIER,
    };
    let json = serde_json::to_value(&defaults).unwrap();
    assert!(
        json.get("importance_multiplier").is_some(),
        "must serialize as importance_multiplier"
    );
    assert!(
        json.get("importance").is_none(),
        "legacy 'importance' must not appear in output"
    );
}

// ─── backup-i13: Viaticum's own storage is never a watch folder ──────────────

/// A fake data dir: both marker files, as the daemon leaves them after its first start.
fn fake_data_dir(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(crate::daemon::identity::KEYFILE_NAME), b"key").unwrap();
    std::fs::write(dir.join(crate::daemon::identity::DB_FILE_NAME), b"db").unwrap();
}

#[tokio::test]
async fn add_watch_rejects_viaticum_data_dir() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().join("vdata");
    fake_data_dir(&data_dir);
    let (admin, mut rx) =
        make_watch_admin_with_config(tmp.path().join("config.toml"), vec![], test_db());

    let result = admin
        .add_watch(AddWatchRequest {
            path: data_dir.to_string_lossy().into_owned(),
            importance_multiplier: None,
            importance_legacy: None,
        })
        .await;

    match result {
        Err(e @ WatchAdminError::DaemonStorage { .. }) => {
            assert!(
                e.to_string().contains("Viaticum data directory"),
                "reason names the data directory: {e}"
            );
        }
        other => panic!("expected DaemonStorage, got {other:?}"),
    }
    assert!(admin.list_watches().is_empty(), "nothing was added");
    assert!(
        rx.try_recv().is_err(),
        "the watcher was not told to watch it"
    );
}

#[tokio::test]
async fn add_watch_rejects_folder_inside_holdings() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().join("vdata");
    fake_data_dir(&data_dir);
    let inside = data_dir.join(crate::daemon::identity::HOLDINGS_DIR_NAME);
    std::fs::create_dir_all(&inside).unwrap();
    let (admin, _rx) =
        make_watch_admin_with_config(tmp.path().join("config.toml"), vec![], test_db());

    let result = admin
        .add_watch(AddWatchRequest {
            path: inside.to_string_lossy().into_owned(),
            importance_multiplier: None,
            importance_legacy: None,
        })
        .await;

    match result {
        Err(e @ WatchAdminError::DaemonStorage { .. }) => {
            assert!(e.to_string().contains("own storage"), "{e}");
        }
        other => panic!("expected DaemonStorage, got {other:?}"),
    }
}

#[tokio::test]
async fn add_watch_allows_user_folder_inside_data_dir() {
    // Every E2E watches `<data-dir>/files`: a folder in a data dir but outside
    // holdings/symbols/restore/system_state is a normal folder.
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().join("vdata");
    fake_data_dir(&data_dir);
    let files = data_dir.join("files");
    std::fs::create_dir_all(&files).unwrap();
    let (admin, _rx) =
        make_watch_admin_with_config(tmp.path().join("config.toml"), vec![], test_db());

    let result = admin
        .add_watch(AddWatchRequest {
            path: files.to_string_lossy().into_owned(),
            importance_multiplier: None,
            importance_legacy: None,
        })
        .await;

    assert!(result.is_ok(), "expected Ok, got {result:?}");
}
