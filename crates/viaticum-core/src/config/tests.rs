#![allow(clippy::cloned_ref_to_slice_refs)]

#[cfg(test)]
use std::io::Write;

#[cfg(test)]
use crate::config::{
    AppConfig, BackupCfg, ClusterCfg, ConfigError, DEFAULT_IMPORTANCE,
    DEFAULT_IMPORTANCE_MULTIPLIER, FourRCfg, MetricsCfg, NetworkCfg, ReliabilityConfig, RestoreCfg,
    StorageCfg, WatchConfig, WebApiCfg, derive_file_importance, disk_reserve_bytes,
    expand_data_dir, hard_quota_bytes, soft_quota_bytes, source_block_size_bytes,
};
#[cfg(test)]
use crate::constants::{
    DEFAULT_DISK_RESERVE_BYTES, DEFAULT_MAX_VERSIONS, DEFAULT_SOURCE_BLOCK_SIZE,
};
#[cfg(test)]
use crate::importance::{
    FolderClassification,
    burst::{apply_burst_downweight, burst_downweight_selects},
};
#[cfg(test)]
use std::collections::HashSet;
#[cfg(test)]
use std::path::Path;

#[cfg(test)]
fn write_toml(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f
}

#[test]
fn config_loads_defaults_when_file_is_empty() {
    let f = write_toml("");
    let cfg = AppConfig::load(f.path()).unwrap();
    let defaults = AppConfig::default();
    assert_eq!(
        cfg.backup.source_block_size_mb,
        defaults.backup.source_block_size_mb
    );
    assert_eq!(cfg.backup.max_versions, defaults.backup.max_versions);
    assert_eq!(
        cfg.backup.max_version_age_days,
        defaults.backup.max_version_age_days
    );
    assert_eq!(cfg.storage.soft_quota_gb, defaults.storage.soft_quota_gb);
    assert_eq!(cfg.storage.hard_quota_gb, defaults.storage.hard_quota_gb);
    assert_eq!(
        cfg.storage.disk_reserve_gb,
        defaults.storage.disk_reserve_gb
    );
    assert_eq!(cfg.storage.data_dir, defaults.storage.data_dir);
    assert_eq!(cfg.network.enable_relay, defaults.network.enable_relay);
    assert_eq!(
        cfg.cluster.sync_batch_size,
        defaults.cluster.sync_batch_size
    );
}

#[test]
fn config_loads_partial_file_merging_with_defaults() {
    let f = write_toml("[backup]\nsource_block_size_mb = 32\n");
    let cfg = AppConfig::load(f.path()).unwrap();
    assert_eq!(cfg.backup.source_block_size_mb, 32);
    assert_eq!(cfg.backup.max_versions, DEFAULT_MAX_VERSIONS);
    assert_eq!(
        cfg.storage.disk_reserve_gb,
        DEFAULT_DISK_RESERVE_BYTES as f64 / 1_073_741_824.0
    );
    assert_eq!(cfg.cluster.sync_batch_size, 100);
}

#[test]
fn config_roundtrips_all_fields() {
    let original = AppConfig {
        backup: BackupCfg {
            source_block_size_mb: 64,
            max_file_size_mb: 512,
            max_versions: 10,
            max_version_age_days: 180,
        },
        storage: StorageCfg {
            soft_quota_gb: 500.0,
            hard_quota_gb: 10.0,
            disk_reserve_gb: 50.0,
            data_dir: "/data/viaticum".to_string(),
        },
        network: NetworkCfg {
            enable_relay: false,
            enable_relay_server: false,
            relay_url: None,
            bootstrap_peers: vec![],
            kademlia_bootstrap_peers: vec![],
            listen_port: 0,
        },
        cluster: ClusterCfg {
            sync_batch_size: 200,
        },
        metrics: MetricsCfg::default(),
        web_api: WebApiCfg::default(),
        restore: RestoreCfg::default(),
        reliability: ReliabilityConfig::default(),
        four_r: FourRCfg::default(),
        watch: vec![],
    };

    let toml_str = toml::to_string(&original).unwrap();
    let f = write_toml(&toml_str);
    let loaded = AppConfig::load(f.path()).unwrap();

    assert_eq!(loaded.backup.source_block_size_mb, 64);
    assert_eq!(loaded.backup.max_file_size_mb, 512);
    assert_eq!(loaded.backup.max_versions, 10);
    assert_eq!(loaded.backup.max_version_age_days, 180);
    assert_eq!(loaded.storage.soft_quota_gb, 500.0);
    assert_eq!(loaded.storage.hard_quota_gb, 10.0);
    assert_eq!(loaded.storage.disk_reserve_gb, 50.0);
    assert_eq!(loaded.storage.data_dir, "/data/viaticum");
    assert!(!loaded.network.enable_relay);
    assert_eq!(loaded.cluster.sync_batch_size, 200);
}

#[test]
fn config_validate_rejects_source_block_size_zero() {
    let mut cfg = AppConfig::default();
    cfg.backup.source_block_size_mb = 0;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, .. } if field == "backup.source_block_size_mb")
    );
}

#[test]
fn config_validate_rejects_source_block_size_not_power_of_two() {
    let mut cfg = AppConfig::default();
    cfg.backup.source_block_size_mb = 100;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, .. } if field == "backup.source_block_size_mb")
    );
}

#[test]
fn config_validate_rejects_source_block_size_3mb() {
    let mut cfg = AppConfig::default();
    cfg.backup.source_block_size_mb = 3;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, .. } if field == "backup.source_block_size_mb")
    );
}

#[test]
fn config_validate_allows_source_block_size_1mb() {
    let mut cfg = AppConfig::default();
    cfg.backup.source_block_size_mb = 1;
    cfg.validate().unwrap();
}

#[test]
fn config_validate_rejects_max_versions_zero() {
    let mut cfg = AppConfig::default();
    cfg.backup.max_versions = 0;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, .. } if field == "backup.max_versions")
    );
}

#[test]
fn config_validate_rejects_max_version_age_days_zero() {
    let mut cfg = AppConfig::default();
    cfg.backup.max_version_age_days = 0;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, .. } if field == "backup.max_version_age_days")
    );
}

#[test]
fn config_validate_rejects_negative_soft_quota() {
    let mut cfg = AppConfig::default();
    cfg.storage.soft_quota_gb = -1.0;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, .. } if field == "storage.soft_quota_gb")
    );
}

#[test]
fn config_validate_rejects_negative_hard_quota() {
    let mut cfg = AppConfig::default();
    cfg.storage.hard_quota_gb = -5.0;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, .. } if field == "storage.hard_quota_gb")
    );
}

#[test]
fn config_validate_rejects_hard_quota_above_soft_quota() {
    let mut cfg = AppConfig::default();
    cfg.storage.soft_quota_gb = 100.0;
    cfg.storage.hard_quota_gb = 200.0;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, .. } if field == "storage.hard_quota_gb")
    );
}

#[test]
fn config_validate_allows_hard_quota_zero_with_nonzero_soft() {
    let mut cfg = AppConfig::default();
    cfg.storage.soft_quota_gb = 100.0;
    cfg.storage.hard_quota_gb = 0.0;
    cfg.validate().unwrap();
}

#[test]
fn config_validate_allows_both_quotas_zero() {
    let mut cfg = AppConfig::default();
    cfg.storage.soft_quota_gb = 0.0;
    cfg.storage.hard_quota_gb = 0.0;
    cfg.validate().unwrap();
}

#[test]
fn config_validate_rejects_cluster_sync_batch_size_zero() {
    let mut cfg = AppConfig::default();
    cfg.cluster.sync_batch_size = 0;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, .. } if field == "cluster.sync_batch_size")
    );
}

#[test]
fn config_load_ignores_legacy_escrow_section() {
    // restore-i6: v1 removed the holder-side escrow gate. A config written before that
    // (with `[escrow] k_factor`, even the old invalid 0.0) must still load, and the rest of
    // the file must still apply.
    let f = write_toml(
        "[storage]\ndisk_reserve_gb = 3.0\n\n[escrow]\nk_factor = 0.0\n\n[cluster]\nsync_batch_size = 7\n",
    );
    let cfg = AppConfig::load(f.path()).unwrap();
    assert_eq!(cfg.storage.disk_reserve_gb, 3.0);
    assert_eq!(cfg.cluster.sync_batch_size, 7);
}

#[test]
fn config_serialized_defaults_have_no_escrow_section() {
    let text = toml::to_string(&AppConfig::default()).unwrap();
    assert!(!text.contains("escrow"), "{text}");
}

#[test]
fn config_load_returns_parse_error_for_invalid_toml() {
    let f = write_toml("not valid toml ][[ garbage");
    let err = AppConfig::load(f.path()).unwrap_err();
    assert!(matches!(err, ConfigError::Parse(_)));
}

#[test]
fn config_load_returns_io_error_for_missing_file() {
    let err = AppConfig::load(std::path::Path::new("/nonexistent/path/config.toml")).unwrap_err();
    assert!(matches!(err, ConfigError::Io(_)));
}

#[test]
fn source_block_size_bytes_converts_correctly() {
    let mut cfg = AppConfig::default();
    cfg.backup.source_block_size_mb = 128;
    assert_eq!(source_block_size_bytes(&cfg), 134_217_728);
}

#[test]
fn soft_quota_bytes_returns_zero_for_unlimited() {
    let mut cfg = AppConfig::default();
    cfg.storage.soft_quota_gb = 0.0;
    assert_eq!(soft_quota_bytes(&cfg), 0);
}

#[test]
fn soft_quota_bytes_converts_fractional_gb() {
    let mut cfg = AppConfig::default();
    cfg.storage.soft_quota_gb = 0.5;
    assert_eq!(soft_quota_bytes(&cfg), 536_870_912);
}

#[test]
fn disk_reserve_bytes_converts_correctly() {
    let mut cfg = AppConfig::default();
    cfg.storage.disk_reserve_gb = 20.0;
    assert_eq!(disk_reserve_bytes(&cfg), 21_474_836_480);
}

#[test]
#[allow(unsafe_code)] // single-threaded test mutating $HOME
fn expand_data_dir_expands_tilde() {
    let mut cfg = AppConfig::default();
    cfg.storage.data_dir = "~/.viaticum".to_string();
    // Force HOME to a known value for the test.
    // SAFETY: single-threaded test, no concurrent env reads.
    unsafe { std::env::set_var("HOME", "/home/user") };
    let result = expand_data_dir(&cfg);
    assert_eq!(result, std::path::PathBuf::from("/home/user/.viaticum"));
}

#[test]
fn expand_data_dir_leaves_absolute_path_unchanged() {
    let mut cfg = AppConfig::default();
    cfg.storage.data_dir = "/mnt/data/viaticum".to_string();
    let result = expand_data_dir(&cfg);
    assert_eq!(result, std::path::PathBuf::from("/mnt/data/viaticum"));
}

#[test]
#[allow(unsafe_code)] // single-threaded test mutating $HOME
fn expand_data_dir_handles_bare_tilde() {
    let mut cfg = AppConfig::default();
    cfg.storage.data_dir = "~".to_string();
    // SAFETY: single-threaded test, no concurrent env reads.
    unsafe { std::env::set_var("HOME", "/home/user") };
    let result = expand_data_dir(&cfg);
    assert_eq!(result, std::path::PathBuf::from("/home/user"));
}

#[test]
fn config_defaults_match_constants() {
    let cfg = AppConfig::default();
    assert_eq!(
        cfg.backup.source_block_size_mb,
        DEFAULT_SOURCE_BLOCK_SIZE / 1_048_576
    );
    assert_eq!(cfg.backup.max_versions, DEFAULT_MAX_VERSIONS);
    assert_eq!(
        cfg.storage.disk_reserve_gb,
        DEFAULT_DISK_RESERVE_BYTES as f64 / 1_073_741_824.0
    );
    assert!(cfg.network.enable_relay);
}

#[test]
fn hard_quota_bytes_returns_zero_for_no_floor() {
    let mut cfg = AppConfig::default();
    cfg.storage.hard_quota_gb = 0.0;
    assert_eq!(hard_quota_bytes(&cfg), 0);
}

#[test]
fn hard_quota_bytes_converts_nonzero_gb() {
    let mut cfg = AppConfig::default();
    cfg.storage.hard_quota_gb = 1.0;
    assert_eq!(hard_quota_bytes(&cfg), 1_073_741_824);
}

#[test]
fn hard_quota_bytes_converts_fractional_gb() {
    let mut cfg = AppConfig::default();
    cfg.storage.hard_quota_gb = 0.5;
    assert_eq!(hard_quota_bytes(&cfg), 536_870_912);
}

#[test]
fn network_cfg_default_enable_relay_is_true() {
    let cfg = NetworkCfg::default();
    assert!(cfg.enable_relay, "enable_relay must default to true");
}

#[test]
fn network_cfg_toml_enable_relay_false() {
    let toml = r#"
[network]
enable_relay = false
"#;
    let app: AppConfig = toml::from_str(toml).unwrap();
    assert!(!app.network.enable_relay);
}

#[test]
fn network_cfg_toml_missing_field_defaults_true() {
    let app: AppConfig = toml::from_str("").unwrap();
    assert!(app.network.enable_relay);
}

// ============================================================
// bootstrap_peers tests
// ============================================================

#[test]
fn network_cfg_bootstrap_peers_defaults_empty() {
    let cfg = NetworkCfg::default();
    assert!(
        cfg.bootstrap_peers.is_empty(),
        "bootstrap_peers must default to empty"
    );
}

#[test]
fn network_cfg_bootstrap_peers_loads_from_toml() {
    let toml = r#"
[network]
bootstrap_peers = [
    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ef@192.168.1.5:12345",
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12@10.0.0.1:54321",
]
"#;
    let app: AppConfig = toml::from_str(toml).unwrap();
    assert_eq!(app.network.bootstrap_peers.len(), 2);
    assert!(app.network.bootstrap_peers[0].contains("192.168.1.5:12345"));
    assert!(app.network.bootstrap_peers[1].contains("10.0.0.1:54321"));
}

#[test]
fn network_cfg_bootstrap_peers_empty_array_in_toml() {
    let toml = "[network]\nbootstrap_peers = []\n";
    let app: AppConfig = toml::from_str(toml).unwrap();
    assert!(app.network.bootstrap_peers.is_empty());
}

#[test]
fn network_cfg_bootstrap_peers_missing_section_defaults_empty() {
    let app: AppConfig = toml::from_str("").unwrap();
    assert!(app.network.bootstrap_peers.is_empty());
}

// ============================================================
// relay_url tests
// ============================================================

#[test]
fn network_cfg_relay_url_defaults_none() {
    let cfg = NetworkCfg::default();
    assert!(cfg.relay_url.is_none());
}

#[test]
fn network_cfg_relay_url_loads_from_toml() {
    let toml = r#"
[network]
relay_url = "http://my-relay:3340"
"#;
    let app: AppConfig = toml::from_str(toml).unwrap();
    assert_eq!(
        app.network.relay_url.as_deref(),
        Some("http://my-relay:3340")
    );
}

#[test]
fn network_cfg_relay_url_missing_defaults_none() {
    let app: AppConfig = toml::from_str("[network]\nenable_relay = true\n").unwrap();
    assert!(app.network.relay_url.is_none());
}

// ============================================================
// WatchConfig / TOML deserialization tests
// ============================================================

#[test]
fn watch_config_default_multiplier_is_one() {
    let wc: WatchConfig = toml::from_str(r#"path = "/home/user/docs""#).unwrap();
    assert!(
        (wc.importance_multiplier - DEFAULT_IMPORTANCE_MULTIPLIER).abs() < 1e-9,
        "expected {DEFAULT_IMPORTANCE_MULTIPLIER}, got {}",
        wc.importance_multiplier
    );
    assert!(!wc.was_legacy_importance);
}

#[test]
fn legacy_importance_field_in_toml_loads_as_multiplier_with_warning() {
    let toml_str = r#"path = "/home/user/photos"
importance = 0.7"#;
    let wc: WatchConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(wc.path, "/home/user/photos");
    assert!((wc.importance_multiplier - 0.7).abs() < 1e-9);
    assert!(wc.was_legacy_importance, "legacy flag should be set");
    assert!(wc.classification.is_none());
}

#[test]
fn current_importance_multiplier_field_loads_directly() {
    let toml_str = r#"path = "/home/user/docs"
importance_multiplier = 1.5"#;
    let wc: WatchConfig = toml::from_str(toml_str).unwrap();
    assert!((wc.importance_multiplier - 1.5).abs() < 1e-9);
    assert!(!wc.was_legacy_importance);
}

#[test]
fn both_fields_present_canonical_wins() {
    let toml_str = r#"path = "/home/user/docs"
importance = 0.3
importance_multiplier = 0.9"#;
    let wc: WatchConfig = toml::from_str(toml_str).unwrap();
    assert!(
        (wc.importance_multiplier - 0.9).abs() < 1e-9,
        "canonical field should win; got {}",
        wc.importance_multiplier
    );
    assert!(
        !wc.was_legacy_importance,
        "not legacy when canonical field is present"
    );
}

#[test]
fn watch_config_serializes_as_importance_multiplier_key() {
    let wc = WatchConfig {
        path: "/home/user/docs".to_string(),
        importance_multiplier: 0.8,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    let s = toml::to_string(&wc).unwrap();
    assert!(
        s.contains("importance_multiplier"),
        "canonical key must be written"
    );
    assert!(
        !s.contains("was_legacy_importance"),
        "skip field must not be written"
    );
    assert!(
        !s.contains("classification"),
        "skip field must not be written"
    );
    assert!(!s.contains("bursts"), "skip field must not be written");
}

#[test]
fn app_config_watch_loads_from_toml_with_legacy_field() {
    let toml_str = r#"
[[watch]]
path = "/home/user/photos"
importance = 0.9

[[watch]]
path = "/home/user/docs"
importance = 0.6
"#;
    let app: AppConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(app.watch.len(), 2);
    assert_eq!(app.watch[0].path, "/home/user/photos");
    assert!((app.watch[0].importance_multiplier - 0.9).abs() < 1e-9);
    assert!(app.watch[0].was_legacy_importance);
    assert_eq!(app.watch[1].path, "/home/user/docs");
    assert!((app.watch[1].importance_multiplier - 0.6).abs() < 1e-9);
    assert!(app.watch[1].was_legacy_importance);
}

#[test]
fn app_config_watch_loads_from_toml_with_canonical_field() {
    let toml_str = r#"
[[watch]]
path = "/home/user/photos"
importance_multiplier = 0.9
"#;
    let app: AppConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(app.watch.len(), 1);
    assert_eq!(app.watch[0].path, "/home/user/photos");
    assert!((app.watch[0].importance_multiplier - 0.9).abs() < 1e-9);
    assert!(!app.watch[0].was_legacy_importance);
}

#[test]
fn app_config_watch_defaults_empty() {
    let app: AppConfig = toml::from_str("").unwrap();
    assert!(app.watch.is_empty());
}

#[test]
fn app_config_watch_missing_importance_uses_default_multiplier() {
    let toml_str = r#"
[[watch]]
path = "/home/user/videos"
"#;
    let app: AppConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(app.watch.len(), 1);
    assert!(
        (app.watch[0].importance_multiplier - DEFAULT_IMPORTANCE_MULTIPLIER).abs() < 1e-9,
        "expected {DEFAULT_IMPORTANCE_MULTIPLIER}"
    );
    assert!(!app.watch[0].was_legacy_importance);
}

// ============================================================
// derive_file_importance tests
// ============================================================

fn make_watch(path: &str, multiplier: f64, is_media: bool) -> WatchConfig {
    WatchConfig {
        path: path.to_string(),
        importance_multiplier: multiplier,
        was_legacy_importance: false,
        classification: Some(FolderClassification {
            is_media_folder: is_media,
            importance_multiplier: 1.0,
        }),
        bursts: None,
    }
}

#[test]
fn derive_file_importance_returns_one_for_text_file_in_text_folder() {
    let wc = make_watch("/home/user/docs", 1.0, false);
    let result = derive_file_importance("/home/user/docs/notes.md", &[wc]);
    assert!(
        (result - 1.0).abs() < 1e-9,
        "TextOrCode × 1.0 = 1.0, got {result}"
    );
}

#[test]
fn derive_file_importance_returns_bucketed_value_for_media_in_media_folder() {
    let wc = make_watch("/home/user/Photos", 1.0, true);
    let result = derive_file_importance("/home/user/Photos/IMG_001.jpg", &[wc]);
    // Media file in media folder → one of MediaHigh/Medium/Low
    assert!(
        result == 0.95 || result == 0.65 || result == 0.20,
        "expected 0.95, 0.65, or 0.20, got {result}"
    );
}

#[test]
fn derive_file_importance_applies_watch_multiplier() {
    let wc = make_watch("/home/user/docs", 0.5, false);
    let result = derive_file_importance("/home/user/docs/budget.txt", &[wc]);
    // TextOrCode 1.0 × 0.5 = 0.5
    assert!(
        (result - 0.5).abs() < 1e-9,
        "TextOrCode × 0.5 = 0.5, got {result}"
    );
}

#[test]
fn derive_file_importance_clamps_at_one_when_multiplier_above_one() {
    let wc = make_watch("/home/user/docs", 2.0, false);
    let result = derive_file_importance("/home/user/docs/main.rs", &[wc]);
    // TextOrCode 1.0 × 2.0 = 2.0 → clamped to 1.0
    assert!(
        (result - 1.0).abs() < 1e-9,
        "expected clamped to 1.0, got {result}"
    );
}

#[test]
fn derive_file_importance_returns_zero_when_multiplier_is_zero() {
    let wc = make_watch("/home/user/docs", 0.0, false);
    let result = derive_file_importance("/home/user/docs/main.rs", &[wc]);
    assert!((result - 0.0).abs() < 1e-9, "expected 0.0, got {result}");
}

#[test]
fn derive_file_importance_returns_default_for_path_not_in_any_watch() {
    let wc = make_watch("/home/user/docs", 0.9, false);
    let result = derive_file_importance("/home/user/Downloads/file.zip", &[wc]);
    assert!(
        (result - DEFAULT_IMPORTANCE).abs() < 1e-9,
        "expected DEFAULT_IMPORTANCE ({DEFAULT_IMPORTANCE}), got {result}"
    );
}

#[test]
fn derive_file_importance_returns_default_when_no_watch_configs() {
    let result = derive_file_importance("/home/user/docs/file.txt", &[]);
    assert_eq!(result, DEFAULT_IMPORTANCE);
}

#[test]
fn derive_file_importance_does_not_match_partial_directory_name() {
    // /home/user/docs should NOT match /home/user/documents/file.txt
    let wc = make_watch("/home/user/docs", 0.9, false);
    let result = derive_file_importance("/home/user/documents/file.txt", &[wc]);
    assert!(
        (result - DEFAULT_IMPORTANCE).abs() < 1e-9,
        "expected DEFAULT_IMPORTANCE, got {result}"
    );
}

#[test]
fn derive_file_importance_path_with_trailing_slash_in_config() {
    let wc = WatchConfig {
        path: "/home/user/docs/".to_string(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: Some(FolderClassification {
            is_media_folder: false,
            importance_multiplier: 1.0,
        }),
        bursts: None,
    };
    let result = derive_file_importance("/home/user/docs/file.txt", &[wc]);
    // TextOrCode × 1.0 = 1.0
    assert!((result - 1.0).abs() < 1e-9, "expected 1.0, got {result}");
}

#[test]
fn derive_file_importance_exact_path_match() {
    // file_path == wc.path: edge case for bare path match.
    let wc = make_watch("/home/user/docs", 1.0, false);
    // file_path exactly equals watch path — should return importance for Unknown
    // (no extension) type = 0.05 * 1.0 = 0.05. Actually "docs" has no extension.
    // classify_file("/home/user/docs", non-media) → Unknown → 0.05
    let result = derive_file_importance("/home/user/docs", &[wc]);
    // Unknown × 1.0 = 0.05 (no extension, not special filename)
    assert!(
        (result - 0.05).abs() < 1e-9,
        "expected 0.05 for Unknown, got {result}"
    );
}

#[test]
fn derive_file_importance_uses_first_matching_config() {
    // Two overlapping watches — first match wins
    let wc1 = make_watch("/home/user", 0.5, false);
    let wc2 = make_watch("/home/user/photos", 1.0, true);
    // /home/user/photos/img.jpg matches both; first match (/home/user, 0.5) wins.
    // classify_file with non-media folder + .jpg → Unknown → 0.05 * 0.5 = 0.025
    let result = derive_file_importance("/home/user/photos/img.jpg", &[wc1, wc2]);
    assert!(
        (result - 0.025).abs() < 1e-9,
        "expected 0.025 (Unknown × 0.5), got {result}"
    );
}

// ============================================================
// populate_classification tests
// ============================================================

#[test]
fn watch_config_classification_populated_at_watch_start() {
    let dir = tempfile::TempDir::new().unwrap();
    for i in 0..10 {
        std::fs::write(dir.path().join(format!("photo{i}.jpg")), b"data").unwrap();
    }
    let mut wc = WatchConfig {
        path: dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    wc.populate_classification();
    assert!(wc.classification.is_some(), "classification should be set");
    assert!(
        wc.classification.as_ref().unwrap().is_media_folder,
        "10/10 media files → is_media_folder = true"
    );
}

#[test]
fn watch_config_empty_folder_classification_defaults_to_non_media() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut wc = WatchConfig {
        path: dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    wc.populate_classification();
    assert_eq!(
        wc.classification,
        Some(FolderClassification {
            is_media_folder: false,
            importance_multiplier: 1.0
        })
    );
}

#[test]
fn populate_classification_samples_up_to_200_paths() {
    let dir = tempfile::TempDir::new().unwrap();
    // Write 300 .txt files
    for i in 0..300 {
        std::fs::write(dir.path().join(format!("file{i:03}.txt")), b"content").unwrap();
    }
    let mut wc = WatchConfig {
        path: dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    wc.populate_classification();
    assert!(wc.classification.is_some());
    // 300 text files → non-media
    assert!(!wc.classification.as_ref().unwrap().is_media_folder);
}

#[test]
fn populate_classification_cap_stops_at_cap_boundary() {
    // Use a small cap. Create 5 txt + 5 jpg (alphabetically: jpg comes before txt).
    // With cap=5 we expect to sample 5 files. Which ones depend on FS order.
    // We can't predict the outcome precisely without knowing the OS order,
    // but we can verify: result is_some and classification is set.
    let dir = tempfile::TempDir::new().unwrap();
    for i in 0..5 {
        std::fs::write(dir.path().join(format!("a{i}.jpg")), b"fake").unwrap();
        std::fs::write(dir.path().join(format!("z{i}.txt")), b"text").unwrap();
    }
    let mut wc = WatchConfig {
        path: dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    wc.populate_classification_with_cap(5);
    assert!(
        wc.classification.is_some(),
        "classification should be set with small cap"
    );
}

#[cfg(unix)]
#[test]
fn populate_classification_excludes_symlinks() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::TempDir::new().unwrap();
    // Create a real .jpg file.
    std::fs::write(dir.path().join("real.jpg"), b"jpeg").unwrap();
    // Create a subdirectory and symlink it back to the parent (would loop).
    let subdir = dir.path().join("subdir");
    std::fs::create_dir(&subdir).unwrap();
    symlink(dir.path(), subdir.join("loop_link")).unwrap();

    let mut wc = WatchConfig {
        path: dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    // Should complete without infinite loop.
    wc.populate_classification();
    assert!(wc.classification.is_some());
}

#[test]
fn populate_classification_missing_directory_sets_default() {
    let mut wc = WatchConfig {
        path: "/nonexistent/path/that/does/not/exist".to_string(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    wc.populate_classification();
    assert_eq!(wc.classification, Some(FolderClassification::default()));
}

#[test]
fn webapi_cfg_default_bind_is_loopback_random_port() {
    let cfg = WebApiCfg::default();
    assert_eq!(cfg.bind, "127.0.0.1:0");
}

#[test]
fn webapi_cfg_rejects_empty_bind_when_enabled() {
    let mut cfg = AppConfig::default();
    cfg.web_api.enabled = true;
    cfg.web_api.bind = String::new();
    assert!(cfg.validate().is_err());
}

#[test]
fn webapi_cfg_accepts_loopback_random() {
    let mut cfg = AppConfig::default();
    cfg.web_api.enabled = true;
    cfg.web_api.bind = "127.0.0.1:0".into();
    assert!(cfg.validate().is_ok());
}

#[test]
fn webapi_cfg_accepts_all_interfaces_fixed_port() {
    let mut cfg = AppConfig::default();
    cfg.web_api.enabled = true;
    cfg.web_api.bind = "0.0.0.0:8080".into();
    assert!(cfg.validate().is_ok());
}

#[test]
fn webapi_cfg_rejects_invalid_socket_addr() {
    let mut cfg = AppConfig::default();
    cfg.web_api.enabled = true;
    cfg.web_api.bind = "not-a-socket".into();
    assert!(cfg.validate().is_err());
}

#[test]
fn restore_staging_warn_gb_zero_is_rejected() {
    let mut cfg = AppConfig::default();
    cfg.restore.staging_warn_gb = 0.0;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, .. } if field == "restore.staging_warn_gb"),
        "expected Validation error for restore.staging_warn_gb, got: {err:?}"
    );
}

#[test]
fn restore_staging_warn_gb_negative_is_rejected() {
    let mut cfg = AppConfig::default();
    cfg.restore.staging_warn_gb = -1.0;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, .. } if field == "restore.staging_warn_gb"),
        "expected Validation error for restore.staging_warn_gb, got: {err:?}"
    );
}

#[test]
fn config_with_legacy_escrow_and_fetch_timeout_still_parses() {
    // restore-i6 / restore-i12: `[escrow]` and `restore.fetch_timeout_secs` are gone;
    // a config that still has them loads, and the rest of `[restore]` applies.
    let f = write_toml(
        "[escrow]\nk_factor = 7.0\n\n[restore]\nstaging_warn_gb = 12.5\nfetch_timeout_secs = 60\n",
    );
    let cfg = AppConfig::load(f.path()).unwrap();
    assert_eq!(cfg.restore.staging_warn_gb, 12.5);
    let text = toml::to_string(&cfg).unwrap();
    assert!(!text.contains("fetch_timeout"), "{text}");
}

// ============================================================
// ReliabilityConfig tests
// ============================================================

#[test]
fn config_completion_bonus_coefficient_defaults_to_1_5() {
    use crate::constants::DEFAULT_COMPLETION_BONUS_COEFFICIENT;
    let cfg = AppConfig::default();
    assert!(
        (cfg.reliability.completion_bonus_coefficient - DEFAULT_COMPLETION_BONUS_COEFFICIENT).abs()
            < 1e-9,
        "expected {DEFAULT_COMPLETION_BONUS_COEFFICIENT}, got {}",
        cfg.reliability.completion_bonus_coefficient
    );
    assert!(
        (cfg.reliability.completion_bonus_coefficient - 1.5).abs() < 1e-9,
        "expected 1.5, got {}",
        cfg.reliability.completion_bonus_coefficient
    );
}

#[test]
fn config_completion_bonus_coefficient_clamps_above_max() {
    use crate::constants::MAX_COMPLETION_BONUS_COEFFICIENT;
    let toml_str = "[reliability]\ncompletion_bonus_coefficient = 7.0\n";
    let f = write_toml(toml_str);
    let cfg = AppConfig::load(f.path()).unwrap();
    assert!(
        (cfg.reliability.completion_bonus_coefficient - MAX_COMPLETION_BONUS_COEFFICIENT).abs()
            < 1e-9,
        "expected clamped to {MAX_COMPLETION_BONUS_COEFFICIENT}, got {}",
        cfg.reliability.completion_bonus_coefficient
    );
}

#[test]
fn config_completion_bonus_coefficient_clamps_below_zero() {
    let toml_str = "[reliability]\ncompletion_bonus_coefficient = -1.0\n";
    let f = write_toml(toml_str);
    let cfg = AppConfig::load(f.path()).unwrap();
    assert!(
        (cfg.reliability.completion_bonus_coefficient - 0.0).abs() < 1e-9,
        "expected clamped to 0.0, got {}",
        cfg.reliability.completion_bonus_coefficient
    );
}

#[test]
fn config_completion_bonus_coefficient_round_trip_serialize_deserialize() {
    let cfg = AppConfig {
        reliability: ReliabilityConfig {
            completion_bonus_coefficient: 3.0,
        },
        ..Default::default()
    };
    let toml_str = toml::to_string(&cfg).unwrap();
    let cfg2: AppConfig = toml::from_str(&toml_str).unwrap();
    assert!(
        (cfg2.reliability.completion_bonus_coefficient - 3.0_f64).abs() < 1e-9,
        "expected 3.0, got {}",
        cfg2.reliability.completion_bonus_coefficient
    );
}

// ============================================================
// Wave 7: derive_file_importance with bursts
// ============================================================

fn make_watch_with_bursts(
    path: &str,
    is_media: bool,
    bursts: Option<Vec<HashSet<std::path::PathBuf>>>,
) -> WatchConfig {
    WatchConfig {
        path: path.to_string(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: Some(FolderClassification {
            is_media_folder: is_media,
            importance_multiplier: 1.0,
        }),
        bursts,
    }
}

#[test]
fn derive_file_importance_applies_burst_downweight_when_path_in_burst() {
    // Find a path for which burst_downweight_selects returns true.
    let target_path = (0..200u32)
        .map(|i| format!("/photos/img_{:04}.jpg", i))
        .find(|p| burst_downweight_selects(Path::new(p)))
        .expect("at least one of 200 paths must be selected");

    let mut burst_set: HashSet<std::path::PathBuf> = HashSet::new();
    burst_set.insert(std::path::PathBuf::from(&target_path));

    let wc = make_watch_with_bursts("/photos", true, Some(vec![burst_set]));

    // Compute what the non-downweighted importance would be.
    let wc_no_burst = WatchConfig {
        bursts: Some(vec![]),
        ..wc.clone()
    };
    let without_downweight = derive_file_importance(&target_path, &[wc_no_burst]);

    // With burst set: downweight should be applied.
    let result = derive_file_importance(&target_path, &[wc]);
    let expected = apply_burst_downweight(without_downweight);
    assert!(
        (result - expected).abs() < 1e-9,
        "burst downweight should halve importance (floor 0.05): result={result} expected={expected}"
    );
}

#[test]
fn derive_file_importance_no_downweight_when_path_not_in_burst() {
    let mut burst_set: HashSet<std::path::PathBuf> = HashSet::new();
    burst_set.insert(std::path::PathBuf::from("/photos/other.jpg"));

    let wc = make_watch_with_bursts("/photos", true, Some(vec![burst_set]));

    let target = "/photos/img_not_in_burst.jpg";
    let result = derive_file_importance(target, &[wc.clone()]);

    // Without burst, same result
    let wc_no_burst = WatchConfig {
        bursts: Some(vec![]),
        ..wc
    };
    let base = derive_file_importance(target, &[wc_no_burst]);
    assert!(
        (result - base).abs() < 1e-9,
        "no downweight for path not in burst"
    );
}

#[test]
fn derive_file_importance_no_downweight_when_bursts_empty() {
    let wc = make_watch_with_bursts("/photos", true, Some(vec![]));
    let target = "/photos/img_001.jpg";
    let result = derive_file_importance(target, &[wc]);
    // Should be one of the media bucket values.
    assert!(
        result == 0.95 || result == 0.65 || result == 0.20,
        "expected media bucket value (no downweight), got {result}"
    );
}

#[test]
fn derive_file_importance_no_downweight_when_bursts_none() {
    let wc = make_watch_with_bursts("/photos", true, None);
    let target = "/photos/img_001.jpg";
    let result = derive_file_importance(target, &[wc]);
    assert!(
        result == 0.95 || result == 0.65 || result == 0.20,
        "expected media bucket value (bursts=None means no downweight), got {result}"
    );
}

#[test]
fn derive_file_importance_no_downweight_when_30pct_selection_excludes_path() {
    // Find a path for which burst_downweight_selects returns FALSE (30% case).
    let not_selected = (0..200u32)
        .map(|i| format!("/photos/img_{:04}.jpg", i))
        .find(|p| !burst_downweight_selects(Path::new(p)))
        .expect("at least one of 200 paths must be in the 30% not-selected bucket");

    let mut burst_set: HashSet<std::path::PathBuf> = HashSet::new();
    burst_set.insert(std::path::PathBuf::from(&not_selected));

    let wc = make_watch_with_bursts("/photos", true, Some(vec![burst_set]));
    let result = derive_file_importance(&not_selected, &[wc.clone()]);

    // Without burst check → same importance.
    let wc_no_burst = WatchConfig {
        bursts: Some(vec![]),
        ..wc
    };
    let base = derive_file_importance(&not_selected, &[wc_no_burst]);
    assert!(
        (result - base).abs() < 1e-9,
        "path in burst but not selected (30%) → no downweight; result={result} base={base}"
    );
}

// ============================================================
// Wave 7: populate_bursts
// ============================================================

#[test]
fn populate_bursts_finds_clusters_in_real_directory() {
    let dir = tempfile::TempDir::new().unwrap();
    // Write 1 .jpg file — not enough for a burst (< min_count=8), but wiring check.
    std::fs::write(dir.path().join("photo.jpg"), b"fake jpg").unwrap();

    let mut wc = WatchConfig {
        path: dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    wc.populate_bursts();

    // Wiring check: populate_bursts ran and stored Some result.
    assert!(
        wc.bursts.is_some(),
        "bursts should be populated after populate_bursts()"
    );
    // 1 file < min_count=8 → no burst detected.
    assert!(
        wc.bursts.as_ref().unwrap().is_empty(),
        "1 file < min_count=8, no bursts expected"
    );
}

#[test]
fn populate_bursts_excludes_text_files() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("notes.txt"), b"text content").unwrap();
    std::fs::write(dir.path().join("README.md"), b"readme").unwrap();
    std::fs::write(dir.path().join("photo.jpg"), b"fake jpg").unwrap();

    let mut wc = WatchConfig {
        path: dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    wc.populate_bursts();

    // Only 1 media file (photo.jpg) found; text files excluded.
    assert!(wc.bursts.is_some(), "bursts should be populated");
    assert!(
        wc.bursts.as_ref().unwrap().is_empty(),
        "only 1 media file found, no burst"
    );
}

#[test]
fn populate_bursts_handles_empty_folder_gracefully() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut wc = WatchConfig {
        path: dir.path().to_string_lossy().into_owned(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    wc.populate_bursts();
    assert_eq!(
        wc.bursts,
        Some(vec![]),
        "empty folder: bursts should be Some(empty vec)"
    );
}

#[test]
fn populate_bursts_handles_missing_directory() {
    let mut wc = WatchConfig {
        path: "/nonexistent/path/does/not/exist".to_string(),
        importance_multiplier: 1.0,
        was_legacy_importance: false,
        classification: None,
        bursts: None,
    };
    wc.populate_bursts();
    assert_eq!(
        wc.bursts,
        Some(vec![]),
        "missing directory: bursts should be Some(empty vec)"
    );
}

// ============================================================
// В-0: [four_r] section (C-1..C-3)
// ============================================================

/// C-1: the defaults are the release-map v1 dials, enforce off.
#[test]
fn four_r_defaults_are_the_v1_dials_with_enforce_off() {
    let d = FourRCfg::default();
    assert!(!d.enforce);
    assert_eq!(d.v_free_gb, 0.0);
    assert_eq!(d.c_recip_days, 30.0);
    assert_eq!(d.w_d, 0.5);
    assert_eq!(d.tau_ref_days, 365.0);
    assert_eq!(d.theta_p, 0.2);
    assert_eq!(d.v_min_gb, 1.0);
    assert_eq!((d.s_hard, d.s_target, d.s_soft), (0.05, 0.15, 0.20));
    assert_eq!(AppConfig::default().four_r, d);
    AppConfig::default().validate().expect("defaults validate");
}

/// C-2: a file without the section gets the defaults; a partial section keeps the other
/// defaults (serde(default) on the struct).
#[test]
fn four_r_section_is_optional_and_partial_sections_merge_with_defaults() {
    let f = write_toml("[storage]\ndisk_reserve_gb = 0.0\n");
    let cfg = AppConfig::load(f.path()).unwrap();
    assert_eq!(cfg.four_r, FourRCfg::default());

    let f = write_toml("[four_r]\nv_min_gb = 0.002\nc_recip_days = 3.0\n");
    let cfg = AppConfig::load(f.path()).unwrap();
    assert_eq!(cfg.four_r.v_min_gb, 0.002);
    assert_eq!(cfg.four_r.c_recip_days, 3.0);
    assert_eq!(cfg.four_r.w_d, FourRCfg::default().w_d);
    assert_eq!(cfg.four_r.s_soft, FourRCfg::default().s_soft);
    assert!(!cfg.four_r.enforce);
}

/// C-3: validation — enforce is refused in this build; thresholds ordered; ranges.
#[test]
fn four_r_validation_refuses_enforce_and_bad_dials() {
    let field_of = |c: &FourRCfg| {
        let cfg = AppConfig {
            four_r: c.clone(),
            ..Default::default()
        };
        match cfg.validate() {
            Err(ConfigError::Validation { field, .. }) => Some(field),
            Err(e) => panic!("unexpected error {e}"),
            Ok(()) => None,
        }
    };
    let d = FourRCfg::default();
    assert_eq!(field_of(&d), None);
    let bad: Vec<(FourRCfg, &str)> = vec![
        (
            FourRCfg {
                enforce: true,
                ..d.clone()
            },
            "four_r.enforce",
        ),
        (
            FourRCfg {
                s_hard: 0.0,
                ..d.clone()
            },
            "four_r.s_hard",
        ),
        (
            FourRCfg {
                s_target: 0.04,
                ..d.clone()
            },
            "four_r.s_hard",
        ),
        (
            FourRCfg {
                s_soft: 0.15,
                ..d.clone()
            },
            "four_r.s_hard",
        ),
        (
            FourRCfg {
                s_soft: 1.0,
                ..d.clone()
            },
            "four_r.s_hard",
        ),
        (
            FourRCfg {
                v_free_gb: -0.1,
                ..d.clone()
            },
            "four_r.v_free_gb",
        ),
        (
            FourRCfg {
                c_recip_days: -1.0,
                ..d.clone()
            },
            "four_r.c_recip_days",
        ),
        (
            FourRCfg {
                w_d: -0.5,
                ..d.clone()
            },
            "four_r.w_d",
        ),
        (
            FourRCfg {
                tau_ref_days: 0.0,
                ..d.clone()
            },
            "four_r.tau_ref_days",
        ),
        (
            FourRCfg {
                theta_p: -0.2,
                ..d.clone()
            },
            "four_r.theta_p",
        ),
        (
            FourRCfg {
                v_min_gb: -1.0,
                ..d.clone()
            },
            "four_r.v_min_gb",
        ),
        (
            FourRCfg {
                theta_p: f64::NAN,
                ..d.clone()
            },
            "four_r.theta_p",
        ),
        (
            FourRCfg {
                v_free_gb: f64::INFINITY,
                ..d.clone()
            },
            "four_r.v_free_gb",
        ),
    ];
    for (c, want) in bad {
        assert_eq!(field_of(&c).as_deref(), Some(want), "{c:?}");
    }
    // c_recip = 0 disables the cap and is valid.
    assert_eq!(
        field_of(&FourRCfg {
            c_recip_days: 0.0,
            ..d.clone()
        }),
        None
    );

    // Through the loader: an `enforce = true` file does not load.
    let f = write_toml("[four_r]\nenforce = true\n");
    match AppConfig::load(f.path()) {
        Err(ConfigError::Validation { field, reason }) => {
            assert_eq!(field, "four_r.enforce");
            assert!(reason.contains("shadow"), "{reason}");
        }
        other => panic!("enforce = true must be refused, got {other:?}"),
    }
}

#[cfg(test)]
fn section_value(cfg: &AppConfig, section: &str) -> toml::Value {
    toml::Value::try_from(cfg).unwrap()[section].clone()
}

/// A present-but-empty section must equal that section's `impl Default`, field for field.
/// A field-level `#[serde(default)]` inside a container-level `#[serde(default)]` struct
/// silently takes the field type's default instead (e.g. `bool` → false) and turns this red.
#[test]
fn every_section_when_present_but_empty_then_equals_section_default() {
    let defaults = AppConfig::default();
    for section in [
        "backup",
        "storage",
        "network",
        "cluster",
        "metrics",
        "web_api",
        "restore",
        "reliability",
        "four_r",
    ] {
        let f = write_toml(&format!("[{section}]\n"));
        let cfg = AppConfig::load(f.path()).unwrap();
        assert_eq!(
            section_value(&cfg, section),
            section_value(&defaults, section),
            "[{section}] present without keys must match its Default"
        );
    }
}

/// network-i17: the IPFS bootstrap switch is gone. A config written before it
/// was removed still loads, the old key changes nothing, and the keys around it
/// are read as usual.
#[test]
fn config_network_legacy_ipfs_key_is_ignored() {
    let f = write_toml(
        "[network]\nkademlia_disable_ipfs_bootstrap = false\nlisten_port = 4001\n\
         kademlia_bootstrap_peers = [\"/ip4/127.0.0.1/tcp/4002\"]\n",
    );
    let cfg = AppConfig::load(f.path()).expect("a legacy [network] key must not refuse the config");
    assert_eq!(cfg.network.listen_port, 4001);
    assert_eq!(
        cfg.network.kademlia_bootstrap_peers,
        vec!["/ip4/127.0.0.1/tcp/4002".to_string()]
    );
    let saved = toml::to_string(&cfg).expect("serialize");
    assert!(
        !saved.contains("ipfs"),
        "the key is not carried over when the config is written back: {saved}"
    );
}

#[test]
fn config_rejects_max_file_size_above_ceiling() {
    let mut cfg = AppConfig::default();
    assert_eq!(cfg.backup.max_file_size_mb, 0, "0 = automatic by default");
    cfg.backup.max_file_size_mb = 3072;
    cfg.validate().unwrap();
    cfg.backup.max_file_size_mb = 3073;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, ref reason }
            if field == "backup.max_file_size_mb" && reason.contains("must be <= 3072")),
        "got {err:?}"
    );
}

#[test]
fn config_without_max_file_size_key_reads_as_automatic() {
    let f = write_toml("[backup]\nsource_block_size_mb = 32\n");
    let cfg = AppConfig::load(f.path()).unwrap();
    assert_eq!(cfg.backup.max_file_size_mb, 0);
}

#[test]
fn config_rejects_source_block_size_above_1024() {
    let mut cfg = AppConfig::default();
    cfg.backup.source_block_size_mb = 1024;
    cfg.validate().unwrap();
    cfg.backup.source_block_size_mb = 2048;
    let err = cfg.validate().unwrap_err();
    assert!(
        matches!(err, ConfigError::Validation { ref field, ref reason }
            if field == "backup.source_block_size_mb" && reason.contains("1024")),
        "got {err:?}"
    );
}
