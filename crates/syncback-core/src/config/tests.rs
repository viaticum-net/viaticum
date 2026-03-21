#[cfg(test)]
use std::io::Write;

#[cfg(test)]
use crate::config::{
    AppConfig, BackupCfg, ClusterCfg, ConfigError, EscrowCfg, NetworkCfg, StorageCfg,
    disk_reserve_bytes, expand_data_dir, hard_quota_bytes, soft_quota_bytes, source_block_size_bytes,
};
#[cfg(test)]
use crate::constants::{
    DEFAULT_DISK_RESERVE_BYTES, DEFAULT_ESCROW_TRUST_FACTOR, DEFAULT_MAX_VERSIONS,
    DEFAULT_SOURCE_BLOCK_SIZE, FREE_TIER_GB, MAX_BOARD_ENTRIES, MAX_BOARD_SIZE_BYTES,
};

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
    assert_eq!(cfg.backup.source_block_size_mb, defaults.backup.source_block_size_mb);
    assert_eq!(cfg.backup.max_versions, defaults.backup.max_versions);
    assert_eq!(cfg.backup.max_version_age_days, defaults.backup.max_version_age_days);
    assert_eq!(cfg.storage.soft_quota_gb, defaults.storage.soft_quota_gb);
    assert_eq!(cfg.storage.hard_quota_gb, defaults.storage.hard_quota_gb);
    assert_eq!(cfg.storage.disk_reserve_gb, defaults.storage.disk_reserve_gb);
    assert_eq!(cfg.storage.data_dir, defaults.storage.data_dir);
    assert_eq!(cfg.escrow.free_tier_gb, defaults.escrow.free_tier_gb);
    assert_eq!(cfg.escrow.trust_factor, defaults.escrow.trust_factor);
    assert_eq!(cfg.network.relay_max_entries, defaults.network.relay_max_entries);
    assert_eq!(cfg.network.relay_max_size_mb, defaults.network.relay_max_size_mb);
    assert_eq!(cfg.network.relay_ttl_days, defaults.network.relay_ttl_days);
    assert_eq!(cfg.cluster.sync_batch_size, defaults.cluster.sync_batch_size);
}

#[test]
fn config_loads_partial_file_merging_with_defaults() {
    let f = write_toml("[backup]\nsource_block_size_mb = 32\n");
    let cfg = AppConfig::load(f.path()).unwrap();
    assert_eq!(cfg.backup.source_block_size_mb, 32);
    assert_eq!(cfg.backup.max_versions, DEFAULT_MAX_VERSIONS);
    assert_eq!(cfg.storage.disk_reserve_gb, DEFAULT_DISK_RESERVE_BYTES as f64 / 1_073_741_824.0);
    assert_eq!(cfg.escrow.trust_factor, DEFAULT_ESCROW_TRUST_FACTOR);
    assert_eq!(cfg.cluster.sync_batch_size, 100);
}

#[test]
fn config_roundtrips_all_fields() {
    let original = AppConfig {
        backup: BackupCfg {
            source_block_size_mb: 64,
            max_versions: 10,
            max_version_age_days: 180,
        },
        storage: StorageCfg {
            soft_quota_gb: 500.0,
            hard_quota_gb: 10.0,
            disk_reserve_gb: 50.0,
            data_dir: "/data/syncback".to_string(),
        },
        escrow: EscrowCfg {
            free_tier_gb: 2.0,
            trust_factor: 30.0,
        },
        network: NetworkCfg {
            relay_max_entries: 1000,
            relay_max_size_mb: 4,
            relay_ttl_days: 14,
            enable_relay: false,
        },
        cluster: ClusterCfg {
            sync_batch_size: 200,
        },
    };

    let toml_str = toml::to_string(&original).unwrap();
    let f = write_toml(&toml_str);
    let loaded = AppConfig::load(f.path()).unwrap();

    assert_eq!(loaded.backup.source_block_size_mb, 64);
    assert_eq!(loaded.backup.max_versions, 10);
    assert_eq!(loaded.backup.max_version_age_days, 180);
    assert_eq!(loaded.storage.soft_quota_gb, 500.0);
    assert_eq!(loaded.storage.hard_quota_gb, 10.0);
    assert_eq!(loaded.storage.disk_reserve_gb, 50.0);
    assert_eq!(loaded.storage.data_dir, "/data/syncback");
    assert_eq!(loaded.escrow.free_tier_gb, 2.0);
    assert_eq!(loaded.escrow.trust_factor, 30.0);
    assert_eq!(loaded.network.relay_max_entries, 1000);
    assert_eq!(loaded.network.relay_max_size_mb, 4);
    assert_eq!(loaded.network.relay_ttl_days, 14);
    assert_eq!(loaded.cluster.sync_batch_size, 200);
}

#[test]
fn config_validate_rejects_source_block_size_zero() {
    let mut cfg = AppConfig::default();
    cfg.backup.source_block_size_mb = 0;
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::Validation { ref field, .. } if field == "backup.source_block_size_mb"));
}

#[test]
fn config_validate_rejects_source_block_size_not_power_of_two() {
    let mut cfg = AppConfig::default();
    cfg.backup.source_block_size_mb = 100;
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::Validation { ref field, .. } if field == "backup.source_block_size_mb"));
}

#[test]
fn config_validate_rejects_source_block_size_3mb() {
    let mut cfg = AppConfig::default();
    cfg.backup.source_block_size_mb = 3;
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::Validation { ref field, .. } if field == "backup.source_block_size_mb"));
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
    assert!(matches!(err, ConfigError::Validation { ref field, .. } if field == "backup.max_versions"));
}

#[test]
fn config_validate_rejects_max_version_age_days_zero() {
    let mut cfg = AppConfig::default();
    cfg.backup.max_version_age_days = 0;
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::Validation { ref field, .. } if field == "backup.max_version_age_days"));
}

#[test]
fn config_validate_rejects_negative_soft_quota() {
    let mut cfg = AppConfig::default();
    cfg.storage.soft_quota_gb = -1.0;
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::Validation { ref field, .. } if field == "storage.soft_quota_gb"));
}

#[test]
fn config_validate_rejects_negative_hard_quota() {
    let mut cfg = AppConfig::default();
    cfg.storage.hard_quota_gb = -5.0;
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::Validation { ref field, .. } if field == "storage.hard_quota_gb"));
}

#[test]
fn config_validate_rejects_hard_quota_above_soft_quota() {
    let mut cfg = AppConfig::default();
    cfg.storage.soft_quota_gb = 100.0;
    cfg.storage.hard_quota_gb = 200.0;
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::Validation { ref field, .. } if field == "storage.hard_quota_gb"));
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
fn config_validate_rejects_relay_max_entries_zero() {
    let mut cfg = AppConfig::default();
    cfg.network.relay_max_entries = 0;
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::Validation { ref field, .. } if field == "network.relay_max_entries"));
}

#[test]
fn config_validate_rejects_relay_ttl_days_zero() {
    let mut cfg = AppConfig::default();
    cfg.network.relay_ttl_days = 0;
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::Validation { ref field, .. } if field == "network.relay_ttl_days"));
}

#[test]
fn config_validate_rejects_cluster_sync_batch_size_zero() {
    let mut cfg = AppConfig::default();
    cfg.cluster.sync_batch_size = 0;
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, ConfigError::Validation { ref field, .. } if field == "cluster.sync_batch_size"));
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
fn expand_data_dir_expands_tilde() {
    let mut cfg = AppConfig::default();
    cfg.storage.data_dir = "~/.syncback".to_string();
    // Force HOME to a known value for the test.
    // SAFETY: single-threaded test, no concurrent env reads.
    unsafe { std::env::set_var("HOME", "/home/user") };
    let result = expand_data_dir(&cfg);
    assert_eq!(result, std::path::PathBuf::from("/home/user/.syncback"));
}

#[test]
fn expand_data_dir_leaves_absolute_path_unchanged() {
    let mut cfg = AppConfig::default();
    cfg.storage.data_dir = "/mnt/data/syncback".to_string();
    let result = expand_data_dir(&cfg);
    assert_eq!(result, std::path::PathBuf::from("/mnt/data/syncback"));
}

#[test]
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
    assert_eq!(cfg.backup.source_block_size_mb, DEFAULT_SOURCE_BLOCK_SIZE / 1_048_576);
    assert_eq!(cfg.backup.max_versions, DEFAULT_MAX_VERSIONS);
    assert_eq!(
        cfg.storage.disk_reserve_gb,
        DEFAULT_DISK_RESERVE_BYTES as f64 / 1_073_741_824.0
    );
    assert_eq!(cfg.escrow.free_tier_gb, FREE_TIER_GB);
    assert_eq!(cfg.escrow.trust_factor, DEFAULT_ESCROW_TRUST_FACTOR);
    assert_eq!(cfg.network.relay_max_entries, MAX_BOARD_ENTRIES);
    assert_eq!(cfg.network.relay_max_size_mb, MAX_BOARD_SIZE_BYTES / 1_048_576);
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
