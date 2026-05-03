use super::*;

use std::sync::Arc;

fn write_config(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = dir.path().join("config.toml");
    std::fs::write(&p, body).unwrap();
    p
}

fn sample_config() -> &'static str {
    // Includes comments, a [[watch]] block, [escrow], [web_api] — none of which
    // the editor should touch.
    r#"# top of file comment

[backup]
source_block_size_mb = 32

[storage]
# user-tuned reserve
disk_reserve_gb = 5.0
soft_quota_gb = 50.0
data_dir = "~/.viaticum"

[escrow]
k_factor = 7.0

[network]
listen_port = 4500
relay_max_entries = 2000

[web_api]
enabled = true
bind = "127.0.0.1:8500"

[[watch]]
path = "/home/bob/Documents"
importance = 0.7
"#
}

#[test]
fn read_editable_returns_current_values() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config());
    let admin = ConfigAdmin::new(p);
    let cfg = admin.read_editable().unwrap();
    assert_eq!(cfg.storage.disk_reserve_gb, 5.0);
    assert_eq!(cfg.storage.soft_quota_gb, 50.0);
    assert_eq!(cfg.network.listen_port, 4500);
}

#[test]
fn read_editable_returns_defaults_when_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let admin = ConfigAdmin::new(dir.path().join("nope.toml"));
    let cfg = admin.read_editable().unwrap();
    let defaults = syncback_core::config::AppConfig::default();
    assert_eq!(cfg.storage.disk_reserve_gb, defaults.storage.disk_reserve_gb);
    assert_eq!(cfg.storage.soft_quota_gb, defaults.storage.soft_quota_gb);
    assert_eq!(cfg.network.listen_port, defaults.network.listen_port);
}

#[tokio::test]
async fn update_writes_atomically_and_reload_sees_changes() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config());
    let admin = ConfigAdmin::new(p.clone());
    admin
        .update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: 10.0,
                soft_quota_gb: 4000.0,
            },
            network: NetworkEditable { listen_port: 4515 },
        })
        .await
        .unwrap();
    let cfg = admin.read_editable().unwrap();
    assert_eq!(cfg.storage.disk_reserve_gb, 10.0);
    assert_eq!(cfg.storage.soft_quota_gb, 4000.0);
    assert_eq!(cfg.network.listen_port, 4515);
    // No leftover .tmp file.
    let tmp = tmp_sibling(&p);
    assert!(!tmp.exists());
}

#[tokio::test]
async fn update_preserves_comments_and_other_sections() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config());
    let admin = ConfigAdmin::new(p.clone());
    admin
        .update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: 1.0,
                soft_quota_gb: 200.0,
            },
            network: NetworkEditable { listen_port: 4600 },
        })
        .await
        .unwrap();
    let after = std::fs::read_to_string(&p).unwrap();
    // Comments + untouched sections still present.
    assert!(after.contains("# top of file comment"));
    assert!(after.contains("# user-tuned reserve"));
    assert!(after.contains("[escrow]"));
    assert!(after.contains("k_factor = 7.0"));
    assert!(after.contains("[[watch]]"));
    assert!(after.contains("/home/bob/Documents"));
    // Other [storage] keys untouched.
    assert!(after.contains("data_dir = \"~/.viaticum\""));
    // [network] kept its sibling key.
    assert!(after.contains("relay_max_entries = 2000"));
    // Updated values present.
    assert!(after.contains("disk_reserve_gb = 1.0"));
    assert!(after.contains("soft_quota_gb = 200.0"));
    assert!(after.contains("listen_port = 4600"));
}

#[tokio::test]
async fn update_creates_file_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("config.toml");
    let admin = ConfigAdmin::new(p.clone());
    admin
        .update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: 2.0,
                soft_quota_gb: 100.0,
            },
            network: NetworkEditable { listen_port: 4700 },
        })
        .await
        .unwrap();
    assert!(p.exists());
    let cfg = admin.read_editable().unwrap();
    assert_eq!(cfg.storage.disk_reserve_gb, 2.0);
    assert_eq!(cfg.network.listen_port, 4700);
}

#[tokio::test]
async fn update_rejects_negative_disk_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config());
    let admin = ConfigAdmin::new(p);
    let err = admin
        .update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: -1.0,
                soft_quota_gb: 50.0,
            },
            network: NetworkEditable { listen_port: 4500 },
        })
        .await
        .unwrap_err();
    matches_validation(&err, "storage.disk_reserve_gb");
}

#[tokio::test]
async fn update_rejects_oversized_soft_quota() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config());
    let admin = ConfigAdmin::new(p);
    let err = admin
        .update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: 0.0,
                soft_quota_gb: 1_000_000.0,
            },
            network: NetworkEditable { listen_port: 4500 },
        })
        .await
        .unwrap_err();
    matches_validation(&err, "storage.soft_quota_gb");
}

#[tokio::test]
async fn update_rejects_listen_port_collision_with_web_bind() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config());
    let admin = ConfigAdmin::new(p);
    let err = admin
        .update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: 0.0,
                soft_quota_gb: 50.0,
            },
            // 8500 collides with [web_api] bind = "127.0.0.1:8500".
            network: NetworkEditable { listen_port: 8500 },
        })
        .await
        .unwrap_err();
    matches_validation(&err, "network.listen_port");
}

#[tokio::test]
async fn update_allows_listen_port_zero() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config());
    let admin = ConfigAdmin::new(p);
    admin
        .update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: 0.0,
                soft_quota_gb: 50.0,
            },
            network: NetworkEditable { listen_port: 0 },
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn update_rejects_nan_disk_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config());
    let admin = ConfigAdmin::new(p);
    let err = admin
        .update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: f64::NAN,
                soft_quota_gb: 50.0,
            },
            network: NetworkEditable { listen_port: 4500 },
        })
        .await
        .unwrap_err();
    matches_validation(&err, "storage.disk_reserve_gb");
}

#[tokio::test]
async fn concurrent_updates_are_serialised() {
    // Two concurrent PUTs racing — both must complete, file must be valid TOML
    // and contain one of the two intended values (no torn merge).
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config());
    let admin = Arc::new(ConfigAdmin::new(p.clone()));

    let a = admin.clone();
    let b = admin.clone();

    let ta = tokio::spawn(async move {
        a.update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: 10.0,
                soft_quota_gb: 100.0,
            },
            network: NetworkEditable { listen_port: 4501 },
        })
        .await
    });
    let tb = tokio::spawn(async move {
        b.update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: 20.0,
                soft_quota_gb: 200.0,
            },
            network: NetworkEditable { listen_port: 4502 },
        })
        .await
    });

    ta.await.unwrap().unwrap();
    tb.await.unwrap().unwrap();

    let raw = std::fs::read_to_string(&p).unwrap();
    let _doc: toml_edit::DocumentMut = raw.parse().expect("file is still valid TOML");
    let final_cfg = admin.read_editable().unwrap();
    let port_ok = final_cfg.network.listen_port == 4501 || final_cfg.network.listen_port == 4502;
    assert!(port_ok, "final listen_port = {}", final_cfg.network.listen_port);
}

fn matches_validation(err: &ConfigAdminError, field: &str) {
    match err {
        ConfigAdminError::Validation { field: f, .. } => assert_eq!(f, field),
        other => panic!("expected Validation, got {other:?}"),
    }
}
