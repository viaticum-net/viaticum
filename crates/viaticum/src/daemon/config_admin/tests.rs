use super::*;

use std::sync::Arc;

fn write_config(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = dir.path().join("config.toml");
    std::fs::write(&p, body).unwrap();
    p
}

fn sample_config() -> &'static str {
    // Includes comments, a [[watch]] block, [web_api] and a legacy [escrow]
    // section (ignored by the daemon since v1, restore-i6) — none of which the
    // editor should touch.
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
    let defaults = viaticum_core::config::AppConfig::default();
    assert_eq!(
        cfg.storage.disk_reserve_gb,
        defaults.storage.disk_reserve_gb
    );
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
    assert!(
        port_ok,
        "final listen_port = {}",
        final_cfg.network.listen_port
    );
}

fn matches_validation(err: &ConfigAdminError, field: &str) {
    match err {
        ConfigAdminError::Validation { field: f, .. } => assert_eq!(f, field),
        other => panic!("expected Validation, got {other:?}"),
    }
}

// ─── Issue J: .bak tests ──────────────────────────────────────────────────────

// T-J1: saving an existing config creates .bak with the old listen_port value.
#[tokio::test]
async fn config_save_creates_bak_before_atomic_write() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config());
    let admin = ConfigAdmin::new(p.clone());

    admin
        .update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: 10.0,
                soft_quota_gb: 200.0,
            },
            network: NetworkEditable { listen_port: 5555 },
        })
        .await
        .unwrap();

    let bak = bak_sibling(&p);
    assert!(bak.exists(), ".bak must exist after first save");
    let bak_content = std::fs::read_to_string(&bak).unwrap();
    // .bak must contain the old listen_port (4500), not the new one (5555).
    assert!(
        bak_content.contains("listen_port = 4500"),
        ".bak must contain old listen_port 4500, got: {bak_content}"
    );
    assert!(
        !bak_content.contains("listen_port = 5555"),
        ".bak must NOT contain new listen_port 5555"
    );
}

// T-J2: validation failure does not create .bak and does not touch config.toml.
#[tokio::test]
async fn config_save_preflight_validation_rejects_invalid_no_bak_created() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config());
    let admin = ConfigAdmin::new(p.clone());

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

    let bak = bak_sibling(&p);
    assert!(!bak.exists(), ".bak must NOT exist when validation fails");

    // config.toml still has original values.
    let cfg = admin.read_editable().unwrap();
    assert_eq!(
        cfg.storage.disk_reserve_gb, 5.0,
        "config.toml must be unchanged"
    );
    assert_eq!(
        cfg.network.listen_port, 4500,
        "config.toml must be unchanged"
    );
}

// T-J3: second save overwrites .bak with the pre-second-save state.
#[tokio::test]
async fn config_save_overwrites_old_bak_with_pre_second_save_state() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config()); // port A = 4500
    let admin = ConfigAdmin::new(p.clone());

    // First save: port A → port B.
    admin
        .update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: 5.0,
                soft_quota_gb: 50.0,
            },
            network: NetworkEditable { listen_port: 5000 }, // port B
        })
        .await
        .unwrap();
    let bak = bak_sibling(&p);
    let bak_after_first = std::fs::read_to_string(&bak).unwrap();
    assert!(
        bak_after_first.contains("listen_port = 4500"),
        ".bak after 1st save must contain port A (4500)"
    );

    // Second save: port B → port C.
    admin
        .update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: 5.0,
                soft_quota_gb: 50.0,
            },
            network: NetworkEditable { listen_port: 6000 }, // port C
        })
        .await
        .unwrap();
    let bak_after_second = std::fs::read_to_string(&bak).unwrap();
    assert!(
        bak_after_second.contains("listen_port = 5000"),
        ".bak after 2nd save must contain port B (5000), got: {bak_after_second}"
    );
    assert!(
        !bak_after_second.contains("listen_port = 4500"),
        ".bak after 2nd save must NOT contain port A (4500)"
    );
}

// T-J4: read_editable returns config.toml values even when .bak is present.
#[tokio::test]
async fn config_load_normal_flow_unaffected_by_bak_presence() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, sample_config()); // listen_port = 4500
    // Write a .bak with a different port.
    let bak = bak_sibling(&p);
    std::fs::write(&bak, "# old config\n[network]\nlisten_port = 9999\n").unwrap();
    let admin = ConfigAdmin::new(p.clone());
    let cfg = admin.read_editable().unwrap();
    assert_eq!(
        cfg.network.listen_port, 4500,
        "read_editable must read config.toml (4500), not .bak (9999)"
    );
}

// T-J5: no .bak is created when config.toml does not exist before the first save.
#[tokio::test]
async fn no_bak_created_when_config_file_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("config.toml");
    let admin = ConfigAdmin::new(p.clone());

    admin
        .update(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb: 3.0,
                soft_quota_gb: 100.0,
            },
            network: NetworkEditable { listen_port: 7777 },
        })
        .await
        .unwrap();

    let bak = bak_sibling(&p);
    assert!(
        !bak.exists(),
        ".bak must NOT exist when config.toml did not exist before save"
    );
    assert!(p.exists(), "config.toml must be created");
    let cfg = admin.read_editable().unwrap();
    assert_eq!(cfg.network.listen_port, 7777);
}

// ─── daemon-i10 (F13): numbers as the user wrote them ─────────────────────────

// Hand-written config: the amounts are TOML integers, not floats.
fn integer_amounts_config() -> &'static str {
    r#"[storage]
disk_reserve_gb = 7
soft_quota_gb = 50

[network]
listen_port = 4500
"#
}

/// The number at `[section].key` of the file on disk, integer or float.
fn number_on_disk(p: &Path, section: &str, key: &str) -> f64 {
    let doc: toml_edit::DocumentMut = std::fs::read_to_string(p).unwrap().parse().unwrap();
    let item = &doc[section][key];
    item.as_float()
        .or_else(|| item.as_integer().map(|i| i as f64))
        .unwrap_or_else(|| panic!("{section}.{key} is not a number on disk: {item}"))
}

// Mutation: read_gb accepts only `as_float()` → the integer quota reads as the
// default (0 = whole disk) and this test goes red.
#[test]
fn read_editable_reads_integer_quota_and_reserve_as_written() {
    let dir = tempfile::tempdir().unwrap();
    let admin = ConfigAdmin::new(write_config(&dir, integer_amounts_config()));
    let cfg = admin.read_editable().unwrap();
    assert_eq!(cfg.storage.soft_quota_gb, 50.0);
    assert_eq!(cfg.storage.disk_reserve_gb, 7.0);
    assert_eq!(cfg.network.listen_port, 4500);
}

// Mutation: read_gb drops the `as_float()` branch → a fractional amount is lost.
#[test]
fn read_editable_reads_fractional_float_amounts() {
    let dir = tempfile::tempdir().unwrap();
    let body = "[storage]\ndisk_reserve_gb = 2.5\nsoft_quota_gb = 12.75\n";
    let admin = ConfigAdmin::new(write_config(&dir, body));
    let cfg = admin.read_editable().unwrap();
    assert_eq!(cfg.storage.disk_reserve_gb, 2.5);
    assert_eq!(cfg.storage.soft_quota_gb, 12.75);
}

// The whole form round-trip the Settings page does: GET, then PUT unchanged.
// Mutation: integer amounts read as defaults → Save writes the defaults over
// 50 / 7 and this test goes red.
#[tokio::test]
async fn save_of_unchanged_form_keeps_integer_amounts_in_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_config(&dir, integer_amounts_config());
    let admin = ConfigAdmin::new(p.clone());
    let form = admin.read_editable().unwrap();
    admin.update(form.clone()).await.unwrap();

    assert_eq!(number_on_disk(&p, "storage", "soft_quota_gb"), 50.0);
    assert_eq!(number_on_disk(&p, "storage", "disk_reserve_gb"), 7.0);
    assert_eq!(number_on_disk(&p, "network", "listen_port"), 4500.0);
    assert_eq!(admin.read_editable().unwrap(), form);
}

// An absent key is not written in the config: the default is the value in force.
#[test]
fn read_editable_uses_defaults_for_absent_keys() {
    let dir = tempfile::tempdir().unwrap();
    let admin = ConfigAdmin::new(write_config(&dir, "[storage]\nsoft_quota_gb = 50\n"));
    let cfg = admin.read_editable().unwrap();
    let defaults = viaticum_core::config::AppConfig::default();
    assert_eq!(cfg.storage.soft_quota_gb, 50.0);
    assert_eq!(
        cfg.storage.disk_reserve_gb,
        defaults.storage.disk_reserve_gb
    );
    assert_eq!(cfg.network.listen_port, defaults.network.listen_port);
}

fn matches_unreadable(err: &ConfigAdminError, field: &str) {
    match err {
        ConfigAdminError::Unreadable { field: f, .. } => assert_eq!(f, field),
        other => panic!("expected Unreadable, got {other:?}"),
    }
}

// Mutation: read_gb falls back to the default for a non-number → Ok, test red.
#[test]
fn read_editable_refuses_non_number_quota_instead_of_default() {
    let dir = tempfile::tempdir().unwrap();
    let admin = ConfigAdmin::new(write_config(&dir, "[storage]\nsoft_quota_gb = \"50\"\n"));
    let err = admin.read_editable().unwrap_err();
    matches_unreadable(&err, "storage.soft_quota_gb");
}

// Mutation: read_port falls back to the default for an out-of-range port → Ok, red.
#[test]
fn read_editable_refuses_out_of_range_port_instead_of_default() {
    let dir = tempfile::tempdir().unwrap();
    let admin = ConfigAdmin::new(write_config(&dir, "[network]\nlisten_port = 70000\n"));
    let err = admin.read_editable().unwrap_err();
    matches_unreadable(&err, "network.listen_port");
}
