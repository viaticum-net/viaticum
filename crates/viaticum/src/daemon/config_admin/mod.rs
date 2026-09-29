// ConfigAdmin: read and write the editable subset of config.toml from the web API.
//
// Only three fields are exposed: `storage.disk_reserve_gb`, `storage.soft_quota_gb`
// and `network.listen_port`. Other sections (web_api, [[watch]], legacy ones, ...) are
// preserved as-is via toml_edit. Writes are atomic (tempfile + rename) and serialised
// across concurrent requests by an internal Mutex.

use std::path::{Path, PathBuf};

use tokio::sync::Mutex;

#[cfg(test)]
mod tests;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ConfigAdminError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse error: {0}")]
    TomlParse(#[from] toml_edit::TomlError),

    #[error("validation: {field}: {msg}")]
    Validation { field: String, msg: String },

    /// A field is present in config.toml but holds a value the editor cannot
    /// represent. Reported instead of silently substituting the default, which a
    /// later Save would write back over the user's value (daemon-i10).
    #[error("config field {field} is not {expected}")]
    Unreadable {
        field: String,
        expected: &'static str,
    },
}

// ─── Public types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EditableConfig {
    pub storage: StorageEditable,
    pub network: NetworkEditable,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StorageEditable {
    pub disk_reserve_gb: f64,
    pub soft_quota_gb: f64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NetworkEditable {
    pub listen_port: u16,
}

// ─── ConfigAdmin ──────────────────────────────────────────────────────────────

pub struct ConfigAdmin {
    config_path: PathBuf,
    write_lock: Mutex<()>,
}

impl ConfigAdmin {
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            config_path,
            write_lock: Mutex::new(()),
        }
    }

    /// Read the editable subset from the live config file.
    ///
    /// If the file is missing, returns the runtime defaults from `AppConfig::default()`
    /// for the editable subset (so the UI can render something sensible on a fresh
    /// install with no config.toml yet).
    pub fn read_editable(&self) -> Result<EditableConfig, ConfigAdminError> {
        if !self.config_path.exists() {
            let defaults = viaticum_core::config::AppConfig::default();
            return Ok(EditableConfig {
                storage: StorageEditable {
                    disk_reserve_gb: defaults.storage.disk_reserve_gb,
                    soft_quota_gb: defaults.storage.soft_quota_gb,
                },
                network: NetworkEditable {
                    listen_port: defaults.network.listen_port,
                },
            });
        }
        let raw = std::fs::read_to_string(&self.config_path)?;
        let doc: toml_edit::DocumentMut = raw.parse()?;
        let defaults = viaticum_core::config::AppConfig::default();

        let disk_reserve_gb = read_gb(&doc, "storage", "disk_reserve_gb")?
            .unwrap_or(defaults.storage.disk_reserve_gb);
        let soft_quota_gb =
            read_gb(&doc, "storage", "soft_quota_gb")?.unwrap_or(defaults.storage.soft_quota_gb);
        let listen_port =
            read_port(&doc, "network", "listen_port")?.unwrap_or(defaults.network.listen_port);

        Ok(EditableConfig {
            storage: StorageEditable {
                disk_reserve_gb,
                soft_quota_gb,
            },
            network: NetworkEditable { listen_port },
        })
    }

    /// Validate, then atomically write the new editable subset back to config.toml.
    /// Other sections (comments, [[watch]], legacy ones, ...) are preserved verbatim.
    pub async fn update(&self, new: EditableConfig) -> Result<(), ConfigAdminError> {
        let _guard = self.write_lock.lock().await;

        let mut doc: toml_edit::DocumentMut = if self.config_path.exists() {
            let raw = std::fs::read_to_string(&self.config_path)?;
            raw.parse()?
        } else {
            toml_edit::DocumentMut::new()
        };

        // Cross-field check: listen_port must not collide with web_api.bind port.
        let web_bind: Option<String> = doc
            .get("web_api")
            .and_then(|v| v.get("bind"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        validate(&new, web_bind.as_deref())?;

        // Backup current config.toml to config.toml.bak before overwriting.
        // Skipped when the file does not yet exist (fresh install — nothing to back up).
        // Overwrites any previous .bak so .bak always reflects the last confirmed-written config.
        // Failure here is returned as Io error; the old config is left untouched (safe-fail).
        if self.config_path.exists() {
            std::fs::copy(&self.config_path, bak_sibling(&self.config_path))?;
        }

        // Ensure section tables exist so the field assignments below don't panic
        // on a freshly-created (empty) document.
        if !doc.contains_key("storage") {
            doc.insert("storage", toml_edit::Item::Table(toml_edit::Table::new()));
        }
        if !doc.contains_key("network") {
            doc.insert("network", toml_edit::Item::Table(toml_edit::Table::new()));
        }

        doc["storage"]["disk_reserve_gb"] = toml_edit::value(new.storage.disk_reserve_gb);
        doc["storage"]["soft_quota_gb"] = toml_edit::value(new.storage.soft_quota_gb);
        doc["network"]["listen_port"] = toml_edit::value(new.network.listen_port as i64);

        // Atomic write: tempfile in same directory + rename.
        let tmp = tmp_sibling(&self.config_path);
        std::fs::write(&tmp, doc.to_string())?;
        std::fs::rename(&tmp, &self.config_path)?;
        Ok(())
    }
}

/// A gigabyte amount at `[section].key`: `None` when absent, the value when it is a
/// TOML float or integer (`50` and `50.0` are the same amount, as the daemon's own
/// serde parse reads them), `Unreadable` for any other type.
fn read_gb(
    doc: &toml_edit::DocumentMut,
    section: &str,
    key: &str,
) -> Result<Option<f64>, ConfigAdminError> {
    let Some(item) = doc.get(section).and_then(|s| s.get(key)) else {
        return Ok(None);
    };
    if let Some(f) = item.as_float() {
        return Ok(Some(f));
    }
    if let Some(i) = item.as_integer() {
        return Ok(Some(i as f64));
    }
    Err(ConfigAdminError::Unreadable {
        field: format!("{section}.{key}"),
        expected: "a number",
    })
}

/// A port at `[section].key`: `None` when absent, the value when it is a TOML
/// integer in `0..=65535`, `Unreadable` otherwise (the daemon would refuse it too).
fn read_port(
    doc: &toml_edit::DocumentMut,
    section: &str,
    key: &str,
) -> Result<Option<u16>, ConfigAdminError> {
    let Some(item) = doc.get(section).and_then(|s| s.get(key)) else {
        return Ok(None);
    };
    item.as_integer()
        .and_then(|i| u16::try_from(i).ok())
        .map(Some)
        .ok_or_else(|| ConfigAdminError::Unreadable {
            field: format!("{section}.{key}"),
            expected: "a port number (integer 0..=65535)",
        })
}

fn tmp_sibling(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

fn bak_sibling(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}

// ─── Validation ───────────────────────────────────────────────────────────────

pub fn validate(
    cfg: &EditableConfig,
    current_web_bind: Option<&str>,
) -> Result<(), ConfigAdminError> {
    if !cfg.storage.disk_reserve_gb.is_finite()
        || cfg.storage.disk_reserve_gb < 0.0
        || cfg.storage.disk_reserve_gb > 1000.0
    {
        return Err(ConfigAdminError::Validation {
            field: "storage.disk_reserve_gb".into(),
            msg: "must be a finite number in [0, 1000]".into(),
        });
    }
    if !cfg.storage.soft_quota_gb.is_finite()
        || cfg.storage.soft_quota_gb < 0.0
        || cfg.storage.soft_quota_gb > 100_000.0
    {
        return Err(ConfigAdminError::Validation {
            field: "storage.soft_quota_gb".into(),
            msg: "must be a finite number in [0, 100000]".into(),
        });
    }
    // listen_port: allow 0 (meaning ephemeral, OS-chosen). Reject only obviously
    // invalid values — u16 already constrains the upper bound.
    if let Some(web_bind) = current_web_bind
        && let Some(web_port) = web_bind
            .rsplit(':')
            .next()
            .and_then(|s| s.parse::<u16>().ok())
    {
        // Only flag a collision when the user picked a real port (not 0).
        if cfg.network.listen_port != 0 && web_port == cfg.network.listen_port {
            return Err(ConfigAdminError::Validation {
                field: "network.listen_port".into(),
                msg: format!("collides with web_api.bind port {web_port}"),
            });
        }
    }
    Ok(())
}
