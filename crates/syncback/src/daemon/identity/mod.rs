// Identity + Init module.
//
// Manages the node's persistent identity: BIP39 mnemonic, derived seed,
// master identity public key, and stable device ID.
//
// Files created under data_dir:
//   identity.key  — CBOR-encoded IdentityKeyFile (mode 0600)
//   config.toml   — default daemon config (written only if absent)

use std::path::{Path, PathBuf};

use syncback_core::cluster::{derive_device_key, derive_epoch_key, derive_iroh_key, derive_master_key, master_identity, EpochCounter};
use syncback_core::types::DeviceId;

#[cfg(test)]
mod tests;

// ============================================================
// Public types
// ============================================================

/// Persistent identity stored at <data_dir>/identity.key.
///
/// The file is CBOR-encoded with Unix permissions 0600.
/// Note: Debug output includes the mnemonic — do not log in production.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Debug))]
pub struct IdentityKeyFile {
    /// 24 BIP39 words, space-separated (English).
    pub mnemonic: String,
    /// 64-byte BIP39 seed derived from mnemonic with empty passphrase.
    /// Stored as Vec<u8> so ciborium encodes it as a CBOR bytes value.
    pub seed: Vec<u8>,
    /// master_identity(derive_master_key(&seed)).0 — Ed25519 verifying key.
    pub identity_pub: [u8; 32],
    /// Random 16-byte device identifier, stable per installation.
    pub device_id: [u8; 16],
    /// Unix timestamp of when init was run.
    pub created_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("already initialized: {0}")]
    AlreadyInitialized(PathBuf),

    #[error("not initialized: run 'syncback init' first")]
    NotInitialized,

    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("key derivation error: {0}")]
    KeyDerivation(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cbor error: {0}")]
    Cbor(String),
}

// ============================================================
// Public API
// ============================================================

/// Generate a new identity with a random 24-word BIP39 mnemonic.
///
/// Writes `<data_dir>/identity.key` (mode 0600) and a default
/// `<data_dir>/config.toml` (only if absent).
/// Returns `IdentityError::AlreadyInitialized` if identity.key already exists.
pub fn init_identity(data_dir: &Path) -> Result<IdentityKeyFile, IdentityError> {
    use rand::RngCore;
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .map_err(|e| IdentityError::InvalidMnemonic(e.to_string()))?;
    create_keyfile(data_dir, &mnemonic)
}

/// Initialize from an existing 24-word BIP39 mnemonic (for DR restore / Docker testing).
///
/// Same behaviour as `init_identity` but uses the supplied mnemonic instead of generating one.
pub fn init_identity_from_mnemonic(
    data_dir: &Path,
    mnemonic: &str,
) -> Result<IdentityKeyFile, IdentityError> {
    let mnemonic = bip39::Mnemonic::parse(mnemonic)
        .map_err(|e| IdentityError::InvalidMnemonic(e.to_string()))?;
    if mnemonic.word_count() != 24 {
        return Err(IdentityError::InvalidMnemonic(format!(
            "expected 24 words, got {}",
            mnemonic.word_count()
        )));
    }
    create_keyfile(data_dir, &mnemonic)
}

/// Load an existing identity from `<data_dir>/identity.key`.
///
/// Returns `IdentityError::NotInitialized` if the file does not exist.
pub fn load_identity(data_dir: &Path) -> Result<IdentityKeyFile, IdentityError> {
    let path = keyfile_path(data_dir);
    let bytes = std::fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            IdentityError::NotInitialized
        } else {
            IdentityError::Io(e)
        }
    })?;
    ciborium::de::from_reader(bytes.as_slice()).map_err(|e| IdentityError::Cbor(e.to_string()))
}

/// Derive the four active keys from a loaded keyfile for a given epoch.
///
/// Returns:
///   - `master_signing_key` — Ed25519 signing key for the master identity
///   - `device_signing_key` — Ed25519 signing key for this device
///   - `epoch_key_bytes`    — 32-byte ChaCha20 symmetric key for `epoch`
///   - `iroh_key_bytes`     — 32-byte raw bytes for `iroh::SecretKey`
pub fn derive_keys(
    keyfile: &IdentityKeyFile,
    epoch: u32,
) -> Result<(ed25519_dalek::SigningKey, ed25519_dalek::SigningKey, [u8; 32], [u8; 32]), IdentityError> {
    let master_key = derive_master_key(&keyfile.seed)
        .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    let device_key = derive_device_key(&keyfile.seed, &DeviceId(keyfile.device_id))
        .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    let epoch_key = derive_epoch_key(&keyfile.seed, EpochCounter(epoch))
        .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    let iroh_key_bytes = derive_iroh_key(&keyfile.seed, &DeviceId(keyfile.device_id))
        .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    Ok((master_key, device_key, epoch_key.key_bytes, iroh_key_bytes))
}

// ============================================================
// Internal helpers
// ============================================================

fn keyfile_path(data_dir: &Path) -> PathBuf {
    data_dir.join("identity.key")
}

/// Shared logic for init_identity and init_identity_from_mnemonic.
fn create_keyfile(
    data_dir: &Path,
    mnemonic: &bip39::Mnemonic,
) -> Result<IdentityKeyFile, IdentityError> {
    let path = keyfile_path(data_dir);
    if path.exists() {
        return Err(IdentityError::AlreadyInitialized(path));
    }

    std::fs::create_dir_all(data_dir)?;

    // BIP39 seed: 64 bytes from mnemonic with empty passphrase.
    let seed_arr: [u8; 64] = mnemonic.to_seed("");
    let seed = seed_arr.to_vec();

    // Derive identity public key.
    let master_key = derive_master_key(&seed)
        .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    let identity_pub = master_identity(&master_key).0;

    // Stable random device ID for this installation.
    let device_id: [u8; 16] = rand::random();

    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let keyfile = IdentityKeyFile {
        mnemonic: mnemonic.to_string(),
        seed,
        identity_pub,
        device_id,
        created_at,
    };

    // Serialize to CBOR.
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&keyfile, &mut buf)
        .map_err(|e| IdentityError::Cbor(e.to_string()))?;

    // Write with restricted permissions (0600).
    write_secret_file(&path, &buf)?;

    // Write default config.toml if absent.
    let config_path = data_dir.join("config.toml");
    if !config_path.exists() {
        std::fs::write(&config_path, DEFAULT_CONFIG_TOML)?;
    }

    Ok(keyfile)
}

/// Write `contents` to `path` with Unix permissions 0600.
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<(), IdentityError> {
    use std::fs::OpenOptions;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        use std::io::Write;
        file.write_all(contents)?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)?;
    }

    Ok(())
}

const DEFAULT_CONFIG_TOML: &str = r#"# SyncBack configuration
# Generated automatically — edit as needed.

[daemon]
# data_dir = "~/.syncback"
# socket_path = "~/.syncback/syncback.sock"
# log_level = "info"

[storage]
# soft_quota_gb = 50
# reserve_gb = 10
"#;
