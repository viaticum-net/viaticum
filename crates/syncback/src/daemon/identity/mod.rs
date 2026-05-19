// Identity + Init module.
//
// Manages the node's persistent identity: BIP39 mnemonic, derived seed,
// master identity public key, and stable device ID.
//
// Files created under data_dir:
//   identity.key  — CBOR-encoded IdentityKeyFile (mode 0600)
//   config.toml   — default daemon config (written only if absent)

use std::path::{Path, PathBuf};

use syncback_core::cluster::{
    EpochCounter, derive_device_key, derive_epoch_key, derive_master_key, master_identity,
};

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
    /// Random 32-byte device seed. Used to derive device signing key.
    /// device_id = derive_device_key(seed, device_seed).verifying_key().to_bytes()
    pub device_seed: [u8; 32],
    /// Ed25519 public key of the device signing key. 32 bytes.
    /// Equals derive_device_key(seed, device_seed).verifying_key().to_bytes().
    pub device_id: [u8; 32],
    /// Unix timestamp of when init was run.
    pub created_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("already initialized: {0}")]
    AlreadyInitialized(PathBuf),

    #[error(
        "identity file at {0} is corrupt or from an incompatible binary version: {1}. \
            Delete the file and re-run 'syncback init', or restore it from a backup."
    )]
    Corrupt(PathBuf, String),

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
    create_keyfile(data_dir, &mnemonic, false)
}

/// Initialize this device as a new member of an existing cluster identified by `mnemonic`.
///
/// Uses the same BIP39 mnemonic as the existing cluster, so `identity_pub` matches.
/// Generates a fresh random `device_id`, giving this device its own unique device key
/// and libp2p PeerId. Writes `<data_dir>/identity.key` (mode 0600).
///
/// Returns `IdentityError::AlreadyInitialized` if identity.key already exists.
/// Returns `IdentityError::InvalidMnemonic` if mnemonic is not valid 24-word BIP39.
pub fn init_identity_new_device(
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
    create_keyfile(data_dir, &mnemonic, false)
}

/// Initialize from an existing 24-word BIP39 mnemonic (for DR restore / Docker testing).
///
/// Same behaviour as `init_identity` but uses the supplied mnemonic instead of
/// generating one. The device_id is derived deterministically from the seed
/// (via HKDF) so that DR restores produce the same handshake identity as the
/// original node. This is critical for SystemState blob lookup.
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
    create_keyfile(data_dir, &mnemonic, true)
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
    ciborium::de::from_reader(bytes.as_slice())
        .map_err(|e| IdentityError::Corrupt(path, e.to_string()))
}

/// Derive the three active keys from a loaded keyfile for a given epoch.
///
/// Returns:
///   - `master_signing_key` — Ed25519 signing key for the master identity
///   - `device_signing_key` — Ed25519 signing key for this device
///   - `epoch_key_bytes`    — 32-byte ChaCha20 symmetric key for `epoch`
pub fn derive_keys(
    keyfile: &IdentityKeyFile,
    epoch: u32,
) -> Result<
    (
        ed25519_dalek::SigningKey,
        ed25519_dalek::SigningKey,
        [u8; 32],
    ),
    IdentityError,
> {
    let master_key = derive_master_key(&keyfile.seed)
        .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    let device_key = derive_device_key(&keyfile.seed, &keyfile.device_seed)
        .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    let epoch_key = derive_epoch_key(&keyfile.seed, EpochCounter(epoch))
        .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    Ok((master_key, device_key, epoch_key.key_bytes))
}

// ============================================================
// Internal helpers
// ============================================================

fn keyfile_path(data_dir: &Path) -> PathBuf {
    data_dir.join("identity.key")
}

/// Shared logic for init_identity and init_identity_from_mnemonic.
///
/// When `deterministic_device_id` is true, the device_id is derived from the
/// seed via HKDF so that the same mnemonic always produces the same identity
/// (critical for DR blob lookup). When false, a random device_id is generated.
fn create_keyfile(
    data_dir: &Path,
    mnemonic: &bip39::Mnemonic,
    deterministic_device_id: bool,
) -> Result<IdentityKeyFile, IdentityError> {
    let path = keyfile_path(data_dir);
    if path.exists() {
        // Distinguish "already initialized & valid" from "file exists but unusable".
        // The former is benign; the latter must be surfaced clearly so the daemon
        // doesn't later crash with a cryptic CBOR error.
        return match std::fs::read(&path) {
            Ok(bytes) => match ciborium::de::from_reader::<IdentityKeyFile, _>(bytes.as_slice()) {
                Ok(_) => Err(IdentityError::AlreadyInitialized(path)),
                Err(e) => Err(IdentityError::Corrupt(path, e.to_string())),
            },
            Err(e) => Err(IdentityError::Corrupt(path, e.to_string())),
        };
    }

    std::fs::create_dir_all(data_dir)?;

    // BIP39 seed: 64 bytes from mnemonic with empty passphrase.
    let seed_arr: [u8; 64] = mnemonic.to_seed("");
    let seed = seed_arr.to_vec();

    // Derive identity public key.
    let master_key =
        derive_master_key(&seed).map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    let identity_pub = master_identity(&master_key).0;

    // device_seed: deterministic from seed for DR restore, random for fresh init.
    // device_id = derive_device_key(seed, device_seed).verifying_key().to_bytes()
    let device_seed: [u8; 32] = if deterministic_device_id {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hkdf = Hkdf::<Sha256>::new(None, &seed);
        let mut seed_out = [0u8; 32];
        hkdf.expand(b"syncback-device-seed-v1", &mut seed_out)
            .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
        seed_out
    } else {
        rand::random()
    };

    let device_key = derive_device_key(&seed, &device_seed)
        .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    let device_id: [u8; 32] = device_key.verifying_key().to_bytes();

    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let keyfile = IdentityKeyFile {
        mnemonic: mnemonic.to_string(),
        seed,
        identity_pub,
        device_seed,
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
/// On Windows the file inherits ACL from its parent directory; the daemon's
/// data dir lives under per-user `%APPDATA%`, which already restricts access
/// to that user.
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
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
# data_dir defaults to platform-native:
#   Linux:   ~/.local/share/syncback
#   macOS:   ~/Library/Application Support/syncback
#   Windows: %APPDATA%/syncback
# log_level = "info"

[storage]
# soft_quota_gb = 50
# reserve_gb = 10

[web_api]
# enabled = true          # then CLI can talk to the daemon over HTTP
# bind = "127.0.0.1:0"    # loopback, random port (default when enabled)
# bind = "0.0.0.0:8080"   # opt-in LAN/NAS access — token auth still required
"#;
