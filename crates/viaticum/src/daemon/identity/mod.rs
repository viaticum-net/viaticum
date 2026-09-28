// Identity + Init module.
//
// Manages the node's persistent identity: BIP39 mnemonic, derived seed,
// master identity public key, and stable device ID.
//
// Files created under data_dir:
//   identity.key  — CBOR-encoded IdentityKeyFile (mode 0600)
//   config.toml   — default daemon config (written only if absent)

use std::path::{Path, PathBuf};

use viaticum_core::cluster::{
    EpochCounter, derive_device_key, derive_epoch_key, derive_master_key, master_identity,
};

#[cfg(test)]
mod tests;

// ============================================================
// Data-directory layout
// ============================================================
//
// The one place these names are spelled. The watcher recognizes a Viaticum data
// directory (its own, a sibling's, one left behind by a move or a DR) by these
// names and keeps it out of the backup (backup-i13): a name changed here changes
// what the watcher looks for.

/// The node's identity (mnemonic, seed, device seed) — `IdentityKeyFile`, CBOR.
pub const KEYFILE_NAME: &str = "identity.key";
/// The catalog database (redb).
pub const DB_FILE_NAME: &str = "db.redb";
/// Daemon configuration.
pub const CONFIG_FILE_NAME: &str = "config.toml";
/// Symbols this node holds for other owners: `holdings/{block_hex}/{esi}.bin`.
pub const HOLDINGS_DIR_NAME: &str = "holdings";
/// Owner-side symbol cache (transitional, W11b).
pub const SYMBOLS_DIR_NAME: &str = "symbols";
/// Restore staging: `restore/<job>/…`.
pub const RESTORE_STAGING_DIR_NAME: &str = "restore";
/// Retained SystemState block blobs.
pub const SYSTEM_STATE_DIR_NAME: &str = "system_state";

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

/// Why a recovery phrase was rejected. `Display` is the friend-facing reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MnemonicProblem {
    /// Not exactly 24 words after normalization.
    WordCount {
        got: usize,
    },
    /// `position` is 1-based.
    UnknownWord {
        position: usize,
        word: String,
    },
    /// All words are in the list but the BIP39 checksum does not match.
    Checksum,
    Other(String),
}

impl std::fmt::Display for MnemonicProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MnemonicProblem::WordCount { got } => write!(f, "expected 24 words, got {got}"),
            MnemonicProblem::UnknownWord { position, word } => {
                write!(
                    f,
                    "word {position} (\"{word}\") is not in the BIP39 word list"
                )
            }
            MnemonicProblem::Checksum => write!(
                f,
                "the words are all valid but do not form a valid phrase (checksum mismatch): \
                 most likely one word is wrong or two are swapped"
            ),
            MnemonicProblem::Other(msg) => write!(f, "{msg}"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("already initialized: {0}")]
    AlreadyInitialized(PathBuf),

    #[error("{}", corrupt_key_hint(.0, .1))]
    Corrupt(PathBuf, String),

    #[error(
        "{} already holds a catalog (db.redb) but no identity.key: run 'viaticum dr' with \
         your recovery phrase, or move db.redb away",
        .0.display()
    )]
    CatalogWithoutKey(PathBuf),

    #[error("not initialized: run 'viaticum init' first")]
    NotInitialized,

    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(MnemonicProblem),

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
    use rand_core::RngCore;
    let mut entropy = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .map_err(|e| IdentityError::InvalidMnemonic(MnemonicProblem::Other(e.to_string())))?;
    install_keyfile(data_dir, &mnemonic, DeviceSeedMode::Random)
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
    let mnemonic = parse_mnemonic(mnemonic)?;
    install_keyfile(data_dir, &mnemonic, DeviceSeedMode::Random)
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
    let mnemonic = parse_mnemonic(mnemonic)?;
    install_keyfile(data_dir, &mnemonic, DeviceSeedMode::DerivedFromSeed)
}

/// Trim, lowercase and collapse every whitespace run to one space. Pure.
pub fn normalize_phrase(s: &str) -> String {
    s.split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse a recovery phrase: `normalize_phrase`, exactly 24 words, every word in the
/// English BIP39 list, valid checksum. The error names the first problem in the
/// friend's terms (word position is 1-based). No "closest word" guessing.
pub fn parse_mnemonic(s: &str) -> Result<bip39::Mnemonic, IdentityError> {
    let normalized = normalize_phrase(s);
    let words: Vec<&str> = normalized.split(' ').filter(|w| !w.is_empty()).collect();
    if words.len() != 24 {
        return Err(IdentityError::InvalidMnemonic(MnemonicProblem::WordCount {
            got: words.len(),
        }));
    }
    bip39::Mnemonic::parse(normalized.as_str()).map_err(|e| {
        let problem = match e {
            bip39::Error::BadWordCount(got) => MnemonicProblem::WordCount { got },
            bip39::Error::UnknownWord(i) => MnemonicProblem::UnknownWord {
                position: i + 1,
                word: words.get(i).map(|w| (*w).to_string()).unwrap_or_default(),
            },
            bip39::Error::InvalidChecksum => MnemonicProblem::Checksum,
            other => MnemonicProblem::Other(other.to_string()),
        };
        IdentityError::InvalidMnemonic(problem)
    })
}

/// How the device seed of a new keyfile is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceSeedMode {
    /// Fresh random device (plain `init`, `init --new-device`).
    Random,
    /// `HKDF(seed, "viaticum-device-seed-v1")`: the same phrase always yields the same
    /// device id (DR, `init --mnemonic`).
    DerivedFromSeed,
}

/// Compute a keyfile for `m` without touching the disk.
pub fn build_keyfile(
    m: &bip39::Mnemonic,
    mode: DeviceSeedMode,
) -> Result<IdentityKeyFile, IdentityError> {
    // BIP39 seed: 64 bytes from mnemonic with empty passphrase.
    let seed_arr: [u8; 64] = m.to_seed("");
    let seed = seed_arr.to_vec();

    // Derive identity public key.
    let master_key =
        derive_master_key(&seed).map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    let identity_pub = master_identity(&master_key).0;

    // device_id = derive_device_key(seed, device_seed).verifying_key().to_bytes()
    let device_seed: [u8; 32] = match mode {
        DeviceSeedMode::DerivedFromSeed => {
            use hkdf::Hkdf;
            use sha2::Sha256;
            let hkdf = Hkdf::<Sha256>::new(None, &seed);
            let mut seed_out = [0u8; 32];
            hkdf.expand(b"viaticum-device-seed-v1", &mut seed_out)
                .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
            seed_out
        }
        DeviceSeedMode::Random => rand::random(),
    };

    let device_key = derive_device_key(&seed, &device_seed)
        .map_err(|e| IdentityError::KeyDerivation(e.to_string()))?;
    let device_id: [u8; 32] = device_key.verifying_key().to_bytes();

    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(IdentityKeyFile {
        mnemonic: m.to_string(),
        seed,
        identity_pub,
        device_seed,
        device_id,
        created_at,
    })
}

/// Write `kf` as CBOR to `path` with mode 0600, never overwriting:
/// an existing file → `AlreadyInitialized(path)`.
pub fn write_keyfile_at(path: &Path, kf: &IdentityKeyFile) -> Result<(), IdentityError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(kf, &mut buf).map_err(|e| IdentityError::Cbor(e.to_string()))?;
    write_secret_file(path, &buf).map_err(|e| match e {
        IdentityError::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists => {
            IdentityError::AlreadyInitialized(path.to_path_buf())
        }
        other => other,
    })
}

/// Write the default `config.toml` into `data_dir` unless one exists.
pub fn write_default_config_if_absent(data_dir: &Path) -> Result<(), IdentityError> {
    let config_path = data_dir.join(CONFIG_FILE_NAME);
    if !config_path.exists() {
        std::fs::write(&config_path, DEFAULT_CONFIG_TOML)?;
    }
    Ok(())
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

/// What the friend reads when `identity.key` exists but cannot be used (daemon start,
/// `init`). Never suggests deleting it: the key may be recoverable, and a new identity
/// leaves every backup under the old one.
pub fn corrupt_key_hint(path: &Path, reason: &str) -> String {
    format!(
        "identity file at {} is corrupt or from an incompatible binary version ({reason}). \
         Do not delete it. Move it away (e.g. identity.key.broken) and run 'viaticum dr' \
         with your recovery phrase. If the file was written by a newer Viaticum, update the \
         binary instead. 'viaticum init' creates a NEW identity: your backups stay under \
         the old one.",
        path.display()
    )
}

/// What the daemon says when `data_dir` has no `identity.key`. A folder that still
/// holds a catalog (`db.redb`) lost its key: recovery (`dr`) comes first there.
pub fn not_initialized_hint(data_dir: &Path) -> String {
    if data_dir.join(DB_FILE_NAME).exists() {
        format!(
            "identity not initialized, but {} already holds a catalog (db.redb): run \
             'viaticum dr' with your recovery phrase to recover it. 'viaticum init' would \
             create a NEW identity and refuses while db.redb is there.",
            data_dir.display()
        )
    } else {
        "identity not initialized: run 'viaticum init' to create a new identity, or \
         'viaticum dr' to recover an existing one from its recovery phrase"
            .to_string()
    }
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
    data_dir.join(KEYFILE_NAME)
}

/// Shared logic of the three `init_identity*`: refuse an existing keyfile (telling a
/// valid one from an unusable one), then build and write a new one plus the default
/// config.
fn install_keyfile(
    data_dir: &Path,
    mnemonic: &bip39::Mnemonic,
    mode: DeviceSeedMode,
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

    // A catalog without its key is a node that lost identity.key: a new identity
    // here would silently start a new, empty history over it (dr-i30).
    if data_dir.join(DB_FILE_NAME).exists() {
        return Err(IdentityError::CatalogWithoutKey(data_dir.to_path_buf()));
    }

    std::fs::create_dir_all(data_dir)?;
    let keyfile = build_keyfile(mnemonic, mode)?;
    write_keyfile_at(&path, &keyfile)?;
    write_default_config_if_absent(data_dir)?;
    Ok(keyfile)
}

/// Write `contents` to a NEW file at `path` (never overwrites) with Unix permissions
/// 0600.
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
        // A key installed by rename/link must never surface empty after a crash.
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }

    Ok(())
}

const DEFAULT_CONFIG_TOML: &str = r#"# Viaticum configuration
# Generated automatically — edit as needed.

[daemon]
# data_dir defaults to platform-native:
#   Linux:   ~/.local/share/viaticum
#   macOS:   ~/Library/Application Support/viaticum
#   Windows: %APPDATA%/viaticum
# log_level = "info"

[storage]
# soft_quota_gb = 50
# reserve_gb = 10

[web_api]
# enabled = true          # then CLI can talk to the daemon over HTTP
# bind = "127.0.0.1:0"    # loopback, random port (default when enabled)
# bind = "0.0.0.0:8080"   # opt-in LAN/NAS access — token auth still required
"#;
