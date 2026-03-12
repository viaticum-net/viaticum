use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;

// ============================================================
// Error type
// ============================================================

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error(
        "~/.syncback/ already exists and is non-empty; delete it first to re-initialize"
    )]
    AlreadyInitialized,

    #[error(
        "confirmation failed: word at position {position} should be '{expected}', got '{got}'"
    )]
    ConfirmationFailed {
        position: usize,
        expected: String,
        got: String,
    },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("cbor serialization: {0}")]
    Cbor(String),
}

// ============================================================
// Key file format
// ============================================================

/// Written to ~/.syncback/identity.key.
/// CBOR-encoded. Permissions 0600.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct IdentityKeyFile {
    /// Version tag for future migration.
    pub version: u8,
    /// BIP39 mnemonic (24 words, space-separated). Stored for recovery UX.
    /// NOTE: This IS the secret. File must be 0600. Do not log.
    pub mnemonic_words: Vec<String>,
    /// Derived Ed25519 identity private key bytes (32 bytes seed).
    pub identity_priv: [u8; 32],
    /// Derived Ed25519 identity public key bytes (32 bytes).
    pub identity_pub: [u8; 32],
    /// Derived iroh private key bytes (32 bytes seed).
    pub iroh_priv: [u8; 32],
}

// ============================================================
// Default config template
// ============================================================

const DEFAULT_CONFIG_TOML: &str = r#"[backup]
include = [
  # { path = "~/Documents", importance = 1.0 },
  # { path = "~/Photos",    importance = 0.5 },
]
exclude = ["*.tmp", "node_modules", ".git"]

[storage]
quota_gb = 100

[network]
seed_nodes = []          # default: hardcoded in binary
bandwidth_limit_mbps = 0 # 0 = unlimited

[schedule]
sync   = "weekly"
vacuum = "monthly"
"#;

// ============================================================
// Public API
// ============================================================

/// Run the interactive init flow.
/// Reads from stdin, writes to stdout/stderr.
/// Returns Ok(()) on success.
pub fn run_init() -> anyhow::Result<()> {
    use bip39::Mnemonic;
    use rand::RngCore;
    use std::io::Write;

    let home = std::env::var("HOME")?;
    let syncback_dir = std::path::PathBuf::from(home).join(".syncback");

    // Guard: don't clobber existing init.
    if syncback_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(&syncback_dir)?.collect();
        if !entries.is_empty() {
            return Err(InitError::AlreadyInitialized.into());
        }
    }

    // Step 1: Generate mnemonic (256 bits = 24 words).
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| anyhow::anyhow!("bip39 error: {e}"))?;
    let words: Vec<&str> = mnemonic.words().collect();

    // Step 2: Display.
    println!("\n=== SYNCBACK INIT ===\n");
    println!(
        "Write down these 24 words on paper. This is the ONLY way to recover your data.\n"
    );
    for (i, word) in words.iter().enumerate() {
        print!("{:2}. {:12}", i + 1, word);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!("\n");

    // Step 3: Confirm 3 random words.
    let mut rng = rand::thread_rng();
    let mut chosen = std::collections::HashSet::new();
    while chosen.len() < 3 {
        chosen.insert(rng.next_u32() as usize % 24);
    }
    let mut positions: Vec<usize> = chosen.into_iter().collect();
    positions.sort_unstable();

    println!("Confirm your seed phrase by entering the requested words:\n");
    for &pos in &positions {
        print!("Word #{}: ", pos + 1);
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();
        let expected = words[pos];
        if input != expected {
            return Err(InitError::ConfirmationFailed {
                position: pos + 1,
                expected: expected.to_string(),
                got: input,
            }
            .into());
        }
    }

    // Steps 4–8: delegate to non-interactive helper.
    let key_file = init_with_mnemonic(&syncback_dir, &words)?;

    println!("\nInitialized ~/.syncback/");
    println!("Identity: {}", hex::encode(&key_file.identity_pub[..8]));
    println!("\nRun the daemon with: syncback daemon");
    println!("(Or: systemctl --user start syncback)\n");

    Ok(())
}

/// Non-interactive init for testing: takes mnemonic words, no prompts.
/// Creates the directory structure and writes key file.
/// Used by integration tests that need a known identity.
pub fn init_with_mnemonic(
    syncback_dir: &Path,
    mnemonic_words: &[&str],
) -> Result<IdentityKeyFile, InitError> {
    use bip39::Mnemonic;

    // Guard: don't clobber a non-empty directory.
    if syncback_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(syncback_dir)?.collect();
        if !entries.is_empty() {
            return Err(InitError::AlreadyInitialized);
        }
    }

    // Parse mnemonic and derive 64-byte BIP39 seed.
    let phrase = mnemonic_words.join(" ");
    let mnemonic =
        Mnemonic::parse(&phrase).map_err(|e| InitError::Cbor(e.to_string()))?;
    let seed_bytes = mnemonic.to_seed(""); // empty passphrase

    let (signing_key, iroh_priv) = derive_keys(&seed_bytes);

    let identity_priv: [u8; 32] = signing_key.to_bytes();
    let identity_pub: [u8; 32] = signing_key.verifying_key().to_bytes();

    let key_file = IdentityKeyFile {
        version: 1,
        mnemonic_words: mnemonic_words.iter().map(|s| s.to_string()).collect(),
        identity_priv,
        identity_pub,
        iroh_priv,
    };

    // Create directory.
    std::fs::create_dir_all(syncback_dir)?;

    // Write identity.key (permissions 0600).
    let key_path = syncback_dir.join("identity.key");
    let cbor = {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&key_file, &mut buf)
            .map_err(|e| InitError::Cbor(e.to_string()))?;
        buf
    };
    std::fs::write(&key_path, &cbor)?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;

    // Write default config.toml.
    let config_path = syncback_dir.join("config.toml");
    std::fs::write(&config_path, DEFAULT_CONFIG_TOML)?;

    tracing::debug!(
        identity = hex::encode(&key_file.identity_pub[..8]),
        "init: derived identity"
    );

    Ok(key_file)
}

/// Derive Ed25519 identity key and iroh key from a 64-byte BIP39 seed.
/// Returns (identity_signing_key, iroh_priv_bytes).
///
/// Uses HKDF-SHA256 with domain separation:
/// - info="syncback-identity-ed25519" → identity keypair
/// - info="syncback-iroh-ed25519"     → iroh keypair seed
pub fn derive_keys(seed_bytes: &[u8; 64]) -> (SigningKey, [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(None, seed_bytes);

    let mut identity_bytes = [0u8; 32];
    hkdf.expand(b"syncback-identity-ed25519", &mut identity_bytes)
        .expect("hkdf expand identity");

    let mut iroh_bytes = [0u8; 32];
    hkdf.expand(b"syncback-iroh-ed25519", &mut iroh_bytes)
        .expect("hkdf expand iroh");

    let signing_key = SigningKey::from_bytes(&identity_bytes);
    (signing_key, iroh_bytes)
}

/// Read the identity key file from disk.
/// Called by daemon startup to load the actual identity key.
pub fn load_identity(syncback_dir: &Path) -> Result<IdentityKeyFile, InitError> {
    let key_path = syncback_dir.join("identity.key");
    let bytes = std::fs::read(&key_path)?;
    let key_file: IdentityKeyFile = ciborium::de::from_reader(bytes.as_slice())
        .map_err(|e| InitError::Cbor(e.to_string()))?;
    Ok(key_file)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a valid 24-word BIP39 mnemonic for testing.
    /// We generate it at test time to ensure a valid checksum.
    fn test_mnemonic_words() -> Vec<String> {
        use bip39::Mnemonic;
        use rand::RngCore;
        let mut entropy = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut entropy);
        let m = Mnemonic::from_entropy(&entropy).unwrap();
        m.words().map(|s: &str| s.to_string()).collect()
    }

    #[test]
    fn derive_keys_is_deterministic() {
        let seed = [42u8; 64];
        let (key1, iroh1) = derive_keys(&seed);
        let (key2, iroh2) = derive_keys(&seed);
        assert_eq!(key1.to_bytes(), key2.to_bytes());
        assert_eq!(iroh1, iroh2);
    }

    #[test]
    fn derive_keys_different_seeds_produce_different_keys() {
        let seed_a = [1u8; 64];
        let seed_b = [2u8; 64];
        let (key_a, iroh_a) = derive_keys(&seed_a);
        let (key_b, iroh_b) = derive_keys(&seed_b);
        assert_ne!(key_a.to_bytes(), key_b.to_bytes());
        assert_ne!(iroh_a, iroh_b);
    }

    #[test]
    fn init_with_mnemonic_creates_files_with_correct_permissions() {
        let dir = tempfile::TempDir::new().unwrap();
        let words = test_mnemonic_words();
        let words_ref: Vec<&str> = words.iter().map(|s| s.as_str()).collect();

        let key_file = init_with_mnemonic(dir.path(), &words_ref).unwrap();

        let key_path = dir.path().join("identity.key");
        assert!(key_path.exists(), "identity.key should exist");

        let perms = std::fs::metadata(&key_path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "identity.key should be 0600"
        );

        let config_path = dir.path().join("config.toml");
        assert!(config_path.exists(), "config.toml should exist");

        let loaded = load_identity(dir.path()).unwrap();
        assert_eq!(
            loaded.identity_pub, key_file.identity_pub,
            "loaded identity_pub should match"
        );
        assert_eq!(
            loaded.identity_priv, key_file.identity_priv,
            "loaded identity_priv should match"
        );
    }

    #[test]
    fn init_with_mnemonic_fails_if_dir_non_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        // Create a file inside so the dir is non-empty.
        std::fs::write(dir.path().join("existing.txt"), b"data").unwrap();

        let words = test_mnemonic_words();
        let words_ref: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        let result = init_with_mnemonic(dir.path(), &words_ref);
        assert!(
            matches!(result, Err(InitError::AlreadyInitialized)),
            "should fail with AlreadyInitialized"
        );
    }

    #[test]
    fn load_identity_fails_if_key_file_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let result = load_identity(dir.path());
        assert!(
            matches!(result, Err(InitError::Io(_))),
            "should fail with Io error"
        );
    }

    #[test]
    fn init_with_mnemonic_roundtrips_mnemonic_words() {
        let dir = tempfile::TempDir::new().unwrap();
        let words = test_mnemonic_words();
        let words_ref: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        let key_file = init_with_mnemonic(dir.path(), &words_ref).unwrap();

        assert_eq!(key_file.mnemonic_words.len(), 24);
        for (i, word) in words_ref.iter().enumerate() {
            assert_eq!(&key_file.mnemonic_words[i], word);
        }
    }
}
