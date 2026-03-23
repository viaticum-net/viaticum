// Tests for daemon/identity module.

use std::os::unix::fs::PermissionsExt;

use super::{
    derive_keys, init_identity, init_identity_from_mnemonic, load_identity, IdentityError,
};

fn tmp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

// ============================================================
// init_identity tests
// ============================================================

#[test]
fn init_creates_keyfile_and_is_deserializable() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");

    let key_path = dir.path().join("identity.key");
    assert!(key_path.exists(), "identity.key should be created");

    // Should be CBOR-deserializable (load_identity exercises this).
    let loaded = load_identity(dir.path()).expect("load_identity");
    assert_eq!(loaded.mnemonic, keyfile.mnemonic);
    assert_eq!(loaded.identity_pub, keyfile.identity_pub);
    assert_eq!(loaded.device_id, keyfile.device_id);
}

#[test]
fn init_creates_keyfile_with_restricted_permissions() {
    let dir = tmp_dir();
    init_identity(dir.path()).expect("init_identity");

    let key_path = dir.path().join("identity.key");
    let metadata = std::fs::metadata(&key_path).expect("metadata");
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "identity.key must have mode 0600, got {mode:03o}");
}

#[test]
fn mnemonic_is_24_words() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");

    let word_count = keyfile.mnemonic.split_whitespace().count();
    assert_eq!(word_count, 24, "mnemonic must be 24 words, got {word_count}");
}

#[test]
fn init_rejects_duplicate() {
    let dir = tmp_dir();
    init_identity(dir.path()).expect("first init_identity");

    let result = init_identity(dir.path());
    assert!(
        matches!(result, Err(IdentityError::AlreadyInitialized(_))),
        "second init should return AlreadyInitialized, got {result:?}"
    );
}

// ============================================================
// init_identity_from_mnemonic tests
// ============================================================

#[test]
fn init_from_mnemonic_is_deterministic() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";

    let dir1 = tmp_dir();
    let dir2 = tmp_dir();

    let kf1 = init_identity_from_mnemonic(dir1.path(), mnemonic).expect("init1");
    let kf2 = init_identity_from_mnemonic(dir2.path(), mnemonic).expect("init2");

    assert_eq!(kf1.identity_pub, kf2.identity_pub, "same mnemonic → same identity_pub");
    assert_eq!(kf1.seed, kf2.seed, "same mnemonic → same seed");
}

#[test]
fn init_from_mnemonic_rejects_duplicate() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";

    let dir = tmp_dir();
    init_identity_from_mnemonic(dir.path(), mnemonic).expect("first init");

    let result = init_identity_from_mnemonic(dir.path(), mnemonic);
    assert!(
        matches!(result, Err(IdentityError::AlreadyInitialized(_))),
        "second init should return AlreadyInitialized"
    );
}

#[test]
fn invalid_mnemonic_returns_error() {
    let dir = tmp_dir();
    let result = init_identity_from_mnemonic(dir.path(), "not a valid bip39 mnemonic at all here");
    assert!(
        matches!(result, Err(IdentityError::InvalidMnemonic(_))),
        "garbage mnemonic should return InvalidMnemonic, got {result:?}"
    );
}

#[test]
fn wrong_word_count_returns_error() {
    // 12 words — valid BIP39 but not 24 words.
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
    let dir = tmp_dir();
    let result = init_identity_from_mnemonic(dir.path(), mnemonic);
    assert!(
        matches!(result, Err(IdentityError::InvalidMnemonic(_))),
        "12-word mnemonic should return InvalidMnemonic, got {result:?}"
    );
}

// ============================================================
// load_identity tests
// ============================================================

#[test]
fn load_roundtrips_all_fields() {
    let dir = tmp_dir();
    let original = init_identity(dir.path()).expect("init_identity");

    let loaded = load_identity(dir.path()).expect("load_identity");

    assert_eq!(loaded.mnemonic, original.mnemonic);
    assert_eq!(loaded.seed, original.seed);
    assert_eq!(loaded.identity_pub, original.identity_pub);
    assert_eq!(loaded.device_id, original.device_id);
    assert_eq!(loaded.created_at, original.created_at);
}

#[test]
fn load_not_initialized_returns_error() {
    let dir = tmp_dir();
    let result = load_identity(dir.path());
    assert!(
        matches!(result, Err(IdentityError::NotInitialized)),
        "missing identity.key should return NotInitialized, got {result:?}"
    );
}

// ============================================================
// derive_keys tests
// ============================================================

#[test]
fn derive_keys_deterministic() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");

    let (master1, device1, epoch1, _) = derive_keys(&keyfile, 0).expect("derive_keys first");
    let (master2, device2, epoch2, _) = derive_keys(&keyfile, 0).expect("derive_keys second");

    assert_eq!(
        master1.verifying_key().to_bytes(),
        master2.verifying_key().to_bytes(),
        "master key must be deterministic"
    );
    assert_eq!(
        device1.verifying_key().to_bytes(),
        device2.verifying_key().to_bytes(),
        "device key must be deterministic"
    );
    assert_eq!(epoch1, epoch2, "epoch key must be deterministic");
}

#[test]
fn derive_keys_differ_per_epoch() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");

    let (_, _, epoch_key_0, _) = derive_keys(&keyfile, 0).expect("derive epoch 0");
    let (_, _, epoch_key_1, _) = derive_keys(&keyfile, 1).expect("derive epoch 1");

    assert_ne!(epoch_key_0, epoch_key_1, "different epochs must produce different epoch keys");
}

#[test]
fn derive_keys_master_matches_identity_pub() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");

    let (master_key, _, _, _) = derive_keys(&keyfile, 0).expect("derive_keys");
    let derived_pub = master_key.verifying_key().to_bytes();

    assert_eq!(
        derived_pub, keyfile.identity_pub,
        "master verifying key must match stored identity_pub"
    );
}

// ============================================================
// derive_keys iroh key tests
// ============================================================

#[test]
fn derive_keys_returns_iroh_key() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");
    let (_master, _device, _epoch, iroh) = derive_keys(&keyfile, 0).expect("derive_keys");
    assert_eq!(iroh.len(), 32, "iroh key must be 32 bytes");
}

#[test]
fn derive_keys_iroh_key_is_deterministic() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");
    let (_, _, _, iroh1) = derive_keys(&keyfile, 0).expect("first call");
    let (_, _, _, iroh2) = derive_keys(&keyfile, 0).expect("second call");
    assert_eq!(iroh1, iroh2, "iroh key must be deterministic");
}

#[test]
fn derive_keys_iroh_key_differs_from_device_key() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");
    let (_, device, _, iroh) = derive_keys(&keyfile, 0).expect("derive_keys");
    assert_ne!(
        iroh,
        device.to_bytes(),
        "iroh key bytes must differ from device signing key bytes"
    );
}

// ─── ID-07: two different 24-word mnemonics produce different identities ──────

#[test]
fn bip39_24_words_produce_unique_identity() {
    // Generate two different identities from two different 24-word mnemonics.
    // Each must produce a unique identity_pub.
    let mnemonic_a = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon art";

    let mnemonic_b = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
                      zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";

    let dir_a = tmp_dir();
    let dir_b = tmp_dir();

    let kf_a = init_identity_from_mnemonic(dir_a.path(), mnemonic_a).expect("init a");
    let kf_b = init_identity_from_mnemonic(dir_b.path(), mnemonic_b).expect("init b");

    assert_ne!(
        kf_a.identity_pub, kf_b.identity_pub,
        "different mnemonics must produce different identity_pub"
    );
    assert_ne!(
        kf_a.seed, kf_b.seed,
        "different mnemonics must produce different seeds"
    );
}
