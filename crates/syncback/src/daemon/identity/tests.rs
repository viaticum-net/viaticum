// Tests for daemon/identity module.

use std::os::unix::fs::PermissionsExt;

use super::{
    derive_keys, init_identity, init_identity_from_mnemonic, init_identity_new_device,
    load_identity, IdentityError,
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
    assert_eq!(loaded.device_seed, keyfile.device_seed);
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
    assert_eq!(loaded.device_seed, original.device_seed);
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

    let (master1, device1, epoch1) = derive_keys(&keyfile, 0).expect("derive_keys first");
    let (master2, device2, epoch2) = derive_keys(&keyfile, 0).expect("derive_keys second");

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

    let (_, _, epoch_key_0) = derive_keys(&keyfile, 0).expect("derive epoch 0");
    let (_, _, epoch_key_1) = derive_keys(&keyfile, 1).expect("derive epoch 1");

    assert_ne!(epoch_key_0, epoch_key_1, "different epochs must produce different epoch keys");
}

#[test]
fn derive_keys_master_matches_identity_pub() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");

    let (master_key, _, _) = derive_keys(&keyfile, 0).expect("derive_keys");
    let derived_pub = master_key.verifying_key().to_bytes();

    assert_eq!(
        derived_pub, keyfile.identity_pub,
        "master verifying key must match stored identity_pub"
    );
}

#[test]
fn derive_keys_returns_three_values_not_four() {
    // Compile-time test: derive_keys returns a 3-tuple.
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");
    let (_master, _device, _epoch) = derive_keys(&keyfile, 0).expect("derive_keys");
    // If this compiles, the test passes.
}

// ============================================================
// Task A: identity-specific tests
// ============================================================

#[test]
fn init_identity_creates_32byte_device_id() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");
    assert_eq!(keyfile.device_id.len(), 32, "device_id must be 32 bytes");
    assert_eq!(keyfile.device_seed.len(), 32, "device_seed must be 32 bytes");
}

#[test]
fn device_id_equals_device_signing_key_pubkey() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");
    let (_, device_signing_key, _) = derive_keys(&keyfile, 0).expect("derive_keys");
    assert_eq!(
        device_signing_key.verifying_key().to_bytes(),
        keyfile.device_id,
        "device_id must equal device signing key's verifying key"
    );
}

#[test]
fn deterministic_device_id_is_reproducible() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";

    let dir1 = tmp_dir();
    let dir2 = tmp_dir();

    let kf1 = init_identity_from_mnemonic(dir1.path(), mnemonic).expect("init1");
    let kf2 = init_identity_from_mnemonic(dir2.path(), mnemonic).expect("init2");

    assert_eq!(
        kf1.device_id, kf2.device_id,
        "deterministic init must produce the same device_id"
    );
    assert_eq!(
        kf1.device_seed, kf2.device_seed,
        "deterministic init must produce the same device_seed"
    );
}

#[test]
fn new_device_gets_different_device_id() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";

    let dir1 = tmp_dir();
    let dir2 = tmp_dir();

    let kf_new = init_identity_new_device(dir1.path(), mnemonic).expect("new_device");
    let kf_det = init_identity_from_mnemonic(dir2.path(), mnemonic).expect("from_mnemonic");

    assert_eq!(
        kf_new.identity_pub, kf_det.identity_pub,
        "same mnemonic → same identity_pub"
    );
    assert_ne!(
        kf_new.device_id, kf_det.device_id,
        "new_device must have a random (different) device_id"
    );
}

// ============================================================
// init_identity_new_device tests
// ============================================================

const MNEMONIC_24: &str = "abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon art";

const MNEMONIC_12: &str = "abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon about";

#[test]
fn new_device_produces_different_device_id_same_identity() {
    let dir1 = tmp_dir();
    let dir2 = tmp_dir();

    let kf_new = init_identity_new_device(dir1.path(), MNEMONIC_24).expect("new_device");
    let kf_det = init_identity_from_mnemonic(dir2.path(), MNEMONIC_24).expect("from_mnemonic");

    assert_eq!(
        kf_new.identity_pub, kf_det.identity_pub,
        "same mnemonic → same identity_pub"
    );
    assert_eq!(kf_new.seed, kf_det.seed, "same mnemonic → same seed");
    assert_ne!(
        kf_new.device_id, kf_det.device_id,
        "new_device must have a random (different) device_id"
    );
}

#[test]
fn new_device_two_calls_produce_different_device_ids() {
    let dir1 = tmp_dir();
    let dir2 = tmp_dir();

    let kf1 = init_identity_new_device(dir1.path(), MNEMONIC_24).expect("call 1");
    let kf2 = init_identity_new_device(dir2.path(), MNEMONIC_24).expect("call 2");

    assert_eq!(kf1.identity_pub, kf2.identity_pub, "same mnemonic → same identity_pub");
    assert_ne!(
        kf1.device_id, kf2.device_id,
        "two new_device calls must produce different device_ids"
    );
}

#[test]
fn new_device_rejects_duplicate() {
    let dir = tmp_dir();
    init_identity_new_device(dir.path(), MNEMONIC_24).expect("first call");

    let result = init_identity_new_device(dir.path(), MNEMONIC_24);
    assert!(
        matches!(result, Err(IdentityError::AlreadyInitialized(_))),
        "second call should return AlreadyInitialized, got {result:?}"
    );
}

#[test]
fn new_device_rejects_invalid_mnemonic() {
    let dir = tmp_dir();
    let result = init_identity_new_device(dir.path(), "not a mnemonic");
    assert!(
        matches!(result, Err(IdentityError::InvalidMnemonic(_))),
        "garbage mnemonic should return InvalidMnemonic, got {result:?}"
    );
}

#[test]
fn new_device_rejects_12_word_mnemonic() {
    let dir = tmp_dir();
    let result = init_identity_new_device(dir.path(), MNEMONIC_12);
    assert!(
        matches!(result, Err(IdentityError::InvalidMnemonic(_))),
        "12-word mnemonic should return InvalidMnemonic, got {result:?}"
    );
}

// ─── ID-07: two different 24-word mnemonics produce different identities ──────

#[test]
fn bip39_24_words_produce_unique_identity() {
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
