// Tests for daemon/identity module.

use super::{
    DEFAULT_WEB_PORT, DeviceSeedMode, IdentityError, MnemonicProblem, build_keyfile,
    corrupt_key_hint, default_config_toml, derive_keys, init_identity, init_identity_from_mnemonic,
    init_identity_new_device, load_identity, normalize_phrase, not_initialized_hint,
    parse_mnemonic, write_default_config_if_absent, write_keyfile_at,
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

#[cfg(unix)]
#[test]
fn init_creates_keyfile_with_restricted_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir();
    init_identity(dir.path()).expect("init_identity");

    let key_path = dir.path().join("identity.key");
    let metadata = std::fs::metadata(&key_path).expect("metadata");
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "identity.key must have mode 0600, got {mode:03o}"
    );
}

#[test]
fn mnemonic_is_24_words() {
    let dir = tmp_dir();
    let keyfile = init_identity(dir.path()).expect("init_identity");

    let word_count = keyfile.mnemonic.split_whitespace().count();
    assert_eq!(
        word_count, 24,
        "mnemonic must be 24 words, got {word_count}"
    );
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

    assert_eq!(
        kf1.identity_pub, kf2.identity_pub,
        "same mnemonic → same identity_pub"
    );
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

    assert_ne!(
        epoch_key_0, epoch_key_1,
        "different epochs must produce different epoch keys"
    );
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
    assert_eq!(
        keyfile.device_seed.len(),
        32,
        "device_seed must be 32 bytes"
    );
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

    assert_eq!(
        kf1.identity_pub, kf2.identity_pub,
        "same mnemonic → same identity_pub"
    );
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

// ============================================================
// B2.1: phrase parsing, pure keyfile build, non-overwriting write
// ============================================================

/// `abandon` x24: every word is in the list, the checksum is wrong.
const ABANDON_X24: &str = "abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon";

fn problem_of(r: Result<bip39::Mnemonic, IdentityError>) -> MnemonicProblem {
    match r {
        Err(IdentityError::InvalidMnemonic(p)) => p,
        other => panic!(
            "expected InvalidMnemonic, got {:?}",
            other.map(|m| m.to_string())
        ),
    }
}

#[test]
fn normalize_phrase_trims_lowercases_and_collapses_whitespace() {
    assert_eq!(
        normalize_phrase("  Abandon\t\tART \n zoo  "),
        "abandon art zoo"
    );
    assert_eq!(normalize_phrase(""), "");
}

#[test]
fn parse_mnemonic_accepts_uppercase_and_extra_whitespace() {
    let messy = format!("  {}  ", MNEMONIC_24.to_uppercase().replace(' ', "   \t"));
    let m = parse_mnemonic(&messy).expect("normalized phrase must parse");
    let canonical = parse_mnemonic(MNEMONIC_24).expect("canonical phrase must parse");
    assert_eq!(m.to_seed(""), canonical.to_seed(""));
}

#[test]
fn parse_mnemonic_reports_unknown_word_one_based_position() {
    let mut words: Vec<&str> = MNEMONIC_24.split_whitespace().collect();
    words[4] = "zzzz";
    let problem = problem_of(parse_mnemonic(&words.join(" ")));
    assert_eq!(
        problem,
        MnemonicProblem::UnknownWord {
            position: 5,
            word: "zzzz".to_string()
        }
    );
    let text = problem.to_string();
    assert!(text.contains("word 5"), "{text}");
    assert!(text.contains("\"zzzz\""), "{text}");
}

#[test]
fn parse_mnemonic_reports_checksum_for_abandon_x24() {
    let problem = problem_of(parse_mnemonic(ABANDON_X24));
    assert_eq!(problem, MnemonicProblem::Checksum);
    assert!(problem.to_string().contains("checksum"));
}

#[test]
fn parse_mnemonic_reports_word_count_for_12_words() {
    // A VALID 12-word BIP39 phrase is still not a Viaticum phrase.
    assert_eq!(
        problem_of(parse_mnemonic(MNEMONIC_12)),
        MnemonicProblem::WordCount { got: 12 }
    );
    let mut words: Vec<&str> = MNEMONIC_24.split_whitespace().collect();
    words.pop();
    assert_eq!(
        problem_of(parse_mnemonic(&words.join(" "))),
        MnemonicProblem::WordCount { got: 23 }
    );
}

/// Regression vector captured from the pre-refactor `create_keyfile` (commit 73c4ef8)
/// for MNEMONIC_24 with the deterministic device seed.
#[test]
fn build_keyfile_derived_matches_init_identity_from_mnemonic_vector() {
    use viaticum_core::types::hex_encode;
    let m = parse_mnemonic(MNEMONIC_24).expect("parse");
    let kf = build_keyfile(&m, DeviceSeedMode::DerivedFromSeed).expect("build");
    assert_eq!(
        hex_encode(&kf.identity_pub),
        "ae2ab7e6df936d6e61997c444685cb568e5930bfcb08120a54e9b811345dd90b"
    );
    assert_eq!(
        hex_encode(&kf.device_seed),
        "8aeb83a85070d68d1cb08206f51556dd2fb5fb1c3b5ac0a8f7bc20724db81c1e"
    );
    assert_eq!(
        hex_encode(&kf.device_id),
        "f5a4215c21c69f043edaddf798ed6df5898660127da08371561794c2f5546a99"
    );

    let dir = tmp_dir();
    let installed = init_identity_from_mnemonic(dir.path(), MNEMONIC_24).expect("init");
    assert_eq!(installed.identity_pub, kf.identity_pub);
    assert_eq!(installed.device_seed, kf.device_seed);
    assert_eq!(installed.device_id, kf.device_id);
    assert_eq!(installed.seed, kf.seed);
}

#[test]
fn build_keyfile_random_mode_keeps_identity_but_changes_device() {
    let m = parse_mnemonic(MNEMONIC_24).expect("parse");
    let a = build_keyfile(&m, DeviceSeedMode::Random).expect("a");
    let b = build_keyfile(&m, DeviceSeedMode::Random).expect("b");
    assert_eq!(a.identity_pub, b.identity_pub);
    assert_ne!(a.device_id, b.device_id);
}

#[test]
fn write_keyfile_at_refuses_to_overwrite_and_sets_0600() {
    let dir = tmp_dir();
    let path = dir.path().join("identity.key.dr-new");
    let m = parse_mnemonic(MNEMONIC_24).expect("parse");
    let kf = build_keyfile(&m, DeviceSeedMode::DerivedFromSeed).expect("build");
    write_keyfile_at(&path, &kf).expect("first write");
    let before = std::fs::read(&path).expect("read");

    let other = build_keyfile(&m, DeviceSeedMode::Random).expect("other");
    let second = write_keyfile_at(&path, &other);
    assert!(
        matches!(second, Err(IdentityError::AlreadyInitialized(ref p)) if p == &path),
        "second write must refuse, got {second:?}"
    );
    assert_eq!(
        std::fs::read(&path).expect("read"),
        before,
        "file untouched"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:03o}");
    }
}

// ============================================================
// dr-i30 / dr-i31: a catalog without its key, a key that cannot be read
// ============================================================

#[test]
fn init_refuses_folder_with_catalog_but_no_key() {
    type InitFn = fn(&std::path::Path) -> Result<super::IdentityKeyFile, IdentityError>;
    let inits: [(&str, InitFn); 3] = [
        ("init", init_identity),
        ("init --mnemonic", |d| {
            init_identity_from_mnemonic(d, MNEMONIC_24)
        }),
        ("init --new-device", |d| {
            init_identity_new_device(d, MNEMONIC_24)
        }),
    ];
    for (name, init) in inits {
        let dir = tmp_dir();
        std::fs::write(dir.path().join("db.redb"), b"a lost node's catalog").unwrap();
        let err = init(dir.path()).expect_err(name);
        assert!(
            matches!(err, IdentityError::CatalogWithoutKey(_)),
            "{name}: got {err:?}"
        );
        let text = err.to_string();
        assert!(
            text.contains("viaticum dr") && text.contains("db.redb"),
            "{text}"
        );
        assert!(
            !dir.path().join("identity.key").exists(),
            "{name} wrote a key"
        );
        assert!(
            !dir.path().join("config.toml").exists(),
            "{name} wrote a config"
        );
    }
}

#[test]
fn init_works_in_folder_left_by_interrupted_dr() {
    // A killed DR may leave only its drafts; there is no catalog to protect.
    let dir = tmp_dir();
    std::fs::write(dir.path().join("db.redb.dr-new"), b"draft").unwrap();
    std::fs::write(dir.path().join("identity.key.dr-new"), b"draft").unwrap();
    init_identity_from_mnemonic(dir.path(), MNEMONIC_24).expect("init --mnemonic");
    assert!(dir.path().join("identity.key").exists());
}

#[test]
fn init_still_works_in_empty_folder() {
    let dir = tmp_dir();
    init_identity(dir.path()).expect("plain init");
    assert!(dir.path().join("identity.key").exists());
    assert!(dir.path().join("config.toml").exists());
}

#[test]
fn not_initialized_hint_puts_dr_first_when_catalog_present() {
    let dir = tmp_dir();
    std::fs::write(dir.path().join("db.redb"), b"catalog").unwrap();
    let text = not_initialized_hint(dir.path());
    let dr = text.find("viaticum dr").expect("mentions dr");
    let init = text.find("viaticum init").expect("mentions init");
    assert!(dr < init, "dr must come first: {text}");
    assert!(text.contains("db.redb"), "{text}");
}

#[test]
fn not_initialized_hint_without_catalog_offers_init_and_dr() {
    let dir = tmp_dir();
    let text = not_initialized_hint(dir.path());
    assert!(
        text.contains("viaticum init") && text.contains("viaticum dr"),
        "{text}"
    );
}

#[test]
fn corrupt_key_hint_never_advises_deleting_the_key() {
    let path = std::path::Path::new("/data/identity.key");
    let text = corrupt_key_hint(path, "bad cbor");
    for needle in [
        "/data/identity.key",
        "bad cbor",
        "Do not delete it",
        "identity.key.broken",
        "viaticum dr",
        "newer Viaticum",
        "NEW identity",
    ] {
        assert!(text.contains(needle), "missing {needle:?}: {text}");
    }
    assert!(!text.contains("Delete the file"), "{text}");
    // `init` over a corrupt key says the same.
    let dir = tmp_dir();
    std::fs::write(dir.path().join("identity.key"), b"not cbor").unwrap();
    let err = init_identity(dir.path()).expect_err("corrupt");
    assert!(err.to_string().contains("Do not delete it"), "{err}");
}

// ============================================================
// init template: web API on a fixed loopback port (daemon-i9, F1)
// ============================================================

/// The `[web_api]` the daemon loads from the config `init` wrote into `dir`.
fn web_api_after_init(dir: &std::path::Path) -> viaticum_core::config::WebApiCfg {
    viaticum_core::config::AppConfig::load(&dir.join("config.toml"))
        .expect("the daemon loads the init config")
        .web_api
}

// Mutation: the template without `enabled = true` → web API off, the CLI has no
// api-port to find the daemon by, and this test goes red.
#[test]
fn init_config_enables_web_api_on_fixed_loopback_port() {
    let dir = tmp_dir();
    init_identity(dir.path()).expect("plain init");
    let web = web_api_after_init(dir.path());
    assert!(web.enabled, "init must leave the web API on");
    let addr: std::net::SocketAddr = web.bind.parse().expect("bind is a socket address");
    assert!(addr.ip().is_loopback(), "bind {addr} must be loopback");
    assert_ne!(addr.port(), 0, "port 0 changes on every restart");
    assert_eq!(addr.port(), DEFAULT_WEB_PORT);
}

// Mutation: a port drawn at render time → two inits disagree, test red.
#[test]
fn init_config_port_is_the_same_on_every_render() {
    let (a, b) = (tmp_dir(), tmp_dir());
    init_identity(a.path()).expect("init a");
    init_identity(b.path()).expect("init b");
    assert_eq!(
        web_api_after_init(a.path()).bind,
        web_api_after_init(b.path()).bind
    );
    assert_eq!(default_config_toml(), default_config_toml());
}

// The port the user may have edited stays: a later default write (DR, re-init
// path) never overwrites an existing config.
#[test]
fn default_config_write_keeps_an_existing_config() {
    let dir = tmp_dir();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[web_api]\nenabled = true\nbind = \"127.0.0.1:9999\"\n",
    )
    .unwrap();
    write_default_config_if_absent(dir.path()).expect("write if absent");
    assert_eq!(web_api_after_init(dir.path()).bind, "127.0.0.1:9999");
}
