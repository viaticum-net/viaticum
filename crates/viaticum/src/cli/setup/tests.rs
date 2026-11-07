// Unit tests of `setup` (R3b b3): pure arithmetic, TOML editing and refusals
// that must happen before the first write.

use std::path::PathBuf;

use super::*;

const GB: u64 = 1_073_741_824;

fn answers() -> SetupAnswers {
    SetupAnswers {
        watch: vec![
            PathBuf::from("/home/friend/Documents"),
            PathBuf::from("/data/Pictures"),
        ],
        quota_gb: 7.0,
        reserve_gb: 4.0,
        seeds: Some(vec!["/ip4/1.2.3.4/tcp/4001/p2p/peer".to_string()]),
        web_port: 7383,
    }
}

#[test]
fn default_quota_is_20_percent_of_free_floored_min_1() {
    assert_eq!(default_quota_gb(10 * GB), 2.0);
    assert_eq!(default_quota_gb(38 * GB), 7.0);
    assert_eq!(default_quota_gb(GB), 1.0);
    assert_eq!(default_quota_gb(4 * GB), 1.0);
    assert_eq!(default_quota_gb(0), 1.0, "0 is never accepted as the quota");
    assert_eq!(default_quota_gb(GB + GB / 2), 1.0, "floor(0.3) = 0 → 1");
}

#[test]
fn default_reserve_clamped_2_to_20() {
    assert_eq!(default_reserve_gb(5 * GB), 2.0);
    assert_eq!(default_reserve_gb(10 * GB), 2.0);
    assert_eq!(default_reserve_gb(100 * GB), 10.0);
    assert_eq!(default_reserve_gb(40 * GB), 4.0);
    assert_eq!(default_reserve_gb(1000 * GB), 20.0);
}

#[test]
fn init_template_web_api_enabled_with_fixed_port() {
    let text = crate::daemon::identity::default_config_toml(23_817, &[]);
    let doc: toml_edit::DocumentMut = text.parse().unwrap();
    assert_eq!(doc["web_api"]["enabled"].as_bool(), Some(true));
    assert_eq!(
        doc["web_api"]["bind"].as_str(),
        Some("127.0.0.1:7383"),
        "F1: init writes a fixed loopback web port"
    );
}

#[test]
fn apply_setup_writes_floats_watch_quota_web() {
    let template = crate::daemon::identity::default_config_toml(23_817, &[]);
    let out = apply_setup_to_config(&template, &answers()).unwrap();
    let doc: toml_edit::DocumentMut = out.parse().unwrap();
    assert_eq!(
        doc["storage"]["soft_quota_gb"].as_float(),
        Some(7.0),
        "{out}"
    );
    assert_eq!(
        doc["storage"]["disk_reserve_gb"].as_float(),
        Some(4.0),
        "reserve must be a float and replace the template value: {out}"
    );
    assert_eq!(doc["web_api"]["enabled"].as_bool(), Some(true));
    assert_eq!(
        doc["web_api"]["bind"].as_str(),
        Some("127.0.0.1:7383"),
        "{out}"
    );
    assert_eq!(
        doc["network"]["kademlia_bootstrap_peers"]
            .as_array()
            .map(|a| a.len()),
        Some(1)
    );
    let watches = doc["watch"].as_array_of_tables().unwrap();
    assert_eq!(watches.len(), 2);
    assert_eq!(
        watches.get(0).unwrap()["path"].as_str(),
        Some("/home/friend/Documents")
    );
    assert_eq!(
        watches.get(1).unwrap()["path"].as_str(),
        Some("/data/Pictures")
    );
}

#[test]
fn apply_setup_is_idempotent_no_duplicate_watch() {
    let template = crate::daemon::identity::default_config_toml(23_817, &[]);
    let once = apply_setup_to_config(&template, &answers()).unwrap();
    let twice = apply_setup_to_config(&once, &answers()).unwrap();
    assert_eq!(once, twice, "the same answers must produce the same config");
    let doc: toml_edit::DocumentMut = twice.parse().unwrap();
    assert_eq!(doc["watch"].as_array_of_tables().unwrap().len(), 2);
}

#[test]
fn apply_setup_keeps_seeds_when_none_given() {
    let template =
        crate::daemon::identity::default_config_toml(23_817, &["/ip4/5.6.7.8/tcp/4001/p2p/seed"]);
    let mut a = answers();
    a.seeds = None;
    let out = apply_setup_to_config(&template, &a).unwrap();
    let doc: toml_edit::DocumentMut = out.parse().unwrap();
    assert_eq!(
        doc["network"]["kademlia_bootstrap_peers"]
            .as_array()
            .map(|v| v.len()),
        Some(1),
        "--seed absent must keep the template's seed"
    );
}

#[test]
fn setup_refuses_root_without_flag() {
    assert!(root_refused(0, false));
    assert!(!root_refused(0, true));
    assert!(!root_refused(1000, false));
}

#[test]
fn setup_rejects_zero_quota() {
    assert!(matches!(
        validate_quota(0.0),
        Err(SetupError::InvalidQuota(0.0))
    ));
    assert!(matches!(
        validate_quota(0.5),
        Err(SetupError::InvalidQuota(_))
    ));
    assert!(validate_quota(1.0).is_ok());
    assert!(validate_quota(f64::NAN).is_err());
}

#[tokio::test]
async fn setup_restore_refuses_data_dir_with_identity() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(KEYFILE_NAME), b"not even cbor").unwrap();
    let err = run_setup(SetupOptions {
        data_dir: dir.path().to_path_buf(),
        mode: Some(SetupMode::Restore),
        watch: vec![],
        quota_gb: Some(2.0),
        seed: vec![],
        phrase_file: Some(dir.path().join("missing-phrase")),
        yes: true,
        skip_phrase_check: false,
        allow_root: true,
        json: true,
    })
    .await
    .unwrap_err();
    assert!(
        matches!(&err, SetupError::DataDirHasIdentity(p) if p == dir.path()),
        "{err}"
    );
}

#[test]
fn phrase_file_with_wide_mode_is_refused() {
    let path = PathBuf::from("/home/friend/phrase");
    assert!(check_phrase_file_mode(&path, 0o600).is_ok());
    assert!(check_phrase_file_mode(&path, 0o400).is_ok());
    assert!(check_phrase_file_mode(&path, 0o640).is_err());
    assert!(check_phrase_file_mode(&path, 0o644).is_err());
    assert!(
        check_phrase_file_mode(&path, 0o700).is_err(),
        "execute bits are wider than 0600 too"
    );
}

/// F-Q: the quota is computed from the filesystem of the data directory's
/// symlink target, not from the path prefix (N3).
#[cfg(unix)]
#[test]
fn setup_quota_uses_statvfs_of_symlink_target() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("disk");
    std::fs::create_dir(&target).unwrap();
    let link = root.path().join("viaticum");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let (free_link, size_link) = free_and_size(&link);
    let (free_target, size_target) = free_and_size(&target);
    assert_eq!(size_link, size_target);
    let (free_link, free_target) = (free_link.unwrap(), free_target.unwrap());
    let diff = free_link.abs_diff(free_target);
    assert!(
        diff < 64 * 1024 * 1024,
        "free space through the symlink {free_link} and the target {free_target} differ"
    );
}

#[test]
fn web_port_differs_from_listen_port() {
    let listen = crate::daemon::identity::DEFAULT_WEB_PORT;
    let web = choose_web_port_with(listen, listen, false, |_| true, |_| Some(24_001));
    assert_ne!(web, listen, "the web port must not take the libp2p port");
    assert_eq!(web, 24_001, "the picker is asked with both ports excluded");
}

#[test]
fn existing_web_port_is_kept() {
    assert_eq!(
        choose_web_port(29_123, 23_817, true),
        29_123,
        "a re-run keeps the port the first run wrote"
    );
}

/// NOTE 2 / install-i9: the first run picks a free port when 7383 is busy; a
/// second run sees 7383 busy (usually its own daemon) and must keep the port
/// from the first run instead of moving the Dashboard and breaking `ssh -L`.
#[test]
fn rerun_keeps_web_port_when_7383_is_busy() {
    let first = choose_web_port_with(7383, 23_817, false, |_| false, |_| Some(26_201));
    assert_eq!(first, 26_201, "first run: 7383 is busy, so pick another");
    let second = choose_web_port_with(
        first,
        23_817,
        true,
        |_| false,
        |_| panic!("a re-run must not pick a new web port"),
    );
    assert_eq!(second, first, "second run keeps the recorded port");
}

/// A hand-edited config keeps both ports on a real re-run through `run_new`:
/// the web port is not re-picked and the libp2p `listen_port` is untouched.
#[tokio::test]
async fn rerun_keeps_web_and_listen_ports() {
    let dir = tempfile::tempdir().unwrap();
    let watch = tempfile::tempdir().unwrap();
    let cfg = crate::daemon::identity::default_config_toml(23_817, &[])
        .replace("127.0.0.1:7383", "127.0.0.1:26201");
    std::fs::write(dir.path().join(CONFIG_FILE_NAME), cfg).unwrap();
    crate::daemon::identity::init_identity(dir.path()).unwrap();
    // 7383 is what the old code reacted to; busy or not, the recorded port stays.
    let _busy = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 7383)).ok();

    run_new(
        SetupOptions {
            data_dir: dir.path().to_path_buf(),
            mode: Some(SetupMode::New),
            watch: vec![watch.path().to_path_buf()],
            quota_gb: Some(2.0),
            seed: vec![],
            phrase_file: None,
            yes: true,
            skip_phrase_check: true,
            allow_root: true,
            json: true,
        },
        false,
        Ui { json: true },
    )
    .await
    .unwrap();

    let text = std::fs::read_to_string(dir.path().join(CONFIG_FILE_NAME)).unwrap();
    let doc: toml_edit::DocumentMut = text.parse().unwrap();
    assert_eq!(
        doc["web_api"]["bind"].as_str(),
        Some("127.0.0.1:26201"),
        "the re-run rewrote the recorded web port: {text}"
    );
    assert_eq!(
        doc["network"]["listen_port"].as_integer(),
        Some(23_817),
        "the re-run rewrote the libp2p listen_port: {text}"
    );
}

/// NOTE 3: merging `[[watch]]` keeps the user's per-folder keys and comments;
/// the `# bind = …` hint stays in `[web_api]`, not under `[[watch]]`.
#[test]
fn apply_setup_merges_watch_and_keeps_hand_edited_config() {
    let hand_edited = r#"# Viaticum configuration
[storage]
soft_quota_gb = 20.0

[web_api]
enabled = true
bind = "127.0.0.1:26201"
# bind = "0.0.0.0:7383"   # opt-in LAN/NAS access

[[watch]]
path = "/home/friend/Documents"
importance_multiplier = 2.0

[[watch]]
path = "/home/friend/Pictures"
importance_multiplier = 1.5
"#;
    let mut answers = answers();
    answers.watch = vec![
        PathBuf::from("/home/friend/Documents"),
        PathBuf::from("/data/New"),
    ];
    let out = apply_setup_to_config(hand_edited, &answers).unwrap();
    let doc: toml_edit::DocumentMut = out.parse().unwrap();
    let watches = doc["watch"].as_array_of_tables().unwrap();
    assert_eq!(watches.len(), 2, "{out}");
    assert_eq!(
        watches.get(0).unwrap()["importance_multiplier"].as_float(),
        Some(2.0),
        "the kept folder lost its importance_multiplier: {out}"
    );
    assert_eq!(
        watches.get(0).unwrap()["path"].as_str(),
        Some("/home/friend/Documents")
    );
    assert_eq!(
        watches.get(1).unwrap()["path"].as_str(),
        Some("/data/New"),
        "a new folder is added"
    );
    let bind_hint = out.find("# bind = \"0.0.0.0:7383\"").unwrap();
    let first_watch = out.find("[[watch]]").unwrap();
    assert!(
        bind_hint < first_watch,
        "the # bind hint must stay in [web_api], not move under [[watch]]: {out}"
    );
}

/// W1: a restore watch folder that does not exist yet is created 0700 before
/// DR, so the commit is never followed by `FolderMissing`.
#[cfg(unix)]
#[test]
fn restore_preflight_creates_a_missing_watch_folder_0700() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("Documents");
    let out = ensure_watch_dirs(vec![missing.clone()]).unwrap();
    assert_eq!(out, vec![missing.clone()]);
    assert!(missing.is_dir());
    assert_eq!(
        std::fs::metadata(&missing).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn setup_mode_answer_has_no_default() {
    assert_eq!(parse_mode_answer(""), None, "an empty Enter must re-ask");
    assert_eq!(parse_mode_answer("1"), Some(SetupMode::New));
    assert_eq!(parse_mode_answer("new"), Some(SetupMode::New));
    assert_eq!(parse_mode_answer("2"), Some(SetupMode::Restore));
    assert_eq!(parse_mode_answer("restore"), Some(SetupMode::Restore));
    assert_eq!(parse_mode_answer("whatever"), None);
}

/// B1/F1: the half-tty case (`setup | tee install.log`) goes through the real
/// `run_new` path, not the grid helper: stdin is a tty, stdout is a pipe, so
/// there is no terminal for the phrase and `setup --mode new` without `--yes`
/// must refuse before writing an identity.
#[tokio::test]
async fn setup_never_prints_phrase_without_tty() {
    let data = tempfile::tempdir().unwrap();
    let watch = tempfile::tempdir().unwrap();
    let err = run_setup_with_ttys(
        SetupOptions {
            data_dir: data.path().to_path_buf(),
            mode: Some(SetupMode::New),
            watch: vec![watch.path().to_path_buf()],
            quota_gb: Some(2.0),
            seed: vec![],
            phrase_file: None,
            yes: false,
            skip_phrase_check: true,
            allow_root: true,
            json: true,
        },
        true,
        false,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, SetupError::NoTty), "{err}");
    assert!(
        !data.path().join(KEYFILE_NAME).exists(),
        "the half-tty run created an identity before refusing"
    );
}

#[test]
fn phrase_grid_for_half_tty_is_none() {
    assert_eq!(
        phrase_grid_for_setup(
            crate::cli::is_interactive(true, false),
            "abandon ability able"
        ),
        None,
        "stdin is a tty, stdout is not: the grid must not be rendered (M3″)"
    );
    let shown = phrase_grid_for_setup(
        crate::cli::is_interactive(true, true),
        "abandon ability able",
    )
    .unwrap();
    assert!(shown.contains("abandon"));
}
