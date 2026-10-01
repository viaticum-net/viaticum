use clap::Parser;

use super::output;
use super::types::{
    CliRequest, CliResponse, DeviceEntry, FileEntry, PeerSummary, RestoreFailure,
    RestoreFailureKind, RestoreJob, RestoreJobState, RestoreOutcome, RestoreRejection, StatusData,
    VersionEntry,
};
use super::{Cli, CliError, Command, DeviceAction};

// ============================================================
// Argument parsing tests
// ============================================================

fn parse(args: &[&str]) -> Command {
    Cli::parse_from(args).command
}

#[test]
fn command_status_parses_correctly() {
    assert!(matches!(
        parse(&["viaticum", "status"]),
        Command::Status { json: false }
    ));
}

#[test]
fn command_restore_parses_path() {
    let cmd = parse(&["viaticum", "restore", "photos/img.jpg"]);
    let Command::Restore {
        path,
        version,
        date,
        dest,
        no_wait,
        status,
        json,
    } = cmd
    else {
        panic!("expected Restore");
    };
    assert_eq!(path.as_deref(), Some("photos/img.jpg"));
    assert!(!no_wait && !json);
    assert_eq!(status, None);
    assert_eq!(version, None);
    assert_eq!(date, None);
    assert_eq!(dest, None);
}

#[test]
fn command_restore_parses_version_flag() {
    let cmd = parse(&["viaticum", "restore", "photos/img.jpg", "--version", "3"]);
    let Command::Restore { version, .. } = cmd else {
        panic!("expected Restore");
    };
    assert_eq!(version, Some(3));
}

#[test]
fn command_restore_parses_date_flag() {
    let cmd = parse(&[
        "viaticum",
        "restore",
        "photos/img.jpg",
        "--date",
        "2026-01-15",
    ]);
    let Command::Restore { date, .. } = cmd else {
        panic!("expected Restore");
    };
    assert_eq!(date, Some("2026-01-15".to_string()));
}

#[test]
fn command_restore_parses_dest_flag() {
    let cmd = parse(&[
        "viaticum",
        "restore",
        "photos/img.jpg",
        "--dest",
        "/tmp/out",
    ]);
    let Command::Restore { dest, .. } = cmd else {
        panic!("expected Restore");
    };
    assert_eq!(dest, Some("/tmp/out".to_string()));
}

#[test]
fn command_files_no_prefix() {
    let cmd = parse(&["viaticum", "files"]);
    let Command::Files { path_prefix } = cmd else {
        panic!("expected Files");
    };
    assert_eq!(path_prefix, None);
}

#[test]
fn command_files_with_prefix() {
    let cmd = parse(&["viaticum", "files", "photos/"]);
    let Command::Files { path_prefix } = cmd else {
        panic!("expected Files");
    };
    assert_eq!(path_prefix, Some("photos/".to_string()));
}

#[test]
fn command_versions_parses_path() {
    let cmd = parse(&["viaticum", "versions", "documents/report.pdf"]);
    let Command::Versions { path } = cmd else {
        panic!("expected Versions");
    };
    assert_eq!(path, "documents/report.pdf");
}

#[test]
fn command_device_list() {
    let cmd = parse(&["viaticum", "device", "list"]);
    let Command::Device { action } = cmd else {
        panic!("expected Device");
    };
    assert!(matches!(action, DeviceAction::List));
}

#[test]
fn command_device_add() {
    let cmd = parse(&["viaticum", "device", "add", "my-phone"]);
    let Command::Device { action } = cmd else {
        panic!("expected Device");
    };
    let DeviceAction::Add { label } = action else {
        panic!("expected Add");
    };
    assert_eq!(label, "my-phone");
}

#[test]
fn command_device_revoke() {
    let cmd = parse(&[
        "viaticum",
        "device",
        "revoke",
        "0102030405060708090a0b0c0d0e0f10",
    ]);
    let Command::Device { action } = cmd else {
        panic!("expected Device");
    };
    let DeviceAction::Revoke { device_id } = action else {
        panic!("expected Revoke");
    };
    assert_eq!(device_id, "0102030405060708090a0b0c0d0e0f10");
}

// ============================================================
// run_command validation tests (daemon not reachable — validation happens first)
// ============================================================

fn run(cmd: &Command) -> Result<i32, CliError> {
    // 127.0.0.1:1 is effectively unreachable (port 1 reserved, no listener)
    let conn = super::Connection {
        url: "http://127.0.0.1:1".into(),
        token: "irrelevant".into(),
    };
    super::run_command(cmd, &conn)
}

#[test]
fn run_command_restore_rejects_version_zero() {
    let cmd = parse(&["viaticum", "restore", "f", "--version", "0"]);
    let err = run(&cmd).unwrap_err();
    assert!(matches!(err, CliError::InvalidArgument(_)));
}

#[test]
fn run_command_restore_rejects_version_and_date_both() {
    let cmd = parse(&[
        "viaticum",
        "restore",
        "f",
        "--version",
        "1",
        "--date",
        "2026-01-01",
    ]);
    let err = run(&cmd).unwrap_err();
    assert!(matches!(err, CliError::InvalidArgument(_)));
}

#[test]
fn run_command_device_revoke_rejects_short_hex() {
    let cmd = Command::Device {
        action: DeviceAction::Revoke {
            device_id: "tooshort".into(),
        },
    };
    let err = run(&cmd).unwrap_err();
    assert!(matches!(err, CliError::InvalidArgument(_)));
}

#[test]
fn run_command_device_revoke_rejects_non_hex() {
    let cmd = Command::Device {
        action: DeviceAction::Revoke {
            // 32 chars but not valid hex
            device_id: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".into(),
        },
    };
    let err = run(&cmd).unwrap_err();
    assert!(matches!(err, CliError::InvalidArgument(_)));
}

#[test]
fn run_command_fails_when_daemon_not_reachable() {
    let cmd = Command::Status { json: false };
    let err = run(&cmd).unwrap_err();
    assert!(matches!(err, CliError::DaemonNotReachable { .. }));
}

// ============================================================
// format_bytes tests
// ============================================================

#[test]
fn format_bytes_under_1kb() {
    assert_eq!(output::format_bytes(0), "0 B");
    assert_eq!(output::format_bytes(512), "512 B");
    assert_eq!(output::format_bytes(1023), "1023 B");
}

#[test]
fn format_bytes_kilobytes() {
    assert_eq!(output::format_bytes(1_024), "1 KB");
    assert_eq!(output::format_bytes(2_048), "2 KB");
    assert_eq!(output::format_bytes(10_240), "10 KB");
    assert_eq!(output::format_bytes(1_048_575), "1023 KB");
}

#[test]
fn format_bytes_megabytes() {
    assert_eq!(output::format_bytes(1_048_576), "1.0 MB");
    assert_eq!(output::format_bytes(1_572_864), "1.5 MB");
    assert_eq!(output::format_bytes(10_485_760), "10.0 MB");
}

#[test]
fn format_bytes_gigabytes() {
    assert_eq!(output::format_bytes(1_073_741_824), "1.00 GB");
    assert_eq!(output::format_bytes(4_509_715_660), "4.20 GB");
}

// ============================================================
// render_status tests
// ============================================================

fn make_status_zero_peers() -> StatusData {
    StatusData {
        node_identity: "0000000000000000".into(),
        device_id: "0000000000000000".into(),
        node_addr: String::new(),
        peer_count: 0,
        peer_count_connected: 0,
        peer_count_authenticated: 0,
        peer_count_known: 0,
        known_devices: None,
        authenticated_devices: None,
        conn_cache: Default::default(),
        avg_trust: 0.0,
        holding_bytes: 0,
        backed_up_files: 0,
        backed_up_bytes: 0,
        blocks_needing_repair: 0,
        peers: vec![],
        effective_quota_bytes: 0,
        quota_state: "bytes".into(),
        quota_note: String::new(),
        below_reserve_giving_back_bytes: None,
        used_bytes: 0,
        pos_total_challenges: 0,
        pos_total_passes: 0,
        placement_count: 0,
        placement_alive: 0,
        placement_lost: 0,
        blocks_ok: 0,
        blocks_at_risk: 0,
        table_stats: None,
        by_importance: vec![],
        restore_staging_jobs: 0,
        restore_staging_bytes: Some(0),
        restore_staging_path: String::new(),
        restore_publish: String::new(),
        restore_staging_squeezes_holdings: false,
        dr_pointer_published_at: 0,
        dr_pointer_files: 0,
        dr_pointer_acks: 0,
        catalog_lineage: String::new(),
        files_without_source: 0,
        dr_ready: false,
        dr_pointer_ack_threshold: 0,
        dr_ss_blocks_placed: 0,
        dr_ss_blocks_total: 0,
        dr_pointer_refusal: String::new(),
        dr_waiting_since: 0,
        dr_waiting: String::new(),
        dr_restores_state_of: 0,
        files_too_large: 0,
        max_file_size_bytes: 0,
        block_work_budget_bytes: 0,
    }
}

/// restore-i8: `status` reminds the user that restored files wait in staging.
#[test]
fn render_status_shows_restore_staging_when_job_dirs_exist() {
    let mut data = make_status_zero_peers();
    data.restore_staging_jobs = 2;
    data.restore_staging_bytes = Some(3 * 1024 * 1024);
    data.restore_staging_path = "/home/kolya/.viaticum/restore".into();
    let rendered = output::render_status(&data);
    assert!(
        rendered.contains("restore staging: 2 job dir(s)"),
        "got: {rendered}"
    );
    assert!(
        rendered.contains("/home/kolya/.viaticum/restore"),
        "got: {rendered}"
    );
    assert!(rendered.contains("move files out, then delete the directories"));
}

#[test]
fn render_status_hides_restore_staging_when_empty() {
    let rendered = output::render_status(&make_status_zero_peers());
    assert!(!rendered.contains("restore staging"), "got: {rendered}");
}

/// Old daemons do not send the staging fields; the CLI still parses the status.
#[test]
fn status_data_without_staging_fields_deserializes_with_zero() {
    let mut v = serde_json::to_value(make_status_zero_peers()).unwrap();
    let obj = v.as_object_mut().unwrap();
    obj.remove("restore_staging_jobs");
    obj.remove("restore_staging_bytes");
    obj.remove("restore_staging_path");
    obj.remove("restore_publish");
    obj.remove("restore_staging_squeezes_holdings");
    let back: StatusData = serde_json::from_value(v).unwrap();
    assert_eq!(back.restore_staging_jobs, 0);
    assert_eq!(back.restore_staging_bytes, None);
    assert!(!back.restore_staging_squeezes_holdings);
}

/// W3: right after start the byte count is not known yet: say so, never "0 B".
#[test]
fn render_status_says_counting_before_bytes_are_known() {
    let mut data = make_status_zero_peers();
    data.restore_staging_jobs = 1;
    data.restore_staging_bytes = None;
    let rendered = output::render_status(&data);
    assert!(rendered.contains("size still counting"), "got: {rendered}");
}

/// restore-i18: the squeeze warning names the staging size and asks to move out.
#[test]
fn render_status_warns_when_staging_takes_space_from_friends() {
    let mut data = make_status_zero_peers();
    data.restore_staging_jobs = 1;
    data.restore_staging_bytes = Some(2 * 1024 * 1024 * 1024);
    data.restore_staging_squeezes_holdings = true;
    let rendered = output::render_status(&data);
    assert!(
        rendered.contains("is taking space from your friends' data; move files out and delete it"),
        "got: {rendered}"
    );
}

/// restore-i19: no atomic publish path → an explicit error line in status.
#[test]
fn render_status_reports_unavailable_publish() {
    let mut data = make_status_zero_peers();
    data.restore_publish = "unavailable".into();
    let rendered = output::render_status(&data);
    assert!(
        rendered.contains("restore cannot write files into staging"),
        "got: {rendered}"
    );
    data.restore_publish = "hard_link".into();
    assert!(!output::render_status(&data).contains("cannot write"));
}

#[test]
fn format_status_zero_peers_prints_no_peers_yet() {
    let data = make_status_zero_peers();
    let rendered = output::render_status(&data);
    assert!(rendered.contains("no peers yet"), "got: {rendered}");
    assert!(rendered.contains("WARNING"), "got: {rendered}");
}

#[test]
fn format_status_includes_identity_and_header() {
    let data = make_status_zero_peers();
    let rendered = output::render_status(&data);
    assert!(rendered.contains("viaticum status"), "got: {rendered}");
    assert!(rendered.contains("0000000000000000"), "got: {rendered}");
}

/// holder-i1: a zero quota is "no room", never "unlimited".
#[test]
fn format_status_zero_quota_is_no_room_not_unlimited() {
    let data = make_status_zero_peers();
    let rendered = output::render_status(&data);
    assert!(!rendered.contains("unlimited"), "got: {rendered}");
    assert!(
        rendered.contains("not taking friends' data"),
        "got: {rendered}"
    );
}

/// holder-i4: below the reserve, status says so and how much is given back — at any quota,
/// not only at 0.
#[test]
fn format_status_below_reserve_says_what_is_given_back() {
    let mut data = make_status_zero_peers();
    data.effective_quota_bytes = 5 * 1024 * 1024 * 1024;
    data.below_reserve_giving_back_bytes = Some(3 * 1024 * 1024 * 1024);
    let rendered = output::render_status(&data);
    assert!(
        rendered.contains("disk below reserve: giving back 3"),
        "got: {rendered}"
    );
    data.below_reserve_giving_back_bytes = None;
    let rendered = output::render_status(&data);
    assert!(!rendered.contains("below reserve"), "got: {rendered}");
}

/// holder-i2: an unread disk shows `unknown` and the note naming the path.
#[test]
fn format_status_unknown_quota_names_the_path() {
    let mut data = make_status_zero_peers();
    data.quota_state = "unknown".into();
    data.quota_note = "could not read free space on /srv/v; not taking friends' data".into();
    let rendered = output::render_status(&data);
    assert!(
        rendered.contains("quota:          unknown"),
        "got: {rendered}"
    );
    assert!(
        rendered.contains("WARNING: could not read free space on /srv/v"),
        "got: {rendered}"
    );
}

#[test]
fn format_status_top_peers_printed() {
    let data = StatusData {
        node_identity: "a1b2c3d4e5f60708".into(),
        device_id: "a1b2c3d4e5f60708".into(),
        node_addr: String::new(),
        peer_count: 2,
        peer_count_connected: 2,
        peer_count_authenticated: 2,
        peer_count_known: 0,
        known_devices: None,
        authenticated_devices: None,
        conn_cache: Default::default(),
        avg_trust: 2.09,
        holding_bytes: 0,
        backed_up_files: 0,
        backed_up_bytes: 0,
        blocks_needing_repair: 0,
        peers: vec![
            PeerSummary {
                identity_hex: "a1b2c3d4e5f60708".into(),
                trust: 2.31,
                bytes_we_store: 1_288_490_189,
                bytes_peer_stores: 858_993_459,
                last_seen: "2026-03-20".into(),
                trust_p: 0.8,
                trust_i: 1.2,
                trust_s: 0.9,
                pos_challenges_recent: 4,
                pos_passes_recent: 4,
                link: "auth".into(),
            },
            PeerSummary {
                identity_hex: "e5f60708090a0b0c".into(),
                trust: 1.87,
                bytes_we_store: 429_496_730,
                bytes_peer_stores: 2_254_857_830,
                last_seen: "2026-03-19".into(),
                trust_p: 0.7,
                trust_i: 1.0,
                trust_s: 0.85,
                pos_challenges_recent: 4,
                pos_passes_recent: 3,
                link: "known".into(),
            },
        ],
        effective_quota_bytes: 0,
        quota_state: "bytes".into(),
        quota_note: String::new(),
        below_reserve_giving_back_bytes: None,
        used_bytes: 0,
        pos_total_challenges: 8,
        pos_total_passes: 7,
        placement_count: 10,
        placement_alive: 8,
        placement_lost: 2,
        blocks_ok: 3,
        blocks_at_risk: 1,
        table_stats: None,
        by_importance: vec![],
        restore_staging_jobs: 0,
        restore_staging_bytes: Some(0),
        restore_staging_path: String::new(),
        restore_publish: String::new(),
        restore_staging_squeezes_holdings: false,
        dr_pointer_published_at: 0,
        dr_pointer_files: 0,
        dr_pointer_acks: 0,
        catalog_lineage: String::new(),
        files_without_source: 0,
        dr_ready: false,
        dr_pointer_ack_threshold: 0,
        dr_ss_blocks_placed: 0,
        dr_ss_blocks_total: 0,
        dr_pointer_refusal: String::new(),
        dr_waiting_since: 0,
        dr_waiting: String::new(),
        dr_restores_state_of: 0,
        files_too_large: 0,
        max_file_size_bytes: 0,
        block_work_budget_bytes: 0,
    };
    let rendered = output::render_status(&data);
    assert!(rendered.contains("a1b2c3d4"), "got: {rendered}");
    assert!(rendered.contains("trust=2.31"), "got: {rendered}");
    assert!(rendered.contains("e5f60708"), "got: {rendered}");
    assert!(rendered.contains("trust=1.87"), "got: {rendered}");
    assert!(rendered.contains("top peers:"), "got: {rendered}");
}

// ============================================================
// render_files tests
// ============================================================

#[test]
fn format_files_empty_list() {
    let rendered = output::render_files(&[]);
    assert!(rendered.contains("no files backed up"), "got: {rendered}");
}

#[test]
fn format_files_single_entry_singular_version() {
    let files = vec![FileEntry {
        path: "doc.pdf".into(),
        versions: 1,
        last_backed_up: "2026-03-20".into(),
        size_bytes: 250_000,
        local_state: "present".into(),
        effective_status: None,
        is_safe_to_delete: false,
        too_large: None,
    }];
    let rendered = output::render_files(&files);
    assert!(rendered.contains("1 version"), "got: {rendered}");
    assert!(
        !rendered.contains("1 versions"),
        "should be singular: {rendered}"
    );
    // 250000 / 1024 = 244.14... → 244 KB
    assert!(rendered.contains("244 KB"), "got: {rendered}");
}

#[test]
fn format_files_multiple_versions_plural() {
    let files = vec![FileEntry {
        path: "archive.tar".into(),
        versions: 5,
        last_backed_up: "2026-03-21".into(),
        size_bytes: 1_048_576,
        local_state: "present".into(),
        effective_status: None,
        is_safe_to_delete: false,
        too_large: None,
    }];
    let rendered = output::render_files(&files);
    assert!(rendered.contains("5 versions"), "got: {rendered}");
    assert!(rendered.contains("backed-up files (1):"), "got: {rendered}");
}

// ============================================================
// render_versions tests
// ============================================================

#[test]
fn format_versions_empty() {
    let rendered = output::render_versions("photos/img.jpg", &[]);
    assert!(
        rendered.contains("no versions found for photos/img.jpg"),
        "got: {rendered}"
    );
}

#[test]
fn format_versions_pending_backed_up() {
    let entry = VersionEntry {
        version: 1,
        created_at: "2026-03-20T10:00:00".into(),
        backed_up_at: "pending".into(),
        content_hash_hex: "ab".repeat(32),
        size_bytes: 1_048_576,
        source_block_id_hex: "cd".repeat(32),
        effective_status: crate::cli::types::EffectiveStatus::Queued,
        restore_blocker: None,
    };
    let rendered = output::render_versions("f", &[entry]);
    assert!(rendered.contains("pending"), "got: {rendered}");
    assert!(rendered.contains("v1"), "got: {rendered}");
    assert!(rendered.contains("1.0 MB"), "got: {rendered}");
}

#[test]
fn format_versions_hash_truncated_to_8_chars() {
    let entry = VersionEntry {
        version: 2,
        created_at: "2026-03-21T09:00:00".into(),
        backed_up_at: "2026-03-21T09:01:00".into(),
        content_hash_hex: "aabbccdd11223344".repeat(4),
        size_bytes: 512,
        source_block_id_hex: "11223344aabbccdd".repeat(4),
        effective_status: crate::cli::types::EffectiveStatus::Restorable { live: 8, target: 5 },
        restore_blocker: None,
    };
    let rendered = output::render_versions("test.txt", &[entry]);
    assert!(rendered.contains("aabbccdd..."), "got: {rendered}");
    assert!(rendered.contains("[block: 11223344]"), "got: {rendered}");
}

// ============================================================
// render_device_list tests
// ============================================================

#[test]
fn format_device_list_marks_current() {
    let devices = vec![
        DeviceEntry {
            device_id_hex: "01".repeat(16),
            label: "laptop".into(),
            is_current: true,
            added_at: "2026-01-10".into(),
            revoked: false,
        },
        DeviceEntry {
            device_id_hex: "02".repeat(16),
            label: "phone".into(),
            is_current: false,
            added_at: "2026-02-15".into(),
            revoked: false,
        },
    ];
    let rendered = output::render_device_list(&devices);
    assert!(rendered.contains("[*]"), "got: {rendered}");
    assert!(rendered.contains("laptop"), "got: {rendered}");
    assert!(rendered.contains("phone"), "got: {rendered}");
}

#[test]
fn format_device_list_marks_revoked() {
    let devices = vec![DeviceEntry {
        device_id_hex: "03".repeat(16),
        label: "old-device".into(),
        is_current: false,
        added_at: "2025-06-01".into(),
        revoked: true,
    }];
    let rendered = output::render_device_list(&devices);
    assert!(rendered.contains("[R]"), "got: {rendered}");
}

#[test]
fn format_device_list_includes_count_header() {
    let devices = vec![DeviceEntry {
        device_id_hex: "aa".repeat(16),
        label: "desktop".into(),
        is_current: false,
        added_at: "2026-01-01".into(),
        revoked: false,
    }];
    let rendered = output::render_device_list(&devices);
    assert!(rendered.contains("cluster devices (1):"), "got: {rendered}");
}

#[test]
fn format_device_list_device_id_truncated_to_16_chars() {
    let full_id = "ab".repeat(16); // 32 hex chars
    let devices = vec![DeviceEntry {
        device_id_hex: full_id.clone(),
        label: "server".into(),
        is_current: false,
        added_at: "2026-03-01".into(),
        revoked: false,
    }];
    let rendered = output::render_device_list(&devices);
    let expected_prefix = &full_id[..16];
    assert!(rendered.contains(expected_prefix), "got: {rendered}");
    assert!(
        !rendered.contains(&full_id),
        "full id should be truncated: {rendered}"
    );
}

// ============================================================
// render_device_added tests
// ============================================================

#[test]
fn format_device_added_shows_label_and_id() {
    let device = DeviceEntry {
        device_id_hex: "ff".repeat(16),
        label: "my-tablet".into(),
        is_current: false,
        added_at: "2026-03-15".into(),
        revoked: false,
    };
    let rendered = output::render_device_added(&device);
    assert!(rendered.contains("device added"), "got: {rendered}");
    assert!(rendered.contains("my-tablet"), "got: {rendered}");
    assert!(rendered.contains("ffffffffffffffff..."), "got: {rendered}");
}

#[test]
fn format_device_added_short_id_not_truncated() {
    let device = DeviceEntry {
        device_id_hex: "abcd".into(),
        label: "watch".into(),
        is_current: false,
        added_at: "2026-03-15".into(),
        revoked: false,
    };
    let rendered = output::render_device_added(&device);
    assert!(rendered.contains("abcd"), "got: {rendered}");
    assert!(
        !rendered.contains("..."),
        "short id should not have ellipsis: {rendered}"
    );
}

// ============================================================
// render_device_revoked tests
// ============================================================

#[test]
fn format_device_revoked_truncates_long_id() {
    let id = "01".repeat(16);
    let rendered = output::render_device_revoked(&id);
    assert!(rendered.contains("device revoked:"), "got: {rendered}");
    assert!(rendered.contains("0101010101010101..."), "got: {rendered}");
}

#[test]
fn format_device_revoked_short_id_shown_in_full() {
    let rendered = output::render_device_revoked("abcdef");
    assert!(
        rendered.contains("device revoked: abcdef"),
        "got: {rendered}"
    );
}

// ============================================================
// render_error tests
// ============================================================

#[test]
fn format_error_prefixes_with_error() {
    let rendered = output::render_error("connection refused");
    assert_eq!(rendered, "error: connection refused\n");
}

#[test]
fn format_error_empty_message() {
    let rendered = output::render_error("");
    assert_eq!(rendered, "error: \n");
}

// ============================================================
// expand_data_dir tests
// ============================================================

#[test]
fn expand_data_dir_none_uses_platform_native_default() {
    let p = super::expand_data_dir(None);
    let expected_parent = dirs::data_dir().expect("data_dir");
    assert_eq!(p, expected_parent.join("viaticum"));
}

#[test]
fn expand_data_dir_tilde_expansion_uses_home_dir() {
    let p = super::expand_data_dir(Some("~/custom-sb"));
    let home = dirs::home_dir().expect("home_dir");
    assert_eq!(p, home.join("custom-sb"));
}

#[test]
fn expand_data_dir_tilde_only_returns_home() {
    let p = super::expand_data_dir(Some("~"));
    let home = dirs::home_dir().expect("home_dir");
    assert_eq!(p, home);
}

#[test]
fn expand_data_dir_absolute_path_passthrough() {
    let p = super::expand_data_dir(Some("/var/lib/viaticum"));
    assert_eq!(p, std::path::PathBuf::from("/var/lib/viaticum"));
}

#[test]
fn expand_data_dir_relative_path_passthrough() {
    let p = super::expand_data_dir(Some("./local-data"));
    assert_eq!(p, std::path::PathBuf::from("./local-data"));
}

// ============================================================
// resolve_connection tests
// ============================================================

#[test]
fn resolve_connection_returns_explicit_when_both_provided() {
    let conn = super::resolve_connection(
        Some("http://remote:8080".to_string()),
        Some("tok123".to_string()),
        std::path::Path::new("/nonexistent"),
    )
    .unwrap();
    assert_eq!(conn.url, "http://remote:8080");
    assert_eq!(conn.token, "tok123");
}

#[test]
fn resolve_connection_errors_when_only_server_provided() {
    let err = super::resolve_connection(
        Some("http://remote:8080".to_string()),
        None,
        std::path::Path::new("/nonexistent"),
    );
    assert!(err.is_err());
}

#[test]
fn resolve_connection_errors_when_only_token_provided() {
    let err = super::resolve_connection(
        None,
        Some("tok123".to_string()),
        std::path::Path::new("/nonexistent"),
    );
    assert!(err.is_err());
}

#[test]
fn resolve_connection_reads_port_and_token_from_data_dir_when_neither_provided() {
    let tmp = tempfile::tempdir().unwrap();
    crate::daemon::web_auth::load_or_create_token(tmp.path()).unwrap();
    crate::daemon::web_auth::write_port_file(tmp.path(), 12345).unwrap();
    let conn = super::resolve_connection(None, None, tmp.path()).unwrap();
    assert_eq!(conn.url, "http://127.0.0.1:12345");
    assert!(!conn.token.is_empty());
}

#[test]
fn build_auth_url_local_uses_loopback_and_port() {
    let conn = super::Connection {
        url: "http://127.0.0.1:12345".into(),
        token: "tok".into(),
    };
    let url = super::build_auth_start_url(&conn);
    assert_eq!(url, "http://127.0.0.1:12345/auth/start?token=tok");
}

#[test]
fn build_auth_url_remote_preserves_host() {
    let conn = super::Connection {
        url: "http://nas.local:8080".into(),
        token: "tok".into(),
    };
    let url = super::build_auth_start_url(&conn);
    assert_eq!(url, "http://nas.local:8080/auth/start?token=tok");
}

#[test]
fn build_auth_url_percent_encodes_special_chars() {
    let conn = super::Connection {
        url: "http://127.0.0.1:1234".into(),
        token: "a b/c+d".into(),
    };
    let url = super::build_auth_start_url(&conn);
    assert_eq!(url, "http://127.0.0.1:1234/auth/start?token=a%20b%2Fc%2Bd");
}

// ============================================================
// CBOR roundtrip tests
// ============================================================

fn cbor_encode<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).expect("cbor encode failed");
    buf
}

fn cbor_decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
    ciborium::de::from_reader(bytes).expect("cbor decode failed")
}

#[test]
fn cli_request_roundtrips_cbor() {
    let requests = vec![
        CliRequest::Status,
        CliRequest::Files {
            path_prefix: Some("photos/".into()),
        },
        CliRequest::Versions {
            path: "doc.pdf".into(),
        },
        CliRequest::Restore {
            path: "a".into(),
            version: Some(2),
            date: None,
            dest: None,
        },
        CliRequest::RestoreJobStatus { job_id: "j".into() },
        CliRequest::RestoreJobList,
        CliRequest::DeviceList,
        CliRequest::DeviceAdd {
            label: "phone".into(),
        },
        CliRequest::DeviceRevoke {
            device_id_hex: "01".repeat(16),
        },
    ];
    for req in &requests {
        let bytes = cbor_encode(req);
        let decoded: CliRequest = cbor_decode(&bytes);
        assert_eq!(&decoded, req);
    }
}

#[test]
fn cli_response_roundtrips_cbor() {
    use super::types::StatusData;

    let responses = vec![
        CliResponse::Status(Box::new(StatusData {
            node_identity: "aabbccdd11223344".into(),
            device_id: "aabbccdd11223344".into(),
            node_addr: String::new(),
            peer_count: 3,
            peer_count_connected: 3,
            peer_count_authenticated: 3,
            peer_count_known: 0,
            known_devices: None,
            authenticated_devices: None,
            conn_cache: Default::default(),
            avg_trust: 1.5,
            holding_bytes: 1_000_000,
            backed_up_files: 10,
            backed_up_bytes: 50_000_000,
            blocks_needing_repair: 0,
            peers: vec![],
            effective_quota_bytes: 0,
            quota_state: "bytes".into(),
            quota_note: String::new(),
            below_reserve_giving_back_bytes: None,
            used_bytes: 1_000_000,
            pos_total_challenges: 0,
            pos_total_passes: 0,
            placement_count: 0,
            placement_alive: 0,
            placement_lost: 0,
            blocks_ok: 0,
            blocks_at_risk: 0,
            table_stats: None,
            by_importance: vec![],
            restore_staging_jobs: 0,
            restore_staging_bytes: Some(0),
            restore_staging_path: String::new(),
            restore_publish: String::new(),
            restore_staging_squeezes_holdings: false,
            dr_pointer_published_at: 0,
            dr_pointer_files: 0,
            dr_pointer_acks: 0,
            catalog_lineage: String::new(),
            files_without_source: 0,
            dr_ready: false,
            dr_pointer_ack_threshold: 0,
            dr_ss_blocks_placed: 0,
            dr_ss_blocks_total: 0,
            dr_pointer_refusal: String::new(),
            dr_waiting_since: 0,
            dr_waiting: String::new(),
            dr_restores_state_of: 0,
            files_too_large: 0,
            max_file_size_bytes: 0,
            block_work_budget_bytes: 0,
        })),
        CliResponse::DeviceList(vec![]),
        CliResponse::Error("oops".into()),
        CliResponse::RestoreJob(finished_job(RestoreOutcome::Partial)),
        CliResponse::RestoreJobs(vec![finished_job(RestoreOutcome::Complete)]),
        CliResponse::RestoreRejected(RestoreRejection::Busy { active: 3 }),
        CliResponse::DeviceRevoked {
            device_id_hex: "01".repeat(16),
        },
        CliResponse::Files(vec![]),
        CliResponse::Versions(vec![]),
    ];
    for resp in &responses {
        let bytes = cbor_encode(resp);
        let decoded: CliResponse = cbor_decode(&bytes);
        assert_eq!(&decoded, resp);
    }
}

// ============================================================
// B1.3: restore as a job — CLI contract (restore-i3, i4, i15)
// ============================================================

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use super::restore::{
    RestoreApi, RestoreArgs, WaitError, WaitPolicy, run_restore_with, wait_for_job,
};

fn job(state: RestoreJobState, restored: u32, total: u32) -> RestoreJob {
    RestoreJob {
        job_id: "3f2a0000-0000-4000-8000-000000000001".into(),
        path: "/home/kolya/photos/".into(),
        state,
        files_total: total,
        files_restored: restored,
        restored_paths: (0..restored)
            .map(|i| format!("/home/kolya/photos/{i}.jpg"))
            .collect(),
        failures: vec![],
        outcome: None,
        staging_path: "/home/kolya/.local/share/viaticum/restore/3f2a".into(),
        submitted_at: "2026-09-27T10:00:00Z".into(),
        finished_at: None,
        waiting_for_holders_until: None,
    }
}

fn finished_job(outcome: RestoreOutcome) -> RestoreJob {
    let (restored, failures) = match outcome {
        RestoreOutcome::Complete => (3, vec![]),
        RestoreOutcome::Partial => (2, vec![holders_failure("/home/kolya/photos/c.jpg")]),
        RestoreOutcome::NothingRestored => (
            0,
            vec![
                holders_failure("/home/kolya/photos/a.jpg"),
                holders_failure("/home/kolya/photos/b.jpg"),
                holders_failure("/home/kolya/photos/c.jpg"),
            ],
        ),
        RestoreOutcome::Interrupted => (
            1,
            vec![RestoreFailure {
                path: "/home/kolya/photos/".into(),
                kind: RestoreFailureKind::Interrupted,
                detail: "daemon stopped during restore".into(),
            }],
        ),
    };
    RestoreJob {
        failures,
        outcome: Some(outcome),
        finished_at: Some("2026-09-27T11:00:00Z".into()),
        ..job(RestoreJobState::Finished, restored, 3)
    }
}

fn holders_failure(path: &str) -> RestoreFailure {
    RestoreFailure {
        path: path.into(),
        kind: RestoreFailureKind::HoldersUnavailable,
        detail: "not enough holders answered: collected 3 of 5 symbols".into(),
    }
}

#[test]
fn restore_outcome_exit_codes_complete_0_partial_2_nothing_1_interrupted_1() {
    assert_eq!(RestoreOutcome::Complete.exit_code(), 0);
    assert_eq!(RestoreOutcome::Partial.exit_code(), 2);
    assert_eq!(RestoreOutcome::NothingRestored.exit_code(), 1);
    assert_eq!(RestoreOutcome::Interrupted.exit_code(), 1);
}

#[test]
fn outcome_from_counts_zero_total_is_nothing_restored() {
    assert_eq!(
        RestoreOutcome::from_counts(0, 0, 0, false),
        RestoreOutcome::NothingRestored
    );
    assert_eq!(
        RestoreOutcome::from_counts(0, 0, 1, false),
        RestoreOutcome::NothingRestored
    );
}

#[test]
fn render_restore_finished_lists_each_failed_path_with_reason_and_retry_hint() {
    let mut j = finished_job(RestoreOutcome::Partial);
    j.failures.push(RestoreFailure {
        path: "/home/kolya/photos/d.jpg".into(),
        kind: RestoreFailureKind::WriteFailed,
        detail: "file already exists in staging".into(),
    });
    let out = output::render_restore_finished(&j);
    assert!(out.contains("2 of 3 file(s) restored"), "{out}");
    assert!(out.contains("not restored (2)"), "{out}");
    assert!(
        out.contains("/home/kolya/photos/c.jpg — not enough holders answered; retry later"),
        "{out}"
    );
    assert!(out.contains("collected 3 of 5 symbols"), "{out}");
    assert!(
        out.contains("/home/kolya/photos/d.jpg — could not write it into staging"),
        "{out}"
    );
    assert!(
        out.contains("Retry: viaticum restore /home/kolya/photos/"),
        "{out}"
    );
    assert!(out.contains(&j.staging_path), "{out}");
}

#[test]
fn render_restore_finished_never_says_started() {
    for o in [
        RestoreOutcome::Complete,
        RestoreOutcome::Partial,
        RestoreOutcome::NothingRestored,
        RestoreOutcome::Interrupted,
    ] {
        let out = output::render_restore_finished(&finished_job(o));
        assert!(!out.contains("started"), "{o:?}: {out}");
    }
    let nothing = output::render_restore_finished(&finished_job(RestoreOutcome::NothingRestored));
    assert!(
        nothing.starts_with("restore failed: nothing restored"),
        "{nothing}"
    );
}

#[test]
fn render_restore_finished_says_staging_is_not_protected() {
    let out = output::render_restore_finished(&finished_job(RestoreOutcome::Complete));
    assert!(out.contains("NOT protected"), "{out}");
    assert!(out.contains("within ~4 weeks of the deletion"), "{out}");
    assert!(!out.contains("Retry:"), "nothing to retry: {out}");
    let nothing = output::render_restore_finished(&finished_job(RestoreOutcome::NothingRestored));
    assert!(
        !nothing.contains("NOT protected"),
        "no files, no note: {nothing}"
    );
}

#[test]
fn render_restore_rejection_not_in_catalog_names_path() {
    let out = output::render_restore_rejection(&RestoreRejection::NotInCatalog {
        path: "/home/kolya/files/nope.bin".into(),
    });
    assert!(out.contains("/home/kolya/files/nope.bin"), "{out}");
    assert!(out.contains("not in the backup catalog"), "{out}");
}

#[test]
fn render_restore_rejection_version_not_found_names_version_and_available() {
    let out = output::render_restore_rejection(&RestoreRejection::VersionNotFound {
        path: "/home/kolya/a.txt".into(),
        version: 7,
        available: vec![1, 3],
    });
    assert!(
        out.contains("version 7 not found for /home/kolya/a.txt (available: 1, 3)"),
        "{out}"
    );
    assert!(!out.contains("nothing under"), "{out}");
}

const FAST: WaitPolicy = WaitPolicy {
    poll_every: Duration::from_secs(2),
    max_silence: Duration::from_secs(60),
    progress_every: Duration::from_secs(10),
};

type Poll = Result<Option<RestoreJob>, CliError>;

fn polls(items: Vec<Poll>) -> impl FnMut() -> Poll {
    let mut q: VecDeque<Poll> = items.into();
    move || q.pop_front().expect("polled past the script")
}

fn unreachable_err() -> CliError {
    CliError::DaemonNotReachable {
        reason: "connection refused".into(),
    }
}

#[test]
fn wait_for_job_polls_until_finished() {
    let mut slept = Duration::ZERO;
    let done = wait_for_job(
        polls(vec![
            Ok(Some(job(RestoreJobState::Queued, 0, 3))),
            Ok(Some(job(RestoreJobState::Running, 1, 3))),
            Ok(Some(finished_job(RestoreOutcome::Complete))),
        ]),
        |d| slept += d,
        |_| {},
        FAST,
    )
    .unwrap();
    assert_eq!(done.outcome, Some(RestoreOutcome::Complete));
    assert_eq!(slept, Duration::from_secs(4), "polled every 2 s");
}

/// restore-i4: no overall deadline — a job that runs for hours is waited for.
#[test]
fn wait_for_job_has_no_overall_deadline() {
    let mut script: Vec<Poll> = (0..5000)
        .map(|_| Ok(Some(job(RestoreJobState::Running, 1, 3))))
        .collect();
    script.push(Ok(Some(finished_job(RestoreOutcome::Complete))));
    let done = wait_for_job(polls(script), |_| {}, |_| {}, FAST).unwrap();
    assert_eq!(done.outcome, Some(RestoreOutcome::Complete));
}

#[test]
fn wait_for_job_reports_progress_only_on_change() {
    let running = |n| Ok(Some(job(RestoreJobState::Running, n, 9)));
    let mut seen: Vec<(RestoreJobState, u32)> = Vec::new();
    wait_for_job(
        polls(vec![
            Ok(Some(job(RestoreJobState::Queued, 0, 9))),
            running(0),
            running(0),
            running(0),
            running(0),
            running(0),
            running(0),
            running(1),
            running(1),
            running(1),
            running(1),
            running(1),
            Ok(Some(finished_job(RestoreOutcome::Complete))),
        ]),
        |_| {},
        |j| seen.push((j.state, j.files_restored)),
        FAST,
    )
    .unwrap();
    // queued at once; running 0/9 once 10 s later; 1/9 once, never repeated.
    assert_eq!(
        seen,
        vec![
            (RestoreJobState::Queued, 0),
            (RestoreJobState::Running, 0),
            (RestoreJobState::Running, 1),
        ]
    );
}

#[test]
fn wait_for_job_gives_up_after_max_silence_with_last_known_job() {
    let mut script: Vec<Poll> = vec![Ok(Some(job(RestoreJobState::Running, 2, 3)))];
    script.extend((0..40).map(|_| Err(unreachable_err())));
    let polled_after = std::cell::Cell::new(0u32);
    let err = wait_for_job(
        {
            let mut inner = polls(script);
            let polled_after = &polled_after;
            move || {
                polled_after.set(polled_after.get() + 1);
                inner()
            }
        },
        |_| {},
        |_| {},
        FAST,
    )
    .unwrap_err();
    let WaitError::LostContact { last_known } = err;
    assert_eq!(last_known.unwrap().files_restored, 2);
    // 1 good poll + 31 failures: 31 × 2 s > 60 s.
    assert_eq!(polled_after.get(), 32);
}

#[test]
fn wait_for_job_tolerates_short_daemon_silence() {
    let mut script: Vec<Poll> = vec![Ok(Some(job(RestoreJobState::Running, 0, 3)))];
    script.extend((0..20).map(|_| Err(unreachable_err())));
    script.push(Ok(Some(finished_job(RestoreOutcome::Complete))));
    let done = wait_for_job(polls(script), |_| {}, |_| {}, FAST).unwrap();
    assert_eq!(done.outcome, Some(RestoreOutcome::Complete));
}

#[test]
fn wait_for_job_treats_unknown_job_as_lost_contact() {
    let err = wait_for_job(
        polls(vec![
            Ok(Some(job(RestoreJobState::Running, 0, 3))),
            Ok(None),
        ]),
        |_| {},
        |_| {},
        FAST,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        WaitError::LostContact {
            last_known: Some(_)
        }
    ));
}

#[test]
fn command_restore_status_without_id_lists_jobs() {
    let Command::Restore { status, path, .. } = parse(&["viaticum", "restore", "--status"]) else {
        panic!("expected Restore");
    };
    assert_eq!(status.as_deref(), Some(""));
    assert_eq!(path, None);
}

#[test]
fn command_restore_status_with_id() {
    let Command::Restore { status, json, .. } =
        parse(&["viaticum", "restore", "--status", "3f2a", "--json"])
    else {
        panic!("expected Restore");
    };
    assert_eq!(status.as_deref(), Some("3f2a"));
    assert!(json);
    assert!(
        Cli::try_parse_from(["viaticum", "restore", "--status", "3f2a", "--no-wait"]).is_err(),
        "--status conflicts with --no-wait"
    );
}

#[test]
fn command_restore_without_path_or_status_is_invalid() {
    let cmd = parse(&["viaticum", "restore"]);
    let err = run(&cmd).unwrap_err();
    assert!(matches!(err, CliError::InvalidArgument(_)), "{err:?}");
}

#[test]
fn command_restore_parses_no_wait_and_json() {
    let Command::Restore {
        path,
        no_wait,
        json,
        ..
    } = parse(&["viaticum", "restore", "/a/b", "--no-wait", "--json"])
    else {
        panic!("expected Restore");
    };
    assert_eq!(path.as_deref(), Some("/a/b"));
    assert!(no_wait && json);
}

// ─── run_restore over a scripted daemon ───────────────────────────────────────

#[derive(Clone, Default)]
struct SharedBuf(Rc<RefCell<Vec<u8>>>);

impl SharedBuf {
    fn text(&self) -> String {
        String::from_utf8(self.0.borrow().clone()).unwrap()
    }
}

impl std::io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The daemon's restore endpoints, scripted. Records every call and what stdout
/// held at the first poll.
struct FakeApi {
    submit: RefCell<Option<Result<RestoreJob, RestoreRejection>>>,
    polls: RefCell<VecDeque<Poll>>,
    out: SharedBuf,
    out_at_first_poll: RefCell<Option<String>>,
    calls: RefCell<Vec<&'static str>>,
}

impl FakeApi {
    fn new(
        submit: Result<RestoreJob, RestoreRejection>,
        polls: Vec<Poll>,
        out: &SharedBuf,
    ) -> Self {
        FakeApi {
            submit: RefCell::new(Some(submit)),
            polls: RefCell::new(polls.into()),
            out: out.clone(),
            out_at_first_poll: RefCell::new(None),
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl RestoreApi for FakeApi {
    fn submit(&self, _body: String) -> Result<Result<RestoreJob, RestoreRejection>, CliError> {
        self.calls.borrow_mut().push("submit");
        Ok(self.submit.borrow_mut().take().expect("one submit"))
    }
    fn get_job(&self, _job_id: &str) -> Result<Option<RestoreJob>, CliError> {
        self.calls.borrow_mut().push("get_job");
        self.out_at_first_poll
            .borrow_mut()
            .get_or_insert_with(|| self.out.text());
        self.polls
            .borrow_mut()
            .pop_front()
            .expect("polled past the script")
    }
    fn list_jobs(&self) -> Result<Vec<RestoreJob>, CliError> {
        self.calls.borrow_mut().push("list_jobs");
        Ok(vec![finished_job(RestoreOutcome::Complete)])
    }
}

fn args(json: bool) -> RestoreArgs<'static> {
    RestoreArgs {
        path: Some("/home/kolya/photos/"),
        version: None,
        date: None,
        dest: None,
        no_wait: false,
        status: None,
        json,
    }
}

/// Run over the fake; (exit code, stdout, stderr).
fn run_fake(api: &FakeApi, a: RestoreArgs<'_>) -> (i32, String, String) {
    let err = SharedBuf::default();
    let code = run_restore_with(
        a,
        api,
        &mut api.out.clone(),
        &mut err.clone(),
        &mut |_| {},
        FAST,
    )
    .unwrap();
    (code, api.out.text(), err.text())
}

/// restore-i3: the exit code is the job's outcome — a job that restored nothing is
/// a failure (1), partial is 2, complete 0; never "success" for nothing restored.
#[test]
fn run_restore_exits_by_the_finished_job_outcome() {
    for (outcome, code) in [
        (RestoreOutcome::Complete, 0),
        (RestoreOutcome::Partial, 2),
        (RestoreOutcome::NothingRestored, 1),
        (RestoreOutcome::Interrupted, 1),
    ] {
        let out = SharedBuf::default();
        let api = FakeApi::new(
            Ok(job(RestoreJobState::Queued, 0, 3)),
            vec![
                Ok(Some(job(RestoreJobState::Running, 0, 3))),
                Ok(Some(finished_job(outcome))),
            ],
            &out,
        );
        let (got, stdout, _) = run_fake(&api, args(false));
        assert_eq!(got, code, "{outcome:?}: {stdout}");
    }
}

/// restore-i15: the job id reaches stdout before any waiting, so Ctrl-C during the
/// wait loses nothing; the JSON first line is the submitted job, the last the
/// finished one.
#[test]
fn json_mode_prints_submitted_job_before_waiting() {
    let out = SharedBuf::default();
    let api = FakeApi::new(
        Ok(job(RestoreJobState::Queued, 0, 3)),
        vec![
            Ok(Some(job(RestoreJobState::Running, 1, 3))),
            Ok(Some(finished_job(RestoreOutcome::Partial))),
        ],
        &out,
    );
    let (code, stdout, _) = run_fake(&api, args(true));
    assert_eq!(code, 2);

    let first_poll = api.out_at_first_poll.borrow().clone().unwrap();
    let submitted: RestoreJob = serde_json::from_str(first_poll.trim()).unwrap();
    assert_eq!(submitted.state, RestoreJobState::Queued);

    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "NDJSON: submitted + final, no progress lines: {stdout}"
    );
    let last: RestoreJob = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(last.outcome, Some(RestoreOutcome::Partial));
}

/// restore-i15: the CLI only ever submits and reads; it has no way to stop a job.
#[test]
fn run_restore_only_submits_and_reads_the_job() {
    let out = SharedBuf::default();
    let api = FakeApi::new(
        Ok(job(RestoreJobState::Queued, 0, 3)),
        vec![Ok(Some(finished_job(RestoreOutcome::Complete)))],
        &out,
    );
    let (_, stdout, _) = run_fake(&api, args(false));
    assert_eq!(*api.calls.borrow(), vec!["submit", "get_job"]);
    assert!(
        stdout.contains("Ctrl-C stops watching, not the restore"),
        "{stdout}"
    );
    assert!(
        stdout.contains("viaticum restore --status 3f2a"),
        "{stdout}"
    );
}

#[test]
fn run_restore_rejected_submit_exits_1_without_polling() {
    let out = SharedBuf::default();
    let api = FakeApi::new(
        Err(RestoreRejection::NotInCatalog {
            path: "/home/kolya/photos/".into(),
        }),
        vec![],
        &out,
    );
    let (code, stdout, stderr) = run_fake(&api, args(false));
    assert_eq!(code, 1);
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("not in the backup catalog"), "{stderr}");
    assert_eq!(*api.calls.borrow(), vec!["submit"]);
}

#[test]
fn run_restore_no_wait_exits_0_after_printing_the_job() {
    let out = SharedBuf::default();
    let api = FakeApi::new(Ok(job(RestoreJobState::Queued, 0, 3)), vec![], &out);
    let (code, stdout, _) = run_fake(
        &api,
        RestoreArgs {
            no_wait: true,
            ..args(false)
        },
    );
    assert_eq!(code, 0);
    assert!(stdout.contains("submitted"), "{stdout}");
    assert_eq!(*api.calls.borrow(), vec!["submit"]);
}

#[test]
fn run_restore_lost_contact_exits_1_and_names_staging() {
    let out = SharedBuf::default();
    let mut script: Vec<Poll> = vec![Ok(Some(job(RestoreJobState::Running, 1, 3)))];
    script.extend((0..40).map(|_| Err(unreachable_err())));
    let api = FakeApi::new(Ok(job(RestoreJobState::Queued, 0, 3)), script, &out);
    let (code, _, stderr) = run_fake(&api, args(false));
    assert_eq!(code, 1);
    assert!(stderr.contains("lost contact with the daemon"), "{stderr}");
    assert!(stderr.contains("/restore/3f2a"), "{stderr}");
    assert!(
        stderr.contains("viaticum restore --status 3f2a"),
        "{stderr}"
    );
}

#[test]
fn run_restore_status_unknown_id_exits_1_and_known_exits_0() {
    let out = SharedBuf::default();
    let api = FakeApi::new(Ok(job(RestoreJobState::Queued, 0, 3)), vec![Ok(None)], &out);
    let (code, _, stderr) = run_fake(
        &api,
        RestoreArgs {
            path: None,
            status: Some("nope"),
            ..args(false)
        },
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("unknown restore job nope"), "{stderr}");

    let out = SharedBuf::default();
    let api = FakeApi::new(
        Ok(job(RestoreJobState::Queued, 0, 3)),
        vec![Ok(Some(finished_job(RestoreOutcome::Interrupted)))],
        &out,
    );
    let (code, stdout, _) = run_fake(
        &api,
        RestoreArgs {
            path: None,
            status: Some("3f2a"),
            json: true,
            ..args(false)
        },
    );
    assert_eq!(code, 0, "found");
    let j: RestoreJob = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(j.outcome, Some(RestoreOutcome::Interrupted));
}

// ── DR readiness and missing sources in `status` (dr-i9, dr-i11) ──────────────

#[test]
fn status_render_says_dr_not_ready_before_any_accepted_publication() {
    let data = make_status_zero_peers();
    let rendered = output::render_status(&data);
    assert!(
        rendered.contains("DR:             NOT READY"),
        "got: {rendered}"
    );
    assert!(
        !rendered.contains("files without local source"),
        "got: {rendered}"
    );
}

#[test]
fn status_render_says_dr_ready_with_time_files_and_acks() {
    let mut data = make_status_zero_peers();
    data.dr_pointer_published_at = 1_790_000_000;
    data.dr_pointer_files = 3;
    data.dr_pointer_acks = 2;
    data.dr_ready = true;
    let rendered = output::render_status(&data);
    assert!(
        rendered.contains("DR:             ready: recovery pointer published 2026-09-21T"),
        "got: {rendered}"
    );
    assert!(
        rendered.contains("3 files, accepted by 2 peer(s)"),
        "got: {rendered}"
    );
}

/// dr-i39 / dr-i41: an accepted pointer below the threshold, with catalog blocks not
/// stored yet, is NOT READY in words, with the counts.
#[test]
fn status_render_says_not_ready_with_acks_needed_and_unplaced_catalog_blocks() {
    let mut data = make_status_zero_peers();
    data.dr_pointer_published_at = 1_790_000_000;
    data.dr_pointer_files = 3;
    data.dr_pointer_acks = 1;
    data.dr_pointer_ack_threshold = 3;
    data.dr_ss_blocks_placed = 1;
    data.dr_ss_blocks_total = 2;
    let rendered = output::render_status(&data);
    assert!(
        rendered.contains("DR:             NOT READY"),
        "got: {rendered}"
    );
    assert!(
        rendered.contains("accepted by 1 of the 3 friends needed"),
        "got: {rendered}"
    );
    assert!(
        rendered.contains("the catalog blocks are not stored at friends yet (1 of 2)"),
        "got: {rendered}"
    );
}

/// mailbox-i49 / i54: the refusal and the wait are printed as the daemon worded them.
#[test]
fn status_render_prints_refusal_and_waiting_lines() {
    let mut data = make_status_zero_peers();
    data.dr_pointer_refusal =
        "DR: friends hold a pointer newer than this computer's clock — the clock went back"
            .to_string();
    data.dr_waiting_since = 1_790_000_000;
    data.dr_waiting = "friends refused".to_string();
    let rendered = output::render_status(&data);
    assert!(rendered.contains("the clock went back"), "got: {rendered}");
    assert!(
        rendered.contains(
            "the newest catalog changes are not in the network yet (waiting since 2026-09-21T"
        ),
        "got: {rendered}"
    );
    assert!(rendered.contains(": friends refused)"), "got: {rendered}");
}

#[test]
fn status_render_counts_files_without_local_source_when_positive() {
    let mut data = make_status_zero_peers();
    data.files_without_source = 3;
    let rendered = output::render_status(&data);
    assert!(
        rendered.contains("files without local source: 3 (not re-protected"),
        "got: {rendered}"
    );
}

// ─── restore-i26: a job waiting for holders does not look hung ───────────────

fn waiting_job(until: &str) -> RestoreJob {
    RestoreJob {
        waiting_for_holders_until: Some(until.into()),
        ..job(RestoreJobState::Running, 1, 3)
    }
}

#[test]
fn render_restore_progress_when_waiting_for_holders_shows_retry_in_relative_time() {
    // 2026-09-27T10:05:00Z = 1790503500; now = 4 min before.
    let now = 1_790_503_500 - 240;
    let line = output::render_restore_progress(&waiting_job("2026-09-27T10:05:00Z"), now);
    assert!(
        line.starts_with("running: 1/3 restored, 0 failed"),
        "{line}"
    );
    assert!(
        line.contains("holders did not answer") && line.contains("retry in 4 min"),
        "{line}"
    );
    let plain = output::render_restore_progress(&job(RestoreJobState::Running, 1, 3), now);
    assert!(!plain.contains("did not answer"), "{plain}");
}

#[test]
fn retry_in_counts_down_from_the_wire_time() {
    let until = "2026-09-27T10:05:00Z";
    let t = 1_790_503_500u64;
    assert_eq!(
        crate::daemon::dispatch::unix_secs_to_iso(t, true),
        until,
        "test anchor matches the daemon's formatter"
    );
    assert_eq!(output::retry_in(until, t - 30), "retry in 30 s");
    assert_eq!(output::retry_in(until, t - 61), "retry in 2 min");
    assert_eq!(output::retry_in(until, t - 3_720), "retry in 1 h 2 min");
    assert_eq!(output::retry_in(until, t), "retrying now");
    assert_eq!(output::retry_in(until, t + 5), "retrying now");
    assert_eq!(output::retry_in("soon", t), "retry at soon");
}

#[test]
fn wait_for_job_reports_when_job_starts_and_stops_waiting_for_holders() {
    let mut seen: Vec<bool> = Vec::new();
    wait_for_job(
        polls(vec![
            Ok(Some(job(RestoreJobState::Running, 1, 3))),
            Ok(Some(job(RestoreJobState::Running, 1, 3))),
            Ok(Some(job(RestoreJobState::Running, 1, 3))),
            Ok(Some(job(RestoreJobState::Running, 1, 3))),
            Ok(Some(job(RestoreJobState::Running, 1, 3))),
            Ok(Some(waiting_job("2026-09-27T10:05:00Z"))),
            Ok(Some(waiting_job("2026-09-27T10:05:00Z"))),
            Ok(Some(waiting_job("2026-09-27T10:05:00Z"))),
            Ok(Some(waiting_job("2026-09-27T10:05:00Z"))),
            Ok(Some(waiting_job("2026-09-27T10:05:00Z"))),
            Ok(Some(job(RestoreJobState::Running, 1, 3))),
            Ok(Some(finished_job(RestoreOutcome::Complete))),
        ]),
        |_| {},
        |j| seen.push(j.waiting_for_holders_until.is_some()),
        FAST,
    )
    .unwrap();
    assert_eq!(seen, vec![false, true, false]);
}

#[test]
fn restore_job_wire_omits_waiting_field_unless_waiting() {
    let plain = serde_json::to_value(job(RestoreJobState::Running, 1, 3)).unwrap();
    assert!(plain.get("waiting_for_holders_until").is_none(), "{plain}");
    let waiting = serde_json::to_value(waiting_job("2026-09-27T10:05:00Z")).unwrap();
    assert_eq!(waiting["waiting_for_holders_until"], "2026-09-27T10:05:00Z");
    let back: RestoreJob = serde_json::from_value(plain).unwrap();
    assert_eq!(back.waiting_for_holders_until, None);
}

// ============================================================
// R1-d-a (backup-i4, backup-i7): too-large files
// ============================================================

fn too_large_entry(last_backed_up: &str, versions: u32) -> FileEntry {
    FileEntry {
        path: "movies/huge.mkv".into(),
        versions,
        last_backed_up: last_backed_up.into(),
        size_bytes: 0,
        local_state: "present".into(),
        effective_status: None,
        is_safe_to_delete: false,
        too_large: Some(crate::cli::types::TooLargeInfo {
            size_bytes: 4 * 1024 * 1024 * 1024,
            limit_bytes: 256 * 1024 * 1024,
            since: "2026-09-30".into(),
        }),
    }
}

#[test]
fn render_files_shows_too_large_instead_of_date() {
    let rendered = output::render_files(&[too_large_entry("never", 0)]);
    assert!(
        rendered.contains("too large for this machine (4.00 GB > 256.0 MB)"),
        "got: {rendered}"
    );
    assert!(
        rendered.contains("not supported yet, not backed up"),
        "got: {rendered}"
    );
    assert!(!rendered.contains("never"), "no date column: {rendered}");
    assert!(!rendered.contains("0 versions"), "got: {rendered}");
}

#[test]
fn render_files_names_the_kept_version_of_a_grown_file() {
    let rendered = output::render_files(&[too_large_entry("2026-09-01", 2)]);
    assert!(
        rendered.contains("too large for this machine"),
        "got: {rendered}"
    );
    assert!(
        rendered.contains("the version of 2026-09-01 is kept in the network but no longer checked"),
        "got: {rendered}"
    );
}

#[test]
fn render_files_says_a_deleted_grown_file_is_being_released() {
    let mut entry = too_large_entry("2026-09-01", 2);
    entry.local_state = "deleted".into();
    let rendered = output::render_files(&[entry]);
    assert!(
        rendered.contains("deleted; its copies are released after the deletion window"),
        "got: {rendered}"
    );
    assert!(
        !rendered.contains("is kept in the network"),
        "a deleted file's copies are not kept: {rendered}"
    );
}

#[test]
fn render_status_reports_too_large_files_and_the_limit() {
    let mut data = make_status_zero_peers();
    let quiet = output::render_status(&data);
    assert!(!quiet.contains("too large:"), "got: {quiet}");
    assert!(!quiet.contains("size limit:"), "got: {quiet}");

    data.files_too_large = 2;
    data.max_file_size_bytes = 256 * 1024 * 1024;
    let rendered = output::render_status(&data);
    assert!(
        rendered.contains("size limit:     256.0 MB per file on this machine"),
        "got: {rendered}"
    );
    assert!(
        rendered.contains(
            "too large:      2 file(s) above the limit: not supported yet, not backed up"
        ),
        "got: {rendered}"
    );
}
