use clap::Parser;

use super::output;
use super::types::{
    CliRequest, CliResponse, DeviceEntry, FileEntry, PeerSummary, RestoreData, StatusData,
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
    } = cmd
    else {
        panic!("expected Restore");
    };
    assert_eq!(path, "photos/img.jpg");
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

fn run(cmd: &Command) -> Result<(), CliError> {
    // 127.0.0.1:1 is effectively unreachable (port 1 reserved, no listener)
    let conn = super::Connection {
        url: "http://127.0.0.1:1".into(),
        token: "irrelevant".into(),
    };
    super::run_command(cmd, &conn)
}

#[test]
fn run_command_restore_rejects_version_zero() {
    let cmd = Command::Restore {
        path: "f".into(),
        version: Some(0),
        date: None,
        dest: None,
    };
    let err = run(&cmd).unwrap_err();
    assert!(matches!(err, CliError::InvalidArgument(_)));
}

#[test]
fn run_command_restore_rejects_version_and_date_both() {
    let cmd = Command::Restore {
        path: "f".into(),
        version: Some(1),
        date: Some("2026-01-01".into()),
        dest: None,
    };
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
        avg_trust: 0.0,
        holding_bytes: 0,
        backed_up_files: 0,
        backed_up_bytes: 0,
        blocks_needing_repair: 0,
        peers: vec![],
        effective_quota_bytes: 0,
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
    }
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

#[test]
fn format_status_unlimited_quota_when_zero() {
    let data = make_status_zero_peers();
    let rendered = output::render_status(&data);
    assert!(rendered.contains("unlimited"), "got: {rendered}");
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
// render_restore tests
// ============================================================

#[test]
fn format_restore_includes_path_version_status() {
    let data = RestoreData {
        path: "/home/user/doc.pdf".into(),
        version_used: 3,
        content_hash_hex: "aabbccdd11223344556677889900aabb".into(),
        status: "started".into(),
        staging_path: "".into(),
    };
    let rendered = output::render_restore(&data);
    assert!(rendered.contains("restore started"), "got: {rendered}");
    assert!(rendered.contains("/home/user/doc.pdf"), "got: {rendered}");
    assert!(rendered.contains("version:  3"), "got: {rendered}");
    assert!(rendered.contains("status:   started"), "got: {rendered}");
}

#[test]
fn format_restore_hash_truncated_to_16_chars() {
    let data = RestoreData {
        path: "f".into(),
        version_used: 1,
        content_hash_hex: "aabbccdd11223344556677889900aabb".into(),
        status: "queued".into(),
        staging_path: "".into(),
    };
    let rendered = output::render_restore(&data);
    // First 16 chars + "..."
    assert!(rendered.contains("aabbccdd11223344..."), "got: {rendered}");
}

#[test]
fn format_restore_short_hash_not_truncated() {
    let data = RestoreData {
        path: "f".into(),
        version_used: 1,
        content_hash_hex: "aabb".into(),
        status: "queued".into(),
        staging_path: "".into(),
    };
    let rendered = output::render_restore(&data);
    assert!(rendered.contains("aabb"), "got: {rendered}");
    assert!(
        !rendered.contains("..."),
        "short hash should not have ellipsis: {rendered}"
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
    use super::types::{RestoreData, StatusData};

    let responses = vec![
        CliResponse::Status(StatusData {
            node_identity: "aabbccdd11223344".into(),
            device_id: "aabbccdd11223344".into(),
            node_addr: String::new(),
            peer_count: 3,
            peer_count_connected: 3,
            peer_count_authenticated: 3,
            avg_trust: 1.5,
            holding_bytes: 1_000_000,
            backed_up_files: 10,
            backed_up_bytes: 50_000_000,
            blocks_needing_repair: 0,
            peers: vec![],
            effective_quota_bytes: 0,
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
        }),
        CliResponse::DeviceList(vec![]),
        CliResponse::Error("oops".into()),
        CliResponse::Restore(RestoreData {
            path: "test.txt".into(),
            version_used: 2,
            content_hash_hex: "aa".repeat(32),
            status: "queued".into(),
            staging_path: "".into(),
        }),
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
