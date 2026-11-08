pub mod output;
pub mod phrase;
pub mod restore;
pub mod setup;
pub mod types;

#[cfg(test)]
mod tests;

use clap::{Parser, Subcommand};

pub use types::CliError;
use types::CliResponse;

/// Both ends have to be a terminal before `setup`/`phrase check` treat the
/// session as interactive (install-i2 M3″, B1). stdin is a tty in
/// `setup | tee install.log`, stdout is not; a phrase printed there would land
/// in the installer log, so half-tty must behave like a pipe.
pub fn is_interactive(stdin_tty: bool, stdout_tty: bool) -> bool {
    stdin_tty && stdout_tty
}

/// Resolve the data directory path.
/// - `None` → platform-native `dirs::data_dir()/viaticum`.
/// - `Some("~/foo")` / `Some("~")` → expanded via `dirs::home_dir()`.
/// - `Some(absolute_or_relative)` → used as-is.
pub fn expand_data_dir(path: Option<&str>) -> std::path::PathBuf {
    match path {
        None => platform_default_data_dir(),
        Some("~") => dirs::home_dir().expect("HOME not set"),
        Some(s) => match s.strip_prefix("~/") {
            Some(rest) => dirs::home_dir().expect("HOME not set").join(rest),
            None => std::path::PathBuf::from(s),
        },
    }
}

/// The exact stdout of `viaticum init` (byte-identical since R2: E2E scripts
/// and `experiments/polygon/fleet.py` parse `Mnemonic (SAVE THIS):`).
pub fn render_init_output(
    keyfile: &crate::daemon::identity::IdentityKeyFile,
    from_mnemonic: bool,
    new_device: bool,
) -> String {
    use viaticum_core::types::hex_encode;
    let mut out = String::new();
    out.push_str("Identity initialized.\n");
    out.push_str(&format!(
        "Public key: {}\n",
        hex_encode(&keyfile.identity_pub)
    ));
    out.push_str(&format!("Device ID:  {}\n", hex_encode(&keyfile.device_id)));
    out.push_str(&format!(
        "\nMnemonic (SAVE THIS):\n  {}\n",
        keyfile.mnemonic
    ));
    if from_mnemonic && !new_device {
        out.push_str(
            "\nIf you are recovering a lost machine, stop here and use \
             'viaticum dr' instead: a node started from an empty catalog does \
             not bring your files back.\n",
        );
    }
    out
}

/// Read a recovery phrase from stdin (one line, trimmed). Used by
/// `dr --mnemonic` / `init --mnemonic` without a value, so the phrase never
/// lands in shell history or `ps` (install-i2).
pub fn read_phrase_stdin() -> Result<String, CliError> {
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let phrase = read_phrase_line(&mut stdin)
        .map_err(|e| CliError::InvalidArgument(format!("cannot read the recovery phrase: {e}")))?
        .unwrap_or_default();
    if phrase.is_empty() {
        return Err(CliError::InvalidArgument(
            "the recovery phrase is empty (stdin closed?)".into(),
        ));
    }
    Ok(phrase)
}

/// Read one line from any reader, trimmed; `None` at end of input.
pub fn read_phrase_line(reader: &mut impl std::io::BufRead) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim().to_string()))
}

fn platform_default_data_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .expect("could not determine platform data directory (HOME/APPDATA unset?)")
        .join("viaticum")
}

// ============================================================
// Clap CLI structures
// ============================================================

/// viaticum — decentralized P2P cold backup
#[derive(Debug, Parser)]
#[command(name = "viaticum", version = crate::build_info::build_id())]
pub struct Cli {
    /// Data directory. Default: platform-native
    /// (Linux: ~/.local/share/viaticum, macOS: ~/Library/Application Support/viaticum,
    /// Windows: %APPDATA%/viaticum).
    #[arg(long, global = true)]
    pub data_dir: Option<String>,

    /// Connect to a remote daemon URL (e.g. http://nas.local:8080).
    /// Must be combined with --token. Env: VIATICUM_SERVER.
    #[arg(long, global = true, env = "VIATICUM_SERVER")]
    pub server: Option<String>,

    /// Bearer token for remote daemon auth. Env: VIATICUM_TOKEN.
    #[arg(long, global = true, env = "VIATICUM_TOKEN")]
    pub token: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

/// A resolved HTTP connection to a viaticum daemon.
#[derive(Debug, Clone)]
pub struct Connection {
    pub url: String,
    pub token: String,
}

/// Resolve how to reach the daemon:
/// - both `server` and `token` provided → remote mode
/// - neither provided → local mode: read port + token from `data_dir`
/// - only one provided → error (ambiguous)
pub fn resolve_connection(
    server: Option<String>,
    token: Option<String>,
    data_dir: &std::path::Path,
) -> Result<Connection, CliError> {
    match (server, token) {
        (Some(url), Some(tok)) => Ok(Connection { url, token: tok }),
        (Some(_), None) => Err(CliError::InvalidArgument(
            "--server requires --token (or VIATICUM_TOKEN)".into(),
        )),
        (None, Some(_)) => Err(CliError::InvalidArgument(
            "--token without --server is not supported; omit both for local mode".into(),
        )),
        (None, None) => {
            let (port, token) =
                crate::daemon::web_auth::read_port_and_token(data_dir).map_err(|e| {
                    CliError::DaemonNotReachable {
                        reason: format!(
                            "cannot read {}/api-port or api-token: {}",
                            data_dir.display(),
                            e
                        ),
                    }
                })?;
            Ok(Connection {
                url: format!("http://127.0.0.1:{port}"),
                token,
            })
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the viaticum daemon
    Daemon {
        /// Time scale factor (1 = real time, 604800 = 1 sec equals 1 week).
        #[arg(long, default_value = "1")]
        time_scale: u64,
        /// Directories to watch for backup (may be specified multiple times).
        #[arg(long)]
        watch_dir: Vec<std::path::PathBuf>,
        /// Log output format: "text" (default) or "json".
        #[arg(long, default_value = "text")]
        log_format: String,
    },

    /// Initialize a new Viaticum identity
    Init {
        /// BIP39 mnemonic phrase (24 words). If omitted, generates a new one;
        /// with the flag but no value, the phrase is read from stdin.
        #[arg(long, num_args = 0..=1)]
        mnemonic: Option<Option<String>>,
        /// Add this machine as a new device to an existing cluster.
        /// Must be combined with --mnemonic. Generates a random device ID
        /// so this device has its own keys while sharing the cluster identity.
        #[arg(long, requires = "mnemonic")]
        new_device: bool,
    },

    /// Show overall system status
    Status {
        /// Output as JSON (machine-readable)
        #[arg(long)]
        json: bool,
    },

    /// Restore a file or directory from backup into a staging directory.
    ///
    /// Restore is a job in the daemon: this command submits it and, by default,
    /// waits for it (it can take hours). Ctrl-C stops waiting, not the restore.
    /// Exit code: 0 all restored, 2 some restored, 1 nothing restored / refused /
    /// interrupted / lost contact with the daemon.
    Restore {
        /// Path to restore (as stored in the backup catalog). Required unless --status.
        path: Option<String>,

        /// Version number to restore (1-based, 1 = oldest). Default: latest.
        #[arg(long)]
        version: Option<u32>,

        /// Restore the version closest to this date (YYYY-MM-DD). Default: latest.
        #[arg(long)]
        date: Option<String>,

        /// Restore to this destination path instead of the original location.
        /// Accepted for older scripts; restore always writes into `restore/`.
        #[arg(long, hide = true)]
        dest: Option<String>,

        /// Submit the job and exit without waiting for it.
        #[arg(long)]
        no_wait: bool,

        /// `--status` lists recent restore jobs; `--status <JOB_ID>` shows one.
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "",
            value_name = "JOB_ID",
            conflicts_with_all = ["path", "version", "date", "dest", "no_wait"]
        )]
        status: Option<String>,

        /// JSON output: the submitted job on the first line, the finished job on the
        /// last line (with --status: the job or the job list, one line).
        #[arg(long)]
        json: bool,
    },

    /// Manage cluster devices
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },

    /// List backed-up files
    Files {
        /// Filter by path prefix. Lists all files if omitted.
        path_prefix: Option<String>,
    },

    /// Show all versions of a file
    Versions {
        /// Path as stored in the backup catalog
        path: String,
    },

    /// Connect to a peer by node address
    Connect {
        /// Node address (from `viaticum status` on the remote node)
        #[arg()]
        addr: String,
    },

    /// Disaster recovery: restore node state from seed phrase
    Dr {
        /// BIP39 mnemonic phrase (24 words). With the flag but no value, the
        /// phrase is read from stdin.
        #[arg(long, num_args = 0..=1)]
        mnemonic: Option<Option<String>>,
        /// Seed peer multiaddr, e.g. /ip4/1.2.3.4/tcp/4001/p2p/<peer id> (repeatable)
        #[arg(long, num_args = 1..)]
        peer: Vec<String>,
        /// Data directory to restore into (default: global --data-dir)
        #[arg(long)]
        data_dir: Option<String>,
        /// Restore this catalog (hex prefix, at least 8 characters) when DR finds several
        #[arg(long)]
        catalog: Option<String>,
    },

    /// Set up a node: new install or restore from 24 words
    Setup {
        /// New installation or restore; without it, setup asks first.
        #[arg(long, value_enum)]
        mode: Option<setup::SetupMode>,
        /// Folder to keep safe (repeatable).
        #[arg(long = "watch", value_name = "DIR")]
        watch: Vec<std::path::PathBuf>,
        /// Space to give friends, in GB (at least 1).
        #[arg(long)]
        quota_gb: Option<f64>,
        /// Seed multiaddr (repeatable); replaces the template's seeds and is
        /// used as `dr --peer` in restore mode.
        #[arg(long = "seed", value_name = "MULTIADDR")]
        seed: Vec<String>,
        /// Restore without a tty: file with the 24 words, mode 0600.
        #[arg(long)]
        phrase_file: Option<std::path::PathBuf>,
        /// Non-interactive new install: defaults for the unanswered questions,
        /// phrase never printed and not confirmed.
        #[arg(long)]
        yes: bool,
        /// Test-only: accept the phrase without asking (E2E).
        #[arg(long, hide = true)]
        skip_phrase_check: bool,
        /// Allow running as root (the friend's files would belong to root).
        #[arg(long)]
        allow_root: bool,
        /// Print the result as one JSON line for the installer.
        #[arg(long)]
        json: bool,
    },

    /// Show or check your 24 recovery words
    Phrase {
        #[command(subcommand)]
        action: PhraseAction,
    },

    /// Open the web UI in the default browser
    Open,

    /// Print the auth token (or a ready-to-use /auth/start URL with --url)
    Token {
        /// Print the full /auth/start URL instead of just the token.
        #[arg(long)]
        url: bool,
    },

    /// Print this binary's build id and the blake3 of its embedded web UI as JSON
    /// (release checks, install-i11). Needs no daemon.
    #[command(hide = true)]
    BuildInfo,
}

#[derive(Debug, Subcommand)]
pub enum PhraseAction {
    /// Check words from your paper; success writes `phrase-confirmed`
    Check {
        /// Positions to ask, 1-based, comma-separated (default: 3 random).
        #[arg(long, value_delimiter = ',')]
        positions: Vec<usize>,
        /// Ask all 24 positions.
        #[arg(long)]
        all: bool,
    },
    /// Show the phrase from `identity.key` (terminal only)
    Show,
}

#[derive(Debug, Subcommand)]
pub enum DeviceAction {
    /// List all devices in the cluster
    List,

    /// Add a new device (generates an invitation)
    Add {
        /// Human-readable label for the new device
        label: String,
    },

    /// Revoke a device
    Revoke {
        /// Device ID to revoke (hex string, 32 chars)
        device_id: String,
    },
}

// ============================================================
// Local-mode subcommands (open, token)
// ============================================================

pub fn build_auth_start_url(conn: &Connection) -> String {
    format!(
        "{}/auth/start?token={}",
        conn.url.trim_end_matches('/'),
        urlencoding::encode(&conn.token)
    )
}

/// `viaticum token` — print the bearer token, or the full /auth/start URL.
pub fn cmd_token(conn: &Connection, url_mode: bool) {
    if url_mode {
        println!("{}", build_auth_start_url(conn));
    } else {
        println!("{}", conn.token);
    }
}

/// `viaticum build-info` — the build id and the embedded web UI hash, one JSON line.
pub fn render_build_info() -> String {
    serde_json::to_string(&crate::build_info::build_info())
        .expect("BuildInfo is plain strings and serializes")
}

/// `viaticum open` — print the Dashboard URL (always), print an SSH tunnel
/// line when there is no local display, and try the browser as a courtesy
/// (install-i9). A missing browser is not an error: the URL is the product.
pub fn cmd_open(conn: &Connection) -> Result<(), CliError> {
    let url = build_auth_start_url(conn);
    let headless = ssh_connection().is_some() || !has_local_display();
    print!(
        "{}",
        render_open(&url, headless, &current_user(), &current_host())
    );
    if let Err(e) = launch_browser(&url) {
        eprintln!("Could not open a browser ({e}); use the URL above.");
    }
    Ok(())
}

/// The exact text `open` prints. Kept pure for the unit test (install-i9).
pub fn render_open(url: &str, headless: bool, user: &str, host: &str) -> String {
    let mut out = format!("Dashboard: {url}\n");
    if headless {
        let port = url_port(url).unwrap_or(0);
        out.push_str(&format!(
            "On another machine, run: ssh -L {port}:127.0.0.1:{port} {user}@{host}\n"
        ));
    }
    out
}

fn url_port(url: &str) -> Option<u16> {
    let rest = url.split("://").nth(1)?;
    let authority = rest.split('/').next()?;
    let port = authority.rsplit_once(':')?.1;
    port.parse().ok()
}

fn has_local_display() -> bool {
    std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
}

/// `SSH_CONNECTION` is "client_ip client_port server_ip server_port". The server
/// address is what the friend typed into SSH (or the box's address as seen by
/// the client), so the tunnel line works from the same machine they came from.
fn ssh_connection() -> Option<(String, String)> {
    let raw = std::env::var("SSH_CONNECTION").ok()?;
    let mut parts = raw.split_whitespace();
    let _client_ip = parts.next()?;
    let _client_port = parts.next()?;
    let server_ip = parts.next()?;
    Some((server_ip.to_string(), current_user()))
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".to_string())
}

fn current_host() -> String {
    if let Some((host, _)) = ssh_connection() {
        return host;
    }
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "localhost".to_string())
}

fn launch_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        if !std::process::Command::new("open")
            .arg(url)
            .status()?
            .success()
        {
            return Err(std::io::Error::other("open exited with an error"));
        }
    }
    #[cfg(target_os = "linux")]
    {
        if !std::process::Command::new("xdg-open")
            .arg(url)
            .status()?
            .success()
        {
            return Err(std::io::Error::other("xdg-open exited with an error"));
        }
    }
    #[cfg(target_os = "windows")]
    {
        if !std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()?
            .success()
        {
            return Err(std::io::Error::other("start exited with an error"));
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = url;
    }
    Ok(())
}

// ============================================================
// Dispatch (HTTP)
// ============================================================

/// Send the command over HTTP to the daemon, receive `CliResponse`,
/// format and print to stdout. Returns the process exit code (`restore` exits by
/// the job's outcome, see `restore::run_restore`).
pub fn run_command(cmd: &Command, connection: &Connection) -> Result<i32, CliError> {
    if let Command::Restore {
        path,
        version,
        date,
        dest,
        no_wait,
        status,
        json,
    } = cmd
    {
        let args = restore::RestoreArgs {
            path: path.as_deref(),
            version: *version,
            date: date.as_deref(),
            dest: dest.as_deref(),
            no_wait: *no_wait,
            status: status.as_deref(),
            json: *json,
        };
        return restore::run_restore(args, connection);
    }
    let response = send_command_http(connection, cmd)?;
    let json_output = matches!(cmd, Command::Status { json: true });
    handle_response(response, json_output);
    Ok(0)
}

fn send_command_http(conn: &Connection, cmd: &Command) -> Result<CliResponse, CliError> {
    let client = crate::http_client::blocking_builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| CliError::Io(std::io::Error::other(e.to_string())))?;

    let (method, path, body) = command_to_http(cmd)?;
    let url = format!("{}{}", conn.url.trim_end_matches('/'), path);
    let mut req = client.request(method, &url).bearer_auth(&conn.token);
    if let Some(b) = body {
        req = req.header("content-type", "application/json").body(b);
    }

    let resp = req.send().map_err(|e| CliError::DaemonNotReachable {
        reason: format!("HTTP request failed: {e}"),
    })?;

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(CliError::Unauthorized);
    }
    let status = resp.status();
    if status == reqwest::StatusCode::NO_CONTENT {
        // Used by DELETE /api/devices/{id} on an older daemon (no body, so holders_skipped = 0); synthesize a response so the handler can format it.
        if let Command::Device {
            action: DeviceAction::Revoke { device_id },
        } = cmd
        {
            return Ok(CliResponse::DeviceRevoked {
                device_id_hex: device_id.clone(),
                holders_skipped: 0,
            });
        }
        return Err(CliError::Decode("unexpected 204 from daemon".into()));
    }
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        return Err(CliError::DaemonError(format!("HTTP {status}: {body}")));
    }

    // Endpoint shapes: the web API returns raw typed bodies (StatusData, Vec<FileEntry>, etc.)
    // rather than a tagged CliResponse. Decode based on the command.
    response_from_http(cmd, resp)
}

fn command_to_http(cmd: &Command) -> Result<(reqwest::Method, String, Option<String>), CliError> {
    use reqwest::Method;
    match cmd {
        Command::Daemon { .. } | Command::Init { .. } | Command::Dr { .. } => {
            unreachable!("local-only command routed to HTTP dispatch")
        }
        Command::Open
        | Command::Token { .. }
        | Command::BuildInfo
        | Command::Phrase { .. }
        | Command::Setup { .. } => {
            unreachable!("local-only command routed to HTTP dispatch")
        }
        Command::Restore { .. } => unreachable!("restore is handled by restore::run_restore"),
        Command::Status { .. } => Ok((Method::GET, "/api/status".into(), None)),
        Command::Device { action } => match action {
            DeviceAction::List => Ok((Method::GET, "/api/devices".into(), None)),
            DeviceAction::Add { label } => {
                let body = serde_json::json!({ "label": label });
                Ok((Method::POST, "/api/devices".into(), Some(body.to_string())))
            }
            DeviceAction::Revoke { device_id } => {
                validate_device_id_hex(device_id)?;
                Ok((Method::DELETE, format!("/api/devices/{}", device_id), None))
            }
        },
        Command::Files { path_prefix } => {
            let q = path_prefix
                .as_ref()
                .map(|p| format!("?prefix={}", urlencoding::encode(p)))
                .unwrap_or_default();
            Ok((Method::GET, format!("/api/files{q}"), None))
        }
        Command::Versions { path } => Ok((
            Method::GET,
            format!("/api/versions?path={}", urlencoding::encode(path)),
            None,
        )),
        Command::Connect { addr } => {
            let body = serde_json::json!({ "addr": addr });
            Ok((Method::POST, "/api/connect".into(), Some(body.to_string())))
        }
    }
}

/// Decode the HTTP body into the `CliResponse` variant matching `cmd`.
/// Endpoints return typed JSON (StatusData, Vec<FileEntry>, DeviceEntry, ...) —
/// not a tagged CliResponse — so we rehydrate here based on the command.
fn response_from_http(
    cmd: &Command,
    resp: reqwest::blocking::Response,
) -> Result<CliResponse, CliError> {
    use crate::cli::types::{DeviceEntry, FileEntry, StatusData, VersionEntry};

    match cmd {
        Command::Status { .. } => {
            let data: StatusData = resp.json().map_err(|e| CliError::Decode(e.to_string()))?;
            Ok(CliResponse::Status(Box::new(data)))
        }
        Command::Files { .. } => {
            let data: Vec<FileEntry> = resp.json().map_err(|e| CliError::Decode(e.to_string()))?;
            Ok(CliResponse::Files(data))
        }
        Command::Versions { .. } => {
            let data: Vec<VersionEntry> =
                resp.json().map_err(|e| CliError::Decode(e.to_string()))?;
            Ok(CliResponse::Versions(data))
        }
        Command::Device { action } => match action {
            DeviceAction::List => {
                let data: Vec<DeviceEntry> =
                    resp.json().map_err(|e| CliError::Decode(e.to_string()))?;
                Ok(CliResponse::DeviceList(data))
            }
            DeviceAction::Add { .. } => {
                let data: DeviceEntry = resp.json().map_err(|e| CliError::Decode(e.to_string()))?;
                Ok(CliResponse::DeviceAdded(data))
            }
            DeviceAction::Revoke { .. } => {
                // Old-daemon 204 path is handled in send_command_http.
                let data: serde_json::Value = resp.json().unwrap_or(serde_json::Value::Null);
                let device_id_hex = data
                    .get("device_id_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let holders_skipped = data
                    .get("holders_skipped")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                Ok(CliResponse::DeviceRevoked {
                    device_id_hex,
                    holders_skipped,
                })
            }
        },
        Command::Connect { .. } => {
            let data: serde_json::Value =
                resp.json().map_err(|e| CliError::Decode(e.to_string()))?;
            let peer_id = data
                .get("peer_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            Ok(CliResponse::Connected { peer_id })
        }
        _ => unreachable!("local-only command in response_from_http"),
    }
}

/// Validate that a device_id string is exactly 32 lowercase hex characters.
fn validate_device_id_hex(id: &str) -> Result<(), CliError> {
    if id.len() != 32 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CliError::InvalidArgument(
            "device ID must be 32 hex characters".into(),
        ));
    }
    Ok(())
}

/// Print the formatted response to stdout (or stderr for errors).
fn handle_response(response: CliResponse, json_output: bool) {
    match response {
        CliResponse::Status(data) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&data).unwrap());
            } else {
                output::format_status(&data);
            }
        }
        CliResponse::DeviceList(devices) => output::format_device_list(&devices),
        CliResponse::DeviceAdded(device) => output::format_device_added(&device),
        CliResponse::DeviceRevoked {
            device_id_hex,
            holders_skipped,
        } => output::format_device_revoked(&device_id_hex, holders_skipped),
        CliResponse::Files(files) => output::format_files(&files),
        CliResponse::Versions(versions) => {
            // We don't have the path here, use empty string as placeholder.
            // In practice, the caller knows the path from the command args.
            output::format_versions("", &versions)
        }
        CliResponse::Connected { peer_id } => output::format_connected(&peer_id),
        CliResponse::RestoreJob(_)
        | CliResponse::RestoreJobs(_)
        | CliResponse::RestoreRejected(_) => {
            unreachable!("restore responses are handled by restore::run_restore")
        }
        #[cfg(feature = "e2e-tools")]
        CliResponse::E2eProbe { .. } => {
            unreachable!("e2e probe responses are read by net-probe, not this CLI")
        }
        CliResponse::Error(msg) => output::format_error(&msg),
    }
}
