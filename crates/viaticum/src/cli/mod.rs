pub mod output;
pub mod types;

#[cfg(test)]
mod tests;

use clap::{Parser, Subcommand};

pub use types::CliError;
use types::CliResponse;

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
#[command(name = "viaticum", version)]
pub struct Cli {
    /// Path to config file. Default: ~/.viaticum/config.toml
    #[arg(long, global = true)]
    pub config: Option<String>,

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
        /// BIP39 mnemonic phrase (24 words). If omitted, generates a new one.
        #[arg(long)]
        mnemonic: Option<String>,
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

    /// Restore a file or directory from backup
    Restore {
        /// Path to restore (as stored in the backup catalog)
        path: String,

        /// Version number to restore (1-based, 1 = oldest). Default: latest.
        #[arg(long)]
        version: Option<u32>,

        /// Restore the version closest to this date (YYYY-MM-DD). Default: latest.
        #[arg(long)]
        date: Option<String>,

        /// Restore to this destination path instead of the original location.
        #[arg(long)]
        dest: Option<String>,
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
        /// BIP39 mnemonic phrase (24 words)
        #[arg(long)]
        mnemonic: String,
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

    /// Open the web UI in the default browser
    Open,

    /// Print the auth token (or a ready-to-use /auth/start URL with --url)
    Token {
        /// Print the full /auth/start URL instead of just the token.
        #[arg(long)]
        url: bool,
    },
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

/// `viaticum open` — launch the default browser on /auth/start.
pub fn cmd_open(conn: &Connection) -> Result<(), CliError> {
    let url = build_auth_start_url(conn);
    launch_browser(&url).map_err(|e| CliError::Io(std::io::Error::other(e.to_string())))
}

fn launch_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).status()?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).status()?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        println!("Open this URL in your browser:\n  {url}");
    }
    Ok(())
}

// ============================================================
// Dispatch (HTTP)
// ============================================================

/// Send the command over HTTP to the daemon, receive `CliResponse`,
/// format and print to stdout.
pub fn run_command(cmd: &Command, connection: &Connection) -> Result<(), CliError> {
    let response = send_command_http(connection, cmd)?;
    let json_output = matches!(cmd, Command::Status { json: true });
    handle_response(response, json_output);
    Ok(())
}

fn send_command_http(conn: &Connection, cmd: &Command) -> Result<CliResponse, CliError> {
    let client = reqwest::blocking::Client::builder()
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
        // Used by DELETE /api/devices/{id}; synthesize a response so the handler can format it.
        if let Command::Device {
            action: DeviceAction::Revoke { device_id },
        } = cmd
        {
            return Ok(CliResponse::DeviceRevoked {
                device_id_hex: device_id.clone(),
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
        Command::Open | Command::Token { .. } => {
            unreachable!("Open/Token handled locally in main.rs before run_command")
        }
        Command::Status { .. } => Ok((Method::GET, "/api/status".into(), None)),
        Command::Restore {
            path,
            version,
            date,
            dest,
        } => {
            if version.is_some() && date.is_some() {
                return Err(CliError::InvalidArgument(
                    "cannot specify both --version and --date".into(),
                ));
            }
            if let Some(v) = *version
                && v == 0
            {
                return Err(CliError::InvalidArgument("--version must be >= 1".into()));
            }
            let body = serde_json::json!({
                "path": path,
                "version": version,
                "date": date,
                "dest": dest,
            });
            Ok((Method::POST, "/api/restore".into(), Some(body.to_string())))
        }
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
    use crate::cli::types::{DeviceEntry, FileEntry, RestoreData, StatusData, VersionEntry};

    match cmd {
        Command::Status { .. } => {
            let data: StatusData = resp.json().map_err(|e| CliError::Decode(e.to_string()))?;
            Ok(CliResponse::Status(data))
        }
        Command::Restore { .. } => {
            let data: RestoreData = resp.json().map_err(|e| CliError::Decode(e.to_string()))?;
            Ok(CliResponse::Restore(data))
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
                // 204 path already handled in send_command_http
                let data: serde_json::Value = resp.json().unwrap_or(serde_json::Value::Null);
                let device_id_hex = data
                    .get("device_id_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                Ok(CliResponse::DeviceRevoked { device_id_hex })
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
        CliResponse::Restore(data) => output::format_restore(&data),
        CliResponse::DeviceList(devices) => output::format_device_list(&devices),
        CliResponse::DeviceAdded(device) => output::format_device_added(&device),
        CliResponse::DeviceRevoked { device_id_hex } => {
            output::format_device_revoked(&device_id_hex)
        }
        CliResponse::Files(files) => output::format_files(&files),
        CliResponse::Versions(versions) => {
            // We don't have the path here, use empty string as placeholder.
            // In practice, the caller knows the path from the command args.
            output::format_versions("", &versions)
        }
        CliResponse::Connected { peer_id } => output::format_connected(&peer_id),
        CliResponse::RestoreBlocked(blocker) => output::format_restore_blocked(&blocker),
        CliResponse::Error(msg) => output::format_error(&msg),
    }
}
