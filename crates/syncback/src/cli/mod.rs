pub mod output;
pub mod types;

#[cfg(test)]
mod tests;

use clap::{Parser, Subcommand};
use std::io::{Read, Write};

pub use types::CliError;
use types::{CliRequest, CliResponse};

/// Default Unix socket path used by daemon and CLI.
pub const DEFAULT_SOCKET_PATH: &str = "~/.syncback/syncback.sock";

/// Expand `~` in socket path to the home directory.
/// Returns the raw path unchanged if `HOME` is not set.
pub fn expand_socket_path(path: &str) -> String {
    expand_tilde(path)
}

/// Expand `~` in a data directory path to the home directory.
/// Returns a `PathBuf` — caller decides whether to resolve symlinks.
pub fn expand_data_dir(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(expand_tilde(path))
}

/// Expand a leading `~/` to `$HOME/`. Returns `path` unchanged if HOME is unset.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    path.to_string()
}

// ============================================================
// Clap CLI structures
// ============================================================

/// syncback — decentralized P2P cold backup
#[derive(Debug, Parser)]
#[command(name = "syncback", version)]
pub struct Cli {
    /// Path to config file. Default: ~/.syncback/config.toml
    #[arg(long, global = true)]
    pub config: Option<String>,

    /// Data directory (determines socket path). Default: ~/.syncback
    #[arg(long, global = true, default_value = "~/.syncback")]
    pub data_dir: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the syncback daemon
    Daemon {
        /// Time scale factor (1 = real time, 604800 = 1 sec equals 1 week).
        #[arg(long, default_value = "1")]
        time_scale: u64,
        /// Directories to watch for backup (may be specified multiple times).
        #[arg(long)]
        watch_dir: Vec<std::path::PathBuf>,
    },

    /// Initialize a new SyncBack identity
    Init {
        /// BIP39 mnemonic phrase (24 words). If omitted, generates a new one.
        #[arg(long)]
        mnemonic: Option<String>,
    },

    /// Show overall system status
    Status,

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

    /// Connect to a peer by iroh node address
    Connect {
        /// Iroh node address (from `syncback status` on the remote node)
        #[arg()]
        addr: String,
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
// Dispatch
// ============================================================

/// Parse `CliRequest` from `Command` args, send to daemon, receive `CliResponse`,
/// format and print to stdout.
///
/// `socket_path` is the expanded (tilde-resolved) path to the Unix socket.
pub fn run_command(cmd: &Command, socket_path: &str) -> Result<(), CliError> {
    let request = build_request(cmd)?;
    let response = send_request(socket_path, &request)?;
    handle_response(response);
    Ok(())
}

/// Build a `CliRequest` from parsed CLI command, applying validation.
fn build_request(cmd: &Command) -> Result<CliRequest, CliError> {
    match cmd {
        Command::Daemon { .. } => unreachable!("Daemon command handled before run_command"),
        Command::Init { .. } => unreachable!("Init command handled before run_command"),
        Command::Status => Ok(CliRequest::Status),
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
            if let Some(v) = *version {
                if v == 0 {
                    return Err(CliError::InvalidArgument(
                        "--version must be >= 1".into(),
                    ));
                }
            }
            Ok(CliRequest::Restore {
                path: path.clone(),
                version: *version,
                date: date.clone(),
                dest: dest.clone(),
            })
        }
        Command::Device { action } => match action {
            DeviceAction::List => Ok(CliRequest::DeviceList),
            DeviceAction::Add { label } => Ok(CliRequest::DeviceAdd {
                label: label.clone(),
            }),
            DeviceAction::Revoke { device_id } => {
                validate_device_id_hex(device_id)?;
                Ok(CliRequest::DeviceRevoke {
                    device_id_hex: device_id.clone(),
                })
            }
        },
        Command::Files { path_prefix } => Ok(CliRequest::Files {
            path_prefix: path_prefix.clone(),
        }),
        Command::Versions { path } => Ok(CliRequest::Versions { path: path.clone() }),
        Command::Connect { addr } => Ok(CliRequest::Connect { addr: addr.clone() }),
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
fn handle_response(response: CliResponse) {
    match response {
        CliResponse::Status(data) => output::format_status(&data),
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
        CliResponse::Error(msg) => output::format_error(&msg),
    }
}

// ============================================================
// Socket I/O (blocking, std — CLI runs sync)
// ============================================================

/// Connect to daemon socket, send request, receive response.
/// Wire format: u32 BE length prefix || CBOR payload.
fn send_request(socket_path: &str, request: &CliRequest) -> Result<CliResponse, CliError> {
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound
            || e.kind() == std::io::ErrorKind::ConnectionRefused
        {
            CliError::DaemonNotRunning {
                path: socket_path.to_string(),
            }
        } else {
            CliError::Io(e)
        }
    })?;

    write_framed(&stream, request)?;
    let response: CliResponse = read_framed(&stream)?;
    Ok(response)
}

/// Write a CBOR-encoded value with u32 BE length prefix.
fn write_framed<W: Write, T: serde::Serialize>(mut writer: W, value: &T) -> Result<(), CliError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)
        .map_err(|e| CliError::Encode(e.to_string()))?;
    let len = buf.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&buf)?;
    Ok(())
}

/// Read a CBOR-encoded value preceded by a u32 BE length prefix.
fn read_framed<R: Read, T: serde::de::DeserializeOwned>(mut reader: R) -> Result<T, CliError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    ciborium::de::from_reader(payload.as_slice()).map_err(|e| CliError::Decode(e.to_string()))
}
