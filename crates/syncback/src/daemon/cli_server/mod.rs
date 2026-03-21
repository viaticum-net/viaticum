use std::io::{Read, Write};

use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

use crate::cli::types::{
    CliRequest, CliResponse, DeviceEntry, RestoreData, StatusData,
};

#[cfg(test)]
mod tests;

// ============================================================
// Public API
// ============================================================

/// Configuration for the CLI server task.
pub struct CliServerConfig {
    /// Path to the Unix socket to bind.
    pub socket_path: String,
}

/// Handle returned by `start`. Caller awaits it to detect server failure.
pub type CliServerHandle = tokio::task::JoinHandle<()>;

/// Errors from CLI server operations.
#[derive(Debug, thiserror::Error)]
pub enum CliServerError {
    #[error("failed to bind socket at {path}: {source}")]
    Bind { path: String, source: std::io::Error },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encode error: {0}")]
    Encode(String),

    #[error("decode error: {0}")]
    Decode(String),
}

/// Start the CLI server task.
///
/// Binds the Unix socket and enters the accept loop. Returns the JoinHandle
/// immediately; the task runs until `cancel` is triggered.
///
/// If binding fails (e.g., socket already in use), the function returns Err
/// immediately (before spawning).
///
/// The task removes the socket file on shutdown (best-effort).
pub async fn start(
    config: CliServerConfig,
    cancel: CancellationToken,
) -> Result<CliServerHandle, CliServerError> {
    // Remove stale socket file if present.
    let _ = std::fs::remove_file(&config.socket_path);

    let listener = UnixListener::bind(&config.socket_path).map_err(|e| CliServerError::Bind {
        path: config.socket_path.clone(),
        source: e,
    })?;

    let socket_path = config.socket_path.clone();
    let handle = tokio::spawn(async move {
        run_accept_loop(listener, cancel).await;
        // Best-effort cleanup.
        let _ = std::fs::remove_file(&socket_path);
    });

    Ok(handle)
}

// ============================================================
// Accept loop
// ============================================================

async fn run_accept_loop(listener: UnixListener, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("cli_server: shutting down");
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        tokio::spawn(async move {
                            handle_connection(stream).await;
                        });
                    }
                    Err(e) => {
                        tracing::error!("cli_server: accept error: {e}");
                    }
                }
            }
        }
    }
}

// ============================================================
// Per-connection handler
// ============================================================

async fn handle_connection(stream: tokio::net::UnixStream) {
    // Convert to std for blocking I/O (one-shot per connection).
    let std_stream = match stream.into_std() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("cli_server: stream conversion error: {e}");
            return;
        }
    };

    let request = match read_framed(&std_stream) {
        Ok(req) => req,
        Err(e) => {
            tracing::error!("cli_server: read error: {e}");
            return;
        }
    };

    let response = dispatch(request).await;

    if let Err(e) = write_framed(&std_stream, &response) {
        tracing::error!("cli_server: write error: {e}");
    }
}

// ============================================================
// Dispatch — Phase 4 stub
// ============================================================

/// Dispatch a CliRequest and produce a CliResponse.
/// Phase 4: stub returns mock data.
/// Phase 5: wire to real daemon state.
pub(crate) async fn dispatch(request: CliRequest) -> CliResponse {
    match request {
        CliRequest::Status => CliResponse::Status(StatusData {
            node_identity: "0000000000000000".into(),
            peer_count: 0,
            avg_trust: 0.0,
            holding_bytes: 0,
            backed_up_files: 0,
            backed_up_bytes: 0,
            blocks_needing_repair: 0,
            peers: vec![],
            effective_quota_bytes: 0,
            used_bytes: 0,
        }),
        CliRequest::Restore { path, .. } => CliResponse::Restore(RestoreData {
            path,
            version_used: 1,
            content_hash_hex: "00".repeat(32),
            status: "queued".into(),
        }),
        CliRequest::DeviceList => CliResponse::DeviceList(vec![]),
        CliRequest::DeviceAdd { label } => CliResponse::DeviceAdded(DeviceEntry {
            device_id_hex: "00".repeat(16),
            label,
            is_current: false,
            added_at: "2026-01-01".into(),
            revoked: false,
        }),
        CliRequest::DeviceRevoke { device_id_hex } => {
            CliResponse::DeviceRevoked { device_id_hex }
        }
        CliRequest::Files { .. } => CliResponse::Files(vec![]),
        CliRequest::Versions { .. } => CliResponse::Versions(vec![]),
    }
}

// ============================================================
// Framing helpers
// ============================================================

fn write_framed<W: Write, T: serde::Serialize>(mut writer: W, value: &T) -> Result<(), CliServerError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)
        .map_err(|e| CliServerError::Encode(e.to_string()))?;
    let len = buf.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&buf)?;
    Ok(())
}

fn read_framed<R: Read, T: serde::de::DeserializeOwned>(mut reader: R) -> Result<T, CliServerError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    ciborium::de::from_reader(payload.as_slice())
        .map_err(|e| CliServerError::Decode(e.to_string()))
}
