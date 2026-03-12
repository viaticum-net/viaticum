use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::daemon::{CliCmd, ProcessorMsg, StatusReply};

#[cfg(test)]
mod tests;

// ============================================================
// Wire types (shared between server and client)
// ============================================================

/// Request sent by the CLI client to the daemon over the Unix socket.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum CliRequest {
    /// Query daemon status.
    Status,
    /// Trigger an immediate backup (equivalent to WeeklySync).
    BackupNow,
    /// Request restore of a file by path.
    RestoreFile {
        /// Path of the file to restore (as originally backed up).
        path: String,
        /// Destination path for restored file.
        dest: String,
    },
    /// List known peers with trust scores.
    Peers,
    /// Gracefully stop the daemon.
    Shutdown,
}

/// Response sent by the daemon back to the CLI client.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CliResponse {
    /// Generic success with a human-readable message.
    Ok { message: String },
    /// Status reply (for Status command).
    StatusOk(StatusPayload),
    /// Peer list reply (for Peers command).
    PeersOk(PeersPayload),
    /// Request accepted, will complete asynchronously.
    Accepted { message: String },
    /// Command failed.
    Error { message: String },
}

/// Mirrors `daemon::StatusReply` — used as the JSON payload for `StatusOk`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct StatusPayload {
    pub uptime_secs: u64,
    pub peer_count: usize,
    pub shards_held: usize,
    pub shards_placed: usize,
    pub budget_gb: f64,
    pub dirty_files: usize,
}

impl From<StatusReply> for StatusPayload {
    fn from(r: StatusReply) -> Self {
        StatusPayload {
            uptime_secs: r.uptime_secs,
            peer_count: r.peer_count,
            shards_held: r.shards_held,
            shards_placed: r.shards_placed,
            budget_gb: r.budget_gb,
            dirty_files: r.dirty_files,
        }
    }
}

/// Payload for the `PeersOk` response.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PeersPayload {
    pub peers: Vec<PeerInfo>,
}

/// Per-peer info returned by `syncback peers`.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PeerInfo {
    /// First 8 bytes of identity_pub as lowercase hex (display identifier).
    pub identity: String,
    pub trust_p: f64,
    pub trust_i: f64,
    pub trust_s: f64,
    /// Combined trust score: (kp*P + ki*I) * clamp(S, 0.1, 1.0)
    pub trust_score: f64,
    pub weeks_in_network: u32,
    pub shards_held_for_us: usize,
    pub last_seen_secs_ago: u64,
}

// ============================================================
// Server task
// ============================================================

/// Run the CLI server task until `cancel` is signalled.
/// Binds `socket_path`, accepts JSON CLI connections, dispatches to Processor.
pub async fn run(
    cancel: CancellationToken,
    processor_tx: mpsc::Sender<ProcessorMsg>,
    socket_path: PathBuf,
) {
    let listener = UnixListener::bind(&socket_path)
        .expect("cli_server: failed to bind socket");
    tracing::info!(socket = ?socket_path, "cli_server: listening");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("cli_server: cancelled");
                break;
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, _addr)) => {
                        let tx = processor_tx.clone();
                        let c = cancel.clone();
                        tokio::spawn(handle_connection(stream, tx, c));
                    }
                    Err(e) => {
                        tracing::debug!(err = %e, "cli_server: accept error");
                    }
                }
            }
        }
    }
}

/// Handle one accepted client connection.
/// Protocol: one JSON line in, one JSON line out, then close.
async fn handle_connection(
    stream: UnixStream,
    processor_tx: mpsc::Sender<ProcessorMsg>,
    cancel: CancellationToken,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    tokio::select! {
        _ = cancel.cancelled() => return,
        result = reader.read_line(&mut line) => {
            if result.unwrap_or(0) == 0 {
                return;
            }
        }
    }

    tracing::debug!(cmd = line.trim(), "cli_server: request from client");

    let response = match serde_json::from_str::<CliRequest>(line.trim()) {
        Ok(req) => dispatch(req, &processor_tx).await,
        Err(e) => CliResponse::Error {
            message: format!("bad request: {e}"),
        },
    };

    tracing::debug!("cli_server: response sent to client");

    let mut json = serde_json::to_string(&response).expect("response serialize");
    json.push('\n');
    let _ = write_half.write_all(json.as_bytes()).await;
}

/// Parse a `CliRequest` and dispatch to Processor via channel.
/// Returns a `CliResponse` to send back to the client.
async fn dispatch(
    request: CliRequest,
    processor_tx: &mpsc::Sender<ProcessorMsg>,
) -> CliResponse {
    match request {
        CliRequest::Status => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let cmd = ProcessorMsg::Cli(CliCmd::Status { reply: reply_tx });
            if processor_tx.send(cmd).await.is_err() {
                return CliResponse::Error {
                    message: "daemon not responding".into(),
                };
            }
            match reply_rx.await {
                Ok(reply) => CliResponse::StatusOk(reply.into()),
                Err(_) => CliResponse::Error {
                    message: "processor dropped reply".into(),
                },
            }
        }

        CliRequest::BackupNow => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let cmd = ProcessorMsg::Cli(CliCmd::BackupNow { reply: reply_tx });
            if processor_tx.send(cmd).await.is_err() {
                return CliResponse::Error {
                    message: "daemon not responding".into(),
                };
            }
            match reply_rx.await {
                Ok(Ok(())) => CliResponse::Ok {
                    message: "backup triggered".into(),
                },
                Ok(Err(e)) => CliResponse::Error { message: e },
                Err(_) => CliResponse::Error {
                    message: "processor dropped reply".into(),
                },
            }
        }

        CliRequest::RestoreFile { path, dest } => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let cmd = ProcessorMsg::Cli(CliCmd::RestoreFile {
                path: std::path::PathBuf::from(&path),
                dest: std::path::PathBuf::from(&dest),
                reply: reply_tx,
            });
            if processor_tx.send(cmd).await.is_err() {
                return CliResponse::Error {
                    message: "daemon not responding".into(),
                };
            }
            match reply_rx.await {
                Ok(Ok(())) => CliResponse::Ok {
                    message: format!("restore started: {path} -> {dest}"),
                },
                Ok(Err(e)) => CliResponse::Error { message: e },
                Err(_) => CliResponse::Error {
                    message: "processor dropped reply".into(),
                },
            }
        }

        CliRequest::Peers => {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            let cmd = ProcessorMsg::Cli(CliCmd::Peers { reply: reply_tx });
            if processor_tx.send(cmd).await.is_err() {
                return CliResponse::Error {
                    message: "daemon not responding".into(),
                };
            }
            match reply_rx.await {
                Ok(peers) => CliResponse::PeersOk(PeersPayload { peers }),
                Err(_) => CliResponse::Error {
                    message: "processor dropped reply".into(),
                },
            }
        }

        CliRequest::Shutdown => {
            let _ = processor_tx
                .send(ProcessorMsg::Cli(CliCmd::Shutdown))
                .await;
            CliResponse::Ok {
                message: "shutdown requested".into(),
            }
        }
    }
}
