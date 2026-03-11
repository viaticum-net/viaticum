use std::path::PathBuf;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::daemon::ProcessorMsg;

pub async fn run(
    cancel: CancellationToken,
    _processor_tx: mpsc::Sender<ProcessorMsg>,
    _socket_path: PathBuf,
) {
    tracing::debug!("cli_server: started (stub)");
    // TODO: bind Unix socket, accept connections, dispatch CliCmd
    cancel.cancelled().await;
    tracing::debug!("cli_server: stopped");
}
