use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::daemon::{NetCommand, NetEvent, ProcessorMsg};

pub async fn run(
    cancel: CancellationToken,
    mut net_cmd_rx: mpsc::Receiver<NetCommand>,
    _net_event_tx: mpsc::Sender<NetEvent>,
    _processor_tx: mpsc::Sender<ProcessorMsg>,
) {
    tracing::debug!("network: started (stub)");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("network: cancelled");
                break;
            }
            cmd = net_cmd_rx.recv() => {
                if cmd.is_none() { break; }
                // TODO: implement in network.md
            }
        }
    }
    tracing::debug!("network: stopped");
}
