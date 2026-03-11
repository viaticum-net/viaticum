use syncback_core::db::Db;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::daemon::{DirtyEvent, NetCommand, NetEvent, ProcessorMsg};

pub async fn run(
    _db: Db,
    cancel: CancellationToken,
    mut processor_rx: mpsc::Receiver<ProcessorMsg>,
    mut dirty_rx: mpsc::Receiver<DirtyEvent>,
    mut net_event_rx: mpsc::Receiver<NetEvent>,
    _net_cmd_tx: mpsc::Sender<NetCommand>,
) {
    tracing::debug!("processor: started (stub)");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("processor: cancelled");
                break;
            }
            msg = processor_rx.recv() => {
                if msg.is_none() { break; }
                // TODO: implement in processor.md
            }
            event = dirty_rx.recv() => {
                if event.is_none() { break; }
                // TODO: implement in processor.md
            }
            event = net_event_rx.recv() => {
                if event.is_none() { break; }
                // TODO: implement in processor.md
            }
        }
    }
    tracing::debug!("processor: stopped");
}
