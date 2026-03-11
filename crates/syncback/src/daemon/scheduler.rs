use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::daemon::ProcessorMsg;

pub async fn run(cancel: CancellationToken, _processor_tx: mpsc::Sender<ProcessorMsg>) {
    tracing::debug!("scheduler: started (stub)");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("scheduler: cancelled");
                break;
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(300)) => {
                tracing::debug!("scheduler: tick (stub)");
            }
        }
    }
    tracing::debug!("scheduler: stopped");
}
