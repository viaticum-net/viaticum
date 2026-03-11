use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::daemon::DirtyEvent;

pub async fn run(cancel: CancellationToken, _dirty_tx: mpsc::Sender<DirtyEvent>) {
    tracing::debug!("watcher: started (stub, Phase 3)");
    cancel.cancelled().await;
    tracing::debug!("watcher: stopped");
}
