// ClusterSyncManager: event log exchange between devices of the same cluster.
//
// Responsibilities:
//   - Build ClusterSyncRequestMsg to send to a peer device.
//   - Process ClusterSyncResponseMsg received from a peer device.
//   - Handle incoming ClusterSyncRequestMsg from a peer device.
//   - Build RevocationBroadcast payload for posting to relay board.
//   - run_periodic_sync: async task that connects to each cluster peer and sends
//     ClusterSyncRequest, registering the connection with the Processor for response handling.
//
// Design: synchronous (no async). Callers manage connections.
// NetworkHandle is NOT a field — sync methods take Connection as parameter.
// This keeps tests simple (no iroh needed).
//
// Cursor persistence: sync_cursors stored in StoredClusterState via
// ClusterState::update_sync_cursor(). No separate DB key needed.
//
// Cursor key: IdentityPub(device_pub_key) — per-device identity. Each device
// in the cluster has a unique device_pub_key, so cursors are tracked per device.

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use syncback_core::cluster::ClusterState;
use syncback_core::db::Db;
use syncback_core::messages::{ClusterSyncRequestMsg, ClusterSyncResponseMsg, Message, RevocationBroadcast};
use syncback_core::types::{DeviceId, IdentityPub, Timestamp};

use crate::daemon::network::NetworkHandle;

#[cfg(test)]
mod tests;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors from ClusterSyncManager operations.
#[derive(Debug, thiserror::Error)]
pub enum ClusterSyncError {
    #[error("cluster state error: {0}")]
    ClusterState(#[from] syncback_core::cluster::ClusterStateError),

    #[error("db error: {0}")]
    Db(#[from] syncback_core::db::DbError),

    #[error("message error: {0}")]
    Message(#[from] syncback_core::messages::MessageError),

    #[error("device not in cluster: {0:?}")]
    NotClusterDevice(DeviceId),
}

// ─── Config ───────────────────────────────────────────────────────────────────

/// Configuration for ClusterSyncManager.
#[derive(Clone)]
pub struct ClusterSyncConfig {
    /// This device's DeviceId.
    pub our_device_id: DeviceId,
    /// Max events per sync batch.
    pub batch_size: usize,
}

impl Default for ClusterSyncConfig {
    fn default() -> Self {
        ClusterSyncConfig {
            our_device_id: DeviceId([0u8; 16]),
            batch_size: 1000,
        }
    }
}

// ─── ClusterSyncManager ───────────────────────────────────────────────────────

/// Manages event log exchange between devices of the same cluster.
///
/// This is synchronous — callers run it in a blocking context or spawn a
/// dedicated thread for the sync calls. The `cluster_state` mutex is
/// std::sync::Mutex so this type is Send + Sync without requiring tokio.
pub struct ClusterSyncManager {
    db: Db,
    config: ClusterSyncConfig,
    cluster_state: Arc<Mutex<ClusterState>>,
}

impl ClusterSyncManager {
    /// Create a new ClusterSyncManager.
    pub fn new(
        db: Db,
        config: ClusterSyncConfig,
        cluster_state: Arc<Mutex<ClusterState>>,
    ) -> Self {
        ClusterSyncManager {
            db,
            config,
            cluster_state,
        }
    }

    // =========================================================
    // Outbound: build a request to send to a peer
    // =========================================================

    /// Build a ClusterSyncRequestMsg to send to a peer device.
    ///
    /// Uses sync_cursors from ClusterState to determine last_known_seq.
    /// Returns 0 if no cursor exists (peer is new / never synced).
    pub fn build_sync_request(&self, peer_identity: &IdentityPub) -> ClusterSyncRequestMsg {
        let last_known_seq = self
            .cluster_state
            .lock()
            .expect("cluster_state lock poisoned")
            .sync_cursor(peer_identity);

        ClusterSyncRequestMsg {
            v: 1,
            from_device_id: self.config.our_device_id,
            last_known_seq,
            timestamp: Timestamp::now(),
        }
    }

    // =========================================================
    // Inbound response: apply events from peer
    // =========================================================

    /// Process a received ClusterSyncResponseMsg from a peer device.
    ///
    /// Applies events to ClusterState, then updates the sync cursor for
    /// this peer to `response.responder_last_seq`.
    ///
    /// Returns the number of events actually applied (idempotent: already-known
    /// events are skipped by apply_events).
    pub fn process_sync_response(
        &self,
        peer_identity: &IdentityPub,
        response: ClusterSyncResponseMsg,
    ) -> Result<usize, ClusterSyncError> {
        let mut state = self
            .cluster_state
            .lock()
            .expect("cluster_state lock poisoned");

        let applied = state.apply_events(&response.events)?;

        // Only advance cursor by the number of events we actually received.
        // A malicious peer could send responder_last_seq = u64::MAX to
        // permanently skip future events. Instead, advance cursor by
        // current_cursor + events_received_count.
        let current_cursor = state.sync_cursor(peer_identity);
        let safe_seq = current_cursor.saturating_add(response.events.len() as u64);
        state.update_sync_cursor(*peer_identity, safe_seq)?;

        Ok(applied)
    }

    // =========================================================
    // Inbound request: serve events to a peer
    // =========================================================

    /// Handle an incoming ClusterSyncRequestMsg from a peer device.
    ///
    /// Validates that `request.from_device_id` belongs to our cluster and
    /// is not revoked. Reads events after `request.last_known_seq` from our
    /// event log. Returns a ClusterSyncResponseMsg with those events.
    ///
    /// Returns Err(NotClusterDevice) if the device is unknown or revoked.
    pub fn handle_sync_request(
        &self,
        request: &ClusterSyncRequestMsg,
    ) -> Result<ClusterSyncResponseMsg, ClusterSyncError> {
        let device_id = request.from_device_id;

        {
            let state = self
                .cluster_state
                .lock()
                .expect("cluster_state lock poisoned");

            let known = state.get_device(&device_id).is_some();
            let revoked = state.is_device_revoked(&device_id);

            if !known || revoked {
                return Err(ClusterSyncError::NotClusterDevice(device_id));
            }
        }

        let events = self
            .db
            .events_after(request.last_known_seq, self.config.batch_size)?;
        let responder_last_seq = self.db.last_event_seq()?;

        Ok(ClusterSyncResponseMsg {
            v: 1,
            events,
            responder_last_seq,
            timestamp: Timestamp::now(),
        })
    }

    // =========================================================
    // Revocation broadcast
    // =========================================================

    /// Build a RevocationBroadcast payload for posting to the relay board.
    ///
    /// The `device_cert` should be the certificate of the device being revoked
    /// so external peers can identify the affected device key.
    pub fn build_revocation_broadcast(
        revocation: &syncback_core::cluster::RevocationCertificate,
        device_cert: &syncback_core::cluster::DeviceCertificate,
    ) -> RevocationBroadcast {
        RevocationBroadcast {
            revocation: revocation.clone(),
            device_cert: device_cert.clone(),
        }
    }

    // =========================================================
    // Cluster master pub
    // =========================================================

    /// Return the cluster master identity (IdentityPub).
    ///
    /// This is the same key used by the Processor when it calls
    /// `process_sync_response` — useful for building consistent cursor keys.
    pub fn master_pub(&self) -> IdentityPub {
        self.cluster_state
            .lock()
            .expect("cluster_state lock poisoned")
            .master_pub()
    }
}

// ─── Periodic sync task ───────────────────────────────────────────────────────

/// Periodically send ClusterSyncRequest to each known cluster peer.
///
/// For each peer in `network.cluster_peers()` (excluding our own device):
///   1. Look up DeviceEntry in cluster_state to get device_pub_key.
///   2. Skip revoked devices.
///   3. Build cursor key as `IdentityPub(device_pub_key)` (per-device cursor).
///   4. Connect directly to peer's EndpointAddr via `network.connect(addr, None)`.
///   5. Send ClusterSyncRequest directly on the connection.
///   6. Hand connection to `incoming_tx` so Processor spawns a read loop
///      to receive and process the ClusterSyncResponse.
///
/// Errors per-peer are logged and skipped. Loop runs until `cancel` fires.
pub async fn run_periodic_sync(
    cluster_sync: Arc<ClusterSyncManager>,
    cluster_state: Arc<Mutex<ClusterState>>,
    network: Arc<NetworkHandle>,
    our_device_id: DeviceId,
    interval_secs: u64,
    cancel: CancellationToken,
    incoming_tx: mpsc::Sender<crate::daemon::network::connection::Connection>,
) -> anyhow::Result<()> {
    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    // Skip the first (immediate) tick to avoid hammering peers on startup.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("cluster_sync: periodic sync cancelled");
                break;
            }
            _ = interval.tick() => {
                let peers = network.cluster_peers().await;
                let mut synced = 0usize;
                let mut skipped = 0usize;

                for (device_id, addr) in peers {
                    if device_id == our_device_id {
                        skipped += 1;
                        continue;
                    }

                    // Look up DeviceEntry for device_pub_key and revocation check.
                    let (device_pub_key, is_revoked) = {
                        let state = cluster_state.lock().expect("cluster_state lock poisoned");
                        let entry = state.get_device(&device_id);
                        match entry {
                            None => {
                                warn!(
                                    device_id = %device_id,
                                    "cluster_sync: device not in cluster state, skipping"
                                );
                                skipped += 1;
                                continue;
                            }
                            Some(e) => (e.device_pub_key, state.is_device_revoked(&device_id)),
                        }
                    };

                    if is_revoked {
                        debug!(
                            device_id = %device_id,
                            "cluster_sync: skipping revoked device"
                        );
                        skipped += 1;
                        continue;
                    }

                    // Per-device cursor key: IdentityPub(device_pub_key).
                    let peer_identity = IdentityPub(device_pub_key);
                    let request = cluster_sync.build_sync_request(&peer_identity);

                    // Connect directly to peer's address (15 s timeout).
                    let conn = match tokio::time::timeout(
                        std::time::Duration::from_secs(15),
                        network.connect(addr, None),
                    )
                    .await
                    {
                        Ok(Ok(c)) => c,
                        Ok(Err(e)) => {
                            warn!(
                                device_id = %device_id,
                                error = %e,
                                "cluster_sync: connect failed"
                            );
                            skipped += 1;
                            continue;
                        }
                        Err(_) => {
                            warn!(
                                device_id = %device_id,
                                "cluster_sync: connect timed out"
                            );
                            skipped += 1;
                            continue;
                        }
                    };

                    // Send ClusterSyncRequest directly on the connection.
                    if let Err(e) = conn
                        .send_message(&Message::ClusterSyncRequest(request))
                        .await
                    {
                        warn!(
                            device_id = %device_id,
                            error = %e,
                            "cluster_sync: failed to send ClusterSyncRequest"
                        );
                        skipped += 1;
                        continue;
                    }

                    // Register connection with Processor so it spawns a read loop
                    // and handles the incoming ClusterSyncResponse.
                    if incoming_tx.send(conn).await.is_err() {
                        warn!("cluster_sync: incoming_tx closed (daemon shutting down?)");
                        // Channel closed means daemon is shutting down — stop the loop.
                        return Ok(());
                    }

                    synced += 1;
                }

                info!(
                    synced,
                    skipped,
                    "cluster_sync: periodic sync tick complete"
                );
            }
        }
    }

    Ok(())
}
