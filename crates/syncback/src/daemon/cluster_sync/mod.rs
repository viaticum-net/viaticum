// ClusterSyncManager: event log exchange between devices of the same cluster.
//
// Responsibilities:
//   - Build ClusterSyncRequestMsg to send to a peer device.
//   - Process ClusterSyncResponseMsg received from a peer device.
//   - Handle incoming ClusterSyncRequestMsg from a peer device.
//   - Build RevocationBroadcast payload for posting to relay board.
//
// Design: synchronous (no async). Callers manage connections.
// NetworkHandle is NOT a field — sync methods take Connection as parameter.
// This keeps tests simple (no iroh needed).
//
// Cursor persistence: sync_cursors stored in StoredClusterState via
// ClusterState::update_sync_cursor(). No separate DB key needed.

use std::sync::{Arc, Mutex};

use syncback_core::cluster::ClusterState;
use syncback_core::db::Db;
use syncback_core::messages::{ClusterSyncRequestMsg, ClusterSyncResponseMsg, RevocationBroadcast};
use syncback_core::types::{DeviceId, IdentityPub, Timestamp};

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
        let responder_last_seq = response.responder_last_seq;
        let mut state = self
            .cluster_state
            .lock()
            .expect("cluster_state lock poisoned");

        let applied = state.apply_events(&response.events)?;
        state.update_sync_cursor(*peer_identity, responder_last_seq)?;

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
}
