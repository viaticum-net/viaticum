// Cluster handlers: sync request/response, revocation broadcast, system state backup/restore.

use libp2p::request_response::ResponseChannel;
use tracing::{debug, error, info, warn};
use viaticum_core::db::SystemStateBlobRecord;
use viaticum_core::messages::{
    ClusterSyncRequestMsg, ClusterSyncResponseMsg, Message, RevocationBroadcast, SystemStateAckMsg,
    SystemStateBackupMsg, SystemStateRequestMsg, SystemStateResponseMsg,
};
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp};

use super::{Processor, ProcessorError};

impl Processor {
    /// Handle a ClusterSyncRequest via libp2p (AC-6).
    ///
    /// Validates that the claimed from_device_id matches the authenticated cert
    /// stored in peer_cert_map. On mismatch: drops the ResponseChannel (no reply),
    /// which causes libp2p to return an error to the sender.
    pub(crate) async fn handle_cluster_sync_request_libp2p(
        &self,
        from_device: DeviceId,
        from_master: IdentityPub,
        request: ClusterSyncRequestMsg,
        response_channel: ResponseChannel<Message>,
    ) -> Result<(), ProcessorError> {
        // Validate: the device cert stored in peer_cert_map must match from_device_id.
        let cert_ok = {
            let map = self.peer_cert_map.lock().unwrap();
            map.get(&from_device)
                .map(|(_, cert)| cert.device_id == request.from_device_id)
                .unwrap_or(false)
        };
        if !cert_ok {
            warn!(
                device = %from_device,
                claimed_device = ?request.from_device_id,
                "processor: ClusterSyncRequest device_id mismatch, dropping"
            );
            // Drop response_channel — libp2p will return an error to the sender.
            drop(response_channel);
            return Ok(());
        }

        match self.cluster_sync.handle_sync_request(&request) {
            Ok(response) => {
                let _ = self
                    .swarm
                    .respond(response_channel, Message::ClusterSyncResponse(response));
                debug!(peer = %from_master, "processor: ClusterSyncRequest served");
            }
            Err(e) => {
                warn!(peer = %from_master, err = %e, "processor: ClusterSyncRequest rejected");
                drop(response_channel);
            }
        }
        Ok(())
    }

    pub(crate) async fn handle_cluster_sync_response(
        &self,
        from_device: DeviceId,
        response: ClusterSyncResponseMsg,
    ) -> Result<(), ProcessorError> {
        match self
            .cluster_sync
            .process_sync_response(&from_device, response)
        {
            Ok(n) => {
                debug!(
                    device = %from_device,
                    applied = n,
                    "processor: cluster sync applied events"
                );
            }
            Err(e) => {
                warn!(device = %from_device, err = %e, "processor: cluster sync response error");
            }
        }
        Ok(())
    }

    /// Receive a RevocationBroadcast from the relay board.
    ///
    /// Verifies both the DeviceCertificate and RevocationCertificate signatures
    /// against the broadcaster's master identity (msg.from). If valid, adds the
    /// device pub key to `PeerRecord.revoked_device_pub_keys` for that peer.
    ///
    /// Peers we have no record of are ignored — we only track revocations for
    /// known peers. This avoids creating phantom PeerRecords from forged broadcasts.
    pub(crate) async fn handle_revocation_broadcast(
        &self,
        from: IdentityPub,
        broadcast: RevocationBroadcast,
    ) -> Result<(), ProcessorError> {
        // Verify DeviceCertificate: signed by the peer's master key.
        if let Err(e) =
            viaticum_core::cluster::verify_device_certificate(&broadcast.device_cert, &from)
        {
            warn!(
                peer = %from,
                err = %e,
                "processor: RevocationBroadcast — invalid DeviceCertificate, ignoring"
            );
            return Ok(());
        }

        // Verify RevocationCertificate: signed by the peer's master key.
        if let Err(e) = viaticum_core::cluster::verify_revocation(&broadcast.revocation, &from) {
            warn!(
                peer = %from,
                err = %e,
                "processor: RevocationBroadcast — invalid RevocationCertificate, ignoring"
            );
            return Ok(());
        }

        // Cross-check: both certs must refer to the same device_id.
        if broadcast.revocation.device_id != broadcast.device_cert.device_id {
            warn!(
                peer = %from,
                revocation_device = ?broadcast.revocation.device_id,
                cert_device = ?broadcast.device_cert.device_id,
                "processor: RevocationBroadcast — device_id mismatch, ignoring"
            );
            return Ok(());
        }

        // device_id.0 IS the device pub key — use it for the revocation list.
        let revoked_pub = broadcast.device_cert.device_id.0;

        // Only update PeerRecords we already know about. Unknown peers are skipped.
        // PeerRecord is keyed by DeviceId; find any device of this master.
        let devices = self.db.get_devices_for_master(&from).unwrap_or_default();
        if devices.is_empty() {
            debug!(
                peer = %from,
                "processor: RevocationBroadcast from unknown peer, ignoring"
            );
            return Ok(());
        }
        for did in &devices {
            let mut record = match self.db.get_peer(did)? {
                Some(r) => r,
                None => continue,
            };
            if !record.revoked_device_pub_keys.contains(&revoked_pub) {
                record.revoked_device_pub_keys.push(revoked_pub);
                self.db.upsert_peer(&record)?;
            }
        }

        info!(
            peer = %from,
            device_id = ?broadcast.revocation.device_id,
            "processor: RevocationBroadcast applied — device key marked revoked"
        );

        Ok(())
    }

    /// Receive and store a system state blob from a peer.
    /// Only accepts blobs from known peers to prevent storage spam.
    /// Sends a SystemStateAck back regardless of outcome.
    /// Receive and store a system state blob from a peer. Returns the ack.
    ///
    /// In the libp2p path the ack is returned to the caller (dispatch_libp2p)
    /// which sends it via ResponseChannel.
    pub(crate) async fn handle_system_state_backup_inner(
        &self,
        owner_id: IdentityPub,
        backup: SystemStateBackupMsg,
    ) -> SystemStateAckMsg {
        if backup.encrypted_blob.is_empty() {
            warn!(peer = %owner_id, "processor: SystemStateBackup: empty blob, ignoring");
            return SystemStateAckMsg {
                v: 1,
                stored: false,
                timestamp: Timestamp::now(),
            };
        }
        // Only accept from known peers (prevent storage spam from strangers).
        // PeerRecord is keyed by DeviceId; check if any device of this master is known.
        let known = self
            .db
            .get_devices_for_master(&owner_id)
            .map(|ds| !ds.is_empty())
            .unwrap_or(false);
        if !known {
            warn!(peer = %owner_id, "processor: SystemStateBackup: unknown peer, rejecting");
            return SystemStateAckMsg {
                v: 1,
                stored: false,
                timestamp: Timestamp::now(),
            };
        }
        // Enforce blob size cap to prevent disk DoS from authenticated peers.
        if backup.encrypted_blob.len() > viaticum_core::constants::MAX_SYSTEM_STATE_BLOB_BYTES {
            warn!(
                peer = %owner_id,
                blob_len = backup.encrypted_blob.len(),
                max = viaticum_core::constants::MAX_SYSTEM_STATE_BLOB_BYTES,
                "processor: SystemStateBackup: blob exceeds size cap, dropping"
            );
            return SystemStateAckMsg {
                v: 1,
                stored: false,
                timestamp: Timestamp::now(),
            };
        }
        let record = SystemStateBlobRecord {
            owner: owner_id,
            encrypted_blob: backup.encrypted_blob,
            created_at: backup.timestamp,
            stored_at: Timestamp::now(),
        };
        match self.db.store_system_state_blob(&owner_id, &record) {
            Ok(()) => {
                info!(peer = %owner_id, "processor: SystemStateBackup: stored");
                SystemStateAckMsg {
                    v: 1,
                    stored: true,
                    timestamp: Timestamp::now(),
                }
            }
            Err(e) => {
                error!(peer = %owner_id, err = %e, "processor: SystemStateBackup: store failed");
                SystemStateAckMsg {
                    v: 1,
                    stored: false,
                    timestamp: Timestamp::now(),
                }
            }
        }
    }

    /// Log receipt of a system state ack from a holder.
    pub(crate) fn handle_system_state_ack(&self, peer_id: IdentityPub, ack: SystemStateAckMsg) {
        if ack.stored {
            info!(peer = %peer_id, "processor: SystemStateAck: stored");
        } else {
            warn!(peer = %peer_id, "processor: SystemStateAck: rejected");
        }
    }

    /// Respond to a system state request. Returns the response message.
    ///
    /// In the libp2p path the response is sent via ResponseChannel by the caller.
    pub(crate) async fn handle_system_state_request_inner(
        &self,
        requester_id: IdentityPub,
        _req: SystemStateRequestMsg,
    ) -> SystemStateResponseMsg {
        let blob = match self.db.get_system_state_blob(&requester_id) {
            Ok(Some(r)) => r.encrypted_blob,
            Ok(None) => vec![],
            Err(e) => {
                error!(peer = %requester_id, err = %e, "processor: SystemStateRequest: db error");
                vec![]
            }
        };
        let found = !blob.is_empty();
        debug!(peer = %requester_id, found, "processor: SystemStateRequest: responding");
        SystemStateResponseMsg {
            v: 1,
            encrypted_blob: blob,
            timestamp: Timestamp::now(),
        }
    }

    /// Log a system state response.
    /// The disaster recovery flow handles this via a dedicated channel; here we
    /// only log so that the dispatch loop does not drop it silently.
    pub(crate) async fn handle_system_state_response(
        &self,
        peer_id: IdentityPub,
        _resp: SystemStateResponseMsg,
    ) {
        debug!(
            peer = %peer_id,
            "processor: SystemStateResponse: received (not in DR mode, ignoring)"
        );
    }
}
