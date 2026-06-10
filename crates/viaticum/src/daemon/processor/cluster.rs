// Cluster handlers: sync request/response (epoch/event-log sibling path).
//
// A2 (T-13b-3): the relay-board RevocationBroadcast handler and the SystemState
// blob backup/request/ack/response handlers were removed here. Device revocation
// now arrives via the mailbox (ProcessorRevocationHandler in symbol.rs), and the
// SystemState blob transport was retired in favour of the mailbox self-pointer bus.

use libp2p::request_response::ResponseChannel;
use tracing::{debug, warn};
use viaticum_core::messages::{ClusterSyncRequestMsg, ClusterSyncResponseMsg, Message};
use viaticum_core::types::{DeviceId, IdentityPub};

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
}
