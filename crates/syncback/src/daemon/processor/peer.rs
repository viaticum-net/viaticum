// Peer handlers: authentication, peer announce, cluster device auto-add.

use libp2p::PeerId;
use syncback_core::cluster::DeviceCertificate;
use syncback_core::constants::{HANDSHAKE_FRESHNESS_SECS, INITIAL_TRUST_P};
use syncback_core::messages::{PeerAnnounceMsg, verify_peer_announce};
use syncback_core::types::{DeviceId, IdentityPub, PeerRecord, Timestamp};
use tracing::{debug, error, info, warn};

use super::{Processor, ProcessorError};

impl Processor {
    /// Called when DeviceCertExchange succeeds for a peer (AC-1, AC-2).
    ///
    /// 1. Stores (identity_pub, device_cert) in peer_cert_map under device_id.
    /// 2. Upserts PeerRecord in DB (sets device_id and x25519_pub fields).
    /// 3. Calls try_auto_add_cluster_device if peer has same master identity.
    /// 4. Sends PeerAnnounce to the newly authenticated peer via swarm.
    pub(crate) async fn on_peer_authenticated(
        &self,
        _peer_id: PeerId,
        device_id: DeviceId,
        identity_pub: IdentityPub,
        device_cert: DeviceCertificate,
        x25519_pub: Option<[u8; 32]>,
    ) {
        // 0. Revocation check (review S1): reject if this device key is in the
        //    cluster's revocation list. We check against both the cluster_state
        //    (master's authoritative list) and the per-peer PeerRecord
        //    revoked_device_pub_keys field (for device-level revocation seen
        //    via signed RevocationMsg). Must come before any DB write so a
        //    revoked device leaves no trace.
        if let Some(cs_arc) = self.cluster_state.as_ref() {
            let cs = cs_arc.lock().unwrap();
            if cs.is_device_revoked(&device_id) {
                warn!(
                    device = %device_id,
                    master = %identity_pub,
                    "processor: revoked device attempted connection — rejecting authentication"
                );
                return;
            }
        }
        if let Ok(Some(existing_peer)) = self.db.get_peer(&device_id)
            && existing_peer.is_device_revoked(&device_id) {
                warn!(
                    device = %device_id,
                    master = %identity_pub,
                    "processor: peer has revoked device key — rejecting authentication"
                );
                return;
            }

        // 1. Store in peer_cert_map.
        {
            let mut map = self.peer_cert_map.lock().unwrap();
            map.insert(device_id, (identity_pub, device_cert.clone()));
        }

        // 2. Upsert PeerRecord in DB (keyed by DeviceId).
        let now = Timestamp::now();
        let record = match self.db.get_peer(&device_id) {
            Ok(Some(mut existing)) => {
                existing.master_identity = identity_pub;
                existing.last_seen = now;
                if x25519_pub.is_some() {
                    existing.x25519_pub = x25519_pub;
                }
                if existing.trust_p == 0.0 && existing.trust_i == 0.0 {
                    existing.trust_p = INITIAL_TRUST_P;
                }
                existing
            }
            Ok(None) => PeerRecord {
                device_id,
                master_identity: identity_pub,
                trust_p: INITIAL_TRUST_P,
                trust_i: 0.0,
                trust_s: 1.0,
                bytes_we_store_for_peer: 0,
                bytes_peer_stores_for_us: 0,
                first_seen: now,
                last_seen: now,
                revoked_device_pub_keys: vec![],
                addrs: vec![],
                x25519_pub,
            },
            Err(e) => {
                error!(
                    device = %device_id,
                    err = %e,
                    "processor: on_peer_authenticated: db.get_peer failed"
                );
                return;
            }
        };
        if let Err(e) = self.db.upsert_peer(&record) {
            error!(
                device = %device_id,
                err = %e,
                "processor: on_peer_authenticated: db.upsert_peer failed"
            );
        }

        // Store device-to-master mapping for two-level trust.
        if let Err(e) = self.db.set_master_for_device(&device_id, &identity_pub) {
            error!(
                device = %device_id,
                err = %e,
                "processor: on_peer_authenticated: failed to store device-to-master mapping"
            );
        }

        // 3. Auto-add cluster device if same master identity.
        self.try_auto_add_cluster_device(Some(identity_pub), Some(device_cert))
            .await;

        // 4. Send PeerAnnounce so the peer learns our identity ↔ DeviceId binding.
        let pa = self.swarm.build_peer_announce(Timestamp::now());
        let pa_msg = syncback_core::messages::Message::PeerAnnounce(pa);
        if let Err(e) = self.swarm.send_to_device(device_id, pa_msg).await {
            warn!(
                device = %device_id,
                err = %e,
                "processor: on_peer_authenticated: failed to send PeerAnnounce"
            );
        } else {
            debug!(device = %device_id, "processor: sent PeerAnnounce after authentication");
        }

        // 5. Notify WorkPipeline worker (if wired) to reset cooldowns and wake.
        if let Some(tx) = &self.work_event_tx {
            let event = crate::daemon::work_pipeline::WorkEvent::PeerAuthenticated { device_id };
            if let Err(e) = tx.try_send(event) {
                debug!(device = %device_id, err = %e, "processor: work_event_tx send failed (pipeline busy or uninitialized)");
            }
        }
    }

    /// Called when libp2p identify delivers a peer's listen addresses for an
    /// already-authenticated peer. Persists them on the PeerRecord so that on
    /// the next daemon restart the auto-dial loop in handle/mod.rs can re-dial
    /// without external bootstrap config.
    ///
    /// Each address is stored as its full multiaddr string, including the
    /// `/p2p/<peer_id>` suffix, so the bootstrap loop can extract the PeerId
    /// without tracking it separately.
    pub(crate) async fn on_peer_identified(
        &self,
        device_id: DeviceId,
        listen_addrs: Vec<libp2p::Multiaddr>,
    ) {
        if listen_addrs.is_empty() {
            return;
        }
        let addr_strings: Vec<String> = listen_addrs.iter().map(|a| a.to_string()).collect();

        match self.db.get_peer(&device_id) {
            Ok(Some(mut record)) => {
                if record.addrs == addr_strings {
                    return;
                }
                record.addrs = addr_strings;
                if let Err(e) = self.db.upsert_peer(&record) {
                    tracing::warn!(device = %device_id, err = %e,
                        "on_peer_identified: failed to persist addrs");
                }
            }
            Ok(None) => {
                tracing::trace!(device = %device_id,
                    "on_peer_identified: PeerRecord missing");
            }
            Err(e) => {
                tracing::warn!(device = %device_id, err = %e,
                    "on_peer_identified: db get_peer failed");
            }
        }
    }

    /// Called when a libp2p connection closes (AC-13).
    ///
    /// Removes the device from peer_cert_map if present.
    pub(crate) async fn on_connection_closed(&self, _peer_id: PeerId, device_id: Option<DeviceId>) {
        if let Some(dev_id) = device_id {
            let removed = {
                let mut map = self.peer_cert_map.lock().unwrap();
                map.remove(&dev_id).is_some()
            };
            debug!(device = %dev_id, removed, "processor: connection closed, removed from peer_cert_map");
        } else {
            debug!("processor: unauthenticated connection closed");
        }
    }

    /// Auto-add a cluster device if the peer has the same master identity as this node.
    ///
    /// Checks whether `peer_master_identity == own_identity`. If so, calls
    /// `cluster_state.add_device`. Routing is by DeviceId via SwarmHandle's
    /// internal authenticated map — no explicit address registration needed.
    ///
    /// Errors from `add_device`:
    ///   - `DeviceAlreadyRegistered` → logged at debug, not an error condition.
    ///   - Other errors → logged at warn.
    ///
    /// Returns `true` if the device was newly added, `false` otherwise.
    pub async fn try_auto_add_cluster_device(
        &self,
        peer_master_identity: Option<syncback_core::types::IdentityPub>,
        peer_device_cert: Option<syncback_core::cluster::DeviceCertificate>,
    ) -> bool {
        let peer_master = match peer_master_identity {
            Some(id) => id,
            None => return false,
        };
        if peer_master != self.own_identity {
            return false;
        }
        let cert = match peer_device_cert {
            Some(c) => c,
            None => return false,
        };
        let cs = match self.cluster_state.as_ref() {
            Some(cs) => cs,
            None => return false,
        };
        // Store hex of device_id.0 (= device pub key) — used for reconnect.
        let addr_str = syncback_core::types::hex_encode(&cert.device_id.0);
        let result = {
            let mut guard = cs.lock().unwrap();
            let r = guard.add_device(cert.clone(), Timestamp::now());
            // Persist address for reconnect after restart (best-effort).
            let _ = guard.set_cluster_addr(cert.device_id, addr_str);
            r
        };
        match result {
            Ok(()) => {
                // libp2p routing is by DeviceId via SwarmHandle's authenticated map.
                // No explicit address registration needed (unlike iroh).
                true
            }
            Err(syncback_core::cluster::ClusterStateError::DeviceAlreadyRegistered(_)) => {
                // libp2p routing is by DeviceId; no explicit address update needed.
                debug!(device = %cert.device_id, "cluster: device already registered, skipping add");
                false
            }
            Err(_) => false,
        }
    }

    /// Learn about a peer's identity. Upsert PeerRecord in DB.
    ///
    /// In the libp2p path, network routing is by PeerId/DeviceId via the
    /// SwarmHandle's authenticated map — no explicit address registration needed.
    /// The node_id field is kept in PeerRecord for backward compatibility
    /// (used in relay board key derivation); it may be a zero placeholder for
    /// libp2p peers.
    pub(crate) async fn handle_peer_announce(
        &self,
        msg: PeerAnnounceMsg,
    ) -> Result<(), ProcessorError> {
        // Verify Ed25519 signature before trusting any fields.
        if let Err(e) = verify_peer_announce(&msg) {
            warn!(
                identity = %msg.identity_pub,
                err = %e,
                "processor: PeerAnnounce signature verification failed, ignoring"
            );
            return Ok(());
        }

        let now = Timestamp::now();
        let age = now.0.saturating_sub(msg.timestamp.0);
        if age > HANDSHAKE_FRESHNESS_SECS {
            warn!(
                identity = %msg.identity_pub,
                age_secs = age,
                "processor: PeerAnnounce rejected — timestamp too old (possible replay)"
            );
            return Ok(());
        }
        if msg.timestamp.0 > now.0.saturating_add(HANDSHAKE_FRESHNESS_SECS) {
            warn!(
                identity = %msg.identity_pub,
                "processor: PeerAnnounce rejected — timestamp is in the future"
            );
            return Ok(());
        }
        // PeerRecord is keyed by DeviceId. Look up all known devices for this master identity.
        // If we have device records — update x25519_pub and last_seen.
        // If no devices known yet — record is created later by on_peer_authenticated.
        let devices = self
            .db
            .get_devices_for_master(&msg.identity_pub)
            .unwrap_or_default();
        for did in &devices {
            if let Some(mut existing) = self.db.get_peer(did)? {
                existing.last_seen = now;
                if msg.x25519_pub.is_some() {
                    existing.x25519_pub = msg.x25519_pub;
                }
                if existing.trust_p == 0.0 && existing.trust_i == 0.0 {
                    existing.trust_p = INITIAL_TRUST_P;
                }
                self.db.upsert_peer(&existing)?;
            }
        }

        info!(
            identity = %msg.identity_pub,
            "processor: PeerAnnounce upserted peer record"
        );

        Ok(())
    }
}
