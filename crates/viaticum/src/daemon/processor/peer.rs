// Peer handlers: authentication, peer announce, cluster device auto-add.

use libp2p::PeerId;
use tracing::{debug, info, warn};
use viaticum_core::cluster::DeviceCertificate;
use viaticum_core::constants::{AVAIL_EWMA_ALPHA, MESSAGE_FRESHNESS_SECS};
use viaticum_core::messages::{PeerAnnounceMsg, verify_peer_announce};
use viaticum_core::types::{DeviceId, IdentityPub, Timestamp, ewma_contact_observed};

use super::{Processor, ProcessorError, work_wake};

impl Processor {
    /// Called when DeviceCertExchange succeeds for a peer (AC-1, AC-2), joined
    /// form for the tests: admission ([`Processor::admit_authenticated`]), the
    /// PeerRecord write as the writer does it (one batch), then the after-steps
    /// ([`Processor::after_peer_authenticated`]). `Processor::run` hands the
    /// event to the PeerRecord writer instead (C-DK C4 fix round 3).
    #[cfg(test)]
    pub(crate) async fn on_peer_authenticated(
        &self,
        _peer_id: PeerId,
        device_id: DeviceId,
        identity_pub: IdentityPub,
        device_cert: DeviceCertificate,
        x25519_pub: Option<[u8; 32]>,
        listen_addrs: Vec<libp2p::Multiaddr>,
    ) {
        if !self.admit_authenticated(device_id, identity_pub, &device_cert) {
            return;
        }
        self.peer_records
            .push(super::peer_record_writer::PeerRecordEvent::Authenticated {
                device_id,
                identity_pub,
                device_cert: Box::new(device_cert),
                x25519_pub,
                listen_addrs: addr_strings(&listen_addrs),
            });
        for w in self.write_peer_records_now() {
            self.after_peer_authenticated(
                w.device_id,
                w.identity_pub,
                w.device_cert,
                w.is_new_peer,
            )
            .await;
        }
    }

    /// Tests: write everything queued for the PeerRecord writer now, in this
    /// thread, as the writer's batches do. Returns the authentications written.
    #[cfg(test)]
    pub(crate) fn write_peer_records_now(&self) -> Vec<super::peer_record_writer::WrittenAuth> {
        let mut written = Vec::new();
        loop {
            let batch = self
                .peer_records
                .take_batch(super::peer_record_writer::BATCH_MAX);
            if batch.is_empty() {
                return written;
            }
            written.extend(
                super::peer_record_writer::apply_batch(&self.db, batch).expect("peer batch write"),
            );
        }
    }

    /// Steps 0–1 of an authentication, run in `Processor::run` before the event
    /// goes to the PeerRecord writer (no write here). Returns false when the
    /// device is revoked: the event is dropped and leaves no trace.
    ///
    /// 0. Revocation check. 1. peer_cert_map.
    pub(crate) fn admit_authenticated(
        &self,
        device_id: DeviceId,
        identity_pub: IdentityPub,
        device_cert: &DeviceCertificate,
    ) -> bool {
        // 0. Revocation check (review S1): reject if this device key is in the
        //    cluster's revocation list. We check against both the cluster_state
        //    (master's authoritative list) and the per-peer PeerRecord
        //    revoked_device_pub_keys field (for device-level revocation seen
        //    via signed RevocationMsg). Must come before any DB write so a
        //    revoked device leaves no trace. (A read transaction only.)
        if let Some(cs_arc) = self.cluster_state.as_ref() {
            let cs = cs_arc.lock().unwrap();
            if cs.is_device_revoked(&device_id) {
                warn!(
                    device = %device_id,
                    master = %identity_pub,
                    "processor: revoked device attempted connection — rejecting authentication"
                );
                return false;
            }
        }
        if let Ok(Some(existing_peer)) = self.db.get_peer(&device_id)
            && existing_peer.is_device_revoked(&device_id)
        {
            warn!(
                device = %device_id,
                master = %identity_pub,
                "processor: peer has revoked device key — rejecting authentication"
            );
            return false;
        }

        // 1. Store in peer_cert_map.
        {
            let mut map = self.peer_cert_map.lock().unwrap();
            map.insert(device_id, (identity_pub, device_cert.clone()));
        }
        true
    }

    /// Steps 3–5 of an authentication, spawned by the PeerRecord writer after
    /// the commit that wrote the record: cluster auto-add, PeerAnnounce over
    /// the connection, the work-pipeline wake.
    pub(crate) async fn after_peer_authenticated(
        &self,
        device_id: DeviceId,
        identity_pub: IdentityPub,
        device_cert: DeviceCertificate,
        is_new_peer: bool,
    ) {
        // 3. Auto-add cluster device if same master identity.
        self.try_auto_add_cluster_device(Some(identity_pub), Some(device_cert))
            .await;

        // 4. Send PeerAnnounce so the peer learns our identity ↔ DeviceId binding.
        //    Only over the connection that just authenticated: never a dial
        //    (C-DK v3.2 N-3 — a peer the cache closed meanwhile stays closed).
        let pa = self.swarm.build_peer_announce(Timestamp::now());
        let pa_msg = viaticum_core::messages::Message::PeerAnnounce(pa);
        if let Err(e) = self.swarm.send_if_connected(device_id, pa_msg).await {
            use crate::daemon::network::swarm::SwarmError;
            if matches!(
                e,
                SwarmError::PeerNotAuthenticated(_) | SwarmError::Unreachable(..)
            ) {
                // The connection is gone already (the cache closed it): normal.
                debug!(device = %device_id, err = %e,
                    "processor: on_peer_authenticated: PeerAnnounce not sent, no connection");
            } else {
                warn!(
                    device = %device_id,
                    err = %e,
                    "processor: on_peer_authenticated: failed to send PeerAnnounce"
                );
            }
        } else {
            debug!(device = %device_id, "processor: sent PeerAnnounce after authentication");
        }

        // 5. Notify WorkPipeline worker (if wired) to reset cooldowns and wake —
        //    a new peer always, a returning one at most once per 10 min /
        //    time_scale per device (C-DK Р-18).
        let wake = self
            .work_wake
            .lock()
            .expect("work wake lock poisoned")
            .allow(
                device_id,
                is_new_peer,
                work_wake::work_wake_min(self.swarm.time_scale()),
                std::time::Instant::now(),
            );
        if !wake {
            self.swarm.note_work_wake_suppressed();
            debug!(device = %device_id, "processor: work wake suppressed");
        } else if let Some(tx) = &self.work_event_tx {
            let event = crate::daemon::work_pipeline::WorkEvent::PeerAuthenticated { device_id };
            if let Err(e) = tx.try_send(event) {
                debug!(device = %device_id, err = %e, "processor: work_event_tx send failed (pipeline busy or uninitialized)");
            }
        }
    }

    /// Tests: an identify through the PeerRecord writer's path, written now
    /// (`Processor::run` pushes `PeerIdentified` to the writer). The addresses
    /// land on an existing PeerRecord, each a full multiaddr string with exactly
    /// one `/p2p/<peer_id>` suffix (the swarm normalizes them): the redial loop
    /// derives the PeerId from `device_id`, DR's HolderHint parsing needs it.
    #[cfg(test)]
    pub(crate) fn on_peer_identified(
        &self,
        device_id: DeviceId,
        listen_addrs: Vec<libp2p::Multiaddr>,
    ) {
        self.peer_records
            .push(super::peer_record_writer::PeerRecordEvent::Identified {
                device_id,
                listen_addrs: addr_strings(&listen_addrs),
            });
        self.write_peer_records_now();
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
        peer_master_identity: Option<viaticum_core::types::IdentityPub>,
        peer_device_cert: Option<viaticum_core::cluster::DeviceCertificate>,
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
        let addr_str = viaticum_core::types::hex_encode(&cert.device_id.0);
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
            Err(viaticum_core::cluster::ClusterStateError::DeviceAlreadyRegistered(_)) => {
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
        if age > MESSAGE_FRESHNESS_SECS {
            warn!(
                identity = %msg.identity_pub,
                age_secs = age,
                "processor: PeerAnnounce rejected — timestamp too old (possible replay)"
            );
            return Ok(());
        }
        if msg.timestamp.0 > now.0.saturating_add(MESSAGE_FRESHNESS_SECS) {
            warn!(
                identity = %msg.identity_pub,
                "processor: PeerAnnounce rejected — timestamp is in the future"
            );
            return Ok(());
        }
        // PeerRecord is keyed by DeviceId. Look up all known devices for this master identity.
        // If we have device records — update x25519_pub and last_seen.
        // If no devices known yet — the record (and the device-to-master mapping, same
        // commit) is created later by the PeerRecord writer from the authentication.
        let devices = self
            .db
            .get_devices_for_master(&msg.identity_pub)
            .unwrap_or_default();
        let now_secs = now.0;
        for did in &devices {
            // One write transaction per record: the PeerRecord writer's batch
            // (identify addresses) is entirely before or after it, never
            // overwritten (C-DK C4 fix rounds 1, 3).
            self.db.update_peer(did, |current| {
                let mut existing = current?;
                #[cfg(test)]
                announce_rmw_test_delay();
                existing.last_seen = now;
                if msg.x25519_pub.is_some() {
                    existing.x25519_pub = msg.x25519_pub;
                }
                existing.avail_ewma = ewma_contact_observed(existing.avail_ewma, AVAIL_EWMA_ALPHA);
                existing.last_avail_sample = now_secs;
                Some(existing)
            })?;
        }

        info!(
            identity = %msg.identity_pub,
            "processor: PeerAnnounce upserted peer record"
        );

        Ok(())
    }
}

/// Tests only: how long a PeerAnnounce update holds between reading the record
/// and writing it back (ms). Makes the read-modify-write window wide enough that
/// a concurrent identify write would be lost if the two were not one
/// transaction (C-DK C4 fix round 2, WARN-B). 0 = off.
#[cfg(test)]
pub(crate) static ANNOUNCE_RMW_DELAY_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
fn announce_rmw_test_delay() {
    let ms = ANNOUNCE_RMW_DELAY_MS.load(std::sync::atomic::Ordering::Relaxed);
    if ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

/// Multiaddrs as the stored strings (the swarm already normalized them: one
/// `/p2p/<peer_id>` suffix each).
pub(crate) fn addr_strings(addrs: &[libp2p::Multiaddr]) -> Vec<String> {
    addrs.iter().map(|a| a.to_string()).collect()
}
