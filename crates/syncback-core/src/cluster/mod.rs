use crate::types::{DeviceId, IdentityPub, Timestamp, sig_serde};
use ed25519_dalek::Signer;
use hkdf::Hkdf;
use sha2::Sha256;

#[cfg(test)]
mod tests;

// ============================================================
// Types
// ============================================================

/// Counter for epoch rotation. Starts at 0; incremented on device revocation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct EpochCounter(pub u32);

/// Certificate issued by master key to authorize a device.
///
/// device_id.0 IS the Ed25519 public key of the device — no separate device_pub_key.
/// Signed payload: device_id.0 (32 bytes) || issued_at.0.to_be_bytes() (8 bytes).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeviceCertificate {
    pub device_id: DeviceId,
    pub issued_at: Timestamp,
    /// Ed25519 signature: master_key.sign(device_id.0 || issued_at_be)
    #[serde(with = "sig_serde")]
    pub signature: [u8; 64],
    /// Identity (master) pub key, so verifier knows who signed.
    pub master_pub_key: IdentityPub,
}

/// Certificate revoking a device key.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RevocationCertificate {
    pub device_id: DeviceId,
    pub revoked_at: Timestamp,
    /// New epoch counter after revocation.
    pub new_epoch: EpochCounter,
    /// Ed25519 signature: master_key.sign(b"revoke" || device_id || revoked_at_be || new_epoch_be)
    #[serde(with = "sig_serde")]
    pub signature: [u8; 64],
    pub master_pub_key: IdentityPub,
}

/// An epoch key: derived symmetric key for file encryption.
#[derive(Debug, Clone)]
pub struct EpochKey {
    pub epoch: EpochCounter,
    /// 32-byte ChaCha20 key.
    pub key_bytes: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error("invalid signature")]
    InvalidSignature,

    #[error("device_id mismatch")]
    DeviceIdMismatch,

    #[error("certificate expired: issued {issued_at:?}, now {now:?}")]
    CertificateExpired {
        issued_at: Timestamp,
        now: Timestamp,
    },

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
}

// ============================================================
// Key derivation
// ============================================================

/// Derive master Ed25519 signing key from raw seed bytes.
///
/// HKDF-SHA256(ikm=seed_bytes, salt=b"", info=b"syncback-identity-ed25519") → 32 bytes
pub fn derive_master_key(seed_bytes: &[u8]) -> Result<ed25519_dalek::SigningKey, ClusterError> {
    let hk = Hkdf::<Sha256>::new(Some(b""), seed_bytes);
    let mut okm = [0u8; 32];
    hk.expand(b"syncback-identity-ed25519", &mut okm)
        .map_err(|e| ClusterError::KeyDerivation(e.to_string()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&okm))
}

/// Derive device Ed25519 signing key from master seed + device_seed.
///
/// HKDF-SHA256(ikm=seed_bytes, salt=device_seed, info=b"syncback-device-ed25519") → 32 bytes
///
/// The returned signing key's verifying_key().to_bytes() IS the DeviceId.
pub fn derive_device_key(
    seed_bytes: &[u8],
    device_seed: &[u8; 32],
) -> Result<ed25519_dalek::SigningKey, ClusterError> {
    let hk = Hkdf::<Sha256>::new(Some(device_seed), seed_bytes);
    let mut okm = [0u8; 32];
    hk.expand(b"syncback-device-ed25519", &mut okm)
        .map_err(|e| ClusterError::KeyDerivation(e.to_string()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&okm))
}

/// Derive epoch encryption key.
///
/// HKDF-SHA256(ikm=seed_bytes, salt=epoch.0.to_be_bytes(), info=b"syncback-encryption") → 32 bytes
pub fn derive_epoch_key(seed_bytes: &[u8], epoch: EpochCounter) -> Result<EpochKey, ClusterError> {
    let salt = epoch.0.to_be_bytes();
    let hk = Hkdf::<Sha256>::new(Some(&salt), seed_bytes);
    let mut okm = [0u8; 32];
    hk.expand(b"syncback-encryption", &mut okm)
        .map_err(|e| ClusterError::KeyDerivation(e.to_string()))?;
    Ok(EpochKey {
        epoch,
        key_bytes: okm,
    })
}

/// Extract IdentityPub from a master signing key.
pub fn master_identity(master_key: &ed25519_dalek::SigningKey) -> IdentityPub {
    IdentityPub(master_key.verifying_key().to_bytes())
}

// ============================================================
// Device certificates
// ============================================================

/// Issue a device certificate. device_id.0 must equal device_signing_key.verifying_key().to_bytes().
///
/// Signed message: device_id.0 (32 bytes) || issued_at.0.to_be_bytes() (8 bytes)
pub fn issue_device_certificate(
    master_key: &ed25519_dalek::SigningKey,
    device_id: DeviceId,
    issued_at: Timestamp,
) -> DeviceCertificate {
    let payload = device_cert_payload(&device_id, issued_at);
    let sig = master_key.sign(&payload);
    DeviceCertificate {
        device_id,
        issued_at,
        signature: sig.to_bytes(),
        master_pub_key: master_identity(master_key),
    }
}

/// Verify a device certificate. Uses cert.device_id.0 as the device public key.
///
/// Checks: 1) signature valid, 2) master_pub_key matches expected identity.
pub fn verify_device_certificate(
    cert: &DeviceCertificate,
    expected_master: &IdentityPub,
) -> Result<(), ClusterError> {
    if cert.master_pub_key != *expected_master {
        return Err(ClusterError::InvalidSignature);
    }
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&cert.master_pub_key.0)
        .map_err(|_| ClusterError::InvalidSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&cert.signature);
    let payload = device_cert_payload(&cert.device_id, cert.issued_at);
    verifying_key
        .verify_strict(&payload, &sig)
        .map_err(|_| ClusterError::InvalidSignature)
}

fn device_cert_payload(device_id: &DeviceId, issued_at: Timestamp) -> Vec<u8> {
    let mut payload = Vec::with_capacity(40);
    payload.extend_from_slice(&device_id.0);
    payload.extend_from_slice(&issued_at.0.to_be_bytes());
    payload
}

// ============================================================
// Revocation
// ============================================================

/// Issue a revocation certificate for a device.
///
/// Signed message: b"revoke" (6) || device_id.0 (32) || revoked_at.0.to_be_bytes() (8) || new_epoch.0.to_be_bytes() (4) = 50 bytes
pub fn issue_revocation(
    master_key: &ed25519_dalek::SigningKey,
    device_id: DeviceId,
    revoked_at: Timestamp,
    new_epoch: EpochCounter,
) -> RevocationCertificate {
    let payload = revocation_payload(&device_id, revoked_at, new_epoch);
    let sig = master_key.sign(&payload);
    RevocationCertificate {
        device_id,
        revoked_at,
        new_epoch,
        signature: sig.to_bytes(),
        master_pub_key: master_identity(master_key),
    }
}

/// Verify a revocation certificate.
pub fn verify_revocation(
    cert: &RevocationCertificate,
    expected_master: &IdentityPub,
) -> Result<(), ClusterError> {
    if cert.master_pub_key != *expected_master {
        return Err(ClusterError::InvalidSignature);
    }
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&cert.master_pub_key.0)
        .map_err(|_| ClusterError::InvalidSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&cert.signature);
    let payload = revocation_payload(&cert.device_id, cert.revoked_at, cert.new_epoch);
    verifying_key
        .verify_strict(&payload, &sig)
        .map_err(|_| ClusterError::InvalidSignature)
}

fn revocation_payload(
    device_id: &DeviceId,
    revoked_at: Timestamp,
    new_epoch: EpochCounter,
) -> Vec<u8> {
    // b"revoke" (6) || device_id.0 (32) || revoked_at_be (8) || epoch_be (4) = 50 bytes
    let mut payload = Vec::with_capacity(50);
    payload.extend_from_slice(b"revoke");
    payload.extend_from_slice(&device_id.0);
    payload.extend_from_slice(&revoked_at.0.to_be_bytes());
    payload.extend_from_slice(&new_epoch.0.to_be_bytes());
    payload
}

// ============================================================
// Epoch management
// ============================================================

/// Compute the next epoch counter (after revocation).
pub fn next_epoch(current: EpochCounter) -> EpochCounter {
    EpochCounter(current.0 + 1)
}

/// Determine which epoch key was used to encrypt a file created at `created_at`.
///
/// epoch_history: Vec<(EpochCounter, activated_at: Timestamp)> sorted by activated_at ascending.
/// Returns the epoch counter that was active when the file was created.
/// If created_at is before all entries, returns the first entry's epoch.
pub fn epoch_for_time(
    epoch_history: &[(EpochCounter, Timestamp)],
    created_at: Timestamp,
) -> EpochCounter {
    let mut result = epoch_history
        .first()
        .map(|(e, _)| *e)
        .unwrap_or(EpochCounter(0));
    for (epoch, activated_at) in epoch_history {
        if *activated_at <= created_at {
            result = *epoch;
        }
    }
    result
}

// ============================================================
// ESI namespace allocation
// ============================================================

/// Compute the ESI namespace start for a device index.
/// ESI = device_index * 2^20 + local_counter.
/// Max 16 devices (ESI space = 2^24, 2^20 per device).
pub fn esi_namespace_start(device_index: u8) -> u32 {
    debug_assert!(
        device_index <= 16,
        "max 16 devices supported (0..=15, 16 as exclusive end)"
    );
    (device_index as u32) << 20
}

/// ESI namespace end (exclusive) for a device index.
pub fn esi_namespace_end(device_index: u8) -> u32 {
    device_index
        .checked_add(1)
        .map_or(u32::MAX, esi_namespace_start)
}

// ============================================================
// ClusterState
// ============================================================

/// Persistent snapshot of cluster state stored in DB.
/// Used for fast load at startup without replaying entire event log.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredClusterState {
    pub master_pub: IdentityPub,
    pub devices: Vec<DeviceEntry>,
    pub current_epoch: EpochCounter,
    /// Epoch rotation history: (epoch_counter, activated_at). Sorted ascending by activated_at.
    pub epoch_history: Vec<(EpochCounter, Timestamp)>,
    /// Revoked device IDs. Append-only.
    pub revoked_devices: Vec<crate::types::DeviceId>,
    /// Peer-to-device affinity: which local device manages each external peer.
    pub peer_affinity: Vec<(IdentityPub, crate::types::DeviceId)>,
    /// Last applied event log sequence number.
    pub last_applied_seq: u64,
    /// Per-device sync cursors for ClusterSync (DeviceId → last received seq).
    #[serde(default)]
    pub sync_cursors: std::collections::HashMap<crate::types::DeviceId, u64>,
    /// Last known network addresses for cluster devices (for reconnect after restart).
    #[serde(default)]
    pub cluster_addrs: std::collections::HashMap<crate::types::DeviceId, String>,
}

/// One registered device in the cluster.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceEntry {
    pub device_id: crate::types::DeviceId,
    // device_pub_key removed — device_id.0 is the Ed25519 public key
    /// Certificate issued by master key.
    pub certificate: DeviceCertificate,
    /// Index assigned at registration. Immutable once assigned. Range: 0..=15.
    pub device_index: u8,
}

/// Error type for ClusterState operations.
#[derive(Debug, thiserror::Error)]
pub enum ClusterStateError {
    #[error("db error: {0}")]
    Db(#[from] crate::db::DbError),

    #[error("cluster crypto error: {0}")]
    Cluster(#[from] ClusterError),

    #[error("device already registered: {0:?}")]
    DeviceAlreadyRegistered(crate::types::DeviceId),

    #[error("device not found: {0:?}")]
    DeviceNotFound(crate::types::DeviceId),

    #[error("device is revoked: {0:?}")]
    DeviceRevoked(crate::types::DeviceId),

    #[error("max devices reached (limit: 16)")]
    MaxDevicesReached,

    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("not initialized")]
    NotInitialized,

    #[error("already initialized")]
    AlreadyInitialized,
}

const MAX_DEVICES: usize = 16;

/// Stateful cluster registry. Persisted via Db.
pub struct ClusterState {
    db: crate::db::Db,
    state: StoredClusterState,
}

impl ClusterState {
    /// Load existing cluster state from DB.
    /// Returns Err(NotInitialized) if no state exists.
    pub fn load(db: crate::db::Db) -> Result<Self, ClusterStateError> {
        match db.get_cluster_state()? {
            Some(state) => Ok(ClusterState { db, state }),
            None => Err(ClusterStateError::NotInitialized),
        }
    }

    /// Initialize a new cluster (first device registration).
    pub fn init(
        db: crate::db::Db,
        master_pub: IdentityPub,
        first_device_cert: DeviceCertificate,
        epoch0_activated_at: crate::types::Timestamp,
        now: crate::types::Timestamp,
    ) -> Result<Self, ClusterStateError> {
        if db.get_cluster_state()?.is_some() {
            return Err(ClusterStateError::AlreadyInitialized);
        }
        verify_device_certificate(&first_device_cert, &master_pub)
            .map_err(|e| ClusterStateError::InvalidCertificate(e.to_string()))?;

        let device_id = first_device_cert.device_id;
        let entry = DeviceEntry {
            device_id,
            certificate: first_device_cert,
            device_index: 0,
        };

        let state = StoredClusterState {
            master_pub,
            devices: vec![entry],
            current_epoch: EpochCounter(0),
            epoch_history: vec![(EpochCounter(0), epoch0_activated_at)],
            revoked_devices: Vec::new(),
            peer_affinity: Vec::new(),
            last_applied_seq: 0,
            sync_cursors: std::collections::HashMap::new(),
            cluster_addrs: std::collections::HashMap::new(),
        };

        db.append_event(&crate::types::EventEntry {
            timestamp: now,
            device_id,
            event: crate::types::Event::DeviceAdded { device_id },
        })?;

        db.set_cluster_state(&state)?;
        Ok(ClusterState { db, state })
    }

    /// Register a new device. Appends DeviceAdded event.
    pub fn add_device(
        &mut self,
        certificate: DeviceCertificate,
        now: crate::types::Timestamp,
    ) -> Result<(), ClusterStateError> {
        let device_id = certificate.device_id;

        if self.state.devices.iter().any(|d| d.device_id == device_id) {
            return Err(ClusterStateError::DeviceAlreadyRegistered(device_id));
        }
        if self.state.devices.len() >= MAX_DEVICES {
            return Err(ClusterStateError::MaxDevicesReached);
        }
        verify_device_certificate(&certificate, &self.state.master_pub)
            .map_err(|e| ClusterStateError::InvalidCertificate(e.to_string()))?;

        let device_index = self.state.devices.len() as u8;
        self.state.devices.push(DeviceEntry {
            device_id,
            certificate,
            device_index,
        });

        self.db.append_event(&crate::types::EventEntry {
            timestamp: now,
            device_id,
            event: crate::types::Event::DeviceAdded { device_id },
        })?;

        self.db.set_cluster_state(&self.state)?;
        Ok(())
    }

    /// Revoke a device. Rotates epoch.
    pub fn revoke_device(
        &mut self,
        revocation_cert: RevocationCertificate,
        epoch_activated_at: crate::types::Timestamp,
        now: crate::types::Timestamp,
    ) -> Result<(), ClusterStateError> {
        let device_id = revocation_cert.device_id;

        if !self.state.devices.iter().any(|d| d.device_id == device_id) {
            return Err(ClusterStateError::DeviceNotFound(device_id));
        }
        if self.state.revoked_devices.contains(&device_id) {
            return Err(ClusterStateError::DeviceRevoked(device_id));
        }
        verify_revocation(&revocation_cert, &self.state.master_pub)
            .map_err(|e| ClusterStateError::InvalidCertificate(e.to_string()))?;

        let new_epoch = revocation_cert.new_epoch;
        self.state.revoked_devices.push(device_id);
        self.state.current_epoch = new_epoch;
        self.state
            .epoch_history
            .push((new_epoch, epoch_activated_at));

        let caller_device_id = self
            .state
            .devices
            .first()
            .map(|d| d.device_id)
            .unwrap_or(device_id);

        self.db.append_event(&crate::types::EventEntry {
            timestamp: now,
            device_id: caller_device_id,
            event: crate::types::Event::DeviceRevoked { device_id },
        })?;
        self.db.append_event(&crate::types::EventEntry {
            timestamp: now,
            device_id: caller_device_id,
            event: crate::types::Event::EpochRotated { epoch: new_epoch.0 },
        })?;

        self.db.set_cluster_state(&self.state)?;
        Ok(())
    }

    /// List all active (non-revoked) devices.
    pub fn active_devices(&self) -> Vec<&DeviceEntry> {
        self.state
            .devices
            .iter()
            .filter(|d| !self.state.revoked_devices.contains(&d.device_id))
            .collect()
    }

    /// List all devices (including revoked).
    pub fn all_devices(&self) -> &[DeviceEntry] {
        &self.state.devices
    }

    /// Get device entry by device_id.
    pub fn get_device(&self, device_id: &crate::types::DeviceId) -> Option<&DeviceEntry> {
        self.state
            .devices
            .iter()
            .find(|d| &d.device_id == device_id)
    }

    /// Check if a device is revoked.
    pub fn is_device_revoked(&self, device_id: &crate::types::DeviceId) -> bool {
        self.state.revoked_devices.contains(device_id)
    }

    /// Current epoch counter.
    pub fn current_epoch(&self) -> EpochCounter {
        self.state.current_epoch
    }

    /// Full epoch history sorted ascending.
    pub fn epoch_history(&self) -> &[(EpochCounter, crate::types::Timestamp)] {
        &self.state.epoch_history
    }

    /// Assign a peer to a device (or reassign). Persists to DB.
    pub fn set_peer_affinity(
        &mut self,
        peer: IdentityPub,
        device_id: crate::types::DeviceId,
    ) -> Result<(), ClusterStateError> {
        if let Some(entry) = self
            .state
            .peer_affinity
            .iter_mut()
            .find(|(p, _)| p == &peer)
        {
            entry.1 = device_id;
        } else {
            self.state.peer_affinity.push((peer, device_id));
        }
        self.db.set_cluster_state(&self.state)?;
        Ok(())
    }

    /// Get the device managing a peer.
    pub fn peer_device(&self, peer: &IdentityPub) -> Option<crate::types::DeviceId> {
        self.state
            .peer_affinity
            .iter()
            .find(|(p, _)| p == peer)
            .map(|(_, d)| *d)
    }

    /// List all peers assigned to a specific device.
    pub fn peers_for_device(&self, device_id: &crate::types::DeviceId) -> Vec<IdentityPub> {
        self.state
            .peer_affinity
            .iter()
            .filter(|(_, d)| d == device_id)
            .map(|(p, _)| *p)
            .collect()
    }

    /// Check if a content_hash is already backed up.
    pub fn is_content_backed_up(&self, content_hash: &[u8; 32]) -> Result<bool, ClusterStateError> {
        let files = self.db.list_all_files()?;
        for file in &files {
            for version in &file.versions {
                if &version.content_hash == content_hash && version.backed_up_at.is_some() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Find the source_block_id for an already-backed-up content_hash.
    pub fn find_source_block_for_content(
        &self,
        content_hash: &[u8; 32],
    ) -> Result<Option<crate::types::SourceBlockId>, ClusterStateError> {
        let files = self.db.list_all_files()?;
        for file in &files {
            for version in &file.versions {
                if &version.content_hash == content_hash && version.backed_up_at.is_some() {
                    return Ok(Some(version.source_block_id));
                }
            }
        }
        Ok(None)
    }

    /// Apply a batch of events from another device.
    pub fn apply_events(
        &mut self,
        events: &[(u64, crate::types::EventEntry)],
    ) -> Result<usize, ClusterStateError> {
        let mut applied = 0;
        for (seq, entry) in events {
            match &entry.event {
                crate::types::Event::DeviceAdded { device_id }
                    if !self.state.devices.iter().any(|d| &d.device_id == device_id) => {
                        let device_index = self.state.devices.len() as u8;
                        self.state.devices.push(DeviceEntry {
                            device_id: *device_id,
                            certificate: DeviceCertificate {
                                device_id: *device_id,
                                issued_at: entry.timestamp,
                                signature: [0u8; 64],
                                master_pub_key: self.state.master_pub,
                            },
                            device_index,
                        });
                        applied += 1;
                    }
                crate::types::Event::DeviceRevoked { device_id }
                    if !self.state.revoked_devices.contains(device_id) => {
                        self.state.revoked_devices.push(*device_id);
                        applied += 1;
                    }
                crate::types::Event::EpochRotated { epoch } => {
                    let new_epoch = EpochCounter(*epoch);
                    if new_epoch > self.state.current_epoch {
                        self.state.current_epoch = new_epoch;
                        self.state.epoch_history.push((new_epoch, entry.timestamp));
                        applied += 1;
                    }
                }
                _ => {}
            }
            if *seq > self.state.last_applied_seq {
                self.state.last_applied_seq = *seq;
            }
        }
        self.db.set_cluster_state(&self.state)?;
        Ok(applied)
    }

    /// Last applied event sequence number.
    pub fn local_last_seq(&self) -> Result<u64, ClusterStateError> {
        Ok(self.db.last_event_seq()?)
    }

    /// Our master public key.
    pub fn master_pub(&self) -> IdentityPub {
        self.state.master_pub
    }

    /// ESI namespace for a device_id. Returns (start, end). None if device not registered.
    pub fn esi_namespace(&self, device_id: &crate::types::DeviceId) -> Option<(u32, u32)> {
        let entry = self.get_device(device_id)?;
        Some((
            esi_namespace_start(entry.device_index),
            esi_namespace_end(entry.device_index),
        ))
    }

    /// Get the sync cursor (last received seq) for a peer device.
    /// Returns 0 if no cursor exists (meaning "start from beginning").
    pub fn sync_cursor(&self, device_id: &crate::types::DeviceId) -> u64 {
        self.state.sync_cursors.get(device_id).copied().unwrap_or(0)
    }

    /// Update the sync cursor for a peer device and persist to DB.
    pub fn update_sync_cursor(
        &mut self,
        device_id: crate::types::DeviceId,
        seq: u64,
    ) -> Result<(), ClusterStateError> {
        self.state.sync_cursors.insert(device_id, seq);
        self.db.set_cluster_state(&self.state)?;
        Ok(())
    }

    /// Store a cluster device's network address for reconnect after daemon restart.
    pub fn set_cluster_addr(
        &mut self,
        device_id: crate::types::DeviceId,
        addr: String,
    ) -> Result<(), ClusterStateError> {
        self.state.cluster_addrs.insert(device_id, addr);
        self.db.set_cluster_state(&self.state)?;
        Ok(())
    }

    /// Get all stored cluster device addresses.
    pub fn cluster_addrs(&self) -> &std::collections::HashMap<crate::types::DeviceId, String> {
        &self.state.cluster_addrs
    }
}
