use crate::types::{DeviceId, IdentityPub, Timestamp};
use ed25519_dalek::{Signer, Verifier};
use hkdf::Hkdf;
use sha2::Sha256;

#[cfg(test)]
mod tests;

// ============================================================
// Serde helper for [u8; 64]
// ============================================================

mod sig_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        sig.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.try_into().map_err(|_| serde::de::Error::custom("expected 64-byte signature"))
    }
}

// ============================================================
// Types
// ============================================================

/// Counter for epoch rotation. Starts at 0; incremented on device revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct EpochCounter(pub u32);

/// Certificate issued by master key to authorize a device.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceCertificate {
    pub device_id: DeviceId,
    /// Device's Ed25519 public key (used as iroh NodeId).
    pub device_pub_key: [u8; 32],
    pub issued_at: Timestamp,
    /// Ed25519 signature: master_key.sign(device_id || device_pub_key || issued_at_be)
    #[serde(with = "sig_serde")]
    pub signature: [u8; 64],
    /// Identity (master) pub key, so verifier knows who signed.
    pub master_pub_key: IdentityPub,
}

/// Certificate revoking a device key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    CertificateExpired { issued_at: Timestamp, now: Timestamp },

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

/// Derive device Ed25519 signing key from seed + device_id.
///
/// HKDF-SHA256(ikm=seed_bytes, salt=device_id.0, info=b"syncback-device-ed25519") → 32 bytes
pub fn derive_device_key(
    seed_bytes: &[u8],
    device_id: &DeviceId,
) -> Result<ed25519_dalek::SigningKey, ClusterError> {
    let hk = Hkdf::<Sha256>::new(Some(&device_id.0), seed_bytes);
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
    Ok(EpochKey { epoch, key_bytes: okm })
}

/// Extract IdentityPub from a master signing key.
pub fn master_identity(master_key: &ed25519_dalek::SigningKey) -> IdentityPub {
    IdentityPub(master_key.verifying_key().to_bytes())
}

// ============================================================
// Device certificates
// ============================================================

/// Issue a device certificate. Called when adding a new device.
///
/// Signed message: device_id.0 (16 bytes) || device_pub_key (32 bytes) || issued_at.0.to_be_bytes() (8 bytes)
pub fn issue_device_certificate(
    master_key: &ed25519_dalek::SigningKey,
    device_id: DeviceId,
    device_pub_key: [u8; 32],
    issued_at: Timestamp,
) -> DeviceCertificate {
    let payload = device_cert_payload(&device_id, &device_pub_key, issued_at);
    let sig = master_key.sign(&payload);
    DeviceCertificate {
        device_id,
        device_pub_key,
        issued_at,
        signature: sig.to_bytes(),
        master_pub_key: master_identity(master_key),
    }
}

/// Verify a device certificate.
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
    let payload = device_cert_payload(&cert.device_id, &cert.device_pub_key, cert.issued_at);
    verifying_key
        .verify(&payload, &sig)
        .map_err(|_| ClusterError::InvalidSignature)
}

fn device_cert_payload(
    device_id: &DeviceId,
    device_pub_key: &[u8; 32],
    issued_at: Timestamp,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(56);
    payload.extend_from_slice(&device_id.0);
    payload.extend_from_slice(device_pub_key);
    payload.extend_from_slice(&issued_at.0.to_be_bytes());
    payload
}

// ============================================================
// Revocation
// ============================================================

/// Issue a revocation certificate for a device.
///
/// Signed message: b"revoke" (6) || device_id.0 (16) || revoked_at.0.to_be_bytes() (8) || new_epoch.0.to_be_bytes() (4)
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
        .verify(&payload, &sig)
        .map_err(|_| ClusterError::InvalidSignature)
}

fn revocation_payload(
    device_id: &DeviceId,
    revoked_at: Timestamp,
    new_epoch: EpochCounter,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(34);
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
    (device_index as u32) << 20
}

/// ESI namespace end (exclusive) for a device index.
pub fn esi_namespace_end(device_index: u8) -> u32 {
    esi_namespace_start(device_index + 1)
}
