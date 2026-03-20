# Task: cluster — Personal Cluster (β)

Module: `crates/syncback-core/src/cluster/`
Files: `mod.rs` + `tests.rs`

---

## Overview

Модуль управления ключами кластера. Чистая логика (ключи, сертификаты, эпохи) — без сети, без DB, без async.

**Что делает:**
1. Иерархия ключей: seed phrase → master key → device keys → epoch keys.
2. Device certificates: master key подписывает device pub key.
3. Revocation certificates: master key подписывает отзыв device key.
4. Epoch rotation: epoch_counter → epoch_key via HKDF.
5. Верификация сертификатов (используется peer'ами при handshake).

**Что НЕ делает:**
- Не хранит state (caller хранит в DB или файлах).
- Не делает сеть (gossip revocation — задача daemon layer).
- Не синхронизирует cluster state между устройствами.

---

## Dependencies

Crate `syncback-core/Cargo.toml` additions:
```toml
ed25519-dalek = { version = "2", features = ["rand_core"] }
hkdf = "0.12"
sha2 = "0.10"
```

- `crate::types::{IdentityPub, DeviceId, Timestamp}`
- `ed25519_dalek::{SigningKey, VerifyingKey, Signature}`
- `hkdf::Hkdf`
- `sha2::Sha256`
- No DB. No async. Pure logic.

---

## Key Hierarchy

```
Seed phrase (BIP39, 24 words)
│
├── Master signing key (Ed25519)
│   IdentityPub = master_key.verifying_key()
│   Derived: HKDF-SHA256(ikm=seed_bytes, salt=b"", info=b"syncback-identity-ed25519") → 32 bytes → Ed25519 key
│
├── Device key N (Ed25519)
│   Derived: HKDF-SHA256(ikm=seed_bytes, salt=device_id.0, info=b"syncback-device-ed25519") → 32 bytes → Ed25519 key
│
└── Epoch key N (ChaCha20-Poly1305 symmetric key)
    Derived: HKDF-SHA256(ikm=seed_bytes, salt=epoch_counter.to_be_bytes(), info=b"syncback-encryption") → 32 bytes
```

The device key derivation uses `device_id` as the HKDF salt, making each device's key unique and independent.

---

## Types

```rust
/// Counter for epoch rotation. Starts at 0; incremented on device revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct EpochCounter(pub u32);

/// Certificate issued by master key to authorize a device.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceCertificate {
    /// Device being authorized.
    pub device_id: DeviceId,
    /// Device's Ed25519 public key (used as iroh NodeId).
    pub device_pub_key: [u8; 32],
    /// When this certificate was issued.
    pub issued_at: Timestamp,
    /// Ed25519 signature: master_key.sign(device_id || device_pub_key || issued_at_be)
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
```

---

## Public API

```rust
// ============================================================
// Key derivation (from raw seed bytes)
// ============================================================

/// Derive master Ed25519 signing key from raw seed bytes.
/// seed_bytes: 32-64 bytes of entropy from BIP39 mnemonic.
///
/// HKDF-SHA256(ikm=seed_bytes, salt=b"", info=b"syncback-identity-ed25519") → 32 bytes
/// → Ed25519 signing key (deterministic)
pub fn derive_master_key(seed_bytes: &[u8]) -> Result<ed25519_dalek::SigningKey, ClusterError>;

/// Derive device Ed25519 signing key from seed + device_id.
///
/// HKDF-SHA256(ikm=seed_bytes, salt=device_id.0, info=b"syncback-device-ed25519") → 32 bytes
pub fn derive_device_key(
    seed_bytes: &[u8],
    device_id: &DeviceId,
) -> Result<ed25519_dalek::SigningKey, ClusterError>;

/// Derive epoch encryption key.
///
/// HKDF-SHA256(ikm=seed_bytes, salt=epoch.0.to_be_bytes(), info=b"syncback-encryption") → 32 bytes
pub fn derive_epoch_key(seed_bytes: &[u8], epoch: EpochCounter) -> Result<EpochKey, ClusterError>;

/// Extract IdentityPub from a master signing key.
pub fn master_identity(master_key: &ed25519_dalek::SigningKey) -> IdentityPub {
    IdentityPub(master_key.verifying_key().to_bytes())
}

// ============================================================
// Device certificates
// ============================================================

/// Issue a device certificate. Called when adding a new device.
///
/// Signed message: device_id.0 || device_pub_key || issued_at.0.to_be_bytes()
pub fn issue_device_certificate(
    master_key: &ed25519_dalek::SigningKey,
    device_id: DeviceId,
    device_pub_key: [u8; 32],
    issued_at: Timestamp,
) -> DeviceCertificate;

/// Verify a device certificate.
/// Returns Ok(()) if valid, Err otherwise.
///
/// Checks: 1) signature valid, 2) master_pub_key matches expected identity.
pub fn verify_device_certificate(
    cert: &DeviceCertificate,
    expected_master: &IdentityPub,
) -> Result<(), ClusterError>;

// ============================================================
// Revocation
// ============================================================

/// Issue a revocation certificate for a device.
///
/// Signed message: b"revoke" || device_id.0 || revoked_at.0.to_be_bytes() || new_epoch.0.to_be_bytes()
pub fn issue_revocation(
    master_key: &ed25519_dalek::SigningKey,
    device_id: DeviceId,
    revoked_at: Timestamp,
    new_epoch: EpochCounter,
) -> RevocationCertificate;

/// Verify a revocation certificate.
pub fn verify_revocation(
    cert: &RevocationCertificate,
    expected_master: &IdentityPub,
) -> Result<(), ClusterError>;

// ============================================================
// Epoch management
// ============================================================

/// Compute the next epoch counter (after revocation).
pub fn next_epoch(current: EpochCounter) -> EpochCounter {
    EpochCounter(current.0 + 1)
}

/// Determine which epoch key was used to encrypt a file created at `created_at`.
/// Given the list of epoch rotation timestamps, returns the epoch that was current at that time.
///
/// epoch_history: Vec<(EpochCounter, activated_at: Timestamp)> sorted by activated_at ascending.
/// Returns the epoch counter that was active when the file was created.
pub fn epoch_for_time(
    epoch_history: &[(EpochCounter, Timestamp)],
    created_at: Timestamp,
) -> EpochCounter;

// ============================================================
// ESI namespace allocation (for multi-device ESI coordination)
// ============================================================

/// Compute the ESI namespace start for a device index.
/// ESI = device_index * 2^20 + local_counter.
///
/// device_index: 0-based index of this device in the cluster (by registration order).
/// Max 16 devices (ESI space = 2^24, 2^20 per device).
pub fn esi_namespace_start(device_index: u8) -> u32 {
    (device_index as u32) << 20
}

/// ESI namespace end (exclusive) for a device index.
pub fn esi_namespace_end(device_index: u8) -> u32 {
    esi_namespace_start(device_index + 1)
}
```

---

## Business Rules

### Key derivation

All derivations use HKDF-SHA256 with domain-separated `info` strings:

| Key | IKM | Salt | Info |
|-----|-----|------|------|
| master | seed_bytes | b"" | b"syncback-identity-ed25519" |
| device | seed_bytes | device_id.0 | b"syncback-device-ed25519" |
| epoch | seed_bytes | epoch.0.to_be_bytes() | b"syncback-encryption" |

Output: always 32 bytes. Used directly as Ed25519 seed or ChaCha20 key.

Caller derives the Ed25519 `SigningKey` from 32 raw bytes using `ed25519_dalek::SigningKey::from_bytes(&[u8;32])`.

### Certificate signing

For `DeviceCertificate`, the signed payload is:
```
device_id.0 (16 bytes) || device_pub_key (32 bytes) || issued_at.0.to_be_bytes() (8 bytes)
= 56 bytes total
```

For `RevocationCertificate`, the signed payload is:
```
b"revoke" (6 bytes) || device_id.0 (16 bytes) || revoked_at.0.to_be_bytes() (8 bytes) || new_epoch.0.to_be_bytes() (4 bytes)
= 34 bytes total
```

Use `master_key.sign(payload)` from `ed25519_dalek`. Signature is 64 bytes.

### Certificate verification

Verifier has the master `IdentityPub` from the handshake. Steps:
1. Reconstruct the signed payload (same bytes as above).
2. `VerifyingKey::from_bytes(&cert.master_pub_key.0)` → verify signature.
3. Check `cert.master_pub_key == expected_master`.

### Epoch for time

Given a sorted list of `(epoch_counter, activated_at)` pairs:
```
epoch_history = [(0, T_genesis), (1, T_rotation1), (2, T_rotation2)]

epoch_for_time(epoch_history, created_at):
  Find last entry where entry.activated_at <= created_at
  Return its epoch_counter
  If none (created_at before genesis): return EpochCounter(0)
```

### ESI namespace

Each device gets `2^20 = 1,048,576` ESIs. With 2^24 total RaptorQ ESI space, supports up to 16 devices.

`device_index` is the zero-based index of the device sorted by registration `issued_at` timestamp (or by any stable ordering the caller establishes).

---

## Test Scenarios

Tests in `cluster/tests.rs`.

### 1. `derive_master_key_is_deterministic`

```
seed = [0u8; 32]
key1 = derive_master_key(&seed)
key2 = derive_master_key(&seed)
key1.to_bytes() == key2.to_bytes()
```

### 2. `derive_device_key_differs_from_master`

```
seed = [1u8; 32]
master = derive_master_key(&seed)
device_id = DeviceId([2u8; 16])
device = derive_device_key(&seed, &device_id)
master.to_bytes() != device.to_bytes()
```

### 3. `derive_device_key_differs_per_device`

```
Same seed. Two different device_ids.
device_key_A.to_bytes() != device_key_B.to_bytes()
```

### 4. `derive_epoch_key_differs_per_epoch`

```
epoch_0 = derive_epoch_key(&seed, EpochCounter(0))
epoch_1 = derive_epoch_key(&seed, EpochCounter(1))
epoch_0.key_bytes != epoch_1.key_bytes
```

### 5. `master_identity_round_trip`

```
seed = [5u8; 32]
master_key = derive_master_key(&seed)
identity = master_identity(&master_key)
identity.0 == master_key.verifying_key().to_bytes()
```

### 6. `issue_and_verify_device_certificate`

```
master_key = derive_master_key(&[1u8;32])
device_id = DeviceId([3u8;16])
device_pub = [4u8;32]
cert = issue_device_certificate(&master_key, device_id, device_pub, Timestamp(1000))

verify_device_certificate(&cert, &master_identity(&master_key)) == Ok(())
```

### 7. `verify_certificate_with_wrong_master_fails`

```
cert issued by master_A
verify with master_B (different key)
→ Err(ClusterError::InvalidSignature)
```

### 8. `verify_certificate_tampered_signature_fails`

```
cert = issue_device_certificate(...)
cert.signature[0] ^= 1;   // flip one bit
verify_device_certificate(&cert, ...) → Err(InvalidSignature)
```

### 9. `verify_certificate_tampered_device_id_fails`

```
cert.device_id = DeviceId([0xFF; 16])  // change device_id after signing
verify_device_certificate → Err(InvalidSignature)  (signature covers device_id)
```

### 10. `issue_and_verify_revocation`

```
master_key = ...
cert = issue_revocation(&master_key, device_id, Timestamp(5000), EpochCounter(1))
verify_revocation(&cert, &master_identity(&master_key)) == Ok(())
```

### 11. `tampered_revocation_fails`

```
cert.new_epoch.0 += 1  // change epoch after signing
verify_revocation → Err(InvalidSignature)
```

### 12. `epoch_for_time_basic`

```
epoch_history = [(EpochCounter(0), T(0)), (EpochCounter(1), T(1000)), (EpochCounter(2), T(2000))]

epoch_for_time(history, T(0))    == EpochCounter(0)
epoch_for_time(history, T(500))  == EpochCounter(0)
epoch_for_time(history, T(1000)) == EpochCounter(1)
epoch_for_time(history, T(1500)) == EpochCounter(1)
epoch_for_time(history, T(2000)) == EpochCounter(2)
epoch_for_time(history, T(9999)) == EpochCounter(2)
```

### 13. `epoch_for_time_before_genesis`

```
epoch_history = [(EpochCounter(0), T(100))]
epoch_for_time(history, T(50)) == EpochCounter(0)  // before genesis → return first epoch
```

### 14. `esi_namespace_no_overlap`

```
device 0: [0, 2^20)
device 1: [2^20, 2*2^20)
device 15: [15*2^20, 16*2^20)

No two devices share an ESI.
esi_namespace_start(0) == 0
esi_namespace_start(1) == 1_048_576
esi_namespace_end(0) == esi_namespace_start(1)
```

### 15. `full_cluster_flow`

```
1. derive master key from seed
2. issue device cert for device A
3. issue device cert for device B
4. verify both certs
5. issue revocation for device A, new epoch = 1
6. verify revocation
7. derive epoch_key(0) and epoch_key(1) — they differ
8. Simulate: files before revocation use epoch 0, after revocation use epoch 1
```

---

## Notes

- The `ed25519_dalek` crate v2 uses `SigningKey` (renamed from `Keypair` in v1). Implementer must check the version in use.
- `SigningKey::from_bytes(&[u8;32])` expects the 32-byte seed, not the full 64-byte keypair.
- HKDF output length: `Hkdf::<Sha256>::new(salt, ikm).expand(info, &mut output)` — output must be 32 bytes.
- Seed bytes passed to derivation functions are the raw entropy bytes, NOT the BIP39 mnemonic (BIP39 → entropy conversion is done at a higher layer, not in this module).
- This module does NOT handle seed storage. Caller decides whether to store seed or only derived keys.
