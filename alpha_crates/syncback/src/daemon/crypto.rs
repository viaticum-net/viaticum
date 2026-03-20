//! Shared cryptographic helpers used by packer and shard_manager.
//!
//! - HKDF-SHA256 key derivation (per unit_id)
//! - ChaCha20-Poly1305 encrypt / decrypt
//! - Reed-Solomon encode / decode

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::Sha256;

use syncback_core::types::UnitId;

// ============================================================
// Constants
// ============================================================

pub(crate) const FILE_ENCRYPTION_INFO: &[u8] = b"syncback-file-encryption";

// ============================================================
// Error
// ============================================================

#[derive(Debug, thiserror::Error)]
pub(crate) enum CryptoError {
    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("reed-solomon error: {0}")]
    ReedSolomon(String),

    #[error("not enough shards to decode: need {need}, have {have}")]
    NotEnoughShards { need: usize, have: usize },
}

// ============================================================
// Key derivation
// ============================================================

/// Derive the 32-byte encryption key for a unit.
///
/// HKDF-SHA256(ikm=identity_key_bytes, salt=unit_id.0, info="syncback-file-encryption")
pub(crate) fn derive_unit_key(identity_key_bytes: &[u8; 32], unit_id: UnitId) -> [u8; 32] {
    let salt = &unit_id.0;
    let hk = Hkdf::<Sha256>::new(Some(salt), identity_key_bytes);
    let mut key = [0u8; 32];
    hk.expand(FILE_ENCRYPTION_INFO, &mut key)
        .expect("HKDF expand: 32-byte output always valid");
    key
}

// ============================================================
// Symmetric encryption
// ============================================================

/// Encrypt plaintext with ChaCha20-Poly1305.
///
/// Output format: [12-byte random nonce][ciphertext + 16-byte tag]
pub(crate) fn encrypt_plaintext(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a ciphertext produced by `encrypt_plaintext`.
///
/// Input format: [12-byte nonce][ciphertext + 16-byte tag]
pub(crate) fn decrypt_ciphertext(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 12 {
        return Err(CryptoError::Encryption("ciphertext too short".into()));
    }
    let nonce_bytes: [u8; 12] = data[..12]
        .try_into()
        .expect("slice is exactly 12 bytes");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(nonce, &data[12..])
        .map_err(|e| CryptoError::Encryption(e.to_string()))
}

// ============================================================
// Reed-Solomon
// ============================================================

/// Encode `ciphertext` into n shards using Reed-Solomon (k data, n-k parity).
///
/// Prepends an 8-byte LE length prefix so that `rs_decode` can strip padding.
/// Returns exactly n shards, each of equal size.
pub(crate) fn rs_encode(ciphertext: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, CryptoError> {
    let r = ReedSolomon::new(k, n - k)
        .map_err(|e| CryptoError::ReedSolomon(e.to_string()))?;

    // Prefix with 8-byte LE length so rs_decode can strip zero padding.
    let orig_len = ciphertext.len() as u64;
    let mut data = Vec::with_capacity(8 + ciphertext.len());
    data.extend_from_slice(&orig_len.to_le_bytes());
    data.extend_from_slice(ciphertext);

    let shard_size = data.len().div_ceil(k);
    let padded_len = shard_size * k;
    data.resize(padded_len, 0u8);

    let mut shards: Vec<Vec<u8>> = data.chunks(shard_size).map(|s| s.to_vec()).collect();
    for _ in 0..(n - k) {
        shards.push(vec![0u8; shard_size]);
    }

    r.encode(&mut shards)
        .map_err(|e| CryptoError::ReedSolomon(e.to_string()))?;

    Ok(shards)
}

/// Decode shards back to ciphertext using Reed-Solomon reconstruction.
///
/// `shard_blobs`: exactly n entries, None for lost shards.
/// At least k must be Some. Strips the length prefix and zero padding added by `rs_encode`.
pub(crate) fn rs_decode(
    mut shard_blobs: Vec<Option<Vec<u8>>>,
    k: usize,
    n: usize,
) -> Result<Vec<u8>, CryptoError> {
    let have = shard_blobs.iter().filter(|s| s.is_some()).count();
    if have < k {
        return Err(CryptoError::NotEnoughShards { need: k, have });
    }

    let shard_size = shard_blobs
        .iter()
        .flatten()
        .map(|s| s.len())
        .next()
        .expect("at least k shards are Some");

    let r = ReedSolomon::new(k, n - k)
        .map_err(|e| CryptoError::ReedSolomon(e.to_string()))?;

    r.reconstruct(&mut shard_blobs)
        .map_err(|e| CryptoError::ReedSolomon(e.to_string()))?;

    // Concatenate only the k data shards.
    let mut data = Vec::with_capacity(shard_size * k);
    for shard in shard_blobs.into_iter().take(k) {
        data.extend_from_slice(&shard.expect("reconstruct filled all missing data shards"));
    }

    // Read the 8-byte LE length prefix and truncate to original ciphertext length.
    if data.len() < 8 {
        return Err(CryptoError::ReedSolomon("decoded data too short for length prefix".into()));
    }
    let orig_len = u64::from_le_bytes(
        data[..8].try_into().expect("slice is exactly 8 bytes"),
    ) as usize;
    if orig_len + 8 > data.len() {
        return Err(CryptoError::ReedSolomon("length prefix exceeds decoded data".into()));
    }
    Ok(data[8..8 + orig_len].to_vec())
}
