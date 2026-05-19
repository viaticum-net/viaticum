// Restore pipeline helpers: decrypt_and_decompress, extract_from_pack.
//
// These are thin wrappers / re-exports from backup pipeline and packing,
// kept here so RestoreCoordinator has a clean local import path.

use syncback_core::types::FileId;

/// Re-export hex_encode from core types.
pub use syncback_core::types::hex_encode;

/// Decrypt and decompress a stored blob.
///
/// Input: `[12-byte nonce][ciphertext]`
/// Returns decompressed plaintext, or error if decryption or decompression fails.
pub use crate::daemon::backup::pipeline::decrypt_and_decompress;

/// Extract bytes for one file from a decoded pack plaintext.
///
/// The plaintext starts with `CBOR(Vec<PackEntry>)` followed by raw file bytes.
/// Returns `Ok(Some(bytes))` if found, `Ok(None)` if `file_id` not in pack.
pub fn extract_from_pack(plaintext: &[u8], file_id: FileId) -> anyhow::Result<Option<Vec<u8>>> {
    crate::daemon::backup::packing::extract_file_from_pack(plaintext, file_id)
}
