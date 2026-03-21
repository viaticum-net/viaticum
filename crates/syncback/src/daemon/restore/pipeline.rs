// Restore pipeline helpers: decrypt_and_decompress, extract_from_pack, hex_encode.
//
// These are thin wrappers / re-exports from backup pipeline and packing,
// kept here so RestoreCoordinator has a clean local import path.

use syncback_core::types::FileId;

/// Decrypt and decompress a stored blob.
///
/// Input: `[12-byte nonce][ciphertext]`
/// Returns decompressed plaintext, or error if decryption or decompression fails.
pub use crate::daemon::backup::pipeline::decrypt_and_decompress;

/// Extract bytes for one file from a decoded pack plaintext.
///
/// The plaintext starts with `CBOR(Vec<PackEntry>)` followed by raw file bytes.
/// Returns `Ok(Some(bytes))` if found, `Ok(None)` if `file_id` not in pack.
pub fn extract_from_pack(
    plaintext: &[u8],
    file_id: FileId,
) -> anyhow::Result<Option<Vec<u8>>> {
    crate::daemon::backup::packing::extract_file_from_pack(plaintext, file_id)
}

/// Hex-encode bytes to lowercase string. Used for block_id directory names.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
