// Restore pipeline helpers: decrypt_and_decompress, extract_from_pack.
//
// These are thin wrappers / re-exports from backup pipeline and packing,
// kept here so RestoreCoordinator has a clean local import path.

use viaticum_core::types::FileId;

/// Re-export hex_encode from core types.
pub use viaticum_core::types::hex_encode;

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

/// The bytes of the pack member a record's version holds (restore-i38).
///
/// By `file_id` first, kept only when its bytes hash to `content_hash`; otherwise the
/// member whose bytes have that hash — a renamed, copied or swapped path points at a
/// member packed under another `file_id`, or its own member now holds another path's
/// content. `Ok(None)`: no member has that content.
pub fn extract_member(
    plaintext: &[u8],
    file_id: FileId,
    content_hash: &[u8; 32],
) -> anyhow::Result<Option<Vec<u8>>> {
    if let Some(bytes) = extract_from_pack(plaintext, file_id)?
        && blake3::hash(&bytes).as_bytes() == content_hash
    {
        return Ok(Some(bytes));
    }
    crate::daemon::backup::packing::extract_pack_entry_by_hash(plaintext, content_hash)
}
