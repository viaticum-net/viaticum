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
/// Returns `Ok(Some(bytes))` if found, `Ok(None)` if `file_id` not in pack. The bytes are a
/// slice of `plaintext` (К-b3: no copy of the member).
pub fn extract_from_pack(plaintext: &[u8], file_id: FileId) -> anyhow::Result<Option<&[u8]>> {
    crate::daemon::backup::packing::extract_file_from_pack(plaintext, file_id)
}

/// The bytes of the pack member a record's version holds (restore-i38).
///
/// By `file_id` first, kept only when its bytes hash to `content_hash`; otherwise the
/// member whose bytes have that hash — a renamed, copied or swapped path points at a
/// member packed under another `file_id`, or its own member now holds another path's
/// content. No member has that hash: the `file_id` member after all, with a WARN — a
/// catalog from before L1 may record the hash of the file at enqueue while the pack holds
/// the bytes of the flush (restore-i38 boundary; the block itself is already verified).
/// `Ok(None)`: neither.
pub fn extract_member<'a>(
    plaintext: &'a [u8],
    file_id: FileId,
    content_hash: &[u8; 32],
) -> anyhow::Result<Option<&'a [u8]>> {
    let own = extract_from_pack(plaintext, file_id)?;
    if let Some(bytes) = &own
        && blake3::hash(bytes).as_bytes() == content_hash
    {
        return Ok(own);
    }
    if let Some(bytes) =
        crate::daemon::backup::packing::extract_pack_entry_by_hash(plaintext, content_hash)?
    {
        return Ok(Some(bytes));
    }
    if own.is_some() {
        tracing::warn!(
            file_id = %file_id,
            "restore: no pack member has the version's content hash; using the member \
             packed under its file_id (a catalog from before L1)"
        );
    }
    Ok(own)
}
