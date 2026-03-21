// Pack format: build plaintext index + file bytes, parse it back.
// plaintext = cbor_serialize(Vec<PackEntry>) + [file1_bytes] + [file2_bytes] + ...
// PackEntry.offset is relative to the first byte AFTER the CBOR index.

use syncback_core::types::{from_cbor_bytes, to_cbor_bytes, FileId, PackEntry};

use super::QueuedFile;

/// Build the plaintext for a pack source block.
///
/// Format: `[CBOR(Vec<PackEntry>)] [file1_bytes] [file2_bytes] ...`
///
/// `files` is a slice of (QueuedFile, raw bytes) pairs.
/// Returns the complete plaintext to be compressed and encrypted.
pub fn build_plaintext(files: &[(QueuedFile, Vec<u8>)]) -> Vec<u8> {
    let mut entries = Vec::with_capacity(files.len());
    let mut offset = 0u64;
    for (qf, bytes) in files {
        entries.push(PackEntry {
            file_id: qf.file_id,
            offset,
            size: bytes.len() as u64,
        });
        offset += bytes.len() as u64;
    }

    let index_bytes = to_cbor_bytes(&entries);

    let mut plaintext = index_bytes;
    for (_, bytes) in files {
        plaintext.extend_from_slice(bytes);
    }
    plaintext
}

/// Result of parsing a pack index.
pub struct ParsedPack {
    /// Number of bytes consumed by the CBOR index.
    pub index_len: usize,
    pub entries: Vec<PackEntry>,
}

/// Parse CBOR PackIndex from the start of `data`. Does not read file bytes.
///
/// Returns `ParsedPack` with the index length (for caller to slice file data).
pub fn parse_pack_index(data: &[u8]) -> anyhow::Result<ParsedPack> {
    // ciborium is self-delimiting: we need to track how many bytes it consumed.
    // We wrap in a counting reader.
    let mut cursor = std::io::Cursor::new(data);
    let entries: Vec<PackEntry> = ciborium::de::from_reader(&mut cursor)
        .map_err(|e| anyhow::anyhow!("cbor decode PackIndex: {e}"))?;
    let index_len = cursor.position() as usize;
    Ok(ParsedPack { index_len, entries })
}

/// Extract file bytes for a given FileId from decoded (decrypted + decompressed) plaintext.
///
/// Returns `None` if `file_id` is not found in the pack.
pub fn extract_file_from_pack(plaintext: &[u8], file_id: FileId) -> anyhow::Result<Option<Vec<u8>>> {
    let parsed = parse_pack_index(plaintext)?;
    let file_data_start = parsed.index_len;
    let file_data = &plaintext[file_data_start..];

    for entry in &parsed.entries {
        if entry.file_id == file_id {
            let start = entry.offset as usize;
            let end = start + entry.size as usize;
            if end > file_data.len() {
                return Err(anyhow::anyhow!(
                    "pack entry out of bounds: file_id={}, offset={}, size={}",
                    entry.file_id,
                    entry.offset,
                    entry.size
                ));
            }
            return Ok(Some(file_data[start..end].to_vec()));
        }
    }
    Ok(None)
}

/// Serialize PackEntry list using CBOR. Used by RestoreCoordinator.
pub fn serialize_pack_index(entries: &[PackEntry]) -> Vec<u8> {
    let v = entries.to_vec();
    to_cbor_bytes(&v)
}

/// Deserialize PackEntry list from CBOR bytes.
pub fn deserialize_pack_index(bytes: &[u8]) -> anyhow::Result<Vec<PackEntry>> {
    from_cbor_bytes(bytes).map_err(|e| anyhow::anyhow!("cbor decode: {e}"))
}
