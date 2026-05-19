// Board file I/O: load, append, rewrite.
//
// Format: sequence of length-prefixed CBOR entries.
//   [u32 BE length][CBOR(StoredEntry)] [u32 BE length][CBOR(StoredEntry)] ...
//
// On load:  read entries sequentially until EOF, skip corrupted trailing data.
// On append: open in append mode, write one record.
// On prune:  write to a temp file adjacent to board_path, then rename (atomic).

use std::io::{self, Write};
use std::path::Path;

use syncback_core::messages::{StoredEntry, from_cbor, to_cbor};
use tracing::warn;

/// Load all entries from the board file.
///
/// Returns an empty `Vec` if the file does not exist.
/// Corrupted trailing data (e.g. from a crash during append) is silently
/// discarded; fully-read entries before the corruption are returned.
pub fn load_board(path: &Path) -> io::Result<Vec<StoredEntry>> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut entries = Vec::new();
    let mut pos = 0usize;

    while pos + 4 <= data.len() {
        let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        let start = pos + 4;
        let end = start + len;

        if end > data.len() {
            // Truncated record — stop here (crash during append).
            warn!(
                board = %path.display(),
                pos,
                declared_len = len,
                available = data.len() - start,
                "truncated board record, stopping load"
            );
            break;
        }

        match from_cbor::<StoredEntry>(&data[start..end]) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                warn!(
                    board = %path.display(),
                    index = entries.len(),
                    err = %e,
                    "corrupt board record, stopping load"
                );
                break;
            }
        }

        pos = end;
    }

    Ok(entries)
}

/// Append a single entry to the board file.
///
/// Opens the file in append mode (creates if absent).
pub fn append_entry(path: &Path, entry: &StoredEntry) -> io::Result<()> {
    let cbor =
        to_cbor(entry).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let len = cbor.len() as u32;
    let len_bytes = len.to_be_bytes();

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    file.write_all(&len_bytes)?;
    file.write_all(&cbor)?;
    file.flush()?;
    Ok(())
}

/// Rewrite the board file atomically with the given entries.
///
/// Writes to `<path>.tmp` then renames to `path`. This prevents data loss if
/// the process is killed during the rewrite.
pub fn rewrite_board(path: &Path, entries: &[StoredEntry]) -> io::Result<()> {
    let tmp_path = {
        let mut p = path.to_path_buf();
        let name = p
            .file_name()
            .map(|n| format!("{}.tmp", n.to_string_lossy()))
            .unwrap_or_else(|| "board.tmp".to_string());
        p.set_file_name(name);
        p
    };

    // Write all entries to the temp file.
    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;

        for entry in entries {
            let cbor = to_cbor(entry)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let len = cbor.len() as u32;
            file.write_all(&len.to_be_bytes())?;
            file.write_all(&cbor)?;
        }

        file.flush()?;
    }

    // Atomic rename.
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Compute the approximate serialized byte size of an entry (CBOR + 4-byte prefix).
pub fn entry_size_bytes(entry: &StoredEntry) -> usize {
    // Approximate: payload + overhead. Use to_cbor for exact, but that's
    // expensive in a hot loop. Add a fixed overhead of 200 bytes for CBOR
    // field names and entry metadata, plus the actual payload size.
    4 + entry.entry.payload.len() + 256
}
