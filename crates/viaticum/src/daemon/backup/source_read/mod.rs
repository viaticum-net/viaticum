// Bounded reads of a source file (backup-i5, J1): no path of the daemon reads more than
// `limit + 1` bytes from one source file. The size is judged by `metadata()` first, so a
// file above the limit is never opened; the read itself is capped too, so a file that grows
// during the read (or lies about its size) is cut at `limit + 1` bytes and refused.

use std::io::Read;
use std::path::Path;

/// Why a source file was not read.
#[derive(Debug, thiserror::Error)]
pub enum SourceReadError {
    /// The file is larger than the limit of this machine. `size` is the size `metadata`
    /// reported, or `limit + 1` when the file grew past the limit while it was being read.
    #[error("file is {size} bytes, limit on this machine is {limit}")]
    TooLarge { size: u64, limit: u64 },
    #[error("read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl SourceReadError {
    /// The file (or a directory on its path) does not exist.
    pub fn is_not_found(&self) -> bool {
        matches!(self, SourceReadError::Io { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound)
    }
}

/// True if any error in the chain is a NotFound `io::Error` or a `SourceReadError::Io`
/// carrying one. Callers wrap read errors in `anyhow` context, so a `downcast_ref` on the
/// outermost error would miss it; the chain is walked instead.
pub fn chain_is_not_found(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return io.kind() == std::io::ErrorKind::NotFound;
        }
        cause
            .downcast_ref::<SourceReadError>()
            .is_some_and(SourceReadError::is_not_found)
    })
}

/// The whole file, or an error.
///
/// 1) `metadata().len() > limit` → `TooLarge`, the file is not opened;
/// 2) otherwise at most `limit + 1` bytes are read into
///    `Vec::with_capacity(size + extra_capacity)`; more than `limit` → `TooLarge`.
///
/// `extra_capacity` is room the caller will append (the encryption tag, padding), so the
/// buffer is not reallocated (a reallocation of a big buffer is a second copy).
pub fn read_source_bounded(
    path: &Path,
    limit: u64,
    extra_capacity: usize,
) -> Result<Vec<u8>, SourceReadError> {
    let io = |source| SourceReadError::Io {
        path: path.display().to_string(),
        source,
    };
    let size = std::fs::metadata(path).map_err(io)?.len();
    if size > limit {
        return Err(SourceReadError::TooLarge { size, limit });
    }
    let file = std::fs::File::open(path).map_err(io)?;
    let capacity = usize::try_from(size)
        .unwrap_or(usize::MAX)
        .saturating_add(extra_capacity);
    read_at_most(file, limit, capacity).map_err(|e| match e {
        SourceReadError::Io { source, .. } => io(source),
        other => other,
    })
}

/// The size of `path` when it is above `limit` (`Some(size)`), else `None`. Reads nothing:
/// only `metadata`. An error (NotFound, permissions) is the caller's to interpret.
pub fn source_exceeds_limit(path: &Path, limit: u64) -> std::io::Result<Option<u64>> {
    let size = std::fs::metadata(path)?.len();
    Ok((size > limit).then_some(size))
}

/// Read `r` to its end, but never more than `limit + 1` bytes: a stream longer than
/// `limit` is `TooLarge { size: limit + 1, limit }`. The `Io` error it returns carries an
/// empty path (the caller knows the path).
fn read_at_most<R: Read>(r: R, limit: u64, cap: usize) -> Result<Vec<u8>, SourceReadError> {
    let mut buf = Vec::with_capacity(cap);
    r.take(limit.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|source| SourceReadError::Io {
            path: String::new(),
            source,
        })?;
    if buf.len() as u64 > limit {
        return Err(SourceReadError::TooLarge {
            size: limit.saturating_add(1),
            limit,
        });
    }
    Ok(buf)
}

#[cfg(test)]
mod tests;
