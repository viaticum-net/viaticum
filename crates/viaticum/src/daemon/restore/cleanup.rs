// Cleanup warning: walk staging_root, warn if total size exceeds threshold.
// Non-critical: read-only scan, errors are silently skipped at sub-dir level.
//
// Also: TTL-based deletion of stale staging directories. After a restore job
// completes, the staging dir is left for user to inspect/move files. Without
// cleanup, repeated restores accumulate copies indefinitely (S-5 finding).

use std::path::Path;
use std::time::{Duration, SystemTime};

/// Default TTL for staging directories: 7 days.
/// After this, the directory is deleted by `evict_stale_stagings`.
pub const STAGING_TTL_SECS: u64 = 7 * 24 * 3600;

/// Walk `staging_root` and return the total byte size of all files.
/// Non-critical: errors in sub-walks are silently skipped (just log at DEBUG).
pub fn staging_total_bytes(staging_root: &Path) -> u64 {
    let mut total = 0u64;
    if !staging_root.exists() {
        return 0;
    }
    walk_dir_size(staging_root, &mut total);
    total
}

fn walk_dir_size(dir: &Path, total: &mut u64) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::debug!(path = %dir.display(), "cleanup: read_dir error: {e}");
            return;
        }
    };
    for entry in rd.flatten() {
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk_dir_size(&entry.path(), total);
        } else {
            *total = total.saturating_add(meta.len());
        }
    }
}

/// Pure predicate: returns true if `used` exceeds `threshold`.
/// Extracted so tests can verify the warn decision without capturing tracing output.
pub fn should_warn(used: u64, threshold: u64) -> bool {
    used > threshold
}

/// Check staging size and emit warn if over threshold.
pub fn check_staging_warn(staging_root: &Path, warn_threshold_bytes: u64) {
    let total = staging_total_bytes(staging_root);
    if should_warn(total, warn_threshold_bytes) {
        tracing::warn!(
            staging_root = %staging_root.display(),
            total_gb = total as f64 / 1_073_741_824.0,
            threshold_gb = warn_threshold_bytes as f64 / 1_073_741_824.0,
            "restore staging directory is large; consider cleaning up old restore jobs manually"
        );
    }
}

/// Delete any staging subdirectory older than `ttl`. Returns the number of
/// directories deleted. Errors are logged but do not propagate — best-effort.
///
/// Age is determined by directory modified time (mtime); since StagingWriter
/// creates each subdir at job start and writes files into it, mtime tracks
/// last write activity. After job completes, mtime stops advancing.
pub fn evict_stale_stagings(staging_root: &Path, ttl: Duration) -> u64 {
    let mut evicted = 0u64;
    let rd = match std::fs::read_dir(staging_root) {
        Ok(rd) => rd,
        Err(_) => return 0,
    };
    let now = SystemTime::now();
    for entry in rd.flatten() {
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) if m.is_dir() => m,
            _ => continue,
        };
        let mtime = match meta.modified() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let age = match now.duration_since(mtime) {
            Ok(d) => d,
            Err(_) => continue, // mtime in future — skip
        };
        if age > ttl {
            match std::fs::remove_dir_all(&path) {
                Ok(_) => {
                    evicted += 1;
                    tracing::info!(
                        path = %path.display(),
                        age_days = age.as_secs() / 86400,
                        "cleanup: evicted stale staging dir"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        err = %e,
                        "cleanup: failed to remove stale staging dir"
                    );
                }
            }
        }
    }
    evicted
}
