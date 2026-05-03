// Cleanup warning: walk staging_root, warn if total size exceeds threshold.
// Non-critical: read-only scan, errors are silently skipped at sub-dir level.

use std::path::Path;

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
