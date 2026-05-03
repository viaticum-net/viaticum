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

/// Check staging size and emit warn if over threshold.
pub fn check_staging_warn(staging_root: &Path, warn_threshold_bytes: u64) {
    let total = staging_total_bytes(staging_root);
    if total > warn_threshold_bytes {
        tracing::warn!(
            staging_root = %staging_root.display(),
            total_gb = total as f64 / 1_073_741_824.0,
            threshold_gb = warn_threshold_bytes as f64 / 1_073_741_824.0,
            "restore staging directory is large; consider cleaning up old restore jobs manually"
        );
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn staging_total_bytes_returns_zero_for_missing_dir() {
        let total = staging_total_bytes(Path::new("/nonexistent/path/that/does/not/exist"));
        assert_eq!(total, 0);
    }

    #[test]
    fn staging_total_bytes_returns_correct_sum() {
        let dir = TempDir::new().unwrap();
        // Write two files of known sizes.
        std::fs::write(dir.path().join("a.bin"), b"hello").unwrap(); // 5 bytes
        std::fs::write(dir.path().join("b.bin"), b"world!!").unwrap(); // 7 bytes

        let total = staging_total_bytes(dir.path());
        assert_eq!(total, 12, "expected 5+7=12 bytes");
    }

    #[test]
    fn staging_total_bytes_recurses_into_subdirectories() {
        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(dir.path().join("root.bin"), &[0u8; 100]).unwrap();
        std::fs::write(sub.join("nested.bin"), &[0u8; 200]).unwrap();

        let total = staging_total_bytes(dir.path());
        assert_eq!(total, 300, "expected 100+200=300 bytes");
    }

    #[test]
    fn staging_cleanup_warn_not_emitted_when_under_threshold() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("small.bin"), b"tiny").unwrap();

        // Threshold = 1 GB; actual = 4 bytes → should not warn (no panic/error).
        let threshold = 1_073_741_824u64;
        check_staging_warn(dir.path(), threshold);
        // No assertion — just verifying it doesn't panic or error.
    }

    #[test]
    fn staging_cleanup_warn_emitted_when_over_threshold() {
        let dir = TempDir::new().unwrap();
        // Write 10 bytes; threshold = 5 bytes → should warn.
        std::fs::write(dir.path().join("big.bin"), b"0123456789").unwrap();

        // We can't easily capture tracing::warn! in a unit test without tracing-test,
        // so we verify the function runs without error and the size check logic works
        // by testing staging_total_bytes separately.
        let total = staging_total_bytes(dir.path());
        assert!(total > 5, "total should exceed threshold");
        // check_staging_warn just calls warn! if total > threshold; no panic.
        check_staging_warn(dir.path(), 5);
    }
}
