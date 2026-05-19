// StagingWriter: per-job restore staging directory using cap_std for O_NOFOLLOW
// sandboxing. Prevents symlink attacks and path traversal during file write.

use std::path::{Path, PathBuf};

use cap_std::fs::Dir;
use syncback_core::path_safety::ValidatedPath;

// ─── JobId ────────────────────────────────────────────────────────────────────

/// Unique identifier for one restore job.
/// Generated as a UUID v4 at the start of each restore request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId(pub uuid::Uuid);

impl JobId {
    pub fn new() -> Self {
        JobId(uuid::Uuid::new_v4())
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// ─── StagingError ─────────────────────────────────────────────────────────────

/// Error type for staging write operations.
#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    #[error("path validation failed: {0}")]
    PathUnsafe(#[from] syncback_core::path_safety::PathSafetyError),

    #[error("file already exists in staging: {0}")]
    AlreadyExists(PathBuf),

    #[error("staging root is outside data_dir (possible symlink attack): {root:?}")]
    OutsideDataDir { root: PathBuf },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── StagingWriter ────────────────────────────────────────────────────────────

/// Per-job staging directory wrapper.
/// All writes go through cap_std::fs::Dir which enforces O_NOFOLLOW semantics
/// and prevents escape from the staging root.
#[derive(Debug)]
pub struct StagingWriter {
    /// cap_std directory handle rooted at the job staging directory.
    dir: Dir,
    /// The absolute path to the job staging directory (for logging and API responses).
    staging_path: PathBuf,
}

impl StagingWriter {
    /// Open (or create) a per-job staging directory under `staging_root`.
    ///
    /// `staging_root` must be an absolute path (asserted). The function:
    /// 1. Canonicalizes `staging_root` and verifies it starts with `data_dir.canonicalize()`.
    /// 2. Creates `staging_root/<job_id>/` with mode 0o700 (Unix).
    /// 3. Opens it as a `cap_std::fs::Dir`.
    ///
    /// # Errors
    /// - `OutsideDataDir`: staging_root (canonical) does not start with data_dir (canonical).
    /// - `Io`: directory creation failed.
    pub fn open(staging_root: &Path, data_dir: &Path, job_id: JobId) -> Result<Self, StagingError> {
        assert!(staging_root.is_absolute(), "staging_root must be absolute");

        // Guard: canonicalize both and check prefix.
        let canonical_root = staging_root.canonicalize()?;
        let canonical_data = data_dir.canonicalize()?;
        if !canonical_root.starts_with(&canonical_data) {
            return Err(StagingError::OutsideDataDir {
                root: canonical_root,
            });
        }

        let job_dir = staging_root.join(job_id.to_string());

        // Create with restricted permissions.
        std::fs::create_dir_all(&job_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&job_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        // Open through cap_std. This gives us O_NOFOLLOW-based sandboxing for all
        // subsequent operations rooted at job_dir.
        let ambient_authority = cap_std::ambient_authority();
        let dir = Dir::open_ambient_dir(&job_dir, ambient_authority)?;

        Ok(StagingWriter {
            dir,
            staging_path: job_dir,
        })
    }

    /// Write `bytes` to a file identified by `validated` within the staging directory.
    ///
    /// Creates parent directories as needed (via cap_std relative ops).
    /// Uses `OpenOptions::create_new(true)` — fails if the file already exists.
    /// On Unix, sets mode 0o600 after writing.
    ///
    /// Returns the absolute path of the written file for logging / API response.
    pub fn write_file(
        &self,
        validated: &ValidatedPath,
        bytes: &[u8],
    ) -> Result<PathBuf, StagingError> {
        let rel = validated.to_relative_path();

        // Create parent directories relative to the cap_std Dir.
        if let Some(parent) = rel.parent()
            && parent != std::path::Path::new("") {
                self.dir.create_dir_all(parent)?;
            }

        // Open with create_new — loud fail on collision.
        {
            use cap_std::fs::OpenOptions;
            use std::io::Write;
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            let mut file = self.dir.open_with(&rel, &opts).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    StagingError::AlreadyExists(self.staging_path.join(&rel))
                } else {
                    StagingError::Io(e)
                }
            })?;
            file.write_all(bytes)?;
        }

        // Set mode 0o600 on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let abs_path = self.staging_path.join(&rel);
            std::fs::set_permissions(&abs_path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(self.staging_path.join(rel))
    }

    /// Absolute path to the job staging directory root.
    pub fn staging_path(&self) -> &Path {
        &self.staging_path
    }
}
