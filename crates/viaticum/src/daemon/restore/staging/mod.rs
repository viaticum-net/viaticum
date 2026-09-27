// StagingWriter: per-job restore staging directory using cap_std for O_NOFOLLOW
// sandboxing. Prevents symlink attacks and path traversal during file write.
//
// restore-i14: a restored file is never visible under its own name while it is
// incomplete. Bytes go to `<job>/.viaticum-partial/<uuid>` first (create_new,
// write, fsync), then it is published under the target name without ever replacing
// an existing file (publish.rs: hard link → renameat2 NOREPLACE → checked rename).
// A crash leaves at most a temp file in `.viaticum-partial/`, never a truncated
// file under the user's file name.
//
// Job directory layout:
//   <staging_root>/<job_id>/
//       .viaticum-job.json     job record (record.rs), rewritten atomically
//       .viaticum-partial/     temp files while they are being written
//       home/kolya/...         the user's files under their catalog paths

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use cap_std::fs::Dir;
use viaticum_core::path_safety::ValidatedPath;

pub mod publish;
pub mod record;

use publish::{PublishError, PublishMethod, publish_chain};

#[cfg(test)]
mod tests;

/// Directory inside a job dir that holds files still being written.
pub const PARTIAL_DIR_NAME: &str = ".viaticum-partial";
/// Job record file inside a job dir (restore-i14).
pub const JOB_RECORD_NAME: &str = ".viaticum-job.json";
/// Top-level names in a job dir that start with this prefix belong to the daemon,
/// not to the user's restored tree.
pub const SERVICE_NAME_PREFIX: &str = ".viaticum-";

/// True for a top-level job-dir entry the daemon owns (`.viaticum-*`).
pub fn is_service_name(top_level_name: &str) -> bool {
    top_level_name.starts_with(SERVICE_NAME_PREFIX)
}

// ─── JobId ────────────────────────────────────────────────────────────────────

/// Unique identifier for one restore job.
/// Generated as a UUID v4 at the start of each restore request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId(pub uuid::Uuid);

impl JobId {
    pub fn new() -> Self {
        JobId(uuid::Uuid::new_v4())
    }

    /// Parse the textual form (`Display`); `None` if it is not a UUID.
    pub fn parse(s: &str) -> Option<Self> {
        uuid::Uuid::parse_str(s).ok().map(JobId)
    }
}

impl serde::Serialize for JobId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for JobId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        JobId::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("invalid job id: {s}")))
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
    PathUnsafe(#[from] viaticum_core::path_safety::PathSafetyError),

    #[error("file already exists in staging: {0}")]
    AlreadyExists(PathBuf),

    /// The record path would land on a daemon-owned name in the job dir
    /// (`.viaticum-*` at the top level).
    #[error("path collides with a reserved staging name: {0}")]
    ReservedName(PathBuf),

    #[error("staging root is outside data_dir (possible symlink attack): {root:?}")]
    OutsideDataDir { root: PathBuf },

    /// No step of the publish chain (hard link, rename-noreplace, checked rename)
    /// works on the staging filesystem (restore-i19).
    #[error(
        "staging filesystem cannot publish complete files atomically ({0}); restore cannot write here"
    )]
    PublishUnsupported(std::io::Error),

    #[error("job record encode failed: {0}")]
    RecordEncode(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── StagedTemp ───────────────────────────────────────────────────────────────

/// A fully written and fsynced temp file inside `.viaticum-partial/`.
/// Dropping it without `commit` leaves the temp in place (as a crash would); the
/// target name is never touched by `stage_temp`.
#[derive(Debug)]
pub(crate) struct StagedTemp {
    /// Path relative to the job dir: `.viaticum-partial/<uuid>`.
    rel: PathBuf,
    /// File name inside `.viaticum-partial/` (the `<uuid>`).
    name: String,
}

impl StagedTemp {
    /// Relative path of the temp file inside the job dir.
    pub(crate) fn rel(&self) -> &Path {
        &self.rel
    }
}

/// A file made visible under its target name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    /// Absolute path of the file.
    pub path: PathBuf,
    /// The publish step that did it (restore-i19; `HardLink` on a normal filesystem).
    pub method: PublishMethod,
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
    /// First step of the publish chain to try (always `HardLink` in production;
    /// tests start later in the chain to exercise the fallbacks on a real FS).
    publish_start: PublishMethod,
}

impl StagingWriter {
    /// Open (or create) a per-job staging directory under `staging_root`.
    ///
    /// `staging_root` must be an absolute path (asserted). The function:
    /// 1. Canonicalizes `staging_root` and verifies it starts with `data_dir.canonicalize()`.
    /// 2. Creates `staging_root/<job_id>/` with mode 0o700 (Unix).
    /// 3. Opens it as a `cap_std::fs::Dir` and creates `.viaticum-partial/` (0o700).
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

        dir.create_dir_all(PARTIAL_DIR_NAME)?;
        #[cfg(unix)]
        {
            use cap_std::fs::PermissionsExt;
            dir.set_permissions(PARTIAL_DIR_NAME, cap_std::fs::Permissions::from_mode(0o700))?;
        }

        Ok(StagingWriter {
            dir,
            staging_path: job_dir,
            publish_start: PublishMethod::HardLink,
        })
    }

    /// Test seam: start the publish chain at `method` (skipping earlier steps).
    #[cfg(test)]
    pub(crate) fn with_publish_start(mut self, method: PublishMethod) -> Self {
        self.publish_start = method;
        self
    }

    /// Write `bytes` so that the target path either does not exist or holds the
    /// complete file (restore-i14). Fails with `AlreadyExists` if the target exists
    /// (create_new semantics, kept from the pre-B1 writer). On Unix the file is 0o600.
    ///
    /// Returns the absolute path of the written file for logging / API response.
    pub fn write_file(
        &self,
        validated: &ValidatedPath,
        bytes: &[u8],
    ) -> Result<PathBuf, StagingError> {
        self.write_file_published(validated, bytes).map(|p| p.path)
    }

    /// `write_file` that also says which publish step made the file visible.
    pub fn write_file_published(
        &self,
        validated: &ValidatedPath,
        bytes: &[u8],
    ) -> Result<Published, StagingError> {
        let mut src = bytes;
        self.write_file_from(validated, &mut src)
    }

    /// `write_file` over a byte source. A source that fails midway (the stand-in
    /// for disk-full or a crash in tests) leaves nothing under the target name.
    pub(crate) fn write_file_from(
        &self,
        validated: &ValidatedPath,
        src: &mut dyn Read,
    ) -> Result<Published, StagingError> {
        let rel = validated.to_relative_path();
        if validated
            .components
            .first()
            .is_some_and(|c| is_service_name(c))
        {
            return Err(StagingError::ReservedName(self.staging_path.join(&rel)));
        }
        let temp = self.stage_temp_from(src)?;
        self.commit(temp, validated)
    }

    /// Step 1 over a byte slice: see `stage_temp_from`.
    pub(crate) fn stage_temp(&self, bytes: &[u8]) -> Result<StagedTemp, StagingError> {
        let mut src = bytes;
        self.stage_temp_from(&mut src)
    }

    /// Step 1: create `.viaticum-partial/<uuid>` (create_new, 0o600), copy `src`
    /// into it and fsync. On error the temp is removed (best effort).
    pub(crate) fn stage_temp_from(&self, src: &mut dyn Read) -> Result<StagedTemp, StagingError> {
        let name = uuid::Uuid::new_v4().to_string();
        let rel = Path::new(PARTIAL_DIR_NAME).join(&name);
        let result = (|| -> std::io::Result<()> {
            let mut opts = cap_std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = self.dir.open_with(&rel, &opts)?;
            #[cfg(unix)]
            {
                // The umask can only clear bits; set the exact mode explicitly.
                use cap_std::fs::PermissionsExt;
                file.set_permissions(cap_std::fs::Permissions::from_mode(0o600))?;
            }
            std::io::copy(src, &mut file)?;
            file.flush()?;
            file.sync_all()
        })();
        match result {
            Ok(()) => Ok(StagedTemp { rel, name }),
            Err(e) => {
                let _ = self.dir.remove_file(&rel);
                Err(StagingError::Io(e))
            }
        }
    }

    /// Steps 2-4: create the target's parent dirs, publish the temp under the target
    /// name through the publish chain (hard link → rename-noreplace → checked rename;
    /// an existing target is never replaced), drop the temp name if it remains. On
    /// any error the temp is removed (best effort) and the target path is untouched.
    pub(crate) fn commit(
        &self,
        temp: StagedTemp,
        validated: &ValidatedPath,
    ) -> Result<Published, StagingError> {
        let rel = validated.to_relative_path();
        let result = self.publish(&temp, &rel);
        let temp_left = match &result {
            Ok(method) => method.keeps_temp_name(),
            Err(_) => true,
        };
        if temp_left && let Err(e) = self.dir.remove_file(temp.rel()) {
            tracing::warn!(
                temp = %self.staging_path.join(temp.rel()).display(),
                "staging: could not remove temp file: {e}"
            );
        }
        result.map(|method| Published {
            path: self.staging_path.join(&rel),
            method,
        })
    }

    fn publish(&self, temp: &StagedTemp, rel: &Path) -> Result<PublishMethod, StagingError> {
        let parent = rel.parent().filter(|p| !p.as_os_str().is_empty());
        if let Some(parent) = parent {
            self.dir.create_dir_all(parent)?;
        }
        // Single-name operations on cap-std handles: no path walk outside the sandbox.
        let to_dir = match parent {
            Some(parent) => self.dir.open_dir(parent)?,
            None => self.dir.try_clone()?,
        };
        let from_dir = self.dir.open_dir(PARTIAL_DIR_NAME)?;
        let to_name = rel
            .file_name()
            .map(Path::new)
            .expect("validated path has a final component");
        let from_name = Path::new(&temp.name);
        publish_chain(self.publish_start, |m| {
            publish::attempt(m, &from_dir, from_name, &to_dir, to_name)
        })
        .map_err(|e| match e {
            PublishError::Exists => StagingError::AlreadyExists(self.staging_path.join(rel)),
            PublishError::Failed(method, e) => StagingError::Io(std::io::Error::new(
                e.kind(),
                format!("publish via {}: {e}", method.as_str()),
            )),
            PublishError::NoneSupported(e) => StagingError::PublishUnsupported(e),
        })
    }

    /// Replace `.viaticum-job.json` atomically: temp in `.viaticum-partial/`, then
    /// rename over the record (overwrite is intended here).
    pub fn write_job_record(&self, record: &record::JobRecord) -> Result<(), StagingError> {
        let json = serde_json::to_vec_pretty(record)
            .map_err(|e| StagingError::RecordEncode(e.to_string()))?;
        let temp = self.stage_temp(&json)?;
        if let Err(e) = self.dir.rename(temp.rel(), &self.dir, JOB_RECORD_NAME) {
            let _ = self.dir.remove_file(temp.rel());
            return Err(StagingError::Io(e));
        }
        Ok(())
    }

    /// Absolute path to the job staging directory root.
    pub fn staging_path(&self) -> &Path {
        &self.staging_path
    }
}
