// Publishing a complete temp file under its target name (restore-i14, restore-i19).
//
// The chain, tried in order, each step only when the previous one is not supported
// by the staging filesystem:
//   1. hard_link              — refuses an existing target; the temp name is removed after;
//   2. renameat2(NOREPLACE)   — Linux (renameat2) and macOS (renameatx_np RENAME_EXCL);
//                               refuses an existing target atomically;
//   3. checked rename         — "target absent?" then rename. The check and the rename are
//                               two steps (TOCTOU). Inside the daemon nothing else writes
//                               this name in between: the restore coordinator runs jobs one
//                               at a time, and each job writes only into its own dir named
//                               by a unique JobId.
// "Create the target and write into it" is never a step: it leaves a truncated file
// under the real name after a crash (pre-mortem 11).
//
// A target that exists stops the chain at once (AlreadyExists): falling through to the
// next step would weaken the no-overwrite contract. A real error (EACCES, EIO, ENOSPC,
// ...) also stops it: only "this filesystem cannot do that" moves to the next step.

use std::io;
use std::path::Path;

use cap_std::fs::Dir;

/// How a complete temp file becomes visible under its target name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishMethod {
    HardLink,
    RenameNoReplace,
    CheckedRename,
}

impl PublishMethod {
    /// The chain, in the order it is tried.
    pub const CHAIN: [PublishMethod; 3] = [
        PublishMethod::HardLink,
        PublishMethod::RenameNoReplace,
        PublishMethod::CheckedRename,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            PublishMethod::HardLink => "hard_link",
            PublishMethod::RenameNoReplace => "rename_noreplace",
            PublishMethod::CheckedRename => "checked_rename",
        }
    }

    /// True if a successful publish leaves the temp name behind (it must be removed).
    pub(crate) fn keeps_temp_name(self) -> bool {
        self == PublishMethod::HardLink
    }
}

/// What one failed attempt means for the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptError {
    /// The target exists: stop, report AlreadyExists.
    Exists,
    /// The filesystem does not support this step: try the next one.
    Unsupported,
    /// A real error: stop, report it.
    Failed,
}

/// Classify an error from `method`. EACCES is a real error (permissions), never
/// "unsupported": distinguished by errno, not by `ErrorKind` (which maps both EPERM
/// and EACCES to PermissionDenied).
pub(crate) fn classify(method: PublishMethod, e: &io::Error) -> AttemptError {
    if e.kind() == io::ErrorKind::AlreadyExists {
        return AttemptError::Exists;
    }
    if e.kind() == io::ErrorKind::Unsupported {
        return AttemptError::Unsupported;
    }
    #[cfg(unix)]
    {
        let unsupported: &[i32] = match method {
            // FAT/exFAT: EPERM; some network filesystems: EOPNOTSUPP; ENOSYS / EXDEV
            // for exotic mounts.
            // ENOTSUP is EOPNOTSUPP on Linux but a distinct value on macOS.
            PublishMethod::HardLink => &[
                libc::EPERM,
                libc::EOPNOTSUPP,
                libc::ENOTSUP,
                libc::EXDEV,
                libc::ENOSYS,
            ],
            // renameat2 flags unknown to the filesystem: EINVAL; old kernel: ENOSYS;
            // macOS renameatx_np on a filesystem without RENAME_EXCL: ENOTSUP.
            PublishMethod::RenameNoReplace => &[
                libc::EINVAL,
                libc::ENOSYS,
                libc::EOPNOTSUPP,
                libc::ENOTSUP,
                libc::EXDEV,
            ],
            PublishMethod::CheckedRename => &[],
        };
        if let Some(code) = e.raw_os_error()
            && unsupported.contains(&code)
        {
            return AttemptError::Unsupported;
        }
    }
    #[cfg(not(unix))]
    let _ = method;
    AttemptError::Failed
}

/// Why the chain did not publish.
#[derive(Debug)]
pub(crate) enum PublishError {
    /// The target exists.
    Exists,
    /// `method` failed with a real error.
    Failed(PublishMethod, io::Error),
    /// No step of the chain is supported here; the last error is kept.
    NoneSupported(io::Error),
}

/// Walk the chain from `start`, calling `attempt` for each step.
/// Pure control flow: the filesystem work is in `attempt` (tests pass fakes).
pub(crate) fn publish_chain(
    start: PublishMethod,
    mut attempt: impl FnMut(PublishMethod) -> io::Result<()>,
) -> Result<PublishMethod, PublishError> {
    let mut last_unsupported: Option<io::Error> = None;
    for method in PublishMethod::CHAIN.into_iter().skip_while(|m| *m != start) {
        match attempt(method) {
            Ok(()) => return Ok(method),
            Err(e) => match classify(method, &e) {
                AttemptError::Exists => return Err(PublishError::Exists),
                AttemptError::Failed => return Err(PublishError::Failed(method, e)),
                AttemptError::Unsupported => {
                    tracing::debug!(method = method.as_str(), "staging: {e}; trying next");
                    last_unsupported = Some(e);
                }
            },
        }
    }
    Err(PublishError::NoneSupported(
        last_unsupported
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "empty publish chain")),
    ))
}

/// One real attempt: publish `from_dir/from` as `to_dir/to` (single names, no '/').
pub(crate) fn attempt(
    method: PublishMethod,
    from_dir: &Dir,
    from: &Path,
    to_dir: &Dir,
    to: &Path,
) -> io::Result<()> {
    match method {
        PublishMethod::HardLink => from_dir.hard_link(from, to_dir, to),
        PublishMethod::RenameNoReplace => rename_noreplace(from_dir, from, to_dir, to),
        PublishMethod::CheckedRename => match to_dir.symlink_metadata(to) {
            Ok(_) => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => from_dir.rename(from, to_dir, to),
            Err(e) => Err(e),
        },
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rename_noreplace(from_dir: &Dir, from: &Path, to_dir: &Dir, to: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        from_dir,
        from,
        to_dir,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_noreplace(_from_dir: &Dir, _from: &Path, _to_dir: &Dir, _to: &Path) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// Startup probe: which step of the chain works in `staging_root`. Creates and
/// removes two `.viaticum-probe-*` files at the staging root.
pub fn probe_publish(staging_root: &Path) -> Result<PublishMethod, io::Error> {
    probe_publish_with(staging_root, attempt)
}

/// `probe_publish` with the per-step attempt injected (tests fake a filesystem
/// that supports nothing).
pub(crate) fn probe_publish_with(
    staging_root: &Path,
    mut attempt_fn: impl FnMut(PublishMethod, &Dir, &Path, &Dir, &Path) -> io::Result<()>,
) -> Result<PublishMethod, io::Error> {
    let dir = Dir::open_ambient_dir(staging_root, cap_std::ambient_authority())?;
    let id = uuid::Uuid::new_v4();
    let from = format!(".viaticum-probe-{id}");
    let to = format!(".viaticum-probe-{id}.published");
    let mut opts = cap_std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    drop(dir.open_with(&from, &opts)?);
    let result = publish_chain(PublishMethod::HardLink, |m| {
        attempt_fn(m, &dir, Path::new(&from), &dir, Path::new(&to))
    });
    let _ = dir.remove_file(&from);
    let _ = dir.remove_file(&to);
    match result {
        Ok(m) => Ok(m),
        Err(PublishError::Exists) => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
        Err(PublishError::Failed(_, e)) | Err(PublishError::NoneSupported(e)) => Err(e),
    }
}
