// Tests for the staging writer (restore-i14 atomic writes), the job record and the
// read-only staging scan. Pattern: what_when_then. Real files in tempdirs.

use std::io::Read;
use std::path::Path;

use tempfile::TempDir;
use viaticum_core::path_safety::validate_record_path;

use super::publish::PublishMethod;
use super::record::{
    JobFailure, JobOutcome, JobRecord, JobState, RecordStatus, read_job_record, scan_staging,
};
use super::{JOB_RECORD_NAME, JobId, PARTIAL_DIR_NAME, StagingError, StagingWriter};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// A `data_dir` with `restore/` inside, and an open writer for a fresh job.
fn open_job() -> (TempDir, StagingWriter) {
    let data_dir = TempDir::new().unwrap();
    let staging_root = data_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).unwrap();
    let writer = StagingWriter::open(&staging_root, data_dir.path(), JobId::new()).unwrap();
    (data_dir, writer)
}

fn partial_entries(writer: &StagingWriter) -> Vec<String> {
    std::fs::read_dir(writer.staging_path().join(PARTIAL_DIR_NAME))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

/// Byte source that yields `ok_bytes` bytes and then fails: the stand-in for a
/// disk-full error or a crash in the middle of writing one file.
struct FailAfter {
    ok_bytes: usize,
}

impl Read for FailAfter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.ok_bytes == 0 {
            return Err(std::io::Error::other("simulated failure mid-write"));
        }
        let n = buf.len().min(self.ok_bytes);
        buf[..n].fill(0xAB);
        self.ok_bytes -= n;
        Ok(n)
    }
}

fn record(state: JobState, outcome: Option<JobOutcome>) -> JobRecord {
    JobRecord {
        job_id: JobId::new(),
        path: "/home/kolya/photos/".to_string(),
        state,
        files_total: 3,
        files_restored: 2,
        restored_paths: vec![
            "/home/kolya/photos/a.jpg".into(),
            "/home/kolya/photos/b.jpg".into(),
        ],
        failures: vec![JobFailure {
            path: "/home/kolya/photos/c.jpg".into(),
            detail: "insufficient symbols".into(),
        }],
        outcome,
        started_at: 1_000,
        finished_at: outcome.map(|_| 2_000),
    }
}

// ─── Existing StagingWriter tests ─────────────────────────────────────────────

/// G1: staging writer creates file at the correct relative path.
#[test]
fn staging_writer_creates_file_at_correct_path() {
    let data_dir = TempDir::new().unwrap();
    let staging_root = data_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).unwrap();

    let job_id = JobId::new();
    let writer = StagingWriter::open(&staging_root, data_dir.path(), job_id).unwrap();

    let validated = validate_record_path("home/alice/docs/report.docx").unwrap();
    let out = writer.write_file(&validated, b"report content").unwrap();

    // File must exist at the returned path.
    assert!(out.exists(), "file must exist at {out:?}");
    let content = std::fs::read(&out).unwrap();
    assert_eq!(content, b"report content");

    // Path must be rooted in staging_path.
    assert!(
        out.starts_with(writer.staging_path()),
        "file must be inside staging dir"
    );
}

/// Basic open test: job dir is created.
#[test]
fn staging_writer_open_creates_job_dir() {
    let data_dir = TempDir::new().unwrap();
    let staging_root = data_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).unwrap();

    let job_id = JobId::new();
    let writer = StagingWriter::open(&staging_root, data_dir.path(), job_id).unwrap();

    assert!(
        writer.staging_path().is_dir(),
        "job staging dir must exist: {:?}",
        writer.staging_path()
    );
    // Job dir name must be the UUID string.
    let dir_name = writer.staging_path().file_name().unwrap().to_string_lossy();
    assert_eq!(
        dir_name,
        job_id.to_string(),
        "job dir name must be the UUID"
    );
}

/// Mode 0o600 on written files (Unix only).
#[cfg(unix)]
#[test]
fn staging_writer_mode_is_600_on_unix() {
    use std::os::unix::fs::PermissionsExt;

    let data_dir = TempDir::new().unwrap();
    let staging_root = data_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).unwrap();

    let writer = StagingWriter::open(&staging_root, data_dir.path(), JobId::new()).unwrap();
    let validated = validate_record_path("secret.txt").unwrap();
    let out = writer.write_file(&validated, b"secret").unwrap();

    let meta = std::fs::metadata(&out).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "file mode must be 0o600, got {:o}", mode);
}

/// Mode 0o700 on job staging directory (Unix only).
#[cfg(unix)]
#[test]
fn staging_writer_job_dir_mode_is_700_on_unix() {
    use std::os::unix::fs::PermissionsExt;

    let data_dir = TempDir::new().unwrap();
    let staging_root = data_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).unwrap();

    let writer = StagingWriter::open(&staging_root, data_dir.path(), JobId::new()).unwrap();

    let meta = std::fs::metadata(writer.staging_path()).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "job dir mode must be 0o700, got {:o}", mode);
}

/// C1: Writing the same path twice in the same job fails on the second attempt.
#[test]
fn write_twice_same_path_fails_second() {
    let data_dir = TempDir::new().unwrap();
    let staging_root = data_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).unwrap();

    let writer = StagingWriter::open(&staging_root, data_dir.path(), JobId::new()).unwrap();
    let validated = validate_record_path("docs/file.txt").unwrap();

    // First write succeeds.
    writer.write_file(&validated, b"first content").unwrap();

    // Second write fails with AlreadyExists.
    let result = writer.write_file(&validated, b"second content");
    assert!(
        matches!(result, Err(StagingError::AlreadyExists(_))),
        "second write must fail with AlreadyExists, got: {result:?}"
    );

    // First file must be intact.
    let out_path = writer.staging_path().join(validated.to_relative_path());
    let content = std::fs::read(&out_path).unwrap();
    assert_eq!(content, b"first content", "first file must remain intact");
}

/// B2: staging_root that is a symlink pointing outside data_dir is rejected.
#[cfg(unix)]
#[test]
fn staging_root_symlink_outside_data_dir_is_rejected() {
    let data_dir = TempDir::new().unwrap();
    // Create a separate "outside" directory.
    let outside_dir = TempDir::new().unwrap();

    // Create staging_root as a symlink to outside_dir.
    let staging_root = data_dir.path().join("restore");
    std::os::unix::fs::symlink(outside_dir.path(), &staging_root).unwrap();

    let job_id = JobId::new();
    let result = StagingWriter::open(&staging_root, data_dir.path(), job_id);

    assert!(
        matches!(result, Err(StagingError::OutsideDataDir { .. })),
        "symlinked staging_root outside data_dir must be rejected, got: {result:?}"
    );
}

/// B1: Write through a symlink in the staging tree — cap_std prevents symlink following.
/// The write should either succeed (capping to staging dir) or fail with an error,
/// but must NOT end up writing to the symlink target.
#[cfg(unix)]
#[test]
fn staging_write_does_not_follow_symlink_in_tree() {
    let data_dir = TempDir::new().unwrap();
    let staging_root = data_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).unwrap();

    let job_id = JobId::new();
    let writer = StagingWriter::open(&staging_root, data_dir.path(), job_id).unwrap();

    // Create a symlink inside the job dir that points to /tmp.
    let job_dir = writer.staging_path();
    let link_path = job_dir.join("link");
    std::os::unix::fs::symlink("/tmp", &link_path).unwrap();

    // Attempt to write "link/attack_file" — cap_std should not follow the symlink.
    let validated = validate_record_path("link/attack_file").unwrap();
    let result = writer.write_file(&validated, b"malicious content");

    // The write must either fail (cap_std rejects symlink in tree) or succeed
    // but land inside the staging dir (not in /tmp).
    match result {
        Err(_) => {
            // Rejected by cap_std — the ideal outcome.
            assert!(
                !Path::new("/tmp/attack_file").exists(),
                "/tmp/attack_file must not be created"
            );
        }
        Ok(out_path) => {
            // Allowed — but must not be at /tmp/attack_file.
            assert!(
                out_path.starts_with(job_dir),
                "written file must be inside staging dir, not symlink target: {out_path:?}"
            );
            assert!(
                !Path::new("/tmp/attack_file").exists(),
                "/tmp/attack_file must not exist"
            );
        }
    }
}

/// G2: Two restore jobs get different job_ids.
#[test]
fn two_restore_jobs_get_different_job_ids() {
    let id1 = JobId::new();
    let id2 = JobId::new();
    assert_ne!(
        id1, id2,
        "two JobId::new() calls must produce different IDs"
    );
}

// ─── restore-i14: atomic write ────────────────────────────────────────────────

/// restore-i14: a failure after bytes were written but before the file was
/// published leaves nothing under the target name (and no temp either). Writing
/// straight to the target name would leave a truncated file here.
#[test]
fn write_file_target_absent_when_error_between_write_and_link() {
    let (_data, writer) = open_job();
    let validated = validate_record_path("home/kolya/video.mp4").unwrap();
    let target = writer.staging_path().join("home/kolya/video.mp4");

    // (a) The source fails midway through the write.
    let mut src = FailAfter { ok_bytes: 4096 };
    let result = writer.write_file_from(&validated, &mut src);
    assert!(
        matches!(result, Err(StagingError::Io(_))),
        "got: {result:?}"
    );
    assert!(
        !target.exists(),
        "no truncated file may appear under the target name"
    );
    assert!(
        partial_entries(&writer).is_empty(),
        "the failed temp must be removed"
    );

    // (b) Crash after the temp is complete but before commit: target still absent,
    // the complete temp sits in .viaticum-partial/.
    let temp = writer.stage_temp(b"complete bytes").unwrap();
    assert!(temp.rel().starts_with(PARTIAL_DIR_NAME));
    drop(temp);
    assert!(
        !target.exists(),
        "stage_temp must never touch the target name"
    );
    assert_eq!(partial_entries(&writer).len(), 1);

    // (c) commit fails (the target's parent is a regular file): target absent,
    // the temp is removed.
    std::fs::remove_dir_all(writer.staging_path().join(PARTIAL_DIR_NAME)).unwrap();
    std::fs::create_dir(writer.staging_path().join(PARTIAL_DIR_NAME)).unwrap();
    std::fs::write(writer.staging_path().join("blocker"), b"a file, not a dir").unwrap();
    let blocked = validate_record_path("blocker/inner.txt").unwrap();
    let temp = writer.stage_temp(b"payload").unwrap();
    let result = writer.commit(temp, &blocked);
    assert!(result.is_err(), "commit under a regular file must fail");
    assert!(!writer.staging_path().join("blocker/inner.txt").exists());
    assert!(
        partial_entries(&writer).is_empty(),
        "commit failure must remove the temp"
    );
}

/// restore-i14 + create_new contract: an existing target is never replaced.
#[test]
fn write_file_existing_target_fails_already_exists_and_keeps_original() {
    let (_data, writer) = open_job();
    let validated = validate_record_path("docs/file.txt").unwrap();
    writer.write_file(&validated, b"original").unwrap();

    let result = writer.write_file(&validated, b"replacement");
    assert!(
        matches!(result, Err(StagingError::AlreadyExists(_))),
        "got: {result:?}"
    );
    let content = std::fs::read(writer.staging_path().join("docs/file.txt")).unwrap();
    assert_eq!(content, b"original");
    assert!(
        partial_entries(&writer).is_empty(),
        "the refused temp must be removed"
    );
}

/// The published file is the complete content and no temp is left behind.
#[test]
fn write_file_publishes_complete_content_and_leaves_no_temp() {
    let (_data, writer) = open_job();
    let validated = validate_record_path("home/kolya/big.bin").unwrap();
    let bytes: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let out = writer.write_file(&validated, &bytes).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), bytes);
    assert!(partial_entries(&writer).is_empty());
}

/// A record path whose first component is a daemon-owned name is refused.
#[test]
fn write_file_rejects_reserved_top_level_name() {
    let (_data, writer) = open_job();
    for p in [".viaticum-partial/x", ".viaticum-job.json"] {
        let validated = validate_record_path(p).unwrap();
        let result = writer.write_file(&validated, b"x");
        assert!(
            matches!(result, Err(StagingError::ReservedName(_))),
            "{p}: got {result:?}"
        );
    }
    // The same name deeper in the tree is an ordinary user file.
    let nested = validate_record_path("home/.viaticum-job.json").unwrap();
    writer.write_file(&nested, b"user file").unwrap();
}

/// `open` creates `.viaticum-partial/` with mode 0o700.
#[cfg(unix)]
#[test]
fn open_creates_partial_dir_with_mode_700() {
    use std::os::unix::fs::PermissionsExt;
    let (_data, writer) = open_job();
    let meta = std::fs::metadata(writer.staging_path().join(PARTIAL_DIR_NAME)).unwrap();
    assert!(meta.is_dir());
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
}

// ─── Job record ───────────────────────────────────────────────────────────────

/// The record is replaced atomically; the last write wins and no temp remains.
#[test]
fn write_job_record_rewrites_running_with_finished() {
    let (_data, writer) = open_job();
    let running = record(JobState::Running, None);
    writer.write_job_record(&running).unwrap();
    let finished = JobRecord {
        state: JobState::Finished,
        outcome: Some(JobOutcome::Partial),
        finished_at: Some(2_000),
        ..running
    };
    writer.write_job_record(&finished).unwrap();

    let back = read_job_record(writer.staging_path()).unwrap().unwrap();
    assert_eq!(back, finished);
    assert!(partial_entries(&writer).is_empty());
}

#[test]
fn outcome_from_counts_follows_the_rules() {
    assert_eq!(
        JobOutcome::from_counts(3, 3, 0, false),
        JobOutcome::Complete
    );
    assert_eq!(JobOutcome::from_counts(3, 2, 1, false), JobOutcome::Partial);
    assert_eq!(
        JobOutcome::from_counts(3, 0, 3, false),
        JobOutcome::NothingRestored
    );
    assert_eq!(
        JobOutcome::from_counts(0, 0, 0, false),
        JobOutcome::NothingRestored
    );
    assert_eq!(
        JobOutcome::from_counts(3, 3, 0, true),
        JobOutcome::Interrupted
    );
}

// ─── Scan ─────────────────────────────────────────────────────────────────────

/// Staging root with one job dir named `id`; returns (root tempdir, job dir).
fn job_dir(id: &str) -> (TempDir, std::path::PathBuf) {
    let root = TempDir::new().unwrap();
    let dir = root.path().join(id);
    std::fs::create_dir_all(dir.join(PARTIAL_DIR_NAME)).unwrap();
    (root, dir)
}

fn put(dir: &Path, rel: &str, bytes: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn put_record(dir: &Path, r: &JobRecord) {
    std::fs::write(dir.join(JOB_RECORD_NAME), serde_json::to_vec(r).unwrap()).unwrap();
}

/// restore-i14: leftover temp + `running` record (daemon died mid-file) → the job
/// is `interrupted`, counting only the complete files under their own names.
#[test]
fn scan_staging_partial_leftover_and_running_record_is_interrupted() {
    let (root, dir) = job_dir("j1");
    put_record(&dir, &record(JobState::Running, None));
    put(&dir, "home/kolya/photos/a.jpg", b"aaaa");
    put(&dir, &format!("{PARTIAL_DIR_NAME}/0b6f-temp"), b"half");

    let jobs = scan_staging(root.path());
    assert_eq!(jobs.len(), 1);
    let j = &jobs[0];
    assert_eq!(j.outcome, JobOutcome::Interrupted);
    assert_eq!(j.record, RecordStatus::NotFinished);
    assert_eq!(j.path, "/home/kolya/photos/");
    assert_eq!(j.files_total, Some(3));
    assert_eq!(j.files_restored, 1, "the temp is not a restored file");
    assert_eq!(
        j.restored_paths,
        vec!["/home/kolya/photos/a.jpg".to_string()]
    );
    assert_eq!(j.partial_files, 1);
}

/// restore-i14: a finished record is the job's outcome after a restart, even when
/// the user already moved restored files out of staging.
#[test]
fn scan_staging_finished_record_returns_its_outcome() {
    let (root, dir) = job_dir("j2");
    let r = record(JobState::Finished, Some(JobOutcome::Partial));
    put_record(&dir, &r);
    put(&dir, "home/kolya/photos/a.jpg", b"aaaa"); // b.jpg already moved out

    let j = &scan_staging(root.path())[0];
    assert_eq!(j.record, RecordStatus::Finished);
    assert_eq!(j.outcome, JobOutcome::Partial);
    assert_eq!(j.files_restored, 2);
    assert_eq!(j.restored_paths, r.restored_paths);
}

/// A job dir without a record (made before B1) is `interrupted`, path unknown.
#[test]
fn scan_staging_without_record_is_interrupted_with_counted_files() {
    let root = TempDir::new().unwrap();
    let dir = root.path().join("old-job");
    put(&dir, "home/kolya/doc.txt", b"doc");
    put(&dir, "home/kolya/sub/x.txt", b"x");

    let j = &scan_staging(root.path())[0];
    assert_eq!(j.record, RecordStatus::Missing);
    assert_eq!(j.outcome, JobOutcome::Interrupted);
    assert_eq!(j.path, "?");
    assert_eq!(j.files_total, None);
    assert_eq!(
        j.restored_paths,
        vec![
            "/home/kolya/doc.txt".to_string(),
            "/home/kolya/sub/x.txt".to_string()
        ]
    );
}

/// An unparseable record is treated like a missing one.
#[test]
fn scan_staging_unreadable_record_is_interrupted() {
    let (root, dir) = job_dir("j3");
    std::fs::write(dir.join(JOB_RECORD_NAME), b"{not json").unwrap();
    let j = &scan_staging(root.path())[0];
    assert_eq!(j.record, RecordStatus::Unreadable);
    assert_eq!(j.outcome, JobOutcome::Interrupted);
}

/// Edge (reported, not in the intent): a finished record wins over a stray temp.
/// A temp can outlive a finished job only if its removal failed after the file was
/// published or refused; the record was written after every file was accounted.
#[test]
fn scan_staging_finished_record_wins_over_leftover_temp() {
    let (root, dir) = job_dir("j4");
    put_record(
        &dir,
        &record(JobState::Finished, Some(JobOutcome::Complete)),
    );
    put(&dir, &format!("{PARTIAL_DIR_NAME}/stray"), b"x");
    let j = &scan_staging(root.path())[0];
    assert_eq!(j.outcome, JobOutcome::Complete);
    assert_eq!(j.partial_files, 1);
}

/// `.viaticum-partial/` and `.viaticum-job.json` are never counted as user files;
/// the scan changes nothing on disk.
#[test]
fn partial_dir_is_not_counted_as_restored_file() {
    let (root, dir) = job_dir("j5");
    put_record(&dir, &record(JobState::Running, None));
    put(&dir, &format!("{PARTIAL_DIR_NAME}/t1"), b"1");
    put(&dir, &format!("{PARTIAL_DIR_NAME}/t2"), b"22");

    let j = &scan_staging(root.path())[0];
    assert_eq!(j.files_restored, 0);
    assert!(j.restored_paths.is_empty());
    assert_eq!(j.partial_files, 2);
    // Read-only: the leftovers and the record are still there.
    assert!(dir.join(PARTIAL_DIR_NAME).join("t1").exists());
    assert!(dir.join(PARTIAL_DIR_NAME).join("t2").exists());
    assert!(dir.join(JOB_RECORD_NAME).exists());
}

/// Files at the staging root are not job dirs; missing root → no jobs.
#[test]
fn scan_staging_ignores_root_files_and_missing_root() {
    let root = TempDir::new().unwrap();
    std::fs::write(root.path().join("loose.txt"), b"x").unwrap();
    assert!(scan_staging(root.path()).is_empty());
    assert!(scan_staging(Path::new("/nonexistent/staging/root")).is_empty());
}

// ─── restore-i19: publish chain ───────────────────────────────────────────────

fn errno(code: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(code)
}

/// EPERM (FAT) on hard link means "unsupported"; EACCES is a real error (N4).
#[cfg(unix)]
#[test]
fn classify_distinguishes_unsupported_from_permission_errors() {
    use super::publish::{AttemptError, classify};
    let hl = PublishMethod::HardLink;
    assert_eq!(classify(hl, &errno(libc::EPERM)), AttemptError::Unsupported);
    assert_eq!(
        classify(hl, &errno(libc::EOPNOTSUPP)),
        AttemptError::Unsupported
    );
    assert_eq!(classify(hl, &errno(libc::EXDEV)), AttemptError::Unsupported);
    assert_eq!(classify(hl, &errno(libc::EACCES)), AttemptError::Failed);
    assert_eq!(classify(hl, &errno(libc::ENOSPC)), AttemptError::Failed);
    assert_eq!(classify(hl, &errno(libc::EEXIST)), AttemptError::Exists);
    let rn = PublishMethod::RenameNoReplace;
    assert_eq!(
        classify(rn, &errno(libc::EINVAL)),
        AttemptError::Unsupported
    );
    assert_eq!(
        classify(rn, &errno(libc::ENOSYS)),
        AttemptError::Unsupported
    );
    assert_eq!(classify(rn, &errno(libc::EEXIST)), AttemptError::Exists);
    assert_eq!(classify(rn, &errno(libc::EACCES)), AttemptError::Failed);
    let cr = PublishMethod::CheckedRename;
    assert_eq!(classify(cr, &errno(libc::EINVAL)), AttemptError::Failed);
}

/// Chain: hard link unsupported → rename-noreplace unsupported → checked rename.
#[cfg(unix)]
#[test]
fn publish_chain_falls_back_only_on_unsupported() {
    use super::publish::{PublishError, publish_chain};
    let mut tried = Vec::new();
    let r = publish_chain(PublishMethod::HardLink, |m| {
        tried.push(m);
        match m {
            PublishMethod::HardLink => Err(errno(libc::EPERM)),
            PublishMethod::RenameNoReplace => Err(errno(libc::EINVAL)),
            PublishMethod::CheckedRename => Ok(()),
        }
    });
    assert_eq!(r.unwrap(), PublishMethod::CheckedRename);
    assert_eq!(tried, PublishMethod::CHAIN.to_vec());

    // EACCES stops the chain: no fallback past a real error.
    let mut tried = Vec::new();
    let r = publish_chain(PublishMethod::HardLink, |m| {
        tried.push(m);
        Err(errno(libc::EACCES))
    });
    assert!(matches!(
        r,
        Err(PublishError::Failed(PublishMethod::HardLink, _))
    ));
    assert_eq!(tried, vec![PublishMethod::HardLink]);

    // An existing target stops the chain at once (never "try a weaker step").
    let mut tried = Vec::new();
    let r = publish_chain(PublishMethod::HardLink, |m| {
        tried.push(m);
        Err(errno(libc::EEXIST))
    });
    assert!(matches!(r, Err(PublishError::Exists)));
    assert_eq!(tried, vec![PublishMethod::HardLink]);

    // Nothing supported → NoneSupported.
    let r = publish_chain(PublishMethod::HardLink, |m| match m {
        PublishMethod::CheckedRename => Err(std::io::Error::from(std::io::ErrorKind::Unsupported)),
        _ => Err(errno(libc::EOPNOTSUPP)),
    });
    assert!(matches!(r, Err(PublishError::NoneSupported(_))));
}

/// Each fallback step on a real filesystem: complete content published, an
/// existing target refused and kept, no temp left behind.
#[test]
fn every_publish_method_publishes_complete_file_and_refuses_existing_target() {
    let starts: &[PublishMethod] = if cfg!(target_os = "linux") {
        &PublishMethod::CHAIN
    } else {
        &[PublishMethod::HardLink, PublishMethod::CheckedRename]
    };
    for &start in starts {
        let (_data, writer) = open_job();
        let writer = writer.with_publish_start(start);
        let validated = validate_record_path("home/kolya/doc.txt").unwrap();
        let out = writer.write_file(&validated, b"complete").unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"complete", "{start:?}");
        assert!(partial_entries(&writer).is_empty(), "{start:?}: temp left");

        let again = writer.write_file(&validated, b"replacement");
        assert!(
            matches!(again, Err(StagingError::AlreadyExists(_))),
            "{start:?}: got {again:?}"
        );
        assert_eq!(std::fs::read(&out).unwrap(), b"complete", "{start:?}");
        assert!(
            partial_entries(&writer).is_empty(),
            "{start:?}: refused temp left"
        );
    }
}

/// The startup probe finds hard links on the test filesystem and cleans up.
#[test]
fn probe_publish_picks_hard_link_on_a_normal_filesystem_and_leaves_nothing() {
    let root = TempDir::new().unwrap();
    assert_eq!(
        super::publish::probe_publish(root.path()).unwrap(),
        PublishMethod::HardLink
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn job_id_parse_and_serde_roundtrip_display() {
    let id = JobId::new();
    assert_eq!(JobId::parse(&id.to_string()), Some(id));
    assert_eq!(JobId::parse("not-a-uuid"), None);
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, format!("\"{id}\""));
    assert_eq!(serde_json::from_str::<JobId>(&json).unwrap(), id);
    assert!(serde_json::from_str::<JobId>("\"nope\"").is_err());
}

/// restore-i22 (mutation M6): the production writer starts the chain at hard link,
/// so on a normal filesystem every restored file is published by hard link.
#[test]
fn production_writer_publishes_via_hard_link_on_a_normal_filesystem() {
    let (_data, writer) = open_job();
    let validated = validate_record_path("home/kolya/photo.jpg").unwrap();
    let published = writer.write_file_published(&validated, b"jpeg").unwrap();
    assert_eq!(published.method, PublishMethod::HardLink);
    assert_eq!(std::fs::read(&published.path).unwrap(), b"jpeg");
}
