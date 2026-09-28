// Job record (`<job>/.viaticum-job.json`), the read-only staging scan and the
// startup loader of a job dir (restore-i14).
//
// The coordinator writes the record when a job starts (`running`) and rewrites it
// when the job ends (`finished` + outcome). After any crash the record is the
// source of truth for "how did this job end": a finished record is reported as is;
// a job dir whose record is not finished (daemon died mid-job) or missing (job dir
// from before B1) is reported `interrupted`, counting only complete files — the
// ones visible under their own names (the atomic writer guarantees those are whole).
//
// `scan_staging` is pure: it reads, it never deletes or rewrites anything.

use std::path::{Path, PathBuf};

use super::{JOB_RECORD_NAME, JobId, PARTIAL_DIR_NAME, is_service_name};
use crate::cli::types::{
    RestoreFailure, RestoreFailureKind, RestoreJob, RestoreJobState, RestoreOutcome,
};

/// Failure to read a job record.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("job record io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("job record is not valid JSON: {0}")]
    Parse(#[from] serde_json::Error),
}

// ─── On-disk record ───────────────────────────────────────────────────────────

/// Contents of `<job>/.viaticum-job.json`; also the registry's in-memory entry
/// (`restore::jobs`), so what `--status` shows and what survives a restart are the
/// same data.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JobRecord {
    pub job_id: JobId,
    /// Path the user asked to restore (file or prefix).
    pub path: String,
    /// On disk only `running` or `finished`; `queued` lives in memory.
    pub state: RestoreJobState,
    /// Number of catalog files the path matched.
    pub files_total: u32,
    pub files_restored: u32,
    /// Catalog paths of files visible in the job dir under their own names.
    #[serde(default)]
    pub restored_paths: Vec<String>,
    #[serde(default)]
    pub failures: Vec<RestoreFailure>,
    /// `None` until finished.
    #[serde(default)]
    pub outcome: Option<RestoreOutcome>,
    /// Unix seconds when the job was accepted (B1.2 records call it `started_at`).
    #[serde(alias = "started_at")]
    pub submitted_at: u64,
    /// Unix seconds; `None` while running, and for a job found interrupted.
    #[serde(default)]
    pub finished_at: Option<u64>,
}

impl JobRecord {
    /// A job just accepted: nothing done yet, submitted now.
    pub fn queued(job_id: JobId, path: &str, files_total: u32) -> Self {
        JobRecord {
            job_id,
            path: path.to_string(),
            state: RestoreJobState::Queued,
            files_total,
            files_restored: 0,
            restored_paths: Vec::new(),
            failures: Vec::new(),
            outcome: None,
            submitted_at: viaticum_core::types::Timestamp::now().0,
            finished_at: None,
        }
    }

    /// `queued` in state `running`.
    pub fn running(job_id: JobId, path: &str, files_total: u32) -> Self {
        JobRecord {
            state: RestoreJobState::Running,
            ..Self::queued(job_id, path, files_total)
        }
    }

    /// Wire view; `staging_root` is the parent of the job dir.
    pub fn to_wire(&self, staging_root: &Path) -> RestoreJob {
        RestoreJob {
            job_id: self.job_id.to_string(),
            path: self.path.clone(),
            state: self.state,
            files_total: self.files_total,
            files_restored: self.files_restored,
            restored_paths: self.restored_paths.clone(),
            failures: self.failures.clone(),
            outcome: self.outcome,
            staging_path: staging_root
                .join(self.job_id.to_string())
                .to_string_lossy()
                .into_owned(),
            submitted_at: iso_utc(self.submitted_at),
            finished_at: self.finished_at.map(iso_utc),
            waiting_for_holders_until: None,
        }
    }
}

/// Unix seconds → `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso_utc(secs: u64) -> String {
    crate::daemon::dispatch::unix_secs_to_iso(secs, true)
}

// ─── Scan ─────────────────────────────────────────────────────────────────────

/// What the job dir's record said when it was scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordStatus {
    /// Record present and finished: its outcome is the job's outcome.
    Finished,
    /// Record present but still `running`: the daemon stopped mid-job.
    NotFinished,
    /// No record (job dir from before B1, or the daemon died before writing it).
    Missing,
    /// Record present but not parseable.
    Unreadable,
}

/// View of one job dir rebuilt from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSummary {
    /// Job dir name.
    pub dir_name: String,
    /// The dir name parsed as a job id (every dir the daemon creates is one).
    pub job_id: Option<JobId>,
    /// Requested path from the record, `"?"` when there is no readable record.
    pub path: String,
    pub record: RecordStatus,
    pub outcome: RestoreOutcome,
    /// From the record when known.
    pub files_total: Option<u32>,
    /// Finished record: its count. Otherwise: complete files on disk.
    pub files_restored: u32,
    /// Finished record: its list. Otherwise: complete files on disk, as catalog paths.
    pub restored_paths: Vec<String>,
    /// Leftover temp files in `.viaticum-partial/` (incomplete by definition).
    pub partial_files: u32,
    /// All bytes under the job dir, service files included.
    pub bytes: u64,
}

/// Rebuild the view of every job dir under `staging_root` (sorted by job id).
/// Read-only: never deletes, never rewrites. Missing root → empty.
pub fn scan_staging(staging_root: &Path) -> Vec<JobSummary> {
    let rd = match std::fs::read_dir(staging_root) {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<JobSummary> = rd
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| summarize_job_dir(&e.path(), &e.file_name().to_string_lossy()))
        .collect();
    out.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
    out
}

/// Rebuild the view of one job dir. Read-only.
pub fn summarize_job_dir(job_dir: &Path, dir_name: &str) -> JobSummary {
    let mut on_disk: Vec<String> = Vec::new();
    let mut partial_files = 0u32;
    let mut bytes = 0u64;

    if let Ok(rd) = std::fs::read_dir(job_dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if name == PARTIAL_DIR_NAME {
                let mut temps = Vec::new();
                walk_files(&path, &mut Vec::new(), &mut temps, &mut bytes);
                partial_files = temps.len() as u32;
            } else if is_service_name(&name) {
                if let Ok(m) = std::fs::symlink_metadata(&path) {
                    bytes = bytes.saturating_add(m.len());
                }
            } else {
                walk_files(&path, &mut vec![name], &mut on_disk, &mut bytes);
            }
        }
    }
    on_disk.sort();

    let (record_status, record) = match read_job_record(job_dir) {
        Ok(Some(r)) if r.state == RestoreJobState::Finished && r.outcome.is_some() => {
            (RecordStatus::Finished, Some(r))
        }
        Ok(Some(r)) => (RecordStatus::NotFinished, Some(r)),
        Ok(None) => (RecordStatus::Missing, None),
        Err(e) => {
            tracing::debug!(
                job = dir_name,
                "restore staging: unreadable job record: {e}"
            );
            (RecordStatus::Unreadable, None)
        }
    };

    match (record_status, record) {
        (RecordStatus::Finished, Some(r)) => JobSummary {
            dir_name: dir_name.to_string(),
            job_id: JobId::parse(dir_name),
            path: r.path,
            record: RecordStatus::Finished,
            outcome: r.outcome.unwrap_or(RestoreOutcome::Interrupted),
            files_total: Some(r.files_total),
            files_restored: r.files_restored,
            restored_paths: r.restored_paths,
            partial_files,
            bytes,
        },
        (status, r) => JobSummary {
            dir_name: dir_name.to_string(),
            job_id: JobId::parse(dir_name),
            path: r
                .as_ref()
                .map(|r| r.path.clone())
                .unwrap_or_else(|| "?".into()),
            record: status,
            outcome: RestoreOutcome::Interrupted,
            files_total: r.as_ref().map(|r| r.files_total),
            files_restored: on_disk.len() as u32,
            restored_paths: on_disk,
            partial_files,
            bytes,
        },
    }
}

// ─── Load (registry) ──────────────────────────────────────────────────────────

/// Detail of the failure entry of a job found interrupted on disk.
pub const INTERRUPTED_DETAIL: &str = "outcome was not recorded (daemon stopped or disk error)";

/// Rebuild a job from its staging directory (restore-i14): the registry's view of a
/// job the daemon did not see end (seeded at startup) or one evicted from memory.
///
/// - finished record → the record as is (no tree walk);
/// - record not finished (the daemon died or stopped mid-job), missing (a job dir
///   from before B1) or unreadable → `finished` + `interrupted`; `files_restored` /
///   `restored_paths` = the complete files on disk (only complete files are ever
///   visible under their names); `failures` = one `interrupted` entry for the
///   requested path. `files_total` from the record, else the count on disk.
///
/// `remove_partials`: delete the leftover temp files in `.viaticum-partial/`
/// (incomplete by definition). Only for a job that is not running (restore-i24): a
/// running job's temp file is a file being written. Never touches anything else.
pub fn load_job_from_dir(job_dir: &Path, job_id: JobId, remove_partials: bool) -> JobRecord {
    if remove_partials {
        remove_partial_files(job_dir, job_id);
    }
    let record = match read_job_record(job_dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(job = %job_id, "restore staging: unreadable job record: {e}");
            None
        }
    };
    if let Some(r) = &record
        && r.state == RestoreJobState::Finished
        && r.outcome.is_some()
    {
        return r.clone();
    }
    let mut on_disk: Vec<String> = Vec::new();
    let mut bytes = 0u64;
    if let Ok(rd) = std::fs::read_dir(job_dir) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_service_name(&name) {
                walk_files(&entry.path(), &mut vec![name], &mut on_disk, &mut bytes);
            }
        }
    }
    on_disk.sort();
    let path = record
        .as_ref()
        .map(|r| r.path.clone())
        .unwrap_or_else(|| "?".into());
    let submitted_at = record.as_ref().map(|r| r.submitted_at).unwrap_or_else(|| {
        std::fs::metadata(job_dir)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });
    let files_restored = on_disk.len() as u32;
    JobRecord {
        job_id,
        failures: vec![RestoreFailure {
            path: path.clone(),
            kind: RestoreFailureKind::Interrupted,
            detail: INTERRUPTED_DETAIL.to_string(),
        }],
        path,
        state: RestoreJobState::Finished,
        files_total: record
            .as_ref()
            .map(|r| r.files_total)
            .unwrap_or(files_restored),
        files_restored,
        restored_paths: on_disk,
        outcome: Some(RestoreOutcome::Interrupted),
        submitted_at,
        finished_at: None,
    }
}

/// Delete the regular files (and symlinks) directly in `<job_dir>/.viaticum-partial/`.
fn remove_partial_files(job_dir: &Path, job_id: JobId) {
    let Ok(rd) = std::fs::read_dir(job_dir.join(PARTIAL_DIR_NAME)) else {
        return;
    };
    let mut removed = 0u32;
    for entry in rd.flatten() {
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(true);
        if is_dir {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            Err(e) => tracing::warn!(
                job = %job_id,
                temp = %entry.path().display(),
                "restore staging: could not remove an unfinished temp file: {e}"
            ),
        }
    }
    if removed > 0 {
        tracing::info!(
            job = %job_id,
            removed,
            "restore staging: removed unfinished temp file(s) of a job that is not running"
        );
    }
}

/// Read `<job_dir>/.viaticum-job.json`. `Ok(None)` if absent (or not a regular file).
pub fn read_job_record(job_dir: &Path) -> Result<Option<JobRecord>, RecordError> {
    let path = job_dir.join(JOB_RECORD_NAME);
    match std::fs::symlink_metadata(&path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let bytes = std::fs::read(&path)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

/// Collect regular files under `path` as catalog paths (`/a/b/c`); symlinks are
/// neither followed nor counted. Adds every regular file's size to `bytes`.
fn walk_files(path: &Path, prefix: &mut Vec<String>, out: &mut Vec<String>, bytes: &mut u64) {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    if meta.is_file() {
        *bytes = bytes.saturating_add(meta.len());
        out.push(format!("/{}", prefix.join("/")));
    } else if meta.is_dir() {
        let rd = match std::fs::read_dir(path) {
            Ok(rd) => rd,
            Err(_) => return,
        };
        for entry in rd.flatten() {
            prefix.push(entry.file_name().to_string_lossy().into_owned());
            let child: PathBuf = entry.path();
            walk_files(&child, prefix, out, bytes);
            prefix.pop();
        }
    }
}
