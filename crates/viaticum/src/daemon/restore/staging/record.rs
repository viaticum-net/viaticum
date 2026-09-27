// Job record (`<job>/.viaticum-job.json`) and the read-only staging scan (restore-i14).
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

/// Failure to read a job record.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("job record io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("job record is not valid JSON: {0}")]
    Parse(#[from] serde_json::Error),
}

// ─── On-disk record ───────────────────────────────────────────────────────────

/// Lifecycle state stored in the job record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Running,
    Finished,
}

/// How a job ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobOutcome {
    /// Every matched file restored, nothing failed.
    Complete,
    /// Some files restored, some failed.
    Partial,
    /// Nothing restored.
    NothingRestored,
    /// The daemon stopped (crash, kill, shutdown) before the job finished.
    Interrupted,
}

impl JobOutcome {
    /// `Complete ⇔ failures == 0 ∧ restored == total ∧ total > 0`; `Interrupted` if
    /// the job was stopped; `NothingRestored ⇔ restored == 0`; otherwise `Partial`.
    pub fn from_counts(
        files_total: u32,
        files_restored: u32,
        failures: usize,
        interrupted: bool,
    ) -> Self {
        if interrupted {
            JobOutcome::Interrupted
        } else if failures == 0 && files_restored == files_total && files_total > 0 {
            JobOutcome::Complete
        } else if files_restored == 0 {
            JobOutcome::NothingRestored
        } else {
            JobOutcome::Partial
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            JobOutcome::Complete => "complete",
            JobOutcome::Partial => "partial",
            JobOutcome::NothingRestored => "nothing_restored",
            JobOutcome::Interrupted => "interrupted",
        }
    }
}

/// One file that was not restored, and why.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JobFailure {
    /// Catalog path of the file.
    pub path: String,
    /// Human-readable reason.
    pub detail: String,
}

/// Contents of `<job>/.viaticum-job.json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JobRecord {
    pub job_id: JobId,
    /// Path the user asked to restore (file or prefix).
    pub path: String,
    pub state: JobState,
    /// Number of catalog files the path matched.
    pub files_total: u32,
    pub files_restored: u32,
    /// Catalog paths of files visible in the job dir under their own names.
    #[serde(default)]
    pub restored_paths: Vec<String>,
    #[serde(default)]
    pub failures: Vec<JobFailure>,
    /// `None` while running.
    #[serde(default)]
    pub outcome: Option<JobOutcome>,
    /// Unix seconds.
    pub started_at: u64,
    /// Unix seconds; `None` while running.
    #[serde(default)]
    pub finished_at: Option<u64>,
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
    pub outcome: JobOutcome,
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
        Ok(Some(r)) if r.state == JobState::Finished && r.outcome.is_some() => {
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
            outcome: r.outcome.unwrap_or(JobOutcome::Interrupted),
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
            outcome: JobOutcome::Interrupted,
            files_total: r.as_ref().map(|r| r.files_total),
            files_restored: on_disk.len() as u32,
            restored_paths: on_disk,
            partial_files,
            bytes,
        },
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
