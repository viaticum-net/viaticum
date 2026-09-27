//! In-memory registry of restore jobs, seeded at startup from staging (restore-i14).
//!
//! A restore is a job in the daemon (restore-i4): `POST /api/restore` submits it and
//! answers at once; the CLI and the web UI poll it by id. The registry holds every
//! queued and running job and the newest `MAX_FINISHED_JOBS_IN_MEMORY` finished
//! ones. A job that is not in memory but has a job dir in staging is read back from
//! that dir (`load_job_from_dir`), so `--status <id>` never answers "unknown" for an
//! existing job dir.
//!
//! Writers: `RestoreCoordinator` (running / per-file progress / finish) and dispatch
//! (submit / rollback on a full queue). Lock: `std::sync::Mutex`, short sections,
//! never held across `.await`, never nested with another lock, no I/O under it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use viaticum_core::types::Timestamp;

use crate::cli::types::{RestoreFailure, RestoreJob, RestoreJobState, RestoreOutcome};
use crate::daemon::restore::staging::JobId;
use crate::daemon::restore::staging::record::{JobRecord, load_job_from_dir};

#[cfg(test)]
mod tests;

/// Finished jobs kept in memory; older ones are read back from their job dirs.
pub const MAX_FINISHED_JOBS_IN_MEMORY: usize = 32;

/// Shared handle to the registry. Cheap to clone.
#[derive(Clone, Debug)]
pub struct RestoreJobs {
    inner: Arc<Mutex<JobsInner>>,
    staging_root: PathBuf,
}

#[derive(Debug, Default)]
struct JobsInner {
    jobs: HashMap<JobId, Entry>,
    /// Monotonic insertion order: newest = largest.
    next_seq: u64,
}

#[derive(Debug)]
struct Entry {
    record: JobRecord,
    seq: u64,
}

impl JobsInner {
    fn insert(&mut self, record: JobRecord) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.jobs.insert(record.job_id, Entry { record, seq });
    }

    /// Drop the oldest finished jobs beyond the cap. Queued and running jobs stay.
    fn evict_finished(&mut self) {
        let mut finished: Vec<(u64, JobId)> = self
            .jobs
            .iter()
            .filter(|(_, e)| e.record.state == RestoreJobState::Finished)
            .map(|(id, e)| (e.seq, *id))
            .collect();
        if finished.len() <= MAX_FINISHED_JOBS_IN_MEMORY {
            return;
        }
        finished.sort_unstable_by_key(|(seq, _)| *seq);
        let excess = finished.len() - MAX_FINISHED_JOBS_IN_MEMORY;
        for (_, id) in finished.into_iter().take(excess) {
            self.jobs.remove(&id);
        }
    }

    fn active(&mut self, job_id: JobId) -> Option<&mut JobRecord> {
        self.jobs
            .get_mut(&job_id)
            .map(|e| &mut e.record)
            .filter(|r| r.state != RestoreJobState::Finished)
    }
}

impl RestoreJobs {
    /// Empty registry for jobs under `staging_root` (`<data_dir>/restore`).
    pub fn new(staging_root: PathBuf) -> Self {
        RestoreJobs {
            inner: Arc::new(Mutex::new(JobsInner::default())),
            staging_root,
        }
    }

    pub fn staging_root(&self) -> &Path {
        &self.staging_root
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, JobsInner> {
        self.inner.lock().expect("restore jobs lock poisoned")
    }

    /// Startup: read every job dir under the staging root (`load_job_from_dir`,
    /// removing leftover temp files — nothing runs yet, restore-i24) and keep the
    /// newest `MAX_FINISHED_JOBS_IN_MEMORY` in memory. Dirs whose name is not a job
    /// id are not jobs and are skipped. Returns the number of job dirs read.
    /// Blocking I/O; call before the web API starts.
    pub fn seed_from_staging(&self) -> usize {
        let Ok(rd) = std::fs::read_dir(&self.staging_root) else {
            return 0;
        };
        let mut loaded: Vec<JobRecord> = Vec::new();
        for entry in rd.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let Some(job_id) = JobId::parse(&entry.file_name().to_string_lossy()) else {
                continue;
            };
            // A job this registry already runs keeps its temp files (restore-i24).
            let running = self.lock().active(job_id).is_some();
            if running {
                continue;
            }
            loaded.push(load_job_from_dir(&entry.path(), job_id, true));
        }
        let count = loaded.len();
        loaded.sort_by_key(|r| (r.submitted_at, r.job_id.to_string()));
        let mut inner = self.lock();
        for record in loaded {
            if !inner.jobs.contains_key(&record.job_id) {
                inner.insert(record);
            }
        }
        inner.evict_finished();
        count
    }

    /// Register a queued job (dispatch, before it is enqueued).
    pub fn submit(&self, job_id: JobId, path: &str, files_total: u32) -> RestoreJob {
        let record = JobRecord::queued(job_id, path, files_total);
        let wire = record.to_wire(&self.staging_root);
        self.lock().insert(record);
        wire
    }

    /// Roll back a submit whose request never reached the coordinator.
    pub fn remove(&self, job_id: JobId) {
        self.lock().jobs.remove(&job_id);
    }

    /// The coordinator took the job. `files_total` is the count it actually
    /// matched. A job the registry does not know (a direct `restore()` call) is
    /// registered here. No-op for a finished job.
    pub fn mark_running(&self, job_id: JobId, path: &str, files_total: u32) {
        let mut inner = self.lock();
        if !inner.jobs.contains_key(&job_id) {
            inner.insert(JobRecord::queued(job_id, path, files_total));
        }
        if let Some(r) = inner.active(job_id) {
            r.state = RestoreJobState::Running;
            r.files_total = files_total;
        }
    }

    /// A file is visible under its own name in the job dir. Call only after that
    /// (restore-i14). No-op for an unknown or finished job.
    pub fn record_restored(&self, job_id: JobId, catalog_path: &str) {
        if let Some(r) = self.lock().active(job_id) {
            r.restored_paths.push(catalog_path.to_string());
            r.files_restored = r.restored_paths.len() as u32;
        }
    }

    /// A file (or the whole request) was not restored. No-op for an unknown or
    /// finished job.
    pub fn record_failure(&self, job_id: JobId, failure: RestoreFailure) {
        if let Some(r) = self.lock().active(job_id) {
            r.failures.push(failure);
        }
    }

    /// Finish the job: outcome from its counts, `interrupted` when the daemon
    /// stopped it. Returns the final record (the coordinator writes it to the job
    /// dir). A job already finished is returned unchanged; unknown → `None`.
    pub fn finish(&self, job_id: JobId, interrupted: bool) -> Option<JobRecord> {
        let mut inner = self.lock();
        let entry = inner.jobs.get_mut(&job_id)?;
        let r = &mut entry.record;
        if r.state != RestoreJobState::Finished {
            r.state = RestoreJobState::Finished;
            r.outcome = Some(RestoreOutcome::from_counts(
                r.files_total,
                r.files_restored,
                r.failures.len(),
                interrupted,
            ));
            r.finished_at = Some(Timestamp::now().0);
        }
        let done = r.clone();
        inner.evict_finished();
        Some(done)
    }

    /// The in-memory record of a job (what the coordinator writes to its job dir).
    pub fn record(&self, job_id: JobId) -> Option<JobRecord> {
        self.lock().jobs.get(&job_id).map(|e| e.record.clone())
    }

    /// Memory first; else read `<staging_root>/<id>` if it exists (never "unknown"
    /// for an existing job dir); else `None`. The disk fallback is read-only: a job
    /// not in memory is not running, and startup already removed its temp files.
    pub fn get(&self, job_id: JobId) -> Option<RestoreJob> {
        if let Some(e) = self.lock().jobs.get(&job_id) {
            return Some(e.record.to_wire(&self.staging_root));
        }
        let dir = self.staging_root.join(job_id.to_string());
        if !dir.is_dir() {
            return None;
        }
        Some(load_job_from_dir(&dir, job_id, false).to_wire(&self.staging_root))
    }

    /// Jobs in memory, newest first.
    pub fn list(&self) -> Vec<RestoreJob> {
        let inner = self.lock();
        let mut entries: Vec<&Entry> = inner.jobs.values().collect();
        entries.sort_by_key(|e| std::cmp::Reverse(e.seq));
        entries
            .into_iter()
            .map(|e| e.record.to_wire(&self.staging_root))
            .collect()
    }

    /// Queued + running jobs.
    pub fn active_count(&self) -> u32 {
        self.lock()
            .jobs
            .values()
            .filter(|e| e.record.state != RestoreJobState::Finished)
            .count() as u32
    }
}
