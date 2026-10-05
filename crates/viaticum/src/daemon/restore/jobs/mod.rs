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
use crate::daemon::restore::staging::record::{JobRecord, iso_utc, load_job_from_dir};

#[cfg(test)]
mod tests;

/// Finished jobs kept in memory; older ones are read back from their job dirs.
pub const MAX_FINISHED_JOBS_IN_MEMORY: usize = 32;

/// Shared handle to the registry. Cheap to clone.
#[derive(Clone, Debug)]
pub struct RestoreJobs {
    inner: Arc<Mutex<JobsInner>>,
    staging_root: PathBuf,
    /// Wakes the backup worker's loop when the set of unfinished jobs changes (Q-V9, spec
    /// v3.12b). Only a wake: the gate itself is computed from the registry (`has_unfinished`).
    gate_wake: Option<crate::daemon::work_pipeline::GateWake>,
    /// How long the backup has been paused (the gate's reading; `status` asks it).
    pause_watch: Arc<crate::daemon::work_pipeline::PauseWatch>,
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
    /// Unix seconds until which the running job waits for holders to answer
    /// (restore-i26). Transient: never written to the job record on disk.
    waiting_until: Option<u64>,
    /// The running job waits for the block work memory budget (restore-i39). Transient.
    waiting_memory: bool,
    /// The INFO line of that wait was written for this job (once per job).
    memory_wait_announced: bool,
}

impl Entry {
    fn to_wire(&self, staging_root: &Path) -> RestoreJob {
        let mut wire = self.record.to_wire(staging_root);
        wire.waiting_for_holders_until = self.waiting_until.map(iso_utc);
        wire.waiting_for_memory = self.waiting_memory;
        wire
    }
}

impl JobsInner {
    fn insert(&mut self, record: JobRecord) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.jobs.insert(
            record.job_id,
            Entry {
                record,
                seq,
                waiting_until: None,
                waiting_memory: false,
                memory_wait_announced: false,
            },
        );
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
            gate_wake: None,
            pause_watch: crate::daemon::work_pipeline::PauseWatch::new(),
        }
    }

    /// The watch of the backup pause: the gate built over this registry shares it.
    pub fn pause_watch(&self) -> Arc<crate::daemon::work_pipeline::PauseWatch> {
        Arc::clone(&self.pause_watch)
    }

    /// The pause has lasted longer than `BACKUP_PAUSE_WARN_AFTER` (`status`).
    pub fn backup_pause_overlong(&self) -> bool {
        crate::daemon::work_pipeline::RESTORE_PAUSES_BACKUP && self.pause_watch.overlong()
    }

    /// The notifier of the backup worker's gate: bumped at every change of the set of jobs.
    pub fn with_gate_wake(mut self, wake: crate::daemon::work_pipeline::GateWake) -> Self {
        self.gate_wake = Some(wake);
        self
    }

    /// Whether a job is not finished — `Queued` or `Running` (spec v3.12b WARN-2). Computed from
    /// the registry at every call: this is the restore half of the backup worker's gate, and no
    /// event has to publish it.
    pub fn has_unfinished(&self) -> bool {
        self.lock()
            .jobs
            .values()
            .any(|e| e.record.state != RestoreJobState::Finished)
    }

    /// Whether the backup worker is paused by an unfinished restore job (Q-V9 (a)): `status` says
    /// so.
    pub fn backup_paused(&self) -> bool {
        crate::daemon::work_pipeline::RESTORE_PAUSES_BACKUP && self.has_unfinished()
    }

    /// The set of jobs changed: wake the worker's loop (it asks the registry again).
    fn publish_running(&self, _inner: &JobsInner) {
        if let Some(wake) = &self.gate_wake {
            crate::daemon::work_pipeline::notify_gate(wake);
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
        let mut inner = self.lock();
        inner.insert(record);
        self.publish_running(&inner);
        wire
    }

    /// Roll back a submit whose request never reached the coordinator.
    pub fn remove(&self, job_id: JobId) {
        let mut inner = self.lock();
        inner.jobs.remove(&job_id);
        self.publish_running(&inner);
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
        self.publish_running(&inner);
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

    /// The running job waits for holders until `until` (unix seconds), or no longer
    /// waits (`None`) (restore-i26). No-op for an unknown or finished job.
    pub fn set_waiting(&self, job_id: JobId, until: Option<u64>) {
        if let Some(e) = self.lock().jobs.get_mut(&job_id)
            && e.record.state != RestoreJobState::Finished
        {
            e.waiting_until = until;
        }
    }

    /// The running job waits for the block work memory budget (`true`) or got it (`false`):
    /// the phase `waiting_for_memory` of `status` (restore-i39, restore-i4). Returns `true`
    /// when this is the first wait of the job — the caller writes the INFO line then, once per
    /// job. No-op for an unknown or finished job.
    pub fn set_waiting_for_memory(&self, job_id: JobId, waiting: bool) -> bool {
        let mut inner = self.lock();
        let Some(e) = inner.jobs.get_mut(&job_id) else {
            return false;
        };
        if e.record.state == RestoreJobState::Finished {
            return false;
        }
        e.waiting_memory = waiting;
        if waiting && !e.memory_wait_announced {
            e.memory_wait_announced = true;
            return true;
        }
        false
    }

    /// Finish the job: outcome from its counts, `interrupted` when the daemon
    /// stopped it. Returns the final record (the coordinator writes it to the job
    /// dir). A job already finished is returned unchanged; unknown → `None`.
    pub fn finish(&self, job_id: JobId, interrupted: bool) -> Option<JobRecord> {
        let mut inner = self.lock();
        let entry = inner.jobs.get_mut(&job_id)?;
        entry.waiting_until = None;
        entry.waiting_memory = false;
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
        self.publish_running(&inner);
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
            return Some(e.to_wire(&self.staging_root));
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
            .map(|e| e.to_wire(&self.staging_root))
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
