// Tests for the restore job registry (restore-i4, i14, i24).
// Pattern: what_when_then. Real job dirs in a TempDir.

use std::path::Path;

use tempfile::TempDir;

use super::{MAX_FINISHED_JOBS_IN_MEMORY, RestoreJobs};
use crate::cli::types::{RestoreFailure, RestoreFailureKind, RestoreJobState, RestoreOutcome};
use crate::daemon::restore::staging::record::{INTERRUPTED_DETAIL, JobRecord};
use crate::daemon::restore::staging::{JOB_RECORD_NAME, JobId, PARTIAL_DIR_NAME};

fn registry() -> (TempDir, RestoreJobs) {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("restore");
    std::fs::create_dir_all(&root).unwrap();
    let jobs = RestoreJobs::new(root);
    (dir, jobs)
}

fn failure(path: &str) -> RestoreFailure {
    RestoreFailure {
        path: path.to_string(),
        kind: RestoreFailureKind::HoldersUnavailable,
        detail: "collected 1 of 3".to_string(),
    }
}

fn write_record(job_dir: &Path, record: &JobRecord) {
    std::fs::create_dir_all(job_dir).unwrap();
    std::fs::write(
        job_dir.join(JOB_RECORD_NAME),
        serde_json::to_vec(record).unwrap(),
    )
    .unwrap();
}

fn put(job_dir: &Path, rel: &str, bytes: &[u8]) {
    let p = job_dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn finished_record(job_id: JobId, submitted_at: u64) -> JobRecord {
    JobRecord {
        state: RestoreJobState::Finished,
        files_restored: 1,
        restored_paths: vec!["/home/kolya/a.txt".into()],
        outcome: Some(RestoreOutcome::Complete),
        submitted_at,
        finished_at: Some(submitted_at + 5),
        ..JobRecord::queued(job_id, "/home/kolya/a.txt", 1)
    }
}

#[test]
fn submit_creates_queued_job_with_staging_path_under_root() {
    let (_d, jobs) = registry();
    let id = JobId::new();
    let job = jobs.submit(id, "/home/kolya/photos/", 40);
    assert_eq!(job.job_id, id.to_string());
    assert_eq!(job.state, RestoreJobState::Queued);
    assert_eq!(job.files_total, 40);
    assert_eq!(job.outcome, None);
    assert_eq!(
        Path::new(&job.staging_path),
        jobs.staging_root().join(id.to_string())
    );
    assert!(job.submitted_at.ends_with('Z'), "{}", job.submitted_at);
    assert_eq!(jobs.get(id), Some(job));
    assert_eq!(jobs.active_count(), 1);
}

#[test]
fn job_moves_queued_running_finished() {
    let (_d, jobs) = registry();
    let id = JobId::new();
    jobs.submit(id, "/p/", 3);
    jobs.mark_running(id, "/p/", 2);
    let running = jobs.get(id).unwrap();
    assert_eq!(running.state, RestoreJobState::Running);
    assert_eq!(running.files_total, 2, "the coordinator's own count wins");
    jobs.record_restored(id, "/p/a");
    jobs.record_failure(id, failure("/p/b"));
    let mid = jobs.get(id).unwrap();
    assert_eq!((mid.files_restored, mid.failures.len()), (1, 1));
    assert_eq!(mid.outcome, None);

    let done = jobs.finish(id, false).unwrap();
    assert_eq!(done.state, RestoreJobState::Finished);
    assert_eq!(done.outcome, Some(RestoreOutcome::Partial));
    assert!(done.finished_at.is_some());
    assert_eq!(jobs.active_count(), 0);
    // Finished is final: later updates and a second finish change nothing.
    jobs.record_restored(id, "/p/c");
    assert_eq!(jobs.finish(id, true), Some(done));
}

#[test]
fn finish_computes_outcome_including_interrupted() {
    let (_d, jobs) = registry();
    let outcome = |restored: u32, failed: u32, total: u32, interrupted: bool| {
        let id = JobId::new();
        jobs.submit(id, "/p/", total);
        jobs.mark_running(id, "/p/", total);
        for i in 0..restored {
            jobs.record_restored(id, &format!("/p/r{i}"));
        }
        for i in 0..failed {
            jobs.record_failure(id, failure(&format!("/p/f{i}")));
        }
        jobs.finish(id, interrupted).unwrap().outcome.unwrap()
    };
    assert_eq!(outcome(3, 0, 3, false), RestoreOutcome::Complete);
    assert_eq!(outcome(2, 1, 3, false), RestoreOutcome::Partial);
    assert_eq!(outcome(0, 3, 3, false), RestoreOutcome::NothingRestored);
    assert_eq!(outcome(3, 0, 3, true), RestoreOutcome::Interrupted);
    assert_eq!(outcome(0, 0, 0, false), RestoreOutcome::NothingRestored);
}

#[test]
fn finished_jobs_beyond_cap_evict_oldest_first_in_memory() {
    let (_d, jobs) = registry();
    let ids: Vec<JobId> = (0..MAX_FINISHED_JOBS_IN_MEMORY + 3)
        .map(|_| JobId::new())
        .collect();
    for id in &ids {
        jobs.submit(*id, "/p", 1);
        jobs.mark_running(*id, "/p", 1);
        jobs.finish(*id, false);
    }
    let listed = jobs.list();
    assert_eq!(listed.len(), MAX_FINISHED_JOBS_IN_MEMORY);
    for evicted in &ids[..3] {
        assert!(
            listed.iter().all(|j| j.job_id != evicted.to_string()),
            "oldest finished evicted first"
        );
        // No job dir was ever written for these: gone for good.
        assert_eq!(jobs.get(*evicted), None);
    }
    assert_eq!(listed[0].job_id, ids.last().unwrap().to_string());
}

#[test]
fn queued_and_running_jobs_are_never_evicted() {
    let (_d, jobs) = registry();
    let queued = JobId::new();
    let running = JobId::new();
    jobs.submit(queued, "/q", 1);
    jobs.submit(running, "/r", 1);
    jobs.mark_running(running, "/r", 1);
    for _ in 0..MAX_FINISHED_JOBS_IN_MEMORY + 5 {
        let id = JobId::new();
        jobs.submit(id, "/p", 1);
        jobs.finish(id, false);
    }
    assert_eq!(jobs.get(queued).unwrap().state, RestoreJobState::Queued);
    assert_eq!(jobs.get(running).unwrap().state, RestoreJobState::Running);
    assert_eq!(jobs.active_count(), 2);
}

/// restore-i14: a job not in memory (evicted, or from before a restart) is read
/// back from its job dir; `--status <id>` is never "unknown" for an existing dir.
#[test]
fn get_falls_back_to_disk_for_evicted_or_pre_restart_job() {
    let (_d, jobs) = registry();
    let finished = JobId::new();
    write_record(
        &jobs.staging_root().join(finished.to_string()),
        &finished_record(finished, 1000),
    );
    let crashed = JobId::new();
    let crashed_dir = jobs.staging_root().join(crashed.to_string());
    write_record(
        &crashed_dir,
        &JobRecord::running(crashed, "/home/kolya/photos/", 3),
    );
    put(&crashed_dir, "home/kolya/photos/a.jpg", b"a");
    put(&crashed_dir, &format!("{PARTIAL_DIR_NAME}/tmp1"), b"half");

    let got = jobs.get(finished).unwrap();
    assert_eq!(got.state, RestoreJobState::Finished);
    assert_eq!(got.outcome, Some(RestoreOutcome::Complete));

    let got = jobs.get(crashed).unwrap();
    assert_eq!(got.state, RestoreJobState::Finished);
    assert_eq!(got.outcome, Some(RestoreOutcome::Interrupted));
    assert_eq!(got.files_total, 3);
    assert_eq!(got.files_restored, 1);
    assert_eq!(
        got.restored_paths,
        vec!["/home/kolya/photos/a.jpg".to_string()]
    );
    assert_eq!(got.failures.len(), 1);
    assert_eq!(got.failures[0].kind, RestoreFailureKind::Interrupted);
    assert_eq!(got.failures[0].detail, INTERRUPTED_DETAIL);
    // The lookup is read-only: it removes nothing.
    assert!(crashed_dir.join(PARTIAL_DIR_NAME).join("tmp1").exists());

    assert_eq!(jobs.get(JobId::new()), None, "no dir → unknown");
}

/// restore-i14 / i24: at startup every job dir becomes a known job; a job the
/// previous run did not finish is `interrupted` and its leftover temp files are
/// removed (nothing runs at startup); the user's files are never touched.
#[test]
fn seed_from_staging_registers_every_job_dir() {
    let (_d, jobs) = registry();
    let root = jobs.staging_root().to_path_buf();
    let done = JobId::new();
    write_record(&root.join(done.to_string()), &finished_record(done, 100));
    let crashed = JobId::new();
    let crashed_dir = root.join(crashed.to_string());
    write_record(&crashed_dir, &JobRecord::running(crashed, "/p/", 2));
    put(&crashed_dir, "p/one.txt", b"1");
    put(&crashed_dir, &format!("{PARTIAL_DIR_NAME}/tmp"), b"half");
    let pre_b1 = JobId::new();
    put(&root.join(pre_b1.to_string()), "old/file.txt", b"old");
    std::fs::create_dir_all(root.join("not-a-job")).unwrap();

    assert_eq!(jobs.seed_from_staging(), 3);

    assert_eq!(jobs.list().len(), 3);
    for id in [done, crashed, pre_b1] {
        assert!(jobs.get(id).is_some(), "{id} registered");
    }
    let c = jobs.get(crashed).unwrap();
    assert_eq!(c.outcome, Some(RestoreOutcome::Interrupted));
    assert_eq!(c.restored_paths, vec!["/p/one.txt".to_string()]);
    let old = jobs.get(pre_b1).unwrap();
    assert_eq!(old.path, "?");
    assert_eq!(old.outcome, Some(RestoreOutcome::Interrupted));
    assert_eq!(old.files_restored, 1);
    assert!(!crashed_dir.join(PARTIAL_DIR_NAME).join("tmp").exists());
    assert!(crashed_dir.join("p/one.txt").exists());
    assert_eq!(jobs.active_count(), 0);
}

/// restore-i24: seeding never removes the temp files of a job this registry is
/// running (a temp file there is a file being written).
#[test]
fn seed_from_staging_keeps_temp_files_of_a_running_job() {
    let (_d, jobs) = registry();
    let running = JobId::new();
    jobs.submit(running, "/p/", 1);
    jobs.mark_running(running, "/p/", 1);
    let dir = jobs.staging_root().join(running.to_string());
    write_record(&dir, &JobRecord::running(running, "/p/", 1));
    put(&dir, &format!("{PARTIAL_DIR_NAME}/being-written"), b"part");

    jobs.seed_from_staging();

    assert!(dir.join(PARTIAL_DIR_NAME).join("being-written").exists());
    assert_eq!(jobs.get(running).unwrap().state, RestoreJobState::Running);
}

#[test]
fn unknown_job_id_calls_are_noops() {
    let (_d, jobs) = registry();
    let id = JobId::new();
    jobs.record_restored(id, "/x");
    jobs.record_failure(id, failure("/x"));
    jobs.remove(id);
    assert_eq!(jobs.finish(id, false), None);
    assert_eq!(jobs.get(id), None);
    assert!(jobs.list().is_empty());
}

#[test]
fn list_is_newest_first() {
    let (_d, jobs) = registry();
    let a = JobId::new();
    let b = JobId::new();
    let c = JobId::new();
    jobs.submit(a, "/a", 1);
    jobs.submit(b, "/b", 1);
    jobs.finish(b, false);
    jobs.submit(c, "/c", 1);
    let order: Vec<String> = jobs.list().into_iter().map(|j| j.job_id).collect();
    assert_eq!(order, vec![c.to_string(), b.to_string(), a.to_string()]);
}

#[test]
fn remove_rolls_back_a_submitted_job() {
    let (_d, jobs) = registry();
    let id = JobId::new();
    jobs.submit(id, "/a", 1);
    jobs.remove(id);
    assert_eq!(jobs.get(id), None);
    assert_eq!(jobs.active_count(), 0);
}

#[test]
fn job_id_parse_roundtrips_display() {
    let id = JobId::new();
    assert_eq!(JobId::parse(&id.to_string()), Some(id));
    assert_eq!(JobId::parse("not-a-uuid"), None);
}

/// restore-i26: while the running job waits for holders the wire view (get and
/// list) says until when; the wait is not written into the record, and finishing
/// the job clears it. A finished job cannot be set waiting.
#[test]
fn set_waiting_shows_in_wire_view_and_clears_on_finish() {
    let (_dir, jobs) = registry();
    let job_id = JobId::new();
    jobs.submit(job_id, "/p/", 2);
    jobs.mark_running(job_id, "/p/", 2);

    jobs.set_waiting(job_id, Some(1_790_000_000));
    let wire = jobs.get(job_id).unwrap();
    let until = wire.waiting_for_holders_until.expect("waiting shown");
    assert!(until.ends_with('Z'), "ISO-8601 UTC: {until}");
    assert_eq!(
        jobs.list()[0].waiting_for_holders_until.as_deref(),
        Some(until.as_str())
    );
    let json = serde_json::to_string(&jobs.record(job_id).unwrap()).unwrap();
    assert!(
        !json.contains("waiting"),
        "transient, not in the record: {json}"
    );

    jobs.set_waiting(job_id, None);
    assert_eq!(jobs.get(job_id).unwrap().waiting_for_holders_until, None);

    jobs.set_waiting(job_id, Some(1_790_000_000));
    jobs.finish(job_id, false);
    assert_eq!(jobs.get(job_id).unwrap().waiting_for_holders_until, None);
    jobs.set_waiting(job_id, Some(1_790_000_000));
    assert_eq!(jobs.get(job_id).unwrap().waiting_for_holders_until, None);
}
