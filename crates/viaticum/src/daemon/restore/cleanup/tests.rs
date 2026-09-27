// Tests for the staging report (restore-i8: staging is never deleted by the daemon).
// Pattern: what_when_then. Real files in tempdirs; log lines captured with a
// thread-local tracing subscriber.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use super::{
    HoldingsPressure, PublishCheck, StagingStatus, StagingSummary, check_staging,
    holder_stops_taking_data, initial_staging_status, report_staging_at_startup,
    run_staging_monitor, should_warn, staging_squeezes_holdings, staging_status_from_probe,
    staging_summary, staging_total_bytes, warn_if_squeezing,
};
use crate::daemon::restore::staging::publish::PublishMethod;
use crate::daemon::restore::staging::{JOB_RECORD_NAME, PARTIAL_DIR_NAME};

// ─── Helpers ──────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `f` with a subscriber that records every event (INFO and up) into a string.
fn with_logs<R>(f: impl FnOnce() -> R) -> (R, String) {
    let buf = LogBuf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    let r = tracing::subscriber::with_default(subscriber, f);
    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (r, logs)
}

/// A job dir with one restored file (`bytes` long), a record and a leftover temp.
fn make_job(root: &Path, id: &str, bytes: usize) -> PathBuf {
    let dir = root.join(id);
    std::fs::create_dir_all(dir.join("home/kolya")).unwrap();
    std::fs::create_dir_all(dir.join(PARTIAL_DIR_NAME)).unwrap();
    std::fs::write(dir.join("home/kolya/file.bin"), vec![7u8; bytes]).unwrap();
    std::fs::write(dir.join(PARTIAL_DIR_NAME).join("temp"), b"half").unwrap();
    dir
}

/// Every path under `root` with its size, sorted: the "nothing changed" witness.
fn tree(root: &Path) -> Vec<(PathBuf, u64)> {
    fn walk(p: &Path, out: &mut Vec<(PathBuf, u64)>) {
        for e in std::fs::read_dir(p).unwrap().flatten() {
            let m = std::fs::symlink_metadata(e.path()).unwrap();
            out.push((e.path(), if m.is_dir() { 0 } else { m.len() }));
            if m.is_dir() {
                walk(&e.path(), out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out.sort();
    out
}

/// Set mtime of `path` (file or dir) to `age` in the past.
fn age_path(path: &Path, age: Duration) {
    let t = SystemTime::now() - age;
    std::fs::File::open(path).unwrap().set_modified(t).unwrap();
}

const EIGHT_DAYS: Duration = Duration::from_secs(8 * 24 * 3600);

// ─── Size helpers (kept from the pre-B1 cleanup) ──────────────────────────────

#[test]
fn staging_total_bytes_returns_zero_for_missing_dir() {
    let total = staging_total_bytes(Path::new("/nonexistent/path/that/does/not/exist"));
    assert_eq!(total, 0);
}

#[test]
fn staging_total_bytes_returns_correct_sum() {
    let dir = TempDir::new().unwrap();
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
    std::fs::write(dir.path().join("root.bin"), [0u8; 100]).unwrap();
    std::fs::write(sub.join("nested.bin"), [0u8; 200]).unwrap();

    let total = staging_total_bytes(dir.path());
    assert_eq!(total, 300, "expected 100+200=300 bytes");
}

/// W2: should_warn returns false when used <= threshold.
#[test]
fn should_warn_returns_false_when_under_threshold() {
    assert!(
        !should_warn(4, 1_073_741_824),
        "4 bytes must not exceed 1 GB threshold"
    );
}

/// W2: should_warn returns true when used > threshold.
#[test]
fn should_warn_returns_true_when_over_threshold() {
    assert!(should_warn(10, 5), "10 bytes must exceed 5-byte threshold");
}

/// W2: should_warn returns false when equal to threshold.
#[test]
fn should_warn_returns_false_when_equal_to_threshold() {
    assert!(!should_warn(5, 5), "equal to threshold must not warn");
}

// ─── restore-i8: report, never delete ─────────────────────────────────────────

#[test]
fn staging_summary_counts_job_dirs_and_bytes() {
    let root = TempDir::new().unwrap();
    make_job(root.path(), "a", 100);
    make_job(root.path(), "b", 50);
    std::fs::write(root.path().join("loose.txt"), b"xyz").unwrap();

    let s = staging_summary(root.path());
    // 100 + 4 (temp) + 50 + 4 (temp) + 3 (loose file at the root).
    assert_eq!(
        s,
        StagingSummary {
            job_dirs: 2,
            bytes: 161
        }
    );
    assert_eq!(
        staging_summary(Path::new("/nonexistent/staging")),
        StagingSummary::default()
    );
}

/// restore-i8 (mutation target: TTL eviction): an 8-day-old job dir survives the
/// startup report untouched, and the report says so.
#[test]
fn startup_report_never_deletes_old_staging_dirs() {
    let root = TempDir::new().unwrap();
    let id = "5a622bf0-677f-4104-8112-94fda181489f";
    let old = make_job(root.path(), id, 10);
    std::fs::write(
        old.join(JOB_RECORD_NAME),
        format!(
            r#"{{"job_id":"{id}","path":"/home/kolya/","state":"finished","files_total":1,
            "files_restored":1,"restored_paths":["/home/kolya/file.bin"],"failures":[],
            "outcome":"complete","started_at":1,"finished_at":2}}"#
        ),
    )
    .unwrap();
    age_path(&old.join("home/kolya/file.bin"), EIGHT_DAYS);
    age_path(&old.join("home/kolya"), EIGHT_DAYS);
    age_path(&old, EIGHT_DAYS);
    let before = tree(root.path());

    let (s, logs) = with_logs(|| report_staging_at_startup(root.path(), u64::MAX));

    assert_eq!(
        tree(root.path()),
        before,
        "the startup report must not change staging"
    );
    assert_eq!(s.job_dirs, 1);
    assert!(
        logs.contains("restore staging: 1 job dir(s)"),
        "startup INFO missing: {logs}"
    );
    assert!(logs.contains("nothing is deleted automatically"), "{logs}");
    assert!(logs.contains("restore staging job: complete"), "{logs}");
    assert!(
        !logs.contains("WARN"),
        "under the threshold there is no WARN: {logs}"
    );
}

/// Startup with an interrupted job (no record) reports it as interrupted.
#[test]
fn startup_report_names_interrupted_job() {
    let root = TempDir::new().unwrap();
    make_job(root.path(), "crashed", 10);
    let (_s, logs) = with_logs(|| report_staging_at_startup(root.path(), u64::MAX));
    assert!(
        logs.contains("restore staging job: interrupted (no job record)"),
        "{logs}"
    );
}

/// Empty staging: no INFO line (nothing to move out).
#[test]
fn startup_report_is_silent_for_empty_staging() {
    let root = TempDir::new().unwrap();
    let (s, logs) = with_logs(|| report_staging_at_startup(root.path(), 0));
    assert_eq!(s, StagingSummary::default());
    assert!(!logs.contains("restore staging:"), "{logs}");
}

/// The periodic check WARNs only over the threshold and never deletes.
#[test]
fn hourly_check_warns_only_over_threshold_and_never_deletes() {
    let root = TempDir::new().unwrap();
    let old = make_job(root.path(), "old", 1000);
    age_path(&old, EIGHT_DAYS);
    let before = tree(root.path());

    let (under, logs_under) = with_logs(|| check_staging(root.path(), 1_000_000));
    assert!(!logs_under.contains("WARN"), "{logs_under}");
    let (over, logs_over) = with_logs(|| check_staging(root.path(), 100));
    assert!(
        logs_over.contains("WARN") && logs_over.contains("restore staging directory is large"),
        "{logs_over}"
    );
    assert_eq!(under, over);
    assert_eq!(
        tree(root.path()),
        before,
        "the check must not change staging"
    );
}

/// The check returns the same summary as `staging_summary` and changes nothing:
/// leftover temps, records and old dirs all stay.
#[test]
fn check_staging_returns_summary_without_side_effects() {
    let root = TempDir::new().unwrap();
    let a = make_job(root.path(), "a", 10);
    make_job(root.path(), "b", 20);
    age_path(&a, EIGHT_DAYS);
    let before = tree(root.path());

    let s = check_staging(root.path(), 0);

    assert_eq!(s, staging_summary(root.path()));
    assert_eq!(s.job_dirs, 2);
    assert_eq!(tree(root.path()), before);
    assert!(a.join(PARTIAL_DIR_NAME).join("temp").exists());
}

async fn wait_for(cache: &Arc<Mutex<StagingStatus>>, want: StagingStatus) -> bool {
    for _ in 0..300 {
        if *cache.lock().unwrap() == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// W3: the startup report (not a periodic tick — the interval is an hour) fills the
/// cached bytes; job dirs are never deleted; cancel stops the task.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_staging_monitor_refreshes_cache_from_startup_report() {
    let root = TempDir::new().unwrap();
    let old = make_job(root.path(), "old", 10);
    age_path(&old, EIGHT_DAYS);

    // As set before the web API starts: count known, bytes still counting.
    let cache = Arc::new(Mutex::new(StagingStatus {
        job_dirs: 1,
        bytes: None,
        publish: PublishCheck::Works(PublishMethod::HardLink),
    }));
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run_staging_monitor(
        root.path().to_path_buf(),
        u64::MAX,
        Duration::from_secs(3600),
        Arc::clone(&cache),
        None,
        cancel.clone(),
    ));

    let want = StagingStatus {
        job_dirs: 1,
        bytes: Some(14), // 10 (file) + 4 (leftover temp)
        publish: PublishCheck::Works(PublishMethod::HardLink),
    };
    assert!(
        wait_for(&cache, want).await,
        "the startup report must fill the cached bytes and keep the publish check; got {:?}",
        *cache.lock().unwrap()
    );

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("monitor must stop on cancel")
        .unwrap();
    assert!(
        old.join("home/kolya/file.bin").exists(),
        "old job dir must survive"
    );
    assert!(old.join(PARTIAL_DIR_NAME).join("temp").exists());
}

/// Each periodic tick refreshes the cache; old dirs survive every tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_staging_monitor_ticks_refresh_cache_and_never_delete() {
    let root = TempDir::new().unwrap();
    let old = make_job(root.path(), "old", 10);
    age_path(&old, EIGHT_DAYS);

    let cache = Arc::new(Mutex::new(StagingStatus::default()));
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run_staging_monitor(
        root.path().to_path_buf(),
        u64::MAX,
        Duration::from_millis(20),
        Arc::clone(&cache),
        None,
        cancel.clone(),
    ));
    let one = StagingStatus {
        job_dirs: 1,
        bytes: Some(14),
        ..Default::default()
    };
    assert!(wait_for(&cache, one).await);
    make_job(root.path(), "new", 10);
    let two = StagingStatus {
        job_dirs: 2,
        bytes: Some(28),
        ..Default::default()
    };
    assert!(wait_for(&cache, two).await, "a tick must refresh the cache");
    tokio::time::sleep(Duration::from_millis(100)).await; // several more ticks

    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("monitor must stop on cancel")
        .unwrap();
    assert!(
        old.join("home/kolya/file.bin").exists(),
        "old job dir must survive"
    );
}

// ─── W3 / restore-i19: status before the web API ─────────────────────────────

/// One cheap `read_dir` for the count, bytes explicitly unknown, the publish probe
/// done and its probe files gone.
#[test]
fn initial_staging_status_counts_dirs_leaves_bytes_unknown_and_probes_publish() {
    let root = TempDir::new().unwrap();
    make_job(root.path(), "a", 10);
    make_job(root.path(), "b", 10);
    let before = tree(root.path());

    let (s, logs) = with_logs(|| initial_staging_status(root.path()));

    assert_eq!(s.job_dirs, 2);
    assert_eq!(
        s.bytes, None,
        "bytes are counted later, never reported as 0"
    );
    // The test filesystem (ext4/tmpfs) supports hard links.
    assert_eq!(s.publish, PublishCheck::Works(PublishMethod::HardLink));
    assert!(logs.contains("restore publish: restored files appear in staging via hard_link"));
    assert_eq!(
        tree(root.path()),
        before,
        "the probe must leave nothing behind"
    );
}

/// A staging root the probe cannot write into → ERROR and `Unavailable`.
#[cfg(unix)]
#[test]
fn initial_staging_status_reports_unavailable_when_probe_cannot_write() {
    let (s, logs) = with_logs(|| initial_staging_status(Path::new("/nonexistent/staging")));
    assert_eq!(s.publish, PublishCheck::Unavailable);
    assert!(logs.contains("ERROR"), "{logs}");
}

// ─── restore-i18 / i21 ────────────────────────────────────────────────────────

const MIB: u64 = 1024 * 1024;

/// restore-i21: soft pressure, or free disk at/below the reserve (effective quota
/// 0, which `should_reject_offers` alone reads as "unlimited"); unknown free space
/// (no matching mount) is not pressure.
#[test]
fn holder_stops_taking_data_covers_soft_pressure_and_below_reserve() {
    let gib = 1024 * MIB;
    // Soft quota 1000 bytes, 950 held: 5 % free < 15 %.
    assert!(holder_stops_taking_data(1000, Some(100 * gib), 0, 950));
    assert!(!holder_stops_taking_data(1000, Some(100 * gib), 0, 100));
    // No soft quota: quota = free - reserve.
    assert!(!holder_stops_taking_data(0, Some(100 * gib), gib, 10 * gib));
    // Free disk at or below the reserve: the node refuses every offer.
    assert!(holder_stops_taking_data(0, Some(gib), gib, 0));
    assert!(holder_stops_taking_data(0, Some(gib / 2), gib, 0));
    // Unknown free space (disk_available_bytes would say 0): no claim.
    assert!(!holder_stops_taking_data(0, None, gib, 0));
}

/// N6 / N10: the flag needs pressure, a known size and at least 1 MiB of staging.
#[test]
fn staging_squeezes_holdings_needs_pressure_known_size_and_one_mib() {
    assert!(staging_squeezes_holdings(true, Some(MIB)));
    assert!(!staging_squeezes_holdings(true, Some(MIB - 1)));
    assert!(!staging_squeezes_holdings(true, Some(0)));
    assert!(
        !staging_squeezes_holdings(true, None),
        "still counting → no flag"
    );
    assert!(!staging_squeezes_holdings(false, Some(1 << 30)));
}

/// The WARN names a human-readable size and asks to move the files out.
#[test]
fn warn_if_squeezing_logs_human_size_only_when_squeezing() {
    let (warned, logs) = with_logs(|| warn_if_squeezing(true, Some(3 * MIB)));
    assert!(warned);
    assert!(
        logs.contains("restore staging 3.0 MB is taking space from your friends' data; move files out and delete it"),
        "{logs}"
    );
    let (warned, logs) = with_logs(|| warn_if_squeezing(false, Some(3 * MIB)));
    assert!(!warned);
    assert!(!logs.contains("WARN"), "{logs}");
}

/// N9: a probe where no publish step works → ERROR and `Unavailable` in status.
#[test]
fn probe_none_supported_makes_status_unavailable() {
    use crate::daemon::restore::staging::publish::probe_publish_with;
    let root = TempDir::new().unwrap();
    let probe = probe_publish_with(root.path(), |_, _, _, _, _| {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    });
    assert!(probe.is_err());
    assert_eq!(
        std::fs::read_dir(root.path()).unwrap().count(),
        0,
        "the probe cleans up even when it fails"
    );
    let (s, logs) = with_logs(|| staging_status_from_probe(root.path(), probe));
    assert_eq!(s.publish, PublishCheck::Unavailable);
    assert!(
        logs.contains("ERROR") && logs.contains("restore cannot write files here"),
        "{logs}"
    );
}

fn pressured_holdings(root: &Path) -> HoldingsPressure {
    let db = viaticum_core::db::Db::open_in_memory().unwrap();
    db.upsert_holding(&viaticum_core::types::HoldingRecord {
        source_block_id: viaticum_core::types::SourceBlockId([9u8; 32]),
        owner_id: viaticum_core::types::IdentityPub([8u8; 32]),
        esi_ranges: vec![(0, 10)],
        importance: 0.5,
        total_bytes: 950,
        status: viaticum_core::types::HoldingStatus::Active,
        received_at: viaticum_core::types::Timestamp(100),
        delete_requested_at: None,
        drop_notice_sent_at: None,
    })
    .unwrap();
    HoldingsPressure {
        db,
        data_dir: root.to_path_buf(),
        soft_quota_bytes: 1000,
        disk_reserve_bytes: 0,
    }
}

/// The monitor WARNs when the holder stops taking data and staging holds ≥ 1 MiB.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_staging_monitor_warns_when_staging_squeezes_holdings() {
    let root = TempDir::new().unwrap();
    make_job(root.path(), "a", 2 * MIB as usize);
    let pressure = pressured_holdings(root.path());
    assert!(pressure.stops_taking_data());

    let cache = Arc::new(Mutex::new(StagingStatus::default()));
    let cancel = CancellationToken::new();
    let (logs_buf, dispatch) = {
        let buf = LogBuf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        (buf, tracing::Dispatch::new(subscriber))
    };
    let fut = run_staging_monitor(
        root.path().to_path_buf(),
        u64::MAX,
        Duration::from_secs(3600),
        Arc::clone(&cache),
        Some(pressure),
        cancel.clone(),
    );
    let task = tokio::spawn(tracing::instrument::WithSubscriber::with_subscriber(
        fut, dispatch,
    ));
    let want = StagingStatus {
        job_dirs: 1,
        bytes: Some(2 * MIB + 4),
        ..Default::default()
    };
    assert!(wait_for(&cache, want).await);
    cancel.cancel();
    task.await.unwrap();
    let logs = String::from_utf8(logs_buf.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("is taking space from your friends' data; move files out and delete it"),
        "{logs}"
    );
    assert!(
        root.path().join("a").exists(),
        "a warning only, never a delete"
    );
}
