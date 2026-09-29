// Restore staging report (restore-i8): the daemon never deletes restored files.
//
// Restored files in `<data_dir>/restore/<job>/` may be the only copy the user has
// (after DR, or after the delete window released the network copy). They stay
// until the user moves them out and deletes the directory. The daemon only
// reports: an INFO summary plus one line per job at startup, a WARN when the
// staging tree exceeds `restore.staging_warn_gb` (startup and hourly), a WARN when
// staging takes disk space from friends' data under holder pressure (restore-i18),
// and a cached `StagingStatus` for `status` (with the publish probe, restore-i19).
//
// Everything here is read-only, except the publish probe's own two files at the
// staging root. The one thing the daemon may ever remove in a job
// dir is a leftover temp in `.viaticum-partial/` (incomplete by definition) — and
// that is not done here.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use viaticum_core::db::Db;

use crate::daemon::restore::staging::publish::{PublishMethod, probe_publish};
use crate::daemon::restore::staging::record::{RecordStatus, scan_staging};

#[cfg(test)]
mod tests;

/// Cadence of the staging size check after the startup report.
pub const STAGING_CHECK_INTERVAL: Duration = Duration::from_secs(3600);

/// Job dirs and bytes under the staging root; cached for `status`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StagingSummary {
    pub job_dirs: u32,
    pub bytes: u64,
}

/// Walk `staging_root` and return the total byte size of all files.
/// Non-critical: errors in sub-walks are silently skipped (just log at DEBUG).
pub fn staging_total_bytes(staging_root: &Path) -> u64 {
    let mut total = 0u64;
    if !staging_root.exists() {
        return 0;
    }
    walk_dir_size(staging_root, &mut total);
    total
}

fn walk_dir_size(dir: &Path, total: &mut u64) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::debug!(path = %dir.display(), "cleanup: read_dir error: {e}");
            return;
        }
    };
    for entry in rd.flatten() {
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk_dir_size(&entry.path(), total);
        } else {
            *total = total.saturating_add(meta.len());
        }
    }
}

/// Pure predicate: returns true if `used` exceeds `threshold`.
pub fn should_warn(used: u64, threshold: u64) -> bool {
    used > threshold
}

/// Count per-job subdirectories and total bytes (recursive). Read-only. Never deletes.
pub fn staging_summary(staging_root: &Path) -> StagingSummary {
    StagingSummary {
        job_dirs: count_job_dirs(staging_root),
        bytes: staging_total_bytes(staging_root),
    }
}

fn warn_if_over(staging_root: &Path, s: StagingSummary, warn_threshold_bytes: u64) {
    if should_warn(s.bytes, warn_threshold_bytes) {
        tracing::warn!(
            staging_root = %staging_root.display(),
            total_gb = s.bytes as f64 / 1_073_741_824.0,
            threshold_gb = warn_threshold_bytes as f64 / 1_073_741_824.0,
            "restore staging directory is large; consider cleaning up old restore jobs manually"
        );
    }
}

// ─── Cached status for `status` ─────────────────────────────────────────────────

/// Result of the startup publish probe (restore-i19).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PublishCheck {
    #[default]
    NotChecked,
    Works(PublishMethod),
    /// No step of the publish chain works in the staging dir: restore cannot write.
    Unavailable,
}

impl PublishCheck {
    pub fn as_str(self) -> &'static str {
        match self {
            PublishCheck::NotChecked => "",
            PublishCheck::Works(m) => m.as_str(),
            PublishCheck::Unavailable => "unavailable",
        }
    }
}

/// What `status` shows about staging. `bytes == None` means "still counting": the
/// job-dir count is known before the web API starts, the byte walk runs in the
/// monitor task.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StagingStatus {
    pub job_dirs: u32,
    pub bytes: Option<u64>,
    pub publish: PublishCheck,
}

impl StagingStatus {
    /// Take a fresh measurement; keeps the publish check.
    pub fn apply(&mut self, s: StagingSummary) {
        self.job_dirs = s.job_dirs;
        self.bytes = Some(s.bytes);
    }
}

/// Number of job dirs under `staging_root` (one `read_dir`, no recursion).
pub fn count_job_dirs(staging_root: &Path) -> u32 {
    match std::fs::read_dir(staging_root) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .count() as u32,
        Err(_) => 0,
    }
}

/// Synchronous, cheap, before the web API starts: job-dir count and the publish
/// probe. Bytes stay `None` until the monitor's startup report.
pub fn initial_staging_status(staging_root: &Path) -> StagingStatus {
    staging_status_from_probe(staging_root, probe_publish(staging_root))
}

/// `initial_staging_status` with the probe result given (seam for tests): INFO
/// with the method that works, or ERROR + `Unavailable` when none does.
pub(crate) fn staging_status_from_probe(
    staging_root: &Path,
    probe: Result<PublishMethod, std::io::Error>,
) -> StagingStatus {
    let publish = match probe {
        Ok(method) => {
            tracing::info!(
                method = method.as_str(),
                "restore publish: restored files appear in staging via {}",
                method.as_str()
            );
            PublishCheck::Works(method)
        }
        Err(e) => {
            tracing::error!(
                staging_root = %staging_root.display(),
                "restore publish: the staging filesystem supports none of hard link, \
                 rename-noreplace, checked rename ({e}); restore cannot write files here"
            );
            PublishCheck::Unavailable
        }
    };
    StagingStatus {
        job_dirs: count_job_dirs(staging_root),
        bytes: None,
        publish,
    }
}

// ─── restore-i18/i21: staging vs friends' data ───────────────────────────────

/// Staging below this size is not worth a warning (N6).
pub const SQUEEZE_WARN_MIN_BYTES: u64 = 1024 * 1024;

/// Has disk pressure stopped this node taking new data from friends? The quota rule the
/// holder applies to symbol offers (`budget::should_reject_offers` over
/// `compute_effective_quota`, one snapshot of `holdings_used_bytes`): soft pressure, or no
/// room at all — free disk plus our holdings at or below the reserve (holder-i1). An
/// unreadable disk without a soft quota (`Quota::Unknown`) refuses offers too, but that is
/// not disk pressure: staging cannot be squeezing what we cannot measure → false.
pub fn holder_stops_taking_data(
    soft_quota_bytes: u64,
    disk_free_bytes: Option<u64>,
    disk_reserve_bytes: u64,
    holdings_used_bytes: u64,
) -> bool {
    use viaticum_core::budget::{Quota, compute_effective_quota, should_reject_offers};
    match compute_effective_quota(
        soft_quota_bytes,
        disk_free_bytes,
        holdings_used_bytes,
        disk_reserve_bytes,
    ) {
        Quota::Unknown => false,
        quota => should_reject_offers(quota, holdings_used_bytes),
    }
}

/// Staging that the user has not moved out takes disk space from friends' data
/// while the node no longer takes their data. Unknown size (`None`, still
/// counting) never raises the flag.
pub fn staging_squeezes_holdings(stops_taking_data: bool, staging_bytes: Option<u64>) -> bool {
    stops_taking_data && staging_bytes.is_some_and(|b| b >= SQUEEZE_WARN_MIN_BYTES)
}

/// WARN (and return true) when staging squeezes friends' data.
pub fn warn_if_squeezing(stops_taking_data: bool, staging_bytes: Option<u64>) -> bool {
    if !staging_squeezes_holdings(stops_taking_data, staging_bytes) {
        return false;
    }
    let size = crate::cli::output::format_bytes(staging_bytes.unwrap_or(0));
    tracing::warn!(
        staging_bytes,
        "restore staging {size} is taking space from your friends' data; move files out \
         and delete it"
    );
    true
}

/// Inputs to evaluate whether the holder still takes friends' data.
#[derive(Clone)]
pub struct HoldingsPressure {
    pub db: Db,
    pub data_dir: PathBuf,
    pub soft_quota_bytes: u64,
    pub disk_reserve_bytes: u64,
}

impl HoldingsPressure {
    pub fn stops_taking_data(&self) -> bool {
        let used: u64 = match self.db.list_all_holdings() {
            Ok(h) => h.iter().map(|h| h.total_bytes).sum(),
            Err(e) => {
                tracing::error!(
                    "restore staging: cannot read holdings for the pressure check: {e}"
                );
                return false;
            }
        };
        holder_stops_taking_data(
            self.soft_quota_bytes,
            crate::daemon::handle::disk_available_bytes(&self.data_dir),
            self.disk_reserve_bytes,
            used,
        )
    }
}

// ─── Report ──────────────────────────────────────────────────────────────────

/// Startup: one INFO line per job dir (outcome from its record, or `interrupted`),
/// then INFO "restore staging: …" when there is at least one job dir, and the WARN
/// when over the threshold. Read-only.
pub fn report_staging_at_startup(staging_root: &Path, warn_threshold_bytes: u64) -> StagingSummary {
    for job in scan_staging(staging_root) {
        let record = match job.record {
            RecordStatus::Finished => "",
            RecordStatus::NotFinished => " (outcome not recorded: daemon stopped or disk error)",
            RecordStatus::Missing => " (no job record)",
            RecordStatus::Unreadable => " (job record unreadable)",
        };
        tracing::info!(
            job = %job.dir_name,
            path = %job.path,
            outcome = job.outcome.as_str(),
            files_restored = job.files_restored,
            unfinished_temp_files = job.partial_files,
            bytes = job.bytes,
            "restore staging job: {}{record}",
            job.outcome.as_str()
        );
    }
    let s = staging_summary(staging_root);
    if s.job_dirs > 0 {
        tracing::info!(
            "restore staging: {} job dir(s), {} bytes under {}; nothing is deleted automatically \
             — move restored files out, then delete the directories",
            s.job_dirs,
            s.bytes,
            staging_root.display()
        );
    }
    warn_if_over(staging_root, s, warn_threshold_bytes);
    s
}

/// Periodic check: WARN only over the threshold. Read-only.
pub fn check_staging(staging_root: &Path, warn_threshold_bytes: u64) -> StagingSummary {
    let s = staging_summary(staging_root);
    warn_if_over(staging_root, s, warn_threshold_bytes);
    s
}

/// Daemon task: startup report, then `check_staging` every `interval`; each result
/// goes into the cached status. With `pressure`, every check also WARNs when
/// staging takes space from friends' data (restore-i18). Never deletes anything.
/// Returns on `cancel`.
pub async fn run_staging_monitor(
    staging_root: PathBuf,
    warn_threshold_bytes: u64,
    interval: Duration,
    cache: Arc<Mutex<StagingStatus>>,
    pressure: Option<HoldingsPressure>,
    cancel: CancellationToken,
) {
    let s = tokio::task::block_in_place(|| {
        let s = report_staging_at_startup(&staging_root, warn_threshold_bytes);
        if let Some(p) = pressure.as_ref() {
            warn_if_squeezing(p.stops_taking_data(), Some(s.bytes));
        }
        s
    });
    cache.lock().expect("staging status lock poisoned").apply(s);

    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // the first tick is immediate; the startup report covered it
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let s = tokio::task::block_in_place(|| {
                    let s = check_staging(&staging_root, warn_threshold_bytes);
                    if let Some(p) = pressure.as_ref() {
            warn_if_squeezing(p.stops_taking_data(), Some(s.bytes));
        }
                    s
                });
                cache.lock().expect("staging status lock poisoned").apply(s);
            }
            _ = cancel.cancelled() => break,
        }
    }
}
