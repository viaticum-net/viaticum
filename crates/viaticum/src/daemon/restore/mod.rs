// RestoreCoordinator: a restore is a job in the daemon (restore-i4).
//
// Dispatch registers the job (`jobs::RestoreJobs`) and enqueues it; the coordinator
// runs jobs one at a time. Per block: rebuild from the owner's own source files if
// they are there, else fetch symbols from holders over the network in chunked
// rounds with no deadline (restore-i12). Every matched file ends restored or with a
// machine-readable failure (restore-i3). The job record in the job dir is written
// when the job starts and when it ends, so the outcome survives a restart
// (restore-i14). On the daemon's cancel token the job stops between requests and
// is recorded `interrupted` (T10).
//
// Module layout:
//   mod.rs      — RestoreCoordinator, restore(), run(), resolve_path(), failure_kind()
//   decode.rs   — decode one block (rebuild / network), write one file
//   no_answer/  — network fetch of a block; retry after rounds nobody answered,
//                 the job's pause budget (restore-i26)
//   pipeline.rs — decrypt_and_decompress(), extract_from_pack()
//   jobs/       — in-memory job registry, seeded from staging at startup
//   staging/    — atomic per-job staging writer, job record, staging scan
//   cleanup/    — staging report (never deletes, restore-i8)
//   tests.rs    — coordinator test scenarios

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use viaticum_core::db::Db;
use viaticum_core::erasure::ErasureEncoder;
use viaticum_core::types::{FileRecord, FileVersion, SourceBlockId, Timestamp};

use crate::cli::types::{RestoreFailure, RestoreFailureKind};
use crate::daemon::restore::cleanup::{HoldingsPressure, StagingStatus};
use crate::daemon::restore::jobs::RestoreJobs;
use crate::daemon::restore::no_answer::NoAnswerPauses;
use crate::daemon::restore::staging::record::JobRecord;
use crate::daemon::restore::staging::{JobId, StagingWriter};
use crate::daemon::symbol_fetch::RestoreSource;

pub mod cleanup;
mod decode;
pub use decode::{
    DecryptedBlock, decode_decrypt_stage, decode_parse_stage, local_plaintext, member_bytes,
    plaintext_stage,
};
pub mod jobs;
mod no_answer;
pub mod pipeline;
pub mod staging;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_budget;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors from restore operations.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("file not found in catalog: {path}")]
    FileNotFound { path: String },

    #[error("version not found: {selector:?} for {path}")]
    VersionNotFound { path: String, selector: String },

    #[error("source block not found in DB: {0}")]
    BlockNotFound(SourceBlockId),

    /// A block record from before encrypted sizes were stored: not restorable.
    #[error("source block {0} has no encrypted_size (legacy record)")]
    LegacyRecord(SourceBlockId),

    #[error("not enough holders answered: collected {got} of {need} symbols for block {block}")]
    InsufficientSymbols {
        block: SourceBlockId,
        got: usize,
        need: usize,
    },

    #[error("decode failed for block {0}: {1}")]
    DecodeFailed(SourceBlockId, String),

    #[error("decryption failed for block {0}")]
    DecryptionFailed(SourceBlockId),

    #[error("decompression failed for block {0}: {1}")]
    DecompressionFailed(SourceBlockId, String),

    #[error("pack index parse failed for block {0}: {1}")]
    PackIndexParseFailed(SourceBlockId, String),

    #[error("swarm error: {0}")]
    Swarm(String),

    #[error("path safety error for {path:?}: {source}")]
    PathUnsafe {
        path: String,
        source: viaticum_core::path_safety::PathSafetyError,
    },

    #[error("staging error: {0}")]
    Staging(#[from] crate::daemon::restore::staging::StagingError),

    #[error("db error: {0}")]
    Db(#[from] viaticum_core::db::DbError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The daemon is stopping (T10).
    #[error("daemon shutting down")]
    Cancelled,
}

impl RestoreError {
    /// Wrap a shared `FetchError` as `RestoreError`.
    pub(crate) fn from_fetch(err: crate::daemon::symbol_fetch::FetchError) -> Self {
        use crate::daemon::symbol_fetch::FetchError;
        match err {
            FetchError::InsufficientSymbols { block, got, need } => {
                RestoreError::InsufficientSymbols { block, got, need }
            }
            FetchError::Swarm(s) => RestoreError::Swarm(s),
            FetchError::Cancelled => RestoreError::Cancelled,
        }
    }
}

/// The machine-readable reason for a failed file (restore-i3).
pub(crate) fn failure_kind(e: &RestoreError) -> RestoreFailureKind {
    match e {
        RestoreError::InsufficientSymbols { .. } | RestoreError::Swarm(_) => {
            RestoreFailureKind::HoldersUnavailable
        }
        RestoreError::FileNotFound { .. } | RestoreError::VersionNotFound { .. } => {
            RestoreFailureKind::NotBackedUp
        }
        RestoreError::BlockNotFound(_) | RestoreError::LegacyRecord(_) => {
            RestoreFailureKind::BlockMissing
        }
        RestoreError::DecodeFailed(..)
        | RestoreError::DecryptionFailed(_)
        | RestoreError::DecompressionFailed(..)
        | RestoreError::PackIndexParseFailed(..) => RestoreFailureKind::Corrupt,
        RestoreError::PathUnsafe { .. } => RestoreFailureKind::PathUnsafe,
        RestoreError::Staging(_) | RestoreError::Io(_) => RestoreFailureKind::WriteFailed,
        RestoreError::Cancelled => RestoreFailureKind::Interrupted,
        RestoreError::Db(_) => RestoreFailureKind::Internal,
    }
}

// ─── Types ────────────────────────────────────────────────────────────────────

/// How to select which version of each file to restore.
#[derive(Debug, Clone, PartialEq)]
pub enum VersionSelector {
    /// Latest backed-up version (default).
    Latest,
    /// Specific version by 0-based index into FileRecord.versions.
    Index(usize),
    /// Nearest version with backed_up_at <= given timestamp.
    BeforeDate(Timestamp),
}

/// A restore request from the user or daemon.
#[derive(Debug, Clone)]
pub struct RestoreRequest {
    /// Path or prefix to restore. Trailing '/' treated as prefix query.
    pub path: String,
    /// Version selection for all matching files.
    pub version_selector: VersionSelector,
    /// Unique identifier for this restore job, generated by dispatch.
    pub job_id: JobId,
}

/// Result of a finished restore job (the same data as its final job record).
#[derive(Debug)]
pub struct RestoreResult {
    /// Number of files restored (visible under their own names in staging).
    pub files_restored: usize,
    /// Number of source blocks decoded.
    pub blocks_fetched: usize,
    /// Files that were not restored, with the reason.
    pub failures: Vec<RestoreFailure>,
    /// Absolute path to the per-job staging directory; empty when the path matched
    /// nothing (no job dir is created then).
    pub staging_path: PathBuf,
    /// The daemon stopped the job before it finished.
    pub interrupted: bool,
}

/// Configuration for RestoreCoordinator.
#[derive(Clone)]
pub struct RestoreConfig {
    /// Epoch key for decryption. 32 bytes. Must match the key used during backup.
    pub epoch_key: [u8; 32],
    /// Where network restore asks holders for symbols (the swarm in the daemon).
    /// `None`: only the owner's own source files can be used.
    pub symbols: Option<Arc<dyn RestoreSource>>,
    /// Root directory for per-job restore staging (`data_dir/restore`).
    /// Each job writes to `staging_root/<job_id>/`.
    pub staging_root: PathBuf,
    /// `data_dir` — used to verify staging_root is inside it.
    pub data_dir: PathBuf,
    /// Job registry shared with dispatch (restore-i4, i14).
    pub jobs: RestoreJobs,
    /// The daemon's cancel token: a running job stops between requests (T10).
    pub cancel: CancellationToken,
    /// Cached staging status for `status`; refreshed after every job.
    pub staging_status: Arc<Mutex<StagingStatus>>,
    /// Holder-pressure inputs for the end-of-job staging warning (restore-i20).
    pub pressure: Option<HoldingsPressure>,
    /// Test clock acceleration: the no-answer pauses are divided by it (restore-i26).
    pub time_scale: u64,
    /// The size limit of this machine: the local tier's rebuild reads no source file above
    /// it (J1, backup-i5). Default: the RaptorQ ceiling; the daemon sets the limit in force.
    pub max_source_bytes: u64,
    /// The block work memory budget shared with the worker and the PoS preparations: a restore
    /// takes one permit per block, as a priority waiter (restore-i39). `RestoreConfig::new` gives
    /// an unbounded one (tests); the daemon sets its own.
    pub mem_budget: Arc<crate::daemon::mem_budget::MemBudget>,
}

impl RestoreConfig {
    /// Config with a fresh registry and cancel token, no network, no pressure check.
    pub fn new(epoch_key: [u8; 32], staging_root: PathBuf, data_dir: PathBuf) -> Self {
        RestoreConfig {
            epoch_key,
            symbols: None,
            jobs: RestoreJobs::new(staging_root.clone()),
            staging_root,
            data_dir,
            cancel: CancellationToken::new(),
            staging_status: Arc::default(),
            pressure: None,
            time_scale: 1,
            max_source_bytes: viaticum_core::constants::MAX_FILE_SIZE_CEILING_BYTES,
            mem_budget: crate::daemon::mem_budget::MemBudget::new(u64::MAX),
        }
    }
}

// ─── RestoreCoordinator ───────────────────────────────────────────────────────

/// Orchestrates: path resolution → symbol fetch → decode → file write.
pub struct RestoreCoordinator {
    db: Db,
    config: RestoreConfig,
    encoder: Arc<dyn ErasureEncoder>,
    /// Test seam: runs before a file is written to staging (the permit must be gone by then).
    #[cfg(test)]
    pub(crate) write_hook: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl RestoreCoordinator {
    /// Create a new coordinator.
    pub fn new(db: Db, config: RestoreConfig, encoder: Arc<dyn ErasureEncoder>) -> Self {
        RestoreCoordinator {
            db,
            config,
            encoder,
            #[cfg(test)]
            write_hook: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn before_write(&self) {
        if let Some(hook) = self.write_hook.lock().unwrap().as_ref() {
            hook();
        }
    }

    /// Run one restore job to its end.
    ///
    /// 1. Resolve the path (the catalog may have changed since dispatch checked it;
    ///    nothing matched → one `not_backed_up` failure, no job dir).
    /// 2. Job running; open the job dir and write the `running` record before any
    ///    file (restore-i14).
    /// 3. Per file: selectable version or `not_backed_up`; per block by importance:
    ///    decode (source rebuild, else network) or a failure for each of its files;
    ///    a file counts as restored only once it is visible under its own name.
    /// 4. On cancel: every file not yet done → `interrupted`; outcome `interrupted`.
    /// 5. Finish the job in the registry and write the same final record to disk.
    ///
    /// `Ok` means the job is finished in the registry. `Err` only for failures
    /// before the job could start (catalog read, job dir); `run` finishes the job.
    /// Never writes `LocalState` (CS-DR-6): restored files land in staging.
    pub async fn restore(&self, request: RestoreRequest) -> Result<RestoreResult, RestoreError> {
        let job_id = request.job_id;
        let jobs = &self.config.jobs;
        info!(path = %request.path, job = %job_id, "restore started");

        let file_records = resolve_path(&self.db, &request.path)?;
        jobs.mark_running(job_id, &request.path, file_records.len() as u32);
        if file_records.is_empty() {
            // Staging is never cleaned up by the daemon (restore-i8): no job dir.
            jobs.record_failure(
                job_id,
                RestoreFailure {
                    path: request.path.clone(),
                    kind: RestoreFailureKind::NotBackedUp,
                    detail: "no matching files found in the backup catalog".to_string(),
                },
            );
            let record = jobs.finish(job_id, false).expect("job registered above");
            return Ok(Self::result(&record, 0, PathBuf::new()));
        }

        let writer = tokio::task::block_in_place(|| self.begin_job(&request))?;
        let (interrupted, blocks_fetched) =
            self.restore_files(&request, file_records, &writer).await;

        let record = jobs
            .finish(job_id, interrupted)
            .expect("job registered above");
        // Final record: the same data the registry holds, so the outcome survives a
        // restart (restore-i14). If it cannot be written (disk full), the registry
        // stays right until a restart, after which the `running` record on disk reads
        // as `interrupted`: the outcome is only ever understated, never overstated.
        if let Err(e) = tokio::task::block_in_place(|| writer.write_job_record(&record)) {
            error!(
                job = %job_id,
                staging = %writer.staging_path().display(),
                error = %e,
                "restore: could not write the final job record; after a restart this \
                 job will read as interrupted"
            );
        }
        info!(
            job = %job_id,
            outcome = record.outcome.map(|o| o.as_str()).unwrap_or("?"),
            files_restored = record.files_restored,
            files_total = record.files_total,
            failed = record.failures.len(),
            "restore finished"
        );
        Ok(Self::result(
            &record,
            blocks_fetched,
            writer.staging_path().to_path_buf(),
        ))
    }

    fn result(record: &JobRecord, blocks_fetched: usize, staging_path: PathBuf) -> RestoreResult {
        RestoreResult {
            files_restored: record.files_restored as usize,
            blocks_fetched,
            failures: record.failures.clone(),
            staging_path,
            interrupted: record.outcome == Some(crate::cli::types::RestoreOutcome::Interrupted),
        }
    }

    /// Open the job dir and write its `running` record (from the registry) —
    /// before any file is written, so a crash at any later point is reported as
    /// `interrupted`, never as unknown (restore-i14). Blocking I/O.
    pub(crate) fn begin_job(
        &self,
        request: &RestoreRequest,
    ) -> Result<StagingWriter, RestoreError> {
        let writer = StagingWriter::open(
            &self.config.staging_root,
            &self.config.data_dir,
            request.job_id,
        )?;
        let record = self.config.jobs.record(request.job_id).unwrap_or_else(|| {
            // Not registered (only in tests that call begin_job directly).
            JobRecord::running(request.job_id, &request.path, 0)
        });
        writer.write_job_record(&record)?;
        Ok(writer)
    }

    /// Steps 3-4 of `restore`. Every matched file ends in the registry either as
    /// restored or as a failure. Returns (interrupted, blocks decoded).
    async fn restore_files(
        &self,
        request: &RestoreRequest,
        file_records: Vec<FileRecord>,
        writer: &StagingWriter,
    ) -> (bool, usize) {
        let job_id = request.job_id;
        let jobs = &self.config.jobs;
        let fail = |path: &str, kind: RestoreFailureKind, detail: String| {
            jobs.record_failure(
                job_id,
                RestoreFailure {
                    path: path.to_string(),
                    kind,
                    detail,
                },
            );
        };

        // Select a version per file; group files by source block.
        let mut block_map: HashMap<SourceBlockId, Vec<(FileRecord, FileVersion)>> = HashMap::new();
        for record in file_records {
            match Self::select_version(&record, &request.version_selector).cloned() {
                Some(version) => block_map
                    .entry(version.source_block_id)
                    .or_default()
                    .push((record, version)),
                None => fail(
                    &record.path,
                    RestoreFailureKind::NotBackedUp,
                    format!(
                        "no backed-up version matches {:?}",
                        request.version_selector
                    ),
                ),
            }
        }

        // Importance-ordered restore: when restore is interrupted, the user has the
        // high-importance files (documents, photos) before low-importance ones.
        let mut block_order: Vec<(f64, SourceBlockId)> = block_map
            .keys()
            .map(|b| {
                let importance = match self.db.get_source_block(b) {
                    Ok(r) => r.map(|r| r.importance).unwrap_or(0.0),
                    Err(e) => {
                        warn!(block = %b, "restore: cannot read block importance: {e}");
                        0.0
                    }
                };
                (importance, *b)
            })
            .collect();
        block_order.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.1.0.cmp(&b.1.0))
        });

        // CS-DR-3: restore is partial-tolerant. An unrecoverable block is recorded
        // against every file of it and the job moves on to the next block.
        // restore-i26: one pause budget for the whole job, not one per block.
        let mut pauses = NoAnswerPauses::new(job_id, self.config.time_scale);
        let mut blocks_fetched = 0usize;
        for (i, (_, block_id)) in block_order.iter().enumerate() {
            if self.config.cancel.is_cancelled() {
                self.interrupt_remaining(job_id, &block_order[i..], &block_map);
                return (true, blocks_fetched);
            }
            let files_in_block = block_map.get(block_id).expect("block from block_map");
            let plaintext = match self.decode_block(block_id, &mut pauses).await {
                Ok(p) => p,
                Err(RestoreError::Cancelled) => {
                    self.interrupt_remaining(job_id, &block_order[i..], &block_map);
                    return (true, blocks_fetched);
                }
                Err(err) => {
                    error!(block = %block_id, "restore: block not restored: {err}");
                    for (record, _) in files_in_block {
                        fail(&record.path, failure_kind(&err), err.to_string());
                    }
                    continue;
                }
            };
            blocks_fetched += 1;

            // Staging writes are blocking I/O (review A1). One block is written in
            // full even if cancel fires meanwhile (bounded by one block).
            for (record, version) in files_in_block {
                let result = tokio::task::block_in_place(|| {
                    self.extract_and_write_file(
                        record,
                        version,
                        &plaintext.block_type,
                        &plaintext.bytes,
                        writer,
                    )
                });
                match result {
                    Ok(()) => {
                        // CS-DR-6 / restore-i11: restore never writes LocalState.
                        // restore-i14: counted only now, when the complete file is
                        // visible under its own name.
                        jobs.record_restored(job_id, &record.path);
                        info!(path = %record.path, job = %job_id, "restored");
                    }
                    Err(e) => {
                        error!(path = %record.path, "failed to write file: {e}");
                        fail(&record.path, failure_kind(&e), e.to_string());
                    }
                }
            }
        }
        (false, blocks_fetched)
    }

    /// Cancel (T10): every file of the blocks not done yet → `interrupted`.
    fn interrupt_remaining(
        &self,
        job_id: JobId,
        remaining: &[(f64, SourceBlockId)],
        block_map: &HashMap<SourceBlockId, Vec<(FileRecord, FileVersion)>>,
    ) {
        info!(job = %job_id, "restore: daemon shutting down; job interrupted");
        for (_, block_id) in remaining {
            for (record, _) in block_map.get(block_id).into_iter().flatten() {
                self.config.jobs.record_failure(
                    job_id,
                    RestoreFailure {
                        path: record.path.clone(),
                        kind: RestoreFailureKind::Interrupted,
                        detail: "daemon shutting down".to_string(),
                    },
                );
            }
        }
    }

    /// Look up the block record and decode the block.
    async fn decode_block(
        &self,
        block_id: &SourceBlockId,
        pauses: &mut NoAnswerPauses,
    ) -> Result<DecodedBlock, RestoreError> {
        let block_record = self
            .db
            .get_source_block(block_id)?
            .ok_or(RestoreError::BlockNotFound(*block_id))?;
        let encrypted_size = block_record
            .encrypted_size
            .ok_or(RestoreError::LegacyRecord(*block_id))?;
        let params = block_record.erasure_params();
        let bytes = self
            .decode_block_local(block_id, &params, encrypted_size, pauses)
            .await?;
        Ok(DecodedBlock {
            block_type: block_record.block_type,
            bytes,
        })
    }

    /// Select which FileVersion to restore.
    ///
    /// - `Latest`:      last version with `backed_up_at.is_some()`
    /// - `Index(n)`:    `versions[n]`, but only if it has `backed_up_at.is_some()`
    /// - `BeforeDate`:  last version with `backed_up_at.is_some() && backed_up_at <= ts`
    ///
    /// CS-DR-14: `Index` applies the same `backed_up_at.is_some()` filter as the
    /// other selectors — a never-backed-up (queued-only) version has no symbols
    /// placed, so selecting it would only produce a loud `BlockNotFound`.
    pub fn select_version<'a>(
        record: &'a FileRecord,
        selector: &VersionSelector,
    ) -> Option<&'a FileVersion> {
        match selector {
            VersionSelector::Latest => record
                .versions
                .iter()
                .rev()
                .find(|v| v.backed_up_at.is_some()),
            VersionSelector::Index(n) => {
                record.versions.get(*n).filter(|v| v.backed_up_at.is_some())
            }
            VersionSelector::BeforeDate(ts) => record
                .versions
                .iter()
                .rev()
                .find(|v| v.backed_up_at.map(|t| t.0 <= ts.0).unwrap_or(false)),
        }
    }

    /// Run the coordinator as a tokio task: jobs one at a time, in submit order.
    ///
    /// Returns on the daemon's cancel token (a running job stops and is recorded
    /// `interrupted` first) or when the channel closes. After each job the cached
    /// staging status is refreshed and, under holder pressure, the staging warning
    /// logged at once (restore-i8, i20) — here, not on the HTTP path.
    pub async fn run(
        self,
        mut rx: tokio::sync::mpsc::Receiver<RestoreRequest>,
    ) -> anyhow::Result<()> {
        info!("RestoreCoordinator started");
        loop {
            let request = tokio::select! {
                _ = self.config.cancel.cancelled() => break,
                r = rx.recv() => match r {
                    Some(r) => r,
                    None => break,
                },
            };
            let (job_id, path) = (request.job_id, request.path.clone());
            if let Err(e) = self.restore(request).await {
                error!(job = %job_id, "restore job failed before it could start: {e}");
                self.config.jobs.record_failure(
                    job_id,
                    RestoreFailure {
                        path,
                        kind: failure_kind(&e),
                        detail: e.to_string(),
                    },
                );
                self.config.jobs.finish(job_id, false);
            }
            if self.config.cancel.is_cancelled() {
                break;
            }
            self.refresh_staging_status();
        }
        info!("RestoreCoordinator stopped");
        Ok(())
    }

    /// Re-count staging into the cached status; WARN when staging squeezes
    /// friends' data (restore-i20). Blocking I/O.
    fn refresh_staging_status(&self) {
        let (summary, stops_taking_data) = tokio::task::block_in_place(|| {
            (
                cleanup::staging_summary(&self.config.staging_root),
                self.config
                    .pressure
                    .as_ref()
                    .is_some_and(|p| p.stops_taking_data()),
            )
        });
        self.config
            .staging_status
            .lock()
            .expect("restore staging status lock poisoned")
            .apply(summary);
        cleanup::warn_if_squeezing(stops_taking_data, Some(summary.bytes));
    }
}

/// A decoded block: its plaintext and whether it is a pack.
struct DecodedBlock {
    block_type: viaticum_core::types::SourceBlockType,
    bytes: Vec<u8>,
}

// ─── Free helpers ─────────────────────────────────────────────────────────────

/// Resolve a user-supplied restore path to catalog records.
///
/// Trailing separator ('/' or `MAIN_SEPARATOR`) → directory prefix query. Otherwise
/// the exact record first; if none, the directory prefix `path + sep` — the prefix
/// matches only on a separator boundary (CS-DR-10: "docs/repo" must not capture
/// "docs/repo-old").
pub(crate) fn resolve_path(
    db: &Db,
    path: &str,
) -> Result<Vec<FileRecord>, viaticum_core::db::DbError> {
    const SEP: char = std::path::MAIN_SEPARATOR;
    if path.ends_with('/') || path.ends_with(SEP) {
        return db.list_files_with_prefix(path);
    }
    if let Some(record) = db.get_file(path)? {
        return Ok(vec![record]);
    }
    let mut records = db.list_files_with_prefix(&format!("{path}/"))?;
    if SEP != '/' {
        let seen: std::collections::HashSet<_> = records.iter().map(|r| r.file_id).collect();
        for r in db.list_files_with_prefix(&format!("{path}{SEP}"))? {
            if !seen.contains(&r.file_id) {
                records.push(r);
            }
        }
    }
    Ok(records)
}

// Re-export shared helper from core (review A3).
#[cfg(test)]
pub(crate) use viaticum_core::types::ranges_to_esi_list as collect_esis_from_ranges;
