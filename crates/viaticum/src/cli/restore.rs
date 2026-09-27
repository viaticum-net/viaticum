//! `viaticum restore`: submit a restore job and follow it (restore-i3, i4, i15).
//!
//! The daemon answers the submit at once with the job; by default the CLI then
//! polls the job every 2 s with no overall deadline and exits by its outcome
//! (0 complete, 2 partial, 1 nothing restored / interrupted / refused / lost
//! contact). Ctrl-C kills only this process: the job keeps running in the daemon,
//! and its id is printed before the wait so it can be looked up later
//! (`--status <id>`). The 30 s HTTP timeout is per request, never per job.

use std::io::Write;
use std::time::Duration;

use crate::cli::Connection;
use crate::cli::output;
use crate::cli::types::{CliError, RestoreJob, RestoreJobState, RestoreRejection};

/// Poll interval while waiting for a job.
pub const POLL_EVERY: Duration = Duration::from_secs(2);
/// Consecutive failed polls, counted in poll intervals, before "lost contact".
pub const MAX_SILENCE: Duration = Duration::from_secs(60);
/// A progress line at most this often (only when something changed).
pub const PROGRESS_EVERY: Duration = Duration::from_secs(10);
/// Timeout of one HTTP request (not of the job).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout of one status poll: a hung daemon must not stretch "lost contact".
const POLL_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Arguments of `viaticum restore`.
#[derive(Debug, Clone, Copy)]
pub struct RestoreArgs<'a> {
    pub path: Option<&'a str>,
    pub version: Option<u32>,
    pub date: Option<&'a str>,
    pub dest: Option<&'a str>,
    pub no_wait: bool,
    /// `Some("")`: list recent jobs; `Some(id)`: one job.
    pub status: Option<&'a str>,
    pub json: bool,
}

/// When `wait_for_job` polls, gives up and reports progress.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WaitPolicy {
    pub poll_every: Duration,
    /// Consecutive failed polls (as `poll_every` × count) before giving up.
    pub max_silence: Duration,
    /// Minimum time (in poll intervals) between two progress reports.
    pub progress_every: Duration,
}

impl WaitPolicy {
    pub(crate) const DEFAULT: WaitPolicy = WaitPolicy {
        poll_every: POLL_EVERY,
        max_silence: MAX_SILENCE,
        progress_every: PROGRESS_EVERY,
    };
}

/// Why waiting ended without a finished job.
#[derive(Debug)]
pub(crate) enum WaitError {
    /// The daemon did not answer for `max_silence`, or no longer knows the job
    /// (restarted before the job dir existed).
    LostContact { last_known: Option<Box<RestoreJob>> },
}

/// Poll `fetch` until the job is finished. `fetch` returns `Ok(None)` when the
/// daemon does not know the job. Progress is reported only when the state or the
/// counts changed, at most once per `progress_every`. Time is counted in poll
/// intervals (`sleep` is injected), so the function is deterministic in tests.
pub(crate) fn wait_for_job<F, S, P>(
    mut fetch: F,
    mut sleep: S,
    mut on_progress: P,
    policy: WaitPolicy,
) -> Result<RestoreJob, WaitError>
where
    F: FnMut() -> Result<Option<RestoreJob>, CliError>,
    S: FnMut(Duration),
    P: FnMut(&RestoreJob),
{
    let mut last_known: Option<RestoreJob> = None;
    let mut last_reported: Option<(RestoreJobState, u32, usize)> = None;
    let mut since_report = policy.progress_every;
    let mut silence = Duration::ZERO;
    loop {
        match fetch() {
            Ok(Some(job)) => {
                silence = Duration::ZERO;
                if job.state == RestoreJobState::Finished {
                    return Ok(job);
                }
                let key = (job.state, job.files_restored, job.failures.len());
                if last_reported != Some(key) && since_report >= policy.progress_every {
                    on_progress(&job);
                    last_reported = Some(key);
                    since_report = Duration::ZERO;
                }
                last_known = Some(job);
            }
            Ok(None) => {
                return Err(WaitError::LostContact {
                    last_known: last_known.map(Box::new),
                });
            }
            Err(_) => {
                silence += policy.poll_every;
                if silence > policy.max_silence {
                    return Err(WaitError::LostContact {
                        last_known: last_known.map(Box::new),
                    });
                }
            }
        }
        sleep(policy.poll_every);
        since_report += policy.poll_every;
    }
}

/// The daemon's restore endpoints, as the CLI uses them. `HttpApi` in production;
/// tests script a fake (there is deliberately no "cancel job" call: Ctrl-C of the
/// CLI must never stop the job, restore-i15).
pub(crate) trait RestoreApi {
    /// POST /api/restore: the accepted job, or the daemon's rejection.
    fn submit(&self, body: String) -> Result<Result<RestoreJob, RestoreRejection>, CliError>;
    /// GET /api/restore/jobs/{id}: the job, or `None` when the daemon does not know it.
    fn get_job(&self, job_id: &str) -> Result<Option<RestoreJob>, CliError>;
    /// GET /api/restore/jobs: recent jobs, newest first.
    fn list_jobs(&self) -> Result<Vec<RestoreJob>, CliError>;
}

/// Run `viaticum restore`; returns the process exit code.
pub fn run_restore(args: RestoreArgs<'_>, conn: &Connection) -> Result<i32, CliError> {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    run_restore_with(
        args,
        &HttpApi { conn },
        &mut stdout.lock(),
        &mut stderr.lock(),
        &mut std::thread::sleep,
        WaitPolicy::DEFAULT,
    )
}

/// `run_restore` over an injected API, output streams, sleep and wait policy.
pub(crate) fn run_restore_with(
    args: RestoreArgs<'_>,
    api: &dyn RestoreApi,
    out: &mut dyn Write,
    err: &mut dyn Write,
    sleep: &mut dyn FnMut(Duration),
    policy: WaitPolicy,
) -> Result<i32, CliError> {
    if let Some(id) = args.status {
        return if id.is_empty() {
            let jobs = api.list_jobs()?;
            if args.json {
                writeln!(out, "{}", to_json(&jobs)?)?;
            } else {
                write!(out, "{}", output::render_restore_jobs(&jobs))?;
            }
            Ok(0)
        } else {
            match api.get_job(id)? {
                Some(job) => {
                    if args.json {
                        writeln!(out, "{}", to_json(&job)?)?;
                    } else if job.state == RestoreJobState::Finished {
                        write!(out, "{}", output::render_restore_finished(&job))?;
                    } else {
                        write!(out, "{}", output::render_restore_progress(&job))?;
                    }
                    Ok(0)
                }
                None => {
                    let rejection = RestoreRejection::UnknownJob {
                        job_id: id.to_string(),
                    };
                    write!(err, "{}", output::render_restore_rejection(&rejection))?;
                    Ok(1)
                }
            }
        };
    }

    let path = args.path.ok_or_else(|| {
        CliError::InvalidArgument("restore needs a PATH (or --status [JOB_ID])".into())
    })?;
    if args.version.is_some() && args.date.is_some() {
        return Err(CliError::InvalidArgument(
            "cannot specify both --version and --date".into(),
        ));
    }
    if args.version == Some(0) {
        return Err(CliError::InvalidArgument("--version must be >= 1".into()));
    }

    let body = serde_json::json!({
        "path": path,
        "version": args.version,
        "date": args.date,
        "dest": args.dest,
    })
    .to_string();
    let job = match api.submit(body)? {
        Ok(job) => job,
        Err(rejection) => {
            write!(err, "{}", output::render_restore_rejection(&rejection))?;
            return Ok(1);
        }
    };
    // Before waiting, so Ctrl-C during the wait never loses the job id (i15).
    if args.json {
        writeln!(out, "{}", to_json(&job)?)?;
    } else {
        write!(out, "{}", output::render_restore_submitted(&job))?;
    }
    out.flush()?;
    if args.no_wait {
        return Ok(0);
    }

    let mut progress_err: Option<std::io::Error> = None;
    let waited = wait_for_job(
        || api.get_job(&job.job_id),
        sleep,
        |j| {
            if !args.json
                && let Err(e) =
                    write!(out, "{}", output::render_restore_progress(j)).and_then(|()| out.flush())
            {
                progress_err.get_or_insert(e);
            }
        },
        policy,
    );
    if let Some(e) = progress_err {
        return Err(CliError::Io(e));
    }
    match waited {
        Ok(done) => {
            if args.json {
                writeln!(out, "{}", to_json(&done)?)?;
            } else {
                write!(out, "{}", output::render_restore_finished(&done))?;
            }
            Ok(done.outcome.map(|o| o.exit_code()).unwrap_or(1))
        }
        Err(WaitError::LostContact { last_known }) => {
            let staging = last_known
                .as_ref()
                .map(|j| j.staging_path.as_str())
                .unwrap_or(job.staging_path.as_str());
            write!(
                err,
                "{}",
                output::render_restore_lost_contact(&job.job_id, staging)
            )?;
            Ok(1)
        }
    }
}

fn to_json<T: serde::Serialize>(v: &T) -> Result<String, CliError> {
    serde_json::to_string(v).map_err(|e| CliError::Encode(e.to_string()))
}

/// The restore endpoints over HTTP.
struct HttpApi<'a> {
    conn: &'a Connection,
}

impl RestoreApi for HttpApi<'_> {
    fn submit(&self, body: String) -> Result<Result<RestoreJob, RestoreRejection>, CliError> {
        let (status, text) = http(
            self.conn,
            reqwest::Method::POST,
            "/api/restore",
            Some(body),
            REQUEST_TIMEOUT,
        )?;
        if (200..300).contains(&status) {
            return serde_json::from_str(&text)
                .map(Ok)
                .map_err(|e| CliError::Decode(format!("restore job: {e}")));
        }
        match serde_json::from_str::<RestoreRejection>(&text) {
            Ok(rejection) => Ok(Err(rejection)),
            Err(_) => Err(CliError::DaemonError(format!("HTTP {status}: {text}"))),
        }
    }

    fn get_job(&self, job_id: &str) -> Result<Option<RestoreJob>, CliError> {
        let path = format!("/api/restore/jobs/{}", urlencoding::encode(job_id));
        let (status, text) = http(
            self.conn,
            reqwest::Method::GET,
            &path,
            None,
            POLL_REQUEST_TIMEOUT,
        )?;
        if (200..300).contains(&status) {
            return serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| CliError::Decode(format!("restore job: {e}")));
        }
        match serde_json::from_str::<RestoreRejection>(&text) {
            Ok(RestoreRejection::UnknownJob { .. }) => Ok(None),
            _ => Err(CliError::DaemonError(format!("HTTP {status}: {text}"))),
        }
    }

    fn list_jobs(&self) -> Result<Vec<RestoreJob>, CliError> {
        let (status, text) = http(
            self.conn,
            reqwest::Method::GET,
            "/api/restore/jobs",
            None,
            REQUEST_TIMEOUT,
        )?;
        if !(200..300).contains(&status) {
            return Err(CliError::DaemonError(format!("HTTP {status}: {text}")));
        }
        serde_json::from_str(&text).map_err(|e| CliError::Decode(format!("restore jobs: {e}")))
    }
}

/// One HTTP request with the bearer token; (status, body). 401 → `Unauthorized`,
/// transport failure → `DaemonNotReachable`.
fn http(
    conn: &Connection,
    method: reqwest::Method,
    path: &str,
    body: Option<String>,
    timeout: Duration,
) -> Result<(u16, String), CliError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| CliError::Io(std::io::Error::other(e.to_string())))?;
    let url = format!("{}{}", conn.url.trim_end_matches('/'), path);
    let mut req = client.request(method, &url).bearer_auth(&conn.token);
    if let Some(b) = body {
        req = req.header("content-type", "application/json").body(b);
    }
    let resp = req.send().map_err(|e| CliError::DaemonNotReachable {
        reason: format!("HTTP request failed: {e}"),
    })?;
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(CliError::Unauthorized);
    }
    let status = resp.status().as_u16();
    let text = resp.text().map_err(|e| CliError::DaemonNotReachable {
        reason: format!("reading the response failed: {e}"),
    })?;
    Ok((status, text))
}
