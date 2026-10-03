// Web API: axum JSON server wrapping the existing dispatch() handlers.

mod budget;
mod embedded;

#[cfg(test)]
pub(crate) mod tests;

// ── Security headers middleware ───────────────────────────────────────────────

/// Attach security-related headers to every HTTP response:
///   Referrer-Policy: no-referrer        — prevents Referer leaks (token in URL)
///   X-Content-Type-Options: nosniff     — blocks MIME sniffing
///   X-Frame-Options: DENY               — prevents clickjacking
pub(super) async fn add_security_headers(
    response: axum::response::Response,
) -> axum::response::Response {
    use axum::http::HeaderValue;
    let mut response = response;
    let headers = response.headers_mut();
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
}

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use tokio_util::sync::CancellationToken;

use crate::cli::types::{
    CliRequest, CliResponse, DeviceEntry, FileEntry, StatusData, VersionEntry,
};
use crate::daemon::config_admin::{ConfigAdminError, EditableConfig};
use crate::daemon::dispatch::dispatch;
use crate::daemon::handle::DaemonState;
use crate::daemon::watch_admin::{
    AddWatchRequest, DeleteWatchQuery, PatchWatchRequest, WatchAdminError, WatchDefaults,
    WatchEntry,
};
use crate::daemon::web_auth::{AuthState, auth_start_handler, require_auth};

// ── Public API ────────────────────────────────────────────────────────────────

/// Configuration for the web API server.
pub struct WebApiConfig {
    pub bind: String,
    pub static_dir: Option<PathBuf>,
}

/// Start the web API server. Returns a JoinHandle that runs until `cancel` fires.
pub async fn start(
    config: WebApiConfig,
    cancel: CancellationToken,
    state: Arc<DaemonState>,
    auth: AuthState,
) -> Result<tokio::task::JoinHandle<anyhow::Result<()>>, anyhow::Error> {
    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    start_with_listener(config, listener, cancel, state, auth).await
}

/// Like `start`, but uses an already-bound listener. Used by the daemon
/// when it needs to read the actual port before starting (e.g. to write
/// it to the api-port file).
pub async fn start_with_listener(
    config: WebApiConfig,
    listener: tokio::net::TcpListener,
    cancel: CancellationToken,
    state: Arc<DaemonState>,
    auth: AuthState,
) -> Result<tokio::task::JoinHandle<anyhow::Result<()>>, anyhow::Error> {
    let mut app = authed_router(state, auth);

    if let Some(ref dir) = config.static_dir {
        if dir.exists() {
            use tower_http::services::{ServeDir, ServeFile};
            let index = dir.join("index.html");
            let serve = ServeDir::new(dir).fallback(ServeFile::new(index));
            app = app.fallback_service(serve);
        } else {
            tracing::warn!(
                path = %dir.display(),
                "static_dir does not exist, falling back to embedded assets"
            );
            app = app.fallback(embedded::handle_embedded);
        }
    } else {
        app = app.fallback(embedded::handle_embedded);
    }

    // Apply security headers to every response, regardless of route.
    let app = app.layer(axum::middleware::map_response(add_security_headers));

    let actual = listener.local_addr()?;
    tracing::info!(bind = %actual, "web API server started");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(cancel.cancelled_owned())
            .await
            .map_err(|e| anyhow::anyhow!("web API server error: {e}"))
    });

    Ok(handle)
}

/// `/api/*` behind `require_auth`, plus `/auth/start` (no static files).
pub(crate) fn authed_router(state: Arc<DaemonState>, auth: AuthState) -> Router {
    let api = api_routes()
        .with_state(state)
        .route_layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            require_auth,
        ));
    let auth_routes = Router::new()
        .route("/auth/start", axum::routing::get(auth_start_handler))
        .with_state(auth);
    api.merge(auth_routes)
}

/// Every `/api/*` route, without state and auth (see `authed_router`).
fn api_routes() -> Router<Arc<DaemonState>> {
    Router::new()
        .route("/api/status", axum::routing::get(handle_status))
        .route("/api/files", axum::routing::get(handle_files))
        .route("/api/versions", axum::routing::get(handle_versions))
        .route("/api/restore", axum::routing::post(handle_restore))
        .route("/api/restore/jobs", axum::routing::get(handle_restore_jobs))
        .route(
            "/api/restore/jobs/{job_id}",
            axum::routing::get(handle_restore_job),
        )
        .route(
            "/api/devices",
            axum::routing::get(handle_devices).post(handle_device_add),
        )
        .route(
            "/api/devices/{device_id}",
            axum::routing::delete(handle_device_revoke),
        )
        .route("/api/connect", axum::routing::post(handle_connect))
        .route(
            "/api/watches",
            axum::routing::get(handle_watches_list).post(handle_watches_add),
        )
        .route(
            "/api/watches/defaults",
            axum::routing::get(handle_watches_defaults),
        )
        .route(
            "/api/watches/refresh",
            axum::routing::post(handle_watches_refresh),
        )
        .route(
            "/api/watches/{path_b64}",
            axum::routing::patch(handle_watches_patch).delete(handle_watches_delete),
        )
        .route(
            "/api/watches/{path_b64}/scan",
            axum::routing::post(handle_watches_scan),
        )
        .route("/api/browse", axum::routing::get(handle_browse))
        .route(
            "/api/config",
            axum::routing::get(handle_config_get).put(handle_config_put),
        )
        .route("/api/restart", axum::routing::post(handle_restart))
        // К-b3 (spec v3.9a): a DR on this machine leases the memory of one SS block at a time.
        .route(
            "/api/budget/lease",
            axum::routing::post(budget::handle_lease),
        )
        .route(
            "/api/budget/release",
            axum::routing::post(budget::handle_release),
        )
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handle_status(
    State(state): State<Arc<DaemonState>>,
) -> Result<Json<StatusData>, (StatusCode, String)> {
    match dispatch(CliRequest::Status, &state).await {
        CliResponse::Status(data) => Ok(Json(*data)),
        CliResponse::Error(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected response".into(),
        )),
    }
}

#[derive(serde::Deserialize)]
struct FilesQuery {
    prefix: Option<String>,
}

async fn handle_files(
    State(state): State<Arc<DaemonState>>,
    Query(q): Query<FilesQuery>,
) -> Result<Json<Vec<FileEntry>>, (StatusCode, String)> {
    match dispatch(
        CliRequest::Files {
            path_prefix: q.prefix,
        },
        &state,
    )
    .await
    {
        CliResponse::Files(data) => Ok(Json(data)),
        CliResponse::Error(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected response".into(),
        )),
    }
}

#[derive(serde::Deserialize)]
struct VersionsQuery {
    path: String,
}

async fn handle_versions(
    State(state): State<Arc<DaemonState>>,
    Query(q): Query<VersionsQuery>,
) -> Result<Json<Vec<VersionEntry>>, (StatusCode, String)> {
    match dispatch(CliRequest::Versions { path: q.path }, &state).await {
        CliResponse::Versions(data) => Ok(Json(data)),
        CliResponse::Error(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected response".into(),
        )),
    }
}

#[derive(serde::Deserialize)]
struct RestoreBody {
    path: String,
    version: Option<u32>,
    date: Option<String>,
    dest: Option<String>,
}

async fn handle_restore(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<RestoreBody>,
) -> axum::response::Response {
    let req = CliRequest::Restore {
        path: body.path,
        version: body.version,
        date: body.date,
        dest: body.dest,
    };
    restore_response(dispatch(req, &state).await, StatusCode::ACCEPTED)
}

async fn handle_restore_jobs(State(state): State<Arc<DaemonState>>) -> axum::response::Response {
    restore_response(
        dispatch(CliRequest::RestoreJobList, &state).await,
        StatusCode::OK,
    )
}

async fn handle_restore_job(
    State(state): State<Arc<DaemonState>>,
    axum::extract::Path(job_id): axum::extract::Path<String>,
) -> axum::response::Response {
    restore_response(
        dispatch(CliRequest::RestoreJobStatus { job_id }, &state).await,
        StatusCode::OK,
    )
}

/// HTTP shape of the restore responses: a job or the job list → `ok` (202 for a
/// submitted job, 200 for a lookup), a rejection → its status
/// (`RestoreRejection::http_status`) with the rejection as JSON
/// (`{"error": "<kind>", ...}`).
fn restore_response(response: CliResponse, ok: StatusCode) -> axum::response::Response {
    use axum::response::IntoResponse;
    match response {
        CliResponse::RestoreJob(job) => (ok, Json(job)).into_response(),
        CliResponse::RestoreJobs(jobs) => (ok, Json(jobs)).into_response(),
        CliResponse::RestoreRejected(rejection) => {
            let status = StatusCode::from_u16(rejection.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, Json(rejection)).into_response()
        }
        CliResponse::Error(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "unexpected response").into_response(),
    }
}

async fn handle_devices(
    State(state): State<Arc<DaemonState>>,
) -> Result<Json<Vec<DeviceEntry>>, (StatusCode, String)> {
    match dispatch(CliRequest::DeviceList, &state).await {
        CliResponse::DeviceList(data) => Ok(Json(data)),
        CliResponse::Error(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected response".into(),
        )),
    }
}

#[derive(serde::Deserialize)]
struct DeviceAddBody {
    label: String,
}

async fn handle_device_add(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<DeviceAddBody>,
) -> Result<Json<DeviceEntry>, (StatusCode, String)> {
    match dispatch(CliRequest::DeviceAdd { label: body.label }, &state).await {
        CliResponse::DeviceAdded(entry) => Ok(Json(entry)),
        CliResponse::Error(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected response".into(),
        )),
    }
}

async fn handle_device_revoke(
    State(state): State<Arc<DaemonState>>,
    axum::extract::Path(device_id_hex): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match dispatch(CliRequest::DeviceRevoke { device_id_hex }, &state).await {
        // 200 + JSON (not 204): the CLI must learn `holders_skipped` (dr-i8).
        CliResponse::DeviceRevoked {
            device_id_hex,
            holders_skipped,
        } => Ok(Json(serde_json::json!({
            "device_id_hex": device_id_hex,
            "holders_skipped": holders_skipped,
        }))),
        CliResponse::Error(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected response".into(),
        )),
    }
}

#[derive(serde::Deserialize)]
struct ConnectBody {
    addr: String,
}

async fn handle_connect(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<ConnectBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match dispatch(CliRequest::Connect { addr: body.addr }, &state).await {
        CliResponse::Connected { peer_id } => Ok(Json(serde_json::json!({ "peer_id": peer_id }))),
        CliResponse::Error(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "unexpected response".into(),
        )),
    }
}

// ── Watch management handlers ─────────────────────────────────────────────────

/// Map WatchAdminError to (StatusCode, String).
fn watch_admin_err(e: WatchAdminError) -> (StatusCode, String) {
    let status = match &e {
        WatchAdminError::NotFound(_) => StatusCode::NOT_FOUND,
        WatchAdminError::NotADirectory(_)
        | WatchAdminError::NotAbsolute(_)
        | WatchAdminError::DaemonStorage { .. } => StatusCode::BAD_REQUEST,
        WatchAdminError::Nested { .. } => StatusCode::CONFLICT,
        WatchAdminError::ConfigSave(_) | WatchAdminError::Db(_) | WatchAdminError::WatcherGone => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    (status, e.to_string())
}

/// Helper: get watch_admin or return 503 Service Unavailable.
fn require_watch_admin(
    state: &DaemonState,
) -> Result<&std::sync::Arc<crate::daemon::watch_admin::WatchAdmin>, (StatusCode, String)> {
    state.watch_admin.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "watch admin not available".to_string(),
        )
    })
}

async fn handle_watches_list(
    State(state): State<Arc<DaemonState>>,
) -> Result<Json<Vec<WatchEntry>>, (StatusCode, String)> {
    let admin = require_watch_admin(&state)?;
    Ok(Json(admin.list_watches()))
}

async fn handle_watches_defaults() -> Json<WatchDefaults> {
    use viaticum_core::config::DEFAULT_IMPORTANCE_MULTIPLIER;
    Json(WatchDefaults {
        importance_multiplier: DEFAULT_IMPORTANCE_MULTIPLIER,
    })
}

async fn handle_watches_add(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<AddWatchRequest>,
) -> Result<(StatusCode, Json<WatchEntry>), (StatusCode, String)> {
    let admin = require_watch_admin(&state)?;
    let entry = admin.add_watch(body).await.map_err(watch_admin_err)?;
    Ok((StatusCode::CREATED, Json(entry)))
}

async fn handle_watches_patch(
    State(state): State<Arc<DaemonState>>,
    axum::extract::Path(path_b64): axum::extract::Path<String>,
    Json(body): Json<PatchWatchRequest>,
) -> Result<Json<WatchEntry>, (StatusCode, String)> {
    let admin = require_watch_admin(&state)?;
    let entry = admin
        .patch_watch(&path_b64, body)
        .await
        .map_err(watch_admin_err)?;
    Ok(Json(entry))
}

async fn handle_watches_delete(
    State(state): State<Arc<DaemonState>>,
    axum::extract::Path(path_b64): axum::extract::Path<String>,
    Query(q): Query<DeleteWatchQuery>,
) -> Result<StatusCode, (StatusCode, String)> {
    let admin = require_watch_admin(&state)?;
    admin
        .remove_watch(&path_b64, q.purge)
        .await
        .map_err(watch_admin_err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn handle_watches_scan(
    State(state): State<Arc<DaemonState>>,
    axum::extract::Path(path_b64): axum::extract::Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let admin = require_watch_admin(&state)?;
    admin.scan_watch(&path_b64).await.map_err(watch_admin_err)?;
    Ok(StatusCode::ACCEPTED)
}

async fn handle_watches_refresh(
    State(state): State<Arc<DaemonState>>,
) -> Result<StatusCode, (StatusCode, String)> {
    let admin = require_watch_admin(&state)?;
    admin.recompute_all_rollups().map_err(watch_admin_err)?;
    Ok(StatusCode::OK)
}

// ── Config + restart handlers ─────────────────────────────────────────────────

fn require_config_admin(
    state: &DaemonState,
) -> Result<&std::sync::Arc<crate::daemon::config_admin::ConfigAdmin>, (StatusCode, String)> {
    state.config_admin.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "config admin not available".to_string(),
        )
    })
}

async fn handle_config_get(
    State(state): State<Arc<DaemonState>>,
) -> Result<Json<EditableConfig>, (StatusCode, String)> {
    let admin = require_config_admin(&state)?;
    admin
        .read_editable()
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

#[derive(serde::Serialize)]
struct ConfigPutOk {
    ok: bool,
}

#[derive(serde::Serialize)]
struct ConfigPutErr {
    field: String,
    error: String,
}

async fn handle_config_put(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<EditableConfig>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let admin = match require_config_admin(&state) {
        Ok(a) => a,
        Err((s, msg)) => return (s, msg).into_response(),
    };
    match admin.update(body).await {
        Ok(()) => (StatusCode::OK, Json(ConfigPutOk { ok: true })).into_response(),
        Err(ConfigAdminError::Validation { field, msg }) => (
            StatusCode::BAD_REQUEST,
            Json(ConfigPutErr { field, error: msg }),
        )
            .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(serde::Serialize)]
struct RestartScheduled {
    scheduled: bool,
}

async fn handle_restart(
    State(state): State<Arc<DaemonState>>,
) -> Result<(StatusCode, Json<RestartScheduled>), (StatusCode, String)> {
    let gate = state.restart_gate.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "restart gate not available".to_string(),
        )
    })?;
    // Spawn the actual rexec on a blocking task so we can return 202 promptly,
    // then let the runtime drain on the cancelled token.
    let gate = gate.clone();
    let token = state.shutdown_token.clone();
    tokio::spawn(async move {
        // Tiny grace period so the 202 response actually lands at the client
        // before the swarm starts dropping connections.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        gate.trigger(&token);
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(RestartScheduled { scheduled: true }),
    ))
}

// ── Filesystem browser ────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct BrowseQuery {
    path: Option<String>,
}

#[derive(serde::Serialize)]
struct BrowseEntry {
    name: String,
    is_dir: bool,
}

#[derive(serde::Serialize)]
struct BrowseResponse {
    path: String,
    parent: Option<String>,
    entries: Vec<BrowseEntry>,
}

/// List subdirectories of a given path, default to user home.
/// Used by the "Browse" picker in the Add-folder dialog.
async fn handle_browse(
    Query(q): Query<BrowseQuery>,
) -> Result<Json<BrowseResponse>, (StatusCode, String)> {
    let raw = q.path.unwrap_or_else(|| "~".to_string());
    let expanded = if let Some(rest) = raw.strip_prefix("~") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
        PathBuf::from(format!("{home}{rest}"))
    } else {
        PathBuf::from(&raw)
    };
    let canonical = expanded.canonicalize().map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("cannot resolve {}: {e}", expanded.display()),
        )
    })?;
    if !canonical.is_dir() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("not a directory: {}", canonical.display()),
        ));
    }
    let read = std::fs::read_dir(&canonical)
        .map_err(|e| (StatusCode::FORBIDDEN, format!("cannot read directory: {e}")))?;
    let mut entries: Vec<BrowseEntry> = read
        .filter_map(|res| res.ok())
        .filter_map(|d| {
            let name = d.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                return None;
            }
            let is_dir = d.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if !is_dir {
                return None;
            }
            Some(BrowseEntry { name, is_dir })
        })
        .collect();
    entries.sort_by_key(|a| a.name.to_lowercase());
    let parent = canonical.parent().map(|p| p.to_string_lossy().into_owned());
    Ok(Json(BrowseResponse {
        path: canonical.to_string_lossy().into_owned(),
        parent,
        entries,
    }))
}
