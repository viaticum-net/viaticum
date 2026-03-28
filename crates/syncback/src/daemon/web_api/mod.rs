// Web API: axum JSON server wrapping the existing dispatch() handlers.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::Router;
use tokio_util::sync::CancellationToken;

use crate::cli::types::{
    CliRequest, CliResponse, DeviceEntry, FileEntry, RestoreData, StatusData, VersionEntry,
};
use crate::daemon::cli_server::dispatch;
use crate::daemon::handle::DaemonState;

// ── Public API ────────────────────────────────────────────────────────────────

/// Configuration for the web API server.
pub struct WebApiConfig {
    pub port: u16,
    pub static_dir: Option<PathBuf>,
}

/// Start the web API server. Returns a JoinHandle that runs until `cancel` fires.
pub async fn start(
    config: WebApiConfig,
    cancel: CancellationToken,
    state: Arc<DaemonState>,
) -> Result<tokio::task::JoinHandle<anyhow::Result<()>>, anyhow::Error> {
    let mut app = Router::new()
        .route("/api/status", axum::routing::get(handle_status))
        .route("/api/files", axum::routing::get(handle_files))
        .route("/api/versions", axum::routing::get(handle_versions))
        .route("/api/restore", axum::routing::post(handle_restore))
        .route("/api/devices", axum::routing::get(handle_devices))
        .route("/api/connect", axum::routing::post(handle_connect))
        .with_state(state);

    // Serve static files (SPA) if configured.
    if let Some(ref dir) = config.static_dir {
        if dir.exists() {
            use tower_http::services::{ServeDir, ServeFile};
            let index = dir.join("index.html");
            let serve = ServeDir::new(dir).fallback(ServeFile::new(index));
            app = app.fallback_service(serve);
        } else {
            tracing::warn!(path = %dir.display(), "web_api static_dir does not exist, skipping static file serving");
        }
    }

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port)).await?;
    tracing::info!(port = config.port, "web API server started");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(cancel.cancelled_owned())
            .await
            .map_err(|e| anyhow::anyhow!("web API server error: {e}"))
    });

    Ok(handle)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handle_status(
    State(state): State<Arc<DaemonState>>,
) -> Result<Json<StatusData>, (StatusCode, String)> {
    match dispatch(CliRequest::Status, &state).await {
        CliResponse::Status(data) => Ok(Json(data)),
        CliResponse::Error(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((StatusCode::INTERNAL_SERVER_ERROR, "unexpected response".into())),
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
    match dispatch(CliRequest::Files { path_prefix: q.prefix }, &state).await {
        CliResponse::Files(data) => Ok(Json(data)),
        CliResponse::Error(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((StatusCode::INTERNAL_SERVER_ERROR, "unexpected response".into())),
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
        _ => Err((StatusCode::INTERNAL_SERVER_ERROR, "unexpected response".into())),
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
) -> Result<Json<RestoreData>, (StatusCode, String)> {
    let req = CliRequest::Restore {
        path: body.path,
        version: body.version,
        date: body.date,
        dest: body.dest,
    };
    match dispatch(req, &state).await {
        CliResponse::Restore(data) => Ok(Json(data)),
        CliResponse::Error(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((StatusCode::INTERNAL_SERVER_ERROR, "unexpected response".into())),
    }
}

async fn handle_devices(
    State(state): State<Arc<DaemonState>>,
) -> Result<Json<Vec<DeviceEntry>>, (StatusCode, String)> {
    match dispatch(CliRequest::DeviceList, &state).await {
        CliResponse::DeviceList(data) => Ok(Json(data)),
        CliResponse::Error(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((StatusCode::INTERNAL_SERVER_ERROR, "unexpected response".into())),
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
        CliResponse::Connected { peer_id } => {
            Ok(Json(serde_json::json!({ "peer_id": peer_id })))
        }
        CliResponse::Error(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
        _ => Err((StatusCode::INTERNAL_SERVER_ERROR, "unexpected response".into())),
    }
}
