//! Integration test: every CLI command has a working HTTP endpoint,
//! and the auth middleware rejects requests with no/wrong bearer.
//!
//! Rather than spin up a full DaemonHandle (heavy: libp2p swarm, DB, etc.),
//! this test pairs the CLI's reqwest client with a minimal mock router
//! that emulates the web_api shape. It verifies:
//!   1. Every Command maps to a reachable HTTP route (no 404s).
//!   2. Valid bearer → 200 with decoded body.
//!   3. Missing/wrong bearer → CliError::Unauthorized.

use axum::Router;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{delete, get, post};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;

use viaticum::cli::{self, Command, Connection, DeviceAction};
use viaticum::daemon::web_auth::{AuthState, require_auth};

const TOKEN: &str = "test-token-abc123";

// Minimal mock endpoints returning the same JSON shapes the real web_api emits.
async fn mock_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "node_identity": "00".repeat(32),
        "device_id": "ff".repeat(8),
        "node_addr": "/ip4/127.0.0.1/tcp/0",
        "peer_count": 0,
        "avg_trust": 0.0,
        "holding_bytes": 0,
        "backed_up_files": 0,
        "backed_up_bytes": 0,
        "blocks_needing_repair": 0,
        "peers": [],
        "effective_quota_bytes": 0,
        "used_bytes": 0,
    }))
}
async fn mock_files() -> Json<serde_json::Value> {
    Json(serde_json::json!([]))
}
async fn mock_versions() -> Json<serde_json::Value> {
    Json(serde_json::json!([]))
}
const JOB_ID: &str = "3f2a0000-0000-4000-8000-000000000001";

fn mock_job(state: &str, outcome: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "job_id": JOB_ID,
        "path": "some/file",
        "state": state,
        "files_total": 1,
        "files_restored": if outcome.is_some() { 1 } else { 0 },
        "restored_paths": if outcome.is_some() { vec!["some/file"] } else { vec![] },
        "failures": [],
        "outcome": outcome,
        "staging_path": format!("/tmp/restore/{JOB_ID}"),
        "submitted_at": "2026-09-27T10:00:00Z",
        "finished_at": null,
    })
}
async fn mock_restore() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::ACCEPTED, Json(mock_job("queued", None)))
}
async fn mock_restore_job() -> Json<serde_json::Value> {
    Json(mock_job("finished", Some("complete")))
}
async fn mock_restore_jobs() -> Json<serde_json::Value> {
    Json(serde_json::json!([mock_job("finished", Some("complete"))]))
}
async fn mock_devices_list() -> Json<serde_json::Value> {
    Json(serde_json::json!([]))
}
async fn mock_device_add() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "device_id_hex": "aa".repeat(32),
        "label": "test",
        "is_current": false,
        "added_at": "2026-04-24",
        "revoked": false,
    }))
}
async fn mock_device_revoke() -> StatusCode {
    StatusCode::NO_CONTENT
}
async fn mock_connect() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "peer_id": "12D3KooW..." }))
}

fn mock_router(auth: AuthState) -> Router {
    Router::new()
        .route("/api/status", get(mock_status))
        .route("/api/files", get(mock_files))
        .route("/api/versions", get(mock_versions))
        .route("/api/restore", post(mock_restore))
        .route("/api/restore/jobs", get(mock_restore_jobs))
        .route("/api/restore/jobs/{job_id}", get(mock_restore_job))
        .route("/api/devices", get(mock_devices_list).post(mock_device_add))
        .route("/api/devices/{device_id}", delete(mock_device_revoke))
        .route("/api/connect", post(mock_connect))
        .route_layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            require_auth,
        ))
        .with_state(auth)
}

/// Start the mock router on a random localhost port. Returns (addr, shutdown_tx).
async fn spawn_mock(token: String) -> (SocketAddr, oneshot::Sender<()>) {
    let auth = AuthState::new(token);
    let app = mock_router(auth);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });
    (addr, tx)
}

fn connection_for(addr: SocketAddr, token: &str) -> Connection {
    Connection {
        url: format!("http://{}", addr),
        token: token.to_string(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_commands_roundtrip_via_http() {
    let (addr, _shutdown) = spawn_mock(TOKEN.to_string()).await;
    let conn = Arc::new(connection_for(addr, TOKEN));

    // run_command is blocking (uses reqwest::blocking), so run it inside spawn_blocking.
    let commands: Vec<Command> = vec![
        Command::Status { json: true },
        Command::Files { path_prefix: None },
        Command::Files {
            path_prefix: Some("some/path".into()),
        },
        Command::Versions {
            path: "/nonexistent".into(),
        },
        // Submit, then wait: the mock job is already complete → exit 0.
        Command::Restore {
            path: Some("some/file".into()),
            version: None,
            date: None,
            dest: None,
            no_wait: false,
            status: None,
            json: false,
        },
        Command::Restore {
            path: None,
            version: None,
            date: None,
            dest: None,
            no_wait: false,
            status: Some(String::new()),
            json: true,
        },
        Command::Restore {
            path: None,
            version: None,
            date: None,
            dest: None,
            no_wait: false,
            status: Some(JOB_ID.into()),
            json: false,
        },
        Command::Device {
            action: DeviceAction::List,
        },
        Command::Device {
            action: DeviceAction::Add {
                label: "laptop".into(),
            },
        },
        Command::Device {
            action: DeviceAction::Revoke {
                device_id: "aa".repeat(16),
            },
        },
        Command::Connect {
            addr: "00ff@127.0.0.1:9999".into(),
        },
    ];

    for cmd in commands {
        let conn = conn.clone();
        let handle = tokio::task::spawn_blocking(move || cli::run_command(&cmd, &conn));
        let result = handle.await.expect("task panicked");
        assert_eq!(result.ok(), Some(0), "run_command failed");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_command_with_wrong_token() {
    let (addr, _shutdown) = spawn_mock(TOKEN.to_string()).await;
    let conn = connection_for(addr, "wrong-token");
    let handle = tokio::task::spawn_blocking(move || {
        cli::run_command(&Command::Status { json: false }, &conn)
    });
    let err = handle
        .await
        .expect("task panicked")
        .expect_err("should reject");
    assert!(matches!(err, cli::CliError::Unauthorized), "got: {err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_command_with_no_token() {
    let (addr, _shutdown) = spawn_mock(TOKEN.to_string()).await;
    let conn = connection_for(addr, "");
    let handle = tokio::task::spawn_blocking(move || {
        cli::run_command(&Command::Status { json: false }, &conn)
    });
    let err = handle
        .await
        .expect("task panicked")
        .expect_err("should reject");
    assert!(matches!(err, cli::CliError::Unauthorized), "got: {err:?}");
}
