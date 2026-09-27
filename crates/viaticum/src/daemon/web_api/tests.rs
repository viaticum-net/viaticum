// Web API handler tests.
// F1: POST /api/restore (no dest) → 200 OK, JSON contains "staging_path".
// F2: POST /api/restore with dest → 400 Bad Request.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::mpsc;
use tower::ServiceExt; // for oneshot

use tokio_util::sync::CancellationToken;
use viaticum_core::db::Db;
use viaticum_core::types::{DeviceId, IdentityPub};

use crate::cli::types::CliRequest;
use crate::daemon::handle::DaemonState;
use crate::daemon::restore::{RestoreError, RestoreRequest, RestoreResult};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Build a minimal DaemonState for web API tests.
/// The restore channel is set up so it immediately returns a synthetic result.
async fn make_test_state_with_restore(staging_path: std::path::PathBuf) -> Arc<DaemonState> {
    let db = Db::open_in_memory().expect("in-memory db");
    let master_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let identity_pub = IdentityPub(master_key.verifying_key().to_bytes());
    let device_id = DeviceId([0u8; 32]);

    let (restore_tx, mut restore_rx) = mpsc::channel::<(
        RestoreRequest,
        tokio::sync::oneshot::Sender<Result<RestoreResult, RestoreError>>,
    )>(4);

    // Spawn a task that auto-responds with a synthetic RestoreResult.
    let sp = staging_path.clone();
    tokio::spawn(async move {
        while let Some((_req, reply)) = restore_rx.recv().await {
            let _ = reply.send(Ok(RestoreResult {
                files_restored: 1,
                blocks_fetched: 1,
                failures: vec![],
                staging_path: sp.clone(),
            }));
        }
    });

    Arc::new(DaemonState {
        db,
        identity_pub,
        device_id,
        restore_tx,
        restore_staging: Default::default(),
        cluster_state: None,
        master_key,
        seed: vec![0u8; 64],
        data_dir: std::path::PathBuf::from("/tmp"),
        soft_quota_bytes: 0,
        disk_reserve_bytes: 0,
        hard_quota_bytes: 0,
        time_scale: 1,
        swarm_handle: None,
        watch_admin: None,
        config_admin: None,
        restart_gate: None,
        shutdown_token: CancellationToken::new(),
        peer_backoff: std::sync::Arc::new(crate::daemon::peer_backoff::PeerBackoff::default()),
        mailbox_router: None,
    })
}

/// Build a test router with auth bypass (no token check for unit tests).
fn build_test_router(state: Arc<DaemonState>) -> axum::Router {
    use crate::cli::types::CliResponse;
    use crate::daemon::dispatch::dispatch;
    use axum::extract::{Json, State};
    use axum::http::StatusCode;
    use axum::routing::post;

    // Inline a minimal router that mirrors the real handle_restore handler,
    // bypassing auth middleware.
    #[derive(serde::Deserialize)]
    struct RestoreBody {
        path: String,
        version: Option<u32>,
        date: Option<String>,
        dest: Option<String>,
    }

    async fn handle_restore_test(
        State(state): State<Arc<DaemonState>>,
        Json(body): Json<RestoreBody>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        let req = CliRequest::Restore {
            path: body.path,
            version: body.version,
            date: body.date,
            dest: body.dest,
        };
        match dispatch(req, &state).await {
            CliResponse::Restore(data) => (StatusCode::OK, Json(data)).into_response(),
            CliResponse::RestoreBlocked(blocker) => {
                (StatusCode::CONFLICT, Json(blocker)).into_response()
            }
            CliResponse::Error(ref e) if e == "dest_not_supported_in_alpha" => {
                let body = serde_json::json!({ "error": "dest_not_supported_in_alpha" });
                (StatusCode::BAD_REQUEST, Json(body)).into_response()
            }
            CliResponse::Error(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "unexpected response").into_response(),
        }
    }

    axum::Router::new()
        .route("/api/restore", post(handle_restore_test))
        .with_state(state)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// F1: POST /api/restore with no dest → 200 OK, body contains "staging_path".
#[tokio::test]
async fn restore_api_returns_staging_path() {
    let staging_path = std::path::PathBuf::from("/tmp/test_staging/job-abc123");
    let state = make_test_state_with_restore(staging_path.clone()).await;
    let app = build_test_router(state);

    let body = serde_json::json!({ "path": "/home/alice/docs/report.docx" });
    let request = Request::builder()
        .method("POST")
        .uri("/api/restore")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK, "expected 200 OK");

    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert!(
        json.get("staging_path").is_some(),
        "response body must contain 'staging_path' field, got: {json}"
    );
    let sp = json["staging_path"].as_str().unwrap_or("");
    assert!(
        !sp.is_empty(),
        "staging_path must be non-empty, got: {json}"
    );
}

// ─── Security header helpers ──────────────────────────────────────────────────

/// Minimal router with only the security headers layer applied.
fn build_headers_test_router() -> axum::Router {
    use axum::routing::get;
    axum::Router::new()
        .route("/ping", get(|| async { "pong" }))
        .layer(axum::middleware::map_response(super::add_security_headers))
}

/// Router with auth layer + security headers, used to test headers on 401.
fn build_full_router_for_header_test() -> axum::Router {
    use axum::routing::get;
    let auth = crate::daemon::web_auth::AuthState::new("secret".to_string());
    let api = axum::Router::new()
        .route("/api/dummy", get(|| async { "ok" }))
        .route_layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            crate::daemon::web_auth::require_auth,
        ));
    api.layer(axum::middleware::map_response(super::add_security_headers))
}

// ─── Security header tests ────────────────────────────────────────────────────

/// I-AC1/2/3: GET /ping → all three security headers present.
#[tokio::test]
async fn security_headers_present_on_api_response() {
    let app = build_headers_test_router();
    let resp = app
        .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let headers = resp.headers();
    assert_eq!(
        headers.get("referrer-policy").unwrap(),
        "no-referrer",
        "Referrer-Policy must be no-referrer"
    );
    assert_eq!(
        headers.get("x-content-type-options").unwrap(),
        "nosniff",
        "X-Content-Type-Options must be nosniff"
    );
    assert_eq!(
        headers.get("x-frame-options").unwrap(),
        "DENY",
        "X-Frame-Options must be DENY"
    );
}

/// I-AC4: GET /api/dummy without auth → 401, but security headers still present.
#[tokio::test]
async fn security_headers_present_on_401_response() {
    let app = build_full_router_for_header_test();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dummy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get("referrer-policy").unwrap(),
        "no-referrer",
        "Referrer-Policy must be present even on 401"
    );
}

/// F2: POST /api/restore with dest → 400 Bad Request with dest_not_supported_in_alpha.
#[tokio::test]
async fn restore_api_with_dest_returns_400() {
    let staging_path = std::path::PathBuf::from("/tmp/staging");
    let state = make_test_state_with_restore(staging_path).await;
    let app = build_test_router(state);

    let body = serde_json::json!({
        "path": "/home/alice/file.txt",
        "dest": "/tmp/custom_dest"
    });
    let request = Request::builder()
        .method("POST")
        .uri("/api/restore")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "expected 400 Bad Request"
    );

    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let error_msg = json["error"].as_str().unwrap_or("");
    assert_eq!(
        error_msg, "dest_not_supported_in_alpha",
        "error must be dest_not_supported_in_alpha, got: {json}"
    );
}
