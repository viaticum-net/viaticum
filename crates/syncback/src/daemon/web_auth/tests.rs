use super::*;
use std::fs;

#[test]
fn load_or_create_token_creates_file_if_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let token = load_or_create_token(tmp.path()).unwrap();
    assert_eq!(token.len(), 43, "32 random bytes base64 (no padding) = 43 chars");
    let file_path = tmp.path().join("api-token");
    assert!(file_path.exists());
    let contents = fs::read_to_string(&file_path).unwrap();
    assert_eq!(contents.trim(), token);
}

#[test]
fn load_or_create_token_reuses_existing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let token1 = load_or_create_token(tmp.path()).unwrap();
    let token2 = load_or_create_token(tmp.path()).unwrap();
    assert_eq!(token1, token2);
}

#[cfg(unix)]
#[test]
fn load_or_create_token_sets_mode_0600_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    load_or_create_token(tmp.path()).unwrap();
    let meta = fs::metadata(tmp.path().join("api-token")).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn write_port_file_creates_file_with_port() {
    let tmp = tempfile::tempdir().unwrap();
    write_port_file(tmp.path(), 45678).unwrap();
    let contents = fs::read_to_string(tmp.path().join("api-port")).unwrap();
    assert_eq!(contents.trim(), "45678");
}

#[test]
fn read_port_and_token_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let written_token = load_or_create_token(tmp.path()).unwrap();
    write_port_file(tmp.path(), 12345).unwrap();
    let (port, token) = read_port_and_token(tmp.path()).unwrap();
    assert_eq!(port, 12345);
    assert_eq!(token, written_token);
}

// AC-B3: all N generated tokens are distinct (probabilistic uniqueness via OsRng)
#[test]
fn api_token_is_unique_across_multiple_generations() {
    let mut tokens = std::collections::HashSet::new();
    for _ in 0..100 {
        let tmp = tempfile::tempdir().unwrap();
        let token = load_or_create_token(tmp.path()).unwrap();
        tokens.insert(token);
    }
    assert_eq!(tokens.len(), 100, "all 100 generated tokens must be distinct");
}

#[test]
fn read_port_and_token_errors_when_files_missing() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(read_port_and_token(tmp.path()).is_err());
}

#[cfg(unix)]
#[test]
fn write_port_file_sets_mode_0600_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    write_port_file(tmp.path(), 8080).unwrap();
    let meta = fs::metadata(tmp.path().join("api-port")).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

// ── Auth middleware + /auth/start ────────────────────────────────────────────

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

fn test_router(token: String) -> Router {
    let auth = AuthState::new(token);
    Router::new()
        .route("/api/echo", axum::routing::get(|| async { "ok" }))
        .route_layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            require_auth,
        ))
        .with_state(auth)
}

#[tokio::test]
async fn auth_middleware_rejects_missing_token() {
    let app = test_router("secret".to_string());
    let resp = app
        .oneshot(Request::builder().uri("/api/echo").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_middleware_rejects_wrong_bearer() {
    let app = test_router("secret".to_string());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/echo")
                .header("Authorization", "Bearer nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_middleware_accepts_valid_bearer() {
    let app = test_router("secret".to_string());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/echo")
                .header("Authorization", "Bearer secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_middleware_accepts_valid_session_cookie() {
    let app = test_router("secret".to_string());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/echo")
                .header("Cookie", "syncback_session=secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_middleware_rejects_wrong_cookie() {
    let app = test_router("secret".to_string());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/echo")
                .header("Cookie", "syncback_session=nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_start_sets_cookie_and_redirects() {
    let auth = AuthState::new("secret".to_string());
    let app = Router::new()
        .route("/auth/start", axum::routing::get(auth_start_handler))
        .with_state(auth);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/auth/start?token=secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(set_cookie.contains("syncback_session=secret"));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert_eq!(resp.headers().get("location").unwrap(), "/");
}

#[tokio::test]
async fn auth_start_rejects_wrong_token() {
    let auth = AuthState::new("secret".to_string());
    let app = Router::new()
        .route("/auth/start", axum::routing::get(auth_start_handler))
        .with_state(auth);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/auth/start?token=nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
