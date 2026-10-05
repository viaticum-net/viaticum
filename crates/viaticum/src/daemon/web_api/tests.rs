// Web API handler tests: the real `/api/*` routes behind `require_auth`
// (`authed_router`), a real in-memory DB and a real job registry; the restore
// queue is a plain channel (no coordinator runs).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::mpsc;
use tower::ServiceExt; // for oneshot

use tokio_util::sync::CancellationToken;
use viaticum_core::db::Db;
use viaticum_core::types::{
    DeviceId, FileId, FileRecord, FileVersion, IdentityPub, SourceBlockId, Timestamp,
};

use crate::daemon::handle::DaemonState;
use crate::daemon::restore::RestoreRequest;
use crate::daemon::restore::jobs::RestoreJobs;
use crate::daemon::restore::staging::JobId;
use crate::daemon::web_auth::AuthState;

pub(crate) const TOKEN: &str = "test-token";

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// DaemonState with one backed-up catalog file (`/home/alice/docs/report.docx`);
/// restore requests land in the returned receiver.
fn test_state() -> (Arc<DaemonState>, mpsc::Receiver<RestoreRequest>) {
    let db = Db::open_in_memory().expect("in-memory db");
    let jobs = RestoreJobs::new("/nonexistent/viaticum-web-test/restore".into());
    db.upsert_file(&FileRecord {
        file_id: FileId(1),
        path: "/home/alice/docs/report.docx".into(),
        importance: 0.5,
        devices: vec![],
        versions: vec![FileVersion {
            content_hash: [1u8; 32],
            source_block_id: SourceBlockId([2u8; 32]),
            k: 1,
            t: 64,
            created_at: Timestamp(10),
            backed_up_at: Some(Timestamp(20)),
        }],
        first_seen: Timestamp(0),
        on_disk_confirmed: true,
    })
    .unwrap();
    state_with(db, jobs)
}

fn state_with(db: Db, jobs: RestoreJobs) -> (Arc<DaemonState>, mpsc::Receiver<RestoreRequest>) {
    let master_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let (restore_tx, restore_rx) = mpsc::channel::<RestoreRequest>(4);
    let state = Arc::new(DaemonState {
        db,
        identity_pub: IdentityPub(master_key.verifying_key().to_bytes()),
        device_id: DeviceId([0u8; 32]),
        restore_tx,
        restore_jobs: jobs,
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
        missing_sources: Default::default(),
        max_file_size_bytes: 0,
        esi_space: Default::default(),
        block_work_budget_bytes: 0,
        dr_leases: None,
    });
    (state, restore_rx)
}

fn app(state: Arc<DaemonState>) -> axum::Router {
    super::authed_router(state, AuthState::new(TOKEN.to_string()))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

fn post_restore(body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/restore")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn json_of(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ─── Restore job API (restore-i3, i4) ─────────────────────────────────────────

/// POST /api/restore answers 202 at once with the queued job; the request is in
/// the coordinator's queue.
#[tokio::test]
async fn restore_api_returns_202_with_job() {
    let (state, mut rx) = test_state();
    let response = app(state)
        .oneshot(post_restore(
            serde_json::json!({ "path": "/home/alice/docs/report.docx" }),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let job = json_of(response).await;
    assert_eq!(job["state"], "queued");
    assert_eq!(job["files_total"], 1);
    assert!(
        job["staging_path"]
            .as_str()
            .unwrap()
            .ends_with(job["job_id"].as_str().unwrap()),
        "{job}"
    );
    let queued = rx.try_recv().expect("enqueued");
    assert_eq!(queued.job_id.to_string(), job["job_id"].as_str().unwrap());
}

#[tokio::test]
async fn restore_api_unknown_path_returns_404_not_in_catalog() {
    let (state, mut rx) = test_state();
    let response = app(state)
        .oneshot(post_restore(
            serde_json::json!({ "path": "/home/alice/nope" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = json_of(response).await;
    assert_eq!(body["error"], "not_in_catalog");
    assert_eq!(body["path"], "/home/alice/nope");
    assert!(rx.try_recv().is_err());
}

/// restore-i29: a version not backed up under the path — including 0 (versions are
/// 1-based; 0 is not a synonym for version 1) — is refused with the available ones.
#[tokio::test]
async fn restore_api_unknown_version_returns_404_version_not_found() {
    for version in [5u32, 0] {
        let (state, mut rx) = test_state();
        let response = app(state)
            .oneshot(post_restore(serde_json::json!({
                "path": "/home/alice/docs/report.docx",
                "version": version,
            })))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "version {version}"
        );
        let body = json_of(response).await;
        assert_eq!(body["error"], "version_not_found", "version {version}");
        assert_eq!(body["version"], version);
        assert_eq!(body["available"], serde_json::json!([1]));
        assert!(
            rx.try_recv().is_err(),
            "version {version}: nothing enqueued"
        );
    }
}

#[tokio::test]
async fn restore_job_api_returns_job_state() {
    let (state, _rx) = test_state();
    let id = JobId::new();
    state.restore_jobs.submit(id, "/home/alice/docs/", 3);
    state.restore_jobs.mark_running(id, "/home/alice/docs/", 3);
    state
        .restore_jobs
        .record_restored(id, "/home/alice/docs/report.docx");

    let response = app(state)
        .oneshot(get(&format!("/api/restore/jobs/{id}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let job = json_of(response).await;
    assert_eq!(job["state"], "running");
    assert_eq!(job["files_restored"], 1);
    assert_eq!(job["restored_paths"][0], "/home/alice/docs/report.docx");
}

#[tokio::test]
async fn restore_job_api_unknown_id_returns_404() {
    let (state, _rx) = test_state();
    let id = JobId::new();
    let response = app(state)
        .oneshot(get(&format!("/api/restore/jobs/{id}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = json_of(response).await;
    assert_eq!(body["error"], "unknown_job");
    assert_eq!(body["job_id"], id.to_string());
}

#[tokio::test]
async fn restore_jobs_api_lists_newest_first() {
    let (state, _rx) = test_state();
    let older = JobId::new();
    let newer = JobId::new();
    state.restore_jobs.submit(older, "/a", 1);
    state.restore_jobs.submit(newer, "/b", 1);
    let response = app(state).oneshot(get("/api/restore/jobs")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let list = json_of(response).await;
    let ids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|j| j["job_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![newer.to_string(), older.to_string()]);
}

#[tokio::test]
async fn restore_api_with_dest_returns_400() {
    let (state, _rx) = test_state();
    let response = app(state)
        .oneshot(post_restore(serde_json::json!({
            "path": "/home/alice/docs/report.docx",
            "dest": "/tmp/custom_dest"
        })))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_of(response).await["error"], "dest_not_supported");
}

#[tokio::test]
async fn restore_routes_require_auth() {
    let (state, mut rx) = test_state();
    let app = app(state);
    let id = JobId::new();
    for request in [
        Request::builder()
            .method("POST")
            .uri("/api/restore")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"path":"/home/alice/docs/report.docx"}"#))
            .unwrap(),
        Request::builder()
            .uri("/api/restore/jobs")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri(format!("/api/restore/jobs/{id}"))
            .header("authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap(),
    ] {
        let uri = request.uri().to_string();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }
    assert!(
        rx.try_recv().is_err(),
        "an unauthenticated POST enqueued nothing"
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

// ─── restore-i15: the job does not belong to the client ──────────────────────

/// restore-i15: a submitted job does not depend on the client that submitted it.
/// The POST is abandoned (Ctrl-C, closed terminal) before the coordinator even
/// starts; the coordinator then runs the job to `complete`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_job_outlives_the_client_that_submitted_it() {
    use crate::cli::types::{RestoreJobState, RestoreOutcome};
    use crate::daemon::backup::{BackupConfig, BackupCoordinator, DirtyEvent, DirtyKind};
    use crate::daemon::restore::{RestoreConfig, RestoreCoordinator};
    use viaticum_core::erasure::RaptorQEncoder;

    const KEY: [u8; 32] = [42u8; 32];
    let files = tempfile::TempDir::new().unwrap();
    let data_dir = tempfile::TempDir::new().unwrap();
    let staging_root = data_dir.path().join("restore");
    std::fs::create_dir_all(&staging_root).unwrap();
    let path = files.path().join("kept.txt");
    std::fs::write(&path, b"the job is not the client's").unwrap();
    let path = path.to_string_lossy().into_owned();

    let db = Db::open_in_memory().unwrap();
    let mut backup = BackupCoordinator::new(
        db.clone(),
        BackupConfig {
            source_block_size: 65_535 * 2,
            symbols_dir: data_dir.path().join("symbols"),
            epoch_key: KEY,
            device_id: DeviceId([1u8; 32]),
            mock_holders: vec![],
            watch_configs: vec![],
            time_scale: 1,
            mock_offer_budget_gb: None,
            master_signing_key: None,
            swarm: None,
            live_watch_configs: None,
            peer_backoff: None,
            work_event_tx: None,
            resubmit_tx: None,
            max_file_size_bytes: viaticum_core::constants::MAX_FILE_SIZE_CEILING_BYTES,
        },
        Arc::new(RaptorQEncoder::new()),
    );
    backup
        .process_event(DirtyEvent {
            path: path.clone(),
            kind: DirtyKind::Added,
            device_id: DeviceId([1u8; 32]),
        })
        .unwrap();
    backup.flush_all(true, &Default::default()).unwrap();

    let jobs = RestoreJobs::new(staging_root.clone());
    let (state, rx) = state_with(db.clone(), jobs.clone());
    let client =
        tokio::spawn(app(state).oneshot(post_restore(serde_json::json!({ "path": path }))));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    client.abort();

    let mut config = RestoreConfig::new(KEY, staging_root, data_dir.path().to_path_buf());
    config.jobs = jobs.clone();
    let cancel = config.cancel.clone();
    let coordinator =
        tokio::spawn(RestoreCoordinator::new(db, config, Arc::new(RaptorQEncoder::new())).run(rx));
    let mut finished = None;
    for _ in 0..100 {
        if let Some(j) = jobs.list().into_iter().next()
            && j.state == RestoreJobState::Finished
        {
            finished = Some(j);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    cancel.cancel();
    coordinator.await.unwrap().unwrap();

    let job = finished.expect("the job ran to the end without its client");
    assert_eq!(job.outcome, Some(RestoreOutcome::Complete), "{job:?}");
    let staged = std::path::Path::new(&job.staging_path).join(path.trim_start_matches('/'));
    assert_eq!(
        std::fs::read(staged).unwrap(),
        b"the job is not the client's"
    );
}

// ─── The DR's lease of the node's memory (К-b3, spec v3.9a) ───────────────────────────────────────

/// The routes of a node whose DR leases are `leases`: the node's side of `viaticum dr`
/// (also served over a socket by the DR tests).
pub(crate) fn lease_app(leases: Arc<crate::daemon::mem_budget::DrLeases>) -> axum::Router {
    let (mut state, _rx) = test_state();
    Arc::get_mut(&mut state).expect("a fresh state").dr_leases = Some(leases);
    app(state)
}

fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn lease_body(size: u64) -> serde_json::Value {
    serde_json::json!({ "block_id": "11".repeat(32), "encrypted_size": size })
}

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !cond() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

fn leases_of(
    budget: &Arc<crate::daemon::mem_budget::MemBudget>,
) -> Arc<crate::daemon::mem_budget::DrLeases> {
    crate::daemon::mem_budget::DrLeases::with_keepalive(
        Arc::clone(budget),
        std::time::Duration::from_secs(3600),
        std::time::Duration::from_millis(20),
    )
}

/// The first line the response of a lease request sends (blank keepalive lines skipped).
async fn first_line(
    stream: &mut (impl futures::Stream<Item = Result<axum::body::Bytes, axum::Error>> + Unpin),
) -> String {
    use futures::StreamExt;
    loop {
        let chunk = stream
            .next()
            .await
            .expect("the stream goes on")
            .expect("a chunk");
        let text = String::from_utf8(chunk.to_vec()).unwrap();
        if !text.trim().is_empty() {
            return text.trim().to_string();
        }
    }
}

/// M67: the response of a lease request owns the lease; when the client drops the connection the
/// bytes go back to the budget.
#[tokio::test]
async fn budget_lease_is_released_when_the_connection_drops() {
    let budget = crate::daemon::mem_budget::MemBudget::new(256 << 20);
    let leases = leases_of(&budget);
    let response = lease_app(Arc::clone(&leases))
        .oneshot(post_json("/api/budget/lease", lease_body(1_000_000)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut stream = response.into_body().into_data_stream();
    let line = first_line(&mut stream).await;
    assert!(line.contains("\"lease\":\"granted\""), "{line}");
    assert!(budget.outstanding_bytes() > 0, "the lease holds memory");
    assert!(leases.status().is_some());

    drop(stream);

    until("the dropped connection releases the lease", || {
        budget.outstanding_bytes() == 0
    })
    .await;
    assert!(leases.status().is_none());
}

/// The explicit end: `release` answers `released`, then `unknown`; the held lease is gone.
#[tokio::test]
async fn budget_release_answers_released_then_unknown() {
    let budget = crate::daemon::mem_budget::MemBudget::new(256 << 20);
    let leases = leases_of(&budget);
    let app = lease_app(Arc::clone(&leases));
    let response = app
        .clone()
        .oneshot(post_json("/api/budget/lease", lease_body(1_000_000)))
        .await
        .unwrap();
    let mut stream = response.into_body().into_data_stream();
    let line = first_line(&mut stream).await;
    let id = serde_json::from_str::<serde_json::Value>(&line).unwrap()["id"]
        .as_u64()
        .unwrap();

    let released = app
        .clone()
        .oneshot(post_json(
            "/api/budget/release",
            serde_json::json!({ "id": id }),
        ))
        .await
        .unwrap();
    assert_eq!(json_of(released).await["status"], "released");
    assert_eq!(budget.outstanding_bytes(), 0);
    let again = app
        .oneshot(post_json(
            "/api/budget/release",
            serde_json::json!({ "id": id }),
        ))
        .await
        .unwrap();
    assert_eq!(json_of(again).await["status"], "unknown");
}

/// A request the node cannot size is answered with a line, and nothing is granted.
#[tokio::test]
async fn budget_lease_of_an_impossible_block_is_refused_with_a_line() {
    let budget = crate::daemon::mem_budget::MemBudget::new(256 << 20);
    let leases = leases_of(&budget);
    let response = lease_app(leases)
        .oneshot(post_json("/api/budget/lease", lease_body(100 << 30)))
        .await
        .unwrap();
    let mut stream = response.into_body().into_data_stream();
    let line = first_line(&mut stream).await;
    assert!(line.contains("\"lease\":\"error\""), "{line}");
    assert_eq!(budget.outstanding_bytes(), 0);
}

#[tokio::test]
async fn budget_lease_needs_the_token_and_a_block_id() {
    let budget = crate::daemon::mem_budget::MemBudget::new(256 << 20);
    let app = lease_app(leases_of(&budget));
    let no_token = Request::builder()
        .method("POST")
        .uri("/api/budget/lease")
        .header("content-type", "application/json")
        .body(Body::from(lease_body(1000).to_string()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(no_token).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let bad = serde_json::json!({ "block_id": "xyz", "encrypted_size": 1000 });
    assert_eq!(
        app.oneshot(post_json("/api/budget/lease", bad))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

// ─── Device revoke (dr-i8) ────────────────────────────────────────────────────

/// DELETE /api/devices/{id} answers 200 + JSON carrying `holders_skipped`, so the CLI can warn
/// about holders whose master is unknown (not 204, which would drop the count).
#[tokio::test]
async fn device_revoke_returns_holders_skipped() {
    let (state, revoked_hex, _h1_master, _h2, _sender) =
        crate::daemon::dispatch::tests::after_dr_revoke_fixture();
    let request = Request::builder()
        .method("DELETE")
        .uri(format!("/api/devices/{revoked_hex}"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let response = app(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_of(response).await;
    assert_eq!(body["device_id_hex"], revoked_hex);
    assert_eq!(body["holders_skipped"], 1, "H2 is unknown anywhere: {body}");
}
