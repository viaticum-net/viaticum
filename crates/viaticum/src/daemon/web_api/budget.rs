// The node's side of a DR's memory lease (К-b3, spec v3.9a): `viaticum dr` on a machine where this
// node runs asks it for the memory of one SS block at a time (`POST /api/budget/lease`), decodes,
// and gives it back (`POST /api/budget/release`).
//
// The lease response is a stream of lines, the HTTP shape of "the connection": while the lease
// waits for the budget a blank line goes out every `keepalive`; the grant is the line
// `{"lease":"granted","id":N}`; blank lines go on while it is held. The response owns the lease:
// when the client drops the connection the stream is dropped, the lease leaves the queue or the
// bytes go back (M67). `release` is the explicit end; it answers `released`, `revoked` (the node
// took the lease back at the ceiling) or `unknown`.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use viaticum_core::types::SourceBlockId;

use crate::daemon::handle::DaemonState;
use crate::daemon::mem_budget::{DrLeases, LeaseError, LeaseGuard, ReleaseOutcome};

#[derive(serde::Deserialize)]
pub(super) struct LeaseBody {
    /// The SS block, 64 hex characters.
    block_id: String,
    encrypted_size: u64,
}

#[derive(serde::Deserialize)]
pub(super) struct ReleaseBody {
    id: u64,
}

fn parse_block_id(hex: &str) -> Option<SourceBlockId> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(SourceBlockId(out))
}

type LeaseFuture = Pin<Box<dyn Future<Output = Result<LeaseGuard, LeaseError>> + Send>>;

enum LeaseStream {
    Waiting(LeaseFuture),
    Held(LeaseGuard),
    Done,
}

/// The lines of a lease response (see the module header).
fn lease_stream(
    leases: Arc<DrLeases>,
    block: SourceBlockId,
    encrypted_size: u64,
) -> impl futures::Stream<Item = Result<Bytes, Infallible>> {
    let keepalive = leases.keepalive();
    let fut: LeaseFuture = Box::pin(async move { leases.lease(block, encrypted_size).await });
    futures::stream::unfold(LeaseStream::Waiting(fut), move |state| async move {
        match state {
            LeaseStream::Waiting(mut fut) => {
                tokio::select! {
                    granted = &mut fut => match granted {
                        Ok(guard) => {
                            let line = format!("{{\"lease\":\"granted\",\"id\":{}}}\n", guard.id());
                            Some((Ok(Bytes::from(line)), LeaseStream::Held(guard)))
                        }
                        Err(e) => {
                            let line = format!(
                                "{{\"lease\":\"error\",\"message\":{}}}\n",
                                serde_json::Value::String(e.to_string())
                            );
                            Some((Ok(Bytes::from(line)), LeaseStream::Done))
                        }
                    },
                    _ = tokio::time::sleep(keepalive) => {
                        Some((Ok(Bytes::from_static(b"\n")), LeaseStream::Waiting(fut)))
                    }
                }
            }
            LeaseStream::Held(guard) => {
                tokio::time::sleep(keepalive).await;
                Some((Ok(Bytes::from_static(b"\n")), LeaseStream::Held(guard)))
            }
            LeaseStream::Done => None,
        }
    })
}

/// `POST /api/budget/lease`.
pub(super) async fn handle_lease(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<LeaseBody>,
) -> Response {
    let Some(leases) = state.dr_leases.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no memory budget here").into_response();
    };
    let Some(block) = parse_block_id(&body.block_id) else {
        return (
            StatusCode::BAD_REQUEST,
            "block_id must be 64 hex characters",
        )
            .into_response();
    };
    let stream = lease_stream(leases, block, body.encrypted_size);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
}

/// `POST /api/budget/release`.
pub(super) async fn handle_release(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<ReleaseBody>,
) -> Response {
    let Some(leases) = state.dr_leases.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no memory budget here").into_response();
    };
    let status = match leases.release(body.id) {
        ReleaseOutcome::Released => "released",
        ReleaseOutcome::Revoked => "revoked",
        ReleaseOutcome::Unknown => "unknown",
    };
    Json(serde_json::json!({ "status": status })).into_response()
}
