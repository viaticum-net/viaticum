use std::io::{Read, Write};
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

use syncback_core::trust::compute_combined;
use syncback_core::types::{LocalState, SourceBlockStatus, Timestamp};

use crate::cli::types::{
    CliRequest, CliResponse, DeviceEntry, FileEntry, PeerSummary, RestoreData, StatusData,
    VersionEntry,
};
use crate::daemon::handle::DaemonState;
use crate::daemon::restore::{RestoreRequest, VersionSelector};

#[cfg(test)]
mod tests;

// ============================================================
// Public API
// ============================================================

/// Configuration for the CLI server task.
pub struct CliServerConfig {
    /// Path to the Unix socket to bind.
    pub socket_path: String,
}

/// Handle returned by `start`. Caller awaits it to detect server failure.
pub type CliServerHandle = tokio::task::JoinHandle<()>;

/// Errors from CLI server operations.
#[derive(Debug, thiserror::Error)]
pub enum CliServerError {
    #[error("failed to bind socket at {path}: {source}")]
    Bind { path: String, source: std::io::Error },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("encode error: {0}")]
    Encode(String),

    #[error("decode error: {0}")]
    Decode(String),
}

/// Start the CLI server task.
///
/// Binds the Unix socket and enters the accept loop. Returns the JoinHandle
/// immediately; the task runs until `cancel` is triggered.
///
/// If binding fails (e.g., socket already in use), the function returns Err
/// immediately (before spawning).
///
/// The task removes the socket file on shutdown (best-effort).
pub async fn start(
    config: CliServerConfig,
    cancel: CancellationToken,
    state: Arc<DaemonState>,
) -> Result<CliServerHandle, CliServerError> {
    // Remove stale socket file if present.
    let _ = std::fs::remove_file(&config.socket_path);

    let listener = UnixListener::bind(&config.socket_path).map_err(|e| CliServerError::Bind {
        path: config.socket_path.clone(),
        source: e,
    })?;

    let socket_path = config.socket_path.clone();
    let handle = tokio::spawn(async move {
        run_accept_loop(listener, cancel, state).await;
        // Best-effort cleanup.
        let _ = std::fs::remove_file(&socket_path);
    });

    Ok(handle)
}

// ============================================================
// Accept loop
// ============================================================

async fn run_accept_loop(
    listener: UnixListener,
    cancel: CancellationToken,
    state: Arc<DaemonState>,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("cli_server: shutting down");
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        let state_clone = Arc::clone(&state);
                        tokio::spawn(async move {
                            handle_connection(stream, state_clone).await;
                        });
                    }
                    Err(e) => {
                        tracing::error!("cli_server: accept error: {e}");
                    }
                }
            }
        }
    }
}

// ============================================================
// Per-connection handler
// ============================================================

async fn handle_connection(stream: tokio::net::UnixStream, state: Arc<DaemonState>) {
    // Convert to std for blocking I/O (one-shot per connection).
    let std_stream = match stream.into_std() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("cli_server: stream conversion error: {e}");
            return;
        }
    };

    let request = match read_framed(&std_stream) {
        Ok(req) => req,
        Err(e) => {
            tracing::error!("cli_server: read error: {e}");
            return;
        }
    };

    let response = dispatch(request, &state).await;

    if let Err(e) = write_framed(&std_stream, &response) {
        tracing::error!("cli_server: write error: {e}");
    }
}

// ============================================================
// Dispatch — wired to real DaemonState
// ============================================================

/// Dispatch a CliRequest and produce a CliResponse.
pub(crate) async fn dispatch(request: CliRequest, state: &DaemonState) -> CliResponse {
    match request {
        CliRequest::Status => dispatch_status(state),

        CliRequest::Files { path_prefix } => dispatch_files(state, path_prefix),

        CliRequest::Versions { path } => dispatch_versions(state, &path),

        CliRequest::Restore {
            path,
            version,
            date,
            dest,
        } => dispatch_restore(state, path, version, date, dest).await,

        CliRequest::DeviceList => dispatch_device_list(state),

        CliRequest::DeviceAdd { label } => dispatch_device_add(state, label),

        CliRequest::DeviceRevoke { device_id_hex } => {
            CliResponse::DeviceRevoked { device_id_hex }
        }

        CliRequest::Connect { addr } => {
            // Phase 6.6: connection not yet fully wired (Processor 6.3 handles discovery).
            // Return stub; the address is echoed back as the peer_id.
            tracing::info!(addr = %addr, "connect request received (stub — Processor not wired yet)");
            CliResponse::Connected { peer_id: addr }
        }
    }
}

// ── Status ────────────────────────────────────────────────────────────────────

fn dispatch_status(state: &DaemonState) -> CliResponse {
    let peers = match state.db.list_all_peers() {
        Ok(p) => p,
        Err(e) => {
            return CliResponse::Error(format!("db error listing peers: {e}"));
        }
    };
    let files = match state.db.list_all_files() {
        Ok(f) => f,
        Err(e) => {
            return CliResponse::Error(format!("db error listing files: {e}"));
        }
    };
    let holdings_bytes = match state.db.total_holding_bytes() {
        Ok(b) => b,
        Err(e) => {
            return CliResponse::Error(format!("db error reading holdings: {e}"));
        }
    };
    let source_blocks = match state.db.list_all_source_blocks() {
        Ok(b) => b,
        Err(e) => {
            return CliResponse::Error(format!("db error reading source blocks: {e}"));
        }
    };

    // Compute peer summaries, sorted by combined trust descending (top 20).
    let mut peer_summaries: Vec<PeerSummary> = peers
        .iter()
        .map(|p| {
            let combined = compute_combined(p.trust_p, p.trust_i, p.trust_s);
            let identity_hex = bytes_to_hex_8(&p.identity.0);
            let last_seen = timestamp_to_iso(p.last_seen);
            PeerSummary {
                identity_hex,
                trust: combined,
                bytes_we_store: p.bytes_we_store_for_peer,
                bytes_peer_stores: p.bytes_peer_stores_for_us,
                last_seen,
            }
        })
        .collect();
    peer_summaries.sort_by(|a, b| b.trust.partial_cmp(&a.trust).unwrap_or(std::cmp::Ordering::Equal));
    peer_summaries.truncate(20);

    // avg_trust across all peers.
    let avg_trust = if peers.is_empty() {
        0.0
    } else {
        let sum: f64 = peers
            .iter()
            .map(|p| compute_combined(p.trust_p, p.trust_i, p.trust_s))
            .sum();
        sum / peers.len() as f64
    };

    // backed_up_bytes: sum of latest-version sizes (use file_size from latest FileVersion).
    // We approximate by using k*t of the latest version's source block params.
    let backed_up_bytes: u64 = files
        .iter()
        .filter_map(|f| f.versions.last())
        .map(|v| v.k as u64 * v.t as u64)
        .sum();

    // blocks_needing_repair: source blocks with NeedsRepair-like status.
    let blocks_needing_repair = source_blocks
        .iter()
        .filter(|b| b.status == SourceBlockStatus::Stale)
        .count() as u32;

    let node_identity = bytes_to_hex_full(&state.identity_pub.0);

    CliResponse::Status(StatusData {
        node_identity,
        peer_count: peers.len() as u32,
        avg_trust,
        holding_bytes: holdings_bytes,
        backed_up_files: files.len() as u32,
        backed_up_bytes,
        blocks_needing_repair,
        peers: peer_summaries,
        effective_quota_bytes: 0, // Phase 4: disk pressure not yet computed
        used_bytes: holdings_bytes,
    })
}

// ── Files ─────────────────────────────────────────────────────────────────────

fn dispatch_files(state: &DaemonState, path_prefix: Option<String>) -> CliResponse {
    let records = match path_prefix {
        Some(ref prefix) => state.db.list_files_with_prefix(prefix),
        None => state.db.list_all_files(),
    };
    let records = match records {
        Ok(r) => r,
        Err(e) => {
            return CliResponse::Error(format!("db error listing files: {e}"));
        }
    };

    let entries: Vec<FileEntry> = records
        .iter()
        .map(|f| {
            let latest = f.versions.last();
            let last_backed_up = latest
                .and_then(|v| v.backed_up_at)
                .map(timestamp_to_iso)
                .unwrap_or_else(|| "pending".to_string());
            let size_bytes = latest
                .map(|v| v.k as u64 * v.t as u64)
                .unwrap_or(0);
            let local_state = f
                .devices
                .iter()
                .map(|(_, ls)| match ls {
                    LocalState::Present => "present",
                    LocalState::Deleted(_) => "deleted",
                })
                .next()
                .unwrap_or("unknown")
                .to_string();
            FileEntry {
                path: f.path.clone(),
                versions: f.versions.len() as u32,
                last_backed_up,
                size_bytes,
                local_state,
            }
        })
        .collect();

    CliResponse::Files(entries)
}

// ── Versions ──────────────────────────────────────────────────────────────────

fn dispatch_versions(state: &DaemonState, path: &str) -> CliResponse {
    let record = match state.db.get_file(path) {
        Ok(Some(r)) => r,
        Ok(None) => return CliResponse::Versions(vec![]),
        Err(e) => return CliResponse::Error(format!("db error: {e}")),
    };

    let entries: Vec<VersionEntry> = record
        .versions
        .iter()
        .enumerate()
        .map(|(idx, v)| {
            let backed_up_at = v
                .backed_up_at
                .map(timestamp_to_iso)
                .unwrap_or_else(|| "pending".to_string());
            let content_hash_hex = bytes_to_hex_full(&v.content_hash);
            let source_block_id_hex = bytes_to_hex_full(&v.source_block_id.0);
            VersionEntry {
                version: (idx + 1) as u32,
                created_at: timestamp_to_iso(v.created_at),
                backed_up_at,
                content_hash_hex,
                size_bytes: v.k as u64 * v.t as u64,
                source_block_id_hex,
            }
        })
        .collect();

    CliResponse::Versions(entries)
}

// ── Restore ───────────────────────────────────────────────────────────────────

async fn dispatch_restore(
    state: &DaemonState,
    path: String,
    version: Option<u32>,
    date: Option<String>,
    dest: Option<String>,
) -> CliResponse {
    // Resolve version selector.
    let version_selector = if let Some(v) = version {
        // version is 1-based from CLI; convert to 0-based index.
        let idx = v.saturating_sub(1) as usize;
        VersionSelector::Index(idx)
    } else if let Some(ref d) = date {
        // Parse ISO-8601 date "YYYY-MM-DD" as a Timestamp (start of day UTC).
        match parse_iso_date(d) {
            Some(ts) => VersionSelector::BeforeDate(ts),
            None => {
                return CliResponse::Error(format!("invalid date format: {d} (expected YYYY-MM-DD)"));
            }
        }
    } else {
        VersionSelector::Latest
    };

    let output_dir = dest
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let request = RestoreRequest {
        path: path.clone(),
        version_selector,
        output_dir,
        device_id: state.device_id,
    };

    // Look up the file record to find the version that will be used.
    // This lets us populate RestoreData accurately without waiting for the full restore.
    let (version_used, content_hash_hex) = match state.db.get_file(&path) {
        Ok(Some(record)) => {
            let v_idx = match &request.version_selector {
                VersionSelector::Latest => record.versions.len().saturating_sub(1),
                VersionSelector::Index(i) => *i,
                VersionSelector::BeforeDate(ts) => {
                    // Find rightmost version with backed_up_at <= ts.
                    record
                        .versions
                        .iter()
                        .enumerate()
                        .filter_map(|(i, v)| v.backed_up_at.map(|t| (i, t)))
                        .filter(|(_, t)| t.0 <= ts.0)
                        .map(|(i, _)| i)
                        .next_back()
                        .unwrap_or(0)
                }
            };
            let hash_hex = record
                .versions
                .get(v_idx)
                .map(|v| bytes_to_hex_full(&v.content_hash))
                .unwrap_or_else(|| "0".repeat(64));
            ((v_idx + 1) as u32, hash_hex)
        }
        Ok(None) => (1, "0".repeat(64)),
        Err(e) => return CliResponse::Error(format!("db error looking up file: {e}")),
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    if state.restore_tx.send((request, reply_tx)).await.is_err() {
        return CliResponse::Error("restore coordinator not running".to_string());
    }

    match reply_rx.await {
        Ok(Ok(_result)) => CliResponse::Restore(RestoreData {
            path,
            version_used,
            content_hash_hex,
            status: "started".to_string(),
        }),
        Ok(Err(e)) => CliResponse::Error(format!("restore failed: {e}")),
        Err(_) => CliResponse::Error("restore coordinator dropped response".to_string()),
    }
}

// ── Device list ───────────────────────────────────────────────────────────────

fn dispatch_device_list(state: &DaemonState) -> CliResponse {
    let cluster = match &state.cluster_state {
        Some(c) => c,
        None => return CliResponse::DeviceList(vec![]),
    };

    let cs = cluster.lock().expect("cluster_state lock poisoned");
    let revoked: std::collections::HashSet<syncback_core::types::DeviceId> = cs
        .all_devices()
        .iter()
        .filter(|d| cs.is_device_revoked(&d.device_id))
        .map(|d| d.device_id)
        .collect();

    let entries: Vec<DeviceEntry> = cs
        .all_devices()
        .iter()
        .map(|d| {
            let device_id_hex = bytes_to_hex_full(&d.device_id.0);
            let is_current = d.device_id == state.device_id;
            let added_at = timestamp_to_iso_date(d.certificate.issued_at);
            let is_revoked = revoked.contains(&d.device_id);
            DeviceEntry {
                device_id_hex,
                label: format!("device-{}", d.device_index),
                is_current,
                added_at,
                revoked: is_revoked,
            }
        })
        .collect();

    CliResponse::DeviceList(entries)
}

// ── Device add ────────────────────────────────────────────────────────────────

fn dispatch_device_add(state: &DaemonState, label: String) -> CliResponse {
    // Phase 6.6: device registration requires key exchange with the new device
    // (Phase 3 ClusterSync). Return a stub that acknowledges the label.
    // The real implementation will generate a cert and sync via cluster_sync.
    tracing::info!(label = %label, "DeviceAdd request received (stub — ClusterSync not yet wired)");

    let device_id_bytes = {
        // Derive a deterministic placeholder from our identity + label for display.
        // Real registration will use the new device's public key.
        let mut h = blake3::Hasher::new();
        h.update(&state.identity_pub.0);
        h.update(label.as_bytes());
        let hash = h.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_bytes()[..16]);
        id
    };

    let added_at = timestamp_to_iso_date(Timestamp::now());

    CliResponse::DeviceAdded(DeviceEntry {
        device_id_hex: bytes_to_hex_full(&device_id_bytes),
        label,
        is_current: false,
        added_at,
        revoked: false,
    })
}

// ============================================================
// Formatting helpers
// ============================================================

/// First 8 bytes as lowercase hex (16 chars). Used for peer identity display.
fn bytes_to_hex_8(bytes: &[u8]) -> String {
    bytes[..8.min(bytes.len())]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Full bytes as lowercase hex.
fn bytes_to_hex_full(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Unix timestamp → "YYYY-MM-DD HH:MM:SS" (UTC, approximate).
fn timestamp_to_iso(ts: Timestamp) -> String {
    unix_secs_to_iso(ts.0, true)
}

/// Unix timestamp → "YYYY-MM-DD" (UTC, date only).
fn timestamp_to_iso_date(ts: Timestamp) -> String {
    unix_secs_to_iso(ts.0, false)
}

/// Minimal ISO-8601-ish formatter without chrono dependency.
/// Computes year/month/day/hour/min/sec from a Unix timestamp using
/// the proleptic Gregorian calendar.
fn unix_secs_to_iso(secs: u64, include_time: bool) -> String {
    // Days since epoch.
    let days = (secs / 86400) as u32;
    let time_secs = secs % 86400;

    // Gregorian calendar calculation (civil date from days since 1970-01-01).
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html (civil_from_days).
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    if include_time {
        let h = time_secs / 3600;
        let min = (time_secs % 3600) / 60;
        let sec = time_secs % 60;
        format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{sec:02}")
    } else {
        format!("{y:04}-{m:02}-{d:02}")
    }
}

/// Parse "YYYY-MM-DD" to a Timestamp (start of day UTC). Returns None on parse error.
fn parse_iso_date(s: &str) -> Option<Timestamp> {
    let parts: Vec<&str> = s.splitn(3, '-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: u64 = parts[0].parse().ok()?;
    let month: u64 = parts[1].parse().ok()?;
    let day: u64 = parts[2].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Days from 1970-01-01 to year-month-day.
    // Algorithm: days_from_civil from Hinnant.
    let y = if month <= 2 { year as i64 - 1 } else { year as i64 };
    let m = month as i64;
    let d = day as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    if days < 0 {
        return None;
    }
    Some(Timestamp(days as u64 * 86400))
}

// ============================================================
// Framing helpers
// ============================================================

fn write_framed<W: Write, T: serde::Serialize>(mut writer: W, value: &T) -> Result<(), CliServerError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)
        .map_err(|e| CliServerError::Encode(e.to_string()))?;
    let len = buf.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&buf)?;
    Ok(())
}

fn read_framed<R: Read, T: serde::de::DeserializeOwned>(mut reader: R) -> Result<T, CliServerError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    ciborium::de::from_reader(payload.as_slice())
        .map_err(|e| CliServerError::Decode(e.to_string()))
}
