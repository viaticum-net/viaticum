// Metrics pusher: periodically POST Prometheus text metrics to a remote endpoint.
//
// Push model (not pull) because nodes are behind NAT and cannot be scraped.
// Target: VictoriaMetrics `POST /api/v1/import/prometheus`.

use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

use syncback_core::config::MetricsCfg;
use syncback_core::types::hex_encode;
use tokio_util::sync::CancellationToken;

use crate::cli::types::{CliResponse, StatusData};
use crate::daemon::handle::DaemonState;

#[cfg(test)]
mod tests;

/// Format a StatusData snapshot as Prometheus text exposition.
///
/// Each metric line: `syncback_<name>{node="<node_id>"} <value>\n`
/// Per-peer metrics add a `peer="<hex>"` label.
pub(crate) fn format_prometheus(status: &StatusData, node_id: &str) -> String {
    let mut out = String::with_capacity(4096);

    // Node-level gauges
    let _ = writeln!(out, "# TYPE syncback_peer_count gauge");
    let _ = writeln!(out, "syncback_peer_count{{node=\"{node_id}\"}} {}", status.peer_count);
    let _ = writeln!(out, "# TYPE syncback_avg_trust gauge");
    let _ = writeln!(out, "syncback_avg_trust{{node=\"{node_id}\"}} {:.6}", status.avg_trust);
    let _ = writeln!(out, "# TYPE syncback_holding_bytes gauge");
    let _ = writeln!(out, "syncback_holding_bytes{{node=\"{node_id}\"}} {}", status.holding_bytes);
    let _ = writeln!(out, "# TYPE syncback_backed_up_files gauge");
    let _ = writeln!(out, "syncback_backed_up_files{{node=\"{node_id}\"}} {}", status.backed_up_files);
    let _ = writeln!(out, "# TYPE syncback_backed_up_bytes gauge");
    let _ = writeln!(out, "syncback_backed_up_bytes{{node=\"{node_id}\"}} {}", status.backed_up_bytes);
    let _ = writeln!(out, "# TYPE syncback_blocks_ok gauge");
    let _ = writeln!(out, "syncback_blocks_ok{{node=\"{node_id}\"}} {}", status.blocks_ok);
    let _ = writeln!(out, "# TYPE syncback_blocks_at_risk gauge");
    let _ = writeln!(out, "syncback_blocks_at_risk{{node=\"{node_id}\"}} {}", status.blocks_at_risk);
    let _ = writeln!(out, "# TYPE syncback_blocks_needing_repair gauge");
    let _ = writeln!(out, "syncback_blocks_needing_repair{{node=\"{node_id}\"}} {}", status.blocks_needing_repair);
    let _ = writeln!(out, "# TYPE syncback_placement_alive gauge");
    let _ = writeln!(out, "syncback_placement_alive{{node=\"{node_id}\"}} {}", status.placement_alive);
    let _ = writeln!(out, "# TYPE syncback_placement_lost gauge");
    let _ = writeln!(out, "syncback_placement_lost{{node=\"{node_id}\"}} {}", status.placement_lost);
    let _ = writeln!(out, "# TYPE syncback_effective_quota_bytes gauge");
    let _ = writeln!(out, "syncback_effective_quota_bytes{{node=\"{node_id}\"}} {}", status.effective_quota_bytes);
    let _ = writeln!(out, "# TYPE syncback_used_bytes gauge");
    let _ = writeln!(out, "syncback_used_bytes{{node=\"{node_id}\"}} {}", status.used_bytes);

    // Counters
    let _ = writeln!(out, "# TYPE syncback_pos_challenges_total counter");
    let _ = writeln!(out, "syncback_pos_challenges_total{{node=\"{node_id}\"}} {}", status.pos_total_challenges);
    let _ = writeln!(out, "# TYPE syncback_pos_passes_total counter");
    let _ = writeln!(out, "syncback_pos_passes_total{{node=\"{node_id}\"}} {}", status.pos_total_passes);

    // Per-peer gauges
    if !status.peers.is_empty() {
        let _ = writeln!(out, "# TYPE syncback_trust_p gauge");
        let _ = writeln!(out, "# TYPE syncback_trust_i gauge");
        let _ = writeln!(out, "# TYPE syncback_trust_s gauge");
        let _ = writeln!(out, "# TYPE syncback_trust_combined gauge");
        let _ = writeln!(out, "# TYPE syncback_peer_bytes_we_store gauge");
        let _ = writeln!(out, "# TYPE syncback_peer_bytes_stored_for_us gauge");
    }
    for p in &status.peers {
        let peer = &p.identity_hex;
        let _ = writeln!(out, "syncback_trust_p{{node=\"{node_id}\",peer=\"{peer}\"}} {:.6}", p.trust_p);
        let _ = writeln!(out, "syncback_trust_i{{node=\"{node_id}\",peer=\"{peer}\"}} {:.6}", p.trust_i);
        let _ = writeln!(out, "syncback_trust_s{{node=\"{node_id}\",peer=\"{peer}\"}} {:.6}", p.trust_s);
        let _ = writeln!(out, "syncback_trust_combined{{node=\"{node_id}\",peer=\"{peer}\"}} {:.6}", p.trust);
        let _ = writeln!(out, "syncback_peer_bytes_we_store{{node=\"{node_id}\",peer=\"{peer}\"}} {}", p.bytes_we_store);
        let _ = writeln!(out, "syncback_peer_bytes_stored_for_us{{node=\"{node_id}\",peer=\"{peer}\"}} {}", p.bytes_peer_stores);
    }

    out
}

/// Run the metrics push loop.
///
/// Periodically calls `dispatch_status` to collect metrics, formats them as
/// Prometheus text, and POSTs to `cfg.push_url`. Exits when `cancel` fires.
pub async fn run(
    cfg: MetricsCfg,
    state: Arc<DaemonState>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    if !cfg.enabled || cfg.push_url.is_empty() {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // Use first 16 hex chars of identity as node label.
    let node_id = hex_encode(&state.identity_pub.0);
    let node_id = &node_id[..16.min(node_id.len())];
    let node_id = node_id.to_string();

    let interval_secs = cfg.push_interval_secs.max(5);
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

    tracing::info!(
        push_url = %cfg.push_url,
        interval_secs,
        "metrics pusher started"
    );

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("metrics pusher: shutting down");
                break;
            }
            _ = interval.tick() => {
                let response = crate::daemon::dispatch::dispatch_status(&state).await;
                if let CliResponse::Status(data) = response {
                    let body = format_prometheus(&data, &node_id);
                    if let Err(e) = client
                        .post(&cfg.push_url)
                        .header("Content-Type", "text/plain")
                        .body(body)
                        .send()
                        .await
                    {
                        tracing::warn!(err = %e, "metrics: push failed");
                    }
                }
            }
        }
    }

    Ok(())
}
