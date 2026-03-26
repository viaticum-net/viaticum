// HolderCleanupTask: periodic cleanup of expired holdings + disk pressure evaluation.
//
// Responsibilities:
//   - Scan for holdings where MarkedForDelete cooldown has expired → delete files + DB record → post SymbolDropped.
//   - Evaluate disk pressure periodically → evict lowest-priority holdings → post SymbolDropped.

use std::path::{Path, PathBuf};

use syncback_core::budget::{evaluate_pressure, DiskPressure};
use syncback_core::constants::{KI, KP, S_CLAMP_MAX, S_CLAMP_MIN};
use syncback_core::db::Db;
use syncback_core::messages::SymbolDroppedMsg;
use syncback_core::types::{hex_encode, IdentityPub, Timestamp};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::daemon::relay::RelayPost;

#[cfg(test)]
mod tests;

/// Run the holder cleanup task.
///
/// Two periodic actions:
/// 1. **Cleanup tick** (every `cleanup_interval_secs`): scan for holdings where
///    MarkedForDelete cooldown has expired. Delete symbol files, remove DB record,
///    post SymbolDropped to the board (directed to the owner).
/// 2. **Pressure tick** (every `pressure_interval_secs`): evaluate disk pressure.
///    On hard pressure, evict lowest-priority holdings and post SymbolDropped.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    db: Db,
    holdings_dir: PathBuf,
    relay_post_tx: mpsc::Sender<RelayPost>,
    soft_quota_bytes: u64,
    hard_quota_bytes: u64,
    data_dir: PathBuf,
    disk_reserve_bytes: u64,
    cleanup_interval_secs: u64,
    pressure_interval_secs: u64,
    time_scale: u64,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let mut cleanup_timer =
        tokio::time::interval(std::time::Duration::from_secs(cleanup_interval_secs.max(1)));
    let mut pressure_timer =
        tokio::time::interval(std::time::Duration::from_secs(pressure_interval_secs.max(1)));
    // Skip first immediate tick.
    cleanup_timer.tick().await;
    pressure_timer.tick().await;

    info!("holder_cleanup: started");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("holder_cleanup: shutting down");
                break;
            }
            _ = cleanup_timer.tick() => {
                if let Err(e) = cleanup_expired(&db, &holdings_dir, &relay_post_tx, time_scale).await {
                    error!("holder_cleanup: cleanup_expired error: {e}");
                }
            }
            _ = pressure_timer.tick() => {
                if let Err(e) = check_pressure(
                    &db, &holdings_dir, &relay_post_tx,
                    soft_quota_bytes, hard_quota_bytes,
                    &data_dir, disk_reserve_bytes,
                ).await {
                    error!("holder_cleanup: check_pressure error: {e}");
                }
            }
        }
    }

    Ok(())
}

/// Delete holdings whose MarkedForDelete cooldown has expired.
async fn cleanup_expired(
    db: &Db,
    holdings_dir: &Path,
    relay_post_tx: &mpsc::Sender<RelayPost>,
    time_scale: u64,
) -> anyhow::Result<()> {
    let now = Timestamp::now();
    let expired = db.list_holdings_cooldown_expired(now, time_scale)?;

    if expired.is_empty() {
        return Ok(());
    }

    info!(count = expired.len(), "holder_cleanup: processing expired holdings");

    for holding in &expired {
        // Delete symbol files.
        let block_hex = hex_encode(&holding.source_block_id.0);
        let block_dir = holdings_dir.join(&block_hex);
        if block_dir.exists() {
            if let Err(e) = tokio::fs::remove_dir_all(&block_dir).await {
                warn!(
                    block_id = %holding.source_block_id,
                    err = %e,
                    "holder_cleanup: failed to remove symbol files (may already be gone)"
                );
            }
        }

        // Remove DB record.
        if let Err(e) = db.delete_holding(&holding.source_block_id, &holding.owner_id) {
            error!(
                block_id = %holding.source_block_id,
                owner = %holding.owner_id,
                err = %e,
                "holder_cleanup: failed to delete holding from DB"
            );
            continue;
        }

        // Post SymbolDropped to the owner via board.
        post_symbol_dropped(
            relay_post_tx,
            holding.owner_id,
            holding.source_block_id,
            &holding.esi_ranges,
        ).await;

        // Refresh storage bytes for this peer.
        if let Err(e) = db.refresh_peer_storage_bytes(&holding.owner_id) {
            warn!(
                owner = %holding.owner_id,
                err = %e,
                "holder_cleanup: failed to refresh storage bytes"
            );
        }

        info!(
            block_id = %holding.source_block_id,
            owner = %holding.owner_id,
            "holder_cleanup: expired holding cleaned up, SymbolDropped sent"
        );
    }

    Ok(())
}

/// Evaluate disk pressure and evict if necessary.
#[allow(clippy::too_many_arguments)]
async fn check_pressure(
    db: &Db,
    holdings_dir: &Path,
    relay_post_tx: &mpsc::Sender<RelayPost>,
    soft_quota_bytes: u64,
    hard_quota_bytes: u64,
    data_dir: &Path,
    disk_reserve_bytes: u64,
) -> anyhow::Result<()> {
    let now = Timestamp::now();
    let holdings = db.list_all_holdings()?;
    let used_bytes: u64 = holdings.iter().map(|h| h.total_bytes).sum();

    // Compute effective quota from config + actual disk space.
    let disk_free = crate::daemon::handle::disk_available_bytes(data_dir);
    let effective_quota = syncback_core::budget::compute_effective_quota(
        soft_quota_bytes, disk_free, disk_reserve_bytes,
    );

    let trust_fn = |owner: &IdentityPub| -> f64 {
        match db.get_peer(owner) {
            Ok(Some(peer)) => {
                let s = peer.trust_s.clamp(S_CLAMP_MIN, S_CLAMP_MAX);
                (KP * peer.trust_p + KI * peer.trust_i) * s
            }
            _ => 0.5,
        }
    };

    let result = evaluate_pressure(
        effective_quota,
        hard_quota_bytes,
        used_bytes,
        &holdings,
        trust_fn,
        now.0,
    );

    match result.pressure {
        DiskPressure::Normal => {}
        DiskPressure::Soft => {
            info!(
                used_bytes,
                effective_quota,
                "holder_cleanup: soft disk pressure — not accepting new symbols"
            );
        }
        DiskPressure::Hard => {
            info!(
                used_bytes,
                effective_quota,
                evictions = result.immediate_evictions.len(),
                freed_bytes = result.freed_bytes,
                "holder_cleanup: hard disk pressure — evicting holdings"
            );

            for target in &result.immediate_evictions {
                // Delete symbol files.
                let block_hex = hex_encode(&target.source_block_id.0);
                let block_dir = holdings_dir.join(&block_hex);
                if block_dir.exists() {
                    if let Err(e) = tokio::fs::remove_dir_all(&block_dir).await {
                        warn!(
                            block_id = %target.source_block_id,
                            err = %e,
                            "holder_cleanup: failed to remove symbol files during eviction"
                        );
                    }
                }

                // Get ESI ranges before deleting.
                let esi_ranges = match db.get_holding(&target.source_block_id, &target.owner_id) {
                    Ok(Some(h)) => h.esi_ranges,
                    _ => vec![],
                };

                // Delete holding from DB.
                if let Err(e) = db.delete_holding(&target.source_block_id, &target.owner_id) {
                    error!(
                        block_id = %target.source_block_id,
                        owner = %target.owner_id,
                        err = %e,
                        "holder_cleanup: failed to delete holding during eviction"
                    );
                    continue;
                }

                // Post SymbolDropped.
                post_symbol_dropped(
                    relay_post_tx,
                    target.owner_id,
                    target.source_block_id,
                    &esi_ranges,
                ).await;
            }

            // Post SymbolDropNotice for buffered drop notices.
            for notice in &result.drop_notices {
                let notice_esi_ranges = match db.get_holding(&notice.source_block_id, &notice.owner_id) {
                    Ok(Some(h)) => h.esi_ranges,
                    _ => vec![],
                };
                let notice_msg = syncback_core::messages::SymbolDropNoticeMsg {
                    v: 1,
                    source_block_id: notice.source_block_id,
                    esi_ranges: notice_esi_ranges,
                    deadline: Timestamp(notice.deadline_secs),
                    timestamp: now,
                };
                if let Ok(payload) = syncback_core::messages::to_cbor(&notice_msg) {
                    let mut msg_id = [0u8; 16];
                    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut msg_id);
                    let _ = relay_post_tx.send(RelayPost {
                        msg_type: "symbol_drop_notice".to_string(),
                        target: Some(notice.owner_id),
                        payload,
                        msg_id,
                    }).await;
                }
            }

            // Refresh storage bytes for evicted owners.
            for target in &result.immediate_evictions {
                if let Err(e) = db.refresh_peer_storage_bytes(&target.owner_id) {
                    warn!(
                        owner = %target.owner_id,
                        err = %e,
                        "holder_cleanup: failed to refresh storage bytes after eviction"
                    );
                }
            }
        }
    }

    Ok(())
}

/// Post a SymbolDropped message to the board (directed to owner).
async fn post_symbol_dropped(
    relay_post_tx: &mpsc::Sender<RelayPost>,
    owner_id: IdentityPub,
    source_block_id: syncback_core::types::SourceBlockId,
    esi_ranges: &[(u32, u32)],
) {
    let msg = SymbolDroppedMsg {
        v: 1,
        source_block_id,
        esi_ranges: esi_ranges.to_vec(),
        timestamp: Timestamp::now(),
    };
    if let Ok(payload) = syncback_core::messages::to_cbor(&msg) {
        let mut msg_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut msg_id);
        let _ = relay_post_tx.send(RelayPost {
            msg_type: "symbol_dropped".to_string(),
            target: Some(owner_id),
            payload,
            msg_id,
        }).await;
    }
}
