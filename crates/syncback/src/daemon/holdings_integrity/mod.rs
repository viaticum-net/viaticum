// HoldingsIntegrityTask: periodic scan verifying that held symbol directories exist on disk.
//
// For each Active holding in the DB, checks that holdings_dir/{block_hex}/ exists.
// If missing: removes the DB record immediately and posts SymbolDropped to the owner.
// Skips MarkedForDelete and Silent holdings — they may legitimately be absent.
//
// Guard: if holdings_dir itself is missing, logs ERROR and returns 0 without firing
// SymbolDropped for every holding (avoids false mass-reports on temporary unmount).

use std::path::{Path, PathBuf};
use std::time::Duration;

use syncback_core::db::Db;
use syncback_core::types::{HoldingRecord, HoldingStatus, IdentityPub, Timestamp, hex_encode};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::daemon::relay::RelayPost;

#[cfg(test)]
mod tests;

/// Run the holdings integrity scan task.
///
/// Periodically scans all Active holdings in DB and verifies that the corresponding
/// symbol directory exists on disk. If missing: posts SymbolDropped to the board
/// and removes the DB holding record immediately.
///
/// Scan interval: scan_interval_secs / time_scale (minimum 1 second).
/// Skips holdings with status != Active (MarkedForDelete, Silent may legitimately be absent).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    db: Db,
    holdings_dir: PathBuf,
    relay_post_tx: mpsc::Sender<RelayPost>,
    my_identity: IdentityPub,
    scan_interval_secs: u64,
    time_scale: u64,
    master_signing_key: ed25519_dalek::SigningKey,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let interval_secs = (scan_interval_secs / time_scale.max(1)).max(1);
    let mut timer = tokio::time::interval(Duration::from_secs(interval_secs));
    timer.tick().await;

    info!(
        interval_secs,
        identity = %my_identity,
        "holdings_integrity: started"
    );

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("holdings_integrity: shutting down");
                break;
            }
            _ = timer.tick() => {
                match scan_holdings(&db, &holdings_dir, &relay_post_tx, &master_signing_key).await {
                    Ok(missing) if missing > 0 => {
                        warn!(missing, "holdings_integrity: found missing holdings");
                    }
                    Ok(_) => {
                        debug!("holdings_integrity: scan complete, all holdings intact");
                    }
                    Err(e) => {
                        error!("holdings_integrity: scan error: {e}");
                    }
                }
            }
        }
    }

    Ok(())
}

/// One scan pass: check all Active holdings, report missing ones.
/// Returns count of missing holdings found.
async fn scan_holdings(
    db: &Db,
    holdings_dir: &Path,
    relay_post_tx: &mpsc::Sender<RelayPost>,
    master_signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<usize> {
    if !holdings_dir.exists() {
        error!(
            path = %holdings_dir.display(),
            "holdings_integrity: holdings_dir does not exist — cannot scan"
        );
        return Ok(0);
    }

    let db_clone = db.clone();
    let holdings = tokio::task::spawn_blocking(move || db_clone.list_all_holdings()).await??;

    let mut missing_count = 0usize;

    for holding in &holdings {
        if holding.status != HoldingStatus::Active {
            continue;
        }

        if !check_holding_on_disk(holding, holdings_dir) {
            missing_count += 1;
            warn!(
                block_id = %holding.source_block_id,
                owner = %holding.owner_id,
                "holdings_integrity: symbol directory missing on disk"
            );
            if let Err(e) =
                report_missing_holding(db, holding, relay_post_tx, master_signing_key).await
            {
                warn!(
                    block_id = %holding.source_block_id,
                    owner = %holding.owner_id,
                    err = %e,
                    "holdings_integrity: failed to report missing holding"
                );
            }
        }
    }

    Ok(missing_count)
}

/// Check if holding's symbol directory exists on disk.
/// Returns true if directory exists (holding intact), false if missing.
fn check_holding_on_disk(holding: &HoldingRecord, holdings_dir: &Path) -> bool {
    let block_hex = hex_encode(&holding.source_block_id.0);
    let block_dir = holdings_dir.join(&block_hex);
    block_dir.exists()
}

/// Post SymbolDropped for a missing holding and remove it from DB.
async fn report_missing_holding(
    db: &Db,
    holding: &HoldingRecord,
    relay_post_tx: &mpsc::Sender<RelayPost>,
    master_signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<()> {
    db.delete_holding(&holding.source_block_id, &holding.owner_id)?;

    // Refresh storage bytes for all devices of this owner's master identity.
    for did in db
        .get_devices_for_master(&holding.owner_id)
        .unwrap_or_default()
    {
        if let Err(e) = db.refresh_peer_storage_bytes(&did) {
            warn!(
                owner = %holding.owner_id,
                device = %did,
                err = %e,
                "holdings_integrity: failed to refresh storage bytes"
            );
        }
    }

    let msg = syncback_core::messages::build_symbol_dropped(
        holding.source_block_id,
        holding.esi_ranges.clone(),
        Timestamp::now(),
        master_signing_key,
    );
    if let Ok(payload) = syncback_core::messages::to_cbor(&msg) {
        let mut msg_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut msg_id);
        relay_post_tx
            .send(RelayPost {
                msg_type: "symbol_dropped".to_string(),
                target: Some(holding.owner_id),
                payload,
                msg_id,
            })
            .await?;
    }

    info!(
        block_id = %holding.source_block_id,
        owner = %holding.owner_id,
        "holdings_integrity: missing holding removed from DB, SymbolDropped sent"
    );
    Ok(())
}
