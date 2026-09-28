// HoldingsIntegrityTask: periodic scan verifying that held symbol directories exist on disk.
//
// For each Active holding in the DB, checks that holdings_dir/{block_hex}/ exists.
// If missing: removes the DB record immediately and publishes an immediate-drop DropNotice
// (deadline=now) via the mailbox bus to notify the owner.
// Skips MarkedForDelete and Silent holdings — they may legitimately be absent.
//
// Guard: if holdings_dir itself is missing, logs ERROR and returns 0 without firing
// DropNotice for every holding (avoids false mass-reports on temporary unmount).
//
// T-13a: migrated from relay (SymbolDropped) to mailbox (DropNotice, deadline=now).
//
// A2 (T-13b-3): relay board fully retired; all DropNotice transport is via the mailbox bus.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use viaticum_core::cluster::master_identity;
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry, class_config};
use viaticum_core::messages::{SymbolDropNoticeBatchMsg, build_signed_symbol_drop_notice, to_cbor};
use viaticum_core::types::{HoldingRecord, HoldingStatus, IdentityPub, Timestamp, hex_encode};

use crate::daemon::mailbox::routing::MailboxRouter;

#[cfg(test)]
mod tests;

/// Run the holdings integrity scan task.
///
/// Periodically scans all Active holdings in DB and verifies that the corresponding
/// symbol directory exists on disk. If missing: publishes an immediate-drop DropNotice
/// (deadline=now) via the mailbox bus and removes the DB holding record immediately.
///
/// T-13a: migrated from relay (SymbolDropped) to mailbox (DropNotice, deadline=now).
///
/// Scan interval: scan_interval_secs / time_scale (minimum 1 second).
/// Skips holdings with status != Active (MarkedForDelete, Silent may legitimately be absent).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    db: Db,
    holdings_dir: PathBuf,
    mailbox_router: Arc<MailboxRouter>,
    my_identity: IdentityPub,
    scan_interval_secs: u64,
    time_scale: u64,
    master_signing_key: ed25519_dalek::SigningKey,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let interval_secs = (scan_interval_secs / time_scale.max(1)).max(1);
    let mut timer = tokio::time::interval(Duration::from_secs(interval_secs));
    timer.tick().await;

    let holder_master_pub = master_identity(&master_signing_key);

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
                match scan_holdings(&db, &holdings_dir, &mailbox_router, holder_master_pub, time_scale, &master_signing_key).await {
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
    mailbox_router: &Arc<MailboxRouter>,
    holder_master_pub: IdentityPub,
    time_scale: u64,
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
            if let Err(e) = report_missing_holding(
                db,
                holding,
                mailbox_router,
                holder_master_pub,
                time_scale,
                master_signing_key,
            )
            .await
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

/// T-13a: Publish an immediate-drop DropNotice (deadline=now) for a missing holding,
/// and remove it from DB. Replaces the former SymbolDropped-via-relay path.
async fn report_missing_holding(
    db: &Db,
    holding: &HoldingRecord,
    mailbox_router: &Arc<MailboxRouter>,
    holder_master_pub: IdentityPub,
    time_scale: u64,
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

    // Publish immediate-drop DropNotice via mailbox (deadline=now).
    // Sign with the holder's master key so the owner can verify authenticity.
    let now = Timestamp::now();
    let now_secs = now.0;
    let notice = build_signed_symbol_drop_notice(
        holding.source_block_id,
        holding.esi_ranges.clone(),
        now,
        now,
        master_signing_key,
    );
    let batch = SymbolDropNoticeBatchMsg {
        v: 1,
        notices: vec![notice],
    };
    if let Ok(payload) = to_cbor(&batch) {
        let ttl_secs = viaticum_core::mailbox::scaled_ttl_secs(
            class_config::DROP_NOTICE_TTL.as_secs(),
            time_scale,
        );
        let mut msg_id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut msg_id);
        let entry = MailboxEntry {
            target: MailboxAddress::for_master(&holding.owner_id),
            msg_id,
            class: MailboxClass::DropNotice,
            payload_version: 1,
            payload,
            expires_at: now_secs + ttl_secs,
            stored_at: now_secs,
            sender: Some(holder_master_pub),
        };
        match mailbox_router.publish(entry, None).await {
            Ok(0) => {
                warn!(
                    block_id = %holding.source_block_id,
                    owner = %holding.owner_id,
                    "holdings_integrity: immediate-drop DropNotice got 0 acks (best-effort)"
                );
            }
            Ok(n) => {
                debug!(
                    block_id = %holding.source_block_id,
                    owner = %holding.owner_id,
                    ack_count = n,
                    "holdings_integrity: immediate-drop DropNotice published via mailbox"
                );
            }
            Err(e) => {
                warn!(
                    block_id = %holding.source_block_id,
                    owner = %holding.owner_id,
                    err = %e,
                    "holdings_integrity: immediate-drop DropNotice publish failed (best-effort)"
                );
            }
        }
    }

    info!(
        block_id = %holding.source_block_id,
        owner = %holding.owner_id,
        "holdings_integrity: missing holding removed from DB, immediate-drop DropNotice sent via mailbox"
    );
    Ok(())
}
