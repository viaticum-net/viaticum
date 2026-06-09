// HolderCleanupTask: periodic cleanup of expired holdings + disk pressure evaluation.
//
// Responsibilities:
//   - Scan for holdings where MarkedForDelete cooldown has expired → delete files + DB record → post SymbolDropped.
//   - Evaluate disk pressure periodically → evict lowest-priority holdings → post SymbolDropped.
//   - T-7: send DropNotice (advance notice) via mailbox instead of relay, batched per owner.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use viaticum_core::budget::{DiskPressure, evaluate_pressure};
use viaticum_core::cluster::master_identity;
use viaticum_core::constants::{KI, KP, S_CLAMP_MAX, S_CLAMP_MIN};
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxClass, MailboxEntry, class_config};
use viaticum_core::messages::{SymbolDropNoticeBatchMsg, SymbolDropNoticeMsg, to_cbor};
use viaticum_core::types::{IdentityPub, Timestamp, hex_encode};

use crate::daemon::mailbox::routing::MailboxRouter;
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
///
/// T-7: advance DropNotice (before physical delete) is routed through the mailbox bus,
/// batched per owner (one `SymbolDropNoticeBatchMsg` entry per owner per chunk ≤ MAX_ENTRY_BYTES).
/// The `SymbolDropped` (immediate eviction) path remains on relay (scope fence: T-13 retires relay).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    db: Db,
    holdings_dir: PathBuf,
    relay_post_tx: mpsc::Sender<RelayPost>,
    mailbox_router: Arc<MailboxRouter>,
    soft_quota_bytes: u64,
    hard_quota_bytes: u64,
    data_dir: PathBuf,
    disk_reserve_bytes: u64,
    cleanup_interval_secs: u64,
    pressure_interval_secs: u64,
    time_scale: u64,
    master_signing_key: ed25519_dalek::SigningKey,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let mut cleanup_timer =
        tokio::time::interval(std::time::Duration::from_secs(cleanup_interval_secs.max(1)));
    let mut pressure_timer = tokio::time::interval(std::time::Duration::from_secs(
        pressure_interval_secs.max(1),
    ));
    // Drop-notice cleanup runs on the same interval as delete-cooldown cleanup.
    let mut drop_notice_timer =
        tokio::time::interval(std::time::Duration::from_secs(cleanup_interval_secs.max(1)));
    // Skip first immediate tick.
    cleanup_timer.tick().await;
    pressure_timer.tick().await;
    drop_notice_timer.tick().await;

    info!("holder_cleanup: started");

    // Derive holder's own master IdentityPub for use as `sender` in mailbox entries.
    let holder_master_pub = master_identity(&master_signing_key);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("holder_cleanup: shutting down");
                break;
            }
            _ = cleanup_timer.tick() => {
                if let Err(e) = cleanup_expired(&db, &holdings_dir, &relay_post_tx, time_scale, &master_signing_key).await {
                    error!("holder_cleanup: cleanup_expired error: {e}");
                }
            }
            _ = pressure_timer.tick() => {
                if let Err(e) = check_pressure(
                    &db, &holdings_dir, &relay_post_tx, &mailbox_router, holder_master_pub,
                    soft_quota_bytes, hard_quota_bytes,
                    &data_dir, disk_reserve_bytes,
                    &master_signing_key,
                ).await {
                    error!("holder_cleanup: check_pressure error: {e}");
                }
            }
            _ = drop_notice_timer.tick() => {
                if let Err(e) = cleanup_drop_notices(&db, &holdings_dir, &relay_post_tx, &master_signing_key).await {
                    error!("holder_cleanup: cleanup_drop_notices error: {e}");
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
    master_signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<()> {
    let now = Timestamp::now();
    let expired = db.list_holdings_cooldown_expired(now, time_scale)?;

    if expired.is_empty() {
        return Ok(());
    }

    info!(
        count = expired.len(),
        "holder_cleanup: processing expired holdings"
    );

    for holding in &expired {
        // Delete symbol files.
        let block_hex = hex_encode(&holding.source_block_id.0);
        let block_dir = holdings_dir.join(&block_hex);
        if block_dir.exists()
            && let Err(e) = tokio::fs::remove_dir_all(&block_dir).await
        {
            warn!(
                block_id = %holding.source_block_id,
                err = %e,
                "holder_cleanup: failed to remove symbol files (may already be gone)"
            );
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
            master_signing_key,
        )
        .await;

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
                    "holder_cleanup: failed to refresh storage bytes"
                );
            }
        }

        info!(
            block_id = %holding.source_block_id,
            owner = %holding.owner_id,
            "holder_cleanup: expired holding cleaned up, SymbolDropped sent"
        );
    }

    Ok(())
}

/// Evict holdings whose drop-notice window (7 days) has expired.
/// The owner was notified via SymbolDropNotice; now we actually delete.
async fn cleanup_drop_notices(
    db: &Db,
    holdings_dir: &Path,
    relay_post_tx: &mpsc::Sender<RelayPost>,
    master_signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<()> {
    let now = Timestamp::now();
    let expired = db.list_holdings_drop_notice_expired(now)?;

    if expired.is_empty() {
        return Ok(());
    }

    info!(
        count = expired.len(),
        "holder_cleanup: processing expired drop notices"
    );

    for holding in &expired {
        // Delete symbol files.
        let block_hex = hex_encode(&holding.source_block_id.0);
        let block_dir = holdings_dir.join(&block_hex);
        if block_dir.exists()
            && let Err(e) = tokio::fs::remove_dir_all(&block_dir).await
        {
            warn!(
                block_id = %holding.source_block_id,
                err = %e,
                "holder_cleanup: failed to remove symbol files for expired drop notice"
            );
        }

        // Remove DB record.
        if let Err(e) = db.delete_holding(&holding.source_block_id, &holding.owner_id) {
            error!(
                block_id = %holding.source_block_id,
                owner = %holding.owner_id,
                err = %e,
                "holder_cleanup: failed to delete holding after drop notice expiry"
            );
            continue;
        }

        // Post SymbolDropped to the owner.
        post_symbol_dropped(
            relay_post_tx,
            holding.owner_id,
            holding.source_block_id,
            &holding.esi_ranges,
            master_signing_key,
        )
        .await;

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
                    "holder_cleanup: failed to refresh storage bytes after drop notice cleanup"
                );
            }
        }

        info!(
            block_id = %holding.source_block_id,
            owner = %holding.owner_id,
            "holder_cleanup: drop notice expired, holding evicted"
        );
    }

    Ok(())
}

/// Evaluate disk pressure and evict if necessary.
///
/// T-7: advance DropNotice entries are routed through the mailbox bus (batched per owner).
/// The `SymbolDropped` (immediate eviction) path remains on relay (T-13 retires relay).
#[allow(clippy::too_many_arguments)]
async fn check_pressure(
    db: &Db,
    holdings_dir: &Path,
    relay_post_tx: &mpsc::Sender<RelayPost>,
    mailbox_router: &Arc<MailboxRouter>,
    holder_master_pub: IdentityPub,
    soft_quota_bytes: u64,
    hard_quota_bytes: u64,
    data_dir: &Path,
    disk_reserve_bytes: u64,
    master_signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<()> {
    let now = Timestamp::now();
    let holdings = db.list_all_holdings()?;
    let used_bytes: u64 = holdings.iter().map(|h| h.total_bytes).sum();

    // Compute effective quota from config + actual disk space.
    let disk_free = crate::daemon::handle::disk_available_bytes(data_dir);
    let effective_quota = viaticum_core::budget::compute_effective_quota(
        soft_quota_bytes,
        disk_free,
        disk_reserve_bytes,
    );

    let trust_fn = |owner: &IdentityPub| -> f64 {
        // PeerRecord is keyed by DeviceId; look up the first device for this master.
        let devices = db.get_devices_for_master(owner).unwrap_or_default();
        let peer_opt = devices
            .iter()
            .find_map(|did| db.get_peer(did).ok().flatten());
        match peer_opt {
            Some(peer) => {
                let s = peer.trust_s.clamp(S_CLAMP_MIN, S_CLAMP_MAX);
                (KP * peer.trust_p + KI * peer.trust_i) * s
            }
            None => 0.5,
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
                effective_quota, "holder_cleanup: soft disk pressure — not accepting new symbols"
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
                if block_dir.exists()
                    && let Err(e) = tokio::fs::remove_dir_all(&block_dir).await
                {
                    warn!(
                        block_id = %target.source_block_id,
                        err = %e,
                        "holder_cleanup: failed to remove symbol files during eviction"
                    );
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
                    master_signing_key,
                )
                .await;
            }

            // T-7: send DropNotice via mailbox, batched per owner.
            // Group notices by owner_id, then publish each group as one or more
            // SymbolDropNoticeBatchMsg entries (chunked to ≤ MAX_ENTRY_BYTES each).
            //
            // Scope fence: `SymbolDropped` (immediate eviction) stays on relay;
            // only the advance-notice path moves here.
            publish_drop_notices_via_mailbox(
                db,
                &result.drop_notices,
                mailbox_router,
                holder_master_pub,
                now,
            )
            .await;

            // Refresh storage bytes for evicted owners (all devices of each master).
            for target in &result.immediate_evictions {
                for did in db
                    .get_devices_for_master(&target.owner_id)
                    .unwrap_or_default()
                {
                    if let Err(e) = db.refresh_peer_storage_bytes(&did) {
                        warn!(
                            owner = %target.owner_id,
                            device = %did,
                            err = %e,
                            "holder_cleanup: failed to refresh storage bytes after eviction"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// T-7: Publish DropNotice entries via the mailbox bus, batched per owner.
///
/// Groups `DropNoticeTarget` list by `owner_id`. For each owner:
///   1. Builds `Vec<SymbolDropNoticeMsg>` (reading ESI ranges from DB for each notice).
///   2. Chunks into `SymbolDropNoticeBatchMsg` entries ≤ `MAX_ENTRY_BYTES` each.
///   3. Publishes each chunk via `mailbox_router.publish`.
///   4. W-4 (best-effort): if publish returns 0 acks, retries once; logs WARN on second 0.
///   5. Records `drop_notice_sent_at` on each holding (once, idempotent).
///
/// `SymbolDropped` (immediate-eviction relay path) is NOT touched — scope fence: T-13.
async fn publish_drop_notices_via_mailbox(
    db: &Db,
    drop_notices: &[viaticum_core::budget::DropNoticeTarget],
    mailbox_router: &Arc<MailboxRouter>,
    holder_master_pub: IdentityPub,
    now: Timestamp,
) {
    if drop_notices.is_empty() {
        return;
    }

    // Step 1: Group notices by owner_id and resolve ESI ranges from DB.
    let mut by_owner: HashMap<IdentityPub, Vec<SymbolDropNoticeMsg>> = HashMap::new();
    for notice in drop_notices {
        let holding = match db.get_holding(&notice.source_block_id, &notice.owner_id) {
            Ok(Some(h)) => h,
            Ok(None) => {
                warn!(
                    block_id = %notice.source_block_id,
                    owner = %notice.owner_id,
                    "holder_cleanup: drop notice holding not found in DB, skipping"
                );
                continue;
            }
            Err(e) => {
                warn!(
                    block_id = %notice.source_block_id,
                    owner = %notice.owner_id,
                    err = %e,
                    "holder_cleanup: failed to get holding for drop notice, skipping"
                );
                continue;
            }
        };

        let notice_msg = SymbolDropNoticeMsg {
            v: 1,
            source_block_id: notice.source_block_id,
            esi_ranges: holding.esi_ranges.clone(),
            deadline: Timestamp(notice.deadline_secs),
            timestamp: now,
        };
        by_owner
            .entry(notice.owner_id)
            .or_default()
            .push(notice_msg);
    }

    let now_secs = now.0;
    let ttl_secs = class_config::DROP_NOTICE_TTL.as_secs();

    // Step 2: For each owner, chunk and publish.
    for (owner_id, notices) in &by_owner {
        // Chunk notices so each SymbolDropNoticeBatchMsg CBOR payload ≤ MAX_ENTRY_BYTES.
        // Estimate: probe-serialize the batch to check; if too large, bisect.
        // Simple approach: start with all, if over cap, split in half recursively.
        let chunks = chunk_notices_to_fit(notices);

        for chunk in chunks {
            let batch = SymbolDropNoticeBatchMsg {
                v: 1,
                notices: chunk,
            };
            let payload = match to_cbor(&batch) {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        owner = %owner_id,
                        err = %e,
                        "holder_cleanup: failed to serialize DropNotice batch, skipping chunk"
                    );
                    continue;
                }
            };

            if payload.len() > class_config::MAX_ENTRY_BYTES {
                // Should not happen after chunking, but guard defensively.
                warn!(
                    owner = %owner_id,
                    size = payload.len(),
                    max = class_config::MAX_ENTRY_BYTES,
                    "holder_cleanup: DropNotice chunk still too large after split, skipping"
                );
                continue;
            }

            let mut msg_id = [0u8; 16];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut msg_id);

            let entry = MailboxEntry {
                target: *owner_id,
                msg_id,
                class: MailboxClass::DropNotice,
                payload_version: 1,
                payload,
                expires_at: now_secs + ttl_secs,
                stored_at: now_secs,
                sender: Some(holder_master_pub),
            };

            // W-4: best-effort publish — retry once on 0 acks.
            let ack_count = match mailbox_router.publish(owner_id, entry.clone()).await {
                Ok(n) => n,
                Err(e) => {
                    warn!(
                        owner = %owner_id,
                        err = %e,
                        "holder_cleanup: DropNotice mailbox publish failed (best-effort, continuing)"
                    );
                    continue;
                }
            };

            if ack_count == 0 {
                // W-4: retry once on 0 acks.
                let mut retry_msg_id = [0u8; 16];
                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut retry_msg_id);
                let retry_entry = MailboxEntry {
                    msg_id: retry_msg_id,
                    ..entry
                };
                match mailbox_router.publish(owner_id, retry_entry).await {
                    Ok(0) => {
                        // W-4 documented known limitation: notice may be lost.
                        // Owner detects via next PoS miss (N-6: notice TTL = 14d).
                        warn!(
                            owner = %owner_id,
                            "holder_cleanup: DropNotice retry also got 0 acks \
                             — notice may be lost (W-4 known limitation; \
                             owner detects via next PoS, TTL=14d)"
                        );
                    }
                    Ok(n) => {
                        info!(
                            owner = %owner_id,
                            ack_count = n,
                            "holder_cleanup: DropNotice published on retry"
                        );
                    }
                    Err(e) => {
                        warn!(
                            owner = %owner_id,
                            err = %e,
                            "holder_cleanup: DropNotice retry publish failed (W-4)"
                        );
                    }
                }
            }
        }
    }

    // Step 3: Record drop_notice_sent_at on each holding (idempotent — only set if not already set).
    for notice in drop_notices {
        let holding = match db.get_holding(&notice.source_block_id, &notice.owner_id) {
            Ok(Some(h)) => h,
            _ => continue,
        };
        if holding.drop_notice_sent_at.is_none() {
            let mut updated = holding;
            updated.drop_notice_sent_at = Some(now);
            if let Err(e) = db.upsert_holding(&updated) {
                warn!(
                    block_id = %notice.source_block_id,
                    owner = %notice.owner_id,
                    err = %e,
                    "holder_cleanup: failed to record drop_notice_sent_at"
                );
            }
        }
    }
}

/// Chunk `notices` into groups where each group's CBOR serialized size ≤ MAX_ENTRY_BYTES.
///
/// Strategy: try all at once; if over the cap, bisect recursively.
/// In practice `~100 bytes/notice × 2560 notices ≤ 256KB`, so a single chunk covers
/// most mass-eviction scenarios. Explicit cap enforcement prevents edge cases.
fn chunk_notices_to_fit(notices: &[SymbolDropNoticeMsg]) -> Vec<Vec<SymbolDropNoticeMsg>> {
    if notices.is_empty() {
        return vec![];
    }

    // Try serializing the full batch to check size.
    let batch = SymbolDropNoticeBatchMsg {
        v: 1,
        notices: notices.to_vec(),
    };
    match to_cbor(&batch) {
        Ok(bytes) if bytes.len() <= class_config::MAX_ENTRY_BYTES => {
            // Fits in one chunk.
            vec![notices.to_vec()]
        }
        _ => {
            // Too large or serialization failed: bisect.
            if notices.len() == 1 {
                // Single notice still over the cap — cannot split further.
                // Return it as-is; the caller's post-chunk size guard (~publish loop)
                // will reject it with a warn and skip it. The holding then falls through
                // to the SymbolDropped relay fallback after the drop window expires
                // (scope fence: T-13 retires relay). The receiver never sees this entry.
                warn!(
                    "holder_cleanup: single DropNotice entry exceeds MAX_ENTRY_BYTES \
                     (esi_ranges list unusually large) — will be skipped by size guard"
                );
                return vec![notices.to_vec()];
            }
            let mid = notices.len() / 2;
            let mut left = chunk_notices_to_fit(&notices[..mid]);
            let right = chunk_notices_to_fit(&notices[mid..]);
            left.extend(right);
            left
        }
    }
}

/// Post a SymbolDropped message to the board (directed to owner).
async fn post_symbol_dropped(
    relay_post_tx: &mpsc::Sender<RelayPost>,
    owner_id: IdentityPub,
    source_block_id: viaticum_core::types::SourceBlockId,
    esi_ranges: &[(u32, u32)],
    master_signing_key: &ed25519_dalek::SigningKey,
) {
    let msg = viaticum_core::messages::build_symbol_dropped(
        source_block_id,
        esi_ranges.to_vec(),
        Timestamp::now(),
        master_signing_key,
    );
    if let Ok(payload) = viaticum_core::messages::to_cbor(&msg) {
        let mut msg_id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut msg_id);
        let _ = relay_post_tx
            .send(RelayPost {
                msg_type: "symbol_dropped".to_string(),
                target: Some(owner_id),
                payload,
                msg_id,
            })
            .await;
    }
}
