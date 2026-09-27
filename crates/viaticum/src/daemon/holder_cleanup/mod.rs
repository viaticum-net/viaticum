// HolderCleanupTask: periodic cleanup of expired holdings + disk pressure evaluation.
//
// Responsibilities:
//   - Scan for holdings where MarkedForDelete cooldown has expired → delete files + DB record → publish DropNotice via mailbox.
//   - Evaluate disk pressure periodically → evict lowest-priority holdings → publish DropNotice via mailbox.
//   - T-7: advance DropNotice (before physical delete) via mailbox, batched per owner.
//   - T-13a: immediate-drop DropNotice (deadline=now) via mailbox.
//
// A2 (T-13b-3): relay board fully retired; all DropNotice transport is via the mailbox bus.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use viaticum_core::budget::{DiskPressure, evaluate_pressure};
use viaticum_core::cluster::master_identity;
use viaticum_core::constants::{KI, KP, S_CLAMP_MAX, S_CLAMP_MIN};
use viaticum_core::db::Db;
use viaticum_core::four_r_holder::FourRParams;
use viaticum_core::mailbox::{MailboxClass, MailboxEntry, class_config};
use viaticum_core::messages::{
    SymbolDropNoticeBatchMsg, SymbolDropNoticeMsg, build_signed_symbol_drop_notice, to_cbor,
};
use viaticum_core::types::{IdentityPub, Timestamp, hex_encode};

use crate::daemon::mailbox::routing::MailboxRouter;

mod shadow;

#[cfg(test)]
mod tests;

/// Run the holder cleanup task.
///
/// Two periodic actions:
/// 1. **Cleanup tick** (every `cleanup_interval_secs`): scan for holdings where
///    MarkedForDelete cooldown has expired. Delete symbol files, remove DB record,
///    publish DropNotice (deadline=now) via mailbox to notify the owner.
/// 2. **Pressure tick** (every `pressure_interval_secs`): evaluate disk pressure.
///    On hard pressure, evict lowest-priority holdings and publish immediate DropNotice.
///
/// T-7: advance DropNotice (before physical delete) via mailbox, batched per owner.
/// T-13a: immediate-drop DropNotice (deadline=now) via mailbox.
///
/// В-0: every pressure tick also runs the 4R SHADOW (`four_r`: the `[four_r]` dials) — logs
/// only, see `shadow.rs`.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    db: Db,
    holdings_dir: PathBuf,
    mailbox_router: Arc<MailboxRouter>,
    soft_quota_bytes: u64,
    hard_quota_bytes: u64,
    data_dir: PathBuf,
    disk_reserve_bytes: u64,
    cleanup_interval_secs: u64,
    pressure_interval_secs: u64,
    time_scale: u64,
    master_signing_key: ed25519_dalek::SigningKey,
    four_r: FourRParams,
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
                if let Err(e) = cleanup_expired(&db, &holdings_dir, &mailbox_router, holder_master_pub, time_scale, &master_signing_key).await {
                    error!("holder_cleanup: cleanup_expired error: {e}");
                }
            }
            _ = pressure_timer.tick() => {
                if let Err(e) = check_pressure(
                    &db, &holdings_dir, &mailbox_router, holder_master_pub,
                    soft_quota_bytes, hard_quota_bytes,
                    &data_dir, disk_reserve_bytes,
                    time_scale,
                    &master_signing_key,
                    &four_r,
                ).await {
                    error!("holder_cleanup: check_pressure error: {e}");
                }
            }
            _ = drop_notice_timer.tick() => {
                if let Err(e) = cleanup_drop_notices(&db, &holdings_dir, &mailbox_router, holder_master_pub, time_scale, &master_signing_key).await {
                    error!("holder_cleanup: cleanup_drop_notices error: {e}");
                }
            }
        }
    }

    Ok(())
}

/// Delete holdings whose MarkedForDelete cooldown has expired.
/// T-13a: publishes immediate-drop DropNotice via mailbox (deadline=now).
async fn cleanup_expired(
    db: &Db,
    holdings_dir: &Path,
    mailbox_router: &Arc<MailboxRouter>,
    holder_master_pub: IdentityPub,
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

        // T-13a: publish immediate-drop DropNotice via mailbox (deadline=now).
        post_symbol_dropped_via_mailbox(
            mailbox_router,
            holder_master_pub,
            holding.owner_id,
            holding.source_block_id,
            &holding.esi_ranges,
            time_scale,
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
            "holder_cleanup: expired holding cleaned up, immediate-drop DropNotice sent via mailbox"
        );
    }

    Ok(())
}

/// Evict holdings whose drop-notice window (7 days) has expired.
/// The owner was notified via SymbolDropNotice; now we actually delete.
/// T-13a: publishes immediate-drop DropNotice via mailbox (deadline=now).
async fn cleanup_drop_notices(
    db: &Db,
    holdings_dir: &Path,
    mailbox_router: &Arc<MailboxRouter>,
    holder_master_pub: IdentityPub,
    time_scale: u64,
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

        // T-13a: publish immediate-drop DropNotice via mailbox (deadline=now).
        post_symbol_dropped_via_mailbox(
            mailbox_router,
            holder_master_pub,
            holding.owner_id,
            holding.source_block_id,
            &holding.esi_ranges,
            time_scale,
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
            "holder_cleanup: drop notice expired, holding evicted, immediate-drop DropNotice sent via mailbox"
        );
    }

    Ok(())
}

/// Evaluate disk pressure and evict if necessary.
///
/// T-7: advance DropNotice entries via mailbox, batched per owner.
/// T-13a: immediate-drop DropNotice (deadline=now) via mailbox (replaces SymbolDropped-via-relay).
///
/// В-0: between `evaluate_pressure` and the old path's actions the 4R shadow runs over the
/// same snapshot (`shadow::shadow_pressure`); its failure is a `warn!`, never an early return.
#[allow(clippy::too_many_arguments)]
async fn check_pressure(
    db: &Db,
    holdings_dir: &Path,
    mailbox_router: &Arc<MailboxRouter>,
    holder_master_pub: IdentityPub,
    soft_quota_bytes: u64,
    hard_quota_bytes: u64,
    data_dir: &Path,
    disk_reserve_bytes: u64,
    time_scale: u64,
    master_signing_key: &ed25519_dalek::SigningKey,
    four_r: &FourRParams,
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

    // В-0: the 4R shadow — same snapshot, before the old path acts; logs only.
    if let Err(e) = shadow::shadow_pressure(
        db,
        &holdings,
        shadow::ShadowQuota {
            disk_free,
            soft: soft_quota_bytes,
            reserve: disk_reserve_bytes,
            hard: hard_quota_bytes,
        },
        holder_master_pub,
        &trust_fn,
        now,
        &result,
        four_r,
    ) {
        warn!(
            target: "viaticum::four_r",
            err = %e,
            "four_r: shadow tick failed — old path unaffected"
        );
    }

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

                // T-13a: publish immediate-drop DropNotice via mailbox (deadline=now).
                post_symbol_dropped_via_mailbox(
                    mailbox_router,
                    holder_master_pub,
                    target.owner_id,
                    target.source_block_id,
                    &esi_ranges,
                    time_scale,
                    master_signing_key,
                )
                .await;
            }

            // T-7: send DropNotice via mailbox, batched per owner.
            // Group notices by owner_id, then publish each group as one or more
            // SymbolDropNoticeBatchMsg entries (chunked to ≤ MAX_ENTRY_BYTES each).
            publish_drop_notices_via_mailbox(
                db,
                &result.drop_notices,
                mailbox_router,
                holder_master_pub,
                now,
                time_scale,
                master_signing_key,
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

/// T-7: Publish advance DropNotice entries via the mailbox bus, batched per owner.
///
/// Groups `DropNoticeTarget` list by `owner_id`. For each owner:
///   1. Builds `Vec<SymbolDropNoticeMsg>` signed with holder's master key.
///   2. Chunks into `SymbolDropNoticeBatchMsg` entries ≤ `MAX_ENTRY_BYTES` each.
///   3. Publishes each chunk via `mailbox_router.publish`.
///   4. W-4 (best-effort): if publish returns 0 acks, retries once; logs WARN on second 0.
///   5. Records `drop_notice_sent_at` on each holding (once, idempotent).
///
/// T-13a: immediate-drop path is now also via mailbox (`post_symbol_dropped_via_mailbox`);
/// this function only handles the advance-notice (buffer-zone) path.
async fn publish_drop_notices_via_mailbox(
    db: &Db,
    drop_notices: &[viaticum_core::budget::DropNoticeTarget],
    mailbox_router: &Arc<MailboxRouter>,
    holder_master_pub: IdentityPub,
    now: Timestamp,
    time_scale: u64,
    master_signing_key: &ed25519_dalek::SigningKey,
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

        // Sign each notice with the holder's master key.
        // Security: the owner verifies this signature before marking placements Lost.
        // An attacker with no private key cannot forge a valid signed DropNotice.
        let notice_msg = build_signed_symbol_drop_notice(
            notice.source_block_id,
            holding.esi_ranges.clone(),
            Timestamp(notice.deadline_secs),
            now,
            master_signing_key,
        );
        by_owner
            .entry(notice.owner_id)
            .or_default()
            .push(notice_msg);
    }

    let now_secs = now.0;
    let ttl_secs = viaticum_core::mailbox::scaled_ttl_secs(
        class_config::DROP_NOTICE_TTL.as_secs(),
        time_scale,
    );

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

/// T-13a: Publish an immediate-drop DropNotice via the mailbox bus.
///
/// Replaces the former `post_symbol_dropped` relay path. Uses the same
/// `SymbolDropNoticeBatchMsg` wire format as the advance-notice path (T-7),
/// but with `deadline = Timestamp::now()` to signal "already dropped".
///
/// The owner's `ProcessorDropHandler` checks deadline ≤ now + epsilon and
/// wakes the repair worker immediately, preserving the former SymbolDropped semantics.
///
/// Each notice is signed with the holder's `master_signing_key` so the owner
/// can verify authenticity before marking placements Lost.
async fn post_symbol_dropped_via_mailbox(
    mailbox_router: &Arc<MailboxRouter>,
    holder_master_pub: IdentityPub,
    owner_id: IdentityPub,
    source_block_id: viaticum_core::types::SourceBlockId,
    esi_ranges: &[(u32, u32)],
    time_scale: u64,
    master_signing_key: &ed25519_dalek::SigningKey,
) {
    let now = Timestamp::now();
    let now_secs = now.0;

    // Build a signed single-notice batch with deadline = now (immediate drop).
    // Security: owner verifies sig before marking placement Lost.
    let notice = build_signed_symbol_drop_notice(
        source_block_id,
        esi_ranges.to_vec(),
        now,
        now,
        master_signing_key,
    );
    let batch = viaticum_core::messages::SymbolDropNoticeBatchMsg {
        v: 1,
        notices: vec![notice],
    };
    let payload = match viaticum_core::messages::to_cbor(&batch) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                block_id = %source_block_id,
                owner = %owner_id,
                err = %e,
                "holder_cleanup: immediate-drop — failed to serialize DropNotice"
            );
            return;
        }
    };

    let ttl_secs = viaticum_core::mailbox::scaled_ttl_secs(
        class_config::DROP_NOTICE_TTL.as_secs(),
        time_scale,
    );
    let mut msg_id = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut msg_id);

    let entry = MailboxEntry {
        target: owner_id,
        msg_id,
        class: MailboxClass::DropNotice,
        payload_version: 1,
        payload,
        expires_at: now_secs + ttl_secs,
        stored_at: now_secs,
        sender: Some(holder_master_pub),
    };

    match mailbox_router.publish(&owner_id, entry).await {
        Ok(0) => {
            warn!(
                block_id = %source_block_id,
                owner = %owner_id,
                "holder_cleanup: immediate-drop DropNotice got 0 acks (best-effort, W-4)"
            );
        }
        Ok(n) => {
            info!(
                block_id = %source_block_id,
                owner = %owner_id,
                ack_count = n,
                "holder_cleanup: immediate-drop DropNotice published via mailbox"
            );
        }
        Err(e) => {
            warn!(
                block_id = %source_block_id,
                owner = %owner_id,
                err = %e,
                "holder_cleanup: immediate-drop DropNotice publish failed (best-effort)"
            );
        }
    }
}
