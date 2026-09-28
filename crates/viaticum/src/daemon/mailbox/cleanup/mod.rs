// T-11: Mailbox self-cleanup — membership-based eviction and TTL sweep.
//
// Two periodic tasks for maintaining the local mailbox store:
//
// 1. `run_mailbox_ttl_sweep` — remove TTL-expired entries of ALL classes every
//    MAILBOX_SWEEP_INTERVAL_SECS. Together with the monotone per-address pointer
//    budget at store time (CROWN-1 Q5/N5, `MailboxEngine::store`) this is how
//    high-trust (SelfPointer) entries leave.
//
// 2. `run_mailbox_self_cleanup` — for each target stored in our mailbox, check
//    whether we are still in the candidate set for that target. If NOT, delete all
//    non-high-trust entries for that target. High-trust (SelfPointer) entries are
//    exempt from membership-based eviction (AC-6 / Bug-D): they are removed only
//    by the TTL sweep above or by the pointer budget.
//
// Routing view sourcing: `run_mailbox_self_cleanup` builds a `KademliaRoutingView`
// per sweep from `db.list_all_peers()` + the node's own peer_id (both available
// without a live swarm). This avoids requiring an `Arc<RwLock<KademliaRoutingView>>`
// and keeps the cleanup task swarm-independent.

use std::time::SystemTime;

use libp2p::PeerId;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use viaticum_core::constants::{MAILBOX_CANDIDATES_N, MAILBOX_SWEEP_INTERVAL_SECS};
use viaticum_core::db::Db;

use crate::daemon::mailbox::candidate::{KademliaRoutingView, should_store};
use crate::daemon::network::swarm::device_id_to_peer_id;

// ──────────────────────────────────────────────────────────────────────────────
// Sweep cadence
// ──────────────────────────────────────────────────────────────────────────────

/// Mailbox housekeeping sweep cadence in seconds, scaled by `time_scale`.
///
/// Mirrors the scheduler and the mailbox poll loop (`poll::poll_interval_secs`),
/// which divide every cadence by `time_scale`. Under time acceleration the producers
/// scale their entry TTLs (`scaled_ttl_secs`) so entries expire in accelerated time;
/// if the sweep kept ticking at a fixed wall-clock 6 hours while TTLs shrank to
/// seconds, expired entries would pile up and the membership-cleanup would lag the
/// candidate-set churn — the whole housekeeping path would be untestable under
/// acceleration. Production (`time_scale = 1`) keeps the full
/// `MAILBOX_SWEEP_INTERVAL_SECS` cadence. Floored at 1s so `tokio::time::interval`
/// never gets a 0s period (which panics); `time_scale = 0` is treated as 1.
pub(crate) fn sweep_interval_secs(time_scale: u64) -> u64 {
    (MAILBOX_SWEEP_INTERVAL_SECS / time_scale.max(1)).max(1)
}

// ──────────────────────────────────────────────────────────────────────────────
// TTL sweep task
// ──────────────────────────────────────────────────────────────────────────────

/// Run the periodic mailbox TTL sweep.
///
/// Removes all entries whose `expires_at < now_secs`, including high-trust
/// SelfPointer entries. SelfPointers leave only by this TTL sweep or by the
/// monotone per-address pointer budget at store time (CROWN-1 Q5/N5,
/// `MailboxEngine::store`); never by membership cleanup.
///
/// Interval: `sweep_interval_secs(time_scale)` — MAILBOX_SWEEP_INTERVAL_SECS
/// (6 hours) in production, divided by `time_scale` under acceleration. First sweep
/// fires immediately on startup to collect any entries that expired while the daemon
/// was offline.
pub async fn run_mailbox_ttl_sweep(db: Db, time_scale: u64, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(sweep_interval_secs(
        time_scale,
    )));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("mailbox_ttl_sweep: cancelled, shutting down");
                break;
            }
            _ = interval.tick() => {
                let now_secs = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                match db.mailbox_sweep_expired(now_secs) {
                    Ok(0) => {
                        debug!("mailbox_ttl_sweep: no expired entries");
                    }
                    Ok(n) => {
                        info!(removed = n, "mailbox_ttl_sweep: removed expired entries");
                    }
                    Err(e) => {
                        warn!(err = %e, "mailbox_ttl_sweep: sweep_expired failed");
                    }
                }
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Membership-based self-cleanup task
// ──────────────────────────────────────────────────────────────────────────────

/// Run the periodic mailbox membership-check cleanup.
///
/// Per sweep interval:
/// 1. Build a `KademliaRoutingView` from current `db.list_all_peers()` + `my_peer_id`.
/// 2. For each target stored in the mailbox, check `should_store(...)`.
/// 3. If we are NO LONGER in the candidate set for a target, delete all NON-high-trust
///    entries for that target.
/// 4. High-trust (SelfPointer) entries are EXEMPT from the membership check — they
///    are only removed by TTL expiry via `run_mailbox_ttl_sweep` (Bug-D / AC-6).
///
/// Routing view sourcing: built on-demand per sweep from the DB, no live swarm needed.
/// `my_peer_id` is derived from the device signing key (stable, precomputed by caller).
///
/// Interval: `sweep_interval_secs(time_scale)` (same as TTL sweep — one housekeeping
/// cadence, scaled by `time_scale`).
pub async fn run_mailbox_self_cleanup(
    db: Db,
    my_peer_id: PeerId,
    time_scale: u64,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(sweep_interval_secs(
        time_scale,
    )));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("mailbox_self_cleanup: cancelled, shutting down");
                break;
            }
            _ = interval.tick() => {
                sweep_membership_once(&db, &my_peer_id);
            }
        }
    }
}

/// Execute one membership-cleanup sweep (extracted for testability).
pub(crate) fn sweep_membership_once(db: &Db, my_peer_id: &PeerId) {
    // Build routing view from all DB-known peers + ourselves.
    let known_peer_ids = build_routing_view_from_db(db, my_peer_id);
    let routing_view = KademliaRoutingView::new(known_peer_ids);

    // Enumerate all targets with at least one stored entry.
    let targets = match db.mailbox_list_all_targets() {
        Ok(t) => t,
        Err(e) => {
            warn!(err = %e, "mailbox_self_cleanup: failed to list targets");
            return;
        }
    };

    if targets.is_empty() {
        debug!("mailbox_self_cleanup: no targets stored");
        return;
    }

    let mut total_deleted = 0u64;

    for target in &targets {
        // Check membership: are we still in the top-MAILBOX_CANDIDATES_N for this target?
        if should_store(&routing_view, target, my_peer_id, MAILBOX_CANDIDATES_N) {
            // Still in candidate set — keep all entries (both HT and non-HT).
            continue;
        }

        // No longer in candidate set. Delete all non-high-trust entries for this target.
        // High-trust (SelfPointer) entries are exempt — AC-6 / Bug-D.
        let non_ht = match db.mailbox_list_non_high_trust_for_target(target) {
            Ok(entries) => entries,
            Err(e) => {
                warn!(
                    target = %target,
                    err = %e,
                    "mailbox_self_cleanup: failed to list non-HT entries"
                );
                continue;
            }
        };

        for entry in non_ht {
            match db.mailbox_delete(target, entry.msg_id, entry.class) {
                Ok(()) => {
                    total_deleted += 1;
                    debug!(
                        target = %target,
                        class = ?entry.class,
                        msg_id = ?entry.msg_id,
                        "mailbox_self_cleanup: deleted non-HT entry (no longer in candidate set)"
                    );
                }
                Err(e) => {
                    warn!(
                        target = %target,
                        class = ?entry.class,
                        err = %e,
                        "mailbox_self_cleanup: delete failed"
                    );
                }
            }
        }
    }

    if total_deleted > 0 {
        info!(
            deleted = total_deleted,
            "mailbox_self_cleanup: removed non-HT entries for targets no longer in candidate set"
        );
    } else {
        debug!("mailbox_self_cleanup: no membership evictions needed");
    }
}

/// Build a list of known PeerIds from the DB (all peers) plus our own PeerId.
///
/// Converting DeviceId → PeerId via `device_id_to_peer_id` (deterministic from
/// Ed25519 pubkey). Peers that fail conversion are silently skipped.
fn build_routing_view_from_db(db: &Db, my_peer_id: &PeerId) -> Vec<PeerId> {
    let peer_records = match db.list_all_peers() {
        Ok(p) => p,
        Err(e) => {
            warn!(err = %e, "mailbox_self_cleanup: failed to list peers from DB");
            return vec![*my_peer_id];
        }
    };

    let mut known: Vec<PeerId> = peer_records
        .into_iter()
        .filter_map(|record| device_id_to_peer_id(&record.device_id).ok())
        .collect();

    // Include our own peer_id so should_store sees the full picture.
    if !known.contains(my_peer_id) {
        known.push(*my_peer_id);
    }

    known
}

#[cfg(test)]
mod tests;
