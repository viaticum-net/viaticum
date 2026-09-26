// Auto-dial of known peers (network-i2).
//
// libp2p does not dial saved peers on its own, so without this every restart
// (or DR) leaves the node isolated until someone runs `connect`. On start and
// then every `redial_interval`, each PeerRecord we are not authenticated with is
// dialed ONCE over all of its stored addresses.
//
// The PeerId is derived from the record's `device_id` (the device key IS the
// libp2p key), so a stored address does not need a `/p2p/` suffix. A stored
// address whose terminal `/p2p/` names another peer is skipped with a warning:
// it is not a route to this peer.

#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use libp2p::Multiaddr;
use tokio_util::sync::CancellationToken;
use viaticum_core::db::{Db, DbError};
use viaticum_core::types::DeviceId;

use crate::daemon::network::swarm::{
    SwarmError, SwarmHandle, device_id_to_peer_id, strip_peer_suffix,
};

/// Counters of one redial pass. Logged as INFO `auto-dial pass` whenever
/// `known_peers > 0`, so a pass that dials nobody is visible in the log.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RedialStats {
    /// PeerRecords considered (own device excluded).
    pub(crate) known_peers: usize,
    /// Peers skipped because they are already authenticated.
    pub(crate) already_connected: usize,
    /// Peers for which one dial (over all their addresses) was issued.
    pub(crate) dialed: usize,
    /// Peers with nothing to dial: no stored address, every stored address
    /// unusable, or a device id that is not a valid Ed25519 key.
    pub(crate) no_addrs: usize,
    /// Individual stored addresses dropped (unparseable, or a terminal `/p2p/`
    /// naming a different peer).
    pub(crate) skipped_addrs: usize,
}

/// Why a redial pass could not run.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RedialError {
    #[error("swarm unavailable: {0}")]
    Swarm(#[from] SwarmError),
    #[error("listing known peers failed: {0}")]
    Db(#[from] DbError),
}

/// Dial every known, currently unauthenticated peer once over all its stored
/// addresses. Returns the pass counters (also logged, see [`RedialStats`]).
pub(crate) async fn redial_known_peers(
    db: &Db,
    swarm: &SwarmHandle,
) -> Result<RedialStats, RedialError> {
    // peer_sets().0 = authenticated DeviceIds. Authentication implies a live
    // connection, so those are exactly the peers not worth re-dialing.
    let (authenticated, _) = swarm.peer_sets().await?;
    let peers = db.list_all_peers()?;

    let mut stats = RedialStats::default();
    for record in &peers {
        if record.device_id == swarm.device_id {
            continue;
        }
        stats.known_peers += 1;
        if authenticated.contains(&record.device_id) {
            stats.already_connected += 1;
            continue;
        }
        let Some((peer_id, addrs)) = dialable_addrs(&record.device_id, &record.addrs, &mut stats)
        else {
            stats.no_addrs += 1;
            continue;
        };
        swarm.dial_addrs(peer_id, addrs).await?;
        stats.dialed += 1;
    }

    if stats.known_peers > 0 {
        tracing::info!(
            dialed = stats.dialed,
            already_connected = stats.already_connected,
            no_addrs = stats.no_addrs,
            known_peers = stats.known_peers,
            skipped_addrs = stats.skipped_addrs,
            "auto-dial pass"
        );
    }
    Ok(stats)
}

/// PeerId of `device` and the transport addresses to dial it on (terminal
/// `/p2p/` stripped, deduplicated). `None` when there is nothing to dial.
fn dialable_addrs(
    device: &DeviceId,
    stored: &[String],
    stats: &mut RedialStats,
) -> Option<(libp2p::PeerId, Vec<Multiaddr>)> {
    let peer_id = match device_id_to_peer_id(device) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(%device, err = %e, "auto-dial: device id is not a valid key, skipping peer");
            return None;
        }
    };
    let mut seen: HashSet<Multiaddr> = HashSet::new();
    let mut addrs: Vec<Multiaddr> = Vec::new();
    for addr_str in stored {
        let addr = match Multiaddr::from_str(addr_str) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(%device, addr = %addr_str, err = %e,
                    "auto-dial: unparseable stored address, skipping");
                stats.skipped_addrs += 1;
                continue;
            }
        };
        match strip_peer_suffix(&addr, peer_id) {
            Ok(transport) => {
                if seen.insert(transport.clone()) {
                    addrs.push(transport);
                }
            }
            Err(found) => {
                tracing::warn!(%device, expected = %peer_id, found = %found, addr = %addr_str,
                    "auto-dial: stored address names another peer, skipping");
                stats.skipped_addrs += 1;
            }
        }
    }
    if addrs.is_empty() {
        None
    } else {
        Some((peer_id, addrs))
    }
}

/// The daemon task: one pass at start, then one every `interval` until
/// `cancel` fires.
pub(crate) async fn run_redial_loop(
    db: Db,
    swarm: std::sync::Arc<SwarmHandle>,
    interval: Duration,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        // The first tick completes immediately: that is the start-up pass that
        // makes a restart re-establish links.
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                if let Err(e) = redial_known_peers(&db, &swarm).await {
                    tracing::warn!(err = %e, "auto-dial pass failed (will retry next tick)");
                }
            }
        }
    }
}
