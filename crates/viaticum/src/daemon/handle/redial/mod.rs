// Auto-dial of known peers (network-i2, under the connection cache: network-i43).
//
// libp2p does not dial saved peers on its own, so without this every restart
// (or DR) leaves the node isolated until someone runs `connect`. On start and
// then every `redial_interval`, known peers we are not authenticated with are
// dialed ONCE each over all of their stored addresses — but only up to a floor
// (C-DK Р-13): the node does not spend connections on keeping a number of them.
//   - infrastructure (a friend's ≤ 2 bootstrap peers) is dialed every pass;
//   - the others only while fewer than floor = min(16, cap / 2) peers are
//     authenticated, at most floor − authenticated per pass, freshest
//     `last_seen` first; when there are more candidates than places, a peer
//     dialed in one of the two previous passes is skipped (rotation);
//   - a seed (relay_role = punch) and a swarm without a cache (ConnPolicy::off)
//     have no floor: every known peer each pass, as before C4.
// Below the floor the cache never evicts (it keeps ≥ cap ≥ 2 × floor), so redial
// never dials back a peer the cache just closed.
//
// The PeerId is derived from the record's `device_id` (the device key IS the
// libp2p key), so a stored address does not need a `/p2p/` suffix. A stored
// address whose terminal `/p2p/` names another peer is skipped with a warning:
// it is not a route to this peer.

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use tokio_util::sync::CancellationToken;
use viaticum_core::constants::REDIAL_FLOOR;
use viaticum_core::db::{Db, DbError};
use viaticum_core::types::{DeviceId, PeerRecord, Timestamp};

use crate::daemon::network::address_book::dialable_addrs;
use crate::daemon::network::conn_lru::DialOrigin;
use crate::daemon::network::swarm::{ConnStats, SwarmError, SwarmHandle};

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
    /// The floor of this pass; None = no floor (seed, no cache).
    pub(crate) floor: Option<usize>,
    /// Candidates not dialed because authenticated ≥ floor (or no place left).
    pub(crate) skipped_floor: usize,
    /// Candidates not dialed because dialed in one of the two previous passes.
    pub(crate) skipped_rotation: usize,
}

/// Why a redial pass could not run.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RedialError {
    #[error("swarm unavailable: {0}")]
    Swarm(#[from] SwarmError),
    #[error("listing known peers failed: {0}")]
    Db(#[from] DbError),
}

/// What the redial loop remembers between passes: the rotation (C-DK Р-13).
#[derive(Debug, Default)]
pub(crate) struct RedialState {
    pass: u64,
    /// Device → the pass it was last dialed in.
    tried: HashMap<DeviceId, u64>,
}

/// One known, unauthenticated peer with something to dial.
#[derive(Debug, Clone)]
pub(crate) struct Candidate {
    pub(crate) device: DeviceId,
    pub(crate) peer: PeerId,
    pub(crate) addrs: Vec<Multiaddr>,
    pub(crate) last_seen: Timestamp,
    /// Infrastructure: dialed every pass whatever the floor.
    pub(crate) infra: bool,
}

/// The floor of the cache's policy: None for a seed and without a cache.
pub(crate) fn redial_floor(stats: &ConnStats) -> Option<usize> {
    if stats.seed_role {
        return None;
    }
    stats.cap.map(|c| REDIAL_FLOOR.min(c as usize / 2))
}

/// Which candidates this pass dials (pure, C-DK Р-13): infrastructure always;
/// the rest up to `floor − authenticated`, freshest first, rotating only when
/// there are more candidates than places. Advances `state` and fills the
/// floor counters of `stats`.
pub(crate) fn plan_redial(
    mut candidates: Vec<Candidate>,
    authenticated: usize,
    floor: Option<usize>,
    state: &mut RedialState,
    stats: &mut RedialStats,
) -> Vec<Candidate> {
    state.pass += 1;
    let pass = state.pass;
    stats.floor = floor;
    let (mut out, mut others): (Vec<Candidate>, Vec<Candidate>) =
        candidates.drain(..).partition(|c| c.infra);
    match floor {
        None => out.append(&mut others),
        Some(floor) => {
            let places = floor.saturating_sub(authenticated);
            others.sort_by(|a, b| {
                b.last_seen
                    .0
                    .cmp(&a.last_seen.0)
                    .then_with(|| a.device.0.cmp(&b.device.0))
            });
            if others.len() > places {
                let (recent, fresh): (Vec<Candidate>, Vec<Candidate>) =
                    others.into_iter().partition(|c| {
                        state
                            .tried
                            .get(&c.device)
                            .is_some_and(|p| pass.saturating_sub(*p) <= 2)
                    });
                stats.skipped_rotation += recent.len();
                others = fresh;
            }
            let take = places.min(others.len());
            stats.skipped_floor += others.len() - take;
            out.extend(others.into_iter().take(take));
        }
    }
    for c in &out {
        state.tried.insert(c.device, pass);
    }
    out
}

/// One pass: dial the known, currently unauthenticated peers the plan picks,
/// once each over all their stored addresses. Returns the pass counters (also
/// logged, see [`RedialStats`]).
pub(crate) async fn redial_known_peers(
    db: &Db,
    swarm: &SwarmHandle,
    state: &mut RedialState,
) -> Result<RedialStats, RedialError> {
    let conn = swarm.conn_stats().await?;
    // peer_sets().0 = authenticated DeviceIds. Authentication implies a live
    // connection, so those are exactly the peers not worth re-dialing.
    let (authenticated, _) = swarm.peer_sets().await?;
    let peers = db.list_all_peers()?;
    let infra: HashSet<PeerId> = conn.infra_peers.iter().copied().collect();
    let floor = redial_floor(&conn);

    let mut stats = RedialStats::default();
    let mut candidates = Vec::new();
    for record in &peers {
        if record.device_id == swarm.device_id {
            continue;
        }
        stats.known_peers += 1;
        if let Some(c) = candidate(record, &authenticated, &infra, &mut stats) {
            candidates.push(c);
        }
    }
    let plan = plan_redial(candidates, authenticated.len(), floor, state, &mut stats);
    for c in plan {
        tracing::info!(device = %c.device, peer_id = %c.peer, infra = c.infra, "auto-dial: dialing peer");
        swarm
            .dial_addrs_from(c.peer, c.addrs, DialOrigin::Redial)
            .await?;
        stats.dialed += 1;
    }

    if stats.known_peers > 0 {
        let floor_txt = floor.map_or_else(|| "none".to_string(), |f| f.to_string());
        tracing::info!(
            dialed = stats.dialed,
            already_connected = stats.already_connected,
            no_addrs = stats.no_addrs,
            known_peers = stats.known_peers,
            skipped_addrs = stats.skipped_addrs,
            floor = %floor_txt,
            below_floor = floor.is_none_or(|f| authenticated.len() < f),
            skipped_floor = stats.skipped_floor,
            skipped_rotation = stats.skipped_rotation,
            "auto-dial pass"
        );
    }
    Ok(stats)
}

/// The candidate of one record, or why not (counted in `stats`).
fn candidate(
    record: &PeerRecord,
    authenticated: &HashSet<DeviceId>,
    infra: &HashSet<PeerId>,
    stats: &mut RedialStats,
) -> Option<Candidate> {
    if authenticated.contains(&record.device_id) {
        stats.already_connected += 1;
        return None;
    }
    let Some((peer, addrs)) =
        dialable_addrs(&record.device_id, &record.addrs, &mut stats.skipped_addrs)
    else {
        stats.no_addrs += 1;
        return None;
    };
    Some(Candidate {
        device: record.device_id,
        peer,
        addrs,
        last_seen: record.last_seen,
        infra: infra.contains(&peer),
    })
}

/// The same pass limited to `devices` (restore-i26: the holders of a block before
/// a retry) — a dial by need, without floor. A device without a PeerRecord has
/// nothing to dial (`no_addrs`); each device is dialed at most once per call.
pub(crate) async fn redial_devices(
    db: &Db,
    swarm: &SwarmHandle,
    devices: &[DeviceId],
) -> Result<RedialStats, RedialError> {
    let (authenticated, _) = swarm.peer_sets().await?;
    let mut stats = RedialStats::default();
    let mut seen: HashSet<DeviceId> = HashSet::new();
    let no_infra = HashSet::new();
    for device in devices {
        if *device == swarm.device_id || !seen.insert(*device) {
            continue;
        }
        stats.known_peers += 1;
        let Some(record) = db.get_peer(device)? else {
            stats.no_addrs += 1;
            continue;
        };
        if let Some(c) = candidate(&record, &authenticated, &no_infra, &mut stats) {
            swarm
                .dial_addrs_from(c.peer, c.addrs, DialOrigin::Restore)
                .await?;
            stats.dialed += 1;
        }
    }
    Ok(stats)
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
    let mut state = RedialState::default();
    loop {
        // The first tick completes immediately: that is the start-up pass that
        // makes a restart re-establish links.
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                if let Err(e) = redial_known_peers(&db, &swarm, &mut state).await {
                    tracing::warn!(err = %e, "auto-dial pass failed (will retry next tick)");
                }
            }
        }
    }
}
