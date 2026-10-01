//! DR network helpers: Kademlia stabilization, candidate dialing, dialing the holders
//! of the pointer's SystemState blocks, and fetching those blocks.
//!
//! Every peer that authenticates while DR waits is upserted into the staging DB (so
//! the mailbox walk has candidates and the recovered DB keeps the addresses DR reached
//! it on, dr-i18).
//!
//! Holders are dialed ONCE each over all their hint addresses (libp2p tries several in
//! parallel; a second `dial` to the same peer while the first is pending would be
//! dropped as "already dialing"), all holders at once, with one shared deadline. Only
//! those that did not authenticate go to the slower Kademlia lookup.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use tokio::sync::mpsc::Receiver;
use viaticum_core::constants::{AVAIL_EWMA_ALPHA, AVAIL_EWMA_INITIAL, INITIAL_TRUST_P};
use viaticum_core::db::Db;
use viaticum_core::system_state::{BlockRef, SelfPointer};
use viaticum_core::types::{DeviceId, IdentityPub, PeerRecord, Timestamp, ewma_contact_observed};

use crate::daemon::network::swarm::{ProtocolEvent, SwarmHandle, device_id_to_peer_id};

#[cfg(test)]
mod tests;

/// Per-connection timeout for dial + DeviceCertExchange; also the shared deadline for
/// dialing all SS-block holders at once.
pub(super) const AUTH_TIMEOUT_SECS: u64 = 15;

/// Minimum authenticated peers before the DR walk proceeds.
///
/// 1 peer is the minimum: a single authenticated peer gives us a DB entry and a live
/// channel to send MailboxFetchRequest. With a larger minimum a 5-node circle (4 other
/// peers) always waits the full DR_KAD_STABILIZE_TIMEOUT_SECS.
pub(super) const KAD_MIN_PEERS_FOR_DR: usize = 1;

/// Shared deadline when dialing the candidates returned by `get_closest_peers`.
const CANDIDATE_DIAL_TIMEOUT_SECS: u64 = 10;

// ─── Peer records learned live ────────────────────────────────────────────────

/// The record of a peer that just authenticated: the existing record refreshed, or a
/// new one. `listen_addrs` (normalized, with `/p2p/`) replace the stored addresses when
/// non-empty — the same rule the daemon applies (`processor/peer.rs`).
pub(super) fn live_peer_record(
    db: &Db,
    device_id: DeviceId,
    identity_pub: IdentityPub,
    x25519_pub: Option<[u8; 32]>,
    listen_addrs: &[Multiaddr],
) -> PeerRecord {
    let now = Timestamp::now();
    let mut record = match db.get_peer(&device_id) {
        Ok(Some(mut existing)) => {
            existing.master_identity = identity_pub;
            existing.last_seen = now;
            if x25519_pub.is_some() {
                existing.x25519_pub = x25519_pub;
            }
            existing.avail_ewma = ewma_contact_observed(existing.avail_ewma, AVAIL_EWMA_ALPHA);
            existing.last_avail_sample = now.0;
            existing
        }
        _ => PeerRecord {
            device_id,
            master_identity: identity_pub,
            trust_p: INITIAL_TRUST_P,
            trust_i: 0.0,
            trust_s: 1.0,
            bytes_we_store_for_peer: 0,
            bytes_peer_stores_for_us: 0,
            first_seen: now,
            last_seen: now,
            revoked_device_pub_keys: vec![],
            addrs: vec![],
            x25519_pub,
            avail_ewma: AVAIL_EWMA_INITIAL,
            last_avail_sample: now.0,
        },
    };
    if !listen_addrs.is_empty() {
        record.addrs = listen_addrs.iter().map(|a| a.to_string()).collect();
    }
    record
}

/// Upsert the record of an authenticated peer; `true` on success.
fn upsert_authenticated(
    db: &Db,
    device_id: DeviceId,
    identity_pub: IdentityPub,
    x25519_pub: Option<[u8; 32]>,
    listen_addrs: &[Multiaddr],
) -> bool {
    let record = live_peer_record(db, device_id, identity_pub, x25519_pub, listen_addrs);
    match db.upsert_peer(&record) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(device = %device_id, "dr: upsert_peer failed: {e}");
            false
        }
    }
}

/// Persist identify addresses on an already-upserted record.
fn persist_identified_addrs(db: &Db, device_id: DeviceId, listen_addrs: &[Multiaddr]) {
    if listen_addrs.is_empty() {
        return;
    }
    if let Ok(Some(mut record)) = db.get_peer(&device_id) {
        record.addrs = listen_addrs.iter().map(|a| a.to_string()).collect();
        let _ = db.upsert_peer(&record);
    }
}

// ─── Kademlia bootstrap stabilization ────────────────────────────────────────

/// Wait for Kademlia bootstrap to produce authenticated peers, upserting each one into
/// `db` so that the mailbox walk has a populated candidate set.
///
/// Returns as soon as `min_peers` have been authenticated OR `timeout_secs` elapsed
/// (best-effort: returns whatever was reached).
pub(super) async fn wait_for_kad_bootstrap_stable(
    event_rx: &mut Receiver<ProtocolEvent>,
    db: &Db,
    timeout_secs: u64,
    min_peers: usize,
) -> usize {
    let mut count = 0usize;
    let _ = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        loop {
            match event_rx.recv().await {
                Some(ProtocolEvent::PeerAuthenticated {
                    peer_id: _,
                    device_id,
                    identity_pub,
                    device_cert: _,
                    x25519_pub,
                    listen_addrs,
                }) => {
                    if upsert_authenticated(db, device_id, identity_pub, x25519_pub, &listen_addrs)
                    {
                        count += 1;
                        tracing::info!(
                            device = %device_id,
                            master = %identity_pub,
                            count,
                            "dr: bootstrap: peer authenticated and upserted"
                        );
                    }
                    if count >= min_peers {
                        tracing::info!(
                            count,
                            "dr: bootstrap: min_peers reached, stopping stabilization wait"
                        );
                        return;
                    }
                }
                Some(ProtocolEvent::PeerIdentified {
                    device_id,
                    listen_addrs,
                }) => persist_identified_addrs(db, device_id, &listen_addrs),
                Some(_) => {}
                None => return,
            }
        }
    })
    .await;
    count
}

// ─── Waiting for a set of peers ───────────────────────────────────────────────

/// Collect `PeerAuthenticated` events until every peer of `expected` arrived or
/// `deadline` passed. Every peer that authenticates meanwhile is upserted into `db`
/// (not only the expected ones: a peer that arrives now must not be lost). Returns the
/// expected peers that arrived.
pub(super) async fn wait_for_auth_set(
    event_rx: &mut Receiver<ProtocolEvent>,
    db: &Db,
    expected: HashSet<PeerId>,
    deadline: Duration,
) -> HashSet<PeerId> {
    let mut arrived: HashSet<PeerId> = HashSet::new();
    if expected.is_empty() {
        return arrived;
    }
    let _ = tokio::time::timeout(deadline, async {
        loop {
            match event_rx.recv().await {
                Some(ProtocolEvent::PeerAuthenticated {
                    peer_id,
                    device_id,
                    identity_pub,
                    device_cert: _,
                    x25519_pub,
                    listen_addrs,
                }) => {
                    upsert_authenticated(db, device_id, identity_pub, x25519_pub, &listen_addrs);
                    if expected.contains(&peer_id) {
                        arrived.insert(peer_id);
                        if arrived.len() == expected.len() {
                            return;
                        }
                    }
                }
                Some(ProtocolEvent::PeerIdentified {
                    device_id,
                    listen_addrs,
                }) => persist_identified_addrs(db, device_id, &listen_addrs),
                Some(_) => {}
                None => return,
            }
        }
    })
    .await;
    arrived
}

// ─── Candidate peer dial (post-Kademlia walk) ─────────────────────────────────

/// Dial the peers returned by `get_closest_peers` (one dial per peer over all its
/// addresses, all at once) and wait for them with one shared deadline, upserting each
/// into the DB so the mailbox walk has them as candidates. Best-effort.
///
/// A candidate that is already authenticated is not dialed, and it is NOT necessarily
/// in the DB yet: the stabilization wait stops at `KAD_MIN_PEERS_FOR_DR`, so the peers
/// that authenticated after it have their `PeerAuthenticated` still queued. They are
/// upserted from the queue at the end ([`upsert_queued_peers`]); without that the walk
/// asks only the seed peer and a seed that swapped the pointer's place ends DR with
/// "no catalog" while other postmen hold the real pointer (dr-i1, CROWN-1 S1 step 7).
/// Call it with an empty `closest` when the lookup failed: the queue is drained the same.
pub(super) async fn dial_and_authenticate_candidates(
    swarm: &SwarmHandle,
    event_rx: &mut Receiver<ProtocolEvent>,
    db: &Db,
    closest: Vec<(PeerId, Vec<Multiaddr>)>,
) {
    let already_auth: HashSet<PeerId> = swarm
        .peer_sets()
        .await
        .map(|(auth, _)| auth)
        .unwrap_or_default()
        .iter()
        .filter_map(|dev| device_id_to_peer_id(dev).ok())
        .collect();

    let mut expected: HashSet<PeerId> = HashSet::new();
    for (peer_id, addrs) in closest {
        if already_auth.contains(&peer_id) || addrs.is_empty() {
            continue;
        }
        match swarm.dial_addrs(peer_id, addrs).await {
            Ok(()) => {
                expected.insert(peer_id);
            }
            Err(e) => tracing::debug!(%peer_id, "dr: candidate dial failed: {e}"),
        }
    }
    let wanted = expected.len();
    let arrived = wait_for_auth_set(
        event_rx,
        db,
        expected,
        Duration::from_secs(CANDIDATE_DIAL_TIMEOUT_SECS),
    )
    .await;
    let queued = upsert_queued_peers(event_rx, db);
    tracing::info!(
        dialed = wanted,
        authenticated = arrived.len(),
        already_authenticated_upserted = queued,
        "dr: candidate peers dialed"
    );
}

/// Upsert every peer whose `PeerAuthenticated` is already queued, without waiting
/// (`PeerIdentified` addresses are persisted too; other events are dropped, as in the
/// waits above). The swarm queues the event in the same step that marks the peer
/// authenticated, so every peer `peer_sets` reported before this call is in the queue.
/// Returns how many peers were upserted.
pub(super) fn upsert_queued_peers(event_rx: &mut Receiver<ProtocolEvent>, db: &Db) -> usize {
    let mut upserted = 0usize;
    while let Ok(event) = event_rx.try_recv() {
        match event {
            ProtocolEvent::PeerAuthenticated {
                peer_id: _,
                device_id,
                identity_pub,
                device_cert: _,
                x25519_pub,
                listen_addrs,
            } => {
                upserted += usize::from(upsert_authenticated(
                    db,
                    device_id,
                    identity_pub,
                    x25519_pub,
                    &listen_addrs,
                ));
            }
            ProtocolEvent::PeerIdentified {
                device_id,
                listen_addrs,
            } => persist_identified_addrs(db, device_id, &listen_addrs),
            _ => {}
        }
    }
    upserted
}

// ─── Pointer holder dialing ───────────────────────────────────────────────────

/// Rank of an address for dialing: public first, then private (RFC 1918, CGNAT,
/// link-local, IPv6 ULA), then loopback / unspecified. Non-IP (DNS) counts as public.
pub(crate) fn addr_rank(addr: &Multiaddr) -> u8 {
    let ip: Option<IpAddr> = addr.iter().find_map(|p| match p {
        Protocol::Ip4(a) => Some(IpAddr::V4(a)),
        Protocol::Ip6(a) => Some(IpAddr::V6(a)),
        _ => None,
    });
    match ip {
        None => 0,
        Some(ip) if ip.is_loopback() || ip.is_unspecified() => 2,
        Some(IpAddr::V4(a)) => {
            let o = a.octets();
            let cgnat = o[0] == 100 && (o[1] & 0xC0) == 64;
            if a.is_private() || a.is_link_local() || cgnat {
                1
            } else {
                0
            }
        }
        Some(IpAddr::V6(a)) => {
            let first = a.segments()[0];
            let ula = (first & 0xfe00) == 0xfc00;
            let link_local = (first & 0xffc0) == 0xfe80;
            if ula || link_local { 1 } else { 0 }
        }
    }
}

/// Parse hint strings; keep only those with a terminal `/p2p/<peer id>` (a hint without
/// it does not say whose address it is); order public → private → loopback, keeping
/// the input order inside a rank.
pub(super) fn order_hint_addrs(hints: &[String]) -> Vec<(PeerId, Multiaddr)> {
    let mut out: Vec<(u8, PeerId, Multiaddr)> = Vec::new();
    for h in hints {
        let Ok(addr) = h.parse::<Multiaddr>() else {
            tracing::debug!(hint = %h, "dr: skip unparsable holder address");
            continue;
        };
        let Some(Protocol::P2p(peer_id)) = addr.iter().last() else {
            tracing::debug!(hint = %h, "dr: skip holder address without /p2p/");
            continue;
        };
        out.push((addr_rank(&addr), peer_id, addr));
    }
    out.sort_by_key(|(rank, _, _)| *rank);
    out.into_iter().map(|(_, p, a)| (p, a)).collect()
}

/// Dial the holders named in the selected pointer so we can fetch their symbols.
///
///   1. every not-yet-authenticated holder with hint addresses gets ONE dial over all
///      of them (ordered by `order_hint_addrs`); all holders are dialed before waiting;
///   2. one shared wait (`AUTH_TIMEOUT_SECS`) for the whole set;
///   3. holders that did not authenticate (or had no usable hint) go to the Kademlia
///      lookup of their own peer id.
///
/// Best-effort: an unreachable holder means fewer symbols for that block (the erasure
/// code tolerates this up to k_eff).
pub(super) async fn dial_pointer_holders(
    swarm: &Arc<SwarmHandle>,
    event_rx: &mut Receiver<ProtocolEvent>,
    db: &Db,
    pointer: &SelfPointer,
) {
    let already_auth = swarm
        .peer_sets()
        .await
        .map(|(auth, _)| auth)
        .unwrap_or_default();

    // Unique holders across base + diffs, not yet authenticated.
    let mut seen: HashSet<DeviceId> = HashSet::new();
    let mut targets: Vec<(DeviceId, Vec<String>)> = Vec::new();
    for bref in std::iter::once(&pointer.base).chain(pointer.diffs.iter()) {
        for h in &bref.holders {
            if already_auth.contains(&h.holder_id) || !seen.insert(h.holder_id) {
                continue;
            }
            targets.push((h.holder_id, h.addrs.clone()));
        }
    }

    // 1. One dial per holder over all its hint addresses, all holders at once.
    let mut expected: HashSet<PeerId> = HashSet::new();
    let mut fallback: Vec<DeviceId> = Vec::new();
    for (device, hints) in &targets {
        let peer_id = match device_id_to_peer_id(device) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(%device, "dr: cannot derive PeerId of holder: {e}");
                continue;
            }
        };
        let addrs: Vec<Multiaddr> = order_hint_addrs(hints)
            .into_iter()
            .filter(|(pid, _)| *pid == peer_id)
            .map(|(_, a)| a)
            .collect();
        if addrs.is_empty() {
            tracing::info!(
                %device,
                "dr: holder has no usable addr hints (normal — will use Kademlia fallback)"
            );
            fallback.push(*device);
            continue;
        }
        match swarm.dial_addrs(peer_id, addrs).await {
            Ok(()) => {
                expected.insert(peer_id);
            }
            Err(e) => {
                tracing::info!(%device, "dr: dial of holder failed: {e}");
                fallback.push(*device);
            }
        }
    }

    // 2. One shared deadline for the whole set.
    let arrived = wait_for_auth_set(
        event_rx,
        db,
        expected.clone(),
        Duration::from_secs(AUTH_TIMEOUT_SECS),
    )
    .await;
    for (device, _) in &targets {
        let Ok(peer_id) = device_id_to_peer_id(device) else {
            continue;
        };
        if arrived.contains(&peer_id) {
            tracing::info!(did = %device, "dr: authenticated pointer holder (via hints)");
        } else if expected.contains(&peer_id) {
            tracing::info!(%device, "dr: could not reach pointer holder via hints");
            fallback.push(*device);
        }
    }

    // 3. Kademlia fallback for the rest.
    for device in fallback {
        tracing::info!(
            %device,
            "dr: holder addrs empty or all failed — trying Kademlia get_closest_peers fallback"
        );
        try_dial_holder_via_kademlia(swarm, event_rx, db, device).await;
    }
}

/// Dial a holder by looking up its current addresses via Kademlia
/// (`get_closest_peers(peer_id)`), which finds nodes whose addresses changed since the
/// pointer was built.
async fn try_dial_holder_via_kademlia(
    swarm: &Arc<SwarmHandle>,
    event_rx: &mut Receiver<ProtocolEvent>,
    db: &Db,
    device: DeviceId,
) {
    let peer_id = match device_id_to_peer_id(&device) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(%device, "dr: cannot derive PeerId for Kademlia holder lookup: {e}");
            return;
        }
    };
    let closest = match swarm.get_closest_peers(peer_id.to_bytes()).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%device, "dr: Kademlia holder lookup failed: {e}");
            return;
        }
    };
    let holder_addrs: Vec<Multiaddr> = closest
        .iter()
        .filter(|(pid, _)| *pid == peer_id)
        .flat_map(|(_, addrs)| addrs.iter().cloned())
        .collect();
    if holder_addrs.is_empty() {
        tracing::debug!(
            %device,
            %peer_id,
            "dr: Kademlia did not return holder's own peer_id in closest set"
        );
        // Still dial the returned peers — one may route to the holder.
        for (cpid, caddrs) in closest {
            if !caddrs.is_empty() {
                let _ = swarm.dial_addrs(cpid, caddrs).await;
            }
        }
        return;
    }
    let _ = swarm.dial_addrs(peer_id, holder_addrs).await;
    let arrived = wait_for_auth_set(
        event_rx,
        db,
        HashSet::from([peer_id]),
        Duration::from_secs(AUTH_TIMEOUT_SECS),
    )
    .await;
    if arrived.contains(&peer_id) {
        tracing::info!(did = %device, "dr: authenticated pointer holder (via Kademlia)");
    } else {
        tracing::info!(%device, "dr: could not reach holder via Kademlia");
    }
}

// ─── SS block fetch ───────────────────────────────────────────────────────────

/// Fetch one SystemState block (base or diff) from its holder hints and return it parsed.
///
/// The memory of the decode is DR's one permit for this block (`memory`, К-b3): the symbols are
/// fetched first, outside the budget; then the decode, the decryption and the parse of the CBOR
/// straight from the decompression stream run on the blocking pool under the permit (there is no
/// plaintext buffer of the block, spec v3.9b (6)); the permit goes back before the next fetch. The
/// parsed value is outside the budget.
pub(super) async fn fetch_ss_block<T: serde::de::DeserializeOwned + Send + 'static>(
    swarm: &Arc<SwarmHandle>,
    encoder: &Arc<dyn viaticum_core::erasure::ErasureEncoder>,
    bref: &BlockRef,
    dr_key: &[u8; 32],
    memory: &mut super::memory::Memory,
) -> anyhow::Result<T> {
    use viaticum_core::types::{ErasureParams, FileId, PlacementStatus, SymbolPlacement};

    let importance = crate::daemon::system_state::block::SYSTEM_STATE_IMPORTANCE;
    let params = ErasureParams::compute(bref.encrypted_size, importance)
        .map_err(|e| anyhow::anyhow!("erasure params for SS block: {e}"))?;

    let placements: Vec<SymbolPlacement> = bref
        .holders
        .iter()
        .map(|h| SymbolPlacement {
            source_block_id: bref.block_id,
            holder_id: h.holder_id,
            file_id: FileId(0),
            esi_ranges: h.esi_ranges.clone(),
            binding_seed: [0u8; 32],
            status: PlacementStatus::Alive,
            last_verified: None,
            placed_at: Timestamp::now(),
            consecutive_misses: 0,
        })
        .collect();

    let symbols = crate::daemon::symbol_fetch::fetch_unbound_symbols(
        swarm.as_ref(),
        encoder,
        &bref.block_id,
        &placements,
        &params,
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("fetch_unbound_symbols: {e}"))?;

    decode_ss_block(
        memory,
        encoder,
        symbols,
        &bref.block_id,
        bref.encrypted_size,
        &params,
        dr_key,
    )
    .await
}

/// The memory half of an SS block's fetch (К-b3): a permit for the decode (DR's own budget, or a
/// lease from the node on this machine), the decode, the decryption and the parse on the blocking
/// pool under it, and the permit back before the next fetch.
pub(super) async fn decode_ss_block<T: serde::de::DeserializeOwned + Send + 'static>(
    memory: &mut super::memory::Memory,
    encoder: &Arc<dyn viaticum_core::erasure::ErasureEncoder>,
    symbols: Vec<viaticum_core::erasure::Symbol>,
    block: &viaticum_core::types::SourceBlockId,
    encrypted_size: u64,
    params: &viaticum_core::types::ErasureParams,
    dr_key: &[u8; 32],
) -> anyhow::Result<T> {
    let held = memory.acquire(block, encrypted_size, params).await?;
    let decoder = Arc::clone(encoder);
    let (key, block, params) = (*dr_key, *block, *params);
    let (parsed, held) = tokio::task::spawn_blocking(move || {
        let r = crate::daemon::restore::decode_parse_stage::<T>(
            held.permit(),
            decoder.as_ref(),
            symbols,
            &params,
            encrypted_size,
            &key,
            &block,
        )
        .map_err(|e| anyhow::anyhow!("decode SS block: {e}"));
        (r, held)
    })
    .await
    .map_err(|e| anyhow::anyhow!("decode SS block task failed: {e}"))?;
    held.release().await;
    parsed
}
