// Disaster recovery: restore node state from seed phrase via peer discovery.
//
// Runs standalone (no daemon, no Processor). Connects to seed peers via libp2p
// SwarmHandle, requests SystemState blobs, and restores the DB.
//
// Flow:
//   1. Init identity from mnemonic → IdentityKeyFile
//   2. Open fresh DB (remove stale db.redb if present)
//   3. Start minimal SwarmHandle (libp2p, no Processor)
//   4. For each seed peer: dial → wait PeerAuthenticated → send SystemStateRequest
//   5. Select freshest blob, decrypt and restore DB
//
// Note: PeerDiscovery (BFS expansion) is removed in ε.2. DHT-based discovery
// comes in ε.3. For ε.2, only explicitly provided seed addresses are visited.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use syncback_core::messages::{Message, SystemStateRequestMsg};
use syncback_core::types::{hex_encode, Timestamp};

use crate::daemon::identity::{derive_keys, init_identity_from_mnemonic, load_identity};
use crate::daemon::network::swarm::{ProtocolEvent, SwarmConfig, SwarmHandle};

#[cfg(test)]
mod tests;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Per-connection timeout for dial + DeviceCertExchange.
const AUTH_TIMEOUT_SECS: u64 = 15;
/// Per-request timeout for waiting for a SystemStateResponse.
const REQUEST_TIMEOUT_SECS: u64 = 10;
/// Max peers to visit.
const BFS_MAX_PEERS: usize = 500;
/// Stop collecting blobs after finding this many.
const BFS_MAX_BLOBS: usize = 10;

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Run disaster recovery: restore node state from mnemonic into data_dir.
///
/// Connects to seed peers via libp2p SwarmHandle. DeviceCertExchange happens
/// automatically. Collects SystemState blobs via request-response and restores
/// the DB from the freshest blob found.
pub async fn run_dr(
    mnemonic: String,
    peer_addrs: Vec<String>,
    data_dir: PathBuf,
) -> anyhow::Result<()> {
    println!("Starting disaster recovery...");
    println!("Data directory: {}", data_dir.display());

    // ── 1. Init identity ──────────────────────────────────────────────────────
    std::fs::create_dir_all(&data_dir)?;

    let keyfile = match init_identity_from_mnemonic(&data_dir, &mnemonic) {
        Ok(kf) => kf,
        Err(e) => {
            tracing::warn!("identity init: {e}, attempting to load existing");
            load_identity(&data_dir)?
        }
    };

    let identity_pub_hex = hex_encode(&keyfile.identity_pub);
    println!("Identity restored: {identity_pub_hex}");

    let (master_key, device_key, _epoch_key_bytes) = derive_keys(&keyfile, 0)?;
    let identity_pub = syncback_core::types::IdentityPub(keyfile.identity_pub);
    let device_id = syncback_core::types::DeviceId(keyfile.device_id);

    // ── 2. Open fresh DB ──────────────────────────────────────────────────────
    let db_path = data_dir.join("db.redb");
    if db_path.exists() {
        std::fs::remove_file(&db_path)?;
        tracing::info!("removed stale db.redb from prior DR attempt");
    }
    let db = syncback_core::db::Db::open(&db_path)?;

    // ── 3. Start minimal SwarmHandle ─────────────────────────────────────────
    // Issue a device certificate so DeviceCertExchange succeeds.
    let device_cert = syncback_core::cluster::issue_device_certificate(
        &master_key,
        device_id,
        Timestamp::now(),
    );

    let swarm_cfg = SwarmConfig {
        device_signing_key: device_key,
        master_signing_key: master_key,
        identity_pub,
        // DR recovers the founder's seed, so this node IS the cluster master.
        // identity_pub == cluster_master_pub by construction here; peers we
        // contact (former joiners) hold certs signed by this same master.
        cluster_master_pub: identity_pub,
        device_cert,
        x25519_pub: None,
        listen_port: 0,
        cert_timeout_secs: AUTH_TIMEOUT_SECS,
        // DR mode: no Kademlia bootstrap — we dial explicit seed peers directly.
        kademlia_bootstrap_peers: vec![],
        kademlia_disable_ipfs_bootstrap: true,
        kad_republish_interval_override: None,
        kad_discovery_interval_override: None,
    };

    let (swarm_handle, mut event_rx) = SwarmHandle::start(swarm_cfg).await?;
    println!("Network ready. Starting peer discovery...");

    // ── 4. BFS: dial seed peers, collect SystemState blobs ───────────────────
    let blobs = bfs_collect_blobs(&swarm_handle, &mut event_rx, peer_addrs).await;

    // ── 5. Select freshest blob and restore ───────────────────────────────────
    if blobs.is_empty() {
        anyhow::bail!("no system state blobs found during BFS discovery");
    }

    // Sort by created_at descending: freshest first.
    let mut blobs = blobs;
    blobs.sort_by(|a, b| b.0.cmp(&a.0));
    let (ts, best_blob) = &blobs[0];

    println!(
        "Restoring from blob (created_at={ts}, {} bytes)...",
        best_blob.len()
    );

    let state = crate::daemon::system_state::decrypt_and_restore(&db, best_blob, &keyfile.seed)?;

    println!("DR restore successful:");
    println!("  Files:         {}", state.files.len());
    println!("  Source blocks: {}", state.source_blocks.len());
    println!("  Placements:    {}", state.symbol_placements.len());
    println!("  Peers:         {}", state.peers.len());
    println!();
    println!("Run 'syncback daemon' to start, then 'syncback restore <path>' to recover files.");

    Ok(())
}

// ─── BFS implementation ───────────────────────────────────────────────────────

/// Parse a Multiaddr string that may contain a /p2p/<PeerId> component.
///
/// Returns (PeerId, Multiaddr) if the p2p component is present, or an error.
fn parse_multiaddr_with_peer_id(
    addr_str: &str,
) -> anyhow::Result<(libp2p::PeerId, libp2p::Multiaddr)> {
    use libp2p::multiaddr::Protocol;
    use std::str::FromStr;

    let ma = libp2p::Multiaddr::from_str(addr_str)
        .map_err(|e| anyhow::anyhow!("invalid multiaddr '{addr_str}': {e}"))?;

    // Extract /p2p/<PeerId> from the last protocol component.
    for proto in ma.iter() {
        if let Protocol::P2p(peer_id) = proto {
            // Strip the /p2p/... suffix so we can dial the transport address.
            let transport_addr: libp2p::Multiaddr = ma
                .iter()
                .filter(|p| !matches!(p, Protocol::P2p(_)))
                .collect();
            return Ok((peer_id, transport_addr));
        }
    }

    anyhow::bail!("multiaddr '{addr_str}' has no /p2p/<PeerId> component")
}

/// BFS over seed peers, collecting (created_at, encrypted_blob) pairs.
///
/// For each seed address:
///   1. Parse Multiaddr (must include /p2p/<PeerId> suffix).
///   2. dial → wait for PeerAuthenticated event (AUTH_TIMEOUT_SECS).
///   3. send SystemStateRequest via send_to_device.
///   4. Collect blob if SystemStateResponse is non-empty.
///
/// In ε.2, BFS expansion via PeerDiscovery is not supported.
/// Only the explicitly provided seed addresses are visited.
async fn bfs_collect_blobs(
    swarm: &SwarmHandle,
    event_rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>,
    seed_addrs: Vec<String>,
) -> Vec<(u64, Vec<u8>)> {
    let mut visited: HashSet<[u8; 32]> = HashSet::new();
    let mut blobs: Vec<(u64, Vec<u8>)> = Vec::new();

    for addr_str in &seed_addrs {
        if visited.len() >= BFS_MAX_PEERS {
            tracing::info!("BFS peer limit reached ({BFS_MAX_PEERS}), stopping.");
            break;
        }
        if blobs.len() >= BFS_MAX_BLOBS {
            tracing::info!("BFS blob limit reached ({BFS_MAX_BLOBS}), stopping.");
            break;
        }

        // Parse address.
        let (peer_id, multiaddr) = match parse_multiaddr_with_peer_id(addr_str) {
            Ok(r) => r,
            Err(e) => {
                tracing::info!("  skip '{addr_str}': {e}");
                continue;
            }
        };

        // De-duplicate by PeerId bytes.
        let peer_id_bytes = peer_id.to_bytes();
        // Use first 32 bytes as key (multihash is longer, but sufficient for dedup).
        let key: [u8; 32] = {
            let mut k = [0u8; 32];
            let src = &peer_id_bytes[..peer_id_bytes.len().min(32)];
            k[..src.len()].copy_from_slice(src);
            k
        };
        if visited.contains(&key) {
            continue;
        }
        visited.insert(key);

        tracing::info!(
            addr = &addr_str[..addr_str.len().min(80)],
            visited = visited.len(),
            blobs = blobs.len(),
            "dr: dialing peer"
        );

        // Dial the peer.
        if let Err(e) = swarm.dial(peer_id, multiaddr).await {
            tracing::info!("dr: skip: dial failed ({e})");
            continue;
        }

        // Wait for PeerAuthenticated event (with timeout).
        let device_id = match wait_for_auth(event_rx, peer_id).await {
            Some(did) => did,
            None => {
                tracing::info!("dr: skip: authentication timeout or connection closed");
                continue;
            }
        };

        tracing::info!(device = %device_id, "dr: authenticated");

        // Send SystemStateRequest via libp2p request-response.
        let req = Message::SystemStateRequest(SystemStateRequestMsg {
            v: 1,
            timestamp: Timestamp::now(),
        });

        match tokio::time::timeout(
            Duration::from_secs(REQUEST_TIMEOUT_SECS),
            swarm.send_to_device(device_id, req),
        )
        .await
        {
            Ok(Ok(Message::SystemStateResponse(resp))) => {
                if !resp.encrypted_blob.is_empty() {
                    tracing::info!(bytes = resp.encrypted_blob.len(), "dr: found blob");
                    blobs.push((resp.timestamp.0, resp.encrypted_blob));
                } else {
                    tracing::info!("dr: peer has no blob stored for us");
                }
            }
            Ok(Ok(other)) => {
                tracing::info!(
                    response = ?std::mem::discriminant(&other),
                    "dr: unexpected response"
                );
            }
            Ok(Err(e)) => {
                tracing::info!("dr: SystemStateRequest failed: {e}");
            }
            Err(_) => {
                tracing::info!("dr: SystemStateRequest timed out");
            }
        }
    }

    tracing::info!(
        visited = visited.len(),
        blobs = blobs.len(),
        "dr: BFS complete"
    );

    blobs
}

/// Wait for a PeerAuthenticated event from the given peer_id.
///
/// Returns the DeviceId if authentication succeeds within AUTH_TIMEOUT_SECS.
/// Returns None on timeout, channel close, or ConnectionClosed.
async fn wait_for_auth(
    event_rx: &mut tokio::sync::mpsc::Receiver<ProtocolEvent>,
    expected_peer_id: libp2p::PeerId,
) -> Option<syncback_core::types::DeviceId> {
    let deadline = Duration::from_secs(AUTH_TIMEOUT_SECS);

    tokio::time::timeout(deadline, async {
        loop {
            match event_rx.recv().await {
                Some(ProtocolEvent::PeerAuthenticated { peer_id, device_id, .. }) => {
                    if peer_id == expected_peer_id {
                        return Some(device_id);
                    }
                    // Different peer authenticated — continue waiting.
                }
                Some(ProtocolEvent::ConnectionClosed { peer_id, .. }) => {
                    if peer_id == expected_peer_id {
                        return None;
                    }
                }
                Some(ProtocolEvent::InboundRequest { .. }) => {
                    // Ignore inbound requests during DR — no Processor running.
                }
                Some(ProtocolEvent::PeerIdentified { .. }) => {
                    // No DB to persist into during DR; just ignore.
                }
                None => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}
