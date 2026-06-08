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

use viaticum_core::messages::{Message, SystemStateRequestMsg};
use viaticum_core::types::{Timestamp, hex_encode};

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
    let identity_pub = viaticum_core::types::IdentityPub(keyfile.identity_pub);
    let device_id = viaticum_core::types::DeviceId(keyfile.device_id);

    // ── 2. Open fresh DB ──────────────────────────────────────────────────────
    let db_path = data_dir.join("db.redb");
    if db_path.exists() {
        std::fs::remove_file(&db_path)?;
        tracing::info!("removed stale db.redb from prior DR attempt");
    }
    let db = viaticum_core::db::Db::open(&db_path)?;

    // ── 3. Start minimal SwarmHandle ─────────────────────────────────────────
    // Issue a device certificate so DeviceCertExchange succeeds.
    let device_cert =
        viaticum_core::cluster::issue_device_certificate(&master_key, device_id, Timestamp::now());

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
        // DR mode is read-only / short-lived — never act as relay server.
        enable_relay_server: false,
    };

    let (swarm_handle, mut event_rx) = SwarmHandle::start(swarm_cfg).await?;
    println!("Network ready. Starting peer discovery...");

    // ── 4. BFS: dial seed peers (= the SS-block holders), collect pointer blobs ─
    // Each SystemStateResponse blob now carries a CBOR SelfPointer (not a full
    // state blob). The dialed seed peers stay authenticated in the swarm, so we
    // reuse those connections below to fetch the base/diff blocks by holder hint.
    let blobs = bfs_collect_blobs(&swarm_handle, &mut event_rx, peer_addrs).await;
    if blobs.is_empty() {
        anyhow::bail!("no system state pointers found during BFS discovery");
    }

    // ── 5. Parse + verify pointers; pick the freshest valid one ───────────────
    let mut pointers: Vec<viaticum_core::system_state::SelfPointer> = blobs
        .iter()
        .filter_map(|(_, blob)| {
            viaticum_core::types::from_cbor_bytes::<viaticum_core::system_state::SelfPointer>(blob)
                .ok()
        })
        .filter(|p| viaticum_core::system_state::verify_self_pointer(p, &identity_pub).is_ok())
        .collect();
    if pointers.is_empty() {
        anyhow::bail!(
            "collected {} blob(s) but none were valid signed self-pointers",
            blobs.len()
        );
    }
    // Freshest first by created_at; generation breaks ties.
    pointers.sort_by_key(|p| std::cmp::Reverse((p.created_at.0, p.generation)));
    let pointer = &pointers[0];
    println!(
        "Selected self-pointer: generation={}, base={}, diffs={}, created_at={}",
        pointer.generation,
        hex_encode(&pointer.base.block_id.0),
        pointer.diffs.len(),
        pointer.created_at.0
    );

    // The seed-peer connections stay authenticated in the swarm; reuse them (Arc)
    // to fetch the base/diff blocks from their holders.
    let swarm_handle = std::sync::Arc::new(swarm_handle);

    // ── 6. Fetch base + diff blocks via holder hints, reassemble state ────────
    let dr_key = crate::daemon::system_state::identity_key_bytes_from_seed(&keyfile.seed)?;
    let encoder: std::sync::Arc<dyn viaticum_core::erasure::ErasureEncoder> =
        std::sync::Arc::new(viaticum_core::erasure::RaptorQEncoder::new());

    let base_bytes = fetch_ss_block(&swarm_handle, &encoder, &pointer.base, &dr_key)
        .await
        .map_err(|e| anyhow::anyhow!("failed to fetch SS base block: {e}"))?;
    let base_state: viaticum_core::system_state::SystemState =
        viaticum_core::types::from_cbor_bytes(&base_bytes)
            .map_err(|e| anyhow::anyhow!("decode base SystemState: {e}"))?;

    let mut diffs: Vec<Vec<viaticum_core::system_state::DiffOp>> =
        Vec::with_capacity(pointer.diffs.len());
    for dref in &pointer.diffs {
        let bytes = fetch_ss_block(&swarm_handle, &encoder, dref, &dr_key)
            .await
            .map_err(|e| anyhow::anyhow!("failed to fetch SS diff block: {e}"))?;
        diffs.push(
            viaticum_core::types::from_cbor_bytes(&bytes)
                .map_err(|e| anyhow::anyhow!("decode diff block: {e}"))?,
        );
    }

    let state = viaticum_core::system_state::apply_diffs(base_state, &diffs);

    // ── 7. Restore into the fresh DB ──────────────────────────────────────────
    viaticum_core::system_state::restore_db(&db, &state)
        .map_err(|e| anyhow::anyhow!("restore_db: {e}"))?;

    println!("DR restore successful:");
    println!("  Files:         {}", state.files.len());
    println!("  Source blocks: {}", state.source_blocks.len());
    println!("  Placements:    {}", state.symbol_placements.len());
    println!("  Peers:         {}", state.peers.len());
    println!();
    println!("Run 'viaticum daemon' to start, then 'viaticum restore <path>' to recover files.");

    Ok(())
}

/// Fetch one SystemState block (base or diff) from its holder hints and return the
/// decrypted plaintext (CBOR of `SystemState` for a base, `Vec<DiffOp>` for a diff).
///
/// DR has no `SourceBlockRecord`/`symbol_placements`, so the params come from the
/// pointer: `ErasureParams::compute(encrypted_size, SYSTEM_STATE_IMPORTANCE)` is
/// deterministic and reproduces the exact placement params. Holders are reached via
/// the authenticated-device map of the seed peers dialed above.
async fn fetch_ss_block(
    swarm: &std::sync::Arc<SwarmHandle>,
    encoder: &std::sync::Arc<dyn viaticum_core::erasure::ErasureEncoder>,
    bref: &viaticum_core::system_state::BlockRef,
    dr_key: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    use viaticum_core::types::{ErasureParams, FileId, PlacementStatus, SymbolPlacement};

    let importance = crate::daemon::system_state::block::SYSTEM_STATE_IMPORTANCE;
    let params = ErasureParams::compute(bref.encrypted_size, importance)
        .map_err(|e| anyhow::anyhow!("erasure params for SS block: {e}"))?;

    // Reconstruct placements from holder hints (holder_id + esi_ranges suffice;
    // unbind derives the binding from block_id + holder_id, not binding_seed).
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
        swarm,
        encoder,
        &bref.block_id,
        &placements,
        params.k_eff as usize,
    )
    .await
    .map_err(|e| anyhow::anyhow!("fetch_unbound_symbols: {e}"))?;

    let padded = encoder
        .decode(&symbols, &params)
        .map_err(|e| anyhow::anyhow!("decode SS block: {e}"))?;
    let size = bref.encrypted_size as usize;
    if padded.len() < size {
        anyhow::bail!(
            "decoded SS block ({} bytes) smaller than encrypted_size ({size})",
            padded.len()
        );
    }
    let stored = &padded[..size];
    crate::daemon::backup::pipeline::decrypt_and_decompress(stored, dr_key)
        .map_err(|e| anyhow::anyhow!("decrypt SS block: {e}"))
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
) -> Option<viaticum_core::types::DeviceId> {
    let deadline = Duration::from_secs(AUTH_TIMEOUT_SECS);

    tokio::time::timeout(deadline, async {
        loop {
            match event_rx.recv().await {
                Some(ProtocolEvent::PeerAuthenticated {
                    peer_id, device_id, ..
                }) => {
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
