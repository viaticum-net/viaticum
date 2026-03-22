// Disaster recovery: restore node state from seed phrase via BFS peer discovery.
//
// Runs standalone (no daemon, no Processor). Connects directly to peers,
// requests SystemState blobs, and restores the DB.
//
// Flow:
//   1. Init identity from mnemonic → IdentityKeyFile
//   2. Open fresh DB (remove stale db.redb if present)
//   3. Start minimal NetworkHandle (iroh endpoint, no Processor)
//   4. BFS over peers: SystemStateRequest + PeerDiscoveryRequest on each connection
//   5. Select freshest blob, decrypt and restore DB

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::RelayMode;
use syncback_core::messages::{Message, PeerDiscoveryRequestMsg, SystemStateRequestMsg};
use syncback_core::types::{hex_encode, Timestamp};
use tokio::sync::mpsc;

use crate::daemon::identity::{derive_keys, init_identity_from_mnemonic, load_identity};
use crate::daemon::network::addr::{parse_node_addr, to_endpoint_addr};
use crate::daemon::network::{NetworkConfig, NetworkHandle};

#[cfg(test)]
mod tests;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Total time budget for BFS discovery.
const BFS_TIMEOUT_SECS: u64 = 120;
/// Max peers to visit during BFS.
const BFS_MAX_PEERS: usize = 500;
/// Stop collecting blobs after finding this many.
const BFS_MAX_BLOBS: usize = 10;
/// Per-connection timeout for connect + handshake.
const CONNECT_TIMEOUT_SECS: u64 = 10;
/// Per-request timeout for waiting for a response message.
const REQUEST_TIMEOUT_SECS: u64 = 5;

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Run disaster recovery: restore node state from mnemonic into data_dir.
///
/// Connects to seed peers, discovers network via BFS, collects SystemState
/// blobs, and restores the DB from the freshest blob found.
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

    let (_master_key, device_key, _epoch_key_bytes, iroh_key_bytes) = derive_keys(&keyfile, 0)?;

    // ── 2. Open fresh DB ──────────────────────────────────────────────────────
    let db_path = data_dir.join("db.redb");
    if db_path.exists() {
        std::fs::remove_file(&db_path)?;
        tracing::info!("removed stale db.redb from prior DR attempt");
    }
    let db = syncback_core::db::Db::open(&db_path)?;

    // ── 3. Start minimal NetworkHandle ────────────────────────────────────────
    // We need an incoming_tx but won't use it (no Processor in DR mode).
    let (incoming_tx, _incoming_rx) = mpsc::channel(16);

    let net_config = NetworkConfig {
        signing_key: device_key,
        known_peers: std::collections::HashMap::new(),
        device_cert: None,
        iroh_secret_key: Some(iroh::SecretKey::from_bytes(&iroh_key_bytes)),
        relay_mode: RelayMode::Default,
    };

    let network = Arc::new(NetworkHandle::start(net_config, incoming_tx).await?);
    println!("Network ready. Starting peer discovery...");

    // ── 4. BFS discovery ──────────────────────────────────────────────────────
    let blobs = bfs_collect_blobs(&network, peer_addrs).await;

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

    // Drop the Arc; the iroh endpoint closes when the last Arc is released.
    drop(network);
    Ok(())
}

// ─── BFS implementation ───────────────────────────────────────────────────────

/// BFS over peers, collecting (created_at, encrypted_blob) pairs.
///
/// Visits each peer once: sends SystemStateRequest and PeerDiscoveryRequest,
/// collects blobs and queues newly discovered peers.
async fn bfs_collect_blobs(
    network: &NetworkHandle,
    seed_addrs: Vec<String>,
) -> Vec<(u64, Vec<u8>)> {
    let timeout = Duration::from_secs(BFS_TIMEOUT_SECS);
    let start = Instant::now();

    let mut queue: VecDeque<String> = seed_addrs.into();
    let mut visited: HashSet<[u8; 32]> = HashSet::new();
    let mut blobs: Vec<(u64, Vec<u8>)> = Vec::new();

    while let Some(addr_str) = queue.pop_front() {
        if start.elapsed() > timeout {
            println!("BFS timeout reached ({BFS_TIMEOUT_SECS}s), stopping.");
            break;
        }
        if visited.len() >= BFS_MAX_PEERS {
            println!("BFS peer limit reached ({BFS_MAX_PEERS}), stopping.");
            break;
        }
        if blobs.len() >= BFS_MAX_BLOBS {
            println!("BFS blob limit reached ({BFS_MAX_BLOBS}), stopping.");
            break;
        }

        // Parse address.
        let parsed = match parse_node_addr(&addr_str) {
            Ok(p) => p,
            Err(e) => {
                println!("  skip '{addr_str}': invalid address ({e})");
                continue;
            }
        };
        let endpoint_addr = match to_endpoint_addr(&parsed) {
            Ok(ea) => ea,
            Err(e) => {
                println!("  skip '{addr_str}': to_endpoint_addr failed ({e})");
                continue;
            }
        };

        // De-duplicate by iroh NodeId bytes (used as IdentityPub stand-in).
        let node_id_bytes = parsed.node_id.0;
        if visited.contains(&node_id_bytes) {
            continue;
        }
        visited.insert(node_id_bytes);

        println!(
            "  connecting to {} ({} visited, {} blobs so far)...",
            hex_encode(&node_id_bytes),
            visited.len(),
            blobs.len()
        );

        // Connect directly (bypasses known_peers lookup).
        let conn = match tokio::time::timeout(
            Duration::from_secs(CONNECT_TIMEOUT_SECS),
            network.connect(endpoint_addr, None),
        )
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                println!("  skip: connect failed ({e})");
                continue;
            }
            Err(_) => {
                println!("  skip: connect timeout");
                continue;
            }
        };

        let peer_identity = conn.peer_identity;
        println!("  connected to {peer_identity}");

        // ── SystemStateRequest ────────────────────────────────────────────────
        let req = Message::SystemStateRequest(SystemStateRequestMsg {
            v: 1,
            timestamp: Timestamp::now(),
        });
        if let Err(e) = conn.send_message(&req).await {
            println!("  send SystemStateRequest failed: {e}");
            continue;
        }

        // Wait for SystemStateResponse, skipping other message types.
        match recv_expecting_system_state(&conn).await {
            Some(resp) if !resp.encrypted_blob.is_empty() => {
                println!("  found blob ({} bytes)", resp.encrypted_blob.len());
                blobs.push((resp.timestamp.0, resp.encrypted_blob));
            }
            Some(_) => {
                println!("  peer has no blob stored for us");
            }
            None => {
                println!("  SystemStateResponse timeout or error");
                continue;
            }
        }

        // ── PeerDiscoveryRequest ──────────────────────────────────────────────
        let req = Message::PeerDiscoveryRequest(PeerDiscoveryRequestMsg {
            v: 1,
            timestamp: Timestamp::now(),
        });
        if let Err(e) = conn.send_message(&req).await {
            println!("  send PeerDiscoveryRequest failed: {e}");
            continue;
        }

        match recv_expecting_peer_discovery(&conn).await {
            Some(resp) => {
                // DiscoveredPeer carries identity_pub + node_id but no socket address,
                // so we cannot directly enqueue discovered peers as connectable addresses.
                // Connectivity to newly discovered peers requires a full addr string
                // (node_id_hex@ip:port). For DR, the seed --peer addresses are the
                // primary entry points. Mark discovered peers as visited for de-duplication
                // so we don't re-visit them if they appear via another route.
                let new_count = resp
                    .peers
                    .iter()
                    .filter(|dp| !visited.contains(&dp.node_id.0))
                    .count();
                for dp in &resp.peers {
                    visited.insert(dp.node_id.0);
                }
                println!(
                    "  discovered {} peers ({} new) from {peer_identity}",
                    resp.peers.len(),
                    new_count
                );
            }
            None => {
                println!("  PeerDiscoveryResponse timeout or error");
            }
        }
    }

    println!(
        "BFS complete: visited {} peers, collected {} blobs ({:.1}s elapsed)",
        visited.len(),
        blobs.len(),
        start.elapsed().as_secs_f32(),
    );

    blobs
}

// ─── Response helpers ─────────────────────────────────────────────────────────

/// Read messages from `conn` until a `SystemStateResponse` arrives, discarding
/// other message types (e.g. `PeerAnnounce` that the remote Processor may send
/// immediately after handshake).
///
/// Returns `None` on timeout or connection error.
async fn recv_expecting_system_state(
    conn: &crate::daemon::network::connection::Connection,
) -> Option<syncback_core::messages::SystemStateResponseMsg> {
    let deadline = Duration::from_secs(REQUEST_TIMEOUT_SECS);
    let start = Instant::now();

    loop {
        let remaining = deadline.checked_sub(start.elapsed())?;
        match tokio::time::timeout(remaining, conn.recv_message()).await {
            Ok(Ok(Message::SystemStateResponse(resp))) => return Some(resp),
            Ok(Ok(_other)) => {
                // Skip unrelated messages (e.g. PeerAnnounce, BoardSync).
                if start.elapsed() >= deadline {
                    return None;
                }
                continue;
            }
            Ok(Err(_)) | Err(_) => return None,
        }
    }
}

/// Read messages from `conn` until a `PeerDiscoveryResponse` arrives.
///
/// Returns `None` on timeout or connection error.
async fn recv_expecting_peer_discovery(
    conn: &crate::daemon::network::connection::Connection,
) -> Option<syncback_core::messages::PeerDiscoveryResponseMsg> {
    let deadline = Duration::from_secs(REQUEST_TIMEOUT_SECS);
    let start = Instant::now();

    loop {
        let remaining = deadline.checked_sub(start.elapsed())?;
        match tokio::time::timeout(remaining, conn.recv_message()).await {
            Ok(Ok(Message::PeerDiscoveryResponse(resp))) => return Some(resp),
            Ok(Ok(_other)) => {
                if start.elapsed() >= deadline {
                    return None;
                }
                continue;
            }
            Ok(Err(_)) | Err(_) => return None,
        }
    }
}
