// Daemon-layer wrappers for system state snapshot/restore.
//
// Bridges syncback-core system_state functions to daemon identity (key
// derivation) and swarm (periodic push).
//
// Functions:
//   snapshot_and_encrypt    — dump DB → encrypted blob using identity key
//   decrypt_and_restore     — decrypt blob → restore DB
//   run_periodic_push       — tokio task: push blob to all known peers via swarm on interval

use std::sync::Arc;
use std::time::Duration;

use syncback_core::cluster::derive_master_key;
use syncback_core::db::Db;
use syncback_core::system_state::{pack_system_state, restore_db, snapshot_db, SystemState};
// Re-exported so tests (and callers) can check the current format version.
pub use syncback_core::system_state::SYSTEM_STATE_VERSION;
use syncback_core::messages::{Message, SystemStateBackupMsg};
use syncback_core::types::Timestamp;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::daemon::network::swarm::SwarmHandle;

#[cfg(test)]
mod tests;

// ─── Key derivation ───────────────────────────────────────────────────────────

/// Derive the 32-byte encryption key from a BIP39 seed.
///
/// Uses the same HKDF path as `derive_master_key` (syncback-core cluster module):
/// HKDF-SHA256(ikm=seed, salt=b"", info=b"syncback-identity-ed25519") → 32 bytes.
/// The scalar bytes of the resulting Ed25519 SigningKey are used directly as
/// the ChaCha20-Poly1305 key in pack_system_state / unpack_system_state.
fn identity_key_bytes_from_seed(seed: &[u8]) -> anyhow::Result<[u8; 32]> {
    let master_key = derive_master_key(seed)
        .map_err(|e| anyhow::anyhow!("derive_master_key failed: {e}"))?;
    Ok(master_key.to_bytes())
}

// ─── snapshot_and_encrypt ────────────────────────────────────────────────────

/// Dump the DB into a SystemState, serialize, compress, and encrypt.
///
/// The encryption key is derived from the node's BIP39 seed via
/// `identity_key_bytes_from_seed`.
///
/// The resulting blob has the wire format:
///   [salt(24)][nonce(12)][ciphertext+poly1305-tag(N+16)]
pub fn snapshot_and_encrypt(db: &Db, seed: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = identity_key_bytes_from_seed(seed)?;
    let state = snapshot_db(db).map_err(|e| anyhow::anyhow!("snapshot_db: {e}"))?;
    let blob = pack_system_state(&state, &key)
        .map_err(|e| anyhow::anyhow!("pack_system_state: {e}"))?;
    Ok(blob)
}

// ─── decrypt_and_restore ─────────────────────────────────────────────────────

/// Decrypt an encrypted blob, deserialize the SystemState, and restore the DB.
///
/// The target DB must be empty (no files, no peers) — restore_db enforces this.
/// Use `syncback_core::system_state::restore_db_force` if you need to bypass
/// the empty-DB check (e.g. during DR boot after self-registration).
///
/// Returns the deserialized SystemState on success so callers can inspect what
/// was restored without reading the DB again.
pub fn decrypt_and_restore(
    db: &Db,
    blob: &[u8],
    seed: &[u8],
) -> anyhow::Result<SystemState> {
    let key = identity_key_bytes_from_seed(seed)?;
    let state = syncback_core::system_state::unpack_system_state(blob, &key)
        .map_err(|e| anyhow::anyhow!("unpack_system_state: {e}"))?;
    restore_db(db, &state).map_err(|e| anyhow::anyhow!("restore_db: {e}"))?;
    Ok(state)
}

// ─── run_periodic_push ───────────────────────────────────────────────────────

/// Periodically snapshot the DB, encrypt the blob, and push it to all known peers.
///
/// Uses SwarmHandle.send_to_master (libp2p request-response, ε.2+).
/// SystemStateBackup is sent as a request; the response (SystemStateAck or Ack) is logged.
///
/// The minimum interval is clamped to 60 seconds to avoid hammering peers.
/// On each tick:
///   1. snapshot_and_encrypt
///   2. db.list_all_peers() — get current peer list from DB
///   3. For each peer: swarm.send_to_master(identity, SystemStateBackup)
///   4. Log success count / failures
pub async fn run_periodic_push(
    db: Db,
    swarm: Arc<SwarmHandle>,
    seed: Vec<u8>,
    interval_secs: u64,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let clamped = interval_secs.max(60);
    info!(interval_secs = clamped, "system_state periodic push: started");
    let period = Duration::from_secs(clamped);
    let mut ticker = tokio::time::interval(period);
    // The first tick fires immediately; skip it so we don't push on startup
    // before the node has had time to learn its peers.
    ticker.tick().await;
    info!("system_state periodic push: first tick skipped, waiting for next");

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = cancel.cancelled() => {
                info!("system_state periodic push: cancelled");
                break;
            }
        }

        // 1. Snapshot + encrypt.
        let blob = match snapshot_and_encrypt(&db, &seed) {
            Ok(b) => b,
            Err(e) => {
                error!(error = %e, "system_state periodic push: snapshot failed");
                continue;
            }
        };

        // 2. Get peer list.
        let peers = match db.list_all_peers() {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "system_state periodic push: list_all_peers failed");
                continue;
            }
        };

        if peers.is_empty() {
            debug!("system_state periodic push: no peers, skipping");
            continue;
        }

        // 3. Send to each peer via swarm.
        let msg = Message::SystemStateBackup(SystemStateBackupMsg {
            v: 1,
            encrypted_blob: blob.clone(),
            timestamp: Timestamp::now(),
        });

        let mut ok_count = 0usize;
        let mut fail_count = 0usize;
        for peer in &peers {
            let device_id = peer.device_id;
            match swarm.send_to_device(device_id, msg.clone()).await {
                Ok(_response) => ok_count += 1,
                Err(e) => {
                    warn!(device = %device_id, error = %e, "system_state push: send failed");
                    fail_count += 1;
                }
            }
        }
        info!(
            blob_bytes = blob.len(),
            peers_ok = ok_count,
            peers_failed = fail_count,
            "system_state periodic push: done"
        );
    }

    Ok(())
}


