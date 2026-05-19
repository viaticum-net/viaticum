// Daemon-layer wrappers for system state snapshot/restore.
//
// Bridges viaticum-core system_state functions to daemon identity (key
// derivation) and swarm (periodic push).
//
// Functions:
//   snapshot_and_encrypt    — dump DB → encrypted blob using identity key
//   decrypt_and_restore     — decrypt blob → restore DB
//   run_periodic_push       — tokio task: push blob to all known peers via swarm on interval

use std::sync::Arc;
use std::time::Duration;

use hkdf::Hkdf;
use sha2::Sha256;
use viaticum_core::db::Db;
use viaticum_core::system_state::{SystemState, pack_system_state, restore_db, snapshot_db};
// Re-exported so tests (and callers) can check the current format version.
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use viaticum_core::messages::{Message, SystemStateBackupMsg};
pub use viaticum_core::system_state::SYSTEM_STATE_VERSION;
use viaticum_core::types::Timestamp;

use crate::daemon::network::swarm::SwarmHandle;

#[cfg(test)]
mod tests;

// ─── Key derivation ───────────────────────────────────────────────────────────

/// Derive the 32-byte AEAD key material for DR blob encryption.
///
/// Uses HKDF-SHA256 directly on the raw BIP39 seed bytes (64 B).
/// info = b"viaticum-dr-key-v1" — distinct from all signing paths.
///
/// DOES NOT pass through Ed25519 SigningKey. The seed is the only IKM.
/// This preserves key separation: signing scalar is never used as AEAD material.
pub(crate) fn identity_key_bytes_from_seed(seed: &[u8]) -> anyhow::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; 32];
    hk.expand(b"viaticum-dr-key-v1", &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
    Ok(okm)
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
    let blob =
        pack_system_state(&state, &key).map_err(|e| anyhow::anyhow!("pack_system_state: {e}"))?;
    Ok(blob)
}

// ─── decrypt_and_restore ─────────────────────────────────────────────────────

/// Decrypt an encrypted blob, deserialize the SystemState, and restore the DB.
///
/// The target DB must be empty (no files, no peers) — restore_db enforces this.
/// Use `viaticum_core::system_state::restore_db_force` if you need to bypass
/// the empty-DB check (e.g. during DR boot after self-registration).
///
/// Returns the deserialized SystemState on success so callers can inspect what
/// was restored without reading the DB again.
pub fn decrypt_and_restore(db: &Db, blob: &[u8], seed: &[u8]) -> anyhow::Result<SystemState> {
    let key = identity_key_bytes_from_seed(seed)?;
    let state = viaticum_core::system_state::unpack_system_state(blob, &key)
        .map_err(|e| anyhow::anyhow!("unpack_system_state: {e}"))?;
    restore_db(db, &state).map_err(|e| anyhow::anyhow!("restore_db: {e}"))?;
    Ok(state)
}

// ─── run_periodic_push ───────────────────────────────────────────────────────

/// Periodically snapshot the DB, encrypt the blob, and push it to all known peers.
///
/// Uses SwarmHandle.send_to_device (libp2p request-response, ε.2+).
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
    info!(
        interval_secs = clamped,
        "system_state periodic push: started"
    );
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
