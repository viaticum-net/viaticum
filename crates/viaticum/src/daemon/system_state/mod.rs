// Daemon-layer wrappers for system state snapshot/restore.
//
// Bridges viaticum-core system_state functions to daemon identity (key
// derivation) and swarm (periodic push).
//
// Functions:
//   snapshot_and_encrypt    — dump DB → encrypted blob using identity key
//   decrypt_and_restore     — decrypt blob → restore DB
//   run_periodic_push       — tokio task: push blob to all known peers via swarm on interval

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hkdf::Hkdf;
use sha2::Sha256;
use viaticum_core::db::Db;
use viaticum_core::system_state::{
    SystemState, diff_states, pack_system_state, restore_db, snapshot_db,
};
// Re-exported so tests (and callers) can check the current format version.
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use viaticum_core::messages::{Message, SystemStateBackupMsg};
pub use viaticum_core::system_state::SYSTEM_STATE_VERSION;
use viaticum_core::types::{SourceBlockId, Timestamp, to_cbor_bytes};

use crate::daemon::network::swarm::SwarmHandle;

pub mod block;
pub mod publish;

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

/// Periodically publish the SystemState as regular blocks + a signed self-pointer.
///
/// Replaces the legacy full-blob push (Bug #4: per-master overwrite, no quota, no
/// PoS). The state now rides the normal block storage primitive:
///   1. snapshot_db → if the snapshot changed since the last publish (or first run),
///      build a new base SS block (`publish_base_block`, DR-stable key), retire the
///      previous base, bump the generation. The work pipeline places the block and
///      the scheduler PoS-challenges it like any block.
///   2. Build + sign a `SelfPointer` over the current base (diffs dormant in v1 —
///      DR already consumes them, so enabling diffs later is a push-loop-only change)
///      and ride it in the EXISTING `SystemStateBackup` blob field. Recipients store
///      it opaque; only DR interprets it.
///
/// The minimum interval is clamped to 60 seconds. The pointer is eventually-consistent:
/// early pointers may reference a base with few/no Alive holders until placement completes.
pub async fn run_periodic_push(
    db: Db,
    swarm: Arc<SwarmHandle>,
    seed: Vec<u8>,
    master_key: ed25519_dalek::SigningKey,
    data_dir: PathBuf,
    interval_secs: u64,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let clamped = interval_secs.max(60);
    let dr_key = identity_key_bytes_from_seed(&seed)?;
    info!(
        interval_secs = clamped,
        "system_state periodic push (SS-as-block): started"
    );
    let period = Duration::from_secs(clamped);
    let mut ticker = tokio::time::interval(period);
    // The first tick fires immediately; skip it so we don't publish on startup
    // before the node has had time to learn its peers / place blocks.
    ticker.tick().await;
    info!("system_state periodic push: first tick skipped, waiting for next");

    // RAM state across ticks (rebuilt fresh on restart — a new base is published).
    // The base is built ONCE and stays stable (so it places and remains fetchable);
    // changes are captured as small diff blocks. Rebuilding the base every time the
    // snapshot churns (peer last_seen / trust / PoS updates) would mean placement
    // never catches up and the pointer would perpetually reference an unplaced base.
    let mut generation: u32 = 0;
    let mut base_id: Option<SourceBlockId> = None;
    let mut last_published_state: Option<SystemState> = None;
    let mut diff_ids: Vec<SourceBlockId> = Vec::new();

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = cancel.cancelled() => {
                info!("system_state periodic push: cancelled");
                break;
            }
        }

        // 1. Snapshot (excludes our own SS blocks via the ledger — no self-reference).
        let state = match snapshot_db(&db) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "system_state push: snapshot failed");
                continue;
            }
        };

        // 2. First publish → base. Subsequent changes → diff blocks; compaction
        //    rebuilds the base when too many diffs accumulate.
        if last_published_state.is_none() {
            let next_gen = generation + 1;
            match publish::publish_base_block(&db, &data_dir, &dr_key, next_gen, &state) {
                Ok(id) => {
                    base_id = Some(id);
                    generation = next_gen;
                    diff_ids.clear();
                    last_published_state = Some(state);
                    info!(generation, base = %id, "system_state push: base published");
                }
                Err(e) => {
                    error!(error = %e, "system_state push: publish_base_block failed");
                    continue;
                }
            }
        } else {
            let diffs = diff_states(last_published_state.as_ref().unwrap(), &state);
            if !diffs.is_empty() {
                if diff_ids.len() >= DIFF_COMPACTION_THRESHOLD {
                    let next_gen = generation + 1;
                    match publish::publish_base_block(&db, &data_dir, &dr_key, next_gen, &state) {
                        Ok(new_base) => {
                            if let Some(old) = base_id {
                                publish::retire_ss_block(&db, &data_dir, &old);
                            }
                            for d in &diff_ids {
                                publish::retire_ss_block(&db, &data_dir, d);
                            }
                            base_id = Some(new_base);
                            generation = next_gen;
                            diff_ids.clear();
                            last_published_state = Some(state);
                            info!(generation, base = %new_base, "system_state push: compacted to new base");
                        }
                        Err(e) => {
                            error!(error = %e, "system_state push: compaction base failed");
                            continue;
                        }
                    }
                } else {
                    match publish::publish_diff_block(&db, &data_dir, &dr_key, generation, &diffs) {
                        Ok(id) => {
                            diff_ids.push(id);
                            last_published_state = Some(state);
                            info!(generation, diff = %id, diffs = diff_ids.len(), "system_state push: diff published");
                        }
                        Err(e) => {
                            error!(error = %e, "system_state push: publish_diff_block failed");
                            continue;
                        }
                    }
                }
            }
        }

        let base = match base_id {
            Some(b) => b,
            None => continue,
        };

        // 3. Build the self-pointer over the PLACED prefix of base + diffs. If the
        //    base has not been placed yet, skip this tick (it places within seconds).
        let pointer = match publish::build_pointer_for_placed(
            &db,
            &master_key,
            generation,
            &base,
            &diff_ids,
            Timestamp::now(),
        ) {
            Ok(Some(p)) => p,
            Ok(None) => {
                debug!("system_state push: base not placed yet, skipping pointer");
                continue;
            }
            Err(e) => {
                error!(error = %e, "system_state push: build_pointer failed");
                continue;
            }
        };
        let blob = to_cbor_bytes(&pointer);

        // 4. Ride the pointer in the existing SystemStateBackup blob field.
        let peers = match db.list_all_peers() {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "system_state push: list_all_peers failed");
                continue;
            }
        };
        if peers.is_empty() {
            debug!("system_state push: no peers, skipping pointer send");
            continue;
        }

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
            generation,
            base = %base,
            diffs = pointer.diffs.len(),
            pointer_bytes = blob.len(),
            base_holders = pointer.base.holders.len(),
            peers_ok = ok_count,
            peers_failed = fail_count,
            "system_state push: pointer published"
        );
    }

    Ok(())
}

/// Rebuild the base (and discard accumulated diffs) once this many diff blocks
/// pile up — keeps DR's apply chain short and bounds retained-blob count.
const DIFF_COMPACTION_THRESHOLD: usize = 20;
