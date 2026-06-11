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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hkdf::Hkdf;
use sha2::Sha256;
use viaticum_core::constants::MAILBOX_POINTER_REPUBLISH_SECS;
use viaticum_core::db::Db;
use viaticum_core::mailbox::{MailboxClass, MailboxEntry, class_config};
use viaticum_core::system_state::{
    SelfPointer, SystemState, diff_states, pack_system_state, restore_db, snapshot_db,
};
// Re-exported so tests (and callers) can check the current format version.
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
pub use viaticum_core::system_state::SYSTEM_STATE_VERSION;
use viaticum_core::types::{IdentityPub, SourceBlockId, Timestamp, to_cbor_bytes};

use crate::daemon::mailbox::routing::MailboxRouter;
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
/// T-8: replaces the former push-to-all pointer fanout with mailbox publish.
/// The SelfPointer is published to `mailbox_router.publish(&my_master_pub, entry)` with
/// class=SelfPointer and TTL=5 years. Republish policy (store-and-forward — not every tick):
///   - Publish when (a) the pointer structurally changed (generation or block_ids differ), OR
///   - (b) 30 days have elapsed since last publish (`MAILBOX_POINTER_REPUBLISH_SECS`).
///   - Skip otherwise (mailbox is store-and-forward with 5y TTL — no need to flood every 6h).
///
/// Block publishing pipeline is unchanged: the base/diff blocks are placed via the
/// existing publish_base_block / publish_diff_block path. Only the *pointer transport*
/// is swapped from push-to-all to mailbox.
///
/// `current_pointer`: shared handle with `run_mailbox_poll`. On publish, this is updated
/// so poll dispatch (W-2 own-pointer arm) can see the latest pointer. On startup, we seed
/// `last_published` from this handle (restart-recovery: avoids re-publishing generation 0).
///
/// The pointer lives only in the mailbox candidate-set; DR finds it via
/// `mailbox_router.dr_walk_for_pointer` (the relay-board / SystemState blob path was
/// retired in A2 / T-13b-3).
///
/// The minimum interval is clamped to 60 seconds.
#[allow(clippy::too_many_arguments)]
pub async fn run_periodic_push(
    db: Db,
    _swarm: Arc<SwarmHandle>,
    seed: Vec<u8>,
    master_key: ed25519_dalek::SigningKey,
    data_dir: PathBuf,
    interval_secs: u64,
    time_scale: u64,
    cancel: CancellationToken,
    mailbox_router: Arc<MailboxRouter>,
    my_master_pub: IdentityPub,
    current_pointer: Arc<Mutex<Option<SelfPointer>>>,
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

    // T-8: Mailbox republish tracking.
    // Seed from current_pointer so restart doesn't re-publish generation 0.
    // Structural key: (generation, base_block_id, diff_block_ids) — detects any pointer change.
    let (mut last_pointer_struct_key, mut last_publish_at) = {
        let guard = current_pointer.lock().expect("current_pointer lock");
        match guard.as_ref() {
            Some(p) => {
                let key = pointer_struct_key(p);
                let ts = p.created_at.0;
                (Some(key), ts)
            }
            None => (None, 0u64),
        }
    };

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
                            // Bug-G / T-10 rotation ordering: retire the old base and diffs
                            // *before* publishing the new pointer. This is safe because:
                            //   1. The old SelfPointer is still live in mailboxes (5y TTL) and
                            //      points to the old block's HolderHints — DR can still fetch
                            //      from those holders (retire only removes local metadata, not
                            //      the remote holders' stored symbols).
                            //   2. The new pointer is only published once `build_pointer_for_placed`
                            //      returns Some (guarded below) — so we never publish a pointer
                            //      that references an unplaced block.
                            // No DropNotice is sent here — old holders keep their symbols until
                            // the scheduled holder_cleanup pass (T-7).
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

        // 3+4. Build pointer (placed-prefix guard) and conditionally publish via mailbox.
        let now_secs = Timestamp::now().0;
        let (new_key, new_publish_at) = publish_pointer_step(
            &db,
            &mailbox_router,
            &master_key,
            &my_master_pub,
            &current_pointer,
            generation,
            &base,
            &diff_ids,
            last_pointer_struct_key.as_ref(),
            last_publish_at,
            now_secs,
            time_scale,
        )
        .await;
        last_pointer_struct_key = new_key;
        last_publish_at = new_publish_at;
    }

    Ok(())
}

/// Rebuild the base (and discard accumulated diffs) once this many diff blocks
/// pile up — keeps DR's apply chain short and bounds retained-blob count.
const DIFF_COMPACTION_THRESHOLD: usize = 20;

/// Structural key type for pointer change-detection.
///
/// Tuple of (generation, base_block_id_bytes, diff_block_id_bytes_vec).
/// Created_at and signature are excluded — only structural identity matters.
pub(crate) type PointerStructKey = (u32, [u8; 32], Vec<[u8; 32]>);

/// One periodic-push step: build the current pointer (placed-prefix guard), decide
/// whether to (re)publish, publish to own mailbox candidate-set, and update the
/// shared current_pointer + tracking state.
///
/// Returns the updated `(last_pointer_struct_key, last_publish_at)`. Pure of swarm.
///
/// If `build_pointer_for_placed` returns `None` (base not yet placed), the function
/// returns the inputs unchanged — the shared `current_pointer` is NOT touched.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_pointer_step(
    db: &Db,
    mailbox_router: &MailboxRouter,
    master_key: &ed25519_dalek::SigningKey,
    my_master_pub: &IdentityPub,
    current_pointer: &Arc<Mutex<Option<SelfPointer>>>,
    generation: u32,
    base_id: &SourceBlockId,
    diff_ids: &[SourceBlockId],
    last_key: Option<&PointerStructKey>,
    last_publish_at: u64,
    now_secs: u64,
    time_scale: u64,
) -> (Option<PointerStructKey>, u64) {
    // Build the self-pointer over the PLACED prefix of base + diffs.
    // If the base has not been placed yet, skip this tick.
    let pointer = match publish::build_pointer_for_placed(
        db,
        master_key,
        generation,
        base_id,
        diff_ids,
        Timestamp::now(),
    ) {
        Ok(Some(p)) => p,
        Ok(None) => {
            debug!("system_state push: base not placed yet, skipping pointer");
            return (last_key.cloned(), last_publish_at);
        }
        Err(e) => {
            error!(error = %e, "system_state push: build_pointer failed");
            return (last_key.cloned(), last_publish_at);
        }
    };

    // Republish decision: structural change OR 30-day refresh.
    if !should_republish(&pointer, last_key, last_publish_at, now_secs) {
        debug!(
            generation,
            base = %base_id,
            "system_state push: pointer unchanged and within 30d window — skipping mailbox publish"
        );
        return (last_key.cloned(), last_publish_at);
    }

    let blob = to_cbor_bytes(&pointer);
    let expires_at = now_secs
        + viaticum_core::mailbox::scaled_ttl_secs(
            class_config::SELF_POINTER_TTL.as_secs(),
            time_scale,
        );

    let mut msg_id = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut msg_id);

    let entry = MailboxEntry {
        target: *my_master_pub,
        msg_id,
        class: MailboxClass::SelfPointer,
        payload_version: 1,
        payload: blob.clone(),
        expires_at,
        stored_at: now_secs,
        sender: Some(*my_master_pub),
    };

    match mailbox_router.publish(my_master_pub, entry).await {
        Ok(0) => {
            warn!(
                generation,
                base = %base_id,
                "system_state push: SelfPointer mailbox publish got 0 acks — will retry on next tick"
            );
            // Do NOT update last_publish_at or current_pointer: retry on next changed/refresh tick.
            (last_key.cloned(), last_publish_at)
        }
        Ok(ack_count) => {
            let new_key = pointer_struct_key(&pointer);
            {
                let mut guard = current_pointer.lock().expect("current_pointer lock");
                *guard = Some(pointer.clone());
            }
            info!(
                generation,
                base = %base_id,
                diffs = pointer.diffs.len(),
                pointer_bytes = blob.len(),
                base_holders = pointer.base.holders.len(),
                ack_count,
                "system_state push: SelfPointer published via mailbox"
            );
            (Some(new_key), now_secs)
        }
        Err(e) => {
            error!(
                generation,
                base = %base_id,
                error = %e,
                "system_state push: mailbox publish failed"
            );
            (last_key.cloned(), last_publish_at)
        }
    }
}

/// Structural identity of a SelfPointer for republish-change detection.
///
/// We compare (generation, base.block_id, diff block_ids). Holder lists are NOT
/// part of the key: they change as placement progresses but the pointer is still
/// the "same" logical pointer. Created_at is also excluded (it's a timestamp, not
/// structural identity). A change in generation, base_id, or diff_ids means we
/// must republish.
pub(crate) fn pointer_struct_key(p: &SelfPointer) -> (u32, [u8; 32], Vec<[u8; 32]>) {
    let diff_keys: Vec<[u8; 32]> = p.diffs.iter().map(|d| d.block_id.0).collect();
    (p.generation, p.base.block_id.0, diff_keys)
}

/// Republish decision: should we publish the pointer now?
///
/// Returns `true` when:
///   (a) structural change — generation, base_block_id, or diff_block_ids changed, OR
///   (b) 30-day refresh — `MAILBOX_POINTER_REPUBLISH_SECS` elapsed since last publish.
#[allow(clippy::type_complexity)]
pub(crate) fn should_republish(
    pointer: &SelfPointer,
    last_struct_key: Option<&(u32, [u8; 32], Vec<[u8; 32]>)>,
    last_publish_at: u64,
    now_secs: u64,
) -> bool {
    let current_key = pointer_struct_key(pointer);
    let changed = last_struct_key != Some(&current_key);
    let refresh_due = now_secs.saturating_sub(last_publish_at) >= MAILBOX_POINTER_REPUBLISH_SECS;
    changed || refresh_due
}
