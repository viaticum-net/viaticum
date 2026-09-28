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
use viaticum_core::mailbox::class_config;
use viaticum_core::mailbox::seal::{PointerPlace, RendezvousKeys, seal_self_pointer};
use viaticum_core::system_state::catalog::{PointerPublication, live_file_count};
use viaticum_core::system_state::{
    SelfPointer, SystemState, diff_states, pack_system_state, restore_db, snapshot_db,
};
// Re-exported so tests (and callers) can check the current format version.
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
pub use viaticum_core::system_state::SYSTEM_STATE_VERSION;
use viaticum_core::types::{
    DeviceId, IdentityPub, SourceBlockId, Timestamp, hex_encode, to_cbor_bytes,
};

use crate::daemon::mailbox::routing::{MailboxRouter, PublishVerdict};
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
/// The SelfPointer is sealed with the seed-derived rendezvous keys and stored in the
/// permanent rendezvous box (CROWN-1 C3a: `RendezvousKeys::derive(seed)`, `msg_id` =
/// the history's pointer place slot, store signature by the box key), class=SelfPointer,
/// TTL = 5 years / time_scale. Republish policy:
///   - Publish when (a) the pointer structurally changed (generation or block_ids differ), OR
///   - (b) the refresh interval elapsed (`MAILBOX_POINTER_REPUBLISH_SECS / time_scale`).
///   - Skip otherwise.
///
/// Block publishing pipeline is unchanged: the base/diff blocks are placed via the
/// existing publish_base_block / publish_diff_block path.
///
/// The daemon never reads its own pointer box (РС3.1): only DR does
/// (`mailbox_router.dr_collect_pointers`). A restart builds a new base and publishes it.
/// `_current_pointer` is unused since C3a; it goes with the handle wiring.
///
/// Catalog history (spec B2): every pointer carries this DB's history id (minted here on
/// first use, never inherited), the publishing device (`publisher` = this daemon's
/// device, so DR can move ownership of restored files to its own device, dr-i19) and
/// the live file count of the state it restores. A publication accepted by ≥ 1 postman
/// is recorded in the DB (`Db::record_pointer_publication`, dr-i9: `status` shows DR
/// readiness from it).
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
    _my_master_pub: IdentityPub,
    publisher: DeviceId,
    _current_pointer: Arc<Mutex<Option<SelfPointer>>>,
) -> anyhow::Result<()> {
    let clamped = interval_secs.max(60);
    let dr_key = identity_key_bytes_from_seed(&seed)?;
    let rv = RendezvousKeys::derive(&seed);
    let lineage = db.get_or_create_catalog_lineage().map_err(|e| {
        error!(error = %e, "system_state push: cannot read or mint the catalog history id");
        anyhow::anyhow!("catalog history id: {e}")
    })?;
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
    // Live file count after the base and after each diff (len == diff_ids.len() + 1
    // once a base exists): the pointer's catalog.files for any listed prefix.
    let mut files_after: Vec<u32> = Vec::new();

    // Republish tracking. Structural key: (generation, base_block_id, diff_block_ids).
    // A restart starts empty: the new base is published (РС3.1: no pointer re-learning).
    let mut last_pointer_struct_key: Option<PointerStructKey> = None;
    let mut last_publish_at = 0u64;

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
                    files_after = vec![live_file_count(&state.files)];
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
                            files_after = vec![live_file_count(&state.files)];
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
                            files_after.push(live_file_count(&state.files));
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
            &rv,
            generation,
            &base,
            &diff_ids,
            publish::PointerCatalog {
                lineage,
                publisher,
                files_after: &files_after,
            },
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
/// whether to (re)publish, seal it into the rendezvous box and publish it.
///
/// Returns the updated `(last_pointer_struct_key, last_publish_at)`. Pure of swarm.
/// If `build_pointer_for_placed` returns `None` (base not yet placed), the function
/// returns the inputs unchanged.
///
/// dr-i9: a publication acked by ≥ 1 postman is recorded in the DB
/// (`record_pointer_publication`); a refusal or 0 acks record nothing and are logged
/// by verdict (V.3).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_pointer_step(
    db: &Db,
    mailbox_router: &MailboxRouter,
    master_key: &ed25519_dalek::SigningKey,
    rv: &RendezvousKeys,
    generation: u32,
    base_id: &SourceBlockId,
    diff_ids: &[SourceBlockId],
    catalog: publish::PointerCatalog<'_>,
    last_key: Option<&PointerStructKey>,
    last_publish_at: u64,
    now_secs: u64,
    time_scale: u64,
) -> (Option<PointerStructKey>, u64) {
    let unchanged = (last_key.cloned(), last_publish_at);
    let pointer = match publish::build_pointer_for_placed(
        db,
        master_key,
        generation,
        base_id,
        diff_ids,
        Timestamp(now_secs),
        catalog,
    ) {
        Ok(Some(p)) => p,
        Ok(None) => {
            debug!("system_state push: base not placed yet, skipping pointer");
            return unchanged;
        }
        Err(e) => {
            error!(error = %e, "system_state push: build_pointer failed");
            return unchanged;
        }
    };

    if !should_republish(&pointer, last_key, last_publish_at, now_secs, time_scale) {
        debug!(
            generation,
            base = %base_id,
            "system_state push: pointer unchanged within the refresh interval — skipping mailbox publish"
        );
        return unchanged;
    }

    let blob = to_cbor_bytes(&pointer);
    let expires_at = now_secs
        + viaticum_core::mailbox::scaled_ttl_secs(
            class_config::SELF_POINTER_TTL.as_secs(),
            time_scale,
        );
    let place = PointerPlace::A;
    let sealed = match seal_self_pointer(
        rv,
        &pointer.catalog.lineage.0,
        place,
        &blob,
        expires_at,
        now_secs,
    ) {
        Ok(s) => s,
        Err(e) => {
            // Impossible by construction (≤ 5 holders, ≤ 4 short addresses, ≤ 20 diffs);
            // skip the tick rather than publish anything else.
            error!(error = %e, pointer_bytes = blob.len(), "system_state push: cannot seal the pointer");
            return unchanged;
        }
    };

    let outcome = mailbox_router
        .publish_detailed(sealed.entry().clone(), sealed.target_sig())
        .await;
    match outcome.verdict() {
        PublishVerdict::Stored { acks } => {
            debug!(
                address = %hex_encode(&rv.address.0),
                slot = %hex_encode(&sealed.entry().msg_id),
                "system_state push: pointer box"
            );
            info!(
                generation,
                base = %base_id,
                diffs = pointer.diffs.len(),
                pointer_bytes = blob.len(),
                base_holders = pointer.base.holders.len(),
                ack_count = acks,
                catalog_files = pointer.catalog.files,
                lineage = %pointer.catalog.lineage,
                place = ?place,
                "system_state push: SelfPointer published via mailbox"
            );
            // dr-i9: status reports DR readiness from this record, never from a pointer
            // that no postman accepted.
            let publication = PointerPublication {
                lineage: pointer.catalog.lineage,
                created_at: pointer.created_at,
                generation: pointer.generation,
                files: pointer.catalog.files,
                acks: acks.try_into().unwrap_or(u32::MAX),
            };
            if let Err(e) = db.record_pointer_publication(&publication) {
                warn!(error = %e, "system_state push: cannot record the pointer publication");
            }
            (Some(pointer_struct_key(&pointer)), now_secs)
        }
        verdict => {
            log_refusal(verdict, generation, base_id);
            unchanged
        }
    }
}

/// The publisher's line for a publication no postman acked (V.3, V.15.3).
pub(crate) fn log_refusal(verdict: PublishVerdict, generation: u32, base_id: &SourceBlockId) {
    match verdict {
        PublishVerdict::Stored { .. } => {}
        PublishVerdict::AllClockSkew => warn!(
            generation,
            base = %base_id,
            "system_state push: every postman refused the pointer as clock skew — check the system clock"
        ),
        PublishVerdict::AllSuperseded => warn!(
            generation,
            base = %base_id,
            "system_state push: every postman holds an equal-time or newer pointer of this place — the system clock went back"
        ),
        PublishVerdict::AllSlotsFull => warn!(
            generation,
            base = %base_id,
            "system_state push: every postman refused a new pointer place — this recovery phrase has no free place left at friends"
        ),
        PublishVerdict::MixedRefusal {
            clock,
            superseded,
            slots_full,
            other,
        } => warn!(
            generation,
            base = %base_id,
            clock,
            superseded,
            slots_full,
            other,
            "system_state push: postmen refused the pointer for different reasons"
        ),
        PublishVerdict::NoAck => warn!(
            generation,
            base = %base_id,
            "system_state push: SelfPointer mailbox publish got 0 acks — will retry on next tick"
        ),
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
///   (b) refresh — `pointer_refresh_interval_secs(time_scale)` elapsed since the last
///       publication (AC-24′, mailbox-i41: every cadence scales, TTL / refresh = 60).
pub(crate) fn should_republish(
    pointer: &SelfPointer,
    last_struct_key: Option<&PointerStructKey>,
    last_publish_at: u64,
    now_secs: u64,
    time_scale: u64,
) -> bool {
    let current_key = pointer_struct_key(pointer);
    let changed = last_struct_key != Some(&current_key);
    let refresh_due =
        now_secs.saturating_sub(last_publish_at) >= pointer_refresh_interval_secs(time_scale);
    changed || refresh_due
}

/// The pointer refresh interval: 30 days / time_scale (`scaled_ttl_secs`), the same
/// division as the pointer TTL, so a live node's pointer never expires at any scale.
pub(crate) fn pointer_refresh_interval_secs(time_scale: u64) -> u64 {
    viaticum_core::mailbox::scaled_ttl_secs(MAILBOX_POINTER_REPUBLISH_SECS, time_scale)
}
