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
use viaticum_core::constants::MAILBOX_POINTER_REPUBLISH_SECS;
use viaticum_core::db::Db;
use viaticum_core::mailbox::seal::RendezvousKeys;
use viaticum_core::system_state::catalog::live_file_count;
use viaticum_core::system_state::{
    SystemState, diff_states, pack_system_state, restore_db, snapshot_db,
};
// Re-exported so tests (and callers) can check the current format version.
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
pub use viaticum_core::system_state::SYSTEM_STATE_VERSION;
use viaticum_core::types::{DeviceId, SourceBlockId, Timestamp};

use crate::daemon::mailbox::routing::{MailboxRouter, PublishVerdict};
use crate::daemon::network::swarm::SwarmHandle;

pub mod block;
mod pointer;
pub mod publish;
pub(crate) mod strength;

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
/// the slot of one of the history's two pointer places, store signature by the box
/// key), class=SelfPointer, TTL = 5 years / time_scale. Which place, when to seal a new
/// envelope, re-offers and retirement of displaced bases: `pointer::PointerPublisher`
/// (state in META, survives restarts). On start every SS block outside META is retired.
///
/// Block publishing pipeline is unchanged: the base/diff blocks are placed via the
/// existing publish_base_block / publish_diff_block path.
///
/// The daemon never reads its own pointer box (РС3.1): only DR does
/// (`mailbox_router.dr_collect_pointers`). A restart builds a new base; it goes to the
/// weaker of the two places.
///
/// Catalog history (spec B2): every pointer carries this DB's history id (minted here on
/// first use, never inherited), the publishing device (`publisher` = this daemon's
/// device, so DR can move ownership of restored files to its own device, dr-i19) and
/// the live file count of the state it restores.
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
    publisher: DeviceId,
) -> anyhow::Result<()> {
    let clamped = interval_secs.max(60);
    let dr_key = identity_key_bytes_from_seed(&seed)?;
    let rv = RendezvousKeys::derive(&seed);
    let lineage = db.get_or_create_catalog_lineage().map_err(|e| {
        error!(error = %e, "system_state push: cannot read or mint the catalog history id");
        anyhow::anyhow!("catalog history id: {e}")
    })?;
    let publisher_ctx = pointer::PointerPublisher {
        db: &db,
        router: &mailbox_router,
        master_key: &master_key,
        rv: &rv,
        data_dir: &data_dir,
        time_scale,
    };
    // V.16.4 п.6: SS blocks of earlier processes that no pointer place refers to.
    publisher_ctx.startup_sweep();
    info!(
        interval_secs = clamped,
        "system_state periodic push (SS-as-block): started"
    );
    let period = Duration::from_secs(clamped);
    let mut ticker = tokio::time::interval(period);
    // A process stopped (SIGSTOP, suspend) owes no burst of missed pushes: one tick on
    // wake-up, then the period (a burst builds a diff per tick, mailbox-i62).
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
                            // The old base stays while a pointer place refers to it (it
                            // may be the strong one, dr-i48); its unpublished diffs and an
                            // unpublished base are retired by the sweep of this tick.
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

        // 3+4. The pointer of the running base into its place; re-offers; retirement.
        publisher_ctx
            .tick(
                pointer::RunningState {
                    generation,
                    base: &base,
                    diffs: &diff_ids,
                    catalog: publish::PointerCatalog {
                        lineage,
                        publisher,
                        files_after: &files_after,
                    },
                },
                Timestamp::now().0,
            )
            .await;
    }

    Ok(())
}

/// Rebuild the base (and discard accumulated diffs) once this many diff blocks
/// pile up — keeps DR's apply chain short and bounds retained-blob count.
const DIFF_COMPACTION_THRESHOLD: usize = 20;

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

/// The pointer refresh interval: 30 days / time_scale (`scaled_ttl_secs`), the same
/// division as the pointer TTL, so a live node's pointer never expires at any scale.
pub(crate) fn pointer_refresh_interval_secs(time_scale: u64) -> u64 {
    viaticum_core::mailbox::scaled_ttl_secs(MAILBOX_POINTER_REPUBLISH_SECS, time_scale)
}
