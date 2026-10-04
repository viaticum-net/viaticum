// The work of one block in an issue tick: load the source, re-encode it once and compute
// every holder's expected chain hash (pos-i7), then the signed entry of each challenge,
// stamped at its publish (pos-i7-a).
//
// СТ-0c round 4: the whole preparation — its database reads, the source file reads and
// the encode — runs as ONE blocking task that the tick awaits with a deadline. No part of
// it runs on the async thread, so a preparation held up by the disk or the database
// cannot hold the tick past its budget: at the deadline the tick stops waiting for it and
// hands the task over to `Preparing` (pos-i7-d-a), which the run loop drains.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;
use tracing::{debug, error, warn};
use viaticum_core::db::Db;
use viaticum_core::erasure::ErasureEncoder;
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::messages::to_cbor;
use viaticum_core::types::{DeviceId, IdentityPub, SourceBlockId, SymbolPlacement, Timestamp};

use super::super::{PendingHashChallenge, Scheduler, random_challenge_id};

/// The WARN "cannot load source block for PoS" is written at most once per this long per
/// block (backup-i7): 86 400 s of the monotonic clock, not scaled by `time_scale`.
pub(crate) const POS_LOAD_WARN_INTERVAL: Duration = Duration::from_secs(86_400);

/// Whether the load failure of `block` at `now` is written as a WARN: the first one, and
/// then one per [`POS_LOAD_WARN_INTERVAL`]; the rest are DEBUG. Records the time of a
/// WARN in `map` and drops the entries that have run out. Pure: the clock is injected.
pub(crate) fn should_warn(
    map: &mut HashMap<SourceBlockId, Instant>,
    block: SourceBlockId,
    now: Instant,
) -> bool {
    if let Some(last) = map.get(&block)
        && now.saturating_duration_since(*last) < POS_LOAD_WARN_INTERVAL
    {
        return false;
    }
    map.retain(|_, at| now.saturating_duration_since(*at) < POS_LOAD_WARN_INTERVAL);
    map.insert(block, now);
    true
}

/// backup-i7: a block whose source outgrew the size limit fails to load every tick; one
/// WARN per block per day, the rest DEBUG. The clock is injected.
pub(crate) fn log_load_failure(
    warned: &Mutex<HashMap<SourceBlockId, Instant>>,
    block_id: SourceBlockId,
    now: Instant,
    err: &anyhow::Error,
) {
    let loud = {
        let mut map = warned.lock().unwrap_or_else(|p| p.into_inner());
        should_warn(&mut map, block_id, now)
    };
    if loud {
        warn!(
            block_id = %block_id,
            err = %format!("{err:#}"),
            "scheduler: cannot load source block for PoS hash, skipping"
        );
    } else {
        debug!(
            block_id = %block_id,
            err = %format!("{err:#}"),
            "scheduler: cannot load source block for PoS hash, skipping"
        );
    }
}

/// One challenge of a block, its expected answer computed.
pub(crate) struct PreparedChallenge {
    pub(super) holder_id: DeviceId,
    challenge_id: [u8; 16],
    expected_chain_hash: [u8; 32],
    /// The ranges the expected hash covers: a publish is valid only for a placement that
    /// still holds exactly these.
    pub(super) esi_ranges: Vec<(u32, u32)>,
    /// The master box the challenge is published to (every device of that master reads
    /// it; `holder_id` inside the signed challenge names the addressee).
    holder_master: IdentityPub,
}

/// Everything one block's preparation needs, owned, for the blocking task.
struct BlockPrep {
    db: Db,
    data_dir: PathBuf,
    epoch_key: [u8; 32],
    rebuild_scope: crate::daemon::backup::rebuild::RebuildScope,
    /// Shared with the scheduler: the last WARN of a load failure per block.
    load_warned: Arc<Mutex<HashMap<SourceBlockId, Instant>>>,
    encoder: Arc<dyn ErasureEncoder>,
    block_id: SourceBlockId,
    holders: Vec<HolderPrep>,
}

/// One holder of the block: its own ESI ranges and its challenge id.
struct HolderPrep {
    holder_id: DeviceId,
    esi_ranges: Vec<(u32, u32)>,
    challenge_id: [u8; 16],
}

impl Scheduler {
    /// Start one block's preparation on the blocking pool (pos-i7: the honest cost, 1×
    /// per block per start). The result is empty when the block cannot be served (logged).
    /// The tick that spawned it waits only until its deadline; the handle then moves to
    /// `Preparing` (pos-i7-d-a), so the task is never abandoned.
    pub(super) fn spawn_prepare(
        &self,
        block_id: SourceBlockId,
        holder_placements: &[&SymbolPlacement],
    ) -> JoinHandle<Vec<PreparedChallenge>> {
        // Generate challenge_ids BEFORE the blocking task so the OsRng nonce is committed
        // before compute_chain_hash runs. This binds expected_hash to this challenge_id.
        let holders = holder_placements
            .iter()
            .map(|p| HolderPrep {
                holder_id: p.holder_id,
                esi_ranges: p.esi_ranges.clone(),
                challenge_id: random_challenge_id(),
            })
            .collect();
        let prep = BlockPrep {
            db: self.db.clone(),
            data_dir: self.data_dir.clone(),
            epoch_key: self.epoch_key,
            rebuild_scope: self.rebuild_scope.clone(),
            load_warned: Arc::clone(&self.pos_load_warned),
            encoder: Arc::clone(&self.encoder),
            block_id,
            holders,
        };
        tokio::task::spawn_blocking(move || prep.run())
    }

    /// The signed mailbox entry of one challenge and its pending record, both stamped
    /// with the time of this call — the moment the challenge is published (pos-i7-a).
    /// None when the challenge cannot be encoded (logged). No database access.
    pub(super) fn challenge_entry(
        &self,
        block_id: SourceBlockId,
        c: PreparedChallenge,
    ) -> Option<(MailboxEntry, PendingHashChallenge)> {
        let now = Timestamp::now();
        // CS-ID-5 / P1-2: sign the challenge with our master key so the holder can
        // authenticate it against MailboxEntry.sender before doing any disk work.
        // pos-i15: addressed to the placement's device; the holder's siblings reading
        // the same master box do not answer it.
        let challenge_msg = viaticum_core::messages::build_pos_hash_challenge(
            c.challenge_id,
            block_id,
            c.esi_ranges.clone(),
            now,
            c.holder_id,
            &self.signing_key,
        );
        let payload = match to_cbor(&challenge_msg) {
            Ok(p) => p,
            Err(e) => {
                error!(
                    block_id = %block_id,
                    holder_id = %c.holder_id,
                    err = %e,
                    "scheduler: failed to encode PosHashChallenge"
                );
                return None;
            }
        };

        let ttl_secs = viaticum_core::mailbox::scaled_ttl_secs(
            viaticum_core::mailbox::class_config::POS_CHALLENGE_TTL.as_secs(),
            self.config.time_scale,
        );
        let entry = MailboxEntry {
            target: MailboxAddress::for_master(&c.holder_master),
            msg_id: c.challenge_id,
            class: MailboxClass::PosChallenge,
            payload_version: 1,
            payload,
            expires_at: now.0 + ttl_secs,
            stored_at: now.0,
            // W-3: sender is our master_pub so holder knows where to publish the response.
            sender: Some(self.my_master_pub),
        };
        // pos-i16: the response is verified against `holder_id` (the device key), so the
        // pending record does not need the master the mailbox entry was addressed to.
        let challenge = PendingHashChallenge {
            source_block_id: block_id,
            holder_id: c.holder_id,
            esi_ranges: c.esi_ranges,
            expected_chain_hash: c.expected_chain_hash,
            issued_at: now,
            challenge_id: c.challenge_id,
        };
        Some((entry, challenge))
    }
}

impl BlockPrep {
    /// Load, encode once, and hash per holder. Blocking; runs on the blocking pool.
    fn run(self) -> Vec<PreparedChallenge> {
        let block_id = self.block_id;
        if self.holders.is_empty() {
            return Vec::new();
        }

        // Load source block data (retained SS blob, else rebuild from source files).
        let source_data = match load_source_block(
            &self.db,
            &self.data_dir,
            &self.epoch_key,
            &self.rebuild_scope,
            &block_id,
        ) {
            Ok(d) => d,
            Err(e) => {
                log_load_failure(&self.load_warned, block_id, Instant::now(), &e);
                return Vec::new();
            }
        };

        let block_record = match self.db.get_source_block(&block_id) {
            Ok(Some(r)) => r,
            _ => {
                warn!(block_id = %block_id, "scheduler: source block record missing, skipping");
                return Vec::new();
            }
        };
        let params = block_record.erasure_params();

        // Union of all holders' ESI ranges for this block: sorted, deduplicated, merged
        // (a placement may hold several ranges — own range + fresh numbers, repair-i9).
        let mut all_esis: Vec<u32> = self
            .holders
            .iter()
            .flat_map(|h| viaticum_core::types::ranges_to_esi_list(&h.esi_ranges))
            .collect();
        all_esis.sort_unstable();
        all_esis.dedup();
        let all_esi_ranges = viaticum_core::types::esi_list_to_ranges(&all_esis);

        // Encode raw symbols for the union of all holders' ESI ranges — one encoder build
        // for every range.
        let mut raw_symbols: HashMap<u32, Vec<u8>> = HashMap::new();
        match self
            .encoder
            .encode_raw_ranges(&source_data, &params, &all_esi_ranges)
        {
            Ok(syms) => {
                for sym in syms {
                    raw_symbols.insert(sym.esi, sym.data);
                }
            }
            Err(e) => {
                error!(block_id = %block_id, "scheduler: encode_raw failed: {e}");
                return Vec::new();
            }
        }

        // Per-holder: apply binding, compute chain hash.
        let mut results = Vec::new();
        for HolderPrep {
            holder_id,
            esi_ranges,
            challenge_id,
        } in self.holders
        {
            // Expand the holder's OWN ranges to a sorted ESI list.
            // Saturating end (CS-ERA-6): the worker keeps every range below 2^24.
            let mut esis: Vec<u32> = viaticum_core::types::ranges_to_esi_list(&esi_ranges);
            esis.sort_unstable();

            // Apply binding keystream and collect bound symbols.
            let bound_pairs: Vec<(u32, Vec<u8>)> = esis
                .iter()
                .filter_map(|&esi| {
                    raw_symbols.get(&esi).map(|raw_data| {
                        let mut data = raw_data.clone();
                        let ks = viaticum_core::erasure::binding_keystream(
                            &block_id,
                            &holder_id,
                            esi,
                            data.len(),
                        );
                        for (d, k) in data.iter_mut().zip(ks.iter()) {
                            *d ^= k;
                        }
                        (esi, data)
                    })
                })
                .collect();

            let refs: Vec<(u32, &[u8])> = bound_pairs
                .iter()
                .map(|(esi, data)| (*esi, data.as_slice()))
                .collect();

            // Seeded with the challenge_id generated before this task (see spawn_prepare).
            match viaticum_core::pos::compute_chain_hash(&challenge_id, &refs) {
                Ok(expected_chain_hash) => {
                    let holder_master = self
                        .db
                        .get_master_for_device(&holder_id)
                        .ok()
                        .flatten()
                        .map(|m| IdentityPub(m.0))
                        .unwrap_or_else(|| IdentityPub(holder_id.0));
                    results.push(PreparedChallenge {
                        holder_id,
                        challenge_id,
                        expected_chain_hash,
                        esi_ranges,
                        holder_master,
                    });
                }
                Err(e) => {
                    error!(
                        holder = %holder_id,
                        block_id = %block_id,
                        "scheduler: chain hash failed: {e}"
                    );
                }
            }
        }
        results
    }
}

/// Load source block data for PoS challenge computation. Blocking.
///
/// Resolution order (2-tier, post-Wave-11b):
///   1. SystemState retained blob (`<data_dir>/system_state/<hex>.bin`) — SS blocks
///      have no backing watch-dir file; the owner retains the blob for PoS re-encode.
///      Corruption is propagated loudly; absence falls through.
///   2. Rebuild from the owner's source files via `rebuild_blob_blocking`, sealed at the
///      record's `seal_generation` (the worker rebuilds through the same function).
///
/// PL-6: the old on-disk `{source_blocks_dir}/{block_hex}/block.bin` middle tier was
/// removed. Wave 11b never writes `block.bin` (the symbol pipeline persists nothing
/// to disk), so that read was always NotFound and always fell through to the rebuild
/// path below — a dead tier.
fn load_source_block(
    db: &Db,
    data_dir: &std::path::Path,
    epoch_key: &[u8; 32],
    scope: &crate::daemon::backup::rebuild::RebuildScope,
    block_id: &SourceBlockId,
) -> anyhow::Result<Vec<u8>> {
    // SystemState blocks: serve the owner-retained blob (verified blake3 == block_id).
    if let Some(blob) =
        crate::daemon::system_state::block::try_load_retained_block(data_dir, block_id)?
    {
        return Ok(blob);
    }

    let block_record = db
        .get_source_block(block_id)?
        .ok_or_else(|| anyhow::anyhow!("source block record missing: {block_id}"))?;
    crate::daemon::backup::pipeline::rebuild_blob_blocking(db, &block_record, epoch_key, scope)
}
