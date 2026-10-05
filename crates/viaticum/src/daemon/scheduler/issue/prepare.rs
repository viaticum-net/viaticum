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
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;
use tracing::{debug, error, warn};
use viaticum_core::db::Db;
use viaticum_core::erasure::ErasureEncoder;
use viaticum_core::mailbox::{MailboxAddress, MailboxClass, MailboxEntry};
use viaticum_core::messages::to_cbor;
use viaticum_core::pos::PosError;
use viaticum_core::types::{
    DeviceId, ErasureParams, IdentityPub, SourceBlockId, SymbolPlacement, Timestamp,
};

use super::super::{PendingHashChallenge, Scheduler, random_challenge_id, scaled_timer_secs};
use super::fold::{self, FoldHolder};
use crate::daemon::mem_budget::{
    HolderKind, MemBudget, MemPermit, WriteOffHandle, estimate_pos_issue,
};

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
    should_warn_every(map, block, now, POS_LOAD_WARN_INTERVAL)
}

/// [`should_warn`] for any key and period: the first call for `key` and then one per
/// `interval` return true (dr-i8: one WARN per holder per PoS period).
pub(crate) fn should_warn_every<K: std::hash::Hash + Eq>(
    map: &mut HashMap<K, Instant>,
    key: K,
    now: Instant,
    interval: Duration,
) -> bool {
    if let Some(last) = map.get(&key)
        && now.saturating_duration_since(*last) < interval
    {
        return false;
    }
    map.retain(|_, at| now.saturating_duration_since(*at) < interval);
    map.insert(key, now);
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
    /// The key the challenge is addressed to, resolved during the preparation (CS-POS-3:
    /// the response is verified against this same key).
    holder_master: IdentityPub,
}

/// How a block's preparation ended (R1-d-b).
pub(crate) enum PrepOutcome {
    /// The challenges to publish (possibly none: every hash failed).
    Prepared(Vec<PreparedChallenge>),
    /// The memory budget was busy at `try_acquire`: nothing was loaded, nothing held. The block
    /// is deferred; from the next tick it waits for memory as an overdue one (pos-i13).
    Deferred,
    /// The block cannot be served now (logged): no record, sources missing or over the limit,
    /// load or encode failed, no holders.
    Unserved,
}

/// Where a preparation is, for the stuck-preparation WARN and the write-off (pos-i7-d-b,
/// pos-i7-d-d). Only `Load` is written off: a read that hangs is not CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrepPhase {
    /// No permit yet (the record read, the precheck, the `try_acquire`).
    Start = 0,
    /// Holding the permit; the sources' `metadata` (a batch member) and loading the source block
    /// (database, source files, seal).
    Load = 1,
    /// Holding the permit; padding and encoding, hashing while it goes.
    Encode = 2,
}

impl PrepPhase {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            PrepPhase::Start => "start",
            PrepPhase::Load => "load",
            PrepPhase::Encode => "encode",
        }
    }
}

/// What the preparation task and the run loop both see of it: its phase, the handle that can
/// write its permit off, and when it started (for a preparation a tick started: that tick's
/// moment; for an overdue one: when its memory was granted — not while it waited, NOTE 6).
pub(crate) struct PrepShared {
    phase: AtomicU8,
    handle: Mutex<Option<WriteOffHandle>>,
    started: Mutex<Option<tokio::time::Instant>>,
    /// Whether this preparation holds the one place of "a batch in flight" (spec v3.7, WARN-1):
    /// set at its start, cleared by its write-off. A batch that is written off no longer stops
    /// the next one from forming.
    counts_in_flight: AtomicBool,
}

impl PrepShared {
    pub(super) fn new(started: Option<tokio::time::Instant>) -> Arc<Self> {
        Arc::new(PrepShared {
            phase: AtomicU8::new(PrepPhase::Start as u8),
            handle: Mutex::new(None),
            started: Mutex::new(started),
            counts_in_flight: AtomicBool::new(true),
        })
    }

    /// Whether the preparation still holds its place in flight (false after a write-off).
    pub(super) fn counts_in_flight(&self) -> bool {
        self.counts_in_flight.load(Ordering::SeqCst)
    }

    pub(super) fn set_started(&self, at: tokio::time::Instant) {
        *self.started.lock().unwrap_or_else(|p| p.into_inner()) = Some(at);
    }

    /// `None` while the preparation waits for memory.
    pub(super) fn started(&self) -> Option<tokio::time::Instant> {
        *self.started.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn phase(&self) -> PrepPhase {
        match self.phase.load(Ordering::SeqCst) {
            1 => PrepPhase::Load,
            2 => PrepPhase::Encode,
            _ => PrepPhase::Start,
        }
    }

    fn set_phase(&self, phase: PrepPhase) {
        self.phase.store(phase as u8, Ordering::SeqCst);
    }

    /// The permit is held: it can be written off from now.
    pub(super) fn hold(&self, permit: &mut MemPermit) {
        *self.handle.lock().unwrap_or_else(|p| p.into_inner()) = Some(permit.write_off_handle());
    }

    /// MiB the permit holds (0 before it is taken).
    pub(super) fn holds_bytes(&self) -> u64 {
        self.handle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map_or(0, WriteOffHandle::bytes)
    }

    /// Write the permit off (pos-i7-d-d): bytes given back, `None` if there is nothing to write
    /// off or another holder is already written off.
    pub(super) fn write_off(&self, budget: &MemBudget) -> Option<u64> {
        let guard = self.handle.lock().unwrap_or_else(|p| p.into_inner());
        let bytes = budget.write_off(guard.as_ref()?)?;
        // A written-off preparation does not count as in flight any more (WARN-1).
        self.counts_in_flight.store(false, Ordering::SeqCst);
        Some(bytes)
    }

    /// Back to "no permit work": between the members of a batch.
    pub(super) fn rest(&self) {
        self.set_phase(PrepPhase::Start);
    }
}

/// How long a block whose last load failed stays out of the overdue queue (NOTE 7): a changed or
/// missing source (`SourceMissing`, a rebuilt blob that is not the block, backup-i7) does not heal
/// by itself, so it waits as long as its WARN; another failure (I/O, database) is tried again
/// after one tick period.
pub(crate) fn load_failed_until(err: &anyhow::Error, now: Instant, period: Duration) -> Instant {
    use crate::daemon::backup::pipeline::BlobHashMismatch;
    use crate::daemon::backup::rebuild::RebuildError;
    let lasting = err.chain().any(|cause| {
        cause.downcast_ref::<BlobHashMismatch>().is_some()
            || matches!(
                cause.downcast_ref::<RebuildError>(),
                Some(RebuildError::SourceMissing { .. })
            )
    });
    now + if lasting {
        POS_LOAD_WARN_INTERVAL
    } else {
        period
    }
}

/// `f` for the blocking pool, run under the tracing dispatch current where this is called: a
/// blocking thread has none of its own, and the preparation's lines (the deferral, the permit
/// grants) belong to the daemon's log like the async side's.
pub(super) fn with_current_dispatch<R>(
    f: impl FnOnce() -> R + Send + 'static,
) -> impl FnOnce() -> R + Send + 'static {
    let dispatch = tracing::dispatcher::get_default(|d| d.clone());
    move || tracing::dispatcher::with_default(&dispatch, f)
}

/// Everything one block's preparation needs, owned, for the blocking task.
pub(super) struct BlockPrep {
    db: Db,
    data_dir: PathBuf,
    epoch_key: [u8; 32],
    rebuild_scope: crate::daemon::backup::rebuild::RebuildScope,
    /// Shared with the scheduler: the last WARN of a load failure per block.
    load_warned: Arc<Mutex<HashMap<SourceBlockId, Instant>>>,
    /// Shared with the scheduler: until when a block whose load failed stays out of the overdue
    /// queue (`load_failed_until`); cleared by a load that succeeds.
    load_failed: Arc<Mutex<HashMap<SourceBlockId, Instant>>>,
    /// How long a failure that may pass by itself (I/O) keeps the block out: one tick period.
    retry_after: Duration,
    encoder: Arc<dyn ErasureEncoder>,
    budget: Arc<MemBudget>,
    block_id: SourceBlockId,
    holders: Vec<FoldHolder>,
    pub(super) state: Arc<PrepShared>,
    /// Runs just before a holder's master is looked up (tests: the permit must be gone).
    #[cfg(test)]
    master_lookup_hook: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Runs at the start of a batch member's sources check (tests: a `metadata` that hangs).
    #[cfg(test)]
    precheck_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl Scheduler {
    /// One block's preparation, owned. `started` is the moment a tick starts it; `None` for an
    /// overdue one, which starts when its memory is granted.
    pub(super) fn make_prep(
        &self,
        block_id: SourceBlockId,
        holder_placements: &[&SymbolPlacement],
        started: Option<tokio::time::Instant>,
    ) -> BlockPrep {
        // Generate challenge_ids BEFORE the blocking task so the OsRng nonce is committed
        // before compute_chain_hash runs. This binds expected_hash to this challenge_id.
        let holders = holder_placements
            .iter()
            .map(|p| FoldHolder {
                holder_id: p.holder_id,
                esi_ranges: p.esi_ranges.clone(),
                challenge_id: random_challenge_id(),
            })
            .collect();
        BlockPrep {
            db: self.db.clone(),
            data_dir: self.data_dir.clone(),
            epoch_key: self.epoch_key,
            rebuild_scope: self.rebuild_scope.clone(),
            load_warned: Arc::clone(&self.pos_load_warned),
            load_failed: Arc::clone(&self.load_failed),
            retry_after: Duration::from_secs(scaled_timer_secs(
                self.config.pos_interval_secs,
                self.config.time_scale,
            )),
            encoder: Arc::clone(&self.encoder),
            budget: Arc::clone(&self.mem_budget),
            block_id,
            holders,
            state: PrepShared::new(started),
            #[cfg(test)]
            master_lookup_hook: self
                .master_lookup_hook
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
            #[cfg(test)]
            precheck_hook: self
                .precheck_hook
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
        }
    }

    /// Start one block's preparation on the blocking pool (pos-i7: the honest cost, 1×
    /// per block per start). The tick that spawned it waits only until its deadline; the
    /// handle then moves to `Preparing` (pos-i7-d-a), so the task is never abandoned. It takes
    /// its memory permit itself, by `try_acquire` (R1-d-b): a busy budget ends it `Deferred`.
    pub(in crate::daemon::scheduler) fn spawn_prepare(
        &self,
        block_id: SourceBlockId,
        holder_placements: &[&SymbolPlacement],
    ) -> (JoinHandle<PrepOutcome>, Arc<PrepShared>) {
        let prep = self.make_prep(
            block_id,
            holder_placements,
            Some(tokio::time::Instant::now()),
        );
        let shared = Arc::clone(&prep.state);
        (
            tokio::task::spawn_blocking(with_current_dispatch(move || prep.run())),
            shared,
        )
    }

    /// Whether `block` failed to load and is still out of the overdue batches at `now`; the
    /// entries that ran out are dropped.
    pub(super) fn load_failed_now(&self, block: &SourceBlockId, now: Instant) -> bool {
        let mut map = self.load_failed.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, until| *until > now);
        map.contains_key(block)
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
        let challenge_msg = viaticum_core::messages::build_pos_hash_challenge(
            c.challenge_id,
            block_id,
            c.esi_ranges.clone(),
            now,
            Some(c.holder_id),
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
        // CS-POS-3: the pending record keeps the holder_master the challenge was addressed
        // to, so the response is verified against the SAME key — not a re-resolve that may
        // have degraded to device-pub by then.
        let challenge = PendingHashChallenge {
            source_block_id: block_id,
            holder_id: c.holder_id,
            esi_ranges: c.esi_ranges,
            expected_chain_hash: c.expected_chain_hash,
            issued_at: now,
            challenge_id: c.challenge_id,
            holder_master: c.holder_master,
        };
        Some((entry, challenge))
    }
}

/// A preparation's hashes, computed under a permit that is gone by now: what is left is the
/// look-up of the holders' masters (database reads), done WITHOUT the permit (J12, MR5).
pub(super) struct Hashed {
    pub(super) prep: BlockPrep,
    pub(super) hashes: HashList,
}

/// The expected chain hash of every holder of a block, in the order of its holders.
pub(super) type HashList = Vec<Result<[u8; 32], PosError>>;

/// One member of a batch of overdue preparations: its record is read, its need known.
pub(super) struct Member {
    pub(super) prep: BlockPrep,
    pub(super) record: viaticum_core::types::SourceBlockRecord,
    pub(super) need_bytes: u64,
}

/// A member's work under the batch's permit: the hashes, or nothing (the block cannot be served,
/// logged).
pub(super) type Computed = Option<HashList>;

impl BlockPrep {
    pub(super) fn block_id(&self) -> SourceBlockId {
        self.block_id
    }

    /// The record of the block, from the database.
    fn record(&self) -> Option<viaticum_core::types::SourceBlockRecord> {
        match self.db.get_source_block(&self.block_id) {
            Ok(Some(r)) => Some(r),
            _ => {
                warn!(block_id = %self.block_id, "scheduler: source block record missing, skipping");
                None
            }
        }
    }

    /// A batch member's first look (blocking, no permit): the record and the need. `None` when the
    /// block has no record (logged) or no holders; it is served nothing.
    pub(super) fn into_member(self) -> Option<Member> {
        if self.holders.is_empty() {
            return None;
        }
        let record = self.record()?;
        let need_bytes = pos_need_bytes(&record);
        Some(Member {
            prep: self,
            record,
            need_bytes,
        })
    }

    /// A member's sources, judged by `metadata` before the load (spec v3.7 WARN-4): a block whose
    /// source files are gone or above the size limit fails at once — `load_failed` for a day, the
    /// WARN of backup-i7 — and never reads a byte. A retained blob (SystemState) needs no source
    /// files; a catalog read that fails is left to the load, which reports it.
    fn sources_are_readable(&self, record: &viaticum_core::types::SourceBlockRecord) -> bool {
        use crate::daemon::backup::rebuild::{SourceCheck, precheck_sources};
        #[cfg(test)]
        {
            if let Some(hook) = &self.precheck_hook {
                hook();
            }
        }
        if crate::daemon::system_state::block::retained_block_path(&self.data_dir, &self.block_id)
            .exists()
        {
            return true;
        }
        let why = match precheck_sources(&self.db, record, &self.rebuild_scope) {
            Ok(SourceCheck::Ready { .. }) | Err(_) => return true,
            Ok(SourceCheck::Missing) => "its source files are missing",
            Ok(SourceCheck::OverLimit) => "its source files are over the size limit",
        };
        let now = Instant::now();
        self.load_failed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(self.block_id, now + POS_LOAD_WARN_INTERVAL);
        log_load_failure(
            &self.load_warned,
            self.block_id,
            now,
            &anyhow::anyhow!("cannot rebuild the block: {why}"),
        );
        false
    }

    /// Load the block and encode it once, folding the hashes of every holder (F8'), under
    /// `permit`. Blocking. `None`: the block cannot be served (logged, `load_failed` set).
    fn compute(
        &self,
        record_params: &ErasureParams,
        permit: &mut MemPermit,
        state: &PrepShared,
    ) -> Computed {
        let block_id = self.block_id;
        state.set_phase(PrepPhase::Load);
        // Load source block data (retained SS blob, else rebuild from source files).
        let blob = match load_source_block(
            &self.db,
            &self.data_dir,
            &self.epoch_key,
            &self.rebuild_scope,
            &block_id,
        ) {
            Ok(d) => {
                self.load_failed
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&block_id);
                d
            }
            Err(e) => {
                let now = Instant::now();
                self.load_failed
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(block_id, load_failed_until(&e, now, self.retry_after));
                log_load_failure(&self.load_warned, block_id, now, &e);
                return None;
            }
        };

        state.set_phase(PrepPhase::Encode);
        // The blob is padded in place, the encoder walks the union of the holders' ESIs once and
        // every symbol goes to the hashers of the holders that have it (F8').
        match fold::hash_holders(
            permit,
            self.encoder.as_ref(),
            &block_id,
            record_params,
            blob,
            &self.holders,
        ) {
            Ok(h) => Some(h),
            Err(e) => {
                error!(block_id = %block_id, "scheduler: encode_raw failed: {e}");
                None
            }
        }
    }

    /// A batch member's turn under the batch's permit: the sources by `metadata`, then the load
    /// and the encode. The permit stays with the batch; the masters are looked up when it is gone.
    /// `state` is the batch's (its phase is what the stuck-load watch reads).
    pub(super) fn compute_member(
        member: Member,
        permit: &mut MemPermit,
        state: &PrepShared,
    ) -> (BlockPrep, Computed) {
        let Member { prep, record, .. } = member;
        // `metadata` of the sources is a read of the disk like the load: a dead NAS hangs it in
        // the same way, so it is the LOAD phase, which the write-off watches (spec v3.7 WARN-4).
        state.set_phase(PrepPhase::Load);
        let hashes = if prep.sources_are_readable(&record) {
            prep.compute(&record.erasure_params(), permit, state)
        } else {
            None
        };
        state.rest();
        (prep, hashes)
    }

    /// The tick's preparation (and a cut one): load, encode once, and hash per holder (F8').
    /// Blocking; runs on the blocking pool.
    ///
    /// The memory permit (backup-i24): taken here by `try_acquire`, right after the block's
    /// record is read — a busy budget ends the run `Deferred` with nothing loaded. It is held
    /// from before the load to the end of the encode and dropped BEFORE the holders' masters are
    /// looked up and the result is returned: nothing is published under it (J12). No check of the
    /// sources here: a missing or grown source is found by the load (backup-i7); a database
    /// catalog scan per block per tick is not for the tick (spec v3.7).
    pub(super) fn run(self) -> PrepOutcome {
        let block_id = self.block_id;
        if self.holders.is_empty() {
            return PrepOutcome::Unserved;
        }
        let Some(record) = self.record() else {
            return PrepOutcome::Unserved;
        };
        let need_bytes = pos_need_bytes(&record);
        let Some(mut permit) = self
            .budget
            .try_acquire(HolderKind::Pos, &block_id, need_bytes)
        else {
            debug!(
                block = %block_id,
                need_mib = need_bytes >> 20,
                queued = self.budget.queued_waiters(),
                outstanding_mib = self.budget.outstanding_bytes() >> 20,
                "pos: block deferred, memory budget busy"
            );
            return PrepOutcome::Deferred;
        };
        self.state.hold(&mut permit);
        let computed = self.compute(&record.erasure_params(), &mut permit, &self.state);
        // The encoder and the source are gone: give the budget back before anything else.
        drop(permit);
        match computed {
            Some(hashes) => Hashed { prep: self, hashes }.finish(),
            None => PrepOutcome::Unserved,
        }
    }
}

impl Hashed {
    /// The challenges: each holder's key resolved (CS-POS-3), its hash paired. Database reads, no
    /// permit.
    pub(super) fn finish(self) -> PrepOutcome {
        let Hashed { prep, hashes } = self;
        let block_id = prep.block_id;
        let mut results = Vec::new();
        for (holder, hash) in prep.holders.into_iter().zip(hashes) {
            match hash {
                Ok(expected_chain_hash) => {
                    #[cfg(test)]
                    {
                        if let Some(hook) = &prep.master_lookup_hook {
                            hook();
                        }
                    }
                    // dr-i8: PEERS first, device_to_master as fallback; no master, no challenge
                    // (never a box addressed by the device id: nobody reads it). The scan already
                    // dropped such holders and warned; a master that vanished between the scan
                    // and here is skipped quietly, the holder is due again next tick.
                    let holder_master = match prep.db.master_for_holder(&holder.holder_id) {
                        Ok(Some(m)) => m,
                        Ok(None) => {
                            debug!(
                                holder = %holder.holder_id,
                                block_id = %block_id,
                                "pos: holder master unknown, challenge skipped"
                            );
                            continue;
                        }
                        Err(e) => {
                            error!(
                                holder = %holder.holder_id,
                                block_id = %block_id,
                                "pos: holder master lookup failed, challenge skipped: {e}"
                            );
                            continue;
                        }
                    };
                    results.push(PreparedChallenge {
                        holder_id: holder.holder_id,
                        challenge_id: holder.challenge_id,
                        expected_chain_hash,
                        esi_ranges: holder.esi_ranges,
                        holder_master,
                    });
                }
                Err(e) => {
                    error!(
                        holder = %holder.holder_id,
                        block_id = %block_id,
                        "scheduler: chain hash failed: {e}"
                    );
                }
            }
        }
        PrepOutcome::Prepared(results)
    }
}

/// The permit a PoS preparation of this block asks for: one encoder build of the padded block
/// and a few symbol buffers (`estimate_pos_issue`).
fn pos_need_bytes(record: &viaticum_core::types::SourceBlockRecord) -> u64 {
    let params = record.erasure_params();
    estimate_pos_issue(params.k, params.t)
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
