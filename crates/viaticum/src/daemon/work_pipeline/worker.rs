// WorkPipeline worker: one encode+deliver cycle for a single block.
//
// This is the core of Wave 11b: replaces both BackupCoordinator::deliver_symbols
// and RepairAgent::repair_placement with a single unified path.
//
// Key invariants:
//   I1: encode_raw called once per block per iteration (not per holder).
//   I2: No disk writes — raw symbols held in RAM, dropped after iteration.
//   I3: CPU-bound encode_raw wrapped in spawn_blocking.
//   I4: Every attempt ends with a cooldown record written by the caller: an ordinary
//       cooldown when offers went out, parking when `offered == 0` or on error
//       (repair-i4).
//   I5: Never overwrite a placement whose status `may_hold_symbols()` (Alive /
//       Uncertain / PresumedLost): only PoS moves those (repair-i2, INV-1).
//   I6: The source is read only when the allocation is non-empty (repair-i4).
//   J8/J12-ex (backup-i24): one memory permit per iteration, taken after the plan and before
//       the source is read, shrunk after the encode, held through the delivery (the named
//       exception to "no network await under a permit"), released at the end. The worker
//       takes no other permit; it yields the budget to an overdue PoS preparation (after
//       at least one attempt this turn) and to a restore (after at least one holder), and
//       only when the waiter (or one ahead of it) cannot fit beside the worker's permit at
//       all (`MemBudget::worker_must_yield`, J13, rule (Б′) of the spec v3.5).
//
// TODO: this function duplicates deliver_to_holder from BackupCoordinator.
// See spec R6: duplication is intentional — worker context differs from coordinator.
// Future: extract shared delivery helper if the implementations diverge.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use viaticum_core::cluster::ClusterState;
use viaticum_core::constants::DECODE_OVERHEAD;
use viaticum_core::db::Db;
use viaticum_core::erasure::{ErasureEncoder, pad_for_encoding};
use viaticum_core::types::{
    DeviceId, ErasureParams, PlacementStatus, SourceBlockId, SourceBlockRecord, SymbolPlacement,
    Timestamp,
};

use super::offer_plan::{self, OfferPlan, add_ranges, subtract_ranges, union_of};
use super::{RestoreGate, WorkPipelineConfig, pool::PoolSnapshot};
use crate::daemon::mem_budget::{
    self, HolderKind, MemBudget, MemPermit, PriorityKind, estimate_worker, estimate_worker_delivery,
};
use crate::daemon::network::swarm::SwarmHandle;
use crate::daemon::peer_backoff::PeerBackoff;

/// Outcome of one block encode+deliver cycle.
#[derive(Debug)]
pub(crate) struct WorkOutcome {
    /// Number of holders that returned SymbolStored acks (Offered→Alive).
    pub acked: usize,
    /// Number of holders that failed or timed out.
    pub failed: usize,
    /// Whether encoding was actually run. `false` means nobody could be offered
    /// symbols (no candidate after exclusions, or an empty allocation); the source
    /// was not read.
    pub encoded: bool,
    /// Number of holders an offer was actually sent to (Offered records written).
    /// `0` = nobody to take symbols (with `encoded = false`), or the block left service
    /// between the plan and the write (`left_service`, repair-i16) — the caller parks the
    /// block (repair-i4).
    pub offered: usize,
    /// The block left service between the plan and the write of the offers (repair-i16):
    /// no offer recorded, nothing delivered.
    pub left_service: bool,
    /// The worker gave the memory budget away before it was done (overdue PoS or restore
    /// waiting): the undelivered placements stay `Offered` and the next turn re-encodes the
    /// block. Not a failure, not counted in `failed` (backup-i24-a).
    pub yielded: bool,
}

/// How one holder's delivery ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeliveryOutcome {
    /// The holder's `acked` covers its whole range; the placement is `Alive`.
    Stored,
    /// Attempted, the range is not covered; the placement stays `Offered`.
    NotStored,
    /// The worker stopped before the next chunk to give the budget away (overdue PoS, or a
    /// restore when `RESTORE_PAUSES_BACKUP` is off).
    Yielded(YieldTo),
}

/// Who the worker gives the budget to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum YieldTo {
    OverduePos,
    Restore,
}

/// How long the worker waits for the budget before the INFO line says so (N4).
const WAIT_LOG_AFTER: Duration = Duration::from_secs(5);

/// Where the delivery to one holder stands between two turns (spec v3.12, К-b2a‴).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HolderState {
    /// The turn gave the budget away in the middle of the share: this holder goes first.
    InProgress,
    /// The last attempt (turn number) ended without the share delivered: an offer without
    /// consent, an error, a chunk not stored. The longest ago goes first among these.
    Failed(u32),
}

/// What the holder has acknowledged of the block, and how its last attempt ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HolderDelivery {
    /// ESIs the holder answered `SymbolStored` for: never sent again (it keeps them; a repeat is
    /// `already_held` at its side). Ascending, merged.
    pub(crate) acked: Vec<(u32, u32)>,
    pub(crate) state: HolderState,
}

/// What the worker keeps between the turns of one block (RAM only, cleared with the yield count,
/// backup-i24-a, spec v3.12): how many turns the block has had (any turn, yielded or not) and,
/// per holder, the delivery memory. A restart empties it: the share is then sent from its first
/// chunk once (the holder writes nothing twice).
#[derive(Debug, Default)]
pub(crate) struct TurnMemory {
    pub(crate) turns: u32,
    pub(crate) holders: HashMap<DeviceId, HolderDelivery>,
}

impl TurnMemory {
    /// The place of a holder in the order of a turn: in progress first, then never attempted
    /// (plan order, the sort is stable), then failed, the longest ago first.
    fn order_key(&self, holder: &DeviceId) -> (u8, u32) {
        match self.holders.get(holder).map(|h| h.state) {
            Some(HolderState::InProgress) => (0, 0),
            None => (1, 0),
            Some(HolderState::Failed(turn)) => (2, turn),
        }
    }

    fn acked_of(&self, holder: &DeviceId) -> &[(u32, u32)] {
        self.holders
            .get(holder)
            .map_or(&[][..], |h| h.acked.as_slice())
    }

    /// The holder's attempt of turn `turn` ended without the share delivered.
    fn mark_failed(&mut self, holder: DeviceId, turn: u32) {
        self.holders
            .entry(holder)
            .and_modify(|h| h.state = HolderState::Failed(turn))
            .or_insert(HolderDelivery {
                acked: Vec::new(),
                state: HolderState::Failed(turn),
            });
    }

    fn mark_in_progress(&mut self, holder: DeviceId) {
        self.holders
            .entry(holder)
            .and_modify(|h| h.state = HolderState::InProgress)
            .or_insert(HolderDelivery {
                acked: Vec::new(),
                state: HolderState::InProgress,
            });
    }

    /// `esis` were acknowledged by the holder.
    fn record_acked(&mut self, holder: DeviceId, esis: &[(u32, u32)]) {
        let entry = self.holders.entry(holder).or_insert(HolderDelivery {
            acked: Vec::new(),
            state: HolderState::InProgress,
        });
        add_ranges(&mut entry.acked, esis);
    }
}

/// Progress of one turn (one `run_block_iteration`) — the yield rules need it: a turn always
/// makes at least one attempt before it yields to an overdue PoS, and at least one holder before
/// it yields to a restore (J13, backup-i24-a).
pub(super) struct Turn<'a> {
    pub(super) budget: &'a MemBudget,
    /// The worker's permit, after its shrink: W of the yield rule.
    pub(super) permit: &'a MemPermit,
    pub(super) chunk_budget_bytes: usize,
    /// Holders whose delivery began this turn.
    pub(super) holders_started: usize,
    /// Attempts this turn (spec v3.5 BLOCK-1): an offer that ended WITHOUT a `SymbolAccept`
    /// (error, timeout, reject, a foreign reply), and every chunk sent, whatever it came to. An
    /// accepted offer counts for nothing by itself: it and the holder's first chunk are one
    /// attempt — so a holder who accepts always gets one chunk per turn.
    pub(super) attempts: u32,
    /// `!RESTORE_PAUSES_BACKUP` (Q-V9 (b), spec v3.12): a waiting restore gets the budget after
    /// the turn's first attempt, before every next send — not only between holders.
    pub(super) restore_at_chunk: bool,
    /// The restore gate (Q-V9 (a), spec v3.12b WARN-1): `Some` when restore comes first. A turn
    /// in progress sees it: while it is up the turn stops at the next boundary — after the
    /// turn's first attempt, before every next send — whether or not a restore waits for the
    /// memory at that moment (at most one re-encode per job).
    pub(super) gate: Option<&'a RestoreGate>,
}

impl Turn<'_> {
    /// Before a next chunk or holder (never before the first attempt of the turn).
    pub(super) fn overdue_pos_wants_the_budget(&self) -> bool {
        self.attempts >= 1
            && self
                .budget
                .worker_must_yield(PriorityKind::OverduePos, self.permit)
    }

    /// The gate is up now (an unfinished restore job or a DR session; computed at the reading).
    pub(super) fn gate_is_up(&self) -> bool {
        self.gate.is_some_and(RestoreGate::is_up)
    }

    /// Before a next chunk: restore stops the worker here when the gate is up (Q-V9 (a), after
    /// the turn's first attempt) or, with the gate not given, when restore yields at the chunk
    /// boundary and waits for the memory (Q-V9 (b)).
    pub(super) fn restore_wants_the_budget_at_a_chunk(&self) -> bool {
        self.attempts >= 1
            && (self.gate_is_up()
                || (self.restore_at_chunk
                    && self
                        .budget
                        .worker_must_yield(PriorityKind::Restore, self.permit)))
    }

    /// Before a next holder.
    pub(super) fn yield_before_next_holder(&self) -> Option<YieldTo> {
        let started = if self.restore_at_chunk {
            self.attempts >= 1
        } else {
            self.holders_started >= 1
        };
        if self.overdue_pos_wants_the_budget() {
            Some(YieldTo::OverduePos)
        } else if (self.attempts >= 1 && self.gate_is_up())
            || (started
                && self
                    .budget
                    .worker_must_yield(PriorityKind::Restore, self.permit))
        {
            Some(YieldTo::Restore)
        } else {
            None
        }
    }
}

fn log_yield(to: YieldTo, block: &SourceBlockId, holders_done: usize, of: usize, yields: u32) {
    match to {
        YieldTo::OverduePos => tracing::info!(
            block = %block,
            holders_done,
            of,
            yields_for_block = yields,
            "work_pipeline: yielding memory to overdue PoS"
        ),
        YieldTo::Restore => tracing::info!(
            block = %block,
            holders_done,
            of,
            yields_for_block = yields,
            "work_pipeline: yielding memory to restore"
        ),
    }
}

/// `a..b` per range of `ranges` (inclusive ends), joined by `,`: the ESIs of a chunk in the log.
fn esis_text(ranges: &[(u32, u32)]) -> String {
    ranges
        .iter()
        .map(|&(start, count)| {
            format!("{start}..{}", start.saturating_add(count.saturating_sub(1)))
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// One DEBUG line per chunk sent: the observable of backup-i24-a (an `Ack` without
/// `SymbolStored` leaves no other line). `esis` are the chunk's ESIs (v3.12): no (holder, ESI)
/// pair repeats in `reply=stored` lines within one process.
fn log_chunk_sent(
    placement: &SymbolPlacement,
    block_id: &SourceBlockId,
    idx: usize,
    total_chunks: usize,
    esis: &[(u32, u32)],
    reply: &str,
) {
    tracing::debug!(
        holder = %placement.holder_id,
        block_id = %block_id,
        chunk = %format!("{}/{}", idx + 1, total_chunks),
        esis = %esis_text(esis),
        reply = %reply,
        "work_pipeline: chunk sent"
    );
}

/// Holders excluded from a new offer of one block (repair-i2).
#[derive(Debug, Default)]
pub(crate) struct ExcludedHolders {
    /// Every excluded holder.
    pub ids: std::collections::HashSet<DeviceId>,
    /// Of which `Alive`: already hold the block.
    pub alive: usize,
    /// Of which `Uncertain` / `PresumedLost`: may still hold it, awaiting a PoS verdict.
    pub awaiting_verdict: usize,
}

/// Execute one encode+deliver cycle for the given block.
///
/// Steps:
///  1. Compute ErasureParams from block record.
///  2. `offer_plan::plan_offers`: exclude holders that hold or may hold the block
///     (`may_hold_symbols`, repair-i2), allocate, assign ESI ranges — a holder with an
///     `Offered` row (e.g. after `SymbolReject`) gets its own range back, fresh numbers only
///     for the rest (repair-i9).
///  3. Nobody to offer to → return `encoded = false` WITHOUT reading the source
///     (repair-i4: cheap outcome) and without touching the memory budget. Otherwise take the
///     memory permit (backup-i24), sized by the plan's symbol count; it waits its turn.
///  4. Load source blob via `rebuild_source_blob` (re-encodes from source files), pad it to
///     `k·t` in place. The allocation never depends on the blob (sizes come from
///     `encrypted_size`).
///  5. `encode_block` once for the union of the plan's ESIs (spawn_blocking — CPU-bound ~30s
///     for 128MB), then shrink the permit to what delivery holds.
///  6. For each allocation: bind symbols inline, send SymbolOffer → SymbolAccept → SymbolTransfer.
///     On `SymbolStored`: transition Offered→Alive + recompute cached fields. Before a next
///     holder or chunk, give the budget away to a waiting restore / overdue PoS (J13).
///  7. Drop raw symbols (no disk spill), release the permit.
///
/// `yields_before` is the number of turns on this block that ended in a yield since it was last
/// delivered in full (for the yield line); `memory` (RAM, per block, cleared with the yield
/// count) counts every turn of the block and holds, per holder, the delivery memory (spec v3.12,
/// К-b2a‴): the ESIs it acknowledged and whether it is in progress or failed. The turn goes
/// through the holders in progress first, then those never attempted, then the failed ones, the
/// longest ago first; to each it sends only the ESIs it has not acknowledged, and the encoder is
/// asked for those only. A placement becomes `Alive` when the acknowledged ESIs cover its range.
///
/// The caller records the attempt after this returns (`last_attempted_at`,
/// `last_pool_signature`): an ordinary cooldown when `offered > 0`, otherwise (or on
/// error) the block is parked (repair-i4).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_block_iteration(
    db: &Db,
    config: &WorkPipelineConfig,
    encoder: &Arc<dyn ErasureEncoder>,
    swarm: &SwarmHandle,
    master_signing_key: Option<&ed25519_dalek::SigningKey>,
    peer_backoff: Option<&PeerBackoff>,
    cluster_state: Option<&Arc<Mutex<ClusterState>>>,
    block: &SourceBlockRecord,
    pool: &PoolSnapshot,
    yields_before: u32,
    memory: &mut TurnMemory,
    gate: Option<&RestoreGate>,
) -> anyhow::Result<WorkOutcome> {
    // 1. Compute ErasureParams.
    let k = block.k;
    let t = block.t;
    let overhead = block.overhead.unwrap_or(1.5);
    let n = block.n.unwrap_or(k * 2);
    let params = ErasureParams {
        k,
        k_eff: k + DECODE_OVERHEAD,
        t,
        overhead,
        n,
    };

    // 2-3. Plan: who gets offers and which ESIs (repair-i2, repair-i9).
    let namespace_start = offer_plan::namespace_start(cluster_state, &config.device_id);
    let offers = match offer_plan::plan_offers(db, block, &pool.candidates, namespace_start)? {
        OfferPlan::Planned { cursor, offers } => {
            tracing::debug!(
                block_id = %block.block_id,
                cursor,
                holders = offers.len(),
                "work_pipeline: offer plan"
            );
            offers
        }
        OfferPlan::NoCandidates(excluded) => {
            tracing::info!(
                block_id = %block.block_id,
                excluded_alive = excluded.alive,
                excluded_awaiting_verdict = excluded.awaiting_verdict,
                pool = pool.candidates.len(),
                "work_pipeline: no new candidates (every pool peer holds the block or awaits a PoS verdict)"
            );
            return Ok(WorkOutcome {
                acked: 0,
                failed: 0,
                encoded: false,
                offered: 0,
                left_service: false,
                yielded: false,
            });
        }
        OfferPlan::EmptyAllocation => {
            tracing::info!(
                block_id = %block.block_id,
                "work_pipeline: compute_allocation returned empty (too few candidates)"
            );
            return Ok(WorkOutcome {
                acked: 0,
                failed: 0,
                encoded: false,
                offered: 0,
                left_service: false,
                yielded: false,
            });
        }
        OfferPlan::AllocationFailed(e) => {
            tracing::warn!(
                block_id = %block.block_id,
                "work_pipeline: compute_allocation failed: {e}"
            );
            return Ok(WorkOutcome {
                acked: 0,
                failed: 0,
                encoded: false,
                offered: 0,
                left_service: false,
                yielded: false,
            });
        }
    };

    // The delivery memory (v3.12): a holder that dropped out of the plan loses its entry. The
    // order of the turn: in progress, then never attempted (plan order, the sort is stable), then
    // failed, the longest ago first. Every yielded turn sends a NEW chunk to its first holder
    // that accepts, so a block is done within Σ ⌈rest / chunk⌉ turns that made progress.
    memory.turns += 1;
    let this_turn = memory.turns;
    memory
        .holders
        .retain(|d, _| offers.iter().any(|o| o.device_id == *d));
    let mut offers = offers;
    offers.sort_by_key(|o| memory.order_key(&o.device_id));
    // What each holder still lacks: only that is encoded and sent.
    let rests: Vec<Vec<(u32, u32)>> = offers
        .iter()
        .map(|o| subtract_ranges(&o.esi_ranges, memory.acked_of(&o.device_id)))
        .collect();

    // 3b. The memory permit (J8): one for the whole iteration, taken now — after the plan, so
    //     the early exits above never touch the budget, and before the source is read. It
    //     waits its turn behind whoever is queued; nothing is held meanwhile. Sized by the
    //     symbols this plan asks the encoder for (J10: at most 10·k_eff of them).
    let encode_ranges = union_of(&rests);
    let out_symbols: u64 = encode_ranges.iter().map(|&(_, count)| count as u64).sum();
    debug_assert!(
        out_symbols <= 10 * params.k_eff as u64,
        "J10: {out_symbols} symbols in one iteration, k_eff = {}",
        params.k_eff
    );
    let e_pad = k as u64 * t as u64;
    let estimate = estimate_worker(k, t, out_symbols);
    let mut permit = config
        .mem_budget
        .acquire(
            HolderKind::Worker,
            &block.block_id,
            estimate,
            WAIT_LOG_AFTER,
            |queued_ahead| {
                tracing::info!(
                    block = %block.block_id,
                    need_mib = estimate.min(config.mem_budget.total_bytes()) >> 20,
                    outstanding_mib = config.mem_budget.outstanding_bytes() >> 20,
                    queued_ahead,
                    "work_pipeline: waiting for memory budget"
                );
            },
        )
        .await;

    // 3c. The gate may have gone up while the permit was waited for (spec v3.12b WARN-1): the
    //     permit goes back before the rebuild and the encode, the turn ends (`yielded`, nothing
    //     encoded, nothing offered). The check follows the grant, whatever the wait was.
    if gate.is_some_and(RestoreGate::is_up) {
        drop(permit);
        tracing::info!(
            block = %block.block_id,
            yields_for_block = yields_before + 1,
            "work_pipeline: restore gate is up after the permit was granted — permit released, no encode"
        );
        return Ok(WorkOutcome {
            acked: 0,
            failed: 0,
            encoded: false,
            offered: 0,
            left_service: false,
            yielded: true,
        });
    }

    // 4. Obtain the source blob — only now that someone can take symbols. SystemState
    //    blocks have no backing watch-dir file: their encoded blob is retained on disk
    //    (blake3 == block_id), so load it directly. All other blocks rebuild from
    //    source files (deterministic).
    let mut source_data = load_source_blob(db, config, block).await?;
    // The block id was checked by the load; padding changes the bytes the id is over.
    // Padded IN PLACE to k·t: the encoder then borrows it instead of copying it (F5).
    pad_for_encoding(&mut source_data, &params);

    // 5. Encode once for the union of every offer's ESIs (ascending, so the delivery
    //    looks symbols up by ESI with a binary search). The task owns the permit and the
    //    source while it runs and hands the permit back: whatever happens to this future,
    //    the budget counts the encoder until the task is over.
    let encoder_clone = Arc::clone(encoder);
    let (permit_back, encoded) = tokio::task::spawn_blocking(move || {
        let result = mem_budget::encode_block(
            &permit,
            encoder_clone.as_ref(),
            &source_data,
            &params,
            &encode_ranges,
        );
        // The source is no longer needed.
        drop(source_data);
        (permit, result)
    })
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking join: {e}"))?;
    permit = permit_back;
    let raw_symbols = encoded.map_err(|e| anyhow::anyhow!("encode_raw: {e}"))?;

    // The encoder is gone: keep what delivery needs, free the rest for the others.
    permit.shrink_to(estimate_worker_delivery(e_pad, out_symbols, t));

    tracing::debug!(
        block_id = %block.block_id,
        symbols = raw_symbols.len(),
        "work_pipeline: encoded raw symbols"
    );

    // 5b. The gate may have gone up while the encoder ran (K-b2a^5 WARN-1: up to minutes on a
    //     big block): the first holder must not get an offer and a first chunk. The permit and
    //     the symbols go back, nothing is offered, no placement is written; the turn ends as a
    //     pause (the block is encoded again after the restore: one re-encode per job).
    if gate.is_some_and(RestoreGate::is_up) {
        drop(raw_symbols);
        drop(permit);
        tracing::info!(
            block = %block.block_id,
            yields_for_block = yields_before + 1,
            "work_pipeline: restore gate is up after the encode — permit released, no offer"
        );
        return Ok(WorkOutcome {
            acked: 0,
            failed: 0,
            encoded: true,
            offered: 0,
            left_service: false,
            yielded: true,
        });
    }

    // 6. Insert all Offered placements before delivery (so retries see them). The write
    //    re-checks that the block is still in service (repair-i16); only the offers it
    //    wrote are delivered.
    let offers = offer_plan::record_offers(db, config.device_id, block, &offers, Timestamp::now())?;
    let offered = offers.len();
    if offers.is_empty() {
        // `permit` and `raw_symbols` go with the scope.
        return Ok(WorkOutcome {
            acked: 0,
            failed: 0,
            encoded: true,
            offered: 0,
            left_service: true,
            yielded: false,
        });
    }

    // 7. Deliver to each holder (binding applied inline at send time).
    let mut acked = 0usize;
    let mut failed = 0usize;
    let mut yielded = false;
    let mut turn = Turn {
        budget: &config.mem_budget,
        permit: &permit,
        chunk_budget_bytes: config.chunk_budget_bytes,
        holders_started: 0,
        attempts: 0,
        restore_at_chunk: !config.restore_pauses_backup,
        gate,
    };

    for (idx, offer) in offers.iter().enumerate() {
        // J13: a restore (after this turn's first holder) or an overdue PoS (after its
        // first attempt) that cannot run beside this permit gets the budget now.
        if let Some(to) = turn.yield_before_next_holder() {
            log_yield(to, &block.block_id, idx, offers.len(), yields_before + 1);
            yielded = true;
            break;
        }
        // Load the Offered placement just inserted.
        let placement = match db.get_placement(&block.block_id, &offer.device_id) {
            Ok(Some(p)) => p,
            Ok(None) => {
                tracing::warn!(
                    block_id = %block.block_id,
                    holder = %offer.device_id,
                    "work_pipeline: placement not found after insert (race?)"
                );
                failed += 1;
                continue;
            }
            Err(e) => {
                tracing::error!(
                    block_id = %block.block_id,
                    holder = %offer.device_id,
                    "work_pipeline: DB error loading placement: {e}"
                );
                failed += 1;
                continue;
            }
        };

        turn.holders_started += 1;
        let attempts_before = turn.attempts;
        let delivery = deliver_to_holder_worker(
            db,
            encoder,
            swarm,
            master_signing_key,
            peer_backoff,
            block,
            &placement,
            &raw_symbols,
            block.importance,
            &mut turn,
            memory,
        )
        .await;
        match delivery {
            Ok(DeliveryOutcome::Stored) => {
                // Alive: the holder is done, its entry goes (v3.12 item 4).
                memory.holders.remove(&offer.device_id);
                acked += 1;
            }
            Ok(DeliveryOutcome::NotStored) => {
                // Delivery attempted but the range is not covered (placement left Offered); what
                // the holder acknowledged is kept.
                memory.mark_failed(offer.device_id, this_turn);
                failed += 1;
            }
            Ok(DeliveryOutcome::Yielded(to)) => {
                // Between two chunks: the placement stays Offered, the holder keeps what it got
                // and what it acknowledged stays in the memory (a later turn sends the rest, not
                // the whole), and this is not a failure. In progress only when this turn put the
                // holder through an attempt: a turn that gave the budget away before its first
                // one leaves it as it was (16', M37).
                if turn.attempts > attempts_before {
                    memory.mark_in_progress(offer.device_id);
                }
                log_yield(to, &block.block_id, idx, offers.len(), yields_before + 1);
                yielded = true;
                break;
            }
            Err(e) => {
                tracing::warn!(
                    block_id = %block.block_id,
                    holder = %offer.device_id,
                    "work_pipeline: deliver_to_holder_worker failed: {e}"
                );
                memory.mark_failed(offer.device_id, this_turn);
                failed += 1;
            }
        }
    }

    // 8. Drop raw symbols explicitly (no disk spill), then give the permit back.
    drop(raw_symbols);
    drop(permit);

    Ok(WorkOutcome {
        acked,
        failed,
        encoded: true,
        offered,
        left_service: false,
        yielded,
    })
}

/// Deliver symbols for one (block, holder) pair using SymbolOffer/Accept/Transfer flow.
///
/// Sends the ESIs of the placement the holder has not acknowledged (`memory`), the offer
/// itself carries the whole range. Returns `Stored` if the acknowledged ESIs now cover the range
/// (Offered→Alive transitioned), `NotStored` if delivery was attempted and they do not,
/// `Yielded` if the worker stopped between two chunks to give the budget away. Returns Err on
/// network or DB error. A holder that has acknowledged everything is not offered again.
#[allow(clippy::too_many_arguments)]
async fn deliver_to_holder_worker(
    db: &Db,
    encoder: &Arc<dyn ErasureEncoder>,
    swarm: &SwarmHandle,
    master_signing_key: Option<&ed25519_dalek::SigningKey>,
    peer_backoff: Option<&PeerBackoff>,
    block: &SourceBlockRecord,
    placement: &SymbolPlacement,
    raw_symbols: &[viaticum_core::erasure::Symbol],
    importance: f64,
    turn: &mut Turn<'_>,
    memory: &mut TurnMemory,
) -> anyhow::Result<DeliveryOutcome> {
    use viaticum_core::messages::Message;

    // Nothing left to send: the memory says the holder has the whole range already.
    if subtract_ranges(&placement.esi_ranges, memory.acked_of(&placement.holder_id)).is_empty() {
        return Ok(confirm_alive(db, &block.block_id, placement));
    }

    // If signing key is present, use SymbolOffer/Accept/Transfer handshake.
    if let Some(signing_key) = master_signing_key {
        let msg_id: [u8; 16] = rand::random();
        let timestamp = Timestamp::now();
        let offer = viaticum_core::messages::build_symbol_offer(
            msg_id,
            block.block_id,
            placement.esi_ranges.clone(),
            importance,
            timestamp,
            signing_key,
        );

        let reply = match swarm
            .send_to_device(placement.holder_id, Message::SymbolOffer(offer))
            .await
        {
            Ok(reply) => reply,
            Err(e) => {
                // An offer that ended without an accept is an attempt (BLOCK-1).
                turn.attempts += 1;
                return Err(anyhow::anyhow!("send SymbolOffer: {e}"));
            }
        };

        match reply {
            Message::SymbolAccept(_) => {
                if let Some(backoff) = peer_backoff {
                    backoff.record_accept(&placement.holder_id);
                }
                // Holder accepted — send the actual symbols.
                deliver_transfer_worker(db, encoder, swarm, placement, raw_symbols, turn, memory)
                    .await
            }
            Message::SymbolReject(reject) => {
                turn.attempts += 1;
                if let Some(backoff) = peer_backoff {
                    backoff.record_reject(placement.holder_id);
                }
                anyhow::bail!(
                    "holder {} rejected offer for block {}: {:?}",
                    placement.holder_id,
                    block.block_id,
                    reject.reason
                )
            }
            other => {
                turn.attempts += 1;
                anyhow::bail!(
                    "unexpected reply to SymbolOffer from {}: {:?}",
                    placement.holder_id,
                    std::mem::discriminant(&other)
                )
            }
        }
    } else {
        // No signing key: fall back to direct SymbolTransfer.
        deliver_transfer_worker(db, encoder, swarm, placement, raw_symbols, turn, memory).await
    }
}

/// The symbols of `placement` the holder has not acknowledged (`acked` is what it has), bound to
/// it: each ESI of `placement.esi_ranges − acked` is looked up BY ESI in `raw_symbols` (ascending
/// by ESI — encoded from the union of the turn's undelivered rests; ranges need not be
/// contiguous, repair-i9) and bound with (block, holder). An ESI of that rest missing from
/// `raw_symbols` is an error, never silently skipped: the holder must get exactly what it lacks.
/// The acknowledged ESIs are not bound: the turn did not encode them (spec v3.12a NOTE 2).
pub(crate) fn bind_placement_symbols(
    encoder: &dyn ErasureEncoder,
    block_id: &SourceBlockId,
    placement: &SymbolPlacement,
    acked: &[(u32, u32)],
    raw_symbols: &[viaticum_core::erasure::Symbol],
) -> anyhow::Result<Vec<viaticum_core::erasure::Symbol>> {
    let rest = subtract_ranges(&placement.esi_ranges, acked);
    let bound: Vec<viaticum_core::erasure::Symbol> = rest
        .iter()
        .flat_map(|&(start_esi, count)| start_esi..start_esi.saturating_add(count))
        .filter_map(|esi| {
            let idx = raw_symbols.binary_search_by_key(&esi, |s| s.esi).ok()?;
            Some(encoder.apply_binding(raw_symbols[idx].clone(), block_id, &placement.holder_id))
        })
        .collect();

    let expected: usize = rest.iter().map(|&(_, count)| count as usize).sum();
    if bound.len() != expected {
        anyhow::bail!(
            "raw symbols missing for block {} holder {}: {} of {} (rest={:?}, raw_len={})",
            block_id,
            placement.holder_id,
            bound.len(),
            expected,
            rest,
            raw_symbols.len(),
        );
    }
    Ok(bound)
}

/// Offered→Alive for a placement whose range the holder has acknowledged in full, plus the
/// W11a hook (cached fields).
fn confirm_alive(
    db: &Db,
    block_id: &SourceBlockId,
    placement: &SymbolPlacement,
) -> DeliveryOutcome {
    let now = Timestamp::now();
    match db.transition_placement_offered_to_alive(block_id, &placement.holder_id, now) {
        Ok(true) => {
            tracing::info!(
                holder = %placement.holder_id,
                block_id = %block_id,
                symbols = placement.symbol_count(),
                "work_pipeline: symbols confirmed stored, placement Offered→Alive"
            );
            crate::daemon::processor::recompute_and_persist_block_cached_fields(db, block_id);
            return DeliveryOutcome::Stored;
        }
        Ok(false) => {
            tracing::debug!(
                holder = %placement.holder_id,
                "work_pipeline: placement transition skipped (not in Offered state)"
            );
        }
        Err(e) => {
            tracing::error!(
                holder = %placement.holder_id,
                err = %e,
                "work_pipeline: DB error transitioning Offered→Alive"
            );
        }
    }
    DeliveryOutcome::NotStored
}

/// Send SymbolTransfer chunks to a holder, wait for SymbolStored acks.
///
/// Only the ESIs the holder has not acknowledged go out (numbered by that rest); each
/// `SymbolStored` adds its ESIs to the memory at once, so a yield or a failure later keeps them.
/// When the acknowledged ESIs cover the placement's range: Offered→Alive + runs W11a hook.
/// Before each chunk once the turn has made an attempt, an overdue PoS that cannot run beside this
/// permit makes the worker stop (`Yielded`, backup-i24-a) — a restore too when it yields at the
/// chunk boundary (`Turn::restore_at_chunk`); the placement stays `Offered`. Every chunk sent
/// counts as an attempt, whatever the holder answers.
async fn deliver_transfer_worker(
    db: &Db,
    encoder: &Arc<dyn ErasureEncoder>,
    swarm: &SwarmHandle,
    placement: &SymbolPlacement,
    raw_symbols: &[viaticum_core::erasure::Symbol],
    turn: &mut Turn<'_>,
    memory: &mut TurnMemory,
) -> anyhow::Result<DeliveryOutcome> {
    use viaticum_core::erasure::chunk_symbols_by_size;
    use viaticum_core::messages::{Message, SymbolTransferMsg};

    let block_id = &placement.source_block_id;
    // Bind raw symbols inline at send time — no disk read. Only the unacknowledged rest.
    let bound = bind_placement_symbols(
        encoder.as_ref(),
        block_id,
        placement,
        memory.acked_of(&placement.holder_id),
        raw_symbols,
    )?;

    let chunks = chunk_symbols_by_size(bound, turn.chunk_budget_bytes);
    let total_chunks = chunks.len();
    let mut stored_ok = 0usize;
    let mut saw_old_protocol = false;

    for (idx, chunk) in chunks.into_iter().enumerate() {
        if turn.overdue_pos_wants_the_budget() {
            return Ok(DeliveryOutcome::Yielded(YieldTo::OverduePos));
        }
        if turn.restore_wants_the_budget_at_a_chunk() {
            return Ok(DeliveryOutcome::Yielded(YieldTo::Restore));
        }
        let chunk_len = chunk.len();
        let chunk_esis = union_of(&[chunk.iter().map(|s| (s.esi, 1)).collect()]);
        let msg = SymbolTransferMsg {
            v: 1,
            source_block_id: *block_id,
            symbols: chunk,
            timestamp: Timestamp::now(),
        };
        let sent = swarm
            .send_to_device(placement.holder_id, Message::SymbolTransfer(msg))
            .await;
        // A chunk sent is an attempt, whatever it came to (BLOCK-1).
        turn.attempts += 1;
        let reply = match sent {
            Ok(reply) => reply,
            Err(e) => {
                log_chunk_sent(placement, block_id, idx, total_chunks, &chunk_esis, "err");
                return Err(anyhow::anyhow!(
                    "send SymbolTransfer chunk {}/{}: {}",
                    idx + 1,
                    total_chunks,
                    e
                ));
            }
        };

        match reply {
            // A `SymbolStored` for another block acknowledges nothing of this one (spec v3.12b
            // NOTE 4): it is not counted, whatever ESIs it names.
            Message::SymbolStored(stored) if stored.source_block_id != *block_id => {
                log_chunk_sent(placement, block_id, idx, total_chunks, &chunk_esis, "other");
                tracing::warn!(
                    holder = %placement.holder_id,
                    block_id = %block_id,
                    replied_block = %stored.source_block_id,
                    "work_pipeline: SymbolStored names another block — not counted"
                );
            }
            Message::SymbolStored(stored) => {
                stored_ok += 1;
                log_chunk_sent(
                    placement,
                    block_id,
                    idx,
                    total_chunks,
                    &chunk_esis,
                    "stored",
                );
                // What the holder acknowledged, as far as it is what this chunk carried (the
                // ESIs of THIS chunk only: a range wider than the chunk counts for the chunk).
                let confirmed = subtract_ranges(
                    &chunk_esis,
                    &subtract_ranges(&chunk_esis, &stored.esi_ranges),
                );
                memory.record_acked(placement.holder_id, &confirmed);
                tracing::debug!(
                    holder = %placement.holder_id,
                    block_id = %block_id,
                    chunk = idx + 1,
                    total = total_chunks,
                    symbols = chunk_len,
                    "work_pipeline: chunk stored",
                );
                // T-12 safety net: persist holder's dialable addrs learned from the
                // authenticated SymbolTransfer connection. This closes the window where
                // identify hasn't yet propagated the holder's addrs to the PeerRecord,
                // so on the next build_pointer_for_placed call the HolderHint.addrs
                // field will be populated for faster DR dialing.
                //
                // The processor's PeerRecord writer (`processor/peer_record_writer`,
                // fed by PeerAuthenticated / PeerIdentified) is the primary source; this
                // is the secondary safety net for the case where identify fires after
                // this point.
                //
                // If addrs are empty (identify not yet done) → skip: the PeerRecord writer
                // will write them when identify completes. Empty addrs are fine:
                // DR falls back to Kademlia get_closest_peers(holder_id) per B-1.
                persist_holder_addrs_from_swarm(db, swarm, placement.holder_id).await;
            }
            Message::Ack(_) => {
                // Holder did not confirm storage with SymbolStored (transfer handler
                // failed, or an older/unhandled path replied with a generic Ack).
                saw_old_protocol = true;
                log_chunk_sent(placement, block_id, idx, total_chunks, &chunk_esis, "ack");
            }
            other => {
                log_chunk_sent(placement, block_id, idx, total_chunks, &chunk_esis, "other");
                tracing::warn!(
                    holder = %placement.holder_id,
                    "work_pipeline: unexpected reply to SymbolTransfer: {:?}",
                    std::mem::discriminant(&other)
                );
            }
        }
    }

    // Alive when the acknowledged ESIs cover the placement's range (not "every chunk of this turn
    // was stored": a delivery spread over several turns is covered by the memory).
    let covered =
        subtract_ranges(&placement.esi_ranges, memory.acked_of(&placement.holder_id)).is_empty();
    if covered {
        return Ok(confirm_alive(db, block_id, placement));
    }
    if saw_old_protocol {
        tracing::debug!(
            holder = %placement.holder_id,
            chunks_ok = stored_ok,
            chunks_total = total_chunks,
            "work_pipeline: holder replied Ack without SymbolStored; placement left Offered"
        );
    } else {
        tracing::warn!(
            holder = %placement.holder_id,
            block_id = %block_id,
            chunks_ok = stored_ok,
            chunks_total = total_chunks,
            "work_pipeline: not all chunks acked; placement left Offered"
        );
    }

    Ok(DeliveryOutcome::NotStored)
}

/// T-12 safety net: query the swarm for a holder's identify-received listen addrs
/// and persist them to the PeerRecord if non-empty.
///
/// Called after the owner receives a `SymbolStored` ack from a holder. This
/// ensures the PeerRecord carries dialable addrs even when identify hasn't yet
/// propagated them through the processor's PeerRecord writer.
///
/// If the swarm returns an empty addr list (identify not yet complete for this
/// peer), the function is a no-op — the PeerRecord writer will write the addrs
/// later when identify completes. Empty addrs are fine: DR uses Kademlia fallback.
pub(crate) async fn persist_holder_addrs_from_swarm(
    db: &Db,
    swarm: &SwarmHandle,
    holder_id: DeviceId,
) {
    let addrs = swarm.get_peer_addrs(holder_id).await;
    if addrs.is_empty() {
        return;
    }
    let addr_strings: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
    persist_holder_addrs_to_db(db, holder_id, addr_strings);
}

/// T-12 inner: persist holder addr strings to the PeerRecord in DB.
///
/// Extracted for testability — callers provide pre-resolved addr strings.
/// No-op if addrs are empty or already match the stored value.
pub(crate) fn persist_holder_addrs_to_db(db: &Db, holder_id: DeviceId, addr_strings: Vec<String>) {
    if addr_strings.is_empty() {
        return;
    }
    match db.get_peer(&holder_id) {
        Ok(Some(mut record)) => {
            if record.addrs == addr_strings {
                return; // no-op: already up to date
            }
            record.addrs = addr_strings;
            if let Err(e) = db.upsert_peer(&record) {
                tracing::warn!(
                    holder = %holder_id,
                    err = %e,
                    "T-12: failed to persist holder addrs after SymbolStored"
                );
            } else {
                tracing::debug!(
                    holder = %holder_id,
                    "T-12: persisted holder addrs from SymbolStored connection"
                );
            }
        }
        Ok(None) => {
            // Peer record not yet in DB (rare: delivery happened before the PeerRecord
            // writer committed the authentication).
            tracing::debug!(
                holder = %holder_id,
                "T-12: PeerRecord not found after SymbolStored — on_peer_identified will update later"
            );
        }
        Err(e) => {
            tracing::warn!(
                holder = %holder_id,
                err = %e,
                "T-12: db.get_peer failed in persist_holder_addrs_to_db"
            );
        }
    }
}

/// The source blob of `block` for encoding (step 4): a SystemState block's retained
/// blob, else the rebuild from this device's files by content (К2b). The rebuild error
/// keeps its type under the added context (`RebuildError::SourceMissing` stays
/// recognisable); gone paths the rebuild met go to `config.recheck_tx`.
pub(crate) async fn load_source_blob(
    db: &Db,
    config: &WorkPipelineConfig,
    block: &SourceBlockRecord,
) -> anyhow::Result<Vec<u8>> {
    use anyhow::Context;
    if let Some(blob) = crate::daemon::system_state::block::try_load_retained_block(
        &config.data_dir,
        &block.block_id,
    )? {
        return Ok(blob);
    }
    let scope = crate::daemon::backup::rebuild::RebuildScope::new(
        config.device_id,
        config.recheck_tx.clone(),
    )
    .with_max_source_bytes(config.max_source_bytes);
    crate::daemon::backup::pipeline::rebuild_source_blob(db, block, &config.epoch_key, &scope)
        .await
        .context("rebuild_source_blob")
}

/// Resolve the `file_id` to stamp on placements this worker creates.
///
/// Fast path: if any placement already exists for the block (repair iterations,
/// or a re-run after partial delivery), reuse its `file_id` — cheap and keeps
/// every placement for the block attributed consistently.
///
/// A4: a freshly-backed-up block has the `SourceBlockRecord` but ZERO placements
/// (backup is no longer a placement creator — the worker is the sole creator).
/// In that case derive the primary `file_id` from the block record itself, NOT
/// from a missing placement. Falling back to `FileId(0)` here (the pre-fix
/// behaviour) silently breaks the FILE_HOLDERS / HOLDER_FILES indices and the
/// watch-admin folder rollups for every initial-backup block, since those index
/// `placement.file_id`. Pack blocks carry their files in `entries` (built in file
/// order, so `entries[0]` is the same file backup used pre-A4); a Single block
/// has no file_id in the record, so reverse-look it up via its file versions.
pub(crate) fn resolve_primary_file_id(
    db: &Db,
    block: &SourceBlockRecord,
) -> anyhow::Result<viaticum_core::types::FileId> {
    use viaticum_core::types::{FileId, SourceBlockType};

    if let Some(p) = db.list_placements_for_block(&block.block_id)?.first() {
        return Ok(p.file_id);
    }
    Ok(match &block.block_type {
        SourceBlockType::Pack { entries } => {
            entries.first().map(|e| e.file_id).unwrap_or(FileId(0))
        }
        SourceBlockType::Single => crate::daemon::backup::packing::find_file_for_block(
            db,
            block.block_id,
        )
        .map(|f| f.file_id)
        .unwrap_or_else(|e| {
            tracing::warn!(
                block_id = %block.block_id,
                "resolve_primary_file_id: no file references Single block ({e}); using FileId(0)"
            );
            FileId(0)
        }),
    })
}

/// Holders excluded from a new offer for this block: Alive (already hold) and
/// Uncertain/PresumedLost (awaiting a PoS verdict — repair-i2), i.e. every placement
/// whose status `may_hold_symbols()`. The worker never overwrites such a placement
/// (INV-1). Offered/Accepted/Lost/Deleting stay candidates: Offered is an unfinished
/// delivery the worker retries (W11b), Lost holds no data.
pub(crate) fn get_existing_holder_ids(
    db: &Db,
    block_id: &SourceBlockId,
) -> anyhow::Result<ExcludedHolders> {
    let mut excluded = ExcludedHolders::default();
    for p in db.list_placements_for_block(block_id)? {
        if !p.status.may_hold_symbols() {
            continue;
        }
        if p.status == PlacementStatus::Alive {
            excluded.alive += 1;
        } else {
            excluded.awaiting_verdict += 1;
        }
        excluded.ids.insert(p.holder_id);
    }
    Ok(excluded)
}
