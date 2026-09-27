//! Drop events of the pair ledger (У-4): what counts as one, under which master it is
//! recorded, and how a tick folds and leaks the counters.
//!
//! Spec: `private/beta-planning/tasks/pair_ledger.md`, section "Спека У-4" (Д-I..Д-M);
//! intent `private/intent/4r.md` 4r-i25..i35.
//!
//! The event sites (the daemon's DropNotice handler and the two PoS paths of its
//! scheduler) ask [`drop_event_for`] whether a placement change IS an event, resolve the
//! master with [`ledger_master_for_device`] and queue the event in the SAME write
//! transaction as the placement change (`DbWriteTxn::record_drop_event`). They never write
//! the ledger: the accrual tick is its only writer, and it folds the queue with
//! [`fold_pending_drops`] after decaying the interval. Like the rest of the recorder,
//! nothing here decides anything (AC-7).

use crate::constants::PAIR_LEDGER_LAMBDA_DROP;
use crate::db::{Db, DbError};
use crate::types::{
    DeviceId, DropKind, IdentityPub, PairLedger, PendingDrops, PlacementStatus, Timestamp,
};

/// Evidence that moved a placement towards loss (У-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossCause {
    /// A signed `SymbolDropNotice` from the holder's master; evidence time = its `timestamp`
    /// (the holder's clock, under its signature).
    DropNotice,
    /// Our PoS: wrong chain hash. Evidence time = the challenge's `issued_at` (our clock).
    PosFail,
    /// Our PoS: an explicit Nack (not delivered over the mailbox today). Same evidence time.
    PosNotHeld,
    /// Our PoS: no answer within the pending timeout. Same evidence time.
    PosTimeout,
}

/// Why a loss transition was NOT recorded — for the debug line only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotCounted {
    /// The status before the change was not Alive/Uncertain (Offered, Accepted,
    /// PresumedLost, Lost, Deleting): nothing of ours was held there, or the loss of this
    /// episode was already recognised.
    PriorNotHeld,
    /// The evidence is not strictly younger than the current placement
    /// (`evidence_at <= placed_at`, whole seconds) — it belongs to an earlier episode.
    EvidenceBeforeEpisode,
    /// The cause does not produce this status (e.g. a timeout that only reached Uncertain).
    NoLossTransition,
}

/// Д-I: the ONE rule of what counts as a drop event. Pure; the three event sites call it.
///
/// `Ok(kind)` only for a placement that was HELD (`Alive`/`Uncertain`) and now left that set
/// for the status its cause produces (`DropNotice`/`PosFail`/`PosNotHeld` → `Lost`,
/// `PosTimeout` → `PresumedLost`), on evidence STRICTLY younger than `episode_started_at`
/// (the placement's `placed_at`).
///
/// Checked in this order, so the debug line names the most basic reason: the cause/status
/// pair, then the prior status, then the time.
pub fn drop_event_for(
    prior: PlacementStatus,
    new: PlacementStatus,
    cause: LossCause,
    evidence_at: Timestamp,
    episode_started_at: Timestamp,
) -> Result<DropKind, NotCounted> {
    let kind = match (cause, new) {
        (LossCause::DropNotice, PlacementStatus::Lost) => DropKind::Announced,
        (LossCause::PosFail | LossCause::PosNotHeld, PlacementStatus::Lost) => DropKind::Silent,
        (LossCause::PosTimeout, PlacementStatus::PresumedLost) => DropKind::Presumed,
        _ => return Err(NotCounted::NoLossTransition),
    };
    if !matches!(prior, PlacementStatus::Alive | PlacementStatus::Uncertain) {
        return Err(NotCounted::PriorNotHeld);
    }
    // STRICT (review of intent 2026-09-26, BLOCK-1): Timestamp is whole seconds, and at a
    // high time_scale a loss, the repair and the new Alive fit in one second — a same-second
    // notice is the OLD notice, not a new drop. Same-second genuine drops are under-counted
    // instead (the same direction as 4r-i31).
    if evidence_at <= episode_started_at {
        return Err(NotCounted::EvidenceBeforeEpisode);
    }
    Ok(kind)
}

/// Д-M: the master a drop event is recorded under — `PeerRecord::master_identity` of the
/// holder device (rule Р3 п.4), never `device_to_master` (not in the SystemState snapshot).
/// It is the same key the accrual sweep (`Db::storage_bytes_by_master`) groups by, so a
/// queued event always meets its row.
///
/// `None` when the device has no `PeerRecord` or its master is the placeholder
/// `IdentityPub([0; 32])` (not a person; the sweep drops it too).
pub fn ledger_master_for_device(
    db: &Db,
    device: &DeviceId,
) -> Result<Option<IdentityPub>, DbError> {
    Ok(db
        .get_peer(device)?
        .map(|peer| peer.master_identity)
        .filter(|master| master.0 != [0u8; 32]))
}

/// Д-K: add the folded events on top of a row whose interval has ALREADY been decayed
/// ("decay over the interval, then `+N`").
pub fn fold_pending_drops(ledger: &mut PairLedger, pending: &PendingDrops) {
    ledger.drop_ann += pending.announced as f64;
    ledger.drop_silent += pending.silent as f64;
    ledger.drop_presumed += pending.presumed as f64;
}

/// Д-L: the sim's sweep expression, literally (`sim_dynamic/engine.rs:1753-1755`:
/// `drop *= (1 − λ_drop·dt).max(0)`), so that at the same `dt` the two agree bit for bit.
/// No kernel function exists for it (the sim does it inline), and the kernel is not touched.
pub(super) fn leak_drop_counter(count: f64, dt_days: f64) -> f64 {
    count * (1.0 - PAIR_LEDGER_LAMBDA_DROP * dt_days).max(0.0)
}
