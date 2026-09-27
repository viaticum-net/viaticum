//! 4R pair-ledger recorder (У-2) — the calendar-time integrator.
//!
//! Spec: `private/beta-planning/tasks/pair_ledger.md`. У-1 landed the storage
//! ([`crate::types::PairLedger`] + the `pair_ledger` table + DR carriage); this module is
//! the part that actually accrues, so that when 4R is wired in months from now it starts
//! on warm series instead of zeros. A leaky integral over months cannot be back-computed —
//! that, and nothing else, is why the recorder ships ahead of the decisions.
//!
//! **It decides nothing.** Every value written here is inert: no placement, eviction,
//! offer-admission or PoS-cadence path reads a `PairLedger` (AC-7). The guarantee is not
//! structural — `Db` is reachable from everywhere — it is simply that the only readers are
//! this module and the SystemState snapshot/restore pair.
//!
//! # What the recorded series IS (read before comparing it to anything)
//!
//! Each tick advances `dG/dt = V_conf − λG` where `V_conf` is read from this node's own
//! bookkeeping at the END of the interval:
//!
//! * "they store for us" = `symbol_count × t` over placements at any device of that master
//!   that are CONFIRMED now: status `Alive` AND a PoS pass no older than
//!   [`crate::constants::PAIR_LEDGER_CONFIRMATION_WINDOW_SECS`] (14 d 3 h) on the scaled
//!   clock ([`crate::types::SymbolPlacement::confirmed_at`], У-3, Д-F = A / Д-G). `Alive`
//!   alone is only our BELIEF — a placement turns `Alive` on `SymbolStored`, before any
//!   PoS — and it is logged next to the confirmed number but charges nothing. The same
//!   confirmed flow charges the capital `G_they`, the depth `D`, the ratchet `v_dem` and
//!   the run `(V0, τ0)`: the model has one `V_conf` (`four_r/mod.rs:270-273`).
//! * "we store for them" = `total_bytes` over `Active` holdings owned by that master —
//!   the same number `refresh_peer_storage_bytes` writes into `PeerRecord`. Not confirmed
//!   by anything (whether the owner is alive is a separate question, nobody reads this
//!   axis in v1).
//!
//! **The invented-service residue that remains, so it is not mistaken for a rounding
//! error.** A holder that dies keeps counting as confirmed until its last pass ages out of
//! the window: at most 14 d 3 h after that pass, ≈10.6 d on average (death uniform inside
//! the weekly PoS cycle) — ≈18 % of `τ = 60 days` on the fast capital. It no longer waits
//! for the PoS state machine (`Alive → Uncertain` needs the next challenge to be issued and
//! then to time out, ≈21 d worst case). The price of the window on the other side: an
//! honest holder that surfaces less often than the window allows blinks out of
//! confirmation (Д-G), and on runs above `time_scale ≈ 3600` the one-second timer floor
//! inflates the PoS cycle in scaled days, so "surfaces weekly" is covered only for an
//! always-on holder there.
//!
//! And a volume measured now is only charged over the part of the interval this node was
//! actually watching: the last [`observed_window_days`]. Everything before that is
//! integrated at `V_conf = 0` — see [`accrue_interval`]. The decay applies to the whole
//! interval either way, which is what the simulator does (`sim_dynamic/engine.rs:1861`:
//! `accrual = if passed { volume·dt } else { 0.0 }`, decay unconditional). Comparability
//! with the model is the only reason this layer exists early, so a charge for hours
//! nobody observed would defeat its own purpose.
//!
//! Read the two halves as different predicates, both now in the recorder: the
//! confirmation window is the PEER answering (the sim's `passed` is
//! `c.holder_surfaced`, `sim_dynamic/engine.rs:1855`), while the observed window is OUR
//! uptime.
//!
//! **Drop events (У-4)** — see [`drops`]: the placement-loss sites queue events in the
//! `pair_ledger_pending_drops` outbox inside their own transaction, and the tick folds them
//! into `drop_ann` / `drop_silent` / `drop_presumed` in ITS transaction, after decaying the
//! interval. The counters leak at `λ_drop` (1/56 day⁻¹) inside the same sub-step loop as
//! everything else.
//!
//! **Output of the writer, not a reader.** [`PairLedgerRecorder::tick_report`] returns the
//! rows it has just written so the scheduler can print one `pair-ledger row` debug line
//! per pair (target `viaticum::ledger`). That line is the only way an operator — or
//! `experiments/local_ledger_test.sh` — sees the ledger; nothing branches on it.
//!
//! # Which volume charges which axis
//!
//! [`crate::types::PairLedger`]'s field names are ABSOLUTE (`gb_days_they_store_for_us`,
//! `gb_days_we_store_for_them`), unlike the kernel's role-relative ones, so this mapping
//! is now a tautology rather than a puzzle:
//!
//! | ledger field | `V_conf` |
//! |---|---|
//! | `gb_days_they_store_for_us` | [`MasterStorageBytes::they_store_for_us_confirmed`] |
//! | `gb_days_we_store_for_them` | [`MasterStorageBytes::we_store_for_them`] |
//! | `depth_of_their_service` | the SAME flow as the first row |
//! | `v_dem`, `observed_volume`, `observed_tau` | the SAME flow as the first row |
//!
//! The third row is the one worth stating a reason for, because the kernel's naming
//! tempted two earlier passes into the transpose. `D` is charged by the counterparty's
//! service to us because that is the pair κ_O consumes: the kernel's own words for its
//! capital term are "the eviction seat: the owner `O`'s reciprocal service to ME, the
//! holder" (`four_r/mod.rs:338-340`), with an explicit "this is the direction the old doc
//! comment inverted" (`four_r/mod.rs:697-703`); the sim charges `g_ho` and `depth_ho` in
//! one statement and reads both back from that same cell
//! (`sim_dynamic/engine.rs:1884-1886`, `1972-1979`). A depth charged by our OWN service
//! would make the loyalty floor read "I keep your data because I have already kept your
//! data" — a sunk cost, not reciprocity.
//!
//! # Units
//!
//! gb·days everywhere, `gb = bytes / BYTES_PER_GB` (2^30) and days from
//! [`crate::types::PairLedger::elapsed_days`] (which applies `time_scale`). This is the
//! same gigabyte and the same scaled day as [`crate::db::Db::stored_for_peer_gb_days`] —
//! W-3 in the spec: a series in a different unit looks plausible and compares to nothing.

#[cfg(test)]
mod drop_tests;
mod drops;
#[cfg(test)]
mod tests;

pub use drops::{
    LossCause, NotCounted, drop_event_for, fold_pending_drops, ledger_master_for_device,
};

use std::collections::HashMap;

use crate::constants::{
    BYTES_PER_GB, PAIR_LEDGER_LAMBDA, PAIR_LEDGER_LAMBDA_DEM, PAIR_LEDGER_LAMBDA_DROP,
    PAIR_LEDGER_LAMBDA_SLOW, PAIR_LEDGER_MAX_LAMBDA_DT, PAIR_LEDGER_OBSERVED_WINDOW_TICKS,
    PAIR_LEDGER_TICK_SECS, SECS_PER_DAY,
};
use crate::db::{Db, DbError, MasterStorageBytes};
use crate::four_r::{update_capital, update_depth, update_v_dem};
use crate::types::{IdentityPub, PairLedger, Timestamp};
use drops::leak_drop_counter;

/// Ceiling on Euler sub-steps for ONE accrual call.
///
/// Only a corrupt clock can reach it: at the 28-day sub-step this is ≈7700 years of
/// simulated calendar. It is not a truncation of accrual — after ~100·τ the integrator has
/// reached `G* = V_conf/λ` to f64 precision and further steps change nothing — it exists so
/// that a nonsense `last_update` cannot spin the loop for hours. When it does bite, the
/// days it could not cover are reported rather than dropped in silence
/// ([`SubStepPlan::uncovered_days`], [`AccrualStats::truncated`]).
const MAX_SUB_STEPS: u32 = 100_000;

/// Errors from the recorder. Only the database can fail here; the integrator itself is
/// total (a degenerate interval accrues nothing rather than erroring).
#[derive(Debug, thiserror::Error)]
pub enum PairLedgerError {
    #[error("db: {0}")]
    Db(#[from] DbError),
}

/// What one [`PairLedgerRecorder::tick`] did, per master. Reported for logging and tests;
/// nothing branches on it.
///
/// Not `Eq`: [`AccrualStats::uncovered_days`] is a magnitude, and a count of truncated rows
/// without the size of the truncation is not enough to act on.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct AccrualStats {
    /// Rows advanced over a positive interval.
    pub accrued: usize,
    /// Rows whose clock had never started: seeded with `last_update = now`, integrating
    /// nothing (there is no interval to integrate over yet).
    pub seeded: usize,
    /// Rows left untouched because the clock did not move (repeat tick within the same
    /// second, or a backward wall-clock jump).
    pub idle: usize,
    /// Rows where part of the interval fell outside the observed window and was charged as
    /// pure decay (`V_conf = 0`) — a daemon outage, a suspended laptop, or a first tick
    /// after a long gap.
    pub with_unobserved_gap: usize,
    /// Rows where the interval was so long that the sub-step ceiling cut it short. Only a
    /// corrupt clock gets here (see `MAX_SUB_STEPS`); every axis is on its steady state
    /// long before, but the count is surfaced rather than swallowed.
    pub truncated: usize,
    /// Days summed over those rows that the ceiling refused to integrate. A count alone
    /// cannot tell "the clock is one year off" from "the clock is 2^40 seconds off", and
    /// the second is a different diagnosis.
    pub uncovered_days: f64,
    /// Rows integrated this tick whose believed volume was > 0 but confirmed volume was 0 —
    /// the Д-D gap made visible (fresh placements before their first pass, a holder that
    /// accepted and never answers, stalled PoS wiring, SystemState blocks). Logged only;
    /// nothing branches on it.
    pub believed_not_confirmed: usize,
    /// Drop events folded into the ledger this tick, all kinds, all rows (У-4). Logged only.
    pub drop_events_folded: u64,
}

/// One ACCRUED row as this tick left it — for the per-row log line only (У-3, Part 0).
///
/// Output of the writer, not a reader: nothing may branch on it (AC-7). Every value is the
/// one written to the `pair_ledger` table in the same tick, or the volume the tick charged.
#[derive(Debug, Clone, PartialEq)]
pub struct LedgerRowReport {
    pub master: IdentityPub,
    /// Interval this tick integrated, in scaled days, dark part included
    /// ([`PairLedger::elapsed_days`]).
    pub dt_days: f64,
    /// [`Volumes::they_store_for_us`], gb — belief (`Alive`), charges nothing.
    pub believed_gb: f64,
    /// [`Volumes::they_store_for_us_confirmed`], gb — `V_conf` of their service.
    pub confirmed_gb: f64,
    pub v_dem: f64,
    /// `gb_days_they_store_for_us`.
    pub g_they: f64,
    /// `depth_of_their_service`.
    pub depth: f64,
    pub observed_volume: f64,
    pub observed_tau: f64,
    /// The three drop counters AFTER this tick's decay and fold (У-4).
    pub drop_ann: f64,
    pub drop_silent: f64,
    pub drop_presumed: f64,
    /// Events folded into this row on this tick, by kind (У-4) — what the outbox held for
    /// this master when the tick took it.
    pub ann_events: u32,
    pub silent_events: u32,
    pub presumed_events: u32,
}

/// What one [`PairLedgerRecorder::tick_report`] did: the counters plus one
/// [`LedgerRowReport`] per ACCRUED row.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TickReport {
    pub stats: AccrualStats,
    /// Rows accrued this tick, in master key order. Seeded and idle rows are not reported
    /// (nothing was integrated for them).
    pub rows: Vec<LedgerRowReport>,
}

/// Accrues [`PairLedger`] rows from the daemon's own storage counters.
pub struct PairLedgerRecorder {
    db: Db,
}

impl PairLedgerRecorder {
    pub fn new(db: Db) -> Self {
        PairLedgerRecorder { db }
    }

    /// One accrual tick over every peer master known to this node.
    ///
    /// `my_master` is this node's own master identity and is SKIPPED: cluster siblings are
    /// ordinary rows in PEERS carrying our own master identity (`processor/peer.rs:80-95`
    /// upserts a record for every authenticated device), so without the guard the sweep
    /// would open an economic ledger of ourselves against ourselves. The placeholder
    /// identity `IdentityPub([0; 32])` is skipped by [`Db::storage_bytes_by_master`] for a
    /// different reason — it is not a person at all.
    ///
    /// The tick is idempotent in the clock, not in the call count (AC-2′): the interval
    /// integrated is `now − last_update`, so a second tick at the same `now` changes
    /// nothing. What that interval BUYS is a different question — the decay covers all of
    /// it, the measured volume only its last [`observed_window_days`] (Д-A). All rows are
    /// written in a single transaction; masters arrive in key order, so nothing depends on
    /// insertion history.
    ///
    /// Cost is one pass over PEERS, SYMBOL_PLACEMENTS, HOLDINGS and PAIR_LEDGER for the
    /// whole sweep, not per master — the tick runs synchronously inside the scheduler's
    /// `select!`, so a per-master query here would stall the daemon's timers (see
    /// [`Db::storage_bytes_by_master`]).
    ///
    /// Signature kept from У-2; delegates to [`PairLedgerRecorder::tick_report`], so the
    /// daemon and the tests run ONE code path.
    pub fn tick(
        &self,
        my_master: &IdentityPub,
        now: Timestamp,
        time_scale: u64,
    ) -> Result<AccrualStats, PairLedgerError> {
        self.tick_report(my_master, now, time_scale)
            .map(|r| r.stats)
    }

    /// [`PairLedgerRecorder::tick`], plus what it wrote: one [`LedgerRowReport`] per
    /// accrued row, filled from the very ledger value handed to `upsert_pair_ledgers`.
    ///
    /// Per accrued row: [`accrue_interval`] (dark part, then the observed tail — `G`, `D`,
    /// the `v_dem` ratchet and the leak of the drop counters), then [`observe_run`] over the
    /// observed tail only (the run `(V0, τ0)`, Д-H), then the drop events queued for that
    /// master since the last fold ([`fold_pending_drops`], У-4 Д-K: decay first, then `+N`).
    /// A seeded row and an idle row touch neither the ratchet nor the run, and leave their
    /// queued events for the next accruing tick (a seeded row is not reported, so an event
    /// folded there would never reach the log).
    ///
    /// Taking the queue and writing the rows is ONE write transaction: an event is folded
    /// into exactly one tick, and a failed commit leaves it queued (Д-K, redb serializes
    /// writers — A7).
    pub fn tick_report(
        &self,
        my_master: &IdentityPub,
        now: Timestamp,
        time_scale: u64,
    ) -> Result<TickReport, PairLedgerError> {
        let observed_days = observed_window_days(time_scale);
        let mut stats = AccrualStats::default();
        let mut reports: Vec<LedgerRowReport> = Vec::new();
        // (master, ledger, index of its report — `Some` only for an ACCRUED row, the only
        // kind that folds drop events)
        let mut rows: Vec<(IdentityPub, PairLedger, Option<usize>)> = Vec::new();

        // One read of the ledger table for the whole sweep, for the same reason the volumes
        // come from one pass: `get_pair_ledger` per master would open a read transaction per
        // master inside the scheduler's `select!`.
        let mut previous: HashMap<[u8; 32], PairLedger> = self
            .db
            .list_pair_ledgers()?
            .into_iter()
            .map(|(master, ledger)| (master.0, ledger))
            .collect();

        for volumes in self.db.storage_bytes_by_master(now, time_scale)? {
            if volumes.master == *my_master {
                continue;
            }
            let mut ledger = previous.remove(&volumes.master.0).unwrap_or_default();
            match ledger.elapsed_days(now, time_scale) {
                // The clock has never started. Seed it; integrating from the unix epoch
                // would invent a history this pair does not have.
                None => {
                    ledger.last_update = Some(now);
                    rows.push((volumes.master, ledger, None));
                    stats.seeded += 1;
                }
                // Clock did not move (same second, or wall clock went backwards — then
                // `elapsed_days` reports 0.0 rather than a negative that would DIScharge
                // the integrator). Nothing accrued and nothing written: rewriting an
                // identical row would only churn the DB and, on a backward jump, would
                // rewind `last_update` and re-charge the interval on the next tick.
                Some(dt_days) if dt_days <= 0.0 => stats.idle += 1,
                Some(dt_days) => {
                    let gb = Volumes::from_bytes(&volumes);
                    let outcome = accrue_interval(&mut ledger, &gb, dt_days, observed_days);
                    observe_run(
                        &mut ledger,
                        gb.they_store_for_us_confirmed,
                        outcome.observed_days,
                    );
                    ledger.last_update = Some(now);
                    stats.accrued += 1;
                    if outcome.unobserved_days > 0.0 {
                        stats.with_unobserved_gap += 1;
                    }
                    if outcome.uncovered_days > 0.0 {
                        stats.truncated += 1;
                        stats.uncovered_days += outcome.uncovered_days;
                    }
                    if volumes.they_store_for_us > 0 && volumes.they_store_for_us_confirmed == 0 {
                        stats.believed_not_confirmed += 1;
                    }
                    reports.push(LedgerRowReport {
                        master: volumes.master,
                        dt_days,
                        believed_gb: gb.they_store_for_us,
                        confirmed_gb: gb.they_store_for_us_confirmed,
                        v_dem: ledger.v_dem,
                        g_they: ledger.gb_days_they_store_for_us,
                        depth: ledger.depth_of_their_service,
                        observed_volume: ledger.observed_volume,
                        observed_tau: ledger.observed_tau,
                        // Filled after the fold, inside the write transaction below.
                        drop_ann: ledger.drop_ann,
                        drop_silent: ledger.drop_silent,
                        drop_presumed: ledger.drop_presumed,
                        ann_events: 0,
                        silent_events: 0,
                        presumed_events: 0,
                    });
                    rows.push((volumes.master, ledger, Some(reports.len() - 1)));
                }
            }
        }

        if !rows.is_empty() {
            let mut txn = self.db.write_txn()?;
            for (master, ledger, report_index) in &mut rows {
                if let Some(i) = *report_index {
                    let pending = txn.take_pending_drops(master)?;
                    fold_pending_drops(ledger, &pending);
                    stats.drop_events_folded += pending.total();
                    let report = &mut reports[i];
                    report.drop_ann = ledger.drop_ann;
                    report.drop_silent = ledger.drop_silent;
                    report.drop_presumed = ledger.drop_presumed;
                    report.ann_events = pending.announced;
                    report.silent_events = pending.silent;
                    report.presumed_events = pending.presumed;
                }
                txn.upsert_pair_ledger(master, ledger)?;
            }
            txn.commit()?;
        }
        Ok(TickReport {
            stats,
            rows: reports,
        })
    }
}

/// The volumes of one pair, in GB, as read at the end of an interval.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Volumes {
    /// GB on `Alive` placements of this master (belief). Diagnostics only under Д-F = A:
    /// logged, never charged.
    pub they_store_for_us: f64,
    /// GB of those placements confirmed by a fresh PoS pass — `V_conf` of their service to
    /// us. Charges `G_they`, `D`, `v_dem` and the run `(V0, τ0)`.
    pub they_store_for_us_confirmed: f64,
    /// GB we keep for this master (`Active` holdings).
    pub we_store_for_them: f64,
}

impl Volumes {
    /// Convert at the write boundary, never inside the ledger (see the units section of
    /// [`crate::types::PairLedger`] — raw bytes parked in a gb·day field cannot be
    /// repaired after the fact).
    pub fn from_bytes(bytes: &MasterStorageBytes) -> Self {
        Volumes {
            they_store_for_us: bytes.they_store_for_us as f64 / BYTES_PER_GB,
            they_store_for_us_confirmed: bytes.they_store_for_us_confirmed as f64 / BYTES_PER_GB,
            we_store_for_them: bytes.we_store_for_them as f64 / BYTES_PER_GB,
        }
    }
}

/// What [`accrue_interval`] did with an interval, for the tick's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct IntervalOutcome {
    /// Days integrated at `V_conf = 0` because they lie outside the observed window.
    pub unobserved_days: f64,
    /// Days of the observed tail — charged with the measured volumes, and the only days
    /// [`observe_run`] may add to `τ0`. `dt_days − unobserved_days`, 0 for a degenerate
    /// interval.
    pub observed_days: f64,
    /// Days the sub-step ceiling refused to integrate at all (corrupt clock only).
    pub uncovered_days: f64,
}

/// Advance one ledger over `dt_days`, charging the measured volumes only over the last
/// `observed_days` of it (Д-A, 2026-08-09).
///
/// The volumes are read at the END of the interval, so they are evidence about its tail
/// and about nothing else. A daemon that was down for a week and comes back to a peer
/// holding 40 GB has no ground to record 280 gb·days of service: it did not run a single
/// PoS challenge in that week, and the model's `G` is fed by confirmed service. So the
/// interval is cut in two and integrated OLDEST FIRST:
///
/// 1. `dt_days − observed_days` at `V_conf = 0` — pure decay, both capitals and the depth;
/// 2. the remaining `≤ observed_days` at the measured volumes.
///
/// Order matters: the unobserved stretch happened first, and decaying after charging would
/// shrink the fresh evidence instead of the stale capital. The same holds for the `v_dem`
/// ratchet (AC-3f): the dark stretch eases the OLD demonstrated scale down before the tail
/// can snap it back up to the confirmed volume.
///
/// The run `(V0, τ0)` is not advanced here — that is [`observe_run`], called by the tick
/// with [`IntervalOutcome::observed_days`], so this function stays "the Д-A split of
/// [`accrue`]" and nothing else.
///
/// A non-positive or non-finite interval accrues nothing. `last_update` is NOT touched
/// here: the clock belongs to the caller, which knows whether the row is being persisted.
pub fn accrue_interval(
    ledger: &mut PairLedger,
    volumes: &Volumes,
    dt_days: f64,
    observed_days: f64,
) -> IntervalOutcome {
    if dt_days.is_nan() || dt_days <= 0.0 {
        return IntervalOutcome::default();
    }
    let observed = dt_days.min(observed_days.max(0.0));
    let unobserved = dt_days - observed;

    let mut outcome = IntervalOutcome {
        unobserved_days: unobserved,
        observed_days: observed,
        uncovered_days: 0.0,
    };
    if unobserved > 0.0 {
        let dark = Volumes {
            they_store_for_us: 0.0,
            they_store_for_us_confirmed: 0.0,
            we_store_for_them: 0.0,
        };
        outcome.uncovered_days += accrue(ledger, &dark, unobserved);
    }
    if observed > 0.0 {
        outcome.uncovered_days += accrue(ledger, volumes, observed);
    }
    outcome
}

/// Advance the run `(V0, τ0)` = the current unbroken run of CONFIRMED service by this pair
/// to us (Д-H) over the observed tail of an interval.
///
/// * `confirmed_gb > 0`: `τ0 += observed_days`; `V0` = the smallest confirmed volume of the
///   run (a new run — `τ0 == 0` — starts at this volume, not at `min(0, V)`).
/// * `confirmed_gb == 0` on an observed tail: the run ends, `V0 = τ0 = 0`.
///
/// `τ0` grows by OBSERVED days only; a dark stretch neither adds to it nor ends the run by
/// itself (the tick only ever hands this function the observed tail). If the peer's last
/// pass is still inside the confirmation window after our outage, the run continues; if
/// not, the first observed tail ends it (4r-i4 / 4r-i6).
///
/// Policy, not kernel — so it lives here and not in [`accrue`] (the AC-1/AC-3b function
/// stays pure kernel). A non-positive or NaN `observed_days` changes nothing.
pub fn observe_run(ledger: &mut PairLedger, confirmed_gb: f64, observed_days: f64) {
    if observed_days.is_nan() || observed_days <= 0.0 {
        return;
    }
    if confirmed_gb > 0.0 {
        ledger.observed_volume = if ledger.observed_tau > 0.0 {
            ledger.observed_volume.min(confirmed_gb)
        } else {
            confirmed_gb
        };
        ledger.observed_tau += observed_days;
    } else {
        ledger.observed_volume = 0.0;
        ledger.observed_tau = 0.0;
    }
}

/// The period of the accrual timer in REAL seconds — the one place that formula lives.
///
/// `(PAIR_LEDGER_TICK_SECS / scale).max(1)`: integer division with a one-second floor,
/// because that is what `tokio::time::interval` gets in
/// `daemon::scheduler::Scheduler::run`. Both readers must use this function, or the window
/// stops being a whole number of ticks (BLOCK-1, third gate): the scheduler to build its
/// timer, [`observed_window_days`] to size the window against it.
///
/// Note what the floor does above `scale = 3600`: the timer cannot go below one real
/// second, so further acceleration no longer shortens the period — it lengthens the tick
/// in SIMULATED time. At `scale = 100_000` the daemon ticks once a real second and each
/// tick spans 100_000 simulated seconds ≈ 1.16 simulated days.
pub fn tick_interval_secs(time_scale: u64) -> u64 {
    (PAIR_LEDGER_TICK_SECS / time_scale.max(1)).max(1)
}

/// The observed window in DAYS of the SCALED clock, i.e. in the same unit
/// [`crate::types::PairLedger::elapsed_days`] returns.
///
/// [`PAIR_LEDGER_OBSERVED_WINDOW_TICKS`] tick periods, where one tick period in scaled
/// seconds is `tick_interval_secs(scale) · scale` — the daemon's real-time period
/// multiplied back by the scale the interval was measured in.
///
/// The two `time_scale` factors cancel EXACTLY only when the scale divides
/// `PAIR_LEDGER_TICK_SECS`. Otherwise the integer division truncates, and in two opposite
/// directions:
///
/// * `scale < 3600` and not a divisor — the tick is slightly SHORTER in simulated time than
///   an hour (at 1000: `3 · 1000 = 3000` s, so the window is 2.5 simulated hours, not 3);
/// * `scale > 3600` — the one-second timer floor makes the tick MUCH LONGER (at 100_000:
///   100_000 s ≈ 1.16 simulated days, window ≈ 3.5 simulated days).
///
/// The second direction is what BLOCK-1 was — a window frozen at 10_800 seconds covered a
/// ninth of one tick there. See [`PAIR_LEDGER_OBSERVED_WINDOW_TICKS`] for the numbers and
/// for the two prices of the tick-period unit.
///
/// Computed in `f64` rather than `u64` because the result is fractional (days), not
/// because of overflow: `tick_interval_secs(scale) · scale` equals `max(3600, scale)` and
/// so never overflows. (What COULD overflow is `3 · scale` past `u64::MAX / 3` — a
/// different product, and `--time-scale` is an unvalidated CLI argument.)
pub fn observed_window_days(time_scale: u64) -> f64 {
    let tick_scaled_secs = tick_interval_secs(time_scale) as f64 * time_scale.max(1) as f64;
    PAIR_LEDGER_OBSERVED_WINDOW_TICKS as f64 * tick_scaled_secs / SECS_PER_DAY as f64
}

/// Advance one ledger over `dt_days` at CONSTANT volumes; returns the days the sub-step
/// ceiling could not cover (0.0 in every non-corrupt case).
///
/// Both volumes are gb; `dt_days` is days. The two capitals relax through
/// [`update_capital`] at `λ`, the depth through [`update_depth`] at `λ_slow`, the
/// demonstrated scale through [`update_v_dem`] at `λ_dem`, over the sub-steps of
/// [`sub_steps`] — so the result is exactly the kernel applied `n` times, not an
/// approximation of it (AC-1, AC-3b). The three drop counters leak on the same sub-steps
/// at `λ_drop` through a literal copy of the simulator's sweep expression (У-4, Д-L — there
/// is no kernel function for it); drop EVENTS are never added here.
///
/// "Their service to us" — `G_they`, `D` and `v_dem` — is charged by the CONFIRMED volume
/// ([`Volumes::they_store_for_us_confirmed`], Д-F = A); the believed volume is not read
/// here at all.
///
/// The NaN guard is defence in depth, not a live path: the only NON-TEST caller in the
/// workspace is [`accrue_interval`], which rejects NaN first, and the interval it derives
/// from `elapsed_days` cannot be NaN. (The tests call this directly in about a dozen
/// places — that is the point of it being `pub`: AC-1 compares the integrator against the
/// kernel, separately from the Д-A policy layered on top.) The guard stays because a NaN
/// would poison every accumulator permanently and silently.
pub fn accrue(ledger: &mut PairLedger, volumes: &Volumes, dt_days: f64) -> f64 {
    if dt_days.is_nan() || dt_days <= 0.0 {
        return 0.0;
    }
    let plan = sub_steps(dt_days);
    // Д-F = A. (Д-F = B would read `volumes.they_store_for_us` here — for G and D only.)
    let their_flow = volumes.they_store_for_us_confirmed;
    for _ in 0..plan.count {
        ledger.gb_days_they_store_for_us = update_capital(
            ledger.gb_days_they_store_for_us,
            their_flow,
            PAIR_LEDGER_LAMBDA,
            plan.step_days,
        );
        ledger.gb_days_we_store_for_them = update_capital(
            ledger.gb_days_we_store_for_them,
            volumes.we_store_for_them,
            PAIR_LEDGER_LAMBDA,
            plan.step_days,
        );
        // Same flow as the first capital — see the module header for why the depth is
        // charged by the peer's service to us and not by ours to them.
        ledger.depth_of_their_service = update_depth(
            ledger.depth_of_their_service,
            their_flow,
            plan.step_days,
            PAIR_LEDGER_LAMBDA_SLOW,
        );
        // A.3: the ratchet always reads the CONFIRMED volume (Д-F part 1 — a definition,
        // not a fork: "max PROVEN retained volume").
        ledger.v_dem = update_v_dem(
            ledger.v_dem,
            volumes.they_store_for_us_confirmed,
            plan.step_days,
            PAIR_LEDGER_LAMBDA_DEM,
        );
        // У-4, Д-L: the drop counters leak on every sub-step of the whole interval, dark part
        // included (decay is unconditional, like the sim). Not a kernel call — the sim does it
        // inline and the kernel has no drop-decay function. Events are added by the tick
        // after this, never here.
        ledger.drop_ann = leak_drop_counter(ledger.drop_ann, plan.step_days);
        ledger.drop_silent = leak_drop_counter(ledger.drop_silent, plan.step_days);
        ledger.drop_presumed = leak_drop_counter(ledger.drop_presumed, plan.step_days);
    }
    plan.uncovered_days
}

/// How one interval is split into explicit-Euler sub-steps.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SubStepPlan {
    /// Number of kernel applications.
    pub count: u32,
    /// Length of each, in days.
    pub step_days: f64,
    /// Days of the requested interval this plan does NOT cover. Non-zero only when the
    /// `MAX_SUB_STEPS` ceiling bites, i.e. for a clock so broken that every axis reached
    /// its steady state thousands of years earlier in the same call.
    pub uncovered_days: f64,
}

/// Split `dt_days` into equal explicit-Euler sub-steps with
/// `λ·step ≤ PAIR_LEDGER_MAX_LAMBDA_DT` for ALL FOUR leak rates (`λ`, `λ_slow`, `λ_dem`,
/// `λ_drop`; the binding one is the fastest, `λ_drop = 1/56` since У-4, so the step is 28
/// days — it was 30 while `λ` was the fastest). One plan for every leak rather than a
/// separate one for the counters: two partitions of one interval would be more code for
/// the same result, and "`λ·step ≤ 0.5` for EACH leak" is the honest invariant (Д-L).
///
/// This is W-2 of the spec. [`crate::types::PairLedger::elapsed_days`] deliberately returns
/// an UNCLAMPED interval, because clamping a three-month outage would silently throw the
/// accrual away. Handing that interval to the kernel in one step is equally wrong in the
/// other direction: the Euler multiplier `(1 − λΔt)` turns negative past `Δt = 60` days, so
/// a pair that stopped storing would be charged a large NEGATIVE capital on the first tick
/// after the outage. Splitting is the only answer that neither truncates nor inverts.
pub fn sub_steps(dt_days: f64) -> SubStepPlan {
    let lambda_max = PAIR_LEDGER_LAMBDA
        .max(PAIR_LEDGER_LAMBDA_SLOW)
        .max(PAIR_LEDGER_LAMBDA_DEM)
        .max(PAIR_LEDGER_LAMBDA_DROP);
    let max_step = PAIR_LEDGER_MAX_LAMBDA_DT / lambda_max;
    if dt_days <= max_step {
        return SubStepPlan {
            count: 1,
            step_days: dt_days,
            uncovered_days: 0.0,
        };
    }
    let wanted = (dt_days / max_step).ceil();
    if wanted >= MAX_SUB_STEPS as f64 {
        // Corrupt clock (see MAX_SUB_STEPS): integrate the leading ≈7700 years, by which
        // point every axis sits on its steady state, and report the rest as uncovered.
        let covered = MAX_SUB_STEPS as f64 * max_step;
        return SubStepPlan {
            count: MAX_SUB_STEPS,
            step_days: max_step,
            uncovered_days: (dt_days - covered).max(0.0),
        };
    }
    let count = wanted as u32;
    SubStepPlan {
        count,
        step_days: dt_days / count as f64,
        uncovered_days: 0.0,
    }
}
