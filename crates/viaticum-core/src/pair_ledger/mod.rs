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
//! * "they store for us" = `symbol_count × t` over placements in status `Alive` at any
//!   device of that master. `Alive` is our belief, maintained by the PoS state machine:
//!   a holder that stops answering stays `Alive` until challenges time out and demote it
//!   to `Uncertain`/`PresumedLost`. So the series is **placement-belief-weighted**, and
//!   calling it "PoS-confirmed" would overstate it by exactly the detection latency
//!   (Д-D — an honest confirmation signal from `pos_weekly` or from the placement
//!   transitions is У-3's problem, recorded as an open item in the spec).
//! * "we store for them" = `total_bytes` over `Active` holdings owned by that master —
//!   the same number `refresh_peer_storage_bytes` writes into `PeerRecord`.
//!
//! **The size of the Д-D residue, so it is not mistaken for a rounding error.** A holder
//! that dies keeps charging BOTH axes and the depth at full volume until its placements
//! leave `Alive`, which needs one challenge to be issued (cadence
//! `POS_BASE_CHALLENGES_PER_WEEK = 1`, so up to a week of waiting) and then to time out
//! (`POS_CHALLENGE_PENDING_TIMEOUT_SECS` = 14 d 2 h; `POS_CONSECUTIVE_MISS_UNCERTAIN = 1`,
//! so the first timeout is enough). That is ≈2-3 weeks of invented service: ≈⅓ of
//! `τ = 60 days` on the fast capitals and ≈10 % of `τ_slow = 180 days` on the depth.
//! Nothing in the observed-window split below reduces it — the window is about whether
//! THIS daemon was awake, not about whether the PEER was alive.
//!
//! And a volume measured now is only charged over the part of the interval this node was
//! actually watching: the last [`observed_window_days`]. Everything before that is
//! integrated at `V_conf = 0` — see [`accrue_interval`]. The decay applies to the whole
//! interval either way, which is what the simulator does (`sim_dynamic/engine.rs:1861`:
//! `accrual = if passed { volume·dt } else { 0.0 }`, decay unconditional). Comparability
//! with the model is the only reason this layer exists early, so a charge for hours
//! nobody observed would defeat its own purpose.
//!
//! Read the two halves as different predicates and the pair is covered from neither side
//! alone: the simulator's `passed` is the PEER answering (`sim_dynamic/engine.rs:1855`,
//! `let passed = c.holder_surfaced`), while the window is OUR uptime. Д-D is the gap
//! between them and it stays open until У-3.
//!
//! # Which volume charges which axis
//!
//! [`crate::types::PairLedger`]'s field names are ABSOLUTE (`gb_days_they_store_for_us`,
//! `gb_days_we_store_for_them`), unlike the kernel's role-relative ones, so this mapping
//! is now a tautology rather than a puzzle:
//!
//! | ledger field | `V_conf` |
//! |---|---|
//! | `gb_days_they_store_for_us` | [`MasterStorageBytes::they_store_for_us`] |
//! | `gb_days_we_store_for_them` | [`MasterStorageBytes::we_store_for_them`] |
//! | `depth_of_their_service` | the SAME flow as the first row |
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
mod tests;

use std::collections::HashMap;

use crate::constants::{
    BYTES_PER_GB, PAIR_LEDGER_LAMBDA, PAIR_LEDGER_LAMBDA_SLOW, PAIR_LEDGER_MAX_LAMBDA_DT,
    PAIR_LEDGER_OBSERVED_WINDOW_TICKS, PAIR_LEDGER_TICK_SECS, SECS_PER_DAY,
};
use crate::db::{Db, DbError, MasterStorageBytes};
use crate::four_r::{update_capital, update_depth};
use crate::types::{IdentityPub, PairLedger, Timestamp};

/// Ceiling on Euler sub-steps for ONE accrual call.
///
/// Only a corrupt clock can reach it: at the 30-day sub-step this is 8000 years of
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
    pub fn tick(
        &self,
        my_master: &IdentityPub,
        now: Timestamp,
        time_scale: u64,
    ) -> Result<AccrualStats, PairLedgerError> {
        let observed_days = observed_window_days(time_scale);
        let mut stats = AccrualStats::default();
        let mut rows: Vec<(IdentityPub, PairLedger)> = Vec::new();

        // One read of the ledger table for the whole sweep, for the same reason the volumes
        // come from one pass: `get_pair_ledger` per master would open a read transaction per
        // master inside the scheduler's `select!`.
        let mut previous: HashMap<[u8; 32], PairLedger> = self
            .db
            .list_pair_ledgers()?
            .into_iter()
            .map(|(master, ledger)| (master.0, ledger))
            .collect();

        for volumes in self.db.storage_bytes_by_master()? {
            if volumes.master == *my_master {
                continue;
            }
            let mut ledger = previous.remove(&volumes.master.0).unwrap_or_default();
            match ledger.elapsed_days(now, time_scale) {
                // The clock has never started. Seed it; integrating from the unix epoch
                // would invent a history this pair does not have.
                None => {
                    ledger.last_update = Some(now);
                    rows.push((volumes.master, ledger));
                    stats.seeded += 1;
                }
                // Clock did not move (same second, or wall clock went backwards — then
                // `elapsed_days` reports 0.0 rather than a negative that would DIScharge
                // the integrator). Nothing accrued and nothing written: rewriting an
                // identical row would only churn the DB and, on a backward jump, would
                // rewind `last_update` and re-charge the interval on the next tick.
                Some(dt_days) if dt_days <= 0.0 => stats.idle += 1,
                Some(dt_days) => {
                    let outcome = accrue_interval(
                        &mut ledger,
                        &Volumes::from_bytes(&volumes),
                        dt_days,
                        observed_days,
                    );
                    ledger.last_update = Some(now);
                    rows.push((volumes.master, ledger));
                    stats.accrued += 1;
                    if outcome.unobserved_days > 0.0 {
                        stats.with_unobserved_gap += 1;
                    }
                    if outcome.uncovered_days > 0.0 {
                        stats.truncated += 1;
                        stats.uncovered_days += outcome.uncovered_days;
                    }
                }
            }
        }

        self.db.upsert_pair_ledgers(&rows)?;
        Ok(stats)
    }
}

/// The two confirmed-service volumes of one pair, in GB — the recorder's `V_conf` pair.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Volumes {
    /// GB this master's devices keep for us.
    pub they_store_for_us: f64,
    /// GB we keep for this master.
    pub we_store_for_them: f64,
}

impl Volumes {
    /// Convert at the write boundary, never inside the ledger (see the units section of
    /// [`crate::types::PairLedger`] — raw bytes parked in a gb·day field cannot be
    /// repaired after the fact).
    pub fn from_bytes(bytes: &MasterStorageBytes) -> Self {
        Volumes {
            they_store_for_us: bytes.they_store_for_us as f64 / BYTES_PER_GB,
            we_store_for_them: bytes.we_store_for_them as f64 / BYTES_PER_GB,
        }
    }
}

/// What [`accrue_interval`] did with an interval, for the tick's counters.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct IntervalOutcome {
    /// Days integrated at `V_conf = 0` because they lie outside the observed window.
    pub unobserved_days: f64,
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
/// shrink the fresh evidence instead of the stale capital.
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
        uncovered_days: 0.0,
    };
    if unobserved > 0.0 {
        let dark = Volumes {
            they_store_for_us: 0.0,
            we_store_for_them: 0.0,
        };
        outcome.uncovered_days += accrue(ledger, &dark, unobserved);
    }
    if observed > 0.0 {
        outcome.uncovered_days += accrue(ledger, volumes, observed);
    }
    outcome
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
/// [`update_capital`] at `λ`, the depth through [`update_depth`] at `λ_slow`, over the
/// sub-steps of [`sub_steps`] — so the result is exactly the kernel applied `n` times, not
/// an approximation of it (AC-1).
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
    for _ in 0..plan.count {
        ledger.gb_days_they_store_for_us = update_capital(
            ledger.gb_days_they_store_for_us,
            volumes.they_store_for_us,
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
            volumes.they_store_for_us,
            plan.step_days,
            PAIR_LEDGER_LAMBDA_SLOW,
        );
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
/// `λ·step ≤ PAIR_LEDGER_MAX_LAMBDA_DT` for BOTH leak rates (the binding one is the faster
/// `λ`, so the step is 30 days).
///
/// This is W-2 of the spec. [`crate::types::PairLedger::elapsed_days`] deliberately returns
/// an UNCLAMPED interval, because clamping a three-month outage would silently throw the
/// accrual away. Handing that interval to the kernel in one step is equally wrong in the
/// other direction: the Euler multiplier `(1 − λΔt)` turns negative past `Δt = 60` days, so
/// a pair that stopped storing would be charged a large NEGATIVE capital on the first tick
/// after the outage. Splitting is the only answer that neither truncates nor inverts.
pub fn sub_steps(dt_days: f64) -> SubStepPlan {
    let lambda_max = PAIR_LEDGER_LAMBDA.max(PAIR_LEDGER_LAMBDA_SLOW);
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
        // Corrupt clock (see MAX_SUB_STEPS): integrate the leading 8000 years, by which
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
