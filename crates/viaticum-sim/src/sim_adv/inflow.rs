//! World-v3 — POPULATION INFLOW (stationary population, Variant A; `4r_inflow_spec.md`).
//!
//! ## Why this axis (Ilya 2026-07-20, Variant A)
//!
//! The long-horizon tiered world DEPOPULATES: churn has no rejoin, so over 520 weekly ticks
//! the cooperative survival `(1 − churn)^520 ≈ 0.35` drains a 180-node cohort to ~59 present
//! (measured). That is a CLOSED-COHORT die-off, not a steady-state network. Real networks
//! have a continuous stream of NEWCOMERS. Adding one lets the long horizon reach a STATIONARY
//! population — the regime the phase-3 incumbent-enclosure (A15) / P8 self-reciprocity /
//! continuous-P3-bootstrap questions actually live in.
//!
//! ## The mechanic is ALREADY on the rails (no matrix surgery)
//!
//! `build_world` pre-allocates the FULL `N×N` capital matrix at t=0 with every node already in
//! `world.nodes` (not-yet-joined nodes just sit `present = false`, capital rows/cols = 0).
//! `join_schedule` gives each node a `joined_tick`; `engine::activate_joins` flips `present =
//! true` at that tick; `churn` flips it `false` forever. So an inflow = **pre-allocate a POOL
//! of future newcomers** and spread their `joined_tick` across the whole horizon at rate λ_in.
//! No dynamic matrix growth (that would be invasive / risky — deliberately NOT done).
//!
//! ## Open-loop, opt-in, byte-identical default (spec §1/§4)
//!
//! [`InflowPolicy::None`] (the DEFAULT for every pre-inflow scenario) never runs [`apply_inflow`]
//! and draws NO RNG, so the honest anchor stays byte-identical — the same opt-in discipline as
//! [`crate::sim_adv::hetero::DemandMix::Uniform`] / [`crate::sim_adv::uptime::UptimeMix::Legacy`].
//! The schedule is a PRE-SCHEDULE (open-loop timetable), NOT a feedback controller reading the
//! present-count back — honest, because real arrivals are not steered by a setpoint. A closed-loop
//! controller variant is a possible ALTERNATIVE, deliberately NOT implemented (spec §1).

use crate::sim_dynamic::engine::CHURN_AGGRESSION_SCALE;
use crate::sim_dynamic::generator::{World, population_mix};

/// The INV-POP-STATIONARY band half-width (spec §3): present-count must hold within ±`POP_BAND`
/// of the setpoint over the last half of the horizon. FROZEN at 0.25 (±25 %) BEFORE the run
/// (anti-Goodhart): calibrate the SCENARIO (n0, λ_in) — never this bar. A genuine drift/collapse
/// beyond it is a real FINDING to report, not a threshold to move.
pub const POP_BAND: f64 = 0.25;

/// Population sample size for the mean churn multiplier (large ⇒ the canonical §3 shares' mean).
const POP_SAMPLE: usize = 10_000;

/// A scenario's population-inflow policy (opt-in; spec §1). `Copy` so it rides [`WorldParams`]
/// cheaply and mirrors the other opt-in mixes.
///
/// [`WorldParams`]: crate::sim_adv::scenario::WorldParams
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InflowPolicy {
    /// No inflow — the closed cohort (every node keeps `build_world`'s `join_schedule`). The
    /// DEFAULT: byte-identical, never runs [`apply_inflow`], draws no RNG.
    None,
    /// A steady arrival stream at `joins_per_tick` (λ_in): pre-allocate a pool of future
    /// newcomers spread across `[1, horizon]` at that intensity. `n_nodes = n0 + pool`, where the
    /// scenario sets `n_nodes` and λ_in and [`pool_size`] derives the pool (so `n0` = the bootstrap
    /// setpoint the population fluctuates around).
    Steady {
        /// Arrival intensity λ_in (newcomers per weekly tick). Calibrate near the expected outflow
        /// at the setpoint (`≈ n0 · churn · ⟨1 + scale·aggr⟩`, see [`expected_outflow`]) so the
        /// present-count fluctuates around n0 rather than collapsing or running away. `≤ 0` ⇒ no-op.
        joins_per_tick: f64,
    },
}

impl InflowPolicy {
    /// Does this policy install an inflow stream (⇒ the runner applies it + records the curve)?
    pub fn is_steady(self) -> bool {
        matches!(self, InflowPolicy::Steady { .. })
    }
}

/// The pre-allocated pool size for a λ_in over `horizon`: `round(λ_in · horizon)` — the TOTAL
/// newcomers that arrive over the horizon at intensity λ_in. Shared by the registry (to size
/// `n_nodes = n0 + pool`) and [`apply_inflow`] / [`bootstrap_n0`] (to split the built world back into
/// bootstrap + pool) so the two can never drift out of sync.
///
/// No dispersion margin (spec §1 sized `ceil(λ·H·1.15)` for a POISSON stream): with the DETERMINISTIC
/// even schedule ([`apply_inflow`]) the arrivals are exactly predictable, so EVERY pool node lands
/// inside the horizon — there is no inert "buffer tail" to over-allocate against, and none to leak
/// into the end-of-run metrics (spec §2). The count is exactly the stream's newcomers.
pub fn pool_size(joins_per_tick: f64, horizon: u64) -> usize {
    if joins_per_tick <= 0.0 {
        return 0;
    }
    (joins_per_tick * horizon as f64).round() as usize
}

/// The bootstrap cohort size `n0` = the population SETPOINT: `n_nodes − pool`. `None` ⇒ the whole
/// world is the bootstrap (no pool).
pub fn bootstrap_n0(n_nodes: usize, policy: InflowPolicy, horizon: u64) -> usize {
    match policy {
        InflowPolicy::Steady { joins_per_tick } => {
            n_nodes.saturating_sub(pool_size(joins_per_tick, horizon).min(n_nodes))
        }
        InflowPolicy::None => n_nodes,
    }
}

/// Expected per-tick OUTFLOW at a present population of `n0`, under the canonical §3 archetype mix:
/// `n0 · churn_out_prob · ⟨1 + CHURN_AGGRESSION_SCALE·aggression⟩`. The λ_in default-guess (spec §1):
/// setting inflow ≈ this outflow makes the population a fixed point at `n0`. Open calibration — the
/// realised steady state may sit slightly ABOVE `n0` (aggressive archetypes churn faster, so present
/// nodes are less aggressive than the raw mix ⇒ true outflow < this), an HONEST finding to REPORT,
/// not to blind-tune (spec §4).
pub fn expected_outflow(n0: usize, churn_out_prob: f64) -> f64 {
    n0 as f64 * churn_out_prob * mean_churn_multiplier()
}

/// The mean churn multiplier `⟨1 + CHURN_AGGRESSION_SCALE·aggression⟩` over the canonical §3
/// population mix (sampled at [`POP_SAMPLE`] — the ideal-share mean). Uses the SAME multiplier the
/// engine's `churn` applies, so λ_in is sized against the real outflow the sim generates.
fn mean_churn_multiplier() -> f64 {
    let mix = population_mix(POP_SAMPLE);
    let sum: f64 = mix
        .iter()
        .map(|a| 1.0 + CHURN_AGGRESSION_SCALE * a.evict_aggression())
        .sum();
    sum / mix.len() as f64
}

/// Apply a [`InflowPolicy`] to a freshly-built world (spec §1/§2): re-schedule the last `pool`
/// nodes as a steady arrival stream. [`InflowPolicy::None`] (or a non-positive λ_in) is a NO-OP that
/// draws NO RNG — the byte-identical default path. Deterministic (an even pre-schedule, no draw):
/// the `pool` newcomers are spread EVENLY over `[1, horizon − 1]` (pool node `p` joins at
/// `1 + ⌊p·(horizon−1)/pool⌋`), so arrivals land at intensity `pool/(horizon−1) ≈ λ_in` and EVERY
/// one activates inside the run (no inert buffer, so nothing leaks into the end-of-run metrics —
/// spec §2). Every pool node starts `present = false` (a future newcomer, even if `build_world`
/// happened to seed it live at t=0).
///
/// Called AFTER `build_world` (+ tier / demand / uptime mixes) — it only rewrites `joined_tick` /
/// `present`, disjoint from those fields, so the order is immaterial; `build_world`'s draws are
/// already complete, so re-scheduling the pool perturbs no honest stream. A salted Poisson stream is
/// a possible dispersion alternative, deliberately not used: an even timetable is the cleanest
/// open-loop schedule and the aggregate present-count — the stationarity signal — is what matters.
pub fn apply_inflow(world: &mut World, policy: InflowPolicy, horizon: u64) {
    let InflowPolicy::Steady { joins_per_tick } = policy else {
        return;
    };
    if joins_per_tick <= 0.0 {
        return;
    }
    let n = world.nodes.len();
    let pool = pool_size(joins_per_tick, horizon).min(n);
    if pool == 0 {
        return;
    }
    let n0 = n - pool;
    // The last `pool` nodes are the future newcomers (index-neutral: `build_world` shuffled the §3
    // archetype/tier mix, so the arriving composition is stationary, not only the count). Span the
    // arrivals over `[1, horizon − 1]` so the last newcomer still activates before the run ends.
    let span = horizon.max(2) - 1;
    for (p, nd) in world.nodes[n0..].iter_mut().enumerate() {
        nd.joined_tick = 1 + (p as u64 * span) / pool as u64;
        nd.present = false;
    }
}

/// God-view present-node count (the population-curve sample). Pure read; never a decision input.
pub fn present_count(world: &World) -> usize {
    world.nodes.iter().filter(|nd| nd.present).count()
}

/// One seed's present-count time-series over the run (the core inflow deliverable, spec §3).
/// `present_per_tick[t]` = the present-node count AFTER tick `t` (post-activation, post-churn).
#[derive(Debug, Clone, PartialEq)]
pub struct PopSeries {
    /// Present-node count per tick (index = tick; length = horizon).
    pub present_per_tick: Vec<usize>,
    /// The bootstrap setpoint `n0` the population should fluctuate around.
    pub setpoint: usize,
}

impl PopSeries {
    /// The INV-POP-STATIONARY scalar (spec §3): the MAX relative deviation of present-count from
    /// the setpoint over the LAST HALF of the horizon. `< POP_BAND` ⇒ the population held within
    /// ±band of the setpoint (stationary, not a monotone collapse); a drift/collapse pushes it up.
    /// `NaN` with no setpoint / empty series (skipped at the board).
    pub fn stationary_max_dev(&self) -> f64 {
        if self.setpoint == 0 || self.present_per_tick.is_empty() {
            return f64::NAN;
        }
        let sp = self.setpoint as f64;
        let half = self.present_per_tick.len() / 2;
        self.present_per_tick[half..]
            .iter()
            .map(|&p| (p as f64 / sp - 1.0).abs())
            .fold(0.0_f64, f64::max)
    }

    /// Mean present-count over the LAST HALF of the horizon (report diagnostic).
    pub fn last_half_mean(&self) -> f64 {
        if self.present_per_tick.is_empty() {
            return f64::NAN;
        }
        let half = self.present_per_tick.len() / 2;
        let tail = &self.present_per_tick[half..];
        if tail.is_empty() {
            return f64::NAN;
        }
        tail.iter().sum::<usize>() as f64 / tail.len() as f64
    }

    /// Present-count at the horizon (the final sample) — the "collapsed to X" headline.
    pub fn final_present(&self) -> usize {
        *self.present_per_tick.last().unwrap_or(&0)
    }
}

/// Bit-exact equality of two population series (the determinism board row). Plain `==` on the
/// `usize` vec + setpoint (no NaN concern — counts are exact).
pub fn bit_eq(a: &PopSeries, b: &PopSeries) -> bool {
    a.setpoint == b.setpoint && a.present_per_tick == b.present_per_tick
}
