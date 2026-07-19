//! World-v3 phase-2a — UPTIME PROFILES (axis 3): STRUCTURAL per-tick availability patterns
//! that replace the archetype's iid Bernoulli for tiered nodes.
//!
//! ## Why this axis (spec `4r_world_v3_spec.md` §2 / `4r_p2a_spec.md` §2)
//!
//! The honest engine models a node's uptime as an iid per-tick draw off the archetype's
//! `base_uptime` (Reliable 0.99, ...). That has no STRUCTURE: no autocorrelated on/off runs, no
//! seasonal pause. The F1 PoS window already FORGIVES a whole week (a symbol passes iff its holder
//! surfaced on ANY of the 7 iid days), so an iid low-uptime node still almost always surfaces.
//! Profiles add structure ON TOP of (and WITHIN) that window:
//!
//! * a REDUCED-MEAN daily uptime ([`UptimeProfile::Diurnal`] / [`UptimeProfile::Ragged`]) — an
//!   evening user / a flaky phone is up fewer hours, so it surfaces MOST weeks but not all
//!   (Q2 resolution: diurnal = a lower MEAN uptime, NOT a sub-tick schedule);
//! * a PHASE-DETERMINISTIC on/off cycle ([`UptimeProfile::WeekendOnly`] nomad /
//!   [`UptimeProfile::Seasonal`] vacation) — autocorrelated runs of on-weeks then off-weeks.
//!   When the OFF run exceeds the 7-day window (`day_uptime == 0` for a stretch of weeks) the
//!   node MISSES PoS honestly for the first time — the whole point of the axis.
//!
//! ## No new RNG stream (byte-identity of the honest anchor)
//!
//! A profile is a pure function `day_uptime(node, tick) -> f64` — the per-day online probability.
//! [`crate::sim_dynamic::generator::World::node_online`] / `node_surfaced_in_window` feed that `u`
//! into the SAME `online_with_u` / `surfaced_with_u` draws the archetype path uses (the existing
//! `ONLINE_TAG` / `SURFACE_TAG` streams). So a profiled node draws on NO new stream, and a node
//! with NO profile (`uptime[i] == None`) takes the EXACT pre-profile code path — the seed-42 honest
//! anchor stays byte-identical. The phase-deterministic parts (`WeekendOnly` / `Seasonal`) consume
//! NO RNG at all; their structure comes from the tick phase, not a draw.
//!
//! ## God-view, opt-in (anti-oracle)
//!
//! The profile is a hidden node attribute (like `GiverTier` / `DemandClass`): it shapes the
//! availability physics and is read ONLY by the two accessors above (PoS surfacing + restore
//! transport), NEVER by a kernel decision. Assignment is opt-in per scenario ([`UptimeMix`]); the
//! default [`UptimeMix::Legacy`] assigns NO profiles, leaving the world byte-identical.

use crate::sim_dynamic::generator::{GiverTier, World};

/// A per-node structural uptime pattern (phase-2a axis 3). `Copy` so it lives on the world as a
/// cheap `Vec<Option<UptimeProfile>>` mirror of the `adv` layer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UptimeProfile {
    /// 24/7 — always on. High constant daily uptime, never a structural pause (the P7 T1 NAS).
    AlwaysOn,
    /// An evening / weekday user: a REDUCED-MEAN daily uptime `hours/24` (NOT a sub-tick
    /// schedule — Q2). Up every day but fewer hours, so it surfaces most weeks yet accrues real
    /// PoS friction as `hours` falls (the P7 T2 photo / T3 laptop tiers).
    Diurnal { hours: u8 },
    /// A weekly nomad: a SHORT phase-deterministic on/off cycle — fully present for a contiguous
    /// run of weeks, then fully absent for a run of weeks (autocorrelated, not iid). Misses PoS
    /// during its off-weeks. Per-node phase offset spreads WHICH weeks are off.
    WeekendOnly,
    /// A vacation-season node: a LONG phase-deterministic cycle — active `duty` of every `period`
    /// weeks, then a CONTIGUOUS pause. When the pause exceeds the 7-day PoS window the node misses
    /// PoS honestly for the first time (the axis headline). `period` in weeks, `duty` in `[0,1]`.
    Seasonal { period: u64, duty: f64 },
    /// A ragged phone: a LOW iid-like reduced daily uptime `p` (structural only in its low mean).
    /// Surfaces unpredictably; the lowest-availability tier (P7 T4).
    Ragged { p: f64 },
}

/// AlwaysOn per-day uptime — a hair under 1 so a rare cosmic miss is representable but the F1
/// window surfaces with probability ≈ 1 (matches Reliable's `base_uptime`).
const ALWAYS_ON_U: f64 = 0.99;
/// Floor on a diurnal daily uptime (guards a `hours == 0` profile from a degenerate always-off).
const DIURNAL_MIN_U: f64 = 0.02;
/// WeekendOnly nomad: ON-week daily uptime (present ⇒ high) and OFF-week (fully absent).
const WEEKEND_ON_U: f64 = 0.95;
const WEEKEND_OFF_U: f64 = 0.0;
/// WeekendOnly nomad cycle: `WEEKEND_DUTY_WEEKS` on out of `WEEKEND_PERIOD_WEEKS` (2-on / 2-off).
const WEEKEND_PERIOD_WEEKS: u64 = 4;
const WEEKEND_DUTY_WEEKS: u64 = 2;
/// Seasonal ACTIVE-week daily uptime (the pause weeks are 0).
const SEASONAL_ON_U: f64 = 0.95;
/// A large odd multiplier that spreads the per-node phase offset across a cycle (deterministic,
/// no RNG) so profiled nodes do not all pause on the same weeks (a synchronized-pause artifact).
const PHASE_MULT: u64 = 0x9E37_79B9_7F4A_7C15;

impl UptimeProfile {
    /// The per-day online probability `u` at weekly `tick` for node `node_id`. DETERMINISTIC —
    /// no RNG: the phase-deterministic profiles gate the whole week on/off by the tick phase, the
    /// flat profiles return a constant reduced mean. This `u` threads the EXISTING online/surface
    /// draws (see the module docs), so it is the single knob the two `World` accessors need.
    pub fn day_uptime(self, node_id: u64, tick: u64) -> f64 {
        match self {
            UptimeProfile::AlwaysOn => ALWAYS_ON_U,
            UptimeProfile::Diurnal { hours } => (hours as f64 / 24.0).clamp(DIURNAL_MIN_U, 1.0),
            UptimeProfile::WeekendOnly => {
                if phase_active(node_id, tick, WEEKEND_PERIOD_WEEKS, WEEKEND_DUTY_WEEKS) {
                    WEEKEND_ON_U
                } else {
                    WEEKEND_OFF_U
                }
            }
            UptimeProfile::Seasonal { period, duty } => {
                let duty_weeks = (duty.clamp(0.0, 1.0) * period.max(1) as f64).round() as u64;
                if phase_active(node_id, tick, period.max(1), duty_weeks) {
                    SEASONAL_ON_U
                } else {
                    0.0
                }
            }
            UptimeProfile::Ragged { p } => p.clamp(0.0, 1.0),
        }
    }

    /// A short label for the tier report / CSV.
    pub fn label(self) -> &'static str {
        match self {
            UptimeProfile::AlwaysOn => "always_on",
            UptimeProfile::Diurnal { .. } => "diurnal",
            UptimeProfile::WeekendOnly => "weekly_nomad",
            UptimeProfile::Seasonal { .. } => "seasonal",
            UptimeProfile::Ragged { .. } => "ragged",
        }
    }
}

/// Is node `node_id` in the ACTIVE window of a phase-deterministic on/off cycle at `tick`?
/// `((tick + phase(node_id)) mod period) < duty_weeks` (spec Q2: fix the Weekend `tick%7` artifact
/// with a clean `(tick + phase) mod period < duty·period` predicate). The per-node phase spreads
/// which weeks are the off-run so a cohort does not pause in lock-step. Pure, no RNG.
fn phase_active(node_id: u64, tick: u64, period: u64, duty_weeks: u64) -> bool {
    if period == 0 {
        return true;
    }
    let phase = node_id.wrapping_mul(PHASE_MULT) % period;
    (tick.wrapping_add(phase)) % period < duty_weeks
}

/// The scenario's uptime-profile distribution over its population (mirrors [`DemandMix`]:
/// [`crate::sim_adv::hetero::DemandMix`]). [`UptimeMix::Legacy`] (the default for every
/// pre-2a scenario) assigns NO profile, keeping the world byte-identical to the archetype
/// iid path.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UptimeMix {
    /// No profiles — every node keeps its archetype's iid Bernoulli uptime (byte-identical).
    Legacy,
    /// Per-P7-tier structural profiles ([`tier_profile`]): T1 → AlwaysOn, T2/T3 → Diurnal
    /// (evening / weekday), T4 → Ragged. Reads each node's `disk.tier` after the world is built.
    Tiered,
}

impl UptimeMix {
    /// Does this mix install profiles (⇒ the runner runs the profile layer + the tier report)?
    pub fn is_tiered(self) -> bool {
        matches!(self, UptimeMix::Tiered)
    }

    /// Assign a profile (or `None`) to each node. `Legacy` ⇒ all `None` (byte-identical); `Tiered`
    /// ⇒ [`tier_profile`] of each node's `disk.tier`. Reads the world AFTER `build_world` (+ any
    /// tier re-mix), so the tier is the final one. Pure, no RNG (the profiles are structural).
    pub fn assign(self, world: &World) -> Vec<Option<UptimeProfile>> {
        match self {
            UptimeMix::Legacy => vec![None; world.nodes.len()],
            UptimeMix::Tiered => world
                .nodes
                .iter()
                .map(|nd| Some(tier_profile(nd.disk.tier)))
                .collect(),
        }
    }
}

/// The P7 tier → uptime profile mapping (`4r_p2a_spec.md` §1). An OPEN calibration guess (the
/// `hours` / `p` values are flagged for Ilya): the point is a monotone availability gradient
/// T1 ≥ T2 ≥ T3 ≥ T4 (window-surfacing p_w ≈ 1.00 / 0.94 / 0.80 / 0.68), the P7 "givers" order.
pub fn tier_profile(tier: GiverTier) -> UptimeProfile {
    match tier {
        // T1 NAS: 24/7 backbone.
        GiverTier::T1 => UptimeProfile::AlwaysOn,
        // T2 photo enthusiast: evening user (~8h/day ⇒ u ≈ 0.33, surfaces ~94% of weeks).
        GiverTier::T2 => UptimeProfile::Diurnal { hours: 8 },
        // T3 laptop: weekday user, fewer hours (~5h/day ⇒ u ≈ 0.21, surfaces ~80% of weeks).
        GiverTier::T3 => UptimeProfile::Diurnal { hours: 5 },
        // T4 phone: ragged, background-restricted (~15% of days ⇒ surfaces ~68% of weeks — the
        // lowest tier; even so the weekly PoS window forgives most misses, the honest finding).
        GiverTier::T4 => UptimeProfile::Ragged { p: 0.15 },
    }
}
