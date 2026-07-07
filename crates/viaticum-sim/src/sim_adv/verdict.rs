//! The verdict engine + invariant board (design `4r_world_v3_detail.md` §3.8, spec §10).
//!
//! Every statistical verdict reports effect/σ and returns INCONCLUSIVE whenever the
//! signal-to-noise power `|mean − threshold| / σ < 2` (spec §10 п.16) — the main risk is
//! a signal below the multi-seed noise, not a mis-tuned threshold. Two board rows are
//! STRUCTURAL rather than statistical: determinism (re-run seed[0], compare bytes) and
//! anti-oracle (the one-way crate edge + the [`super::BehaviorHook`] shape that cannot
//! borrow `&World`). This replaces the tautological INV-AGG-1 with the real
//! non-inflation test — per-node extraction ROI by archetype (spec §10 п.17).
//!
//! ## Deviation from the §4 sketch
//!
//! The sketch types the invariant as `eval: fn(&RunResult) -> (bool, f64)`. That cannot
//! carry σ, the power gate, or the structural/statistical split the spec §10 п.16/п.17
//! require, so [`InvariantSpec`] is a small enum over the three row shapes instead.

use crate::sim_adv::metrics::{MetricSet, mean_sigma};
use crate::sim_adv::runner::{RunResult, run_one_seed};
use crate::sim_adv::scenario::Scenario;

/// A three-valued verdict (spec §10 п.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictKind {
    Pass,
    Fail,
    /// Power `< 2`: the effect is below the multi-seed noise — neither PASS nor FAIL.
    Inconclusive,
}

impl VerdictKind {
    /// Fixed-width label for the report.
    pub fn label(self) -> &'static str {
        match self {
            VerdictKind::Pass => "PASS        ",
            VerdictKind::Fail => "FAIL        ",
            VerdictKind::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// The direction a statistical invariant passes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// PASS iff `mean < threshold`.
    LessThan,
    /// PASS iff `mean > threshold`.
    GreaterThan,
}

impl Direction {
    fn note(self) -> &'static str {
        match self {
            Direction::LessThan => "mean < threshold",
            Direction::GreaterThan => "mean > threshold",
        }
    }
}

/// How a board row is evaluated.
pub enum InvariantSpec {
    /// Per-seed scalar → mean±σ vs threshold, with the power<2 gate.
    Statistical {
        /// Extract the invariant's scalar from one seed's metrics.
        measure: fn(&MetricSet) -> f64,
        /// The pass direction.
        dir: Direction,
    },
    /// Re-run seed[0] and assert the metrics are bit-identical (structural).
    Determinism,
    /// The anti-oracle structural guarantee (crate edge + hook signature).
    AntiOracle,
}

/// One invariant-board row spec.
pub struct Invariant {
    /// Stable id (report/CSV).
    pub id: &'static str,
    /// How it is evaluated.
    pub spec: InvariantSpec,
    /// The frozen threshold (statistical rows; 1.0 sentinel for structural rows).
    pub threshold: f64,
}

// Invariant carries a `fn` pointer, so it is not `Clone`-derivable via `Scenario`'s
// derive unless we spell it out; `fn` pointers ARE `Copy`, so a manual impl is trivial.
impl Clone for Invariant {
    fn clone(&self) -> Self {
        Invariant {
            id: self.id,
            spec: match &self.spec {
                InvariantSpec::Statistical { measure, dir } => InvariantSpec::Statistical {
                    measure: *measure,
                    dir: *dir,
                },
                InvariantSpec::Determinism => InvariantSpec::Determinism,
                InvariantSpec::AntiOracle => InvariantSpec::AntiOracle,
            },
            threshold: self.threshold,
        }
    }
}

impl std::fmt::Debug for Invariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invariant")
            .field("id", &self.id)
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}

/// The evaluated verdict for one board row.
#[derive(Debug, Clone, Copy)]
pub struct Verdict {
    /// The invariant id.
    pub id: &'static str,
    /// PASS / FAIL / INCONCLUSIVE.
    pub kind: VerdictKind,
    /// The measured effect (mean over seeds for statistical rows; 1.0/0.0 for structural).
    pub effect: f64,
    /// Multi-seed σ (0.0 for structural rows).
    pub sigma: f64,
    /// The frozen threshold.
    pub threshold: f64,
    /// Signal-to-noise power `|effect − threshold| / σ`; `NaN` for structural rows.
    pub power: f64,
    /// A one-line note (the pass rule or the structural guarantee).
    pub note: &'static str,
}

/// Decide a statistical verdict from mean/σ vs a threshold, applying the power<2 gate
/// (spec §10 п.16). σ non-finite (fewer than two finite seeds) ⇒ INCONCLUSIVE (no spread
/// estimate). σ == 0 ⇒ decisive unless the effect sits exactly on the threshold.
pub(crate) fn decide(mean: f64, sigma: f64, threshold: f64, dir: Direction) -> (VerdictKind, f64) {
    if !mean.is_finite() {
        return (VerdictKind::Inconclusive, f64::NAN);
    }
    if !sigma.is_finite() {
        return (VerdictKind::Inconclusive, 0.0);
    }
    let power = if sigma == 0.0 {
        if mean == threshold {
            0.0
        } else {
            f64::INFINITY
        }
    } else {
        (mean - threshold).abs() / sigma
    };
    if power < 2.0 {
        return (VerdictKind::Inconclusive, power);
    }
    let pass = match dir {
        Direction::LessThan => mean < threshold,
        Direction::GreaterThan => mean > threshold,
    };
    (
        if pass {
            VerdictKind::Pass
        } else {
            VerdictKind::Fail
        },
        power,
    )
}

/// Evaluate all of a scenario's invariant-board rows against a completed run.
pub fn evaluate_board(scenario: &Scenario, result: &RunResult) -> Vec<Verdict> {
    scenario
        .verdicts
        .iter()
        .map(|inv| match &inv.spec {
            InvariantSpec::Statistical { measure, dir } => {
                let vals: Vec<f64> = result.per_seed.iter().map(measure).collect();
                let (mean, sigma) = mean_sigma(&vals);
                let sigma_r = if sigma.is_finite() { sigma } else { 0.0 };
                let (kind, power) = decide(mean, sigma, inv.threshold, *dir);
                Verdict {
                    id: inv.id,
                    kind,
                    effect: mean,
                    sigma: sigma_r,
                    threshold: inv.threshold,
                    power,
                    note: dir.note(),
                }
            }
            InvariantSpec::Determinism => {
                let pass = match result.seeds.first() {
                    Some(&s0) => {
                        let (m, _) = run_one_seed(scenario, s0);
                        result
                            .per_seed
                            .first()
                            .map(|m0| crate::sim_adv::metrics::bit_eq(m0, &m))
                            .unwrap_or(false)
                    }
                    None => false,
                };
                Verdict {
                    id: inv.id,
                    kind: if pass {
                        VerdictKind::Pass
                    } else {
                        VerdictKind::Fail
                    },
                    effect: if pass { 1.0 } else { 0.0 },
                    sigma: 0.0,
                    threshold: 1.0,
                    power: f64::NAN,
                    note: "structural: re-run seed[0] bit-identical",
                }
            }
            InvariantSpec::AntiOracle => Verdict {
                id: inv.id,
                kind: VerdictKind::Pass,
                effect: 1.0,
                sigma: 0.0,
                threshold: 1.0,
                power: f64::NAN,
                note: "structural: one-way crate edge + BehaviorHook has no &World",
            },
        })
        .collect()
}
