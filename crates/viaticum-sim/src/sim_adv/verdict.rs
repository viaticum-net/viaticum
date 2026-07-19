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
//! require, so [`InvariantSpec`] is a small enum over the row shapes instead (statistical
//! over `MetricSet`, statistical over restore-truth, determinism, anti-oracle).

use crate::sim_adv::hetero::HeteroReport;
use crate::sim_adv::metrics::{MetricSet, mean_sigma};
use crate::sim_adv::predators::AdvMetrics;
use crate::sim_adv::restore::RestoreTruth;
use crate::sim_adv::runner::{RunResult, run_one_seed};
use crate::sim_adv::scenario::Scenario;
use crate::sim_adv::tier::TierReport;

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
    /// Per-seed RESTORE-TRUTH scalar → mean±σ vs threshold, power<2 gate. Reads
    /// [`RunResult::per_seed_restore`] (restore-truth is not on [`MetricSet`]); seeds with
    /// no Disaster contribute `NaN` (skipped by `mean_sigma`).
    RestoreStatistical {
        /// Extract the invariant's scalar from one seed's restore-truth.
        measure: fn(&RestoreTruth) -> f64,
        /// The pass direction.
        dir: Direction,
    },
    /// Re-run seed[0] and assert the metrics (and restore-truth) are bit-identical.
    Determinism,
    /// The anti-oracle structural guarantee (crate edge + hook signature).
    AntiOracle,
    /// A phase-1 PREDATOR-side scalar → mean±σ vs threshold, power<2 gate. Reads the
    /// predator's [`AdvMetrics`] from [`RunResult::per_seed_adv`]. Used by INV-P1B-CAP /
    /// INV-P2-REENTRY (the Р-7 cap ratio holds ≤ 1 where the cap engages).
    AdvCap {
        /// Extract the invariant's scalar from the predator's Attack-ROI read.
        measure: fn(&AdvMetrics) -> f64,
        /// The pass direction.
        dir: Direction,
    },
    /// A phase-1 COMPARATIVE row (predator vs matched twin): per seed the ratio
    /// `measure(pred) / measure(twin)` → mean±σ vs threshold, power<2 gate. Used by
    /// INV-ROI-PRED≤TWIN (the attack yields no more than honest play ⇒ ratio < 1). A twin
    /// measure of `0` contributes `NaN` (skipped — no baseline to divide by).
    AdvComparative {
        /// Extract the compared scalar from an Attack-ROI read (applied to both sides).
        measure: fn(&AdvMetrics) -> f64,
        /// The pass direction.
        dir: Direction,
    },
    /// A hetero-v2 (D1) per-CLASS scalar → mean±σ vs threshold, power<2 gate. Reads the
    /// per-seed [`HeteroReport`] from [`RunResult::per_seed_hetero`]; seeds with no hetero
    /// report contribute `NaN` (skipped). Used by INV-HETERO-NO-STARVATION (the L-class
    /// footprint must reach floor comparably to S/M ⇒ its floor-completeness clears a floor).
    HeteroStatistical {
        /// Extract the invariant's scalar from one seed's hetero report.
        measure: fn(&HeteroReport) -> f64,
        /// The pass direction.
        dir: Direction,
    },
    /// A phase-2a per-TIER scalar → mean±σ vs threshold, power<2 gate. Reads the per-seed
    /// [`TierReport`] from [`RunResult::per_seed_tier`]; seeds with no tier report contribute
    /// `NaN` (skipped). Used by INV-TIER-GIVERS (the P7 give↔get rank) + the T1 sanity floor.
    TierStatistical {
        /// Extract the invariant's scalar from one seed's tier report.
        measure: fn(&TierReport) -> f64,
        /// The pass direction.
        dir: Direction,
    },
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
                InvariantSpec::RestoreStatistical { measure, dir } => {
                    InvariantSpec::RestoreStatistical {
                        measure: *measure,
                        dir: *dir,
                    }
                }
                InvariantSpec::Determinism => InvariantSpec::Determinism,
                InvariantSpec::AntiOracle => InvariantSpec::AntiOracle,
                InvariantSpec::AdvCap { measure, dir } => InvariantSpec::AdvCap {
                    measure: *measure,
                    dir: *dir,
                },
                InvariantSpec::AdvComparative { measure, dir } => InvariantSpec::AdvComparative {
                    measure: *measure,
                    dir: *dir,
                },
                InvariantSpec::HeteroStatistical { measure, dir } => {
                    InvariantSpec::HeteroStatistical {
                        measure: *measure,
                        dir: *dir,
                    }
                }
                InvariantSpec::TierStatistical { measure, dir } => InvariantSpec::TierStatistical {
                    measure: *measure,
                    dir: *dir,
                },
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
            InvariantSpec::RestoreStatistical { measure, dir } => {
                let vals: Vec<f64> = result
                    .per_seed_restore
                    .iter()
                    .map(|r| r.as_ref().map(measure).unwrap_or(f64::NAN))
                    .collect();
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
                        let sr = run_one_seed(scenario, s0);
                        let metrics_eq = result
                            .per_seed
                            .first()
                            .map(|m0| crate::sim_adv::metrics::bit_eq(m0, &sr.metrics))
                            .unwrap_or(false);
                        // Restore-truth (if any) must be bit-identical on the re-run too.
                        let restore_eq = match result.per_seed_restore.first() {
                            Some(Some(r0)) => sr
                                .restore
                                .as_ref()
                                .map(|r1| crate::sim_adv::restore::bit_eq(r0, r1))
                                .unwrap_or(false),
                            Some(None) => sr.restore.is_none(),
                            None => true,
                        };
                        // The R̂-calibration channel (transche 0.3) must re-run bit-identical
                        // too — it feeds the report, so determinism must cover it.
                        let calib_eq = result
                            .per_seed_calibration
                            .first()
                            .map(|c0| crate::sim_adv::brier::bit_eq(c0, &sr.calib))
                            .unwrap_or(false);
                        // The predator's Attack-ROI read (phase 1) must re-run bit-identical
                        // too (it feeds the ROI report + the AdvCap/AdvComparative verdicts).
                        let adv_eq = match result.per_seed_adv.first() {
                            Some(Some(p0)) => sr
                                .adv
                                .as_ref()
                                .map(|a1| crate::sim_adv::predators::bit_eq(&p0.pred, a1))
                                .unwrap_or(false),
                            Some(None) => sr.adv.is_none(),
                            None => true,
                        };
                        // The hetero report (hetero-v2) must re-run bit-identical too — it feeds
                        // the per-class report + the INV-HETERO-NO-STARVATION verdict.
                        let hetero_eq = match result.per_seed_hetero.first() {
                            Some(Some(h0)) => sr
                                .hetero
                                .as_ref()
                                .map(|h1| crate::sim_adv::hetero::bit_eq(h0, h1))
                                .unwrap_or(false),
                            Some(None) => sr.hetero.is_none(),
                            None => true,
                        };
                        // The per-tier report (phase-2a) must re-run bit-identical too — it feeds
                        // the tier table + the INV-TIER-GIVERS / INV-TIER-T1-ALIVE verdicts.
                        let tier_eq = match result.per_seed_tier.first() {
                            Some(Some(t0)) => sr
                                .tier
                                .as_ref()
                                .map(|t1| crate::sim_adv::tier::bit_eq(t0, t1))
                                .unwrap_or(false),
                            Some(None) => sr.tier.is_none(),
                            None => true,
                        };
                        metrics_eq && restore_eq && calib_eq && adv_eq && hetero_eq && tier_eq
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
            InvariantSpec::AdvCap { measure, dir } => {
                let vals: Vec<f64> = result
                    .per_seed_adv
                    .iter()
                    .map(|p| p.as_ref().map(|pp| measure(&pp.pred)).unwrap_or(f64::NAN))
                    .collect();
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
                    note: "predator: Р-7 cap ratio where the cap engages",
                }
            }
            InvariantSpec::AdvComparative { measure, dir } => {
                // Per seed: ratio measure(pred)/measure(twin). A twin measure of 0 ⇒ NaN
                // (no baseline to divide by) — skipped by `mean_sigma`.
                let vals: Vec<f64> = result
                    .per_seed_adv
                    .iter()
                    .map(|p| {
                        p.as_ref()
                            .map(|pp| {
                                let t = measure(&pp.twin);
                                if t > 0.0 {
                                    measure(&pp.pred) / t
                                } else {
                                    f64::NAN
                                }
                            })
                            .unwrap_or(f64::NAN)
                    })
                    .collect();
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
                    note: "predator vs matched twin (ratio)",
                }
            }
            InvariantSpec::HeteroStatistical { measure, dir } => {
                let vals: Vec<f64> = result
                    .per_seed_hetero
                    .iter()
                    .map(|h| h.as_ref().map(measure).unwrap_or(f64::NAN))
                    .collect();
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
                    note: "hetero: per-class placement (no starvation)",
                }
            }
            InvariantSpec::TierStatistical { measure, dir } => {
                let vals: Vec<f64> = result
                    .per_seed_tier
                    .iter()
                    .map(|t| t.as_ref().map(measure).unwrap_or(f64::NAN))
                    .collect();
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
                    note: "tier: P7 give↔get rank (T1 ≥ T2 ≥ T3 ≥ T4)",
                }
            }
        })
        .collect()
}
