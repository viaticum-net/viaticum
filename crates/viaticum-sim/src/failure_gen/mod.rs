//! Honest hazard generator for SIM-12 / SIM-12b — the HIDDEN ground-truth form.
//!
//! This module generates a [`crate::surface_fit::FailureDataset`] from a hidden
//! true hazard form. The form ([`HazardForm`]) is ground-truth: it lives ONLY
//! here and is NEVER passed into the nonparametric estimator's decision
//! ([`crate::surface_fit::classify_form`]) nor into any `viaticum_core::four_r`
//! kernel function. The estimator sees only the emitted outcomes
//! (`time, censored, volume`); it must DISCOVER the form, not be told it.
//!
//! There is NO adversary here — SIM-12 is about the surface FORM on honest data
//! (adversarial prior-poisoning is SIM-10, a separate scenario).
//!
//! ## In-family vs out-of-family
//!
//! [`HazardForm`] holds the IN-FAMILY honest forms the parametric backbone can
//! represent (exponential, bathtub/Weibull, volume-dependent). [`OutOfFamily`]
//! holds forms the Weibull × power-volume backbone CANNOT represent (multimodal,
//! long-plateau-then-cliff) — used by SIM-12b to test graceful degradation under
//! mis-specification.

#[cfg(test)]
mod tests;

use crate::generator::Rng;
use crate::surface_fit::{FailureDataset, FailureObs};

/// The HIDDEN true hazard form (ground-truth). Never reaches the estimator's
/// decision — it only drives event generation here.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HazardForm {
    /// Constant hazard `h(t) = rate` (memoryless ⇒ exponential time-to-failure).
    Exponential { rate: f64 },
    /// Bathtub: a Weibull with shape `k < 1` (infant-mortality, decreasing
    /// hazard) plus a late wear-out rise. Realised as a mixture of an
    /// infant-mortality Weibull and a late-onset wear-out component.
    Bathtub {
        /// Weibull shape of the early (infant-mortality) component, `k < 1`.
        early_k: f64,
        /// Weibull scale of the early component.
        early_lambda: f64,
        /// Onset time of the wear-out rise.
        wearout_onset: f64,
        /// Wear-out hazard slope past the onset.
        wearout_rate: f64,
    },
    /// Volume-dependent: base exponential hazard multiplied by `(volume/v_ref)^p`.
    VolumeDependent {
        base_rate: f64,
        v_ref: f64,
        exponent: f64,
    },
    /// A plain Weibull with shape `k` and scale `λ` — NO infant-mortality mixture
    /// and NO wear-out offset. `k < 1` is monotone-falling (DFR), `k = 1` is the
    /// exponential, `k ≥ 1` is monotone-rising PURE WEAR-OUT (IFR). The pure-IFR
    /// case (`k ≥ 1.5`) is the one the classifier must NOT call a bathtub: a
    /// monotone-rising hazard with no early infant-mortality region (`formula_phase`
    /// §3 — this `k ≥ 1` case KILLS seniority-as-horizon, the opposite of the `k<1`
    /// bathtub left edge).
    Weibull { k: f64, lambda: f64 },
}

/// OUT-OF-FAMILY true forms (SIM-12b) — the Weibull × power-volume backbone
/// cannot represent these. Used to test that the kernel's inflated-uncertainty
/// guardrail still keeps the estimate conservative when the form is WRONG.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutOfFamily {
    /// Bimodal time-to-failure: two failure clusters (early burst + late burst)
    /// with a quiet plateau between — a monotone-or-bathtub Weibull cannot match
    /// the dip-rise-dip-rise structure.
    Multimodal {
        /// Fraction failing in the early cluster.
        early_frac: f64,
        early_center: f64,
        early_spread: f64,
        late_center: f64,
        late_spread: f64,
    },
    /// Long flat plateau (almost no failures) then a sudden cliff (mass failure in
    /// a narrow window) — a heavy-tailed / deadline form Weibull's smooth hazard
    /// cannot capture.
    PlateauCliff {
        /// Plateau length: near-zero hazard until here.
        plateau: f64,
        /// Cliff width: failures concentrate in `[plateau, plateau+cliff_width]`.
        cliff_width: f64,
        /// Residual hazard during the plateau (small but nonzero).
        plateau_rate: f64,
    },
}

/// Sample a time-to-failure for one holder of the given hidden form. `volume` is
/// the holder's carried volume (only the volume-dependent form uses it).
fn sample_failure_time(form: HazardForm, volume: f64, rng: &mut Rng) -> f64 {
    match form {
        HazardForm::Exponential { rate } => exp_sample(rate.max(1e-9), rng),
        HazardForm::Bathtub {
            early_k,
            early_lambda,
            wearout_onset,
            wearout_rate,
        } => {
            // Mixture: most failures from the infant-mortality Weibull, plus a
            // late wear-out exponential offset past the onset. Take the minimum of
            // the two competing risks (whichever fires first).
            let infant = weibull_sample(early_k.max(1e-9), early_lambda.max(1e-9), rng);
            let wearout = wearout_onset + exp_sample(wearout_rate.max(1e-9), rng);
            infant.min(wearout)
        }
        HazardForm::VolumeDependent {
            base_rate,
            v_ref,
            exponent,
        } => {
            let mult = (volume.max(0.0) / v_ref.max(1e-9)).powf(exponent.max(0.0));
            exp_sample((base_rate * mult).max(1e-9), rng)
        }
        HazardForm::Weibull { k, lambda } => weibull_sample(k.max(1e-9), lambda.max(1e-9), rng),
    }
}

/// Sample a time-to-failure for one holder of an OUT-OF-FAMILY form.
fn sample_failure_time_oof(form: OutOfFamily, rng: &mut Rng) -> f64 {
    match form {
        OutOfFamily::Multimodal {
            early_frac,
            early_center,
            early_spread,
            late_center,
            late_spread,
        } => {
            if rng.unit() < early_frac {
                gaussian_like(early_center, early_spread, rng).max(0.0)
            } else {
                gaussian_like(late_center, late_spread, rng).max(0.0)
            }
        }
        OutOfFamily::PlateauCliff {
            plateau,
            cliff_width,
            plateau_rate,
        } => {
            // Small chance of an early (plateau) failure, else fail at the cliff.
            let early = exp_sample(plateau_rate.max(1e-12), rng);
            if early < plateau {
                early
            } else {
                plateau + rng.range(0.0, cliff_width.max(1e-9))
            }
        }
    }
}

/// Inverse-CDF exponential sample: `-ln(1-u)/rate`.
fn exp_sample(rate: f64, rng: &mut Rng) -> f64 {
    let u = rng.unit().min(1.0 - 1e-12);
    -(1.0 - u).ln() / rate.max(1e-12)
}

/// Inverse-CDF Weibull sample: `λ·(-ln(1-u))^{1/k}`.
fn weibull_sample(k: f64, lambda: f64, rng: &mut Rng) -> f64 {
    let u = rng.unit().min(1.0 - 1e-12);
    lambda * (-(1.0 - u).ln()).powf(1.0 / k.max(1e-9))
}

/// A crude Gaussian-like sample (sum of 4 uniforms, central-limit) centred at
/// `center` with spread `spread`. Dependency-free; good enough for clustering
/// failure times into modes.
fn gaussian_like(center: f64, spread: f64, rng: &mut Rng) -> f64 {
    let s = rng.unit() + rng.unit() + rng.unit() + rng.unit() - 2.0; // mean 0, ~N
    center + spread * s
}

/// Generate a honest in-family failure dataset for `n_holders`, censoring any
/// holder still alive at `horizon`. Volumes are drawn uniformly in `[v_lo, v_hi)`.
pub fn generate(
    form: HazardForm,
    n_holders: usize,
    horizon: f64,
    v_lo: f64,
    v_hi: f64,
    seed: u64,
) -> FailureDataset {
    let mut rng = Rng::new(seed);
    let mut data = FailureDataset::new();
    for _ in 0..n_holders {
        let volume = rng.range(v_lo, v_hi);
        let t = sample_failure_time(form, volume, &mut rng);
        if t >= horizon {
            data.push(FailureObs {
                time: horizon,
                censored: true,
                volume,
            });
        } else {
            data.push(FailureObs {
                time: t,
                censored: false,
                volume,
            });
        }
    }
    data
}

/// Generate a honest OUT-OF-FAMILY failure dataset (SIM-12b).
pub fn generate_oof(
    form: OutOfFamily,
    n_holders: usize,
    horizon: f64,
    v_lo: f64,
    v_hi: f64,
    seed: u64,
) -> FailureDataset {
    let mut rng = Rng::new(seed);
    let mut data = FailureDataset::new();
    for _ in 0..n_holders {
        let volume = rng.range(v_lo, v_hi);
        let t = sample_failure_time_oof(form, &mut rng);
        if t >= horizon {
            data.push(FailureObs {
                time: horizon,
                censored: true,
                volume,
            });
        } else {
            data.push(FailureObs {
                time: t,
                censored: false,
                volume,
            });
        }
    }
    data
}

/// TRUE survival `S(t) = P(T > t)` of an out-of-family form, by Monte-Carlo over a
/// large hidden sample. Used ONLY by the SIM-12b evaluator (god-view) to check the
/// kernel's estimate stays conservative — NEVER fed into a decision.
pub fn true_survival_oof(form: OutOfFamily, t: f64, n: usize, seed: u64) -> f64 {
    let mut rng = Rng::new(seed);
    let mut alive = 0usize;
    for _ in 0..n {
        if sample_failure_time_oof(form, &mut rng) > t {
            alive += 1;
        }
    }
    alive as f64 / n.max(1) as f64
}

/// TRUE survival of an IN-FAMILY Weibull form `S(τ) = exp(−(τ/λ_W)^k)`, computed
/// analytically (the Weibull tail is exact, no Monte-Carlo needed). Used ONLY by
/// the SIM-12b *counter-check*: when the offline prior form is CORRECT (the data
/// really are this Weibull), the kernel's conservative `r_hat` at long τ must stay
/// a USEFUL (non-vacuous) fraction of this true survival — proving the strengthened
/// off-sample inflation does not crush a correctly-specified prior to zero. God-view
/// only — NEVER fed into a decision.
pub fn true_survival_weibull(k: f64, lambda: f64, tau: f64) -> f64 {
    let k = k.max(1e-9);
    let lambda = lambda.max(1e-9);
    let tau = tau.max(0.0);
    (-(tau / lambda).powf(k)).exp().clamp(0.0, 1.0)
}
