//! Offline nonparametric survival/hazard estimator (SIM-12 calibration tool).
//!
//! This is the "experiments = nonparametric to DISCOVER the shape" path
//! (4r_trust_foundation.md §9.2): given a honest failure dataset (many holders ×
//! observed failure/censoring times × volumes) it recovers the hazard FORM
//! nonparametrically — Kaplan-Meier survival curves and a binned (piecewise)
//! hazard estimate — and classifies which qualitative law the data follow
//! (exponential / bathtub-with-infant-mortality+wear-out / volume-dependent).
//!
//! This module is NOT production code and does NOT live in the kernel. It is the
//! OFFLINE calibration that PRODUCES a [`viaticum_core::four_r::SurfacePrior`];
//! the production kernel reads the resulting form, it does not run this.
//!
//! ## ANTI-ORACLE litmus (meta-level, the load-bearing one for SIM-12)
//!
//! The estimator may see failure OUTCOMES — that is the legitimate curated
//! offline data. But it is **BLIND to the generator's true form**: its only input
//! is a [`FailureDataset`] of `(time, censored, volume)` triples. The generator's
//! hidden hazard form (`generator::HazardForm`) is NOT a field of `FailureDataset`
//! and is NEVER passed into [`classify_form`] or any fit here. If `classify_form`
//! returned a hardwired answer regardless of the data, THAT would be a form-oracle
//! — exactly the original sin the whole 4R redesign fights. PASS = it
//! DISTINGUISHES forms from the data, not "confirms one".

#[cfg(test)]
mod tests;

/// One observation in the honest failure dataset: a holder we watched until it
/// either failed (`censored == false`, `time` = time-to-failure) or we stopped
/// watching while it was still alive (`censored == true`, `time` = censoring
/// time). `volume` is the volume that holder was carrying.
///
/// This carries ONLY outcomes — there is deliberately no `form`/`archetype` field.
/// The estimator cannot see the generator's hidden law even if a future bug tried.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FailureObs {
    /// Time-to-failure (if `!censored`) or censoring time (if `censored`).
    pub time: f64,
    /// True iff the holder was still alive when observation ended (right-censored).
    pub censored: bool,
    /// Volume the holder was carrying (the V-axis covariate).
    pub volume: f64,
}

/// A honest failure dataset: many holders' observed outcomes. Blind to the
/// generator's form by construction (no form field anywhere).
#[derive(Debug, Clone, Default)]
pub struct FailureDataset {
    pub obs: Vec<FailureObs>,
}

impl FailureDataset {
    pub fn new() -> Self {
        FailureDataset { obs: Vec::new() }
    }

    pub fn push(&mut self, o: FailureObs) {
        self.obs.push(o);
    }

    pub fn len(&self) -> usize {
        self.obs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.obs.is_empty()
    }
}

/// A Kaplan-Meier survival curve: the nonparametric estimate of `S(t) = P(T > t)`
/// from right-censored data, with no parametric form assumed.
#[derive(Debug, Clone, PartialEq)]
pub struct KaplanMeier {
    /// Distinct event times (ascending) at which the estimate steps down.
    pub times: Vec<f64>,
    /// `S(t)` at each event time (the product-limit estimate, non-increasing).
    pub survival: Vec<f64>,
}

impl KaplanMeier {
    /// Survival at an arbitrary time `t` (right-continuous step function): the
    /// last `survival[i]` whose `times[i] <= t`, or 1.0 before the first event.
    pub fn at(&self, t: f64) -> f64 {
        let mut s = 1.0;
        for (i, &ti) in self.times.iter().enumerate() {
            if ti <= t {
                s = self.survival[i];
            } else {
                break;
            }
        }
        s
    }
}

/// Compute the Kaplan-Meier product-limit estimate from a (possibly censored)
/// failure dataset. No parametric form is assumed — this is the nonparametric
/// backbone of the discovery.
///
/// At each distinct failure time `t_i` with `d_i` failures out of `n_i` still
/// at risk, `S` multiplies by `(1 − d_i/n_i)`. Censored observations leave the
/// risk set without an event (they reduce `n` at later times).
pub fn kaplan_meier(data: &FailureDataset) -> KaplanMeier {
    // Sort observations by time. At a tie, process failures before censorings so
    // the at-risk count is conventional (censored-at-t are still at risk at t).
    let mut items: Vec<FailureObs> = data.obs.clone();
    items.sort_by(|a, b| {
        a.time
            .total_cmp(&b.time)
            .then((a.censored as u8).cmp(&(b.censored as u8)))
    });

    let n_total = items.len();
    let mut times = Vec::new();
    let mut survival = Vec::new();
    let mut s = 1.0_f64;
    let mut i = 0;
    let mut at_risk = n_total;

    while i < n_total {
        let t = items[i].time;
        // Count failures and total leaving (failures + censorings) at this time.
        let mut deaths = 0usize;
        let mut leaving = 0usize;
        let mut j = i;
        while j < n_total && items[j].time == t {
            if !items[j].censored {
                deaths += 1;
            }
            leaving += 1;
            j += 1;
        }
        if deaths > 0 && at_risk > 0 {
            s *= 1.0 - (deaths as f64) / (at_risk as f64);
            times.push(t);
            survival.push(s);
        }
        at_risk = at_risk.saturating_sub(leaving);
        i = j;
    }

    KaplanMeier { times, survival }
}

/// A binned (piecewise-constant) hazard estimate: the empirical instantaneous
/// failure rate `h(t) ≈ deaths_in_bin / (person-time-at-risk in bin)` over equal
/// time bins. This is the actuarial / life-table hazard — the direct nonparametric
/// view of the hazard SHAPE (rising / falling / U-shaped) that the discovery reads.
#[derive(Debug, Clone, PartialEq)]
pub struct BinnedHazard {
    /// Bin upper edges (ascending).
    pub edges: Vec<f64>,
    /// Estimated hazard rate in each bin (same length as `edges`). `NaN` is never
    /// produced — a bin with zero person-time reports 0.0.
    pub hazard: Vec<f64>,
}

/// Estimate the binned hazard over `n_bins` equal-width bins spanning `[0, t_max]`,
/// where `t_max` is the largest observed time. Person-time is accumulated exactly:
/// each observation contributes the time it spent at risk within each bin, and a
/// failure contributes one death to the bin its failure time falls in.
pub fn binned_hazard(data: &FailureDataset, n_bins: usize) -> BinnedHazard {
    let n_bins = n_bins.max(1);
    let t_max = data
        .obs
        .iter()
        .map(|o| o.time)
        .fold(0.0_f64, |m, t| m.max(t))
        .max(1e-9);
    let width = t_max / n_bins as f64;

    let mut edges = Vec::with_capacity(n_bins);
    for b in 0..n_bins {
        edges.push(width * (b + 1) as f64);
    }

    let mut deaths = vec![0.0_f64; n_bins];
    let mut person_time = vec![0.0_f64; n_bins];

    for o in &data.obs {
        // Spread the at-risk time of this observation across bins up to `o.time`.
        let end = o.time;
        for (b, pt) in person_time.iter_mut().enumerate() {
            let lo = width * b as f64;
            let hi = width * (b + 1) as f64;
            if lo >= end {
                break;
            }
            let overlap = end.min(hi) - lo;
            if overlap > 0.0 {
                *pt += overlap;
            }
        }
        // A failure contributes a death to its bin.
        if !o.censored {
            let b = ((end / width).floor() as usize).min(n_bins - 1);
            deaths[b] += 1.0;
        }
    }

    let hazard = deaths
        .iter()
        .zip(person_time.iter())
        .map(|(&d, &pt)| if pt > 0.0 { d / pt } else { 0.0 })
        .collect();

    BinnedHazard { edges, hazard }
}

/// The qualitative hazard form recovered nonparametrically from the data. This is
/// the estimator's ANSWER — it is computed from the data, never read from the
/// generator. Mirrors (but is independent of) the generator's hidden form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveredForm {
    /// Roughly constant hazard over time (memoryless ⇒ exponential).
    Exponential,
    /// Falling-then-rising hazard (bathtub: infant-mortality + wear-out).
    Bathtub,
    /// Hazard rises markedly with volume (volume-dependent law).
    VolumeDependent,
}

/// Summary of the nonparametric trend used to classify the time-axis shape.
///
/// The time-shape fields implement an INTERIOR-TROUGH U-detector. A true bathtub
/// has a genuine interior minimum: a high infant-mortality region EARLY, a dip to a
/// trough IN THE INTERIOR, then a wear-out rise LATE. The detector locates the
/// trough bin (the global hazard minimum among bins with appreciable person-time)
/// and then measures the peak BEFORE it (`early_peak`, the infant-mortality side)
/// and the peak AFTER it (`late_peak`, the wear-out side).
///
/// The interior position is load-bearing. A pure WEAR-OUT (monotone increasing
/// hazard, Weibull `k ≥ 1` with NO infant mortality) has its minimum at the START,
/// so there is NO bin before the trough — `early_peak` is then 0 and there is no
/// early segment rising above an interior trough. That is exactly the case
/// `formula_phase.md` §3 says KILLS seniority-as-horizon (the OPPOSITE of the `k<1`
/// infant-mortality bathtub), so it must NOT classify as a bathtub. The earlier
/// global-min-only detector accepted it (a monotone-IFR global min trivially sits
/// below the late peak), a real form-error this fixes.
///
/// (Using the PEAK within a segment, not the mean, keeps the detector robust to a
/// SHARP infant-mortality spike concentrated in the first bin — diluting it into a
/// mean-of-thirds was a real miss in an early SIM-12 run.)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ShapeSummary {
    /// Peak hazard among the bins STRICTLY BEFORE the interior trough bin (the
    /// infant-mortality side). `0.0` if the trough is the first bin (monotone IFR).
    pub early_peak: f64,
    /// Global minimum hazard among bins with appreciable person-time (the trough).
    pub trough_hazard: f64,
    /// Peak hazard among the bins STRICTLY AFTER the interior trough bin (the
    /// wear-out side). `0.0` if the trough is the last bin (monotone DFR).
    pub late_peak: f64,
    /// True iff the trough bin lies in the INTERIOR — there is at least one bin
    /// (with person-time) both before AND after it. A monotone hazard (pure IFR or
    /// pure DFR) has its trough at an endpoint, so this is false for them.
    pub trough_interior: bool,
    /// Hazard for the LOW-volume half of the population (pooled).
    pub low_volume_hazard: f64,
    /// Hazard for the HIGH-volume half of the population (pooled).
    pub high_volume_hazard: f64,
}

/// Compute the shape summary: time-axis INTERIOR-TROUGH U-detector (peak before /
/// trough / peak after, plus whether the trough is genuinely interior) and the
/// volume split (low-vs-high-volume hazard). Pure nonparametric reads of the data —
/// no form assumed.
pub fn shape_summary(data: &FailureDataset, n_bins: usize) -> ShapeSummary {
    let bh = binned_hazard(data, n_bins);
    let n = bh.hazard.len();

    let max_of = |slice: &[f64]| -> f64 { slice.iter().copied().fold(0.0_f64, f64::max) };

    // Locate the trough = the bin with the global MINIMUM hazard among bins that
    // actually carry failures (hazard exactly 0 means "no person-time / no data
    // here", not a real low — skip those when picking the trough).
    let mut trough_idx: Option<usize> = None;
    let mut trough_hazard = f64::INFINITY;
    for (b, &h) in bh.hazard.iter().enumerate() {
        if h > 0.0 && h < trough_hazard {
            trough_hazard = h;
            trough_idx = Some(b);
        }
    }
    let trough_hazard = if trough_hazard.is_finite() {
        trough_hazard
    } else {
        0.0
    };

    // Peaks strictly BEFORE and strictly AFTER the trough bin, and whether the
    // trough is interior (a bin with failures exists on BOTH sides of it). A
    // monotone-rising (pure wear-out / IFR) hazard troughs at the first bin → no
    // "before" segment → early_peak 0, not interior; a monotone-falling (pure DFR)
    // hazard troughs at the last bin → no "after" segment.
    let (early_peak, late_peak, trough_interior) = match trough_idx {
        Some(ti) => {
            let before = &bh.hazard[0..ti];
            let after = if ti + 1 < n {
                &bh.hazard[ti + 1..n]
            } else {
                &[][..]
            };
            let has_before = before.iter().any(|&h| h > 0.0);
            let has_after = after.iter().any(|&h| h > 0.0);
            (max_of(before), max_of(after), has_before && has_after)
        }
        None => (0.0, 0.0, false),
    };

    // Volume split: median volume, then hazard of each half independently.
    let mut vols: Vec<f64> = data.obs.iter().map(|o| o.volume).collect();
    vols.sort_by(|a, b| a.total_cmp(b));
    let med_v = if vols.is_empty() {
        0.0
    } else {
        vols[vols.len() / 2]
    };
    let low: FailureDataset = FailureDataset {
        obs: data
            .obs
            .iter()
            .copied()
            .filter(|o| o.volume <= med_v)
            .collect(),
    };
    let high: FailureDataset = FailureDataset {
        obs: data
            .obs
            .iter()
            .copied()
            .filter(|o| o.volume > med_v)
            .collect(),
    };
    let low_h = overall_hazard(&low);
    let high_h = overall_hazard(&high);

    ShapeSummary {
        early_peak,
        trough_hazard,
        late_peak,
        trough_interior,
        low_volume_hazard: low_h,
        high_volume_hazard: high_h,
    }
}

/// Overall (pooled) hazard `total_deaths / total_person_time` of a dataset.
/// Person-time = sum of all observed times (each obs is at risk for its whole
/// observed duration). A single scalar summary of failure intensity.
pub fn overall_hazard(data: &FailureDataset) -> f64 {
    let deaths: f64 = data.obs.iter().filter(|o| !o.censored).count() as f64;
    let person_time: f64 = data.obs.iter().map(|o| o.time).sum();
    if person_time > 0.0 {
        deaths / person_time
    } else {
        0.0
    }
}

/// Classify the recovered hazard FORM nonparametrically from the data alone.
///
/// ANTI-ORACLE: the only argument is `data` (outcomes). The generator's true form
/// is NOT available here. The decision rule:
///
/// 1. **Volume-dependence first.** If the high-volume half's hazard is much larger
///    than the low-volume half's (ratio above `vol_ratio_thresh`), the dominant
///    discovered structure is volume-dependence.
/// 2. Otherwise look at the TIME shape with an INTERIOR-TROUGH U-detector: a
///    bathtub requires a genuine interior trough — the hazard minimum lies strictly
///    inside (a bin with failures on BOTH sides), with the peak BEFORE it
///    (infant-mortality) AND the peak AFTER it (wear-out) both materially above the
///    trough. A pure WEAR-OUT (monotone-rising, `k ≥ 1`, no infant mortality)
///    troughs at the START, so there is no early segment above an interior trough →
///    it is NOT a bathtub (it is the seniority-killing IFR case, classified as
///    wear-out/IFR, never bathtub).
/// 3. Else (flat within tolerance, or monotone with no interior trough) it is
///    **exponential** (the conservative default — see the honest-scope note in
///    `sim12`: near-threshold / weak-signal forms fall back to the conservative
///    form, and the SIM-12b conservatism guardrail is the backstop for any form
///    error here).
///
/// `vol_ratio_thresh` and `bathtub_rel` are tuning knobs of the CLASSIFIER, not of
/// the generator; they are passed in so a scenario can document the CI it used.
pub fn classify_form(
    data: &FailureDataset,
    vol_ratio_thresh: f64,
    bathtub_rel: f64,
) -> RecoveredForm {
    let n_bins = 12;
    let s = shape_summary(data, n_bins);

    // 1. Volume-dependence.
    let vol_ratio = if s.low_volume_hazard > 0.0 {
        s.high_volume_hazard / s.low_volume_hazard
    } else if s.high_volume_hazard > 0.0 {
        f64::INFINITY
    } else {
        1.0
    };
    if vol_ratio >= vol_ratio_thresh {
        return RecoveredForm::VolumeDependent;
    }

    // 2. Bathtub INTERIOR-TROUGH detector: the trough must be genuinely interior
    //    (failures on both sides), AND the early peak (before it) AND the late peak
    //    (after it) must both be materially above the trough. Robust to a sharp
    //    infant-mortality spike (peak, not mean). A monotone-rising pure-IFR hazard
    //    troughs at the start ⇒ `trough_interior` is false ⇒ NOT a bathtub.
    let trough = s.trough_hazard.max(1e-12);
    let early_up = s.early_peak / trough;
    let late_up = s.late_peak / trough;
    if s.trough_interior && early_up >= bathtub_rel && late_up >= bathtub_rel {
        return RecoveredForm::Bathtub;
    }

    // 3. Otherwise flat / monotone-without-interior-trough ⇒ exponential default.
    RecoveredForm::Exponential
}
