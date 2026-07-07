//! R̂-CALIBRATION scoring (transche 0.3) — the JUDGE of sim-unification (spec §10 п.7).
//!
//! The 0.3 acceptance question is NOT "did share A>0 move" (that metric is saturated near
//! its ceiling) but "is the node's own survival forecast R̂_wc WELL-CALIBRATED against what
//! actually happens". The engine logs, at each successful placement, the block's forecast
//! survival over a horizon `H` (`World::pred_log`, a god-view metric channel); the runner
//! resolves each forecast against the realised outcome "block still has ≥ `k_eff` live
//! symbols `H` ticks later". This module turns that `(forecast, outcome)` dataset into a
//! Brier score + its Murphy reliability/resolution/uncertainty decomposition.
//!
//! God-view, evaluator-only (anti-oracle): the forecast `r_hat` is a COPY of the kernel's
//! own output, read here ONLY to score it — never fed back into any decision. The outcome
//! is a god-view read of the real engine run.
//!
//! ## Brier + decomposition
//!
//! * **Brier** `BS = (1/N) Σ (f_i − o_i)²` — mean squared forecast error, `o_i ∈ {0,1}`.
//!   Lower is better; a perfect forecast scores 0, a constant `0.5` on a 50/50 world 0.25.
//! * **Murphy decomposition** over `B` forecast buckets: `BS = reliability − resolution +
//!   uncertainty`, where
//!   * `reliability = Σ_b (n_b/N)(f̄_b − ō_b)²` — how far each bucket's mean forecast sits
//!     from its observed frequency (LOWER better: 0 = perfectly calibrated);
//!   * `resolution  = Σ_b (n_b/N)(ō_b − ō)²` — how much the buckets separate outcomes from
//!     the base rate (HIGHER better: a forecast that always predicts the base rate has 0);
//!   * `uncertainty = ō(1−ō)` — the irreducible variance of the outcome, forecast-free.
//!
//! The identity is EXACT when forecasts are constant within a bucket; with a spread of
//! forecasts inside a bucket there is a small within-bin term, so we report the DIRECT
//! Brier as the headline and the decomposition as diagnostics.

/// The default number of equal-width forecast buckets for the decomposition (spec §10 п.7).
pub const DEFAULT_BRIER_BUCKETS: usize = 10;

/// The resolved R̂-calibration dataset for one seed: `(forecast r_hat, realised outcome,
/// floor_complete)` triples, in placement→resolution order (deterministic). A GOD-VIEW metric
/// container — the forecasts are copies of the kernel's own output, scored here, never fed back.
///
/// **WARN-1 split.** `floor_complete == false` marks a STILL-INCOMPLETE block (fewer than
/// `k_eff` symbols at the forecast), whose A.9 `r_hat` is a forced structural zero carrying no
/// information. The Brier JUDGE ([`Calibration::complete_report`]) scores ONLY the complete
/// rows; the incomplete population is a separate structural-zero diagnostic
/// ([`Calibration::incomplete_summary`]).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Calibration {
    /// `(r_hat ∈ [0,1], block survived ≥ k_eff to horizon H, floor_complete)` triples.
    pub pairs: Vec<(f64, bool, bool)>,
}

impl Calibration {
    /// A fresh empty dataset.
    pub fn new() -> Self {
        Calibration { pairs: Vec::new() }
    }

    /// Record one resolved prediction (`r_hat` clamped to `[0,1]`). `floor_complete` marks
    /// whether the block held ≥ `k_eff` symbols at the forecast (a real forecast vs a
    /// structural-zero incomplete row).
    pub fn push(&mut self, r_hat: f64, outcome: bool, floor_complete: bool) {
        self.pairs
            .push((r_hat.clamp(0.0, 1.0), outcome, floor_complete));
    }

    /// How many resolved predictions this seed contributed (both cuts).
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Whether no prediction was resolved (⇒ no Brier report).
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// The Brier JUDGE (WARN-1): the report over the FLOOR-COMPLETE rows only (`≥ k_eff`
    /// symbols at the forecast) — the rows whose `r_hat` is a real, informative forecast.
    /// `None` when no complete prediction resolved.
    pub fn complete_report(&self, buckets: usize) -> Option<BrierReport> {
        let pts: Vec<(f64, bool)> = self
            .pairs
            .iter()
            .filter(|(_, _, c)| *c)
            .map(|&(f, o, _)| (f, o))
            .collect();
        report_from(&pts, buckets)
    }

    /// The report over ALL resolved rows (complete + incomplete), for diagnostics and the
    /// pure-math synthetic tests. `None` when empty.
    pub fn overall_report(&self, buckets: usize) -> Option<BrierReport> {
        let pts: Vec<(f64, bool)> = self.pairs.iter().map(|&(f, o, _)| (f, o)).collect();
        report_from(&pts, buckets)
    }

    /// The structural-zero diagnostic: the INCOMPLETE population (`< k_eff` symbols at the
    /// forecast, `r_hat` forced 0). Reports its size, mean forecast, observed survival, and
    /// share of the whole dataset. `None` when there is no incomplete row.
    pub fn incomplete_summary(&self) -> Option<IncompleteSummary> {
        let total = self.pairs.len();
        let inc: Vec<(f64, bool)> = self
            .pairs
            .iter()
            .filter(|(_, _, c)| !*c)
            .map(|&(f, o, _)| (f, o))
            .collect();
        let n = inc.len();
        if n == 0 {
            return None;
        }
        let mean_forecast = inc.iter().map(|(f, _)| *f).sum::<f64>() / n as f64;
        let observed_freq = inc.iter().filter(|(_, o)| *o).count() as f64 / n as f64;
        Some(IncompleteSummary {
            n,
            mean_forecast,
            observed_freq,
            share_of_total: if total > 0 {
                n as f64 / total as f64
            } else {
                0.0
            },
        })
    }
}

/// The structural-zero diagnostic for the incomplete-block forecast population (WARN-1).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IncompleteSummary {
    /// How many incomplete-block forecasts resolved.
    pub n: usize,
    /// Their mean forecast `f̄` (≈ 0 — the structural zero).
    pub mean_forecast: f64,
    /// Their observed survival frequency `ō` (repair fills the block, so this is HIGH — the
    /// mismatch that WARN-1 excludes from the judge).
    pub observed_freq: f64,
    /// Their share of the whole resolved dataset.
    pub share_of_total: f64,
}

/// Compute a [`BrierReport`] over `(r_hat, outcome)` points and `buckets` bins (`≥ 1`).
/// `None` when there is no point. Shared by the complete / overall cuts.
fn report_from(points: &[(f64, bool)], buckets: usize) -> Option<BrierReport> {
    let n = points.len();
    if n == 0 {
        return None;
    }
    let nb = buckets.max(1);
    let nf = n as f64;

    // Direct Brier + base rate.
    let mut se = 0.0f64;
    let mut o_sum = 0.0f64;
    for &(f, o) in points {
        let ov = if o { 1.0 } else { 0.0 };
        se += (f - ov) * (f - ov);
        o_sum += ov;
    }
    let brier = se / nf;
    let base_rate = o_sum / nf;
    let uncertainty = base_rate * (1.0 - base_rate);

    // Per-bucket aggregation (equal-width; the top bucket is closed at 1.0).
    let mut count = vec![0usize; nb];
    let mut f_sum = vec![0.0f64; nb];
    let mut out_sum = vec![0.0f64; nb];
    for &(f, o) in points {
        let b = bucket_index(f, nb);
        count[b] += 1;
        f_sum[b] += f;
        out_sum[b] += if o { 1.0 } else { 0.0 };
    }

    let mut reliability = 0.0f64;
    let mut resolution = 0.0f64;
    let mut bkts = Vec::with_capacity(nb);
    for b in 0..nb {
        let (lo, hi) = bucket_edges(b, nb);
        let nbk = count[b];
        if nbk == 0 {
            bkts.push(BrierBucket {
                lo,
                hi,
                n: 0,
                mean_forecast: f64::NAN,
                observed_freq: f64::NAN,
            });
            continue;
        }
        let w = nbk as f64 / nf;
        let f_bar = f_sum[b] / nbk as f64;
        let o_bar = out_sum[b] / nbk as f64;
        reliability += w * (f_bar - o_bar) * (f_bar - o_bar);
        resolution += w * (o_bar - base_rate) * (o_bar - base_rate);
        bkts.push(BrierBucket {
            lo,
            hi,
            n: nbk,
            mean_forecast: f_bar,
            observed_freq: o_bar,
        });
    }

    Some(BrierReport {
        n,
        brier,
        reliability,
        resolution,
        uncertainty,
        base_rate,
        buckets: bkts,
    })
}

/// The equal-width bucket index of a forecast `f ∈ [0,1]`: `min(⌊f·B⌋, B−1)` (the top edge
/// is closed at 1.0 so `f == 1.0` lands in the last bucket).
fn bucket_index(f: f64, buckets: usize) -> usize {
    let b = (f.clamp(0.0, 1.0) * buckets as f64).floor() as usize;
    b.min(buckets - 1)
}

/// The `[lo, hi)` edges of bucket `b` of `buckets`.
fn bucket_edges(b: usize, buckets: usize) -> (f64, f64) {
    let w = 1.0 / buckets as f64;
    (b as f64 * w, (b as f64 + 1.0) * w)
}

/// One forecast bucket's calibration facts.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BrierBucket {
    /// Bucket lower edge (inclusive).
    pub lo: f64,
    /// Bucket upper edge (exclusive except the last, closed at 1.0).
    pub hi: f64,
    /// How many predictions fell in this bucket.
    pub n: usize,
    /// The mean forecast `f̄_b` in the bucket (`NaN` if empty).
    pub mean_forecast: f64,
    /// The observed survival frequency `ō_b` in the bucket (`NaN` if empty).
    pub observed_freq: f64,
}

/// The Brier score + Murphy decomposition for one seed's calibration dataset.
#[derive(Debug, Clone, PartialEq)]
pub struct BrierReport {
    /// Number of resolved predictions (the denominator `N`).
    pub n: usize,
    /// Direct Brier `(1/N) Σ (f−o)²` (the headline; lower better).
    pub brier: f64,
    /// Reliability `Σ_b (n_b/N)(f̄_b−ō_b)²` (lower better; 0 = perfectly calibrated).
    pub reliability: f64,
    /// Resolution `Σ_b (n_b/N)(ō_b−ō)²` (higher better; 0 = no discrimination).
    pub resolution: f64,
    /// Uncertainty `ō(1−ō)` (forecast-free irreducible variance).
    pub uncertainty: f64,
    /// The outcome base rate `ō` (fraction of blocks that survived to `H`).
    pub base_rate: f64,
    /// Per-bucket calibration detail (reliability diagram rows).
    pub buckets: Vec<BrierBucket>,
}

/// Bit-exact equality of two calibration datasets (used by the determinism board row so the
/// R̂-calibration channel is covered too). `f64::to_bits` so a deterministic value matches
/// itself exactly.
pub fn bit_eq(a: &Calibration, b: &Calibration) -> bool {
    a.pairs.len() == b.pairs.len()
        && a.pairs
            .iter()
            .zip(&b.pairs)
            .all(|((fa, oa, ca), (fb, ob, cb))| {
                fa.to_bits() == fb.to_bits() && oa == ob && ca == cb
            })
}
