//! P8 — does the RECIPROCITY SHARE HOLD under a steady inflow? (`4r_p8_spec.md`)
//!
//! ## The question (Ilya's counter-hypothesis, 2026-07-05)
//!
//! `share_a_pos` — the share of alive symbols sitting on pairs that carry reciprocity (`A > 0`) —
//! reads ≈ 75.9 % on the closed `honest_v2` anchor. A closed world is a weak witness: nobody
//! arrives, so everyone has had the whole horizon to serve everyone else. The strong form of the
//! P8 question needs a world with a CONTINUOUS newcomer stream, which mechanically DILUTES the
//! share (every arrival starts at `A = 0` and immediately begins placing on `A = 0` pairs):
//!
//! > under steady inflow, does the share HOLD / RISE (reciprocity compounds faster than arrivals
//! > dilute), or does it SLIDE (dilution wins, and 75.9 % was an artifact of the closed world)?
//!
//! A slide is a first-class RESULT, not a failure — `4r_decision_model.md` §11 says so explicitly
//! ("if A>0 sticks even in world v2, the binding constraint is NOT bootstrap — that is also a
//! result"). Calibrate the SCENARIO (inflow intensity, horizon); never the bar.
//!
//! ## The measured answer, stated at the strength the numbers support
//!
//! **Under sustained dilution the share HOLDS ON A PLATEAU; self-reinforcement OFFSETS dilution
//! rather than outrunning it.** The stronger reading ("reciprocity compounds FASTER than arrivals
//! dilute") is NOT supported and was withdrawn after an adversarial review of this tranche:
//!
//! * the board LEVEL holds — 60.33 ± 1.84 % under the stream, nowhere near the "sticks at a few
//!   percent" null, which is the pre-registered question P8 was built to answer;
//! * but the within-arm RISE cannot carry the causal half of the story. Scored over the SAME
//!   window, the matched CLOSED control rises MORE than the inflow arm (see
//!   [`RecipSeries::inflow_phase_rise`]), so the rise is a shared recovery leg minus dilution, not
//!   evidence that reciprocity outgrows the stream;
//! * in the MATURE phase, with the stream already steady, there is no growth left to find at all
//!   ([`RecipSeries::mature_rise`] reads flat) while the standing newcomer stock keeps climbing.
//!   A flat share under a growing newcomer stock IS the finding: dilution is being paid for
//!   continuously and continuously offset.
//!
//! ## Model ↔ sim: the entry chain runs in the OPPOSITE ORDER (finding, not a bug)
//!
//! `4r_decision_model.md` orders a newcomer's entry as *place your own data (free under `V_free`)
//! → store other people's → `g_ho` grows → preemption opens at ≈ `θ_p/λ`*. The sim runs it the
//! other way round: a newcomer SERVES from its very first tick (median join → first earned `g` = 0
//! ticks) and gets its OWN data placed only 7-12 ticks later, if ever (only ~74 % ever do — see
//! [`EntryStats::n_own_placed`]). Neither side is wrong-by-construction; they are two different
//! bootstrap orders, and the difference matters because the model's `θ_p/λ ≈ 1-3 ticks` prediction
//! is about a LATER milestone (preemption opening) than the sim's `first_earned_g` (the first PoS
//! pass). Do not read one as a measurement of the other.
//!
//! ## Evaluator-only, god-view — the same discipline as restore-truth
//!
//! [`RecipSeries`] is read from the god-view [`World`] in the EVALUATOR role and is NEVER fed back
//! into any node decision, exactly like `restore::RestoreTruth` and `inflow::PopSeries`. It draws
//! no RNG and mutates nothing, so recording it cannot perturb the world (the anchor test
//! `p8_series_is_a_pure_observer_of_the_world` pins that: the runner's metrics with the series ON
//! match a series-free bare `step` loop bit for bit).
//!
//! ## What is deliberately NOT built here (spec §1.3)
//!
//! No second reciprocity metric. `share_a_pos` already exists — overall
//! ([`crate::sim_adv::metrics::share_a_pos_percent`]), per tier (`tier.rs`) and per demand class
//! (`hetero.rs`). P8 adds the TRAJECTORY of the existing read plus the newcomer's entry time; it
//! does not invent a new one.

use crate::sim_dynamic::generator::World;

/// The RIGHT-CENSORING guard for the P8-B entry-time read: a newcomer needs at least this many
/// ticks of exposure before the horizon to count in the cohort. FROZEN at 12 (≈ 3 months of weekly
/// ticks) — generously larger than the model's own `θ_p/λ ≈ 1-3` tick prediction, so a node in the
/// cohort has had several times the predicted latency to earn. This is a MEASUREMENT hygiene
/// constant, not a bar: nothing passes or fails on it (P8-B asserts only non-emptiness, spec §4.2).
pub const ENTRY_MIN_EXPOSURE_TICKS: u64 = 12;

/// The WIDTH (in ticks) of the baseline window [`RecipSeries::inflow_phase_rise`] averages over:
/// the 10 ticks immediately before [`RecipSeries::onset_tick`]. 10 weekly ticks ≈ 2 months — long
/// enough to average out per-tick jitter.
///
/// **What this window actually is — read this before quoting the rise it feeds.** On the
/// `p8_reciprocity` scenario the measured onsets are ticks `[68, 68, 68, 66, 68]` (1-based, as the
/// tests print them), so the window covers **ticks 58-67**. Two things it is NOT:
///
/// * it is NOT past the world's bootstrap ramp. `T_join = round(join_horizon_ticks · t_join_frac)
///   = round(130 · 0.5) = 65`, so **8 of the 10 baseline ticks sit INSIDE the ramp**, with the
///   bootstrap cohort still joining;
/// * it is NOT pre-arrival. `apply_inflow` spreads the pool evenly over `[1, horizon−1]`, so
///   **≈ 32 of the 76 pool nodes have already arrived** before the window opens. What begins at
///   the onset is the COUNTING of newcomers (arrivals past the A15 cut), not the arrivals.
///
/// On top of that the measured trajectory is U-SHAPED (3.30 % at t1 → 64.85 % at t21 → a **50.50 %
/// TROUGH at t51** → 60-66 % at t160), and this window reads 50.76 ± 1.24 % — the trough, not a
/// settled level. A rise measured off it is dominated by the shared post-trough recovery and
/// therefore **cannot carry a causal claim on its own**: scored over the SAME window the matched
/// CLOSED control rises MORE (+15.19 pp vs the inflow arm's +9.56 pp — see
/// `p8_dilution_gap_vs_the_matched_closed_world`, which prints both side by side).
pub const INFLOW_BASELINE_WINDOW: usize = 10;

/// The MATURE-PHASE window pair (0-based tick indices, half-open `[a, b)`) for
/// [`RecipSeries::mature_rise`] — the honest answer to "once the stream is STEADY, does the share
/// still grow, or does it only hold?".
///
/// Both windows are 10 ticks wide (as [`INFLOW_BASELINE_WINDOW`]) and both sit far past the
/// bootstrap ramp (`T_join = 65`) and past the U-shape's trough (t ≈ 51), so neither contains
/// warm-up or the recovery leg. The standing newcomer stock still GROWS between them (13.3 → 37.8
/// on `p8_reciprocity`), which is what makes a flat read informative rather than empty. Frozen
/// against the 160-tick P8 horizon; on a shorter series [`RecipSeries::mean_over`] clamps and the
/// read degrades to `NaN` rather than silently sliding to another part of the curve.
pub const MATURE_EARLY_WINDOW: (usize, usize) = (90, 100);

/// The LATE half of the mature-phase window pair — see [`MATURE_EARLY_WINDOW`].
pub const MATURE_LATE_WINDOW: (usize, usize) = (150, 160);

/// God-view count of PRESENT nodes that joined strictly AFTER `cutoff` — the standing stock of
/// COUNTABLE newcomers, i.e. the denominator the dilution acts through.
///
/// ⚠ This counts arrivals PAST THE CUT, not arrivals. Under `InflowPolicy::Steady` the pool starts
/// landing at tick 1, but a pool node that arrives during the bootstrap ramp has `joined_tick
/// <= cutoff` and is folded into the cohort, so this read stays 0 for the first ≈ 65 ticks while
/// ~40 % of the pool has in fact already joined. "Newcomers = 0" therefore means "no arrival past
/// the cohort yet", NOT "nobody has arrived".
///
/// `cutoff` is the A15 newcomer cut ([`crate::sim_adv::inflow::newcomer_cutoff`]): the last tick
/// of the initial bootstrap cohort. In a CLOSED world the cut is taken over the whole population,
/// so nothing sits past it and this reads 0 at every tick — the honest reading ("a closed world
/// has no newcomers"), and exactly what makes the inflow-ON/OFF comparison legible. Pure read;
/// never a decision input.
pub fn newcomers_present(world: &World, cutoff: u64) -> usize {
    world
        .nodes
        .iter()
        .filter(|nd| nd.present && nd.joined_tick > cutoff)
        .count()
}

/// One seed's reciprocity trajectory + newcomer-entry trace (the P8 deliverable, spec §1.2).
///
/// Built by the runner: the two per-tick vectors are pushed AFTER each `step` (index = tick,
/// length = horizon); the two per-node vectors are read once at the horizon, in node-index order
/// (deterministic, no RNG).
#[derive(Debug, Clone, PartialEq)]
pub struct RecipSeries {
    /// `share_a_pos` IN PERCENT (the same scale as [`crate::sim_adv::MetricSet::share_a_pos`]) at
    /// each tick — the trajectory P8-A reads.
    pub share_a_pos: Vec<f64>,
    /// PRESENT nodes that joined after [`RecipSeries::cutoff`], at each tick — the dilution
    /// denominator ([`newcomers_present`]).
    pub newcomers_present: Vec<usize>,
    /// Per node: the tick it FIRST earned `g` as a SERVER (`world.first_earned_g` — set by the
    /// engine the first tick the node passes a PoS challenge as a HOLDER), or `None` if it never
    /// did. See the module note on the capital index: earning as a server writes
    /// `capital[server][owner].g_ho`.
    pub first_earned_tick: Vec<Option<u64>>,
    /// Per node: the tick its CURRENT identity joined (`world.nodes[i].joined_tick`).
    pub joined_tick: Vec<u64>,
    /// Per node: the tick its OWN first symbol was accepted by any holder
    /// (`world.first_own_accept`), or `None`. The far end of the entry chain the P8-B question
    /// actually asks about — "join → serve → get your own data placed" — so the report can say
    /// whether the newcomer merely earned credit or actually got backed up.
    pub first_own_accept: Vec<Option<u64>>,
    /// Per node: was it still PRESENT at the horizon? Carried so the entry-time read can state its
    /// own censoring honestly (a newcomer that churned out early is not the same thing as one that
    /// failed to break in).
    pub present_at_end: Vec<bool>,
    /// The newcomer cut this series was taken at (the last bootstrap-cohort join tick).
    pub cutoff: u64,
}

/// The newcomer ENTRY-TIME read (P8-B): how long a newcomer waits between joining and first
/// earning reciprocity as a server — and, the number that matters more to the newcomer itself,
/// whether it ever got its OWN data backed up.
///
/// ⚠ The earn-side gap is **not** the model's `θ_p/λ ≈ 1-3 ticks`: see the module note on the
/// reversed chain order. `first_earned_g` is the first PoS pass as a holder (the SERVICE channel
/// opening); `θ_p/λ` is when accumulated `κ_O` clears a holder's PREEMPTION margin — a strictly
/// later milestone. Printing them side by side is a context line, never a validation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntryStats {
    /// Newcomers in the cohort (joined past the cut, with at least the requested exposure).
    pub n_newcomers: usize,
    /// How many of them EVER earned `g` as a server.
    pub n_earned: usize,
    /// Median `first_earned_tick − joined_tick` over those that earned, in ticks. `NaN` if none.
    pub median_gap: f64,
    /// 90th percentile of the same gap (nearest-rank). `NaN` if none.
    pub p90_gap: f64,
    /// Share of the cohort that never earned. `NaN` on an empty cohort.
    pub frac_never_earned: f64,
    /// How many of the cohort ever got their OWN first symbol accepted somewhere — the P8
    /// bootstrap-LIVENESS headline. MEASURED on `p8_reciprocity`: **145 of 196 (74.0 %)**, i.e.
    /// ≈ 1 in 4 newcomers never got a single own symbol placed anywhere inside a 3-year horizon,
    /// even though 196/196 earned `g` as servers. And 40 of those 51 were still PRESENT at the
    /// horizon ([`EntryStats::n_never_placed_present`]), so they were not merely early leavers —
    /// they had the whole exposure and stayed unbacked. Earning credit and getting backed up are
    /// different events, and only the second one is why a newcomer joined.
    pub n_own_placed: usize,
    /// Median `first_own_accept − joined_tick`, in ticks. **CONDITIONED on the
    /// [`EntryStats::n_own_placed`] newcomers that ever placed** — it is the wait of the ones that
    /// made it, and says nothing about the ~26 % that never did. `NaN` if none placed.
    pub median_own_gap: f64,
    /// Of the cohort members that NEVER placed own data, how many were still PRESENT at the
    /// horizon — the ones that failed to get backed up while alive, as opposed to leaving early.
    /// Separates "never broke in" from "churned out before it could".
    pub n_never_placed_present: usize,
}

impl EntryStats {
    /// The empty read (no newcomer cleared the exposure filter).
    fn empty() -> Self {
        EntryStats {
            n_newcomers: 0,
            n_earned: 0,
            median_gap: f64::NAN,
            p90_gap: f64::NAN,
            frac_never_earned: f64::NAN,
            n_own_placed: 0,
            median_own_gap: f64::NAN,
            n_never_placed_present: 0,
        }
    }
}

impl RecipSeries {
    /// Mean `share_a_pos` over the FIRST quarter of the horizon (the "where it started" end of the
    /// P8-A trajectory test). `NaN` on an empty series.
    pub fn first_quarter_mean(&self) -> f64 {
        let q = self.share_a_pos.len() / 4;
        mean(&self.share_a_pos[..q.max(1).min(self.share_a_pos.len())])
    }

    /// Mean `share_a_pos` over the LAST quarter of the horizon (the "where it ended" end).
    /// `NaN` on an empty series.
    pub fn last_quarter_mean(&self) -> f64 {
        let len = self.share_a_pos.len();
        if len == 0 {
            return f64::NAN;
        }
        let start = len - (len / 4).max(1);
        mean(&self.share_a_pos[start..])
    }

    /// The rise over the horizon: last quarter minus first quarter, in percentage points.
    ///
    /// **Warm-up-contaminated by construction.** The first quarter contains the world's COLD START
    /// (at tick 1 almost nothing has been served yet, so the share is near 0), so a positive value
    /// here is mostly the world booting up and appears just as strongly with NO inflow at all —
    /// the matched closed control rises +16.54 pp over the same quarters against the inflow arm's
    /// +11.18 pp. Its sibling [`RecipSeries::inflow_phase_rise`] is LESS contaminated but not
    /// clean either; the only warm-up-free rise on this struct is [`RecipSeries::mature_rise`].
    pub fn rise(&self) -> f64 {
        self.last_quarter_mean() - self.first_quarter_mean()
    }

    /// The first tick index at which the standing newcomer count is non-zero — the onset of
    /// COUNTABLE newcomers. `None` for a closed world (no node ever sits past the cut).
    ///
    /// ⚠ **Not the onset of ARRIVALS.** `apply_inflow` starts landing pool nodes at tick 1; this
    /// index is where the first arrival PAST THE A15 CUT shows up, which on `p8_reciprocity` is
    /// tick ≈ 66-68 — by which point ≈ 32 of the 76 pool nodes are already in the world. Anything
    /// built on "before the onset ⇒ no inflow yet" is wrong; see [`INFLOW_BASELINE_WINDOW`].
    pub fn onset_tick(&self) -> Option<usize> {
        self.newcomers_present.iter().position(|&c| c > 0)
    }

    /// Mean `share_a_pos` over the half-open tick-index range `[a, b)`, clamped to the series.
    /// `NaN` on an empty range.
    pub fn mean_over(&self, a: usize, b: usize) -> f64 {
        let len = self.share_a_pos.len();
        let lo = a.min(len);
        let hi = b.min(len);
        if lo >= hi {
            return f64::NAN;
        }
        mean(&self.share_a_pos[lo..hi])
    }

    /// The last-quarter mean minus a baseline over the `window` ticks immediately BEFORE the first
    /// COUNTABLE newcomer ([`RecipSeries::onset_tick`]). `NaN` for a closed world (no onset ⇒ no
    /// window to anchor).
    ///
    /// **This is NOT a warm-up-free reading, and on its own it carries no attribution.** The
    /// baseline sits inside the bootstrap ramp, after ~⅖ of the pool has already arrived, on the
    /// TROUGH of a U-shaped curve — all three are spelled out under [`INFLOW_BASELINE_WINDOW`].
    /// Measured on `p8_reciprocity` it reads **+9.56 ± 2.64 pp**, but the matched CLOSED control
    /// scored over the SAME window (the inflow arm's onset, since a closed world has none) rises
    /// **+15.19 ± 2.67 pp**. So the +9.56 decomposes as *(shared post-trough recovery +15.19) −
    /// (dilution −5.64, paired t(4) = −3.29, p = 0.030)*: the control rises MORE, and the honest
    /// statement is that inflow SUBTRACTS from a recovery both arms share.
    ///
    /// Read it as a within-arm descriptive number, and never as "self-reinforcement beat dilution".
    /// The load-bearing reads are the board LEVEL (INV-P8-RECIPROCITY-SHARE), the PAIRED gap
    /// against the matched control, and [`RecipSeries::mature_rise`].
    pub fn inflow_phase_rise(&self, window: usize) -> f64 {
        let onset = match self.onset_tick() {
            Some(t) => t,
            None => return f64::NAN,
        };
        let baseline = self.mean_over(onset.saturating_sub(window), onset);
        self.last_quarter_mean() - baseline
    }

    /// The MATURE-phase change in percentage points: mean over [`MATURE_LATE_WINDOW`] minus mean
    /// over [`MATURE_EARLY_WINDOW`]. `NaN` if the series is too short to cover both.
    ///
    /// The one rise-shaped read on this struct that is free of BOTH the cold start and the
    /// U-shape's recovery leg: both windows sit deep inside the steady stream. It answers the
    /// question the horizon-spanning rises cannot — *once arrivals are routine, does the share
    /// still grow?* MEASURED on `p8_reciprocity` (5 seeds): the inflow arm reads
    /// **−2.02 ± 3.64 pp, signal/noise 0.56 ⇒ FLAT** (per seed `+0.35, −4.82, +2.04, −0.96,
    /// −6.70`), against the closed arm's +2.62 ± 3.09 pp, while the standing newcomer stock nearly
    /// TRIPLES between the windows (13.3 → 37.8). Flat-under-growing-dilution is the plateau claim
    /// in its testable form.
    pub fn mature_rise(&self) -> f64 {
        self.mean_over(MATURE_LATE_WINDOW.0, MATURE_LATE_WINDOW.1)
            - self.mean_over(MATURE_EARLY_WINDOW.0, MATURE_EARLY_WINDOW.1)
    }

    /// Mean standing newcomer count over the half-open tick-index range `[a, b)`, clamped to the
    /// series. `NaN` on an empty range. The dilution-load companion to [`RecipSeries::mean_over`]
    /// — a flat share only means something next to the newcomer stock it was flat against.
    pub fn newcomers_mean_over(&self, a: usize, b: usize) -> f64 {
        let len = self.newcomers_present.len();
        let lo = a.min(len);
        let hi = b.min(len);
        if lo >= hi {
            return f64::NAN;
        }
        let sum: usize = self.newcomers_present[lo..hi].iter().sum();
        sum as f64 / (hi - lo) as f64
    }

    /// `share_a_pos` at the horizon (the board row's scalar, for cross-checking against
    /// [`crate::sim_adv::MetricSet::share_a_pos`]). `NaN` on an empty series.
    pub fn final_share(&self) -> f64 {
        self.share_a_pos.last().copied().unwrap_or(f64::NAN)
    }

    /// Peak standing newcomer count over the run (a scenario-intensity diagnostic).
    pub fn peak_newcomers(&self) -> usize {
        self.newcomers_present.iter().copied().max().unwrap_or(0)
    }

    /// TOTAL nodes that joined past the cut over the whole run (the arrival stream's size — the
    /// "how much dilution was actually applied" number). Counts nodes, not tick-samples.
    pub fn newcomers_total(&self) -> usize {
        self.joined_tick
            .iter()
            .filter(|&&j| j > self.cutoff)
            .count()
    }

    /// The P8-B entry-time distribution over the newcomer cohort.
    ///
    /// `min_exposure` filters out RIGHT-CENSORED newcomers — a node that joined 2 ticks before the
    /// horizon has not "failed to break in", it simply has not had time. Only nodes with
    /// `horizon − joined_tick >= min_exposure` enter the cohort. Nodes that CHURNED OUT are kept
    /// (dropping them would bias the read optimistic, the `bootstrap.rs` caveat) —
    /// [`RecipSeries::present_at_end`] lets the report state how many those were.
    pub fn entry_stats(&self, horizon: u64, min_exposure: u64) -> EntryStats {
        let mut gaps: Vec<u64> = Vec::new();
        let mut own_gaps: Vec<u64> = Vec::new();
        let mut cohort = 0usize;
        let mut never_placed_present = 0usize;
        for i in 0..self.joined_tick.len() {
            let joined = self.joined_tick[i];
            if joined <= self.cutoff {
                continue; // bootstrap cohort, not a newcomer
            }
            if horizon.saturating_sub(joined) < min_exposure {
                continue; // right-censored: too little time to have earned anything
            }
            cohort += 1;
            if let Some(e) = self.first_earned_tick[i] {
                gaps.push(e.saturating_sub(joined));
            }
            match self.first_own_accept[i] {
                Some(o) => own_gaps.push(o.saturating_sub(joined)),
                None => {
                    if self.present_at_end[i] {
                        never_placed_present += 1;
                    }
                }
            }
        }
        if cohort == 0 {
            return EntryStats::empty();
        }
        gaps.sort_unstable();
        own_gaps.sort_unstable();
        EntryStats {
            n_newcomers: cohort,
            n_earned: gaps.len(),
            median_gap: quantile(&gaps, 0.5),
            p90_gap: quantile(&gaps, 0.9),
            frac_never_earned: (cohort - gaps.len()) as f64 / cohort as f64,
            n_own_placed: own_gaps.len(),
            median_own_gap: quantile(&own_gaps, 0.5),
            n_never_placed_present: never_placed_present,
        }
    }

    /// How many newcomers of the cohort (same cut + exposure filter as [`RecipSeries::entry_stats`])
    /// were still PRESENT at the horizon — the censoring caveat, quantified.
    pub fn newcomers_surviving(&self, horizon: u64, min_exposure: u64) -> usize {
        (0..self.joined_tick.len())
            .filter(|&i| {
                self.joined_tick[i] > self.cutoff
                    && horizon.saturating_sub(self.joined_tick[i]) >= min_exposure
                    && self.present_at_end[i]
            })
            .count()
    }
}

// ============================================================
// The PAIRED two-arm statistic (the dilution gap's correct analysis)
// ============================================================

/// A MATCHED-PAIR comparison of two arms measured on the SAME seeds.
///
/// P8's A/B flips exactly one switch (`InflowPolicy`) while seed, node count, archetype/tier draws
/// and every dial stay identical, so seed `k`'s two readings are a PAIR, not two independent
/// samples. Comparing the arms' independent means throws that away and reports the between-seed
/// spread (which is large: the same world realised under a different seed lands several pp apart)
/// as if it were the uncertainty of the switch. The paired analysis differences it out first.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PairedStats {
    /// Number of pairs.
    pub n: usize,
    /// Mean of the per-pair differences `a[k] − b[k]`.
    pub mean_diff: f64,
    /// Sample σ (n−1) of those differences — the noise the paired test actually faces.
    pub sigma_diff: f64,
    /// Standard error of the mean difference, `sigma_diff / √n`.
    pub se: f64,
    /// The paired t statistic, `mean_diff / se`.
    pub t: f64,
    /// Degrees of freedom, `n − 1`.
    pub df: usize,
    /// Two-sided p, or `NaN` when [`student_two_sided_p`] has no exact form for this `df`.
    pub p_two_sided: f64,
}

/// The paired statistic over two equal-length arms (`a[k]` and `b[k]` are the same seed).
/// All-`NaN` with a zero `n` when the lengths differ or there are fewer than 2 pairs — no
/// approximation, so a mis-paired call is visible instead of quietly plausible.
pub fn paired_stats(a: &[f64], b: &[f64]) -> PairedStats {
    let empty = PairedStats {
        n: 0,
        mean_diff: f64::NAN,
        sigma_diff: f64::NAN,
        se: f64::NAN,
        t: f64::NAN,
        df: 0,
        p_two_sided: f64::NAN,
    };
    if a.len() != b.len() || a.len() < 2 {
        return empty;
    }
    let d: Vec<f64> = a.iter().zip(b).map(|(x, y)| x - y).collect();
    if d.iter().any(|x| !x.is_finite()) {
        return empty;
    }
    let n = d.len();
    let mean = d.iter().sum::<f64>() / n as f64;
    let var = d.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0);
    let sigma = var.sqrt();
    let se = sigma / (n as f64).sqrt();
    let t = if se > 0.0 {
        mean / se
    } else if mean == 0.0 {
        0.0
    } else {
        f64::INFINITY.copysign(mean)
    };
    let df = n - 1;
    PairedStats {
        n,
        mean_diff: mean,
        sigma_diff: sigma,
        se,
        t,
        df,
        p_two_sided: student_two_sided_p(t, df),
    }
}

/// Two-sided Student-t p-value, **EXACT for `df == 4` only** — the 5-seed paired design every P8
/// arm uses. Any other `df` returns `NaN` rather than an approximation that would be wrong in the
/// small-sample regime this crate lives in; add the closed form for that ν when a caller needs it.
///
/// For ν = 4 the density is `(3/8)(1 + t²/4)^(−5/2)`, which integrates in closed form: with
/// `s = |t| / √(4 + t²)`, the two-sided tail is `1 − 1.5·s + 0.5·s³` (checks out at `t = 0 ⇒ 1`,
/// `t → ∞ ⇒ 0`, and `t = 2.776 ⇒ 0.05`, the textbook 5 % critical value for 4 df).
pub fn student_two_sided_p(t: f64, df: usize) -> f64 {
    if df != 4 || t.is_nan() {
        return f64::NAN;
    }
    if t.is_infinite() {
        return 0.0;
    }
    let s = t.abs() / (4.0 + t * t).sqrt();
    (1.0 - 1.5 * s + 0.5 * s * s * s).clamp(0.0, 1.0)
}

/// Nearest-rank quantile of an ASCENDING-sorted slice, as `f64`. `NaN` on empty.
fn quantile(sorted: &[u64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    let idx = rank.clamp(1, sorted.len()) - 1;
    sorted[idx] as f64
}

/// Plain mean, `NaN` on empty.
fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        f64::NAN
    } else {
        xs.iter().sum::<f64>() / xs.len() as f64
    }
}

/// Bit-exact equality of two reciprocity series (the determinism board row). The `f64` trajectory
/// is compared through `to_bits` so a deterministically-produced `NaN` compares equal to itself;
/// the integer / `Option` / `bool` vectors compare exactly.
pub fn bit_eq(a: &RecipSeries, b: &RecipSeries) -> bool {
    a.cutoff == b.cutoff
        && a.share_a_pos.len() == b.share_a_pos.len()
        && a.share_a_pos
            .iter()
            .zip(&b.share_a_pos)
            .all(|(x, y)| x.to_bits() == y.to_bits())
        && a.newcomers_present == b.newcomers_present
        && a.first_earned_tick == b.first_earned_tick
        && a.joined_tick == b.joined_tick
        && a.first_own_accept == b.first_own_accept
        && a.present_at_end == b.present_at_end
}
