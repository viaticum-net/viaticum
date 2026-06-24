//! SIM-R1 generator — the hidden ground-truth population for the per-symbol
//! block-survival calibration.
//!
//! This is the ONLY place ground-truth lives. A [`SimR1Holder`] carries:
//!   * the TRUE hardware-death survival to the horizon (Route A ground-truth),
//!   * the owner's TRUE pairwise standing `G(h←O)` and the TRUE reject/drop
//!     fraction the holder inflicts (the first-hand SIGNALS the observer shadows),
//!   * the TRUE retained DEPTH the holder keeps for the owner under contention
//!     (Route B ground-truth — the eviction edge the god-view evaluator applies),
//!   * a hidden `archetype` that the kernel must NEVER see (the anti-oracle axis).
//!
//! The observer shadows each holder into a `FirstHandObs` + the owner's ι-ladder.
//! It exposes ONLY observables (surface PoS record, standing `G(h←O)`, observed
//! drops, addresses, the owner's own declared ι). It MUST NOT — and structurally
//! cannot — copy the hidden `true_surface`/`true_keep_depth`/`archetype`.

use crate::generator::Rng;

/// Hidden give/take archetype of a holder (ground-truth; NEVER a kernel input).
/// In SIM-R1 the archetype only labels the population for the anti-oracle guard —
/// two holders identical in every OBSERVABLE but differing in `archetype` must
/// produce a bit-identical forecast (the kernel has no field for it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Archetype {
    /// A generous, deep partner (high true standing).
    Generous,
    /// A shallow / indifferent holder (low true standing).
    Indifferent,
    /// A flaky holder that drops a meaningful fraction of rounds.
    Flaky,
}

/// One holder in the hidden SIM-R1 population, holding a MIX of the owner's
/// symbols at different ι (the eviction ladder).
#[derive(Debug, Clone)]
pub struct SimR1Holder {
    /// Observable master-id byte (the observer shadows this into `master_id`).
    pub master: u8,
    /// Observable subnet (first-hand at connect; the §7 spread bucket).
    pub subnet: u32,
    /// The owner's TRUE pairwise standing `G(h←O)` with this holder. Bilaterally
    /// observable, so the observer DOES shadow it into `g_holder_from_owner` (it is
    /// first-hand, not an oracle) — the kernel reads it for the standing signal.
    pub true_g_holder_from_owner: f64,
    /// GROUND-TRUTH hardware-death survival to the horizon: `P(holder alive at τ)`.
    /// The evaluator draws a Bernoulli on this. Observable ONLY as the holder's PoS
    /// surface record (the observer turns it into a clean/dirty pass/fail history);
    /// the raw probability is NEVER shadowed.
    pub true_surface: f64,
    /// GROUND-TRUTH retained DEPTH ∈ [0,1]: the fraction of the owner's ι-ladder on
    /// this holder the holder ACTUALLY keeps under its own contention. The evaluator
    /// drops the owner's symbols whose ι-rank is BELOW `1 − true_keep_depth` (the
    /// two-level rule: within this owner, lowest-ι goes first). NEVER shadowed — the
    /// kernel must INFER its φ_O from first-hand standing/drops, not read this.
    pub true_keep_depth: f64,
    /// GROUND-TRUTH observed-drop fraction: the fraction of the owner's PoS rounds
    /// with this holder that FAIL/TIME-OUT — the first-hand evidence of pressure.
    /// The observer DOES shadow this (as the pass/fail/timeout counts); it is a
    /// first-hand signal, correlated with (but not equal to) `true_keep_depth`.
    pub observed_drop_frac: f64,
    /// The ι-ladder of the owner's symbols on this holder (declared importances).
    /// First-hand metadata the owner authored — the observer shadows it verbatim.
    pub ladder_iotas: Vec<f64>,
    /// Hidden archetype (ground-truth — NEVER reaches the kernel).
    pub archetype: Archetype,
}

/// The hidden SIM-R1 population: a set of holders, each carrying a MIX of the
/// owner's symbols at varied ι, with ground-truth surface + eviction depth.
#[derive(Debug, Clone)]
pub struct SimR1Pop {
    pub holders: Vec<SimR1Holder>,
}

/// Dials that shape the SIM-R1 population — swept to prove the structural claims
/// are robust to the chosen numbers (sim_plan.md §5.1).
#[derive(Debug, Clone, Copy)]
pub struct Dial {
    /// Number of holders the owner places symbols on.
    pub n_holders: usize,
    /// Number of the owner's symbols on EACH holder (the ι-ladder length).
    pub ladder_len: usize,
    /// Mean ground-truth hardware-death survival (Route A strength). Swept to move
    /// the surface route up/down independently of eviction.
    pub mean_surface: f64,
    /// Mean ground-truth retained depth (Route B strength / contention severity).
    /// Lower ⇒ holders keep less of the owner's ladder ⇒ more low-ι symbols die.
    pub mean_keep_depth: f64,
}

impl SimR1Pop {
    /// Build the hidden population for one dial. Each holder gets a distinct subnet
    /// (so the §7 spread places one symbol per holder — independence earned), a true
    /// surface and keep-depth spread around the dial means, a standing correlated
    /// with its keep-depth (deeper partners are kept more — the model's premise),
    /// and an ι-ladder with a MIX of importances.
    pub fn build(dial: Dial, seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let mut holders = Vec::with_capacity(dial.n_holders);

        let ladder_len = dial.ladder_len.max(1);
        for i in 0..dial.n_holders {
            // True surface spread ±0.1 around the dial mean, clamped to (0,1].
            let true_surface = (dial.mean_surface + rng.range(-0.1, 0.1)).clamp(0.05, 1.0);
            // True keep-depth spread ±0.25 around the dial mean, clamped to [0,1].
            let true_keep_depth = (dial.mean_keep_depth + rng.range(-0.25, 0.25)).clamp(0.0, 1.0);

            // Standing is correlated with keep-depth: a holder that keeps more of my
            // ladder is (by the model's premise) one I have served well — high
            // G(h←O). This is the structure the kernel exploits: more standing ⇒
            // deeper retention. We add noise so the mapping is not a giveaway.
            let true_g = (true_keep_depth * 8.0 + rng.range(-1.0, 1.0)).max(0.0);

            // Observed drops are correlated with shallow keep-depth (a squeezed
            // holder drops more of my rounds), again with noise so the first-hand
            // signal only PARTIALLY reveals the hidden depth.
            let observed_drop_frac =
                ((1.0 - true_keep_depth) * 0.4 + rng.range(-0.05, 0.05)).clamp(0.0, 1.0);

            // ι-ladder: a MIX of importances spread across [0.1, 0.9] so the rank is
            // well-defined and every rung is distinct.
            let ladder_iotas: Vec<f64> = (0..ladder_len)
                .map(|j| 0.1 + 0.8 * (j as f64) / (ladder_len.max(2) - 1) as f64)
                .collect();

            // Archetype label from the standing tier (god-view only; the anti-oracle
            // guard uses it OUTSIDE the kernel call).
            let archetype = if true_g >= 5.0 {
                Archetype::Generous
            } else if observed_drop_frac > 0.2 {
                Archetype::Flaky
            } else {
                Archetype::Indifferent
            };

            holders.push(SimR1Holder {
                master: i as u8,
                subnet: i as u32, // distinct subnet per holder ⇒ one symbol each
                true_g_holder_from_owner: true_g,
                true_surface,
                true_keep_depth,
                observed_drop_frac,
                ladder_iotas,
                archetype,
            });
        }

        SimR1Pop { holders }
    }
}
