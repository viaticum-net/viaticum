//! Generator — the hidden ground-truth layer.
//!
//! This is the ONLY place a hidden `GroundTruth` (archetype, true pairwise
//! service, hidden hazards) exists. None of these structs are ever passed into a
//! `viaticum_core::four_r` decision function — the [`crate::observer`] is the
//! single boundary that converts a hidden fact into a first-hand shadow.
//!
//! For SIM-2 (a loop-stability test) the ground-truth is deliberately small: a
//! population of owners each carrying a give/take archetype and a per-pair true
//! `g_holder_from_owner` toward the focus holder. No disk-death or departure is
//! modelled — SIM-2 only drives `φ` back and forth across `s_hard`.

#[cfg(test)]
mod tests;

/// A tiny deterministic LCG so the whole simulation is reproducible from a seed
/// (numerical recipes constants). Not cryptographic — it only spreads the
/// synthetic population deterministically.
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        // Avoid a zero state (would stick at 0 for some LCG variants).
        Rng {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state
    }

    /// Uniform f64 in [0, 1).
    pub fn unit(&mut self) -> f64 {
        // Use the top 53 bits for a uniform double.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform f64 in [lo, hi).
    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.unit()
    }
}

/// Hidden give/take archetype of an owner (ground-truth; NEVER an input to a
/// kernel decision). For SIM-2 this only sets the TRUE pairwise service an owner
/// has rendered to the focus holder, which the observer will shadow into
/// `g_holder_from_owner`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Archetype {
    /// Renders generous reciprocal service → high true `G(h←O)` (net-creditor).
    Reciprocator,
    /// Renders moderate service.
    Modest,
    /// Renders almost nothing → near-zero true `G(h←O)` (net-debtor / freeloader).
    Freeloader,
}

/// One owner in the hidden population, as seen by the simulator god-view.
#[derive(Debug, Clone)]
pub struct OwnerGt {
    /// Hidden archetype (ground-truth — never reaches the kernel).
    pub archetype: Archetype,
    /// TRUE pairwise service this owner has rendered to the focus holder, i.e.
    /// the hidden `G(h←O)` value. The observer shadows this into a FirstHandObs;
    /// the kernel only ever sees the shadow, never this field directly.
    pub true_g_holder_from_owner: f64,
    /// TRUE retention duration (`τ`) of this owner's symbols on the holder — used
    /// only to give the retention tie-breaker something to act on.
    pub true_tau: f64,
    /// The owner's DECLARED importance `ι` for the symbol it placed on the focus
    /// holder. Unlike `archetype`/`true_*` this is NOT ground-truth oracle — it is
    /// owner-declared metadata that travels WITH the symbol, so the holder
    /// observes it first-hand. The observer shadows it into [`SymbolDecl`]; the
    /// kernel uses it only as the INTRA-owner ordering key (never cross-owner).
    pub declared_iota: f64,
}

/// Whether an owner is a net-debtor by ground truth (used ONLY by the evaluator
/// to score the eviction rank — never by the kernel).
impl OwnerGt {
    pub fn is_net_debtor(&self, median_g: f64) -> bool {
        self.true_g_holder_from_owner < median_g
    }
}

/// The full hidden ground-truth population for SIM-2: one focus holder with a
/// finite disk and a set of owners placing data on it.
#[derive(Debug, Clone)]
pub struct Population {
    pub owners: Vec<OwnerGt>,
}

impl Population {
    /// Build a SIM-2 population: `n` owners spread across reciprocator / modest /
    /// freeloader archetypes, each with a distinct true `G(h←O)` so the eviction
    /// rank is well-defined.
    pub fn sim2(n: usize, seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let mut owners = Vec::with_capacity(n);
        for i in 0..n {
            // Deterministically tier the population: a third each.
            let archetype = match i % 3 {
                0 => Archetype::Reciprocator,
                1 => Archetype::Modest,
                _ => Archetype::Freeloader,
            };
            // True service per archetype, with a small deterministic spread so no
            // two owners tie (keeps the Spearman rank check unambiguous).
            let base = match archetype {
                Archetype::Reciprocator => 8.0,
                Archetype::Modest => 4.0,
                Archetype::Freeloader => 0.2,
            };
            let true_g = base + rng.range(0.0, 1.5);
            // Longer-held symbols for higher-service owners (incidental; only the
            // tie-breaker uses tau, and these G values do not tie).
            let true_tau = rng.range(1.0, 100.0);
            // Declared importance spread across owners. SIM-2 places ONE symbol per
            // owner, so ι is intra-owner-singleton (it never affects the inter-owner
            // G ranking here); it is carried for shape-completeness and so the
            // anti-oracle guard covers the ι path too.
            let declared_iota = rng.range(0.0, 1.0);
            owners.push(OwnerGt {
                archetype,
                true_g_holder_from_owner: true_g,
                true_tau,
                declared_iota,
            });
        }
        Population { owners }
    }

    /// Median true `G(h←O)` over the population — used by the evaluator to define
    /// net-debtor status. God-view only.
    pub fn median_true_g(&self) -> f64 {
        let mut v: Vec<f64> = self
            .owners
            .iter()
            .map(|o| o.true_g_holder_from_owner)
            .collect();
        v.sort_by(|a, b| a.total_cmp(b));
        if v.is_empty() { 0.0 } else { v[v.len() / 2] }
    }
}
