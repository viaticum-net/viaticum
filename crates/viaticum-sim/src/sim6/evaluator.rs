//! SIM-6 evaluator — the god-view scorer (outside every node decision).
//!
//! The evaluator may read the hidden ground-truth (`is_farm`) because it never
//! feeds anything back into a placement decision — it only SCORES the outcome of
//! the synchronous farm drop. This is the §1 carve-out for evaluation only: the
//! cap in `place` saw nothing but the observable subnet; here we use the hidden
//! truth solely to decide whether the block survived.

use crate::sim6::generator::Sim6Pop;

/// Score whether the block survives the farm's SYNCHRONOUS drop at hour X.
///
/// Among the chosen placement holders (indices into `pop.holders`), the farm
/// members all fail TOGETHER (the hidden correlation realises). The block survives
/// iff at least `k_eff` of the chosen holders are HONEST (and thus keep their
/// symbol). This is the god-view truth, computed from `is_farm` — which `place`
/// never saw.
pub fn block_survives_farm_drop(pop: &Sim6Pop, chosen: &[usize], k_eff: usize) -> bool {
    let honest_surviving = chosen
        .iter()
        .filter(|&&idx| !pop.holders[idx].is_farm)
        .count();
    honest_surviving >= k_eff
}

/// Number of farm symbols the placement handed to the adversary cluster — a
/// diagnostic the report can show to explain WHY a block fell (the farm seized
/// `≥ n − k_eff + 1` positions) or held (the cap kept it below that).
pub fn farm_positions_taken(pop: &Sim6Pop, chosen: &[usize]) -> usize {
    chosen
        .iter()
        .filter(|&&idx| pop.holders[idx].is_farm)
        .count()
}
