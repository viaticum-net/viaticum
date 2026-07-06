//! SIM-6 — spread by observable address vs by master-id (§7). See
//! `meaning_scenarios_sim.md` SIM-6 and `sim_plan.md` §5 / §5.1.
//!
//! ## Hypothesis (STRUCTURAL, not a measured multiplier)
//!
//! Spreading symbols by an OBSERVABLE address bucket (`addr_subnet` / ASN —
//! first-hand, §1-legal) catches the "hidden correlation × restore-moment" denial
//! (C1): an adversary farm of N master-ids confined to one subnet collapses to ONE
//! subnet bucket → gets at most ONE symbol, no matter how many keys it mints. The
//! load-bearing claim is a SIGN robust to the dialed-in numbers (`sim_plan.md §5.1`):
//!
//! > Under policy **B** (spread by `addr_subnet`) the farm needs strictly MORE
//! > independent ADDRESSES (distinct subnets) to achieve denial than under policy
//! > **A** (spread by `master_id` only) — for EVERY plausible dial setting, not one
//! > tuned point.
//!
//! Equivalently: under B a farm confined to one subnet gets ≤1 position (one subnet
//! bucket) → the block survives; under A the same farm mints N master-ids, each a
//! separate bucket, and seizes N positions → the block falls. Spreading by the
//! observable subnet beats spreading by the cheap-to-mint master-id (addr-spread >
//! master-spread). The observed cost-ratio (how many MORE subnets B forces) is
//! reported as a DIAL-DEPENDENT observation, NOT a pinned bound.
//!
//! ## ANTI-ORACLE (read before the scenario)
//!
//! The node sees, FIRST-HAND, each holder's `addr_subnet` (a connection fact,
//! §1-legal) and `master_id`. It does NOT see "these N holders are one
//! operator/farm" — that is ground-truth, and there is no field for it on
//! [`viaticum_core::four_r::FirstHandObs`] (the crate boundary keeps it out). The
//! spread in [`viaticum_core::four_r::place`] operates on the OBSERVABLE address
//! bucket; it never receives the hidden "is-one-farm" truth.
//!
//! Litmus: the arguments to `place`/the spread are ⊆ {surface `r_hat` (from
//! `estimate_surface(F^O)`), `addr_subnet`, `master_id`} plus the owner-private
//! `req`. The hidden farm-identity is used ONLY by the [`crate::sim6::evaluator`]
//! to SCORE whether the block survived the synchronous farm drop. ✓

#[cfg(test)]
mod tests;

pub mod evaluator;
pub mod generator;
pub mod observer;

use viaticum_core::four_r::{
    BlockReq, CapMode, PlacementPolicy, PlacementResult, SurfacePrior, place,
};

use self::evaluator::block_survives_farm_drop;
use self::generator::Sim6Pop;

/// One swept dial setting: erasure parameters and the farm's address spread.
#[derive(Debug, Clone, Copy)]
pub struct Dial {
    /// Erasure width `n` (symbols / holder slots).
    pub n_symbols: usize,
    /// Reconstruction threshold `k_eff`.
    pub k_eff: usize,
    /// Number of honest holders available (on varied subnets).
    pub honest_holders: usize,
    /// Number of master-ids the farm controls (cheap — minting keys is free).
    pub farm_masters: usize,
}

/// Result of probing ONE dial: the minimum number of distinct subnets the farm
/// needs to deny the block under each policy.
#[derive(Debug, Clone, Copy)]
pub struct DialResult {
    pub dial: Dial,
    /// Minimum distinct subnets the farm needs to DENY under master-id spread (A).
    pub min_subnets_deny_a: usize,
    /// Minimum distinct subnets the farm needs to DENY under addr-subnet spread (B).
    pub min_subnets_deny_b: usize,
    /// Whether B strictly raised the attacker's address floor for this dial
    /// (`min_subnets_deny_b > min_subnets_deny_a`) — the structural sign.
    pub b_raises_floor: bool,
    /// The observed cost-ratio for this dial (`b / max(a,1)`) — a DIAL-DEPENDENT
    /// observation, never a PASS criterion.
    pub cost_ratio: f64,
}

/// Full SIM-6 report over a battery of dials.
#[derive(Debug, Clone)]
pub struct Sim6Report {
    pub rows: Vec<DialResult>,
    /// The STRUCTURAL pass: B raised the attacker's address floor for EVERY dial.
    pub structural_sign_holds: bool,
    /// A single concrete witness (the default dial) that under B a one-subnet farm
    /// cannot take the block while under A it can — the survive/fall contrast.
    pub witness_b_survives_a_falls: bool,
    pub pass: bool,
    /// The cost-ratio range observed across dials (min, max) — reported, not gated.
    pub cost_ratio_range: (f64, f64),
}

/// For a fixed dial and policy, find the minimum number of distinct subnets the
/// farm must spread across to DENY the block.
///
/// We scan `farm_subnets = 1, 2, 3, …` upward. For each candidate spread we build
/// the population, place under the policy, and ask the god-view evaluator whether
/// the block survives the synchronous farm drop. The first spread at which the
/// block is DENIED is the attacker's address floor under that policy. We cap the
/// scan at `n_symbols` (beyond that the farm could fill every slot on distinct
/// subnets; a defender can never beat a farm that has as many independent
/// addresses as symbols — that is the honest limit of address-diversity).
fn min_subnets_to_deny(dial: Dial, policy: &PlacementPolicy, seed: u64) -> usize {
    let prior = SurfacePrior::default();
    // The victim's importance maps to a high reliability target so the placement
    // genuinely tries to fill the block (and would happily take farm holders that
    // pass PoS — the farm is INDISTINGUISHABLE by surface).
    let req = BlockReq {
        // Per-symbol volume 10 at observed scale → high in-sample r_hat.
        volume: 10.0 * dial.n_symbols as f64,
        n_symbols: dial.n_symbols,
        k_eff: dial.k_eff,
        tau: 30.0,
        r_target: 0.999,
        // SIM-6 isolates the §7 address-spread; r_min = 0 disables the Р-5 credit cap
        // so an unrelated mechanism cannot perturb the spread measurement.
        r_min: 0.0,
    };

    // WORST-CASE adversary. The farm is surface-INDISTINGUISHABLE from an honest
    // holder (it passes PoS; §1: "a patient spite-holder is the best holder by
    // evidence"), so in the worst case it gets SELECTED. We realise that worst case
    // by presenting the farm candidates FIRST — `place` sorts by r_hat with a
    // stable sort, so among the (equal) surfaces it keeps input order and fills
    // farm slots up to the per-bucket spread limit. This reordering is GOD-VIEW (the
    // scenario uses the hidden `is_farm` to construct the adversary's best
    // presentation); `place` itself still only sees observables
    // (subnet/master/surface) — it never learns which candidates are farm. The
    // address-spread, not the node's luck, is what defends.
    //
    // We scan `farm_subnets = 1, 2, …` and return the FIRST spread at which the
    // worst-case farm denies the block. Analytic expectation: A denies at 1 (the
    // master-id spread gives every farm key its own bucket); B forces the farm to
    // spread until it has enough subnet buckets to seize n−k_eff+1 positions. We
    // MEASURE this rather than assert the formula, so a regression in the kernel
    // spread is caught.
    let max_scan = (dial.n_symbols + 1).max(2);
    for farm_subnets in 1..=max_scan {
        let pop = Sim6Pop::build(dial, farm_subnets, seed);
        let candidates = observer::observe_all(&pop);
        // God-view worst-case ordering: farm first, honest after. (place never sees
        // is_farm; it only sees the reordered observable candidate slice.)
        let mut order: Vec<usize> = (0..pop.holders.len()).collect();
        order.sort_by_key(|&i| !pop.holders[i].is_farm); // false (farm) sorts first
        let reordered: Vec<_> = order.iter().map(|&i| candidates[i].clone()).collect();
        let placement = place(&req, &reordered, &prior, policy);
        let chosen_reordered: Vec<usize> = match placement {
            PlacementResult::Placed { holders, .. } => holders,
            PlacementResult::Insufficient { holders, .. } => holders,
        };
        // Map chosen indices (into `reordered`) back to population indices.
        let chosen: Vec<usize> = chosen_reordered.iter().map(|&i| order[i]).collect();
        if !block_survives_farm_drop(&pop, &chosen, dial.k_eff) {
            return farm_subnets;
        }
    }
    // Never denied within the scan budget → the floor is at least max_scan+1
    // (the defender held across the whole address-diversity range we probed).
    max_scan + 1
}

/// Run SIM-6 over a battery of dials and return the structural verdict.
pub fn run(seed: u64) -> Sim6Report {
    // A battery spanning a RANGE of dials (sim_plan.md §5.1: the sign must hold for
    // ALL plausible settings, not one tuned point). Vary n, k_eff, honest supply,
    // and farm key-count.
    let dials = [
        Dial {
            n_symbols: 6,
            k_eff: 3,
            honest_holders: 12,
            farm_masters: 50,
        },
        Dial {
            n_symbols: 8,
            k_eff: 4,
            honest_holders: 16,
            farm_masters: 80,
        },
        Dial {
            n_symbols: 10,
            k_eff: 6,
            honest_holders: 20,
            farm_masters: 100,
        },
        Dial {
            n_symbols: 12,
            k_eff: 5,
            honest_holders: 24,
            farm_masters: 200,
        },
        Dial {
            n_symbols: 5,
            k_eff: 2,
            honest_holders: 10,
            farm_masters: 30,
        },
        Dial {
            n_symbols: 16,
            k_eff: 8,
            honest_holders: 30,
            farm_masters: 300,
        },
    ];

    let policy_a = PlacementPolicy {
        cap_mode: CapMode::MasterIdOnly,
    };
    let policy_b = PlacementPolicy {
        cap_mode: CapMode::AddrCorrelate,
    };

    let mut rows = Vec::new();
    let mut structural_sign_holds = true;
    let mut ratio_min = f64::INFINITY;
    let mut ratio_max = f64::NEG_INFINITY;

    for (i, dial) in dials.iter().enumerate() {
        let s = seed.wrapping_add(i as u64 * 7919);
        let a = min_subnets_to_deny(*dial, &policy_a, s);
        let b = min_subnets_to_deny(*dial, &policy_b, s);
        let b_raises_floor = b > a;
        structural_sign_holds &= b_raises_floor;
        let cost_ratio = b as f64 / (a.max(1) as f64);
        ratio_min = ratio_min.min(cost_ratio);
        ratio_max = ratio_max.max(cost_ratio);
        rows.push(DialResult {
            dial: *dial,
            min_subnets_deny_a: a,
            min_subnets_deny_b: b,
            b_raises_floor,
            cost_ratio,
        });
    }

    // Concrete witness on the default dial: a ONE-SUBNET farm.
    let witness_dial = dials[0];
    let witness_b_survives_a_falls = one_subnet_farm_contrast(witness_dial, seed);

    let cost_ratio_range = if rows.is_empty() {
        (0.0, 0.0)
    } else {
        (ratio_min, ratio_max)
    };

    let pass = structural_sign_holds && witness_b_survives_a_falls;

    Sim6Report {
        rows,
        structural_sign_holds,
        witness_b_survives_a_falls,
        pass,
        cost_ratio_range,
    }
}

/// The concrete survive/fall witness: with the farm confined to ONE subnet, does
/// the block SURVIVE under B (subnet-spread holds — the farm gets one position) yet
/// FALL under A (master-spread bypassed by N master-ids)? This is the single
/// sharpest illustration of the sign.
fn one_subnet_farm_contrast(dial: Dial, seed: u64) -> bool {
    let prior = SurfacePrior::default();
    let req = BlockReq {
        volume: 10.0 * dial.n_symbols as f64,
        n_symbols: dial.n_symbols,
        k_eff: dial.k_eff,
        tau: 30.0,
        r_target: 0.999,
        // See min_subnets_to_deny: r_min = 0 disables the Р-5 credit cap (SIM-6 tests §7 spread only).
        r_min: 0.0,
    };
    let pop = Sim6Pop::build(dial, 1, seed); // farm on ONE subnet
    let candidates = observer::observe_all(&pop);

    // Worst-case (farm-first) ordering, as in `min_subnets_to_deny`.
    let mut order: Vec<usize> = (0..pop.holders.len()).collect();
    order.sort_by_key(|&i| !pop.holders[i].is_farm);
    let reordered: Vec<_> = order.iter().map(|&i| candidates[i].clone()).collect();

    let policy_a = PlacementPolicy {
        cap_mode: CapMode::MasterIdOnly,
    };
    let policy_b = PlacementPolicy {
        cap_mode: CapMode::AddrCorrelate,
    };

    let place_back = |policy: &PlacementPolicy| -> Vec<usize> {
        let chosen = match place(&req, &reordered, &prior, policy) {
            PlacementResult::Placed { holders, .. } => holders,
            PlacementResult::Insufficient { holders, .. } => holders,
        };
        chosen.iter().map(|&i| order[i]).collect()
    };
    let chosen_a = place_back(&policy_a);
    let chosen_b = place_back(&policy_b);

    let survives_b = block_survives_farm_drop(&pop, &chosen_b, dial.k_eff);
    let falls_a = !block_survives_farm_drop(&pop, &chosen_a, dial.k_eff);
    survives_b && falls_a
}

/// Pretty-print the SIM-6 report.
pub fn print_report(report: &Sim6Report) {
    println!("=== SIM-6: spread by addr-subnet vs by master-id (structural) ===");
    println!();
    println!("STRUCTURAL CLAIM (sign, robust to dials): under policy B (spread by addr_subnet)");
    println!("the farm needs strictly MORE distinct subnets to deny than under policy A");
    println!("(spread by master-id only) — for EVERY swept dial. Cost-ratio = DIAL-DEPENDENT obs.");
    println!();
    println!(
        "{:<28} {:>8} {:>8} {:>8} {:>9}",
        "dial (n,k_eff,honest,masters)", "minA", "minB", "B>A?", "ratio"
    );
    for r in &report.rows {
        println!(
            "n={:>2} k={:>2} h={:>3} m={:>4}     {:>8} {:>8} {:>8} {:>9.2}",
            r.dial.n_symbols,
            r.dial.k_eff,
            r.dial.honest_holders,
            r.dial.farm_masters,
            r.min_subnets_deny_a,
            r.min_subnets_deny_b,
            if r.b_raises_floor { "yes" } else { "NO" },
            r.cost_ratio,
        );
    }
    println!();
    println!(
        "  B raises the attacker address-floor for EVERY dial : {}",
        report.structural_sign_holds
    );
    println!(
        "  witness: one-subnet farm SURVIVES under B, FALLS under A : {}",
        report.witness_b_survives_a_falls
    );
    println!(
        "  observed cost-ratio range (dial-dependent, NOT a bound)  : [{:.2}, {:.2}]",
        report.cost_ratio_range.0, report.cost_ratio_range.1
    );
    println!();
    println!("RESULT: {}", if report.pass { "PASS" } else { "FAIL" });
    println!();
    println!("HONEST FRAME (sim_plan.md §5.1):");
    println!("  • The PASS criterion is the SIGN (B's address-floor > A's), not a number.");
    println!("  • The cost-ratio is reported as a dial-dependent observation only; it");
    println!("    moves with n, k_eff and the honest/farm supply and is NOT a guarantee.");
    println!("  • The spread keys on the OBSERVABLE subnet bucket; the hidden \"is-one-farm\"");
    println!("    truth is used ONLY by the evaluator to score survival — never by place().");
}
