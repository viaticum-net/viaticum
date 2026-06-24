//! SIM-2 — eviction-by-reciprocity without oscillation (anti-oscillation +
//! eviction order). See `meaning_scenarios_sim.md` SIM-2.
//!
//! Hypothesis: under disk pressure the holder drops data with the smallest
//! `G(h←O)` first, and there is NO accept↔evict limit cycle on the regime
//! boundary when the two-gap hysteresis is at least `Δ_min` (formula_phase.md
//! §10). With `Δ = 0` (a relay with no gap) the limit cycle MUST appear, proving
//! the damper is load-bearing, not cosmetic.
//!
//! ## Regime exercised (WARN-1 retune — read before over-reading "0 chatter")
//!
//! Earlier this scenario kept `s_soft` so far above the reachable `φ` envelope
//! that the kernel's accept leg (`φ > s_soft`) NEVER fired in the damped run — so
//! the `Evicted → Held` reaccept leg was structurally DEAD and "0 chatter" was
//! driven partly by a dead branch, not purely by the damper. The claim this
//! scenario must demonstrate is stronger: a non-zero accept gap forbids
//! drop→immediately-reaccept→drop chatter of the SAME symbol EVEN WHEN the accept
//! condition is genuinely reachable.
//!
//! The retuned [`engine`] therefore drives `φ` with a slow, bounded external load
//! whose envelope spans the WHOLE band — it reaches above `s_soft` (accept fires
//! repeatedly, the reaccept leg is LIVE) and below `s_hard` (evict fires). With
//! both legs live the damped run necessarily contains the legitimate slow
//! load-period cycle (one drop + one reaccept per load period); that cycle is NOT
//! chatter. The chatter metric is period-aware: only drop→reaccept→drop cycles
//! whose period is at most the tick-frequency band count. The two-gap hysteresis
//! pushes the relay's would-be tick chatter up to (at least) the switch period
//! `T_switch ≈ (Δ_evict+Δ_accept)·(1/a+1/b)`, far above that band — so the damped
//! run shows `accept_fire_count > 0` and `all_cycles > 0` yet `chatter_cycles = 0`,
//! while the `Δ=0` control still chatters thousands of times at the tick frequency.
//!
//! Anti-oracle litmus: the eviction rule's only arguments are
//! `{φ_own, g_holder_from_owner}` — both first-hand. The hidden archetype is used
//! ONLY by the evaluator to confirm the dropped holdings were truly net-debtors.

#[cfg(test)]
mod tests;

use viaticum_core::four_r::{Hysteresis, min_hysteresis_gap};

use crate::engine::{self, EngineParams};
use crate::evaluator::{self, Sim2Result};
use crate::generator::Population;
use crate::observer;

/// Outcome of the full SIM-2 scenario (both the damped run and the Δ=0 control).
#[derive(Debug, Clone)]
pub struct Sim2Report {
    /// Analytic `Δ_min = κ·max(a,b)·tick` (formula_phase.md §10).
    pub delta_min_analytic: f64,
    /// The `Δ_evict` / `Δ_accept` gap actually used in the damped run.
    pub delta_used: f64,
    /// Result of the damped run (Δ > Δ_min, BOTH legs live): expect accept firing,
    /// ≥1 slow load cycle, 0 short-period chatter, ascending eviction order.
    pub damped: Sim2Result,
    /// Result of the Δ=0 control run: expect the tick-frequency limit cycle to APPEAR.
    pub undamped_control: Sim2Result,
    /// Overall PASS/FAIL.
    pub pass: bool,
}

/// Run SIM-2 end-to-end and return the report.
///
/// `n_owners` is the population size, `seed` the deterministic seed. The
/// hysteresis band for the damped run is built from `Δ_min` with a safety factor
/// so `Δ_used > Δ_min`; the control run zeroes both gaps.
pub fn run(n_owners: usize, seed: u64) -> Sim2Report {
    // --- Ground truth → first-hand shadows (through the observer boundary). ---
    // Two-level eviction views: one per owner, each with one symbol (SIM-2 is an
    // inter-owner-level test).
    let pop = Population::sim2(n_owners, seed);
    let holdings = observer::observe_eviction_views(&pop.owners);

    // --- Engine params; the φ-rates a, b and tick feed the analytic Δ_min. ---
    let mut params = EngineParams::default();
    let kappa = 3.0; // safety factor (several ticks of margin)
    let delta_min_analytic = min_hysteresis_gap(
        params.rate_accept_a,
        params.rate_evict_b,
        params.tick,
        kappa,
    );

    // --- Damped run: both gaps comfortably above Δ_min. ---
    let delta_used = 2.0 * delta_min_analytic.max(1e-6);
    let s_hard = 0.30;
    let damped_hyst = Hysteresis {
        s_hard,
        s_target: s_hard + delta_used,
        s_soft: s_hard + 2.0 * delta_used,
    };

    // Chatter-period threshold (principled, not magic): the damped relay's own
    // would-be switch period is `T_switch ≈ (Δ_evict+Δ_accept)·(1/a+1/b)`
    // (formula_phase.md §10). The hysteresis pushes the relay cycle to (at least)
    // this period; the tick-frequency chatter we count lives FAR below it (~1-2
    // ticks). We set the threshold to a small fraction of T_switch so a genuine
    // tick chatter (period ~1-2) is caught while neither the gap-induced switch
    // period nor the slow load period (≈ 2π/ω) is ever miscounted as chatter.
    let a = params.rate_accept_a.max(1e-9);
    let b = params.rate_evict_b.max(1e-9);
    let t_switch = (2.0 * delta_used) * (1.0 / a + 1.0 / b);
    // Quarter of the switch period, floored at a few ticks. With the defaults this
    // is ~6 ticks: well above tick chatter (~2) and well below T_switch (~24) and
    // the load period (~628).
    params.chatter_period_ticks = ((t_switch / 4.0).floor() as usize).max(3);

    let damped_trace = engine::run(&holdings, damped_hyst, params);
    let damped = evaluator::score(&pop, &damped_trace);

    // --- Control run: Δ = 0 (relay with no gap) → expect chatter. ---
    // Same load + same chatter threshold so the comparison is apples-to-apples:
    // with the band collapsed to a single threshold the relay dithers across it at
    // the tick frequency → many short-period (≤ threshold) chatter cycles.
    let undamped_hyst = Hysteresis {
        s_hard,
        s_target: s_hard, // Δ_evict = 0
        s_soft: s_hard,   // Δ_accept = 0
    };
    let undamped_trace = engine::run(&holdings, undamped_hyst, params);
    let undamped_control = evaluator::score(&pop, &undamped_trace);

    // --- PASS criteria (meaning_scenarios_sim.md SIM-2 metric). ---
    // (1) Eviction order strictly ascending in true G AND Spearman ≥ 0.9.
    // (2) Damped run: the ACCEPT leg is genuinely live (accept_fire_count > 0 and
    //     at least one full drop→reaccept→drop cycle exists, all_cycles > 0) — this
    //     is the WARN-1 fix: the reaccept leg is reachable, not dead. With both
    //     legs live the two-gap hysteresis STILL yields 0 short-period chatter.
    // (3) Control run: short-period chatter APPEARS (> 0) — proves the damper matters.
    let pass = damped.strictly_ascending
        && damped.debtors_before_creditors
        && damped.eviction_rank_spearman >= 0.9
        && damped.accept_fire_count > 0
        && damped.all_cycles > 0
        && damped.chatter_cycles == 0
        && undamped_control.chatter_cycles > 0;

    Sim2Report {
        delta_min_analytic,
        delta_used,
        damped,
        undamped_control,
        pass,
    }
}

/// Pretty-print the SIM-2 report (used by the binary).
pub fn print_report(report: &Sim2Report) {
    println!("=== SIM-2: eviction-by-reciprocity without oscillation ===");
    println!();
    println!(
        "Analytic Δ_min (κ·max(a,b)·tick) = {:.6}",
        report.delta_min_analytic
    );
    println!(
        "Δ_used (damped run gap)          = {:.6}",
        report.delta_used
    );
    println!();
    println!("-- Damped run (Δ > Δ_min; BOTH legs live) --");
    println!(
        "  eviction order strictly ascending in true G : {}",
        report.damped.strictly_ascending
    );
    println!(
        "  net-debtors evicted before net-creditors     : {}",
        report.damped.debtors_before_creditors
    );
    println!(
        "  eviction-rank Spearman vs true net-debtor    : {:.4} (need ≥ 0.90)",
        report.damped.eviction_rank_spearman
    );
    println!(
        "  accept leg fired (ticks accept_ok true)      : {} (need > 0: reaccept leg LIVE)",
        report.damped.accept_fire_count
    );
    println!(
        "  total drop→reaccept→drop cycles (any period) : {} (slow load cycle — not chatter)",
        report.damped.all_cycles
    );
    println!(
        "  short-period chatter cycles                  : {} (need 0)",
        report.damped.chatter_cycles
    );
    println!();
    println!("-- Control run (Δ = 0, relay with no gap) --");
    println!(
        "  accept leg fired (ticks accept_ok true)      : {}",
        report.undamped_control.accept_fire_count
    );
    println!(
        "  short-period chatter cycles                  : {} (need > 0: damper is load-bearing)",
        report.undamped_control.chatter_cycles
    );
    println!();
    println!("RESULT: {}", if report.pass { "PASS" } else { "FAIL" });
}
