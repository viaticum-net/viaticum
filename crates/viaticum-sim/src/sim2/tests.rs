use super::*;

#[test]
fn sim2_passes_with_damped_relay_and_shows_cycle_when_undamped() {
    let report = run(40, 42);

    // The damped run must order evictions strictly ascending in true G and have
    // a high rank correlation with the true net-debtor order.
    assert!(
        report.damped.strictly_ascending,
        "damped eviction order must be strictly ascending in true G"
    );
    assert!(
        report.damped.eviction_rank_spearman >= 0.9,
        "eviction-rank Spearman {} must be ≥ 0.9",
        report.damped.eviction_rank_spearman
    );
    assert!(
        report.damped.debtors_before_creditors,
        "every true net-debtor must be evicted before every true net-creditor"
    );

    // WARN-1: the accept (reaccept) leg must be GENUINELY LIVE in the damped run —
    // not structurally dead. accept_ok fires repeatedly and at least one full
    // drop→reaccept→drop cycle occurs.
    assert!(
        report.damped.accept_fire_count > 0,
        "damped run accept leg must fire (reaccept leg is live, not dead)"
    );
    assert!(
        report.damped.all_cycles > 0,
        "damped run must complete ≥1 full drop→reaccept→drop cycle (both legs live)"
    );

    // ...and EVEN SO the two-gap hysteresis yields 0 SHORT-PERIOD chatter cycles:
    // the would-be tick-frequency limit cycle is pushed up to the slow load period.
    assert_eq!(
        report.damped.chatter_cycles, 0,
        "damped run must have 0 short-period accept→evict→reaccept chatter cycles"
    );

    // The Δ=0 control MUST chatter at the tick frequency — proving the hysteresis
    // damper is load-bearing, not cosmetic.
    assert!(
        report.undamped_control.chatter_cycles > 0,
        "Δ=0 control must exhibit the tick-frequency accept↔evict limit cycle"
    );

    assert!(report.pass, "overall SIM-2 verdict must be PASS");
}

#[test]
fn sim2_delta_min_matches_analytic_formula() {
    let report = run(40, 42);
    // Δ_min = κ·max(a,b)·tick with the engine defaults (a=b=0.02, tick=1) and
    // κ=3 → 0.06. The damped gap must sit above it.
    let expected = 3.0 * 0.02 * 1.0;
    assert!(
        (report.delta_min_analytic - expected).abs() < 1e-9,
        "analytic Δ_min {} must equal κ·max(a,b)·tick = {}",
        report.delta_min_analytic,
        expected
    );
    assert!(
        report.delta_used > report.delta_min_analytic,
        "damped gap {} must exceed Δ_min {}",
        report.delta_used,
        report.delta_min_analytic
    );
}

#[test]
fn sim2_is_deterministic_across_runs() {
    let a = run(40, 7);
    let b = run(40, 7);
    assert_eq!(a.damped.chatter_cycles, b.damped.chatter_cycles);
    assert_eq!(a.damped.all_cycles, b.damped.all_cycles);
    assert_eq!(a.damped.accept_fire_count, b.damped.accept_fire_count);
    assert_eq!(
        a.undamped_control.chatter_cycles,
        b.undamped_control.chatter_cycles
    );
    assert_eq!(a.damped.strictly_ascending, b.damped.strictly_ascending);
}

#[test]
fn sim2_passes_across_several_seeds() {
    for seed in [1u64, 2, 3, 99, 12345] {
        let report = run(40, seed);
        assert!(
            report.pass,
            "SIM-2 must PASS for seed {seed}: damped_chatter={}, all_cycles={}, accept_fires={}, ascending={}, spearman={}, ctrl_chatter={}",
            report.damped.chatter_cycles,
            report.damped.all_cycles,
            report.damped.accept_fire_count,
            report.damped.strictly_ascending,
            report.damped.eviction_rank_spearman,
            report.undamped_control.chatter_cycles
        );
    }
}
