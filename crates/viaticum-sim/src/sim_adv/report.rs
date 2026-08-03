//! Report rendering: human text (mean±σ over seeds) + machine CSV (one row per seed).
//!
//! Single-seed numbers never appear in the TEXT report (spec §5) — only mean±σ across
//! seeds. The CSV keeps per-seed rows (the legitimate machine dump, detail §3): that is
//! where the regression anchor reads seed 42's exact values from. The text is rendered
//! with fixed-precision formatters and fixed iteration order, so it is byte-identical on
//! repeat (the determinism gate).

use std::fmt::Write as _;

use crate::sim_adv::brier::{Calibration, DEFAULT_BRIER_BUCKETS};
use crate::sim_adv::hetero::{DemandClass, HeteroReport};
use crate::sim_adv::inflow::{POP_BAND, PopSeries};
use crate::sim_adv::metrics::{MetricSet, mean_sigma};
use crate::sim_adv::restore::{IOTA_BUCKETS, RestoreTruth};
use crate::sim_adv::runner::{RunResult, SweepRow};
use crate::sim_adv::scenario::Scenario;
use crate::sim_adv::tier::{TIER_ORDER, TierReport, tier_index};
use crate::sim_adv::uptime::tier_profile;
use crate::sim_adv::verdict::Verdict;
use crate::sim_dynamic::generator::Archetype;

/// Mean and σ of one scalar column across the seeds.
fn col(result: &RunResult, f: impl Fn(&MetricSet) -> f64) -> (f64, f64) {
    let vals: Vec<f64> = result.per_seed.iter().map(&f).collect();
    mean_sigma(&vals)
}

/// Render the full human report for a completed run + its verdicts.
pub fn format_report(scenario: &Scenario, result: &RunResult, verdicts: &[Verdict]) -> String {
    let mut o = String::new();
    let base = &scenario.world.base;

    let _ = writeln!(o, "=== sim_adv scenario '{}' ===", scenario.id);
    let _ = writeln!(o, "  {}", scenario.about);
    let _ = writeln!(
        o,
        "  world: n={}  block_volume={}  reciprocal={}  preempt_theta={}  recalibrated={}  U={}  cream={}",
        scenario.world.n_nodes,
        base.block_volume,
        base.reciprocal_placement,
        base.preempt_theta,
        base.recalibrated_retention,
        base.bandwidth_u,
        base.cream_enabled,
    );
    let _ = writeln!(
        o,
        "  horizon={} ticks   seeds={:?}   metrics={}",
        scenario.horizon,
        result.seeds,
        scenario
            .metrics
            .iter()
            .map(|m| m.label())
            .collect::<Vec<_>>()
            .join(","),
    );
    let _ = writeln!(o);

    // --- v2-acceptance metric block (mean±σ over seeds) ---
    let _ = writeln!(
        o,
        "-- metrics (mean ± σ over {} seeds) --",
        result.seeds.len()
    );
    let (m, s) = col(result, |x| x.share_a_pos);
    let _ = writeln!(o, "  share A>0 (%)        {:>10.4} ± {:.4}", m, s);
    let (m, s) = col(result, |x| x.alive_symbols as f64);
    let _ = writeln!(o, "  alive symbols        {:>10.2} ± {:.2}", m, s);
    let (m, s) = col(result, |x| x.present_nodes as f64);
    let _ = writeln!(o, "  present nodes        {:>10.2} ± {:.2}", m, s);
    let (m, s) = col(result, |x| x.evicts as f64);
    let _ = writeln!(o, "  evicts               {:>10.2} ± {:.2}", m, s);
    let (m, s) = col(result, |x| x.preempts as f64);
    let _ = writeln!(o, "  preempts             {:>10.2} ± {:.2}", m, s);
    let (m, s) = col(result, |x| x.cap_trims as f64);
    let _ = writeln!(o, "  cap_trims            {:>10.2} ± {:.2}", m, s);
    let (m, s) = col(result, |x| x.mean_depth);
    let _ = writeln!(o, "  mean loyalty D       {:>10.4} ± {:.4}", m, s);
    let (m, s) = col(result, |x| x.mean_sigma);
    let _ = writeln!(o, "  mean suspicion σ     {:>10.4} ± {:.4}", m, s);
    // SIM-UNIFICATION §4: decodability of the target-ever-met blocks (cream INCLUDED) — the
    // restorability cross-check to the non-cream floor-fill proxy, plus the size of the
    // silent undecodable tail.
    let (m, s) = col(result, |x| x.decodable_fraction);
    let _ = writeln!(o, "  decodable (≥k_eff)   {:>10.4} ± {:.4}", m, s);
    let (m, s) = col(result, |x| x.undecodable_blocks as f64);
    let _ = writeln!(o, "  undecodable tail     {:>10.2} ± {:.2}  blocks", m, s);
    let _ = writeln!(o);

    // --- per-archetype durability + extraction ROI ---
    let _ = writeln!(
        o,
        "-- per-archetype (mean ± σ over seeds): floor durability | extraction ROI --"
    );
    let _ = writeln!(
        o,
        "  {:<12} {:>18}   {:>18}",
        "archetype", "durability", "extraction ROI"
    );
    for (i, &a) in Archetype::ALL.iter().enumerate() {
        let (dm, ds) = col(result, |x| x.durability[i]);
        let (rm, rs) = col(result, |x| x.extraction_roi[i]);
        let _ = writeln!(
            o,
            "  {:<12} {:>9.3} ± {:>6.3}   {:>9.3} ± {:>6.3}",
            aname(a),
            dm,
            ds,
            rm,
            rs,
        );
    }
    let _ = writeln!(o);

    // --- Attack-ROI: predator vs matched twin (phase 1), when adversaries ran. A2's matched
    //     control is the POLITE dropper (not the honest node), so it gets a bespoke section. ---
    if scenario_is_a2(scenario) {
        if let Some(section) = format_a2(result) {
            o.push_str(&section);
        }
    } else {
        if let Some(section) = format_adv(result) {
            o.push_str(&section);
        }
        // phase-2a-2 predator appendices (specific diagnostic rows on top of the generic table).
        if scenario_has(scenario, crate::sim_adv::AdvId::A3Flapper)
            && let Some(section) = format_a3(result)
        {
            o.push_str(&section);
        }
        if scenario_has(scenario, crate::sim_adv::AdvId::A5DeepSilent)
            && let Some(section) = format_a5(result)
        {
            o.push_str(&section);
        }
        if scenario_has(scenario, crate::sim_adv::AdvId::A6Discriminator)
            && let Some(section) = format_a6(result)
        {
            o.push_str(&section);
        }
    }

    // --- restore-truth (metric №1), only when a Disaster fired ---
    if let Some(section) = format_restore(result) {
        o.push_str(&section);
    }

    // --- hetero-v2 (D1): per-class placement + the L-footprint curve ---
    if let Some(section) = format_hetero(result) {
        o.push_str(&section);
    }

    // --- provider-exit (A10): floor-fill proxy + the SIM-UNIFICATION decodability cross-check ---
    if let Some(section) = format_provider_exit(result) {
        o.push_str(&section);
    }

    // --- inflow (4r_inflow_spec.md §3): the present-count population curve + stationarity band ---
    if let Some(section) = format_population(result) {
        o.push_str(&section);
    }

    // --- phase-2a P7: the per-tier "who gets what in the network of givers" table ---
    if let Some(section) = format_tier(result) {
        o.push_str(&section);
    }

    // --- R̂-calibration (transche 0.3 judge), when predictions resolved ---
    if let Some(section) = format_brier(result) {
        o.push_str(&section);
    }

    // --- events dispatched (0.1 no-op record; empty for honest_v2) ---
    let fired_total: usize = result.fired.iter().map(|f| f.len()).sum();
    if fired_total > 0 {
        let _ = writeln!(o, "-- events dispatched (0.1 no-op record) --");
        // Deterministic: the first seed's record is representative (scripted, seeded).
        if let Some(first) = result.fired.first() {
            for fe in first {
                let _ = writeln!(o, "  seed[0] tick {:>4}: {}", fe.tick, fe.kind.label());
            }
        }
        let _ = writeln!(o);
    }

    // --- invariant board ---
    let _ = writeln!(o, "-- invariant board --");
    let _ = writeln!(
        o,
        "  {:<20} {:<12} {:>12} {:>10} {:>10} {:>8}  note",
        "id", "verdict", "effect", "σ", "threshold", "power"
    );
    for v in verdicts {
        let _ = writeln!(
            o,
            "  {:<20} {} {:>12.4} {:>10.4} {:>10.4} {:>8}  {}",
            v.id,
            v.kind.label(),
            v.effect,
            v.sigma,
            v.threshold,
            fmt_power(v.power),
            v.note,
        );
    }

    o
}

/// Mean±σ of one predator-side scalar (`side` picks predator or twin) across the seeds
/// (seeds with no adversaries → `NaN`, skipped by `mean_sigma`).
fn acol(
    result: &RunResult,
    twin: bool,
    f: impl Fn(&crate::sim_adv::AdvMetrics) -> f64,
) -> (f64, f64) {
    let vals: Vec<f64> = result
        .per_seed_adv
        .iter()
        .map(|p| {
            p.as_ref()
                .map(|pp| if twin { f(&pp.twin) } else { f(&pp.pred) })
                .unwrap_or(f64::NAN)
        })
        .collect();
    mean_sigma(&vals)
}

/// Render the Attack-ROI predator-vs-twin table (phase 1). `None` when no seed had
/// adversaries. The table gives, per side, the parked live volume, the protected-storage
/// and served integrals and the (diagnostic) ROI; the pred/twin gap is the load-bearing
/// comparison. Reports the Р-7 cap ratio + cap-trims + rejoins as engagement evidence.
fn format_adv(result: &RunResult) -> Option<String> {
    // Need at least one seed with an adversary pair to render.
    if !result.per_seed_adv.iter().any(|p| p.is_some()) {
        return None;
    }
    let mut o = String::new();
    let _ = writeln!(
        o,
        "-- Attack-ROI: predator vs matched honest twin (mean ± σ over seeds) --"
    );
    let _ = writeln!(
        o,
        "  {:<22} {:>20} {:>20}",
        "metric", "predator", "honest twin"
    );
    let row = |o: &mut String, name: &str, f: fn(&crate::sim_adv::AdvMetrics) -> f64| {
        let (pm, ps) = acol(result, false, f);
        let (tm, ts) = acol(result, true, f);
        let _ = writeln!(
            o,
            "  {:<22} {:>11.2} ± {:>6.2} {:>11.2} ± {:>6.2}",
            name, pm, ps, tm, ts
        );
    };
    row(&mut o, "parked live (gb)", |a| a.parked_live);
    row(&mut o, "protected gb·days", |a| a.consumed);
    row(&mut o, "served_out gb·days", |a| a.served_out);
    row(&mut o, "ROI consumed/served", |a| a.roi);
    row(&mut o, "cap_trims (world)", |a| a.cap_trims as f64);
    row(&mut o, "rejoins", |a| a.rejoins as f64);
    // The Р-7 cap ratio (predator side): ≤ 1 ⇒ the cap holds where it engages.
    let (cm, cs) = acol(result, false, |a| a.max_cap_ratio);
    let _ = writeln!(
        o,
        "  {:<22} {:>11.4} ± {:>6.4}   [≤1 ⇒ Р-7 cap holds where it binds]",
        "cap ratio (pred)", cm, cs
    );
    // The two seed-paired ROI comparatives (the verdict quantities): the structurally-robust
    // protected-storage ratio, and the raw extraction ratio (asserted while defined, WARN-2).
    let (rm, rs) = acol_ratio(result, |a| a.consumed);
    let _ = writeln!(
        o,
        "  {:<22} {:>11.4} ± {:>6.4}   [<1 ⇒ attack ≤ honest twin]",
        "protected pred/twin", rm, rs
    );
    let (rr, rrs) = acol_ratio(result, |a| a.roi);
    let _ = writeln!(
        o,
        "  {:<22} {:>11.4} ± {:>6.4}   [<1 ⇒ raw ROI ≤ honest twin]",
        "raw ROI pred/twin", rr, rrs
    );
    let _ = writeln!(o);
    Some(o)
}

/// Whether the scenario is the A2 DropNotice-refuser (its matched control is the POLITE dropper,
/// not the honest node — so the report labels + rows differ from the generic Attack-ROI table).
fn scenario_is_a2(scenario: &Scenario) -> bool {
    scenario
        .adversaries
        .iter()
        .any(|a| a.id == crate::sim_adv::AdvId::A2DropRefuser)
}

/// Render the A2 price-of-silence table: SILENT predator vs POLITE twin (equal-harm matched
/// control). The load-bearing rows are the reliability ledger `Σ_O g_oh` and the placement
/// inflow; parked / consumed / served / σ are diagnostics. `None` when no seed had adversaries.
fn format_a2(result: &RunResult) -> Option<String> {
    if !result.per_seed_adv.iter().any(|p| p.is_some()) {
        return None;
    }
    let mut o = String::new();
    let _ = writeln!(
        o,
        "-- A2 price of silence: SILENT predator vs POLITE twin (equal-rate drop; mean ± σ over seeds) --"
    );
    let _ = writeln!(
        o,
        "  {:<24} {:>18} {:>18}",
        "metric", "silent (pred)", "polite (twin)"
    );
    let row = |o: &mut String, name: &str, f: fn(&crate::sim_adv::AdvMetrics) -> f64| {
        let (pm, ps) = acol(result, false, f);
        let (tm, ts) = acol(result, true, f);
        let _ = writeln!(
            o,
            "  {:<24} {:>10.3} ± {:>5.3} {:>10.3} ± {:>5.3}",
            name, pm, ps, tm, ts
        );
    };
    row(&mut o, "g_oh ledger Σ (gb·d)", |a| a.retention_g);
    row(&mut o, "inflow Σ holdings.len", |a| a.inflow_total);
    row(&mut o, "σ owed Σ", |a| a.sigma_owed);
    row(&mut o, "parked live (gb)", |a| a.parked_live);
    row(&mut o, "protected gb·days", |a| a.consumed);
    row(&mut o, "served_out gb·days", |a| a.served_out);
    row(&mut o, "ROI consumed/served", |a| a.roi);
    row(&mut o, "g_oh ledger ∫ (gb·d·t)", |a| {
        a.retention_g_integral
    });
    row(&mut o, "parked ∫ (gb·t)", |a| a.parked_integral);
    row(&mut o, "own data evicted (#)", |a| a.data_evicted);
    // The asserted comparatives (silent/polite ratios) — the board verdict quantities. After the
    // seat-sync fix the two arms diverge chaotically, so the TIME-INTEGRAL ratios (not the horizon
    // snapshots) are the stable signals the board reads.
    let (gm, gs) = acol_ratio(result, |a| a.retention_g_integral);
    let _ = writeln!(
        o,
        "  {:<24} {:>10.4} ± {:>5.4}   [<0.85 ⇒ silence punished in the ledger (INV-SILENT-PUNISHED)]",
        "g_oh ∫ silent/polite", gm, gs
    );
    let (pm, ps) = acol_ratio(result, |a| a.parked_integral);
    let _ = writeln!(
        o,
        "  {:<24} {:>10.4} ± {:>5.4}   [<0.85 ⇒ silent's park squeezed (INV-RETENTION; noisy downstream)]",
        "parked ∫ silent/polite", pm, ps
    );
    let (em, es) = acol_ratio(result, |a| a.data_evicted);
    let _ = writeln!(
        o,
        "  {:<24} {:>10.4} ± {:>5.4}   [>1 ⇒ silent's data dropped more (DIAGNOSTIC, very noisy)]",
        "data-evicted silent/polite", em, es
    );
    let (im, is) = acol_ratio(result, |a| a.inflow_total);
    let _ = writeln!(
        o,
        "  {:<24} {:>10.4} ± {:>5.4}   [placement is surface-blind ⇒ EXPECTED noisy ~1, INCONCLUSIVE]",
        "inflow silent/polite", im, is
    );
    let _ = writeln!(
        o,
        "  NOTE: the seat-sync burn fix (2026-07-19) wired the drop burn to the ENFORCEMENT key"
    );
    let _ = writeln!(
        o,
        "        g_ho (V_ret / eviction / preemption), so silence is now punished in RETENTION, not"
    );
    let _ = writeln!(
        o,
        "        only the (inert) forecast ledger. INFLOW stays INCONCLUSIVE — placement reads the"
    );
    let _ = writeln!(
        o,
        "        surface PoS-window ONLY (that consumer is honest phase-4 work, out of A2 scope)."
    );
    let _ = writeln!(o);
    Some(o)
}

/// Does the scenario carry an adversary of `id`?
fn scenario_has(scenario: &Scenario, id: crate::sim_adv::AdvId) -> bool {
    scenario.adversaries.iter().any(|a| a.id == id)
}

/// Mean±σ of the seed-paired DIFFERENCE `f(pred) − f(twin)` (either side NaN ⇒ NaN, skipped).
fn acol_diff(result: &RunResult, f: impl Fn(&crate::sim_adv::AdvMetrics) -> f64) -> (f64, f64) {
    let vals: Vec<f64> = result
        .per_seed_adv
        .iter()
        .map(|p| {
            p.as_ref()
                .map(|pp| f(&pp.pred) - f(&pp.twin))
                .unwrap_or(f64::NAN)
        })
        .collect();
    mean_sigma(&vals)
}

/// A3 (флаппер) DIAGNOSTIC section (phase-2a-2 §A3): the σ-profile / PoS-pass / real-storage gap
/// between the bursty flapper and its mean-matched iid honest twin. NO board row — this is the
/// finding fed to the phase-4 σ-cadence design. `None` when no seed had adversaries.
fn format_a3(result: &RunResult) -> Option<String> {
    if !result.per_seed_adv.iter().any(|p| p.is_some()) {
        return None;
    }
    let mut o = String::new();
    let _ = writeln!(
        o,
        "-- A3 flapper DIAGNOSTIC: bursty flapper vs mean-matched iid honest twin (mean ± σ over seeds) --"
    );
    let _ = writeln!(
        o,
        "  {:<26} {:>18} {:>18}",
        "metric", "flapper (pred)", "iid twin"
    );
    let row = |o: &mut String, name: &str, f: fn(&crate::sim_adv::AdvMetrics) -> f64| {
        let (pm, ps) = acol(result, false, f);
        let (tm, ts) = acol(result, true, f);
        let _ = writeln!(
            o,
            "  {:<26} {:>11.4} ± {:>4.4} {:>11.4} ± {:>4.4}",
            name, pm, ps, tm, ts
        );
    };
    row(&mut o, "online-frac (storage)", |a| a.online_frac);
    row(&mut o, "surfaced-frac (PoS pass)", |a| a.surfaced_frac);
    row(&mut o, "σ owed Σ", |a| a.sigma_owed);
    row(&mut o, "g_oh ledger Σ (gb·d)", |a| a.retention_g);
    row(&mut o, "served_out gb·days", |a| a.served_out);
    let _ = writeln!(
        o,
        "  FINDING (phase-4 σ-cadence): at EQUAL online-frac (mean-matched real storage), the window"
    );
    let _ = writeln!(
        o,
        "  forgiveness p_w = 1−(1−u)^7 SPREADS the iid twin's misses (surfaced ≈ 1, σ ≈ 0) but the"
    );
    let _ = writeln!(
        o,
        "  CLUSTERED flapper misses whole off-runs (lower surfaced, higher σ). σ HAS signal against"
    );
    let _ = writeln!(
        o,
        "  bursting but is INERT — the phase-4 PoS cadence r_0(1+σ) must consume it; the residual gap"
    );
    let _ = writeln!(
        o,
        "  is the SPREAD-cheap node (iid-low), which the window forgives ≈ fully and σ cannot see."
    );
    let _ = writeln!(o);
    Some(o)
}

/// A5 (молчащий глубокий) section (phase-2a-2 §A5): the deep node's parked-data SURVIVAL across the
/// pause WITH the depth floor (pred, `w_d=0.5`) vs WITHOUT (twin, `w_d=0`) — the Р-1/W10 test. `None`
/// when no seed had adversaries.
fn format_a5(result: &RunResult) -> Option<String> {
    if !result.per_seed_adv.iter().any(|p| p.is_some()) {
        return None;
    }
    let mut o = String::new();
    let _ = writeln!(
        o,
        "-- A5 deep-silent: parked-data survival across the pause, DEPTH FLOOR on vs off (mean ± σ) --"
    );
    let _ = writeln!(
        o,
        "  {:<26} {:>18} {:>18}",
        "metric", "w_d=0.5 (pred)", "w_d=0 (twin)"
    );
    let row = |o: &mut String, name: &str, f: fn(&crate::sim_adv::AdvMetrics) -> f64| {
        let (pm, ps) = acol(result, false, f);
        let (tm, ts) = acol(result, true, f);
        let _ = writeln!(
            o,
            "  {:<26} {:>11.4} ± {:>4.4} {:>11.4} ± {:>4.4}",
            name, pm, ps, tm, ts
        );
    };
    row(&mut o, "park survival (end/peak)", |a| a.park_survival);
    row(&mut o, "protected gb·days", |a| a.consumed);
    row(&mut o, "parked live (gb)", |a| a.parked_live);
    let (dm, ds) = acol_diff(result, |a| a.park_survival);
    let _ = writeln!(
        o,
        "  {:<26} {:>11.4} ± {:>4.4}   [INV-A5-DEEP-FLOOR: >0.10 ⇒ the floor keeps the deep tail alive]",
        "survival diff (pred−twin)", dm, ds
    );
    let _ = writeln!(
        o,
        "  NOTE: the mean lift is robustly POSITIVE (the sign; the M-ladder decays with the pause"
    );
    let _ = writeln!(
        o,
        "        toward τ_slow≈6mo), but the per-seed lift is SEED-realization-dependent (σ ≈ the"
    );
    let _ = writeln!(
        o,
        "        effect) — the board is INCONCLUSIVE (power<2, WARN-7), NOT a tuned PASS."
    );
    let _ = writeln!(o);
    Some(o)
}

/// A6 (дискриминатор) section (phase-2a-2 §A6): the cost-or-impunity of shedding small owners — the
/// discriminator's protected-storage vs its honest twin's, plus the small-owner retention it keeps
/// (≈ 0) vs the twin's. `None` when no seed had adversaries.
fn format_a6(result: &RunResult) -> Option<String> {
    if !result.per_seed_adv.iter().any(|p| p.is_some()) {
        return None;
    }
    let mut o = String::new();
    let _ = writeln!(
        o,
        "-- A6 discriminator: shed-the-small holder vs honest twin (mean ± σ over seeds) --"
    );
    let _ = writeln!(
        o,
        "  {:<26} {:>18} {:>18}",
        "metric", "discr (pred)", "honest twin"
    );
    let row = |o: &mut String, name: &str, f: fn(&crate::sim_adv::AdvMetrics) -> f64| {
        let (pm, ps) = acol(result, false, f);
        let (tm, ts) = acol(result, true, f);
        let _ = writeln!(
            o,
            "  {:<26} {:>11.4} ± {:>4.4} {:>11.4} ± {:>4.4}",
            name, pm, ps, tm, ts
        );
    };
    row(&mut o, "protected gb·days", |a| a.consumed);
    row(&mut o, "served_out gb·days", |a| a.served_out);
    row(&mut o, "small-owner held (gb)", |a| a.small_retention_gb);
    let (cm, cs) = acol_ratio(result, |a| a.consumed);
    let _ = writeln!(
        o,
        "  {:<26} {:>11.4} ± {:>4.4}   [INV-A6-DISCR-ROI: <1 ⇒ discrimination does NOT pay]",
        "protected discr/twin", cm, cs
    );
    let _ = writeln!(
        o,
        "  FINDING (v_free=0): small-owner retention at the discriminator vs the honest holder is the"
    );
    let _ = writeln!(
        o,
        "  'small held' row; the discr/twin protected ratio is the price (or impunity) of the shed."
    );
    let _ = writeln!(o);
    Some(o)
}

/// Mean±σ of the seed-paired ratio `f(pred)/f(twin)` (twin `0` ⇒ NaN, skipped).
fn acol_ratio(result: &RunResult, f: impl Fn(&crate::sim_adv::AdvMetrics) -> f64) -> (f64, f64) {
    let vals: Vec<f64> = result
        .per_seed_adv
        .iter()
        .map(|p| {
            p.as_ref()
                .map(|pp| {
                    let t = f(&pp.twin);
                    if t > 0.0 { f(&pp.pred) / t } else { f64::NAN }
                })
                .unwrap_or(f64::NAN)
        })
        .collect();
    mean_sigma(&vals)
}

/// Mean±σ of one restore-truth scalar across the seeds (seeds with no Disaster → `NaN`,
/// skipped by `mean_sigma`).
fn rcol(result: &RunResult, f: impl Fn(&RestoreTruth) -> f64) -> (f64, f64) {
    let vals: Vec<f64> = result
        .per_seed_restore
        .iter()
        .map(|r| r.as_ref().map(&f).unwrap_or(f64::NAN))
        .collect();
    mean_sigma(&vals)
}

/// Render the restore-truth section (metric №1). `None` when no seed had a Disaster.
fn format_restore(result: &RunResult) -> Option<String> {
    let first = result.per_seed_restore.iter().flatten().next()?;
    let mut o = String::new();
    let _ = writeln!(
        o,
        "-- restore-truth (metric №1; god-view over the real engine) --"
    );
    let _ = writeln!(
        o,
        "  disaster @ tick {}   W = {} days ({} ticks)   victims = {}   info_model = {}",
        first.disaster_tick,
        first.window_days,
        first.window_ticks,
        first.n_victims,
        first.info_model,
    );
    let s_budget = first.restore_bw_gb_day * first.window_days;
    if first.restore_bw_gb_day > 0.0 {
        let _ = writeln!(
            o,
            "  Model S download budget: {} GB/day × {} days = {} GB",
            first.restore_bw_gb_day, first.window_days, s_budget,
        );
    } else {
        let _ = writeln!(o, "  Model S download budget: unlimited (bw ≤ 0 ⇒ S ≡ U)");
    }
    let _ = writeln!(
        o,
        "  (over {} surviving-victim blocks / seed)",
        first.n_blocks()
    );
    let (m, s) = rcol(result, |r| r.restore_truth_u());
    let _ = writeln!(
        o,
        "  restore-truth U (any)  {:>8.4} ± {:.4}  [ASPIRATIONAL, D7]",
        m, s
    );
    let (m, s) = rcol(result, |r| r.restore_truth_s());
    let _ = writeln!(o, "  restore-truth S (bw)   {:>8.4} ± {:.4}", m, s);
    let (m, s) = rcol(result, |r| r.restore_truth_o());
    let _ = writeln!(
        o,
        "  restore-truth O (1shot){:>8.4} ± {:.4}  [O ≤ U; today's no-retry floor]",
        m, s
    );
    let (m, s) = rcol(result, |r| r.durability_floor());
    let _ = writeln!(o, "  durability-floor       {:>8.4} ± {:.4}", m, s);
    // Per-ι-bucket restore-truth U (detail §3.1 cut).
    let _ = writeln!(o, "  by ι bucket (restore-truth U):");
    for (b, &(lo, hi)) in IOTA_BUCKETS.iter().enumerate() {
        let (m, s) = rcol(result, |r| r.restore_u_in_bucket(b));
        if m.is_nan() {
            continue;
        }
        let _ = writeln!(o, "    [{lo:.1},{hi:.1})  {m:>8.4} ± {s:.4}");
    }
    // Per-demand-class restore-truth (hetero DR): only when >1 class was struck (dr_hetero).
    let classes_present = first
        .blocks
        .iter()
        .map(|b| b.class)
        .collect::<std::collections::BTreeSet<_>>();
    if classes_present.len() > 1 {
        let _ = writeln!(o, "  by demand class (restore-truth U / S / O):");
        for c in DemandClass::ALL {
            let (u, _) = rcol(result, |r| r.restore_u_in_class(c));
            if u.is_nan() {
                continue;
            }
            let (s, _) = rcol(result, |r| r.restore_s_in_class(c));
            let (o_, _) = rcol(result, |r| r.restore_o_in_class(c));
            let (nb, _) = rcol(result, |r| r.n_blocks_in_class(c) as f64);
            let _ = writeln!(
                o,
                "    {}: U={u:>7.4}  S={s:>7.4}  O={o_:>7.4}  (mean blocks/seed = {nb:.1})",
                c.label(),
            );
        }
        let _ = writeln!(
            o,
            "    NOTE: S/M restore-truth is NOISE-DOMINATED (< 5 blocks/seed — a single victim's"
        );
        let _ = writeln!(
            o,
            "          1-3 blocks); the DR-primary SIGNAL is the L victim (big footprint = more blocks)."
        );
    }
    let _ = writeln!(
        o,
        "  NOTE-8: dr_baseline is a SANITY FLOOR (~high under the current uptime), not a"
    );
    let _ = writeln!(
        o,
        "          regression detector — discrimination arrives with phase-2 uptime profiles."
    );
    let _ = writeln!(o);
    Some(o)
}

/// The restore-truth machine CSV (detail §3.1 columns + both models + `info_model`, spec
/// §10 п.18 / NOTE-5). One row per seed that had a Disaster; empty (header only) otherwise.
pub fn restore_csv(result: &RunResult) -> String {
    let mut o = String::from(
        "scenario,seed,tick_disaster,window_days,window_ticks,n_victims,n_blocks,restorable_u,restorable_s,restorable_o,restorable_floor,restore_truth_u,restore_truth_s,restore_truth_o,durability_floor,restore_bw_gb_day,info_model\n",
    );
    for (i, r) in result.per_seed_restore.iter().enumerate() {
        let Some(rt) = r else { continue };
        let n_u = rt.blocks.iter().filter(|b| b.restorable_u).count();
        let n_s = rt.blocks.iter().filter(|b| b.restorable_s).count();
        let n_o = rt.blocks.iter().filter(|b| b.restorable_o).count();
        let n_f = rt.blocks.iter().filter(|b| b.restorable_floor).count();
        let _ = writeln!(
            o,
            "{},{},{},{},{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{},{}",
            result.scenario,
            result.seeds[i],
            rt.disaster_tick,
            rt.window_days,
            rt.window_ticks,
            rt.n_victims,
            rt.n_blocks(),
            n_u,
            n_s,
            n_o,
            n_f,
            rt.restore_truth_u(),
            rt.restore_truth_s(),
            rt.restore_truth_o(),
            rt.durability_floor(),
            rt.restore_bw_gb_day,
            rt.info_model,
        );
    }
    o
}

/// Format a `mean ± σ` cell at `prec` decimals; σ prints "—" for < 2 finite seeds (NaN σ) so a
/// one-owner-per-class cut reads "63.5 ± —" rather than "63.5 ± NaN" (NOTE-2 cosmetic).
fn ms_cell(mean: f64, sigma: f64, prec: usize) -> String {
    let s = if sigma.is_finite() {
        format!("{sigma:.prec$}")
    } else {
        "—".to_string()
    };
    format!("{mean:.prec$}±{s}")
}

/// Mean±σ of one hetero-report scalar across the seeds (seeds with no hetero report → `NaN`,
/// skipped by `mean_sigma`).
fn hcol(result: &RunResult, f: impl Fn(&HeteroReport) -> f64) -> (f64, f64) {
    let vals: Vec<f64> = result
        .per_seed_hetero
        .iter()
        .map(|h| h.as_ref().map(&f).unwrap_or(f64::NAN))
        .collect();
    mean_sigma(&vals)
}

/// Render the hetero-v2 (D1) section: the per-class placement table + the L-footprint
/// "parked-vs-tick" curve (the load-bearing "does the big footprint reach floor" evidence).
/// `None` when no seed carried a hetero report (a uniform-demand scenario).
fn format_hetero(result: &RunResult) -> Option<String> {
    let first = result.per_seed_hetero.iter().flatten().next()?;
    let mut o = String::new();
    let _ = writeln!(
        o,
        "-- hetero-v2 (D1): per-owner demand classes (number of equal blocks per owner) --"
    );
    let _ = writeln!(
        o,
        "  footprint n_blocks: S={} M={} L={}   assigned owners: S={} M={} L={}",
        first.n_blocks[0],
        first.n_blocks[1],
        first.n_blocks[2],
        first.assigned[0],
        first.assigned[1],
        first.assigned[2],
    );
    // WARN-1: floor_complete ≡ placed_frac (block-weighted = owner-weighted at constant n_blocks),
    // so only floor_complete is shown. NOTE-1: mean_holders (current alive floor holders/block, the
    // steady-state "placed-then-shed" diagnostic) is a column. mean±σ; σ = "—" for < 2 finite seeds.
    let _ = writeln!(
        o,
        "  {:<6} {:>7} {:>15} {:>15} {:>15} {:>15} {:>10}",
        "class", "owners", "floor_complete", "mean_holders", "share A>0", "tick_full", "never_full",
    );
    for (ci, c) in DemandClass::ALL.iter().enumerate() {
        let (own, _) = hcol(result, |h| h.class[ci].n_owners_present as f64);
        let (fc, fcs) = hcol(result, |h| h.class[ci].floor_completeness);
        let (mh, mhs) = hcol(result, |h| h.class[ci].mean_floor_holders);
        let (sa, sas) = hcol(result, |h| h.class[ci].share_a_pos);
        let (tf, tfs) = hcol(result, |h| h.class[ci].mean_tick_full);
        let (nf, _) = hcol(result, |h| h.class[ci].n_never_full as f64);
        let _ = writeln!(
            o,
            "  {:<6} {:>7.1} {:>15} {:>15} {:>15} {:>15} {:>10.2}",
            c.label(),
            own,
            ms_cell(fc, fcs, 3),
            ms_cell(mh, mhs, 2),
            ms_cell(sa, sas, 2),
            ms_cell(tf, tfs, 1),
            nf,
        );
    }
    // The L-footprint placement curve: per-class mean placed-fraction over seeds, per sample
    // tick, plus the L full-footprint owner count — the "parked vs tick per class" evidence.
    let _ = writeln!(
        o,
        "  placement curve (placed_frac mean over seeds, per class | L owners fully placed):"
    );
    let _ = writeln!(
        o,
        "    {:>6}  {:>7} {:>7} {:>7}   {:>10}",
        "tick", "S", "M", "L", "L n_full"
    );
    let curves: Vec<&Vec<crate::sim_adv::HeteroSample>> = result
        .per_seed_hetero
        .iter()
        .flatten()
        .map(|h| &h.curve)
        .collect();
    for k in 0..first.curve.len() {
        let tick = first.curve[k].tick;
        let mut sum = [0.0f64; 3];
        let mut cnt = [0usize; 3];
        let mut lfull_sum = 0.0f64;
        let mut lfull_cnt = 0usize;
        for cv in &curves {
            let Some(s) = cv.get(k) else { continue };
            for c in 0..3 {
                if s.placed_frac[c].is_finite() {
                    sum[c] += s.placed_frac[c];
                    cnt[c] += 1;
                }
            }
            lfull_sum += s.n_full[2] as f64;
            lfull_cnt += 1;
        }
        let mean_c = |c: usize| {
            if cnt[c] > 0 {
                sum[c] / cnt[c] as f64
            } else {
                f64::NAN
            }
        };
        let lfull = if lfull_cnt > 0 {
            lfull_sum / lfull_cnt as f64
        } else {
            0.0
        };
        let _ = writeln!(
            o,
            "    {:>6}  {:>7.3} {:>7.3} {:>7.3}   {:>10.1}",
            tick,
            mean_c(0),
            mean_c(1),
            mean_c(2),
            lfull,
        );
    }
    let _ = writeln!(o);
    Some(o)
}

/// Render the PROVIDER-EXIT (A10) section: the post-exit non-cream floor-fill PROXY next to the
/// SIM-UNIFICATION §4 restorability CROSS-CHECK (decodable fraction + undecodable tail, cream
/// included) — the two answer different questions and the A10 review (B1) asked for both side by
/// side, since a block below the placed floor can still be decodable. `None` for a scenario with
/// no ProviderExit event (every other report is unchanged).
fn format_provider_exit(result: &RunResult) -> Option<String> {
    if result
        .per_seed_overall_durability
        .iter()
        .all(|d| d.is_nan())
    {
        return None;
    }
    let mut o = String::new();
    let _ = writeln!(
        o,
        "-- provider-exit (A10): floor-fill proxy vs decodability cross-check (mean ± σ) --"
    );
    let (m, s) = mean_sigma(&result.per_seed_overall_durability);
    let _ = writeln!(
        o,
        "  post-exit floor-fill (non-cream / n_symbols, PROXY)   {:>8.4} ± {:.4}",
        m, s
    );
    let (m, s) = col(result, |x| x.decodable_fraction);
    let _ = writeln!(
        o,
        "  decodable blocks (alive ≥ k_eff, cream INCLUDED)      {:>8.4} ± {:.4}",
        m, s
    );
    let (m, s) = col(result, |x| x.undecodable_blocks as f64);
    let _ = writeln!(
        o,
        "  undecodable tail (blocks < k_eff)                     {:>8.2} ± {:.2}",
        m, s
    );
    let _ = writeln!(
        o,
        "  (floor-fill answers 'how much of the PLACED floor holders retain'; decodability answers"
    );
    let _ = writeln!(
        o,
        "   'could the owner still reconstruct it' — the honest restorability read.)"
    );
    let _ = writeln!(o);
    Some(o)
}

/// Render the inflow POPULATION-CURVE section (`4r_inflow_spec.md` §3): the present-count over
/// ticks (mean ± σ over seeds, sampled) + the last-half stationarity band around the setpoint.
/// `None` when no seed carried a population curve (a non-inflow scenario — output unchanged). The
/// curve is the core inflow deliverable: without inflow the closed cohort collapses; with inflow it
/// stabilises near the setpoint.
fn format_population(result: &RunResult) -> Option<String> {
    let series: Vec<&PopSeries> = result.per_seed_pop.iter().flatten().collect();
    let first = *series.first()?;
    let len = first.present_per_tick.len();
    if len == 0 {
        return None;
    }
    let setpoint = first.setpoint as f64;
    let mut o = String::new();
    let _ = writeln!(
        o,
        "-- inflow population curve (present nodes per tick, mean ± σ over seeds) --"
    );
    let _ = writeln!(
        o,
        "  setpoint n0 = {}   band = ±{:.0}%   (open-loop steady arrival; INV-POP-STATIONARY over last half)",
        first.setpoint,
        POP_BAND * 100.0,
    );
    let _ = writeln!(o, "  {:>6}  {:>16} {:>10}", "tick", "present", "dev%");
    // Sample ~26 evenly-spaced ticks (plus the last) so the curve is readable at any horizon.
    let step = (len / 26).max(1);
    let mut ticks: Vec<usize> = (0..len).step_by(step).collect();
    if ticks.last() != Some(&(len - 1)) {
        ticks.push(len - 1);
    }
    for &k in &ticks {
        let vals: Vec<f64> = series
            .iter()
            .map(|s| s.present_per_tick[k] as f64)
            .collect();
        let (m, s) = mean_sigma(&vals);
        let dev = if setpoint > 0.0 {
            (m / setpoint - 1.0) * 100.0
        } else {
            f64::NAN
        };
        // tick index k is 0-based post-step; show the 1-based tick number.
        let _ = writeln!(o, "  {:>6}  {:>16} {:>9.1}%", k + 1, ms_cell(m, s, 1), dev);
    }
    // Last-half stationarity band: mean present (over seeds) + the INV-POP-STATIONARY max-dev scalar.
    let lh_vals: Vec<f64> = series.iter().map(|s| s.last_half_mean()).collect();
    let (lhm, lhs) = mean_sigma(&lh_vals);
    let dev_vals: Vec<f64> = series.iter().map(|s| s.stationary_max_dev()).collect();
    let (dm, ds) = mean_sigma(&dev_vals);
    let fin_vals: Vec<f64> = series.iter().map(|s| s.final_present() as f64).collect();
    let (fm, fs) = mean_sigma(&fin_vals);
    let _ = writeln!(
        o,
        "  last-half mean present = {}   final present = {}",
        ms_cell(lhm, lhs, 1),
        ms_cell(fm, fs, 1),
    );
    let _ = writeln!(
        o,
        "  last-half max deviation from setpoint = {}   [INV-POP-STATIONARY: < {:.2} ⇒ stationary]",
        ms_cell(dm, ds, 4),
        POP_BAND,
    );
    let _ = writeln!(o);
    Some(o)
}

/// Mean±σ of one tier-report scalar across the seeds (seeds with no tier report → `NaN`, skipped).
fn tcol(result: &RunResult, f: impl Fn(&TierReport) -> f64) -> (f64, f64) {
    let vals: Vec<f64> = result
        .per_seed_tier
        .iter()
        .map(|t| t.as_ref().map(&f).unwrap_or(f64::NAN))
        .collect();
    mean_sigma(&vals)
}

/// Render the phase-2a P7 per-tier table: "who gets what in the network of givers" (`4r_p2a_spec.md`
/// §3). Columns per tier (T1..T4): the assigned uptime profile, present/total owners, the RECEIVED
/// facts (floor-completeness, durability, share A>0, mean parked gb, mean inbound served) and the
/// GIVEN / balance facts (mean outbound served, extraction = received/given). `None` when no seed
/// carried a tier report (a non-tiered scenario). mean±σ over seeds; σ = "—" for < 2 finite seeds.
fn format_tier(result: &RunResult) -> Option<String> {
    if !result.per_seed_tier.iter().any(|t| t.is_some()) {
        return None;
    }
    let mut o = String::new();
    let _ = writeln!(
        o,
        "-- phase-2a P7 per-tier report: what each giver tier RECEIVES (mean ± σ over seeds) --"
    );
    let _ = writeln!(
        o,
        "  (floor_complete = FROZEN board metric over ALL owners; fc_stayers = NOTE-c diagnostic over present-at-horizon owners)"
    );
    let _ = writeln!(
        o,
        "  {:<4} {:<11} {:>9} {:>15} {:>13} {:>11} {:>12} {:>11}",
        "tier",
        "uptime",
        "owners",
        "floor_complete",
        "fc_stayers",
        "durability",
        "share A>0",
        "parked gb",
    );
    for &t in &TIER_ORDER {
        let ti = tier_index(t);
        let profile = tier_profile(t).label();
        let (tot, _) = tcol(result, |r| r.tier[ti].n_owners_total as f64);
        let (pres, _) = tcol(result, |r| r.tier[ti].n_owners_present as f64);
        let (fc, fcs) = tcol(result, |r| r.tier[ti].floor_completeness);
        let (fs, fss) = tcol(result, |r| r.tier[ti].floor_completeness_stayers);
        let (du, dus) = tcol(result, |r| r.tier[ti].durability);
        let (sa, sas) = tcol(result, |r| r.tier[ti].share_a_pos);
        let (pk, pks) = tcol(result, |r| r.tier[ti].mean_parked_gb);
        let _ = writeln!(
            o,
            "  {:<4} {:<11} {:>4.0}/{:<4.0} {:>15} {:>13} {:>11} {:>12} {:>11}",
            tier_name(t),
            profile,
            pres,
            tot,
            ms_cell(fc, fcs, 3),
            ms_cell(fs, fss, 3),
            ms_cell(du, dus, 2),
            ms_cell(sa, sas, 1),
            ms_cell(pk, pks, 1),
        );
    }
    // The give↔get balance row set (received / given served integrals + extraction ratio).
    let _ = writeln!(
        o,
        "  give↔get (served gb·d integral per present owner | extraction = received/given):"
    );
    let _ = writeln!(
        o,
        "  {:<4} {:>18} {:>18} {:>14}",
        "tier", "received (in)", "given (out)", "extraction",
    );
    for &t in &TIER_ORDER {
        let ti = tier_index(t);
        let (inb, inbs) = tcol(result, |r| r.tier[ti].mean_inbound_served);
        let (out, outs) = tcol(result, |r| r.tier[ti].mean_outbound_served);
        let (ex, exs) = tcol(result, |r| r.tier[ti].extraction);
        let _ = writeln!(
            o,
            "  {:<4} {:>18} {:>18} {:>14}",
            tier_name(t),
            ms_cell(inb, inbs, 1),
            ms_cell(out, outs, 1),
            ms_cell(ex, exs, 3),
        );
    }
    let _ = writeln!(o);
    Some(o)
}

/// Short tier label for the report.
fn tier_name(t: crate::sim_dynamic::generator::GiverTier) -> &'static str {
    use crate::sim_dynamic::generator::GiverTier;
    match t {
        GiverTier::T1 => "T1",
        GiverTier::T2 => "T2",
        GiverTier::T3 => "T3",
        GiverTier::T4 => "T4",
    }
}

/// Render the R̂-calibration section (transche 0.3 judge, WARN-1). Pools every seed's resolved
/// rows, then scores ONLY the FLOOR-COMPLETE cut (≥ k_eff symbols at the forecast — the rows
/// whose `r_hat` is a real forecast); the incomplete structural-zero population is reported as
/// a separate diagnostic line, NOT part of the judge. `None` when no complete row resolved.
fn format_brier(result: &RunResult) -> Option<String> {
    // Pool all seeds (the aggregate calibration curve).
    let mut pooled = Calibration::new();
    for c in &result.per_seed_calibration {
        for &(f, o, cpl) in &c.pairs {
            pooled.push(f, o, cpl);
        }
    }
    // The JUDGE: floor-complete rows only.
    let agg = pooled.complete_report(DEFAULT_BRIER_BUCKETS)?;

    // Per-seed Brier mean±σ over the complete cut (seeds with ≥1 complete row).
    let per_seed_brier: Vec<f64> = result
        .per_seed_calibration
        .iter()
        .filter_map(|c| c.complete_report(DEFAULT_BRIER_BUCKETS).map(|r| r.brier))
        .collect();
    let (bm, bs) = mean_sigma(&per_seed_brier);

    let mut o = String::new();
    let _ = writeln!(
        o,
        "-- R̂-calibration (transche 0.3 judge, WARN-1; floor-COMPLETE rows only) --"
    );
    let _ = writeln!(
        o,
        "  judged N = {}   base-rate ō = {:.4}   (outcome = block ≥ k_eff live @ +H ticks)",
        agg.n, agg.base_rate,
    );
    let _ = writeln!(
        o,
        "  Brier (pooled)        {:>8.4}   [lower better; perfect 0, const-ō {:.4}]",
        agg.brier, agg.uncertainty,
    );
    let _ = writeln!(o, "  Brier (per-seed)      {:>8.4} ± {:.4}", bm, bs);
    let _ = writeln!(
        o,
        "  reliability           {:>8.4}   [lower better; 0 = perfectly calibrated]",
        agg.reliability,
    );
    let _ = writeln!(
        o,
        "  resolution            {:>8.4}   [higher better; 0 = no discrimination]",
        agg.resolution,
    );
    let _ = writeln!(
        o,
        "  uncertainty ō(1−ō)    {:>8.4}   [Brier ≈ reliability − resolution + uncertainty]",
        agg.uncertainty,
    );
    let _ = writeln!(
        o,
        "  reliability diagram (forecast bucket → observed freq):"
    );
    for b in &agg.buckets {
        if b.n == 0 {
            continue;
        }
        let _ = writeln!(
            o,
            "    [{:.1},{:.1})  n={:>6}  f̄={:.4}  ō={:.4}",
            b.lo, b.hi, b.n, b.mean_forecast, b.observed_freq,
        );
    }
    // Incomplete structural-zero population (excluded from the judge) — diagnostic only.
    if let Some(inc) = pooled.incomplete_summary() {
        let _ = writeln!(
            o,
            "  [incomplete (excl.): n={} ({:.1}% of resolved)  f̄={:.4} (structural 0)  ō={:.4}]",
            inc.n,
            100.0 * inc.share_of_total,
            inc.mean_forecast,
            inc.observed_freq,
        );
    }
    let _ = writeln!(o);
    Some(o)
}

fn fmt_power(p: f64) -> String {
    if p.is_nan() {
        "  struct".to_string()
    } else if p.is_infinite() {
        "     inf".to_string()
    } else {
        format!("{p:>8.2}")
    }
}

fn aname(a: Archetype) -> &'static str {
    match a {
        Archetype::Reliable => "Reliable",
        Archetype::Weekend => "Weekend",
        Archetype::Seasonal => "Seasonal",
        Archetype::Nomad => "Nomad",
        Archetype::Hoarder => "Hoarder",
        Archetype::Freeloader => "Freeloader",
    }
}

/// The shared header row (scenario/seed/god-view columns + per-archetype durability and
/// ROI), reused by both the per-seed CSV and the sweep CSV — kept in one place so the two
/// never drift out of column-sync.
fn header_base() -> String {
    let mut h = String::from(
        "scenario,seed,alive_symbols,present_nodes,share_a_pos,evicts,preempts,cap_trims,mean_depth,mean_sigma",
    );
    for a in Archetype::ALL {
        let _ = write!(h, ",dur_{}", aname(a));
    }
    for a in Archetype::ALL {
        let _ = write!(h, ",roi_{}", aname(a));
    }
    h
}

/// Append one seed's data row (no trailing newline) to `o`.
fn write_seed_row(o: &mut String, result: &RunResult, i: usize) {
    let seed = result.seeds[i];
    let m = &result.per_seed[i];
    let _ = write!(
        o,
        "{},{},{},{},{:.6},{},{},{},{:.6},{:.6}",
        result.scenario,
        seed,
        m.alive_symbols,
        m.present_nodes,
        m.share_a_pos,
        m.evicts,
        m.preempts,
        m.cap_trims,
        m.mean_depth,
        m.mean_sigma,
    );
    for d in m.durability {
        let _ = write!(o, ",{d:.6}");
    }
    for r in m.extraction_roi {
        let _ = write!(o, ",{r:.6}");
    }
}

/// Render the machine CSV: one row per seed (the per-seed dump, detail §3). This is where
/// the regression anchor reads seed 42's exact numbers.
pub fn run_result_csv(result: &RunResult) -> String {
    let mut o = header_base();
    o.push('\n');
    for i in 0..result.per_seed.len() {
        write_seed_row(&mut o, result, i);
        o.push('\n');
    }
    o
}

/// Render the machine CSV for a `--sweep` run: ONE header (never repeated per point),
/// plus `dial`/`value` columns on every row so sweep points stay distinguishable (the
/// BLOCK fix — concatenating per-point [`run_result_csv`] output repeated the header and
/// dropped the handle value, making e.g. `block_volume=20` and `=50` rows identical
/// except by god-view metric values). One row per (sweep point × seed).
pub fn sweep_csv(dial: &str, rows: &[SweepRow]) -> String {
    let mut o = header_base();
    o.push_str(",dial,value\n");
    for row in rows {
        for i in 0..row.result.per_seed.len() {
            write_seed_row(&mut o, &row.result, i);
            let _ = writeln!(o, ",{dial},{}", row.value);
        }
    }
    o
}

/// Render a compact dial-sweep table (mean over seeds of the headline metrics).
pub fn format_sweep(scenario: &Scenario, dial: &str, rows: &[SweepRow]) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "=== sim_adv sweep '{}' over dial '{}' ===",
        scenario.id, dial
    );
    let _ = writeln!(
        o,
        "  {:>12} {:>12} {:>12} {:>14}",
        dial, "share A>0", "evicts", "ROI Reliable"
    );
    for row in rows {
        let (share, _) = col(&row.result, |x| x.share_a_pos);
        let (evicts, _) = col(&row.result, |x| x.evicts as f64);
        let (roi, _) = col(&row.result, |x| x.extraction_roi[0]);
        let _ = writeln!(
            o,
            "  {:>12.4} {:>12.4} {:>12.2} {:>14.4}",
            row.value, share, evicts, roi
        );
    }
    o
}
