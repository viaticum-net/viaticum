//! Report rendering: human text (mean±σ over seeds) + machine CSV (one row per seed).
//!
//! Single-seed numbers never appear in the TEXT report (spec §5) — only mean±σ across
//! seeds. The CSV keeps per-seed rows (the legitimate machine dump, detail §3): that is
//! where the regression anchor reads seed 42's exact values from. The text is rendered
//! with fixed-precision formatters and fixed iteration order, so it is byte-identical on
//! repeat (the determinism gate).

use std::fmt::Write as _;

use crate::sim_adv::brier::{Calibration, DEFAULT_BRIER_BUCKETS};
use crate::sim_adv::metrics::{MetricSet, mean_sigma};
use crate::sim_adv::restore::{IOTA_BUCKETS, RestoreTruth};
use crate::sim_adv::runner::{RunResult, SweepRow};
use crate::sim_adv::scenario::Scenario;
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

    // --- restore-truth (metric №1), only when a Disaster fired ---
    if let Some(section) = format_restore(result) {
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
