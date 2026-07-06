//! `sim_diag` — god-view diagnostic for the dynamic 4R world (NOT a gate).
//!
//! Sections 1-5 open the "parasite wins" box on a contended run (φ distribution,
//! where symbols live, per-pair reciprocity, drop discrimination, truthful durability).
//! Section 6 is the world-v2 §9 "живая сеть" (living network) instrument: the share-A>0
//! trajectory, concentration, newcomer-entry chain vs the θ_p/λ prediction, the
//! preemption counter, and a Sybil sanity read. Section 7 is the correlated-holder-death
//! "repair-storm" sweep (aggregate review §5.2): kill the top-K% popular holders at a
//! shock tick and measure whether the synchronous repair spike cascades — instant vs
//! latent (PoS-cadence) detection.
//!
//! Usage: `sim_diag [seed] [n_nodes] [block_volume] [reciprocal 0|1] [world v1|v2]
//! [preempt off|θ_p] [recalibrated 0|1] [T_shock] [K_csv] [latent_cadence]` — all
//! positional, all optional:
//!
//! * `seed` — run seed (default 0x00E15EED).
//! * `n_nodes` — node count (default 200).
//! * `block_volume` — gb per block (default 20 ⇒ 4 gb/symbol).
//! * `reciprocal` — 1/default = canon retained_depth ranking; 0 = pure surface.
//! * `world` — `v2` (default) = incremental arrival + bandwidth `U` + cream (the living
//!   network); `v1` = one-shot залп, `U=∞`, no cream (the degenerate baseline, for A/B).
//! * `preempt` — `off` disables preemption; a number sets `θ_p` (default 0.2).
//! * `recalibrated` — 1/default = canon RetentionPrior (ceiling φ_O 0.900, Р-2 accepted,
//!   = kernel default); `0` = A/B baseline (pre-Р-2 ceiling 0.622). Measured separately.
//! * `T_shock` — the tick the repair-storm shock fires at (default 80).
//! * `K_csv` — comma-separated top-K% holder-kill fractions for section 7 (default
//!   `1,5,10`). A `0` control (background baseline) is always prepended.
//! * `latent_cadence` — the latent-detection window in ticks (default 3 ≈ a ~3-week PoS
//!   cadence); each K is run at both instant (0) and this latent cadence.

use viaticum_core::four_r::{PlacementPolicy, SurfacePrior};
use viaticum_sim::sim_dynamic::build_world;
use viaticum_sim::sim_dynamic::engine::{DynParams, step};
use viaticum_sim::sim_dynamic::generator::{Archetype, DAYS_PER_TICK, World};
use viaticum_sim::sim_dynamic::repair_storm::{
    RepairStormConfig, RepairStormReport, run_repair_storm,
};

const ARCHES: [Archetype; 6] = [
    Archetype::Reliable,
    Archetype::Weekend,
    Archetype::Seasonal,
    Archetype::Nomad,
    Archetype::Hoarder,
    Archetype::Freeloader,
];

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

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        f64::NAN
    } else {
        xs.iter().sum::<f64>() / xs.len() as f64
    }
}

/// Gini coefficient of a non-negative distribution (0 = perfectly even, →1 = all mass on
/// one). Returns NaN for an empty / all-zero distribution.
fn gini(xs: &[f64]) -> f64 {
    let n = xs.len();
    if n == 0 {
        return f64::NAN;
    }
    let sum: f64 = xs.iter().sum();
    if sum <= 0.0 {
        return f64::NAN;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    // G = (2·Σ i·x_i)/(n·Σ x_i) − (n+1)/n  (1-based i).
    let mut weighted = 0.0;
    for (i, &x) in v.iter().enumerate() {
        weighted += (i as f64 + 1.0) * x;
    }
    (2.0 * weighted) / (n as f64 * sum) - (n as f64 + 1.0) / n as f64
}

fn main() {
    let mut args = std::env::args().skip(1);
    let seed: u64 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x00E1_5EED);
    let n_nodes: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(200);
    let block_volume: f64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(20.0);
    let reciprocal_placement: bool = args
        .next()
        .map(|s| s != "0" && !s.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    // World preset (§9 A/B): v1 = one-shot залп + U=∞ + no cream; v2 = living network.
    let world_v2: bool = match args.next().as_deref() {
        Some("v1") | Some("V1") => false,
        _ => true, // "v2"/default
    };
    // Preemption: "off" disables; a number sets θ_p.
    let preempt_theta: f64 = match args.next() {
        Some(s) if s.eq_ignore_ascii_case("off") => f64::NEG_INFINITY,
        Some(s) => s
            .parse()
            .unwrap_or_else(|_| DynParams::default().preempt_theta),
        None => DynParams::default().preempt_theta,
    };
    // Р-2 accepted ⇒ canon 0.900 is the DEFAULT; pass `0`/`false` for the A/B baseline 0.622.
    let recalibrated: bool = args
        .next()
        .map(|s| s != "0" && !s.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    // Section-7 (repair-storm) args: shock tick, K% list, latent detection cadence.
    let t_shock: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(80);
    let k_list: Vec<f64> = args
        .next()
        .map(|s| {
            s.split(',')
                .filter_map(|p| p.trim().parse::<f64>().ok())
                .filter(|&k| k > 0.0)
                .collect::<Vec<_>>()
        })
        .filter(|v: &Vec<f64>| !v.is_empty())
        .unwrap_or_else(|| vec![1.0, 5.0, 10.0]);
    let latent_cadence: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(3);

    let base = DynParams::default();
    let params = DynParams {
        block_volume,
        reciprocal_placement,
        preempt_theta,
        recalibrated_retention: recalibrated,
        // World preset.
        incremental: world_v2,
        bandwidth_u: if world_v2 {
            base.bandwidth_u
        } else {
            f64::INFINITY
        },
        cream_enabled: world_v2,
        ..base
    };
    println!(
        "[world = {}  reciprocal = {reciprocal_placement}  preempt θ_p = {preempt_theta}  \
         recalibrated_prior = {recalibrated}  U = {}  cream = {}]",
        if world_v2 {
            "v2 (living)"
        } else {
            "v1 (one-shot)"
        },
        params.bandwidth_u,
        params.cream_enabled,
    );
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();

    let mut world = build_world(n_nodes, &params, seed);
    let nn = world.nodes.len();

    // Over all ALIVE symbols: (count, share with reciprocal A=g_ho>0, total alive vol).
    let snapshot = |w: &World| -> (usize, f64, f64) {
        let mut total = 0usize;
        let mut a_pos = 0usize;
        let mut vol = 0.0;
        for h in 0..w.nodes.len() {
            if !w.nodes[h].present {
                continue;
            }
            for s in w.nodes[h].holdings.iter().filter(|s| s.alive) {
                total += 1;
                vol += s.volume;
                if w.capital[s.owner][h].g_ho > 1e-12 {
                    a_pos += 1;
                }
            }
        }
        let share = if total > 0 {
            100.0 * a_pos as f64 / total as f64
        } else {
            0.0
        };
        (total, share, vol)
    };

    // ~130 ticks — the experiment horizon. Track the share-A>0 TRAJECTORY (§9 gate a).
    println!("=== sim_diag time-series (n={nn} block_volume={block_volume}) ===");
    println!(
        "  {:>4}  {:>10} {:>12}  {:>11} {:>10} {:>9} {:>7}",
        "tick", "alive syms", "alive vol gb", "share A>0", "present", "evicts", "preempt"
    );
    for t in 0..130u64 {
        step(&mut world, &params, &prior, &policy);
        if (t + 1) % 20 == 0 || t == 9 {
            let (cnt, share, vol) = snapshot(&world);
            let present = world.nodes.iter().filter(|n| n.present).count();
            println!(
                "  {:>4}  {:>10} {:>12.0}  {:>10.1}% {:>10} {:>9} {:>7}",
                t + 1,
                cnt,
                vol,
                share,
                present,
                world.eviction_log.len(),
                world.preempt_count,
            );
        }
    }

    let n = world.nodes.len();
    println!(
        "=== sim_diag (seed={seed} n={n_nodes} block_volume={block_volume}, floor={:.0}gb) ===",
        params.blocks_per_node as f64 * block_volume
    );

    // --- (1) φ distribution by archetype (present nodes only) ---
    println!("\n-- (1) φ free-ratio by archetype (present nodes; →0 = filled) --");
    println!(
        "  {:<10} {:>6}  {:>7} {:>7} {:>7}  {:>10}",
        "archetype", "count", "mean φ", "min φ", "max φ", "mean util"
    );
    for &a in &ARCHES {
        let phis: Vec<f64> = (0..n)
            .filter(|&i| world.nodes[i].present && world.nodes[i].archetype == a)
            .map(|i| world.nodes[i].phi_free_ratio())
            .collect();
        if phis.is_empty() {
            continue;
        }
        let mn = phis.iter().cloned().fold(f64::INFINITY, f64::min);
        let mx = phis.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        println!(
            "  {:<10} {:>6} {:>8.3} {:>7.3} {:>7.3} {:>10.3}",
            aname(a),
            phis.len(),
            mean(&phis),
            mn,
            mx,
            1.0 - mean(&phis)
        );
    }

    // --- (2) WHERE alive symbols live: holder-archetype distribution per owner-archetype ---
    println!("\n-- (2) WHERE alive symbols live (holder-archetype share per owner-archetype) --");
    for &owner_a in &[
        Archetype::Reliable,
        Archetype::Freeloader,
        Archetype::Hoarder,
    ] {
        let mut by_holder: Vec<(Archetype, f64, f64)> = Vec::new();
        for h in 0..n {
            if !world.nodes[h].present {
                continue;
            }
            let h_arch = world.nodes[h].archetype;
            let h_phi = world.nodes[h].phi_free_ratio();
            let h_up = world.nodes[h].archetype.base_uptime();
            for s in world.nodes[h].holdings.iter().filter(|s| s.alive) {
                if world.nodes[s.owner].archetype == owner_a {
                    by_holder.push((h_arch, h_phi, h_up));
                }
            }
        }
        let total = by_holder.len();
        println!(
            "\n  owner = {:<10} : {} alive symbols stored network-wide",
            aname(owner_a),
            total
        );
        if total == 0 {
            continue;
        }
        let mean_holder_phi = mean(&by_holder.iter().map(|x| x.1).collect::<Vec<_>>());
        let mean_holder_up = mean(&by_holder.iter().map(|x| x.2).collect::<Vec<_>>());
        println!(
            "    mean holder φ = {mean_holder_phi:.3}   mean holder base-uptime = {mean_holder_up:.3}"
        );
        for &h_a in &ARCHES {
            let cnt = by_holder.iter().filter(|x| x.0 == h_a).count();
            if cnt == 0 {
                continue;
            }
            println!(
                "    on {:<10} holders: {:>5}  ({:>5.1}%)",
                aname(h_a),
                cnt,
                100.0 * cnt as f64 / total as f64
            );
        }
    }

    // --- (2b) per-pair reciprocity over ALIVE symbols (B=h-holds-O, A=O-holds-h) ---
    println!("\n-- (2b) per-pair reciprocity over ALIVE symbols (B=h-holds-O, A=O-holds-h) --");
    println!(
        "  {:<10} {:>8}  {:>8} {:>8}  {:>11}  {:>11}",
        "owner", "symbols", "mean B", "mean A", "share A>0", "share B>0"
    );
    for &owner_a in &ARCHES {
        let mut ab: Vec<(f64, f64)> = Vec::new();
        for h in 0..n {
            if !world.nodes[h].present {
                continue;
            }
            for s in world.nodes[h].holdings.iter().filter(|s| s.alive) {
                if world.nodes[s.owner].archetype == owner_a {
                    let b = world.capital[s.owner][h].g_oh;
                    let a = world.capital[s.owner][h].g_ho;
                    ab.push((a, b));
                }
            }
        }
        if ab.is_empty() {
            continue;
        }
        let a_pos = ab.iter().filter(|&&(a, _)| a > 1e-12).count();
        let b_pos = ab.iter().filter(|&&(_, b)| b > 1e-12).count();
        let mean_a = mean(&ab.iter().map(|x| x.0).collect::<Vec<_>>());
        let mean_b = mean(&ab.iter().map(|x| x.1).collect::<Vec<_>>());
        println!(
            "  {:<10} {:>8} {:>9.3} {:>8.3} {:>10.1}% {:>10.1}%",
            aname(owner_a),
            ab.len(),
            mean_b,
            mean_a,
            100.0 * a_pos as f64 / ab.len() as f64,
            100.0 * b_pos as f64 / ab.len() as f64
        );
    }

    // --- (2c) do drops concentrate on g_ho≈0 placements? ---
    {
        let drops = world.eviction_log.len();
        let drops_recip = world
            .eviction_log
            .iter()
            .filter(|ev| ev.g_ho_at_drop > 1e-12)
            .count();
        let mean_drop_g = if drops > 0 {
            world
                .eviction_log
                .iter()
                .map(|ev| ev.g_ho_at_drop)
                .sum::<f64>()
                / drops as f64
        } else {
            f64::NAN
        };
        let (_t, pop_share, _v) = snapshot(&world);
        println!("\n-- (2c) reciprocity of DROPPED placements (mechanism discrimination) --");
        println!(
            "  drops with g_ho>0 = {:.1}%  (mean g_ho_at_drop = {:.3})   vs live population share A>0 = {:.1}%",
            if drops > 0 {
                100.0 * drops_recip as f64 / drops as f64
            } else {
                0.0
            },
            mean_drop_g,
            pop_share
        );
    }

    // --- (3) Eviction counts by owner-archetype (whose data got dropped) ---
    println!("\n-- (3) evictions by OWNER archetype (whose data was dropped) --");
    let mut evict_by_owner = [0usize; 6];
    for ev in &world.eviction_log {
        if ev.owner < n {
            let a = world.nodes[ev.owner].archetype;
            let idx = ARCHES.iter().position(|&x| x == a).unwrap();
            evict_by_owner[idx] += 1;
        }
    }
    let total_ev = world.eviction_log.len().max(1);
    for (i, &a) in ARCHES.iter().enumerate() {
        let node_cnt = (0..n)
            .filter(|&j| world.nodes[j].archetype == a)
            .count()
            .max(1);
        println!(
            "  {:<10} evictions = {:>5}  ({:>5.1}% of all)   per-node = {:>6.1}",
            aname(a),
            evict_by_owner[i],
            100.0 * evict_by_owner[i] as f64 / total_ev as f64,
            evict_by_owner[i] as f64 / node_cnt as f64
        );
    }

    // --- (5) TRUTHFUL durability by owner-archetype (FLOOR symbols only, §9.3 cream not counted) ---
    let k_eff = params.k_eff;
    println!(
        "\n-- (5) TRUTHFUL durability by owner-archetype (FLOOR alive holders/block; k_eff={k_eff}) --"
    );
    println!(
        "  {:<10} {:>7}  {:>11}  {:>13}  {:>9}",
        "owner", "blocks", "mean alive", "under-repl <k", "lost =0"
    );
    for &a in &ARCHES {
        let mut counts: Vec<usize> = Vec::new();
        for o in 0..n {
            if !world.nodes[o].present || world.nodes[o].archetype != a {
                continue;
            }
            for b in &world.nodes[o].own_blocks {
                // FLOOR (non-cream) alive holders only — cream is not a durability guarantee.
                let alive = (0..n)
                    .filter(|&h| {
                        world.nodes[h].present
                            && world.nodes[h]
                                .holdings
                                .iter()
                                .any(|s| s.alive && !s.cream && s.owner == o && s.block == b.id)
                    })
                    .count();
                counts.push(alive);
            }
        }
        if counts.is_empty() {
            continue;
        }
        let blocks = counts.len();
        let mean_alive = counts.iter().sum::<usize>() as f64 / blocks as f64;
        let under = counts.iter().filter(|&&c| c < k_eff).count();
        let lost = counts.iter().filter(|&&c| c == 0).count();
        println!(
            "  {:<10} {:>7} {:>11.2}  {:>11.1}%  {:>7.1}%",
            aname(a),
            blocks,
            mean_alive,
            100.0 * under as f64 / blocks as f64,
            100.0 * lost as f64 / blocks as f64
        );
    }

    // --- (6) WORLD-v2 §9 "живая сеть" (living network) ---
    print_section6(&world, &params);

    // --- (7) repair-storm: correlated holder death (aggregate review §5.2) ---
    print_section7(&params, seed, n_nodes, t_shock, &k_list, latent_cadence);
}

/// Section 6 (world-v2 §9): share-A>0 final, concentration, newcomer-entry chain vs the
/// θ_p/λ prediction, the preemption counter, and a Sybil sanity read.
fn print_section6(world: &World, params: &DynParams) {
    let n = world.nodes.len();
    println!("\n=== (6) WORLD-v2 §9 living-network diagnostics ===");

    // (6a) final share A>0 over alive symbols (the P8 gate-a headline).
    let mut total = 0usize;
    let mut a_pos = 0usize;
    for h in 0..n {
        if !world.nodes[h].present {
            continue;
        }
        for s in world.nodes[h].holdings.iter().filter(|s| s.alive) {
            total += 1;
            if world.capital[s.owner][h].g_ho > 1e-12 {
                a_pos += 1;
            }
        }
    }
    let share = if total > 0 {
        100.0 * a_pos as f64 / total as f64
    } else {
        0.0
    };
    println!(
        "  (6a) FINAL share A>0 (reciprocal alive symbols) = {share:.1}%   over {total} alive symbols"
    );

    // (6b) concentration: symbols per active (owner,holder) pair + Gini of holdings/holder.
    let mut pair_counts: std::collections::BTreeMap<(usize, usize), usize> =
        std::collections::BTreeMap::new();
    let mut holder_load: Vec<f64> = vec![0.0; n];
    for (h, node) in world.nodes.iter().enumerate() {
        if !node.present {
            continue;
        }
        for s in node.holdings.iter().filter(|s| s.alive) {
            *pair_counts.entry((s.owner, h)).or_insert(0) += 1;
            holder_load[h] += 1.0;
        }
    }
    let mean_per_pair = if pair_counts.is_empty() {
        f64::NAN
    } else {
        pair_counts.values().map(|&c| c as f64).sum::<f64>() / pair_counts.len() as f64
    };
    let present_load: Vec<f64> = (0..n)
        .filter(|&i| world.nodes[i].present)
        .map(|i| holder_load[i])
        .collect();
    println!(
        "  (6b) concentration: active pairs = {}   mean symbols/pair = {:.2}   Gini(holdings/holder) = {:.3}",
        pair_counts.len(),
        mean_per_pair,
        gini(&present_load),
    );

    // (6c) newcomer-entry chain (nodes joined after t=0): joined → first_earned_g →
    // first_own_accept, compared with the θ_p/λ prediction.
    let lambda_dt = params.lambda * DAYS_PER_TICK;
    let pred_ticks = if params.preempt_theta.is_finite() && params.preempt_theta >= 0.0 {
        params.preempt_theta / lambda_dt
    } else {
        f64::NAN
    };
    let mut earn_gap: Vec<f64> = Vec::new(); // first_earned_g − joined
    let mut serve_to_accept: Vec<f64> = Vec::new(); // first_own_accept − first_earned_g
    let mut joined_after0 = 0usize;
    let mut ever_earned = 0usize;
    let mut ever_own = 0usize;
    let mut accept_before_earn = 0usize; // own data accepted BEFORE any earned g (free slot)
    for i in 0..n {
        if world.nodes[i].joined_tick == 0 {
            continue;
        }
        joined_after0 += 1;
        let j = world.nodes[i].joined_tick;
        if let Some(e) = world.first_earned_g[i] {
            ever_earned += 1;
            earn_gap.push(e.saturating_sub(j) as f64);
            if let Some(o) = world.first_own_accept[i] {
                ever_own += 1;
                if o >= e {
                    serve_to_accept.push((o - e) as f64);
                } else {
                    accept_before_earn += 1; // entered via a FREE slot before serving
                }
            }
        }
    }
    println!("  (6c) newcomer entry (nodes joined after t=0 = {joined_after0}):");
    println!(
        "       earned g (served someone) : {}/{} nodes, mean (first_earned_g − joined) = {:.2} ticks",
        ever_earned,
        joined_after0,
        mean(&earn_gap)
    );
    println!(
        "       own data accepted         : {}/{} nodes ({} entered via a FREE slot BEFORE earning g)",
        ever_own, joined_after0, accept_before_earn
    );
    println!(
        "       serve→accept gap          : mean {:.2} ticks over {} nodes that served THEN placed",
        mean(&serve_to_accept),
        serve_to_accept.len()
    );
    println!(
        "       θ_p/λ prediction for the serve→accept gap = {:.2} ticks  (θ_p={:.3}, λ·dt={:.4})",
        pred_ticks, params.preempt_theta, lambda_dt
    );
    // Small histogram of the serve→accept gap.
    if !serve_to_accept.is_empty() {
        let mut buckets = [0usize; 6]; // 0,1,2,3,4,5+
        for &g in &serve_to_accept {
            let b = (g as usize).min(5);
            buckets[b] += 1;
        }
        print!("       serve→accept gap histogram [ticks]:");
        for (b, &c) in buckets.iter().enumerate() {
            let label = if b == 5 {
                "5+".to_string()
            } else {
                b.to_string()
            };
            print!("  {label}:{c}");
        }
        println!();
    }

    // (6d) preemption counter (was ~0 in the degenerate "starved, not frozen" world).
    println!("  (6d) preemptive swaps fired = {}", world.preempt_count);

    // (6e) Sybil sanity: late-joining Freeloaders (zero-giving farm) must NOT enter their
    // own data faster than late-joining Reliable (honest) newcomers.
    let mut rel_entry: Vec<f64> = Vec::new();
    let mut free_entry: Vec<f64> = Vec::new();
    let mut rel_late = 0usize;
    let mut free_late = 0usize;
    let mut rel_got = 0usize;
    let mut free_got = 0usize;
    for i in 0..n {
        if world.nodes[i].joined_tick == 0 {
            continue;
        }
        let j = world.nodes[i].joined_tick;
        match world.nodes[i].archetype {
            Archetype::Reliable => {
                rel_late += 1;
                if let Some(o) = world.first_own_accept[i] {
                    rel_got += 1;
                    rel_entry.push(o.saturating_sub(j) as f64);
                }
            }
            Archetype::Freeloader => {
                free_late += 1;
                if let Some(o) = world.first_own_accept[i] {
                    free_got += 1;
                    free_entry.push(o.saturating_sub(j) as f64);
                }
            }
            _ => {}
        }
    }
    println!("  (6e) Sybil sanity (late joiners; entry = first_own_accept − joined):");
    println!(
        "       Reliable   : {}/{} placed own data, mean entry = {:.2} ticks",
        rel_got,
        rel_late,
        mean(&rel_entry)
    );
    println!(
        "       Freeloader : {}/{} placed own data, mean entry = {:.2} ticks",
        free_got,
        free_late,
        mean(&free_entry)
    );
    let rel_rate = if rel_late > 0 {
        rel_got as f64 / rel_late as f64
    } else {
        f64::NAN
    };
    let free_rate = if free_late > 0 {
        free_got as f64 / free_late as f64
    } else {
        f64::NAN
    };
    println!(
        "       → honest entry-rate {:.2} vs zero-giving farm {:.2} (farm ≤ honest ⇒ Sybil-priced)",
        rel_rate, free_rate
    );

    // (6f) transaction-3a diagnostic: the A.4 loyalty depth D over alive-symbol pairs
    // (the slow W10 carrier that now feeds the κ_O eviction key). Read the SAME cell
    // (capital[owner][holder].depth_ho) as share A>0, so the shift is visible by eye.
    let mut d_vals: Vec<f64> = Vec::new();
    for h in 0..n {
        if !world.nodes[h].present {
            continue;
        }
        for s in world.nodes[h].holdings.iter().filter(|s| s.alive) {
            d_vals.push(world.capital[s.owner][h].depth_ho);
        }
    }
    let d_pos = d_vals.iter().filter(|&&d| d > 1e-12).count();
    let share_d = if d_vals.is_empty() {
        0.0
    } else {
        100.0 * d_pos as f64 / d_vals.len() as f64
    };
    println!(
        "  (6f) mean loyalty depth D over {} alive pairs = {:.3} gb·days   (share D>0 = {share_d:.1}%)",
        d_vals.len(),
        mean(&d_vals),
    );
}

/// Section 7 (aggregate review §5.2): the correlated-holder-death "repair-storm" sweep.
/// Kills the top-K% popular holders at `t_shock` and measures whether the synchronous
/// repair spike cascades — swept over K and over detection mode (instant vs latent PoS
/// cadence). Runs fresh worlds (independent of the sections 1-6 world) in the same regime.
fn print_section7(
    base: &DynParams,
    seed: u64,
    n_nodes: usize,
    t_shock: u64,
    k_list: &[f64],
    latent_cadence: u64,
) {
    // Observe long enough after the shock to see recovery (or its absence).
    const POST_TICKS: u64 = 50;
    println!("\n=== (7) REPAIR-STORM: correlated holder death (aggregate review §5.2) ===");
    println!(
        "  shock at T={t_shock}, +{POST_TICKS} post-ticks; kill top-K% holders by popularity \
         (god-view alive foreign symbols held)."
    );
    println!(
        "  detection: instant (owner refills next tick) vs latent (PoS cadence, seeded offset in \
         [0,{latent_cadence}] ticks)."
    );
    println!(
        "  hypothesis under test: latency STAGGERS the shock → lower concurrency, redundancy carries \
         the blocks, no cascade."
    );

    let run = |k_percent: f64, delay: u64| -> RepairStormReport {
        run_repair_storm(&RepairStormConfig {
            base_params: *base,
            n_nodes,
            seed,
            warmup_ticks: t_shock,
            post_ticks: POST_TICKS,
            k_percent,
            detection_delay_max: delay,
        })
    };

    // Control (no shock) per mode: the background-churn baseline for the same seed.
    let ctrl_instant = run(0.0, 0);
    let ctrl_latent = run(0.0, latent_cadence);
    println!(
        "\n  -- controls (no shock): background under-repl / lost at horizon (baseline to subtract) --"
    );
    println!(
        "     instant : baseline under-k(@T)={:>3}  end under-k={:>3}  end zero={:>3}  orphan-lost={:>3}",
        ctrl_instant.baseline_under_k,
        ctrl_instant.blocks_under_k_end,
        ctrl_instant.blocks_zero_end,
        ctrl_instant.blocks_orphaned_lost
    );
    println!(
        "     latent  : baseline under-k(@T)={:>3}  end under-k={:>3}  end zero={:>3}  orphan-lost={:>3}",
        ctrl_latent.baseline_under_k,
        ctrl_latent.blocks_under_k_end,
        ctrl_latent.blocks_zero_end,
        ctrl_latent.blocks_orphaned_lost
    );

    // Headline sweep table: K × mode. The two loss columns are SEPARATED: `casc` (cascade
    // among third parties) is the storm-cascade signal, compared against the control
    // baseline above; `vicOwn` is the killed nodes' OWN data (a direct kill, not a cascade).
    let casc_base_inst = ctrl_instant.blocks_orphaned_lost;
    let casc_base_lat = ctrl_latent.blocks_orphaned_lost;
    println!("\n  -- sweep: K × detection mode --");
    println!(
        "  {:>4} {:>5}  {:>6} {:>7}  {:>7} {:>8} {:>7} {:>6} {:>6}  {:>7} {:>7} {:>6} {:>6}",
        "K%",
        "mode",
        "killed",
        "sym-los",
        "pkUndK",
        "pkConc",
        "pkDem",
        "bw",
        "dem>bw",
        "endUndK",
        "casc",
        "vicOwn",
        "recov"
    );
    for &k in k_list {
        for (label, delay) in [("inst", 0u64), ("lat", latent_cadence)] {
            let r = run(k, delay);
            let recov = match r.ticks_to_recover {
                Some(t) => format!("{t}t"),
                None => "never".to_string(),
            };
            println!(
                "  {:>4.0} {:>5}  {:>6} {:>7}  {:>7} {:>8} {:>7} {:>6} {:>6}  {:>7} {:>7} {:>6} {:>6}",
                k,
                label,
                r.victims_killed,
                r.victim_symbols_killed,
                r.peak_under_k,
                r.peak_owners_repairing,
                r.peak_detected_demand_symbols,
                r.bandwidth_symbols,
                r.demand_exceeds_bandwidth_ticks,
                r.blocks_under_k_end,
                r.blocks_orphaned_lost,
                r.blocks_victim_owned_lost,
                recov
            );
        }
    }
    println!(
        "  legend: pkUndK=peak blocks<k_eff; pkConc=peak owners repairing/tick; pkDem=peak detected \
         repair symbols/tick; bw=aggregate upload symbols/tick;"
    );
    println!(
        "          dem>bw=ticks demand exceeded bandwidth; endUndK=present-owner blocks<k_eff at \
         horizon (recoverable);"
    );
    println!(
        "          casc=CASCADE loss (departed non-victim owners' blocks<k_eff; control baseline \
         inst={casc_base_inst}/lat={casc_base_lat} — SUBTRACT it);"
    );
    println!(
        "          vicOwn=killed nodes' OWN data<k_eff (direct kill, not a cascade); recov=ticks \
         until under-k≤baseline."
    );

    // Detailed trajectory for the largest K, instant vs latent (the smearing picture).
    if let Some(&k_max) = k_list.iter().max_by(|a, b| a.total_cmp(b)) {
        print_storm_trajectory(k_max, &run(k_max, 0), &run(k_max, latent_cadence));
    }
}

/// Print the post-shock trajectory (sampled) for the largest K at instant vs latent — the
/// direct picture of whether latency staggers the repair load and redundancy carries the gap.
fn print_storm_trajectory(k: f64, inst: &RepairStormReport, lat: &RepairStormReport) {
    println!("\n  -- trajectory at K={k:.0}% (instant vs latent), per post-shock tick --");
    println!(
        "  {:>4}  | {:>8} {:>8} {:>8} {:>8} | {:>8} {:>8} {:>8} {:>8}",
        "+t", "i:undK", "i:conc", "i:dem", "i:out", "l:undK", "l:conc", "l:dem", "l:out"
    );
    let n = inst.trajectory.len().min(lat.trajectory.len());
    for idx in 0..n {
        let it = &inst.trajectory[idx];
        // Show the first 12 ticks densely (the spike window), then every 5th.
        if it.since_shock > 12 && !it.since_shock.is_multiple_of(5) {
            continue;
        }
        let lt = &lat.trajectory[idx];
        println!(
            "  {:>4}  | {:>8} {:>8} {:>8} {:>8} | {:>8} {:>8} {:>8} {:>8}",
            it.since_shock,
            it.under_k_blocks,
            it.owners_repairing,
            it.detected_demand_symbols,
            it.outstanding_demand_symbols,
            lt.under_k_blocks,
            lt.owners_repairing,
            lt.detected_demand_symbols,
            lt.outstanding_demand_symbols,
        );
    }
    println!(
        "  (i:=instant, l:=latent; undK=blocks<k_eff, conc=owners repairing, dem=detected repair \
         symbols/tick, out=total outstanding repair symbols)"
    );
}
