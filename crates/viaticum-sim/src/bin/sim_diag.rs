//! `sim_diag` — god-view diagnostic for the "parasite wins" puzzle (NOT a gate).
//!
//! The experiment harness reports OUTCOMES (R_actual by archetype) but is BLIND to
//! the mechanism internals that explain them. This binary opens that box by
//! tabulating, on a contended run, three god-view diagnostics:
//!   1. φ (free-ratio) distribution by archetype — is contention BIMODAL (a filled
//!      always-on core + an under-filled periphery)?
//!   2. WHERE each owner-archetype's ALIVE symbols live — the holder-archetype
//!      distribution + mean holder φ + mean holder base-uptime. This directly tests
//!      the hypothesis "free-rider data just lives on OTHER free-riders" (fragile,
//!      self-contained, not subsidised by the cooperative core).
//!   3. Eviction counts by owner-archetype (from the god-view eviction log).
//!
//! Headroom regime via `block_volume` alone (floor = blocks(3)×20 = 60 gb < lendable
//! end-state ≈72 gb at the 0.62 own-ceiling) — reproduces the parasite-wins regime
//! WITHOUT touching the OWN_DATA_DISK_FRACTION const.
//!
//! Usage: `cargo run -p viaticum-sim --bin sim_diag [seed] [n_nodes] [block_volume]`

use viaticum_core::four_r::{PlacementPolicy, SurfacePrior};
use viaticum_sim::sim_dynamic::engine::{DynParams, step};
use viaticum_sim::sim_dynamic::generator::Archetype;
use viaticum_sim::sim_dynamic::build_world;

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

fn main() {
    let mut args = std::env::args().skip(1);
    let seed: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(0x00E1_5EED);
    let n_nodes: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(200);
    let block_volume: f64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(20.0);
    // 4th arg: reciprocity-aware placement weight (canon §9.5 / эталон §1 main lever).
    // 0.0 = pure-surface baseline; default = the model value. A/B the g_ho-population.
    let recip_weight: f64 = args
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| DynParams::default().recip_weight);

    let params = DynParams {
        block_volume,
        recip_weight,
        ..DynParams::default()
    };
    println!("[recip_weight = {recip_weight}]");
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();

    let mut world = build_world(n_nodes, &params, seed);
    let nn = world.nodes.len();

    // Helper: over all ALIVE symbols, (count, share with reciprocal A=g_ho>0, total
    // alive holdings volume). Tests "does reciprocity BUILD over time or freeze flat?"
    let snapshot = |w: &viaticum_sim::sim_dynamic::generator::World| -> (usize, f64, f64) {
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

    // ~130 ticks (Regime-1 fill + Regime-2 steady) — matches the experiment horizon.
    println!("=== sim_diag time-series (n={nn} block_volume={block_volume}) ===");
    println!(
        "  {:>4}  {:>10} {:>12}  {:>11} {:>11}",
        "tick", "alive syms", "alive vol gb", "share A>0", "evicts cum"
    );
    for t in 0..130u64 {
        step(&mut world, &params, &prior, &policy);
        if (t + 1) % 20 == 0 || t == 9 {
            let (cnt, share, vol) = snapshot(&world);
            println!(
                "  {:>4}  {:>10} {:>12.0}  {:>10.1}% {:>11}",
                t + 1,
                cnt,
                vol,
                share,
                world.eviction_log.len()
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
    // For each owner-archetype, over ALL its alive symbols across the network, count
    // how many sit on a holder of each archetype, and the mean holder φ / base-uptime.
    println!("\n-- (2) WHERE alive symbols live (holder-archetype share per owner-archetype) --");
    for &owner_a in &[Archetype::Reliable, Archetype::Freeloader, Archetype::Hoarder] {
        // Collect (holder_archetype, holder_phi, holder_uptime) for every alive symbol
        // whose OWNER is of archetype owner_a.
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

    // --- (2b) The ACTUAL eviction key: capital[owner][holder].g_ho ("owner served
    // holder") over alive symbol placements, by owner-archetype. This is the value
    // eviction_order ranks owners ASCENDING by — low g_ho should be dropped FIRST.
    // If Freeloader g_ho is NOT the lowest, that explains why it is not evicted.
    // For each alive symbol (O's data on holder h, so B>0 by definition), read BOTH
    // per-pair quantities from the N×N capital matrix:
    //   B = g_oh(O,h) = capital[O][h].g_oh = "h holds O's blocks" (mine at his place)
    //   A = g_ho(O,h) = capital[O][h].g_ho = "O holds h's blocks" (his at my place) = the eviction key
    // Reciprocal pair ⇔ A>0. If the harness tracked an AGGREGATE, A could not vary
    // per (O,h); the per-pair joint below proves it is a genuine N×N matrix.
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
                    let b = world.capital[s.owner][h].g_oh; // h holds O
                    let a = world.capital[s.owner][h].g_ho; // O holds h (eviction key)
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

    // --- (2c) DECISIVE mechanism test: do drops concentrate on g_ho≈0 placements? ---
    // The eviction ranks owners ascending by g_ho, so if the mechanism bites, the
    // DROPPED placements should be far MORE g_ho≈0 than the live population. If drops'
    // share-g_ho>0 ≈ the population's share A>0, the relay is NOT discriminating by
    // reciprocity (it is dropping g_ho>0 and g_ho=0 placements alike — the signal is
    // drowned in the tied-at-zero crowd).
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
        println!(
            "  → drops' share-g_ho>0 MUCH below population ⇒ relay protects reciprocal data (mechanism works, sparsity is the limit)"
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
        // Normalise per node-count so we can compare drop-RATE, not raw (Reliable has
        // 8× more nodes than Freeloader).
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

    // --- (4) NODE-INDEX tie-break artifact check: when g_ho ties (98% at 0), eviction
    // breaks ties by ascending owner node-index. population_mix is block-ordered
    // (Reliable=low indices, Freeloader=high), so if eviction is index-biased the
    // evicted owners cluster at LOW indices regardless of reciprocity. ---
    let evicted_idx: Vec<f64> = world
        .eviction_log
        .iter()
        .filter(|ev| ev.owner < n)
        .map(|ev| ev.owner as f64)
        .collect();
    let all_owner_idx: Vec<f64> = (0..n).map(|i| i as f64).collect();
    println!("\n-- (4) node-index tie-break artifact check --");
    println!(
        "  mean node-index of EVICTED owner = {:.1}   (vs mean of all nodes = {:.1}, n={})",
        mean(&evicted_idx),
        mean(&all_owner_idx),
        n
    );
    let low_half = world
        .eviction_log
        .iter()
        .filter(|ev| ev.owner < n / 2)
        .count();
    println!(
        "  evictions hitting LOW-index half (0..{}) = {:.1}%   (uniform would be ~50%)",
        n / 2,
        100.0 * low_half as f64 / total_ev as f64
    );
}
