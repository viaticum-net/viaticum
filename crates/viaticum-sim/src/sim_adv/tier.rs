//! World-v3 phase-2a — the PER-TIER report (P7 axis 2): "who gets what in the network of
//! givers" as numbers (`4r_p2a_spec.md` §3, spec `4r_world_v3_spec.md` §4 п.7).
//!
//! The giver tier ([`GiverTier`]) is already a god-view attribute on every node (`disk.tier`,
//! assigned by `giver_tier_mix` / re-mixed by [`apply_tier_mix`]). This module (a) lets a scenario
//! OVERRIDE the tier-share distribution ([`TierMix`]), and (b) finalises a god-view PER-TIER table
//! ([`TierReport`]) from the end-of-run world — floor-completeness, durability, share A>0, the
//! give↔get served integrals, and a parked-volume (V_ret) proxy, per tier.
//!
//! ## Evaluator-only (anti-oracle)
//!
//! Everything here is read from the god-view [`World`] in the EVALUATOR role, never fed back into a
//! node decision. [`apply_tier_mix`] only mutates god-view disk/tier fields and draws on a dedicated
//! salted stream (it never touches the engine's per-tick draws), so it is deterministic and does not
//! perturb the honest streams.
//!
//! ## The INV-TIER-GIVERS invariant (frozen BEFORE the run, anti-Goodhart)
//!
//! P7 predicts the rank of what each tier RECEIVES (floor-completeness) tracks the rank of what it
//! can GIVE (free lendable disk): T1 ≥ T2 ≥ T3 ≥ T4. [`TierReport::min_adjacent_giver_gap`] is the
//! single scalar the board reads — the smallest adjacent floor-completeness step; the invariant
//! PASSES iff no adjacent tier drops by more than the frozen `TIER_RANK_MARGIN` (a 5-pp tolerance
//! for multi-seed noise). The sanity floor [`TierReport::t1_floor_completeness`] guards "T1 NAS does
//! not starve". If floor-completeness SATURATES across tiers (all ≈ 1 — every tier places initially
//! in early abundance, and `target_ever_met` is monotone), the rank holds trivially and the real tier
//! gradient lives in the durability / parked / served columns — that is a FINDING to report, not a
//! threshold to tune.

use crate::generator::Rng;
use crate::sim_dynamic::generator::{GiverTier, World};

/// The margin (in floor-completeness units) an adjacent tier may INVERT before INV-TIER-GIVERS
/// fails. FROZEN at 0.05 before the run (anti-Goodhart): the rank T1 ≥ T2 ≥ T3 ≥ T4 holds within a
/// 5-pp tolerance for multi-seed noise; a genuine inversion beyond it is a real FAIL / finding.
pub const TIER_RANK_MARGIN: f64 = 0.05;

/// The four tiers in canonical order (T1..T4) — the report / invariant iteration order.
pub const TIER_ORDER: [GiverTier; 4] = [GiverTier::T1, GiverTier::T2, GiverTier::T3, GiverTier::T4];

/// Canonical tier index (T1→0 .. T4→3) for the report arrays.
pub fn tier_index(t: GiverTier) -> usize {
    match t {
        GiverTier::T1 => 0,
        GiverTier::T2 => 1,
        GiverTier::T3 => 2,
        GiverTier::T4 => 3,
    }
}

/// The scenario's tier-share distribution over its population. [`TierMix::Backbone`] (the default)
/// keeps `build_world`'s canonical 35/30/25/10 tier assignment untouched (byte-identical for every
/// pre-2a scenario); [`TierMix::Custom`] re-mixes the tiers (and re-shapes each node's disk to its
/// new tier) after the world is built.
#[derive(Debug, Clone, PartialEq)]
pub enum TierMix {
    /// Leave `build_world`'s tiers as-is (35/30/25/10). Never runs [`apply_tier_mix`].
    Backbone,
    /// Explicit tier shares (Σ ≈ 1); the last tier absorbs the rounding remainder. The P7 tiered
    /// scenarios use the 15/25/40/20 population guess (`4r_p2a_spec.md` §1) — T3 laptops the
    /// plurality, T1 NAS the minority (a realistic population of would-be givers).
    Custom(Vec<(GiverTier, f64)>),
}

impl TierMix {
    /// Does this mix re-assign tiers (⇒ the runner runs [`apply_tier_mix`])?
    pub fn is_custom(&self) -> bool {
        matches!(self, TierMix::Custom(_))
    }
}

/// Salt for the tier-re-mix SHUFFLE stream (kept off the engine's per-tick draws).
const TIER_REMIX_SHUFFLE_TAG: u64 = 0x71E5_A17A_5EED_71E5;
/// Salt for the per-node disk-shape JITTER when re-tiering (mirrors `build_world`'s ±15% jitter on
/// a dedicated stream — deterministic, and off the engine's streams).
const TIER_REMIX_JITTER_TAG: u64 = 0xD15C_5EED_A17E_71E5;

/// Re-assign every node's giver tier from `shares` and RE-SHAPE its disk (own-data + growth) to the
/// new tier, deterministically in `seed`. Mirrors `build_world`'s disk formula (the physical
/// `disk_cap` is tier-INDEPENDENT and kept; only `own_to_free` / `own_growth` depend on the tier),
/// with a fresh ±15% own:free jitter on a dedicated salted stream. God-view only; draws no engine
/// RNG, so the engine loop stays bit-identical run-to-run. Call AFTER `build_world`, BEFORE the
/// demand-class + uptime layers (they read the final tier).
pub fn apply_tier_mix(world: &mut World, shares: &[(GiverTier, f64)], seed: u64) {
    let n = world.nodes.len();
    let tiers = tier_mix_assign(shares, n, seed);
    for (i, &tier) in tiers.iter().enumerate() {
        let node_id = world.nodes[i].id;
        // Fresh ±15% own:free jitter (mirrors build_world), on a dedicated per-node stream.
        let mut rng = Rng::derive(seed, TIER_REMIX_JITTER_TAG, node_id, 0, 0);
        let ratio_jitter = 1.0 + rng.range(-0.15, 0.15);
        let own_to_free = (tier.own_to_free_centre() * ratio_jitter).max(0.05);
        let disk_cap = world.nodes[i].disk_cap; // tier-independent — keep the built cap
        let own_data = disk_cap * own_to_free / (1.0 + own_to_free);
        world.nodes[i].disk.tier = tier;
        world.nodes[i].disk.own_data = own_data;
        world.nodes[i].disk.own_growth_per_tick = own_data * tier.own_growth_frac_per_tick();
    }
}

/// Build the tier pool from `shares` (last tier absorbs the remainder), then shuffle it
/// deterministically (mirrors `giver_tier_mix` so tier is uncorrelated with the node index /
/// archetype layout). Reproducible in `seed`; its own salted stream.
fn tier_mix_assign(shares: &[(GiverTier, f64)], n: usize, seed: u64) -> Vec<GiverTier> {
    if shares.is_empty() {
        return vec![GiverTier::T1; n];
    }
    let mut pool: Vec<GiverTier> = Vec::with_capacity(n);
    for (t, frac) in shares.iter().take(shares.len() - 1) {
        let count = (frac * n as f64).round() as usize;
        for _ in 0..count {
            pool.push(*t);
        }
    }
    let last = shares[shares.len() - 1].0;
    while pool.len() < n {
        pool.push(last);
    }
    pool.truncate(n);
    let mut rng = Rng::derive(seed, TIER_REMIX_SHUFFLE_TAG, n as u64, 0, 0);
    for i in (1..pool.len()).rev() {
        let j = (rng.unit() * (i as f64 + 1.0)) as usize;
        pool.swap(i, j.min(i));
    }
    pool
}

/// End-of-run per-tier metrics (god-view, evaluator-only). "What the tier RECEIVES" is the P7
/// question; the served integrals also expose what it GIVES so the give↔get rank is visible.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TierMetrics {
    /// All owners assigned to this tier (present or departed) — the lifetime floor-completeness
    /// denominator (robust against long-horizon depopulation; `target_ever_met` is monotone).
    pub n_owners_total: usize,
    /// Present owners of this tier at the horizon (the durability / parked denominator context).
    pub n_owners_present: usize,
    /// Floor-completeness: fraction of the tier's blocks (over ALL owners) that EVER reached floor
    /// (the monotone `target_ever_met` — placement completed to R_target depth). `NaN` if no blocks.
    /// This is the FROZEN board metric (INV-TIER-GIVERS / INV-TIER-T1-ALIVE).
    pub floor_completeness: f64,
    /// NOTE-c diagnostic (NOT a board metric): floor-completeness with the denominator = owners
    /// PRESENT at the horizon (the "stayers"). Discriminates the driver of a low lifetime
    /// `floor_completeness`: if `stayers` ≫ `floor_completeness` the gap is owners who CHURNED OUT
    /// before completing placement; if `stayers` ≈ `floor_completeness` even the survivors do not
    /// complete placement ⇒ the driver is placement DYNAMICS (bandwidth × demand × contention),
    /// not churn. `NaN` if the tier has no present-owner block.
    pub floor_completeness_stayers: f64,
    /// Durability: mean CURRENT alive NON-cream floor holders per block, over PRESENT owners'
    /// blocks (the steady-state retention — settles near k_eff under the eviction economy). `NaN`
    /// if no present-owner block.
    pub durability: f64,
    /// Share A>0: fraction of the tier-OWNED alive symbols (on present holders) whose (owner←holder)
    /// reciprocity `g_ho > 0`, in percent. `NaN` if the tier has no alive owned symbol.
    pub share_a_pos: f64,
    /// Mean INBOUND served-volume integral per PRESENT owner — "what the tier RECEIVES" (the
    /// PoS-confirmed gb·time others retained for its data). `NaN` if no present owner.
    pub mean_inbound_served: f64,
    /// Mean OUTBOUND served-volume integral per PRESENT owner — "what the tier GIVES" (the gb·time
    /// it retained-and-confirmed for others as a holder). `NaN` if no present owner.
    pub mean_outbound_served: f64,
    /// Extraction ratio `inbound / outbound` per tier (received / given). ≈ 1 ⇒ balanced; > 1 ⇒ a
    /// net receiver, < 1 ⇒ a net giver. `NaN` if the tier gave nothing.
    pub extraction: f64,
    /// Mean PARKED alive own-volume (gb) per PRESENT owner: the network storage the tier's data
    /// currently occupies across all holders — the realized V_ret ("what is retained for me").
    /// `NaN` if no present owner.
    pub mean_parked_gb: f64,
}

impl TierMetrics {
    const EMPTY: TierMetrics = TierMetrics {
        n_owners_total: 0,
        n_owners_present: 0,
        floor_completeness: f64::NAN,
        floor_completeness_stayers: f64::NAN,
        durability: f64::NAN,
        share_a_pos: f64::NAN,
        mean_inbound_served: f64::NAN,
        mean_outbound_served: f64::NAN,
        extraction: f64::NAN,
        mean_parked_gb: f64::NAN,
    };
}

/// The per-seed per-tier report (indexed by [`tier_index`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TierReport {
    pub tier: [TierMetrics; 4],
}

impl TierReport {
    /// The T1-NAS floor-completeness — the "the backbone does not starve" sanity scalar.
    pub fn t1_floor_completeness(&self) -> f64 {
        self.tier[tier_index(GiverTier::T1)].floor_completeness
    }

    /// The smallest adjacent floor-completeness STEP (`fc[T_i] − fc[T_{i+1}]`) over the tier rank
    /// — the INV-TIER-GIVERS scalar. ≥ `−TIER_RANK_MARGIN` ⇒ the rank T1 ≥ T2 ≥ T3 ≥ T4 holds
    /// within tolerance. A tier with no block (`NaN` fc) is skipped from the gaps it bounds; if
    /// fewer than two tiers have a finite fc the gap is `NaN` (INCONCLUSIVE at the board).
    pub fn min_adjacent_giver_gap(&self) -> f64 {
        let fc: Vec<f64> = TIER_ORDER
            .iter()
            .map(|&t| self.tier[tier_index(t)].floor_completeness)
            .collect();
        let mut min_gap = f64::INFINITY;
        let mut any = false;
        for i in 0..3 {
            if fc[i].is_finite() && fc[i + 1].is_finite() {
                let gap = fc[i] - fc[i + 1];
                if gap < min_gap {
                    min_gap = gap;
                }
                any = true;
            }
        }
        if any { min_gap } else { f64::NAN }
    }
}

/// Bit-exact equality of two tier reports (the determinism board row). `to_bits` so a
/// deterministically-produced `NaN` compares equal to itself.
pub fn bit_eq(a: &TierReport, b: &TierReport) -> bool {
    a.tier.iter().zip(&b.tier).all(|(x, y)| {
        x.n_owners_total == y.n_owners_total
            && x.n_owners_present == y.n_owners_present
            && x.floor_completeness.to_bits() == y.floor_completeness.to_bits()
            && x.floor_completeness_stayers.to_bits() == y.floor_completeness_stayers.to_bits()
            && x.durability.to_bits() == y.durability.to_bits()
            && x.share_a_pos.to_bits() == y.share_a_pos.to_bits()
            && x.mean_inbound_served.to_bits() == y.mean_inbound_served.to_bits()
            && x.mean_outbound_served.to_bits() == y.mean_outbound_served.to_bits()
            && x.extraction.to_bits() == y.extraction.to_bits()
            && x.mean_parked_gb.to_bits() == y.mean_parked_gb.to_bits()
    })
}

/// Finalise the per-tier report from the end-of-run god-view world (a pure read — every column is
/// an end-of-run fact: `target_ever_met` is monotone, the served matrix is a lifetime integral).
/// Owners injected as predators are excluded (the tiered scenarios have none, but keep it robust).
pub fn tier_report(world: &World) -> TierReport {
    let n = world.nodes.len();

    let mut owners_total = [0usize; 4];
    let mut owners_present = [0usize; 4];
    let mut blocks_at_floor = [0usize; 4];
    let mut blocks_total = [0usize; 4];
    let mut floor_holder_sum = [0usize; 4];
    let mut blocks_present = [0usize; 4];
    let mut blocks_at_floor_present = [0usize; 4];
    let mut inbound_sum = [0.0f64; 4];
    let mut outbound_sum = [0.0f64; 4];
    let mut parked_sum = [0.0f64; 4];
    // share A>0 accumulators (over tier-owned alive symbols on present holders).
    let mut sym_total = [0usize; 4];
    let mut sym_pos = [0usize; 4];

    for o in 0..n {
        if world.adv[o].is_some() {
            continue; // an injected predator is not a giver-tier owner
        }
        let ti = tier_index(world.nodes[o].disk.tier);
        owners_total[ti] += 1;
        // Floor-completeness over ALL owners (lifetime-monotone; robust to depopulation).
        for b in &world.nodes[o].own_blocks {
            blocks_total[ti] += 1;
            if b.target_ever_met {
                blocks_at_floor[ti] += 1;
            }
        }
        if !world.nodes[o].present {
            continue;
        }
        owners_present[ti] += 1;
        // Durability + parked (current alive holders / parked volume) over present owners, plus
        // the NOTE-c stayers floor-completeness (target_ever_met among PRESENT owners' blocks).
        for b in &world.nodes[o].own_blocks {
            blocks_present[ti] += 1;
            if b.target_ever_met {
                blocks_at_floor_present[ti] += 1;
            }
            floor_holder_sum[ti] += block_floor_holders(world, o, b.id);
        }
        parked_sum[ti] += parked_own_volume(world, o);
        // Give↔get lifetime served integrals (row = given, column = received).
        let (inbound, outbound) = served_in_out(world, o);
        inbound_sum[ti] += inbound;
        outbound_sum[ti] += outbound;
    }

    // share A>0: bucket every alive tier-owned symbol on a present holder by the OWNER's tier.
    for h in 0..n {
        if !world.nodes[h].present {
            continue;
        }
        for s in world.nodes[h].holdings.iter().filter(|s| s.alive) {
            if world.adv[s.owner].is_some() {
                continue;
            }
            let ti = tier_index(world.nodes[s.owner].disk.tier);
            sym_total[ti] += 1;
            if world.capital[s.owner][h].g_ho > 1e-12 {
                sym_pos[ti] += 1;
            }
        }
    }

    let mut tier = [TierMetrics::EMPTY; 4];
    for t in 0..4 {
        let inbound = mean(inbound_sum[t], owners_present[t]);
        let outbound = mean(outbound_sum[t], owners_present[t]);
        tier[t] = TierMetrics {
            n_owners_total: owners_total[t],
            n_owners_present: owners_present[t],
            floor_completeness: frac(blocks_at_floor[t], blocks_total[t]),
            floor_completeness_stayers: frac(blocks_at_floor_present[t], blocks_present[t]),
            durability: mean(floor_holder_sum[t] as f64, blocks_present[t]),
            share_a_pos: if sym_total[t] > 0 {
                100.0 * sym_pos[t] as f64 / sym_total[t] as f64
            } else {
                f64::NAN
            },
            mean_inbound_served: inbound,
            mean_outbound_served: outbound,
            extraction: if outbound_sum[t] > 0.0 {
                inbound_sum[t] / outbound_sum[t]
            } else {
                f64::NAN
            },
            mean_parked_gb: mean(parked_sum[t], owners_present[t]),
        };
    }
    TierReport { tier }
}

/// God-view alive NON-cream FLOOR holders of `owner`'s block `block_id` over present holders.
fn block_floor_holders(world: &World, owner: usize, block_id: usize) -> usize {
    world
        .nodes
        .iter()
        .filter(|nd| nd.present)
        .filter(|nd| {
            nd.holdings
                .iter()
                .any(|s| s.alive && !s.cream && s.owner == owner && s.block == block_id)
        })
        .count()
}

/// Total ALIVE parked volume (gb) of `owner`'s OWN data across all present holders (the realized
/// V_ret — the network storage currently retained for this owner).
fn parked_own_volume(world: &World, owner: usize) -> f64 {
    let mut v = 0.0;
    for nd in world.nodes.iter().filter(|nd| nd.present) {
        for s in nd.holdings.iter().filter(|s| s.alive && s.owner == owner) {
            v += s.volume;
        }
    }
    v
}

/// (inbound, outbound) lifetime served integrals for `owner`: inbound = Σ_h served[h][owner] (what
/// owner received), outbound = Σ_h served[owner][h] (what owner gave as a holder).
fn served_in_out(world: &World, owner: usize) -> (f64, f64) {
    let n = world.nodes.len();
    let mut inbound = 0.0;
    let mut outbound = 0.0;
    for h in 0..n {
        inbound += world.served[h][owner];
        outbound += world.served[owner][h];
    }
    (inbound, outbound)
}

/// `num / den` as a fraction, `NaN` for an empty denominator.
fn frac(num: usize, den: usize) -> f64 {
    if den == 0 {
        f64::NAN
    } else {
        num as f64 / den as f64
    }
}

/// `sum / count`, `NaN` for an empty count.
fn mean(sum: f64, count: usize) -> f64 {
    if count == 0 {
        f64::NAN
    } else {
        sum / count as f64
    }
}
