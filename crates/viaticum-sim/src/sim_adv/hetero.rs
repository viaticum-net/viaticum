//! World-v3 heterogeneity v2 (D1 redo): data heterogeneity = the NUMBER of equal blocks
//! an owner backs up, NOT the size of a symbol/block.
//!
//! ## Why this axis (D1 verdict, `4r_substrate_drift_audit.md` §D1)
//!
//! The rejected 0.4 tranche modelled a per-SYMBOL volume (`VolumeClass {5,50,250}gb`), fed
//! that into the off-sample surface penalty, and produced an "archive floor 0%" cliff. That
//! was an ARTIFACT: on the real substrate a symbol is a fixed 64 KB constant — a big archive
//! is simply MORE equal blocks, each with ordinary symbols. So the honest axis is the block
//! COUNT per owner, and the real question is: **does a large footprint (L-class) get all its
//! blocks placed under the credit / reciprocity constraint, or does the mechanic lock it?**
//!
//! ## The demand classes
//!
//! * **S** — 1 block (a tiny footprint).
//! * **M** — `blocks_per_node` blocks (the current default = 3). M IS the honest_v2 owner.
//! * **L** — 10 blocks (a big archive / NAS footprint).
//!
//! ## Byte-identity of the honest anchor (mandatory)
//!
//! [`apply_demand_classes`] rebuilds each owner's footprint from its class. An M owner is
//! left BIT-IDENTICAL to `build_world` (its `source_scale` is exactly `1.0`, and the rebuilt
//! `own_blocks` reproduce `build_world`'s id / volume / ι spread verbatim), so a 100 %-M mix
//! reproduces the seed-42 honest path byte-for-byte (asserted in the tests). The runner only
//! CALLS `apply_demand_classes` for a non-uniform mix; `honest_v2` (Uniform) never touches it.
//!
//! ## Disk / source reconciliation (spec §1: "L = bigger source")
//!
//! An L owner is a bigger data source, so both its physical disk cap and its own-data (source
//! on disk) scale UP with the class (× `source_scale = n_blocks / blocks_per_node`), keeping the
//! tier's own:free ratio — a big NAS genuinely has both more source and proportionally more
//! lendable free disk (the honest T1 shape).
//!
//! The scale only ever GROWS (`max(1.0)`): a SMALL-source owner (S) is NOT shrunk. A tiny source
//! does not mean a tiny DEVICE — an S owner is a normal laptop/NAS with one small folder and
//! plenty of free disk to lend. Shrinking S's disk cap would (wrongly) conflate source size with
//! device size and, because S is the MAJORITY class, would starve the whole holder pool — which
//! is exactly what made a first cut read a false "archive-0 %" (the D1 artifact in another guise).
//! So M and S keep their `build_world` disk; only L grows. (S's own-data still scales down with
//! its footprint below, so a 1-block owner is not carrying an M-sized source.)
//!
//! ## God-view, evaluator-only (anti-oracle)
//!
//! The demand class is a hidden node attribute (like [`Archetype`](crate::sim_dynamic::
//! generator::Archetype) / `GiverTier`): it shapes the world at build time and is read ONLY
//! by the god-view [`HeteroReport`] metrics — never by a kernel decision. The assignment is
//! seeded and INDEPENDENT of the archetype (its own salted RNG stream), so it perturbs no
//! engine draw.

use crate::generator::Rng;
use crate::sim_dynamic::engine::DynParams;
use crate::sim_dynamic::generator::{OwnBlock, World};

/// A per-owner demand class = the NUMBER of equal blocks the owner backs up (the D1 axis).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DemandClass {
    /// A tiny footprint: 1 block.
    S,
    /// The default footprint: `blocks_per_node` blocks (3 at the defaults). M IS honest_v2.
    M,
    /// A big archive / NAS footprint: 10 blocks.
    L,
}

impl DemandClass {
    /// All three, in canonical order (S, M, L) — the class-array index order.
    pub const ALL: [DemandClass; 3] = [DemandClass::S, DemandClass::M, DemandClass::L];

    /// Short label for reports / CSV.
    pub fn label(self) -> &'static str {
        match self {
            DemandClass::S => "S",
            DemandClass::M => "M",
            DemandClass::L => "L",
        }
    }

    /// The class-array index (0..3): S→0, M→1, L→2.
    pub fn index(self) -> usize {
        match self {
            DemandClass::S => 0,
            DemandClass::M => 1,
            DemandClass::L => 2,
        }
    }

    /// The number of equal blocks an owner of this class backs up. **M ties to
    /// `blocks_per_node`** (so an M owner is byte-identical to `build_world` for any
    /// `blocks_per_node`, and the spec's S=1 / M=3 / L=10 holds at the defaults). S=1, L=10
    /// are absolute footprint sizes.
    pub fn n_blocks(self, blocks_per_node: usize) -> usize {
        match self {
            DemandClass::S => 1,
            DemandClass::M => blocks_per_node.max(1),
            DemandClass::L => 10,
        }
    }
}

/// How a hetero owner's DEVICE (disk cap) relates to its source (WARN-2: the two D1 regimes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskPolicy {
    /// LIGHT regime: the device cap GROWS with the source (`× source_scale`, ≥ 1), so a big
    /// archive owner keeps the tier's own:free ratio — its lendable free scales up too. Credit /
    /// reciprocity is then scale-NEUTRAL (a big NAS earns proportionally more κ_O). The honest T1
    /// NAS shape.
    Grow,
    /// HARD regime: the device cap is FIXED at `build_world` size for EVERY class. A big source on
    /// an ORDINARY device eats its OWN disk (own-data × source_scale on an unchanged cap), leaving
    /// little lendable free ⇒ little κ_O ⇒ V_ret stays near V_free — the SHARP D1 credit test (the
    /// P7 T4 "full device"). If the scaled source exceeds the device it is TRUNCATED at the cap
    /// (honest "device too small for its backups" physics — free disk floors at 0; the placement
    /// demand of all n_blocks still exists).
    Fixed,
}

/// The scenario's demand-class distribution over its population.
#[derive(Debug, Clone, PartialEq)]
pub enum DemandMix {
    /// Every owner is M (`blocks_per_node`) — the honest_v2 default. The runner NEVER runs the
    /// hetero layer for this, so the world is byte-identical to the pre-hetero path.
    Uniform,
    /// Explicit class shares (Σ ≈ 1) + the disk policy (light vs hard regime). Deterministic
    /// strided-then-seeded-shuffle assignment (mirrors `giver_tier_mix`), INDEPENDENT of the
    /// archetype. The last class absorbs the rounding remainder so the counts sum to exactly `n`.
    Classes(Vec<(DemandClass, f64)>, DiskPolicy),
}

impl DemandMix {
    /// Is this a real hetero mix (⇒ the runner applies the class layer)?
    pub fn is_hetero(&self) -> bool {
        matches!(self, DemandMix::Classes(..))
    }

    /// The disk policy (irrelevant for `Uniform`, which is never applied — returns `Grow`).
    pub fn disk_policy(&self) -> DiskPolicy {
        match self {
            DemandMix::Classes(_, p) => *p,
            DemandMix::Uniform => DiskPolicy::Grow,
        }
    }

    /// Assign a class to each of `n` nodes, deterministically in `seed`. `Uniform` ⇒ every M
    /// (no RNG drawn). `Classes` ⇒ a share-sized pool, shuffled on a dedicated salted stream.
    pub fn assign(&self, n: usize, seed: u64) -> Vec<DemandClass> {
        match self {
            DemandMix::Uniform => vec![DemandClass::M; n],
            DemandMix::Classes(shares, _) => assign_classes(shares, n, seed),
        }
    }
}

/// Salt for the demand-class assignment RNG (a dedicated stream, kept off the engine's
/// disk / PoS / online / placement / tier draws so class assignment perturbs nothing).
const DEMAND_SHUFFLE_TAG: u64 = 0xDEA1_1C7A_555E_5D17;

/// Build the class pool from the shares (last class absorbs the remainder), then shuffle it
/// deterministically. Mirrors `giver_tier_mix` so the two god-view layers assign the same way.
fn assign_classes(shares: &[(DemandClass, f64)], n: usize, seed: u64) -> Vec<DemandClass> {
    if shares.is_empty() {
        return vec![DemandClass::M; n];
    }
    let mut pool: Vec<DemandClass> = Vec::with_capacity(n);
    for (c, frac) in shares.iter().take(shares.len() - 1) {
        let count = (frac * n as f64).round() as usize;
        for _ in 0..count {
            pool.push(*c);
        }
    }
    let last = shares[shares.len() - 1].0;
    while pool.len() < n {
        pool.push(last);
    }
    pool.truncate(n);
    // Deterministic shuffle so class is uncorrelated with the node index (and thus with the
    // block-ordered archetype layout). Reproducible in the seed; its own salted stream.
    let mut rng = Rng::derive(seed, DEMAND_SHUFFLE_TAG, n as u64, 0, 0);
    for i in (1..pool.len()).rev() {
        let j = (rng.unit() * (i as f64 + 1.0)) as usize;
        pool.swap(i, j.min(i));
    }
    pool
}

/// Rebuild every owner's footprint from its demand class + reconcile its disk with the source,
/// under the given [`DiskPolicy`] (WARN-2: light `Grow` vs hard `Fixed` regime).
///
/// An M owner is left BIT-IDENTICAL to `build_world` (`source_scale = 1.0`, and both regimes leave
/// M untouched). own-data (the source on disk) tracks the footprint in BOTH regimes (L bigger, S
/// smaller). The DEVICE cap differs: `Grow` grows it with the source (`× max(1, source_scale)` —
/// never shrinks the majority S class's device, which would starve the holder pool); `Fixed` keeps
/// the `build_world` cap for every class, and TRUNCATES a source that overflows it at the cap (the
/// "full device" physics — free disk floors at 0). Mutates only god-view fields; draws no RNG.
/// Called after `build_world`, before predator injection (a repurposed predator slot's footprint
/// is then overwritten by the injector).
pub fn apply_demand_classes(
    world: &mut World,
    classes: &[DemandClass],
    params: &DynParams,
    disk: DiskPolicy,
) {
    let bpn = params.blocks_per_node.max(1);
    for (i, &class) in classes.iter().enumerate() {
        if i >= world.nodes.len() {
            break;
        }
        let n_blocks = class.n_blocks(bpn);
        // Footprint relative to the M baseline. M ⇒ exactly 1.0 (byte-identical).
        let source_scale = n_blocks as f64 / bpn as f64;
        // Rebuild own_blocks: `n_blocks` equal blocks, the SAME id / volume / ι-spread formula
        // `build_world` uses (so an M owner reproduces its blocks verbatim).
        let mut blocks = Vec::with_capacity(n_blocks);
        for b in 0..n_blocks {
            blocks.push(OwnBlock {
                id: b,
                volume: params.block_volume,
                iota: 0.2 + 0.6 * (b as f64) / (n_blocks.max(2) - 1) as f64,
                placements: Vec::new(),
                target_ever_met: false,
                target_deficit_since: None,
                to_restore: false,
            });
        }
        world.nodes[i].own_blocks = blocks;
        world.next_block_id[i] = n_blocks;
        // Device cap: grow with the source (light) or keep it fixed (hard).
        let disk_scale = match disk {
            DiskPolicy::Grow => source_scale.max(1.0),
            DiskPolicy::Fixed => 1.0,
        };
        world.nodes[i].disk_cap *= disk_scale;
        // own-data tracks the source in BOTH regimes; in `Fixed`, TRUNCATE at the (unchanged)
        // device cap when the big source overflows it (the "full device" physics — a source too
        // big for its disk; free disk then floors at 0 and the node lends nothing → no κ_O).
        let scaled_own = world.nodes[i].disk.own_data * source_scale;
        world.nodes[i].disk.own_data = scaled_own.min(world.nodes[i].disk_cap);
        world.nodes[i].disk.own_growth_per_tick *= source_scale;
    }
}

/// Sample the placement curve every this many ticks (plus the horizon-end tick lands on a
/// multiple at the standard horizons). Small enough to see the L-footprint fill.
pub const HETERO_SAMPLE_EVERY: u64 = 10;

/// One tick's god-view sample of the per-class placement progress (the L-curve rows).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HeteroSample {
    /// The tick this sample was taken at (post-step).
    pub tick: u64,
    /// Per-class MEAN footprint-placed fraction over the class's present owners: an owner's
    /// (blocks at floor) / (its n_blocks). `NaN` for a class with no present owner.
    pub placed_frac: [f64; 3],
    /// Per-class count of present owners whose ENTIRE footprint is at floor this tick.
    pub n_full: [usize; 3],
}

/// End-of-run per-class metrics (god-view, evaluator-only).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClassMetrics {
    /// Present owners of the class (the denominator of the per-owner fractions).
    pub n_owners_present: usize,
    /// Floor-completeness: fraction of the class's blocks (over present owners) that EVER
    /// reached floor (the monotonic `target_ever_met` — placement completed to R_target depth).
    /// This is placement SUCCESS, not steady-state retention. `NaN` if no blocks.
    ///
    /// (WARN-1: this equals the per-owner mean of `blocks_at_floor / n_blocks` EXACTLY — every
    /// owner in a class carries the SAME constant `n_blocks`, so the block-weighted fraction and
    /// the owner-weighted mean coincide. So there is no separate `footprint_placed_frac` field —
    /// it would be a duplicate column. The `curve.placed_frac` time-series is the per-tick view
    /// of this same quantity.)
    pub floor_completeness: f64,
    /// Mean CURRENT alive floor-holders per block (the steady-state retention diagnostic — it
    /// settles near k_eff under the eviction economy, so it is much smaller than `n_symbols`).
    /// The "placed-then-shed" signal: high `floor_completeness` with low `mean_floor_holders`
    /// means blocks reached floor once but eviction thinned them back toward k_eff.
    pub mean_floor_holders: f64,
    /// Share A>0: fraction of the class-OWNED alive symbols (on present holders) whose
    /// (owner←holder) reciprocity `g_ho > 0`. `NaN` if the class placed nothing.
    pub share_a_pos: f64,
    /// Mean tick at which an owner FIRST had its ENTIRE footprint at floor, over the class's
    /// owners that ever reached it. `NaN` if none did (the starvation signal).
    pub mean_tick_full: f64,
    /// Present owners of the class that NEVER reached a full footprint by the horizon.
    pub n_never_full: usize,
}

impl ClassMetrics {
    const EMPTY: ClassMetrics = ClassMetrics {
        n_owners_present: 0,
        floor_completeness: f64::NAN,
        mean_floor_holders: f64::NAN,
        share_a_pos: f64::NAN,
        mean_tick_full: f64::NAN,
        n_never_full: 0,
    };
}

/// The per-seed hetero report: per-class end metrics + the placement curve (the L-curve).
#[derive(Debug, Clone, PartialEq)]
pub struct HeteroReport {
    /// The demand-class share footprint sizes `n_blocks` per class (S, M, L), for the header.
    pub n_blocks: [usize; 3],
    /// Total assigned owners per class (S, M, L).
    pub assigned: [usize; 3],
    /// Per-class end-of-run metrics (indexed by [`DemandClass::index`]).
    pub class: [ClassMetrics; 3],
    /// The placement curve (sampled every [`HETERO_SAMPLE_EVERY`] ticks) — the L-class
    /// "parked vs tick" evidence in the report.
    pub curve: Vec<HeteroSample>,
}

impl HeteroReport {
    /// The flagship no-starvation scalar: the L-class floor-completeness (fraction of the big
    /// footprint that reached floor). `NaN` if there is no present L owner.
    pub fn l_floor_completeness(&self) -> f64 {
        self.class[DemandClass::L.index()].floor_completeness
    }
}

/// Bit-exact equality of two hetero reports (the determinism board row). `to_bits` so a
/// deterministically-produced `NaN` compares equal to itself.
pub fn bit_eq(a: &HeteroReport, b: &HeteroReport) -> bool {
    a.n_blocks == b.n_blocks
        && a.assigned == b.assigned
        && a.class
            .iter()
            .zip(&b.class)
            .all(|(x, y)| class_bit_eq(x, y))
        && a.curve.len() == b.curve.len()
        && a.curve.iter().zip(&b.curve).all(|(x, y)| {
            x.tick == y.tick
                && x.n_full == y.n_full
                && x.placed_frac
                    .iter()
                    .zip(&y.placed_frac)
                    .all(|(p, q)| p.to_bits() == q.to_bits())
        })
}

fn class_bit_eq(a: &ClassMetrics, b: &ClassMetrics) -> bool {
    a.n_owners_present == b.n_owners_present
        && a.n_never_full == b.n_never_full
        && a.floor_completeness.to_bits() == b.floor_completeness.to_bits()
        && a.mean_floor_holders.to_bits() == b.mean_floor_holders.to_bits()
        && a.share_a_pos.to_bits() == b.share_a_pos.to_bits()
        && a.mean_tick_full.to_bits() == b.mean_tick_full.to_bits()
}

/// Accumulates the hetero placement metrics across a run: samples the per-class curve and
/// records each owner's first full-footprint tick, then finalises into a [`HeteroReport`].
pub struct HeteroTracker {
    classes: Vec<DemandClass>,
    blocks_per_node: usize,
    /// The tick each owner FIRST had its whole footprint placed to floor (`None` until then).
    first_full: Vec<Option<u64>>,
    curve: Vec<HeteroSample>,
}

impl HeteroTracker {
    /// A fresh tracker for one seed. Reads `blocks_per_node` from the dials (for the footprint
    /// header).
    pub fn new(classes: &[DemandClass], params: &DynParams) -> Self {
        HeteroTracker {
            classes: classes.to_vec(),
            blocks_per_node: params.blocks_per_node.max(1),
            first_full: vec![None; classes.len()],
            curve: Vec::new(),
        }
    }

    /// Observe the world after a `step` (at `world.tick`): update each owner's first-full tick,
    /// and record a curve sample on every [`HETERO_SAMPLE_EVERY`]th tick.
    pub fn observe(&mut self, world: &World) {
        let tick = world.tick;
        // First-full detection for every present, non-adversary owner.
        for i in 0..self.classes.len() {
            if self.first_full[i].is_some() {
                continue;
            }
            if !owner_active(world, i) {
                continue;
            }
            if footprint_fully_placed(world, i) {
                self.first_full[i] = Some(tick);
            }
        }
        if tick.is_multiple_of(HETERO_SAMPLE_EVERY) {
            self.curve.push(self.sample(world));
        }
    }

    /// One curve sample: per-class mean placed-fraction + full-footprint count.
    fn sample(&self, world: &World) -> HeteroSample {
        let mut sum = [0.0f64; 3];
        let mut cnt = [0usize; 3];
        let mut n_full = [0usize; 3];
        for i in 0..self.classes.len() {
            if !owner_active(world, i) {
                continue;
            }
            let ci = self.classes[i].index();
            let (placed, total) = footprint_progress(world, i);
            if total > 0 {
                sum[ci] += placed as f64 / total as f64;
                cnt[ci] += 1;
                if placed == total {
                    n_full[ci] += 1;
                }
            }
        }
        let mut placed_frac = [f64::NAN; 3];
        for c in 0..3 {
            if cnt[c] > 0 {
                placed_frac[c] = sum[c] / cnt[c] as f64;
            }
        }
        HeteroSample {
            tick: world.tick,
            placed_frac,
            n_full,
        }
    }

    /// Finalise into a [`HeteroReport`] from the end-of-run world.
    pub fn finalize(self, world: &World) -> HeteroReport {
        let mut assigned = [0usize; 3];
        for &c in &self.classes {
            assigned[c.index()] += 1;
        }
        let n_blocks = [
            DemandClass::S.n_blocks(self.blocks_per_node),
            DemandClass::M.n_blocks(self.blocks_per_node),
            DemandClass::L.n_blocks(self.blocks_per_node),
        ];

        // Per-class accumulators.
        let mut owners_present = [0usize; 3];
        let mut blocks_at_floor = [0usize; 3];
        let mut blocks_total = [0usize; 3];
        let mut floor_holder_sum = [0usize; 3];
        let mut tick_full_sum = [0.0f64; 3];
        let mut tick_full_cnt = [0usize; 3];
        let mut never_full = [0usize; 3];
        // share A>0 per class (over class-owned alive symbols on present holders).
        let mut sym_total = [0usize; 3];
        let mut sym_pos = [0usize; 3];

        for i in 0..self.classes.len() {
            if !owner_active(world, i) {
                continue;
            }
            let ci = self.classes[i].index();
            owners_present[ci] += 1;
            for b in &world.nodes[i].own_blocks {
                floor_holder_sum[ci] += block_floor_holders(world, i, b.id);
                blocks_total[ci] += 1;
                if b.target_ever_met {
                    blocks_at_floor[ci] += 1;
                }
            }
            match self.first_full[i] {
                Some(t) => {
                    tick_full_sum[ci] += t as f64;
                    tick_full_cnt[ci] += 1;
                }
                None => never_full[ci] += 1,
            }
        }

        // share A>0: bucket every alive class-owned symbol on a present holder by owner class.
        for h in 0..world.nodes.len() {
            if !world.nodes[h].present {
                continue;
            }
            for s in world.nodes[h].holdings.iter().filter(|s| s.alive) {
                if world.adv[s.owner].is_some() || s.owner >= self.classes.len() {
                    continue;
                }
                let ci = self.classes[s.owner].index();
                sym_total[ci] += 1;
                if world.capital[s.owner][h].g_ho > 1e-12 {
                    sym_pos[ci] += 1;
                }
            }
        }

        let mut class = [ClassMetrics::EMPTY; 3];
        for c in 0..3 {
            let np = owners_present[c];
            class[c] = ClassMetrics {
                n_owners_present: np,
                floor_completeness: frac(blocks_at_floor[c], blocks_total[c]),
                mean_floor_holders: mean(floor_holder_sum[c] as f64, blocks_total[c]),
                share_a_pos: if sym_total[c] > 0 {
                    100.0 * sym_pos[c] as f64 / sym_total[c] as f64
                } else {
                    f64::NAN
                },
                mean_tick_full: mean(tick_full_sum[c], tick_full_cnt[c]),
                n_never_full: never_full[c],
            };
        }

        HeteroReport {
            n_blocks,
            assigned,
            class,
            curve: self.curve,
        }
    }
}

/// An owner counts for the hetero metrics iff it is present and NOT an injected predator.
fn owner_active(world: &World, i: usize) -> bool {
    world.nodes[i].present && world.adv[i].is_none()
}

/// God-view alive FLOOR holders of `owner`'s block `block_id` (≤ 1 symbol per holder per
/// block by the §7 spread, so this is the distinct-live-floor-holder count).
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

/// (blocks of `owner` that reached target, total own blocks). The predicate is the block's
/// monotonic `target_ever_met` flag — its estimated survival R̂ EVER reached `r_target`.
/// **Post-SIM-UNIFICATION this is NOT the old `n_symbols` floor** (the R̂ loop stops as soon as
/// the target is met, typically at 3-4 holders where the floor asked for 5), so the predicate is
/// strictly LIGHTER than the one this read used to carry — the established denominator grew
/// 55 → 67 across the tranche. This is PLACEMENT SUCCESS (the D1 question "does the footprint get
/// placed"), NOT the current-alive holder count, which under the steady-state eviction economy
/// settles near k_eff for EVERY class (honest_v2's own durability is ~1 holder/block — so a
/// current-count threshold would read every class, INCLUDING the honest M baseline, as ~0).
fn footprint_progress(world: &World, owner: usize) -> (usize, usize) {
    let total = world.nodes[owner].own_blocks.len();
    let placed = world.nodes[owner]
        .own_blocks
        .iter()
        .filter(|b| b.target_ever_met)
        .count();
    (placed, total)
}

/// Is `owner`'s ENTIRE footprint placed (every own block reached floor at least once)?
fn footprint_fully_placed(world: &World, owner: usize) -> bool {
    let (placed, total) = footprint_progress(world, owner);
    total > 0 && placed == total
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
