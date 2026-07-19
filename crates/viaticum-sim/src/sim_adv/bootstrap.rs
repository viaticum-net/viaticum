//! Bootstrap-focus measurement (Р-9 V_free sweep): a NEWCOMER's onboarding under
//! contention — the key missing measurement the V_free dial is supposed to serve
//! ("the newcomer's first backup survives").
//!
//! This is a pure GOD-VIEW evaluator over a FINISHED world — NO new physics. It reads the
//! engine's already-existing newcomer-entry trace ([`World::first_earned_g`] /
//! [`World::first_own_accept`] / [`Node::joined_tick`]) plus each newcomer's first block's
//! [`OwnBlock::floor_ever_met`] and its horizon floor-holder count, restricted to the
//! LATE-joining cohort (nodes that entered an ALREADY-established world — the real
//! "newcomer into a running network", not a t=0 bootstrap node).
//!
//! The V_free question it answers: does the free retention floor let a newcomer's first
//! backup survive under contention? The Р-9 rationale (ledger) is that V_free is only a
//! RETENTION floor — entry (getting ADMITTED) is κ-gated by preemption — so a newcomer with
//! κ_O = 0 may fail to place at all regardless of V_free. This measures which way it points.

use crate::sim_dynamic::build_world;
use crate::sim_dynamic::engine::{DynParams, step};
use crate::sim_dynamic::generator::{Archetype, World};

use viaticum_core::four_r::{PlacementPolicy, SurfacePrior};

/// Aggregate newcomer-onboarding stats over the LATE-joining cooperative cohort of one
/// finished world. All fields are god-view reads; none is ever fed into a node decision.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BootstrapStats {
    /// Newcomers in the cohort: PRESENT-at-horizon cooperative nodes (Reliable / Weekend /
    /// Seasonal / Nomad — the honest audience, not the Hoarder / Freeloader parasites) whose
    /// `joined_tick >= join_threshold`.
    pub n_newcomers: usize,
    /// Fraction of newcomers whose FIRST own block (smallest block id — eligible the moment
    /// they joined) EVER reached its `n_symbols` floor ([`OwnBlock::floor_ever_met`]). The
    /// "did the first backup ever succeed" headline.
    pub first_block_floor_ever: f64,
    /// Mean ticks from join to first EARNED reciprocity (`g_ho > 0` with some peer — it served
    /// someone and passed PoS). The "sing for your supper" latency. `NaN` if none ever earned.
    pub mean_time_to_first_g: f64,
    /// Mean ticks from join to first OWN symbol accepted by any holder
    /// ([`World::first_own_accept`]). `NaN` if none ever placed.
    pub mean_time_to_first_accept: f64,
    /// Fraction of newcomers that EVER placed any own symbol (`first_own_accept.is_some()`).
    pub frac_ever_placed: f64,
    /// Mean settled ALIVE FLOOR holders (non-cream) of each newcomer's FIRST block at the
    /// horizon — the durability of its onboarding backup. 0 for a never-placed / trimmed block.
    pub mean_first_block_parked_holders: f64,
    /// Fraction of newcomers whose first block sits at ZERO live floor holders at the horizon
    /// (its onboarding backup is GONE — parked@horizon lost). The clearest "V_free failed the
    /// newcomer" signal.
    pub frac_first_block_lost: f64,
}

impl BootstrapStats {
    /// The empty read (no newcomers in the cohort) — every rate is `NaN` (undefined, not 0).
    fn empty() -> Self {
        BootstrapStats {
            n_newcomers: 0,
            first_block_floor_ever: f64::NAN,
            mean_time_to_first_g: f64::NAN,
            mean_time_to_first_accept: f64::NAN,
            frac_ever_placed: f64::NAN,
            mean_first_block_parked_holders: f64::NAN,
            frac_first_block_lost: f64::NAN,
        }
    }
}

/// Is this a cooperative (honest-audience) archetype — the newcomer we care about onboarding?
/// Hoarder / Freeloader are the parasites the Sybil price is meant to keep out, not the
/// newcomers V_free is meant to welcome, so they are excluded from the cohort.
fn is_cooperative(a: Archetype) -> bool {
    matches!(
        a,
        Archetype::Reliable | Archetype::Weekend | Archetype::Seasonal | Archetype::Nomad
    )
}

/// Count the newcomer's first block's ALIVE FLOOR (non-cream) holders at the horizon — the
/// god-view durability of its onboarding backup.
fn first_block_alive_floor_holders(world: &World, owner: usize, block_id: usize) -> usize {
    world
        .nodes
        .iter()
        .filter(|nd| nd.present)
        .map(|nd| {
            nd.holdings
                .iter()
                .filter(|s| s.alive && !s.cream && s.owner == owner && s.block == block_id)
                .count()
        })
        .sum()
}

/// Collect the newcomer-onboarding stats over the late-joining cooperative cohort of a
/// FINISHED world. `join_threshold` selects "late" joiners (`joined_tick >= join_threshold`)
/// — the newcomers entering an already-established network. Pure god-view; no mutation.
///
/// Cohort caveat (review W2): the cohort is PRESENT-AT-HORIZON — late joiners who churned
/// out before the horizon drop out of the denominator, so `frac_first_block_lost` is biased
/// OPTIMISTIC for high-churn archetypes (Nomad churns most AND has the frailest blocks).
/// A departed newcomer is also not the same thing as a dead backup (its symbols may outlive
/// it on holders). Read the table as "of those who stayed", not "of those who tried".
pub fn collect_bootstrap(world: &World, join_threshold: u64) -> BootstrapStats {
    let newcomers: Vec<usize> = (0..world.nodes.len())
        .filter(|&i| {
            world.nodes[i].present
                && world.nodes[i].joined_tick >= join_threshold
                && is_cooperative(world.nodes[i].archetype)
        })
        .collect();

    if newcomers.is_empty() {
        return BootstrapStats::empty();
    }
    let n = newcomers.len();

    let mut floor_ever = 0usize;
    let mut earn_gaps: Vec<f64> = Vec::new();
    let mut accept_gaps: Vec<f64> = Vec::new();
    let mut ever_placed = 0usize;
    let mut parked_holders_sum = 0usize;
    let mut first_block_lost = 0usize;

    for &i in &newcomers {
        let joined = world.nodes[i].joined_tick;
        // The FIRST block = the smallest block id (eligible the moment the node joined). A
        // late-joiner that never repaired still carries it (floor_ever_met persists on it).
        let first_block = world.nodes[i].own_blocks.iter().min_by_key(|b| b.id);
        if let Some(b) = first_block {
            if b.floor_ever_met {
                floor_ever += 1;
            }
            let held = first_block_alive_floor_holders(world, i, b.id);
            parked_holders_sum += held;
            if held == 0 {
                first_block_lost += 1;
            }
        } else {
            // No own block at all ⇒ its backup is trivially "lost" (it never had one to place).
            first_block_lost += 1;
        }

        if let Some(e) = world.first_earned_g[i] {
            earn_gaps.push(e.saturating_sub(joined) as f64);
        }
        if let Some(o) = world.first_own_accept[i] {
            ever_placed += 1;
            accept_gaps.push(o.saturating_sub(joined) as f64);
        }
    }

    let mean = |xs: &[f64]| {
        if xs.is_empty() {
            f64::NAN
        } else {
            xs.iter().sum::<f64>() / xs.len() as f64
        }
    };

    BootstrapStats {
        n_newcomers: n,
        first_block_floor_ever: floor_ever as f64 / n as f64,
        mean_time_to_first_g: mean(&earn_gaps),
        mean_time_to_first_accept: mean(&accept_gaps),
        frac_ever_placed: ever_placed as f64 / n as f64,
        mean_first_block_parked_holders: parked_holders_sum as f64 / n as f64,
        frac_first_block_lost: first_block_lost as f64 / n as f64,
    }
}

/// Run one seeded honest world to `horizon` and collect its newcomer-onboarding stats. Reuses
/// `build_world` + `step` UNCHANGED (the same engine `sim_diag` drives — no new physics), so
/// the only thing this adds is the god-view read at the end. `params` carries the V_free dial
/// (and any contention knob such as `disk_cap_base`) the caller wants to measure.
pub fn run_bootstrap(
    params: &DynParams,
    n_nodes: usize,
    horizon: u64,
    seed: u64,
    join_threshold: u64,
) -> BootstrapStats {
    let prior = SurfacePrior::default();
    let policy = PlacementPolicy::default();
    let mut world = build_world(n_nodes, params, seed);
    for _ in 0..horizon {
        step(&mut world, params, &prior, &policy);
    }
    collect_bootstrap(&world, join_threshold)
}

/// Mean over seeds of a `BootstrapStats` field, skipping `NaN` (an empty-cohort seed). Shared
/// by the report so the multi-seed bootstrap table reads a single mean per cell.
pub fn mean_over_seeds(stats: &[BootstrapStats], f: impl Fn(&BootstrapStats) -> f64) -> f64 {
    let v: Vec<f64> = stats.iter().map(f).filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        f64::NAN
    } else {
        v.iter().sum::<f64>() / v.len() as f64
    }
}
