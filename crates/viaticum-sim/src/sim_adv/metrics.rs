//! God-view metric collection (design `4r_world_v3_detail.md` §3).
//!
//! All metrics are read from the god-view [`World`] in the evaluator role — NEVER fed
//! back into a node decision. The scalar/durability readers here replicate `sim_diag`'s
//! sections (6a) share-A>0, (6f) mean loyalty depth D, (6g) mean suspicion σ, (5) floor
//! durability, plus the eviction/preemption/cap-trim counters — so `honest_v2`'s
//! seed-42 numbers match `sim_diag 42 100 50 1 v2` byte-for-byte (the regression anchor).
//!
//! The extraction-ratio (design §3.2) is the real non-inflation signal (spec §10 п.17):
//! per archetype, `Σ consumed / Σ served_out` over the `served` gb·time integral.

use crate::sim_dynamic::engine::DynParams;
use crate::sim_dynamic::generator::{Archetype, World};

/// One seed's god-view snapshot at the run horizon.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricSet {
    /// Alive symbols over present holders (the share-A>0 denominator).
    pub alive_symbols: usize,
    /// Present node count at the horizon.
    pub present_nodes: usize,
    /// Share of alive symbols whose (owner←holder) reciprocity `g_ho > 0`, in percent
    /// (sim_diag 6a).
    pub share_a_pos: f64,
    /// Total eviction events over the run (`world.eviction_log.len()`).
    pub evicts: usize,
    /// Preemptive-swap count (`world.preempt_count`).
    pub preempts: usize,
    /// Р-7 holder-side volume-cap trims (`world.cap_trim_count`).
    pub cap_trims: usize,
    /// Mean loyalty depth D over alive pairs (sim_diag 6f), gb·days.
    pub mean_depth: f64,
    /// Mean suspicion σ over alive pairs (sim_diag 6g).
    pub mean_sigma: f64,
    /// Per-archetype floor durability = mean alive NON-cream holders per own block
    /// (sim_diag 5). Indexed by [`Archetype::ALL`] position; `NaN` if the archetype has
    /// no present-owner blocks.
    pub durability: [f64; 6],
    /// Per-archetype extraction ratio = `Σ consumed / Σ served_out` over the archetype's
    /// nodes (design §3.2). Indexed by [`Archetype::ALL`] position; `NaN` if the
    /// archetype gave nothing (served_out == 0).
    pub extraction_roi: [f64; 6],
    /// SIM-UNIFICATION §4: the DECODABILITY fraction — of the target-ever-met blocks of
    /// present owners, the share that still holds ≥ `k_eff` alive symbols, CREAM INCLUDED
    /// ([`block_decodable_fraction`]). The honest restorability cross-check to the non-cream
    /// floor-fill proxy. `NaN` when no present owner has a target-ever-met block.
    pub decodable_fraction: f64,
    /// SIM-UNIFICATION §4: the TAIL — how many target-ever-met blocks of present owners are
    /// BELOW `k_eff` alive symbols (cream included), i.e. currently UNDECODABLE.
    pub undecodable_blocks: usize,
}

/// Collect every 0.1 metric from a run's final god-view world. Pure read — no mutation,
/// no RNG, no feedback into any decision (evaluator discipline). `params` is read for the
/// dial-dependent cuts (SIM-UNIFICATION: `k_eff` for the decodability read).
pub fn collect_metrics(world: &World, params: &DynParams) -> MetricSet {
    let n = world.nodes.len();

    // --- share A>0, mean D, mean σ over alive pairs on present holders (6a/6f/6g) ---
    let mut alive_symbols = 0usize;
    let mut depth_sum = 0.0f64;
    let mut sigma_sum = 0.0f64;
    for h in 0..n {
        if !world.nodes[h].present {
            continue;
        }
        for s in world.nodes[h].holdings.iter().filter(|s| s.alive) {
            alive_symbols += 1;
            let cap = &world.capital[s.owner][h];
            depth_sum += cap.depth_ho;
            sigma_sum += cap.sigma;
        }
    }
    // Single source of truth (P8): the SAME reader the per-tick reciprocity trajectory samples,
    // so the trajectory's last point and this horizon snapshot can never drift apart.
    let share_a_pos = share_a_pos_percent(world);
    let mean_depth = if alive_symbols > 0 {
        depth_sum / alive_symbols as f64
    } else {
        f64::NAN
    };
    let mean_sigma = if alive_symbols > 0 {
        sigma_sum / alive_symbols as f64
    } else {
        f64::NAN
    };

    let present_nodes = world.nodes.iter().filter(|nd| nd.present).count();

    // --- per-archetype floor durability (sim_diag section 5) ---
    let mut durability = [f64::NAN; 6];
    for (ai, &arch) in Archetype::ALL.iter().enumerate() {
        let mut sum = 0usize;
        let mut blocks = 0usize;
        for o in 0..n {
            if !world.nodes[o].present || world.nodes[o].archetype != arch {
                continue;
            }
            for b in &world.nodes[o].own_blocks {
                let alive = (0..n)
                    .filter(|&h| {
                        world.nodes[h].present
                            && world.nodes[h]
                                .holdings
                                .iter()
                                .any(|s| s.alive && !s.cream && s.owner == o && s.block == b.id)
                    })
                    .count();
                sum += alive;
                blocks += 1;
            }
        }
        if blocks > 0 {
            durability[ai] = sum as f64 / blocks as f64;
        }
    }

    // --- per-archetype extraction ratio Σconsumed/Σserved_out (design §3.2) ---
    // served[holder][owner] = gb·time the OWNER received at that HOLDER (a PoS-confirmed
    // retained integral). consumed(O) = column O sum (what O received for its own data);
    // served_out(O) = row O sum (what O gave others as a holder). Lifetime integral, so
    // departed nodes still count — archetype persists on the node.
    let mut extraction_roi = [f64::NAN; 6];
    for (ai, &arch) in Archetype::ALL.iter().enumerate() {
        let mut consumed = 0.0f64;
        let mut served_out = 0.0f64;
        for o in 0..n {
            if world.nodes[o].archetype != arch {
                continue;
            }
            for h in 0..n {
                consumed += world.served[h][o];
                served_out += world.served[o][h];
            }
        }
        if served_out > 0.0 {
            extraction_roi[ai] = consumed / served_out;
        }
    }

    // --- SIM-UNIFICATION §4: decodability (alive TOTAL incl. cream ≥ k_eff) ---
    let decodable = block_decodable_fraction(world, params.k_eff);

    MetricSet {
        alive_symbols,
        present_nodes,
        share_a_pos,
        evicts: world.eviction_log.len(),
        preempts: world.preempt_count,
        cap_trims: world.cap_trim_count,
        mean_depth,
        mean_sigma,
        durability,
        extraction_roi,
        decodable_fraction: decodable.fraction,
        undecodable_blocks: decodable.below_k_eff,
    }
}

/// The share-A>0 god-view read (sim_diag §6a), **IN PERCENT**: of the alive symbols sitting on
/// PRESENT holders, the share whose pair carries RECIPROCITY — the owner has itself served that
/// holder, so the holder's own books hold `g_ho > 0` for it.
///
/// **The capital index, derived from the accrual site (`engine::pos_and_capital`), NOT from prose.**
/// When holder `h` passes a PoS challenge for owner `o` the engine writes BOTH mirror cells:
/// `capital[o][h].g_oh += a` (the owner's forecast of that holder) and `capital[h][o].g_ho += a`
/// (the holder's own record of the storage it performed). So `capital[X][Y].g_ho` reads "X served
/// Y". This function's `capital[s.owner][h].g_ho` therefore asks "has the OWNER served this
/// HOLDER" — which is exactly the key the holder's own eviction / preemption / retention rank
/// reads (`run_eviction` builds its view from `&world.capital[owner_idx][holder]`), i.e. exactly
/// the A>0 reciprocity a symbol's survival depends on.
///
/// `0.0` on an empty world (no alive symbols) — the pre-existing convention, kept verbatim so the
/// `honest_v2` anchor does not move. Pure evaluator read: never fed into a node decision.
pub fn share_a_pos_percent(world: &World) -> f64 {
    let n = world.nodes.len();
    let mut alive_symbols = 0usize;
    let mut a_pos = 0usize;
    for h in 0..n {
        if !world.nodes[h].present {
            continue;
        }
        for s in world.nodes[h].holdings.iter().filter(|s| s.alive) {
            alive_symbols += 1;
            if world.capital[s.owner][h].g_ho > 1e-12 {
                a_pos += 1;
            }
        }
    }
    if alive_symbols > 0 {
        100.0 * a_pos as f64 / alive_symbols as f64
    } else {
        0.0
    }
}

/// SIM-UNIFICATION §4 (closes the A10 review-B1 gap): block DECODABILITY — the god-view
/// EVALUATOR read of "could the owner still reconstruct this block", as opposed to "how much
/// of the placed floor do holders retain".
///
/// Over the TARGET-EVER-MET own blocks of PRESENT owners (the "data that was once durable"
/// denominator every other evaluator read uses), counts the blocks whose TOTAL alive symbols
/// on present holders reach `k_eff` — **CREAM INCLUDED**: RaptorQ decodes from ANY `k_eff`
/// symbols, so the floor/cream label (a placement-budget distinction) is irrelevant to
/// restorability. Returns the fraction AND the TAIL count of blocks below `k_eff` (one scan,
/// so the two can never drift apart).
///
/// Relation to the other reads: [`overall_floor_durability`] is a conservative non-cream
/// FILL proxy (its scale is "how full is the 5-symbol floor", ≈ 0.34 at steady state);
/// `restore::RestoreTruth` measures collectability in a post-Disaster window under uptime +
/// bandwidth. THIS one is the cheap end-of-run "is there a silent undecodable tail" read
/// that needs no disaster. Pure god-view; never an input to any decision.
///
/// `to_restore` (source-less disaster-victim) blocks are deliberately INCLUDED — for a DR
/// read "can it still be reconstructed from holders" is exactly the question for them; do
/// not "fix" this by filtering them out.
///
/// `k_eff == 0` ⇒ every block is vacuously decodable (fraction 1.0, no tail).
pub fn block_decodable_fraction(world: &World, k_eff: usize) -> Decodability {
    let n = world.nodes.len();
    let mut blocks = 0usize;
    let mut decodable = 0usize;
    for o in 0..n {
        if !world.nodes[o].present {
            continue;
        }
        for b in &world.nodes[o].own_blocks {
            if !b.target_ever_met {
                continue;
            }
            blocks += 1;
            if alive_symbols(world, o, b.id) >= k_eff {
                decodable += 1;
            }
        }
    }
    Decodability {
        fraction: if blocks > 0 {
            decodable as f64 / blocks as f64
        } else {
            f64::NAN
        },
        below_k_eff: blocks - decodable,
        blocks,
    }
}

/// The alive symbols of ONE block on PRESENT holders — **CREAM INCLUDED**, because erasure
/// decode does not know the floor/cream label. THE decodability primitive: every "is this
/// block still reconstructible" read ([`block_decodable_fraction`],
/// [`newcomer_decodable_fraction`], and the A9 eclipse's lethal predicate + kill attribution in
/// `sim_dynamic::engine::adv_eclipse_drops`) counts through here, so they can never drift apart.
/// (The non-cream FILL reads — [`overall_floor_durability`] and `collect_metrics`'s
/// `durability` — deliberately do NOT: they measure a different thing.)
pub(crate) fn alive_symbols(world: &World, owner: usize, block_id: usize) -> usize {
    (0..world.nodes.len())
        .filter(|&h| {
            world.nodes[h].present
                && world.nodes[h]
                    .holdings
                    .iter()
                    .any(|s| s.alive && s.owner == owner && s.block == block_id)
        })
        .count()
}

/// The [`block_decodable_fraction`] read: the decodable FRACTION plus the size of the
/// undecodable TAIL (and the denominator both are taken over).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Decodability {
    /// Fraction of target-ever-met blocks (present owners) with ≥ `k_eff` alive symbols,
    /// cream included. `NaN` when the denominator is empty.
    pub fraction: f64,
    /// How many of those blocks are BELOW `k_eff` alive symbols — currently undecodable.
    pub below_k_eff: usize,
    /// The denominator: target-ever-met blocks of present owners.
    pub blocks: usize,
}

/// Bit-exact metric equality (used by the determinism board row). Uses `f64::to_bits`
/// so a deterministically-produced `NaN` (an archetype with no blocks / no served-out)
/// compares EQUAL to itself — the derived `PartialEq` would report `NaN != NaN` and
/// false-FAIL the determinism check.
pub(crate) fn bit_eq(a: &MetricSet, b: &MetricSet) -> bool {
    a.alive_symbols == b.alive_symbols
        && a.present_nodes == b.present_nodes
        && a.share_a_pos.to_bits() == b.share_a_pos.to_bits()
        && a.evicts == b.evicts
        && a.preempts == b.preempts
        && a.cap_trims == b.cap_trims
        && a.mean_depth.to_bits() == b.mean_depth.to_bits()
        && a.mean_sigma.to_bits() == b.mean_sigma.to_bits()
        && a.durability
            .iter()
            .zip(&b.durability)
            .all(|(x, y)| x.to_bits() == y.to_bits())
        && a.extraction_roi
            .iter()
            .zip(&b.extraction_roi)
            .all(|(x, y)| x.to_bits() == y.to_bits())
        && a.decodable_fraction.to_bits() == b.decodable_fraction.to_bits()
        && a.undecodable_blocks == b.undecodable_blocks
}

/// World-v3 phase-3 (A15) god-view EVALUATOR read (never a decision input): the NEWCOMER
/// DECODABLE fraction. Among PRESENT nodes that joined strictly AFTER `join_cutoff` — the
/// genuine newcomers arriving into an already-established network (the inflow pool tail; the
/// bootstrap cohort all joins by `T_join ≤ cutoff`, so `joined_tick > cutoff` cleanly isolates
/// them) — the MEAN over nodes of `(TARGET-ever-met blocks that are CURRENTLY DECODABLE) /
/// (target-ever-met blocks)`, where decodable = `alive symbols ≥ k_eff`, **CREAM INCLUDED**
/// (the shared `alive_symbols` primitive). A newcomer with no target-ever-met block yet is
/// SKIPPED (no denominator); `NaN` if no newcomer has one. The A15 enclosure headline: did
/// newcomers' data, once it reached durable, STAY recoverable despite the incumbent cartel?
///
/// **Ф-2 RE-BASE (sim-unification follow-up, review STOP-2).** Both halves of this metric used
/// to be COUNTS against the `n_symbols = 5` placement floor. The R̂ loop stops widening the
/// moment `R̂ ≥ r_target`, so post-unification a healthy block routinely sits at 3-4 holders and
/// the old numerator ("still ≥ 5 non-cream holders") went nearly always false — the measured
/// A15 headline collapsed 0.53 → 0.12 with NOTHING having happened to newcomers' data. The
/// numerator is therefore re-based on the question the invariant actually asks — *can the
/// newcomer still get its data back* — i.e. DECODABILITY, the same cut
/// [`block_decodable_fraction`] uses network-wide. Deliberately NOT re-based on the new
/// placement width (`min_width`): re-importing a count into a metric that a count just burned
/// would buy the same fragility again. The DENOMINATOR (`target_ever_met`) is the tranche's
/// "data that was once durable" set, unchanged here.
///
/// Consequence for reading the number: its SCALE changed (decodability sits near 1 in a healthy
/// world, the floor-fill proxy near 0.34) — the frozen `A15_FLOOR_X` was re-derived against the
/// re-based baseline, and pre-Ф-2 A15 numbers are NOT comparable to post-Ф-2 ones.
///
/// ⚠ **Aggregation differs from [`block_decodable_fraction`] (review NOTE-3):** "one physics"
/// holds for the PREDICATE (both go through `alive_symbols`), not for the aggregation. This is a
/// MEAN OVER NODES of per-node fractions — a newcomer with one block weighs as much as one with
/// three — while `block_decodable_fraction` POOLS blocks. The node-mean is what produces the
/// coarse 1/2, 2/3, 3/4 granularity that dominates this metric's per-seed σ (0.11-0.24); it is
/// pre-existing structure, but post-Ф-2 that noise is larger than the enclosure effect it would
/// have to resolve (see [`crate::sim_adv::registry::a15_enclosure`]).
pub fn newcomer_decodable_fraction(world: &World, join_cutoff: u64, k_eff: usize) -> f64 {
    let n = world.nodes.len();
    let mut ratio_sum = 0.0f64;
    let mut counted = 0usize;
    for o in 0..n {
        if !world.nodes[o].present || world.nodes[o].joined_tick <= join_cutoff {
            continue;
        }
        let mut met = 0usize; // blocks that ever reached the reliability target
        let mut decodable = 0usize; // ... that CURRENTLY still hold ≥ k_eff alive symbols
        for b in &world.nodes[o].own_blocks {
            if !b.target_ever_met {
                continue;
            }
            met += 1;
            if alive_symbols(world, o, b.id) >= k_eff {
                decodable += 1;
            }
        }
        if met > 0 {
            ratio_sum += decodable as f64 / met as f64;
            counted += 1;
        }
    }
    if counted > 0 {
        ratio_sum / counted as f64
    } else {
        f64::NAN
    }
}

/// World-v3 phase-3 (A8 collusion-ring / friend-circle, `4r_a8_spec.md` §3.1) god-view EVALUATOR
/// read (never a decision input): the DECODABLE fraction of an explicit node GROUP's own data — the
/// mean over `group` members present at the horizon of `(target-ever-met blocks currently holding
/// ≥ k_eff alive symbols) / (target-ever-met blocks)`, cream INCLUDED (the shared
/// [`alive_symbols`] primitive).
///
/// Same predicate and same node-mean aggregation as [`newcomer_decodable_fraction`] — only the
/// membership cut differs (an explicit index slice instead of the join-tick cut), so a ring's
/// number is directly comparable with the honest complement's when both are read through here.
/// That comparison IS the "does the system punish the friend circle" measurement: a circle whose
/// data dies reads BELOW the honest group. A member with no target-ever-met block yet is SKIPPED
/// (no denominator); `NaN` if no member has one (or the group is empty).
pub fn group_decodable_fraction(world: &World, group: &[usize], k_eff: usize) -> f64 {
    let mut ratio_sum = 0.0f64;
    let mut counted = 0usize;
    for &o in group {
        if o >= world.nodes.len() || !world.nodes[o].present {
            continue;
        }
        let mut met = 0usize;
        let mut decodable = 0usize;
        for b in &world.nodes[o].own_blocks {
            if !b.target_ever_met {
                continue;
            }
            met += 1;
            if alive_symbols(world, o, b.id) >= k_eff {
                decodable += 1;
            }
        }
        if met > 0 {
            ratio_sum += decodable as f64 / met as f64;
            counted += 1;
        }
    }
    if counted > 0 {
        ratio_sum / counted as f64
    } else {
        f64::NAN
    }
}

/// World-v3 phase-3 (A8, `4r_a8_spec.md` §3.1) god-view EVALUATOR read: the INTRA-GROUP SHARE — of
/// the group's own ALIVE symbols placed anywhere in the network, the fraction sitting on a holder
/// that is itself a group member. THE calibration question "does a friend circle converge on its
/// own?": compare it against the PROPORTIONAL reference (the group's share of the present roster a
/// member could place on) — at ≈ proportional the "circle" is just N arbitrary nodes and the R2 arm
/// measures nothing; well above it, the circle really keeps its data at home.
///
/// Counts alive symbols on PRESENT holders (cream included — a symbol is a symbol for this
/// question). `NaN` when the group has no alive symbol placed anywhere (nothing to take a share of).
pub fn group_intra_share(world: &World, group: &[usize]) -> f64 {
    let mut inside = 0usize;
    let mut total = 0usize;
    for (h, node) in world.nodes.iter().enumerate() {
        if !node.present {
            continue;
        }
        let held = node
            .holdings
            .iter()
            .filter(|s| s.alive && group.contains(&s.owner) && s.owner != h)
            .count();
        total += held;
        if group.contains(&h) {
            inside += held;
        }
    }
    if total > 0 {
        inside as f64 / total as f64
    } else {
        f64::NAN
    }
}

/// World-v3 phase-3 (A10 provider-exit) god-view EVALUATOR read (never a decision input,
/// `4r_a10_spec.md` §2): the network-wide non-cream FLOOR-FILL. Among ALL PRESENT owners, the
/// MEAN over owners of that owner's floor-fill = the mean over its FLOOR-EVER-MET own blocks
/// of `min(alive non-cream holders / floor, 1.0)` — the fraction of the `floor = n_symbols` floor
/// the block currently keeps filled. An owner with no floor-ever-met block is SKIPPED (no
/// denominator); `NaN` if no present owner has a floor-ever-met block (or `floor == 0`).
///
/// **This is a conservative floor-fill PROXY, NOT a decodability/restorability measure** (A10 review
/// B1): it counts non-cream holders only, while RaptorQ decodes from ANY ≥ k_eff symbols — cream
/// included — so a block below the non-cream floor can still be fully restorable. The B1 gap is
/// CLOSED by [`block_decodable_fraction`] (SIM-UNIFICATION §4), which reads exactly that
/// cream-inclusive decodability over the same denominator and is printed next to this proxy in the
/// provider-exit report section; `restore::RestoreTruth` remains the full post-Disaster measure.
/// It answers "how much of the PLACED floor do holders retain",
/// not "did data survive". Restricting to `target_ever_met` isolates "data that WAS at floor staying
/// filled" from young blocks still placing their first backup, so the control at provider_frac = 0
/// reads the steady-state retention (not a fill transient). NOTE the SCALE: under the eviction
/// economy a floor-met block settles near k_eff non-cream holders (≈ 1.7 of the 5-symbol floor), so
/// the steady-state baseline is ≈ 0.34 — NOT ≈ 1; a post-exit reading AT the baseline means the
/// survivors re-took the orphaned floor, below it means floor-fill thinned. Pure god-view — the
/// per-block "alive non-cream holders" of [`collect_metrics`]'s `durability`, normalised to the
/// floor, clipped, and averaged per-owner then over present owners.
pub fn overall_floor_durability(world: &World, floor: usize) -> f64 {
    let n = world.nodes.len();
    if floor == 0 {
        return f64::NAN;
    }
    let mut owner_sum = 0.0f64;
    let mut owner_cnt = 0usize;
    for o in 0..n {
        if !world.nodes[o].present {
            continue;
        }
        let mut block_sum = 0.0f64;
        let mut met = 0usize;
        for b in &world.nodes[o].own_blocks {
            if !b.target_ever_met {
                continue;
            }
            met += 1;
            let live = (0..n)
                .filter(|&h| {
                    world.nodes[h].present
                        && world.nodes[h]
                            .holdings
                            .iter()
                            .any(|s| s.alive && !s.cream && s.owner == o && s.block == b.id)
                })
                .count();
            block_sum += (live as f64 / floor as f64).min(1.0);
        }
        if met > 0 {
            owner_sum += block_sum / met as f64;
            owner_cnt += 1;
        }
    }
    if owner_cnt > 0 {
        owner_sum / owner_cnt as f64
    } else {
        f64::NAN
    }
}

/// World-v3 phase-3 (A15) CARTEL-PAYS read (spec §4, SECONDARY): the mean outbound-service
/// integral `served_out = Σ_h served[node][h]` (gb·days the node GAVE others) for the CARTEL
/// nodes vs the NON-cartel INCUMBENTS (present nodes that joined by `join_cutoff` and are not in
/// the cartel). Returns `(cartel_mean, non_cartel_incumbent_mean)`. A cartel that refuses to
/// serve newcomers serves LESS, so it should earn NO MORE than an honest incumbent of the same
/// vintage. Each side is `NaN` when it has no members (skipped by the caller). Pure god-view.
pub fn cartel_earnings_split(world: &World, cartel: &[usize], join_cutoff: u64) -> (f64, f64) {
    let n = world.nodes.len();
    let served_out = |node: usize| -> f64 { (0..n).map(|h| world.served[node][h]).sum() };
    let mut cartel_sum = 0.0f64;
    let mut cartel_cnt = 0usize;
    let mut inc_sum = 0.0f64;
    let mut inc_cnt = 0usize;
    for node in 0..n {
        if !world.nodes[node].present {
            continue;
        }
        if cartel.contains(&node) {
            cartel_sum += served_out(node);
            cartel_cnt += 1;
        } else if world.nodes[node].joined_tick <= join_cutoff {
            // A non-cartel INCUMBENT (same "established" vintage as the cartel).
            inc_sum += served_out(node);
            inc_cnt += 1;
        }
    }
    let cartel_mean = if cartel_cnt > 0 {
        cartel_sum / cartel_cnt as f64
    } else {
        f64::NAN
    };
    let inc_mean = if inc_cnt > 0 {
        inc_sum / inc_cnt as f64
    } else {
        f64::NAN
    };
    (cartel_mean, inc_mean)
}

/// World-v3 phase-3 (A7 sybil-farm) god-view EVALUATOR read (never a decision input, `4r_a7_spec.md`
/// §3): the CROSS-BOUNDARY honest storage the farm captured. `Σ_{h∉farm, s∈farm} served[h][s]` —
/// the gb·time integral of the FARM's own data (`s` = sybil owner ∈ farm) that lived on an HONEST
/// holder (`h` ∉ farm), PoS-confirmed. This is the storage the farm actually captured from the honest
/// network. The reader counts only honest↔farm flows (the intra-farm `served[i∈farm][j∈farm]` cells
/// the collusion writes are EXCLUDED: `h ∉ farm`, `s ∈ farm`).
///
/// NOTE (SIM-FIDELITY ARTIFACT, `4r_a7_spec.md` + A7 adversarial review): under collusion this metric
/// inflates ~58× — but NOT because collusion beats the credit-limit. The pairwise κ_O credit key
/// [`farm_honest_reciprocity`] (`capital[sybil][honest].g_ho`) stays ≈ 0, so the credit-limit HOLDS.
/// The inflation rides the sim's OWNER-ORDERING PROXY: `place_own_data`'s `giver_priority_order`
/// (engine `place_own_data`, default on) sorts owners each tick by the GLOBAL row-sum
/// `Σ_h capital[o][h].g_ho`, which collusion inflates for free — so the sybils sort to the FRONT of
/// the placement order and win scarce free-accept holder slots under contention. That global scheduler
/// ranking-all-owners-by-total-service has NO real-protocol analogue (the daemon's priority is
/// holder-side pairwise), and the code itself flags it as a proxy "NOT the spec's ideal". So the 58×
/// is a sim-fidelity artifact; the trust-model defence is [`farm_honest_reciprocity`] ≈ 0
/// (INV-SYBIL-CREDIT-LIMIT-HOLDS). `0.0` for an empty farm.
pub fn farm_honest_storage(world: &World, farm: &[usize]) -> f64 {
    let n = world.nodes.len();
    let is_farm = |x: usize| farm.contains(&x);
    let mut sum = 0.0f64;
    for h in 0..n {
        if is_farm(h) {
            continue; // honest holder only
        }
        for &s in farm {
            sum += world.served[h][s]; // served[holder][owner] = honest h held sybil s's data
        }
    }
    sum
}

/// World-v3 phase-3 (A7) THE HEADLINE DEFENCE reader (`4r_a7_spec.md` §4 + A7 review): the farm's
/// EARNED HONEST RECIPROCITY — the pairwise κ_O credit key that gates the farm's data on honest
/// holders — `Σ_{s∈farm, h∉farm} capital[s][h].g_ho`. This is the cell the eviction/preemption rank
/// (core `eviction_order`) and the admit-guard read to decide how much of sybil `s`'s data holder `h`
/// keeps (`V_ret = v_free + κ_O/c_recip`). Collusion writes ONLY intra-farm cells, so it can NOT
/// inflate this honest key: it stays ≈ 0 under collude-ON (the ε-farm never serves honest, so it earns
/// no honest reciprocity). INV-SYBIL-CREDIT-LIMIT-HOLDS asserts this ≈ 0 — the proof that
/// "reputation = credit-limit" RESISTS sybil multiplication. `0.0` for an empty farm.
pub fn farm_honest_reciprocity(world: &World, farm: &[usize]) -> f64 {
    let n = world.nodes.len();
    let is_farm = |x: usize| farm.contains(&x);
    let mut sum = 0.0f64;
    for &s in farm {
        for h in 0..n {
            if is_farm(h) {
                continue; // honest holder only
            }
            sum += world.capital[s][h].g_ho; // sybil s's earned reciprocity as a SERVER of honest h
        }
    }
    sum
}

/// World-v3 phase-3 (A7) god-view EVALUATOR read (`4r_a7_spec.md` §3): the farm→honest OUTBOUND
/// service `Σ_{s∈farm, h∉farm} served[s][h]` — how much the farm REALLY served the honest network
/// (for the cross-ROI if it is > 0). An ε-serving sybil farm gives ≈ 0 (it earns no honest
/// reciprocity — which is why [`farm_honest_reciprocity`] stays ≈ 0). `0.0` for an empty farm.
pub fn farm_honest_served(world: &World, farm: &[usize]) -> f64 {
    let n = world.nodes.len();
    let is_farm = |x: usize| farm.contains(&x);
    let mut sum = 0.0f64;
    for &s in farm {
        for h in 0..n {
            if is_farm(h) {
                continue; // honest holder only
            }
            sum += world.served[s][h]; // served[holder][owner] = sybil s held honest h's data
        }
    }
    sum
}

/// World-v3 phase-3 A9 (`4r_a9_spec.md` §4.1) god-view EVALUATOR read of the eclipse's COST.
/// Read straight off the engine's `world.eclipse` bookkeeping, which attributes both numbers AT
/// the drop itself. Never a decision input.
///
/// ⚠ **`blocks_pushed_below_k_eff` is NOT a damage unit (review BLOCK-2).** It counts blocks the
/// volley drove under `k_eff` AT THE MOMENT OF THE DROP. Whether that costs the owner anything
/// depends entirely on when it happened:
/// * **before the disaster** — the owner still has its source, so repair restores every one of
///   them (arm A: 3 blocks pushed, restore-truth 1.0000 on 5/5 seeds — P1 working as documented);
/// * **inside the restore window at `detect = 0`** — terminal (4 blocks pushed, Δ = 0.27-0.33);
/// * **inside the window at `detect = 1`** — the victim's first collection pass has already run,
///   so MORE blocks get pushed (6) for EXACTLY ZERO damage.
///
/// So this counter must never be compared across arms as if it were harm, and
/// `symbols_per_block_pushed` is an efficiency read ONLY between arms whose volleys land in the
/// same tick (B vs C). Arm A's ratio prices blocks that cost the victim nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EclipseCost {
    /// Alive symbols of the target the group burned over the run.
    pub symbols_dropped: usize,
    /// Target blocks the drop pushed from `≥ k_eff` alive symbols to `< k_eff` **at the volley**.
    /// See the type doc: this is a volley-time count, NOT damage.
    pub blocks_pushed_below_k_eff: usize,
}

impl EclipseCost {
    /// Symbols burned per block pushed below `k_eff`. `NaN` when nothing was pushed (an attack
    /// that burned symbols for nothing has no finite ratio — reported as NaN rather than as a
    /// flattering 0). Comparable BETWEEN ARMS ONLY when their volleys land in the same tick.
    pub fn symbols_per_block_pushed(&self) -> f64 {
        if self.blocks_pushed_below_k_eff == 0 {
            f64::NAN
        } else {
            self.symbols_dropped as f64 / self.blocks_pushed_below_k_eff as f64
        }
    }
}

/// Read one run's [`EclipseCost`] off the horizon world (pure god-view read, no mutation).
pub fn collect_eclipse_cost(world: &World) -> EclipseCost {
    EclipseCost {
        symbols_dropped: world.eclipse.symbols_dropped,
        blocks_pushed_below_k_eff: world.eclipse.blocks_pushed_below_k_eff,
    }
}

/// Mean and SAMPLE standard deviation (n−1) over the FINITE values (NaN skipped). The
/// mean is `NaN` with no finite value; σ is `NaN` with fewer than two (undefined spread).
/// Shared by the report's metric table and the verdict engine's power test.
pub(crate) fn mean_sigma(xs: &[f64]) -> (f64, f64) {
    let v: Vec<f64> = xs.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return (f64::NAN, f64::NAN);
    }
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    let sigma = if v.len() < 2 {
        f64::NAN
    } else {
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (v.len() as f64 - 1.0);
        var.sqrt()
    };
    (mean, sigma)
}
