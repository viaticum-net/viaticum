//! `sim_dynamic` engine — the dynamic time-loop over the god-view world.
//!
//! Each tick (design §6 + §10) runs, in order:
//!   1. **own-data → `place`** (kernel, greedy; §10.I scopes the newcomer probe to
//!      plain `place`, no probation arm) → record god-view placements.
//!   2. **holder accept/reject** — a seeded Bernoulli on the holder archetype's
//!      `accept_rate` decides whether an offered symbol lands (§10.A).
//!   3. **PoS-challenge sampling** (§10.B) — for each placed symbol, sample the
//!      hidden truth: offline ⇒ `timeout`; online ∧ ¬holds ⇒ `fail`; online ∧ holds
//!      ⇒ `pass`. ALL draws from `Rng::derive(run_seed, o, h, s, tick)`.
//!   4. **`update_capital`** (kernel) with `v_conf = passed ? volume : 0` (§10.C) —
//!      capital grows ONLY on a pass.
//!   5. **eviction** when `φ < s_soft` via `eviction_order` (§10.G; the φ-integrator
//!      + latch pattern mirrors `engine/mod.rs`).
//!   6. **repair** — the harness calls `place` for blocks below `r_target`.
//!   7. **churn** — nodes leave/join by archetype; on leave, held symbols die.
//!
//! Anti-oracle: the kernel is called ONLY through the observer (first-hand). The
//! engine knows archetypes (god-view) but passes them to NO kernel function — it
//! uses them only to drive BEHAVIOUR (accept/reject, online, evict-aggression).

use viaticum_core::four_r::{
    BlockReq, Hysteresis, NodeLocal, PlacementPolicy, PlacementResult, SurfacePrior,
    eviction_order, place,
};

use crate::generator::Rng;
use crate::sim_dynamic::generator::{
    Archetype, BlockPlacement, DAYS_PER_TICK, HeldSymbol, Node, OwnBlock, POS_WINDOW_LEN,
    PairCapital, World, online,
};
use crate::sim_dynamic::observer::{self, ObsAddr};

/// Tunable dials for one dynamic run.
#[derive(Debug, Clone, Copy)]
pub struct DynParams {
    /// Capital leak rate `λ` (per day). `1/λ` is the capital memory in days —
    /// months (design §10.C). With weekly `dt`, `λ·dt < 1` holds with room.
    pub lambda: f64,
    /// Per-symbol erasure count `n` for own-data blocks.
    pub n_symbols: usize,
    /// Reconstruction threshold `k_eff`.
    pub k_eff: usize,
    /// Per-block target reliability for `place`.
    pub r_target: f64,
    /// Per-block total volume (gb).
    pub block_volume: f64,
    /// How many own blocks each node tries to back up.
    pub blocks_per_node: usize,
    /// Hysteresis band for the eviction relay.
    pub hyst: Hysteresis,
    /// Per-tick probability a present cooperative node departs (churn out). Hoarder
    /// / Freeloader churn at a higher multiple (they are less committed).
    pub churn_out_prob: f64,
}

impl Default for DynParams {
    fn default() -> Self {
        DynParams {
            // 1/λ ≈ 60 days (two months) of capital memory; λ·dt = (1/60)·7 ≈ 0.117 ≪ 1.
            lambda: 1.0 / 60.0,
            n_symbols: 6,
            k_eff: 3,
            r_target: 0.90,
            block_volume: 60.0, // ⇒ 10 gb/symbol = the canonical observed V0
            blocks_per_node: 3,
            hyst: Hysteresis {
                s_hard: 0.10,
                s_target: 0.20,
                s_soft: 0.30,
            },
            churn_out_prob: 0.002,
        }
    }
}

/// The asserted numerical-stability guard (design §10.C, mod.rs:176): `λ·dt < 1`.
/// Panics on violation — a degenerate dial would make the discrete capital step
/// oscillate/diverge, which would silently corrupt the whole run.
pub fn assert_lambda_dt_stable(lambda: f64, dt_days: f64) {
    let prod = lambda * dt_days;
    assert!(
        prod < 1.0,
        "λ·dt = {prod} must be < 1 for monotone capital relaxation (design §10.C / mod.rs:176)"
    );
}

/// Capital index helper: get a mutable handle to the `[owner][holder]` pair state,
/// growing the dense matrix as the node count grows.
fn cap_mut(capital: &mut [Vec<PairCapital>], owner: usize, holder: usize) -> &mut PairCapital {
    &mut capital[owner][holder]
}

/// Run ONE tick of the dynamic loop (design §6 + §10). Mutates the world in place.
///
/// `params` are the dials; the kernel `prior`/`policy` are the owner-private
/// surface form + spread policy (defaults).
pub fn step(world: &mut World, params: &DynParams, prior: &SurfacePrior, policy: &PlacementPolicy) {
    assert_lambda_dt_stable(params.lambda, DAYS_PER_TICK);
    let tick = world.tick;
    let n = world.nodes.len();

    // ---- (1) own-data → place (kernel, greedy) + (2) holder accept/reject ----
    place_own_data(world, params, prior, policy);

    // ---- (3) PoS-challenge sampling + (4) update_capital ----
    pos_and_capital(world, params);

    // ---- (5) eviction when φ < s_soft (kernel eviction_order + latch) ----
    run_eviction(world, params);

    // ---- (6) repair: re-place blocks below r_target ----
    repair(world, params, prior, policy);

    // ---- (7) churn: departures by archetype ----
    churn(world, params);

    let _ = n;
    world.tick = tick + 1;
}

/// (1)+(2): each present owner attempts to back up its own blocks that are not yet
/// at `r_target`, via the kernel `place`, then the chosen holders accept/reject by
/// their archetype `accept_rate` (seeded Bernoulli, §10.A). Accepted symbols are
/// recorded both as god-view holdings on the holder AND as the block's placements.
fn place_own_data(
    world: &mut World,
    params: &DynParams,
    prior: &SurfacePrior,
    policy: &PlacementPolicy,
) {
    let n = world.nodes.len();
    let dt = DAYS_PER_TICK;
    let tick = world.tick;

    for owner in 0..n {
        if !world.nodes[owner].present {
            continue;
        }
        // Snapshot the owner's blocks that still need holders (placements below n).
        let needy: Vec<usize> = world.nodes[owner]
            .own_blocks
            .iter()
            .enumerate()
            .filter(|(_, b)| b.placements.len() < params.n_symbols)
            .map(|(i, _)| i)
            .collect();
        if needy.is_empty() {
            continue;
        }

        for bi in needy {
            // Build the candidate set: all OTHER present nodes (a star network of
            // independent owners — siblings/self excluded, as in the real placement).
            let block_iota = world.nodes[owner].own_blocks[bi].iota;
            let block_volume = world.nodes[owner].own_blocks[bi].volume;
            let block_id = world.nodes[owner].own_blocks[bi].id;
            let already: Vec<usize> = world.nodes[owner].own_blocks[bi]
                .placements
                .iter()
                .map(|p| p.holder)
                .collect();

            let mut cand_idx: Vec<usize> = (0..n)
                .filter(|&h| h != owner && world.nodes[h].present && !already.contains(&h))
                .collect();
            if cand_idx.is_empty() {
                continue;
            }
            // Deterministically SHUFFLE the candidate order per (owner, block, tick).
            // `place` ranks by descending surface r_hat with a STABLE sort, so among
            // the many strangers with identical obs the input order decides ties. An
            // unshuffled `0..n` order would always resolve ties to the lowest indices,
            // funnelling EVERY placement onto the same handful of nodes (a topology
            // artifact, not a model property — it would starve all but the first few
            // holders). The shuffle gives candidates no incidental index advantage,
            // exactly as a real network has no global node ordering. Deterministic in
            // the run seed, so the run stays bit-reproducible.
            shuffle(&mut cand_idx, world.seed, owner as u64, tick, bi as u64);

            let cand_nodes: Vec<&Node> = cand_idx.iter().map(|&h| &world.nodes[h]).collect();
            let caps: Vec<&PairCapital> =
                cand_idx.iter().map(|&h| &world.capital[owner][h]).collect();
            let cand_obs = observer::observe_candidates(&cand_nodes, &caps, dt);

            let req = BlockReq {
                volume: block_volume,
                n_symbols: params.n_symbols,
                k_eff: params.k_eff,
                tau: DAYS_PER_TICK,
                r_target: params.r_target,
            };

            let result = place(&req, &cand_obs, prior, policy);
            let chosen_local: Vec<usize> = match result {
                PlacementResult::Placed { holders, .. } => holders,
                PlacementResult::Insufficient { holders, .. } => holders,
            };

            let v_per_symbol = req.volume_per_symbol();
            for &local in &chosen_local {
                let holder = cand_idx[local];
                // (2) holder accept/reject — seeded Bernoulli on accept_rate (§10.A).
                let mut rng = Rng::derive(
                    world.seed,
                    0xACCE_7711,
                    owner as u64,
                    holder as u64,
                    (tick << 8) ^ bi as u64,
                );
                let accept = rng.unit() < world.nodes[holder].archetype.accept_rate();
                if !accept {
                    continue;
                }
                // Record the god-view holding on the holder.
                world.nodes[holder].holdings.push(HeldSymbol {
                    owner,
                    block: block_id,
                    iota: block_iota,
                    volume: v_per_symbol,
                    alive: true,
                });
                // Record the block placement on the owner.
                world.nodes[owner].own_blocks[bi]
                    .placements
                    .push(BlockPlacement { holder });
                // The owner accrues g_holder_from_owner (its service to the holder):
                // it just stored a symbol FOR... no — it stored ON the holder, so the
                // HOLDER's g_holder_from_owner toward THIS owner rises (the holder is
                // serving the owner). We accrue the holder's service-to-owner as the
                // owner's g_oh-side later via PoS; the owner's service TO the holder
                // (g_ho) accrues when the holder backs up ON the owner. Here the owner
                // is the data SOURCE, the holder is storing — so from the holder's
                // perspective g_holder_from_owner(holder←... ) — we model reciprocity
                // symmetrically below in pos_and_capital. Nothing to add here.
            }
        }
    }
}

/// (3)+(4): for every alive placed symbol, sample the PoS outcome from the hidden
/// truth and thread `update_capital` (design §10.B/§10.C).
///
/// The challenge is owner O challenging holder h on symbol s:
///   * `is_online ~ Bernoulli(online_prob)` — offline ⇒ `timeout`.
///   * online: `holds ~ Bernoulli(true_retained_indicator)` — the realisation of
///     god-view eviction on h (surface alive × the symbol above the effective
///     retained edge). online ∧ ¬holds ⇒ `fail`; online ∧ holds ⇒ `pass`.
///
/// `update_capital` grows the owner's `g_oh` ONLY on a pass (`v_conf = volume`).
fn pos_and_capital(world: &mut World, params: &DynParams) {
    let n = world.nodes.len();
    let tick = world.tick;
    let dt = DAYS_PER_TICK;

    // First: roll over g_oh_prev for the D-projection finite difference.
    for o in 0..n {
        for h in 0..n {
            world.capital[o][h].g_oh_prev = world.capital[o][h].g_oh;
        }
    }

    // Collect challenges as (owner, holder, block, volume, iota) over alive symbols.
    // We iterate over each holder's holdings (the holder physically stores them).
    struct Challenge {
        owner: usize,
        holder: usize,
        block: usize,
        volume: f64,
        // The symbol's ι-rank within the owner's ladder on this holder, and the
        // holder's effective retained edge — both god-view (the evaluator/engine
        // realises eviction; the kernel never sees these).
        iota_rank: f64,
        retained_edge: f64,
        holder_online: bool,
    }
    let mut challenges: Vec<Challenge> = Vec::new();

    for holder in 0..n {
        if !world.nodes[holder].present {
            continue;
        }
        // God-view: is this holder online this tick?
        let h_online = online(
            world.nodes[holder].archetype,
            world.nodes[holder].id,
            tick,
            world.seed,
        );
        // God-view effective retained depth on this holder: a baseline keep-depth
        // shaved by the archetype's evict-aggression (Hoarder/Freeloader keep less).
        // Cooperative archetypes keep deep (edge near 0); aggressive ones keep only
        // the top of the ladder (edge near 1).
        let aggression = world.nodes[holder].archetype.evict_aggression();
        // Disk pressure also lowers the effective keep-depth: a near-full disk keeps
        // less. φ small ⇒ shallow retention.
        let phi = world.nodes[holder].phi_free_ratio();
        // Effective keep-depth ∈ [0,1]: full disk + high aggression ⇒ shallow.
        let keep_depth = ((1.0 - aggression) * phi).clamp(0.0, 1.0);
        let retained_edge = 1.0 - keep_depth;

        // Build the owner→symbols grouping to compute per-owner ι-ranks.
        // For each alive symbol, find its ι-rank within the owner's ladder on this
        // holder.
        for (owner, block, iota) in world.nodes[holder]
            .holdings
            .iter()
            .filter(|s| s.alive)
            .map(|s| (s.owner, s.block, s.iota))
            .collect::<Vec<_>>()
        {
            let (ladder, _rung) =
                observer::owner_ladder_on_holder(&world.nodes[holder], owner, block);
            let iota_rank = iota_rank_of(&ladder, iota);
            // Volume of this symbol.
            let volume = world.nodes[holder]
                .holdings
                .iter()
                .find(|s| s.alive && s.owner == owner && s.block == block)
                .map(|s| s.volume)
                .unwrap_or(0.0);
            challenges.push(Challenge {
                owner,
                holder,
                block,
                volume,
                iota_rank,
                retained_edge,
                holder_online: h_online,
            });
        }
    }

    // Now sample each challenge + thread capital.
    for c in &challenges {
        let mut rng = Rng::derive(
            world.seed,
            c.owner as u64,
            c.holder as u64,
            ((c.block as u64) << 1) ^ 0x9_u64,
            tick,
        );

        // Outcome classification (§10.B).
        let outcome = if !c.holder_online {
            PosOutcome::Timeout
        } else {
            // online: does the holder actually still hold this symbol? Realise
            // god-view eviction: the symbol is held iff its ι-rank is at/above the
            // effective retained edge (the two-level rule, with the HIDDEN edge).
            let holds = c.iota_rank + 1e-12 >= c.retained_edge;
            // Independent draw against the realised indicator (it is 0/1 here; the
            // Bernoulli collapses to a deterministic outcome, but we still consume
            // the RNG stream so timeouts and passes share the keying discipline).
            let _u = rng.unit();
            if holds {
                PosOutcome::Pass
            } else {
                PosOutcome::Fail
            }
        };

        let passed = matches!(outcome, PosOutcome::Pass);
        let v_conf = if passed { c.volume } else { 0.0 };

        // God-view served TIME-INTEGRAL (design §10.E): on a PoS PASS this tick, the
        // holder demonstrably retained this symbol of the owner's data — add its
        // volume to served[holder][owner]. This accumulates the integral of PoS-
        // confirmed retained bytes over the WHOLE run (NOT a standing snapshot, NOT
        // the G-ledger). Fail/timeout add nothing. Monotone non-decreasing per cell.
        if passed {
            world.served[c.holder][c.owner] += c.volume;
        }

        let cap = cap_mut(&mut world.capital, c.owner, c.holder);
        // Capital grows ONLY on a pass (fail/timeout ⇒ v_conf = 0). The owner's
        // g_oh (holder's service TO me) integrates confirmed retained volume.
        cap.g_oh = viaticum_core::four_r::update_capital(cap.g_oh, v_conf, params.lambda, dt);
        if passed {
            cap.v_dem = cap.v_dem.max(c.volume);
        }
        cap.push_outcome(passed);

        // Reciprocity: the HOLDER's service to the owner means the holder accrues
        // g_holder_from_owner toward the owner — i.e. the pair (holder, owner)'s
        // g_ho rises (the holder is the one storing). We model g_ho as the mirror:
        // when O challenges h and h passes, h has demonstrably served O, so from h's
        // OWN ledger g_holder_from_owner(h, O) — which the holder reads as the
        // eviction key — rises. We store that on capital[holder][owner].g_ho? No:
        // g_ho on capital[o][h] is "owner o's service to holder h". The eviction key
        // the holder ranks owners by is g_holder_from_owner = capital[h][o].g_ho is
        // not it either. The kernel reads obs.g_holder_from_owner; the observer fills
        // it from capital[owner][holder].g_ho. For the HOLDER's eviction decision,
        // owner = the data owner, holder = self; the obs.g_holder_from_owner must be
        // the holder's record of ITS service to that owner. Symmetric model: a pass
        // means BOTH directions served each other this round (the owner confirmed
        // storage = the holder served the owner). So we bump g_ho on the same pair
        // state, representing the holder's service-to-owner that the holder will read
        // when it later ranks this owner for eviction.
        if passed {
            let cap = cap_mut(&mut world.capital, c.owner, c.holder);
            cap.g_ho = viaticum_core::four_r::update_capital(cap.g_ho, v_conf, params.lambda, dt);
        } else {
            let cap = cap_mut(&mut world.capital, c.owner, c.holder);
            cap.g_ho = viaticum_core::four_r::update_capital(cap.g_ho, 0.0, params.lambda, dt);
        }
    }
}

/// PoS outcome classification (design §10.B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosOutcome {
    /// Holder online and still holds the symbol.
    Pass,
    /// Holder online but withheld / dropped the symbol.
    Fail,
    /// Holder offline — kernel §7 forgives this (scrutiny↑, no burn).
    Timeout,
}

/// The ι-rank ∈ [0,1] of `iota` within `ladder` (same convention as the kernel's
/// `HolderPlacement::iota_rank`): the fraction strictly below; singleton ⇒ 0.
fn iota_rank_of(ladder: &[f64], iota: f64) -> f64 {
    let m = ladder.len();
    if m <= 1 {
        return 0.0;
    }
    let lower = ladder.iter().filter(|&&i| i < iota).count();
    lower as f64 / (m - 1) as f64
}

/// (5): eviction when `φ < s_soft` (design §10.G). Builds each present holder's
/// eviction view through the observer, calls `eviction_order` (latch threaded
/// through `Node::evict_phase`), and applies the drop slots to god-view holdings
/// until `φ ≥ s_target`.
fn run_eviction(world: &mut World, params: &DynParams) {
    let n = world.nodes.len();
    let dt = DAYS_PER_TICK;

    for holder in 0..n {
        if !world.nodes[holder].present {
            continue;
        }
        let phi = world.nodes[holder].phi_free_ratio();
        // Only do work if we might be (or stay) in the evicting state.
        let prev = world.nodes[holder].evict_phase;

        // Build the eviction view through the observer (first-hand only).
        let owner_addr = |owner_idx: usize| -> ObsAddr {
            ObsAddr {
                addr_subnet: world.nodes[owner_idx].addr_subnet,
                master_byte: world.nodes[owner_idx].master_byte,
                present: world.nodes[owner_idx].present,
            }
        };
        // Capture caps by owner: capital[owner][holder].g_ho is the holder's service
        // to that owner — the inter-owner eviction key.
        let views = observer::observe_eviction_views(
            &world.nodes[holder],
            |owner_idx| &world.capital[owner_idx][holder],
            owner_addr,
            dt,
        );

        let decision = eviction_order(&views, phi, params.hyst, prev);
        world.nodes[holder].evict_phase = decision.phase;

        if !decision.phase.evicting || decision.drop_order.is_empty() {
            continue;
        }

        // Apply drops one slot at a time until φ recovers to s_target. Map each
        // SymbolSlot (owner_idx into views, symbol_idx into that owner's symbols)
        // back to the god-view HeldSymbol and mark it dead.
        // Reconstruct the owner each view-slot refers to: the observer grouped owners
        // ascending, so reproduce exactly that grouping.
        let owner_of_view: Vec<usize> = {
            let mut owners: Vec<usize> = Vec::new();
            for s in world.nodes[holder].holdings.iter().filter(|s| s.alive) {
                if !owners.contains(&s.owner) {
                    owners.push(s.owner);
                }
            }
            owners.sort_unstable();
            owners
        };

        for slot in &decision.drop_order {
            if world.nodes[holder].phi_free_ratio() >= params.hyst.s_target {
                break;
            }
            let owner_idx = match owner_of_view.get(slot.owner_idx) {
                Some(&o) => o,
                None => continue,
            };
            // The view's symbols for this owner were the alive symbols in storage
            // order; map symbol_idx to the matching god-view holding and kill it.
            let block = nth_alive_block(&world.nodes[holder], owner_idx, slot.symbol_idx);
            if let Some(block) = block {
                if let Some(hs) = world.nodes[holder]
                    .holdings
                    .iter_mut()
                    .find(|s| s.alive && s.owner == owner_idx && s.block == block)
                {
                    hs.alive = false;
                }
                // The owner loses this placement (god-view block bookkeeping).
                if let Some(b) = world.nodes[owner_idx]
                    .own_blocks
                    .iter_mut()
                    .find(|b| b.id == block)
                    && let Some(pos) = b.placements.iter().position(|p| p.holder == holder)
                {
                    b.placements.remove(pos);
                }
            }
        }
    }
}

/// The `idx`-th alive block of `owner` on `holder`, in the SAME order the observer
/// builds the owner's symbol list (filtered alive, storage order). Returns the
/// god-view block id, or None if out of range.
fn nth_alive_block(holder: &Node, owner: usize, idx: usize) -> Option<usize> {
    holder
        .holdings
        .iter()
        .filter(|s| s.alive && s.owner == owner)
        .nth(idx)
        .map(|s| s.block)
}

/// (6): repair. For each present owner, any block whose ALIVE placement count has
/// fallen below `n_symbols` is re-placed via the same greedy `place` path. This is
/// the W12-actuator: repair = the harness calling `place`, NOT a kernel fn.
fn repair(world: &mut World, params: &DynParams, prior: &SurfacePrior, policy: &PlacementPolicy) {
    // Drop dead placements from the block bookkeeping first (a holder that left or
    // evicted left a stale BlockPlacement only if eviction missed it; we re-sync by
    // counting alive holdings on each holder). Then place_own_data refills.
    let n = world.nodes.len();
    for owner in 0..n {
        if !world.nodes[owner].present {
            continue;
        }
        let block_ids: Vec<usize> = world.nodes[owner].own_blocks.iter().map(|b| b.id).collect();
        for block_id in block_ids {
            // Count holders that still hold an alive symbol of this block.
            let alive_holders: Vec<usize> = (0..n)
                .filter(|&h| {
                    world.nodes[h].present
                        && world.nodes[h]
                            .holdings
                            .iter()
                            .any(|s| s.alive && s.owner == owner && s.block == block_id)
                })
                .collect();
            // Resync the block's placement list to the actual alive holders.
            if let Some(b) = world.nodes[owner]
                .own_blocks
                .iter_mut()
                .find(|b| b.id == block_id)
            {
                b.placements = alive_holders
                    .iter()
                    .map(|&h| BlockPlacement { holder: h })
                    .collect();
            }
        }
    }
    // Re-run the placement pass: blocks below n_symbols get new holders.
    place_own_data(world, params, prior, policy);
}

/// (7): churn. Each present node departs with a per-archetype probability (seeded
/// Bernoulli). On departure, the node's HELD symbols are marked dead (so owners'
/// R_actual drops and repair triggers next tick), and the node is marked absent.
fn churn(world: &mut World, params: &DynParams) {
    let n = world.nodes.len();
    let tick = world.tick;
    for node in 0..n {
        if !world.nodes[node].present {
            continue;
        }
        let mut rng = Rng::derive(world.seed, 0xC4_07_C4_07, world.nodes[node].id, tick, 0);
        let p = match world.nodes[node].archetype {
            Archetype::Hoarder | Archetype::Freeloader => params.churn_out_prob * 3.0,
            _ => params.churn_out_prob,
        };
        if rng.unit() < p {
            world.nodes[node].present = false;
            // Mark all symbols this node was HOLDING for others as dead.
            for hs in world.nodes[node].holdings.iter_mut() {
                hs.alive = false;
            }
        }
    }
    let _ = POS_WINDOW_LEN;
}

/// Build the kernel's `NodeLocal` snapshot for a holder (its own disk free-ratio).
/// Exposed for tests / diagnostics.
pub fn node_local(node: &Node) -> NodeLocal {
    NodeLocal {
        phi_free_ratio: node.phi_free_ratio(),
    }
}

/// Deterministic Fisher-Yates shuffle of `v`, keyed by the run seed + three mixing
/// coordinates. Used to give placement candidates no incidental index advantage (so
/// ties in `place` do not always funnel onto the lowest-index nodes). Reproducible.
fn shuffle(v: &mut [usize], seed: u64, k0: u64, k1: u64, k2: u64) {
    let mut rng = Rng::derive(seed, 0x0544_FF1E_5417_F1E0, k0, k1, k2);
    let len = v.len();
    for i in (1..len).rev() {
        let j = (rng.unit() * (i as f64 + 1.0)) as usize;
        let j = j.min(i);
        v.swap(i, j);
    }
}

/// Convenience: a new pair-capital matrix sized for `n` nodes.
pub fn fresh_capital(n: usize) -> Vec<Vec<PairCapital>> {
    (0..n)
        .map(|_| (0..n).map(|_| PairCapital::default()).collect())
        .collect()
}

/// Build an OwnBlock with a fresh id from the world's per-owner counter.
pub fn fresh_block(world: &mut World, owner: usize, volume: f64, iota: f64) -> OwnBlock {
    let id = world.next_block_id[owner];
    world.next_block_id[owner] += 1;
    OwnBlock {
        id,
        volume,
        iota,
        placements: Vec::new(),
    }
}
