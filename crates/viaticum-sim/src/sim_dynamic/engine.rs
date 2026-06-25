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
    BlockReq, Hysteresis, NodeLocal, PlacementPolicy, RetentionPrior, SurfacePrior,
    estimate_surface, eviction_order, retained_depth,
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
    /// Cream margin (design §A.1, W9): extra redundant symbols an owner greedily
    /// places ABOVE the `r_target` floor, ι-prioritized. `R_target(ι)` is a
    /// FLOOR/setpoint, NOT a ceiling — once the core `n_symbols` reach the floor, the
    /// owner keeps adding symbols (cream) up to `n_symbols + ⌈cream_max·ι⌉`, filling
    /// free holder capacity (utilization→1). The ι-weighting makes redundancy ∝ ι at
    /// every capacity level. This is the holder-greed driver that, combined with
    /// own-data growth (§A.2), pushes the world to contention. Limited only by
    /// physical disk + reciprocal capacity (holders reject when full, §A.3).
    pub cream_max: usize,
    /// Base physical disk capacity (gb), SHARED between own data and foreign holdings
    /// (design §A.2). Deliberately modest relative to the aggregate backup+cream
    /// demand so own-data growth fills it and the world contends (utilization→1).
    pub disk_cap_base: f64,
    /// Per-node uniform spread (gb) added to `disk_cap_base` (heterogeneous disks).
    pub disk_cap_spread: f64,
    /// Reciprocity-aware placement via the CANON retention forecast (canon §9.5 /
    /// эталон §1, поправка Ильи 2026-06-26). When `true`, placement ranks candidates by
    /// the canon two-route keep-probability `surface · retained_depth(obs)` instead of
    /// surface alone — `retained_depth` (mod.rs:1134) folds in the owner's first-hand
    /// `g_holder_from_owner` (= `capital[owner][h].g_ho` = "how much h stores at us"),
    /// so a holder that already stores at us forecasts a HIGHER survival for our symbol
    /// and is preferred. This is the canon mechanism that forces reciprocity (the
    /// dynamic `place` used surface-only K2 and ignored it). `false` ⇒ pure-surface
    /// baseline (for A/B). Strength is set by the canon `RetentionPrior`, not a magic
    /// weight — the old ad-hoc `recip_weight` bonus is GONE.
    pub reciprocal_placement: bool,
}

impl Default for DynParams {
    fn default() -> Self {
        DynParams {
            // 1/λ ≈ 60 days (two months) of capital memory; λ·dt = (1/60)·7 ≈ 0.117 ≪ 1.
            lambda: 1.0 / 60.0,
            n_symbols: 5,
            // k_eff=2: under contention the equilibrium per-block holder count is a
            // few (the lendable budget is rationed), so a k_eff of 2 is the realistic
            // reconstruction threshold — a well-reciprocating node clears it, an
            // exploiter does not (the pillar-1 separation).
            k_eff: 2,
            r_target: 0.90,
            block_volume: 50.0, // ⇒ 10 gb/symbol = the canonical observed V0
            blocks_per_node: 3,
            // Accept band: greedy accept parks holdings near φ≈s_soft; own-data growth
            // then pushes φ down through the band into contention where eviction
            // rations the cream margin (low-G owners' symbols first). Both gaps
            // non-zero (NEW-2 anti-chatter): Δ_evict = 0.10, Δ_accept = 0.10.
            hyst: Hysteresis {
                s_hard: 0.10,
                s_target: 0.20,
                s_soft: 0.30,
            },
            churn_out_prob: 0.002,
            // Greedy cream above the r_target floor (design §A.1): a high-ι block can
            // pull up to n_symbols + cream_max extra redundant symbols, a low-ι one
            // far fewer. Sized so aggregate demand MODERATELY oversubscribes the
            // lendable budget (≈1.3-1.6×) — enough to fill disks and keep eviction
            // firing (utilization→1), but NOT a 3-4× flood that pins every disk to the
            // wall and makes eviction thrash indiscriminately (it must stay SELECTIVE
            // by G so the drop-ranking signal is real). A top-ι block seeks ~9 holders.
            cream_max: 2,
            // Modest SHARED disk (design §A.2). Lendable budget (~70-90gb/node) ×
            // 200 nodes ≈ 15-18 Tb; aggregate floor+cream demand moderately exceeds
            // it (~1.5-2×), so Regime-1 establishes the floor and own-data growth tips
            // the world into contention where eviction rations the cream margin.
            disk_cap_base: 160.0,
            disk_cap_spread: 60.0,
            // Reciprocity-aware placement via the canon retention forecast (default
            // ON). Ranks by surface · retained_depth(obs); reciprocity enters through
            // the canon RetentionPrior, no magic weight. false = pure-surface baseline.
            reciprocal_placement: true,
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

    // ---- (0) own-data growth (design §A.2): own data grows each tick, shrinking
    //          free disk (φ) and driving the drift to contention (utilization→1). ----
    world.grow_own_data();

    // ---- (1) own-data → place (kernel, greedy cream above r_target floor §A.1)
    //          + (2) holder accept/reject (willing AND has room §A.3) ----
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

/// The greedy per-block placement target (design §A.1, W9): the `r_target` FLOOR
/// (`n_symbols`) plus an ι-prioritized CREAM margin. `R_target(ι)` is a FLOOR, NOT a
/// ceiling — above it the owner greedily adds redundant symbols ∝ ι, filling free
/// holder capacity (utilization→1). A top-ι block (ι≈1) pulls the full `cream_max`
/// extra; a low-ι one (ι≈0) pulls ~none. This greed, combined with own-data growth,
/// is what drives the world to contention.
fn target_symbols(n_symbols: usize, cream_max: usize, iota: f64) -> usize {
    let iota = iota.clamp(0.0, 1.0);
    let cream = (cream_max as f64 * iota).round() as usize;
    n_symbols + cream
}

/// (1)+(2): each present owner greedily backs up its own blocks toward the
/// ι-prioritized cream target (design §A.1: `r_target` floor + greedy margin), via
/// the kernel `place`, then the chosen holders accept/reject by WILL (archetype
/// `willing_accept_rate`, seeded Bernoulli §10.A) AND ROOM (`free_disk ≥ v_per_symbol`
/// — the SymbolReject-on-quota fidelity fix, §A.3). Accepted symbols are recorded
/// both as god-view holdings on the holder AND as the block's placements.
fn place_own_data(
    world: &mut World,
    params: &DynParams,
    prior: &SurfacePrior,
    policy: &PlacementPolicy,
) {
    // `policy` is kept on the placement API for symmetry with the kernel, but the
    // contention placement spreads by `addr_subnet` (the AddrCorrelate default the
    // sim always uses); the cap_mode switch is not exercised here.
    let _ = policy;
    let n = world.nodes.len();
    let dt = DAYS_PER_TICK;
    let tick = world.tick;

    for owner in 0..n {
        if !world.nodes[owner].present {
            continue;
        }
        // Snapshot the owner's blocks still BELOW their greedy cream target (design
        // §A.1: greed to fill, not stop at the r_target floor). A block at/above its
        // ι-cream target is satisfied THIS tick.
        let needy: Vec<usize> = world.nodes[owner]
            .own_blocks
            .iter()
            .enumerate()
            .filter(|(_, b)| {
                b.placements.len() < target_symbols(params.n_symbols, params.cream_max, b.iota)
            })
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

            // The greedy cream target for THIS block (floor + ι-margin, §A.1).
            let want = target_symbols(params.n_symbols, params.cream_max, block_iota);
            let have = already.len();
            let still_need = want.saturating_sub(have);
            if still_need == 0 {
                continue;
            }

            // `place_reciprocal` reaches the r_target FLOOR (durability, same r_target
            // stop as the kernel `place`) then greedily fills the cream up to `want`,
            // ranking candidates by a BLENDED key: surface r_hat PRIMARY + a SOFT
            // ι-scoped reciprocity bonus (canon §9.5 / эталон §1). Drive it with a req
            // whose n_symbols is the cream target so the floor logic earns the floor
            // and the harness adds the greedy ι-margin (§A.1).
            let req = BlockReq {
                volume: block_volume,
                n_symbols: want,
                k_eff: params.k_eff,
                tau: DAYS_PER_TICK,
                r_target: params.r_target,
            };

            // Reciprocity enters through the canon retention forecast inside
            // place_reciprocal: each candidate's `obs.g_holder_from_owner` (built from
            // `capital[owner][h].g_ho` by the observer) feeds `retained_depth`. No
            // separate g_ho plumbing — the reciprocity is already in `cand_obs`.
            let chosen_local: Vec<usize> = place_reciprocal(
                &cand_obs,
                &req,
                prior,
                params.reciprocal_placement,
                want,
            );

            let v_per_symbol = req.volume_per_symbol();
            for &local in &chosen_local {
                if world.nodes[owner].own_blocks[bi].placements.len() >= want {
                    break; // reached the greedy cream target for this block
                }
                let holder = cand_idx[local];
                // (2) holder accept/reject — WILL × ROOM (§A.3 fidelity).
                //  * WILL: seeded Bernoulli on the archetype's willingness (§10.A).
                //  * ROOM: the holder must physically have free disk ≥ v_per_symbol —
                //    a full disk yields a SymbolReject{QuotaExceeded}-equivalent. The
                //    old engine had ONLY the will draw and no room check (engine.rs:211),
                //    so a "full" disk still accepted — no quota reject ever fired and
                //    the world could not contend. This is the fidelity fix.
                let mut rng = Rng::derive(
                    world.seed,
                    0xACCE_7711,
                    owner as u64,
                    holder as u64,
                    (tick << 8) ^ bi as u64,
                );
                let willing = rng.unit() < world.nodes[holder].archetype.willing_accept_rate();
                let has_room = world.nodes[holder].free_disk() >= v_per_symbol;
                // Hysteresis ACCEPT-GATE (kernel §6½/§10, NEW-2 damper): a holder only
                // accepts new foreign data when it is ABOVE the accept threshold AND
                // not currently evicting — `accept_ok = φ > s_soft ∧ ¬evicting`. This
                // is what FORBIDS "drop to s_target then immediately re-accept and fall
                // below s_hard again" (the NEW-2 accept↔evict cycle). Without it the
                // greedy cream re-offers every evicted symbol next tick and the relay
                // thrashes. The upper gap (s_soft) is the §A.3 reciprocal admission
                // headroom; the latch bit is threaded through `Node::evict_phase`.
                let accept_ok = world.nodes[holder].phi_free_ratio() > params.hyst.s_soft
                    && !world.nodes[holder].evict_phase.evicting;
                if !willing || !has_room || !accept_ok {
                    continue; // reject: unwilling, full (quota §A.3), or hysteresis gate
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
                // Reciprocity (g_ho / g_oh) is threaded in pos_and_capital on a PoS
                // pass — the eviction-by-G self-balancing (§C.3) plus the quota reject
                // above ARE the reciprocity mechanism (§A.1: NOT a separate accept-gate).
            }
        }
    }
}

/// Reciprocity-aware placement via the CANON retention forecast (canon §9.5 / эталон
/// §1, the main lever of §8; поправка Ильи 2026-06-26). Ranks holders by the canon
/// two-route keep-probability and greedily admits them (≤1 per observable address
/// bucket, the §7 spread), filling to `want` (the floor `R̂ ≥ r_target` is reached
/// along the surface-dominated order the same way the kernel `place` stops, plus the
/// greedy ι-cream margin §A.1). Returns the chosen LOCAL candidate indices.
///
/// **Reciprocity IS the canon retention forecast — NOT an ad-hoc bonus.** Each
/// candidate's per-symbol keep-prob is `surface · retained_depth(obs)` — the rank-
/// marginalized form of the canon K3 `estimate_block_survival_per_symbol` (mod.rs:1269)
/// keep-prob `surface · s(rank; φ_O)`. `retained_depth` (mod.rs:1134) reads
/// `obs.g_holder_from_owner` = the owner's OWN first-hand `capital[owner][h].g_ho`
/// ("how much h stores at us" / "my service to h") and maps it through
/// `sigmoid(standing − pressure − conservatism)` to `φ_O ∈ [~0.18 stranger, ~0.62
/// deeply-reciprocal]`. So a holder that already stores at us forecasts a HIGHER
/// survival for our symbol → it is preferred. This is the canon mechanism that forces
/// reciprocity; the dynamic `place` was using surface-only K2 and IGNORING it (the
/// drift Ilya caught). The ~3.4× multiplicative range keeps surface primary (a far-
/// better-surface stranger still wins) yet concentrates data on reciprocal holders,
/// POPULATING g_ho so §4 eviction drops the non-reciprocal parasite first.
/// `reciprocal = false` recovers the pure-surface kernel behaviour exactly (A/B).
///
/// **Anti-oracle.** Reads only the first-hand `cand_obs` the kernel sees — `surface`
/// and `g_holder_from_owner` are first-hand `FirstHandObs` fields; no peer's private
/// cell, no god-view. Strength is the canon `RetentionPrior`, not a magic weight.
fn place_reciprocal(
    cand_obs: &[viaticum_core::four_r::FirstHandObs],
    req: &BlockReq,
    prior: &SurfacePrior,
    reciprocal: bool,
    want: usize,
) -> Vec<usize> {
    let v_per_symbol = req.volume_per_symbol();
    let tau = req.tau.max(0.0);
    let retention = RetentionPrior::default();

    // Per-candidate keep-prob = surface × retained_depth(obs) (canon two-route, rank-
    // marginalized). retained_depth folds in reciprocity via g_holder_from_owner; with
    // `reciprocal = false` it is surface alone (the pure-surface baseline).
    let score: Vec<f64> = cand_obs
        .iter()
        .map(|obs| {
            let surface = estimate_surface(obs, prior, v_per_symbol, tau).r_hat;
            if reciprocal {
                surface * retained_depth(obs, &retention)
            } else {
                surface
            }
        })
        .collect();
    let mut order: Vec<usize> = (0..cand_obs.len()).collect();
    order.sort_by(|&a, &b| score[b].total_cmp(&score[a]));

    // Greedy admit with the §7 spread (≤1 per addr_subnet bucket — AddrCorrelate, the
    // harness default that matches `place`). Fill to `want`; the floor (R̂ ≥ r_target)
    // is reached along the surface-dominated order, the same stop as the kernel `place`.
    let mut chosen: Vec<usize> = Vec::new();
    let mut occupied: Vec<u32> = Vec::new();
    for &cand in &order {
        if chosen.len() >= want {
            break;
        }
        let bucket = cand_obs[cand].addr_subnet;
        if occupied.contains(&bucket) {
            continue;
        }
        chosen.push(cand);
        occupied.push(bucket);
    }
    chosen
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

        // Reciprocal direction (g_ho) — the eviction-priority key, maintained on the
        // SERVER's OWN first-hand books. This challenge is "holder c.holder served
        // owner c.owner" (G(c.owner ← c.holder), the g_oh just bumped above). The
        // SAME physical service is, from the server c.holder's own ledger, "I
        // (c.holder) stored for c.owner" = `capital[c.holder][c.owner].g_ho`
        // (PairCapital doc: g_ho accrues "when [a node] itself stores for the
        // peer"). So the pass bumps the TRANSPOSE cell's g_ho — NOT
        // capital[c.owner][c.holder].g_ho.
        //
        // Why the transpose, not the same cell (the bug this replaces): the old code
        // bumped capital[c.owner][c.holder].g_ho symmetrically, making g_ho a MIRROR
        // of g_oh (both = holder-served-owner). That inverted the eviction key — a
        // holder h ranking owner O read capital[O][h].g_ho = "h served O" (its OWN
        // service to O) instead of "O served h" (O's reciprocal service to h). It
        // squeezed the owners it had served LEAST rather than the owners who had
        // served IT least, so a free-rider (serves nobody) was NOT dropped first.
        // Maintaining g_ho on the server's-own cell makes capital[O][h].g_ho =
        // "O served h" = the reciprocity key both the placement forecast
        // (retained_depth) and eviction_order read first-hand. Anti-oracle: this is
        // c.holder's OWN record of storage it performed — not a peer's private cell.
        let v_recip = if passed { v_conf } else { 0.0 };
        let cap_t = cap_mut(&mut world.capital, c.holder, c.owner);
        cap_t.g_ho = viaticum_core::four_r::update_capital(cap_t.g_ho, v_recip, params.lambda, dt);
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
    let tick = world.tick;
    let mut any_eviction_this_tick = false;

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
        // The distinct alive-symbol owners on this holder, in a DETERMINISTIC SHUFFLE
        // (keyed by seed, holder, tick) — NOT ascending node-index. `eviction_order`
        // sorts STABLY, so this input order is the tie-break among equal-`g_ho` owners.
        // With ~90% of g_ho still tied at 0 (reciprocity is sparse, эталон §0/§9.13a),
        // an ascending-index order makes the relay sacrifice low-index owners first
        // EVERY tick — a pure node-index artifact that swamps the reciprocity signal
        // and is archetype-correlated whenever the population layout is. The shuffle
        // makes ties index-neutral and spreads them fairly across tied owners over
        // ticks, so only the REAL `g_ho` differences drive who is dropped (эталон §4
        // deeper fix). This SAME slice maps the drop slots back below.
        let owner_of_view: Vec<usize> = {
            let mut owners: Vec<usize> = Vec::new();
            for s in world.nodes[holder].holdings.iter().filter(|s| s.alive) {
                if !owners.contains(&s.owner) {
                    owners.push(s.owner);
                }
            }
            shuffle(
                &mut owners,
                world.seed,
                holder as u64,
                tick,
                0x00E7_1C7B_12A4_u64,
            );
            owners
        };

        // Capture caps by owner: capital[owner][holder].g_ho is THAT OWNER's service
        // to THIS holder ("has the owner stored my data?") — the inter-owner eviction
        // key. The holder ranks owners ASCENDING by it, so an owner that never served
        // this holder (a parasite, g_ho≈0) is squeezed first. (PairCapital doc: g_ho
        // accrues when the owner itself stores for the holder.)
        let views = observer::observe_eviction_views(
            &world.nodes[holder],
            &owner_of_view,
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
        // back to the god-view HeldSymbol and mark it dead. `owner_of_view` (the
        // shuffled slice above) is the single source of truth for the view order.

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
                // The reciprocity key at drop time (diagnostic): did this drop land on
                // a non-reciprocal (g_ho≈0) placement or a reciprocal one?
                let g_ho_at_drop = world.capital[owner_idx][holder].g_ho;
                if let Some(hs) = world.nodes[holder]
                    .holdings
                    .iter_mut()
                    .find(|s| s.alive && s.owner == owner_idx && s.block == block)
                {
                    hs.alive = false;
                    // Log the eviction event (design §D.1 drop-ranking + §E): which
                    // holder dropped which owner's symbol, this tick.
                    any_eviction_this_tick = true;
                    world
                        .eviction_log
                        .push(crate::sim_dynamic::generator::EvictionEvent {
                            tick,
                            holder,
                            owner: owner_idx,
                            g_ho_at_drop,
                        });
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
    if any_eviction_this_tick {
        world.ticks_with_eviction += 1;
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
