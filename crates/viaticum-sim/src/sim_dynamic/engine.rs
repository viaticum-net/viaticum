//! `sim_dynamic` engine — the dynamic time-loop over the god-view world.
//!
//! Each tick (design §6 + §10 + world-v2 §9) runs, in order:
//!   0. **own-data growth** (§A.2) + **incremental joins** (§9.1: activate nodes whose
//!      seeded `joined_tick` has arrived).
//!   1. **resync placements** (drop dead/departed holders from owners' bookkeeping)
//!      then **place** (kernel `place_reciprocal`, floor + cream) under a per-node
//!      **bandwidth budget** `U` (§9.2): ≤ `U/v_per_symbol` symbols placed per node per
//!      tick, ι-priority, the rest carried to later ticks. Holder accept/reject by WILL
//!      × ROOM, with **preemption** under contention (§9 fixes / A.12-2).
//!   2. **PoS-challenge + capital update** (§9.4 ONE physics): PoS-pass ⟺ the symbol is
//!      alive ∧ the holder is online. No `retained_edge`; archetype aggression is NOT in
//!      the PoS outcome (it lives ONLY in churn). The A.1 leaky decay is applied to ALL
//!      capital pairs each tick (idle/dead relationships drain), not just active ones.
//!   3. **eviction** when `φ < s_soft` via `eviction_order` (§10.G, NOTE1 snapshot).
//!   4. **churn** — nodes depart by archetype (aggression raises the rate); held
//!      symbols die.
//!
//! Anti-oracle: the kernel is called ONLY through the observer (first-hand). The
//! engine knows archetypes / tiers / join schedule (god-view) but passes them to NO
//! kernel function — it uses them only to drive BEHAVIOUR.

use viaticum_core::four_r::{
    BlockReq, BurnParams, DepthParams, Hysteresis, NodeLocal, PlacementPolicy, RetentionCap,
    RetentionPrior, SurfacePrior, apply_burn, capital_steady_state, estimate_surface,
    eviction_order, kappa_key, retained_depth, update_depth, update_suspicion, update_v_dem,
};

use crate::generator::Rng;
use crate::sim_dynamic::generator::{
    BlockPlacement, DAYS_PER_TICK, EvictionEvent, HeldSymbol, Node, OwnBlock, PairCapital,
    RepairStat, SilentLoss, World, online,
};
use crate::sim_dynamic::observer::{self, ObsAddr};

/// Tunable dials for one dynamic run.
#[derive(Debug, Clone, Copy)]
pub struct DynParams {
    /// Capital leak rate `λ` (per day). `1/λ` is the capital memory in days —
    /// months (design §10.C). With weekly `dt`, `λ·dt < 1` holds with room.
    pub lambda: f64,
    /// A.4 SLOW leak rate `λ_slow` (per day) for the loyalty depth `D`. `1/λ_slow` is
    /// the depth memory — `τ_slow ≈ 6 months` (§13 default `1/180`), MUCH slower than
    /// the fast capital `λ` so a deep partner's floor decays over months, not weeks.
    /// With weekly `dt`, `λ_slow·dt = 7/180 ≈ 0.039 < 1`.
    pub lambda_slow: f64,
    /// A.3 demonstrated-scale ratchet leak `λ_dem` (per day) for `V_dem` — the SLOWEST
    /// leak in the model, `λ_dem ≪ λ` and `≪ λ_slow`. `1/λ_dem` is how long a
    /// demonstrated scale survives with no re-confirmation. §13 default `1/365`
    /// (`τ_dem ≈ 1 year`), an OPEN calibration guess. With weekly `dt`,
    /// `λ_dem·dt = 7/365 ≈ 0.019 < 1`.
    pub lambda_dem: f64,
    /// A.14 depth-floor weight `w_d`: the W10 loyalty floor in the κ_O eviction key is
    /// `w_d·min(D/d_ref, 1)·g*` — a silent-but-deep partner ranks as if it carried
    /// `w_d·g*` of fast capital. §13 default 0.5.
    pub depth_w_d: f64,
    /// A.14 depth reference `d_ref` in DAYS: the depth (relative to `V_sym`) at which
    /// the loyalty floor saturates. The kernel `DepthParams.d_ref` is this ×
    /// `v_per_symbol` gb·days. §13 default 365 (≈ one year of a single symbol).
    pub depth_ref_days: f64,
    /// Р-7 (A.14) reciprocity price `c_recip` in DAYS: the holder-side volume cap is
    /// `V_ret(O) = V_free + κ_O/c_recip` ([`RetentionCap`]). κ_O is in gb·days and
    /// V_ret in gb, so `c_recip` MUST be a DURATION (WARN-1 — a dimensionless value
    /// would drift with λ). §13 default ≈ 30 days ("+1 gb of retention per 30 gb·days
    /// of lived service above V_free"). `≤ 0` DISABLES the cap (WARN-1 guard).
    pub c_recip_days: f64,
    /// Р-7 (A.14) free retention floor `V_free`, in UNITS of `v_per_symbol`: the
    /// kernel `RetentionCap.v_free` is this × `v_per_symbol` gb. Every owner keeps this
    /// much for free (bootstrap-by-storage entry; the newcomer's first backup survives).
    /// **OPEN calibration guess (spec 3b): `2.0` = 2 symbols' worth** — flagged for
    /// review, NOT a settled canon value.
    pub v_free_symbols: f64,
    /// A.2 (транше 4 / §13): the WEAK announced-drop burn fraction `b_ann`. §13-OPEN
    /// default `0.05` (`b_ann ≪ b_max`). Feeds [`BurnParams`].
    pub burn_b_ann: f64,
    /// A.2 (транше 4 / §13): the STRONG silent-loss burn fraction `b_max`. §13 default
    /// **1.0** (confirmed by Ilya 2026-07-07 — a fully silent total loss zeroes the
    /// owner's reliability capital for that holder).
    pub burn_b_max: f64,
    /// A.2 (транше 4 / §13): repair latency `τ_rep` in DAYS for the head-start
    /// forgiveness axis. Default `2·DAYS_PER_TICK = 14` (≈ 2 ticks of repair latency).
    /// In the sim ALL evictions are instantaneous (no advance DropNotice), so the caller
    /// always passes `t_n = 0` and this dial does not change sim behaviour — it is
    /// transcribed for the daemon (where an advance DropNotice carries a real head-start).
    pub burn_tau_rep: f64,
    /// A.5 (транше 4 / §13): suspicion forget rate `μ` (per day). Default `1/14`
    /// (`τ_σ ≈ 2 weeks ≪ τ_g = 60 d`: suspicion is forgotten fast). Feeds
    /// [`update_suspicion`] in the W2 sweep.
    pub sigma_mu: f64,
    /// A.5 (транше 4 / §13): suspicion jump amplitude `j_σ` on a confirmed silent defect.
    /// Default `0.5`. A lone PoS-timeout jumps only `j_σ/5` (weak, транше-4 fix).
    pub sigma_j: f64,
    /// A.2/A.7 (транше-4 fix / §13): decay rate `λ_drop` (per day) of the owner-side
    /// `drop_ann`/`drop_silent` retention counters — "the system must forgive" (Ilya
    /// 2026-07-07). Default `1/56` (τ ≈ 8 weeks ≈ the PoS-window scale of 8 ticks): a
    /// single drop fades out of the retention forecast rather than being an eternal penalty
    /// under windowed PoS counters (WARN-1 review т4). OPEN calibration, flagged for Ilya.
    pub lambda_drop: f64,
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
    /// Cream margin (world-v2 §9.3, W9): extra redundant symbols an owner greedily
    /// places ABOVE the `r_target` floor, ι-prioritized (up to `⌈cream_max·ι⌉`). Cream
    /// is placed with the owner's LEFTOVER per-tick bandwidth once the floor is met; it
    /// is NOT counted in the floor-durability metric and does NOT trigger repair.
    pub cream_max: usize,
    /// Base physical disk capacity (gb), SHARED between own data and foreign holdings
    /// (design §A.2). Deliberately modest relative to the aggregate demand.
    pub disk_cap_base: f64,
    /// Per-node uniform spread (gb) added to `disk_cap_base` (heterogeneous disks).
    pub disk_cap_spread: f64,
    /// Reciprocity-aware placement via the CANON retention forecast (canon §9.5 /
    /// эталон §1). When `true`, placement ranks candidates by `surface · retained_depth`
    /// (folds in `capital[owner][h].g_ho`), so a holder that already stores at us is
    /// preferred. `false` ⇒ pure-surface baseline (A/B).
    pub reciprocal_placement: bool,
    /// Preemptive-accept margin as a DIMENSIONLESS fraction `θ_p` of the per-symbol
    /// steady-state capital `g* = capital_steady_state(v_per_symbol, λ)` (WARN-1, A.12-2).
    /// A contended holder admits a new owner `O` only by displacing its least-reciprocal
    /// current owner `O_min`, and only if `g_ho(O) > g_ho(O_min) + θ_p·g*`. A NEGATIVE or
    /// non-finite `θ_p` DISABLES preemption (WARN-2 — a negative margin must not merely
    /// WEAKEN the gate). Default `0.2`.
    pub preempt_theta: f64,
    /// World-v2 §9.1 toggle: incremental arrival. `true` ⇒ nodes join over `[0, T_join]`
    /// per a seeded schedule and each node's blocks MATURE over time; `false` ⇒ every
    /// node and block is live at t=0 (the one-shot world, for A/B).
    pub incremental: bool,
    /// §9.1: fraction of nodes live at t=0 (the bootstrap set `n0`). Rest join later.
    pub n0_frac: f64,
    /// §9.1: nodes finish joining by `round(join_horizon_ticks · t_join_frac)`.
    pub t_join_frac: f64,
    /// §9.1: the run horizon (ticks) the join schedule is spread over. Kept on the dials
    /// (not the world) so `build_world` can compute the schedule deterministically.
    pub join_horizon_ticks: u64,
    /// §9.1: block maturation cadence. A node's block at position `b` becomes eligible
    /// for placement at `joined_tick + b·maturation_ticks_per_block` — its placement
    /// DEMAND appears in portions over time (own-data accumulating into new backups),
    /// with `blocks_per_node` the ceiling. `0` ⇒ all blocks eligible at join.
    pub maturation_ticks_per_block: u64,
    /// World-v2 §9.2 upload bandwidth `U` (gb/tick). A node places ≤ `⌊U/v_per_symbol⌋`
    /// symbols per tick (floored at 1 so a node always makes SOME progress); the rest of
    /// its placement demand carries to later ticks (cold-backup: initial backup stretched
    /// over days-weeks). `∞` ⇒ unlimited (the one-shot world, for A/B).
    pub bandwidth_u: f64,
    /// World-v2 §9.3 toggle: place cream (over-the-floor redundancy) with leftover
    /// bandwidth. `false` ⇒ floor only (the degenerate world has no new-pair entry
    /// channel).
    pub cream_enabled: bool,
    /// World-v2 §9.5 toggle: GIVER-PRIORITY owner-order (an owner-order PROXY, NOT literal
    /// per-holder pairwise familiarity — WARN-3 honesty). When `true`, owners are processed
    /// in DESCENDING order of TOTAL rendered service `Σ_h g_ho` (net givers place before
    /// net takers, so under contention givers win scarce slots first). `false` ⇒ a neutral
    /// seeded shuffle (no index bias). This is a GLOBAL giver rank, NOT the spec's ideal
    /// "each holder prefers owners that served IT" (`capital[O][h].g_ho`) — a true
    /// per-holder offer queue does not fit the owner-pull (budget-on-success) architecture
    /// without a full matching pass. In abundance it barely changes anything; it bites only
    /// for scarce slots under contention.
    pub giver_priority_order: bool,
    /// World-v2 §9 A/B toggle (phase-A decision Р-2 / A.7). Р-2 is ACCEPTED: the
    /// recalibrated ceiling `sigmoid(3.7−1.5)=0.900` is now CANON and lives in
    /// `RetentionPrior::default()` (the kernel, Phase-B transcription). `true` (the
    /// DEFAULT) ⇒ canon 0.900. `false` ⇒ A/B CONTROL only: pins `standing_scale=2.0` to
    /// reproduce the pre-Р-2 baseline `sigmoid(2.0−1.5)=0.622`, for measuring the
    /// recalibration's separate contribution to the share-A>0 trajectory.
    pub recalibrated_retention: bool,
    /// Repair-storm §7 detection latency: the PoS-cadence window (ticks) over which an
    /// owner notices that one of its ALREADY-BACKED-UP blocks has dropped below its
    /// `n_symbols` floor. `0` ⇒ INSTANT detection (the owner refills the very next tick,
    /// the previous behaviour — bit-identical, no RNG drawn). `> 0` ⇒ LATENT: each
    /// (owner, block) deficit episode gets a SEEDED uniform offset in `[0, max]` ticks
    /// before the owner acts, so a synchronous correlated-holder-death shock is
    /// discovered at spread-out ticks (the crux of the "latency smears the shock"
    /// hypothesis). Applies only to REPAIR (a block that met its floor then lost
    /// holders), never to an initial backup (`floor_ever_met == false`).
    pub repair_detection_delay_max: u64,
}

impl Default for DynParams {
    fn default() -> Self {
        DynParams {
            lambda: 1.0 / 60.0,
            // A.4 / §13: τ_slow ≈ 6 months, w_d = 0.5, d_ref ≈ 1 year·V_sym.
            lambda_slow: 1.0 / 180.0,
            // A.3 / §13: τ_dem ≈ 1 year (the slowest leak; OPEN calibration guess).
            lambda_dem: 1.0 / 365.0,
            depth_w_d: 0.5,
            depth_ref_days: 365.0,
            // Р-7 (A.14 / §13): c_recip ≈ 30 days (Ilya); V_free = 2·v_per_symbol is an
            // OPEN calibration guess (spec 3b) — "first backup of a newcomer survives".
            c_recip_days: 30.0,
            v_free_symbols: 2.0,
            // A.2 / A.5 (транше 4 / §13): §13 defaults (b_max confirmed 1.0 by Ilya
            // 2026-07-07; the rest are OPEN calibration guesses flagged for Ilya).
            burn_b_ann: 0.05,
            burn_b_max: 1.0, // silent total loss zeroes the reliability capital (§13)
            burn_tau_rep: 2.0 * DAYS_PER_TICK, // ≈ 2 ticks repair latency (sim t_n always 0)
            sigma_mu: 1.0 / 14.0, // τ_σ ≈ 2 weeks ≪ τ_g = 60 d
            sigma_j: 0.5,
            lambda_drop: 1.0 / 56.0, // τ ≈ 8 weeks ≈ PoS-window scale ("system forgives")
            n_symbols: 5,
            k_eff: 2,
            r_target: 0.90,
            block_volume: 50.0, // ⇒ 10 gb/symbol = the canonical observed V0
            blocks_per_node: 3,
            hyst: Hysteresis {
                s_hard: 0.10,
                s_target: 0.20,
                s_soft: 0.30,
            },
            churn_out_prob: 0.002,
            cream_max: 2,
            disk_cap_base: 160.0,
            disk_cap_spread: 60.0,
            reciprocal_placement: true,
            // Dimensionless preemption margin (WARN-1): θ_p·g*. Default 0.2 ⇒ the newcomer
            // entry latency after it starts serving is ≈ θ_p/λ ≈ 12 days ≈ 2 weeks (A.12).
            preempt_theta: 0.2,
            // World-v2 defaults = the NEW behaviour (§9). A/B recovers the old world by
            // incremental=false + bandwidth_u=∞ + cream_enabled=false.
            incremental: true,
            n0_frac: 0.20,
            t_join_frac: 0.50,
            join_horizon_ticks: 130,
            maturation_ticks_per_block: 6,
            bandwidth_u: 20.0, // 2 symbols/tick at the default 10 gb/symbol
            cream_enabled: true,
            giver_priority_order: true,
            // Р-2 ACCEPTED ⇒ recalibrated ceiling 0.900 is canon (default kernel prior).
            // `false` is the A/B control that dials back to the pre-Р-2 0.622 baseline.
            recalibrated_retention: true,
            // Instant repair detection = the previous behaviour (owner refills next tick).
            // The repair-storm §7 sweep raises this to model the PoS-cadence detection lag.
            repair_detection_delay_max: 0,
        }
    }
}

/// The asserted numerical-stability guard (design §10.C, mod.rs:176): `λ·dt < 1`.
pub fn assert_lambda_dt_stable(lambda: f64, dt_days: f64) {
    let prod = lambda * dt_days;
    assert!(
        prod < 1.0,
        "λ·dt = {prod} must be < 1 for monotone capital relaxation (design §10.C / mod.rs:176)"
    );
}

/// The retention prior fed to `retained_depth` (world-v2 §9 A/B toggle / A.7). Р-2 is
/// ACCEPTED, so the recalibrated ceiling `sigmoid(3.7−1.5)=0.900` is CANON and is exactly
/// what `RetentionPrior::default()` (the kernel, Phase-B transcription) now encodes — the
/// DEFAULT path returns it unchanged. `recalibrated_retention == false` is an A/B CONTROL
/// that pins `standing_scale=2.0` to reproduce the pre-Р-2 baseline `sigmoid(2.0−1.5)=0.622`
/// (the stranger floor stays `sigmoid(−1.5)=0.182` in both; the known-vs-stranger
/// multiplier is ~4.9× at canon vs ~3.4× at baseline). The KERNEL is not toggled — the
/// prior is an INPUT parameter.
pub fn retention_prior(params: &DynParams) -> RetentionPrior {
    if params.recalibrated_retention {
        // Canon (Р-2): ceiling 0.900 — the recalibrated prior IS the kernel default now.
        RetentionPrior::default()
    } else {
        // A/B control ONLY: pre-Р-2 baseline (standing_scale 2.0 ⇒ ceiling 0.622).
        RetentionPrior {
            standing_scale: 2.0,
            ..RetentionPrior::default()
        }
    }
}

/// The A.14 κ_O depth params (holder-independent): the kernel does not know λ/V_sym,
/// so the caller carries `g*` and the days→gb·days `d_ref` conversion. SHARED by
/// `run_eviction` (inter-owner rank + Р-7 cap) and `admit_offer` (preemption + accept
/// guard) so all three holder-side mechanisms read the SAME κ_O (B-1, fix ADV2-D2).
fn depth_params_of(params: &DynParams, v_per_symbol: f64) -> DepthParams {
    DepthParams {
        w_d: params.depth_w_d,
        d_ref: params.depth_ref_days * v_per_symbol,
        g_star: capital_steady_state(v_per_symbol, params.lambda),
    }
}

/// The Р-7 (A.14) holder-side volume cap `V_ret = V_free + κ_O/c_recip` in kernel
/// units: `V_free = v_free_symbols·v_per_symbol` gb, `c_recip = c_recip_days` days.
/// `c_recip ≤ 0` DISABLES the cap ([`RetentionCap::disabled`], WARN-1 guard).
fn retention_cap(params: &DynParams, v_per_symbol: f64) -> RetentionCap {
    RetentionCap {
        v_free: params.v_free_symbols * v_per_symbol,
        c_recip: params.c_recip_days,
    }
}

/// The A.2 burn params (транше 4 / §13): announced ≪ silent, τ_rep = repair latency.
fn burn_params_of(params: &DynParams) -> BurnParams {
    BurnParams {
        b_ann: params.burn_b_ann,
        b_max: params.burn_b_max,
        tau_rep: params.burn_tau_rep,
    }
}

/// Volume (gb) of `owner`'s ALIVE symbols currently on `holder` — the burn's `V_held`
/// (the base the lost fraction `V_lost/V_held` is measured against). Computed BEFORE the
/// lost symbol is marked dead, so it includes the symbol about to be lost.
fn owner_alive_volume_on(world: &World, owner: usize, holder: usize) -> f64 {
    world.nodes[holder]
        .holdings
        .iter()
        .filter(|s| s.alive && s.owner == owner)
        .map(|s| s.volume)
        .sum()
}

/// A.2 ANNOUNCED burn: a LIVE holder dropped `owner`'s symbol (eviction / preemption
/// victim) — the protocol sends a DropNotice, so from the owner's seat this is an
/// ANNOUNCED loss with head-start `t_n = 0` in the sim (evictions are instantaneous).
/// Burns the owner-side reliability capital `g_oh` = `G(O←h)` (the owner's record of the
/// holder's service TO IT — the reliability evidence, decision_model §1), bumps the
/// `drop_ann` retention-forecast counter (C2FARM-3), and tallies the event.
///
/// **Direction (traced, not guessed — 3a discipline):** the write is to
/// `capital[owner][holder].g_oh`, the cell that accumulates "this HOLDER served this
/// OWNER" (`observer::observe_pair` reads it into `g_owner_from_holder`). This is the
/// reliability capital A.2 burns, NOT the reciprocal `g_ho` (the owner's own service).
/// `v_held` is `owner`'s alive volume on `holder` BEFORE the drop; `v_lost` is the
/// dropped symbol's volume.
fn apply_announced_burn(
    world: &mut World,
    owner: usize,
    holder: usize,
    v_lost: f64,
    params: &DynParams,
) {
    let v_held = owner_alive_volume_on(world, owner, holder);
    let p = burn_params_of(params);
    let cell = &mut world.capital[owner][holder];
    cell.g_oh = apply_burn(cell.g_oh, &p, true, 0.0, v_lost, v_held);
    cell.drop_ann += 1.0; // leaky counter (decayed in the W2 sweep by λ_drop)
    world.burn_ann_count += 1;
}

/// Per-symbol volume (gb) for the default block: `block_volume / n_symbols`.
fn v_per_symbol_of(params: &DynParams) -> f64 {
    if params.n_symbols > 0 {
        params.block_volume / params.n_symbols as f64
    } else {
        params.block_volume
    }
}

/// World-v2 §9.2: how many symbols a node may upload this tick = `⌊U/v_per_symbol⌋`
/// (floored at 1 so a node always makes some progress; `∞` ⇒ unlimited).
fn symbols_per_tick(u: f64, v_per_symbol: f64) -> usize {
    if !u.is_finite() || v_per_symbol <= 0.0 {
        return usize::MAX;
    }
    ((u / v_per_symbol).floor() as usize).max(1)
}

/// World-v2 §9.2 per-node upload budget (symbols/tick) for these params. The repair-
/// storm §7 aggregate-bandwidth ceiling is this × the present-node count (`usize::MAX`
/// for the unlimited one-shot world — the storm always runs the finite-`U` v2 regime).
pub fn per_node_upload_budget(params: &DynParams) -> usize {
    symbols_per_tick(params.bandwidth_u, v_per_symbol_of(params))
}

/// World-v2 §9.1: is the block at position `block_pos` of a node that joined at
/// `joined_tick` eligible for placement at `tick`? (demand appears in portions).
fn block_mature(joined_tick: u64, block_pos: usize, tick: u64, params: &DynParams) -> bool {
    if !params.incremental {
        return true;
    }
    tick >= joined_tick + (block_pos as u64) * params.maturation_ticks_per_block
}

/// Preemption enabled? (WARN-2: a negative / non-finite `θ_p` DISABLES it.)
fn preempt_enabled(params: &DynParams) -> bool {
    params.preempt_theta.is_finite() && params.preempt_theta >= 0.0
}

/// Repair-storm §7 detection: has the owner NOTICED (via its PoS cadence) that a
/// below-floor block needs repair, given the deficit was first observed at
/// `deficit_since`? Detection fires at `deficit_since + offset`, where `offset` is a
/// SEEDED uniform integer in `[0, delay_max]` per deficit episode — spreading the
/// discovery of a synchronous correlated-holder-death shock across the cadence window
/// (the "latency smears the shock" mechanism under test). `delay_max = 0` ⇒ instant.
fn repair_detected(
    seed: u64,
    owner_id: u64,
    block_id: usize,
    deficit_since: u64,
    tick: u64,
    delay_max: u64,
) -> bool {
    tick >= deficit_since + detection_offset(seed, owner_id, block_id, deficit_since, delay_max)
}

/// The seeded detection offset (ticks) for one deficit episode: a uniform integer in
/// `[0, max]`, stable within the episode (keyed on `deficit_since`). `max = 0` ⇒ 0.
/// A dedicated salted stream so it never perturbs the placement / PoS / churn draws.
fn detection_offset(
    seed: u64,
    owner_id: u64,
    block_id: usize,
    deficit_since: u64,
    max: u64,
) -> u64 {
    if max == 0 {
        return 0;
    }
    let r = Rng::derive(
        seed ^ REPAIR_DETECT_SALT,
        owner_id,
        block_id as u64,
        deficit_since,
        0,
    )
    .unit();
    ((r * (max as f64 + 1.0)).floor() as u64).min(max)
}

/// Salt for the repair-detection RNG stream (kept off the placement/PoS/churn streams).
const REPAIR_DETECT_SALT: u64 = 0x5E17_D37E_C7ED_10AD;

/// Run ONE tick of the dynamic loop (design §6 + §10 + world-v2 §9). Mutates in place.
pub fn step(world: &mut World, params: &DynParams, prior: &SurfacePrior, policy: &PlacementPolicy) {
    assert_lambda_dt_stable(params.lambda, DAYS_PER_TICK);
    // The slow loyalty-depth leak (A.4) obeys the SAME stability guard.
    assert_lambda_dt_stable(params.lambda_slow, DAYS_PER_TICK);
    // The A.3 demonstrated-scale ratchet leak `λ_dem` (slowest of the three).
    assert_lambda_dt_stable(params.lambda_dem, DAYS_PER_TICK);
    // The A.2/A.7 drop-counter forgiveness leak `λ_drop` obeys the SAME stability guard.
    assert_lambda_dt_stable(params.lambda_drop, DAYS_PER_TICK);
    let _ = policy; // kept on the API for symmetry; the sim always spreads by addr_subnet
    let tick = world.tick;

    // (0a) own-data growth + (0b) incremental joins (§9.1).
    world.grow_own_data();
    activate_joins(world);

    // (1a) resync placements (drop dead) + (1b) bandwidth-limited place (floor + cream).
    resync_placements(world);
    let retention = retention_prior(params);
    // Repair-storm §7: reset the per-tick repair instrument before the placement pass
    // fills it (owners repairing, detected deficit, symbols repaired this tick).
    world.repair_stat = RepairStat::default();
    place_own_data(world, params, prior, &retention);

    // (2) PoS-challenge sampling + capital update, A.1 decay on all pairs (§9.4).
    pos_and_capital(world, params);

    // (3) eviction when φ < s_soft (kernel eviction_order + latch).
    run_eviction(world, params);

    // (4) churn: departures by archetype (aggression raises the departure rate, §9.4).
    churn(world, params);

    world.tick = tick + 1;
}

/// World-v2 §9.1: activate any node whose seeded `joined_tick` has arrived. A node that
/// is absent at tick T with `joined_tick == T` can only be a not-yet-joined node (churn
/// fires only on PRESENT nodes, so a departed node was joined earlier) — unambiguous.
fn activate_joins(world: &mut World) {
    let tick = world.tick;
    for node in world.nodes.iter_mut() {
        if !node.present && node.joined_tick == tick {
            node.present = true;
        }
    }
}

/// Capital index helper: mutable handle to the `[owner][holder]` pair state.
fn cap_mut(capital: &mut [Vec<PairCapital>], owner: usize, holder: usize) -> &mut PairCapital {
    &mut capital[owner][holder]
}

/// Count a block's ALIVE symbols across the network, split into (floor, cream).
fn alive_block_counts(world: &World, owner: usize, block_id: usize) -> (usize, usize) {
    let mut floor = 0usize;
    let mut cream = 0usize;
    for node in &world.nodes {
        if let Some(s) = node
            .holdings
            .iter()
            .find(|s| s.alive && s.owner == owner && s.block == block_id)
        {
            if s.cream {
                cream += 1;
            } else {
                floor += 1;
            }
        }
    }
    (floor, cream)
}

/// (1b): each present owner backs up its own blocks under a per-tick bandwidth budget
/// (§9.2), FLOOR first (ι-priority) then CREAM with leftover bandwidth (§9.3). Owner
/// processing order is the accept-toggle proxy (§9.5). Uses the kernel retention forecast
/// for reciprocity-aware ranking.
fn place_own_data(
    world: &mut World,
    params: &DynParams,
    prior: &SurfacePrior,
    retention: &RetentionPrior,
) {
    let n = world.nodes.len();
    let tick = world.tick;
    let v_per_symbol = v_per_symbol_of(params);

    // Owner order (§9.5 GIVER-PRIORITY proxy, WARN-3): a neutral seeded shuffle (removes
    // the node-index bias the old 0..n loop had), then — when giver_priority_order — a
    // STABLE sort by descending TOTAL rendered service Σ_h g_ho so net givers place first.
    // This is an owner-order proxy, NOT literal per-holder pairwise familiarity.
    let mut owners: Vec<usize> = (0..n).filter(|&o| world.nodes[o].present).collect();
    shuffle(&mut owners, world.seed, OWNER_ORDER_TAG, tick, 0);
    if params.giver_priority_order {
        let mut zipped: Vec<(usize, f64)> = owners
            .iter()
            .map(|&o| (o, (0..n).map(|h| world.capital[o][h].g_ho).sum::<f64>()))
            .collect();
        zipped.sort_by(|a, b| b.1.total_cmp(&a.1)); // stable ⇒ ties keep the shuffle
        owners = zipped.into_iter().map(|(o, _)| o).collect();
    }

    for owner in owners {
        let mut budget = symbols_per_tick(params.bandwidth_u, v_per_symbol);
        if budget == 0 {
            continue;
        }
        // Block positions by descending ι (tie by position) — the ι-priority queue.
        let mut border: Vec<usize> = (0..world.nodes[owner].own_blocks.len()).collect();
        border.sort_by(|&a, &b| {
            world.nodes[owner].own_blocks[b]
                .iota
                .total_cmp(&world.nodes[owner].own_blocks[a].iota)
                .then(a.cmp(&b))
        });

        // FLOOR phase: fill each mature block to n_symbols, ι-priority, within budget.
        // Repair-storm §7 detection gate: a block that ALREADY met its floor but has now
        // dropped below it (a REPAIR after a holder death) is only refilled once the
        // owner has NOTICED the loss — instantly (delay_max=0) or after a seeded per-block
        // cadence offset (latent). An INITIAL backup (never met floor) has no latency.
        let owner_id = world.nodes[owner].id;
        let mut owner_repaired = false;
        for &bp in &border {
            // P1 (world-v3 axis 8): a source-less block (owner suffered a Disaster) can
            // NEVER be repaired — no source to re-encode from, only restore from holders.
            if world.nodes[owner].own_blocks[bp].to_restore {
                continue;
            }
            if !block_mature(world.nodes[owner].joined_tick, bp, tick, params) {
                continue;
            }
            let block_id = world.nodes[owner].own_blocks[bp].id;
            let (floor, _) = alive_block_counts(world, owner, block_id);
            if floor >= params.n_symbols {
                // Floor met (or over): mark reached, clear any deficit episode.
                let b = &mut world.nodes[owner].own_blocks[bp];
                b.floor_ever_met = true;
                b.floor_deficit_since = None;
                continue;
            }
            // Below floor. Repair (met floor before) is detection-gated; a first backup
            // (floor_ever_met == false) is always eligible (no PoS-detection latency).
            let is_repair = world.nodes[owner].own_blocks[bp].floor_ever_met;
            let detected = if is_repair && params.repair_detection_delay_max > 0 {
                let since = *world.nodes[owner].own_blocks[bp]
                    .floor_deficit_since
                    .get_or_insert(tick);
                repair_detected(
                    world.seed,
                    owner_id,
                    block_id,
                    since,
                    tick,
                    params.repair_detection_delay_max,
                )
            } else {
                true
            };
            if is_repair && detected {
                world.repair_stat.detected_deficit_symbols += params.n_symbols - floor;
                owner_repaired = true;
            }
            if !detected || budget == 0 {
                continue; // loss not yet noticed, or no upload budget left this tick
            }
            let mut cur = floor;
            while budget > 0 && cur < params.n_symbols {
                if try_place_one_symbol(world, owner, bp, false, params, prior, retention) {
                    budget -= 1;
                    cur += 1;
                    if is_repair {
                        world.repair_stat.symbols_repaired += 1;
                    }
                } else {
                    break; // no admissible holder this tick for this block
                }
            }
        }
        if owner_repaired {
            world.repair_stat.owners_repairing += 1;
        }

        // CREAM phase: leftover bandwidth → over-the-floor redundancy (§9.3).
        if params.cream_enabled {
            for &bp in &border {
                if budget == 0 {
                    break;
                }
                // P1 (world-v3 axis 8): no cream repair for a source-less block either.
                if world.nodes[owner].own_blocks[bp].to_restore {
                    continue;
                }
                if !block_mature(world.nodes[owner].joined_tick, bp, tick, params) {
                    continue;
                }
                let iota = world.nodes[owner].own_blocks[bp].iota.clamp(0.0, 1.0);
                let cream_target = (params.cream_max as f64 * iota).round() as usize;
                let block_id = world.nodes[owner].own_blocks[bp].id;
                let (floor, mut cream) = alive_block_counts(world, owner, block_id);
                if floor < params.n_symbols {
                    continue; // floor not yet met → no cream for this block yet
                }
                while budget > 0 && cream < cream_target {
                    if try_place_one_symbol(world, owner, bp, true, params, prior, retention) {
                        budget -= 1;
                        cream += 1;
                    } else {
                        break;
                    }
                }
            }
        }
    }
}

/// Try to place ONE symbol of `owner`'s block (position `block_pos`) on the best
/// admissible holder (§9.2 per-symbol placement). Ranks candidates by the canon
/// keep-probability (`place_reciprocal`), then walks them in order running the holder
/// accept/preemption gate; on the first acceptance it records the god-view holding +
/// placement (flagged `cream`) and returns `true`. Returns `false` if none admit.
fn try_place_one_symbol(
    world: &mut World,
    owner: usize,
    block_pos: usize,
    cream: bool,
    params: &DynParams,
    prior: &SurfacePrior,
    retention: &RetentionPrior,
) -> bool {
    let n = world.nodes.len();
    let tick = world.tick;
    let block_id = world.nodes[owner].own_blocks[block_pos].id;
    let block_iota = world.nodes[owner].own_blocks[block_pos].iota;
    let block_volume = world.nodes[owner].own_blocks[block_pos].volume;
    let v_per_symbol = if params.n_symbols > 0 {
        block_volume / params.n_symbols as f64
    } else {
        block_volume
    };

    // Holders already storing this block (spread: ≤1 symbol per addr bucket per block).
    let mut occupied: Vec<u32> = Vec::new();
    let mut already: Vec<usize> = Vec::new();
    for (h, node) in world.nodes.iter().enumerate() {
        if node
            .holdings
            .iter()
            .any(|s| s.alive && s.owner == owner && s.block == block_id)
        {
            already.push(h);
            occupied.push(node.addr_subnet);
        }
    }
    let mut cand_idx: Vec<usize> = (0..n)
        .filter(|&h| h != owner && world.nodes[h].present && !already.contains(&h))
        .collect();
    if cand_idx.is_empty() {
        return false;
    }
    // Shuffle the candidate order per (owner, block, attempt) — attempts differ via the
    // already-placed count so successive symbols of the same block do not tie-order the
    // same way. Deterministic in the seed.
    shuffle(
        &mut cand_idx,
        world.seed,
        owner as u64,
        (tick << 20) ^ (block_pos as u64),
        already.len() as u64,
    );

    let cand_nodes: Vec<&Node> = cand_idx.iter().map(|&h| &world.nodes[h]).collect();
    let caps: Vec<&PairCapital> = cand_idx.iter().map(|&h| &world.capital[owner][h]).collect();
    let cand_obs = observer::observe_candidates(&cand_nodes, &caps, DAYS_PER_TICK);

    let req = BlockReq {
        volume: block_volume,
        n_symbols: params.n_symbols.max(1),
        k_eff: params.k_eff,
        tau: DAYS_PER_TICK,
        r_target: params.r_target,
        // sim_dynamic uses place_reciprocal (its own placement), NOT the core place();
        // r_min feeds only the core credit cap, so it is inert here.
        r_min: 0.5,
    };
    let ranked = place_reciprocal(
        &cand_obs,
        &req,
        prior,
        params.reciprocal_placement,
        retention,
        cand_idx.len(),
        &occupied,
    );
    drop(cand_nodes);
    drop(caps);

    for local in ranked {
        let holder = cand_idx[local];
        if admit_offer(world, owner, holder, v_per_symbol, params, tick) {
            world.nodes[holder].holdings.push(HeldSymbol {
                owner,
                block: block_id,
                iota: block_iota,
                volume: v_per_symbol,
                alive: true,
                cream,
            });
            if let Some(b) = world.nodes[owner]
                .own_blocks
                .iter_mut()
                .find(|b| b.id == block_id)
            {
                b.placements.push(BlockPlacement { holder, cream });
            }
            // World-v2 §9 newcomer trace: first tick this owner's own data was accepted.
            if world.first_own_accept[owner].is_none() {
                world.first_own_accept[owner] = Some(tick);
            }
            return true;
        }
    }
    false
}

/// The holder accept/preemption gate (§9 / A.12-2). Returns whether `holder` admits a
/// new symbol from `owner`. In abundance: accept freely (willing ∧ room ∧ above the
/// accept gate). Under contention: a PREEMPTIVE swap — displace the holder's
/// least-reciprocal current owner `O_min` by the SINGLE key κ_O (its LOW-ι symbol,
/// WARN-4) iff `κ_O(owner) > κ_O(O_min) + θ_p·g*` (WARN-1). The swap is φ-neutral (one
/// out + one in ≈ equal volume), so it bypasses the accept freeze without thrash.
///
/// **Unified κ_O (транш 3b, closes ADV2-D2).** Both the victim rank and the offering
/// owner's key read the SAME `kappa_key` (`g_ho + w_d·sat(D/d_ref)·g*`) that the
/// eviction inter-owner rank and the Р-7 cap use — NOT bare `g_ho`. A bare-`g_ho`
/// preemption would evict a silent-but-DEEP loyal partner (`g_ho→0`, `D≥d_ref`) while a
/// shallow stranger with more fast capital survived (W10 broke under contention); on κ_O
/// the deep partner ranks above the stranger, so it is not the victim. A parasite
/// (κ_O≈0 with all) still can never clear the margin, so it cannot preempt in.
///
/// **Accept-guard (B-1 consistency, spec-3b decision above the model letter).** The
/// preemption path REJECTS the offer if the OWNER's own V_ret cannot hold it
/// (`V_parked(owner) + v_per_symbol > V_ret(owner)`), so we never "admit then instantly
/// cap-trim". The free-accept (abundance) path is deliberately NOT gated by the cap.
///
/// Side effects (eviction of the victim, logging, counters) happen here; the caller
/// records the accepted holding.
fn admit_offer(
    world: &mut World,
    owner: usize,
    holder: usize,
    v_per_symbol: f64,
    params: &DynParams,
    tick: u64,
) -> bool {
    // WILL: seeded Bernoulli on the archetype's willingness (§10.A).
    let mut rng = Rng::derive(world.seed, ACCEPT_TAG, owner as u64, holder as u64, tick);
    if rng.unit() >= world.nodes[holder].archetype.willing_accept_rate() {
        return false; // unwilling = behavioural hard reject
    }
    // ROOM + accept-gate (NEW-2 damper): freely accept only above s_soft and not evicting.
    let has_room = world.nodes[holder].free_disk() >= v_per_symbol;
    let accept_ok = world.nodes[holder].phi_free_ratio() > params.hyst.s_soft
        && !world.nodes[holder].evict_phase.evicting;
    if has_room && accept_ok {
        return true;
    }
    // Contended / frozen → PREEMPTION (§2 / A.12-2), if enabled.
    if !preempt_enabled(params) {
        return false;
    }
    let margin = params.preempt_theta * capital_steady_state(v_per_symbol, params.lambda);

    // SINGLE key κ_O (B-1): the same kappa_key the eviction rank + Р-7 cap read.
    let depth_params = depth_params_of(params, v_per_symbol);
    let cap = retention_cap(params, v_per_symbol);
    let kappa_of = |o: usize| {
        kappa_key(
            world.capital[o][holder].g_ho,
            world.capital[o][holder].depth_ho,
            &depth_params,
        )
    };
    let kappa_new = kappa_of(owner);

    // Accept-guard (B-1): don't admit a symbol the OWNER's own V_ret cannot hold (it would
    // just be cap-trimmed next eviction). Free-accept path above is NOT gated by the cap.
    if cap.active() {
        let v_parked: f64 = world.nodes[holder]
            .holdings
            .iter()
            .filter(|s| s.alive && s.owner == owner)
            .map(|s| s.volume)
            .sum();
        if v_parked + v_per_symbol > cap.v_ret(kappa_new) {
            return false;
        }
    }

    // Victim OWNER = the holder's least-reciprocal DISTINCT alive foreign owner by κ_O
    // (min κ, NOT bare g_ho — the ADV2-D2 fix), excluding `owner` (don't cannibalise the
    // offering owner's own data).
    let mut victim_owner: Option<usize> = None;
    let mut kappa_min = f64::INFINITY;
    let mut seen: Vec<usize> = Vec::new();
    for s in world.nodes[holder]
        .holdings
        .iter()
        .filter(|s| s.alive && s.owner != owner)
    {
        if seen.contains(&s.owner) {
            continue;
        }
        seen.push(s.owner);
        let k = kappa_of(s.owner);
        if k < kappa_min {
            kappa_min = k;
            victim_owner = Some(s.owner);
        }
    }
    let vo = match victim_owner {
        Some(v) => v,
        None => return false,
    };
    if kappa_new <= kappa_min + margin {
        return false; // parasite (κ_new≈0) can never clear this
    }
    // WARN-4: the victim symbol is O_min's LOWEST-ι symbol on this holder (intra-owner
    // ladder), not the first in storage order.
    let victim = world.nodes[holder]
        .holdings
        .iter()
        .enumerate()
        .filter(|(_, s)| s.alive && s.owner == vo)
        .min_by(|a, b| a.1.iota.total_cmp(&b.1.iota))
        .map(|(idx, s)| (idx, s.block, s.volume));
    let (v_idx, v_block, v_vol) = match victim {
        Some(t) => t,
        None => return false,
    };
    if world.nodes[holder].free_disk() + v_vol < v_per_symbol {
        return false; // swap would not actually free enough room
    }
    // A.2 ANNOUNCED burn (transche 4): the preemption victim is a live-holder drop of
    // `vo`'s symbol — burn `vo`'s reliability capital g_oh BEFORE marking it dead (V_held
    // includes it). Same announced treatment as a pressure/cap eviction.
    apply_announced_burn(world, vo, holder, v_vol, params);
    // Evict the victim (φ-neutral swap): mark dead, log, drop the owner's placement. The
    // logged `g_ho_at_drop` is the victim's BARE g_ho (diagnostic continuity §2c — the
    // rank now uses κ_O, but the drop-reciprocity metric still reads the raw g_ho).
    let g_ho_at_drop = world.capital[vo][holder].g_ho;
    world.nodes[holder].holdings[v_idx].alive = false;
    world.eviction_log.push(EvictionEvent {
        tick,
        holder,
        owner: vo,
        g_ho_at_drop,
    });
    world.preempt_count += 1;
    if let Some(b) = world.nodes[vo]
        .own_blocks
        .iter_mut()
        .find(|b| b.id == v_block)
        && let Some(pos) = b.placements.iter().position(|p| p.holder == holder)
    {
        b.placements.remove(pos);
    }
    true
}

/// Reciprocity-aware ranking via the CANON retention forecast (canon §9.5 / эталон §1).
/// Ranks holders by the per-symbol keep-probability `surface · retained_depth(obs)` (the
/// rank-marginalized canon K3 form; `retained_depth` folds in `obs.g_holder_from_owner`
/// = `capital[owner][h].g_ho`, "how much h stores at us"), greedily admits ≤1 per
/// observable address bucket (§7 spread, starting from `occupied_init`), filling to
/// `want`. `reciprocal = false` recovers pure-surface. Returns chosen LOCAL indices.
///
/// Anti-oracle: reads only first-hand `cand_obs`; strength is the `RetentionPrior`
/// (default or recalibrated), not a magic weight.
fn place_reciprocal(
    cand_obs: &[viaticum_core::four_r::FirstHandObs],
    req: &BlockReq,
    prior: &SurfacePrior,
    reciprocal: bool,
    retention: &RetentionPrior,
    want: usize,
    occupied_init: &[u32],
) -> Vec<usize> {
    let v_per_symbol = req.volume_per_symbol();
    let tau = req.tau.max(0.0);

    let score: Vec<f64> = cand_obs
        .iter()
        .map(|obs| {
            let surface = estimate_surface(obs, prior, v_per_symbol, tau).r_hat;
            if reciprocal {
                surface * retained_depth(obs, retention)
            } else {
                surface
            }
        })
        .collect();
    let mut order: Vec<usize> = (0..cand_obs.len()).collect();
    order.sort_by(|&a, &b| score[b].total_cmp(&score[a]));

    let mut chosen: Vec<usize> = Vec::new();
    let mut occupied: Vec<u32> = occupied_init.to_vec();
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

/// (2): PoS-challenge + capital update (world-v2 §9.4 ONE physics), obeying the A.1
/// leaky-integrator contract for EVERY pair — not only active ones (WARN-2 fix).
///
/// The A.1 law is `g ← g·(1−λΔt) + V_conf·Δt`. The old code applied it ONLY on a
/// challenge event (a holder's alive symbol), so a pair with NO alive symbol FROZE its
/// `g_oh`/`g_ho` forever — fossil reciprocity that inflated `share A>0`, eternally
/// protected departed reciprocators' ghost symbols in `eviction_order`, and let them
/// preempt forever. Now the DECAY `g ← g·(1−λΔt)` is applied to ALL N² pairs each tick,
/// and only the `+V_conf·Δt` accumulation is added on an active challenge — so an idle /
/// dead relationship drains to zero over the ~2-month capital memory, as A.1 requires.
///
/// PoS-pass ⟺ the holder is online (the symbol is alive by construction). There is NO
/// `retained_edge` and NO archetype in the outcome — aggression lives in churn only.
/// A DEPARTED owner runs no PoS: challenges (and `served`) are gated on the owner being
/// present, so a churned-out owner no longer "confirms" its ghost data.
///
/// `v_dem` is the demonstrated-scale RATCHET (A.3, `λ_dem ≪ λ`), NOT the λ-capital. It
/// follows the SAME W2 split as `g_ho`/`depth` — the slow leak `V_dem·(1−λ_dem·Δt)` is
/// applied to EVERY pair in the sweep below, and a confirmed pass snaps it UP to the
/// served volume via a MAX (not a `+=`, since A.3 is a ratchet). The two steps compose
/// EXACTLY to A.3 `V_dem ← max(V_conf, V_dem·(1−λ_dem·Δt))` per tick (see the event loop),
/// with no double decay: the sweep decays once (`dt`), the event max takes `dt = 0`.
fn pos_and_capital(world: &mut World, params: &DynParams) {
    let n = world.nodes.len();
    let tick = world.tick;
    let dt = DAYS_PER_TICK;
    let decay = (1.0 - params.lambda * dt).max(0.0);

    // Roll g_oh_prev for the D-projection finite difference, then apply the A.1 DECAY to
    // EVERY pair (idle pairs drain; active pairs get the +V_conf accumulation below).
    // The A.4 loyalty depth decays on EVERY pair too (same W2 pattern, slower τ_slow):
    // this is the load-bearing leak — a silent pair's depth fades over months, so a
    // farmed depth burst is not a permanent floor. Its +V_conf accrual is added in the
    // challenge loop below (mirroring the split of `g_ho`'s decay-then-accrue).
    for o in 0..n {
        for h in 0..n {
            let cell = &mut world.capital[o][h];
            cell.g_oh_prev = cell.g_oh;
            cell.g_oh *= decay;
            cell.g_ho *= decay;
            cell.depth_ho = update_depth(cell.depth_ho, 0.0, dt, params.lambda_slow);
            // A.3 ratchet leak: decay `V_dem` on EVERY pair (v_conf = 0). A silent pair's
            // demonstrated scale fades over `τ_dem ≈ 1 year` — no fossil scale survives
            // forever; a confirmed pass re-snaps it up in the challenge loop below.
            cell.v_dem = update_v_dem(cell.v_dem, 0.0, dt, params.lambda_dem);
            // A.5 W2 sweep: decay suspicion `σ` on EVERY pair (defect = false). Fast
            // forgetting (`1/μ ≈ 2 weeks`) — a σ jump from a past silent loss fades in
            // weeks. A confirmed silent loss re-jumps it in the pending-loss pass below
            // (dt = 0 there, so the two compose to exactly σ(1−μΔt) + j_σ per tick).
            cell.sigma = update_suspicion(cell.sigma, false, dt, params.sigma_mu, params.sigma_j);
            // A.2/A.7 W2 sweep (транше-4 fix): decay the LEAKY drop counters `drop_ann`/
            // `drop_silent` on EVERY pair — "the system must forgive" (Ilya 2026-07-07).
            // A drop's retention penalty fades over `1/λ_drop ≈ 8 weeks` rather than being
            // eternal under windowed PoS; new drops re-add `+1.0` in the burn paths.
            let drop_decay = (1.0 - params.lambda_drop * dt).max(0.0);
            cell.drop_ann *= drop_decay;
            cell.drop_silent *= drop_decay;
        }
    }

    // A.2 (транше 4): apply SILENT losses queued last tick by `churn` — "detected on the
    // next PoS round". A holder departed with this owner's symbols; from the owner's seat
    // it is a confirmed SILENT loss (b_max) with no head-start. Applied AFTER the decay
    // sweep so the burn lands on the decayed g_oh and the σ jump (dt = 0) sits on top of
    // this tick's decayed σ — composing to A.5's σ(1−μΔt) + j_σ. Drains the queue.
    if !world.pending_silent_loss.is_empty() {
        let bp = burn_params_of(params);
        let pending = std::mem::take(&mut world.pending_silent_loss);
        for ev in pending {
            let SilentLoss {
                owner,
                holder,
                volume,
            } = ev;
            let cell = &mut world.capital[owner][holder];
            // Silent: announced = false ⇒ b_max, t_n = 0. A total loss (V_lost = V_held).
            cell.g_oh = apply_burn(cell.g_oh, &bp, false, 0.0, volume, volume);
            cell.drop_silent += 1.0; // leaky counter (decayed in the W2 sweep by λ_drop)
            // σ jump (pure, dt = 0 — the sweep already decayed σ this tick).
            cell.sigma = update_suspicion(cell.sigma, true, 0.0, params.sigma_mu, params.sigma_j);
            world.burn_silent_count += 1;
        }
    }

    // Collect challenges (owner, holder, volume, online) over alive holdings whose OWNER
    // is still PRESENT (a departed owner runs no PoS challenge).
    struct Challenge {
        owner: usize,
        holder: usize,
        volume: f64,
        holder_online: bool,
    }
    let mut challenges: Vec<Challenge> = Vec::new();
    for holder in 0..n {
        if !world.nodes[holder].present {
            continue;
        }
        let h_online = online(
            world.nodes[holder].archetype,
            world.nodes[holder].id,
            tick,
            world.seed,
        );
        for s in world.nodes[holder].holdings.iter().filter(|s| s.alive) {
            if !world.nodes[s.owner].present {
                continue; // departed owner: no challenge, no served accrual
            }
            challenges.push(Challenge {
                owner: s.owner,
                holder,
                volume: s.volume,
                holder_online: h_online,
            });
        }
    }

    // A.5 (транше-4 fix): pairs whose holder TIMED OUT this tick (holder offline). Each
    // gets ONE weak σ jump `j_σ/5` below — per PAIR, not per symbol (a holder with 3 of an
    // owner's symbols is one timeout event, not three). BTreeSet ⇒ deterministic.
    let mut timed_out_pairs: std::collections::BTreeSet<(usize, usize)> =
        std::collections::BTreeSet::new();

    for c in &challenges {
        // §9.4 one physics: pass ⟺ online (the symbol is alive by construction).
        let passed = c.holder_online;
        if !passed {
            timed_out_pairs.insert((c.owner, c.holder));
        }
        // On a pass, ADD the A.1 accumulation `+V_conf·Δt` (the decay is already applied
        // above); a timeout adds nothing (v_conf = 0), leaving only the decay.
        let accrual = if passed { c.volume * dt } else { 0.0 };

        if passed {
            world.served[c.holder][c.owner] += c.volume;
        }

        let cap = cap_mut(&mut world.capital, c.owner, c.holder);
        cap.g_oh += accrual;
        if passed {
            // A.3 ratchet UP on a confirmed pass. `dt = 0` here — the slow decay was already
            // applied to this pair in the sweep above, so this is the pure MAX arm of A.3
            // (`max(V_conf, V_dem_decayed)`); composing sweep+event gives exactly
            // `V_dem ← max(V_conf, V_dem·(1−λ_dem·Δt))` with a SINGLE decay per tick.
            cap.v_dem = update_v_dem(cap.v_dem, c.volume, 0.0, params.lambda_dem);
        }
        cap.push_outcome(passed);

        // Reciprocal g_ho on the holder's OWN books (the transpose cell) — the eviction /
        // preemption / retention key. Anti-oracle: this is the holder's own record of
        // storage it performed, not a peer's private cell. The SAME confirmed V_conf·Δt
        // also feeds the slow loyalty depth (A.4) on that cell (its decay was applied to
        // all pairs in the sweep above), so depth accrues ONLY on live confirmed service
        // (PoS-pass ∧ alive ∧ online — the same physics that feeds g_ho).
        let cap_t = cap_mut(&mut world.capital, c.holder, c.owner);
        cap_t.g_ho += accrual;
        cap_t.depth_ho += accrual;

        // World-v2 §9 newcomer trace: first tick this holder EARNED reciprocity (served).
        if passed && world.first_earned_g[c.holder].is_none() {
            world.first_earned_g[c.holder] = Some(tick);
        }
    }

    // A.5 (транше-4 fix, Ilya 2026-07-07): a lone PoS-timeout raises σ WEAKLY by `j_σ/5`
    // (the escalation ladder — timeout → challenge more often → confirm/clear faster; a
    // false timeout is cheap since σ forgets in ~2 weeks). ONE jump per (owner, holder)
    // pair per tick (the dedup set above), NOT per symbol. `dt = 0` here — the per-pair σ
    // decay was already applied in the W2 sweep — so this composes to A.5's
    // `σ(1−μΔt) + (j_σ/5)` exactly. A CONFIRMED silent defect (holder death) still jumps
    // the FULL `j_σ` in the pending-loss pass above; a departed holder runs no challenge,
    // so the two σ paths never touch the same pair in the same tick.
    let j_timeout = params.sigma_j / 5.0;
    for (owner, holder) in timed_out_pairs {
        let cell = &mut world.capital[owner][holder];
        cell.sigma = update_suspicion(cell.sigma, true, 0.0, params.sigma_mu, j_timeout);
    }
}

/// PoS outcome classification (world-v2 §9.4). Only two outcomes survive the one-physics
/// collapse: a challenged (alive) symbol on an online holder PASSES; an offline holder
/// TIMES OUT. A "fail on a still-held symbol" no longer exists — symbol death is a real
/// engine event (eviction / preemption / churn) that removes it from the challenge set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosOutcome {
    /// Holder online ⇒ the alive symbol passes.
    Pass,
    /// Holder offline ⇒ timeout (kernel §7 forgives: scrutiny↑, no burn).
    Timeout,
}

/// (3): eviction when `φ < s_soft` (design §10.G). Builds each present holder's eviction
/// view through the observer, calls `eviction_order`, and applies drop slots to god-view
/// holdings until `φ ≥ s_target`. NOTE1: all `(owner, block)` drop targets are RESOLVED
/// from a pre-mutation snapshot before any symbol is killed (so killing one does not
/// renumber the `nth_alive` mapping of the others).
fn run_eviction(world: &mut World, params: &DynParams) {
    let n = world.nodes.len();
    let dt = DAYS_PER_TICK;
    let tick = world.tick;
    let mut any_eviction_this_tick = false;

    // A.14 κ_O depth params + Р-7 volume cap — computed once (holder-independent). The
    // kernel does not know λ/V_sym, so the caller carries g*, the days→gb·days d_ref
    // conversion, and V_free/c_recip. SHARED with `admit_offer` (same κ_O — B-1).
    let v_per_symbol = v_per_symbol_of(params);
    let depth_params = depth_params_of(params, v_per_symbol);
    let cap = retention_cap(params, v_per_symbol);

    for holder in 0..n {
        if !world.nodes[holder].present {
            continue;
        }
        let phi = world.nodes[holder].phi_free_ratio();
        let prev = world.nodes[holder].evict_phase;

        let owner_addr = |owner_idx: usize| -> ObsAddr {
            ObsAddr {
                addr_subnet: world.nodes[owner_idx].addr_subnet,
                master_byte: world.nodes[owner_idx].master_byte,
                present: world.nodes[owner_idx].present,
            }
        };
        // Distinct alive-symbol owners in a DETERMINISTIC SHUFFLE (tie-break among equal
        // g_ho is index-neutral). This SAME slice maps drop slots back.
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

        let views = observer::observe_eviction_views(
            &world.nodes[holder],
            &owner_of_view,
            |owner_idx| &world.capital[owner_idx][holder],
            owner_addr,
            dt,
        );

        let decision = eviction_order(&views, phi, params.hyst, prev, &depth_params, &cap);
        world.nodes[holder].evict_phase = decision.phase;

        if !decision.phase.evicting {
            continue;
        }

        // NOTE1: resolve ALL (owner_idx, block) drop targets — for BOTH the Р-7
        // cap_drops AND the pressure drop_order — from ONE PRE-mutation snapshot before
        // killing any symbol (a holder holds ≤1 symbol per (owner, block) by the §7
        // spread, so (owner, block) is a unique symbol key; killing one must not renumber
        // the `nth_alive` mapping of the others). The two lists are disjoint (the kernel
        // excludes cap_drops from drop_order), so the resolved targets are disjoint too.
        let resolve = |slots: &[viaticum_core::four_r::SymbolSlot]| -> Vec<(usize, usize)> {
            let mut out: Vec<(usize, usize)> = Vec::new();
            for slot in slots {
                let owner_idx = match owner_of_view.get(slot.owner_idx) {
                    Some(&o) => o,
                    None => continue,
                };
                if let Some(block) =
                    nth_alive_block(&world.nodes[holder], owner_idx, slot.symbol_idx)
                {
                    out.push((owner_idx, block));
                }
            }
            out
        };
        let cap_targets = resolve(&decision.cap_drops);
        let pressure_targets = resolve(&decision.drop_order);

        // Р-7 cap_drops FIRST, UNCONDITIONALLY (tariff enforcement — NOT gated on the
        // φ-target; the excess above V_ret leaves regardless of how much room it frees).
        // burn = FALSE (транше-4 fix): a cap-trim is a predictable tariff, not a
        // reliability signal — it does NOT burn g_oh nor bump drop_ann.
        for (owner_idx, block) in cap_targets {
            if evict_symbol(world, holder, owner_idx, block, tick, params, false) {
                any_eviction_this_tick = true;
                world.cap_trim_count += 1;
            }
        }

        // THEN the pressure drops, stopping once φ has recovered to s_target. burn = TRUE:
        // a squeeze drop IS a reliability signal (burns g_oh + bumps drop_ann).
        for (owner_idx, block) in pressure_targets {
            if world.nodes[holder].phi_free_ratio() >= params.hyst.s_target {
                break;
            }
            if evict_symbol(world, holder, owner_idx, block, tick, params, true) {
                any_eviction_this_tick = true;
            }
        }
    }
    if any_eviction_this_tick {
        world.ticks_with_eviction += 1;
    }
}

/// Kill one alive symbol `(owner, block)` on `holder` (god-view): OPTIONALLY apply the A.2
/// ANNOUNCED burn (a live-holder drop, транше 4), mark it dead, log the [`EvictionEvent`]
/// with the victim's BARE `g_ho` (`g_ho_at_drop` — diagnostic continuity §2c), and drop the
/// owner's placement bookkeeping. Returns whether a symbol was actually killed (it may
/// already be dead if resolved-then-superseded). Shared by the Р-7 cap trims and the
/// pressure drops.
///
/// `burn` (транше-4 fix, Ilya 2026-07-07 / review WARN-2 т4): a PRESSURE drop passes
/// `true` (a real squeeze signal → burn `g_oh` + bump `drop_ann`); a Р-7 cap-trim passes
/// `false` — a mandatory tariff enforcement the OWNER can predict (it knows its own
/// `V_ret`), NOT a reliability signal, so it must NOT punish the holder's capital nor stain
/// the retention forecast. Punishing the holder for the owner's over-placement would
/// corrupt the signal.
fn evict_symbol(
    world: &mut World,
    holder: usize,
    owner_idx: usize,
    block: usize,
    tick: u64,
    params: &DynParams,
    burn: bool,
) -> bool {
    // Locate the target symbol's volume BEFORE any mutation (confirms it is still alive).
    let v_lost = match world.nodes[holder]
        .holdings
        .iter()
        .find(|s| s.alive && s.owner == owner_idx && s.block == block)
    {
        Some(s) => s.volume,
        None => return false, // already dead / superseded this tick
    };
    // A.2 ANNOUNCED burn (transche 4) on the owner's reliability capital g_oh, computed
    // with V_held INCLUDING the symbol about to die (it is still alive here) — but ONLY for
    // a PRESSURE drop; a cap-trim (burn = false) is tariff enforcement, not a burn/drop.
    if burn {
        apply_announced_burn(world, owner_idx, holder, v_lost, params);
    }
    let g_ho_at_drop = world.capital[owner_idx][holder].g_ho;
    let killed = if let Some(hs) = world.nodes[holder]
        .holdings
        .iter_mut()
        .find(|s| s.alive && s.owner == owner_idx && s.block == block)
    {
        hs.alive = false;
        world.eviction_log.push(EvictionEvent {
            tick,
            holder,
            owner: owner_idx,
            g_ho_at_drop,
        });
        true
    } else {
        false
    };
    if killed
        && let Some(b) = world.nodes[owner_idx]
            .own_blocks
            .iter_mut()
            .find(|b| b.id == block)
        && let Some(pos) = b.placements.iter().position(|p| p.holder == holder)
    {
        b.placements.remove(pos);
    }
    killed
}

/// The `idx`-th alive block of `owner` on `holder`, in the observer's symbol order
/// (filtered alive, storage order). Returns the god-view block id, or None if OOB.
fn nth_alive_block(holder: &Node, owner: usize, idx: usize) -> Option<usize> {
    holder
        .holdings
        .iter()
        .filter(|s| s.alive && s.owner == owner)
        .nth(idx)
        .map(|s| s.block)
}

/// (1a): resync placement bookkeeping to the actual ALIVE holdings (drop dead / departed
/// holders; carry the cream flag). Refill happens in `place_own_data` (§9.2 bandwidth),
/// so a below-FLOOR block gets new floor holders on subsequent ticks. Cream deaths are
/// NOT refilled toward the floor (cream-no-mandatory-repair, §9.3).
fn resync_placements(world: &mut World) {
    let n = world.nodes.len();
    for owner in 0..n {
        if !world.nodes[owner].present {
            continue;
        }
        let block_ids: Vec<usize> = world.nodes[owner].own_blocks.iter().map(|b| b.id).collect();
        for block_id in block_ids {
            let alive: Vec<(usize, bool)> = world
                .nodes
                .iter()
                .enumerate()
                .filter_map(|(h, node)| {
                    node.holdings
                        .iter()
                        .find(|s| s.alive && s.owner == owner && s.block == block_id)
                        .map(|s| (h, s.cream))
                })
                .collect();
            if let Some(b) = world.nodes[owner]
                .own_blocks
                .iter_mut()
                .find(|b| b.id == block_id)
            {
                b.placements = alive
                    .iter()
                    .map(|&(h, cream)| BlockPlacement { holder: h, cream })
                    .collect();
            }
        }
    }
}

/// (4): churn. Each present node departs with a seeded per-tick probability. The
/// archetype `evict_aggression` RAISES the departure rate (world-v2 §9.4: aggression
/// lives ONLY in willingness/churn — not in the PoS outcome): a cooperative archetype
/// (aggression 0) churns at the base rate, an aggressive one at
/// `base·(1 + CHURN_AGGRESSION_SCALE·aggression)` (Hoarder aggression 0.7 ⇒ ~3×, matching
/// the old flat multiplier; Freeloader 0.85 ⇒ ~3.4×). On departure the node's HELD
/// symbols are marked dead and it becomes absent.
fn churn(world: &mut World, params: &DynParams) {
    let n = world.nodes.len();
    let tick = world.tick;
    for node in 0..n {
        if !world.nodes[node].present {
            continue;
        }
        let mut rng = Rng::derive(world.seed, 0xC4_07_C4_07, world.nodes[node].id, tick, 0);
        let aggression = world.nodes[node].archetype.evict_aggression();
        let p = params.churn_out_prob * (1.0 + CHURN_AGGRESSION_SCALE * aggression);
        if rng.unit() < p {
            world.nodes[node].present = false;
            // A.2 (транше 4): the departing node is a HOLDER — every owner whose data it
            // carried suffers a SILENT loss, detected on the owner's NEXT PoS round (next
            // tick). Queue one event per PRESENT distinct owner, V_lost = V_held = all of
            // that owner's alive symbols here (a total loss). Deterministic (storage order).
            let mut per_owner: Vec<(usize, f64)> = Vec::new();
            for hs in world.nodes[node].holdings.iter().filter(|s| s.alive) {
                if !world.nodes[hs.owner].present {
                    continue; // a departed owner cannot detect the loss (dead pair)
                }
                match per_owner.iter_mut().find(|(o, _)| *o == hs.owner) {
                    Some(e) => e.1 += hs.volume,
                    None => per_owner.push((hs.owner, hs.volume)),
                }
            }
            for (owner, volume) in per_owner {
                world.pending_silent_loss.push(SilentLoss {
                    owner,
                    holder: node,
                    volume,
                });
            }
            for hs in world.nodes[node].holdings.iter_mut() {
                hs.alive = false;
            }
        }
    }
}

/// How strongly archetype aggression raises the churn rate (§9.4). Chosen so a Hoarder
/// (aggression 0.7) churns at ~3× the base, matching the old flat multiplier.
const CHURN_AGGRESSION_SCALE: f64 = 2.857;

/// World-v3 event executor (axis 8, sub-tranche 0.2): a Disaster hits `victim` — its
/// disk, and with it EVERYTHING local, is destroyed. This is the DR-primary scenario
/// (Ilya's NAS, house burned down) in god-view terms. Distinct from [`churn`] (a holder
/// merely LEAVING): here the OWNER's source data is lost, so P1 bites — no repair is
/// possible, only RESTORE from surviving holders (see [`OwnBlock::to_restore`]).
///
/// The mutation is all "one physics" (both sides see it consistently):
///  * The victim is a HOLDER for others — every foreign symbol it stored dies, a SILENT
///    loss queued to `pending_silent_loss` for each present owner whose data it carried.
///    **Timing (0.2-fix, honest):** detected within the SAME tick T — the runner
///    (`sim_adv::runner::run_one_seed`) applies this event BEFORE calling `step(T)`, and
///    `pos_and_capital` drains the queue inside that same `step(T)` call. This is ONE
///    TICK EARLIER than `churn`'s convention: a departure inside `step(T)`'s `churn(..)`
///    call is queued and only drained by `pos_and_capital` in the FOLLOWING `step(T+1)`
///    call, i.e. detected at T+1. Not unified on purpose — unify when a detection-latency
///    metric lands (phase 1+). The victim's holdings are then CLEARED — it lost the disk
///    and returns with an empty holdings store.
///  * The victim's OWN blocks are marked `to_restore` (source lost → no repair, P1).
///    Their symbols on OTHER holders are UNTOUCHED — they live their own life; the
///    restore-truth evaluator measures whether ≥ k_eff can be re-collected in the window.
///  * The victim goes `present = false`. The caller (the sim_adv runner) revives it at
///    `tick + 1` with the SAME identity — counterparties remember it.
///  * **First-hand-ledger death (P1 decision, documented):** the victim's redb died with
///    the disk, so its OWN PRIVATE assessments of its holders — held in the capital rows
///    `capital[victim][*]` — die: `g_oh` (its reliability record of each holder), its
///    trend `g_oh_prev`, its suspicion `sigma`, its drop counters `drop_ann`/`drop_silent`,
///    its PoS-outcome window, and `v_dem` (0.2-fix: `v_dem` is written ONLY by the
///    victim's own PoS challenge as owner — `capital[owner][holder]` at the challenge
///    loop below — and read only from the owner seat by `credit_limit`/`backbone_survival`
///    upstream in `four_r`; it is victim-seat data, NOT counterparty-observable, so it
///    dies with the rest of the row). What is PRESERVED, deliberately, is everything that
///    is BILATERALLY observable — the fields the COUNTERPARTY (holder) keeps on ITS own
///    disk: `g_ho` and `depth_ho` (the victim's past SERVICE to the holder, which the
///    holder ranks eviction on). "Counterparties remember the node" — so the victim's
///    symbols keep the eviction protection its past service earned; erasing the whole row
///    would strip that shared memory and understate restore-truth. The columns
///    `capital[*][victim]` (other owners' records of the victim as their holder) are
///    untouched for the same reason.
pub fn disaster_strike(world: &mut World, victim: usize) {
    let n = world.nodes.len();
    // The victim as a holder: every present owner whose data it carried suffers a SILENT
    // loss, detected within this SAME tick (see the timing note in the doc comment above —
    // one tick earlier than `churn`'s T+1 convention). V_lost = V_held = all of that
    // owner's alive symbols here (a total loss). Deterministic (storage order).
    let mut per_owner: Vec<(usize, f64)> = Vec::new();
    for hs in world.nodes[victim].holdings.iter().filter(|s| s.alive) {
        if !world.nodes[hs.owner].present {
            continue; // a departed owner cannot detect the loss (dead pair)
        }
        match per_owner.iter_mut().find(|(o, _)| *o == hs.owner) {
            Some(e) => e.1 += hs.volume,
            None => per_owner.push((hs.owner, hs.volume)),
        }
    }
    for (owner, volume) in per_owner {
        world.pending_silent_loss.push(SilentLoss {
            owner,
            holder: victim,
            volume,
        });
    }
    // Lost disk: the victim returns with an empty holdings store.
    world.nodes[victim].holdings.clear();
    // Own data: source lost ⇒ every own block is `to_restore` (P1 — no repair, restore only).
    for b in world.nodes[victim].own_blocks.iter_mut() {
        b.to_restore = true;
    }
    // First-hand-ledger death (P1): reset the victim's PRIVATE assessments of its holders
    // (died with the disk), including `v_dem` (0.2-fix: it is victim-seat data, written by
    // the victim's own PoS challenge — see the doc comment above — NOT counterparty-
    // observable, so it does not survive). PRESERVE the bilaterally-observable
    // `g_ho`/`depth_ho` (the counterparty's memory of the victim's service, kept on the
    // holder's disk — so the victim's symbols retain the eviction protection it earned).
    for h in 0..n {
        let cell = &mut world.capital[victim][h];
        cell.g_oh = 0.0;
        cell.g_oh_prev = 0.0;
        cell.v_dem = 0.0;
        cell.sigma = 0.0;
        cell.drop_ann = 0.0;
        cell.drop_silent = 0.0;
        cell.pos_window.clear();
    }
    // Gone until the caller revives it (tick + 1, same identity).
    world.nodes[victim].present = false;
}

/// Build the kernel's `NodeLocal` snapshot for a holder (its own disk free-ratio).
pub fn node_local(node: &Node) -> NodeLocal {
    NodeLocal {
        phi_free_ratio: node.phi_free_ratio(),
    }
}

/// Deterministic Fisher-Yates shuffle of `v`, keyed by the run seed + three coordinates.
fn shuffle(v: &mut [usize], seed: u64, k0: u64, k1: u64, k2: u64) {
    let mut rng = Rng::derive(seed, 0x0544_FF1E_5417_F1E0, k0, k1, k2);
    let len = v.len();
    for i in (1..len).rev() {
        let j = (rng.unit() * (i as f64 + 1.0)) as usize;
        let j = j.min(i);
        v.swap(i, j);
    }
}

/// Salt for the §9.5 owner-processing-order shuffle (kept off the other streams).
const OWNER_ORDER_TAG: u64 = 0x0B0E_0F0C_5EED_A011;
/// Salt for the accept-gate willingness stream.
const ACCEPT_TAG: u64 = 0xACCE_7711;

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
        floor_ever_met: false,
        floor_deficit_since: None,
        to_restore: false,
    }
}

// ============================================================
// Test-only accessors for the internal decision functions. These exist ONLY under
// `cfg(test)` so they never widen the production API; each wraps an internal fn that
// IS used in the normal build (no dead code).
// ============================================================

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn place_reciprocal_for_test(
    cand_obs: &[viaticum_core::four_r::FirstHandObs],
    req: &BlockReq,
    prior: &SurfacePrior,
    reciprocal: bool,
    retention: &RetentionPrior,
    want: usize,
    occupied_init: &[u32],
) -> Vec<usize> {
    place_reciprocal(
        cand_obs,
        req,
        prior,
        reciprocal,
        retention,
        want,
        occupied_init,
    )
}

#[cfg(test)]
pub fn admit_offer_for_test(
    world: &mut World,
    owner: usize,
    holder: usize,
    v_per_symbol: f64,
    params: &DynParams,
    tick: u64,
) -> bool {
    admit_offer(world, owner, holder, v_per_symbol, params, tick)
}

#[cfg(test)]
pub fn pos_and_capital_for_test(world: &mut World, params: &DynParams) {
    pos_and_capital(world, params);
}

#[cfg(test)]
pub fn churn_for_test(world: &mut World, params: &DynParams) {
    churn(world, params);
}

#[cfg(test)]
pub fn run_eviction_for_test(world: &mut World, params: &DynParams) {
    run_eviction(world, params);
}

#[cfg(test)]
pub fn symbols_per_tick_for_test(u: f64, v_per_symbol: f64) -> usize {
    symbols_per_tick(u, v_per_symbol)
}

#[cfg(test)]
pub fn block_mature_for_test(
    joined_tick: u64,
    block_pos: usize,
    tick: u64,
    params: &DynParams,
) -> bool {
    block_mature(joined_tick, block_pos, tick, params)
}

#[cfg(test)]
pub fn alive_block_counts_for_test(world: &World, owner: usize, block_id: usize) -> (usize, usize) {
    alive_block_counts(world, owner, block_id)
}

#[cfg(test)]
pub fn repair_detected_for_test(
    seed: u64,
    owner_id: u64,
    block_id: usize,
    deficit_since: u64,
    tick: u64,
    delay_max: u64,
) -> bool {
    repair_detected(seed, owner_id, block_id, deficit_since, tick, delay_max)
}
