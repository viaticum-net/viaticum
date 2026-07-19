//! World-v3 phase-1 predators: A1 ε-give whale + A4 whitewasher (design `4r_world_v3_spec.md`
//! §3 rows A1/A4, `4r_world_v3_detail.md` §2 mini-specs, §3.3 Attack-ROI, `4r_p1_spec.md`).
//!
//! Three pieces live here:
//!
//! * **Behaviour hooks** — the `fn(&AdvContext) -> AdvAction` strategies. A1 serves ε (its
//!   low reciprocity κ_O lets every holder cap its parked volume at ≈ V_free, Р-7); A4 burns
//!   its identity every `period_ticks`. Both are pure functions of first-hand context (their
//!   own dials + join tick) — never `&World` (anti-oracle, spec §10 п.14).
//! * **Injection** — [`inject_adversaries`] re-purposes the world's LAST node slots into
//!   predators. Their CONSTRUCTION (base archetype, inflated demand, present-from-t0) is
//!   applied for BOTH [`RunMode`]s so the predator and its HONEST TWIN are matched to the
//!   tick; only [`RunMode::Predator`] installs the behaviour hooks. The twin is therefore the
//!   SAME heavy node playing honestly — the matched control the Attack-ROI compares against.
//! * **Metrics** — [`AdvMetrics`] is the god-view Attack-ROI read of the injected nodes
//!   (parked live volume, the Р-7 cap ratio, the protected-storage / served integrals, the
//!   ROI, cap-trims, rejoins) — an EVALUATOR read, never fed into a decision.
//!
//! ## Attack-ROI, honestly (finding 0.1: mean extraction ROI ≡ 1 is conservative)
//!
//! The served matrix conserves globally (`Σ consumed ≡ Σ served_out`), so the mean extraction
//! ratio over ALL nodes is exactly 1 — "everyone extracts" is impossible. The honest test is
//! therefore COMPARATIVE, predator vs matched twin, and reads as `pred ≤ twin`. TWO verdict
//! rows carry it (plus the Р-7 cap):
//!  * PROTECTED-storage integral `consumed` (§3.3 utility = "own gb·days protected") — the
//!    STRUCTURALLY robust comparative: it stays well-defined and `pred ≤ twin` even for a
//!    FUTURE predator whose served DIVERGES from its twin's (a true zero-give parasite drives
//!    `served_out → 0`, which leaves the raw ratio undefined);
//!  * RAW ROI `consumed / served_out` — asserted as an ADDITIONAL row WHILE it is defined. In
//!    the A1/A4 scenarios BOTH sides serve comparably (`served_out(pred) ≈ served_out(twin)`),
//!    so the raw ratio is well-defined and `pred < twin` (1.32 < 1.99 for A1, 0.65 < 1.41 for
//!    A4). It is NOT reduced to a diagnostic — it is a real board row here.
//!
//! The whale's PARKED volume is additionally capped below the twin's (the Р-7 cap, INV-P1B-CAP).

use viaticum_core::four_r::{RetentionCap, kappa_key};

use crate::sim_dynamic::engine::{DynParams, depth_params_of, retention_cap, v_per_symbol_of};
use crate::sim_dynamic::generator::{Archetype, OwnBlock, World};

use crate::sim_adv::scenario::{AdvAction, AdvContext, AdvId, AdvRole, AdvSpec, BehaviorHook};

/// Which side of the matched comparison a run is on: the predator (hooks active) or its
/// honest twin (identical construction, hooks OFF — the matched control).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Hooks installed — the predator runs its strategy.
    Predator,
    /// Hooks omitted — the same heavy node plays honestly (the matched twin).
    Twin,
}

// ============================================================
// Behaviour hooks (spec §10 п.14: fn(&AdvContext) -> AdvAction, no &World).
// ============================================================

/// A1 ε-give whale: as a HOLDER it accepts only `whale_accept` (≈5%), so it earns almost no
/// reciprocity κ_O and the Р-7 cap trims its parked volume to ≈ V_free at every holder.
/// Never rejoins.
pub fn a1_epsilon_whale_hook(ctx: &AdvContext) -> AdvAction {
    AdvAction {
        accept_rate: Some(ctx.dials.whale_accept),
        ..AdvAction::NOOP
    }
}

/// A4 whitewasher: BURNS its identity every `period_ticks` (measured from the CURRENT
/// identity's join tick — the cadence resets on each burn).
///
/// Between burns it returns `accept_rate = None`, i.e. it serves at the FULL archetype rate
/// (Reliable ⇒ ~1.0). This is deliberately STRONGER than the brief's prose "serve minimally":
/// serving fully lets each identity build REAL reciprocity κ_O within its cycle — and then the
/// burn THROWS IT AWAY. That makes the acceptance sharper, not weaker: the whitewasher pays
/// the honest entry (θ_p/λ) every cycle and still ends up with strictly less delivered park
/// than the twin, precisely because the reset discards what the serving earned. A
/// serve-minimally variant would earn less to lose, a WEAKER test of the re-entry price.
pub fn a4_whitewasher_hook(ctx: &AdvContext) -> AdvAction {
    let period = ctx.dials.period_ticks;
    let elapsed = ctx.tick.saturating_sub(ctx.joined_tick);
    // Rejoin once per period, strictly after the join tick (so a just-revived identity at
    // `elapsed == 0` does not immediately re-burn).
    let rejoin = period > 0 && ctx.tick > ctx.joined_tick && elapsed.is_multiple_of(period);
    AdvAction {
        rejoin,
        ..AdvAction::NOOP
    }
}

/// A no-op hook (the phase-1 default for the not-yet-implemented zoo members).
fn noop_hook(_ctx: &AdvContext) -> AdvAction {
    AdvAction::NOOP
}

/// A2 DropNotice-refuser, SILENT variant (the молчун / predator arm). It VOLUNTARILY drops a
/// fraction `dials.drop_rate` of its own foreign holdings every tick WITHOUT announcing —
/// each dropped symbol dies now and is detected on the owner's next PoS round (the EXISTING
/// silent-loss path: `t_n = 0`, `b_max`, `drop_silent`, σ-jump). Serves fully otherwise
/// (`accept_rate = None` ⇒ the Reliable-base rate), so the ONLY thing separating it from its
/// polite twin is the announcedness of the drop — the price of silence.
pub fn a2_silent_dropper_hook(ctx: &AdvContext) -> AdvAction {
    AdvAction {
        drop_frac_per_tick: Some(ctx.dials.drop_rate.max(0.0)),
        announce_drops: false,
        ..AdvAction::NOOP
    }
}

/// A2 DropNotice-refuser, POLITE variant (the вежливый двойник / matched twin). It drops the
/// SAME fraction `dials.drop_rate` of the SAME holdings by the SAME deterministic selection —
/// EQUAL harm — but ANNOUNCES each drop, so it rides the EXISTING F2 notice mechanism (noticed
/// at T, dies at T+1, `t_n = 7`d, `b_ann`, `drop_ann`; no σ-jump). This is the A2 matched
/// control (unlike A1/A4, whose control is the honest hooks-off node): it isolates the ONE
/// variable — announcedness — holding the drop-rate constant.
pub fn a2_polite_dropper_hook(ctx: &AdvContext) -> AdvAction {
    AdvAction {
        drop_frac_per_tick: Some(ctx.dials.drop_rate.max(0.0)),
        announce_drops: true,
        ..AdvAction::NOOP
    }
}

/// The behaviour hook for a predator id in the PREDATOR arm. Phase 1 implements A1 + A4 + A2
/// (A2 predator = the SILENT dropper); the rest are still skeleton (a no-op hook) — an A3/A5+
/// scenario would run but exert no adversary pressure (their tranches are later — spec §6).
pub fn hook_for(id: AdvId) -> BehaviorHook {
    match id {
        AdvId::A1EpsilonWhale => a1_epsilon_whale_hook,
        AdvId::A4Whitewasher => a4_whitewasher_hook,
        AdvId::A2DropRefuser => a2_silent_dropper_hook,
        _ => noop_hook,
    }
}

/// The behaviour hook for a predator id in the matched-TWIN arm. For A1/A4 the matched control
/// is the HONEST node (`noop_hook`, hooks OFF), unchanged. For A2 the matched control is NOT
/// honest — it is the POLITE dropper (`a2_polite_dropper_hook`): the same equal-harm drop
/// stream, announced. This is the only place the "what does the matched twin do" policy
/// branches per predator; A1/A4 stay byte-identical (they still get `noop_hook`).
pub fn twin_hook_for(id: AdvId) -> BehaviorHook {
    match id {
        AdvId::A2DropRefuser => a2_polite_dropper_hook,
        _ => noop_hook,
    }
}

// ============================================================
// Injection (deterministic; no RNG).
// ============================================================

/// Inject the scenario's adversaries into a freshly-built world. The LAST `Σ count` node
/// slots are re-purposed: their construction is applied for BOTH modes (so predator and twin
/// are matched), and BOTH modes install an `adv` role — the ONLY difference is the hook. Returns
/// the adversary node indices, in injection order, for the metric read.
///
/// **The twin carries a role, not `None` (WARN-1 fix).** An `adv` role makes the engine's
/// `churn` treat the node as HOOK-driven — it bypasses the random-departure Bernoulli. If the
/// twin had `None` it would churn at `p ≈ 0.002/tick` (≈29% chance of departing over a
/// 170-tick horizon) while the predator (which always carries a role) is immortal — a MORTALITY
/// confound on top of the intended hook difference. The twin's hook is [`twin_hook_for`]: for
/// A1/A4 it is `noop_hook` (accept_rate `None` ⇒ the archetype rate, no rejoin, no drop) — the
/// clean hooks-OFF honest control; for A2 it is the POLITE dropper — the equal-harm matched
/// control that isolates announcedness. Either way the twin carries a role, so it is immortal
/// exactly like the predator (no mortality confound).
pub fn inject_adversaries(
    world: &mut World,
    adversaries: &[AdvSpec],
    params: &DynParams,
    mode: RunMode,
) -> Vec<usize> {
    let n = world.nodes.len();
    let total: usize = adversaries.iter().map(|s| s.count).sum();
    if total == 0 || total > n {
        return Vec::new();
    }
    let mut idx = n - total;
    let mut nodes = Vec::with_capacity(total);
    for spec in adversaries {
        for _ in 0..spec.count {
            let node = idx;
            configure_adv_node(world, node, spec, params);
            let hook = match mode {
                RunMode::Predator => hook_for(spec.id),
                RunMode::Twin => twin_hook_for(spec.id),
            };
            world.adv[node] = Some(AdvRole {
                id: spec.id,
                info_model: spec.info_model,
                dials: spec.dials,
                hook,
            });
            nodes.push(node);
            idx += 1;
        }
    }
    nodes
}

/// Configure one node into the shared (mode-independent) adversary shape: a present-from-t0,
/// high-uptime cooperative base (a consistent placer whose symbols are reliably challenged —
/// the strategy rides on the hook, not on a flaky base archetype), with A1's inflated
/// backup demand (`whale_block_mult`) or A4's plain demand.
fn configure_adv_node(world: &mut World, node: usize, spec: &AdvSpec, params: &DynParams) {
    world.nodes[node].archetype = Archetype::Reliable;
    world.nodes[node].joined_tick = 0;
    world.nodes[node].present = true;
    world.nodes[node].holdings.clear();

    let mult = match spec.id {
        AdvId::A1EpsilonWhale => spec.dials.whale_block_mult.max(1.0),
        _ => 1.0,
    };
    let n_blocks = ((params.blocks_per_node as f64) * mult).round() as usize;
    let n_blocks = n_blocks.max(1);
    let mut blocks = Vec::with_capacity(n_blocks);
    world.next_block_id[node] = 0;
    for b in 0..n_blocks {
        let id = world.next_block_id[node];
        world.next_block_id[node] += 1;
        blocks.push(OwnBlock {
            id,
            volume: params.block_volume,
            iota: 0.2 + 0.6 * (b as f64) / (n_blocks.max(2) - 1) as f64,
            placements: Vec::new(),
            floor_ever_met: false,
            floor_deficit_since: None,
            to_restore: false,
        });
    }
    world.nodes[node].own_blocks = blocks;
}

// ============================================================
// Metrics — the Attack-ROI god-view read (evaluator role, never a decision input).
// ============================================================

/// The god-view Attack-ROI read of the injected adversary nodes at the run horizon.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdvMetrics {
    /// SETTLED live parked volume (gb) summed over the adversary nodes: alive own symbols on
    /// present holders, EXCLUDING those already noticed for eviction (a cap-trim / pressure
    /// DropNotice dies next tick — the settled state is what the node actually keeps).
    pub parked_live: f64,
    /// Max over (adversary, EVICTING holder) of `settled_parked / (V_ret + one chunk)`. The
    /// Р-7 cap is enforced during eviction, so this is measured exactly where it binds:
    /// ≤ 1.0 ⇒ the cap holds (parked within V_ret + the chunk-granularity tolerance). `NaN`
    /// if no evicting holder carries adversary data on this seed (cap never engaged).
    pub max_cap_ratio: f64,
    /// `consumed = Σ_h served[h][adv]` — the protected-own-storage TIME-INTEGRAL (gb·days the
    /// adversary's own data was retained-and-PoS-confirmed). The §3.3 utility ("own gb·days
    /// protected"); the load-bearing pred-vs-twin comparative.
    pub consumed: f64,
    /// `served_out = Σ_h served[adv][h]` — the outbound service integral (what the adversary
    /// GAVE others). The ROI cost.
    pub served_out: f64,
    /// `roi = consumed / served_out` (`NaN` if `served_out == 0`). The raw extraction ratio; a
    /// board row asserts `roi(pred) < roi(twin)` WHILE it is defined (both A1/A4 sides serve
    /// comparably, so it is). `consumed` above stays the structurally-robust comparative for a
    /// future predator whose served diverges from its twin's (there `served_out → 0` ⇒ NaN).
    pub roi: f64,
    /// Whitewash rejoin cycles the adversary nodes completed (Σ `adv_rejoin_count`).
    pub rejoins: usize,
    /// World cap-trim count at the horizon (evidence the Р-7 cap engaged). Global — the honest
    /// baseline barely trims (≈ 0-1), an ε-whale world trims heavily.
    pub cap_trims: usize,
    /// A2 (DropNotice-refuser) — the PRICE-OF-SILENCE ledger: `Σ_O capital[O][adv].g_oh` over
    /// NON-adversary owners O = the reliability capital owners hold in the adversary (`G(O←adv)`,
    /// the owner's record of the adversary's service TO it). A voluntary drop BURNS this: SILENT
    /// at `b_max` (a total-loss burn ⇒ ≈ 0), ANNOUNCED at `b_ann` (barely). The load-bearing A2
    /// comparative — silent's ledger ≪ polite's. `0` for a scenario with no A2 drops.
    pub retention_g: f64,
    /// A2 — placement-INFLOW proxy: `Σ_adv holdings.len()` = the cumulative count of foreign
    /// symbols the adversary was ever OFFERED-AND-ACCEPTED (dead-marked drops stay in the vec, so
    /// the length is monotone = total inflow over the run). The spec's "владельцы отворачиваются"
    /// row reads this: inflow(silent) vs inflow(polite). See the A2 report finding on whether the
    /// DECISIVE placement path can discriminate them (post-0.3 it reads surface only).
    pub inflow_total: f64,
    /// A2 — DIAGNOSTIC σ-profile: `Σ_O capital[O][adv].sigma` over non-adversary owners = the
    /// suspicion owners carry toward the adversary. A SILENT loss jumps σ by the full `j_σ`; an
    /// announced drop does NOT jump σ, so silent's σ ≫ polite's. σ is INERT in the kernel (no
    /// decision reads it — spec §3), so this is reported, never asserted.
    pub sigma_owed: f64,
    /// A2 — the price-of-silence ledger, TIME-INTEGRATED over the run (`Σ_t retention_g`). After
    /// the seat-sync burn fix (2026-07-19) the two arms DIVERGE chaotically, so the horizon
    /// SNAPSHOT `retention_g` is noisy; the integral averages out the per-tick chaos into a
    /// stable paired ratio — the load-bearing INV-A2-SILENT-PUNISHED quantity. `0` when no
    /// adversary ran.
    pub retention_g_integral: f64,
    /// A2 — the adversary's PARKED own-volume, TIME-INTEGRATED over the run (`Σ_t parked_live`).
    /// The RETENTION channel now enforced (the seat-sync fix lets the drop burn the enforcement
    /// key `g_ho`, so V_ret / eviction / preemption squeeze the silent dropper's parked data
    /// harder than the polite twin's). Integrated for the same noise-smoothing reason. A
    /// downstream diagnostic (diluted by non-victim park + the un-burned depth floor). `0` when
    /// no adversary ran.
    pub parked_integral: f64,
    /// A2 — the DIRECT enforcement count: how many of the ADVERSARY's OWN symbols holders dropped
    /// over the run (`eviction_log` entries whose `owner ∈ adversaries`: pressure drops +
    /// preemption victims + Р-7 cap-trims). This is the enforcement ACTION the burned `g_ho`
    /// drives. DIAGNOSTIC ONLY (report row, very noisy — no invariant asserts it; the
    /// INV-A2-RETENTION board row is fed by `parked_integral`, and the enforcement PROOF is
    /// the κ_O row INV-A2-SILENT-PUNISHED). `0` when no adversary ran.
    pub data_evicted: f64,
}

/// Bit-exact equality (the determinism board row). `to_bits` so a deterministically-produced
/// `NaN` compares equal to itself.
pub fn bit_eq(a: &AdvMetrics, b: &AdvMetrics) -> bool {
    a.parked_live.to_bits() == b.parked_live.to_bits()
        && a.max_cap_ratio.to_bits() == b.max_cap_ratio.to_bits()
        && a.consumed.to_bits() == b.consumed.to_bits()
        && a.served_out.to_bits() == b.served_out.to_bits()
        && a.roi.to_bits() == b.roi.to_bits()
        && a.rejoins == b.rejoins
        && a.cap_trims == b.cap_trims
        && a.retention_g.to_bits() == b.retention_g.to_bits()
        && a.inflow_total.to_bits() == b.inflow_total.to_bits()
        && a.sigma_owed.to_bits() == b.sigma_owed.to_bits()
        && a.retention_g_integral.to_bits() == b.retention_g_integral.to_bits()
        && a.parked_integral.to_bits() == b.parked_integral.to_bits()
        && a.data_evicted.to_bits() == b.data_evicted.to_bits()
}

/// A2 per-tick god-view aggregate of the injected adversaries: `(Σ_O g_oh, Σ parked_live)` where
/// O ranges over the NON-adversary owners and parked is the adversaries' alive own volume on
/// present holders. The runner folds this every tick into the time-integrals (the seat-sync fix
/// makes the horizon snapshot chaotic; the integral is the stable paired signal). Evaluator-only.
pub fn observe_adv_aggregates(world: &World, nodes: &[usize]) -> (f64, f64) {
    let n = world.nodes.len();
    let is_adv = |o: usize| nodes.contains(&o);
    let mut g = 0.0f64;
    let mut park = 0.0f64;
    for &adv in nodes {
        for o in 0..n {
            if o == adv || is_adv(o) {
                continue;
            }
            g += world.capital[o][adv].g_oh;
        }
        for h in 0..n {
            if h == adv || !world.nodes[h].present {
                continue;
            }
            park += settled_parked_on(world, adv, h);
        }
    }
    (g, park)
}

/// Is `(holder, owner, block)` currently noticed for eviction (a pending DropNotice that dies
/// next tick)? Such a symbol is already effectively trimmed — excluded from the settled read.
fn is_noticed(world: &World, holder: usize, owner: usize, block: usize) -> bool {
    world
        .pending_evictions
        .iter()
        .any(|p| p.holder == holder && p.owner == owner && p.block == block)
}

/// Settled live parked volume (gb) of `owner`'s own symbols on `holder`: alive, minus any
/// symbol already noticed for eviction (the post-DropNotice state).
fn settled_parked_on(world: &World, owner: usize, holder: usize) -> f64 {
    world.nodes[holder]
        .holdings
        .iter()
        .filter(|s| s.alive && s.owner == owner && !is_noticed(world, holder, owner, s.block))
        .map(|s| s.volume)
        .sum()
}

/// The MAX Р-7 cap ratio `settled_parked / (V_ret + one chunk)` over (adversary, EVICTING
/// holder) pairs THIS tick (`NaN` if no evicting holder carries adversary data now). The
/// runner folds this over every tick so the cap invariant captures the cap wherever it
/// engaged during the run — the eviction latch is momentary, so an end-of-run snapshot alone
/// would usually miss it. Measured EXACTLY on evicting holders (where the cap is the binding
/// constraint; elsewhere the constraint is disk room and the node is trimmed the moment that
/// holder contends), on the SETTLED parked (a noticed cap-trim / pressure drop already
/// excluded), so a passing tick reads `parked ≤ V_ret`.
pub fn observe_cap_ratio(world: &World, params: &DynParams, nodes: &[usize]) -> f64 {
    let n = world.nodes.len();
    let vps = v_per_symbol_of(params);
    let dp = depth_params_of(params, vps);
    let cap: RetentionCap = retention_cap(params, vps);
    if !cap.active() {
        return f64::NAN;
    }
    let mut max_ratio = f64::NAN;
    for &adv in nodes {
        for h in 0..n {
            if h == adv || !world.nodes[h].present || !world.nodes[h].evict_phase.evicting {
                continue;
            }
            let parked = settled_parked_on(world, adv, h);
            if parked <= 0.0 {
                continue;
            }
            let kappa = kappa_key(
                world.capital[adv][h].g_ho,
                world.capital[adv][h].depth_ho,
                &dp,
            );
            let ratio = parked / (cap.v_ret(kappa) + vps);
            max_ratio = if max_ratio.is_nan() {
                ratio
            } else {
                max_ratio.max(ratio)
            };
        }
    }
    max_ratio
}

/// Fold a fresh per-tick cap ratio into a running maximum (NaN-tolerant: NaN is "no sample").
pub fn fold_cap_ratio(running: f64, tick_ratio: f64) -> f64 {
    match (running.is_nan(), tick_ratio.is_nan()) {
        (_, true) => running,
        (true, false) => tick_ratio,
        (false, false) => running.max(tick_ratio),
    }
}

/// Collect the Attack-ROI read for the injected adversary `nodes` from the horizon world.
/// `run_cap_ratio` is the per-tick-tracked max Р-7 cap ratio (see [`observe_cap_ratio`]) —
/// threaded in because the cap engages transiently through the run, not only at the horizon.
/// (The end-of-run integrals here read only the god-view world, no dials.)
pub fn collect_adv_metrics(
    world: &World,
    nodes: &[usize],
    run_cap_ratio: f64,
    retention_g_integral: f64,
    parked_integral: f64,
) -> AdvMetrics {
    let n = world.nodes.len();

    let mut parked_live = 0.0f64;
    let mut consumed = 0.0f64;
    let mut served_out = 0.0f64;
    let mut rejoins = 0usize;
    // A2 reads: reliability ledger owners hold in the adversary + suspicion + inflow.
    let mut retention_g = 0.0f64;
    let mut sigma_owed = 0.0f64;
    let mut inflow_total = 0.0f64;
    let is_adv = |o: usize| nodes.contains(&o);

    for &adv in nodes {
        rejoins += world.adv_rejoin_count[adv];
        inflow_total += world.nodes[adv].holdings.len() as f64;
        for h in 0..n {
            consumed += world.served[h][adv];
            served_out += world.served[adv][h];
        }
        for h in 0..n {
            if h == adv || !world.nodes[h].present {
                continue;
            }
            parked_live += settled_parked_on(world, adv, h);
        }
        // A2 price-of-silence ledger + σ-profile: sum over NON-adversary owners O of the
        // reliability capital `capital[O][adv].g_oh` (owners' record of the adversary's service)
        // and their suspicion `capital[O][adv].sigma`. The drop burn hits g_oh; a silent loss
        // jumps σ.
        for o in 0..n {
            if o == adv || is_adv(o) {
                continue;
            }
            retention_g += world.capital[o][adv].g_oh;
            sigma_owed += world.capital[o][adv].sigma;
        }
    }

    let roi = if served_out > 0.0 {
        consumed / served_out
    } else {
        f64::NAN
    };

    // DIRECT enforcement count: adversary-owned symbols holders dropped over the run.
    let data_evicted = world
        .eviction_log
        .iter()
        .filter(|e| nodes.contains(&e.owner))
        .count() as f64;

    AdvMetrics {
        parked_live,
        max_cap_ratio: run_cap_ratio,
        consumed,
        served_out,
        roi,
        rejoins,
        cap_trims: world.cap_trim_count,
        retention_g,
        inflow_total,
        sigma_owed,
        retention_g_integral,
        parked_integral,
        data_evicted,
    }
}
