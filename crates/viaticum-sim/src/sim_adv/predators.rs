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

use crate::sim_adv::scenario::{
    AdvAction, AdvContext, AdvId, AdvRole, AdvSpec, BehaviorHook, InfoModel,
};
use crate::sim_adv::uptime::UptimeProfile;

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

/// A3 flapper: the FLAP itself is the bursty UPTIME PROFILE ([`install_adv_uptime`] installs a
/// [`crate::sim_adv::uptime::UptimeProfile::Seasonal`] on/off cycle in the predator arm and a
/// mean-matched iid [`crate::sim_adv::uptime::UptimeProfile::Ragged`] on the twin), NOT a BEHAVIOUR
/// override — so the hook is a no-op. The flapper serves honestly WHEN it is up; its σ/pass
/// divergence from the mean-matched honest twin comes entirely from the availability autocorrelation.
pub fn a3_flapper_hook(_ctx: &AdvContext) -> AdvAction {
    AdvAction::NOOP
}

/// A5 деep-silent: the deep node goes silent (PRESENT = false — a PAUSE, not a death) for the
/// contiguous window `[pause_start, pause_start + pause_len)`, then returns. First-hand: it reads
/// only its own strategy dials and the tick. Its capital / holdings / own blocks are untouched by
/// the pause (see `engine::adv_pause`); the depth-floor test is whether its OWN parked data survives
/// the κ_O erosion of the silence.
pub fn a5_deep_silent_hook(ctx: &AdvContext) -> AdvAction {
    let start = ctx.dials.pause_start;
    let len = ctx.dials.pause_len;
    let paused = len > 0 && ctx.tick >= start && ctx.tick < start.saturating_add(len);
    AdvAction {
        offline: paused,
        ..AdvAction::NOOP
    }
}

/// A6 discriminator: as a HOLDER it SILENTLY drops the symbols of SMALL owners (footprint
/// `own_blocks.len() <= dials.discr_max_blocks`) every tick — "serves the large, sheds the small".
/// `drop_frac_per_tick = 1.0` ⇒ it sheds ALL currently-held small-owner data each tick, so it never
/// retains a small owner. Serves large owners fully (`accept_rate = None`). The victim-restriction
/// to small owners is applied in `engine::adv_voluntary_drops` via `discriminate`.
pub fn a6_discriminator_hook(_ctx: &AdvContext) -> AdvAction {
    AdvAction {
        drop_frac_per_tick: Some(1.0),
        announce_drops: false,
        discriminate: true,
        ..AdvAction::NOOP
    }
}

/// A15 incumbent-enclosure: as a HOLDER it declares the enclosure FLAG every tick — the engine
/// then hard-rejects (in `admit_offer`) any owner whose reciprocity `capital[owner][holder].g_ho`
/// is below the cartel's `enclose_thresh` (a newcomer that has not served the cartel). First-hand:
/// the hook reads only its own context and returns a flag; it NEVER learns who is a newcomer (that
/// is the engine's g_ho read on the holder's own pair capital — anti-oracle preserved).
pub fn a15_incumbent_enclosure_hook(_ctx: &AdvContext) -> AdvAction {
    AdvAction {
        enclose_newcomers: true,
        ..AdvAction::NOOP
    }
}

/// A7 sybil-farm: the farm ε-serves (`accept_rate = whale_accept`, ≈0 — it stores ~nothing real, so
/// it earns NO honest reciprocity `capital[sybil][honest].g_ho`) and DECLARES collusion when its own
/// `collude` dial is set. The engine's `adv_collude_farm` pass then accrues FAKE mutual served/g_ho
/// among the same-`group_subnet` farm-mates (no real holdings). First-hand: the hook reads only its
/// own dials + returns flags; it NEVER learns who the farm-mates are (that is the engine's god-view
/// membership read — anti-oracle preserved, the same split as A6/A15). The `collude` dial is the
/// clean ON/OFF A/B lever: with it false the SAME ε-serving farm runs but the collusive pass is off,
/// isolating collusion from the (fixed) construction. The ε-serve is what makes "the farm never
/// served honest" TRUE in the sim (spec §2): without it the farm would earn REAL honest storage and
/// the V_free-surface finding would not isolate.
pub fn a7_sybil_farm_hook(ctx: &AdvContext) -> AdvAction {
    AdvAction {
        accept_rate: Some(ctx.dials.whale_accept),
        collude_farm: ctx.dials.collude,
        ..AdvAction::NOOP
    }
}

/// A8 collusion-ring / friend-circle (`4r_a8_spec.md`): ONE hook, both arms — every lever is read
/// off the node's OWN dials (first-hand), so the arms differ by dials alone and the construction
/// stays fixed across them:
///
/// * `accept_rate = whale_accept` — how much this node serves as a HOLDER, toward EVERYONE alike.
///   **R1 (fake ring)** sets ε: it accepts little, from strangers and ring-mates equally (it runs
///   no group policy at all), and the collusive PoS is a SUPPLEMENT to that little real storage,
///   not a substitute for it. ⚠ MEASURED, R1 still ends up holding its friends' data — the ring's
///   own symbols sit 0.865 inside the ring (twin 0.289), because the fake κ_O makes each ring
///   holder RETAIN the ring-mates' symbols it did accept and shed the strangers'. **R2 (friend
///   circle)** sets 1.0 (it really stores) and pairs it with `serve_ring_only`.
/// * `serve_group_only = serve_ring_only` — R2's "I store for my friends, not for strangers". The
///   hook declares only the FLAG; WHO is a friend is the engine's god-view membership read in
///   `admit_offer` (anti-oracle split, as A6/A15/A7).
/// * `collude_farm = collude` — R1's collusive fake PoS (the shared `adv_collude_farm` pass). This
///   is the ONE dial the matched TWIN flips ([`a8_ring_twin_hook`]), so the board comparative
///   isolates COLLUSION from the ring's construction.
///
/// It never learns who its ring-mates are, and it never reads `&World`.
pub fn a8_collusion_ring_hook(ctx: &AdvContext) -> AdvAction {
    AdvAction {
        accept_rate: Some(ctx.dials.whale_accept),
        serve_group_only: ctx.dials.serve_ring_only,
        collude_farm: ctx.dials.collude,
        ..AdvAction::NOOP
    }
}

/// A8's MATCHED TWIN (`4r_a8_spec.md` §1.1): the SAME ring — same demand, same accept rate, same
/// serving policy — with COLLUSION OFF. One dial, exactly the A2 polite-twin idiom: the twin is not
/// an honest hooks-off node (that would confound collusion with the ring's ε-serving construction),
/// it is the ring playing without the fake PoS. So `ext_roi(pred)/ext_roi(twin)` prices COLLUSION
/// and nothing else.
pub fn a8_ring_twin_hook(ctx: &AdvContext) -> AdvAction {
    AdvAction {
        collude_farm: false,
        ..a8_collusion_ring_hook(ctx)
    }
}

/// A9 eclipse-targeter (`4r_a9_spec.md` §2.1): an EXEMPLARY holder that is recruited into the
/// victim's holder set by the ordinary candidate ranking (`accept_rate = 1.0`, never drops, passes
/// PoS honestly) and then drops synchronously. Which of the three ARMS it plays is read off its own
/// declared info-model + dials — all first-hand, never `&World`:
///
/// * **arm B (card)** — `InfoModel::DrCard`: from `eclipse_arm_tick` it declares
///   `eclipse_lethal_watch`. The per-block "how many symbols are alive and how many are mine"
///   knowledge — the CROWN-1 leak itself — is read ENGINE-side; the hook never sees a count.
/// * **arm A (blind schedule)** — `InfoModel::Own`, `eclipse_on_silence = false`: it fires on ONE
///   fixed tick, `eclipse_drop_tick`.
/// * **arm C (blind-on-silence)** — `InfoModel::Own`, `eclipse_on_silence = true`: it declares
///   readiness EVERY tick ("I will drop the moment I notice my owner went quiet"); the engine gates
///   the actual fire on the silence latch, so the hook stays blind to the world.
///
/// **Why arm A is a ONE-SHOT (`tick == drop_tick`), deviating from the spec's literal
/// `tick >= drop_tick`.** A standing `>=` makes arm A a permanent BOYCOTT: it re-drops every
/// re-placement for the rest of the run, so (a) it burns symbols every tick — destroying the
/// symbols-per-kill efficiency comparison the price of the card is expressed in — and (b) by the
/// disaster tick it holds nothing of the target, so "the blind schedule missed the DR window" would
/// be measuring capacity-denial, not timing. A single dated volley is the faithful "blind schedule"
/// the spec describes ("the owner has time to repair it").
///
/// **Why arm B is ALSO silence-gated (an engine-side gate shared with arm C).** The silence signal
/// is first-hand (§1.3 grants it to the blind arm C explicitly), so a card-holder has it too;
/// withholding it from B would (a) confound the headline B-vs-C with "card vs silence" instead of
/// isolating the card, and (b) make B fire while the owner is still ALIVE, where P1 repair simply
/// undoes the drop — a NEGATIVE card price that is an artifact of a mis-specified trigger. With the
/// shared gate, B and C fire on the SAME tick from the SAME signal, and the only difference left
/// between them is the per-block card. (`eclipse_on_silence = false` on a DrCard role is kept
/// working as an A/B lever: it measures the un-timed card.)
pub fn a9_eclipse_targeter_hook(ctx: &AdvContext) -> AdvAction {
    let base = AdvAction {
        // An exemplary holder: accepts everything, so the ordinary candidate ranking recruits it
        // into the victim's holder set (spec §1.1 BLOCK-2 — no god-view forcing of the choice).
        //
        // ⚠ Read this honestly: the accept override is NOT what recruits the group. The injected
        // base archetype is already `Reliable`, whose willingness is 1.0, so `Some(1.0)` is
        // behaviourally identical to the honest path. What actually concentrates the victim's
        // symbols on the group is its CONSTRUCTION (`configure_adv_node`): present from t=0,
        // 0.99 uptime, no backup demand of its own (so most of its disk is free to lend) and — as
        // any node carrying an `adv` role — immune to the churn Bernoulli. The flag stays because
        // it DECLARES the strategy.
        //
        // ⚠ And do NOT read the group as super-concentrated (review W4). At G = 40 it holds 0.371
        // of the victim's alive symbols at 0.286 of the roster — but across the sweep that ratio
        // is 1.26 / 2.28 / 1.37 / 0.78 / 1.30 / 1.27 (G = 5…50), i.e. it straddles 1.0 and the
        // "≈1.3× proportional" reading of the frozen G alone is a cherry. The group holds roughly
        // its share. What share it holds is itself set by the roster denominator: with
        // `n0_frac = 0.20` the whole group is present from t = 0 while only ~20 honest nodes are,
        // so during the victim's INITIAL placement window the group was about two thirds of the
        // reachable network. That — not any reputation-driven concentration — is the mechanism.
        accept_rate: Some(1.0),
        ..AdvAction::NOOP
    };
    match ctx.info_model {
        InfoModel::DrCard { .. } => AdvAction {
            eclipse_lethal_watch: ctx.tick >= ctx.dials.eclipse_arm_tick,
            ..base
        },
        InfoModel::Own => AdvAction {
            eclipse_fire: if ctx.dials.eclipse_on_silence {
                true // ready every tick; the ENGINE's silence latch decides when it lands
            } else {
                ctx.tick == ctx.dials.eclipse_drop_tick
            },
            ..base
        },
    }
}

/// The `RestoreTruth::info_model` label for a scenario's adversaries (`4r_world_v3_spec.md` NOTE-5:
/// the field exists exactly for A9's arm comparison). `"dr_card"` / `"own_silence"` /
/// `"own_schedule"` for the three A9 arms, `"none"` for every other scenario (unchanged output).
pub fn a9_arm_label(adversaries: &[AdvSpec]) -> &'static str {
    match adversaries
        .iter()
        .find(|a| a.id == AdvId::A9EclipseTargeter)
    {
        Some(spec) => match spec.info_model {
            InfoModel::DrCard { .. } => "dr_card",
            InfoModel::Own if spec.dials.eclipse_on_silence => "own_silence",
            InfoModel::Own => "own_schedule",
        },
        None => "none",
    }
}

/// The behaviour hook for a predator id in the PREDATOR arm. A1 ε-whale, A4 whitewasher, A2 silent
/// dropper, A5 deep-silent pause, A6 discriminatory drop, A7 sybil-farm collusion, A8 collusion-ring
/// / friend-circle, A15 incumbent-enclosure. A3's flap is an uptime profile (not a hook), so its
/// predator hook is a no-op; the rest (A11-A14) are skeleton no-ops (later tranches).
pub fn hook_for(id: AdvId) -> BehaviorHook {
    match id {
        AdvId::A1EpsilonWhale => a1_epsilon_whale_hook,
        AdvId::A4Whitewasher => a4_whitewasher_hook,
        AdvId::A2DropRefuser => a2_silent_dropper_hook,
        AdvId::A3Flapper => a3_flapper_hook,
        AdvId::A5DeepSilent => a5_deep_silent_hook,
        AdvId::A6Discriminator => a6_discriminator_hook,
        AdvId::A7SybilFarm => a7_sybil_farm_hook,
        AdvId::A8CollusionRing => a8_collusion_ring_hook,
        AdvId::A9EclipseTargeter => a9_eclipse_targeter_hook,
        AdvId::A15IncumbentEnclosure => a15_incumbent_enclosure_hook,
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
        // A5's matched control is the SAME deep node PAUSING IDENTICALLY, differing ONLY in the
        // depth-floor dial (`depth_w_d = 0` via `twin_params`, spec: "тот же узел в мире с w_d=0").
        // So the twin must ALSO run the pause hook — the pause is the constant, the D-floor the
        // isolated variable (analogous to A2's polite twin isolating announcedness).
        AdvId::A5DeepSilent => a5_deep_silent_hook,
        // A8's matched control is NOT honest either — it is the SAME ring with COLLUSION OFF
        // (`a8_ring_twin_hook`): same demand, same accept rate, same serving policy, one dial
        // flipped, so the ROI comparative prices collusion and not the ring's construction.
        AdvId::A8CollusionRing => a8_ring_twin_hook,
        // A1/A4/A3/A6/A15/A9: the matched control is the HONEST node (hooks off). For A3 the flap is
        // the uptime profile (mode-differentiated in `install_adv_uptime`), so its hook stays noop.
        // A15 is a cartel-fraction SWEEP, NOT a twin comparison (its control is a separate
        // cartel_frac=0 run), so its twin hook is a plain noop — an honest incumbent that never
        // encloses (kept role-carrying only for churn-immortality parity with the predator arm).
        // A9 (eclipse) is likewise a world-cut across THREE arms (its control is the count = 0 run
        // + the disarmed-watch A/B), so it never runs a twin either.
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

/// World-v3 phase-3 (A15): inject an INCUMBENT-ENCLOSURE cartel (spec §2). Unlike
/// [`inject_adversaries`] — which re-purposes the world's LAST slots (under inflow, the NEWCOMER
/// arrival pool) — the cartel is the `spec.dials.group_size` EARLIEST-ESTABLISHED present nodes:
/// sort the present nodes by `(joined_tick, index)` and take the prefix. At t=0 those are exactly
/// the `joined_tick == 0` bootstrap incumbents, so the cartel is DISJOINT from the inflow pool
/// (whose nodes start `present = false` with `joined_tick ≥ 1`). Deterministic — a pure sort, NO
/// RNG, so it perturbs no engine stream (determinism preserved).
///
/// The cartel members are drawn from the EXISTING honest population and are NOT re-constructed
/// (no forced Reliable base, no demand inflation — that would confound "an incumbent that stops
/// serving newcomers" with "a heavy node"): only the A15 `adv` role (with the enclosure hook +
/// `enclose_thresh` dial) is layered on. The cartel places its OWN data HONESTLY — there is NO
/// placement-side lever (spec CRITICAL note), so the enclosure is SOFT: a newcomer can serve the
/// cartel first (earning `g_ho`) and break in. `Predator` installs the enclosure hook; `Twin`
/// installs the noop hook (an honest incumbent — A15's control is a separate cartel_frac=0 run,
/// so the twin is unused, kept only for churn-immortality parity). Returns the cartel node indices
/// (ascending). `group_size == 0` ⇒ the empty cartel (the cartel_frac=0 honest-inflow control).
pub fn inject_incumbent_cartel(world: &mut World, spec: &AdvSpec, mode: RunMode) -> Vec<usize> {
    let group_size = spec.dials.group_size;
    if group_size == 0 {
        return Vec::new();
    }
    let mut cartel: Vec<usize> = (0..world.nodes.len())
        .filter(|&i| world.nodes[i].present)
        .collect();
    // Earliest-established first: (joined_tick, index). Take the prefix — the incumbents.
    cartel.sort_by(|&a, &b| {
        world.nodes[a]
            .joined_tick
            .cmp(&world.nodes[b].joined_tick)
            .then(a.cmp(&b))
    });
    cartel.truncate(group_size);
    let hook = match mode {
        RunMode::Predator => hook_for(spec.id),
        RunMode::Twin => twin_hook_for(spec.id),
    };
    for &node in &cartel {
        world.adv[node] = Some(AdvRole {
            id: spec.id,
            info_model: spec.info_model,
            dials: spec.dials,
            hook,
        });
    }
    cartel.sort_unstable(); // ascending node order for a deterministic return
    cartel
}

/// World-v3 phase-2a-2 (A3): install the FLAPPER's structural uptime profile on each A3 adversary
/// slot, MODE-DIFFERENTIATED — the predator flaps (a bursty [`UptimeProfile::Seasonal`] on/off cycle
/// of `period_ticks` weeks, `duty` active), the twin is a mean-matched HONEST diurnal (an iid
/// [`UptimeProfile::Ragged`] whose per-day rate equals the flapper's exact period mean). So the ONLY
/// difference between the arms is the AUTOCORRELATION of absence (clustered off-runs vs spread), the
/// σ/pass discriminator the diagnostic measures. Every OTHER predator id is left on its archetype
/// uptime (A5 pauses via PRESENCE, not surfacing; A1/A2/A4/A6 do not touch availability). Called by
/// the runner AFTER injection (and after any tiered assign), so it wins the A3 slots. Deterministic,
/// no RNG (the profiles are structural; the surfacing draw rides the existing `SURFACE_TAG` stream).
pub fn install_adv_uptime(world: &mut World, adv_nodes: &[usize], mode: RunMode) {
    for &node in adv_nodes {
        let Some(role) = world.adv[node].as_ref() else {
            continue;
        };
        if role.id != AdvId::A3Flapper {
            continue;
        }
        let period = role.dials.period_ticks.max(2);
        let duty = role.dials.duty.clamp(0.0, 1.0);
        let flapper = UptimeProfile::Seasonal { period, duty };
        world.uptime[node] = Some(match mode {
            RunMode::Predator => flapper,
            RunMode::Twin => UptimeProfile::Ragged {
                p: flapper.mean_daily_uptime(period),
            },
        });
    }
}

/// The MATCHED-TWIN dial override for a scenario's adversaries (spec: some predators' matched control
/// differs from the honest node by ONE DIAL, not a hook). A5 (молчащий глубокий): the twin is the
/// SAME deep node in a world with the depth floor OFF (`depth_w_d = 0`), so its parked data's
/// survival across the pause is measured WITHOUT the W10/Р-1 loyalty floor — the isolated variable.
/// `None` for every other predator (their twin shares the predator's dials). Applied by the runner
/// to the TWIN arm's `DynParams` only; the predator arm is untouched.
pub fn twin_dial_override(adversaries: &[AdvSpec]) -> Option<(&'static str, f64)> {
    if adversaries.iter().any(|a| a.id == AdvId::A5DeepSilent) {
        Some(("depth_w_d", 0.0))
    } else {
        None
    }
}

/// Configure one node into the shared (mode-independent) adversary shape: a present-from-t0,
/// high-uptime cooperative base (a consistent placer whose symbols are reliably challenged —
/// the strategy rides on the hook, not on a flaky base archetype), with A1's inflated
/// backup demand (`whale_block_mult`) or A4's plain demand.
///
/// **A9 (eclipse) carries NO backup demand at all** — it is a dedicated STORAGE node an attacker
/// deployed to hold other people's data, not a participant with files of its own. This is not
/// cosmetic: with the ordinary `blocks_per_node` demand, an eclipse group of G = 30 adds 30 owners
/// to an already bandwidth-starved world, and the MEASURED consequence is that the honest owners
/// with at least one established block fall ~25 % (32/30/32 → 25/17/24 on seeds 42-44) and the
/// DR-primary victim itself routinely never establishes — an EMPTY restore denominator, i.e. no
/// measurement at all rather than a strong attack. Removing the attacker's own demand also happens
/// to be the attacker-FAVOURABLE choice (its whole disk is free to attract the victim's symbols),
/// which is the right direction when the deliverable is the PRICE of a leak.
fn configure_adv_node(world: &mut World, node: usize, spec: &AdvSpec, params: &DynParams) {
    world.nodes[node].archetype = Archetype::Reliable;
    world.nodes[node].joined_tick = 0;
    world.nodes[node].present = true;
    world.nodes[node].holdings.clear();

    if spec.id == AdvId::A9EclipseTargeter {
        world.next_block_id[node] = 0;
        world.nodes[node].own_blocks = Vec::new();
        return;
    }

    let mult = match spec.id {
        // A1 whale + A7 sybil-farm both inflate demand via `whale_block_mult` so they have plenty
        // of data to push onto the network (A7: the farm needs data to place to even TRY to capture
        // honest storage — the surface the collusion is tested against).
        AdvId::A1EpsilonWhale | AdvId::A7SybilFarm => spec.dials.whale_block_mult.max(1.0),
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
            target_ever_met: false,
            target_deficit_since: None,
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
    ///
    /// ⚠ **This raw ratio is NOT usable for a GROUP that colludes (A8 finding).** `consumed` and
    /// `served_out` both range over ALL `h`, the group's own members INCLUDED, and
    /// `engine::adv_collude_farm` adds the SAME total `Σ_{i≠j} v_per_symbol` to both sides — so
    /// collusion drags the raw ratio toward 1 mechanically, and a colluding group whose twin
    /// extracts (`roi(twin) > 1`) clears `roi(pred) < roi(twin)` by DILUTION rather than by any
    /// defence holding. MEASURED on the A8 board seeds: the spec's literal `roi` row lands at
    /// 0.9304 ± 0.0497 (power 1.40 ⇒ INCONCLUSIVE, below the X = 1 bar — i.e. it does not convict),
    /// while the same comparison on [`AdvMetrics::ext_roi`] FAILs at 2.7485. Use `ext_roi` for a
    /// group; both are printed side by side in the A8 calibration dump, and the swap is pinned by
    /// `a8_spec_literal_roi_row_does_not_fail_which_is_why_the_board_reads_ext_roi`.
    pub roi: f64,
    /// A8 (`4r_a8_spec.md`): the CROSS-BOUNDARY consumed integral
    /// `Σ_{h ∉ adv} served[h][adv]` — gb·days of the group's OWN data that lived on an OUTSIDER's
    /// disk (PoS-confirmed). This is what the group actually took FROM the honest network; the
    /// intra-group cells (which a collusive pass writes for free) are excluded. Same reader as A7's
    /// [`crate::sim_adv::metrics::farm_honest_storage`].
    pub ext_consumed: f64,
    /// A8: the CROSS-BOUNDARY served integral `Σ_{h ∉ adv} served[adv][h]` — what the group really
    /// GAVE outsiders. Same reader as A7's [`crate::sim_adv::metrics::farm_honest_served`]. An
    /// ε-serving group gives a little (so the ratio below stays defined); a group that serves
    /// strangers NOTHING gives exactly 0 (⇒ `ext_roi` = NaN, which is the honest reading: an
    /// undefined ratio, not a flattering number).
    pub ext_served: f64,
    /// A8 THE BOARD QUANTITY: `ext_roi = ext_consumed / ext_served` (`NaN` if `ext_served == 0`) —
    /// the EXTRACTION ratio across the group boundary. Unlike [`AdvMetrics::roi`] it is untouched
    /// by the collusive pass (which writes intra-group cells only), so `ext_roi(pred)/ext_roi(twin)`
    /// measures exactly what INV-A8-RING-ROI≤TWIN asks: did the collusive intra-ring reputation buy
    /// the ring any more of the honest network's disk than the same ring got WITHOUT colluding.
    pub ext_roi: f64,
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
    /// A3 (флаппер) DIAGNOSTIC: the fraction of run ticks the adversary SURFACED in the 7-day PoS
    /// window (the PoS PASS proxy as a HOLDER). Runner-accumulated over all ticks / all adv nodes.
    /// `NaN` for a non-A3 scenario. The finding is the pred(bursty)-vs-twin(iid) gap at equal
    /// `online_frac`: the window forgives the SPREAD twin (~0.99) but not the CLUSTERED flapper.
    pub surfaced_frac: f64,
    /// A3 DIAGNOSTIC: the fraction of run ticks the adversary was ONLINE (the REAL storage-time
    /// proxy). Bursty flapper and iid twin share this by construction (mean-matched), so a divergent
    /// `surfaced_frac` at equal `online_frac` isolates the autocorrelation effect. `NaN` off-A3.
    pub online_frac: f64,
    /// A5 (молчащий глубокий) headline: the deep node's parked-own-symbol SURVIVAL across the pause
    /// = (alive parked own symbols at pause END) / (alive parked own symbols at pause START). The
    /// W10/Р-1 depth-floor test — pred (D-floor on) should retain MORE than twin (D-floor off). `NaN`
    /// off-A5 (no pause window) or if the deep node parked nothing before the pause.
    pub park_survival: f64,
    /// A6 (дискриминатор) DIAGNOSTIC: mean ALIVE small-owner volume (gb) the adversary currently
    /// HOLDS — small = an owner whose footprint `own_blocks.len() <= dials.discr_max_blocks`. The
    /// discriminator sheds small owners ⇒ ≈ 0; the honest twin retains them ⇒ > 0. The realized
    /// "мелкий у дискриминатора vs честного" retention. `0` when no adversary ran / no small owners.
    pub small_retention_gb: f64,
}

/// Bit-exact equality (the determinism board row). `to_bits` so a deterministically-produced
/// `NaN` compares equal to itself.
pub fn bit_eq(a: &AdvMetrics, b: &AdvMetrics) -> bool {
    a.parked_live.to_bits() == b.parked_live.to_bits()
        && a.max_cap_ratio.to_bits() == b.max_cap_ratio.to_bits()
        && a.consumed.to_bits() == b.consumed.to_bits()
        && a.served_out.to_bits() == b.served_out.to_bits()
        && a.roi.to_bits() == b.roi.to_bits()
        && a.ext_consumed.to_bits() == b.ext_consumed.to_bits()
        && a.ext_served.to_bits() == b.ext_served.to_bits()
        && a.ext_roi.to_bits() == b.ext_roi.to_bits()
        && a.rejoins == b.rejoins
        && a.cap_trims == b.cap_trims
        && a.retention_g.to_bits() == b.retention_g.to_bits()
        && a.inflow_total.to_bits() == b.inflow_total.to_bits()
        && a.sigma_owed.to_bits() == b.sigma_owed.to_bits()
        && a.retention_g_integral.to_bits() == b.retention_g_integral.to_bits()
        && a.parked_integral.to_bits() == b.parked_integral.to_bits()
        && a.data_evicted.to_bits() == b.data_evicted.to_bits()
        && a.surfaced_frac.to_bits() == b.surfaced_frac.to_bits()
        && a.online_frac.to_bits() == b.online_frac.to_bits()
        && a.park_survival.to_bits() == b.park_survival.to_bits()
        && a.small_retention_gb.to_bits() == b.small_retention_gb.to_bits()
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
#[allow(clippy::too_many_arguments)]
pub fn collect_adv_metrics(
    world: &World,
    nodes: &[usize],
    run_cap_ratio: f64,
    retention_g_integral: f64,
    parked_integral: f64,
    surfaced_frac: f64,
    online_frac: f64,
    park_survival: f64,
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
    // A6 read: alive small-owner volume the adversary currently HOLDS (small = footprint ≤ the
    // adversary's own discrimination threshold, so it is 0 for a non-A6 role with `discr_max = 0`).
    let mut small_held = 0.0f64;
    let is_adv = |o: usize| nodes.contains(&o);

    for &adv in nodes {
        rejoins += world.adv_rejoin_count[adv];
        inflow_total += world.nodes[adv].holdings.len() as f64;
        let discr_max = world.adv[adv].as_ref().map(|r| r.dials.discr_max_blocks);
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
        // A6 small-owner retention: alive foreign symbols the adversary holds whose owner is small.
        if let Some(max) = discr_max
            && max > 0
        {
            for s in world.nodes[adv].holdings.iter().filter(|s| s.alive) {
                if s.owner != adv
                    && world.adv[s.owner].is_none()
                    && world.nodes[s.owner].own_blocks.len() <= max
                {
                    small_held += s.volume;
                }
            }
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

    // A8: the CROSS-BOUNDARY extraction read (group ↔ outsiders only). The SAME readers A7 uses
    // (they are generic over a node set), so the two tranches can never drift apart.
    let ext_consumed = crate::sim_adv::metrics::farm_honest_storage(world, nodes);
    let ext_served = crate::sim_adv::metrics::farm_honest_served(world, nodes);
    let ext_roi = if ext_served > 0.0 {
        ext_consumed / ext_served
    } else {
        f64::NAN
    };

    // DIRECT enforcement count: adversary-owned symbols holders dropped over the run.
    let data_evicted = world
        .eviction_log
        .iter()
        .filter(|e| nodes.contains(&e.owner))
        .count() as f64;

    let small_retention_gb = small_held / nodes.len() as f64;

    AdvMetrics {
        parked_live,
        max_cap_ratio: run_cap_ratio,
        consumed,
        served_out,
        roi,
        ext_consumed,
        ext_served,
        ext_roi,
        rejoins,
        cap_trims: world.cap_trim_count,
        retention_g,
        inflow_total,
        sigma_owed,
        retention_g_integral,
        parked_integral,
        data_evicted,
        surfaced_frac,
        online_frac,
        park_survival,
        small_retention_gb,
    }
}
