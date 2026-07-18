//! 4R trust-model decision kernel — pure functions over first-hand observations.
//!
//! This module is the *shared kernel* for the 4R trust/economy redesign: the
//! exact same code path drives both the offline `viaticum-sim` harness and (later)
//! the production daemon. Keeping the kernel here in `viaticum-core` — which does
//! **not** depend on `viaticum-sim` — is the load-bearing anti-oracle guarantee:
//! a kernel function physically cannot see the simulator's hidden `GroundTruth`,
//! because that type is not in this crate's dependency graph. It is
//! compile-impossible to leak the archetype/hazard oracle that poisoned the old
//! Python sims (`S = STORAGE_RATIOS[archetype[peer]]`).
//!
//! The second lock is structural: [`FirstHandObs`] contains **only** first-hand
//! observable quantities (sim_plan.md §2). There is no field for `archetype`,
//! hidden `hazard`, a global `φ`, or "the peer's behaviour toward third parties".
//! If there is no field, there is nowhere for the oracle to leak.
//!
//! Math source: `formula_phase.md` (leaky-integrator capital, two-gap hysteresis
//! `Δ_min ≈ κ·max(a,b)·Δt_tick`, credit-limit `L ≥ V_dem`).

#[cfg(test)]
mod tests;

use crate::types::{DeviceId, IdentityPub};

// ============================================================
// First-hand observation: the ONLY input to every decision function.
// ============================================================

/// First-hand observations a node holds about ONE pair (peer/holder) plus its
/// own local disk state. By construction this carries **only** first-hand
/// observable quantities (§1 local observability). There is deliberately NO
/// field for hidden archetype, hidden hazard, a global free-ratio `φ`, or the
/// peer's behaviour toward third parties — there is nowhere for an oracle to leak.
///
/// Two independent per-pair coordinates live here (formula_phase.md "volume not
/// in the charge"): the leaky-integrator capital `g_*` (a charge, dimension
/// gb·days) and `v_dem` (a slow ratchet of demonstrated scale, dimension gb).
/// A scalar charge cannot distinguish `1 GB × 1000 d` from `1000 GB × 1 d`, so
/// `v_dem` is a separate axis — never collapse trust into `g` alone.
#[derive(Debug, Clone, PartialEq)]
pub struct FirstHandObs {
    /// `G(O←h)`: the holder's service TO ME — leaky integral of PoS-confirmed
    /// gb·days this peer stored for me. First-hand: I confirmed every PoS round.
    pub g_owner_from_holder: f64,
    /// `G(h←O)`: MY service to the holder — leaky integral of gb·days I stored
    /// for them. First-hand: bilaterally observable (I performed the storage).
    /// This is the eviction-priority key (W6: evict ascending `g_holder_from_owner`).
    pub g_holder_from_owner: f64,
    /// Demonstrated scale `V_dem`: the max proven retained volume for this pair.
    /// A slow ratchet (rises on successful retention, does not leak away fast).
    pub v_dem: f64,
    /// P-projection: recent PoS confirmation rate (high-pass tap of the same
    /// filter). First-hand from my own challenge outcomes.
    pub recent_rate_p: f64,
    /// D-projection: trend `Ġ` (derivative tap; a DEPENDENT axis, not an
    /// independent gain — H3 / W2-NB). Early-warning of degradation.
    pub trend_d: f64,
    /// PoS rounds I challenged this peer with that PASSED (first-hand outcome).
    pub pos_pass: u32,
    /// PoS rounds that FAILED (wrong / missing symbol).
    pub pos_fail: u32,
    /// PoS rounds that TIMED OUT (no response within window).
    pub pos_timeout: u32,
    /// C2FARM-3 (A.2): DECAYING count of ANNOUNCED drop events by this peer of MY data — a
    /// signed `DropNotice` arrived, or I observed the polite drop first-hand. Each is an
    /// "observation of unreliability" that feeds the retention forecast ([`retained_depth`]
    /// `drop_frac`) EVEN THOUGH the announced burn on the capital is weak (`b_ann`): a
    /// reputation-retention read must see even the polite drops. **Leaky, not a raw tally
    /// (транше-4 fix, Ilya 2026-07-07):** the owner-side counter FADES with `λ_drop`
    /// (τ ≈ PoS-window scale) — "the system must forgive": one drop is not an eternal
    /// retention penalty under windowed PoS. Incremented `+= 1.0` per event. Default 0.0
    /// (bit-neutral for every pre-C2FARM-3 caller).
    pub drop_ann: f64,
    /// C2FARM-3 (A.2): DECAYING count of SILENT drop events by this peer of MY data — I
    /// detected the loss myself (a symbol vanished, PoS-confirmed) with no `DropNotice`.
    /// Feeds `drop_frac` alongside `drop_ann`, and FADES with the same `λ_drop`
    /// (транше-4 fix). The silent burn on the capital is strong (`b_max`); this counter is
    /// the retention-forecast channel. Default 0.0.
    pub drop_silent: f64,
    /// `V0`: the single observed volume point — the only `(V,τ)` slice I ever
    /// sampled this holder at (B1: one point per holder).
    pub observed_volume: f64,
    /// `τ0`: the observed retention duration at `V0`.
    pub observed_tau: f64,
    /// Observed address correlate: ASN / subnet proxy. First-hand at connect
    /// time, §1-legal (it is a connection fact, not a hidden archetype).
    pub addr_subnet: u32,
    /// Observed geo correlate (coarse). First-hand and §1-legal; the §7
    /// address-spread keys on `addr_subnet`, so this is retained as a future
    /// correlate but is not currently used by placement.
    pub addr_geo: u16,
    /// Observed round-trip latency (ms).
    pub latency_ms: f64,
    /// Whether the peer is currently reachable (first-hand).
    pub reachable: bool,
    /// Scrutiny multiplier on challenge cadence (rises on suspicion, decays).
    /// First-hand: my own private suspicion state for this pair.
    pub scrutiny: f64,
    /// Master identity of the peer (crypto-id, first-hand).
    pub master_id: IdentityPub,
    /// Device identity of the peer (crypto-id, first-hand).
    pub device_id: DeviceId,
}

/// A node's own local state and dimensionless policy parameters. This is the
/// node's OWN disk and its OWN private policy — not anything observed about peers.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeLocal {
    /// `φ`: free-disk ratio `1 − (H+own)/cap` ∈ [0,1]. First-hand (my own disk).
    pub phi_free_ratio: f64,
}

// ============================================================
// Hysteresis thresholds (two-gap, formula_phase.md §10 / Step 2).
// ============================================================

/// Two-gap hysteresis band for the accept/evict relay (formula_phase.md §10).
///
/// The free-ratio `φ` is controlled by a bang-bang relay with THREE thresholds
/// and TWO gaps, both of which must be non-zero or the relay chatters at the
/// tick frequency (NEW-2):
///
/// * **evict** when `φ < s_hard`, down to `φ = s_target`
///   (`Δ_evict ≡ s_target − s_hard` is the lower gap);
/// * **accept** new foreign data only when `φ > s_soft`
///   (`Δ_accept ≡ s_soft − s_target` is the upper gap).
///
/// Collapsing `s_soft = s_target` removes the accept gap → the exact
/// accept↔evict cycle of NEW-2: drop to target, immediately re-accept at the
/// same level, fall below hard again, evict again. Both gaps are load-bearing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Hysteresis {
    /// `s_hard`: evict-trigger threshold. Evicting starts when `φ < s_hard`.
    pub s_hard: f64,
    /// `s_target`: evict-release threshold. Evicting stops once `φ ≥ s_target`.
    pub s_target: f64,
    /// `s_soft`: accept threshold. New foreign data accepted only when `φ > s_soft`.
    pub s_soft: f64,
}

impl Hysteresis {
    /// The lower gap `Δ_evict = s_target − s_hard` (how far above the hard
    /// threshold to let `φ` recover before we stop evicting).
    pub fn delta_evict(&self) -> f64 {
        self.s_target - self.s_hard
    }

    /// The upper gap `Δ_accept = s_soft − s_target` (how far above target `φ`
    /// must rise before we start accepting again).
    pub fn delta_accept(&self) -> f64 {
        self.s_soft - self.s_target
    }
}

/// Analytic minimum hysteresis gap that avoids chatter (formula_phase.md §10):
///
/// ```text
/// Δ_min ≈ κ · max(a, b) · Δt_tick,   κ ≳ 1
/// ```
///
/// where `a` is the rate `|dφ/dt|` at which `φ` falls under accept, `b` the rate
/// at which it rises under evict, and `Δt_tick` the control tick. Over one tick
/// `φ` moves by `≈ max(a,b)·Δt_tick`; if a gap is smaller than that the band is
/// skipped in a single tick → chatter. `kappa` is the safety factor (a margin of
/// several ticks). Each gap (`Δ_evict`, `Δ_accept`) must individually exceed this.
///
/// All inputs are defensively clamped to be non-negative.
pub fn min_hysteresis_gap(rate_accept_a: f64, rate_evict_b: f64, tick: f64, kappa: f64) -> f64 {
    let a = rate_accept_a.max(0.0);
    let b = rate_evict_b.max(0.0);
    let tick = tick.max(0.0);
    let kappa = kappa.max(0.0);
    kappa * a.max(b) * tick
}

// ============================================================
// S1 — pairwise capital: leaky integrator (RC / leaky-charge).
// ============================================================

/// Leaky-integrator update for pairwise capital `G` (one explicit Euler step):
///
/// ```text
/// G_{t+Δt} = G_t + Δt · (V_conf − λ·G_t)
/// ```
///
/// This is the discretised `dG/dt = V_conf − λG` (formula_phase.md, the
/// "universal capital form"): a leaky capacitor charged by the confirmed
/// retained volume `V_conf` and leaking at rate `λ`. Its steady state is
/// `G* = V_conf / λ` (set `dG/dt = 0`).
///
/// Numerical-stability note (capstone flag-3a): the Euler multiplier is
/// `(1 − λΔt)`. Monotone relaxation requires `λΔt < 1` (i.e. sample faster than
/// you forget, `ρ ≫ 1`). For `1 < λΔt < 2` the discrete step oscillates, for
/// `> 2` it diverges. The caller owns the tick; this function does not silently
/// re-scale it, but inputs are clamped so a degenerate call cannot NaN.
///
/// `lambda` and `dt` are clamped to be non-negative; `g` and `v_conf` are taken
/// as given (capital and volume are both non-negative quantities by construction,
/// but we do not force-clamp them so a caller can observe a transient negative if
/// it ever constructs one).
pub fn update_capital(g: f64, v_conf: f64, lambda: f64, dt: f64) -> f64 {
    let lambda = lambda.max(0.0);
    let dt = dt.max(0.0);
    g + dt * (v_conf - lambda * g)
}

/// Steady-state capital `G* = V_conf / λ` for a constant confirmed input.
///
/// Returns `0.0` if `λ ≤ 0` (no leak → no finite steady state; we report 0 rather
/// than an infinity so callers/tests get a well-defined sentinel).
pub fn capital_steady_state(v_conf: f64, lambda: f64) -> f64 {
    if lambda <= 0.0 {
        return 0.0;
    }
    v_conf / lambda
}

/// A.3: the demonstrated-scale `V_dem` **ratchet** — one explicit step of
///
/// ```text
/// V_dem ← max( V_conf, V_dem·(1 − λ_dem·Δt) )          [gb]
/// ```
///
/// (decision_model A.3 / §2). Unlike the leaky INTEGRATOR of the fast capital `g`
/// [`update_capital`], this is a MAX (not a sum): the ratchet snaps UP instantly to
/// any freshly-confirmed retained volume `V_conf`, and only ever eases DOWN through
/// the slow leak `λ_dem·Δt`. So a pair that has proven it can hold `V` keeps a
/// demonstrated scale near `V` for a long time, and it fades only if the pair goes
/// silent (no confirmed service) for many time constants — there is no fossil scale
/// that survives forever with zero recent proof.
///
/// **Why a slow leak at all (not a pure non-decaying max).** A pure `max` never
/// forgets: one lucky large retention would pin `V_dem` — and hence the credit limit
/// `L ≥ V_dem` (A.13) — at that peak permanently, a farmable free floor. The leak is
/// the fix: the demonstrated scale is only real while it keeps being demonstrated.
///
/// **`λ_dem` is the SLOWEST leak in the model** — `λ_dem ≪ λ` (`= 1/60`) and
/// `≪ λ_slow` (`= 1/180`, the loyalty depth). The default guess is
/// **`λ_dem = 1/365 day⁻¹`** (`τ_dem ≈ 1 year`: "a demonstrated scale lives about a
/// year without re-confirmation"). This is an **OPEN calibration** — like every
/// constant in §13, it is a starting guess to be tuned in the field, NOT a settled
/// canon value.
///
/// Inputs are clamped like the sibling ratchets: negative `v_dem`/`v_conf` are floored
/// at 0 (a negative demonstrated scale is meaningless), and `λ_dem`/`Δt` are floored at
/// 0; the decayed term is itself floored at 0 so a degenerate `λ_dem·Δt > 1` cannot
/// drive it negative. The caller owns the tick; it is not silently re-scaled here.
pub fn update_v_dem(v_dem: f64, v_conf: f64, dt_days: f64, lambda_dem: f64) -> f64 {
    let v_dem = v_dem.max(0.0);
    let v_conf = v_conf.max(0.0);
    let lambda_dem = lambda_dem.max(0.0);
    let dt_days = dt_days.max(0.0);
    let decayed = (v_dem * (1.0 - lambda_dem * dt_days)).max(0.0);
    v_conf.max(decayed)
}

// ============================================================
// S1b — pairwise DEPTH: the SLOW-leaky loyalty carrier (A.4) and the single
//        holder-side reciprocity key κ_O (A.14).
// ============================================================

/// A.4: slow-leaky **depth** `D` of a pair's confirmed-service history — the W10
/// loyalty carrier. One explicit Euler step of the SAME leaky-integrator law as the
/// fast capital [`update_capital`], but driven by a MUCH slower leak `λ_slow ≪ λ`:
///
/// ```text
/// D_{t+Δt} = D_t·(1 − λ_slow·Δt) + V_conf·Δt          [gb·days]
/// ```
///
/// `V_conf` is the SAME confirmed-service signal that charges the fast capital `g`
/// (PoS-passed, live retained gb this tick) — depth is a second tap of that flow on a
/// slow time constant `τ_slow = 1/λ_slow ≈ 6 months` (decision_model A.4 / §13).
/// Steady state `D* = V_conf·τ_slow`; a burst of service then decays with an e-fold
/// per `τ_slow`, so a farmed spike fades over months and only *continued* service
/// keeps `D` high — loyalty is not a permanent free floor (ADV2-D1/D2). Two years of
/// silence leave `e⁻⁴ ≈ 1.8%` (the "50 MB of super-precious data survives for years"
/// case, canon §7).
///
/// **Why NOT a non-decaying accumulator.** An un-leaked cumulative ledger is
/// FARMABLE: no channel ever lowers it, so a one-off burst of service buys a
/// permanent floor forever. The slow leak is the fix — the deep-partner floor is real
/// only while the service continues.
///
/// Numerical stability (the same guard as [`update_capital`]): the Euler multiplier is
/// `(1 − λ_slow·Δt)`; monotone relaxation needs `λ_slow·Δt < 1`. The caller owns the
/// tick and it is not silently re-scaled here (the sim asserts it once per step via
/// `assert_lambda_dt_stable`, consistent with the fast capital). Inputs are clamped so
/// a degenerate call cannot NaN: `depth` and `v_conf` are floored at 0 — unlike
/// [`update_capital`], which lets a caller observe a transient negative capital, a
/// *negative depth* is a meaningless loyalty quantity, so it is clamped — and
/// `λ_slow`/`Δt` are floored at 0.
pub fn update_depth(depth: f64, v_conf: f64, dt_days: f64, lambda_slow: f64) -> f64 {
    let depth = depth.max(0.0);
    let v_conf = v_conf.max(0.0);
    let lambda_slow = lambda_slow.max(0.0);
    let dt_days = dt_days.max(0.0);
    depth * (1.0 - lambda_slow * dt_days) + v_conf * dt_days
}

/// Calibration for the single holder-side reciprocity key κ_O (A.14 / §13). The kernel
/// does NOT hard-code these — the caller carries them (it alone knows `λ` and the
/// per-symbol volume behind `g_star`). See [`kappa_key`].
///
/// §13 defaults (carried by the caller): `w_d ≈ 0.5`, `d_ref ≈ 365·V_sym` gb·days
/// (≈ one year of a single symbol's steady service), `g_star = capital_steady_state(
/// V_sym, λ)`.
///
/// **NB — the half floor on a single steady symbol (a §13 consequence, not a bug).**
/// With those defaults a pair served by ONE symbol at constant service reaches
/// `D* = V_sym/λ_slow = 180·V_sym` gb·days (at `τ_slow ≈ 6 months`), so
/// `min(D*/d_ref, 1) = 180/365 ≈ 0.49`: the depth floor a *single* steadily-served
/// symbol earns is only HALF-saturated, and full saturation (`min = 1`) needs steady
/// service by ≈ two symbols. That is the deliberate effect of pairing a ~6-month
/// `τ_slow` with a ~1-year `d_ref` (deep loyalty is earned over more than one
/// symbol-year of service), NOT a defect.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DepthParams {
    /// `w_d`: weight of the depth floor relative to `g_star`. `w_d < 0` is treated as
    /// 0 (no floor). §13 default ≈ 0.5.
    pub w_d: f64,
    /// `d_ref`: depth (gb·days) at which the loyalty floor saturates. `d_ref ≤ 0`
    /// saturates the floor to 1 (like the `standing_ref`/`g_ref` guards). §13 default
    /// ≈ `365·V_sym`.
    pub d_ref: f64,
    /// `g_star`: the fast-capital steady state `g*(V_sym) = V_sym/λ` the floor is
    /// measured in — the caller computes it with [`capital_steady_state`] (the kernel
    /// does not know `λ`/`V_sym`). Floored at 0.
    pub g_star: f64,
}

/// A.14: the ONE holder-side reciprocity key κ_O — the single ranking a holder uses
/// under contention.
///
/// ```text
/// κ_O = g_ho + w_d · min(D/d_ref, 1) · g_star
/// ```
///
/// * `g_ho` = `G(h←O)` (the eviction seat: the owner `O`'s reciprocal service to ME,
///   the holder — how much of MY data `O` has been keeping alive lately), the fast
///   capital, bilaterally observable and unfakeable.
/// * the second term is the **W10 loyalty floor**: a silent-but-deep partner
///   (`g_ho → 0`, `D ≥ d_ref`) still ranks as if it carried `w_d·g_star` of fast
///   capital — above every stranger, below an actively-reciprocating partner — and
///   that floor FADES with `D` over `τ_slow` (no permanent free floor, A.4).
///
/// **One key, three consumers.** In transaction 3a κ_O drives eviction
/// ([`eviction_order`]); the preemption gate and the `V_ret` volume cap join it in 3b.
/// All three MUST read this SAME key — a bare-`g_ho` ranking would bypass the depth
/// floor and let contention evict a silent-but-deep loyal partner (ADV2-D2).
///
/// All terms are gb·days. `depth`/`g_star` are floored at 0; `d_ref ≤ 0` saturates the
/// floor to 1; `w_d < 0` is treated as 0.
pub fn kappa_key(g_ho: f64, depth: f64, p: &DepthParams) -> f64 {
    let depth = depth.max(0.0);
    let g_star = p.g_star.max(0.0);
    let w_d = p.w_d.max(0.0);
    let sat = if p.d_ref > 0.0 {
        (depth / p.d_ref).min(1.0)
    } else {
        1.0
    };
    g_ho + w_d * sat * g_star
}

// ============================================================
// A.2 — burn: impulse to the holder-reliability capital on CONFIRMED loss.
// A.5 — suspicion σ: fast-forgetting pair state with two consumers.
// ============================================================

/// Calibration for the A.2 burn (decision_model A.2 / §13). Carried by the caller
/// (node policy), like [`DepthParams`]. **§13 defaults**: `b_ann = 0.05` (announced),
/// `b_max = 1.0` (silent, confirmed by Ilya 2026-07-07) with `b_ann ≪ b_max` — honesty is
/// always cheaper; `tau_rep` = the repair latency (days).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BurnParams {
    /// `b_ann`: the WEAK burn fraction for any SIGNED `DropNotice` (announced). `b_ann ≪
    /// b_max`. Clamped to [0,1]. §13 default 0.05.
    pub b_ann: f64,
    /// `b_max`: the STRONG burn fraction for a SILENT loss (detected via PoS, no notice).
    /// Clamped to [0,1]. §13 default **1.0** (confirmed by Ilya 2026-07-07 — a fully silent
    /// total loss zeroes the reliability capital).
    pub b_max: f64,
    /// `τ_rep`: the repair latency (DAYS). An announced drop with head-start `t_n ≥ τ_rep`
    /// gives the owner enough warning to repair before the actual loss ⇒ ZERO burn
    /// (the M5 forgiveness continuum). `τ_rep ≤ 0` ⇒ the head-start axis is neutralised
    /// (factor 1, MAXIMUM penalty on that axis — documented degenerate guard).
    pub tau_rep: f64,
}

/// A.2: impulse **burn** on a CONFIRMED loss of held data (decision_model A.2, canon
/// §6/§7). One multiplicative step on the holder-reliability capital `g`
/// (`G(O←h)` — the owner's record of the holder's service to it):
///
/// ```text
/// g ← g·(1 − b·(1 − min(1, t_n/τ_rep))·V_lost/V_held)
/// b = b_ann  (any signed DropNotice — announced)
///   = b_max  (silent, detected via PoS)          with b_ann ≪ b_max
/// ```
///
/// **Two axes, both load-bearing** (audit B-1):
/// * **announcedness** — a SILENT loss (`announced = false`) burns at the strong `b_max`;
///   ANY signed announcement (`announced = true`) burns at the weak `b_ann`. Honesty is
///   always cheaper (the ordering invariant below), even without a head-start.
/// * **head-start `t_n`** (`DropNotice → actual drop`, M5 continuum) — an announced drop
///   with `t_n ≥ τ_rep` gives the owner time to repair ⇒ ZERO burn; announce-without-
///   head-start (`t_n = 0`) still burns the WEAK `b_ann` (not zero). A silent loss has
///   `t_n = 0` by construction (the caller passes 0; this fn does not check).
///
/// **Ordering invariant (honesty always pays).** For any `t_n < τ_rep` and `V_lost > 0`,
/// `burn(announced) < burn(silent)` STRICTLY (`b_ann·headstart ≤ b_ann < b_max`), so a
/// node is never worse off announcing a drop than hiding it.
///
/// **Deadband is the CALLER's responsibility (documented).** A single timeout NEVER
/// burns — burn fires only on a CONFIRMED loss (a repeated fail / a symbol that actually
/// vanished). A lone timeout instead raises suspicion σ ([`update_suspicion`]); this fn
/// is only ever called once the loss is confirmed. (Model question RESOLVED by Ilya
/// 2026-07-07, decision_model A.2/A.5: a lone PoS-timeout raises σ WEAKLY by `j_σ/5` —
/// the escalation ladder "timeout → challenge more often → confirm/clear faster"; a
/// CONFIRMED silent defect raises σ by the full `j_σ`. Burn stays timeout-immune.)
///
/// Guards: `V_held ≤ 0` ⇒ `g` unchanged (nothing was held to lose); `V_lost` is clamped
/// to `[0, V_held]`; `b` to `[0,1]`; `t_n` floored at 0; `τ_rep ≤ 0` ⇒ head-start factor
/// 1; the result is floored at 0.
pub fn apply_burn(
    g: f64,
    p: &BurnParams,
    announced: bool,
    t_n_days: f64,
    v_lost: f64,
    v_held: f64,
) -> f64 {
    if v_held <= 0.0 {
        return g; // nothing held ⇒ nothing to burn
    }
    let v_lost = v_lost.clamp(0.0, v_held);
    let b = (if announced { p.b_ann } else { p.b_max }).clamp(0.0, 1.0);
    let t_n = t_n_days.max(0.0);
    // Head-start forgiveness: full warning (t_n ≥ τ_rep) ⇒ factor 0 ⇒ no burn; no warning
    // (t_n = 0) ⇒ factor 1 ⇒ the full b. τ_rep ≤ 0 ⇒ factor 1 (max penalty on this axis).
    let headstart = if p.tau_rep > 0.0 {
        1.0 - (t_n / p.tau_rep).min(1.0)
    } else {
        1.0
    };
    let factor = 1.0 - b * headstart * (v_lost / v_held);
    (g * factor).max(0.0)
}

/// A.5: one step of the **suspicion** `σ` dynamics (decision_model A.5, canon §10.2 /
/// §9.14д):
///
/// ```text
/// σ ← σ(1 − μΔt) + j_σ·1{silent defection / hostage} + (j_σ/5)·1{PoS-timeout}
/// ```
///
/// σ is a fast-forgetting pair state — `1/μ ≪ 1/λ` (the capital memory), so suspicion
/// fades in ~weeks while capital remembers ~months. It jumps by the passed `j_sigma` on a
/// detected defect, then decays back. The two consumers are the PoS cadence
/// [`pos_cadence`] and the daemon-side decoy-DR frequency `r_dr·(1+σ)` (NOT coded here —
/// the sim has no DR actuator; see the transche-4 spec).
///
/// **Two jump amplitudes (транше-4, Ilya 2026-07-07).** A CONFIRMED silent defect (or a
/// first-hand hostage pattern) jumps by the FULL `j_σ`; a lone PoS-timeout (holder
/// offline) jumps WEAKLY by `j_σ/5` — the caller passes the smaller amplitude as
/// `j_sigma`. The escalation ladder "timeout → challenge more often → confirm/clear
/// faster" makes a false timeout cheap (σ forgets in ~2 weeks); at most ONE timeout jump
/// per pair per tick (the caller dedups, not this fn).
///
/// **Composing decay and jump like the sibling ratchets.** Call with `defect = false`,
/// `dt = Δt` in the per-tick sweep (the decay for EVERY pair), and with `defect = true`,
/// `dt = 0` at the moment a loss/timeout is detected (a PURE jump `+j_sigma`, no extra
/// decay) — the two compose to exactly `σ(1−μΔt) + j_sigma` per tick, one decay per tick.
///
/// **Hostage-pattern is a CALLER policy (documented).** The `defect` flag is a boolean:
/// the DETECTION of a silent defect or a hostage pattern ("dropped all my low-ι, kept
/// only high-ι") is the caller's job; this fn only applies the consequence. The sim does
/// not implement the hostage detector (no such actuator) — it raises σ only on a
/// confirmed silent holder loss.
///
/// Guards (mirroring [`update_depth`]): `σ` and `μ`/`dt`/`j_σ` are floored at 0; the
/// decayed term is floored at 0 so a degenerate `μ·dt > 1` cannot drive σ negative (no
/// assert in the kernel — the caller owns the tick).
pub fn update_suspicion(sigma: f64, defect: bool, dt_days: f64, mu: f64, j_sigma: f64) -> f64 {
    let sigma = sigma.max(0.0);
    let mu = mu.max(0.0);
    let dt = dt_days.max(0.0);
    let decayed = (sigma * (1.0 - mu * dt)).max(0.0);
    if defect {
        decayed + j_sigma.max(0.0)
    } else {
        decayed
    }
}

/// A.5 consumer: the **PoS challenge cadence** scales up with suspicion,
/// `cadence = r_0·(1 + σ)` — a suspected holder is challenged more often. `r_0` and `σ`
/// are floored at 0. (The second A.5 consumer, the decoy-DR frequency `r_dr·(1+σ)`, is
/// daemon-side and NOT transcribed here — the sim has no DR actuator, decision_model
/// A.5. In the sim PoS already runs every tick, so this cadence read is INERT there; it
/// is transcribed for the daemon.)
pub fn pos_cadence(r_0: f64, sigma: f64) -> f64 {
    r_0.max(0.0) * (1.0 + sigma.max(0.0))
}

// ============================================================
// S2 — eviction order under disk pressure (two-level: κ_O-priority across
//      owners, ι within an owner) + hysteresis.
// ============================================================

/// Opaque per-symbol identifier as the holder sees it. First-hand: it is the
/// label attached to a symbol the holder physically stores; it carries no
/// ground-truth. A newtype (project convention: all IDs are newtypes) so a symbol
/// index can never be silently confused with an owner index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(pub u64);

/// One symbol the holder stores for a given owner, as first-hand metadata.
///
/// Both fields are first-hand for the holder: `id` is the symbol it physically
/// holds, and `importance` is the OWNER-DECLARED importance `ι` that arrived
/// *with* the symbol — the holder observes it as plain metadata attached to the
/// symbol (it does not, and cannot, see the owner's hidden internal valuation).
/// There is no archetype/hazard field here, by construction.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SymbolDecl {
    /// The symbol's opaque identifier (first-hand: the holder stores it).
    pub id: SymbolId,
    /// Owner-declared importance `ι` of this symbol (first-hand metadata the
    /// holder received with the symbol). Higher ι ⇒ the owner wants it kept
    /// longer; it orders symbols WITHIN this one owner only — see [`eviction_order`].
    pub importance: f64,
    /// Per-symbol volume `V` (gb) the holder physically stores for this symbol —
    /// first-hand (the size of the symbol on disk). The Р-7 volume cap
    /// ([`RetentionCap`]) trims an owner's parked volume `V_parked(O) = Σ volume`
    /// (over that owner's symbols) down to `V_ret`; the kernel does NOT assume
    /// symbols are uniform in size, so each carries its own `volume`.
    pub volume: f64,
}

/// The holder's eviction view of ONE owner: the pairwise capital that sets this
/// owner's disk SHARE, plus the set of that owner's symbols each with its ι.
///
/// This is the minimal shape that expresses `owner → { (symbol_id, ι) }` for the
/// two-level eviction decision while staying strictly first-hand:
/// * `obs.g_holder_from_owner` (`G(h←O)`) is the holder's OWN pairwise capital —
///   bilaterally observable, UNFAKEABLE by the owner (the owner cannot inflate it
///   by lying). Combined with `depth` through [`kappa_key`] it forms the INTER-owner
///   ranking key κ_O (each owner's share).
/// * `depth` (`D`) is the SLOW-leaky loyalty depth of this pair (A.4) — the W10
///   carrier that lets a silent-but-deep partner keep its disk share above a
///   stranger's; it enters the INTER-owner rank only through κ_O.
/// * `symbols` are this owner's symbols with their owner-declared ι — the
///   INTRA-owner ordering key (lowest-ι dropped first), scoped strictly within
///   this owner so an inflated ι can only reorder the owner's OWN symbols.
///
/// `obs` carries the full [`FirstHandObs`] so the retention tie-breaker
/// (`observed_tau`) and any later refinement keep working off first-hand fields;
/// none of them is a ground-truth oracle.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnerEvictionView {
    /// First-hand observation of this owner-pair (carries `g_holder_from_owner`,
    /// the fast capital in the inter-owner key, and `observed_tau`, the tie-breaker).
    pub obs: FirstHandObs,
    /// `D`: the SLOW-leaky loyalty depth of this pair (A.4), from the holder's seat —
    /// the accumulated history of "this owner served ME" on the `τ_slow ≈ 6-month`
    /// time constant. Feeds the W10 floor in the κ_O rank ([`kappa_key`]); it is the
    /// pair's own first-hand state, never a ground-truth oracle.
    pub depth: f64,
    /// This owner's symbols on the holder, each with its owner-declared ι.
    pub symbols: Vec<SymbolDecl>,
}

/// A single symbol slot in the flattened eviction order: which owner it belongs
/// to and which of that owner's symbols it is. The drop list is a sequence of
/// these — first the lowest-`G` owner's lowest-ι symbol, then upward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolSlot {
    /// Index into the input `owners` slice (which owner this symbol belongs to).
    pub owner_idx: usize,
    /// Index into that owner's `symbols` vec (which symbol of that owner).
    pub symbol_idx: usize,
}

/// Per-call eviction state needed to apply the two-gap hysteresis across ticks.
///
/// The relay is a state machine: it is either currently evicting or not. Without
/// remembering that bit, the kernel cannot apply the accept↔evict hysteresis
/// (the gaps only matter relative to "what am I doing right now"). The caller
/// owns this bit and threads it through ticks; [`eviction_order`] returns the
/// updated bit alongside the drop list.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct EvictPhase {
    /// True iff the relay is currently in the evicting state (latched on when
    /// `φ < s_hard`, latched off when `φ ≥ s_target`).
    pub evicting: bool,
}

/// Р-7 (A.14): the holder-side VOLUME cap `V_ret` — the ι-envelope a holder keeps
/// for ONE owner under contention. It is NOT an independent limit: it reads the SAME
/// single reciprocity key κ_O ([`kappa_key`]) that the inter-owner eviction rank and
/// the preemption gate use (audit B-1: a cap "independent of κ" would neutralise the
/// W10 depth floor, so P5 would be unmeetable).
///
/// ```text
/// V_ret(O у h) = v_free + κ_O(O) / c_recip
/// ```
///
/// with κ_O in gb·days and `V_ret`/`v_free` in gb, so `c_recip` MUST be a DURATION
/// [days] (WARN-1) — "for every `c_recip` gb·days of lived service the holder keeps
/// +1 gb of your data above `v_free`". Under contention a holder trims each owner's
/// parked volume down to its `V_ret`, dropping that owner's LOWEST-ι symbols first
/// ([`eviction_order`]'s `cap_drops`).
///
/// **One formula, three properties** (decision_model §8):
/// 1. **ε-give whale (Р-7 tariff).** κ_O ≈ ε ⇒ V_ret ≈ v_free: a peer that barely
///    reciprocates cannot park unbounded volume — "I keep your data ∝ how much you
///    served me" (§2B ENFORCED; the owner-side credit limit is NOT enforcement).
/// 2. **W10 loyalty = ι-envelope that MELTS with D.** A silent-but-deep partner
///    (`g_ho → 0`, `D ≥ d_ref`) still keeps `v_free + w_d·sat(D/d_ref)·g*/c_recip`,
///    and that floor fades with `D` over `τ_slow` (no permanent free floor, A.4).
/// 3. **V_free floor = cream (holder-side).** Every owner — even a zero-service
///    stranger — keeps a little (`v_free`) for free: the newcomer entry channel
///    (bootstrap by storage), no mandatory repair. The owner-side cream ceiling
///    (A.11, транш 3c) is the dual of this floor.
///
/// There is NO separate `V_floor` envelope beside this cap: the old per-pair floor
/// and the Р-7 cap collapsed into this ONE `V_ret` (B-1) — do not code a second limit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetentionCap {
    /// `V_free` (gb): the free retention floor every owner gets (property 3 above).
    pub v_free: f64,
    /// `c_recip` (DAYS): the reciprocity price — gb·days of κ_O bought per +1 gb of
    /// retention above `v_free`. Guard: `c_recip ≤ 0` DISABLES the cap entirely
    /// ([`RetentionCap::disabled`]) — a misconfigured (zero / negative) price must NOT
    /// divide-by-zero nor silently evict everything (mirror of the `preempt_enabled`
    /// WARN-2 guard).
    pub c_recip: f64,
}

impl RetentionCap {
    /// A disabled cap (`c_recip = 0` ⇒ the cap is OFF). Used by callers that predate
    /// Р-7 (e.g. SIM-2) or scenarios isolating a different mechanism: [`eviction_order`]
    /// then produces NO `cap_drops` and behaves exactly as before 3b.
    pub fn disabled() -> Self {
        RetentionCap {
            v_free: 0.0,
            c_recip: 0.0,
        }
    }

    /// Whether the cap is active (`c_recip > 0`). When false, `V_ret` is unbounded and
    /// no volume is cap-trimmed (the WARN-1 divide-by-zero / evict-all guard).
    pub fn active(&self) -> bool {
        self.c_recip > 0.0
    }

    /// `V_ret(O) = v_free + κ_O/c_recip` for an owner whose reciprocity key is `kappa`.
    /// Only meaningful when [`RetentionCap::active`]; callers guard on that first (an
    /// inactive cap has an unbounded `V_ret`, not `v_free + κ/0`).
    pub fn v_ret(&self, kappa: f64) -> f64 {
        self.v_free + kappa / self.c_recip
    }
}

/// Result of one eviction tick.
#[derive(Debug, Clone, PartialEq)]
pub struct EvictionDecision {
    /// **MANDATORY** Р-7 cap trims ([`RetentionCap`]): symbols that MUST be dropped to
    /// bring each owner's parked volume down to its `V_ret`, applied by the caller
    /// UNCONDITIONALLY (no φ-target stop — this is tariff enforcement, not pressure
    /// relief). Ordered inter-owner by ascending κ_O (tie `observed_tau`) and
    /// intra-owner by ascending ι (tie [`SymbolId`]). Empty when not evicting or when
    /// the cap is disabled. Disjoint from `drop_order` (no symbol appears in both).
    pub cap_drops: Vec<SymbolSlot>,
    /// Per-symbol PRESSURE drop order ([`SymbolSlot`]s), ordered by eviction priority:
    /// first the lowest-κ_O owner's lowest-ι symbol, then upward. Applied by the caller
    /// only until `φ ≥ s_target`. Empty when the relay is not in the evicting state
    /// this tick. EXCLUDES every symbol already in `cap_drops` (no double-drop). See
    /// [`eviction_order`] for the exact two-level rule.
    pub drop_order: Vec<SymbolSlot>,
    /// Whether new foreign data may be accepted this tick (`φ > s_soft` and not
    /// currently evicting).
    pub accept_ok: bool,
    /// Updated relay phase to thread into the next tick.
    pub phase: EvictPhase,
}

/// Decide the eviction order under disk pressure, applying two-gap hysteresis.
///
/// Eviction is **two-level** (W3 / W6 / W9, foundation §2A):
///
/// * **INTER-owner level (the disk SHARE).** Owners are ranked by ascending κ_O
///   ([`kappa_key`], A.14): the owner with the lowest κ_O is squeezed first. κ_O
///   combines two first-hand terms.
///   * `obs.g_holder_from_owner` (`G(h←O)`), read FROM THE HOLDER-EVICTOR'S SEAT, is
///     **this owner's reciprocal service TO ME** (decision_model §1) — my own
///     first-hand record of MY data that the owner keeps alive for me (measured by my
///     PoS of my symbols stored at that owner). The owner that has served me least
///     ranks lowest. It is UNFAKEABLE: the owner cannot inflate `G(h←O)` by lying —
///     it is bilaterally observable service. (This is the direction the old doc
///     comment inverted: the field is the OWNER's service to the holder, not the
///     holder's service to the owner.)
///   * the W10 loyalty floor `w_d·min(D/d_ref, 1)·g_star` (`depth_params`), which
///     lets a silent-but-DEEP partner (`g_ho → 0`, `D ≥ d_ref`) keep its disk share
///     above a stranger's — and which FADES with `D` over `τ_slow`, so it is not a
///     permanent free floor (A.4, ADV2-D2).
///
///   κ_O sets each owner's slice of this holder's disk.
/// * **INTRA-owner level (which of that owner's symbols).** WITHIN a single
///   owner's symbols, drop ascending by THAT owner's declared `ι`
///   ([`SymbolDecl::importance`]) — the owner's lowest-ι symbol first. `ι` is the
///   metadata the owner attached to its own symbols; the holder respects it as a
///   ladder for which of that owner's symbols to keep, scoped STRICTLY within
///   this owner.
///
/// **Strictly forbidden — the rejected cross-owner `×ι` design.** An owner's `ι`
/// NEVER lets its symbols jump over ANOTHER owner's symbols. There is no global
/// `G×ι` product across owners: `ι` is compared only between symbols of the SAME
/// owner, never across owners. This is what makes `ι` honest (incentive-
/// compatible): inflating `ι` cannot grow an owner's disk share (the share is set
/// by `G(h←O)`, which lying cannot touch) and cannot evict another owner's
/// symbol earlier — it can only permute the inflating owner's OWN symbols (H2).
///
/// Archetype is NOT an input (there is no such field). The evaluator's
/// ground-truth net-debtor status is used only OUTSIDE this function to score the
/// result.
///
/// Behaviour:
/// * The relay latches into the evicting state when `φ < s_hard` and out of it
///   when `φ ≥ s_target` (the `Δ_evict` gap). In between it holds its previous
///   state — that latch is what kills the lower-loop chatter.
/// * While evicting, the result is the flattened two-level order above. The
///   inter-owner sort is by ascending κ_O, stable (ties keep input order) with a
///   small retention tie-breaker on `observed_tau` (longer-held owner-pair dropped
///   LAST — premium for stillness, formula_phase.md §10); the intra-owner sort is by
///   ascending `ι` with a [`SymbolId`] tie-breaker for determinism.
/// * `accept_ok` is true only when `φ > s_soft` AND we are not evicting (the
///   `Δ_accept` gap), which forbids "drop and immediately re-accept".
///
/// **Р-7 volume cap (A.14 ⭐, транш 3b).** When the `cap` is active (`c_recip > 0`)
/// and the relay is evicting, each owner's parked volume is trimmed down to its
/// `V_ret = v_free + κ_O/c_recip` ([`RetentionCap`]) by dropping that owner's
/// LOWEST-ι symbols first. Those MANDATORY trims come back in `cap_drops` (applied by
/// the caller WITHOUT the φ-target stop — tariff enforcement) and are EXCLUDED from
/// the pressure `drop_order`. Both lists key ι strictly WITHIN an owner (H2 holds in
/// both). In abundance (not evicting) the cap does nothing (W9 greed: the disk would
/// otherwise idle; a whale parks freely, but its excess goes FIRST at the next
/// contention). A disabled cap ([`RetentionCap::disabled`]) yields empty `cap_drops`
/// and the exact pre-3b behaviour.
pub fn eviction_order(
    owners: &[OwnerEvictionView],
    phi: f64,
    hyst: Hysteresis,
    prev: EvictPhase,
    depth_params: &DepthParams,
    cap: &RetentionCap,
) -> EvictionDecision {
    // --- Relay latch with hysteresis on the lower (evict) gap. ---
    let mut evicting = prev.evicting;
    if phi < hyst.s_hard {
        evicting = true;
    } else if phi >= hyst.s_target {
        evicting = false;
    }
    // (s_hard ≤ φ < s_target ⇒ hold previous state: this is the Δ_evict deadband.)

    let (cap_drops, drop_order) = if evicting {
        // INTER-owner rank (SHARED by both lists): ascending κ_O (kappa_key: the fast
        // reciprocal capital `g_ho` plus the slow W10 depth floor) — the owner that has
        // served ME least loses disk first — with the `observed_tau` retention
        // tie-breaker (longer-held owner-pair dropped LAST).
        let kappa =
            |v: &OwnerEvictionView| kappa_key(v.obs.g_holder_from_owner, v.depth, depth_params);
        let mut owner_idx: Vec<usize> = (0..owners.len()).collect();
        owner_idx.sort_by(|&i, &j| {
            kappa(&owners[i]).total_cmp(&kappa(&owners[j])).then(
                owners[i]
                    .obs
                    .observed_tau
                    .total_cmp(&owners[j].obs.observed_tau),
            )
        });

        // INTRA-owner ladder (per owner): ascending ι, [`SymbolId`] tie-break. Computed
        // ONCE and reused by BOTH lists — ι is sorted ONLY within an owner, never across
        // owners, so a high-ι symbol of a low-κ owner still drops before any symbol of a
        // higher-κ owner. This is the structural ban on cross-owner ×ι (H2).
        let sorted_syms: Vec<Vec<usize>> = owners
            .iter()
            .map(|o| {
                let mut idx: Vec<usize> = (0..o.symbols.len()).collect();
                idx.sort_by(|&a, &b| {
                    o.symbols[a]
                        .importance
                        .total_cmp(&o.symbols[b].importance)
                        .then(o.symbols[a].id.cmp(&o.symbols[b].id))
                });
                idx
            })
            .collect();

        // Р-7 cap_drops (A.14 ⭐): MANDATORY tariff enforcement. For each owner in κ_O
        // order, trim its parked volume down to V_ret = v_free + κ_O/c_recip by dropping
        // its LOWEST-ι symbols first (the excess V_parked − V_ret is evicted first).
        // Only when the cap is active (c_recip > 0 — else V_ret is unbounded).
        let mut capped: Vec<Vec<bool>> = owners
            .iter()
            .map(|o| vec![false; o.symbols.len()])
            .collect();
        let mut cap_drops: Vec<SymbolSlot> = Vec::new();
        if cap.active() {
            for &oi in &owner_idx {
                let v_ret = cap.v_ret(kappa(&owners[oi]));
                let mut parked: f64 = owners[oi].symbols.iter().map(|s| s.volume).sum();
                if parked <= v_ret {
                    continue;
                }
                for &si in &sorted_syms[oi] {
                    if parked <= v_ret {
                        break;
                    }
                    cap_drops.push(SymbolSlot {
                        owner_idx: oi,
                        symbol_idx: si,
                    });
                    capped[oi][si] = true;
                    parked -= owners[oi].symbols[si].volume;
                }
            }
        }

        // Pressure drop_order: every REMAINING (non-cap-trimmed) symbol, same two-level
        // order. The caller stops at φ ≥ s_target; cap_drops are already excluded here
        // so no symbol is dropped twice.
        let mut slots: Vec<SymbolSlot> = Vec::new();
        for &oi in &owner_idx {
            for &si in &sorted_syms[oi] {
                if capped[oi][si] {
                    continue;
                }
                slots.push(SymbolSlot {
                    owner_idx: oi,
                    symbol_idx: si,
                });
            }
        }

        (cap_drops, slots)
    } else {
        (Vec::new(), Vec::new())
    };

    // Accept only above the upper gap and only when not evicting (Δ_accept).
    let accept_ok = phi > hyst.s_soft && !evicting;

    EvictionDecision {
        cap_drops,
        drop_order,
        accept_ok,
        phase: EvictPhase { evicting },
    }
}

// ============================================================
// S1 — credit limit: L ≥ V_dem, ratchets only by proven service.
// ============================================================

/// Owner-private credit-limit policy (dimensionless risk-tolerance knobs).
///
/// `L` reads off the (conservative) reliability surface; this struct holds the
/// policy choices that the surface is parameterised by. Per formula_phase.md
/// "Сборка — кредит-лимит", the construction GUARANTEES only `L ≥ V_dem`; how far
/// `L` exceeds `V_dem` is a risk-tolerance POLICY (steep extrapolation distrust ⇒
/// `L ≈ V_dem·(1+small)`; shallow ⇒ `L` noticeably above `V_dem`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CreditPolicy {
    /// Extra fraction above `V_dem` granted at full capital, before the
    /// capital-confidence factor. `margin ≥ 0`. With steep distrust this is
    /// small (`L ≈ V_dem·(1+margin)`).
    pub margin: f64,
    /// Capital scale `G_ref` at which the confidence factor saturates toward 1.
    /// Larger ⇒ slower ratchet (more proven service required to grant the full
    /// margin). Must be `> 0`; non-positive is treated as "saturated" (factor 1).
    pub g_ref: f64,
}

impl Default for CreditPolicy {
    fn default() -> Self {
        // Conservative defaults: a 25% headroom above the demonstrated scale,
        // ratcheting in over a capital scale of 1.0 (dimensionless).
        CreditPolicy {
            margin: 0.25,
            g_ref: 1.0,
        }
    }
}

/// Credit limit `L(G, V_dem)` for a pair — the CLOSED-FORM APPROXIMATION.
///
/// **This is a documented approximation of the canonical surface read
/// [`credit_limit_from_surface`] (A.13 / decision_model §7), valid under the default
/// prior only.** The canonical definition is `L(O→h) = max{V : r̂_h(V, T_horizon) ≥
/// r_min(ι)}` — the largest volume at which the holder still meets the required
/// reliability on the horizon, read straight off the surface. The closed form below
/// captures the same SHAPE (`L ≥ V_dem`, ratcheting smoothly with proven capital)
/// without a surface inversion; when using it, `g_ref` should be read in units of
/// `g*(V_dem)` (the steady-state capital of retaining `V_dem`), NOT the bare `1.0`
/// default. Kept because it is cheap and self-documenting; `place` uses the exact
/// surface read, not this. (Grep-verified 2026-07-06: zero production/sim consumers.)
///
/// Guarantees `L ≥ V_dem` (W4: you may always be trusted up to the largest barrel
/// you have proven). The headroom above `V_dem` ratchets up ONLY with proven
/// service (capital `g`): the confidence factor `g/(g+g_ref) ∈ [0,1)` rises
/// monotonically with `g` and never jumps (no discontinuity), so a node cannot
/// be granted `V ≫ V_dem` without first accumulating real, time-integrated
/// capital. The ratchet is smooth in `g` — there is no step.
///
/// ```text
/// L = V_dem · (1 + margin · g/(g + g_ref))
/// ```
///
/// All inputs are clamped: negative `v_dem`/`g` are floored at 0, a non-positive
/// `g_ref` saturates the factor to 1 (full margin).
pub fn credit_limit(g: f64, v_dem: f64, policy: &CreditPolicy) -> f64 {
    let v_dem = v_dem.max(0.0);
    let g = g.max(0.0);
    let margin = policy.margin.max(0.0);

    let confidence = if policy.g_ref > 0.0 {
        g / (g + policy.g_ref)
    } else {
        1.0
    };

    v_dem * (1.0 + margin * confidence)
}

/// Number of bisection halvings for the surface credit read. A FIXED count (no
/// data-dependent loop bound) so two runs are byte-identical — determinism is
/// load-bearing here (the kernel drives a deterministic sim). 60 halvings shrink the
/// `[0, v_max]` bracket by `2⁻⁶⁰ ≈ 9e-19` of its width, far below any meaningful
/// volume, so the returned `L` is exact for every practical purpose.
const CREDIT_SURFACE_BISECTION_ITERS: u32 = 60;

/// Credit limit `L(O→h)` READ FROM THE RELIABILITY SURFACE — the canonical A.13 /
/// decision_model §7 definition:
///
/// ```text
/// L(O→h) = max{ V ∈ [0, v_max] : r̂_h(V, t_horizon) ≥ r_min }
/// ```
///
/// the largest per-holder volume at which the holder still meets the required
/// per-holder reliability `r_min` on the horizon `t_horizon`. The closed-form
/// [`credit_limit`] is only a documented approximation of THIS read.
///
/// **Why a bisection inverts it exactly.** `r̂` from [`estimate_surface`] is MONOTONE
/// NON-INCREASING in `V` (the volume-hazard multiplier only rises with volume; the
/// off-sample inflation only grows the excess `(V − v_dem)/v_dem`). So the feasible
/// set `{V : r̂(V, t_horizon) ≥ r_min}` is an interval `[0, L]`, and bisecting on `V`
/// with the invariant "`lo` feasible, `hi` infeasible" converges to `L`.
///
/// Boundary cases short-circuit: if even the ceiling `v_max` meets `r_min` the whole
/// range is feasible (`L = v_max`); if `V = 0` already fails, the holder cannot be
/// trusted with any volume at this floor (`L = 0`). Both `r_min` and `v_max` are
/// clamped defensively.
///
/// Anti-oracle: inputs are the first-hand `obs` + the offline `prior` + the
/// owner-private `r_min`/`t_horizon`/`v_max`. No hidden hazard/archetype is reachable
/// — it flows entirely through [`estimate_surface`], which has no such field.
pub fn credit_limit_from_surface(
    obs: &FirstHandObs,
    prior: &SurfacePrior,
    r_min: f64,
    t_horizon: f64,
    v_max: f64,
) -> f64 {
    let r_min = r_min.clamp(0.0, 1.0);
    let v_max = v_max.max(0.0);

    // Ceiling already meets the floor ⇒ the whole range is feasible.
    if estimate_surface(obs, prior, v_max, t_horizon).r_hat >= r_min {
        return v_max;
    }
    // Even a vanishing volume fails the floor ⇒ no volume can be trusted.
    if estimate_surface(obs, prior, 0.0, t_horizon).r_hat < r_min {
        return 0.0;
    }

    // Bisect: `lo` always feasible (r̂ ≥ r_min), `hi` always infeasible (r̂ < r_min).
    let mut lo = 0.0f64;
    let mut hi = v_max;
    for _ in 0..CREDIT_SURFACE_BISECTION_ITERS {
        let mid = 0.5 * (lo + hi);
        if estimate_surface(obs, prior, mid, t_horizon).r_hat >= r_min {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

// ============================================================
// Phase 2 — surface / placement / block-survival (STUBS ONLY).
// ============================================================
//
// These are declared so the type surface is stable for later scenarios
// (SIM-6/8/11/12). They are NOT implemented in Phase 1 (SIM-2 needs only
// capital + eviction + hysteresis). The bodies intentionally do not exist yet;
// see Phase 2 of sim_plan.md §7.

/// Offline-calibrated reliability surface prior (Phase 2): the parametric
/// skeleton (Weibull-in-τ × volume-hazard) whose SHAPE is an offline prior, not
/// learned online (CONV-8 / formula_phase.md §3 "k offline, λ_W online").
///
/// This is the **one place global structure legitimately enters** (4r §1
/// carve-out): the FORM of the evidence→survival map is a shared modeling prior,
/// calibrated offline on honest curated data (recovered by the SIM-12
/// nonparametric estimator), carrying ≤ a couple of per-pair handles. Mis-spec
/// must be SAFE: a wrong form must drive the estimate to the conservative
/// (under-estimate) side, never the dangerous over-estimate side. That safety is
/// enforced in [`estimate_surface`] by the off-sample uncertainty inflation, not
/// by the prior being correct.
///
/// The form (`weibull_k`, `volume_hazard_exponent`) is the OFFLINE part — read,
/// never fit from `obs`. The scale (`weibull_lambda_default`) is the slot the
/// node could learn online per-pair; here it is a default the node starts from.
#[derive(Debug, Clone, PartialEq)]
pub struct SurfacePrior {
    /// Weibull shape `k` (offline-calibrated; sign of DFR↔IFR). `k<1` =
    /// infant-mortality / decreasing-failure-rate (survived early ⇒ safer),
    /// `k=1` = memoryless exponential, `k>1` = wear-out. OFFLINE — the form.
    pub weibull_k: f64,
    /// Weibull scale `λ_W` default (the characteristic time-to-failure; the
    /// online-learnable per-node handle). Time units match `tau`.
    pub weibull_lambda_default: f64,
    /// Volume-hazard exponent `p`: how steeply the per-unit-time hazard rises once
    /// volume exceeds the demonstrated scale. The multiplier on the Weibull hazard
    /// is `(v / v_dem)^p` for `v > v_dem` (and `1` at/below `v_dem`): a larger
    /// commitment is easier to drop / has more bits to rot. OFFLINE — part of the
    /// form. `p ≥ 0`.
    pub volume_hazard_exponent: f64,
    /// Prior relative uncertainty `σ0` (dimensionless): the spread the form itself
    /// carries even AT the observed point, before any off-sample inflation. Models
    /// "the offline form is a prior, not a fact". `σ0 ≥ 0`.
    pub prior_rel_uncertainty: f64,
    /// Off-sample inflation gain `γ`: how fast the confidence interval widens per
    /// unit of off-sample distance in `v` (linear in the relative excess) and `τ`
    /// (√ of the relative excess). The B1 guardrail dial: larger `γ` ⇒ thinner-data
    /// points get a wider CI and a more conservative lower bound. `γ ≥ 0`.
    pub off_sample_inflation: f64,
}

impl Default for SurfacePrior {
    fn default() -> Self {
        // Cold-backup-relevant defaults: a mildly infant-mortality form (k<1),
        // a characteristic retention scale of ~1 year, a super-linear
        // volume-hazard, a modest prior spread, and an off-sample inflation gain
        // that meaningfully widens the CI a decade of volume / √-time off-sample.
        // `off_sample_inflation = 0.8` is the value at which the SIM-12b
        // out-of-family battery (multimodal, plateau-cliff) stays conservative
        // across a dense `(v, τ)` grid (worst `r_hat − true_r` ≲ 0.004) WHILE an
        // in-family-correct prior still yields a useful `r_hat` at long τ given a
        // reasonable observation window — the genuine mis-spec-safety ⇄ usefulness
        // balance, verified end-to-end in `viaticum-sim::sim12b`.
        SurfacePrior {
            weibull_k: 0.8,
            weibull_lambda_default: 365.0,
            volume_hazard_exponent: 1.5,
            prior_rel_uncertainty: 0.05,
            off_sample_inflation: 0.8,
        }
    }
}

/// A point estimate on the reliability surface with off-sample uncertainty
/// (Phase 2). The decision takes the LOWER bound off-sample (conservative).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SurfaceEstimate {
    /// Conservative point estimate of `r̂(V, τ)` actually used by decisions.
    /// In-sample this sits near the parametric value; off-sample it is pulled
    /// DOWN toward `ci_low` (under-estimate where data is thin — the B1 / W5 safe
    /// side). This is the value placement/credit reads.
    pub r_hat: f64,
    /// Lower confidence bound. Widens (drops) as `(v, τ)` move off-sample.
    pub ci_low: f64,
    /// Upper confidence bound. Widens (rises toward 1) off-sample. Reported for
    /// honesty / diagnostics; decisions do NOT use it (over-trust would be unsafe).
    pub ci_high: f64,
}

/// A block-placement request (Phase 2): erasure parameters, volume, horizon,
/// reliability target.
///
/// The block is erasure-coded into `n_symbols` symbols, any `k_eff` of which
/// reconstruct it. One symbol goes to each chosen holder, so the per-symbol
/// volume the holder is asked to keep is `volume / n_symbols`. The block survives
/// to `tau` iff at least `k_eff` of its holders keep their symbol intact.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockReq {
    /// Total volume of the block (all `n_symbols` symbols together).
    pub volume: f64,
    /// Number of erasure symbols `n` (one per holder).
    pub n_symbols: usize,
    /// Reconstruction threshold `k_eff`: this many surviving symbols suffice.
    pub k_eff: usize,
    /// Horizon `τ` (days) the block must survive. Doubles as the credit horizon
    /// `T_horizon` the per-holder cap (A.13) reads the surface at.
    pub tau: f64,
    /// Target reliability `R_target(ι)` derived from owner-private importance. This
    /// is the BLOCK floor `place` places up to (decision_model §6 / A.10).
    pub r_target: f64,
    /// Per-holder reliability floor `r_min(ι)` for the credit cap (A.13 /
    /// decision_model §7): the minimum INDIVIDUAL reliability a holder must still
    /// meet at `tau` to be handed one symbol. It is a SEPARATE, MUCH LOWER knob than
    /// `r_target` — a single holder is never asked to reach the whole-block target;
    /// that is what erasure across many holders is for. The per-holder credit limit
    /// `L(O→h) = max{V : r̂_h(V, tau) ≥ r_min}` ([`credit_limit_from_surface`]) reads
    /// off this floor, and [`place`] skips any candidate whose `L < volume_per_symbol`
    /// (Р-5). Setting `r_min = 0` disables the credit cap (used where a scenario
    /// isolates a different mechanism, e.g. SIM-6's §7 spread).
    pub r_min: f64,
}

impl BlockReq {
    /// Per-symbol volume `V = volume / n_symbols` — what one holder is asked to
    /// keep intact. Falls back to the whole volume if `n_symbols == 0` (degenerate;
    /// callers should pass `n_symbols ≥ 1`).
    pub fn volume_per_symbol(&self) -> f64 {
        if self.n_symbols == 0 {
            self.volume
        } else {
            self.volume / self.n_symbols as f64
        }
    }
}

/// Placement result (Phase 2).
///
/// Either a set of chosen holders that reach `r_target` under the §7 address-spread,
/// or `Insufficient` when no admissible selection can reach the target (too few
/// candidates, or too few distinct observable address buckets to spread across).
#[derive(Debug, Clone, PartialEq)]
pub enum PlacementResult {
    /// A successful placement.
    Placed {
        /// Indices (into the candidate slice) of chosen holders.
        holders: Vec<usize>,
        /// Estimated block survival `R̂_wc(T)` of the chosen set — the A.9
        /// worst-case bound ([`estimate_block_survival`]). `place` spreads ≤1 symbol
        /// per bucket, so this reduces to the independent Poisson-binomial over the
        /// per-bucket probs (the degenerate case); NOT the evaluator's true `R(T)`.
        r_hat_block: f64,
    },
    /// `r_target` is unreachable under the §7 spread with the given candidates.
    /// Carries the best `R̂` achieved and the holders that achieved it, for
    /// diagnostics.
    Insufficient {
        /// The best `R̂(T)` reachable under the spread (still below `r_target`).
        best_r_hat_block: f64,
        /// The holders that achieved `best_r_hat_block` (the spread-admissible set
        /// the greedy selection ended on).
        holders: Vec<usize>,
    },
}

/// Which OBSERVABLE address bucket holders are SPREAD across (≤1 symbol per
/// bucket) — the §7 spread rule. A bucket is the unit that, worst-case, fails
/// together; spreading one symbol per bucket *earns* the independence the block
/// survival estimate assumes BETWEEN buckets. The estimate itself does NOT rely on
/// the spread having happened: [`group_min_survival`] takes the worst-case
/// `min(comonotone-within-bucket, independent)` for any number of symbols per
/// bucket (A.9), so multiple symbols in one bucket get NO free independence. Hidden
/// BETWEEN-bucket correlation is not on the formula — it is carried by the ι-margin
/// (§6 cream) and repair, not by a per-symbol penalty.
///
/// Both variants key on FIRST-HAND observables only (§1): `master_id` is a
/// crypto-id, `addr_subnet` is a connection fact. NEITHER variant ever sees the
/// hidden "are these N actually one operator/farm" ground-truth — that is invisible
/// per §1 and lives only in the sim evaluator. The whole point of §7 is that the
/// spread bites on the OBSERVABLE correlate, not the hidden truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapMode {
    /// (A) Spread by `master_id`. A farm of N distinct master-ids on one subnet
    /// looks like N independent buckets → takes N symbols (this is the weak policy
    /// SIM-6 shows failing: minting keys is free, so the master bucket is cheap to
    /// multiply).
    MasterIdOnly,
    /// (B) Spread by `addr_subnet` (the first-hand-observable address bucket). A
    /// farm confined to one subnet collapses to a single bucket regardless of how
    /// many master-ids it mints → gets at most ONE symbol (the strong policy SIM-6
    /// shows holding). Subnets are scarce/costly to multiply, unlike master-ids.
    AddrCorrelate,
}

/// Owner-private placement policy: which observable address bucket to spread over.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlacementPolicy {
    /// Which observable correlate defines the spread bucket (the knob SIM-6 sweeps).
    pub cap_mode: CapMode,
}

impl Default for PlacementPolicy {
    fn default() -> Self {
        // Default to the STRONG spread (by observable subnet); the weak
        // master-id-only mode is the comparison baseline SIM-6 sweeps.
        PlacementPolicy {
            cap_mode: CapMode::AddrCorrelate,
        }
    }
}

/// Survival of the parametric backbone at `(v, tau)`: a Weibull in time, with the
/// per-unit-time hazard scaled up by a volume multiplier past the demonstrated
/// scale. This is the FORM read from the offline prior — `k` and the
/// volume-hazard exponent are never fit from `obs`.
///
/// ```text
/// h_time(τ) = (k/λ_W)·(τ/λ_W)^{k−1}          (Weibull hazard)
/// m_vol(v)  = (v / v_dem)^p   for v > v_dem,  else 1     (volume multiplier)
/// S(v, τ)   = exp( −(τ/λ_W)^k · m_vol(v) )    (multiplier scales cumulative hazard)
/// ```
///
/// Scaling the cumulative hazard `(τ/λ_W)^k` by a per-volume factor is the
/// proportional-hazards form: more volume ⇒ uniformly higher instantaneous hazard
/// ⇒ lower survival, monotonically, at every `τ`. `S` is monotone decreasing in
/// both `τ` and `v` by construction.
fn backbone_survival(prior: &SurfacePrior, v: f64, v_dem: f64, tau: f64) -> f64 {
    let k = prior.weibull_k.max(1e-9);
    let lambda = prior.weibull_lambda_default.max(1e-9);
    let p = prior.volume_hazard_exponent.max(0.0);
    let tau = tau.max(0.0);
    let v = v.max(0.0);
    let v_dem = v_dem.max(1e-9);

    // Volume multiplier on the hazard: 1 at/below demonstrated scale, rising as a
    // power past it. Never below 1 (more volume never makes a holder safer).
    let m_vol = if v > v_dem { (v / v_dem).powf(p) } else { 1.0 };

    let cumulative_hazard = (tau / lambda).powf(k) * m_vol;
    (-cumulative_hazard).exp().clamp(0.0, 1.0)
}

/// Estimate the reliability surface `r̂(V, τ) = P(holder keeps volume `v` intact
/// for time `τ`)` for a holder, conservatively off-sample.
///
/// The node has observed essentially ONE point `(obs.observed_volume,
/// obs.observed_tau)` with a PoS pass/fail history there (B1: one slice per
/// holder). The `v`-axis and long `τ` were never observed, so their value is the
/// shared **offline** form ([`SurfacePrior`]) — NOT fit from `obs`. The further
/// `(v, τ)` is from the observed point, the wider the confidence interval and the
/// lower the conservative point estimate.
///
/// Construction:
/// 1. **Backbone.** [`backbone_survival`] gives the parametric value `r_back` at
///    `(v, τ)` (Weibull-time × volume-hazard, form from the prior). Monotone
///    decreasing in `τ` and in `v`.
/// 2. **In-sample anchor.** At the observed point the node has direct PoS
///    evidence; the PoS pass-fraction `q = pass/(pass+fail+timeout)` anchors the
///    estimate there. We blend the empirical anchor toward the observed point and
///    let the backbone carry the shape away from it, so the curve passes near the
///    PoS evidence in-sample yet follows the form off-sample.
/// 3. **Off-sample distance (ONE-SIDED).** A dimensionless distance `d` grows
///    with the EXTRAPOLATION beyond the observed point in the demanding direction:
///    `max(0, (v − v_dem)/v_dem)` (asking to trust MORE volume than proven, LINEAR)
///    and `√(max(0, (τ − τ0)/τ0))` (asking to trust for LONGER than observed,
///    SQUARE-ROOT). Below/at the observed point these are zero — interpolating
///    toward a region the backbone already calls safer needs no inflation, and
///    keeping the penalty one-sided is what makes `r_hat` globally monotone in `τ`
///    and `v`. The time penalty grows as a square root (faster than the old
///    logarithm, slower than the volume axis's linear): the logarithm grew too
///    slowly to drag `r_hat` down to a wrong-form long-τ tail (SIM-12b BLOCK),
///    while a linear penalty would make even a CORRECT prior vacuous at long τ;
///    the square root makes unobserved long τ conservative yet keeps long-horizon
///    backup useful when the observation window is a reasonable fraction of the
///    horizon. A small-sample term `1/(1+n)` adds distance when there is little PoS
///    evidence even in-sample. `d = 0` exactly at the observed point with ample
///    samples.
/// 4. **CI + conservatism.** The half-width is `w = σ0 + γ·d` (prior spread plus
///    inflation). `ci_low = clamp(r_back·exp(−w))`, `ci_high = clamp(1 −
///    (1−r_back)·exp(−w))` (a multiplicative band that widens symmetrically in
///    log-survival yet stays in [0,1]). The returned `r_hat` is pulled from the
///    backbone toward `ci_low` by the off-sample fraction `1 − exp(−d)`: in-sample
///    (`d→0`) `r_hat → anchored` (near the empirical PoS pass-fraction, but capped
///    at the backbone — a bad record drops it, a good record does not raise it
///    above the form); off-sample (`d` large) `r_hat → ci_low` (the conservative
///    lower edge — under-estimate where data is thin, the B1 / W5 safe side).
///    `r_hat` is always within `[ci_low, ci_high]` AND at or below the backbone
///    `r_back` everywhere — the estimate is never more optimistic than the form.
///
/// Anti-oracle: every input here is first-hand (`obs`) or the offline shared form
/// (`prior`). There is no hidden archetype/hazard anywhere in the signature — the
/// crate boundary makes it compile-impossible.
pub fn estimate_surface(
    obs: &FirstHandObs,
    prior: &SurfacePrior,
    v: f64,
    tau: f64,
) -> SurfaceEstimate {
    let v = v.max(0.0);
    let tau = tau.max(0.0);
    let v0 = obs.observed_volume.max(0.0);
    let tau0 = obs.observed_tau.max(0.0);
    // The demonstrated scale anchors the volume-hazard knee. Use the larger of the
    // ratchet `v_dem` and the actually-observed volume so the multiplier never
    // punishes a holder for the very volume it has already proven.
    let v_dem = obs.v_dem.max(v0).max(1e-9);

    // 1. Parametric backbone value at the query point (form from the prior).
    let r_back = backbone_survival(prior, v, v_dem, tau);

    // 2. In-sample PoS anchor: pass-fraction over my own challenge outcomes.
    //    Samples = pass+fail+timeout. With zero samples the anchor is undefined →
    //    fall back to the backbone (and the small-sample term below widens the CI).
    let n = (obs.pos_pass + obs.pos_fail + obs.pos_timeout) as f64;
    let q = if n > 0.0 {
        obs.pos_pass as f64 / n
    } else {
        r_back
    };

    // 3. Off-sample distance (dimensionless, ONE-SIDED). Zero at/below the
    //    observed point, growing only as we EXTRAPOLATE to more volume / longer
    //    time than proven. One-sidedness keeps r_hat globally monotone in v and τ
    //    (no V-shaped penalty below the observed point) and matches the intent:
    //    the dangerous, conservatism-requiring direction is "trust more than seen".
    //    A small-sample term `1/(1+n)` adds distance when PoS evidence is thin.
    //
    //    The VOLUME axis grows LINEARLY in the relative excess `(v − v_dem)/v_dem`.
    //    The TIME axis grows as the SQUARE ROOT of the relative excess
    //    `√((τ − τ0)/τ0)` — deliberately FASTER than the old logarithm. The log was
    //    too weak: at `v ≤ v_dem` there is no volume multiplier to rescue the
    //    estimate, and a slowly-decaying in-family Weibull tail (`k<1`) sits far
    //    above a true late-burst/cliff form at long τ, so a `ln(τ/τ0)` distance that
    //    barely grows let `r_hat` over-estimate by ~50× (SIM-12b BLOCK). Unobserved
    //    long τ is thin data ⇒ MAX uncertainty ⇒ under-estimate, in the TIME axis
    //    too, not only volume. Square-root (rather than linear) keeps the penalty
    //    bounded enough that an in-family-CORRECT prior remains USEFUL at long τ
    //    when the observation window `τ0` is a reasonable fraction of the queried
    //    horizon — the conservatism scales with how far past the OBSERVED window we
    //    extrapolate, in relative terms (a 30-day observation rightly cannot vouch
    //    for 5 years; a 1-year observation can vouch usefully out to a few years).
    let v_off = ((v - v_dem) / v_dem).max(0.0);
    let tau_off = if tau0 > 0.0 && tau > 0.0 {
        ((tau - tau0).max(0.0) / tau0).sqrt()
    } else {
        // No observed τ to compare against → treat any positive τ as off-sample
        // by a unit of distance (cannot claim in-sample confidence we never had).
        if tau > 0.0 { 1.0 } else { 0.0 }
    };
    let small_sample = 1.0 / (1.0 + n);
    let d = (v_off + tau_off + small_sample).max(0.0);

    // 4. CI half-width and conservative point estimate.
    let sigma0 = prior.prior_rel_uncertainty.max(0.0);
    let gamma = prior.off_sample_inflation.max(0.0);
    let w = sigma0 + gamma * d;
    let band = (-w).exp(); // ∈ (0, 1]; →1 as w→0 (in-sample), →0 off-sample

    let ci_low = (r_back * band).clamp(0.0, 1.0);
    let ci_high = (1.0 - (1.0 - r_back) * band).clamp(0.0, 1.0);

    // In-sample, blend the backbone toward the empirical PoS anchor `q` so the
    // curve honours direct evidence at the observed point; the blend vanishes
    // off-sample (where `q` is irrelevant — we never sampled there). The anchor is
    // capped at the backbone (`min`): a BAD PoS record can only DROP the estimate
    // below the form, a good record leaves it at the form. This one-sided anchor
    // guarantees `r_hat ≤ r_back` everywhere → the conservatism (B1 / W5 safe
    // side) cannot be undone by an optimistic empirical reading.
    let in_sample = band; // close to 1 in-sample, →0 off-sample
    let q_safe = q.min(r_back);
    let anchored = (1.0 - in_sample) * r_back + in_sample * q_safe;

    // Pull the (anchored) value toward the conservative lower edge by the
    // off-sample fraction. d→0: r_hat → anchored (≤ backbone, near the PoS
    // evidence). d large: r_hat → ci_low (under-estimate, the safe side).
    let off_frac = 1.0 - (-d).exp(); // ∈ [0, 1)
    let r_hat = ((1.0 - off_frac) * anchored + off_frac * ci_low).clamp(ci_low, ci_high);

    SurfaceEstimate {
        r_hat,
        ci_low,
        ci_high,
    }
}

// ============================================================
// Phase 2b-1 — block survival R̂ + placement with §7 address-spread.
// ============================================================

/// The observable address bucket a holder belongs to under the spread policy: its
/// `addr_subnet` (spread by subnet, the §7 default) or its `master_id` (spread by
/// master-id only). One symbol per bucket — distinct buckets are treated
/// independent, so the bucket is exactly the unit the spread keeps to ≤1 symbol.
///
/// Anti-oracle: the only inputs are first-hand observables on [`FirstHandObs`]
/// (`addr_subnet`, `master_id`). The hidden "is-one-farm" truth is NOT a field on
/// `FirstHandObs` and the crate boundary keeps it out (it lives only in the sim
/// generator), so the bucket key physically cannot be the hidden truth.
fn bucket_key(holder: &FirstHandObs, policy: &PlacementPolicy) -> BucketKey {
    match policy.cap_mode {
        CapMode::MasterIdOnly => BucketKey::Master(holder.master_id.0),
        CapMode::AddrCorrelate => BucketKey::Subnet(holder.addr_subnet),
    }
}

/// An observable address-bucket label (subnet or master-id). Equality is what
/// groups holders into one bucket; the two variants never compare equal, so the
/// policy choice fully determines the partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BucketKey {
    /// Spread by `addr_subnet`.
    Subnet(u32),
    /// Spread by `master_id` bytes.
    Master([u8; 32]),
}

/// Number of distinct address buckets spanned by a holder set under the policy.
/// Diagnostic helper (used by tests and callers checking the spread): the number
/// of independent positions the §7 spread can place (≤1 symbol each).
pub fn cluster_count(holders: &[FirstHandObs], policy: &PlacementPolicy) -> usize {
    let mut seen: Vec<BucketKey> = Vec::new();
    for h in holders {
        let key = bucket_key(h, policy);
        if !seen.contains(&key) {
            seen.push(key);
        }
    }
    seen.len()
}

/// Node-side estimate of a block's survival `R̂_wc(T)`: the CORRELATION-AWARE
/// worst-case probability that at least `k_eff` of the chosen holders keep their
/// symbol intact to `tau` (A.9 / decision_model §5, canon §5½ B1).
///
/// Construction:
/// 1. **Per-symbol surface prob for ALL holders.** Every holder in `placement`
///    contributes ONE position, labelled by its first-hand correlate group
///    ([`bucket_key`]: `addr_subnet` by the §7 default, or `master_id`). Its
///    survival prob is `estimate_surface(...).r_hat` — the conservative
///    off-sample-inflated lower bound from Phase 2a. The estimator does NOT collapse
///    same-group holders to one best position (that is the job of [`place`], not of
///    the estimate); it honestly carries every symbol in the group.
/// 2. **A.9 worst-case convolution** ([`group_min_survival`]):
///    `R̂_wc = min(comonotone-within-groups, independent-over-all-symbols)`. Symbols
///    sharing an observable correlate are treated as worst-case positively coupled
///    (comonotone) INSIDE the group and independent BETWEEN groups (the independence
///    the §7 spread earns on the observable correlate); the `min` with the plain
///    Poisson-binomial keeps the bound conservative even where thin within-group
///    redundancy makes comonotone non-worst-case (audit B-2).
///
/// **Why worst-case, not the point independent Poisson-binomial (§7, §9½).** The
/// bare independent estimate errs to the DANGEROUS side (over-estimating `R̂` ⇒
/// under-placement) under unobserved within-correlate coupling. The old estimator
/// also carried a geo-radius union-find and an `n−k_eff` concentration cap; both are
/// gone — the geo machinery needed a non-calibratable "geo-radius" magic number we
/// do not have (`sim_plan.md §5.1`), and the observable-correlate risk is now
/// handled honestly by the comonotone-within construction. Hidden BETWEEN-group
/// correlation is not on the formula — it is carried by the ι-margin (§6 cream) and
/// repair.
///
/// In the ≤1-symbol-per-group regime (what [`place`] produces) `R̂_wc` is
/// bit-identical to the pre-A.9 independent Poisson-binomial (the degenerate
/// identity in [`group_min_survival`]). If fewer than `k_eff` symbols exist in
/// total, `R̂_wc = 0` (structurally undeliverable). NOT the evaluator's true `R(T)`
/// (that is god-view, from the hidden hazards; this is the node's decision input).
///
/// Anti-oracle: inputs are first-hand `placement` observations + the offline
/// `prior` + the `req`/`policy`. No hidden hazard or farm-truth is reachable — the
/// bucket key is an observable address, never the hidden "is-one-farm" truth.
pub fn estimate_block_survival(
    placement: &[FirstHandObs],
    prior: &SurfacePrior,
    req: &BlockReq,
    policy: &PlacementPolicy,
) -> f64 {
    if placement.is_empty() || req.k_eff == 0 {
        // k_eff == 0 means "no holders needed" — vacuously certain to survive.
        return if req.k_eff == 0 { 1.0 } else { 0.0 };
    }

    let v_per_symbol = req.volume_per_symbol();
    let tau = req.tau.max(0.0);

    // A.9′ (Р-8) врезка: partition holders into correlate GROUPS by their observable
    // key ([`bucket_key`]: `addr_subnet` by the §7 default, or `master_id`), each
    // holder carrying one symbol (`s_h = 1` in the kernel's one-symbol-per-holder
    // model) at its conservative surface prob. NO best-per-bucket collapse — the A.9′
    // convolution honestly carries every symbol in the group; the ≤1/group spread is a
    // `place`-side concern (now the BLOCK-1 guard), not the estimate's.
    //
    // Because `s_h = 1` here, `block_survival_grouped` degenerates to the per-symbol
    // A.9 [`group_min_survival`] (its comonotone staircase over unit weights is exactly
    // the per-symbol comonotone law, and construction B is the same
    // `correlated_recovery_prob`) — so the estimate is numerically unchanged, and in
    // the singleton-group substrate it is bit-identical to `correlated_recovery_prob`.
    // Groups are built in insertion order via a linear scan (no HashMap ⇒ deterministic).
    let mut groups: Vec<(BucketKey, Vec<(u32, f64)>)> = Vec::new();
    for obs in placement {
        let p = estimate_surface(obs, prior, v_per_symbol, tau)
            .r_hat
            .clamp(0.0, 1.0);
        let key = bucket_key(obs, policy);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, hs)) => hs.push((1, p)),
            None => groups.push((key, vec![(1, p)])),
        }
    }
    let grouped: Vec<Vec<(u32, f64)>> = groups.into_iter().map(|(_, hs)| hs).collect();

    block_survival_grouped(&grouped, req.k_eff as u32)
}

/// `P(≥ k successes)` for independent Bernoulli trials with the given success
/// probabilities, via an exact Poisson-binomial DP. `O(m·k)` time, `O(k)` space.
fn poisson_binomial_at_least(probs: &[f64], k: usize) -> f64 {
    if k == 0 {
        return 1.0;
    }
    let m = probs.len();
    if k > m {
        return 0.0;
    }
    // dp[c] = probability that exactly c of the trials so far succeeded.
    let mut dp = vec![0.0f64; m + 1];
    dp[0] = 1.0;
    let mut filled = 0usize; // how many entries of dp are meaningful so far
    for &p in probs {
        let p = p.clamp(0.0, 1.0);
        // Update in descending order so we read dp[c-1] before overwriting it.
        let upper = filled + 1;
        for c in (0..=upper).rev() {
            let stay = dp[c] * (1.0 - p);
            let gain = if c > 0 { dp[c - 1] * p } else { 0.0 };
            dp[c] = stay + gain;
        }
        filled = upper;
    }
    dp[k..=m].iter().sum::<f64>().clamp(0.0, 1.0)
}

/// Construction A of the A.9 worst-case bound: **comonotone WITHIN each observable
/// correlate group, independent BETWEEN groups** (decision_model §5 / A.9).
///
/// Symbols of the block are partitioned by their [`BucketKey`] (subnet / master,
/// per the spread policy). Within one group `c` a SINGLE shared uniform `U_c`
/// drives every symbol — the perfectly-positively-correlated (comonotone) coupling
/// that models "these symbols share an observable risk correlate, so worst-case
/// they fail together". A symbol with survival prob `p_i` survives iff `U_c ≤ p_i`,
/// so with the group's probs sorted DESCENDING `p₍₁₎ ≥ … ≥ p₍g₎` the number of
/// survivors `N_c = #{i : U_c ≤ p_i}` has the CLOSED-FORM law (no sampling —
/// analytic, hence bit-deterministic):
///
/// ```text
/// P(N_c = 0) = 1 − p₍₁₎
/// P(N_c = j) = p₍ⱼ₎ − p₍ⱼ₊₁₎     (1 ≤ j < g)
/// P(N_c = g) = p₍g₎
/// ```
///
/// (convention `p₍₀₎ = 1`, `p₍g₊₁₎ = 0`; the terms telescope to 1 and are all
/// non-negative because the sorted probs are non-increasing). The survivors are
/// NESTED: whenever the weaker symbol survives so does every stronger one, so a
/// single-symbol group is exactly a `Bernoulli(p)` and the whole construction
/// degenerates to the independent Poisson-binomial (the load-bearing degenerate
/// identity below).
///
/// Between groups the coupling is INDEPENDENCE (exactly the independence the §7
/// spread EARNS on the observable correlate), so the total survivor count
/// `N = Σ_c N_c` is the convolution of the per-group laws. We DP-convolve the group
/// laws in INSERTION order (deterministic — no `HashMap`) and return
/// `R̂_A = P(N ≥ k_eff)`.
///
/// Determinism: grouping preserves insertion order via a linear `Vec` scan, the
/// per-group sort is `total_cmp`, and `U_c` is handled analytically (never sampled)
/// — two runs are byte-identical.
fn comonotone_within_groups_at_least(positions: &[(BucketKey, f64)], k_eff: usize) -> f64 {
    if k_eff == 0 {
        return 1.0;
    }
    // Partition into insertion-ordered groups (no HashMap — deterministic order).
    let mut groups: Vec<(BucketKey, Vec<f64>)> = Vec::new();
    for &(key, p) in positions {
        let p = p.clamp(0.0, 1.0);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, ps)) => ps.push(p),
            None => groups.push((key, vec![p])),
        }
    }

    // DP over the total survivor count N = Σ_c N_c. `dp[n] = P(total survivors = n)`.
    let mut dp = vec![1.0f64]; // N = 0 with probability 1 before any group.
    for (_, ps) in &groups {
        // Per-group comonotone law over {0..g}, from the DESCENDING-sorted probs.
        let mut q = ps.clone();
        q.sort_by(|a, b| b.total_cmp(a));
        let g = q.len();
        let mut group_law = vec![0.0f64; g + 1];
        group_law[0] = 1.0 - q[0]; // P(N_c = 0) = 1 − p₍₁₎
        for j in 1..g {
            group_law[j] = q[j - 1] - q[j]; // P(N_c = j) = p₍ⱼ₎ − p₍ⱼ₊₁₎
        }
        group_law[g] = q[g - 1]; // P(N_c = g) = p₍g₎

        // Convolve dp with this group's law (groups independent).
        let mut next = vec![0.0f64; dp.len() + g];
        for (n, &pn) in dp.iter().enumerate() {
            if pn == 0.0 {
                continue;
            }
            for (j, &pj) in group_law.iter().enumerate() {
                next[n + j] += pn * pj;
            }
        }
        dp = next;
    }

    dp.iter().skip(k_eff).sum::<f64>().clamp(0.0, 1.0)
}

/// The A.9 correlation-aware worst-case block survival `R̂_wc` (decision_model §5,
/// canon §5½ B1). Replaces the naïve independent Poisson-binomial (a POINT estimate
/// that errs to the DANGEROUS side — over-estimating `R̂` ⇒ under-placement) with a
/// conservative lower bound under the unobserved within-correlate coupling.
///
/// `R̂_wc = min(R̂_A, R̂_B)` of two GLOBAL constructions (both: independence BETWEEN
/// groups):
///
/// * **A — comonotone within groups** ([`comonotone_within_groups_at_least`]):
///   worst-case positive dependence inside each observable correlate.
/// * **B — independent within and between**: the plain Poisson-binomial over ALL
///   symbols ([`poisson_binomial_at_least`]), grouping irrelevant.
///
/// **Why `min`, not "comonotone is always worst-case" (audit B-2).** Comonotone is
/// worst-case only when `k_eff` is LOW relative to a group's size (our spread
/// regime, ≤1 symbol/group); for THIN within-group redundancy (`k_eff` near the
/// group size) it FLIPS and independence is the more conservative of the two — e.g.
/// 3 symbols `p=0.9` in one group, `k_eff=3`: comonotone `P = 0.9` > independent
/// `0.9³ = 0.729`. So "`R̂_wc ≤ independent` always" would be FALSE for pure
/// comonotone; taking the per-construction `min` restores conservatism cheaply.
/// This is NOT the true Fréchet lower bound (which is harder and NOT needed —
/// placement spreads ≤1 symbol/group so multi-per-group is off the operating path);
/// the hidden BETWEEN-group correlation the formula cannot see is carried by the
/// ι-margin (§6 cream) and repair, not by this bound.
///
/// **Degenerate case (≤1 symbol per group) — load-bearing.** A single-symbol group
/// is its own comonotone coupling, so construction A is analytically IDENTICAL to B
/// (and bit-identical too: both walk the same symbols in the same order through the
/// same `stay·(1−p) + gain·p` recurrence, and IEEE-754 addition is commutative), so
/// `R̂_wc` reduces to exactly the pre-A.9 independent Poisson-binomial. This is what
/// keeps [`place`] — which spreads ≤1 symbol/bucket — and the whole sim UNCHANGED.
///
/// **Structural zero.** `R̂_wc = 0` exactly when fewer than `k_eff` symbols exist in
/// total (`positions.len() < k_eff`): even all-survive cannot reach the threshold,
/// so both constructions vanish (max `Σ N_c` = the symbol count). NOTE this is
/// SYMBOL count, not DISTINCT-GROUP count: A.9 no longer collapses a group to one
/// position, so `g` symbols in one correlate CAN deliver up to `g` survivors
/// together (comonotone) — the old "distinct buckets < k_eff ⇒ 0" gate was the
/// collapse-model artefact this transche removes. In the ≤1/group regime the two
/// conditions coincide, so `place`/sim see no change.
fn group_min_survival(positions: &[(BucketKey, f64)], k_eff: usize) -> f64 {
    if k_eff == 0 {
        return 1.0;
    }
    // Structural zero: fewer symbols than k_eff ⇒ the threshold is unreachable even
    // if every symbol survives (max Σ N_c = the symbol count).
    if positions.len() < k_eff {
        return 0.0;
    }

    // Construction B: independent over ALL symbols (grouping irrelevant).
    let all_probs: Vec<f64> = positions.iter().map(|(_, p)| *p).collect();
    let r_b = poisson_binomial_at_least(&all_probs, k_eff);

    // Construction A: comonotone within groups, independent between.
    let r_a = comonotone_within_groups_at_least(positions, k_eff);

    r_a.min(r_b)
}

// ============================================================
// A.9′ (Р-8) — HOLDER-level correlation-aware worst-case block survival, built ON
// TOP of the production reliability DP. The holder-weighted generalisation of the
// per-symbol A.9 above: the unit of survival is a HOLDER carrying `s_h` symbols
// (comonotone within the holder — its symbols live/die together), and correlate
// groups partition HOLDERS, not symbols. `4r_rebase_quanta.md` §3 / decision_model §5.
// ============================================================

/// The comonotone survivor-count STAIRCASE of ONE correlate group (A.9′ construction
/// A, `4r_rebase_quanta.md` §3). A single shared uniform `U_c` drives every holder in
/// the group, so a holder survives iff `U_c ≤ p_h` and the survivors are NESTED:
/// sorting the group by `p` DESCENDING (`p₍₁₎ ≥ … ≥ p₍ₘ₎`), the survivor SYMBOL count
/// is the prefix SUM of the weights `S_j = Σ_{i≤j} s₍ᵢ₎` with law
///
/// ```text
/// P(N_c = 0)   = 1 − p₍₁₎
/// P(N_c = S_j) = p₍ⱼ₎ − p₍ⱼ₊₁₎      (1 ≤ j ≤ m, convention p₍ₘ₊₁₎ = 0)
/// ```
///
/// Returns the `(added_symbols, probability)` outcomes UNCAPPED (the caller convolves
/// and caps at `k_eff`). The probabilities telescope to exactly `1` — a proper law —
/// which is the load-bearing invariant `a9_staircase_sums_to_one` asserts. Survival
/// probs are clamped to `[0,1]` (four_r convention). An empty group yields the single
/// deterministic outcome `(0, 1.0)` (it contributes no survivors, never NaN).
///
/// The prefix sums use `u64` so a real-scale group (≤30 holders × up to 2048 symbols)
/// cannot overflow the survivor axis.
fn comonotone_group_law(group: &[(u32, f64)]) -> Vec<(u64, f64)> {
    if group.is_empty() {
        return vec![(0, 1.0)];
    }
    // Sort the group's holders by survival prob DESCENDING (staircase order).
    let mut hs: Vec<(u32, f64)> = group.iter().map(|&(s, p)| (s, p.clamp(0.0, 1.0))).collect();
    hs.sort_by(|a, b| b.1.total_cmp(&a.1));
    let m = hs.len();

    let mut law: Vec<(u64, f64)> = Vec::with_capacity(m + 1);
    law.push((0, 1.0 - hs[0].1)); // N_c = 0 with probability 1 − p₍₁₎
    let mut prefix: u64 = 0;
    for j in 0..m {
        prefix += hs[j].0 as u64; // S_j = Σ_{i≤j} s₍ᵢ₎
        let p_j = hs[j].1;
        let p_next = if j + 1 < m { hs[j + 1].1 } else { 0.0 }; // p₍ⱼ₊₁₎, with p₍ₘ₊₁₎ = 0
        law.push((prefix, p_j - p_next));
    }
    law
}

/// A.9′ (Р-8) worst-case block survival `R̂_wc` over EXPLICIT correlate groups of
/// WEIGHTED holders — `min(R̂_A, R̂_B)` (`4r_rebase_quanta.md` §3, decision_model §5).
///
/// `groups[c]` = the holders of correlate group `c`, each `(s_h, p_h)` = its symbol
/// weight and survival probability. Two GLOBAL constructions, both with independence
/// BETWEEN groups:
///
/// * **B — independent holders** = [`reliability::correlated_recovery_prob`] over ALL
///   holders flattened (the production DP `P(Σ_{alive} s_h ≥ k_eff)`), called
///   VERBATIM. A.9′ is built ON TOP of the production reliability function, not beside
///   it (AC-2 "поверх, не рядом") — the same code the daemon already ships.
/// * **A — comonotone within a group, independent between** = each group's
///   [`comonotone_group_law`] staircase, DP-convolved on the survivor axis and capped
///   at `k_eff`.
///
/// **Why `min` (`4r_rebase_quanta.md` §3 BLOCK-1).** The sanctioned within-group
/// dependency family is the common-shock MIXTURE `α·comonotone + (1−α)·independent`
/// (group-wide shock — power/ISP — vs individual fates); for any such mixture
/// `P = α·P_A + (1−α)·P_B ≥ min(P_A, P_B)`, so `min` is a PROVABLE lower bound within
/// the family. Out-of-family "k-of-m within one group" couplings (where `min` is not a
/// bound) are made unreachable by the placement BLOCK-1 guard ([`place`] /
/// [`block1_guard_admits`]): no group is decode-critical.
///
/// **Singleton equivalence (AC-2), load-bearing.** When every group is a singleton
/// (one holder), that holder's staircase is a single `Bernoulli(p_h)` over `{0, s_h}`
/// — the EXACT per-holder step of `correlated_recovery_prob` — so construction A walks
/// the same holders through the same capped recurrence as construction B and `R̂_A`,
/// `R̂_B` are BIT-identical, i.e. `R̂_wc ≡ correlated_recovery_prob`. The current
/// substrate has no ASN/geo sources (D8), so every group IS a singleton and the 4R
/// kernel and the production reliability code compute the SAME number. That is the
/// врезка's regression guarantee.
///
/// Degenerate cases: `k_eff == 0` ⇒ `1.0` (nothing needed); empty `groups` or total
/// weight `Σ s_h < k_eff` ⇒ `0.0` (structurally undeliverable — even all-survive
/// cannot reach `k_eff`). Survival probs are CLAMPED to `[0,1]` (the four_r
/// convention: [`estimate_surface`] / [`poisson_binomial_at_least`] clamp too). The
/// clamp makes `correlated_recovery_prob`'s range check always pass, so its `Result`
/// is `Ok` and `unwrap_or(0.0)` is a pure defensive floor, never a real error path.
///
/// Cost `O((Σ_c |group_c|) · k_eff)` per construction — trivial (H ≤ 30, k_eff ≤ 2052).
pub fn block_survival_grouped(groups: &[Vec<(u32, f64)>], k_eff: u32) -> f64 {
    if k_eff == 0 {
        return 1.0;
    }
    let cap = k_eff as usize;

    // Structural zero: fewer symbols than k_eff ⇒ the threshold is unreachable even if
    // every holder survives (max Σ N_c = the total symbol weight).
    let total: u64 = groups.iter().flatten().map(|&(s, _)| s as u64).sum();
    if total < k_eff as u64 {
        return 0.0;
    }

    // --- Construction B: production reliability DP over all holders, VERBATIM. ---
    let flat: Vec<(u32, f64)> = groups
        .iter()
        .flatten()
        .map(|&(s, p)| (s, p.clamp(0.0, 1.0)))
        .collect();
    let r_b = crate::reliability::correlated_recovery_prob(&flat, k_eff).unwrap_or(0.0);

    // --- Construction A: comonotone within a group, independent between. ---
    // dp[n] = P(total survivors so far = n), with n ≥ k_eff lumped into dp[cap].
    let mut dp = vec![0.0f64; cap + 1];
    dp[0] = 1.0;
    for group in groups {
        let law = comonotone_group_law(group);
        let mut next = vec![0.0f64; cap + 1];
        for (x, &mass) in dp.iter().enumerate() {
            if mass == 0.0 {
                continue;
            }
            for &(add, prob) in &law {
                if prob == 0.0 {
                    continue;
                }
                let nx = ((x as u64) + add).min(cap as u64) as usize;
                next[nx] += mass * prob;
            }
        }
        dp = next;
    }
    let r_a = dp[cap].clamp(0.0, 1.0);

    r_a.min(r_b)
}

/// BLOCK-1 placement-guard predicate (Р-8, `4r_rebase_quanta.md` §3): may one more
/// symbol be added to correlate group `c` without risking the block becoming
/// decode-critical on `c` (i.e. dying if the WHOLE of group `c` is lost)?
///
/// Admissible iff group `c` is currently EMPTY — opening a fresh group, exactly as the
/// retired ≤1/group spread opened a fresh bucket, the block does not yet depend on it
/// — OR the chosen set already holds ≥ `k_eff` symbols OUTSIDE group `c`, so a further
/// symbol on `c` cannot make the block depend on `c`: losing `c` entirely still leaves
/// ≥ `k_eff` survivors.
///
/// `symbols_in_c` / `symbols_total` are the CURRENT (pre-add) chosen counts;
/// `symbols_total − symbols_in_c = Σ_{h∉c} s_h`. Adding a symbol to `c` raises both by
/// one, leaving `Σ_{h∉c} s_h` unchanged, so testing the pre-add value is exact — and
/// it is precisely the "convenient form" `S_c ≤ S_total − k_eff` of the invariant
/// (`4r_rebase_quanta.md` §3): post-add `S_c+1 ≤ (S_total+1) − k_eff ⟺
/// symbols_total − symbols_in_c ≥ k_eff`.
///
/// **Guarantee.** Every group that ever receives a SECOND symbol did so while ≥ `k_eff`
/// symbols already sat outside it, and placement never removes symbols, so at
/// termination no MULTI-symbol group is decode-critical. Single-symbol groups are
/// governed by `r_target` exactly as under the old cap (a minimal `k_eff`-group
/// placement was decode-critical under BOTH the old ≤1/bucket cap and this guard;
/// redundancy beyond that is `r_target`'s job, and cream's above the floor).
///
/// **Equivalence to the retired ≤1/group cap for singleton groups
/// (`guard_equals_legacy_cap_for_singleton_groups`).** With ≤1 symbol per group every
/// candidate opens a FRESH group (`symbols_in_c == 0`), so this predicate is ALWAYS
/// true — it admits exactly the fresh-bucket candidates the old spread admitted, and a
/// second-per-group symbol (which the old cap forbade outright) is only permitted here
/// once the block is already safe against that group's loss. Neutral in the singleton
/// world; the sanctioned behaviour change is confined to genuine multi-holder groups.
fn block1_guard_admits(symbols_in_c: u64, symbols_total: u64, k_eff: u32) -> bool {
    symbols_in_c == 0 || symbols_total.saturating_sub(symbols_in_c) >= k_eff as u64
}

// ============================================================
// K3 — per-symbol block survival R̂: surface × eviction-retention.
// ============================================================
//
// K2 estimated one survival prob per HOLDER and treated every one of an owner's
// symbols on that holder as equally safe. That is too coarse: a holder under
// contention does not drop "all my symbols or none" — it drops my LOWEST-ι
// symbols first (the intra-owner ladder of `eviction_order`), keeping the top of
// my ladder. So two symbols of MINE on the SAME holder do NOT have the same
// keep-probability: a high-ι symbol that sits above the holder's retained depth
// survives eviction; a low-ι one below it is the first to go.
//
// K3 forecasts the keep-probability of EACH symbol separately as the product of
// two INDEPENDENT death routes (the architect-approved model):
//
//     p_symbol = surface(h, τ) × s(r ; φ_O, β)
//
//   * Route A — `surface(h, τ)`: the holder dies / leaves the network (hardware
//     death, departure). INDEPENDENT of importance — the disk failing does not
//     ask which symbol is which. This is exactly the K2 per-holder
//     `estimate_surface(...).r_hat`.
//   * Route B — `s(r ; φ_O, β)`: the holder is ALIVE but evicts my symbol under
//     its own disk pressure. `r` is the symbol's ι-RANK within MY symbols on that
//     holder (the eviction ladder), in [0,1]; `φ_O` is the retained DEPTH the
//     holder keeps for me. A symbol above the retained depth survives eviction
//     (`s → 1`); below it, `s` is small.
//
// The two routes multiply because hardware-death and eviction are independent
// failure modes; block-R̂ is then the heterogeneous Poisson-binomial over the
// per-symbol `p_i` (one chosen holder per address bucket, K2's §7 spread).

/// Calibratable priors for the eviction-retention route `s(r ; φ_O, β)` and the
/// retained-depth `φ_O = sigmoid(standing − pressure)`.
///
/// Every field here is a CALIBRATABLE PRIOR with a sane default — the same status
/// as [`SurfacePrior`]'s `weibull_k` / `off_sample_inflation`. We choose start
/// values now from a rough picture of the world (sim_plan.md §5.1: choosing a
/// number is fine, *believing* it is not); the field re-calibrates them. The
/// FORM (a sigmoid step in ι-rank, a sigmoid in standing−pressure) is the modeling
/// commitment; the SCALES below are weakly-held knobs.
///
/// Anti-oracle: these are dimensionless constants on the owner's OWN policy — none
/// is observed about a peer and none is a hidden archetype/hazard.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetentionPrior {
    /// `β`: softness of the retention step `s(r) = sigmoid(β·(r − (1−φ_O)))`.
    /// Larger `β` ⇒ a SHARPER step at the retained-depth edge (closer to a hard
    /// "above the line survives, below it dies"); smaller `β` ⇒ a gentler ramp.
    /// CALIBRATABLE PRIOR.
    pub step_beta: f64,
    /// `standing_scale`: how strongly first-hand capital `G(h←O)` raises the
    /// retained depth. `standing = standing_scale · G(h←O)/(G(h←O)+standing_ref)`
    /// — a saturating map of my OWN service to the holder into a standing in
    /// roughly [0, standing_scale]. More proven service ⇒ the holder keeps more of
    /// my ladder. This sets the DYNAMIC RANGE of φ_O: at full standing the sigmoid
    /// argument is `standing_scale − depth_conservatism`. CALIBRATABLE PRIOR.
    pub standing_scale: f64,
    /// `standing_ref`: the capital scale at which standing is half-saturated.
    /// Larger ⇒ more `G(h←O)` needed before the holder is modeled as keeping my
    /// symbols. Must be `> 0`; non-positive saturates standing to `standing_scale`.
    /// CALIBRATABLE PRIOR.
    pub standing_ref: f64,
    /// `pressure_scale`: how strongly my OWN observed reject/drop history with this
    /// holder lowers the retained depth. `pressure = pressure_scale · drop_frac`,
    /// where `drop_frac` is the fraction of my PoS rounds that FAILED or TIMED OUT
    /// (first-hand evidence the holder is dropping my symbols / is under pressure).
    /// CALIBRATABLE PRIOR.
    pub pressure_scale: f64,
    /// `depth_conservatism`: a fixed PESSIMISTIC offset subtracted inside the φ_O
    /// sigmoid (`φ_O = sigmoid(standing − pressure − depth_conservatism)`). This is
    /// the retention-route ANALOG of [`SurfacePrior::off_sample_inflation`]: when we
    /// are uncertain how deep a holder retains, leaning SHALLOW (under-estimating
    /// retention) is the SAFE side — over-estimating how much a holder keeps is the
    /// dangerous, optimistic direction (it would forecast a symbol as surviving
    /// eviction when it actually gets dropped). A positive offset biases every φ_O
    /// down so the forecast is conservative; standing must EARN retention back over
    /// this floor. `depth_conservatism ≥ 0`. CALIBRATABLE PRIOR — held weakly, the
    /// field re-calibrates it, but its SIGN (≥0, pessimistic) is load-bearing for
    /// the conservative-calibration property (SIM-R1 claim 1).
    pub depth_conservatism: f64,
}

impl Default for RetentionPrior {
    fn default() -> Self {
        // Rough-world start values (held weakly; the field re-calibrates). The
        // SHAPE is the intent, not the magnitudes (sim_plan.md §5.1): a stranger is
        // weakly trusted by default (the conservatism floor stays), but standing
        // raises the retained depth as proven service accrues.
        //  * step_beta = 8.0 → a fairly sharp ι-rank step a few ranks wide.
        //  * standing_scale = 3.7, standing_ref = 6.0 → standing rises from the
        //    stranger floor toward sigmoid(3.7 − 1.5) = sigmoid(2.2) ≈ 0.90 as
        //    G(h←O) grows past the half-saturation reference (Р-2 / A.7: the earlier
        //    0.62 ceiling made deep reciprocity indistinguishable from "a bit above
        //    average"; the requirement is φ_O(deep) ≈ 0.9 ⇒ c_s − c_0 ≈ 2.2), so a
        //    well-served partner keeps much more of the ladder than a stranger.
        //  * pressure_scale = 6.0 → observed drops/timeouts pull φ_O down hard.
        //  * depth_conservatism = 1.5 → the KEPT stranger floor (variant A): with
        //    zero standing and no observed drops, φ_O = sigmoid(−1.5) ≈ 0.18 — a
        //    stranger is weakly trusted by default; standing must EARN retention
        //    back over this floor.
        RetentionPrior {
            step_beta: 8.0,
            standing_scale: 3.7,
            standing_ref: 6.0,
            pressure_scale: 6.0,
            depth_conservatism: 1.5,
        }
    }
}

/// Numerically-stable logistic sigmoid `1/(1+e^{−x})`.
fn sigmoid(x: f64) -> f64 {
    if x >= 0.0 {
        1.0 / (1.0 + (-x).exp())
    } else {
        let e = x.exp();
        e / (1.0 + e)
    }
}

/// The owner's retained DEPTH `φ_O ∈ [0,1]` at a holder: the fraction of the
/// owner's ι-ladder the holder is modeled to keep, from FIRST-HAND signals only.
///
/// ```text
/// standing = standing_scale · G(h←O)/(G(h←O)+standing_ref)   (my proven service)
/// pressure = pressure_scale · drop_frac                       (my observed rejects)
/// φ_O      = sigmoid(standing − pressure − depth_conservatism)
/// ```
///
/// * `standing` rises with `obs.g_holder_from_owner` (`G(h←O)` — MY service to the
///   holder, bilaterally observable and UNFAKEABLE by the holder). A deeply-served
///   partner is kept generously (`φ_O → 1`: the holder retains my whole ladder).
/// * `pressure` rises with the fraction of MY PoS rounds with this holder that
///   FAILED or TIMED OUT **plus the announced/silent DROP events** (C2FARM-3 / A.2):
///   `drop_frac = (fail+timeout+drop_ann+drop_silent) /
///   (pass+fail+timeout+drop_ann+drop_silent)` — my own first-hand evidence the holder
///   is dropping my symbols / is squeezed. Announced (polite) drops barely burn the
///   capital (`b_ann`) but STILL enter this forecast. High observed drops ⇒ `φ_O → 0`
///   (only the very top of my ladder is modeled to survive).
/// * `depth_conservatism` is a pessimistic offset that biases `φ_O` DOWN: when in
///   doubt, model the holder as retaining LESS of my ladder. Over-estimating
///   retention is the dangerous (optimistic) direction — it would forecast a symbol
///   as surviving eviction when it actually gets dropped — so the safe side is to
///   under-estimate depth and let proven `standing` earn it back. This mirrors the
///   surface route's off-sample inflation (under-estimate where uncertain) and is
///   what makes the per-symbol block forecast CONSERVATIVE (SIM-R1 claim 1).
///
/// `φ_O` is a STEADY-STATE snapshot from CURRENT first-hand signals, NOT a
/// trajectory: we do not model how the holder's contention evolves over τ (that
/// would require god-view of the holder's future — an oracle). One φ_O, now.
///
/// Anti-oracle: both inputs are first-hand fields of [`FirstHandObs`]
/// (`g_holder_from_owner`, the PoS counters). There is no hidden archetype/hazard
/// in the signature — the crate boundary makes it compile-impossible.
pub fn retained_depth(obs: &FirstHandObs, retention: &RetentionPrior) -> f64 {
    let g = obs.g_holder_from_owner.max(0.0);
    let standing_ref = retention.standing_ref;
    let standing_sat = if standing_ref > 0.0 {
        g / (g + standing_ref)
    } else {
        1.0
    };
    let standing = retention.standing_scale.max(0.0) * standing_sat;

    // C2FARM-3 (A.2): each announced/silent DROP event is an OBSERVATION of unreliability
    // in the retention forecast — it counts in drop_frac ALONGSIDE the PoS fail/timeouts,
    // even the polite (announced) drops that barely burn the capital (b_ann). The drop
    // counters are LEAKY f64 (транше-4: they fade with λ_drop so one drop is not an eternal
    // penalty), hence added as f64 to the u32 PoS tallies. Default-0.0 counters leave every
    // pre-C2FARM-3 obs bit-identical.
    let drops = (obs.pos_fail + obs.pos_timeout) as f64 + obs.drop_ann + obs.drop_silent;
    let n = (obs.pos_pass + obs.pos_fail + obs.pos_timeout) as f64 + obs.drop_ann + obs.drop_silent;
    let drop_frac = if n > 0.0 { drops / n } else { 0.0 };
    let pressure = retention.pressure_scale.max(0.0) * drop_frac;
    let conservatism = retention.depth_conservatism.max(0.0);

    sigmoid(standing - pressure - conservatism).clamp(0.0, 1.0)
}

/// Eviction-retention probability `s(r ; φ_O, β)` — the chance a symbol at ι-rank
/// `r` survives the holder's eviction, given the retained depth `φ_O`.
///
/// ```text
/// s(r ; φ_O, β) = sigmoid(β · (r − (1 − φ_O)))
/// ```
///
/// `r ∈ [0,1]` is the symbol's ι-RANK within the OWNER's symbols on this holder
/// (0 = the owner's lowest-ι symbol there, 1 = the highest). The step is centred
/// at `1 − φ_O`, the bottom edge of the retained band: symbols ABOVE that edge
/// (`r > 1−φ_O`) are kept (`s → 1`), symbols below it are the first evicted
/// (`s` small). A larger `φ_O` shifts the edge DOWN (more of the ladder retained);
/// `φ_O = 1` ⇒ edge at 0 ⇒ every symbol kept; `φ_O = 0` ⇒ edge at 1 ⇒ only the
/// very top survives. `β` sets the softness of the step.
///
/// `r` is clamped to [0,1] and `φ_O` to [0,1] defensively.
///
/// Anti-oracle: `r` is the owner's OWN ι-rank (first-hand, from the ladder the
/// owner itself declared) and `φ_O` comes from [`retained_depth`] (first-hand). No
/// hidden field enters.
pub fn eviction_retention(r: f64, phi_o: f64, retention: &RetentionPrior) -> f64 {
    let r = r.clamp(0.0, 1.0);
    let phi_o = phi_o.clamp(0.0, 1.0);
    let edge = 1.0 - phi_o; // bottom edge of the retained band, in rank units
    let beta = retention.step_beta;
    sigmoid(beta * (r - edge)).clamp(0.0, 1.0)
}

/// One chosen holder's placement, with the owner's ι-LADDER on that holder and
/// which rung this block's symbol sits at.
///
/// This is the minimal shape that expresses the per-holder ι-ladder the K3
/// per-symbol forecast needs while staying strictly first-hand. The eviction
/// route is ranked WITHIN the owner's symbols on this one holder (the same
/// intra-owner ladder `eviction_order` uses), so the owner must tell the kernel
/// the full set of ι it has placed on this holder, not just this block's symbol.
///
/// Anti-oracle: `obs` carries only [`FirstHandObs`] fields; `ladder_iotas` are the
/// owner's OWN declared importances (first-hand metadata the owner authored); the
/// symbol index is the owner's own bookkeeping. No hidden field is reachable.
#[derive(Debug, Clone, PartialEq)]
pub struct HolderPlacement {
    /// First-hand observation of this holder (surface + standing + pressure
    /// signals).
    pub obs: FirstHandObs,
    /// The owner's full ι-ladder on this holder: the declared importances of ALL
    /// of the owner's symbols stored on this holder (this block's symbol included).
    /// The eviction rank is computed WITHIN this set — the intra-owner ladder.
    pub ladder_iotas: Vec<f64>,
    /// Index into `ladder_iotas` of THIS block's symbol (which rung of my ladder
    /// the symbol I am forecasting sits at). Must be `< ladder_iotas.len()`; an
    /// out-of-range index is treated as the lowest rank (most pessimistic).
    pub symbol_in_ladder: usize,
}

impl HolderPlacement {
    /// The ι-RANK `r ∈ (0,1)` of this block's symbol within the owner's ladder on
    /// this holder, MIDPOINT convention `r = (lower + 0.5) / m` (Р-3 / A.8), where
    /// `lower` is the count of the owner's symbols on this holder with a ι strictly
    /// LOWER than this symbol's (ties share the lower fraction). The bottom rung sits
    /// at `0.5/m`, the top at `(m − 0.5)/m`, and a single-symbol ladder is the
    /// MIDPOINT `0.5` (not `0`). This replaces the earlier `lower/(m−1)` convention,
    /// whose singleton degeneracy (`m=1 → 0`) collapsed the K3 per-symbol keep to
    /// ≤ 0.05 even for an ideal partner, making the K2→K3 replacement numerically
    /// impossible.
    ///
    /// This is the ladder coordinate the eviction-retention route keys on; it is
    /// the owner's own first-hand bookkeeping (its declared ι), never a hidden
    /// field.
    pub fn iota_rank(&self) -> f64 {
        let m = self.ladder_iotas.len();
        if m == 0 {
            return 0.5; // empty ladder is degenerate ⇒ the midpoint
        }
        let my_iota = self
            .ladder_iotas
            .get(self.symbol_in_ladder)
            .copied()
            .unwrap_or(f64::NEG_INFINITY); // out-of-range ⇒ treat as lowest
        let lower = self.ladder_iotas.iter().filter(|&&i| i < my_iota).count();
        // Midpoint rank in (0,1): the fraction of the ladder strictly below me,
        // shifted by half a rung so the bottom sits at 0.5/m and the top at
        // (m−0.5)/m, and a one-rung ladder lands on 0.5.
        (lower as f64 + 0.5) / m as f64
    }
}

/// Per-symbol node-side estimate of a block's survival `R̂(T)`: the probability
/// that at least `k_eff` of the chosen holders keep THEIR symbol intact to `tau`,
/// where each symbol's keep-probability is `surface(h,τ) × s(r ; φ_O, β)` — the
/// K3 two-route model. This REPLACES the K2 per-holder-average estimate with a
/// genuinely heterogeneous per-symbol Poisson-binomial.
///
/// Construction (composes K1/K2):
/// 1. **Per-symbol keep-probability (K3).** For each placement, `p = surface · s`,
///    with `surface = estimate_surface(obs, prior, v_per_symbol, τ).r_hat` (Route
///    A, conservative off-sample lower bound) and
///    `s = eviction_retention(iota_rank, retained_depth(obs), retention)` (Route
///    B, the eviction ladder). Both routes are first-hand. Every placement
///    contributes ONE position, labelled by its observable correlate group
///    ([`bucket_key`]); the estimator does NOT collapse same-group symbols to one
///    best position (that is [`place`]'s job).
/// 2. **A.9 worst-case convolution** ([`group_min_survival`]):
///    `R̂_wc = min(comonotone-within-groups, independent-over-all-symbols)`,
///    correlated inside an observable group and independent between (the same B1
///    worst-case bound the K2 aggregate uses).
///
/// In the ≤1-symbol-per-group regime (what [`place`] produces) `R̂_wc` is
/// bit-identical to the pre-A.9 heterogeneous Poisson-binomial. If fewer than
/// `k_eff` symbols exist in total, `R̂ = 0` (structurally undeliverable).
///
/// Anti-oracle: every input is first-hand `placement` observations + the offline
/// `prior`/`retention` + the owner-private `req`/`policy`. No hidden hazard,
/// archetype, or farm-truth is reachable — surface keys on PoS obs, the eviction
/// route on the owner's OWN `G(h←O)`/reject-history/ι-ranks, the spread on an
/// observable address. Two owners differing ONLY in a hidden archetype produce a
/// BIT-IDENTICAL forecast (there is no field to differ on).
pub fn estimate_block_survival_per_symbol(
    placement: &[HolderPlacement],
    prior: &SurfacePrior,
    retention: &RetentionPrior,
    req: &BlockReq,
    policy: &PlacementPolicy,
) -> f64 {
    if req.k_eff == 0 {
        // No holders needed — vacuously certain.
        return 1.0;
    }
    if placement.is_empty() {
        return 0.0;
    }

    let v_per_symbol = req.volume_per_symbol();
    let tau = req.tau.max(0.0);

    // One position per placement, labelled by its observable correlate group. NO
    // best-per-bucket collapse — the A.9 convolution handles any number of symbols
    // per group; the ≤1/group spread is enforced by `place`, not here.
    let positions: Vec<(BucketKey, f64)> = placement
        .iter()
        .map(|hp| {
            // Route A: holder reliability surface (importance-independent).
            let surface = estimate_surface(&hp.obs, prior, v_per_symbol, tau)
                .r_hat
                .clamp(0.0, 1.0);
            // Route B: eviction-retention at this symbol's ι-rank within my ladder.
            let phi_o = retained_depth(&hp.obs, retention);
            let s = eviction_retention(hp.iota_rank(), phi_o, retention);
            // Independent death routes multiply.
            let p = (surface * s).clamp(0.0, 1.0);
            (bucket_key(&hp.obs, policy), p)
        })
        .collect();

    group_min_survival(&positions, req.k_eff)
}

/// Headroom factor for the per-holder credit ceiling in [`place`]. The A.13 credit
/// read [`credit_limit_from_surface`] needs a finite `v_max`; the cap only ever
/// tests `L < volume_per_symbol`, so any ceiling `≥ volume_per_symbol` is decision-
/// equivalent. We probe up to `4×` the per-symbol ask so the returned `L` also
/// carries a little headroom (useful for diagnostics) without affecting the skip
/// decision. A holder that reliably retains ≥ `volume_per_symbol` at `r_min` is
/// uncapped; one that cannot is skipped (Р-5).
const CREDIT_PLACE_HEADROOM: f64 = 4.0;

/// Place a block: greedily add each symbol to the candidate that MAXIMISES the
/// marginal gain in worst-case block survival `ΔR̂_wc` (A.10 / decision_model §6),
/// SPREAD ≤1 symbol per observable address bucket (§7), under the per-holder credit
/// cap `L(O→h) ≥ volume_per_symbol` (Р-5 / A.13). Stops once `R̂_wc ≥ req.r_target`.
///
/// ## argmax marginal ΔR̂_wc (A.10)
///
/// At every step we pick, among the still-admissible candidates, the one whose
/// addition raises the block's worst-case survival [`estimate_block_survival`] the
/// most. Because the survival of the CURRENT chosen set is a constant at that step,
/// `argmax ΔR̂_wc = argmax R̂_wc(chosen ∪ {cand})`, so we compare the full A.9
/// convolution of `chosen ∪ {cand}` per candidate and keep the best. Ties break to
/// the SMALLEST candidate index — a deterministic rule (no `HashMap`, no clock) that
/// also preserves the worst-case input ordering an adversary scenario (SIM-6)
/// constructs by presenting farm holders first.
///
/// This single principle ABSORBS the old surface-rank sort: with all surfaces equal
/// and ≤1 symbol per independent bucket the marginal gain is identical across fresh
/// buckets, so argmax degenerates to input order and the result is bit-identical to
/// the pre-A.10 "sort by surface, greedily add" path (this is why SIM-6 does not
/// move). Where surfaces DIFFER **and the block already holds ≥ k_eff−1 fresh
/// buckets**, argmax genuinely tracks the block-survival gain rather than a raw
/// per-holder surface — the intended §6 unification.
///
/// CAVEAT (reviewer NOTE-1, транш 2b): while `chosen.len() < k_eff` for `k_eff > 1`,
/// `estimate_block_survival` is a STRUCTURAL ZERO for every candidate (fewer than
/// `k_eff` symbols can never meet the threshold), so all marginals are identically 0
/// and the first `k_eff−1` picks fall to the index tie-break, NOT surface. This is
/// SAFE (the `r_target` floor is still reached whenever the admissible set is feasible;
/// the ≤1/bucket and credit caps hold) but mildly SUB-OPTIMAL: an index-first pick can
/// pull a weaker holder into the mandatory `k_eff` set, costing an extra redundancy
/// slot versus a surface-first pick. Left as the faithful greedy-argmax transcription;
/// revisit if транш 3 layers reciprocity/cream on placement.
///
/// ## Spread by address (§7) — the BLOCK-1 guard replaces the old ≤1/bucket cap (Р-8)
///
/// Р-8 replaces the hard "≤1 symbol per observable bucket" spread with the BLOCK-1
/// guard [`block1_guard_admits`]: no correlate group may become decode-critical (the
/// block must survive losing ANY one group — `addr_subnet` by default, or `master_id`
/// under [`CapMode::MasterIdOnly`]). A candidate in an already-occupied group is
/// admissible only once the block already holds ≥ `k_eff` symbols OUTSIDE that group;
/// a fresh group is always admissible. In the singleton-group substrate (all holders
/// in distinct buckets) every candidate opens a fresh group, so the guard admits
/// EXACTLY the fresh-bucket candidates the old ≤1/bucket cap admitted — the change is
/// neutral there and only lets a genuine multi-holder group carry SAFE intra-group
/// redundancy (guarded so it is never a single point of failure). Under
/// [`CapMode::MasterIdOnly`] a same-subnet farm presents N master-ids → N distinct
/// groups → the guard sees N safe groups (the SIM-6 sign: subnet-spread beats
/// master-spread, unchanged). Cream ([`place_cream`]) is exempt (it keeps its own
/// ≤1/bucket spread, outside the `r_target` count), as under the old cap.
///
/// ## Per-holder credit cap (Р-5 / A.13)
///
/// A candidate whose credit limit `L(O→h) = credit_limit_from_surface(obs, prior,
/// req.r_min, req.tau, v_max)` is below `volume_per_symbol` cannot reliably hold even
/// one symbol at the required per-holder floor `r_min` on the horizon — it is SKIPPED
/// before it can be selected. This is the mandatory consumer A.13 was missing: it
/// stops the owner from asking a holder to keep a per-symbol volume its demonstrated
/// scale cannot vouch for. Setting `req.r_min = 0` disables the cap.
///
/// ## Result
///
/// Returns [`PlacementResult::Placed`] once `R̂_wc ≥ r_target`. If the admissible
/// candidates (fresh bucket AND credit-uncapped) are exhausted first, returns
/// [`PlacementResult::Insufficient`] with the best `R̂` achieved.
///
/// Anti-oracle litmus: the arguments to selection, spread and credit cap are ⊆
/// {surface `r_hat` (from `estimate_surface(F^O)`), `addr_subnet`, `master_id`} plus
/// the owner-private `req` (which carries `ι_own` only as `r_target`/`r_min`). No
/// hidden farm-identity is reachable — it is not a field on [`FirstHandObs`].
pub fn place(
    req: &BlockReq,
    candidates: &[FirstHandObs],
    prior: &SurfacePrior,
    policy: &PlacementPolicy,
) -> PlacementResult {
    let v_per_symbol = req.volume_per_symbol();
    let tau = req.tau.max(0.0);
    // Ceiling for the A.13 credit read: only `L < v_per_symbol` matters, so a finite
    // multiple of the per-symbol ask suffices (see CREDIT_PLACE_HEADROOM).
    let credit_v_max = v_per_symbol * CREDIT_PLACE_HEADROOM;

    // Р-5 per-holder credit cap, computed ONCE per candidate: `L(O→h)` depends only on
    // the holder's own observation, not on the chosen set, so a holder that cannot be
    // trusted with even one symbol's volume at the floor `r_min` on the horizon is
    // inadmissible for the whole placement.
    let credit_ok: Vec<bool> = candidates
        .iter()
        .map(|obs| {
            credit_limit_from_surface(obs, prior, req.r_min, tau, credit_v_max) >= v_per_symbol
        })
        .collect();

    let mut chosen: Vec<usize> = Vec::new();
    let mut chosen_obs: Vec<FirstHandObs> = Vec::new();
    let mut best_r_hat = if req.k_eff == 0 { 1.0 } else { 0.0 };

    loop {
        // Pick the admissible candidate maximising R̂_wc(chosen ∪ {cand}) — i.e. the
        // largest marginal ΔR̂_wc (A.10). Admissible = not already chosen, credit-
        // uncapped (Р-5), and BLOCK-1-guard-admitted (Р-8: opening a fresh group, or
        // ≥ k_eff symbols already outside this candidate's group). Tie-break: smallest
        // index (deterministic; preserves adversary-first ordering).
        let mut best_cand: Option<usize> = None;
        let mut best_cand_r = f64::NEG_INFINITY;
        for cand in 0..candidates.len() {
            if chosen.contains(&cand) {
                continue;
            }
            // Р-5 per-holder credit cap (precomputed).
            if !credit_ok[cand] {
                continue;
            }
            // BLOCK-1 guard (Р-8) replaces the old hard ≤1/bucket skip: admit a
            // same-group candidate only once the block is already safe against losing
            // that group; a fresh group is always admissible (singleton-neutral).
            let key = bucket_key(&candidates[cand], policy);
            let symbols_in_c = chosen_obs
                .iter()
                .filter(|o| bucket_key(o, policy) == key)
                .count() as u64;
            if !block1_guard_admits(symbols_in_c, chosen_obs.len() as u64, req.k_eff as u32) {
                continue;
            }
            // Marginal argmax: R̂_wc of the chosen set WITH this candidate added.
            chosen_obs.push(candidates[cand].clone());
            let r = estimate_block_survival(&chosen_obs, prior, req, policy);
            chosen_obs.pop();
            // Strict `>` with ascending `cand` ⇒ ties keep the smallest index.
            if r > best_cand_r {
                best_cand_r = r;
                best_cand = Some(cand);
            }
        }

        match best_cand {
            Some(cand) => {
                chosen.push(cand);
                chosen_obs.push(candidates[cand].clone());
                best_r_hat = best_cand_r;
                if best_r_hat >= req.r_target {
                    return PlacementResult::Placed {
                        holders: chosen,
                        r_hat_block: best_r_hat,
                    };
                }
            }
            // No admissible candidate left → cannot improve further.
            None => break,
        }
    }

    PlacementResult::Insufficient {
        best_r_hat_block: best_r_hat,
        holders: chosen,
    }
}

/// Rank fresh `candidates` for INCREMENTAL placement given an already-committed holder
/// set — the §9.2 "one symbol per attempt" twin of [`place`] (A.10 / decision_model §6).
///
/// [`place`] builds a whole placement from an EMPTY chosen set, greedily adding the
/// argmax-ΔR̂_wc holder until `R̂_wc ≥ r_target`. A cold, bandwidth-stretched backup (the
/// sim's §9.2 regime, and the daemon's real initial backup) instead already holds SOME
/// symbols of the block and adds ONE more per attempt. This ranks the fresh candidates by
/// exactly the A.10 principle `place` uses — the MARGINAL block-survival gain `ΔR̂_wc`
/// when the candidate is added to the CURRENT (committed) set — but for a SINGLE
/// incremental add rather than an iterated greedy fill:
///
/// * `committed` = the block's holders already storing a symbol (their [`FirstHandObs`]).
///   The chosen set is SEEDED with them, so each candidate's marginal is measured over the
///   REAL current placement. This is what makes the argmax meaningful before `k_eff`
///   symbols exist: once `committed.len() ≥ k_eff` the marginal is non-degenerate — it
///   resolves the structural-zero index-order caveat [`place`] documents for its own first
///   `k_eff−1` picks.
/// * The `committed` holders' observable buckets are PRE-CLOSED (§7 spread ≤1/bucket
///   across committed+fresh) and can never be reopened, so a fresh candidate sharing a
///   committed holder's bucket is never returned (no two symbols of a block in one bucket
///   — the invariant a naïve "feed committed to `place` as ordinary candidates" adapter
///   would break the moment the argmax reordered a committed holder behind a fresh one).
/// * The per-holder credit cap (Р-5 / A.13, [`credit_limit_from_surface`], `req.r_min`)
///   gates every candidate exactly as in [`place`].
/// * There is NO `r_target` stop: the caller's own redundancy policy (the sim's
///   count-based `n_symbols` floor) governs HOW MANY symbols to place; this returns the
///   full ranked walk order so the caller can try candidates through its own holder-side
///   accept gate and place the first that admits.
///
/// **Single-add marginal, not iterated greedy — deliberate (§9.2).** Because the caller
/// places exactly ONE symbol per invocation and re-reads `committed` on the next attempt,
/// the correct per-attempt decision is the argmax over the FIXED committed set (a single
/// [`estimate_block_survival`] per candidate, `O(F)`), not a full iterated greedy fill
/// (`O(F²)`). The two coincide on the first pick (argmax single-add marginal ≡ greedy first
/// pick); across attempts the iterated behaviour is recovered as `committed` grows by one
/// each successful attempt.
///
/// Returns indices into `candidates`, in descending marginal order (ties → smallest index,
/// deterministic), filtered to ≤1 per observable bucket (the best-ranked fresh candidate
/// per fresh bucket). Empty `candidates` ⇒ empty `Vec`.
///
/// Anti-oracle: identical to [`place`] — every input is first-hand `candidates`/`committed`
/// plus the offline `prior` plus the owner-private `req`/`policy`. No hidden farm-identity is
/// reachable (it is not a field on [`FirstHandObs`]).
pub fn place_incremental_rank(
    req: &BlockReq,
    candidates: &[FirstHandObs],
    committed: &[FirstHandObs],
    prior: &SurfacePrior,
    policy: &PlacementPolicy,
) -> Vec<usize> {
    if candidates.is_empty() {
        return Vec::new();
    }
    let v_per_symbol = req.volume_per_symbol();
    let tau = req.tau.max(0.0);
    let r_min = req.r_min.clamp(0.0, 1.0);

    // Buckets already claimed by the committed holders — PRE-CLOSED (§7 ≤1/bucket across
    // committed+fresh; never reopened, so no fresh candidate can double up a bucket).
    let committed_buckets: Vec<BucketKey> =
        committed.iter().map(|o| bucket_key(o, policy)).collect();

    // Marginal score per fresh candidate: R̂_wc(committed ∪ {cand}). Since R̂_wc(committed)
    // is a constant this tick, argmax R̂_wc(committed ∪ {cand}) = argmax ΔR̂_wc (A.10).
    // Credit-capped and committed-bucket candidates are dropped up front.
    let mut scored: Vec<(usize, f64)> = Vec::new();
    let mut ext: Vec<FirstHandObs> = committed.to_vec();
    for (i, obs) in candidates.iter().enumerate() {
        // Р-5 credit cap (`req.r_min == 0` disables it). The A.13 cap `L(O→h) =
        // credit_limit_from_surface(obs, r_min, τ, ·) ≥ v_per_symbol` is — by the
        // monotone-non-increasing r̂(V) that makes the cap a clean interval [0, L] (see
        // [`credit_limit_from_surface`]) — IDENTICAL to `r̂(v_per_symbol, τ) ≥ r_min`, since
        // `L` is the LARGEST V with `r̂(V) ≥ r_min`. We test that equivalent single-eval form
        // rather than inverting the surface 60× for a value we only compare to v_per_symbol:
        // the SAME Р-5 gate, not a weakening (a kernel unit test asserts the equivalence).
        if estimate_surface(obs, prior, v_per_symbol, tau).r_hat < r_min {
            continue;
        }
        // §7: never rank a candidate whose bucket a committed holder already occupies.
        if committed_buckets.contains(&bucket_key(obs, policy)) {
            continue;
        }
        ext.push(obs.clone());
        let r = estimate_block_survival(&ext, prior, req, policy);
        ext.pop();
        scored.push((i, r));
    }

    // Descending marginal, smallest-index tie-break (deterministic — no HashMap/clock).
    scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));

    // ≤1 fresh candidate per observable bucket: keep the best-ranked per bucket (the caller
    // places one symbol per attempt, so a same-bucket runner-up is redundant — this matches
    // the retired place_reciprocal ≤1/bucket walk order the sim replaced).
    let mut out: Vec<usize> = Vec::new();
    let mut occupied: Vec<BucketKey> = Vec::new();
    for (i, _) in scored {
        let bucket = bucket_key(&candidates[i], policy);
        if occupied.contains(&bucket) {
            continue;
        }
        occupied.push(bucket);
        out.push(i);
    }
    out
}

/// A.11: place **cream** — surplus symbols ABOVE the `R_target` floor (decision_model
/// §6 A.11, W9 greed + pair probation).
///
/// Cream is the owner-side twin of the holder-side `V_free` floor (A.14): a node with
/// spare disk/bandwidth greedily backs up EXTRA redundancy beyond what `R_target`
/// requires, because storing more of others' data grows its own reciprocal capacity
/// and because the physics of backup wants maximum redundancy. It is driven by free
/// resources, NOT by a discretionary "budget B" (the §5.3 externality dissolves).
///
/// **Structural guarantees (H4↓ / A.15).** The returned indices are a SEPARATE list,
/// DISJOINT from `chosen_core` — cream is NEVER folded into the core placement. That
/// type-level separation is the guarantee that:
/// * cream is **NOT counted toward `R_target`** (block survival `R̂_wc` and the repair
///   trigger [A.15] read the CORE set only);
/// * **cream deaths MUST NOT trigger repair** (a lost cream symbol is best-effort
///   surplus; the block still meets its floor on the core set).
///
/// **Caps are the SAME as core-place, NOT weakened for cream:**
/// * the §7 address spread is enforced ACROSS core+cream: buckets already occupied by
///   `chosen_core` are CLOSED to cream, and cream itself keeps ≤1 symbol per bucket —
///   the ≤1/risk-group cap is end-to-end;
/// * the per-holder credit cap `L(O→h) ≥ volume_per_symbol` (Р-5 / A.13,
///   [`credit_limit_from_surface`]) gates every cream candidate exactly as in [`place`].
///
/// **Candidate order — TWO ARMS (decision_model §6 A.11).** Cream does not run the
/// core argmax; it fills surplus slots in a deterministic order:
/// * **arm (a): probationary STRANGERS** — candidates with NO pair history at all
///   (`pos_pass + pos_fail + pos_timeout == 0`), in input-index order;
/// * **arm (b): the rest**, in DESCENDING canonical quality (the surface reliability
///   `estimate_surface(...).r_hat` at the per-symbol ask on the horizon — the SAME
///   per-holder signal core's argmax rewards; the kernel `place` folds NO reciprocity,
///   so neither does cream), index tie-break.
///
/// **Strangers-first is a §5½ design decision, NOT formalized by the model** (flagged
/// for reviewer adjudication). It is the ENTRY channel for a NEW pair: cream is how an
/// established node `E` places a symbol onto a newcomer `N`'s empty disk, letting `N`
/// earn reciprocal capital `g_ho` and bootstrap into the network (P3 liveness). A
/// mature, fully-utilised network that always probed its deepest partners first would
/// never probe a stranger, and the P3 entry chain would be dead — so cream deliberately
/// probes strangers BEFORE established partners. A stranger's surface `r̂ → 0`, so
/// WITHOUT this rule arm (b)'s descending-quality sort would place strangers LAST; the
/// two-arm order is what pulls them to the front.
///
/// `want_cream == 0` or empty `candidates` ⇒ an empty `Vec` (never a panic).
///
/// Anti-oracle: identical to [`place`] — selection reads only surface `r̂`, the
/// observable `addr_subnet`/`master_id` bucket, and owner-private `req` fields. No
/// hidden farm-identity is reachable.
pub fn place_cream(
    req: &BlockReq,
    candidates: &[FirstHandObs],
    prior: &SurfacePrior,
    policy: &PlacementPolicy,
    chosen_core: &[usize],
    want_cream: usize,
) -> Vec<usize> {
    if want_cream == 0 || candidates.is_empty() {
        return Vec::new();
    }

    let v_per_symbol = req.volume_per_symbol();
    let tau = req.tau.max(0.0);
    let credit_v_max = v_per_symbol * CREDIT_PLACE_HEADROOM;

    // Buckets already claimed by the CORE placement are CLOSED to cream: the §7 ≤1/bucket
    // spread is enforced end-to-end across core+cream (cap NOT weakened for cream).
    let mut occupied: Vec<BucketKey> = chosen_core
        .iter()
        .filter_map(|&i| candidates.get(i))
        .map(|obs| bucket_key(obs, policy))
        .collect();

    // Two-arm candidate order (A.11 / §6): (a) probationary strangers (zero pair history)
    // in input-index order, then (b) the rest by DESCENDING canon quality. Cream is
    // disjoint from `chosen_core` — core indices are excluded from BOTH arms.
    let mut strangers: Vec<usize> = Vec::new();
    let mut established: Vec<usize> = Vec::new();
    for (i, obs) in candidates.iter().enumerate() {
        if chosen_core.contains(&i) {
            continue; // disjoint with core (structural "not counted toward R_target")
        }
        let no_history = obs.pos_pass == 0 && obs.pos_fail == 0 && obs.pos_timeout == 0;
        if no_history {
            strangers.push(i);
        } else {
            established.push(i);
        }
    }
    // Arm (b): descending canonical quality (surface r̂), smallest-index tie-break —
    // deterministic (`total_cmp`, no `HashMap`, no clock).
    established.sort_by(|&a, &b| {
        let qa = estimate_surface(&candidates[a], prior, v_per_symbol, tau).r_hat;
        let qb = estimate_surface(&candidates[b], prior, v_per_symbol, tau).r_hat;
        qb.total_cmp(&qa).then(a.cmp(&b))
    });

    let mut cream: Vec<usize> = Vec::new();
    for &i in strangers.iter().chain(established.iter()) {
        if cream.len() >= want_cream {
            break;
        }
        let obs = &candidates[i];
        // Р-5 per-holder credit cap (same as core; `req.r_min == 0` disables it).
        if credit_limit_from_surface(obs, prior, req.r_min, tau, credit_v_max) < v_per_symbol {
            continue;
        }
        // §7 spread: skip a candidate whose bucket is already occupied (by core or by an
        // already-chosen cream symbol).
        let bucket = bucket_key(obs, policy);
        if occupied.contains(&bucket) {
            continue;
        }
        cream.push(i);
        occupied.push(bucket);
    }
    cream
}
