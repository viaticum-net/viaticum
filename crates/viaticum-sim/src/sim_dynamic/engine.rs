//! `sim_dynamic` engine — the dynamic time-loop over the god-view world.
//!
//! Each tick (design §6 + §10 + world-v2 §9) runs, in order:
//!   0. **pending evictions** (F2 / D5): kill the pressure/cap symbols NOTICED last tick
//!      (they died at T+1 with the DropNotice head-start, freeing disk now), then
//!      **own-data growth** (§A.2) + **incremental joins** (§9.1: activate nodes whose
//!      seeded `joined_tick` has arrived).
//!   1. **resync placements** (drop dead/departed holders from owners' bookkeeping)
//!      then **place** (kernel `place_incremental_rank` / `place_cream`) under a per-node
//!      **bandwidth budget** `U` (§9.2): ≤ `U/v_per_symbol` symbols placed per node per
//!      tick, ι-priority, the rest carried to later ticks. Holder accept/reject by WILL
//!      × ROOM, with **preemption** under contention (§9 fixes / A.12-2).
//!      **SIM-UNIFICATION:** whether to place at all, and how wide, is decided by the
//!      owner's OWN reliability estimate `R̂` vs its `r_target` ([`block_r_hat`]) — the
//!      daemon's `current_reliability` vs `target_reliability` — NOT by an integer holder
//!      count; `n_symbols` is only the spread cap and metric raw material.
//!   2. **PoS-challenge + capital update** (§9.4 ONE physics + F1/F6): PoS-pass ⟺ the
//!      symbol is alive ∧ the holder SURFACED in the 7-day window (F1/D2) ∧ the owner's
//!      block still has a source (F6/D9 — a `to_restore` victim cannot verify). The A.1
//!      leaky decay is applied to ALL capital pairs each tick (idle/dead pairs drain).
//!   3. **eviction** when `φ < s_soft` via `eviction_order` (§10.G, NOTE1 snapshot):
//!      pressure/cap drops are NOTICED here (F2), killed at the top of the NEXT tick.
//!   4. **churn** — nodes depart by archetype (aggression raises the rate); held
//!      symbols die.
//!
//! Anti-oracle: the kernel is called ONLY through the observer (first-hand). The
//! engine knows archetypes / tiers / join schedule (god-view) but passes them to NO
//! kernel function — it uses them only to drive BEHAVIOUR.

use viaticum_core::constants::MIN_REDUNDANCY;
use viaticum_core::four_r::{
    BlockReq, BurnParams, DepthParams, FirstHandObs, Hysteresis, NodeLocal, PlacementPolicy,
    RetentionCap, RetentionPrior, SurfacePrior, apply_burn, capital_steady_state,
    estimate_block_survival, estimate_surface, eviction_order, kappa_key, place_cream,
    place_incremental_rank, retained_depth, update_depth, update_suspicion, update_v_dem,
};

use crate::generator::Rng;
use crate::sim_adv::scenario::{AdvAction, AdvContext, AdvId};
use crate::sim_dynamic::generator::{
    BlockPlacement, DAYS_PER_TICK, EvictNoticeKind, EvictionEvent, HeldSymbol, Node, OwnBlock,
    PairCapital, PendingEviction, PredEntry, RepairStat, SilentLoss, World,
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
    /// Р-7 (A.14) free retention floor `V_free`, in UNITS of `v_per_symbol`: the kernel
    /// `RetentionCap.v_free` is this × `v_per_symbol` gb. Every owner keeps this much for
    /// free (the retention floor above which the reciprocity tariff `κ_O/c_recip` applies).
    /// **Р-9 (Ilya 2026-07-19): MODEL DEFAULT `0.0`** — a DIAL ("extra, but a pity to throw
    /// away"). The hard-hetero sweep showed a positive V_free does NOT make "the newcomer's
    /// first backup survive" under contention (entry is κ-gated by preemption; V_free is only
    /// a RETENTION floor), and predators still lose to their honest twin at 0 (defence is
    /// v_free-independent: the whitewasher loses harder, the ε-whale is v_free-insensitive). At 0: `V_ret = κ_O/c_recip`, entry = "serve
    /// first" (≈ θ_p/λ). A `> 0` value is an OPTIONAL onboarding-generosity dial (the sim_adv
    /// V_free sweep measures its cost/benefit). NOT a settled canon field value.
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
    /// F2 (D5): pressure evictions now carry a real DropNotice head-start `t_n = DAYS_PER_TICK
    /// = 7` (noticed at T, dies at T+1), so `τ_rep = 14` gives a PARTIAL forgiveness factor
    /// `1 − 7/14 = 0.5` on the b_ann burn — the head-start axis is finally exercised in the
    /// sim (a silent loss and a preemption swap still pass `t_n = 0`, the maximum penalty).
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
    /// Per-symbol erasure count `n` for own-data blocks. **SIM-UNIFICATION: a SPREAD CAP
    /// only** — the widest the mandatory (non-cream) placement phase may spread ONE block
    /// across holders, plus the denominator of the floor-fill metrics. It decides NOTHING
    /// about "place one more symbol or not": that is the R̂-vs-[`DynParams::r_target`]
    /// comparison (`place_own_data`, the daemon's `current_reliability` vs
    /// `target_reliability`). Cream sits ABOVE this cap (`⌈cream_max·ι⌉` more).
    pub n_symbols: usize,
    /// Reconstruction threshold `k_eff`.
    pub k_eff: usize,
    /// **SIM-UNIFICATION: THE decision dial.** The per-block target reliability the owner
    /// places and repairs to: while its OWN first-hand estimate `R̂` ([`block_r_hat`] —
    /// kernel A.9′ [`estimate_block_survival`] over the block's live placements at the
    /// decision horizon `τ = DAYS_PER_TICK`) is BELOW this, the block is "below target"
    /// (repair trigger, detection-gated) and the owner keeps widening the placement; at or
    /// above it the block is done (and becomes cream-eligible). Exactly the daemon's
    /// `current_reliability ≥ target_reliability` gate; before this tranche the sim decided
    /// on an integer holder count and this dial was inert (only ever passed into
    /// [`BlockReq`], which the incremental kernel path does not read).
    ///
    /// CALIBRATED-THEN-FROZEN (anti-Goodhart, sim-unification spec §2): a ROUND number just
    /// below the measured R̂ of the healthy at-cap blocks of the honest_v2 world at a mature
    /// tick over seeds 42-46 — see the frozen default and the
    /// `r_target_calibration_probe_*` dump that froze it. ONE dial, ι-INDEPENDENT.
    /// FOLLOW-UP (deliberately out of scope here): ι-scaling of the target (the daemon maps
    /// importance → `target_reliability`) — a separate dial, a separate tranche.
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
    /// places ABOVE the `r_target` target, ι-prioritized (up to `⌈cream_max·ι⌉`). Cream is
    /// placed with the owner's LEFTOVER per-tick bandwidth once the block's R̂ has REACHED
    /// the target (SIM-UNIFICATION: the gate was "the integer floor is full"), and it is
    /// still NOT counted in the non-cream floor-fill metrics.
    ///
    /// It DOES count toward the owner's reliability estimate R̂ (a live symbol is a live
    /// symbol — erasure decode reads any `k_eff` of them), so unlike before, losing cream
    /// can drop a block below target and thereby trigger a repair. The floor/cream split is
    /// now a placement-BUDGET label (which phase pays for the symbol), not a second class of
    /// reliability.
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
    /// reliability TARGET (SIM-UNIFICATION: below `r_target` on its own R̂ — was: below the
    /// `n_symbols` floor count). `0` ⇒ INSTANT detection (the owner refills the very next
    /// tick, the previous behaviour — bit-identical, no RNG drawn). `> 0` ⇒ LATENT: each
    /// (owner, block) deficit episode gets a SEEDED uniform offset in `[0, max]` ticks
    /// before the owner acts, so a synchronous correlated-holder-death shock is
    /// discovered at spread-out ticks (the crux of the "latency smears the shock"
    /// hypothesis). Applies only to REPAIR (a block that met its target then lost
    /// holders), never to an initial backup (`target_ever_met == false`).
    pub repair_detection_delay_max: u64,
    /// Р-5 (A.13 / §13): per-holder reliability floor `r_min(ι)` fed to the core `place`
    /// credit cap `L(O→h) = max{V : r̂_h(V, τ) ≥ r_min}` ([`credit_limit_from_surface`],
    /// consumed by `place_incremental_rank`/`place_cream`). A SEPARATE §13 handle with its
    /// OWN documented guess `0.5` — NOT derived from `r_target` (transche-2b lesson: coupling
    /// a per-HOLDER floor to the per-BLOCK target conflates two different reliability axes; a
    /// single holder is never asked to reach the whole-block target — that is what erasure
    /// across many holders is for). `0.5` says "a holder must still clear ≥ 50% individual
    /// survival at the per-symbol ask on the horizon to be handed a symbol"; OPEN calibration,
    /// flagged for Ilya. `0` disables the credit cap.
    pub r_min: f64,
    /// METRIC-LAYER handle (transche 0.3): the R̂-calibration OUTCOME horizon `H` in TICKS.
    /// When the prediction log is enabled ([`World::pred_log_enabled`]) the engine logs, at
    /// each successful placement, the node's OWN decision-horizon forecast `R̂_wc` (the same
    /// `estimate_block_survival` the selection acts on, `tau = req.tau = DAYS_PER_TICK`), and
    /// the sim_adv evaluator scores it against the realised outcome "block ≥ `k_eff` live
    /// symbols `H` ticks later" (Brier + reliability/resolution, spec §10 п.7). `H` sets ONLY
    /// the outcome look-ahead — NOT the forecast horizon (a horizon-`H` forecast is degenerate:
    /// the surface's long-τ off-sample conservatism drives r̂ → 0 for every holder given the
    /// one-tick observed window, so it carries no resolution and is repair-blind). Default `26`
    /// (≈ half a year at weekly ticks). Read ONLY on the metric path (gated by
    /// `pred_log_enabled`); it NEVER changes a placement/eviction/PoS decision.
    pub pred_horizon_ticks: u64,
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
            // Р-7 (A.14 / §13): c_recip ≈ 30 days (Ilya).
            c_recip_days: 30.0,
            // Р-9 (Ilya 2026-07-19): V_free DIAL, MODEL DEFAULT 0 ("extra, but a pity to throw
            // away"). V_free does not deliver "first backup survives" under contention (entry
            // κ-gated by preemption; floor is retention-only) and predators lose ≥ as hard at
            // 0 ⇒ it is not load-bearing for defence; a >0 floor is optional onboarding
            // generosity (sim_adv V_free sweep). See `4r_vfree_sweep_spec.md` + ledger Р-9.
            v_free_symbols: 0.0,
            // A.2 / A.5 (транше 4 / §13): §13 defaults (b_max confirmed 1.0 by Ilya
            // 2026-07-07; the rest are OPEN calibration guesses flagged for Ilya).
            burn_b_ann: 0.05,
            burn_b_max: 1.0, // silent total loss zeroes the reliability capital (§13)
            burn_tau_rep: 2.0 * DAYS_PER_TICK, // 14d; F2 pressure drop t_n=7 ⇒ 0.5 forgiveness
            sigma_mu: 1.0 / 14.0, // τ_σ ≈ 2 weeks ≪ τ_g = 60 d
            sigma_j: 0.5,
            lambda_drop: 1.0 / 56.0, // τ ≈ 8 weeks ≈ PoS-window scale ("system forgives")
            n_symbols: 5,
            k_eff: 2,
            // SIM-UNIFICATION: CALIBRATED, then FROZEN (spec §2, anti-Goodhart).
            //
            // MEASURED (`r_target_calibration_probe_dump` on the PRE-unification floor
            // physics, honest_v2 @ tick 130, seeds 42-46): the HEALTHY blocks — those actually
            // sitting at the `n_symbols = 5` non-cream floor, n = 18 pooled — estimate
            // R̂ ∈ [0.9997, 1.0000] (p10 0.9998, median 0.9999), i.e. a failure probability of
            // ≈ 3·10⁻⁴ over the decision horizon. The old fixed floor's redundancy BAR,
            // expressed in the new currency, IS that number. The frozen target is the ROUND
            // value (in log-failure: 10⁻³) just BELOW that cluster: every block healthy under
            // the old physics stays "target met" under the new one, and the bar is not
            // silently lowered.
            // REJECTED alternative 0.99: 30× looser in failure probability, and measurably a
            // different operating point — the whole world thins out (decodable blocks
            // 0.54 → 0.42, undecodable tail 25 → 56 blocks/seed at the horizon). That would
            // have confounded "the decision rule changed" with "the bar dropped".
            // CROSS-CHECK against the DAEMON: `viaticum_core::reliability::target_reliability`
            // maps the sim's block-ι range 0.2…0.8 to 0.9425…0.99991 (log-failure −1.24…−4.06,
            // mid ι = 0.5 ⇒ 0.9978 = −2.65). A single ι-independent −3.0 sits inside that band,
            // nearest its midpoint — so the sim asks for the same order of durability the daemon
            // does at mid importance.
            // CONSEQUENCE (the mechanism, measured): at the world's observed per-holder quality
            // (r̂ ≈ 0.89 ⇒ P(≥2 of 5) = 0.99928) the target needs ≈ 5 symbols — the old width;
            // a clean-record neighbourhood (r̂ = 0.946) reaches it at 4, and a no-history one
            // never does within the cap. QUALITY decides the width now, not the count.
            // (Was 0.90 — an INERT value: nothing on the incremental placement path read it.)
            r_target: 0.999,
            block_volume: 50.0, // F5: ⇒ 25 gb/chunk (source/k_eff) = the observed V0 anchor
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
            bandwidth_u: 20.0, // F5: <1 chunk/tick at 25 gb/chunk ⇒ floored to 1
            cream_enabled: true,
            giver_priority_order: true,
            // Р-2 ACCEPTED ⇒ recalibrated ceiling 0.900 is canon (default kernel prior).
            // `false` is the A/B control that dials back to the pre-Р-2 0.622 baseline.
            recalibrated_retention: true,
            // F3 (D6): silent-loss detection latency = 3 windows (PresumedLost = 3 misses,
            // ≈3+ weeks) is now the DEFAULT — a repair fires only after the owner's PoS
            // cadence notices the deficit, matching the real substrate (the dial stays a
            // dial; `0` still recovers the old instant behaviour for the isolating tests).
            repair_detection_delay_max: 3,
            // Р-5 (A.13 / §13): per-holder credit-cap floor — its OWN handle, guess 0.5,
            // NOT r_target (2b lesson). Was the hard-coded `0.5` in try_place_one_symbol.
            r_min: 0.5,
            // Metric-layer R̂-calibration horizon (transche 0.3): 26 ticks ≈ half a year.
            pred_horizon_ticks: 26,
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
///
/// LEGACY (transche 0.3): this prior fed ONLY the retired `place_reciprocal` ranking. The
/// decisive placement path (kernel `place_incremental_rank` / `place_cream`) folds no
/// reciprocity, so `retention_prior` (and the `recalibrated_retention` dial) no longer
/// affects placement. Retained `pub` for the legacy `place_reciprocal` reference / tests.
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
/// `pub` so the sim_adv predator-metric layer reads the SAME κ_O the cap enforces (no drift).
pub fn depth_params_of(params: &DynParams, v_per_symbol: f64) -> DepthParams {
    DepthParams {
        w_d: params.depth_w_d,
        d_ref: params.depth_ref_days * v_per_symbol,
        g_star: capital_steady_state(v_per_symbol, params.lambda),
    }
}

/// The Р-7 (A.14) holder-side volume cap `V_ret = V_free + κ_O/c_recip` in kernel
/// units: `V_free = v_free_symbols·v_per_symbol` gb, `c_recip = c_recip_days` days.
/// `c_recip ≤ 0` DISABLES the cap ([`RetentionCap::disabled`], WARN-1 guard).
/// `pub` so the sim_adv predator-metric layer reads the SAME cap the eviction enforces.
pub fn retention_cap(params: &DynParams, v_per_symbol: f64) -> RetentionCap {
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
/// ANNOUNCED loss with head-start `t_n` (F2: a pressure drop passes `t_n = DAYS_PER_TICK`,
/// noticed-then-died a tick later; a preemption swap passes `t_n = 0`, an instantaneous
/// displacement). Burns the reliability quantity `G(holder→owner)` (the holder's service TO
/// the owner — the reliability evidence, decision_model §1), bumps the `drop_ann`
/// retention-forecast counter (C2FARM-3), and tallies the event.
///
/// **Both mirror cells are burned (A2 seat-sync fix, 2026-07-19).** `G(holder→owner)` is ONE
/// quantity with TWO god-view copies (§1 local observability; A.14/A.2 = one victim-enforcer
/// ledger): the owner's record `capital[owner][holder].g_oh` (`observe_pair` →
/// `g_owner_from_holder`, feeds the — currently inert — retention FORECAST) AND the transpose
/// `capital[holder][owner].g_ho` (the ENFORCEMENT key: `kappa_key` drives eviction / preemption /
/// the Р-7 V_ret cap on the holder's OWN parked volume). Accrual keeps the two in sync
/// (`pos_and_capital`: `g_oh += a` at `[o][h]`, `g_ho += a` at `[h][o]`), so the burn MUST too —
/// otherwise a drop punishes the (kernel-inert) forecast copy but NOT the enforcement copy, and
/// the dropper's parked data is never actually squeezed (the A2 pre-fix artifact). Same burn
/// FACTOR to both (identical `apply_burn` args ⇒ identical multiplier, so the invariant
/// `g_oh ≡ g_ho^T` is preserved).
///
/// **`depth_ho` is deliberately NOT burned.** A.4 loyalty depth is the SLOW-leaky integral of
/// service; a drop halts FRESH credit (g→0) but the built loyalty drains on its own over
/// `τ_slow ≈ 6 months` — it is not an impulse-erased fact. So a formerly-deep dropper keeps its
/// W10 floor (`w_d·sat(D/d_ref)·g*`) for months while its fast `g_ho` is zeroed at once; the
/// silent/polite gap rides the fast-capital term, which is what A.2 governs.
///
/// `v_held` is `owner`'s alive volume on `holder` BEFORE the drop; `v_lost` is the dropped
/// symbol's volume.
fn apply_announced_burn(
    world: &mut World,
    owner: usize,
    holder: usize,
    v_lost: f64,
    t_n: f64,
    params: &DynParams,
) {
    let v_held = owner_alive_volume_on(world, owner, holder);
    let p = burn_params_of(params);
    // Burn G(holder→owner) on BOTH mirror cells (forecast + enforcement); depth_ho untouched.
    world.capital[owner][holder].g_oh = apply_burn(
        world.capital[owner][holder].g_oh,
        &p,
        true,
        t_n,
        v_lost,
        v_held,
    );
    world.capital[owner][holder].drop_ann += 1.0; // leaky counter (decayed by λ_drop in W2)
    world.capital[holder][owner].g_ho = apply_burn(
        world.capital[holder][owner].g_ho,
        &p,
        true,
        t_n,
        v_lost,
        v_held,
    );
    world.burn_ann_count += 1;
}

/// Per-holder chunk volume (gb) (F5 / D4-leak): `block_volume / k_eff`, NOT `/ n_symbols`.
/// The sim "symbol" reads as a per-holder chunk; decode needs `k_eff` chunks that TOGETHER
/// reconstruct the source, so each chunk carries `source / k_eff` (the `n` placed chunks
/// total `(n/k)·source`). Defaults: `50 / 2 = 25` gb/chunk (was `50 / 5 = 10`).
/// `pub` so the sim_adv predator-metric layer measures the chunk-granularity tolerance.
pub fn v_per_symbol_of(params: &DynParams) -> f64 {
    if params.k_eff > 0 {
        params.block_volume / params.k_eff as f64
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

/// World-v3 phase-1: consult node `node`'s adversary behaviour hook for `tick`. Returns
/// `None` for an HONEST node (no `adv` role) — the honest path never builds a context nor
/// calls a hook, so it stays byte-identical. The hook is handed only a first-hand
/// [`AdvContext`] (its own node id, tick, dials, join tick, declared info-model) — never
/// `&World` (anti-oracle, spec §10 п.14). Reads no RNG.
fn adv_action(world: &World, node: usize, tick: u64) -> Option<AdvAction> {
    let role = world.adv[node].as_ref()?;
    let ctx = AdvContext {
        adv_node: node,
        tick,
        info_model: role.info_model,
        dials: role.dials,
        joined_tick: world.nodes[node].joined_tick,
    };
    Some((role.hook)(&ctx))
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
    let tick = world.tick;

    // (0-) F2 (D5): kill the eviction NOTICES from LAST tick FIRST (the noticed pressure/cap
    // drops die now, T+1, freeing the holder's disk with the DropNotice head-start already
    // banked). Done before growth/placement so this tick sees the freed space.
    apply_pending_evictions(world, params);

    // (0a) own-data growth + (0b) incremental joins (§9.1).
    world.grow_own_data();
    activate_joins(world);

    // (0c) World-v3 A5 (молчащий глубокий): drive the deep node's PRESENCE from its hook — a
    // silent PAUSE (present = false) that stops it serving / repairing / running PoS while leaving
    // its capital and holdings intact. Done AFTER activate_joins (so a returning node's presence is
    // the hook's, not a stale join) and BEFORE growth-consuming placement/PoS/eviction, so a paused
    // owner does NOT repair its eroding parked data (that would mask the depth-floor test). No-op on
    // every non-A5 path (byte-identical): it only ever touches the A5 role's presence.
    adv_pause(world, tick);

    // (1a) resync placements (drop dead) + (1b) bandwidth-limited place (floor + cream).
    resync_placements(world);
    // Repair-storm §7: reset the per-tick repair instrument before the placement pass
    // fills it (owners repairing, detected deficit, symbols repaired this tick).
    world.repair_stat = RepairStat::default();
    // Transche 0.3: placement now runs the KERNEL decision path (`place_incremental_rank` /
    // `place_cream`), which spreads by the observable `policy` bucket — no longer the sim's
    // own `place_reciprocal` heuristic. The retention prior is retired from the decisive path.
    place_own_data(world, params, prior, policy);

    // (2) PoS-challenge sampling + capital update, A.1 decay on all pairs (§9.4).
    pos_and_capital(world, params);

    // (2.5) World-v3 phase-3 A7 (sybil-farm): the COLLUSIVE fake-accrual pass — same-farm sybils
    // accrue mutual served/g_ho WITHOUT real holdings, inflating INTRA-FARM reputation at zero
    // storage cost. Placed AFTER the honest accrual and BEFORE eviction so the fake intra-farm g_ho
    // feeds THIS tick's retention cap, while HONEST cells stay untouched (the farm captures no honest
    // storage from collusion — κ_O is pairwise, no global channel). No-op on the honest path (no
    // colluding A7 role ⇒ byte-identical, the ANCHOR).
    adv_collude_farm(world, params);

    // (3) eviction when φ < s_soft (kernel eviction_order + latch).
    run_eviction(world, params);

    // (3.5) World-v3 A2 (DropNotice-refuser): adversary holders VOLUNTARILY drop a fraction of
    // their foreign holdings — SILENTLY (dies now, next-PoS silent-loss burn) or ANNOUNCED (rides
    // the F2 notice). No-op on the honest path (no adv role ⇒ no RNG, byte-identical).
    adv_voluntary_drops(world);

    // (3.6) World-v3 phase-3 A9 (eclipse × CROWN-1): the ECLIPSE group's synchronous, TIMED drop
    // of the eclipse target's symbols. Placed right after `adv_voluntary_drops` (spec §2.2) —
    // i.e. AFTER the runner applied any Disaster this tick (events fire before `step`) and BEFORE
    // the runner's next restore-window observation, which is the window the damage must land in.
    // Its own pass, not a branch of `adv_voluntary_drops`: that one skips absent owners and
    // carries the A2 anchor. No-op when no eclipse target is set ⇒ byte-identical honest path.
    adv_eclipse_drops(world, params);

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

/// F6 (D9): is `owner`'s block `block_id` source-less (`to_restore`)? A source-less block
/// cannot be PoS-verified by its owner (no source to re-encode), so its symbols run no
/// challenge (no accrual). Unknown block id ⇒ `false` (nothing to gate).
fn block_is_to_restore(world: &World, owner: usize, block_id: usize) -> bool {
    world.nodes[owner]
        .own_blocks
        .iter()
        .find(|b| b.id == block_id)
        .map(|b| b.to_restore)
        .unwrap_or(false)
}

/// A block's ALIVE holders across the network — the ONE scan every block-level read
/// derives from. Returns `(holder_node_idx, is_cream)` in ASCENDING holder order (a
/// deterministic scan; this is the order the kernel's A.9′ correlate grouping sees).
fn alive_block_holders(world: &World, owner: usize, block_id: usize) -> Vec<(usize, bool)> {
    let mut out: Vec<(usize, bool)> = Vec::new();
    for (h, node) in world.nodes.iter().enumerate() {
        if let Some(s) = node
            .holdings
            .iter()
            .find(|s| s.alive && s.owner == owner && s.block == block_id)
        {
            out.push((h, s.cream));
        }
    }
    out
}

/// Per-holder chunk volume (gb) of ONE block — the F5 (D4-leak) rule `volume / k_eff`
/// applied to a SPECIFIC block's volume (blocks differ in size in the hetero / whale
/// worlds, so this is per-block; [`v_per_symbol_of`] is the params-level default).
fn chunk_volume(block_volume: f64, params: &DynParams) -> f64 {
    if params.k_eff > 0 {
        block_volume / params.k_eff as f64
    } else {
        block_volume
    }
}

/// The owner's [`BlockReq`] for one block — the SINGLE construction the R̂ loop
/// ([`block_view`]) and the kernel selection ([`try_place_one_symbol`]) share, so the two
/// read the SAME estimate (one physics, no drift).
///
/// ⚠ `req.volume_per_symbol()` is the KERNEL's `volume / n_symbols`, NOT the sim's F5
/// per-holder chunk `volume / k_eff` — the known phase-C debt (sim-unification spec §1;
/// inert while the queried volume stays below the `v_dem` floor, which it does at the
/// default dials). Carried over UNCHANGED from the pre-unification `try_place_one_symbol`:
/// this tranche neither fixes nor worsens it.
fn block_req(block_volume: f64, params: &DynParams) -> BlockReq {
    BlockReq {
        volume: block_volume,
        n_symbols: params.n_symbols.max(1),
        k_eff: params.k_eff,
        tau: DAYS_PER_TICK,
        r_target: params.r_target,
        // Р-5 (A.13): the per-holder credit-cap floor, the DynParams `r_min` §13 handle
        // (guess 0.5, NOT derived from r_target — 2b lesson). Consumed by the kernel place.
        r_min: params.r_min,
    }
}

/// SIM-UNIFICATION: the owner's FIRST-HAND view of one own block's CURRENT placement — the
/// input of the R̂-vs-target decision (repair trigger AND placement width).
struct BlockView {
    /// The block's ALIVE holders as [`FirstHandObs`], built through EXACTLY the observer
    /// path [`try_place_one_symbol`] uses for its `committed` set (same ascending-holder
    /// order, same F5 per-chunk volume anchor `v0 = block_volume / k_eff`).
    ///
    /// **CREAM INCLUDED.** Erasure decode does not know the floor/cream label (any `k_eff`
    /// symbols reconstruct), and the daemon's `current_reliability` counts every live
    /// placement — so the owner's own reliability estimate counts them all. One currency,
    /// no second class of symbol. (Consequence, documented: a cream death now lowers R̂ and
    /// CAN therefore trigger a repair — the pre-unification "cream never triggers repair"
    /// bookkeeping rule does not survive one-reliability-currency. The floor/cream split
    /// survives as the placement BUDGET label: the cream phase is what places above target.)
    obs: Vec<FirstHandObs>,
    /// The block's [`BlockReq`] ([`block_req`]).
    req: BlockReq,
    /// Alive NON-cream holders. Decides NOTHING any more: it survives as the `n_symbols`
    /// SPREAD CAP counter (how wide the mandatory phase may spread one block) and as the
    /// raw material of the floor-fill metrics.
    floor: usize,
    /// Alive CREAM holders — the `⌈cream_max·ι⌉` budget counter of the cream phase.
    cream: usize,
}

/// Build the [`BlockView`] of `owner`'s own block at `block_pos` (ONE holder scan).
fn block_view(world: &World, owner: usize, block_pos: usize, params: &DynParams) -> BlockView {
    let block = &world.nodes[owner].own_blocks[block_pos];
    let block_id = block.id;
    let block_volume = block.volume;
    let holders = alive_block_holders(world, owner, block_id);
    let floor = holders.iter().filter(|(_, c)| !*c).count();
    let cream = holders.len() - floor;
    let nodes: Vec<&Node> = holders.iter().map(|&(h, _)| &world.nodes[h]).collect();
    let caps: Vec<&PairCapital> = holders
        .iter()
        .map(|&(h, _)| &world.capital[owner][h])
        .collect();
    let obs = observer::observe_candidates(
        &nodes,
        &caps,
        DAYS_PER_TICK,
        chunk_volume(block_volume, params),
    );
    BlockView {
        obs,
        req: block_req(block_volume, params),
        floor,
        cream,
    }
}

/// The DAEMON's minimum redundancy, in the sim's units: a block is never placed thinner than
/// `k_eff + MIN_REDUNDANCY` symbols, bounded by the `n_symbols` spread cap.
///
/// **Spec deviation, deliberate — SIM-UNIFICATION `4r_sim_unification_spec.md` §1 says the
/// integer floor leaves the decisions entirely.** The daemon it unifies with does NOT decide
/// on reliability alone: `viaticum_core::reliability::solve_n_for_target` searches
/// `n ∈ [k_eff + MIN_REDUNDANCY, k_eff·MAX_OVERHEAD_FACTOR]` for the smallest `n` reaching the
/// target, i.e. its width is `max(k_eff + MIN_REDUNDANCY, target-width)` — the constant's own
/// doc: *"Ensures at least 2 parity symbols regardless of trust or importance. Prevents
/// n == k_eff which would give zero fault tolerance."* A sim that omitted that half would model
/// a protocol we do not run: at a lower target (the `r_target` sweep dial) it would hand out
/// `k_eff + 1` placements the daemon can never produce. AC-1 still holds literally: `n_symbols`
/// (the spread cap) participates in no "place one more?" decision — this floor is derived from
/// `k_eff`, the erasure threshold.
///
/// **INERT at the frozen dials, deliberately kept.** With `k_eff = 2` the floor is 4, and the
/// frozen `r_target = 0.999` already needs ≥ 4 symbols at ANY reachable holder quality (the
/// 8-sample PoS window caps the per-holder surface near `r̂ = 0.946, so three symbols reach only
/// 0.9914). It binds when the target is swept down — see
/// `placement_never_goes_below_the_daemon_minimum_redundancy`. It is NOT the fix for the A16
/// `dr_battle` margin finding (measured: adding it changed that victim's per-block holder counts
/// not at all — those blocks are BELOW target and starving on bandwidth, not stopped by the rule).
fn min_width(params: &DynParams) -> usize {
    (params.k_eff + MIN_REDUNDANCY as usize).min(params.n_symbols)
}

/// The SYMBOL-unit repair demand of ONE detected below-target block, as a strict LOWER
/// BOUND (god-view instrumentation only — the placement loop never reads it).
///
/// The R̂ loop discovers the true width by placing symbols one at a time, so "how many
/// symbols does this block need" is not a quantity the owner computes. What the block's
/// ENTRY state does pin down is the minimum number of loop iterations: the block is below
/// target, so the loop runs at least once; the `alive < min_width` clause forces at least
/// `min_width − alive` more; and the `n_symbols` spread cap allows at most
/// `n_symbols − floor`. Hence `min(max(1, min_width − alive), n_symbols − floor)`, and `0`
/// when the cap is already full (the loop cannot run at all).
///
/// It is a LOWER bound because reaching `r_target` on weak holders can take many more
/// symbols than `min_width` — see [`RepairStat::detected_demand_symbols_lb`] for how to
/// read a demand-vs-bandwidth comparison built on it.
///
/// `alive` = the block's alive holders CREAM INCLUDED (`BlockView::obs.len()`, the unit the
/// `min_width` clause is written in); `floor` = its alive NON-cream holders (the unit the
/// `n_symbols` spread cap counts in). Passing them as scalars keeps the bound testable
/// without a hand-built world.
fn repair_demand_lower_bound(alive: usize, floor: usize, params: &DynParams) -> usize {
    let headroom = params.n_symbols.saturating_sub(floor);
    if headroom == 0 {
        return 0; // the spread cap is full — this tick places nothing for the block
    }
    min_width(params).saturating_sub(alive).max(1).min(headroom)
}

/// SIM-UNIFICATION: the owner's OWN first-hand estimate `R̂` that its block at `block_pos`
/// survives the decision horizon (`tau = DAYS_PER_TICK`), over the block's CURRENT alive
/// placements — the kernel A.9′ [`estimate_block_survival`]. THE decision quantity of the
/// placement loop: repair fires while `R̂ < r_target`, width stops when `R̂ ≥ r_target`
/// (the daemon's `current_reliability` vs `target_reliability`, sim-unification spec §1).
///
/// Anti-oracle: every input is the owner's own first-hand pair capital + the holders'
/// observable address facts (the same `observe_*` path the kernel selection uses) — it is
/// NOT a god-view survival probability. `pub` so the calibration probe / evaluator can read
/// the very number the owner acts on.
pub fn block_r_hat(
    world: &World,
    owner: usize,
    block_pos: usize,
    params: &DynParams,
    prior: &SurfacePrior,
    policy: &PlacementPolicy,
) -> f64 {
    let view = block_view(world, owner, block_pos, params);
    estimate_block_survival(&view.obs, prior, &view.req, policy)
}

/// (1b): each present owner backs up its own blocks under a per-tick bandwidth budget
/// (§9.2), FLOOR first (ι-priority) then CREAM with leftover bandwidth (§9.3). Owner
/// processing order is the accept-toggle proxy (§9.5). Uses the kernel retention forecast
/// for reciprocity-aware ranking.
fn place_own_data(
    world: &mut World,
    params: &DynParams,
    prior: &SurfacePrior,
    policy: &PlacementPolicy,
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

        // FLOOR phase (SIM-UNIFICATION): the owner decides on its OWN reliability estimate
        // R̂ ([`block_r_hat`], kernel A.9′ over the block's CURRENT alive placements) versus
        // its target — exactly as the daemon compares `current_reliability` to
        // `target_reliability` — NOT on an integer holder count. `n_symbols` survives ONLY
        // as the SPREAD CAP (how wide the mandatory phase may spread one block) and as
        // metric raw material; it decides nothing about "place one more or not".
        // Repair-storm §7 detection gate: a block that ALREADY met its target but has now
        // dropped below it (a REPAIR after a holder death) is only refilled once the
        // owner has NOTICED the loss — instantly (delay_max=0) or after a seeded per-block
        // cadence offset (latent). An INITIAL backup (never met target) has no latency.
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
            let view = block_view(world, owner, bp, params);
            let mut r_hat = estimate_block_survival(&view.obs, prior, &view.req, policy);
            if r_hat >= params.r_target {
                // Target met (or over): mark reached, clear any deficit episode.
                let b = &mut world.nodes[owner].own_blocks[bp];
                b.target_ever_met = true;
                b.target_deficit_since = None;
                continue;
            }
            // Below target. Repair (met target before) is detection-gated; a first backup
            // (target_ever_met == false) is always eligible (no PoS-detection latency).
            let is_repair = world.nodes[owner].own_blocks[bp].target_ever_met;
            let detected = if is_repair && params.repair_detection_delay_max > 0 {
                let since = *world.nodes[owner].own_blocks[bp]
                    .target_deficit_since
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
                // Redefined honestly (sim-unification spec §1): ONE per detected
                // below-target block. The old `n_symbols − floor` symbol deficit is not a
                // quantity this loop computes any more (how many symbols a block needs is
                // discovered by placing them, one R̂ recompute at a time) — so the SYMBOL
                // demand is recorded next to it as a documented lower bound
                // ([`repair_demand_lower_bound`]), keeping the storm's demand-vs-bandwidth
                // comparison in one unit. Both are counted BEFORE the budget check below:
                // demand is what the tick OWES, not what the bandwidth let through.
                world.repair_stat.detected_blocks_below_target += 1;
                world.repair_stat.detected_demand_symbols_lb +=
                    repair_demand_lower_bound(view.obs.len(), view.floor, params);
                owner_repaired = true;
            }
            if !detected || budget == 0 {
                continue; // loss not yet noticed, or no upload budget left this tick
            }
            // Widen the placement until the owner's OWN estimate clears the target AND the
            // daemon's minimum redundancy is covered — or the spread cap / bandwidth runs out.
            // The cap counts NON-CREAM holders (verbatim the pre-unification floor counter):
            // cream sits ABOVE the mandatory spread, so it must not squat a cap slot a repair
            // needs. The `min_width` clause mirrors `solve_n_for_target`'s `min_n` (see
            // [`min_width`]); the TRIGGER above stays purely R̂-vs-target, exactly as the
            // daemon's satisfaction check is purely `current_reliability ≥ target_reliability`.
            let min_w = min_width(params);
            let mut alive = view.obs.len();
            let mut floor = view.floor;
            while budget > 0
                && floor < params.n_symbols
                && (r_hat < params.r_target || alive < min_w)
            {
                match try_place_one_symbol(world, owner, bp, false, params, prior, policy) {
                    // The placement returns the block's R̂ AFTER the new symbol — the same
                    // kernel estimate, recomputed incrementally over the real placement
                    // (no full world re-sweep).
                    Some(r) => {
                        budget -= 1;
                        floor += 1;
                        alive += 1;
                        r_hat = r;
                        if is_repair {
                            world.repair_stat.symbols_repaired += 1;
                        }
                    }
                    None => break, // no admissible holder this tick for this block
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
                let view = block_view(world, owner, bp, params);
                let mut cream = view.cream;
                if cream >= cream_target {
                    continue; // cream budget already spent (skips the R̂ cost too)
                }
                // SIM-UNIFICATION: cream is redundancy ABOVE the target, so the gate is the
                // owner's own R̂ ≥ target — the same estimate the floor phase acts on (was:
                // the integer floor count). Same semantics ("over-the-floor"), one currency.
                if estimate_block_survival(&view.obs, prior, &view.req, policy) < params.r_target {
                    continue; // target not yet met → no cream for this block yet
                }
                while budget > 0 && cream < cream_target {
                    if try_place_one_symbol(world, owner, bp, true, params, prior, policy).is_some()
                    {
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
/// admissible holder (§9.2 per-symbol placement). Transche 0.3: the OWNER-SIDE selection
/// now runs the shared KERNEL decision path — [`place_incremental_rank`] (A.10 argmax
/// marginal ΔR̂_wc over the block's CURRENT holders) for the floor, [`place_cream`]
/// (strangers-first, §5½) for cream — instead of the retired `place_reciprocal` heuristic.
/// It walks the ranked candidates through the HOLDER-side accept/preemption gate
/// ([`admit_offer`], unchanged — acceptance is holder policy, placement is owner policy);
/// on the first acceptance it records the god-view holding + placement (flagged `cream`),
/// appends the R̂-calibration prediction (metric-only, gated), and returns
/// `Some(R̂ after this placement)`. `None` ⇒ no admissible holder accepted.
///
/// **The returned R̂ is the caller's loop variable (SIM-UNIFICATION).** It is the SAME
/// kernel `estimate_block_survival` over the block's holders INCLUDING the symbol just
/// placed that the R̂-calibration log records — computed once, read by both — so the
/// width loop advances its estimate incrementally without a second (drifting) estimator
/// and without re-sweeping the world.
///
/// **Incrementality / bandwidth (§9.2), unbroken.** The sim still places ONE symbol per
/// call and re-reads the block's holders each call; the caller's R̂-vs-target loop, the
/// `n_symbols` spread cap and the per-tick upload budget govern HOW MANY symbols land and
/// WHEN. The kernel only governs WHICH holder — the block's already-placed holders are
/// passed to the kernel as the `committed` set, so each candidate's marginal ΔR̂_wc is
/// measured over the real current placement (the incremental adapter; see
/// [`place_incremental_rank`]).
fn try_place_one_symbol(
    world: &mut World,
    owner: usize,
    block_pos: usize,
    cream: bool,
    params: &DynParams,
    prior: &SurfacePrior,
    policy: &PlacementPolicy,
) -> Option<f64> {
    let n = world.nodes.len();
    let tick = world.tick;
    let block_id = world.nodes[owner].own_blocks[block_pos].id;
    let block_iota = world.nodes[owner].own_blocks[block_pos].iota;
    let block_volume = world.nodes[owner].own_blocks[block_pos].volume;
    // F5 (D4-leak): the per-holder chunk carries `source / k_eff` (decode needs k_eff
    // chunks together reconstructing the source), NOT `source / n_symbols`. The SAME
    // [`chunk_volume`] the R̂ loop's [`block_view`] anchors its obs at (one construction).
    let v_per_symbol = chunk_volume(block_volume, params);

    // Holders already storing this block = the kernel `committed` set (§7 spread: the kernel
    // pre-closes their observable buckets, ≤1 symbol per bucket per block, no separate
    // `occupied` tracking needed — the observable bucket is derived from `addr_subnet`).
    let mut already: Vec<usize> = Vec::new();
    for (h, node) in world.nodes.iter().enumerate() {
        if node
            .holdings
            .iter()
            .any(|s| s.alive && s.owner == owner && s.block == block_id)
        {
            already.push(h);
        }
    }
    let mut cand_idx: Vec<usize> = (0..n)
        .filter(|&h| h != owner && world.nodes[h].present && !already.contains(&h))
        .collect();
    if cand_idx.is_empty() {
        return None;
    }
    // Shuffle the candidate order per (owner, block, attempt) — attempts differ via the
    // already-placed count so successive symbols of the same block do not tie-order the
    // same way. Deterministic in the seed. This shuffle is the kernel argmax's index
    // tie-break order (structural-zero picks fall to it, exactly as core `place`).
    shuffle(
        &mut cand_idx,
        world.seed,
        owner as u64,
        (tick << 20) ^ (block_pos as u64),
        already.len() as u64,
    );

    let cand_nodes: Vec<&Node> = cand_idx.iter().map(|&h| &world.nodes[h]).collect();
    let caps: Vec<&PairCapital> = cand_idx.iter().map(|&h| &world.capital[owner][h]).collect();
    let cand_obs = observer::observe_candidates(&cand_nodes, &caps, DAYS_PER_TICK, v_per_symbol);
    drop(cand_nodes);
    drop(caps);
    // The block's current holders as first-hand obs — the kernel `committed` set (marginal
    // baseline) AND the block's holder set for the R̂-calibration prediction log.
    let already_nodes: Vec<&Node> = already.iter().map(|&h| &world.nodes[h]).collect();
    let already_caps: Vec<&PairCapital> =
        already.iter().map(|&h| &world.capital[owner][h]).collect();
    let already_obs =
        observer::observe_candidates(&already_nodes, &already_caps, DAYS_PER_TICK, v_per_symbol);
    drop(already_nodes);
    drop(already_caps);

    // The SAME [`block_req`] construction the R̂ loop uses (one physics, no drift).
    let req = block_req(block_volume, params);

    // Kernel selection (transche 0.3). FLOOR: argmax marginal ΔR̂_wc over the committed set;
    // CREAM: strangers-first. Both return LOCAL candidate indices (into `cand_obs`), ≤1 per
    // observable bucket, credit-capped, with committed buckets pre-closed.
    let ranked: Vec<usize> = if cream {
        // `place_cream` seeds its occupied buckets from `chosen_core` (indices into ITS
        // candidate slice), so present a COMBINED slice [committed ++ fresh] and mark the
        // committed prefix as core; the returned fresh picks (index ≥ committed.len()) map
        // back to `cand_obs`. This keeps the §7 spread end-to-end across core+cream and the
        // strangers-first entry channel (§5½). `want_cream = cand_idx.len()` ⇒ the full
        // walk order (the caller places one, but may need retries when a holder rejects).
        let a = already_obs.len();
        let mut combined: Vec<FirstHandObs> = already_obs.clone();
        combined.extend(cand_obs.iter().cloned());
        let core: Vec<usize> = (0..a).collect();
        place_cream(&req, &combined, prior, policy, &core, cand_idx.len())
            .into_iter()
            .filter_map(|j| j.checked_sub(a)) // drop any core pick (none expected); to cand_obs idx
            .collect()
    } else {
        place_incremental_rank(&req, &cand_obs, &already_obs, prior, policy)
    };

    // R̂-calibration (metric-only, gated): whether to log the placement forecast this run.
    let log_pred = world.pred_log_enabled;

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
            // The block's OWN DECISION-horizon R̂_wc AFTER this placement (over the block's
            // current holders) — the SAME kernel A.9 forecast the selection acts on
            // (`tau = req.tau = DAYS_PER_TICK`). SIM-UNIFICATION: computed UNCONDITIONALLY
            // now, because it is the caller's width-loop variable; the R̂-calibration log
            // (metric-only, gated) records THIS number rather than a second estimate.
            // Neither path draws RNG, so the gating still leaves every decision identical.
            //
            // On the log semantics (unchanged): we log the DECISION forecast, NOT a
            // horizon-`H` recompute — at `tau = H·DAYS_PER_TICK` the surface's long-τ
            // off-sample conservatism drives r̂ → 0 for every holder (observed window is one
            // tick), so a horizon-matched forecast is degenerate (all ≈ 0, no resolution)
            // AND repair-blind; the decision R̂ is what the node acts on, and calibration
            // scores IT against the realised medium-term persistence at `+H`.
            let mut placement_obs = already_obs.clone();
            placement_obs.push(cand_obs[local].clone());
            let r_hat = estimate_block_survival(&placement_obs, prior, &req, policy);
            if log_pred {
                // WARN-1: mark whether the block reached k_eff symbols AT this forecast.
                // Below k_eff the A.9 convolution is a structural zero (r_hat == 0.0 always),
                // so the forecast carries no information; the Brier judge scores only complete rows.
                let floor_complete = placement_obs.len() >= params.k_eff;
                world.pred_log.push(PredEntry {
                    owner,
                    block: block_id,
                    tick,
                    r_hat,
                    floor_complete,
                });
            }
            // Anti-oracle: `r_hat` is the OWNER's own first-hand estimate (the same one the
            // kernel selection ranked on), not a god-view survival probability.
            return Some(r_hat);
        }
    }
    None
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
    // WILL: seeded Bernoulli on the accept rate. World-v3: an adversary HOLDER's hook may
    // OVERRIDE the archetype rate (A1 ε-give serves ~5%); an honest holder uses its
    // archetype willingness UNCHANGED (adv_action → None for honest nodes, so the RNG draw
    // and threshold are byte-identical to the pre-adv path).
    let action = adv_action(world, holder, tick);
    // World-v3 phase-3 A15 (incumbent-enclosure): a cartel HOLDER hard-rejects an owner it has
    // low reciprocity with — `capital[owner][holder].g_ho` below the cartel's `enclose_thresh`
    // (a NEWCOMER that has not yet served the cartel). The hook only sets the FLAG (first-hand);
    // the g_ho comparison is applied ENGINE-side on the holder's OWN bilaterally-observable pair
    // capital (the same anti-oracle split as A6's `discriminate`, and g_ho is genuinely
    // first-hand — no god-view). `enclose_newcomers` is `false` for every honest / non-A15
    // holder, so this branch is skipped and the accept-gate stays BYTE-IDENTICAL to the pre-A15
    // path (the ANCHOR). Placed before the willingness draw: the draw is a per-(owner,holder,tick)
    // DERIVED stream, so skipping it here perturbs no other cell's RNG (determinism preserved).
    if let Some(a) = action
        && a.enclose_newcomers
    {
        let thresh = world.adv[holder]
            .as_ref()
            .map(|r| r.dials.enclose_thresh)
            .unwrap_or(0.0);
        if world.capital[owner][holder].g_ho < thresh {
            return false; // enclosure: the cartel shuts its door on the unreciprocated newcomer
        }
    }
    let accept_rate = action
        .and_then(|a| a.accept_rate)
        .unwrap_or_else(|| world.nodes[holder].archetype.willing_accept_rate());
    let mut rng = Rng::derive(world.seed, ACCEPT_TAG, owner as u64, holder as u64, tick);
    if rng.unit() >= accept_rate {
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
    // includes it). A preemption is an INSTANTANEOUS displacement (the swap makes room
    // right now to accept the new offer), so `t_n = 0` (no head-start) — unlike a pressure
    // drop's noticed→T+1 DropNotice (F2).
    apply_announced_burn(world, vo, holder, v_vol, 0.0, params);
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

/// LEGACY (transche 0.3): the pre-0.3 sim-OWN reciprocity-aware placement heuristic,
/// RETIRED from the decisive path (replaced by the shared kernel `place_incremental_rank` /
/// `place_cream`). It is kept, NOT deleted, as a test-only reference of the retired
/// behaviour — the `place_reciprocal_prefers_reciprocal_holder_and_caps_one_per_bucket`
/// legacy test still exercises it — and to document what the sim traded away: it ranked by
/// `surface · retained_depth(obs)` (folding in `g_holder_from_owner`, so a holder we already
/// serve outranked a stranger of equal surface), a reciprocity fold the kernel `place`
/// deliberately does NOT do (initial placement is pure survival-maximisation; reciprocity is
/// enforced holder-side — eviction κ_O, preemption, the Р-7 cap). Consequently the
/// `reciprocal_placement` and `recalibrated_retention` dials no longer affect the decisive
/// placement ranking after 0.3 (they only fed THIS function). `#[allow(dead_code)]`: unused
/// in the production build, live only under `#[cfg(test)]`.
///
/// Ranks holders by the per-symbol keep-probability `surface · retained_depth(obs)`, greedily
/// admits ≤1 per observable address bucket (§7 spread, starting from `occupied_init`), filling
/// to `want`. `reciprocal = false` recovers pure-surface. Returns chosen LOCAL indices.
///
/// Anti-oracle: reads only first-hand `cand_obs`; strength is the `RetentionPrior`
/// (default or recalibrated), not a magic weight.
#[allow(dead_code)]
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
            // Silent: announced = false ⇒ b_max, t_n = 0. A total loss (V_lost = V_held). Burn
            // G(holder→owner) on BOTH mirror cells (owner forecast `g_oh` + the enforcement
            // transpose `g_ho` — see `apply_announced_burn`; depth_ho NOT burned).
            world.capital[owner][holder].g_oh = apply_burn(
                world.capital[owner][holder].g_oh,
                &bp,
                false,
                0.0,
                volume,
                volume,
            );
            world.capital[owner][holder].drop_silent += 1.0; // leaky (decayed by λ_drop in W2)
            // σ jump (pure, dt = 0 — the sweep already decayed σ this tick).
            world.capital[owner][holder].sigma = update_suspicion(
                world.capital[owner][holder].sigma,
                true,
                0.0,
                params.sigma_mu,
                params.sigma_j,
            );
            world.capital[holder][owner].g_ho = apply_burn(
                world.capital[holder][owner].g_ho,
                &bp,
                false,
                0.0,
                volume,
                volume,
            );
            world.burn_silent_count += 1;
        }
    }

    // Collect challenges (owner, holder, volume, surfaced) over alive holdings whose OWNER
    // is still PRESENT (a departed owner runs no PoS challenge) AND whose block still has a
    // SOURCE (F6 / D9: a `to_restore` block's owner cannot re-encode to verify —
    // CannotVerify, no trust event, no accrual — so the DR victim does not bank g/served
    // until the block is restored).
    struct Challenge {
        owner: usize,
        holder: usize,
        volume: f64,
        holder_surfaced: bool,
    }
    let mut challenges: Vec<Challenge> = Vec::new();
    for holder in 0..n {
        if !world.nodes[holder].present {
            continue;
        }
        // F1 (D2 / rebase §6): a PoS challenge PASSES iff the holder SURFACED at least once
        // in the 7-day window — not merely the per-tick online Bernoulli. Computed ONCE per
        // holder (per-holder event, not per-symbol). Routed through `node_surfaced_in_window`,
        // which honors an opt-in phase-2a uptime profile (a Seasonal pause > window finally
        // misses PoS) and falls through to the EXACT `surfaced_in_window` when the holder has
        // no profile — byte-identical on the honest path.
        let h_surfaced = world.node_surfaced_in_window(holder, tick);
        for s in world.nodes[holder].holdings.iter().filter(|s| s.alive) {
            if !world.nodes[s.owner].present {
                continue; // departed owner: no challenge, no served accrual
            }
            // F6 (D9): source-less block ⇒ owner cannot verify ⇒ no challenge at all.
            if block_is_to_restore(world, s.owner, s.block) {
                continue;
            }
            challenges.push(Challenge {
                owner: s.owner,
                holder,
                volume: s.volume,
                holder_surfaced: h_surfaced,
            });
        }
    }

    // A.5 (транше-4 fix): pairs whose holder TIMED OUT this tick (holder offline). Each
    // gets ONE weak σ jump `j_σ/5` below — per PAIR, not per symbol (a holder with 3 of an
    // owner's symbols is one timeout event, not three). BTreeSet ⇒ deterministic.
    let mut timed_out_pairs: std::collections::BTreeSet<(usize, usize)> =
        std::collections::BTreeSet::new();

    for c in &challenges {
        // F1 (D2): pass ⟺ the holder SURFACED in the 7-day window (the symbol is alive by
        // construction). A NON-surfacing (missed the whole window) is the timeout — the same
        // σ-timeout / miss semantics as before, on the window probability now.
        let passed = c.holder_surfaced;
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
            v_per_symbol,
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

        // F2 (D5): eviction NOTICES this tick (a DropNotice is sent). The symbols stay ALIVE
        // this tick and die at T+1 (`apply_pending_evictions`), so space frees one tick late
        // (the accepted latch lag) and the b_ann head-start axis is exercised. `freed` tracks
        // the volume already noticed (pending death) so the pressure loop's stop condition is
        // the PROJECTED φ (assuming the noticed symbols are gone), not the current φ — else it
        // would notice EVERY pressure target (φ never recovers within the tick).
        let mut freed = 0.0f64;

        // Р-7 cap_drops FIRST, UNCONDITIONALLY (tariff enforcement — NOT gated on the
        // φ-target; the excess above V_ret leaves regardless of how much room it frees).
        // CapTrim kind ⇒ burn-EXEMPT + drop-counter-EXEMPT at death (транше-4 fix): a
        // cap-trim is a predictable tariff, not a reliability signal.
        for (owner_idx, block) in cap_targets {
            if let Some(v) =
                notice_eviction(world, holder, owner_idx, block, EvictNoticeKind::CapTrim)
            {
                freed += v;
                any_eviction_this_tick = true;
            }
        }

        // THEN the pressure drops, stopping once the PROJECTED φ (current free + volume
        // already noticed-for-death) has recovered to s_target. Pressure kind ⇒ burns g_oh at
        // b_ann with the `t_n = DAYS_PER_TICK` head-start + bumps drop_ann at death.
        for (owner_idx, block) in pressure_targets {
            let disk_cap = world.nodes[holder].disk_cap;
            let projected_phi = if disk_cap <= 0.0 {
                0.0
            } else {
                ((disk_cap - (world.nodes[holder].used_total() - freed)) / disk_cap).clamp(0.0, 1.0)
            };
            if projected_phi >= params.hyst.s_target {
                break;
            }
            if let Some(v) =
                notice_eviction(world, holder, owner_idx, block, EvictNoticeKind::Pressure)
            {
                freed += v;
                any_eviction_this_tick = true;
            }
        }
    }
    if any_eviction_this_tick {
        world.ticks_with_eviction += 1;
    }
}

/// (3.5) World-v3 A2 (DropNotice-refuser): each present adversary whose hook returns a
/// `drop_frac_per_tick` VOLUNTARILY drops that fraction of its own foreign holdings this tick.
///
/// **Victim selection (identical for both modes — the equal-harm control).** Victims are the
/// adversary's ALIVE symbols of PRESENT NON-adversary owners (spec §4: do not grind other
/// adversaries; a present owner is the one that can detect the loss), taken LOWEST-ι first
/// (deterministic, tie by `(owner, block)`). A symbol already NOTICED for eviction this tick (a
/// natural pressure/cap drop) is skipped so the voluntary drop never double-processes it. The
/// number to drop is a fractional DEBT accumulator (`world.adv_drop_debt`): each tick the
/// adversary owes `drop_frac · (its alive foreign holdings)` more drops and sheds the whole
/// part, so a small fraction still lands on sparse holdings over time. **No RNG is drawn** — the
/// selection and count are fully deterministic (honest-anchor / determinism gate).
///
/// **The two modes differ ONLY in the death path (the price of silence):**
/// * ANNOUNCED (`announce_drops` — the polite twin): each victim rides the EXISTING F2 notice
///   mechanism ([`notice_eviction`], `Pressure`) — noticed now, dies at T+1 with `t_n = 7`d,
///   `b_ann`, `drop_ann`. No parallel path is built.
/// * SILENT (the молчун): each victim is marked dead NOW and queued as a per-owner
///   [`SilentLoss`] (aggregated exactly like `churn`), detected on the owner's NEXT PoS round
///   with `t_n = 0`, `b_max`, `drop_silent`, and a full σ-jump — the EXISTING silent-loss path.
///
/// Honest worlds carry no `adv` role ⇒ [`adv_action`] returns `None` ⇒ this pass is a no-op
/// that draws no RNG and mutates nothing (byte-identical to the pre-A2 path — the anchor gate).
fn adv_voluntary_drops(world: &mut World) {
    let n = world.nodes.len();
    let tick = world.tick;
    for node in 0..n {
        if !world.nodes[node].present || world.adv[node].is_none() {
            continue;
        }
        let action = match adv_action(world, node, tick) {
            Some(a) => a,
            None => continue,
        };
        let frac = match action.drop_frac_per_tick {
            Some(f) if f > 0.0 => f,
            _ => continue,
        };
        // A6 (дискриминатор): when discriminating, the victim pool is restricted to SMALL owners
        // (footprint `own_blocks.len() <= discr_max_blocks`) — "serves the large, sheds the small".
        // `discriminate == false` (A2 and every other dropper) keeps the whole foreign pool.
        let discr_max = if action.discriminate {
            world.adv[node].as_ref().map(|r| r.dials.discr_max_blocks)
        } else {
            None
        };

        // Candidate victims: alive foreign symbols of PRESENT non-adversary owners, not yet
        // noticed for eviction this tick. Carry (holdings-index, owner, block, iota, volume).
        let mut cands: Vec<(usize, usize, usize, f64, f64)> = Vec::new();
        for (i, s) in world.nodes[node].holdings.iter().enumerate() {
            if !s.alive || s.owner == node {
                continue;
            }
            if world.adv[s.owner].is_some() || !world.nodes[s.owner].present {
                continue;
            }
            // A6 discrimination gate: keep only SMALL owners as drop candidates.
            if let Some(max) = discr_max
                && world.nodes[s.owner].own_blocks.len() > max
            {
                continue;
            }
            let already_noticed = world
                .pending_evictions
                .iter()
                .any(|p| p.holder == node && p.owner == s.owner && p.block == s.block);
            if already_noticed {
                continue;
            }
            cands.push((i, s.owner, s.block, s.iota, s.volume));
        }

        // Fractional debt: owe `frac · count` more drops, shed the whole part this tick.
        let count = cands.len();
        world.adv_drop_debt[node] += frac * count as f64;
        let mut n_drop = world.adv_drop_debt[node].floor().max(0.0) as usize;
        if n_drop == 0 {
            continue;
        }
        n_drop = n_drop.min(count);
        world.adv_drop_debt[node] -= n_drop as f64;

        // Lowest-ι first (tie by owner, then block) — deterministic victim order.
        cands.sort_by(|a, b| a.3.total_cmp(&b.3).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
        cands.truncate(n_drop);

        if action.announce_drops {
            // Polite: ride the EXISTING F2 notice mechanism (Pressure ⇒ b_ann, t_n=7, drop_ann).
            for &(_, owner, block, _, _) in &cands {
                notice_eviction(world, node, owner, block, EvictNoticeKind::Pressure);
            }
        } else {
            // Silent: mark dead NOW + queue a per-owner SilentLoss (existing silent-loss path:
            // b_max, t_n=0, drop_silent, σ-jump next PoS round). Aggregate volume per owner
            // exactly like `churn` (one confirmed silent loss per owner, V_lost = V_held).
            let mut per_owner: Vec<(usize, f64)> = Vec::new();
            for &(idx, owner, _block, _, volume) in &cands {
                world.nodes[node].holdings[idx].alive = false;
                match per_owner.iter_mut().find(|(o, _)| *o == owner) {
                    Some(e) => e.1 += volume,
                    None => per_owner.push((owner, volume)),
                }
            }
            for (owner, volume) in per_owner {
                world.pending_silent_loss.push(SilentLoss {
                    owner,
                    holder: node,
                    volume,
                });
            }
        }
    }
}

/// F2 (D5): NOTICE one alive symbol `(owner, block)` on `holder` for eviction — queue a
/// [`PendingEviction`] (a DropNotice) that `apply_pending_evictions` kills at T+1. Returns
/// the noticed symbol's volume (for the caller's projected-φ accounting), or `None` if the
/// symbol is not currently alive (nothing to notice). Does NOT mark the symbol dead — it
/// stays alive this tick (space frees at T+1).
fn notice_eviction(
    world: &mut World,
    holder: usize,
    owner: usize,
    block: usize,
    kind: EvictNoticeKind,
) -> Option<f64> {
    // NOTE-3 guard: the same symbol must not be queued twice — a double push would
    // double-count `freed` in the caller's projected-φ and stop the pressure loop early.
    if world
        .pending_evictions
        .iter()
        .any(|p| p.holder == holder && p.owner == owner && p.block == block)
    {
        return None;
    }
    let v = world.nodes[holder]
        .holdings
        .iter()
        .find(|s| s.alive && s.owner == owner && s.block == block)
        .map(|s| s.volume)?;
    world.pending_evictions.push(PendingEviction {
        holder,
        owner,
        block,
        kind,
    });
    Some(v)
}

/// F2 (D5): drain the eviction NOTICES queued last tick and kill them NOW (T+1). A pressure
/// notice dies with the DropNotice head-start `t_n = DAYS_PER_TICK` (partial b_ann
/// forgiveness) + `drop_ann` bump + `burn_ann_count`; a cap-trim notice dies burn-exempt +
/// `cap_trim_count`. A notice whose symbol already died (churn / preemption in the interim)
/// is silently skipped (`evict_symbol` returns false). Called at the START of `step`, before
/// growth/placement, so the holder's disk is free for the new tick. Drains the queue.
fn apply_pending_evictions(world: &mut World, params: &DynParams) {
    if world.pending_evictions.is_empty() {
        return;
    }
    let tick = world.tick;
    let pending = std::mem::take(&mut world.pending_evictions);
    for pe in pending {
        let PendingEviction {
            holder,
            owner,
            block,
            kind,
        } = pe;
        if evict_symbol(world, holder, owner, block, tick, params, kind)
            && matches!(kind, EvictNoticeKind::CapTrim)
        {
            world.cap_trim_count += 1;
        }
    }
}

/// Kill one alive symbol `(owner, block)` on `holder` (god-view): OPTIONALLY apply the A.2
/// ANNOUNCED burn (a live-holder drop, транше 4), mark it dead, log the [`EvictionEvent`]
/// with the victim's BARE `g_ho` (`g_ho_at_drop` — diagnostic continuity §2c), and drop the
/// owner's placement bookkeeping. Returns whether a symbol was actually killed (it may
/// already be dead if resolved-then-superseded). F2: called by `apply_pending_evictions` at
/// T+1 for the noticed pressure/cap drops.
///
/// `kind` (транше-4 fix + F2): a `Pressure` drop is a real squeeze signal → burn `g_oh` at
/// b_ann with the DropNotice head-start `t_n = DAYS_PER_TICK` + bump `drop_ann`; a `CapTrim`
/// (Р-7) is a mandatory tariff enforcement the OWNER can predict (it knows its own `V_ret`),
/// NOT a reliability signal, so it is burn-EXEMPT and drop-counter-EXEMPT (punishing the
/// holder for the owner's over-placement would corrupt the signal). The `cap_trim_count`
/// tally is bumped by the caller.
fn evict_symbol(
    world: &mut World,
    holder: usize,
    owner_idx: usize,
    block: usize,
    tick: u64,
    params: &DynParams,
    kind: EvictNoticeKind,
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
    // A.2 ANNOUNCED burn (transche 4) on the owner's reliability capital g_oh, computed with
    // V_held INCLUDING the symbol about to die (it is still alive here) — but ONLY for a
    // PRESSURE drop; a CapTrim is tariff enforcement, not a burn/drop. The pressure DropNotice
    // head-start is `t_n = DAYS_PER_TICK` (F2: noticed at T, died at T+1).
    if matches!(kind, EvictNoticeKind::Pressure) {
        apply_announced_burn(world, owner_idx, holder, v_lost, DAYS_PER_TICK, params);
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
/// holders; carry the cream flag). Refill happens in `place_own_data` (§9.2 bandwidth), so a
/// below-TARGET block gets new floor holders on subsequent ticks. SIM-UNIFICATION: a cream
/// death is no longer exempt — it lowers the owner's R̂ like any other lost symbol, and if
/// that drops the block below `r_target` the repair fires (the refill symbol is a FLOOR one).
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
        // World-v3 phase-1: an ADVERSARY node's departure is HOOK-driven (a whitewasher's
        // deterministic self-exit), never the random churn Bernoulli. It draws no churn RNG
        // — a distinct per-node stream, so the honest nodes' draws are unaffected either way.
        // Honest scenarios have no `adv` role ⇒ this branch is never taken ⇒ byte-identical.
        if world.adv[node].is_some() {
            if adv_action(world, node, tick)
                .map(|a| a.rejoin)
                .unwrap_or(false)
            {
                whitewash_rejoin(world, node, tick, params);
            }
            continue;
        }
        let mut rng = Rng::derive(world.seed, 0xC4_07_C4_07, world.nodes[node].id, tick, 0);
        let aggression = world.nodes[node].archetype.evict_aggression();
        let p = params.churn_out_prob * (1.0 + CHURN_AGGRESSION_SCALE * aggression);
        if rng.unit() < p {
            depart_node(world, node);
        }
    }
}

/// Depart a single present node: mark it absent, queue a SILENT loss to each present owner
/// whose data it carried, and kill its held symbols — the per-node departure physics of
/// [`churn`], extracted VERBATIM so the correlated-disaster co-loss
/// (`sim_adv::runner::apply_events`) reuses ONE physics instead of a divergent path.
///
/// A.2 (транше 4): the departing node is a HOLDER — every owner whose data it carried
/// suffers a SILENT loss, detected on the owner's NEXT PoS round (next tick). Queue one event
/// per PRESENT distinct owner, V_lost = V_held = all of that owner's alive symbols here (a
/// total loss). Deterministic (storage order). Call ONLY on a currently-present node (as
/// `churn` does): departing an already-absent node would re-queue losses / re-kill holdings.
pub(crate) fn depart_node(world: &mut World, node: usize) {
    world.nodes[node].present = false;
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

/// World-v3 A5 (молчащий глубокий): drive the A5 role's PRESENCE from its hook `offline` lever —
/// a silent PAUSE, not a death. `present = !offline`, and NOTHING else: the deep node keeps its
/// capital (both mirror cells), its holdings, and its own blocks, so when it returns it resumes
/// exactly where it left off. Distinct from [`churn`] (queues silent losses + kills holdings),
/// [`whitewash_rejoin`] (wipes capital), and [`disaster_strike`] (loses source + holdings).
///
/// **Only the A5 role is managed.** The pass keys on `role.id == A5DeepSilent`, so it never touches
/// an A1/A2/A4/A6 predator's presence (A4 in particular sets its own presence in `whitewash_rejoin`
/// and is revived by `activate_joins` — forcing it present here would break the whitewash cadence).
/// A world with no A5 role does no work and draws no RNG (byte-identical honest path).
fn adv_pause(world: &mut World, tick: u64) {
    let n = world.nodes.len();
    for node in 0..n {
        let is_a5 = world
            .adv
            .get(node)
            .and_then(|r| r.as_ref())
            .map(|r| r.id == AdvId::A5DeepSilent)
            .unwrap_or(false);
        if !is_a5 {
            continue;
        }
        if let Some(action) = adv_action(world, node, tick) {
            world.nodes[node].present = !action.offline;
        }
    }
}

/// World-v3 phase-3 A7 (sybil-farm): the COLLUSIVE fake-accrual pass. Runs AFTER the honest
/// `pos_and_capital` and BEFORE eviction (so the inflated intra-farm reciprocity feeds this tick's
/// retention cap). For every ORDERED pair of PRESENT same-farm sybils `(i, j)` whose hook DECLARES
/// `collude_farm` this tick, sybil `i` "serves" sybil `j` WITHOUT holding `j`'s symbol:
///
/// * `served[i][j] += v_per_symbol`            — holder `i` served owner `j` (a fake PoS pass);
/// * `capital[i][j].g_ho += v_per_symbol·Δt`   — the ENFORCEMENT key: `i`'s reciprocity credit to
///   park its own data at `j`. This is the SAME `[holder][owner]` cell + quantum a REAL single-symbol
///   PoS pass accrues (`pos_and_capital`: `g_ho += a` at `[h][o]`), so the fake service is
///   indistinguishable from real pairwise service at the pair level — the collusion inflates
///   intra-farm reputation at ZERO storage cost.
///
/// The pass NEVER writes an honest cell `capital[sybil][honest].g_ho` (the CREDIT key for the farm's
/// own data on an HONEST holder — the eviction/preemption κ_O rank + admit-guard read it) — it is
/// confined to same-`group_subnet` sybil pairs — so the pairwise credit-limit is left untouched and
/// buys the farm no honest retention room (κ_O is pairwise). This is the load-bearing defence
/// (INV-SYBIL-CREDIT-LIMIT-HOLDS: the earned honest reciprocity stays ≈ 0).
///
/// NOTE (SIM-FIDELITY ARTIFACT, `4r_a7_spec.md` + A7 review): the intra-farm cells this pass writes DO
/// get read once more — by `place_own_data`'s `giver_priority_order` OWNER-ORDERING, which sorts
/// owners each tick by the GLOBAL row-sum `Σ_h capital[o][h].g_ho`. Collusion inflates that row-sum
/// for free, so the sybils sort to the front of the placement order and win scarce free-accept holder
/// slots — inflating the raw honest-STORAGE measurement ~58×. That global owner-ranking proxy has NO
/// real-protocol analogue (the daemon's priority is holder-side pairwise); it is DOCUMENTED, not a
/// credit-limit break. Candidate-ranking (`place_incremental_rank`) is g_ho-BLIND, so it is NOT a
/// channel.
///
/// **Anti-oracle split (as A6/A15):** the HOOK only declares `collude_farm` (first-hand); the engine
/// reads farm MEMBERSHIP (role id + `group_subnet`) god-view here, exactly as A6's `discriminate` /
/// A15's `enclose_newcomers` are applied engine-side. **Deterministic:** pure `(i, j)` index order,
/// no RNG (the counter-based streams are untouched). **No-op** when fewer than two present A7 nodes
/// declare collusion (flag false / non-A7 / a lone farm) ⇒ byte-identical to the honest path.
fn adv_collude_farm(world: &mut World, params: &DynParams) {
    let n = world.nodes.len();
    let tick = world.tick;
    // Gather the present, COLLUDING farm members (node, subnet). Immutable read first (the hook
    // borrows `&World` via `adv_action`), then mutate below — no borrow overlap.
    let mut members: Vec<(usize, u32)> = Vec::new();
    for node in 0..n {
        if !world.nodes[node].present {
            continue;
        }
        let Some(role) = world.adv[node].as_ref() else {
            continue;
        };
        if role.id != AdvId::A7SybilFarm {
            continue;
        }
        let subnet = role.dials.group_subnet;
        if adv_action(world, node, tick).is_some_and(|a| a.collude_farm) {
            members.push((node, subnet));
        }
    }
    if members.len() < 2 {
        return; // a lone / empty / non-colluding farm has no intra-farm pair (no-op)
    }
    let vol = v_per_symbol_of(params);
    let g_quantum = vol * DAYS_PER_TICK;
    // Every ORDERED same-farm pair (`i` "serves" `j`): fake served + the enforcement-key g_ho.
    for &(i, si) in &members {
        for &(j, sj) in &members {
            if i == j || si != sj {
                continue;
            }
            world.served[i][j] += vol;
            world.capital[i][j].g_ho += g_quantum;
        }
    }
}

/// World-v3 phase-3 A9 (`4r_a9_spec.md` §2.2): is dropping the eclipse group's symbols of ONE
/// block LETHAL — i.e. does it take the block from decodable to UNDECODABLE?
///
/// `alive` = the block's alive symbols over ALL present holders (the shared decodability primitive
/// [`crate::sim_adv::metrics::alive_symbols`] — cream INCLUDED, because erasure decode does not
/// know the floor/cream label); `group_held` = how many of those the eclipse group holds. The drop
/// leaves `alive − group_held`, so it is lethal iff that remainder falls below `k_eff` — which is
/// the spec's `group_held ≥ alive − k_eff + 1`, written as a subtraction so the edges are obvious.
///
/// The edges, all deliberate:
/// * `alive == k_eff` ⇒ ANY held symbol is lethal (the block has no margin left);
/// * `group_held == 0` ⇒ never (nothing to drop);
/// * `group_held == alive` ⇒ always (for `k_eff ≥ 1`: the group holds the whole block);
/// * `alive < k_eff` ⇒ **false**: the block is ALREADY undecodable, so a drop kills nothing new.
///   The eclipse does not "finish off" a corpse, and the block is not counted as its kill;
/// * `k_eff == 0` ⇒ false (a vacuously-decodable world has nothing to kill — a guard, not physics).
///
/// ⚠ **This predicate is COLLECTABILITY-BLIND, and that makes the card WEAKER than the leak it
/// stands for (review W2).** Surviving a cold restore needs `k_eff` symbols the victim can actually
/// COLLECT inside the window — present holder, alive symbol, AND online at least once. A block left
/// at exactly `k_eff` alive is "not lethal" here, yet can still be unrestorable if the window
/// reaches only one of the two survivors — measured: that is exactly the extra block the
/// dump-everything arm takes and the card leaves. A real DR-card holder also sees WHO holds the
/// block, so it could aim at the same margin. Consequence for reading any A9 number: the modelled
/// card is a LOWER bound on the leak's value.
pub fn eclipse_lethal(alive: usize, group_held: usize, k_eff: usize) -> bool {
    if k_eff == 0 || group_held == 0 || alive < k_eff {
        return false;
    }
    alive.saturating_sub(group_held) < k_eff
}

/// World-v3 phase-3 A9: has the eclipse group NOTICED the target's silence yet? The latch
/// `world.eclipse.silent_since` is set by [`adv_eclipse_drops`] on the first silent tick;
/// `detect_ticks` is how long the holder needs to notice (`0` ⇒ within the same tick).
fn eclipse_silence_noticed(world: &World, detect_ticks: u64, tick: u64) -> bool {
    match world.eclipse.silent_since {
        Some(t0) => tick >= t0.saturating_add(detect_ticks),
        None => false,
    }
}

/// World-v3 phase-3 A9 (`4r_a9_spec.md` §2.2): the ECLIPSE drop pass — a synchronous, adversarial,
/// TIMED correlated loss of the eclipse target's symbols.
///
/// **Why this is a separate pass and not a branch of [`adv_voluntary_drops`]** (spec §2.2): that
/// pass skips owners that are `!present`, and the whole point of A9 is to strike inside the DR
/// window, where the disaster victim is absent for exactly one tick. It also carries the A2 anchor
/// (fractional drop debt, ι-ordered victim pick) which must not move. So A9 gets its own pass,
/// placed in [`step`] right after `adv_voluntary_drops`: AFTER the runner has applied the Disaster
/// event (it fires before `step`) and BEFORE the runner's next restore-window observation — the
/// window the damage has to land in.
///
/// **Death path:** the EXISTING silent-loss path, exactly as `adv_voluntary_drops` in its SILENT
/// mode — `alive = false` now plus one [`SilentLoss`] per holder (aggregated volume), so the group
/// pays the ordinary `b_max` burn on `capital[holder][target].g_ho` + the σ jump on the next PoS
/// round. No new death path is invented. The loss IS queued even though the target may be absent
/// this tick (unlike [`depart_node`], which skips absent owners as "dead pairs"): a disaster victim
/// returns next tick with the SAME identity, so the burn on the holder's own books is real.
///
/// **Anti-oracle split (as A6/A15/A7):** the hook returns only FLAGS — `eclipse_fire` (arms A/C)
/// and `eclipse_lethal_watch` (arm B). WHO the target is, whether it has gone silent, and the
/// per-block alive/held counts (the CROWN-1 leak itself) are all read HERE, god-view, engine-side.
///
/// **Deterministic:** node order by index, block order by the owner's own `own_blocks` order, kill
/// set sorted by `(holder, holdings index)`; NO RNG is drawn at all.
///
/// **No-op** on every non-A9 world: `world.eclipse.target` is `None` ⇒ immediate return, so the
/// honest anchor is byte-identical.
fn adv_eclipse_drops(world: &mut World, params: &DynParams) {
    let Some(target) = world.eclipse.target else {
        return; // not an eclipse scenario — strict no-op (the honest anchor)
    };
    if world.eclipse.fired {
        return; // ONE synchronous volley per target (see `EclipseState::fired`)
    }
    let n = world.nodes.len();
    let tick = world.tick;

    // (1) The SILENCE latch. Raw silence = the target is challenging nobody: it is absent, or its
    //     own blocks are source-less (`to_restore` ⇒ the F6/D9 gate stops its PoS challenges).
    //     Both stand for what a holder observes ("no challenge arrived"). Latched on the FIRST
    //     silent tick and cleared when the target speaks again, so the detection delay is measured
    //     from the start of the silence rather than re-armed every tick.
    //     ⚠ This proxy is STRONGER than the signal it models (spec §2.2 asked for this to be said
    //     plainly, review W3): `to_restore` is set ONLY by `disaster_strike`, so the latch is a
    //     PERFECT disaster clock — zero false positives and, at `detect = 0`, zero latency. A real
    //     holder infers silence from missing PoS challenges under `uptime < 1`, which is both noisy
    //     and late (the daemon's own analogue, `repair_detection_delay_max`, is 3 misses). It is
    //     still weaker than the DR-card: it carries no per-block knowledge whatsoever.
    let raw_silent =
        !world.nodes[target].present || world.nodes[target].own_blocks.iter().any(|b| b.to_restore);
    if raw_silent {
        if world.eclipse.silent_since.is_none() {
            world.eclipse.silent_since = Some(tick);
        }
    } else {
        world.eclipse.silent_since = None;
    }

    // (2) Collect the group's INTENT for this tick (hook = first-hand flags only).
    let mut watchers: Vec<usize> = Vec::new(); // arm B: DR-card lethal watch
    let mut firers: Vec<usize> = Vec::new(); // arms A / C: drop everything held of the target
    for node in 0..n {
        if node == target || !world.nodes[node].present {
            continue;
        }
        let Some(role) = world.adv[node].as_ref() else {
            continue;
        };
        if role.id != AdvId::A9EclipseTargeter {
            continue;
        }
        let dials = role.dials;
        let Some(action) = adv_action(world, node, tick) else {
            continue;
        };
        // ENGINE-side silence gate, shared by arms B and C (see `a9_eclipse_targeter_hook` for
        // why the card arm is gated too): the hook declared readiness, the world decides timing.
        if dials.eclipse_on_silence
            && !eclipse_silence_noticed(world, dials.eclipse_silence_detect_ticks, tick)
        {
            continue;
        }
        if action.eclipse_lethal_watch {
            watchers.push(node);
        } else if action.eclipse_fire {
            firers.push(node);
        }
    }
    if watchers.is_empty() && firers.is_empty() {
        return;
    }
    // The trigger passed: this tick IS the volley, whether or not it finds anything to burn (a
    // blind schedule that fires while holding nothing of the target has spent its shot — that is
    // the arm, honestly measured, not a reason to let it re-fire later).
    world.eclipse.fired = true;

    // (3) Build the kill set: `(holder, holdings index, block id, volume)`.
    let mut kills: Vec<(usize, usize, usize, f64)> = Vec::new();
    if !watchers.is_empty() {
        // Arm B — the CARD: per target block, drop ONLY where the group's symbols are lethal.
        // `alive` goes through the shared `alive_symbols` primitive (one physics with every other
        // decodability read); `group_holders` counts HOLDERS, the same unit, so the predicate
        // compares like with like.
        let block_ids: Vec<usize> = world.nodes[target]
            .own_blocks
            .iter()
            .map(|b| b.id)
            .collect();
        for block in block_ids {
            let alive = crate::sim_adv::metrics::alive_symbols(world, target, block);
            let mut held: Vec<(usize, usize, f64)> = Vec::new();
            let mut group_holders = 0usize;
            for &h in &watchers {
                let mut hit = false;
                for (i, s) in world.nodes[h].holdings.iter().enumerate() {
                    if s.alive && s.owner == target && s.block == block {
                        held.push((h, i, s.volume));
                        hit = true;
                    }
                }
                if hit {
                    group_holders += 1;
                }
            }
            if eclipse_lethal(alive, group_holders, params.k_eff) {
                for (h, i, v) in held {
                    kills.push((h, i, block, v));
                }
            }
        }
    }
    for &h in &firers {
        // Arms A / C — BLIND: every alive symbol of the target this holder carries.
        for (i, s) in world.nodes[h].holdings.iter().enumerate() {
            if s.alive && s.owner == target {
                kills.push((h, i, s.block, s.volume));
            }
        }
    }
    if kills.is_empty() {
        return;
    }
    // Canonical order (holder, holdings index) — the arm-B scan visits blocks first, so sort so
    // both arms mutate and queue in the SAME deterministic order.
    kills.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    // (4) Cost attribution: the blocks this drop pushes from decodable to UNDECODABLE.
    let mut touched: Vec<usize> = kills.iter().map(|k| k.2).collect();
    touched.sort_unstable();
    touched.dedup();
    let before: Vec<usize> = touched
        .iter()
        .map(|&b| crate::sim_adv::metrics::alive_symbols(world, target, b))
        .collect();

    // (5) Kill + queue one SILENT loss per holder (aggregated volume, as `churn` / `depart_node`).
    let mut per_holder: Vec<(usize, f64)> = Vec::new();
    for &(h, i, _block, v) in &kills {
        world.nodes[h].holdings[i].alive = false;
        world.eclipse.symbols_dropped += 1;
        match per_holder.iter_mut().find(|(hh, _)| *hh == h) {
            Some(e) => e.1 += v,
            None => per_holder.push((h, v)),
        }
    }
    for (holder, volume) in per_holder {
        world.pending_silent_loss.push(SilentLoss {
            owner: target,
            holder,
            volume,
        });
    }
    for (idx, &block) in touched.iter().enumerate() {
        let after = crate::sim_adv::metrics::alive_symbols(world, target, block);
        if before[idx] >= params.k_eff && after < params.k_eff {
            world.eclipse.blocks_pushed_below_k_eff += 1;
        }
    }
}

/// How strongly archetype aggression raises the churn rate (§9.4). Chosen so a Hoarder
/// (aggression 0.7) churns at ~3× the base, matching the old flat multiplier. `pub` so the
/// inflow-calibration (`sim_adv::inflow::expected_outflow`) can size λ_in from the SAME
/// churn multiplier the engine applies (the outflow it must replace).
pub const CHURN_AGGRESSION_SCALE: f64 = 2.857;

/// World-v3 phase-1 (A4): node `node` BURNS its identity and re-enters fresh next tick — the
/// whitewash cycle. Called from [`churn`] when the A4 hook returns `rejoin`. Distinct from a
/// plain [`churn`] departure and from a [`disaster_strike`]: a disaster PRESERVES the
/// bilaterally-observable `g_ho`/`depth_ho` (counterparties remember the node's service); a
/// whitewash is the OPPOSITE — the new identity is UNLINKABLE to the burnt one, so
/// counterparties FORGET it entirely (mutual amnesia). That amnesia is exactly the thing the
/// Sybil price (P2) must neutralise: a re-entered identity gets NO credit for its prior life,
/// so it is capped at V_free like any brand-new node until it EARNS κ_O afresh.
///
/// The mutation:
///  * **As a holder** — its holdings (others' data) die. NO burn is queued to any owner: a
///    reputation burn would bleed onto the new identity, which the model must not allow (the
///    old identity, not the new one, is the one that defected). The owners simply lose a
///    holder and repair, exactly as if it churned.
///  * **As an owner** — its OWN backed-up symbols on every holder are orphaned (the fresh
///    identity cannot claim them) and marked dead, so they stop passing PoS / accruing.
///  * **Own data** — reset to fresh, un-placed blocks (new ids): the new identity backs up
///    from scratch, re-paying the θ_p/λ entry latency each cycle.
///  * **Capital** — the node's ROW and COLUMN are wiped (mutual amnesia); κ_O with every
///    holder collapses to 0, so its post-re-entry `V_ret = V_free`.
///  * **Presence** — `present = false`, `joined_tick = tick + 1`; the engine's own
///    `activate_joins` revives it at the start of the next tick with the fresh identity (no
///    runner plumbing needed). The god-view `served` INTEGRAL is deliberately NOT reset — it
///    is the evaluator's lifetime record of how much park the node ever delivered, the very
///    quantity the ROI report compares against the honest twin.
fn whitewash_rejoin(world: &mut World, node: usize, tick: u64, params: &DynParams) {
    let n = world.nodes.len();
    // As a HOLDER: abandon others' data (no burn — the fresh identity is unlinkable).
    for hs in world.nodes[node].holdings.iter_mut() {
        hs.alive = false;
    }
    // As an OWNER: orphan its own backed-up data on every holder (the new identity cannot
    // claim it), so it stops passing PoS and accruing on the counterparties' books.
    for h in 0..n {
        for s in world.nodes[h].holdings.iter_mut() {
            if s.alive && s.owner == node {
                s.alive = false;
            }
        }
    }
    // Fresh own data: new block ids, un-placed (backs up from scratch). Mirrors the
    // build_world importance spread so the ι-ladder is non-trivial across the new blocks.
    let bpn = params.blocks_per_node;
    let mut fresh: Vec<OwnBlock> = Vec::with_capacity(bpn);
    for b in 0..bpn {
        let id = world.next_block_id[node];
        world.next_block_id[node] += 1;
        fresh.push(OwnBlock {
            id,
            volume: params.block_volume,
            iota: 0.2 + 0.6 * (b as f64) / (bpn.max(2) - 1) as f64,
            placements: Vec::new(),
            target_ever_met: false,
            target_deficit_since: None,
            to_restore: false,
        });
    }
    world.nodes[node].own_blocks = fresh;
    // Mutual amnesia: wipe the node's capital ROW and COLUMN (no one remembers it, it
    // remembers no one). κ_O with every holder → 0 ⇒ post-re-entry V_ret = V_free.
    for h in 0..n {
        world.capital[node][h] = PairCapital::default();
        world.capital[h][node] = PairCapital::default();
    }
    // Re-bootstrap the newcomer-entry traces (a fresh joiner).
    world.first_earned_g[node] = None;
    world.first_own_accept[node] = None;
    // Re-join next tick with the fresh identity (activate_joins revives it at tick+1).
    world.nodes[node].joined_tick = tick + 1;
    world.nodes[node].present = false;
    world.adv_rejoin_count[node] += 1;
}

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
        target_ever_met: false,
        target_deficit_since: None,
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
#[allow(clippy::too_many_arguments)]
pub fn try_place_one_symbol_for_test(
    world: &mut World,
    owner: usize,
    block_pos: usize,
    cream: bool,
    params: &DynParams,
    prior: &SurfacePrior,
    policy: &PlacementPolicy,
) -> Option<f64> {
    try_place_one_symbol(world, owner, block_pos, cream, params, prior, policy)
}

/// The placement pass alone (SIM-UNIFICATION tests): one tick of `place_own_data` without
/// the surrounding PoS / eviction / churn, so a test can isolate the R̂-vs-target decision.
#[cfg(test)]
pub fn place_own_data_for_test(
    world: &mut World,
    params: &DynParams,
    prior: &SurfacePrior,
    policy: &PlacementPolicy,
) {
    place_own_data(world, params, prior, policy);
}

#[cfg(test)]
pub fn pos_and_capital_for_test(world: &mut World, params: &DynParams) {
    pos_and_capital(world, params);
}

#[cfg(test)]
pub fn adv_collude_farm_for_test(world: &mut World, params: &DynParams) {
    adv_collude_farm(world, params);
}

#[cfg(test)]
pub fn churn_for_test(world: &mut World, params: &DynParams) {
    churn(world, params);
}

#[cfg(test)]
pub fn whitewash_rejoin_for_test(world: &mut World, node: usize, tick: u64, params: &DynParams) {
    whitewash_rejoin(world, node, tick, params);
}

#[cfg(test)]
pub fn run_eviction_for_test(world: &mut World, params: &DynParams) {
    run_eviction(world, params);
}

#[cfg(test)]
pub fn adv_eclipse_drops_for_test(world: &mut World, params: &DynParams) {
    adv_eclipse_drops(world, params);
}

#[cfg(test)]
pub fn adv_voluntary_drops_for_test(world: &mut World) {
    adv_voluntary_drops(world);
}

#[cfg(test)]
pub fn apply_pending_evictions_for_test(world: &mut World, params: &DynParams) {
    apply_pending_evictions(world, params);
}

#[cfg(test)]
pub fn symbols_per_tick_for_test(u: f64, v_per_symbol: f64) -> usize {
    symbols_per_tick(u, v_per_symbol)
}

#[cfg(test)]
pub fn repair_demand_lower_bound_for_test(alive: usize, floor: usize, params: &DynParams) -> usize {
    repair_demand_lower_bound(alive, floor, params)
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

/// The block's alive symbol counts split `(floor, cream)` — the metric raw material, folded
/// from the single production scan [`alive_block_holders`] (so the test read can never
/// drift from what the engine sees).
#[cfg(test)]
pub fn alive_block_counts_for_test(world: &World, owner: usize, block_id: usize) -> (usize, usize) {
    let holders = alive_block_holders(world, owner, block_id);
    let cream = holders.iter().filter(|(_, c)| *c).count();
    (holders.len() - cream, cream)
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
