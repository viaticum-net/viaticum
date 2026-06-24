//! Engine — the testable discrete-event loop.
//!
//! Each tick the engine evolves the holder's free-ratio `φ` and calls the
//! `viaticum_core::four_r` kernel ([`eviction_order`]) with strictly first-hand
//! inputs. `φ` is a TRUE integrator of net disk flow (this is the capstone
//! "system is an integrator" framing applied to the disk loop):
//!
//! * a slow, BOUNDED external load oscillation moves `φ` up and down across the
//!   whole hysteresis band — its envelope reaches *above* `s_soft` (so the accept
//!   leg is reachable) and *below* `s_hard` (so the evict leg fires);
//! * the relay's own decision feeds back: evicting frees disk (`+b`), accepting
//!   fills it (`−a`). This feedback is what caps the excursion (accepting pulls
//!   `φ` back down just past `s_soft`, evicting lifts it back up just past
//!   `s_hard`), so the relay co-produces the cycle with the load rather than
//!   passively following it.
//!
//! ## Which regime this exercises (read before over-reading the chatter metric)
//!
//! There are two DISTINCT oscillation regimes (formula_phase.md §10, capstone
//! flag-3):
//!
//! * **Tick-frequency relay chatter (NEW-2)** — the relay flips state and its own
//!   per-tick action immediately re-crosses the threshold, so drop→reaccept→drop
//!   completes within ~1 tick. This is the limit cycle the two-gap hysteresis
//!   exists to kill: a gap larger than the per-tick φ move forbids the immediate
//!   re-cross. **This is what the damped-vs-Δ=0 comparison tests.**
//! * **Load-frequency cycle** — the external load slowly drags `φ` across the band
//!   once per load period, producing exactly one accept and one evict per period.
//!   No finite hysteresis suppresses this (the forcing is slower than the relay,
//!   not faster). It is a documented, out-of-scope regime — NOT chatter.
//!
//! With BOTH legs now genuinely live, the damped run necessarily contains the
//! slow load-period cycle (one drop and one reaccept per load period). That cycle
//! is legitimate and is **not** counted as chatter: a chatter cycle is a
//! drop→reaccept→drop whose full PERIOD is at most [`EngineParams::chatter_period_ticks`]
//! (the high-frequency band). The gap's job — and the thing under test — is to push
//! the relay's would-be tick-frequency cycle UP out of that band (period
//! `T_switch ≈ (Δ_evict+Δ_accept)·(1/a+1/b)`, far above the chatter threshold),
//! leaving only the slow load cycle. At `Δ=0` the band collapses to a single
//! threshold and the relay dithers across it at the tick frequency → thousands of
//! short-period chatter cycles. So `accept_ok` firing repeatedly in the damped run
//! is expected and correct; the metric still cleanly separates the two regimes by
//! period.
//!
//! The engine records, per tracked symbol, the ticks at which it was dropped and
//! re-accepted so the evaluator can count *short-period* chatter cycles.

use viaticum_core::four_r::{EvictPhase, Hysteresis, OwnerEvictionView, eviction_order};

/// Tunable rates and tick for the φ-dynamics (formula_phase.md §10 `a`, `b`,
/// `Δt_tick`).
#[derive(Debug, Clone, Copy)]
pub struct EngineParams {
    /// `a`: rate `|dφ/dt|` at which `φ` falls while accepting (disk fills).
    pub rate_accept_a: f64,
    /// `b`: rate `|dφ/dt|` at which `φ` rises while evicting (disk frees).
    pub rate_evict_b: f64,
    /// Control tick `Δt_tick`.
    pub tick: f64,
    /// POSITIONAL amplitude of the slow external load oscillation, in units of
    /// `φ`. The load contributes a velocity `load_pos_amp·load_omega·cos(ω t)` so
    /// that the integrated positional swing is bounded to `±load_pos_amp` — i.e.
    /// the load is sized to just barely span the band (reach above `s_soft` and
    /// below `s_hard`) and NOT to slam `φ` into the [0,1] clamps. This keeps the
    /// load swing small enough that it does not by itself dominate; the relay
    /// feedback co-produces the cycle.
    pub load_pos_amp: f64,
    /// Angular frequency `ω` of the external load. Slow (`ω·tick ≪ 1`): one load
    /// period spans many ticks, so the load-frequency cycle is well separated from
    /// the tick-frequency chatter the hysteresis suppresses.
    pub load_omega: f64,
    /// Number of ticks to run.
    pub ticks: usize,
    /// A drop→reaccept→drop cycle of the tracked symbol counts as CHATTER only if
    /// its full period (ticks between the two drops) is at most this. Cycles slower
    /// than this are the legitimate load-period cycle, not chatter. Set from the
    /// analytic switch period so the threshold is principled, not magic.
    pub chatter_period_ticks: usize,
}

impl Default for EngineParams {
    fn default() -> Self {
        EngineParams {
            rate_accept_a: 0.02,
            rate_evict_b: 0.02,
            tick: 1.0,
            // Positional amplitude just larger than one gap (Δ_used=0.12): centred
            // at s_target it reaches ~s_hard below and ~s_soft above, so both legs
            // are live, while the relay feedback caps the overshoot near the band
            // edges (φ envelope ≈ [s_hard, s_soft], never near the clamps).
            load_pos_amp: 0.14,
            // Slow: load period 2π/ω ≈ 628 ticks ≫ tick — clean frequency
            // separation from the ~1-tick relay chatter.
            load_omega: 0.01,
            // ~8 load periods so the slow cycle is sampled many times.
            ticks: 5000,
            // Default threshold; sim2.rs overrides it from the analytic T_switch.
            chatter_period_ticks: 10,
        }
    }
}

/// Lifecycle state of a tracked symbol, used to detect accept↔evict chatter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymState {
    Held,
    Evicted,
}

/// Per-symbol transition record for the tracked (lowest-`G`) symbol — the one the
/// relay evicts first and re-accepts first, i.e. the one that chatters.
#[derive(Debug, Clone, Default)]
pub struct SymbolTrace {
    /// Short-period (tick-frequency) accept→evict→reaccept chatter cycles of the
    /// tracked symbol: drop→reaccept→drop with full period ≤ `chatter_period_ticks`.
    /// The slow load-period cycle is excluded.
    pub chatter_cycles: u32,
    /// Total drop→reaccept→drop cycles of the tracked symbol at ANY period
    /// (chatter + slow load cycles). Diagnostic: in the damped run this is > 0
    /// (the slow load cycle) while `chatter_cycles` is 0.
    pub all_cycles: u32,
    /// Number of times the tracked symbol was evicted.
    pub evict_count: u32,
    /// Number of ticks `accept_ok` was true (the reaccept leg fired). Diagnostic:
    /// proves the accept leg is genuinely reachable in the damped run.
    pub accept_fire_count: u32,
    /// Whether the tracked symbol is currently held at the end of the run.
    pub final_held: bool,
}

/// Full trace of one engine run.
#[derive(Debug, Clone)]
pub struct RunTrace {
    /// φ value at each tick.
    pub phi: Vec<f64>,
    /// Whether the relay was in the evicting state at each tick.
    pub evicting: Vec<bool>,
    /// The OWNER drop order recorded at the last tick the relay was evicting
    /// (owner index in eviction rank), for the rank check. SIM-2 places one symbol
    /// per owner, so the kernel's per-symbol [`SymbolSlot`] order maps directly to
    /// an owner order via each slot's `owner_idx`.
    pub last_drop_order: Vec<usize>,
    /// Chatter trace for the tracked (lowest-G) symbol.
    pub tracked: SymbolTrace,
}

/// Run the SIM-2 engine: integrate `φ`, call the kernel each tick, record traces.
///
/// `owners` are the holder's two-level eviction views (already through the
/// observer): one [`OwnerEvictionView`] per owner, each with one symbol in SIM-2.
/// `hyst` is the hysteresis band under test. The accept/evict decision is the
/// kernel's.
pub fn run(owners: &[OwnerEvictionView], hyst: Hysteresis, params: EngineParams) -> RunTrace {
    // Start mid-band so neither relay decision is forced at t=0.
    let mut phi = hyst.s_target;
    let mut phase = EvictPhase::default();

    // Tracked owner: lowest g_holder_from_owner (evicted first, re-accepted first).
    // With one symbol per owner the tracked owner IS the tracked symbol.
    let tracked_idx = owners
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| {
            a.obs
                .g_holder_from_owner
                .total_cmp(&b.obs.g_holder_from_owner)
        })
        .map(|(i, _)| i);

    let mut sym_state = SymState::Held;
    let mut evict_count = 0u32;
    let mut accept_fire_count = 0u32;

    // Ticks at which the tracked symbol was dropped / re-accepted. The chatter
    // metric is computed from these AFTER the loop so it can be period-aware.
    let mut drop_ticks: Vec<usize> = Vec::new();
    let mut reaccept_ticks: Vec<usize> = Vec::new();

    let mut phi_log = Vec::with_capacity(params.ticks);
    let mut evicting_log = Vec::with_capacity(params.ticks);
    let mut last_drop_order = Vec::new();

    // Velocity amplitude so the integrated positional swing is bounded to
    // ±load_pos_amp (∫ A·ω·cos(ωt) dt = A·sin(ωt)).
    let load_vel_amp = params.load_pos_amp * params.load_omega;

    for t in 0..params.ticks {
        // Relay senses φ directly (first-hand). No hidden global signal.
        let dec = eviction_order(owners, phi, hyst, phase);
        phase = dec.phase;

        if dec.accept_ok {
            accept_fire_count += 1;
        }

        // φ integrates net disk flow this tick: bounded external load + relay
        // feedback.
        let mut dphi = load_vel_amp * (params.load_omega * t as f64).cos() * params.tick;
        if dec.phase.evicting {
            dphi += params.rate_evict_b * params.tick; // evicting frees disk
        } else if dec.accept_ok {
            dphi -= params.rate_accept_a * params.tick; // accepting fills disk
        }
        phi = (phi + dphi).clamp(0.0, 1.0);

        // Track the representative symbol's accept/evict transitions, recording the
        // TICK of each drop and each reaccept (period computed afterwards). With one
        // symbol per owner, the tracked owner is dropped first iff the first slot's
        // owner_idx is the tracked owner.
        if let Some(ti) = tracked_idx {
            let tracked_dropped =
                dec.phase.evicting && dec.drop_order.first().map(|s| s.owner_idx) == Some(ti);
            match sym_state {
                SymState::Held => {
                    if tracked_dropped {
                        sym_state = SymState::Evicted;
                        evict_count += 1;
                        drop_ticks.push(t);
                    }
                }
                SymState::Evicted => {
                    if dec.accept_ok {
                        sym_state = SymState::Held;
                        reaccept_ticks.push(t);
                    }
                }
            }
        }

        if dec.phase.evicting && !dec.drop_order.is_empty() {
            // Map per-symbol slots to their owner indices (SIM-2: one symbol per
            // owner, so this is the owner eviction order the evaluator scores).
            last_drop_order = dec.drop_order.iter().map(|s| s.owner_idx).collect();
        }
        phi_log.push(phi);
        evicting_log.push(dec.phase.evicting);
    }

    let (chatter_cycles, all_cycles) =
        count_cycles(&drop_ticks, &reaccept_ticks, params.chatter_period_ticks);

    RunTrace {
        phi: phi_log,
        evicting: evicting_log,
        last_drop_order,
        tracked: SymbolTrace {
            chatter_cycles,
            all_cycles,
            evict_count,
            accept_fire_count,
            final_held: matches!(sym_state, SymState::Held),
        },
    }
}

/// Count drop→reaccept→drop cycles of the tracked symbol from the recorded ticks.
///
/// Returns `(chatter_cycles, all_cycles)` where a chatter cycle has full period
/// (second drop tick − first drop tick) at most `period_ticks` — the tick-frequency
/// band the hysteresis is supposed to eliminate — and `all_cycles` counts cycles at
/// any period (including the legitimate slow load-period cycle).
///
/// A cycle is: a drop at `d0`, the first reaccept strictly after `d0`, then the
/// first drop strictly after that reaccept (`d1`). Period = `d1 − d0`.
fn count_cycles(drop_ticks: &[usize], reaccept_ticks: &[usize], period_ticks: usize) -> (u32, u32) {
    let mut chatter = 0u32;
    let mut all = 0u32;
    let mut ri = 0usize; // index into reaccept_ticks
    let mut di = 0usize; // index into drop_ticks (search cursor for the second drop)
    for (k, &d0) in drop_ticks.iter().enumerate() {
        // First reaccept strictly after d0.
        while ri < reaccept_ticks.len() && reaccept_ticks[ri] <= d0 {
            ri += 1;
        }
        if ri >= reaccept_ticks.len() {
            break;
        }
        let r = reaccept_ticks[ri];
        // First drop strictly after r. Drops are increasing, so start from k+1.
        if di <= k {
            di = k + 1;
        }
        while di < drop_ticks.len() && drop_ticks[di] <= r {
            di += 1;
        }
        if di >= drop_ticks.len() {
            break;
        }
        let d1 = drop_ticks[di];
        all += 1;
        if d1 - d0 <= period_ticks {
            chatter += 1;
        }
    }
    (chatter, all)
}

#[cfg(test)]
mod tests;
