//! SIM-R1 observer — the trust boundary for the per-symbol forecast.
//!
//! Converts each hidden [`SimR1Holder`] into the owner's first-hand observation
//! plus the owner's ι-ladder on that holder ([`HolderPlacement`]). The ONLY fields
//! it writes are observable / first-hand:
//!   * the holder's `master_id` / `addr_subnet` (connection facts, §1-legal);
//!   * `g_holder_from_owner` = the owner's TRUE standing `G(h←O)` (bilaterally
//!     observable — the owner performed the storage, so this is first-hand, NOT an
//!     oracle);
//!   * a PoS pass/fail record that encodes the FIRST-HAND evidence the owner has:
//!     the fraction of its rounds with this holder that FAILED (the `observed_drop_frac`
//!     signal). This drives BOTH the surface anchor and the eviction-pressure signal,
//!     exactly as the kernel reads them.
//!   * the owner's OWN declared ι-ladder (`ladder_iotas`) — first-hand metadata the
//!     owner authored, shadowed verbatim.
//!
//! It MUST NOT copy `true_surface`, `true_keep_depth`, or `archetype` — and
//! structurally it cannot: [`FirstHandObs`] / [`HolderPlacement`] have no field for
//! them, and the sim's `GroundTruth` types are not in `viaticum-core`'s graph.

use viaticum_core::four_r::{FirstHandObs, HolderPlacement};
use viaticum_core::types::{DeviceId, IdentityPub};

use crate::sim_r1::generator::{SimR1Holder, SimR1Pop};

/// Total PoS rounds the owner has run against each holder (the observation depth).
/// Large enough that `observed_drop_frac` maps cleanly into integer fail counts.
const POS_ROUNDS: u32 = 100;

/// Shadow one hidden holder into the owner's first-hand observation. The observed
/// point is `(V0=10, τ0=30)` for every holder (the owner sampled them at the same
/// slice), so the surface route varies ONLY through the first-hand PoS record — no
/// hidden surface probability leaks. The eviction-pressure signal is the same PoS
/// record's fail fraction (`observed_drop_frac`).
pub fn observe(h: &SimR1Holder) -> FirstHandObs {
    let mut master = [0u8; 32];
    master[0] = h.master;
    let mut device = [0u8; 32];
    device[0] = h.master ^ 0xA5;

    // Encode the FIRST-HAND drop evidence into the PoS record: `fail` counts are the
    // rounds the owner observed this holder drop/miss. The remaining rounds passed.
    // The kernel reads pass-fraction (surface anchor) and (fail+timeout)-fraction
    // (eviction pressure) from exactly these counts.
    let fail = ((h.observed_drop_frac.clamp(0.0, 1.0)) * POS_ROUNDS as f64).round() as u32;
    let pass = POS_ROUNDS.saturating_sub(fail);

    FirstHandObs {
        g_owner_from_holder: 0.0,
        // First-hand standing: the owner's proven service to this holder.
        g_holder_from_owner: h.true_g_holder_from_owner,
        v_dem: 10.0,
        recent_rate_p: 0.0,
        trend_d: 0.0,
        pos_pass: pass,
        pos_fail: fail,
        pos_timeout: 0,
        observed_volume: 10.0,
        observed_tau: 30.0,
        addr_subnet: h.subnet,
        addr_geo: 0,
        latency_ms: 10.0,
        reachable: true,
        scrutiny: 0.0,
        master_id: IdentityPub(master),
        device_id: DeviceId(device),
        // NOTE: nowhere to write `true_surface` / `true_keep_depth` / `archetype`.
    }
}

/// Shadow the whole population into per-holder placements, each forecasting the
/// symbol at rung `symbol_in_ladder` of the owner's ι-ladder on that holder.
/// Index order is preserved so the evaluator can map a placement back to its
/// hidden holder.
pub fn observe_all(pop: &SimR1Pop, symbol_in_ladder: usize) -> Vec<HolderPlacement> {
    pop.holders
        .iter()
        .map(|h| {
            let idx = symbol_in_ladder.min(h.ladder_iotas.len().saturating_sub(1));
            HolderPlacement {
                obs: observe(h),
                ladder_iotas: h.ladder_iotas.clone(),
                symbol_in_ladder: idx,
            }
        })
        .collect()
}
