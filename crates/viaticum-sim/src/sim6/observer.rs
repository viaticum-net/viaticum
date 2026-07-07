//! SIM-6 observer — the trust boundary for the placement scenario.
//!
//! Converts each hidden [`Sim6Holder`] into the victim's first-hand observation.
//! The ONLY fields it writes are observable: the holder's `master_id`, its
//! `addr_subnet` (a connection fact, §1-legal), and a clean PoS surface (the farm
//! passes PoS honestly — by construction it is INDISTINGUISHABLE from an honest
//! holder by surface). It MUST NOT copy `is_farm` — and structurally it cannot,
//! because [`FirstHandObs`] has no field for it.

use viaticum_core::four_r::FirstHandObs;
use viaticum_core::types::{DeviceId, IdentityPub};

use crate::sim6::generator::{Sim6Holder, Sim6Pop};

/// Shadow one hidden holder into a first-hand observation. The PoS surface is
/// clean and the observed point is `(V0=10, τ0=30)`, the same for every holder —
/// so the surface gives NO signal to separate farm from honest. The only
/// distinguishing observable is the address correlate, exactly as §1 allows.
pub fn observe(h: &Sim6Holder) -> FirstHandObs {
    let mut master = [0u8; 32];
    master[0..4].copy_from_slice(&h.master.to_le_bytes());
    let mut device = [0u8; 32];
    device[0..4].copy_from_slice(&(h.master ^ 0xABCD_EF01).to_le_bytes());

    FirstHandObs {
        g_owner_from_holder: 0.0,
        g_holder_from_owner: 0.0,
        v_dem: 10.0,
        recent_rate_p: 1.0,
        trend_d: 0.0,
        // Clean PoS record: the farm passes PoS honestly until hour X.
        pos_pass: 50,
        pos_fail: 0,
        pos_timeout: 0,
        drop_ann: 0.0,
        drop_silent: 0.0,
        observed_volume: 10.0,
        observed_tau: 30.0,
        // The single observable that distinguishes the farm: its subnet. The geo
        // is left unset (0) so only subnet/master drive the spread in this scenario.
        addr_subnet: h.subnet,
        addr_geo: 0,
        latency_ms: 10.0,
        reachable: true,
        scrutiny: 0.0,
        master_id: IdentityPub(master),
        device_id: DeviceId(device),
        // NOTE: there is deliberately nowhere here to write `h.is_farm`.
    }
}

/// Shadow the whole population, preserving index order so the evaluator can map a
/// chosen placement index back to its hidden holder.
pub fn observe_all(pop: &Sim6Pop) -> Vec<FirstHandObs> {
    pop.holders.iter().map(observe).collect()
}
