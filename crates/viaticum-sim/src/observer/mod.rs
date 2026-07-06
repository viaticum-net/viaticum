//! Observer — the single trust boundary (anti-oracle choke point).
//!
//! This is the ONLY module that may read a hidden [`crate::generator::OwnerGt`]
//! and produce a [`FirstHandObs`]. It writes **only** first-hand shadows: the
//! pairwise service the holder itself rendered/received (a first-hand fact for
//! the holder), the holder's own PoS outcomes, reachability, address correlates,
//! crypto-ids. It MUST NOT copy `archetype`, hidden hazard, a global `φ`, or the
//! owner's behaviour toward third parties — and structurally it cannot, because
//! [`FirstHandObs`] has no field for any of those.
//!
//! The litmus (`meaning_scenarios_sim.md` §1) is now backed by the type: the
//! eviction rule's only arguments are `{φ_own, g_holder_from_owner}`, both
//! first-hand.

#[cfg(test)]
mod tests;

use viaticum_core::four_r::{FirstHandObs, OwnerEvictionView, SymbolDecl, SymbolId};
use viaticum_core::types::{DeviceId, IdentityPub};

use crate::generator::OwnerGt;

/// Convert a hidden owner ground-truth into the holder's first-hand observation
/// of that pair. The ONLY ground-truth quantity shadowed is the TRUE pairwise
/// service `true_g_holder_from_owner` — which is genuinely first-hand for the
/// holder (it performed that storage and confirmed it). The hidden `archetype`
/// is NOT read here, and there is nowhere on `FirstHandObs` to put it even if a
/// future bug tried to.
pub fn observe(owner: &OwnerGt, index: usize) -> FirstHandObs {
    // Distinct, deterministic crypto-ids per owner index (first-hand at connect).
    let mut master = [0u8; 32];
    master[0..8].copy_from_slice(&(index as u64).to_le_bytes());
    let mut device = [0u8; 32];
    device[0..8].copy_from_slice(&((index as u64) ^ 0xABCD).to_le_bytes());

    FirstHandObs {
        // g_owner_from_holder is the holder→owner direction; SIM-2 does not use it
        // (it is a holder-side eviction test). Left at 0 — first-hand default.
        g_owner_from_holder: 0.0,
        // The eviction-priority key: holder's first-hand record of the owner's
        // service to it. Shadowed from ground-truth (legitimately first-hand).
        g_holder_from_owner: owner.true_g_holder_from_owner,
        v_dem: owner.true_g_holder_from_owner, // demonstrated scale proxy (first-hand)
        recent_rate_p: 1.0,
        trend_d: 0.0,
        pos_pass: 1,
        pos_fail: 0,
        pos_timeout: 0,
        observed_volume: owner.true_g_holder_from_owner,
        observed_tau: owner.true_tau,
        addr_subnet: index as u32,
        addr_geo: 0,
        latency_ms: 10.0,
        reachable: true,
        scrutiny: 0.0,
        master_id: IdentityPub(master),
        device_id: DeviceId(device),
    }
}

/// Shadow the whole population into a first-hand observation list, preserving
/// index order so the evaluator can map an observation back to its hidden owner.
pub fn observe_all(owners: &[OwnerGt]) -> Vec<FirstHandObs> {
    owners
        .iter()
        .enumerate()
        .map(|(i, o)| observe(o, i))
        .collect()
}

/// Shadow the population into the holder's two-level eviction view: one
/// [`OwnerEvictionView`] per owner, each carrying that owner's first-hand
/// observation (the inter-owner `G(h←O)` key) and ONE symbol with the owner's
/// declared importance `ι`.
///
/// SIM-2 is an inter-owner-level test (each owner places a single symbol on the
/// focus holder), so each view holds exactly one symbol. The symbol id is the
/// owner index — opaque and first-hand (the holder labels what it stores). The
/// importance is the owner's declared ι, shadowed from `OwnerGt::declared_iota`;
/// like every other field here it is OWNER-DECLARED metadata, NOT a ground-truth
/// archetype/hazard (there is nowhere on these types to put one).
pub fn observe_eviction_views(owners: &[OwnerGt]) -> Vec<OwnerEvictionView> {
    owners
        .iter()
        .enumerate()
        .map(|(i, o)| OwnerEvictionView {
            obs: observe(o, i),
            // SIM-2 predates the A.4 loyalty depth; these views carry no depth (κ_O
            // collapses to bare g_ho for this legacy inter-owner test).
            depth: 0.0,
            symbols: vec![SymbolDecl {
                id: SymbolId(i as u64),
                importance: o.declared_iota,
                // SIM-2 predates the Р-7 volume cap; volume is inert here (the harness
                // passes RetentionCap::disabled()). Uniform unit volume keeps it simple.
                volume: 1.0,
            }],
        })
        .collect()
}

/// Build the production-node first-hand view of a single observed `(V0, τ0)`
/// surface point with a PoS pass/fail history there (SIM-12/SIM-13 surface
/// scenarios). This is exactly what a real node would hold after placing data on a
/// holder at one volume and challenging it over time — ONE slice, plus PoS
/// outcomes. The `v`-axis and long `τ` are NOT observed (that is the whole point —
/// off-sample is the shared offline prior, not an observation). No ground-truth
/// hazard form is read; there is nowhere on [`FirstHandObs`] to put it.
pub fn observe_failure_point(v0: f64, tau0: f64, pass: u32, fail: u32) -> FirstHandObs {
    FirstHandObs {
        g_owner_from_holder: 0.0,
        g_holder_from_owner: 0.0,
        // The demonstrated scale is exactly the volume we proved at this point.
        v_dem: v0,
        recent_rate_p: if pass + fail > 0 {
            pass as f64 / (pass + fail) as f64
        } else {
            0.0
        },
        trend_d: 0.0,
        pos_pass: pass,
        pos_fail: fail,
        pos_timeout: 0,
        observed_volume: v0,
        observed_tau: tau0,
        addr_subnet: 0,
        addr_geo: 0,
        latency_ms: 10.0,
        reachable: true,
        scrutiny: 0.0,
        master_id: IdentityPub([0u8; 32]),
        device_id: DeviceId([0u8; 32]),
    }
}
