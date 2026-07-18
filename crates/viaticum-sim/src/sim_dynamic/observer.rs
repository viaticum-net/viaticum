//! `sim_dynamic` observer — the single trust boundary (anti-oracle choke point).
//!
//! Builds the kernel's first-hand inputs ([`FirstHandObs`], [`OwnerEvictionView`],
//! [`HolderPlacement`]) from a node's FIRST-HAND history ONLY — the per-pair capital
//! state ([`PairCapital`]) and the symbols it physically holds. It **NEVER** reads
//! [`Node::archetype`] or any `true_*` field; there is nowhere on these kernel types
//! to put one (design §10.H — the regression test asserts this can't slip).
//!
//! The discipline (design §10): the observer DERIVES the P/D projections
//! (`recent_rate_p`, `trend_d`) from the recorded first-hand outcomes, it does NOT
//! copy a hidden probability. Capital `g_*` is the threaded leaky-integral state.

use viaticum_core::four_r::{
    FirstHandObs, HolderPlacement, OwnerEvictionView, SymbolDecl, SymbolId,
};
use viaticum_core::types::{DeviceId, IdentityPub};

use crate::sim_dynamic::generator::{DAYS_PER_TICK, HeldSymbol, Node, PairCapital};

/// The canonical observed `τ0` slice every pair is sampled at (the per-tick horizon in
/// days, one week). The observed VOLUME anchor `v0` is NO LONGER a hardcoded const (F5 /
/// D4-leak): it is CONSTRUCTED by the caller from the actual per-holder chunk volume
/// `v_per_symbol = block_volume / k_eff` and threaded into the `observe_*` functions — so
/// the surface is sampled at the SAME scale the block is actually placed at (querying 25 gb
/// with a demonstrated floor of 25 gb ⇒ no spurious off-sample penalty). The dual role from
/// phase B is preserved: `v0` is BOTH the `observed_volume` surface anchor AND the `v_dem`
/// floor (`cap.v_dem.max(v0)`).
pub const OBSERVED_TAU0: f64 = DAYS_PER_TICK;

/// Build the owner `O`'s first-hand observation of holder node `h_node`, given the
/// per-pair capital state (the leaky-integral `g_*`, the recent-outcome window).
///
/// The leak-rate `lambda` and tick `dt` are not needed here (capital is already
/// integrated in `cap`); they enter the D-projection finite difference, which is
/// precomputed in `cap.g_oh`/`cap.g_oh_prev`.
///
/// Anti-oracle: every field comes from `cap` (threaded first-hand capital), the
/// PoS counters (first-hand outcomes), or `h_node`'s OBSERVABLE address/crypto-id.
/// `h_node.archetype` is never touched. `v0` (F5) is the observed-volume anchor the
/// caller derives from the actual per-holder chunk volume.
pub fn observe_pair(cap: &PairCapital, h_node: &Node, dt: f64, v0: f64) -> FirstHandObs {
    let mut master = [0u8; 32];
    master[0] = h_node.master_byte;
    let mut device = [0u8; 32];
    device[0] = h_node.master_byte ^ 0xA5;

    // PoS counters from the recent window (first-hand outcomes).
    let pass = cap.pos_window.iter().filter(|&&p| p).count() as u32;
    let total = cap.pos_window.len() as u32;
    let fail_and_timeout = total.saturating_sub(pass);
    // We do not distinguish fail vs timeout in the windowed counters here for the
    // surface anchor (both are non-passes); the harness records the SPLIT separately
    // for the capital-threading invariant. For the kernel's surface/retention reads,
    // (fail+timeout) is what matters (drop_frac), so we bucket non-passes as fail
    // unless the pair has a recorded timeout split. To keep the observation honest
    // and bit-stable we attribute non-passes to `pos_fail` here (the kernel treats
    // fail and timeout identically for retained_depth's drop_frac; surface uses
    // pass-fraction, also identical). The fail/timeout SPLIT is exercised in the
    // harness invariant test, not needed for the kernel decision.
    let pos_fail = fail_and_timeout;
    let pos_timeout = 0u32;

    // D-projection: finite difference of g_owner_from_holder over one tick.
    let dt = dt.max(1e-9);
    let trend_d = (cap.g_oh - cap.g_oh_prev) / dt;

    FirstHandObs {
        // The holder's service TO me (leaky integral, first-hand confirmed).
        g_owner_from_holder: cap.g_oh,
        // My service to the holder (the eviction key; bilaterally observable).
        g_holder_from_owner: cap.g_ho,
        v_dem: cap.v_dem.max(v0),
        // P-projection: recent pass-fraction over the window.
        recent_rate_p: cap.recent_rate_p(),
        trend_d,
        pos_pass: pass,
        pos_fail,
        pos_timeout,
        // C2FARM-3 (A.2): the owner-side drop counters feed retained_depth's drop_frac.
        drop_ann: cap.drop_ann,
        drop_silent: cap.drop_silent,
        observed_volume: v0,
        observed_tau: OBSERVED_TAU0,
        addr_subnet: h_node.addr_subnet,
        addr_geo: 0,
        latency_ms: 10.0,
        reachable: h_node.present,
        // A.5: the pair's live suspicion σ (finally a live field). NOTE: the kernel does
        // NOT read `scrutiny` in any decision (grep-verified) — this is an HONEST INERT
        // wiring in the sim; the σ→cadence/decoy-DR consumers are daemon-side.
        scrutiny: cap.sigma,
        master_id: IdentityPub(master),
        device_id: DeviceId(device),
        // NOTE: nowhere to write archetype / true_* — anti-oracle by construction.
    }
}

/// Build the eviction view of holder node `h` over ALL owners whose ALIVE symbols
/// it currently stores. One [`OwnerEvictionView`] per owner, carrying that owner's
/// first-hand pair observation plus the pair's loyalty `depth` — together the
/// inputs of the inter-owner κ_O key (A.14: `g_ho` + D-floor) — and the owner's
/// symbols on this holder (each with its declared ι).
///
/// `cap_of(owner_idx)` returns the holder's per-pair capital with that owner
/// (`g_holder_from_owner` = `G(h←O)`, the holder's first-hand record of THAT
/// OWNER's reciprocal service to the holder — the owner keeping MY data alive,
/// proven by MY PoS of my symbols stored at that owner; unfakeable by the owner).
/// `owner_node(owner_idx)` gives the owner's observable address for the obs (the
/// holder observes the OWNER's connection facts).
///
/// `owners` is the caller-supplied owner ORDER (the distinct alive-symbol owners on
/// `h`). The caller owns the order so the SAME slice can map the resulting drop
/// slots back (single source of truth) AND so the order can be a deterministic
/// shuffle rather than ascending node-index — `eviction_order` sorts STABLY, so the
/// input order is the tie-break among equal-`g_ho` owners; an ascending-index input
/// would systematically sacrifice low-index owners first (an artifact, not the
/// reciprocity signal). See `run_eviction`.
pub fn observe_eviction_views<'a>(
    h: &Node,
    owners: &[usize],
    mut cap_of: impl FnMut(usize) -> &'a PairCapital,
    mut owner_node: impl FnMut(usize) -> ObsAddr,
    dt: f64,
    v0: f64,
) -> Vec<OwnerEvictionView> {
    owners
        .iter()
        .map(|&owner_idx| {
            let cap = cap_of(owner_idx);
            let addr = owner_node(owner_idx);
            let obs = observe_pair_from_addr(cap, &addr, dt, v0);
            let symbols: Vec<SymbolDecl> = h
                .holdings
                .iter()
                .filter(|s| s.alive && s.owner == owner_idx)
                .map(|s| SymbolDecl {
                    // Opaque, first-hand id: (block, owner) folded deterministically.
                    id: SymbolId(((owner_idx as u64) << 32) ^ s.block as u64),
                    importance: s.iota,
                    // Per-symbol volume the holder physically stores — the Р-7 cap trims
                    // V_parked(O) = Σ volume down to V_ret (A.14).
                    volume: s.volume,
                })
                .collect();
            // A.4 loyalty depth of THIS owner→holder direction ("O served me"), the
            // same first-hand cell `g_ho` is read from — feeds the κ_O W10 floor.
            OwnerEvictionView {
                obs,
                depth: cap.depth_ho,
                symbols,
            }
        })
        .collect()
}

/// The observable address of a peer (subnet + master byte + presence) — the only
/// connection facts the obs needs when the peer is the OWNER (not a `Node` we hold
/// the full god-view of in this call).
#[derive(Debug, Clone, Copy)]
pub struct ObsAddr {
    pub addr_subnet: u32,
    pub master_byte: u8,
    pub present: bool,
}

/// Like [`observe_pair`] but from a bare [`ObsAddr`] (used by the eviction view,
/// where the peer is the owner whose `Node` we are not holding by reference here).
fn observe_pair_from_addr(cap: &PairCapital, addr: &ObsAddr, dt: f64, v0: f64) -> FirstHandObs {
    let mut master = [0u8; 32];
    master[0] = addr.master_byte;
    let mut device = [0u8; 32];
    device[0] = addr.master_byte ^ 0xA5;

    let pass = cap.pos_window.iter().filter(|&&p| p).count() as u32;
    let total = cap.pos_window.len() as u32;
    let pos_fail = total.saturating_sub(pass);

    let dt = dt.max(1e-9);
    let trend_d = (cap.g_oh - cap.g_oh_prev) / dt;

    FirstHandObs {
        g_owner_from_holder: cap.g_oh,
        g_holder_from_owner: cap.g_ho,
        v_dem: cap.v_dem.max(v0),
        recent_rate_p: cap.recent_rate_p(),
        trend_d,
        pos_pass: pass,
        pos_fail,
        pos_timeout: 0,
        // C2FARM-3 (A.2): owner-side drop counters → retained_depth drop_frac.
        drop_ann: cap.drop_ann,
        drop_silent: cap.drop_silent,
        observed_volume: v0,
        observed_tau: OBSERVED_TAU0,
        addr_subnet: addr.addr_subnet,
        addr_geo: 0,
        latency_ms: 10.0,
        reachable: addr.present,
        // A.5: live suspicion σ (inert in the sim — kernel reads no scrutiny; daemon-side).
        scrutiny: cap.sigma,
        master_id: IdentityPub(master),
        device_id: DeviceId(device),
    }
}

/// Build the owner's per-holder placement view for the per-symbol survival forecast
/// / DR check: one [`HolderPlacement`] per holder storing a symbol of the block.
///
/// `caps[i]` is the owner's capital with holder `holders[i]`; `ladder_iotas[i]` is
/// the owner's full ι-ladder on that holder (all the owner's symbols there), and
/// `symbol_in_ladder[i]` is which rung this block's symbol sits at.
pub fn observe_placements(
    holders: &[&Node],
    caps: &[&PairCapital],
    ladder_iotas: &[Vec<f64>],
    symbol_in_ladder: &[usize],
    dt: f64,
    v0: f64,
) -> Vec<HolderPlacement> {
    holders
        .iter()
        .enumerate()
        .map(|(i, h)| HolderPlacement {
            obs: observe_pair(caps[i], h, dt, v0),
            ladder_iotas: ladder_iotas[i].clone(),
            symbol_in_ladder: symbol_in_ladder[i],
        })
        .collect()
}

/// Build a flat candidate-observation list for `place`: one [`FirstHandObs`] per
/// present candidate holder, from the owner's first-hand capital with each. Returns
/// the obs in the same order as `candidates` so the caller can map a chosen index
/// back to its holder.
pub fn observe_candidates(
    candidates: &[&Node],
    caps: &[&PairCapital],
    dt: f64,
    v0: f64,
) -> Vec<FirstHandObs> {
    candidates
        .iter()
        .enumerate()
        .map(|(i, h)| observe_pair(caps[i], h, dt, v0))
        .collect()
}

/// The owner's ι-ladder on a holder = the declared ι of ALL the owner's ALIVE
/// symbols stored on that holder (god-view bookkeeping the OWNER itself authored —
/// first-hand metadata, not an oracle). Returned sorted-by-block for determinism,
/// together with the rung of the symbol belonging to `target_block`.
pub fn owner_ladder_on_holder(
    holder: &Node,
    owner_idx: usize,
    target_block: usize,
) -> (Vec<f64>, usize) {
    let mut syms: Vec<&HeldSymbol> = holder
        .holdings
        .iter()
        .filter(|s| s.alive && s.owner == owner_idx)
        .collect();
    syms.sort_by_key(|s| s.block);
    let iotas: Vec<f64> = syms.iter().map(|s| s.iota).collect();
    let rung = syms
        .iter()
        .position(|s| s.block == target_block)
        .unwrap_or(0);
    (iotas, rung)
}
