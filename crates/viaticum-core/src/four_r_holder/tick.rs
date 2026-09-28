//! One shadow pressure tick: the same snapshot the old path decided on → what 4R would do.

use std::collections::HashMap;

use super::measure::{
    OrderDivergence, ZeroKappaClass, compare_owner_orders, placement_presence_by_master,
    zero_kappa_class,
};
use super::plan::{EvictionPlan, PlannedWhy, plan_eviction};
use super::quota::{QuotaInputs, QuotaState, quota_state};
use super::view::{HolderView, HoldingKey, build_holder_view};
use super::{FourRParams, ZERO_KAPPA_EPS};
use crate::budget::DiskPressure;
use crate::four_r::{
    EvictPhase, EvictionDecision, Hysteresis, eviction_order_in_phase, owner_order_by_key,
    relay_latch,
};
use crate::types::{HoldingRecord, IdentityPub, PairLedger, PeerRecord, SymbolPlacement};

/// The old path's plan of this tick, taken from `evaluate_pressure`'s result BEFORE the old
/// path acts on it (W-1): exactly the set it then executes.
#[derive(Debug, Clone, PartialEq)]
pub struct OldPlan {
    pub pressure: DiskPressure,
    /// Immediate evictions, in the old path's order.
    pub immediate: Vec<HoldingKey>,
    /// Advance drop notices, in the old path's order.
    pub notices: Vec<HoldingKey>,
}

/// Everything one shadow pressure tick reads (one snapshot).
#[derive(Debug, Clone)]
pub struct ShadowPressureInput<'a> {
    pub holdings: &'a [HoldingRecord],
    pub ledgers: &'a [(IdentityPub, PairLedger)],
    pub placements: &'a [SymbolPlacement],
    pub peers: &'a [PeerRecord],
    pub own_master: IdentityPub,
    pub quota: QuotaInputs,
    /// The persisted latch before this tick.
    pub phase_prev: EvictPhase,
    /// The old path's owner order ([`super::old_owner_order`] with the old path's trust).
    pub old_owner_order: Vec<IdentityPub>,
    pub old_plan: OldPlan,
}

/// One in-view owner of the tick.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnerShadowRow {
    pub master: IdentityPub,
    /// Position in the new (κ) order, 0 = squeezed first.
    pub rank_new: usize,
    /// Position in the old order (`None`: not in it).
    pub rank_old: Option<usize>,
    pub kappa: f64,
    /// `V_ret` [gb] (`None`: cap disabled).
    pub v_ret_gb: Option<f64>,
    /// In-view bytes (`V_parked`).
    pub parked_bytes: u64,
    /// Bytes of this owner's notified holdings (outside the view).
    pub notified_bytes: u64,
    /// Set only when κ < [`ZERO_KAPPA_EPS`].
    pub zk_class: Option<ZeroKappaClass>,
    pub cap_bytes: u64,
    pub pressure_bytes: u64,
}

/// Parked bytes of the κ = 0 owners, by class (R2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ZeroKappaBytes {
    pub total: u64,
    pub never_asked: u64,
    pub asked: u64,
    pub serving_unconfirmed: u64,
}

/// The shadow's result for one pressure tick.
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowTick {
    pub quota: QuotaState,
    pub phase_prev: EvictPhase,
    pub decision: EvictionDecision,
    pub plan: EvictionPlan,
    /// The new owner order (masters, first = squeezed first).
    pub owner_order: Vec<IdentityPub>,
    /// In-view owners, in `owner_order`.
    pub owners: Vec<OwnerShadowRow>,
    pub zero_kappa: ZeroKappaBytes,
    pub divergence: OrderDivergence,
    /// Bytes of holdings of this node's own master (outside the view, Р-20).
    pub own_master_bytes: u64,
}

/// The phase of one tick: the latch rule on the FORECAST φ (Р-14) — unless the tick's measure
/// is invalid (`disk_free = 0`, the node did not read its disk): then the latch does not move
/// at all, the tick runs in the previous phase (`4r-i66`). A blind tick can push the latch
/// EITHER way: with `disk_free = 0`, `Q = H − reserve`, so the actual φ is ≤ 0 and the
/// forecast is `φ_forecast = (H_n − reserve)/Q` — about `H_n/Q` for a small reserve. Few
/// notified bytes ⇒ the forecast falls below `s_hard` and the latch would switch ON; many
/// notified bytes ⇒ `H_n/Q ≥ s_target` and a latch that was ON would be RELEASED on a disk
/// nobody read. Either decision, persisted, would be carried into the next valid tick's
/// deadband.
pub fn tick_phase(q: &QuotaState, hyst: Hysteresis, prev: EvictPhase) -> EvictPhase {
    if q.measure_valid {
        relay_latch(q.phi_forecast, hyst, prev)
    } else {
        prev
    }
}

/// The shadow pressure tick. The phase is [`tick_phase`] (the latch on the FORECAST φ, frozen
/// on an invalid tick); the plan uses the same κ vector as the order and the cap (one key).
pub fn shadow_pressure_tick(input: &ShadowPressureInput, p: &FourRParams) -> ShadowTick {
    let view: HolderView = build_holder_view(input.holdings, input.ledgers, &input.own_master, p);
    let q = quota_state(&input.quota);
    let cap = p.retention_cap();
    let decision = eviction_order_in_phase(
        &view.views,
        &view.kappa,
        q.phi_forecast,
        p.hyst,
        tick_phase(&q, p.hyst, input.phase_prev),
        &cap,
    );
    let plan = plan_eviction(&view, &decision, &q, &input.quota, p.hyst.s_target);
    let order_idx = owner_order_by_key(&view.views, &view.kappa);
    let owner_order: Vec<IdentityPub> = order_idx.iter().map(|&i| view.masters[i]).collect();

    let presence = placement_presence_by_master(input.placements, input.peers);
    let old_rank: HashMap<&IdentityPub, usize> = input
        .old_owner_order
        .iter()
        .enumerate()
        .map(|(i, m)| (m, i))
        .collect();
    let mut notified_by: HashMap<IdentityPub, u64> = HashMap::new();
    for h in &view.notified {
        *notified_by.entry(h.key.owner_id).or_default() += h.bytes;
    }
    let mut planned_by: HashMap<(IdentityPub, bool), u64> = HashMap::new();
    for d in &plan.drops {
        // Per-owner columns count cap and pressure drops; MarkedForDelete is the owner's own
        // deletion, reported only in the tick total (`plan.mfd_bytes`).
        if d.why == PlannedWhy::MarkedForDelete {
            continue;
        }
        let is_cap = d.why == PlannedWhy::Cap;
        *planned_by.entry((d.key.owner_id, is_cap)).or_default() += d.bytes;
    }

    let mut zero_kappa = ZeroKappaBytes::default();
    let mut owners = Vec::with_capacity(order_idx.len());
    for (rank_new, &oi) in order_idx.iter().enumerate() {
        let master = view.masters[oi];
        let kappa = view.kappa[oi];
        let parked_bytes = view.parked_bytes(oi);
        let zk_class = if kappa < ZERO_KAPPA_EPS {
            let c = zero_kappa_class(presence.get(&master));
            zero_kappa.total += parked_bytes;
            match c {
                ZeroKappaClass::NeverAsked => zero_kappa.never_asked += parked_bytes,
                ZeroKappaClass::Asked => zero_kappa.asked += parked_bytes,
                ZeroKappaClass::ServingUnconfirmed => {
                    zero_kappa.serving_unconfirmed += parked_bytes
                }
            }
            Some(c)
        } else {
            None
        };
        owners.push(OwnerShadowRow {
            master,
            rank_new,
            rank_old: old_rank.get(&master).copied(),
            kappa,
            v_ret_gb: cap.active().then(|| cap.v_ret(kappa)),
            parked_bytes,
            notified_bytes: notified_by.get(&master).copied().unwrap_or(0),
            zk_class,
            cap_bytes: planned_by.get(&(master, true)).copied().unwrap_or(0),
            pressure_bytes: planned_by.get(&(master, false)).copied().unwrap_or(0),
        });
    }
    let divergence = compare_owner_orders(&input.old_owner_order, &owner_order);

    ShadowTick {
        quota: q,
        phase_prev: input.phase_prev,
        decision,
        plan,
        owner_order,
        owners,
        zero_kappa,
        divergence,
        own_master_bytes: view.own_master_bytes,
    }
}
