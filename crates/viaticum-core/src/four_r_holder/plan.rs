//! The holder's eviction plan (T4 + T8 + Р-20): kernel decision → which holdings go, and why.

use super::quota::{QuotaInputs, QuotaState};
use super::view::{HolderView, HoldingKey, ViewHolding};
use crate::four_r::{EvictionDecision, SymbolSlot};

/// Why a holding is in the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum PlannedWhy {
    /// Р-7 cap trim: the owner parks more than its `V_ret` (no φ stop).
    Cap,
    /// The owner asked to delete it (cooldown running): first in the pressure list.
    MarkedForDelete,
    /// Pressure relief down to `s_target`.
    Pressure,
}

/// One planned drop.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlannedDrop {
    pub key: HoldingKey,
    pub bytes: u64,
    pub why: PlannedWhy,
}

/// What 4R would drop on this tick.
#[derive(Debug, Clone, PartialEq)]
pub struct EvictionPlan {
    /// In order: every cap trim (kernel order), then MarkedForDelete, then pressure.
    pub drops: Vec<PlannedDrop>,
    pub cap_bytes: u64,
    pub mfd_bytes: u64,
    pub pressure_bytes: u64,
    /// Candidates skipped because dropping them would cross the `hard_quota` floor.
    pub floor_skipped_bytes: u64,
    /// φ forecast after the plan (−1.0 when `Q ≤ 0`).
    pub phi_forecast_after: f64,
}

/// Plan the drops of one tick.
///
/// Not evicting ⇒ empty plan. Otherwise, with `H_live = H − H_notified` and `planned = 0`, a
/// candidate of `b` bytes is SKIPPED (counted in `floor_skipped_bytes`) when `hard > 0` and
/// `H_live − planned − b < hard` (the floor bounds both lists). (1) Every `cap_drops` slot in
/// kernel order — no φ stop, only the floor. (2) While `φ_after = (Q − (H_live − planned))/Q
/// < s_target`: first `marked_for_delete` (block order), then `drop_order`; the same floor.
/// With `Q ≤ 0`, `φ_after = −1` throughout: pressure takes everything the floor lets through.
pub fn plan_eviction(
    view: &HolderView,
    decision: &EvictionDecision,
    q: &QuotaState,
    quota: &QuotaInputs,
    s_target: f64,
) -> EvictionPlan {
    let mut plan = EvictionPlan {
        drops: Vec::new(),
        cap_bytes: 0,
        mfd_bytes: 0,
        pressure_bytes: 0,
        floor_skipped_bytes: 0,
        phi_forecast_after: q.phi_forecast,
    };
    if !decision.phase.evicting {
        return plan;
    }
    let h_live = quota.h_all_bytes as i128 - quota.h_notified_bytes as i128;
    let hard = quota.hard_quota_bytes as i128;
    let mut planned: i128 = 0;
    let phi_after = |planned: i128| -> f64 {
        if q.q_nonpositive {
            -1.0
        } else {
            (q.q_bytes - (h_live - planned)) as f64 / q.q_bytes as f64
        }
    };
    let slot = |s: &SymbolSlot| -> ViewHolding { view.holdings[s.owner_idx][s.symbol_idx] };

    // (1) Cap trims: all of them, the floor only.
    for s in &decision.cap_drops {
        let h = slot(s);
        let b = h.bytes as i128;
        if hard > 0 && h_live - planned - b < hard {
            plan.floor_skipped_bytes += h.bytes;
            continue;
        }
        planned += b;
        plan.cap_bytes += h.bytes;
        plan.drops.push(PlannedDrop {
            key: h.key,
            bytes: h.bytes,
            why: PlannedWhy::Cap,
        });
    }

    // (2) Pressure down to s_target: MarkedForDelete first, then the kernel's drop order.
    let pressure_candidates = view
        .marked_for_delete
        .iter()
        .map(|h| (*h, PlannedWhy::MarkedForDelete))
        .chain(
            decision
                .drop_order
                .iter()
                .map(|s| (slot(s), PlannedWhy::Pressure)),
        );
    for (h, why) in pressure_candidates {
        if phi_after(planned) >= s_target {
            break;
        }
        let b = h.bytes as i128;
        if hard > 0 && h_live - planned - b < hard {
            plan.floor_skipped_bytes += h.bytes;
            continue;
        }
        planned += b;
        match why {
            PlannedWhy::MarkedForDelete => plan.mfd_bytes += h.bytes,
            _ => plan.pressure_bytes += h.bytes,
        }
        plan.drops.push(PlannedDrop {
            key: h.key,
            bytes: h.bytes,
            why,
        });
    }
    plan.phi_forecast_after = phi_after(planned);
    plan
}
