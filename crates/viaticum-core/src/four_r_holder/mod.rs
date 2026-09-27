//! Holder-side 4R bridge (В-0): daemon records (HOLDINGS, PAIR_LEDGER, placements, PEERS,
//! quota) → kernel inputs → kernel decisions ([`crate::four_r`]) → holder plans. Pure: no
//! database, no clock, no async — the daemon reads the tables and hands the rows in.
//!
//! In В-0 every consumer is the SHADOW: the daemon logs what 4R would do next to what the
//! old path did, and decides nothing on it. В-1b/В-2 apply the same plans, so the shadow
//! measures exactly the functions enforce will call.
//!
//! **Seat (the load-bearing mapping, audit О-1).** The holder ranks an owner `O` by κ_O —
//! the service `O` gives to THIS node. In the ledger row of master `O` that is
//! `gb_days_they_store_for_us` (and its slow twin `depth_of_their_service`), NOT
//! `gb_days_we_store_for_them` (the seat table on [`PairLedger`]). [`holder_kappa`] is the
//! only place that reads the row for κ; the view, the cap, the offer shadow and the log
//! record all take κ from it (one key, A.14).
//!
//! **Units.** "gb" = bytes / [`BYTES_PER_GB`] (2^30), converted by [`bytes_to_gb`] only;
//! κ in gb·days (scaled days, as the ledger integrates them); the preemption margin through
//! [`PAIR_LEDGER_LAMBDA`], the same `λ` the ledger leaks at.

use crate::config::FourRCfg;
use crate::constants::{BYTES_PER_GB, PAIR_LEDGER_LAMBDA};
use crate::four_r::{
    AdmitParams, DepthParams, FirstHandObs, Hysteresis, RetentionCap, capital_steady_state,
    kappa_key,
};
use crate::types::{DeviceId, IdentityPub, PairLedger};

mod measure;
mod offer;
mod plan;
mod quota;
mod record;
mod tick;
mod view;

pub use measure::{
    OrderDivergence, Presence, ZeroKappaClass, compare_owner_orders, old_owner_order,
    placement_presence_by_master, zero_kappa_class,
};
pub use offer::{HolderAdmit, HolderReject, OfferIn, ShadowOffer, raw_offer_record, shadow_offer};
pub use plan::{EvictionPlan, PlannedDrop, PlannedWhy, plan_eviction};
pub use quota::{QuotaInputs, QuotaState, quota_state};
pub use record::{
    RAW_RECORD_VERSION, RawAdmitOut, RawHolding, RawOffer, RawOldPlan, RawOut, RawOwner, RawParams,
    RawPeerMaster, RawPlacement, RawPresence, RawRecord, RawRow, RawZeroKappa, raw_pressure_record,
};
pub use tick::{
    OldPlan, OwnerShadowRow, ShadowPressureInput, ShadowTick, ZeroKappaBytes, shadow_pressure_tick,
    tick_phase,
};
pub use view::{HolderView, HoldingKey, ViewHolding, build_holder_view};

#[cfg(test)]
mod tests;

/// Below this κ [gb·days] an owner is in the "zero service" class (audit §10 R2).
pub const ZERO_KAPPA_EPS: f64 = 1e-6;

/// The holder-side 4R dials, in kernel units (from `[four_r]`).
#[derive(Debug, Clone, PartialEq)]
pub struct FourRParams {
    /// Apply 4R decisions. Always false in В-0 (config validation refuses `true`).
    pub enforce: bool,
    /// `V_free` [gb].
    pub v_free_gb: f64,
    /// `c_recip` [days]; `≤ 0` disables the cap.
    pub c_recip_days: f64,
    /// `w_d`: weight of the depth floor in κ_O.
    pub w_d: f64,
    /// `τ_ref` [days]: per-pair `d_ref = τ_ref · v_dem`.
    pub tau_ref_days: f64,
    /// `θ_p`: preemption margin factor.
    pub theta_p: f64,
    /// `V_min` [gb]: margin floor.
    pub v_min_gb: f64,
    /// Relay thresholds `s_hard < s_target < s_soft` on φ.
    pub hyst: Hysteresis,
}

impl FourRParams {
    /// Kernel params from the `[four_r]` config section (already validated by the loader).
    pub fn from_cfg(cfg: &FourRCfg) -> Self {
        FourRParams {
            enforce: cfg.enforce,
            v_free_gb: cfg.v_free_gb,
            c_recip_days: cfg.c_recip_days,
            w_d: cfg.w_d,
            tau_ref_days: cfg.tau_ref_days,
            theta_p: cfg.theta_p,
            v_min_gb: cfg.v_min_gb,
            hyst: Hysteresis {
                s_hard: cfg.s_hard,
                s_target: cfg.s_target,
                s_soft: cfg.s_soft,
            },
        }
    }

    /// Per-pair A.4 params: `d_ref = τ_ref · v_dem` [gb·days], `g* = v_dem / λ` [gb·days]
    /// with `λ` = [`PAIR_LEDGER_LAMBDA`] (the ledger's own leak). `v_dem = 0` ⇒ `d_ref = 0`
    /// (the kernel saturates the floor) and `g* = 0` (no floor): κ = g.
    pub fn depth_params(&self, v_dem_gb: f64) -> DepthParams {
        DepthParams {
            w_d: self.w_d,
            d_ref: self.tau_ref_days * v_dem_gb,
            g_star: capital_steady_state(v_dem_gb, PAIR_LEDGER_LAMBDA),
        }
    }

    /// The Р-7 cap `V_ret = V_free + κ/c_recip` (disabled when `c_recip ≤ 0`).
    pub fn retention_cap(&self) -> RetentionCap {
        RetentionCap {
            v_free: self.v_free_gb,
            c_recip: self.c_recip_days,
        }
    }

    /// Kernel dials of [`crate::four_r::admit_offer`]: the same hysteresis and cap as the
    /// eviction, `λ` = [`PAIR_LEDGER_LAMBDA`] (the margin in the ledger's steady capital).
    pub fn admit_params(&self) -> AdmitParams {
        AdmitParams {
            hyst: self.hyst,
            cap: self.retention_cap(),
            theta_p: self.theta_p,
            v_min: self.v_min_gb,
            lambda: PAIR_LEDGER_LAMBDA,
        }
    }
}

impl Default for FourRParams {
    fn default() -> Self {
        FourRParams::from_cfg(&FourRCfg::default())
    }
}

/// Bytes → the kernel's "gb" (2^30 bytes). The ONE conversion of the bridge.
pub fn bytes_to_gb(bytes: u64) -> f64 {
    bytes as f64 / BYTES_PER_GB
}

/// T1: κ_O of an owner from THIS holder's ledger row for that master. HOLDER SEAT:
/// `g = gb_days_they_store_for_us` (the owner's service to us), `D = depth_of_their_service`,
/// per-pair depth params from `v_dem` ([`FourRParams::depth_params`]). No row ⇒ `0.0`
/// explicitly (a pair with no history has earned nothing, З-15) — never an error, never a
/// skipped owner.
pub fn holder_kappa(row: Option<&PairLedger>, p: &FourRParams) -> f64 {
    match row {
        None => 0.0,
        Some(r) => kappa_key(
            r.gb_days_they_store_for_us,
            r.depth_of_their_service,
            &p.depth_params(r.v_dem),
        ),
    }
}

/// The holder-seat [`FirstHandObs`] of one owner (Р-4, honest defaults): the two capitals by
/// their seat (`g_holder_from_owner` = THEIR service to us — the κ input; `g_owner_from_holder`
/// = OUR service to them), `v_dem`, the current run `(observed_volume, observed_tau)` and the
/// drop counters from the row (no row ⇒ 0). Everything the daemon does not observe per pair
/// is an honest zero / inert value: `recent_rate_p = trend_d = 0`, `pos_* = 0`, `addr_* = 0`,
/// `latency_ms = 0`, `reachable = true` (inert in eviction, З-11), `scrutiny = 1.0`, device
/// = zeros (the pair is a master). The holder-side kernel reads only `g_holder_from_owner`
/// (through κ, which the bridge computes itself) and `observed_tau` (the tie-breaker).
pub fn holder_view_obs(row: Option<&PairLedger>, master: IdentityPub) -> FirstHandObs {
    let r = row.cloned().unwrap_or_default();
    FirstHandObs {
        g_owner_from_holder: r.gb_days_we_store_for_them,
        g_holder_from_owner: r.gb_days_they_store_for_us,
        v_dem: r.v_dem,
        recent_rate_p: 0.0,
        trend_d: 0.0,
        pos_pass: 0,
        pos_fail: 0,
        pos_timeout: 0,
        drop_ann: r.drop_ann,
        drop_silent: r.drop_silent,
        observed_volume: r.observed_volume,
        observed_tau: r.observed_tau,
        addr_subnet: 0,
        addr_geo: 0,
        latency_ms: 0.0,
        reachable: true,
        scrutiny: 1.0,
        master_id: master,
        device_id: DeviceId([0u8; 32]),
    }
}
