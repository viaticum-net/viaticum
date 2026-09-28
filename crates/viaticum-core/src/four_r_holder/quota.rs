//! Quota and φ of the holder (Р-12, Р-14): `Q = min(soft, H + free − reserve)` with holdings
//! counted ONCE, the actual φ (what is on disk) and the forecast φ (what will be on disk once
//! the notified holdings leave).

use crate::types::{HoldingRecord, HoldingStatus};

/// Raw quota inputs of one decision, as the daemon read them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct QuotaInputs {
    /// `H`: Σ `total_bytes` over ALL holdings (incl. notified, MarkedForDelete, own master).
    pub h_all_bytes: u64,
    /// Σ over holdings with `drop_notice_sent_at` set (leaving within the notice window).
    pub h_notified_bytes: u64,
    /// Σ over `MarkedForDelete` holdings WITHOUT a notice.
    pub h_mfd_bytes: u64,
    /// Free bytes on the data-dir filesystem, as reported. `0` is AMBIGUOUS in В-0 (disk full
    /// or mount not found) — flagged, and the tick is excluded from the measures (`4r-i52`).
    pub disk_free_bytes: u64,
    /// `[storage] soft_quota` in bytes; `0` = no configured cap.
    pub soft_quota_bytes: u64,
    /// `[storage] disk_reserve` in bytes.
    pub disk_reserve_bytes: u64,
    /// `[storage] hard_quota` in bytes: the eviction FLOOR (`0` = none).
    pub hard_quota_bytes: u64,
}

impl QuotaInputs {
    /// Aggregate the holdings of one read of HOLDINGS plus the raw quota numbers.
    pub fn from_holdings(
        h: &[HoldingRecord],
        disk_free: u64,
        soft: u64,
        reserve: u64,
        hard: u64,
    ) -> Self {
        let mut q = QuotaInputs {
            h_all_bytes: 0,
            h_notified_bytes: 0,
            h_mfd_bytes: 0,
            disk_free_bytes: disk_free,
            soft_quota_bytes: soft,
            disk_reserve_bytes: reserve,
            hard_quota_bytes: hard,
        };
        for r in h {
            q.h_all_bytes += r.total_bytes;
            if r.drop_notice_sent_at.is_some() {
                q.h_notified_bytes += r.total_bytes;
            } else if r.status == HoldingStatus::MarkedForDelete {
                q.h_mfd_bytes += r.total_bytes;
            }
        }
        q
    }
}

/// The holder's quota state derived from [`QuotaInputs`].
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct QuotaState {
    /// `Q = min(soft, H + free − reserve)`; `soft = 0` ⇒ `Q = H + free − reserve` [bytes].
    pub q_bytes: i128,
    /// `(Q − H)/Q`: the free share of the quota NOW (acceptance, "is there room").
    pub phi_actual: f64,
    /// `(Q − (H − H_notified))/Q`: the free share once the notified bytes leave (latch and
    /// pressure, Р-14).
    pub phi_forecast: f64,
    /// `max(0, Q − H)` [bytes].
    pub free_now_bytes: u64,
    /// `Q ≤ 0` ⇒ both φ = −1.0 and `free_now = 0`.
    pub q_nonpositive: bool,
    /// The reported free disk was exactly 0 (disk full or mount not found — ambiguous).
    pub disk_free_zero: bool,
    /// false ⇔ `disk_free_zero`: this tick is excluded from the R1/R2 measures (`4r-i52`).
    pub measure_valid: bool,
}

/// Р-12 quota: holdings counted once (the old `compute_effective_quota` subtracts them twice,
/// because `disk_free` already excludes them), arithmetic in `i128`, no silent "0 = unlimited".
pub fn quota_state(q: &QuotaInputs) -> QuotaState {
    let h = q.h_all_bytes as i128;
    let base = h + q.disk_free_bytes as i128 - q.disk_reserve_bytes as i128;
    let q_bytes = if q.soft_quota_bytes == 0 {
        base
    } else {
        base.min(q.soft_quota_bytes as i128)
    };
    let disk_free_zero = q.disk_free_bytes == 0;
    if q_bytes <= 0 {
        return QuotaState {
            q_bytes,
            phi_actual: -1.0,
            phi_forecast: -1.0,
            free_now_bytes: 0,
            q_nonpositive: true,
            disk_free_zero,
            measure_valid: !disk_free_zero,
        };
    }
    let qf = q_bytes as f64;
    let h_live = h - q.h_notified_bytes as i128;
    QuotaState {
        q_bytes,
        phi_actual: (q_bytes - h) as f64 / qf,
        phi_forecast: (q_bytes - h_live) as f64 / qf,
        free_now_bytes: (q_bytes - h).max(0) as u64,
        q_nonpositive: false,
        disk_free_zero,
        measure_valid: !disk_free_zero,
    }
}
