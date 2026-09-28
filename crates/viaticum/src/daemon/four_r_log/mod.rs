// four_r_log — the ONLY place the daemon writes 4R lines (target `viaticum::four_r`).
//
// В-0: 4R runs in SHADOW. These lines are its whole output (plus its own latch row): what 4R
// would do, next to what the old path did. Nothing here is read back by any decision.
//
//   `four_r: pressure tick`  INFO   one per pressure tick (summary, measures, old plan)
//   `four_r: owner`          DEBUG  one per in-view owner of the tick
//   `four_r: offer`          INFO when the shadow disagrees with the old answer, else DEBUG
//                                   (one per offer shadow; В-0b)
//   `four_r: record`         DEBUG  the raw replay record, `rec=<JSON one line>` — built only
//                                   when DEBUG of this target is on (4r-i50)
//
// Masters and blocks are printed as full hex (the scenario compares prefixes with
// `node_identity`); absent optional values print as `-`.

use tracing::{debug, info, warn};
use viaticum_core::budget::DiskPressure;
use viaticum_core::four_r_holder::{
    HolderAdmit, OfferIn, OldPlan, QuotaInputs, RawRecord, ShadowOffer, ShadowTick,
};
use viaticum_core::types::{IdentityPub, hex_encode};

#[cfg(test)]
pub(crate) mod tests;

fn hex_or_dash(m: Option<&IdentityPub>) -> String {
    m.map_or_else(|| "-".to_string(), |m| hex_encode(&m.0))
}

fn f64_or_dash(v: Option<f64>) -> String {
    v.map_or_else(|| "-".to_string(), |v| format!("{v:?}"))
}

fn usize_or_dash(v: Option<usize>) -> String {
    v.map_or_else(|| "-".to_string(), |v| v.to_string())
}

fn pressure_name(p: DiskPressure) -> &'static str {
    match p {
        DiskPressure::Normal => "Normal",
        DiskPressure::Soft => "Soft",
        DiskPressure::Hard => "Hard",
    }
}

/// The per-tick summary (INFO) and one DEBUG line per in-view owner.
pub(crate) fn log_pressure_tick(tick: &ShadowTick, quota: &QuotaInputs, old: &OldPlan) {
    let q = &tick.quota;
    info!(
        target: "viaticum::four_r",
        mode = "shadow",
        phi_actual = ?q.phi_actual,
        phi_forecast = ?q.phi_forecast,
        q_bytes = q.q_bytes as i64,
        h_bytes = quota.h_all_bytes,
        h_notified_bytes = quota.h_notified_bytes,
        h_mfd_bytes = quota.h_mfd_bytes,
        disk_free_zero = q.disk_free_zero,
        measure_valid = q.measure_valid,
        q_nonpositive = q.q_nonpositive,
        phase_prev = tick.phase_prev.evicting,
        phase = tick.decision.phase.evicting,
        accept_ok = tick.decision.accept_ok,
        owners = tick.owners.len(),
        cap_bytes = tick.plan.cap_bytes,
        mfd_bytes = tick.plan.mfd_bytes,
        pressure_bytes = tick.plan.pressure_bytes,
        floor_skipped_bytes = tick.plan.floor_skipped_bytes,
        zk_bytes = tick.zero_kappa.total,
        zk_never_asked_bytes = tick.zero_kappa.never_asked,
        zk_asked_bytes = tick.zero_kappa.asked,
        zk_serving_bytes = tick.zero_kappa.serving_unconfirmed,
        first_owner_old = %hex_or_dash(tick.divergence.first_old.as_ref()),
        first_owner_new = %hex_or_dash(tick.divergence.first_new.as_ref()),
        top10_overlap = tick.divergence.top10_overlap,
        kendall_tau = %f64_or_dash(tick.divergence.kendall_tau),
        old_pressure = %pressure_name(old.pressure),
        old_immediate = old.immediate.len(),
        old_notices = old.notices.len(),
        "four_r: pressure tick"
    );
    for o in &tick.owners {
        debug!(
            target: "viaticum::four_r",
            rank_new = o.rank_new,
            rank_old = %usize_or_dash(o.rank_old),
            master = %hex_encode(&o.master.0),
            kappa = ?o.kappa,
            v_ret_gb = %f64_or_dash(o.v_ret_gb),
            parked_bytes = o.parked_bytes,
            notified_bytes = o.notified_bytes,
            zk_class = %o.zk_class.map_or_else(|| "-".to_string(), |c| format!("{c:?}")),
            cap_bytes = o.cap_bytes,
            pressure_bytes = o.pressure_bytes,
            "four_r: owner"
        );
    }
}

/// One line per offer shadow (В-0b). INFO when 4R would answer differently from the old rule
/// (`old_accept ≠ new ∈ {free, preempt}`), DEBUG otherwise. `skipped_since_last`: offers whose
/// shadow was skipped because the single shadow slot was busy (4r-i50).
pub(crate) fn log_offer(
    offer: &OfferIn,
    out: &ShadowOffer,
    old_accept: bool,
    skipped_since_last: u64,
) {
    let victim = match &out.admit {
        HolderAdmit::Preempt { victim, .. } => Some(victim),
        _ => None,
    };
    let old = if old_accept { "accept" } else { "reject" };
    let new = out.admit.tag();
    macro_rules! offer_line {
        ($lvl:ident) => {
            $lvl!(
                target: "viaticum::four_r",
                mode = "shadow",
                owner = %hex_encode(&offer.owner.0),
                block_id = %hex_encode(&offer.block.0),
                offer_bytes = offer.offer_bytes,
                old = %old,
                new = %new,
                reason = %out.admit.reason().unwrap_or_else(|| "-".to_string()),
                victim = %hex_or_dash(victim),
                kappa_offerer = ?out.offerer_kappa,
                kappa_victim = %f64_or_dash(out.victim_kappa),
                margin = ?out.margin,
                v_ret_offerer_gb = %f64_or_dash(out.v_ret_offerer_gb),
                parked_offerer_bytes = out.offerer_parked_bytes,
                phi_actual = ?out.quota.phi_actual,
                phase = out.phase.evicting,
                skipped_since_last,
                "four_r: offer"
            )
        };
    }
    if old_accept != out.admit.admits() {
        offer_line!(info);
    } else {
        offer_line!(debug);
    }
}

/// Build and log the raw replay record — ONLY when DEBUG of `viaticum::four_r` is enabled
/// (W-6: on a large NAS the pressure record is megabytes; `make` is not even called
/// otherwise). One line: `four_r: record rec=<JSON>`.
pub(crate) fn log_record_with(make: impl FnOnce() -> RawRecord) {
    if !tracing::enabled!(target: "viaticum::four_r", tracing::Level::DEBUG) {
        return;
    }
    let rec = make();
    match serde_json::to_string(&rec) {
        Ok(json) => debug!(target: "viaticum::four_r", rec = %json, "four_r: record"),
        Err(e) => warn!(
            target: "viaticum::four_r",
            err = %e,
            "four_r: record not serialisable — skipped"
        ),
    }
}
