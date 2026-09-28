//! The shadow's replay record (JSON, [`RAW_RECORD_VERSION`], `4r-i45`): raw inputs as the
//! daemon read them plus the shadow's outputs, so an independent re-computation
//! (`experiments/four_r_replay.py`, written from the spec's formulas, not from this code) can
//! check every decision. The DTO
//! lives here; the daemon serialises it (and builds it only when DEBUG of the 4R target is
//! on, `4r-i50`).
//!
//! Ledger fields go under their ABSOLUTE names, copied from the DB row — never from the
//! assembled view — so a seat inverted inside the bridge shows up as a mismatch.
//! Holding pairs are `(block hex, owner hex)` everywhere; masters are full hex.

use std::collections::{BTreeMap, BTreeSet};

use super::FourRParams;
use super::tick::{ShadowPressureInput, ShadowTick};
use crate::constants::PAIR_LEDGER_LAMBDA;
use crate::four_r_holder::quota::QuotaInputs;
use crate::four_r_holder::view::HoldingKey;
use crate::types::{
    HoldingRecord, HoldingStatus, IdentityPub, PairLedger, PeerRecord, SymbolPlacement, hex_encode,
};

/// Format version of [`RawRecord`]. v2: the pressure record carries the raw inputs of the
/// presence join (`placements`, `peer_masters`, `4r-i67`).
pub const RAW_RECORD_VERSION: u32 = 2;

/// All dials of the decision, in kernel units, plus the `λ` of the margin / `g*`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawParams {
    pub v_free_gb: f64,
    pub c_recip_days: f64,
    pub w_d: f64,
    pub tau_ref_days: f64,
    pub theta_p: f64,
    pub v_min_gb: f64,
    pub s_hard: f64,
    pub s_target: f64,
    pub s_soft: f64,
    pub lambda: f64,
}

/// A ledger row under ABSOLUTE names (copied from the DB row).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawRow {
    /// `gb_days_they_store_for_us`.
    pub g_they: f64,
    /// `gb_days_we_store_for_them`.
    pub g_we: f64,
    /// `depth_of_their_service`.
    pub depth: f64,
    pub v_dem: f64,
    pub observed_tau: f64,
}

/// One holding with its flags.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawHolding {
    pub block: String,
    pub bytes: u64,
    pub importance: f64,
    /// `Active` | `MarkedForDelete` | `Silent`.
    pub status: String,
    /// `drop_notice_sent_at` is set.
    pub notified: bool,
}

/// One owner with holdings on this holder (including this node's own master).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawOwner {
    pub master: String,
    pub row: Option<RawRow>,
    /// In-view bytes: holdings neither notified nor MarkedForDelete; 0 for the own master.
    pub parked_bytes: u64,
    pub notified_bytes: u64,
    /// Pressure record: ALL holdings of this owner, block ascending.
    pub holdings: Vec<RawHolding>,
}

/// Our placements at one holder DEVICE with one status (raw input of the presence join).
/// Grouped by `(device, status)` with a count — the join needs no more, and one row per
/// placement would make the hourly record of a large NAS grow with its own backup (W-6).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawPlacement {
    /// The holder's `DeviceId`, hex.
    pub device: String,
    /// `PlacementStatus` name (`Offered`, `Accepted`, `Alive`, `Uncertain`, `PresumedLost`,
    /// `Lost`, `Deleting`).
    pub status: String,
    pub count: u64,
}

/// `PeerRecord::master_identity` of one device that appears in [`RawPlacement`] — as stored,
/// the placeholder `[0; 32]` included (the replay applies the skip rule itself).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawPeerMaster {
    pub device: String,
    pub master: String,
}

/// Presence of our placements at one master (R2 classes) — the shadow's own join, checked by
/// the replay against its join of `placements` × `peer_masters`.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawPresence {
    pub master: String,
    pub any: bool,
    pub held: bool,
}

/// The old path's plan of the tick.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawOldPlan {
    /// `Normal` | `Soft` | `Hard`.
    pub pressure: String,
    pub immediate: Vec<(String, String)>,
    pub notices: Vec<(String, String)>,
}

/// The offer and the old path's answer to it (offer records).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawOffer {
    pub owner: String,
    pub block: String,
    pub offer_bytes: u64,
    /// What the OLD rule answered (the reply that was sent).
    pub old_accept: bool,
    /// `total_holding_bytes` the old rule decided on (the shadow re-reads HOLDINGS: A3).
    pub old_held_bytes: u64,
    /// This (owner, block) already has a notified holding here (Р-26).
    pub offer_block_notified: bool,
    /// The offerer's ledger row (absolute names), also when it has no holdings here.
    pub offerer_row: Option<RawRow>,
}

/// The shadow's decision on an offer.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawAdmitOut {
    /// `Free` | `Preempt` | `Reject`.
    pub tag: String,
    /// Reject reason (`QuotaNonPositive`, `NotifiedBlock`, `GuardWhileNotified` or the
    /// kernel's `PreemptDisabled`, `Guard`, `NoVictim`, `Margin`, `VictimTooSmall`,
    /// `NoRoomNow`).
    pub reason: Option<String>,
    pub victim: Option<String>,
    /// The candidate victim (least-reciprocal other owner) whether or not displaced.
    pub candidate: Option<String>,
    /// Displaced holdings `(block, owner)` in drop order (Preempt only).
    pub victims: Vec<(String, String)>,
    pub victim_bytes: u64,
    pub offerer_kappa: f64,
    pub victim_kappa: Option<f64>,
    pub margin: f64,
    pub v_ret_offerer_gb: Option<f64>,
    pub offerer_parked_bytes: u64,
    pub offerer_notified_bytes: u64,
}

/// κ = 0 bytes by class.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawZeroKappa {
    pub total: u64,
    pub never_asked: u64,
    pub asked: u64,
    pub serving_unconfirmed: u64,
}

/// The shadow's outputs.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawOut {
    pub phi_actual: f64,
    pub phi_forecast: f64,
    pub q_bytes: i128,
    pub q_nonpositive: bool,
    pub measure_valid: bool,
    pub phase: bool,
    pub accept_ok: bool,
    /// κ of every view owner (view order).
    pub kappa: Vec<(String, f64)>,
    /// In-view bytes of every view owner (W-2).
    pub parked_bytes: Vec<(String, u64)>,
    pub owner_order_new: Vec<String>,
    pub cap: Vec<(String, String)>,
    pub mfd: Vec<(String, String)>,
    pub pressure: Vec<(String, String)>,
    pub floor_skipped_bytes: u64,
    pub phi_forecast_after: f64,
    pub zk: RawZeroKappa,
    /// Class of every κ = 0 view owner.
    pub zk_class: Vec<(String, String)>,
    pub first_owner_old: Option<String>,
    pub first_owner_new: Option<String>,
    pub top10_overlap: u32,
    pub kendall_tau: Option<f64>,
    /// Offer records: the shadow's decision (`None` in pressure records).
    pub admit: Option<RawAdmitOut>,
}

/// One replay record.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RawRecord {
    /// [`RAW_RECORD_VERSION`].
    pub v: u32,
    /// `pressure` | `offer`.
    pub kind: &'static str,
    /// Wall clock of the decision (unix seconds).
    pub now: u64,
    pub own_master: String,
    pub params: RawParams,
    pub quota: QuotaInputs,
    pub phase_prev: bool,
    /// Pressure: EVERY owner with holdings here (incl. own master) with ALL holdings;
    /// offer: aggregates only (`holdings` empty), see `victim_holdings`.
    pub owners: Vec<RawOwner>,
    /// Pressure only: the shadow's presence by master (an output of the join).
    pub presence: Vec<RawPresence>,
    /// Pressure only: our placements by `(device, status)`, device then status ascending.
    pub placements: Vec<RawPlacement>,
    /// Pressure only: the master of every device in `placements` that has a `PeerRecord`,
    /// device ascending (a device without one is absent).
    pub peer_masters: Vec<RawPeerMaster>,
    /// Pressure only.
    pub old_owner_order: Vec<String>,
    /// Pressure only.
    pub old_plan: Option<RawOldPlan>,
    /// Offer only.
    pub offer: Option<RawOffer>,
    /// Offer only: the VIEW holdings of the candidate victim (the least-reciprocal other
    /// owner), block ascending — the only holdings an offer record carries (W-6).
    pub victim_holdings: Option<Vec<RawHolding>>,
    pub out: RawOut,
}

fn hex_m(m: &IdentityPub) -> String {
    hex_encode(&m.0)
}

fn pair(k: &HoldingKey) -> (String, String) {
    (hex_encode(&k.source_block_id.0), hex_m(&k.owner_id))
}

pub(super) fn hex_master(m: &IdentityPub) -> String {
    hex_m(m)
}

pub(super) fn hex_pair(k: &HoldingKey) -> (String, String) {
    pair(k)
}

pub(super) fn raw_params(p: &FourRParams) -> RawParams {
    RawParams {
        v_free_gb: p.v_free_gb,
        c_recip_days: p.c_recip_days,
        w_d: p.w_d,
        tau_ref_days: p.tau_ref_days,
        theta_p: p.theta_p,
        v_min_gb: p.v_min_gb,
        s_hard: p.hyst.s_hard,
        s_target: p.hyst.s_target,
        s_soft: p.hyst.s_soft,
        lambda: PAIR_LEDGER_LAMBDA,
    }
}

pub(super) fn raw_row(r: &PairLedger) -> RawRow {
    RawRow {
        g_they: r.gb_days_they_store_for_us,
        g_we: r.gb_days_we_store_for_them,
        depth: r.depth_of_their_service,
        v_dem: r.v_dem,
        observed_tau: r.observed_tau,
    }
}

fn status_name(s: HoldingStatus) -> String {
    format!("{s:?}")
}

/// Every owner with holdings here, master ascending; aggregates always, holdings only when
/// `with_holdings` (pressure records).
pub(super) fn raw_owners(
    holdings: &[HoldingRecord],
    ledgers: &[(IdentityPub, PairLedger)],
    own_master: &IdentityPub,
    with_holdings: bool,
) -> Vec<RawOwner> {
    let mut by: BTreeMap<[u8; 32], Vec<&HoldingRecord>> = BTreeMap::new();
    for h in holdings {
        by.entry(h.owner_id.0).or_default().push(h);
    }
    by.into_iter()
        .map(|(m, mut hs)| {
            let master = IdentityPub(m);
            hs.sort_by_key(|h| h.source_block_id.0);
            let own = master == *own_master;
            let mut parked = 0u64;
            let mut notified = 0u64;
            for h in &hs {
                if h.drop_notice_sent_at.is_some() {
                    notified += h.total_bytes;
                } else if h.status != HoldingStatus::MarkedForDelete && !own {
                    parked += h.total_bytes;
                }
            }
            RawOwner {
                master: hex_m(&master),
                row: ledgers
                    .iter()
                    .find(|(lm, _)| *lm == master)
                    .map(|(_, r)| raw_row(r)),
                parked_bytes: parked,
                notified_bytes: notified,
                holdings: if with_holdings {
                    hs.iter()
                        .map(|h| RawHolding {
                            block: hex_encode(&h.source_block_id.0),
                            bytes: h.total_bytes,
                            importance: h.importance,
                            status: status_name(h.status),
                            notified: h.drop_notice_sent_at.is_some(),
                        })
                        .collect()
                } else {
                    Vec::new()
                },
            }
        })
        .collect()
}

/// The raw inputs of the presence join: placements grouped by `(device, status)` and the
/// stored master of each such device (copied from `PeerRecord`, no filtering).
fn raw_presence_inputs(
    placements: &[SymbolPlacement],
    peers: &[PeerRecord],
) -> (Vec<RawPlacement>, Vec<RawPeerMaster>) {
    let mut groups: BTreeMap<([u8; 32], String), u64> = BTreeMap::new();
    for pl in placements {
        *groups
            .entry((pl.holder_id.0, format!("{:?}", pl.status)))
            .or_default() += 1;
    }
    let devices: BTreeSet<[u8; 32]> = groups.keys().map(|(d, _)| *d).collect();
    let mut peer_masters: BTreeMap<[u8; 32], IdentityPub> = BTreeMap::new();
    for p in peers {
        if devices.contains(&p.device_id.0) {
            peer_masters.insert(p.device_id.0, p.master_identity);
        }
    }
    (
        groups
            .into_iter()
            .map(|((d, status), count)| RawPlacement {
                device: hex_encode(&d),
                status,
                count,
            })
            .collect(),
        peer_masters
            .into_iter()
            .map(|(d, m)| RawPeerMaster {
                device: hex_encode(&d),
                master: hex_m(&m),
            })
            .collect(),
    )
}

/// The replay record of one shadow pressure tick.
pub fn raw_pressure_record(
    input: &ShadowPressureInput,
    p: &FourRParams,
    tick: &ShadowTick,
    now: u64,
) -> RawRecord {
    let presence = super::placement_presence_by_master(input.placements, input.peers);
    let mut presence: Vec<RawPresence> = presence
        .into_iter()
        .map(|(m, pr)| RawPresence {
            master: hex_m(&m),
            any: pr.any,
            held: pr.held,
        })
        .collect();
    presence.sort_by(|a, b| a.master.cmp(&b.master));
    let (placements, peer_masters) = raw_presence_inputs(input.placements, input.peers);
    let drops = |why: super::PlannedWhy| -> Vec<(String, String)> {
        tick.plan
            .drops
            .iter()
            .filter(|d| d.why == why)
            .map(|d| pair(&d.key))
            .collect()
    };
    let mut view_order = tick.owners.clone();
    view_order.sort_by_key(|o| o.master.0);
    RawRecord {
        v: RAW_RECORD_VERSION,
        kind: "pressure",
        now,
        own_master: hex_m(&input.own_master),
        params: raw_params(p),
        quota: input.quota,
        phase_prev: input.phase_prev.evicting,
        owners: raw_owners(input.holdings, input.ledgers, &input.own_master, true),
        presence,
        placements,
        peer_masters,
        old_owner_order: input.old_owner_order.iter().map(hex_m).collect(),
        old_plan: Some(RawOldPlan {
            pressure: format!("{:?}", input.old_plan.pressure),
            immediate: input.old_plan.immediate.iter().map(pair).collect(),
            notices: input.old_plan.notices.iter().map(pair).collect(),
        }),
        out: RawOut {
            phi_actual: tick.quota.phi_actual,
            phi_forecast: tick.quota.phi_forecast,
            q_bytes: tick.quota.q_bytes,
            q_nonpositive: tick.quota.q_nonpositive,
            measure_valid: tick.quota.measure_valid,
            phase: tick.decision.phase.evicting,
            accept_ok: tick.decision.accept_ok,
            kappa: view_order
                .iter()
                .map(|o| (hex_m(&o.master), o.kappa))
                .collect(),
            parked_bytes: view_order
                .iter()
                .map(|o| (hex_m(&o.master), o.parked_bytes))
                .collect(),
            owner_order_new: tick.owner_order.iter().map(hex_m).collect(),
            cap: drops(super::PlannedWhy::Cap),
            mfd: drops(super::PlannedWhy::MarkedForDelete),
            pressure: drops(super::PlannedWhy::Pressure),
            floor_skipped_bytes: tick.plan.floor_skipped_bytes,
            phi_forecast_after: tick.plan.phi_forecast_after,
            zk: RawZeroKappa {
                total: tick.zero_kappa.total,
                never_asked: tick.zero_kappa.never_asked,
                asked: tick.zero_kappa.asked,
                serving_unconfirmed: tick.zero_kappa.serving_unconfirmed,
            },
            zk_class: view_order
                .iter()
                .filter_map(|o| o.zk_class.map(|c| (hex_m(&o.master), format!("{c:?}"))))
                .collect(),
            first_owner_old: tick.divergence.first_old.as_ref().map(hex_m),
            first_owner_new: tick.divergence.first_new.as_ref().map(hex_m),
            top10_overlap: tick.divergence.top10_overlap,
            kendall_tau: tick.divergence.kendall_tau,
            admit: None,
        },
        offer: None,
        victim_holdings: None,
    }
}
