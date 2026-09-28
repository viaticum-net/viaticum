//! The offer shadow (В-0b): what 4R would answer to a symbol offer — the kernel
//! [`crate::four_r::admit_offer`] over the holder view, plus the holder layer the kernel does
//! not know (Q ≤ 0, Р-26, Р-17). In В-0 the daemon calls it AFTER the old rule answered and
//! off the reply path; the answer never depends on it.

use super::quota::{QuotaInputs, QuotaState, quota_state};
use super::record::{
    RawAdmitOut, RawHolding, RawOffer, RawOut, RawRecord, RawZeroKappa, hex_master, hex_pair,
    raw_owners, raw_params, raw_row,
};
use super::view::{HoldingKey, build_holder_view};
use super::{FourRParams, bytes_to_gb, holder_kappa};
use crate::four_r::{
    AdmitDecision, AdmitOfferer, AdmitReject, EvictPhase, admit_offer, preemption_margin,
    preemption_victim_owner,
};
use crate::types::{HoldingRecord, IdentityPub, PairLedger, SourceBlockId, hex_encode};

/// One incoming offer, as the holder saw it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OfferIn {
    /// The offering owner's MASTER (`from_master` of the handshake).
    pub owner: IdentityPub,
    pub block: SourceBlockId,
    pub offer_bytes: u64,
}

/// The holder-level decision.
#[derive(Debug, Clone, PartialEq)]
pub enum HolderAdmit {
    Free,
    /// Displace these holdings of `victim` (drop order).
    Preempt {
        victim: IdentityPub,
        victims: Vec<HoldingKey>,
        victim_bytes: u64,
    },
    Reject(HolderReject),
}

/// Why the holder layer refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderReject {
    /// `Q ≤ 0` — an explicit refusal, never "unlimited" (WARN-9).
    QuotaNonPositive,
    /// Р-26: this (owner, block) has a notified holding here — a re-offer into a record that
    /// is leaving would be wiped with it.
    NotifiedBlock,
    /// Р-17: the offerer has notified holdings here and its own `V_ret` cannot hold the offer
    /// even on the free path (no see-saw).
    GuardWhileNotified,
    /// The kernel's refusal.
    Kernel(AdmitReject),
}

/// The offer shadow's result with the numbers the log line carries.
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowOffer {
    pub quota: QuotaState,
    /// The persisted latch the decision read.
    pub phase: EvictPhase,
    pub offerer_kappa: f64,
    /// In-view bytes of the offerer here.
    pub offerer_parked_bytes: u64,
    pub offerer_notified_bytes: u64,
    /// `V_ret` [gb] of the offerer (`None`: cap disabled).
    pub v_ret_offerer_gb: Option<f64>,
    /// Preemption margin [gb·days].
    pub margin: f64,
    /// The candidate victim (least-reciprocal other owner), whether or not it is displaced.
    pub victim: Option<IdentityPub>,
    pub victim_kappa: Option<f64>,
    pub admit: HolderAdmit,
}

/// Decide an offer as 4R would: (1) `Q ≤ 0` → `QuotaNonPositive`; (2) Р-26; (3) the kernel
/// with `φ = phi_actual` and `free_now = bytes_to_gb(free_now_bytes)` (acceptance reads what
/// is on disk NOW, Р-14); (4) Р-17 on a kernel `Free`.
pub fn shadow_offer(
    holdings: &[HoldingRecord],
    ledgers: &[(IdentityPub, PairLedger)],
    own_master: IdentityPub,
    quota: QuotaInputs,
    phase: EvictPhase,
    offer: &OfferIn,
    p: &FourRParams,
) -> ShadowOffer {
    let q = quota_state(&quota);
    let view = build_holder_view(holdings, ledgers, &own_master, p);
    let row = ledgers
        .iter()
        .find(|(m, _)| *m == offer.owner)
        .map(|(_, r)| r);
    let offerer_kappa = holder_kappa(row, p);
    let index = view.index_of(&offer.owner);
    let offerer_parked_bytes = index.map_or(0, |i| view.parked_bytes(i));
    let offerer_notified_bytes: u64 = view
        .notified
        .iter()
        .filter(|h| h.key.owner_id == offer.owner)
        .map(|h| h.bytes)
        .sum();
    let cap = p.retention_cap();
    let v_ret_offerer_gb = cap.active().then(|| cap.v_ret(offerer_kappa));
    let v_offer = bytes_to_gb(offer.offer_bytes);
    let ap = p.admit_params();
    let margin = preemption_margin(ap.theta_p, v_offer, ap.v_min, ap.lambda);
    let victim_idx = preemption_victim_owner(&view.views, &view.kappa, index);
    let key = HoldingKey {
        source_block_id: offer.block,
        owner_id: offer.owner,
    };

    let admit = if q.q_nonpositive {
        HolderAdmit::Reject(HolderReject::QuotaNonPositive)
    } else if view.notified.iter().any(|h| h.key == key) {
        HolderAdmit::Reject(HolderReject::NotifiedBlock)
    } else {
        let offerer = AdmitOfferer {
            index,
            kappa: offerer_kappa,
            v_parked: bytes_to_gb(offerer_parked_bytes),
        };
        match admit_offer(
            &view.views,
            &view.kappa,
            &offerer,
            v_offer,
            q.phi_actual,
            bytes_to_gb(q.free_now_bytes),
            phase,
            &ap,
        ) {
            AdmitDecision::Free => {
                if offerer_notified_bytes > 0
                    && cap.active()
                    && offerer.v_parked + v_offer > cap.v_ret(offerer_kappa)
                {
                    HolderAdmit::Reject(HolderReject::GuardWhileNotified)
                } else {
                    HolderAdmit::Free
                }
            }
            AdmitDecision::Preempt {
                victim_owner,
                victim_symbols,
            } => {
                let hs: Vec<_> = victim_symbols
                    .iter()
                    .map(|&si| view.holdings[victim_owner][si])
                    .collect();
                HolderAdmit::Preempt {
                    victim: view.masters[victim_owner],
                    victims: hs.iter().map(|h| h.key).collect(),
                    victim_bytes: hs.iter().map(|h| h.bytes).sum(),
                }
            }
            AdmitDecision::Reject(r) => HolderAdmit::Reject(HolderReject::Kernel(r)),
        }
    };

    ShadowOffer {
        quota: q,
        phase,
        offerer_kappa,
        offerer_parked_bytes,
        offerer_notified_bytes,
        v_ret_offerer_gb,
        margin,
        victim: victim_idx.map(|i| view.masters[i]),
        victim_kappa: victim_idx.map(|i| view.kappa[i]),
        admit,
    }
}

impl HolderAdmit {
    /// `free` | `preempt` | `reject` (the log's `new=`).
    pub fn tag(&self) -> &'static str {
        match self {
            HolderAdmit::Free => "free",
            HolderAdmit::Preempt { .. } => "preempt",
            HolderAdmit::Reject(_) => "reject",
        }
    }

    /// Would 4R take the offer (freely or by preemption)?
    pub fn admits(&self) -> bool {
        !matches!(self, HolderAdmit::Reject(_))
    }

    /// The reject reason's name (`None` unless a reject).
    pub fn reason(&self) -> Option<String> {
        match self {
            HolderAdmit::Reject(HolderReject::Kernel(r)) => Some(format!("{r:?}")),
            HolderAdmit::Reject(r) => Some(format!("{r:?}")),
            _ => None,
        }
    }
}

/// The replay record of one offer shadow: owner AGGREGATES only (tens of rows even on a
/// large NAS, W-6) plus the view holdings of the candidate victim.
#[allow(clippy::too_many_arguments)]
pub fn raw_offer_record(
    holdings: &[HoldingRecord],
    ledgers: &[(IdentityPub, PairLedger)],
    own_master: IdentityPub,
    quota: QuotaInputs,
    offer: &OfferIn,
    p: &FourRParams,
    out: &ShadowOffer,
    old_accept: bool,
    old_held_bytes: u64,
    now: u64,
) -> RawRecord {
    let owners = raw_owners(holdings, ledgers, &own_master, false);
    let view = build_holder_view(holdings, ledgers, &own_master, p);
    let victim_holdings = out.victim.and_then(|v| view.index_of(&v)).map(|vi| {
        view.holdings[vi]
            .iter()
            .map(|h| RawHolding {
                block: hex_encode(&h.key.source_block_id.0),
                bytes: h.bytes,
                importance: h.importance,
                status: "view".to_string(),
                notified: false,
            })
            .collect()
    });
    let key = HoldingKey {
        source_block_id: offer.block,
        owner_id: offer.owner,
    };
    let (victims, victim_bytes) = match &out.admit {
        HolderAdmit::Preempt {
            victims,
            victim_bytes,
            ..
        } => (victims.iter().map(hex_pair).collect(), *victim_bytes),
        _ => (Vec::new(), 0),
    };
    RawRecord {
        v: super::RAW_RECORD_VERSION,
        kind: "offer",
        now,
        own_master: hex_master(&own_master),
        params: raw_params(p),
        quota,
        phase_prev: out.phase.evicting,
        owners,
        presence: Vec::new(),
        placements: Vec::new(),
        peer_masters: Vec::new(),
        old_owner_order: Vec::new(),
        old_plan: None,
        offer: Some(RawOffer {
            owner: hex_master(&offer.owner),
            block: hex_encode(&offer.block.0),
            offer_bytes: offer.offer_bytes,
            old_accept,
            old_held_bytes,
            offer_block_notified: view.notified.iter().any(|h| h.key == key),
            offerer_row: ledgers
                .iter()
                .find(|(m, _)| *m == offer.owner)
                .map(|(_, r)| raw_row(r)),
        }),
        victim_holdings,
        out: RawOut {
            phi_actual: out.quota.phi_actual,
            phi_forecast: out.quota.phi_forecast,
            q_bytes: out.quota.q_bytes,
            q_nonpositive: out.quota.q_nonpositive,
            measure_valid: out.quota.measure_valid,
            phase: out.phase.evicting,
            accept_ok: false,
            kappa: view
                .masters
                .iter()
                .zip(&view.kappa)
                .map(|(m, k)| (hex_master(m), *k))
                .collect(),
            parked_bytes: (0..view.masters.len())
                .map(|i| (hex_master(&view.masters[i]), view.parked_bytes(i)))
                .collect(),
            owner_order_new: Vec::new(),
            cap: Vec::new(),
            mfd: Vec::new(),
            pressure: Vec::new(),
            floor_skipped_bytes: 0,
            phi_forecast_after: out.quota.phi_forecast,
            zk: RawZeroKappa {
                total: 0,
                never_asked: 0,
                asked: 0,
                serving_unconfirmed: 0,
            },
            zk_class: Vec::new(),
            first_owner_old: None,
            first_owner_new: None,
            top10_overlap: 0,
            kendall_tau: None,
            admit: Some(RawAdmitOut {
                tag: match out.admit {
                    HolderAdmit::Free => "Free",
                    HolderAdmit::Preempt { .. } => "Preempt",
                    HolderAdmit::Reject(_) => "Reject",
                }
                .to_string(),
                reason: out.admit.reason(),
                victim: match &out.admit {
                    HolderAdmit::Preempt { victim, .. } => Some(hex_master(victim)),
                    _ => None,
                },
                candidate: out.victim.as_ref().map(hex_master),
                victims,
                victim_bytes,
                offerer_kappa: out.offerer_kappa,
                victim_kappa: out.victim_kappa,
                margin: out.margin,
                v_ret_offerer_gb: out.v_ret_offerer_gb,
                offerer_parked_bytes: out.offerer_parked_bytes,
                offerer_notified_bytes: out.offerer_notified_bytes,
            }),
        },
    }
}
